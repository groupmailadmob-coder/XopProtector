#include "dex/dex_file.h"
#include "common/log.h"
#include "common/va_tag.h"
#include "common/runtime_state.h"
#include "common/protector_macro.h"
#include "crypto/insn_crypt.h"
#include "vm/vm_codec.h"
#include "risk/risk.h"

#include <atomic>
#include <cerrno>
#include <cstring>
#include <cctype>
#include <dirent.h>
#include <fcntl.h>
#include <mutex>
#include <thread>
#include <utility>
#include <ctime>
#include <time.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/uio.h>
#include <unistd.h>
#include <cstddef>
#include <vector>
#include <unordered_set>
#include <unordered_map>
#include <string>

namespace protector::dex {

static std::unordered_set<uintptr_t> g_writable_dex_bases;
static std::mutex g_mprotect_mutex;

size_t read_uleb128(const uint8_t* data, size_t max_len, uint64_t* val, bool* ok) {
    if (ok) *ok = false;
    if (data == nullptr || val == nullptr || max_len == 0) return 0;
    uint64_t result = 0;
    size_t read = 0;
    for (int i = 0; i < 5; i++) {
        if (read >= max_len) return 0;
        uint8_t b = data[read];
        result |= (static_cast<uint64_t>(b & 0x7f) << (i * 7));
        read++;
        if ((b & 0x80) == 0) {
            *val = result;
            if (ok) *ok = true;
            return read;
        }
    }
    return 0; // malformed (>5 bytes)
}

size_t skip_fields(const uint8_t* data, size_t max_len, uint64_t count, bool* ok) {
    if (ok) *ok = false;
    size_t read = 0;
    for (uint64_t i = 0; i < count; i++) {
        bool local_ok = false;
        uint64_t tmp = 0;
        size_t n = read_uleb128(data + read, max_len - read, &tmp, &local_ok);
        if (!local_ok) return 0;
        read += n;
        n = read_uleb128(data + read, max_len - read, &tmp, &local_ok);
        if (!local_ok) return 0;
        read += n;
    }
    if (ok) *ok = true;
    return read;
}

size_t read_methods(const uint8_t* data, size_t max_len, ClassDataMethod* out,
                    uint64_t count, bool* ok) {
    if (ok) *ok = false;
    if (out == nullptr && count > 0) return 0;
    size_t read = 0;
    uint32_t idx = 0;
    for (uint64_t i = 0; i < count; i++) {
        bool local_ok = false;
        uint64_t delta = 0, flags = 0, code_off = 0;
        size_t n = read_uleb128(data + read, max_len - read, &delta, &local_ok);
        if (!local_ok) return 0;
        read += n;
        idx += static_cast<uint32_t>(delta);
        n = read_uleb128(data + read, max_len - read, &flags, &local_ok);
        if (!local_ok) return 0;
        read += n;
        n = read_uleb128(data + read, max_len - read, &code_off, &local_ok);
        if (!local_ok) return 0;
        read += n;
        out[i].method_idx = idx;
        out[i].access_flags = static_cast<uint32_t>(flags);
        out[i].code_off = static_cast<uint32_t>(code_off);
    }
    if (ok) *ok = true;
    return read;
}

static bool ptr_userspace_plausible(const void* p) {
    auto u = strip_va_tag(reinterpret_cast<uintptr_t>(p));
    if (u < 0x1000u) return false;
#ifdef __LP64__
    if (u > 0x00007FFFFFFFFFFFULL) return false;
#endif
    return true;
}

/** Read without SIGSEGV. process_vm_readv first; ENOSYS/EPERM falls back to memcpy. */
static bool safe_read(const void* addr, void* out, size_t n) {
    if (out == nullptr || n == 0) return false;
    const void* p = untag_ptr(addr);
    if (!ptr_userspace_plausible(p)) return false;
    auto end = reinterpret_cast<uintptr_t>(p) + (n - 1);
    if (!ptr_userspace_plausible(reinterpret_cast<const void*>(end))) return false;

    static int vm_readv_state = 0; // 0 unknown, 1 ok, -1 memcpy fallback
    if (vm_readv_state < 0) {
        memcpy(out, p, n);
        return true;
    }

    iovec local{out, n};
    iovec remote{const_cast<void*>(p), n};
    ssize_t got = process_vm_readv(getpid(), &local, 1, &remote, 1, 0);
    if (got == static_cast<ssize_t>(n)) {
        vm_readv_state = 1;
        return true;
    }
    // Some OEM kernels reject same-process vm_readv with EACCES/EINVAL;
    // fall back to memcpy so probe still works (pre-XOM / normal DEX pages).
    if (got < 0 && (errno == ENOSYS || errno == EPERM || errno == EACCES
                    || errno == EINVAL)) {
        vm_readv_state = -1;
        memcpy(out, p, n);
        return true;
    }
    return false;
}

static bool location_chars_ok(const char* s, size_t n) {
    if (s == nullptr || n == 0) return false;
    for (size_t i = 0; i < n; i++) {
        unsigned char c = static_cast<unsigned char>(s[i]);
        if (c == 0) return false;
        if (c < 0x20 && c != '\t') return false;
        if (c == 0x7f) return false;
    }
    return true;
}

/** Copy libc++ std::string without deref'ing a corrupt object. */
static bool try_copy_std_string(const void* str_obj, std::string* out) {
    if (out == nullptr || !ptr_userspace_plausible(str_obj)) return false;
    uint8_t raw[24] = {};
    if (!safe_read(str_obj, raw, sizeof(raw))) return false;

#ifdef __LP64__
    uintptr_t long_data = 0;
    size_t long_size = 0;
    memcpy(&long_data, raw, sizeof(long_data));
    memcpy(&long_size, raw + sizeof(void*), sizeof(long_size));
    if (long_size > 0 && long_size < 4096
        && ptr_userspace_plausible(reinterpret_cast<const void*>(long_data))) {
        std::string tmp(long_size, '\0');
        if (safe_read(reinterpret_cast<const void*>(long_data), tmp.data(), long_size)
            && location_chars_ok(tmp.data(), long_size)) {
            *out = std::move(tmp);
            return true;
        }
    }
    size_t short_size = static_cast<size_t>(raw[23] >> 1);
    if (short_size > 0 && short_size <= 22
        && location_chars_ok(reinterpret_cast<const char*>(raw), short_size)) {
        out->assign(reinterpret_cast<const char*>(raw), short_size);
        return true;
    }
#else
    uintptr_t long_data = 0;
    size_t long_size = 0;
    memcpy(&long_data, raw, sizeof(long_data));
    memcpy(&long_size, raw + sizeof(void*), sizeof(long_size));
    if (long_size > 0 && long_size < 4096
        && ptr_userspace_plausible(reinterpret_cast<const void*>(long_data))) {
        std::string tmp(long_size, '\0');
        if (safe_read(reinterpret_cast<const void*>(long_data), tmp.data(), long_size)
            && location_chars_ok(tmp.data(), long_size)) {
            *out = std::move(tmp);
            return true;
        }
    }
    size_t short_size = static_cast<size_t>(raw[11] >> 1);
    if (short_size > 0 && short_size <= 10
        && location_chars_ok(reinterpret_cast<const char*>(raw), short_size)) {
        out->assign(reinterpret_cast<const char*>(raw), short_size);
        return true;
    }
#endif
    return false;
}

enum class LayoutProbe {
    kUnsafe,
    kInvalidLayout,
    kOk,
};

struct DexLayout {
    size_t off_begin;
    size_t off_size;
    bool has_size;
    size_t off_location;
    size_t off_header;
};

static LayoutProbe try_probe_layout(const void* dex_file, const DexLayout& layout,
                                    DexView* view) {
    if (view == nullptr) return LayoutProbe::kUnsafe;
    if (!ptr_userspace_plausible(dex_file)) return LayoutProbe::kUnsafe;

    const uint8_t* begin = nullptr;
    if (!safe_read(reinterpret_cast<const char*>(dex_file) + layout.off_begin,
                   &begin, sizeof(begin))) {
        return LayoutProbe::kUnsafe;
    }
    if (!ptr_userspace_plausible(begin)) return LayoutProbe::kInvalidLayout;

    uint8_t magic[4] = {};
    if (!safe_read(begin, magic, sizeof(magic))) {
        return LayoutProbe::kInvalidLayout;
    }
    if (!(magic[0] == 'd' && magic[1] == 'e' && magic[2] == 'x' && magic[3] == '\n')) {
        return LayoutProbe::kInvalidLayout;
    }

    std::string location;
    if (!try_copy_std_string(
                reinterpret_cast<const char*>(dex_file) + layout.off_location,
                &location)) {
        return LayoutProbe::kInvalidLayout;
    }

    size_t size = 0;
    if (layout.has_size) {
        if (!safe_read(reinterpret_cast<const char*>(dex_file) + layout.off_size,
                       &size, sizeof(size))) {
            size = 0;
        }
    }
    if (size == 0) {
        const void* header = nullptr;
        if (safe_read(reinterpret_cast<const char*>(dex_file) + layout.off_header,
                      &header, sizeof(header))
            && ptr_userspace_plausible(header)) {
            uint32_t file_size = 0;
            if (safe_read(reinterpret_cast<const uint8_t*>(header) + 32,
                          &file_size, sizeof(file_size))) {
                size = file_size;
            }
        }
    }
    if (size == 0 || size > 256u * 1024u * 1024u) {
        return LayoutProbe::kInvalidLayout;
    }

    view->begin = begin;
    view->size = size;
    view->location = std::move(location);
    return LayoutProbe::kOk;
}

/** Normalize path separators and check protected dex location by path segments. */
static bool is_protected_dex_location(const std::string& location) {
    if (location.empty()) return false;

    std::string path = location;
    for (char& c : path) {
        if (c == '\\') c = '/';
    }

    // Multidex / zip container: .../dexes.zip!classes2.dex or .../dexes.zip!N
    size_t sep = path.rfind('!');
    if (sep == std::string::npos) {
        sep = path.rfind(':');
    }
    if (sep != std::string::npos) {
        std::string container = path.substr(0, sep);
        size_t slash = container.rfind('/');
        std::string base = (slash == std::string::npos) ? container : container.substr(slash + 1);
        if (base == "dexes.zip") return true;
        // Also accept path ending with /dexes.zip before separator
        if (container.size() >= 10 && container.compare(container.size() - 10, 10, "/dexes.zip") == 0) {
            return true;
        }
        return false;
    }

    // Extracted files must live under .../code_cache/protector/
    const char* marker = "/code_cache/protector/";
    auto pos = path.find(marker);
    if (pos != std::string::npos) {
        // Require a .dex entry under that directory (not arbitrary files)
        auto after = pos + strlen(marker);
        if (after < path.size() && path.find(".dex", after) != std::string::npos) {
            return true;
        }
    }
    // Exact directory without trailing slash then /classes.dex
    const char* marker_end = "/code_cache/protector";
    pos = path.find(marker_end);
    if (pos != std::string::npos) {
        size_t end = pos + strlen(marker_end);
        if (end == path.size()) return false;
        if (path[end] == '/' && path.find(".dex", end) != std::string::npos) return true;
    }
    return false;
}

DexView probe_dex_file(const void* dex_file, int sdk_level) {
    DexView view;
    if (dex_file == nullptr) return view;

    const DexLayout kV35{
            offsetof(V35::DexFile, begin_),
            offsetof(V35::DexFile, unused_size_),
            false,
            offsetof(V35::DexFile, location_),
            offsetof(V35::DexFile, header_),
    };
    const DexLayout kV28{
            offsetof(V28::DexFile, begin_),
            offsetof(V28::DexFile, size_),
            true,
            offsetof(V28::DexFile, location_),
            offsetof(V28::DexFile, header_),
    };
    const DexLayout kV21{
            offsetof(V21::DexFile, begin_),
            offsetof(V21::DexFile, size_),
            true,
            offsetof(V21::DexFile, location_),
            offsetof(V21::DexFile, header_),
    };

    DexLayout order[3];
    int n = 0;
    if (sdk_level >= 35) {
        order[n++] = kV35;
        order[n++] = kV28;
        order[n++] = kV21;
    } else if (sdk_level >= 28) {
        order[n++] = kV28;
        order[n++] = kV35;
        order[n++] = kV21;
    } else {
        order[n++] = kV21;
        order[n++] = kV28;
        order[n++] = kV35;
    }

    bool filled = false;
    for (int i = 0; i < n; i++) {
        DexView candidate;
        LayoutProbe r = try_probe_layout(dex_file, order[i], &candidate);
        if (r == LayoutProbe::kOk) {
            view = std::move(candidate);
            filled = true;
            break;
        }
        if (r == LayoutProbe::kUnsafe) {
            static std::atomic_bool logged{false};
            if (!logged.exchange(true)) {
                PLOGE("DexFile probe unsafe sdk=%d (further skips silent)", sdk_level);
            }
            view.valid = false;
            return view;
        }
        // kInvalidLayout: try next candidate
    }
    if (!filled) {
        view.valid = false;
        return view;
    }

    if (!is_protected_dex_location(view.location)) {
        view.valid = false;
        return view;
    }
    view.valid = true;
    return view;
}

static int digits_from_suffix(const std::string& str) {
    int sum = 0;
    int mul = 1;
    for (auto it = str.crbegin(); it != str.crend(); ++it) {
        if (isdigit(static_cast<unsigned char>(*it))) {
            sum += (*it - '0') * mul;
            mul *= 10;
        } else if (sum != 0) {
            break;
        }
    }
    return sum;
}

/** Map classesN.dex ordinal to 0-based index: classes.dex -> 0, classes2 -> 1. */
static int normalize_classes_n(int num) {
    return num <= 0 ? 0 : (num - 1);
}

int parse_dex_number(const std::string& location) {
    // Prefer multidex separator forms: base!classes2.dex or base!N (0-based)
    size_t sep = location.rfind('!');
    if (sep == std::string::npos) {
        sep = location.rfind(':');
    }
    if (sep != std::string::npos) {
        std::string suffix = location.substr(sep + 1);
        int num = digits_from_suffix(suffix);
        if (suffix.find(".dex") != std::string::npos) {
            // classes.dex / classes2.dex naming is 1-based for N>=2
            return normalize_classes_n(num);
        }
        // Pure numeric !N / :N is already a 0-based dex index
        return num;
    }

    // Extracted file path: .../classes.dex, .../classes2.dex
    auto pos = location.rfind("classes");
    if (pos == std::string::npos) return 0;
    auto start = pos + 7;
    if (start >= location.size() || !isdigit(static_cast<unsigned char>(location[start]))) {
        return 0;
    }
    int num = 0;
    while (start < location.size() && isdigit(static_cast<unsigned char>(location[start]))) {
        num = num * 10 + (location[start] - '0');
        start++;
    }
    return normalize_classes_n(num);
}

static int page_size() {
    static int ps = static_cast<int>(sysconf(_SC_PAGESIZE));
    return ps;
}

/** Per-dex in-flight writers: prevents mprotect(RO) while another thread still writes. */
static std::unordered_map<uintptr_t, int> g_dex_writers;

/** Track begin/size/dex_index for deferred RO flush after startup hold window. */
struct DexRwInfo {
    uint8_t* begin = nullptr;
    size_t size = 0;
    int dex_index = -1;
};
static std::unordered_map<uintptr_t, DexRwInfo> g_dex_rw_info;

/** Keep DEX mappings RW during early startup to avoid RW↔RO thrash (P0). */
static constexpr int64_t kDexRwHoldNs = 25LL * 1000 * 1000 * 1000; // 25s
static std::atomic<int64_t> g_rw_hold_deadline_ns{0};
static std::once_flag g_rw_flusher_once;

static int64_t mono_ns() {
    struct timespec ts{};
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return static_cast<int64_t>(ts.tv_sec) * 1000000000LL
            + static_cast<int64_t>(ts.tv_nsec);
}

static bool dex_has_unpatched(int dex_index) {
    auto& state = runtime_state();
    auto dex_it = state.code_map.find(dex_index);
    if (dex_it == state.code_map.end()) return false;
    for (const auto& kv : dex_it->second) {
        if (kv.second != nullptr && !kv.second->patched.load(std::memory_order_acquire)) {
            return true;
        }
    }
    return false;
}

static void wipe_secrets_if_all_patched_locked() {
    auto& state = runtime_state();
    for (const auto& dex : state.code_map) {
        for (const auto& kv : dex.second) {
            if (kv.second != nullptr && !kv.second->patched.load(std::memory_order_acquire)) {
                return;
            }
        }
    }
    if (!state.config.insns_aes_key.empty()) {
        memset(state.config.insns_aes_key.data(), 0, state.config.insns_aes_key.size());
        state.config.insns_aes_key.clear();
        PLOGD("wiped insn AES key after full patch");
    }
    if (!state.code_blob.empty()) {
        memset(state.code_blob.data(), 0, state.code_blob.size());
        state.code_blob.clear();
        state.code_blob.shrink_to_fit();
        for (auto& dex : state.code_map) {
            for (auto& kv : dex.second) {
                if (kv.second != nullptr) {
                    kv.second->insns = nullptr;
                    kv.second->insns_size = 0;
                }
            }
        }
        PLOGD("wiped code_blob after full patch");
    }
}

static bool mprotect_dex_rw_locked(uint8_t* begin, size_t size) {
    uintptr_t start = reinterpret_cast<uintptr_t>(begin) & ~static_cast<uintptr_t>(page_size() - 1);
    uintptr_t end = (reinterpret_cast<uintptr_t>(begin) + size + page_size() - 1) &
                    ~static_cast<uintptr_t>(page_size() - 1);
    if (mprotect(reinterpret_cast<void*>(start), end - start, PROT_READ | PROT_WRITE) != 0) {
        PLOGE("mprotect failed for %p", begin);
        return false;
    }
    return true;
}

static void mprotect_dex_ro_locked(uint8_t* begin, size_t size, int dex_index) {
    uintptr_t key = reinterpret_cast<uintptr_t>(begin);
    if (!g_writable_dex_bases.count(key)) return;
    uintptr_t start = reinterpret_cast<uintptr_t>(begin) & ~static_cast<uintptr_t>(page_size() - 1);
    uintptr_t end = (reinterpret_cast<uintptr_t>(begin) + size + page_size() - 1) &
                    ~static_cast<uintptr_t>(page_size() - 1);
    if (mprotect(reinterpret_cast<void*>(start), end - start, PROT_READ) != 0) {
        PLOGW("mprotect restore RO failed for %p", begin);
        return;
    }
    g_writable_dex_bases.erase(key);
    g_dex_rw_info.erase(key);
    PLOGD("restored PROT_READ for dex=%d %p", dex_index, begin);
}

/** Restore RO for writable dexes that have no writers and no pending patches. */
static void flush_deferred_ro() {
    std::lock_guard<std::mutex> lock(g_mprotect_mutex);
    std::vector<DexRwInfo> candidates;
    candidates.reserve(g_dex_rw_info.size());
    for (const auto& kv : g_dex_rw_info) {
        candidates.push_back(kv.second);
    }
    for (const auto& info : candidates) {
        if (info.begin == nullptr || info.size == 0) continue;
        uintptr_t key = reinterpret_cast<uintptr_t>(info.begin);
        auto wit = g_dex_writers.find(key);
        if (wit != g_dex_writers.end() && wit->second > 0) continue;
        if (dex_has_unpatched(info.dex_index)) continue;
        mprotect_dex_ro_locked(info.begin, info.size, info.dex_index);
    }
    wipe_secrets_if_all_patched_locked();
    PLOGI("dex RW hold flush done remaining_rw=%zu", g_writable_dex_bases.size());
}

static void ensure_rw_hold_flusher() {
    std::call_once(g_rw_flusher_once, [] {
        int64_t deadline = mono_ns() + kDexRwHoldNs;
        g_rw_hold_deadline_ns.store(deadline, std::memory_order_release);
        std::thread([] {
            for (;;) {
                int64_t dl = g_rw_hold_deadline_ns.load(std::memory_order_acquire);
                int64_t now = mono_ns();
                if (now >= dl) break;
                int64_t sleep_ns = dl - now;
                if (sleep_ns > 500000000LL) sleep_ns = 500000000LL; // 500ms slices
                usleep(static_cast<useconds_t>(sleep_ns / 1000));
            }
            flush_deferred_ro();
        }).detach();
        PLOGI("dex RW hold window %lld ms", static_cast<long long>(kDexRwHoldNs / 1000000));
    });
}

static bool begin_dex_write(uint8_t* begin, size_t size, int dex_index) {
    if (begin == nullptr || size == 0) return false;
    std::lock_guard<std::mutex> lock(g_mprotect_mutex);
    auto key = reinterpret_cast<uintptr_t>(begin);
    int& writers = g_dex_writers[key];
    if (writers == 0 || g_writable_dex_bases.count(key) == 0) {
        if (!mprotect_dex_rw_locked(begin, size)) {
            if (writers == 0) {
                g_dex_writers.erase(key);
            }
            return false;
        }
        g_writable_dex_bases.insert(key);
        g_dex_rw_info[key] = DexRwInfo{begin, size, dex_index};
        PLOGD("mprotect ok %p size=%zu", begin, size);
        ensure_rw_hold_flusher();
    } else {
        // Refresh mapping metadata (dex_index may be known on later writers).
        g_dex_rw_info[key] = DexRwInfo{begin, size, dex_index};
    }
    writers++;
    return true;
}

static void end_dex_write(uint8_t* begin, size_t size, int dex_index) {
    if (begin == nullptr || size == 0) return;
    std::lock_guard<std::mutex> lock(g_mprotect_mutex);
    auto key = reinterpret_cast<uintptr_t>(begin);
    auto it = g_dex_writers.find(key);
    if (it == g_dex_writers.end()) return;
    if (--(it->second) > 0) return;
    g_dex_writers.erase(it);

    // Still have hollow methods in this dex → must stay RW.
    if (dex_has_unpatched(dex_index)) {
        return;
    }

    // Startup hold: defer RO until flusher deadline (avoids mid-startup RO churn).
    int64_t deadline = g_rw_hold_deadline_ns.load(std::memory_order_acquire);
    if (deadline != 0 && mono_ns() < deadline) {
        return;
    }

    mprotect_dex_ro_locked(begin, size, dex_index);
    wipe_secrets_if_all_patched_locked();
}

/**
 * Prepare one method for class-batch patch: CAS + decrypt into out_plain.
 * Does not mprotect or write DEX. On failure rolls back patched flag.
 * @return true if out_plain holds plaintext ready to write.
 */
PROTECTOR_ENCRYPT static bool prepare_method_decrypt(
        int dex_index, uint32_t method_idx, uint32_t code_off, size_t dex_size,
        CodeItem** out_item, std::vector<uint8_t>* out_plain) {
    if (out_item == nullptr || out_plain == nullptr) return false;
    *out_item = nullptr;
    out_plain->clear();
    if (code_off == 0 || dex_size == 0) return false;

    auto& state = runtime_state();
    auto dex_it = state.code_map.find(dex_index);
    if (dex_it == state.code_map.end()) return false;
    auto method_it = dex_it->second.find(method_idx);
    if (method_it == dex_it->second.end()) return false;

    CodeItem* item = method_it->second;
    if (item == nullptr) return false;
    if ((item->flags & vm::FLAG_TRUE_VMP) != 0) return false;
    if (item->insns == nullptr || item->insns_size == 0 || item->plain_insns_size == 0) {
        return false;
    }
    if (static_cast<uint64_t>(code_off) + kCodeItemFixedSize > dex_size) {
        PLOGE("code_off out of range: %u dex_size=%zu", code_off, dex_size);
        return false;
    }
    if (static_cast<uint64_t>(code_off) + kCodeItemFixedSize + item->plain_insns_size > dex_size) {
        PLOGE("insns write would exceed dex: off=%u size=%u dex=%zu",
              code_off, item->plain_insns_size, dex_size);
        return false;
    }

    bool expected = false;
    if (!item->patched.compare_exchange_strong(expected, true,
                                               std::memory_order_acq_rel,
                                               std::memory_order_acquire)) {
        return false;
    }

    const uint8_t* enc_ptr = item->insns;
    const uint32_t enc_size = item->insns_size;
    if (enc_ptr == nullptr || enc_size == 0 || item->plain_insns_size == 0) {
        item->patched.store(false, std::memory_order_release);
        return false;
    }

    out_plain->resize(item->plain_insns_size);
    if (!crypto::decrypt_insns(enc_ptr, enc_size,
                               out_plain->data(), item->plain_insns_size,
                               item->method_idx, item->flags, state.config)) {
        PLOGE("decrypt/VMP failed method=%u flags=0x%x", method_idx, item->flags);
        memset(out_plain->data(), 0, out_plain->size());
        out_plain->clear();
        item->patched.store(false, std::memory_order_release);
        return false;
    }
    *out_item = item;
    return true;
}

/** Write already-decrypted plaintext into DEX (caller holds RW via begin_dex_write). */
PROTECTOR_ENCRYPT static bool commit_method_write(
        uint8_t* begin, size_t dex_size, uint32_t method_idx, uint32_t code_off,
        CodeItem* item, std::vector<uint8_t>& plain) {
    if (begin == nullptr || item == nullptr || plain.empty()) return false;
    auto* code_item = reinterpret_cast<CodeItemHeader*>(begin + code_off);
    uint64_t declared_bytes = static_cast<uint64_t>(code_item->insns_size_) * 2u;
    if (item->plain_insns_size > declared_bytes || plain.size() != item->plain_insns_size) {
        PLOGE("insns_size mismatch method=%u stored=%u declared=%llu",
              method_idx, item->plain_insns_size,
              static_cast<unsigned long long>(declared_bytes));
        item->patched.store(false, std::memory_order_release);
        memset(plain.data(), 0, plain.size());
        return false;
    }
    auto* dst = reinterpret_cast<uint8_t*>(code_item->insns_);
    memcpy(dst, plain.data(), plain.size());
    memset(plain.data(), 0, plain.size());
    if (item->insns != nullptr && item->insns_size > 0) {
        memset(item->insns, 0, item->insns_size);
    }
    item->insns = nullptr;
    item->insns_size = 0;
    PLOGD("patched method=%u size=%u vmp=%d", method_idx, item->plain_insns_size,
          (item->flags & 1) ? 1 : 0);
    return true;
}

/** Base junk class path without L/; illegal clones end with a digit before ';'. */
static constexpr const char kJunkClassPath[] = "com/yqsh/protector/junkcode/JunkClass";

PROTECTOR_ENCRYPT void patch_class(const char* descriptor, const void* dex_file, const void* dex_class_def) {
    auto& state = runtime_state();
    if (!state.inited.load()) return;

    if (descriptor != nullptr && strstr(descriptor, kJunkClassPath) != nullptr) {
        size_t len = strlen(descriptor);
        if (len >= 2 && isdigit(static_cast<unsigned char>(descriptor[len - 2]))) {
            PLOGE("illegal junk class patch: %s", descriptor);
            protector::risk::crash_hang();  // junk code tampered
            return;
        }
    }

    DexView view = probe_dex_file(dex_file, state.sdk_level);
    if (!view.valid || dex_class_def == nullptr || view.begin == nullptr || view.size == 0) {
        return;
    }

    int dex_index = parse_dex_number(view.location);
    auto* class_def = reinterpret_cast<const ClassDef*>(dex_class_def);
    if (class_def->class_data_off_ == 0) return;
    if (static_cast<uint64_t>(class_def->class_data_off_) >= view.size) {
        PLOGE("class_data_off out of range: %u", class_def->class_data_off_);
        return;
    }

    const uint8_t* class_data = view.begin + class_def->class_data_off_;
    size_t remain = view.size - class_def->class_data_off_;
    size_t read = 0;
    bool ok = false;
    uint64_t static_fields = 0, instance_fields = 0, direct_methods = 0, virtual_methods = 0;

    size_t n = read_uleb128(class_data + read, remain - read, &static_fields, &ok);
    if (!ok) return;
    read += n;
    n = read_uleb128(class_data + read, remain - read, &instance_fields, &ok);
    if (!ok) return;
    read += n;
    n = read_uleb128(class_data + read, remain - read, &direct_methods, &ok);
    if (!ok) return;
    read += n;
    n = read_uleb128(class_data + read, remain - read, &virtual_methods, &ok);
    if (!ok) return;
    read += n;

    if (direct_methods > kMaxMethodsPerClass || virtual_methods > kMaxMethodsPerClass
        || static_fields > kMaxMethodsPerClass || instance_fields > kMaxMethodsPerClass) {
        PLOGE("class_data counts too large");
        return;
    }

    n = skip_fields(class_data + read, remain - read, static_fields, &ok);
    if (!ok) return;
    read += n;
    n = skip_fields(class_data + read, remain - read, instance_fields, &ok);
    if (!ok) return;
    read += n;

    std::vector<ClassDataMethod> directs(static_cast<size_t>(direct_methods));
    std::vector<ClassDataMethod> virtuals(static_cast<size_t>(virtual_methods));
    if (direct_methods > 0) {
        n = read_methods(class_data + read, remain - read, directs.data(), direct_methods, &ok);
        if (!ok) return;
        read += n;
    }
    if (virtual_methods > 0) {
        n = read_methods(class_data + read, remain - read, virtuals.data(), virtual_methods, &ok);
        if (!ok) return;
        read += n;
    }

    struct BatchEntry {
        uint32_t method_idx = 0;
        uint32_t code_off = 0;
        CodeItem* item = nullptr;
        std::vector<uint8_t> plain;
    };

    auto rollback_batch = [](std::vector<BatchEntry>& batch) {
        for (auto& e : batch) {
            if (e.item != nullptr) {
                e.item->patched.store(false, std::memory_order_release);
            }
            if (!e.plain.empty()) {
                memset(e.plain.data(), 0, e.plain.size());
            }
        }
        batch.clear();
    };

    auto collect_methods = [&](const ClassDataMethod* methods, size_t count,
                               std::vector<BatchEntry>* batch) {
        for (size_t i = 0; i < count; i++) {
            BatchEntry e;
            e.method_idx = methods[i].method_idx;
            e.code_off = methods[i].code_off;
            if (prepare_method_decrypt(dex_index, methods[i].method_idx, methods[i].code_off,
                                       view.size, &e.item, &e.plain)) {
                batch->push_back(std::move(e));
            }
        }
    };

    auto apply_batch = [&](std::vector<BatchEntry>& batch, bool use_mprotect) {
        if (batch.empty()) return;
        auto* begin = const_cast<uint8_t*>(view.begin);
        if (use_mprotect) {
            if (!begin_dex_write(begin, view.size, dex_index)) {
                rollback_batch(batch);
                return;
            }
        }
        for (auto& e : batch) {
            commit_method_write(begin, view.size, e.method_idx, e.code_off, e.item, e.plain);
        }
        if (use_mprotect) {
            end_dex_write(begin, view.size, dex_index);
        }
    };

    std::vector<BatchEntry> batch;
    batch.reserve(directs.size() + virtuals.size());
    collect_methods(directs.data(), directs.size(), &batch);
    collect_methods(virtuals.data(), virtuals.size(), &batch);
    apply_batch(batch, true);

    if (descriptor) {
        PLOGD("patch_class %s dex=%d batch=%zu", descriptor, dex_index, batch.size());
    }
}

static bool dex_magic_ok(const uint8_t* begin, size_t size) {
    return size >= 112 && begin[0] == 'd' && begin[1] == 'e' && begin[2] == 'x' && begin[3] == '\n';
}

static bool collect_coded_method_ids(const uint8_t* begin, size_t size,
                                     uint32_t* method_ids_size_out,
                                     std::unordered_set<uint32_t>* out) {
    if (begin == nullptr || out == nullptr || method_ids_size_out == nullptr) return false;
    if (!dex_magic_ok(begin, size)) return false;
    uint32_t method_ids_size = 0;
    memcpy(&method_ids_size, begin + 88, 4);
    *method_ids_size_out = method_ids_size;

    uint32_t class_defs_size = 0;
    uint32_t class_defs_off = 0;
    memcpy(&class_defs_size, begin + 96, 4);
    memcpy(&class_defs_off, begin + 100, 4);
    if (class_defs_off == 0 || class_defs_size == 0) return true;
    if (static_cast<uint64_t>(class_defs_off)
                + static_cast<uint64_t>(class_defs_size) * sizeof(ClassDef) > size) {
        return false;
    }
    auto* defs = reinterpret_cast<const ClassDef*>(begin + class_defs_off);
    for (uint32_t i = 0; i < class_defs_size; i++) {
        const ClassDef& class_def = defs[i];
        if (class_def.class_data_off_ == 0) continue;
        if (static_cast<uint64_t>(class_def.class_data_off_) >= size) continue;
        const uint8_t* class_data = begin + class_def.class_data_off_;
        size_t remain = size - class_def.class_data_off_;
        size_t read = 0;
        bool ok = false;
        uint64_t static_fields = 0, instance_fields = 0, direct_methods = 0, virtual_methods = 0;
        size_t n = read_uleb128(class_data + read, remain - read, &static_fields, &ok);
        if (!ok) return false;
        read += n;
        n = read_uleb128(class_data + read, remain - read, &instance_fields, &ok);
        if (!ok) return false;
        read += n;
        n = read_uleb128(class_data + read, remain - read, &direct_methods, &ok);
        if (!ok) return false;
        read += n;
        n = read_uleb128(class_data + read, remain - read, &virtual_methods, &ok);
        if (!ok) return false;
        read += n;
        if (direct_methods > kMaxMethodsPerClass || virtual_methods > kMaxMethodsPerClass
            || static_fields > kMaxMethodsPerClass || instance_fields > kMaxMethodsPerClass) {
            return false;
        }
        n = skip_fields(class_data + read, remain - read, static_fields, &ok);
        if (!ok) return false;
        read += n;
        n = skip_fields(class_data + read, remain - read, instance_fields, &ok);
        if (!ok) return false;
        read += n;
        std::vector<ClassDataMethod> directs(static_cast<size_t>(direct_methods));
        std::vector<ClassDataMethod> virtuals(static_cast<size_t>(virtual_methods));
        if (direct_methods > 0) {
            n = read_methods(class_data + read, remain - read, directs.data(), direct_methods, &ok);
            if (!ok) return false;
            read += n;
        }
        if (virtual_methods > 0) {
            n = read_methods(class_data + read, remain - read, virtuals.data(), virtual_methods, &ok);
            if (!ok) return false;
        }
        auto take = [&](const ClassDataMethod& m) {
            if (m.code_off != 0) {
                out->insert(m.method_idx);
            }
        };
        for (const auto& m : directs) take(m);
        for (const auto& m : virtuals) take(m);
    }
    return true;
}

bool verify_code_methods_in_extracted_dexes(const char* protector_dir) {
    auto& state = runtime_state();
    if (state.code_map.empty()) {
        return true;
    }
    if (protector_dir == nullptr || protector_dir[0] == '\0') {
        PLOGE("code methods: protector dir empty");
        return false;
    }

    std::unordered_map<int, std::unordered_set<uint32_t>> needed;
    for (const auto& dex : state.code_map) {
        for (const auto& kv : dex.second) {
            if (kv.second == nullptr) continue;
            needed[dex.first].insert(kv.first);
        }
    }
    if (needed.empty()) {
        return true;
    }

    DIR* dir = opendir(protector_dir);
    if (dir == nullptr) {
        PLOGE("code methods: opendir failed %s", protector_dir);
        return false;
    }
    std::unordered_map<int, std::string> dex_files;
    while (dirent* ent = readdir(dir)) {
        if (ent->d_name[0] == '.') continue;
        std::string name = ent->d_name;
        if (name.size() < 5 || name.compare(name.size() - 4, 4, ".dex") != 0) continue;
        if (name.rfind("classes", 0) != 0) continue;
        int dex_index = parse_dex_number(name);
        dex_files[dex_index] = std::string(protector_dir) + "/" + name;
    }
    closedir(dir);

    for (const auto& need : needed) {
        auto it = dex_files.find(need.first);
        if (it == dex_files.end()) {
            PLOGE("code methods: no extracted DEX for dex=%d", need.first);
            return false;
        }
        int fd = open(it->second.c_str(), O_RDONLY | O_CLOEXEC);
        if (fd < 0) {
            PLOGE("code methods: open failed %s errno=%d", it->second.c_str(), errno);
            return false;
        }
        struct stat st {};
        if (fstat(fd, &st) != 0 || st.st_size <= 0) {
            close(fd);
            PLOGE("code methods: stat failed %s", it->second.c_str());
            return false;
        }
        void* map = mmap(nullptr, static_cast<size_t>(st.st_size), PROT_READ, MAP_PRIVATE, fd, 0);
        close(fd);
        if (map == MAP_FAILED) {
            PLOGE("code methods: mmap failed %s errno=%d", it->second.c_str(), errno);
            return false;
        }
        uint32_t method_ids_size = 0;
        std::unordered_set<uint32_t> coded;
        bool ok = collect_coded_method_ids(reinterpret_cast<const uint8_t*>(map),
                                           static_cast<size_t>(st.st_size),
                                           &method_ids_size, &coded);
        munmap(map, static_cast<size_t>(st.st_size));
        if (!ok) {
            PLOGE("code methods: parse DEX failed %s", it->second.c_str());
            return false;
        }
        for (uint32_t idx : need.second) {
            if (idx >= method_ids_size || coded.count(idx) == 0) {
                PLOGE("code methods: dex=%d method_idx=%u missing in extracted DEX",
                      need.first, idx);
                return false;
            }
        }
    }
    PLOGI("code methods: matched extracted DEX dexes=%zu", needed.size());
    return true;
}

/** DEX Adler32 (same as zlib adler32 starting from 1). */
static uint32_t dex_adler32(const uint8_t* data, size_t len) {
    uint32_t a = 1, b = 0;
    for (size_t i = 0; i < len; i++) {
        a += data[i];
        if (a >= 65521) a -= 65521;
        b += a;
        if (b >= 65521) b -= 65521;
    }
    return (b << 16) | a;
}

/** Minimal SHA-1 for DEX signature field. */
static void dex_sha1(const uint8_t* data, size_t len, uint8_t out[20]) {
    uint32_t h0 = 0x67452301, h1 = 0xEFCDAB89, h2 = 0x98BADCFE, h3 = 0x10325476, h4 = 0xC3D2E1F0;
    auto rotr = [](uint32_t x, unsigned n) { return (x << n) | (x >> (32 - n)); };
    auto big32 = [](const uint8_t* p) {
        return (uint32_t(p[0]) << 24) | (uint32_t(p[1]) << 16) | (uint32_t(p[2]) << 8) | uint32_t(p[3]);
    };
    auto put_big32 = [](uint8_t* p, uint32_t v) {
        p[0] = uint8_t(v >> 24); p[1] = uint8_t(v >> 16); p[2] = uint8_t(v >> 8); p[3] = uint8_t(v);
    };

    size_t bit_len = len * 8;
    size_t pad_len = ((len + 8) / 64 + 1) * 64;
    std::vector<uint8_t> buf(pad_len, 0);
    if (len > 0) memcpy(buf.data(), data, len);
    buf[len] = 0x80;
    put_big32(buf.data() + pad_len - 8, static_cast<uint32_t>(bit_len >> 32));
    put_big32(buf.data() + pad_len - 4, static_cast<uint32_t>(bit_len));

    for (size_t off = 0; off < pad_len; off += 64) {
        uint32_t w[80];
        for (int i = 0; i < 16; i++) w[i] = big32(buf.data() + off + i * 4);
        for (int i = 16; i < 80; i++) w[i] = rotr(w[i-3] ^ w[i-8] ^ w[i-14] ^ w[i-16], 1);
        uint32_t a = h0, b = h1, c = h2, d = h3, e = h4;
        for (int i = 0; i < 80; i++) {
            uint32_t f, k;
            if (i < 20) { f = (b & c) | ((~b) & d); k = 0x5A827999; }
            else if (i < 40) { f = b ^ c ^ d; k = 0x6ED9EBA1; }
            else if (i < 60) { f = (b & c) | (b & d) | (c & d); k = 0x8F1BBCDC; }
            else { f = b ^ c ^ d; k = 0xCA62C1D6; }
            uint32_t temp = rotr(a, 5) + f + e + k + w[i];
            e = d; d = c; c = rotr(b, 30); b = a; a = temp;
        }
        h0 += a; h1 += b; h2 += c; h3 += d; h4 += e;
    }
    put_big32(out, h0);
    put_big32(out + 4, h1);
    put_big32(out + 8, h2);
    put_big32(out + 12, h3);
    put_big32(out + 16, h4);
}

/** Refresh signature (SHA-1 @12) + checksum (Adler32 @8) after mutating code items. */
static void rewrite_dex_hashes(uint8_t* begin, size_t size) {
    if (begin == nullptr || size < 32) return;
    uint8_t sig[20];
    dex_sha1(begin + 32, size - 32, sig);
    memcpy(begin + 12, sig, 20);
    uint32_t sum = dex_adler32(begin + 12, size - 12);
    memcpy(begin + 8, &sum, 4);
}

/** Patch one ClassDef into an already-writable mapping (no mprotect). */
static void prepatch_one_class_def(uint8_t* begin, size_t size, int dex_index,
                                   const ClassDef* class_def) {
    if (class_def == nullptr || class_def->class_data_off_ == 0) return;
    if (static_cast<uint64_t>(class_def->class_data_off_) >= size) return;

    const uint8_t* class_data = begin + class_def->class_data_off_;
    size_t remain = size - class_def->class_data_off_;
    size_t read = 0;
    bool ok = false;
    uint64_t static_fields = 0, instance_fields = 0, direct_methods = 0, virtual_methods = 0;

    size_t n = read_uleb128(class_data + read, remain - read, &static_fields, &ok);
    if (!ok) return;
    read += n;
    n = read_uleb128(class_data + read, remain - read, &instance_fields, &ok);
    if (!ok) return;
    read += n;
    n = read_uleb128(class_data + read, remain - read, &direct_methods, &ok);
    if (!ok) return;
    read += n;
    n = read_uleb128(class_data + read, remain - read, &virtual_methods, &ok);
    if (!ok) return;
    read += n;

    if (direct_methods > kMaxMethodsPerClass || virtual_methods > kMaxMethodsPerClass
        || static_fields > kMaxMethodsPerClass || instance_fields > kMaxMethodsPerClass) {
        return;
    }

    n = skip_fields(class_data + read, remain - read, static_fields, &ok);
    if (!ok) return;
    read += n;
    n = skip_fields(class_data + read, remain - read, instance_fields, &ok);
    if (!ok) return;
    read += n;

    std::vector<ClassDataMethod> directs(static_cast<size_t>(direct_methods));
    std::vector<ClassDataMethod> virtuals(static_cast<size_t>(virtual_methods));
    if (direct_methods > 0) {
        n = read_methods(class_data + read, remain - read, directs.data(), direct_methods, &ok);
        if (!ok) return;
        read += n;
    }
    if (virtual_methods > 0) {
        n = read_methods(class_data + read, remain - read, virtuals.data(), virtual_methods, &ok);
        if (!ok) return;
    }

    struct BatchEntry {
        uint32_t method_idx = 0;
        uint32_t code_off = 0;
        CodeItem* item = nullptr;
        std::vector<uint8_t> plain;
    };
    std::vector<BatchEntry> batch;
    batch.reserve(directs.size() + virtuals.size());
    auto enqueue = [&](const ClassDataMethod& m) {
        BatchEntry e;
        e.method_idx = m.method_idx;
        e.code_off = m.code_off;
        if (prepare_method_decrypt(dex_index, m.method_idx, m.code_off, size, &e.item, &e.plain)) {
            batch.push_back(std::move(e));
        }
    };
    for (auto& m : directs) enqueue(m);
    for (auto& m : virtuals) enqueue(m);
    for (auto& e : batch) {
        commit_method_write(begin, size, e.method_idx, e.code_off, e.item, e.plain);
    }
}

static void prepatch_dex_memory(uint8_t* begin, size_t size, int dex_index) {
    if (!dex_magic_ok(begin, size)) {
        PLOGE("prepatch bad dex magic dex=%d", dex_index);
        return;
    }
    uint32_t class_defs_size = 0;
    uint32_t class_defs_off = 0;
    memcpy(&class_defs_size, begin + 96, 4);
    memcpy(&class_defs_off, begin + 100, 4);
    if (class_defs_off == 0 || class_defs_size == 0) return;
    if (static_cast<uint64_t>(class_defs_off)
                + static_cast<uint64_t>(class_defs_size) * sizeof(ClassDef) > size) {
        PLOGE("prepatch class_defs OOB dex=%d", dex_index);
        return;
    }
    auto* defs = reinterpret_cast<const ClassDef*>(begin + class_defs_off);
    size_t patched_classes = 0;
    for (uint32_t i = 0; i < class_defs_size; i++) {
        prepatch_one_class_def(begin, size, dex_index, &defs[i]);
        patched_classes++;
    }
    rewrite_dex_hashes(begin, size);
    PLOGI("prepatch dex=%d class_defs=%u done", dex_index, class_defs_size);
    (void)patched_classes;
}

static bool prepatch_dex_file(const char* path, int dex_index) {
    if (path == nullptr) return false;
    int fd = open(path, O_RDWR);
    if (fd < 0) {
        PLOGE("prepatch open failed %s errno=%d", path, errno);
        return false;
    }
    struct stat st{};
    if (fstat(fd, &st) != 0 || st.st_size <= 0) {
        close(fd);
        return false;
    }
    size_t size = static_cast<size_t>(st.st_size);
    void* map = mmap(nullptr, size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (map == MAP_FAILED) {
        PLOGE("prepatch mmap failed %s errno=%d", path, errno);
        close(fd);
        return false;
    }
    prepatch_dex_memory(reinterpret_cast<uint8_t*>(map), size, dex_index);
    if (msync(map, size, MS_SYNC) != 0) {
        PLOGW("prepatch msync failed %s", path);
    }
    munmap(map, size);
    close(fd);
    return true;
}

void prepatch_extracted_dexes(const char* protector_dir) {
    if (protector_dir == nullptr || protector_dir[0] == '\0') return;
    auto& state = runtime_state();
    if (!state.inited.load()) {
        PLOGW("prepatch skipped: runtime not inited");
        return;
    }

    DIR* dir = opendir(protector_dir);
    if (dir == nullptr) {
        PLOGE("prepatch opendir failed %s", protector_dir);
        return;
    }

    struct Job {
        std::string path;
        int dex_index;
    };
    std::vector<Job> jobs;
    while (dirent* ent = readdir(dir)) {
        if (ent->d_name[0] == '.') continue;
        std::string name = ent->d_name;
        if (name.size() < 5 || name.compare(name.size() - 4, 4, ".dex") != 0) continue;
        if (name.rfind("classes", 0) != 0) continue;
        int dex_index = parse_dex_number(name);
        jobs.push_back(Job{std::string(protector_dir) + "/" + name, dex_index});
    }
    closedir(dir);

    if (jobs.empty()) {
        PLOGW("prepatch: no classes*.dex under %s", protector_dir);
        return;
    }

    PLOGI("prepatch start files=%zu", jobs.size());
    int64_t t0 = mono_ns();
    std::vector<std::thread> threads;
    threads.reserve(jobs.size());
    for (const auto& job : jobs) {
        threads.emplace_back([job] {
            prepatch_dex_file(job.path.c_str(), job.dex_index);
        });
    }
    for (auto& t : threads) {
        t.join();
    }
    int64_t ms = (mono_ns() - t0) / 1000000LL;
    PLOGI("prepatch finished files=%zu cost_ms=%lld", jobs.size(),
          static_cast<long long>(ms));
}

} // namespace protector::dex
