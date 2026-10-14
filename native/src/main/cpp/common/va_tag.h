#pragma once

#include <cstdint>

/**
 * Drop the arm64 top-byte tag (TBI / MTE). Untagged pointers (top byte 0)
 * are unchanged, so every API level uses the same path.
 * Kernel process_vm_readv on older Android 11 devices faults on a tagged
 * address (EFAULT) and does not fall back.
 */
static inline uintptr_t strip_va_tag(uintptr_t p) {
#if defined(__aarch64__)
    return p & 0x00FFFFFFFFFFFFFFULL;
#else
    return p;
#endif
}

template <typename T>
static inline T* untag_ptr(T* p) {
    return reinterpret_cast<T*>(strip_va_tag(reinterpret_cast<uintptr_t>(p)));
}
