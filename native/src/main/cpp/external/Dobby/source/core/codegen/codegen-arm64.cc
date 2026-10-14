#include "platform_macro.h"
#if defined(TARGET_ARCH_ARM64)

#include "dobby_internal.h"
#include "core/codegen/codegen-arm64.h"

#include <android/log.h>
#include <pthread.h>
#include <stdio.h>
#include <sys/mman.h>

#ifndef MAP_FIXED_NOREPLACE
#define MAP_FIXED_NOREPLACE 0x100000
#endif

namespace zz {
namespace arm64 {

// imm26 reaches [-128MB, +128MB). Keep the stub inside that window.
static bool branch_distance_ok(addr_t stub, addr_t target) {
  int64_t distance = (int64_t)target - (int64_t)stub;
  return (distance & 3) == 0 && distance > -(1ll << 27) && distance < (1ll << 27) && distance != 0;
}

static addr_t alloc_bti_stub(addr_t target) {
  const long page = sysconf(_SC_PAGESIZE) > 0 ? sysconf(_SC_PAGESIZE) : 4096;
  const uintptr_t page_mask = (uintptr_t)page - 1;

  FILE *fp = fopen("/proc/self/maps", "r");
  if (fp == nullptr)
    return 0;

  struct Span {
    uintptr_t start;
    uintptr_t end;
  };
  Span spans[512];
  int nspans = 0;
  char line[512];
  while (nspans < 512 && fgets(line, sizeof(line), fp) != nullptr) {
    unsigned long start = 0, end = 0;
    if (sscanf(line, "%lx-%lx", &start, &end) != 2 || end <= start)
      continue;
    spans[nspans].start = (uintptr_t)start;
    spans[nspans].end = (uintptr_t)end;
    nspans++;
  }
  fclose(fp);
  if (nspans < 2)
    return 0;
  for (int i = 1; i < nspans; i++) {
    Span key = spans[i];
    int j = i;
    while (j > 0 && spans[j - 1].start > key.start) {
      spans[j] = spans[j - 1];
      j--;
    }
    spans[j] = key;
  }

  struct Gap {
    uintptr_t addr;
    uint64_t dist;
  };
  Gap gaps[48];
  int ngaps = 0;
  for (int i = 0; i + 1 < nspans; i++) {
    uintptr_t gap_start = (spans[i].end + page_mask) & ~page_mask;
    uintptr_t gap_end = spans[i + 1].start & ~page_mask;
    if (gap_end < gap_start + (uintptr_t)page)
      continue;
    if (!branch_distance_ok((addr_t)gap_start, target))
      continue;
    uint64_t dist = (uint64_t)llabs((int64_t)target - (int64_t)gap_start);
    if (ngaps < 48) {
      gaps[ngaps++] = Gap{(uintptr_t)gap_start, dist};
    } else {
      int worst = 0;
      for (int g = 1; g < ngaps; g++) {
        if (gaps[g].dist > gaps[worst].dist)
          worst = g;
      }
      if (dist < gaps[worst].dist)
        gaps[worst] = Gap{(uintptr_t)gap_start, dist};
    }
  }

  for (int i = 1; i < ngaps; i++) {
    Gap key = gaps[i];
    int j = i;
    while (j > 0 && gaps[j - 1].dist > key.dist) {
      gaps[j] = gaps[j - 1];
      j--;
    }
    gaps[j] = key;
  }

  for (int i = 0; i < ngaps; i++) {
    void *mapped = mmap((void *)gaps[i].addr, (size_t)page, PROT_READ | PROT_EXEC,
                        MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, -1, 0);
    if (mapped != (void *)gaps[i].addr) {
      if (mapped != MAP_FAILED)
        munmap(mapped, (size_t)page);
      continue;
    }
    int64_t distance = (int64_t)target - (int64_t)mapped;
    uint32_t imm26 = (uint32_t)(distance >> 2) & 0x03ffffffu;
    uint32_t b_insn = 0x14000000u | imm26;
    if (DobbyCodePatch(mapped, (uint8_t *)&b_insn, sizeof(b_insn)) != kMemoryOperationSuccess) {
      munmap(mapped, (size_t)page);
      continue;
    }
    return (addr_t)mapped;
  }
  return 0;
}

static bool insn_is_pc_relative(uint32_t inst) {
  if ((inst & 0xFC000000u) == 0x14000000u || (inst & 0xFC000000u) == 0x94000000u)
    return true; // b / bl
  if ((inst & 0xFF000010u) == 0x54000000u)
    return true; // b.cond
  if ((inst & 0x7E000000u) == 0x34000000u || (inst & 0x7E000000u) == 0x36000000u)
    return true; // cbz / tbz
  if ((inst & 0x9F000000u) == 0x10000000u || (inst & 0x9F000000u) == 0x90000000u)
    return true; // adr / adrp
  if ((inst & 0x3B000000u) == 0x18000000u)
    return true; // ldr literal
  return false;
}

bool arm64_make_bti_landing(addr_t target, uint32_t *replay) {
  if (replay != nullptr)
    *replay = 0;
  if (target == 0 || (target & 3) != 0 || replay == nullptr)
    return false;

  struct Slot {
    addr_t target;
    uint32_t replay;
    bool used;
  };
  static Slot slots[128];
  static pthread_mutex_t mu = PTHREAD_MUTEX_INITIALIZER;

  pthread_mutex_lock(&mu);
  for (const Slot &slot : slots) {
    if (slot.used && slot.target == target) {
      *replay = slot.replay;
      pthread_mutex_unlock(&mu);
      return true;
    }
  }
  pthread_mutex_unlock(&mu);

  uint32_t insn = *reinterpret_cast<uint32_t *>(target);
  const uint32_t kBtiC = 0xd503245fu;
  const uint32_t kBtiJ = 0xd503249fu;
  const uint32_t kBtiJc = 0xd50324dfu;
  uint32_t stolen = 0;
  if (insn != kBtiJc) {
    if (insn != kBtiC && insn != kBtiJ) {
      if (insn_is_pc_relative(insn))
        return false;
      stolen = insn;
    }
    if (DobbyCodePatch(reinterpret_cast<void *>(target), (uint8_t *)&kBtiJc, sizeof(kBtiJc)) !=
        kMemoryOperationSuccess)
      return false;
  }

  pthread_mutex_lock(&mu);
  for (Slot &slot : slots) {
    if (slot.used && slot.target == target) {
      *replay = slot.replay;
      pthread_mutex_unlock(&mu);
      return true;
    }
  }
  for (Slot &slot : slots) {
    if (!slot.used) {
      slot.used = true;
      slot.target = target;
      slot.replay = stolen;
      break;
    }
  }
  pthread_mutex_unlock(&mu);
  *replay = stolen;
  return true;
}

addr_t arm64_bti_direct_landing(addr_t target) {
  if (target == 0 || (target & 3) != 0)
    return target;

  struct Slot {
    addr_t target;
    addr_t stub;
  };
  static Slot slots[128];
  static pthread_mutex_t mu = PTHREAD_MUTEX_INITIALIZER;

  pthread_mutex_lock(&mu);
  for (const Slot &slot : slots) {
    if (slot.target == target && slot.stub != 0) {
      addr_t cached = slot.stub;
      pthread_mutex_unlock(&mu);
      return cached;
    }
  }

  addr_t stub = alloc_bti_stub(target);
  if (stub == 0 || !branch_distance_ok(stub, target)) {
    pthread_mutex_unlock(&mu);
    __android_log_print(ANDROID_LOG_ERROR, "protector",
                        "bti stub alloc failed target=%p", (void *)target);
    return target;
  }

  for (Slot &slot : slots) {
    if (slot.target == 0 || slot.target == target) {
      slot.target = target;
      slot.stub = stub;
      break;
    }
  }
  pthread_mutex_unlock(&mu);
  return stub;
}

void CodeGen::LiteralLdrBranch(uint64_t address) {
  auto turbo_assembler_ = reinterpret_cast<TurboAssembler *>(this->assembler_);
#define _ turbo_assembler_->

  uint32_t replay = 0;
  if (!arm64_make_bti_landing((addr_t)address, &replay)) {
    address = arm64_bti_direct_landing((addr_t)address);
    replay = 0;
  }
  if (replay != 0)
    _ Emit(replay);

  auto dst_label = new RelocLabel(address);
  turbo_assembler_->AppendRelocLabel(dst_label);

  _ Ldr(TMP_REG_0, dst_label);
  _ br(TMP_REG_0);

#undef _
}

} // namespace arm64
} // namespace zz

#endif
