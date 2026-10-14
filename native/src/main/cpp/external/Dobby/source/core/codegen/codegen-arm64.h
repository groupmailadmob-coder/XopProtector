#ifndef CORE_CODEGEN_ARM64_H
#define CORE_CODEGEN_ARM64_H

#include "core/codegen/codegen.h"
#include "core/assembler/assembler.h"
#include "core/assembler/assembler-arm64.h"

namespace zz {
namespace arm64 {

class CodeGen : public CodeGenBase {
public:
  CodeGen(TurboAssembler *turbo_assembler) : CodeGenBase(turbo_assembler) {
  }
  void LiteralLdrBranch(uint64_t address);
};

// Indirect BR/BLR into a BTI-guarded page (Android 14+ linker / libart) raises
// SIGILL unless the landing instruction is a BTI. Prefer planting `bti jc` and
// replaying the stolen instruction; the near direct-B stub is the fallback.
addr_t arm64_bti_direct_landing(addr_t target);
// On success, execute `*replay` (0 if none) immediately before branching to target.
bool arm64_make_bti_landing(addr_t target, uint32_t *replay);

} // namespace arm64
} // namespace zz

#endif