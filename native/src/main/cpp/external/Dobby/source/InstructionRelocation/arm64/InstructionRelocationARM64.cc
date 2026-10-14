#include "platform_macro.h"

#if defined(TARGET_ARCH_ARM64)

#include "InstructionRelocation/arm64/InstructionRelocationARM64.h"

#include "dobby_internal.h"

#include "core/arch/arm64/registers-arm64.h"
#include "core/assembler/assembler-arm64.h"
#include "core/codegen/codegen-arm64.h"

#include "inst_constants.h"
#include "inst_decode_encode_kit.h"

using namespace zz::arm64;

#if defined(DOBBY_DEBUG)
#define debug_nop() _ nop()
#else
#define debug_nop()
#endif

#define arm64_trunc_page(x) ((x) & (~(0x1000 - 1)))
#define arm64_round_page(x) trunc_page((x) + (0x1000 - 1))

typedef struct {
  addr_t mapped_addr;

  uint8_t *buffer;
  uint8_t *buffer_cursor;
  size_t buffer_size;

  vmaddr_t src_vmaddr;
  vmaddr_t dst_vmaddr;

  CodeMemBlock *origin;
  CodeMemBlock *relocated;

  tinystl::unordered_map<off_t, off_t> relocated_offset_map;

  tinystl::unordered_map<vmaddr_t, AssemblerPseudoLabel *> label_map;

} relo_ctx_t;

// ---

addr_t relo_cur_src_vmaddr(relo_ctx_t *ctx) {
  return ctx->src_vmaddr + (ctx->buffer_cursor - ctx->buffer);
}

addr_t relo_cur_dst_vmaddr(relo_ctx_t *ctx, TurboAssembler *assembler) {
  return ctx->dst_vmaddr + assembler->GetCodeBuffer()->GetBufferSize();
}

addr_t relo_src_offset_to_vmaddr(relo_ctx_t *ctx, off_t offset) {
  return ctx->src_vmaddr + offset;
}

addr_t relo_dst_offset_to_vmaddr(relo_ctx_t *ctx, off_t offset) {
  return ctx->dst_vmaddr + offset;
}

// ---

#if 0
bool has_relo_label_at(relo_ctx_t *ctx, vmaddr_t addr) {
  if (ctx->label_map.count(addr)) {
    return true;
  }
  return false;
}

AssemblerPseudoLabel *relo_label_create_or_get(relo_ctx_t *ctx, vmaddr_t addr) {
  if (!ctx->label_map.count(addr)) {
    auto *label = new AssemblerPseudoLabel(addr);
    ctx->label_map[addr] = label;
  }
  return ctx->label_map[addr];
}

int64_t relo_label_link_offset(relo_ctx_t *ctx, pcrel_type_t pcrel_type, int64_t offset) {
  auto is_offset_undefined = [ctx](int64_t offset) -> bool {
    if (ctx->buffer_cursor + offset < ctx->buffer || ctx->buffer_cursor + offset > ctx->buffer + ctx->buffer_size) {
      return true;
    }
    return false;
  };

  auto is_offset_uninitialized = [ctx](int64_t offset) -> bool {
    if (ctx->buffer_cursor + offset > ctx->buffer && ctx->buffer_cursor + offset < ctx->buffer + ctx->buffer_size) {
      if (!ctx->relocated_offset_map.count(ctx->buffer_cursor + offset - ctx->buffer_cursor))
        return true;
    }
    return false;
  };

  addr_t label_vmaddr = relo_cur_src_vmaddr(ctx) + offset;
  if (pcrel_type == RELO_ARM64_RELOC_PAGE21) {
    label_vmaddr = arm64_trunc_page(label_vmaddr);
  }

  auto *label = relo_label_create_or_get(ctx, label_vmaddr);
  if (is_offset_undefined(offset)) { // pc relative target is beyond our scope
    label->link_to(AssemblerPseudoLabel::kLabelImm19, relo_cur_src_vmaddr(ctx), (addr_t)ctx->buffer_cursor - ctx->mapped_addr);
    return 0;
  } else if (is_offset_uninitialized(offset)) { // pc relative target is in our control, but not handle yet
    label->link_to(AssemblerPseudoLabel::kLabelImm19, relo_cur_src_vmaddr(ctx), (addr_t)ctx->buffer_cursor - ctx->mapped_addr);
    return 0;
  } else { // pc relative target is already handled
    off_t off = ctx->buffer_cursor + offset - ctx->buffer;
    off_t relocated_off = label->relocated_pos();
    int64_t new_offset = relo_dst_offset_to_vmaddr(ctx, relocated_off) - relo_src_offset_to_vmaddr(ctx, off);
    return new_offset;
  }
}
#endif

// ---

static inline bool inst_is_b_bl(uint32_t instr) {
  return (instr & UnconditionalBranchFixedMask) == UnconditionalBranchFixed;
}

static inline bool inst_is_ldr_literal(uint32_t instr) {
  return ((instr & LoadRegLiteralFixedMask) == LoadRegLiteralFixed);
}

static inline bool inst_is_adr(uint32_t instr) {
  return (instr & PCRelAddressingFixedMask) == PCRelAddressingFixed && (instr & PCRelAddressingMask) == ADR;
}

static inline bool inst_is_adrp(uint32_t instr) {
  return (instr & PCRelAddressingFixedMask) == PCRelAddressingFixed && (instr & PCRelAddressingMask) == ADRP;
}

static inline bool inst_is_b_cond(uint32_t instr) {
  return (instr & ConditionalBranchFixedMask) == ConditionalBranchFixed;
}

static inline bool inst_is_compare_b(uint32_t instr) {
  return (instr & CompareBranchFixedMask) == CompareBranchFixed;
}

static inline bool inst_is_test_b(uint32_t instr) {
  return (instr & TestBranchFixedMask) == TestBranchFixed;
}

struct LocalBranchFix {
  uint32_t b_off;
  uint32_t target_off;
};

static bool dst_in_origin_window(relo_ctx_t *ctx, addr_t dst, uint32_t *off) {
  if (dst < ctx->src_vmaddr)
    return false;
  addr_t rel = dst - ctx->src_vmaddr;
  if (rel >= ctx->buffer_size || (rel & 3) != 0)
    return false;
  *off = (uint32_t)rel;
  return true;
}

// Bytes emitted by emit_taken_sequence for this target.
static int taken_sequence_bytes(relo_ctx_t *ctx, addr_t dst, int nfixes) {
  uint32_t off = 0;
  if (dst_in_origin_window(ctx, dst, &off) && nfixes < 32)
    return 4;
  uint32_t replay = 0;
  if (arm64_make_bti_landing(dst, &replay))
    return (replay != 0 ? 4 : 0) + 8;
  return 8;
}

// Branch to dst. Targets inside the patched prologue go to the relocated
// copy — the original bytes are the hook trampoline. Other targets get a
// BTI landing pad so the indirect branch is legal on Android 14+.
static void emit_taken_sequence(relo_ctx_t *ctx, TurboAssembler &as, LocalBranchFix *fixes, int *nfixes,
                                addr_t dst, bool is_call) {
  uint32_t target_off = 0;
  if (dst_in_origin_window(ctx, dst, &target_off) && *nfixes < 32) {
    uint32_t b_off = (uint32_t)as.GetCodeBuffer()->GetBufferSize();
    as.Emit(is_call ? 0x94000000u : 0x14000000u);
    fixes[(*nfixes)++] = LocalBranchFix{b_off, target_off};
    return;
  }
  uint32_t replay = 0;
  addr_t land = dst;
  if (!arm64_make_bti_landing(dst, &replay)) {
    land = arm64_bti_direct_landing(dst);
    replay = 0;
  }
  if (replay != 0)
    as.Emit(replay);
  RelocLabel *dst_label = new RelocLabel(land);
  as.AppendRelocLabel(dst_label);
  as.Ldr(TMP_REG_0, dst_label);
  if (is_call)
    as.blr(TMP_REG_0);
  else
    as.br(TMP_REG_0);
}

// ---

int relo_relocate(relo_ctx_t *ctx, bool branch) {
  int relocated_insn_count = 0;

  TurboAssembler turbo_assembler_(0);
#define _ turbo_assembler_.

  auto relocated_buffer = turbo_assembler_.GetCodeBuffer();
  LocalBranchFix fixes[32];
  int nfixes = 0;

  while (ctx->buffer_cursor < ctx->buffer + ctx->buffer_size) {
    uint32_t orig_off = ctx->buffer_cursor - ctx->buffer;
    uint32_t relocated_off = relocated_buffer->GetBufferSize();
    ctx->relocated_offset_map[orig_off] = relocated_off;

#if 0
    vmaddr_t inst_vmaddr = 0;
    inst_vmaddr = relo_cur_src_vmaddr(ctx);
    if (has_relo_label_at(ctx, inst_vmaddr)) {
      auto *label = relo_label_create_or_get(ctx, inst_vmaddr);
      label->bind_to(inst_vmaddr);
    }
#endif

    arm64_inst_t inst = *(arm64_inst_t *)ctx->buffer_cursor;
    if (inst_is_b_bl(inst)) {
      DLOG(0, "%d:relo <b_bl> at %p", relocated_insn_count++, relo_cur_src_vmaddr(ctx));

      int64_t offset = decode_imm26_offset(inst);
      addr_t dst_vmaddr = relo_cur_src_vmaddr(ctx) + offset;
      bool is_call = (inst & UnconditionalBranchMask) == BL;
      emit_taken_sequence(ctx, turbo_assembler_, fixes, &nfixes, dst_vmaddr, is_call);

    } else if (inst_is_ldr_literal(inst)) {
      DLOG(0, "%d:relo <ldr_literal> at %p", relocated_insn_count++, relo_cur_src_vmaddr(ctx));

      int64_t offset = decode_imm19_offset(inst);
      addr_t dst_vmaddr = relo_cur_src_vmaddr(ctx) + offset;

      int rt = decode_rt(inst);
      char opc = bits(inst, 30, 31);

      {
        _ Mov(TMP_REG_0, dst_vmaddr);
        if (opc == 0b00)
          _ ldr(W(rt), MemOperand(TMP_REG_0, 0));
        else if (opc == 0b01)
          _ ldr(X(rt), MemOperand(TMP_REG_0, 0));
        else {
          UNIMPLEMENTED();
        }
      }
    } else if (inst_is_adr(inst)) {
      DLOG(0, "%d:relo <adr> at %p", relocated_insn_count++, relo_cur_src_vmaddr(ctx));

      int64_t offset = decode_immhi_immlo_offset(inst);
      addr_t dst_vmaddr = relo_cur_src_vmaddr(ctx) + offset;

      int rd = decode_rd(inst);

      {
        _ Mov(X(rd), dst_vmaddr);
        ;
      }
    } else if (inst_is_adrp(inst)) {
      DLOG(0, "%d:relo <adrp> at %p", relocated_insn_count++, relo_cur_src_vmaddr(ctx));

      int64_t offset = decode_immhi_immlo_zero12_offset(inst);
      addr_t dst_vmaddr = relo_cur_src_vmaddr(ctx) + offset;
      dst_vmaddr = arm64_trunc_page(dst_vmaddr);

      int rd = decode_rd(inst);

      {
        _ Mov(X(rd), dst_vmaddr);
        ;
      }
    } else if (inst_is_b_cond(inst)) {
      DLOG(0, "%d:relo <b_cond> at %p", relocated_insn_count++, relo_cur_src_vmaddr(ctx));

      int64_t offset = decode_imm19_offset(inst);
      addr_t dst_vmaddr = relo_cur_src_vmaddr(ctx) + offset;

      arm64_inst_t branch_instr = inst;
      {
        char cond = bits(inst, 0, 3);
        cond = cond ^ 1;
        set_bits(branch_instr, 0, 3, cond);

        int64_t skip = 4 + taken_sequence_bytes(ctx, dst_vmaddr, nfixes);
        uint32_t imm19 = (uint32_t)skip >> 2;
        set_bits(branch_instr, 5, 23, imm19);
      }

      _ Emit(branch_instr);
      emit_taken_sequence(ctx, turbo_assembler_, fixes, &nfixes, dst_vmaddr, false);
    } else if (inst_is_compare_b(inst)) {
      DLOG(0, "%d:relo <compare_b> at %p", relocated_insn_count++, relo_cur_src_vmaddr(ctx));

      int64_t offset = decode_imm19_offset(inst);
      addr_t dst_vmaddr = relo_cur_src_vmaddr(ctx) + offset;

      arm64_inst_t branch_instr = inst;
      {
        char op = bit(inst, 24);
        op = op ^ 1;
        set_bit(branch_instr, 24, op);

        int64_t skip = 4 + taken_sequence_bytes(ctx, dst_vmaddr, nfixes);
        uint32_t imm19 = (uint32_t)skip >> 2;
        set_bits(branch_instr, 5, 23, imm19);
      }

      _ Emit(branch_instr);
      emit_taken_sequence(ctx, turbo_assembler_, fixes, &nfixes, dst_vmaddr, false);
    } else if (inst_is_test_b(inst)) {
      DLOG(0, "%d:relo <test_b> at %p", relocated_insn_count++, relo_cur_src_vmaddr(ctx));

      int64_t offset = decode_imm14_offset(inst);
      addr_t dst_vmaddr = relo_cur_src_vmaddr(ctx) + offset;

      arm64_inst_t branch_instr = inst;
      {
        char op = bit(inst, 24);
        op = op ^ 1;
        set_bit(branch_instr, 24, op);

        int64_t skip = 4 + taken_sequence_bytes(ctx, dst_vmaddr, nfixes);
        uint32_t imm14 = (uint32_t)skip >> 2;
        set_bits(branch_instr, 5, 18, imm14);
      }

      _ Emit(branch_instr);
      emit_taken_sequence(ctx, turbo_assembler_, fixes, &nfixes, dst_vmaddr, false);
    } else {
      _ Emit(inst);
    }

    ctx->buffer_cursor += sizeof(arm64_inst_t);
  }
#undef _

  // update origin
  int new_origin_len = (addr_t)ctx->buffer_cursor - (addr_t)ctx->buffer;
  ctx->origin->reset(ctx->origin->addr, new_origin_len);

  // TODO: if last instr is unlink branch, ignore it
  if (branch) {
    CodeGen codegen(&turbo_assembler_);
    codegen.LiteralLdrBranch(ctx->origin->addr + ctx->origin->size);
  }

  for (int i = 0; i < nfixes; i++) {
    off_t dest = ctx->relocated_offset_map[(off_t)fixes[i].target_off];
    int64_t distance = (int64_t)dest - (int64_t)fixes[i].b_off;
    uint32_t old = (uint32_t)relocated_buffer->LoadInst(fixes[i].b_off);
    uint32_t insn = (old & 0xFC000000u) | ((uint32_t)(distance >> 2) & 0x03ffffffu);
    relocated_buffer->RewriteInst(fixes[i].b_off, (arm64_inst_t)insn);
  }

  // Bind all labels
  turbo_assembler_.RelocBind();

  // Generate executable code
  {
    auto code = AssemblyCodeBuilder::FinalizeFromTurboAssembler(&turbo_assembler_);
    ctx->relocated = code;
  }
  return 0;
}

void GenRelocateCode(void *buffer, CodeMemBlock *origin, CodeMemBlock *relocated, bool branch) {
  relo_ctx_t ctx = {0};

  ctx.buffer = ctx.buffer_cursor = (uint8_t *)buffer;
  ctx.buffer_size = origin->size;

  ctx.src_vmaddr = (vmaddr_t)origin->addr;
  ctx.dst_vmaddr = (vmaddr_t)relocated->addr;

  ctx.origin = origin;

  relo_relocate(&ctx, branch);

  relocated->reset(ctx.relocated->addr, ctx.relocated->size);
}

void GenRelocateCodeAndBranch(void *buffer, CodeMemBlock *origin, CodeMemBlock *relocated) {
  GenRelocateCode(buffer, origin, relocated, true);
}

#endif
