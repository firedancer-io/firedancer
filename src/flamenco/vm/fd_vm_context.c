#include "fd_vm_context.h"

ulong
fd_vm_consume_compute_meter(fd_vm_exec_context_t * ctx, ulong cost) {
  ulong exceeded = ctx->compute_meter < cost;
  ctx->compute_meter = fd_ulong_sat_sub(ctx->compute_meter, cost);
  // FD_LOG_WARNING(("CUs! consumed %lu cost %lu", ctx->compute_meter, cost));
  return exceeded;
}

// Opcode validation success/error codes.
#define FD_VALID        (0) /* Valid opcode */
#define FD_CHECK_JMP    (1) /* Validation should check that the instruction is a valid jump */
#define FD_CHECK_END    (2) /* Validation should check that the instruction is a valid endianness conversion */
#define FD_CHECK_ST     (3) /* Validation should check that the instruction is a valid store */
#define FD_CHECK_LDQ    (4) /* Validation should check that the instruction is a valid load-quad */
#define FD_CHECK_CALL   (5) /* Validation should check that the instruction is a valid function call */
#define FD_INVALID      (6) /* The opcode is invalid */

// A mapping of all the possible 1-byte sBPF opcodes to their validation criteria.
uchar const FD_OPCODE_VALIDATION_MAP[256] = {
  /* 0x00 */ FD_INVALID,    /* 0x01 */ FD_INVALID,    /* 0x02 */ FD_INVALID,    /* 0x03 */ FD_INVALID,
  /* 0x04 */ FD_VALID,      /* 0x05 */ FD_CHECK_JMP,  /* 0x06 */ FD_INVALID,    /* 0x07 */ FD_VALID,
  /* 0x08 */ FD_INVALID,    /* 0x09 */ FD_INVALID,    /* 0x0a */ FD_INVALID,    /* 0x0b */ FD_INVALID,
  /* 0x0c */ FD_VALID,      /* 0x0d */ FD_INVALID,    /* 0x0e */ FD_INVALID,    /* 0x0f */ FD_VALID,
  /* 0x10 */ FD_INVALID,    /* 0x11 */ FD_INVALID,    /* 0x12 */ FD_INVALID,    /* 0x13 */ FD_INVALID,
  /* 0x14 */ FD_VALID,      /* 0x15 */ FD_CHECK_JMP,  /* 0x16 */ FD_CHECK_JMP,  /* 0x17 */ FD_VALID,
  /* 0x18 */ FD_CHECK_LDQ,  /* 0x19 */ FD_INVALID,    /* 0x1a */ FD_INVALID,    /* 0x1b */ FD_INVALID,
  /* 0x1c */ FD_VALID,      /* 0x1d */ FD_CHECK_JMP,  /* 0x1e */ FD_CHECK_JMP,  /* 0x1f */ FD_VALID,
  /* 0x20 */ FD_INVALID,    /* 0x21 */ FD_INVALID,    /* 0x22 */ FD_INVALID,    /* 0x23 */ FD_INVALID,
  /* 0x24 */ FD_VALID,      /* 0x25 */ FD_CHECK_JMP,  /* 0x26 */ FD_CHECK_JMP,  /* 0x27 */ FD_VALID,
  /* 0x28 */ FD_INVALID,    /* 0x29 */ FD_INVALID,    /* 0x2a */ FD_INVALID,    /* 0x2b */ FD_INVALID,
  /* 0x2c */ FD_VALID,      /* 0x2d */ FD_CHECK_JMP,  /* 0x2e */ FD_CHECK_JMP,  /* 0x2f */ FD_VALID,
  /* 0x30 */ FD_INVALID,    /* 0x31 */ FD_INVALID,    /* 0x32 */ FD_INVALID,    /* 0x33 */ FD_INVALID,
  /* 0x34 */ FD_VALID,      /* 0x35 */ FD_CHECK_JMP,  /* 0x36 */ FD_CHECK_JMP,  /* 0x37 */ FD_VALID,
  /* 0x38 */ FD_INVALID,    /* 0x39 */ FD_INVALID,    /* 0x3a */ FD_INVALID,    /* 0x3b */ FD_INVALID,
  /* 0x3c */ FD_VALID,      /* 0x3d */ FD_CHECK_JMP,  /* 0x3e */ FD_CHECK_JMP,  /* 0x3f */ FD_VALID,
  /* 0x40 */ FD_INVALID,    /* 0x41 */ FD_INVALID,    /* 0x42 */ FD_INVALID,    /* 0x43 */ FD_INVALID,
  /* 0x44 */ FD_VALID,      /* 0x45 */ FD_CHECK_JMP,  /* 0x46 */ FD_CHECK_JMP,  /* 0x47 */ FD_VALID,
  /* 0x48 */ FD_INVALID,    /* 0x49 */ FD_INVALID,    /* 0x4a */ FD_INVALID,    /* 0x4b */ FD_INVALID,
  /* 0x4c */ FD_VALID,      /* 0x4d */ FD_CHECK_JMP,  /* 0x4e */ FD_CHECK_JMP,  /* 0x4f */ FD_VALID,
  /* 0x50 */ FD_INVALID,    /* 0x51 */ FD_INVALID,    /* 0x52 */ FD_INVALID,    /* 0x53 */ FD_INVALID,
  /* 0x54 */ FD_VALID,      /* 0x55 */ FD_CHECK_JMP,  /* 0x56 */ FD_CHECK_JMP,  /* 0x57 */ FD_VALID,
  /* 0x58 */ FD_INVALID,    /* 0x59 */ FD_INVALID,    /* 0x5a */ FD_INVALID,    /* 0x5b */ FD_INVALID,
  /* 0x5c */ FD_VALID,      /* 0x5d */ FD_CHECK_JMP,  /* 0x5e */ FD_CHECK_JMP,  /* 0x5f */ FD_VALID,
  /* 0x60 */ FD_INVALID,    /* 0x61 */ FD_VALID,      /* 0x62 */ FD_CHECK_ST,   /* 0x63 */ FD_CHECK_ST,
  /* 0x64 */ FD_VALID,      /* 0x65 */ FD_CHECK_JMP,  /* 0x66 */ FD_CHECK_JMP,  /* 0x67 */ FD_VALID,
  /* 0x68 */ FD_INVALID,    /* 0x69 */ FD_VALID,      /* 0x6a */ FD_CHECK_ST,   /* 0x6b */ FD_CHECK_ST,
  /* 0x6c */ FD_VALID,      /* 0x6d */ FD_CHECK_JMP,  /* 0x6e */ FD_CHECK_JMP,  /* 0x6f */ FD_VALID,
  /* 0x70 */ FD_INVALID,    /* 0x71 */ FD_VALID,      /* 0x72 */ FD_CHECK_ST,   /* 0x73 */ FD_CHECK_ST,
  /* 0x74 */ FD_VALID,      /* 0x75 */ FD_CHECK_JMP,  /* 0x76 */ FD_CHECK_JMP,  /* 0x77 */ FD_VALID,
  /* 0x78 */ FD_INVALID,    /* 0x79 */ FD_VALID,      /* 0x7a */ FD_CHECK_ST,   /* 0x7b */ FD_CHECK_ST,
  /* 0x7c */ FD_VALID,      /* 0x7d */ FD_CHECK_JMP,  /* 0x7e */ FD_CHECK_JMP,  /* 0x7f */ FD_VALID,
  /* 0x80 */ FD_INVALID,    /* 0x81 */ FD_INVALID,    /* 0x82 */ FD_INVALID,    /* 0x83 */ FD_INVALID,
  /* 0x84 */ FD_VALID,      /* 0x85 */ FD_CHECK_CALL, /* 0x86 */ FD_INVALID,    /* 0x87 */ FD_VALID,
  /* 0x88 */ FD_INVALID,    /* 0x89 */ FD_INVALID,    /* 0x8a */ FD_INVALID,    /* 0x8b */ FD_INVALID,
  /* 0x8c */ FD_INVALID,    /* 0x8d */ FD_VALID,      /* 0x8e */ FD_INVALID,    /* 0x8f */ FD_INVALID,
  /* 0x90 */ FD_INVALID,    /* 0x91 */ FD_INVALID,    /* 0x92 */ FD_INVALID,    /* 0x93 */ FD_INVALID,
  /* 0x94 */ FD_VALID,      /* 0x95 */ FD_VALID,      /* 0x96 */ FD_INVALID,    /* 0x97 */ FD_VALID,
  /* 0x98 */ FD_INVALID,    /* 0x99 */ FD_INVALID,    /* 0x9a */ FD_INVALID,    /* 0x9b */ FD_INVALID,
  /* 0x9c */ FD_VALID,      /* 0x9d */ FD_INVALID,    /* 0x9e */ FD_INVALID,    /* 0x9f */ FD_VALID,
  /* 0xa0 */ FD_INVALID,    /* 0xa1 */ FD_INVALID,    /* 0xa2 */ FD_INVALID,    /* 0xa3 */ FD_INVALID,
  /* 0xa4 */ FD_VALID,      /* 0xa5 */ FD_CHECK_JMP,  /* 0xa6 */ FD_CHECK_JMP,  /* 0xa7 */ FD_VALID,
  /* 0xa8 */ FD_INVALID,    /* 0xa9 */ FD_INVALID,    /* 0xaa */ FD_INVALID,    /* 0xab */ FD_INVALID,
  /* 0xac */ FD_VALID,      /* 0xad */ FD_CHECK_JMP,  /* 0xae */ FD_CHECK_JMP,  /* 0xaf */ FD_VALID,
  /* 0xb0 */ FD_INVALID,    /* 0xb1 */ FD_INVALID,    /* 0xb2 */ FD_INVALID,    /* 0xb3 */ FD_INVALID,
  /* 0xb4 */ FD_VALID,      /* 0xb5 */ FD_CHECK_JMP,  /* 0xb6 */ FD_CHECK_JMP,  /* 0xb7 */ FD_VALID,
  /* 0xb8 */ FD_INVALID,    /* 0xb9 */ FD_INVALID,    /* 0xba */ FD_INVALID,    /* 0xbb */ FD_INVALID,
  /* 0xbc */ FD_VALID,      /* 0xbd */ FD_CHECK_JMP,  /* 0xbe */ FD_CHECK_JMP,  /* 0xbf */ FD_VALID,
  /* 0xc0 */ FD_INVALID,    /* 0xc1 */ FD_INVALID,    /* 0xc2 */ FD_INVALID,    /* 0xc3 */ FD_INVALID,
  /* 0xc4 */ FD_VALID,      /* 0xc5 */ FD_CHECK_JMP,  /* 0xc6 */ FD_CHECK_JMP,  /* 0xc7 */ FD_VALID,
  /* 0xc8 */ FD_INVALID,    /* 0xc9 */ FD_INVALID,    /* 0xca */ FD_INVALID,    /* 0xcb */ FD_INVALID,
  /* 0xcc */ FD_VALID,      /* 0xcd */ FD_CHECK_JMP,  /* 0xce */ FD_CHECK_JMP,  /* 0xcf */ FD_VALID,
  /* 0xd0 */ FD_INVALID,    /* 0xd1 */ FD_INVALID,    /* 0xd2 */ FD_INVALID,    /* 0xd3 */ FD_INVALID,
  /* 0xd4 */ FD_CHECK_END,  /* 0xd5 */ FD_CHECK_JMP,  /* 0xd6 */ FD_CHECK_JMP,  /* 0xd7 */ FD_INVALID,
  /* 0xd8 */ FD_INVALID,    /* 0xd9 */ FD_INVALID,    /* 0xda */ FD_INVALID,    /* 0xdb */ FD_INVALID,
  /* 0xdc */ FD_CHECK_END,  /* 0xdd */ FD_CHECK_JMP,  /* 0xde */ FD_CHECK_JMP,  /* 0xdf */ FD_INVALID,
  /* 0xe0 */ FD_INVALID,    /* 0xe1 */ FD_INVALID,    /* 0xe2 */ FD_INVALID,    /* 0xe3 */ FD_INVALID,
  /* 0xe4 */ FD_INVALID,    /* 0xe5 */ FD_INVALID,    /* 0xe6 */ FD_INVALID,    /* 0xe7 */ FD_INVALID,
  /* 0xec */ FD_INVALID,    /* 0xed */ FD_INVALID,    /* 0xee */ FD_INVALID,    /* 0xef */ FD_INVALID,
  /* 0xf0 */ FD_INVALID,    /* 0xf1 */ FD_INVALID,    /* 0xf2 */ FD_INVALID,    /* 0xf3 */ FD_INVALID,
  /* 0xf4 */ FD_INVALID,    /* 0xf5 */ FD_INVALID,    /* 0xf6 */ FD_INVALID,    /* 0xf7 */ FD_INVALID,
  /* 0xf8 */ FD_INVALID,    /* 0xf9 */ FD_INVALID,    /* 0xfa */ FD_INVALID,    /* 0xfb */ FD_INVALID,
  /* 0xfc */ FD_INVALID,    /* 0xfd */ FD_INVALID,    /* 0xfe */ FD_INVALID,    /* 0xff */ FD_INVALID,
};

// FIXME: add a pedantic version of this validation that does things like:
//  - only 0 imms when the instruction does not use an imm
//  - same as above but for src/dst reg, offset
FD_FN_PURE ulong
fd_vm_context_validate( fd_vm_exec_context_t const * ctx ) {
  for( ulong i = 0; i < ctx->instrs_sz; ++i ) {
    fd_sbpf_instr_t instr = ctx->instrs[i];
    uchar validation_code = FD_OPCODE_VALIDATION_MAP[instr.opcode.raw];

    switch (validation_code) {
      case FD_VALID: {
        break;
      }
      case FD_CHECK_JMP: {
        long jmp_dst = (long)i + instr.offset + 1;
        if (jmp_dst < 0 || jmp_dst >= (long)ctx->instrs_sz) {
          return FD_VM_SBPF_VALIDATE_ERR_JMP_OUT_OF_BOUNDS;
        } else if (ctx->instrs[jmp_dst].opcode.raw == FD_SBPF_OP_ADDL_IMM) {
          return FD_VM_SBPF_VALIDATE_ERR_JMP_TO_ADDL_IMM;
        }
        break;
      }
      case FD_CHECK_END: { /* FD_BPF_OP_END_LE, FD_BPF_OP_END_BE */
        if (instr.imm != 16 && instr.imm != 32 && instr.imm != 64) {
          return FD_VM_SBPF_VALIDATE_ERR_INVALID_END_IMM;
        }
        break;
      }
      case FD_CHECK_ST: {
        break;
      }
      /* https://github.com/solana-labs/rbpf/blob/b503a1867a9cfa13f93b4d99679a17fe219831de/src/verifier.rs#L244 */
      case FD_CHECK_LDQ: { /* LD_DDW_IMM == FD_BPF_OP_LDQ */
        /* https://github.com/solana-labs/rbpf/blob/b503a1867a9cfa13f93b4d99679a17fe219831de/src/verifier.rs#L131 */
        if ((i+1) >= ctx->instrs_sz) {
          return FD_VM_SBPF_VALIDATE_ERR_INCOMPLETE_LDQ;
        }
        if (ctx->instrs[i + 1].opcode.raw != FD_SBPF_OP_ADDL_IMM) {
          return FD_VM_SBPF_VALIDATE_ERR_LDQ_NO_ADDL_IMM;
        }
        ++i;
        break;
      }
      /* https://github.com/solana-labs/rbpf/blob/b503a1867a9cfa13f93b4d99679a17fe219831de/src/elf.rs#L829-L830 */
      case FD_CHECK_CALL: { /* CALL_IMM == FD_BPF_OP_CALL_IMM */
        if( instr.src_reg == 0 ) {
          ulong target_pc = fd_ulong_sat_add( fd_ulong_sat_add( i, instr.imm ), 1 );
          if( target_pc >= ctx->instrs_sz ) {
            return FD_VM_SBPF_VALIDATE_ERR_JMP_OUT_OF_BOUNDS;
          }
        }
        break;
      }
      case FD_INVALID: {
        return FD_VM_SBPF_VALIDATE_ERR_INVALID_OPCODE;
      }
    }

    if (instr.src_reg > 10) {
      return FD_VM_SBPF_VALIDATE_ERR_INVALID_SRC_REG;
    }

    int is_invalid_dst_reg = instr.dst_reg > ((validation_code == FD_CHECK_ST) ? 10 : 9);
    if (is_invalid_dst_reg) {
      return FD_VM_SBPF_VALIDATE_ERR_INVALID_DST_REG;
    }
  }
  return FD_VM_SBPF_VALIDATE_SUCCESS;
}

ulong
fd_vm_translate_vm_to_host_private( fd_vm_exec_context_t *  ctx,
                                    ulong                   vm_addr,
                                    ulong                   sz,
                                    int                     write ) {
  /* FIXME: if the size if zero, then we should not error out here 
  https://github.com/firedancer-io/solana/blob/d8292b427adf8367d87068a3a88f6fd3ed8916a5/programs/bpf_loader/src/syscalls/mod.rs#L512-L514 */

  ulong mem_region = vm_addr & FD_VM_MEM_MAP_REGION_MASK;
  ulong start_addr = vm_addr & FD_VM_MEM_MAP_REGION_SZ;
  ulong end_addr = start_addr + sz;

  ulong host_addr = 0UL;
  switch( mem_region ) {
    case FD_VM_MEM_MAP_PROGRAM_REGION_START:
      /* Read-only program binary blob memory region */
      if( FD_UNLIKELY( ( write                        )
                     | ( end_addr > ctx->read_only_sz ) ) ) {
        return 0UL;
      }

      host_addr = (ulong)ctx->read_only + start_addr;
      break;
    case FD_VM_MEM_MAP_STACK_REGION_START:
      /* Stack memory region */
      /* TODO: needs more of the runtime to actually implement */
      /* FIXME: check that we are in the current or previous stack frame! */
      if( FD_UNLIKELY( end_addr > (FD_VM_STACK_MAX_DEPTH * FD_VM_STACK_FRAME_WITH_GUARD_SZ ) ) ) {
        return 0UL;
      }
      host_addr = (ulong)ctx->stack.data + start_addr;
      break;
    case FD_VM_MEM_MAP_HEAP_REGION_START:
      /* Heap memory region */
      if( FD_UNLIKELY( end_addr > ctx->heap_sz ) ) {
        return 0UL;
      }
      host_addr = (ulong)ctx->heap + start_addr;
      break;
    case FD_VM_MEM_MAP_INPUT_REGION_START:
      /* Program input memory region */
      if( FD_UNLIKELY( end_addr > ctx->input_sz ) ) {
        return 0UL;
      }
      host_addr = (ulong)ctx->input + start_addr;
      break;
    default:
      return 0UL;
  }

#ifdef FD_DEBUG_SBPF_TRACES
  // /* This is for mem entries. Commenting this out speeds up execution.*/
  // uchar * signature = (uchar*)ctx->instr_ctx->txn_ctx->_txn_raw->raw + ctx->instr_ctx->txn_ctx->txn_descriptor->signature_off;
  // uchar sig[64];
  // fd_base58_decode_64("46mXgo95nA6vC7jTYJP3pCE5U1BpSgV7sZnQHpbHmrbPMDqRGes3jrvYEZUk8TfnhUgkpmNN73q7A3GcBVZTg3gq", sig);
  // if (memcmp(signature, sig, 64) == 0) {
  //     fd_vm_trace_context_add_mem_entry( ctx->trace_ctx, vm_addr, sz, host_addr, write );
  // }
#endif
  return host_addr;
}
