#include "fd_vm.h"

char const *
fd_vm_strerror( int err ) {

  switch( err ) {

  /* "Standard" Firedancer error codes */

  case FD_VM_SUCCESS:   return "SUCCESS success";
  case FD_VM_ERR_INVAL: return "INVAL invalid request";
  case FD_VM_ERR_UNSUP: return "UNSUP unsupported request";
  case FD_VM_ERR_PERM:  return "PERM unauthorized request";
  case FD_VM_ERR_FULL:  return "FULL storage full";
  case FD_VM_ERR_EMPTY: return "EMPTY nothing to do";
  case FD_VM_ERR_IO:    return "IO input-output error";
  case FD_VM_ERR_AGAIN: return "AGAIN try again later";

  /* VM syscall error codes */

  case FD_VM_ERR_BUDGET:                       return "BUDGET compute budget exceeded";
  case FD_VM_ERR_ABORT:                        return "ABORT";                        /* FIXME: description */
  case FD_VM_ERR_PANIC:                        return "PANIC";                        /* FIXME: description */
  case FD_VM_ERR_MEM_OVERLAP:                  return "MEM_OVERLAP";                  /* FIXME: description */
  case FD_VM_ERR_INSTR_ERR:                    return "INSTR_ERR";                    /* FIXME: description */
  case FD_VM_ERR_RETURN_DATA_TOO_LARGE:        return "RETURN_DATA_TOO_LARGE";        /* FIXME: description */
  case FD_VM_ERR_INVOKE_CONTEXT_BORROW_FAILED: return "INVOKE_CONTEXT_BORROW_FAILED"; /* FIXME: description */

  /* sBPF validation error codes */

  case FD_VM_ERR_INVALID_OPCODE:    return "INVALID_OPCODE detected an invalid opcode";
  case FD_VM_ERR_INVALID_SRC_REG:   return "INVALID_SRC_REG detected an invalid source register";
  case FD_VM_ERR_INVALID_DST_REG:   return "INVALID_DST_REG detected an invalid destination register";
  case FD_VM_ERR_INF_LOOP:          return "INF_LOOP detected an infinite loop";
  case FD_VM_ERR_JMP_OUT_OF_BOUNDS: return "JMP_OUT_OF_BOUNDS detected an out of bounds jump";
  case FD_VM_ERR_JMP_TO_ADDL_IMM:   return "JMP_TO_ADDL_IMM detected a jump to an addl imm";
  case FD_VM_ERR_INVALID_END_IMM:   return "INVALID_END_IMM detected an invalid immediate for an endianness conversion instruction";
  case FD_VM_ERR_INCOMPLETE_LDQ:    return "INCOMPLETE_LDQ detected an incomplete ldq at program end";
  case FD_VM_ERR_LDQ_NO_ADDL_IMM:   return "LDQ_NO_ADDL_IMM detected a ldq without an addl imm following it";
  case FD_VM_ERR_NO_SUCH_EXT_CALL:  return "NO_SUCH_EXT_CALL detected a call imm with no function was registered for that immediate";

  /* VM fault error codes */

  case FD_VM_ERR_MEM_TRANS: return "MEM_TRANS"; /* FIXME: description */
  case FD_VM_ERR_BAD_CALL:  return "BAD_CALL";  /* FIXME: description */

  default: break;
  }

  return "UNKNOWN probably not a FD_VM_ERR code";
}

/* FIXME: MOVE TO BASE/SBPF? */
/* FIXME: CORRELATE AND VALIDATE AGAINST SOLANA CODE */

fd_vm_exec_compute_budget_t const vm_compute_budget = {
  .compute_unit_limit                        = FD_VM_MAX_COMPUTE_UNIT_LIMIT,
  .log_64_units                              =   100UL,
  .create_program_address_units              =  1500UL,
  .invoke_units                              =  1000UL,
  .max_invoke_depth                          =     4UL,
  .sha256_base_cost                          =    85UL,
  .sha256_byte_cost                          =     1UL,
  .sha256_max_slices                         = 20000UL,
  .max_call_depth                            =    64UL,
  .stack_frame_size                          =  4096UL,
  .log_pubkey_units                          =   100UL,
  .max_cpi_instruction_size                  =  1280UL, // IPv6 Min MTU size
  .cpi_bytes_per_unit                        =   250UL, // ~50MB at 200,000 units
  .sysvar_base_cost                          =   100UL,
  .secp256k1_recover_cost                    = 25000UL,
  .syscall_base_cost                         =   100UL,
  .curve25519_edwards_validate_point_cost    =   159UL,
  .curve25519_edwards_add_cost               =   473UL,
  .curve25519_edwards_subtract_cost          =   475UL,
  .curve25519_edwards_multiply_cost          =  2177UL,
  .curve25519_edwards_msm_base_cost          =  2273UL,
  .curve25519_edwards_msm_incremental_cost   =   758UL,
  .curve25519_ristretto_validate_point_cost  =   169UL,
  .curve25519_ristretto_add_cost             =   521UL,
  .curve25519_ristretto_subtract_cost        =   519UL,
  .curve25519_ristretto_multiply_cost        =  2208UL,
  .curve25519_ristretto_msm_base_cost        =  2303UL,
  .curve25519_ristretto_msm_incremental_cost =   788UL,
  .heap_size                                 =     0UL, /* FIXME: WHY COMMENTED OUT BEFORE? */
  .heap_cost                                 =     8UL,
  .mem_op_base_cost                          =    10UL,
  .loaded_accounts_data_size_limit           = FD_VM_MAX_LOADED_ACCOUNTS_DATA_SIZE_BYTES, // 64MiB
};

/* FIXME: add a pedantic version of this validation that does things
   like:
  - only 0 imms when the instruction does not use an imm
  - same as above but for src/dst reg, offset */
/* FIXME: HANDLING OF LDQ ON NEWER SBPF VERSUS OLDER SBPF (AND WITH CALL
   REG) */
/* FIXME: LINK TO SOLANA CODE VALIDATE AND DOUBLE CHECK THIS BEHAVES
   IDENTICALLY! */

int
fd_vm_validate( fd_vm_t const * vm ) {

  /* A mapping of all the possible 1-byte sBPF opcodes to their
     validation criteria. */

# define FD_VALID      ((uchar)0) /* Valid opcode */
# define FD_CHECK_JMP  ((uchar)1) /* Validation should check that the instruction is a valid jump */
# define FD_CHECK_END  ((uchar)2) /* Validation should check that the instruction is a valid endianness conversion */
# define FD_CHECK_ST   ((uchar)3) /* Validation should check that the instruction is a valid store */
# define FD_CHECK_LDQ  ((uchar)4) /* Validation should check that the instruction is a valid load-quad */
# define FD_CHECK_CALL ((uchar)5) /* Validation should check that the instruction is a valid function call */
# define FD_INVALID    ((uchar)6) /* The opcode is invalid */

  static uchar const validation_map[ 256 ] = {
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

  /* FIXME: CLEAN UP LONG / ULONG TYPE CONVERSION */

  ulong const * text     = vm->text;
  ulong         text_cnt = vm->text_cnt;
  for( ulong i=0UL; i<text_cnt; i++ ) {
    fd_sbpf_instr_t instr = fd_sbpf_instr( text[i] );

    uchar validation_code = validation_map[ instr.opcode.raw ];
    switch( validation_code ) {

    case FD_VALID: break;

    case FD_CHECK_JMP: {
      if( FD_UNLIKELY( instr.offset==-1 ) ) return FD_VM_ERR_INF_LOOP;
      long jmp_dst = (long)i + (long)instr.offset + 1L;
      if( FD_UNLIKELY( (jmp_dst<0) | (jmp_dst>=(long)text_cnt)                          ) ) return FD_VM_ERR_JMP_OUT_OF_BOUNDS;
      if( FD_UNLIKELY( fd_sbpf_instr( text[ jmp_dst ] ).opcode.raw==FD_SBPF_OP_ADDL_IMM ) ) return FD_VM_ERR_JMP_TO_ADDL_IMM;
      break;
    }

    case FD_CHECK_END: {
      if( FD_UNLIKELY( !((instr.imm==16) | (instr.imm==32) | (instr.imm==64)) ) ) return FD_VM_ERR_INVALID_END_IMM;
      break;
    }

    case FD_CHECK_ST: break; /* FIXME: HMMM ... */

    case FD_CHECK_LDQ: {
      if( FD_UNLIKELY( instr.src_reg                                                ) ) return FD_VM_ERR_INVALID_SRC_REG;
      if( FD_UNLIKELY( (i+1UL)>=text_cnt                                            ) ) return FD_VM_ERR_INCOMPLETE_LDQ;
      if( FD_UNLIKELY( fd_sbpf_instr( text[i+1UL] ).opcode.raw!=FD_SBPF_OP_ADDL_IMM ) ) return FD_VM_ERR_LDQ_NO_ADDL_IMM;
      /* FIXME: SHOULD THERE BE EXTRA CHECKS ON THE ADDL_IMM HERE? */
      /* FIXME: SET A BIT MAP HERE OF ADDL_IMM TO DENOTE * AS FORBIDDEN
         BRANCH TARGETS OF CALL_REG?? */
      i++;
      break;
    }

    case FD_CHECK_CALL: { /* FIXME: Check to make sure we are really doing this right! (required for sbpf2?) */
      if( instr.imm>=text_cnt                                                      &&
          !fd_sbpf_syscalls_query( vm->syscalls, instr.imm, NULL )                 &&
          !fd_sbpf_calldests_test( vm->calldests, fd_pchash_inverse( instr.imm ) ) ) return FD_VM_ERR_NO_SUCH_EXT_CALL;
      break;
    }

    case FD_INVALID: default: return FD_VM_ERR_INVALID_OPCODE;
    }

    if( FD_UNLIKELY( instr.src_reg>10 ) ) return FD_VM_ERR_INVALID_SRC_REG; /* FIXME: MAGIC NUMBER */

    int is_invalid_dst_reg = instr.dst_reg > ((validation_code == FD_CHECK_ST) ? 10 : 9); /* FIXME: MAGIC NUMBER */
    if( FD_UNLIKELY( is_invalid_dst_reg ) ) return FD_VM_ERR_INVALID_DST_REG;
  }

  return FD_VM_SUCCESS;
}

ulong
fd_vm_translate_vm_to_host_private( fd_vm_t * vm,
                                    ulong     vaddr,
                                    ulong     sz,
                                    int       write ) {
  ulong mem_region = vaddr & FD_VM_MEM_MAP_REGION_MASK;
  ulong start_addr = vaddr & FD_VM_MEM_MAP_REGION_SZ;
  ulong end_addr = start_addr + sz;

  ulong haddr = 0UL;
  switch( mem_region ) {
    case FD_VM_MEM_MAP_PROGRAM_REGION_START:
      /* Read-only program binary blob memory region */
      if( FD_UNLIKELY( ( write                        )
                     | ( end_addr > vm->read_only_sz ) ) )
        return 0UL;

      haddr = (ulong)vm->read_only + start_addr;
      break;
    case FD_VM_MEM_MAP_STACK_REGION_START:
      /* Stack memory region */
      /* TODO: needs more of the runtime to actually implement */
      /* FIXME: check that we are in the current or previous stack frame! */
      if( FD_UNLIKELY( end_addr > FD_VM_STACK_DATA_MAX ) ) return 0UL;
      haddr = (ulong)fd_vm_stack_data( vm->stack ) + start_addr;
      break;
    case FD_VM_MEM_MAP_HEAP_REGION_START:
      /* Heap memory region */
      if( FD_UNLIKELY( end_addr > vm->heap_sz ) )
        return 0UL;
      haddr = (ulong)vm->heap + start_addr;
      break;
    case FD_VM_MEM_MAP_INPUT_REGION_START:
      /* Program input memory region */
      if( FD_UNLIKELY( end_addr > vm->input_sz ) )
        return 0UL;
      haddr = (ulong)vm->input + start_addr;
      break;
    default:
      return 0UL;
  }

#ifdef FD_DEBUG_SBPF_TRACES
uchar * signature = (uchar*)vm->instr_ctx->txn_ctx->_txn_raw->raw + vm->instr_ctx->txn_ctx->txn_descriptor->signature_off;
uchar sig[64];
fd_base58_decode_64("mu7GV8tiEU58hnugxCcuuGh11MvM5tb2ib2qqYu9WYKHhc9Jsm187S31nEX1fg9RYM1NwWJiJkfXNNK21M6Yd8u", sig);
if( FD_UNLIKELY( !memcmp( signature, sig, 64 ) ) ) fd_vm_trace_event_mem( vm->trace, write, vaddr, sz, (void *)haddr );
#endif

  return haddr;
}
