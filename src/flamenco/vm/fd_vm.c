#include "fd_vm_private.h"
#include "../runtime/context/fd_exec_slot_ctx.h"
#include "../features/fd_features.h"

/* fd_vm_syscall_strerror() returns the error message corresponding to err,
   intended to be logged by log_collector, or an empty string if the error code
   should be omitted in logs for whatever reason.  Omitted examples are success,
   panic (logged in place)...
   See also fd_log_collector_program_failure(). */
char const *
fd_vm_syscall_strerror( int err ) {

  switch( err ) {

  case FD_VM_SYSCALL_ERR_INVALID_STRING:                         return "invalid utf-8 sequence"; // truncated
  case FD_VM_SYSCALL_ERR_ABORT:                                  return "SBF program panicked";
  case FD_VM_SYSCALL_ERR_PANIC:                                  return "SBF program Panicked in..."; // truncated
  case FD_VM_SYSCALL_ERR_INVOKE_CONTEXT_BORROW_FAILED:           return "Cannot borrow invoke context";
  case FD_VM_SYSCALL_ERR_MALFORMED_SIGNER_SEED:                  return "Malformed signer seed"; // truncated
  case FD_VM_SYSCALL_ERR_BAD_SEEDS:                              return "Could not create program address with signer seeds"; // truncated
  case FD_VM_SYSCALL_ERR_PROGRAM_NOT_SUPPORTED:                  return "Program not supported by inner instructions"; // truncated
  case FD_VM_SYSCALL_ERR_UNALIGNED_POINTER:                      return "Unaligned pointer";
  case FD_VM_SYSCALL_ERR_TOO_MANY_SIGNERS:                       return "Too many signers";
  case FD_VM_SYSCALL_ERR_INSTRUCTION_TOO_LARGE:                  return "Instruction passed to inner instruction is too large"; // truncated
  case FD_VM_SYSCALL_ERR_TOO_MANY_ACCOUNTS:                      return "Too many accounts passed to inner instruction";
  case FD_VM_SYSCALL_ERR_COPY_OVERLAPPING:                       return "Overlapping copy";
  case FD_VM_SYSCALL_ERR_RETURN_DATA_TOO_LARGE:                  return "Return data too large"; // truncated
  case FD_VM_SYSCALL_ERR_TOO_MANY_SLICES:                        return "Hashing too many sequences";
  case FD_VM_SYSCALL_ERR_INVALID_LENGTH:                         return "InvalidLength";
  case FD_VM_SYSCALL_ERR_MAX_INSTRUCTION_DATA_LEN_EXCEEDED:      return "Invoked an instruction with data that is too large"; // truncated
  case FD_VM_SYSCALL_ERR_MAX_INSTRUCTION_ACCOUNTS_EXCEEDED:      return "Invoked an instruction with too many accounts"; // truncated
  case FD_VM_SYSCALL_ERR_MAX_INSTRUCTION_ACCOUNT_INFOS_EXCEEDED: return "Invoked an instruction with too many account info's"; // truncated
  case FD_VM_SYSCALL_ERR_INVALID_ATTRIBUTE:                      return "InvalidAttribute";
  case FD_VM_SYSCALL_ERR_INVALID_POINTER:                        return "Invalid pointer";
  case FD_VM_SYSCALL_ERR_ARITHMETIC_OVERFLOW:                    return "Arithmetic overflow";

  case FD_VM_SYSCALL_ERR_INSTR_ERR:                              return "Instruction error";
  case FD_VM_SYSCALL_ERR_INVALID_PDA:                            return "Invalid PDA";
  case FD_VM_SYSCALL_ERR_COMPUTE_BUDGET_EXCEEDED:                return "Compute budget exceeded";
  case FD_VM_SYSCALL_ERR_SEGFAULT:                               return "Segmentation fault";
  case FD_VM_SYSCALL_ERR_OUTSIDE_RUNTIME:                        return "Syscall executed outside runtime";


  case FD_VM_SYSCALL_ERR_POSEIDON_INVALID_PARAMS:                return "Invalid parameters.";
  case FD_VM_SYSCALL_ERR_POSEIDON_INVALID_ENDIANNESS:            return "Invalid endianness.";

  default: break;
  }

  return "";
}

/* fd_vm_ebpf_strerror() returns the error message corresponding to err,
   intended to be logged by log_collector, or an empty string if the error code
   should be omitted in logs for whatever reason.
   See also fd_log_collector_program_failure(). */
char const *
fd_vm_ebpf_strerror( int err ) {

  switch( err ) {

  case FD_VM_ERR_EBPF_ELF_ERROR:                   return "ELF error"; // truncated
  case FD_VM_ERR_EBPF_FUNCTION_ALREADY_REGISTERED: return "function was already registered"; // truncated
  case FD_VM_ERR_EBPF_CALL_DEPTH_EXCEEDED:         return "exceeded max BPF to BPF call depth";
  case FD_VM_ERR_EBPF_EXIT_ROOT_CALL_FRAME:        return "attempted to exit root call frame";
  case FD_VM_ERR_EBPF_DIVIDE_BY_ZERO:              return "divide by zero at BPF instruction";
  case FD_VM_ERR_EBPF_DIVIDE_OVERFLOW:             return "division overflow at BPF instruction";
  case FD_VM_ERR_EBPF_EXECUTION_OVERRUN:           return "attempted to execute past the end of the text segment at BPF instruction";
  case FD_VM_ERR_EBPF_CALL_OUTSIDE_TEXT_SEGMENT:   return "callx attempted to call outside of the text segment";
  case FD_VM_ERR_EBPF_EXCEEDED_MAX_INSTRUCTIONS:   return "exceeded CUs meter at BPF instruction";
  case FD_VM_ERR_EBPF_JIT_NOT_COMPILED:            return "program has not been JIT-compiled";
  case FD_VM_ERR_EBPF_INVALID_VIRTUAL_ADDRESS:     return "invalid virtual address"; // truncated
  case FD_VM_ERR_EBPF_INVALID_MEMORY_REGION:       return "Invalid memory region at index"; // truncated
  case FD_VM_ERR_EBPF_ACCESS_VIOLATION:            return "Access violation"; // truncated
  case FD_VM_ERR_EBPF_STACK_ACCESS_VIOLATION:      return "Access violation in stack frame"; // truncated
  case FD_VM_ERR_EBPF_INVALID_INSTRUCTION:         return "invalid BPF instruction";
  case FD_VM_ERR_EBPF_UNSUPPORTED_INSTRUCTION:     return "unsupported BPF instruction";
  case FD_VM_ERR_EBPF_EXHAUSTED_TEXT_SEGMENT:      return "Compilation exhausted text segment at BPF instruction"; // truncated
  case FD_VM_ERR_EBPF_LIBC_INVOCATION_FAILED:      return "Libc calling returned error code"; // truncated
  case FD_VM_ERR_EBPF_VERIFIER_ERROR:              return "Verifier error"; // truncated
  case FD_VM_ERR_EBPF_SYSCALL_ERROR:               return ""; // handled explicitly via fd_vm_syscall_strerror()

  default: break;
  }

  return "";
}

/* fd_vm_strerror() returns the error message corresponding to err, used internally
   for system logs, NOT for log_collector / transaction logs. */
char const *
fd_vm_strerror( int err ) {

  switch( err ) {

  /* "Standard" Firedancer error codes */

  case FD_VM_SUCCESS:   return "SUCCESS success";
  case FD_VM_ERR_INVAL: return "INVAL invalid request";
  case FD_VM_ERR_UNSUP: return "UNSUP unsupported request";
  case FD_VM_ERR_FULL:  return "FULL storage full";
  case FD_VM_ERR_EMPTY: return "EMPTY nothing to do";
  case FD_VM_ERR_IO:    return "IO input-output error";

  /* VM exec error codes */

  case FD_VM_ERR_SIGFPE:      return "SIGFPE division by zero";

  /* VM validate error codes */

  case FD_VM_ERR_INVALID_OPCODE:    return "INVALID_OPCODE detected an invalid opcode";
  case FD_VM_ERR_INVALID_SRC_REG:   return "INVALID_SRC_REG detected an invalid source register";
  case FD_VM_ERR_INVALID_DST_REG:   return "INVALID_DST_REG detected an invalid destination register";
  case FD_VM_ERR_JMP_OUT_OF_BOUNDS: return "JMP_OUT_OF_BOUNDS detected an out of bounds jump";
  case FD_VM_ERR_JMP_TO_ADDL_IMM:   return "JMP_TO_ADDL_IMM detected a jump to an addl imm";
  case FD_VM_ERR_INVALID_END_IMM:   return "INVALID_END_IMM detected an invalid immediate for an endianness conversion instruction";
  case FD_VM_ERR_INCOMPLETE_LDQ:    return "INCOMPLETE_LDQ detected an incomplete ldq at program end";
  case FD_VM_ERR_LDQ_NO_ADDL_IMM:   return "LDQ_NO_ADDL_IMM detected a ldq without an addl imm following it";
  case FD_VM_ERR_INVALID_REG:       return "INVALID_REG detected an invalid register number in a callx instruction";
  case FD_VM_ERR_BAD_TEXT:          return "BAD_TEXT detected a bad text section";
  case FD_VM_SH_OVERFLOW:           return "SH_OVERFLOW detected a shift overflow in an instruction";
  case FD_VM_TEXT_SZ_UNALIGNED:     return "TEXT_SZ_UNALIGNED detected an unaligned text section size (not a multiple of 8)";

  default: break;
  }

  return "UNKNOWN probably not a FD_VM_ERR code";
}

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

  ulong sbpf_version = vm->sbpf_version;

  /* A mapping of all the possible 1-byte sBPF opcodes to their
     validation criteria. */

# define FD_VALID               ((uchar)0) /* Valid opcode */
# define FD_CHECK_JMP_V3        ((uchar)1) /* Validation should check that the instruction is a valid jump (v3+) */
# define FD_CHECK_END           ((uchar)2) /* Validation should check that the instruction is a valid endianness conversion */
# define FD_CHECK_ST            ((uchar)3) /* Validation should check that the instruction is a valid store */
# define FD_CHECK_LDQ           ((uchar)4) /* Validation should check that the instruction is a valid load-quad */
# define FD_CHECK_DIV           ((uchar)5) /* Validation should check that the instruction is a valid division by immediate */
# define FD_CHECK_SH32          ((uchar)6) /* Validation should check that the immediate is a valid 32-bit shift exponent */
# define FD_CHECK_SH64          ((uchar)7) /* Validation should check that the immediate is a valid 64-bit shift exponent */
# define FD_INVALID             ((uchar)8) /* The opcode is invalid */
# define FD_CHECK_CALL_REG      ((uchar)9) /* Validation should check that callx has valid register number */
# define FD_CHECK_CALL_REG_DEPR ((uchar)10) /* Older / deprecated FD_CHECK_CALLX */
# define FD_CHECK_CALL_IMM      ((uchar)11) /* Check call against functions registry */
# define FD_CHECK_SYSCALL       ((uchar)12) /* Check call against syscalls registry */
# define FD_CHECK_JMP_V0        ((uchar)13) /* Validation should check that the instruction is a valid jump (v0..v2) */

  uchar FD_CHECK_JMP = fd_sbpf_static_syscalls( sbpf_version ) ? FD_CHECK_JMP_V3 : FD_CHECK_JMP_V0;

  uchar validation_map[ 256 ] = {
    /* 0x00 */ FD_INVALID,    /* 0x01 */ FD_INVALID,    /* 0x02 */ FD_INVALID,    /* 0x03 */ FD_INVALID,
    /* 0x04 */ FD_VALID,      /* 0x05 */ FD_CHECK_JMP,  /* 0x06 */ FD_INVALID,    /* 0x07 */ FD_VALID,
    /* 0x08 */ FD_INVALID,    /* 0x09 */ FD_INVALID,    /* 0x0a */ FD_INVALID,    /* 0x0b */ FD_INVALID,
    /* 0x0c */ FD_VALID,      /* 0x0d */ FD_INVALID,    /* 0x0e */ FD_INVALID,    /* 0x0f */ FD_VALID,
    /* 0x10 */ FD_INVALID,    /* 0x11 */ FD_INVALID,    /* 0x12 */ FD_INVALID,    /* 0x13 */ FD_INVALID,
    /* 0x14 */ FD_VALID,      /* 0x15 */ FD_CHECK_JMP,  /* 0x16 */ FD_INVALID,    /* 0x17 */ FD_VALID,
    /* 0x18 */ FD_INVALID,    /* 0x19 */ FD_INVALID,    /* 0x1a */ FD_INVALID,    /* 0x1b */ FD_INVALID,
    /* 0x1c */ FD_VALID,      /* 0x1d */ FD_CHECK_JMP,  /* 0x1e */ FD_INVALID,    /* 0x1f */ FD_VALID,
    /* 0x20 */ FD_INVALID,    /* 0x21 */ FD_INVALID,    /* 0x22 */ FD_INVALID,    /* 0x23 */ FD_INVALID,
    /* 0x24 */ FD_INVALID,    /* 0x25 */ FD_CHECK_JMP,  /* 0x26 */ FD_INVALID,    /* 0x27 */ FD_CHECK_ST,
    /* 0x28 */ FD_INVALID,    /* 0x29 */ FD_INVALID,    /* 0x2a */ FD_INVALID,    /* 0x2b */ FD_INVALID,
    /* 0x2c */ FD_VALID,      /* 0x2d */ FD_CHECK_JMP,  /* 0x2e */ FD_INVALID,    /* 0x2f */ FD_CHECK_ST,
    /* 0x30 */ FD_INVALID,    /* 0x31 */ FD_INVALID,    /* 0x32 */ FD_INVALID,    /* 0x33 */ FD_INVALID,
    /* 0x34 */ FD_INVALID,    /* 0x35 */ FD_CHECK_JMP,  /* 0x36 */ FD_VALID,      /* 0x37 */ FD_CHECK_ST,
    /* 0x38 */ FD_INVALID,    /* 0x39 */ FD_INVALID,    /* 0x3a */ FD_INVALID,    /* 0x3b */ FD_INVALID,
    /* 0x3c */ FD_VALID,      /* 0x3d */ FD_CHECK_JMP,  /* 0x3e */ FD_VALID,      /* 0x3f */ FD_CHECK_ST,
    /* 0x40 */ FD_INVALID,    /* 0x41 */ FD_INVALID,    /* 0x42 */ FD_INVALID,    /* 0x43 */ FD_INVALID,
    /* 0x44 */ FD_VALID,      /* 0x45 */ FD_CHECK_JMP,  /* 0x46 */ FD_CHECK_DIV,  /* 0x47 */ FD_VALID,
    /* 0x48 */ FD_INVALID,    /* 0x49 */ FD_INVALID,    /* 0x4a */ FD_INVALID,    /* 0x4b */ FD_INVALID,
    /* 0x4c */ FD_VALID,      /* 0x4d */ FD_CHECK_JMP,  /* 0x4e */ FD_VALID,      /* 0x4f */ FD_VALID,
    /* 0x50 */ FD_INVALID,    /* 0x51 */ FD_INVALID,    /* 0x52 */ FD_INVALID,    /* 0x53 */ FD_INVALID,
    /* 0x54 */ FD_VALID,      /* 0x55 */ FD_CHECK_JMP,  /* 0x56 */ FD_CHECK_DIV,  /* 0x57 */ FD_VALID,
    /* 0x58 */ FD_INVALID,    /* 0x59 */ FD_INVALID,    /* 0x5a */ FD_INVALID,    /* 0x5b */ FD_INVALID,
    /* 0x5c */ FD_VALID,      /* 0x5d */ FD_CHECK_JMP,  /* 0x5e */ FD_VALID,      /* 0x5f */ FD_VALID,
    /* 0x60 */ FD_INVALID,    /* 0x61 */ FD_INVALID,    /* 0x62 */ FD_INVALID,    /* 0x63 */ FD_INVALID,
    /* 0x64 */ FD_CHECK_SH32, /* 0x65 */ FD_CHECK_JMP,  /* 0x66 */ FD_CHECK_DIV,  /* 0x67 */ FD_CHECK_SH64,
    /* 0x68 */ FD_INVALID,    /* 0x69 */ FD_INVALID,    /* 0x6a */ FD_INVALID,    /* 0x6b */ FD_INVALID,
    /* 0x6c */ FD_VALID,      /* 0x6d */ FD_CHECK_JMP,  /* 0x6e */ FD_VALID,      /* 0x6f */ FD_VALID,
    /* 0x70 */ FD_INVALID,    /* 0x71 */ FD_INVALID,    /* 0x72 */ FD_INVALID,    /* 0x73 */ FD_INVALID,
    /* 0x74 */ FD_CHECK_SH32, /* 0x75 */ FD_CHECK_JMP,  /* 0x76 */ FD_CHECK_DIV,  /* 0x77 */ FD_CHECK_SH64,
    /* 0x78 */ FD_INVALID,    /* 0x79 */ FD_INVALID,    /* 0x7a */ FD_INVALID,    /* 0x7b */ FD_INVALID,
    /* 0x7c */ FD_VALID,      /* 0x7d */ FD_CHECK_JMP,  /* 0x7e */ FD_VALID,      /* 0x7f */ FD_VALID,
    /* 0x80 */ FD_INVALID,    /* 0x81 */ FD_INVALID,    /* 0x82 */ FD_INVALID,    /* 0x83 */ FD_INVALID,
    /* 0x84 */ FD_INVALID,    /* 0x85 */ FD_CHECK_CALL_IMM,/*0x86*/FD_VALID,      /* 0x87 */ FD_CHECK_ST,
    /* 0x88 */ FD_INVALID,    /* 0x89 */ FD_INVALID,    /* 0x8a */ FD_INVALID,    /* 0x8b */ FD_INVALID,
    /* 0x8c */ FD_VALID,      /* 0x8d */ FD_CHECK_CALL_REG,/*0x8e*/FD_VALID,      /* 0x8f */ FD_CHECK_ST,
    /* 0x90 */ FD_INVALID,    /* 0x91 */ FD_INVALID,    /* 0x92 */ FD_INVALID,    /* 0x93 */ FD_INVALID,
    /* 0x94 */ FD_INVALID,    /* 0x95 */ FD_CHECK_SYSCALL,/*0x96*/ FD_VALID,      /* 0x97 */ FD_CHECK_ST,
    /* 0x98 */ FD_INVALID,    /* 0x99 */ FD_INVALID,    /* 0x9a */ FD_INVALID,    /* 0x9b */ FD_INVALID,
    /* 0x9c */ FD_VALID,      /* 0x9d */ FD_VALID,      /* 0x9e */ FD_VALID,      /* 0x9f */ FD_CHECK_ST,
    /* 0xa0 */ FD_INVALID,    /* 0xa1 */ FD_INVALID,    /* 0xa2 */ FD_INVALID,    /* 0xa3 */ FD_INVALID,
    /* 0xa4 */ FD_VALID,      /* 0xa5 */ FD_CHECK_JMP,  /* 0xa6 */ FD_INVALID,    /* 0xa7 */ FD_VALID,
    /* 0xa8 */ FD_INVALID,    /* 0xa9 */ FD_INVALID,    /* 0xaa */ FD_INVALID,    /* 0xab */ FD_INVALID,
    /* 0xac */ FD_VALID,      /* 0xad */ FD_CHECK_JMP,  /* 0xae */ FD_INVALID,    /* 0xaf */ FD_VALID,
    /* 0xb0 */ FD_INVALID,    /* 0xb1 */ FD_INVALID,    /* 0xb2 */ FD_INVALID,    /* 0xb3 */ FD_INVALID,
    /* 0xb4 */ FD_VALID,      /* 0xb5 */ FD_CHECK_JMP,  /* 0xb6 */ FD_VALID,      /* 0xb7 */ FD_VALID,
    /* 0xb8 */ FD_INVALID,    /* 0xb9 */ FD_INVALID,    /* 0xba */ FD_INVALID,    /* 0xbb */ FD_INVALID,
    /* 0xbc */ FD_VALID,      /* 0xbd */ FD_CHECK_JMP,  /* 0xbe */ FD_VALID,      /* 0xbf */ FD_VALID,
    /* 0xc0 */ FD_INVALID,    /* 0xc1 */ FD_INVALID,    /* 0xc2 */ FD_INVALID,    /* 0xc3 */ FD_INVALID,
    /* 0xc4 */ FD_CHECK_SH32, /* 0xc5 */ FD_CHECK_JMP,  /* 0xc6 */ FD_CHECK_DIV,  /* 0xc7 */ FD_CHECK_SH64,
    /* 0xc8 */ FD_INVALID,    /* 0xc9 */ FD_INVALID,    /* 0xca */ FD_INVALID,    /* 0xcb */ FD_INVALID,
    /* 0xcc */ FD_VALID,      /* 0xcd */ FD_CHECK_JMP,  /* 0xce */ FD_VALID,      /* 0xcf */ FD_VALID,
    /* 0xd0 */ FD_INVALID,    /* 0xd1 */ FD_INVALID,    /* 0xd2 */ FD_INVALID,    /* 0xd3 */ FD_INVALID,
    /* 0xd4 */ FD_INVALID,    /* 0xd5 */ FD_CHECK_JMP,  /* 0xd6 */ FD_CHECK_DIV,  /* 0xd7 */ FD_INVALID,
    /* 0xd8 */ FD_INVALID,    /* 0xd9 */ FD_INVALID,    /* 0xda */ FD_INVALID,    /* 0xdb */ FD_INVALID,
    /* 0xdc */ FD_CHECK_END,  /* 0xdd */ FD_CHECK_JMP,  /* 0xde */ FD_VALID,      /* 0xdf */ FD_INVALID,
    /* 0xe0 */ FD_INVALID,    /* 0xe1 */ FD_INVALID,    /* 0xe2 */ FD_INVALID,    /* 0xe3 */ FD_INVALID,
    /* 0xe4 */ FD_INVALID,    /* 0xe5 */ FD_INVALID,    /* 0xe6 */ FD_CHECK_DIV,  /* 0xe7 */ FD_INVALID,
    /* 0xe8 */ FD_INVALID,    /* 0xe9 */ FD_INVALID,    /* 0xea */ FD_INVALID,    /* 0xeb */ FD_INVALID,
    /* 0xec */ FD_INVALID,    /* 0xed */ FD_INVALID,    /* 0xee */ FD_VALID,      /* 0xef */ FD_INVALID,
    /* 0xf0 */ FD_INVALID,    /* 0xf1 */ FD_INVALID,    /* 0xf2 */ FD_INVALID,    /* 0xf3 */ FD_INVALID,
    /* 0xf4 */ FD_INVALID,    /* 0xf5 */ FD_INVALID,    /* 0xf6 */ FD_CHECK_DIV,  /* 0xf7 */ FD_VALID,
    /* 0xf8 */ FD_INVALID,    /* 0xf9 */ FD_INVALID,    /* 0xfa */ FD_INVALID,    /* 0xfb */ FD_INVALID,
    /* 0xfc */ FD_INVALID,    /* 0xfd */ FD_INVALID,    /* 0xfe */ FD_VALID,      /* 0xff */ FD_INVALID,
  };

  /* SIMD-0173: LDDW */
  validation_map[ 0x18 ] = fd_sbpf_enable_lddw( sbpf_version ) ? FD_CHECK_LDQ : FD_INVALID;
  validation_map[ 0xf7 ] = fd_sbpf_enable_lddw( sbpf_version ) ? FD_INVALID   : FD_VALID; /* HOR64 */

  /* SIMD-0173: LE */
  validation_map[ 0xd4 ] = fd_sbpf_enable_le( sbpf_version ) ? FD_CHECK_END : FD_INVALID;

  /* SIMD-0173: LDXW, STW, STXW */
  validation_map[ 0x61 ] = fd_sbpf_move_memory_ix_classes( sbpf_version ) ? FD_INVALID   : FD_VALID;
  validation_map[ 0x62 ] = fd_sbpf_move_memory_ix_classes( sbpf_version ) ? FD_INVALID   : FD_CHECK_ST;
  validation_map[ 0x63 ] = fd_sbpf_move_memory_ix_classes( sbpf_version ) ? FD_INVALID   : FD_CHECK_ST;
  validation_map[ 0x8c ] = fd_sbpf_move_memory_ix_classes( sbpf_version ) ? FD_VALID     : FD_INVALID;
  validation_map[ 0x87 ] = fd_sbpf_move_memory_ix_classes( sbpf_version ) ? FD_CHECK_ST  : FD_VALID; /* VALID because it's NEG64 */
  validation_map[ 0x8f ] = fd_sbpf_move_memory_ix_classes( sbpf_version ) ? FD_CHECK_ST  : FD_INVALID;

  /* SIMD-0173: LDXH, STH, STXH */
  validation_map[ 0x69 ] = fd_sbpf_move_memory_ix_classes( sbpf_version ) ? FD_INVALID   : FD_VALID;
  validation_map[ 0x6a ] = fd_sbpf_move_memory_ix_classes( sbpf_version ) ? FD_INVALID   : FD_CHECK_ST;
  validation_map[ 0x6b ] = fd_sbpf_move_memory_ix_classes( sbpf_version ) ? FD_INVALID   : FD_CHECK_ST;
  validation_map[ 0x3c ] = fd_sbpf_move_memory_ix_classes( sbpf_version ) ? FD_VALID     : FD_VALID;
  validation_map[ 0x37 ] = fd_sbpf_move_memory_ix_classes( sbpf_version ) ? FD_CHECK_ST  : FD_CHECK_DIV;
  validation_map[ 0x3f ] = fd_sbpf_move_memory_ix_classes( sbpf_version ) ? FD_CHECK_ST  : FD_VALID;

  /* SIMD-0173: LDXB, STB, STXB */
  validation_map[ 0x71 ] = fd_sbpf_move_memory_ix_classes( sbpf_version ) ? FD_INVALID   : FD_VALID;
  validation_map[ 0x72 ] = fd_sbpf_move_memory_ix_classes( sbpf_version ) ? FD_INVALID   : FD_CHECK_ST;
  validation_map[ 0x73 ] = fd_sbpf_move_memory_ix_classes( sbpf_version ) ? FD_INVALID   : FD_CHECK_ST;
  validation_map[ 0x2c ] = fd_sbpf_move_memory_ix_classes( sbpf_version ) ? FD_VALID     : FD_VALID;
  validation_map[ 0x27 ] = fd_sbpf_move_memory_ix_classes( sbpf_version ) ? FD_CHECK_ST  : FD_VALID;
  validation_map[ 0x2f ] = fd_sbpf_move_memory_ix_classes( sbpf_version ) ? FD_CHECK_ST  : FD_VALID;

  /* SIMD-0173: LDXDW, STDW, STXDW */
  validation_map[ 0x79 ] = fd_sbpf_move_memory_ix_classes( sbpf_version ) ? FD_INVALID   : FD_VALID;
  validation_map[ 0x7a ] = fd_sbpf_move_memory_ix_classes( sbpf_version ) ? FD_INVALID   : FD_CHECK_ST;
  validation_map[ 0x7b ] = fd_sbpf_move_memory_ix_classes( sbpf_version ) ? FD_INVALID   : FD_CHECK_ST;
  validation_map[ 0x9c ] = fd_sbpf_move_memory_ix_classes( sbpf_version ) ? FD_VALID     : FD_VALID;
  validation_map[ 0x97 ] = fd_sbpf_move_memory_ix_classes( sbpf_version ) ? FD_CHECK_ST  : FD_CHECK_DIV;
  validation_map[ 0x9f ] = fd_sbpf_move_memory_ix_classes( sbpf_version ) ? FD_CHECK_ST  : FD_VALID;

  /* SIMD-0173: CALLX */
  validation_map[ 0x8d ] = fd_sbpf_callx_uses_src_reg( sbpf_version ) ? FD_CHECK_CALL_REG : FD_CHECK_CALL_REG_DEPR;

  /* SIMD-0174: MUL, DIV, MOD */
  validation_map[ 0x24 ] = fd_sbpf_enable_pqr( sbpf_version ) ? FD_INVALID : FD_VALID;
  validation_map[ 0x34 ] = fd_sbpf_enable_pqr( sbpf_version ) ? FD_INVALID : FD_CHECK_DIV;
  validation_map[ 0x94 ] = fd_sbpf_enable_pqr( sbpf_version ) ? FD_INVALID : FD_CHECK_DIV;
  /* note: 0x?c, 0x?7, 0x?f should not be overwritten because they're now load/store ix */

  /* SIMD-0174: NEG */
  validation_map[ 0x84 ] = fd_sbpf_enable_neg( sbpf_version ) ? FD_VALID : FD_INVALID;
  /* note: 0x87 should not be overwritten because it was NEG64 and it becomes STW */

  /* SIMD-0174: MUL, DIV, MOD */
  validation_map[ 0x36 ] = fd_sbpf_enable_pqr( sbpf_version ) ? FD_VALID     : FD_INVALID; /* UHMUL64 */
  validation_map[ 0x3e ] = fd_sbpf_enable_pqr( sbpf_version ) ? FD_VALID     : FD_INVALID;
  validation_map[ 0x46 ] = fd_sbpf_enable_pqr( sbpf_version ) ? FD_CHECK_DIV : FD_INVALID; /* UDIV32 */
  validation_map[ 0x4e ] = fd_sbpf_enable_pqr( sbpf_version ) ? FD_VALID     : FD_INVALID;
  validation_map[ 0x56 ] = fd_sbpf_enable_pqr( sbpf_version ) ? FD_CHECK_DIV : FD_INVALID; /* UDIV64 */
  validation_map[ 0x5e ] = fd_sbpf_enable_pqr( sbpf_version ) ? FD_VALID     : FD_INVALID;
  validation_map[ 0x66 ] = fd_sbpf_enable_pqr( sbpf_version ) ? FD_CHECK_DIV : FD_INVALID; /* UREM32 */
  validation_map[ 0x6e ] = fd_sbpf_enable_pqr( sbpf_version ) ? FD_VALID     : FD_INVALID;
  validation_map[ 0x76 ] = fd_sbpf_enable_pqr( sbpf_version ) ? FD_CHECK_DIV : FD_INVALID; /* UREM64 */
  validation_map[ 0x7e ] = fd_sbpf_enable_pqr( sbpf_version ) ? FD_VALID     : FD_INVALID;
  validation_map[ 0x86 ] = fd_sbpf_enable_pqr( sbpf_version ) ? FD_VALID     : FD_INVALID; /* LMUL32 */
  validation_map[ 0x8e ] = fd_sbpf_enable_pqr( sbpf_version ) ? FD_VALID     : FD_INVALID;
  validation_map[ 0x96 ] = fd_sbpf_enable_pqr( sbpf_version ) ? FD_VALID     : FD_INVALID; /* LMUL64 */
  validation_map[ 0x9e ] = fd_sbpf_enable_pqr( sbpf_version ) ? FD_VALID     : FD_INVALID;
  validation_map[ 0xb6 ] = fd_sbpf_enable_pqr( sbpf_version ) ? FD_VALID     : FD_INVALID; /* SHMUL64 */
  validation_map[ 0xbe ] = fd_sbpf_enable_pqr( sbpf_version ) ? FD_VALID     : FD_INVALID;
  validation_map[ 0xc6 ] = fd_sbpf_enable_pqr( sbpf_version ) ? FD_CHECK_DIV : FD_INVALID; /* SDIV32 */
  validation_map[ 0xce ] = fd_sbpf_enable_pqr( sbpf_version ) ? FD_VALID     : FD_INVALID;
  validation_map[ 0xd6 ] = fd_sbpf_enable_pqr( sbpf_version ) ? FD_CHECK_DIV : FD_INVALID; /* SDIV64 */
  validation_map[ 0xde ] = fd_sbpf_enable_pqr( sbpf_version ) ? FD_VALID     : FD_INVALID;
  validation_map[ 0xe6 ] = fd_sbpf_enable_pqr( sbpf_version ) ? FD_CHECK_DIV : FD_INVALID; /* SREM32 */
  validation_map[ 0xee ] = fd_sbpf_enable_pqr( sbpf_version ) ? FD_VALID     : FD_INVALID;
  validation_map[ 0xf6 ] = fd_sbpf_enable_pqr( sbpf_version ) ? FD_CHECK_DIV : FD_INVALID; /* SREM64 */
  validation_map[ 0xfe ] = fd_sbpf_enable_pqr( sbpf_version ) ? FD_VALID     : FD_INVALID;

  /* SIMD-0178: static syscalls */
  validation_map[ 0x85 ] = fd_sbpf_static_syscalls( sbpf_version ) ? FD_CHECK_CALL_IMM : FD_VALID;
  validation_map[ 0x95 ] = fd_sbpf_static_syscalls( sbpf_version ) ? FD_CHECK_SYSCALL : FD_VALID;
  validation_map[ 0x9d ] = fd_sbpf_static_syscalls( sbpf_version ) ? FD_VALID : FD_INVALID;

  /* FIXME: These checks are not necessary assuming fd_vm_t is populated by metadata
     generated in fd_sbpf_elf_peek (which performs these checks). But there is no guarantee, and
     this non-guarantee is (rightfully) exploited by the fuzz harnesses.
     Agave doesn't perform these checks explicitly due to Rust's guarantees  */
  if( FD_UNLIKELY( vm->text_sz / 8UL != vm->text_cnt ||
                   (const uchar *)vm->text < vm->rodata ||
                   (ulong)vm->text > (ulong)vm->text + vm->text_sz || /* Overflow chk */
                   (const uchar *)vm->text + vm->text_sz > vm->rodata + vm->rodata_sz ) )
    return FD_VM_ERR_BAD_TEXT;

  if( FD_UNLIKELY( !fd_ulong_is_aligned( vm->text_sz, 8UL ) ) ) /* https://github.com/solana-labs/rbpf/blob/v0.8.0/src/verifier.rs#L109 */
    return FD_VM_TEXT_SZ_UNALIGNED;

  if ( FD_UNLIKELY( vm->text_cnt == 0UL ) ) /* https://github.com/solana-labs/rbpf/blob/v0.8.0/src/verifier.rs#L112 */
    return FD_VM_ERR_EMPTY;

  ulong const * text     = vm->text;
  ulong         text_cnt = vm->text_cnt;

  /* https://github.com/anza-xyz/sbpf/blob/v0.12.2/src/verifier.rs#L233-L235 */
  ulong function_start = 0UL;
  ulong function_next  = 0UL;
  if( fd_sbpf_enable_stricter_elf_headers(sbpf_version) ) {
    if( FD_UNLIKELY( !fd_sbpf_is_function_start( fd_sbpf_instr( text[0] ) ) ) ) {
      return FD_VM_INVALID_FUNCTION;
    }
  }

  for( ulong i=0UL; i<text_cnt; i++ ) {
    fd_sbpf_instr_t instr = fd_sbpf_instr( text[i] );

    /* Validate functions
       https://github.com/anza-xyz/sbpf/blob/v0.12.2/src/verifier.rs#L240-L255
       At the start of a function, we check that the function ends with JA(0x05) or RETURN(0x9D).
       As a side effect, the range of the function is [function_start, function_next-1],
       used to validate jumps.
       Note that the first function always starts at 0, and similarly the last function
       always ends at text_cnt-1. */
    if( FD_UNLIKELY( fd_sbpf_enable_stricter_elf_headers(sbpf_version) && fd_sbpf_is_function_start( instr ) ) ) {
      function_start = i;
      function_next  = i+1;
      while( function_next<text_cnt && !fd_sbpf_is_function_start( fd_sbpf_instr( text[function_next] ) ) ) {
        function_next++;
      }
      if( FD_UNLIKELY( !fd_sbpf_is_function_end( fd_sbpf_instr( text[function_next-1] ) ) ) ) {
        return FD_VM_INVALID_FUNCTION;
      }
    }

    uchar validation_code = validation_map[ instr.opcode.raw ];
    switch( validation_code ) {

    case FD_VALID: break;

    /* Store ops are special because they allow dreg==r10.
       We use a special validation_code, used later in the
       "Check registers" section.
       But there's nothing to do at this time. */
    case FD_CHECK_ST: break;

    case FD_CHECK_JMP_V0: {
      long jmp_dst = (long)i + (long)instr.offset + 1L;
      if( FD_UNLIKELY( (jmp_dst<0) | (jmp_dst>=(long)text_cnt)                          ) ) return FD_VM_ERR_JMP_OUT_OF_BOUNDS;
      //FIXME: this shouldn't be here?
      if( FD_UNLIKELY( fd_sbpf_instr( text[ jmp_dst ] ).opcode.raw==FD_SBPF_OP_ADDL_IMM ) ) return FD_VM_ERR_JMP_TO_ADDL_IMM;
      break;
    }

    case FD_CHECK_JMP_V3: {
      long jmp_dst = (long)i + (long)instr.offset + 1L;
      if( FD_UNLIKELY( (jmp_dst<(long)function_start) | (jmp_dst>=(long)function_next) ) ) return FD_VM_ERR_JMP_OUT_OF_BOUNDS;
      break;
    }

    case FD_CHECK_END: {
      if( FD_UNLIKELY( !((instr.imm==16) | (instr.imm==32) | (instr.imm==64)) ) ) return FD_VM_ERR_INVALID_END_IMM;
      break;
    }

    /* https://github.com/solana-labs/rbpf/blob/b503a1867a9cfa13f93b4d99679a17fe219831de/src/verifier.rs#L244 */
    case FD_CHECK_LDQ: {
      /* https://github.com/solana-labs/rbpf/blob/b503a1867a9cfa13f93b4d99679a17fe219831de/src/verifier.rs#L131 */
      if( FD_UNLIKELY( (i+1UL)>=text_cnt ) ) return FD_VM_ERR_INCOMPLETE_LDQ;

      /* https://github.com/solana-labs/rbpf/blob/b503a1867a9cfa13f93b4d99679a17fe219831de/src/verifier.rs#L137-L139 */
      fd_sbpf_instr_t addl_imm = fd_sbpf_instr( text[ i+1UL ] );
      if( FD_UNLIKELY( addl_imm.opcode.raw!=FD_SBPF_OP_ADDL_IMM ) ) return FD_VM_ERR_LDQ_NO_ADDL_IMM;

      /* FIXME: SET A BIT MAP HERE OF ADDL_IMM TO DENOTE * AS FORBIDDEN
         BRANCH TARGETS OF CALL_REG?? */

      i++; /* Skip the addl imm */
      break;
    }

    case FD_CHECK_DIV: {
      if( FD_UNLIKELY( instr.imm==0 ) ) return FD_VM_ERR_SIGFPE;
      break;
    }

    case FD_CHECK_SH32: {
      if( FD_UNLIKELY( instr.imm>=32 ) ) return FD_VM_SH_OVERFLOW;
      break;
    }

    case FD_CHECK_SH64: {
      if( FD_UNLIKELY( instr.imm>=64 ) ) return FD_VM_SH_OVERFLOW;
      break;
    }

    /* https://github.com/anza-xyz/sbpf/blob/v0.11.1/src/verifier.rs#L220 */
    case FD_CHECK_CALL_REG: {
      if( FD_UNLIKELY( instr.src_reg > 9 ) ) {
        return FD_VM_ERR_INVALID_REG;
      }
      break;
    }
    case FD_CHECK_CALL_REG_DEPR: {
      if( FD_UNLIKELY( instr.imm > 9 ) ) {
        return FD_VM_ERR_INVALID_REG;
      }
      break;
    }

    /* https://github.com/anza-xyz/sbpf/blob/v0.12.2/src/verifier.rs#L403-L409 */
    case FD_CHECK_CALL_IMM: {
      ulong target_pc = (ulong)( fd_long_sat_add( (long)i, fd_long_sat_add( (long)(int)instr.imm, 1 ) ) );
      if( FD_UNLIKELY( !(
        target_pc<text_cnt && fd_sbpf_is_function_start( fd_sbpf_instr( text[target_pc] ) )
      ) ) ) {
        return FD_VM_INVALID_FUNCTION;
      }
      break;
    }

    /* https://github.com/anza-xyz/sbpf/blob/v0.12.2/src/verifier.rs#L414-L423 */
    case FD_CHECK_SYSCALL: {
      /* check active syscall */
      fd_sbpf_syscalls_t const * syscall = fd_sbpf_syscalls_query_const( vm->syscalls, (ulong)instr.imm, NULL );
      if( FD_UNLIKELY( !syscall ) ) {
        return FD_VM_INVALID_SYSCALL;
      }
      break;
    }

    case FD_INVALID: default: return FD_VM_ERR_INVALID_OPCODE;
    }

    /* Check registers
       https://github.com/solana-labs/rbpf/blob/v0.8.5/src/verifier.rs#L177 */

    /* Source register */
    if( FD_UNLIKELY( instr.src_reg>10 ) ) return FD_VM_ERR_INVALID_SRC_REG;

    /* Special R10 register allowed for ADD64_IMM */
    if( instr.dst_reg==10U
        && fd_sbpf_dynamic_stack_frames( sbpf_version )
        && instr.opcode.raw == 0x07
        && ( instr.imm % FD_VM_SBPF_DYNAMIC_STACK_FRAMES_ALIGN )==0 )
        continue;

    /* Destination register. */
    if( FD_UNLIKELY( instr.dst_reg==10U && validation_code != FD_CHECK_ST ) ) return FD_VM_ERR_INVALID_DST_REG;
    if( FD_UNLIKELY( instr.dst_reg > 10U ) ) return FD_VM_ERR_INVALID_DST_REG;
  }

  return FD_VM_SUCCESS;
}

FD_FN_CONST ulong
fd_vm_align( void ) {
  return FD_VM_ALIGN;
}

FD_FN_CONST ulong
fd_vm_footprint( void ) {
  return FD_VM_FOOTPRINT;
}

void *
fd_vm_new( void * shmem ) {

  if( FD_UNLIKELY( !shmem ) ) {
    FD_LOG_WARNING(( "NULL shmem" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shmem, fd_vm_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned shmem" ));
    return NULL;
  }

  fd_vm_t * vm = (fd_vm_t *)shmem;
  fd_memset( vm, 0, fd_vm_footprint() );

  FD_COMPILER_MFENCE();
  FD_VOLATILE( vm->magic ) = FD_VM_MAGIC;
  FD_COMPILER_MFENCE();

  return shmem;
}

fd_vm_t *
fd_vm_join( void * shmem ) {

  if( FD_UNLIKELY( !shmem ) ) {
    FD_LOG_WARNING(( "NULL shmem" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shmem, fd_vm_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned shmem" ));
    return NULL;
  }

  fd_vm_t * vm = (fd_vm_t *)shmem;

  if( FD_UNLIKELY( vm->magic!=FD_VM_MAGIC ) ) {
    FD_LOG_WARNING(( "bad magic" ));
    return NULL;
  }

  return vm;
}

void *
fd_vm_leave( fd_vm_t * vm ) {

  if( FD_UNLIKELY( !vm ) ) {
    FD_LOG_WARNING(( "NULL vm" ));
    return NULL;
  }

  return (void *)vm;
}

void *
fd_vm_delete( void * shmem ) {

  if( FD_UNLIKELY( !shmem ) ) {
    FD_LOG_WARNING(( "NULL shmem" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shmem, fd_vm_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned shmem" ));
    return NULL;
  }

  fd_vm_t * vm = (fd_vm_t *)shmem;

  if( FD_UNLIKELY( vm->magic!=FD_VM_MAGIC ) ) {
    FD_LOG_WARNING(( "bad magic" ));
    return NULL;
  }

  FD_COMPILER_MFENCE();
  FD_VOLATILE( vm->magic ) = 0UL;
  FD_COMPILER_MFENCE();

  return (void *)vm;
}

fd_vm_t *
fd_vm_init(
   fd_vm_t * vm,
   fd_exec_instr_ctx_t *instr_ctx,
   ulong heap_max,
   ulong entry_cu,
   uchar const * rodata,
   ulong rodata_sz,
   ulong const * text,
   ulong text_cnt,
   ulong text_off,
   ulong text_sz,
   ulong entry_pc,
   ulong * calldests,
   ulong sbpf_version,
   fd_sbpf_syscalls_t * syscalls,
   fd_vm_trace_t * trace,
   fd_sha256_t * sha,
   fd_vm_input_region_t * mem_regions,
   uint mem_regions_cnt,
   fd_vm_acc_region_meta_t * acc_region_metas,
   uchar is_deprecated,
   int direct_mapping,
   int dump_syscall_to_pb ) {

  if ( FD_UNLIKELY( vm == NULL ) ) {
    FD_LOG_WARNING(( "NULL vm" ));
    return NULL;
  }

  if ( FD_UNLIKELY( vm->magic != FD_VM_MAGIC ) ) {
    FD_LOG_WARNING(( "bad magic" ));
    return NULL;
  }

  if ( FD_UNLIKELY( heap_max > FD_VM_HEAP_MAX ) ) {
    FD_LOG_WARNING(( "heap_max > FD_VM_HEAP_MAX" ));
    return NULL;
  }

  /* We do support calldests==NULL for tests that do not require
     program execution, e.g. just testing some interpreter functionality
     or syscalls.
     SBPF v3+ no longer needs calldests, so we enforce it to be NULL. */
  if( FD_UNLIKELY( calldests && fd_sbpf_enable_stricter_elf_headers(sbpf_version) ) ) {
    return NULL;
  }

  // Set the vm fields
  vm->instr_ctx             = instr_ctx;
  vm->heap_max              = heap_max;
  vm->entry_cu              = entry_cu;
  vm->rodata                = rodata;
  vm->rodata_sz             = rodata_sz;
  vm->text                  = text;
  vm->text_cnt              = text_cnt;
  vm->text_off              = text_off;
  vm->text_sz               = text_sz;
  vm->entry_pc              = entry_pc;
  vm->calldests             = calldests;
  vm->sbpf_version          = sbpf_version;
  vm->syscalls              = syscalls;
  vm->trace                 = trace;
  vm->sha                   = sha;
  vm->input_mem_regions     = mem_regions;
  vm->input_mem_regions_cnt = mem_regions_cnt;
  vm->acc_region_metas      = acc_region_metas;
  vm->is_deprecated         = is_deprecated;
  vm->direct_mapping        = direct_mapping;
  vm->stack_frame_size      = FD_VM_STACK_FRAME_SZ + ( direct_mapping ? 0UL : FD_VM_STACK_GUARD_SZ );
  vm->segv_vaddr            = ULONG_MAX;
  vm->segv_access_type      = 0;
  vm->dump_syscall_to_pb    = dump_syscall_to_pb;

  /* Unpack the configuration */
  int err = fd_vm_setup_state_for_execution( vm );
  if( FD_UNLIKELY( err != FD_VM_SUCCESS ) ) {
    return NULL;
  }

  return vm;
}

int
fd_vm_setup_state_for_execution( fd_vm_t * vm ) {

  if ( FD_UNLIKELY( !vm ) ) {
    FD_LOG_WARNING(( "NULL vm" ));
    return FD_VM_ERR_INVAL;
  }

  /* Unpack input and rodata */
  fd_vm_mem_cfg( vm );

  /* Initialize registers */
  /* FIXME: Zero out shadow, stack and heap here? */
  fd_memset( vm->reg, 0, FD_VM_REG_MAX * sizeof(ulong) );
  vm->reg[ 1] = FD_VM_MEM_MAP_INPUT_REGION_START;
  /* https://github.com/solana-labs/rbpf/blob/4ad935be45e5663be23b30cfc750b1ae1ad03c44/src/vm.rs#L326-L333 */
  vm->reg[10] = FD_VM_MEM_MAP_STACK_REGION_START +
    ( fd_sbpf_dynamic_stack_frames( vm->sbpf_version ) ? FD_VM_STACK_MAX : FD_VM_STACK_FRAME_SZ );
  /* Note: Agave uses r11 as pc, we don't */

  /* Set execution state */
  vm->pc        = vm->entry_pc;
  vm->ic        = 0UL;
  vm->cu        = vm->entry_cu;
  vm->frame_cnt = 0UL;

  vm->heap_sz = 0UL;

  /* Do NOT reset logs */

  return FD_VM_SUCCESS;
}
