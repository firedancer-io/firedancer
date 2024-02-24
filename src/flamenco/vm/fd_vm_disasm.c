#include "fd_vm_disasm.h"

# define OUT_PRINTF(...) \
  do { \
    *out_len = fd_ulong_sat_add(*out_len, (ulong)snprintf(out + (*out_len), MAX_BUFFER_LEN - *out_len, __VA_ARGS__)); \
    if( FD_UNLIKELY( *out_len > MAX_BUFFER_LEN ) ) return 0; \
  } while(0)

static int
fd_vm_disassemble_instr_alu( fd_sbpf_instr_t  instr,
                             char const *     suffix,
                             char *           out,
                             ulong *          out_len ) {

  char * op_name;
  switch (instr.opcode.normal.op_mode) {
    case FD_SBPF_OPCODE_ALU_OP_MODE_ADD:
      op_name = "add";
      break;
    case FD_SBPF_OPCODE_ALU_OP_MODE_SUB:
      op_name = "sub";
      break;
    case FD_SBPF_OPCODE_ALU_OP_MODE_MUL:
      op_name = "mul";
      break;
    case FD_SBPF_OPCODE_ALU_OP_MODE_DIV:
      op_name = "div";
      break;
    case FD_SBPF_OPCODE_ALU_OP_MODE_OR:
      op_name = "or";
      break;
    case FD_SBPF_OPCODE_ALU_OP_MODE_AND:
      op_name = "and";
      break;
    case FD_SBPF_OPCODE_ALU_OP_MODE_LSH:
      op_name = "lsh";
      break;
    case FD_SBPF_OPCODE_ALU_OP_MODE_RSH:
      op_name = "rsh";
      break;
    case FD_SBPF_OPCODE_ALU_OP_MODE_NEG:
      op_name = "neg";
      break;
    case FD_SBPF_OPCODE_ALU_OP_MODE_MOD:
      op_name = "mod";
      break;
    case FD_SBPF_OPCODE_ALU_OP_MODE_XOR:
      op_name = "xor";
      break;
    case FD_SBPF_OPCODE_ALU_OP_MODE_MOV:
      op_name = "mov";
      break;
    case FD_SBPF_OPCODE_ALU_OP_MODE_ARSH:
      op_name = "arsh";
      break;
    case FD_SBPF_OPCODE_ALU_OP_MODE_END:
      op_name = "end";
      break;
    default:
      return 1;
  }

  if( FD_UNLIKELY( instr.opcode.normal.op_mode == FD_SBPF_OPCODE_ALU_OP_MODE_NEG ) ) {
    OUT_PRINTF( "%s%s r%d", op_name, suffix, instr.dst_reg );
    return 1;
  }

  switch( instr.opcode.normal.op_src ) {
    case FD_SBPF_OPCODE_SOURCE_MODE_IMM:
      OUT_PRINTF( "%s%s r%d, %d",  op_name, suffix, instr.dst_reg, instr.imm     );
      break;
    case FD_SBPF_OPCODE_SOURCE_MODE_REG:
      OUT_PRINTF( "%s%s r%d, r%d", op_name, suffix, instr.dst_reg, instr.src_reg );
      break;
  }

  return 1;
}

static int
fd_vm_disassemble_instr_jmp( fd_sbpf_instr_t        instr,
                             ulong                  pc,
                             char const *           suffix,
                             fd_sbpf_syscalls_t *   syscalls,
                             char *                 out,
                             ulong *                out_len ) {

  char * op_name;
  switch(instr.opcode.normal.op_mode) {
    case FD_SBPF_OPCODE_JMP_OP_MODE_JA:
      op_name = "ja";
      break;
    case FD_SBPF_OPCODE_JMP_OP_MODE_JEQ:
      op_name = "jeq";
      break;
    case FD_SBPF_OPCODE_JMP_OP_MODE_JGT:
      op_name = "jgt";
      break;
    case FD_SBPF_OPCODE_JMP_OP_MODE_JGE:
      op_name = "jge";
      break;
    case FD_SBPF_OPCODE_JMP_OP_MODE_JSET:
      op_name = "jset";
      break;
    case FD_SBPF_OPCODE_JMP_OP_MODE_JNE:
      op_name = "jne";
      break;
    case FD_SBPF_OPCODE_JMP_OP_MODE_JSGT:
      op_name = "jsgt";
      break;
    case FD_SBPF_OPCODE_JMP_OP_MODE_JSGE:
      op_name = "jsge";
      break;
    case FD_SBPF_OPCODE_JMP_OP_MODE_CALL:
      op_name = "call";
      break;
    case FD_SBPF_OPCODE_JMP_OP_MODE_EXIT:
      op_name = "exit";
      break;
    case FD_SBPF_OPCODE_JMP_OP_MODE_JLT:
      op_name = "jlt";
      break;
    case FD_SBPF_OPCODE_JMP_OP_MODE_JLE:
      op_name = "jle";
      break;
    case FD_SBPF_OPCODE_JMP_OP_MODE_JSLT:
      op_name = "jslt";
      break;
    case FD_SBPF_OPCODE_JMP_OP_MODE_JSLE:
      op_name = "jsle";
      break;
    default:
      return 1;
  }

  if( FD_UNLIKELY( instr.opcode.normal.op_mode == FD_SBPF_OPCODE_JMP_OP_MODE_CALL ) ) {
    switch ( instr.opcode.normal.op_src ) {
      case FD_SBPF_OPCODE_SOURCE_MODE_IMM: {
        fd_sbpf_syscalls_t * syscall = fd_sbpf_syscalls_query( syscalls, instr.imm, NULL );
        if( syscall ) {
          char const * name = syscall->name;
          if( name ) {
            OUT_PRINTF( "syscall%s %s",     suffix, name ? name : "???" );
          } else {
            OUT_PRINTF( "syscall%s 0x%08x", suffix, instr.imm );
          }
        } else {
          uint pc = fd_pchash_inverse( instr.imm );
          if( pc<(10<<17) )  /* TODO hardcoded constant */
            OUT_PRINTF( "%s%s function_%u", op_name, suffix, pc );
          else
            OUT_PRINTF( "%s%s function_%#x", op_name, suffix, instr.imm );
        }
        break;
      }
      case FD_SBPF_OPCODE_SOURCE_MODE_REG:
        OUT_PRINTF( "%sx%s r%d", op_name, suffix, instr.imm );
        break;
    }
    return 1;
  }

  if( FD_UNLIKELY( instr.opcode.normal.op_mode == FD_SBPF_OPCODE_JMP_OP_MODE_EXIT ) ) {
    OUT_PRINTF( "%s%s", op_name, suffix );
    return 1;
  }

  if( FD_UNLIKELY( instr.opcode.normal.op_mode == FD_SBPF_OPCODE_JMP_OP_MODE_JA ) ) {
    OUT_PRINTF( "%s%s lbb_%ld", op_name, suffix, (long)pc+(long)instr.offset+1 );
    return 1;
  }

  switch( instr.opcode.normal.op_src ) {
    case FD_SBPF_OPCODE_SOURCE_MODE_IMM:
      OUT_PRINTF( "%s%s r%d, %d, lbb_%ld",  op_name, suffix, instr.dst_reg, instr.imm,     (long)pc+(long)instr.offset+1 );
      break;
    case FD_SBPF_OPCODE_SOURCE_MODE_REG:
      OUT_PRINTF( "%s%s r%d, r%d, lbb_%ld", op_name, suffix, instr.dst_reg, instr.src_reg, (long)pc+(long)instr.offset+1 );
      break;
  }

  return 1;
}

static int
fd_vm_disassemble_instr_ldx( fd_sbpf_instr_t instr,
                             char *          out,
                             ulong *         out_len ) {


  char * op_name;
  switch (instr.opcode.mem.op_size) {
    case FD_SBPF_OPCODE_SIZE_MODE_WORD:
      op_name = "ldxw";
      break;
    case FD_SBPF_OPCODE_SIZE_MODE_HALF:
      op_name = "ldxh";
      break;
    case FD_SBPF_OPCODE_SIZE_MODE_BYTE:
      op_name = "ldxb";
      break;
    case FD_SBPF_OPCODE_SIZE_MODE_DOUB:
      op_name = "ldxdw";
      break;
  }

  if( instr.offset < 0 ) {
    OUT_PRINTF( "%s r%d, [r%d-0x%x]", op_name, instr.dst_reg, instr.src_reg, -instr.offset );
  } else {
    OUT_PRINTF( "%s r%d, [r%d+0x%x]", op_name, instr.dst_reg, instr.src_reg,  instr.offset );
  }

  return 1;
}

static int
fd_vm_disassemble_instr_stx( fd_sbpf_instr_t instr,
                             char *          out,
                             ulong *          out_len ) {

  char * op_name;
  switch (instr.opcode.mem.op_size) {
    case FD_SBPF_OPCODE_SIZE_MODE_WORD:
      op_name = "stxw";
      break;
    case FD_SBPF_OPCODE_SIZE_MODE_HALF:
      op_name = "stxh";
      break;
    case FD_SBPF_OPCODE_SIZE_MODE_BYTE:
      op_name = "stxb";
      break;
    case FD_SBPF_OPCODE_SIZE_MODE_DOUB:
      op_name = "stxdw";
      break;
  }

  if( instr.offset < 0 ) {
    OUT_PRINTF( "%s [r%d-0x%x], r%d", op_name, instr.dst_reg, -instr.offset, instr.src_reg );
  } else {
    OUT_PRINTF( "%s [r%d+0x%x], r%d", op_name, instr.dst_reg,  instr.offset, instr.src_reg );
  }

  return 1;
}

int
fd_vm_disassemble_instr( fd_sbpf_instr_t const * instr,
                         ulong                   pc,
                         fd_sbpf_syscalls_t *    syscalls,
                         void *                  _out,
                         ulong *                 out_len ) {
  char * out = (char *)_out;

  switch( instr->opcode.any.op_class ) {
    case FD_SBPF_OPCODE_CLASS_LD:
      OUT_PRINTF( "lddw r%d, 0x%lx", instr->dst_reg, (ulong)((ulong)instr[0].imm | (ulong)((ulong)instr[1].imm << 32UL)) );
      break;
    case FD_SBPF_OPCODE_CLASS_LDX:
      return fd_vm_disassemble_instr_ldx( *instr, out, out_len);
    case FD_SBPF_OPCODE_CLASS_ST:
      break;
    case FD_SBPF_OPCODE_CLASS_STX:
      return fd_vm_disassemble_instr_stx( *instr, out, out_len );
    case FD_SBPF_OPCODE_CLASS_ALU:
      return fd_vm_disassemble_instr_alu( *instr, "", out, out_len );
    case FD_SBPF_OPCODE_CLASS_JMP:
      return fd_vm_disassemble_instr_jmp( *instr, pc, "", syscalls, out, out_len );
    case FD_SBPF_OPCODE_CLASS_JMP32:
      return fd_vm_disassemble_instr_jmp( *instr, pc, "32", syscalls, out, out_len );
    case FD_SBPF_OPCODE_CLASS_ALU64:
      return fd_vm_disassemble_instr_alu( *instr, "64", out, out_len );
  }
  return 1;
}

int
fd_vm_disassemble_program( fd_sbpf_instr_t const * instrs,
                           ulong                   instrs_cnt,
                           fd_sbpf_syscalls_t *    syscalls,
                           void *                  _out ) {
  char * out = (char *)_out;
  ulong len = 0;
  ulong * out_len = &len;

  OUT_PRINTF( "function_0:\n" );

  ulong label_pcs[65536];
  ulong num_label_pcs = 0;

  ulong func_pcs[65536];
  ulong num_func_pcs = 0;

  /* FIXME missing bounds checks on label_pcs */

  for( ulong i = 0; i < instrs_cnt; i++ ) {
    fd_sbpf_instr_t instr = instrs[i];

    if( instr.opcode.raw == FD_SBPF_OP_CALL_IMM ) {
      func_pcs[num_func_pcs] = i+instr.imm+1;
      num_func_pcs++;
    } else if( instr.opcode.raw == FD_SBPF_OP_EXIT ) {
      func_pcs[num_func_pcs] = i+instr.imm+1;
      num_func_pcs++;
    } else if( instr.opcode.raw == FD_SBPF_OP_CALL_REG ) {
      continue;
    } else if( instr.opcode.any.op_class == FD_SBPF_OPCODE_CLASS_JMP
               || instr.opcode.any.op_class == FD_SBPF_OPCODE_CLASS_JMP32 ) {
      label_pcs[num_label_pcs] = (ulong)((long)i+(long)instr.offset+1);
      num_label_pcs++;
    }
  }

  for( ulong i = 0; i < instrs_cnt; i++ ) {
    out += *out_len;
    *out_len = 0;

    uint label_found = 0;
    for( ulong j = 0; j < num_label_pcs; j++ ) {
      if( label_pcs[j] == i ) {
        label_found = 1;
        OUT_PRINTF( "lbb_%lu:\n", i );
        break;
      }
    }

    if( !label_found ) {
      for( ulong j = 0; j < num_func_pcs; j++ ) {
        if( func_pcs[j] == i ) {
          OUT_PRINTF( "\nfunction_%lu:\n", i );
          break;
        }
      }
    }

    OUT_PRINTF( "    " );

    fd_sbpf_instr_t const * instr = &instrs[i];

    if( FD_UNLIKELY( !fd_vm_disassemble_instr( instr, i, syscalls, out, out_len ) ) )
      return 0;

    OUT_PRINTF( "\n" );

    if( instr->opcode.raw == FD_SBPF_OP_LDDW ) {
      i++;
    }

    uint next_label_found = 0;
    for( ulong j = 0; j < num_label_pcs; j++ ) {
      if( label_pcs[j] == i+1 ) {
        next_label_found = 1;
        break;
      }
    }

    if( !next_label_found && ( instr->opcode.raw == FD_SBPF_OP_JA ) ) {
      OUT_PRINTF( "\nfunction_%lu:\n", i+1 );
    }
  }

  return 1;
}

# undef OUT_PRINTF

