#include <stdio.h>

#include "fd_sbpf_disasm.h"

#include "fd_opcodes.h"

static ulong 
fd_sbpf_disassemble_instr_alu( fd_vm_sbpf_instr_t instr, 
                             char const * suffix,
                             char * out, 
                             FD_FN_UNUSED ulong out_sz ) { 
  ulong consumed = 0;
  char * op_name;
  switch (instr.opcode.normal.op_mode) {
    case FD_BPF_OPCODE_ALU_OP_MODE_ADD:
      op_name = "add";
      break;
    case FD_BPF_OPCODE_ALU_OP_MODE_SUB:                                                       
      op_name = "sub";
      break;
    case FD_BPF_OPCODE_ALU_OP_MODE_MUL:                                                       
      op_name = "mul";
      break;
    case FD_BPF_OPCODE_ALU_OP_MODE_DIV:                                                       
      op_name = "div";
      break;
    case FD_BPF_OPCODE_ALU_OP_MODE_OR:                                                       
      op_name = "or";
      break;
    case FD_BPF_OPCODE_ALU_OP_MODE_AND:                                                       
      op_name = "and";
      break;
    case FD_BPF_OPCODE_ALU_OP_MODE_LSH:                                                       
      op_name = "lsh";
      break;
    case FD_BPF_OPCODE_ALU_OP_MODE_RSH:                                                       
      op_name = "rsh";
      break;
    case FD_BPF_OPCODE_ALU_OP_MODE_NEG:                                                       
      op_name = "neg";
      break;
    case FD_BPF_OPCODE_ALU_OP_MODE_MOD:                                                       
      op_name = "mod";
      break;
    case FD_BPF_OPCODE_ALU_OP_MODE_XOR:                                                       
      op_name = "xor";
      break;
    case FD_BPF_OPCODE_ALU_OP_MODE_MOV:
      op_name = "mov";
      break;
    case FD_BPF_OPCODE_ALU_OP_MODE_ARSH:                                       
      op_name = "arsh";
      break;
    case FD_BPF_OPCODE_ALU_OP_MODE_END:          
      op_name = "end";
      break;
    default:
      return 0;
  }

  if( FD_UNLIKELY( instr.opcode.normal.op_mode == FD_BPF_OPCODE_ALU_OP_MODE_NEG ) ) {
    consumed += sprintf(out, "%s%s r%d", op_name, suffix, instr.dst_reg);
    return consumed;
  }

  switch ( instr.opcode.normal.op_src ) {
    case FD_BPF_OPCODE_SOURCE_MODE_IMM:
      consumed += sprintf(out, "%s%s r%d, %d", op_name, suffix, instr.dst_reg, instr.imm);
      break;
    case FD_BPF_OPCODE_SOURCE_MODE_REG:
      consumed += sprintf(out, "%s%s r%d, r%d", op_name, suffix, instr.dst_reg, instr.src_reg);
      break;
    default: 
      return 0;
  }

  return consumed;
}

static ulong 
fd_sbpf_disassemble_instr_jmp( fd_vm_sbpf_instr_t instr, 
                             ulong pc,
                             char const * suffix,
                             char * out, 
                             FD_FN_UNUSED ulong out_sz ) { 
  ulong consumed = 0;
  char * op_name;
  switch (instr.opcode.normal.op_mode) {
    case FD_BPF_OPCODE_JMP_OP_MODE_JA:
      op_name = "ja";
      break;
    case FD_BPF_OPCODE_JMP_OP_MODE_JEQ:
      op_name = "jeq";
      break;
    case FD_BPF_OPCODE_JMP_OP_MODE_JGT:
      op_name = "jgt";
      break;
    case FD_BPF_OPCODE_JMP_OP_MODE_JGE:
      op_name = "jge";
      break;
    case FD_BPF_OPCODE_JMP_OP_MODE_JSET:
      op_name = "jset";
      break;
    case FD_BPF_OPCODE_JMP_OP_MODE_JNE:
      op_name = "jne";
      break;
    case FD_BPF_OPCODE_JMP_OP_MODE_JSGT:
      op_name = "jsgt";
      break;
    case FD_BPF_OPCODE_JMP_OP_MODE_JSGE:
      op_name = "jsge";
      break;
    case FD_BPF_OPCODE_JMP_OP_MODE_CALL:
      op_name = "call";
      break;
    case FD_BPF_OPCODE_JMP_OP_MODE_EXIT:
      op_name = "exit";
      break;
    case FD_BPF_OPCODE_JMP_OP_MODE_JLT:
      op_name = "jlt";
      break;
    case FD_BPF_OPCODE_JMP_OP_MODE_JLE:      
      op_name = "jle";
      break;
    case FD_BPF_OPCODE_JMP_OP_MODE_JSLT:
      op_name = "jslt";
      break;
    case FD_BPF_OPCODE_JMP_OP_MODE_JSLE:   
      op_name = "jsle";
      break;
    default:
      return 0;
  }
  
  if( FD_UNLIKELY( instr.opcode.normal.op_mode == FD_BPF_OPCODE_JMP_OP_MODE_CALL ) ) {
    switch ( instr.opcode.normal.op_src ) {
      case FD_BPF_OPCODE_SOURCE_MODE_IMM:
        consumed += sprintf(out, "%s%s function_%ld", op_name, suffix, (long)((long)pc+(int)instr.imm+1L));
        break;
      case FD_BPF_OPCODE_SOURCE_MODE_REG:
        consumed += sprintf(out, "%sx%s r%d", op_name, suffix, instr.imm);
        break;
      default: 
        return 0;
    }
    return consumed;
  }
  
  if( FD_UNLIKELY( instr.opcode.normal.op_mode == FD_BPF_OPCODE_JMP_OP_MODE_EXIT ) ) {
    consumed += sprintf(out, "%s%s", op_name, suffix);
    return consumed;
  }
  
  if( FD_UNLIKELY( instr.opcode.normal.op_mode == FD_BPF_OPCODE_JMP_OP_MODE_JA ) ) {
    consumed += sprintf(out, "%s%s lbb_%ld", op_name, suffix, pc+instr.offset+1);
    return consumed;
  }
  
  switch ( instr.opcode.normal.op_src ) {
    case FD_BPF_OPCODE_SOURCE_MODE_IMM:
      consumed += sprintf(out, "%s%s r%d, %d, lbb_%ld", op_name, suffix, instr.dst_reg, instr.imm, pc+instr.offset+1);
      break;
    case FD_BPF_OPCODE_SOURCE_MODE_REG:
      consumed += sprintf(out, "%s%s r%d, r%d, lbb_%ld", op_name, suffix, instr.dst_reg, instr.src_reg, pc+instr.offset+1);
      break;
    default: 
      return 0;
  }

  return consumed;
}

static ulong 
fd_sbpf_disassemble_instr_ldx( fd_vm_sbpf_instr_t instr, 
                               char * out, 
                               FD_FN_UNUSED ulong out_sz ) { 

  ulong consumed = 0;
  char * op_name;
  switch (instr.opcode.mem.op_size) {
    case FD_BPF_OPCODE_SIZE_MODE_WORD:
      op_name = "ldxw";
      break;
    case FD_BPF_OPCODE_SIZE_MODE_HALF:
      op_name = "ldxh";
      break;
    case FD_BPF_OPCODE_SIZE_MODE_BYTE:
      op_name = "ldxb";
      break;
    case FD_BPF_OPCODE_SIZE_MODE_QUAD:
      op_name = "ldxdw";
      break;
  }
  
  if( instr.offset < 0 ) {
    consumed += sprintf(out, "%s r%d, [r%d-0x%x]", op_name, instr.dst_reg, instr.src_reg, -instr.offset);
  } else {
    consumed += sprintf(out, "%s r%d, [r%d+0x%x]", op_name, instr.dst_reg, instr.src_reg, instr.offset);
  }

  return consumed;
}

static ulong 
fd_sbpf_disassemble_instr_stx( fd_vm_sbpf_instr_t instr, 
                               char * out, 
                               FD_FN_UNUSED ulong out_sz ) { 

  ulong consumed = 0;
  char * op_name;
  switch (instr.opcode.mem.op_size) {
    case FD_BPF_OPCODE_SIZE_MODE_WORD:
      op_name = "stxw";
      break;
    case FD_BPF_OPCODE_SIZE_MODE_HALF:
      op_name = "stxh";
      break;
    case FD_BPF_OPCODE_SIZE_MODE_BYTE:
      op_name = "stxb";
      break;
    case FD_BPF_OPCODE_SIZE_MODE_QUAD:
      op_name = "stxdw";
      break;
  }
    
  if( instr.offset < 0 ) {
    consumed += sprintf(out, "%s [r%d-0x%x], r%d", op_name, instr.dst_reg, -instr.offset, instr.src_reg);
  } else {
    consumed += sprintf(out, "%s [r%d+0x%x], r%d", op_name, instr.dst_reg, instr.offset, instr.src_reg);
  }

  return consumed;
}

static ulong 
fd_sbpf_disassemble_instr( fd_vm_sbpf_instr_t const * instr, 
                          ulong pc,
                          char * out, 
                         FD_FN_UNUSED ulong out_sz ) { 
  ulong consumed = 0;
  switch( instr->opcode.any.op_class ) {
    case FD_BPF_OPCODE_CLASS_LD:
      consumed += sprintf(out, "lddw r%d, 0x%lx %x %x", instr->dst_reg, (ulong)((ulong)instr[0].imm | (ulong)((ulong)instr[1].imm << 32UL)), instr[0].imm, instr[1].imm);
      break;
    case FD_BPF_OPCODE_CLASS_LDX:
      consumed += fd_sbpf_disassemble_instr_ldx( *instr, out, out_sz );
      break;
    case FD_BPF_OPCODE_CLASS_ST:
      break;
    case FD_BPF_OPCODE_CLASS_STX:
      consumed += fd_sbpf_disassemble_instr_stx( *instr, out, out_sz );
      break;
    case FD_BPF_OPCODE_CLASS_ALU:
      consumed += fd_sbpf_disassemble_instr_alu( *instr, "", out, out_sz );
      break;
    case FD_BPF_OPCODE_CLASS_JMP:
      consumed += fd_sbpf_disassemble_instr_jmp( *instr, pc, "", out, out_sz );
      break;
    case FD_BPF_OPCODE_CLASS_JMP32:
      consumed += fd_sbpf_disassemble_instr_jmp( *instr, pc, "32", out, out_sz );
      break;
    case FD_BPF_OPCODE_CLASS_ALU64:
      consumed += fd_sbpf_disassemble_instr_alu( *instr, "64", out, out_sz );
      break;
    default:
      return 0;
  }
  return consumed;
}

char * 
fd_sbpf_disassemble_program( fd_vm_sbpf_instr_t const *  instrs, 
                                  ulong                 instrs_sz, 
                                  char *                out, 
                                  FD_FN_UNUSED ulong                 out_sz ) {
  out += sprintf(out, "function_0:\n");
  ulong label_pcs[65536];
  ulong num_label_pcs = 0;
  
  ulong func_pcs[65536];
  ulong num_func_pcs = 0;

  for( ulong i = 0; i < instrs_sz; i++ ) {
    fd_vm_sbpf_instr_t instr = instrs[i];

    if( instr.opcode.raw == FD_BPF_OP_CALL_IMM ) {
      func_pcs[num_func_pcs] = i+instr.imm+1;
      num_func_pcs++;
    } else if( instr.opcode.raw == FD_BPF_OP_EXIT ) {
      func_pcs[num_func_pcs] = i+instr.imm+1;
      num_func_pcs++;
    } else if( instr.opcode.raw == FD_BPF_OP_CALL_REG ) {
      continue;
    } else if( instr.opcode.any.op_class == FD_BPF_OPCODE_CLASS_JMP                                        
               || instr.opcode.any.op_class == FD_BPF_OPCODE_CLASS_JMP32 ) {
      label_pcs[num_label_pcs] = i+instr.offset+1;
      num_label_pcs++;
    }
  }

  char * original_out = out;
  for( ulong i = 0; i < instrs_sz; i++ ) {
    uint label_found = 0;
    for( ulong j = 0; j < num_label_pcs; j++ ) {
      if( label_pcs[j] == i ) {
        label_found = 1;
        //fd_vm_sbpf_instr_t prev_instr = instrs[i-1];

        //if( prev_instr.opcode.normal.op_mode == FD_BPF_OPCODE_JMP_OP_MODE_EXIT ) {
        //  out += sprintf(out, "\nfunction_%lu:\n", i+1);
         
        //} else {
          out += sprintf(out, "lbb_%lu:\n", i);
        //}
        break;
      }
    }
   
    if( !label_found ) {
      for( ulong j = 0; j < num_func_pcs; j++ ) {
        if( func_pcs[j] == i ) {
          out += sprintf(out, "\nfunction_%lu:\n", i);
          break;
        }
      }
    }

    fd_memset(out, ' ',  4);
    out += 4;
    
    fd_vm_sbpf_instr_t const * instr = &instrs[i];

    out += fd_sbpf_disassemble_instr(instr, i, out, out_sz);

    *out = '\n';
    out++;

    if( instr->opcode.raw == FD_BPF_OP_LDQ ) {
      i++;
    }

    uint next_label_found = 0;
    for( ulong j = 0; j < num_label_pcs; j++ ) {
      if( label_pcs[j] == i+1 ) {
        next_label_found = 1;
        break;
      }
    }
    
    if( !next_label_found && ( instr->opcode.raw == FD_BPF_OP_JA ) ) {
      out += sprintf(out, "\nfunction_%lu:\n", i+1);
    }
  }

  return original_out;
}
