  /* This is the VM SBPF interpreter core.  The caller unpacks the VM
     state and then just lets execution continue into this (or jumps to
     interp_exec) to start running.  The VM will run until it halts or
     faults.  On normal termination, it will branch to interp_halt to
     exit.  Each fault has its own exit label to allow the caller to
     handle individually.  FIXME: DOCUMENT LABELS. */

  /* FIXME: SIGILLS FOR VARIOUS THINGS THAT HAVE UNNECESSARY BITS IN IMM
     SET? (LIKE WIDE SHIFTS?) */
  /* FIXME: WHAT ABOUT RUNNING UNVALIDATED BYTE CODE? */

# if defined(__GNUC__) /* -Wpedantic rejects labels as values and rejects goto *expr */
# pragma GCC diagnostic push
# pragma GCC diagnostic ignored "-Wpedantic"
# pragma GCC diagnostic ignored "-Wmaybe-uninitialized" /* Suppress false positives (FIXME: HMMM) */
# endif

# if defined(__clang__) /* Clang is differently picky about labels as values and goto *expr */
# pragma clang diagnostic push
# pragma clang diagnostic ignored "-Wpedantic"
# pragma clang diagnostic ignored "-Wgnu-label-as-value"
# endif

  /* Include the jump table */

# include "fd_vm_interp_jump_table.c" /* FIXME: RENAME TO FD_VM_INTERP_JUMP_TABLE */

  /* These fields hold the instruction word at pc and the prefetched of reg_dst / reg_src. */

  /* JT_INSTR_EXEC loads the instruction at pc, parses, fetchs the
     associated register values and then executes the corresponding
     instruction.  After normal instruction execution, the pc will be
     updated and JT_INSTR_EXEC will be invoked again to do then next
     interation.  After a normal halt, this will branch to interp_halt.
     Otherwise, it will branch to the appropriate normal termination. */

  ulong instr;
  ulong opcode;
  ulong dst;
  ulong src;
  short offset;
  uint  imm;
  ulong reg_dst;
  ulong reg_src;

# define JT_INSTR_EXEC                                                           \
  instr   = text[ pc ];                  /* FIXME: GUARANTEES ON PC? */          \
  opcode  = fd_vm_instr_opcode( instr ); /* in [0,256) even if malformed */      \
  dst     = fd_vm_instr_dst   ( instr ); /* in [0, 16) even if malformed */      \
  src     = fd_vm_instr_src   ( instr ); /* in [0, 16) even if malformed */      \
  offset  = fd_vm_instr_offset( instr ); /* in [-2^15,2^15) even if malformed */ \
  imm     = fd_vm_instr_imm   ( instr ); /* in [0,2^32) even if malformed */     \
  reg_dst = reg[ dst ];                  /* Guaranteed in-bounds */              \
  reg_src = reg[ src ];                  /* Guaranteed in-bounds */              \
  goto *interp_jump_table[ opcode ]      /* Guaranteed in-bounds */

  /* JT_INSTR_BEGIN / JT_INSTR_END bracket opcode's implementation for
     an opcode that does not branch.  On entry, the instruction word has
     been unpacked the ulongs dst / src / offset / imm and reg[dst] and
     reg[src] have been preloaded into reg_dst and reg_src. */

# define JT_INSTR_BEGIN(opcode) JT_CASE(opcode)

# if 1 /* Non-tracing path only, ~0.3% faster in benchmarks but more code footprint */
# define JT_INSTR_END pc++; JT_INSTR_EXEC
# else /* Use this branch when tracing or wanting a small code footprint */
# define JT_INSTR_END pc++; goto interp_exec
# endif

  /* FIXME: CLEAN UP BRANCHING CODE PATHS */
# define BRANCH_PRE_CODE             \
  do {                               \
    ulong insns = pc - start_pc + 1UL; /* FIXME: TRIGGERS SPURIOUS UNINIT WARNING FOR SOME REASON */

# if 1 /* Non-tracing path only, ~4% faster in benchmarks but more code footprint */
# define BRANCH_POST_CODE                                                         \
    pc++;                                                                         \
    start_pc       = pc;                                                          \
    ic            += insns - skipped_insns;                                       \
    due_insn_cnt  += insns - skipped_insns;                                       \
    skipped_insns  = 0;                                                           \
    if( FD_UNLIKELY( due_insn_cnt >= previous_instruction_meter ) ) goto sigcost; \
    JT_INSTR_EXEC;                                                                \
  } while(0);
# else /* Use this branch when tracing or wanting a small code footprint */
# define BRANCH_POST_CODE                                                         \
    pc++;                                                                         \
    start_pc       = pc;                                                          \
    ic            += insns - skipped_insns;                                       \
    due_insn_cnt  += insns - skipped_insns;                                       \
    skipped_insns  = 0;                                                           \
    if( FD_UNLIKELY( due_insn_cnt >= previous_instruction_meter ) ) goto sigcost; \
    goto interp_exec;                                                             \
  } while(0);
# endif

#define JT_CASE(opcode) interp_##opcode:
#define JT_CASE_END

  goto interp_exec; /* Avoid unused label warning */
interp_exec:

  /* Note: in a tracing mode of execution and a small code footprint
     mode of execution, all instruction execution starts here such that
     this is only point where exe tracing diagnostics are needed. */

  /* FIXME: exe tracing diagnostics go here */

  JT_INSTR_EXEC;

  /* 0x00 - 0x0f ******************************************************/

/* FIXME: MORE THINKING AROUND LDQ HANDLING HERE */
/* 0x00 */ JT_CASE(0x00); // FD_SBPF_OP_ADDL_IMM

  JT_INSTR_BEGIN(0x04) /* FD_SBPF_OP_ADD_IMM */
    reg[ dst ] = (ulong)( (uint)reg_dst + imm );
  JT_INSTR_END;

/* 0x05 */ JT_CASE(0x05) // FD_SBPF_OP_JA
BRANCH_PRE_CODE
  pc += (ulong)(long)offset;
BRANCH_POST_CODE
JT_CASE_END

  JT_INSTR_BEGIN(0x07) /* FD_SBPF_OP_ADD64_IMM */
    reg[ dst ] = reg_dst + (ulong)(long)(int)imm;
  JT_INSTR_END;

  JT_INSTR_BEGIN(0x0c) /* FD_SBPF_OP_ADD_REG */
    reg[ dst ] = (ulong)(uint)( reg_dst + reg_src );
  JT_INSTR_END;

  JT_INSTR_BEGIN(0x0f) /* FD_SBPF_OP_ADD64_REG */
    reg[ dst ] = reg_dst + reg_src;
  JT_INSTR_END;

  /* 0x10 - 0x1f ******************************************************/

  JT_INSTR_BEGIN(0x14) /* FD_SBPF_OP_SUB_IMM */
    reg[ dst ] = (ulong)( (uint)reg_dst - imm );
  JT_INSTR_END;

/* 0x15 */ JT_CASE(0x15) // FD_SBPF_OP_JEQ_IMM
BRANCH_PRE_CODE
  pc += ((long)reg_dst == (long)(int)imm) ? (ulong)(long)offset : 0UL;
BRANCH_POST_CODE
JT_CASE_END

  JT_INSTR_BEGIN(0x17) /* FD_SBPF_OP_SUB64_IMM */
    reg[ dst ] = reg_dst - (ulong)(long)(int)imm;
  JT_INSTR_END;

/* FIXME: MORE THINKING AROUND LDQ */
/* 0x18 */ JT_INSTR_BEGIN(0x18) // FD_SBPF_OP_LDQ
  reg[ dst ] = (ulong)((ulong)imm | ((ulong)fd_vm_instr_imm( text[pc+1UL] ) << 32));
  pc++;
  skipped_insns++;
JT_INSTR_END;

  JT_INSTR_BEGIN(0x1c) /* FD_SBPF_OP_SUB_REG */
    reg[ dst ] = (ulong)( (uint)reg_dst - (uint)reg_src );
  JT_INSTR_END;

/* 0x1d */ JT_CASE(0x1d) // FD_SBPF_OP_JEQ_REG
BRANCH_PRE_CODE
  pc += (reg_dst == reg_src) ? (ulong)(long)offset : 0UL;
BRANCH_POST_CODE
JT_CASE_END

  JT_INSTR_BEGIN(0x1f) /* FD_SBPF_OP_SUB64_REG */
    reg[ dst ] = reg_dst - reg_src;
  JT_INSTR_END;

  /* 0x20 - 0x2f ******************************************************/

  JT_INSTR_BEGIN(0x24) /* FD_SBPF_OP_MUL_IMM */
    reg[ dst ] = (ulong)( (uint)reg_dst * imm );
  JT_INSTR_END;

/* 0x25 */ JT_CASE(0x25) // FD_SBPF_OP_JGT_IMM
BRANCH_PRE_CODE
  pc += (reg_dst > (ulong)(long)(int)imm) ? (ulong)(long)offset : 0UL; /* FIXME: HMMM ... SIGNED OR UNSIGNED COMP */
BRANCH_POST_CODE
JT_CASE_END

  JT_INSTR_BEGIN(0x27) /* FD_SBPF_OP_MUL64_IMM */
    reg[ dst ] = (ulong)( (long)reg_dst * (long)(int)imm );
  JT_INSTR_END;

  JT_INSTR_BEGIN(0x2c) /* FD_SBPF_OP_MUL_REG */
    reg[ dst ] = (ulong)( (uint)reg_dst * (uint)reg_src );
  JT_INSTR_END;

/* 0x2d */ JT_CASE(0x2d) // FD_SBPF_OP_JGT_REG
BRANCH_PRE_CODE
  pc += (reg_dst > reg_src) ? (ulong)(long)offset : 0UL;
BRANCH_POST_CODE
JT_CASE_END

  JT_INSTR_BEGIN(0x2f) /* FD_SBPF_OP_MUL64_REG */
    reg[ dst ] = reg_dst * reg_src;
  JT_INSTR_END;

  /* 0x30 - 0x3f ******************************************************/

  JT_INSTR_BEGIN(0x34) /* FD_SBPF_OP_DIV_IMM */
    /* FIXME: is div-by-zero a fault? reject imm==0 at validation
       time?  convert to a multiply at validation time (usually probably
       not worth it) */
    reg[ dst ] = (ulong)( FD_UNLIKELY( !imm ) ? 0U : ((uint)reg_dst / imm) );
  JT_INSTR_END;

/* 0x35 */ JT_CASE(0x35) // FD_SBPF_OP_JGE_IMM
BRANCH_PRE_CODE
  pc += (reg_dst >= imm) ? (ulong)(long)offset : 0UL;
BRANCH_POST_CODE
JT_CASE_END

  JT_INSTR_BEGIN(0x37) /* FD_SBPF_OP_DIV64_IMM */ /* FIXME: see notes for OP_DIV_IMM */
    reg[ dst ] = FD_UNLIKELY( !imm ) ? 0UL : ( reg_dst / (ulong)imm );
  JT_INSTR_END;

  JT_INSTR_BEGIN(0x3c) /* FD_SBPF_OP_DIV_REG */ /* FIXME: IS DIV-BY-ZERO A FAULT? */
    reg[ dst ] = (ulong)( FD_UNLIKELY( !(uint)reg_src ) ? 0U : ((uint)reg_dst / (uint)reg_src) );
  JT_INSTR_END;

/* 0x3d */ JT_CASE(0x3d) // FD_SBPF_OP_JGE_REG
BRANCH_PRE_CODE
  pc += (reg_dst >= reg_src) ? (ulong)(long)offset : 0UL;
BRANCH_POST_CODE
JT_CASE_END

  JT_INSTR_BEGIN(0x3f) /* FD_SBPF_OP_DIV64_REG */ /* FIXME: IS DIV-BY-ZERO A FAULT? */
    reg[ dst ] = FD_UNLIKELY( !reg_src ) ? 0UL : (reg_dst / reg_src);
  JT_INSTR_END;

  /* 0x40 - 0x4f ******************************************************/

  JT_INSTR_BEGIN(0x44) /* FD_SBPF_OP_OR_IMM */
    reg[ dst ] = (ulong)( (uint)reg_dst | imm );
  JT_INSTR_END;

/* 0x45 */ JT_CASE(0x45) // FD_SBPF_OP_JSET_IMM
BRANCH_PRE_CODE
  pc += (reg_dst & imm) ? (ulong)(long)offset : 0UL;
BRANCH_POST_CODE
JT_CASE_END

  JT_INSTR_BEGIN(0x47) /* FD_SBPF_OP_OR64_IMM */
    reg[ dst ] = reg_dst | (ulong)(long)(int)imm;
  JT_INSTR_END;

  JT_INSTR_BEGIN(0x4c) /* FD_SBPF_OP_OR_REG */
    reg[ dst ] = (ulong)(uint)( reg_dst | reg_src );
  JT_INSTR_END;

/* 0x4d */ JT_CASE(0x4d) // FD_SBPF_OP_JSET_REG
BRANCH_PRE_CODE
  pc += (reg_dst & reg_src) ? (ulong)(long)offset : 0UL;
BRANCH_POST_CODE
JT_CASE_END

  JT_INSTR_BEGIN(0x4f) /* FD_SBPF_OP_OR64_REG */
    reg[ dst ] = reg_dst | reg_src;
  JT_INSTR_END;

  /* 0x50 - 0x5f ******************************************************/

  JT_INSTR_BEGIN(0x54) /* FD_SBPF_OP_AND_IMM */
    reg[ dst ] = (ulong)( (uint)reg_dst & imm );
  JT_INSTR_END;

/* 0x55 */ JT_CASE(0x55) // FD_SBPF_OP_JNE_IMM
BRANCH_PRE_CODE
  pc += ((long)reg_dst != (long)(int)imm) ? (ulong)(long)offset : 0UL;
BRANCH_POST_CODE
JT_CASE_END

  JT_INSTR_BEGIN(0x57) /* FD_SBPF_OP_AND64_IMM */
    reg[ dst ] = reg_dst & (ulong)(long)(int)imm;
  JT_INSTR_END;

  JT_INSTR_BEGIN(0x5c) /* FD_SBPF_OP_AND_REG */
    reg[ dst ] = (ulong)(uint)( reg_dst & reg_src );
  JT_INSTR_END;

/* 0x5d */ JT_CASE(0x5d) // FD_SBPF_OP_JNE_REG
BRANCH_PRE_CODE
  pc += (reg_dst != reg_src) ? (ulong)(long)offset : 0UL;
BRANCH_POST_CODE
JT_CASE_END

  JT_INSTR_BEGIN(0x5f) /* FD_SBPF_OP_AND64_REG */
    reg[ dst ] = reg_dst & reg_src;
  JT_INSTR_END;

  /* 0x60 - 0x6f ******************************************************/

  JT_INSTR_BEGIN(0x61) { /* FD_SBPF_OP_LDXW */
    ulong vaddr   = reg_src + (ulong)(long)offset;
    ulong haddr   = fd_vm_mem_haddr( vaddr, sizeof(uint), region_haddr, region_ld_sz, 0UL );
    int   sigsegv = !haddr;
    int   sigbus  = check_align & !fd_ulong_is_aligned( vaddr, sizeof(uint) );
    if( FD_UNLIKELY( sigsegv | sigbus ) ) goto *(sigsegv ? &&sigsegv : &&sigbus); /* Note: untaken branches don't consume BTB */
    reg[ dst ] = fd_vm_mem_ld_4( haddr );
  }
  JT_INSTR_END;

  JT_INSTR_BEGIN(0x62) { /* FD_SBPF_OP_STW */
    ulong vaddr   = reg_dst + (ulong)(long)offset;
    ulong haddr   = fd_vm_mem_haddr( vaddr, sizeof(uint), region_haddr, region_st_sz, 0UL );
    int   sigsegv = !haddr;
    int   sigbus  = check_align & !fd_ulong_is_aligned( vaddr, sizeof(uint) );
    if( FD_UNLIKELY( sigsegv | sigbus ) ) goto *(sigsegv ? &&sigsegv : &&sigbus); /* Note: untaken branches don't consume BTB */
    fd_vm_mem_st_4( haddr, imm );
  }
  JT_INSTR_END;

  JT_INSTR_BEGIN(0x63) { /* FD_SBPF_OP_STXW */
    ulong vaddr   = reg_dst + (ulong)(long)offset;
    ulong haddr   = fd_vm_mem_haddr( vaddr, sizeof(uint), region_haddr, region_st_sz, 0UL );
    int   sigsegv = !haddr;
    int   sigbus  = check_align & !fd_ulong_is_aligned( vaddr, sizeof(uint) );
    if( FD_UNLIKELY( sigsegv | sigbus ) ) goto *(sigsegv ? &&sigsegv : &&sigbus); /* Note: untaken branches don't consume BTB */
    fd_vm_mem_st_4( haddr, (uint)reg_src );
  }
  JT_INSTR_END;

  JT_INSTR_BEGIN(0x64) /* FD_SBPF_OP_LSH_IMM */
    reg[ dst ] = (ulong)( (uint)reg_dst << imm ); /* FIXME: WIDE SHIFT */
  JT_INSTR_END;

/* 0x65 */ JT_CASE(0x65) // FD_SBPF_OP_JSGT_IMM
BRANCH_PRE_CODE
  pc += ((long)reg_dst > (long)(int)imm) ? (ulong)(long)offset : 0UL;
BRANCH_POST_CODE
JT_CASE_END

  JT_INSTR_BEGIN(0x67) /* FD_SBPF_OP_LSH64_IMM */
    reg[ dst ] = reg_dst << imm; /* FIXME: WIDE SHIFT */
  JT_INSTR_END;

  JT_INSTR_BEGIN(0x69) { /* FD_SBPF_OP_LDXH */
    ulong vaddr   = reg_src + (ulong)(long)offset;
    ulong haddr   = fd_vm_mem_haddr( vaddr, sizeof(ushort), region_haddr, region_ld_sz, 0UL );
    int   sigsegv = !haddr;
    int   sigbus  = check_align & !fd_ulong_is_aligned( vaddr, sizeof(ushort) );
    if( FD_UNLIKELY( sigsegv | sigbus ) ) goto *(sigsegv ? &&sigsegv : &&sigbus); /* Note: untaken branches don't consume BTB */
    reg[ dst ] = fd_vm_mem_ld_2( haddr );
  }
  JT_INSTR_END;

  JT_INSTR_BEGIN(0x6a) { /* FD_SBPF_OP_STH */
    ulong vaddr   = reg_dst + (ulong)(long)offset;
    ulong haddr   = fd_vm_mem_haddr( vaddr, sizeof(ushort), region_haddr, region_st_sz, 0UL );
    int   sigsegv = !haddr;
    int   sigbus  = check_align & !fd_ulong_is_aligned( vaddr, sizeof(ushort) );
    if( FD_UNLIKELY( sigsegv | sigbus ) ) goto *(sigsegv ? &&sigsegv : &&sigbus); /* Note: untaken branches don't consume BTB */
    fd_vm_mem_st_2( haddr, (ushort)imm );
  }
  JT_INSTR_END;

  JT_INSTR_BEGIN(0x6b) { /* FD_SBPF_OP_STXH */
    ulong vaddr   = reg_dst + (ulong)(long)offset;
    ulong haddr   = fd_vm_mem_haddr( vaddr, sizeof(ushort), region_haddr, region_st_sz, 0UL );
    int   sigsegv = !haddr;
    int   sigbus  = check_align & !fd_ulong_is_aligned( vaddr, sizeof(ushort) );
    if( FD_UNLIKELY( sigsegv | sigbus ) ) goto *(sigsegv ? &&sigsegv : &&sigbus); /* Note: untaken branches don't consume BTB */
    fd_vm_mem_st_2( haddr, (ushort)reg_src );
  }
  JT_INSTR_END;

  JT_INSTR_BEGIN(0x6c) /* FD_SBPF_OP_LSH_REG */
    reg[ dst ] = (ulong)( (uint)reg_dst << (uint)reg_src ); /* FIXME: WIDE SHIFT */
  JT_INSTR_END;

/* 0x6d */ JT_CASE(0x6d) // FD_SBPF_OP_JSGT_REG
BRANCH_PRE_CODE
  pc += ((long)reg_dst > (long)reg_src) ? (ulong)(long)offset : 0UL;
BRANCH_POST_CODE
JT_CASE_END

  JT_INSTR_BEGIN(0x6f) /* FD_SBPF_OP_LSH64_REG */
    reg[ dst ] = reg_dst << reg_src; /* FIXME: WIDE SHIFT */
  JT_INSTR_END;

  /* 0x70 - 0x7f ******************************************************/

  JT_INSTR_BEGIN(0x71) { /* FD_SBPF_OP_LDXB */
    ulong vaddr = reg_src + (ulong)(long)offset;
    ulong haddr = fd_vm_mem_haddr( vaddr, sizeof(uchar), region_haddr, region_ld_sz, 0UL );
    if( FD_UNLIKELY( !haddr ) ) goto sigsegv; /* Note: untaken branches don't consume BTB */
    reg[ dst ] = fd_vm_mem_ld_1( haddr );
  }
  JT_INSTR_END;

  JT_INSTR_BEGIN(0x72) { /* FD_SBPF_OP_STB */
    ulong vaddr = reg_dst + (ulong)(long)offset;
    ulong haddr = fd_vm_mem_haddr( vaddr, sizeof(uchar), region_haddr, region_st_sz, 0UL );
    if( FD_UNLIKELY( !haddr ) ) goto sigsegv; /* Note: untaken branches don't consume BTB */
    fd_vm_mem_st_1( haddr, (uchar)imm );
  }
  JT_INSTR_END;

  JT_INSTR_BEGIN(0x73) { /* FD_SBPF_OP_STXB */
    ulong vaddr = reg_dst + (ulong)(long)offset;
    ulong haddr = fd_vm_mem_haddr( vaddr, sizeof(uchar), region_haddr, region_st_sz, 0UL );
    if( FD_UNLIKELY( !haddr ) ) goto sigsegv; /* Note: untaken branches don't consume BTB */
    fd_vm_mem_st_1( haddr, (uchar)reg_src );
  }
  JT_INSTR_END;

  JT_INSTR_BEGIN(0x74) /* FD_SBPF_OP_RSH_IMM */
    reg[ dst ] = (ulong)( (uint)reg_dst >> imm ); /* FIXME: WIDE SHIFTS */
  JT_INSTR_END;

/* 0x75 */ JT_CASE(0x75) // FD_SBPF_OP_JSGE_IMM
BRANCH_PRE_CODE
  pc += ((long)reg_dst >= (long)(int)imm) ? (ulong)(long)offset : 0UL;
BRANCH_POST_CODE
JT_CASE_END

  JT_INSTR_BEGIN(0x77) /* FD_SBPF_OP_RSH64_IMM */
    reg[ dst ] = reg_dst >> imm; /* FIXME: WIDE SHIFTS */
  JT_INSTR_END;

  JT_INSTR_BEGIN(0x79) { /* FD_SBPF_OP_LDXQ */
    ulong vaddr   = reg_src + (ulong)(long)offset;
    ulong haddr   = fd_vm_mem_haddr( vaddr, sizeof(ulong), region_haddr, region_ld_sz, 0UL );
    int   sigsegv = !haddr;
    int   sigbus  = check_align & !fd_ulong_is_aligned( vaddr, sizeof(ulong) );
    if( FD_UNLIKELY( sigsegv | sigbus ) ) goto *(sigsegv ? &&sigsegv : &&sigbus); /* Note: untaken branches don't consume BTB */
    reg[ dst ] = fd_vm_mem_ld_8( haddr );
  }
  JT_INSTR_END;

  JT_INSTR_BEGIN(0x7a) { /* FD_SBPF_OP_STQ */
    ulong vaddr   = reg_dst + (ulong)(long)offset;
    ulong haddr   = fd_vm_mem_haddr( vaddr, sizeof(ulong), region_haddr, region_st_sz, 0UL );
    int   sigsegv = !haddr;
    int   sigbus  = check_align & !fd_ulong_is_aligned( vaddr, sizeof(ulong) );
    if( FD_UNLIKELY( sigsegv | sigbus ) ) goto *(sigsegv ? &&sigsegv : &&sigbus); /* Note: untaken branches don't consume BTB */
    fd_vm_mem_st_8( haddr, (ulong)imm );
  }
  JT_INSTR_END;

  JT_INSTR_BEGIN(0x7b) { /* FD_SBPF_OP_STXQ */
    ulong vaddr   = reg_dst + (ulong)(long)offset;
    ulong haddr   = fd_vm_mem_haddr( vaddr, sizeof(ulong), region_haddr, region_st_sz, 0UL );
    int   sigsegv = !haddr;
    int   sigbus  = check_align & !fd_ulong_is_aligned( vaddr, sizeof(ulong) );
    if( FD_UNLIKELY( sigsegv | sigbus ) ) goto *(sigsegv ? &&sigsegv : &&sigbus); /* Note: untaken branches don't consume BTB */
    fd_vm_mem_st_8( haddr, reg_src );
  }
  JT_INSTR_END;

  JT_INSTR_BEGIN(0x7c) /* FD_SBPF_OP_RSH_REG */
    reg[ dst ] = (ulong)( (uint)reg_dst >> (uint)reg_src ); /* FIXME: WIDE SHIFTS */
  JT_INSTR_END;

/* 0x7d */ JT_CASE(0x7d) // FD_SBPF_OP_JSGE_REG
BRANCH_PRE_CODE
  pc += ((long)reg_dst >= (long)reg_src) ? (ulong)(long)offset : 0UL;
BRANCH_POST_CODE
JT_CASE_END

  JT_INSTR_BEGIN(0x7f) /* FD_SBPF_OP_RSH64_REG */
    reg[ dst ] = reg_dst >> reg_src; /* FIXME: WIDE SHIFTS */
  JT_INSTR_END;

  /* 0x80-0x8f ********************************************************/

  JT_INSTR_BEGIN(0x84) /* FD_SBPF_OP_NEG */
    reg[ dst ] = (ulong)( -(uint)reg_dst );
  JT_INSTR_END;

/* 0x85 */ JT_CASE(0x85) // FD_SBPF_OP_CALL_IMM
BRANCH_PRE_CODE
  if( (pc + (ulong)(long)(int)imm + 1UL)<text_cnt ) { /* FIXME: +1? */
    reg[10] += 0x2000;
    err = 0;
    fd_vm_stack_push( vm, pc, &reg[6] ); // FIXME: stack overflow fault
    pc += (ulong)(long)(int)imm;
  } else {
    compute_meter = fd_ulong_sat_sub(compute_meter, due_insn_cnt); vm->compute_meter = compute_meter;
    due_insn_cnt  = 0;                                             vm->due_insn_cnt  = 0;

    fd_sbpf_syscalls_t const * syscall = fd_sbpf_syscalls_query_const( syscalls, imm, NULL );
    if( !syscall ) {
      // FIXME: DO STACK STUFF correctly: move this r10 manipulation on success.
      reg[10] += 0x2000; // FIXME: MAGIC NUMBER
      fd_vm_stack_push( vm, pc, &reg[6] ); // FIXME: stack overflow fault.
      uint target_pc = fd_pchash_inverse( imm );
      if( FD_LIKELY( target_pc<text_cnt                             ) &&
          FD_LIKELY( fd_sbpf_calldests_test( calldests, target_pc ) ) ) pc  = target_pc - 1UL;
      else if( FD_LIKELY( imm==0x71e3cf81U ) ) /* FIXME: MAGIC */       pc  = entrypoint - 1UL;
      else                                                              err = 1; /* FIXME: real error for nonexistent func */
    } else {
      err = syscall->func( vm, reg[1], reg[2], reg[3], reg[4], reg[5], &reg[0] );
      compute_meter = vm->compute_meter;
      /* FIXME: ARE SYSCALLS ALLOWED TO TOUCH OTHER VM VARIABLES? */
    }

    previous_instruction_meter = compute_meter; vm->previous_instruction_meter = previous_instruction_meter;
  }
  goto *(!err ? &&fallthrough_0x85 : &&sigcall);
fallthrough_0x85:
BRANCH_POST_CODE
JT_CASE_END

  JT_INSTR_BEGIN(0x87) /* FD_SBPF_OP_NEG64 */
    reg[ dst ] = -reg_dst;
  JT_INSTR_END;

/* 0x8d */ JT_CASE(0x8d)  // FD_SBPF_OP_CALL_REG
BRANCH_PRE_CODE
{
  /* Check if we are in the read only region */
  ulong call_addr = reg[imm]; /* FIXME: WHAT THE HECK? */
  // FIXME: check alignment
  // FIXME: check for run into other region.
  ulong start_addr = call_addr & FD_VM_MEM_MAP_REGION_SZ;
  // FIXME: DO STACK STUFF correctly: move this r10 manipulation on success.
  reg[10] += 0x2000; // FIXME: MAGIC NUMBER
  err = fd_vm_stack_push( vm, pc, &reg[6] ); // FIXME: stack overflow fault
  pc  = (start_addr/8UL) - 1UL;
  pc -= text_word_off;
  /* TODO verify that program counter is within bounds */
  /* TODO when static_syscalls are enabled, check that the call destination is valid */
  goto *(!err ? &&fallthrough_0x8d : &&sigcall);
}
fallthrough_0x8d:
BRANCH_POST_CODE
JT_CASE_END

  /* 0x90 - 0x9f ******************************************************/

  JT_INSTR_BEGIN(0x94) /* FD_SBPF_OP_MOD_IMM */ /* FIXME: IS MOD ZERO A FAULT?  DETECT IN VALIDATION? */
    reg[ dst ] = (ulong)( FD_UNLIKELY( !imm ) ? (uint)reg_dst : ((uint)reg_dst % imm) );
  JT_INSTR_END;

/* 0x95 */ JT_CASE(0x95) // FD_SBPF_OP_EXIT
BRANCH_PRE_CODE
  reg[10] -= 0x2000;
  if( FD_UNLIKELY( fd_vm_stack_is_empty( vm ) ) ) {
    if( due_insn_cnt > previous_instruction_meter ) goto sigcost;
    goto interp_halt;
  }
  fd_vm_stack_pop( vm, (ulong *)&pc, &reg[6] ); /* FIXME: DON'T LEAK THE POINTER */
BRANCH_POST_CODE
JT_CASE_END

  JT_INSTR_BEGIN(0x97) /* FD_SBPF_OP_MOD64_IMM */ /* FIXME: IS MOD ZERO A FAULT?  DETECT IN VALIDATION? */
    reg[ dst ] = FD_UNLIKELY( !imm ) ? reg_dst : (reg_dst % (ulong)imm);
  JT_INSTR_END;

  JT_INSTR_BEGIN(0x9c) /* FD_SBPF_OP_MOD_REG */ /* FIXME: IS MOD ZERO A FAULT? */
    reg[ dst ] = (ulong)( FD_UNLIKELY( !(uint)reg_src ) ? (uint)reg_dst : ((uint)reg_dst % (uint)reg_src) );
  JT_INSTR_END;

  JT_INSTR_BEGIN(0x9f) /* FD_SBPF_OP_MOD64_REG */ /* FIXME: IS MOD ZERO A FAULT? */
    reg[ dst ] = FD_UNLIKELY( !reg_src ) ? reg_dst : (reg_dst % reg_src);
  JT_INSTR_END;

  /* 0xa0 - 0xaf ******************************************************/

  JT_INSTR_BEGIN(0xa4) /* FD_SBPF_OP_XOR_IMM */
    reg[ dst ] = (ulong)( (uint)reg_dst ^ imm );
  JT_INSTR_END;

/* 0xa5 */ JT_CASE(0xa5) // FD_SBPF_OP_JLT_IMM
BRANCH_PRE_CODE
  pc += (reg_dst < imm) ? (ulong)(long)offset : 0UL;
BRANCH_POST_CODE
JT_CASE_END

  JT_INSTR_BEGIN(0xa7) /* FD_SBPF_OP_XOR64_IMM */
    reg[ dst ] = reg_dst ^ (ulong)(long)(int)imm;
  JT_INSTR_END;

  JT_INSTR_BEGIN(0xac) /* FD_SBPF_XOR_REG */
    reg[ dst ] = (ulong)(uint)( reg_dst ^ reg_src );
  JT_INSTR_END;

/* 0xad */ JT_CASE(0xad) // FD_SBPF_OP_JLT_REG
BRANCH_PRE_CODE
  pc += (reg_dst < reg_src) ? (ulong)(long)offset : 0UL;
BRANCH_POST_CODE
JT_CASE_END

  JT_INSTR_BEGIN(0xaf) /* FD_SBPF_OP_XOR64_REG */
    reg[ dst ] = reg_dst ^ reg_src;
  JT_INSTR_END;

  /* 0xb0 - 0xbf ******************************************************/

  JT_INSTR_BEGIN(0xb4) /* FD_SBPF_OP_MOV_IMM */
    reg[ dst ] = (ulong)imm;
  JT_INSTR_END;

/* 0xb5 */ JT_CASE(0xb5) // FD_SBPF_OP_JLE_IMM
BRANCH_PRE_CODE
  pc += (reg_dst <= imm) ? (ulong)(long)offset : 0UL;
BRANCH_POST_CODE
JT_CASE_END

  JT_INSTR_BEGIN(0xb7) /* FD_SBPF_OP_MOV64_IMM */
    reg[ dst ] = (ulong)(long)(int)imm;
  JT_INSTR_END;

  JT_INSTR_BEGIN(0xbc) /* FD_SBPF_OP_MOV_REG */
    reg[ dst ] = (ulong)(uint)reg_src;
  JT_INSTR_END;

/* 0xbd */ JT_CASE(0xbd) // FD_SBPF_OP_JLE_REG
BRANCH_PRE_CODE
  pc += (reg_dst <= reg_src) ? (ulong)(long)offset : 0UL;
BRANCH_POST_CODE
JT_CASE_END

  JT_INSTR_BEGIN(0xbf) /* FD_SBPF_OP_MOV64_REG */
    reg[ dst ] = reg_src;
  JT_INSTR_END;

  /* 0xc0 - 0xcf ******************************************************/

  JT_INSTR_BEGIN(0xc4) /* FD_SBPF_OP_ARSH_IMM */
    reg[ dst ] = (ulong)(uint)( (int)reg_dst >> imm ); /* FIXME: WIDE SHIFTS, STRICT SIGN EXTENSION */
  JT_INSTR_END;

/* 0xc5 */ JT_CASE(0xc5) // FD_SBPF_OP_JSLT_IMM
BRANCH_PRE_CODE
  pc += ((long)reg_dst < (long)imm) ? (ulong)(long)offset : 0UL;
BRANCH_POST_CODE
JT_CASE_END

  JT_INSTR_BEGIN(0xc7) /* FD_SBPF_OP_ARSH64_IMM */
    reg[ dst ] = (ulong)( (long)reg_dst >> imm ); /* FIXME: WIDE SHIFTS, STRICT SIGN EXTENSION */
  JT_INSTR_END;

  JT_INSTR_BEGIN(0xcc) /* FD_SBPF_OP_ARSH_REG */
    reg[ dst ] = (ulong)(uint)( (int)reg_dst >> (uint)reg_src ); /* FIXME: WIDE SHIFTS, STRICT SIGN EXTENSION */
  JT_INSTR_END;

/* 0xcd */ JT_CASE(0xcd) // FD_SBPF_OP_JSLT_REG
BRANCH_PRE_CODE
  pc += ((long)reg_dst < (long)reg_src) ? (ulong)(long)offset : 0UL;
BRANCH_POST_CODE
JT_CASE_END

  JT_INSTR_BEGIN(0xcf) /* FD_SBPF_OP_ARSH64_REG */
    reg[ dst ] = (ulong)( (long)reg_dst >> reg_src ); /* FIXME: WIDE SHIFTS, STRICT SIGN EXTENSION */
  JT_INSTR_END;

  /* 0xd0 - 0xdf ******************************************************/

  JT_INSTR_BEGIN(0xd4) /* FD_SBPF_OP_END_LE */
    /* fd machine is little endian */
  JT_INSTR_END;

/* 0xd5 */ JT_CASE(0xd5) // FD_SBPF_OP_JSLE_IMM
BRANCH_PRE_CODE
  pc += ((long)reg_dst <= (long)imm) ? (ulong)(long)offset : 0UL;
BRANCH_POST_CODE
JT_CASE_END

  JT_INSTR_BEGIN(0xdc) /* FD_SBPF_OP_END_BE */
    switch( imm ) {
    case 16U: reg[ dst ] = (ulong)fd_ushort_bswap( (ushort)reg_dst ); break;
    case 32U: reg[ dst ] = (ulong)fd_uint_bswap  ( (uint)  reg_dst ); break;
    case 64U: reg[ dst ] =        fd_ulong_bswap ( (ulong) reg_dst ); break;
    /* FIXME: DEFAULT CASE (VALIDATOR REJECTS BUT RUNNING ON UNVALIDATED CODE)? SIGILL? JUST DO 64? */
    }
  JT_INSTR_END;

/* 0xdd */ JT_CASE(0xdd) // FD_SBPF_OP_JSLE_REG
BRANCH_PRE_CODE
  pc += ((long)reg_dst <= (long)reg_src) ? (ulong)(long)offset : 0UL;
BRANCH_POST_CODE
JT_CASE_END

  /* FIXME: CLEAN UP BRANCH CODE */
# undef JT_CASE

# undef JT_INSTR_END
# undef JT_INSTR_BEGIN
# undef JT_INSTR_EXEC

# if defined(__clang__)
# pragma clang diagnostic pop
# endif

# if defined(__GNUC__)
# pragma GCC diagnostic pop
# endif
