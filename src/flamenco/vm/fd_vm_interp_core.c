  /* This is the VM SBPF interpreter core.  The caller unpacks the VM
     state and then just lets execution continue into this (or jumps to
     interp_exec) to start running.  The VM will run until it halts or
     faults.  On normal termination, it will branch to interp_halt to
     exit.  Each fault has its own exit label to allow the caller to
     handle individually. */

  /* FIXME: SIGILLS FOR VARIOUS THINGS THAT HAVE UNNECESSARY BITS IN IMM
     SET? (LIKE WIDE SHIFTS?) */

# if defined(__GNUC__) /* -Wpedantic rejects labels as values and rejects goto *expr */
# pragma GCC diagnostic push
# pragma GCC diagnostic ignored "-Wpedantic"
# endif

# if defined(__clang__) /* Clang is differently picky about labels as values and goto *expr */
# pragma clang diagnostic push
# pragma clang diagnostic ignored "-Wpedantic"
# pragma clang diagnostic ignored "-Wgnu-label-as-value"
# endif

  /* Include the jump table */

# include "fd_vm_interp_jump_table.c"

  /* Unpack the VM state */

  ulong pc        = vm->pc;
  ulong ic        = vm->ic;
  ulong cu        = vm->cu;
  ulong frame_cnt = vm->frame_cnt;

  /* FD_VM_INTERP_INSTR_EXEC loads the first word of the instruction at
     pc, parses it, fetches the associated register values and then
     jumps to the code that executes the instruction.  On normal
     instruction execution, the pc will be updated and
     FD_VM_INTERP_INSTR_EXEC will be invoked again to do the next
     instruction.  After a normal halt, this will branch to interp_halt.
     Otherwise, it will branch to the appropriate normal termination. */

  ulong instr;
  ulong opcode;
  ulong dst;
  ulong src;
  short offset;
  uint  imm;
  ulong reg_dst;
  ulong reg_src;

# define FD_VM_INTERP_INSTR_EXEC                                                                 \
  if( FD_UNLIKELY( pc>=text_cnt ) ) goto sigtext; /* Note: untaken branches don't consume BTB */ \
  instr   = text[ pc ];                  /* Guaranteed in-bounds */                              \
  opcode  = fd_vm_instr_opcode( instr ); /* in [0,256) even if malformed */                      \
  dst     = fd_vm_instr_dst   ( instr ); /* in [0, 16) even if malformed */                      \
  src     = fd_vm_instr_src   ( instr ); /* in [0, 16) even if malformed */                      \
  offset  = fd_vm_instr_offset( instr ); /* in [-2^15,2^15) even if malformed */                 \
  imm     = fd_vm_instr_imm   ( instr ); /* in [0,2^32) even if malformed */                     \
  reg_dst = reg[ dst ];                  /* Guaranteed in-bounds */                              \
  reg_src = reg[ src ];                  /* Guaranteed in-bounds */                              \
  goto *interp_jump_table[ opcode ]      /* Guaranteed in-bounds */

  /* FD_VM_INTERP_INSTR_BEGIN / FD_VM_INTERP_INSTR_END bracket opcode's
     implementation for an opcode that does not branch.  On entry, the
     instruction word has been unpacked into dst / src / offset / imm
     and reg[dst] / reg[src] has been prefetched into reg_dst / reg_src. */

# define FD_VM_INTERP_INSTR_BEGIN(opcode) interp_##opcode:

# if 0 /* Non-tracing path only, ~0.3% faster in some benchmarks, slower in others but more code footprint */
# define FD_VM_INTERP_INSTR_END pc++; FD_VM_INTERP_INSTR_EXEC
# else /* Use this version when tracing or optimizing code footprint */
# define FD_VM_INTERP_INSTR_END pc++; goto interp_exec
# endif

  /* Instead of doing a lot of compute budget calcs and tests every
     instruction, we note that the program counter increases
     monotonically after a branch (or a program start) until the next
     branch (or program termination).  We save the program counter of
     the start of such a segment in pc0.  Whenever we encounter a branch
     (or a program termination) at pc, we know we processed pc-pc0+1
     text words (including the text word for the branch instruction
     itself as all branch instructions are single word).

     Each instruction costs 1 cu (syscalls can cost extra on top of
     this that is accounted separately in CALL_IMM below).  Since there
     could have been multiword instructions in this segment, at start of
     such a segment, we zero out the accumulator ic_correction and have
     every multiword instruction in the segment accumulate the number of
     extra text words it has to this variable.  (Sigh ... it would be a
     lot simpler to bill based on text words processed but this would be
     very difficult to make this protocol change at this point.)

     When we encounter a branch at pc, the number of instructions
     processed (and thus the number of compute units to bill for that
     segment) is thus:

       pc - pc0 + 1 - ic_correction

     IMPORTANT SAFETY TIP!  This implies the worst case interval before
     checking the cu budget is the worst case text_cnt.  But since all
     such instructions are cheap 1 cu instructions and processed fast
     and text max is limited in size, this should be acceptable in
     practice.  FIXME: DOUBLE CHECK THE MATH ABOVE AGAINST PROTOCOL
     LIMITS. */

  ulong pc0           = pc;
  ulong ic_correction = 0UL;

# define FD_VM_INTERP_BRANCH_BEGIN(opcode)                                                              \
  interp_##opcode:                                                                                      \
    /* Bill linear text segment and this branch instruction as per the above */                         \
    ic_correction = pc - pc0 + 1UL - ic_correction;                                                     \
    ic += ic_correction;                                                                                \
    if( FD_UNLIKELY( ic_correction>=cu ) ) goto sigcost; /* Note: untaken branches don't consume BTB */ \
    cu -= ic_correction;                                                                                \
    /* At this point, cu is positive */                                                                 \
    ic_correction = 0UL;

  /* FIXME: debatable if it is better to do pc++ here or have the
     instruction implementations do it in their code path. */

# if 0 /* Non-tracing path only, ~4% faster in some benchmarks, slower in others but more code footprint */
# define FD_VM_INTERP_BRANCH_END               \
    pc++;                                      \
    pc0 = pc; /* Start a new linear segment */ \
    FD_VM_INTERP_INSTR_EXEC
# else /* Use this version when tracing or optimizing code footprint */
# define FD_VM_INTERP_BRANCH_END               \
    pc++;                                      \
    pc0 = pc; /* Start a new linear segment */ \
    /* FIXME: TEST sigsplit HERE */            \
    goto interp_exec
# endif

  /* FD_VM_INTERP_STACK_PUSH pushes reg[6:9] onto the shadow stack and
     advances reg[10] to a new user stack frame.  If there are no more
     stack frames available, will do a SIGSTACK. */

  /* FIXME: double check faulting is desired on stack overflow. */

  /* FIXME: a pre-belt-sanding FIXME implied the TLB should be updated
     to prevent byte code from accessing the stack outside its current
     stack frame.  But this would break the common practice of a
     function passing a pointer to something on its stack into a
     function that it calls:

       void foo( ... ) {
         ...
         int ret;
         bar( &ret );
         ...
       }

     So this probably shouldn't be done.  But, if it is in fact
     necessary, the TLB updates would be here and in pop. */

  /* FIXME: unvalidated code mucking with r10 */

# define FD_VM_INTERP_STACK_PUSH                                                                          \
  if( FD_UNLIKELY( frame_cnt>=frame_max ) ) goto sigstack; /* Note: untaken branches don't consume BTB */ \
  shadow[ frame_cnt ].r6 = reg[6];                                                                        \
  shadow[ frame_cnt ].r7 = reg[7];                                                                        \
  shadow[ frame_cnt ].r8 = reg[8];                                                                        \
  shadow[ frame_cnt ].r9 = reg[9];                                                                        \
  shadow[ frame_cnt ].pc = pc;                                                                            \
  frame_cnt++;                                                                                            \
  reg[10] += FD_VM_STACK_FRAME_SZ + FD_VM_STACK_GUARD_SZ

  /* Before starting execution, allocate the requested heap size.  If
     this requires more compute units than can be supported, we don't
     even execute the first instruction. */

//let heap_size = compute_budget.heap_size.unwrap_or(HEAP_LENGTH);
//let _ = invoke_context.consume_checked(
//    ((heap_size as u64).saturating_div(32_u64.saturating_mul(1024)))
//        .saturating_sub(1)
//        .saturating_mul(compute_budget.heap_cost),
//);

  ulong heap_cu_cost = fd_ulong_sat_mul( fd_ulong_sat_sub( heap_max / (32UL*1024UL), 1UL ), FD_VM_HEAP_COST );
  if( FD_UNLIKELY( heap_cu_cost>=cu ) ) goto sigcost; /* Note: untaken branches don't consume BTB */ /* FIXME: SIGHEAP? */
  cu -= heap_cu_cost;

  /* At this point, cu is positive */

  goto interp_exec; /* Silly but to avoid unused label warning in some configurations */
interp_exec:

  /* Note: when tracing or optimizing for code footprint, all
     instruction execution starts here such that this is only point
     where exe tracing diagnostics are needed. */

  /* FIXME: exe tracing diagnostics go here */

  FD_VM_INTERP_INSTR_EXEC;

  /* 0x00 - 0x0f ******************************************************/

/* FIXME: MORE THINKING AROUND LDQ HANDLING HERE (see below) */
interp_0x00: // FD_SBPF_OP_ADDL_IMM

  FD_VM_INTERP_INSTR_BEGIN(0x04) /* FD_SBPF_OP_ADD_IMM */
    reg[ dst ] = (ulong)( (uint)reg_dst + imm );
  FD_VM_INTERP_INSTR_END;

  FD_VM_INTERP_BRANCH_BEGIN(0x05) /* FD_SBPF_OP_JA */
    pc += (ulong)(long)offset;
  FD_VM_INTERP_BRANCH_END;

  FD_VM_INTERP_INSTR_BEGIN(0x07) /* FD_SBPF_OP_ADD64_IMM */
    reg[ dst ] = reg_dst + (ulong)(long)(int)imm;
  FD_VM_INTERP_INSTR_END;

  FD_VM_INTERP_INSTR_BEGIN(0x0c) /* FD_SBPF_OP_ADD_REG */
    reg[ dst ] = (ulong)(uint)( reg_dst + reg_src );
  FD_VM_INTERP_INSTR_END;

  FD_VM_INTERP_INSTR_BEGIN(0x0f) /* FD_SBPF_OP_ADD64_REG */
    reg[ dst ] = reg_dst + reg_src;
  FD_VM_INTERP_INSTR_END;

  /* 0x10 - 0x1f ******************************************************/

  FD_VM_INTERP_INSTR_BEGIN(0x14) /* FD_SBPF_OP_SUB_IMM */
    reg[ dst ] = (ulong)( (uint)reg_dst - imm );
  FD_VM_INTERP_INSTR_END;

  FD_VM_INTERP_BRANCH_BEGIN(0x15) /* FD_SBPF_OP_JEQ_IMM */ /* FIXME: CHECK IMM SIGN EXTENSION */
    pc += fd_ulong_if( reg_dst==(ulong)(long)(int)imm, (ulong)(long)offset, 0UL );
  FD_VM_INTERP_BRANCH_END;

  FD_VM_INTERP_INSTR_BEGIN(0x17) /* FD_SBPF_OP_SUB64_IMM */
    reg[ dst ] = reg_dst - (ulong)(long)(int)imm;
  FD_VM_INTERP_INSTR_END;

  FD_VM_INTERP_INSTR_BEGIN(0x18) /* FD_SBPF_OP_LDQ */ /* FIXME: MORE THINKING AROUND LDQ HANDLING HERE */
    pc++;
    ic_correction++;
    if( FD_UNLIKELY( pc>=text_cnt ) ) goto sigsplit; /* Note: untaken branches don't consume BTB */
    reg[ dst ] = (ulong)((ulong)imm | ((ulong)fd_vm_instr_imm( text[ pc ] ) << 32));
  FD_VM_INTERP_INSTR_END;

  FD_VM_INTERP_INSTR_BEGIN(0x1c) /* FD_SBPF_OP_SUB_REG */
    reg[ dst ] = (ulong)( (uint)reg_dst - (uint)reg_src );
  FD_VM_INTERP_INSTR_END;

  FD_VM_INTERP_BRANCH_BEGIN(0x1d) /* FD_SBPF_OP_JEQ_REG */
    pc += fd_ulong_if( reg_dst==reg_src, (ulong)(long)offset, 0UL );
  FD_VM_INTERP_BRANCH_END;

  FD_VM_INTERP_INSTR_BEGIN(0x1f) /* FD_SBPF_OP_SUB64_REG */
    reg[ dst ] = reg_dst - reg_src;
  FD_VM_INTERP_INSTR_END;

  /* 0x20 - 0x2f ******************************************************/

  FD_VM_INTERP_INSTR_BEGIN(0x24) /* FD_SBPF_OP_MUL_IMM */
    reg[ dst ] = (ulong)( (uint)reg_dst * imm );
  FD_VM_INTERP_INSTR_END;

  FD_VM_INTERP_BRANCH_BEGIN(0x25) /* FD_SBPF_OP_JGT_IMM */ /* FIXME: CHECK IMM SIGN EXTENSION */
    pc += fd_ulong_if( reg_dst>(ulong)(long)(int)imm, (ulong)(long)offset, 0UL );
  FD_VM_INTERP_BRANCH_END;

  FD_VM_INTERP_INSTR_BEGIN(0x27) /* FD_SBPF_OP_MUL64_IMM */
    reg[ dst ] = (ulong)( (long)reg_dst * (long)(int)imm );
  FD_VM_INTERP_INSTR_END;

  FD_VM_INTERP_INSTR_BEGIN(0x2c) /* FD_SBPF_OP_MUL_REG */
    reg[ dst ] = (ulong)( (uint)reg_dst * (uint)reg_src );
  FD_VM_INTERP_INSTR_END;

  FD_VM_INTERP_BRANCH_BEGIN(0x2d) /* FD_SBPF_OP_JGT_REG */
    pc += fd_ulong_if( reg_dst>reg_src, (ulong)(long)offset, 0UL );
  FD_VM_INTERP_BRANCH_END;

  FD_VM_INTERP_INSTR_BEGIN(0x2f) /* FD_SBPF_OP_MUL64_REG */
    reg[ dst ] = reg_dst * reg_src;
  FD_VM_INTERP_INSTR_END;

  /* 0x30 - 0x3f ******************************************************/

  FD_VM_INTERP_INSTR_BEGIN(0x34) /* FD_SBPF_OP_DIV_IMM */
    /* FIXME: is div-by-zero a fault? reject imm==0 at validation time?
       convert to a multiply at validation time (usually probably not
       worth it) */
    reg[ dst ] = (ulong)( FD_UNLIKELY( !imm ) ? 0U : ((uint)reg_dst / imm) );
  FD_VM_INTERP_INSTR_END;

  FD_VM_INTERP_BRANCH_BEGIN(0x35) /* FD_SBPF_OP_JGE_IMM */ /* FIXME: CHECK IMM SIGN EXTENSION */
    pc += fd_ulong_if( reg_dst>=(ulong)imm, (ulong)(long)offset, 0UL );
  FD_VM_INTERP_BRANCH_END;

  FD_VM_INTERP_INSTR_BEGIN(0x37) /* FD_SBPF_OP_DIV64_IMM */ /* FIXME: see notes for OP_DIV_IMM */
    reg[ dst ] = FD_UNLIKELY( !imm ) ? 0UL : ( reg_dst / (ulong)imm );
  FD_VM_INTERP_INSTR_END;

  FD_VM_INTERP_INSTR_BEGIN(0x3c) /* FD_SBPF_OP_DIV_REG */ /* FIXME: IS DIV-BY-ZERO A FAULT? */
    reg[ dst ] = (ulong)( FD_UNLIKELY( !(uint)reg_src ) ? 0U : ((uint)reg_dst / (uint)reg_src) );
  FD_VM_INTERP_INSTR_END;

  FD_VM_INTERP_BRANCH_BEGIN(0x3d) /* FD_SBPF_OP_JGE_REG */
    pc += fd_ulong_if( reg_dst>=reg_src, (ulong)(long)offset, 0UL );
  FD_VM_INTERP_BRANCH_END;

  FD_VM_INTERP_INSTR_BEGIN(0x3f) /* FD_SBPF_OP_DIV64_REG */ /* FIXME: IS DIV-BY-ZERO A FAULT? */
    reg[ dst ] = FD_UNLIKELY( !reg_src ) ? 0UL : (reg_dst / reg_src);
  FD_VM_INTERP_INSTR_END;

  /* 0x40 - 0x4f ******************************************************/

  FD_VM_INTERP_INSTR_BEGIN(0x44) /* FD_SBPF_OP_OR_IMM */
    reg[ dst ] = (ulong)( (uint)reg_dst | imm );
  FD_VM_INTERP_INSTR_END;

  FD_VM_INTERP_BRANCH_BEGIN(0x45) /* FD_SBPF_OP_JSET_IMM */
    pc += fd_ulong_if( !!(reg_dst & (ulong)imm), (ulong)(long)offset, 0UL );
  FD_VM_INTERP_BRANCH_END;

  FD_VM_INTERP_INSTR_BEGIN(0x47) /* FD_SBPF_OP_OR64_IMM */
    reg[ dst ] = reg_dst | (ulong)(long)(int)imm;
  FD_VM_INTERP_INSTR_END;

  FD_VM_INTERP_INSTR_BEGIN(0x4c) /* FD_SBPF_OP_OR_REG */
    reg[ dst ] = (ulong)(uint)( reg_dst | reg_src );
  FD_VM_INTERP_INSTR_END;

  FD_VM_INTERP_BRANCH_BEGIN(0x4d) /* FD_SBPF_OP_JSET_REG */
    pc += fd_ulong_if( !!(reg_dst & reg_src), (ulong)(long)offset, 0UL );
  FD_VM_INTERP_BRANCH_END;

  FD_VM_INTERP_INSTR_BEGIN(0x4f) /* FD_SBPF_OP_OR64_REG */
    reg[ dst ] = reg_dst | reg_src;
  FD_VM_INTERP_INSTR_END;

  /* 0x50 - 0x5f ******************************************************/

  FD_VM_INTERP_INSTR_BEGIN(0x54) /* FD_SBPF_OP_AND_IMM */
    reg[ dst ] = (ulong)( (uint)reg_dst & imm );
  FD_VM_INTERP_INSTR_END;

  FD_VM_INTERP_BRANCH_BEGIN(0x55) /* FD_SBPF_OP_JNE_IMM */ /* FIXME: CHECK IMM SIGN EXTENSION */
    pc += fd_ulong_if( reg_dst!=(ulong)(long)(int)imm, (ulong)(long)offset, 0UL );
  FD_VM_INTERP_BRANCH_END;

  FD_VM_INTERP_INSTR_BEGIN(0x57) /* FD_SBPF_OP_AND64_IMM */
    reg[ dst ] = reg_dst & (ulong)(long)(int)imm;
  FD_VM_INTERP_INSTR_END;

  FD_VM_INTERP_INSTR_BEGIN(0x5c) /* FD_SBPF_OP_AND_REG */
    reg[ dst ] = (ulong)(uint)( reg_dst & reg_src );
  FD_VM_INTERP_INSTR_END;

  FD_VM_INTERP_BRANCH_BEGIN(0x5d) /* FD_SBPF_OP_JNE_REG */
    pc += fd_ulong_if( reg_dst!=reg_src, (ulong)(long)offset, 0UL );
  FD_VM_INTERP_BRANCH_END;

  FD_VM_INTERP_INSTR_BEGIN(0x5f) /* FD_SBPF_OP_AND64_REG */
    reg[ dst ] = reg_dst & reg_src;
  FD_VM_INTERP_INSTR_END;

  /* 0x60 - 0x6f ******************************************************/

  /* FIXME: CHECK THE CU COST MODEL FOR THESE (IS IT LIKE
     FD_VM_CONSUME_MEM AND NOT JUST FIXED) */
  /* FIXME: MEM TRACING DIAGNOSTICS GO IN HERE */

  FD_VM_INTERP_INSTR_BEGIN(0x61) { /* FD_SBPF_OP_LDXW */
    ulong vaddr   = reg_src + (ulong)(long)offset;
    ulong haddr   = fd_vm_mem_haddr( vaddr, sizeof(uint), region_haddr, region_ld_sz, 0UL );
    int   sigsegv = !haddr;
    int   sigbus  = check_align & !fd_ulong_is_aligned( vaddr, sizeof(uint) );
    if( FD_UNLIKELY( sigsegv | sigbus ) ) goto sigsegv; /* Note: untaken branches don't consume BTB */ /* FIXME: sigbus */
    reg[ dst ] = fd_vm_mem_ld_4( haddr );
  }
  FD_VM_INTERP_INSTR_END;

  FD_VM_INTERP_INSTR_BEGIN(0x62) { /* FD_SBPF_OP_STW */
    ulong vaddr   = reg_dst + (ulong)(long)offset;
    ulong haddr   = fd_vm_mem_haddr( vaddr, sizeof(uint), region_haddr, region_st_sz, 0UL );
    int   sigsegv = !haddr;
    int   sigbus  = check_align & !fd_ulong_is_aligned( vaddr, sizeof(uint) );
    if( FD_UNLIKELY( sigsegv | sigbus ) ) goto sigsegv; /* Note: untaken branches don't consume BTB */ /* FIXME: sigbus */
    fd_vm_mem_st_4( haddr, imm );
  }
  FD_VM_INTERP_INSTR_END;

  FD_VM_INTERP_INSTR_BEGIN(0x63) { /* FD_SBPF_OP_STXW */
    ulong vaddr   = reg_dst + (ulong)(long)offset;
    ulong haddr   = fd_vm_mem_haddr( vaddr, sizeof(uint), region_haddr, region_st_sz, 0UL );
    int   sigsegv = !haddr;
    int   sigbus  = check_align & !fd_ulong_is_aligned( vaddr, sizeof(uint) );
    if( FD_UNLIKELY( sigsegv | sigbus ) ) goto sigsegv; /* Note: untaken branches don't consume BTB */ /* FIXME: sigbus/rdonly */
    fd_vm_mem_st_4( haddr, (uint)reg_src );
  }
  FD_VM_INTERP_INSTR_END;

  FD_VM_INTERP_INSTR_BEGIN(0x64) /* FD_SBPF_OP_LSH_IMM */
    reg[ dst ] = (ulong)( (uint)reg_dst << imm ); /* FIXME: WIDE SHIFT */
  FD_VM_INTERP_INSTR_END;

  FD_VM_INTERP_BRANCH_BEGIN(0x65) /* FD_SBPF_OP_JSGT_IMM */ /* FIXME: CHECK IMM SIGN EXTENSION */
    pc += fd_ulong_if( (long)reg_dst>(long)(int)imm, (ulong)(long)offset, 0UL );
  FD_VM_INTERP_BRANCH_END;

  FD_VM_INTERP_INSTR_BEGIN(0x67) /* FD_SBPF_OP_LSH64_IMM */
    reg[ dst ] = reg_dst << imm; /* FIXME: WIDE SHIFT */
  FD_VM_INTERP_INSTR_END;

  FD_VM_INTERP_INSTR_BEGIN(0x69) { /* FD_SBPF_OP_LDXH */
    ulong vaddr   = reg_src + (ulong)(long)offset;
    ulong haddr   = fd_vm_mem_haddr( vaddr, sizeof(ushort), region_haddr, region_ld_sz, 0UL );
    int   sigsegv = !haddr;
    int   sigbus  = check_align & !fd_ulong_is_aligned( vaddr, sizeof(ushort) );
    if( FD_UNLIKELY( sigsegv | sigbus ) ) goto sigsegv; /* Note: untaken branches don't consume BTB */ /* FIXME: sigbus */
    reg[ dst ] = fd_vm_mem_ld_2( haddr );
  }
  FD_VM_INTERP_INSTR_END;

  FD_VM_INTERP_INSTR_BEGIN(0x6a) { /* FD_SBPF_OP_STH */
    ulong vaddr   = reg_dst + (ulong)(long)offset;
    ulong haddr   = fd_vm_mem_haddr( vaddr, sizeof(ushort), region_haddr, region_st_sz, 0UL );
    int   sigsegv = !haddr;
    int   sigbus  = check_align & !fd_ulong_is_aligned( vaddr, sizeof(ushort) );
    if( FD_UNLIKELY( sigsegv | sigbus ) ) goto sigsegv; /* Note: untaken branches don't consume BTB */ /* FIXME: sigbus */
    fd_vm_mem_st_2( haddr, (ushort)imm );
  }
  FD_VM_INTERP_INSTR_END;

  FD_VM_INTERP_INSTR_BEGIN(0x6b) { /* FD_SBPF_OP_STXH */
    ulong vaddr   = reg_dst + (ulong)(long)offset;
    ulong haddr   = fd_vm_mem_haddr( vaddr, sizeof(ushort), region_haddr, region_st_sz, 0UL );
    int   sigsegv = !haddr;
    int   sigbus  = check_align & !fd_ulong_is_aligned( vaddr, sizeof(ushort) );
    if( FD_UNLIKELY( sigsegv | sigbus ) ) goto sigsegv; /* Note: untaken branches don't consume BTB */ /* FIXME: sigbus/rdonly */
    fd_vm_mem_st_2( haddr, (ushort)reg_src );
  }
  FD_VM_INTERP_INSTR_END;

  FD_VM_INTERP_INSTR_BEGIN(0x6c) /* FD_SBPF_OP_LSH_REG */
    reg[ dst ] = (ulong)( (uint)reg_dst << (uint)reg_src ); /* FIXME: WIDE SHIFT */
  FD_VM_INTERP_INSTR_END;

  FD_VM_INTERP_BRANCH_BEGIN(0x6d) /* FD_SBPF_OP_JSGT_REG */
    pc += fd_ulong_if( (long)reg_dst>(long)reg_src, (ulong)(long)offset, 0UL );
  FD_VM_INTERP_BRANCH_END;

  FD_VM_INTERP_INSTR_BEGIN(0x6f) /* FD_SBPF_OP_LSH64_REG */
    reg[ dst ] = reg_dst << reg_src; /* FIXME: WIDE SHIFT */
  FD_VM_INTERP_INSTR_END;

  /* 0x70 - 0x7f ******************************************************/

  FD_VM_INTERP_INSTR_BEGIN(0x71) { /* FD_SBPF_OP_LDXB */
    ulong vaddr = reg_src + (ulong)(long)offset;
    ulong haddr = fd_vm_mem_haddr( vaddr, sizeof(uchar), region_haddr, region_ld_sz, 0UL );
    if( FD_UNLIKELY( !haddr ) ) goto sigsegv; /* Note: untaken branches don't consume BTB */
    reg[ dst ] = fd_vm_mem_ld_1( haddr );
  }
  FD_VM_INTERP_INSTR_END;

  FD_VM_INTERP_INSTR_BEGIN(0x72) { /* FD_SBPF_OP_STB */
    ulong vaddr = reg_dst + (ulong)(long)offset;
    ulong haddr = fd_vm_mem_haddr( vaddr, sizeof(uchar), region_haddr, region_st_sz, 0UL );
    if( FD_UNLIKELY( !haddr ) ) goto sigsegv; /* Note: untaken branches don't consume BTB */
    fd_vm_mem_st_1( haddr, (uchar)imm );
  }
  FD_VM_INTERP_INSTR_END;

  FD_VM_INTERP_INSTR_BEGIN(0x73) { /* FD_SBPF_OP_STXB */
    ulong vaddr = reg_dst + (ulong)(long)offset;
    ulong haddr = fd_vm_mem_haddr( vaddr, sizeof(uchar), region_haddr, region_st_sz, 0UL );
    if( FD_UNLIKELY( !haddr ) ) goto sigsegv; /* Note: untaken branches don't consume BTB */ /* FIXME: sigrdonly */
    fd_vm_mem_st_1( haddr, (uchar)reg_src );
  }
  FD_VM_INTERP_INSTR_END;

  FD_VM_INTERP_INSTR_BEGIN(0x74) /* FD_SBPF_OP_RSH_IMM */
    reg[ dst ] = (ulong)( (uint)reg_dst >> imm ); /* FIXME: WIDE SHIFTS */
  FD_VM_INTERP_INSTR_END;

  FD_VM_INTERP_BRANCH_BEGIN(0x75) /* FD_SBPF_OP_JSGE_IMM */ /* FXIME: CHECK IMM SIGN EXTENSION */
    pc += fd_ulong_if( (long)reg_dst>=(long)(int)imm, (ulong)(long)offset, 0UL );
  FD_VM_INTERP_BRANCH_END;

  FD_VM_INTERP_INSTR_BEGIN(0x77) /* FD_SBPF_OP_RSH64_IMM */
    reg[ dst ] = reg_dst >> imm; /* FIXME: WIDE SHIFTS */
  FD_VM_INTERP_INSTR_END;

  FD_VM_INTERP_INSTR_BEGIN(0x79) { /* FD_SBPF_OP_LDXQ */
    ulong vaddr   = reg_src + (ulong)(long)offset;
    ulong haddr   = fd_vm_mem_haddr( vaddr, sizeof(ulong), region_haddr, region_ld_sz, 0UL );
    int   sigsegv = !haddr;
    int   sigbus  = check_align & !fd_ulong_is_aligned( vaddr, sizeof(ulong) );
    if( FD_UNLIKELY( sigsegv | sigbus ) ) goto sigsegv; /* Note: untaken branches don't consume BTB */ /* FIXME: sigbus */
    reg[ dst ] = fd_vm_mem_ld_8( haddr );
  }
  FD_VM_INTERP_INSTR_END;

  FD_VM_INTERP_INSTR_BEGIN(0x7a) { /* FD_SBPF_OP_STQ */
    ulong vaddr   = reg_dst + (ulong)(long)offset;
    ulong haddr   = fd_vm_mem_haddr( vaddr, sizeof(ulong), region_haddr, region_st_sz, 0UL );
    int   sigsegv = !haddr;
    int   sigbus  = check_align & !fd_ulong_is_aligned( vaddr, sizeof(ulong) );
    if( FD_UNLIKELY( sigsegv | sigbus ) ) goto sigsegv; /* Note: untaken branches don't consume BTB */ /* FIXME: sigbus */
    fd_vm_mem_st_8( haddr, (ulong)imm );
  }
  FD_VM_INTERP_INSTR_END;

  FD_VM_INTERP_INSTR_BEGIN(0x7b) { /* FD_SBPF_OP_STXQ */
    ulong vaddr   = reg_dst + (ulong)(long)offset;
    ulong haddr   = fd_vm_mem_haddr( vaddr, sizeof(ulong), region_haddr, region_st_sz, 0UL );
    int   sigsegv = !haddr;
    int   sigbus  = check_align & !fd_ulong_is_aligned( vaddr, sizeof(ulong) );
    if( FD_UNLIKELY( sigsegv | sigbus ) ) goto sigsegv; /* Note: untaken branches don't consume BTB */ /* FIXME: sigbus/rdonly */
    fd_vm_mem_st_8( haddr, reg_src );
  }
  FD_VM_INTERP_INSTR_END;

  FD_VM_INTERP_INSTR_BEGIN(0x7c) /* FD_SBPF_OP_RSH_REG */
    reg[ dst ] = (ulong)( (uint)reg_dst >> (uint)reg_src ); /* FIXME: WIDE SHIFTS */
  FD_VM_INTERP_INSTR_END;

  FD_VM_INTERP_BRANCH_BEGIN(0x7d) /* FD_SBPF_OP_JSGE_REG */
    pc += fd_ulong_if( (long)reg_dst>=(long)reg_src, (ulong)(long)offset, 0UL );
  FD_VM_INTERP_BRANCH_END;

  FD_VM_INTERP_INSTR_BEGIN(0x7f) /* FD_SBPF_OP_RSH64_REG */
    reg[ dst ] = reg_dst >> reg_src; /* FIXME: WIDE SHIFTS */
  FD_VM_INTERP_INSTR_END;

  /* 0x80-0x8f ********************************************************/

  FD_VM_INTERP_INSTR_BEGIN(0x84) /* FD_SBPF_OP_NEG */
    reg[ dst ] = (ulong)( -(uint)reg_dst );
  FD_VM_INTERP_INSTR_END;

  FD_VM_INTERP_BRANCH_BEGIN(0x85) /* FD_SBPF_OP_CALL_IMM */

    /* Note we do the stack push before updating the pc.  This implies
       that the call stack frame gets allocated _before_ checking if the
       call target is valid.  It would be fine to switch the order
       though such would change the precise faulting semantics of
       sigcall and sigstack. */

    fd_sbpf_syscalls_t const * syscall = fd_sbpf_syscalls_query_const( syscalls, imm, NULL );
    if( FD_UNLIKELY( !syscall ) ) { /* Optimize for the syscall case */

      /* Note the original implementation had the imm magic number
          check after the calldest check.  But fd_pchash_inverse of the
          magic number is 0xb00c380U.  This is beyond possible text_cnt
          values.  So we do it first to simplify the code and clean up
          fault handling. */

      FD_VM_INTERP_STACK_PUSH;

      if( FD_UNLIKELY( imm==0x71e3cf81U ) ) pc = entry_pc; /* FIXME: MAGIC NUMBER */
      else {
        pc = (ulong)fd_pchash_inverse( imm );
        if( FD_UNLIKELY( pc>=text_cnt ) || FD_UNLIKELY( !fd_sbpf_calldests_test( calldests, pc ) ) ) goto sigcall;
      }
      pc--;

    } else {

      /* Update the vm with the current vm execution state for the
          syscall.  Note that BRANCH_BEGIN has pc at the syscall and
          already updated ic and cu to reflect all instructions up to
          and including the syscall instruction itself. */

      vm->pc        = pc;
      vm->ic        = ic;
      vm->cu        = cu;
      vm->frame_cnt = frame_cnt;

      /* Do the syscall.  We use ret reduce the risk of the syscall
          accidentally modifying other registers (note however since a
          syscall has the vm handle it still do arbitrary modifications
          to the vm state) and the risk of a pointer escape on reg from
          inhibiting compiler optimizations (this risk is likely low in
          as this is the only point in the whole interpreter core that
          calls outside this translation unit). */

      /* At this point, vm->cu is positive */

      ulong ret[1];
      err = syscall->func( vm, reg[1], reg[2], reg[3], reg[4], reg[5], ret );
      reg[0] = ret[0];

      /* If we trust syscall implementations to handle the vm state
          correctly, the below could be implemented as unpacking the vm
          state and jumping to sigsys on error.  But we provide some
          extra protection to make various strong guarantees:

          - We do not let the syscall modify pc currently as nothing
            requires this and it reduces risk of a syscall bug mucking
            up the interpreter.  If there ever was a syscall that
            needed to modify the pc (e.g. a syscall that has execution
            resume from a different location than the instruction
            following the syscall), do "pc = vm->pc" below.

          - We do not let the syscall modify ic currently as nothing
            requires this and it keeps the ic precise.  If a future
            syscall needs this, do "ic = vm->ic" below.

          - We do not let the syscall increase cu as nothing requires
            this and it guarantees the interpreter will halt in a
            reasonable finite amount of time.  If a future syscall
            needs this, do "cu = vm->cu" below.

          - A syscall that returns SIGCOST is always treated as though
            it also zerod cu. */

      /* At this point, vm->cu is whatever the syscall tried to set
          and cu is positive */

      ulong cu_req = vm->cu;
      cu = fd_ulong_min( cu_req, cu );
      if( FD_UNLIKELY( err ) ) {
        if( err==FD_VM_ERR_SIGCOST ) cu = 0UL; /* cmov */
        goto sigsyscall;
      }

      /* At this point, cu is positive and err is clear */
    }

  FD_VM_INTERP_BRANCH_END;

  FD_VM_INTERP_INSTR_BEGIN(0x87) /* FD_SBPF_OP_NEG64 */
    reg[ dst ] = -reg_dst;
  FD_VM_INTERP_INSTR_END;

  FD_VM_INTERP_BRANCH_BEGIN(0x8d) { /* FD_SBPF_OP_CALL_REG */

    FD_VM_INTERP_STACK_PUSH;

    /* FIXME: REALLY??  SBPF USES IMM TO INDEX THE REG FILE??  DOUBLE
       CHECK THIS.  AT LEAST MASKING THE LSB IN THE MEANTIME TO
       GUARANTEE TO OVERFLOW.*/
    ulong vaddr = reg[ imm & 15U ];

    ulong region = vaddr >> 32;
    ulong align  = vaddr & 7UL;
    pc = ((vaddr & 0xffffffffUL)/8UL) - text_word_off;

    /* Note: BRANCH_END will implicitly handle a pc that fell outside
       the text section (below via unsigned wraparoud or above) as
       sigtext */

    /* FIXME: when static_syscalls are enabled, check that the call destination is valid */
    /* FIXME: sigbus for misaligned? */

    if( FD_UNLIKELY( (region!=1UL) | (!!align) ) ) goto sigcall; /* Note: untaken branches don't consume BTB */

    pc--;

  } FD_VM_INTERP_BRANCH_END;

  /* 0x90 - 0x9f ******************************************************/

  FD_VM_INTERP_INSTR_BEGIN(0x94) /* FD_SBPF_OP_MOD_IMM */ /* FIXME: IS MOD ZERO A FAULT?  DETECT IN VALIDATION? */
    reg[ dst ] = (ulong)( FD_UNLIKELY( !imm ) ? (uint)reg_dst : ((uint)reg_dst % imm) );
  FD_VM_INTERP_INSTR_END;

  FD_VM_INTERP_BRANCH_BEGIN(0x95) /* FD_SBPF_OP_EXIT */
    if( FD_UNLIKELY( !frame_cnt ) ) goto interp_halt; /* Exit program */
    frame_cnt--;
    reg[6]   = shadow[ frame_cnt ].r6;
    reg[7]   = shadow[ frame_cnt ].r7;
    reg[8]   = shadow[ frame_cnt ].r8;
    reg[9]   = shadow[ frame_cnt ].r9;
    pc       = shadow[ frame_cnt ].pc;
    reg[10] -= FD_VM_STACK_FRAME_SZ + FD_VM_STACK_GUARD_SZ;
  FD_VM_INTERP_BRANCH_END;

  FD_VM_INTERP_INSTR_BEGIN(0x97) /* FD_SBPF_OP_MOD64_IMM */ /* FIXME: IS MOD ZERO A FAULT?  DETECT IN VALIDATION? */
    reg[ dst ] = FD_UNLIKELY( !imm ) ? reg_dst : (reg_dst % (ulong)imm);
  FD_VM_INTERP_INSTR_END;

  FD_VM_INTERP_INSTR_BEGIN(0x9c) /* FD_SBPF_OP_MOD_REG */ /* FIXME: IS MOD ZERO A FAULT? */
    reg[ dst ] = (ulong)( FD_UNLIKELY( !(uint)reg_src ) ? (uint)reg_dst : ((uint)reg_dst % (uint)reg_src) );
  FD_VM_INTERP_INSTR_END;

  FD_VM_INTERP_INSTR_BEGIN(0x9f) /* FD_SBPF_OP_MOD64_REG */ /* FIXME: IS MOD ZERO A FAULT? */
    reg[ dst ] = FD_UNLIKELY( !reg_src ) ? reg_dst : (reg_dst % reg_src);
  FD_VM_INTERP_INSTR_END;

  /* 0xa0 - 0xaf ******************************************************/

  FD_VM_INTERP_INSTR_BEGIN(0xa4) /* FD_SBPF_OP_XOR_IMM */
    reg[ dst ] = (ulong)( (uint)reg_dst ^ imm );
  FD_VM_INTERP_INSTR_END;

  FD_VM_INTERP_BRANCH_BEGIN(0xa5) /* FD_SBPF_OP_JLT_IMM */ /* FIXME: CHECK IMM SIGN EXTENSION */
    pc += fd_ulong_if( reg_dst<(ulong)imm, (ulong)(long)offset, 0UL );
  FD_VM_INTERP_BRANCH_END;

  FD_VM_INTERP_INSTR_BEGIN(0xa7) /* FD_SBPF_OP_XOR64_IMM */
    reg[ dst ] = reg_dst ^ (ulong)(long)(int)imm;
  FD_VM_INTERP_INSTR_END;

  FD_VM_INTERP_INSTR_BEGIN(0xac) /* FD_SBPF_OP_XOR_REG */
    reg[ dst ] = (ulong)(uint)( reg_dst ^ reg_src );
  FD_VM_INTERP_INSTR_END;

  FD_VM_INTERP_BRANCH_BEGIN(0xad) /* FD_SBPF_OP_JLT_REG */
    pc += fd_ulong_if( reg_dst<reg_src, (ulong)(long)offset, 0UL );
  FD_VM_INTERP_BRANCH_END;

  FD_VM_INTERP_INSTR_BEGIN(0xaf) /* FD_SBPF_OP_XOR64_REG */
    reg[ dst ] = reg_dst ^ reg_src;
  FD_VM_INTERP_INSTR_END;

  /* 0xb0 - 0xbf ******************************************************/

  FD_VM_INTERP_INSTR_BEGIN(0xb4) /* FD_SBPF_OP_MOV_IMM */
    reg[ dst ] = (ulong)imm;
  FD_VM_INTERP_INSTR_END;

  FD_VM_INTERP_BRANCH_BEGIN(0xb5) /* FD_SBPF_OP_JLE_IMM */ /* FIXME: CHECK IMM SIGN EXTENSION */
    pc += fd_ulong_if( reg_dst<=(ulong)imm, (ulong)(long)offset, 0UL );
  FD_VM_INTERP_BRANCH_END;

  FD_VM_INTERP_INSTR_BEGIN(0xb7) /* FD_SBPF_OP_MOV64_IMM */
    reg[ dst ] = (ulong)(long)(int)imm;
  FD_VM_INTERP_INSTR_END;

  FD_VM_INTERP_INSTR_BEGIN(0xbc) /* FD_SBPF_OP_MOV_REG */
    reg[ dst ] = (ulong)(uint)reg_src;
  FD_VM_INTERP_INSTR_END;

  FD_VM_INTERP_BRANCH_BEGIN(0xbd) /* FD_SBPF_OP_JLE_REG */
    pc += fd_ulong_if( reg_dst<=reg_src, (ulong)(long)offset, 0UL );
  FD_VM_INTERP_BRANCH_END;

  FD_VM_INTERP_INSTR_BEGIN(0xbf) /* FD_SBPF_OP_MOV64_REG */
    reg[ dst ] = reg_src;
  FD_VM_INTERP_INSTR_END;

  /* 0xc0 - 0xcf ******************************************************/

  FD_VM_INTERP_INSTR_BEGIN(0xc4) /* FD_SBPF_OP_ARSH_IMM */
    reg[ dst ] = (ulong)(uint)( (int)reg_dst >> imm ); /* FIXME: WIDE SHIFTS, STRICT SIGN EXTENSION */
  FD_VM_INTERP_INSTR_END;

  FD_VM_INTERP_BRANCH_BEGIN(0xc5) /* FD_SBPF_OP_JSLT_IMM */ /* FIXME: CHECK IMM SIGN EXTENSION */
    pc += fd_ulong_if( (long)reg_dst<(long)(int)imm, (ulong)(long)offset, 0UL );
  FD_VM_INTERP_BRANCH_END;

  FD_VM_INTERP_INSTR_BEGIN(0xc7) /* FD_SBPF_OP_ARSH64_IMM */
    reg[ dst ] = (ulong)( (long)reg_dst >> imm ); /* FIXME: WIDE SHIFTS, STRICT SIGN EXTENSION */
  FD_VM_INTERP_INSTR_END;

  FD_VM_INTERP_INSTR_BEGIN(0xcc) /* FD_SBPF_OP_ARSH_REG */
    reg[ dst ] = (ulong)(uint)( (int)reg_dst >> (uint)reg_src ); /* FIXME: WIDE SHIFTS, STRICT SIGN EXTENSION */
  FD_VM_INTERP_INSTR_END;

  FD_VM_INTERP_BRANCH_BEGIN(0xcd) /* FD_SBPF_OP_JSLT_REG */
    pc += fd_ulong_if( (long)reg_dst<(long)reg_src, (ulong)(long)offset, 0UL );
  FD_VM_INTERP_BRANCH_END;

  FD_VM_INTERP_INSTR_BEGIN(0xcf) /* FD_SBPF_OP_ARSH64_REG */
    reg[ dst ] = (ulong)( (long)reg_dst >> reg_src ); /* FIXME: WIDE SHIFTS, STRICT SIGN EXTENSION */
  FD_VM_INTERP_INSTR_END;

  /* 0xd0 - 0xdf ******************************************************/

  FD_VM_INTERP_INSTR_BEGIN(0xd4) /* FD_SBPF_OP_END_LE */
    /* fd machine is little endian */
  FD_VM_INTERP_INSTR_END;

  FD_VM_INTERP_BRANCH_BEGIN(0xd5) /* FD_SBPF_OP_JSLE_IMM */ /* FIXME: CHECK IMM SIGN EXTENSION */
    pc += fd_ulong_if( (long)reg_dst<=(long)(int)imm, (ulong)(long)offset, 0UL );
  FD_VM_INTERP_BRANCH_END;

  FD_VM_INTERP_INSTR_BEGIN(0xdc) /* FD_SBPF_OP_END_BE */
    /* Note: since fd_vm_validate rejects BE with strange immediates, we
       sigill if we encouter such in unvalidated code to match (FIXME:
       IS THIS THE DESIRED BEHAVIOR?) */
    switch( imm ) {
    case 16U: reg[ dst ] = (ulong)fd_ushort_bswap( (ushort)reg_dst ); break;
    case 32U: reg[ dst ] = (ulong)fd_uint_bswap  ( (uint)  reg_dst ); break;
    case 64U: reg[ dst ] =        fd_ulong_bswap ( (ulong) reg_dst ); break;
    default: goto sigill;
    }
  FD_VM_INTERP_INSTR_END;

  FD_VM_INTERP_BRANCH_BEGIN(0xdd) /* FD_SBPF_OP_JSLE_REG */
    pc += fd_ulong_if( (long)reg_dst<=(long)reg_src, (ulong)(long)offset, 0UL );
  FD_VM_INTERP_BRANCH_END;

  /* FIXME: sigsplit is only partially implemented (needs the bit vector
     of invalid jump targets in BRANCH_END) */

  /* FIXME: sigbus/sigrdonly are mapped to sigsegv for simplicity
     currently but could be enabled if desired. */

  /* FD_VM_INTERP_FAULT accumulates to ic and cu all non-faulting
     instructions preceeding a fault generated by a non-branching
     instruction.  When a non-branching instruction faults, pc is at the
     instruction and the number of non-branching instructions that have
     not yet been reflected in ic and cu is:

       pc - pc0 - ic_correction

     as per the accounting described above.

     Note that, for a sigtext caused by a branch instruction, pc0==pc
     (from the BRANCH_END) and ic_correction==0 (from the BRANCH_BEGIN)
     such that the below does not change the already current values in
     ic and cu.  Thus it also "does the right thing" in both the
     non-branching and branching cases for sigtext.  The same applies to
     sigsplit. */

#define FD_VM_INTERP_FAULT                  \
  ic_correction = pc - pc0 - ic_correction; \
  ic += ic_correction;                      \
  cu -= fd_ulong_min( ic_correction, cu )

sigtext:     FD_VM_INTERP_FAULT;                  err = FD_VM_ERR_SIGTEXT;   goto interp_halt;
sigsplit:    FD_VM_INTERP_FAULT;                  err = FD_VM_ERR_SIGSPLIT;  goto interp_halt;
sigcall:     /* ic current */    /* cu current */ err = FD_VM_ERR_SIGCALL;   goto interp_halt;
sigstack:    /* ic current */    /* cu current */ err = FD_VM_ERR_SIGSTACK;  goto interp_halt;
sigill:      FD_VM_INTERP_FAULT;                  err = FD_VM_ERR_SIGILL;    goto interp_halt;
sigsegv:     FD_VM_INTERP_FAULT;                  err = FD_VM_ERR_SIGSEGV;   goto interp_halt;
//sigbus:    FD_VM_INTERP_FAULT;                  err = FD_VM_ERR_SIGBUS;    goto interp_halt;
//sigrdonly: FD_VM_INTERP_FAULT;                  err = FD_VM_ERR_SIGRDONLY; goto interp_halt;
sigcost:
  /* ic current */
  cu = 0UL;
  /* if frame count is 0, then we are in an edge case where an execution has consumed
     exactly the right number of CUs, but FD_SBPF_OP_EXIT's FD_VM_INTERP_BRANCH_BEGIN
     has thrown an error because cu == 0. Therefore we should not return an error in
     this case. */
  if ( FD_LIKELY( frame_cnt ) ) {
    err = FD_VM_ERR_SIGCOST;
  }
  goto interp_halt;
sigsyscall:  /* ic current */    /* cu current */ /* err current */          goto interp_halt;

#undef FD_VM_INTERP_FAULT

interp_halt:

  /* Pack the unpacked execution state into vm to give a precise view of
     the execution when the vm halted. */

  vm->pc        = pc;
  vm->ic        = ic;
  vm->cu        = cu;
  vm->frame_cnt = frame_cnt;

# undef FD_VM_INTERP_STACK_PUSH

# undef FD_VM_INTERP_BRANCH_END
# undef FD_VM_INTERP_BRANCH_BEGIN

# undef FD_VM_INTERP_INSTR_END
# undef FD_VM_INTERP_INSTR_BEGIN
# undef FD_VM_INTERP_INSTR_EXEC

# if defined(__clang__)
# pragma clang diagnostic pop
# endif

# if defined(__GNUC__)
# pragma GCC diagnostic pop
# endif
