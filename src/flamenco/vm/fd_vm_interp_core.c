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

/* These mimic the exact Rust semantics for wrapping_shl and wrapping_shr. */

/* u64::wrapping_shl: a.unchecked_shl(b & (64 - 1))
   
   https://doc.rust-lang.org/std/primitive.u64.html#method.wrapping_shl
 */
#define FD_RUST_ULONG_WRAPPING_SHL( a, b ) (a << ( b & ( 63 ) ))

/* u64::wrapping_shr: a.unchecked_shr(b & (64 - 1))
   
   https://doc.rust-lang.org/std/primitive.u64.html#method.wrapping_shr
 */
#define FD_RUST_ULONG_WRAPPING_SHR( a, b ) (a >> ( b & ( 63 ) ))

/* u32::wrapping_shl: a.unchecked_shl(b & (32 - 1))
   
   https://doc.rust-lang.org/std/primitive.u32.html#method.wrapping_shl
 */
#define FD_RUST_UINT_WRAPPING_SHL( a, b ) (a << ( b & ( 31 ) ))

/* u32::wrapping_shr: a.unchecked_shr(b & (32 - 1))
   
   https://doc.rust-lang.org/std/primitive.u32.html#method.wrapping_shr
 */
#define FD_RUST_UINT_WRAPPING_SHR( a, b ) (a >> ( b & ( 31 ) ))


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

# ifndef FD_VM_INTERP_EXE_TRACING_ENABLED /* Non-tracing path only, ~0.3% faster in some benchmarks, slower in others but more code footprint */
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
    if( FD_UNLIKELY( ic_correction>cu ) ) goto sigcost; /* Note: untaken branches don't consume BTB */  \
    cu -= ic_correction;                                                                                \
    /* At this point, cu>=0 */                                                                          \
    ic_correction = 0UL;

  /* FIXME: debatable if it is better to do pc++ here or have the
     instruction implementations do it in their code path. */

# ifndef FD_VM_INTERP_EXE_TRACING_ENABLED /* Non-tracing path only, ~4% faster in some benchmarks, slower in others but more code footprint */
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

# define FD_VM_INTERP_STACK_PUSH                                                                            \
  shadow[ frame_cnt ].r6 = reg[6];                                                                          \
  shadow[ frame_cnt ].r7 = reg[7];                                                                          \
  shadow[ frame_cnt ].r8 = reg[8];                                                                          \
  shadow[ frame_cnt ].r9 = reg[9];                                                                          \
  shadow[ frame_cnt ].pc = pc;                                                                              \
  if( FD_UNLIKELY( ++frame_cnt>=frame_max ) ) goto sigstack; /* Note: untaken branches don't consume BTB */ \
  reg[10] += vm->stack_frame_size

  /* We subtract the heap cost in the BPF loader */

  goto interp_exec; /* Silly but to avoid unused label warning in some configurations */
interp_exec:

# ifdef FD_VM_INTERP_EXE_TRACING_ENABLED
  /* Note: when tracing or optimizing for code footprint, all
     instruction execution starts here such that this is only point
     where exe tracing diagnostics are needed. */
  if( FD_UNLIKELY( pc>=text_cnt ) ) goto sigtext;
  fd_vm_trace_event_exe( vm->trace, pc, ic + ( pc - pc0 - ic_correction ), cu, reg, vm->text + pc, vm->text_cnt - pc, ic_correction, frame_cnt );
# endif

  FD_VM_INTERP_INSTR_EXEC;

  /* 0x00 - 0x0f ******************************************************/

/* FIXME: MORE THINKING AROUND LDQ HANDLING HERE (see below) */
  FD_VM_INTERP_INSTR_BEGIN(0x04) /* FD_SBPF_OP_ADD_IMM */
    reg[ dst ] = (ulong)(long)( (int)reg_dst + (int)imm );
  FD_VM_INTERP_INSTR_END;

  FD_VM_INTERP_BRANCH_BEGIN(0x05) /* FD_SBPF_OP_JA */
    pc += (ulong)(long)offset;
  FD_VM_INTERP_BRANCH_END;

  FD_VM_INTERP_INSTR_BEGIN(0x07) /* FD_SBPF_OP_ADD64_IMM */
    reg[ dst ] = reg_dst + (ulong)(long)(int)imm;
  FD_VM_INTERP_INSTR_END;

  FD_VM_INTERP_INSTR_BEGIN(0x0c) /* FD_SBPF_OP_ADD_REG */
    reg[ dst ] = (ulong)(long)( (int)reg_dst + (int)reg_src );
  FD_VM_INTERP_INSTR_END;

  FD_VM_INTERP_INSTR_BEGIN(0x0f) /* FD_SBPF_OP_ADD64_REG */
    reg[ dst ] = reg_dst + reg_src;
  FD_VM_INTERP_INSTR_END;

  /* 0x10 - 0x1f ******************************************************/

  FD_VM_INTERP_INSTR_BEGIN(0x14) /* FD_SBPF_OP_SUB_IMM */
    reg[ dst ] = (ulong)(long)( (int)reg_dst - (int)imm );
  FD_VM_INTERP_INSTR_END;

  FD_VM_INTERP_BRANCH_BEGIN(0x15) /* FD_SBPF_OP_JEQ_IMM */
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
    reg[ dst ] = (ulong)(long)( (int)reg_dst - (int)reg_src );
  FD_VM_INTERP_INSTR_END;

  FD_VM_INTERP_BRANCH_BEGIN(0x1d) /* FD_SBPF_OP_JEQ_REG */
    pc += fd_ulong_if( reg_dst==reg_src, (ulong)(long)offset, 0UL );
  FD_VM_INTERP_BRANCH_END;

  FD_VM_INTERP_INSTR_BEGIN(0x1f) /* FD_SBPF_OP_SUB64_REG */
    reg[ dst ] = reg_dst - reg_src;
  FD_VM_INTERP_INSTR_END;

  /* 0x20 - 0x2f ******************************************************/

  FD_VM_INTERP_INSTR_BEGIN(0x24) /* FD_SBPF_OP_MUL_IMM */
    reg[ dst ] = (ulong)(long)( (int)reg_dst * (int)imm );
  FD_VM_INTERP_INSTR_END;

  FD_VM_INTERP_BRANCH_BEGIN(0x25) /* FD_SBPF_OP_JGT_IMM */
    pc += fd_ulong_if( reg_dst>(ulong)(long)(int)imm, (ulong)(long)offset, 0UL );
  FD_VM_INTERP_BRANCH_END;

  FD_VM_INTERP_INSTR_BEGIN(0x27) /* FD_SBPF_OP_MUL64_IMM */
    reg[ dst ] = (ulong)( (long)reg_dst * (long)(int)imm );
  FD_VM_INTERP_INSTR_END;

  FD_VM_INTERP_INSTR_BEGIN(0x2c) /* FD_SBPF_OP_MUL_REG */
    reg[ dst ] = (ulong)(long)( (int)reg_dst * (int)reg_src );
  FD_VM_INTERP_INSTR_END;

  FD_VM_INTERP_BRANCH_BEGIN(0x2d) /* FD_SBPF_OP_JGT_REG */
    pc += fd_ulong_if( reg_dst>reg_src, (ulong)(long)offset, 0UL );
  FD_VM_INTERP_BRANCH_END;

  FD_VM_INTERP_INSTR_BEGIN(0x2f) /* FD_SBPF_OP_MUL64_REG */
    reg[ dst ] = reg_dst * reg_src;
  FD_VM_INTERP_INSTR_END;

  /* 0x30 - 0x3f ******************************************************/

  FD_VM_INTERP_INSTR_BEGIN(0x34) /* FD_SBPF_OP_DIV_IMM */
    /* FIXME: convert to a multiply at validation time (usually probably
       not worth it) */
    reg[ dst ] = (ulong)((uint)reg_dst / imm);
  FD_VM_INTERP_INSTR_END;

  FD_VM_INTERP_BRANCH_BEGIN(0x35) /* FD_SBPF_OP_JGE_IMM */
    pc += fd_ulong_if( reg_dst>=(ulong)(long)(int)imm, (ulong)(long)offset, 0UL );
  FD_VM_INTERP_BRANCH_END;

  FD_VM_INTERP_INSTR_BEGIN(0x37) /* FD_SBPF_OP_DIV64_IMM */
    reg[ dst ] = reg_dst / (ulong)imm;
  FD_VM_INTERP_INSTR_END;

  FD_VM_INTERP_INSTR_BEGIN(0x3c) /* FD_SBPF_OP_DIV_REG */
    if( FD_UNLIKELY( !(uint)reg_src ) ) goto sigfpe;
    reg[ dst ] = (ulong)((uint)reg_dst / (uint)reg_src);
  FD_VM_INTERP_INSTR_END;

  FD_VM_INTERP_BRANCH_BEGIN(0x3d) /* FD_SBPF_OP_JGE_REG */
    pc += fd_ulong_if( reg_dst>=reg_src, (ulong)(long)offset, 0UL );
  FD_VM_INTERP_BRANCH_END;

  FD_VM_INTERP_INSTR_BEGIN(0x3f) /* FD_SBPF_OP_DIV64_REG */
    if( FD_UNLIKELY( !reg_src ) ) goto sigfpe;
    reg[ dst ] = reg_dst / reg_src;
  FD_VM_INTERP_INSTR_END;

  /* 0x40 - 0x4f ******************************************************/

  FD_VM_INTERP_INSTR_BEGIN(0x44) /* FD_SBPF_OP_OR_IMM */
    reg[ dst ] = (ulong)( (uint)reg_dst | imm );
  FD_VM_INTERP_INSTR_END;

  FD_VM_INTERP_BRANCH_BEGIN(0x45) /* FD_SBPF_OP_JSET_IMM */
    pc += fd_ulong_if( !!(reg_dst & (ulong)(long)(int)imm), (ulong)(long)offset, 0UL );
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

  FD_VM_INTERP_BRANCH_BEGIN(0x55) /* FD_SBPF_OP_JNE_IMM */
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
    uchar is_multi_region = 0;
    ulong vaddr           = reg_src + (ulong)(long)offset;
    ulong haddr           = fd_vm_mem_haddr( vm, vaddr, sizeof(uint), region_haddr, region_ld_sz, 0, 0UL, &is_multi_region );
    int   sigsegv         = !haddr;
    if( FD_UNLIKELY( sigsegv ) ) goto sigsegv; /* Note: untaken branches don't consume BTB */ /* FIXME: sigbus */
    reg[ dst ] = fd_vm_mem_ld_4( vm, vaddr, haddr, is_multi_region );
  }
  FD_VM_INTERP_INSTR_END;

  FD_VM_INTERP_INSTR_BEGIN(0x62) { /* FD_SBPF_OP_STW */
    uchar is_multi_region = 0;
    ulong vaddr           = reg_dst + (ulong)(long)offset;
    ulong haddr           = fd_vm_mem_haddr( vm, vaddr, sizeof(uint), region_haddr, region_st_sz, 1, 0UL, &is_multi_region );
    int   sigsegv         = !haddr;
    if( FD_UNLIKELY( sigsegv ) ) { vm->segv_store_vaddr = vaddr; goto sigsegv; } /* Note: untaken branches don't consume BTB */ /* FIXME: sigbus */
    fd_vm_mem_st_4( vm, vaddr, haddr, imm, is_multi_region );
  }
  FD_VM_INTERP_INSTR_END;

  FD_VM_INTERP_INSTR_BEGIN(0x63) { /* FD_SBPF_OP_STXW */
    uchar is_multi_region = 0;
    ulong vaddr           = reg_dst + (ulong)(long)offset;
    ulong haddr           = fd_vm_mem_haddr( vm, vaddr, sizeof(uint), region_haddr, region_st_sz, 1, 0UL, &is_multi_region );
    int   sigsegv         = !haddr;
    if( FD_UNLIKELY( sigsegv ) ) { vm->segv_store_vaddr = vaddr; goto sigsegv; } /* Note: untaken branches don't consume BTB */ /* FIXME: sigbus/rdonly */
    fd_vm_mem_st_4( vm, vaddr, haddr, (uint)reg_src, is_multi_region );
  }
  FD_VM_INTERP_INSTR_END;

  FD_VM_INTERP_INSTR_BEGIN(0x64) /* FD_SBPF_OP_LSH_IMM */
    /* https://github.com/solana-labs/rbpf/blob/8d36530b7071060e2837ebb26f25590db6816048/src/interpreter.rs#L291 */
    reg[ dst ] = (ulong)( FD_RUST_UINT_WRAPPING_SHL( (uint)reg_dst, (uint)imm ) );
  FD_VM_INTERP_INSTR_END;

  FD_VM_INTERP_BRANCH_BEGIN(0x65) /* FD_SBPF_OP_JSGT_IMM */
    pc += fd_ulong_if( (long)reg_dst>(long)(int)imm, (ulong)(long)offset, 0UL );
  FD_VM_INTERP_BRANCH_END;

  FD_VM_INTERP_INSTR_BEGIN(0x67) /* FD_SBPF_OP_LSH64_IMM */
    /* https://github.com/solana-labs/rbpf/blob/8d36530b7071060e2837ebb26f25590db6816048/src/interpreter.rs#L376 */
    reg[ dst ] = FD_RUST_ULONG_WRAPPING_SHL( reg_dst, imm );
  FD_VM_INTERP_INSTR_END;

  FD_VM_INTERP_INSTR_BEGIN(0x69) { /* FD_SBPF_OP_LDXH */
    uchar is_multi_region = 0;
    ulong vaddr           = reg_src + (ulong)(long)offset;
    ulong haddr           = fd_vm_mem_haddr( vm, vaddr, sizeof(ushort), region_haddr, region_ld_sz, 0, 0UL, &is_multi_region );
    int   sigsegv         = !haddr;
    if( FD_UNLIKELY( sigsegv ) ) goto sigsegv; /* Note: untaken branches don't consume BTB */ /* FIXME: sigbus */
    reg[ dst ] = fd_vm_mem_ld_2( vm, vaddr, haddr, is_multi_region );
  }
  FD_VM_INTERP_INSTR_END;

  FD_VM_INTERP_INSTR_BEGIN(0x6a) { /* FD_SBPF_OP_STH */
    uchar is_multi_region = 0;
    ulong vaddr           = reg_dst + (ulong)(long)offset;
    ulong haddr           = fd_vm_mem_haddr( vm, vaddr, sizeof(ushort), region_haddr, region_st_sz, 1, 0UL, &is_multi_region );
    int   sigsegv         = !haddr;
    if( FD_UNLIKELY( sigsegv ) ) { vm->segv_store_vaddr = vaddr; goto sigsegv; } /* Note: untaken branches don't consume BTB */ /* FIXME: sigbus */
    fd_vm_mem_st_2( vm, vaddr, haddr, (ushort)imm, is_multi_region );
  }
  FD_VM_INTERP_INSTR_END;

  FD_VM_INTERP_INSTR_BEGIN(0x6b) { /* FD_SBPF_OP_STXH */
    uchar is_multi_region = 0;
    ulong vaddr           = reg_dst + (ulong)(long)offset;
    ulong haddr           = fd_vm_mem_haddr( vm, vaddr, sizeof(ushort), region_haddr, region_st_sz, 1, 0UL, &is_multi_region );
    int   sigsegv         = !haddr;
    if( FD_UNLIKELY( sigsegv ) ) { vm->segv_store_vaddr = vaddr; goto sigsegv; } /* Note: untaken branches don't consume BTB */ /* FIXME: sigbus/rdonly */
    fd_vm_mem_st_2( vm, vaddr, haddr, (ushort)reg_src, is_multi_region );
  }
  FD_VM_INTERP_INSTR_END;

  FD_VM_INTERP_INSTR_BEGIN(0x6c) /* FD_SBPF_OP_LSH_REG */
    /* https://github.com/solana-labs/rbpf/blob/8d36530b7071060e2837ebb26f25590db6816048/src/interpreter.rs#L292 */
    reg[ dst ] = (ulong)( FD_RUST_UINT_WRAPPING_SHL( (uint)reg_dst, reg_src ) );
  FD_VM_INTERP_INSTR_END;

  FD_VM_INTERP_BRANCH_BEGIN(0x6d) /* FD_SBPF_OP_JSGT_REG */
    pc += fd_ulong_if( (long)reg_dst>(long)reg_src, (ulong)(long)offset, 0UL );
  FD_VM_INTERP_BRANCH_END;

  FD_VM_INTERP_INSTR_BEGIN(0x6f) /* FD_SBPF_OP_LSH64_REG */
    /* https://github.com/solana-labs/rbpf/blob/8d36530b7071060e2837ebb26f25590db6816048/src/interpreter.rs#L377 */
    reg[ dst ] = FD_RUST_ULONG_WRAPPING_SHL( reg_dst, reg_src );
  FD_VM_INTERP_INSTR_END;

  /* 0x70 - 0x7f ******************************************************/

  FD_VM_INTERP_INSTR_BEGIN(0x71) { /* FD_SBPF_OP_LDXB */
    uchar is_multi_region = 0;
    ulong vaddr           = reg_src + (ulong)(long)offset;
    ulong haddr           = fd_vm_mem_haddr( vm, vaddr, sizeof(uchar), region_haddr, region_ld_sz, 0, 0UL, &is_multi_region );
    if( FD_UNLIKELY( !haddr ) ) goto sigsegv; /* Note: untaken branches don't consume BTB */
    reg[ dst ] = fd_vm_mem_ld_1( haddr );
  }
  FD_VM_INTERP_INSTR_END;

  FD_VM_INTERP_INSTR_BEGIN(0x72) { /* FD_SBPF_OP_STB */
    uchar is_multi_region = 0;
    ulong vaddr           = reg_dst + (ulong)(long)offset;
    ulong haddr           = fd_vm_mem_haddr( vm, vaddr, sizeof(uchar), region_haddr, region_st_sz, 1, 0UL, &is_multi_region );
    if( FD_UNLIKELY( !haddr ) ) { vm->segv_store_vaddr = vaddr; goto sigsegv; } /* Note: untaken branches don't consume BTB */
    fd_vm_mem_st_1( haddr, (uchar)imm );
  }
  FD_VM_INTERP_INSTR_END;

  FD_VM_INTERP_INSTR_BEGIN(0x73) { /* FD_SBPF_OP_STXB */
    uchar is_multi_region = 0;
    ulong vaddr           = reg_dst + (ulong)(long)offset;
    ulong haddr           = fd_vm_mem_haddr( vm, vaddr, sizeof(uchar), region_haddr, region_st_sz, 1, 0UL, &is_multi_region );
    if( FD_UNLIKELY( !haddr ) ) { vm->segv_store_vaddr = vaddr; goto sigsegv; } /* Note: untaken branches don't consume BTB */ /* FIXME: sigrdonly */
    fd_vm_mem_st_1( haddr, (uchar)reg_src );
  }
  FD_VM_INTERP_INSTR_END;

  FD_VM_INTERP_INSTR_BEGIN(0x74) /* FD_SBPF_OP_RSH_IMM */
    /* https://github.com/solana-labs/rbpf/blob/8d36530b7071060e2837ebb26f25590db6816048/src/interpreter.rs#L293 */
    reg[ dst ] = (ulong)( FD_RUST_UINT_WRAPPING_SHR( (uint)reg_dst, imm ) );
  FD_VM_INTERP_INSTR_END;

  FD_VM_INTERP_BRANCH_BEGIN(0x75) /* FD_SBPF_OP_JSGE_IMM */
    pc += fd_ulong_if( (long)reg_dst>=(long)(int)imm, (ulong)(long)offset, 0UL );
  FD_VM_INTERP_BRANCH_END;

  FD_VM_INTERP_INSTR_BEGIN(0x77) /* FD_SBPF_OP_RSH64_IMM */
    /* https://github.com/solana-labs/rbpf/blob/8d36530b7071060e2837ebb26f25590db6816048/src/interpreter.rs#L378 */
    reg[ dst ] = FD_RUST_ULONG_WRAPPING_SHR( reg_dst, imm );
  FD_VM_INTERP_INSTR_END;

  FD_VM_INTERP_INSTR_BEGIN(0x79) { /* FD_SBPF_OP_LDXQ */
    uchar is_multi_region = 0;
    ulong vaddr           = reg_src + (ulong)(long)offset;
    ulong haddr           = fd_vm_mem_haddr( vm, vaddr, sizeof(ulong), region_haddr, region_ld_sz, 0, 0UL, &is_multi_region );
    int   sigsegv         = !haddr;
    if( FD_UNLIKELY( sigsegv ) ) goto sigsegv; /* Note: untaken branches don't consume BTB */ /* FIXME: sigbus */
    reg[ dst ] = fd_vm_mem_ld_8( vm, vaddr, haddr, is_multi_region );
  }
  FD_VM_INTERP_INSTR_END;

  FD_VM_INTERP_INSTR_BEGIN(0x7a) { /* FD_SBPF_OP_STQ */
    uchar is_multi_region = 0;
    ulong vaddr           = reg_dst + (ulong)(long)offset;
    ulong haddr           = fd_vm_mem_haddr( vm, vaddr, sizeof(ulong), region_haddr, region_st_sz, 1, 0UL, &is_multi_region );
    int   sigsegv         = !haddr;
    if( FD_UNLIKELY( sigsegv ) ) { vm->segv_store_vaddr = vaddr; goto sigsegv; } /* Note: untaken branches don't consume BTB */ /* FIXME: sigbus */
    fd_vm_mem_st_8( vm, vaddr, haddr, (ulong)imm, is_multi_region );
  }
  FD_VM_INTERP_INSTR_END;

  FD_VM_INTERP_INSTR_BEGIN(0x7b) { /* FD_SBPF_OP_STXQ */
    uchar is_multi_region = 0;
    ulong vaddr           = reg_dst + (ulong)(long)offset;
    ulong haddr           = fd_vm_mem_haddr( vm, vaddr, sizeof(ulong), region_haddr, region_st_sz, 1, 0UL, &is_multi_region );
    int   sigsegv         = !haddr;
    if( FD_UNLIKELY( sigsegv ) ) { vm->segv_store_vaddr = vaddr; goto sigsegv; } /* Note: untaken branches don't consume BTB */ /* FIXME: sigbus/rdonly */
    fd_vm_mem_st_8( vm, vaddr, haddr, reg_src, is_multi_region );
  }
  FD_VM_INTERP_INSTR_END;

  FD_VM_INTERP_INSTR_BEGIN(0x7c) /* FD_SBPF_OP_RSH_REG */
    /* https://github.com/solana-labs/rbpf/blob/8d36530b7071060e2837ebb26f25590db6816048/src/interpreter.rs#L294 */
    reg[ dst ] = (ulong)( FD_RUST_UINT_WRAPPING_SHR( (uint)reg_dst, (uint)reg_src ) );
  FD_VM_INTERP_INSTR_END;

  FD_VM_INTERP_BRANCH_BEGIN(0x7d) /* FD_SBPF_OP_JSGE_REG */
    pc += fd_ulong_if( (long)reg_dst>=(long)reg_src, (ulong)(long)offset, 0UL );
  FD_VM_INTERP_BRANCH_END;

  FD_VM_INTERP_INSTR_BEGIN(0x7f) /* FD_SBPF_OP_RSH64_REG */
    /* https://github.com/solana-labs/rbpf/blob/8d36530b7071060e2837ebb26f25590db6816048/src/interpreter.rs#L379 */
    reg[ dst ] = FD_RUST_ULONG_WRAPPING_SHR( reg_dst, reg_src );
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
       GUARANTEE TO OVERFLOW. */
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

  FD_VM_INTERP_INSTR_BEGIN(0x94) /* FD_SBPF_OP_MOD_IMM */
    reg[ dst ] = (ulong)( (uint)reg_dst % imm );
  FD_VM_INTERP_INSTR_END;

  FD_VM_INTERP_BRANCH_BEGIN(0x95) /* FD_SBPF_OP_EXIT */
      /* Agave JIT VM exit implementation analysis below.

       Agave references:
       https://github.com/solana-labs/rbpf/blob/v0.8.5/src/interpreter.rs#L503-L509
       https://github.com/solana-labs/rbpf/blob/v0.8.5/src/jit.rs#L697-L702 */
    if( FD_UNLIKELY( !frame_cnt ) ) goto sigexit; /* Exit program */
    frame_cnt--;
    reg[6]   = shadow[ frame_cnt ].r6;
    reg[7]   = shadow[ frame_cnt ].r7;
    reg[8]   = shadow[ frame_cnt ].r8;
    reg[9]   = shadow[ frame_cnt ].r9;
    pc       = shadow[ frame_cnt ].pc;
    reg[10] -= vm->stack_frame_size;
  FD_VM_INTERP_BRANCH_END;

  FD_VM_INTERP_INSTR_BEGIN(0x97) /* FD_SBPF_OP_MOD64_IMM */
    reg[ dst ] = reg_dst % (ulong)(long)(int)imm;
  FD_VM_INTERP_INSTR_END;

  FD_VM_INTERP_INSTR_BEGIN(0x9c) /* FD_SBPF_OP_MOD_REG */
    if( FD_UNLIKELY( !(uint)reg_src ) ) goto sigfpe;
    reg[ dst ] = (ulong)( ((uint)reg_dst % (uint)reg_src) );
  FD_VM_INTERP_INSTR_END;

  FD_VM_INTERP_INSTR_BEGIN(0x9f) /* FD_SBPF_OP_MOD64_REG */
    if( FD_UNLIKELY( !reg_src ) ) goto sigfpe;
    reg[ dst ] = reg_dst % reg_src;
  FD_VM_INTERP_INSTR_END;

  /* 0xa0 - 0xaf ******************************************************/

  FD_VM_INTERP_INSTR_BEGIN(0xa4) /* FD_SBPF_OP_XOR_IMM */
    reg[ dst ] = (ulong)( (uint)reg_dst ^ imm );
  FD_VM_INTERP_INSTR_END;

  FD_VM_INTERP_BRANCH_BEGIN(0xa5) /* FD_SBPF_OP_JLT_IMM */
    pc += fd_ulong_if( reg_dst<(ulong)(long)(int)imm, (ulong)(long)offset, 0UL );
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

  FD_VM_INTERP_BRANCH_BEGIN(0xb5) /* FD_SBPF_OP_JLE_IMM */
    pc += fd_ulong_if( reg_dst<=(ulong)(long)(int)imm, (ulong)(long)offset, 0UL );
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
    /* Note: since fd_vm_validate rejects LE with strange immediates, we
       sigill if we encouter such in unvalidated code to match (FIXME:
       IS THIS THE DESIRED BEHAVIOR?) */
    switch( imm ) {
    case 16U: reg[ dst ] = (ushort)reg_dst; break;
    case 32U: reg[ dst ] = (uint)  reg_dst; break;
    case 64U:                               break;
    default: goto sigill;
    }
  FD_VM_INTERP_INSTR_END;

  FD_VM_INTERP_BRANCH_BEGIN(0xd5) /* FD_SBPF_OP_JSLE_IMM */
    pc += fd_ulong_if( (long)reg_dst<=(long)(int)imm, (ulong)(long)offset, 0UL );
  FD_VM_INTERP_BRANCH_END;

  FD_VM_INTERP_INSTR_BEGIN(0xdc) /* FD_SBPF_OP_END_BE */
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

       pc - pc0 + 1 - ic_correction

     as per the accounting described above. +1 to include the faulting
     instruction itself.

     Note that, for a sigtext caused by a branch instruction, pc0==pc
     (from the BRANCH_END) and ic_correction==0 (from the BRANCH_BEGIN)
     such that the below does not change the already current values in
     ic and cu.  Thus it also "does the right thing" in both the
     non-branching and branching cases for sigtext.  The same applies to
     sigsplit. */

#define FD_VM_INTERP_FAULT                                          \
  ic_correction = pc - pc0 + 1UL - ic_correction;                   \
  ic += ic_correction;                                              \
  if ( FD_UNLIKELY( ic_correction > cu ) ) err = FD_VM_ERR_SIGCOST; \
  cu -= fd_ulong_min( ic_correction, cu )

sigtext:     err = FD_VM_ERR_SIGTEXT;  FD_VM_INTERP_FAULT;                     goto interp_halt;
sigsplit:    err = FD_VM_ERR_SIGSPLIT; FD_VM_INTERP_FAULT;                     goto interp_halt;
sigcall:     err = FD_VM_ERR_SIGCALL;  /* ic current */      /* cu current */  goto interp_halt;
sigstack:    err = FD_VM_ERR_SIGSTACK; /* ic current */      /* cu current */  goto interp_halt;
sigill:      err = FD_VM_ERR_SIGILL;   FD_VM_INTERP_FAULT;                     goto interp_halt;
sigsegv:     err = FD_VM_ERR_SIGSEGV;  FD_VM_INTERP_FAULT;                     goto interp_halt;
sigcost:     err = FD_VM_ERR_SIGCOST;  /* ic current */      cu = 0UL;         goto interp_halt;
sigsyscall:  /* err current */         /* ic current */      /* cu current */  goto interp_halt;
sigfpe:      err = FD_VM_ERR_SIGFPE;   FD_VM_INTERP_FAULT;                     goto interp_halt;
sigexit:     /* err current */         /* ic current */      /* cu current */  goto interp_halt;

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

/*   Agave/JIT CU model analysis (and why we are conformant!):

     The Agave JIT employs a similar strategy of accumulating instructions
     in a linear run and processing them at the start of a new linear 
     run/branch (side note: the JIT treats the LDQ instruction as a "branch" 
     that jumps pc + 2). 
     
     In what is assumed to be an act of register conservation, the JIT 
     uses a catch-all "instruction meter" (IM) register (REGISTER_INSTRUCTION_METER)
     that represents two different interpretations of the question
     "how many instructions can I execute?".

     The IM, depending on where we are in the execution, either represents:
        1. IM => The number of instructions remaining before exhausting CU 
        budget. This is analagous to vm->cu in our interpreter.
        2. IM' => The last pc you can execute in the current linear run before
        exhausting CU budget.  Mathematically, IM' = IM + pc0
        where pc0, just like our definition, is the start of the linear run.
        
        Note: IM' can go past the actual basic block/segment. In-fact, 
        it typically does, and implies we can execute the full block without
        exhausting CU budget (reminder that LDQ is treated as a branch).
      
      By default, the IM' form is used during execution. The IM form is used:
        - (transiently) during the processing of a branch instruction 
        - in post-VM cleanup (updates EbpfVm::previous_instruction_meter).

      When a branch instruction is encountered, the JIT checks
      for CU exhaustion with pc > IM', and throws an exception if so. This is valid,
      because as described above, IM' is the largest PC you can reach.
      
      If we haven't exhausted our CU limit, it updates IM':
        1. IM = IM' - (pc + 1)  # Note that IM' at this point is IM + pc0', 
                                # where pc0' is the start of the current linear run.
        2. IM' = IM + pc0       # pc0 is the start of the new linear run (typically the target pc)
      
      Code (that does the above in one ALU instruction):
       https://github.com/solana-labs/rbpf/blob/v0.8.5/src/jit.rs#L891


      ### How does this relate to our interpreter?

      This process is similar to FD_VM_INTERP_BRANCH_BEGIN.
      We just deal with the IM form throughout (with vm->cu and ic_correction).
      If we break down step 1 from above with what we know about IM and IM',
      we get the following:
        1. IM = IM' - (pc + 1)
           IM = (IM + pc0') - (pc + 1)
           IM = IM + (pc0' - (pc + 1))
           IM = IM - ((pc + 1) - pc0')
           IM = IM - ic_correction
      Here, ((pc + 1) - pc0') is the number of instrutions executed in the current
      linear run. This is the same as our ic_correction(*) in FD_VM_INTERP_BRANCH_BEGIN.

      If we replace IM with cu, this effectively becomes the
           cu -= ic_correction 
      line in FD_VM_INTERP_BRANCH_BEGIN.

      (*) Note: ic_correction (also) takes two forms. It is either the instruction 
      accumulator or the number of instructions executed in the current linear run. 
      It (transiently) takes the latter form during FD_VM_INTERP_BRANCH_BEGIN and 
      FD_VM_INTERP_FAULT, and the former form otherwise.
*/

/* (WIP) Precise faulting and the Agave JIT:
   
   Since the cost model is a part of consensus, we need to conform with the Agave/JIT
   cost model 1:1. To achieve that, our faulting model also needs to match precisely. This
   section covers the various faults that the respective VMs implement and how they match.

   # Normal VM exit (sigexit):
   VM exit instruction entrypoint: https://github.com/solana-labs/rbpf/blob/12237895305ab38514be865ebed6268553e4f589/src/jit.rs#L698-L708

   Pseudocode (with FD semantics):
   ```
    # pc is at the exit instruction
    # pc0 is the start of the current linear run
    if (frame_cnt == 0) {
        goto sigexit;
    }
    ...

    sigexit:
    if IM' <= pc {
      goto sigcost;
    } else {
      goto interp_halt;
    }
    ```

    Breaking down the IM' < pc check:
    - IM' = IM + pc0
    - pc  = ic + pc0, where (ic + 1) is the number of instructions executed in the current linear run

    IM' <= pc
    IM + pc0 <= ic + pc0
    IM <= ic
    IM <= pc - pc0
    IM < pc - pc0 + 1 # all unsigned integers
    IM < ic_correction

    This is analagous to the ic_correction>cu check in VM_INTERP_BRANCH_BEGIN.
   
   # (TODO) Text Overrun (sigtext/sigsplit):

*/
