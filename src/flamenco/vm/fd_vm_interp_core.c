  /* This is the VM SBPF interpreter core.  The caller unpacks the VM
     state and then just lets execution continue into this (or jumps to
     interp_exec) to start running.  The VM will run until it halts or
     faults.  On normal termination, it will branch to interp_halt to
     exit.  Each fault has its own exit label to allow the caller to
     handle individually. */

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

  /* Unpack only the truly per-instruction VM state so the live variable
     set across the 256-way computed-goto dispatch fits effortlessly in
     callee/scratch GPRs with zero stack or XMM spills on both GCC and
     Clang: {vm, text, version_interp_jump_table, pc, pc_bias, cu,
     block_text_limit, instr} = 8 GPRs total. */

  ulong pc = vm->pc;
  ulong cu = vm->cu;

  void const * const * const version_interp_jump_table = interp_jump_table[ vm->sbpf_version ];

  ulong instr;

#define reg      (vm->reg)
#define text_cnt (vm->text_cnt)

#define FD_VM_DST    fd_vm_instr_dst   ( instr )
#ifdef __clang__
#define FD_VM_SRC    ((ulong)((ushort)instr >> 12))
#else
#define FD_VM_SRC    fd_vm_instr_src   ( instr )
#endif
#define FD_VM_OFFSET fd_vm_instr_offset( instr )
#define FD_VM_IMM    fd_vm_instr_imm   ( instr )
#define FD_VM_SIMM   ((ulong)(long)(int)(instr >> 32))

/* These mimic the exact Rust semantics for wrapping_shl and wrapping_shr. */
#define FD_RUST_ULONG_WRAPPING_SHL( a, b ) ((a) << ( (b) & ( 63 ) ))
#define FD_RUST_ULONG_WRAPPING_SHR( a, b ) ((a) >> ( (b) & ( 63 ) ))
#define FD_RUST_UINT_WRAPPING_SHL( a, b )  ((a) << ( (b) & ( 31 ) ))
#define FD_RUST_UINT_WRAPPING_SHR( a, b )  ((a) >> ( (b) & ( 31 ) ))
#define FD_RUST_INT_WRAPPING_SHR( a, b )   ((a) >> ( (b) & ( 31 ) ))
#define FD_RUST_LONG_WRAPPING_SHR( a, b )  ((a) >> ( (b) & ( 63 ) ))

# define FD_VM_INTERP_INSTR_EXEC                                                                                    \
  if( FD_UNLIKELY( pc>=block_text_limit ) ) goto sigtext_or_sigcost; /* Note: untaken branches don't consume BTB */ \
  instr = text[ pc ];                                                /* Guaranteed in-bounds */                     \
  goto *version_interp_jump_table[ instr & 255UL ]                   /* Guaranteed in-bounds */

# define FD_VM_INTERP_SYSCALL_EXEC_DUMP                                       \
  /* Dumping for debugging purposes */                                        \
  if( FD_UNLIKELY( vm->dump_syscall_to_pb ) ) {                               \
    fd_dump_vm_syscall_to_protobuf( vm, syscall->name );                      \
  }

# define FD_VM_INTERP_SYSCALL_EXEC                                            \
  /* Setup */                                                                 \
  ulong _ic_save = vm->ic;                                                    \
  ulong _fc_save = vm->frame_cnt;                                             \
  vm->pc         = pc;                                                        \
  vm->cu         = cu;                                                        \
  FD_VM_INTERP_SYSCALL_EXEC_DUMP                                              \
  /* Execution */                                                             \
  err = syscall->func( vm, reg[1], reg[2], reg[3], reg[4], reg[5] );          \
  vm->ic         = _ic_save;                                                  \
  vm->frame_cnt  = _fc_save;                                                  \
  /* Error handling */                                                        \
  ulong cu_req = vm->cu;                                                      \
  cu = fd_ulong_min( cu_req, cu );                                            \
  if( FD_UNLIKELY( err ) ) {                                                  \
    if( err==FD_VM_SYSCALL_ERR_COMPUTE_BUDGET_EXCEEDED ) cu = 0UL; /* cmov */ \
    FD_VM_TEST_ERR_EXISTS( vm );                                              \
    goto sigsyscall;                                                          \
  }

# define FD_VM_INTERP_INSTR_BEGIN(opcode) interp_##opcode:

# ifndef FD_VM_INTERP_EXE_TRACING_ENABLED
# define FD_VM_INTERP_INSTR_END pc++; FD_VM_INTERP_INSTR_EXEC
# else
# define FD_VM_INTERP_INSTR_END pc++; goto interp_exec
# endif

  /* Instead of maintaining pc0 and ic_correction as two separate live
     registers that are only ever combined as (pc0 + ic_correction) at
     branches and faults, the non-tracing path maintains the single
     combined `pc_bias = pc0 + ic_correction`.  Each 2-word LDQ
     increments both `pc` and `pc_bias`, so `pc - pc_bias + 1` always
     equals `pc - pc0 + 1 - ic_correction`. */

# ifndef FD_VM_INTERP_EXE_TRACING_ENABLED

  ulong pc_bias          = pc;
  ulong block_text_limit = fd_ulong_min( text_cnt, pc+cu+cu+1UL );

# define FD_VM_INTERP_LDQ_EXTRA pc_bias++

# define FD_VM_INTERP_BRANCH_BEGIN(opcode)                                                       \
  interp_##opcode: {                                                                             \
    ulong _insns = pc - pc_bias + 1UL;                                                           \
    vm->ic += _insns;                                                                            \
    if( FD_UNLIKELY( _insns>cu ) ) goto sigcost; /* Note: untaken branches don't consume BTB */  \
    cu -= _insns;                                                                                \
  }

# define FD_VM_INTERP_BRANCH_END                                    \
    pc++;                                                           \
    pc_bias          = pc;                                          \
    block_text_limit = fd_ulong_min( text_cnt, pc+cu+cu+1UL );      \
    FD_VM_INTERP_INSTR_EXEC

# define FD_VM_INTERP_FAULT                                                              \
  do {                                                                                   \
    ulong _insns = pc - pc_bias + 1UL;                                                   \
    vm->ic += _insns;                                                                    \
    if( FD_UNLIKELY( _insns > cu ) ) err = FD_VM_ERR_EBPF_EXCEEDED_MAX_INSTRUCTIONS;     \
    cu -= fd_ulong_min( _insns, cu );                                                    \
  } while(0)

# else /* FD_VM_INTERP_EXE_TRACING_ENABLED */

  ulong pc0              = pc;
  ulong ic_correction    = 0UL;
  ulong block_text_limit = fd_ulong_min( text_cnt, pc0+cu+cu+1UL );

# define FD_VM_INTERP_LDQ_EXTRA ic_correction++

# define FD_VM_INTERP_BRANCH_BEGIN(opcode)                                                              \
  interp_##opcode:                                                                                      \
    ic_correction = pc - pc0 + 1UL - ic_correction;                                                     \
    vm->ic += ic_correction;                                                                            \
    if( FD_UNLIKELY( ic_correction>cu ) ) goto sigcost; /* Note: untaken branches don't consume BTB */  \
    cu -= ic_correction;                                                                                \
    ic_correction = 0UL;

# define FD_VM_INTERP_BRANCH_END                                    \
    pc++;                                                           \
    pc0              = pc;                                          \
    block_text_limit = fd_ulong_min( text_cnt, pc0+cu+cu+1UL );     \
    goto interp_exec

# define FD_VM_INTERP_FAULT                                                                 \
  do {                                                                                      \
    ic_correction = pc - pc0 + 1UL - ic_correction;                                         \
    vm->ic += ic_correction;                                                                \
    if( FD_UNLIKELY( ic_correction > cu ) ) err = FD_VM_ERR_EBPF_EXCEEDED_MAX_INSTRUCTIONS; \
    cu -= fd_ulong_min( ic_correction, cu );                                                \
  } while(0)

# endif

# define FD_VM_INTERP_STACK_PUSH                                                                                        \
  do {                                                                                                                  \
    ulong _fc = vm->frame_cnt;                                                                                          \
    fd_vm_shadow_t * _sh = &vm->shadow[ _fc ];                                                                          \
    _sh->r6  = reg[6];                                                                                                  \
    _sh->r7  = reg[7];                                                                                                  \
    _sh->r8  = reg[8];                                                                                                  \
    _sh->r9  = reg[9];                                                                                                  \
    _sh->r10 = reg[10];                                                                                                 \
    _sh->pc  = pc;                                                                                                      \
    vm->frame_cnt = ++_fc;                                                                                              \
    if( FD_UNLIKELY( _fc>=FD_VM_STACK_FRAME_MAX ) ) goto sigstack; /* Note: untaken branches don't consume BTB */       \
    reg[10] += vm->stack_frame_sz;                                                                                      \
  } while(0)

/* Memory load/store templates. */
# define FD_VM_INTERP_LD(opcode, sz, ld_fn)                                                         \
  FD_VM_INTERP_INSTR_BEGIN(opcode) {                                                                \
    ulong _vaddr = reg[ FD_VM_SRC ] + FD_VM_OFFSET;                                                 \
    ulong _haddr = fd_vm_mem_haddr( vm, _vaddr, (sz), vm->region_haddr, vm->region_ld_sz, 0, 0UL ); \
    if( FD_UNLIKELY( !_haddr ) ) {                                                                  \
      vm->segv_vaddr       = _vaddr;                                                                \
      vm->segv_access_type = FD_VM_ACCESS_TYPE_LD;                                                  \
      vm->segv_access_len  = (sz);                                                                  \
      goto sigsegv;                                                                                 \
    }                                                                                               \
    reg[ FD_VM_DST ] = ld_fn( _haddr );                                                             \
  } FD_VM_INTERP_INSTR_END

# define FD_VM_INTERP_ST_IMM(opcode, sz, st_fn, val_expr)                                           \
  FD_VM_INTERP_INSTR_BEGIN(opcode) {                                                                \
    ulong _vaddr = reg[ FD_VM_DST ] + FD_VM_OFFSET;                                                 \
    ulong _haddr = fd_vm_mem_haddr( vm, _vaddr, (sz), vm->region_haddr, vm->region_st_sz, 1, 0UL ); \
    if( FD_UNLIKELY( !_haddr ) ) {                                                                  \
      vm->segv_vaddr       = _vaddr;                                                                \
      vm->segv_access_type = FD_VM_ACCESS_TYPE_ST;                                                  \
      vm->segv_access_len  = (sz);                                                                  \
      goto sigsegv;                                                                                 \
    }                                                                                               \
    st_fn( _haddr, (val_expr) );                                                                    \
  } FD_VM_INTERP_INSTR_END

# define FD_VM_INTERP_ST_REG(opcode, sz, st_fn, cast_t)                                             \
  FD_VM_INTERP_INSTR_BEGIN(opcode) {                                                                \
    ulong _vaddr = reg[ FD_VM_DST ] + FD_VM_OFFSET;                                                 \
    ulong _haddr = fd_vm_mem_haddr( vm, _vaddr, (sz), vm->region_haddr, vm->region_st_sz, 1, 0UL ); \
    if( FD_UNLIKELY( !_haddr ) ) {                                                                  \
      vm->segv_vaddr       = _vaddr;                                                                \
      vm->segv_access_type = FD_VM_ACCESS_TYPE_ST;                                                  \
      vm->segv_access_len  = (sz);                                                                  \
      goto sigsegv;                                                                                 \
    }                                                                                               \
    st_fn( _haddr, (cast_t)reg[ FD_VM_SRC ] );                                                      \
  } FD_VM_INTERP_INSTR_END

  goto interp_exec;
interp_exec:

# ifdef FD_VM_INTERP_EXE_TRACING_ENABLED
  if( FD_UNLIKELY( pc>=block_text_limit ) ) goto sigtext_or_sigcost;
  fd_vm_trace_event_exe( vm->trace, pc, vm->ic + ( pc - pc0 - ic_correction ), cu, reg, text + pc, text_cnt - pc, ic_correction, vm->frame_cnt );
# endif

  FD_VM_INTERP_INSTR_EXEC;

  /* 0x00 - 0x0f ******************************************************/

  FD_VM_INTERP_INSTR_BEGIN(0x04) { /* FD_SBPF_OP_ADD_IMM */
    ulong dst = FD_VM_DST;
    reg[ dst ] = (ulong)(uint)( (int)reg[ dst ] + (int)FD_VM_IMM );
  } FD_VM_INTERP_INSTR_END;

  FD_VM_INTERP_INSTR_BEGIN(0x04depr) { /* FD_SBPF_OP_ADD_IMM deprecated SIMD-0174 */
    ulong dst = FD_VM_DST;
    reg[ dst ] = (ulong)(long)( (int)reg[ dst ] + (int)FD_VM_IMM );
  } FD_VM_INTERP_INSTR_END;

  FD_VM_INTERP_BRANCH_BEGIN(0x05) /* FD_SBPF_OP_JA */
    pc += FD_VM_OFFSET;
  FD_VM_INTERP_BRANCH_END;

  FD_VM_INTERP_INSTR_BEGIN(0x07) /* FD_SBPF_OP_ADD64_IMM */
    reg[ FD_VM_DST ] += FD_VM_SIMM;
  FD_VM_INTERP_INSTR_END;

  FD_VM_INTERP_INSTR_BEGIN(0x0c) { /* FD_SBPF_OP_ADD_REG */
    ulong dst = FD_VM_DST;
    reg[ dst ] = (ulong)(uint)( (int)reg[ dst ] + (int)reg[ FD_VM_SRC ] );
  } FD_VM_INTERP_INSTR_END;

  FD_VM_INTERP_INSTR_BEGIN(0x0cdepr) { /* FD_SBPF_OP_ADD_REG deprecated SIMD-0174 */
    ulong dst = FD_VM_DST;
    reg[ dst ] = (ulong)(long)( (int)reg[ dst ] + (int)reg[ FD_VM_SRC ] );
  } FD_VM_INTERP_INSTR_END;

  FD_VM_INTERP_INSTR_BEGIN(0x0f) /* FD_SBPF_OP_ADD64_REG */
    reg[ FD_VM_DST ] += reg[ FD_VM_SRC ];
  FD_VM_INTERP_INSTR_END;

  /* 0x10 - 0x1f ******************************************************/

  FD_VM_INTERP_INSTR_BEGIN(0x14) { /* FD_SBPF_OP_SUB_IMM */
    ulong dst = FD_VM_DST;
    reg[ dst ] = (ulong)(uint)( (int)FD_VM_IMM - (int)reg[ dst ] );
  } FD_VM_INTERP_INSTR_END;

  FD_VM_INTERP_INSTR_BEGIN(0x14depr) { /* FD_SBPF_OP_SUB_IMM deprecated SIMD-0174 */
    ulong dst = FD_VM_DST;
    reg[ dst ] = (ulong)(long)( (int)reg[ dst ] - (int)FD_VM_IMM );
  } FD_VM_INTERP_INSTR_END;

  FD_VM_INTERP_BRANCH_BEGIN(0x15) /* FD_SBPF_OP_JEQ_IMM */
    pc += fd_ulong_if( reg[ FD_VM_DST ]==FD_VM_SIMM, FD_VM_OFFSET, 0UL );
  FD_VM_INTERP_BRANCH_END;

  FD_VM_INTERP_INSTR_BEGIN(0x17) { /* FD_SBPF_OP_SUB64_IMM */
    ulong dst = FD_VM_DST;
    reg[ dst ] = FD_VM_SIMM - reg[ dst ];
  } FD_VM_INTERP_INSTR_END;

  FD_VM_INTERP_INSTR_BEGIN(0x17depr) /* FD_SBPF_OP_SUB64_IMM deprecated SIMD-0174 */
    reg[ FD_VM_DST ] -= FD_VM_SIMM;
  FD_VM_INTERP_INSTR_END;

  FD_VM_INTERP_INSTR_BEGIN(0x18) { /* FD_SBPF_OP_LDQ */
    ulong dst = FD_VM_DST;
    ulong lo  = (ulong)FD_VM_IMM;
    pc++;
    FD_VM_INTERP_LDQ_EXTRA;
    reg[ dst ] = lo | (text[ pc ] & 0xFFFFFFFF00000000UL);
  } FD_VM_INTERP_INSTR_END;

  FD_VM_INTERP_INSTR_BEGIN(0x1c) { /* FD_SBPF_OP_SUB_REG */
    ulong dst = FD_VM_DST;
    reg[ dst ] = (ulong)(uint)( (int)reg[ dst ] - (int)reg[ FD_VM_SRC ] );
  } FD_VM_INTERP_INSTR_END;

  FD_VM_INTERP_INSTR_BEGIN(0x1cdepr) { /* FD_SBPF_OP_SUB_REG deprecated SIMD-0174 */
    ulong dst = FD_VM_DST;
    reg[ dst ] = (ulong)(long)( (int)reg[ dst ] - (int)reg[ FD_VM_SRC ] );
  } FD_VM_INTERP_INSTR_END;

  FD_VM_INTERP_BRANCH_BEGIN(0x1d) /* FD_SBPF_OP_JEQ_REG */
    pc += fd_ulong_if( reg[ FD_VM_DST ]==reg[ FD_VM_SRC ], FD_VM_OFFSET, 0UL );
  FD_VM_INTERP_BRANCH_END;

  FD_VM_INTERP_INSTR_BEGIN(0x1f) /* FD_SBPF_OP_SUB64_REG */
    reg[ FD_VM_DST ] -= reg[ FD_VM_SRC ];
  FD_VM_INTERP_INSTR_END;

  /* 0x20 - 0x2f ******************************************************/

  FD_VM_INTERP_INSTR_BEGIN(0x24) { /* FD_SBPF_OP_MUL_IMM */
    ulong dst = FD_VM_DST;
    reg[ dst ] = (ulong)(long)( (int)reg[ dst ] * (int)FD_VM_IMM );
  } FD_VM_INTERP_INSTR_END;

  FD_VM_INTERP_BRANCH_BEGIN(0x25) /* FD_SBPF_OP_JGT_IMM */
    pc += fd_ulong_if( reg[ FD_VM_DST ]>FD_VM_SIMM, FD_VM_OFFSET, 0UL );
  FD_VM_INTERP_BRANCH_END;

  FD_VM_INTERP_ST_IMM( 0x27, sizeof(uchar), fd_vm_mem_st_1, (uchar)FD_VM_IMM );  /* FD_SBPF_OP_STB  */
  FD_VM_INTERP_LD    ( 0x2c, sizeof(uchar), fd_vm_mem_ld_1 );                    /* FD_SBPF_OP_LDXB */

  FD_VM_INTERP_BRANCH_BEGIN(0x2d) /* FD_SBPF_OP_JGT_REG */
    pc += fd_ulong_if( reg[ FD_VM_DST ]>reg[ FD_VM_SRC ], FD_VM_OFFSET, 0UL );
  FD_VM_INTERP_BRANCH_END;

  FD_VM_INTERP_ST_REG( 0x2f, sizeof(uchar), fd_vm_mem_st_1, uchar );             /* FD_SBPF_OP_STXB */

  FD_VM_INTERP_INSTR_BEGIN(0x27depr) { /* FD_SBPF_OP_MUL64_IMM */
    ulong dst = FD_VM_DST;
    reg[ dst ] = (ulong)( (long)reg[ dst ] * (long)FD_VM_SIMM );
  } FD_VM_INTERP_INSTR_END;

  FD_VM_INTERP_INSTR_BEGIN(0x2cdepr) { /* FD_SBPF_OP_MUL_REG */
    ulong dst = FD_VM_DST;
    reg[ dst ] = (ulong)(long)( (int)reg[ dst ] * (int)reg[ FD_VM_SRC ] );
  } FD_VM_INTERP_INSTR_END;

  FD_VM_INTERP_INSTR_BEGIN(0x2fdepr) /* FD_SBPF_OP_MUL64_REG */
    reg[ FD_VM_DST ] *= reg[ FD_VM_SRC ];
  FD_VM_INTERP_INSTR_END;

  /* 0x30 - 0x3f ******************************************************/

  FD_VM_INTERP_INSTR_BEGIN(0x34) { /* FD_SBPF_OP_DIV_IMM */
    ulong dst = FD_VM_DST;
    reg[ dst ] = (ulong)((uint)reg[ dst ] / FD_VM_IMM);
  } FD_VM_INTERP_INSTR_END;

  FD_VM_INTERP_BRANCH_BEGIN(0x35) /* FD_SBPF_OP_JGE_IMM */
    pc += fd_ulong_if( reg[ FD_VM_DST ]>=FD_VM_SIMM, FD_VM_OFFSET, 0UL );
  FD_VM_INTERP_BRANCH_END;

  FD_VM_INTERP_INSTR_BEGIN(0x36) { /* FD_SBPF_OP_UHMUL64_IMM */
    ulong dst = FD_VM_DST;
    reg[ dst ] = (ulong)(( (uint128)reg[ dst ] * (uint128)(ulong)FD_VM_IMM ) >> 64 );
  } FD_VM_INTERP_INSTR_END;

  FD_VM_INTERP_ST_IMM( 0x37, sizeof(ushort), fd_vm_mem_st_2, (ushort)FD_VM_IMM ); /* FD_SBPF_OP_STH  */
  FD_VM_INTERP_LD    ( 0x3c, sizeof(ushort), fd_vm_mem_ld_2 );                    /* FD_SBPF_OP_LDXH */

  FD_VM_INTERP_BRANCH_BEGIN(0x3d) /* FD_SBPF_OP_JGE_REG */
    pc += fd_ulong_if( reg[ FD_VM_DST ]>=reg[ FD_VM_SRC ], FD_VM_OFFSET, 0UL );
  FD_VM_INTERP_BRANCH_END;

  FD_VM_INTERP_ST_REG( 0x3f, sizeof(ushort), fd_vm_mem_st_2, ushort );            /* FD_SBPF_OP_STXH */

  FD_VM_INTERP_INSTR_BEGIN(0x3e) { /* FD_SBPF_OP_UHMUL64_REG */
    ulong dst = FD_VM_DST;
    reg[ dst ] = (ulong)(( (uint128)reg[ dst ] * (uint128)reg[ FD_VM_SRC ] ) >> 64 );
  } FD_VM_INTERP_INSTR_END;

  FD_VM_INTERP_INSTR_BEGIN(0x37depr) { /* FD_SBPF_OP_DIV64_IMM */
    ulong dst = FD_VM_DST;
    reg[ dst ] = reg[ dst ] / FD_VM_SIMM;
  } FD_VM_INTERP_INSTR_END;

  FD_VM_INTERP_INSTR_BEGIN(0x3cdepr) { /* FD_SBPF_OP_DIV_REG */
    uint rsrc = (uint)reg[ FD_VM_SRC ];
    if( FD_UNLIKELY( !rsrc ) ) goto sigfpe;
    ulong dst = FD_VM_DST;
    reg[ dst ] = (ulong)((uint)reg[ dst ] / rsrc);
  } FD_VM_INTERP_INSTR_END;

  FD_VM_INTERP_INSTR_BEGIN(0x3fdepr) { /* FD_SBPF_OP_DIV64_REG */
    ulong rsrc = reg[ FD_VM_SRC ];
    if( FD_UNLIKELY( !rsrc ) ) goto sigfpe;
    reg[ FD_VM_DST ] /= rsrc;
  } FD_VM_INTERP_INSTR_END;

  /* 0x40 - 0x4f ******************************************************/

  FD_VM_INTERP_INSTR_BEGIN(0x44) { /* FD_SBPF_OP_OR_IMM */
    ulong dst = FD_VM_DST;
    reg[ dst ] = (ulong)( (uint)reg[ dst ] | FD_VM_IMM );
  } FD_VM_INTERP_INSTR_END;

  FD_VM_INTERP_BRANCH_BEGIN(0x45) /* FD_SBPF_OP_JSET_IMM */
    pc += fd_ulong_if( !!(reg[ FD_VM_DST ] & FD_VM_SIMM), FD_VM_OFFSET, 0UL );
  FD_VM_INTERP_BRANCH_END;

  FD_VM_INTERP_INSTR_BEGIN(0x46) { /* FD_SBPF_OP_UDIV32_IMM */
    ulong dst = FD_VM_DST;
    reg[ dst ] = (ulong)( (uint)reg[ dst ] / FD_VM_IMM );
  } FD_VM_INTERP_INSTR_END;

  FD_VM_INTERP_INSTR_BEGIN(0x47) /* FD_SBPF_OP_OR64_IMM */
    reg[ FD_VM_DST ] |= FD_VM_SIMM;
  FD_VM_INTERP_INSTR_END;

  FD_VM_INTERP_INSTR_BEGIN(0x4c) { /* FD_SBPF_OP_OR_REG */
    ulong dst = FD_VM_DST;
    reg[ dst ] = (ulong)(uint)( reg[ dst ] | reg[ FD_VM_SRC ] );
  } FD_VM_INTERP_INSTR_END;

  FD_VM_INTERP_BRANCH_BEGIN(0x4d) /* FD_SBPF_OP_JSET_REG */
    pc += fd_ulong_if( !!(reg[ FD_VM_DST ] & reg[ FD_VM_SRC ]), FD_VM_OFFSET, 0UL );
  FD_VM_INTERP_BRANCH_END;

  FD_VM_INTERP_INSTR_BEGIN(0x4e) { /* FD_SBPF_OP_UDIV32_REG */
    uint rsrc = (uint)reg[ FD_VM_SRC ];
    if( FD_UNLIKELY( !rsrc ) ) goto sigfpe;
    ulong dst = FD_VM_DST;
    reg[ dst ] = (ulong)( (uint)reg[ dst ] / rsrc );
  } FD_VM_INTERP_INSTR_END;

  FD_VM_INTERP_INSTR_BEGIN(0x4f) /* FD_SBPF_OP_OR64_REG */
    reg[ FD_VM_DST ] |= reg[ FD_VM_SRC ];
  FD_VM_INTERP_INSTR_END;

  /* 0x50 - 0x5f ******************************************************/

  FD_VM_INTERP_INSTR_BEGIN(0x54) { /* FD_SBPF_OP_AND_IMM */
    ulong dst = FD_VM_DST;
    reg[ dst ] = (ulong)( (uint)reg[ dst ] & FD_VM_IMM );
  } FD_VM_INTERP_INSTR_END;

  FD_VM_INTERP_BRANCH_BEGIN(0x55) /* FD_SBPF_OP_JNE_IMM */
    pc += fd_ulong_if( reg[ FD_VM_DST ]!=FD_VM_SIMM, FD_VM_OFFSET, 0UL );
  FD_VM_INTERP_BRANCH_END;

  FD_VM_INTERP_INSTR_BEGIN(0x56) { /* FD_SBPF_OP_UDIV64_IMM */
    ulong dst = FD_VM_DST;
    reg[ dst ] = reg[ dst ] / (ulong)FD_VM_IMM;
  } FD_VM_INTERP_INSTR_END;

  FD_VM_INTERP_INSTR_BEGIN(0x57) /* FD_SBPF_OP_AND64_IMM */
    reg[ FD_VM_DST ] &= FD_VM_SIMM;
  FD_VM_INTERP_INSTR_END;

  FD_VM_INTERP_INSTR_BEGIN(0x5c) { /* FD_SBPF_OP_AND_REG */
    ulong dst = FD_VM_DST;
    reg[ dst ] = (ulong)(uint)( reg[ dst ] & reg[ FD_VM_SRC ] );
  } FD_VM_INTERP_INSTR_END;

  FD_VM_INTERP_BRANCH_BEGIN(0x5d) /* FD_SBPF_OP_JNE_REG */
    pc += fd_ulong_if( reg[ FD_VM_DST ]!=reg[ FD_VM_SRC ], FD_VM_OFFSET, 0UL );
  FD_VM_INTERP_BRANCH_END;

  FD_VM_INTERP_INSTR_BEGIN(0x5e) { /* FD_SBPF_OP_UDIV64_REG */
    ulong rsrc = reg[ FD_VM_SRC ];
    if( FD_UNLIKELY( !rsrc ) ) goto sigfpe;
    reg[ FD_VM_DST ] /= rsrc;
  } FD_VM_INTERP_INSTR_END;

  FD_VM_INTERP_INSTR_BEGIN(0x5f) /* FD_SBPF_OP_AND64_REG */
    reg[ FD_VM_DST ] &= reg[ FD_VM_SRC ];
  FD_VM_INTERP_INSTR_END;

  /* 0x60 - 0x6f ******************************************************/

  FD_VM_INTERP_INSTR_BEGIN(0x64) { /* FD_SBPF_OP_LSH_IMM */
    ulong dst = FD_VM_DST;
    reg[ dst ] = (ulong)( FD_RUST_UINT_WRAPPING_SHL( (uint)reg[ dst ], FD_VM_IMM ) );
  } FD_VM_INTERP_INSTR_END;

  FD_VM_INTERP_BRANCH_BEGIN(0x65) /* FD_SBPF_OP_JSGT_IMM */
    pc += fd_ulong_if( (long)reg[ FD_VM_DST ]>(long)FD_VM_SIMM, FD_VM_OFFSET, 0UL );
  FD_VM_INTERP_BRANCH_END;

  FD_VM_INTERP_INSTR_BEGIN(0x66) { /* FD_SBPF_OP_UREM32_IMM */
    ulong dst = FD_VM_DST;
    reg[ dst ] = (ulong)( (uint)reg[ dst ] % FD_VM_IMM );
  } FD_VM_INTERP_INSTR_END;

  FD_VM_INTERP_INSTR_BEGIN(0x67) { /* FD_SBPF_OP_LSH64_IMM */
    ulong dst = FD_VM_DST;
    reg[ dst ] = FD_RUST_ULONG_WRAPPING_SHL( reg[ dst ], FD_VM_IMM );
  } FD_VM_INTERP_INSTR_END;

  FD_VM_INTERP_INSTR_BEGIN(0x6c) { /* FD_SBPF_OP_LSH_REG */
    ulong dst = FD_VM_DST;
    reg[ dst ] = (ulong)( FD_RUST_UINT_WRAPPING_SHL( (uint)reg[ dst ], reg[ FD_VM_SRC ] ) );
  } FD_VM_INTERP_INSTR_END;

  FD_VM_INTERP_BRANCH_BEGIN(0x6d) /* FD_SBPF_OP_JSGT_REG */
    pc += fd_ulong_if( (long)reg[ FD_VM_DST ]>(long)reg[ FD_VM_SRC ], FD_VM_OFFSET, 0UL );
  FD_VM_INTERP_BRANCH_END;

  FD_VM_INTERP_INSTR_BEGIN(0x6e) { /* FD_SBPF_OP_UREM32_REG */
    uint rsrc = (uint)reg[ FD_VM_SRC ];
    if( FD_UNLIKELY( !rsrc ) ) goto sigfpe;
    ulong dst = FD_VM_DST;
    reg[ dst ] = (ulong)( (uint)reg[ dst ] % rsrc );
  } FD_VM_INTERP_INSTR_END;

  FD_VM_INTERP_INSTR_BEGIN(0x6f) { /* FD_SBPF_OP_LSH64_REG */
    ulong dst = FD_VM_DST;
    reg[ dst ] = FD_RUST_ULONG_WRAPPING_SHL( reg[ dst ], reg[ FD_VM_SRC ] );
  } FD_VM_INTERP_INSTR_END;

  /* 0x70 - 0x7f ******************************************************/

  FD_VM_INTERP_INSTR_BEGIN(0x74) { /* FD_SBPF_OP_RSH_IMM */
    ulong dst = FD_VM_DST;
    reg[ dst ] = (ulong)( FD_RUST_UINT_WRAPPING_SHR( (uint)reg[ dst ], FD_VM_IMM ) );
  } FD_VM_INTERP_INSTR_END;

  FD_VM_INTERP_BRANCH_BEGIN(0x75) /* FD_SBPF_OP_JSGE_IMM */
    pc += fd_ulong_if( (long)reg[ FD_VM_DST ]>=(long)FD_VM_SIMM, FD_VM_OFFSET, 0UL );
  FD_VM_INTERP_BRANCH_END;

  FD_VM_INTERP_INSTR_BEGIN(0x76) { /* FD_SBPF_OP_UREM64_IMM */
    ulong dst = FD_VM_DST;
    reg[ dst ] = reg[ dst ] % (ulong)FD_VM_IMM;
  } FD_VM_INTERP_INSTR_END;

  FD_VM_INTERP_INSTR_BEGIN(0x77) { /* FD_SBPF_OP_RSH64_IMM */
    ulong dst = FD_VM_DST;
    reg[ dst ] = FD_RUST_ULONG_WRAPPING_SHR( reg[ dst ], FD_VM_IMM );
  } FD_VM_INTERP_INSTR_END;

  FD_VM_INTERP_INSTR_BEGIN(0x7c) { /* FD_SBPF_OP_RSH_REG */
    ulong dst = FD_VM_DST;
    reg[ dst ] = (ulong)( FD_RUST_UINT_WRAPPING_SHR( (uint)reg[ dst ], (uint)reg[ FD_VM_SRC ] ) );
  } FD_VM_INTERP_INSTR_END;

  FD_VM_INTERP_BRANCH_BEGIN(0x7d) /* FD_SBPF_OP_JSGE_REG */
    pc += fd_ulong_if( (long)reg[ FD_VM_DST ]>=(long)reg[ FD_VM_SRC ], FD_VM_OFFSET, 0UL );
  FD_VM_INTERP_BRANCH_END;

  FD_VM_INTERP_INSTR_BEGIN(0x7e) { /* FD_SBPF_OP_UREM64_REG */
    ulong rsrc = reg[ FD_VM_SRC ];
    if( FD_UNLIKELY( !rsrc ) ) goto sigfpe;
    reg[ FD_VM_DST ] %= rsrc;
  } FD_VM_INTERP_INSTR_END;

  FD_VM_INTERP_INSTR_BEGIN(0x7f) { /* FD_SBPF_OP_RSH64_REG */
    ulong dst = FD_VM_DST;
    reg[ dst ] = FD_RUST_ULONG_WRAPPING_SHR( reg[ dst ], reg[ FD_VM_SRC ] );
  } FD_VM_INTERP_INSTR_END;

  /* 0x80-0x8f ********************************************************/

  FD_VM_INTERP_INSTR_BEGIN(0x84) { /* FD_SBPF_OP_NEG */
    ulong dst = FD_VM_DST;
    reg[ dst ] = (ulong)( -(uint)reg[ dst ] );
  } FD_VM_INTERP_INSTR_END;

  FD_VM_INTERP_BRANCH_BEGIN(0x85) { /* FD_SBPF_OP_CALL_IMM */
    uint imm = FD_VM_IMM;
    /* Note: imm is uint so (ulong)imm <= UINT_MAX < fd_sbpf_syscalls_key_null() (ULONG_MAX). */
    fd_sbpf_syscalls_t const * syscall = fd_sbpf_syscalls_query_const( vm->syscalls, (ulong)imm, NULL );
    if( !syscall ) { /* ~85% of CALL_IMM on mainnet are internal BPF-to-BPF calls */
      ulong target_pc;
      if( FD_UNLIKELY( imm==0x71e3cf81U ) ) {
        target_pc = vm->entry_pc;
      } else {
        target_pc = (ulong)fd_pchash_inverse( imm );
        if( FD_UNLIKELY( target_pc>=text_cnt || !fd_sbpf_calldests_test( vm->calldests, target_pc ) ) ) {
          goto sigillbr;
        }
      }
      FD_VM_INTERP_STACK_PUSH;
      pc = target_pc - 1UL;
    } else {
      FD_VM_INTERP_SYSCALL_EXEC;
    }
  } FD_VM_INTERP_BRANCH_END;

  /* SIMD-0178: Static syscalls (SBPF V3+)
     https://github.com/anza-xyz/sbpf/blob/v0.14.4/src/interpreter.rs#L542-L577 */
  FD_VM_INTERP_BRANCH_BEGIN(0x85_static) { /* FD_SBPF_OP_CALL_IMM (static syscalls) */
    ulong src = FD_VM_SRC;
    uint  imm = FD_VM_IMM;
    if( src == 1UL ) {
      /* Internal call */
      long target_pc_l = fd_long_sat_add( (long)pc, fd_long_sat_add( (long)(int)imm, 1L ) );
      if( FD_UNLIKELY( target_pc_l<0L || (ulong)target_pc_l>=text_cnt ) ) goto sigillbr;
      FD_VM_INTERP_STACK_PUSH;
      pc = (ulong)target_pc_l - 1UL;
    } else if( src == 0UL ) {
      /* External syscall */
      fd_sbpf_syscalls_t const * syscall = fd_sbpf_syscalls_query_const( vm->syscalls, (ulong)imm, NULL );
      if( FD_UNLIKELY( !syscall ) ) goto sigillbr;
      FD_VM_INTERP_SYSCALL_EXEC;
    } else {
      goto sigillbr;
    }
  } FD_VM_INTERP_BRANCH_END;

  FD_VM_INTERP_INSTR_BEGIN(0x86) { /* FD_SBPF_OP_LMUL32_IMM */
    ulong dst = FD_VM_DST;
    reg[ dst ] = (ulong)( (uint)reg[ dst ] * FD_VM_IMM );
  } FD_VM_INTERP_INSTR_END;

  FD_VM_INTERP_ST_IMM( 0x87, sizeof(uint), fd_vm_mem_st_4, FD_VM_IMM );           /* FD_SBPF_OP_STW  */

  FD_VM_INTERP_INSTR_BEGIN(0x87depr) { /* FD_SBPF_OP_NEG64 deprecated */
    ulong dst = FD_VM_DST;
    reg[ dst ] = -reg[ dst ];
  } FD_VM_INTERP_INSTR_END;

  FD_VM_INTERP_LD    ( 0x8c, sizeof(uint), fd_vm_mem_ld_4 );                      /* FD_SBPF_OP_LDXW */

  FD_VM_INTERP_BRANCH_BEGIN(0x8d) { /* FD_SBPF_OP_CALL_REG */
    ulong rsrc = reg[ FD_VM_SRC ];
    FD_VM_INTERP_STACK_PUSH;

    ulong sbpf_ver = vm->sbpf_version;
    ulong vaddr = fd_sbpf_callx_uses_src_reg_enabled( sbpf_ver ) ? rsrc
                : fd_sbpf_callx_uses_dst_reg_enabled( sbpf_ver ) ? reg[ FD_VM_DST ]
                : reg[ FD_VM_IMM & 15U ];

    ulong region    = vaddr >> 32;
    ulong target_pc = ((vaddr & FD_VM_OFFSET_MASK) - vm->text_off) / 8UL;
    if( FD_UNLIKELY( (region!=1UL) | (target_pc>=text_cnt) ) ) goto sigtextbr;
    pc = target_pc - 1UL;
  } FD_VM_INTERP_BRANCH_END;

  FD_VM_INTERP_INSTR_BEGIN(0x8e) { /* FD_SBPF_OP_LMUL32_REG */
    ulong dst = FD_VM_DST;
    reg[ dst ] = (ulong)( (uint)reg[ dst ] * (uint)reg[ FD_VM_SRC ] );
  } FD_VM_INTERP_INSTR_END;

  FD_VM_INTERP_ST_REG( 0x8f, sizeof(uint), fd_vm_mem_st_4, uint );                /* FD_SBPF_OP_STXW */

  /* 0x90 - 0x9f ******************************************************/

  FD_VM_INTERP_INSTR_BEGIN(0x94) { /* FD_SBPF_OP_MOD_IMM */
    ulong dst = FD_VM_DST;
    reg[ dst ] = (ulong)( (uint)reg[ dst ] % FD_VM_IMM );
  } FD_VM_INTERP_INSTR_END;

  FD_VM_INTERP_BRANCH_BEGIN(0x95) { /* FD_SBPF_OP_EXIT */
    ulong _fc = vm->frame_cnt;
    if( FD_UNLIKELY( !_fc ) ) goto sigexit; /* Exit program */
    _fc--;
    vm->frame_cnt = _fc;
    fd_vm_shadow_t const * sh = &vm->shadow[ _fc ];
    reg[6]  = sh->r6;
    reg[7]  = sh->r7;
    reg[8]  = sh->r8;
    reg[9]  = sh->r9;
    reg[10] = sh->r10;
    pc      = sh->pc;
  } FD_VM_INTERP_BRANCH_END;

  FD_VM_INTERP_INSTR_BEGIN(0x96) /* FD_SBPF_OP_LMUL64_IMM */
    reg[ FD_VM_DST ] *= FD_VM_SIMM;
  FD_VM_INTERP_INSTR_END;

  FD_VM_INTERP_ST_IMM( 0x97, sizeof(ulong), fd_vm_mem_st_8, FD_VM_SIMM );         /* FD_SBPF_OP_STQ  */
  FD_VM_INTERP_LD    ( 0x9c, sizeof(ulong), fd_vm_mem_ld_8 );                     /* FD_SBPF_OP_LDXQ */

  FD_VM_INTERP_INSTR_BEGIN(0x9e) /* FD_SBPF_OP_LMUL64_REG */
    reg[ FD_VM_DST ] *= reg[ FD_VM_SRC ];
  FD_VM_INTERP_INSTR_END;

  FD_VM_INTERP_ST_REG( 0x9f, sizeof(ulong), fd_vm_mem_st_8, ulong );              /* FD_SBPF_OP_STXQ */

  FD_VM_INTERP_INSTR_BEGIN(0x97depr) { /* FD_SBPF_OP_MOD64_IMM */
    ulong dst = FD_VM_DST;
    reg[ dst ] = reg[ dst ] % FD_VM_SIMM;
  } FD_VM_INTERP_INSTR_END;

  FD_VM_INTERP_INSTR_BEGIN(0x9cdepr) { /* FD_SBPF_OP_MOD_REG */
    uint rsrc = (uint)reg[ FD_VM_SRC ];
    if( FD_UNLIKELY( !rsrc ) ) goto sigfpe;
    ulong dst = FD_VM_DST;
    reg[ dst ] = (ulong)( (uint)reg[ dst ] % rsrc );
  } FD_VM_INTERP_INSTR_END;

  FD_VM_INTERP_INSTR_BEGIN(0x9fdepr) { /* FD_SBPF_OP_MOD64_REG */
    ulong rsrc = reg[ FD_VM_SRC ];
    if( FD_UNLIKELY( !rsrc ) ) goto sigfpe;
    reg[ FD_VM_DST ] %= rsrc;
  } FD_VM_INTERP_INSTR_END;

  /* 0xa0 - 0xaf ******************************************************/

  FD_VM_INTERP_INSTR_BEGIN(0xa4) { /* FD_SBPF_OP_XOR_IMM */
    ulong dst = FD_VM_DST;
    reg[ dst ] = (ulong)( (uint)reg[ dst ] ^ FD_VM_IMM );
  } FD_VM_INTERP_INSTR_END;

  FD_VM_INTERP_BRANCH_BEGIN(0xa5) /* FD_SBPF_OP_JLT_IMM */
    pc += fd_ulong_if( reg[ FD_VM_DST ]<FD_VM_SIMM, FD_VM_OFFSET, 0UL );
  FD_VM_INTERP_BRANCH_END;

  FD_VM_INTERP_INSTR_BEGIN(0xa7) /* FD_SBPF_OP_XOR64_IMM */
    reg[ FD_VM_DST ] ^= FD_VM_SIMM;
  FD_VM_INTERP_INSTR_END;

  FD_VM_INTERP_INSTR_BEGIN(0xac) { /* FD_SBPF_OP_XOR_REG */
    ulong dst = FD_VM_DST;
    reg[ dst ] = (ulong)(uint)( reg[ dst ] ^ reg[ FD_VM_SRC ] );
  } FD_VM_INTERP_INSTR_END;

  FD_VM_INTERP_BRANCH_BEGIN(0xad) /* FD_SBPF_OP_JLT_REG */
    pc += fd_ulong_if( reg[ FD_VM_DST ]<reg[ FD_VM_SRC ], FD_VM_OFFSET, 0UL );
  FD_VM_INTERP_BRANCH_END;

  FD_VM_INTERP_INSTR_BEGIN(0xaf) /* FD_SBPF_OP_XOR64_REG */
    reg[ FD_VM_DST ] ^= reg[ FD_VM_SRC ];
  FD_VM_INTERP_INSTR_END;

  /* 0xb0 - 0xbf ******************************************************/

  FD_VM_INTERP_INSTR_BEGIN(0xb4) /* FD_SBPF_OP_MOV_IMM */
    reg[ FD_VM_DST ] = (ulong)FD_VM_IMM;
  FD_VM_INTERP_INSTR_END;

  FD_VM_INTERP_BRANCH_BEGIN(0xb5) /* FD_SBPF_OP_JLE_IMM */
    pc += fd_ulong_if( reg[ FD_VM_DST ]<=FD_VM_SIMM, FD_VM_OFFSET, 0UL );
  FD_VM_INTERP_BRANCH_END;

  FD_VM_INTERP_INSTR_BEGIN(0xb6) { /* FD_SBPF_OP_SHMUL64_IMM */
    ulong dst = FD_VM_DST;
    reg[ dst ] = (ulong)(( (int128)(long)reg[ dst ] * (int128)(long)FD_VM_SIMM ) >> 64 );
  } FD_VM_INTERP_INSTR_END;

  FD_VM_INTERP_INSTR_BEGIN(0xb7) /* FD_SBPF_OP_MOV64_IMM */
    reg[ FD_VM_DST ] = FD_VM_SIMM;
  FD_VM_INTERP_INSTR_END;

  FD_VM_INTERP_INSTR_BEGIN(0xbc) /* FD_SBPF_OP_MOV_REG */
    reg[ FD_VM_DST ] = (ulong)(long)(int)reg[ FD_VM_SRC ];
  FD_VM_INTERP_INSTR_END;

  FD_VM_INTERP_INSTR_BEGIN(0xbcdepr) /* FD_SBPF_OP_MOV_REG deprecated SIMD-0174 */
    reg[ FD_VM_DST ] = (ulong)(uint)reg[ FD_VM_SRC ];
  FD_VM_INTERP_INSTR_END;

  FD_VM_INTERP_BRANCH_BEGIN(0xbd) /* FD_SBPF_OP_JLE_REG */
    pc += fd_ulong_if( reg[ FD_VM_DST ]<=reg[ FD_VM_SRC ], FD_VM_OFFSET, 0UL );
  FD_VM_INTERP_BRANCH_END;

  FD_VM_INTERP_INSTR_BEGIN(0xbe) { /* FD_SBPF_OP_SHMUL64_REG */
    ulong dst = FD_VM_DST;
    reg[ dst ] = (ulong)(( (int128)(long)reg[ dst ] * (int128)(long)reg[ FD_VM_SRC ] ) >> 64 );
  } FD_VM_INTERP_INSTR_END;

  FD_VM_INTERP_INSTR_BEGIN(0xbf) /* FD_SBPF_OP_MOV64_REG */
    reg[ FD_VM_DST ] = reg[ FD_VM_SRC ];
  FD_VM_INTERP_INSTR_END;

  /* 0xc0 - 0xcf ******************************************************/

  FD_VM_INTERP_INSTR_BEGIN(0xc4) { /* FD_SBPF_OP_ARSH_IMM */
    ulong dst = FD_VM_DST;
    reg[ dst ] = (ulong)(uint)( FD_RUST_INT_WRAPPING_SHR( (int)reg[ dst ], FD_VM_IMM ) );
  } FD_VM_INTERP_INSTR_END;

  FD_VM_INTERP_BRANCH_BEGIN(0xc5) /* FD_SBPF_OP_JSLT_IMM */
    pc += fd_ulong_if( (long)reg[ FD_VM_DST ]<(long)FD_VM_SIMM, FD_VM_OFFSET, 0UL );
  FD_VM_INTERP_BRANCH_END;

  FD_VM_INTERP_INSTR_BEGIN(0xc6) { /* FD_SBPF_OP_SDIV32_IMM */
    ulong dst  = FD_VM_DST;
    int   rdst = (int)reg[ dst ];
    int   simm = (int)FD_VM_IMM;
    if( FD_UNLIKELY( (rdst==INT_MIN) & (simm==-1) ) ) goto sigfpeof;
    reg[ dst ] = (ulong)(uint)( rdst / simm );
  } FD_VM_INTERP_INSTR_END;

  FD_VM_INTERP_INSTR_BEGIN(0xc7) { /* FD_SBPF_OP_ARSH64_IMM */
    ulong dst = FD_VM_DST;
    reg[ dst ] = (ulong)( FD_RUST_LONG_WRAPPING_SHR( (long)reg[ dst ], FD_VM_IMM ) );
  } FD_VM_INTERP_INSTR_END;

  FD_VM_INTERP_INSTR_BEGIN(0xcc) { /* FD_SBPF_OP_ARSH_REG */
    ulong dst = FD_VM_DST;
    reg[ dst ] = (ulong)(uint)( FD_RUST_INT_WRAPPING_SHR( (int)reg[ dst ], (uint)reg[ FD_VM_SRC ] ) );
  } FD_VM_INTERP_INSTR_END;

  FD_VM_INTERP_BRANCH_BEGIN(0xcd) /* FD_SBPF_OP_JSLT_REG */
    pc += fd_ulong_if( (long)reg[ FD_VM_DST ]<(long)reg[ FD_VM_SRC ], FD_VM_OFFSET, 0UL );
  FD_VM_INTERP_BRANCH_END;

  FD_VM_INTERP_INSTR_BEGIN(0xce) { /* FD_SBPF_OP_SDIV32_REG */
    int rsrc = (int)reg[ FD_VM_SRC ];
    if( FD_UNLIKELY( !rsrc ) ) goto sigfpe;
    ulong dst  = FD_VM_DST;
    int   rdst = (int)reg[ dst ];
    if( FD_UNLIKELY( (rdst==INT_MIN) & (rsrc==-1) ) ) goto sigfpeof;
    reg[ dst ] = (ulong)(uint)( rdst / rsrc );
  } FD_VM_INTERP_INSTR_END;

  FD_VM_INTERP_INSTR_BEGIN(0xcf) { /* FD_SBPF_OP_ARSH64_REG */
    ulong dst = FD_VM_DST;
    reg[ dst ] = (ulong)( FD_RUST_LONG_WRAPPING_SHR( (long)reg[ dst ], reg[ FD_VM_SRC ] ) );
  } FD_VM_INTERP_INSTR_END;

  /* 0xd0 - 0xdf ******************************************************/

  FD_VM_INTERP_INSTR_BEGIN(0xd4) { /* FD_SBPF_OP_END_LE */
    ulong dst = FD_VM_DST;
    switch( FD_VM_IMM ) {
    case 16U: reg[ dst ] = (ushort)reg[ dst ]; break;
    case 32U: reg[ dst ] = (uint)  reg[ dst ]; break;
    case 64U:                                  break;
    default: goto siginv;
    }
  } FD_VM_INTERP_INSTR_END;

  FD_VM_INTERP_BRANCH_BEGIN(0xd5) /* FD_SBPF_OP_JSLE_IMM */
    pc += fd_ulong_if( (long)reg[ FD_VM_DST ]<=(long)FD_VM_SIMM, FD_VM_OFFSET, 0UL );
  FD_VM_INTERP_BRANCH_END;

  FD_VM_INTERP_INSTR_BEGIN(0xd6) { /* FD_SBPF_OP_SDIV64_IMM */
    ulong dst  = FD_VM_DST;
    long  rdst = (long)reg[ dst ];
    long  simm = (long)FD_VM_SIMM;
    if( FD_UNLIKELY( (rdst==LONG_MIN) & (simm==-1L) ) ) goto sigfpeof;
    reg[ dst ] = (ulong)( rdst / simm );
  } FD_VM_INTERP_INSTR_END;

  FD_VM_INTERP_INSTR_BEGIN(0xdc) { /* FD_SBPF_OP_END_BE */
    ulong dst  = FD_VM_DST;
    ulong rdst = reg[ dst ];
    switch( FD_VM_IMM ) {
    case 16U: reg[ dst ] = (ulong)fd_ushort_bswap( (ushort)rdst ); break;
    case 32U: reg[ dst ] = (ulong)fd_uint_bswap  ( (uint)  rdst ); break;
    case 64U: reg[ dst ] =        fd_ulong_bswap ( (ulong) rdst ); break;
    default: goto siginv;
    }
  } FD_VM_INTERP_INSTR_END;

  FD_VM_INTERP_BRANCH_BEGIN(0xdd) /* FD_SBPF_OP_JSLE_REG */
    pc += fd_ulong_if( (long)reg[ FD_VM_DST ]<=(long)reg[ FD_VM_SRC ], FD_VM_OFFSET, 0UL );
  FD_VM_INTERP_BRANCH_END;

  FD_VM_INTERP_INSTR_BEGIN(0xde) { /* FD_SBPF_OP_SDIV64_REG */
    long rsrc = (long)reg[ FD_VM_SRC ];
    if( FD_UNLIKELY( !rsrc ) ) goto sigfpe;
    ulong dst  = FD_VM_DST;
    long  rdst = (long)reg[ dst ];
    if( FD_UNLIKELY( (rdst==LONG_MIN) & (rsrc==-1L) ) ) goto sigfpeof;
    reg[ dst ] = (ulong)( rdst / rsrc );
  } FD_VM_INTERP_INSTR_END;

  /* 0xe0 - 0xef ******************************************************/

  FD_VM_INTERP_INSTR_BEGIN(0xe6) { /* FD_SBPF_OP_SREM32_IMM */
    ulong dst  = FD_VM_DST;
    int   rdst = (int)reg[ dst ];
    int   simm = (int)FD_VM_IMM;
    if( FD_UNLIKELY( (rdst==INT_MIN) & (simm==-1) ) ) goto sigfpeof;
    reg[ dst ] = (ulong)(uint)( rdst % simm );
  } FD_VM_INTERP_INSTR_END;

  FD_VM_INTERP_INSTR_BEGIN(0xee) { /* FD_SBPF_OP_SREM32_REG */
    int rsrc = (int)reg[ FD_VM_SRC ];
    if( FD_UNLIKELY( !rsrc ) ) goto sigfpe;
    ulong dst  = FD_VM_DST;
    int   rdst = (int)reg[ dst ];
    if( FD_UNLIKELY( (rdst==INT_MIN) & (rsrc==-1) ) ) goto sigfpeof;
    reg[ dst ] = (ulong)(uint)( rdst % rsrc );
  } FD_VM_INTERP_INSTR_END;

  /* 0xf0 - 0xff ******************************************************/

  FD_VM_INTERP_INSTR_BEGIN(0xf6) { /* FD_SBPF_OP_SREM64_IMM */
    ulong dst  = FD_VM_DST;
    long  rdst = (long)reg[ dst ];
    long  simm = (long)FD_VM_SIMM;
    if( FD_UNLIKELY( (rdst==LONG_MIN) & (simm==-1L) ) ) goto sigfpeof;
    reg[ dst ] = (ulong)( rdst % simm );
  } FD_VM_INTERP_INSTR_END;

  FD_VM_INTERP_INSTR_BEGIN(0xf7) /* FD_SBPF_OP_HOR64 */
    reg[ FD_VM_DST ] |= (instr & 0xFFFFFFFF00000000UL);
  FD_VM_INTERP_INSTR_END;

  FD_VM_INTERP_INSTR_BEGIN(0xfe) { /* FD_SBPF_OP_SREM64_REG */
    long rsrc = (long)reg[ FD_VM_SRC ];
    if( FD_UNLIKELY( !rsrc ) ) goto sigfpe;
    ulong dst  = FD_VM_DST;
    long  rdst = (long)reg[ dst ];
    if( FD_UNLIKELY( (rdst==LONG_MIN) & (rsrc==-1L) ) ) goto sigfpeof;
    reg[ dst ] = (ulong)( rdst % rsrc );
  } FD_VM_INTERP_INSTR_END;

  /* SIMD-0377: JMP32
     https://github.com/anza-xyz/sbpf/blob/v0.14.4/src/interpreter.rs#L480-L501

     0x16 - 0xde ******************************************************/

  FD_VM_INTERP_BRANCH_BEGIN(0x16_jmp32) /* FD_SBPF_OP_JEQ32_IMM */
    pc += fd_ulong_if( (uint)reg[ FD_VM_DST ]==FD_VM_IMM, FD_VM_OFFSET, 0UL );
  FD_VM_INTERP_BRANCH_END;

  FD_VM_INTERP_BRANCH_BEGIN(0x1e_jmp32) /* FD_SBPF_OP_JEQ32_REG */
    pc += fd_ulong_if( (uint)reg[ FD_VM_DST ]==(uint)reg[ FD_VM_SRC ], FD_VM_OFFSET, 0UL );
  FD_VM_INTERP_BRANCH_END;

  FD_VM_INTERP_BRANCH_BEGIN(0x26_jmp32) /* FD_SBPF_OP_JGT32_IMM */
    pc += fd_ulong_if( (uint)reg[ FD_VM_DST ]>FD_VM_IMM, FD_VM_OFFSET, 0UL );
  FD_VM_INTERP_BRANCH_END;

  FD_VM_INTERP_BRANCH_BEGIN(0x2e_jmp32) /* FD_SBPF_OP_JGT32_REG */
    pc += fd_ulong_if( (uint)reg[ FD_VM_DST ]>(uint)reg[ FD_VM_SRC ], FD_VM_OFFSET, 0UL );
  FD_VM_INTERP_BRANCH_END;

  FD_VM_INTERP_BRANCH_BEGIN(0x36_jmp32) /* FD_SBPF_OP_JGE32_IMM */
    pc += fd_ulong_if( (uint)reg[ FD_VM_DST ]>=FD_VM_IMM, FD_VM_OFFSET, 0UL );
  FD_VM_INTERP_BRANCH_END;

  FD_VM_INTERP_BRANCH_BEGIN(0x3e_jmp32) /* FD_SBPF_OP_JGE32_REG */
    pc += fd_ulong_if( (uint)reg[ FD_VM_DST ]>=(uint)reg[ FD_VM_SRC ], FD_VM_OFFSET, 0UL );
  FD_VM_INTERP_BRANCH_END;

  FD_VM_INTERP_BRANCH_BEGIN(0x46_jmp32) /* FD_SBPF_OP_JSET32_IMM */
    pc += fd_ulong_if( !!((uint)reg[ FD_VM_DST ] & FD_VM_IMM), FD_VM_OFFSET, 0UL );
  FD_VM_INTERP_BRANCH_END;

  FD_VM_INTERP_BRANCH_BEGIN(0x4e_jmp32) /* FD_SBPF_OP_JSET32_REG */
    pc += fd_ulong_if( !!((uint)reg[ FD_VM_DST ] & (uint)reg[ FD_VM_SRC ]), FD_VM_OFFSET, 0UL );
  FD_VM_INTERP_BRANCH_END;

  FD_VM_INTERP_BRANCH_BEGIN(0x56_jmp32) /* FD_SBPF_OP_JNE32_IMM */
    pc += fd_ulong_if( (uint)reg[ FD_VM_DST ]!=FD_VM_IMM, FD_VM_OFFSET, 0UL );
  FD_VM_INTERP_BRANCH_END;

  FD_VM_INTERP_BRANCH_BEGIN(0x5e_jmp32) /* FD_SBPF_OP_JNE32_REG */
    pc += fd_ulong_if( (uint)reg[ FD_VM_DST ]!=(uint)reg[ FD_VM_SRC ], FD_VM_OFFSET, 0UL );
  FD_VM_INTERP_BRANCH_END;

  FD_VM_INTERP_BRANCH_BEGIN(0x66_jmp32) /* FD_SBPF_OP_JSGT32_IMM */
    pc += fd_ulong_if( (int)reg[ FD_VM_DST ]>(int)FD_VM_IMM, FD_VM_OFFSET, 0UL );
  FD_VM_INTERP_BRANCH_END;

  FD_VM_INTERP_BRANCH_BEGIN(0x6e_jmp32) /* FD_SBPF_OP_JSGT32_REG */
    pc += fd_ulong_if( (int)reg[ FD_VM_DST ]>(int)reg[ FD_VM_SRC ], FD_VM_OFFSET, 0UL );
  FD_VM_INTERP_BRANCH_END;

  FD_VM_INTERP_BRANCH_BEGIN(0x76_jmp32) /* FD_SBPF_OP_JSGE32_IMM */
    pc += fd_ulong_if( (int)reg[ FD_VM_DST ]>=(int)FD_VM_IMM, FD_VM_OFFSET, 0UL );
  FD_VM_INTERP_BRANCH_END;

  FD_VM_INTERP_BRANCH_BEGIN(0x7e_jmp32) /* FD_SBPF_OP_JSGE32_REG */
    pc += fd_ulong_if( (int)reg[ FD_VM_DST ]>=(int)reg[ FD_VM_SRC ], FD_VM_OFFSET, 0UL );
  FD_VM_INTERP_BRANCH_END;

  FD_VM_INTERP_BRANCH_BEGIN(0xa6_jmp32) /* FD_SBPF_OP_JLT32_IMM */
    pc += fd_ulong_if( (uint)reg[ FD_VM_DST ]<FD_VM_IMM, FD_VM_OFFSET, 0UL );
  FD_VM_INTERP_BRANCH_END;

  FD_VM_INTERP_BRANCH_BEGIN(0xae_jmp32) /* FD_SBPF_OP_JLT32_REG */
    pc += fd_ulong_if( (uint)reg[ FD_VM_DST ]<(uint)reg[ FD_VM_SRC ], FD_VM_OFFSET, 0UL );
  FD_VM_INTERP_BRANCH_END;

  FD_VM_INTERP_BRANCH_BEGIN(0xb6_jmp32) /* FD_SBPF_OP_JLE32_IMM */
    pc += fd_ulong_if( (uint)reg[ FD_VM_DST ]<=FD_VM_IMM, FD_VM_OFFSET, 0UL );
  FD_VM_INTERP_BRANCH_END;

  FD_VM_INTERP_BRANCH_BEGIN(0xbe_jmp32) /* FD_SBPF_OP_JLE32_REG */
    pc += fd_ulong_if( (uint)reg[ FD_VM_DST ]<=(uint)reg[ FD_VM_SRC ], FD_VM_OFFSET, 0UL );
  FD_VM_INTERP_BRANCH_END;

  FD_VM_INTERP_BRANCH_BEGIN(0xc6_jmp32) /* FD_SBPF_OP_JSLT32_IMM */
    pc += fd_ulong_if( (int)reg[ FD_VM_DST ]<(int)FD_VM_IMM, FD_VM_OFFSET, 0UL );
  FD_VM_INTERP_BRANCH_END;

  FD_VM_INTERP_BRANCH_BEGIN(0xce_jmp32) /* FD_SBPF_OP_JSLT32_REG */
    pc += fd_ulong_if( (int)reg[ FD_VM_DST ]<(int)reg[ FD_VM_SRC ], FD_VM_OFFSET, 0UL );
  FD_VM_INTERP_BRANCH_END;

  FD_VM_INTERP_BRANCH_BEGIN(0xd6_jmp32) /* FD_SBPF_OP_JSLE32_IMM */
    pc += fd_ulong_if( (int)reg[ FD_VM_DST ]<=(int)FD_VM_IMM, FD_VM_OFFSET, 0UL );
  FD_VM_INTERP_BRANCH_END;

  FD_VM_INTERP_BRANCH_BEGIN(0xde_jmp32) /* FD_SBPF_OP_JSLE32_REG */
    pc += fd_ulong_if( (int)reg[ FD_VM_DST ]<=(int)reg[ FD_VM_SRC ], FD_VM_OFFSET, 0UL );
  FD_VM_INTERP_BRANCH_END;

sigtext_or_sigcost:
  if( pc<text_cnt ) goto sigcost; else goto sigtext;
sigtext:     err = FD_VM_ERR_EBPF_EXECUTION_OVERRUN;                                     FD_VM_INTERP_FAULT;                    goto interp_halt;
sigtextbr:   err = FD_VM_ERR_EBPF_CALL_OUTSIDE_TEXT_SEGMENT;                             /* ic current */     /* cu current */  goto interp_halt;
sigstack:    err = FD_VM_ERR_EBPF_CALL_DEPTH_EXCEEDED;                                   /* ic current */     /* cu current */  goto interp_halt;
sigill:      err = FD_VM_ERR_EBPF_UNSUPPORTED_INSTRUCTION;                               FD_VM_INTERP_FAULT;                    goto interp_halt;
sigillbr:    err = FD_VM_ERR_EBPF_UNSUPPORTED_INSTRUCTION;                               /* ic current */     /* cu current */  goto interp_halt;
siginv:      err = FD_VM_ERR_EBPF_INVALID_INSTRUCTION;                                   FD_VM_INTERP_FAULT;                    goto interp_halt;
sigsegv:     err = fd_vm_generate_access_violation( vm->segv_vaddr, vm->sbpf_version );  FD_VM_INTERP_FAULT;                    goto interp_halt;
sigcost:     err = FD_VM_ERR_EBPF_EXCEEDED_MAX_INSTRUCTIONS;                             /* ic current */     cu = 0UL;         goto interp_halt;
sigsyscall:  err = FD_VM_ERR_EBPF_SYSCALL_ERROR;                                         /* ic current */     /* cu current */  goto interp_halt;
sigfpe:      err = FD_VM_ERR_EBPF_DIVIDE_BY_ZERO;                                        FD_VM_INTERP_FAULT;                    goto interp_halt;
sigfpeof:    err = FD_VM_ERR_EBPF_DIVIDE_OVERFLOW;                                       FD_VM_INTERP_FAULT;                    goto interp_halt;
sigexit:     /* err current */                                                           /* ic current */     /* cu current */  goto interp_halt;

interp_halt:

  /* Pack the unpacked execution state into vm to give a precise view of
     the execution when the vm halted. */

  vm->pc = pc;
  vm->cu = cu;

# undef text_cnt
# undef reg

# undef FD_VM_INTERP_ST_REG
# undef FD_VM_INTERP_ST_IMM
# undef FD_VM_INTERP_LD
# undef FD_VM_INTERP_STACK_PUSH
# undef FD_VM_INTERP_FAULT
# undef FD_VM_INTERP_BRANCH_END
# undef FD_VM_INTERP_BRANCH_BEGIN
# undef FD_VM_INTERP_LDQ_EXTRA
# undef FD_VM_INTERP_INSTR_END
# undef FD_VM_INTERP_INSTR_BEGIN
# undef FD_VM_INTERP_SYSCALL_EXEC
# undef FD_VM_INTERP_SYSCALL_EXEC_DUMP
# undef FD_VM_INTERP_INSTR_EXEC
# undef FD_RUST_LONG_WRAPPING_SHR
# undef FD_RUST_INT_WRAPPING_SHR
# undef FD_RUST_UINT_WRAPPING_SHR
# undef FD_RUST_UINT_WRAPPING_SHL
# undef FD_RUST_ULONG_WRAPPING_SHR
# undef FD_RUST_ULONG_WRAPPING_SHL
# undef FD_VM_SIMM
# undef FD_VM_IMM
# undef FD_VM_OFFSET
# undef FD_VM_SRC
# undef FD_VM_DST

# if defined(__clang__)
# pragma clang diagnostic pop
# endif

# if defined(__GNUC__)
# pragma GCC diagnostic pop
# endif
