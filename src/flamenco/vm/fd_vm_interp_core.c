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

/* Pre-scaled byte offsets into reg[16] (at offset 0 of fd_vm_t) avoid
   16-bit partial-register shifts (shr $12, %ax) on GCC and 2-cycle BMI1
   bextr sequences on Clang. */
#ifdef __clang__
#define FD_VM_REG_AT(off) (*({ ulong _o = (off); FD_COMPILER_FORGET( _o ); (ulong *)((uchar *)reg + _o); }))
#else
#define FD_VM_REG_AT(off) (*(ulong *)((uchar *)reg + (off)))
#endif
#define FD_VM_DST_OFF (((uint)instr >> 5) & 0x78U)
#define FD_VM_SRC_OFF (((uint)instr >> 9) & 0x78U)
#define FD_VM_REG_DST FD_VM_REG_AT( FD_VM_DST_OFF )
#define FD_VM_REG_SRC FD_VM_REG_AT( FD_VM_SRC_OFF )
#define FD_VM_SRC     fd_vm_instr_src   ( instr )
#define FD_VM_OFFSET  fd_vm_instr_offset( instr )
#define FD_VM_IMM     fd_vm_instr_imm   ( instr )
#define FD_VM_SIMM    ((ulong)(long)(int)(instr >> 32))

/* These mimic the exact Rust semantics for wrapping_shl and wrapping_shr. */
#define FD_RUST_ULONG_WRAPPING_SHL( a, b ) ((a) << ( (b) & ( 63 ) ))
#define FD_RUST_ULONG_WRAPPING_SHR( a, b ) ((a) >> ( (b) & ( 63 ) ))
#define FD_RUST_UINT_WRAPPING_SHL( a, b )  ((a) << ( (b) & ( 31 ) ))
#define FD_RUST_UINT_WRAPPING_SHR( a, b )  ((a) >> ( (b) & ( 31 ) ))
#define FD_RUST_INT_WRAPPING_SHR( a, b )   ((a) >> ( (b) & ( 31 ) ))
#define FD_RUST_LONG_WRAPPING_SHR( a, b )  ((a) >> ( (b) & ( 63 ) ))

# if defined(__clang__) && !defined(FD_VM_INTERP_EXE_TRACING_ENABLED)
# define FD_VM_STR2(x) #x
# define FD_VM_STR(x)  FD_VM_STR2(x)
/* Give each handler its own indirectbr target expression so Clang
   duplicates threaded dispatch per opcode instead of tail-merging all
   handlers into a single shared indirect jump. */
# define FD_VM_INTERP_INSTR_EXEC                                                                                    \
  if( FD_UNLIKELY( pc>=block_text_limit ) ) goto sigtext_or_sigcost; /* Note: untaken branches don't consume BTB */ \
  instr = text[ pc ];                                                /* Guaranteed in-bounds */                     \
  { void const * const * _jt = version_interp_jump_table;                                                           \
    __asm__( "# " FD_VM_STR(__COUNTER__) : "+r"(_jt) );                                                             \
    goto *_jt[ instr & 255UL ]; }
# else
# define FD_VM_INTERP_INSTR_EXEC                                                                                    \
  if( FD_UNLIKELY( pc>=block_text_limit ) ) goto sigtext_or_sigcost; /* Note: untaken branches don't consume BTB */ \
  instr = text[ pc ];                                                /* Guaranteed in-bounds */                     \
  goto *version_interp_jump_table[ instr & 255UL ]                   /* Guaranteed in-bounds */
# endif

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

/* Memory load/store templates.  Regions 0..4 share a unified 5-slot
   inline TLB: slot 4 caches the active MRU input sub-region with
   region_haddr[4] pre-biased by -region_voff[4] so the host address
   issues in parallel with the bounds check. */
# ifdef __clang__
# define FD_VM_FORGET_REGION(r) FD_COMPILER_FORGET(r)
# else
# define FD_VM_FORGET_REGION(r) ((void)0)
# endif

# define FD_VM_INTERP_LD(opcode, sz, ld_fn)                                                         \
  FD_VM_INTERP_INSTR_BEGIN(opcode) {                                                                \
    ulong _vaddr  = FD_VM_REG_SRC + FD_VM_OFFSET;                                                   \
    ulong _region = _vaddr >> 32;                                                                   \
    FD_VM_FORGET_REGION( _region );                                                                 \
    ulong _off32  = (ulong)(uint)_vaddr;                                                            \
    ulong _haddr;                                                                                   \
    if( FD_LIKELY( _region<5UL && ((ulong)((uint)_off32 - vm->region_voff[ _region ])+(sz))<=(ulong)vm->region_ld_sz[ _region ] ) ) { \
      _haddr = vm->region_haddr[ _region ] + _off32;                                                \
    } else {                                                                                        \
      _haddr = fd_vm_mem_haddr_ld_slow( vm, _vaddr, (sz) );                                         \
      if( FD_UNLIKELY( !_haddr ) ) goto sigsegv;                                                    \
    }                                                                                               \
    FD_VM_REG_DST = ld_fn( _haddr );                                                                \
  } FD_VM_INTERP_INSTR_END

# define FD_VM_INTERP_ST_IMM(opcode, sz, st_fn, val_expr)                                           \
  FD_VM_INTERP_INSTR_BEGIN(opcode) {                                                                \
    ulong _vaddr  = FD_VM_REG_DST + FD_VM_OFFSET;                                                   \
    ulong _region = _vaddr >> 32;                                                                   \
    FD_VM_FORGET_REGION( _region );                                                                 \
    ulong _off32  = (ulong)(uint)_vaddr;                                                            \
    ulong _haddr;                                                                                   \
    if( FD_LIKELY( _region<5UL && ((ulong)((uint)_off32 - vm->region_voff[ _region ])+(sz))<=(ulong)vm->region_st_sz[ _region ] ) ) { \
      _haddr = vm->region_haddr[ _region ] + _off32;                                                \
    } else {                                                                                        \
      _haddr = fd_vm_mem_haddr_st_slow( vm, _vaddr, (sz) );                                         \
      if( FD_UNLIKELY( !_haddr ) ) goto sigsegv;                                                    \
    }                                                                                               \
    st_fn( _haddr, (val_expr) );                                                                    \
  } FD_VM_INTERP_INSTR_END

# define FD_VM_INTERP_ST_REG(opcode, sz, st_fn, cast_t)                                             \
  FD_VM_INTERP_INSTR_BEGIN(opcode) {                                                                \
    ulong _vaddr  = FD_VM_REG_DST + FD_VM_OFFSET;                                                   \
    ulong _region = _vaddr >> 32;                                                                   \
    FD_VM_FORGET_REGION( _region );                                                                 \
    ulong _off32  = (ulong)(uint)_vaddr;                                                            \
    ulong _haddr;                                                                                   \
    if( FD_LIKELY( _region<5UL && ((ulong)((uint)_off32 - vm->region_voff[ _region ])+(sz))<=(ulong)vm->region_st_sz[ _region ] ) ) { \
      _haddr = vm->region_haddr[ _region ] + _off32;                                                \
    } else {                                                                                        \
      _haddr = fd_vm_mem_haddr_st_slow( vm, _vaddr, (sz) );                                         \
      if( FD_UNLIKELY( !_haddr ) ) goto sigsegv;                                                    \
    }                                                                                               \
    st_fn( _haddr, (cast_t)FD_VM_REG_SRC );                                                         \
  } FD_VM_INTERP_INSTR_END

# define FD_VM_INTERP_ALU(opcode, stmt) \
  FD_VM_INTERP_INSTR_BEGIN(opcode) { ulong * _d = &FD_VM_REG_DST; stmt; } FD_VM_INTERP_INSTR_END

# define FD_VM_INTERP_JMP(opcode, cond) \
  FD_VM_INTERP_BRANCH_BEGIN(opcode) pc += fd_ulong_if( (cond), FD_VM_OFFSET, 0UL ); FD_VM_INTERP_BRANCH_END

  goto interp_exec;
interp_exec:

# ifdef FD_VM_INTERP_EXE_TRACING_ENABLED
  if( FD_UNLIKELY( pc>=block_text_limit ) ) goto sigtext_or_sigcost;
  fd_vm_trace_event_exe( vm->trace, pc, vm->ic + ( pc - pc0 - ic_correction ), cu, reg, text + pc, text_cnt - pc, ic_correction, vm->frame_cnt );
# endif

  FD_VM_INTERP_INSTR_EXEC;

  /* 0x00 - 0x0f ******************************************************/

  FD_VM_INTERP_ALU( 0x04,     *_d = (ulong)(uint)( (int)*_d + (int)FD_VM_IMM )     ); /* FD_SBPF_OP_ADD_IMM        */
  FD_VM_INTERP_ALU( 0x04depr, *_d = (ulong)(long)( (int)*_d + (int)FD_VM_IMM )     ); /* FD_SBPF_OP_ADD_IMM (depr) */

  FD_VM_INTERP_BRANCH_BEGIN(0x05) /* FD_SBPF_OP_JA */
    pc += FD_VM_OFFSET;
  FD_VM_INTERP_BRANCH_END;

  FD_VM_INTERP_ALU( 0x07,     *_d += FD_VM_SIMM                                    ); /* FD_SBPF_OP_ADD64_IMM      */
  FD_VM_INTERP_ALU( 0x0c,     *_d = (ulong)(uint)( (int)*_d + (int)FD_VM_REG_SRC ) ); /* FD_SBPF_OP_ADD_REG        */
  FD_VM_INTERP_ALU( 0x0cdepr, *_d = (ulong)(long)( (int)*_d + (int)FD_VM_REG_SRC ) ); /* FD_SBPF_OP_ADD_REG (depr) */
  FD_VM_INTERP_ALU( 0x0f,     *_d += FD_VM_REG_SRC                                 ); /* FD_SBPF_OP_ADD64_REG      */

  /* 0x10 - 0x1f ******************************************************/

  FD_VM_INTERP_ALU( 0x14,     *_d = (ulong)(uint)( (int)FD_VM_IMM - (int)*_d )     ); /* FD_SBPF_OP_SUB_IMM        */
  FD_VM_INTERP_ALU( 0x14depr, *_d = (ulong)(long)( (int)*_d - (int)FD_VM_IMM )     ); /* FD_SBPF_OP_SUB_IMM (depr) */
  FD_VM_INTERP_JMP( 0x15,     FD_VM_REG_DST==FD_VM_SIMM                            ); /* FD_SBPF_OP_JEQ_IMM        */
  FD_VM_INTERP_ALU( 0x17,     *_d = FD_VM_SIMM - *_d                               ); /* FD_SBPF_OP_SUB64_IMM      */
  FD_VM_INTERP_ALU( 0x17depr, *_d -= FD_VM_SIMM                                    ); /* FD_SBPF_OP_SUB64_IMM(depr)*/

  FD_VM_INTERP_INSTR_BEGIN(0x18) { /* FD_SBPF_OP_LDQ */
    ulong * _d = &FD_VM_REG_DST;
    ulong   lo = (ulong)FD_VM_IMM;
    pc++;
    FD_VM_INTERP_LDQ_EXTRA;
    *_d = lo | (text[ pc ] & 0xFFFFFFFF00000000UL);
  } FD_VM_INTERP_INSTR_END;

  FD_VM_INTERP_ALU( 0x1c,     *_d = (ulong)(uint)( (int)*_d - (int)FD_VM_REG_SRC ) ); /* FD_SBPF_OP_SUB_REG        */
  FD_VM_INTERP_ALU( 0x1cdepr, *_d = (ulong)(long)( (int)*_d - (int)FD_VM_REG_SRC ) ); /* FD_SBPF_OP_SUB_REG (depr) */
  FD_VM_INTERP_JMP( 0x1d,     FD_VM_REG_DST==FD_VM_REG_SRC                         ); /* FD_SBPF_OP_JEQ_REG        */
  FD_VM_INTERP_ALU( 0x1f,     *_d -= FD_VM_REG_SRC                                 ); /* FD_SBPF_OP_SUB64_REG      */

  /* 0x20 - 0x2f ******************************************************/

  FD_VM_INTERP_ALU   ( 0x24,     *_d = (ulong)(long)( (int)*_d * (int)FD_VM_IMM )     ); /* FD_SBPF_OP_MUL_IMM   */
  FD_VM_INTERP_JMP   ( 0x25,     FD_VM_REG_DST>FD_VM_SIMM                             ); /* FD_SBPF_OP_JGT_IMM   */
  FD_VM_INTERP_ST_IMM( 0x27,     sizeof(uchar), fd_vm_mem_st_1, (uchar)FD_VM_IMM      ); /* FD_SBPF_OP_STB       */
  FD_VM_INTERP_LD    ( 0x2c,     sizeof(uchar), fd_vm_mem_ld_1                        ); /* FD_SBPF_OP_LDXB      */
  FD_VM_INTERP_JMP   ( 0x2d,     FD_VM_REG_DST>FD_VM_REG_SRC                          ); /* FD_SBPF_OP_JGT_REG   */
  FD_VM_INTERP_ST_REG( 0x2f,     sizeof(uchar), fd_vm_mem_st_1, uchar                 ); /* FD_SBPF_OP_STXB      */
  FD_VM_INTERP_ALU   ( 0x27depr, *_d = (ulong)( (long)*_d * (long)FD_VM_SIMM )        ); /* FD_SBPF_OP_MUL64_IMM */
  FD_VM_INTERP_ALU   ( 0x2cdepr, *_d = (ulong)(long)( (int)*_d * (int)FD_VM_REG_SRC ) ); /* FD_SBPF_OP_MUL_REG   */
  FD_VM_INTERP_ALU   ( 0x2fdepr, *_d *= FD_VM_REG_SRC                                 ); /* FD_SBPF_OP_MUL64_REG */

  /* 0x30 - 0x3f ******************************************************/

  FD_VM_INTERP_ALU   ( 0x34,     *_d = (ulong)((uint)*_d / FD_VM_IMM)                             ); /* FD_SBPF_OP_DIV_IMM     */
  FD_VM_INTERP_JMP   ( 0x35,     FD_VM_REG_DST>=FD_VM_SIMM                                        ); /* FD_SBPF_OP_JGE_IMM     */
  FD_VM_INTERP_ALU   ( 0x36,     *_d = (ulong)(( (uint128)*_d * (uint128)(ulong)FD_VM_IMM ) >> 64)); /* FD_SBPF_OP_UHMUL64_IMM */
  FD_VM_INTERP_ST_IMM( 0x37,     sizeof(ushort), fd_vm_mem_st_2, (ushort)FD_VM_IMM                ); /* FD_SBPF_OP_STH         */
  FD_VM_INTERP_LD    ( 0x3c,     sizeof(ushort), fd_vm_mem_ld_2                                   ); /* FD_SBPF_OP_LDXH        */
  FD_VM_INTERP_JMP   ( 0x3d,     FD_VM_REG_DST>=FD_VM_REG_SRC                                     ); /* FD_SBPF_OP_JGE_REG     */
  FD_VM_INTERP_ST_REG( 0x3f,     sizeof(ushort), fd_vm_mem_st_2, ushort                           ); /* FD_SBPF_OP_STXH        */
  FD_VM_INTERP_ALU   ( 0x3e,     *_d = (ulong)(( (uint128)*_d * (uint128)FD_VM_REG_SRC ) >> 64)   ); /* FD_SBPF_OP_UHMUL64_REG */
  FD_VM_INTERP_ALU   ( 0x37depr, *_d /= FD_VM_SIMM                                                ); /* FD_SBPF_OP_DIV64_IMM   */

  FD_VM_INTERP_ALU( 0x3cdepr, uint  rsrc = (uint)FD_VM_REG_SRC; if( FD_UNLIKELY( !rsrc ) ) goto sigfpe; *_d = (ulong)((uint)*_d / rsrc) ); /* FD_SBPF_OP_DIV_REG   */
  FD_VM_INTERP_ALU( 0x3fdepr, ulong rsrc =       FD_VM_REG_SRC; if( FD_UNLIKELY( !rsrc ) ) goto sigfpe; *_d /= rsrc                     ); /* FD_SBPF_OP_DIV64_REG */

  /* 0x40 - 0x4f ******************************************************/

  FD_VM_INTERP_ALU( 0x44, *_d = (ulong)( (uint)*_d | FD_VM_IMM )         ); /* FD_SBPF_OP_OR_IMM     */
  FD_VM_INTERP_JMP( 0x45, !!(FD_VM_REG_DST & FD_VM_SIMM)                 ); /* FD_SBPF_OP_JSET_IMM   */
  FD_VM_INTERP_ALU( 0x46, *_d = (ulong)( (uint)*_d / FD_VM_IMM )         ); /* FD_SBPF_OP_UDIV32_IMM */
  FD_VM_INTERP_ALU( 0x47, *_d |= FD_VM_SIMM                              ); /* FD_SBPF_OP_OR64_IMM   */
  FD_VM_INTERP_ALU( 0x4c, *_d = (ulong)(uint)( *_d | FD_VM_REG_SRC )     ); /* FD_SBPF_OP_OR_REG     */
  FD_VM_INTERP_JMP( 0x4d, !!(FD_VM_REG_DST & FD_VM_REG_SRC)              ); /* FD_SBPF_OP_JSET_REG   */
  FD_VM_INTERP_ALU( 0x4e, uint rsrc = (uint)FD_VM_REG_SRC; if( FD_UNLIKELY( !rsrc ) ) goto sigfpe; *_d = (ulong)( (uint)*_d / rsrc ) ); /* FD_SBPF_OP_UDIV32_REG */
  FD_VM_INTERP_ALU( 0x4f, *_d |= FD_VM_REG_SRC                           ); /* FD_SBPF_OP_OR64_REG   */

  /* 0x50 - 0x5f ******************************************************/

  FD_VM_INTERP_ALU( 0x54, *_d = (ulong)( (uint)*_d & FD_VM_IMM )         ); /* FD_SBPF_OP_AND_IMM    */
  FD_VM_INTERP_JMP( 0x55, FD_VM_REG_DST!=FD_VM_SIMM                      ); /* FD_SBPF_OP_JNE_IMM    */
  FD_VM_INTERP_ALU( 0x56, *_d /= (ulong)FD_VM_IMM                        ); /* FD_SBPF_OP_UDIV64_IMM */
  FD_VM_INTERP_ALU( 0x57, *_d &= FD_VM_SIMM                              ); /* FD_SBPF_OP_AND64_IMM  */
  FD_VM_INTERP_ALU( 0x5c, *_d = (ulong)(uint)( *_d & FD_VM_REG_SRC )     ); /* FD_SBPF_OP_AND_REG    */
  FD_VM_INTERP_JMP( 0x5d, FD_VM_REG_DST!=FD_VM_REG_SRC                   ); /* FD_SBPF_OP_JNE_REG    */
  FD_VM_INTERP_ALU( 0x5e, ulong rsrc = FD_VM_REG_SRC; if( FD_UNLIKELY( !rsrc ) ) goto sigfpe; *_d /= rsrc ); /* FD_SBPF_OP_UDIV64_REG */
  FD_VM_INTERP_ALU( 0x5f, *_d &= FD_VM_REG_SRC                           ); /* FD_SBPF_OP_AND64_REG  */

  /* 0x60 - 0x6f ******************************************************/

  FD_VM_INTERP_ALU( 0x64, *_d = (ulong)FD_RUST_UINT_WRAPPING_SHL ( (uint)*_d, FD_VM_IMM     ) ); /* FD_SBPF_OP_LSH_IMM    */
  FD_VM_INTERP_JMP( 0x65, (long)FD_VM_REG_DST>(long)FD_VM_SIMM                                ); /* FD_SBPF_OP_JSGT_IMM   */
  FD_VM_INTERP_ALU( 0x66, *_d = (ulong)( (uint)*_d % FD_VM_IMM )                              ); /* FD_SBPF_OP_UREM32_IMM */
  FD_VM_INTERP_ALU( 0x67, *_d =        FD_RUST_ULONG_WRAPPING_SHL(       *_d, FD_VM_IMM     ) ); /* FD_SBPF_OP_LSH64_IMM  */
  FD_VM_INTERP_ALU( 0x6c, *_d = (ulong)FD_RUST_UINT_WRAPPING_SHL ( (uint)*_d, FD_VM_REG_SRC ) ); /* FD_SBPF_OP_LSH_REG    */
  FD_VM_INTERP_JMP( 0x6d, (long)FD_VM_REG_DST>(long)FD_VM_REG_SRC                             ); /* FD_SBPF_OP_JSGT_REG   */
  FD_VM_INTERP_ALU( 0x6e, uint rsrc = (uint)FD_VM_REG_SRC; if( FD_UNLIKELY( !rsrc ) ) goto sigfpe; *_d = (ulong)( (uint)*_d % rsrc ) ); /* FD_SBPF_OP_UREM32_REG */
  FD_VM_INTERP_ALU( 0x6f, *_d =        FD_RUST_ULONG_WRAPPING_SHL(       *_d, FD_VM_REG_SRC ) ); /* FD_SBPF_OP_LSH64_REG  */

  /* 0x70 - 0x7f ******************************************************/

  FD_VM_INTERP_ALU( 0x74, *_d = (ulong)FD_RUST_UINT_WRAPPING_SHR ( (uint)*_d,       FD_VM_IMM     ) ); /* FD_SBPF_OP_RSH_IMM    */
  FD_VM_INTERP_JMP( 0x75, (long)FD_VM_REG_DST>=(long)FD_VM_SIMM                                     ); /* FD_SBPF_OP_JSGE_IMM   */
  FD_VM_INTERP_ALU( 0x76, *_d %= (ulong)FD_VM_IMM                                                   ); /* FD_SBPF_OP_UREM64_IMM */
  FD_VM_INTERP_ALU( 0x77, *_d =        FD_RUST_ULONG_WRAPPING_SHR(       *_d,       FD_VM_IMM     ) ); /* FD_SBPF_OP_RSH64_IMM  */
  FD_VM_INTERP_ALU( 0x7c, *_d = (ulong)FD_RUST_UINT_WRAPPING_SHR ( (uint)*_d, (uint)FD_VM_REG_SRC ) ); /* FD_SBPF_OP_RSH_REG    */
  FD_VM_INTERP_JMP( 0x7d, (long)FD_VM_REG_DST>=(long)FD_VM_REG_SRC                                  ); /* FD_SBPF_OP_JSGE_REG   */
  FD_VM_INTERP_ALU( 0x7e, ulong rsrc = FD_VM_REG_SRC; if( FD_UNLIKELY( !rsrc ) ) goto sigfpe; *_d %= rsrc ); /* FD_SBPF_OP_UREM64_REG */
  FD_VM_INTERP_ALU( 0x7f, *_d =        FD_RUST_ULONG_WRAPPING_SHR(       *_d,       FD_VM_REG_SRC ) ); /* FD_SBPF_OP_RSH64_REG  */

  /* 0x80-0x8f ********************************************************/

  FD_VM_INTERP_ALU( 0x84, *_d = (ulong)( -(uint)*_d ) ); /* FD_SBPF_OP_NEG */

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

  FD_VM_INTERP_ALU   ( 0x86,     *_d = (ulong)( (uint)*_d * FD_VM_IMM )           ); /* FD_SBPF_OP_LMUL32_IMM */
  FD_VM_INTERP_ST_IMM( 0x87,     sizeof(uint), fd_vm_mem_st_4, FD_VM_IMM          ); /* FD_SBPF_OP_STW        */
  FD_VM_INTERP_ALU   ( 0x87depr, *_d = -*_d                                       ); /* FD_SBPF_OP_NEG64      */
  FD_VM_INTERP_LD    ( 0x8c,     sizeof(uint), fd_vm_mem_ld_4                     ); /* FD_SBPF_OP_LDXW       */

  FD_VM_INTERP_BRANCH_BEGIN(0x8d) { /* FD_SBPF_OP_CALL_REG */
    ulong rsrc = FD_VM_REG_SRC;
    ulong rdst = FD_VM_REG_DST;
    FD_VM_INTERP_STACK_PUSH;

    ulong sbpf_ver = vm->sbpf_version;
    ulong vaddr = fd_sbpf_callx_uses_src_reg_enabled( sbpf_ver ) ? rsrc
                : fd_sbpf_callx_uses_dst_reg_enabled( sbpf_ver ) ? rdst
                : reg[ FD_VM_IMM & 15U ];

    ulong region    = vaddr >> 32;
    ulong target_pc = ((vaddr & FD_VM_OFFSET_MASK) - vm->text_off) / 8UL;
    if( FD_UNLIKELY( (region!=1UL) | (target_pc>=text_cnt) ) ) goto sigtextbr;
    pc = target_pc - 1UL;
  } FD_VM_INTERP_BRANCH_END;

  FD_VM_INTERP_ALU   ( 0x8e,     *_d = (ulong)( (uint)*_d * (uint)FD_VM_REG_SRC ) ); /* FD_SBPF_OP_LMUL32_REG */
  FD_VM_INTERP_ST_REG( 0x8f,     sizeof(uint), fd_vm_mem_st_4, uint               ); /* FD_SBPF_OP_STXW       */

  /* 0x90 - 0x9f ******************************************************/

  FD_VM_INTERP_ALU( 0x94, *_d = (ulong)( (uint)*_d % FD_VM_IMM ) ); /* FD_SBPF_OP_MOD_IMM */

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

  FD_VM_INTERP_ALU   ( 0x96,     *_d *= FD_VM_SIMM                                ); /* FD_SBPF_OP_LMUL64_IMM */
  FD_VM_INTERP_ST_IMM( 0x97,     sizeof(ulong), fd_vm_mem_st_8, FD_VM_SIMM        ); /* FD_SBPF_OP_STQ        */
  FD_VM_INTERP_LD    ( 0x9c,     sizeof(ulong), fd_vm_mem_ld_8                    ); /* FD_SBPF_OP_LDXQ       */
  FD_VM_INTERP_ALU   ( 0x9e,     *_d *= FD_VM_REG_SRC                             ); /* FD_SBPF_OP_LMUL64_REG */
  FD_VM_INTERP_ST_REG( 0x9f,     sizeof(ulong), fd_vm_mem_st_8, ulong             ); /* FD_SBPF_OP_STXQ       */
  FD_VM_INTERP_ALU   ( 0x97depr, *_d %= FD_VM_SIMM                                ); /* FD_SBPF_OP_MOD64_IMM  */
  FD_VM_INTERP_ALU   ( 0x9cdepr, uint  rsrc = (uint)FD_VM_REG_SRC; if( FD_UNLIKELY( !rsrc ) ) goto sigfpe; *_d = (ulong)( (uint)*_d % rsrc ) ); /* FD_SBPF_OP_MOD_REG   */
  FD_VM_INTERP_ALU   ( 0x9fdepr, ulong rsrc =       FD_VM_REG_SRC; if( FD_UNLIKELY( !rsrc ) ) goto sigfpe; *_d %= rsrc                     ); /* FD_SBPF_OP_MOD64_REG */

  /* 0xa0 - 0xaf ******************************************************/

  FD_VM_INTERP_ALU( 0xa4, *_d = (ulong)( (uint)*_d ^ FD_VM_IMM )     ); /* FD_SBPF_OP_XOR_IMM   */
  FD_VM_INTERP_JMP( 0xa5, FD_VM_REG_DST<FD_VM_SIMM                   ); /* FD_SBPF_OP_JLT_IMM   */
  FD_VM_INTERP_ALU( 0xa7, *_d ^= FD_VM_SIMM                          ); /* FD_SBPF_OP_XOR64_IMM */
  FD_VM_INTERP_ALU( 0xac, *_d = (ulong)(uint)( *_d ^ FD_VM_REG_SRC ) ); /* FD_SBPF_OP_XOR_REG   */
  FD_VM_INTERP_JMP( 0xad, FD_VM_REG_DST<FD_VM_REG_SRC                ); /* FD_SBPF_OP_JLT_REG   */
  FD_VM_INTERP_ALU( 0xaf, *_d ^= FD_VM_REG_SRC                       ); /* FD_SBPF_OP_XOR64_REG */

  /* 0xb0 - 0xbf ******************************************************/

  FD_VM_INTERP_ALU( 0xb4,     *_d = (ulong)FD_VM_IMM                                                  ); /* FD_SBPF_OP_MOV_IMM        */
  FD_VM_INTERP_JMP( 0xb5,     FD_VM_REG_DST<=FD_VM_SIMM                                               ); /* FD_SBPF_OP_JLE_IMM        */
  FD_VM_INTERP_ALU( 0xb6,     *_d = (ulong)(( (int128)(long)*_d * (int128)(long)FD_VM_SIMM    ) >> 64)); /* FD_SBPF_OP_SHMUL64_IMM    */
  FD_VM_INTERP_ALU( 0xb7,     *_d = FD_VM_SIMM                                                        ); /* FD_SBPF_OP_MOV64_IMM      */
  FD_VM_INTERP_ALU( 0xbc,     *_d = (ulong)(long)(int)FD_VM_REG_SRC                                   ); /* FD_SBPF_OP_MOV_REG        */
  FD_VM_INTERP_ALU( 0xbcdepr, *_d = (ulong)(uint)     FD_VM_REG_SRC                                   ); /* FD_SBPF_OP_MOV_REG (depr) */
  FD_VM_INTERP_JMP( 0xbd,     FD_VM_REG_DST<=FD_VM_REG_SRC                                            ); /* FD_SBPF_OP_JLE_REG        */
  FD_VM_INTERP_ALU( 0xbe,     *_d = (ulong)(( (int128)(long)*_d * (int128)(long)FD_VM_REG_SRC ) >> 64)); /* FD_SBPF_OP_SHMUL64_REG    */
  FD_VM_INTERP_ALU( 0xbf,     *_d = FD_VM_REG_SRC                                                     ); /* FD_SBPF_OP_MOV64_REG      */

  /* 0xc0 - 0xcf ******************************************************/

  FD_VM_INTERP_ALU( 0xc4, *_d = (ulong)(uint)FD_RUST_INT_WRAPPING_SHR ( (int) *_d,       FD_VM_IMM     ) ); /* FD_SBPF_OP_ARSH_IMM   */
  FD_VM_INTERP_JMP( 0xc5, (long)FD_VM_REG_DST<(long)FD_VM_SIMM                                           ); /* FD_SBPF_OP_JSLT_IMM   */
  FD_VM_INTERP_ALU( 0xc6, int rdst = (int)*_d; int simm = (int)FD_VM_IMM;
                          if( FD_UNLIKELY( (rdst==INT_MIN) & (simm==-1) ) ) goto sigfpeof;
                          *_d = (ulong)(uint)( rdst / simm ) );                                             /* FD_SBPF_OP_SDIV32_IMM */
  FD_VM_INTERP_ALU( 0xc7, *_d = (ulong)      FD_RUST_LONG_WRAPPING_SHR( (long)*_d,       FD_VM_IMM     ) ); /* FD_SBPF_OP_ARSH64_IMM */
  FD_VM_INTERP_ALU( 0xcc, *_d = (ulong)(uint)FD_RUST_INT_WRAPPING_SHR ( (int) *_d, (uint)FD_VM_REG_SRC ) ); /* FD_SBPF_OP_ARSH_REG   */
  FD_VM_INTERP_JMP( 0xcd, (long)FD_VM_REG_DST<(long)FD_VM_REG_SRC                                        ); /* FD_SBPF_OP_JSLT_REG   */
  FD_VM_INTERP_ALU( 0xce, int rsrc = (int)FD_VM_REG_SRC; if( FD_UNLIKELY( !rsrc ) ) goto sigfpe;
                          int rdst = (int)*_d; if( FD_UNLIKELY( (rdst==INT_MIN) & (rsrc==-1) ) ) goto sigfpeof;
                          *_d = (ulong)(uint)( rdst / rsrc ) );                                             /* FD_SBPF_OP_SDIV32_REG */
  FD_VM_INTERP_ALU( 0xcf, *_d = (ulong)      FD_RUST_LONG_WRAPPING_SHR( (long)*_d,       FD_VM_REG_SRC ) ); /* FD_SBPF_OP_ARSH64_REG */

  /* 0xd0 - 0xdf ******************************************************/

  FD_VM_INTERP_ALU( 0xd4, switch( FD_VM_IMM ) {
    case 16U: *_d = (ushort)*_d; break;
    case 32U: *_d = (uint)  *_d; break;
    case 64U:                    break;
    default: goto siginv;
  } ); /* FD_SBPF_OP_END_LE */

  FD_VM_INTERP_JMP( 0xd5, (long)FD_VM_REG_DST<=(long)FD_VM_SIMM ); /* FD_SBPF_OP_JSLE_IMM */

  FD_VM_INTERP_ALU( 0xd6, long rdst = (long)*_d; long simm = (long)FD_VM_SIMM;
                          if( FD_UNLIKELY( (rdst==LONG_MIN) & (simm==-1L) ) ) goto sigfpeof;
                          *_d = (ulong)( rdst / simm ) ); /* FD_SBPF_OP_SDIV64_IMM */

  FD_VM_INTERP_ALU( 0xdc, ulong rdst = *_d; switch( FD_VM_IMM ) {
    case 16U: *_d = (ulong)fd_ushort_bswap( (ushort)rdst ); break;
    case 32U: *_d = (ulong)fd_uint_bswap  ( (uint)  rdst ); break;
    case 64U: *_d =        fd_ulong_bswap (         rdst ); break;
    default: goto siginv;
  } ); /* FD_SBPF_OP_END_BE */

  FD_VM_INTERP_JMP( 0xdd, (long)FD_VM_REG_DST<=(long)FD_VM_REG_SRC ); /* FD_SBPF_OP_JSLE_REG */

  FD_VM_INTERP_ALU( 0xde, long rsrc = (long)FD_VM_REG_SRC; if( FD_UNLIKELY( !rsrc ) ) goto sigfpe;
                          long rdst = (long)*_d; if( FD_UNLIKELY( (rdst==LONG_MIN) & (rsrc==-1L) ) ) goto sigfpeof;
                          *_d = (ulong)( rdst / rsrc ) ); /* FD_SBPF_OP_SDIV64_REG */

  /* 0xe0 - 0xef ******************************************************/

  FD_VM_INTERP_ALU( 0xe6, int rdst = (int)*_d; int simm = (int)FD_VM_IMM;
                          if( FD_UNLIKELY( (rdst==INT_MIN) & (simm==-1) ) ) goto sigfpeof;
                          *_d = (ulong)(uint)( rdst % simm ) ); /* FD_SBPF_OP_SREM32_IMM */

  FD_VM_INTERP_ALU( 0xee, int rsrc = (int)FD_VM_REG_SRC; if( FD_UNLIKELY( !rsrc ) ) goto sigfpe;
                          int rdst = (int)*_d; if( FD_UNLIKELY( (rdst==INT_MIN) & (rsrc==-1) ) ) goto sigfpeof;
                          *_d = (ulong)(uint)( rdst % rsrc ) ); /* FD_SBPF_OP_SREM32_REG */

  /* 0xf0 - 0xff ******************************************************/

  FD_VM_INTERP_ALU( 0xf6, long rdst = (long)*_d; long simm = (long)FD_VM_SIMM;
                          if( FD_UNLIKELY( (rdst==LONG_MIN) & (simm==-1L) ) ) goto sigfpeof;
                          *_d = (ulong)( rdst % simm ) ); /* FD_SBPF_OP_SREM64_IMM */

  FD_VM_INTERP_ALU( 0xf7, *_d |= (instr & 0xFFFFFFFF00000000UL) ); /* FD_SBPF_OP_HOR64 */

  FD_VM_INTERP_ALU( 0xfe, long rsrc = (long)FD_VM_REG_SRC; if( FD_UNLIKELY( !rsrc ) ) goto sigfpe;
                          long rdst = (long)*_d; if( FD_UNLIKELY( (rdst==LONG_MIN) & (rsrc==-1L) ) ) goto sigfpeof;
                          *_d = (ulong)( rdst % rsrc ) ); /* FD_SBPF_OP_SREM64_REG */

  /* SIMD-0377: JMP32
     https://github.com/anza-xyz/sbpf/blob/v0.14.4/src/interpreter.rs#L480-L501

     0x16 - 0xde ******************************************************/

  FD_VM_INTERP_JMP( 0x16_jmp32,   (uint)FD_VM_REG_DST==      FD_VM_IMM      ); /* FD_SBPF_OP_JEQ32_IMM  */
  FD_VM_INTERP_JMP( 0x1e_jmp32,   (uint)FD_VM_REG_DST==(uint)FD_VM_REG_SRC  ); /* FD_SBPF_OP_JEQ32_REG  */
  FD_VM_INTERP_JMP( 0x26_jmp32,   (uint)FD_VM_REG_DST>       FD_VM_IMM      ); /* FD_SBPF_OP_JGT32_IMM  */
  FD_VM_INTERP_JMP( 0x2e_jmp32,   (uint)FD_VM_REG_DST> (uint)FD_VM_REG_SRC  ); /* FD_SBPF_OP_JGT32_REG  */
  FD_VM_INTERP_JMP( 0x36_jmp32,   (uint)FD_VM_REG_DST>=      FD_VM_IMM      ); /* FD_SBPF_OP_JGE32_IMM  */
  FD_VM_INTERP_JMP( 0x3e_jmp32,   (uint)FD_VM_REG_DST>=(uint)FD_VM_REG_SRC  ); /* FD_SBPF_OP_JGE32_REG  */
  FD_VM_INTERP_JMP( 0x46_jmp32, !!((uint)FD_VM_REG_DST &      FD_VM_IMM    ) ); /* FD_SBPF_OP_JSET32_IMM */
  FD_VM_INTERP_JMP( 0x4e_jmp32, !!((uint)FD_VM_REG_DST &(uint)FD_VM_REG_SRC) ); /* FD_SBPF_OP_JSET32_REG */
  FD_VM_INTERP_JMP( 0x56_jmp32,   (uint)FD_VM_REG_DST!=      FD_VM_IMM      ); /* FD_SBPF_OP_JNE32_IMM  */
  FD_VM_INTERP_JMP( 0x5e_jmp32,   (uint)FD_VM_REG_DST!=(uint)FD_VM_REG_SRC  ); /* FD_SBPF_OP_JNE32_REG  */
  FD_VM_INTERP_JMP( 0x66_jmp32,   (int) FD_VM_REG_DST> (int) FD_VM_IMM      ); /* FD_SBPF_OP_JSGT32_IMM */
  FD_VM_INTERP_JMP( 0x6e_jmp32,   (int) FD_VM_REG_DST> (int) FD_VM_REG_SRC  ); /* FD_SBPF_OP_JSGT32_REG */
  FD_VM_INTERP_JMP( 0x76_jmp32,   (int) FD_VM_REG_DST>=(int) FD_VM_IMM      ); /* FD_SBPF_OP_JSGE32_IMM */
  FD_VM_INTERP_JMP( 0x7e_jmp32,   (int) FD_VM_REG_DST>=(int) FD_VM_REG_SRC  ); /* FD_SBPF_OP_JSGE32_REG */
  FD_VM_INTERP_JMP( 0xa6_jmp32,   (uint)FD_VM_REG_DST<       FD_VM_IMM      ); /* FD_SBPF_OP_JLT32_IMM  */
  FD_VM_INTERP_JMP( 0xae_jmp32,   (uint)FD_VM_REG_DST< (uint)FD_VM_REG_SRC  ); /* FD_SBPF_OP_JLT32_REG  */
  FD_VM_INTERP_JMP( 0xb6_jmp32,   (uint)FD_VM_REG_DST<=      FD_VM_IMM      ); /* FD_SBPF_OP_JLE32_IMM  */
  FD_VM_INTERP_JMP( 0xbe_jmp32,   (uint)FD_VM_REG_DST<=(uint)FD_VM_REG_SRC  ); /* FD_SBPF_OP_JLE32_REG  */
  FD_VM_INTERP_JMP( 0xc6_jmp32,   (int) FD_VM_REG_DST< (int) FD_VM_IMM      ); /* FD_SBPF_OP_JSLT32_IMM */
  FD_VM_INTERP_JMP( 0xce_jmp32,   (int) FD_VM_REG_DST< (int) FD_VM_REG_SRC  ); /* FD_SBPF_OP_JSLT32_REG */
  FD_VM_INTERP_JMP( 0xd6_jmp32,   (int) FD_VM_REG_DST<=(int) FD_VM_IMM      ); /* FD_SBPF_OP_JSLE32_IMM */
  FD_VM_INTERP_JMP( 0xde_jmp32,   (int) FD_VM_REG_DST<=(int) FD_VM_REG_SRC  ); /* FD_SBPF_OP_JSLE32_REG */

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

# undef FD_VM_INTERP_JMP
# undef FD_VM_INTERP_ALU
# undef FD_VM_INTERP_ST_REG
# undef FD_VM_INTERP_ST_IMM
# undef FD_VM_INTERP_LD
# undef FD_VM_FORGET_REGION
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
# undef FD_VM_STR
# undef FD_VM_STR2
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
# undef FD_VM_REG_SRC
# undef FD_VM_REG_DST
# undef FD_VM_SRC_OFF
# undef FD_VM_DST_OFF
# undef FD_VM_REG_AT

# if defined(__clang__)
# pragma clang diagnostic pop
# endif

# if defined(__GNUC__)
# pragma GCC diagnostic pop
# endif
