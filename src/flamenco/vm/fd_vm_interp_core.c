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

  /* Update the jump table based on SBPF version */

  ulong sbpf_version = vm->sbpf_version;

  for( ulong table_sbpf_version=0UL; table_sbpf_version<FD_SBPF_VERSION_COUNT; table_sbpf_version++ ) {
    /* SIMD-0173: LDDW */
    interp_jump_table[ table_sbpf_version ][ 0x18 ] = FD_VM_SBPF_ENABLE_LDDW(table_sbpf_version) ? &&interp_0x18 : &&sigill;
    interp_jump_table[ table_sbpf_version ][ 0xf7 ] = FD_VM_SBPF_ENABLE_LDDW(table_sbpf_version) ? &&sigill : &&interp_0xf7; /* HOR64 */

    /* SIMD-0173: LE */
    interp_jump_table[ table_sbpf_version ][ 0xd4 ] = FD_VM_SBPF_ENABLE_LE  (table_sbpf_version) ? &&interp_0xd4 : &&sigill;

    /* SIMD-0173: LDXW, STW, STXW */
    interp_jump_table[ table_sbpf_version ][ 0x61 ] = FD_VM_SBPF_MOVE_MEMORY_IX_CLASSES(table_sbpf_version) ? &&sigill : &&interp_0x8c;
    interp_jump_table[ table_sbpf_version ][ 0x62 ] = FD_VM_SBPF_MOVE_MEMORY_IX_CLASSES(table_sbpf_version) ? &&sigill : &&interp_0x87;
    interp_jump_table[ table_sbpf_version ][ 0x63 ] = FD_VM_SBPF_MOVE_MEMORY_IX_CLASSES(table_sbpf_version) ? &&sigill : &&interp_0x8f;
    interp_jump_table[ table_sbpf_version ][ 0x8c ] = FD_VM_SBPF_MOVE_MEMORY_IX_CLASSES(table_sbpf_version) ? &&interp_0x8c : &&sigill;
    interp_jump_table[ table_sbpf_version ][ 0x87 ] = FD_VM_SBPF_MOVE_MEMORY_IX_CLASSES(table_sbpf_version) ? &&interp_0x87 : &&interp_0x87depr;
    interp_jump_table[ table_sbpf_version ][ 0x8f ] = FD_VM_SBPF_MOVE_MEMORY_IX_CLASSES(table_sbpf_version) ? &&interp_0x8f : &&sigill;

    /* SIMD-0173: LDXH, STH, STXH */
    interp_jump_table[ table_sbpf_version ][ 0x69 ] = FD_VM_SBPF_MOVE_MEMORY_IX_CLASSES(table_sbpf_version) ? &&sigill : &&interp_0x3c;
    interp_jump_table[ table_sbpf_version ][ 0x6a ] = FD_VM_SBPF_MOVE_MEMORY_IX_CLASSES(table_sbpf_version) ? &&sigill : &&interp_0x37;
    interp_jump_table[ table_sbpf_version ][ 0x6b ] = FD_VM_SBPF_MOVE_MEMORY_IX_CLASSES(table_sbpf_version) ? &&sigill : &&interp_0x3f;
    interp_jump_table[ table_sbpf_version ][ 0x3c ] = FD_VM_SBPF_MOVE_MEMORY_IX_CLASSES(table_sbpf_version) ? &&interp_0x3c : &&interp_0x3cdepr;
    interp_jump_table[ table_sbpf_version ][ 0x37 ] = FD_VM_SBPF_MOVE_MEMORY_IX_CLASSES(table_sbpf_version) ? &&interp_0x37 : &&interp_0x37depr;
    interp_jump_table[ table_sbpf_version ][ 0x3f ] = FD_VM_SBPF_MOVE_MEMORY_IX_CLASSES(table_sbpf_version) ? &&interp_0x3f : &&interp_0x3fdepr;

    /* SIMD-0173: LDXB, STB, STXB */
    interp_jump_table[ table_sbpf_version ][ 0x71 ] = FD_VM_SBPF_MOVE_MEMORY_IX_CLASSES(table_sbpf_version) ? &&sigill : &&interp_0x2c;
    interp_jump_table[ table_sbpf_version ][ 0x72 ] = FD_VM_SBPF_MOVE_MEMORY_IX_CLASSES(table_sbpf_version) ? &&sigill : &&interp_0x27;
    interp_jump_table[ table_sbpf_version ][ 0x73 ] = FD_VM_SBPF_MOVE_MEMORY_IX_CLASSES(table_sbpf_version) ? &&sigill : &&interp_0x2f;
    interp_jump_table[ table_sbpf_version ][ 0x2c ] = FD_VM_SBPF_MOVE_MEMORY_IX_CLASSES(table_sbpf_version) ? &&interp_0x2c : &&interp_0x2cdepr;
    interp_jump_table[ table_sbpf_version ][ 0x27 ] = FD_VM_SBPF_MOVE_MEMORY_IX_CLASSES(table_sbpf_version) ? &&interp_0x27 : &&interp_0x27depr;
    interp_jump_table[ table_sbpf_version ][ 0x2f ] = FD_VM_SBPF_MOVE_MEMORY_IX_CLASSES(table_sbpf_version) ? &&interp_0x2f : &&interp_0x2fdepr;

    /* SIMD-0173: LDXDW, STDW, STXDW */
    interp_jump_table[ table_sbpf_version ][ 0x79 ] = FD_VM_SBPF_MOVE_MEMORY_IX_CLASSES(table_sbpf_version) ? &&sigill : &&interp_0x9c;
    interp_jump_table[ table_sbpf_version ][ 0x7a ] = FD_VM_SBPF_MOVE_MEMORY_IX_CLASSES(table_sbpf_version) ? &&sigill : &&interp_0x97;
    interp_jump_table[ table_sbpf_version ][ 0x7b ] = FD_VM_SBPF_MOVE_MEMORY_IX_CLASSES(table_sbpf_version) ? &&sigill : &&interp_0x9f;
    interp_jump_table[ table_sbpf_version ][ 0x9c ] = FD_VM_SBPF_MOVE_MEMORY_IX_CLASSES(table_sbpf_version) ? &&interp_0x9c : &&interp_0x9cdepr;
    interp_jump_table[ table_sbpf_version ][ 0x97 ] = FD_VM_SBPF_MOVE_MEMORY_IX_CLASSES(table_sbpf_version) ? &&interp_0x97 : &&interp_0x97depr;
    interp_jump_table[ table_sbpf_version ][ 0x9f ] = FD_VM_SBPF_MOVE_MEMORY_IX_CLASSES(table_sbpf_version) ? &&interp_0x9f : &&interp_0x9fdepr;

    /* SIMD-0174: PQR */
    interp_jump_table[ table_sbpf_version ][ 0x36 ] = FD_VM_SBPF_ENABLE_PQR (table_sbpf_version) ? &&interp_0x36 : &&sigill;
    interp_jump_table[ table_sbpf_version ][ 0x3e ] = FD_VM_SBPF_ENABLE_PQR (table_sbpf_version) ? &&interp_0x3e : &&sigill;

    interp_jump_table[ table_sbpf_version ][ 0x46 ] = FD_VM_SBPF_ENABLE_PQR (table_sbpf_version) ? &&interp_0x46 : &&sigill;
    interp_jump_table[ table_sbpf_version ][ 0x4e ] = FD_VM_SBPF_ENABLE_PQR (table_sbpf_version) ? &&interp_0x4e : &&sigill;
    interp_jump_table[ table_sbpf_version ][ 0x56 ] = FD_VM_SBPF_ENABLE_PQR (table_sbpf_version) ? &&interp_0x56 : &&sigill;
    interp_jump_table[ table_sbpf_version ][ 0x5e ] = FD_VM_SBPF_ENABLE_PQR (table_sbpf_version) ? &&interp_0x5e : &&sigill;
    interp_jump_table[ table_sbpf_version ][ 0x66 ] = FD_VM_SBPF_ENABLE_PQR (table_sbpf_version) ? &&interp_0x66 : &&sigill;
    interp_jump_table[ table_sbpf_version ][ 0x6e ] = FD_VM_SBPF_ENABLE_PQR (table_sbpf_version) ? &&interp_0x6e : &&sigill;
    interp_jump_table[ table_sbpf_version ][ 0x76 ] = FD_VM_SBPF_ENABLE_PQR (table_sbpf_version) ? &&interp_0x76 : &&sigill;
    interp_jump_table[ table_sbpf_version ][ 0x7e ] = FD_VM_SBPF_ENABLE_PQR (table_sbpf_version) ? &&interp_0x7e : &&sigill;

    interp_jump_table[ table_sbpf_version ][ 0x86 ] = FD_VM_SBPF_ENABLE_PQR (table_sbpf_version) ? &&interp_0x86 : &&sigill;
    interp_jump_table[ table_sbpf_version ][ 0x8e ] = FD_VM_SBPF_ENABLE_PQR (table_sbpf_version) ? &&interp_0x8e : &&sigill;
    interp_jump_table[ table_sbpf_version ][ 0x96 ] = FD_VM_SBPF_ENABLE_PQR (table_sbpf_version) ? &&interp_0x96 : &&sigill;
    interp_jump_table[ table_sbpf_version ][ 0x9e ] = FD_VM_SBPF_ENABLE_PQR (table_sbpf_version) ? &&interp_0x9e : &&sigill;
    interp_jump_table[ table_sbpf_version ][ 0xb6 ] = FD_VM_SBPF_ENABLE_PQR (table_sbpf_version) ? &&interp_0xb6 : &&sigill;
    interp_jump_table[ table_sbpf_version ][ 0xbe ] = FD_VM_SBPF_ENABLE_PQR (table_sbpf_version) ? &&interp_0xbe : &&sigill;

    interp_jump_table[ table_sbpf_version ][ 0xc6 ] = FD_VM_SBPF_ENABLE_PQR (table_sbpf_version) ? &&interp_0xc6 : &&sigill;
    interp_jump_table[ table_sbpf_version ][ 0xce ] = FD_VM_SBPF_ENABLE_PQR (table_sbpf_version) ? &&interp_0xce : &&sigill;
    interp_jump_table[ table_sbpf_version ][ 0xd6 ] = FD_VM_SBPF_ENABLE_PQR (table_sbpf_version) ? &&interp_0xd6 : &&sigill;
    interp_jump_table[ table_sbpf_version ][ 0xde ] = FD_VM_SBPF_ENABLE_PQR (table_sbpf_version) ? &&interp_0xde : &&sigill;
    interp_jump_table[ table_sbpf_version ][ 0xe6 ] = FD_VM_SBPF_ENABLE_PQR (table_sbpf_version) ? &&interp_0xe6 : &&sigill;
    interp_jump_table[ table_sbpf_version ][ 0xee ] = FD_VM_SBPF_ENABLE_PQR (table_sbpf_version) ? &&interp_0xee : &&sigill;
    interp_jump_table[ table_sbpf_version ][ 0xf6 ] = FD_VM_SBPF_ENABLE_PQR (table_sbpf_version) ? &&interp_0xf6 : &&sigill;
    interp_jump_table[ table_sbpf_version ][ 0xfe ] = FD_VM_SBPF_ENABLE_PQR (table_sbpf_version) ? &&interp_0xfe : &&sigill;

    /* SIMD-0174: disable MUL, DIV, MOD */
    interp_jump_table[ table_sbpf_version ][ 0x24 ] = FD_VM_SBPF_ENABLE_PQR (table_sbpf_version) ? &&sigill : &&interp_0x24;
    interp_jump_table[ table_sbpf_version ][ 0x34 ] = FD_VM_SBPF_ENABLE_PQR (table_sbpf_version) ? &&sigill : &&interp_0x34;
    interp_jump_table[ table_sbpf_version ][ 0x94 ] = FD_VM_SBPF_ENABLE_PQR (table_sbpf_version) ? &&sigill : &&interp_0x94;

    /* SIMD-0174: NEG */
    interp_jump_table[ table_sbpf_version ][ 0x84 ] = FD_VM_SBPF_ENABLE_NEG (table_sbpf_version) ? &&interp_0x84 : &&sigill;
    /* note: 0x87 should not be overwritten because it was NEG64 and it becomes STW */

    /* SIMD-0174: Explicit Sign Extension + Register Immediate Subtraction.
      Note: 0x14 is affected by both. */
    interp_jump_table[ table_sbpf_version ][ 0x04 ] = FD_VM_SBPF_EXPLICIT_SIGN_EXT        (table_sbpf_version) ? &&interp_0x04 : &&interp_0x04depr;
    interp_jump_table[ table_sbpf_version ][ 0x0c ] = FD_VM_SBPF_EXPLICIT_SIGN_EXT        (table_sbpf_version) ? &&interp_0x0c : &&interp_0x0cdepr;
    interp_jump_table[ table_sbpf_version ][ 0x1c ] = FD_VM_SBPF_EXPLICIT_SIGN_EXT        (table_sbpf_version) ? &&interp_0x1c : &&interp_0x1cdepr;
    interp_jump_table[ table_sbpf_version ][ 0xbc ] = FD_VM_SBPF_EXPLICIT_SIGN_EXT        (table_sbpf_version) ? &&interp_0xbc : &&interp_0xbcdepr;
    interp_jump_table[ table_sbpf_version ][ 0x14 ] = FD_VM_SBPF_SWAP_SUB_REG_IMM_OPERANDS(table_sbpf_version) ? &&interp_0x14 : &&interp_0x14depr;
    interp_jump_table[ table_sbpf_version ][ 0x17 ] = FD_VM_SBPF_SWAP_SUB_REG_IMM_OPERANDS(table_sbpf_version) ? &&interp_0x17 : &&interp_0x17depr;

    /* SIMD-0178: static syscalls */
    interp_jump_table[ table_sbpf_version ][ 0x85 ] = FD_VM_SBPF_STATIC_SYSCALLS (table_sbpf_version) ? &&interp_0x85 : &&interp_0x85depr;
    interp_jump_table[ table_sbpf_version ][ 0x95 ] = FD_VM_SBPF_STATIC_SYSCALLS (table_sbpf_version) ? &&interp_0x95 : &&interp_0x9d;
    interp_jump_table[ table_sbpf_version ][ 0x9d ] = FD_VM_SBPF_STATIC_SYSCALLS (table_sbpf_version) ? &&interp_0x9d : &&sigill;

    /* SIMD-0173 + SIMD-0179: CALLX */
    interp_jump_table[ table_sbpf_version ][ 0x8d ] = FD_VM_SBPF_STATIC_SYSCALLS (table_sbpf_version) ? &&interp_0x8d : &&interp_0x8ddepr;

  }

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
  ulong offset; /* offset is 16-bit but always sign extended, so we handle cast once */
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
  goto *interp_jump_table[ sbpf_version ][ opcode ]      /* Guaranteed in-bounds */

/* FD_VM_INTERP_SYSCALL_EXEC
   (macro to handle the logic of 0x85 pre- and post- SIMD-0178: static syscalls)

   Setup.
   Update the vm with the current vm execution state for the
   syscall.  Note that BRANCH_BEGIN has pc at the syscall and
   already updated ic and cu to reflect all instructions up to
   and including the syscall instruction itself.

   Execution.
   Do the syscall.  We use ret reduce the risk of the syscall
   accidentally modifying other registers (note however since a
   syscall has the vm handle it still do arbitrary modifications
   to the vm state) and the risk of a pointer escape on reg from
   inhibiting compiler optimizations (this risk is likely low in
   as this is the only point in the whole interpreter core that
   calls outside this translation unit).
   At this point, vm->cu is positive.

   Error handling.
   If we trust syscall implementations to handle the vm state
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
     it also zerod cu.

   At this point, vm->cu is whatever the syscall tried to set
   and cu is positive.

   Exit
   At this point, cu is positive and err is clear.
*/
# define FD_VM_INTERP_SYSCALL_EXEC                                            \
  /* Setup */                                                                 \
  vm->pc        = pc;                                                         \
  vm->ic        = ic;                                                         \
  vm->cu        = cu;                                                         \
  vm->frame_cnt = frame_cnt;                                                  \
  /* Dumping for debugging purposes */                                        \
  if( FD_UNLIKELY( vm->dump_syscall_to_pb ) ) {                               \
    fd_dump_vm_syscall_to_protobuf( vm, syscall->name );                      \
  }                                                                           \
  /* Execution */                                                             \
  ulong ret[1];                                                               \
  err = syscall->func( vm, reg[1], reg[2], reg[3], reg[4], reg[5], ret );     \
  reg[0] = ret[0];                                                            \
  /* Error handling */                                                        \
  ulong cu_req = vm->cu;                                                      \
  cu = fd_ulong_min( cu_req, cu );                                            \
  if( FD_UNLIKELY( err ) ) {                                                  \
    if( err==FD_VM_SYSCALL_ERR_COMPUTE_BUDGET_EXCEEDED ) cu = 0UL; /* cmov */ \
    FD_VM_TEST_ERR_EXISTS( vm );                                              \
    goto sigsyscall;                                                          \
  }                                                                           \
  /* Exit */


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
  shadow[ frame_cnt ].r6  = reg[6];                                                                          \
  shadow[ frame_cnt ].r7  = reg[7];                                                                          \
  shadow[ frame_cnt ].r8  = reg[8];                                                                          \
  shadow[ frame_cnt ].r9  = reg[9];                                                                          \
  shadow[ frame_cnt ].r10 = reg[10];                                                                         \
  shadow[ frame_cnt ].pc  = pc;                                                                              \
  if( FD_UNLIKELY( ++frame_cnt>=frame_max ) ) goto sigstack; /* Note: untaken branches don't consume BTB */ \
  if( !FD_VM_SBPF_DYNAMIC_STACK_FRAMES( sbpf_version ) ) reg[10] += vm->stack_frame_size;

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

  FD_VM_INTERP_INSTR_BEGIN(0x04) /* FD_SBPF_OP_ADD_IMM */
    reg[ dst ] = (ulong)(uint)( (int)reg_dst + (int)imm );
  FD_VM_INTERP_INSTR_END;

  FD_VM_INTERP_INSTR_BEGIN(0x04depr) /* FD_SBPF_OP_ADD_IMM deprecated SIMD-0174 */
    reg[ dst ] = (ulong)(long)( (int)reg_dst + (int)imm );
  FD_VM_INTERP_INSTR_END;

  FD_VM_INTERP_BRANCH_BEGIN(0x05) /* FD_SBPF_OP_JA */
    pc += offset;
  FD_VM_INTERP_BRANCH_END;

  FD_VM_INTERP_INSTR_BEGIN(0x07) /* FD_SBPF_OP_ADD64_IMM */
    reg[ dst ] = reg_dst + (ulong)(long)(int)imm;
  FD_VM_INTERP_INSTR_END;

  FD_VM_INTERP_INSTR_BEGIN(0x0c) /* FD_SBPF_OP_ADD_REG */
    reg[ dst ] = (ulong)(uint)( (int)reg_dst + (int)reg_src );
  FD_VM_INTERP_INSTR_END;

  FD_VM_INTERP_INSTR_BEGIN(0x0cdepr) /* FD_SBPF_OP_ADD_REG deprecated SIMD-0174 */
    reg[ dst ] = (ulong)(long)( (int)reg_dst + (int)reg_src );
  FD_VM_INTERP_INSTR_END;

  FD_VM_INTERP_INSTR_BEGIN(0x0f) /* FD_SBPF_OP_ADD64_REG */
    reg[ dst ] = reg_dst + reg_src;
  FD_VM_INTERP_INSTR_END;

  /* 0x10 - 0x1f ******************************************************/

  FD_VM_INTERP_INSTR_BEGIN(0x14) /* FD_SBPF_OP_SUB_IMM */
    reg[ dst ] = (ulong)(uint)( (int)imm - (int)reg_dst );
  FD_VM_INTERP_INSTR_END;

  FD_VM_INTERP_INSTR_BEGIN(0x14depr) /* FD_SBPF_OP_SUB_IMM deprecated SIMD-0174 */
    reg[ dst ] = (ulong)(long)( (int)reg_dst - (int)imm );
  FD_VM_INTERP_INSTR_END;

  FD_VM_INTERP_BRANCH_BEGIN(0x15) /* FD_SBPF_OP_JEQ_IMM */
    pc += fd_ulong_if( reg_dst==(ulong)(long)(int)imm, offset, 0UL );
  FD_VM_INTERP_BRANCH_END;

  FD_VM_INTERP_INSTR_BEGIN(0x17) /* FD_SBPF_OP_SUB64_IMM */
    reg[ dst ] = (ulong)(long)(int)imm - reg_dst;
  FD_VM_INTERP_INSTR_END;

  FD_VM_INTERP_INSTR_BEGIN(0x17depr) /* FD_SBPF_OP_SUB64_IMM deprecated SIMD-0174 */
    reg[ dst ] = reg_dst - (ulong)(long)(int)imm;
  FD_VM_INTERP_INSTR_END;

  FD_VM_INTERP_INSTR_BEGIN(0x18) /* FD_SBPF_OP_LDQ */
    pc++;
    ic_correction++;
    /* No need to check pc because it's already checked during validation.
       if( FD_UNLIKELY( pc>=text_cnt ) ) goto sigsplit; // Note: untaken branches don't consume BTB */
    reg[ dst ] = (ulong)((ulong)imm | ((ulong)fd_vm_instr_imm( text[ pc ] ) << 32));
  FD_VM_INTERP_INSTR_END;

  FD_VM_INTERP_INSTR_BEGIN(0x1c) /* FD_SBPF_OP_SUB_REG */
    reg[ dst ] = (ulong)(uint)( (int)reg_dst - (int)reg_src );
  FD_VM_INTERP_INSTR_END;

  FD_VM_INTERP_INSTR_BEGIN(0x1cdepr) /* FD_SBPF_OP_SUB_REG deprecated SIMD-0174 */
    reg[ dst ] = (ulong)(long)( (int)reg_dst - (int)reg_src );
  FD_VM_INTERP_INSTR_END;

  FD_VM_INTERP_BRANCH_BEGIN(0x1d) /* FD_SBPF_OP_JEQ_REG */
    pc += fd_ulong_if( reg_dst==reg_src, offset, 0UL );
  FD_VM_INTERP_BRANCH_END;

  FD_VM_INTERP_INSTR_BEGIN(0x1f) /* FD_SBPF_OP_SUB64_REG */
    reg[ dst ] = reg_dst - reg_src;
  FD_VM_INTERP_INSTR_END;

  /* 0x20 - 0x2f ******************************************************/

  FD_VM_INTERP_INSTR_BEGIN(0x24) /* FD_SBPF_OP_MUL_IMM */
    reg[ dst ] = (ulong)(long)( (int)reg_dst * (int)imm );
  FD_VM_INTERP_INSTR_END;

  FD_VM_INTERP_BRANCH_BEGIN(0x25) /* FD_SBPF_OP_JGT_IMM */
    pc += fd_ulong_if( reg_dst>(ulong)(long)(int)imm, offset, 0UL );
  FD_VM_INTERP_BRANCH_END;

  FD_VM_INTERP_INSTR_BEGIN(0x27) { /* FD_SBPF_OP_STB */
    uchar is_multi_region = 0;
    ulong vaddr           = reg_dst + offset;
    ulong haddr           = fd_vm_mem_haddr( vm, vaddr, sizeof(uchar), region_haddr, region_st_sz, 1, 0UL, &is_multi_region );
    if( FD_UNLIKELY( !haddr ) ) {
      vm->segv_vaddr       = vaddr;
      vm->segv_access_type = FD_VM_ACCESS_TYPE_ST;
      goto sigsegv;
    } /* Note: untaken branches don't consume BTB */
    fd_vm_mem_st_1( haddr, (uchar)imm );
  }
  FD_VM_INTERP_INSTR_END;

  FD_VM_INTERP_INSTR_BEGIN(0x2c) { /* FD_SBPF_OP_LDXB */
    uchar is_multi_region = 0;
    ulong vaddr           = reg_src + offset;
    ulong haddr           = fd_vm_mem_haddr( vm, vaddr, sizeof(uchar), region_haddr, region_ld_sz, 0, 0UL, &is_multi_region );
    if( FD_UNLIKELY( !haddr ) ) {
      vm->segv_vaddr       = vaddr;
      vm->segv_access_type = FD_VM_ACCESS_TYPE_LD;
      goto sigsegv;
    } /* Note: untaken branches don't consume BTB */
    reg[ dst ] = fd_vm_mem_ld_1( haddr );
  }
  FD_VM_INTERP_INSTR_END;

  FD_VM_INTERP_BRANCH_BEGIN(0x2d) /* FD_SBPF_OP_JGT_REG */
    pc += fd_ulong_if( reg_dst>reg_src, offset, 0UL );
  FD_VM_INTERP_BRANCH_END;

  FD_VM_INTERP_INSTR_BEGIN(0x2f) { /* FD_SBPF_OP_STXB */
    uchar is_multi_region = 0;
    ulong vaddr           = reg_dst + offset;
    ulong haddr           = fd_vm_mem_haddr( vm, vaddr, sizeof(uchar), region_haddr, region_st_sz, 1, 0UL, &is_multi_region );
    if( FD_UNLIKELY( !haddr ) ) {
      vm->segv_vaddr       = vaddr;
      vm->segv_access_type = FD_VM_ACCESS_TYPE_ST;
      goto sigsegv;
    } /* Note: untaken branches don't consume BTB */ /* FIXME: sigrdonly */
    fd_vm_mem_st_1( haddr, (uchar)reg_src );
  }
  FD_VM_INTERP_INSTR_END;

  FD_VM_INTERP_INSTR_BEGIN(0x27depr) /* FD_SBPF_OP_MUL64_IMM */
    reg[ dst ] = (ulong)( (long)reg_dst * (long)(int)imm );
  FD_VM_INTERP_INSTR_END;

  FD_VM_INTERP_INSTR_BEGIN(0x2cdepr) /* FD_SBPF_OP_MUL_REG */
    reg[ dst ] = (ulong)(long)( (int)reg_dst * (int)reg_src );
  FD_VM_INTERP_INSTR_END;

  FD_VM_INTERP_INSTR_BEGIN(0x2fdepr) /* FD_SBPF_OP_MUL64_REG */
    reg[ dst ] = reg_dst * reg_src;
  FD_VM_INTERP_INSTR_END;

  /* 0x30 - 0x3f ******************************************************/

  FD_VM_INTERP_INSTR_BEGIN(0x34) /* FD_SBPF_OP_DIV_IMM */
    /* FIXME: convert to a multiply at validation time (usually probably
       not worth it) */
    reg[ dst ] = (ulong)((uint)reg_dst / imm);
  FD_VM_INTERP_INSTR_END;

  FD_VM_INTERP_BRANCH_BEGIN(0x35) /* FD_SBPF_OP_JGE_IMM */
    pc += fd_ulong_if( reg_dst>=(ulong)(long)(int)imm, offset, 0UL );
  FD_VM_INTERP_BRANCH_END;

  FD_VM_INTERP_INSTR_BEGIN(0x36) /* FD_SBPF_OP_UHMUL64_IMM */
    reg[ dst ] = (ulong)(( (uint128)reg_dst * (uint128)(ulong)imm ) >> 64 );
  FD_VM_INTERP_INSTR_END;

  FD_VM_INTERP_INSTR_BEGIN(0x37) { /* FD_SBPF_OP_STH */
    uchar is_multi_region = 0;
    ulong vaddr           = reg_dst + offset;
    ulong haddr           = fd_vm_mem_haddr( vm, vaddr, sizeof(ushort), region_haddr, region_st_sz, 1, 0UL, &is_multi_region );
    int   sigsegv         = !haddr;
    if( FD_UNLIKELY( sigsegv ) ) {
      vm->segv_vaddr       = vaddr;
      vm->segv_access_type = FD_VM_ACCESS_TYPE_ST;

      if( vm->direct_mapping ) {
        /* Only execute slow path partial store when direct mapping is enabled.
           Note that Agave implements direct mapping as an UnalignedMemoryMapping.
           When account memory regions are not aligned, there are edge cases that require
           the slow path partial store.
           https://github.com/anza-xyz/sbpf/blob/410a627313124252ab1abbd3a3b686c03301bb2a/src/memory_region.rs#L388-L419 */
        ushort val = (ushort)imm;
        fd_vm_mem_st_try( vm, vaddr, sizeof(ushort), (uchar*)&val );
      }

      goto sigsegv;
    } /* Note: untaken branches don't consume BTB */ /* FIXME: sigbus */
    fd_vm_mem_st_2( vm, vaddr, haddr, (ushort)imm, is_multi_region );
  }
  FD_VM_INTERP_INSTR_END;

  FD_VM_INTERP_INSTR_BEGIN(0x3c) { /* FD_SBPF_OP_LDXH */
    uchar is_multi_region = 0;
    ulong vaddr           = reg_src + offset;
    ulong haddr           = fd_vm_mem_haddr( vm, vaddr, sizeof(ushort), region_haddr, region_ld_sz, 0, 0UL, &is_multi_region );
    int   sigsegv         = !haddr;
    if( FD_UNLIKELY( sigsegv ) ) {
      vm->segv_vaddr       = vaddr;
      vm->segv_access_type = FD_VM_ACCESS_TYPE_LD;
      goto sigsegv; /* Note: untaken branches don't consume BTB */ /* FIXME: sigbus */
    }
    reg[ dst ] = fd_vm_mem_ld_2( vm, vaddr, haddr, is_multi_region );
  }
  FD_VM_INTERP_INSTR_END;

  FD_VM_INTERP_BRANCH_BEGIN(0x3d) /* FD_SBPF_OP_JGE_REG */
    pc += fd_ulong_if( reg_dst>=reg_src, offset, 0UL );
  FD_VM_INTERP_BRANCH_END;

  FD_VM_INTERP_INSTR_BEGIN(0x3f) { /* FD_SBPF_OP_STXH */
    uchar is_multi_region = 0;
    ulong vaddr           = reg_dst + offset;
    ulong haddr           = fd_vm_mem_haddr( vm, vaddr, sizeof(ushort), region_haddr, region_st_sz, 1, 0UL, &is_multi_region );
    int   sigsegv         = !haddr;
    if( FD_UNLIKELY( sigsegv ) ) {
      vm->segv_vaddr       = vaddr;
      vm->segv_access_type = FD_VM_ACCESS_TYPE_ST;

      if( vm->direct_mapping ) {
        /* See FD_SBPF_OP_STH for details */
        ushort val = (ushort)reg_src;
        fd_vm_mem_st_try( vm, vaddr, sizeof(ushort), (uchar*)&val );
      }

      goto sigsegv;
    } /* Note: untaken branches don't consume BTB */ /* FIXME: sigbus */
    fd_vm_mem_st_2( vm, vaddr, haddr, (ushort)reg_src, is_multi_region );
  }
  FD_VM_INTERP_INSTR_END;

  FD_VM_INTERP_INSTR_BEGIN(0x3e) /* FD_SBPF_OP_UHMUL64_REG */
    reg[ dst ] = (ulong)(( (uint128)reg_dst * (uint128)reg_src ) >> 64 );
  FD_VM_INTERP_INSTR_END;

  FD_VM_INTERP_INSTR_BEGIN(0x37depr) /* FD_SBPF_OP_DIV64_IMM */
    reg[ dst ] = reg_dst / (ulong)(long)(int)imm;
  FD_VM_INTERP_INSTR_END;

  FD_VM_INTERP_INSTR_BEGIN(0x3cdepr) /* FD_SBPF_OP_DIV_REG */
    if( FD_UNLIKELY( !(uint)reg_src ) ) goto sigfpe;
    reg[ dst ] = (ulong)((uint)reg_dst / (uint)reg_src);
  FD_VM_INTERP_INSTR_END;

  FD_VM_INTERP_INSTR_BEGIN(0x3fdepr) /* FD_SBPF_OP_DIV64_REG */
    if( FD_UNLIKELY( !reg_src ) ) goto sigfpe;
    reg[ dst ] = reg_dst / reg_src;
  FD_VM_INTERP_INSTR_END;

  /* 0x40 - 0x4f ******************************************************/

  FD_VM_INTERP_INSTR_BEGIN(0x44) /* FD_SBPF_OP_OR_IMM */
    reg[ dst ] = (ulong)( (uint)reg_dst | imm );
  FD_VM_INTERP_INSTR_END;

  FD_VM_INTERP_BRANCH_BEGIN(0x45) /* FD_SBPF_OP_JSET_IMM */
    pc += fd_ulong_if( !!(reg_dst & (ulong)(long)(int)imm), offset, 0UL );
  FD_VM_INTERP_BRANCH_END;

  FD_VM_INTERP_INSTR_BEGIN(0x46) /* FD_SBPF_OP_UDIV32_IMM */
    reg[ dst ] = (ulong)( (uint)reg_dst / (uint)imm );
  FD_VM_INTERP_INSTR_END;

  FD_VM_INTERP_INSTR_BEGIN(0x47) /* FD_SBPF_OP_OR64_IMM */
    reg[ dst ] = reg_dst | (ulong)(long)(int)imm;
  FD_VM_INTERP_INSTR_END;

  FD_VM_INTERP_INSTR_BEGIN(0x4c) /* FD_SBPF_OP_OR_REG */
    reg[ dst ] = (ulong)(uint)( reg_dst | reg_src );
  FD_VM_INTERP_INSTR_END;

  FD_VM_INTERP_BRANCH_BEGIN(0x4d) /* FD_SBPF_OP_JSET_REG */
    pc += fd_ulong_if( !!(reg_dst & reg_src), offset, 0UL );
  FD_VM_INTERP_BRANCH_END;

  FD_VM_INTERP_INSTR_BEGIN(0x4e) /* FD_SBPF_OP_UDIV32_REG */
    if( FD_UNLIKELY( !(uint)reg_src ) ) goto sigfpe;
    reg[ dst ] = (ulong)( (uint)reg_dst / (uint)reg_src );
  FD_VM_INTERP_INSTR_END;

  FD_VM_INTERP_INSTR_BEGIN(0x4f) /* FD_SBPF_OP_OR64_REG */
    reg[ dst ] = reg_dst | reg_src;
  FD_VM_INTERP_INSTR_END;

  /* 0x50 - 0x5f ******************************************************/

  FD_VM_INTERP_INSTR_BEGIN(0x54) /* FD_SBPF_OP_AND_IMM */
    reg[ dst ] = (ulong)( (uint)reg_dst & imm );
  FD_VM_INTERP_INSTR_END;

  FD_VM_INTERP_BRANCH_BEGIN(0x55) /* FD_SBPF_OP_JNE_IMM */
    pc += fd_ulong_if( reg_dst!=(ulong)(long)(int)imm, offset, 0UL );
  FD_VM_INTERP_BRANCH_END;

  FD_VM_INTERP_INSTR_BEGIN(0x56) /* FD_SBPF_OP_UDIV64_IMM */
    reg[ dst ] = reg_dst / (ulong)imm;
  FD_VM_INTERP_INSTR_END;

  FD_VM_INTERP_INSTR_BEGIN(0x57) /* FD_SBPF_OP_AND64_IMM */
    reg[ dst ] = reg_dst & (ulong)(long)(int)imm;
  FD_VM_INTERP_INSTR_END;

  FD_VM_INTERP_INSTR_BEGIN(0x5c) /* FD_SBPF_OP_AND_REG */
    reg[ dst ] = (ulong)(uint)( reg_dst & reg_src );
  FD_VM_INTERP_INSTR_END;

  FD_VM_INTERP_BRANCH_BEGIN(0x5d) /* FD_SBPF_OP_JNE_REG */
    pc += fd_ulong_if( reg_dst!=reg_src, offset, 0UL );
  FD_VM_INTERP_BRANCH_END;

  FD_VM_INTERP_INSTR_BEGIN(0x5e) /* FD_SBPF_OP_UDIV64_REG */
    if( FD_UNLIKELY( !reg_src ) ) goto sigfpe;
    reg[ dst ] = reg_dst / reg_src;
  FD_VM_INTERP_INSTR_END;

  FD_VM_INTERP_INSTR_BEGIN(0x5f) /* FD_SBPF_OP_AND64_REG */
    reg[ dst ] = reg_dst & reg_src;
  FD_VM_INTERP_INSTR_END;

  /* 0x60 - 0x6f ******************************************************/

  /* FIXME: CHECK THE CU COST MODEL FOR THESE (IS IT LIKE
     FD_VM_CONSUME_MEM AND NOT JUST FIXED) */
  /* FIXME: MEM TRACING DIAGNOSTICS GO IN HERE */

  FD_VM_INTERP_INSTR_BEGIN(0x64) /* FD_SBPF_OP_LSH_IMM */
    /* https://github.com/solana-labs/rbpf/blob/8d36530b7071060e2837ebb26f25590db6816048/src/interpreter.rs#L291 */
    reg[ dst ] = (ulong)( FD_RUST_UINT_WRAPPING_SHL( (uint)reg_dst, (uint)imm ) );
  FD_VM_INTERP_INSTR_END;

  FD_VM_INTERP_BRANCH_BEGIN(0x65) /* FD_SBPF_OP_JSGT_IMM */
    pc += fd_ulong_if( (long)reg_dst>(long)(int)imm, offset, 0UL );
  FD_VM_INTERP_BRANCH_END;

  FD_VM_INTERP_INSTR_BEGIN(0x66) /* FD_SBPF_OP_UREM32_IMM */
    reg[ dst ] = (ulong)( (uint)reg_dst % (uint)imm );
  FD_VM_INTERP_INSTR_END;

  FD_VM_INTERP_INSTR_BEGIN(0x67) /* FD_SBPF_OP_LSH64_IMM */
    /* https://github.com/solana-labs/rbpf/blob/8d36530b7071060e2837ebb26f25590db6816048/src/interpreter.rs#L376 */
    reg[ dst ] = FD_RUST_ULONG_WRAPPING_SHL( reg_dst, imm );
  FD_VM_INTERP_INSTR_END;

  FD_VM_INTERP_INSTR_BEGIN(0x6c) /* FD_SBPF_OP_LSH_REG */
    /* https://github.com/solana-labs/rbpf/blob/8d36530b7071060e2837ebb26f25590db6816048/src/interpreter.rs#L292 */
    reg[ dst ] = (ulong)( FD_RUST_UINT_WRAPPING_SHL( (uint)reg_dst, reg_src ) );
  FD_VM_INTERP_INSTR_END;

  FD_VM_INTERP_BRANCH_BEGIN(0x6d) /* FD_SBPF_OP_JSGT_REG */
    pc += fd_ulong_if( (long)reg_dst>(long)reg_src, offset, 0UL );
  FD_VM_INTERP_BRANCH_END;

  FD_VM_INTERP_INSTR_BEGIN(0x6e) /* FD_SBPF_OP_UREM32_REG */
    if( FD_UNLIKELY( !(uint)reg_src ) ) goto sigfpe;
    reg[ dst ] = (ulong)( (uint)reg_dst % (uint)reg_src );
  FD_VM_INTERP_INSTR_END;

  FD_VM_INTERP_INSTR_BEGIN(0x6f) /* FD_SBPF_OP_LSH64_REG */
    /* https://github.com/solana-labs/rbpf/blob/8d36530b7071060e2837ebb26f25590db6816048/src/interpreter.rs#L377 */
    reg[ dst ] = FD_RUST_ULONG_WRAPPING_SHL( reg_dst, reg_src );
  FD_VM_INTERP_INSTR_END;

  /* 0x70 - 0x7f ******************************************************/

  FD_VM_INTERP_INSTR_BEGIN(0x74) /* FD_SBPF_OP_RSH_IMM */
    /* https://github.com/solana-labs/rbpf/blob/8d36530b7071060e2837ebb26f25590db6816048/src/interpreter.rs#L293 */
    reg[ dst ] = (ulong)( FD_RUST_UINT_WRAPPING_SHR( (uint)reg_dst, imm ) );
  FD_VM_INTERP_INSTR_END;

  FD_VM_INTERP_BRANCH_BEGIN(0x75) /* FD_SBPF_OP_JSGE_IMM */
    pc += fd_ulong_if( (long)reg_dst>=(long)(int)imm, offset, 0UL );
  FD_VM_INTERP_BRANCH_END;

  FD_VM_INTERP_INSTR_BEGIN(0x76) /* FD_SBPF_OP_UREM64_IMM */
    reg[ dst ] = reg_dst % (ulong)imm;
  FD_VM_INTERP_INSTR_END;

  FD_VM_INTERP_INSTR_BEGIN(0x77) /* FD_SBPF_OP_RSH64_IMM */
    /* https://github.com/solana-labs/rbpf/blob/8d36530b7071060e2837ebb26f25590db6816048/src/interpreter.rs#L378 */
    reg[ dst ] = FD_RUST_ULONG_WRAPPING_SHR( reg_dst, imm );
  FD_VM_INTERP_INSTR_END;

  FD_VM_INTERP_INSTR_BEGIN(0x7c) /* FD_SBPF_OP_RSH_REG */
    /* https://github.com/solana-labs/rbpf/blob/8d36530b7071060e2837ebb26f25590db6816048/src/interpreter.rs#L294 */
    reg[ dst ] = (ulong)( FD_RUST_UINT_WRAPPING_SHR( (uint)reg_dst, (uint)reg_src ) );
  FD_VM_INTERP_INSTR_END;

  FD_VM_INTERP_BRANCH_BEGIN(0x7d) /* FD_SBPF_OP_JSGE_REG */
    pc += fd_ulong_if( (long)reg_dst>=(long)reg_src, offset, 0UL );
  FD_VM_INTERP_BRANCH_END;

  FD_VM_INTERP_INSTR_BEGIN(0x7e) /* FD_SBPF_OP_UREM64_REG */
    if( FD_UNLIKELY( !reg_src ) ) goto sigfpe;
    reg[ dst ] = reg_dst % reg_src;
  FD_VM_INTERP_INSTR_END;

  FD_VM_INTERP_INSTR_BEGIN(0x7f) /* FD_SBPF_OP_RSH64_REG */
    /* https://github.com/solana-labs/rbpf/blob/8d36530b7071060e2837ebb26f25590db6816048/src/interpreter.rs#L379 */
    reg[ dst ] = FD_RUST_ULONG_WRAPPING_SHR( reg_dst, reg_src );
  FD_VM_INTERP_INSTR_END;

  /* 0x80-0x8f ********************************************************/

  FD_VM_INTERP_INSTR_BEGIN(0x84) /* FD_SBPF_OP_NEG */
    reg[ dst ] = (ulong)( -(uint)reg_dst );
  FD_VM_INTERP_INSTR_END;

  FD_VM_INTERP_BRANCH_BEGIN(0x85) /* FD_SBPF_OP_CALL_IMM */
    /* imm has already been validated */
    FD_VM_INTERP_STACK_PUSH;
    pc = (ulong)( (long)pc + (long)(int)imm );
  FD_VM_INTERP_BRANCH_END;

  FD_VM_INTERP_BRANCH_BEGIN(0x85depr) { /* FD_SBPF_OP_CALL_IMM */

    fd_sbpf_syscalls_t const * syscall = imm!=fd_sbpf_syscalls_key_null() ? fd_sbpf_syscalls_query_const( syscalls, (ulong)imm, NULL ) : NULL;
    if( FD_UNLIKELY( !syscall ) ) { /* Optimize for the syscall case */

      /* Note we do the stack push before updating the pc(*). This implies
       that the call stack frame gets allocated _before_ checking if the
       call target is valid.  It would be fine to switch the order
       though such would change the precise faulting semantics of
       sigtextbr and sigstack.

       (*)but after checking calldests, see point below. */

      /* Agave's order of checks
         (https://github.com/solana-labs/rbpf/blob/v0.8.5/src/interpreter.rs#L486):
          1. Lookup imm hash in FunctionRegistry (calldests_test is our equivalent)
          2. Push stack frame
          3. Check PC
          4. Update PC

          Following this precisely is impossible as our PC check also
          serves as a bounds check for the calldests_test call. So we
          have to perform step 3 before step 1. The following
          is a best-effort implementation that should match the VM state
          in all ways except error code. */

      /* Special case to handle entrypoint.
         ebpf::hash_symbol_name(b"entrypoint") = 0xb00c380, and
         fd_pchash_inverse( 0xb00c380U ) = 0x71e3cf81U */
      if( FD_UNLIKELY( imm==0x71e3cf81U ) ) {
        FD_VM_INTERP_STACK_PUSH;
        pc = entry_pc - 1;
      } else {
        ulong target_pc = (ulong)fd_pchash_inverse( imm );
        if( FD_UNLIKELY( target_pc>=text_cnt ) ) {
          goto sigillbr; /* different return between 0x85 and 0x8d */
        }
        if( FD_UNLIKELY( !fd_sbpf_calldests_test( calldests, target_pc ) ) ) {
          goto sigillbr;
        }
        FD_VM_INTERP_STACK_PUSH;
        pc = target_pc - 1;
      }

    } else {

      FD_VM_INTERP_SYSCALL_EXEC;

    }
  } FD_VM_INTERP_BRANCH_END;

  FD_VM_INTERP_INSTR_BEGIN(0x86) /* FD_SBPF_OP_LMUL32_IMM */
    reg[ dst ] = (ulong)( (uint)reg_dst * imm );
  FD_VM_INTERP_INSTR_END;

  FD_VM_INTERP_INSTR_BEGIN(0x87) { /* FD_SBPF_OP_STW */
    uchar is_multi_region = 0;
    ulong vaddr           = reg_dst + offset;
    ulong haddr           = fd_vm_mem_haddr( vm, vaddr, sizeof(uint), region_haddr, region_st_sz, 1, 0UL, &is_multi_region );
    int   sigsegv         = !haddr;
    if( FD_UNLIKELY( sigsegv ) ) {
      vm->segv_vaddr       = vaddr;
      vm->segv_access_type = FD_VM_ACCESS_TYPE_ST;

      if( vm->direct_mapping ) {
        /* See FD_SBPF_OP_STH for details */
        uint val = (uint)imm;
        fd_vm_mem_st_try( vm, vaddr, sizeof(uint), (uchar*)&val );
      }

      goto sigsegv;
    } /* Note: untaken branches don't consume BTB */ /* FIXME: sigbus */
    fd_vm_mem_st_4( vm, vaddr, haddr, imm, is_multi_region );
  } FD_VM_INTERP_INSTR_END;

  FD_VM_INTERP_INSTR_BEGIN(0x87depr) /* FD_SBPF_OP_NEG64 deprecated */
    reg[ dst ] = -reg_dst;
  FD_VM_INTERP_INSTR_END;

  FD_VM_INTERP_INSTR_BEGIN(0x8c) { /* FD_SBPF_OP_LDXW */
    uchar is_multi_region = 0;
    ulong vaddr           = reg_src + offset;
    ulong haddr           = fd_vm_mem_haddr( vm, vaddr, sizeof(uint), region_haddr, region_ld_sz, 0, 0UL, &is_multi_region );
    int   sigsegv         = !haddr;
    if( FD_UNLIKELY( sigsegv ) ) {
      vm->segv_vaddr       = vaddr;
      vm->segv_access_type = FD_VM_ACCESS_TYPE_LD;
      goto sigsegv; /* Note: untaken branches don't consume BTB */ /* FIXME: sigbus */
    }
    reg[ dst ] = fd_vm_mem_ld_4( vm, vaddr, haddr, is_multi_region );
  }
  FD_VM_INTERP_INSTR_END;

  FD_VM_INTERP_BRANCH_BEGIN(0x8d) { /* FD_SBPF_OP_CALL_REG */
    FD_VM_INTERP_STACK_PUSH;
    ulong target_pc = (reg_src - vm->text_off) / 8UL;
    if( FD_UNLIKELY( target_pc>=text_cnt ) ) goto sigtextbr;
    if( FD_UNLIKELY( !fd_sbpf_calldests_test( calldests, target_pc ) ) ) {
      goto sigillbr;
    }
    pc = target_pc - 1;
  } FD_VM_INTERP_BRANCH_END;

  FD_VM_INTERP_BRANCH_BEGIN(0x8ddepr) { /* FD_SBPF_OP_CALL_REG */

    FD_VM_INTERP_STACK_PUSH;

    ulong vaddr = FD_VM_SBPF_CALLX_USES_SRC_REG(sbpf_version) ? reg_src : reg[ imm & 15U ];

    /* Notes: Agave checks region and target_pc before updating the pc.
       To match their state, we do the same, even though we could simply
       update the pc and let BRANCH_END fail.
       Also, Agave doesn't check alignment. */

    ulong region = vaddr >> 32;
    /* ulong align  = vaddr & 7UL; */
    ulong target_pc = ((vaddr & FD_VM_OFFSET_MASK) - vm->text_off) / 8UL;
    if( FD_UNLIKELY( (region!=1UL) | (target_pc>=text_cnt) ) ) goto sigtextbr; /* Note: untaken branches don't consume BTB */
    pc = target_pc - 1;

  } FD_VM_INTERP_BRANCH_END;

  FD_VM_INTERP_INSTR_BEGIN(0x8e) /* FD_SBPF_OP_LMUL32_REG */
    reg[ dst ] = (ulong)( (uint)reg_dst * (uint)reg_src );
  FD_VM_INTERP_INSTR_END;

  FD_VM_INTERP_INSTR_BEGIN(0x8f) { /* FD_SBPF_OP_STXW */
    uchar is_multi_region = 0;
    ulong vaddr           = reg_dst + offset;
    ulong haddr           = fd_vm_mem_haddr( vm, vaddr, sizeof(uint), region_haddr, region_st_sz, 1, 0UL, &is_multi_region );
    int   sigsegv         = !haddr;
    if( FD_UNLIKELY( sigsegv ) ) {
      vm->segv_vaddr       = vaddr;
      vm->segv_access_type = FD_VM_ACCESS_TYPE_ST;

      if( vm->direct_mapping ) {
        /* See FD_SBPF_OP_STH for details */
        uint val = (uint)reg_src;
        fd_vm_mem_st_try( vm, vaddr, sizeof(uint), (uchar*)&val );
      }

      goto sigsegv;
    } /* Note: untaken branches don't consume BTB */ /* FIXME: sigbus */
    fd_vm_mem_st_4( vm, vaddr, haddr, (uint)reg_src, is_multi_region );
  }
  FD_VM_INTERP_INSTR_END;

  /* 0x90 - 0x9f ******************************************************/

  FD_VM_INTERP_INSTR_BEGIN(0x94) /* FD_SBPF_OP_MOD_IMM */
    reg[ dst ] = (ulong)( (uint)reg_dst % imm );
  FD_VM_INTERP_INSTR_END;

  FD_VM_INTERP_BRANCH_BEGIN(0x95) { /* FD_SBPF_OP_SYSCALL */
    /* imm has already been validated */
    fd_sbpf_syscalls_t const * syscall = fd_sbpf_syscalls_query_const( syscalls, (ulong)imm, NULL );
    if( FD_UNLIKELY( !syscall ) ) goto sigillbr;

    FD_VM_INTERP_SYSCALL_EXEC;

  } FD_VM_INTERP_BRANCH_END;

  FD_VM_INTERP_INSTR_BEGIN(0x96) /* FD_SBPF_OP_LMUL64_IMM */
    reg[ dst ] = reg_dst * (ulong)(long)(int)imm;
  FD_VM_INTERP_INSTR_END;

  FD_VM_INTERP_INSTR_BEGIN(0x97) { /* FD_SBPF_OP_STQ */
    uchar is_multi_region = 0;
    ulong vaddr           = reg_dst + offset;
    ulong haddr           = fd_vm_mem_haddr( vm, vaddr, sizeof(ulong), region_haddr, region_st_sz, 1, 0UL, &is_multi_region );
    int   sigsegv         = !haddr;
    if( FD_UNLIKELY( sigsegv ) ) {
      vm->segv_vaddr       = vaddr;
      vm->segv_access_type = FD_VM_ACCESS_TYPE_ST;

      if( vm->direct_mapping ) {
        /* See FD_SBPF_OP_STH for details */
        ulong val = (ulong)(long)(int)imm;
        fd_vm_mem_st_try( vm, vaddr, sizeof(ulong), (uchar*)&val );
      }

      goto sigsegv;
    } /* Note: untaken branches don't consume BTB */ /* FIXME: sigbus */
    fd_vm_mem_st_8( vm, vaddr, haddr, (ulong)(long)(int)imm, is_multi_region );
  }
  FD_VM_INTERP_INSTR_END;

  FD_VM_INTERP_INSTR_BEGIN(0x9c) { /* FD_SBPF_OP_LDXQ */
    uchar is_multi_region = 0;
    ulong vaddr           = reg_src + offset;
    ulong haddr           = fd_vm_mem_haddr( vm, vaddr, sizeof(ulong), region_haddr, region_ld_sz, 0, 0UL, &is_multi_region );
    int   sigsegv         = !haddr;
    if( FD_UNLIKELY( sigsegv ) ) {
      vm->segv_vaddr       = vaddr;
      vm->segv_access_type = FD_VM_ACCESS_TYPE_LD;
      goto sigsegv; /* Note: untaken branches don't consume BTB */ /* FIXME: sigbus */
    }
    reg[ dst ] = fd_vm_mem_ld_8( vm, vaddr, haddr, is_multi_region );
  }
  FD_VM_INTERP_INSTR_END;

  FD_VM_INTERP_BRANCH_BEGIN(0x9d) /* FD_SBPF_OP_EXIT */
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
    reg[10]  = shadow[ frame_cnt ].r10;
    pc       = shadow[ frame_cnt ].pc;
  FD_VM_INTERP_BRANCH_END;

  FD_VM_INTERP_INSTR_BEGIN(0x9e) /* FD_SBPF_OP_LMUL64_REG */
    reg[ dst ] = reg_dst * reg_src;
  FD_VM_INTERP_INSTR_END;

  FD_VM_INTERP_INSTR_BEGIN(0x9f) { /* FD_SBPF_OP_STXQ */
    uchar is_multi_region = 0;
    ulong vaddr           = reg_dst + offset;
    ulong haddr           = fd_vm_mem_haddr( vm, vaddr, sizeof(ulong), region_haddr, region_st_sz, 1, 0UL, &is_multi_region );
    int   sigsegv         = !haddr;
    if( FD_UNLIKELY( sigsegv ) ) {
      vm->segv_vaddr       = vaddr;
      vm->segv_access_type = FD_VM_ACCESS_TYPE_ST;

      if( vm->direct_mapping ) {
        /* See FD_SBPF_OP_STH for details */
        fd_vm_mem_st_try( vm, vaddr, sizeof(ulong), (uchar*)&reg_src );
      }

      goto sigsegv;
    } /* Note: untaken branches don't consume BTB */ /* FIXME: sigbus */
    fd_vm_mem_st_8( vm, vaddr, haddr, reg_src, is_multi_region );
  }
  FD_VM_INTERP_INSTR_END;

  FD_VM_INTERP_INSTR_BEGIN(0x97depr) /* FD_SBPF_OP_MOD64_IMM */
    reg[ dst ] = reg_dst % (ulong)(long)(int)imm;
  FD_VM_INTERP_INSTR_END;

  FD_VM_INTERP_INSTR_BEGIN(0x9cdepr) /* FD_SBPF_OP_MOD_REG */
    if( FD_UNLIKELY( !(uint)reg_src ) ) goto sigfpe;
    reg[ dst ] = (ulong)( ((uint)reg_dst % (uint)reg_src) );
  FD_VM_INTERP_INSTR_END;

  FD_VM_INTERP_INSTR_BEGIN(0x9fdepr) /* FD_SBPF_OP_MOD64_REG */
    if( FD_UNLIKELY( !reg_src ) ) goto sigfpe;
    reg[ dst ] = reg_dst % reg_src;
  FD_VM_INTERP_INSTR_END;

  /* 0xa0 - 0xaf ******************************************************/

  FD_VM_INTERP_INSTR_BEGIN(0xa4) /* FD_SBPF_OP_XOR_IMM */
    reg[ dst ] = (ulong)( (uint)reg_dst ^ imm );
  FD_VM_INTERP_INSTR_END;

  FD_VM_INTERP_BRANCH_BEGIN(0xa5) /* FD_SBPF_OP_JLT_IMM */
    pc += fd_ulong_if( reg_dst<(ulong)(long)(int)imm, offset, 0UL );
  FD_VM_INTERP_BRANCH_END;

  FD_VM_INTERP_INSTR_BEGIN(0xa7) /* FD_SBPF_OP_XOR64_IMM */
    reg[ dst ] = reg_dst ^ (ulong)(long)(int)imm;
  FD_VM_INTERP_INSTR_END;

  FD_VM_INTERP_INSTR_BEGIN(0xac) /* FD_SBPF_OP_XOR_REG */
    reg[ dst ] = (ulong)(uint)( reg_dst ^ reg_src );
  FD_VM_INTERP_INSTR_END;

  FD_VM_INTERP_BRANCH_BEGIN(0xad) /* FD_SBPF_OP_JLT_REG */
    pc += fd_ulong_if( reg_dst<reg_src, offset, 0UL );
  FD_VM_INTERP_BRANCH_END;

  FD_VM_INTERP_INSTR_BEGIN(0xaf) /* FD_SBPF_OP_XOR64_REG */
    reg[ dst ] = reg_dst ^ reg_src;
  FD_VM_INTERP_INSTR_END;

  /* 0xb0 - 0xbf ******************************************************/

  FD_VM_INTERP_INSTR_BEGIN(0xb4) /* FD_SBPF_OP_MOV_IMM */
    reg[ dst ] = (ulong)imm;
  FD_VM_INTERP_INSTR_END;

  FD_VM_INTERP_BRANCH_BEGIN(0xb5) /* FD_SBPF_OP_JLE_IMM */
    pc += fd_ulong_if( reg_dst<=(ulong)(long)(int)imm, offset, 0UL );
  FD_VM_INTERP_BRANCH_END;

  FD_VM_INTERP_INSTR_BEGIN(0xb6) /* FD_SBPF_OP_SHMUL64_IMM */
    reg[ dst ] = (ulong)(( (int128)(long)reg_dst * (int128)(long)(int)imm ) >> 64 );
  FD_VM_INTERP_INSTR_END;

  FD_VM_INTERP_INSTR_BEGIN(0xb7) /* FD_SBPF_OP_MOV64_IMM */
    reg[ dst ] = (ulong)(long)(int)imm;
  FD_VM_INTERP_INSTR_END;

  FD_VM_INTERP_INSTR_BEGIN(0xbc) /* FD_SBPF_OP_MOV_REG */
    reg[ dst ] = (ulong)(long)(int)reg_src;
  FD_VM_INTERP_INSTR_END;

  FD_VM_INTERP_INSTR_BEGIN(0xbcdepr) /* FD_SBPF_OP_MOV_REG deprecated SIMD-1074 */
    reg[ dst ] = (ulong)(uint)reg_src;
  FD_VM_INTERP_INSTR_END;

  FD_VM_INTERP_BRANCH_BEGIN(0xbd) /* FD_SBPF_OP_JLE_REG */
    pc += fd_ulong_if( reg_dst<=reg_src, offset, 0UL );
  FD_VM_INTERP_BRANCH_END;

  FD_VM_INTERP_INSTR_BEGIN(0xbe) /* FD_SBPF_OP_SHMUL64_REG */
    reg[ dst ] = (ulong)(( (int128)(long)reg_dst * (int128)(long)reg_src ) >> 64 );
  FD_VM_INTERP_INSTR_END;

  FD_VM_INTERP_INSTR_BEGIN(0xbf) /* FD_SBPF_OP_MOV64_REG */
    reg[ dst ] = reg_src;
  FD_VM_INTERP_INSTR_END;

  /* 0xc0 - 0xcf ******************************************************/

  FD_VM_INTERP_INSTR_BEGIN(0xc4) /* FD_SBPF_OP_ARSH_IMM */
    reg[ dst ] = (ulong)(uint)( (int)reg_dst >> imm ); /* FIXME: WIDE SHIFTS, STRICT SIGN EXTENSION */
  FD_VM_INTERP_INSTR_END;

  FD_VM_INTERP_BRANCH_BEGIN(0xc5) /* FD_SBPF_OP_JSLT_IMM */ /* FIXME: CHECK IMM SIGN EXTENSION */
    pc += fd_ulong_if( (long)reg_dst<(long)(int)imm, offset, 0UL );
  FD_VM_INTERP_BRANCH_END;

  FD_VM_INTERP_INSTR_BEGIN(0xc6) /* FD_SBPF_OP_SDIV32_IMM */
    if( FD_UNLIKELY( ((int)reg_dst==INT_MIN) & ((int)imm==-1) ) ) goto sigfpeof;
    reg[ dst ] = (ulong)(uint)( (int)reg_dst / (int)imm );
  FD_VM_INTERP_INSTR_END;

  FD_VM_INTERP_INSTR_BEGIN(0xc7) /* FD_SBPF_OP_ARSH64_IMM */
    reg[ dst ] = (ulong)( (long)reg_dst >> imm ); /* FIXME: WIDE SHIFTS, STRICT SIGN EXTENSION */
  FD_VM_INTERP_INSTR_END;

  FD_VM_INTERP_INSTR_BEGIN(0xcc) /* FD_SBPF_OP_ARSH_REG */
    reg[ dst ] = (ulong)(uint)( (int)reg_dst >> (uint)reg_src ); /* FIXME: WIDE SHIFTS, STRICT SIGN EXTENSION */
  FD_VM_INTERP_INSTR_END;

  FD_VM_INTERP_BRANCH_BEGIN(0xcd) /* FD_SBPF_OP_JSLT_REG */
    pc += fd_ulong_if( (long)reg_dst<(long)reg_src, offset, 0UL );
  FD_VM_INTERP_BRANCH_END;

  FD_VM_INTERP_INSTR_BEGIN(0xce) /* FD_SBPF_OP_SDIV32_REG */
    if( FD_UNLIKELY( !(int)reg_src ) ) goto sigfpe;
    if( FD_UNLIKELY( ((int)reg_dst==INT_MIN) & ((int)reg_src==-1) ) ) goto sigfpeof;
    reg[ dst ] = (ulong)(uint)( (int)reg_dst / (int)reg_src );
  FD_VM_INTERP_INSTR_END;

  FD_VM_INTERP_INSTR_BEGIN(0xcf) /* FD_SBPF_OP_ARSH64_REG */
    reg[ dst ] = (ulong)( (long)reg_dst >> reg_src ); /* FIXME: WIDE SHIFTS, STRICT SIGN EXTENSION */
  FD_VM_INTERP_INSTR_END;

  /* 0xd0 - 0xdf ******************************************************/

  FD_VM_INTERP_INSTR_BEGIN(0xd4) /* FD_SBPF_OP_END_LE */
    switch( imm ) {
    case 16U: reg[ dst ] = (ushort)reg_dst; break;
    case 32U: reg[ dst ] = (uint)  reg_dst; break;
    case 64U:                               break;
    default: goto siginv;
    }
  FD_VM_INTERP_INSTR_END;

  FD_VM_INTERP_BRANCH_BEGIN(0xd5) /* FD_SBPF_OP_JSLE_IMM */
    pc += fd_ulong_if( (long)reg_dst<=(long)(int)imm, offset, 0UL );
  FD_VM_INTERP_BRANCH_END;

  FD_VM_INTERP_INSTR_BEGIN(0xd6) /* FD_SBPF_OP_SDIV64_IMM */
    if( FD_UNLIKELY( ((long)reg_dst==LONG_MIN) & ((long)(int)imm==-1L) ) ) goto sigfpeof;
    reg[ dst ] = (ulong)( (long)reg_dst / (long)(int)imm );
  FD_VM_INTERP_INSTR_END;

  FD_VM_INTERP_INSTR_BEGIN(0xdc) /* FD_SBPF_OP_END_BE */
    switch( imm ) {
    case 16U: reg[ dst ] = (ulong)fd_ushort_bswap( (ushort)reg_dst ); break;
    case 32U: reg[ dst ] = (ulong)fd_uint_bswap  ( (uint)  reg_dst ); break;
    case 64U: reg[ dst ] =        fd_ulong_bswap ( (ulong) reg_dst ); break;
    default: goto siginv;
    }
  FD_VM_INTERP_INSTR_END;

  FD_VM_INTERP_BRANCH_BEGIN(0xdd) /* FD_SBPF_OP_JSLE_REG */
    pc += fd_ulong_if( (long)reg_dst<=(long)reg_src, offset, 0UL );
  FD_VM_INTERP_BRANCH_END;

  FD_VM_INTERP_INSTR_BEGIN(0xde) /* FD_SBPF_OP_SDIV64_REG */
    if( FD_UNLIKELY( !reg_src ) ) goto sigfpe;
    if( FD_UNLIKELY( ((long)reg_dst==LONG_MIN) & ((long)reg_src==-1L) ) ) goto sigfpeof;
    reg[ dst ] = (ulong)( (long)reg_dst / (long)reg_src );
  FD_VM_INTERP_INSTR_END;

  /* 0xe0 - 0xef ******************************************************/

  FD_VM_INTERP_INSTR_BEGIN(0xe6) /* FD_SBPF_OP_SREM32_IMM */
    if( FD_UNLIKELY( ((int)reg_dst==INT_MIN) & ((int)imm==-1) ) ) goto sigfpeof;
    reg[ dst ] = (ulong)(uint)( (int)reg_dst % (int)imm );
  FD_VM_INTERP_INSTR_END;

  FD_VM_INTERP_INSTR_BEGIN(0xee) /* FD_SBPF_OP_SREM32_REG */
    if( FD_UNLIKELY( !(int)reg_src ) ) goto sigfpe;
    if( FD_UNLIKELY( ((int)reg_dst==INT_MIN) & ((int)reg_src==-1) ) ) goto sigfpeof;
    reg[ dst ] = (ulong)(uint)( (int)reg_dst % (int)reg_src );
  FD_VM_INTERP_INSTR_END;

  /* 0xf0 - 0xff ******************************************************/

  FD_VM_INTERP_INSTR_BEGIN(0xf6) /* FD_SBPF_OP_SREM64_IMM */
    if( FD_UNLIKELY( ((long)reg_dst==LONG_MIN) & ((long)(int)imm==-1L) ) ) goto sigfpeof;
    reg[ dst ] = (ulong)( (long)reg_dst % (long)(int)imm );
  FD_VM_INTERP_INSTR_END;

  FD_VM_INTERP_BRANCH_BEGIN(0xf7) /* FD_SBPF_OP_HOR64 */
    reg[ dst ] = reg_dst | (((ulong)imm) << 32);
  FD_VM_INTERP_BRANCH_END;

  FD_VM_INTERP_INSTR_BEGIN(0xfe) /* FD_SBPF_OP_SREM64_REG */
    if( FD_UNLIKELY( !reg_src ) ) goto sigfpe;
    if( FD_UNLIKELY( ((long)reg_dst==LONG_MIN) & ((long)reg_src==-1L) ) ) goto sigfpeof;
    reg[ dst ] = (ulong)( (long)reg_dst % (long)reg_src );
  FD_VM_INTERP_INSTR_END;

  /* FIXME: sigbus/sigrdonly are mapped to sigsegv for simplicity
     currently but could be enabled if desired. */

  /* Note: sigtextbr is for sigtext errors that occur on branching
     instructions (i.e., prefixed with FD_VM_INTERP_BRANCH_BEGIN).
     We skip a repeat ic accumulation in FD_VM_INTERP_FAULT */

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

#define FD_VM_INTERP_FAULT                                                                 \
  ic_correction = pc - pc0 + 1UL - ic_correction;                                          \
  ic += ic_correction;                                                                     \
  if ( FD_UNLIKELY( ic_correction > cu ) ) err = FD_VM_ERR_EBPF_EXCEEDED_MAX_INSTRUCTIONS; \
  cu -= fd_ulong_min( ic_correction, cu )

sigtext:     err = FD_VM_ERR_EBPF_EXECUTION_OVERRUN;                                     FD_VM_INTERP_FAULT;                    goto interp_halt;
sigtextbr:   err = FD_VM_ERR_EBPF_CALL_OUTSIDE_TEXT_SEGMENT;                             /* ic current */     /* cu current */  goto interp_halt;
sigstack:    err = FD_VM_ERR_EBPF_CALL_DEPTH_EXCEEDED;                                   /* ic current */     /* cu current */  goto interp_halt;
sigill:      err = FD_VM_ERR_EBPF_UNSUPPORTED_INSTRUCTION;                               FD_VM_INTERP_FAULT;                    goto interp_halt;
sigillbr:    err = FD_VM_ERR_EBPF_UNSUPPORTED_INSTRUCTION;                               /* ic current */     /* cu current */  goto interp_halt;
siginv:      err = FD_VM_ERR_EBPF_INVALID_INSTRUCTION;                                   /* ic current */     /* cu current */  goto interp_halt;
sigsegv:     err = fd_vm_generate_access_violation( vm->segv_vaddr, vm->sbpf_version );  FD_VM_INTERP_FAULT;                    goto interp_halt;
sigcost:     err = FD_VM_ERR_EBPF_EXCEEDED_MAX_INSTRUCTIONS;                             /* ic current */     cu = 0UL;         goto interp_halt;
sigsyscall:  err = FD_VM_ERR_EBPF_SYSCALL_ERROR;                                         /* ic current */     /* cu current */  goto interp_halt;
sigfpe:      err = FD_VM_ERR_EBPF_DIVIDE_BY_ZERO;                                        FD_VM_INTERP_FAULT;                    goto interp_halt;
sigfpeof:    err = FD_VM_ERR_EBPF_DIVIDE_OVERFLOW;                                       FD_VM_INTERP_FAULT;                    goto interp_halt;
sigexit:     /* err current */                                                           /* ic current */     /* cu current */  goto interp_halt;

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
