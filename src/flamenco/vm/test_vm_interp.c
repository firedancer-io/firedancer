#include "fd_vm.h"
#include "fd_vm_base.h"
#include "fd_vm_private.h"
#include "test_vm_util.h"
#include "../runtime/fd_bank.h"
#include "../../ballet/sbpf/fd_sbpf_instr.h"
#include "../../ballet/sbpf/fd_sbpf_opcodes.h"
#include "../../ballet/murmur3/fd_murmur3.h"
#include <stdlib.h>  /* malloc */

static int
accumulator_syscall( /**/            void *  _vm,
                     /**/            ulong   arg0,
                     /**/            ulong   arg1,
                     /**/            ulong   arg2,
                     /**/            ulong   arg3,
                     /**/            ulong   arg4 ) {
  fd_vm_t * vm = (fd_vm_t *)_vm;
  vm->reg[0] = arg0 + arg1 + arg2 + arg3 + arg4;
  return 0;
}

/* Returns the number of instructions executed */
static ulong
test_program_exec( char *                   test_case_name,
                      ulong                 expected_result,
                      int                   expected_err,
                      ulong                 cu_limit,
                      ulong                 sbpf_version,
                      ulong const *         text,
                      ulong                 text_cnt,
                      fd_sbpf_syscalls_t *  syscalls,
                      fd_exec_instr_ctx_t * instr_ctx ) {

  fd_sha256_t _sha[1];
  fd_sha256_t * sha = fd_sha256_join( fd_sha256_new( _sha ) );

  fd_vm_t _vm[1];
  fd_vm_t * vm = fd_vm_join( fd_vm_new( _vm ) );
  FD_TEST( vm );

  int vm_ok = !!fd_vm_init(
      /* vm                                     */ vm,
      /* instr_ctx                              */ instr_ctx,
      /* heap_max                               */ FD_VM_HEAP_DEFAULT,
      /* entry_cu                               */ cu_limit,
      /* rodata                                 */ (uchar *)text,
      /* rodata_sz                              */ 8UL*text_cnt,
      /* text                                   */ text,
      /* text_cnt                               */ text_cnt,
      /* text_off                               */ 0UL,
      /* text_sz                                */ 8UL*text_cnt,
      /* entry_pc                               */ 0UL,
      /* calldests                              */ NULL,
      /* sbpf_version                           */ sbpf_version,
      /* syscalls                               */ syscalls,
      /* trace                                  */ NULL,
      /* sha                                    */ sha,
      /* mem_regions                            */ NULL,
      /* mem_regions_cnt                        */ 0UL,
      /* mem_regions_accs                       */ NULL,
      /* is_deprecated                          */ 0,
      /* dump_syscall_to_pb                     */ 0,
      /* reg                                    */ (ulong[ FD_VM_REG_CNT ]){ 0 }
  );
  FD_TEST( vm_ok );

  /* FIXME: GROSS */
  vm->pc        = vm->entry_pc;
  vm->ic        = 0UL;
  vm->cu        = vm->entry_cu;
  vm->frame_cnt = 0UL;
  vm->heap_sz   = 0UL;
  fd_vm_mem_cfg( vm );

  int err = fd_vm_validate( vm );
  if( FD_UNLIKELY( err ) ) FD_LOG_ERR(( "validation failed: %i-%s", err, fd_vm_strerror( err ) ));

  long dt = -fd_log_wallclock();
  err = fd_vm_exec( vm );
  dt += fd_log_wallclock();

  if( FD_UNLIKELY( err!=expected_err ) ) {
    FD_LOG_WARNING(( "Expected err %i (%s), got %i (%s)",
                     expected_err, fd_vm_strerror( expected_err ),
                     err,          fd_vm_strerror( err ) ));
  }
  FD_TEST( err==expected_err );
  if( expected_err!=FD_VM_SUCCESS ) {
    test_vm_clear_txn_ctx_err( instr_ctx->txn_out );
  } else {
    if( FD_UNLIKELY( vm->reg[0]!=expected_result ) ) {
      FD_LOG_WARNING(( "Interp err: %i (%s)",   err,        fd_vm_strerror( err ) ));
      FD_LOG_WARNING(( "RET:        %lu 0x%lx", vm->reg[0], vm->reg[0]            ));
      FD_LOG_WARNING(( "PC:         %lu 0x%lx", vm->pc,     vm->pc                ));
      FD_LOG_WARNING(( "IC:         %lu 0x%lx", vm->ic,     vm->ic                ));
    }
    FD_TEST( vm->reg[0]==expected_result );
  }

//FD_LOG_NOTICE(( "Instr counter: %lu", vm.ic ));
  FD_LOG_NOTICE(( "%-20s %11li ns", test_case_name, dt ));
//FD_LOG_NOTICE(( "Time/Instr: %f ns", (double)dt / (double)vm.ic ));
//FD_LOG_NOTICE(( "Mega Instr/Sec: %f", 1000.0 * ((double)vm.ic / (double) dt)));

  return vm->ic;
}


static int
test_vm_validate( ulong                 sbpf_version,
                       ulong const *         text,
                       ulong                 text_cnt,
                       fd_sbpf_syscalls_t *  syscalls,
                       fd_exec_instr_ctx_t * instr_ctx ) {
  fd_sha256_t _sha[1];
  fd_sha256_t * sha = fd_sha256_join( fd_sha256_new( _sha ) );
  fd_vm_t _vm[1];
  fd_vm_t * vm = fd_vm_join( fd_vm_new( _vm ) );
  FD_TEST( vm );
  int ok = !!fd_vm_init(
      vm, instr_ctx, FD_VM_HEAP_DEFAULT, FD_VM_COMPUTE_UNIT_LIMIT,
      (uchar *)text, 8UL*text_cnt, text, text_cnt, 0UL, 8UL*text_cnt,
      0UL, NULL, sbpf_version, syscalls, NULL, sha, NULL, 0UL, NULL, 0,
      0, (ulong[ FD_VM_REG_CNT ]){ 0 } );
  FD_TEST( ok );
  vm->pc        = vm->entry_pc;
  vm->ic        = 0UL;
  vm->cu        = vm->entry_cu;
  vm->frame_cnt = 0UL;
  vm->heap_sz   = 0UL;
  fd_vm_mem_cfg( vm );
  return fd_vm_validate( vm );
}

static void
test_stack_configuration( fd_sbpf_syscalls_t *  syscalls,
                          fd_exec_instr_ctx_t * instr_ctx ) {
  fd_sha256_t _sha[1];
  fd_sha256_t * sha = fd_sha256_join( fd_sha256_new( _sha ) );
  fd_vm_t _vm[1];
  fd_vm_t * vm = fd_vm_join( fd_vm_new( _vm ) );
  ulong text[] = { fd_vm_instr( FD_SBPF_OP_EXIT, 0, 0, 0, 0 ) };

  ulong versions[]    = { FD_SBPF_V0, FD_SBPF_V1, FD_SBPF_V2, FD_SBPF_V3 };
  ulong expected_sz[] = { FD_VM_STACK_FRAME_SZ, 0UL, 0UL, FD_VM_STACK_FRAME_SZ };

  for( ulong i=0; i<4; i++ ) {
    FD_TEST( fd_vm_init( vm, instr_ctx, FD_VM_HEAP_DEFAULT, FD_VM_COMPUTE_UNIT_LIMIT,
        (uchar *)text, 8UL, text, 1UL, 0UL, 8UL, 0UL, NULL,
        versions[i], syscalls, NULL, sha, NULL, 0UL, NULL, 0,
        0, (ulong[ FD_VM_REG_CNT ]){ 0 } ) );
    FD_TEST( vm->stack_frame_sz==expected_sz[i] );
  }

  FD_LOG_NOTICE(( "%-20s PASS", "stack-frame-cfg" ));
}

/* fd_vm_init zeroes no stack and no heap; fd_vm_{stack,heap}_grow do it
   on demand.  These tests ensure that the guest's view is coherent.

   Each runs two programs through the *same* fd_vm_t: the first writes
   0xff somewhere the second reads back.  Reusing the vm is what makes
   this deterministic -- the second fd_vm_init drops the clean bound back
   to 0 without touching the buffer, so the 0xff is definitely still
   there, and the read can only return 0 if grow zeroed it. */

static ulong
lazy_exec( fd_vm_t *             vm,
           fd_sha256_t *         sha,
           char const *          name,
           ulong                 sbpf_version,
           ulong const *         text,
           ulong                 text_cnt,
           int                   expected_err,
           fd_sbpf_syscalls_t *  syscalls,
           fd_exec_instr_ctx_t * instr_ctx ) {

  FD_TEST( fd_vm_init( vm, instr_ctx, FD_VM_HEAP_DEFAULT, FD_VM_COMPUTE_UNIT_LIMIT,
      (uchar *)text, 8UL*text_cnt, text, text_cnt, 0UL, 8UL*text_cnt, 0UL, NULL,
      sbpf_version, syscalls, NULL, sha, NULL, 0UL, NULL, 0,
      0, (ulong[ FD_VM_REG_CNT ]){ 0 } ) );

  int err = fd_vm_validate( vm );
  if( FD_UNLIKELY( err ) ) FD_LOG_ERR(( "%s: validate: %i-%s", name, err, fd_vm_strerror( err ) ));

  err = fd_vm_exec( vm );
  if( FD_UNLIKELY( err!=expected_err ) ) {
    FD_LOG_ERR(( "%s: expected %i (%s), got %i (%s)", name,
                 expected_err, fd_vm_strerror( expected_err ), err, fd_vm_strerror( err ) ));
  }
  if( err!=FD_VM_SUCCESS ) test_vm_clear_txn_ctx_err( instr_ctx->txn_out );

  return vm->reg[0];
}

/* The heap must read as zero anywhere in [0,heap_max), including bytes
   sol_alloc_free has never handed out -- it does not zero what it
   returns, so the guest can allocate and read before writing. */

static void
test_lazy_heap_zeroing( fd_sbpf_syscalls_t *  syscalls,
                        fd_exec_instr_ctx_t * instr_ctx ) {

  fd_sha256_t   _sha[1]; fd_sha256_t * sha = fd_sha256_join( fd_sha256_new( _sha ) );
  fd_vm_t       _vm [1]; fd_vm_t     * vm  = fd_vm_join   ( fd_vm_new   ( _vm  ) );
  FD_TEST( vm );

  /* Well past FD_VM_GROW_MIN but inside the default heap_max. */
# define TEST_LHZ_OFF (24576U)

  /* r1 = 3<<32 | off, i.e. FD_VM_MEM_MAP_HEAP_REGION_START + off */
# define TEST_LHZ_ADDR( off )                                    \
    fd_vm_instr( FD_SBPF_OP_MOV64_IMM, 1UL, 0UL, 0, 3U  ),       \
    fd_vm_instr( FD_SBPF_OP_LSH64_IMM, 1UL, 0UL, 0, 32U ),       \
    fd_vm_instr( FD_SBPF_OP_ADD64_IMM, 1UL, 0UL, 0, (off) )

  ulong dirty[] = {
    TEST_LHZ_ADDR( TEST_LHZ_OFF ),
    fd_vm_instr( FD_SBPF_OP_MOV64_IMM, 2UL, 0UL, 0, 0xffffffffU ),
    fd_vm_instr( FD_SBPF_OP_STXDW,     1UL, 2UL, 0, 0U          ),
    fd_vm_instr( FD_SBPF_OP_EXIT,      0UL, 0UL, 0, 0U          ),
  };

  ulong read[] = {
    TEST_LHZ_ADDR( TEST_LHZ_OFF ),
    fd_vm_instr( FD_SBPF_OP_LDXDW, 0UL, 1UL, 0, 0U ),
    fd_vm_instr( FD_SBPF_OP_EXIT,  0UL, 0UL, 0, 0U ),
  };

  /* First byte past heap_max must fault, not grow. */
  ulong oob[] = {
    TEST_LHZ_ADDR( FD_VM_HEAP_DEFAULT ),
    fd_vm_instr( FD_SBPF_OP_LDXDW, 0UL, 1UL, 0, 0U ),
    fd_vm_instr( FD_SBPF_OP_EXIT,  0UL, 0UL, 0, 0U ),
  };

  lazy_exec( vm, sha, "lazy-heap-dirty", FD_SBPF_V3, dirty, 6UL, FD_VM_SUCCESS, syscalls, instr_ctx );
  FD_TEST( lazy_exec( vm, sha, "lazy-heap-read", FD_SBPF_V3, read, 5UL, FD_VM_SUCCESS, syscalls, instr_ctx )==0UL );
  lazy_exec( vm, sha, "lazy-heap-oob", FD_SBPF_V3, oob, 5UL, FD_VM_ERR_EBPF_ACCESS_VIOLATION, syscalls, instr_ctx );

  FD_LOG_NOTICE(( "%-20s PASS", "lazy-heap-zero" ));

# undef TEST_LHZ_ADDR
# undef TEST_LHZ_OFF
}

static void
test_lazy_stack_zeroing( fd_sbpf_syscalls_t *  syscalls,
                         fd_exec_instr_ctx_t * instr_ctx ) {

  fd_sha256_t   _sha[1]; fd_sha256_t * sha = fd_sha256_join( fd_sha256_new( _sha ) );
  fd_vm_t       _vm [1]; fd_vm_t     * vm  = fd_vm_join   ( fd_vm_new   ( _vm  ) );
  FD_TEST( vm );

  /* Buffer offset to poke: frame 40 of 64, far above the frame a
     depth-1 program owns.  reg[10] and frame_cnt bound nothing -- the
     stack region is mapped flat -- so this must be reachable and zero. */
# define TEST_LSZ_OFF (163840UL)

  static struct { char const * name; ulong ver; ulong delta; } const cases[] = {
    /* Virtual distance == buffer offset. */
    { "v0", FD_SBPF_V0, TEST_LSZ_OFF - FD_VM_STACK_FRAME_SZ },
    { "v3", FD_SBPF_V3, TEST_LSZ_OFF - FD_VM_STACK_FRAME_SZ },
  };

  for( ulong i=0UL; i<2UL; i++ ) {
    uint delta = (uint)cases[i].delta;

    /* r1 = r10 + delta; r2 = -1; *(ulong *)r1 = r2 */
    ulong dirty[] = {
      fd_vm_instr( FD_SBPF_OP_MOV64_REG, 1UL, 10UL, 0, 0U          ),
      fd_vm_instr( FD_SBPF_OP_ADD64_IMM, 1UL,  0UL, 0, delta       ),
      fd_vm_instr( FD_SBPF_OP_MOV64_IMM, 2UL,  0UL, 0, 0xffffffffU ),
      fd_vm_instr( FD_SBPF_OP_STXDW,     1UL,  2UL, 0, 0U          ),
      fd_vm_instr( FD_SBPF_OP_EXIT,      0UL,  0UL, 0, 0U          ),
    };

    /* r1 = r10 + delta; r0 = *(ulong *)r1 */
    ulong read[] = {
      fd_vm_instr( FD_SBPF_OP_MOV64_REG, 1UL, 10UL, 0, 0U    ),
      fd_vm_instr( FD_SBPF_OP_ADD64_IMM, 1UL,  0UL, 0, delta ),
      fd_vm_instr( FD_SBPF_OP_LDXDW,     0UL,  1UL, 0, 0U    ),
      fd_vm_instr( FD_SBPF_OP_EXIT,      0UL,  0UL, 0, 0U    ),
    };

    lazy_exec( vm, sha, "lazy-stack-dirty", cases[i].ver, dirty, 5UL, FD_VM_SUCCESS, syscalls, instr_ctx );
    FD_TEST( lazy_exec( vm, sha, "lazy-stack-read", cases[i].ver, read, 4UL, FD_VM_SUCCESS, syscalls, instr_ctx )==0UL );

    FD_LOG_NOTICE(( "%-20s PASS (%s)", "lazy-stack-zero", cases[i].name ));
  }

  /* The first byte past the end of the stack must still fault.  V3 starts
     reg[10] one frame in, so this lands exactly on FD_VM_STACK_MAX -- the
     boundary lazy growth has to refuse to cross.  That offset is call
     depth FD_VM_MAX_CALL_DEPTH, so fd_vm_generate_access_violation still
     classifies it as a stack violation rather than a generic one. */
  {
    uint  delta = (uint)( FD_VM_STACK_MAX - FD_VM_STACK_FRAME_SZ );
    ulong oob[] = {
      fd_vm_instr( FD_SBPF_OP_MOV64_REG, 1UL, 10UL, 0, 0U    ),
      fd_vm_instr( FD_SBPF_OP_ADD64_IMM, 1UL,  0UL, 0, delta ),
      fd_vm_instr( FD_SBPF_OP_LDXDW,     0UL,  1UL, 0, 0U    ),
      fd_vm_instr( FD_SBPF_OP_EXIT,      0UL,  0UL, 0, 0U    ),
    };
    lazy_exec( vm, sha, "lazy-stack-oob", FD_SBPF_V3, oob, 4UL,
               FD_VM_ERR_EBPF_STACK_ACCESS_VIOLATION, syscalls, instr_ctx );
    FD_LOG_NOTICE(( "%-20s PASS", "lazy-stack-oob" ));
  }

# undef TEST_LSZ_OFF
}

static void
test_geometric_region_growth( fd_sbpf_syscalls_t *  syscalls,
                              fd_exec_instr_ctx_t * instr_ctx ) {
  fd_sha256_t _sha[1]; fd_sha256_t * sha = fd_sha256_join( fd_sha256_new( _sha ) );
  fd_vm_t     _vm [1]; fd_vm_t     * vm  = fd_vm_join   ( fd_vm_new   ( _vm  ) );
  FD_TEST( vm );

  ulong noop_text[] = { fd_vm_instr( FD_SBPF_OP_EXIT, 0UL, 0UL, 0, 0U ) };

  /* 1. Stack geometric doubling: 0 -> 4096 -> 8192 -> ... -> FD_VM_STACK_MAX (262144) */
  fd_memset( vm->stack, 0xA5, FD_VM_STACK_MAX );
  FD_TEST( fd_vm_init( vm, instr_ctx, FD_VM_HEAP_DEFAULT, FD_VM_COMPUTE_UNIT_LIMIT,
                       (uchar *)noop_text, 8UL, noop_text, 1UL, 0UL, 8UL, 0UL, NULL,
                       FD_SBPF_V3, syscalls, NULL, sha, NULL, 0U, NULL, 0, 0,
                       (ulong[ FD_VM_REG_CNT ]){ 0 } ) );
  FD_TEST( vm->stack_clean == 0UL );
  fd_vm_stack_grow( vm, 0UL );
  FD_TEST( vm->stack_clean == 0UL );

  static ulong const stack_reqs[] = {    1UL, 4096UL, 4097UL,  8193UL, 16385UL, 32769UL,  65537UL, 131073UL };
  static ulong const stack_exps[] = { 4096UL, 4096UL, 8192UL, 16384UL, 32768UL, 65536UL, 131072UL, 262144UL };
  for( ulong i=0UL; i<sizeof(stack_reqs)/sizeof(stack_reqs[0]); i++ ) {
    fd_vm_stack_grow( vm, stack_reqs[i] );
    ulong exp = stack_exps[i];
    FD_TEST( vm->stack_clean == exp );
    FD_TEST( vm->region_ld_sz[ FD_VM_STACK_REGION ] == (uint)exp );
    FD_TEST( vm->region_st_sz[ FD_VM_STACK_REGION ] == (uint)exp );
    FD_TEST( vm->stack[ exp - 1UL ] == 0U );
    if( exp < FD_VM_STACK_MAX ) FD_TEST( vm->stack[ exp ] == 0xA5U );
  }

  /* 2. Large stride jump (> 2*clean) aligns up to quantum, then doubles and caps */
  fd_memset( vm->stack, 0x5A, FD_VM_STACK_MAX );
  FD_TEST( fd_vm_init( vm, instr_ctx, FD_VM_HEAP_DEFAULT, FD_VM_COMPUTE_UNIT_LIMIT,
                       (uchar *)noop_text, 8UL, noop_text, 1UL, 0UL, 8UL, 0UL, NULL,
                       FD_SBPF_V3, syscalls, NULL, sha, NULL, 0U, NULL, 0, 0,
                       (ulong[ FD_VM_REG_CNT ]){ 0 } ) );
  fd_vm_stack_grow( vm, 8UL );
  FD_TEST( vm->stack_clean == 4096UL );
  fd_vm_stack_grow( vm, 20000UL ); /* align_up(20000, 4096) == 20480 > 8192 */
  FD_TEST( vm->stack_clean == 20480UL );
  FD_TEST( vm->stack[ 20479UL ] == 0U && vm->stack[ 20480UL ] == 0x5AU );
  fd_vm_stack_grow( vm, 20481UL ); /* 2 * 20480 == 40960 */
  FD_TEST( vm->stack_clean == 40960UL );
  fd_vm_stack_grow( vm, 150000UL ); /* align_up(150000, 4096) == 151552 > 81920 */
  FD_TEST( vm->stack_clean == 151552UL );
  fd_vm_stack_grow( vm, 151553UL ); /* 2 * 151552 == 303104 -> clamped to FD_VM_STACK_MAX (262144) */
  FD_TEST( vm->stack_clean == FD_VM_STACK_MAX );
  FD_TEST( vm->stack[ FD_VM_STACK_MAX - 1UL ] == 0U );

  /* 3. Heap geometric doubling with non-quantum-aligned heap_max (5000B) */
  fd_memset( vm->heap, 0xCC, 8192UL );
  FD_TEST( fd_vm_init( vm, instr_ctx, 5000UL, FD_VM_COMPUTE_UNIT_LIMIT,
                       (uchar *)noop_text, 8UL, noop_text, 1UL, 0UL, 8UL, 0UL, NULL,
                       FD_SBPF_V3, syscalls, NULL, sha, NULL, 0U, NULL, 0, 0,
                       (ulong[ FD_VM_REG_CNT ]){ 0 } ) );
  static ulong const heap_reqs[] = {    8UL, 1024UL, 1025UL, 2049UL, 4097UL };
  static ulong const heap_exps[] = { 1024UL, 1024UL, 2048UL, 4096UL, 5000UL };
  for( ulong i=0UL; i<sizeof(heap_reqs)/sizeof(heap_reqs[0]); i++ ) {
    fd_vm_heap_grow( vm, heap_reqs[i] );
    ulong exp = heap_exps[i];
    FD_TEST( vm->heap_clean == exp );
    FD_TEST( vm->region_ld_sz[ FD_VM_HEAP_REGION ] == (uint)exp );
    FD_TEST( vm->region_st_sz[ FD_VM_HEAP_REGION ] == (uint)exp );
    FD_TEST( vm->heap[ exp - 1UL ] == 0U );
    FD_TEST( vm->heap[ 5000UL ] == 0xCCU );
  }

  /* 4. Multi-step interpreter execution across geometric heap boundaries */
  fd_memset( vm->heap, 0xFF, FD_VM_HEAP_DEFAULT );
  ulong prog[] = {
    fd_vm_instr( FD_SBPF_OP_MOV64_IMM, 1UL, 0UL,    0, 3U  ),
    fd_vm_instr( FD_SBPF_OP_LSH64_IMM, 1UL, 0UL,    0, 32U ),
    fd_vm_instr( FD_SBPF_OP_LDXDW,     0UL, 1UL,  512, 0U  ), /* grows 0 -> 1024 */
    fd_vm_instr( FD_SBPF_OP_LDXDW,     2UL, 1UL, 1504, 0U  ), /* grows 1024 -> 2048 */
    fd_vm_instr( FD_SBPF_OP_OR64_REG,  0UL, 2UL,    0, 0U  ),
    fd_vm_instr( FD_SBPF_OP_LDXDW,     2UL, 1UL, 3504, 0U  ), /* grows 2048 -> 4096 */
    fd_vm_instr( FD_SBPF_OP_OR64_REG,  0UL, 2UL,    0, 0U  ),
    fd_vm_instr( FD_SBPF_OP_LDXDW,     2UL, 1UL,12000, 0U  ), /* grows 4096 -> 12288 */
    fd_vm_instr( FD_SBPF_OP_OR64_REG,  0UL, 2UL,    0, 0U  ),
    fd_vm_instr( FD_SBPF_OP_EXIT,      0UL, 0UL,    0, 0U  ),
  };
  FD_TEST( lazy_exec( vm, sha, "geom-heap-steps", FD_SBPF_V3, prog,
                      sizeof(prog)/sizeof(prog[0]), FD_VM_SUCCESS, syscalls, instr_ctx )==0UL );
  FD_TEST( vm->heap_clean == 12288UL );

  FD_LOG_NOTICE(( "%-20s PASS", "geom-region-grow" ));
}

static void
test_validate_opcode_classes( fd_sbpf_syscalls_t *  syscalls,
                              fd_exec_instr_ctx_t * instr_ctx ) {
  /* Fast-path FD_VALID (0) and FD_CHECK_ST (1): verify r10 write permission
     distinction and src/dst register bounds across V0 and V3. */
  ulong valid_alu[] = {
    fd_vm_instr( FD_SBPF_OP_ADD64_IMM, 1UL,  0UL,  0, 42U ),
    fd_vm_instr( FD_SBPF_OP_STXDW,    10UL,  1UL, -8,  0U ), /* V0 STXDW (0x7b): dst==r10 allowed */
    fd_vm_instr( FD_SBPF_OP_EXIT,      0UL,  0UL,  0,  0U ),
  };
  FD_TEST( test_vm_validate( FD_SBPF_V0, valid_alu, 3UL, syscalls, instr_ctx )==FD_VM_SUCCESS );

  ulong valid_st_v2[] = {
    fd_vm_instr( FD_SBPF_OP_MOV64_IMM, 1UL,  0UL,  0, 42U ),
    fd_vm_instr( 0x9fUL,              10UL,  1UL, -8,  0U ), /* V2 STXDW (0x9f): FD_CHECK_ST allows dst==r10 */
    fd_vm_instr( FD_SBPF_OP_EXIT,      0UL,  0UL,  0,  0U ),
  };
  FD_TEST( test_vm_validate( FD_SBPF_V2, valid_st_v2, 3UL, syscalls, instr_ctx )==FD_VM_SUCCESS );
  FD_TEST( test_vm_validate( FD_SBPF_V3, valid_st_v2, 3UL, syscalls, instr_ctx )==FD_VM_ERR_INVALID_DST_REG );

  ulong bad_alu_r10[] = {
    fd_vm_instr( FD_SBPF_OP_ADD64_IMM, 10UL, 0UL, 0, 8U ), /* FD_VALID: dst==r10 rejected in V0/V3 */
    fd_vm_instr( FD_SBPF_OP_EXIT,       0UL, 0UL, 0, 0U ),
  };
  FD_TEST( test_vm_validate( FD_SBPF_V0, bad_alu_r10, 2UL, syscalls, instr_ctx )==FD_VM_ERR_INVALID_DST_REG );
  FD_TEST( test_vm_validate( FD_SBPF_V3, bad_alu_r10, 2UL, syscalls, instr_ctx )==FD_VM_ERR_INVALID_DST_REG );

  ulong bad_st_dst11[] = {
    fd_vm_instr( FD_SBPF_OP_STXDW, 11UL, 1UL, -8, 0U ),
    fd_vm_instr( FD_SBPF_OP_EXIT,   0UL, 0UL,  0, 0U ),
  };
  FD_TEST( test_vm_validate( FD_SBPF_V0, bad_st_dst11, 2UL, syscalls, instr_ctx )==FD_VM_ERR_INVALID_DST_REG );

  ulong bad_st_src11[] = {
    fd_vm_instr( FD_SBPF_OP_STXDW, 10UL, 11UL, -8, 0U ),
    fd_vm_instr( FD_SBPF_OP_EXIT,   0UL,  0UL,  0, 0U ),
  };
  FD_TEST( test_vm_validate( FD_SBPF_V0, bad_st_src11, 2UL, syscalls, instr_ctx )==FD_VM_ERR_INVALID_SRC_REG );

  /* Slow-path validation codes (> FD_CHECK_ST): END, JMP, LDQ, DIV, SH32, SH64, INVALID */
  ulong end_ok[]  = { fd_vm_instr( FD_SBPF_OP_END_BE, 1UL, 0UL, 0, 32U ), fd_vm_instr( FD_SBPF_OP_EXIT, 0UL, 0UL, 0, 0U ) };
  ulong end_bad[] = { fd_vm_instr( FD_SBPF_OP_END_BE, 1UL, 0UL, 0, 24U ), fd_vm_instr( FD_SBPF_OP_EXIT, 0UL, 0UL, 0, 0U ) };
  FD_TEST( test_vm_validate( FD_SBPF_V0, end_ok,  2UL, syscalls, instr_ctx )==FD_VM_SUCCESS );
  FD_TEST( test_vm_validate( FD_SBPF_V0, end_bad, 2UL, syscalls, instr_ctx )==FD_VM_ERR_INVALID_END_IMM );

  ulong jmp_oob[] = { fd_vm_instr( FD_SBPF_OP_JA, 0UL, 0UL, 5, 0U ), fd_vm_instr( FD_SBPF_OP_EXIT, 0UL, 0UL, 0, 0U ) };
  FD_TEST( test_vm_validate( FD_SBPF_V0, jmp_oob, 2UL, syscalls, instr_ctx )==FD_VM_ERR_JMP_OUT_OF_BOUNDS );

  ulong jmp_addl[] = {
    fd_vm_instr( FD_SBPF_OP_JA,       0UL, 0UL, 1, 0U ), /* lands on ADDL_IMM at pc=2 */
    fd_vm_instr( FD_SBPF_OP_LDDW,     1UL, 0UL, 0, 1U ),
    fd_vm_instr( FD_SBPF_OP_ADDL_IMM, 0UL, 0UL, 0, 2U ),
    fd_vm_instr( FD_SBPF_OP_EXIT,     0UL, 0UL, 0, 0U ),
  };
  FD_TEST( test_vm_validate( FD_SBPF_V0, jmp_addl, 4UL, syscalls, instr_ctx )==FD_VM_ERR_JMP_TO_ADDL_IMM );

  ulong ldq_inc[]  = { fd_vm_instr( FD_SBPF_OP_LDDW, 1UL, 0UL, 0, 1U ) };
  ulong ldq_noad[] = { fd_vm_instr( FD_SBPF_OP_LDDW, 1UL, 0UL, 0, 1U ), fd_vm_instr( FD_SBPF_OP_EXIT, 0UL, 0UL, 0, 0U ) };
  FD_TEST( test_vm_validate( FD_SBPF_V0, ldq_inc,  1UL, syscalls, instr_ctx )==FD_VM_ERR_INCOMPLETE_LDQ );
  FD_TEST( test_vm_validate( FD_SBPF_V0, ldq_noad, 2UL, syscalls, instr_ctx )==FD_VM_ERR_LDQ_NO_ADDL_IMM );

  ulong div0[]   = { fd_vm_instr( FD_SBPF_OP_DIV64_IMM, 1UL, 0UL, 0,  0U ), fd_vm_instr( FD_SBPF_OP_EXIT, 0UL, 0UL, 0, 0U ) };
  ulong sh32[]   = { fd_vm_instr( FD_SBPF_OP_LSH_IMM,   1UL, 0UL, 0, 32U ), fd_vm_instr( FD_SBPF_OP_EXIT, 0UL, 0UL, 0, 0U ) };
  ulong sh64[]   = { fd_vm_instr( FD_SBPF_OP_LSH64_IMM, 1UL, 0UL, 0, 64U ), fd_vm_instr( FD_SBPF_OP_EXIT, 0UL, 0UL, 0, 0U ) };
  ulong inv_op[] = { fd_vm_instr( 0xffUL,               0UL, 0UL, 0,  0U ), fd_vm_instr( FD_SBPF_OP_EXIT, 0UL, 0UL, 0, 0U ) };
  FD_TEST( test_vm_validate( FD_SBPF_V0, div0,   2UL, syscalls, instr_ctx )==FD_VM_ERR_SIGFPE );
  FD_TEST( test_vm_validate( FD_SBPF_V0, sh32,   2UL, syscalls, instr_ctx )==FD_VM_SH_OVERFLOW );
  FD_TEST( test_vm_validate( FD_SBPF_V0, sh64,   2UL, syscalls, instr_ctx )==FD_VM_SH_OVERFLOW );
  FD_TEST( test_vm_validate( FD_SBPF_V0, inv_op, 2UL, syscalls, instr_ctx )==FD_VM_ERR_INVALID_OPCODE );

  FD_LOG_NOTICE(( "%-20s PASS", "validate-opclasses" ));
}

static void
assert_trace_notrace_eq( char const *          name,
                         ulong                 sbpf_version,
                         ulong                 cu_limit,
                         ulong const *         text,
                         ulong                 text_cnt,
                         ulong const *         calldests,
                         int                   expected_err,
                         ulong                 expected_r0,
                         fd_sbpf_syscalls_t *  syscalls,
                         fd_exec_instr_ctx_t * instr_ctx ) {
  fd_sha256_t _sha1[1]; fd_sha256_t * sha1 = fd_sha256_join( fd_sha256_new( _sha1 ) );
  fd_sha256_t _sha2[1]; fd_sha256_t * sha2 = fd_sha256_join( fd_sha256_new( _sha2 ) );
  fd_vm_t     _vm1 [1]; fd_vm_t     * vm1  = fd_vm_join    ( fd_vm_new    ( _vm1  ) );
  fd_vm_t     _vm2 [1]; fd_vm_t     * vm2  = fd_vm_join    ( fd_vm_new    ( _vm2  ) );

  static uchar trace_mem[ 65536 ] __attribute__((aligned(8)));
  fd_vm_trace_t * trace = fd_vm_trace_join( fd_vm_trace_new( trace_mem, 256UL ) );
  FD_TEST( trace );

  ulong init_reg[ FD_VM_REG_CNT ] = { 0, 0x11UL, 0x22UL, 0x33UL, 0x44UL, 0x55UL, 0, 0, 0, 0, 0 };

  FD_TEST( fd_vm_init( vm1, instr_ctx, FD_VM_HEAP_DEFAULT, cu_limit,
                       (uchar const *)text, 8UL*text_cnt, text, text_cnt, 0UL, 8UL*text_cnt,
                       0UL, calldests, sbpf_version, syscalls, NULL, sha1,
                       NULL, 0U, NULL, 0, 0, init_reg ) );
  int err1 = fd_vm_exec( vm1 );
  test_vm_clear_txn_ctx_err( instr_ctx->txn_out );

  FD_TEST( fd_vm_init( vm2, instr_ctx, FD_VM_HEAP_DEFAULT, cu_limit,
                       (uchar const *)text, 8UL*text_cnt, text, text_cnt, 0UL, 8UL*text_cnt,
                       0UL, calldests, sbpf_version, syscalls, trace, sha2,
                       NULL, 0U, NULL, 0, 0, init_reg ) );
  int err2 = fd_vm_exec( vm2 );
  test_vm_clear_txn_ctx_err( instr_ctx->txn_out );

  if( FD_UNLIKELY( err1 != expected_err || err1 != err2 ) ) {
    FD_LOG_ERR(( "%s: err1=%i err2=%i expected=%i", name, err1, err2, expected_err ));
  }
  FD_TEST( vm1->pc == vm2->pc );
  FD_TEST( vm1->ic == vm2->ic );
  FD_TEST( vm1->cu == vm2->cu );
  for( ulong r=0UL; r<FD_VM_REG_CNT; r++ ) {
    FD_TEST( vm1->reg[r] == vm2->reg[r] );
  }
  if( expected_err == FD_VM_SUCCESS ) {
    FD_TEST( vm1->reg[0] == expected_r0 );
  }
  FD_TEST( fd_vm_trace_event_sz( trace ) > 0UL );
  fd_vm_trace_delete( fd_vm_trace_leave( trace ) );
}

static void
test_trace_notrace_parity( fd_sbpf_syscalls_t *  syscalls,
                           fd_exec_instr_ctx_t * instr_ctx ) {
  /* 1. Multi-LDDW basic block + untaken/taken branches + negative SIMM/OFFSET + high src_reg (r8..r10) */
  ulong prog_lddw_branch[] = {
    fd_vm_instr( FD_SBPF_OP_LDDW,      8UL,  0UL,   0, 0x9abcdef0U ), /* ic=1, pc=0..1 */
    fd_vm_instr( FD_SBPF_OP_ADDL_IMM,  0UL,  0UL,   0, 0x12345678U ),
    fd_vm_instr( FD_SBPF_OP_LDDW,      9UL,  0UL,   0, 0x00000010U ), /* ic=2, pc=2..3 */
    fd_vm_instr( FD_SBPF_OP_ADDL_IMM,  0UL,  0UL,   0, 0x00000000U ),
    fd_vm_instr( FD_SBPF_OP_STXDW,    10UL,  8UL, -16, 0U          ), /* src=r8 (high nibble) */
    fd_vm_instr( FD_SBPF_OP_LDXDW,     2UL, 10UL, -16, 0U          ), /* src=r10, neg offset */
    fd_vm_instr( FD_SBPF_OP_JEQ_IMM,   9UL,  0UL,   2, 0x99U       ), /* untaken branch */
    fd_vm_instr( FD_SBPF_OP_ADD64_IMM, 2UL,  0UL,   0, (uint)-10   ), /* negative SIMM */
    fd_vm_instr( FD_SBPF_OP_JEQ_IMM,   9UL,  0UL,   1, 0x10U       ), /* taken branch -> skips next */
    fd_vm_instr( FD_SBPF_OP_MOV64_IMM, 2UL,  0UL,   0, 0U          ),
    fd_vm_instr( FD_SBPF_OP_MOV64_REG, 0UL,  2UL,   0, 0U          ),
    fd_vm_instr( FD_SBPF_OP_EXIT,      0UL,  0UL,   0, 0U          ),
  };
  ulong exp_val = 0x123456789abcdef0UL - 10UL;
  assert_trace_notrace_eq( "parity-lddw-branch-v0", FD_SBPF_V0, 100UL, prog_lddw_branch,
                           sizeof(prog_lddw_branch)/sizeof(ulong), NULL, FD_VM_SUCCESS, exp_val, syscalls, instr_ctx );
  assert_trace_notrace_eq( "parity-lddw-branch-v3", FD_SBPF_V3, 100UL, prog_lddw_branch,
                           sizeof(prog_lddw_branch)/sizeof(ulong), NULL, FD_VM_SUCCESS, exp_val, syscalls, instr_ctx );

  /* 2. Local CALL_IMM (fd_pchash_inverse) + shadow stack r6..r10 save/restore + syscall */
  uint acc_hash = fd_murmur3_32( "accumulator", 11UL, 0U );
  (void)fd_vm_syscall_register( syscalls, "accumulator", accumulator_syscall );
  ulong prog_call[] = {
    fd_vm_instr( FD_SBPF_OP_MOV64_IMM, 6UL, 0UL, 0, 777U            ),
    fd_vm_instr( FD_SBPF_OP_MOV64_IMM, 1UL, 0UL, 0, 10U             ),
    fd_vm_instr( FD_SBPF_OP_MOV64_IMM, 2UL, 0UL, 0, 20U             ),
    fd_vm_instr( FD_SBPF_OP_MOV64_IMM, 3UL, 0UL, 0, 30U             ),
    fd_vm_instr( FD_SBPF_OP_MOV64_IMM, 4UL, 0UL, 0, 40U             ),
    fd_vm_instr( FD_SBPF_OP_MOV64_IMM, 5UL, 0UL, 0, 50U             ),
    fd_vm_instr( FD_SBPF_OP_CALL_IMM,  0UL, 0UL, 0, fd_pchash( 9U ) ), /* local call -> pc=9 */
    fd_vm_instr( FD_SBPF_OP_ADD64_REG, 0UL, 6UL, 0, 0U              ), /* r6 must be restored to 777 */
    fd_vm_instr( FD_SBPF_OP_EXIT,      0UL, 0UL, 0, 0U              ),
    /* pc=9: helper clobbers r6, calls accumulator_syscall, returns */
    fd_vm_instr( FD_SBPF_OP_MOV64_IMM, 6UL, 0UL, 0, 999U            ),
    fd_vm_instr( FD_SBPF_OP_CALL_IMM,  0UL, 0UL, 0, acc_hash        ),
    fd_vm_instr( FD_SBPF_OP_EXIT,      0UL, 0UL, 0, 0U              ),
  };
  uchar calldests_mem[ 128 ] __attribute__((aligned(16)));
  FD_TEST( fd_sbpf_calldests_footprint( sizeof(prog_call)/sizeof(ulong) ) <= sizeof(calldests_mem) );
  ulong * calldests = fd_sbpf_calldests_join( fd_sbpf_calldests_new( calldests_mem, sizeof(prog_call)/sizeof(ulong) ) );
  FD_TEST( calldests );
  fd_sbpf_calldests_insert( calldests, 9UL );
  assert_trace_notrace_eq( "parity-call-pchash", FD_SBPF_V0, 100UL, prog_call,
                           sizeof(prog_call)/sizeof(ulong), calldests,
                           FD_VM_SUCCESS, 150UL + 777UL, syscalls, instr_ctx );
  fd_sbpf_calldests_delete( fd_sbpf_calldests_leave( calldests ) );

  /* 3. Exact CU exhaustion and fault IC/CU accounting after multi-word LDDWs */
  assert_trace_notrace_eq( "parity-lddw-sigcost", FD_SBPF_V0, 5UL, prog_lddw_branch,
                           sizeof(prog_lddw_branch)/sizeof(ulong), NULL,
                           FD_VM_ERR_EBPF_EXCEEDED_MAX_INSTRUCTIONS, 0UL, syscalls, instr_ctx );

  ulong prog_lddw_div0[] = {
    fd_vm_instr( FD_SBPF_OP_LDDW,      1UL, 0UL, 0, 100U ),
    fd_vm_instr( FD_SBPF_OP_ADDL_IMM,  0UL, 0UL, 0,   0U ),
    fd_vm_instr( FD_SBPF_OP_LDDW,      2UL, 0UL, 0,   0U ),
    fd_vm_instr( FD_SBPF_OP_ADDL_IMM,  0UL, 0UL, 0,   0U ),
    fd_vm_instr( FD_SBPF_OP_DIV64_REG, 1UL, 2UL, 0,   0U ), /* sigfpe at pc=4, ic=3 */
    fd_vm_instr( FD_SBPF_OP_EXIT,      0UL, 0UL, 0,   0U ),
  };
  assert_trace_notrace_eq( "parity-lddw-sigfpe", FD_SBPF_V0, 20UL, prog_lddw_div0,
                           sizeof(prog_lddw_div0)/sizeof(ulong), NULL,
                           FD_VM_ERR_EBPF_DIVIDE_BY_ZERO, 0UL, syscalls, instr_ctx );

  FD_LOG_NOTICE(( "%-20s PASS", "trace-notrace-eq" ));
}

static void
test_input_tlb_and_region_lookup( fd_sbpf_syscalls_t *  syscalls,
                                  fd_exec_instr_ctx_t * instr_ctx ) {
  fd_sha256_t _sha[1]; fd_sha256_t * sha = fd_sha256_join( fd_sha256_new( _sha ) );
  fd_vm_t     _vm [1]; fd_vm_t     * vm  = fd_vm_join    ( fd_vm_new    ( _vm  ) );
  FD_TEST( vm );

  uchar buf0[ 32 ]   __attribute__((aligned(8)));
  uchar buf1[ 32 ]   __attribute__((aligned(8)));
  uchar buf2[ 32 ]   __attribute__((aligned(8)));
  uchar buf3[ 1024 ] __attribute__((aligned(8)));
  uchar buf4[ 24 ]   __attribute__((aligned(8)));
  fd_memset( buf0, 0x11, sizeof(buf0) );
  fd_memset( buf1, 0x22, sizeof(buf1) );
  fd_memset( buf2, 0x33, sizeof(buf2) );
  fd_memset( buf3, 0x44, 16UL );
  fd_memset( buf3 + 16UL, 0xEE, sizeof(buf3) - 16UL ); /* dirty bytes beyond initial region_sz */
  fd_memset( buf4, 0x55, sizeof(buf4) );

  uchar touched0 = 0U, touched1 = 0U, touched2 = 0U;
  fd_acc_t resizable_acc[1];
  fd_memset( resizable_acc, 0, sizeof(resizable_acc) );
  resizable_acc->data     = buf3;
  resizable_acc->data_len = 16UL;

  fd_vm_acc_region_meta_t arm[3];
  fd_memset( arm, 0, sizeof(arm) );
  arm[0].touched = &touched0;
  arm[1].touched = &touched1;
  arm[2].acc     = resizable_acc;
  arm[2].touched = &touched2;

  fd_vm_input_region_t regs[5] = {
    /* 0: writable untouched account -> pre-warmed for LD, gated (st_sz=0) for first ST */
    { .vaddr_offset =    0UL, .haddr = (ulong)buf0, .region_sz = 32U, .address_space_reserved =   32UL, .is_writable = 1U, .acc_region_meta_idx = 0UL       },
    /* 1: read-only account contiguous with region 0 */
    { .vaddr_offset =   32UL, .haddr = (ulong)buf1, .region_sz = 32U, .address_space_reserved =   32UL, .is_writable = 0U, .acc_region_meta_idx = 1UL       },
    /* 2: zero-length region */
    { .vaddr_offset =   64UL, .haddr = (ulong)buf2, .region_sz =  0U, .address_space_reserved =   32UL, .is_writable = 1U, .acc_region_meta_idx = ULONG_MAX },
    /* 3: resizable writable account */
    { .vaddr_offset =   96UL, .haddr = (ulong)buf3, .region_sz = 16U, .address_space_reserved = 1024UL, .is_writable = 1U, .acc_region_meta_idx = 2UL       },
    /* 4: trailing instruction-data region (exercises O(1) tail fast-path) */
    { .vaddr_offset = 1120UL, .haddr = (ulong)buf4, .region_sz = 24U, .address_space_reserved =   24UL, .is_writable = 0U, .acc_region_meta_idx = ULONG_MAX },
  };

  ulong init_reg[ FD_VM_REG_CNT ] = { 0UL, FD_VM_MEM_MAP_INPUT_REGION_START, 0 };

  /* 1. Pre-warmed r0 hit, O(1) tail lookup (r4), backward 32-bit wraparound (r4->r0),
        and touched-flag transition on first store vs inline TLB hit on second store. */
  {
    ulong prog[] = {
      fd_vm_instr( FD_SBPF_OP_LDXDW,     2UL, 1UL,    0, 0U          ), /* r0 pre-warmed hit */
      fd_vm_instr( FD_SBPF_OP_LDXDW,     3UL, 1UL, 1120, 0U          ), /* r4 tail fast-path -> voff[4]=1120 */
      fd_vm_instr( FD_SBPF_OP_LDXDW,     4UL, 1UL,    8, 0U          ), /* r0 < 1120 wraparound miss -> bsearch r0 */
      fd_vm_instr( FD_SBPF_OP_LDXDW,     5UL, 1UL,   40, 0U          ), /* r1 miss -> voff[4]=32 */
      fd_vm_instr( FD_SBPF_OP_MOV64_IMM, 6UL, 0UL,    0, 0x12345678U ),
      fd_vm_instr( FD_SBPF_OP_STXDW,     1UL, 6UL,   16, 0U          ), /* r0 first ST: slow path sets touched0=1, st_sz[4]=32 */
      fd_vm_instr( FD_SBPF_OP_MOV64_IMM, 6UL, 0UL,    0, 0x76543210U ),
      fd_vm_instr( FD_SBPF_OP_STXDW,     1UL, 6UL,   24, 0U          ), /* r0 second ST: inline TLB hit */
      fd_vm_instr( FD_SBPF_OP_MOV64_REG, 0UL, 2UL,    0, 0U          ),
      fd_vm_instr( FD_SBPF_OP_XOR64_REG, 0UL, 3UL,    0, 0U          ),
      fd_vm_instr( FD_SBPF_OP_XOR64_REG, 0UL, 4UL,    0, 0U          ),
      fd_vm_instr( FD_SBPF_OP_XOR64_REG, 0UL, 5UL,    0, 0U          ),
      fd_vm_instr( FD_SBPF_OP_EXIT,      0UL, 0UL,    0, 0U          ),
    };
    FD_TEST( fd_vm_init( vm, instr_ctx, FD_VM_HEAP_DEFAULT, 100UL,
                         (uchar const *)prog, sizeof(prog), prog, sizeof(prog)/8UL, 0UL, sizeof(prog),
                         0UL, NULL, FD_SBPF_V3, syscalls, NULL, sha,
                         regs, 5U, arm, 0, 0, init_reg ) );
    FD_TEST( vm->region_voff [ FD_VM_INPUT_REGION ] == 0U  );
    FD_TEST( vm->region_ld_sz[ FD_VM_INPUT_REGION ] == 32U );
    FD_TEST( vm->region_st_sz[ FD_VM_INPUT_REGION ] == 0U  ); /* gated on touched0==0 */
    FD_TEST( fd_vm_exec( vm ) == FD_VM_SUCCESS );
    ulong exp_xor = 0x1111111111111111UL ^ 0x5555555555555555UL ^ 0x1111111111111111UL ^ 0x2222222222222222UL;
    FD_TEST( vm->reg[0] == exp_xor );
    FD_TEST( touched0 == 1U && touched1 == 0U );
    FD_TEST( vm->region_voff [ FD_VM_INPUT_REGION ] == 0U  );
    FD_TEST( vm->region_st_sz[ FD_VM_INPUT_REGION ] == 32U );
    FD_TEST( FD_LOAD( ulong, buf0 + 16UL ) == 0x12345678UL );
    FD_TEST( FD_LOAD( ulong, buf0 + 24UL ) == 0x76543210UL );
  }

  /* 2. Read-only region: LD warms region_ld_sz[4], subsequent ST still faults */
  {
    ulong prog_ro_st[] = {
      fd_vm_instr( FD_SBPF_OP_LDXDW, 2UL, 1UL, 32, 0U ), /* warms r1 in slot 4 */
      fd_vm_instr( FD_SBPF_OP_STXDW, 1UL, 2UL, 32, 0U ), /* must fault */
      fd_vm_instr( FD_SBPF_OP_EXIT,  0UL, 0UL,  0, 0U ),
    };
    FD_TEST( fd_vm_init( vm, instr_ctx, FD_VM_HEAP_DEFAULT, 100UL,
                         (uchar const *)prog_ro_st, sizeof(prog_ro_st), prog_ro_st, 3UL, 0UL, sizeof(prog_ro_st),
                         0UL, NULL, FD_SBPF_V3, syscalls, NULL, sha,
                         regs, 5U, arm, 0, 0, init_reg ) );
    FD_TEST( fd_vm_exec( vm ) == FD_VM_ERR_EBPF_ACCESS_VIOLATION );
    FD_TEST( touched1 == 0U );
    test_vm_clear_txn_ctx_err( instr_ctx->txn_out );
  }

  /* 3. Cross-region straddle (r0 [28..32) into contiguous r1 [32..36)) and zero-len r2 must fault */
  {
    ulong prog_straddle[] = {
      fd_vm_instr( FD_SBPF_OP_LDXDW, 0UL, 1UL, 28, 0U ),
      fd_vm_instr( FD_SBPF_OP_EXIT,  0UL, 0UL,  0, 0U ),
    };
    FD_TEST( fd_vm_init( vm, instr_ctx, FD_VM_HEAP_DEFAULT, 100UL,
                         (uchar const *)prog_straddle, sizeof(prog_straddle), prog_straddle, 2UL, 0UL, sizeof(prog_straddle),
                         0UL, NULL, FD_SBPF_V3, syscalls, NULL, sha,
                         regs, 5U, arm, 0, 0, init_reg ) );
    FD_TEST( fd_vm_exec( vm ) == FD_VM_ERR_EBPF_ACCESS_VIOLATION );
    test_vm_clear_txn_ctx_err( instr_ctx->txn_out );

    ulong prog_zerolen[] = {
      fd_vm_instr( FD_SBPF_OP_LDXB, 0UL, 1UL, 64, 0U ),
      fd_vm_instr( FD_SBPF_OP_EXIT, 0UL, 0UL,  0, 0U ),
    };
    FD_TEST( fd_vm_init( vm, instr_ctx, FD_VM_HEAP_DEFAULT, 100UL,
                         (uchar const *)prog_zerolen, sizeof(prog_zerolen), prog_zerolen, 2UL, 0UL, sizeof(prog_zerolen),
                         0UL, NULL, FD_SBPF_V3, syscalls, NULL, sha,
                         regs, 5U, arm, 0, 0, init_reg ) );
    FD_TEST( fd_vm_exec( vm ) == FD_VM_ERR_EBPF_ACCESS_VIOLATION );
    test_vm_clear_txn_ctx_err( instr_ctx->txn_out );
  }

  /* 4. OOB write auto-resize on r3 updates region_sz, zeroes gap, sets touched2=1, and refreshes TLB */
  {
    instr_ctx->txn_out->details.accounts_resize_delta = 0L;
    ulong prog_resize[] = {
      fd_vm_instr( FD_SBPF_OP_LDXDW,     2UL, 1UL,  96,     0U          ), /* warms r3 with old sz=16 */
      fd_vm_instr( FD_SBPF_OP_MOV64_IMM, 3UL, 0UL,   0,     0x42424242U ),
      fd_vm_instr( FD_SBPF_OP_STXDW,     1UL, 3UL,  96 + 24, 0U         ), /* OOB write -> auto-resizes r3 to 1024 */
      fd_vm_instr( FD_SBPF_OP_LDXDW,     0UL, 1UL,  96 + 16, 0U         ), /* zeroed gap [16..24) must read 0 */
      fd_vm_instr( FD_SBPF_OP_LDXDW,     4UL, 1UL,  96 + 24, 0U         ), /* written word hits refreshed TLB */
      fd_vm_instr( FD_SBPF_OP_ADD64_REG, 0UL, 4UL,   0,      0U         ),
      fd_vm_instr( FD_SBPF_OP_EXIT,      0UL, 0UL,   0,      0U         ),
    };
    FD_TEST( fd_vm_init( vm, instr_ctx, FD_VM_HEAP_DEFAULT, 100UL,
                         (uchar const *)prog_resize, sizeof(prog_resize), prog_resize, 7UL, 0UL, sizeof(prog_resize),
                         0UL, NULL, FD_SBPF_V3, syscalls, NULL, sha,
                         regs, 5U, arm, 0, 0, init_reg ) );
    FD_TEST( fd_vm_exec( vm ) == FD_VM_SUCCESS );
    FD_TEST( vm->reg[0] == 0x42424242UL );
    FD_TEST( touched2 == 1U );
    FD_TEST( resizable_acc->data_len == 1024UL );
    FD_TEST( regs[3].region_sz == 1024U );
    FD_TEST( vm->region_ld_sz[ FD_VM_INPUT_REGION ] == 1024U );
    FD_TEST( vm->region_st_sz[ FD_VM_INPUT_REGION ] == 1024U );
    instr_ctx->txn_out->details.accounts_resize_delta = 0L;
  }

  /* 5. Unmapped high regions (_region >= 5) fault cleanly without OOB reading region_voff[5] */
  {
    ulong hi_addrs[] = { 0x500000000UL, 0xfffffffffffffff8UL };
    for( ulong i=0UL; i<2UL; i++ ) {
      ulong hi_reg[ FD_VM_REG_CNT ] = { 0UL, hi_addrs[i], 0 };
      ulong prog_hi_ld[] = { fd_vm_instr( FD_SBPF_OP_LDXDW, 0UL, 1UL, 0, 0U ), fd_vm_instr( FD_SBPF_OP_EXIT, 0UL, 0UL, 0, 0U ) };
      ulong prog_hi_st[] = { fd_vm_instr( FD_SBPF_OP_STXDW, 1UL, 0UL, 0, 0U ), fd_vm_instr( FD_SBPF_OP_EXIT, 0UL, 0UL, 0, 0U ) };
      FD_TEST( fd_vm_init( vm, instr_ctx, FD_VM_HEAP_DEFAULT, 100UL,
                           (uchar const *)prog_hi_ld, 16UL, prog_hi_ld, 2UL, 0UL, 16UL,
                           0UL, NULL, FD_SBPF_V3, syscalls, NULL, sha,
                           regs, 5U, arm, 0, 0, hi_reg ) );
      FD_TEST( fd_vm_exec( vm ) == FD_VM_ERR_EBPF_ACCESS_VIOLATION );
      test_vm_clear_txn_ctx_err( instr_ctx->txn_out );

      FD_TEST( fd_vm_init( vm, instr_ctx, FD_VM_HEAP_DEFAULT, 100UL,
                           (uchar const *)prog_hi_st, 16UL, prog_hi_st, 2UL, 0UL, 16UL,
                           0UL, NULL, FD_SBPF_V3, syscalls, NULL, sha,
                           regs, 5U, arm, 0, 0, hi_reg ) );
      FD_TEST( fd_vm_exec( vm ) == FD_VM_ERR_EBPF_ACCESS_VIOLATION );
      test_vm_clear_txn_ctx_err( instr_ctx->txn_out );
    }
  }

  FD_LOG_NOTICE(( "%-20s PASS", "input-tlb-lookup" ));
}

static void
generate_random_alu_instrs( fd_rng_t * rng,
                            ulong *    text,
                            ulong      text_cnt ) {
  static uchar const opcodes[23] = {
    FD_SBPF_OP_ADD_IMM,
    FD_SBPF_OP_ADD_REG,
    FD_SBPF_OP_SUB_IMM,
    FD_SBPF_OP_SUB_REG,
    FD_SBPF_OP_MUL_IMM,
    FD_SBPF_OP_MUL_REG,
    FD_SBPF_OP_DIV_IMM,
    FD_SBPF_OP_OR_IMM,
    FD_SBPF_OP_OR_REG,
    FD_SBPF_OP_AND_IMM,
    FD_SBPF_OP_AND_REG,
    FD_SBPF_OP_LSH_IMM,
    FD_SBPF_OP_LSH_REG,
    FD_SBPF_OP_RSH_IMM,
    FD_SBPF_OP_RSH_REG,
    FD_SBPF_OP_NEG,
    FD_SBPF_OP_MOD_IMM,
    FD_SBPF_OP_XOR_IMM,
    FD_SBPF_OP_XOR_REG,
    FD_SBPF_OP_MOV_IMM,
    FD_SBPF_OP_MOV_REG,
    FD_SBPF_OP_ARSH_IMM,
    FD_SBPF_OP_ARSH_REG,
  };

  if( FD_UNLIKELY( !text_cnt ) ) return;

  fd_sbpf_instr_t instr;
  for( ulong i=0UL; i<text_cnt-1UL; i++ ) {
    instr.opcode.raw = opcodes[fd_rng_ulong_roll(rng, 23)];
    instr.dst_reg    = (1+fd_rng_uchar_roll(rng, 9)) & 0xFUL;
    instr.src_reg    = (1+fd_rng_uchar_roll(rng, 9)) & 0xFUL;
    instr.offset     = 0;
    instr.imm        = fd_rng_uint_roll(rng, 1024*1024);
    switch( instr.opcode.raw ) {
    case 0x34:  /* FD_SBPF_OP_DIV_IMM */
    case 0x94:  /* FD_SBPF_OP_MOD_IMM */
      instr.imm = fd_uint_max( instr.imm, 1 );
      break;
    case 0x64:  /* FD_SBPF_OP_LSH_IMM */
    case 0x74:  /* FD_SBPF_OP_RSH_IMM */
    case 0xc4:  /* FD_SBPF_OP_ARSH_IMM */
      instr.imm &= 31;
      break;
    }
    text[i] = fd_sbpf_ulong( instr );
  }
  instr.opcode.raw = FD_SBPF_OP_EXIT;
  text[text_cnt-1UL] = fd_sbpf_ulong( instr );
}

static void
generate_random_alu64_instrs( fd_rng_t * rng,
                              ulong *    text,
                              ulong      text_cnt ) {

  static uchar const opcodes[23] = {
    FD_SBPF_OP_ADD64_IMM,
    FD_SBPF_OP_ADD64_REG,
    FD_SBPF_OP_SUB64_IMM,
    FD_SBPF_OP_SUB64_REG,
    FD_SBPF_OP_MUL64_IMM,
    FD_SBPF_OP_MUL64_REG,
    FD_SBPF_OP_DIV64_IMM,
    FD_SBPF_OP_OR64_IMM,
    FD_SBPF_OP_OR64_REG,
    FD_SBPF_OP_AND64_IMM,
    FD_SBPF_OP_AND64_REG,
    FD_SBPF_OP_LSH64_IMM,
    FD_SBPF_OP_LSH64_REG,
    FD_SBPF_OP_RSH64_IMM,
    FD_SBPF_OP_RSH64_REG,
    FD_SBPF_OP_NEG64,
    FD_SBPF_OP_MOD64_IMM,
    FD_SBPF_OP_XOR64_IMM,
    FD_SBPF_OP_XOR64_REG,
    FD_SBPF_OP_MOV64_IMM,
    FD_SBPF_OP_MOV64_REG,
    FD_SBPF_OP_ARSH64_IMM,
    FD_SBPF_OP_ARSH64_REG,
  };

  if( FD_UNLIKELY( !text_cnt ) ) return;

  fd_sbpf_instr_t instr;
  for( ulong i=0UL; i<text_cnt-1UL; i++ ) {
    instr.opcode.raw = opcodes[fd_rng_ulong_roll(rng, 23)];
    instr.dst_reg    = (1+fd_rng_uchar_roll(rng, 9)) & 0xFUL;
    instr.src_reg    = (1+fd_rng_uchar_roll(rng, 9)) & 0xFUL;
    instr.offset     = 0;
    instr.imm        = fd_rng_uint_roll( rng, 1024*1024 );
    switch( instr.opcode.raw ) {
    case 0x37:  /* FD_SBPF_OP_DIV64_IMM */
    case 0x97:  /* FD_SBPF_OP_MOD64_IMM */
      instr.imm = fd_uint_max( instr.imm, 1 );
      break;
    case 0x67:  /* FD_SBPF_OP_LSH_IMM */
    case 0x77:  /* FD_SBPF_OP_RSH_IMM */
    case 0xc7:  /* FD_SBPF_OP_ARSH_IMM */
      instr.imm &= 31;
      break;
    }
    text[i] = fd_sbpf_ulong( instr );
  }
  instr.opcode.raw = FD_SBPF_OP_EXIT;
  text[text_cnt-1UL] = fd_sbpf_ulong( instr );
}

/* test_0cu_exit ensures that the VM correctly exits the root frame if
   the CU count after the final exit instruction reaches zero. */

static void
test_0cu_exit( fd_runtime_t * runtime ) {

  fd_sha256_t _sha[1];
  fd_sha256_t * sha = fd_sha256_join( fd_sha256_new( _sha ) );

  fd_vm_t _vm[1];
  fd_vm_t * vm = fd_vm_join( fd_vm_new( _vm ) );
  FD_TEST( vm );

  ulong const text[3] = {
    fd_vm_instr( FD_SBPF_OP_XOR64_REG, 0, 0, 0, 0 ),
    fd_vm_instr( FD_SBPF_OP_XOR64_REG, 0, 0, 0, 0 ),
    fd_vm_instr( FD_SBPF_OP_EXIT,      0, 0, 0, 0 )
  };
  ulong text_cnt = 3UL;

  static fd_exec_instr_ctx_t instr_ctx[1];
  static fd_bank_t           bank[1];
  static fd_txn_out_t        txn_out[1];
  test_vm_minimal_exec_instr_ctx( instr_ctx, runtime, bank, txn_out );

  /* Ensure the VM exits with success if the CU count after the final
     exit instruction reaches zero. */

  int vm_ok = !!fd_vm_init(
      /* vm                                     */ vm,
      /* instr_ctx                              */ instr_ctx,
      /* heap_max                               */ FD_VM_HEAP_DEFAULT,
      /* entry_cu                               */ text_cnt,
      /* rodata                                 */ (uchar *)text,
      /* rodata_sz                              */ 8UL*text_cnt,
      /* text                                   */ text,
      /* text_cnt                               */ text_cnt,
      /* text_off                               */ 0UL,
      /* text_sz                                */ 8UL*text_cnt,
      /* entry_pc                               */ 0UL,
      /* calldests                              */ NULL,
      /* sbpf_version                           */ TEST_VM_DEFAULT_SBPF_VERSION,
      /* syscalls                               */ NULL,
      /* trace                                  */ NULL,
      /* sha                                    */ sha,
      /* mem_regions                            */ NULL,
      /* mem_regions_cnt                        */ 0UL,
      /* mem_regions_accs                       */ NULL,
      /* is_deprecated                          */ 0,
      /* dump_syscall_to_pb                     */ 0,
      /* reg                                    */ (ulong[ FD_VM_REG_CNT ]){ 0 }
  );
  FD_TEST( vm_ok );

  FD_TEST( fd_vm_validate( vm )==FD_VM_SUCCESS );
  FD_TEST( fd_vm_exec    ( vm )==FD_VM_SUCCESS );
  FD_TEST( vm->cu == 0UL );

  /* Ensure the VM exits with failure if CUs are exhausted. */

  vm_ok = !!fd_vm_init(
      /* vm                                     */ vm,
      /* instr_ctx                              */ instr_ctx,
      /* heap_max                               */ FD_VM_HEAP_DEFAULT,
      /* entry_cu                               */ text_cnt - 1UL,
      /* rodata                                 */ (uchar *)text,
      /* rodata_sz                              */ 8UL*text_cnt,
      /* text                                   */ text,
      /* text_cnt                               */ text_cnt,
      /* text_off                               */ 0UL,
      /* text_sz                                */ 8UL*text_cnt,
      /* entry_pc                               */ 0UL,
      /* calldests                              */ NULL,
      /* sbpf_version                           */ TEST_VM_DEFAULT_SBPF_VERSION,
      /* syscalls                               */ NULL,
      /* trace                                  */ NULL,
      /* sha                                    */ sha,
      /* mem_regions                            */ NULL,
      /* mem_regions_cnt                        */ 0UL,
      /* mem_regions_accs                       */ NULL,
      /* is_deprecated                          */ 0,
      /* dump_syscall_to_pb                     */ 0,
      /* reg                                    */ (ulong[ FD_VM_REG_CNT ]){ 0 }
  );
  FD_TEST( vm_ok );

  FD_TEST( fd_vm_validate( vm )==FD_VM_SUCCESS );
  FD_TEST( fd_vm_exec    ( vm )==FD_VM_ERR_EBPF_EXCEEDED_MAX_INSTRUCTIONS );

  fd_vm_delete( fd_vm_leave( vm ) );
  fd_sha256_delete( fd_sha256_leave( sha ) );
}

static ulong
build_alu_block( ulong * text,
                 ulong   n_alu ) {
  for( ulong i=0UL; i<n_alu; i++ ) text[ i ] = fd_vm_instr( FD_SBPF_OP_MOV64_IMM, 0, 0, 0, 0 );
  text[ n_alu ] = fd_vm_instr( FD_SBPF_OP_EXIT, 0, 0, 0, 0 );
  return n_alu + 1UL;
}

static ulong
build_lddw_block( ulong * text,
                  ulong   n_lddw ) {
  for( ulong i=0UL; i<n_lddw; i++ ) {
    text[ 2UL*i     ] = fd_vm_instr( FD_SBPF_OP_LDDW,     0, 0, 0, 0 );
    text[ 2UL*i+1UL ] = fd_vm_instr( FD_SBPF_OP_ADDL_IMM, 0, 0, 0, 0 );
  }
  text[ 2UL*n_lddw ] = fd_vm_instr( FD_SBPF_OP_EXIT, 0, 0, 0, 0 );
  return 2UL*n_lddw + 1UL;
}

/* Tests for the tighter block_text_limit:
   - If a block fits into the CU budget, it always succeeds. Including
     when the CU budget is the maximum FD_VM_COMPUTE_UNIT_LIMIT.
   - A block succeeds when the CU budget is exactly its cost,
     and fails when the CU budget is one short.
   - This is the case for LDDW instructions too: each LDDW costs one
     CU but occupies two text words, so the block_text_limit must be
     2*(remaining cu budget).
   - Blocks which have a large amount of instructions but a small amount
     of remaining CU fail early, instead of scanning to the end. */

static void
test_block_text_limit( fd_sbpf_syscalls_t *  syscalls,
                       fd_exec_instr_ctx_t * instr_ctx ) {
  static ulong text[ 65536 ];
  ulong        ver      = TEST_VM_DEFAULT_SBPF_VERSION;
  ulong        text_cnt = 0UL;
  ulong        ic       = 0UL;

  /* If a block fits into the CU budget, it always succeeds.  Including
     when the CU budget is the maximum FD_VM_COMPUTE_UNIT_LIMIT. */

  text_cnt = build_alu_block( text, 4999UL ); /* 5000 instructions */
  test_program_exec( "btl-fits",     0UL, FD_VM_SUCCESS, 5001UL,                   ver, text, text_cnt, syscalls, instr_ctx );
  test_program_exec( "btl-fits-max", 0UL, FD_VM_SUCCESS, FD_VM_COMPUTE_UNIT_LIMIT, ver, text, text_cnt, syscalls, instr_ctx );

  /* A block succeeds when the CU budget is exactly its cost, and fails
     when the CU budget is one short. */

  ic = test_program_exec( "btl-exact", 0UL, FD_VM_SUCCESS, 5000UL, ver, text, text_cnt, syscalls, instr_ctx );
  FD_TEST( ic==5000UL );
  test_program_exec( "btl-short", 0UL, FD_VM_ERR_EBPF_EXCEEDED_MAX_INSTRUCTIONS, 4999UL, ver, text, text_cnt, syscalls, instr_ctx );

  /* This is the case for LDDW instructions too: each LDDW costs one CU but
     occupies two text words, so the block_text_limit must be
     2*(remaining cu budget). */

  text_cnt = build_lddw_block( text, 4000UL ); /* 4001 instructions, 8001 text words */
  ic = test_program_exec( "btl-lddw-exact", 0UL, FD_VM_SUCCESS, 4001UL, ver, text, text_cnt, syscalls, instr_ctx );
  FD_TEST( ic==4001UL );
  test_program_exec( "btl-lddw-short", 0UL, FD_VM_ERR_EBPF_EXCEEDED_MAX_INSTRUCTIONS, 4000UL, ver, text, text_cnt, syscalls, instr_ctx );

  /* Blocks which have a large amount of instructions but a small amount of
     remaining CU fail early, instead of scanning to the end. */

  text_cnt = build_alu_block( text, 60000UL );
  ic = test_program_exec( "btl-fail-early", 0UL, FD_VM_ERR_EBPF_EXCEEDED_MAX_INSTRUCTIONS, 100UL, ver, text, text_cnt, syscalls, instr_ctx );
  FD_TEST( ic<=2UL*100UL+2UL ); /* stopped near the limit       */
  FD_TEST( ic< text_cnt      ); /* did not scan the whole block */

  FD_LOG_NOTICE(( "test_block_text_limit: ok" ));
}

static fd_sbpf_syscalls_t _syscalls[ FD_SBPF_SYSCALLS_SLOT_CNT ];

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  char const * name     = fd_env_strip_cmdline_cstr ( &argc, &argv, "--wksp",      NULL, NULL            );
  char const * _page_sz = fd_env_strip_cmdline_cstr ( &argc, &argv, "--page-sz",   NULL, "gigantic"      );
  ulong        page_cnt = fd_env_strip_cmdline_ulong( &argc, &argv, "--page-cnt",  NULL, 1UL             );
  ulong        near_cpu = fd_env_strip_cmdline_ulong( &argc, &argv, "--near-cpu",  NULL, fd_log_cpu_id() );
  ulong        wksp_tag = fd_env_strip_cmdline_ulong( &argc, &argv, "--wksp-tag",  NULL, 1234UL          );

  fd_wksp_t * wksp;
  if( name ) {
    FD_LOG_NOTICE(( "Attaching to --wksp %s", name ));
    wksp = fd_wksp_attach( name );
  } else {
    FD_LOG_NOTICE(( "--wksp not specified, using an anonymous local workspace, --page-sz %s, --page-cnt %lu, --near-cpu %lu",
                    _page_sz, page_cnt, near_cpu ));
    wksp = fd_wksp_new_anonymous( fd_cstr_to_shmem_page_sz( _page_sz ), page_cnt, near_cpu, "wksp", 0UL );
  }

  fd_runtime_t * runtime = fd_wksp_alloc_laddr( wksp, alignof(fd_runtime_t), sizeof(fd_runtime_t), wksp_tag );
  FD_TEST( runtime );

  fd_rng_t _rng[1]; fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, 0U, 0UL ) );

  fd_sbpf_syscalls_t * syscalls = fd_sbpf_syscalls_join( fd_sbpf_syscalls_new( _syscalls ) ); FD_TEST( syscalls );

  static fd_exec_instr_ctx_t instr_ctx[1];
  static fd_bank_t           bank[1];
  static fd_txn_out_t        txn_out[1];
  test_vm_minimal_exec_instr_ctx( instr_ctx, runtime, bank, txn_out );

  FD_TEST( fd_vm_syscall_register( syscalls, "accumulator", accumulator_syscall )==FD_VM_SUCCESS );

# define TEST_PROGRAM_SUCCESS( test_case_name, expected_result, text_cnt, ... ) do {         \
    ulong _text[ text_cnt ] = { __VA_ARGS__ };                                               \
    test_program_exec( (test_case_name), (expected_result), FD_VM_SUCCESS, FD_VM_COMPUTE_UNIT_LIMIT, \
                          TEST_VM_DEFAULT_SBPF_VERSION, _text, (text_cnt), syscalls, instr_ctx ); \
  } while(0)

# define TEST_V3_SUCCESS( test_case_name, expected_result, text_cnt, ... ) do { \
    ulong _text[ text_cnt ] = { __VA_ARGS__ };                                  \
    test_program_exec( (test_case_name), (expected_result), FD_VM_SUCCESS, FD_VM_COMPUTE_UNIT_LIMIT, \
                          FD_SBPF_V3, _text, (text_cnt), syscalls, instr_ctx ); \
  } while(0)

# define TEST_V3_ERROR( test_case_name, expected_err, text_cnt, ... ) do {    \
    ulong _text[ text_cnt ] = { __VA_ARGS__ };                                \
    test_program_exec( (test_case_name), 0UL, (expected_err), FD_VM_COMPUTE_UNIT_LIMIT, \
                          FD_SBPF_V3, _text, (text_cnt), syscalls, instr_ctx ); \
  } while(0)

# define FD_SBPF_INSTR(op, dst, src, off, val) (fd_vm_instr( op, dst, src, off, val ))

  TEST_PROGRAM_SUCCESS("add", 0x3, 5,
    FD_SBPF_INSTR(FD_SBPF_OP_MOV_IMM,   FD_SBPF_R0,  0,      0, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV_IMM,   FD_SBPF_R1,  0,      0, 2),
    FD_SBPF_INSTR(FD_SBPF_OP_ADD_IMM,   FD_SBPF_R0,  0,      0, 1),
    FD_SBPF_INSTR(FD_SBPF_OP_ADD_REG,   FD_SBPF_R0,  FD_SBPF_R1,  0, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,      0,      0,      0, 0),
  );

  TEST_PROGRAM_SUCCESS("add64", 0x3, 5,
    FD_SBPF_INSTR(FD_SBPF_OP_MOV_IMM,   FD_SBPF_R0,  0,      0, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV_IMM,   FD_SBPF_R1,  0,      0, 2),
    FD_SBPF_INSTR(FD_SBPF_OP_ADD64_IMM, FD_SBPF_R0,  0,      0, 1),
    FD_SBPF_INSTR(FD_SBPF_OP_ADD64_REG, FD_SBPF_R0,  FD_SBPF_R1,  0, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,      0,      0,      0, 0),
  );

  TEST_PROGRAM_SUCCESS("alu-arith", 0x150, 17,
    FD_SBPF_INSTR(FD_SBPF_OP_MOV_IMM,   FD_SBPF_R0,  0,      0, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV_IMM,   FD_SBPF_R1,  0,      0, 1),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV_IMM,   FD_SBPF_R2,  0,      0, 2),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV_IMM,   FD_SBPF_R3,  0,      0, 3),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV_IMM,   FD_SBPF_R4,  0,      0, 4),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV_IMM,   FD_SBPF_R5,  0,      0, 5),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV_IMM,   FD_SBPF_R6,  0,      0, 6),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV_IMM,   FD_SBPF_R7,  0,      0, 7),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV_IMM,   FD_SBPF_R8,  0,      0, 8),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV_IMM,   FD_SBPF_R9,  0,      0, 9),

    FD_SBPF_INSTR(FD_SBPF_OP_ADD_IMM,   FD_SBPF_R0,  0,      0, 23),
    FD_SBPF_INSTR(FD_SBPF_OP_ADD_REG,   FD_SBPF_R0,  FD_SBPF_R7,  0, 0),

    FD_SBPF_INSTR(FD_SBPF_OP_SUB_IMM,   FD_SBPF_R0,  0,      0, 13),
    FD_SBPF_INSTR(FD_SBPF_OP_SUB_REG,   FD_SBPF_R0,  FD_SBPF_R1,  0, 0),

    FD_SBPF_INSTR(FD_SBPF_OP_MUL_IMM,   FD_SBPF_R0,  0,      0, 7),
    FD_SBPF_INSTR(FD_SBPF_OP_MUL_REG,   FD_SBPF_R0,  FD_SBPF_R3,  0, 0),

    /* Divide by zero faults */
    //FD_SBPF_INSTR(FD_SBPF_OP_DIV_IMM,   FD_SBPF_R0,  0,      0, 2),
    //FD_SBPF_INSTR(FD_SBPF_OP_DIV_REG,   FD_SBPF_R0,  FD_SBPF_R4,  0, 0),

    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,      0,      0,      0, 0),
  );

  TEST_PROGRAM_SUCCESS("alu-bitwise", 0x11, 21,
    FD_SBPF_INSTR(FD_SBPF_OP_MOV_IMM,   FD_SBPF_R0,  0,      0, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV_IMM,   FD_SBPF_R1,  0,      0, 1),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV_IMM,   FD_SBPF_R2,  0,      0, 2),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV_IMM,   FD_SBPF_R3,  0,      0, 3),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV_IMM,   FD_SBPF_R4,  0,      0, 4),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV_IMM,   FD_SBPF_R5,  0,      0, 5),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV_IMM,   FD_SBPF_R6,  0,      0, 6),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV_IMM,   FD_SBPF_R7,  0,      0, 7),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV_IMM,   FD_SBPF_R8,  0,      0, 8),

    FD_SBPF_INSTR(FD_SBPF_OP_OR_REG,    FD_SBPF_R0,  FD_SBPF_R5,  0, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_OR_IMM,    FD_SBPF_R0,  0,      0, 0xa0),

    FD_SBPF_INSTR(FD_SBPF_OP_AND_IMM,   FD_SBPF_R0,  0,      0, 0xa3),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV_IMM,   FD_SBPF_R9,  0,      0, 0x91),
    FD_SBPF_INSTR(FD_SBPF_OP_AND_REG,   FD_SBPF_R0,  FD_SBPF_R9,  0, 0),

    FD_SBPF_INSTR(FD_SBPF_OP_LSH_IMM,   FD_SBPF_R0,  0,      0, 22),
    FD_SBPF_INSTR(FD_SBPF_OP_LSH_REG,   FD_SBPF_R0,  FD_SBPF_R8,  0, 0),

    FD_SBPF_INSTR(FD_SBPF_OP_RSH_IMM,   FD_SBPF_R0,  0,      0, 19),
    FD_SBPF_INSTR(FD_SBPF_OP_RSH_REG,   FD_SBPF_R0,  FD_SBPF_R7,  0, 0),

    FD_SBPF_INSTR(FD_SBPF_OP_XOR_IMM,   FD_SBPF_R0,  0,      0, 0x03),
    FD_SBPF_INSTR(FD_SBPF_OP_XOR_REG,   FD_SBPF_R0,  FD_SBPF_R2,  0, 0),

    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,      0,      0,      0, 0),
  );

  TEST_PROGRAM_SUCCESS("alu64-arith", 0x2a, 19,
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM,   FD_SBPF_R0,  0,      0, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM,   FD_SBPF_R1,  0,      0, 1),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM,   FD_SBPF_R2,  0,      0, 2),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM,   FD_SBPF_R3,  0,      0, 3),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM,   FD_SBPF_R4,  0,      0, 4),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM,   FD_SBPF_R5,  0,      0, 5),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM,   FD_SBPF_R6,  0,      0, 6),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM,   FD_SBPF_R7,  0,      0, 7),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM,   FD_SBPF_R8,  0,      0, 8),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM,   FD_SBPF_R9,  0,      0, 9),

    FD_SBPF_INSTR(FD_SBPF_OP_ADD64_IMM,   FD_SBPF_R0,  0,           0, 23),
    FD_SBPF_INSTR(FD_SBPF_OP_ADD64_REG,   FD_SBPF_R0,  FD_SBPF_R7,  0, 0),

    FD_SBPF_INSTR(FD_SBPF_OP_SUB64_IMM,   FD_SBPF_R0,  0,           0, 13),
    FD_SBPF_INSTR(FD_SBPF_OP_SUB64_REG,   FD_SBPF_R0,  FD_SBPF_R1,  0, 0),

    FD_SBPF_INSTR(FD_SBPF_OP_MUL64_IMM,   FD_SBPF_R0,  0,           0, 7),
    FD_SBPF_INSTR(FD_SBPF_OP_MUL64_REG,   FD_SBPF_R0,  FD_SBPF_R3,  0, 0),

    FD_SBPF_INSTR(FD_SBPF_OP_DIV64_IMM,   FD_SBPF_R0,  0,           0, 2),
    FD_SBPF_INSTR(FD_SBPF_OP_DIV64_REG,   FD_SBPF_R0,  FD_SBPF_R4,  0, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,      0,      0,      0, 0),
  );

  TEST_PROGRAM_SUCCESS("alu64-bitwise", 0x811, 21,
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM,   FD_SBPF_R0,  0,      0, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM,   FD_SBPF_R1,  0,      0, 1),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM,   FD_SBPF_R2,  0,      0, 2),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM,   FD_SBPF_R3,  0,      0, 3),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM,   FD_SBPF_R4,  0,      0, 4),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM,   FD_SBPF_R5,  0,      0, 5),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM,   FD_SBPF_R6,  0,      0, 6),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM,   FD_SBPF_R7,  0,      0, 7),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM,   FD_SBPF_R8,  0,      0, 8),

    FD_SBPF_INSTR(FD_SBPF_OP_OR64_REG,    FD_SBPF_R0,  FD_SBPF_R5,  0, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_OR64_IMM,    FD_SBPF_R0,  0,      0, 0xa0),

    FD_SBPF_INSTR(FD_SBPF_OP_AND64_IMM,   FD_SBPF_R0,  0,      0, 0xa3),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM,   FD_SBPF_R9,  0,      0, 0x91),
    FD_SBPF_INSTR(FD_SBPF_OP_AND64_REG,   FD_SBPF_R0,  FD_SBPF_R9,  0, 0),

    FD_SBPF_INSTR(FD_SBPF_OP_LSH64_IMM,   FD_SBPF_R0,  0,      0, 22),
    FD_SBPF_INSTR(FD_SBPF_OP_LSH64_REG,   FD_SBPF_R0,  FD_SBPF_R8,  0, 0),

    FD_SBPF_INSTR(FD_SBPF_OP_RSH64_IMM,   FD_SBPF_R0,  0,      0, 19),
    FD_SBPF_INSTR(FD_SBPF_OP_RSH64_REG,   FD_SBPF_R0,  FD_SBPF_R7,  0, 0),

    FD_SBPF_INSTR(FD_SBPF_OP_XOR64_IMM,   FD_SBPF_R0,  0,      0, 0x03),
    FD_SBPF_INSTR(FD_SBPF_OP_XOR64_REG,   FD_SBPF_R0,  FD_SBPF_R2,  0, 0),

    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,      0,      0,      0, 0),
  );

  TEST_PROGRAM_SUCCESS("arsh-reg", 0xffff8000, 5,
    FD_SBPF_INSTR(FD_SBPF_OP_MOV_IMM,   FD_SBPF_R0,  0,      0, 0xf8),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV_IMM,   FD_SBPF_R1,  0,      0, 16),
    FD_SBPF_INSTR(FD_SBPF_OP_LSH_IMM,   FD_SBPF_R0,  0,      0, 28),
    FD_SBPF_INSTR(FD_SBPF_OP_ARSH_REG,  FD_SBPF_R0,  FD_SBPF_R1,  0, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,      0,      0,      0, 0),
  );

  TEST_PROGRAM_SUCCESS("arsh", 0xffff8000, 4,
    FD_SBPF_INSTR(FD_SBPF_OP_MOV_IMM,   FD_SBPF_R0,  0,      0, 0xf8),
    FD_SBPF_INSTR(FD_SBPF_OP_LSH_IMM,   FD_SBPF_R0,  0,      0, 28),
    FD_SBPF_INSTR(FD_SBPF_OP_ARSH_IMM,  FD_SBPF_R0,  0,      0, 16),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,      0,      0,      0, 0),
  );

  TEST_PROGRAM_SUCCESS("arsh-high-shift", 0x4, 5,
    FD_SBPF_INSTR(FD_SBPF_OP_MOV_IMM,   FD_SBPF_R0,  0,      0, 0x8),
    FD_SBPF_INSTR(FD_SBPF_OP_LDDW,      FD_SBPF_R1,  0,      0, 0x1),
    FD_SBPF_INSTR(FD_SBPF_OP_ADDL_IMM,  0,      0,      0, 0x1),
    FD_SBPF_INSTR(FD_SBPF_OP_ARSH_REG,  FD_SBPF_R0,  FD_SBPF_R1,  0, 16),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,      0,      0,      0, 0),
  );

  TEST_PROGRAM_SUCCESS("arsh64", 0xfffffffffffffff8, 6,
    FD_SBPF_INSTR(FD_SBPF_OP_MOV_IMM,     FD_SBPF_R0,  0,      0, 1),
    FD_SBPF_INSTR(FD_SBPF_OP_LSH64_IMM,   FD_SBPF_R0,  0,      0, 63),
    FD_SBPF_INSTR(FD_SBPF_OP_ARSH64_IMM,  FD_SBPF_R0,  0,      0, 55),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV_IMM,     FD_SBPF_R1,  0,      0, 5),
    FD_SBPF_INSTR(FD_SBPF_OP_ARSH64_REG,  FD_SBPF_R0,  FD_SBPF_R1,  0, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,        0,      0,      0, 0),
  );

  TEST_PROGRAM_SUCCESS("be16-high", 0x1122, 4,
    FD_SBPF_INSTR(FD_SBPF_OP_LDDW,      FD_SBPF_R0,  0,      0, 0x44332211),
    FD_SBPF_INSTR(FD_SBPF_OP_ADDL_IMM,  0,      0,      0, 0x88776655),
    FD_SBPF_INSTR(FD_SBPF_OP_END_BE,    FD_SBPF_R0,  0,      0, 16),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,      0,      0,      0, 0),
  );

  TEST_PROGRAM_SUCCESS("be16", 0x1122, 3,
    FD_SBPF_INSTR(FD_SBPF_OP_MOV_IMM,   FD_SBPF_R0,  0,      0, 0x00002211),
    FD_SBPF_INSTR(FD_SBPF_OP_END_BE,    FD_SBPF_R0,  0,      0, 16),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,      0,      0,      0, 0),
  );

  TEST_PROGRAM_SUCCESS("be32-high", 0x11223344, 4,
    FD_SBPF_INSTR(FD_SBPF_OP_LDDW,      FD_SBPF_R0,  0,      0, 0x44332211),
    FD_SBPF_INSTR(FD_SBPF_OP_ADDL_IMM,  0,      0,      0, 0x88776655),
    FD_SBPF_INSTR(FD_SBPF_OP_END_BE,    FD_SBPF_R0,  0,      0, 32),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,      0,      0,      0, 0),
  );

  TEST_PROGRAM_SUCCESS("be32", 0x11223344, 3,
    FD_SBPF_INSTR(FD_SBPF_OP_MOV_IMM,   FD_SBPF_R0,  0,      0, 0x44332211),
    FD_SBPF_INSTR(FD_SBPF_OP_END_BE,    FD_SBPF_R0,  0,      0, 32),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,      0,      0,      0, 0),
  );

  TEST_PROGRAM_SUCCESS("be64", 0x1122334455667788, 4,
    FD_SBPF_INSTR(FD_SBPF_OP_LDDW,      FD_SBPF_R0,  0,      0, 0x44332211),
    FD_SBPF_INSTR(FD_SBPF_OP_ADDL_IMM,  0,      0,      0, 0x88776655),
    FD_SBPF_INSTR(FD_SBPF_OP_END_BE,    FD_SBPF_R0,  0,      0, 64),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,      0,      0,      0, 0),
  );

  TEST_PROGRAM_SUCCESS("div-high-divisor", 0x3, 5,
    FD_SBPF_INSTR(FD_SBPF_OP_MOV_IMM,   FD_SBPF_R0,  0,      0, 12),
    FD_SBPF_INSTR(FD_SBPF_OP_LDDW,      FD_SBPF_R1,  0,      0, 0x4),
    FD_SBPF_INSTR(FD_SBPF_OP_ADDL_IMM,  0,      0,      0, 0x1),
    FD_SBPF_INSTR(FD_SBPF_OP_DIV_REG,   FD_SBPF_R0,  FD_SBPF_R1,  0, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,      0,      0,      0, 0),
  );

  TEST_PROGRAM_SUCCESS("div-imm", 0x3, 4,
    FD_SBPF_INSTR(FD_SBPF_OP_LDDW,      FD_SBPF_R0,  0,      0, 0xc),
    FD_SBPF_INSTR(FD_SBPF_OP_ADDL_IMM,  0,      0,      0, 0x1),
    FD_SBPF_INSTR(FD_SBPF_OP_DIV_IMM,   FD_SBPF_R0,  0,      0, 4),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,      0,      0,      0, 0),
  );

  TEST_PROGRAM_SUCCESS("div-reg", 0x3, 5,
    FD_SBPF_INSTR(FD_SBPF_OP_LDDW,      FD_SBPF_R0,  0,      0, 0xc),
    FD_SBPF_INSTR(FD_SBPF_OP_ADDL_IMM,  0,      0,      0, 0x1),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV_IMM,   FD_SBPF_R1,  0,      0, 4),
    FD_SBPF_INSTR(FD_SBPF_OP_DIV_REG,   FD_SBPF_R0,  FD_SBPF_R1,  0, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,      0,      0,      0, 0),
  );

  TEST_PROGRAM_SUCCESS("div64-high-divisor", 0x15555555, 6,
    FD_SBPF_INSTR(FD_SBPF_OP_MOV_IMM,   FD_SBPF_R0,  0,      0, 12),
    FD_SBPF_INSTR(FD_SBPF_OP_LDDW,      FD_SBPF_R1,  0,      0, 0x4),
    FD_SBPF_INSTR(FD_SBPF_OP_ADDL_IMM,  0,      0,      0, 0x1),
    FD_SBPF_INSTR(FD_SBPF_OP_DIV64_REG, FD_SBPF_R1,  FD_SBPF_R0,  0, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV_REG,   FD_SBPF_R0,  FD_SBPF_R1,  0, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,      0,      0,      0, 0),
  );

  TEST_PROGRAM_SUCCESS("div64-imm", 0x40000003, 4,
    FD_SBPF_INSTR(FD_SBPF_OP_LDDW,      FD_SBPF_R0,  0,      0, 0xc),
    FD_SBPF_INSTR(FD_SBPF_OP_ADDL_IMM,  0,      0,      0, 0x1),
    FD_SBPF_INSTR(FD_SBPF_OP_DIV64_IMM, FD_SBPF_R0,  0,      0, 4),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,      0,      0,      0, 0),
  );

  TEST_PROGRAM_SUCCESS("div64-reg", 0x40000003, 6,
    FD_SBPF_INSTR(FD_SBPF_OP_LDDW,      FD_SBPF_R1,  0,      0, 0xc),
    FD_SBPF_INSTR(FD_SBPF_OP_ADDL_IMM,  0,      0,      0, 0x1),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV_IMM,   FD_SBPF_R0,  0,      0, 4),
    FD_SBPF_INSTR(FD_SBPF_OP_DIV64_REG, FD_SBPF_R1,  FD_SBPF_R0,  0, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV_REG,   FD_SBPF_R0,  FD_SBPF_R1,  0, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,      0,      0,      0, 0),
  );

  TEST_PROGRAM_SUCCESS("mod-high-divisor", 0x0, 5,
    FD_SBPF_INSTR(FD_SBPF_OP_MOV_IMM,   FD_SBPF_R0,  0,      0, 12),
    FD_SBPF_INSTR(FD_SBPF_OP_LDDW,      FD_SBPF_R1,  0,      0, 0x4),
    FD_SBPF_INSTR(FD_SBPF_OP_ADDL_IMM,  0,      0,      0, 0x1),
    FD_SBPF_INSTR(FD_SBPF_OP_MOD_REG,   FD_SBPF_R0,  FD_SBPF_R1,  0, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,      0,      0,      0, 0),
  );

  TEST_PROGRAM_SUCCESS("mod-imm", 0x0, 4,
    FD_SBPF_INSTR(FD_SBPF_OP_LDDW,      FD_SBPF_R0,  0,      0, 0xc),
    FD_SBPF_INSTR(FD_SBPF_OP_ADDL_IMM,  0,      0,      0, 0x1),
    FD_SBPF_INSTR(FD_SBPF_OP_MOD_IMM,   FD_SBPF_R0,  0,      0, 4),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,      0,      0,      0, 0),
  );

  TEST_PROGRAM_SUCCESS("mod-reg", 0x0, 5,
    FD_SBPF_INSTR(FD_SBPF_OP_LDDW,      FD_SBPF_R0,  0,      0, 0xc),
    FD_SBPF_INSTR(FD_SBPF_OP_ADDL_IMM,  0,      0,      0, 0x1),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV_IMM,   FD_SBPF_R1,  0,      0, 4),
    FD_SBPF_INSTR(FD_SBPF_OP_MOD_REG,   FD_SBPF_R0,  FD_SBPF_R1,  0, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,      0,      0,      0, 0),
  );

  TEST_PROGRAM_SUCCESS("mod64-high-divisor", 0x8, 6,
    FD_SBPF_INSTR(FD_SBPF_OP_MOV_IMM,   FD_SBPF_R0,  0,      0, 12),
    FD_SBPF_INSTR(FD_SBPF_OP_LDDW,      FD_SBPF_R1,  0,      0, 0x4),
    FD_SBPF_INSTR(FD_SBPF_OP_ADDL_IMM,  0,      0,      0, 0x1),
    FD_SBPF_INSTR(FD_SBPF_OP_MOD64_REG, FD_SBPF_R1,  FD_SBPF_R0,  0, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV_REG,   FD_SBPF_R0,  FD_SBPF_R1,  0, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,      0,      0,      0, 0),
  );

  TEST_PROGRAM_SUCCESS("mod64-imm", 0x0, 4,
    FD_SBPF_INSTR(FD_SBPF_OP_LDDW,      FD_SBPF_R0,  0,      0, 0xc),
    FD_SBPF_INSTR(FD_SBPF_OP_ADDL_IMM,  0,      0,      0, 0x1),
    FD_SBPF_INSTR(FD_SBPF_OP_MOD64_IMM, FD_SBPF_R0,  0,      0, 4),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,      0,      0,      0, 0),
  );

  TEST_PROGRAM_SUCCESS("mod64-reg", 0x0, 6,
    FD_SBPF_INSTR(FD_SBPF_OP_LDDW,      FD_SBPF_R1,  0,      0, 0xc),
    FD_SBPF_INSTR(FD_SBPF_OP_ADDL_IMM,  0,      0,      0, 0x1),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV_IMM,   FD_SBPF_R0,  0,      0, 4),
    FD_SBPF_INSTR(FD_SBPF_OP_MOD64_REG, FD_SBPF_R1,  FD_SBPF_R0,  0, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV_REG,   FD_SBPF_R0,  FD_SBPF_R1,  0, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,      0,      0,      0, 0),
  );

  TEST_PROGRAM_SUCCESS("early-exit", 0x3, 4,
    FD_SBPF_INSTR(FD_SBPF_OP_MOV_IMM,   FD_SBPF_R0,  0,      0, 3),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,      0,      0,      0, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV_IMM,   FD_SBPF_R0,  0,      0, 4),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,      0,      0,      0, 0),
  );

  TEST_PROGRAM_SUCCESS("exit-not-last", 0x0, 1,
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,      0,      0,      0, 0),
  );

  TEST_PROGRAM_SUCCESS("exit", 0x0, 2,
    FD_SBPF_INSTR(FD_SBPF_OP_MOV_IMM,   FD_SBPF_R0,  0,      0, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,      0,      0,      0, 0),
  );

  TEST_PROGRAM_SUCCESS("ja", 0x1, 4,
    FD_SBPF_INSTR(FD_SBPF_OP_MOV_IMM,   FD_SBPF_R0,  0,      0, 1),
    FD_SBPF_INSTR(FD_SBPF_OP_JA,        0,      0,     +1, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV_IMM,   FD_SBPF_R0,  0,      0, 2),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,      0,      0,      0, 0),
  );

  TEST_PROGRAM_SUCCESS("jeq-imm", 0x1, 8,
    FD_SBPF_INSTR(FD_SBPF_OP_MOV_IMM,   FD_SBPF_R0,  0,      0, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV_IMM,   FD_SBPF_R1,  0,      0, 0xa),
    FD_SBPF_INSTR(FD_SBPF_OP_JEQ_IMM,   FD_SBPF_R1,  0,     +4, 0xb),

    FD_SBPF_INSTR(FD_SBPF_OP_MOV_IMM,   FD_SBPF_R0,  0,      0, 1),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV_IMM,   FD_SBPF_R1,  0,      0, 0xb),
    FD_SBPF_INSTR(FD_SBPF_OP_JEQ_IMM,   FD_SBPF_R1,  0,     +1, 0xb),

    FD_SBPF_INSTR(FD_SBPF_OP_MOV_IMM,   FD_SBPF_R0,  0,      0, 2),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,      0,      0,      0, 0),
  );

  TEST_PROGRAM_SUCCESS("jeq-reg", 0x1, 9,
    FD_SBPF_INSTR(FD_SBPF_OP_MOV_IMM,   FD_SBPF_R0,  0,      0, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV_IMM,   FD_SBPF_R1,  0,      0, 0xa),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV_IMM,   FD_SBPF_R2,  0,      0, 0xb),
    FD_SBPF_INSTR(FD_SBPF_OP_JEQ_REG,   FD_SBPF_R1,  FD_SBPF_R2, +4, 0),

    FD_SBPF_INSTR(FD_SBPF_OP_MOV_IMM,   FD_SBPF_R0,  0,      0, 1),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV_IMM,   FD_SBPF_R1,  0,      0, 0xb),
    FD_SBPF_INSTR(FD_SBPF_OP_JEQ_REG,   FD_SBPF_R1,  FD_SBPF_R2, +1, 0),

    FD_SBPF_INSTR(FD_SBPF_OP_MOV_IMM,   FD_SBPF_R0,  0,      0, 2),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,      0,      0,      0, 0),
  );

  TEST_PROGRAM_SUCCESS("jge-imm", 0x1, 8,
    FD_SBPF_INSTR(FD_SBPF_OP_MOV_IMM,   FD_SBPF_R0,  0,      0, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV_IMM,   FD_SBPF_R1,  0,      0, 4),

    FD_SBPF_INSTR(FD_SBPF_OP_JGE_IMM,   FD_SBPF_R1,  0,     +2, 6),
    FD_SBPF_INSTR(FD_SBPF_OP_JGE_IMM,   FD_SBPF_R1,  0,     +1, 5),
    FD_SBPF_INSTR(FD_SBPF_OP_JGE_IMM,   FD_SBPF_R1,  0,     +1, 4),

    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,      0,      0,      0, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV_IMM,   FD_SBPF_R0,  0,      0, 1),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,      0,      0,      0, 0),
  );

  TEST_PROGRAM_SUCCESS("jge-reg", 0x1, 11,
    FD_SBPF_INSTR(FD_SBPF_OP_MOV_IMM,   FD_SBPF_R0,  0,      0, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV_IMM,   FD_SBPF_R1,  0,      0, 4),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV_IMM,   FD_SBPF_R2,  0,      0, 6),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV_IMM,   FD_SBPF_R3,  0,      0, 4),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV_IMM,   FD_SBPF_R4,  0,      0, 5),

    FD_SBPF_INSTR(FD_SBPF_OP_JGE_REG,   FD_SBPF_R1,  FD_SBPF_R2, +2, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_JGE_REG,   FD_SBPF_R1,  FD_SBPF_R4, +1, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_JGE_REG,   FD_SBPF_R1,  FD_SBPF_R3, +1, 0),

    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,      0,      0,      0, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV_IMM,   FD_SBPF_R0,  0,      0, 1),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,      0,      0,      0, 0),
  );

  TEST_PROGRAM_SUCCESS("jgt-imm", 0x1, 8,
    FD_SBPF_INSTR(FD_SBPF_OP_MOV_IMM,   FD_SBPF_R0,  0,      0, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV_IMM,   FD_SBPF_R1,  0,      0, 5),

    FD_SBPF_INSTR(FD_SBPF_OP_JGT_IMM,   FD_SBPF_R1,  0,     +2, 6),
    FD_SBPF_INSTR(FD_SBPF_OP_JGT_IMM,   FD_SBPF_R1,  0,     +1, 5),
    FD_SBPF_INSTR(FD_SBPF_OP_JGT_IMM,   FD_SBPF_R1,  0,     +1, 4),

    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,      0,      0,      0, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV_IMM,   FD_SBPF_R0,  0,      0, 1),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,      0,      0,      0, 0),
  );

  TEST_PROGRAM_SUCCESS("jgt-reg", 0x1, 10,
    FD_SBPF_INSTR(FD_SBPF_OP_MOV_IMM,   FD_SBPF_R0,  0,      0, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV_IMM,   FD_SBPF_R1,  0,      0, 5),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV_IMM,   FD_SBPF_R2,  0,      0, 6),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV_IMM,   FD_SBPF_R3,  0,      0, 4),

    FD_SBPF_INSTR(FD_SBPF_OP_JGT_REG,   FD_SBPF_R1,  FD_SBPF_R2, +2, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_JGT_REG,   FD_SBPF_R1,  FD_SBPF_R1, +1, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_JGT_REG,   FD_SBPF_R1,  FD_SBPF_R3, +1, 0),

    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,      0,      0,      0, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV_IMM,   FD_SBPF_R0,  0,      0, 1),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,      0,      0,      0, 0),
  );

  TEST_PROGRAM_SUCCESS("jle-imm", 0x1, 8,
    FD_SBPF_INSTR(FD_SBPF_OP_MOV_IMM,   FD_SBPF_R0,  0,      0, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV_IMM,   FD_SBPF_R1,  0,      0, 7),

    FD_SBPF_INSTR(FD_SBPF_OP_JLE_IMM,   FD_SBPF_R1,  0,     +2, 6),
    FD_SBPF_INSTR(FD_SBPF_OP_JLE_IMM,   FD_SBPF_R1,  0,     +2, 8),
    FD_SBPF_INSTR(FD_SBPF_OP_JLE_IMM,   FD_SBPF_R1,  0,     +1, 4),

    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,      0,      0,      0, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV_IMM,   FD_SBPF_R0,  0,      0, 1),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,      0,      0,      0, 0),
  );

  TEST_PROGRAM_SUCCESS("jle-reg", 0x1, 11,
    FD_SBPF_INSTR(FD_SBPF_OP_MOV_IMM,   FD_SBPF_R0,  0,      0, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV_IMM,   FD_SBPF_R1,  0,      0, 10),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV_IMM,   FD_SBPF_R2,  0,      0, 7),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV_IMM,   FD_SBPF_R3,  0,      0, 11),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV_IMM,   FD_SBPF_R4,  0,      0, 5),

    FD_SBPF_INSTR(FD_SBPF_OP_JLE_REG,   FD_SBPF_R1,  FD_SBPF_R2, +2, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_JLE_REG,   FD_SBPF_R1,  FD_SBPF_R4, +1, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_JLE_REG,   FD_SBPF_R1,  FD_SBPF_R3, +1, 0),

    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,      0,      0,      0, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV_IMM,   FD_SBPF_R0,  0,      0, 1),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,      0,      0,      0, 0),
  );

  TEST_PROGRAM_SUCCESS("jlt-imm", 0x1, 8,
    FD_SBPF_INSTR(FD_SBPF_OP_MOV_IMM,   FD_SBPF_R0,  0,      0, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV_IMM,   FD_SBPF_R1,  0,      0, 7),

    FD_SBPF_INSTR(FD_SBPF_OP_JLT_IMM,   FD_SBPF_R1,  0,     +2, 6),
    FD_SBPF_INSTR(FD_SBPF_OP_JLT_IMM,   FD_SBPF_R1,  0,     +2, 8),
    FD_SBPF_INSTR(FD_SBPF_OP_JLT_IMM,   FD_SBPF_R1,  0,     +1, 4),

    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,      0,      0,      0, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV_IMM,   FD_SBPF_R0,  0,      0, 1),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,      0,      0,      0, 0),
  );

  TEST_PROGRAM_SUCCESS("jlt-reg", 0x1, 11,
    FD_SBPF_INSTR(FD_SBPF_OP_MOV_IMM,   FD_SBPF_R0,  0,      0, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV_IMM,   FD_SBPF_R1,  0,      0, 10),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV_IMM,   FD_SBPF_R2,  0,      0, 7),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV_IMM,   FD_SBPF_R3,  0,      0, 11),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV_IMM,   FD_SBPF_R4,  0,      0, 5),

    FD_SBPF_INSTR(FD_SBPF_OP_JLT_REG,   FD_SBPF_R1,  FD_SBPF_R2, +2, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_JLT_REG,   FD_SBPF_R1,  FD_SBPF_R4, +1, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_JLT_REG,   FD_SBPF_R1,  FD_SBPF_R3, +1, 0),

    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,      0,      0,      0, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV_IMM,   FD_SBPF_R0,  0,      0, 1),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,      0,      0,      0, 0),
  );

  TEST_PROGRAM_SUCCESS("jne-imm", 0x1, 8,
    FD_SBPF_INSTR(FD_SBPF_OP_MOV_IMM,   FD_SBPF_R0,  0,      0, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV_IMM,   FD_SBPF_R1,  0,      0, 7),

    FD_SBPF_INSTR(FD_SBPF_OP_JNE_IMM,   FD_SBPF_R1,  0,     +2, 7),
    FD_SBPF_INSTR(FD_SBPF_OP_JNE_IMM,   FD_SBPF_R1,  0,     +2, 10),
    FD_SBPF_INSTR(FD_SBPF_OP_JNE_IMM,   FD_SBPF_R1,  0,     +1, 7),

    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,      0,      0,      0, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV_IMM,   FD_SBPF_R0,  0,      0, 1),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,      0,      0,      0, 0),
  );

  TEST_PROGRAM_SUCCESS("jne-reg", 0x1, 11,
    FD_SBPF_INSTR(FD_SBPF_OP_MOV_IMM,   FD_SBPF_R0,  0,      0, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV_IMM,   FD_SBPF_R1,  0,      0, 10),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV_IMM,   FD_SBPF_R2,  0,      0, 10),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV_IMM,   FD_SBPF_R3,  0,      0, 24),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV_IMM,   FD_SBPF_R4,  0,      0, 10),

    FD_SBPF_INSTR(FD_SBPF_OP_JNE_REG,   FD_SBPF_R1,  FD_SBPF_R2, +2, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_JNE_REG,   FD_SBPF_R1,  FD_SBPF_R4, +1, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_JNE_REG,   FD_SBPF_R1,  FD_SBPF_R3, +1, 0),

    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,      0,      0,      0, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV_IMM,   FD_SBPF_R0,  0,      0, 1),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,      0,      0,      0, 0),
  );

  TEST_PROGRAM_SUCCESS("jset-imm", 0x1, 8,
    FD_SBPF_INSTR(FD_SBPF_OP_MOV_IMM,   FD_SBPF_R0,  0,      0, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV_IMM,   FD_SBPF_R1,  0,      0, 0x8),

    FD_SBPF_INSTR(FD_SBPF_OP_JSET_IMM,   FD_SBPF_R1,  0,     +2, 0x7),
    FD_SBPF_INSTR(FD_SBPF_OP_JSET_IMM,   FD_SBPF_R1,  0,     +2, 0x9),
    FD_SBPF_INSTR(FD_SBPF_OP_JSET_IMM,   FD_SBPF_R1,  0,     +1, 0x10),

    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,      0,      0,      0, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV_IMM,   FD_SBPF_R0,  0,      0, 1),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,      0,      0,      0, 0),
  );

  TEST_PROGRAM_SUCCESS("jset-reg", 0x1, 11,
    FD_SBPF_INSTR(FD_SBPF_OP_MOV_IMM,   FD_SBPF_R0,  0,      0, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV_IMM,   FD_SBPF_R1,  0,      0, 0x8),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV_IMM,   FD_SBPF_R2,  0,      0, 0x7),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV_IMM,   FD_SBPF_R3,  0,      0, 0x9),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV_IMM,   FD_SBPF_R4,  0,      0, 0x0),

    FD_SBPF_INSTR(FD_SBPF_OP_JSET_REG,   FD_SBPF_R1,  FD_SBPF_R2, +2, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_JSET_REG,   FD_SBPF_R1,  FD_SBPF_R4, +1, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_JSET_REG,   FD_SBPF_R1,  FD_SBPF_R3, +1, 0),

    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,      0,      0,      0, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV_IMM,   FD_SBPF_R0,  0,      0, 1),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,      0,      0,      0, 0),
  );

  TEST_PROGRAM_SUCCESS("ldq", 0x1122334455667788, 3,
    FD_SBPF_INSTR(FD_SBPF_OP_LDDW,      FD_SBPF_R0,  0,      0, 0x55667788),
    FD_SBPF_INSTR(FD_SBPF_OP_ADDL_IMM,  0,      0,      0, 0x11223344),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,      0,      0,      0, 0),
  );

  TEST_PROGRAM_SUCCESS("stb-heap", 0x11, 5,
    FD_SBPF_INSTR(FD_SBPF_OP_LDDW,      FD_SBPF_R1,  0,      0, 0x0),
    FD_SBPF_INSTR(FD_SBPF_OP_ADDL_IMM,  0,      0,      0, 0x3),
    FD_SBPF_INSTR(FD_SBPF_OP_STB,       FD_SBPF_R1,  0,     +2, 0x11),
    FD_SBPF_INSTR(FD_SBPF_OP_LDXB,      FD_SBPF_R0,  FD_SBPF_R1, +2, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,      0,      0,      0, 0),
  );

  TEST_PROGRAM_SUCCESS("sth-heap", 0x1122, 5,
    FD_SBPF_INSTR(FD_SBPF_OP_LDDW,      FD_SBPF_R1,  0,      0, 0x0),
    FD_SBPF_INSTR(FD_SBPF_OP_ADDL_IMM,  0,      0,      0, 0x3),
    FD_SBPF_INSTR(FD_SBPF_OP_STH,       FD_SBPF_R1,  0,     +2, 0x1122),
    FD_SBPF_INSTR(FD_SBPF_OP_LDXH,      FD_SBPF_R0,  FD_SBPF_R1, +2, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,      0,      0,      0, 0),
  );

  TEST_PROGRAM_SUCCESS("stw-heap", 0x11223344, 5,
    FD_SBPF_INSTR(FD_SBPF_OP_LDDW,      FD_SBPF_R1,  0,      0, 0x0),
    FD_SBPF_INSTR(FD_SBPF_OP_ADDL_IMM,  0,      0,      0, 0x3),
    FD_SBPF_INSTR(FD_SBPF_OP_STW,       FD_SBPF_R1,  0,     +2, 0x11223344),
    FD_SBPF_INSTR(FD_SBPF_OP_LDXW,      FD_SBPF_R0,  FD_SBPF_R1, +2, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,      0,      0,      0, 0),
  );

  // TODO: check that we zero upper 32 bits
  TEST_PROGRAM_SUCCESS("stq-heap", 0x11223344, 5,
    FD_SBPF_INSTR(FD_SBPF_OP_LDDW,      FD_SBPF_R1,  0,      0, 0x0),
    FD_SBPF_INSTR(FD_SBPF_OP_ADDL_IMM,  0,      0,      0, 0x3),
    FD_SBPF_INSTR(FD_SBPF_OP_STDW,      FD_SBPF_R1,  0,     +2, 0x11223344),
    FD_SBPF_INSTR(FD_SBPF_OP_LDXDW,     FD_SBPF_R0,  FD_SBPF_R1, +2, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,      0,      0,      0, 0),
  );

  TEST_PROGRAM_SUCCESS("stxb-heap", 0x11, 6,
    FD_SBPF_INSTR(FD_SBPF_OP_LDDW,      FD_SBPF_R1,  0,      0, 0x0),
    FD_SBPF_INSTR(FD_SBPF_OP_ADDL_IMM,  0,      0,      0, 0x3),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV_IMM,   FD_SBPF_R2,  0,      0, 0x11),
    FD_SBPF_INSTR(FD_SBPF_OP_STXB,      FD_SBPF_R1,  FD_SBPF_R2, +2, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_LDXB,      FD_SBPF_R0,  FD_SBPF_R1, +2, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,      0,      0,      0, 0),
  );

  TEST_PROGRAM_SUCCESS("stxh-heap", 0x1122, 6,
    FD_SBPF_INSTR(FD_SBPF_OP_LDDW,      FD_SBPF_R1,  0,      0, 0x0),
    FD_SBPF_INSTR(FD_SBPF_OP_ADDL_IMM,  0,      0,      0, 0x3),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV_IMM,   FD_SBPF_R2,  0,      0, 0x1122),
    FD_SBPF_INSTR(FD_SBPF_OP_STXH,      FD_SBPF_R1,  FD_SBPF_R2, +2, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_LDXH,      FD_SBPF_R0,  FD_SBPF_R1, +2, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,      0,      0,      0, 0),
  );

  TEST_PROGRAM_SUCCESS("stxw-heap", 0x11223344, 6,
    FD_SBPF_INSTR(FD_SBPF_OP_LDDW,      FD_SBPF_R1,  0,      0, 0x0),
    FD_SBPF_INSTR(FD_SBPF_OP_ADDL_IMM,  0,      0,      0, 0x3),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV_IMM,   FD_SBPF_R2,  0,      0, 0x11223344),
    FD_SBPF_INSTR(FD_SBPF_OP_STXW,      FD_SBPF_R1,  FD_SBPF_R2, +2, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_LDXW,      FD_SBPF_R0,  FD_SBPF_R1, +2, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,      0,      0,      0, 0),
  );

  TEST_PROGRAM_SUCCESS("stxq-heap", 0x1122334455667788, 7,
    FD_SBPF_INSTR(FD_SBPF_OP_LDDW,      FD_SBPF_R1,  0,      0, 0x0),
    FD_SBPF_INSTR(FD_SBPF_OP_ADDL_IMM,  0,      0,      0, 0x3),
    FD_SBPF_INSTR(FD_SBPF_OP_LDDW,      FD_SBPF_R2,  0,      0, 0x55667788),
    FD_SBPF_INSTR(FD_SBPF_OP_ADDL_IMM,  0,      0,      0, 0x11223344),
    FD_SBPF_INSTR(FD_SBPF_OP_STXDW,     FD_SBPF_R1,  FD_SBPF_R2, +2, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_LDXDW,     FD_SBPF_R0,  FD_SBPF_R1, +2, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,      0,      0,      0, 0),
  );

  TEST_PROGRAM_SUCCESS("prime", 0x1, 16,
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM, FD_SBPF_R1,  0,      0, 10007),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM, FD_SBPF_R0,  0,      0, 0x1),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM, FD_SBPF_R2,  0,      0, 0x2),
    FD_SBPF_INSTR(FD_SBPF_OP_JGT_IMM,   FD_SBPF_R1,  0,     +4, 0x2),

    FD_SBPF_INSTR(FD_SBPF_OP_JA,        0,      0,    +10, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_ADD64_IMM, FD_SBPF_R2,  0,      0, 0x1),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM, FD_SBPF_R0,  0,      0, 0x1),
    FD_SBPF_INSTR(FD_SBPF_OP_JGE_REG,   FD_SBPF_R2,  FD_SBPF_R1, +7, 0),

    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_REG, FD_SBPF_R3,  FD_SBPF_R1,  0, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_DIV64_REG, FD_SBPF_R3,  FD_SBPF_R2,  0, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_MUL64_REG, FD_SBPF_R3,  FD_SBPF_R2,  0, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_REG, FD_SBPF_R4,  FD_SBPF_R1,  0, 0),

    FD_SBPF_INSTR(FD_SBPF_OP_SUB64_REG, FD_SBPF_R4,  FD_SBPF_R3,  0, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM, FD_SBPF_R0,  0,      0, 0x0),
    FD_SBPF_INSTR(FD_SBPF_OP_JNE_IMM,   FD_SBPF_R4,  0,    -10, 0x0),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,      0,      0,      0, 0),
  );

  TEST_PROGRAM_SUCCESS("syscall", 15, 7,
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM, FD_SBPF_R1,  0,      0, 1),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM, FD_SBPF_R2,  0,      0, 2),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM, FD_SBPF_R3,  0,      0, 3),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM, FD_SBPF_R4,  0,      0, 4),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM, FD_SBPF_R5,  0,      0, 5),
    FD_SBPF_INSTR(FD_SBPF_OP_CALL_IMM,      0,      0,      0, fd_murmur3_32( "accumulator", 11UL, 0U ) ),

    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,      0,      0,      0, 0),
  );

  /* SIMD-0178: Static syscalls (SBPF V3+) */

  TEST_V3_SUCCESS("static-syscall", 15, 7,
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM, FD_SBPF_R1,  0,      0, 1),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM, FD_SBPF_R2,  0,      0, 2),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM, FD_SBPF_R3,  0,      0, 3),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM, FD_SBPF_R4,  0,      0, 4),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM, FD_SBPF_R5,  0,      0, 5),
    FD_SBPF_INSTR(FD_SBPF_OP_CALL_IMM,  0,           0,      0, fd_murmur3_32( "accumulator", 11UL, 0U ) ),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,      0,           0,      0, 0),
  );

  TEST_V3_SUCCESS("static-syscall-args", 150, 7,
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM, FD_SBPF_R1,  0,      0, 10),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM, FD_SBPF_R2,  0,      0, 20),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM, FD_SBPF_R3,  0,      0, 30),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM, FD_SBPF_R4,  0,      0, 40),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM, FD_SBPF_R5,  0,      0, 50),
    FD_SBPF_INSTR(FD_SBPF_OP_CALL_IMM,  0,           0,      0, fd_murmur3_32( "accumulator", 11UL, 0U ) ),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,      0,           0,      0, 0),
  );

  TEST_V3_SUCCESS("static-call-fwd", 42, 4,
    FD_SBPF_INSTR(FD_SBPF_OP_CALL_IMM,  0,           1,   0, 1),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,      0,           0,   0, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM, FD_SBPF_R0,  0,   0, 42),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,      0,           0,   0, 0),
  );

  TEST_V3_SUCCESS("static-call-bwd", 99, 5,
    FD_SBPF_INSTR(FD_SBPF_OP_JA,        0,          0,     +2, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM, FD_SBPF_R0, 0,      0, 99),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,      0,          0,      0, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_CALL_IMM,  0,          1,      0, (uint)(int)-3),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,      0,          0,      0, 0),
  );

  TEST_V3_SUCCESS("static-call-boundary", 55, 5,
    FD_SBPF_INSTR(FD_SBPF_OP_CALL_IMM,  0,          1,      0, 2),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,      0,          0,      0, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM, FD_SBPF_R0, 0,      0, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM, FD_SBPF_R0, 0,      0, 55),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,      0,          0,      0, 0),
  );

  TEST_V3_SUCCESS("static-call-nested", 42, 8,
    FD_SBPF_INSTR(FD_SBPF_OP_CALL_IMM,  0,          1,      0, 2),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,      0,          0,      0, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM, FD_SBPF_R0, 0,      0, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_CALL_IMM,  0,          1,      0, 2),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,      0,          0,      0, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM, FD_SBPF_R0, 0,      0, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM, FD_SBPF_R0, 0,      0, 42),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,      0,          0,      0, 0),
  );

  TEST_V3_SUCCESS("static-call-then-external-syscall", 100, 11,
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM, FD_SBPF_R6, 0,           0, 100),
    FD_SBPF_INSTR(FD_SBPF_OP_CALL_IMM,  0,          1,           0, 7),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_REG, FD_SBPF_R1, FD_SBPF_R6, 0, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM, FD_SBPF_R2, 0,           0, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM, FD_SBPF_R3, 0,           0, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM, FD_SBPF_R4, 0,           0, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM, FD_SBPF_R5, 0,           0, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_CALL_IMM,  0,          0,           0, fd_murmur3_32( "accumulator", 11UL, 0U ) ),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,      0,          0,           0, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM, FD_SBPF_R0, 0,           0, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,      0,          0,           0, 0),
  );

  TEST_V3_ERROR("static-syscall-external-missing", FD_VM_ERR_EBPF_UNSUPPORTED_INSTRUCTION, 2,
    FD_SBPF_INSTR(FD_SBPF_OP_CALL_IMM, 0, 0, 0, 0xDEADBEEF),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,     0, 0, 0, 0),
  );

  TEST_V3_ERROR("static-syscall-external-zero", FD_VM_ERR_EBPF_UNSUPPORTED_INSTRUCTION, 2,
    FD_SBPF_INSTR(FD_SBPF_OP_CALL_IMM, 0, 0, 0, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,     0, 0, 0, 0),
  );

  TEST_V3_ERROR("static-call-oob-hi", FD_VM_ERR_EBPF_UNSUPPORTED_INSTRUCTION, 3,
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM, FD_SBPF_R0, 0, 0, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_CALL_IMM,  0,          1, 0, 100),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,      0,          0, 0, 0),
  );

  TEST_V3_ERROR("static-call-oob-lo", FD_VM_ERR_EBPF_UNSUPPORTED_INSTRUCTION, 3,
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM, FD_SBPF_R0, 0, 0, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_CALL_IMM,  0,          1, 0, (uint)(int)-10),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,      0,          0, 0, 0),
  );

  TEST_V3_ERROR("static-call-oob-eq", FD_VM_ERR_EBPF_UNSUPPORTED_INSTRUCTION, 4,
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM, FD_SBPF_R0, 0, 0, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_CALL_IMM,  0,          1, 0, 2), /* target=4==text_cnt */
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,      0,          0, 0, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,      0,          0, 0, 0),
  );

  TEST_V3_ERROR("static-bad-src-2", FD_VM_ERR_EBPF_UNSUPPORTED_INSTRUCTION, 2,
    FD_SBPF_INSTR(FD_SBPF_OP_CALL_IMM, 0, 2, 0, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,     0, 0, 0, 0),
  );

  TEST_V3_ERROR("static-bad-src-9", FD_VM_ERR_EBPF_UNSUPPORTED_INSTRUCTION, 2,
    FD_SBPF_INSTR(FD_SBPF_OP_CALL_IMM, 0, 9, 0, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,     0, 0, 0, 0),
  );

  TEST_V3_ERROR("static-stack-ovflw", FD_VM_ERR_EBPF_CALL_DEPTH_EXCEEDED, 2,
    FD_SBPF_INSTR(FD_SBPF_OP_CALL_IMM, 0, 1, 0, (uint)(int)-1), /* self-call (target=0) */
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,     0, 0, 0, 0),
  );

  /* SIMD-0377: JMP32 (SBPF V3+)
     Branch taken -> r0=2, not taken -> r0=1. */

  /* JEQ32 */

  TEST_V3_SUCCESS("jeq32-imm-taken", 2, 6,
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM, FD_SBPF_R0, 0, 0, 1),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM, FD_SBPF_R1, 0, 0, 5),
    FD_SBPF_INSTR(FD_SBPF_OP_JEQ32_IMM, FD_SBPF_R1, 0, 1, 5),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,      0,          0, 0, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM, FD_SBPF_R0, 0, 0, 2),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,      0,          0, 0, 0),
  );
  TEST_V3_SUCCESS("jeq32-imm-ntaken", 1, 6,
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM, FD_SBPF_R0, 0, 0, 1),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM, FD_SBPF_R1, 0, 0, 5),
    FD_SBPF_INSTR(FD_SBPF_OP_JEQ32_IMM, FD_SBPF_R1, 0, 1, 6),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,      0,          0, 0, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM, FD_SBPF_R0, 0, 0, 2),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,      0,          0, 0, 0),
  );
  TEST_V3_SUCCESS("jeq32-reg-taken", 2, 7,
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM, FD_SBPF_R0, 0,          0, 1),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM, FD_SBPF_R1, 0,          0, 5),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM, FD_SBPF_R2, 0,          0, 5),
    FD_SBPF_INSTR(FD_SBPF_OP_JEQ32_REG, FD_SBPF_R1, FD_SBPF_R2, 1, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,      0,          0,          0, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM, FD_SBPF_R0, 0,          0, 2),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,      0,          0,          0, 0),
  );
  TEST_V3_SUCCESS("jeq32-reg-ntaken", 1, 7,
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM, FD_SBPF_R0, 0,          0, 1),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM, FD_SBPF_R1, 0,          0, 5),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM, FD_SBPF_R2, 0,          0, 6),
    FD_SBPF_INSTR(FD_SBPF_OP_JEQ32_REG, FD_SBPF_R1, FD_SBPF_R2, 1, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,      0,          0,          0, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM, FD_SBPF_R0, 0,          0, 2),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,      0,          0,          0, 0),
  );

  /* JGT32 */

  TEST_V3_SUCCESS("jgt32-imm-taken", 2, 6,
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM, FD_SBPF_R0, 0, 0, 1),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM, FD_SBPF_R1, 0, 0, 6),
    FD_SBPF_INSTR(FD_SBPF_OP_JGT32_IMM, FD_SBPF_R1, 0, 1, 5),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,      0,          0, 0, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM, FD_SBPF_R0, 0, 0, 2),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,      0,          0, 0, 0),
  );
  TEST_V3_SUCCESS("jgt32-imm-ntaken", 1, 6,
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM, FD_SBPF_R0, 0, 0, 1),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM, FD_SBPF_R1, 0, 0, 5),
    FD_SBPF_INSTR(FD_SBPF_OP_JGT32_IMM, FD_SBPF_R1, 0, 1, 5),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,      0,          0, 0, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM, FD_SBPF_R0, 0, 0, 2),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,      0,          0, 0, 0),
  );
  TEST_V3_SUCCESS("jgt32-reg-taken", 2, 7,
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM, FD_SBPF_R0, 0,          0, 1),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM, FD_SBPF_R1, 0,          0, 6),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM, FD_SBPF_R2, 0,          0, 5),
    FD_SBPF_INSTR(FD_SBPF_OP_JGT32_REG, FD_SBPF_R1, FD_SBPF_R2, 1, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,      0,          0,          0, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM, FD_SBPF_R0, 0,          0, 2),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,      0,          0,          0, 0),
  );
  TEST_V3_SUCCESS("jgt32-reg-ntaken", 1, 7,
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM, FD_SBPF_R0, 0,          0, 1),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM, FD_SBPF_R1, 0,          0, 5),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM, FD_SBPF_R2, 0,          0, 5),
    FD_SBPF_INSTR(FD_SBPF_OP_JGT32_REG, FD_SBPF_R1, FD_SBPF_R2, 1, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,      0,          0,          0, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM, FD_SBPF_R0, 0,          0, 2),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,      0,          0,          0, 0),
  );

  /* JGE32 */

  TEST_V3_SUCCESS("jge32-imm-taken", 2, 6,
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM, FD_SBPF_R0, 0, 0, 1),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM, FD_SBPF_R1, 0, 0, 5),
    FD_SBPF_INSTR(FD_SBPF_OP_JGE32_IMM, FD_SBPF_R1, 0, 1, 5),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,      0,          0, 0, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM, FD_SBPF_R0, 0, 0, 2),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,      0,          0, 0, 0),
  );
  TEST_V3_SUCCESS("jge32-imm-ntaken", 1, 6,
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM, FD_SBPF_R0, 0, 0, 1),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM, FD_SBPF_R1, 0, 0, 4),
    FD_SBPF_INSTR(FD_SBPF_OP_JGE32_IMM, FD_SBPF_R1, 0, 1, 5),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,      0,          0, 0, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM, FD_SBPF_R0, 0, 0, 2),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,      0,          0, 0, 0),
  );
  TEST_V3_SUCCESS("jge32-reg-taken", 2, 7,
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM, FD_SBPF_R0, 0,          0, 1),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM, FD_SBPF_R1, 0,          0, 5),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM, FD_SBPF_R2, 0,          0, 5),
    FD_SBPF_INSTR(FD_SBPF_OP_JGE32_REG, FD_SBPF_R1, FD_SBPF_R2, 1, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,      0,          0,          0, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM, FD_SBPF_R0, 0,          0, 2),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,      0,          0,          0, 0),
  );
  TEST_V3_SUCCESS("jge32-reg-ntaken", 1, 7,
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM, FD_SBPF_R0, 0,          0, 1),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM, FD_SBPF_R1, 0,          0, 4),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM, FD_SBPF_R2, 0,          0, 5),
    FD_SBPF_INSTR(FD_SBPF_OP_JGE32_REG, FD_SBPF_R1, FD_SBPF_R2, 1, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,      0,          0,          0, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM, FD_SBPF_R0, 0,          0, 2),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,      0,          0,          0, 0),
  );

  /* JSET32 */

  TEST_V3_SUCCESS("jset32-imm-taken", 2, 6,
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM,  FD_SBPF_R0, 0, 0, 1),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM,  FD_SBPF_R1, 0, 0, 3),
    FD_SBPF_INSTR(FD_SBPF_OP_JSET32_IMM, FD_SBPF_R1, 0, 1, 1),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,       0,          0, 0, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM,  FD_SBPF_R0, 0, 0, 2),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,       0,          0, 0, 0),
  );
  TEST_V3_SUCCESS("jset32-imm-ntaken", 1, 6,
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM,  FD_SBPF_R0, 0, 0, 1),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM,  FD_SBPF_R1, 0, 0, 4),
    FD_SBPF_INSTR(FD_SBPF_OP_JSET32_IMM, FD_SBPF_R1, 0, 1, 2),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,       0,          0, 0, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM,  FD_SBPF_R0, 0, 0, 2),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,       0,          0, 0, 0),
  );
  TEST_V3_SUCCESS("jset32-reg-taken", 2, 7,
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM,  FD_SBPF_R0, 0,          0, 1),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM,  FD_SBPF_R1, 0,          0, 3),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM,  FD_SBPF_R2, 0,          0, 1),
    FD_SBPF_INSTR(FD_SBPF_OP_JSET32_REG, FD_SBPF_R1, FD_SBPF_R2, 1, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,       0,          0,          0, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM,  FD_SBPF_R0, 0,          0, 2),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,       0,          0,          0, 0),
  );
  TEST_V3_SUCCESS("jset32-reg-ntaken", 1, 7,
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM,  FD_SBPF_R0, 0,          0, 1),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM,  FD_SBPF_R1, 0,          0, 4),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM,  FD_SBPF_R2, 0,          0, 2),
    FD_SBPF_INSTR(FD_SBPF_OP_JSET32_REG, FD_SBPF_R1, FD_SBPF_R2, 1, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,       0,          0,          0, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM,  FD_SBPF_R0, 0,          0, 2),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,       0,          0,          0, 0),
  );

  /* JNE32 */

  TEST_V3_SUCCESS("jne32-imm-taken", 2, 6,
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM, FD_SBPF_R0, 0, 0, 1),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM, FD_SBPF_R1, 0, 0, 5),
    FD_SBPF_INSTR(FD_SBPF_OP_JNE32_IMM, FD_SBPF_R1, 0, 1, 6),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,      0,          0, 0, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM, FD_SBPF_R0, 0, 0, 2),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,      0,          0, 0, 0),
  );
  TEST_V3_SUCCESS("jne32-imm-ntaken", 1, 6,
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM, FD_SBPF_R0, 0, 0, 1),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM, FD_SBPF_R1, 0, 0, 5),
    FD_SBPF_INSTR(FD_SBPF_OP_JNE32_IMM, FD_SBPF_R1, 0, 1, 5),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,      0,          0, 0, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM, FD_SBPF_R0, 0, 0, 2),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,      0,          0, 0, 0),
  );
  TEST_V3_SUCCESS("jne32-reg-taken", 2, 7,
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM, FD_SBPF_R0, 0,          0, 1),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM, FD_SBPF_R1, 0,          0, 5),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM, FD_SBPF_R2, 0,          0, 6),
    FD_SBPF_INSTR(FD_SBPF_OP_JNE32_REG, FD_SBPF_R1, FD_SBPF_R2, 1, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,      0,          0,          0, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM, FD_SBPF_R0, 0,          0, 2),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,      0,          0,          0, 0),
  );
  TEST_V3_SUCCESS("jne32-reg-ntaken", 1, 7,
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM, FD_SBPF_R0, 0,          0, 1),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM, FD_SBPF_R1, 0,          0, 5),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM, FD_SBPF_R2, 0,          0, 5),
    FD_SBPF_INSTR(FD_SBPF_OP_JNE32_REG, FD_SBPF_R1, FD_SBPF_R2, 1, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,      0,          0,          0, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM, FD_SBPF_R0, 0,          0, 2),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,      0,          0,          0, 0),
  );

  /* JSGT32 */

  TEST_V3_SUCCESS("jsgt32-imm-taken", 2, 6,
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM,  FD_SBPF_R0, 0, 0, 1),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM,  FD_SBPF_R1, 0, 0, 1),
    FD_SBPF_INSTR(FD_SBPF_OP_JSGT32_IMM, FD_SBPF_R1, 0, 1, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,       0,          0, 0, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM,  FD_SBPF_R0, 0, 0, 2),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,       0,          0, 0, 0),
  );
  TEST_V3_SUCCESS("jsgt32-imm-ntaken", 1, 6,
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM,  FD_SBPF_R0, 0, 0, 1),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM,  FD_SBPF_R1, 0, 0, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_JSGT32_IMM, FD_SBPF_R1, 0, 1, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,       0,          0, 0, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM,  FD_SBPF_R0, 0, 0, 2),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,       0,          0, 0, 0),
  );
  TEST_V3_SUCCESS("jsgt32-reg-taken", 2, 7,
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM,  FD_SBPF_R0, 0,          0, 1),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM,  FD_SBPF_R1, 0,          0, 1),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM,  FD_SBPF_R2, 0,          0, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_JSGT32_REG, FD_SBPF_R1, FD_SBPF_R2, 1, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,       0,          0,          0, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM,  FD_SBPF_R0, 0,          0, 2),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,       0,          0,          0, 0),
  );
  TEST_V3_SUCCESS("jsgt32-reg-ntaken", 1, 7,
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM,  FD_SBPF_R0, 0,          0, 1),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM,  FD_SBPF_R1, 0,          0, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM,  FD_SBPF_R2, 0,          0, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_JSGT32_REG, FD_SBPF_R1, FD_SBPF_R2, 1, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,       0,          0,          0, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM,  FD_SBPF_R0, 0,          0, 2),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,       0,          0,          0, 0),
  );

  /* JSGE32 */

  TEST_V3_SUCCESS("jsge32-imm-taken", 2, 6,
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM,  FD_SBPF_R0, 0, 0, 1),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM,  FD_SBPF_R1, 0, 0, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_JSGE32_IMM, FD_SBPF_R1, 0, 1, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,       0,          0, 0, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM,  FD_SBPF_R0, 0, 0, 2),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,       0,          0, 0, 0),
  );
  TEST_V3_SUCCESS("jsge32-imm-ntaken", 1, 6,
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM,  FD_SBPF_R0, 0, 0, 1),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM,  FD_SBPF_R1, 0, 0, (uint)(int)-1),
    FD_SBPF_INSTR(FD_SBPF_OP_JSGE32_IMM, FD_SBPF_R1, 0, 1, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,       0,          0, 0, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM,  FD_SBPF_R0, 0, 0, 2),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,       0,          0, 0, 0),
  );
  TEST_V3_SUCCESS("jsge32-reg-taken", 2, 7,
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM,  FD_SBPF_R0, 0,          0, 1),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM,  FD_SBPF_R1, 0,          0, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM,  FD_SBPF_R2, 0,          0, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_JSGE32_REG, FD_SBPF_R1, FD_SBPF_R2, 1, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,       0,          0,          0, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM,  FD_SBPF_R0, 0,          0, 2),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,       0,          0,          0, 0),
  );
  TEST_V3_SUCCESS("jsge32-reg-ntaken", 1, 7,
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM,  FD_SBPF_R0, 0,          0, 1),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM,  FD_SBPF_R1, 0,          0, (uint)(int)-1),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM,  FD_SBPF_R2, 0,          0, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_JSGE32_REG, FD_SBPF_R1, FD_SBPF_R2, 1, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,       0,          0,          0, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM,  FD_SBPF_R0, 0,          0, 2),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,       0,          0,          0, 0),
  );

  /* JLT32 */

  TEST_V3_SUCCESS("jlt32-imm-taken", 2, 6,
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM, FD_SBPF_R0, 0, 0, 1),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM, FD_SBPF_R1, 0, 0, 4),
    FD_SBPF_INSTR(FD_SBPF_OP_JLT32_IMM, FD_SBPF_R1, 0, 1, 5),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,      0,          0, 0, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM, FD_SBPF_R0, 0, 0, 2),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,      0,          0, 0, 0),
  );
  TEST_V3_SUCCESS("jlt32-imm-ntaken", 1, 6,
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM, FD_SBPF_R0, 0, 0, 1),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM, FD_SBPF_R1, 0, 0, 5),
    FD_SBPF_INSTR(FD_SBPF_OP_JLT32_IMM, FD_SBPF_R1, 0, 1, 5),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,      0,          0, 0, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM, FD_SBPF_R0, 0, 0, 2),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,      0,          0, 0, 0),
  );
  TEST_V3_SUCCESS("jlt32-reg-taken", 2, 7,
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM, FD_SBPF_R0, 0,          0, 1),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM, FD_SBPF_R1, 0,          0, 4),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM, FD_SBPF_R2, 0,          0, 5),
    FD_SBPF_INSTR(FD_SBPF_OP_JLT32_REG, FD_SBPF_R1, FD_SBPF_R2, 1, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,      0,          0,          0, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM, FD_SBPF_R0, 0,          0, 2),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,      0,          0,          0, 0),
  );
  TEST_V3_SUCCESS("jlt32-reg-ntaken", 1, 7,
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM, FD_SBPF_R0, 0,          0, 1),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM, FD_SBPF_R1, 0,          0, 5),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM, FD_SBPF_R2, 0,          0, 5),
    FD_SBPF_INSTR(FD_SBPF_OP_JLT32_REG, FD_SBPF_R1, FD_SBPF_R2, 1, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,      0,          0,          0, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM, FD_SBPF_R0, 0,          0, 2),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,      0,          0,          0, 0),
  );

  /* JLE32 */

  TEST_V3_SUCCESS("jle32-imm-taken", 2, 6,
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM, FD_SBPF_R0, 0, 0, 1),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM, FD_SBPF_R1, 0, 0, 5),
    FD_SBPF_INSTR(FD_SBPF_OP_JLE32_IMM, FD_SBPF_R1, 0, 1, 5),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,      0,          0, 0, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM, FD_SBPF_R0, 0, 0, 2),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,      0,          0, 0, 0),
  );
  TEST_V3_SUCCESS("jle32-imm-ntaken", 1, 6,
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM, FD_SBPF_R0, 0, 0, 1),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM, FD_SBPF_R1, 0, 0, 6),
    FD_SBPF_INSTR(FD_SBPF_OP_JLE32_IMM, FD_SBPF_R1, 0, 1, 5),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,      0,          0, 0, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM, FD_SBPF_R0, 0, 0, 2),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,      0,          0, 0, 0),
  );
  TEST_V3_SUCCESS("jle32-reg-taken", 2, 7,
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM, FD_SBPF_R0, 0,          0, 1),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM, FD_SBPF_R1, 0,          0, 5),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM, FD_SBPF_R2, 0,          0, 5),
    FD_SBPF_INSTR(FD_SBPF_OP_JLE32_REG, FD_SBPF_R1, FD_SBPF_R2, 1, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,      0,          0,          0, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM, FD_SBPF_R0, 0,          0, 2),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,      0,          0,          0, 0),
  );
  TEST_V3_SUCCESS("jle32-reg-ntaken", 1, 7,
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM, FD_SBPF_R0, 0,          0, 1),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM, FD_SBPF_R1, 0,          0, 6),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM, FD_SBPF_R2, 0,          0, 5),
    FD_SBPF_INSTR(FD_SBPF_OP_JLE32_REG, FD_SBPF_R1, FD_SBPF_R2, 1, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,      0,          0,          0, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM, FD_SBPF_R0, 0,          0, 2),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,      0,          0,          0, 0),
  );

  /* JSLT32 */

  TEST_V3_SUCCESS("jslt32-imm-taken", 2, 6,
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM,  FD_SBPF_R0, 0, 0, 1),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM,  FD_SBPF_R1, 0, 0, (uint)(int)-1),
    FD_SBPF_INSTR(FD_SBPF_OP_JSLT32_IMM, FD_SBPF_R1, 0, 1, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,       0,          0, 0, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM,  FD_SBPF_R0, 0, 0, 2),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,       0,          0, 0, 0),
  );
  TEST_V3_SUCCESS("jslt32-imm-ntaken", 1, 6,
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM,  FD_SBPF_R0, 0, 0, 1),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM,  FD_SBPF_R1, 0, 0, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_JSLT32_IMM, FD_SBPF_R1, 0, 1, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,       0,          0, 0, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM,  FD_SBPF_R0, 0, 0, 2),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,       0,          0, 0, 0),
  );
  TEST_V3_SUCCESS("jslt32-reg-taken", 2, 7,
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM,  FD_SBPF_R0, 0,          0, 1),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM,  FD_SBPF_R1, 0,          0, (uint)(int)-1),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM,  FD_SBPF_R2, 0,          0, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_JSLT32_REG, FD_SBPF_R1, FD_SBPF_R2, 1, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,       0,          0,          0, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM,  FD_SBPF_R0, 0,          0, 2),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,       0,          0,          0, 0),
  );
  TEST_V3_SUCCESS("jslt32-reg-ntaken", 1, 7,
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM,  FD_SBPF_R0, 0,          0, 1),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM,  FD_SBPF_R1, 0,          0, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM,  FD_SBPF_R2, 0,          0, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_JSLT32_REG, FD_SBPF_R1, FD_SBPF_R2, 1, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,       0,          0,          0, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM,  FD_SBPF_R0, 0,          0, 2),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,       0,          0,          0, 0),
  );

  /* JSLE32 */

  TEST_V3_SUCCESS("jsle32-imm-taken", 2, 6,
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM,  FD_SBPF_R0, 0, 0, 1),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM,  FD_SBPF_R1, 0, 0, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_JSLE32_IMM, FD_SBPF_R1, 0, 1, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,       0,          0, 0, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM,  FD_SBPF_R0, 0, 0, 2),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,       0,          0, 0, 0),
  );
  TEST_V3_SUCCESS("jsle32-imm-ntaken", 1, 6,
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM,  FD_SBPF_R0, 0, 0, 1),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM,  FD_SBPF_R1, 0, 0, 1),
    FD_SBPF_INSTR(FD_SBPF_OP_JSLE32_IMM, FD_SBPF_R1, 0, 1, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,       0,          0, 0, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM,  FD_SBPF_R0, 0, 0, 2),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,       0,          0, 0, 0),
  );
  TEST_V3_SUCCESS("jsle32-reg-taken", 2, 7,
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM,  FD_SBPF_R0, 0,          0, 1),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM,  FD_SBPF_R1, 0,          0, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM,  FD_SBPF_R2, 0,          0, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_JSLE32_REG, FD_SBPF_R1, FD_SBPF_R2, 1, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,       0,          0,          0, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM,  FD_SBPF_R0, 0,          0, 2),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,       0,          0,          0, 0),
  );
  TEST_V3_SUCCESS("jsle32-reg-ntaken", 1, 7,
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM,  FD_SBPF_R0, 0,          0, 1),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM,  FD_SBPF_R1, 0,          0, 1),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM,  FD_SBPF_R2, 0,          0, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_JSLE32_REG, FD_SBPF_R1, FD_SBPF_R2, 1, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,       0,          0,          0, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM,  FD_SBPF_R0, 0,          0, 2),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,       0,          0,          0, 0),
  );

  /* JMP32 32-bit truncation: upper 32 bits should be ignored */
  TEST_V3_SUCCESS("jeq32-trunc-imm", 2, 7,
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM, FD_SBPF_R0, 0, 0, 1),
    FD_SBPF_INSTR(FD_SBPF_OP_LDDW,      FD_SBPF_R1, 0, 0, 5),
    FD_SBPF_INSTR(0,                     0,          0, 0, 1),
    FD_SBPF_INSTR(FD_SBPF_OP_JEQ32_IMM, FD_SBPF_R1, 0, 1, 5),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,      0,          0, 0, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM, FD_SBPF_R0, 0, 0, 2),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,      0,          0, 0, 0),
  );

  TEST_V3_SUCCESS("jeq32-trunc-reg", 2, 9,
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM, FD_SBPF_R0, 0,          0, 1),
    FD_SBPF_INSTR(FD_SBPF_OP_LDDW,      FD_SBPF_R1, 0,          0, 5),
    FD_SBPF_INSTR(0,                     0,          0,          0, 1),
    FD_SBPF_INSTR(FD_SBPF_OP_LDDW,      FD_SBPF_R2, 0,          0, 5),
    FD_SBPF_INSTR(0,                     0,          0,          0, 2),
    FD_SBPF_INSTR(FD_SBPF_OP_JEQ32_REG, FD_SBPF_R1, FD_SBPF_R2, 1, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,      0,          0,          0, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM, FD_SBPF_R0, 0,          0, 2),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,      0,          0,          0, 0),
  );

  TEST_V3_SUCCESS("jne32-trunc-reg", 1, 9,
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM, FD_SBPF_R0, 0,          0, 1),
    FD_SBPF_INSTR(FD_SBPF_OP_LDDW,      FD_SBPF_R1, 0,          0, 0x42),
    FD_SBPF_INSTR(0,                     0,          0,          0, 0xDEAD),
    FD_SBPF_INSTR(FD_SBPF_OP_LDDW,      FD_SBPF_R2, 0,          0, 0x42),
    FD_SBPF_INSTR(0,                     0,          0,          0, 0xBEEF),
    FD_SBPF_INSTR(FD_SBPF_OP_JNE32_REG, FD_SBPF_R1, FD_SBPF_R2, 1, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,      0,          0,          0, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM, FD_SBPF_R0, 0,          0, 2),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,      0,          0,          0, 0),
  );

  TEST_V3_SUCCESS("jeq32-hi-set-lo0", 2, 7,
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM, FD_SBPF_R0, 0, 0, 1),
    FD_SBPF_INSTR(FD_SBPF_OP_LDDW,      FD_SBPF_R1, 0, 0, 0),
    FD_SBPF_INSTR(0,                     0,          0, 0, 0xFFFFFFFFU),
    FD_SBPF_INSTR(FD_SBPF_OP_JEQ32_IMM, FD_SBPF_R1, 0, 1, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,      0,          0, 0, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM, FD_SBPF_R0, 0, 0, 2),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,      0,          0, 0, 0),
  );

  /* JMP32 signed vs unsigned cross-boundary edge cases */
  TEST_V3_SUCCESS("jgt32-0x80000000", 1, 6,
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM, FD_SBPF_R0, 0, 0, 1),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM, FD_SBPF_R1, 0, 0, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_JGT32_IMM, FD_SBPF_R1, 0, 1, 0x80000000U),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,      0,          0, 0, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM, FD_SBPF_R0, 0, 0, 2),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,      0,          0, 0, 0),
  );
  TEST_V3_SUCCESS("jsgt32-0x80000000", 2, 6,
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM,  FD_SBPF_R0, 0, 0, 1),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM,  FD_SBPF_R1, 0, 0, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_JSGT32_IMM, FD_SBPF_R1, 0, 1, 0x80000000U),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,       0,          0, 0, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM,  FD_SBPF_R0, 0, 0, 2),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,       0,          0, 0, 0),
  );

  TEST_V3_SUCCESS("jgt32-0xffffffff", 2, 6,
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM, FD_SBPF_R0, 0, 0, 1),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM, FD_SBPF_R1, 0, 0, (uint)(int)-1),
    FD_SBPF_INSTR(FD_SBPF_OP_JGT32_IMM, FD_SBPF_R1, 0, 1, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,      0,          0, 0, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM, FD_SBPF_R0, 0, 0, 2),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,      0,          0, 0, 0),
  );
  TEST_V3_SUCCESS("jsgt32-neg1-vs-0", 1, 6,
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM,  FD_SBPF_R0, 0, 0, 1),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM,  FD_SBPF_R1, 0, 0, (uint)(int)-1),
    FD_SBPF_INSTR(FD_SBPF_OP_JSGT32_IMM, FD_SBPF_R1, 0, 1, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,       0,          0, 0, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM,  FD_SBPF_R0, 0, 0, 2),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,       0,          0, 0, 0),
  );

  TEST_V3_SUCCESS("jsgt32-max-vs-min", 2, 6,
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM,  FD_SBPF_R0, 0, 0, 1),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM,  FD_SBPF_R1, 0, 0, 0x7FFFFFFFU),
    FD_SBPF_INSTR(FD_SBPF_OP_JSGT32_IMM, FD_SBPF_R1, 0, 1, 0x80000000U),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,       0,          0, 0, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM,  FD_SBPF_R0, 0, 0, 2),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,       0,          0, 0, 0),
  );
  TEST_V3_SUCCESS("jgt32-max-vs-min", 1, 6,
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM, FD_SBPF_R0, 0, 0, 1),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM, FD_SBPF_R1, 0, 0, 0x7FFFFFFFU),
    FD_SBPF_INSTR(FD_SBPF_OP_JGT32_IMM, FD_SBPF_R1, 0, 1, 0x80000000U),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,      0,          0, 0, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM, FD_SBPF_R0, 0, 0, 2),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,      0,          0, 0, 0),
  );

  TEST_V3_SUCCESS("jsgt32-neg2-neg1", 1, 6,
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM,  FD_SBPF_R0, 0, 0, 1),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM,  FD_SBPF_R1, 0, 0, (uint)(int)-2),
    FD_SBPF_INSTR(FD_SBPF_OP_JSGT32_IMM, FD_SBPF_R1, 0, 1, (uint)(int)-1),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,       0,          0, 0, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM,  FD_SBPF_R0, 0, 0, 2),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,       0,          0, 0, 0),
  );
  TEST_V3_SUCCESS("jsgt32-neg1-neg2", 2, 6,
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM,  FD_SBPF_R0, 0, 0, 1),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM,  FD_SBPF_R1, 0, 0, (uint)(int)-1),
    FD_SBPF_INSTR(FD_SBPF_OP_JSGT32_IMM, FD_SBPF_R1, 0, 1, (uint)(int)-2),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,       0,          0, 0, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM,  FD_SBPF_R0, 0, 0, 2),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,       0,          0, 0, 0),
  );

  TEST_V3_SUCCESS("jsge32-min-vs-max", 1, 6,
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM,  FD_SBPF_R0, 0, 0, 1),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM,  FD_SBPF_R1, 0, 0, 0x80000000U),
    FD_SBPF_INSTR(FD_SBPF_OP_JSGE32_IMM, FD_SBPF_R1, 0, 1, 0x7FFFFFFFU),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,       0,          0, 0, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM,  FD_SBPF_R0, 0, 0, 2),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,       0,          0, 0, 0),
  );
  TEST_V3_SUCCESS("jge32-min-vs-max", 2, 6,
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM, FD_SBPF_R0, 0, 0, 1),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM, FD_SBPF_R1, 0, 0, 0x80000000U),
    FD_SBPF_INSTR(FD_SBPF_OP_JGE32_IMM, FD_SBPF_R1, 0, 1, 0x7FFFFFFFU),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,      0,          0, 0, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM, FD_SBPF_R0, 0, 0, 2),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,      0,          0, 0, 0),
  );

  TEST_V3_SUCCESS("jslt32-max-vs-min", 1, 6,
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM,  FD_SBPF_R0, 0, 0, 1),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM,  FD_SBPF_R1, 0, 0, 0x7FFFFFFFU),
    FD_SBPF_INSTR(FD_SBPF_OP_JSLT32_IMM, FD_SBPF_R1, 0, 1, 0x80000000U),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,       0,          0, 0, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM,  FD_SBPF_R0, 0, 0, 2),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,       0,          0, 0, 0),
  );
  TEST_V3_SUCCESS("jlt32-max-vs-min", 2, 6,
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM, FD_SBPF_R0, 0, 0, 1),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM, FD_SBPF_R1, 0, 0, 0x7FFFFFFFU),
    FD_SBPF_INSTR(FD_SBPF_OP_JLT32_IMM, FD_SBPF_R1, 0, 1, 0x80000000U),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,      0,          0, 0, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM, FD_SBPF_R0, 0, 0, 2),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,      0,          0, 0, 0),
  );

  /* JSET32 bit-test edge cases */
  TEST_V3_SUCCESS("jset32-no-overlap", 1, 6,
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM,  FD_SBPF_R0, 0, 0, 1),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM,  FD_SBPF_R1, 0, 0, 0xAAAAAAAAU),
    FD_SBPF_INSTR(FD_SBPF_OP_JSET32_IMM, FD_SBPF_R1, 0, 1, 0x55555555U),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,       0,          0, 0, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM,  FD_SBPF_R0, 0, 0, 2),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,       0,          0, 0, 0),
  );

  TEST_V3_SUCCESS("jset32-all-overlap", 2, 6,
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM,  FD_SBPF_R0, 0, 0, 1),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM,  FD_SBPF_R1, 0, 0, (uint)(int)-1),
    FD_SBPF_INSTR(FD_SBPF_OP_JSET32_IMM, FD_SBPF_R1, 0, 1, 0xFFFFFFFFU),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,       0,          0, 0, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM,  FD_SBPF_R0, 0, 0, 2),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,       0,          0, 0, 0),
  );

  TEST_V3_SUCCESS("jset32-high-bit", 2, 6,
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM,  FD_SBPF_R0, 0, 0, 1),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM,  FD_SBPF_R1, 0, 0, 0x80000000U),
    FD_SBPF_INSTR(FD_SBPF_OP_JSET32_IMM, FD_SBPF_R1, 0, 1, 0x80000000U),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,       0,          0, 0, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM,  FD_SBPF_R0, 0, 0, 2),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,       0,          0, 0, 0),
  );

  TEST_V3_SUCCESS("jset32-upper-only", 1, 9,
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM,  FD_SBPF_R0, 0,          0, 1),
    FD_SBPF_INSTR(FD_SBPF_OP_LDDW,       FD_SBPF_R1, 0,          0, 0),
    FD_SBPF_INSTR(0,                      0,          0,          0, 0xFFFF0000U),
    FD_SBPF_INSTR(FD_SBPF_OP_LDDW,       FD_SBPF_R2, 0,          0, 0),
    FD_SBPF_INSTR(0,                      0,          0,          0, 0xFFFF0000U),
    FD_SBPF_INSTR(FD_SBPF_OP_JSET32_REG, FD_SBPF_R1, FD_SBPF_R2, 1, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,       0,          0,          0, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM,  FD_SBPF_R0, 0,          0, 2),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,       0,          0,          0, 0),
  );

  /* JMP32 boundary values */
  TEST_V3_SUCCESS("jeq32-both-zero", 2, 6,
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM, FD_SBPF_R0, 0, 0, 1),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM, FD_SBPF_R1, 0, 0, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_JEQ32_IMM, FD_SBPF_R1, 0, 1, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,      0,          0, 0, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM, FD_SBPF_R0, 0, 0, 2),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,      0,          0, 0, 0),
  );

  TEST_V3_SUCCESS("jeq32-both-max", 2, 6,
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM, FD_SBPF_R0, 0, 0, 1),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM, FD_SBPF_R1, 0, 0, (uint)(int)-1),
    FD_SBPF_INSTR(FD_SBPF_OP_JEQ32_IMM, FD_SBPF_R1, 0, 1, 0xFFFFFFFFU),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,      0,          0, 0, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM, FD_SBPF_R0, 0, 0, 2),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,      0,          0, 0, 0),
  );

  /* SIMD-0377: CALLX uses dst register in V3 */

  TEST_V3_SUCCESS("callx-dst-reg", 42, 7,
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM, FD_SBPF_R0, 0, 0, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_LDDW,      FD_SBPF_R1, 0, 0, 5*8),
    FD_SBPF_INSTR(0,                     0,         0, 0, 1),
    FD_SBPF_INSTR(FD_SBPF_OP_CALL_REG,  FD_SBPF_R1, 0, 0, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,      0,          0, 0, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM, FD_SBPF_R0, 0, 0, 42),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,      0,          0, 0, 0),
  );

  /* CALLX validation */
  {
    ulong vtext_callx_inv[] = {
      fd_vm_instr( FD_SBPF_OP_CALL_REG, 10, 0, 0, 0 ),
      fd_vm_instr( FD_SBPF_OP_EXIT,      0, 0, 0, 0 ),
    };
    FD_TEST( test_vm_validate( FD_SBPF_V3, vtext_callx_inv, 2, syscalls, instr_ctx )==FD_VM_ERR_INVALID_REG );
    FD_LOG_NOTICE(( "%-20s PASS", "callx-dst-inv-v3" ));
  }

  {
    ulong vtext_callx_ok[] = {
      fd_vm_instr( FD_SBPF_OP_CALL_REG, 9, 0, 0, 0 ),
      fd_vm_instr( FD_SBPF_OP_EXIT,     0, 0, 0, 0 ),
    };
    FD_TEST( test_vm_validate( FD_SBPF_V3, vtext_callx_ok, 2, syscalls, instr_ctx )==FD_VM_SUCCESS );
    FD_LOG_NOTICE(( "%-20s PASS", "callx-dst-max-v3" ));
  }

  {
    ulong vtext_jmp32[] = {
      fd_vm_instr( FD_SBPF_OP_MOV64_IMM, 0, 0, 0, 0 ),
      fd_vm_instr( FD_SBPF_OP_JEQ32_IMM, 0, 0, 0, 0 ),
      fd_vm_instr( FD_SBPF_OP_EXIT,      0, 0, 0, 0 ),
    };
    FD_TEST( test_vm_validate( FD_SBPF_V0, vtext_jmp32, 3, syscalls, instr_ctx )!=FD_VM_SUCCESS );
    FD_TEST( test_vm_validate( FD_SBPF_V3, vtext_jmp32, 3, syscalls, instr_ctx )==FD_VM_SUCCESS );
    FD_LOG_NOTICE(( "%-20s PASS", "jmp32-vfy-gate" ));
  }

  test_stack_configuration( syscalls, instr_ctx );
  test_lazy_stack_zeroing( syscalls, instr_ctx );
  test_lazy_heap_zeroing( syscalls, instr_ctx );
  test_geometric_region_growth( syscalls, instr_ctx );
  test_validate_opcode_classes( syscalls, instr_ctx );
  test_trace_notrace_parity( syscalls, instr_ctx );
  test_input_tlb_and_region_lookup( syscalls, instr_ctx );

  ulong   text_cnt = 1024UL*1024UL;
  ulong * text     = (ulong *)malloc( sizeof(ulong)*text_cnt ); /* FIXME: gross */

  generate_random_alu_instrs( rng, text, text_cnt );
  test_program_exec( "alu_bench", 0x0, FD_VM_SUCCESS, FD_VM_COMPUTE_UNIT_LIMIT, TEST_VM_DEFAULT_SBPF_VERSION, text, text_cnt, syscalls, instr_ctx );

  generate_random_alu64_instrs( rng, text, text_cnt );
  test_program_exec( "alu64_bench", 0x0, FD_VM_SUCCESS, FD_VM_COMPUTE_UNIT_LIMIT, TEST_VM_DEFAULT_SBPF_VERSION, text, text_cnt, syscalls, instr_ctx );

  text_cnt = 1024UL;
  generate_random_alu_instrs( rng, text, text_cnt );
  test_program_exec( "alu_bench_short", 0x0, FD_VM_SUCCESS, FD_VM_COMPUTE_UNIT_LIMIT, TEST_VM_DEFAULT_SBPF_VERSION, text, text_cnt, syscalls, instr_ctx );

  generate_random_alu64_instrs( rng, text, text_cnt );
  test_program_exec( "alu64_bench_short", 0x0, FD_VM_SUCCESS, FD_VM_COMPUTE_UNIT_LIMIT, TEST_VM_DEFAULT_SBPF_VERSION, text, text_cnt, syscalls, instr_ctx );

  test_0cu_exit( runtime );

  test_block_text_limit( syscalls, instr_ctx );

  free( text );

  fd_sbpf_syscalls_delete( fd_sbpf_syscalls_leave( syscalls ) );

  FD_LOG_NOTICE(( "pass" ));
  fd_rng_delete( fd_rng_leave( rng ) );
  fd_halt();
  return 0;
}
