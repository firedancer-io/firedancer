#include "fd_vm_syscall.h"
#include "../test_vm_util.h"

static inline void set_memory_region( uchar * mem, ulong sz ) { for( ulong i=0UL; i<sz; i++ ) mem[i] = (uchar)(i & 0xffUL); }

static void
test_vm_syscall_toggle_direct_mapping( fd_vm_t * vm_ctx, int enable ) {
  ulong slot = enable ? 0UL : FD_FEATURE_DISABLED;
  char const * one_offs[] = { "EenyoWx9UMXYKpR8mW5Jmfmy2fRjzUtM7NduYMY8bx33" };
  fd_features_enable_one_offs( (fd_features_t*)&vm_ctx->instr_ctx->epoch_ctx->features, one_offs, 1U, slot );
  vm_ctx->direct_mapping = enable;
}

static void
test_vm_syscall_sol_memset( char const * test_case_name,
                            fd_vm_t *    vm,
                            ulong        dst_vaddr,
                            ulong        dst_haddr,
                            ulong        val,
                            ulong        sz,
                            ulong        expected_ret,
                            int          expected_err ) {
  set_memory_region( vm->heap, vm->heap_max );

  ulong ret = 0UL;
  int   err = fd_vm_syscall_sol_memset( vm, dst_vaddr, val, sz, 0, 0, &ret );
  FD_TEST( ret==expected_ret );
  FD_TEST( err==expected_err );

  if( !ret && !err ) {
    char expected_block[sz];
    memset( expected_block, (int)val, sz);
    FD_TEST( !memcmp( (void *)dst_haddr, expected_block, sz ) );
  }

  FD_LOG_NOTICE(( "Passed test program (%s)", test_case_name ));
}

static void
test_vm_syscall_sol_memcpy( char const * test_case_name,
                            fd_vm_t *    vm,
                            ulong        src_vaddr,
                            ulong        dst_vaddr,
                            ulong        src_haddr,
                            ulong        dst_haddr,
                            ulong        sz,
                            ulong        expected_ret,
                            int          expected_err ) {
  set_memory_region( vm->heap, vm->heap_max );

  ulong ret = 0UL;
  int   err = fd_vm_syscall_sol_memcpy( vm, dst_vaddr, src_vaddr, sz, 0, 0, &ret );
  FD_TEST( ret==expected_ret );
  FD_TEST( err==expected_err );

  if( !ret && !err ) FD_TEST( !memcmp( (void *)dst_haddr, (void *)src_haddr, sz ) );

  FD_LOG_NOTICE(( "Passed test program (%s)", test_case_name ));
}

static void
test_vm_syscall_sol_memcmp( char const * test_case_name,
                            fd_vm_t *    vm,
                            ulong        vaddr_1,
                            ulong        vaddr_2,
                            ulong        vm_cmp_result_addr,
                            ulong        haddr_1,
                            ulong        haddr_2,
                            ulong        host_cmp_result_addr,
                            ulong        sz,
                            ulong        expected_ret,
                            int          expected_err ) {
  ulong ret = 0UL;
  int   err = fd_vm_syscall_sol_memcmp( vm, vaddr_1, vaddr_2, sz, vm_cmp_result_addr, 0, &ret );
  FD_TEST( ret==expected_ret );
  FD_TEST( err==expected_err );

  if( !ret && !err ) FD_TEST( memcmp( (void *)haddr_1, (void *)haddr_2, sz )==*(int *)(host_cmp_result_addr) );

  FD_LOG_NOTICE(( "Passed test program (%s)", test_case_name ));
}

static void
test_vm_syscall_sol_memmove( char const * test_case_name,
                             fd_vm_t *    vm,
                             ulong        src_vaddr,
                             ulong        dst_vaddr,
                             ulong        src_haddr,
                             ulong        dst_haddr,
                             ulong        sz,
                             ulong        expected_ret,
                             int          expected_err ) {
  set_memory_region( vm->heap, vm->heap_max );

  void * temp = malloc( sz ); /* FIXME: So gross */
  FD_TEST( temp );
  memcpy( temp, (void *)src_haddr, sz );

  ulong ret = 0UL;
  int   err = fd_vm_syscall_sol_memmove( vm, dst_vaddr, src_vaddr, sz, 0, 0, &ret );
  FD_TEST( ret==expected_ret );
  FD_TEST( err==expected_err );
  if( !ret && !err ) FD_TEST( !memcmp( (void *)dst_haddr, temp, sz ) );

  free( temp );

  FD_LOG_NOTICE(( "Passed test program (%s)", test_case_name ));
}

static void
test_vm_syscall_sol_log( char const *            test_case_name,
                         fd_vm_t *               vm,
                         ulong                   msg_vaddr,
                         ulong                   msg_len,
                         ulong                   expected_ret,
                         int                     expected_err,
                         uchar *                 expected_log,
                         ulong                   expected_log_sz ) {
  fd_log_collector_t * log = &vm->instr_ctx->txn_ctx->log_collector;
  ulong log_vec_len = fd_log_collector_debug_len( log );

  ulong ret = 0UL;
  int   err = fd_vm_syscall_sol_log( vm, msg_vaddr, msg_len, 0, 0, 0, &ret );
  FD_TEST( ret==expected_ret );
  FD_TEST( err==expected_err );
  if( !ret && !err ) {
    FD_TEST( fd_log_collector_debug_len( log )==log_vec_len+1 );
    uchar const * msg; ulong msg_sz;
    fd_log_collector_debug_get( log, log_vec_len, &msg, &msg_sz );
    FD_TEST( msg_sz==expected_log_sz && !memcmp( msg, expected_log, msg_sz ) );
  }
  FD_LOG_NOTICE(( "Passed test program (%s)", test_case_name ));
}

static void
test_vm_syscall_sol_log_64( char const *            test_case_name,
                            fd_vm_t *               vm,
                            ulong                   r1,
                            ulong                   r2,
                            ulong                   r3,
                            ulong                   r4,
                            ulong                   r5,
                            ulong                   expected_ret,
                            int                     expected_err,
                            uchar *                 expected_log,
                            ulong                   expected_log_sz ) {
  fd_log_collector_t * log = &vm->instr_ctx->txn_ctx->log_collector;
  ulong log_vec_len = fd_log_collector_debug_len( log );

  ulong ret = 0UL;
  int   err = fd_vm_syscall_sol_log_64( vm, r1, r2, r3, r4, r5, &ret );
  FD_TEST( ret==expected_ret );
  FD_TEST( err==expected_err );
  if( !ret && !err ) {
    FD_TEST( fd_log_collector_debug_len( log )==log_vec_len+1 );
    uchar const * msg; ulong msg_sz;
    fd_log_collector_debug_get( log, log_vec_len, &msg, &msg_sz );
    FD_TEST( msg_sz==expected_log_sz && !memcmp( msg, expected_log, msg_sz ) );
  }
  FD_LOG_NOTICE(( "Passed test program (%s)", test_case_name ));
}

static void
test_vm_syscall_sol_log_data( char const *            test_case_name,
                              fd_vm_t *               vm,
                              ulong                   data_vaddr,
                              ulong                   data_len,
                              ulong                   expected_ret,
                              int                     expected_err,
                              uchar *                 expected_log,
                              ulong                   expected_log_sz ) {
  fd_log_collector_t * log = &vm->instr_ctx->txn_ctx->log_collector;
  ulong log_vec_len = fd_log_collector_debug_len( log );

  ulong ret = 0UL;
  int   err = fd_vm_syscall_sol_log_data( vm, data_vaddr, data_len, 0, 0, 0, &ret );
  FD_TEST( ret==expected_ret );
  FD_TEST( err==expected_err );
  if( !ret && !err ) {
    FD_TEST( fd_log_collector_debug_len( log )==log_vec_len+1 );
    uchar const * msg; ulong msg_sz;
    fd_log_collector_debug_get( log, log_vec_len, &msg, &msg_sz );
    FD_TEST( msg_sz==expected_log_sz && !memcmp( msg, expected_log, msg_sz ) );
  }
  FD_LOG_NOTICE(( "Passed test program (%s)", test_case_name ));
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  fd_rng_t _rng[1]; fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, 0U, 0UL ) );

  fd_sha256_t _sha[1];
  fd_sha256_t * sha = fd_sha256_join( fd_sha256_new( _sha ) );

  fd_vm_t _vm[1];
  fd_vm_t * vm = fd_vm_join( fd_vm_new( _vm ) );
  FD_TEST( vm );

  ulong const rodata_sz = 500UL;
  uchar rodata[ rodata_sz ];
  set_memory_region( rodata, rodata_sz );

  /* Setup multi region input region. */
  ulong const input_sz = 1000UL;
  uchar input[ input_sz ];
  ulong const mem_regions_cnt = 4UL;
  fd_vm_input_region_t input_mem_regions[ mem_regions_cnt ];
  input_mem_regions[0] = (fd_vm_input_region_t){ .haddr = (ulong)input,         .region_sz = 100UL, .is_writable = 1, .vaddr_offset = 0UL };
  input_mem_regions[1] = (fd_vm_input_region_t){ .haddr = (ulong)input + 100UL, .region_sz = 1UL,   .is_writable = 1, .vaddr_offset = 100UL };
  input_mem_regions[2] = (fd_vm_input_region_t){ .haddr = (ulong)input + 101UL, .region_sz = 400UL, .is_writable = 1, .vaddr_offset = 101UL };
  input_mem_regions[3] = (fd_vm_input_region_t){ .haddr = (ulong)input + 501UL, .region_sz = 499UL, .is_writable = 1, .vaddr_offset = 501UL };

  fd_exec_instr_ctx_t * instr_ctx = test_vm_minimal_exec_instr_ctx( fd_libc_alloc_virtual() );

  int vm_ok = !!fd_vm_init(
      /* vm               */ vm,
      /* instr_ctx        */ instr_ctx,
      /* heap_max         */ FD_VM_HEAP_DEFAULT,
      /* entry_cu         */ FD_VM_COMPUTE_UNIT_LIMIT,
      /* rodata           */ rodata,
      /* rodata_sz        */ rodata_sz,
      /* text             */ NULL,
      /* text_cnt         */ 0UL,
      /* text_off         */ 0UL,
      /* text_sz          */ 0UL,
      /* entry_pc         */ 0UL,
      /* calldests        */ NULL,
      /* syscalls         */ NULL,
      /* trace            */ NULL,
      /* sha              */ sha,
      /* mem_regions      */ input_mem_regions,
      /* mem_regions_cnt  */ (uint)mem_regions_cnt,
      /* mem_regions_accs */ NULL,
      /* is_deprecated    */ 0,
      /* direct mapping   */ FD_FEATURE_ACTIVE( instr_ctx->slot_ctx, bpf_account_data_direct_mapping )
  );
  FD_TEST( vm_ok );

  /* Run relevant tests with and without direct mapping enabled */
  test_vm_syscall_toggle_direct_mapping( vm, 0 ); /* disable direct mapping */

  test_vm_syscall_sol_memset( "test_vm_syscall_sol_memset: memset at the heap region without offset",
                              vm,
                              FD_VM_MEM_MAP_HEAP_REGION_START,
                              (ulong)&vm->heap[0],
                              0UL,
                              100UL,
                              0UL, FD_VM_SUCCESS );

  test_vm_syscall_sol_memset( "test_vm_syscall_sol_memset: memset at the heap region with offset",
                              vm,
                              FD_VM_MEM_MAP_HEAP_REGION_START + 10UL,
                              (ulong)&vm->heap[10],
                              0UL,
                              100UL,
                              0UL, FD_VM_SUCCESS );

  // test we cannot memset at the rodata region
  test_vm_syscall_sol_memset( "test_vm_syscall_sol_memset: memset at the rodata region",
                              vm,
                              FD_VM_MEM_MAP_PROGRAM_REGION_START,
                              0UL,
                              0UL,
                              100UL,
                              0UL, FD_VM_ERR_SIGSEGV );

  test_vm_syscall_toggle_direct_mapping( vm, 1 ); /* enable direct mapping */

  test_vm_syscall_sol_memset( "test_vm_syscall_sol_memset: memset at the heap region without offset",
                              vm,
                              FD_VM_MEM_MAP_HEAP_REGION_START,
                              (ulong)&vm->heap[0],
                              0UL,
                              100UL,
                              0UL, FD_VM_SUCCESS );

  test_vm_syscall_sol_memset( "test_vm_syscall_sol_memset: memset at the heap region with offset",
                              vm,
                              FD_VM_MEM_MAP_HEAP_REGION_START + 10UL,
                              (ulong)&vm->heap[10],
                              0UL,
                              100UL,
                              0UL, FD_VM_SUCCESS );

  // test we cannot memset at the rodata region
  test_vm_syscall_sol_memset( "test_vm_syscall_sol_memset: memset at the rodata region",
                              vm,
                              FD_VM_MEM_MAP_PROGRAM_REGION_START,
                              0UL,
                              0UL,
                              100UL,
                              0UL, FD_VM_ERR_SIGSEGV );

  test_vm_syscall_sol_memset( "test_vm_syscall_sol_memset: memset across multiple input mem regions",
                              vm,
                              FD_VM_MEM_MAP_INPUT_REGION_START,
                              (ulong)&input,
                              1UL,
                              1000UL,
                              0UL, FD_VM_SUCCESS );

  test_vm_syscall_sol_memset( "test_vm_syscall_sol_memset: memset across multiple input mem regions 2",
                              vm,
                              FD_VM_MEM_MAP_INPUT_REGION_START,
                              (ulong)&input + 50UL,
                              1UL,
                              800UL,
                              0UL, FD_VM_SUCCESS );

  input_mem_regions[2].is_writable=0;
  test_vm_syscall_sol_memset( "test_vm_syscall_sol_memset: memset across multiple input mem regions invalid write",
                              vm,
                              FD_VM_MEM_MAP_INPUT_REGION_START,
                              (ulong)&input + 50UL,
                              1UL,
                              800UL,
                              0UL, FD_VM_ERR_EBPF_ACCESS_VIOLATION );
  input_mem_regions[2].is_writable=1;


  test_vm_syscall_toggle_direct_mapping( vm, 0 ); /* disable direct mapping */

  test_vm_syscall_sol_memcpy( "test_vm_syscall_sol_memcpy: memcpy at the heap region",
                              vm,
                              FD_VM_MEM_MAP_HEAP_REGION_START,
                              FD_VM_MEM_MAP_HEAP_REGION_START + 100UL,
                              (ulong)&vm->heap[0],
                              (ulong)&vm->heap[100],
                              100UL,
                              0UL, FD_VM_SUCCESS );

  // test we can copy from ready only region to heap region
  test_vm_syscall_sol_memcpy( "test_vm_syscall_sol_memcpy: memcpy from read only region to heap region",
                              vm,
                              FD_VM_MEM_MAP_PROGRAM_REGION_START,
                              FD_VM_MEM_MAP_HEAP_REGION_START,
                              (ulong)&vm->rodata[0],
                              (ulong)&vm->heap[0],
                              100UL,
                              0UL, FD_VM_SUCCESS );

  // test we cannot copy from heap region to read only region
  test_vm_syscall_sol_memcpy( "test_vm_syscall_sol_memcpy: memcpy from heap region to read only region",
                              vm,
                              FD_VM_MEM_MAP_HEAP_REGION_START,
                              FD_VM_MEM_MAP_PROGRAM_REGION_START,
                              (ulong)&vm->heap[0],
                              (ulong)&vm->rodata[0],
                              100UL,
                              0UL, FD_VM_ERR_SIGSEGV );

  // test we cannot copy more than the available size from the read-only region
  test_vm_syscall_sol_memcpy( "test_vm_syscall_sol_memcpy: memcpy from read only region to heap region",
                              vm,
                              FD_VM_MEM_MAP_PROGRAM_REGION_START,
                              FD_VM_MEM_MAP_HEAP_REGION_START,
                              (ulong)&vm->rodata[0],
                              (ulong)&vm->heap[0],
                              rodata_sz + 1UL,
                              0UL, FD_VM_ERR_SIGSEGV );

  // test we cannot copy overlapping regions in heap where src is before dst
  test_vm_syscall_sol_memcpy( "test_vm_syscall_sol_memcpy: memcpy overlapping regions in heap - src before dst",
                              vm,
                              FD_VM_MEM_MAP_HEAP_REGION_START,
                              FD_VM_MEM_MAP_HEAP_REGION_START + 10UL,
                              (ulong)&vm->heap[0],
                              (ulong)&vm->heap[10],
                              100UL,
                              0UL, FD_VM_ERR_MEM_OVERLAP );

  // test we cannot copy overlapping regions in heap where src is after dst
  test_vm_syscall_sol_memcpy( "test_vm_syscall_sol_memcpy: memcpy overlapping regions in heap - src after dst",
                              vm,
                              FD_VM_MEM_MAP_HEAP_REGION_START + 10UL,
                              FD_VM_MEM_MAP_HEAP_REGION_START,
                              (ulong)&vm->heap[10],
                              (ulong)&vm->heap[0],
                              100UL,
                              0UL, FD_VM_ERR_MEM_OVERLAP );

  test_vm_syscall_toggle_direct_mapping( vm, 1 ); /* enable direct mapping */

  test_vm_syscall_sol_memcpy( "test_vm_syscall_sol_memcpy: memcpy at the heap region",
                              vm,
                              FD_VM_MEM_MAP_HEAP_REGION_START,
                              FD_VM_MEM_MAP_HEAP_REGION_START + 100UL,
                              (ulong)&vm->heap[0],
                              (ulong)&vm->heap[100],
                              100UL,
                              0UL, FD_VM_SUCCESS );

  // test we can copy from ready only region to heap region
  test_vm_syscall_sol_memcpy( "test_vm_syscall_sol_memcpy: memcpy from read only region to heap region",
                              vm,
                              FD_VM_MEM_MAP_PROGRAM_REGION_START,
                              FD_VM_MEM_MAP_HEAP_REGION_START,
                              (ulong)&vm->rodata[0],
                              (ulong)&vm->heap[0],
                              100UL,
                              0UL, FD_VM_SUCCESS );

  // test we cannot copy from heap region to read only region
  test_vm_syscall_sol_memcpy( "test_vm_syscall_sol_memcpy: memcpy from heap region to read only region",
                              vm,
                              FD_VM_MEM_MAP_HEAP_REGION_START,
                              FD_VM_MEM_MAP_PROGRAM_REGION_START,
                              (ulong)&vm->heap[0],
                              (ulong)&vm->rodata[0],
                              100UL,
                              0UL, FD_VM_ERR_SIGSEGV );

  // test we cannot copy more than the available size from the read-only region
  test_vm_syscall_sol_memcpy( "test_vm_syscall_sol_memcpy: memcpy from read only region to heap region",
                              vm,
                              FD_VM_MEM_MAP_PROGRAM_REGION_START,
                              FD_VM_MEM_MAP_HEAP_REGION_START,
                              (ulong)&vm->rodata[0],
                              (ulong)&vm->heap[0],
                              rodata_sz + 1UL,
                              0UL, FD_VM_ERR_SIGSEGV );

  // test we cannot copy overlapping regions in heap where src is before dst
  test_vm_syscall_sol_memcpy( "test_vm_syscall_sol_memcpy: memcpy overlapping regions in heap - src before dst",
                              vm,
                              FD_VM_MEM_MAP_HEAP_REGION_START,
                              FD_VM_MEM_MAP_HEAP_REGION_START + 10UL,
                              (ulong)&vm->heap[0],
                              (ulong)&vm->heap[10],
                              100UL,
                              0UL, FD_VM_ERR_MEM_OVERLAP );

  // test we cannot copy overlapping regions in heap where src is after dst
  test_vm_syscall_sol_memcpy( "test_vm_syscall_sol_memcpy: memcpy overlapping regions in heap - src after dst",
                              vm,
                              FD_VM_MEM_MAP_HEAP_REGION_START + 10UL,
                              FD_VM_MEM_MAP_HEAP_REGION_START,
                              (ulong)&vm->heap[10],
                              (ulong)&vm->heap[0],
                              100UL,
                              0UL, FD_VM_ERR_MEM_OVERLAP );

  test_vm_syscall_sol_memcpy( "test_vm_syscall_sol_memcpy: memcpy in input (single region)",
                                vm,
                                FD_VM_MEM_MAP_INPUT_REGION_START + 10UL,
                                FD_VM_MEM_MAP_INPUT_REGION_START + 800UL,
                                vm->input_mem_regions[0].haddr + 10UL,
                                vm->input_mem_regions[0].haddr + 800UL,
                                50UL,
                                0UL, FD_VM_SUCCESS );

  test_vm_syscall_sol_memcpy( "test_vm_syscall_sol_memcpy: memcpy in input overlapping vaddr",
                                vm,
                                FD_VM_MEM_MAP_INPUT_REGION_START + 80UL,
                                FD_VM_MEM_MAP_INPUT_REGION_START + 120UL,
                                vm->input_mem_regions[0].haddr + 80UL,
                                vm->input_mem_regions[0].haddr + 120UL,
                                50UL,
                                0UL, FD_VM_ERR_MEM_OVERLAP );

  test_vm_syscall_sol_memcpy( "test_vm_syscall_sol_memcpy: memcpy in input multiple regions",
                                vm,
                                FD_VM_MEM_MAP_INPUT_REGION_START + 50UL,
                                FD_VM_MEM_MAP_INPUT_REGION_START + 450UL,
                                vm->input_mem_regions[0].haddr + 50UL,
                                vm->input_mem_regions[0].haddr + 450UL,
                                100UL,
                                0UL, FD_VM_SUCCESS );

  test_vm_syscall_sol_memcpy( "test_vm_syscall_sol_memcpy: memcpy in input overlapping vaddr multiple regions",
                                vm,
                                FD_VM_MEM_MAP_INPUT_REGION_START + 50UL,
                                FD_VM_MEM_MAP_INPUT_REGION_START + 450UL,
                                vm->input_mem_regions[0].haddr + 50UL,
                                vm->input_mem_regions[0].haddr + 450UL,
                                500UL,
                                0UL, FD_VM_ERR_MEM_OVERLAP );


  test_vm_syscall_toggle_direct_mapping( vm, 0 ); /* disable direct mapping */

  // test we can memmove from heap region to heap region
  test_vm_syscall_sol_memmove( "test_vm_syscall_sol_memmove: memmove from heap region to heap region",
                               vm,
                               FD_VM_MEM_MAP_HEAP_REGION_START,
                               FD_VM_MEM_MAP_HEAP_REGION_START + 100UL,
                               (ulong)&vm->heap[0],
                               (ulong)&vm->heap[100],
                               100UL,
                               0UL, FD_VM_SUCCESS );

  // test we can memmove overlapping regions in heap
  test_vm_syscall_sol_memmove( "test_vm_syscall_sol_memmove: memmove overlapping regions in heap",
                               vm,
                               FD_VM_MEM_MAP_HEAP_REGION_START,
                               FD_VM_MEM_MAP_HEAP_REGION_START + 10UL,
                               (ulong)&vm->heap[0],
                               (ulong)&vm->heap[10],
                               100UL,
                               0UL, FD_VM_SUCCESS );

  // test we can memmove from read only region to heap region
  test_vm_syscall_sol_memmove( "test_vm_syscall_sol_memmove: memmove from read only region to heap region",
                               vm,
                               FD_VM_MEM_MAP_PROGRAM_REGION_START,
                               FD_VM_MEM_MAP_HEAP_REGION_START,
                               (ulong)&vm->rodata[0],
                               (ulong)&vm->heap[0],
                               100UL,
                               0UL, FD_VM_SUCCESS );

  // test we cannot memmove from heap region to read only region
  test_vm_syscall_sol_memmove( "test_vm_syscall_sol_memmove: memmove from heap region to read only region",
                               vm,
                               FD_VM_MEM_MAP_HEAP_REGION_START,
                               FD_VM_MEM_MAP_PROGRAM_REGION_START,
                               (ulong)&vm->heap[0],
                               (ulong)&vm->rodata[0],
                               100UL,
                               0UL, FD_VM_ERR_SIGSEGV );

  test_vm_syscall_toggle_direct_mapping( vm, 1 ); /* enable direct mapping */

  // test we can memmove from heap region to heap region
  test_vm_syscall_sol_memmove( "test_vm_syscall_sol_memmove: memmove from heap region to heap region",
                               vm,
                               FD_VM_MEM_MAP_HEAP_REGION_START,
                               FD_VM_MEM_MAP_HEAP_REGION_START + 100UL,
                               (ulong)&vm->heap[0],
                               (ulong)&vm->heap[100],
                               100UL,
                               0UL, FD_VM_SUCCESS );

  // test we can memmove overlapping regions in heap
  test_vm_syscall_sol_memmove( "test_vm_syscall_sol_memmove: memmove overlapping regions in heap",
                               vm,
                               FD_VM_MEM_MAP_HEAP_REGION_START,
                               FD_VM_MEM_MAP_HEAP_REGION_START + 10UL,
                               (ulong)&vm->heap[0],
                               (ulong)&vm->heap[10],
                               100UL,
                               0UL, FD_VM_SUCCESS );

  // test we can memmove from read only region to heap region
  test_vm_syscall_sol_memmove( "test_vm_syscall_sol_memmove: memmove from read only region to heap region",
                               vm,
                               FD_VM_MEM_MAP_PROGRAM_REGION_START,
                               FD_VM_MEM_MAP_HEAP_REGION_START,
                               (ulong)&vm->rodata[0],
                               (ulong)&vm->heap[0],
                               100UL,
                               0UL, FD_VM_SUCCESS );

  // test we cannot memmove from heap region to read only region
  test_vm_syscall_sol_memmove( "test_vm_syscall_sol_memmove: memmove from heap region to read only region",
                               vm,
                               FD_VM_MEM_MAP_HEAP_REGION_START,
                               FD_VM_MEM_MAP_PROGRAM_REGION_START,
                               (ulong)&vm->heap[0],
                               (ulong)&vm->rodata[0],
                               100UL,
                               0UL, FD_VM_ERR_SIGSEGV );


  test_vm_syscall_sol_memmove( "test_vm_syscall_sol_memmove: memmove in input (single region)",
                              vm,
                              FD_VM_MEM_MAP_INPUT_REGION_START + 10UL,
                              FD_VM_MEM_MAP_INPUT_REGION_START + 800UL,
                              vm->input_mem_regions[0].haddr + 10UL,
                              vm->input_mem_regions[0].haddr + 800UL,
                              50UL,
                              0UL, FD_VM_SUCCESS );

  test_vm_syscall_sol_memmove( "test_vm_syscall_sol_memmove: memmove in input overlapping vaddr",
                              vm,
                              FD_VM_MEM_MAP_INPUT_REGION_START + 80UL,
                              FD_VM_MEM_MAP_INPUT_REGION_START + 120UL,
                              vm->input_mem_regions[0].haddr + 80UL,
                              vm->input_mem_regions[0].haddr + 120UL,
                              50UL,
                              0UL, FD_VM_SUCCESS );

  test_vm_syscall_sol_memmove( "test_vm_syscall_sol_memmove: memmove in input multiple regions",
                              vm,
                              FD_VM_MEM_MAP_INPUT_REGION_START + 50UL,
                              FD_VM_MEM_MAP_INPUT_REGION_START + 450UL,
                              vm->input_mem_regions[0].haddr + 50UL,
                              vm->input_mem_regions[0].haddr + 450UL,
                              100UL,
                              0UL, FD_VM_SUCCESS );

  test_vm_syscall_sol_memmove( "test_vm_syscall_sol_memmove: memmove in input overlapping vaddr multiple regions",
                                vm,
                                FD_VM_MEM_MAP_INPUT_REGION_START + 50UL,
                                FD_VM_MEM_MAP_INPUT_REGION_START + 450UL,
                                vm->input_mem_regions[0].haddr + 50UL,
                                vm->input_mem_regions[0].haddr + 450UL,
                                500UL,
                                0UL, FD_VM_SUCCESS );

  // test for memcmp at the heap region
  test_vm_syscall_sol_memcmp( "test_vm_syscall_sol_memcmp: memcmp at the heap region",
                              vm,
                              FD_VM_MEM_MAP_HEAP_REGION_START,
                              FD_VM_MEM_MAP_HEAP_REGION_START + 100UL,
                              FD_VM_MEM_MAP_HEAP_REGION_START + 200UL,
                              (ulong)&vm->heap[0],
                              (ulong)&vm->heap[100],
                              (ulong)&vm->heap[200],
                              100UL,
                              0UL, FD_VM_SUCCESS );

  // test for memcmp at the read only region
  test_vm_syscall_sol_memcmp( "test_vm_syscall_sol_memcmp: memcmp at the read only region",
                              vm,
                              FD_VM_MEM_MAP_PROGRAM_REGION_START,
                              FD_VM_MEM_MAP_PROGRAM_REGION_START + 100UL,
                              FD_VM_MEM_MAP_HEAP_REGION_START,
                              (ulong)&vm->rodata[0],
                              (ulong)&vm->rodata[100],
                              (ulong)&vm->heap[0],
                              100UL,
                              0UL, FD_VM_SUCCESS );

  // test we cannot write memcmp results to read only region
  test_vm_syscall_sol_memcmp( "test_vm_syscall_sol_memcmp: memcmp write result to the read only region",
                              vm,
                              FD_VM_MEM_MAP_PROGRAM_REGION_START,
                              FD_VM_MEM_MAP_PROGRAM_REGION_START + 100UL,
                              FD_VM_MEM_MAP_PROGRAM_REGION_START + 200UL,
                              (ulong)&vm->rodata[0],
                              (ulong)&vm->rodata[100],
                              (ulong)&vm->rodata[200],
                              100UL,
                              0UL, FD_VM_ERR_SIGSEGV );

  memset( (void*)input_mem_regions[0].haddr, 0xFF, 400UL );
  test_vm_syscall_sol_memcmp( "test_vm_syscall_sol_memcmp: memcmp input region equal",
                              vm,
                              FD_VM_MEM_MAP_INPUT_REGION_START,
                              FD_VM_MEM_MAP_INPUT_REGION_START + 200UL,
                              FD_VM_MEM_MAP_INPUT_REGION_START + 600UL,
                              input_mem_regions[0].haddr,
                              input_mem_regions[0].haddr + 200UL,
                              input_mem_regions[0].haddr + 600UL,
                              200UL,
                              0UL, FD_VM_SUCCESS );

  memset( (void*)input_mem_regions[0].haddr, 0xEE, 200UL );
  test_vm_syscall_sol_memcmp( "test_vm_syscall_sol_memcmp: memcmp input region not equal",
                              vm,
                              FD_VM_MEM_MAP_INPUT_REGION_START,
                              FD_VM_MEM_MAP_INPUT_REGION_START + 200UL,
                              FD_VM_MEM_MAP_INPUT_REGION_START + 600UL,
                              input_mem_regions[0].haddr,
                              input_mem_regions[0].haddr + 200UL,
                              input_mem_regions[0].haddr + 600UL,
                              200UL,
                              0UL, FD_VM_SUCCESS );

  uchar expected_log[ FD_VM_LOG_MAX ];
  ulong expected_log_sz = 0UL;

# define APPEND(msg,sz) do {                                                             \
    ulong _cpy_sz = fd_ulong_min( (sz), FD_VM_LOG_MAX - expected_log_sz );               \
    if( FD_LIKELY( _cpy_sz ) ) memcpy( expected_log + expected_log_sz, (msg), _cpy_sz ); \
    expected_log_sz += _cpy_sz;                                                          \
  } while(0)

  fd_log_collector_init( &vm->instr_ctx->txn_ctx->log_collector, 1 );

  expected_log_sz = 0UL;
  APPEND( "Program log: hello world", 24UL );
  memcpy( &vm->heap[0], "hello world", 11 );
  // test for collecting logs at the heap region
  test_vm_syscall_sol_log( "test_vm_syscall_sol_log: log at the heap region",
                           vm,
                           FD_VM_MEM_MAP_HEAP_REGION_START,
                           11UL,
                           0,
                           0,
                           expected_log, expected_log_sz );

  // test for collecting logs at the read only region
  expected_log_sz = 0UL;
  APPEND( "Program log: ", 13UL );
  APPEND( &vm->rodata[0], 100UL );
  test_vm_syscall_sol_log( "test_vm_syscall_sol_log: log at the read only region",
                           vm,
                           FD_VM_MEM_MAP_PROGRAM_REGION_START,
                           100UL,
                           0,
                           0,
                           expected_log, expected_log_sz );

  // test for writing logs that exceed the remaining space
  expected_log_sz = 0UL;
  APPEND( "Program log: ", 13UL );
  fd_memset( &vm->heap[0], 'x', FD_VM_LOG_MAX+1 );
  APPEND( &vm->heap[0], FD_VM_LOG_MAX );
  test_vm_syscall_sol_log( "test_vm_syscall_sol_log: log that exceeds the limit",
                           vm,
                           FD_VM_MEM_MAP_HEAP_REGION_START,
                           FD_VM_LOG_MAX + 1UL,
                           0,
                           0,
                           (uchar *)"Log truncated", 13 );

  // test for collecting log_64 at the heap region

  fd_log_collector_init( &vm->instr_ctx->txn_ctx->log_collector, 1 );

  expected_log_sz = 0UL;

  ulong r0 = fd_rng_ulong(rng);
  ulong r1 = fd_rng_ulong(rng);
  ulong r2 = fd_rng_ulong(rng);
  ulong r3 = fd_rng_ulong(rng);
  ulong r4 = fd_rng_ulong(rng);
  char  msg[1024];
  ulong msg_len = (ulong)sprintf( msg, "Program log: 0x%lx, 0x%lx, 0x%lx, 0x%lx, 0x%lx", r0, r1, r2, r3, r4 );

  APPEND( msg, msg_len );
  test_vm_syscall_sol_log_64( "test_vm_syscall_sol_log_64: log_64 at the heap region",
                              vm,
                              r0, r1, r2, r3, r4,
                              0UL, FD_VM_SUCCESS, expected_log, expected_log_sz );

  // test for collecting log_data at the heap region

  fd_log_collector_init( &vm->instr_ctx->txn_ctx->log_collector, 1 );

  expected_log_sz = 0UL;

  fd_vm_vec_t log_vec = { .addr = FD_VM_MEM_MAP_HEAP_REGION_START + 100, .len = 5UL };
  ulong data_chunk_num = 5UL;
  memcpy( &vm->heap[100], "abcde", 5 );
  for( ulong i=0UL; i<data_chunk_num; i++ ) memcpy( &vm->heap[0] + i*sizeof(fd_vm_vec_t), &log_vec, sizeof(log_vec) );
  APPEND( "Program data: YWJjZGU= YWJjZGU= YWJjZGU= YWJjZGU= YWJjZGU=", 58UL );
  test_vm_syscall_sol_log_data( "test_vm_syscall_sol_log_data: log_data at the heap region",
                                vm,
                                FD_VM_MEM_MAP_HEAP_REGION_START,
                                data_chunk_num,
                                0UL, FD_VM_SUCCESS, expected_log, expected_log_sz );

# undef APPEND

  fd_vm_delete    ( fd_vm_leave    ( vm  ) );
  fd_sha256_delete( fd_sha256_leave( sha ) );
  fd_rng_delete   ( fd_rng_leave   ( rng ) );
  test_vm_exec_instr_ctx_delete( instr_ctx );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
