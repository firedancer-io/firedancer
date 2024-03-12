#include "syscall/fd_vm_syscall.h"

static void
set_vm_heap_memory_region( fd_vm_t * vm ) {
  for( ulong i=0UL; i<vm->heap_sz; i++ ) vm->heap[i] = (uchar) (i % (UCHAR_MAX + 1));
}

static void
set_vm_read_only_memory_region( fd_vm_t * vm ) {
  for( ulong i=0UL; i<vm->read_only_sz; i++ ) vm->read_only[i] = (uchar) (i % (UCHAR_MAX + 1));
}

static void
test_vm_syscall_sol_memset( char const * test_case_name,
                            fd_vm_t *    vm,
                            ulong        dst_vaddr,
                            ulong        dst_haddr,
                            ulong        val,
                            ulong        sz,
                            ulong        expected_ret_code,
                            int          expected_syscall_ret ) {
  set_vm_heap_memory_region( vm );

  ulong ret_code    = 0UL;
  int   syscall_ret = fd_vm_syscall_sol_memset( vm, dst_vaddr, val, sz, 0, 0, &ret_code );
  FD_TEST( ret_code==expected_ret_code );
  FD_TEST( syscall_ret==expected_syscall_ret );

  if( !ret_code && !syscall_ret ) {
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
                            ulong        expected_ret_code,
                            int          expected_syscall_ret ) {
  set_vm_heap_memory_region( vm );

  ulong ret_code    = 0UL;
  int   syscall_ret = fd_vm_syscall_sol_memcpy(vm, dst_vaddr, src_vaddr, sz, 0, 0, &ret_code);
  FD_TEST( ret_code==expected_ret_code );
  FD_TEST( syscall_ret==expected_syscall_ret );

  if( !ret_code && !syscall_ret ) FD_TEST( !memcmp( (void *)dst_haddr, (void *)src_haddr, sz ) );

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
                            ulong        expected_ret_code,
                            int          expected_syscall_ret ) {
  ulong ret_code    = 0UL;
  int   syscall_ret = fd_vm_syscall_sol_memcmp( vm, vaddr_1, vaddr_2, sz, vm_cmp_result_addr, 0, &ret_code);
  FD_TEST( ret_code==expected_ret_code );
  FD_TEST( syscall_ret==expected_syscall_ret );

  if( !ret_code && !syscall_ret ) FD_TEST( memcmp( (void *)haddr_1, (void *)haddr_2, sz )==*(int *)(host_cmp_result_addr) );

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
                             ulong        expected_ret_code,
                             int          expected_syscall_ret ) {
  set_vm_heap_memory_region( vm );

  void * temp = malloc( sz ); /* FIXME: So gross */
  FD_TEST( temp );
  memcpy( temp, (void *)src_haddr, sz );

  ulong ret_code    = 0UL;
  int   syscall_ret = fd_vm_syscall_sol_memmove( vm, dst_vaddr, src_vaddr, sz, 0, 0, &ret_code );
  FD_TEST( ret_code==expected_ret_code );
  FD_TEST( syscall_ret==expected_syscall_ret );
  if( !ret_code && !syscall_ret ) FD_TEST( !memcmp( (void *)dst_haddr, temp, sz ) );

  free( temp );

  FD_LOG_NOTICE(( "Passed test program (%s)", test_case_name ));
}

static void
test_vm_syscall_sol_log( char const *            test_case_name,
                         fd_vm_t *               vm,
                         ulong                   msg_vaddr,
                         ulong                   msg_len,
                         ulong                   expected_ret_code,
                         int                     expected_syscall_ret,
                         fd_vm_log_collector_t * expected_log_collector ) {
  ulong ret_code    = 0UL;
  int   syscall_ret = fd_vm_syscall_sol_log(vm, msg_vaddr, msg_len, 0, 0, 0, &ret_code);
  FD_TEST( ret_code==expected_ret_code );
  FD_TEST( syscall_ret==expected_syscall_ret );
  if( !ret_code && !syscall_ret ) FD_TEST( !memcmp( &vm->log_collector, expected_log_collector, sizeof(fd_vm_log_collector_t) ) );
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
                            ulong                   expected_ret_code,
                            int                     expected_syscall_ret,
                            fd_vm_log_collector_t * expected_log_collector ) {
  ulong ret_code    = 0UL;
  int   syscall_ret = fd_vm_syscall_sol_log_64(vm, r1, r2, r3, r4, r5, &ret_code);
  FD_TEST( ret_code==expected_ret_code );
  FD_TEST( syscall_ret==expected_syscall_ret );
  if( !ret_code && !syscall_ret ) FD_TEST( !memcmp( &vm->log_collector, expected_log_collector, sizeof(fd_vm_log_collector_t) ) );
  FD_LOG_NOTICE(( "Passed test program (%s)", test_case_name ));
}

static void
test_vm_syscall_sol_log_data( char const *            test_case_name,
                              fd_vm_t *               vm,
                              ulong                   data_vaddr,
                              ulong                   data_len,
                              ulong                   expected_ret_code,
                              int                     expected_syscall_ret,
                              fd_vm_log_collector_t * expected_log_collector ) {
  ulong ret_code    = 0UL;
  int   syscall_ret = fd_vm_syscall_sol_log_data(vm, data_vaddr, data_len, 0, 0, 0, &ret_code);
  FD_TEST( ret_code==expected_ret_code );
  FD_TEST( syscall_ret==expected_syscall_ret );
  if( !ret_code && !syscall_ret ) FD_TEST( !memcmp( &vm->log_collector, expected_log_collector, sizeof(fd_vm_log_collector_t) ) );
  FD_LOG_NOTICE(( "Passed test program (%s)", test_case_name ));
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  fd_rng_t _rng[1]; fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, 0U, 0UL ) );

  ulong const read_only_sz = 500UL;
  uchar read_only_prog[read_only_sz];

  fd_vm_t vm = {
    .entrypoint          = 0,
    .program_counter     = 0,
    .instruction_counter = 0,
    .text                = NULL,
    .text_cnt            = 0,
    .text_off            = 0,
    .syscalls            = NULL,
    .calldests           = NULL,
    .input               = NULL,
    .input_sz            = 0,
    .read_only           = read_only_prog,
    .read_only_sz        = read_only_sz,
    .heap_sz             = FD_VM_HEAP_SZ_DEFAULT,
    .compute_meter       = FD_VM_MAX_COMPUTE_UNIT_LIMIT,
  };

  set_vm_read_only_memory_region( &vm );

  fd_vm_log_collector_t expected_log_collector[1];

  test_vm_syscall_sol_memset(
      "test_vm_syscall_sol_memset: memset at the heap region without offset",
      &vm,
      FD_VM_MEM_MAP_HEAP_REGION_START,
      (ulong) &vm.heap[0],
      0UL,
      100UL,
      0,
      0
  );

  ulong offset = 10UL;
  test_vm_syscall_sol_memset(
      "test_vm_syscall_sol_memset: memset at the heap region with offset",
      &vm,
      FD_VM_MEM_MAP_HEAP_REGION_START + offset,
      (ulong) &vm.heap[offset],
      0UL,
      100UL,
      0,
      0
  );

  // test we cannot memset at the read_only region
  test_vm_syscall_sol_memset(
      "test_vm_syscall_sol_memset: memset at the read_only region",
      &vm,
      FD_VM_MEM_MAP_PROGRAM_REGION_START,
      0UL,
      0UL,
      100UL,
      0,
      FD_VM_ERR_PERM
  );

  test_vm_syscall_sol_memcpy(
      "test_vm_syscall_sol_memcpy: memcpy at the heap region",
      &vm,
      FD_VM_MEM_MAP_HEAP_REGION_START,
      FD_VM_MEM_MAP_HEAP_REGION_START + 100UL,
      (ulong) &vm.heap[0],
      (ulong) &vm.heap[100],
      100UL,
      0,
      0
  );

  // test we can copy from ready only region to heap region
  test_vm_syscall_sol_memcpy(
      "test_vm_syscall_sol_memcpy: memcpy from read only region to heap region",
      &vm,
      FD_VM_MEM_MAP_PROGRAM_REGION_START,
      FD_VM_MEM_MAP_HEAP_REGION_START,
      (ulong) &vm.read_only[0],
      (ulong) &vm.heap[0],
      100UL,
      0,
      0
  );

  // test we cannot copy from heap region to read only region
  test_vm_syscall_sol_memcpy(
      "test_vm_syscall_sol_memcpy: memcpy from heap region to read only region",
      &vm,
      FD_VM_MEM_MAP_HEAP_REGION_START,
      FD_VM_MEM_MAP_PROGRAM_REGION_START,
      (ulong) &vm.heap[0],
      (ulong) &vm.read_only[0],
      100UL,
      0,
      FD_VM_ERR_PERM
  );

  // test we cannot copy more than the available size from the read-only region
  test_vm_syscall_sol_memcpy(
      "test_vm_syscall_sol_memcpy: memcpy from read only region to heap region",
      &vm,
      FD_VM_MEM_MAP_PROGRAM_REGION_START,
      FD_VM_MEM_MAP_HEAP_REGION_START,
      (ulong) &vm.read_only[0],
      (ulong) &vm.heap[0],
      read_only_sz + 1UL,
      0,
      FD_VM_ERR_PERM
  );

  // test we cannot copy overlapping regions in heap where src is before dst
  test_vm_syscall_sol_memcpy(
      "test_vm_syscall_sol_memcpy: memcpy overlapping regions in heap - src before dst",
      &vm,
      FD_VM_MEM_MAP_HEAP_REGION_START,
      FD_VM_MEM_MAP_HEAP_REGION_START + 10UL,
      (ulong) &vm.heap[0],
      (ulong) &vm.heap[10],
      100UL,
      0,
      FD_VM_ERR_MEM_OVERLAP
  );

  // test we cannot copy overlapping regions in heap where src is after dst
  test_vm_syscall_sol_memcpy(
      "test_vm_syscall_sol_memcpy: memcpy overlapping regions in heap - src after dst",
      &vm,
      FD_VM_MEM_MAP_HEAP_REGION_START + 10UL,
      FD_VM_MEM_MAP_HEAP_REGION_START,
      (ulong) &vm.heap[10],
      (ulong) &vm.heap[0],
      100UL,
      0,
      FD_VM_ERR_MEM_OVERLAP
  );

  // test we can memmove from heap region to heap region
  test_vm_syscall_sol_memmove(
      "test_vm_syscall_sol_memmove: memmove from heap region to heap region",
      &vm,
      FD_VM_MEM_MAP_HEAP_REGION_START,
      FD_VM_MEM_MAP_HEAP_REGION_START + 100UL,
      (ulong) &vm.heap[0],
      (ulong) &vm.heap[100],
      100UL,
      0,
      0
  );

  // test we can memmove overlapping regions in heap
  test_vm_syscall_sol_memmove(
      "test_vm_syscall_sol_memmove: memmove overlapping regions in heap",
      &vm,
      FD_VM_MEM_MAP_HEAP_REGION_START,
      FD_VM_MEM_MAP_HEAP_REGION_START + 10UL,
      (ulong) &vm.heap[0],
      (ulong) &vm.heap[10],
      100UL,
      0,
      0
  );

  // test we can memmove from read only region to heap region
  test_vm_syscall_sol_memmove(
      "test_vm_syscall_sol_memmove: memmove from read only region to heap region",
      &vm,
      FD_VM_MEM_MAP_PROGRAM_REGION_START,
      FD_VM_MEM_MAP_HEAP_REGION_START,
      (ulong) &vm.read_only[0],
      (ulong) &vm.heap[0],
      100UL,
      0,
      0
  );

  // test we cannot memmove from heap region to read only region
  test_vm_syscall_sol_memmove(
      "test_vm_syscall_sol_memmove: memmove from heap region to read only region",
      &vm,
      FD_VM_MEM_MAP_HEAP_REGION_START,
      FD_VM_MEM_MAP_PROGRAM_REGION_START,
      (ulong) &vm.heap[0],
      (ulong) &vm.read_only[0],
      100UL,
      0,
      FD_VM_ERR_PERM
  );

  // test for memcmp at the heap region
  test_vm_syscall_sol_memcmp(
      "test_vm_syscall_sol_memcmp: memcmp at the heap region",
      &vm,
      FD_VM_MEM_MAP_HEAP_REGION_START,
      FD_VM_MEM_MAP_HEAP_REGION_START + 100UL,
      FD_VM_MEM_MAP_HEAP_REGION_START + 200UL,
      (ulong) &vm.heap[0],
      (ulong) &vm.heap[100],
      (ulong) &vm.heap[200],
      100UL,
      0,
      0
  );

  // test for memcmp at the read only region
  test_vm_syscall_sol_memcmp(
      "test_vm_syscall_sol_memcmp: memcmp at the read only region",
      &vm,
      FD_VM_MEM_MAP_PROGRAM_REGION_START,
      FD_VM_MEM_MAP_PROGRAM_REGION_START + 100UL,
      FD_VM_MEM_MAP_HEAP_REGION_START,
      (ulong) &vm.read_only[0],
      (ulong) &vm.read_only[100],
      (ulong) &vm.heap[0],
      100UL,
      0,
      0
  );

  // test we cannot write memcmp results to read only region
  test_vm_syscall_sol_memcmp(
      "test_vm_syscall_sol_memcmp: memcmp write result to the read only region",
      &vm,
      FD_VM_MEM_MAP_PROGRAM_REGION_START,
      FD_VM_MEM_MAP_PROGRAM_REGION_START + 100UL,
      FD_VM_MEM_MAP_PROGRAM_REGION_START + 200UL,
      (ulong) &vm.read_only[0],
      (ulong) &vm.read_only[100],
      (ulong) &vm.read_only[200],
      100UL,
      0,
      FD_VM_ERR_PERM
  );

  fd_vm_log_collector_wipe( expected_log_collector );
  fd_vm_log_collector_wipe( vm.log_collector   );

  fd_vm_log_collector_append( expected_log_collector, "hello world", 11UL );
  memcpy( &vm.heap[0], "hello world", 11 );
  // test for collecting logs at the heap region
  test_vm_syscall_sol_log(
      "test_vm_syscall_sol_log: log at the heap region",
      &vm,
      FD_VM_MEM_MAP_HEAP_REGION_START,
      11UL,
      0,
      0,
      expected_log_collector
  );

  // test for collecting logs at the read only region
  fd_vm_log_collector_append( expected_log_collector, &vm.read_only[0], 100UL );
  test_vm_syscall_sol_log(
      "test_vm_syscall_sol_log: log at the read only region",
      &vm,
      FD_VM_MEM_MAP_PROGRAM_REGION_START,
      100UL,
      0,
      0,
      expected_log_collector
  );

  // test for writing logs that exceed the remaining space
  fd_vm_log_collector_append( expected_log_collector, &vm.heap[0], FD_VM_LOG_COLLECTOR_BUF_MAX );
  test_vm_syscall_sol_log(
      "test_vm_syscall_sol_log: log that exceeds the limit",
      &vm,
      FD_VM_MEM_MAP_HEAP_REGION_START,
      FD_VM_LOG_COLLECTOR_BUF_MAX + 1UL,
      0,
      0,
      expected_log_collector
  );

  // test for writing logs when there's no more space
  test_vm_syscall_sol_log(
      "test_vm_syscall_sol_log: log when there's no more space",
      &vm,
      FD_VM_MEM_MAP_HEAP_REGION_START,
      1UL,
      0,
      0,
      expected_log_collector
  );

  fd_vm_log_collector_wipe( expected_log_collector );
  fd_vm_log_collector_wipe( vm.log_collector   );
  ulong r1 = fd_rng_ulong(rng);
  ulong r2 = fd_rng_ulong(rng);
  ulong r3 = fd_rng_ulong(rng);
  ulong r4 = fd_rng_ulong(rng);
  ulong r5 = fd_rng_ulong(rng);
  char msg[1024];
  ulong msg_len = (ulong)sprintf( msg, "Program log: %lx %lx %lx %lx %lx", r1, r2, r3, r4, r5 );
  fd_vm_log_collector_append( expected_log_collector, msg, msg_len );

  // test for collecting log_64 at the heap region
  test_vm_syscall_sol_log_64(
      "test_vm_syscall_sol_log_64: log_64 at the heap region",
      &vm,
      r1,
      r2,
      r3,
      r4,
      r5,
      0,
      0,
      expected_log_collector
  );

  fd_vm_log_collector_wipe( expected_log_collector );
  fd_vm_log_collector_wipe( vm.log_collector   );

  // test for collecting log_data at the heap region
  fd_vm_vec_t log_vec = { .addr = FD_VM_MEM_MAP_HEAP_REGION_START + 100, .len = 5UL };
  ulong data_chunk_num = 5UL;
  for( ulong i=0UL; i<data_chunk_num; i++ ) memcpy( (&vm.heap[0] + i * sizeof(fd_vm_vec_t)), &log_vec, sizeof(log_vec));
  fd_vm_log_collector_append( expected_log_collector, "Program data: ZGVmZ2g= ZGVmZ2g= ZGVmZ2g= ZGVmZ2g= ZGVmZ2g=", 58UL );

  test_vm_syscall_sol_log_data(
    "test_vm_syscall_sol_log_data: log_data at the heap region",
    &vm,
    FD_VM_MEM_MAP_HEAP_REGION_START,
    data_chunk_num,
    0,
    0,
    expected_log_collector
  );

  fd_rng_delete( fd_rng_leave( rng ) );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
