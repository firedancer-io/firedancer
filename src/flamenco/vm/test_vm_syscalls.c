
#include "fd_vm_context.h"
#include "fd_vm_syscalls.h"

#include <stdio.h>

static void
set_vm_heap_memory_region( fd_vm_exec_context_t * vm_ctx ) {
    for (ulong i = 0; i < vm_ctx->heap_sz; i++) {
        vm_ctx->heap[i] = (uchar) (i % (UCHAR_MAX + 1));
    }
}

static void
set_vm_read_only_memory_region( fd_vm_exec_context_t * vm_ctx ) {
    for (ulong i = 0; i < vm_ctx->read_only_sz; i++) {
        vm_ctx->read_only[i] = (uchar) (i % (UCHAR_MAX + 1));
    }
}

static void
reset_log_collector( fd_vm_log_collector_t * log_collector ) {
    log_collector->buf_used = 0;
    fd_memset( log_collector->buf, 0, FD_VM_LOG_COLLECTOR_BYTES_LIMIT );
}

static void
test_vm_syscall_sol_memset(
    char *                 test_case_name,
    fd_vm_exec_context_t * vm_ctx,
    ulong                  dst_vm_addr,
    ulong                  dst_host_addr,
    ulong                  val,
    ulong                  sz,
    ulong                  expected_ret_code,
    ulong                  expected_syscall_ret
) {
    set_vm_heap_memory_region( vm_ctx );
    ulong ret_code = 0UL;
    ulong syscall_ret = fd_vm_syscall_sol_memset((void *) vm_ctx, dst_vm_addr, val, sz, 0, 0, &ret_code);
    FD_TEST( ret_code == expected_ret_code );
    FD_TEST( syscall_ret == expected_syscall_ret );

    if (ret_code == 0 && syscall_ret == 0) {
        char expected_block[sz];
        fd_memset( expected_block, (int)val, sz);
        FD_TEST( memcmp( (void *)dst_host_addr, expected_block, sz ) == 0 );
    }

    FD_LOG_NOTICE(( "Passed test program (%s)", test_case_name ));
}

static void
test_vm_syscall_sol_memcpy(
    char *                test_case_name,
    fd_vm_exec_context_t *vm_ctx,
    ulong                 src_vm_addr,
    ulong                 dst_vm_addr,
    ulong                 src_host_addr,
    ulong                 dst_host_addr,
    ulong                 sz,
    ulong                 expected_ret_code,
    ulong                 expected_syscall_ret
) {
    set_vm_heap_memory_region( vm_ctx );
    ulong ret_code = 0UL;
    ulong syscall_ret = fd_vm_syscall_sol_memcpy((void *) vm_ctx, dst_vm_addr, src_vm_addr, sz, 0, 0, &ret_code);
    FD_TEST( ret_code == expected_ret_code );
    FD_TEST( syscall_ret == expected_syscall_ret );

    if (ret_code == 0 && syscall_ret == 0) {
        FD_TEST( memcmp( (void *)dst_host_addr, (void *)src_host_addr, sz ) == 0 );
    }

    FD_LOG_NOTICE(( "Passed test program (%s)", test_case_name ));
}

static void
test_vm_syscall_sol_memcmp(
    char *                 test_case_name,
    fd_vm_exec_context_t * vm_ctx,
    ulong                  vm_addr_1,
    ulong                  vm_addr_2,
    ulong                  vm_cmp_result_addr,
    ulong                  host_addr_1,
    ulong                  host_addr_2,
    ulong                  host_cmp_result_addr,
    ulong                  sz,
    ulong                  expected_ret_code,
    ulong                  expected_syscall_ret
) {
    ulong ret_code = 0UL;
    ulong syscall_ret = fd_vm_syscall_sol_memcmp((void *) vm_ctx, vm_addr_1, vm_addr_2, sz, vm_cmp_result_addr, 0, &ret_code);
    FD_TEST( ret_code == expected_ret_code );
    FD_TEST( syscall_ret == expected_syscall_ret );

    if (ret_code == 0 && syscall_ret == 0) {
        FD_TEST( memcmp( (void *)host_addr_1, (void *)host_addr_2, sz ) == *(int *)(host_cmp_result_addr) );
    }

    FD_LOG_NOTICE(( "Passed test program (%s)", test_case_name ));
}

static void
test_vm_syscall_sol_memmove(
    char *                test_case_name,
    fd_vm_exec_context_t *vm_ctx,
    ulong                 src_vm_addr,
    ulong                 dst_vm_addr,
    ulong                 src_host_addr,
    ulong                 dst_host_addr,
    ulong                 sz,
    ulong                 expected_ret_code,
    ulong                 expected_syscall_ret
) {
    set_vm_heap_memory_region( vm_ctx );
    uchar * temp = (uchar *)malloc(sz);
    fd_memcpy( temp, (void *)src_host_addr, sz );

    ulong ret_code = 0UL;
    ulong syscall_ret = fd_vm_syscall_sol_memmove((void *) vm_ctx, dst_vm_addr, src_vm_addr, sz, 0, 0, &ret_code);
    FD_TEST( ret_code == expected_ret_code );
    FD_TEST( syscall_ret == expected_syscall_ret );

    if (ret_code == 0 && syscall_ret == 0) {
        FD_TEST( memcmp( (void *)dst_host_addr, (void *)temp, sz ) == 0 );
    }

    FD_LOG_NOTICE(( "Passed test program (%s)", test_case_name ));
}

static void
test_vm_syscall_sol_log(
    char *                  test_case_name,
    fd_vm_exec_context_t *  vm_ctx,
    ulong                   msg_vm_addr,
    ulong                   msg_len,
    ulong                   expected_ret_code,
    ulong                   expected_syscall_ret,
    fd_vm_log_collector_t * expected_log_collector
) {
    ulong ret_code = 0UL;
    ulong syscall_ret = fd_vm_syscall_sol_log((void *) vm_ctx, msg_vm_addr, msg_len, 0, 0, 0, &ret_code);
    FD_TEST( ret_code == expected_ret_code );
    FD_TEST( syscall_ret == expected_syscall_ret );

    if (ret_code == 0 && syscall_ret == 0) {
        FD_TEST( memcmp( (void *)&vm_ctx->log_collector, (void *)expected_log_collector, sizeof(fd_vm_log_collector_t)) == 0 );
    }

    FD_LOG_NOTICE(( "Passed test program (%s)", test_case_name ));
}

static void
test_vm_syscall_sol_log_64(
    char *                  test_case_name,
    fd_vm_exec_context_t *  vm_ctx,
    ulong                   r1,
    ulong                   r2,
    ulong                   r3,
    ulong                   r4,
    ulong                   r5,
    ulong                   expected_ret_code,
    ulong                   expected_syscall_ret,
    fd_vm_log_collector_t * expected_log_collector
) {
    ulong ret_code = 0UL;
    ulong syscall_ret = fd_vm_syscall_sol_log_64((void *) vm_ctx, r1, r2, r3, r4, r5, &ret_code);
    FD_TEST( ret_code == expected_ret_code );
    FD_TEST( syscall_ret == expected_syscall_ret );

    if (ret_code == 0 && syscall_ret == 0) {
        FD_TEST( memcmp( (void *)&vm_ctx->log_collector, (void *)expected_log_collector, sizeof(fd_vm_log_collector_t)) == 0 );
    }

    FD_LOG_NOTICE(( "Passed test program (%s)", test_case_name ));
}

static void
test_vm_syscall_sol_log_data(
    char *                  test_case_name,
    fd_vm_exec_context_t *  vm_ctx,
    ulong                   data_vm_addr,
    ulong                   data_len,
    ulong                   expected_ret_code,
    ulong                   expected_syscall_ret,
    fd_vm_log_collector_t * expected_log_collector
) {
    ulong ret_code = 0UL;
    ulong syscall_ret = fd_vm_syscall_sol_log_data((void *) vm_ctx, data_vm_addr, data_len, 0, 0, 0, &ret_code);
    FD_TEST( ret_code == expected_ret_code );
    FD_TEST( syscall_ret == expected_syscall_ret );

    if (ret_code == 0 && syscall_ret == 0) {
        FD_TEST( memcmp( (void *)&vm_ctx->log_collector, (void *)expected_log_collector, sizeof(fd_vm_log_collector_t)) == 0 );
    }

    FD_LOG_NOTICE(( "Passed test program (%s)", test_case_name ));
}


int
main( int     argc,
      char ** argv ) {
    fd_boot( &argc, &argv );

    fd_rng_t _rng[1]; fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, 0U, 0UL ) );
    ulong const read_only_sz = 500UL;
    uchar read_only_prog[read_only_sz];

    fd_vm_exec_context_t vm_ctx = {
        .entrypoint          = 0,
        .program_counter     = 0,
        .instruction_counter = 0,
        .instrs              = NULL,
        .instrs_sz           = 0,
        .instrs_offset       = 0,
        .syscall_map         = NULL,
        .calldests           = NULL,
        .input               = NULL,
        .input_sz            = 0,
        .read_only           = read_only_prog,
        .read_only_sz        = read_only_sz,
        .heap_sz             = FD_VM_DEFAULT_HEAP_SZ,
    };

    set_vm_read_only_memory_region( &vm_ctx );

    test_vm_syscall_sol_memset(
        "test_vm_syscall_sol_memset: memset at the heap region without offset",
        &vm_ctx,
        FD_VM_MEM_MAP_HEAP_REGION_START,
        (ulong) &vm_ctx.heap[0],
        0UL,
        100UL,
        0,
        0
    );

    ulong offset = 10UL;
    test_vm_syscall_sol_memset(
        "test_vm_syscall_sol_memset: memset at the heap region with offset",
        &vm_ctx,
        FD_VM_MEM_MAP_HEAP_REGION_START + offset,
        (ulong) &vm_ctx.heap[offset],
        0UL,
        100UL,
        0,
        0
    );

    // test we cannot memset at the read_only region
    test_vm_syscall_sol_memset(
        "test_vm_syscall_sol_memset: memset at the read_only region",
        &vm_ctx,
        FD_VM_MEM_MAP_PROGRAM_REGION_START,
        0UL,
        0UL,
        100UL,
        0,
        FD_VM_MEM_MAP_ERR_ACC_VIO
    );

    test_vm_syscall_sol_memcpy(
        "test_vm_syscall_sol_memcpy: memcpy at the heap region",
        &vm_ctx,
        FD_VM_MEM_MAP_HEAP_REGION_START,
        FD_VM_MEM_MAP_HEAP_REGION_START + 100UL,
        (ulong) &vm_ctx.heap[0],
        (ulong) &vm_ctx.heap[100],
        100UL,
        0,
        0
    );

    // test we can copy from ready only region to heap region
    test_vm_syscall_sol_memcpy(
        "test_vm_syscall_sol_memcpy: memcpy from read only region to heap region",
        &vm_ctx,
        FD_VM_MEM_MAP_PROGRAM_REGION_START,
        FD_VM_MEM_MAP_HEAP_REGION_START,
        (ulong) &vm_ctx.read_only[0],
        (ulong) &vm_ctx.heap[0],
        100UL,
        0,
        0
    );

    // test we cannot copy from heap region to read only region
    test_vm_syscall_sol_memcpy(
        "test_vm_syscall_sol_memcpy: memcpy from heap region to read only region",
        &vm_ctx,
        FD_VM_MEM_MAP_HEAP_REGION_START,
        FD_VM_MEM_MAP_PROGRAM_REGION_START,
        (ulong) &vm_ctx.heap[0],
        (ulong) &vm_ctx.read_only[0],
        100UL,
        0,
        FD_VM_MEM_MAP_ERR_ACC_VIO
    );

    // test we cannot copy more than the available size from the read-only region
    test_vm_syscall_sol_memcpy(
        "test_vm_syscall_sol_memcpy: memcpy from read only region to heap region",
        &vm_ctx,
        FD_VM_MEM_MAP_PROGRAM_REGION_START,
        FD_VM_MEM_MAP_HEAP_REGION_START,
        (ulong) &vm_ctx.read_only[0],
        (ulong) &vm_ctx.heap[0],
        read_only_sz + 1UL,
        0,
        FD_VM_MEM_MAP_ERR_ACC_VIO
    );

    // test we cannot copy overlapping regions in heap where src is before dst
    test_vm_syscall_sol_memcpy(
        "test_vm_syscall_sol_memcpy: memcpy overlapping regions in heap - src before dst",
        &vm_ctx,
        FD_VM_MEM_MAP_HEAP_REGION_START,
        FD_VM_MEM_MAP_HEAP_REGION_START + 10UL,
        (ulong) &vm_ctx.heap[0],
        (ulong) &vm_ctx.heap[10],
        100UL,
        0,
        FD_VM_SYSCALL_ERR_MEM_OVERLAP
    );

    // test we cannot copy overlapping regions in heap where src is after dst
    test_vm_syscall_sol_memcpy(
        "test_vm_syscall_sol_memcpy: memcpy overlapping regions in heap - src after dst",
        &vm_ctx,
        FD_VM_MEM_MAP_HEAP_REGION_START + 10UL,
        FD_VM_MEM_MAP_HEAP_REGION_START,
        (ulong) &vm_ctx.heap[10],
        (ulong) &vm_ctx.heap[0],
        100UL,
        0,
        FD_VM_SYSCALL_ERR_MEM_OVERLAP
    );

    // test we can memmove from heap region to heap region
    test_vm_syscall_sol_memmove(
        "test_vm_syscall_sol_memmove: memmove from heap region to heap region",
        &vm_ctx,
        FD_VM_MEM_MAP_HEAP_REGION_START,
        FD_VM_MEM_MAP_HEAP_REGION_START + 100UL,
        (ulong) &vm_ctx.heap[0],
        (ulong) &vm_ctx.heap[100],
        100UL,
        0,
        0
    );

    // test we can memmove overlapping regions in heap
    test_vm_syscall_sol_memmove(
        "test_vm_syscall_sol_memmove: memmove overlapping regions in heap",
        &vm_ctx,
        FD_VM_MEM_MAP_HEAP_REGION_START,
        FD_VM_MEM_MAP_HEAP_REGION_START + 10UL,
        (ulong) &vm_ctx.heap[0],
        (ulong) &vm_ctx.heap[10],
        100UL,
        0,
        0
    );

    // test we can memmove from read only region to heap region
    test_vm_syscall_sol_memmove(
        "test_vm_syscall_sol_memmove: memmove from read only region to heap region",
        &vm_ctx,
        FD_VM_MEM_MAP_PROGRAM_REGION_START,
        FD_VM_MEM_MAP_HEAP_REGION_START,
        (ulong) &vm_ctx.read_only[0],
        (ulong) &vm_ctx.heap[0],
        100UL,
        0,
        0
    );

    // test we cannot memmove from heap region to read only region
    test_vm_syscall_sol_memmove(
        "test_vm_syscall_sol_memmove: memmove from heap region to read only region",
        &vm_ctx,
        FD_VM_MEM_MAP_HEAP_REGION_START,
        FD_VM_MEM_MAP_PROGRAM_REGION_START,
        (ulong) &vm_ctx.heap[0],
        (ulong) &vm_ctx.read_only[0],
        100UL,
        0,
        FD_VM_MEM_MAP_ERR_ACC_VIO
    );

    // test for memcmp at the heap region
    test_vm_syscall_sol_memcmp(
        "test_vm_syscall_sol_memcmp: memcmp at the heap region",
        &vm_ctx,
        FD_VM_MEM_MAP_HEAP_REGION_START,
        FD_VM_MEM_MAP_HEAP_REGION_START + 100UL,
        FD_VM_MEM_MAP_HEAP_REGION_START + 200UL,
        (ulong) &vm_ctx.heap[0],
        (ulong) &vm_ctx.heap[100],
        (ulong) &vm_ctx.heap[200],
        100UL,
        0,
        0
    );

    // test for memcmp at the read only region
    test_vm_syscall_sol_memcmp(
        "test_vm_syscall_sol_memcmp: memcmp at the read only region",
        &vm_ctx,
        FD_VM_MEM_MAP_PROGRAM_REGION_START,
        FD_VM_MEM_MAP_PROGRAM_REGION_START + 100UL,
        FD_VM_MEM_MAP_HEAP_REGION_START,
        (ulong) &vm_ctx.read_only[0],
        (ulong) &vm_ctx.read_only[100],
        (ulong) &vm_ctx.heap[0],
        100UL,
        0,
        0
    );

    // test we cannot write memcmp results to read only region
    test_vm_syscall_sol_memcmp(
        "test_vm_syscall_sol_memcmp: memcmp write result to the read only region",
        &vm_ctx,
        FD_VM_MEM_MAP_PROGRAM_REGION_START,
        FD_VM_MEM_MAP_PROGRAM_REGION_START + 100UL,
        FD_VM_MEM_MAP_PROGRAM_REGION_START + 200UL,
        (ulong) &vm_ctx.read_only[0],
        (ulong) &vm_ctx.read_only[100],
        (ulong) &vm_ctx.read_only[200],
        100UL,
        0,
        FD_VM_MEM_MAP_ERR_ACC_VIO
    );

    fd_vm_log_collector_t expected_log_collector;
    reset_log_collector(&expected_log_collector);
    reset_log_collector(&vm_ctx.log_collector);

    fd_memcpy( expected_log_collector.buf, "hello world", 11 );
    expected_log_collector.buf_used = 11;
    fd_memcpy( &vm_ctx.heap[0], "hello world", 11 );
    // test for colletcing logs at the heap region
    test_vm_syscall_sol_log(
        "test_vm_syscall_sol_log: log at the heap region",
        &vm_ctx,
        FD_VM_MEM_MAP_HEAP_REGION_START,
        11UL,
        0,
        0,
        &expected_log_collector
    );

    // test for colletcing logs at the read only region
    fd_memcpy( expected_log_collector.buf + expected_log_collector.buf_used, &vm_ctx.read_only[0], 100 );
    expected_log_collector.buf_used += 100UL;
    test_vm_syscall_sol_log(
        "test_vm_syscall_sol_log: log at the read only region",
        &vm_ctx,
        FD_VM_MEM_MAP_PROGRAM_REGION_START,
        100UL,
        0,
        0,
        &expected_log_collector
    );

    // test for writing logs that exceed the remaining space
    fd_memcpy( expected_log_collector.buf + expected_log_collector.buf_used, &vm_ctx.heap[0], FD_VM_LOG_COLLECTOR_BYTES_LIMIT );
    expected_log_collector.buf_used = FD_VM_LOG_COLLECTOR_BYTES_LIMIT;
    test_vm_syscall_sol_log(
        "test_vm_syscall_sol_log: log that exceeds the limit",
        &vm_ctx,
        FD_VM_MEM_MAP_HEAP_REGION_START,
        FD_VM_LOG_COLLECTOR_BYTES_LIMIT + 1UL,
        0,
        0,
        &expected_log_collector
    );

    // test for writing logs when there's no more space
    test_vm_syscall_sol_log(
        "test_vm_syscall_sol_log: log when there's no more space",
        &vm_ctx,
        FD_VM_MEM_MAP_HEAP_REGION_START,
        1UL,
        0,
        0,
        &expected_log_collector
    );

    reset_log_collector(&expected_log_collector);
    reset_log_collector(&vm_ctx.log_collector);
    ulong r1 = fd_rng_ulong(rng);
    ulong r2 = fd_rng_ulong(rng);
    ulong r3 = fd_rng_ulong(rng);
    ulong r4 = fd_rng_ulong(rng);
    ulong r5 = fd_rng_ulong(rng);
    char msg[1024];
    ulong msg_len =  (ulong)sprintf( msg, "Program log: %lx %lx %lx %lx %lx", r1, r2, r3, r4, r5 );
    fd_memcpy( expected_log_collector.buf, msg, msg_len );
    expected_log_collector.buf_used = msg_len;

    // test for colletcing log_64 at the heap region
    test_vm_syscall_sol_log_64(
        "test_vm_syscall_sol_log_64: log_64 at the heap region",
        &vm_ctx,
        r1,
        r2,
        r3,
        r4,
        r5,
        0,
        0,
        &expected_log_collector
    );

    reset_log_collector(&expected_log_collector);
    reset_log_collector(&vm_ctx.log_collector);

    // test for collecting log_data at the heap region
    fd_vm_vec_t log_vec = {
        .addr = FD_VM_MEM_MAP_HEAP_REGION_START + 100,
        .len = 5UL
    };
    ulong data_chunk_num = 5UL;
    for (ulong i = 0; i < data_chunk_num; ++i) {
        fd_memcpy((void *) (&vm_ctx.heap[0] + i * sizeof(fd_vm_vec_t)), &log_vec, sizeof(log_vec));
    }
    ulong data_len = data_chunk_num * sizeof(fd_vm_vec_t);

    expected_log_collector.buf_used = 58UL;
    memcpy(&expected_log_collector.buf[0], "Program data: ZGVmZ2g= ZGVmZ2g= ZGVmZ2g= ZGVmZ2g= ZGVmZ2g=", expected_log_collector.buf_used);

    test_vm_syscall_sol_log_data(
        "test_vm_syscall_sol_log_data: log_data at the heap region",
        &vm_ctx,
        FD_VM_MEM_MAP_HEAP_REGION_START,
        data_len,
        0,
        0,
        &expected_log_collector
    );
    fd_rng_delete( fd_rng_leave( rng ) );

    FD_LOG_NOTICE(( "pass" ));
    fd_halt();
}
