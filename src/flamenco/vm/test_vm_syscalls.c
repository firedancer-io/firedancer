
#include "fd_vm_context.h"
#include "fd_vm_syscalls.h"

static void
test_vm_syscall_sol_memset(
    char *                 test_case_name,
    fd_vm_exec_context_t * vm_ctx,
    ulong                  dst_vm_addr,
    ulong                  dst_host_addr,
    ulong                  val,
    ulong                  sz, 
    ulong                  expected_ret_code,
    ulong                  expected_syscall_ret )
{
    ulong ret_code = 0UL;
    ulong syscall_ret = fd_vm_syscall_sol_memset((void *) vm_ctx, dst_vm_addr, val, sz, 0, 0, &ret_code);
    FD_TEST( ret_code == expected_ret_code );
    FD_TEST( syscall_ret == expected_syscall_ret );

    if (ret_code == 0 && syscall_ret == 0) {
        char expected_block[sz];
        fd_memset( expected_block, (int)val, sz);
        FD_TEST( memcmp((void *)dst_host_addr, expected_block, sz) == 0 );
    }

    FD_LOG_NOTICE(( "Passed test program (%s)", test_case_name ));
}

static void
set_vm_heap_memory_region( fd_vm_exec_context_t * vm_ctx ) {
    for (int i = 0; i < FD_VM_HEAP_SZ; i++) {
        vm_ctx->heap[i] = (uchar) (i % (UCHAR_MAX + 1));
    }
}

int
main( int     argc,
      char ** argv ) {
    fd_boot( &argc, &argv );

    // fd_rng_t _rng[1]; fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, 0U, 0UL ) );

    fd_vm_exec_context_t vm_ctx = {
        .entrypoint          = 0,
        .program_counter     = 0,
        .instruction_counter = 0,
        .instrs              = NULL,
        .instrs_sz           = 0,
        .instrs_offset       = 0,
        .syscall_map         = NULL,
        .local_call_map      = NULL,
        .input               = NULL,
        .input_sz            = 0,
        .read_only           = NULL,
        .read_only_sz        = 0,
    };

    set_vm_heap_memory_region( &vm_ctx );

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

    set_vm_heap_memory_region( &vm_ctx );

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

    FD_LOG_NOTICE(( "pass" ));
    fd_halt();
}
