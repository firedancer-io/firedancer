#include "fd_vm_syscall.h"

static void
set_vm_read_only_memory_region( fd_vm_exec_context_t * vm_ctx ) {
  for( ulong i=0UL; i<vm_ctx->read_only_sz; i++ ) vm_ctx->read_only[i] = (uchar) (i % (UCHAR_MAX + 1));
}

static void
test_vm_syscall_sol_curve_multiscalar_mul(
    char *                test_case_name,
    fd_vm_exec_context_t *vm_ctx,
    ulong                 curve_id,
    ulong                 scalar_vm_addr,
    ulong                 point_vm_addr,
    ulong                 point_cnt,
    ulong                 result_point_vm_addr,
    ulong                 expected_ret_code,
    int                   expected_syscall_ret,
    void *                expected_result_host_ptr
) {
    ulong ret_code = 0UL;
    int   syscall_ret = fd_vm_syscall_sol_curve_multiscalar_mul((void *) vm_ctx, curve_id, scalar_vm_addr, point_vm_addr, point_cnt, result_point_vm_addr, &ret_code);
    FD_TEST( ret_code == expected_ret_code );
    FD_TEST( syscall_ret == expected_syscall_ret );

    void * result_point_host_addr = fd_vm_translate_vm_to_host( vm_ctx, result_point_vm_addr, 32, 1 );
    if (ret_code == 0 && syscall_ret == 0) {
        FD_TEST( memcmp( result_point_host_addr, expected_result_host_ptr, 32 ) == 0 );
    }

    FD_LOG_NOTICE(( "Passed test program (%s)", test_case_name ));
}

static void
test_fd_vm_syscall_sol_curve_group_op(
    char *                test_case_name,
    fd_vm_exec_context_t *vm_ctx,
    ulong                 curve_id,
    ulong                 op_id,
    ulong                 in0_vm_addr,
    ulong                 in1_vm_addr,
    ulong                 result_point_vm_addr,
    ulong                 expected_ret_code,
    int                   expected_syscall_ret,
    void *                expected_result_host_ptr
) {
    ulong ret_code = 0UL;
    int   syscall_ret = fd_vm_syscall_sol_curve_group_op((void *) vm_ctx, curve_id, op_id, in0_vm_addr, in1_vm_addr, result_point_vm_addr, &ret_code);
    FD_TEST( ret_code == expected_ret_code );
    FD_TEST( syscall_ret == expected_syscall_ret );

    void * result_point_host_addr = fd_vm_translate_vm_to_host( vm_ctx, result_point_vm_addr, 32, 1 );
    if (ret_code == 0 && syscall_ret == 0) {
        FD_TEST( memcmp( result_point_host_addr, expected_result_host_ptr, 32 ) == 0 );
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

  ulong scalar_vm_addr = 0;
  ulong point_vm_addr = 0;
  ulong result_point_vm_addr = 0;
  ulong in0_vm_addr = 0;
  ulong in1_vm_addr = 0;
  void * expected_result_host_ptr = NULL;

  // invalid
  test_vm_syscall_sol_curve_multiscalar_mul(
    "test_vm_syscall_sol_curve_multiscalar_mul: invalid",
    &vm_ctx,
    FD_VM_SYSCALL_SOL_CURVE_ECC_ED25519,
    scalar_vm_addr,
    point_vm_addr,
    0UL, // point_cnt
    result_point_vm_addr,
    0UL, // ret_code
    FD_VM_ERR_PERM, // syscall_ret
    expected_result_host_ptr
  );

  // success
  // https://github.com/solana-labs/solana/blob/v1.17.15/programs/bpf_loader/src/syscalls/mod.rs#L3107
  {
    uchar _scalars[ 64 ] = {
      254, 198, 23, 138, 67, 243, 184, 110, 236, 115, 236, 205, 205, 215, 79, 114, 45, 250,
      78, 137, 3, 107, 136, 237, 49, 126, 117, 223, 37, 191, 88, 6,
      254, 198, 23, 138, 67, 243, 184, 110, 236, 115, 236, 205, 205, 215, 79, 114, 45, 250,
      78, 137, 3, 107, 136, 237, 49, 126, 117, 223, 37, 191, 88, 6,
    }; uchar * scalars = _scalars;

    uchar _points[ 64 ] = {
      252, 31, 230, 46, 173, 95, 144, 148, 158, 157, 63, 10, 8, 68, 58, 176, 142, 192, 168,
      53, 61, 105, 194, 166, 43, 56, 246, 236, 28, 146, 114, 133,
      10, 111, 8, 236, 97, 189, 124, 69, 89, 176, 222, 39, 199, 253, 111, 11, 248, 186, 128,
      90, 120, 128, 248, 210, 232, 183, 93, 104, 111, 150, 7, 241,
    }; uchar * points = _points;

    uchar _expected[ 32 ] = {
      30, 174, 168, 34, 160, 70, 63, 166, 236, 18, 74, 144, 185, 222, 208, 243, 5, 54, 223,
      172, 185, 75, 244, 26, 70, 18, 248, 46, 207, 184, 235, 60,
    };

    memcpy( &vm_ctx.heap[0], scalars, 64 );
    memcpy( &vm_ctx.heap[64], points, 64 );

    scalar_vm_addr = FD_VM_MEM_MAP_HEAP_REGION_START;
    point_vm_addr = FD_VM_MEM_MAP_HEAP_REGION_START + 64UL;
    result_point_vm_addr = FD_VM_MEM_MAP_HEAP_REGION_START + 128UL;
    expected_result_host_ptr = _expected;

    test_vm_syscall_sol_curve_multiscalar_mul(
      "test_vm_syscall_sol_curve_multiscalar_mul: ed25519",
      &vm_ctx,
      FD_VM_SYSCALL_SOL_CURVE_ECC_ED25519,
      scalar_vm_addr,
      point_vm_addr,
      2UL,
      result_point_vm_addr,
      0UL, // ret_code
      FD_VM_SUCCESS, // syscall_ret
      expected_result_host_ptr
    );
  }

  {
    uchar _scalars[ 64 ] = {
      254, 198, 23, 138, 67, 243, 184, 110, 236, 115, 236, 205, 205, 215, 79, 114, 45, 250,
      78, 137, 3, 107, 136, 237, 49, 126, 117, 223, 37, 191, 88, 6,
      254, 198, 23, 138, 67, 243, 184, 110, 236, 115, 236, 205, 205, 215, 79, 114, 45, 250,
      78, 137, 3, 107, 136, 237, 49, 126, 117, 223, 37, 191, 88, 6,
    }; uchar * scalars = _scalars;

    uchar _points[ 64 ] = {
      130, 35, 97, 25, 18, 199, 33, 239, 85, 143, 119, 111, 49, 51, 224, 40, 167, 185, 240,
      179, 25, 194, 213, 41, 14, 155, 104, 18, 181, 197, 15, 112,
      152, 156, 155, 197, 152, 232, 92, 206, 219, 159, 193, 134, 121, 128, 139, 36, 56, 191,
      51, 143, 72, 204, 87, 76, 110, 124, 101, 96, 238, 158, 42, 108,
    }; uchar * points = _points;

    uchar _expected[ 32 ] = {
      78, 120, 86, 111, 152, 64, 146, 84, 14, 236, 77, 147, 237, 190, 251, 241, 136, 167, 21,
      94, 84, 118, 92, 140, 120, 81, 30, 246, 173, 140, 195, 86,
    };

    memcpy( &vm_ctx.heap[0], scalars, 64 );
    memcpy( &vm_ctx.heap[64], points, 64 );

    scalar_vm_addr = FD_VM_MEM_MAP_HEAP_REGION_START;
    point_vm_addr = FD_VM_MEM_MAP_HEAP_REGION_START + 64UL;
    result_point_vm_addr = FD_VM_MEM_MAP_HEAP_REGION_START + 128UL;
    expected_result_host_ptr = _expected;

    test_vm_syscall_sol_curve_multiscalar_mul(
      "test_vm_syscall_sol_curve_multiscalar_mul: ristretto255",
      &vm_ctx,
      FD_VM_SYSCALL_SOL_CURVE_ECC_RISTRETTO255,
      scalar_vm_addr,
      point_vm_addr,
      2UL,
      result_point_vm_addr,
      0UL, // ret_code
      FD_VM_SUCCESS, // syscall_ret
      expected_result_host_ptr
    );
  }

  // test 0 + P
  {
    uchar _points[ 64 ] = {
      0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
      0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
      78, 173, 9, 241, 180, 224, 31, 107, 176, 210, 144, 240, 118, 73, 70, 191, 128, 119,
      141, 113, 125, 215, 161, 71, 49, 176, 87, 38, 180, 177, 39, 78,
    }; uchar * points = _points;

    uchar _expected[ 32 ] = {
      78, 173, 9, 241, 180, 224, 31, 107, 176, 210, 144, 240, 118, 73, 70, 191, 128, 119,
      141, 113, 125, 215, 161, 71, 49, 176, 87, 38, 180, 177, 39, 78,
    };

    memcpy( &vm_ctx.heap[0], points, 64 );

    in0_vm_addr = FD_VM_MEM_MAP_HEAP_REGION_START;
    in1_vm_addr = FD_VM_MEM_MAP_HEAP_REGION_START + 32UL;
    result_point_vm_addr = FD_VM_MEM_MAP_HEAP_REGION_START + 64UL;
    expected_result_host_ptr = _expected;

    test_fd_vm_syscall_sol_curve_group_op(
      "fd_vm_syscall_sol_curve_group_op: ristretto255, add 0 + P",
      &vm_ctx,
      FD_VM_SYSCALL_SOL_CURVE_ECC_RISTRETTO255,
      FD_VM_SYSCALL_SOL_CURVE_ECC_G_ADD,
      in0_vm_addr,
      in1_vm_addr,
      result_point_vm_addr,
      0UL, // ret_code
      FD_VM_SUCCESS, // syscall_ret
      expected_result_host_ptr
    );
  }

  // https://github.com/solana-labs/solana/blob/v1.17.15/programs/bpf_loader/src/syscalls/mod.rs#L2948C8-L2948C46
  {
    uchar _points[ 64 ] = {
      208, 165, 125, 204, 2, 100, 218, 17, 170, 194, 23, 9, 102, 156, 134, 136, 217, 190, 98,
      34, 183, 194, 228, 153, 92, 11, 108, 103, 28, 57, 88, 15,
      208, 241, 72, 163, 73, 53, 32, 174, 54, 194, 71, 8, 70, 181, 244, 199, 93, 147, 99,
      231, 162, 127, 25, 40, 39, 19, 140, 132, 112, 212, 145, 108,
      // 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
      // 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    }; uchar * points = _points;

    uchar _expected[ 32 ] = {
      78, 173, 9, 241, 180, 224, 31, 107, 176, 210, 144, 240, 118, 73, 70, 191, 128, 119,
      141, 113, 125, 215, 161, 71, 49, 176, 87, 38, 180, 177, 39, 78,
    };

    memcpy( &vm_ctx.heap[0], points, 64 );

    in0_vm_addr = FD_VM_MEM_MAP_HEAP_REGION_START;
    in1_vm_addr = FD_VM_MEM_MAP_HEAP_REGION_START + 32UL;
    result_point_vm_addr = FD_VM_MEM_MAP_HEAP_REGION_START + 64UL;
    expected_result_host_ptr = _expected;

    test_fd_vm_syscall_sol_curve_group_op(
      "fd_vm_syscall_sol_curve_group_op: ristretto255, add",
      &vm_ctx,
      FD_VM_SYSCALL_SOL_CURVE_ECC_RISTRETTO255,
      FD_VM_SYSCALL_SOL_CURVE_ECC_G_ADD,
      in0_vm_addr,
      in1_vm_addr,
      result_point_vm_addr,
      0UL, // ret_code
      FD_VM_SUCCESS, // syscall_ret
      expected_result_host_ptr
    );
  }

  {
    uchar _points[ 64 ] = {
      208, 165, 125, 204, 2, 100, 218, 17, 170, 194, 23, 9, 102, 156, 134, 136, 217, 190, 98,
      34, 183, 194, 228, 153, 92, 11, 108, 103, 28, 57, 88, 15,
      208, 241, 72, 163, 73, 53, 32, 174, 54, 194, 71, 8, 70, 181, 244, 199, 93, 147, 99,
      231, 162, 127, 25, 40, 39, 19, 140, 132, 112, 212, 145, 108,
    }; uchar * points = _points;

    uchar _expected[ 32 ] = {
      150, 72, 222, 61, 148, 79, 96, 130, 151, 176, 29, 217, 231, 211, 0, 215, 76, 86, 212,
      146, 110, 128, 24, 151, 187, 144, 108, 233, 221, 208, 157, 52,
    };

    memcpy( &vm_ctx.heap[0], points, 64 );

    in0_vm_addr = FD_VM_MEM_MAP_HEAP_REGION_START;
    in1_vm_addr = FD_VM_MEM_MAP_HEAP_REGION_START + 32UL;
    result_point_vm_addr = FD_VM_MEM_MAP_HEAP_REGION_START + 64UL;
    expected_result_host_ptr = _expected;

    test_fd_vm_syscall_sol_curve_group_op(
      "fd_vm_syscall_sol_curve_group_op: ristretto255, sub",
      &vm_ctx,
      FD_VM_SYSCALL_SOL_CURVE_ECC_RISTRETTO255,
      FD_VM_SYSCALL_SOL_CURVE_ECC_G_SUB,
      in0_vm_addr,
      in1_vm_addr,
      result_point_vm_addr,
      0UL, // ret_code
      FD_VM_SUCCESS, // syscall_ret
      expected_result_host_ptr
    );
  }

  {
    uchar _scalars[ 32 ] = {
      254, 198, 23, 138, 67, 243, 184, 110, 236, 115, 236, 205, 205, 215, 79, 114, 45, 250,
      78, 137, 3, 107, 136, 237, 49, 126, 117, 223, 37, 191, 88, 6,
    }; uchar * scalars = _scalars;

    uchar _points[ 32 ] = {
      208, 241, 72, 163, 73, 53, 32, 174, 54, 194, 71, 8, 70, 181, 244, 199, 93, 147, 99,
      231, 162, 127, 25, 40, 39, 19, 140, 132, 112, 212, 145, 108,
    }; uchar * points = _points;

    uchar _expected[ 32 ] = {
      4, 16, 46, 2, 53, 151, 201, 133, 117, 149, 232, 164, 119, 109, 136, 20, 153, 24, 124,
      21, 101, 124, 80, 19, 119, 100, 77, 108, 65, 187, 228, 5,
    };

    memcpy( &vm_ctx.heap[0], scalars, 32 );
    memcpy( &vm_ctx.heap[32], points, 32 );

    in0_vm_addr = FD_VM_MEM_MAP_HEAP_REGION_START;
    in1_vm_addr = FD_VM_MEM_MAP_HEAP_REGION_START + 32UL;
    result_point_vm_addr = FD_VM_MEM_MAP_HEAP_REGION_START + 64UL;
    expected_result_host_ptr = _expected;

    test_fd_vm_syscall_sol_curve_group_op(
      "fd_vm_syscall_sol_curve_group_op: ristretto255, mul",
      &vm_ctx,
      FD_VM_SYSCALL_SOL_CURVE_ECC_RISTRETTO255,
      FD_VM_SYSCALL_SOL_CURVE_ECC_G_MUL,
      in0_vm_addr,
      in1_vm_addr,
      result_point_vm_addr,
      0UL, // ret_code
      FD_VM_SUCCESS, // syscall_ret
      expected_result_host_ptr
    );
  }

  fd_rng_delete( fd_rng_leave( rng ) );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
}
