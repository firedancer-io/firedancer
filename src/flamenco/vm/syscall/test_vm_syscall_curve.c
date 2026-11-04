#include "fd_vm_syscall.h"
#include "../test_vm_util.h"
#include "../../runtime/fd_bank.h"
#include "../../../ballet/hex/fd_hex.h"

static inline void set_memory_region( uchar * mem, ulong sz ) { for( ulong i=0UL; i<sz; i++ ) mem[i] = (uchar)(i & 0xffUL); }

static int
test_vm_syscall_sol_curve_multiscalar_mul( char const * test_case_name,
                                           fd_vm_t *    vm,
                                           ulong        curve_id,
                                           ulong        scalar_vaddr,
                                           ulong        point_vaddr,
                                           ulong        point_cnt,
                                           ulong        result_point_vaddr,
                                           ulong        result_sz,
                                           ulong        expected_ret_code,
                                           int          expected_syscall_ret,
                                           void *       expected_result_host_ptr ) {
    int   syscall_ret = fd_vm_syscall_sol_curve_multiscalar_mul((void *) vm, curve_id, scalar_vaddr, point_vaddr, point_cnt, result_point_vaddr);
    ulong ret_code = vm->reg[0];
    FD_TEST( syscall_ret == expected_syscall_ret );
    if( syscall_ret==FD_VM_SUCCESS ) {
      FD_TEST( ret_code == expected_ret_code );
    }
    test_vm_clear_txn_ctx_err( vm->instr_ctx->txn_out );

    if (ret_code == 0 && syscall_ret == 0) {
        const void * result_point_host_addr = FD_VM_MEM_HADDR_LD( vm, result_point_vaddr, 1, result_sz );
        FD_TEST( memcmp( result_point_host_addr, expected_result_host_ptr, result_sz ) == 0 );
    }

    FD_LOG_NOTICE(( "Passed test program (%s)", test_case_name ));

    return 1;
}

static int
test_fd_vm_syscall_sol_curve_group_op( char const * test_case_name,
                                       fd_vm_t *    vm,
                                       ulong        curve_id,
                                       ulong        op_id,
                                       ulong        in0_vaddr,
                                       ulong        in1_vaddr,
                                       ulong        result_point_vaddr,
                                       ulong        result_sz,
                                       ulong        expected_ret_code,
                                       int          expected_syscall_ret,
                                       void *       expected_result_host_ptr ) {
    int   syscall_ret = fd_vm_syscall_sol_curve_group_op((void *) vm, curve_id, op_id, in0_vaddr, in1_vaddr, result_point_vaddr);
    ulong ret_code = vm->reg[0];
    FD_TEST( syscall_ret == expected_syscall_ret );
    if( syscall_ret==FD_VM_SUCCESS ) {
      FD_TEST( ret_code == expected_ret_code );
    }
    test_vm_clear_txn_ctx_err( vm->instr_ctx->txn_out );

    if (ret_code == 0 && syscall_ret == 0) {
        const void * result_point_host_addr = FD_VM_MEM_HADDR_LD( vm, result_point_vaddr, 1, result_sz );
        FD_TEST( memcmp( result_point_host_addr, expected_result_host_ptr, result_sz ) == 0 );
    }

    FD_LOG_NOTICE(( "Passed test program (%s)", test_case_name ));

    return 1;
}

static int
test_fd_vm_syscall_sol_curve_decompress( char const * test_case_name,
                                         fd_vm_t *    vm,
                                         ulong        curve_id,
                                         ulong        point_vaddr,
                                         ulong        result_vaddr,
                                         ulong        result_sz,
                                         ulong        expected_ret_code,
                                         int          expected_syscall_ret,
                                         void const * expected_result_host_ptr ) {
    int   syscall_ret = fd_vm_syscall_sol_curve_decompress( (void *)vm, curve_id, point_vaddr, result_vaddr, 0UL, 0UL );
    ulong ret_code = vm->reg[0];
    FD_TEST( syscall_ret == expected_syscall_ret );
    if( syscall_ret==FD_VM_SUCCESS ) {
      FD_TEST( ret_code == expected_ret_code );
    }
    test_vm_clear_txn_ctx_err( vm->instr_ctx->txn_out );

    if( ret_code==0UL && syscall_ret==FD_VM_SUCCESS ) {
      void const * result_host_addr = FD_VM_MEM_HADDR_LD( vm, result_vaddr, 1, result_sz );
      FD_TEST( memcmp( result_host_addr, expected_result_host_ptr, result_sz ) == 0 );
    }

    FD_LOG_NOTICE(( "Passed test program (%s)", test_case_name ));

    return 1;
}

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

  fd_sha256_t _sha[1];
  fd_sha256_t * sha = fd_sha256_join( fd_sha256_new( _sha ) );

  fd_vm_t _vm[1];
  fd_vm_t * vm = fd_vm_join( fd_vm_new( _vm ) );
  FD_TEST( vm );

  ulong const rodata_sz = 500UL;
  uchar       rodata[ rodata_sz ];
  set_memory_region( rodata, rodata_sz );

  static fd_exec_instr_ctx_t instr_ctx[1];
  static fd_bank_t           bank[1];
  static fd_txn_out_t        txn_out[1];
  test_vm_minimal_exec_instr_ctx( instr_ctx, runtime, bank, txn_out );

  fd_features_enable_all( &bank->f.features );

  int vm_ok = !!fd_vm_init(
      /* vm                                     */ vm,
      /* instr_ctx                              */ instr_ctx,  /* required for FD_FEATURE_ACTIVE */
      /* heap_max                               */ FD_VM_HEAP_DEFAULT,
      /* entry_cu                               */ FD_VM_COMPUTE_UNIT_LIMIT,
      /* rodata                                 */ rodata,
      /* rodata_sz                              */ rodata_sz,
      /* text                                   */ NULL,
      /* text_cnt                               */ 0UL,
      /* text_off                               */ 0UL,
      /* text_sz                                */ 0UL,
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
      /* direct mapping                         */ FD_FEATURE_ACTIVE_BANK( instr_ctx->bank, account_data_direct_mapping ),
      /* syscall_parameter_address_restrictions */ FD_FEATURE_ACTIVE_BANK( instr_ctx->bank, syscall_parameter_address_restrictions ),
      /* virtual_address_space_adjustments      */ FD_FEATURE_ACTIVE_BANK( instr_ctx->bank, virtual_address_space_adjustments ),
      /* dump_syscall_to_pb                     */ 0,
      /* r2_initial_value                       */ 0UL
  );
  FD_TEST( vm_ok );
  fd_vm_mem_init_full( vm );

  ulong scalar_vaddr = 0;
  ulong point_vaddr = 0;
  ulong result_point_vaddr = 0;
  ulong in0_vaddr = 0;
  ulong in1_vaddr = 0;
  void * expected_result_host_ptr = NULL;

  // invalid
  FD_TEST( test_vm_syscall_sol_curve_multiscalar_mul(
    "test_vm_syscall_sol_curve_multiscalar_mul: invalid",
    vm,
    FD_VM_SYSCALL_SOL_CURVE_CURVE25519_EDWARDS,
    scalar_vaddr,
    point_vaddr,
    0UL, // point_cnt
    result_point_vaddr,
    32UL, // result_sz
    0UL, // ret_code
    FD_VM_SYSCALL_ERR_SEGFAULT, // syscall_ret
    expected_result_host_ptr
  ) );
  test_vm_clear_txn_ctx_err( vm->instr_ctx->txn_out );

  // invalid (max 512 points)
  FD_TEST( test_vm_syscall_sol_curve_multiscalar_mul(
    "test_vm_syscall_sol_curve_multiscalar_mul: invalid",
    vm,
    FD_VM_SYSCALL_SOL_CURVE_CURVE25519_EDWARDS,
    scalar_vaddr,
    point_vaddr,
    513UL, // point_cnt
    result_point_vaddr,
    32UL, // result_sz
    0UL, // ret_code
    FD_VM_SYSCALL_ERR_INVALID_LENGTH, // syscall_ret
    expected_result_host_ptr
  ) );
  test_vm_clear_txn_ctx_err( vm->instr_ctx->txn_out );

  // invalid (max 512 points)
  FD_TEST( test_vm_syscall_sol_curve_multiscalar_mul(
    "test_vm_syscall_sol_curve_multiscalar_mul: invalid",
    vm,
    5, // invalid curve
    scalar_vaddr,
    point_vaddr,
    2UL, // point_cnt
    result_point_vaddr,
    32UL, // result_sz
    0UL, // ret_code
    FD_VM_SYSCALL_ERR_INVALID_ATTRIBUTE, // syscall_ret
    expected_result_host_ptr
  ) );
  test_vm_clear_txn_ctx_err( vm->instr_ctx->txn_out );

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

    memcpy( &vm->heap[0], scalars, 64 );
    memcpy( &vm->heap[64], points, 64 );

    scalar_vaddr = FD_VM_MEM_MAP_HEAP_REGION_START;
    point_vaddr = FD_VM_MEM_MAP_HEAP_REGION_START + 64UL;
    result_point_vaddr = FD_VM_MEM_MAP_HEAP_REGION_START + 128UL;
    expected_result_host_ptr = _expected;

    FD_TEST( test_vm_syscall_sol_curve_multiscalar_mul(
      "test_vm_syscall_sol_curve_multiscalar_mul: ed25519",
      vm,
      FD_VM_SYSCALL_SOL_CURVE_CURVE25519_EDWARDS,
      scalar_vaddr,
      point_vaddr,
      2UL,
      result_point_vaddr,
      32UL, // result_sz
      0UL, // ret_code
      FD_VM_SUCCESS, // syscall_ret
      expected_result_host_ptr
    ) );
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

    memcpy( &vm->heap[0], scalars, 64 );
    memcpy( &vm->heap[64], points, 64 );

    scalar_vaddr = FD_VM_MEM_MAP_HEAP_REGION_START;
    point_vaddr = FD_VM_MEM_MAP_HEAP_REGION_START + 64UL;
    result_point_vaddr = FD_VM_MEM_MAP_HEAP_REGION_START + 128UL;
    expected_result_host_ptr = _expected;

    FD_TEST( test_vm_syscall_sol_curve_multiscalar_mul(
      "test_vm_syscall_sol_curve_multiscalar_mul: ristretto255",
      vm,
      FD_VM_SYSCALL_SOL_CURVE_CURVE25519_RISTRETTO,
      scalar_vaddr,
      point_vaddr,
      2UL,
      result_point_vaddr,
      32UL, // result_sz
      0UL, // ret_code
      FD_VM_SUCCESS, // syscall_ret
      expected_result_host_ptr
    ) );
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

    memcpy( &vm->heap[0], points, 64 );

    in0_vaddr = FD_VM_MEM_MAP_HEAP_REGION_START;
    in1_vaddr = FD_VM_MEM_MAP_HEAP_REGION_START + 32UL;
    result_point_vaddr = FD_VM_MEM_MAP_HEAP_REGION_START + 64UL;
    expected_result_host_ptr = _expected;

    FD_TEST( test_fd_vm_syscall_sol_curve_group_op(
      "fd_vm_syscall_sol_curve_group_op: ristretto255, add 0 + P",
      vm,
      FD_VM_SYSCALL_SOL_CURVE_CURVE25519_RISTRETTO,
      FD_VM_SYSCALL_SOL_CURVE_ADD,
      in0_vaddr,
      in1_vaddr,
      result_point_vaddr,
      32UL, // result_sz
      0UL, // ret_code
      FD_VM_SUCCESS, // syscall_ret
      expected_result_host_ptr
    ) );
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

    memcpy( &vm->heap[0], points, 64 );

    in0_vaddr = FD_VM_MEM_MAP_HEAP_REGION_START;
    in1_vaddr = FD_VM_MEM_MAP_HEAP_REGION_START + 32UL;
    result_point_vaddr = FD_VM_MEM_MAP_HEAP_REGION_START + 64UL;
    expected_result_host_ptr = _expected;

    FD_TEST( test_fd_vm_syscall_sol_curve_group_op(
      "fd_vm_syscall_sol_curve_group_op: ristretto255, add",
      vm,
      FD_VM_SYSCALL_SOL_CURVE_CURVE25519_RISTRETTO,
      FD_VM_SYSCALL_SOL_CURVE_ADD,
      in0_vaddr,
      in1_vaddr,
      result_point_vaddr,
      32UL, // result_sz
      0UL, // ret_code
      FD_VM_SUCCESS, // syscall_ret
      expected_result_host_ptr
    ) );
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

    memcpy( &vm->heap[0], points, 64 );

    in0_vaddr = FD_VM_MEM_MAP_HEAP_REGION_START;
    in1_vaddr = FD_VM_MEM_MAP_HEAP_REGION_START + 32UL;
    result_point_vaddr = FD_VM_MEM_MAP_HEAP_REGION_START + 64UL;
    expected_result_host_ptr = _expected;

    FD_TEST( test_fd_vm_syscall_sol_curve_group_op(
      "fd_vm_syscall_sol_curve_group_op: ristretto255, sub",
      vm,
      FD_VM_SYSCALL_SOL_CURVE_CURVE25519_RISTRETTO,
      FD_VM_SYSCALL_SOL_CURVE_SUB,
      in0_vaddr,
      in1_vaddr,
      result_point_vaddr,
      32UL, // result_sz
      0UL, // ret_code
      FD_VM_SUCCESS, // syscall_ret
      expected_result_host_ptr
    ) );
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

    memcpy( &vm->heap[0], scalars, 32 );
    memcpy( &vm->heap[32], points, 32 );

    in0_vaddr = FD_VM_MEM_MAP_HEAP_REGION_START;
    in1_vaddr = FD_VM_MEM_MAP_HEAP_REGION_START + 32UL;
    result_point_vaddr = FD_VM_MEM_MAP_HEAP_REGION_START + 64UL;
    expected_result_host_ptr = _expected;

    FD_TEST( test_fd_vm_syscall_sol_curve_group_op(
      "fd_vm_syscall_sol_curve_group_op: ristretto255, mul",
      vm,
      FD_VM_SYSCALL_SOL_CURVE_CURVE25519_RISTRETTO,
      FD_VM_SYSCALL_SOL_CURVE_MUL,
      in0_vaddr,
      in1_vaddr,
      result_point_vaddr,
      32UL, // result_sz
      0UL, // ret_code
      FD_VM_SUCCESS, // syscall_ret
      expected_result_host_ptr
    ) );
  }

  {
    uchar _points[ 96*2 ]; uchar * points = _points;
    fd_hex_decode( points, "b0f82e3a5a3a9a589b4887a2c8b4f2757f688fa839d4afe1d702c5c6dc606b3985b764630d38b77f6511f5ecd4a95609af2327c3a3fbb03906dd1f7b24e8c3b9f7f17570ffe93539357bb17604a1d685e1dbfca45ea51e0a593901f07019ce0ab0f82e3a5a3a9a589b4887a2c8b4f2757f688fa839d4afe1d702c5c6dc606b3985b764630d38b77f6511f5ecd4a95609af2327c3a3fbb03906dd1f7b24e8c3b9f7f17570ffe93539357bb17604a1d685e1dbfca45ea51e0a593901f07019ce0a", 96*2 );

    uchar _expected[ 96 ];
    fd_hex_decode( _expected, "35c4b6c580fc3cc85b1d1af6fa7df01003f908d571b11da441c1d02c00ab90659e65a070448be749c571882b7a3e67146c3548e1cce95bc06f736678bc2843145837f5345c7384550d2687185ab68a7b171bf4dcb79476208a960056c7fe0017", 96 );

    memcpy( &vm->heap[0], points, 96*2 );

    in0_vaddr = FD_VM_MEM_MAP_HEAP_REGION_START;
    in1_vaddr = FD_VM_MEM_MAP_HEAP_REGION_START + 96UL;
    result_point_vaddr = FD_VM_MEM_MAP_HEAP_REGION_START + 96UL*2;
    expected_result_host_ptr = _expected;

    FD_TEST( test_fd_vm_syscall_sol_curve_group_op(
      "fd_vm_syscall_sol_curve_group_op: bls12-381, add",
      vm,
      FD_VM_SYSCALL_SOL_CURVE_BLS12_381_G1_LE,
      FD_VM_SYSCALL_SOL_CURVE_ADD,
      in0_vaddr,
      in1_vaddr,
      result_point_vaddr,
      FD_VM_SYSCALL_SOL_CURVE_BLS12_381_G1_POINT_SZ, // result_sz
      0UL, // ret_code
      FD_VM_SUCCESS, // syscall_ret
      expected_result_host_ptr
    ) );
  }

  {
    uchar compressed[ FD_VM_SYSCALL_SOL_CURVE_BLS12_381_G1_COMPRESSED_SZ ];
    fd_hex_decode( compressed, "dadeb9267a9864e5a4379ef08a3b6f4bf48e5a6e80d5896c6a07190c46e672876fbd02c13a468f719abc608e44f59faf", FD_VM_SYSCALL_SOL_CURVE_BLS12_381_G1_COMPRESSED_SZ );

    uchar expected[ FD_VM_SYSCALL_SOL_CURVE_BLS12_381_G1_POINT_SZ ];
    fd_hex_decode( expected, "dadeb9267a9864e5a4379ef08a3b6f4bf48e5a6e80d5896c6a07190c46e672876fbd02c13a468f719abc608e44f59f0f3a7b32648787e478caf1abf65f6b043ac82933a8eda04fb8351bc175f4b51f9efa0a682c55076d92eaa2233ef6014f12", FD_VM_SYSCALL_SOL_CURVE_BLS12_381_G1_POINT_SZ );

    ulong point_off = vm->heap_max - FD_VM_SYSCALL_SOL_CURVE_BLS12_381_G1_COMPRESSED_SZ;
    memcpy( &vm->heap[ point_off ], compressed, FD_VM_SYSCALL_SOL_CURVE_BLS12_381_G1_COMPRESSED_SZ );

    FD_TEST( test_fd_vm_syscall_sol_curve_decompress(
      "fd_vm_syscall_sol_curve_decompress: bls12-381 g1, compressed input at heap end",
      vm,
      FD_VM_SYSCALL_SOL_CURVE_BLS12_381_G1_LE,
      FD_VM_MEM_MAP_HEAP_REGION_START + point_off,
      FD_VM_MEM_MAP_HEAP_REGION_START,
      FD_VM_SYSCALL_SOL_CURVE_BLS12_381_G1_POINT_SZ,
      0UL, /* ret_code */
      FD_VM_SUCCESS, /* syscall_ret */
      expected
    ) );
  }

  {
    uchar compressed[ FD_VM_SYSCALL_SOL_CURVE_BLS12_381_G2_COMPRESSED_SZ ];
    fd_hex_decode( compressed, "6ff24e70ff109bcf1fdeb647afd8251087bc605685240b6fa3c4be73023b8fd3120f49acb6e0bae733a76a6f3baa181768c33027df47696fb3b9ee79d10dde7dd130e8adfb40f93589872a4a6a0b8992accd4ab39268238be4049828dc126a8f", FD_VM_SYSCALL_SOL_CURVE_BLS12_381_G2_COMPRESSED_SZ );

    uchar expected[ FD_VM_SYSCALL_SOL_CURVE_BLS12_381_G2_POINT_SZ ];
    fd_hex_decode( expected, "6ff24e70ff109bcf1fdeb647afd8251087bc605685240b6fa3c4be73023b8fd3120f49acb6e0bae733a76a6f3baa181768c33027df47696fb3b9ee79d10dde7dd130e8adfb40f93589872a4a6a0b8992accd4ab39268238be4049828dc126a0f0537997d0bd6a8ea4076cd4bb2686bc0e0bb78807963ab0c1594c49057d94d38bf40b06a0f1fbb6cdb9f55aafb6f3b0d90ce38a4d6205c92ffae784a9df66fb2e40d394ab06093fd545c1b7a7e9f455f9d8255c776b7cdaba8b66fc953f4d90b", FD_VM_SYSCALL_SOL_CURVE_BLS12_381_G2_POINT_SZ );

    ulong point_off = vm->heap_max - FD_VM_SYSCALL_SOL_CURVE_BLS12_381_G2_COMPRESSED_SZ;
    memcpy( &vm->heap[ point_off ], compressed, FD_VM_SYSCALL_SOL_CURVE_BLS12_381_G2_COMPRESSED_SZ );

    FD_TEST( test_fd_vm_syscall_sol_curve_decompress(
      "fd_vm_syscall_sol_curve_decompress: bls12-381 g2, compressed input at heap end",
      vm,
      FD_VM_SYSCALL_SOL_CURVE_BLS12_381_G2_LE,
      FD_VM_MEM_MAP_HEAP_REGION_START + point_off,
      FD_VM_MEM_MAP_HEAP_REGION_START,
      FD_VM_SYSCALL_SOL_CURVE_BLS12_381_G2_POINT_SZ,
      0UL, /* ret_code */
      FD_VM_SUCCESS, /* syscall_ret */
      expected
    ) );
  }

  /* Test: sol_curve_pairing_map with num_pairs=0, NULL g1/g2 pointers.
     This must succeed and write the GT identity to the result buffer.
     Regression test for zero-pair BLS12-381 pairing divergence. */
  {
    ulong gt_sz = FD_VM_SYSCALL_SOL_CURVE_BLS12_381_GT_ELE_SZ; /* 576 */
    ulong result_off = 0UL;
    memset( &vm->heap[ result_off ], 0xAA, gt_sz );

    ulong result_vaddr = FD_VM_MEM_MAP_HEAP_REGION_START + result_off;

    vm->cu = FD_VM_COMPUTE_UNIT_LIMIT;

    int syscall_ret = fd_vm_syscall_sol_curve_pairing_map(
      (void *)vm,
      FD_VM_SYSCALL_SOL_CURVE_BLS12_381_LE,
      0UL,            /* num_pairs = 0 */
      0UL,            /* g1_points_addr = NULL */
      0UL,            /* g2_points_addr = NULL */
      result_vaddr
    );
    FD_TEST( syscall_ret == FD_VM_SUCCESS );
    FD_TEST( vm->reg[0]  == 0UL );

    /* Verify the GT identity was written (little-endian encoding of 1 in Fp12:
       first 48 bytes = 1 LE, remaining 528 bytes = 0). */
    uchar const * result_host = (uchar const *)FD_VM_MEM_HADDR_LD( vm, result_vaddr, 1, gt_sz );
    FD_TEST( result_host[0] == 1 );
    for( ulong i=1UL; i<gt_sz; i++ ) {
      FD_TEST( result_host[i] == 0 );
    }

    FD_LOG_NOTICE(( "Passed test program (sol_curve_pairing_map: bls12-381 zero pairs, LE)" ));
    test_vm_clear_txn_ctx_err( vm->instr_ctx->txn_out );
  }

  /* Same test but big-endian. */
  {
    ulong gt_sz = FD_VM_SYSCALL_SOL_CURVE_BLS12_381_GT_ELE_SZ;
    ulong result_off = 0UL;
    memset( &vm->heap[ result_off ], 0xAA, gt_sz );

    ulong result_vaddr = FD_VM_MEM_MAP_HEAP_REGION_START + result_off;

    vm->cu = FD_VM_COMPUTE_UNIT_LIMIT;

    int syscall_ret = fd_vm_syscall_sol_curve_pairing_map(
      (void *)vm,
      FD_VM_SYSCALL_SOL_CURVE_BLS12_381_BE,
      0UL,            /* num_pairs = 0 */
      0UL,            /* g1_points_addr = NULL */
      0UL,            /* g2_points_addr = NULL */
      result_vaddr
    );
    FD_TEST( syscall_ret == FD_VM_SUCCESS );
    FD_TEST( vm->reg[0]  == 0UL );

    /* Big-endian GT identity: the "1" Fp element is serialized at the
       end of the buffer (offset 48*11), as BE Fp: 47 zero bytes then 0x01.
       So byte [575] == 1, everything else == 0. */
    uchar const * result_host = (uchar const *)FD_VM_MEM_HADDR_LD( vm, result_vaddr, 1, gt_sz );
    for( ulong i=0UL; i<gt_sz-1UL; i++ ) {
      FD_TEST( result_host[i] == 0 );
    }
    FD_TEST( result_host[gt_sz-1UL] == 1 );

    FD_LOG_NOTICE(( "Passed test program (sol_curve_pairing_map: bls12-381 zero pairs, BE)" ));
    test_vm_clear_txn_ctx_err( vm->instr_ctx->txn_out );
  }


  /* secp256r1, test vectors from agave test_syscall_secp256r1_*.
     LE vectors are the BE ones with each 32-byte coordinate / scalar reversed. */
  {
    struct {
      ulong        curve_id;
      char const * p;            /* valid point */
      char const * p_invalid;    /* p with y+1, off curve */
      char const * p_compressed;
      char const * q;
      char const * p_add_q;
      char const * p_sub_q;
      char const * a;            /* scalar */
      char const * a_p;
      char const * b;            /* scalar */
      char const * a_p_add_b_q;
      char const * n;            /* group order, smallest invalid scalar */
    } const tests[2] = {
      {
        FD_VM_SYSCALL_SOL_CURVE_SECP256R1_BE,
        "e35eb19eb79db78851fa937af739a7e674a8922fd892fe8790a020b62694aed643b52bb88b2286ee58c56943f42d6fa06bcd63a78469f992c29ea3451b8de5ca",
        "e35eb19eb79db78851fa937af739a7e674a8922fd892fe8790a020b62694aed643b52bb88b2286ee58c56943f42d6fa06bcd63a78469f992c29ea3451b8de5cb",
        "02e35eb19eb79db78851fa937af739a7e674a8922fd892fe8790a020b62694aed6",
        "13536a4e32c9b408faf7ebc3fc6c3605c2271446b6e5a8ac81f23538afe81a43e4027ed5953d6050fa565e91f5146140f76a3bad9cec1bacc02d0577ebaaf0cb",
        "4fb14d7db13b3053b4cc66d97201104a418ec9178505b8d0f201c4376555b70e35b8e8c7081c9b317d846bf639f379f1639d0ee7bf61cc9e556b91d0a70a811c",
        "9ced1bbacc5a58b329ee0721c770d1105ca7a8b690f5033343dd8e3b82f06004daec98afebb934d2e9cd722d41ad9673f58809e28cd6115fa851752b1d7d48fe",
        "7b4b57f1a31ed9636c806712a9bd03bc8364dd9a404592c0937ef48aa174a36a",
        "a04a6c74523cb2e3776e35d87f4b914a23dcd05105606b39b4eaa54a1eb01f53b86987a384e67ddda648e85c83723473098f5a24a22734aa53e8bc68435706e2",
        "492fa2b5748bf18b880ed104dd0483321f53f87d63da7125d4120ab008539adb",
        "18995d3bb393b818d06284894ab0b8d7ff5aaf8188fb46bcc589f8ef2f4f45c1fc94d7cbe3897979b4f600da0c66c72d28d880e7d913b3395e9671e85df63cb1",
        "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551",
      },
      {
        FD_VM_SYSCALL_SOL_CURVE_SECP256R1_LE,
        "d6ae9426b620a09087fe92d82f92a874e6a739f77a93fa5188b79db79eb15ee3cae58d1b45a39ec292f96984a763cd6ba06f2df44369c558ee86228bb82bb543",
        "d6ae9426b620a09087fe92d82f92a874e6a739f77a93fa5188b79db79eb15ee3cbe58d1b45a39ec292f96984a763cd6ba06f2df44369c558ee86228bb82bb543",
        "02d6ae9426b620a09087fe92d82f92a874e6a739f77a93fa5188b79db79eb15ee3",
        "431ae8af3835f281aca8e5b6461427c205366cfcc3ebf7fa08b4c9324e6a5313cbf0aaeb77052dc0ac1bec9cad3b6af7406114f5915e56fa50603d95d57e02e4",
        "0eb7556537c401f2d0b8058517c98e414a100172d966ccb453303bb17d4db14f1c810aa7d0916b559ecc61bfe70e9d63f179f339f66b847d319b1c08c7e8b835",
        "0460f0823b8edd433303f590b6a8a75c10d170c72107ee29b3585accba1bed9cfe487d1d2b7551a85f11d68ce20988f57396ad412d72cde9d234b9ebaf98ecda",
        "6aa374a18af47e93c09245409add6483bc03bda91267806c63d91ea3f1574b7b",
        "531fb01e4aa5eab4396b600551d0dc234a914b7fd8356e77e3b23c52746c4aa0e206574368bce853aa3427a2245a8f09733472835ce848a6dd7de684a38769b8",
        "db9a5308b00a12d42571da637df8531f328304dd04d10e888bf18b74b5a22f49",
        "c1454f2feff889c5bc46fb8881af5affd7b8b04a898462d018b893b33b5d9918b13cf65de871965e39b313d9e780d8282dc7660cda00f6b4797989e3cbd794fc",
        "512563fcc2cab9f3849e17a7adfae6bcffffffffffffffff00000000ffffffff",
      },
    };

    ulong const point_sz      = FD_VM_SYSCALL_SOL_CURVE_SECP256R1_POINT_SZ;
    ulong const compressed_sz = FD_VM_SYSCALL_SOL_CURVE_SECP256R1_COMPRESSED_SZ;
    ulong const scalar_sz     = FD_VM_SYSCALL_SOL_CURVE_SECP256R1_SCALAR_SZ;

    /* heap layout */
    ulong const p_off          = 0UL;
    ulong const q_off          = p_off          + point_sz;
    ulong const p_invalid_off  = q_off          + point_sz;
    ulong const p_compr_off    = p_invalid_off  + point_sz;
    ulong const a_off          = p_compr_off    + point_sz;   /* a || b, msm scalars */
    ulong const b_off          = a_off          + scalar_sz;
    ulong const a2_off         = b_off          + scalar_sz;  /* a || n, invalid msm scalars */
    ulong const n_off          = a2_off         + scalar_sz;
    ulong const result_off     = n_off          + scalar_sz;
    ulong const heap_start     = FD_VM_MEM_MAP_HEAP_REGION_START;

    for( ulong i=0UL; i<2UL; i++ ) {
      ulong curve_id = tests[i].curve_id;
      char const * name = i==0UL ? "be" : "le";

      fd_hex_decode( &vm->heap[ p_off ],         tests[i].p,            point_sz );
      fd_hex_decode( &vm->heap[ q_off ],         tests[i].q,            point_sz );
      fd_hex_decode( &vm->heap[ p_invalid_off ], tests[i].p_invalid,    point_sz );
      fd_hex_decode( &vm->heap[ p_compr_off ],   tests[i].p_compressed, compressed_sz );
      fd_hex_decode( &vm->heap[ a_off ],         tests[i].a,            scalar_sz );
      fd_hex_decode( &vm->heap[ b_off ],         tests[i].b,            scalar_sz );
      fd_hex_decode( &vm->heap[ a2_off ],        tests[i].a,            scalar_sz );
      fd_hex_decode( &vm->heap[ n_off ],         tests[i].n,            scalar_sz );

      uchar expected[ 64 ];
      uchar * result = &vm->heap[ result_off ];

      /* validate */
      vm->cu = 2UL*FD_VM_CURVE_SECP256R1_VALIDATE_COST;
      FD_TEST( fd_vm_syscall_sol_curve_validate_point( vm, curve_id, heap_start+p_off, 0UL, 0UL, 0UL )==FD_VM_SUCCESS );
      FD_TEST( vm->reg[0]==0UL );
      FD_TEST( fd_vm_syscall_sol_curve_validate_point( vm, curve_id, heap_start+p_invalid_off, 0UL, 0UL, 0UL )==FD_VM_SUCCESS );
      FD_TEST( vm->reg[0]==1UL );
      FD_TEST( fd_vm_syscall_sol_curve_validate_point( vm, curve_id, heap_start+p_off, 0UL, 0UL, 0UL )==FD_VM_SYSCALL_ERR_COMPUTE_BUDGET_EXCEEDED );
      test_vm_clear_txn_ctx_err( vm->instr_ctx->txn_out );
      FD_LOG_NOTICE(( "Passed test program (fd_vm_syscall_sol_curve_validate_point: secp256r1 %s)", name ));

      /* decompress */
      vm->cu = FD_VM_CURVE_SECP256R1_DECOMPRESS_COST;
      fd_hex_decode( expected, tests[i].p, point_sz );
      FD_TEST( test_fd_vm_syscall_sol_curve_decompress(
        "fd_vm_syscall_sol_curve_decompress: secp256r1",
        vm, curve_id, heap_start+p_compr_off, heap_start+result_off, point_sz,
        0UL, FD_VM_SUCCESS, expected ) );
      FD_TEST( fd_vm_syscall_sol_curve_decompress( vm, curve_id, heap_start+p_compr_off, heap_start+result_off, 0UL, 0UL )==FD_VM_SYSCALL_ERR_COMPUTE_BUDGET_EXCEEDED );
      test_vm_clear_txn_ctx_err( vm->instr_ctx->txn_out );

      /* add */
      vm->cu = FD_VM_CURVE_SECP256R1_ADD_COST;
      fd_hex_decode( expected, tests[i].p_add_q, point_sz );
      FD_TEST( test_fd_vm_syscall_sol_curve_group_op(
        "fd_vm_syscall_sol_curve_group_op: secp256r1, add",
        vm, curve_id, FD_VM_SYSCALL_SOL_CURVE_ADD, heap_start+p_off, heap_start+q_off, heap_start+result_off, point_sz,
        0UL, FD_VM_SUCCESS, expected ) );
      FD_TEST( test_fd_vm_syscall_sol_curve_group_op(
        "fd_vm_syscall_sol_curve_group_op: secp256r1, add, out of cu",
        vm, curve_id, FD_VM_SYSCALL_SOL_CURVE_ADD, heap_start+p_off, heap_start+q_off, heap_start+result_off, point_sz,
        0UL, FD_VM_SYSCALL_ERR_COMPUTE_BUDGET_EXCEEDED, expected ) );

      /* sub */
      vm->cu = FD_VM_CURVE_SECP256R1_SUB_COST;
      fd_hex_decode( expected, tests[i].p_sub_q, point_sz );
      FD_TEST( test_fd_vm_syscall_sol_curve_group_op(
        "fd_vm_syscall_sol_curve_group_op: secp256r1, sub",
        vm, curve_id, FD_VM_SYSCALL_SOL_CURVE_SUB, heap_start+p_off, heap_start+q_off, heap_start+result_off, point_sz,
        0UL, FD_VM_SUCCESS, expected ) );
      FD_TEST( test_fd_vm_syscall_sol_curve_group_op(
        "fd_vm_syscall_sol_curve_group_op: secp256r1, sub, out of cu",
        vm, curve_id, FD_VM_SYSCALL_SOL_CURVE_SUB, heap_start+p_off, heap_start+q_off, heap_start+result_off, point_sz,
        0UL, FD_VM_SYSCALL_ERR_COMPUTE_BUDGET_EXCEEDED, expected ) );

      /* mul, then scalar n is rejected and leaves result untouched */
      vm->cu = 3UL*FD_VM_CURVE_SECP256R1_MUL_COST;
      fd_hex_decode( expected, tests[i].a_p, point_sz );
      FD_TEST( test_fd_vm_syscall_sol_curve_group_op(
        "fd_vm_syscall_sol_curve_group_op: secp256r1, mul",
        vm, curve_id, FD_VM_SYSCALL_SOL_CURVE_MUL, heap_start+a_off, heap_start+p_off, heap_start+result_off, point_sz,
        0UL, FD_VM_SUCCESS, expected ) );
      FD_TEST( test_fd_vm_syscall_sol_curve_group_op(
        "fd_vm_syscall_sol_curve_group_op: secp256r1, mul, scalar n",
        vm, curve_id, FD_VM_SYSCALL_SOL_CURVE_MUL, heap_start+n_off, heap_start+p_off, heap_start+result_off, point_sz,
        1UL, FD_VM_SUCCESS, expected ) );
      FD_TEST( memcmp( result, expected, point_sz )==0 );
      FD_TEST( test_fd_vm_syscall_sol_curve_group_op(
        "fd_vm_syscall_sol_curve_group_op: secp256r1, mul, invalid point",
        vm, curve_id, FD_VM_SYSCALL_SOL_CURVE_MUL, heap_start+a_off, heap_start+p_invalid_off, heap_start+result_off, point_sz,
        1UL, FD_VM_SUCCESS, expected ) );
      FD_TEST( memcmp( result, expected, point_sz )==0 );
      FD_TEST( test_fd_vm_syscall_sol_curve_group_op(
        "fd_vm_syscall_sol_curve_group_op: secp256r1, mul, out of cu",
        vm, curve_id, FD_VM_SYSCALL_SOL_CURVE_MUL, heap_start+a_off, heap_start+p_off, heap_start+result_off, point_sz,
        0UL, FD_VM_SYSCALL_ERR_COMPUTE_BUDGET_EXCEEDED, expected ) );

      /* msm, then scalar n is rejected and leaves result untouched */
      ulong msm_cost = FD_VM_CURVE_SECP256R1_MSM_BASE_COST + FD_VM_CURVE_SECP256R1_MSM_INCREMENTAL_COST;
      vm->cu = 2UL*msm_cost;
      fd_hex_decode( expected, tests[i].a_p_add_b_q, point_sz );
      FD_TEST( test_vm_syscall_sol_curve_multiscalar_mul(
        "test_vm_syscall_sol_curve_multiscalar_mul: secp256r1",
        vm, curve_id, heap_start+a_off, heap_start+p_off, 2UL, heap_start+result_off, point_sz,
        0UL, FD_VM_SUCCESS, expected ) );
      FD_TEST( test_vm_syscall_sol_curve_multiscalar_mul(
        "test_vm_syscall_sol_curve_multiscalar_mul: secp256r1, scalar n",
        vm, curve_id, heap_start+a2_off, heap_start+p_off, 2UL, heap_start+result_off, point_sz,
        1UL, FD_VM_SUCCESS, expected ) );
      FD_TEST( memcmp( result, expected, point_sz )==0 );
      FD_TEST( test_vm_syscall_sol_curve_multiscalar_mul(
        "test_vm_syscall_sol_curve_multiscalar_mul: secp256r1, out of cu",
        vm, curve_id, heap_start+a_off, heap_start+p_off, 2UL, heap_start+result_off, point_sz,
        0UL, FD_VM_SYSCALL_ERR_COMPUTE_BUDGET_EXCEEDED, expected ) );

      /* msm with 0 points is the point at infinity */
      vm->cu = FD_VM_COMPUTE_UNIT_LIMIT;
      memset( expected, 0, point_sz );
      FD_TEST( test_vm_syscall_sol_curve_multiscalar_mul(
        "test_vm_syscall_sol_curve_multiscalar_mul: secp256r1, 0 points",
        vm, curve_id, 0UL, 0UL, 0UL, heap_start+result_off, point_sz,
        0UL, FD_VM_SUCCESS, expected ) );

      /* feature disabled */
      bank->f.features.secp256r1_syscall_enabled = FD_FEATURE_DISABLED;
      FD_TEST( fd_vm_syscall_sol_curve_validate_point( vm, curve_id, 0UL, 0UL, 0UL, 0UL )==FD_VM_SYSCALL_ERR_INVALID_ATTRIBUTE );
      test_vm_clear_txn_ctx_err( vm->instr_ctx->txn_out );
      FD_TEST( fd_vm_syscall_sol_curve_decompress( vm, curve_id, 0UL, 0UL, 0UL, 0UL )==FD_VM_SYSCALL_ERR_INVALID_ATTRIBUTE );
      test_vm_clear_txn_ctx_err( vm->instr_ctx->txn_out );
      FD_TEST( fd_vm_syscall_sol_curve_group_op( vm, curve_id, FD_VM_SYSCALL_SOL_CURVE_ADD, 0UL, 0UL, 0UL )==FD_VM_SYSCALL_ERR_INVALID_ATTRIBUTE );
      test_vm_clear_txn_ctx_err( vm->instr_ctx->txn_out );
      FD_TEST( fd_vm_syscall_sol_curve_multiscalar_mul( vm, curve_id, 0UL, 0UL, 1UL, 0UL )==FD_VM_SYSCALL_ERR_INVALID_ATTRIBUTE );
      test_vm_clear_txn_ctx_err( vm->instr_ctx->txn_out );
      bank->f.features.secp256r1_syscall_enabled = 0UL;
      FD_LOG_NOTICE(( "Passed test program (secp256r1 %s, feature disabled)", name ));
    }
  }

  fd_vm_delete    ( fd_vm_leave    ( vm  ) );
  fd_sha256_delete( fd_sha256_leave( sha ) );
  fd_rng_delete   ( fd_rng_leave   ( rng ) );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
}
