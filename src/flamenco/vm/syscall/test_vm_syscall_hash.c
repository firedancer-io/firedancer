#include "fd_vm_syscall.h"
#include "../test_vm_util.h"
#include "../../runtime/fd_bank.h"

#include "../../../ballet/sha512/fd_sha512.h"
#include "../../../ballet/keccak256/fd_keccak256.h"

/* Generic test harness for all hash syscalls (sha256, keccak256, blake3, sha512).
   They all share the same interface and CU model; only the hash algo and
   output size differ. */

typedef struct {
  char const *           name;
  fd_sbpf_syscall_func_t syscall_fn;
  ulong                  hash_sz;
  uchar                  expected_empty[64];
  uchar                  expected_abc[64];
} hash_test_spec_t;

static void
test_hash_empty( fd_vm_t * vm, hash_test_spec_t const * spec ) {
  ulong result_offset = 0UL;
  memset( vm->heap + result_offset, 0xcc, spec->hash_sz );

  ulong ret = 0UL;
  int err = spec->syscall_fn( vm, 0UL, 0UL,
      FD_VM_MEM_MAP_HEAP_REGION_START + result_offset,
      0UL, 0UL, &ret );

  FD_TEST( err==FD_VM_SUCCESS );
  FD_TEST( ret==0UL );
  FD_TEST( !memcmp( vm->heap + result_offset, spec->expected_empty, spec->hash_sz ) );
  FD_LOG_NOTICE(( "Passed: %s empty input", spec->name ));
}

static void
test_hash_abc( fd_vm_t * vm, hash_test_spec_t const * spec ) {
  ulong data_offset   = 256UL;
  ulong vec_offset    = 128UL;
  ulong result_offset = 0UL;

  memcpy( vm->heap + data_offset, "abc", 3 );

  fd_vm_vec_t vec = {
    .addr = FD_VM_MEM_MAP_HEAP_REGION_START + data_offset,
    .len  = 3UL
  };
  memcpy( vm->heap + vec_offset, &vec, sizeof(fd_vm_vec_t) );

  memset( vm->heap + result_offset, 0xcc, spec->hash_sz );

  ulong ret = 0UL;
  int err = spec->syscall_fn( vm,
      FD_VM_MEM_MAP_HEAP_REGION_START + vec_offset,
      1UL,
      FD_VM_MEM_MAP_HEAP_REGION_START + result_offset,
      0UL, 0UL, &ret );

  FD_TEST( err==FD_VM_SUCCESS );
  FD_TEST( ret==0UL );
  FD_TEST( !memcmp( vm->heap + result_offset, spec->expected_abc, spec->hash_sz ) );
  FD_LOG_NOTICE(( "Passed: %s \"abc\"", spec->name ));
}

static void
test_hash_two_slices( fd_vm_t * vm, hash_test_spec_t const * spec ) {
  /* Hash "abc"+"def" via two slices, then verify by hashing "abc"+"def"
     as a single 1-slice call. */
  ulong data_offset1  = 256UL;
  ulong data_offset2  = 320UL;
  ulong vec_offset    = 128UL;
  ulong result_offset = 0UL;

  memcpy( vm->heap + data_offset1, "abc", 3 );
  memcpy( vm->heap + data_offset2, "def", 3 );

  fd_vm_vec_t vecs[2] = {
    { .addr = FD_VM_MEM_MAP_HEAP_REGION_START + data_offset1, .len = 3UL },
    { .addr = FD_VM_MEM_MAP_HEAP_REGION_START + data_offset2, .len = 3UL }
  };
  memcpy( vm->heap + vec_offset, vecs, sizeof(vecs) );

  memset( vm->heap + result_offset, 0xcc, spec->hash_sz );

  ulong ret = 0UL;
  int err = spec->syscall_fn( vm,
      FD_VM_MEM_MAP_HEAP_REGION_START + vec_offset,
      2UL,
      FD_VM_MEM_MAP_HEAP_REGION_START + result_offset,
      0UL, 0UL, &ret );

  FD_TEST( err==FD_VM_SUCCESS );
  FD_TEST( ret==0UL );

  /* Now hash "abcdef" as a single slice and compare */
  ulong data_offset_full = 384UL;
  ulong vec_offset2      = 448UL;
  ulong result_offset2   = 512UL;

  memcpy( vm->heap + data_offset_full, "abcdef", 6 );

  fd_vm_vec_t vec_full = {
    .addr = FD_VM_MEM_MAP_HEAP_REGION_START + data_offset_full,
    .len  = 6UL
  };
  memcpy( vm->heap + vec_offset2, &vec_full, sizeof(fd_vm_vec_t) );

  memset( vm->heap + result_offset2, 0xcc, spec->hash_sz );

  ulong ret2 = 0UL;
  int err2 = spec->syscall_fn( vm,
      FD_VM_MEM_MAP_HEAP_REGION_START + vec_offset2,
      1UL,
      FD_VM_MEM_MAP_HEAP_REGION_START + result_offset2,
      0UL, 0UL, &ret2 );

  FD_TEST( err2==FD_VM_SUCCESS );
  FD_TEST( ret2==0UL );
  FD_TEST( !memcmp( vm->heap + result_offset, vm->heap + result_offset2, spec->hash_sz ) );
  FD_LOG_NOTICE(( "Passed: %s two slices", spec->name ));
}

static void
test_hash_too_many_slices( fd_vm_t * vm, hash_test_spec_t const * spec ) {
  ulong result_offset = 0UL;
  memset( vm->heap + result_offset, 0xcc, spec->hash_sz );

  ulong ret = 0UL;
  int err = spec->syscall_fn( vm,
      0UL,
      FD_VM_SHA256_MAX_SLICES + 1UL,
      FD_VM_MEM_MAP_HEAP_REGION_START + result_offset,
      0UL, 0UL, &ret );

  FD_TEST( err==FD_VM_SYSCALL_ERR_TOO_MANY_SLICES );
  FD_LOG_NOTICE(( "Passed: %s too many slices", spec->name ));
}

static void
test_hash_all( fd_vm_t * vm, hash_test_spec_t const * spec ) {
  /* Reset CU budget before each hash function's test suite */
  vm->cu = FD_VM_COMPUTE_UNIT_LIMIT;
  test_hash_empty(           vm, spec );
  vm->cu = FD_VM_COMPUTE_UNIT_LIMIT;
  test_hash_abc(             vm, spec );
  vm->cu = FD_VM_COMPUTE_UNIT_LIMIT;
  test_hash_two_slices(      vm, spec );
  vm->cu = FD_VM_COMPUTE_UNIT_LIMIT;
  test_hash_too_many_slices( vm, spec );
  /* Clear error fields so the next hash function doesn't trip
     the FD_VM_TEST_ERR_OVERWRITE handholding assertion. */
  vm->instr_ctx->txn_out->err.exec_err      = 0;
  vm->instr_ctx->txn_out->err.exec_err_kind = 0;
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  char const * _page_sz = fd_env_strip_cmdline_cstr ( &argc, &argv, "--page-sz",  NULL, "gigantic"      );
  ulong        page_cnt = fd_env_strip_cmdline_ulong( &argc, &argv, "--page-cnt", NULL, 5UL             );
  ulong        near_cpu = fd_env_strip_cmdline_ulong( &argc, &argv, "--near-cpu", NULL, fd_log_cpu_id() );
  ulong        wksp_tag = fd_env_strip_cmdline_ulong( &argc, &argv, "--wksp-tag", NULL, 1234UL          );

  fd_wksp_t * wksp = fd_wksp_new_anonymous( fd_cstr_to_shmem_page_sz( _page_sz ), page_cnt, near_cpu, "wksp", 0UL );
  FD_TEST( wksp );

  fd_runtime_t * runtime = fd_wksp_alloc_laddr( wksp, alignof(fd_runtime_t), sizeof(fd_runtime_t), wksp_tag );
  FD_TEST( runtime );

  fd_sha256_t _sha[1];
  fd_sha256_t * sha = fd_sha256_join( fd_sha256_new( _sha ) );

  fd_vm_t _vm[1];
  fd_vm_t * vm = fd_vm_join( fd_vm_new( _vm ) );
  FD_TEST( vm );

  ulong const rodata_sz = 64UL;
  uchar rodata[ rodata_sz ];
  memset( rodata, 0, rodata_sz );

  static fd_exec_instr_ctx_t instr_ctx[1];
  static fd_bank_t           bank[1];
  static fd_txn_out_t        txn_out[1];
  static fd_log_collector_t  log_collector[1];
  runtime->log.log_collector = log_collector;
  test_vm_minimal_exec_instr_ctx( instr_ctx, runtime, bank, txn_out );

  /* Activate feature-gated syscalls */
  char const * feature_gates[] = {
    "HTW2pSyErTj4BV6KBM9NZ9VBUJVxt7sacNWcf76wtzb3",  /* blake3_syscall_enabled */
    "ToDo111111111111111111111111111111111111111",      /* enable_sha512_syscall  */
  };
  fd_features_enable_one_offs( &bank->f.features, feature_gates,
                               (uint)(sizeof(feature_gates)/sizeof(feature_gates[0])), 0UL );

  int vm_ok = !!fd_vm_init(
      vm, instr_ctx, FD_VM_HEAP_DEFAULT, FD_VM_COMPUTE_UNIT_LIMIT,
      rodata, rodata_sz, NULL, 0UL, 0UL, 0UL, 0UL, NULL,
      TEST_VM_DEFAULT_SBPF_VERSION, NULL, NULL, sha,
      NULL, 0U, NULL, 0,
      FD_FEATURE_ACTIVE_BANK( bank, account_data_direct_mapping ),
      FD_FEATURE_ACTIVE_BANK( bank, syscall_parameter_address_restrictions ),
      FD_FEATURE_ACTIVE_BANK( bank, virtual_address_space_adjustments ),
      0, 0UL );
  FD_TEST( vm_ok );

  /* Test specs: {name, fn, hash_sz, expected_empty, expected_abc} */

  hash_test_spec_t const specs[] = {
    { .name       = "sha256",
      .syscall_fn = fd_vm_syscall_sol_sha256,
      .hash_sz    = 32UL,
      .expected_empty = {
        0xe3,0xb0,0xc4,0x42,0x98,0xfc,0x1c,0x14,0x9a,0xfb,0xf4,0xc8,0x99,0x6f,0xb9,0x24,
        0x27,0xae,0x41,0xe4,0x64,0x9b,0x93,0x4c,0xa4,0x95,0x99,0x1b,0x78,0x52,0xb8,0x55 },
      .expected_abc = {
        0xba,0x78,0x16,0xbf,0x8f,0x01,0xcf,0xea,0x41,0x41,0x40,0xde,0x5d,0xae,0x22,0x23,
        0xb0,0x03,0x61,0xa3,0x96,0x17,0x7a,0x9c,0xb4,0x10,0xff,0x61,0xf2,0x00,0x15,0xad },
    },
    { .name       = "keccak256",
      .syscall_fn = fd_vm_syscall_sol_keccak256,
      .hash_sz    = 32UL,
      .expected_empty = {
        0xc5,0xd2,0x46,0x01,0x86,0xf7,0x23,0x3c,0x92,0x7e,0x7d,0xb2,0xdc,0xc7,0x03,0xc0,
        0xe5,0x00,0xb6,0x53,0xca,0x82,0x27,0x3b,0x7b,0xfa,0xd8,0x04,0x5d,0x85,0xa4,0x70 },
      .expected_abc = {
        0x4e,0x03,0x65,0x7a,0xea,0x45,0xa9,0x4f,0xc7,0xd4,0x7b,0xa8,0x26,0xc8,0xd6,0x67,
        0xc0,0xd1,0xe6,0xe3,0x3a,0x64,0xa0,0x36,0xec,0x44,0xf5,0x8f,0xa1,0x2d,0x6c,0x45 },
    },
    { .name       = "blake3",
      .syscall_fn = fd_vm_syscall_sol_blake3,
      .hash_sz    = 32UL,
      .expected_empty = {
        0xaf,0x13,0x49,0xb9,0xf5,0xf9,0xa1,0xa6,0xa0,0x40,0x4d,0xea,0x36,0xdc,0xc9,0x49,
        0x9b,0xcb,0x25,0xc9,0xad,0xc1,0x12,0xb7,0xcc,0x9a,0x93,0xca,0xe4,0x1f,0x32,0x62 },
      .expected_abc = {
        0x64,0x37,0xb3,0xac,0x38,0x46,0x51,0x33,0xff,0xb6,0x3b,0x75,0x27,0x3a,0x8d,0xb5,
        0x48,0xc5,0x58,0x46,0x5d,0x79,0xdb,0x03,0xfd,0x35,0x9c,0x6c,0xd5,0xbd,0x9d,0x85 },
    },
    { .name       = "sha512",
      .syscall_fn = fd_vm_syscall_sol_sha512,
      .hash_sz    = 64UL,
      .expected_empty = {
        0xcf,0x83,0xe1,0x35,0x7e,0xef,0xb8,0xbd,0xf1,0x54,0x28,0x50,0xd6,0x6d,0x80,0x07,
        0xd6,0x20,0xe4,0x05,0x0b,0x57,0x15,0xdc,0x83,0xf4,0xa9,0x21,0xd3,0x6c,0xe9,0xce,
        0x47,0xd0,0xd1,0x3c,0x5d,0x85,0xf2,0xb0,0xff,0x83,0x18,0xd2,0x87,0x7e,0xec,0x2f,
        0x63,0xb9,0x31,0xbd,0x47,0x41,0x7a,0x81,0xa5,0x38,0x32,0x7a,0xf9,0x27,0xda,0x3e },
      .expected_abc = {
        0xdd,0xaf,0x35,0xa1,0x93,0x61,0x7a,0xba,0xcc,0x41,0x73,0x49,0xae,0x20,0x41,0x31,
        0x12,0xe6,0xfa,0x4e,0x89,0xa9,0x7e,0xa2,0x0a,0x9e,0xee,0xe6,0x4b,0x55,0xd3,0x9a,
        0x21,0x92,0x99,0x2a,0x27,0x4f,0xc1,0xa8,0x36,0xba,0x3c,0x23,0xa3,0xfe,0xeb,0xbd,
        0x45,0x4d,0x44,0x23,0x64,0x3c,0xe8,0x0e,0x2a,0x9a,0xc9,0x4f,0xa5,0x4c,0xa4,0x9f },
    },
  };

  ulong spec_cnt = sizeof(specs) / sizeof(specs[0]);
  for( ulong i=0UL; i<spec_cnt; i++ ) {
    FD_LOG_NOTICE(( "--- Testing %s ---", specs[i].name ));
    test_hash_all( vm, &specs[i] );
  }

  fd_vm_delete    ( fd_vm_leave    ( vm  ) );
  fd_sha256_delete( fd_sha256_leave( sha ) );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
