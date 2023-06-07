#include "../fd_tests.h"
int test_1475(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 80,29,123,2,76,114,122,127,33,89,61,124,111,77,120,87,62,116,118,113,26,112,110,78,83,30,117,55,109,126,92,56,103,121,125,108,15,24,75,90,105,98,128,27,106,79,82 };
  test.disable_feature = disabled_features;
  test.test_name = "tests::test_bpf_loader_finalize";
  test.test_nonce  = 21;
  test.test_number = 1475;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 1;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111112uFcGnkfwYRy55mCjhxGKsMaZTDbToAqFfV",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "BPFLoader2111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 16871040UL;
  test_acc->result_lamports = 16871040UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1475_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1475_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1475_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1475_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "BPFLoader2111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1475_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1475_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1476(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 80,29,123,2,76,114,122,127,33,89,61,124,111,77,120,87,62,116,118,113,26,112,110,78,83,30,117,55,109,126,92,56,103,121,125,108,15,24,75,90,105,98,128,27,106,79,82 };
  test.disable_feature = disabled_features;
  test.test_name = "tests::test_bpf_loader_finalize";
  test.test_nonce  = 2;
  test.test_number = 1476;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 1;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111112uFcGnkfwYRy55mCjhxGKsMaZTDbToAqFfV",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "BPFLoader2111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 16871040UL;
  test_acc->result_lamports = 16871040UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1476_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1476_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1476_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1476_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "BPFLoader2111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1476_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1476_raw_sz;
  test.expected_result = -8;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1477(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 80,29,123,2,76,114,122,127,33,89,61,124,111,77,120,87,62,116,118,113,26,112,110,78,83,30,117,55,109,126,92,56,103,121,125,108,15,24,75,90,105,98,128,27,106,79,82 };
  test.disable_feature = disabled_features;
  test.test_name = "tests::test_bpf_loader_finalize";
  test.test_nonce  = 31;
  test.test_number = 1477;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 1;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111112uFcGnkfwYRy55mCjhxGKsMaZTDbToAqFfV",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "BPFLoader2111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 16871040UL;
  test_acc->result_lamports = 16871040UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1477_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1477_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1477_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1477_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "BPFLoader2111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1477_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1477_raw_sz;
  test.expected_result = -4;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1478(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 108,62,33,113,106,29,128,2,122,105,127,56,27,92,98,87,24,114,117,109,126,80,124,116,118,78,110,90,79,103,30,121,82,75,120,83,61,123,77,76,26,15,89,125,112,111,55 };
  test.disable_feature = disabled_features;
  test.test_name = "tests::test_bpf_loader_invoke_main";
  test.test_nonce  = 56;
  test.test_number = 1478;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 1;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111112trGfoeNeqFWCGL4egXw1PEJmpiLX5wFRM9",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "BPFLoader2111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 16871040UL;
  test_acc->result_lamports = 16871040UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1478_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1478_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1478_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1478_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "BPFLoader2111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1478_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1478_raw_sz;
  test.expected_result = -7;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1479(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 90,116,111,114,26,61,110,89,27,121,120,118,122,79,105,78,82,29,108,128,117,98,2,55,75,106,127,24,77,126,62,112,92,80,15,87,30,124,33,56,123,83,125,113,109,76,103 };
  test.disable_feature = disabled_features;
  test.test_name = "tests::test_bpf_loader_invoke_main";
  test.test_nonce  = 34;
  test.test_number = 1479;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 1;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111112trGfoeNeqFWCGL4egXw1PEJmpiLX5wFRM9",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "BPFLoader2111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 16871040UL;
  test_acc->result_lamports = 16871040UL;
  test_acc->executable      = 1;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1479_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1479_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1479_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1479_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "BPFLoader2111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1479_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1479_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1480(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 124,121,103,87,62,123,127,92,80,27,109,118,33,111,117,83,82,128,106,2,122,15,113,77,26,61,56,126,55,125,105,98,120,108,75,24,30,112,89,79,29,110,78,116,90,76,114 };
  test.disable_feature = disabled_features;
  test.test_name = "tests::test_bpf_loader_invoke_main";
  test.test_nonce  = 46;
  test.test_number = 1480;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 2;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111112trGfoeNeqFWCGL4egXw1PEJmpiLX5wFRM9",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "BPFLoader2111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 16871040UL;
  test_acc->result_lamports = 16871040UL;
  test_acc->executable      = 1;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1480_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1480_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1480_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1480_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111112uewsmryEFcRwuCLpjNbeMUrM5irQWQR5yq",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "BPFLoader2111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1480_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1480_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1480_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1480_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "BPFLoader2111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1480_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1480_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1481(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 62,83,125,106,113,111,121,105,75,33,118,117,78,90,109,27,76,15,127,123,114,30,124,29,77,120,103,26,92,126,55,108,116,79,122,80,61,110,56,82,2,98,87,89,112,128,24 };
  test.disable_feature = disabled_features;
  test.test_name = "tests::test_bpf_loader_invoke_main";
  test.test_nonce  = 54;
  test.test_number = 1481;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 1;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111112trGfoeNeqFWCGL4egXw1PEJmpiLX5wFRM9",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "BPFLoader2111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 16871040UL;
  test_acc->result_lamports = 16871040UL;
  test_acc->executable      = 1;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1481_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1481_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1481_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1481_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "BPFLoader2111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1481_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1481_raw_sz;
  test.expected_result = -41;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1482(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 80,111,118,77,55,33,108,105,114,110,112,98,126,56,87,122,26,62,121,61,117,24,79,30,106,27,123,113,89,2,15,116,82,128,90,120,75,83,125,109,103,78,76,92,29,127,124 };
  test.disable_feature = disabled_features;
  test.test_name = "tests::test_bpf_loader_invoke_main";
  test.test_nonce  = 0;
  test.test_number = 1482;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 0;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_base58_decode_32( "BPFLoader2111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1482_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1482_raw_sz;
  test.expected_result = -20;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1483(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 30,116,127,117,82,118,111,29,26,79,112,128,83,62,106,89,27,114,109,61,33,56,75,122,125,110,121,105,78,24,124,108,126,98,90,77,120,103,113,92,2,123,76,55,15,87,80 };
  test.disable_feature = disabled_features;
  test.test_name = "tests::test_bpf_loader_invoke_main";
  test.test_nonce  = 51;
  test.test_number = 1483;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 2;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111112trGfoeNeqFWCGL4egXw1PEJmpiLX5wFRM9",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "BPFLoader2111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 16871040UL;
  test_acc->result_lamports = 16871040UL;
  test_acc->executable      = 1;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1483_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1483_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1483_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1483_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111112uewsmryEFcRwuCLpjNbeMUrM5irQWQR5yq",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "BPFLoader2111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1483_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1483_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1483_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1483_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "BPFLoader2111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1483_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1483_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1484(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 30,116,127,117,82,118,111,29,26,79,112,128,83,62,106,89,27,114,109,61,33,56,75,122,125,110,121,105,78,24,124,108,126,98,90,77,120,103,113,92,2,123,76,55,15,87,80 };
  test.disable_feature = disabled_features;
  test.test_name = "tests::test_bpf_loader_invoke_main";
  test.test_nonce  = 0;
  test.test_number = 1484;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 0;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_base58_decode_32( "BPFLoader2111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1484_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1484_raw_sz;
  test.expected_result = -20;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1485(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 30,116,127,117,82,118,111,29,26,79,112,128,83,62,106,89,27,114,109,61,33,56,75,122,125,110,121,105,78,24,124,108,126,98,90,77,120,103,113,92,2,123,76,55,15,87,80 };
  test.disable_feature = disabled_features;
  test.test_name = "tests::test_bpf_loader_invoke_main";
  test.test_nonce  = 41;
  test.test_number = 1485;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 1;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111112uewsmryEFcRwuCLpjNbeMUrM5irQWQR5yq",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "BPFLoader2111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 16871040UL;
  test_acc->result_lamports = 16871040UL;
  test_acc->executable      = 1;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1485_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1485_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1485_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1485_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "BPFLoader2111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1485_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1485_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1486(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 30,116,127,117,82,118,111,29,26,79,112,128,83,62,106,89,27,114,109,61,33,56,75,122,125,110,121,105,78,24,124,108,126,98,90,77,120,103,113,92,2,123,76,55,15,87,80 };
  test.disable_feature = disabled_features;
  test.test_name = "tests::test_bpf_loader_invoke_main";
  test.test_nonce  = 47;
  test.test_number = 1486;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 2;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111112uewsmryEFcRwuCLpjNbeMUrM5irQWQR5yq",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "BPFLoader2111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 16871040UL;
  test_acc->result_lamports = 16871040UL;
  test_acc->executable      = 1;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1486_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1486_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1486_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1486_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111112vTd5k5ZofyMhY4cznDGHKjPvLjNHvsakcX",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "BPFLoader2111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1486_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1486_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1486_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1486_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "BPFLoader2111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1486_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1486_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1487(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 30,116,127,117,82,118,111,29,26,79,112,128,83,62,106,89,27,114,109,61,33,56,75,122,125,110,121,105,78,24,124,108,126,98,90,77,120,103,113,92,2,123,76,55,15,87,80 };
  test.disable_feature = disabled_features;
  test.test_name = "tests::test_bpf_loader_invoke_main";
  test.test_nonce  = 53;
  test.test_number = 1487;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 2;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111112uewsmryEFcRwuCLpjNbeMUrM5irQWQR5yq",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "BPFLoader2111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 16871040UL;
  test_acc->result_lamports = 16871040UL;
  test_acc->executable      = 1;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1487_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1487_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1487_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1487_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111112vTd5k5ZofyMhY4cznDGHKjPvLjNHvsakcX",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "BPFLoader2111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1487_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1487_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1487_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1487_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "BPFLoader2111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1487_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1487_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1488(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 30,116,127,117,82,118,111,29,26,79,112,128,83,62,106,89,27,114,109,61,33,56,75,122,125,110,121,105,78,24,124,108,126,98,90,77,120,103,113,92,2,123,76,55,15,87,80 };
  test.disable_feature = disabled_features;
  test.test_name = "tests::test_bpf_loader_invoke_main";
  test.test_nonce  = 58;
  test.test_number = 1488;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 1;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111112uewsmryEFcRwuCLpjNbeMUrM5irQWQR5yq",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "BPFLoader2111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 16871040UL;
  test_acc->result_lamports = 16871040UL;
  test_acc->executable      = 1;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1488_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1488_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1488_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1488_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "BPFLoader2111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1488_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1488_raw_sz;
  test.expected_result = -41;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1489(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 30,116,127,117,82,118,111,29,26,79,112,128,83,62,106,89,27,114,109,61,33,56,75,122,125,110,121,105,78,24,124,108,126,98,90,77,120,103,113,92,2,123,76,55,15,87,80 };
  test.disable_feature = disabled_features;
  test.test_name = "tests::test_bpf_loader_invoke_main";
  test.test_nonce  = 59;
  test.test_number = 1489;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 1;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111112uewsmryEFcRwuCLpjNbeMUrM5irQWQR5yq",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "BPFLoader2111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 16871040UL;
  test_acc->result_lamports = 16871040UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1489_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1489_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1489_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1489_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "BPFLoader2111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1489_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1489_raw_sz;
  test.expected_result = -7;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1490(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 26,126,55,80,83,89,121,30,79,125,117,109,62,92,77,90,2,110,116,128,120,111,106,108,112,98,118,76,123,61,114,33,75,78,29,82,15,113,105,127,124,122,24,27,56,103,87 };
  test.disable_feature = disabled_features;
  test.test_name = "tests::test_bpf_loader_serialize_aligned";
  test.test_nonce  = 37;
  test.test_number = 1490;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 2;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111112vrxgjBs6P9paMVm5odbborfhyEdEe7Aavs",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "BPFLoader2111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 16871040UL;
  test_acc->result_lamports = 16871040UL;
  test_acc->executable      = 1;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1490_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1490_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1490_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1490_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111112wfdthQTfoWkKzN3FrUGEn7DHEF984aLFZZ",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "BPFLoader2111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1490_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1490_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1490_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1490_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "BPFLoader2111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1490_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1490_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1491(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 62,106,56,30,123,105,33,80,2,118,108,76,126,128,127,79,82,125,27,112,78,98,75,113,55,15,24,110,103,26,114,109,77,87,90,124,92,117,116,89,121,111,120,122,61,83,29 };
  test.disable_feature = disabled_features;
  test.test_name = "tests::test_bpf_loader_serialize_aligned";
  test.test_nonce  = 48;
  test.test_number = 1491;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 2;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111112vrxgjBs6P9paMVm5odbborfhyEdEe7Aavs",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "BPFLoader2111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 16871040UL;
  test_acc->result_lamports = 16871040UL;
  test_acc->executable      = 1;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1491_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1491_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1491_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1491_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111112wfdthQTfoWkKzN3FrUGEn7DHEF984aLFZZ",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "BPFLoader2111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1491_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1491_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1491_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1491_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "BPFLoader2111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1491_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1491_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1492(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 62,106,56,30,123,105,33,80,2,118,108,76,126,128,127,79,82,125,27,112,78,98,75,113,55,15,24,110,103,26,114,109,77,87,90,124,92,117,116,89,121,111,120,122,61,83,29 };
  test.disable_feature = disabled_features;
  test.test_name = "tests::test_bpf_loader_serialize_aligned";
  test.test_nonce  = 42;
  test.test_number = 1492;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 2;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111112vrxgjBs6P9paMVm5odbborfhyEdEe7Aavs",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "BPFLoader2111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 16871040UL;
  test_acc->result_lamports = 16871040UL;
  test_acc->executable      = 1;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1492_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1492_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1492_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1492_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111112wfdthQTfoWkKzN3FrUGEn7DHEF984aLFZZ",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "BPFLoader2111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1492_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1492_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1492_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1492_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "BPFLoader2111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1492_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1492_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1493(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 62,106,56,30,123,105,33,80,2,118,108,76,126,128,127,79,82,125,27,112,78,98,75,113,55,15,24,110,103,26,114,109,77,87,90,124,92,117,116,89,121,111,120,122,61,83,29 };
  test.disable_feature = disabled_features;
  test.test_name = "tests::test_bpf_loader_serialize_aligned";
  test.test_nonce  = 49;
  test.test_number = 1493;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 2;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111112vrxgjBs6P9paMVm5odbborfhyEdEe7Aavs",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "BPFLoader2111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 16871040UL;
  test_acc->result_lamports = 16871040UL;
  test_acc->executable      = 1;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1493_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1493_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1493_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1493_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111112wfdthQTfoWkKzN3FrUGEn7DHEF984aLFZZ",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "BPFLoader2111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1493_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1493_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1493_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1493_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "BPFLoader2111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1493_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1493_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1494(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 123,75,92,105,114,109,106,24,103,27,108,110,90,121,116,117,98,126,76,127,124,87,120,62,128,82,2,122,118,30,33,77,83,78,113,55,56,26,111,112,79,61,80,29,125,89,15 };
  test.disable_feature = disabled_features;
  test.test_name = "tests::test_bpf_loader_serialize_unaligned";
  test.test_nonce  = 45;
  test.test_number = 1494;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 2;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111112yGzJdqepeEbqG6bbx9bWicJRkGAtuWfapw",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "BPFLoader1111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 16536960UL;
  test_acc->result_lamports = 16536960UL;
  test_acc->executable      = 1;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1494_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1494_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1494_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1494_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111112ztLiaGqyUxTLXq9x3pvnf7PaGHCfkSzv6K",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "BPFLoader1111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1494_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1494_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1494_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1494_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "BPFLoader1111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1494_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1494_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1495(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 117,118,122,83,108,89,90,24,79,56,92,33,113,30,103,124,29,77,87,105,126,76,55,128,112,61,111,114,75,127,120,116,62,26,98,121,2,27,123,78,15,106,110,80,125,109,82 };
  test.disable_feature = disabled_features;
  test.test_name = "tests::test_bpf_loader_serialize_unaligned";
  test.test_nonce  = 30;
  test.test_number = 1495;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 2;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111112yGzJdqepeEbqG6bbx9bWicJRkGAtuWfapw",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "BPFLoader1111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 16536960UL;
  test_acc->result_lamports = 16536960UL;
  test_acc->executable      = 1;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1495_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1495_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1495_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1495_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111112ztLiaGqyUxTLXq9x3pvnf7PaGHCfkSzv6K",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "BPFLoader1111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1495_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1495_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1495_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1495_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "BPFLoader1111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1495_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1495_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1496(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 117,118,122,83,108,89,90,24,79,56,92,33,113,30,103,124,29,77,87,105,126,76,55,128,112,61,111,114,75,127,120,116,62,26,98,121,2,27,123,78,15,106,110,80,125,109,82 };
  test.disable_feature = disabled_features;
  test.test_name = "tests::test_bpf_loader_serialize_unaligned";
  test.test_nonce  = 40;
  test.test_number = 1496;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 2;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111112x4yVgWkxWhDCooBLstbZGEV4rkQ4mov5su",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "BPFLoader1111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 16536960UL;
  test_acc->result_lamports = 16536960UL;
  test_acc->executable      = 1;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1496_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1496_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1496_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1496_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111112xsehejMXw48xSfTWvjGCEV2e7kuxCH5kWb",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "BPFLoader1111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1496_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1496_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1496_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1496_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "BPFLoader1111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1496_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1496_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1497(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 117,118,122,83,108,89,90,24,79,56,92,33,113,30,103,124,29,77,87,105,126,76,55,128,112,61,111,114,75,127,120,116,62,26,98,121,2,27,123,78,15,106,110,80,125,109,82 };
  test.disable_feature = disabled_features;
  test.test_name = "tests::test_bpf_loader_serialize_unaligned";
  test.test_nonce  = 46;
  test.test_number = 1497;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 2;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111112x4yVgWkxWhDCooBLstbZGEV4rkQ4mov5su",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "BPFLoader1111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 16536960UL;
  test_acc->result_lamports = 16536960UL;
  test_acc->executable      = 1;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1497_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1497_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1497_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1497_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111112xsehejMXw48xSfTWvjGCEV2e7kuxCH5kWb",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "BPFLoader1111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1497_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1497_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1497_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1497_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "BPFLoader1111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1497_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1497_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1498(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 105,29,125,61,116,15,89,112,109,82,87,118,108,122,111,127,128,113,76,33,24,120,103,80,114,56,83,90,126,30,110,92,106,2,79,75,27,124,26,78,123,98,55,121,62,77,117 };
  test.disable_feature = disabled_features;
  test.test_name = "tests::test_bpf_loader_upgradeable_close";
  test.test_nonce  = 31;
  test.test_number = 1498;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 2;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "11111131h1vYVSYuKP6AhS86fbRdMw9XHiZAvAaj1",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "BPFLoaderUpgradeab1e11111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1498_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1498_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1498_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1498_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "111111326MXXbjqcVqxz8aD85vk7VCw9nyVt9kR3M",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "BPFLoaderUpgradeab1e11111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 1;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1498_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1498_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1498_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1498_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "111111326MXXbjqcVqxz8aD85vk7VCw9nyVt9kR3M",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1498_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1498_raw_sz;
  test.expected_result = -4;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1499(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 105,29,125,61,116,15,89,112,109,82,87,118,108,122,111,127,128,113,76,33,24,120,103,80,114,56,83,90,126,30,110,92,106,2,79,75,27,124,26,78,123,98,55,121,62,77,117 };
  test.disable_feature = disabled_features;
  test.test_name = "tests::test_bpf_loader_upgradeable_close";
  test.test_nonce  = 32;
  test.test_number = 1499;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 2;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "11111132Vh8Wi38KgJqoZiJ9WG4bcUinJESbPLFMh",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "BPFLoaderUpgradeab1e11111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1499_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1499_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1499_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1499_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111132u2jVpLR2rmiczrPAvbP5jkWQoVPJcv5g3",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "BPFLoaderUpgradeab1e11111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 1;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1499_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1499_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1499_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1499_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111132u2jVpLR2rmiczrPAvbP5jkWQoVPJcv5g3",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1499_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1499_raw_sz;
  test.expected_result = -4;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
