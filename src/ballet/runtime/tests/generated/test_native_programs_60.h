#include "../fd_tests.h"
int test_1500(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 108,2,127,15,62,111,112,30,125,98,124,106,80,92,61,120,26,27,75,77,76,105,118,103,56,113,117,90,24,123,55,82,116,121,122,110,29,109,83,114,87,89,128,78,79,33,126 };
  test.disable_feature = disabled_features;
  test.test_name = "tests::test_bpf_loader_upgradeable_close";
  test.test_nonce  = 16;
  test.test_number = 1500;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "11111131HgKZP9GC8vDMGJ35FG79EfMtnTcTgakQf",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "BPFLoaderUpgradeab1e11111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1500_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1500_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1500_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1500_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111112ygKucwx7MR4i5XjgyZvqCjaDNmRqckFR9H",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "1111112z5fWc4FQ4bXatxsmzzG9grr11GgnKyqFTd",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 2UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1500_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1500_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1500_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1500_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111112x4yVgWkxWhDCooBLstbZGEV4rkQ4mov5su",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "1111112xsehejMXw48xSfTWvjGCEV2e7kuxCH5kWb",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1500_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1500_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1500_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1500_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "BPFLoaderUpgradeab1e11111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1500_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1500_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1501(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 113,112,114,92,120,123,111,61,110,33,116,62,128,109,121,106,83,117,98,124,80,78,29,118,79,127,77,75,56,15,103,82,89,2,55,87,26,76,126,30,108,122,125,24,90,27,105 };
  test.disable_feature = disabled_features;
  test.test_name = "tests::test_bpf_loader_upgradeable_close";
  test.test_nonce  = 10;
  test.test_number = 1501;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111112zV17bAYgmmzTiQ1s2QbUAz7ndmwj3DR5my",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "BPFLoaderUpgradeab1e11111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1501_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1501_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1501_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1501_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111112ygKucwx7MR4i5XjgyZvqCjaDNmRqckFR9H",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "1111112z5fWc4FQ4bXatxsmzzG9grr11GgnKyqFTd",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1501_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1501_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1501_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1501_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111112x4yVgWkxWhDCooBLstbZGEV4rkQ4mov5su",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "1111112xsehejMXw48xSfTWvjGCEV2e7kuxCH5kWb",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1501_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1501_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1501_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1501_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "BPFLoaderUpgradeab1e11111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1501_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1501_raw_sz;
  test.expected_result = -44;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1502(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 62,30,76,83,79,61,33,117,15,127,124,109,55,75,120,82,56,108,26,123,121,105,118,80,92,78,29,116,24,77,106,111,2,90,103,113,89,87,128,112,114,27,126,125,98,110,122 };
  test.disable_feature = disabled_features;
  test.test_name = "tests::test_bpf_loader_upgradeable_close";
  test.test_nonce  = 2;
  test.test_number = 1502;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111112zV17bAYgmmzTiQ1s2QbUAz7ndmwj3DR5my",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "BPFLoaderUpgradeab1e11111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1502_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1502_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1502_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1502_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111112ygKucwx7MR4i5XjgyZvqCjaDNmRqckFR9H",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "1111112z5fWc4FQ4bXatxsmzzG9grr11GgnKyqFTd",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 2UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1502_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1502_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1502_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1502_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111112xUK6fd4FDsg5dEKRuJvskMkrVFf1V3VvCF",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "1111112xsehejMXw48xSfTWvjGCEV2e7kuxCH5kWb",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1502_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1502_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1502_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1502_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "BPFLoaderUpgradeab1e11111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1502_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1502_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1503(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 92,55,128,127,113,110,30,108,121,24,79,87,112,26,126,80,2,116,83,109,62,82,111,105,27,125,122,15,124,117,78,56,61,114,29,106,75,103,89,123,90,118,33,120,77,98,76 };
  test.disable_feature = disabled_features;
  test.test_name = "tests::test_bpf_loader_upgradeable_close";
  test.test_nonce  = 25;
  test.test_number = 1503;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 4;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "11111131h1vYVSYuKP6AhS86fbRdMw9XHiZAvAaj1",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "BPFLoaderUpgradeab1e11111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1503_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1503_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1503_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1503_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111112ygKucwx7MR4i5XjgyZvqCjaDNmRqckFR9H",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "1111112z5fWc4FQ4bXatxsmzzG9grr11GgnKyqFTd",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 2UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1503_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1503_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1503_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1503_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111112xUK6fd4FDsg5dEKRuJvskMkrVFf1V3VvCF",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "1111112xsehejMXw48xSfTWvjGCEV2e7kuxCH5kWb",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1503_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1503_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1503_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1503_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "111111326MXXbjqcVqxz8aD85vk7VCw9nyVt9kR3M",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "BPFLoaderUpgradeab1e11111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 1;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1503_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1503_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1503_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1503_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "BPFLoaderUpgradeab1e11111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1503_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1503_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1504(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 92,55,128,127,113,110,30,108,121,24,79,87,112,26,126,80,2,116,83,109,62,82,111,105,27,125,122,15,124,117,78,56,61,114,29,106,75,103,89,123,90,118,33,120,77,98,76 };
  test.disable_feature = disabled_features;
  test.test_name = "tests::test_bpf_loader_upgradeable_close";
  test.test_nonce  = 11;
  test.test_number = 1504;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "11111131h1vYVSYuKP6AhS86fbRdMw9XHiZAvAaj1",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "BPFLoaderUpgradeab1e11111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1504_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1504_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1504_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1504_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111112ztLiaGqyUxTLXq9x3pvnf7PaGHCfkSzv6K",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111131HgKZP9GC8vDMGJ35FG79EfMtnTcTgakQf",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1504_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1504_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1504_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1504_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111112ygKucwx7MR4i5XjgyZvqCjaDNmRqckFR9H",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "1111112zV17bAYgmmzTiQ1s2QbUAz7ndmwj3DR5my",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1504_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1504_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1504_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1504_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "BPFLoaderUpgradeab1e11111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1504_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1504_raw_sz;
  test.expected_result = -44;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1505(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 92,55,128,127,113,110,30,108,121,24,79,87,112,26,126,80,2,116,83,109,62,82,111,105,27,125,122,15,124,117,78,56,61,114,29,106,75,103,89,123,90,118,33,120,77,98,76 };
  test.disable_feature = disabled_features;
  test.test_name = "tests::test_bpf_loader_upgradeable_close";
  test.test_nonce  = 20;
  test.test_number = 1505;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "111111326MXXbjqcVqxz8aD85vk7VCw9nyVt9kR3M",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "BPFLoaderUpgradeab1e11111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1505_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1505_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1505_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1505_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111112ztLiaGqyUxTLXq9x3pvnf7PaGHCfkSzv6K",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111131HgKZP9GC8vDMGJ35FG79EfMtnTcTgakQf",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 2UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1505_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1505_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1505_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1505_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111112ygKucwx7MR4i5XjgyZvqCjaDNmRqckFR9H",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "1111112zV17bAYgmmzTiQ1s2QbUAz7ndmwj3DR5my",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1505_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1505_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1505_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1505_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "BPFLoaderUpgradeab1e11111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1505_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1505_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1506(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 92,55,128,127,113,110,30,108,121,24,79,87,112,26,126,80,2,116,83,109,62,82,111,105,27,125,122,15,124,117,78,56,61,114,29,106,75,103,89,123,90,118,33,120,77,98,76 };
  test.disable_feature = disabled_features;
  test.test_name = "tests::test_bpf_loader_upgradeable_close";
  test.test_nonce  = 26;
  test.test_number = 1506;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 4;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "11111132Vh8Wi38KgJqoZiJ9WG4bcUinJESbPLFMh",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "BPFLoaderUpgradeab1e11111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1506_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1506_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1506_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1506_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111112ztLiaGqyUxTLXq9x3pvnf7PaGHCfkSzv6K",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111131HgKZP9GC8vDMGJ35FG79EfMtnTcTgakQf",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 2UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1506_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1506_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1506_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1506_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111112z5fWc4FQ4bXatxsmzzG9grr11GgnKyqFTd",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "1111112zV17bAYgmmzTiQ1s2QbUAz7ndmwj3DR5my",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1506_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1506_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1506_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1506_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111132u2jVpLR2rmiczrPAvbP5jkWQoVPJcv5g3",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "BPFLoaderUpgradeab1e11111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 1;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1506_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1506_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1506_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1506_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "BPFLoaderUpgradeab1e11111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1506_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1506_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1507(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 92,55,128,127,113,110,30,108,121,24,79,87,112,26,126,80,2,116,83,109,62,82,111,105,27,125,122,15,124,117,78,56,61,114,29,106,75,103,89,123,90,118,33,120,77,98,76 };
  test.disable_feature = disabled_features;
  test.test_name = "tests::test_bpf_loader_upgradeable_close";
  test.test_nonce  = 4;
  test.test_number = 1507;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "11111131h1vYVSYuKP6AhS86fbRdMw9XHiZAvAaj1",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "BPFLoaderUpgradeab1e11111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1507_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1507_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1507_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1507_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111112ztLiaGqyUxTLXq9x3pvnf7PaGHCfkSzv6K",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111131HgKZP9GC8vDMGJ35FG79EfMtnTcTgakQf",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 2UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1507_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1507_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1507_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1507_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111112z5fWc4FQ4bXatxsmzzG9grr11GgnKyqFTd",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "1111112zV17bAYgmmzTiQ1s2QbUAz7ndmwj3DR5my",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1507_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1507_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1507_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1507_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "BPFLoaderUpgradeab1e11111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1507_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1507_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1508(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 111,108,122,124,103,87,126,79,61,112,116,109,76,110,92,125,98,29,118,128,127,106,114,89,78,113,123,83,27,105,117,2,55,15,77,90,24,56,62,120,80,82,26,33,30,75,121 };
  test.disable_feature = disabled_features;
  test.test_name = "tests::test_bpf_loader_upgradeable_deploy_with_max_len";
  test.test_nonce  = 61;
  test.test_number = 1508;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 2;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "8jZm2zfUgyUHWqSNyig8dB5qBaHxWrftadfdPxLRjF6d",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "BPFLoaderUpgradeab1e11111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 17184240UL;
  test_acc->result_lamports = 17184240UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1508_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1508_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1508_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1508_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "BowF3zP9zMwhVaHuQHqCpyjmDkFzogVRZdv4aMyqhFLn",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "BPFLoaderUpgradeab1e11111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1141440UL;
  test_acc->result_lamports = 1141440UL;
  test_acc->executable      = 1;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1508_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1508_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1508_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1508_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "BPFLoaderUpgradeab1e11111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1508_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1508_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1509(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 111,108,122,124,103,87,126,79,61,112,116,109,76,110,92,125,98,29,118,128,127,106,114,89,78,113,123,83,27,105,117,2,55,15,77,90,24,56,62,120,80,82,26,33,30,75,121 };
  test.disable_feature = disabled_features;
  test.test_name = "tests::test_bpf_loader_upgradeable_deploy_with_max_len";
  test.test_nonce  = 61;
  test.test_number = 1509;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 2;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "8VQCM8aCs44YyxXw33yvQ2RbiqHsfs4RHEteo6LaG34",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "BPFLoaderUpgradeab1e11111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 17184240UL;
  test_acc->result_lamports = 17184240UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1509_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1509_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1509_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1509_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "5JAfp5rQEZ3UW4gqAHcTPufPvCKkF7b9ddasoqqWYsh6",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "BPFLoaderUpgradeab1e11111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1141440UL;
  test_acc->result_lamports = 1141440UL;
  test_acc->executable      = 1;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1509_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1509_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1509_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1509_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "BPFLoaderUpgradeab1e11111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1509_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1509_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1510(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 105,56,89,122,118,120,108,76,90,30,75,80,125,55,124,24,123,112,109,26,83,61,92,27,98,128,121,78,114,127,62,113,126,29,111,82,106,110,15,87,33,117,103,116,77,2,79 };
  test.disable_feature = disabled_features;
  test.test_name = "tests::test_bpf_loader_upgradeable_initialize_buffer";
  test.test_nonce  = 11;
  test.test_number = 1510;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 2;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "11111133JNLUvdhk3EbSRzUCLvhZs2J3JkL1rVuzP",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "BPFLoaderUpgradeab1e11111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1510_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1510_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1510_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1510_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111133hhwU2vzTDhUFs8ZDmG23zJ5fp1Gj65kJj",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "BPFLoaderUpgradeab1e11111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1510_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1510_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1510_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1510_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "BPFLoaderUpgradeab1e11111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1510_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1510_raw_sz;
  test.expected_result = -9;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1511(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 122,127,24,124,98,89,76,83,114,126,61,92,113,90,55,109,56,121,103,29,87,116,128,33,123,111,78,62,82,2,79,80,105,110,118,75,120,108,77,27,112,30,15,106,26,117,125 };
  test.disable_feature = disabled_features;
  test.test_name = "tests::test_bpf_loader_upgradeable_initialize_buffer";
  test.test_nonce  = 3;
  test.test_number = 1511;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 2;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "11111133JNLUvdhk3EbSRzUCLvhZs2J3JkL1rVuzP",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "BPFLoaderUpgradeab1e11111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1511_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1511_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1511_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1511_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111133hhwU2vzTDhUFs8ZDmG23zJ5fp1Gj65kJj",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "BPFLoaderUpgradeab1e11111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1511_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1511_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1511_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1511_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "BPFLoaderUpgradeab1e11111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1511_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1511_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1512(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 122,127,24,124,98,89,76,83,114,126,61,92,113,90,55,109,56,121,103,29,87,116,128,33,123,111,78,62,82,2,79,80,105,110,118,75,120,108,77,27,112,30,15,106,26,117,125 };
  test.disable_feature = disabled_features;
  test.test_name = "tests::test_bpf_loader_upgradeable_initialize_buffer";
  test.test_nonce  = 10;
  test.test_number = 1512;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 2;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "11111133hhwU2vzTDhUFs8ZDmG23zJ5fp1Gj65kJj",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "BPFLoaderUpgradeab1e11111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1512_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1512_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1512_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1512_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111113473YT9EHAQAM5JGeFBbLY7ZsJKGDSKfad5",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "BPFLoaderUpgradeab1e11111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1512_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1512_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1512_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1512_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "BPFLoaderUpgradeab1e11111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1512_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1512_raw_sz;
  test.expected_result = -9;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1513(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 122,127,24,124,98,89,76,83,114,126,61,92,113,90,55,109,56,121,103,29,87,116,128,33,123,111,78,62,82,2,79,80,105,110,118,75,120,108,77,27,112,30,15,106,26,117,125 };
  test.disable_feature = disabled_features;
  test.test_name = "tests::test_bpf_loader_upgradeable_initialize_buffer";
  test.test_nonce  = 3;
  test.test_number = 1513;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 2;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "11111133hhwU2vzTDhUFs8ZDmG23zJ5fp1Gj65kJj",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "BPFLoaderUpgradeab1e11111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1513_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1513_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1513_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1513_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111113473YT9EHAQAM5JGeFBbLY7ZsJKGDSKfad5",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "BPFLoaderUpgradeab1e11111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1513_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1513_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1513_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1513_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "BPFLoaderUpgradeab1e11111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1513_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1513_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1514(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 78,124,75,92,118,113,126,106,80,105,33,61,79,109,56,120,29,90,26,122,110,98,30,62,15,123,125,76,111,114,108,27,112,2,55,24,87,127,89,116,77,121,128,82,83,103,117 };
  test.disable_feature = disabled_features;
  test.test_name = "tests::test_bpf_loader_upgradeable_set_buffer_authority";
  test.test_nonce  = 32;
  test.test_number = 1514;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "111111367jZNgiiiJUjATy5NHFvxjvoSqYvzVakCo",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "BPFLoaderUpgradeab1e11111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1514_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1514_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1514_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1514_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111134WP9SFXZsadDtjQjGbvf2EqevpXA9ZFQwR",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111134uikRMpram66iAYpJ2FyWN7SZKn6rnqFFm",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1514_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1514_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1514_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1514_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111135K4MQU89HwYyXbguKSbHzVPEBq33a2R5a7",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111135iPxPaRS181rM2pzLrvcUcf1pLHzHFzutT",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1514_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1514_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1514_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1514_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "BPFLoaderUpgradeab1e11111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1514_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1514_raw_sz;
  test.expected_result = -44;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1515(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 105,76,126,117,98,24,55,122,125,30,106,111,82,89,90,2,109,123,127,120,77,87,103,29,80,124,61,112,110,56,33,114,78,116,118,113,92,62,79,108,128,27,15,83,75,26,121 };
  test.disable_feature = disabled_features;
  test.test_name = "tests::test_bpf_loader_upgradeable_set_buffer_authority";
  test.test_nonce  = 39;
  test.test_number = 1515;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "111111367jZNgiiiJUjATy5NHFvxjvoSqYvzVakCo",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "BPFLoaderUpgradeab1e11111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1515_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1515_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1515_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1515_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111134WP9SFXZsadDtjQjGbvf2EqevpXA9ZFQwR",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111134uikRMpram66iAYpJ2FyWN7SZKn6rnqFFm",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1515_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1515_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1515_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1515_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111135K4MQU89HwYyXbguKSbHzVPEBq33a2R5a7",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111135iPxPaRS181rM2pzLrvcUcf1pLHzHFzutT",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1515_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1515_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1515_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1515_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "BPFLoaderUpgradeab1e11111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1515_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1515_raw_sz;
  test.expected_result = -43;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1516(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 26,29,106,112,114,15,127,62,110,30,56,120,61,78,117,125,76,122,103,55,123,80,108,79,109,75,113,89,105,83,98,111,2,124,126,77,128,92,27,24,90,87,116,33,82,121,118 };
  test.disable_feature = disabled_features;
  test.test_name = "tests::test_bpf_loader_upgradeable_set_buffer_authority";
  test.test_nonce  = 26;
  test.test_number = 1516;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "111111367jZNgiiiJUjATy5NHFvxjvoSqYvzVakCo",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "BPFLoaderUpgradeab1e11111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1516_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1516_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1516_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1516_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111113473YT9EHAQAM5JGeFBbLY7ZsJKGDSKfad5",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111134uikRMpram66iAYpJ2FyWN7SZKn6rnqFFm",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1516_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1516_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1516_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1516_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111135K4MQU89HwYyXbguKSbHzVPEBq33a2R5a7",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111135iPxPaRS181rM2pzLrvcUcf1pLHzHFzutT",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1516_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1516_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1516_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1516_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "BPFLoaderUpgradeab1e11111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1516_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1516_raw_sz;
  test.expected_result = -44;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1517(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 33,122,114,124,24,90,26,80,79,106,116,15,77,78,87,92,120,123,127,103,117,110,125,56,98,75,105,109,111,29,126,113,30,112,121,108,55,83,62,61,118,82,76,128,89,2,27 };
  test.disable_feature = disabled_features;
  test.test_name = "tests::test_bpf_loader_upgradeable_set_buffer_authority";
  test.test_nonce  = 14;
  test.test_number = 1517;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "111111367jZNgiiiJUjATy5NHFvxjvoSqYvzVakCo",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "BPFLoaderUpgradeab1e11111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1517_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1517_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1517_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1517_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111134WP9SFXZsadDtjQjGbvf2EqevpXA9ZFQwR",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111134uikRMpram66iAYpJ2FyWN7SZKn6rnqFFm",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1517_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1517_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1517_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1517_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111135K4MQU89HwYyXbguKSbHzVPEBq33a2R5a7",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111135iPxPaRS181rM2pzLrvcUcf1pLHzHFzutT",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1517_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1517_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1517_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1517_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "BPFLoaderUpgradeab1e11111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1517_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1517_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1518(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 83,77,121,116,90,76,75,26,106,114,124,2,109,89,122,128,117,118,62,78,123,24,33,80,112,15,82,126,92,87,110,111,103,120,55,56,127,30,29,125,27,108,79,61,113,105,98 };
  test.disable_feature = disabled_features;
  test.test_name = "tests::test_bpf_loader_upgradeable_set_buffer_authority";
  test.test_nonce  = 41;
  test.test_number = 1518;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "111111367jZNgiiiJUjATy5NHFvxjvoSqYvzVakCo",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "BPFLoaderUpgradeab1e11111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1518_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1518_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1518_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1518_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111134WP9SFXZsadDtjQjGbvf2EqevpXA9ZFQwR",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111134uikRMpram66iAYpJ2FyWN7SZKn6rnqFFm",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1518_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1518_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1518_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1518_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111135K4MQU89HwYyXbguKSbHzVPEBq33a2R5a7",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111135iPxPaRS181rM2pzLrvcUcf1pLHzHFzutT",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1518_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1518_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1518_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1518_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "BPFLoaderUpgradeab1e11111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1518_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1518_raw_sz;
  test.expected_result = -2;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1519(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 109,24,127,82,98,92,89,56,110,114,76,29,128,103,2,116,126,112,77,113,62,78,33,125,122,26,108,75,105,124,27,15,90,106,83,121,111,123,61,87,55,80,120,79,117,30,118 };
  test.disable_feature = disabled_features;
  test.test_name = "tests::test_bpf_loader_upgradeable_set_buffer_authority";
  test.test_nonce  = 4;
  test.test_number = 1519;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "111111367jZNgiiiJUjATy5NHFvxjvoSqYvzVakCo",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "BPFLoaderUpgradeab1e11111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1519_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1519_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1519_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1519_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111134WP9SFXZsadDtjQjGbvf2EqevpXA9ZFQwR",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111134uikRMpram66iAYpJ2FyWN7SZKn6rnqFFm",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1519_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1519_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1519_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1519_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111135K4MQU89HwYyXbguKSbHzVPEBq33a2R5a7",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111135iPxPaRS181rM2pzLrvcUcf1pLHzHFzutT",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1519_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1519_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1519_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1519_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "BPFLoaderUpgradeab1e11111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1519_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1519_raw_sz;
  test.expected_result = -44;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1520(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 125,123,27,89,128,90,76,126,75,120,117,114,15,103,121,62,79,127,24,26,112,56,109,113,2,118,33,78,55,87,61,122,124,30,92,111,110,108,98,116,80,77,83,105,29,106,82 };
  test.disable_feature = disabled_features;
  test.test_name = "tests::test_bpf_loader_upgradeable_set_buffer_authority";
  test.test_nonce  = 20;
  test.test_number = 1520;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "111111367jZNgiiiJUjATy5NHFvxjvoSqYvzVakCo",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "BPFLoaderUpgradeab1e11111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1520_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1520_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1520_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1520_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111134WP9SFXZsadDtjQjGbvf2EqevpXA9ZFQwR",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111134uikRMpram66iAYpJ2FyWN7SZKn6rnqFFm",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1520_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1520_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1520_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1520_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111135K4MQU89HwYyXbguKSbHzVPEBq33a2R5a7",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111135iPxPaRS181rM2pzLrvcUcf1pLHzHFzutT",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1520_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1520_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1520_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1520_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "BPFLoaderUpgradeab1e11111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1520_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1520_raw_sz;
  test.expected_result = -8;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1521(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 125,123,27,89,128,90,76,126,75,120,117,114,15,103,121,62,79,127,24,26,112,56,109,113,2,118,33,78,55,87,61,122,124,30,92,111,110,108,98,116,80,77,83,105,29,106,82 };
  test.disable_feature = disabled_features;
  test.test_name = "tests::test_bpf_loader_upgradeable_set_buffer_authority";
  test.test_nonce  = 13;
  test.test_number = 1521;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "11111137KkNL1caqqsMcmPLSYFtR7kALMKm8CLF9q",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "BPFLoaderUpgradeab1e11111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1521_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1521_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1521_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1521_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111135iPxPaRS181rM2pzLrvcUcf1pLHzHFzutT",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "111111367jZNgiiiJUjATy5NHFvxjvoSqYvzVakCo",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1521_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1521_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1521_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1521_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111136X5AMo21RUwbyu7APhbFSsCb5LoshjAaX9",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111136vQmLuKJ8fQUoLFFR7vZvzUNhr4pQxkQqV",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1521_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1521_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1521_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1521_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "BPFLoaderUpgradeab1e11111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1521_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1521_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1522(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 125,123,27,89,128,90,76,126,75,120,117,114,15,103,121,62,79,127,24,26,112,56,109,113,2,118,33,78,55,87,61,122,124,30,92,111,110,108,98,116,80,77,83,105,29,106,82 };
  test.disable_feature = disabled_features;
  test.test_name = "tests::test_bpf_loader_upgradeable_set_buffer_authority";
  test.test_nonce  = 22;
  test.test_number = 1522;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "11111137KkNL1caqqsMcmPLSYFtR7kALMKm8CLF9q",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "BPFLoaderUpgradeab1e11111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1522_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1522_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1522_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1522_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111135iPxPaRS181rM2pzLrvcUcf1pLHzHFzutT",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "111111367jZNgiiiJUjATy5NHFvxjvoSqYvzVakCo",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1522_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1522_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1522_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1522_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111136X5AMo21RUwbyu7APhbFSsCb5LoshjAaX9",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111136vQmLuKJ8fQUoLFFR7vZvzUNhr4pQxkQqV",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1522_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1522_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1522_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1522_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "BPFLoaderUpgradeab1e11111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1522_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1522_raw_sz;
  test.expected_result = -8;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1523(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 125,123,27,89,128,90,76,126,75,120,117,114,15,103,121,62,79,127,24,26,112,56,109,113,2,118,33,78,55,87,61,122,124,30,92,111,110,108,98,116,80,77,83,105,29,106,82 };
  test.disable_feature = disabled_features;
  test.test_name = "tests::test_bpf_loader_upgradeable_set_buffer_authority";
  test.test_nonce  = 25;
  test.test_number = 1523;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "11111137KkNL1caqqsMcmPLSYFtR7kALMKm8CLF9q",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "BPFLoaderUpgradeab1e11111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1523_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1523_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1523_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1523_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111135K4MQU89HwYyXbguKSbHzVPEBq33a2R5a7",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "111111367jZNgiiiJUjATy5NHFvxjvoSqYvzVakCo",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1523_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1523_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1523_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1523_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111136X5AMo21RUwbyu7APhbFSsCb5LoshjAaX9",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111136vQmLuKJ8fQUoLFFR7vZvzUNhr4pQxkQqV",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1523_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1523_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1523_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1523_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "BPFLoaderUpgradeab1e11111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1523_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1523_raw_sz;
  test.expected_result = -44;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1524(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 125,123,27,89,128,90,76,126,75,120,117,114,15,103,121,62,79,127,24,26,112,56,109,113,2,118,33,78,55,87,61,122,124,30,92,111,110,108,98,116,80,77,83,105,29,106,82 };
  test.disable_feature = disabled_features;
  test.test_name = "tests::test_bpf_loader_upgradeable_set_buffer_authority";
  test.test_nonce  = 29;
  test.test_number = 1524;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "11111137KkNL1caqqsMcmPLSYFtR7kALMKm8CLF9q",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "BPFLoaderUpgradeab1e11111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1524_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1524_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1524_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1524_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111135iPxPaRS181rM2pzLrvcUcf1pLHzHFzutT",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "111111367jZNgiiiJUjATy5NHFvxjvoSqYvzVakCo",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1524_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1524_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1524_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1524_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111136X5AMo21RUwbyu7APhbFSsCb5LoshjAaX9",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111136vQmLuKJ8fQUoLFFR7vZvzUNhr4pQxkQqV",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1524_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1524_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1524_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1524_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "BPFLoaderUpgradeab1e11111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1524_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1524_raw_sz;
  test.expected_result = -44;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
