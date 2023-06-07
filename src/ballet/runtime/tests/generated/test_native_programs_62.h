#include "../fd_tests.h"
int test_1550(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 62,127,124,87,128,114,111,89,79,121,109,15,122,56,2,76,90,116,78,24,103,55,77,27,120,112,108,26,29,106,61,110,126,82,125,123,83,105,33,117,98,118,30,75,92,113,80 };
  test.disable_feature = disabled_features;
  test.test_name = "tests::test_bpf_loader_upgradeable_upgrade";
  test.test_nonce  = 49;
  test.test_number = 1550;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 7;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "4hY786hrW4iqpcavNK2fsRcFWWrx2opgCupp9h3ShMgW",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "BPFLoaderUpgradeab1e11111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 17184240UL;
  test_acc->result_lamports = 17184240UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1550_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1550_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1550_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1550_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111114m6BvfrZ9pn9tFvZxGPXjpxXQ8QeGKwAWRu",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "BPFLoaderUpgradeab1e11111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1141440UL;
  test_acc->result_lamports = 1141440UL;
  test_acc->executable      = 1;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1550_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1550_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1550_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1550_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111139jmzEfQK6vecXNDrb4FoKsNt7NsRPbqF3u",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "BPFLoaderUpgradeab1e11111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1550_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1550_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1550_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1550_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111114mVXXexrSXxcm5Mi3Hos4K5oBkuuD3AkLkF",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "1111114nJCjdBT1xKYWiDzDLeXhHLLm1vR6Tdv1Nw",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1550_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1550_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1550_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1550_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1550_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1550_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1550_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1550_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1550_acc_5_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1550_acc_5_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1550_acc_5_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1550_acc_5_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111113A97bDmhbp77VLoMwcUb7ozefjt8N6qR5NF",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "1111114nhYLcHkJfW1PXf8JN4s1mTcYeRg3AsVqhH",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1550_acc_6_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1550_acc_6_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1550_acc_6_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1550_acc_6_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "BPFLoaderUpgradeab1e11111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1550_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1550_raw_sz;
  test.expected_result = -2;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1551(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 79,98,116,114,61,110,29,122,105,78,83,80,90,123,15,124,33,89,125,108,26,128,82,55,106,56,111,27,118,120,109,127,113,62,76,87,117,2,77,24,75,92,30,121,112,103,126 };
  test.disable_feature = disabled_features;
  test.test_name = "tests::test_bpf_loader_upgradeable_upgrade";
  test.test_nonce  = 44;
  test.test_number = 1551;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 7;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "2NbfcEHRkzV9DUKNbasmVdJj7Fhx2myW9z5sG1zsNeyR",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "BPFLoaderUpgradeab1e11111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 17184240UL;
  test_acc->result_lamports = 17184240UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1551_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1551_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1551_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1551_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111114FKBHopVqHRs3jrFYTLt9wgPBZ5aTibzs2P",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "BPFLoaderUpgradeab1e11111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1141440UL;
  test_acc->result_lamports = 1141440UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1551_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1551_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1551_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1551_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111139jmzEfQK6vecXNDrb4FoKsNt7NsRPbqF3u",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "BPFLoaderUpgradeab1e11111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1551_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1551_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1551_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1551_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111114FiWtnvo7zcKvZHPdUmDURoeyBaqQRqahLj",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "1111114GvXhkFgz89iZ1aotZ2DRtBUL56cEZYLCHm",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1551_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1551_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1551_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1551_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1551_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1551_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1551_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1551_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1551_acc_5_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1551_acc_5_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1551_acc_5_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1551_acc_5_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111113A97bDmhbp77VLoMwcUb7ozefjt8N6qR5NF",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "1111114HKsJjMzGqLBRq1wyaSYkNJk7hbsBGmv2c7",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1551_acc_6_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1551_acc_6_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1551_acc_6_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1551_acc_6_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "BPFLoaderUpgradeab1e11111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1551_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1551_raw_sz;
  test.expected_result = -22;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1552(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 61,33,76,108,87,116,112,121,26,82,55,117,90,109,128,75,105,98,110,122,124,24,62,103,83,114,89,30,123,27,29,106,79,78,126,125,80,92,113,111,15,2,127,77,56,120,118 };
  test.disable_feature = disabled_features;
  test.test_name = "tests::test_bpf_loader_upgradeable_upgrade";
  test.test_nonce  = 58;
  test.test_number = 1552;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 7;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "4i6ZuLLfwHEWNQF2YcB9Mj5TY5v5psGovVe2DBXy8YjQ",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "BPFLoaderUpgradeab1e11111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 17184240UL;
  test_acc->result_lamports = 17184240UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1552_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1552_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1552_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1552_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111168m7MdMaCQVuNBkB77TUqqnRAkHf36JfT4B",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "BPFLoaderUpgradeab1e11111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1141440UL;
  test_acc->result_lamports = 1141440UL;
  test_acc->executable      = 1;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1552_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1552_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1552_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1552_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111139jmzEfQK6vecXNDrb4FoKsNt7NsRPbqF3u",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "BPFLoaderUpgradeab1e11111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1552_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1552_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1552_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1552_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111169ASxcTsV7gNF1BKC8spAKugxNnuyoYFHNX",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111169y8AagU4Y3Hze3bNBiUoJAEXdoRsE1Qx1D",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1552_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1552_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1552_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1552_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1552_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1552_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1552_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1552_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1552_acc_5_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1552_acc_5_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1552_acc_5_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1552_acc_5_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111113A97bDmhbp77VLoMwcUb7ozefjt8N6qR5NF",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "1111116ANTmZnmMFDksTUjTD8p7nHWKGJgowEznKZ",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1552_acc_6_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1552_acc_6_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1552_acc_6_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1552_acc_6_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "BPFLoaderUpgradeab1e11111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1552_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1552_raw_sz;
  test.expected_result = -44;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1553(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 77,76,15,111,55,26,62,98,83,127,24,109,125,79,105,112,90,75,27,78,126,121,61,89,2,122,120,30,87,116,29,110,92,128,80,82,106,33,103,123,108,118,124,114,56,117,113 };
  test.disable_feature = disabled_features;
  test.test_name = "tests::test_bpf_loader_upgradeable_upgrade";
  test.test_nonce  = 42;
  test.test_number = 1553;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 7;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "3XpsxL2EysHdgTkVwJGTks5DxkdaSomseNxmgqowDYjs",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "BPFLoaderUpgradeab1e11111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 17184240UL;
  test_acc->result_lamports = 17184240UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1553_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1553_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1553_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1553_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111142SMzJLxcZf31ZynmfvDxRfg1QwLGy7LCuM",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "BPFLoaderUpgradeab1e11111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1141440UL;
  test_acc->result_lamports = 1141440UL;
  test_acc->executable      = 1;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1553_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1553_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1553_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1553_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111139jmzEfQK6vecXNDrb4FoKsNt7NsRPbqF3u",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "BPFLoaderUpgradeab1e11111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1553_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1553_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1553_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1553_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111142qhbHTFuGqVtPQvrhLZGunwo3SbDgLv3Dh",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111143eNoFfrUhCRe2HD2kBDut3VNJT776p5hrP",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1553_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1553_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1553_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1553_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1553_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1553_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1553_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1553_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1553_acc_5_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1553_acc_5_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1553_acc_5_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1553_acc_5_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111113A97bDmhbp77VLoMwcUb7ozefjt8N6qR5NF",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "111111443iQEn9mQNtWqiM7mbZENAm9vxN3p3fYAj",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1553_acc_6_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1553_acc_6_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1553_acc_6_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1553_acc_6_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "BPFLoaderUpgradeab1e11111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1553_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1553_raw_sz;
  test.expected_result = -8;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1554(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 125,15,24,56,106,98,78,77,27,89,128,113,55,103,80,114,29,82,79,92,75,33,30,62,121,105,76,61,118,110,116,126,109,127,83,117,122,120,26,123,112,108,2,111,87,90,124 };
  test.disable_feature = disabled_features;
  test.test_name = "tests::test_bpf_loader_upgradeable_upgrade";
  test.test_nonce  = 52;
  test.test_number = 1554;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 7;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111115ErWYcM82pE8LgqBvxLWjHcJgZDRMP6QzFh",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "BPFLoaderUpgradeab1e11111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 17184240UL;
  test_acc->result_lamports = 17184240UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1554_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1554_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1554_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1554_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111115DFA8fuvsyWGqR6darfBTM7DY3CPaYA5ezK",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "BPFLoaderUpgradeab1e11111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1141440UL;
  test_acc->result_lamports = 1141440UL;
  test_acc->executable      = 1;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1554_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1554_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1554_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1554_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111139jmzEfQK6vecXNDrb4FoKsNt7NsRPbqF3u",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "BPFLoaderUpgradeab1e11111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1554_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1554_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1554_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1554_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111115DeVjf2EAggjiEXmft5WmqEVKfheXFPfVJf",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "1111115E3qLe8XTPsCb3xukuVr6KMm7JCuTxdFKd1",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1554_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1554_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1554_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1554_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1554_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1554_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1554_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1554_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1554_acc_5_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1554_acc_5_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1554_acc_5_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1554_acc_5_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111113A97bDmhbp77VLoMwcUb7ozefjt8N6qR5NF",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "1111115ETAwdEpk73fTsQ3qvvBQoV2tviAQfrq9wM",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1554_acc_6_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1554_acc_6_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1554_acc_6_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1554_acc_6_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "BPFLoaderUpgradeab1e11111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1554_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1554_raw_sz;
  test.expected_result = -2;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1555(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 125,15,24,56,106,98,78,77,27,89,128,113,55,103,80,114,29,82,79,92,75,33,30,62,121,105,76,61,118,110,116,126,109,127,83,117,122,120,26,123,112,108,2,111,87,90,124 };
  test.disable_feature = disabled_features;
  test.test_name = "tests::test_bpf_loader_upgradeable_upgrade";
  test.test_nonce  = 16;
  test.test_number = 1555;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 7;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "FSzwNmsXn5eJJJ4k8kv56HrWQhGHq98jjpt9v9oRzYmS",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "BPFLoaderUpgradeab1e11111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 17184240UL;
  test_acc->result_lamports = 17184240UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1555_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1555_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1555_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1555_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111113BM8QB6bTweW7o6nCgjb5GNU2dPuCEYAaKH",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "BPFLoaderUpgradeab1e11111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1141440UL;
  test_acc->result_lamports = 1141440UL;
  test_acc->executable      = 1;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1555_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1555_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1555_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1555_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111113AYTCCsztXHaNAEW2dtvSJ7vTNPPJp4zugb",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "BPFLoaderUpgradeab1e11111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1555_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1555_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1555_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1555_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111113BkU1ACtkepxzcXvHi9vPkVjpFuA8wmkQdd",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "1111113EAVd4rgUuukFX8korfvJfFNY2vhoDBFQXh",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1555_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1555_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1555_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1555_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1555_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1555_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1555_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1555_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1555_acc_5_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1555_acc_5_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1555_acc_5_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1555_acc_5_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111113AwnoBzJBEU3Eyfe7fKFknFCEzteFXJajzw",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "1111113EZqE3xymd6D8LZttt6Fd9NeKfRxjvQqEr3",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1555_acc_6_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1555_acc_6_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1555_acc_6_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1555_acc_6_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "BPFLoaderUpgradeab1e11111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1555_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1555_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1556(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 125,15,24,56,106,98,78,77,27,89,128,113,55,103,80,114,29,82,79,92,75,33,30,62,121,105,76,61,118,110,116,126,109,127,83,117,122,120,26,123,112,108,2,111,87,90,124 };
  test.disable_feature = disabled_features;
  test.test_name = "tests::test_bpf_loader_upgradeable_upgrade";
  test.test_nonce  = 38;
  test.test_number = 1556;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 7;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "ARa2FHG7PpcrjMjFVYBmMwFhRco8Bu733c77fD47YWwd",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "BPFLoaderUpgradeab1e11111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 17184240UL;
  test_acc->result_lamports = 17184240UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1556_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1556_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1556_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1556_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111113RqJ7d1KqW9BfEhoKZqaYitGMHZB9pyAZhh",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "BPFLoaderUpgradeab1e11111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1141440UL;
  test_acc->result_lamports = 1141440UL;
  test_acc->executable      = 1;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1556_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1556_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1556_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1556_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111113AYTCCsztXHaNAEW2dtvSJ7vTNPPJp4zugb",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "BPFLoaderUpgradeab1e11111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1556_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1556_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1556_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1556_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111113SEdic7d8DKeY48wQbFusD1Y8v4S6YCkQ23",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "1111113V3zwVsi9BatfnAv1mCF6btSeKbEhWqqEET",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1556_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1556_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1556_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1556_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1556_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1556_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1556_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1556_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1556_acc_5_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1556_acc_5_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1556_acc_5_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1556_acc_5_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111113AwnoBzJBEU3Eyfe7fKFknFCEzteFXJajzw",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "1111113VTLYUz1RtmMYbc46ncaR61iRx6VeE5R4Yo",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1556_acc_6_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1556_acc_6_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1556_acc_6_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1556_acc_6_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "BPFLoaderUpgradeab1e11111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1556_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1556_raw_sz;
  test.expected_result = -43;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1557(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 125,15,24,56,106,98,78,77,27,89,128,113,55,103,80,114,29,82,79,92,75,33,30,62,121,105,76,61,118,110,116,126,109,127,83,117,122,120,26,123,112,108,2,111,87,90,124 };
  test.disable_feature = disabled_features;
  test.test_name = "tests::test_bpf_loader_upgradeable_upgrade";
  test.test_nonce  = 39;
  test.test_number = 1557;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 7;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "2K4Kxm3gNYv46B9YVB2PzCFcYH3FXVS9CwvS9wvvJgMz",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "BPFLoaderUpgradeab1e11111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 17184240UL;
  test_acc->result_lamports = 17184240UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1557_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1557_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1557_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1557_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111113b64zGWBTqHqp3g1K8VEssmXSmA6rBMaiyd",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "BPFLoaderUpgradeab1e11111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1141440UL;
  test_acc->result_lamports = 1141440UL;
  test_acc->executable      = 1;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1557_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1557_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1557_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1557_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111113AYTCCsztXHaNAEW2dtvSJ7vTNPPJp4zugb",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "BPFLoaderUpgradeab1e11111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1557_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1557_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1557_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1557_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111113bVQbFcUkYUJgs79Q9uaCMtoEPfMntbAZHy",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "1111113chRQCwNcg1hKKQZfEAa9pGcbHB8d2Hv4F1",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1557_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1557_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1557_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1557_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1557_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1557_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1557_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1557_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1557_acc_5_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1557_acc_5_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1557_acc_5_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1557_acc_5_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111113dW6cB9yC6Nd4xGqqH1EnnXAAYBeWSm5ish",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "1111113d6m1C3fuPCAC8qhkFauUJPtNugPZjXVtZM",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1557_acc_6_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1557_acc_6_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1557_acc_6_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1557_acc_6_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "BPFLoaderUpgradeab1e11111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1557_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1557_raw_sz;
  test.expected_result = -44;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1558(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 125,15,24,56,106,98,78,77,27,89,128,113,55,103,80,114,29,82,79,92,75,33,30,62,121,105,76,61,118,110,116,126,109,127,83,117,122,120,26,123,112,108,2,111,87,90,124 };
  test.disable_feature = disabled_features;
  test.test_name = "tests::test_bpf_loader_upgradeable_upgrade";
  test.test_nonce  = 43;
  test.test_number = 1558;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 7;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "258oEiVNkhdqawdhyEzZzaiLT5pmTy2nkEgWRz4CD4Wd",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "BPFLoaderUpgradeab1e11111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 17184240UL;
  test_acc->result_lamports = 17184240UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1558_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1558_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1558_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1558_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111113m9X4tDdfaoRiVWVUjyZqzuL7VmYRxDAYtF",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "BPFLoaderUpgradeab1e11111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1141440UL;
  test_acc->result_lamports = 1141440UL;
  test_acc->executable      = 1;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1558_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1558_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1558_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1558_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111113AYTCCsztXHaNAEW2dtvSJ7vTNPPJp4zugb",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "BPFLoaderUpgradeab1e11111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1558_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1558_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1558_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1558_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111113mYrfsKvxHytbJwdZmPuAV2bu8GoNfSkPCb",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "1111113nksUpeppRXHDmF3pqeu7wQRG1naCo9Vt9d",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1558_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1558_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1558_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1558_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1558_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1558_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1558_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1558_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1558_acc_5_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1558_acc_5_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1558_acc_5_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1558_acc_5_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111113AwnoBzJBEU3Eyfe7fKFknFCEzteFXJajzw",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "1111113oAD5om878hk6agBus5ESRXh3eHq9WP5iTy",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1558_acc_6_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1558_acc_6_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1558_acc_6_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1558_acc_6_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "BPFLoaderUpgradeab1e11111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1558_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1558_raw_sz;
  test.expected_result = -8;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1559(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 125,15,24,56,106,98,78,77,27,89,128,113,55,103,80,114,29,82,79,92,75,33,30,62,121,105,76,61,118,110,116,126,109,127,83,117,122,120,26,123,112,108,2,111,87,90,124 };
  test.disable_feature = disabled_features;
  test.test_name = "tests::test_bpf_loader_upgradeable_upgrade";
  test.test_nonce  = 44;
  test.test_number = 1559;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 7;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "9Kk9igJPCnK3cTdhEBHmmDvoAWvBpEHz7DwVoJn5ezAm",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "BPFLoaderUpgradeab1e11111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 17184240UL;
  test_acc->result_lamports = 17184240UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1559_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1559_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1559_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1559_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111113vQHwXiVHux5sJUhUJdEB9nbCyNU8JbaiAB",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "BPFLoaderUpgradeab1e11111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1141440UL;
  test_acc->result_lamports = 1141440UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1559_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1559_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1559_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1559_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111113AYTCCsztXHaNAEW2dtvSJ7vTNPPJp4zugb",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "BPFLoaderUpgradeab1e11111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1559_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1559_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1559_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1559_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111113vodYWpnad8Yk7uqZL3ZVdurzbsj51qAYUX",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "1111113wcJkV3PA3VUVkn7jNtE8cAQZrtExSJLD7D",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1559_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1559_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1559_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1559_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1559_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1559_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1559_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1559_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1559_acc_5_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1559_acc_5_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1559_acc_5_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1559_acc_5_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111113AwnoBzJBEU3Eyfe7fKFknFCEzteFXJajzw",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "1111113x1eMU9gSkfwNaDFpQJZT6HgMVPVu9Xv3RZ",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1559_acc_6_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1559_acc_6_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1559_acc_6_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1559_acc_6_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "BPFLoaderUpgradeab1e11111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1559_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1559_raw_sz;
  test.expected_result = -22;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1560(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 125,15,24,56,106,98,78,77,27,89,128,113,55,103,80,114,29,82,79,92,75,33,30,62,121,105,76,61,118,110,116,126,109,127,83,117,122,120,26,123,112,108,2,111,87,90,124 };
  test.disable_feature = disabled_features;
  test.test_name = "tests::test_bpf_loader_upgradeable_upgrade";
  test.test_nonce  = 45;
  test.test_number = 1560;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 7;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "Rjziupy92CKvVnMd5eCXm3QyS843LpmfZtD8GmARZSP",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "BPFLoaderUpgradeab1e11111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 17184240UL;
  test_acc->result_lamports = 17184240UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1560_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1560_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1560_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1560_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111145f4pBDLvF6k27SuTsGtWJfrJSyPpeyzsS7",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111147fkq6kqMo14QCcbtzNZ6jJDEbVgYD9v31q",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1141440UL;
  test_acc->result_lamports = 1141440UL;
  test_acc->executable      = 1;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1560_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1560_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1560_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1560_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111113AYTCCsztXHaNAEW2dtvSJ7vTNPPJp4zugb",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "BPFLoaderUpgradeab1e11111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1560_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1560_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1560_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1560_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "111111464QRAKeCxHCtvt3YthDpno865UemNDahkT",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111146s5d8YEnNe8eZkKiwXtTm3ffLVAengkNP9",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1560_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1560_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1560_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1560_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1560_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1560_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1560_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1560_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1560_acc_5_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1560_acc_5_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1560_acc_5_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1560_acc_5_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111113AwnoBzJBEU3Eyfe7fKFknFCEzteFXJajzw",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111147GRE7eY55pbXPBToxxDnFAwSxzRbVvLChV",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1560_acc_6_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1560_acc_6_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1560_acc_6_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1560_acc_6_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "BPFLoaderUpgradeab1e11111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1560_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1560_raw_sz;
  test.expected_result = -7;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1561(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 125,15,24,56,106,98,78,77,27,89,128,113,55,103,80,114,29,82,79,92,75,33,30,62,121,105,76,61,118,110,116,126,109,127,83,117,122,120,26,123,112,108,2,111,87,90,124 };
  test.disable_feature = disabled_features;
  test.test_name = "tests::test_bpf_loader_upgradeable_upgrade";
  test.test_nonce  = 48;
  test.test_number = 1561;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 7;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "EQCfzYcoKq8FRgzyPxycgDD8Xj8Zg6B8pk829ZZD8NXt",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "BPFLoaderUpgradeab1e11111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 17184240UL;
  test_acc->result_lamports = 17184240UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1561_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1561_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1561_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1561_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111114DJVGtH1PjXYfegZ7LFDZX42FQZHkAS5hSf",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "BPFLoaderUpgradeab1e11111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1141440UL;
  test_acc->result_lamports = 1141440UL;
  test_acc->executable      = 1;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1561_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1561_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1561_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1561_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111113AYTCCsztXHaNAEW2dtvSJ7vTNPPJp4zugb",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "BPFLoaderUpgradeab1e11111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1561_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1561_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1561_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1561_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111114DhpssPJgSi1YU7hCMfYt1BJ334YgsffXm1",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "1111114EWW5qbuFs4wJ6yyNQWDWyRqcJ54aJ8qCPh",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1561_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1561_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1561_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1561_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1561_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1561_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1561_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1561_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1561_acc_5_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1561_acc_5_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1561_acc_5_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1561_acc_5_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111113AwnoBzJBEU3Eyfe7fKFknFCEzteFXJajzw",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "1111114EuqgpiCYaFQAvR7TRvYqTZ7PvaKX1NR2i3",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1561_acc_6_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1561_acc_6_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1561_acc_6_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1561_acc_6_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "BPFLoaderUpgradeab1e11111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1561_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1561_raw_sz;
  test.expected_result = -2;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1562(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 125,15,24,56,106,98,78,77,27,89,128,113,55,103,80,114,29,82,79,92,75,33,30,62,121,105,76,61,118,110,116,126,109,127,83,117,122,120,26,123,112,108,2,111,87,90,124 };
  test.disable_feature = disabled_features;
  test.test_name = "tests::test_bpf_loader_upgradeable_upgrade";
  test.test_nonce  = 50;
  test.test_number = 1562;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 7;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "AHtneKtG8BUATCzBvDkDKQ7BCuHF2TsxqY6oYLAGjWCF",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "BPFLoaderUpgradeab1e11111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 17184240UL;
  test_acc->result_lamports = 17184240UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1562_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1562_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1562_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1562_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111114MkawZZGSeKH4pnUvr4DFhgjmd9hZ6MLC5u",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "BPFLoaderUpgradeab1e11111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1141440UL;
  test_acc->result_lamports = 1141440UL;
  test_acc->executable      = 1;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1562_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1562_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1562_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1562_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111113AYTCCsztXHaNAEW2dtvSJ7vTNPPJp4zugb",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "BPFLoaderUpgradeab1e11111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1562_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1562_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1562_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1562_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111114N9vYYfZjMVjweDd1sUYaBp1ZFexVoav2QF",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "1111114PMwMVzTbV38a6X3GwjYXeBpv9AjKwHfXMH",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1562_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1562_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1562_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1562_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1562_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1562_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1562_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1562_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1562_acc_5_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1562_acc_5_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1562_acc_5_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1562_acc_5_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111113AwnoBzJBEU3Eyfe7fKFknFCEzteFXJajzw",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "1111114PmGxV6ktCDbSuxBMy9sr8K6hmfzGeXFMfd",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1562_acc_6_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1562_acc_6_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1562_acc_6_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1562_acc_6_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "BPFLoaderUpgradeab1e11111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1562_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1562_raw_sz;
  test.expected_result = -4;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1563(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 125,15,24,56,106,98,78,77,27,89,128,113,55,103,80,114,29,82,79,92,75,33,30,62,121,105,76,61,118,110,116,126,109,127,83,117,122,120,26,123,112,108,2,111,87,90,124 };
  test.disable_feature = disabled_features;
  test.test_name = "tests::test_bpf_loader_upgradeable_upgrade";
  test.test_nonce  = 51;
  test.test_number = 1563;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 7;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111114ZRPS7huoEYiUYMXSZDsVmKdasnAui9FMFu",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "BPFLoaderUpgradeab1e11111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 17184240UL;
  test_acc->result_lamports = 17184240UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1563_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1563_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1563_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1563_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111114XQhRCARMgeQ6TBq1S8CuLhGejFtC9yLBgB",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "BPFLoaderUpgradeab1e11111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1141440UL;
  test_acc->result_lamports = 1141440UL;
  test_acc->executable      = 1;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1563_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1563_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1563_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1563_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111113AYTCCsztXHaNAEW2dtvSJ7vTNPPJp4zugb",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "BPFLoaderUpgradeab1e11111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1563_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1563_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1563_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1563_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111114Xp32BGiePpryGcy6TYYDppYSMm98sCv1zX",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "1111114YciE9VKDpBniuVFGWPCro561cmf2Hg5gdD",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1563_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1563_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1563_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1563_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1563_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1563_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1563_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1563_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1563_acc_5_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1563_acc_5_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1563_acc_5_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1563_acc_5_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111113AwnoBzJBEU3Eyfe7fKFknFCEzteFXJajzw",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "1111114Z23q8bcWXNFbivPMXoYBHCMoFGuxzufWwZ",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1563_acc_6_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1563_acc_6_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1563_acc_6_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1563_acc_6_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "BPFLoaderUpgradeab1e11111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1563_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1563_raw_sz;
  test.expected_result = -2;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1564(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 125,15,24,56,106,98,78,77,27,89,128,113,55,103,80,114,29,82,79,92,75,33,30,62,121,105,76,61,118,110,116,126,109,127,83,117,122,120,26,123,112,108,2,111,87,90,124 };
  test.disable_feature = disabled_features;
  test.test_name = "tests::test_bpf_loader_upgradeable_upgrade";
  test.test_nonce  = 52;
  test.test_number = 1564;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 7;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "DGSZQVGauc9Z6qVfDKM9tto4WATj7fQyAnQ3VfXEtcMt",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "BPFLoaderUpgradeab1e11111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 17184240UL;
  test_acc->result_lamports = 17184240UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1564_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1564_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1564_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1564_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111114hsV6nzAr9LSsiTTG52sBwxM76Naie4Vqu9",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "BPFLoaderUpgradeab1e11111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1141440UL;
  test_acc->result_lamports = 1141440UL;
  test_acc->executable      = 1;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1564_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1564_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1564_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1564_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111113AYTCCsztXHaNAEW2dtvSJ7vTNPPJp4zugb",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "BPFLoaderUpgradeab1e11111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1564_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1564_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1564_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1564_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111114iGphn6U8rWukXtbM6TCWS5ctisqfMJ5gDV",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "1111114j5VukK4iGsqWAksX9Hs9QLATytMYmmFLrB",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1564_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1564_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1564_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1564_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1564_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1564_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1564_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1564_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1564_acc_5_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1564_acc_5_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1564_acc_5_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1564_acc_5_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111113AwnoBzJBEU3Eyfe7fKFknFCEzteFXJajzw",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "1111114jUqWjRMzz4JNzC1cAiCTtTSFcPcVUzqBAX",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1564_acc_6_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1564_acc_6_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1564_acc_6_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1564_acc_6_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "BPFLoaderUpgradeab1e11111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1564_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1564_raw_sz;
  test.expected_result = -2;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1565(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 125,15,24,56,106,98,78,77,27,89,128,113,55,103,80,114,29,82,79,92,75,33,30,62,121,105,76,61,118,110,116,126,109,127,83,117,122,120,26,123,112,108,2,111,87,90,124 };
  test.disable_feature = disabled_features;
  test.test_name = "tests::test_bpf_loader_upgradeable_upgrade";
  test.test_nonce  = 54;
  test.test_number = 1565;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 7;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "Bxcf5XfJK7cpYGAVL9jKbXXFNzjm7h4tgnYNnNMP2iJX",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "BPFLoaderUpgradeab1e11111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 17184240UL;
  test_acc->result_lamports = 17184240UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1565_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1565_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1565_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1565_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111114qvFAVA8cLwiQ58EzZRXZeTnqgTjarkAWE3",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "BPFLoaderUpgradeab1e11111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1141440UL;
  test_acc->result_lamports = 1141440UL;
  test_acc->executable      = 1;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1565_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1565_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1565_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1565_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111113AYTCCsztXHaNAEW2dtvSJ7vTNPPJp4zugb",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "BPFLoaderUpgradeab1e11111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1565_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1565_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1565_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1565_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111114rKamUGRu48BGtZP5aqrt8b4dJxzXZykLYP",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "1111114s8FySV2UUV72XRfFdgXX6qcCZyWQzSv1B5",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1565_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1565_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1565_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1565_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1565_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1565_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1565_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1565_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1565_acc_5_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1565_acc_5_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1565_acc_5_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1565_acc_5_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111113AwnoBzJBEU3Eyfe7fKFknFCEzteFXJajzw",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "1111114sXbaRbKmBfZuLroLf6rqaxszCUmMhgVqVR",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1565_acc_6_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1565_acc_6_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1565_acc_6_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1565_acc_6_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "BPFLoaderUpgradeab1e11111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1565_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1565_raw_sz;
  test.expected_result = -5;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1566(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 125,15,24,56,106,98,78,77,27,89,128,113,55,103,80,114,29,82,79,92,75,33,30,62,121,105,76,61,118,110,116,126,109,127,83,117,122,120,26,123,112,108,2,111,87,90,124 };
  test.disable_feature = disabled_features;
  test.test_name = "tests::test_bpf_loader_upgradeable_upgrade";
  test.test_nonce  = 55;
  test.test_number = 1566;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 7;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "HH9twTv9TVYw7czA9LY7tx6AqDirNzimpXFxCg7MKTmr",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "BPFLoaderUpgradeab1e11111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 17184240UL;
  test_acc->result_lamports = 17184240UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1566_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1566_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1566_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1566_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111114zNLqASPfFjSoFEAp5EXFq6WMu49PnfQzsH",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "BPFLoaderUpgradeab1e11111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1141440UL;
  test_acc->result_lamports = 1141440UL;
  test_acc->executable      = 1;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1566_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1566_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1566_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1566_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111113AYTCCsztXHaNAEW2dtvSJ7vTNPPJp4zugb",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "BPFLoaderUpgradeab1e11111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1566_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1566_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1566_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1566_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111114zmgS9Ygwxuug4fJu6eraKDn9XZQLVtzqBd",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111151aMe7mHXPGqRhXb59VXDHUKinZvDvNAVpK",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1566_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1566_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1566_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1566_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1566_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1566_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1566_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1566_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1566_acc_5_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1566_acc_5_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1566_acc_5_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1566_acc_5_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111113AwnoBzJBEU3Eyfe7fKFknFCEzteFXJajzw",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111151yhF6sap6TJJWxjAAurXmbbWR5BAdbkL8f",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1566_acc_6_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1566_acc_6_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1566_acc_6_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1566_acc_6_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "BPFLoaderUpgradeab1e11111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1566_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1566_raw_sz;
  test.expected_result = -4;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1567(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 125,15,24,56,106,98,78,77,27,89,128,113,55,103,80,114,29,82,79,92,75,33,30,62,121,105,76,61,118,110,116,126,109,127,83,117,122,120,26,123,112,108,2,111,87,90,124 };
  test.disable_feature = disabled_features;
  test.test_name = "tests::test_bpf_loader_upgradeable_upgrade";
  test.test_nonce  = 56;
  test.test_number = 1567;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 7;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "HyygUzroLi7zPqHGkLuQWHUjWSPVtSbteuK2y793TCup",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "BPFLoaderUpgradeab1e11111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 17184240UL;
  test_acc->result_lamports = 17184240UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1567_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1567_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1567_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1567_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "111111581mHsW48kAFSnTpTYCrK3UgJre3KJ7Vpsq",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "BPFLoaderUpgradeab1e11111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1141440UL;
  test_acc->result_lamports = 1141440UL;
  test_acc->executable      = 1;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1567_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1567_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1567_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1567_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111113AYTCCsztXHaNAEW2dtvSJ7vTNPPJp4zugb",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "BPFLoaderUpgradeab1e11111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1567_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1567_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1567_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1567_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111158R6trcMRTLiKbtxYZdBdXbx6V9JG1M5fCB",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111159Dn6ppwzshe5EmEicTrGVrVfk9p9RpFKps",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1567_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1567_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1567_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1567_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1567_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1567_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1567_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1567_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1567_acc_5_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1567_acc_5_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1567_acc_5_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1567_acc_5_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111113AwnoBzJBEU3Eyfe7fKFknFCEzteFXJajzw",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111159d7howFHat6x4CNodtBayymTNf5693qA9D",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1567_acc_6_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1567_acc_6_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1567_acc_6_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1567_acc_6_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "BPFLoaderUpgradeab1e11111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1567_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1567_raw_sz;
  test.expected_result = -44;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1568(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 125,15,24,56,106,98,78,77,27,89,128,113,55,103,80,114,29,82,79,92,75,33,30,62,121,105,76,61,118,110,116,126,109,127,83,117,122,120,26,123,112,108,2,111,87,90,124 };
  test.disable_feature = disabled_features;
  test.test_name = "tests::test_bpf_loader_upgradeable_upgrade";
  test.test_nonce  = 57;
  test.test_number = 1568;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 7;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "6BP1RvKWwyruqGPSV4vj3H3DrCBtZFVF3mURK5napGYY",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "BPFLoaderUpgradeab1e11111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 17184240UL;
  test_acc->result_lamports = 17184240UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1568_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1568_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1568_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1568_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111115GsCZXtcUN8SimztN5SBKiEfchji4wGL9qR",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "BPFLoaderUpgradeab1e11111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1141440UL;
  test_acc->result_lamports = 1141440UL;
  test_acc->executable      = 1;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1568_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1568_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1568_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1568_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111113AYTCCsztXHaNAEW2dtvSJ7vTNPPJp4zugb",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "BPFLoaderUpgradeab1e11111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1568_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1568_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1568_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1568_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111115HGYAWzum5JubbS2T6rWeCMwQLEy1eVuz9m",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "1111115J5DNVDWLVfqMEJJd9hBHAcUybFUu4y5enT",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1568_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1568_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1568_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1568_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1568_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1568_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1568_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1568_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1568_acc_5_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1568_acc_5_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1568_acc_5_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1568_acc_5_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111113AwnoBzJBEU3Eyfe7fKFknFCEzteFXJajzw",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "1111115JUYyUKodCrJE3jSiB7WbejkmDkjqnCfV6o",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1568_acc_6_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1568_acc_6_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1568_acc_6_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1568_acc_6_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "BPFLoaderUpgradeab1e11111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1568_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1568_raw_sz;
  test.expected_result = -44;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1569(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 125,15,24,56,106,98,78,77,27,89,128,113,55,103,80,114,29,82,79,92,75,33,30,62,121,105,76,61,118,110,116,126,109,127,83,117,122,120,26,123,112,108,2,111,87,90,124 };
  test.disable_feature = disabled_features;
  test.test_name = "tests::test_bpf_loader_upgradeable_upgrade";
  test.test_nonce  = 60;
  test.test_number = 1569;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 7;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "qbP2q6u5VrfjAscmMt7P2WcJArUEZpbHYvknUFTnL14",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "BPFLoaderUpgradeab1e11111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 17184240UL;
  test_acc->result_lamports = 17184240UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1569_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1569_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1569_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1569_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111115S7ySBPU6hH6say6Me5qes7viBLdmHekK7M",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "BPFLoaderUpgradeab1e11111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1141440UL;
  test_acc->result_lamports = 1141440UL;
  test_acc->executable      = 1;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1569_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1569_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1569_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1569_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111113AYTCCsztXHaNAEW2dtvSJ7vTNPPJp4zugb",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "BPFLoaderUpgradeab1e11111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1569_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1569_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1569_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1569_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111115SXK3AVmPQTZkQQESfWAyMFCVoqthztL9Rh",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "1111115TKzF8iMxppVW3GWciLqcKVk54rQbRMVp4P",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1569_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1569_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1569_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1569_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1569_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1569_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1569_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1569_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1569_acc_5_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1569_acc_5_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1569_acc_5_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1569_acc_5_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111113AwnoBzJBEU3Eyfe7fKFknFCEzteFXJajzw",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "1111115TjKr7pfFXzxNrhehjmAvod1rhMfY8b5eNj",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1569_acc_6_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1569_acc_6_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1569_acc_6_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1569_acc_6_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "BPFLoaderUpgradeab1e11111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1569_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1569_raw_sz;
  test.expected_result = -44;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1570(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 123,111,33,116,26,92,105,2,90,61,122,113,82,30,80,127,117,89,112,62,120,114,103,29,125,110,78,76,121,77,108,75,98,24,27,56,83,124,106,55,79,126,118,128,87,15,109 };
  test.disable_feature = disabled_features;
  test.test_name = "tests::test_bpf_loader_upgradeable_write";
  test.test_nonce  = 12;
  test.test_number = 1570;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 1;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111113BM8QB6bTweW7o6nCgjb5GNU2dPuCEYAaKH",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "BPFLoaderUpgradeab1e11111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1570_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1570_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1570_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1570_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "BPFLoaderUpgradeab1e11111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1570_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1570_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1571(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 118,125,30,108,98,89,121,116,117,114,120,55,123,92,126,124,33,77,105,15,29,112,110,26,122,80,83,62,79,27,75,113,128,90,76,24,56,127,111,2,61,109,106,78,82,103,87 };
  test.disable_feature = disabled_features;
  test.test_name = "tests::test_bpf_loader_upgradeable_write";
  test.test_nonce  = 36;
  test.test_number = 1571;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 1;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111113BM8QB6bTweW7o6nCgjb5GNU2dPuCEYAaKH",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "BPFLoaderUpgradeab1e11111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1571_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1571_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1571_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1571_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "BPFLoaderUpgradeab1e11111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1571_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1571_raw_sz;
  test.expected_result = -8;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1572(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 77,98,62,2,124,56,117,33,61,111,120,128,106,121,78,82,76,123,118,30,116,27,55,75,122,87,26,103,112,127,89,114,125,83,29,108,79,92,109,113,105,126,80,90,24,15,110 };
  test.disable_feature = disabled_features;
  test.test_name = "tests::test_bpf_loader_upgradeable_write";
  test.test_nonce  = 5;
  test.test_number = 1572;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 1;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111113BM8QB6bTweW7o6nCgjb5GNU2dPuCEYAaKH",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "BPFLoaderUpgradeab1e11111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1572_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1572_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1572_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1572_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "BPFLoaderUpgradeab1e11111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1572_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1572_raw_sz;
  test.expected_result = -4;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1573(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 77,98,62,2,124,56,117,33,61,111,120,128,106,121,78,82,76,123,118,30,116,27,55,75,122,87,26,103,112,127,89,114,125,83,29,108,79,92,109,113,105,126,80,90,24,15,110 };
  test.disable_feature = disabled_features;
  test.test_name = "tests::test_bpf_loader_upgradeable_write";
  test.test_nonce  = 12;
  test.test_number = 1573;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 1;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111113CxUp7XncnNMd4qLYnQvMCsZB9Qvy5UVuaf",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "BPFLoaderUpgradeab1e11111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1573_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1573_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1573_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1573_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "BPFLoaderUpgradeab1e11111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1573_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1573_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1574(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 77,98,62,2,124,56,117,33,61,111,120,128,106,121,78,82,76,123,118,30,116,27,55,75,122,87,26,103,112,127,89,114,125,83,29,108,79,92,109,113,105,126,80,90,24,15,110 };
  test.disable_feature = disabled_features;
  test.test_name = "tests::test_bpf_loader_upgradeable_write";
  test.test_nonce  = 30;
  test.test_number = 1574;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 1;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111113CxUp7XncnNMd4qLYnQvMCsZB9Qvy5UVuaf",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "BPFLoaderUpgradeab1e11111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1574_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1574_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1574_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1574_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "BPFLoaderUpgradeab1e11111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1574_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1574_raw_sz;
  test.expected_result = -8;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
