#include "../fd_tests.h"
int test_1725(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 123,76,118,80,27,112,124,126,87,125,2,90,61,30,121,83,92,108,33,29,55,24,120,26,128,103,106,82,75,117,127,98,79,114,122,78,111,77,116,109,113,105,89,110,56,62,15 };
  test.disable_feature = disabled_features;
  test.test_name = "vote_processor::tests::test_vote_withdraw";
  test.test_nonce  = 68;
  test.test_number = 1725;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 4;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "GaKyKdk6VewrKiEbgaAFwR2fesBu8Bx2bW5CSwpfD5gD",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 26858640UL;
  test_acc->result_lamports = 26858598UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1725_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1725_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1725_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1725_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1725_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1725_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1725_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1725_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1725_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1725_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1725_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1725_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "9oy7bvcoZ4bYL5PUiQ6xGWBTE2exdZjTLhpM23Y1kjZ3",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 42UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1725_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1725_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1725_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1725_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1725_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1725_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1726(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 83,128,55,121,76,109,77,92,106,110,80,61,82,29,108,105,89,98,116,87,15,24,90,78,114,120,30,111,56,2,117,122,123,75,127,27,113,103,33,126,124,118,26,79,62,112,125 };
  test.disable_feature = disabled_features;
  test.test_name = "vote_processor::tests::test_vote_withdraw";
  test.test_nonce  = 40;
  test.test_number = 1726;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 4;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "2v7ibcAKT78LDQV48eNdxk6WeHdJjSq4QF7e6Ao6T961",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 26858640UL;
  test_acc->result_lamports = 26858640UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1726_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1726_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1726_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1726_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1726_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1726_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1726_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1726_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1726_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1726_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1726_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1726_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "AgrAibrNFysBYA4e4jkKSB55j6sXx7xtuAiR8vchBRaa",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1726_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1726_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1726_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1726_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1726_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1726_raw_sz;
  test.expected_result = -8;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1727(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 113,123,120,29,128,61,110,75,105,98,127,125,126,87,83,82,106,112,92,79,33,80,108,117,2,15,90,122,124,26,89,24,76,55,78,27,56,121,103,114,111,109,30,116,118,62,77 };
  test.disable_feature = disabled_features;
  test.test_name = "vote_processor::tests::test_vote_withdraw";
  test.test_nonce  = 52;
  test.test_number = 1727;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 4;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "2v7ibcAKT78LDQV48eNdxk6WeHdJjSq4QF7e6Ao6T961",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 26858640UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1727_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1727_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1727_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1727_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1727_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1727_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1727_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1727_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1727_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1727_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1727_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1727_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "AgrAibrNFysBYA4e4jkKSB55j6sXx7xtuAiR8vchBRaa",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 26858640UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1727_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1727_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1727_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1727_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1727_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1727_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1728(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 121,24,128,123,116,76,55,90,79,110,27,62,89,83,117,92,78,111,2,109,120,29,33,26,108,56,114,75,113,126,124,15,77,106,103,125,105,98,87,61,30,112,118,122,80,127,82 };
  test.disable_feature = disabled_features;
  test.test_name = "vote_processor::tests::test_vote_withdraw";
  test.test_nonce  = 25;
  test.test_number = 1728;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 4;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "2v7ibcAKT78LDQV48eNdxk6WeHdJjSq4QF7e6Ao6T961",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 26858640UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1728_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1728_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1728_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1728_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1728_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1728_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1728_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1728_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1728_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1728_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1728_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1728_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "AgrAibrNFysBYA4e4jkKSB55j6sXx7xtuAiR8vchBRaa",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 26858640UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1728_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1728_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1728_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1728_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1728_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1728_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1729(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 121,24,128,123,116,76,55,90,79,110,27,62,89,83,117,92,78,111,2,109,120,29,33,26,108,56,114,75,113,126,124,15,77,106,103,125,105,98,87,61,30,112,118,122,80,127,82 };
  test.disable_feature = disabled_features;
  test.test_name = "vote_processor::tests::test_vote_withdraw";
  test.test_nonce  = 29;
  test.test_number = 1729;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 4;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "GaKyKdk6VewrKiEbgaAFwR2fesBu8Bx2bW5CSwpfD5gD",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 26858640UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1729_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1729_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1729_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1729_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1729_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1729_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1729_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1729_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1729_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1729_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1729_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1729_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "9oy7bvcoZ4bYL5PUiQ6xGWBTE2exdZjTLhpM23Y1kjZ3",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 26858640UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1729_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1729_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1729_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1729_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1729_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1729_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1730(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 121,24,128,123,116,76,55,90,79,110,27,62,89,83,117,92,78,111,2,109,120,29,33,26,108,56,114,75,113,126,124,15,77,106,103,125,105,98,87,61,30,112,118,122,80,127,82 };
  test.disable_feature = disabled_features;
  test.test_name = "vote_processor::tests::test_vote_withdraw";
  test.test_nonce  = 42;
  test.test_number = 1730;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 4;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "GaKyKdk6VewrKiEbgaAFwR2fesBu8Bx2bW5CSwpfD5gD",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 26858640UL;
  test_acc->result_lamports = 26858640UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1730_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1730_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1730_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1730_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1730_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1730_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1730_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1730_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1730_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1730_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1730_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1730_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "9oy7bvcoZ4bYL5PUiQ6xGWBTE2exdZjTLhpM23Y1kjZ3",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1730_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1730_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1730_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1730_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1730_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1730_raw_sz;
  test.expected_result = -8;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1731(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 121,24,128,123,116,76,55,90,79,110,27,62,89,83,117,92,78,111,2,109,120,29,33,26,108,56,114,75,113,126,124,15,77,106,103,125,105,98,87,61,30,112,118,122,80,127,82 };
  test.disable_feature = disabled_features;
  test.test_name = "vote_processor::tests::test_vote_withdraw";
  test.test_nonce  = 54;
  test.test_number = 1731;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 4;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "GaKyKdk6VewrKiEbgaAFwR2fesBu8Bx2bW5CSwpfD5gD",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 26858640UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1731_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1731_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1731_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1731_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1731_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1731_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1731_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1731_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1731_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1731_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1731_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1731_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "9oy7bvcoZ4bYL5PUiQ6xGWBTE2exdZjTLhpM23Y1kjZ3",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 26858640UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1731_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1731_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1731_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1731_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1731_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1731_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1732(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 127,80,125,116,26,15,114,83,55,30,77,2,110,117,124,128,121,126,79,90,109,120,103,122,56,87,29,24,76,92,62,112,78,123,108,75,89,27,33,61,106,113,111,105,82,118,98 };
  test.disable_feature = disabled_features;
  test.test_name = "vote_processor::tests::test_vote_withdraw";
  test.test_nonce  = 62;
  test.test_number = 1732;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 4;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "2v7ibcAKT78LDQV48eNdxk6WeHdJjSq4QF7e6Ao6T961",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 26858640UL;
  test_acc->result_lamports = 26858640UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1732_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1732_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1732_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1732_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1732_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1732_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1732_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1732_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1732_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1732_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1732_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1732_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "AgrAibrNFysBYA4e4jkKSB55j6sXx7xtuAiR8vchBRaa",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1732_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1732_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1732_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1732_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1732_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1732_raw_sz;
  test.expected_result = -6;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1733(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 127,80,125,116,26,15,114,83,55,30,77,2,110,117,124,128,121,126,79,90,109,120,103,122,56,87,29,24,76,92,62,112,78,123,108,75,89,27,33,61,106,113,111,105,82,118,98 };
  test.disable_feature = disabled_features;
  test.test_name = "vote_processor::tests::test_vote_withdraw";
  test.test_nonce  = 61;
  test.test_number = 1733;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 4;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "GaKyKdk6VewrKiEbgaAFwR2fesBu8Bx2bW5CSwpfD5gD",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 26858640UL;
  test_acc->result_lamports = 26858640UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1733_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1733_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1733_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1733_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1733_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1733_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1733_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1733_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1733_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1733_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1733_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1733_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "9oy7bvcoZ4bYL5PUiQ6xGWBTE2exdZjTLhpM23Y1kjZ3",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1733_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1733_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1733_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1733_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1733_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1733_raw_sz;
  test.expected_result = -6;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1734(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 127,80,125,116,26,15,114,83,55,30,77,2,110,117,124,128,121,126,79,90,109,120,103,122,56,87,29,24,76,92,62,112,78,123,108,75,89,27,33,61,106,113,111,105,82,118,98 };
  test.disable_feature = disabled_features;
  test.test_name = "vote_processor::tests::test_withdrawer_base_key_can_authorize_new_voter_checked";
  test.test_nonce  = 55;
  test.test_number = 1734;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 4;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111111FVAiSujNZVgYSc27t6zUTWoKfAGxbRzzPR",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1734_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1734_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1734_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1734_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1734_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1734_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1734_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1734_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111GhBXQEdEh35AtuSNxMzRutcgYg3nj8kVLT",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1734_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1734_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1734_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1734_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111R9HC5WtHbpoa51NCUAz86XLCmGTbf3zyyh",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1734_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1734_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1734_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1734_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1734_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1734_raw_sz;
  test.expected_result = -8;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1735(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 129;
  uchar disabled_features[] = { 52,33,27,7,23,88,98,84,105,22,57,49,29,21,124,51,63,8,13,48,119,78,59,17,106,14,50,28,10,53,1,107,101,117,67,100,94,31,108,4,43,0,30,46,65,80,122,70,55,41,87,123,77,115,96,68,86,116,35,36,16,25,114,125,15,92,111,120,89,56,20,71,26,40,9,83,128,12,74,75,112,81,76,42,64,109,45,34,82,90,93,32,54,39,113,103,5,95,66,11,38,73,37,18,121,127,99,126,19,97,72,102,85,79,58,110,44,60,62,69,3,6,2,47,61,24,104,91,118 };
  test.disable_feature = disabled_features;
  test.test_name = "vote_processor::tests::test_withdrawer_base_key_can_authorize_new_voter_checked";
  test.test_nonce  = 78;
  test.test_number = 1735;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 4;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111111FVAiSujNZVgYSc27t6zUTWoKfAGxbRzzPR",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1735_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1735_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1735_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1735_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1735_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1735_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1735_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1735_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111GhBXQEdEh35AtuSNxMzRutcgYg3nj8kVLT",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1735_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1735_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1735_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1735_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111R9HC5WtHbpoa51NCUAz86XLCmGTbf3zyyh",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1735_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1735_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1735_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1735_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1735_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1735_raw_sz;
  test.expected_result = -3;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1736(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 52,33,27,7,23,88,98,84,105,22,57,49,29,21,124,51,63,8,13,48,119,78,59,17,106,14,50,28,10,53,1,107,101,117,67,100,94,31,108,4,43,0,30,46,65,80,122,70,55,41,87,123,77,115,96,68,86,116,35,36,16,25,114,125,15,92,111,120,89,56,20,71,26,40,9,83,128,12,74,75,112,81,76,42,64,109,45,34,82,90,93,32,54,39,113,103,5,95,66,11,38,73,37,18,121,127,99,126,19,97,72,102,85,79,58,110,44,60,62,69,3,6,2,47,61,24,104,91,118 };
  test.disable_feature = disabled_features;
  test.test_name = "vote_processor::tests::test_withdrawer_base_key_can_authorize_new_voter_checked";
  test.test_nonce  = 18;
  test.test_number = 1736;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 4;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111111FVAiSujNZVgYSc27t6zUTWoKfAGxbRzzPR",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1736_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1736_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1736_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1736_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1736_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1736_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1736_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1736_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111GhBXQEdEh35AtuSNxMzRutcgYg3nj8kVLT",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1736_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1736_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1736_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1736_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111R9HC5WtHbpoa51NCUAz86XLCmGTbf3zyyh",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1736_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1736_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1736_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1736_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1736_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1736_raw_sz;
  test.expected_result = -8;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1737(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 52,33,27,7,23,88,98,84,105,22,57,49,29,21,124,51,63,8,13,48,119,78,59,17,106,14,50,28,10,53,1,107,101,117,67,100,94,31,108,4,43,0,30,46,65,80,122,70,55,41,87,123,77,115,96,68,86,116,35,36,16,25,114,125,15,92,111,120,89,56,20,71,26,40,9,83,128,12,74,75,112,81,76,42,64,109,45,34,82,90,93,32,54,39,113,103,5,95,66,11,38,73,37,18,121,127,99,126,19,97,72,102,85,79,58,110,44,60,62,69,3,6,2,47,61,24,104,91,118 };
  test.disable_feature = disabled_features;
  test.test_name = "vote_processor::tests::test_withdrawer_base_key_can_authorize_new_voter_checked";
  test.test_nonce  = 34;
  test.test_number = 1737;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 4;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111111FVAiSujNZVgYSc27t6zUTWoKfAGxbRzzPR",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1737_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1737_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1737_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1737_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1737_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1737_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1737_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1737_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111GhBXQEdEh35AtuSNxMzRutcgYg3nj8kVLT",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1737_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1737_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1737_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1737_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111R9HC5WtHbpoa51NCUAz86XLCmGTbf3zyyh",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1737_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1737_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1737_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1737_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1737_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1737_raw_sz;
  test.expected_result = -8;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1738(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 52,33,27,7,23,88,98,84,105,22,57,49,29,21,124,51,63,8,13,48,119,78,59,17,106,14,50,28,10,53,1,107,101,117,67,100,94,31,108,4,43,0,30,46,65,80,122,70,55,41,87,123,77,115,96,68,86,116,35,36,16,25,114,125,15,92,111,120,89,56,20,71,26,40,9,83,128,12,74,75,112,81,76,42,64,109,45,34,82,90,93,32,54,39,113,103,5,95,66,11,38,73,37,18,121,127,99,126,19,97,72,102,85,79,58,110,44,60,62,69,3,6,2,47,61,24,104,91,118 };
  test.disable_feature = disabled_features;
  test.test_name = "vote_processor::tests::test_withdrawer_base_key_can_authorize_new_voter_checked";
  test.test_nonce  = 73;
  test.test_number = 1738;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 4;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111111FVAiSujNZVgYSc27t6zUTWoKfAGxbRzzPR",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1738_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1738_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1738_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1738_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1738_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1738_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1738_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1738_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111GhBXQEdEh35AtuSNxMzRutcgYg3nj8kVLT",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1738_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1738_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1738_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1738_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111R9HC5WtHbpoa51NCUAz86XLCmGTbf3zyyh",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1738_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1738_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1738_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1738_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1738_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1738_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1739(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 120,87,56,83,110,108,117,2,27,116,75,122,127,111,124,89,82,125,126,112,77,26,33,15,123,103,105,29,90,121,62,78,113,30,128,55,114,118,109,24,76,79,98,61,80,92,106 };
  test.disable_feature = disabled_features;
  test.test_name = "vote_processor::tests::test_withdrawer_base_key_can_authorize_new_voter_checked";
  test.test_nonce  = 39;
  test.test_number = 1739;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 4;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111111GHqvR8KwyrcJ5UJHvwf7RmLtvAnr1uAf27",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1739_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1739_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1739_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1739_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1739_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1739_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1739_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1739_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111HVrjNTDp7PzvXmiZ1Cf4t9AFogZg9bv9y9",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1739_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1739_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1739_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1739_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111Qjwb6QazteLhFaE7SkeocQ4R8mCewpR9fM",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1739_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1739_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1739_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1739_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1739_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1739_raw_sz;
  test.expected_result = -8;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1740(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 129;
  uchar disabled_features[] = { 103,127,79,51,61,57,81,66,46,10,4,27,92,18,16,19,84,37,5,42,70,72,125,121,97,64,124,41,120,58,3,47,14,69,29,87,17,21,83,126,95,13,114,56,78,116,38,82,30,52,0,96,20,55,53,59,39,7,26,68,123,119,128,117,2,15,112,71,49,11,22,35,63,76,32,34,118,75,62,23,104,43,94,107,88,9,89,48,122,67,90,93,115,33,8,85,54,28,65,98,100,24,108,106,6,77,102,101,109,44,74,80,40,12,91,99,111,86,110,31,50,1,113,25,36,105,45,73,60 };
  test.disable_feature = disabled_features;
  test.test_name = "vote_processor::tests::test_withdrawer_base_key_can_authorize_new_voter_checked";
  test.test_nonce  = 73;
  test.test_number = 1740;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 4;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111111GHqvR8KwyrcJ5UJHvwf7RmLtvAnr1uAf27",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1740_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1740_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1740_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1740_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1740_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1740_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1740_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1740_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111HVrjNTDp7PzvXmiZ1Cf4t9AFogZg9bv9y9",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1740_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1740_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1740_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1740_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111Qjwb6QazteLhFaE7SkeocQ4R8mCewpR9fM",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1740_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1740_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1740_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1740_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1740_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1740_raw_sz;
  test.expected_result = -3;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1741(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 26,55,108,116,128,124,80,118,29,24,125,61,123,112,89,2,105,76,122,77,79,33,120,62,92,127,56,82,103,30,126,27,110,114,113,78,98,117,109,75,121,111,15,87,90,106,83 };
  test.disable_feature = disabled_features;
  test.test_name = "vote_processor::tests::test_withdrawer_base_key_can_authorize_new_voter_checked";
  test.test_nonce  = 14;
  test.test_number = 1741;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 4;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111111GHqvR8KwyrcJ5UJHvwf7RmLtvAnr1uAf27",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1741_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1741_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1741_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1741_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1741_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1741_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1741_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1741_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111HVrjNTDp7PzvXmiZ1Cf4t9AFogZg9bv9y9",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1741_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1741_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1741_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1741_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111Qjwb6QazteLhFaE7SkeocQ4R8mCewpR9fM",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1741_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1741_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1741_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1741_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1741_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1741_raw_sz;
  test.expected_result = -8;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1742(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 79,29,55,127,77,90,2,124,123,92,56,103,114,113,120,75,116,112,98,121,87,110,26,33,111,27,122,89,128,24,61,109,82,78,108,80,15,30,106,126,83,118,117,62,125,76,105 };
  test.disable_feature = disabled_features;
  test.test_name = "vote_processor::tests::test_withdrawer_base_key_can_authorize_new_voter_checked";
  test.test_nonce  = 63;
  test.test_number = 1742;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 4;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111111GHqvR8KwyrcJ5UJHvwf7RmLtvAnr1uAf27",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1742_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1742_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1742_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1742_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1742_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1742_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1742_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1742_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111HVrjNTDp7PzvXmiZ1Cf4t9AFogZg9bv9y9",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1742_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1742_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1742_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1742_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111Qjwb6QazteLhFaE7SkeocQ4R8mCewpR9fM",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1742_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1742_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1742_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1742_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1742_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1742_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1743(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 61,108,15,89,87,120,29,106,113,55,26,105,118,124,128,121,114,33,116,111,110,76,109,125,83,82,27,122,98,77,112,79,78,56,62,24,126,123,30,2,75,80,127,92,117,90,103 };
  test.disable_feature = disabled_features;
  test.test_name = "vote_processor::tests::test_withdrawer_base_key_can_authorize_new_voter_checked";
  test.test_nonce  = 26;
  test.test_number = 1743;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 4;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111111GHqvR8KwyrcJ5UJHvwf7RmLtvAnr1uAf27",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1743_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1743_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1743_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1743_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1743_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1743_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1743_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1743_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111HVrjNTDp7PzvXmiZ1Cf4t9AFogZg9bv9y9",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1743_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1743_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1743_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1743_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111Qjwb6QazteLhFaE7SkeocQ4R8mCewpR9fM",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1743_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1743_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1743_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1743_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1743_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1743_raw_sz;
  test.expected_result = -8;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1744(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 33,105,55,122,127,124,116,103,26,24,92,128,106,83,121,90,114,75,113,118,78,108,89,15,110,109,30,87,125,126,76,120,123,117,79,98,77,111,80,29,2,61,82,27,62,56,112 };
  test.disable_feature = disabled_features;
  test.test_name = "vote_processor::tests::test_withdrawer_base_key_can_authorize_new_voter_checked";
  test.test_nonce  = 51;
  test.test_number = 1744;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 4;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111111GHqvR8KwyrcJ5UJHvwf7RmLtvAnr1uAf27",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1744_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1744_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1744_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1744_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1744_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1744_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1744_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1744_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111HVrjNTDp7PzvXmiZ1Cf4t9AFogZg9bv9y9",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1744_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1744_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1744_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1744_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111Qjwb6QazteLhFaE7SkeocQ4R8mCewpR9fM",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1744_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1744_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1744_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1744_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1744_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1744_raw_sz;
  test.expected_result = -8;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1745(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 33,105,55,122,127,124,116,103,26,24,92,128,106,83,121,90,114,75,113,118,78,108,89,15,110,109,30,87,125,126,76,120,123,117,79,98,77,111,80,29,2,61,82,27,62,56,112 };
  test.disable_feature = disabled_features;
  test.test_name = "vote_processor::tests::test_withdrawer_base_key_can_authorize_new_voter_checked";
  test.test_nonce  = 66;
  test.test_number = 1745;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 4;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111111FVAiSujNZVgYSc27t6zUTWoKfAGxbRzzPR",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1745_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1745_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1745_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1745_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1745_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1745_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1745_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1745_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111GhBXQEdEh35AtuSNxMzRutcgYg3nj8kVLT",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1745_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1745_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1745_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1745_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111R9HC5WtHbpoa51NCUAz86XLCmGTbf3zyyh",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1745_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1745_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1745_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1745_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1745_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1745_raw_sz;
  test.expected_result = -8;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1746(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 33,105,55,122,127,124,116,103,26,24,92,128,106,83,121,90,114,75,113,118,78,108,89,15,110,109,30,87,125,126,76,120,123,117,79,98,77,111,80,29,2,61,82,27,62,56,112 };
  test.disable_feature = disabled_features;
  test.test_name = "vote_processor::tests::test_withdrawer_base_key_can_authorize_new_voter";
  test.test_nonce  = 35;
  test.test_number = 1746;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111111D596YFweJQuHY1BbjazZYmAbt8jJL2VzVM",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1746_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1746_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1746_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1746_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1746_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1746_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1746_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1746_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111EH9uVaqWRxHuzJbroqzX18yxmeW8TjFVSP",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1746_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1746_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1746_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1746_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1746_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1746_raw_sz;
  test.expected_result = -8;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1747(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 129;
  uchar disabled_features[] = { 118,107,17,50,38,60,15,28,74,98,84,71,99,22,83,40,106,29,21,125,6,87,80,68,25,65,24,109,11,45,85,116,12,63,58,43,97,46,127,5,91,41,35,0,33,42,77,126,75,61,26,49,69,57,115,8,100,3,113,51,96,34,54,19,52,73,18,114,95,103,123,119,31,47,66,70,67,102,7,30,105,128,4,27,1,13,89,78,14,37,32,79,76,72,44,59,120,117,64,62,48,81,92,104,94,121,108,124,88,10,53,9,56,122,82,86,55,101,23,16,112,39,111,36,110,93,90,2,20 };
  test.disable_feature = disabled_features;
  test.test_name = "vote_processor::tests::test_withdrawer_base_key_can_authorize_new_voter";
  test.test_nonce  = 76;
  test.test_number = 1747;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111111D596YFweJQuHY1BbjazZYmAbt8jJL2VzVM",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1747_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1747_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1747_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1747_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1747_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1747_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1747_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1747_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111EH9uVaqWRxHuzJbroqzX18yxmeW8TjFVSP",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1747_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1747_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1747_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1747_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1747_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1747_raw_sz;
  test.expected_result = -3;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1748(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 118,107,17,50,38,60,15,28,74,98,84,71,99,22,83,40,106,29,21,125,6,87,80,68,25,65,24,109,11,45,85,116,12,63,58,43,97,46,127,5,91,41,35,0,33,42,77,126,75,61,26,49,69,57,115,8,100,3,113,51,96,34,54,19,52,73,18,114,95,103,123,119,31,47,66,70,67,102,7,30,105,128,4,27,1,13,89,78,14,37,32,79,76,72,44,59,120,117,64,62,48,81,92,104,94,121,108,124,88,10,53,9,56,122,82,86,55,101,23,16,112,39,111,36,110,93,90,2,20 };
  test.disable_feature = disabled_features;
  test.test_name = "vote_processor::tests::test_withdrawer_base_key_can_authorize_new_voter";
  test.test_nonce  = 17;
  test.test_number = 1748;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111111D596YFweJQuHY1BbjazZYmAbt8jJL2VzVM",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1748_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1748_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1748_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1748_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1748_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1748_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1748_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1748_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111EH9uVaqWRxHuzJbroqzX18yxmeW8TjFVSP",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1748_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1748_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1748_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1748_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1748_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1748_raw_sz;
  test.expected_result = -8;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1749(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 118,107,17,50,38,60,15,28,74,98,84,71,99,22,83,40,106,29,21,125,6,87,80,68,25,65,24,109,11,45,85,116,12,63,58,43,97,46,127,5,91,41,35,0,33,42,77,126,75,61,26,49,69,57,115,8,100,3,113,51,96,34,54,19,52,73,18,114,95,103,123,119,31,47,66,70,67,102,7,30,105,128,4,27,1,13,89,78,14,37,32,79,76,72,44,59,120,117,64,62,48,81,92,104,94,121,108,124,88,10,53,9,56,122,82,86,55,101,23,16,112,39,111,36,110,93,90,2,20 };
  test.disable_feature = disabled_features;
  test.test_name = "vote_processor::tests::test_withdrawer_base_key_can_authorize_new_voter";
  test.test_nonce  = 67;
  test.test_number = 1749;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111111D596YFweJQuHY1BbjazZYmAbt8jJL2VzVM",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1749_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1749_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1749_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1749_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1749_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1749_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1749_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1749_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111EH9uVaqWRxHuzJbroqzX18yxmeW8TjFVSP",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1749_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1749_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1749_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1749_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1749_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1749_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
