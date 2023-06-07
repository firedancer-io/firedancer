#include "../fd_tests.h"
int test_850(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 1;
  uchar disabled_features[] = { 89 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_split_split_not_uninitialized::old_behavior";
  test.test_nonce  = 224;
  test.test_number = 850;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 2;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "2GMLBtqE2TDukq4vEZLAcsFgWq98WTqdFo8kBubK8Zt1",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 42UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_850_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_850_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_850_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_850_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "DZQnG3YvLc37ZSiQRCRqsg5uSRugEo7MC6e6YXTRCW59",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_850_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_850_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_850_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_850_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_850_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_850_raw_sz;
  test.expected_result = -4;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_851(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 1;
  uchar disabled_features[] = { 89 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_split_split_not_uninitialized::old_behavior";
  test.test_nonce  = 250;
  test.test_number = 851;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 2;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "2GMLBtqE2TDukq4vEZLAcsFgWq98WTqdFo8kBubK8Zt1",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 42UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_851_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_851_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_851_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_851_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "DZQnG3YvLc37ZSiQRCRqsg5uSRugEo7MC6e6YXTRCW59",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_851_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_851_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_851_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_851_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_851_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_851_raw_sz;
  test.expected_result = -4;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_852(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 27,126,29,79,83,128,33,127,24,82,125,123,114,30,61,122,117,111,98,121,55,106,116,15,56,80,113,62,110,92,118,2,109,89,77,87,26,90,108,78,103,76,105,112,75,124,120 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_split_to_account_with_rent_exempt_reserve::new_behavior";
  test.test_nonce  = 157;
  test.test_number = 852;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "AgVJV5oFebsbwC1NbvhQ5CCGxDyNVFtyqdBk9ZQMBBKQ",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2004565760UL;
  test_acc->result_lamports = 2004565760UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_852_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_852_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_852_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_852_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "FkEMp93msm5684r2i1q1R5C5jaijkFy84nDTg9dCTbZF",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2282879UL;
  test_acc->result_lamports = 2282879UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_852_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_852_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_852_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_852_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_852_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_852_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_852_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_852_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_852_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_852_raw_sz;
  test.expected_result = -6;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_853(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 27,126,29,79,83,128,33,127,24,82,125,123,114,30,61,122,117,111,98,121,55,106,116,15,56,80,113,62,110,92,118,2,109,89,77,87,26,90,108,78,103,76,105,112,75,124,120 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_split_to_account_with_rent_exempt_reserve::new_behavior";
  test.test_nonce  = 234;
  test.test_number = 853;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "AgVJV5oFebsbwC1NbvhQ5CCGxDyNVFtyqdBk9ZQMBBKQ",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2004565760UL;
  test_acc->result_lamports = 2004565760UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_853_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_853_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_853_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_853_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "FkEMp93msm5684r2i1q1R5C5jaijkFy84nDTg9dCTbZF",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2282880UL;
  test_acc->result_lamports = 2282880UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_853_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_853_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_853_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_853_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_853_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_853_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_853_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_853_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_853_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_853_raw_sz;
  test.expected_result = -6;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_854(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 27,126,29,79,83,128,33,127,24,82,125,123,114,30,61,122,117,111,98,121,55,106,116,15,56,80,113,62,110,92,118,2,109,89,77,87,26,90,108,78,103,76,105,112,75,124,120 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_split_to_account_with_rent_exempt_reserve::new_behavior";
  test.test_nonce  = 268;
  test.test_number = 854;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "AgVJV5oFebsbwC1NbvhQ5CCGxDyNVFtyqdBk9ZQMBBKQ",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2004565760UL;
  test_acc->result_lamports = 2004565760UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_854_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_854_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_854_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_854_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "FkEMp93msm5684r2i1q1R5C5jaijkFy84nDTg9dCTbZF",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1002282879UL;
  test_acc->result_lamports = 1002282879UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_854_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_854_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_854_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_854_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_854_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_854_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_854_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_854_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_854_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_854_raw_sz;
  test.expected_result = -6;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_855(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 27,126,29,79,83,128,33,127,24,82,125,123,114,30,61,122,117,111,98,121,55,106,116,15,56,80,113,62,110,92,118,2,109,89,77,87,26,90,108,78,103,76,105,112,75,124,120 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_split_to_account_with_rent_exempt_reserve::new_behavior";
  test.test_nonce  = 312;
  test.test_number = 855;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "AgVJV5oFebsbwC1NbvhQ5CCGxDyNVFtyqdBk9ZQMBBKQ",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2004565760UL;
  test_acc->result_lamports = 2004565760UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_855_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_855_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_855_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_855_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "FkEMp93msm5684r2i1q1R5C5jaijkFy84nDTg9dCTbZF",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1002282880UL;
  test_acc->result_lamports = 1002282880UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_855_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_855_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_855_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_855_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_855_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_855_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_855_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_855_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_855_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_855_raw_sz;
  test.expected_result = -6;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_856(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 27,126,29,79,83,128,33,127,24,82,125,123,114,30,61,122,117,111,98,121,55,106,116,15,56,80,113,62,110,92,118,2,109,89,77,87,26,90,108,78,103,76,105,112,75,124,120 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_split_to_account_with_rent_exempt_reserve::new_behavior";
  test.test_nonce  = 84;
  test.test_number = 856;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "AgVJV5oFebsbwC1NbvhQ5CCGxDyNVFtyqdBk9ZQMBBKQ",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2004565760UL;
  test_acc->result_lamports = 2004565760UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_856_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_856_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_856_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_856_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "FkEMp93msm5684r2i1q1R5C5jaijkFy84nDTg9dCTbZF",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_856_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_856_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_856_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_856_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_856_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_856_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_856_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_856_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_856_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_856_raw_sz;
  test.expected_result = -6;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_857(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 27,126,29,79,83,128,33,127,24,82,125,123,114,30,61,122,117,111,98,121,55,106,116,15,56,80,113,62,110,92,118,2,109,89,77,87,26,90,108,78,103,76,105,112,75,124,120 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_split_to_account_with_rent_exempt_reserve::new_behavior";
  test.test_nonce  = 138;
  test.test_number = 857;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "62YZeWnBPuNBUffXAZ1VjiWc9h5fYMDE1zVSa7aK1T1m",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2004565760UL;
  test_acc->result_lamports = 2004565760UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_857_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_857_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_857_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_857_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Nn8nDPsbmheaMxBtA3EP3LuSPLNH5naQJanmmntMGoW",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_857_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_857_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_857_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_857_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_857_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_857_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_857_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_857_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_857_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_857_raw_sz;
  test.expected_result = -6;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_858(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 27,126,29,79,83,128,33,127,24,82,125,123,114,30,61,122,117,111,98,121,55,106,116,15,56,80,113,62,110,92,118,2,109,89,77,87,26,90,108,78,103,76,105,112,75,124,120 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_split_to_account_with_rent_exempt_reserve::new_behavior";
  test.test_nonce  = 178;
  test.test_number = 858;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "62YZeWnBPuNBUffXAZ1VjiWc9h5fYMDE1zVSa7aK1T1m",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2004565760UL;
  test_acc->result_lamports = 2004565760UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_858_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_858_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_858_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_858_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Nn8nDPsbmheaMxBtA3EP3LuSPLNH5naQJanmmntMGoW",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2282879UL;
  test_acc->result_lamports = 2282879UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_858_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_858_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_858_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_858_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_858_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_858_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_858_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_858_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_858_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_858_raw_sz;
  test.expected_result = -6;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_859(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 27,126,29,79,83,128,33,127,24,82,125,123,114,30,61,122,117,111,98,121,55,106,116,15,56,80,113,62,110,92,118,2,109,89,77,87,26,90,108,78,103,76,105,112,75,124,120 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_split_to_account_with_rent_exempt_reserve::new_behavior";
  test.test_nonce  = 222;
  test.test_number = 859;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "62YZeWnBPuNBUffXAZ1VjiWc9h5fYMDE1zVSa7aK1T1m",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2004565760UL;
  test_acc->result_lamports = 2004565760UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_859_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_859_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_859_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_859_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Nn8nDPsbmheaMxBtA3EP3LuSPLNH5naQJanmmntMGoW",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2282880UL;
  test_acc->result_lamports = 2282880UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_859_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_859_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_859_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_859_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_859_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_859_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_859_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_859_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_859_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_859_raw_sz;
  test.expected_result = -6;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_860(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 27,126,29,79,83,128,33,127,24,82,125,123,114,30,61,122,117,111,98,121,55,106,116,15,56,80,113,62,110,92,118,2,109,89,77,87,26,90,108,78,103,76,105,112,75,124,120 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_split_to_account_with_rent_exempt_reserve::new_behavior";
  test.test_nonce  = 274;
  test.test_number = 860;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "62YZeWnBPuNBUffXAZ1VjiWc9h5fYMDE1zVSa7aK1T1m",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2004565760UL;
  test_acc->result_lamports = 2004565760UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_860_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_860_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_860_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_860_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Nn8nDPsbmheaMxBtA3EP3LuSPLNH5naQJanmmntMGoW",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1002282879UL;
  test_acc->result_lamports = 1002282879UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_860_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_860_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_860_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_860_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_860_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_860_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_860_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_860_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_860_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_860_raw_sz;
  test.expected_result = -6;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_861(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 27,126,29,79,83,128,33,127,24,82,125,123,114,30,61,122,117,111,98,121,55,106,116,15,56,80,113,62,110,92,118,2,109,89,77,87,26,90,108,78,103,76,105,112,75,124,120 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_split_to_account_with_rent_exempt_reserve::new_behavior";
  test.test_nonce  = 314;
  test.test_number = 861;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "62YZeWnBPuNBUffXAZ1VjiWc9h5fYMDE1zVSa7aK1T1m",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2004565760UL;
  test_acc->result_lamports = 2004565760UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_861_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_861_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_861_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_861_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Nn8nDPsbmheaMxBtA3EP3LuSPLNH5naQJanmmntMGoW",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1002282880UL;
  test_acc->result_lamports = 1002282880UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_861_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_861_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_861_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_861_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_861_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_861_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_861_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_861_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_861_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_861_raw_sz;
  test.expected_result = -6;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_862(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 27,126,29,79,83,128,33,127,24,82,125,123,114,30,61,122,117,111,98,121,55,106,116,15,56,80,113,62,110,92,118,2,109,89,77,87,26,90,108,78,103,76,105,112,75,124,120 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_split_to_account_with_rent_exempt_reserve::new_behavior";
  test.test_nonce  = 134;
  test.test_number = 862;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "AgVJV5oFebsbwC1NbvhQ5CCGxDyNVFtyqdBk9ZQMBBKQ",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2004565760UL;
  test_acc->result_lamports = 1002282880UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_862_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_862_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_862_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_862_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "FkEMp93msm5684r2i1q1R5C5jaijkFy84nDTg9dCTbZF",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 1002282880UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_862_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_862_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_862_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_862_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_862_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_862_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_862_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_862_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_862_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_862_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_863(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 27,126,29,79,83,128,33,127,24,82,125,123,114,30,61,122,117,111,98,121,55,106,116,15,56,80,113,62,110,92,118,2,109,89,77,87,26,90,108,78,103,76,105,112,75,124,120 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_split_to_account_with_rent_exempt_reserve::new_behavior";
  test.test_nonce  = 211;
  test.test_number = 863;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "AgVJV5oFebsbwC1NbvhQ5CCGxDyNVFtyqdBk9ZQMBBKQ",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2004565760UL;
  test_acc->result_lamports = 1002282880UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_863_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_863_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_863_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_863_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "FkEMp93msm5684r2i1q1R5C5jaijkFy84nDTg9dCTbZF",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2282879UL;
  test_acc->result_lamports = 1004565759UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_863_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_863_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_863_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_863_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_863_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_863_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_863_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_863_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_863_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_863_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_864(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 27,126,29,79,83,128,33,127,24,82,125,123,114,30,61,122,117,111,98,121,55,106,116,15,56,80,113,62,110,92,118,2,109,89,77,87,26,90,108,78,103,76,105,112,75,124,120 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_split_to_account_with_rent_exempt_reserve::new_behavior";
  test.test_nonce  = 247;
  test.test_number = 864;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "AgVJV5oFebsbwC1NbvhQ5CCGxDyNVFtyqdBk9ZQMBBKQ",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2004565760UL;
  test_acc->result_lamports = 1002282880UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_864_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_864_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_864_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_864_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "FkEMp93msm5684r2i1q1R5C5jaijkFy84nDTg9dCTbZF",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2282880UL;
  test_acc->result_lamports = 1004565760UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_864_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_864_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_864_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_864_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_864_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_864_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_864_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_864_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_864_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_864_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_865(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 27,126,29,79,83,128,33,127,24,82,125,123,114,30,61,122,117,111,98,121,55,106,116,15,56,80,113,62,110,92,118,2,109,89,77,87,26,90,108,78,103,76,105,112,75,124,120 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_split_to_account_with_rent_exempt_reserve::new_behavior";
  test.test_nonce  = 287;
  test.test_number = 865;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "AgVJV5oFebsbwC1NbvhQ5CCGxDyNVFtyqdBk9ZQMBBKQ",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2004565760UL;
  test_acc->result_lamports = 1002282880UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_865_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_865_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_865_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_865_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "FkEMp93msm5684r2i1q1R5C5jaijkFy84nDTg9dCTbZF",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1002282879UL;
  test_acc->result_lamports = 2004565759UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_865_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_865_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_865_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_865_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_865_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_865_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_865_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_865_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_865_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_865_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_866(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 27,126,29,79,83,128,33,127,24,82,125,123,114,30,61,122,117,111,98,121,55,106,116,15,56,80,113,62,110,92,118,2,109,89,77,87,26,90,108,78,103,76,105,112,75,124,120 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_split_to_account_with_rent_exempt_reserve::new_behavior";
  test.test_nonce  = 323;
  test.test_number = 866;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "AgVJV5oFebsbwC1NbvhQ5CCGxDyNVFtyqdBk9ZQMBBKQ",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2004565760UL;
  test_acc->result_lamports = 1002282880UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_866_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_866_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_866_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_866_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "FkEMp93msm5684r2i1q1R5C5jaijkFy84nDTg9dCTbZF",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1002282880UL;
  test_acc->result_lamports = 2004565760UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_866_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_866_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_866_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_866_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_866_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_866_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_866_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_866_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_866_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_866_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_867(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 27,126,29,79,83,128,33,127,24,82,125,123,114,30,61,122,117,111,98,121,55,106,116,15,56,80,113,62,110,92,118,2,109,89,77,87,26,90,108,78,103,76,105,112,75,124,120 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_split_to_account_with_rent_exempt_reserve::new_behavior";
  test.test_nonce  = 154;
  test.test_number = 867;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "62YZeWnBPuNBUffXAZ1VjiWc9h5fYMDE1zVSa7aK1T1m",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2004565760UL;
  test_acc->result_lamports = 1002282880UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_867_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_867_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_867_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_867_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Nn8nDPsbmheaMxBtA3EP3LuSPLNH5naQJanmmntMGoW",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 1002282880UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_867_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_867_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_867_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_867_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_867_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_867_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_867_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_867_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_867_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_867_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_868(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 27,126,29,79,83,128,33,127,24,82,125,123,114,30,61,122,117,111,98,121,55,106,116,15,56,80,113,62,110,92,118,2,109,89,77,87,26,90,108,78,103,76,105,112,75,124,120 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_split_to_account_with_rent_exempt_reserve::new_behavior";
  test.test_nonce  = 198;
  test.test_number = 868;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "62YZeWnBPuNBUffXAZ1VjiWc9h5fYMDE1zVSa7aK1T1m",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2004565760UL;
  test_acc->result_lamports = 1002282880UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_868_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_868_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_868_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_868_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Nn8nDPsbmheaMxBtA3EP3LuSPLNH5naQJanmmntMGoW",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2282879UL;
  test_acc->result_lamports = 1004565759UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_868_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_868_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_868_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_868_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_868_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_868_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_868_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_868_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_868_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_868_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_869(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 27,126,29,79,83,128,33,127,24,82,125,123,114,30,61,122,117,111,98,121,55,106,116,15,56,80,113,62,110,92,118,2,109,89,77,87,26,90,108,78,103,76,105,112,75,124,120 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_split_to_account_with_rent_exempt_reserve::new_behavior";
  test.test_nonce  = 259;
  test.test_number = 869;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "62YZeWnBPuNBUffXAZ1VjiWc9h5fYMDE1zVSa7aK1T1m",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2004565760UL;
  test_acc->result_lamports = 1002282880UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_869_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_869_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_869_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_869_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Nn8nDPsbmheaMxBtA3EP3LuSPLNH5naQJanmmntMGoW",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2282880UL;
  test_acc->result_lamports = 1004565760UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_869_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_869_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_869_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_869_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_869_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_869_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_869_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_869_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_869_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_869_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_870(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 27,126,29,79,83,128,33,127,24,82,125,123,114,30,61,122,117,111,98,121,55,106,116,15,56,80,113,62,110,92,118,2,109,89,77,87,26,90,108,78,103,76,105,112,75,124,120 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_split_to_account_with_rent_exempt_reserve::new_behavior";
  test.test_nonce  = 292;
  test.test_number = 870;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "62YZeWnBPuNBUffXAZ1VjiWc9h5fYMDE1zVSa7aK1T1m",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2004565760UL;
  test_acc->result_lamports = 1002282880UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_870_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_870_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_870_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_870_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Nn8nDPsbmheaMxBtA3EP3LuSPLNH5naQJanmmntMGoW",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1002282879UL;
  test_acc->result_lamports = 2004565759UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_870_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_870_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_870_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_870_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_870_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_870_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_870_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_870_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_870_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_870_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_871(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 27,126,29,79,83,128,33,127,24,82,125,123,114,30,61,122,117,111,98,121,55,106,116,15,56,80,113,62,110,92,118,2,109,89,77,87,26,90,108,78,103,76,105,112,75,124,120 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_split_to_account_with_rent_exempt_reserve::new_behavior";
  test.test_nonce  = 321;
  test.test_number = 871;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "62YZeWnBPuNBUffXAZ1VjiWc9h5fYMDE1zVSa7aK1T1m",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2004565760UL;
  test_acc->result_lamports = 1002282880UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_871_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_871_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_871_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_871_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Nn8nDPsbmheaMxBtA3EP3LuSPLNH5naQJanmmntMGoW",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1002282880UL;
  test_acc->result_lamports = 2004565760UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_871_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_871_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_871_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_871_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_871_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_871_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_871_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_871_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_871_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_871_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_872(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 27,121,123,24,126,111,80,109,124,90,92,77,30,56,83,79,78,113,125,2,118,75,87,26,89,106,105,116,110,120,108,62,82,117,29,122,15,127,128,76,55,33,114,103,61,112,98 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_split_to_account_with_rent_exempt_reserve::old_behavior";
  test.test_nonce  = 163;
  test.test_number = 872;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "9GL4NbsVF4Awba2CSnbtUicfGZdgaWWU1CHba2VuDh9s",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 4565762UL;
  test_acc->result_lamports = 4565762UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_872_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_872_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_872_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_872_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "cfbLU4D6kkFVDumFJ35SGLfaYQjbcL4LxA1nuszGLsv",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2282879UL;
  test_acc->result_lamports = 2282879UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_872_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_872_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_872_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_872_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_872_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_872_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_872_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_872_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_872_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_872_raw_sz;
  test.expected_result = -6;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_873(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 27,121,123,24,126,111,80,109,124,90,92,77,30,56,83,79,78,113,125,2,118,75,87,26,89,106,105,116,110,120,108,62,82,117,29,122,15,127,128,76,55,33,114,103,61,112,98 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_split_to_account_with_rent_exempt_reserve::old_behavior";
  test.test_nonce  = 237;
  test.test_number = 873;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "9GL4NbsVF4Awba2CSnbtUicfGZdgaWWU1CHba2VuDh9s",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 4565762UL;
  test_acc->result_lamports = 4565762UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_873_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_873_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_873_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_873_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "cfbLU4D6kkFVDumFJ35SGLfaYQjbcL4LxA1nuszGLsv",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2282880UL;
  test_acc->result_lamports = 2282880UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_873_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_873_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_873_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_873_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_873_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_873_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_873_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_873_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_873_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_873_raw_sz;
  test.expected_result = -6;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_874(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 27,121,123,24,126,111,80,109,124,90,92,77,30,56,83,79,78,113,125,2,118,75,87,26,89,106,105,116,110,120,108,62,82,117,29,122,15,127,128,76,55,33,114,103,61,112,98 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_split_to_account_with_rent_exempt_reserve::old_behavior";
  test.test_nonce  = 290;
  test.test_number = 874;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "9GL4NbsVF4Awba2CSnbtUicfGZdgaWWU1CHba2VuDh9s",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 4565762UL;
  test_acc->result_lamports = 4565762UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_874_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_874_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_874_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_874_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "cfbLU4D6kkFVDumFJ35SGLfaYQjbcL4LxA1nuszGLsv",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2282880UL;
  test_acc->result_lamports = 2282880UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_874_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_874_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_874_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_874_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_874_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_874_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_874_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_874_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_874_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_874_raw_sz;
  test.expected_result = -6;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
