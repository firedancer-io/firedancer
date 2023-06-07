#include "../fd_tests.h"
int test_800(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 55,56,62,27,78,109,128,24,106,121,2,15,80,92,113,118,127,120,98,116,124,30,123,105,76,111,29,110,89,117,126,33,125,114,75,103,87,122,61,79,112,90,77,83,82,108,26 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_split_rent_exemptness::new_behavior";
  test.test_nonce  = 262;
  test.test_number = 800;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "2NN7WHDQMYqzKmwFknPs9gW2V19MMxmPzX47nsi1wzQm",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1002978880UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_800_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_800_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_800_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_800_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "EkUBG7PMjzw2Gh5YeTEqpECZR1UiuAwyT9khmnE5Hzna",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 1002978880UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_800_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_800_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_800_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_800_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_800_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_800_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_800_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_800_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_800_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_800_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_801(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 55,56,62,27,78,109,128,24,106,121,2,15,80,92,113,118,127,120,98,116,124,30,123,105,76,111,29,110,89,117,126,33,125,114,75,103,87,122,61,79,112,90,77,83,82,108,26 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_split_rent_exemptness::new_behavior";
  test.test_nonce  = 289;
  test.test_number = 801;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "2NN7WHDQMYqzKmwFknPs9gW2V19MMxmPzX47nsi1wzQm",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1002978880UL;
  test_acc->result_lamports = 1002978880UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_801_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_801_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_801_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_801_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "EkUBG7PMjzw2Gh5YeTEqpECZR1UiuAwyT9khmnE5Hzna",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_801_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_801_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_801_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_801_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_801_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_801_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_801_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_801_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_801_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_801_raw_sz;
  test.expected_result = -4;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_802(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 55,56,62,27,78,109,128,24,106,121,2,15,80,92,113,118,127,120,98,116,124,30,123,105,76,111,29,110,89,117,126,33,125,114,75,103,87,122,61,79,112,90,77,83,82,108,26 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_split_rent_exemptness::new_behavior";
  test.test_nonce  = 363;
  test.test_number = 802;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "2NN7WHDQMYqzKmwFknPs9gW2V19MMxmPzX47nsi1wzQm",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1002978880UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_802_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_802_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_802_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_802_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "EkUBG7PMjzw2Gh5YeTEqpECZR1UiuAwyT9khmnE5Hzna",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 1002978880UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_802_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_802_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_802_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_802_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_802_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_802_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_802_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_802_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_802_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_802_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_803(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 55,56,62,27,78,109,128,24,106,121,2,15,80,92,113,118,127,120,98,116,124,30,123,105,76,111,29,110,89,117,126,33,125,114,75,103,87,122,61,79,112,90,77,83,82,108,26 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_split_rent_exemptness::new_behavior";
  test.test_nonce  = 55;
  test.test_number = 803;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "2NN7WHDQMYqzKmwFknPs9gW2V19MMxmPzX47nsi1wzQm",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1002978880UL;
  test_acc->result_lamports = 1002978880UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_803_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_803_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_803_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_803_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "EkUBG7PMjzw2Gh5YeTEqpECZR1UiuAwyT9khmnE5Hzna",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_803_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_803_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_803_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_803_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_803_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_803_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_803_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_803_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_803_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_803_raw_sz;
  test.expected_result = -4;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_804(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 55,56,62,27,78,109,128,24,106,121,2,15,80,92,113,118,127,120,98,116,124,30,123,105,76,111,29,110,89,117,126,33,125,114,75,103,87,122,61,79,112,90,77,83,82,108,26 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_split_rent_exemptness::new_behavior";
  test.test_nonce  = 131;
  test.test_number = 804;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "GGoW9u8zTzLhddFqU47qvCYpWFhAs6bgwJrmZSHANWYv",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1002978880UL;
  test_acc->result_lamports = 1002978880UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_804_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_804_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_804_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_804_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "47cSQw6bJ1Qh9pyJFMrNAVQYUskvetUtwvbEYRBrsazi",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_804_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_804_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_804_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_804_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_804_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_804_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_804_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_804_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_804_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_804_raw_sz;
  test.expected_result = -4;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_805(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 55,56,62,27,78,109,128,24,106,121,2,15,80,92,113,118,127,120,98,116,124,30,123,105,76,111,29,110,89,117,126,33,125,114,75,103,87,122,61,79,112,90,77,83,82,108,26 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_split_rent_exemptness::new_behavior";
  test.test_nonce  = 333;
  test.test_number = 805;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "GGoW9u8zTzLhddFqU47qvCYpWFhAs6bgwJrmZSHANWYv",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1002978880UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_805_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_805_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_805_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_805_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "47cSQw6bJ1Qh9pyJFMrNAVQYUskvetUtwvbEYRBrsazi",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 1002978880UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_805_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_805_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_805_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_805_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_805_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_805_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_805_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_805_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_805_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_805_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_806(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 55,56,62,27,78,109,128,24,106,121,2,15,80,92,113,118,127,120,98,116,124,30,123,105,76,111,29,110,89,117,126,33,125,114,75,103,87,122,61,79,112,90,77,83,82,108,26 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_split_rent_exemptness::new_behavior";
  test.test_nonce  = 344;
  test.test_number = 806;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "GGoW9u8zTzLhddFqU47qvCYpWFhAs6bgwJrmZSHANWYv",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1002978880UL;
  test_acc->result_lamports = 1002978880UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_806_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_806_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_806_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_806_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "47cSQw6bJ1Qh9pyJFMrNAVQYUskvetUtwvbEYRBrsazi",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_806_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_806_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_806_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_806_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_806_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_806_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_806_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_806_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_806_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_806_raw_sz;
  test.expected_result = -4;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_807(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 55,56,62,27,78,109,128,24,106,121,2,15,80,92,113,118,127,120,98,116,124,30,123,105,76,111,29,110,89,117,126,33,125,114,75,103,87,122,61,79,112,90,77,83,82,108,26 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_split_rent_exemptness::new_behavior";
  test.test_nonce  = 387;
  test.test_number = 807;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "GGoW9u8zTzLhddFqU47qvCYpWFhAs6bgwJrmZSHANWYv",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1002978880UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_807_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_807_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_807_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_807_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "47cSQw6bJ1Qh9pyJFMrNAVQYUskvetUtwvbEYRBrsazi",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 1002978880UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_807_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_807_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_807_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_807_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_807_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_807_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_807_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_807_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_807_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_807_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_808(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 1;
  uchar disabled_features[] = { 89 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_split_rent_exemptness::old_behavior";
  test.test_nonce  = 107;
  test.test_number = 808;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "7QWo6nzWxN1QPfKqkfzvExYdeq6XnmT2rWwPyVcVHgnJ",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2978881UL;
  test_acc->result_lamports = 2978881UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_808_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_808_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_808_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_808_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "GNZm9A7ikEEhpi39TxRGo5bBgxPKYFYSBf9D5E5WJvok",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_808_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_808_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_808_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_808_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_808_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_808_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_808_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_808_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_808_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_808_raw_sz;
  test.expected_result = -4;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_809(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 1;
  uchar disabled_features[] = { 89 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_split_rent_exemptness::old_behavior";
  test.test_nonce  = 302;
  test.test_number = 809;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "7QWo6nzWxN1QPfKqkfzvExYdeq6XnmT2rWwPyVcVHgnJ",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2978881UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_809_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_809_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_809_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_809_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "GNZm9A7ikEEhpi39TxRGo5bBgxPKYFYSBf9D5E5WJvok",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 2978881UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_809_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_809_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_809_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_809_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_809_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_809_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_809_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_809_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_809_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_809_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_810(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 1;
  uchar disabled_features[] = { 89 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_split_rent_exemptness::old_behavior";
  test.test_nonce  = 310;
  test.test_number = 810;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "7QWo6nzWxN1QPfKqkfzvExYdeq6XnmT2rWwPyVcVHgnJ",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2978881UL;
  test_acc->result_lamports = 2978881UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_810_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_810_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_810_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_810_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "GNZm9A7ikEEhpi39TxRGo5bBgxPKYFYSBf9D5E5WJvok",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_810_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_810_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_810_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_810_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_810_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_810_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_810_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_810_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_810_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_810_raw_sz;
  test.expected_result = -4;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_811(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 1;
  uchar disabled_features[] = { 89 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_split_rent_exemptness::old_behavior";
  test.test_nonce  = 358;
  test.test_number = 811;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "7QWo6nzWxN1QPfKqkfzvExYdeq6XnmT2rWwPyVcVHgnJ",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2978881UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_811_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_811_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_811_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_811_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "GNZm9A7ikEEhpi39TxRGo5bBgxPKYFYSBf9D5E5WJvok",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 2978881UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_811_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_811_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_811_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_811_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_811_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_811_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_811_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_811_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_811_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_811_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_812(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 125,116,114,103,26,15,79,61,106,89,80,123,92,29,27,117,105,83,122,127,24,77,120,90,87,128,56,108,76,124,55,113,126,62,109,2,33,75,78,110,118,112,82,121,98,111,30 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_split_rent_exemptness::old_behavior";
  test.test_nonce  = 181;
  test.test_number = 812;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "H2WiA81uukBaBAB3gqRgWBwo3Q9MZeJL1X6DBZcVGtNX",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2978881UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_812_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_812_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_812_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_812_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "HDfssPze5reLajvCcd6p2EHbSBDDdt5aCMJ6dCs7UdJh",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 2978881UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_812_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_812_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_812_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_812_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_812_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_812_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_812_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_812_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_812_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_812_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_813(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 125,116,114,103,26,15,79,61,106,89,80,123,92,29,27,117,105,83,122,127,24,77,120,90,87,128,56,108,76,124,55,113,126,62,109,2,33,75,78,110,118,112,82,121,98,111,30 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_split_rent_exemptness::old_behavior";
  test.test_nonce  = 198;
  test.test_number = 813;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "H2WiA81uukBaBAB3gqRgWBwo3Q9MZeJL1X6DBZcVGtNX",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2978881UL;
  test_acc->result_lamports = 2978881UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_813_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_813_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_813_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_813_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "HDfssPze5reLajvCcd6p2EHbSBDDdt5aCMJ6dCs7UdJh",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_813_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_813_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_813_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_813_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_813_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_813_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_813_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_813_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_813_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_813_raw_sz;
  test.expected_result = -4;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_814(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 125,116,114,103,26,15,79,61,106,89,80,123,92,29,27,117,105,83,122,127,24,77,120,90,87,128,56,108,76,124,55,113,126,62,109,2,33,75,78,110,118,112,82,121,98,111,30 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_split_rent_exemptness::old_behavior";
  test.test_nonce  = 292;
  test.test_number = 814;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "H2WiA81uukBaBAB3gqRgWBwo3Q9MZeJL1X6DBZcVGtNX",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2978881UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_814_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_814_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_814_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_814_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "HDfssPze5reLajvCcd6p2EHbSBDDdt5aCMJ6dCs7UdJh",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 2978881UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_814_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_814_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_814_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_814_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_814_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_814_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_814_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_814_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_814_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_814_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_815(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 125,116,114,103,26,15,79,61,106,89,80,123,92,29,27,117,105,83,122,127,24,77,120,90,87,128,56,108,76,124,55,113,126,62,109,2,33,75,78,110,118,112,82,121,98,111,30 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_split_rent_exemptness::old_behavior";
  test.test_nonce  = 56;
  test.test_number = 815;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "H2WiA81uukBaBAB3gqRgWBwo3Q9MZeJL1X6DBZcVGtNX",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2978881UL;
  test_acc->result_lamports = 2978881UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_815_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_815_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_815_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_815_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "HDfssPze5reLajvCcd6p2EHbSBDDdt5aCMJ6dCs7UdJh",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_815_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_815_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_815_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_815_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_815_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_815_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_815_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_815_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_815_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_815_raw_sz;
  test.expected_result = -4;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_816(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 113,79,109,114,82,92,78,106,126,123,90,76,55,30,105,33,75,15,127,26,62,124,87,112,121,128,29,122,27,98,80,83,61,120,116,108,77,125,24,56,89,117,118,103,111,110,2 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_split_source_uninitialized::new_behavior";
  test.test_nonce  = 106;
  test.test_number = 816;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 2;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "5kKC7Hci4buRri4GANoACDZN25ATs1KHqNQovnezvDJU",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2004565760UL;
  test_acc->result_lamports = 2004565760UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_816_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_816_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_816_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_816_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "FGFAig59u3Ez1zDQn66L8eL8WqT2NZmjvEpb4m6Lvahn",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_816_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_816_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_816_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_816_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_816_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_816_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_817(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 113,79,109,114,82,92,78,106,126,123,90,76,55,30,105,33,75,15,127,26,62,124,87,112,121,128,29,122,27,98,80,83,61,120,116,108,77,125,24,56,89,117,118,103,111,110,2 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_split_source_uninitialized::new_behavior";
  test.test_nonce  = 132;
  test.test_number = 817;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 2;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "3yUG7VoXyG82btqgD2T5DkYTdf7Y6hxRFJhiw75Hq7Us",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2004565760UL;
  test_acc->result_lamports = 2004565760UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_817_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_817_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_817_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_817_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "FSd4tivd12HfVWRBFgXmKtSK3QbMh7yU2HV6LAZeFG5d",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_817_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_817_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_817_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_817_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_817_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_817_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_818(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 113,79,109,114,82,92,78,106,126,123,90,76,55,30,105,33,75,15,127,26,62,124,87,112,121,128,29,122,27,98,80,83,61,120,116,108,77,125,24,56,89,117,118,103,111,110,2 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_split_source_uninitialized::new_behavior";
  test.test_nonce  = 61;
  test.test_number = 818;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 2;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "5kKC7Hci4buRri4GANoACDZN25ATs1KHqNQovnezvDJU",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2004565760UL;
  test_acc->result_lamports = 2004565760UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_818_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_818_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_818_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_818_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "FGFAig59u3Ez1zDQn66L8eL8WqT2NZmjvEpb4m6Lvahn",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_818_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_818_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_818_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_818_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_818_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_818_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_819(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 113,79,109,114,82,92,78,106,126,123,90,76,55,30,105,33,75,15,127,26,62,124,87,112,121,128,29,122,27,98,80,83,61,120,116,108,77,125,24,56,89,117,118,103,111,110,2 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_split_source_uninitialized::new_behavior";
  test.test_nonce  = 106;
  test.test_number = 819;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 2;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "3yUG7VoXyG82btqgD2T5DkYTdf7Y6hxRFJhiw75Hq7Us",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2004565760UL;
  test_acc->result_lamports = 2004565760UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_819_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_819_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_819_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_819_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "FSd4tivd12HfVWRBFgXmKtSK3QbMh7yU2HV6LAZeFG5d",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_819_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_819_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_819_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_819_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_819_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_819_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_820(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 113,79,109,114,82,92,78,106,126,123,90,76,55,30,105,33,75,15,127,26,62,124,87,112,121,128,29,122,27,98,80,83,61,120,116,108,77,125,24,56,89,117,118,103,111,110,2 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_split_source_uninitialized::new_behavior";
  test.test_nonce  = 175;
  test.test_number = 820;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 2;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "5kKC7Hci4buRri4GANoACDZN25ATs1KHqNQovnezvDJU",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2004565760UL;
  test_acc->result_lamports = 2004565760UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_820_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_820_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_820_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_820_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "FGFAig59u3Ez1zDQn66L8eL8WqT2NZmjvEpb4m6Lvahn",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_820_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_820_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_820_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_820_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_820_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_820_raw_sz;
  test.expected_result = -6;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_821(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 113,79,109,114,82,92,78,106,126,123,90,76,55,30,105,33,75,15,127,26,62,124,87,112,121,128,29,122,27,98,80,83,61,120,116,108,77,125,24,56,89,117,118,103,111,110,2 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_split_source_uninitialized::new_behavior";
  test.test_nonce  = 166;
  test.test_number = 821;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 2;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "3yUG7VoXyG82btqgD2T5DkYTdf7Y6hxRFJhiw75Hq7Us",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2004565760UL;
  test_acc->result_lamports = 2004565760UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_821_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_821_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_821_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_821_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "FSd4tivd12HfVWRBFgXmKtSK3QbMh7yU2HV6LAZeFG5d",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_821_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_821_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_821_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_821_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_821_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_821_raw_sz;
  test.expected_result = -6;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_822(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 113,79,109,114,82,92,78,106,126,123,90,76,55,30,105,33,75,15,127,26,62,124,87,112,121,128,29,122,27,98,80,83,61,120,116,108,77,125,24,56,89,117,118,103,111,110,2 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_split_source_uninitialized::new_behavior";
  test.test_nonce  = 138;
  test.test_number = 822;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 2;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "5kKC7Hci4buRri4GANoACDZN25ATs1KHqNQovnezvDJU",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2004565760UL;
  test_acc->result_lamports = 2004565760UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_822_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_822_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_822_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_822_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "FGFAig59u3Ez1zDQn66L8eL8WqT2NZmjvEpb4m6Lvahn",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_822_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_822_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_822_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_822_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_822_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_822_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_823(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 113,79,109,114,82,92,78,106,126,123,90,76,55,30,105,33,75,15,127,26,62,124,87,112,121,128,29,122,27,98,80,83,61,120,116,108,77,125,24,56,89,117,118,103,111,110,2 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_split_source_uninitialized::new_behavior";
  test.test_nonce  = 193;
  test.test_number = 823;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 2;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "5kKC7Hci4buRri4GANoACDZN25ATs1KHqNQovnezvDJU",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2004565760UL;
  test_acc->result_lamports = 1002282880UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_823_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_823_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_823_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_823_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "FGFAig59u3Ez1zDQn66L8eL8WqT2NZmjvEpb4m6Lvahn",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 1002282880UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_823_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_823_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_823_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_823_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_823_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_823_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_824(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 113,79,109,114,82,92,78,106,126,123,90,76,55,30,105,33,75,15,127,26,62,124,87,112,121,128,29,122,27,98,80,83,61,120,116,108,77,125,24,56,89,117,118,103,111,110,2 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_split_source_uninitialized::new_behavior";
  test.test_nonce  = 232;
  test.test_number = 824;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 2;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "5kKC7Hci4buRri4GANoACDZN25ATs1KHqNQovnezvDJU",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2004565760UL;
  test_acc->result_lamports = 2004565760UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_824_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_824_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_824_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_824_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "FGFAig59u3Ez1zDQn66L8eL8WqT2NZmjvEpb4m6Lvahn",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_824_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_824_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_824_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_824_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_824_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_824_raw_sz;
  test.expected_result = -8;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
