#include "../fd_tests.h"
int test_350(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 128,98,83,61,78,121,87,113,33,126,110,109,89,92,27,82,76,117,105,80,108,62,55,127,124,24,118,106,123,30,79,125,2,75,122,15,56,116,120,111,90,114,77,29,26,112,103 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_merge_active_stake::old_behavior";
  test.test_nonce  = 196;
  test.test_number = 350;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 5;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "BRrKtHnGnVfmBgAMUhY4bA96qr7bNuq4ECupm2LvugYk",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 4244707122UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_350_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_350_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_350_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_350_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "98RF4UhnFFLhmqP5Dw5DFtPksKAP8VDqpZemVjfzF338",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 4244707122UL;
  test_acc->result_lamports = 8489414244UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_350_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_350_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_350_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_350_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "2mTeE1soMBtQYHaoKaAaUmZfSkRxzBdkBhViH4s9UUqS",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_350_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_350_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_350_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_350_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_350_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_350_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_350_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_350_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_350_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_350_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_350_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_350_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_350_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_350_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_351(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 128,98,83,61,78,121,87,113,33,126,110,109,89,92,27,82,76,117,105,80,108,62,55,127,124,24,118,106,123,30,79,125,2,75,122,15,56,116,120,111,90,114,77,29,26,112,103 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_merge_active_stake::old_behavior";
  test.test_nonce  = 32;
  test.test_number = 351;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 5;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "BRrKtHnGnVfmBgAMUhY4bA96qr7bNuq4ECupm2LvugYk",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 4244707122UL;
  test_acc->result_lamports = 8489414244UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_351_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_351_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_351_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_351_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "98RF4UhnFFLhmqP5Dw5DFtPksKAP8VDqpZemVjfzF338",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 4244707122UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_351_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_351_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_351_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_351_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "2mTeE1soMBtQYHaoKaAaUmZfSkRxzBdkBhViH4s9UUqS",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_351_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_351_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_351_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_351_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_351_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_351_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_351_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_351_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_351_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_351_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_351_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_351_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_351_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_351_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_352(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 128,98,83,61,78,121,87,113,33,126,110,109,89,92,27,82,76,117,105,80,108,62,55,127,124,24,118,106,123,30,79,125,2,75,122,15,56,116,120,111,90,114,77,29,26,112,103 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_merge_active_stake::old_behavior";
  test.test_nonce  = 359;
  test.test_number = 352;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 5;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "BRrKtHnGnVfmBgAMUhY4bA96qr7bNuq4ECupm2LvugYk",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 4244707122UL;
  test_acc->result_lamports = 4244707122UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_352_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_352_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_352_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_352_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "98RF4UhnFFLhmqP5Dw5DFtPksKAP8VDqpZemVjfzF338",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 4244707122UL;
  test_acc->result_lamports = 4244707122UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_352_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_352_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_352_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_352_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "2mTeE1soMBtQYHaoKaAaUmZfSkRxzBdkBhViH4s9UUqS",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_352_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_352_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_352_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_352_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_352_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_352_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_352_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_352_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_352_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_352_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_352_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_352_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_352_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_352_raw_sz;
  test.expected_result = -26;
  test.custom_err = 5;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_353(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 128,98,83,61,78,121,87,113,33,126,110,109,89,92,27,82,76,117,105,80,108,62,55,127,124,24,118,106,123,30,79,125,2,75,122,15,56,116,120,111,90,114,77,29,26,112,103 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_merge_active_stake::old_behavior";
  test.test_nonce  = 415;
  test.test_number = 353;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 5;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "BRrKtHnGnVfmBgAMUhY4bA96qr7bNuq4ECupm2LvugYk",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 4244707122UL;
  test_acc->result_lamports = 4244707122UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_353_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_353_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_353_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_353_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "98RF4UhnFFLhmqP5Dw5DFtPksKAP8VDqpZemVjfzF338",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 4244707122UL;
  test_acc->result_lamports = 4244707122UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_353_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_353_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_353_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_353_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "2mTeE1soMBtQYHaoKaAaUmZfSkRxzBdkBhViH4s9UUqS",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_353_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_353_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_353_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_353_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_353_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_353_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_353_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_353_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_353_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_353_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_353_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_353_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_353_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_353_raw_sz;
  test.expected_result = -26;
  test.custom_err = 5;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_354(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 128,98,83,61,78,121,87,113,33,126,110,109,89,92,27,82,76,117,105,80,108,62,55,127,124,24,118,106,123,30,79,125,2,75,122,15,56,116,120,111,90,114,77,29,26,112,103 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_merge_active_stake::old_behavior";
  test.test_nonce  = 478;
  test.test_number = 354;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 5;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "BRrKtHnGnVfmBgAMUhY4bA96qr7bNuq4ECupm2LvugYk",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 4244707122UL;
  test_acc->result_lamports = 4244707122UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_354_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_354_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_354_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_354_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "98RF4UhnFFLhmqP5Dw5DFtPksKAP8VDqpZemVjfzF338",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 4244707122UL;
  test_acc->result_lamports = 4244707122UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_354_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_354_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_354_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_354_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "2mTeE1soMBtQYHaoKaAaUmZfSkRxzBdkBhViH4s9UUqS",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_354_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_354_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_354_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_354_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_354_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_354_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_354_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_354_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_354_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_354_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_354_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_354_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_354_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_354_raw_sz;
  test.expected_result = -26;
  test.custom_err = 5;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_355(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 128,98,83,61,78,121,87,113,33,126,110,109,89,92,27,82,76,117,105,80,108,62,55,127,124,24,118,106,123,30,79,125,2,75,122,15,56,116,120,111,90,114,77,29,26,112,103 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_merge_active_stake::old_behavior";
  test.test_nonce  = 513;
  test.test_number = 355;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 5;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "BRrKtHnGnVfmBgAMUhY4bA96qr7bNuq4ECupm2LvugYk",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 4244707122UL;
  test_acc->result_lamports = 4244707122UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_355_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_355_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_355_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_355_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "98RF4UhnFFLhmqP5Dw5DFtPksKAP8VDqpZemVjfzF338",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 4244707122UL;
  test_acc->result_lamports = 4244707122UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_355_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_355_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_355_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_355_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "2mTeE1soMBtQYHaoKaAaUmZfSkRxzBdkBhViH4s9UUqS",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_355_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_355_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_355_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_355_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_355_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_355_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_355_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_355_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_355_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_355_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_355_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_355_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_355_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_355_raw_sz;
  test.expected_result = -26;
  test.custom_err = 5;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_356(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 128,98,83,61,78,121,87,113,33,126,110,109,89,92,27,82,76,117,105,80,108,62,55,127,124,24,118,106,123,30,79,125,2,75,122,15,56,116,120,111,90,114,77,29,26,112,103 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_merge_active_stake::old_behavior";
  test.test_nonce  = 547;
  test.test_number = 356;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 5;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "BRrKtHnGnVfmBgAMUhY4bA96qr7bNuq4ECupm2LvugYk",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 4244707122UL;
  test_acc->result_lamports = 4244707122UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_356_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_356_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_356_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_356_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "98RF4UhnFFLhmqP5Dw5DFtPksKAP8VDqpZemVjfzF338",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 4244707122UL;
  test_acc->result_lamports = 4244707122UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_356_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_356_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_356_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_356_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "2mTeE1soMBtQYHaoKaAaUmZfSkRxzBdkBhViH4s9UUqS",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_356_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_356_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_356_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_356_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_356_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_356_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_356_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_356_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_356_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_356_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_356_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_356_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_356_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_356_raw_sz;
  test.expected_result = -26;
  test.custom_err = 5;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_357(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 128,98,83,61,78,121,87,113,33,126,110,109,89,92,27,82,76,117,105,80,108,62,55,127,124,24,118,106,123,30,79,125,2,75,122,15,56,116,120,111,90,114,77,29,26,112,103 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_merge_active_stake::old_behavior";
  test.test_nonce  = 578;
  test.test_number = 357;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 5;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "BRrKtHnGnVfmBgAMUhY4bA96qr7bNuq4ECupm2LvugYk",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 4244707122UL;
  test_acc->result_lamports = 4244707122UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_357_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_357_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_357_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_357_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "98RF4UhnFFLhmqP5Dw5DFtPksKAP8VDqpZemVjfzF338",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 4244707122UL;
  test_acc->result_lamports = 4244707122UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_357_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_357_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_357_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_357_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "2mTeE1soMBtQYHaoKaAaUmZfSkRxzBdkBhViH4s9UUqS",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_357_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_357_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_357_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_357_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_357_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_357_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_357_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_357_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_357_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_357_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_357_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_357_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_357_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_357_raw_sz;
  test.expected_result = -26;
  test.custom_err = 5;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_358(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 128,98,83,61,78,121,87,113,33,126,110,109,89,92,27,82,76,117,105,80,108,62,55,127,124,24,118,106,123,30,79,125,2,75,122,15,56,116,120,111,90,114,77,29,26,112,103 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_merge_active_stake::old_behavior";
  test.test_nonce  = 596;
  test.test_number = 358;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 5;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "BRrKtHnGnVfmBgAMUhY4bA96qr7bNuq4ECupm2LvugYk",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 4244707122UL;
  test_acc->result_lamports = 4244707122UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_358_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_358_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_358_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_358_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "98RF4UhnFFLhmqP5Dw5DFtPksKAP8VDqpZemVjfzF338",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 4244707122UL;
  test_acc->result_lamports = 4244707122UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_358_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_358_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_358_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_358_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "2mTeE1soMBtQYHaoKaAaUmZfSkRxzBdkBhViH4s9UUqS",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_358_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_358_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_358_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_358_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_358_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_358_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_358_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_358_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_358_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_358_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_358_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_358_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_358_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_358_raw_sz;
  test.expected_result = -26;
  test.custom_err = 5;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_359(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 128,98,83,61,78,121,87,113,33,126,110,109,89,92,27,82,76,117,105,80,108,62,55,127,124,24,118,106,123,30,79,125,2,75,122,15,56,116,120,111,90,114,77,29,26,112,103 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_merge_active_stake::old_behavior";
  test.test_nonce  = 609;
  test.test_number = 359;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 5;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "BRrKtHnGnVfmBgAMUhY4bA96qr7bNuq4ECupm2LvugYk",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 4244707122UL;
  test_acc->result_lamports = 4244707122UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_359_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_359_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_359_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_359_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "98RF4UhnFFLhmqP5Dw5DFtPksKAP8VDqpZemVjfzF338",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 4244707122UL;
  test_acc->result_lamports = 4244707122UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_359_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_359_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_359_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_359_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "2mTeE1soMBtQYHaoKaAaUmZfSkRxzBdkBhViH4s9UUqS",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_359_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_359_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_359_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_359_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_359_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_359_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_359_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_359_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_359_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_359_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_359_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_359_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_359_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_359_raw_sz;
  test.expected_result = -26;
  test.custom_err = 5;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_360(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 128,98,83,61,78,121,87,113,33,126,110,109,89,92,27,82,76,117,105,80,108,62,55,127,124,24,118,106,123,30,79,125,2,75,122,15,56,116,120,111,90,114,77,29,26,112,103 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_merge_active_stake::old_behavior";
  test.test_nonce  = 620;
  test.test_number = 360;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 5;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "BRrKtHnGnVfmBgAMUhY4bA96qr7bNuq4ECupm2LvugYk",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 4244707122UL;
  test_acc->result_lamports = 8489414244UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_360_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_360_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_360_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_360_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "98RF4UhnFFLhmqP5Dw5DFtPksKAP8VDqpZemVjfzF338",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 4244707122UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_360_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_360_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_360_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_360_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "2mTeE1soMBtQYHaoKaAaUmZfSkRxzBdkBhViH4s9UUqS",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_360_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_360_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_360_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_360_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_360_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_360_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_360_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_360_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_360_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_360_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_360_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_360_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_360_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_360_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_361(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 128,98,83,61,78,121,87,113,33,126,110,109,89,92,27,82,76,117,105,80,108,62,55,127,124,24,118,106,123,30,79,125,2,75,122,15,56,116,120,111,90,114,77,29,26,112,103 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_merge_active_stake::old_behavior";
  test.test_nonce  = 628;
  test.test_number = 361;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 5;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "BRrKtHnGnVfmBgAMUhY4bA96qr7bNuq4ECupm2LvugYk",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 4244707122UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_361_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_361_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_361_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_361_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "98RF4UhnFFLhmqP5Dw5DFtPksKAP8VDqpZemVjfzF338",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 4244707122UL;
  test_acc->result_lamports = 8489414244UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_361_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_361_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_361_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_361_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "2mTeE1soMBtQYHaoKaAaUmZfSkRxzBdkBhViH4s9UUqS",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_361_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_361_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_361_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_361_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_361_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_361_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_361_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_361_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_361_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_361_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_361_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_361_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_361_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_361_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_362(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 128,98,83,61,78,121,87,113,33,126,110,109,89,92,27,82,76,117,105,80,108,62,55,127,124,24,118,106,123,30,79,125,2,75,122,15,56,116,120,111,90,114,77,29,26,112,103 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_merge_active_stake::old_behavior";
  test.test_nonce  = 632;
  test.test_number = 362;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 5;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "BRrKtHnGnVfmBgAMUhY4bA96qr7bNuq4ECupm2LvugYk",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 4244707122UL;
  test_acc->result_lamports = 4244707122UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_362_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_362_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_362_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_362_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "98RF4UhnFFLhmqP5Dw5DFtPksKAP8VDqpZemVjfzF338",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 4244707122UL;
  test_acc->result_lamports = 4244707122UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_362_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_362_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_362_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_362_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "2mTeE1soMBtQYHaoKaAaUmZfSkRxzBdkBhViH4s9UUqS",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_362_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_362_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_362_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_362_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_362_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_362_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_362_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_362_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_362_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_362_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_362_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_362_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_362_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_362_raw_sz;
  test.expected_result = -26;
  test.custom_err = 5;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_363(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 128,98,83,61,78,121,87,113,33,126,110,109,89,92,27,82,76,117,105,80,108,62,55,127,124,24,118,106,123,30,79,125,2,75,122,15,56,116,120,111,90,114,77,29,26,112,103 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_merge_active_stake::old_behavior";
  test.test_nonce  = 636;
  test.test_number = 363;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 5;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "BRrKtHnGnVfmBgAMUhY4bA96qr7bNuq4ECupm2LvugYk",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 4244707122UL;
  test_acc->result_lamports = 4244707122UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_363_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_363_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_363_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_363_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "98RF4UhnFFLhmqP5Dw5DFtPksKAP8VDqpZemVjfzF338",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 4244707122UL;
  test_acc->result_lamports = 4244707122UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_363_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_363_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_363_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_363_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "2mTeE1soMBtQYHaoKaAaUmZfSkRxzBdkBhViH4s9UUqS",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_363_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_363_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_363_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_363_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_363_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_363_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_363_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_363_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_363_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_363_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_363_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_363_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_363_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_363_raw_sz;
  test.expected_result = -26;
  test.custom_err = 5;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_364(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 128,98,83,61,78,121,87,113,33,126,110,109,89,92,27,82,76,117,105,80,108,62,55,127,124,24,118,106,123,30,79,125,2,75,122,15,56,116,120,111,90,114,77,29,26,112,103 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_merge_active_stake::old_behavior";
  test.test_nonce  = 639;
  test.test_number = 364;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 5;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "BRrKtHnGnVfmBgAMUhY4bA96qr7bNuq4ECupm2LvugYk",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 4244707122UL;
  test_acc->result_lamports = 4244707122UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_364_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_364_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_364_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_364_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "98RF4UhnFFLhmqP5Dw5DFtPksKAP8VDqpZemVjfzF338",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 4244707122UL;
  test_acc->result_lamports = 4244707122UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_364_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_364_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_364_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_364_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "2mTeE1soMBtQYHaoKaAaUmZfSkRxzBdkBhViH4s9UUqS",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_364_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_364_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_364_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_364_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_364_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_364_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_364_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_364_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_364_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_364_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_364_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_364_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_364_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_364_raw_sz;
  test.expected_result = -26;
  test.custom_err = 5;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_365(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 128,98,83,61,78,121,87,113,33,126,110,109,89,92,27,82,76,117,105,80,108,62,55,127,124,24,118,106,123,30,79,125,2,75,122,15,56,116,120,111,90,114,77,29,26,112,103 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_merge_active_stake::old_behavior";
  test.test_nonce  = 641;
  test.test_number = 365;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 5;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "BRrKtHnGnVfmBgAMUhY4bA96qr7bNuq4ECupm2LvugYk",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 4244707122UL;
  test_acc->result_lamports = 4244707122UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_365_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_365_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_365_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_365_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "98RF4UhnFFLhmqP5Dw5DFtPksKAP8VDqpZemVjfzF338",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 4244707122UL;
  test_acc->result_lamports = 4244707122UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_365_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_365_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_365_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_365_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "2mTeE1soMBtQYHaoKaAaUmZfSkRxzBdkBhViH4s9UUqS",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_365_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_365_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_365_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_365_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_365_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_365_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_365_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_365_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_365_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_365_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_365_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_365_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_365_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_365_raw_sz;
  test.expected_result = -26;
  test.custom_err = 5;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_366(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 128,98,83,61,78,121,87,113,33,126,110,109,89,92,27,82,76,117,105,80,108,62,55,127,124,24,118,106,123,30,79,125,2,75,122,15,56,116,120,111,90,114,77,29,26,112,103 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_merge_active_stake::old_behavior";
  test.test_nonce  = 642;
  test.test_number = 366;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 5;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "BRrKtHnGnVfmBgAMUhY4bA96qr7bNuq4ECupm2LvugYk",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 4244707122UL;
  test_acc->result_lamports = 4244707122UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_366_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_366_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_366_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_366_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "98RF4UhnFFLhmqP5Dw5DFtPksKAP8VDqpZemVjfzF338",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 4244707122UL;
  test_acc->result_lamports = 4244707122UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_366_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_366_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_366_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_366_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "2mTeE1soMBtQYHaoKaAaUmZfSkRxzBdkBhViH4s9UUqS",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_366_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_366_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_366_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_366_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_366_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_366_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_366_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_366_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_366_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_366_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_366_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_366_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_366_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_366_raw_sz;
  test.expected_result = -26;
  test.custom_err = 5;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_367(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 128,98,83,61,78,121,87,113,33,126,110,109,89,92,27,82,76,117,105,80,108,62,55,127,124,24,118,106,123,30,79,125,2,75,122,15,56,116,120,111,90,114,77,29,26,112,103 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_merge_active_stake::old_behavior";
  test.test_nonce  = 643;
  test.test_number = 367;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 5;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "BRrKtHnGnVfmBgAMUhY4bA96qr7bNuq4ECupm2LvugYk",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 4244707122UL;
  test_acc->result_lamports = 4244707122UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_367_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_367_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_367_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_367_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "98RF4UhnFFLhmqP5Dw5DFtPksKAP8VDqpZemVjfzF338",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 4244707122UL;
  test_acc->result_lamports = 4244707122UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_367_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_367_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_367_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_367_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "2mTeE1soMBtQYHaoKaAaUmZfSkRxzBdkBhViH4s9UUqS",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_367_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_367_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_367_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_367_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_367_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_367_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_367_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_367_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_367_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_367_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_367_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_367_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_367_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_367_raw_sz;
  test.expected_result = -26;
  test.custom_err = 5;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_368(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 128,98,83,61,78,121,87,113,33,126,110,109,89,92,27,82,76,117,105,80,108,62,55,127,124,24,118,106,123,30,79,125,2,75,122,15,56,116,120,111,90,114,77,29,26,112,103 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_merge_active_stake::old_behavior";
  test.test_nonce  = 644;
  test.test_number = 368;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 5;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "BRrKtHnGnVfmBgAMUhY4bA96qr7bNuq4ECupm2LvugYk",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 4244707122UL;
  test_acc->result_lamports = 4244707122UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_368_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_368_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_368_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_368_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "98RF4UhnFFLhmqP5Dw5DFtPksKAP8VDqpZemVjfzF338",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 4244707122UL;
  test_acc->result_lamports = 4244707122UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_368_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_368_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_368_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_368_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "2mTeE1soMBtQYHaoKaAaUmZfSkRxzBdkBhViH4s9UUqS",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_368_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_368_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_368_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_368_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_368_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_368_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_368_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_368_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_368_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_368_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_368_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_368_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_368_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_368_raw_sz;
  test.expected_result = -26;
  test.custom_err = 5;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_369(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 128,98,83,61,78,121,87,113,33,126,110,109,89,92,27,82,76,117,105,80,108,62,55,127,124,24,118,106,123,30,79,125,2,75,122,15,56,116,120,111,90,114,77,29,26,112,103 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_merge_active_stake::old_behavior";
  test.test_nonce  = 645;
  test.test_number = 369;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 5;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "BRrKtHnGnVfmBgAMUhY4bA96qr7bNuq4ECupm2LvugYk",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 4244707122UL;
  test_acc->result_lamports = 4244707122UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_369_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_369_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_369_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_369_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "98RF4UhnFFLhmqP5Dw5DFtPksKAP8VDqpZemVjfzF338",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 4244707122UL;
  test_acc->result_lamports = 4244707122UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_369_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_369_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_369_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_369_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "2mTeE1soMBtQYHaoKaAaUmZfSkRxzBdkBhViH4s9UUqS",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_369_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_369_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_369_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_369_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_369_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_369_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_369_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_369_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_369_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_369_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_369_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_369_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_369_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_369_raw_sz;
  test.expected_result = -26;
  test.custom_err = 5;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_370(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 128,98,83,61,78,121,87,113,33,126,110,109,89,92,27,82,76,117,105,80,108,62,55,127,124,24,118,106,123,30,79,125,2,75,122,15,56,116,120,111,90,114,77,29,26,112,103 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_merge_active_stake::old_behavior";
  test.test_nonce  = 646;
  test.test_number = 370;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 5;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "BRrKtHnGnVfmBgAMUhY4bA96qr7bNuq4ECupm2LvugYk",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 4244707122UL;
  test_acc->result_lamports = 8489414244UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_370_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_370_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_370_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_370_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "98RF4UhnFFLhmqP5Dw5DFtPksKAP8VDqpZemVjfzF338",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 4244707122UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_370_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_370_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_370_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_370_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "2mTeE1soMBtQYHaoKaAaUmZfSkRxzBdkBhViH4s9UUqS",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_370_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_370_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_370_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_370_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_370_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_370_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_370_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_370_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_370_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_370_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_370_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_370_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_370_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_370_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_371(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 128,98,83,61,78,121,87,113,33,126,110,109,89,92,27,82,76,117,105,80,108,62,55,127,124,24,118,106,123,30,79,125,2,75,122,15,56,116,120,111,90,114,77,29,26,112,103 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_merge_active_stake::old_behavior";
  test.test_nonce  = 647;
  test.test_number = 371;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 5;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "BRrKtHnGnVfmBgAMUhY4bA96qr7bNuq4ECupm2LvugYk",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 4244707122UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_371_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_371_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_371_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_371_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "98RF4UhnFFLhmqP5Dw5DFtPksKAP8VDqpZemVjfzF338",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 4244707122UL;
  test_acc->result_lamports = 8489414244UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_371_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_371_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_371_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_371_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "2mTeE1soMBtQYHaoKaAaUmZfSkRxzBdkBhViH4s9UUqS",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_371_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_371_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_371_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_371_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_371_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_371_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_371_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_371_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_371_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_371_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_371_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_371_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_371_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_371_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_372(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 124,117,87,125,98,113,80,110,78,33,123,55,77,116,83,103,26,61,62,112,76,90,82,29,128,2,89,118,122,24,79,56,111,126,114,75,109,121,27,92,105,127,106,15,120,30,108 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_merge_fake_stake_source::new_behavior";
  test.test_nonce  = 33;
  test.test_number = 372;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 5;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "34i1CKLime27XCsF9EKvtwYRK2WTCghAj7UPNuH4y7cB",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 42UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_372_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_372_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_372_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_372_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Bz8phN8L6j8uF5BjGHmJUEvoEdbu2NbyENB6XBoc7jYz",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "7oftK2havbyhZprn6TKVtxcuAzD3WdiCsXrSCA8xFqfo",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 42UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_372_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_372_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_372_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_372_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "EwL5pf5APUCvVdXNheheyibQqXWmMb6gR2H3BybFHL2A",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_372_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_372_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_372_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_372_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_372_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_372_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_372_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_372_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_372_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_372_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_372_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_372_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_372_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_372_raw_sz;
  test.expected_result = -7;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_373(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 124,117,87,125,98,113,80,110,78,33,123,55,77,116,83,103,26,61,62,112,76,90,82,29,128,2,89,118,122,24,79,56,111,126,114,75,109,121,27,92,105,127,106,15,120,30,108 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_merge_fake_stake_source::new_behavior";
  test.test_nonce  = 20;
  test.test_number = 373;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 5;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "EjcYfhydKAPYqnXeb5LN2sSw1PxZ8dvRqWUE6JKyxgph",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 42UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_373_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_373_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_373_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_373_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "3XwTidfQQJFi1AyKrbjUvdnXKUPA4FYevPAsRWgBWnAz",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "7eJUg1JfbzMdfu3xCUvqgKQhVvdn9pssps1SZeTTSm3K",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 42UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_373_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_373_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_373_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_373_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "2dFd9LN6zPja8tUxbCRfPwCpapqKAi7am2KmBDRkRXyA",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_373_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_373_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_373_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_373_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_373_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_373_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_373_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_373_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_373_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_373_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_373_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_373_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_373_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_373_raw_sz;
  test.expected_result = -7;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_374(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 1;
  uchar disabled_features[] = { 89 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_merge_fake_stake_source::old_behavior";
  test.test_nonce  = 31;
  test.test_number = 374;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 5;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "214CRSYgwRCP1LzdqkjbhLsHuiyH52TxQmtfZj6YvCxT",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 42UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_374_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_374_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_374_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_374_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "G8Ux291T5Nbo9Yq4xRftStUmihZRmESXqWQbJs2CQXu9",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "4B5MTKfGaAD7ctnbMZbmoG9wTpGQtFp2sKZL9w8p4iSz",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 42UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_374_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_374_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_374_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_374_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Avak12UGFeAAFrXN1MWAsvhcyScDtC49tyNegVDzMoTp",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_374_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_374_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_374_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_374_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_374_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_374_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_374_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_374_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_374_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_374_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_374_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_374_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_374_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_374_raw_sz;
  test.expected_result = -7;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
