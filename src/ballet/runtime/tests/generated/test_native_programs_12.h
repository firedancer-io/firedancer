#include "../fd_tests.h"
int test_300(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 83,108,78,79,128,61,117,124,33,116,114,111,121,62,27,98,126,82,112,90,75,24,92,2,55,120,106,76,122,109,80,105,127,56,87,26,123,118,125,15,77,103,29,89,30,110,113 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_merge_active_stake::new_behavior";
  test.test_nonce  = 625;
  test.test_number = 300;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 5;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "8nDyGaaLD2E5NbpQKqtqyt8QYKwc3CdxeKPkddmCpDRp",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 4244707122UL;
  test_acc->result_lamports = 4244707122UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_300_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_300_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_300_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_300_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "3nWKsRHcGZMkxCqxwzoSkJL75s5d8c6KpzRfmtkuvQuH",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 4244707122UL;
  test_acc->result_lamports = 4244707122UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_300_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_300_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_300_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_300_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "HpKz3VfNTNBTdJS8PAqTGoEPk9RAHqBNmVjYhWxa3fUy",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_300_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_300_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_300_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_300_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_300_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_300_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_300_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_300_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_300_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_300_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_300_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_300_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_300_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_300_raw_sz;
  test.expected_result = -26;
  test.custom_err = 5;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_301(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 83,108,78,79,128,61,117,124,33,116,114,111,121,62,27,98,126,82,112,90,75,24,92,2,55,120,106,76,122,109,80,105,127,56,87,26,123,118,125,15,77,103,29,89,30,110,113 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_merge_active_stake::new_behavior";
  test.test_nonce  = 629;
  test.test_number = 301;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 5;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "8nDyGaaLD2E5NbpQKqtqyt8QYKwc3CdxeKPkddmCpDRp",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 4244707122UL;
  test_acc->result_lamports = 4244707122UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_301_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_301_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_301_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_301_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "3nWKsRHcGZMkxCqxwzoSkJL75s5d8c6KpzRfmtkuvQuH",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 4244707122UL;
  test_acc->result_lamports = 4244707122UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_301_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_301_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_301_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_301_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "HpKz3VfNTNBTdJS8PAqTGoEPk9RAHqBNmVjYhWxa3fUy",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_301_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_301_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_301_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_301_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_301_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_301_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_301_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_301_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_301_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_301_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_301_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_301_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_301_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_301_raw_sz;
  test.expected_result = -26;
  test.custom_err = 5;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_302(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 83,108,78,79,128,61,117,124,33,116,114,111,121,62,27,98,126,82,112,90,75,24,92,2,55,120,106,76,122,109,80,105,127,56,87,26,123,118,125,15,77,103,29,89,30,110,113 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_merge_active_stake::new_behavior";
  test.test_nonce  = 631;
  test.test_number = 302;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 5;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "8nDyGaaLD2E5NbpQKqtqyt8QYKwc3CdxeKPkddmCpDRp",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 4244707122UL;
  test_acc->result_lamports = 4244707122UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_302_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_302_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_302_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_302_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "3nWKsRHcGZMkxCqxwzoSkJL75s5d8c6KpzRfmtkuvQuH",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 4244707122UL;
  test_acc->result_lamports = 4244707122UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_302_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_302_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_302_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_302_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "HpKz3VfNTNBTdJS8PAqTGoEPk9RAHqBNmVjYhWxa3fUy",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_302_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_302_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_302_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_302_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_302_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_302_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_302_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_302_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_302_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_302_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_302_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_302_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_302_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_302_raw_sz;
  test.expected_result = -26;
  test.custom_err = 5;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_303(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 83,108,78,79,128,61,117,124,33,116,114,111,121,62,27,98,126,82,112,90,75,24,92,2,55,120,106,76,122,109,80,105,127,56,87,26,123,118,125,15,77,103,29,89,30,110,113 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_merge_active_stake::new_behavior";
  test.test_nonce  = 634;
  test.test_number = 303;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 5;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "8nDyGaaLD2E5NbpQKqtqyt8QYKwc3CdxeKPkddmCpDRp",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 4244707122UL;
  test_acc->result_lamports = 4244707122UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_303_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_303_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_303_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_303_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "3nWKsRHcGZMkxCqxwzoSkJL75s5d8c6KpzRfmtkuvQuH",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 4244707122UL;
  test_acc->result_lamports = 4244707122UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_303_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_303_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_303_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_303_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "HpKz3VfNTNBTdJS8PAqTGoEPk9RAHqBNmVjYhWxa3fUy",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_303_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_303_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_303_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_303_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_303_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_303_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_303_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_303_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_303_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_303_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_303_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_303_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_303_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_303_raw_sz;
  test.expected_result = -26;
  test.custom_err = 5;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_304(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 83,108,78,79,128,61,117,124,33,116,114,111,121,62,27,98,126,82,112,90,75,24,92,2,55,120,106,76,122,109,80,105,127,56,87,26,123,118,125,15,77,103,29,89,30,110,113 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_merge_active_stake::new_behavior";
  test.test_nonce  = 635;
  test.test_number = 304;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 5;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "8nDyGaaLD2E5NbpQKqtqyt8QYKwc3CdxeKPkddmCpDRp",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 4244707122UL;
  test_acc->result_lamports = 8489414244UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_304_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_304_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_304_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_304_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "3nWKsRHcGZMkxCqxwzoSkJL75s5d8c6KpzRfmtkuvQuH",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 4244707122UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_304_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_304_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_304_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_304_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "HpKz3VfNTNBTdJS8PAqTGoEPk9RAHqBNmVjYhWxa3fUy",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_304_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_304_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_304_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_304_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_304_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_304_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_304_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_304_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_304_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_304_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_304_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_304_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_304_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_304_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_305(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 83,108,78,79,128,61,117,124,33,116,114,111,121,62,27,98,126,82,112,90,75,24,92,2,55,120,106,76,122,109,80,105,127,56,87,26,123,118,125,15,77,103,29,89,30,110,113 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_merge_active_stake::new_behavior";
  test.test_nonce  = 638;
  test.test_number = 305;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 5;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "8nDyGaaLD2E5NbpQKqtqyt8QYKwc3CdxeKPkddmCpDRp",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 4244707122UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_305_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_305_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_305_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_305_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "3nWKsRHcGZMkxCqxwzoSkJL75s5d8c6KpzRfmtkuvQuH",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 4244707122UL;
  test_acc->result_lamports = 8489414244UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_305_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_305_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_305_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_305_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "HpKz3VfNTNBTdJS8PAqTGoEPk9RAHqBNmVjYhWxa3fUy",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_305_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_305_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_305_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_305_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_305_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_305_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_305_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_305_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_305_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_305_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_305_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_305_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_305_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_305_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_306(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 83,108,78,79,128,61,117,124,33,116,114,111,121,62,27,98,126,82,112,90,75,24,92,2,55,120,106,76,122,109,80,105,127,56,87,26,123,118,125,15,77,103,29,89,30,110,113 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_merge_active_stake::new_behavior";
  test.test_nonce  = 207;
  test.test_number = 306;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 5;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "HPupyEHGx5obkcTGAWxMkUm1wEBU7GNjXZYVmy2C84mn",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 4244707122UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_306_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_306_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_306_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_306_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "97jUK7hiGqWE5H7daG8jAV3JJ2fVbKpm4zgnMKcawQsp",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 4244707122UL;
  test_acc->result_lamports = 8489414244UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_306_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_306_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_306_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_306_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "FrMtC7PDULT3T41NMjLKB19XECXcM5wyMidxqy6mHojo",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_306_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_306_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_306_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_306_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_306_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_306_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_306_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_306_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_306_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_306_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_306_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_306_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_306_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_306_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_307(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 83,108,78,79,128,61,117,124,33,116,114,111,121,62,27,98,126,82,112,90,75,24,92,2,55,120,106,76,122,109,80,105,127,56,87,26,123,118,125,15,77,103,29,89,30,110,113 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_merge_active_stake::new_behavior";
  test.test_nonce  = 22;
  test.test_number = 307;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 5;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "HPupyEHGx5obkcTGAWxMkUm1wEBU7GNjXZYVmy2C84mn",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 4244707122UL;
  test_acc->result_lamports = 8489414244UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_307_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_307_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_307_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_307_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "97jUK7hiGqWE5H7daG8jAV3JJ2fVbKpm4zgnMKcawQsp",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 4244707122UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_307_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_307_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_307_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_307_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "FrMtC7PDULT3T41NMjLKB19XECXcM5wyMidxqy6mHojo",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_307_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_307_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_307_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_307_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_307_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_307_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_307_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_307_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_307_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_307_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_307_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_307_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_307_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_307_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_308(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 83,108,78,79,128,61,117,124,33,116,114,111,121,62,27,98,126,82,112,90,75,24,92,2,55,120,106,76,122,109,80,105,127,56,87,26,123,118,125,15,77,103,29,89,30,110,113 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_merge_active_stake::new_behavior";
  test.test_nonce  = 334;
  test.test_number = 308;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 5;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "HPupyEHGx5obkcTGAWxMkUm1wEBU7GNjXZYVmy2C84mn",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 4244707122UL;
  test_acc->result_lamports = 4244707122UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_308_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_308_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_308_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_308_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "97jUK7hiGqWE5H7daG8jAV3JJ2fVbKpm4zgnMKcawQsp",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 4244707122UL;
  test_acc->result_lamports = 4244707122UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_308_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_308_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_308_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_308_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "FrMtC7PDULT3T41NMjLKB19XECXcM5wyMidxqy6mHojo",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_308_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_308_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_308_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_308_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_308_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_308_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_308_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_308_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_308_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_308_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_308_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_308_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_308_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_308_raw_sz;
  test.expected_result = -26;
  test.custom_err = 5;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_309(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 83,108,78,79,128,61,117,124,33,116,114,111,121,62,27,98,126,82,112,90,75,24,92,2,55,120,106,76,122,109,80,105,127,56,87,26,123,118,125,15,77,103,29,89,30,110,113 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_merge_active_stake::new_behavior";
  test.test_nonce  = 406;
  test.test_number = 309;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 5;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "HPupyEHGx5obkcTGAWxMkUm1wEBU7GNjXZYVmy2C84mn",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 4244707122UL;
  test_acc->result_lamports = 4244707122UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_309_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_309_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_309_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_309_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "97jUK7hiGqWE5H7daG8jAV3JJ2fVbKpm4zgnMKcawQsp",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 4244707122UL;
  test_acc->result_lamports = 4244707122UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_309_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_309_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_309_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_309_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "FrMtC7PDULT3T41NMjLKB19XECXcM5wyMidxqy6mHojo",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_309_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_309_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_309_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_309_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_309_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_309_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_309_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_309_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_309_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_309_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_309_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_309_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_309_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_309_raw_sz;
  test.expected_result = -26;
  test.custom_err = 5;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_310(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 83,108,78,79,128,61,117,124,33,116,114,111,121,62,27,98,126,82,112,90,75,24,92,2,55,120,106,76,122,109,80,105,127,56,87,26,123,118,125,15,77,103,29,89,30,110,113 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_merge_active_stake::new_behavior";
  test.test_nonce  = 458;
  test.test_number = 310;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 5;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "HPupyEHGx5obkcTGAWxMkUm1wEBU7GNjXZYVmy2C84mn",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 4244707122UL;
  test_acc->result_lamports = 4244707122UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_310_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_310_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_310_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_310_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "97jUK7hiGqWE5H7daG8jAV3JJ2fVbKpm4zgnMKcawQsp",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 4244707122UL;
  test_acc->result_lamports = 4244707122UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_310_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_310_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_310_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_310_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "FrMtC7PDULT3T41NMjLKB19XECXcM5wyMidxqy6mHojo",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_310_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_310_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_310_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_310_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_310_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_310_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_310_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_310_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_310_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_310_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_310_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_310_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_310_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_310_raw_sz;
  test.expected_result = -26;
  test.custom_err = 5;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_311(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 83,108,78,79,128,61,117,124,33,116,114,111,121,62,27,98,126,82,112,90,75,24,92,2,55,120,106,76,122,109,80,105,127,56,87,26,123,118,125,15,77,103,29,89,30,110,113 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_merge_active_stake::new_behavior";
  test.test_nonce  = 516;
  test.test_number = 311;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 5;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "HPupyEHGx5obkcTGAWxMkUm1wEBU7GNjXZYVmy2C84mn",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 4244707122UL;
  test_acc->result_lamports = 4244707122UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_311_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_311_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_311_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_311_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "97jUK7hiGqWE5H7daG8jAV3JJ2fVbKpm4zgnMKcawQsp",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 4244707122UL;
  test_acc->result_lamports = 4244707122UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_311_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_311_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_311_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_311_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "FrMtC7PDULT3T41NMjLKB19XECXcM5wyMidxqy6mHojo",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_311_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_311_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_311_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_311_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_311_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_311_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_311_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_311_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_311_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_311_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_311_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_311_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_311_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_311_raw_sz;
  test.expected_result = -26;
  test.custom_err = 5;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_312(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 83,108,78,79,128,61,117,124,33,116,114,111,121,62,27,98,126,82,112,90,75,24,92,2,55,120,106,76,122,109,80,105,127,56,87,26,123,118,125,15,77,103,29,89,30,110,113 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_merge_active_stake::new_behavior";
  test.test_nonce  = 545;
  test.test_number = 312;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 5;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "HPupyEHGx5obkcTGAWxMkUm1wEBU7GNjXZYVmy2C84mn",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 4244707122UL;
  test_acc->result_lamports = 4244707122UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_312_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_312_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_312_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_312_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "97jUK7hiGqWE5H7daG8jAV3JJ2fVbKpm4zgnMKcawQsp",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 4244707122UL;
  test_acc->result_lamports = 4244707122UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_312_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_312_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_312_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_312_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "FrMtC7PDULT3T41NMjLKB19XECXcM5wyMidxqy6mHojo",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_312_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_312_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_312_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_312_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_312_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_312_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_312_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_312_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_312_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_312_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_312_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_312_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_312_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_312_raw_sz;
  test.expected_result = -26;
  test.custom_err = 5;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_313(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 83,108,78,79,128,61,117,124,33,116,114,111,121,62,27,98,126,82,112,90,75,24,92,2,55,120,106,76,122,109,80,105,127,56,87,26,123,118,125,15,77,103,29,89,30,110,113 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_merge_active_stake::new_behavior";
  test.test_nonce  = 570;
  test.test_number = 313;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 5;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "HPupyEHGx5obkcTGAWxMkUm1wEBU7GNjXZYVmy2C84mn",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 4244707122UL;
  test_acc->result_lamports = 4244707122UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_313_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_313_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_313_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_313_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "97jUK7hiGqWE5H7daG8jAV3JJ2fVbKpm4zgnMKcawQsp",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 4244707122UL;
  test_acc->result_lamports = 4244707122UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_313_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_313_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_313_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_313_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "FrMtC7PDULT3T41NMjLKB19XECXcM5wyMidxqy6mHojo",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_313_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_313_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_313_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_313_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_313_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_313_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_313_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_313_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_313_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_313_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_313_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_313_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_313_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_313_raw_sz;
  test.expected_result = -26;
  test.custom_err = 5;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_314(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 83,108,78,79,128,61,117,124,33,116,114,111,121,62,27,98,126,82,112,90,75,24,92,2,55,120,106,76,122,109,80,105,127,56,87,26,123,118,125,15,77,103,29,89,30,110,113 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_merge_active_stake::new_behavior";
  test.test_nonce  = 590;
  test.test_number = 314;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 5;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "HPupyEHGx5obkcTGAWxMkUm1wEBU7GNjXZYVmy2C84mn",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 4244707122UL;
  test_acc->result_lamports = 4244707122UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_314_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_314_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_314_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_314_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "97jUK7hiGqWE5H7daG8jAV3JJ2fVbKpm4zgnMKcawQsp",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 4244707122UL;
  test_acc->result_lamports = 4244707122UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_314_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_314_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_314_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_314_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "FrMtC7PDULT3T41NMjLKB19XECXcM5wyMidxqy6mHojo",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_314_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_314_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_314_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_314_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_314_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_314_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_314_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_314_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_314_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_314_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_314_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_314_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_314_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_314_raw_sz;
  test.expected_result = -26;
  test.custom_err = 5;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_315(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 83,108,78,79,128,61,117,124,33,116,114,111,121,62,27,98,126,82,112,90,75,24,92,2,55,120,106,76,122,109,80,105,127,56,87,26,123,118,125,15,77,103,29,89,30,110,113 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_merge_active_stake::new_behavior";
  test.test_nonce  = 598;
  test.test_number = 315;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 5;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "HPupyEHGx5obkcTGAWxMkUm1wEBU7GNjXZYVmy2C84mn",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 4244707122UL;
  test_acc->result_lamports = 4244707122UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_315_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_315_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_315_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_315_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "97jUK7hiGqWE5H7daG8jAV3JJ2fVbKpm4zgnMKcawQsp",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 4244707122UL;
  test_acc->result_lamports = 4244707122UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_315_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_315_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_315_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_315_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "FrMtC7PDULT3T41NMjLKB19XECXcM5wyMidxqy6mHojo",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_315_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_315_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_315_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_315_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_315_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_315_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_315_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_315_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_315_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_315_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_315_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_315_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_315_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_315_raw_sz;
  test.expected_result = -26;
  test.custom_err = 5;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_316(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 83,108,78,79,128,61,117,124,33,116,114,111,121,62,27,98,126,82,112,90,75,24,92,2,55,120,106,76,122,109,80,105,127,56,87,26,123,118,125,15,77,103,29,89,30,110,113 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_merge_active_stake::new_behavior";
  test.test_nonce  = 606;
  test.test_number = 316;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 5;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "HPupyEHGx5obkcTGAWxMkUm1wEBU7GNjXZYVmy2C84mn",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 4244707122UL;
  test_acc->result_lamports = 8489414244UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_316_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_316_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_316_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_316_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "97jUK7hiGqWE5H7daG8jAV3JJ2fVbKpm4zgnMKcawQsp",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 4244707122UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_316_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_316_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_316_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_316_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "FrMtC7PDULT3T41NMjLKB19XECXcM5wyMidxqy6mHojo",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_316_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_316_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_316_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_316_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_316_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_316_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_316_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_316_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_316_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_316_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_316_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_316_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_316_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_316_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_317(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 83,108,78,79,128,61,117,124,33,116,114,111,121,62,27,98,126,82,112,90,75,24,92,2,55,120,106,76,122,109,80,105,127,56,87,26,123,118,125,15,77,103,29,89,30,110,113 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_merge_active_stake::new_behavior";
  test.test_nonce  = 610;
  test.test_number = 317;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 5;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "HPupyEHGx5obkcTGAWxMkUm1wEBU7GNjXZYVmy2C84mn",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 4244707122UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_317_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_317_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_317_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_317_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "97jUK7hiGqWE5H7daG8jAV3JJ2fVbKpm4zgnMKcawQsp",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 4244707122UL;
  test_acc->result_lamports = 8489414244UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_317_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_317_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_317_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_317_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "FrMtC7PDULT3T41NMjLKB19XECXcM5wyMidxqy6mHojo",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_317_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_317_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_317_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_317_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_317_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_317_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_317_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_317_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_317_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_317_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_317_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_317_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_317_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_317_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_318(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 83,108,78,79,128,61,117,124,33,116,114,111,121,62,27,98,126,82,112,90,75,24,92,2,55,120,106,76,122,109,80,105,127,56,87,26,123,118,125,15,77,103,29,89,30,110,113 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_merge_active_stake::new_behavior";
  test.test_nonce  = 614;
  test.test_number = 318;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 5;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "HPupyEHGx5obkcTGAWxMkUm1wEBU7GNjXZYVmy2C84mn",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 4244707122UL;
  test_acc->result_lamports = 4244707122UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_318_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_318_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_318_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_318_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "97jUK7hiGqWE5H7daG8jAV3JJ2fVbKpm4zgnMKcawQsp",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 4244707122UL;
  test_acc->result_lamports = 4244707122UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_318_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_318_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_318_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_318_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "FrMtC7PDULT3T41NMjLKB19XECXcM5wyMidxqy6mHojo",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_318_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_318_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_318_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_318_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_318_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_318_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_318_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_318_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_318_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_318_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_318_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_318_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_318_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_318_raw_sz;
  test.expected_result = -26;
  test.custom_err = 5;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_319(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 83,108,78,79,128,61,117,124,33,116,114,111,121,62,27,98,126,82,112,90,75,24,92,2,55,120,106,76,122,109,80,105,127,56,87,26,123,118,125,15,77,103,29,89,30,110,113 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_merge_active_stake::new_behavior";
  test.test_nonce  = 619;
  test.test_number = 319;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 5;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "HPupyEHGx5obkcTGAWxMkUm1wEBU7GNjXZYVmy2C84mn",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 4244707122UL;
  test_acc->result_lamports = 4244707122UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_319_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_319_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_319_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_319_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "97jUK7hiGqWE5H7daG8jAV3JJ2fVbKpm4zgnMKcawQsp",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 4244707122UL;
  test_acc->result_lamports = 4244707122UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_319_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_319_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_319_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_319_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "FrMtC7PDULT3T41NMjLKB19XECXcM5wyMidxqy6mHojo",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_319_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_319_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_319_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_319_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_319_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_319_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_319_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_319_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_319_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_319_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_319_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_319_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_319_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_319_raw_sz;
  test.expected_result = -26;
  test.custom_err = 5;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_320(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 83,108,78,79,128,61,117,124,33,116,114,111,121,62,27,98,126,82,112,90,75,24,92,2,55,120,106,76,122,109,80,105,127,56,87,26,123,118,125,15,77,103,29,89,30,110,113 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_merge_active_stake::new_behavior";
  test.test_nonce  = 623;
  test.test_number = 320;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 5;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "HPupyEHGx5obkcTGAWxMkUm1wEBU7GNjXZYVmy2C84mn",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 4244707122UL;
  test_acc->result_lamports = 4244707122UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_320_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_320_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_320_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_320_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "97jUK7hiGqWE5H7daG8jAV3JJ2fVbKpm4zgnMKcawQsp",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 4244707122UL;
  test_acc->result_lamports = 4244707122UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_320_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_320_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_320_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_320_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "FrMtC7PDULT3T41NMjLKB19XECXcM5wyMidxqy6mHojo",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_320_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_320_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_320_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_320_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_320_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_320_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_320_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_320_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_320_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_320_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_320_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_320_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_320_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_320_raw_sz;
  test.expected_result = -26;
  test.custom_err = 5;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_321(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 83,108,78,79,128,61,117,124,33,116,114,111,121,62,27,98,126,82,112,90,75,24,92,2,55,120,106,76,122,109,80,105,127,56,87,26,123,118,125,15,77,103,29,89,30,110,113 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_merge_active_stake::new_behavior";
  test.test_nonce  = 628;
  test.test_number = 321;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 5;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "HPupyEHGx5obkcTGAWxMkUm1wEBU7GNjXZYVmy2C84mn",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 4244707122UL;
  test_acc->result_lamports = 4244707122UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_321_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_321_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_321_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_321_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "97jUK7hiGqWE5H7daG8jAV3JJ2fVbKpm4zgnMKcawQsp",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 4244707122UL;
  test_acc->result_lamports = 4244707122UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_321_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_321_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_321_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_321_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "FrMtC7PDULT3T41NMjLKB19XECXcM5wyMidxqy6mHojo",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_321_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_321_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_321_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_321_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_321_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_321_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_321_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_321_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_321_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_321_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_321_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_321_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_321_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_321_raw_sz;
  test.expected_result = -26;
  test.custom_err = 5;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_322(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 83,108,78,79,128,61,117,124,33,116,114,111,121,62,27,98,126,82,112,90,75,24,92,2,55,120,106,76,122,109,80,105,127,56,87,26,123,118,125,15,77,103,29,89,30,110,113 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_merge_active_stake::new_behavior";
  test.test_nonce  = 634;
  test.test_number = 322;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 5;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "HPupyEHGx5obkcTGAWxMkUm1wEBU7GNjXZYVmy2C84mn",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 4244707122UL;
  test_acc->result_lamports = 4244707122UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_322_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_322_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_322_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_322_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "97jUK7hiGqWE5H7daG8jAV3JJ2fVbKpm4zgnMKcawQsp",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 4244707122UL;
  test_acc->result_lamports = 4244707122UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_322_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_322_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_322_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_322_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "FrMtC7PDULT3T41NMjLKB19XECXcM5wyMidxqy6mHojo",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_322_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_322_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_322_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_322_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_322_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_322_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_322_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_322_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_322_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_322_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_322_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_322_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_322_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_322_raw_sz;
  test.expected_result = -26;
  test.custom_err = 5;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_323(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 83,108,78,79,128,61,117,124,33,116,114,111,121,62,27,98,126,82,112,90,75,24,92,2,55,120,106,76,122,109,80,105,127,56,87,26,123,118,125,15,77,103,29,89,30,110,113 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_merge_active_stake::new_behavior";
  test.test_nonce  = 637;
  test.test_number = 323;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 5;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "HPupyEHGx5obkcTGAWxMkUm1wEBU7GNjXZYVmy2C84mn",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 4244707122UL;
  test_acc->result_lamports = 4244707122UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_323_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_323_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_323_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_323_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "97jUK7hiGqWE5H7daG8jAV3JJ2fVbKpm4zgnMKcawQsp",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 4244707122UL;
  test_acc->result_lamports = 4244707122UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_323_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_323_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_323_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_323_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "FrMtC7PDULT3T41NMjLKB19XECXcM5wyMidxqy6mHojo",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_323_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_323_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_323_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_323_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_323_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_323_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_323_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_323_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_323_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_323_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_323_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_323_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_323_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_323_raw_sz;
  test.expected_result = -26;
  test.custom_err = 5;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_324(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 83,108,78,79,128,61,117,124,33,116,114,111,121,62,27,98,126,82,112,90,75,24,92,2,55,120,106,76,122,109,80,105,127,56,87,26,123,118,125,15,77,103,29,89,30,110,113 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_merge_active_stake::new_behavior";
  test.test_nonce  = 641;
  test.test_number = 324;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 5;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "HPupyEHGx5obkcTGAWxMkUm1wEBU7GNjXZYVmy2C84mn",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 4244707122UL;
  test_acc->result_lamports = 4244707122UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_324_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_324_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_324_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_324_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "97jUK7hiGqWE5H7daG8jAV3JJ2fVbKpm4zgnMKcawQsp",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 4244707122UL;
  test_acc->result_lamports = 4244707122UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_324_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_324_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_324_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_324_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "FrMtC7PDULT3T41NMjLKB19XECXcM5wyMidxqy6mHojo",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_324_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_324_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_324_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_324_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_324_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_324_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_324_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_324_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_324_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_324_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_324_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_324_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_324_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_324_raw_sz;
  test.expected_result = -26;
  test.custom_err = 5;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
