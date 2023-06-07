#include "../fd_tests.h"
int test_175(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 24,122,98,90,82,30,124,79,106,33,117,121,112,105,108,62,61,27,87,128,109,75,77,56,120,113,118,92,110,78,29,15,83,111,123,76,126,127,26,103,125,80,55,116,2,89,114 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_behavior_withdrawal_then_redelegate_with_less_than_minimum_stake_delegation::old_old_behavior";
  test.test_nonce  = 397;
  test.test_number = 175;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 7;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "5Lq46ZH9XNgQo6moXgqzg58bhn5KPeVFtgAZG26CjB5e",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2282881UL;
  test_acc->result_lamports = 2282881UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_175_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_175_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_175_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_175_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "79XA8mK44YkFq12FRtUhBXucz3uJas4bTXqobsqeNtEZ",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_175_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_175_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_175_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_175_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "4jSnxN1WnirAHr5aHgbwbjQ5YywgVtCWhRfVhvDJ9zVw",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2282880UL;
  test_acc->result_lamports = 2282880UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_175_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_175_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_175_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_175_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_175_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_175_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_175_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_175_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_175_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_175_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_175_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_175_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "StakeConfig11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_175_acc_5_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_175_acc_5_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_175_acc_5_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_175_acc_5_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_175_acc_6_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_175_acc_6_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_175_acc_6_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_175_acc_6_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_175_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_175_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_176(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 24,122,98,90,82,30,124,79,106,33,117,121,112,105,108,62,61,27,87,128,109,75,77,56,120,113,118,92,110,78,29,15,83,111,123,76,126,127,26,103,125,80,55,116,2,89,114 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_deactivate_delinquent::new_behavior";
  test.test_nonce  = 104;
  test.test_number = 176;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "11111112D1oxKts8YPdTJRG5FzxTNpMtWmq8hkVx3",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_176_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_176_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_176_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_176_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111ogCyDbaRMvkdsHB3qfdyFYaG1WtRUAfdh",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_176_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_176_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_176_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_176_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111QLbz7JHiBTspS962RLKV8GndWFwiEaqKM",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_176_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_176_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_176_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_176_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_176_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_176_raw_sz;
  test.expected_result = -26;
  test.custom_err = 9;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_177(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 24,122,98,90,82,30,124,79,106,33,117,121,112,105,108,62,61,27,87,128,109,75,77,56,120,113,118,92,110,78,29,15,83,111,123,76,126,127,26,103,125,80,55,116,2,89,114 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_deactivate_delinquent::new_behavior";
  test.test_nonce  = 141;
  test.test_number = 177;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "11111112D1oxKts8YPdTJRG5FzxTNpMtWmq8hkVx3",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_177_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_177_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_177_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_177_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111ogCyDbaRMvkdsHB3qfdyFYaG1WtRUAfdh",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_177_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_177_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_177_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_177_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111QLbz7JHiBTspS962RLKV8GndWFwiEaqKM",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_177_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_177_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_177_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_177_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_177_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_177_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_178(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 24,122,98,90,82,30,124,79,106,33,117,121,112,105,108,62,61,27,87,128,109,75,77,56,120,113,118,92,110,78,29,15,83,111,123,76,126,127,26,103,125,80,55,116,2,89,114 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_deactivate_delinquent::new_behavior";
  test.test_nonce  = 164;
  test.test_number = 178;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "11111112D1oxKts8YPdTJRG5FzxTNpMtWmq8hkVx3",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_178_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_178_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_178_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_178_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111ogCyDbaRMvkdsHB3qfdyFYaG1WtRUAfdh",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_178_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_178_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_178_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_178_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111QLbz7JHiBTspS962RLKV8GndWFwiEaqKM",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_178_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_178_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_178_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_178_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_178_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_178_raw_sz;
  test.expected_result = -26;
  test.custom_err = 9;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_179(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 24,122,98,90,82,30,124,79,106,33,117,121,112,105,108,62,61,27,87,128,109,75,77,56,120,113,118,92,110,78,29,15,83,111,123,76,126,127,26,103,125,80,55,116,2,89,114 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_deactivate_delinquent::new_behavior";
  test.test_nonce  = 167;
  test.test_number = 179;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "11111112D1oxKts8YPdTJRG5FzxTNpMtWmq8hkVx3",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_179_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_179_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_179_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_179_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111ogCyDbaRMvkdsHB3qfdyFYaG1WtRUAfdh",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_179_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_179_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_179_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_179_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111QLbz7JHiBTspS962RLKV8GndWFwiEaqKM",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_179_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_179_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_179_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_179_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_179_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_179_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_180(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 24,122,98,90,82,30,124,79,106,33,117,121,112,105,108,62,61,27,87,128,109,75,77,56,120,113,118,92,110,78,29,15,83,111,123,76,126,127,26,103,125,80,55,116,2,89,114 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_deactivate_delinquent::new_behavior";
  test.test_nonce  = 190;
  test.test_number = 180;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111111UMz1xPGbHGWacUUtfXefyXWVoJX9LvfeWT",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_180_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_180_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_180_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_180_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111ogCyDbaRMvkdsHB3qfdyFYaG1WtRUAfdh",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_180_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_180_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_180_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_180_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111QLbz7JHiBTspS962RLKV8GndWFwiEaqKM",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_180_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_180_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_180_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_180_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_180_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_180_raw_sz;
  test.expected_result = -26;
  test.custom_err = 10;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_181(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 24,122,98,90,82,30,124,79,106,33,117,121,112,105,108,62,61,27,87,128,109,75,77,56,120,113,118,92,110,78,29,15,83,111,123,76,126,127,26,103,125,80,55,116,2,89,114 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_deactivate_delinquent::new_behavior";
  test.test_nonce  = 223;
  test.test_number = 181;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "11111112D1oxKts8YPdTJRG5FzxTNpMtWmq8hkVx3",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_181_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_181_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_181_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_181_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111ogCyDbaRMvkdsHB3qfdyFYaG1WtRUAfdh",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_181_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_181_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_181_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_181_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111QLbz7JHiBTspS962RLKV8GndWFwiEaqKM",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_181_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_181_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_181_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_181_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_181_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_181_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_182(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 24,122,98,90,82,30,124,79,106,33,117,121,112,105,108,62,61,27,87,128,109,75,77,56,120,113,118,92,110,78,29,15,83,111,123,76,126,127,26,103,125,80,55,116,2,89,114 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_deactivate_delinquent::new_behavior";
  test.test_nonce  = 235;
  test.test_number = 182;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "11111112D1oxKts8YPdTJRG5FzxTNpMtWmq8hkVx3",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_182_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_182_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_182_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_182_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111ogCyDbaRMvkdsHB3qfdyFYaG1WtRUAfdh",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_182_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_182_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_182_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_182_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111QLbz7JHiBTspS962RLKV8GndWFwiEaqKM",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_182_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_182_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_182_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_182_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_182_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_182_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_183(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 24,122,98,90,82,30,124,79,106,33,117,121,112,105,108,62,61,27,87,128,109,75,77,56,120,113,118,92,110,78,29,15,83,111,123,76,126,127,26,103,125,80,55,116,2,89,114 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_deactivate_delinquent::new_behavior";
  test.test_nonce  = 251;
  test.test_number = 183;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "11111112D1oxKts8YPdTJRG5FzxTNpMtWmq8hkVx3",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_183_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_183_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_183_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_183_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111ogCyDbaRMvkdsHB3qfdyFYaG1WtRUAfdh",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_183_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_183_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_183_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_183_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111QLbz7JHiBTspS962RLKV8GndWFwiEaqKM",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_183_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_183_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_183_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_183_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_183_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_183_raw_sz;
  test.expected_result = -26;
  test.custom_err = 11;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_184(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 24,122,98,90,82,30,124,79,106,33,117,121,112,105,108,62,61,27,87,128,109,75,77,56,120,113,118,92,110,78,29,15,83,111,123,76,126,127,26,103,125,80,55,116,2,89,114 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_deactivate_delinquent::new_behavior";
  test.test_nonce  = 26;
  test.test_number = 184;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "11111112D1oxKts8YPdTJRG5FzxTNpMtWmq8hkVx3",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_184_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_184_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_184_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_184_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111ogCyDbaRMvkdsHB3qfdyFYaG1WtRUAfdh",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_184_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_184_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_184_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_184_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111QLbz7JHiBTspS962RLKV8GndWFwiEaqKM",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_184_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_184_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_184_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_184_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_184_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_184_raw_sz;
  test.expected_result = -26;
  test.custom_err = 9;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_185(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 24,122,98,90,82,30,124,79,106,33,117,121,112,105,108,62,61,27,87,128,109,75,77,56,120,113,118,92,110,78,29,15,83,111,123,76,126,127,26,103,125,80,55,116,2,89,114 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_deactivate_delinquent::new_behavior";
  test.test_nonce  = 297;
  test.test_number = 185;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "11111112D1oxKts8YPdTJRG5FzxTNpMtWmq8hkVx3",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_185_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_185_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_185_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_185_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111ogCyDbaRMvkdsHB3qfdyFYaG1WtRUAfdh",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_185_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_185_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_185_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_185_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111QLbz7JHiBTspS962RLKV8GndWFwiEaqKM",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_185_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_185_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_185_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_185_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_185_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_185_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_186(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 24,122,98,90,82,30,124,79,106,33,117,121,112,105,108,62,61,27,87,128,109,75,77,56,120,113,118,92,110,78,29,15,83,111,123,76,126,127,26,103,125,80,55,116,2,89,114 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_deactivate_delinquent::new_behavior";
  test.test_nonce  = 319;
  test.test_number = 186;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111111gqTiUkWXHrsjxuoaRXyZ1QwtJwWPPBkUK9",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_186_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_186_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_186_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_186_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111ogCyDbaRMvkdsHB3qfdyFYaG1WtRUAfdh",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_186_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_186_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_186_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_186_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111QLbz7JHiBTspS962RLKV8GndWFwiEaqKM",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_186_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_186_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_186_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_186_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_186_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_186_raw_sz;
  test.expected_result = -26;
  test.custom_err = 10;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_187(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 24,122,98,90,82,30,124,79,106,33,117,121,112,105,108,62,61,27,87,128,109,75,77,56,120,113,118,92,110,78,29,15,83,111,123,76,126,127,26,103,125,80,55,116,2,89,114 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_deactivate_delinquent::new_behavior";
  test.test_nonce  = 350;
  test.test_number = 187;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "11111112D1oxKts8YPdTJRG5FzxTNpMtWmq8hkVx3",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_187_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_187_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_187_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_187_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111ogCyDbaRMvkdsHB3qfdyFYaG1WtRUAfdh",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_187_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_187_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_187_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_187_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111QLbz7JHiBTspS962RLKV8GndWFwiEaqKM",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_187_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_187_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_187_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_187_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_187_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_187_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_188(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 24,122,98,90,82,30,124,79,106,33,117,121,112,105,108,62,61,27,87,128,109,75,77,56,120,113,118,92,110,78,29,15,83,111,123,76,126,127,26,103,125,80,55,116,2,89,114 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_deactivate_delinquent::new_behavior";
  test.test_nonce  = 373;
  test.test_number = 188;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "11111112D1oxKts8YPdTJRG5FzxTNpMtWmq8hkVx3",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_188_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_188_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_188_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_188_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111ogCyDbaRMvkdsHB3qfdyFYaG1WtRUAfdh",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_188_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_188_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_188_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_188_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111QLbz7JHiBTspS962RLKV8GndWFwiEaqKM",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_188_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_188_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_188_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_188_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_188_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_188_raw_sz;
  test.expected_result = -26;
  test.custom_err = 11;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_189(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 24,122,98,90,82,30,124,79,106,33,117,121,112,105,108,62,61,27,87,128,109,75,77,56,120,113,118,92,110,78,29,15,83,111,123,76,126,127,26,103,125,80,55,116,2,89,114 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_deactivate_delinquent::new_behavior";
  test.test_nonce  = 6;
  test.test_number = 189;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "11111112D1oxKts8YPdTJRG5FzxTNpMtWmq8hkVx3",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_189_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_189_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_189_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_189_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111ogCyDbaRMvkdsHB3qfdyFYaG1WtRUAfdh",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_189_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_189_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_189_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_189_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111QLbz7JHiBTspS962RLKV8GndWFwiEaqKM",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_189_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_189_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_189_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_189_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_189_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_189_raw_sz;
  test.expected_result = -26;
  test.custom_err = 9;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_190(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 24,122,98,90,82,30,124,79,106,33,117,121,112,105,108,62,61,27,87,128,109,75,77,56,120,113,118,92,110,78,29,15,83,111,123,76,126,127,26,103,125,80,55,116,2,89,114 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_deactivate_delinquent::new_behavior";
  test.test_nonce  = 74;
  test.test_number = 190;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "11111112D1oxKts8YPdTJRG5FzxTNpMtWmq8hkVx3",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_190_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_190_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_190_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_190_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111ogCyDbaRMvkdsHB3qfdyFYaG1WtRUAfdh",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_190_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_190_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_190_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_190_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111QLbz7JHiBTspS962RLKV8GndWFwiEaqKM",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_190_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_190_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_190_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_190_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_190_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_190_raw_sz;
  test.expected_result = -26;
  test.custom_err = 9;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_191(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 24,122,98,90,82,30,124,79,106,33,117,121,112,105,108,62,61,27,87,128,109,75,77,56,120,113,118,92,110,78,29,15,83,111,123,76,126,127,26,103,125,80,55,116,2,89,114 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_deactivate_delinquent::new_behavior";
  test.test_nonce  = 90;
  test.test_number = 191;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "11111112D1oxKts8YPdTJRG5FzxTNpMtWmq8hkVx3",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_191_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_191_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_191_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_191_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111ogCyDbaRMvkdsHB3qfdyFYaG1WtRUAfdh",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_191_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_191_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_191_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_191_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111QLbz7JHiBTspS962RLKV8GndWFwiEaqKM",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_191_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_191_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_191_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_191_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_191_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_191_raw_sz;
  test.expected_result = -26;
  test.custom_err = 9;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_192(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 1;
  uchar disabled_features[] = { 89 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_deactivate_delinquent::old_behavior";
  test.test_nonce  = 108;
  test.test_number = 192;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "11111113R2cuenjG5nFubqX9Wzuukdin2YfGQVzu5",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_192_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_192_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_192_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_192_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "111111131h1vYVSYuKP6AhS86fbRdMw9XHiZAvAaj",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_192_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_192_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_192_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_192_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111112cMQwSC9qirWGjZM6gLGwW69X22mqwLLGP",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_192_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_192_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_192_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_192_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_192_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_192_raw_sz;
  test.expected_result = -26;
  test.custom_err = 9;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_193(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 1;
  uchar disabled_features[] = { 89 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_deactivate_delinquent::old_behavior";
  test.test_nonce  = 120;
  test.test_number = 193;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "11111113R2cuenjG5nFubqX9Wzuukdin2YfGQVzu5",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_193_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_193_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_193_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_193_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "111111131h1vYVSYuKP6AhS86fbRdMw9XHiZAvAaj",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_193_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_193_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_193_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_193_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111112cMQwSC9qirWGjZM6gLGwW69X22mqwLLGP",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_193_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_193_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_193_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_193_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_193_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_193_raw_sz;
  test.expected_result = -26;
  test.custom_err = 9;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_194(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 1;
  uchar disabled_features[] = { 89 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_deactivate_delinquent::old_behavior";
  test.test_nonce  = 161;
  test.test_number = 194;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "11111113R2cuenjG5nFubqX9Wzuukdin2YfGQVzu5",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_194_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_194_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_194_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_194_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "111111131h1vYVSYuKP6AhS86fbRdMw9XHiZAvAaj",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_194_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_194_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_194_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_194_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111112cMQwSC9qirWGjZM6gLGwW69X22mqwLLGP",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_194_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_194_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_194_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_194_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_194_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_194_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_195(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 1;
  uchar disabled_features[] = { 89 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_deactivate_delinquent::old_behavior";
  test.test_nonce  = 184;
  test.test_number = 195;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "11111113R2cuenjG5nFubqX9Wzuukdin2YfGQVzu5",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_195_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_195_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_195_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_195_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "111111131h1vYVSYuKP6AhS86fbRdMw9XHiZAvAaj",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_195_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_195_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_195_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_195_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111112cMQwSC9qirWGjZM6gLGwW69X22mqwLLGP",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_195_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_195_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_195_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_195_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_195_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_195_raw_sz;
  test.expected_result = -26;
  test.custom_err = 9;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_196(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 1;
  uchar disabled_features[] = { 89 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_deactivate_delinquent::old_behavior";
  test.test_nonce  = 189;
  test.test_number = 196;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "11111113R2cuenjG5nFubqX9Wzuukdin2YfGQVzu5",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_196_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_196_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_196_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_196_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "111111131h1vYVSYuKP6AhS86fbRdMw9XHiZAvAaj",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_196_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_196_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_196_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_196_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111112cMQwSC9qirWGjZM6gLGwW69X22mqwLLGP",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_196_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_196_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_196_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_196_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_196_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_196_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_197(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 1;
  uchar disabled_features[] = { 89 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_deactivate_delinquent::old_behavior";
  test.test_nonce  = 231;
  test.test_number = 197;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111111aoPfi83Ce9vbhQiH4EymjXs5sNeEifzyZy",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_197_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_197_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_197_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_197_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "111111131h1vYVSYuKP6AhS86fbRdMw9XHiZAvAaj",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_197_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_197_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_197_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_197_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111112cMQwSC9qirWGjZM6gLGwW69X22mqwLLGP",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_197_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_197_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_197_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_197_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_197_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_197_raw_sz;
  test.expected_result = -26;
  test.custom_err = 10;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_198(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 1;
  uchar disabled_features[] = { 89 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_deactivate_delinquent::old_behavior";
  test.test_nonce  = 256;
  test.test_number = 198;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "11111113R2cuenjG5nFubqX9Wzuukdin2YfGQVzu5",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_198_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_198_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_198_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_198_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "111111131h1vYVSYuKP6AhS86fbRdMw9XHiZAvAaj",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_198_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_198_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_198_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_198_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111112cMQwSC9qirWGjZM6gLGwW69X22mqwLLGP",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_198_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_198_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_198_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_198_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_198_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_198_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_199(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 1;
  uchar disabled_features[] = { 89 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_deactivate_delinquent::old_behavior";
  test.test_nonce  = 257;
  test.test_number = 199;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "11111113R2cuenjG5nFubqX9Wzuukdin2YfGQVzu5",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_199_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_199_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_199_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_199_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "111111131h1vYVSYuKP6AhS86fbRdMw9XHiZAvAaj",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_199_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_199_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_199_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_199_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111112cMQwSC9qirWGjZM6gLGwW69X22mqwLLGP",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_199_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_199_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_199_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_199_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_199_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_199_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
