#include "../fd_tests.h"
int test_625(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 1;
  uchar disabled_features[] = { 89 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_set_lockup::old_behavior";
  test.test_nonce  = 613;
  test.test_number = 625;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 8;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "8WU9zSWDU3hKLhKW4ZUs2adbrDFbqQM3TghE6xdcbLiV",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_625_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_625_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_625_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_625_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "8ZoALppn3VLvvUPwEUQDkXo5TA8EZ4LWekCYqtL56SaP",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_625_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_625_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_625_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_625_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Aue963DTZK22gsCQMyATXMk3k4HuLfrxNJe98qo9mR3H",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_625_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_625_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_625_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_625_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "39hmeJmzvWdNeQFU3xwJnAcpoDmhDD2ffyQhDvh53WuD",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_625_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_625_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_625_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_625_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_625_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_625_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_625_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_625_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_625_acc_5_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_625_acc_5_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_625_acc_5_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_625_acc_5_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_625_acc_6_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_625_acc_6_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_625_acc_6_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_625_acc_6_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "StakeConfig11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_625_acc_7_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_625_acc_7_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_625_acc_7_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_625_acc_7_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_625_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_625_raw_sz;
  test.expected_result = -8;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_626(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 1;
  uchar disabled_features[] = { 89 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_set_lockup::old_behavior";
  test.test_nonce  = 620;
  test.test_number = 626;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 8;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "8WU9zSWDU3hKLhKW4ZUs2adbrDFbqQM3TghE6xdcbLiV",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_626_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_626_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_626_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_626_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "8ZoALppn3VLvvUPwEUQDkXo5TA8EZ4LWekCYqtL56SaP",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_626_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_626_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_626_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_626_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Aue963DTZK22gsCQMyATXMk3k4HuLfrxNJe98qo9mR3H",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_626_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_626_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_626_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_626_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "39hmeJmzvWdNeQFU3xwJnAcpoDmhDD2ffyQhDvh53WuD",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_626_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_626_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_626_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_626_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_626_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_626_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_626_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_626_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_626_acc_5_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_626_acc_5_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_626_acc_5_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_626_acc_5_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_626_acc_6_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_626_acc_6_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_626_acc_6_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_626_acc_6_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "StakeConfig11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_626_acc_7_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_626_acc_7_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_626_acc_7_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_626_acc_7_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_626_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_626_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_627(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 1;
  uchar disabled_features[] = { 89 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_set_lockup::old_behavior";
  test.test_nonce  = 632;
  test.test_number = 627;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 8;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "8WU9zSWDU3hKLhKW4ZUs2adbrDFbqQM3TghE6xdcbLiV",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_627_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_627_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_627_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_627_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "8ZoALppn3VLvvUPwEUQDkXo5TA8EZ4LWekCYqtL56SaP",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_627_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_627_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_627_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_627_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Aue963DTZK22gsCQMyATXMk3k4HuLfrxNJe98qo9mR3H",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_627_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_627_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_627_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_627_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "39hmeJmzvWdNeQFU3xwJnAcpoDmhDD2ffyQhDvh53WuD",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_627_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_627_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_627_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_627_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_627_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_627_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_627_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_627_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_627_acc_5_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_627_acc_5_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_627_acc_5_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_627_acc_5_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_627_acc_6_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_627_acc_6_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_627_acc_6_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_627_acc_6_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "StakeConfig11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_627_acc_7_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_627_acc_7_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_627_acc_7_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_627_acc_7_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_627_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_627_raw_sz;
  test.expected_result = -8;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_628(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 15,27,123,112,128,87,29,30,92,111,106,75,83,114,24,80,113,105,124,109,26,82,125,78,89,33,2,126,116,55,122,127,76,61,103,121,62,120,98,117,108,110,90,56,118,79,77 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_split_100_percent_of_source::new_behavior";
  test.test_nonce  = 103;
  test.test_number = 628;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "H3oHBALFMfpmiUFp1dPrqkFw7p7xnPF8VDrvKP9p8H81",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1002282880UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_628_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_628_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_628_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_628_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "B5Je7wrLAS72HhjpLzCPyxSfhjrAKtkCWm6RtQU2wD2x",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 1002282880UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_628_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_628_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_628_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_628_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_628_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_628_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_628_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_628_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_628_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_628_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_629(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 15,27,123,112,128,87,29,30,92,111,106,75,83,114,24,80,113,105,124,109,26,82,125,78,89,33,2,126,116,55,122,127,76,61,103,121,62,120,98,117,108,110,90,56,118,79,77 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_split_100_percent_of_source::new_behavior";
  test.test_nonce  = 44;
  test.test_number = 629;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "H3oHBALFMfpmiUFp1dPrqkFw7p7xnPF8VDrvKP9p8H81",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1002282880UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_629_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_629_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_629_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_629_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "B5Je7wrLAS72HhjpLzCPyxSfhjrAKtkCWm6RtQU2wD2x",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 1002282880UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_629_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_629_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_629_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_629_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_629_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_629_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_629_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_629_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_629_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_629_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_630(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 15,27,123,112,128,87,29,30,92,111,106,75,83,114,24,80,113,105,124,109,26,82,125,78,89,33,2,126,116,55,122,127,76,61,103,121,62,120,98,117,108,110,90,56,118,79,77 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_split_100_percent_of_source::new_behavior";
  test.test_nonce  = 44;
  test.test_number = 630;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "CaMZcjQ9FrW39xf6ph2PMfLEAyb6wHC9Z6tsucS2RSbr",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1002282880UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_630_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_630_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_630_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_630_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "6J1EDdkiQJHHchg3Soq9Lodwscy36Rnp3qjBY3LW4p8A",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 1002282880UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_630_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_630_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_630_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_630_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_630_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_630_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_630_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_630_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_630_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_630_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_631(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 15,27,123,112,128,87,29,30,92,111,106,75,83,114,24,80,113,105,124,109,26,82,125,78,89,33,2,126,116,55,122,127,76,61,103,121,62,120,98,117,108,110,90,56,118,79,77 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_split_100_percent_of_source::new_behavior";
  test.test_nonce  = 60;
  test.test_number = 631;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "CaMZcjQ9FrW39xf6ph2PMfLEAyb6wHC9Z6tsucS2RSbr",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1002282880UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_631_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_631_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_631_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_631_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "6J1EDdkiQJHHchg3Soq9Lodwscy36Rnp3qjBY3LW4p8A",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 1002282880UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_631_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_631_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_631_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_631_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_631_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_631_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_631_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_631_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_631_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_631_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_632(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 29,105,112,55,109,120,77,27,121,128,108,126,83,110,90,15,24,26,106,78,82,123,113,122,124,62,114,127,80,98,87,89,111,118,2,116,92,117,79,125,61,76,56,30,33,75,103 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_split_100_percent_of_source::old_behavior";
  test.test_nonce  = 38;
  test.test_number = 632;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "GRjHShS6oAUfDAN3KfeW4tZDrGqVsVhZP683bzVLk85P",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2282881UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_632_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_632_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_632_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_632_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "xJouYwa9kab8m1Sgnv3SbggMmLnRspo28KBq38EZ4uw",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 2282881UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_632_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_632_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_632_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_632_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_632_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_632_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_632_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_632_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_632_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_632_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_633(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 29,105,112,55,109,120,77,27,121,128,108,126,83,110,90,15,24,26,106,78,82,123,113,122,124,62,114,127,80,98,87,89,111,118,2,116,92,117,79,125,61,76,56,30,33,75,103 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_split_100_percent_of_source::old_behavior";
  test.test_nonce  = 86;
  test.test_number = 633;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "GRjHShS6oAUfDAN3KfeW4tZDrGqVsVhZP683bzVLk85P",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2282881UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_633_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_633_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_633_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_633_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "xJouYwa9kab8m1Sgnv3SbggMmLnRspo28KBq38EZ4uw",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 2282881UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_633_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_633_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_633_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_633_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_633_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_633_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_633_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_633_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_633_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_633_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_634(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 1;
  uchar disabled_features[] = { 89 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_split_100_percent_of_source::old_behavior";
  test.test_nonce  = 47;
  test.test_number = 634;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "37KbMiKLe4Rf4EAAcd566uPVx4SYQrp11T8k9rGkJGpH",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2282881UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_634_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_634_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_634_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_634_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Ci2JP7yYBjq892FrHR9FjgQEVokWGHoHhPgvk1kLrmCv",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 2282881UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_634_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_634_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_634_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_634_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_634_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_634_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_634_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_634_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_634_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_634_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_635(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 1;
  uchar disabled_features[] = { 89 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_split_100_percent_of_source::old_behavior";
  test.test_nonce  = 77;
  test.test_number = 635;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "37KbMiKLe4Rf4EAAcd566uPVx4SYQrp11T8k9rGkJGpH",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2282881UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_635_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_635_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_635_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_635_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Ci2JP7yYBjq892FrHR9FjgQEVokWGHoHhPgvk1kLrmCv",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 2282881UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_635_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_635_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_635_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_635_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_635_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_635_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_635_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_635_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_635_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_635_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_636(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 55,2,103,30,82,118,121,108,114,128,111,92,122,27,125,106,78,33,109,87,75,117,29,56,105,76,124,98,83,112,116,126,123,62,90,61,113,24,110,15,89,127,26,80,77,120,79 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_split_100_percent_of_source_to_account_with_lamports::new_behavior";
  test.test_nonce  = 118;
  test.test_number = 636;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "5MdSLRZujjTUAu5hGGDyeGnSQQNmQoy3TQ4QMsNBK5xi",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1002282880UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_636_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_636_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_636_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_636_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "8jtMV6bBJ5i6Ywcy2E9oKeuTX3S3aee7kdYXoq8kcxaS",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2282880UL;
  test_acc->result_lamports = 1004565760UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_636_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_636_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_636_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_636_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_636_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_636_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_636_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_636_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_636_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_636_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_637(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 55,2,103,30,82,118,121,108,114,128,111,92,122,27,125,106,78,33,109,87,75,117,29,56,105,76,124,98,83,112,116,126,123,62,90,61,113,24,110,15,89,127,26,80,77,120,79 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_split_100_percent_of_source_to_account_with_lamports::new_behavior";
  test.test_nonce  = 144;
  test.test_number = 637;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "5MdSLRZujjTUAu5hGGDyeGnSQQNmQoy3TQ4QMsNBK5xi",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1002282880UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_637_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_637_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_637_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_637_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "8jtMV6bBJ5i6Ywcy2E9oKeuTX3S3aee7kdYXoq8kcxaS",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1002282879UL;
  test_acc->result_lamports = 2004565759UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_637_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_637_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_637_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_637_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_637_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_637_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_637_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_637_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_637_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_637_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_638(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 55,2,103,30,82,118,121,108,114,128,111,92,122,27,125,106,78,33,109,87,75,117,29,56,105,76,124,98,83,112,116,126,123,62,90,61,113,24,110,15,89,127,26,80,77,120,79 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_split_100_percent_of_source_to_account_with_lamports::new_behavior";
  test.test_nonce  = 166;
  test.test_number = 638;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "5MdSLRZujjTUAu5hGGDyeGnSQQNmQoy3TQ4QMsNBK5xi",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1002282880UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_638_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_638_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_638_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_638_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "8jtMV6bBJ5i6Ywcy2E9oKeuTX3S3aee7kdYXoq8kcxaS",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1002282880UL;
  test_acc->result_lamports = 2004565760UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_638_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_638_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_638_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_638_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_638_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_638_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_638_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_638_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_638_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_638_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_639(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 55,2,103,30,82,118,121,108,114,128,111,92,122,27,125,106,78,33,109,87,75,117,29,56,105,76,124,98,83,112,116,126,123,62,90,61,113,24,110,15,89,127,26,80,77,120,79 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_split_100_percent_of_source_to_account_with_lamports::new_behavior";
  test.test_nonce  = 69;
  test.test_number = 639;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "5MdSLRZujjTUAu5hGGDyeGnSQQNmQoy3TQ4QMsNBK5xi",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1002282880UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_639_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_639_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_639_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_639_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "8jtMV6bBJ5i6Ywcy2E9oKeuTX3S3aee7kdYXoq8kcxaS",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 1002282880UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_639_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_639_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_639_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_639_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_639_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_639_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_639_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_639_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_639_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_639_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_640(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 55,2,103,30,82,118,121,108,114,128,111,92,122,27,125,106,78,33,109,87,75,117,29,56,105,76,124,98,83,112,116,126,123,62,90,61,113,24,110,15,89,127,26,80,77,120,79 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_split_100_percent_of_source_to_account_with_lamports::new_behavior";
  test.test_nonce  = 98;
  test.test_number = 640;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "5MdSLRZujjTUAu5hGGDyeGnSQQNmQoy3TQ4QMsNBK5xi",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1002282880UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_640_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_640_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_640_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_640_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "8jtMV6bBJ5i6Ywcy2E9oKeuTX3S3aee7kdYXoq8kcxaS",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2282879UL;
  test_acc->result_lamports = 1004565759UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_640_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_640_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_640_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_640_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_640_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_640_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_640_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_640_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_640_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_640_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_641(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 55,2,103,30,82,118,121,108,114,128,111,92,122,27,125,106,78,33,109,87,75,117,29,56,105,76,124,98,83,112,116,126,123,62,90,61,113,24,110,15,89,127,26,80,77,120,79 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_split_100_percent_of_source_to_account_with_lamports::new_behavior";
  test.test_nonce  = 126;
  test.test_number = 641;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "J4DuSjgTpVEUpJii7FbhsNyUMKSZBw4PRTv8hBb823C",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1002282880UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_641_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_641_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_641_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_641_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "GdA5NqQHzA6ZEmuHB8bRL7eLN2UUXNHzoxwr52Nxitid",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1002282880UL;
  test_acc->result_lamports = 2004565760UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_641_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_641_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_641_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_641_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_641_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_641_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_641_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_641_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_641_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_641_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_642(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 55,2,103,30,82,118,121,108,114,128,111,92,122,27,125,106,78,33,109,87,75,117,29,56,105,76,124,98,83,112,116,126,123,62,90,61,113,24,110,15,89,127,26,80,77,120,79 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_split_100_percent_of_source_to_account_with_lamports::new_behavior";
  test.test_nonce  = 52;
  test.test_number = 642;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "J4DuSjgTpVEUpJii7FbhsNyUMKSZBw4PRTv8hBb823C",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1002282880UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_642_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_642_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_642_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_642_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "GdA5NqQHzA6ZEmuHB8bRL7eLN2UUXNHzoxwr52Nxitid",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 1002282880UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_642_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_642_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_642_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_642_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_642_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_642_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_642_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_642_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_642_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_642_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_643(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 55,2,103,30,82,118,121,108,114,128,111,92,122,27,125,106,78,33,109,87,75,117,29,56,105,76,124,98,83,112,116,126,123,62,90,61,113,24,110,15,89,127,26,80,77,120,79 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_split_100_percent_of_source_to_account_with_lamports::new_behavior";
  test.test_nonce  = 76;
  test.test_number = 643;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "J4DuSjgTpVEUpJii7FbhsNyUMKSZBw4PRTv8hBb823C",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1002282880UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_643_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_643_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_643_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_643_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "GdA5NqQHzA6ZEmuHB8bRL7eLN2UUXNHzoxwr52Nxitid",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2282879UL;
  test_acc->result_lamports = 1004565759UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_643_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_643_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_643_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_643_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_643_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_643_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_643_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_643_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_643_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_643_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_644(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 55,2,103,30,82,118,121,108,114,128,111,92,122,27,125,106,78,33,109,87,75,117,29,56,105,76,124,98,83,112,116,126,123,62,90,61,113,24,110,15,89,127,26,80,77,120,79 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_split_100_percent_of_source_to_account_with_lamports::new_behavior";
  test.test_nonce  = 89;
  test.test_number = 644;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "J4DuSjgTpVEUpJii7FbhsNyUMKSZBw4PRTv8hBb823C",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1002282880UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_644_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_644_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_644_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_644_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "GdA5NqQHzA6ZEmuHB8bRL7eLN2UUXNHzoxwr52Nxitid",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2282880UL;
  test_acc->result_lamports = 1004565760UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_644_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_644_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_644_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_644_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_644_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_644_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_644_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_644_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_644_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_644_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_645(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 55,2,103,30,82,118,121,108,114,128,111,92,122,27,125,106,78,33,109,87,75,117,29,56,105,76,124,98,83,112,116,126,123,62,90,61,113,24,110,15,89,127,26,80,77,120,79 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_split_100_percent_of_source_to_account_with_lamports::new_behavior";
  test.test_nonce  = 99;
  test.test_number = 645;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "J4DuSjgTpVEUpJii7FbhsNyUMKSZBw4PRTv8hBb823C",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1002282880UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_645_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_645_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_645_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_645_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "GdA5NqQHzA6ZEmuHB8bRL7eLN2UUXNHzoxwr52Nxitid",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1002282879UL;
  test_acc->result_lamports = 2004565759UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_645_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_645_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_645_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_645_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_645_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_645_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_645_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_645_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_645_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_645_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_646(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 1;
  uchar disabled_features[] = { 89 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_split_100_percent_of_source_to_account_with_lamports::old_behavior";
  test.test_nonce  = 113;
  test.test_number = 646;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "ENyvk3wQJTk9U2LGvNCv29mtTTet7QKAfZxV4XAvYrES",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2282881UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_646_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_646_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_646_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_646_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "8NuCUBUQtaKUDaxv7qvhJvoziMdMqNnHnrKCW8iSYCZP",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2282880UL;
  test_acc->result_lamports = 4565761UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_646_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_646_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_646_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_646_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_646_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_646_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_646_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_646_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_646_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_646_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_647(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 1;
  uchar disabled_features[] = { 89 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_split_100_percent_of_source_to_account_with_lamports::old_behavior";
  test.test_nonce  = 127;
  test.test_number = 647;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "ENyvk3wQJTk9U2LGvNCv29mtTTet7QKAfZxV4XAvYrES",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2282881UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_647_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_647_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_647_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_647_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "8NuCUBUQtaKUDaxv7qvhJvoziMdMqNnHnrKCW8iSYCZP",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2282881UL;
  test_acc->result_lamports = 4565762UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_647_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_647_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_647_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_647_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_647_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_647_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_647_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_647_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_647_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_647_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_648(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 1;
  uchar disabled_features[] = { 89 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_split_100_percent_of_source_to_account_with_lamports::old_behavior";
  test.test_nonce  = 64;
  test.test_number = 648;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "ENyvk3wQJTk9U2LGvNCv29mtTTet7QKAfZxV4XAvYrES",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2282881UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_648_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_648_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_648_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_648_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "8NuCUBUQtaKUDaxv7qvhJvoziMdMqNnHnrKCW8iSYCZP",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 2282881UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_648_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_648_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_648_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_648_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_648_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_648_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_648_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_648_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_648_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_648_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_649(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 1;
  uchar disabled_features[] = { 89 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_split_100_percent_of_source_to_account_with_lamports::old_behavior";
  test.test_nonce  = 87;
  test.test_number = 649;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "ENyvk3wQJTk9U2LGvNCv29mtTTet7QKAfZxV4XAvYrES",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2282881UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_649_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_649_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_649_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_649_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "8NuCUBUQtaKUDaxv7qvhJvoziMdMqNnHnrKCW8iSYCZP",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2282879UL;
  test_acc->result_lamports = 4565760UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_649_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_649_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_649_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_649_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_649_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_649_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_649_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_649_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_649_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_649_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
