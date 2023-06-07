#include "../fd_tests.h"
int test_600(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 82,114,76,78,27,111,121,89,56,24,106,30,116,79,126,92,124,80,26,125,109,75,113,29,110,2,15,105,122,83,120,118,33,90,112,108,127,61,103,98,123,128,117,55,77,87,62 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_set_lockup::new_behavior";
  test.test_nonce  = 618;
  test.test_number = 600;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 8;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "7u4qaaEuBngu1fpCX5Ea5CGjZkEyVBu8mTtVKzvccXRj",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1000000000UL;
  test_acc->result_lamports = 1000000000UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_600_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_600_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_600_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_600_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "5yj2m2DS36C65nqupK69cVMJ9LJ2CjskPoT6avhSoczU",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_600_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_600_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_600_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_600_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "EnmFddoB1jVAS3keNAnbkfbjrLRcMNSrneXrnv8GPmTV",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_600_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_600_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_600_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_600_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "2SFQXjM8W2iMPsxkJYbDyZij3mXrijnRnepvAwBUgXc9",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_600_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_600_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_600_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_600_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_600_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_600_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_600_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_600_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_600_acc_5_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_600_acc_5_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_600_acc_5_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_600_acc_5_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_600_acc_6_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_600_acc_6_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_600_acc_6_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_600_acc_6_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "StakeConfig11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_600_acc_7_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_600_acc_7_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_600_acc_7_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_600_acc_7_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_600_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_600_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_601(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 82,114,76,78,27,111,121,89,56,24,106,30,116,79,126,92,124,80,26,125,109,75,113,29,110,2,15,105,122,83,120,118,33,90,112,108,127,61,103,98,123,128,117,55,77,87,62 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_set_lockup::new_behavior";
  test.test_nonce  = 629;
  test.test_number = 601;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 8;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "7u4qaaEuBngu1fpCX5Ea5CGjZkEyVBu8mTtVKzvccXRj",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1000000000UL;
  test_acc->result_lamports = 1000000000UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_601_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_601_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_601_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_601_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "5yj2m2DS36C65nqupK69cVMJ9LJ2CjskPoT6avhSoczU",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_601_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_601_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_601_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_601_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "EnmFddoB1jVAS3keNAnbkfbjrLRcMNSrneXrnv8GPmTV",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_601_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_601_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_601_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_601_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "2SFQXjM8W2iMPsxkJYbDyZij3mXrijnRnepvAwBUgXc9",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_601_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_601_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_601_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_601_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_601_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_601_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_601_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_601_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_601_acc_5_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_601_acc_5_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_601_acc_5_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_601_acc_5_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_601_acc_6_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_601_acc_6_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_601_acc_6_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_601_acc_6_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "StakeConfig11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_601_acc_7_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_601_acc_7_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_601_acc_7_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_601_acc_7_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_601_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_601_raw_sz;
  test.expected_result = -8;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_602(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 120,76,80,33,117,78,56,124,106,62,112,126,29,116,87,75,26,83,127,103,123,92,98,55,125,118,109,82,121,15,113,79,110,111,77,30,128,2,114,90,24,105,89,108,122,27,61 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_set_lockup::old_behavior";
  test.test_nonce  = 342;
  test.test_number = 602;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 8;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "vBVCRwVgoEDvK87hP5NhWWNyKKbSkE2SbWXuxZkash9",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_602_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_602_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_602_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_602_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "5om2Do5VHK5sNoEnrAwSSi7ebEZdU6XSdU6ucmQUCDqq",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_602_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_602_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_602_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_602_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "N6C5mPr9ZUzQa2i3B6DYdpjFs4gH23McYrMM3kJX6vY",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_602_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_602_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_602_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_602_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "2Q85PVvbBy2ULJbgseaH1WsNfoEhh6Jn5jzZPPnDMTYV",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_602_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_602_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_602_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_602_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_602_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_602_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_602_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_602_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_602_acc_5_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_602_acc_5_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_602_acc_5_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_602_acc_5_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_602_acc_6_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_602_acc_6_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_602_acc_6_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_602_acc_6_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "StakeConfig11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_602_acc_7_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_602_acc_7_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_602_acc_7_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_602_acc_7_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_602_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_602_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_603(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 1;
  uchar disabled_features[] = { 89 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_set_lockup::old_behavior";
  test.test_nonce  = 346;
  test.test_number = 603;
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
  test_acc->data            = fd_flamenco_native_prog_test_603_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_603_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_603_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_603_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "8ZoALppn3VLvvUPwEUQDkXo5TA8EZ4LWekCYqtL56SaP",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_603_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_603_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_603_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_603_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Aue963DTZK22gsCQMyATXMk3k4HuLfrxNJe98qo9mR3H",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_603_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_603_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_603_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_603_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "39hmeJmzvWdNeQFU3xwJnAcpoDmhDD2ffyQhDvh53WuD",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_603_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_603_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_603_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_603_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_603_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_603_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_603_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_603_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_603_acc_5_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_603_acc_5_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_603_acc_5_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_603_acc_5_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_603_acc_6_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_603_acc_6_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_603_acc_6_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_603_acc_6_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "StakeConfig11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_603_acc_7_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_603_acc_7_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_603_acc_7_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_603_acc_7_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_603_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_603_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_604(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 120,76,80,33,117,78,56,124,106,62,112,126,29,116,87,75,26,83,127,103,123,92,98,55,125,118,109,82,121,15,113,79,110,111,77,30,128,2,114,90,24,105,89,108,122,27,61 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_set_lockup::old_behavior";
  test.test_nonce  = 619;
  test.test_number = 604;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 8;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "vBVCRwVgoEDvK87hP5NhWWNyKKbSkE2SbWXuxZkash9",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_604_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_604_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_604_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_604_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "5om2Do5VHK5sNoEnrAwSSi7ebEZdU6XSdU6ucmQUCDqq",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_604_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_604_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_604_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_604_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "N6C5mPr9ZUzQa2i3B6DYdpjFs4gH23McYrMM3kJX6vY",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_604_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_604_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_604_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_604_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "2Q85PVvbBy2ULJbgseaH1WsNfoEhh6Jn5jzZPPnDMTYV",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_604_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_604_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_604_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_604_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_604_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_604_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_604_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_604_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_604_acc_5_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_604_acc_5_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_604_acc_5_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_604_acc_5_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_604_acc_6_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_604_acc_6_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_604_acc_6_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_604_acc_6_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "StakeConfig11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_604_acc_7_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_604_acc_7_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_604_acc_7_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_604_acc_7_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_604_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_604_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_605(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 1;
  uchar disabled_features[] = { 89 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_set_lockup::old_behavior";
  test.test_nonce  = 625;
  test.test_number = 605;
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
  test_acc->data            = fd_flamenco_native_prog_test_605_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_605_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_605_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_605_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "8ZoALppn3VLvvUPwEUQDkXo5TA8EZ4LWekCYqtL56SaP",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_605_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_605_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_605_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_605_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Aue963DTZK22gsCQMyATXMk3k4HuLfrxNJe98qo9mR3H",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_605_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_605_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_605_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_605_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "39hmeJmzvWdNeQFU3xwJnAcpoDmhDD2ffyQhDvh53WuD",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_605_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_605_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_605_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_605_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_605_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_605_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_605_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_605_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_605_acc_5_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_605_acc_5_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_605_acc_5_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_605_acc_5_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_605_acc_6_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_605_acc_6_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_605_acc_6_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_605_acc_6_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "StakeConfig11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_605_acc_7_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_605_acc_7_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_605_acc_7_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_605_acc_7_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_605_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_605_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_606(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 120,76,80,33,117,78,56,124,106,62,112,126,29,116,87,75,26,83,127,103,123,92,98,55,125,118,109,82,121,15,113,79,110,111,77,30,128,2,114,90,24,105,89,108,122,27,61 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_set_lockup::old_behavior";
  test.test_nonce  = 521;
  test.test_number = 606;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 8;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "vBVCRwVgoEDvK87hP5NhWWNyKKbSkE2SbWXuxZkash9",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_606_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_606_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_606_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_606_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "5om2Do5VHK5sNoEnrAwSSi7ebEZdU6XSdU6ucmQUCDqq",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_606_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_606_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_606_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_606_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "N6C5mPr9ZUzQa2i3B6DYdpjFs4gH23McYrMM3kJX6vY",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_606_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_606_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_606_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_606_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "2Q85PVvbBy2ULJbgseaH1WsNfoEhh6Jn5jzZPPnDMTYV",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_606_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_606_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_606_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_606_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_606_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_606_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_606_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_606_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_606_acc_5_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_606_acc_5_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_606_acc_5_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_606_acc_5_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_606_acc_6_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_606_acc_6_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_606_acc_6_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_606_acc_6_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "StakeConfig11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_606_acc_7_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_606_acc_7_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_606_acc_7_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_606_acc_7_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_606_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_606_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_607(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 1;
  uchar disabled_features[] = { 89 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_set_lockup::old_behavior";
  test.test_nonce  = 541;
  test.test_number = 607;
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
  test_acc->data            = fd_flamenco_native_prog_test_607_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_607_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_607_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_607_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "8ZoALppn3VLvvUPwEUQDkXo5TA8EZ4LWekCYqtL56SaP",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_607_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_607_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_607_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_607_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Aue963DTZK22gsCQMyATXMk3k4HuLfrxNJe98qo9mR3H",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_607_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_607_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_607_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_607_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "39hmeJmzvWdNeQFU3xwJnAcpoDmhDD2ffyQhDvh53WuD",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_607_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_607_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_607_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_607_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_607_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_607_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_607_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_607_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_607_acc_5_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_607_acc_5_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_607_acc_5_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_607_acc_5_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_607_acc_6_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_607_acc_6_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_607_acc_6_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_607_acc_6_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "StakeConfig11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_607_acc_7_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_607_acc_7_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_607_acc_7_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_607_acc_7_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_607_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_607_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_608(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 120,76,80,33,117,78,56,124,106,62,112,126,29,116,87,75,26,83,127,103,123,92,98,55,125,118,109,82,121,15,113,79,110,111,77,30,128,2,114,90,24,105,89,108,122,27,61 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_set_lockup::old_behavior";
  test.test_nonce  = 404;
  test.test_number = 608;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 8;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "vBVCRwVgoEDvK87hP5NhWWNyKKbSkE2SbWXuxZkash9",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_608_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_608_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_608_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_608_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "5om2Do5VHK5sNoEnrAwSSi7ebEZdU6XSdU6ucmQUCDqq",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_608_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_608_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_608_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_608_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "N6C5mPr9ZUzQa2i3B6DYdpjFs4gH23McYrMM3kJX6vY",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_608_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_608_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_608_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_608_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "2Q85PVvbBy2ULJbgseaH1WsNfoEhh6Jn5jzZPPnDMTYV",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_608_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_608_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_608_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_608_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_608_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_608_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_608_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_608_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_608_acc_5_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_608_acc_5_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_608_acc_5_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_608_acc_5_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_608_acc_6_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_608_acc_6_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_608_acc_6_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_608_acc_6_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "StakeConfig11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_608_acc_7_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_608_acc_7_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_608_acc_7_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_608_acc_7_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_608_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_608_raw_sz;
  test.expected_result = -8;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_609(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 120,76,80,33,117,78,56,124,106,62,112,126,29,116,87,75,26,83,127,103,123,92,98,55,125,118,109,82,121,15,113,79,110,111,77,30,128,2,114,90,24,105,89,108,122,27,61 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_set_lockup::old_behavior";
  test.test_nonce  = 474;
  test.test_number = 609;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 8;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "vBVCRwVgoEDvK87hP5NhWWNyKKbSkE2SbWXuxZkash9",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_609_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_609_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_609_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_609_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "5om2Do5VHK5sNoEnrAwSSi7ebEZdU6XSdU6ucmQUCDqq",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_609_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_609_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_609_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_609_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "N6C5mPr9ZUzQa2i3B6DYdpjFs4gH23McYrMM3kJX6vY",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_609_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_609_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_609_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_609_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "2Q85PVvbBy2ULJbgseaH1WsNfoEhh6Jn5jzZPPnDMTYV",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_609_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_609_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_609_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_609_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_609_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_609_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_609_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_609_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_609_acc_5_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_609_acc_5_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_609_acc_5_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_609_acc_5_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_609_acc_6_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_609_acc_6_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_609_acc_6_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_609_acc_6_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "StakeConfig11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_609_acc_7_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_609_acc_7_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_609_acc_7_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_609_acc_7_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_609_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_609_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_610(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 120,76,80,33,117,78,56,124,106,62,112,126,29,116,87,75,26,83,127,103,123,92,98,55,125,118,109,82,121,15,113,79,110,111,77,30,128,2,114,90,24,105,89,108,122,27,61 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_set_lockup::old_behavior";
  test.test_nonce  = 52;
  test.test_number = 610;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 8;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "vBVCRwVgoEDvK87hP5NhWWNyKKbSkE2SbWXuxZkash9",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_610_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_610_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_610_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_610_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "5om2Do5VHK5sNoEnrAwSSi7ebEZdU6XSdU6ucmQUCDqq",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_610_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_610_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_610_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_610_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "N6C5mPr9ZUzQa2i3B6DYdpjFs4gH23McYrMM3kJX6vY",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_610_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_610_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_610_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_610_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "2Q85PVvbBy2ULJbgseaH1WsNfoEhh6Jn5jzZPPnDMTYV",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_610_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_610_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_610_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_610_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_610_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_610_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_610_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_610_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_610_acc_5_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_610_acc_5_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_610_acc_5_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_610_acc_5_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_610_acc_6_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_610_acc_6_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_610_acc_6_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_610_acc_6_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "StakeConfig11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_610_acc_7_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_610_acc_7_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_610_acc_7_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_610_acc_7_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_610_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_610_raw_sz;
  test.expected_result = -4;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_611(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 120,76,80,33,117,78,56,124,106,62,112,126,29,116,87,75,26,83,127,103,123,92,98,55,125,118,109,82,121,15,113,79,110,111,77,30,128,2,114,90,24,105,89,108,122,27,61 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_set_lockup::old_behavior";
  test.test_nonce  = 542;
  test.test_number = 611;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 8;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "vBVCRwVgoEDvK87hP5NhWWNyKKbSkE2SbWXuxZkash9",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_611_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_611_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_611_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_611_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "5om2Do5VHK5sNoEnrAwSSi7ebEZdU6XSdU6ucmQUCDqq",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_611_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_611_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_611_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_611_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "N6C5mPr9ZUzQa2i3B6DYdpjFs4gH23McYrMM3kJX6vY",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_611_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_611_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_611_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_611_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "2Q85PVvbBy2ULJbgseaH1WsNfoEhh6Jn5jzZPPnDMTYV",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_611_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_611_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_611_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_611_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_611_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_611_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_611_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_611_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_611_acc_5_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_611_acc_5_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_611_acc_5_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_611_acc_5_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_611_acc_6_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_611_acc_6_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_611_acc_6_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_611_acc_6_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "StakeConfig11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_611_acc_7_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_611_acc_7_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_611_acc_7_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_611_acc_7_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_611_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_611_raw_sz;
  test.expected_result = -8;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_612(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 120,76,80,33,117,78,56,124,106,62,112,126,29,116,87,75,26,83,127,103,123,92,98,55,125,118,109,82,121,15,113,79,110,111,77,30,128,2,114,90,24,105,89,108,122,27,61 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_set_lockup::old_behavior";
  test.test_nonce  = 561;
  test.test_number = 612;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 8;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "vBVCRwVgoEDvK87hP5NhWWNyKKbSkE2SbWXuxZkash9",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_612_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_612_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_612_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_612_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "5om2Do5VHK5sNoEnrAwSSi7ebEZdU6XSdU6ucmQUCDqq",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_612_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_612_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_612_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_612_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "N6C5mPr9ZUzQa2i3B6DYdpjFs4gH23McYrMM3kJX6vY",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_612_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_612_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_612_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_612_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "2Q85PVvbBy2ULJbgseaH1WsNfoEhh6Jn5jzZPPnDMTYV",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_612_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_612_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_612_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_612_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_612_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_612_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_612_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_612_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_612_acc_5_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_612_acc_5_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_612_acc_5_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_612_acc_5_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_612_acc_6_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_612_acc_6_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_612_acc_6_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_612_acc_6_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "StakeConfig11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_612_acc_7_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_612_acc_7_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_612_acc_7_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_612_acc_7_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_612_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_612_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_613(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 1;
  uchar disabled_features[] = { 89 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_set_lockup::old_behavior";
  test.test_nonce  = 426;
  test.test_number = 613;
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
  test_acc->data            = fd_flamenco_native_prog_test_613_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_613_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_613_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_613_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "8ZoALppn3VLvvUPwEUQDkXo5TA8EZ4LWekCYqtL56SaP",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_613_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_613_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_613_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_613_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Aue963DTZK22gsCQMyATXMk3k4HuLfrxNJe98qo9mR3H",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_613_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_613_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_613_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_613_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "39hmeJmzvWdNeQFU3xwJnAcpoDmhDD2ffyQhDvh53WuD",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_613_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_613_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_613_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_613_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_613_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_613_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_613_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_613_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_613_acc_5_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_613_acc_5_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_613_acc_5_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_613_acc_5_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_613_acc_6_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_613_acc_6_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_613_acc_6_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_613_acc_6_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "StakeConfig11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_613_acc_7_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_613_acc_7_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_613_acc_7_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_613_acc_7_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_613_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_613_raw_sz;
  test.expected_result = -8;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_614(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 1;
  uchar disabled_features[] = { 89 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_set_lockup::old_behavior";
  test.test_nonce  = 491;
  test.test_number = 614;
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
  test_acc->data            = fd_flamenco_native_prog_test_614_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_614_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_614_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_614_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "8ZoALppn3VLvvUPwEUQDkXo5TA8EZ4LWekCYqtL56SaP",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_614_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_614_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_614_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_614_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Aue963DTZK22gsCQMyATXMk3k4HuLfrxNJe98qo9mR3H",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_614_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_614_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_614_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_614_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "39hmeJmzvWdNeQFU3xwJnAcpoDmhDD2ffyQhDvh53WuD",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_614_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_614_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_614_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_614_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_614_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_614_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_614_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_614_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_614_acc_5_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_614_acc_5_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_614_acc_5_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_614_acc_5_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_614_acc_6_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_614_acc_6_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_614_acc_6_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_614_acc_6_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "StakeConfig11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_614_acc_7_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_614_acc_7_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_614_acc_7_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_614_acc_7_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_614_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_614_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_615(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 1;
  uchar disabled_features[] = { 89 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_set_lockup::old_behavior";
  test.test_nonce  = 573;
  test.test_number = 615;
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
  test_acc->data            = fd_flamenco_native_prog_test_615_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_615_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_615_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_615_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "8ZoALppn3VLvvUPwEUQDkXo5TA8EZ4LWekCYqtL56SaP",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_615_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_615_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_615_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_615_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Aue963DTZK22gsCQMyATXMk3k4HuLfrxNJe98qo9mR3H",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_615_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_615_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_615_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_615_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "39hmeJmzvWdNeQFU3xwJnAcpoDmhDD2ffyQhDvh53WuD",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_615_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_615_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_615_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_615_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_615_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_615_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_615_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_615_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_615_acc_5_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_615_acc_5_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_615_acc_5_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_615_acc_5_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_615_acc_6_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_615_acc_6_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_615_acc_6_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_615_acc_6_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "StakeConfig11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_615_acc_7_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_615_acc_7_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_615_acc_7_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_615_acc_7_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_615_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_615_raw_sz;
  test.expected_result = -8;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_616(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 1;
  uchar disabled_features[] = { 89 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_set_lockup::old_behavior";
  test.test_nonce  = 594;
  test.test_number = 616;
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
  test_acc->data            = fd_flamenco_native_prog_test_616_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_616_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_616_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_616_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "8ZoALppn3VLvvUPwEUQDkXo5TA8EZ4LWekCYqtL56SaP",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_616_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_616_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_616_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_616_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Aue963DTZK22gsCQMyATXMk3k4HuLfrxNJe98qo9mR3H",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_616_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_616_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_616_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_616_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "39hmeJmzvWdNeQFU3xwJnAcpoDmhDD2ffyQhDvh53WuD",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_616_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_616_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_616_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_616_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_616_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_616_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_616_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_616_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_616_acc_5_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_616_acc_5_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_616_acc_5_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_616_acc_5_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_616_acc_6_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_616_acc_6_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_616_acc_6_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_616_acc_6_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "StakeConfig11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_616_acc_7_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_616_acc_7_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_616_acc_7_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_616_acc_7_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_616_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_616_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_617(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 1;
  uchar disabled_features[] = { 89 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_set_lockup::old_behavior";
  test.test_nonce  = 59;
  test.test_number = 617;
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
  test_acc->data            = fd_flamenco_native_prog_test_617_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_617_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_617_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_617_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "8ZoALppn3VLvvUPwEUQDkXo5TA8EZ4LWekCYqtL56SaP",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_617_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_617_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_617_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_617_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Aue963DTZK22gsCQMyATXMk3k4HuLfrxNJe98qo9mR3H",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_617_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_617_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_617_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_617_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "39hmeJmzvWdNeQFU3xwJnAcpoDmhDD2ffyQhDvh53WuD",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_617_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_617_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_617_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_617_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_617_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_617_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_617_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_617_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_617_acc_5_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_617_acc_5_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_617_acc_5_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_617_acc_5_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_617_acc_6_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_617_acc_6_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_617_acc_6_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_617_acc_6_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "StakeConfig11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_617_acc_7_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_617_acc_7_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_617_acc_7_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_617_acc_7_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_617_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_617_raw_sz;
  test.expected_result = -4;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_618(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 120,76,80,33,117,78,56,124,106,62,112,126,29,116,87,75,26,83,127,103,123,92,98,55,125,118,109,82,121,15,113,79,110,111,77,30,128,2,114,90,24,105,89,108,122,27,61 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_set_lockup::old_behavior";
  test.test_nonce  = 584;
  test.test_number = 618;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 8;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "vBVCRwVgoEDvK87hP5NhWWNyKKbSkE2SbWXuxZkash9",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_618_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_618_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_618_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_618_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "5om2Do5VHK5sNoEnrAwSSi7ebEZdU6XSdU6ucmQUCDqq",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_618_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_618_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_618_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_618_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "N6C5mPr9ZUzQa2i3B6DYdpjFs4gH23McYrMM3kJX6vY",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_618_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_618_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_618_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_618_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "2Q85PVvbBy2ULJbgseaH1WsNfoEhh6Jn5jzZPPnDMTYV",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_618_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_618_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_618_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_618_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_618_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_618_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_618_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_618_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_618_acc_5_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_618_acc_5_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_618_acc_5_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_618_acc_5_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_618_acc_6_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_618_acc_6_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_618_acc_6_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_618_acc_6_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "StakeConfig11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_618_acc_7_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_618_acc_7_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_618_acc_7_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_618_acc_7_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_618_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_618_raw_sz;
  test.expected_result = -8;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_619(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 120,76,80,33,117,78,56,124,106,62,112,126,29,116,87,75,26,83,127,103,123,92,98,55,125,118,109,82,121,15,113,79,110,111,77,30,128,2,114,90,24,105,89,108,122,27,61 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_set_lockup::old_behavior";
  test.test_nonce  = 595;
  test.test_number = 619;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 8;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "vBVCRwVgoEDvK87hP5NhWWNyKKbSkE2SbWXuxZkash9",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_619_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_619_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_619_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_619_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "5om2Do5VHK5sNoEnrAwSSi7ebEZdU6XSdU6ucmQUCDqq",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_619_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_619_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_619_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_619_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "N6C5mPr9ZUzQa2i3B6DYdpjFs4gH23McYrMM3kJX6vY",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_619_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_619_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_619_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_619_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "2Q85PVvbBy2ULJbgseaH1WsNfoEhh6Jn5jzZPPnDMTYV",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_619_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_619_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_619_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_619_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_619_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_619_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_619_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_619_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_619_acc_5_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_619_acc_5_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_619_acc_5_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_619_acc_5_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_619_acc_6_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_619_acc_6_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_619_acc_6_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_619_acc_6_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "StakeConfig11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_619_acc_7_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_619_acc_7_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_619_acc_7_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_619_acc_7_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_619_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_619_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_620(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 120,76,80,33,117,78,56,124,106,62,112,126,29,116,87,75,26,83,127,103,123,92,98,55,125,118,109,82,121,15,113,79,110,111,77,30,128,2,114,90,24,105,89,108,122,27,61 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_set_lockup::old_behavior";
  test.test_nonce  = 604;
  test.test_number = 620;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 8;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "vBVCRwVgoEDvK87hP5NhWWNyKKbSkE2SbWXuxZkash9",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_620_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_620_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_620_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_620_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "5om2Do5VHK5sNoEnrAwSSi7ebEZdU6XSdU6ucmQUCDqq",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_620_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_620_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_620_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_620_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "N6C5mPr9ZUzQa2i3B6DYdpjFs4gH23McYrMM3kJX6vY",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_620_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_620_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_620_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_620_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "2Q85PVvbBy2ULJbgseaH1WsNfoEhh6Jn5jzZPPnDMTYV",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_620_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_620_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_620_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_620_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_620_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_620_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_620_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_620_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_620_acc_5_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_620_acc_5_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_620_acc_5_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_620_acc_5_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_620_acc_6_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_620_acc_6_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_620_acc_6_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_620_acc_6_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "StakeConfig11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_620_acc_7_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_620_acc_7_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_620_acc_7_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_620_acc_7_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_620_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_620_raw_sz;
  test.expected_result = -8;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_621(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 120,76,80,33,117,78,56,124,106,62,112,126,29,116,87,75,26,83,127,103,123,92,98,55,125,118,109,82,121,15,113,79,110,111,77,30,128,2,114,90,24,105,89,108,122,27,61 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_set_lockup::old_behavior";
  test.test_nonce  = 612;
  test.test_number = 621;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 8;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "vBVCRwVgoEDvK87hP5NhWWNyKKbSkE2SbWXuxZkash9",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_621_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_621_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_621_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_621_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "5om2Do5VHK5sNoEnrAwSSi7ebEZdU6XSdU6ucmQUCDqq",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_621_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_621_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_621_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_621_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "N6C5mPr9ZUzQa2i3B6DYdpjFs4gH23McYrMM3kJX6vY",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_621_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_621_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_621_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_621_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "2Q85PVvbBy2ULJbgseaH1WsNfoEhh6Jn5jzZPPnDMTYV",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_621_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_621_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_621_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_621_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_621_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_621_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_621_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_621_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_621_acc_5_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_621_acc_5_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_621_acc_5_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_621_acc_5_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_621_acc_6_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_621_acc_6_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_621_acc_6_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_621_acc_6_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "StakeConfig11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_621_acc_7_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_621_acc_7_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_621_acc_7_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_621_acc_7_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_621_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_621_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_622(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 120,76,80,33,117,78,56,124,106,62,112,126,29,116,87,75,26,83,127,103,123,92,98,55,125,118,109,82,121,15,113,79,110,111,77,30,128,2,114,90,24,105,89,108,122,27,61 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_set_lockup::old_behavior";
  test.test_nonce  = 623;
  test.test_number = 622;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 8;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "vBVCRwVgoEDvK87hP5NhWWNyKKbSkE2SbWXuxZkash9",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_622_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_622_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_622_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_622_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "5om2Do5VHK5sNoEnrAwSSi7ebEZdU6XSdU6ucmQUCDqq",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_622_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_622_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_622_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_622_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "N6C5mPr9ZUzQa2i3B6DYdpjFs4gH23McYrMM3kJX6vY",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_622_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_622_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_622_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_622_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "2Q85PVvbBy2ULJbgseaH1WsNfoEhh6Jn5jzZPPnDMTYV",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_622_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_622_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_622_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_622_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_622_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_622_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_622_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_622_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_622_acc_5_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_622_acc_5_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_622_acc_5_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_622_acc_5_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_622_acc_6_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_622_acc_6_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_622_acc_6_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_622_acc_6_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "StakeConfig11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_622_acc_7_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_622_acc_7_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_622_acc_7_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_622_acc_7_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_622_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_622_raw_sz;
  test.expected_result = -8;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_623(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 1;
  uchar disabled_features[] = { 89 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_set_lockup::old_behavior";
  test.test_nonce  = 601;
  test.test_number = 623;
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
  test_acc->data            = fd_flamenco_native_prog_test_623_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_623_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_623_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_623_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "8ZoALppn3VLvvUPwEUQDkXo5TA8EZ4LWekCYqtL56SaP",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_623_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_623_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_623_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_623_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Aue963DTZK22gsCQMyATXMk3k4HuLfrxNJe98qo9mR3H",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_623_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_623_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_623_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_623_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "39hmeJmzvWdNeQFU3xwJnAcpoDmhDD2ffyQhDvh53WuD",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_623_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_623_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_623_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_623_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_623_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_623_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_623_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_623_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_623_acc_5_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_623_acc_5_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_623_acc_5_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_623_acc_5_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_623_acc_6_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_623_acc_6_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_623_acc_6_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_623_acc_6_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "StakeConfig11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_623_acc_7_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_623_acc_7_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_623_acc_7_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_623_acc_7_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_623_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_623_raw_sz;
  test.expected_result = -8;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_624(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 1;
  uchar disabled_features[] = { 89 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_set_lockup::old_behavior";
  test.test_nonce  = 608;
  test.test_number = 624;
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
  test_acc->data            = fd_flamenco_native_prog_test_624_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_624_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_624_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_624_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "8ZoALppn3VLvvUPwEUQDkXo5TA8EZ4LWekCYqtL56SaP",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_624_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_624_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_624_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_624_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Aue963DTZK22gsCQMyATXMk3k4HuLfrxNJe98qo9mR3H",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_624_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_624_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_624_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_624_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "39hmeJmzvWdNeQFU3xwJnAcpoDmhDD2ffyQhDvh53WuD",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_624_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_624_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_624_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_624_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_624_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_624_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_624_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_624_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_624_acc_5_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_624_acc_5_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_624_acc_5_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_624_acc_5_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_624_acc_6_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_624_acc_6_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_624_acc_6_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_624_acc_6_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "StakeConfig11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_624_acc_7_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_624_acc_7_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_624_acc_7_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_624_acc_7_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_624_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_624_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
