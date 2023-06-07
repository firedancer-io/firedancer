#include "../fd_tests.h"
int test_575(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 1;
  uchar disabled_features[] = { 89 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_redelegate::old_behavior";
  test.test_nonce  = 91;
  test.test_number = 575;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 5;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "11111116djSnXB2wXVGT4xDLsfTnkp1p4cCxHAfRq",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 4565761UL;
  test_acc->result_lamports = 2282880UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_575_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_575_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_575_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_575_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111117353mdUKehx9GW6JNHznGt5oSZs9fWkVkB",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 2282881UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_575_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_575_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_575_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_575_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111116EPqoQskEM2Pddp8KTL9JdYEBZMGF3aq7V",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_575_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_575_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_575_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_575_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "StakeConfig11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_575_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_575_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_575_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_575_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111115RidqCHAoz6dzmXxGcfWLNzevYqNpaRAUo",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_575_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_575_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_575_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_575_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_575_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_575_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_576(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 82,114,76,78,27,111,121,89,56,24,106,30,116,79,126,92,124,80,26,125,109,75,113,29,110,2,15,105,122,83,120,118,33,90,112,108,127,61,103,98,123,128,117,55,77,87,62 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_set_lockup::new_behavior";
  test.test_nonce  = 338;
  test.test_number = 576;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 8;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "4Xi58L4Z8upvYw9STcprWSbXHGSTL83FXTAETtewrMqp",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1000000000UL;
  test_acc->result_lamports = 1000000000UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_576_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_576_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_576_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_576_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "HEoMitJGfnjGwBBCm7HrvppBmsdxM9W53uNWCT3v8Uew",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_576_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_576_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_576_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_576_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "5PLhbr4QzMiyzzCpGwNk8JWXxcfV5V1Gm7gyd7ZBmh33",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_576_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_576_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_576_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_576_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "FNo4BmEyfbbEapgKq5JLztWS39FnGB9Sstcpfv55LJz5",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_576_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_576_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_576_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_576_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_576_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_576_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_576_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_576_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_576_acc_5_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_576_acc_5_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_576_acc_5_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_576_acc_5_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_576_acc_6_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_576_acc_6_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_576_acc_6_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_576_acc_6_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "StakeConfig11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_576_acc_7_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_576_acc_7_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_576_acc_7_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_576_acc_7_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_576_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_576_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_577(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 82,114,76,78,27,111,121,89,56,24,106,30,116,79,126,92,124,80,26,125,109,75,113,29,110,2,15,105,122,83,120,118,33,90,112,108,127,61,103,98,123,128,117,55,77,87,62 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_set_lockup::new_behavior";
  test.test_nonce  = 364;
  test.test_number = 577;
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
  test_acc->data            = fd_flamenco_native_prog_test_577_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_577_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_577_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_577_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "5yj2m2DS36C65nqupK69cVMJ9LJ2CjskPoT6avhSoczU",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_577_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_577_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_577_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_577_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "EnmFddoB1jVAS3keNAnbkfbjrLRcMNSrneXrnv8GPmTV",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_577_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_577_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_577_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_577_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "2SFQXjM8W2iMPsxkJYbDyZij3mXrijnRnepvAwBUgXc9",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_577_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_577_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_577_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_577_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_577_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_577_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_577_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_577_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_577_acc_5_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_577_acc_5_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_577_acc_5_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_577_acc_5_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_577_acc_6_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_577_acc_6_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_577_acc_6_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_577_acc_6_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "StakeConfig11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_577_acc_7_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_577_acc_7_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_577_acc_7_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_577_acc_7_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_577_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_577_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_578(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 82,114,76,78,27,111,121,89,56,24,106,30,116,79,126,92,124,80,26,125,109,75,113,29,110,2,15,105,122,83,120,118,33,90,112,108,127,61,103,98,123,128,117,55,77,87,62 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_set_lockup::new_behavior";
  test.test_nonce  = 637;
  test.test_number = 578;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 8;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "4Xi58L4Z8upvYw9STcprWSbXHGSTL83FXTAETtewrMqp",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1000000000UL;
  test_acc->result_lamports = 1000000000UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_578_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_578_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_578_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_578_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "HEoMitJGfnjGwBBCm7HrvppBmsdxM9W53uNWCT3v8Uew",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_578_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_578_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_578_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_578_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "5PLhbr4QzMiyzzCpGwNk8JWXxcfV5V1Gm7gyd7ZBmh33",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_578_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_578_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_578_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_578_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "FNo4BmEyfbbEapgKq5JLztWS39FnGB9Sstcpfv55LJz5",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_578_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_578_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_578_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_578_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_578_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_578_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_578_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_578_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_578_acc_5_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_578_acc_5_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_578_acc_5_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_578_acc_5_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_578_acc_6_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_578_acc_6_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_578_acc_6_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_578_acc_6_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "StakeConfig11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_578_acc_7_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_578_acc_7_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_578_acc_7_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_578_acc_7_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_578_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_578_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_579(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 82,114,76,78,27,111,121,89,56,24,106,30,116,79,126,92,124,80,26,125,109,75,113,29,110,2,15,105,122,83,120,118,33,90,112,108,127,61,103,98,123,128,117,55,77,87,62 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_set_lockup::new_behavior";
  test.test_nonce  = 622;
  test.test_number = 579;
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
  test_acc->data            = fd_flamenco_native_prog_test_579_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_579_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_579_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_579_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "5yj2m2DS36C65nqupK69cVMJ9LJ2CjskPoT6avhSoczU",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_579_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_579_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_579_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_579_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "EnmFddoB1jVAS3keNAnbkfbjrLRcMNSrneXrnv8GPmTV",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_579_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_579_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_579_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_579_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "2SFQXjM8W2iMPsxkJYbDyZij3mXrijnRnepvAwBUgXc9",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_579_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_579_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_579_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_579_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_579_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_579_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_579_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_579_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_579_acc_5_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_579_acc_5_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_579_acc_5_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_579_acc_5_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_579_acc_6_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_579_acc_6_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_579_acc_6_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_579_acc_6_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "StakeConfig11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_579_acc_7_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_579_acc_7_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_579_acc_7_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_579_acc_7_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_579_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_579_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_580(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 82,114,76,78,27,111,121,89,56,24,106,30,116,79,126,92,124,80,26,125,109,75,113,29,110,2,15,105,122,83,120,118,33,90,112,108,127,61,103,98,123,128,117,55,77,87,62 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_set_lockup::new_behavior";
  test.test_nonce  = 518;
  test.test_number = 580;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 8;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "4Xi58L4Z8upvYw9STcprWSbXHGSTL83FXTAETtewrMqp",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1000000000UL;
  test_acc->result_lamports = 1000000000UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_580_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_580_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_580_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_580_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "HEoMitJGfnjGwBBCm7HrvppBmsdxM9W53uNWCT3v8Uew",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_580_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_580_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_580_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_580_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "5PLhbr4QzMiyzzCpGwNk8JWXxcfV5V1Gm7gyd7ZBmh33",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_580_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_580_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_580_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_580_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "FNo4BmEyfbbEapgKq5JLztWS39FnGB9Sstcpfv55LJz5",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_580_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_580_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_580_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_580_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_580_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_580_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_580_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_580_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_580_acc_5_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_580_acc_5_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_580_acc_5_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_580_acc_5_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_580_acc_6_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_580_acc_6_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_580_acc_6_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_580_acc_6_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "StakeConfig11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_580_acc_7_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_580_acc_7_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_580_acc_7_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_580_acc_7_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_580_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_580_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_581(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 82,114,76,78,27,111,121,89,56,24,106,30,116,79,126,92,124,80,26,125,109,75,113,29,110,2,15,105,122,83,120,118,33,90,112,108,127,61,103,98,123,128,117,55,77,87,62 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_set_lockup::new_behavior";
  test.test_nonce  = 530;
  test.test_number = 581;
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
  test_acc->data            = fd_flamenco_native_prog_test_581_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_581_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_581_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_581_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "5yj2m2DS36C65nqupK69cVMJ9LJ2CjskPoT6avhSoczU",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_581_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_581_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_581_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_581_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "EnmFddoB1jVAS3keNAnbkfbjrLRcMNSrneXrnv8GPmTV",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_581_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_581_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_581_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_581_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "2SFQXjM8W2iMPsxkJYbDyZij3mXrijnRnepvAwBUgXc9",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_581_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_581_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_581_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_581_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_581_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_581_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_581_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_581_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_581_acc_5_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_581_acc_5_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_581_acc_5_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_581_acc_5_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_581_acc_6_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_581_acc_6_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_581_acc_6_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_581_acc_6_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "StakeConfig11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_581_acc_7_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_581_acc_7_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_581_acc_7_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_581_acc_7_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_581_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_581_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_582(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 82,114,76,78,27,111,121,89,56,24,106,30,116,79,126,92,124,80,26,125,109,75,113,29,110,2,15,105,122,83,120,118,33,90,112,108,127,61,103,98,123,128,117,55,77,87,62 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_set_lockup::new_behavior";
  test.test_nonce  = 431;
  test.test_number = 582;
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
  test_acc->data            = fd_flamenco_native_prog_test_582_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_582_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_582_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_582_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "5yj2m2DS36C65nqupK69cVMJ9LJ2CjskPoT6avhSoczU",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_582_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_582_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_582_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_582_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "EnmFddoB1jVAS3keNAnbkfbjrLRcMNSrneXrnv8GPmTV",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_582_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_582_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_582_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_582_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "2SFQXjM8W2iMPsxkJYbDyZij3mXrijnRnepvAwBUgXc9",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_582_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_582_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_582_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_582_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_582_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_582_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_582_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_582_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_582_acc_5_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_582_acc_5_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_582_acc_5_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_582_acc_5_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_582_acc_6_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_582_acc_6_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_582_acc_6_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_582_acc_6_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "StakeConfig11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_582_acc_7_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_582_acc_7_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_582_acc_7_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_582_acc_7_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_582_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_582_raw_sz;
  test.expected_result = -8;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_583(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 82,114,76,78,27,111,121,89,56,24,106,30,116,79,126,92,124,80,26,125,109,75,113,29,110,2,15,105,122,83,120,118,33,90,112,108,127,61,103,98,123,128,117,55,77,87,62 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_set_lockup::new_behavior";
  test.test_nonce  = 486;
  test.test_number = 583;
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
  test_acc->data            = fd_flamenco_native_prog_test_583_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_583_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_583_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_583_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "5yj2m2DS36C65nqupK69cVMJ9LJ2CjskPoT6avhSoczU",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_583_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_583_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_583_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_583_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "EnmFddoB1jVAS3keNAnbkfbjrLRcMNSrneXrnv8GPmTV",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_583_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_583_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_583_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_583_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "2SFQXjM8W2iMPsxkJYbDyZij3mXrijnRnepvAwBUgXc9",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_583_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_583_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_583_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_583_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_583_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_583_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_583_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_583_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_583_acc_5_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_583_acc_5_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_583_acc_5_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_583_acc_5_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_583_acc_6_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_583_acc_6_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_583_acc_6_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_583_acc_6_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "StakeConfig11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_583_acc_7_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_583_acc_7_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_583_acc_7_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_583_acc_7_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_583_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_583_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_584(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 82,114,76,78,27,111,121,89,56,24,106,30,116,79,126,92,124,80,26,125,109,75,113,29,110,2,15,105,122,83,120,118,33,90,112,108,127,61,103,98,123,128,117,55,77,87,62 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_set_lockup::new_behavior";
  test.test_nonce  = 558;
  test.test_number = 584;
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
  test_acc->data            = fd_flamenco_native_prog_test_584_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_584_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_584_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_584_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "5yj2m2DS36C65nqupK69cVMJ9LJ2CjskPoT6avhSoczU",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_584_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_584_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_584_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_584_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "EnmFddoB1jVAS3keNAnbkfbjrLRcMNSrneXrnv8GPmTV",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_584_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_584_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_584_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_584_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "2SFQXjM8W2iMPsxkJYbDyZij3mXrijnRnepvAwBUgXc9",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_584_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_584_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_584_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_584_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_584_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_584_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_584_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_584_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_584_acc_5_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_584_acc_5_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_584_acc_5_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_584_acc_5_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_584_acc_6_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_584_acc_6_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_584_acc_6_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_584_acc_6_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "StakeConfig11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_584_acc_7_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_584_acc_7_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_584_acc_7_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_584_acc_7_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_584_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_584_raw_sz;
  test.expected_result = -8;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_585(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 82,114,76,78,27,111,121,89,56,24,106,30,116,79,126,92,124,80,26,125,109,75,113,29,110,2,15,105,122,83,120,118,33,90,112,108,127,61,103,98,123,128,117,55,77,87,62 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_set_lockup::new_behavior";
  test.test_nonce  = 55;
  test.test_number = 585;
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
  test_acc->data            = fd_flamenco_native_prog_test_585_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_585_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_585_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_585_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "5yj2m2DS36C65nqupK69cVMJ9LJ2CjskPoT6avhSoczU",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_585_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_585_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_585_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_585_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "EnmFddoB1jVAS3keNAnbkfbjrLRcMNSrneXrnv8GPmTV",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_585_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_585_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_585_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_585_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "2SFQXjM8W2iMPsxkJYbDyZij3mXrijnRnepvAwBUgXc9",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_585_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_585_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_585_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_585_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_585_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_585_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_585_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_585_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_585_acc_5_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_585_acc_5_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_585_acc_5_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_585_acc_5_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_585_acc_6_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_585_acc_6_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_585_acc_6_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_585_acc_6_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "StakeConfig11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_585_acc_7_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_585_acc_7_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_585_acc_7_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_585_acc_7_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_585_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_585_raw_sz;
  test.expected_result = -4;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_586(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 82,114,76,78,27,111,121,89,56,24,106,30,116,79,126,92,124,80,26,125,109,75,113,29,110,2,15,105,122,83,120,118,33,90,112,108,127,61,103,98,123,128,117,55,77,87,62 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_set_lockup::new_behavior";
  test.test_nonce  = 580;
  test.test_number = 586;
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
  test_acc->data            = fd_flamenco_native_prog_test_586_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_586_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_586_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_586_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "5yj2m2DS36C65nqupK69cVMJ9LJ2CjskPoT6avhSoczU",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_586_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_586_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_586_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_586_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "EnmFddoB1jVAS3keNAnbkfbjrLRcMNSrneXrnv8GPmTV",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_586_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_586_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_586_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_586_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "2SFQXjM8W2iMPsxkJYbDyZij3mXrijnRnepvAwBUgXc9",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_586_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_586_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_586_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_586_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_586_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_586_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_586_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_586_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_586_acc_5_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_586_acc_5_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_586_acc_5_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_586_acc_5_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_586_acc_6_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_586_acc_6_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_586_acc_6_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_586_acc_6_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "StakeConfig11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_586_acc_7_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_586_acc_7_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_586_acc_7_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_586_acc_7_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_586_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_586_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_587(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 82,114,76,78,27,111,121,89,56,24,106,30,116,79,126,92,124,80,26,125,109,75,113,29,110,2,15,105,122,83,120,118,33,90,112,108,127,61,103,98,123,128,117,55,77,87,62 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_set_lockup::new_behavior";
  test.test_nonce  = 403;
  test.test_number = 587;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 8;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "4Xi58L4Z8upvYw9STcprWSbXHGSTL83FXTAETtewrMqp",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1000000000UL;
  test_acc->result_lamports = 1000000000UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_587_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_587_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_587_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_587_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "HEoMitJGfnjGwBBCm7HrvppBmsdxM9W53uNWCT3v8Uew",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_587_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_587_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_587_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_587_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "5PLhbr4QzMiyzzCpGwNk8JWXxcfV5V1Gm7gyd7ZBmh33",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_587_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_587_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_587_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_587_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "FNo4BmEyfbbEapgKq5JLztWS39FnGB9Sstcpfv55LJz5",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_587_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_587_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_587_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_587_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_587_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_587_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_587_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_587_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_587_acc_5_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_587_acc_5_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_587_acc_5_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_587_acc_5_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_587_acc_6_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_587_acc_6_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_587_acc_6_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_587_acc_6_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "StakeConfig11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_587_acc_7_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_587_acc_7_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_587_acc_7_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_587_acc_7_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_587_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_587_raw_sz;
  test.expected_result = -8;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_588(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 82,114,76,78,27,111,121,89,56,24,106,30,116,79,126,92,124,80,26,125,109,75,113,29,110,2,15,105,122,83,120,118,33,90,112,108,127,61,103,98,123,128,117,55,77,87,62 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_set_lockup::new_behavior";
  test.test_nonce  = 471;
  test.test_number = 588;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 8;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "4Xi58L4Z8upvYw9STcprWSbXHGSTL83FXTAETtewrMqp",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1000000000UL;
  test_acc->result_lamports = 1000000000UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_588_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_588_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_588_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_588_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "HEoMitJGfnjGwBBCm7HrvppBmsdxM9W53uNWCT3v8Uew",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_588_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_588_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_588_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_588_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "5PLhbr4QzMiyzzCpGwNk8JWXxcfV5V1Gm7gyd7ZBmh33",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_588_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_588_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_588_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_588_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "FNo4BmEyfbbEapgKq5JLztWS39FnGB9Sstcpfv55LJz5",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_588_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_588_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_588_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_588_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_588_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_588_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_588_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_588_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_588_acc_5_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_588_acc_5_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_588_acc_5_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_588_acc_5_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_588_acc_6_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_588_acc_6_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_588_acc_6_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_588_acc_6_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "StakeConfig11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_588_acc_7_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_588_acc_7_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_588_acc_7_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_588_acc_7_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_588_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_588_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_589(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 82,114,76,78,27,111,121,89,56,24,106,30,116,79,126,92,124,80,26,125,109,75,113,29,110,2,15,105,122,83,120,118,33,90,112,108,127,61,103,98,123,128,117,55,77,87,62 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_set_lockup::new_behavior";
  test.test_nonce  = 53;
  test.test_number = 589;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 8;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "4Xi58L4Z8upvYw9STcprWSbXHGSTL83FXTAETtewrMqp",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1000000000UL;
  test_acc->result_lamports = 1000000000UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_589_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_589_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_589_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_589_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "HEoMitJGfnjGwBBCm7HrvppBmsdxM9W53uNWCT3v8Uew",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_589_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_589_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_589_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_589_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "5PLhbr4QzMiyzzCpGwNk8JWXxcfV5V1Gm7gyd7ZBmh33",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_589_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_589_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_589_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_589_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "FNo4BmEyfbbEapgKq5JLztWS39FnGB9Sstcpfv55LJz5",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_589_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_589_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_589_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_589_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_589_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_589_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_589_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_589_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_589_acc_5_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_589_acc_5_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_589_acc_5_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_589_acc_5_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_589_acc_6_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_589_acc_6_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_589_acc_6_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_589_acc_6_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "StakeConfig11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_589_acc_7_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_589_acc_7_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_589_acc_7_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_589_acc_7_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_589_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_589_raw_sz;
  test.expected_result = -4;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_590(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 82,114,76,78,27,111,121,89,56,24,106,30,116,79,126,92,124,80,26,125,109,75,113,29,110,2,15,105,122,83,120,118,33,90,112,108,127,61,103,98,123,128,117,55,77,87,62 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_set_lockup::new_behavior";
  test.test_nonce  = 555;
  test.test_number = 590;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 8;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "4Xi58L4Z8upvYw9STcprWSbXHGSTL83FXTAETtewrMqp",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1000000000UL;
  test_acc->result_lamports = 1000000000UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_590_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_590_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_590_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_590_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "HEoMitJGfnjGwBBCm7HrvppBmsdxM9W53uNWCT3v8Uew",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_590_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_590_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_590_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_590_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "5PLhbr4QzMiyzzCpGwNk8JWXxcfV5V1Gm7gyd7ZBmh33",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_590_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_590_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_590_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_590_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "FNo4BmEyfbbEapgKq5JLztWS39FnGB9Sstcpfv55LJz5",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_590_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_590_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_590_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_590_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_590_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_590_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_590_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_590_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_590_acc_5_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_590_acc_5_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_590_acc_5_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_590_acc_5_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_590_acc_6_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_590_acc_6_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_590_acc_6_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_590_acc_6_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "StakeConfig11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_590_acc_7_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_590_acc_7_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_590_acc_7_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_590_acc_7_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_590_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_590_raw_sz;
  test.expected_result = -8;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_591(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 82,114,76,78,27,111,121,89,56,24,106,30,116,79,126,92,124,80,26,125,109,75,113,29,110,2,15,105,122,83,120,118,33,90,112,108,127,61,103,98,123,128,117,55,77,87,62 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_set_lockup::new_behavior";
  test.test_nonce  = 588;
  test.test_number = 591;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 8;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "4Xi58L4Z8upvYw9STcprWSbXHGSTL83FXTAETtewrMqp",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1000000000UL;
  test_acc->result_lamports = 1000000000UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_591_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_591_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_591_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_591_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "HEoMitJGfnjGwBBCm7HrvppBmsdxM9W53uNWCT3v8Uew",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_591_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_591_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_591_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_591_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "5PLhbr4QzMiyzzCpGwNk8JWXxcfV5V1Gm7gyd7ZBmh33",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_591_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_591_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_591_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_591_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "FNo4BmEyfbbEapgKq5JLztWS39FnGB9Sstcpfv55LJz5",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_591_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_591_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_591_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_591_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_591_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_591_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_591_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_591_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_591_acc_5_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_591_acc_5_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_591_acc_5_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_591_acc_5_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_591_acc_6_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_591_acc_6_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_591_acc_6_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_591_acc_6_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "StakeConfig11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_591_acc_7_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_591_acc_7_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_591_acc_7_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_591_acc_7_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_591_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_591_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_592(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 82,114,76,78,27,111,121,89,56,24,106,30,116,79,126,92,124,80,26,125,109,75,113,29,110,2,15,105,122,83,120,118,33,90,112,108,127,61,103,98,123,128,117,55,77,87,62 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_set_lockup::new_behavior";
  test.test_nonce  = 605;
  test.test_number = 592;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 8;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "4Xi58L4Z8upvYw9STcprWSbXHGSTL83FXTAETtewrMqp",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1000000000UL;
  test_acc->result_lamports = 1000000000UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_592_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_592_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_592_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_592_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "HEoMitJGfnjGwBBCm7HrvppBmsdxM9W53uNWCT3v8Uew",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_592_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_592_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_592_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_592_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "5PLhbr4QzMiyzzCpGwNk8JWXxcfV5V1Gm7gyd7ZBmh33",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_592_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_592_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_592_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_592_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "FNo4BmEyfbbEapgKq5JLztWS39FnGB9Sstcpfv55LJz5",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_592_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_592_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_592_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_592_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_592_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_592_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_592_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_592_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_592_acc_5_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_592_acc_5_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_592_acc_5_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_592_acc_5_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_592_acc_6_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_592_acc_6_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_592_acc_6_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_592_acc_6_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "StakeConfig11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_592_acc_7_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_592_acc_7_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_592_acc_7_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_592_acc_7_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_592_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_592_raw_sz;
  test.expected_result = -8;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_593(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 82,114,76,78,27,111,121,89,56,24,106,30,116,79,126,92,124,80,26,125,109,75,113,29,110,2,15,105,122,83,120,118,33,90,112,108,127,61,103,98,123,128,117,55,77,87,62 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_set_lockup::new_behavior";
  test.test_nonce  = 616;
  test.test_number = 593;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 8;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "4Xi58L4Z8upvYw9STcprWSbXHGSTL83FXTAETtewrMqp",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1000000000UL;
  test_acc->result_lamports = 1000000000UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_593_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_593_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_593_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_593_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "HEoMitJGfnjGwBBCm7HrvppBmsdxM9W53uNWCT3v8Uew",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_593_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_593_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_593_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_593_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "5PLhbr4QzMiyzzCpGwNk8JWXxcfV5V1Gm7gyd7ZBmh33",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_593_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_593_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_593_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_593_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "FNo4BmEyfbbEapgKq5JLztWS39FnGB9Sstcpfv55LJz5",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_593_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_593_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_593_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_593_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_593_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_593_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_593_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_593_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_593_acc_5_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_593_acc_5_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_593_acc_5_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_593_acc_5_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_593_acc_6_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_593_acc_6_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_593_acc_6_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_593_acc_6_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "StakeConfig11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_593_acc_7_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_593_acc_7_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_593_acc_7_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_593_acc_7_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_593_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_593_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_594(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 82,114,76,78,27,111,121,89,56,24,106,30,116,79,126,92,124,80,26,125,109,75,113,29,110,2,15,105,122,83,120,118,33,90,112,108,127,61,103,98,123,128,117,55,77,87,62 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_set_lockup::new_behavior";
  test.test_nonce  = 627;
  test.test_number = 594;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 8;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "4Xi58L4Z8upvYw9STcprWSbXHGSTL83FXTAETtewrMqp",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1000000000UL;
  test_acc->result_lamports = 1000000000UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_594_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_594_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_594_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_594_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "HEoMitJGfnjGwBBCm7HrvppBmsdxM9W53uNWCT3v8Uew",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_594_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_594_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_594_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_594_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "5PLhbr4QzMiyzzCpGwNk8JWXxcfV5V1Gm7gyd7ZBmh33",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_594_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_594_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_594_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_594_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "FNo4BmEyfbbEapgKq5JLztWS39FnGB9Sstcpfv55LJz5",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_594_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_594_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_594_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_594_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_594_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_594_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_594_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_594_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_594_acc_5_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_594_acc_5_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_594_acc_5_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_594_acc_5_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_594_acc_6_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_594_acc_6_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_594_acc_6_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_594_acc_6_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "StakeConfig11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_594_acc_7_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_594_acc_7_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_594_acc_7_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_594_acc_7_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_594_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_594_raw_sz;
  test.expected_result = -8;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_595(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 82,114,76,78,27,111,121,89,56,24,106,30,116,79,126,92,124,80,26,125,109,75,113,29,110,2,15,105,122,83,120,118,33,90,112,108,127,61,103,98,123,128,117,55,77,87,62 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_set_lockup::new_behavior";
  test.test_nonce  = 633;
  test.test_number = 595;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 8;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "4Xi58L4Z8upvYw9STcprWSbXHGSTL83FXTAETtewrMqp",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1000000000UL;
  test_acc->result_lamports = 1000000000UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_595_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_595_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_595_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_595_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "HEoMitJGfnjGwBBCm7HrvppBmsdxM9W53uNWCT3v8Uew",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_595_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_595_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_595_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_595_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "5PLhbr4QzMiyzzCpGwNk8JWXxcfV5V1Gm7gyd7ZBmh33",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_595_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_595_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_595_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_595_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "FNo4BmEyfbbEapgKq5JLztWS39FnGB9Sstcpfv55LJz5",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_595_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_595_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_595_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_595_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_595_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_595_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_595_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_595_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_595_acc_5_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_595_acc_5_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_595_acc_5_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_595_acc_5_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_595_acc_6_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_595_acc_6_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_595_acc_6_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_595_acc_6_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "StakeConfig11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_595_acc_7_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_595_acc_7_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_595_acc_7_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_595_acc_7_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_595_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_595_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_596(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 82,114,76,78,27,111,121,89,56,24,106,30,116,79,126,92,124,80,26,125,109,75,113,29,110,2,15,105,122,83,120,118,33,90,112,108,127,61,103,98,123,128,117,55,77,87,62 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_set_lockup::new_behavior";
  test.test_nonce  = 640;
  test.test_number = 596;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 8;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "4Xi58L4Z8upvYw9STcprWSbXHGSTL83FXTAETtewrMqp",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1000000000UL;
  test_acc->result_lamports = 1000000000UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_596_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_596_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_596_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_596_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "HEoMitJGfnjGwBBCm7HrvppBmsdxM9W53uNWCT3v8Uew",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_596_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_596_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_596_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_596_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "5PLhbr4QzMiyzzCpGwNk8JWXxcfV5V1Gm7gyd7ZBmh33",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_596_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_596_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_596_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_596_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "FNo4BmEyfbbEapgKq5JLztWS39FnGB9Sstcpfv55LJz5",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_596_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_596_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_596_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_596_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_596_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_596_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_596_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_596_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_596_acc_5_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_596_acc_5_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_596_acc_5_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_596_acc_5_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_596_acc_6_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_596_acc_6_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_596_acc_6_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_596_acc_6_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "StakeConfig11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_596_acc_7_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_596_acc_7_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_596_acc_7_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_596_acc_7_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_596_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_596_raw_sz;
  test.expected_result = -8;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_597(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 82,114,76,78,27,111,121,89,56,24,106,30,116,79,126,92,124,80,26,125,109,75,113,29,110,2,15,105,122,83,120,118,33,90,112,108,127,61,103,98,123,128,117,55,77,87,62 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_set_lockup::new_behavior";
  test.test_nonce  = 595;
  test.test_number = 597;
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
  test_acc->data            = fd_flamenco_native_prog_test_597_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_597_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_597_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_597_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "5yj2m2DS36C65nqupK69cVMJ9LJ2CjskPoT6avhSoczU",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_597_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_597_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_597_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_597_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "EnmFddoB1jVAS3keNAnbkfbjrLRcMNSrneXrnv8GPmTV",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_597_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_597_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_597_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_597_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "2SFQXjM8W2iMPsxkJYbDyZij3mXrijnRnepvAwBUgXc9",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_597_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_597_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_597_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_597_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_597_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_597_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_597_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_597_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_597_acc_5_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_597_acc_5_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_597_acc_5_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_597_acc_5_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_597_acc_6_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_597_acc_6_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_597_acc_6_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_597_acc_6_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "StakeConfig11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_597_acc_7_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_597_acc_7_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_597_acc_7_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_597_acc_7_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_597_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_597_raw_sz;
  test.expected_result = -8;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_598(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 82,114,76,78,27,111,121,89,56,24,106,30,116,79,126,92,124,80,26,125,109,75,113,29,110,2,15,105,122,83,120,118,33,90,112,108,127,61,103,98,123,128,117,55,77,87,62 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_set_lockup::new_behavior";
  test.test_nonce  = 603;
  test.test_number = 598;
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
  test_acc->data            = fd_flamenco_native_prog_test_598_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_598_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_598_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_598_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "5yj2m2DS36C65nqupK69cVMJ9LJ2CjskPoT6avhSoczU",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_598_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_598_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_598_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_598_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "EnmFddoB1jVAS3keNAnbkfbjrLRcMNSrneXrnv8GPmTV",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_598_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_598_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_598_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_598_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "2SFQXjM8W2iMPsxkJYbDyZij3mXrijnRnepvAwBUgXc9",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_598_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_598_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_598_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_598_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_598_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_598_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_598_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_598_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_598_acc_5_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_598_acc_5_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_598_acc_5_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_598_acc_5_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_598_acc_6_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_598_acc_6_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_598_acc_6_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_598_acc_6_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "StakeConfig11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_598_acc_7_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_598_acc_7_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_598_acc_7_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_598_acc_7_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_598_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_598_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_599(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 82,114,76,78,27,111,121,89,56,24,106,30,116,79,126,92,124,80,26,125,109,75,113,29,110,2,15,105,122,83,120,118,33,90,112,108,127,61,103,98,123,128,117,55,77,87,62 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_set_lockup::new_behavior";
  test.test_nonce  = 611;
  test.test_number = 599;
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
  test_acc->data            = fd_flamenco_native_prog_test_599_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_599_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_599_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_599_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "5yj2m2DS36C65nqupK69cVMJ9LJ2CjskPoT6avhSoczU",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_599_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_599_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_599_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_599_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "EnmFddoB1jVAS3keNAnbkfbjrLRcMNSrneXrnv8GPmTV",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_599_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_599_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_599_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_599_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "2SFQXjM8W2iMPsxkJYbDyZij3mXrijnRnepvAwBUgXc9",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_599_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_599_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_599_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_599_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_599_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_599_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_599_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_599_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_599_acc_5_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_599_acc_5_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_599_acc_5_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_599_acc_5_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_599_acc_6_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_599_acc_6_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_599_acc_6_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_599_acc_6_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "StakeConfig11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_599_acc_7_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_599_acc_7_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_599_acc_7_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_599_acc_7_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_599_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_599_raw_sz;
  test.expected_result = -8;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
