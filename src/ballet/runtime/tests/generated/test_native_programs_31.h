#include "../fd_tests.h"
int test_775(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 1;
  uchar disabled_features[] = { 89 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_split_minimum_stake_delegation::old_behavior";
  test.test_nonce  = 156;
  test.test_number = 775;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111111DUUhXNEw1bNAMSKgm1Kt2tSPWdzF3G5poh",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 4565761UL;
  test_acc->result_lamports = 4565761UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_775_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_775_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_775_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_775_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111DspJWUYDimq3AsTmnRfCX1iB99FBkVff83",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_775_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_775_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_775_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_775_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_775_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_775_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_775_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_775_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_775_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_775_raw_sz;
  test.expected_result = -6;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_776(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 113,114,98,24,120,90,123,103,110,79,61,30,121,2,116,122,15,126,112,83,87,26,56,75,62,92,111,118,128,125,106,108,77,124,89,80,78,55,76,109,127,117,27,105,82,29,33 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_split_more_than_staked::new_behavior";
  test.test_nonce  = 65;
  test.test_number = 776;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "7wwgHEE4WoatmZXQVbMeE5vpQNX7xxntCEib9CC66N6x",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2004565760UL;
  test_acc->result_lamports = 2004565760UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_776_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_776_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_776_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_776_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "CieFCA1ykNf9EVqAzr6WdXACDACPHSuBmf7TkmSGF8s2",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_776_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_776_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_776_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_776_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_776_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_776_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_776_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_776_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_776_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_776_raw_sz;
  test.expected_result = -26;
  test.custom_err = 12;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_777(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 113,114,98,24,120,90,123,103,110,79,61,30,121,2,116,122,15,126,112,83,87,26,56,75,62,92,111,118,128,125,106,108,77,124,89,80,78,55,76,109,127,117,27,105,82,29,33 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_split_more_than_staked::new_behavior";
  test.test_nonce  = 81;
  test.test_number = 777;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "2J7JZpGZE8htUazJ54JYYqw884JEnvx9ccLvQLZxWKu4",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2004565760UL;
  test_acc->result_lamports = 2004565760UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_777_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_777_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_777_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_777_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "F21BWAU1CY1cNc7AEyJzuHeASA4rkc6nwJyphaKYFYDg",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_777_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_777_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_777_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_777_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_777_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_777_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_777_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_777_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_777_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_777_raw_sz;
  test.expected_result = -26;
  test.custom_err = 12;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_778(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 1;
  uchar disabled_features[] = { 89 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_split_more_than_staked::old_behavior";
  test.test_nonce  = 100;
  test.test_number = 778;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "J52tU79AxfMQdLh3zvHK3SYFt1xw8QDhgSCZsoa66kgS",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 4565762UL;
  test_acc->result_lamports = 4565762UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_778_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_778_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_778_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_778_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "72pXL71P9xaegwufes45uPZXoCXxemUY1HHxC7hL6Pz5",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_778_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_778_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_778_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_778_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_778_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_778_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_778_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_778_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_778_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_778_raw_sz;
  test.expected_result = -26;
  test.custom_err = 12;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_779(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 114,30,106,56,89,78,61,83,55,82,110,98,103,76,122,125,79,109,2,92,27,29,121,77,26,118,117,75,128,127,116,80,112,15,113,120,126,33,108,24,105,123,90,62,124,87,111 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_split_more_than_staked::old_behavior";
  test.test_nonce  = 62;
  test.test_number = 779;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "9dnELoRJTGDwu8KcPQ9VhPpJ9GL3NF7DhS6mbruyjpF9",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 4565762UL;
  test_acc->result_lamports = 4565762UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_779_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_779_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_779_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_779_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "amD4cyYjjqiC4cmYQoh6W24ShWHfeJK8VdSQbcEMkvh",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_779_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_779_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_779_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_779_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_779_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_779_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_779_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_779_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_779_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_779_raw_sz;
  test.expected_result = -26;
  test.custom_err = 12;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_780(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 114,30,106,56,89,78,61,83,55,82,110,98,103,76,122,125,79,109,2,92,27,29,121,77,26,118,117,75,128,127,116,80,112,15,113,120,126,33,108,24,105,123,90,62,124,87,111 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_split::new_behavior";
  test.test_nonce  = 120;
  test.test_number = 780;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 2;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "HnbxHGRVQP6BJ1MZqTEpK9AoCZuuj4H5K2GVaETUoYz8",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2000000000UL;
  test_acc->result_lamports = 2000000000UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_780_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_780_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_780_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_780_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "5BVuQDXwweAtWykP9mZYFD9xs1jh64qXny1t7Rh8zzjy",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "4PVSvygwgiBEsD66x2SSAGeEZxwT4hfyrQUqEd1qqAh7",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_780_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_780_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_780_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_780_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_780_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_780_raw_sz;
  test.expected_result = -7;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_781(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 114,30,106,56,89,78,61,83,55,82,110,98,103,76,122,125,79,109,2,92,27,29,121,77,26,118,117,75,128,127,116,80,112,15,113,120,126,33,108,24,105,123,90,62,124,87,111 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_split::new_behavior";
  test.test_nonce  = 29;
  test.test_number = 781;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 2;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "CNc5hPQfcSihbFeEMqXEBiu7JM2kQDbTYcTVQ5PPxV1a",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2000000000UL;
  test_acc->result_lamports = 1000000000UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_781_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_781_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_781_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_781_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "FqXPW54KxPHHE8rj5LrDCeDxpbB76KGDC4EvUzp4GewC",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 1000000000UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_781_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_781_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_781_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_781_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_781_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_781_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_782(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 114,30,106,56,89,78,61,83,55,82,110,98,103,76,122,125,79,109,2,92,27,29,121,77,26,118,117,75,128,127,116,80,112,15,113,120,126,33,108,24,105,123,90,62,124,87,111 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_split::new_behavior";
  test.test_nonce  = 57;
  test.test_number = 782;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 2;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "CNc5hPQfcSihbFeEMqXEBiu7JM2kQDbTYcTVQ5PPxV1a",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2000000000UL;
  test_acc->result_lamports = 1000000000UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_782_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_782_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_782_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_782_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "FqXPW54KxPHHE8rj5LrDCeDxpbB76KGDC4EvUzp4GewC",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 1000000000UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_782_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_782_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_782_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_782_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_782_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_782_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_783(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 114,30,106,56,89,78,61,83,55,82,110,98,103,76,122,125,79,109,2,92,27,29,121,77,26,118,117,75,128,127,116,80,112,15,113,120,126,33,108,24,105,123,90,62,124,87,111 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_split::new_behavior";
  test.test_nonce  = 68;
  test.test_number = 783;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 2;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "HnbxHGRVQP6BJ1MZqTEpK9AoCZuuj4H5K2GVaETUoYz8",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2000000000UL;
  test_acc->result_lamports = 1000000000UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_783_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_783_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_783_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_783_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "5BVuQDXwweAtWykP9mZYFD9xs1jh64qXny1t7Rh8zzjy",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 1000000000UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_783_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_783_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_783_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_783_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_783_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_783_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_784(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 114,30,106,56,89,78,61,83,55,82,110,98,103,76,122,125,79,109,2,92,27,29,121,77,26,118,117,75,128,127,116,80,112,15,113,120,126,33,108,24,105,123,90,62,124,87,111 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_split::new_behavior";
  test.test_nonce  = 72;
  test.test_number = 784;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 2;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "CNc5hPQfcSihbFeEMqXEBiu7JM2kQDbTYcTVQ5PPxV1a",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2000000000UL;
  test_acc->result_lamports = 2000000000UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_784_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_784_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_784_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_784_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "FqXPW54KxPHHE8rj5LrDCeDxpbB76KGDC4EvUzp4GewC",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Db3u83YxBhpx7T8a427QDP5rox3YebgyEj634oFM5YNR",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_784_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_784_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_784_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_784_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_784_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_784_raw_sz;
  test.expected_result = -7;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_785(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 114,30,106,56,89,78,61,83,55,82,110,98,103,76,122,125,79,109,2,92,27,29,121,77,26,118,117,75,128,127,116,80,112,15,113,120,126,33,108,24,105,123,90,62,124,87,111 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_split::new_behavior";
  test.test_nonce  = 95;
  test.test_number = 785;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 2;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "HnbxHGRVQP6BJ1MZqTEpK9AoCZuuj4H5K2GVaETUoYz8",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2000000000UL;
  test_acc->result_lamports = 1000000000UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_785_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_785_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_785_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_785_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "5BVuQDXwweAtWykP9mZYFD9xs1jh64qXny1t7Rh8zzjy",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 1000000000UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_785_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_785_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_785_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_785_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_785_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_785_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_786(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 114,30,106,56,89,78,61,83,55,82,110,98,103,76,122,125,79,109,2,92,27,29,121,77,26,118,117,75,128,127,116,80,112,15,113,120,126,33,108,24,105,123,90,62,124,87,111 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_split::new_behavior";
  test.test_nonce  = 10;
  test.test_number = 786;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 2;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "CNc5hPQfcSihbFeEMqXEBiu7JM2kQDbTYcTVQ5PPxV1a",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2000000000UL;
  test_acc->result_lamports = 2000000000UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_786_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_786_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_786_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_786_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "FqXPW54KxPHHE8rj5LrDCeDxpbB76KGDC4EvUzp4GewC",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_786_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_786_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_786_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_786_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_786_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_786_raw_sz;
  test.expected_result = -6;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_787(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 114,30,106,56,89,78,61,83,55,82,110,98,103,76,122,125,79,109,2,92,27,29,121,77,26,118,117,75,128,127,116,80,112,15,113,120,126,33,108,24,105,123,90,62,124,87,111 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_split::new_behavior";
  test.test_nonce  = 42;
  test.test_number = 787;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 2;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "CNc5hPQfcSihbFeEMqXEBiu7JM2kQDbTYcTVQ5PPxV1a",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2000000000UL;
  test_acc->result_lamports = 2000000000UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_787_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_787_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_787_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_787_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "FqXPW54KxPHHE8rj5LrDCeDxpbB76KGDC4EvUzp4GewC",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_787_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_787_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_787_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_787_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_787_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_787_raw_sz;
  test.expected_result = -6;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_788(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 114,30,106,56,89,78,61,83,55,82,110,98,103,76,122,125,79,109,2,92,27,29,121,77,26,118,117,75,128,127,116,80,112,15,113,120,126,33,108,24,105,123,90,62,124,87,111 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_split::new_behavior";
  test.test_nonce  = 45;
  test.test_number = 788;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 2;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "HnbxHGRVQP6BJ1MZqTEpK9AoCZuuj4H5K2GVaETUoYz8",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2000000000UL;
  test_acc->result_lamports = 2000000000UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_788_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_788_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_788_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_788_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "5BVuQDXwweAtWykP9mZYFD9xs1jh64qXny1t7Rh8zzjy",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_788_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_788_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_788_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_788_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_788_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_788_raw_sz;
  test.expected_result = -6;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_789(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 114,30,106,56,89,78,61,83,55,82,110,98,103,76,122,125,79,109,2,92,27,29,121,77,26,118,117,75,128,127,116,80,112,15,113,120,126,33,108,24,105,123,90,62,124,87,111 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_split::new_behavior";
  test.test_nonce  = 82;
  test.test_number = 789;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 2;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "HnbxHGRVQP6BJ1MZqTEpK9AoCZuuj4H5K2GVaETUoYz8",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2000000000UL;
  test_acc->result_lamports = 2000000000UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_789_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_789_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_789_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_789_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "5BVuQDXwweAtWykP9mZYFD9xs1jh64qXny1t7Rh8zzjy",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_789_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_789_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_789_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_789_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_789_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_789_raw_sz;
  test.expected_result = -6;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_790(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 1;
  uchar disabled_features[] = { 89 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_split::old_behavior";
  test.test_nonce  = 26;
  test.test_number = 790;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 2;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "Aka9kpwuesoxvBisnAS5G426ucw2cRCArvBipvR9oH5R",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_790_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_790_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_790_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_790_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "GR65onFgqAy2DVpy1HG4zLLJR5PVvDjnVVeE3hknomkj",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_790_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_790_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_790_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_790_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_790_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_790_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_791(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 1;
  uchar disabled_features[] = { 89 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_split::old_behavior";
  test.test_nonce  = 54;
  test.test_number = 791;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 2;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "78cxK4eJp5DtjUaAB6HRHBx45YCgfrUN5tsKqVsR4mrS",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_791_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_791_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_791_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_791_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "6bv766gSCAVDpX7ZK5dBp7d3cRmFdRPE3sS2ubBc9W4J",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_791_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_791_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_791_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_791_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_791_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_791_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_792(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 1;
  uchar disabled_features[] = { 89 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_split::old_behavior";
  test.test_nonce  = 63;
  test.test_number = 792;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 2;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "Aka9kpwuesoxvBisnAS5G426ucw2cRCArvBipvR9oH5R",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_792_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_792_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_792_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_792_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "GR65onFgqAy2DVpy1HG4zLLJR5PVvDjnVVeE3hknomkj",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_792_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_792_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_792_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_792_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_792_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_792_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_793(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 1;
  uchar disabled_features[] = { 89 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_split::old_behavior";
  test.test_nonce  = 80;
  test.test_number = 793;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 2;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "Aka9kpwuesoxvBisnAS5G426ucw2cRCArvBipvR9oH5R",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2UL;
  test_acc->result_lamports = 2UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_793_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_793_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_793_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_793_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "GR65onFgqAy2DVpy1HG4zLLJR5PVvDjnVVeE3hknomkj",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "fcTJ2pBKaijtebr811UevDf3VFGQDUtfVRG5761V2fd",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_793_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_793_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_793_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_793_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_793_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_793_raw_sz;
  test.expected_result = -7;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_794(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 1;
  uchar disabled_features[] = { 89 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_split::old_behavior";
  test.test_nonce  = 84;
  test.test_number = 794;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 2;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "78cxK4eJp5DtjUaAB6HRHBx45YCgfrUN5tsKqVsR4mrS",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_794_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_794_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_794_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_794_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "6bv766gSCAVDpX7ZK5dBp7d3cRmFdRPE3sS2ubBc9W4J",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_794_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_794_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_794_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_794_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_794_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_794_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_795(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 1;
  uchar disabled_features[] = { 89 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_split::old_behavior";
  test.test_nonce  = 92;
  test.test_number = 795;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 2;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "78cxK4eJp5DtjUaAB6HRHBx45YCgfrUN5tsKqVsR4mrS",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2UL;
  test_acc->result_lamports = 2UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_795_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_795_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_795_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_795_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "6bv766gSCAVDpX7ZK5dBp7d3cRmFdRPE3sS2ubBc9W4J",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "3VbJqfG9rGu36uJdRx8YndPq6WAgx5YyHmPLhz4U459P",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_795_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_795_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_795_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_795_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_795_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_795_raw_sz;
  test.expected_result = -7;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_796(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 1;
  uchar disabled_features[] = { 89 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_split::old_behavior";
  test.test_nonce  = 12;
  test.test_number = 796;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 2;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "Aka9kpwuesoxvBisnAS5G426ucw2cRCArvBipvR9oH5R",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2UL;
  test_acc->result_lamports = 2UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_796_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_796_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_796_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_796_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "GR65onFgqAy2DVpy1HG4zLLJR5PVvDjnVVeE3hknomkj",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_796_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_796_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_796_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_796_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_796_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_796_raw_sz;
  test.expected_result = -6;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_797(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 1;
  uchar disabled_features[] = { 89 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_split::old_behavior";
  test.test_nonce  = 37;
  test.test_number = 797;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 2;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "Aka9kpwuesoxvBisnAS5G426ucw2cRCArvBipvR9oH5R",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2UL;
  test_acc->result_lamports = 2UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_797_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_797_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_797_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_797_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "GR65onFgqAy2DVpy1HG4zLLJR5PVvDjnVVeE3hknomkj",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_797_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_797_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_797_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_797_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_797_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_797_raw_sz;
  test.expected_result = -6;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_798(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 1;
  uchar disabled_features[] = { 89 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_split::old_behavior";
  test.test_nonce  = 43;
  test.test_number = 798;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 2;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "78cxK4eJp5DtjUaAB6HRHBx45YCgfrUN5tsKqVsR4mrS",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2UL;
  test_acc->result_lamports = 2UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_798_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_798_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_798_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_798_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "6bv766gSCAVDpX7ZK5dBp7d3cRmFdRPE3sS2ubBc9W4J",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_798_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_798_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_798_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_798_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_798_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_798_raw_sz;
  test.expected_result = -6;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_799(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 1;
  uchar disabled_features[] = { 89 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_split::old_behavior";
  test.test_nonce  = 73;
  test.test_number = 799;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 2;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "78cxK4eJp5DtjUaAB6HRHBx45YCgfrUN5tsKqVsR4mrS",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2UL;
  test_acc->result_lamports = 2UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_799_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_799_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_799_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_799_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "6bv766gSCAVDpX7ZK5dBp7d3cRmFdRPE3sS2ubBc9W4J",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_799_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_799_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_799_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_799_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_799_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_799_raw_sz;
  test.expected_result = -6;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
