#include "../fd_tests.h"
int test_1125(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 1;
  uchar disabled_features[] = { 89 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_stake_initialize::old_behavior";
  test.test_nonce  = 209;
  test.test_number = 1125;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 2;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "HD11ZVE7824S4Ja7c6cCDvB4zncZWnuvKoxNXJLDN9PN",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2282880UL;
  test_acc->result_lamports = 2282880UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1125_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1125_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1125_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1125_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1125_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1125_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1125_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1125_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1125_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1125_raw_sz;
  test.expected_result = -6;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1126(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 1;
  uchar disabled_features[] = { 89 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_stake_initialize::old_behavior";
  test.test_nonce  = 214;
  test.test_number = 1126;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 2;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "HD11ZVE7824S4Ja7c6cCDvB4zncZWnuvKoxNXJLDN9PN",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2282880UL;
  test_acc->result_lamports = 2282880UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1126_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1126_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1126_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1126_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1126_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1126_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1126_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1126_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1126_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1126_raw_sz;
  test.expected_result = -4;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1127(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 1;
  uchar disabled_features[] = { 89 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_stake_initialize::old_behavior";
  test.test_nonce  = 226;
  test.test_number = 1127;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 2;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "HD11ZVE7824S4Ja7c6cCDvB4zncZWnuvKoxNXJLDN9PN",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2282880UL;
  test_acc->result_lamports = 2282880UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1127_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1127_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1127_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1127_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1127_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1127_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1127_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1127_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1127_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1127_raw_sz;
  test.expected_result = -4;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1128(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 30,106,108,61,78,116,77,127,83,62,128,117,124,120,122,114,79,2,125,109,92,55,24,82,33,76,103,56,113,118,75,89,105,90,126,111,121,87,80,112,110,26,98,123,29,15,27 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_stake_process_instruction_decode_bail::new_behavior";
  test.test_nonce  = 201;
  test.test_number = 1128;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 0;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1128_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1128_raw_sz;
  test.expected_result = -20;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1129(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 30,106,108,61,78,116,77,127,83,62,128,117,124,120,122,114,79,2,125,109,92,55,24,82,33,76,103,56,113,118,75,89,105,90,126,111,121,87,80,112,110,26,98,123,29,15,27 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_stake_process_instruction_decode_bail::new_behavior";
  test.test_nonce  = 280;
  test.test_number = 1129;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 1;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111111T9yD14Nj9j7xAB4dbGeiX9h8unkKDDv9ZR",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1129_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1129_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1129_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1129_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1129_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1129_raw_sz;
  test.expected_result = -20;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1130(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 30,106,108,61,78,116,77,127,83,62,128,117,124,120,122,114,79,2,125,109,92,55,24,82,33,76,103,56,113,118,75,89,105,90,126,111,121,87,80,112,110,26,98,123,29,15,27 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_stake_process_instruction_decode_bail::new_behavior";
  test.test_nonce  = 310;
  test.test_number = 1130;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 2;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111111T9yD14Nj9j7xAB4dbGeiX9h8unkKDDv9ZR",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1130_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1130_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1130_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1130_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1130_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1130_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1130_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1130_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1130_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1130_raw_sz;
  test.expected_result = -4;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1131(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 30,106,108,61,78,116,77,127,83,62,128,117,124,120,122,114,79,2,125,109,92,55,24,82,33,76,103,56,113,118,75,89,105,90,126,111,121,87,80,112,110,26,98,123,29,15,27 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_stake_process_instruction_decode_bail::new_behavior";
  test.test_nonce  = 199;
  test.test_number = 1131;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 0;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1131_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1131_raw_sz;
  test.expected_result = -20;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1132(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 30,106,108,61,78,116,77,127,83,62,128,117,124,120,122,114,79,2,125,109,92,55,24,82,33,76,103,56,113,118,75,89,105,90,126,111,121,87,80,112,110,26,98,123,29,15,27 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_stake_process_instruction_decode_bail::new_behavior";
  test.test_nonce  = 208;
  test.test_number = 1132;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 1;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111111TZJozAg1ruapycCicgz31GxvYJ1FvTVysm",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1132_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1132_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1132_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1132_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1132_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1132_raw_sz;
  test.expected_result = -20;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1133(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 30,106,108,61,78,116,77,127,83,62,128,117,124,120,122,114,79,2,125,109,92,55,24,82,33,76,103,56,113,118,75,89,105,90,126,111,121,87,80,112,110,26,98,123,29,15,27 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_stake_process_instruction_decode_bail::new_behavior";
  test.test_nonce  = 227;
  test.test_number = 1133;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 2;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111111TZJozAg1ruapycCicgz31GxvYJ1FvTVysm",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1133_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1133_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1133_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1133_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1133_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1133_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1133_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1133_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1133_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1133_raw_sz;
  test.expected_result = -4;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1134(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 30,106,108,61,78,116,77,127,83,62,128,117,124,120,122,114,79,2,125,109,92,55,24,82,33,76,103,56,113,118,75,89,105,90,126,111,121,87,80,112,110,26,98,123,29,15,27 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_stake_process_instruction_decode_bail::new_behavior";
  test.test_nonce  = 327;
  test.test_number = 1134;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 1;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111111T9yD14Nj9j7xAB4dbGeiX9h8unkKDDv9ZR",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1134_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1134_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1134_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1134_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1134_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1134_raw_sz;
  test.expected_result = -20;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1135(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 30,106,108,61,78,116,77,127,83,62,128,117,124,120,122,114,79,2,125,109,92,55,24,82,33,76,103,56,113,118,75,89,105,90,126,111,121,87,80,112,110,26,98,123,29,15,27 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_stake_process_instruction_decode_bail::new_behavior";
  test.test_nonce  = 353;
  test.test_number = 1135;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 1;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111111T9yD14Nj9j7xAB4dbGeiX9h8unkKDDv9ZR",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1135_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1135_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1135_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1135_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1135_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1135_raw_sz;
  test.expected_result = -20;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1136(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 30,106,108,61,78,116,77,127,83,62,128,117,124,120,122,114,79,2,125,109,92,55,24,82,33,76,103,56,113,118,75,89,105,90,126,111,121,87,80,112,110,26,98,123,29,15,27 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_stake_process_instruction_decode_bail::new_behavior";
  test.test_nonce  = 365;
  test.test_number = 1136;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 5;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111111T9yD14Nj9j7xAB4dbGeiX9h8unkKDDv9ZR",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1136_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1136_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1136_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1136_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111TZJozAg1ruapycCicgz31GxvYJ1FvTVysm",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1136_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1136_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1136_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1136_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1136_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1136_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1136_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1136_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1136_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1136_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1136_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1136_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "StakeConfig11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1136_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1136_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1136_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1136_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1136_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1136_raw_sz;
  test.expected_result = -4;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1137(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 30,106,108,61,78,116,77,127,83,62,128,117,124,120,122,114,79,2,125,109,92,55,24,82,33,76,103,56,113,118,75,89,105,90,126,111,121,87,80,112,110,26,98,123,29,15,27 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_stake_process_instruction_decode_bail::new_behavior";
  test.test_nonce  = 270;
  test.test_number = 1137;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 1;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111111TZJozAg1ruapycCicgz31GxvYJ1FvTVysm",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1137_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1137_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1137_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1137_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1137_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1137_raw_sz;
  test.expected_result = -20;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1138(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 30,106,108,61,78,116,77,127,83,62,128,117,124,120,122,114,79,2,125,109,92,55,24,82,33,76,103,56,113,118,75,89,105,90,126,111,121,87,80,112,110,26,98,123,29,15,27 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_stake_process_instruction_decode_bail::new_behavior";
  test.test_nonce  = 282;
  test.test_number = 1138;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 1;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111111TZJozAg1ruapycCicgz31GxvYJ1FvTVysm",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1138_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1138_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1138_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1138_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1138_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1138_raw_sz;
  test.expected_result = -20;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1139(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 30,106,108,61,78,116,77,127,83,62,128,117,124,120,122,114,79,2,125,109,92,55,24,82,33,76,103,56,113,118,75,89,105,90,126,111,121,87,80,112,110,26,98,123,29,15,27 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_stake_process_instruction_decode_bail::new_behavior";
  test.test_nonce  = 311;
  test.test_number = 1139;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 5;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111111TZJozAg1ruapycCicgz31GxvYJ1FvTVysm",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1139_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1139_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1139_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1139_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111UMz1xPGbHGWacUUtfXefyXWVoJX9LvfeWT",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1139_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1139_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1139_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1139_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1139_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1139_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1139_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1139_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1139_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1139_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1139_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1139_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "StakeConfig11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1139_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1139_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1139_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1139_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1139_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1139_raw_sz;
  test.expected_result = -4;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1140(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 30,106,108,61,78,116,77,127,83,62,128,117,124,120,122,114,79,2,125,109,92,55,24,82,33,76,103,56,113,118,75,89,105,90,126,111,121,87,80,112,110,26,98,123,29,15,27 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_stake_process_instruction_decode_bail::new_behavior";
  test.test_nonce  = 399;
  test.test_number = 1140;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 4;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111111T9yD14Nj9j7xAB4dbGeiX9h8unkKDDv9ZR",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1140_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1140_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1140_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1140_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111TZJozAg1ruapycCicgz31GxvYJ1FvTVysm",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1140_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1140_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1140_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1140_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRewards111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1140_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1140_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1140_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1140_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1140_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1140_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1140_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1140_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1140_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1140_raw_sz;
  test.expected_result = -2;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1141(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 30,106,108,61,78,116,77,127,83,62,128,117,124,120,122,114,79,2,125,109,92,55,24,82,33,76,103,56,113,118,75,89,105,90,126,111,121,87,80,112,110,26,98,123,29,15,27 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_stake_process_instruction_decode_bail::new_behavior";
  test.test_nonce  = 428;
  test.test_number = 1141;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 1;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111111T9yD14Nj9j7xAB4dbGeiX9h8unkKDDv9ZR",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1141_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1141_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1141_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1141_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1141_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1141_raw_sz;
  test.expected_result = -20;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1142(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 30,106,108,61,78,116,77,127,83,62,128,117,124,120,122,114,79,2,125,109,92,55,24,82,33,76,103,56,113,118,75,89,105,90,126,111,121,87,80,112,110,26,98,123,29,15,27 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_stake_process_instruction_decode_bail::new_behavior";
  test.test_nonce  = 392;
  test.test_number = 1142;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 4;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111111TZJozAg1ruapycCicgz31GxvYJ1FvTVysm",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1142_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1142_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1142_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1142_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111UMz1xPGbHGWacUUtfXefyXWVoJX9LvfeWT",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1142_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1142_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1142_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1142_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRewards111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1142_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1142_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1142_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1142_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1142_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1142_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1142_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1142_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1142_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1142_raw_sz;
  test.expected_result = -2;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1143(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 30,106,108,61,78,116,77,127,83,62,128,117,124,120,122,114,79,2,125,109,92,55,24,82,33,76,103,56,113,118,75,89,105,90,126,111,121,87,80,112,110,26,98,123,29,15,27 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_stake_process_instruction_decode_bail::new_behavior";
  test.test_nonce  = 446;
  test.test_number = 1143;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 1;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111111TZJozAg1ruapycCicgz31GxvYJ1FvTVysm",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1143_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1143_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1143_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1143_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1143_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1143_raw_sz;
  test.expected_result = -20;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1144(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 30,106,108,61,78,116,77,127,83,62,128,117,124,120,122,114,79,2,125,109,92,55,24,82,33,76,103,56,113,118,75,89,105,90,126,111,121,87,80,112,110,26,98,123,29,15,27 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_stake_process_instruction_decode_bail::new_behavior";
  test.test_nonce  = 441;
  test.test_number = 1144;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 2;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111111T9yD14Nj9j7xAB4dbGeiX9h8unkKDDv9ZR",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1144_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1144_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1144_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1144_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRewards111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1144_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1144_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1144_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1144_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1144_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1144_raw_sz;
  test.expected_result = -2;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1145(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 30,106,108,61,78,116,77,127,83,62,128,117,124,120,122,114,79,2,125,109,92,55,24,82,33,76,103,56,113,118,75,89,105,90,126,111,121,87,80,112,110,26,98,123,29,15,27 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_stake_process_instruction_decode_bail::new_behavior";
  test.test_nonce  = 448;
  test.test_number = 1145;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 0;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1145_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1145_raw_sz;
  test.expected_result = -20;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1146(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 30,106,108,61,78,116,77,127,83,62,128,117,124,120,122,114,79,2,125,109,92,55,24,82,33,76,103,56,113,118,75,89,105,90,126,111,121,87,80,112,110,26,98,123,29,15,27 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_stake_process_instruction_decode_bail::new_behavior";
  test.test_nonce  = 449;
  test.test_number = 1146;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 2;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111111TZJozAg1ruapycCicgz31GxvYJ1FvTVysm",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1146_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1146_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1146_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1146_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRewards111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1146_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1146_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1146_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1146_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1146_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1146_raw_sz;
  test.expected_result = -2;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1147(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 30,106,108,61,78,116,77,127,83,62,128,117,124,120,122,114,79,2,125,109,92,55,24,82,33,76,103,56,113,118,75,89,105,90,126,111,121,87,80,112,110,26,98,123,29,15,27 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_stake_process_instruction_decode_bail::new_behavior";
  test.test_nonce  = 453;
  test.test_number = 1147;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 0;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1147_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1147_raw_sz;
  test.expected_result = -20;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1148(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 30,106,108,61,78,116,77,127,83,62,128,117,124,120,122,114,79,2,125,109,92,55,24,82,33,76,103,56,113,118,75,89,105,90,126,111,121,87,80,112,110,26,98,123,29,15,27 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_stake_process_instruction_decode_bail::new_behavior";
  test.test_nonce  = 459;
  test.test_number = 1148;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 0;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1148_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1148_raw_sz;
  test.expected_result = -20;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1149(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 30,106,108,61,78,116,77,127,83,62,128,117,124,120,122,114,79,2,125,109,92,55,24,82,33,76,103,56,113,118,75,89,105,90,126,111,121,87,80,112,110,26,98,123,29,15,27 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_stake_process_instruction_decode_bail::new_behavior";
  test.test_nonce  = 467;
  test.test_number = 1149;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 1;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111111T9yD14Nj9j7xAB4dbGeiX9h8unkKDDv9ZR",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1149_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1149_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1149_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1149_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1149_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1149_raw_sz;
  test.expected_result = -20;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
