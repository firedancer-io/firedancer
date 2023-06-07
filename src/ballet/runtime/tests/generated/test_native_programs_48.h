#include "../fd_tests.h"
int test_1200(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 15,114,77,106,78,29,117,127,56,2,124,62,55,33,112,76,123,108,128,109,75,87,126,103,26,89,80,90,116,24,92,125,111,27,120,121,122,82,79,110,98,61,83,113,118,30,105 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_stake_process_instruction_error_ordering::old_behavior";
  test.test_nonce  = 265;
  test.test_number = 1200;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 2;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111111VZzpuiATQouD4mu9jnedRuKrgpHyUdR9TV",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 18446744073709551615UL;
  test_acc->result_lamports = 18446744073709551615UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1200_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1200_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1200_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1200_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1200_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1200_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1200_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1200_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1200_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1200_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1201(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 15,114,77,106,78,29,117,127,56,2,124,62,55,33,112,76,123,108,128,109,75,87,126,103,26,89,80,90,116,24,92,125,111,27,120,121,122,82,79,110,98,61,83,113,118,30,105 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_stake_process_instruction_error_ordering::old_behavior";
  test.test_nonce  = 294;
  test.test_number = 1201;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 0;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1201_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1201_raw_sz;
  test.expected_result = -20;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1202(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 15,114,106,29,78,117,127,77,56,2,124,62,55,33,112,76,123,108,128,109,75,87,126,103,26,89,80,90,116,24,92,125,111,27,120,121,122,82,79,110,98,61,83,113,118,30,105 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_stake_process_instruction_error_ordering::old_behavior";
  test.test_nonce  = 194;
  test.test_number = 1202;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 2;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111111VZzpuiATQouD4mu9jnedRuKrgpHyUdR9TV",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 18446744073709551615UL;
  test_acc->result_lamports = 18446744073709551615UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1202_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1202_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1202_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1202_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1202_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1202_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1202_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1202_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1202_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1202_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1203(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 15,114,106,29,78,117,127,77,56,2,124,62,55,33,112,76,123,108,128,109,75,87,126,103,26,89,80,90,116,24,92,125,111,27,120,121,122,82,79,110,98,61,83,113,118,30,105 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_stake_process_instruction_error_ordering::old_behavior";
  test.test_nonce  = 236;
  test.test_number = 1203;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 0;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1203_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1203_raw_sz;
  test.expected_result = -20;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1204(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 2;
  uchar disabled_features[] = { 89,77 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_stake_process_instruction_error_ordering::old_behavior";
  test.test_nonce  = 263;
  test.test_number = 1204;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 2;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111111TxeQyGyJa63ho3Loe7KMVQEiAoGCdh5pC7",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 18446744073709551615UL;
  test_acc->result_lamports = 18446744073709551615UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1204_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1204_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1204_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1204_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1204_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1204_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1204_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1204_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1204_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1204_raw_sz;
  test.expected_result = -3;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1205(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 2;
  uchar disabled_features[] = { 89,77 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_stake_process_instruction_error_ordering::old_behavior";
  test.test_nonce  = 269;
  test.test_number = 1205;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 0;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1205_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1205_raw_sz;
  test.expected_result = -20;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1206(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 1;
  uchar disabled_features[] = { 89 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_stake_process_instruction_error_ordering::old_behavior";
  test.test_nonce  = 211;
  test.test_number = 1206;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 2;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111111TxeQyGyJa63ho3Loe7KMVQEiAoGCdh5pC7",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 18446744073709551615UL;
  test_acc->result_lamports = 18446744073709551615UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1206_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1206_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1206_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1206_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1206_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1206_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1206_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1206_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1206_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1206_raw_sz;
  test.expected_result = -3;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1207(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 1;
  uchar disabled_features[] = { 89 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_stake_process_instruction_error_ordering::old_behavior";
  test.test_nonce  = 230;
  test.test_number = 1207;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 0;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1207_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1207_raw_sz;
  test.expected_result = -3;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1208(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 15,114,77,106,78,29,117,127,56,2,124,62,55,33,112,76,123,108,128,109,75,87,126,103,26,89,80,90,116,24,92,125,111,27,120,121,122,82,79,110,98,61,83,113,118,30,105 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_stake_process_instruction_error_ordering::old_behavior";
  test.test_nonce  = 281;
  test.test_number = 1208;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 2;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111111VZzpuiATQouD4mu9jnedRuKrgpHyUdR9TV",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 18446744073709551615UL;
  test_acc->result_lamports = 18446744073709551615UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1208_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1208_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1208_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1208_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1208_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1208_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1208_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1208_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1208_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1208_raw_sz;
  test.expected_result = -3;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1209(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 15,114,77,106,78,29,117,127,56,2,124,62,55,33,112,76,123,108,128,109,75,87,126,103,26,89,80,90,116,24,92,125,111,27,120,121,122,82,79,110,98,61,83,113,118,30,105 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_stake_process_instruction_error_ordering::old_behavior";
  test.test_nonce  = 311;
  test.test_number = 1209;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 0;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1209_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1209_raw_sz;
  test.expected_result = -20;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1210(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 15,114,106,29,78,117,127,77,56,2,124,62,55,33,112,76,123,108,128,109,75,87,126,103,26,89,80,90,116,24,92,125,111,27,120,121,122,82,79,110,98,61,83,113,118,30,105 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_stake_process_instruction_error_ordering::old_behavior";
  test.test_nonce  = 222;
  test.test_number = 1210;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 2;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111111VZzpuiATQouD4mu9jnedRuKrgpHyUdR9TV",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 18446744073709551615UL;
  test_acc->result_lamports = 18446744073709551615UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1210_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1210_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1210_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1210_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1210_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1210_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1210_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1210_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1210_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1210_raw_sz;
  test.expected_result = -3;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1211(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 15,114,106,29,78,117,127,77,56,2,124,62,55,33,112,76,123,108,128,109,75,87,126,103,26,89,80,90,116,24,92,125,111,27,120,121,122,82,79,110,98,61,83,113,118,30,105 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_stake_process_instruction_error_ordering::old_behavior";
  test.test_nonce  = 253;
  test.test_number = 1211;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 0;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1211_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1211_raw_sz;
  test.expected_result = -3;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1212(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 127,122,33,118,79,125,82,116,120,110,90,2,75,80,113,103,83,56,87,61,108,111,98,62,55,124,26,128,29,112,27,126,105,89,121,117,76,78,106,114,109,15,92,24,30,123,77 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_stake_process_instruction::new_behavior";
  test.test_nonce  = 260;
  test.test_number = 1212;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1212_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1212_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1212_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1212_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111SMJ12qn9jNCCXJnTYRz5Yu9ZenERnkkUvj",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1212_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1212_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1212_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1212_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1212_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1212_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1212_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1212_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1212_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1212_raw_sz;
  test.expected_result = -4;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1213(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 127,122,33,118,79,125,82,116,120,110,90,2,75,80,113,103,83,56,87,61,108,111,98,62,55,124,26,128,29,112,27,126,105,89,121,117,76,78,106,114,109,15,92,24,30,123,77 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_stake_process_instruction::new_behavior";
  test.test_nonce  = 172;
  test.test_number = 1213;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1213_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1213_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1213_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1213_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1213_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1213_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1213_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1213_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111Qjwb6QazteLhFaE7SkeocQ4R8mCewpR9fM",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1213_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1213_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1213_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1213_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1213_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1213_raw_sz;
  test.expected_result = -4;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1214(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 127,122,33,118,79,125,82,116,120,110,90,2,75,80,113,103,83,56,87,61,108,111,98,62,55,124,26,128,29,112,27,126,105,89,121,117,76,78,106,114,109,15,92,24,30,123,77 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_stake_process_instruction::new_behavior";
  test.test_nonce  = 190;
  test.test_number = 1214;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1214_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1214_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1214_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1214_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111VZzpuiATQouD4mu9jnedRuKrgpHyUdR9TV",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1214_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1214_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1214_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1214_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111VyLRtpTk7zN5tD3EmCywv2beKKYvBrzymq",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1214_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1214_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1214_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1214_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1214_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1214_raw_sz;
  test.expected_result = -4;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1215(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 127,122,33,118,79,125,82,116,120,110,90,2,75,80,113,103,83,56,87,61,108,111,98,62,55,124,26,128,29,112,27,126,105,89,121,117,76,78,106,114,109,15,92,24,30,123,77 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_stake_process_instruction::new_behavior";
  test.test_nonce  = 296;
  test.test_number = 1215;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111111dDRHcmpvuEhrc1YoCkygeHVoeQBtz5VyU3",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1215_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1215_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1215_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1215_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1215_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1215_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1215_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1215_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111dcktbt8DcRAjRSgtEBK18QmbGuSqhK5onP",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1215_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1215_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1215_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1215_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1215_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1215_raw_sz;
  test.expected_result = -4;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1216(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 127,122,33,118,79,125,82,116,120,110,90,2,75,80,113,103,83,56,87,61,108,111,98,62,55,124,26,128,29,112,27,126,105,89,121,117,76,78,106,114,109,15,92,24,30,123,77 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_stake_process_instruction::new_behavior";
  test.test_nonce  = 451;
  test.test_number = 1216;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 6;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111111sJFQ5aG1kYvXEBRq4Sdqcg2Lg4CusGv8Y7",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1216_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1216_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1216_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1216_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "BadVote111111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1216_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1216_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1216_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1216_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1216_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1216_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1216_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1216_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1216_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1216_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1216_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1216_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "StakeConfig11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1216_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1216_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1216_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1216_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111shb14gZJTjPQ3cZv5ryA6oJ8JZTraWVxrT",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1216_acc_5_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1216_acc_5_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1216_acc_5_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1216_acc_5_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1216_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1216_raw_sz;
  test.expected_result = -4;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1217(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 127,122,33,118,79,125,82,116,120,110,90,2,75,80,113,103,83,56,87,61,108,111,98,62,55,124,26,128,29,112,27,126,105,89,121,117,76,78,106,114,109,15,92,24,30,123,77 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_stake_process_instruction::new_behavior";
  test.test_nonce  = 409;
  test.test_number = 1217;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 6;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "StakeConfig11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1217_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1217_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1217_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1217_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "BadVote111111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1217_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1217_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1217_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1217_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1217_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1217_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1217_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1217_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1217_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1217_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1217_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1217_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111rVaC7MfSLBzmbK9f1byCeRUmR3h2SokTuR",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1217_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1217_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1217_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1217_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111r6Eb8FN9d1Xtmt1ZzBdtAJCynYS5jaAdb5",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1217_acc_5_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1217_acc_5_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1217_acc_5_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1217_acc_5_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1217_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1217_raw_sz;
  test.expected_result = -4;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1218(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 127,122,33,118,79,125,82,116,120,110,90,2,75,80,113,103,83,56,87,61,108,111,98,62,55,124,26,128,29,112,27,126,105,89,121,117,76,78,106,114,109,15,92,24,30,123,77 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_stake_process_instruction::new_behavior";
  test.test_nonce  = 324;
  test.test_number = 1218;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 4;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111111epmhZD25jxZMsk79JSJxanaxARDfq1qJjR",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1218_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1218_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1218_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1218_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111eRS6a6io2n6V4Jy4H1ye6fKAXuxj7nFUR5",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1218_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1218_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1218_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1218_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "BadStake11111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1218_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1218_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1218_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1218_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1218_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1218_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1218_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1218_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1218_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1218_raw_sz;
  test.expected_result = -4;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1219(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 127,122,33,118,79,125,82,116,120,110,90,2,75,80,113,103,83,56,87,61,108,111,98,62,55,124,26,128,29,112,27,126,105,89,121,117,76,78,106,114,109,15,92,24,30,123,77 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_stake_process_instruction::new_behavior";
  test.test_nonce  = 426;
  test.test_number = 1219;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 4;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111111p5YaChsi57DWgiK8s5yHjfr3e29NBQFU1M",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1219_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1219_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1219_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1219_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "BadStake11111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1219_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1219_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1219_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1219_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111pUtBBpAznHgPW9TDtWJcDo7qGXQJtdqJKh",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1219_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1219_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1219_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1219_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1219_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1219_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1219_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1219_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1219_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1219_raw_sz;
  test.expected_result = -4;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1220(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 127,122,33,118,79,125,82,116,120,110,90,2,75,80,113,103,83,56,87,61,108,111,98,62,55,124,26,128,29,112,27,126,105,89,121,117,76,78,106,114,109,15,92,24,30,123,77 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_stake_process_instruction::new_behavior";
  test.test_nonce  = 229;
  test.test_number = 1220;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 4;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111111aQ44j1juvyTisyaC2peTFQbJEsPJ1SR9Fd",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1220_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1220_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1220_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1220_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111ZziTjuSdDnzr4YS71QK8mHKWcN8MJCqJwH",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1220_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1220_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1220_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1220_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1220_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1220_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1220_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1220_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "BadStake11111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1220_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1220_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1220_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1220_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1220_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1220_raw_sz;
  test.expected_result = -4;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1221(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 127,122,33,118,79,125,82,116,120,110,90,2,75,80,113,103,83,56,87,61,108,111,98,62,55,124,26,128,29,112,27,126,105,89,121,117,76,78,106,114,109,15,92,24,30,123,77 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_stake_process_instruction::new_behavior";
  test.test_nonce  = 398;
  test.test_number = 1221;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 4;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "BadStake11111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1221_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1221_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1221_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1221_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111pUtBBpAznHgPW9TDtWJcDo7qGXQJtdqJKh",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1221_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1221_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1221_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1221_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1221_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1221_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1221_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1221_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111p5YaChsi57DWgiK8s5yHjfr3e29NBQFU1M",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1221_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1221_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1221_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1221_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1221_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1221_raw_sz;
  test.expected_result = -4;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1222(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 127,122,33,118,79,125,82,116,120,110,90,2,75,80,113,103,83,56,87,61,108,111,98,62,55,124,26,128,29,112,27,126,105,89,121,117,76,78,106,114,109,15,92,24,30,123,77 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_stake_process_instruction::new_behavior";
  test.test_nonce  = 501;
  test.test_number = 1222;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 5;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111111wiy2umYBZY2ADwxnL4JLx41zbc3HgrLJ1u",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1222_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1222_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1222_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1222_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111xXeEsz8kytwurpExNtxyvJZZrcZB7KVxeb",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1222_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1222_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1222_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1222_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1222_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1222_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1222_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1222_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111x8JdtsqUGiV33P6sMUdfSBHnE7JEQ5v8LF",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1222_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1222_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1222_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1222_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1222_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1222_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1222_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1222_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1222_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1222_raw_sz;
  test.expected_result = -4;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1223(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 127,122,33,118,79,125,82,116,120,110,90,2,75,80,113,103,83,56,87,61,108,111,98,62,55,124,26,128,29,112,27,126,105,89,121,117,76,78,106,114,109,15,92,24,30,123,77 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_stake_process_instruction::new_behavior";
  test.test_nonce  = 465;
  test.test_number = 1223;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 5;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111111xvyqs6S3h5QngFP3QKJJQRqMV7p7pZ5nxw",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1223_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1223_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1223_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1223_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1223_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1223_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1223_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1223_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111yjf3qK2d7SLYK7fDT9xwNgNvk8L1F2FTbd",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1223_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1223_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1223_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1223_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1223_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1223_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1223_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1223_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111yLKSrCjLQFsfVgX8RjdctZ797d54XnfdHH",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1223_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1223_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1223_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1223_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1223_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1223_raw_sz;
  test.expected_result = -4;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1224(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 127,122,33,118,79,125,82,116,120,110,90,2,75,80,113,103,83,56,87,61,108,111,98,62,55,124,26,128,29,112,27,126,105,89,121,117,76,78,106,114,109,15,92,24,30,123,77 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_stake_process_instruction::new_behavior";
  test.test_nonce  = 532;
  test.test_number = 1224;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "111111125mj6bwVwm9HgackWpSxieZTjBhC9uXzxLo",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1224_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1224_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1224_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1224_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1224_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1224_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1224_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1224_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "111111125NPVcqCf3xpomBcRo2dQASBwZBwDCJR82T",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1224_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1224_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1224_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1224_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1224_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1224_raw_sz;
  test.expected_result = -4;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
