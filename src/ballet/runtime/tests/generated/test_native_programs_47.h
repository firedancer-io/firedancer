#include "../fd_tests.h"
int test_1175(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 1;
  uchar disabled_features[] = { 89 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_stake_process_instruction_decode_bail::old_behavior";
  test.test_nonce  = 470;
  test.test_number = 1175;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 1;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111111UmKcwVZszSyTRucygwyzTenHRon64AFUpo",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1175_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1175_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1175_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1175_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1175_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1175_raw_sz;
  test.expected_result = -20;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1176(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 1;
  uchar disabled_features[] = { 89 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_stake_process_instruction_decode_bail::old_behavior";
  test.test_nonce  = 473;
  test.test_number = 1176;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 2;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111111UmKcwVZszSyTRucygwyzTenHRon64AFUpo",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1176_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1176_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1176_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1176_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111VAfDvbsAhdSLFLm4iNKJwn454K32mPqK99",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1176_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1176_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1176_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1176_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1176_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1176_raw_sz;
  test.expected_result = -20;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1177(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 121,108,98,92,90,128,122,103,15,125,89,87,61,116,27,62,33,80,110,109,75,29,30,127,124,112,113,24,126,118,105,114,120,106,111,26,55,82,123,2,83,56,79,78,76,117,77 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_stake_process_instruction_decode_bail::old_behavior";
  test.test_nonce  = 454;
  test.test_number = 1177;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 0;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1177_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1177_raw_sz;
  test.expected_result = -20;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1178(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 121,108,98,92,90,128,122,103,15,125,89,87,61,116,27,62,33,80,110,109,75,29,30,127,124,112,113,24,126,118,105,114,120,106,111,26,55,82,123,2,83,56,79,78,76,117,77 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_stake_process_instruction_decode_bail::old_behavior";
  test.test_nonce  = 462;
  test.test_number = 1178;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 1;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111111UmKcwVZszSyTRucygwyzTenHRon64AFUpo",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1178_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1178_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1178_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1178_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1178_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1178_raw_sz;
  test.expected_result = -20;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1179(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 121,108,98,92,90,128,122,103,15,125,89,87,61,116,27,62,33,80,110,109,75,29,30,127,124,112,113,24,126,118,105,114,120,106,111,26,55,82,123,2,83,56,79,78,76,117,77 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_stake_process_instruction_decode_bail::old_behavior";
  test.test_nonce  = 476;
  test.test_number = 1179;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 2;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111111UmKcwVZszSyTRucygwyzTenHRon64AFUpo",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1179_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1179_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1179_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1179_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111VAfDvbsAhdSLFLm4iNKJwn454K32mPqK99",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1179_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1179_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1179_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1179_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1179_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1179_raw_sz;
  test.expected_result = -20;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1180(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 1;
  uchar disabled_features[] = { 77 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_stake_process_instruction_error_ordering::new_behavior";
  test.test_nonce  = 247;
  test.test_number = 1180;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 2;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111111T9yD14Nj9j7xAB4dbGeiX9h8unkKDDv9ZR",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 18446744073709551615UL;
  test_acc->result_lamports = 18446744073709551615UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1180_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1180_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1180_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1180_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1180_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1180_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1180_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1180_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1180_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1180_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1181(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 1;
  uchar disabled_features[] = { 77 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_stake_process_instruction_error_ordering::new_behavior";
  test.test_nonce  = 272;
  test.test_number = 1181;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 0;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1181_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1181_raw_sz;
  test.expected_result = -20;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1182(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 77 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_stake_process_instruction_error_ordering::new_behavior";
  test.test_nonce  = 200;
  test.test_number = 1182;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 2;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111111T9yD14Nj9j7xAB4dbGeiX9h8unkKDDv9ZR",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 18446744073709551615UL;
  test_acc->result_lamports = 18446744073709551615UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1182_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1182_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1182_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1182_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1182_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1182_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1182_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1182_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1182_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1182_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1183(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 77 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_stake_process_instruction_error_ordering::new_behavior";
  test.test_nonce  = 225;
  test.test_number = 1183;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 0;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1183_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1183_raw_sz;
  test.expected_result = -20;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1184(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 118,121,80,30,33,111,128,55,113,117,90,15,127,110,124,61,24,103,92,122,109,62,105,108,89,98,2,116,56,27,120,87,77,106,78,126,29,26,79,76,83,82,125,112,114,75,123 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_stake_process_instruction_error_ordering::new_behavior";
  test.test_nonce  = 263;
  test.test_number = 1184;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 2;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111111XagqqFetxiDb9wbartKDrXgnqLah2oLK3D",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 18446744073709551615UL;
  test_acc->result_lamports = 18446744073709551615UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1184_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1184_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1184_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1184_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1184_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1184_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1184_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1184_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1184_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1184_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1185(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 118,121,80,30,33,111,128,55,113,117,90,15,127,110,124,61,24,103,92,122,109,62,105,108,89,98,2,116,56,27,120,87,77,106,78,126,29,26,79,76,83,82,125,112,114,75,123 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_stake_process_instruction_error_ordering::new_behavior";
  test.test_nonce  = 308;
  test.test_number = 1185;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 0;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1185_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1185_raw_sz;
  test.expected_result = -20;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1186(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 118,121,80,30,33,111,128,55,113,117,90,15,127,110,124,61,24,103,92,122,109,62,105,108,89,98,2,116,56,27,120,87,77,106,78,126,29,26,79,76,83,82,125,112,114,75,123 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_stake_process_instruction_error_ordering::new_behavior";
  test.test_nonce  = 333;
  test.test_number = 1186;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 2;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111111XagqqFetxiDb9wbartKDrXgnqLah2oLK3D",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 18446744073709551615UL;
  test_acc->result_lamports = 18446744073709551615UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1186_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1186_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1186_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1186_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1186_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1186_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1186_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1186_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1186_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1186_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1187(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 118,121,80,30,33,111,128,55,113,117,90,15,127,110,124,61,24,103,92,122,109,62,105,108,89,98,2,116,56,27,120,87,77,106,78,126,29,26,79,76,83,82,125,112,114,75,123 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_stake_process_instruction_error_ordering::new_behavior";
  test.test_nonce  = 354;
  test.test_number = 1187;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 0;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1187_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1187_raw_sz;
  test.expected_result = -20;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1188(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 118,121,80,30,33,111,128,55,113,117,90,15,127,110,124,61,24,103,92,122,109,62,105,108,89,98,2,116,56,27,120,87,77,106,78,126,29,26,79,76,83,82,125,112,114,75,123 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_stake_process_instruction_error_ordering::new_behavior";
  test.test_nonce  = 282;
  test.test_number = 1188;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 2;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111111XagqqFetxiDb9wbartKDrXgnqLah2oLK3D",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 18446744073709551615UL;
  test_acc->result_lamports = 18446744073709551615UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1188_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1188_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1188_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1188_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1188_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1188_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1188_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1188_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1188_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1188_raw_sz;
  test.expected_result = -3;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1189(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 118,121,80,30,33,111,128,55,113,117,90,15,127,110,124,61,24,103,92,122,109,62,105,108,89,98,2,116,56,27,120,87,77,106,78,126,29,26,79,76,83,82,125,112,114,75,123 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_stake_process_instruction_error_ordering::new_behavior";
  test.test_nonce  = 321;
  test.test_number = 1189;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 0;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1189_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1189_raw_sz;
  test.expected_result = -3;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1190(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 118,121,80,30,33,111,128,55,113,117,90,15,127,110,124,61,24,103,92,122,109,62,105,108,89,98,2,116,56,27,120,87,77,106,78,126,29,26,79,76,83,82,125,112,114,75,123 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_stake_process_instruction_error_ordering::new_behavior";
  test.test_nonce  = 345;
  test.test_number = 1190;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 2;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111111XagqqFetxiDb9wbartKDrXgnqLah2oLK3D",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 18446744073709551615UL;
  test_acc->result_lamports = 18446744073709551615UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1190_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1190_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1190_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1190_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1190_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1190_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1190_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1190_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1190_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1190_raw_sz;
  test.expected_result = -3;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1191(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 118,121,80,30,33,111,128,55,113,117,90,15,127,110,124,61,24,103,92,122,109,62,105,108,89,98,2,116,56,27,120,87,77,106,78,126,29,26,79,76,83,82,125,112,114,75,123 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_stake_process_instruction_error_ordering::new_behavior";
  test.test_nonce  = 366;
  test.test_number = 1191;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 0;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1191_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1191_raw_sz;
  test.expected_result = -20;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1192(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 1;
  uchar disabled_features[] = { 77 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_stake_process_instruction_error_ordering::new_behavior";
  test.test_nonce  = 264;
  test.test_number = 1192;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 2;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111111T9yD14Nj9j7xAB4dbGeiX9h8unkKDDv9ZR",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 18446744073709551615UL;
  test_acc->result_lamports = 18446744073709551615UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1192_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1192_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1192_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1192_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1192_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1192_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1192_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1192_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1192_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1192_raw_sz;
  test.expected_result = -3;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1193(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 1;
  uchar disabled_features[] = { 77 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_stake_process_instruction_error_ordering::new_behavior";
  test.test_nonce  = 283;
  test.test_number = 1193;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 0;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1193_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1193_raw_sz;
  test.expected_result = -20;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1194(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 77 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_stake_process_instruction_error_ordering::new_behavior";
  test.test_nonce  = 213;
  test.test_number = 1194;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 2;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111111T9yD14Nj9j7xAB4dbGeiX9h8unkKDDv9ZR",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 18446744073709551615UL;
  test_acc->result_lamports = 18446744073709551615UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1194_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1194_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1194_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1194_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1194_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1194_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1194_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1194_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1194_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1194_raw_sz;
  test.expected_result = -3;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1195(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 77 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_stake_process_instruction_error_ordering::new_behavior";
  test.test_nonce  = 231;
  test.test_number = 1195;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 0;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1195_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1195_raw_sz;
  test.expected_result = -3;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1196(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 2;
  uchar disabled_features[] = { 89,77 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_stake_process_instruction_error_ordering::old_behavior";
  test.test_nonce  = 245;
  test.test_number = 1196;
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
  test_acc->data            = fd_flamenco_native_prog_test_1196_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1196_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1196_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1196_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1196_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1196_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1196_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1196_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1196_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1196_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1197(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 2;
  uchar disabled_features[] = { 89,77 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_stake_process_instruction_error_ordering::old_behavior";
  test.test_nonce  = 266;
  test.test_number = 1197;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 0;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1197_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1197_raw_sz;
  test.expected_result = -20;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1198(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 1;
  uchar disabled_features[] = { 89 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_stake_process_instruction_error_ordering::old_behavior";
  test.test_nonce  = 201;
  test.test_number = 1198;
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
  test_acc->data            = fd_flamenco_native_prog_test_1198_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1198_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1198_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1198_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1198_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1198_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1198_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1198_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1198_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1198_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1199(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 1;
  uchar disabled_features[] = { 89 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_stake_process_instruction_error_ordering::old_behavior";
  test.test_nonce  = 223;
  test.test_number = 1199;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 0;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1199_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1199_raw_sz;
  test.expected_result = -20;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
