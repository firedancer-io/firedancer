#include "../fd_tests.h"
int test_1150(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 30,106,108,61,78,116,77,127,83,62,128,117,124,120,122,114,79,2,125,109,92,55,24,82,33,76,103,56,113,118,75,89,105,90,126,111,121,87,80,112,110,26,98,123,29,15,27 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_stake_process_instruction_decode_bail::new_behavior";
  test.test_nonce  = 481;
  test.test_number = 1150;
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
  test_acc->data            = fd_flamenco_native_prog_test_1150_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1150_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1150_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1150_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111TZJozAg1ruapycCicgz31GxvYJ1FvTVysm",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1150_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1150_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1150_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1150_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1150_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1150_raw_sz;
  test.expected_result = -20;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1151(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 30,106,108,61,78,116,77,127,83,62,128,117,124,120,122,114,79,2,125,109,92,55,24,82,33,76,103,56,113,118,75,89,105,90,126,111,121,87,80,112,110,26,98,123,29,15,27 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_stake_process_instruction_decode_bail::new_behavior";
  test.test_nonce  = 456;
  test.test_number = 1151;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 0;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1151_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1151_raw_sz;
  test.expected_result = -20;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1152(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 30,106,108,61,78,116,77,127,83,62,128,117,124,120,122,114,79,2,125,109,92,55,24,82,33,76,103,56,113,118,75,89,105,90,126,111,121,87,80,112,110,26,98,123,29,15,27 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_stake_process_instruction_decode_bail::new_behavior";
  test.test_nonce  = 460;
  test.test_number = 1152;
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
  test_acc->data            = fd_flamenco_native_prog_test_1152_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1152_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1152_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1152_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1152_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1152_raw_sz;
  test.expected_result = -20;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1153(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 30,106,108,61,78,116,77,127,83,62,128,117,124,120,122,114,79,2,125,109,92,55,24,82,33,76,103,56,113,118,75,89,105,90,126,111,121,87,80,112,110,26,98,123,29,15,27 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_stake_process_instruction_decode_bail::new_behavior";
  test.test_nonce  = 463;
  test.test_number = 1153;
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
  test_acc->data            = fd_flamenco_native_prog_test_1153_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1153_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1153_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1153_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111UMz1xPGbHGWacUUtfXefyXWVoJX9LvfeWT",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1153_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1153_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1153_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1153_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1153_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1153_raw_sz;
  test.expected_result = -20;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1154(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 1;
  uchar disabled_features[] = { 89 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_stake_process_instruction_decode_bail::old_behavior";
  test.test_nonce  = 197;
  test.test_number = 1154;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 0;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1154_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1154_raw_sz;
  test.expected_result = -20;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1155(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 1;
  uchar disabled_features[] = { 89 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_stake_process_instruction_decode_bail::old_behavior";
  test.test_nonce  = 232;
  test.test_number = 1155;
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
  test_acc->data            = fd_flamenco_native_prog_test_1155_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1155_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1155_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1155_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1155_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1155_raw_sz;
  test.expected_result = -20;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1156(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 1;
  uchar disabled_features[] = { 89 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_stake_process_instruction_decode_bail::old_behavior";
  test.test_nonce  = 251;
  test.test_number = 1156;
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
  test_acc->data            = fd_flamenco_native_prog_test_1156_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1156_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1156_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1156_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1156_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1156_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1156_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1156_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1156_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1156_raw_sz;
  test.expected_result = -4;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1157(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 121,108,98,92,90,128,122,103,15,125,89,87,61,116,27,62,33,80,110,109,75,29,30,127,124,112,113,24,126,118,105,114,120,106,111,26,55,82,123,2,83,56,79,78,76,117,77 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_stake_process_instruction_decode_bail::old_behavior";
  test.test_nonce  = 214;
  test.test_number = 1157;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 0;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1157_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1157_raw_sz;
  test.expected_result = -20;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1158(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 121,108,98,92,90,128,122,103,15,125,89,87,61,116,27,62,33,80,110,109,75,29,30,127,124,112,113,24,126,118,105,114,120,106,111,26,55,82,123,2,83,56,79,78,76,117,77 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_stake_process_instruction_decode_bail::old_behavior";
  test.test_nonce  = 230;
  test.test_number = 1158;
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
  test_acc->data            = fd_flamenco_native_prog_test_1158_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1158_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1158_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1158_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1158_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1158_raw_sz;
  test.expected_result = -20;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1159(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 121,108,98,92,90,128,122,103,15,125,89,87,61,116,27,62,33,80,110,109,75,29,30,127,124,112,113,24,126,118,105,114,120,106,111,26,55,82,123,2,83,56,79,78,76,117,77 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_stake_process_instruction_decode_bail::old_behavior";
  test.test_nonce  = 241;
  test.test_number = 1159;
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
  test_acc->data            = fd_flamenco_native_prog_test_1159_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1159_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1159_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1159_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1159_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1159_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1159_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1159_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1159_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1159_raw_sz;
  test.expected_result = -4;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1160(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 1;
  uchar disabled_features[] = { 89 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_stake_process_instruction_decode_bail::old_behavior";
  test.test_nonce  = 271;
  test.test_number = 1160;
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
  test_acc->data            = fd_flamenco_native_prog_test_1160_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1160_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1160_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1160_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1160_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1160_raw_sz;
  test.expected_result = -20;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1161(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 1;
  uchar disabled_features[] = { 89 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_stake_process_instruction_decode_bail::old_behavior";
  test.test_nonce  = 284;
  test.test_number = 1161;
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
  test_acc->data            = fd_flamenco_native_prog_test_1161_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1161_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1161_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1161_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1161_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1161_raw_sz;
  test.expected_result = -20;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1162(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 1;
  uchar disabled_features[] = { 89 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_stake_process_instruction_decode_bail::old_behavior";
  test.test_nonce  = 322;
  test.test_number = 1162;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 5;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111111UmKcwVZszSyTRucygwyzTenHRon64AFUpo",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1162_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1162_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1162_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1162_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111VAfDvbsAhdSLFLm4iNKJwn454K32mPqK99",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1162_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1162_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1162_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1162_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1162_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1162_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1162_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1162_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1162_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1162_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1162_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1162_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "StakeConfig11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1162_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1162_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1162_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1162_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1162_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1162_raw_sz;
  test.expected_result = -4;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1163(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 121,108,98,92,90,128,122,103,15,125,89,87,61,116,27,62,33,80,110,109,75,29,30,127,124,112,113,24,126,118,105,114,120,106,111,26,55,82,123,2,83,56,79,78,76,117,77 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_stake_process_instruction_decode_bail::old_behavior";
  test.test_nonce  = 257;
  test.test_number = 1163;
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
  test_acc->data            = fd_flamenco_native_prog_test_1163_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1163_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1163_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1163_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1163_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1163_raw_sz;
  test.expected_result = -20;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1164(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 121,108,98,92,90,128,122,103,15,125,89,87,61,116,27,62,33,80,110,109,75,29,30,127,124,112,113,24,126,118,105,114,120,106,111,26,55,82,123,2,83,56,79,78,76,117,77 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_stake_process_instruction_decode_bail::old_behavior";
  test.test_nonce  = 279;
  test.test_number = 1164;
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
  test_acc->data            = fd_flamenco_native_prog_test_1164_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1164_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1164_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1164_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1164_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1164_raw_sz;
  test.expected_result = -20;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1165(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 121,108,98,92,90,128,122,103,15,125,89,87,61,116,27,62,33,80,110,109,75,29,30,127,124,112,113,24,126,118,105,114,120,106,111,26,55,82,123,2,83,56,79,78,76,117,77 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_stake_process_instruction_decode_bail::old_behavior";
  test.test_nonce  = 318;
  test.test_number = 1165;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 5;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111111UmKcwVZszSyTRucygwyzTenHRon64AFUpo",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1165_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1165_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1165_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1165_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111VAfDvbsAhdSLFLm4iNKJwn454K32mPqK99",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1165_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1165_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1165_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1165_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1165_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1165_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1165_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1165_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1165_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1165_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1165_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1165_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "StakeConfig11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1165_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1165_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1165_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1165_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1165_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1165_raw_sz;
  test.expected_result = -4;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1166(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 1;
  uchar disabled_features[] = { 89 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_stake_process_instruction_decode_bail::old_behavior";
  test.test_nonce  = 404;
  test.test_number = 1166;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 4;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111111UmKcwVZszSyTRucygwyzTenHRon64AFUpo",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1166_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1166_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1166_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1166_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111VAfDvbsAhdSLFLm4iNKJwn454K32mPqK99",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1166_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1166_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1166_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1166_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRewards111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1166_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1166_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1166_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1166_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1166_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1166_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1166_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1166_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1166_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1166_raw_sz;
  test.expected_result = -2;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1167(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 1;
  uchar disabled_features[] = { 89 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_stake_process_instruction_decode_bail::old_behavior";
  test.test_nonce  = 452;
  test.test_number = 1167;
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
  test_acc->data            = fd_flamenco_native_prog_test_1167_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1167_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1167_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1167_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1167_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1167_raw_sz;
  test.expected_result = -20;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1168(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 121,108,98,92,90,128,122,103,15,125,89,87,61,116,27,62,33,80,110,109,75,29,30,127,124,112,113,24,126,118,105,114,120,106,111,26,55,82,123,2,83,56,79,78,76,117,77 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_stake_process_instruction_decode_bail::old_behavior";
  test.test_nonce  = 393;
  test.test_number = 1168;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 4;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111111UmKcwVZszSyTRucygwyzTenHRon64AFUpo",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1168_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1168_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1168_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1168_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111VAfDvbsAhdSLFLm4iNKJwn454K32mPqK99",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1168_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1168_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1168_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1168_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRewards111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1168_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1168_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1168_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1168_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1168_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1168_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1168_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1168_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1168_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1168_raw_sz;
  test.expected_result = -2;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1169(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 121,108,98,92,90,128,122,103,15,125,89,87,61,116,27,62,33,80,110,109,75,29,30,127,124,112,113,24,126,118,105,114,120,106,111,26,55,82,123,2,83,56,79,78,76,117,77 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_stake_process_instruction_decode_bail::old_behavior";
  test.test_nonce  = 420;
  test.test_number = 1169;
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
  test_acc->data            = fd_flamenco_native_prog_test_1169_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1169_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1169_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1169_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1169_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1169_raw_sz;
  test.expected_result = -20;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1170(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 1;
  uchar disabled_features[] = { 89 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_stake_process_instruction_decode_bail::old_behavior";
  test.test_nonce  = 457;
  test.test_number = 1170;
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
  test_acc->data            = fd_flamenco_native_prog_test_1170_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1170_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1170_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1170_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRewards111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1170_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1170_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1170_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1170_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1170_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1170_raw_sz;
  test.expected_result = -2;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1171(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 1;
  uchar disabled_features[] = { 89 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_stake_process_instruction_decode_bail::old_behavior";
  test.test_nonce  = 461;
  test.test_number = 1171;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 0;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1171_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1171_raw_sz;
  test.expected_result = -20;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1172(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 121,108,98,92,90,128,122,103,15,125,89,87,61,116,27,62,33,80,110,109,75,29,30,127,124,112,113,24,126,118,105,114,120,106,111,26,55,82,123,2,83,56,79,78,76,117,77 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_stake_process_instruction_decode_bail::old_behavior";
  test.test_nonce  = 433;
  test.test_number = 1172;
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
  test_acc->data            = fd_flamenco_native_prog_test_1172_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1172_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1172_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1172_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRewards111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1172_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1172_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1172_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1172_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1172_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1172_raw_sz;
  test.expected_result = -2;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1173(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 121,108,98,92,90,128,122,103,15,125,89,87,61,116,27,62,33,80,110,109,75,29,30,127,124,112,113,24,126,118,105,114,120,106,111,26,55,82,123,2,83,56,79,78,76,117,77 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_stake_process_instruction_decode_bail::old_behavior";
  test.test_nonce  = 445;
  test.test_number = 1173;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 0;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1173_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1173_raw_sz;
  test.expected_result = -20;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1174(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 1;
  uchar disabled_features[] = { 89 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_stake_process_instruction_decode_bail::old_behavior";
  test.test_nonce  = 464;
  test.test_number = 1174;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 0;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1174_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1174_raw_sz;
  test.expected_result = -20;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
