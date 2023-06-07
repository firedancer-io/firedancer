#include "../fd_tests.h"
int test_1375(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 90,33,128,116,127,75,121,24,120,83,87,109,112,56,62,103,26,77,89,82,114,124,113,105,30,29,110,27,106,79,80,125,61,123,2,76,55,111,98,122,78,126,15,92,117,118,108 };
  test.disable_feature = disabled_features;
  test.test_name = "system_instruction_processor::tests::test_create_account_with_seed_separate_base_account";
  test.test_nonce  = 6;
  test.test_number = 1375;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111113WdLfRPMoakqrfpJfRkUhwxuRuTkBeDzeLFH",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 50UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1375_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1375_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1375_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1375_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "dLgf8Q3MjJi7q5xuH8kCR7c3LGYqoGi97KDKCEtV9Ri",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 50UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1375_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1375_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1375_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1375_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111113Wdk12NU6sU2KYdjoWmu3GT2hh6FSawEEAZd",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1375_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1375_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1375_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1375_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1375_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1375_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1376(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 120,110,76,126,61,75,105,128,113,114,117,103,33,82,123,55,29,30,83,116,78,124,15,56,87,27,108,122,62,98,118,121,112,127,89,92,90,24,77,109,106,2,111,80,125,79,26 };
  test.disable_feature = disabled_features;
  test.test_name = "system_instruction_processor::tests::test_create_already_in_use";
  test.test_nonce  = 10;
  test.test_number = 1376;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 2;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111113VFfjzRrnYB87BtV4GuQkqx5Y8qsAsTd9Pd1",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1376_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1376_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1376_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1376_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111113VG55bQy5ptJa4hvCMvq6ASCovUNRpArjDwM",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1376_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1376_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1376_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1376_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1376_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1376_raw_sz;
  test.expected_result = -26;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1377(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 113,30,29,61,78,105,118,76,55,122,110,124,82,111,77,92,116,87,123,120,126,33,103,90,98,106,121,80,27,56,62,83,112,108,117,109,15,79,24,114,89,2,26,128,127,125,75 };
  test.disable_feature = disabled_features;
  test.test_name = "system_instruction_processor::tests::test_create_already_in_use";
  test.test_nonce  = 12;
  test.test_number = 1377;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 2;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111113VFfjzRrnYB87BtV4GuQkqx5Y8qsAsTd9Pd1",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1377_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1377_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1377_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1377_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111113VG55bQy5ptJa4hvCMvq6ASCovUNRpArjDwM",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1377_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1377_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1377_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1377_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1377_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1377_raw_sz;
  test.expected_result = -26;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1378(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 15,126,116,29,113,110,61,77,92,108,114,122,90,124,24,82,26,117,125,87,120,118,109,103,89,27,128,83,105,106,75,112,127,55,56,62,78,33,79,76,30,121,98,111,123,80,2 };
  test.disable_feature = disabled_features;
  test.test_name = "system_instruction_processor::tests::test_create_already_in_use";
  test.test_nonce  = 7;
  test.test_number = 1378;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 2;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111113VFfjzRrnYB87BtV4GuQkqx5Y8qsAsTd9Pd1",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1378_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1378_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1378_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1378_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111113VG55bQy5ptJa4hvCMvq6ASCovUNRpArjDwM",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "LbUiWL3xVV8hTFYBVdbTNrpDo41NKS6o3LHHuDzjfcY",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1378_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1378_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1378_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1378_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1378_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1378_raw_sz;
  test.expected_result = -26;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1379(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 15,126,116,29,113,110,61,77,92,108,114,122,90,124,24,82,26,117,125,87,120,118,109,103,89,27,128,83,105,106,75,112,127,55,56,62,78,33,79,76,30,121,98,111,123,80,2 };
  test.disable_feature = disabled_features;
  test.test_name = "system_instruction_processor::tests::test_create_already_in_use";
  test.test_nonce  = 15;
  test.test_number = 1379;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 2;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111113WhN3TESnTreVRze4Hzg38pA9mknm5LLUfQj",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1379_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1379_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1379_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1379_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111113WhmP4DZ5kZpxJp5CP26NTJHRZPJ223a4Vj5",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "LbUiWL3xVV8hTFYBVdbTNrpDo41NKS6o3LHHuDzjfcY",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1379_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1379_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1379_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1379_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1379_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1379_raw_sz;
  test.expected_result = -26;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1380(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 15,126,116,29,113,110,61,77,92,108,114,122,90,124,24,82,26,117,125,87,120,118,109,103,89,27,128,83,105,106,75,112,127,55,56,62,78,33,79,76,30,121,98,111,123,80,2 };
  test.disable_feature = disabled_features;
  test.test_name = "system_instruction_processor::tests::test_create_already_in_use";
  test.test_nonce  = 16;
  test.test_number = 1380;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 2;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111113WhN3TESnTreVRze4Hzg38pA9mknm5LLUfQj",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1380_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1380_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1380_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1380_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111113WhmP4DZ5kZpxJp5CP26NTJHRZPJ223a4Vj5",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1380_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1380_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1380_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1380_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1380_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1380_raw_sz;
  test.expected_result = -26;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1381(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 15,126,116,29,113,110,61,77,92,108,114,122,90,124,24,82,26,117,125,87,120,118,109,103,89,27,128,83,105,106,75,112,127,55,56,62,78,33,79,76,30,121,98,111,123,80,2 };
  test.disable_feature = disabled_features;
  test.test_name = "system_instruction_processor::tests::test_create_already_in_use";
  test.test_nonce  = 17;
  test.test_number = 1381;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 2;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111113WhN3TESnTreVRze4Hzg38pA9mknm5LLUfQj",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1381_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1381_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1381_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1381_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111113WhmP4DZ5kZpxJp5CP26NTJHRZPJ223a4Vj5",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1381_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1381_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1381_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1381_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1381_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1381_raw_sz;
  test.expected_result = -26;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1382(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 62,126,78,112,79,55,123,27,111,98,82,121,122,77,109,103,2,110,128,108,116,117,15,127,61,118,92,125,90,120,83,24,26,75,89,106,76,56,113,30,105,33,80,114,87,29,124 };
  test.disable_feature = disabled_features;
  test.test_name = "system_instruction_processor::tests::test_create_data_populated";
  test.test_nonce  = 22;
  test.test_number = 1382;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 2;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111113VN79eBbZ9Y1XCyRHfJ85wi5tiuwHxqNUigX",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1382_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1382_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1382_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1382_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111113VNWVFAhrSFBz5nrRkKYRGCDAWYSYuYc4Yzs",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1382_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1382_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1382_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1382_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1382_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1382_raw_sz;
  test.expected_result = -26;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1383(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 62,126,78,112,79,55,123,27,111,98,82,121,122,77,109,103,2,110,128,108,116,117,15,127,61,118,92,125,90,120,83,24,26,75,89,106,76,56,113,30,105,33,80,114,87,29,124 };
  test.disable_feature = disabled_features;
  test.test_name = "system_instruction_processor::tests::test_create_data_populated";
  test.test_nonce  = 11;
  test.test_number = 1383;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 2;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111113WiAifCfP3H1RBdWLU3WhmnQhM1oGxkoeL3R",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1383_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1383_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1383_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1383_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111113Wia4GBmgKzBt4SwUZ4w36GXy8eJXuU3EAMm",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1383_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1383_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1383_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1383_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1383_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1383_raw_sz;
  test.expected_result = -26;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1384(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 2,103,113,26,83,79,89,122,106,126,123,116,109,75,77,120,80,118,61,90,105,110,124,78,108,33,56,121,98,30,24,125,87,29,128,92,114,82,15,62,27,112,76,127,117,55,111 };
  test.disable_feature = disabled_features;
  test.test_name = "system_instruction_processor::tests::test_create_from_account_is_nonce_fail";
  test.test_nonce  = 9;
  test.test_number = 1384;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 2;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111113VHgS1MQGyj2RZyeki2WRSNhu4zPTb1o4ZCj",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 42UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1384_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1384_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1384_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1384_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111113VKh82GwmRGvjx4pT99c62oLG18ukJZxyinT",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1384_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1384_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1384_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1384_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1384_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1384_raw_sz;
  test.expected_result = -2;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1385(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 2,103,113,26,83,79,89,122,106,126,123,116,109,75,77,120,80,118,61,90,105,110,124,78,108,33,56,121,98,30,24,125,87,29,128,92,114,82,15,62,27,112,76,127,117,55,111 };
  test.disable_feature = disabled_features;
  test.test_name = "system_instruction_processor::tests::test_create_from_account_is_nonce_fail";
  test.test_nonce  = 8;
  test.test_number = 1385;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 2;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111113We9LdMaQABCnRTAwboKNaw9yUikhXeTozsy",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 42UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1385_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1385_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1385_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1385_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111113WeYgELghStPFJGc5gpjhuRHFGMFxUMhPqCK",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1385_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1385_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1385_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1385_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1385_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1385_raw_sz;
  test.expected_result = -2;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1386(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 109,83,24,114,128,113,126,105,89,103,116,106,82,27,118,33,92,2,76,29,15,120,122,62,80,121,98,87,26,90,111,123,30,79,78,61,110,55,127,108,75,125,112,77,117,56,124 };
  test.disable_feature = disabled_features;
  test.test_name = "system_instruction_processor::tests::test_create_negative_lamports";
  test.test_nonce  = 8;
  test.test_number = 1386;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 2;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111113VJV7DKcsZ9PMKcX2t5M65LxSeFPyUSGEDqR",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "1111113VJtSpJjAqrZpCRxAy6mRPq5iRsuER9Vp49m",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1386_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1386_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1386_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1386_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111113VKHnRHqU8ZkH5FPK48BkiKCzDWQVMrjPtU7",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1386_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1386_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1386_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1386_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1386_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1386_raw_sz;
  test.expected_result = -26;
  test.custom_err = 1;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1387(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 109,83,24,114,128,113,126,105,89,103,116,106,82,27,118,33,92,2,76,29,15,120,122,62,80,121,98,87,26,90,111,123,30,79,78,61,110,55,127,108,75,125,112,77,117,56,124 };
  test.disable_feature = disabled_features;
  test.test_name = "system_instruction_processor::tests::test_create_negative_lamports";
  test.test_nonce  = 14;
  test.test_number = 1387;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 2;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111113WfMMSJuJ2JkB3uUMrsaNYPXnqcGUMnAZVq1",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "1111113Wfkh3J1bK1vdviuVwtzhrsf4dEmjJVQ9L9M",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1387_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1387_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1387_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1387_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111113WgA2eH7tbj76oYLe2vR3BMnLQsGzFCdjATh",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1387_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1387_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1387_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1387_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1387_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1387_raw_sz;
  test.expected_result = -26;
  test.custom_err = 1;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1388(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 111,82,79,116,124,77,103,87,108,90,117,123,76,110,98,105,75,122,78,118,2,92,55,126,120,29,80,112,33,83,109,15,125,26,62,127,106,61,27,121,24,56,113,114,128,30,89 };
  test.disable_feature = disabled_features;
  test.test_name = "system_instruction_processor::tests::test_create_sysvar_invalid_id_with_feature";
  test.test_nonce  = 11;
  test.test_number = 1388;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 2;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111113VGURCQ5P7bV2wXMLSxFRUvL5i6sgkt6K4Fh",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 50UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1388_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1388_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1388_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1388_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111113VGskoPBgQJfVpLnUXyfkoQTMVjNwhbKtta3",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 50UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1388_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1388_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1388_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1388_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1388_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1388_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1389(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 111,82,79,116,124,77,103,87,108,90,117,123,76,110,98,105,75,122,78,118,2,92,55,126,120,29,80,112,33,83,109,15,125,26,62,127,106,61,27,121,24,56,113,114,128,30,89 };
  test.disable_feature = disabled_features;
  test.test_name = "system_instruction_processor::tests::test_create_sysvar_invalid_id_with_feature";
  test.test_nonce  = 18;
  test.test_number = 1389;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 2;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111113WkBQg8CsUpujZig2uAcNND34HAKZgJyZVd9",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 50UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1389_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1389_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1389_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1389_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111113WkakH7KAmY6CSY7AzC2hghAL4nppd2D9KwV",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 50UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1389_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1389_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1389_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1389_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1389_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1389_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1390(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 87,27,75,26,113,111,89,128,15,124,109,80,79,90,61,30,127,24,82,105,110,103,92,120,77,106,117,121,78,83,76,126,98,2,112,55,114,125,116,29,122,33,62,123,56,108,118 };
  test.disable_feature = disabled_features;
  test.test_name = "system_instruction_processor::tests::test_create_unsigned";
  test.test_nonce  = 15;
  test.test_number = 1390;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 2;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111113VHH6QNHyh1qxhADcd1667tadHMtCeJZUitP",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1390_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1390_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1390_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1390_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111113VJ5mcLWaGSCtSo5to3vkkrqArctiXj2ePX5",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1390_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1390_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1390_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1390_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1390_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1390_raw_sz;
  test.expected_result = -8;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1391(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 75,125,112,105,108,128,122,113,127,56,83,120,61,29,121,27,89,2,114,87,78,106,123,92,79,30,24,124,76,77,118,33,55,82,15,126,111,103,110,26,62,80,117,90,109,98,116 };
  test.disable_feature = disabled_features;
  test.test_name = "system_instruction_processor::tests::test_create_unsigned";
  test.test_nonce  = 17;
  test.test_number = 1391;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 2;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111113VHH6QNHyh1qxhADcd1667tadHMtCeJZUitP",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1391_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1391_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1391_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1391_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111113VJ5mcLWaGSCtSo5to3vkkrqArctiXj2ePX5",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1391_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1391_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1391_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1391_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1391_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1391_raw_sz;
  test.expected_result = -8;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1392(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 92,106,122,27,61,15,117,127,56,116,112,103,75,125,55,109,126,83,110,2,24,111,114,113,120,128,77,79,62,98,123,89,121,105,82,78,33,30,80,29,108,87,26,90,118,76,124 };
  test.disable_feature = disabled_features;
  test.test_name = "system_instruction_processor::tests::test_create_unsigned";
  test.test_nonce  = 16;
  test.test_number = 1392;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 2;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111113VHH6QNHyh1qxhADcd1667tadHMtCeJZUitP",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1392_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1392_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1392_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1392_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111113VJ5mcLWaGSCtSo5to3vkkrqArctiXj2ePX5",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1392_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1392_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1392_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1392_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1392_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1392_raw_sz;
  test.expected_result = -8;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1393(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 92,106,122,27,61,15,117,127,56,116,112,103,75,125,55,109,126,83,110,2,24,111,114,113,120,128,77,79,62,98,123,89,121,105,82,78,33,30,80,29,108,87,26,90,118,76,124 };
  test.disable_feature = disabled_features;
  test.test_name = "system_instruction_processor::tests::test_create_unsigned";
  test.test_nonce  = 10;
  test.test_number = 1393;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 2;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111113WgZNFGEBtSHZgMmn7wqNVqucCVnFBusJzn3",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1393_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1393_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1393_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1393_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111113WgxhrFLVB9U2ZBCvCyFhpL2sz8HW8d6tq6P",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1393_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1393_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1393_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1393_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1393_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1393_raw_sz;
  test.expected_result = -8;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1394(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 92,106,122,27,61,15,117,127,56,116,112,103,75,125,55,109,126,83,110,2,24,111,114,113,120,128,77,79,62,98,123,89,121,105,82,78,33,30,80,29,108,87,26,90,118,76,124 };
  test.disable_feature = disabled_features;
  test.test_name = "system_instruction_processor::tests::test_create_unsigned";
  test.test_nonce  = 12;
  test.test_number = 1394;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 2;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111113WgZNFGEBtSHZgMmn7wqNVqucCVnFBusJzn3",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1394_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1394_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1394_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1394_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111113WgxhrFLVB9U2ZBCvCyFhpL2sz8HW8d6tq6P",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1394_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1394_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1394_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1394_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1394_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1394_raw_sz;
  test.expected_result = -8;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1395(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 92,106,122,27,61,15,117,127,56,116,112,103,75,125,55,109,126,83,110,2,24,111,114,113,120,128,77,79,62,98,123,89,121,105,82,78,33,30,80,29,108,87,26,90,118,76,124 };
  test.disable_feature = disabled_features;
  test.test_name = "system_instruction_processor::tests::test_create_unsigned";
  test.test_nonce  = 9;
  test.test_number = 1395;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 2;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111113WgZNFGEBtSHZgMmn7wqNVqucCVnFBusJzn3",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1395_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1395_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1395_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1395_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111113WgxhrFLVB9U2ZBCvCyFhpL2sz8HW8d6tq6P",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1395_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1395_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1395_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1395_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1395_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1395_raw_sz;
  test.expected_result = -8;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1396(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 2,123,125,110,87,61,112,98,116,30,92,29,127,124,77,122,89,75,126,121,33,113,109,82,106,15,26,56,128,27,90,79,120,103,62,76,114,80,108,118,78,24,117,55,111,105,83 };
  test.disable_feature = disabled_features;
  test.test_name = "system_instruction_processor::tests::test_create_with_zero_lamports";
  test.test_nonce  = 13;
  test.test_number = 1396;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 2;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111113VLVoEFAMzhHfhhgjKCSkfmaoaPvGBzS9PR9",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "1111113VLu8qEGfHQU8aX7sQDs5zFi5N2RX8hfjDjV",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1396_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1396_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1396_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1396_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111113VMJUSDNxa7ebTLZ1VFHRJjqM9evn5QuK43q",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1396_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1396_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1396_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1396_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1396_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1396_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1397(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 2,123,125,110,87,61,112,98,116,30,92,29,127,124,77,122,89,75,126,121,33,113,109,82,106,15,26,56,128,27,90,79,120,103,62,76,114,80,108,118,78,24,117,55,111,105,83 };
  test.disable_feature = disabled_features;
  test.test_name = "system_instruction_processor::tests::test_create_with_zero_lamports";
  test.test_nonce  = 13;
  test.test_number = 1397;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 2;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111113WiyPsAsychNLwGNce6MNQkfEvGonrBGozg7",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "1111113WjNjU9zGuQYop5okj7mhjEnWhuK3ntWPpzT",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1397_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1397_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1397_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1397_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111113Wjn5596aC7jGguEtp9C33iunVXpJjbjyfJo",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1397_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1397_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1397_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1397_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1397_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1397_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1398(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 118,110,78,125,111,105,113,128,24,2,82,55,103,27,56,62,120,126,79,29,75,127,83,123,122,114,106,61,108,117,90,89,87,77,116,109,26,121,98,33,124,76,80,30,92,15,112 };
  test.disable_feature = disabled_features;
  test.test_name = "system_instruction_processor::tests::test_nonce_account_upgrade_check_owner";
  test.test_nonce  = 18;
  test.test_number = 1398;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 1;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111113VRjC53aEjvdh6LKYSWu5p5DLoaUcTEUjDXd",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "1111113VS8Xg2gY2dp9y9kgXYKR8ZLcbCysPwiK3qy",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1000000UL;
  test_acc->result_lamports = 1000000UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1398_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1398_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1398_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1398_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1398_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1398_raw_sz;
  test.expected_result = -47;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1399(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 118,110,78,125,111,105,113,128,24,2,82,55,103,27,56,62,120,126,79,29,75,127,83,123,122,114,106,61,108,117,90,89,87,77,116,109,26,121,98,33,124,76,80,30,92,15,112 };
  test.disable_feature = disabled_features;
  test.test_name = "system_instruction_processor::tests::test_nonce_account_upgrade_check_owner";
  test.test_nonce  = 24;
  test.test_number = 1399;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 1;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111113XVdupTw4bWPnC3V6FovLnaaTF8oPZ6GZTnP",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "1111113XW3FRT3MtDaF4rvELqLg74hj2mJeVoW9J6j",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1000000UL;
  test_acc->result_lamports = 1000000UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1399_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1399_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1399_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1399_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1399_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1399_raw_sz;
  test.expected_result = -47;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
