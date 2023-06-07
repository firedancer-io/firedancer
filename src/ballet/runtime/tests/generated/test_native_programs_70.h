#include "../fd_tests.h"
int test_1750(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 30,114,2,106,27,120,110,123,56,103,111,83,109,124,118,15,82,61,76,75,77,26,108,125,113,78,29,126,90,117,55,33,62,92,105,79,128,122,127,24,87,116,80,112,98,121,89 };
  test.disable_feature = disabled_features;
  test.test_name = "vote_processor::tests::test_withdrawer_base_key_can_authorize_new_voter";
  test.test_nonce  = 31;
  test.test_number = 1750;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111111EH9uVaqWRxHuzJbroqzX18yxmeW8TjFVSP",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1750_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1750_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1750_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1750_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1750_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1750_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1750_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1750_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111FVAiSujNZVgYSc27t6zUTWoKfAGxbRzzPR",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1750_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1750_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1750_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1750_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1750_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1750_raw_sz;
  test.expected_result = -8;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1751(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 108,116,89,103,87,98,83,112,110,124,80,15,90,79,75,123,92,122,76,29,106,111,2,109,126,127,121,24,30,33,56,125,82,62,55,78,105,26,27,120,77,114,113,117,118,61,128 };
  test.disable_feature = disabled_features;
  test.test_name = "vote_processor::tests::test_withdrawer_base_key_can_authorize_new_voter";
  test.test_nonce  = 57;
  test.test_number = 1751;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111111EH9uVaqWRxHuzJbroqzX18yxmeW8TjFVSP",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1751_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1751_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1751_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1751_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1751_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1751_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1751_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1751_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111FVAiSujNZVgYSc27t6zUTWoKfAGxbRzzPR",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1751_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1751_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1751_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1751_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1751_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1751_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1752(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 128,2,122,124,77,112,114,109,15,90,26,24,89,82,98,113,83,61,76,120,87,30,56,116,106,80,33,92,78,110,103,111,108,118,121,75,126,62,79,27,123,117,55,127,125,29,105 };
  test.disable_feature = disabled_features;
  test.test_name = "vote_processor::tests::test_withdrawer_base_key_can_authorize_new_voter";
  test.test_nonce  = 17;
  test.test_number = 1752;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111111EH9uVaqWRxHuzJbroqzX18yxmeW8TjFVSP",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1752_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1752_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1752_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1752_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1752_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1752_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1752_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1752_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111FVAiSujNZVgYSc27t6zUTWoKfAGxbRzzPR",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1752_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1752_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1752_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1752_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1752_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1752_raw_sz;
  test.expected_result = -8;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1753(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 129;
  uchar disabled_features[] = { 0,120,71,4,5,53,113,28,89,63,99,82,21,39,19,32,93,33,8,88,18,85,29,73,102,124,40,122,11,65,47,117,125,104,105,58,114,91,1,12,2,36,55,42,72,52,60,86,75,74,110,92,49,30,94,3,70,41,57,119,64,22,107,31,44,24,112,37,43,83,123,109,96,128,6,79,87,103,46,68,69,15,66,98,9,84,100,81,59,25,111,45,16,77,101,116,35,78,26,80,10,14,61,95,62,90,51,48,97,38,108,56,76,126,54,13,67,50,115,121,7,27,17,34,23,106,118,20,127 };
  test.disable_feature = disabled_features;
  test.test_name = "vote_processor::tests::test_withdrawer_base_key_can_authorize_new_voter";
  test.test_nonce  = 70;
  test.test_number = 1753;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111111EH9uVaqWRxHuzJbroqzX18yxmeW8TjFVSP",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1753_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1753_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1753_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1753_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1753_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1753_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1753_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1753_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111FVAiSujNZVgYSc27t6zUTWoKfAGxbRzzPR",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1753_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1753_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1753_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1753_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1753_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1753_raw_sz;
  test.expected_result = -3;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1754(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 124,80,125,121,55,118,109,90,77,127,111,2,114,76,108,110,116,117,92,89,122,15,123,113,61,30,83,105,33,62,78,29,27,128,112,98,75,24,120,79,56,103,106,87,126,26,82 };
  test.disable_feature = disabled_features;
  test.test_name = "vote_processor::tests::test_withdrawer_base_key_can_authorize_new_voter";
  test.test_nonce  = 45;
  test.test_number = 1754;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111111EH9uVaqWRxHuzJbroqzX18yxmeW8TjFVSP",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1754_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1754_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1754_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1754_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1754_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1754_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1754_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1754_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111FVAiSujNZVgYSc27t6zUTWoKfAGxbRzzPR",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1754_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1754_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1754_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1754_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1754_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1754_raw_sz;
  test.expected_result = -8;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1755(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 124,80,125,121,55,118,109,90,77,127,111,2,114,76,108,110,116,117,92,89,122,15,123,113,61,30,83,105,33,62,78,29,27,128,112,98,75,24,120,79,56,103,106,87,126,26,82 };
  test.disable_feature = disabled_features;
  test.test_name = "vote_processor::tests::test_withdrawer_base_key_can_authorize_new_voter";
  test.test_nonce  = 56;
  test.test_number = 1755;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111111D596YFweJQuHY1BbjazZYmAbt8jJL2VzVM",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1755_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1755_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1755_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1755_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1755_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1755_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1755_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1755_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111EH9uVaqWRxHuzJbroqzX18yxmeW8TjFVSP",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1755_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1755_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1755_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1755_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1755_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1755_raw_sz;
  test.expected_result = -8;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1756(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 110,62,108,61,75,87,105,15,55,83,123,118,126,33,128,114,122,77,120,92,27,116,103,89,80,82,26,79,106,124,78,113,76,127,24,56,30,112,29,98,111,125,121,90,109,117,2 };
  test.disable_feature = disabled_features;
  test.test_name = "vote_processor::tests::test_withdrawer_base_key_can_authorize_new_withdrawer_checked";
  test.test_nonce  = 43;
  test.test_number = 1756;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 4;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111111M7uAERuQW2AotfyLDyewFGcLUDtAYiAepF",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1756_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1756_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1756_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1756_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1756_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1756_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1756_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1756_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111NKuyBkoGdZZSLyPbJEetheRhMjezgQv9mH",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1756_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1756_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1756_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1756_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111RwxQ3jUs2BjKhseNX1em4msn2GyV5XAecP",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1756_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1756_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1756_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1756_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1756_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1756_raw_sz;
  test.expected_result = -8;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1757(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 116,90,75,109,114,27,61,106,83,2,126,76,78,77,105,33,82,122,128,113,118,29,111,15,127,24,62,112,103,121,26,123,125,30,55,120,80,89,87,117,108,98,92,124,110,79,56 };
  test.disable_feature = disabled_features;
  test.test_name = "vote_processor::tests::test_withdrawer_base_key_can_authorize_new_withdrawer_checked";
  test.test_nonce  = 66;
  test.test_number = 1757;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 4;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111111M7uAERuQW2AotfyLDyewFGcLUDtAYiAepF",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1757_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1757_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1757_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1757_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1757_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1757_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1757_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1757_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111NKuyBkoGdZZSLyPbJEetheRhMjezgQv9mH",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1757_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1757_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1757_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1757_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111RwxQ3jUs2BjKhseNX1em4msn2GyV5XAecP",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1757_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1757_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1757_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1757_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1757_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1757_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1758(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 116,56,122,112,2,127,124,76,128,113,83,33,106,77,105,103,79,98,55,114,26,15,62,82,78,110,117,109,121,87,125,30,61,90,29,80,89,75,120,27,108,123,126,24,92,111,118 };
  test.disable_feature = disabled_features;
  test.test_name = "vote_processor::tests::test_withdrawer_base_key_can_authorize_new_withdrawer_checked";
  test.test_nonce  = 29;
  test.test_number = 1758;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 4;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111111M7uAERuQW2AotfyLDyewFGcLUDtAYiAepF",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1758_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1758_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1758_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1758_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1758_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1758_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1758_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1758_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111NKuyBkoGdZZSLyPbJEetheRhMjezgQv9mH",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1758_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1758_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1758_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1758_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111RwxQ3jUs2BjKhseNX1em4msn2GyV5XAecP",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1758_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1758_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1758_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1758_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1758_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1758_raw_sz;
  test.expected_result = -8;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1759(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 129;
  uchar disabled_features[] = { 76,122,18,33,40,2,126,39,89,110,38,66,43,8,26,108,49,94,7,52,4,106,55,60,44,30,78,19,121,112,91,35,36,105,95,123,47,87,22,84,13,58,28,114,100,37,124,71,80,41,1,117,27,109,53,50,83,63,24,11,82,99,10,118,79,81,9,34,128,93,15,16,17,127,56,12,25,116,20,69,72,5,51,67,46,104,6,64,74,101,73,120,45,111,86,90,14,115,102,96,42,98,23,62,68,57,88,3,31,48,103,59,29,119,21,32,107,70,113,125,85,92,75,54,97,0,77,61,65 };
  test.disable_feature = disabled_features;
  test.test_name = "vote_processor::tests::test_withdrawer_base_key_can_authorize_new_withdrawer_checked";
  test.test_nonce  = 74;
  test.test_number = 1759;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 4;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111111M7uAERuQW2AotfyLDyewFGcLUDtAYiAepF",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1759_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1759_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1759_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1759_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1759_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1759_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1759_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1759_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111NKuyBkoGdZZSLyPbJEetheRhMjezgQv9mH",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1759_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1759_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1759_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1759_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111RwxQ3jUs2BjKhseNX1em4msn2GyV5XAecP",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1759_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1759_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1759_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1759_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1759_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1759_raw_sz;
  test.expected_result = -3;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1760(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 109,29,78,30,15,56,61,127,27,118,80,108,87,79,105,128,121,83,114,26,125,98,92,110,82,62,126,90,106,116,76,55,75,122,77,89,103,113,112,123,33,2,120,117,124,24,111 };
  test.disable_feature = disabled_features;
  test.test_name = "vote_processor::tests::test_withdrawer_base_key_can_authorize_new_withdrawer_checked";
  test.test_nonce  = 18;
  test.test_number = 1760;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 4;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111111M7uAERuQW2AotfyLDyewFGcLUDtAYiAepF",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1760_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1760_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1760_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1760_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1760_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1760_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1760_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1760_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111NKuyBkoGdZZSLyPbJEetheRhMjezgQv9mH",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1760_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1760_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1760_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1760_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111RwxQ3jUs2BjKhseNX1em4msn2GyV5XAecP",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1760_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1760_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1760_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1760_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1760_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1760_raw_sz;
  test.expected_result = -8;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1761(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 109,29,78,30,15,56,61,127,27,118,80,108,87,79,105,128,121,83,114,26,125,98,92,110,82,62,126,90,106,116,76,55,75,122,77,89,103,113,112,123,33,2,120,117,124,24,111 };
  test.disable_feature = disabled_features;
  test.test_name = "vote_processor::tests::test_withdrawer_base_key_can_authorize_new_withdrawer_checked";
  test.test_nonce  = 40;
  test.test_number = 1761;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 4;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111111MXEmDYChDCdgi77RFPzFjPt86j97FwkV8b",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1761_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1761_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1761_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1761_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1761_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1761_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1761_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1761_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111NjFaAs6ZLk2KAQXgKezDBmhUzEuwPeVz5d",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1761_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1761_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1761_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1761_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111RwxQ3jUs2BjKhseNX1em4msn2GyV5XAecP",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1761_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1761_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1761_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1761_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1761_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1761_raw_sz;
  test.expected_result = -8;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1762(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 129;
  uchar disabled_features[] = { 59,32,43,107,6,85,35,121,118,77,21,108,47,61,37,99,42,128,1,104,110,14,97,24,75,9,115,19,69,112,119,62,57,64,23,45,46,74,8,92,76,73,72,53,98,13,93,80,126,78,4,55,71,67,81,82,27,36,65,111,44,86,123,12,106,120,26,40,10,11,30,49,109,16,34,90,70,48,117,114,100,5,116,125,51,96,58,94,91,17,38,22,60,33,113,105,0,66,83,54,63,29,25,127,52,103,50,7,2,15,41,95,20,18,84,39,102,87,28,122,101,124,68,79,89,3,56,88,31 };
  test.disable_feature = disabled_features;
  test.test_name = "vote_processor::tests::test_withdrawer_base_key_can_authorize_new_withdrawer_checked";
  test.test_nonce  = 70;
  test.test_number = 1762;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 4;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111111MXEmDYChDCdgi77RFPzFjPt86j97FwkV8b",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1762_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1762_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1762_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1762_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1762_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1762_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1762_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1762_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111NjFaAs6ZLk2KAQXgKezDBmhUzEuwPeVz5d",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1762_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1762_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1762_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1762_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111RwxQ3jUs2BjKhseNX1em4msn2GyV5XAecP",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1762_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1762_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1762_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1762_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1762_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1762_raw_sz;
  test.expected_result = -3;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1763(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 59,32,43,107,6,85,35,121,118,77,21,108,47,61,37,99,42,128,1,104,110,14,97,24,75,9,115,19,69,112,119,62,57,64,23,45,46,74,8,92,76,73,72,53,98,13,93,80,126,78,4,55,71,67,81,82,27,36,65,111,44,86,123,12,106,120,26,40,10,11,30,49,109,16,34,90,70,48,117,114,100,5,116,125,51,96,58,94,91,17,38,22,60,33,113,105,0,66,83,54,63,29,25,127,52,103,50,7,2,15,41,95,20,18,84,39,102,87,28,122,101,124,68,79,89,3,56,88,31 };
  test.disable_feature = disabled_features;
  test.test_name = "vote_processor::tests::test_withdrawer_base_key_can_authorize_new_withdrawer_checked";
  test.test_nonce  = 15;
  test.test_number = 1763;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 4;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111111MXEmDYChDCdgi77RFPzFjPt86j97FwkV8b",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1763_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1763_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1763_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1763_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1763_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1763_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1763_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1763_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111NjFaAs6ZLk2KAQXgKezDBmhUzEuwPeVz5d",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1763_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1763_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1763_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1763_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111RwxQ3jUs2BjKhseNX1em4msn2GyV5XAecP",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1763_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1763_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1763_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1763_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1763_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1763_raw_sz;
  test.expected_result = -8;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1764(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 59,32,43,107,6,85,35,121,118,77,21,108,47,61,37,99,42,128,1,104,110,14,97,24,75,9,115,19,69,112,119,62,57,64,23,45,46,74,8,92,76,73,72,53,98,13,93,80,126,78,4,55,71,67,81,82,27,36,65,111,44,86,123,12,106,120,26,40,10,11,30,49,109,16,34,90,70,48,117,114,100,5,116,125,51,96,58,94,91,17,38,22,60,33,113,105,0,66,83,54,63,29,25,127,52,103,50,7,2,15,41,95,20,18,84,39,102,87,28,122,101,124,68,79,89,3,56,88,31 };
  test.disable_feature = disabled_features;
  test.test_name = "vote_processor::tests::test_withdrawer_base_key_can_authorize_new_withdrawer_checked";
  test.test_nonce  = 27;
  test.test_number = 1764;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 4;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111111MXEmDYChDCdgi77RFPzFjPt86j97FwkV8b",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1764_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1764_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1764_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1764_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1764_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1764_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1764_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1764_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111NjFaAs6ZLk2KAQXgKezDBmhUzEuwPeVz5d",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1764_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1764_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1764_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1764_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111RwxQ3jUs2BjKhseNX1em4msn2GyV5XAecP",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1764_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1764_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1764_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1764_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1764_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1764_raw_sz;
  test.expected_result = -8;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1765(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 59,32,43,107,6,85,35,121,118,77,21,108,47,61,37,99,42,128,1,104,110,14,97,24,75,9,115,19,69,112,119,62,57,64,23,45,46,74,8,92,76,73,72,53,98,13,93,80,126,78,4,55,71,67,81,82,27,36,65,111,44,86,123,12,106,120,26,40,10,11,30,49,109,16,34,90,70,48,117,114,100,5,116,125,51,96,58,94,91,17,38,22,60,33,113,105,0,66,83,54,63,29,25,127,52,103,50,7,2,15,41,95,20,18,84,39,102,87,28,122,101,124,68,79,89,3,56,88,31 };
  test.disable_feature = disabled_features;
  test.test_name = "vote_processor::tests::test_withdrawer_base_key_can_authorize_new_withdrawer_checked";
  test.test_nonce  = 62;
  test.test_number = 1765;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 4;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111111MXEmDYChDCdgi77RFPzFjPt86j97FwkV8b",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1765_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1765_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1765_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1765_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1765_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1765_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1765_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1765_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111NjFaAs6ZLk2KAQXgKezDBmhUzEuwPeVz5d",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1765_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1765_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1765_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1765_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111RwxQ3jUs2BjKhseNX1em4msn2GyV5XAecP",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1765_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1765_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1765_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1765_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1765_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1765_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1766(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 109,126,103,118,2,79,106,90,114,105,122,77,83,62,56,87,112,111,80,33,108,123,30,75,27,92,117,120,89,110,121,113,127,26,24,29,125,116,55,61,15,124,82,128,98,78,76 };
  test.disable_feature = disabled_features;
  test.test_name = "vote_processor::tests::test_withdrawer_base_key_can_authorize_new_withdrawer_checked";
  test.test_nonce  = 55;
  test.test_number = 1766;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 4;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111111M7uAERuQW2AotfyLDyewFGcLUDtAYiAepF",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1766_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1766_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1766_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1766_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1766_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1766_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1766_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1766_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111NKuyBkoGdZZSLyPbJEetheRhMjezgQv9mH",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1766_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1766_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1766_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1766_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111RwxQ3jUs2BjKhseNX1em4msn2GyV5XAecP",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1766_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1766_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1766_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1766_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1766_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1766_raw_sz;
  test.expected_result = -8;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1767(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 109,126,103,118,2,79,106,90,114,105,122,77,83,62,56,87,112,111,80,33,108,123,30,75,27,92,117,120,89,110,121,113,127,26,24,29,125,116,55,61,15,124,82,128,98,78,76 };
  test.disable_feature = disabled_features;
  test.test_name = "vote_processor::tests::test_withdrawer_base_key_can_authorize_new_withdrawer_checked";
  test.test_nonce  = 51;
  test.test_number = 1767;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 4;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111111MXEmDYChDCdgi77RFPzFjPt86j97FwkV8b",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1767_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1767_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1767_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1767_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1767_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1767_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1767_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1767_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111NjFaAs6ZLk2KAQXgKezDBmhUzEuwPeVz5d",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1767_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1767_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1767_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1767_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111RwxQ3jUs2BjKhseNX1em4msn2GyV5XAecP",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1767_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1767_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1767_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1767_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1767_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1767_raw_sz;
  test.expected_result = -8;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1768(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 109,126,103,118,2,79,106,90,114,105,122,77,83,62,56,87,112,111,80,33,108,123,30,75,27,92,117,120,89,110,121,113,127,26,24,29,125,116,55,61,15,124,82,128,98,78,76 };
  test.disable_feature = disabled_features;
  test.test_name = "vote_processor::tests::test_withdrawer_base_key_can_authorize_new_withdrawer";
  test.test_nonce  = 28;
  test.test_number = 1768;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111111JJXwLfpPXkvgAdzj43KhrPhq4h5Za55pbq",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1768_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1768_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1768_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1768_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1768_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1768_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1768_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1768_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111KWYkHziFfJKJcwQz8JKfJmXBxCrPhmqKYs",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1768_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1768_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1768_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1768_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1768_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1768_raw_sz;
  test.expected_result = -8;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1769(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 129;
  uchar disabled_features[] = { 70,24,85,6,103,32,61,42,86,82,0,76,99,71,3,120,56,69,34,1,75,33,84,22,25,15,14,115,49,73,66,40,101,35,113,114,7,29,2,20,80,39,8,11,122,78,44,110,46,23,27,92,65,57,97,68,64,123,119,41,96,112,48,91,19,100,21,109,102,59,9,89,51,72,77,83,98,111,53,50,37,43,127,67,93,38,17,81,62,95,104,60,126,118,13,45,10,124,116,52,16,47,36,30,108,121,12,55,79,58,88,74,18,4,63,54,87,106,5,125,105,31,107,28,128,26,90,117,94 };
  test.disable_feature = disabled_features;
  test.test_name = "vote_processor::tests::test_withdrawer_base_key_can_authorize_new_withdrawer";
  test.test_nonce  = 64;
  test.test_number = 1769;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111111JJXwLfpPXkvgAdzj43KhrPhq4h5Za55pbq",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1769_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1769_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1769_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1769_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1769_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1769_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1769_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1769_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111KWYkHziFfJKJcwQz8JKfJmXBxCrPhmqKYs",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1769_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1769_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1769_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1769_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1769_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1769_raw_sz;
  test.expected_result = -3;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1770(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 70,24,85,6,103,32,61,42,86,82,0,76,99,71,3,120,56,69,34,1,75,33,84,22,25,15,14,115,49,73,66,40,101,35,113,114,7,29,2,20,80,39,8,11,122,78,44,110,46,23,27,92,65,57,97,68,64,123,119,41,96,112,48,91,19,100,21,109,102,59,9,89,51,72,77,83,98,111,53,50,37,43,127,67,93,38,17,81,62,95,104,60,126,118,13,45,10,124,116,52,16,47,36,30,108,121,12,55,79,58,88,74,18,4,63,54,87,106,5,125,105,31,107,28,128,26,90,117,94 };
  test.disable_feature = disabled_features;
  test.test_name = "vote_processor::tests::test_withdrawer_base_key_can_authorize_new_withdrawer";
  test.test_nonce  = 16;
  test.test_number = 1770;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111111JJXwLfpPXkvgAdzj43KhrPhq4h5Za55pbq",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1770_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1770_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1770_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1770_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1770_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1770_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1770_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1770_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111KWYkHziFfJKJcwQz8JKfJmXBxCrPhmqKYs",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1770_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1770_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1770_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1770_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1770_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1770_raw_sz;
  test.expected_result = -8;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1771(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 70,24,85,6,103,32,61,42,86,82,0,76,99,71,3,120,56,69,34,1,75,33,84,22,25,15,14,115,49,73,66,40,101,35,113,114,7,29,2,20,80,39,8,11,122,78,44,110,46,23,27,92,65,57,97,68,64,123,119,41,96,112,48,91,19,100,21,109,102,59,9,89,51,72,77,83,98,111,53,50,37,43,127,67,93,38,17,81,62,95,104,60,126,118,13,45,10,124,116,52,16,47,36,30,108,121,12,55,79,58,88,74,18,4,63,54,87,106,5,125,105,31,107,28,128,26,90,117,94 };
  test.disable_feature = disabled_features;
  test.test_name = "vote_processor::tests::test_withdrawer_base_key_can_authorize_new_withdrawer";
  test.test_nonce  = 52;
  test.test_number = 1771;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111111JJXwLfpPXkvgAdzj43KhrPhq4h5Za55pbq",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1771_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1771_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1771_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1771_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1771_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1771_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1771_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1771_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111KWYkHziFfJKJcwQz8JKfJmXBxCrPhmqKYs",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1771_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1771_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1771_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1771_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1771_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1771_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1772(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 110,109,2,106,78,82,108,30,112,116,61,75,127,103,105,98,76,113,118,79,126,92,128,56,87,123,111,114,121,80,89,24,90,29,117,55,125,27,62,33,122,15,124,77,120,26,83 };
  test.disable_feature = disabled_features;
  test.test_name = "vote_processor::tests::test_withdrawer_base_key_can_authorize_new_withdrawer";
  test.test_nonce  = 28;
  test.test_number = 1772;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111111JhsYKn7gEwPYz58p5Tf2LWychCLWHJfevB",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1772_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1772_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1772_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1772_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1772_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1772_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1772_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1772_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111KutMH71YNUnBSNZ59ieyntnyai7LR1R9sD",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1772_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1772_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1772_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1772_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1772_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1772_raw_sz;
  test.expected_result = -8;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1773(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 113,80,98,77,126,112,108,116,109,103,26,79,27,76,75,122,120,117,90,111,56,106,124,110,2,62,118,127,92,61,123,33,128,83,114,55,125,24,87,121,105,29,78,89,30,82,15 };
  test.disable_feature = disabled_features;
  test.test_name = "vote_processor::tests::test_withdrawer_base_key_can_authorize_new_withdrawer";
  test.test_nonce  = 16;
  test.test_number = 1773;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111111JhsYKn7gEwPYz58p5Tf2LWychCLWHJfevB",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1773_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1773_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1773_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1773_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1773_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1773_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1773_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1773_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111KutMH71YNUnBSNZ59ieyntnyai7LR1R9sD",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1773_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1773_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1773_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1773_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1773_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1773_raw_sz;
  test.expected_result = -8;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1774(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 129;
  uchar disabled_features[] = { 20,121,9,46,60,126,21,106,91,81,58,14,11,68,10,35,85,79,38,24,119,30,77,49,64,87,94,101,22,117,86,34,109,44,50,122,67,120,3,80,23,97,7,16,83,13,12,74,43,19,54,78,111,47,123,72,82,103,18,70,27,26,37,61,116,36,100,110,4,93,29,40,66,89,5,105,0,8,124,33,48,57,99,118,32,53,92,90,71,41,88,1,114,115,45,98,65,25,6,125,2,39,69,15,63,127,128,56,112,96,95,104,113,28,51,62,52,108,31,75,17,73,76,102,84,42,107,55,59 };
  test.disable_feature = disabled_features;
  test.test_name = "vote_processor::tests::test_withdrawer_base_key_can_authorize_new_withdrawer";
  test.test_nonce  = 67;
  test.test_number = 1774;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111111JhsYKn7gEwPYz58p5Tf2LWychCLWHJfevB",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1774_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1774_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1774_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1774_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1774_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1774_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1774_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1774_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111KutMH71YNUnBSNZ59ieyntnyai7LR1R9sD",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1774_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1774_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1774_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1774_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1774_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1774_raw_sz;
  test.expected_result = -3;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
