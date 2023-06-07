#include "../fd_tests.h"
int test_975(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 92,126,124,26,56,62,121,109,80,112,125,105,30,128,33,2,116,90,127,113,79,82,114,111,77,87,123,61,122,55,103,106,110,15,29,108,118,83,78,117,120,75,98,89,24,27,76 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_stake_checked_instructions::new_behavior";
  test.test_nonce  = 278;
  test.test_number = 975;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 4;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111111EH9uVaqWRxHuzJbroqzX18yxmeW8TjFVSP",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 42UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_975_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_975_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_975_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_975_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_975_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_975_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_975_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_975_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111GHqvR8KwyrcJ5UJHvwf7RmLtvAnr1uAf27",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "1111111GhBXQEdEh35AtuSNxMzRutcgYg3nj8kVLT",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_975_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_975_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_975_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_975_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111EgVWUh8o98knojjwqGKqVGFkQ9m5AxqKkj",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "1111111H6X8PLvXQDY3iLaTynKkQ1tUBBJjSNLKeo",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_975_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_975_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_975_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_975_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_975_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_975_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_976(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 92,126,124,26,56,62,121,109,80,112,125,105,30,128,33,2,116,90,127,113,79,82,114,111,77,87,123,61,122,55,103,106,110,15,29,108,118,83,78,117,120,75,98,89,24,27,76 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_stake_checked_instructions::new_behavior";
  test.test_nonce  = 250;
  test.test_number = 976;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 4;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111111EH9uVaqWRxHuzJbroqzX18yxmeW8TjFVSP",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_976_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_976_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_976_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_976_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_976_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_976_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_976_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_976_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111HVrjNTDp7PzvXmiZ1Cf4t9AFogZg9bv9y9",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_976_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_976_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_976_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_976_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111FtWKS22fGg9RG3ACuXKnwe57HfXuJfaphm",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_976_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_976_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_976_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_976_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_976_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_976_raw_sz;
  test.expected_result = -8;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_977(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 92,126,124,26,56,62,121,109,80,112,125,105,30,128,33,2,116,90,127,113,79,82,114,111,77,87,123,61,122,55,103,106,110,15,29,108,118,83,78,117,120,75,98,89,24,27,76 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_stake_checked_instructions::new_behavior";
  test.test_nonce  = 319;
  test.test_number = 977;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 4;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111111EH9uVaqWRxHuzJbroqzX18yxmeW8TjFVSP",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 42UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_977_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_977_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_977_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_977_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_977_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_977_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_977_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_977_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111HVrjNTDp7PzvXmiZ1Cf4t9AFogZg9bv9y9",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "1111111HuCLMZX6paToMCre2czPNGS3SBpcrqVzHV",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_977_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_977_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_977_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_977_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111FtWKS22fGg9RG3ACuXKnwe57HfXuJfaphm",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "1111111JJXwLfpPXkvgAdzj43KhrPhq4h5Za55pbq",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_977_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_977_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_977_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_977_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_977_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_977_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_978(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 92,126,124,26,56,62,121,109,80,112,125,105,30,128,33,2,116,90,127,113,79,82,114,111,77,87,123,61,122,55,103,106,110,15,29,108,118,83,78,117,120,75,98,89,24,27,76 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_stake_checked_instructions::new_behavior";
  test.test_nonce  = 260;
  test.test_number = 978;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 4;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111111EH9uVaqWRxHuzJbroqzX18yxmeW8TjFVSP",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_978_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_978_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_978_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_978_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111FVAiSujNZVgYSc27t6zUTWoKfAGxbRzzPR",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_978_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_978_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_978_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_978_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_978_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_978_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_978_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_978_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111GHqvR8KwyrcJ5UJHvwf7RmLtvAnr1uAf27",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_978_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_978_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_978_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_978_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_978_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_978_raw_sz;
  test.expected_result = -8;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_979(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 92,126,124,26,56,62,121,109,80,112,125,105,30,128,33,2,116,90,127,113,79,82,114,111,77,87,123,61,122,55,103,106,110,15,29,108,118,83,78,117,120,75,98,89,24,27,76 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_stake_checked_instructions::new_behavior";
  test.test_nonce  = 300;
  test.test_number = 979;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 4;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111111EH9uVaqWRxHuzJbroqzX18yxmeW8TjFVSP",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 42UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_979_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_979_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_979_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_979_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_979_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_979_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_979_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_979_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111GHqvR8KwyrcJ5UJHvwf7RmLtvAnr1uAf27",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "1111111GhBXQEdEh35AtuSNxMzRutcgYg3nj8kVLT",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_979_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_979_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_979_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_979_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111FVAiSujNZVgYSc27t6zUTWoKfAGxbRzzPR",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "1111111H6X8PLvXQDY3iLaTynKkQ1tUBBJjSNLKeo",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_979_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_979_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_979_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_979_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_979_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_979_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_980(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 92,126,124,26,56,62,121,109,80,112,125,105,30,128,33,2,116,90,127,113,79,82,114,111,77,87,123,61,122,55,103,106,110,15,29,108,118,83,78,117,120,75,98,89,24,27,76 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_stake_checked_instructions::new_behavior";
  test.test_nonce  = 307;
  test.test_number = 980;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 4;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111111g2nWWXuwsVwzL3XQNhJv3AQK3vzVxiaogT",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_980_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_980_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_980_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_980_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111EgVWUh8o98knojjwqGKqVGFkQ9m5AxqKkj",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_980_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_980_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_980_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_980_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111EH9uVaqWRxHuzJbroqzX18yxmeW8TjFVSP",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_980_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_980_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_980_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_980_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_980_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_980_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_980_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_980_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_980_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_980_raw_sz;
  test.expected_result = -8;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_981(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 92,126,124,26,56,62,121,109,80,112,125,105,30,128,33,2,116,90,127,113,79,82,114,111,77,87,123,61,122,55,103,106,110,15,29,108,118,83,78,117,120,75,98,89,24,27,76 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_stake_checked_instructions::new_behavior";
  test.test_nonce  = 331;
  test.test_number = 981;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 4;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "HbXHzDNb6at14gDG9Ni5kP9Uu9CBd4ka4Jh8DHNVb6Ph",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 42UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_981_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_981_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_981_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_981_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111g2nWWXuwsVwzL3XQNhJv3AQK3vzVxiaogT",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "1111111GhBXQEdEh35AtuSNxMzRutcgYg3nj8kVLT",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_981_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_981_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_981_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_981_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_981_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_981_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_981_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_981_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111EgVWUh8o98knojjwqGKqVGFkQ9m5AxqKkj",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "1111111H6X8PLvXQDY3iLaTynKkQ1tUBBJjSNLKeo",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_981_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_981_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_981_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_981_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_981_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_981_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_982(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 92,126,124,26,56,62,121,109,80,112,125,105,30,128,33,2,116,90,127,113,79,82,114,111,77,87,123,61,122,55,103,106,110,15,29,108,118,83,78,117,120,75,98,89,24,27,76 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_stake_checked_instructions::new_behavior";
  test.test_nonce  = 340;
  test.test_number = 982;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 4;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111111EH9uVaqWRxHuzJbroqzX18yxmeW8TjFVSP",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_982_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_982_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_982_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_982_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111i3UXS5QPRQGNRDDqVnyWTnmFCTHDWtVyGB",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_982_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_982_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_982_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_982_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_982_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_982_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_982_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_982_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111EgVWUh8o98knojjwqGKqVGFkQ9m5AxqKkj",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_982_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_982_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_982_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_982_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_982_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_982_raw_sz;
  test.expected_result = -8;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_983(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 92,126,124,26,56,62,121,109,80,112,125,105,30,128,33,2,116,90,127,113,79,82,114,111,77,87,123,61,122,55,103,106,110,15,29,108,118,83,78,117,120,75,98,89,24,27,76 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_stake_checked_instructions::new_behavior";
  test.test_nonce  = 370;
  test.test_number = 983;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 4;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "4NE1n1P1kvL23Uky6oC7Zpyz9Hjpxgywm3ciaX92ftKA",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 42UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_983_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_983_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_983_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_983_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111i3UXS5QPRQGNRDDqVnyWTnmFCTHDWtVyGB",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "1111111HuCLMZX6paToMCre2czPNGS3SBpcrqVzHV",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_983_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_983_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_983_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_983_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_983_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_983_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_983_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_983_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111EgVWUh8o98knojjwqGKqVGFkQ9m5AxqKkj",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "1111111JJXwLfpPXkvgAdzj43KhrPhq4h5Za55pbq",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_983_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_983_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_983_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_983_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_983_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_983_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_984(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 92,126,124,26,56,62,121,109,80,112,125,105,30,128,33,2,116,90,127,113,79,82,114,111,77,87,123,61,122,55,103,106,110,15,29,108,118,83,78,117,120,75,98,89,24,27,76 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_stake_checked_instructions::new_behavior";
  test.test_nonce  = 316;
  test.test_number = 984;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 4;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_984_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_984_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_984_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_984_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111EgVWUh8o98knojjwqGKqVGFkQ9m5AxqKkj",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_984_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_984_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_984_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_984_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111EH9uVaqWRxHuzJbroqzX18yxmeW8TjFVSP",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_984_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_984_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_984_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_984_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111g2nWWXuwsVwzL3XQNhJv3AQK3vzVxiaogT",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_984_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_984_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_984_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_984_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_984_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_984_raw_sz;
  test.expected_result = -8;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_985(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 92,126,124,26,56,62,121,109,80,112,125,105,30,128,33,2,116,90,127,113,79,82,114,111,77,87,123,61,122,55,103,106,110,15,29,108,118,83,78,117,120,75,98,89,24,27,76 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_stake_checked_instructions::new_behavior";
  test.test_nonce  = 343;
  test.test_number = 985;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 4;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "HbXHzDNb6at14gDG9Ni5kP9Uu9CBd4ka4Jh8DHNVb6Ph",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 42UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_985_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_985_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_985_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_985_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111g2nWWXuwsVwzL3XQNhJv3AQK3vzVxiaogT",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "1111111GhBXQEdEh35AtuSNxMzRutcgYg3nj8kVLT",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_985_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_985_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_985_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_985_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_985_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_985_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_985_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_985_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111FVAiSujNZVgYSc27t6zUTWoKfAGxbRzzPR",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "1111111H6X8PLvXQDY3iLaTynKkQ1tUBBJjSNLKeo",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_985_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_985_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_985_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_985_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_985_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_985_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_986(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 92,126,124,26,56,62,121,109,80,112,125,105,30,128,33,2,116,90,127,113,79,82,114,111,77,87,123,61,122,55,103,106,110,15,29,108,118,83,78,117,120,75,98,89,24,27,76 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_stake_checked_instructions::new_behavior";
  test.test_nonce  = 351;
  test.test_number = 986;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 4;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111111i3UXS5QPRQGNRDDqVnyWTnmFCTHDWtVyGB",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_986_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_986_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_986_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_986_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111EH9uVaqWRxHuzJbroqzX18yxmeW8TjFVSP",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_986_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_986_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_986_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_986_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_986_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_986_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_986_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_986_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111EgVWUh8o98knojjwqGKqVGFkQ9m5AxqKkj",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_986_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_986_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_986_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_986_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_986_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_986_raw_sz;
  test.expected_result = -8;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_987(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 92,126,124,26,56,62,121,109,80,112,125,105,30,128,33,2,116,90,127,113,79,82,114,111,77,87,123,61,122,55,103,106,110,15,29,108,118,83,78,117,120,75,98,89,24,27,76 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_stake_checked_instructions::new_behavior";
  test.test_nonce  = 390;
  test.test_number = 987;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 4;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "4NE1n1P1kvL23Uky6oC7Zpyz9Hjpxgywm3ciaX92ftKA",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 42UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_987_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_987_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_987_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_987_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111i3UXS5QPRQGNRDDqVnyWTnmFCTHDWtVyGB",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "1111111HuCLMZX6paToMCre2czPNGS3SBpcrqVzHV",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_987_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_987_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_987_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_987_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_987_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_987_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_987_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_987_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111FtWKS22fGg9RG3ACuXKnwe57HfXuJfaphm",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "1111111JJXwLfpPXkvgAdzj43KhrPhq4h5Za55pbq",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_987_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_987_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_987_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_987_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_987_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_987_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_988(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 92,126,124,26,56,62,121,109,80,112,125,105,30,128,33,2,116,90,127,113,79,82,114,111,77,87,123,61,122,55,103,106,110,15,29,108,118,83,78,117,120,75,98,89,24,27,76 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_stake_checked_instructions::new_behavior";
  test.test_nonce  = 412;
  test.test_number = 988;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 4;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_988_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_988_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_988_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_988_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111MXEmDYChDCdgi77RFPzFjPt86j97FwkV8b",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_988_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_988_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_988_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_988_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111FtWKS22fGg9RG3ACuXKnwe57HfXuJfaphm",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_988_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_988_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_988_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_988_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111EH9uVaqWRxHuzJbroqzX18yxmeW8TjFVSP",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_988_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_988_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_988_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_988_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_988_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_988_raw_sz;
  test.expected_result = -8;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_989(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 92,126,124,26,56,62,121,109,80,112,125,105,30,128,33,2,116,90,127,113,79,82,114,111,77,87,123,61,122,55,103,106,110,15,29,108,118,83,78,117,120,75,98,89,24,27,76 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_stake_checked_instructions::new_behavior";
  test.test_nonce  = 432;
  test.test_number = 989;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 4;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_989_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_989_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_989_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_989_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111EH9uVaqWRxHuzJbroqzX18yxmeW8TjFVSP",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 42UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_989_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_989_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_989_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_989_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111FtWKS22fGg9RG3ACuXKnwe57HfXuJfaphm",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "1111111GHqvR8KwyrcJ5UJHvwf7RmLtvAnr1uAf27",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_989_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_989_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_989_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_989_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111MXEmDYChDCdgi77RFPzFjPt86j97FwkV8b",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "1111111MvaNCeVyvP6ZXYFWGpKaDX9ujEQ3yBLKSw",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_989_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_989_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_989_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_989_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_989_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_989_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_990(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 92,126,124,26,56,62,121,109,80,112,125,105,30,128,33,2,116,90,127,113,79,82,114,111,77,87,123,61,122,55,103,106,110,15,29,108,118,83,78,117,120,75,98,89,24,27,76 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_stake_checked_instructions::new_behavior";
  test.test_nonce  = 352;
  test.test_number = 990;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 4;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111111HVrjNTDp7PzvXmiZ1Cf4t9AFogZg9bv9y9",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_990_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_990_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_990_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_990_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111FVAiSujNZVgYSc27t6zUTWoKfAGxbRzzPR",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_990_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_990_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_990_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_990_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_990_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_990_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_990_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_990_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111EH9uVaqWRxHuzJbroqzX18yxmeW8TjFVSP",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_990_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_990_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_990_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_990_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_990_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_990_raw_sz;
  test.expected_result = -8;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_991(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 92,126,124,26,56,62,121,109,80,112,125,105,30,128,33,2,116,90,127,113,79,82,114,111,77,87,123,61,122,55,103,106,110,15,29,108,118,83,78,117,120,75,98,89,24,27,76 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_stake_checked_instructions::new_behavior";
  test.test_nonce  = 365;
  test.test_number = 991;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 4;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_991_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_991_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_991_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_991_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111EH9uVaqWRxHuzJbroqzX18yxmeW8TjFVSP",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 42UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_991_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_991_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_991_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_991_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111FVAiSujNZVgYSc27t6zUTWoKfAGxbRzzPR",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "1111111FtWKS22fGg9RG3ACuXKnwe57HfXuJfaphm",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_991_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_991_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_991_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_991_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111HVrjNTDp7PzvXmiZ1Cf4t9AFogZg9bv9y9",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "1111111HuCLMZX6paToMCre2czPNGS3SBpcrqVzHV",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_991_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_991_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_991_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_991_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_991_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_991_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_992(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 29,61,2,126,106,123,117,90,55,122,111,33,76,92,121,82,24,15,79,110,62,30,77,87,124,75,105,116,127,108,114,26,78,112,120,109,83,113,103,56,80,128,118,89,98,27,125 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_stake_checked_instructions::old_behavior";
  test.test_nonce  = 131;
  test.test_number = 992;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 5;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111111FVAiSujNZVgYSc27t6zUTWoKfAGxbRzzPR",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_992_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_992_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_992_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_992_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111GhBXQEdEh35AtuSNxMzRutcgYg3nj8kVLT",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_992_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_992_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_992_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_992_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111JhsYKn7gEwPYz58p5Tf2LWychCLWHJfevB",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_992_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_992_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_992_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_992_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_992_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_992_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_992_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_992_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_992_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_992_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_992_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_992_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_992_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_992_raw_sz;
  test.expected_result = -8;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_993(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 29,61,2,126,106,123,117,90,55,122,111,33,76,92,121,82,24,15,79,110,62,30,77,87,124,75,105,116,127,108,114,26,78,112,120,109,83,113,103,56,80,128,118,89,98,27,125 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_stake_checked_instructions::old_behavior";
  test.test_nonce  = 180;
  test.test_number = 993;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 4;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111111FVAiSujNZVgYSc27t6zUTWoKfAGxbRzzPR",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2282881UL;
  test_acc->result_lamports = 2282881UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_993_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_993_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_993_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_993_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_993_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_993_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_993_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_993_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111GhBXQEdEh35AtuSNxMzRutcgYg3nj8kVLT",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "1111111H6X8PLvXQDY3iLaTynKkQ1tUBBJjSNLKeo",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_993_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_993_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_993_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_993_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111JhsYKn7gEwPYz58p5Tf2LWychCLWHJfevB",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "1111111K7D9JtQxx7rRoWGu6szLpeFQKhbSzYFVEX",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_993_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_993_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_993_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_993_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_993_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_993_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_994(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 1;
  uchar disabled_features[] = { 89 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_stake_checked_instructions::old_behavior";
  test.test_nonce  = 170;
  test.test_number = 994;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 5;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_994_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_994_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_994_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_994_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111JJXwLfpPXkvgAdzj43KhrPhq4h5Za55pbq",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_994_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_994_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_994_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_994_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_994_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_994_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_994_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_994_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111KWYkHziFfJKJcwQz8JKfJmXBxCrPhmqKYs",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_994_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_994_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_994_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_994_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111JhsYKn7gEwPYz58p5Tf2LWychCLWHJfevB",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_994_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_994_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_994_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_994_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_994_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_994_raw_sz;
  test.expected_result = -8;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_995(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 1;
  uchar disabled_features[] = { 89 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_stake_checked_instructions::old_behavior";
  test.test_nonce  = 193;
  test.test_number = 995;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 4;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111111JJXwLfpPXkvgAdzj43KhrPhq4h5Za55pbq",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2282881UL;
  test_acc->result_lamports = 2282881UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_995_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_995_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_995_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_995_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_995_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_995_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_995_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_995_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111JhsYKn7gEwPYz58p5Tf2LWychCLWHJfevB",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "1111111K7D9JtQxx7rRoWGu6szLpeFQKhbSzYFVEX",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_995_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_995_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_995_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_995_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111KWYkHziFfJKJcwQz8JKfJmXBxCrPhmqKYs",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "1111111KutMH71YNUnBSNZ59ieyntnyai7LR1R9sD",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_995_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_995_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_995_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_995_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_995_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_995_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_996(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 29,61,2,126,106,123,117,90,55,122,111,33,76,92,121,82,24,15,79,110,62,30,77,87,124,75,105,116,127,108,114,26,78,112,120,109,83,113,103,56,80,128,118,89,98,27,125 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_stake_checked_instructions::old_behavior";
  test.test_nonce  = 218;
  test.test_number = 996;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 4;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111111GhBXQEdEh35AtuSNxMzRutcgYg3nj8kVLT",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_996_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_996_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_996_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_996_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111FVAiSujNZVgYSc27t6zUTWoKfAGxbRzzPR",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_996_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_996_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_996_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_996_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111KWYkHziFfJKJcwQz8JKfJmXBxCrPhmqKYs",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_996_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_996_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_996_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_996_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_996_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_996_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_996_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_996_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_996_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_996_raw_sz;
  test.expected_result = -8;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_997(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 29,61,2,126,106,123,117,90,55,122,111,33,76,92,121,82,24,15,79,110,62,30,77,87,124,75,105,116,127,108,114,26,78,112,120,109,83,113,103,56,80,128,118,89,98,27,125 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_stake_checked_instructions::old_behavior";
  test.test_nonce  = 322;
  test.test_number = 997;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 4;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111111FVAiSujNZVgYSc27t6zUTWoKfAGxbRzzPR",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 42UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_997_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_997_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_997_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_997_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_997_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_997_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_997_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_997_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111KWYkHziFfJKJcwQz8JKfJmXBxCrPhmqKYs",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "1111111KutMH71YNUnBSNZ59ieyntnyai7LR1R9sD",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_997_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_997_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_997_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_997_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111GhBXQEdEh35AtuSNxMzRutcgYg3nj8kVLT",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "1111111LKDxGDJq5fF4FohAB8zJH24mDDNH8EzzBZ",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_997_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_997_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_997_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_997_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_997_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_997_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_998(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 1;
  uchar disabled_features[] = { 89 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_stake_checked_instructions::old_behavior";
  test.test_nonce  = 219;
  test.test_number = 998;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 4;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111111LKDxGDJq5fF4FohAB8zJH24mDDNH8EzzBZ",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_998_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_998_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_998_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_998_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111JJXwLfpPXkvgAdzj43KhrPhq4h5Za55pbq",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_998_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_998_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_998_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_998_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_998_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_998_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_998_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_998_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111JhsYKn7gEwPYz58p5Tf2LWychCLWHJfevB",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_998_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_998_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_998_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_998_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_998_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_998_raw_sz;
  test.expected_result = -8;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_999(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 1;
  uchar disabled_features[] = { 89 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_stake_checked_instructions::old_behavior";
  test.test_nonce  = 318;
  test.test_number = 999;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 4;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111111JJXwLfpPXkvgAdzj43KhrPhq4h5Za55pbq",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 42UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_999_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_999_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_999_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_999_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_999_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_999_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_999_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_999_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111LKDxGDJq5fF4FohAB8zJH24mDDNH8EzzBZ",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "1111111LiZZFKc7nqhw5EqFCZKcm9LYqidDqUapVu",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_999_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_999_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_999_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_999_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111JhsYKn7gEwPYz58p5Tf2LWychCLWHJfevB",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "1111111M7uAERuQW2AotfyLDyewFGcLUDtAYiAepF",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_999_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_999_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_999_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_999_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_999_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_999_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
