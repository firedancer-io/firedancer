#include "../fd_tests.h"
int test_900(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 126,118,121,61,82,109,125,128,89,79,112,105,124,103,62,108,98,76,24,78,80,77,111,75,87,26,15,83,27,120,2,127,114,116,113,123,90,55,30,106,122,117,110,33,56,29,92 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_split_with_rent::new_behavior";
  test.test_nonce  = 226;
  test.test_number = 900;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "6r4jQfE9eoKkSqs8Ct7qVn6SwRVu8tL1uqTgFbt7vks5",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2004565760UL;
  test_acc->result_lamports = 1002282879UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_900_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_900_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_900_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_900_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "FuwyCFMbYTVQmX1ohcWcZrnBdQUtR6Znwjm4FULjrWYT",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 1002282881UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_900_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_900_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_900_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_900_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_900_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_900_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_900_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_900_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_900_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_900_raw_sz;
  test.expected_result = -6;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_901(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 126,118,121,61,82,109,125,128,89,79,112,105,124,103,62,108,98,76,24,78,80,77,111,75,87,26,15,83,27,120,2,127,114,116,113,123,90,55,30,106,122,117,110,33,56,29,92 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_split_with_rent::new_behavior";
  test.test_nonce  = 301;
  test.test_number = 901;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "ArCxhTFRmHDrtkiAhHwHz1oXt7eCW3ZasgzJCyCR9Ee8",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2004565760UL;
  test_acc->result_lamports = 2004565760UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_901_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_901_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_901_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_901_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "5jfpEmx62h5VcaZwcuDE3jjNnQ9NCYMbB2yPW7aYGuj",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_901_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_901_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_901_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_901_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_901_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_901_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_901_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_901_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_901_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_901_raw_sz;
  test.expected_result = -6;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_902(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 126,118,121,61,82,109,125,128,89,79,112,105,124,103,62,108,98,76,24,78,80,77,111,75,87,26,15,83,27,120,2,127,114,116,113,123,90,55,30,106,122,117,110,33,56,29,92 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_split_with_rent::new_behavior";
  test.test_nonce  = 150;
  test.test_number = 902;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "6r4jQfE9eoKkSqs8Ct7qVn6SwRVu8tL1uqTgFbt7vks5",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 4565760UL;
  test_acc->result_lamports = 4565760UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_902_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_902_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_902_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_902_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "FuwyCFMbYTVQmX1ohcWcZrnBdQUtR6Znwjm4FULjrWYT",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_902_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_902_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_902_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_902_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_902_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_902_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_902_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_902_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_902_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_902_raw_sz;
  test.expected_result = -6;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_903(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 126,118,121,61,82,109,125,128,89,79,112,105,124,103,62,108,98,76,24,78,80,77,111,75,87,26,15,83,27,120,2,127,114,116,113,123,90,55,30,106,122,117,110,33,56,29,92 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_split_with_rent::new_behavior";
  test.test_nonce  = 204;
  test.test_number = 903;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "ArCxhTFRmHDrtkiAhHwHz1oXt7eCW3ZasgzJCyCR9Ee8",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 4565760UL;
  test_acc->result_lamports = 4565760UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_903_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_903_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_903_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_903_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "5jfpEmx62h5VcaZwcuDE3jjNnQ9NCYMbB2yPW7aYGuj",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_903_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_903_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_903_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_903_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_903_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_903_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_903_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_903_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_903_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_903_raw_sz;
  test.expected_result = -6;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_904(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 1;
  uchar disabled_features[] = { 89 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_split_with_rent::old_behavior";
  test.test_nonce  = 206;
  test.test_number = 904;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "2DYA62Kj5NrdDrG3EzAM95puQJqya4aoy5YbEttYo51X",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 4565760UL;
  test_acc->result_lamports = 4565760UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_904_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_904_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_904_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_904_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "9kJVFztCbu6662bdE7HymExazEroW8oznSG5smnHXPxf",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_904_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_904_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_904_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_904_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_904_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_904_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_904_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_904_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_904_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_904_raw_sz;
  test.expected_result = -6;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_905(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 117,98,26,126,103,80,106,15,56,62,78,27,90,55,89,111,118,83,110,122,76,61,2,121,125,128,79,105,116,92,114,123,109,127,113,33,124,87,30,108,24,75,77,120,29,82,112 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_split_with_rent::old_behavior";
  test.test_nonce  = 136;
  test.test_number = 905;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "J617RAs8zhbAbnFCgUbiMYDSBY3iZEUqgLSbhcoBAogN",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 4565760UL;
  test_acc->result_lamports = 4565760UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_905_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_905_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_905_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_905_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "4XvdDUzc4rkrw6WNnnEXLQJGPM4MAG3yr2RtmA1hLFv9",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_905_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_905_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_905_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_905_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_905_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_905_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_905_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_905_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_905_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_905_raw_sz;
  test.expected_result = -6;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_906(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 1;
  uchar disabled_features[] = { 89 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_split_with_rent::old_behavior";
  test.test_nonce  = 262;
  test.test_number = 906;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "2DYA62Kj5NrdDrG3EzAM95puQJqya4aoy5YbEttYo51X",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 4565760UL;
  test_acc->result_lamports = 2282880UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_906_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_906_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_906_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_906_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "9kJVFztCbu6662bdE7HymExazEroW8oznSG5smnHXPxf",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2282880UL;
  test_acc->result_lamports = 4565760UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_906_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_906_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_906_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_906_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_906_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_906_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_906_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_906_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_906_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_906_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_907(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 1;
  uchar disabled_features[] = { 89 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_split_with_rent::old_behavior";
  test.test_nonce  = 277;
  test.test_number = 907;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "2DYA62Kj5NrdDrG3EzAM95puQJqya4aoy5YbEttYo51X",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 4565762UL;
  test_acc->result_lamports = 4565762UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_907_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_907_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_907_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_907_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "9kJVFztCbu6662bdE7HymExazEroW8oznSG5smnHXPxf",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_907_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_907_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_907_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_907_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_907_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_907_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_907_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_907_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_907_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_907_raw_sz;
  test.expected_result = -6;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_908(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 117,98,26,126,103,80,106,15,56,62,78,27,90,55,89,111,118,83,110,122,76,61,2,121,125,128,79,105,116,92,114,123,109,127,113,33,124,87,30,108,24,75,77,120,29,82,112 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_split_with_rent::old_behavior";
  test.test_nonce  = 217;
  test.test_number = 908;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "J617RAs8zhbAbnFCgUbiMYDSBY3iZEUqgLSbhcoBAogN",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 4565760UL;
  test_acc->result_lamports = 4565760UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_908_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_908_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_908_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_908_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "4XvdDUzc4rkrw6WNnnEXLQJGPM4MAG3yr2RtmA1hLFv9",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2282880UL;
  test_acc->result_lamports = 2282880UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_908_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_908_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_908_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_908_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_908_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_908_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_908_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_908_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_908_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_908_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_909(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 117,98,26,126,103,80,106,15,56,62,78,27,90,55,89,111,118,83,110,122,76,61,2,121,125,128,79,105,116,92,114,123,109,127,113,33,124,87,30,108,24,75,77,120,29,82,112 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_split_with_rent::old_behavior";
  test.test_nonce  = 297;
  test.test_number = 909;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "J617RAs8zhbAbnFCgUbiMYDSBY3iZEUqgLSbhcoBAogN",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 4565762UL;
  test_acc->result_lamports = 4565762UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_909_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_909_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_909_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_909_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "4XvdDUzc4rkrw6WNnnEXLQJGPM4MAG3yr2RtmA1hLFv9",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_909_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_909_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_909_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_909_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_909_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_909_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_909_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_909_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_909_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_909_raw_sz;
  test.expected_result = -6;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_910(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 1;
  uchar disabled_features[] = { 89 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_split_with_rent::old_behavior";
  test.test_nonce  = 237;
  test.test_number = 910;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "2DYA62Kj5NrdDrG3EzAM95puQJqya4aoy5YbEttYo51X",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 4565760UL;
  test_acc->result_lamports = 4565760UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_910_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_910_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_910_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_910_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "9kJVFztCbu6662bdE7HymExazEroW8oznSG5smnHXPxf",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_910_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_910_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_910_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_910_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_910_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_910_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_910_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_910_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_910_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_910_raw_sz;
  test.expected_result = -6;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_911(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 1;
  uchar disabled_features[] = { 89 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_split_with_rent::old_behavior";
  test.test_nonce  = 306;
  test.test_number = 911;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "2DYA62Kj5NrdDrG3EzAM95puQJqya4aoy5YbEttYo51X",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 4565762UL;
  test_acc->result_lamports = 2282881UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_911_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_911_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_911_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_911_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "9kJVFztCbu6662bdE7HymExazEroW8oznSG5smnHXPxf",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2282881UL;
  test_acc->result_lamports = 4565762UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_911_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_911_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_911_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_911_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_911_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_911_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_911_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_911_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_911_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_911_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_912(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 117,98,26,126,103,80,106,15,56,62,78,27,90,55,89,111,118,83,110,122,76,61,2,121,125,128,79,105,116,92,114,123,109,127,113,33,124,87,30,108,24,75,77,120,29,82,112 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_split_with_rent::old_behavior";
  test.test_nonce  = 182;
  test.test_number = 912;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "J617RAs8zhbAbnFCgUbiMYDSBY3iZEUqgLSbhcoBAogN",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 4565760UL;
  test_acc->result_lamports = 4565760UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_912_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_912_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_912_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_912_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "4XvdDUzc4rkrw6WNnnEXLQJGPM4MAG3yr2RtmA1hLFv9",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_912_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_912_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_912_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_912_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_912_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_912_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_912_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_912_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_912_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_912_raw_sz;
  test.expected_result = -6;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_913(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 117,98,26,126,103,80,106,15,56,62,78,27,90,55,89,111,118,83,110,122,76,61,2,121,125,128,79,105,116,92,114,123,109,127,113,33,124,87,30,108,24,75,77,120,29,82,112 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_split_with_rent::old_behavior";
  test.test_nonce  = 341;
  test.test_number = 913;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "J617RAs8zhbAbnFCgUbiMYDSBY3iZEUqgLSbhcoBAogN",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 4565762UL;
  test_acc->result_lamports = 2282881UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_913_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_913_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_913_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_913_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "4XvdDUzc4rkrw6WNnnEXLQJGPM4MAG3yr2RtmA1hLFv9",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2282881UL;
  test_acc->result_lamports = 4565762UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_913_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_913_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_913_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_913_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_913_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_913_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_913_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_913_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_913_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_913_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_914(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 1;
  uchar disabled_features[] = { 89 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_split_with_rent::old_behavior";
  test.test_nonce  = 299;
  test.test_number = 914;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "2DYA62Kj5NrdDrG3EzAM95puQJqya4aoy5YbEttYo51X",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 4565762UL;
  test_acc->result_lamports = 4565762UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_914_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_914_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_914_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_914_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "9kJVFztCbu6662bdE7HymExazEroW8oznSG5smnHXPxf",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_914_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_914_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_914_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_914_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_914_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_914_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_914_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_914_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_914_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_914_raw_sz;
  test.expected_result = -6;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_915(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 117,98,26,126,103,80,106,15,56,62,78,27,90,55,89,111,118,83,110,122,76,61,2,121,125,128,79,105,116,92,114,123,109,127,113,33,124,87,30,108,24,75,77,120,29,82,112 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_split_with_rent::old_behavior";
  test.test_nonce  = 316;
  test.test_number = 915;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "J617RAs8zhbAbnFCgUbiMYDSBY3iZEUqgLSbhcoBAogN",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 4565762UL;
  test_acc->result_lamports = 4565762UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_915_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_915_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_915_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_915_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "4XvdDUzc4rkrw6WNnnEXLQJGPM4MAG3yr2RtmA1hLFv9",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_915_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_915_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_915_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_915_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_915_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_915_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_915_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_915_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_915_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_915_raw_sz;
  test.expected_result = -6;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_916(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 78,106,113,116,114,92,128,2,75,56,83,117,33,61,118,27,109,79,122,15,29,87,110,124,103,98,126,90,123,105,89,76,55,125,127,62,30,111,80,26,108,121,82,24,77,112,120 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_spoofed_stake_accounts::new_behavior";
  test.test_nonce  = 127;
  test.test_number = 916;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "SpoofedStake1111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Spoofed111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_916_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_916_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_916_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_916_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_916_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_916_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_916_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_916_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_916_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_916_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_916_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_916_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_916_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_916_raw_sz;
  test.expected_result = -47;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_917(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 78,106,113,116,114,92,128,2,75,56,83,117,33,61,118,27,109,79,122,15,29,87,110,124,103,98,126,90,123,105,89,76,55,125,127,62,30,111,80,26,108,121,82,24,77,112,120 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_spoofed_stake_accounts::new_behavior";
  test.test_nonce  = 119;
  test.test_number = 917;
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
  test_acc->data            = fd_flamenco_native_prog_test_917_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_917_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_917_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_917_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_917_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_917_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_917_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_917_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SpoofedStake1111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Spoofed111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_917_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_917_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_917_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_917_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_917_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_917_raw_sz;
  test.expected_result = -47;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_918(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 78,106,113,116,114,92,128,2,75,56,83,117,33,61,118,27,109,79,122,15,29,87,110,124,103,98,126,90,123,105,89,76,55,125,127,62,30,111,80,26,108,121,82,24,77,112,120 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_spoofed_stake_accounts::new_behavior";
  test.test_nonce  = 154;
  test.test_number = 918;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111111P8bB9yPr3vVByqfmM5KXftyGckAt6t5pPy",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_918_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_918_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_918_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_918_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SpoofedStake1111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Spoofed111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_918_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_918_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_918_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_918_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_918_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_918_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_918_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_918_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_918_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_918_raw_sz;
  test.expected_result = -47;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_919(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 78,106,113,116,114,92,128,2,75,56,83,117,33,61,118,27,109,79,122,15,29,87,110,124,103,98,126,90,123,105,89,76,55,125,127,62,30,111,80,26,108,121,82,24,77,112,120 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_spoofed_stake_accounts::new_behavior";
  test.test_nonce  = 142;
  test.test_number = 919;
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
  test_acc->data            = fd_flamenco_native_prog_test_919_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_919_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_919_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_919_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SpoofedStake1111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Spoofed111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_919_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_919_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_919_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_919_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111P8bB9yPr3vVByqfmM5KXftyGckAt6t5pPy",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_919_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_919_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_919_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_919_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_919_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_919_raw_sz;
  test.expected_result = -47;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_920(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 78,106,113,116,114,92,128,2,75,56,83,117,33,61,118,27,109,79,122,15,29,87,110,124,103,98,126,90,123,105,89,76,55,125,127,62,30,111,80,26,108,121,82,24,77,112,120 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_spoofed_stake_accounts::new_behavior";
  test.test_nonce  = 479;
  test.test_number = 920;
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
  test_acc->data            = fd_flamenco_native_prog_test_920_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_920_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_920_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_920_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_920_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_920_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_920_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_920_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_920_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_920_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_920_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_920_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SpoofedStake1111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Spoofed111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_920_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_920_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_920_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_920_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111vWxDxSeKRzdXmeYXFoJPVgCdi6GTZ9ao4s",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_920_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_920_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_920_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_920_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111v7ccyLM2ipAexDQSENy51Yvr5b1WquzxkX",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_920_acc_5_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_920_acc_5_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_920_acc_5_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_920_acc_5_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_920_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_920_raw_sz;
  test.expected_result = -47;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_921(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 78,106,113,116,114,92,128,2,75,56,83,117,33,61,118,27,109,79,122,15,29,87,110,124,103,98,126,90,123,105,89,76,55,125,127,62,30,111,80,26,108,121,82,24,77,112,120 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_spoofed_stake_accounts::new_behavior";
  test.test_nonce  = 436;
  test.test_number = 921;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 6;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111111vWxDxSeKRzdXmeYXFoJPVgCdi6GTZ9ao4s",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_921_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_921_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_921_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_921_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_921_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_921_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_921_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_921_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_921_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_921_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_921_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_921_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111v7ccyLM2ipAexDQSENy51Yvr5b1WquzxkX",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_921_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_921_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_921_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_921_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "StakeConfig11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_921_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_921_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_921_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_921_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SpoofedStake1111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Spoofed111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_921_acc_5_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_921_acc_5_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_921_acc_5_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_921_acc_5_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_921_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_921_raw_sz;
  test.expected_result = -47;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_922(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 78,106,113,116,114,92,128,2,75,56,83,117,33,61,118,27,109,79,122,15,29,87,110,124,103,98,126,90,123,105,89,76,55,125,127,62,30,111,80,26,108,121,82,24,77,112,120 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_spoofed_stake_accounts::new_behavior";
  test.test_nonce  = 178;
  test.test_number = 922;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 4;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111111Qjwb6QazteLhFaE7SkeocQ4R8mCewpR9fM",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_922_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_922_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_922_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_922_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111R9HC5WtHbpoa51NCUAz86XLCmGTbf3zyyh",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_922_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_922_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_922_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_922_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_922_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_922_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_922_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_922_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SpoofedStake1111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Spoofed111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_922_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_922_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_922_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_922_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_922_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_922_raw_sz;
  test.expected_result = -47;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_923(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 78,106,113,116,114,92,128,2,75,56,83,117,33,61,118,27,109,79,122,15,29,87,110,124,103,98,126,90,123,105,89,76,55,125,127,62,30,111,80,26,108,121,82,24,77,112,120 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_spoofed_stake_accounts::new_behavior";
  test.test_nonce  = 220;
  test.test_number = 923;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 4;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111111ZC3Fmgr3oS56Rg9vxZeVo2mwMMcTsjfeJb",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_923_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_923_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_923_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_923_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111YnhenaYm6FcDcF1qw9KBJuW9irMXAW5ozF",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_923_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_923_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_923_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_923_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SpoofedStake1111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Spoofed111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_923_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_923_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_923_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_923_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_923_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_923_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_923_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_923_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_923_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_923_raw_sz;
  test.expected_result = -7;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_924(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 78,106,113,116,114,92,128,2,75,56,83,117,33,61,118,27,109,79,122,15,29,87,110,124,103,98,126,90,123,105,89,76,55,125,127,62,30,111,80,26,108,121,82,24,77,112,120 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_spoofed_stake_accounts::new_behavior";
  test.test_nonce  = 455;
  test.test_number = 924;
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
  test_acc->data            = fd_flamenco_native_prog_test_924_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_924_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_924_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_924_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111uJwR17kTJTEuKM8GBYJS3JPGpaVdRSqJ7q",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_924_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_924_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_924_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_924_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SpoofedStake1111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Spoofed111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_924_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_924_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_924_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_924_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111tubp21TAbGn2VuzBA7y7ZB7VC5EgiDFToV",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_924_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_924_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_924_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_924_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_924_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_924_raw_sz;
  test.expected_result = -47;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
