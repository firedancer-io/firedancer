#include "../fd_tests.h"
int test_675(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 90,120,103,121,112,79,124,33,125,114,98,82,126,87,62,76,108,116,29,27,109,77,118,128,26,75,24,122,80,113,117,56,110,89,127,123,30,55,105,15,78,83,106,111,2,61,92 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_split_from_larger_sized_account::new_behavior";
  test.test_nonce  = 65;
  test.test_number = 675;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "FJ57JsuFVjuoJDHuwBpp7TWGCErMcBTjf3pbKpcugkYk",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2005957760UL;
  test_acc->result_lamports = 2005957760UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_675_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_675_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_675_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_675_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "HkcvgPDLL6HMQnYseNp4Lpaeb1obrdgP62onUrasgTf2",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_675_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_675_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_675_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_675_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_675_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_675_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_675_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_675_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_675_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_675_raw_sz;
  test.expected_result = -6;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_676(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 118,114,128,75,122,56,117,124,90,123,106,27,120,125,87,89,76,113,62,83,109,127,98,108,82,105,77,26,116,2,55,29,103,126,111,33,110,15,112,24,61,78,30,92,79,121,80 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_split_from_larger_sized_account::old_behavior";
  test.test_nonce  = 126;
  test.test_number = 676;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "2onLF6jBJ2H3pP82Zg3D18hXixEuCLgmk9i7syeLzziz",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 5957762UL;
  test_acc->result_lamports = 2978881UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_676_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_676_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_676_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_676_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "D3y8w1tHhByo5JKfWq1AuZ31cKxSyCLzy2UFV3ppEmEZ",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2282879UL;
  test_acc->result_lamports = 5261760UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_676_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_676_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_676_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_676_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_676_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_676_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_676_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_676_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_676_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_676_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_677(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 118,114,128,75,122,56,117,124,90,123,106,27,120,125,87,89,76,113,62,83,109,127,98,108,82,105,77,26,116,2,55,29,103,126,111,33,110,15,112,24,61,78,30,92,79,121,80 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_split_from_larger_sized_account::old_behavior";
  test.test_nonce  = 185;
  test.test_number = 677;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "2onLF6jBJ2H3pP82Zg3D18hXixEuCLgmk9i7syeLzziz",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 5957762UL;
  test_acc->result_lamports = 2978881UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_677_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_677_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_677_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_677_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "D3y8w1tHhByo5JKfWq1AuZ31cKxSyCLzy2UFV3ppEmEZ",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2282880UL;
  test_acc->result_lamports = 5261761UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_677_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_677_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_677_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_677_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_677_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_677_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_677_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_677_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_677_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_677_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_678(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 118,114,128,75,122,56,117,124,90,123,106,27,120,125,87,89,76,113,62,83,109,127,98,108,82,105,77,26,116,2,55,29,103,126,111,33,110,15,112,24,61,78,30,92,79,121,80 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_split_from_larger_sized_account::old_behavior";
  test.test_nonce  = 224;
  test.test_number = 678;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "2onLF6jBJ2H3pP82Zg3D18hXixEuCLgmk9i7syeLzziz",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 5957762UL;
  test_acc->result_lamports = 2978881UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_678_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_678_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_678_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_678_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "D3y8w1tHhByo5JKfWq1AuZ31cKxSyCLzy2UFV3ppEmEZ",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2282880UL;
  test_acc->result_lamports = 5261761UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_678_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_678_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_678_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_678_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_678_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_678_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_678_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_678_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_678_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_678_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_679(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 118,114,128,75,122,56,117,124,90,123,106,27,120,125,87,89,76,113,62,83,109,127,98,108,82,105,77,26,116,2,55,29,103,126,111,33,110,15,112,24,61,78,30,92,79,121,80 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_split_from_larger_sized_account::old_behavior";
  test.test_nonce  = 258;
  test.test_number = 679;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "2onLF6jBJ2H3pP82Zg3D18hXixEuCLgmk9i7syeLzziz",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 5957762UL;
  test_acc->result_lamports = 2978881UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_679_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_679_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_679_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_679_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "D3y8w1tHhByo5JKfWq1AuZ31cKxSyCLzy2UFV3ppEmEZ",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2282881UL;
  test_acc->result_lamports = 5261762UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_679_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_679_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_679_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_679_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_679_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_679_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_679_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_679_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_679_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_679_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_680(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 118,114,128,75,122,56,117,124,90,123,106,27,120,125,87,89,76,113,62,83,109,127,98,108,82,105,77,26,116,2,55,29,103,126,111,33,110,15,112,24,61,78,30,92,79,121,80 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_split_from_larger_sized_account::old_behavior";
  test.test_nonce  = 88;
  test.test_number = 680;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "2onLF6jBJ2H3pP82Zg3D18hXixEuCLgmk9i7syeLzziz",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 5957762UL;
  test_acc->result_lamports = 2978881UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_680_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_680_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_680_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_680_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "D3y8w1tHhByo5JKfWq1AuZ31cKxSyCLzy2UFV3ppEmEZ",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 2978881UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_680_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_680_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_680_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_680_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_680_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_680_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_680_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_680_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_680_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_680_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_681(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 1;
  uchar disabled_features[] = { 89 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_split_from_larger_sized_account::old_behavior";
  test.test_nonce  = 102;
  test.test_number = 681;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "HRHc87rF18iGtMCoVgUHDU1NJqLBNx1J97yU4TVPfFak",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 5957762UL;
  test_acc->result_lamports = 2978881UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_681_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_681_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_681_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_681_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "9J9zNapNff6DwyCpyqVEDgsfcwHf7hzfFCvVNS5iHWNS",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 2978881UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_681_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_681_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_681_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_681_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_681_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_681_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_681_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_681_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_681_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_681_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_682(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 1;
  uchar disabled_features[] = { 89 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_split_from_larger_sized_account::old_behavior";
  test.test_nonce  = 160;
  test.test_number = 682;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "HRHc87rF18iGtMCoVgUHDU1NJqLBNx1J97yU4TVPfFak",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 5957762UL;
  test_acc->result_lamports = 2978881UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_682_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_682_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_682_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_682_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "9J9zNapNff6DwyCpyqVEDgsfcwHf7hzfFCvVNS5iHWNS",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2282879UL;
  test_acc->result_lamports = 5261760UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_682_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_682_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_682_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_682_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_682_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_682_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_682_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_682_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_682_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_682_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_683(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 1;
  uchar disabled_features[] = { 89 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_split_from_larger_sized_account::old_behavior";
  test.test_nonce  = 194;
  test.test_number = 683;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "HRHc87rF18iGtMCoVgUHDU1NJqLBNx1J97yU4TVPfFak",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 5957762UL;
  test_acc->result_lamports = 2978881UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_683_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_683_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_683_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_683_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "9J9zNapNff6DwyCpyqVEDgsfcwHf7hzfFCvVNS5iHWNS",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2282880UL;
  test_acc->result_lamports = 5261761UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_683_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_683_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_683_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_683_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_683_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_683_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_683_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_683_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_683_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_683_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_684(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 1;
  uchar disabled_features[] = { 89 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_split_from_larger_sized_account::old_behavior";
  test.test_nonce  = 234;
  test.test_number = 684;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "HRHc87rF18iGtMCoVgUHDU1NJqLBNx1J97yU4TVPfFak",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 5957762UL;
  test_acc->result_lamports = 2978881UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_684_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_684_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_684_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_684_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "9J9zNapNff6DwyCpyqVEDgsfcwHf7hzfFCvVNS5iHWNS",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2282880UL;
  test_acc->result_lamports = 5261761UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_684_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_684_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_684_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_684_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_684_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_684_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_684_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_684_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_684_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_684_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_685(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 1;
  uchar disabled_features[] = { 89 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_split_from_larger_sized_account::old_behavior";
  test.test_nonce  = 268;
  test.test_number = 685;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "HRHc87rF18iGtMCoVgUHDU1NJqLBNx1J97yU4TVPfFak",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 5957762UL;
  test_acc->result_lamports = 2978881UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_685_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_685_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_685_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_685_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "9J9zNapNff6DwyCpyqVEDgsfcwHf7hzfFCvVNS5iHWNS",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2282881UL;
  test_acc->result_lamports = 5261762UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_685_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_685_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_685_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_685_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_685_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_685_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_685_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_685_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_685_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_685_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_686(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 118,114,128,75,122,56,117,124,90,123,106,27,120,125,87,89,76,113,62,83,109,127,98,108,82,105,77,26,116,2,55,29,103,126,111,33,110,15,112,24,61,78,30,92,79,121,80 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_split_from_larger_sized_account::old_behavior";
  test.test_nonce  = 108;
  test.test_number = 686;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "2onLF6jBJ2H3pP82Zg3D18hXixEuCLgmk9i7syeLzziz",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 5957762UL;
  test_acc->result_lamports = 5957762UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_686_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_686_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_686_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_686_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "D3y8w1tHhByo5JKfWq1AuZ31cKxSyCLzy2UFV3ppEmEZ",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2282879UL;
  test_acc->result_lamports = 2282879UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_686_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_686_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_686_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_686_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_686_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_686_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_686_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_686_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_686_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_686_raw_sz;
  test.expected_result = -6;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_687(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 118,114,128,75,122,56,117,124,90,123,106,27,120,125,87,89,76,113,62,83,109,127,98,108,82,105,77,26,116,2,55,29,103,126,111,33,110,15,112,24,61,78,30,92,79,121,80 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_split_from_larger_sized_account::old_behavior";
  test.test_nonce  = 145;
  test.test_number = 687;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "2onLF6jBJ2H3pP82Zg3D18hXixEuCLgmk9i7syeLzziz",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 5957762UL;
  test_acc->result_lamports = 5957762UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_687_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_687_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_687_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_687_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "D3y8w1tHhByo5JKfWq1AuZ31cKxSyCLzy2UFV3ppEmEZ",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2282880UL;
  test_acc->result_lamports = 2282880UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_687_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_687_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_687_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_687_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_687_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_687_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_687_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_687_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_687_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_687_raw_sz;
  test.expected_result = -6;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_688(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 118,114,128,75,122,56,117,124,90,123,106,27,120,125,87,89,76,113,62,83,109,127,98,108,82,105,77,26,116,2,55,29,103,126,111,33,110,15,112,24,61,78,30,92,79,121,80 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_split_from_larger_sized_account::old_behavior";
  test.test_nonce  = 195;
  test.test_number = 688;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "2onLF6jBJ2H3pP82Zg3D18hXixEuCLgmk9i7syeLzziz",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 5957762UL;
  test_acc->result_lamports = 5957762UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_688_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_688_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_688_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_688_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "D3y8w1tHhByo5JKfWq1AuZ31cKxSyCLzy2UFV3ppEmEZ",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2282880UL;
  test_acc->result_lamports = 2282880UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_688_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_688_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_688_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_688_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_688_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_688_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_688_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_688_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_688_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_688_raw_sz;
  test.expected_result = -6;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_689(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 118,114,128,75,122,56,117,124,90,123,106,27,120,125,87,89,76,113,62,83,109,127,98,108,82,105,77,26,116,2,55,29,103,126,111,33,110,15,112,24,61,78,30,92,79,121,80 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_split_from_larger_sized_account::old_behavior";
  test.test_nonce  = 240;
  test.test_number = 689;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "2onLF6jBJ2H3pP82Zg3D18hXixEuCLgmk9i7syeLzziz",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 5957762UL;
  test_acc->result_lamports = 5957762UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_689_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_689_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_689_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_689_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "D3y8w1tHhByo5JKfWq1AuZ31cKxSyCLzy2UFV3ppEmEZ",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2282881UL;
  test_acc->result_lamports = 2282881UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_689_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_689_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_689_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_689_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_689_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_689_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_689_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_689_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_689_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_689_raw_sz;
  test.expected_result = -6;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_690(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 118,114,128,75,122,56,117,124,90,123,106,27,120,125,87,89,76,113,62,83,109,127,98,108,82,105,77,26,116,2,55,29,103,126,111,33,110,15,112,24,61,78,30,92,79,121,80 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_split_from_larger_sized_account::old_behavior";
  test.test_nonce  = 41;
  test.test_number = 690;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "2onLF6jBJ2H3pP82Zg3D18hXixEuCLgmk9i7syeLzziz",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 5957762UL;
  test_acc->result_lamports = 5957762UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_690_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_690_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_690_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_690_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "D3y8w1tHhByo5JKfWq1AuZ31cKxSyCLzy2UFV3ppEmEZ",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_690_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_690_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_690_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_690_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_690_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_690_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_690_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_690_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_690_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_690_raw_sz;
  test.expected_result = -6;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_691(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 1;
  uchar disabled_features[] = { 89 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_split_from_larger_sized_account::old_behavior";
  test.test_nonce  = 121;
  test.test_number = 691;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "HRHc87rF18iGtMCoVgUHDU1NJqLBNx1J97yU4TVPfFak",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 5957762UL;
  test_acc->result_lamports = 5957762UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_691_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_691_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_691_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_691_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "9J9zNapNff6DwyCpyqVEDgsfcwHf7hzfFCvVNS5iHWNS",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2282879UL;
  test_acc->result_lamports = 2282879UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_691_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_691_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_691_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_691_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_691_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_691_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_691_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_691_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_691_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_691_raw_sz;
  test.expected_result = -6;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_692(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 1;
  uchar disabled_features[] = { 89 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_split_from_larger_sized_account::old_behavior";
  test.test_nonce  = 173;
  test.test_number = 692;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "HRHc87rF18iGtMCoVgUHDU1NJqLBNx1J97yU4TVPfFak",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 5957762UL;
  test_acc->result_lamports = 5957762UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_692_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_692_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_692_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_692_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "9J9zNapNff6DwyCpyqVEDgsfcwHf7hzfFCvVNS5iHWNS",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2282880UL;
  test_acc->result_lamports = 2282880UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_692_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_692_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_692_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_692_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_692_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_692_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_692_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_692_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_692_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_692_raw_sz;
  test.expected_result = -6;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_693(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 1;
  uchar disabled_features[] = { 89 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_split_from_larger_sized_account::old_behavior";
  test.test_nonce  = 215;
  test.test_number = 693;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "HRHc87rF18iGtMCoVgUHDU1NJqLBNx1J97yU4TVPfFak",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 5957762UL;
  test_acc->result_lamports = 5957762UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_693_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_693_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_693_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_693_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "9J9zNapNff6DwyCpyqVEDgsfcwHf7hzfFCvVNS5iHWNS",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2282880UL;
  test_acc->result_lamports = 2282880UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_693_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_693_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_693_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_693_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_693_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_693_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_693_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_693_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_693_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_693_raw_sz;
  test.expected_result = -6;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_694(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 1;
  uchar disabled_features[] = { 89 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_split_from_larger_sized_account::old_behavior";
  test.test_nonce  = 261;
  test.test_number = 694;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "HRHc87rF18iGtMCoVgUHDU1NJqLBNx1J97yU4TVPfFak",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 5957762UL;
  test_acc->result_lamports = 5957762UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_694_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_694_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_694_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_694_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "9J9zNapNff6DwyCpyqVEDgsfcwHf7hzfFCvVNS5iHWNS",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2282881UL;
  test_acc->result_lamports = 2282881UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_694_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_694_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_694_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_694_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_694_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_694_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_694_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_694_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_694_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_694_raw_sz;
  test.expected_result = -6;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_695(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 1;
  uchar disabled_features[] = { 89 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_split_from_larger_sized_account::old_behavior";
  test.test_nonce  = 71;
  test.test_number = 695;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "HRHc87rF18iGtMCoVgUHDU1NJqLBNx1J97yU4TVPfFak",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 5957762UL;
  test_acc->result_lamports = 5957762UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_695_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_695_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_695_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_695_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "9J9zNapNff6DwyCpyqVEDgsfcwHf7hzfFCvVNS5iHWNS",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_695_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_695_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_695_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_695_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_695_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_695_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_695_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_695_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_695_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_695_raw_sz;
  test.expected_result = -6;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_696(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 2,26,105,24,110,124,87,90,106,89,30,111,125,29,98,15,123,126,78,108,82,79,109,117,61,122,118,76,116,120,92,113,121,80,114,56,77,33,103,75,62,112,83,55,127,27,128 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_split_from_smaller_sized_account::new_behavior";
  test.test_nonce  = 107;
  test.test_number = 696;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "34EqnSHtG7Li4KswcyrcZgGGksv4sacnmPq8ca1CuzAo",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2978881UL;
  test_acc->result_lamports = 2978881UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_696_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_696_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_696_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_696_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "DSYuVtwrpPPZDsZ3MDrm8p8znxQVJNUVXLKFyb4HrUPU",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_696_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_696_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_696_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_696_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_696_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_696_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_696_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_696_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_696_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_696_raw_sz;
  test.expected_result = -4;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_697(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 2,26,105,24,110,124,87,90,106,89,30,111,125,29,98,15,123,126,78,108,82,79,109,117,61,122,118,76,116,120,92,113,121,80,114,56,77,33,103,75,62,112,83,55,127,27,128 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_split_from_smaller_sized_account::new_behavior";
  test.test_nonce  = 156;
  test.test_number = 697;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "34EqnSHtG7Li4KswcyrcZgGGksv4sacnmPq8ca1CuzAo",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2978881UL;
  test_acc->result_lamports = 2978881UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_697_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_697_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_697_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_697_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "DSYuVtwrpPPZDsZ3MDrm8p8znxQVJNUVXLKFyb4HrUPU",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_697_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_697_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_697_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_697_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_697_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_697_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_697_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_697_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_697_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_697_raw_sz;
  test.expected_result = -4;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_698(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 2,26,105,24,110,124,87,90,106,89,30,111,125,29,98,15,123,126,78,108,82,79,109,117,61,122,118,76,116,120,92,113,121,80,114,56,77,33,103,75,62,112,83,55,127,27,128 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_split_from_smaller_sized_account::new_behavior";
  test.test_nonce  = 188;
  test.test_number = 698;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "34EqnSHtG7Li4KswcyrcZgGGksv4sacnmPq8ca1CuzAo",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2978881UL;
  test_acc->result_lamports = 2978881UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_698_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_698_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_698_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_698_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "DSYuVtwrpPPZDsZ3MDrm8p8znxQVJNUVXLKFyb4HrUPU",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2978880UL;
  test_acc->result_lamports = 2978880UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_698_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_698_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_698_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_698_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_698_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_698_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_698_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_698_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_698_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_698_raw_sz;
  test.expected_result = -4;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_699(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 2,26,105,24,110,124,87,90,106,89,30,111,125,29,98,15,123,126,78,108,82,79,109,117,61,122,118,76,116,120,92,113,121,80,114,56,77,33,103,75,62,112,83,55,127,27,128 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_split_from_smaller_sized_account::new_behavior";
  test.test_nonce  = 228;
  test.test_number = 699;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "34EqnSHtG7Li4KswcyrcZgGGksv4sacnmPq8ca1CuzAo",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2978881UL;
  test_acc->result_lamports = 2978881UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_699_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_699_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_699_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_699_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "DSYuVtwrpPPZDsZ3MDrm8p8znxQVJNUVXLKFyb4HrUPU",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2978881UL;
  test_acc->result_lamports = 2978881UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_699_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_699_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_699_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_699_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_699_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_699_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_699_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_699_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_699_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_699_raw_sz;
  test.expected_result = -4;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
