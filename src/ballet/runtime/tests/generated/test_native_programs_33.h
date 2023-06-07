#include "../fd_tests.h"
int test_825(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 113,79,109,114,82,92,78,106,126,123,90,76,55,30,105,33,75,15,127,26,62,124,87,112,121,128,29,122,27,98,80,83,61,120,116,108,77,125,24,56,89,117,118,103,111,110,2 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_split_source_uninitialized::new_behavior";
  test.test_nonce  = 152;
  test.test_number = 825;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 2;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "3yUG7VoXyG82btqgD2T5DkYTdf7Y6hxRFJhiw75Hq7Us",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2004565760UL;
  test_acc->result_lamports = 2004565760UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_825_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_825_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_825_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_825_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "FSd4tivd12HfVWRBFgXmKtSK3QbMh7yU2HV6LAZeFG5d",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_825_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_825_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_825_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_825_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_825_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_825_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_826(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 113,79,109,114,82,92,78,106,126,123,90,76,55,30,105,33,75,15,127,26,62,124,87,112,121,128,29,122,27,98,80,83,61,120,116,108,77,125,24,56,89,117,118,103,111,110,2 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_split_source_uninitialized::new_behavior";
  test.test_nonce  = 186;
  test.test_number = 826;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 2;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "3yUG7VoXyG82btqgD2T5DkYTdf7Y6hxRFJhiw75Hq7Us",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2004565760UL;
  test_acc->result_lamports = 1002282880UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_826_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_826_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_826_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_826_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "FSd4tivd12HfVWRBFgXmKtSK3QbMh7yU2HV6LAZeFG5d",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 1002282880UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_826_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_826_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_826_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_826_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_826_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_826_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_827(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 113,79,109,114,82,92,78,106,126,123,90,76,55,30,105,33,75,15,127,26,62,124,87,112,121,128,29,122,27,98,80,83,61,120,116,108,77,125,24,56,89,117,118,103,111,110,2 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_split_source_uninitialized::new_behavior";
  test.test_nonce  = 220;
  test.test_number = 827;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 2;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "3yUG7VoXyG82btqgD2T5DkYTdf7Y6hxRFJhiw75Hq7Us",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2004565760UL;
  test_acc->result_lamports = 2004565760UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_827_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_827_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_827_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_827_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "FSd4tivd12HfVWRBFgXmKtSK3QbMh7yU2HV6LAZeFG5d",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_827_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_827_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_827_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_827_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_827_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_827_raw_sz;
  test.expected_result = -8;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_828(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 1;
  uchar disabled_features[] = { 89 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_split_source_uninitialized::old_behavior";
  test.test_nonce  = 130;
  test.test_number = 828;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 2;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "4DevouK2m1zSqLjVj9aXeWnjvf1fZTFHKU1eBSDZrjWC",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 4565762UL;
  test_acc->result_lamports = 4565762UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_828_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_828_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_828_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_828_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "DAaBC8sz7ViXFbnueSJ5gZqyqokwzZ9uoq15NrM2J1Ve",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_828_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_828_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_828_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_828_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_828_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_828_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_829(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 30,62,55,113,124,112,105,76,87,79,118,121,29,56,110,61,24,90,80,125,98,122,83,108,27,106,128,114,15,82,33,2,77,120,103,26,123,89,92,75,111,126,116,109,127,78,117 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_split_source_uninitialized::old_behavior";
  test.test_nonce  = 100;
  test.test_number = 829;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 2;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "CqiaEDp1DS7GQmNc7bz7ZWQnH4eJjcFatbNYzwVLhYGW",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 4565762UL;
  test_acc->result_lamports = 4565762UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_829_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_829_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_829_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_829_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "72FGiwpfU3vjXfgX7vu4zuUN84rYiLmKu1TjknCshvbg",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_829_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_829_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_829_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_829_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_829_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_829_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_830(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 1;
  uchar disabled_features[] = { 89 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_split_source_uninitialized::old_behavior";
  test.test_nonce  = 98;
  test.test_number = 830;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 2;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "4DevouK2m1zSqLjVj9aXeWnjvf1fZTFHKU1eBSDZrjWC",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 4565762UL;
  test_acc->result_lamports = 4565762UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_830_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_830_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_830_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_830_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "DAaBC8sz7ViXFbnueSJ5gZqyqokwzZ9uoq15NrM2J1Ve",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_830_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_830_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_830_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_830_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_830_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_830_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_831(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 30,62,55,113,124,112,105,76,87,79,118,121,29,56,110,61,24,90,80,125,98,122,83,108,27,106,128,114,15,82,33,2,77,120,103,26,123,89,92,75,111,126,116,109,127,78,117 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_split_source_uninitialized::old_behavior";
  test.test_nonce  = 59;
  test.test_number = 831;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 2;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "CqiaEDp1DS7GQmNc7bz7ZWQnH4eJjcFatbNYzwVLhYGW",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 4565762UL;
  test_acc->result_lamports = 4565762UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_831_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_831_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_831_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_831_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "72FGiwpfU3vjXfgX7vu4zuUN84rYiLmKu1TjknCshvbg",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_831_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_831_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_831_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_831_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_831_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_831_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_832(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 1;
  uchar disabled_features[] = { 89 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_split_source_uninitialized::old_behavior";
  test.test_nonce  = 146;
  test.test_number = 832;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 2;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "4DevouK2m1zSqLjVj9aXeWnjvf1fZTFHKU1eBSDZrjWC",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 4565762UL;
  test_acc->result_lamports = 4565762UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_832_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_832_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_832_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_832_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "DAaBC8sz7ViXFbnueSJ5gZqyqokwzZ9uoq15NrM2J1Ve",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_832_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_832_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_832_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_832_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_832_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_832_raw_sz;
  test.expected_result = -6;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_833(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 30,62,55,113,124,112,105,76,87,79,118,121,29,56,110,61,24,90,80,125,98,122,83,108,27,106,128,114,15,82,33,2,77,120,103,26,123,89,92,75,111,126,116,109,127,78,117 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_split_source_uninitialized::old_behavior";
  test.test_nonce  = 148;
  test.test_number = 833;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 2;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "CqiaEDp1DS7GQmNc7bz7ZWQnH4eJjcFatbNYzwVLhYGW",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 4565762UL;
  test_acc->result_lamports = 4565762UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_833_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_833_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_833_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_833_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "72FGiwpfU3vjXfgX7vu4zuUN84rYiLmKu1TjknCshvbg",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_833_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_833_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_833_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_833_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_833_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_833_raw_sz;
  test.expected_result = -6;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_834(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 1;
  uchar disabled_features[] = { 89 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_split_source_uninitialized::old_behavior";
  test.test_nonce  = 140;
  test.test_number = 834;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 2;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "4DevouK2m1zSqLjVj9aXeWnjvf1fZTFHKU1eBSDZrjWC",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 4565762UL;
  test_acc->result_lamports = 4565762UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_834_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_834_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_834_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_834_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "DAaBC8sz7ViXFbnueSJ5gZqyqokwzZ9uoq15NrM2J1Ve",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_834_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_834_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_834_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_834_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_834_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_834_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_835(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 1;
  uchar disabled_features[] = { 89 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_split_source_uninitialized::old_behavior";
  test.test_nonce  = 148;
  test.test_number = 835;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 2;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "4DevouK2m1zSqLjVj9aXeWnjvf1fZTFHKU1eBSDZrjWC",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 4565762UL;
  test_acc->result_lamports = 2282881UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_835_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_835_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_835_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_835_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "DAaBC8sz7ViXFbnueSJ5gZqyqokwzZ9uoq15NrM2J1Ve",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 2282881UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_835_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_835_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_835_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_835_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_835_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_835_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_836(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 1;
  uchar disabled_features[] = { 89 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_split_source_uninitialized::old_behavior";
  test.test_nonce  = 159;
  test.test_number = 836;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 2;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "4DevouK2m1zSqLjVj9aXeWnjvf1fZTFHKU1eBSDZrjWC",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 4565762UL;
  test_acc->result_lamports = 4565762UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_836_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_836_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_836_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_836_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "DAaBC8sz7ViXFbnueSJ5gZqyqokwzZ9uoq15NrM2J1Ve",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_836_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_836_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_836_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_836_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_836_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_836_raw_sz;
  test.expected_result = -8;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_837(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 30,62,55,113,124,112,105,76,87,79,118,121,29,56,110,61,24,90,80,125,98,122,83,108,27,106,128,114,15,82,33,2,77,120,103,26,123,89,92,75,111,126,116,109,127,78,117 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_split_source_uninitialized::old_behavior";
  test.test_nonce  = 113;
  test.test_number = 837;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 2;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "CqiaEDp1DS7GQmNc7bz7ZWQnH4eJjcFatbNYzwVLhYGW",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 4565762UL;
  test_acc->result_lamports = 4565762UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_837_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_837_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_837_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_837_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "72FGiwpfU3vjXfgX7vu4zuUN84rYiLmKu1TjknCshvbg",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_837_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_837_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_837_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_837_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_837_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_837_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_838(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 30,62,55,113,124,112,105,76,87,79,118,121,29,56,110,61,24,90,80,125,98,122,83,108,27,106,128,114,15,82,33,2,77,120,103,26,123,89,92,75,111,126,116,109,127,78,117 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_split_source_uninitialized::old_behavior";
  test.test_nonce  = 170;
  test.test_number = 838;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 2;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "CqiaEDp1DS7GQmNc7bz7ZWQnH4eJjcFatbNYzwVLhYGW",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 4565762UL;
  test_acc->result_lamports = 2282881UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_838_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_838_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_838_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_838_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "72FGiwpfU3vjXfgX7vu4zuUN84rYiLmKu1TjknCshvbg",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 2282881UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_838_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_838_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_838_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_838_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_838_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_838_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_839(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 30,62,55,113,124,112,105,76,87,79,118,121,29,56,110,61,24,90,80,125,98,122,83,108,27,106,128,114,15,82,33,2,77,120,103,26,123,89,92,75,111,126,116,109,127,78,117 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_split_source_uninitialized::old_behavior";
  test.test_nonce  = 187;
  test.test_number = 839;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 2;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "CqiaEDp1DS7GQmNc7bz7ZWQnH4eJjcFatbNYzwVLhYGW",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 4565762UL;
  test_acc->result_lamports = 4565762UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_839_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_839_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_839_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_839_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "72FGiwpfU3vjXfgX7vu4zuUN84rYiLmKu1TjknCshvbg",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_839_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_839_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_839_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_839_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_839_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_839_raw_sz;
  test.expected_result = -8;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_840(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 61,80,89,110,103,125,111,114,120,105,108,112,27,33,123,116,118,113,29,55,30,83,90,2,76,75,122,98,15,124,109,126,82,106,77,56,26,121,127,128,117,78,62,92,87,24,79 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_split_split_not_uninitialized::new_behavior";
  test.test_nonce  = 110;
  test.test_number = 840;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 2;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "9GhGP5W8qw3AfhY7BCkVrzgCvVnrStBrho8zHN6Xr75s",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 42UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_840_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_840_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_840_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_840_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "9percktZUYYtaDq2M34x3koa4S9ZntquyrdfRu9SLScu",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_840_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_840_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_840_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_840_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_840_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_840_raw_sz;
  test.expected_result = -4;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_841(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 61,80,89,110,103,125,111,114,120,105,108,112,27,33,123,116,118,113,29,55,30,83,90,2,76,75,122,98,15,124,109,126,82,106,77,56,26,121,127,128,117,78,62,92,87,24,79 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_split_split_not_uninitialized::new_behavior";
  test.test_nonce  = 133;
  test.test_number = 841;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 2;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "9GhGP5W8qw3AfhY7BCkVrzgCvVnrStBrho8zHN6Xr75s",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 42UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_841_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_841_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_841_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_841_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "9percktZUYYtaDq2M34x3koa4S9ZntquyrdfRu9SLScu",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_841_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_841_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_841_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_841_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_841_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_841_raw_sz;
  test.expected_result = -4;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_842(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 61,80,89,110,103,125,111,114,120,105,108,112,27,33,123,116,118,113,29,55,30,83,90,2,76,75,122,98,15,124,109,126,82,106,77,56,26,121,127,128,117,78,62,92,87,24,79 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_split_split_not_uninitialized::new_behavior";
  test.test_nonce  = 82;
  test.test_number = 842;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 2;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "9GhGP5W8qw3AfhY7BCkVrzgCvVnrStBrho8zHN6Xr75s",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 42UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_842_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_842_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_842_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_842_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "9percktZUYYtaDq2M34x3koa4S9ZntquyrdfRu9SLScu",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_842_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_842_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_842_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_842_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_842_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_842_raw_sz;
  test.expected_result = -4;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_843(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 61,80,89,110,103,125,111,114,120,105,108,112,27,33,123,116,118,113,29,55,30,83,90,2,76,75,122,98,15,124,109,126,82,106,77,56,26,121,127,128,117,78,62,92,87,24,79 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_split_split_not_uninitialized::new_behavior";
  test.test_nonce  = 128;
  test.test_number = 843;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 2;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "CoMM5FTnZFHGfLenokiwZRZLe615khS11SsH6uuDmjos",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 42UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_843_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_843_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_843_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_843_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "GogQvcZTm88jEZSjBUt87yxNAzgDZ8LeH24eWv9Bkrjh",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_843_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_843_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_843_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_843_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_843_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_843_raw_sz;
  test.expected_result = -4;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_844(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 61,80,89,110,103,125,111,114,120,105,108,112,27,33,123,116,118,113,29,55,30,83,90,2,76,75,122,98,15,124,109,126,82,106,77,56,26,121,127,128,117,78,62,92,87,24,79 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_split_split_not_uninitialized::new_behavior";
  test.test_nonce  = 158;
  test.test_number = 844;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 2;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "CoMM5FTnZFHGfLenokiwZRZLe615khS11SsH6uuDmjos",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 42UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_844_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_844_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_844_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_844_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "GogQvcZTm88jEZSjBUt87yxNAzgDZ8LeH24eWv9Bkrjh",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_844_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_844_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_844_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_844_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_844_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_844_raw_sz;
  test.expected_result = -4;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_845(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 61,80,89,110,103,125,111,114,120,105,108,112,27,33,123,116,118,113,29,55,30,83,90,2,76,75,122,98,15,124,109,126,82,106,77,56,26,121,127,128,117,78,62,92,87,24,79 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_split_split_not_uninitialized::new_behavior";
  test.test_nonce  = 165;
  test.test_number = 845;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 2;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "CoMM5FTnZFHGfLenokiwZRZLe615khS11SsH6uuDmjos",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 42UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_845_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_845_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_845_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_845_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "GogQvcZTm88jEZSjBUt87yxNAzgDZ8LeH24eWv9Bkrjh",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_845_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_845_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_845_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_845_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_845_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_845_raw_sz;
  test.expected_result = -4;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_846(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 29,108,83,30,128,62,61,117,105,2,78,24,56,122,120,123,109,125,33,113,82,106,110,121,77,87,75,114,76,118,98,116,55,79,126,127,26,111,124,15,103,27,90,112,89,80,92 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_split_split_not_uninitialized::old_behavior";
  test.test_nonce  = 125;
  test.test_number = 846;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 2;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "B7R1xjWE3MsUxGMP5NakMNMXiiXvbbDhJVf9xATL15Ss",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 42UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_846_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_846_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_846_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_846_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "BvMFTV61idzLhVXdp9HpLExRvaxcEH6Tk52BBXAWM98R",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_846_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_846_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_846_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_846_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_846_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_846_raw_sz;
  test.expected_result = -4;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_847(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 29,108,83,30,128,62,61,117,105,2,78,24,56,122,120,123,109,125,33,113,82,106,110,121,77,87,75,114,76,118,98,116,55,79,126,127,26,111,124,15,103,27,90,112,89,80,92 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_split_split_not_uninitialized::old_behavior";
  test.test_nonce  = 146;
  test.test_number = 847;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 2;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "B7R1xjWE3MsUxGMP5NakMNMXiiXvbbDhJVf9xATL15Ss",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 42UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_847_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_847_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_847_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_847_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "BvMFTV61idzLhVXdp9HpLExRvaxcEH6Tk52BBXAWM98R",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_847_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_847_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_847_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_847_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_847_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_847_raw_sz;
  test.expected_result = -4;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_848(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 29,108,83,30,128,62,61,117,105,2,78,24,56,122,120,123,109,125,33,113,82,106,110,121,77,87,75,114,76,118,98,116,55,79,126,127,26,111,124,15,103,27,90,112,89,80,92 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_split_split_not_uninitialized::old_behavior";
  test.test_nonce  = 85;
  test.test_number = 848;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 2;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "B7R1xjWE3MsUxGMP5NakMNMXiiXvbbDhJVf9xATL15Ss",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 42UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_848_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_848_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_848_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_848_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "BvMFTV61idzLhVXdp9HpLExRvaxcEH6Tk52BBXAWM98R",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_848_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_848_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_848_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_848_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_848_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_848_raw_sz;
  test.expected_result = -4;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_849(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 1;
  uchar disabled_features[] = { 89 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_split_split_not_uninitialized::old_behavior";
  test.test_nonce  = 179;
  test.test_number = 849;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 2;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "2GMLBtqE2TDukq4vEZLAcsFgWq98WTqdFo8kBubK8Zt1",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 42UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_849_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_849_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_849_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_849_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "DZQnG3YvLc37ZSiQRCRqsg5uSRugEo7MC6e6YXTRCW59",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_849_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_849_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_849_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_849_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_849_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_849_raw_sz;
  test.expected_result = -4;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
