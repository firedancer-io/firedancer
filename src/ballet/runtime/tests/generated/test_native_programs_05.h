#include "../fd_tests.h"
int test_125(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 124,92,125,61,78,89,117,114,103,113,83,15,87,128,120,116,76,90,109,77,75,122,55,62,30,105,111,82,56,26,79,110,106,118,98,121,33,112,108,29,126,127,2,123,27,80,24 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_authorize_override::new_behavior";
  test.test_nonce  = 58;
  test.test_number = 125;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "9KE9CYxji5WJJt6jiMfeV41zntEbNv7FZCsKB1TyZ56P",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 42UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_125_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_125_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_125_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_125_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "ApbwCvbaVcpdM9Q1x3DKFstmuisYTgWmdqV3E21buzJR",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_125_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_125_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_125_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_125_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_125_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_125_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_125_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_125_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_125_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_125_raw_sz;
  test.expected_result = -8;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_126(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 1;
  uchar disabled_features[] = { 89 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_authorize_override::old_behavior";
  test.test_nonce  = 36;
  test.test_number = 126;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "7k6qLekdxcNDgkSbpAp1Vyyk9e2WLsHPJydumjVDddzQ",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 42UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_126_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_126_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_126_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_126_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "6i2SHbENrUxQ9jEZoMGakJ4Jhh44DbD7jJVbjFCzeYiq",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_126_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_126_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_126_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_126_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_126_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_126_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_126_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_126_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_126_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_126_raw_sz;
  test.expected_result = -8;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_127(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 1;
  uchar disabled_features[] = { 89 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_authorize_override::old_behavior";
  test.test_nonce  = 4;
  test.test_number = 127;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "7k6qLekdxcNDgkSbpAp1Vyyk9e2WLsHPJydumjVDddzQ",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 42UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_127_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_127_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_127_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_127_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "6i2SHbENrUxQ9jEZoMGakJ4Jhh44DbD7jJVbjFCzeYiq",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_127_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_127_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_127_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_127_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_127_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_127_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_127_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_127_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_127_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_127_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_128(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 1;
  uchar disabled_features[] = { 89 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_authorize_override::old_behavior";
  test.test_nonce  = 48;
  test.test_number = 128;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "7k6qLekdxcNDgkSbpAp1Vyyk9e2WLsHPJydumjVDddzQ",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 42UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_128_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_128_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_128_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_128_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "6i2SHbENrUxQ9jEZoMGakJ4Jhh44DbD7jJVbjFCzeYiq",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_128_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_128_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_128_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_128_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_128_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_128_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_128_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_128_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_128_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_128_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_129(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 1;
  uchar disabled_features[] = { 89 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_authorize_override::old_behavior";
  test.test_nonce  = 66;
  test.test_number = 129;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "7k6qLekdxcNDgkSbpAp1Vyyk9e2WLsHPJydumjVDddzQ",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 42UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_129_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_129_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_129_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_129_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "6i2SHbENrUxQ9jEZoMGakJ4Jhh44DbD7jJVbjFCzeYiq",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_129_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_129_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_129_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_129_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_129_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_129_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_129_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_129_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_129_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_129_raw_sz;
  test.expected_result = -8;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_130(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 56,87,62,27,2,92,89,79,30,29,109,103,26,24,110,116,61,106,75,121,123,33,83,108,82,90,127,78,76,124,120,80,55,113,125,105,128,122,111,77,112,117,98,114,118,126,15 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_authorize_override::old_behavior";
  test.test_nonce  = 2;
  test.test_number = 130;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "FMG1tTY6Se84bs2i3wXw4qUtKvenLy8G4UdAvJChnrbB",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 42UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_130_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_130_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_130_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_130_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "8hv2gVqbakMqksbysCYUen7YUcpwsyqao1XurR7yJQPW",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_130_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_130_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_130_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_130_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_130_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_130_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_130_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_130_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_130_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_130_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_131(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 56,87,62,27,2,92,89,79,30,29,109,103,26,24,110,116,61,106,75,121,123,33,83,108,82,90,127,78,76,124,120,80,55,113,125,105,128,122,111,77,112,117,98,114,118,126,15 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_authorize_override::old_behavior";
  test.test_nonce  = 77;
  test.test_number = 131;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "FMG1tTY6Se84bs2i3wXw4qUtKvenLy8G4UdAvJChnrbB",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 42UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_131_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_131_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_131_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_131_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "8hv2gVqbakMqksbysCYUen7YUcpwsyqao1XurR7yJQPW",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_131_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_131_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_131_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_131_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_131_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_131_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_131_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_131_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_131_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_131_raw_sz;
  test.expected_result = -8;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_132(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 56,87,62,27,2,92,89,79,30,29,109,103,26,24,110,116,61,106,75,121,123,33,83,108,82,90,127,78,76,124,120,80,55,113,125,105,128,122,111,77,112,117,98,114,118,126,15 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_authorize_override::old_behavior";
  test.test_nonce  = 112;
  test.test_number = 132;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "FMG1tTY6Se84bs2i3wXw4qUtKvenLy8G4UdAvJChnrbB",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 42UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_132_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_132_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_132_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_132_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "8hv2gVqbakMqksbysCYUen7YUcpwsyqao1XurR7yJQPW",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_132_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_132_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_132_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_132_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_132_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_132_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_132_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_132_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_132_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_132_raw_sz;
  test.expected_result = -8;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_133(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 56,87,62,27,2,92,89,79,30,29,109,103,26,24,110,116,61,106,75,121,123,33,83,108,82,90,127,78,76,124,120,80,55,113,125,105,128,122,111,77,112,117,98,114,118,126,15 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_authorize_override::old_behavior";
  test.test_nonce  = 94;
  test.test_number = 133;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "FMG1tTY6Se84bs2i3wXw4qUtKvenLy8G4UdAvJChnrbB",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 42UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_133_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_133_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_133_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_133_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "8hv2gVqbakMqksbysCYUen7YUcpwsyqao1XurR7yJQPW",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_133_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_133_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_133_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_133_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_133_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_133_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_133_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_133_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_133_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_133_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_134(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 1;
  uchar disabled_features[] = { 89 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_authorize_override::old_behavior";
  test.test_nonce  = 17;
  test.test_number = 134;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "7k6qLekdxcNDgkSbpAp1Vyyk9e2WLsHPJydumjVDddzQ",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 42UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_134_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_134_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_134_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_134_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "6i2SHbENrUxQ9jEZoMGakJ4Jhh44DbD7jJVbjFCzeYiq",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_134_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_134_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_134_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_134_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_134_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_134_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_134_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_134_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_134_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_134_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_135(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 56,87,62,27,2,92,89,79,30,29,109,103,26,24,110,116,61,106,75,121,123,33,83,108,82,90,127,78,76,124,120,80,55,113,125,105,128,122,111,77,112,117,98,114,118,126,15 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_authorize_override::old_behavior";
  test.test_nonce  = 47;
  test.test_number = 135;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "FMG1tTY6Se84bs2i3wXw4qUtKvenLy8G4UdAvJChnrbB",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 42UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_135_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_135_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_135_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_135_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "8hv2gVqbakMqksbysCYUen7YUcpwsyqao1XurR7yJQPW",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_135_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_135_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_135_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_135_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_135_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_135_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_135_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_135_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_135_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_135_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_136(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 56,87,62,27,2,92,89,79,30,29,109,103,26,24,110,116,61,106,75,121,123,33,83,108,82,90,127,78,76,124,120,80,55,113,125,105,128,122,111,77,112,117,98,114,118,126,15 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_authorize_with_seed::new_behavior";
  test.test_nonce  = 6;
  test.test_number = 136;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "DaTaGZGNqxDHAhxn2BsGChRi14ZfnjbJoJP8jam6MoBJ",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 42UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_136_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_136_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_136_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_136_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "GfuDkBiNrjSxjMQY2H8QXuNLArMEkmSdM2BkJcLJacsu",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_136_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_136_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_136_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_136_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_136_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_136_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_136_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_136_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_136_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_136_raw_sz;
  test.expected_result = -8;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_137(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 56,87,62,27,2,92,89,79,30,29,109,103,26,24,110,116,61,106,75,121,123,33,83,108,82,90,127,78,76,124,120,80,55,113,125,105,128,122,111,77,112,117,98,114,118,126,15 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_authorize_with_seed::new_behavior";
  test.test_nonce  = 28;
  test.test_number = 137;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "DaTaGZGNqxDHAhxn2BsGChRi14ZfnjbJoJP8jam6MoBJ",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 42UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_137_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_137_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_137_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_137_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "GfuDkBiNrjSxjMQY2H8QXuNLArMEkmSdM2BkJcLJacsu",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_137_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_137_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_137_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_137_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_137_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_137_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_137_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_137_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_137_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_137_raw_sz;
  test.expected_result = -8;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_138(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 56,87,62,27,2,92,89,79,30,29,109,103,26,24,110,116,61,106,75,121,123,33,83,108,82,90,127,78,76,124,120,80,55,113,125,105,128,122,111,77,112,117,98,114,118,126,15 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_authorize_with_seed::new_behavior";
  test.test_nonce  = 51;
  test.test_number = 138;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "DaTaGZGNqxDHAhxn2BsGChRi14ZfnjbJoJP8jam6MoBJ",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 42UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_138_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_138_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_138_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_138_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "GfuDkBiNrjSxjMQY2H8QXuNLArMEkmSdM2BkJcLJacsu",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_138_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_138_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_138_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_138_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_138_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_138_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_138_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_138_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_138_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_138_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_139(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 56,87,62,27,2,92,89,79,30,29,109,103,26,24,110,116,61,106,75,121,123,33,83,108,82,90,127,78,76,124,120,80,55,113,125,105,128,122,111,77,112,117,98,114,118,126,15 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_authorize_with_seed::new_behavior";
  test.test_nonce  = 74;
  test.test_number = 139;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "DaTaGZGNqxDHAhxn2BsGChRi14ZfnjbJoJP8jam6MoBJ",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 42UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_139_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_139_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_139_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_139_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "GfuDkBiNrjSxjMQY2H8QXuNLArMEkmSdM2BkJcLJacsu",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_139_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_139_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_139_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_139_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_139_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_139_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_139_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_139_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_139_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_139_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_140(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 56,87,62,27,2,92,89,79,30,29,109,103,26,24,110,116,61,106,75,121,123,33,83,108,82,90,127,78,76,124,120,80,55,113,125,105,128,122,111,77,112,117,98,114,118,126,15 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_authorize_with_seed::new_behavior";
  test.test_nonce  = 88;
  test.test_number = 140;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "DaTaGZGNqxDHAhxn2BsGChRi14ZfnjbJoJP8jam6MoBJ",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 42UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_140_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_140_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_140_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_140_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "GfuDkBiNrjSxjMQY2H8QXuNLArMEkmSdM2BkJcLJacsu",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_140_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_140_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_140_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_140_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_140_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_140_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_140_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_140_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_140_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_140_raw_sz;
  test.expected_result = -8;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_141(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 108,109,15,56,113,24,89,103,118,75,33,120,125,121,116,112,90,111,80,122,92,27,123,128,76,127,77,117,87,114,29,79,98,61,55,30,82,105,124,26,83,2,78,126,106,110,62 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_authorize_with_seed::new_behavior";
  test.test_nonce  = 20;
  test.test_number = 141;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "ANUK2tZFigWvhVX8ujGUftiiyyYgmUaNnN2yaXGmSsjn",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 42UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_141_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_141_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_141_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_141_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "DrnGrwnWCQoqSUXKnhsLeuq782VFneKHiBvtjZM7pmxr",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_141_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_141_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_141_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_141_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_141_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_141_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_141_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_141_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_141_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_141_raw_sz;
  test.expected_result = -8;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_142(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 108,109,15,56,113,24,89,103,118,75,33,120,125,121,116,112,90,111,80,122,92,27,123,128,76,127,77,117,87,114,29,79,98,61,55,30,82,105,124,26,83,2,78,126,106,110,62 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_authorize_with_seed::new_behavior";
  test.test_nonce  = 49;
  test.test_number = 142;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "ANUK2tZFigWvhVX8ujGUftiiyyYgmUaNnN2yaXGmSsjn",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 42UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_142_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_142_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_142_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_142_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "DrnGrwnWCQoqSUXKnhsLeuq782VFneKHiBvtjZM7pmxr",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_142_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_142_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_142_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_142_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_142_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_142_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_142_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_142_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_142_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_142_raw_sz;
  test.expected_result = -8;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_143(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 108,109,15,56,113,24,89,103,118,75,33,120,125,121,116,112,90,111,80,122,92,27,123,128,76,127,77,117,87,114,29,79,98,61,55,30,82,105,124,26,83,2,78,126,106,110,62 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_authorize_with_seed::new_behavior";
  test.test_nonce  = 78;
  test.test_number = 143;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "ANUK2tZFigWvhVX8ujGUftiiyyYgmUaNnN2yaXGmSsjn",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 42UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_143_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_143_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_143_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_143_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "DrnGrwnWCQoqSUXKnhsLeuq782VFneKHiBvtjZM7pmxr",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_143_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_143_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_143_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_143_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_143_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_143_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_143_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_143_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_143_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_143_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_144(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 108,109,15,56,113,24,89,103,118,75,33,120,125,121,116,112,90,111,80,122,92,27,123,128,76,127,77,117,87,114,29,79,98,61,55,30,82,105,124,26,83,2,78,126,106,110,62 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_authorize_with_seed::new_behavior";
  test.test_nonce  = 105;
  test.test_number = 144;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "ANUK2tZFigWvhVX8ujGUftiiyyYgmUaNnN2yaXGmSsjn",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 42UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_144_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_144_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_144_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_144_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "DrnGrwnWCQoqSUXKnhsLeuq782VFneKHiBvtjZM7pmxr",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_144_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_144_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_144_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_144_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_144_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_144_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_144_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_144_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_144_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_144_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_145(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 108,109,15,56,113,24,89,103,118,75,33,120,125,121,116,112,90,111,80,122,92,27,123,128,76,127,77,117,87,114,29,79,98,61,55,30,82,105,124,26,83,2,78,126,106,110,62 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_authorize_with_seed::new_behavior";
  test.test_nonce  = 121;
  test.test_number = 145;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "ANUK2tZFigWvhVX8ujGUftiiyyYgmUaNnN2yaXGmSsjn",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 42UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_145_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_145_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_145_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_145_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "DrnGrwnWCQoqSUXKnhsLeuq782VFneKHiBvtjZM7pmxr",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_145_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_145_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_145_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_145_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_145_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_145_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_145_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_145_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_145_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_145_raw_sz;
  test.expected_result = -8;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_146(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 1;
  uchar disabled_features[] = { 89 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_authorize_with_seed::old_behavior";
  test.test_nonce  = 5;
  test.test_number = 146;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "JAiEgimVAdz7y1BK7piKHkebTFSQwEguN4HWVbbvDmpR",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 42UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_146_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_146_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_146_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_146_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "DtsXRgow2QjurBSSvceN8JKug9fvPfZ1mKHsG649q8Qn",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_146_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_146_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_146_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_146_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_146_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_146_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_146_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_146_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_146_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_146_raw_sz;
  test.expected_result = -8;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_147(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 1;
  uchar disabled_features[] = { 89 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_authorize_with_seed::old_behavior";
  test.test_nonce  = 27;
  test.test_number = 147;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "JAiEgimVAdz7y1BK7piKHkebTFSQwEguN4HWVbbvDmpR",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 42UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_147_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_147_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_147_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_147_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "DtsXRgow2QjurBSSvceN8JKug9fvPfZ1mKHsG649q8Qn",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_147_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_147_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_147_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_147_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_147_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_147_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_147_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_147_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_147_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_147_raw_sz;
  test.expected_result = -8;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_148(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 1;
  uchar disabled_features[] = { 89 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_authorize_with_seed::old_behavior";
  test.test_nonce  = 49;
  test.test_number = 148;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "JAiEgimVAdz7y1BK7piKHkebTFSQwEguN4HWVbbvDmpR",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 42UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_148_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_148_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_148_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_148_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "DtsXRgow2QjurBSSvceN8JKug9fvPfZ1mKHsG649q8Qn",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_148_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_148_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_148_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_148_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_148_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_148_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_148_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_148_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_148_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_148_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_149(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 1;
  uchar disabled_features[] = { 89 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_authorize_with_seed::old_behavior";
  test.test_nonce  = 70;
  test.test_number = 149;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "JAiEgimVAdz7y1BK7piKHkebTFSQwEguN4HWVbbvDmpR",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 42UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_149_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_149_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_149_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_149_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "DtsXRgow2QjurBSSvceN8JKug9fvPfZ1mKHsG649q8Qn",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_149_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_149_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_149_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_149_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_149_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_149_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_149_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_149_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_149_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_149_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
