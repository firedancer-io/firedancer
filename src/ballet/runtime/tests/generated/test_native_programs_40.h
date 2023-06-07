#include "../fd_tests.h"
int test_1000(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 29,61,2,126,106,123,117,90,55,122,111,33,76,92,121,82,24,15,79,110,62,30,77,87,124,75,105,116,127,108,114,26,78,112,120,109,83,113,103,56,80,128,118,89,98,27,125 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_stake_checked_instructions::old_behavior";
  test.test_nonce  = 293;
  test.test_number = 1000;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 4;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111111KWYkHziFfJKJcwQz8JKfJmXBxCrPhmqKYs",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1000_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1000_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1000_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1000_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111JhsYKn7gEwPYz58p5Tf2LWychCLWHJfevB",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1000_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1000_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1000_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1000_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1000_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1000_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1000_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1000_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111FVAiSujNZVgYSc27t6zUTWoKfAGxbRzzPR",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1000_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1000_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1000_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1000_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1000_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1000_raw_sz;
  test.expected_result = -8;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1001(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 29,61,2,126,106,123,117,90,55,122,111,33,76,92,121,82,24,15,79,110,62,30,77,87,124,75,105,116,127,108,114,26,78,112,120,109,83,113,103,56,80,128,118,89,98,27,125 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_stake_checked_instructions::old_behavior";
  test.test_nonce  = 337;
  test.test_number = 1001;
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
  test_acc->data            = fd_flamenco_native_prog_test_1001_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1001_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1001_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1001_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1001_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1001_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1001_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1001_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111KWYkHziFfJKJcwQz8JKfJmXBxCrPhmqKYs",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "1111111KutMH71YNUnBSNZ59ieyntnyai7LR1R9sD",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1001_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1001_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1001_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1001_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111JhsYKn7gEwPYz58p5Tf2LWychCLWHJfevB",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "1111111LKDxGDJq5fF4FohAB8zJH24mDDNH8EzzBZ",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1001_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1001_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1001_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1001_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1001_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1001_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1002(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 1;
  uchar disabled_features[] = { 89 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_stake_checked_instructions::old_behavior";
  test.test_nonce  = 275;
  test.test_number = 1002;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 4;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111111KWYkHziFfJKJcwQz8JKfJmXBxCrPhmqKYs",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1002_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1002_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1002_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1002_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111LKDxGDJq5fF4FohAB8zJH24mDDNH8EzzBZ",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1002_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1002_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1002_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1002_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111JJXwLfpPXkvgAdzj43KhrPhq4h5Za55pbq",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1002_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1002_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1002_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1002_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1002_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1002_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1002_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1002_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1002_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1002_raw_sz;
  test.expected_result = -8;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1003(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 1;
  uchar disabled_features[] = { 89 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_stake_checked_instructions::old_behavior";
  test.test_nonce  = 332;
  test.test_number = 1003;
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
  test_acc->data            = fd_flamenco_native_prog_test_1003_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1003_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1003_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1003_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1003_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1003_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1003_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1003_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111LKDxGDJq5fF4FohAB8zJH24mDDNH8EzzBZ",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "1111111LiZZFKc7nqhw5EqFCZKcm9LYqidDqUapVu",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1003_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1003_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1003_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1003_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111KWYkHziFfJKJcwQz8JKfJmXBxCrPhmqKYs",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "1111111M7uAERuQW2AotfyLDyewFGcLUDtAYiAepF",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1003_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1003_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1003_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1003_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1003_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1003_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1004(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 29,61,2,126,106,123,117,90,55,122,111,33,76,92,121,82,24,15,79,110,62,30,77,87,124,75,105,116,127,108,114,26,78,112,120,109,83,113,103,56,80,128,118,89,98,27,125 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_stake_checked_instructions::old_behavior";
  test.test_nonce  = 356;
  test.test_number = 1004;
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
  test_acc->data            = fd_flamenco_native_prog_test_1004_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1004_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1004_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1004_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111FVAiSujNZVgYSc27t6zUTWoKfAGxbRzzPR",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1004_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1004_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1004_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1004_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1004_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1004_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1004_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1004_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111k4AYMctpyJakWNvGcte6tR8BLyZw54R8qu",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1004_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1004_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1004_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1004_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1004_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1004_raw_sz;
  test.expected_result = -8;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1005(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 29,61,2,126,106,123,117,90,55,122,111,33,76,92,121,82,24,15,79,110,62,30,77,87,124,75,105,116,127,108,114,26,78,112,120,109,83,113,103,56,80,128,118,89,98,27,125 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_stake_checked_instructions::old_behavior";
  test.test_nonce  = 401;
  test.test_number = 1005;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 4;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "2Nup69Pg93efgRC5RxCd1LNnvS7dmbL1tBgL5iX8Cgig",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 42UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1005_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1005_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1005_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1005_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111k4AYMctpyJakWNvGcte6tR8BLyZw54R8qu",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "1111111KutMH71YNUnBSNZ59ieyntnyai7LR1R9sD",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1005_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1005_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1005_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1005_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1005_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1005_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1005_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1005_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111GhBXQEdEh35AtuSNxMzRutcgYg3nj8kVLT",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "1111111LKDxGDJq5fF4FohAB8zJH24mDDNH8EzzBZ",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1005_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1005_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1005_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1005_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1005_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1005_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1006(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 1;
  uchar disabled_features[] = { 89 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_stake_checked_instructions::old_behavior";
  test.test_nonce  = 345;
  test.test_number = 1006;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 4;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111111k4AYMctpyJakWNvGcte6tR8BLyZw54R8qu",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1006_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1006_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1006_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1006_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1006_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1006_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1006_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1006_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111JhsYKn7gEwPYz58p5Tf2LWychCLWHJfevB",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1006_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1006_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1006_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1006_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111JJXwLfpPXkvgAdzj43KhrPhq4h5Za55pbq",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1006_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1006_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1006_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1006_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1006_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1006_raw_sz;
  test.expected_result = -8;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1007(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 1;
  uchar disabled_features[] = { 89 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_stake_checked_instructions::old_behavior";
  test.test_nonce  = 366;
  test.test_number = 1007;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 4;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "2Nup69Pg93efgRC5RxCd1LNnvS7dmbL1tBgL5iX8Cgig",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 42UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1007_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1007_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1007_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1007_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111k4AYMctpyJakWNvGcte6tR8BLyZw54R8qu",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "1111111LiZZFKc7nqhw5EqFCZKcm9LYqidDqUapVu",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1007_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1007_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1007_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1007_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1007_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1007_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1007_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1007_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111JhsYKn7gEwPYz58p5Tf2LWychCLWHJfevB",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "1111111M7uAERuQW2AotfyLDyewFGcLUDtAYiAepF",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1007_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1007_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1007_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1007_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1007_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1007_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1008(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 29,61,2,126,106,123,117,90,55,122,111,33,76,92,121,82,24,15,79,110,62,30,77,87,124,75,105,116,127,108,114,26,78,112,120,109,83,113,103,56,80,128,118,89,98,27,125 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_stake_checked_instructions::old_behavior";
  test.test_nonce  = 377;
  test.test_number = 1008;
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
  test_acc->data            = fd_flamenco_native_prog_test_1008_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1008_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1008_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1008_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111GhBXQEdEh35AtuSNxMzRutcgYg3nj8kVLT",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1008_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1008_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1008_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1008_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111FVAiSujNZVgYSc27t6zUTWoKfAGxbRzzPR",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1008_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1008_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1008_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1008_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111k4AYMctpyJakWNvGcte6tR8BLyZw54R8qu",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1008_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1008_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1008_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1008_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1008_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1008_raw_sz;
  test.expected_result = -8;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1009(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 29,61,2,126,106,123,117,90,55,122,111,33,76,92,121,82,24,15,79,110,62,30,77,87,124,75,105,116,127,108,114,26,78,112,120,109,83,113,103,56,80,128,118,89,98,27,125 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_stake_checked_instructions::old_behavior";
  test.test_nonce  = 417;
  test.test_number = 1009;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 4;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "2Nup69Pg93efgRC5RxCd1LNnvS7dmbL1tBgL5iX8Cgig",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 42UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1009_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1009_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1009_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1009_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111k4AYMctpyJakWNvGcte6tR8BLyZw54R8qu",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "1111111KutMH71YNUnBSNZ59ieyntnyai7LR1R9sD",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1009_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1009_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1009_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1009_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1009_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1009_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1009_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1009_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111JhsYKn7gEwPYz58p5Tf2LWychCLWHJfevB",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "1111111LKDxGDJq5fF4FohAB8zJH24mDDNH8EzzBZ",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1009_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1009_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1009_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1009_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1009_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1009_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1010(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 1;
  uchar disabled_features[] = { 89 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_stake_checked_instructions::old_behavior";
  test.test_nonce  = 355;
  test.test_number = 1010;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 4;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111111k4AYMctpyJakWNvGcte6tR8BLyZw54R8qu",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1010_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1010_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1010_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1010_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1010_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1010_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1010_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1010_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111JJXwLfpPXkvgAdzj43KhrPhq4h5Za55pbq",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1010_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1010_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1010_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1010_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111JhsYKn7gEwPYz58p5Tf2LWychCLWHJfevB",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1010_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1010_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1010_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1010_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1010_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1010_raw_sz;
  test.expected_result = -8;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1011(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 1;
  uchar disabled_features[] = { 89 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_stake_checked_instructions::old_behavior";
  test.test_nonce  = 375;
  test.test_number = 1011;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 4;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "2Nup69Pg93efgRC5RxCd1LNnvS7dmbL1tBgL5iX8Cgig",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 42UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1011_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1011_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1011_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1011_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111k4AYMctpyJakWNvGcte6tR8BLyZw54R8qu",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "1111111LiZZFKc7nqhw5EqFCZKcm9LYqidDqUapVu",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1011_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1011_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1011_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1011_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1011_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1011_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1011_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1011_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111KWYkHziFfJKJcwQz8JKfJmXBxCrPhmqKYs",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "1111111M7uAERuQW2AotfyLDyewFGcLUDtAYiAepF",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1011_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1011_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1011_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1011_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1011_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1011_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1012(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 29,61,2,126,106,123,117,90,55,122,111,33,76,92,121,82,24,15,79,110,62,30,77,87,124,75,105,116,127,108,114,26,78,112,120,109,83,113,103,56,80,128,118,89,98,27,125 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_stake_checked_instructions::old_behavior";
  test.test_nonce  = 442;
  test.test_number = 1012;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 4;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111111LiZZFKc7nqhw5EqFCZKcm9LYqidDqUapVu",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1012_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1012_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1012_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1012_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111FVAiSujNZVgYSc27t6zUTWoKfAGxbRzzPR",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1012_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1012_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1012_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1012_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111JhsYKn7gEwPYz58p5Tf2LWychCLWHJfevB",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1012_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1012_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1012_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1012_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1012_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1012_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1012_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1012_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1012_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1012_raw_sz;
  test.expected_result = -8;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1013(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 29,61,2,126,106,123,117,90,55,122,111,33,76,92,121,82,24,15,79,110,62,30,77,87,124,75,105,116,127,108,114,26,78,112,120,109,83,113,103,56,80,128,118,89,98,27,125 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_stake_checked_instructions::old_behavior";
  test.test_nonce  = 461;
  test.test_number = 1013;
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
  test_acc->data            = fd_flamenco_native_prog_test_1013_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1013_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1013_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1013_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111FVAiSujNZVgYSc27t6zUTWoKfAGxbRzzPR",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 42UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1013_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1013_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1013_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1013_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111JhsYKn7gEwPYz58p5Tf2LWychCLWHJfevB",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "1111111K7D9JtQxx7rRoWGu6szLpeFQKhbSzYFVEX",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1013_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1013_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1013_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1013_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111LiZZFKc7nqhw5EqFCZKcm9LYqidDqUapVu",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "1111111M7uAERuQW2AotfyLDyewFGcLUDtAYiAepF",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1013_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1013_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1013_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1013_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1013_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1013_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1014(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 1;
  uchar disabled_features[] = { 89 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_stake_checked_instructions::old_behavior";
  test.test_nonce  = 386;
  test.test_number = 1014;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 4;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111111JJXwLfpPXkvgAdzj43KhrPhq4h5Za55pbq",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1014_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1014_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1014_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1014_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111KWYkHziFfJKJcwQz8JKfJmXBxCrPhmqKYs",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1014_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1014_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1014_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1014_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1014_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1014_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1014_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1014_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111MXEmDYChDCdgi77RFPzFjPt86j97FwkV8b",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1014_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1014_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1014_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1014_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1014_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1014_raw_sz;
  test.expected_result = -8;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1015(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 1;
  uchar disabled_features[] = { 89 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_stake_checked_instructions::old_behavior";
  test.test_nonce  = 396;
  test.test_number = 1015;
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
  test_acc->data            = fd_flamenco_native_prog_test_1015_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1015_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1015_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1015_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111JJXwLfpPXkvgAdzj43KhrPhq4h5Za55pbq",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 42UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1015_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1015_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1015_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1015_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111KWYkHziFfJKJcwQz8JKfJmXBxCrPhmqKYs",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "1111111KutMH71YNUnBSNZ59ieyntnyai7LR1R9sD",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1015_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1015_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1015_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1015_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111MXEmDYChDCdgi77RFPzFjPt86j97FwkV8b",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "1111111MvaNCeVyvP6ZXYFWGpKaDX9ujEQ3yBLKSw",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1015_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1015_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1015_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1015_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1015_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1015_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1016(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 26,90,103,79,112,15,56,29,116,75,2,111,76,24,114,78,98,80,110,127,62,113,125,123,117,124,77,126,27,87,105,92,61,108,33,128,120,106,118,30,82,89,55,121,83,109,122 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_stake_delegate::new_behavior";
  test.test_nonce  = 301;
  test.test_number = 1016;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 6;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "7vE2aTfQk6WeBaTnb7RJbRb9e1psH6GGf1ZYHTo3X8Ry",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1000000000UL;
  test_acc->result_lamports = 1000000000UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1016_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1016_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1016_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1016_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "HezP98LPSimUAXSkHQRfXsqUsMthfuHnDRJvWqJMiW2k",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1016_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1016_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1016_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1016_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "FmLQHWGUvVe3rKhFrm6tHus1gKvEXtH5StcEFzZpeZJS",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1016_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1016_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1016_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1016_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1016_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1016_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1016_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1016_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1016_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1016_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1016_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1016_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "StakeConfig11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1016_acc_5_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1016_acc_5_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1016_acc_5_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1016_acc_5_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1016_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1016_raw_sz;
  test.expected_result = -8;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1017(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 26,90,103,79,112,15,56,29,116,75,2,111,76,24,114,78,98,80,110,127,62,113,125,123,117,124,77,126,27,87,105,92,61,108,33,128,120,106,118,30,82,89,55,121,83,109,122 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_stake_delegate::new_behavior";
  test.test_nonce  = 424;
  test.test_number = 1017;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 6;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "7vE2aTfQk6WeBaTnb7RJbRb9e1psH6GGf1ZYHTo3X8Ry",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1000000000UL;
  test_acc->result_lamports = 1000000000UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1017_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1017_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1017_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1017_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "HezP98LPSimUAXSkHQRfXsqUsMthfuHnDRJvWqJMiW2k",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1017_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1017_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1017_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1017_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "FmLQHWGUvVe3rKhFrm6tHus1gKvEXtH5StcEFzZpeZJS",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1017_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1017_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1017_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1017_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1017_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1017_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1017_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1017_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1017_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1017_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1017_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1017_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "StakeConfig11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1017_acc_5_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1017_acc_5_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1017_acc_5_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1017_acc_5_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1017_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1017_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1018(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 26,90,103,79,112,15,56,29,116,75,2,111,76,24,114,78,98,80,110,127,62,113,125,123,117,124,77,126,27,87,105,92,61,108,33,128,120,106,118,30,82,89,55,121,83,109,122 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_stake_delegate::new_behavior";
  test.test_nonce  = 493;
  test.test_number = 1018;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 6;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "7vE2aTfQk6WeBaTnb7RJbRb9e1psH6GGf1ZYHTo3X8Ry",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1000000000UL;
  test_acc->result_lamports = 1000000000UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1018_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1018_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1018_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1018_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "HezP98LPSimUAXSkHQRfXsqUsMthfuHnDRJvWqJMiW2k",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1018_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1018_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1018_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1018_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "FmLQHWGUvVe3rKhFrm6tHus1gKvEXtH5StcEFzZpeZJS",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1018_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1018_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1018_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1018_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1018_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1018_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1018_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1018_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1018_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1018_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1018_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1018_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "StakeConfig11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1018_acc_5_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1018_acc_5_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1018_acc_5_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1018_acc_5_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1018_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1018_raw_sz;
  test.expected_result = -26;
  test.custom_err = 3;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1019(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 26,90,103,79,112,15,56,29,116,75,2,111,76,24,114,78,98,80,110,127,62,113,125,123,117,124,77,126,27,87,105,92,61,108,33,128,120,106,118,30,82,89,55,121,83,109,122 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_stake_delegate::new_behavior";
  test.test_nonce  = 582;
  test.test_number = 1019;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 6;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "7vE2aTfQk6WeBaTnb7RJbRb9e1psH6GGf1ZYHTo3X8Ry",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1000000000UL;
  test_acc->result_lamports = 1000000000UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1019_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1019_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1019_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1019_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "HezP98LPSimUAXSkHQRfXsqUsMthfuHnDRJvWqJMiW2k",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1019_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1019_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1019_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1019_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "FmLQHWGUvVe3rKhFrm6tHus1gKvEXtH5StcEFzZpeZJS",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1019_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1019_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1019_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1019_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1019_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1019_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1019_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1019_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1019_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1019_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1019_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1019_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "StakeConfig11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1019_acc_5_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1019_acc_5_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1019_acc_5_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1019_acc_5_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1019_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1019_raw_sz;
  test.expected_result = -26;
  test.custom_err = 3;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1020(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 26,90,103,79,112,15,56,29,116,75,2,111,76,24,114,78,98,80,110,127,62,113,125,123,117,124,77,126,27,87,105,92,61,108,33,128,120,106,118,30,82,89,55,121,83,109,122 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_stake_delegate::new_behavior";
  test.test_nonce  = 602;
  test.test_number = 1020;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 6;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "7vE2aTfQk6WeBaTnb7RJbRb9e1psH6GGf1ZYHTo3X8Ry",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1000000000UL;
  test_acc->result_lamports = 1000000000UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1020_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1020_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1020_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1020_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "HezP98LPSimUAXSkHQRfXsqUsMthfuHnDRJvWqJMiW2k",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1020_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1020_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1020_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1020_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "FmLQHWGUvVe3rKhFrm6tHus1gKvEXtH5StcEFzZpeZJS",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1020_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1020_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1020_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1020_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1020_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1020_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1020_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1020_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1020_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1020_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1020_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1020_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "StakeConfig11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1020_acc_5_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1020_acc_5_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1020_acc_5_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1020_acc_5_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1020_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1020_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1021(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 26,90,103,79,112,15,56,29,116,75,2,111,76,24,114,78,98,80,110,127,62,113,125,123,117,124,77,126,27,87,105,92,61,108,33,128,120,106,118,30,82,89,55,121,83,109,122 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_stake_delegate::new_behavior";
  test.test_nonce  = 613;
  test.test_number = 1021;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 6;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "7vE2aTfQk6WeBaTnb7RJbRb9e1psH6GGf1ZYHTo3X8Ry",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1000000000UL;
  test_acc->result_lamports = 1000000000UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1021_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1021_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1021_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1021_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "HezP98LPSimUAXSkHQRfXsqUsMthfuHnDRJvWqJMiW2k",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1021_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1021_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1021_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1021_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "FmLQHWGUvVe3rKhFrm6tHus1gKvEXtH5StcEFzZpeZJS",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1021_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1021_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1021_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1021_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1021_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1021_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1021_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1021_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1021_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1021_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1021_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1021_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "StakeConfig11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1021_acc_5_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1021_acc_5_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1021_acc_5_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1021_acc_5_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1021_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1021_raw_sz;
  test.expected_result = -26;
  test.custom_err = 3;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1022(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 26,90,103,79,112,15,56,29,116,75,2,111,76,24,114,78,98,80,110,127,62,113,125,123,117,124,77,126,27,87,105,92,61,108,33,128,120,106,118,30,82,89,55,121,83,109,122 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_stake_delegate::new_behavior";
  test.test_nonce  = 622;
  test.test_number = 1022;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 6;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "7vE2aTfQk6WeBaTnb7RJbRb9e1psH6GGf1ZYHTo3X8Ry",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1000000000UL;
  test_acc->result_lamports = 1000000000UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1022_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1022_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1022_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1022_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "HezP98LPSimUAXSkHQRfXsqUsMthfuHnDRJvWqJMiW2k",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1022_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1022_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1022_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1022_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "FmLQHWGUvVe3rKhFrm6tHus1gKvEXtH5StcEFzZpeZJS",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1022_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1022_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1022_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1022_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1022_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1022_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1022_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1022_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1022_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1022_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1022_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1022_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "StakeConfig11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1022_acc_5_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1022_acc_5_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1022_acc_5_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1022_acc_5_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1022_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1022_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1023(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 26,90,103,79,112,15,56,29,116,75,2,111,76,24,114,78,98,80,110,127,62,113,125,123,117,124,77,126,27,87,105,92,61,108,33,128,120,106,118,30,82,89,55,121,83,109,122 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_stake_delegate::new_behavior";
  test.test_nonce  = 626;
  test.test_number = 1023;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 6;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "7vE2aTfQk6WeBaTnb7RJbRb9e1psH6GGf1ZYHTo3X8Ry",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1000000000UL;
  test_acc->result_lamports = 1000000000UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1023_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1023_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1023_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1023_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "FmLQHWGUvVe3rKhFrm6tHus1gKvEXtH5StcEFzZpeZJS",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "B5TAeSVJmKSNQdbAdTNt8LsQRqB1tJuR36CgZHFUkNsu",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1023_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1023_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1023_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1023_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "FmLQHWGUvVe3rKhFrm6tHus1gKvEXtH5StcEFzZpeZJS",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1023_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1023_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1023_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1023_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1023_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1023_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1023_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1023_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1023_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1023_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1023_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1023_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "StakeConfig11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1023_acc_5_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1023_acc_5_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1023_acc_5_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1023_acc_5_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1023_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1023_raw_sz;
  test.expected_result = -7;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1024(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 26,90,103,79,112,15,56,29,116,75,2,111,76,24,114,78,98,80,110,127,62,113,125,123,117,124,77,126,27,87,105,92,61,108,33,128,120,106,118,30,82,89,55,121,83,109,122 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_stake_delegate::new_behavior";
  test.test_nonce  = 630;
  test.test_number = 1024;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 6;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "7vE2aTfQk6WeBaTnb7RJbRb9e1psH6GGf1ZYHTo3X8Ry",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1000000000UL;
  test_acc->result_lamports = 1000000000UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1024_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1024_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1024_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1024_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "FmLQHWGUvVe3rKhFrm6tHus1gKvEXtH5StcEFzZpeZJS",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "B5TAeSVJmKSNQdbAdTNt8LsQRqB1tJuR36CgZHFUkNsu",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1024_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1024_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1024_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1024_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "FmLQHWGUvVe3rKhFrm6tHus1gKvEXtH5StcEFzZpeZJS",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1024_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1024_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1024_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1024_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1024_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1024_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1024_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1024_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1024_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1024_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1024_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1024_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "StakeConfig11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1024_acc_5_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1024_acc_5_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1024_acc_5_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1024_acc_5_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1024_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1024_raw_sz;
  test.expected_result = -7;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
