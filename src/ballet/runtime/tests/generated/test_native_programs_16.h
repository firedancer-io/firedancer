#include "../fd_tests.h"
int test_400(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 1;
  uchar disabled_features[] = { 89 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_merge_incorrect_authorized_staker::old_behavior";
  test.test_nonce  = 210;
  test.test_number = 400;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 6;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "65Xa4Hkcf8JjawtueQsTvgojws41FjxksotnBv8AsQdf",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 42UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_400_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_400_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_400_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_400_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "7AJP1GXSJcHxQc45xiZjHtVgdBFniQvXrLcE3DCidAA1",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 42UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_400_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_400_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_400_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_400_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "5VCsimEDrKuF57y24FgHRxhCrYTtEsxTHtH1B3V5aDqW",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_400_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_400_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_400_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_400_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "4HiCUA6uSKeDjAm9FKtyojrkbu9NmhUM7SYopL6g7eH6",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_400_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_400_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_400_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_400_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_400_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_400_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_400_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_400_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_400_acc_5_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_400_acc_5_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_400_acc_5_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_400_acc_5_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_400_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_400_raw_sz;
  test.expected_result = -26;
  test.custom_err = 6;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_401(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 1;
  uchar disabled_features[] = { 89 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_merge_incorrect_authorized_staker::old_behavior";
  test.test_nonce  = 21;
  test.test_number = 401;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 6;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "65Xa4Hkcf8JjawtueQsTvgojws41FjxksotnBv8AsQdf",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 42UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_401_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_401_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_401_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_401_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "7AJP1GXSJcHxQc45xiZjHtVgdBFniQvXrLcE3DCidAA1",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 42UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_401_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_401_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_401_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_401_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "5VCsimEDrKuF57y24FgHRxhCrYTtEsxTHtH1B3V5aDqW",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_401_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_401_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_401_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_401_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "4HiCUA6uSKeDjAm9FKtyojrkbu9NmhUM7SYopL6g7eH6",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_401_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_401_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_401_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_401_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_401_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_401_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_401_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_401_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_401_acc_5_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_401_acc_5_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_401_acc_5_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_401_acc_5_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_401_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_401_raw_sz;
  test.expected_result = -8;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_402(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 1;
  uchar disabled_features[] = { 89 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_merge_incorrect_authorized_staker::old_behavior";
  test.test_nonce  = 320;
  test.test_number = 402;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 6;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "65Xa4Hkcf8JjawtueQsTvgojws41FjxksotnBv8AsQdf",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 42UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_402_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_402_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_402_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_402_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "7AJP1GXSJcHxQc45xiZjHtVgdBFniQvXrLcE3DCidAA1",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 42UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_402_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_402_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_402_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_402_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "5VCsimEDrKuF57y24FgHRxhCrYTtEsxTHtH1B3V5aDqW",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_402_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_402_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_402_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_402_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "4HiCUA6uSKeDjAm9FKtyojrkbu9NmhUM7SYopL6g7eH6",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_402_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_402_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_402_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_402_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_402_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_402_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_402_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_402_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_402_acc_5_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_402_acc_5_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_402_acc_5_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_402_acc_5_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_402_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_402_raw_sz;
  test.expected_result = -8;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_403(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 1;
  uchar disabled_features[] = { 89 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_merge_incorrect_authorized_staker::old_behavior";
  test.test_nonce  = 395;
  test.test_number = 403;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 6;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "65Xa4Hkcf8JjawtueQsTvgojws41FjxksotnBv8AsQdf",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 42UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_403_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_403_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_403_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_403_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "7AJP1GXSJcHxQc45xiZjHtVgdBFniQvXrLcE3DCidAA1",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 42UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_403_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_403_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_403_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_403_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "5VCsimEDrKuF57y24FgHRxhCrYTtEsxTHtH1B3V5aDqW",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_403_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_403_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_403_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_403_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "4HiCUA6uSKeDjAm9FKtyojrkbu9NmhUM7SYopL6g7eH6",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_403_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_403_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_403_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_403_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_403_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_403_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_403_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_403_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_403_acc_5_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_403_acc_5_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_403_acc_5_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_403_acc_5_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_403_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_403_raw_sz;
  test.expected_result = -26;
  test.custom_err = 6;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_404(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 1;
  uchar disabled_features[] = { 89 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_merge_incorrect_authorized_staker::old_behavior";
  test.test_nonce  = 434;
  test.test_number = 404;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 6;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "65Xa4Hkcf8JjawtueQsTvgojws41FjxksotnBv8AsQdf",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 42UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_404_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_404_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_404_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_404_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "7AJP1GXSJcHxQc45xiZjHtVgdBFniQvXrLcE3DCidAA1",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 42UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_404_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_404_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_404_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_404_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "5VCsimEDrKuF57y24FgHRxhCrYTtEsxTHtH1B3V5aDqW",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_404_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_404_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_404_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_404_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "4HiCUA6uSKeDjAm9FKtyojrkbu9NmhUM7SYopL6g7eH6",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_404_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_404_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_404_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_404_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_404_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_404_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_404_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_404_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_404_acc_5_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_404_acc_5_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_404_acc_5_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_404_acc_5_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_404_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_404_raw_sz;
  test.expected_result = -8;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_405(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 1;
  uchar disabled_features[] = { 89 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_merge_incorrect_authorized_staker::old_behavior";
  test.test_nonce  = 466;
  test.test_number = 405;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 6;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "65Xa4Hkcf8JjawtueQsTvgojws41FjxksotnBv8AsQdf",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 42UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_405_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_405_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_405_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_405_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "7AJP1GXSJcHxQc45xiZjHtVgdBFniQvXrLcE3DCidAA1",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 42UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_405_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_405_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_405_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_405_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "5VCsimEDrKuF57y24FgHRxhCrYTtEsxTHtH1B3V5aDqW",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_405_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_405_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_405_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_405_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "4HiCUA6uSKeDjAm9FKtyojrkbu9NmhUM7SYopL6g7eH6",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_405_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_405_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_405_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_405_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_405_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_405_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_405_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_405_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_405_acc_5_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_405_acc_5_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_405_acc_5_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_405_acc_5_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_405_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_405_raw_sz;
  test.expected_result = -26;
  test.custom_err = 6;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_406(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 1;
  uchar disabled_features[] = { 89 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_merge_incorrect_authorized_staker::old_behavior";
  test.test_nonce  = 498;
  test.test_number = 406;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 6;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "65Xa4Hkcf8JjawtueQsTvgojws41FjxksotnBv8AsQdf",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 42UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_406_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_406_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_406_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_406_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "7AJP1GXSJcHxQc45xiZjHtVgdBFniQvXrLcE3DCidAA1",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 42UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_406_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_406_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_406_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_406_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "5VCsimEDrKuF57y24FgHRxhCrYTtEsxTHtH1B3V5aDqW",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_406_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_406_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_406_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_406_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "4HiCUA6uSKeDjAm9FKtyojrkbu9NmhUM7SYopL6g7eH6",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_406_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_406_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_406_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_406_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_406_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_406_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_406_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_406_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_406_acc_5_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_406_acc_5_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_406_acc_5_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_406_acc_5_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_406_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_406_raw_sz;
  test.expected_result = -8;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_407(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 1;
  uchar disabled_features[] = { 89 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_merge_incorrect_authorized_staker::old_behavior";
  test.test_nonce  = 524;
  test.test_number = 407;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 6;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "65Xa4Hkcf8JjawtueQsTvgojws41FjxksotnBv8AsQdf",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 42UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_407_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_407_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_407_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_407_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "7AJP1GXSJcHxQc45xiZjHtVgdBFniQvXrLcE3DCidAA1",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 42UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_407_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_407_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_407_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_407_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "5VCsimEDrKuF57y24FgHRxhCrYTtEsxTHtH1B3V5aDqW",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_407_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_407_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_407_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_407_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "4HiCUA6uSKeDjAm9FKtyojrkbu9NmhUM7SYopL6g7eH6",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_407_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_407_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_407_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_407_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_407_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_407_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_407_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_407_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_407_acc_5_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_407_acc_5_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_407_acc_5_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_407_acc_5_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_407_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_407_raw_sz;
  test.expected_result = -26;
  test.custom_err = 6;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_408(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 108,2,89,15,55,80,117,120,90,61,92,124,75,87,24,78,121,27,126,82,62,118,116,122,77,106,30,111,109,113,33,110,56,123,79,112,128,125,98,83,76,114,103,29,26,105,127 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_merge_invalid_account_data::new_behavior";
  test.test_nonce  = 14;
  test.test_number = 408;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 5;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "F96TENcmJYuw2RkokT5LmS6CA2gTYYPgGNWUGq5uC5vf",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 42UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_408_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_408_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_408_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_408_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Cqr7DxjMuouGnW9QBPV5Ey6z7qXCV5sgKWbcBSJM7gex",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 42UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_408_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_408_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_408_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_408_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "CG3mqkeLXQHjkZvt93QE4115N89YBe7SxXqNC7xWzLVh",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_408_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_408_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_408_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_408_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_408_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_408_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_408_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_408_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_408_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_408_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_408_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_408_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_408_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_408_raw_sz;
  test.expected_result = -4;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_409(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 108,2,89,15,55,80,117,120,90,61,92,124,75,87,24,78,121,27,126,82,62,118,116,122,77,106,30,111,109,113,33,110,56,123,79,112,128,125,98,83,76,114,103,29,26,105,127 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_merge_invalid_account_data::new_behavior";
  test.test_nonce  = 197;
  test.test_number = 409;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 5;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "F96TENcmJYuw2RkokT5LmS6CA2gTYYPgGNWUGq5uC5vf",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 42UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_409_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_409_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_409_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_409_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Cqr7DxjMuouGnW9QBPV5Ey6z7qXCV5sgKWbcBSJM7gex",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 42UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_409_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_409_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_409_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_409_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "CG3mqkeLXQHjkZvt93QE4115N89YBe7SxXqNC7xWzLVh",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_409_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_409_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_409_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_409_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_409_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_409_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_409_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_409_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_409_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_409_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_409_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_409_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_409_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_409_raw_sz;
  test.expected_result = -4;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_410(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 108,2,89,15,55,80,117,120,90,61,92,124,75,87,24,78,121,27,126,82,62,118,116,122,77,106,30,111,109,113,33,110,56,123,79,112,128,125,98,83,76,114,103,29,26,105,127 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_merge_invalid_account_data::new_behavior";
  test.test_nonce  = 371;
  test.test_number = 410;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 5;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "F96TENcmJYuw2RkokT5LmS6CA2gTYYPgGNWUGq5uC5vf",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 42UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_410_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_410_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_410_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_410_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Cqr7DxjMuouGnW9QBPV5Ey6z7qXCV5sgKWbcBSJM7gex",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 42UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_410_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_410_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_410_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_410_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "CG3mqkeLXQHjkZvt93QE4115N89YBe7SxXqNC7xWzLVh",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_410_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_410_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_410_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_410_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_410_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_410_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_410_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_410_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_410_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_410_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_410_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_410_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_410_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_410_raw_sz;
  test.expected_result = -4;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_411(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 108,2,89,15,55,80,117,120,90,61,92,124,75,87,24,78,121,27,126,82,62,118,116,122,77,106,30,111,109,113,33,110,56,123,79,112,128,125,98,83,76,114,103,29,26,105,127 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_merge_invalid_account_data::new_behavior";
  test.test_nonce  = 430;
  test.test_number = 411;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 5;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "F96TENcmJYuw2RkokT5LmS6CA2gTYYPgGNWUGq5uC5vf",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 42UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_411_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_411_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_411_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_411_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Cqr7DxjMuouGnW9QBPV5Ey6z7qXCV5sgKWbcBSJM7gex",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 42UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_411_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_411_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_411_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_411_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "CG3mqkeLXQHjkZvt93QE4115N89YBe7SxXqNC7xWzLVh",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_411_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_411_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_411_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_411_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_411_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_411_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_411_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_411_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_411_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_411_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_411_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_411_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_411_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_411_raw_sz;
  test.expected_result = -4;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_412(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 108,2,89,15,55,80,117,120,90,61,92,124,75,87,24,78,121,27,126,82,62,118,116,122,77,106,30,111,109,113,33,110,56,123,79,112,128,125,98,83,76,114,103,29,26,105,127 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_merge_invalid_account_data::new_behavior";
  test.test_nonce  = 477;
  test.test_number = 412;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 5;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "F96TENcmJYuw2RkokT5LmS6CA2gTYYPgGNWUGq5uC5vf",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 42UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_412_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_412_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_412_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_412_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Cqr7DxjMuouGnW9QBPV5Ey6z7qXCV5sgKWbcBSJM7gex",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 42UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_412_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_412_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_412_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_412_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "CG3mqkeLXQHjkZvt93QE4115N89YBe7SxXqNC7xWzLVh",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_412_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_412_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_412_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_412_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_412_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_412_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_412_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_412_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_412_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_412_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_412_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_412_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_412_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_412_raw_sz;
  test.expected_result = -4;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_413(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 108,2,89,15,55,80,117,120,90,61,92,124,75,87,24,78,121,27,126,82,62,118,116,122,77,106,30,111,109,113,33,110,56,123,79,112,128,125,98,83,76,114,103,29,26,105,127 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_merge_invalid_account_data::new_behavior";
  test.test_nonce  = 498;
  test.test_number = 413;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 5;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "F96TENcmJYuw2RkokT5LmS6CA2gTYYPgGNWUGq5uC5vf",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 42UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_413_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_413_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_413_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_413_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Cqr7DxjMuouGnW9QBPV5Ey6z7qXCV5sgKWbcBSJM7gex",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 42UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_413_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_413_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_413_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_413_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "CG3mqkeLXQHjkZvt93QE4115N89YBe7SxXqNC7xWzLVh",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_413_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_413_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_413_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_413_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_413_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_413_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_413_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_413_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_413_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_413_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_413_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_413_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_413_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_413_raw_sz;
  test.expected_result = -4;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_414(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 108,2,89,15,55,80,117,120,90,61,92,124,75,87,24,78,121,27,126,82,62,118,116,122,77,106,30,111,109,113,33,110,56,123,79,112,128,125,98,83,76,114,103,29,26,105,127 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_merge_invalid_account_data::new_behavior";
  test.test_nonce  = 520;
  test.test_number = 414;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 5;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "F96TENcmJYuw2RkokT5LmS6CA2gTYYPgGNWUGq5uC5vf",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 42UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_414_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_414_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_414_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_414_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Cqr7DxjMuouGnW9QBPV5Ey6z7qXCV5sgKWbcBSJM7gex",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 42UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_414_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_414_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_414_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_414_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "CG3mqkeLXQHjkZvt93QE4115N89YBe7SxXqNC7xWzLVh",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_414_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_414_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_414_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_414_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_414_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_414_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_414_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_414_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_414_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_414_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_414_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_414_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_414_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_414_raw_sz;
  test.expected_result = -4;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_415(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 108,2,89,15,55,80,117,120,90,61,92,124,75,87,24,78,121,27,126,82,62,118,116,122,77,106,30,111,109,113,33,110,56,123,79,112,128,125,98,83,76,114,103,29,26,105,127 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_merge_invalid_account_data::new_behavior";
  test.test_nonce  = 536;
  test.test_number = 415;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 5;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "F96TENcmJYuw2RkokT5LmS6CA2gTYYPgGNWUGq5uC5vf",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 42UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_415_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_415_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_415_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_415_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Cqr7DxjMuouGnW9QBPV5Ey6z7qXCV5sgKWbcBSJM7gex",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 42UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_415_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_415_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_415_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_415_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "CG3mqkeLXQHjkZvt93QE4115N89YBe7SxXqNC7xWzLVh",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_415_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_415_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_415_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_415_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_415_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_415_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_415_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_415_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_415_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_415_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_415_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_415_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_415_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_415_raw_sz;
  test.expected_result = -4;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_416(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 108,2,89,15,55,80,117,120,90,61,92,124,75,87,24,78,121,27,126,82,62,118,116,122,77,106,30,111,109,113,33,110,56,123,79,112,128,125,98,83,76,114,103,29,26,105,127 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_merge_invalid_account_data::new_behavior";
  test.test_nonce  = 255;
  test.test_number = 416;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 5;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "99vnHgPB466FwWnrk17XAPJARAzRFWnAoTKrLLkbhj9J",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 42UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_416_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_416_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_416_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_416_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "8mRt7zBiSNuxTXqvVVkGT5EXaMy16VQ3Ux7AQEavXQFG",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 42UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_416_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_416_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_416_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_416_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "A7FDx9wPALpfs7G1693AbiiFpSn9dTNAybTbfw9RuLFG",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_416_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_416_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_416_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_416_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_416_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_416_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_416_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_416_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_416_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_416_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_416_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_416_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_416_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_416_raw_sz;
  test.expected_result = -4;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_417(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 108,2,89,15,55,80,117,120,90,61,92,124,75,87,24,78,121,27,126,82,62,118,116,122,77,106,30,111,109,113,33,110,56,123,79,112,128,125,98,83,76,114,103,29,26,105,127 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_merge_invalid_account_data::new_behavior";
  test.test_nonce  = 354;
  test.test_number = 417;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 5;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "99vnHgPB466FwWnrk17XAPJARAzRFWnAoTKrLLkbhj9J",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 42UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_417_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_417_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_417_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_417_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "8mRt7zBiSNuxTXqvVVkGT5EXaMy16VQ3Ux7AQEavXQFG",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 42UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_417_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_417_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_417_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_417_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "A7FDx9wPALpfs7G1693AbiiFpSn9dTNAybTbfw9RuLFG",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_417_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_417_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_417_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_417_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_417_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_417_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_417_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_417_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_417_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_417_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_417_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_417_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_417_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_417_raw_sz;
  test.expected_result = -4;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_418(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 108,2,89,15,55,80,117,120,90,61,92,124,75,87,24,78,121,27,126,82,62,118,116,122,77,106,30,111,109,113,33,110,56,123,79,112,128,125,98,83,76,114,103,29,26,105,127 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_merge_invalid_account_data::new_behavior";
  test.test_nonce  = 38;
  test.test_number = 418;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 5;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "99vnHgPB466FwWnrk17XAPJARAzRFWnAoTKrLLkbhj9J",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 42UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_418_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_418_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_418_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_418_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "8mRt7zBiSNuxTXqvVVkGT5EXaMy16VQ3Ux7AQEavXQFG",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 42UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_418_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_418_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_418_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_418_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "A7FDx9wPALpfs7G1693AbiiFpSn9dTNAybTbfw9RuLFG",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_418_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_418_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_418_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_418_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_418_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_418_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_418_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_418_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_418_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_418_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_418_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_418_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_418_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_418_raw_sz;
  test.expected_result = -4;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_419(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 108,2,89,15,55,80,117,120,90,61,92,124,75,87,24,78,121,27,126,82,62,118,116,122,77,106,30,111,109,113,33,110,56,123,79,112,128,125,98,83,76,114,103,29,26,105,127 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_merge_invalid_account_data::new_behavior";
  test.test_nonce  = 422;
  test.test_number = 419;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 5;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "99vnHgPB466FwWnrk17XAPJARAzRFWnAoTKrLLkbhj9J",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 42UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_419_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_419_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_419_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_419_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "8mRt7zBiSNuxTXqvVVkGT5EXaMy16VQ3Ux7AQEavXQFG",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 42UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_419_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_419_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_419_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_419_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "A7FDx9wPALpfs7G1693AbiiFpSn9dTNAybTbfw9RuLFG",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_419_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_419_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_419_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_419_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_419_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_419_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_419_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_419_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_419_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_419_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_419_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_419_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_419_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_419_raw_sz;
  test.expected_result = -4;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_420(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 108,2,89,15,55,80,117,120,90,61,92,124,75,87,24,78,121,27,126,82,62,118,116,122,77,106,30,111,109,113,33,110,56,123,79,112,128,125,98,83,76,114,103,29,26,105,127 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_merge_invalid_account_data::new_behavior";
  test.test_nonce  = 477;
  test.test_number = 420;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 5;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "99vnHgPB466FwWnrk17XAPJARAzRFWnAoTKrLLkbhj9J",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 42UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_420_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_420_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_420_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_420_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "8mRt7zBiSNuxTXqvVVkGT5EXaMy16VQ3Ux7AQEavXQFG",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 42UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_420_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_420_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_420_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_420_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "A7FDx9wPALpfs7G1693AbiiFpSn9dTNAybTbfw9RuLFG",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_420_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_420_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_420_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_420_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_420_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_420_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_420_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_420_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_420_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_420_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_420_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_420_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_420_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_420_raw_sz;
  test.expected_result = -4;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_421(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 108,2,89,15,55,80,117,120,90,61,92,124,75,87,24,78,121,27,126,82,62,118,116,122,77,106,30,111,109,113,33,110,56,123,79,112,128,125,98,83,76,114,103,29,26,105,127 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_merge_invalid_account_data::new_behavior";
  test.test_nonce  = 526;
  test.test_number = 421;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 5;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "99vnHgPB466FwWnrk17XAPJARAzRFWnAoTKrLLkbhj9J",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 42UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_421_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_421_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_421_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_421_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "8mRt7zBiSNuxTXqvVVkGT5EXaMy16VQ3Ux7AQEavXQFG",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 42UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_421_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_421_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_421_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_421_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "A7FDx9wPALpfs7G1693AbiiFpSn9dTNAybTbfw9RuLFG",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_421_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_421_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_421_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_421_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_421_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_421_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_421_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_421_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_421_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_421_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_421_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_421_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_421_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_421_raw_sz;
  test.expected_result = -4;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_422(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 108,2,89,15,55,80,117,120,90,61,92,124,75,87,24,78,121,27,126,82,62,118,116,122,77,106,30,111,109,113,33,110,56,123,79,112,128,125,98,83,76,114,103,29,26,105,127 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_merge_invalid_account_data::new_behavior";
  test.test_nonce  = 553;
  test.test_number = 422;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 5;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "99vnHgPB466FwWnrk17XAPJARAzRFWnAoTKrLLkbhj9J",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 42UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_422_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_422_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_422_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_422_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "8mRt7zBiSNuxTXqvVVkGT5EXaMy16VQ3Ux7AQEavXQFG",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 42UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_422_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_422_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_422_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_422_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "A7FDx9wPALpfs7G1693AbiiFpSn9dTNAybTbfw9RuLFG",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_422_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_422_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_422_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_422_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_422_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_422_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_422_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_422_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_422_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_422_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_422_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_422_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_422_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_422_raw_sz;
  test.expected_result = -4;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_423(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 108,2,89,15,55,80,117,120,90,61,92,124,75,87,24,78,121,27,126,82,62,118,116,122,77,106,30,111,109,113,33,110,56,123,79,112,128,125,98,83,76,114,103,29,26,105,127 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_merge_invalid_account_data::new_behavior";
  test.test_nonce  = 577;
  test.test_number = 423;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 5;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "99vnHgPB466FwWnrk17XAPJARAzRFWnAoTKrLLkbhj9J",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 42UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_423_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_423_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_423_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_423_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "8mRt7zBiSNuxTXqvVVkGT5EXaMy16VQ3Ux7AQEavXQFG",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 42UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_423_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_423_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_423_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_423_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "A7FDx9wPALpfs7G1693AbiiFpSn9dTNAybTbfw9RuLFG",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_423_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_423_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_423_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_423_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_423_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_423_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_423_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_423_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_423_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_423_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_423_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_423_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_423_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_423_raw_sz;
  test.expected_result = -4;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_424(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 1;
  uchar disabled_features[] = { 89 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_merge_invalid_account_data::old_behavior";
  test.test_nonce  = 246;
  test.test_number = 424;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 5;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "9DwLyQKMvw3pgnfyoUHJtiVYgduTkLRosAHsW4Uj4XCh",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 42UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_424_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_424_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_424_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_424_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "CNbZgQiy1vG1fgxCzHDyhV9mwjZyxayRWqDfgywDSuxV",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 42UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_424_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_424_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_424_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_424_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "FuxXmjYxaAXUW4Y4QbNDjbzQqDdgHVq36s6c6B5xqAd2",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_424_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_424_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_424_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_424_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_424_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_424_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_424_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_424_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_424_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_424_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_424_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_424_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_424_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_424_raw_sz;
  test.expected_result = -4;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
