#include "../fd_tests.h"
int test_1300(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 1;
  uchar disabled_features[] = { 89 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_withdraw_rent_exempt::old_behavior";
  test.test_nonce  = 359;
  test.test_number = 1300;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 5;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "Dp9gm8T98cdnRhaN9BAXnG4NsjECsgvHxXmh1a6Er28W",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2282887UL;
  test_acc->result_lamports = 2282887UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1300_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1300_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1300_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1300_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "8ZWmxr5wyYa5PzoVCMWvzPaHhVnePnc2S9KXiBS6Zy24",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1300_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1300_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1300_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1300_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "6WnTucZhvQbVgazgDWrvnzDUammCnTVHiSTpsAAySYgr",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1300_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1300_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1300_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1300_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1300_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1300_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1300_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1300_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1300_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1300_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1300_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1300_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1300_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1300_raw_sz;
  test.expected_result = -6;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1301(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 62,61,105,98,122,76,80,110,79,92,78,30,2,109,103,106,118,116,89,123,124,77,27,127,83,55,126,90,15,128,121,82,111,24,56,120,87,26,125,114,112,75,113,117,29,108,33 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_withdraw_rent_exempt::old_behavior";
  test.test_nonce  = 352;
  test.test_number = 1301;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 5;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "6qTh9GzmaWWpwSSyg71ZxVSz6oYMPrgAGC657tJuLcaG",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2282887UL;
  test_acc->result_lamports = 2282887UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1301_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1301_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1301_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1301_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "ByoRhpidxmZNbF8p3ZL5cgspHmMaiJMLUDHJ8k3344qo",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1301_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1301_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1301_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1301_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "5dLJwrwfk4Zh3ME1guXZDx3d2MGdhDR9EGkF9z7RD1TV",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1301_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1301_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1301_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1301_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1301_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1301_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1301_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1301_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1301_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1301_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1301_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1301_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1301_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1301_raw_sz;
  test.expected_result = -6;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1302(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 1;
  uchar disabled_features[] = { 89 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_withdraw_rent_exempt::old_behavior";
  test.test_nonce  = 425;
  test.test_number = 1302;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 5;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "Dp9gm8T98cdnRhaN9BAXnG4NsjECsgvHxXmh1a6Er28W",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2282887UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1302_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1302_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1302_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1302_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "8ZWmxr5wyYa5PzoVCMWvzPaHhVnePnc2S9KXiBS6Zy24",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 2282887UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1302_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1302_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1302_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1302_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "6WnTucZhvQbVgazgDWrvnzDUammCnTVHiSTpsAAySYgr",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1302_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1302_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1302_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1302_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1302_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1302_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1302_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1302_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1302_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1302_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1302_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1302_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1302_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1302_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1303(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 62,61,105,98,122,76,80,110,79,92,78,30,2,109,103,106,118,116,89,123,124,77,27,127,83,55,126,90,15,128,121,82,111,24,56,120,87,26,125,114,112,75,113,117,29,108,33 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_withdraw_rent_exempt::old_behavior";
  test.test_nonce  = 409;
  test.test_number = 1303;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 5;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "6qTh9GzmaWWpwSSyg71ZxVSz6oYMPrgAGC657tJuLcaG",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2282887UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1303_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1303_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1303_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1303_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "ByoRhpidxmZNbF8p3ZL5cgspHmMaiJMLUDHJ8k3344qo",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 2282887UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1303_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1303_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1303_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1303_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "5dLJwrwfk4Zh3ME1guXZDx3d2MGdhDR9EGkF9z7RD1TV",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1303_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1303_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1303_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1303_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1303_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1303_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1303_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1303_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1303_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1303_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1303_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1303_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1303_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1303_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1304(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 105,27,83,113,123,127,108,124,55,24,77,120,78,114,87,30,15,82,121,106,29,75,109,112,90,103,26,76,62,110,89,128,98,2,116,122,56,79,92,126,117,118,61,33,80,125,111 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_withdraw_stake_before_warmup::new_behavior";
  test.test_nonce  = 361;
  test.test_number = 1304;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 6;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "57Ma1PGoKvAgec3CGjJyaE5Gu7yKjYC5Bz6Wih9x6btJ",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1000000033UL;
  test_acc->result_lamports = 1000000033UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1304_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1304_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1304_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1304_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "BZaPTnMRTV14xJFEPfMcj4Eg65Y5KHyAvTW4puFSxr68",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1304_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1304_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1304_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1304_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "35Gbc5UeEVtJwRMpowZcu5ZQbL5n5zToi5byWbi734hR",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1304_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1304_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1304_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1304_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1304_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1304_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1304_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1304_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1304_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1304_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1304_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1304_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "StakeConfig11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1304_acc_5_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1304_acc_5_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1304_acc_5_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1304_acc_5_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1304_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1304_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1305(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 105,27,83,113,123,127,108,124,55,24,77,120,78,114,87,30,15,82,121,106,29,75,109,112,90,103,26,76,62,110,89,128,98,2,116,122,56,79,92,126,117,118,61,33,80,125,111 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_withdraw_stake_before_warmup::new_behavior";
  test.test_nonce  = 337;
  test.test_number = 1305;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 6;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "5UVvKqS2Yb1dNGJBw5tQZME6bYhi2aG3cB4UTdQEjc5i",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1000000033UL;
  test_acc->result_lamports = 1000000033UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1305_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1305_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1305_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1305_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "fjR9L6Hf9XS56puvLj7HXPL49XAKYSaG8kzj7JVr8Us",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1305_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1305_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1305_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1305_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "7vzoMr5hEmyHUAZVFpQu15FDQVCHHEowobYPMoGedYoE",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1305_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1305_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1305_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1305_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1305_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1305_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1305_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1305_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1305_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1305_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1305_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1305_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "StakeConfig11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1305_acc_5_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1305_acc_5_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1305_acc_5_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1305_acc_5_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1305_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1305_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1306(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 105,27,83,113,123,127,108,124,55,24,77,120,78,114,87,30,15,82,121,106,29,75,109,112,90,103,26,76,62,110,89,128,98,2,116,122,56,79,92,126,117,118,61,33,80,125,111 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_withdraw_stake_before_warmup::new_behavior";
  test.test_nonce  = 418;
  test.test_number = 1306;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 6;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "57Ma1PGoKvAgec3CGjJyaE5Gu7yKjYC5Bz6Wih9x6btJ",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1000000033UL;
  test_acc->result_lamports = 1000000033UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1306_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1306_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1306_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1306_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "BZaPTnMRTV14xJFEPfMcj4Eg65Y5KHyAvTW4puFSxr68",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1306_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1306_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1306_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1306_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "35Gbc5UeEVtJwRMpowZcu5ZQbL5n5zToi5byWbi734hR",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1306_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1306_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1306_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1306_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1306_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1306_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1306_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1306_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1306_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1306_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1306_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1306_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "StakeConfig11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1306_acc_5_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1306_acc_5_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1306_acc_5_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1306_acc_5_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1306_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1306_raw_sz;
  test.expected_result = -6;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1307(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 105,27,83,113,123,127,108,124,55,24,77,120,78,114,87,30,15,82,121,106,29,75,109,112,90,103,26,76,62,110,89,128,98,2,116,122,56,79,92,126,117,118,61,33,80,125,111 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_withdraw_stake_before_warmup::new_behavior";
  test.test_nonce  = 420;
  test.test_number = 1307;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 6;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "5UVvKqS2Yb1dNGJBw5tQZME6bYhi2aG3cB4UTdQEjc5i",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1000000033UL;
  test_acc->result_lamports = 1000000033UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1307_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1307_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1307_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1307_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "fjR9L6Hf9XS56puvLj7HXPL49XAKYSaG8kzj7JVr8Us",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1307_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1307_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1307_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1307_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "7vzoMr5hEmyHUAZVFpQu15FDQVCHHEowobYPMoGedYoE",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1307_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1307_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1307_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1307_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1307_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1307_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1307_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1307_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1307_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1307_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1307_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1307_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "StakeConfig11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1307_acc_5_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1307_acc_5_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1307_acc_5_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1307_acc_5_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1307_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1307_raw_sz;
  test.expected_result = -6;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1308(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 105,114,113,90,106,29,116,122,127,126,27,103,128,117,30,62,79,89,33,118,112,61,78,80,92,123,125,77,82,120,24,83,98,87,26,111,75,109,124,108,76,121,110,2,56,55,15 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_withdraw_stake_before_warmup::old_behavior";
  test.test_nonce  = 362;
  test.test_number = 1308;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 6;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "HdgBfhw1649yV6J1mmkM6PF7Soyr92KG9cr9mGixmJbE",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 34UL;
  test_acc->result_lamports = 34UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1308_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1308_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1308_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1308_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "8tdMWSEkpxsfvPQj1NNRy33ZLQ3BPY29ZnZCwcvvsUB7",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1308_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1308_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1308_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1308_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "7UqEthpXQoKogDctCLeyhFRx8kpRQcAfiAY9asLfS7yV",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1308_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1308_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1308_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1308_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1308_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1308_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1308_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1308_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1308_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1308_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1308_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1308_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "StakeConfig11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1308_acc_5_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1308_acc_5_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1308_acc_5_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1308_acc_5_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1308_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1308_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1309(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 1;
  uchar disabled_features[] = { 89 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_withdraw_stake_before_warmup::old_behavior";
  test.test_nonce  = 335;
  test.test_number = 1309;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 6;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "3tRPrb3NbCewcphFWLBATWwdsju5vfonzUYqddnTn6oT",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 34UL;
  test_acc->result_lamports = 34UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1309_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1309_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1309_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1309_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "BSYPTQBshjCLPRRDHC68YVbzmrDaFRJTR9tZmGHPNHdk",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1309_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1309_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1309_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1309_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "3PDdG4M5JRfbjhgybKSeAPFfpRQoPT5cAZir1tyDEBnk",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1309_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1309_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1309_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1309_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1309_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1309_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1309_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1309_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1309_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1309_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1309_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1309_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "StakeConfig11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1309_acc_5_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1309_acc_5_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1309_acc_5_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1309_acc_5_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1309_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1309_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1310(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 105,114,113,90,106,29,116,122,127,126,27,103,128,117,30,62,79,89,33,118,112,61,78,80,92,123,125,77,82,120,24,83,98,87,26,111,75,109,124,108,76,121,110,2,56,55,15 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_withdraw_stake_before_warmup::old_behavior";
  test.test_nonce  = 429;
  test.test_number = 1310;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 6;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "HdgBfhw1649yV6J1mmkM6PF7Soyr92KG9cr9mGixmJbE",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 34UL;
  test_acc->result_lamports = 34UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1310_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1310_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1310_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1310_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "8tdMWSEkpxsfvPQj1NNRy33ZLQ3BPY29ZnZCwcvvsUB7",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1310_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1310_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1310_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1310_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "7UqEthpXQoKogDctCLeyhFRx8kpRQcAfiAY9asLfS7yV",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1310_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1310_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1310_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1310_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1310_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1310_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1310_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1310_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1310_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1310_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1310_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1310_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "StakeConfig11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1310_acc_5_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1310_acc_5_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1310_acc_5_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1310_acc_5_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1310_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1310_raw_sz;
  test.expected_result = -6;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1311(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 1;
  uchar disabled_features[] = { 89 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_withdraw_stake_before_warmup::old_behavior";
  test.test_nonce  = 418;
  test.test_number = 1311;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 6;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "3tRPrb3NbCewcphFWLBATWwdsju5vfonzUYqddnTn6oT",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 34UL;
  test_acc->result_lamports = 34UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1311_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1311_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1311_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1311_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "BSYPTQBshjCLPRRDHC68YVbzmrDaFRJTR9tZmGHPNHdk",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1311_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1311_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1311_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1311_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "3PDdG4M5JRfbjhgybKSeAPFfpRQoPT5cAZir1tyDEBnk",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1311_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1311_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1311_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1311_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1311_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1311_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1311_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1311_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1311_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1311_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1311_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1311_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "StakeConfig11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1311_acc_5_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1311_acc_5_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1311_acc_5_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1311_acc_5_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1311_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1311_raw_sz;
  test.expected_result = -6;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1312(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 108,106,75,55,114,118,113,15,26,128,117,125,83,90,122,78,77,112,79,61,30,109,56,126,111,103,92,62,89,121,2,127,87,29,98,24,123,110,33,116,124,76,120,82,27,105,80 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_withdraw_stake::new_behavior";
  test.test_nonce  = 457;
  test.test_number = 1312;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 9;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "4omDQx3gmg2bZqkLjTZoCUadshXV7gMLPEhg5bL5urnq",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1000000000UL;
  test_acc->result_lamports = 1000000000UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1312_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1312_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1312_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1312_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "C1yhE9JiKDWKyWpGwwLR96Q7ZVfs3fTqcKnWEBBeLR4P",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1312_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1312_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1312_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1312_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "HVtYUPmJaFWi7Sucsc1Fq7etkoRuqcZjbXBcsvvmuugm",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1312_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1312_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1312_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1312_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "EQy3NVjkmA8FCjMaB7pFfNzcVGKTRxg8whZwxCCJAAoo",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 42UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1312_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1312_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1312_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1312_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "AL7b2h1vjn2okVcxtDovAS2ang4Qscoscmz4pnnzqsM2",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1312_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1312_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1312_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1312_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1312_acc_5_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1312_acc_5_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1312_acc_5_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1312_acc_5_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1312_acc_6_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1312_acc_6_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1312_acc_6_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1312_acc_6_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1312_acc_7_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1312_acc_7_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1312_acc_7_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1312_acc_7_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "StakeConfig11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1312_acc_8_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1312_acc_8_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1312_acc_8_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1312_acc_8_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1312_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1312_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1313(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 108,106,75,55,114,118,113,15,26,128,117,125,83,90,122,78,77,112,79,61,30,109,56,126,111,103,92,62,89,121,2,127,87,29,98,24,123,110,33,116,124,76,120,82,27,105,80 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_withdraw_stake::new_behavior";
  test.test_nonce  = 476;
  test.test_number = 1313;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 9;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "DgJh6HV56PK4xx92vU3HpYjmMo2wW28jysJcfXTMhMgw",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1000000000UL;
  test_acc->result_lamports = 1000000000UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1313_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1313_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1313_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1313_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "CdMT8H8hCLNoQY1sf9iH1KMKGy2WEosyH2i7mBq1N3rz",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1313_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1313_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1313_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1313_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "7PYTiHqL8YwQPxMH8RtHwZoPPt65oV5dhUKcdw4c5tMM",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1313_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1313_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1313_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1313_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "LAjAkNeQUqMzAQdiQZNmraw9Fa77vqsEMXSUdM462Nd",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 42UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1313_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1313_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1313_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1313_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "CTPXtmWqHEHCicwRh2Y4WMrfM8TZZsHkeiFoQNifUPZV",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1313_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1313_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1313_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1313_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1313_acc_5_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1313_acc_5_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1313_acc_5_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1313_acc_5_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1313_acc_6_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1313_acc_6_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1313_acc_6_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1313_acc_6_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1313_acc_7_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1313_acc_7_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1313_acc_7_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1313_acc_7_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "StakeConfig11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1313_acc_8_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1313_acc_8_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1313_acc_8_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1313_acc_8_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1313_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1313_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1314(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 108,106,75,55,114,118,113,15,26,128,117,125,83,90,122,78,77,112,79,61,30,109,56,126,111,103,92,62,89,121,2,127,87,29,98,24,123,110,33,116,124,76,120,82,27,105,80 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_withdraw_stake::new_behavior";
  test.test_nonce  = 517;
  test.test_number = 1314;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 9;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "4omDQx3gmg2bZqkLjTZoCUadshXV7gMLPEhg5bL5urnq",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1000000000UL;
  test_acc->result_lamports = 1000000000UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1314_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1314_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1314_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1314_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "C1yhE9JiKDWKyWpGwwLR96Q7ZVfs3fTqcKnWEBBeLR4P",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1314_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1314_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1314_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1314_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "HVtYUPmJaFWi7Sucsc1Fq7etkoRuqcZjbXBcsvvmuugm",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1314_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1314_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1314_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1314_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "EQy3NVjkmA8FCjMaB7pFfNzcVGKTRxg8whZwxCCJAAoo",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 42UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1314_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1314_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1314_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1314_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "AL7b2h1vjn2okVcxtDovAS2ang4Qscoscmz4pnnzqsM2",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1314_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1314_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1314_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1314_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1314_acc_5_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1314_acc_5_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1314_acc_5_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1314_acc_5_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1314_acc_6_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1314_acc_6_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1314_acc_6_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1314_acc_6_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1314_acc_7_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1314_acc_7_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1314_acc_7_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1314_acc_7_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "StakeConfig11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1314_acc_8_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1314_acc_8_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1314_acc_8_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1314_acc_8_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1314_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1314_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1315(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 108,106,75,55,114,118,113,15,26,128,117,125,83,90,122,78,77,112,79,61,30,109,56,126,111,103,92,62,89,121,2,127,87,29,98,24,123,110,33,116,124,76,120,82,27,105,80 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_withdraw_stake::new_behavior";
  test.test_nonce  = 564;
  test.test_number = 1315;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 9;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "DgJh6HV56PK4xx92vU3HpYjmMo2wW28jysJcfXTMhMgw",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1000000000UL;
  test_acc->result_lamports = 1000000000UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1315_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1315_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1315_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1315_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "CdMT8H8hCLNoQY1sf9iH1KMKGy2WEosyH2i7mBq1N3rz",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1315_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1315_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1315_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1315_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "7PYTiHqL8YwQPxMH8RtHwZoPPt65oV5dhUKcdw4c5tMM",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1315_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1315_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1315_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1315_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "LAjAkNeQUqMzAQdiQZNmraw9Fa77vqsEMXSUdM462Nd",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 42UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1315_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1315_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1315_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1315_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "CTPXtmWqHEHCicwRh2Y4WMrfM8TZZsHkeiFoQNifUPZV",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1315_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1315_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1315_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1315_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1315_acc_5_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1315_acc_5_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1315_acc_5_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1315_acc_5_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1315_acc_6_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1315_acc_6_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1315_acc_6_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1315_acc_6_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1315_acc_7_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1315_acc_7_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1315_acc_7_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1315_acc_7_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "StakeConfig11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1315_acc_8_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1315_acc_8_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1315_acc_8_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1315_acc_8_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1315_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1315_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1316(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 108,106,75,55,114,118,113,15,26,128,117,125,83,90,122,78,77,112,79,61,30,109,56,126,111,103,92,62,89,121,2,127,87,29,98,24,123,110,33,116,124,76,120,82,27,105,80 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_withdraw_stake::new_behavior";
  test.test_nonce  = 299;
  test.test_number = 1316;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 9;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "4omDQx3gmg2bZqkLjTZoCUadshXV7gMLPEhg5bL5urnq",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1000000000UL;
  test_acc->result_lamports = 1000000000UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1316_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1316_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1316_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1316_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "C1yhE9JiKDWKyWpGwwLR96Q7ZVfs3fTqcKnWEBBeLR4P",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1316_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1316_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1316_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1316_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "HVtYUPmJaFWi7Sucsc1Fq7etkoRuqcZjbXBcsvvmuugm",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1316_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1316_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1316_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1316_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "EQy3NVjkmA8FCjMaB7pFfNzcVGKTRxg8whZwxCCJAAoo",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 42UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1316_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1316_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1316_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1316_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "AL7b2h1vjn2okVcxtDovAS2ang4Qscoscmz4pnnzqsM2",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1316_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1316_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1316_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1316_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1316_acc_5_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1316_acc_5_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1316_acc_5_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1316_acc_5_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1316_acc_6_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1316_acc_6_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1316_acc_6_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1316_acc_6_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1316_acc_7_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1316_acc_7_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1316_acc_7_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1316_acc_7_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "StakeConfig11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1316_acc_8_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1316_acc_8_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1316_acc_8_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1316_acc_8_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1316_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1316_raw_sz;
  test.expected_result = -8;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1317(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 108,106,75,55,114,118,113,15,26,128,117,125,83,90,122,78,77,112,79,61,30,109,56,126,111,103,92,62,89,121,2,127,87,29,98,24,123,110,33,116,124,76,120,82,27,105,80 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_withdraw_stake::new_behavior";
  test.test_nonce  = 406;
  test.test_number = 1317;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 9;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "4omDQx3gmg2bZqkLjTZoCUadshXV7gMLPEhg5bL5urnq",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1000000000UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1317_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1317_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1317_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1317_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "C1yhE9JiKDWKyWpGwwLR96Q7ZVfs3fTqcKnWEBBeLR4P",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1317_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1317_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1317_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1317_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "HVtYUPmJaFWi7Sucsc1Fq7etkoRuqcZjbXBcsvvmuugm",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 1000000000UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1317_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1317_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1317_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1317_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "EQy3NVjkmA8FCjMaB7pFfNzcVGKTRxg8whZwxCCJAAoo",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 42UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1317_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1317_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1317_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1317_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "AL7b2h1vjn2okVcxtDovAS2ang4Qscoscmz4pnnzqsM2",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1317_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1317_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1317_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1317_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1317_acc_5_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1317_acc_5_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1317_acc_5_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1317_acc_5_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1317_acc_6_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1317_acc_6_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1317_acc_6_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1317_acc_6_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1317_acc_7_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1317_acc_7_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1317_acc_7_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1317_acc_7_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "StakeConfig11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1317_acc_8_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1317_acc_8_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1317_acc_8_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1317_acc_8_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1317_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1317_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1318(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 108,106,75,55,114,118,113,15,26,128,117,125,83,90,122,78,77,112,79,61,30,109,56,126,111,103,92,62,89,121,2,127,87,29,98,24,123,110,33,116,124,76,120,82,27,105,80 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_withdraw_stake::new_behavior";
  test.test_nonce  = 618;
  test.test_number = 1318;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 9;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "4omDQx3gmg2bZqkLjTZoCUadshXV7gMLPEhg5bL5urnq",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1000000000UL;
  test_acc->result_lamports = 1000000000UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1318_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1318_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1318_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1318_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "C1yhE9JiKDWKyWpGwwLR96Q7ZVfs3fTqcKnWEBBeLR4P",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1318_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1318_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1318_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1318_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "HVtYUPmJaFWi7Sucsc1Fq7etkoRuqcZjbXBcsvvmuugm",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1000000000UL;
  test_acc->result_lamports = 1000000000UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1318_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1318_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1318_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1318_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "EQy3NVjkmA8FCjMaB7pFfNzcVGKTRxg8whZwxCCJAAoo",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 42UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1318_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1318_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1318_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1318_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "AL7b2h1vjn2okVcxtDovAS2ang4Qscoscmz4pnnzqsM2",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1318_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1318_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1318_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1318_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1318_acc_5_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1318_acc_5_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1318_acc_5_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1318_acc_5_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1318_acc_6_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1318_acc_6_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1318_acc_6_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1318_acc_6_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1318_acc_7_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1318_acc_7_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1318_acc_7_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1318_acc_7_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "StakeConfig11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1318_acc_8_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1318_acc_8_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1318_acc_8_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1318_acc_8_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1318_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1318_raw_sz;
  test.expected_result = -4;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1319(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 108,106,75,55,114,118,113,15,26,128,117,125,83,90,122,78,77,112,79,61,30,109,56,126,111,103,92,62,89,121,2,127,87,29,98,24,123,110,33,116,124,76,120,82,27,105,80 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_withdraw_stake::new_behavior";
  test.test_nonce  = 285;
  test.test_number = 1319;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 9;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "DgJh6HV56PK4xx92vU3HpYjmMo2wW28jysJcfXTMhMgw",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1000000000UL;
  test_acc->result_lamports = 1000000000UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1319_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1319_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1319_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1319_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "CdMT8H8hCLNoQY1sf9iH1KMKGy2WEosyH2i7mBq1N3rz",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1319_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1319_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1319_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1319_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "7PYTiHqL8YwQPxMH8RtHwZoPPt65oV5dhUKcdw4c5tMM",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1319_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1319_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1319_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1319_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "LAjAkNeQUqMzAQdiQZNmraw9Fa77vqsEMXSUdM462Nd",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 42UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1319_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1319_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1319_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1319_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "CTPXtmWqHEHCicwRh2Y4WMrfM8TZZsHkeiFoQNifUPZV",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1319_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1319_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1319_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1319_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1319_acc_5_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1319_acc_5_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1319_acc_5_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1319_acc_5_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1319_acc_6_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1319_acc_6_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1319_acc_6_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1319_acc_6_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1319_acc_7_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1319_acc_7_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1319_acc_7_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1319_acc_7_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "StakeConfig11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1319_acc_8_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1319_acc_8_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1319_acc_8_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1319_acc_8_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1319_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1319_raw_sz;
  test.expected_result = -8;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1320(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 108,106,75,55,114,118,113,15,26,128,117,125,83,90,122,78,77,112,79,61,30,109,56,126,111,103,92,62,89,121,2,127,87,29,98,24,123,110,33,116,124,76,120,82,27,105,80 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_withdraw_stake::new_behavior";
  test.test_nonce  = 408;
  test.test_number = 1320;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 9;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "DgJh6HV56PK4xx92vU3HpYjmMo2wW28jysJcfXTMhMgw",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1000000000UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1320_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1320_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1320_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1320_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "CdMT8H8hCLNoQY1sf9iH1KMKGy2WEosyH2i7mBq1N3rz",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1320_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1320_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1320_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1320_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "7PYTiHqL8YwQPxMH8RtHwZoPPt65oV5dhUKcdw4c5tMM",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 1000000000UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1320_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1320_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1320_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1320_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "LAjAkNeQUqMzAQdiQZNmraw9Fa77vqsEMXSUdM462Nd",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 42UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1320_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1320_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1320_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1320_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "CTPXtmWqHEHCicwRh2Y4WMrfM8TZZsHkeiFoQNifUPZV",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1320_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1320_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1320_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1320_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1320_acc_5_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1320_acc_5_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1320_acc_5_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1320_acc_5_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1320_acc_6_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1320_acc_6_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1320_acc_6_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1320_acc_6_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1320_acc_7_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1320_acc_7_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1320_acc_7_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1320_acc_7_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "StakeConfig11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1320_acc_8_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1320_acc_8_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1320_acc_8_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1320_acc_8_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1320_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1320_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1321(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 108,106,75,55,114,118,113,15,26,128,117,125,83,90,122,78,77,112,79,61,30,109,56,126,111,103,92,62,89,121,2,127,87,29,98,24,123,110,33,116,124,76,120,82,27,105,80 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_withdraw_stake::new_behavior";
  test.test_nonce  = 640;
  test.test_number = 1321;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 9;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "DgJh6HV56PK4xx92vU3HpYjmMo2wW28jysJcfXTMhMgw",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1000000000UL;
  test_acc->result_lamports = 1000000000UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1321_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1321_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1321_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1321_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "CdMT8H8hCLNoQY1sf9iH1KMKGy2WEosyH2i7mBq1N3rz",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1321_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1321_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1321_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1321_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "7PYTiHqL8YwQPxMH8RtHwZoPPt65oV5dhUKcdw4c5tMM",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1000000000UL;
  test_acc->result_lamports = 1000000000UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1321_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1321_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1321_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1321_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "LAjAkNeQUqMzAQdiQZNmraw9Fa77vqsEMXSUdM462Nd",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 42UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1321_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1321_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1321_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1321_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "CTPXtmWqHEHCicwRh2Y4WMrfM8TZZsHkeiFoQNifUPZV",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1321_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1321_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1321_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1321_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1321_acc_5_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1321_acc_5_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1321_acc_5_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1321_acc_5_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1321_acc_6_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1321_acc_6_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1321_acc_6_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1321_acc_6_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1321_acc_7_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1321_acc_7_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1321_acc_7_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1321_acc_7_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "StakeConfig11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1321_acc_8_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1321_acc_8_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1321_acc_8_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1321_acc_8_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1321_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1321_raw_sz;
  test.expected_result = -4;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1322(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 108,106,75,55,114,118,113,15,26,128,117,125,83,90,122,78,77,112,79,61,30,109,56,126,111,103,92,62,89,121,2,127,87,29,98,24,123,110,33,116,124,76,120,82,27,105,80 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_withdraw_stake::new_behavior";
  test.test_nonce  = 488;
  test.test_number = 1322;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 9;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "4omDQx3gmg2bZqkLjTZoCUadshXV7gMLPEhg5bL5urnq",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1000000000UL;
  test_acc->result_lamports = 1000000000UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1322_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1322_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1322_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1322_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "C1yhE9JiKDWKyWpGwwLR96Q7ZVfs3fTqcKnWEBBeLR4P",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1322_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1322_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1322_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1322_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "HVtYUPmJaFWi7Sucsc1Fq7etkoRuqcZjbXBcsvvmuugm",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1322_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1322_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1322_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1322_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "EQy3NVjkmA8FCjMaB7pFfNzcVGKTRxg8whZwxCCJAAoo",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 42UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1322_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1322_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1322_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1322_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "AL7b2h1vjn2okVcxtDovAS2ang4Qscoscmz4pnnzqsM2",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1322_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1322_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1322_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1322_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1322_acc_5_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1322_acc_5_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1322_acc_5_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1322_acc_5_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1322_acc_6_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1322_acc_6_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1322_acc_6_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1322_acc_6_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1322_acc_7_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1322_acc_7_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1322_acc_7_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1322_acc_7_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "StakeConfig11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1322_acc_8_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1322_acc_8_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1322_acc_8_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1322_acc_8_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1322_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1322_raw_sz;
  test.expected_result = -6;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1323(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 108,106,75,55,114,118,113,15,26,128,117,125,83,90,122,78,77,112,79,61,30,109,56,126,111,103,92,62,89,121,2,127,87,29,98,24,123,110,33,116,124,76,120,82,27,105,80 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_withdraw_stake::new_behavior";
  test.test_nonce  = 532;
  test.test_number = 1323;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 9;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "DgJh6HV56PK4xx92vU3HpYjmMo2wW28jysJcfXTMhMgw",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1000000000UL;
  test_acc->result_lamports = 1000000000UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1323_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1323_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1323_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1323_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "CdMT8H8hCLNoQY1sf9iH1KMKGy2WEosyH2i7mBq1N3rz",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1323_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1323_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1323_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1323_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "7PYTiHqL8YwQPxMH8RtHwZoPPt65oV5dhUKcdw4c5tMM",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1323_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1323_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1323_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1323_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "LAjAkNeQUqMzAQdiQZNmraw9Fa77vqsEMXSUdM462Nd",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 42UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1323_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1323_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1323_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1323_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "CTPXtmWqHEHCicwRh2Y4WMrfM8TZZsHkeiFoQNifUPZV",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1323_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1323_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1323_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1323_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1323_acc_5_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1323_acc_5_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1323_acc_5_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1323_acc_5_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1323_acc_6_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1323_acc_6_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1323_acc_6_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1323_acc_6_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1323_acc_7_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1323_acc_7_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1323_acc_7_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1323_acc_7_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "StakeConfig11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1323_acc_8_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1323_acc_8_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1323_acc_8_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1323_acc_8_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1323_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1323_raw_sz;
  test.expected_result = -6;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1324(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 108,106,75,55,114,118,113,15,26,128,117,125,83,90,122,78,77,112,79,61,30,109,56,126,111,103,92,62,89,121,2,127,87,29,98,24,123,110,33,116,124,76,120,82,27,105,80 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_withdraw_stake::new_behavior";
  test.test_nonce  = 538;
  test.test_number = 1324;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 9;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "4omDQx3gmg2bZqkLjTZoCUadshXV7gMLPEhg5bL5urnq",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1000000010UL;
  test_acc->result_lamports = 1000000000UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1324_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1324_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1324_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1324_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "C1yhE9JiKDWKyWpGwwLR96Q7ZVfs3fTqcKnWEBBeLR4P",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1324_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1324_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1324_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1324_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "HVtYUPmJaFWi7Sucsc1Fq7etkoRuqcZjbXBcsvvmuugm",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 10UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1324_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1324_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1324_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1324_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "EQy3NVjkmA8FCjMaB7pFfNzcVGKTRxg8whZwxCCJAAoo",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 42UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1324_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1324_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1324_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1324_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "AL7b2h1vjn2okVcxtDovAS2ang4Qscoscmz4pnnzqsM2",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1324_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1324_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1324_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1324_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1324_acc_5_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1324_acc_5_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1324_acc_5_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1324_acc_5_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1324_acc_6_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1324_acc_6_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1324_acc_6_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1324_acc_6_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1324_acc_7_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1324_acc_7_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1324_acc_7_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1324_acc_7_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "StakeConfig11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1324_acc_8_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1324_acc_8_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1324_acc_8_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1324_acc_8_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1324_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1324_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
