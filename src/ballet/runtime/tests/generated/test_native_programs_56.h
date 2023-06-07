#include "../fd_tests.h"
int test_1400(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 29,2,77,128,78,122,24,79,75,123,89,109,114,125,56,118,108,90,61,106,33,76,120,116,27,127,105,87,55,15,117,112,62,103,30,126,110,113,82,92,124,83,80,121,26,111,98 };
  test.disable_feature = disabled_features;
  test.test_name = "system_instruction_processor::tests::test_nonce_account_upgrade";
  test.test_nonce  = 29;
  test.test_number = 1400;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 1;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111113VQvWs5MeAWGmLhTGGU4RB6xoEKU6Zp1ZYtw",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1000000UL;
  test_acc->result_lamports = 1000000UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1400_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1400_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1400_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1400_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1400_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1400_raw_sz;
  test.expected_result = -2;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1401(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 103,87,123,98,80,121,108,26,56,114,113,15,77,24,106,90,33,105,127,55,110,29,61,124,30,111,83,126,117,79,118,27,78,92,109,120,116,125,112,89,76,75,122,2,82,128,62 };
  test.disable_feature = disabled_features;
  test.test_name = "system_instruction_processor::tests::test_nonce_account_upgrade";
  test.test_nonce  = 23;
  test.test_number = 1401;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 1;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111113VQvWs5MeAWGmLhTGGU4RB6xoEKU6Zp1ZYtw",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1000000UL;
  test_acc->result_lamports = 1000000UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1401_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1401_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1401_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1401_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1401_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1401_raw_sz;
  test.expected_result = -2;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1402(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 113,78,110,90,125,82,123,128,61,98,114,116,15,127,121,29,106,87,109,2,30,117,76,111,27,103,126,83,124,105,92,122,77,79,118,120,55,33,24,80,56,62,26,89,75,108,112 };
  test.disable_feature = disabled_features;
  test.test_name = "system_instruction_processor::tests::test_nonce_account_upgrade";
  test.test_nonce  = 31;
  test.test_number = 1402;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 1;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111113VQvWs5MeAWGmLhTGGU4RB6xoEKU6Zp1ZYtw",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1000000UL;
  test_acc->result_lamports = 1000000UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1402_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1402_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1402_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1402_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1402_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1402_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1403(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 125,33,79,126,80,61,123,106,109,127,120,76,30,105,113,83,124,111,82,118,24,108,87,78,2,90,77,128,98,29,103,112,121,15,92,89,117,110,55,62,75,27,116,26,114,56,122 };
  test.disable_feature = disabled_features;
  test.test_name = "system_instruction_processor::tests::test_nonce_account_upgrade";
  test.test_nonce  = 34;
  test.test_number = 1403;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 1;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111113VQvWs5MeAWGmLhTGGU4RB6xoEKU6Zp1ZYtw",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1000000UL;
  test_acc->result_lamports = 1000000UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1403_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1403_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1403_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1403_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1403_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1403_raw_sz;
  test.expected_result = -2;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1404(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 92,114,112,103,125,105,29,62,79,111,27,83,116,24,55,77,56,117,78,2,15,124,106,110,122,127,89,87,82,108,26,113,61,98,118,75,109,120,30,33,80,123,126,121,128,90,76 };
  test.disable_feature = disabled_features;
  test.test_name = "system_instruction_processor::tests::test_nonce_account_upgrade";
  test.test_nonce  = 25;
  test.test_number = 1404;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 1;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111113VQvWs5MeAWGmLhTGGU4RB6xoEKU6Zp1ZYtw",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1000000UL;
  test_acc->result_lamports = 1000000UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1404_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1404_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1404_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1404_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1404_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1404_raw_sz;
  test.expected_result = -2;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1405(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 92,114,112,103,125,105,29,62,79,111,27,83,116,24,55,77,56,117,78,2,15,124,106,110,122,127,89,87,82,108,26,113,61,98,118,75,109,120,30,33,80,123,126,121,128,90,76 };
  test.disable_feature = disabled_features;
  test.test_name = "system_instruction_processor::tests::test_nonce_account_upgrade";
  test.test_nonce  = 19;
  test.test_number = 1405;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 1;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111113XVEaDUpmJoDKKE3xAnW1U6TBTWJ8cP2ydU3",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1000000UL;
  test_acc->result_lamports = 1000000UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1405_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1405_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1405_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1405_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1405_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1405_raw_sz;
  test.expected_result = -2;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1406(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 92,114,112,103,125,105,29,62,79,111,27,83,116,24,55,77,56,117,78,2,15,124,106,110,122,127,89,87,82,108,26,113,61,98,118,75,109,120,30,33,80,123,126,121,128,90,76 };
  test.disable_feature = disabled_features;
  test.test_name = "system_instruction_processor::tests::test_nonce_account_upgrade";
  test.test_nonce  = 22;
  test.test_number = 1406;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 1;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111113XVEaDUpmJoDKKE3xAnW1U6TBTWJ8cP2ydU3",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1000000UL;
  test_acc->result_lamports = 1000000UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1406_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1406_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1406_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1406_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1406_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1406_raw_sz;
  test.expected_result = -2;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1407(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 92,114,112,103,125,105,29,62,79,111,27,83,116,24,55,77,56,117,78,2,15,124,106,110,122,127,89,87,82,108,26,113,61,98,118,75,109,120,30,33,80,123,126,121,128,90,76 };
  test.disable_feature = disabled_features;
  test.test_name = "system_instruction_processor::tests::test_nonce_account_upgrade";
  test.test_nonce  = 23;
  test.test_number = 1407;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 1;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111113XVEaDUpmJoDKKE3xAnW1U6TBTWJ8cP2ydU3",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1000000UL;
  test_acc->result_lamports = 1000000UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1407_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1407_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1407_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1407_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1407_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1407_raw_sz;
  test.expected_result = -2;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1408(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 92,114,112,103,125,105,29,62,79,111,27,83,116,24,55,77,56,117,78,2,15,124,106,110,122,127,89,87,82,108,26,113,61,98,118,75,109,120,30,33,80,123,126,121,128,90,76 };
  test.disable_feature = disabled_features;
  test.test_name = "system_instruction_processor::tests::test_nonce_account_upgrade";
  test.test_nonce  = 25;
  test.test_number = 1408;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 1;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111113XVEaDUpmJoDKKE3xAnW1U6TBTWJ8cP2ydU3",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1000000UL;
  test_acc->result_lamports = 1000000UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1408_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1408_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1408_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1408_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1408_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1408_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1409(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 92,114,112,103,125,105,29,62,79,111,27,83,116,24,55,77,56,117,78,2,15,124,106,110,122,127,89,87,82,108,26,113,61,98,118,75,109,120,30,33,80,123,126,121,128,90,76 };
  test.disable_feature = disabled_features;
  test.test_name = "system_instruction_processor::tests::test_nonce_account_upgrade";
  test.test_nonce  = 26;
  test.test_number = 1409;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 1;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111113XVEaDUpmJoDKKE3xAnW1U6TBTWJ8cP2ydU3",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1000000UL;
  test_acc->result_lamports = 1000000UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1409_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1409_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1409_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1409_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1409_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1409_raw_sz;
  test.expected_result = -2;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1410(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 120,27,30,78,123,80,109,75,82,77,92,62,33,105,114,56,103,83,79,90,122,127,113,24,121,108,125,2,26,55,126,61,106,89,87,117,98,76,118,29,112,15,124,128,111,116,110 };
  test.disable_feature = disabled_features;
  test.test_name = "system_instruction_processor::tests::test_nonce_advance_with_empty_recent_blockhashes_fail";
  test.test_nonce  = 32;
  test.test_number = 1410;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 2;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111113VQXBG6FLso6JTt28BSe5rcqXSgxqd6myiab",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1000000UL;
  test_acc->result_lamports = 1000000UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1410_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1410_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1410_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1410_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRecentB1ockHashes11111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1410_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1410_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1410_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1410_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1410_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1410_raw_sz;
  test.expected_result = -26;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1411(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 120,27,30,78,123,80,109,75,82,77,92,62,33,105,114,56,103,83,79,90,122,127,113,24,121,108,125,2,26,55,126,61,106,89,87,117,98,76,118,29,112,15,124,128,111,116,110 };
  test.disable_feature = disabled_features;
  test.test_name = "system_instruction_processor::tests::test_nonce_advance_with_empty_recent_blockhashes_fail";
  test.test_nonce  = 39;
  test.test_number = 1411;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 2;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111113XWSb2S9fAvkhwgMNRrm1RYpzpPouSWjj8R5",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1000000UL;
  test_acc->result_lamports = 1000000UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1411_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1411_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1411_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1411_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRecentB1ockHashes11111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1411_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1411_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1411_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1411_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1411_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1411_raw_sz;
  test.expected_result = -26;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1412(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 30,76,127,109,27,77,117,78,118,33,90,24,55,114,29,128,112,113,83,62,111,122,126,15,120,103,61,26,124,79,110,87,56,125,80,121,123,89,98,108,2,75,92,116,106,82,105 };
  test.disable_feature = disabled_features;
  test.test_name = "system_instruction_processor::tests::test_nonce_advance_with_empty_recent_blockhashes_fail";
  test.test_nonce  = 28;
  test.test_number = 1412;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111113VQXBG6FLso6JTt28BSe5rcqXSgxqd6myiab",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1000000UL;
  test_acc->result_lamports = 1000000UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1412_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1412_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1412_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1412_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRecentB1ockHashes11111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1412_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1412_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1412_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1412_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1412_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1412_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1412_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1412_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1412_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1412_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1413(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 30,76,127,109,27,77,117,78,118,33,90,24,55,114,29,128,112,113,83,62,111,122,126,15,120,103,61,26,124,79,110,87,56,125,80,121,123,89,98,108,2,75,92,116,106,82,105 };
  test.disable_feature = disabled_features;
  test.test_name = "system_instruction_processor::tests::test_nonce_advance_with_empty_recent_blockhashes_fail";
  test.test_nonce  = 29;
  test.test_number = 1413;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111113XWSb2S9fAvkhwgMNRrm1RYpzpPouSWjj8R5",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1000000UL;
  test_acc->result_lamports = 1000000UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1413_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1413_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1413_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1413_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRecentB1ockHashes11111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1413_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1413_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1413_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1413_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1413_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1413_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1413_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1413_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1413_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1413_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1414(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 117,123,56,15,103,82,106,114,92,29,125,24,61,105,90,124,113,111,75,98,108,83,62,79,110,55,122,89,2,77,87,116,120,26,78,118,121,27,80,126,76,30,109,128,127,112,33 };
  test.disable_feature = disabled_features;
  test.test_name = "system_instruction_processor::tests::test_nonce_initialize_with_empty_recent_blockhashes_fail";
  test.test_nonce  = 27;
  test.test_number = 1414;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111113VSXsH1nqKLzcqyBpcZjkT3TtNqV8LewttAK",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1000000UL;
  test_acc->result_lamports = 1000000UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1414_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1414_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1414_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1414_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRecentB1ockHashes11111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1414_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1414_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1414_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1414_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1414_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1414_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1414_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1414_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1414_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1414_raw_sz;
  test.expected_result = -26;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1415(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 117,123,56,15,103,82,106,114,92,29,125,24,61,105,90,124,113,111,75,98,108,83,62,79,110,55,122,89,2,77,87,116,120,26,78,118,121,27,80,126,76,30,109,128,127,112,33 };
  test.disable_feature = disabled_features;
  test.test_name = "system_instruction_processor::tests::test_nonce_initialize_with_empty_recent_blockhashes_fail";
  test.test_nonce  = 20;
  test.test_number = 1415;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111113XWqvdRFxTdwApVnWWtBLk2xGc2KAPDyJxjR",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1000000UL;
  test_acc->result_lamports = 1000000UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1415_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1415_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1415_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1415_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRecentB1ockHashes11111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1415_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1415_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1415_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1415_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1415_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1415_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1415_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1415_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1415_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1415_raw_sz;
  test.expected_result = -26;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1416(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 24,87,55,26,27,90,122,2,114,118,89,105,82,110,112,30,83,106,103,33,125,61,29,117,80,123,79,111,108,128,121,76,92,116,75,127,126,77,120,113,56,62,78,109,124,15,98 };
  test.disable_feature = disabled_features;
  test.test_name = "system_instruction_processor::tests::test_process_authorize_bad_account_data_fail";
  test.test_nonce  = 19;
  test.test_number = 1416;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 2;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111113VSwCszu8c4B5incxhbA5mXbAATzPHNBUiUf",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "1111113VTjt5y7jBUY1URVEsdzkQVqhjizuAneeP7M",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1416_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1416_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1416_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1416_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111113VTLYUz1RtmMYbc46ncaR61iRx6VeE5R4Yo1",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "1111113VU9DgxE2UBiUMEvNxfR5iyxyXMWA7VtEDRh",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1416_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1416_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1416_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1416_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1416_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1416_raw_sz;
  test.expected_result = -4;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1417(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 24,87,55,26,27,90,122,2,114,118,89,105,82,110,112,30,83,106,103,33,125,61,29,117,80,123,79,111,108,128,121,76,92,116,75,127,126,77,120,113,56,62,78,109,124,15,98 };
  test.disable_feature = disabled_features;
  test.test_name = "system_instruction_processor::tests::test_process_authorize_bad_account_data_fail";
  test.test_nonce  = 21;
  test.test_number = 1417;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 2;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111113XXFGEQNFkM7dhKDebubg4X5YPepRKwCto3m",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "1111113XY3wSNarKmUZSx5vmxSLhVL5xupwDMg4TgT",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1417_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1417_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1417_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1417_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111113XXebqPUZ34J6a8engw21P1CpBHKgGeSUdN7",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "1111113XYTH3Mh9cUf2KmX4ryrg1yTMkYLCA4ueHzo",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1417_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1417_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1417_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1417_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1417_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1417_raw_sz;
  test.expected_result = -4;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1418(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 83,98,126,106,89,109,92,112,24,80,15,123,127,75,108,121,61,77,82,113,105,118,56,27,120,125,124,30,78,103,79,87,117,90,29,62,2,76,116,114,55,33,128,111,110,122,26 };
  test.disable_feature = disabled_features;
  test.test_name = "system_instruction_processor::tests::test_process_authorize_ix_ok";
  test.test_nonce  = 39;
  test.test_number = 1418;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111113VVMEVuYvLKFryhDoDjg5gSLntF1vwdayiNj",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1000000UL;
  test_acc->result_lamports = 1000000UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1418_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1418_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1418_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1418_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRecentB1ockHashes11111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1418_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1418_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1418_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1418_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1418_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1418_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1418_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1418_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1418_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1418_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1419(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 83,98,126,106,89,109,92,112,24,80,15,123,127,75,108,121,61,77,82,113,105,118,56,27,120,125,124,30,78,103,79,87,117,90,29,62,2,76,116,114,55,33,128,111,110,122,26 };
  test.disable_feature = disabled_features;
  test.test_name = "system_instruction_processor::tests::test_process_authorize_ix_ok";
  test.test_nonce  = 27;
  test.test_number = 1419;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111113XYrceLoSuBqVCaxCx1H1LTadYAqT6n9E8K9",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1000000UL;
  test_acc->result_lamports = 1000000UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1419_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1419_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1419_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1419_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRecentB1ockHashes11111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1419_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1419_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1419_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1419_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1419_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1419_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1419_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1419_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1419_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1419_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1420(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 120,123,24,118,103,109,87,75,89,128,114,116,117,106,92,110,90,124,33,26,27,62,61,126,82,79,108,122,113,80,127,112,55,15,30,78,29,121,105,125,111,2,98,83,77,56,76 };
  test.disable_feature = disabled_features;
  test.test_name = "system_instruction_processor::tests::test_process_authorize_ix_ok";
  test.test_nonce  = 41;
  test.test_number = 1420;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 1;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111113VVMEVuYvLKFryhDoDjg5gSLntF1vwdayiNj",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1000000UL;
  test_acc->result_lamports = 1000000UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1420_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1420_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1420_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1420_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1420_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1420_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1421(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 120,123,24,118,103,109,87,75,89,128,114,116,117,106,92,110,90,124,33,26,27,62,61,126,82,79,108,122,113,80,127,112,55,15,30,78,29,121,105,125,111,2,98,83,77,56,76 };
  test.disable_feature = disabled_features;
  test.test_name = "system_instruction_processor::tests::test_process_authorize_ix_ok";
  test.test_nonce  = 38;
  test.test_number = 1421;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 1;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111113XYrceLoSuBqVCaxCx1H1LTadYAqT6n9E8K9",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1000000UL;
  test_acc->result_lamports = 1000000UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1421_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1421_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1421_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1421_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1421_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1421_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1422(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 123,92,83,108,127,126,114,78,89,2,55,61,122,118,105,121,111,33,75,80,62,124,77,76,112,120,29,103,109,128,116,110,56,113,79,15,125,30,87,26,24,117,106,27,98,82,90 };
  test.disable_feature = disabled_features;
  test.test_name = "system_instruction_processor::tests::test_process_bogus_instruction";
  test.test_nonce  = 24;
  test.test_number = 1422;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 0;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_base58_decode_32( "11111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1422_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1422_raw_sz;
  test.expected_result = -20;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1423(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 123,92,83,108,127,126,114,78,89,2,55,61,122,118,105,121,111,33,75,80,62,124,77,76,112,120,29,103,109,128,116,110,56,113,79,15,125,30,87,26,24,117,106,27,98,82,90 };
  test.disable_feature = disabled_features;
  test.test_name = "system_instruction_processor::tests::test_process_bogus_instruction";
  test.test_nonce  = 32;
  test.test_number = 1423;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 0;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_base58_decode_32( "11111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1423_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1423_raw_sz;
  test.expected_result = -20;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1424(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 128,87,109,83,55,112,79,105,123,114,29,113,2,27,108,80,90,120,75,76,122,56,117,30,62,121,89,124,125,110,116,77,98,103,26,126,15,92,24,111,61,82,78,118,106,33,127 };
  test.disable_feature = disabled_features;
  test.test_name = "system_instruction_processor::tests::test_process_bogus_instruction";
  test.test_nonce  = 26;
  test.test_number = 1424;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 1;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111113VWZFJrspCSoFc9XDUow5dticF8XhmmHjDKm",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1424_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1424_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1424_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1424_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1424_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1424_raw_sz;
  test.expected_result = -20;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
