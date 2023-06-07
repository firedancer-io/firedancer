#include "../fd_tests.h"
int test_0(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 89,120,123,121,111,110,124,30,61,75,127,126,125,24,15,80,105,114,109,56,62,113,55,77,128,29,2,83,27,79,82,108,87,122,78,117,90,26,98,92,116,106,112,118,76,103,33 };
  test.disable_feature = disabled_features;
  test.test_name = "config_processor::tests::test_config_bad_owner";
  test.test_nonce  = 3;
  test.test_number = 0;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 1;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "J9QybVjRRmrVT6zuoqwLxy1SZeUndtu6b17fn1UMUP33",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_0_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_0_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_0_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_0_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_0_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_0_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 89,120,123,121,111,110,124,30,61,75,127,126,125,24,15,80,105,114,109,56,62,113,55,77,128,29,2,83,27,79,82,108,87,122,78,117,90,26,98,92,116,106,112,118,76,103,33 };
  test.disable_feature = disabled_features;
  test.test_name = "config_processor::tests::test_config_bad_owner";
  test.test_nonce  = 0;
  test.test_number = 1;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 1;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "4ARkUCGV3cUe27wXBs8GcLPK283zcz9BGmBophmcri9b",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_2(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 33,106,78,82,90,105,127,112,123,114,30,56,120,103,26,108,79,111,113,29,76,89,27,125,128,24,87,61,80,98,109,124,2,62,116,77,110,83,55,122,15,117,92,118,75,121,126 };
  test.disable_feature = disabled_features;
  test.test_name = "config_processor::tests::test_config_bad_owner";
  test.test_nonce  = 16;
  test.test_number = 2;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 2;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111111ogCyDbaRMvkdsHB3qfdyFYaG1WtRUAfdh",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "111111131h1vYVSYuKP6AhS86fbRdMw9XHiZAvAaj",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_2_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_2_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_2_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_2_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111112D1oxKts8YPdTJRG5FzxTNpMtWmq8hkVx3",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111112cMQwSC9qirWGjZM6gLGwW69X22mqwLLGP",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_2_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_2_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_2_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_2_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_2_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_2_raw_sz;
  test.expected_result = -47;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_3(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 33,106,78,82,90,105,127,112,123,114,30,56,120,103,26,108,79,111,113,29,76,89,27,125,128,24,87,61,80,98,109,124,2,62,116,77,110,83,55,122,15,117,92,118,75,121,126 };
  test.disable_feature = disabled_features;
  test.test_name = "config_processor::tests::test_config_bad_owner";
  test.test_nonce  = 13;
  test.test_number = 3;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 2;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111111ogCyDbaRMvkdsHB3qfdyFYaG1WtRUAfdh",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "111111131h1vYVSYuKP6AhS86fbRdMw9XHiZAvAaj",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_3_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_3_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_3_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_3_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111112D1oxKts8YPdTJRG5FzxTNpMtWmq8hkVx3",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111112cMQwSC9qirWGjZM6gLGwW69X22mqwLLGP",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_3_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_3_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_3_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_3_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_3_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_3_raw_sz;
  test.expected_result = -47;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_4(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 110,76,106,61,126,112,98,113,62,79,114,15,26,78,127,121,82,30,105,118,111,123,90,120,29,24,80,125,117,108,33,128,77,116,124,122,56,109,27,55,103,87,2,75,92,83,89 };
  test.disable_feature = disabled_features;
  test.test_name = "config_processor::tests::test_config_initialize_contains_duplicates_fails";
  test.test_nonce  = 12;
  test.test_number = 4;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 1;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "7DECKteHDY3KcUpzYsPe7VBJzqoMigDBwSyUrFbGeKHB",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_4_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_4_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_4_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_4_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_4_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_4_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_5(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 110,76,106,61,126,112,98,113,62,79,114,15,26,78,127,121,82,30,105,118,111,123,90,120,29,24,80,125,117,108,33,128,77,116,124,122,56,109,27,55,103,87,2,75,92,83,89 };
  test.disable_feature = disabled_features;
  test.test_name = "config_processor::tests::test_config_initialize_contains_duplicates_fails";
  test.test_nonce  = 3;
  test.test_number = 5;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 1;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "6pzHuYwj2SvrtuNkCgfuoAcV7oiyGmvv6d3QGtaBNCte",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_5_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_5_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_5_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_5_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_5_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_5_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_6(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 110,76,106,61,126,112,98,113,62,79,114,15,26,78,127,121,82,30,105,118,111,123,90,120,29,24,80,125,117,108,33,128,77,116,124,122,56,109,27,55,103,87,2,75,92,83,89 };
  test.disable_feature = disabled_features;
  test.test_name = "config_processor::tests::test_config_initialize_contains_duplicates_fails";
  test.test_nonce  = 16;
  test.test_number = 6;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 2;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "6pzHuYwj2SvrtuNkCgfuoAcV7oiyGmvv6d3QGtaBNCte",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_6_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_6_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_6_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_6_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111115RidqCHAoz6dzmXxGcfWLNzevYqNpaRAUo",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111115q4EpJaTXAZWpCg3J2zppWGSZ46KXozzo9",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_6_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_6_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_6_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_6_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_6_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_6_raw_sz;
  test.expected_result = -2;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_7(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 92,29,124,61,118,109,80,123,24,78,128,79,33,116,122,90,75,105,83,112,125,117,98,76,2,56,108,103,111,15,126,82,87,106,62,110,30,121,127,114,26,77,113,55,27,120,89 };
  test.disable_feature = disabled_features;
  test.test_name = "config_processor::tests::test_config_initialize_contains_duplicates_fails";
  test.test_nonce  = 24;
  test.test_number = 7;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 2;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "7DECKteHDY3KcUpzYsPe7VBJzqoMigDBwSyUrFbGeKHB",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_7_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_7_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_7_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_7_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111117SQekjmcMtR25wEPPiL6m1Mb5586NkLL4X",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111117qkFjr4u54stuNNUR8fRF8dNhaP35yvANs",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_7_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_7_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_7_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_7_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_7_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_7_raw_sz;
  test.expected_result = -2;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_8(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 30,114,118,124,77,15,108,128,89,121,98,56,82,75,126,112,125,105,120,78,2,55,127,92,87,111,123,109,27,90,24,79,116,103,117,122,80,33,61,113,106,110,76,62,26,83,29 };
  test.disable_feature = disabled_features;
  test.test_name = "config_processor::tests::test_config_initialize_no_panic";
  test.test_nonce  = 0;
  test.test_number = 8;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 1;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "Bi64x32apnC2B5bS4LqX4reQUTGF2FU4Nnvie2qa2Q9u",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_8_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_8_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_8_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_8_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_8_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_8_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_9(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 106,55,15,33,116,61,98,110,76,2,127,105,128,82,114,79,89,92,125,122,118,103,26,80,78,117,124,83,30,56,29,62,121,113,126,123,112,24,77,90,108,109,27,75,87,120,111 };
  test.disable_feature = disabled_features;
  test.test_name = "config_processor::tests::test_config_initialize_no_panic";
  test.test_nonce  = 13;
  test.test_number = 9;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 0;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_9_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_9_raw_sz;
  test.expected_result = -20;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_10(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 106,55,15,33,116,61,98,110,76,2,127,105,128,82,114,79,89,92,125,122,118,103,26,80,78,117,124,83,30,56,29,62,121,113,126,123,112,24,77,90,108,109,27,75,87,120,111 };
  test.disable_feature = disabled_features;
  test.test_name = "config_processor::tests::test_config_initialize_no_panic";
  test.test_nonce  = 17;
  test.test_number = 10;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 0;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_10_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_10_raw_sz;
  test.expected_result = -20;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_11(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 106,55,15,33,116,61,98,110,76,2,127,105,128,82,114,79,89,92,125,122,118,103,26,80,78,117,124,83,30,56,29,62,121,113,126,123,112,24,77,90,108,109,27,75,87,120,111 };
  test.disable_feature = disabled_features;
  test.test_name = "config_processor::tests::test_config_initialize_no_panic";
  test.test_nonce  = 5;
  test.test_number = 11;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 1;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "7LKna1wLb4HtniSzCvmsbKDiU7qZA6fwgCmbJRWMjbtg",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_11_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_11_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_11_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_11_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_11_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_11_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_12(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 114,80,26,79,61,122,24,123,62,103,111,98,89,108,128,117,124,2,87,120,15,77,112,110,90,33,75,29,118,55,27,109,83,127,116,125,121,78,82,113,126,30,92,105,106,76,56 };
  test.disable_feature = disabled_features;
  test.test_name = "config_processor::tests::test_config_update_contains_duplicates_fails";
  test.test_nonce  = 2;
  test.test_number = 12;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 1;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "AsAkUR8oZPZDDFBWm6ARfiUjh7YFALhjxbfCQnPJJwEX",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_12_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_12_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_12_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_12_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_12_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_12_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_13(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 114,80,26,79,61,122,24,123,62,103,111,98,89,108,128,117,124,2,87,120,15,77,112,110,90,33,75,29,118,55,27,109,83,127,116,125,121,78,82,113,126,30,92,105,106,76,56 };
  test.disable_feature = disabled_features;
  test.test_name = "config_processor::tests::test_config_update_contains_duplicates_fails";
  test.test_nonce  = 4;
  test.test_number = 13;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 1;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "7X8j1ZxHa84aAKMiNuK1TsHyqjK3KZEhcbH35SCiC2MB",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_13_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_13_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_13_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_13_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_13_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_13_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_14(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 122,33,76,90,79,29,105,124,117,56,61,125,123,89,98,77,87,121,62,110,109,127,30,112,24,27,111,15,114,82,106,128,92,2,83,80,75,78,120,103,118,116,26,108,126,113,55 };
  test.disable_feature = disabled_features;
  test.test_name = "config_processor::tests::test_config_update_contains_duplicates_fails";
  test.test_nonce  = 25;
  test.test_number = 14;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 2;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "AsAkUR8oZPZDDFBWm6ARfiUjh7YFALhjxbfCQnPJJwEX",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_14_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_14_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_14_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_14_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111115RidqCHAoz6dzmXxGcfWLNzevYqNpaRAUo",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111116EPqoQskEM2Pddp8KTL9JdYEBZMGF3aq7V",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_14_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_14_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_14_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_14_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_14_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_14_raw_sz;
  test.expected_result = -2;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_15(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 33,76,111,106,78,103,121,62,83,112,113,123,90,61,109,105,116,55,75,80,127,126,124,125,108,98,82,26,114,77,29,110,92,128,122,118,89,117,79,27,30,2,15,24,56,120,87 };
  test.disable_feature = disabled_features;
  test.test_name = "config_processor::tests::test_config_update_contains_duplicates_fails";
  test.test_nonce  = 15;
  test.test_number = 15;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "AsAkUR8oZPZDDFBWm6ARfiUjh7YFALhjxbfCQnPJJwEX",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_15_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_15_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_15_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_15_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111115RidqCHAoz6dzmXxGcfWLNzevYqNpaRAUo",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111116EPqoQskEM2Pddp8KTL9JdYEBZMGF3aq7V",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_15_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_15_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_15_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_15_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111115q4EpJaTXAZWpCg3J2zppWGSZ46KXozzo9",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111116djSnXB2wXVGT4xDLsfTnkp1p4cCxHAfRq",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_15_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_15_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_15_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_15_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_15_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_15_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_16(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 33,76,111,106,78,103,121,62,83,112,113,123,90,61,109,105,116,55,75,80,127,126,124,125,108,98,82,26,114,77,29,110,92,128,122,118,89,117,79,27,30,2,15,24,56,120,87 };
  test.disable_feature = disabled_features;
  test.test_name = "config_processor::tests::test_config_update_contains_duplicates_fails";
  test.test_nonce  = 27;
  test.test_number = 16;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 2;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "7X8j1ZxHa84aAKMiNuK1TsHyqjK3KZEhcbH35SCiC2MB",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_16_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_16_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_16_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_16_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111118eRTi4fUVRoeYEeeTyL4DPAwxatvWT5q1Z",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111119T6fgHG3unjQB6vpWozhBdiXDbQovvFVeF",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_16_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_16_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_16_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_16_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_16_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_16_raw_sz;
  test.expected_result = -2;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_17(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 33,76,111,106,78,103,121,62,83,112,113,123,90,61,109,105,116,55,75,80,127,126,124,125,108,98,82,26,114,77,29,110,92,128,122,118,89,117,79,27,30,2,15,24,56,120,87 };
  test.disable_feature = disabled_features;
  test.test_name = "config_processor::tests::test_config_update_contains_duplicates_fails";
  test.test_nonce  = 18;
  test.test_number = 17;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "7X8j1ZxHa84aAKMiNuK1TsHyqjK3KZEhcbH35SCiC2MB",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_17_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_17_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_17_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_17_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111118eRTi4fUVRoeYEeeTyL4DPAwxatvWT5q1Z",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111119T6fgHG3unjQB6vpWozhBdiXDbQovvFVeF",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_17_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_17_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_17_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_17_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "111111193m4hAxmCcGXMfnjVPfNhWSjb69sDgffKu",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111119rSGfPZLcyCGzY4uYEL1fkzJr6fke9qKxb",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_17_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_17_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_17_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_17_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_17_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_17_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_18(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 126,124,125,111,118,122,83,105,26,108,110,2,79,55,89,56,78,33,117,29,80,61,112,123,106,76,75,87,82,15,90,128,109,127,24,116,113,62,121,77,103,98,114,120,30,92,27 };
  test.disable_feature = disabled_features;
  test.test_name = "config_processor::tests::test_config_updates";
  test.test_nonce  = 6;
  test.test_number = 18;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 1;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "81fotDFihmt1p6r1AdmBNpL9aEBXtLWtRZu6jjBPBozW",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_18_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_18_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_18_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_18_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_18_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_18_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_19(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 126,124,125,111,118,122,83,105,26,108,110,2,79,55,89,56,78,33,117,29,80,61,112,123,106,76,75,87,82,15,90,128,109,127,24,116,113,62,121,77,103,98,114,120,30,92,27 };
  test.disable_feature = disabled_features;
  test.test_name = "config_processor::tests::test_config_updates";
  test.test_nonce  = 2;
  test.test_number = 19;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 1;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "ANFPuKmeR9jDeAFURRBpGdaXYgPhduuyFXiAvPpuem1p",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_19_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_19_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_19_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_19_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_19_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_19_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_20(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 117,108,116,92,122,112,15,27,120,110,80,33,121,61,118,76,2,105,123,30,82,75,26,29,111,127,113,62,126,89,24,90,78,128,79,83,124,77,98,114,125,109,106,87,55,56,103 };
  test.disable_feature = disabled_features;
  test.test_name = "config_processor::tests::test_config_updates";
  test.test_nonce  = 30;
  test.test_number = 20;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "81fotDFihmt1p6r1AdmBNpL9aEBXtLWtRZu6jjBPBozW",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_20_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_20_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_20_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_20_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111119T6fgHG3unjQB6vpWozhBdiXDbQovvFVeF",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "1111111Af7Udc9v3L82dQM5b4zee1Xt77Be4czzbH",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_20_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_20_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_20_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_20_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111119rSGfPZLcyCGzY4uYEL1fkzJr6fke9qKxb",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "1111111BTngbpkVTh3nGGdFdufHcG5TN7hXV6AfDy",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_20_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_20_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_20_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_20_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_20_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_20_raw_sz;
  test.expected_result = -8;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_21(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 117,108,116,92,122,112,15,27,120,110,80,33,121,61,118,76,2,105,123,30,82,75,26,29,111,127,113,62,126,89,24,90,78,128,79,83,124,77,98,114,125,109,106,87,55,56,103 };
  test.disable_feature = disabled_features;
  test.test_name = "config_processor::tests::test_config_updates";
  test.test_nonce  = 30;
  test.test_number = 21;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "ANFPuKmeR9jDeAFURRBpGdaXYgPhduuyFXiAvPpuem1p",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_21_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_21_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_21_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_21_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111B4T5ciTCkWauSqVAcVKy88ofjcSamrapud",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "1111111CGTta3M4t3yXu8uRgkKvaWd2d8DQuZLKrf",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_21_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_21_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_21_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_21_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111BTngbpkVTh3nGGdFdufHcG5TN7hXV6AfDy",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "1111111CfoVZ9eMbESQia3WiAfF4dtpFdUMcnvAB1",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_21_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_21_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_21_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_21_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_21_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_21_raw_sz;
  test.expected_result = -8;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_22(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 80,29,62,105,89,92,123,117,98,90,124,56,24,103,128,87,26,108,55,127,110,109,126,76,79,61,30,106,78,118,83,2,116,114,120,33,77,27,82,112,121,125,75,122,111,113,15 };
  test.disable_feature = disabled_features;
  test.test_name = "config_processor::tests::test_config_updates";
  test.test_nonce  = 19;
  test.test_number = 22;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "81fotDFihmt1p6r1AdmBNpL9aEBXtLWtRZu6jjBPBozW",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_22_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_22_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_22_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_22_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111119T6fgHG3unjQB6vpWozhBdiXDbQovvFVeF",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "1111111Af7Udc9v3L82dQM5b4zee1Xt77Be4czzbH",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_22_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_22_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_22_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_22_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111119rSGfPZLcyCGzY4uYEL1fkzJr6fke9qKxb",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "1111111BTngbpkVTh3nGGdFdufHcG5TN7hXV6AfDy",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_22_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_22_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_22_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_22_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_22_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_22_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_23(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 109,122,15,127,30,128,103,78,120,56,123,117,55,124,80,87,26,113,27,98,116,105,62,90,76,126,110,83,77,108,33,75,24,61,89,106,112,92,118,2,114,125,111,79,121,82,29 };
  test.disable_feature = disabled_features;
  test.test_name = "config_processor::tests::test_config_updates";
  test.test_nonce  = 27;
  test.test_number = 23;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "81fotDFihmt1p6r1AdmBNpL9aEBXtLWtRZu6jjBPBozW",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_23_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_23_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_23_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_23_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111119T6fgHG3unjQB6vpWozhBdiXDbQovvFVeF",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "1111111Af7Udc9v3L82dQM5b4zee1Xt77Be4czzbH",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_23_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_23_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_23_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_23_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111119rSGfPZLcyCGzY4uYEL1fkzJr6fke9qKxb",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "1111111BTngbpkVTh3nGGdFdufHcG5TN7hXV6AfDy",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_23_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_23_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_23_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_23_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_23_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_23_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_24(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 90,80,125,15,127,24,87,56,114,30,61,82,123,26,89,120,75,55,113,108,110,117,126,2,116,29,33,76,79,103,112,121,128,118,124,109,77,62,27,92,98,122,111,105,83,106,78 };
  test.disable_feature = disabled_features;
  test.test_name = "config_processor::tests::test_config_updates";
  test.test_nonce  = 31;
  test.test_number = 24;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "81fotDFihmt1p6r1AdmBNpL9aEBXtLWtRZu6jjBPBozW",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_24_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_24_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_24_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_24_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111119T6fgHG3unjQB6vpWozhBdiXDbQovvFVeF",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "1111111Af7Udc9v3L82dQM5b4zee1Xt77Be4czzbH",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_24_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_24_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_24_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_24_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111AFmseVrdL9f9oyCzZefL9tG6UbvhMPRAGw",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "1111111Bs8Haw3nAsWf5hmLfKzc6PMEzcxUCKkVYK",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_24_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_24_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_24_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_24_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_24_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_24_raw_sz;
  test.expected_result = -8;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
