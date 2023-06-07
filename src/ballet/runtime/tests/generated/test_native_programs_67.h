#include "../fd_tests.h"
int test_1675(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 129;
  uchar disabled_features[] = { 73,109,121,0,96,1,18,25,13,16,102,68,33,57,49,43,80,93,32,123,9,81,23,44,126,28,42,113,62,127,97,87,2,116,75,12,39,55,34,61,63,85,94,11,112,20,86,119,51,120,65,52,46,17,26,30,78,117,111,21,58,36,41,38,8,24,48,106,88,83,66,114,72,92,98,14,27,53,108,110,47,90,3,35,71,95,122,103,70,40,4,22,56,128,82,60,107,104,54,10,79,118,101,6,125,19,31,5,15,105,69,74,124,59,67,77,91,7,29,37,76,115,45,50,100,84,64,89,99 };
  test.disable_feature = disabled_features;
  test.test_name = "vote_processor::tests::test_voter_base_key_can_authorize_new_voter";
  test.test_nonce  = 63;
  test.test_number = 1675;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "11111113pNDtm61yGF8j2ycAwLEPsuWQXobye5qDR",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1675_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1675_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1675_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1675_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1675_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1675_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1675_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1675_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111114DhpssPJgSi1YU7hCMfYt1BJ334YgsffXm",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1675_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1675_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1675_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1675_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1675_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1675_raw_sz;
  test.expected_result = -3;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1676(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 73,109,121,0,96,1,18,25,13,16,102,68,33,57,49,43,80,93,32,123,9,81,23,44,126,28,42,113,62,127,97,87,2,116,75,12,39,55,34,61,63,85,94,11,112,20,86,119,51,120,65,52,46,17,26,30,78,117,111,21,58,36,41,38,8,24,48,106,88,83,66,114,72,92,98,14,27,53,108,110,47,90,3,35,71,95,122,103,70,40,4,22,56,128,82,60,107,104,54,10,79,118,101,6,125,19,31,5,15,105,69,74,124,59,67,77,91,7,29,37,76,115,45,50,100,84,64,89,99 };
  test.disable_feature = disabled_features;
  test.test_name = "vote_processor::tests::test_voter_base_key_can_authorize_new_voter";
  test.test_nonce  = 13;
  test.test_number = 1676;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "11111113pNDtm61yGF8j2ycAwLEPsuWQXobye5qDR",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1676_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1676_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1676_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1676_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1676_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1676_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1676_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1676_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111114DhpssPJgSi1YU7hCMfYt1BJ334YgsffXm",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1676_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1676_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1676_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1676_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1676_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1676_raw_sz;
  test.expected_result = -8;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1677(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 73,109,121,0,96,1,18,25,13,16,102,68,33,57,49,43,80,93,32,123,9,81,23,44,126,28,42,113,62,127,97,87,2,116,75,12,39,55,34,61,63,85,94,11,112,20,86,119,51,120,65,52,46,17,26,30,78,117,111,21,58,36,41,38,8,24,48,106,88,83,66,114,72,92,98,14,27,53,108,110,47,90,3,35,71,95,122,103,70,40,4,22,56,128,82,60,107,104,54,10,79,118,101,6,125,19,31,5,15,105,69,74,124,59,67,77,91,7,29,37,76,115,45,50,100,84,64,89,99 };
  test.disable_feature = disabled_features;
  test.test_name = "vote_processor::tests::test_voter_base_key_can_authorize_new_voter";
  test.test_nonce  = 48;
  test.test_number = 1677;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "11111113pNDtm61yGF8j2ycAwLEPsuWQXobye5qDR",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1677_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1677_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1677_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1677_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1677_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1677_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1677_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1677_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111114DhpssPJgSi1YU7hCMfYt1BJ334YgsffXm",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1677_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1677_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1677_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1677_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1677_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1677_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1678(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 117,90,83,124,118,126,125,108,2,112,109,75,116,29,15,127,24,80,121,77,56,120,76,110,27,26,79,92,128,103,111,62,61,30,106,105,55,89,114,82,78,123,122,113,33,87,98 };
  test.disable_feature = disabled_features;
  test.test_name = "vote_processor::tests::test_voter_base_key_can_authorize_new_voter";
  test.test_nonce  = 22;
  test.test_number = 1678;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "11111113pNDtm61yGF8j2ycAwLEPsuWQXobye5qDR",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1678_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1678_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1678_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1678_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1678_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1678_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1678_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1678_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111114DhpssPJgSi1YU7hCMfYt1BJ334YgsffXm",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1678_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1678_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1678_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1678_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1678_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1678_raw_sz;
  test.expected_result = -8;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1679(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 117,90,83,124,118,126,125,108,2,112,109,75,116,29,15,127,24,80,121,77,56,120,76,110,27,26,79,92,128,103,111,62,61,30,106,105,55,89,114,82,78,123,122,113,33,87,98 };
  test.disable_feature = disabled_features;
  test.test_name = "vote_processor::tests::test_voter_base_key_can_authorize_new_voter";
  test.test_nonce  = 24;
  test.test_number = 1679;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "11111113pNDtm61yGF8j2ycAwLEPsuWQXobye5qDR",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1679_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1679_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1679_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1679_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1679_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1679_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1679_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1679_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111114DhpssPJgSi1YU7hCMfYt1BJ334YgsffXm",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1679_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1679_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1679_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1679_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1679_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1679_raw_sz;
  test.expected_result = -8;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1680(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 106,98,121,116,62,30,75,82,55,124,83,79,123,110,118,114,78,105,87,26,29,89,109,127,76,24,128,125,117,122,112,77,111,56,61,113,120,108,126,2,27,80,103,92,15,33,90 };
  test.disable_feature = disabled_features;
  test.test_name = "vote_processor::tests::test_voter_base_key_can_authorize_new_voter";
  test.test_nonce  = 35;
  test.test_number = 1680;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "11111113pNDtm61yGF8j2ycAwLEPsuWQXobye5qDR",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1680_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1680_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1680_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1680_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1680_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1680_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1680_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1680_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111114DhpssPJgSi1YU7hCMfYt1BJ334YgsffXm",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1680_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1680_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1680_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1680_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1680_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1680_raw_sz;
  test.expected_result = -8;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1681(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 106,98,121,116,62,30,75,82,55,124,83,79,123,110,118,114,78,105,87,26,29,89,109,127,76,24,128,125,117,122,112,77,111,56,61,113,120,108,126,2,27,80,103,92,15,33,90 };
  test.disable_feature = disabled_features;
  test.test_name = "vote_processor::tests::test_voter_base_key_can_authorize_new_voter";
  test.test_nonce  = 37;
  test.test_number = 1681;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "11111113pNDtm61yGF8j2ycAwLEPsuWQXobye5qDR",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1681_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1681_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1681_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1681_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1681_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1681_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1681_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1681_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111114DhpssPJgSi1YU7hCMfYt1BJ334YgsffXm",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1681_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1681_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1681_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1681_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1681_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1681_raw_sz;
  test.expected_result = -8;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1682(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 128,79,2,29,116,61,90,122,62,123,106,78,118,89,76,24,55,110,108,56,117,103,120,26,82,127,111,92,113,27,33,77,121,83,30,75,112,87,124,105,114,15,109,80,98,125,126 };
  test.disable_feature = disabled_features;
  test.test_name = "vote_processor::tests::test_voter_base_key_can_not_authorize_new_withdrawer_checked";
  test.test_nonce  = 15;
  test.test_number = 1682;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 4;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111111Af7Udc9v3L82dQM5b4zee1Xt77Be4czzbH",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1682_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1682_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1682_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1682_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1682_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1682_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1682_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1682_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111B4T5ciTCkWauSqVAcVKy88ofjcSamrapud",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1682_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1682_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1682_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1682_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111PXvn95h8m6x4oGorNVerA2F4FFRpp7feiK",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1682_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1682_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1682_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1682_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1682_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1682_raw_sz;
  test.expected_result = -8;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1683(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 128,79,2,29,116,61,90,122,62,123,106,78,118,89,76,24,55,110,108,56,117,103,120,26,82,127,111,92,113,27,33,77,121,83,30,75,112,87,124,105,114,15,109,80,98,125,126 };
  test.disable_feature = disabled_features;
  test.test_name = "vote_processor::tests::test_voter_base_key_can_not_authorize_new_withdrawer_checked";
  test.test_nonce  = 11;
  test.test_number = 1683;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 4;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111111B4T5ciTCkWauSqVAcVKy88ofjcSamrapud",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1683_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1683_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1683_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1683_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1683_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1683_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1683_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1683_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111BTngbpkVTh3nGGdFdufHcG5TN7hXV6AfDy",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1683_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1683_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1683_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1683_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111M7uAERuQW2AotfyLDyewFGcLUDtAYiAepF",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1683_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1683_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1683_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1683_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1683_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1683_raw_sz;
  test.expected_result = -8;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1684(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 83,105,109,75,113,126,108,61,128,121,24,92,123,77,124,98,106,103,125,89,56,26,2,112,127,87,29,116,90,82,122,79,114,111,15,27,120,76,78,110,118,80,62,30,33,55,117 };
  test.disable_feature = disabled_features;
  test.test_name = "vote_processor::tests::test_voter_base_key_can_not_authorize_new_withdrawer";
  test.test_nonce  = 11;
  test.test_number = 1684;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "11111117qkFjr4u54stuNNUR8fRF8dNhaP35yvANs",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1684_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1684_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1684_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1684_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1684_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1684_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1684_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1684_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111118F5rixNBnFLmioWZSYzjjFuAL5dyoDVzhD",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1684_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1684_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1684_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1684_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1684_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1684_raw_sz;
  test.expected_result = -8;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1685(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 83,105,109,75,113,126,108,61,128,121,24,92,123,77,124,98,106,103,125,89,56,26,2,112,127,87,29,116,90,82,122,79,114,111,15,27,120,76,78,110,118,80,62,30,33,55,117 };
  test.disable_feature = disabled_features;
  test.test_name = "vote_processor::tests::test_voter_base_key_can_not_authorize_new_withdrawer";
  test.test_nonce  = 8;
  test.test_number = 1685;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "11111118F5rixNBnFLmioWZSYzjjFuAL5dyoDVzhD",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1685_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1685_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1685_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1685_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1685_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1685_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1685_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1685_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111118eRTi4fUVRoeYEeeTyL4DPAwxatvWT5q1Z",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1685_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1685_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1685_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1685_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1685_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1685_raw_sz;
  test.expected_result = -8;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1686(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 83,98,82,111,105,76,15,124,123,2,92,90,33,87,128,126,62,61,120,78,127,117,24,122,103,106,118,80,112,29,116,55,110,75,125,113,77,26,121,79,108,114,27,109,56,89,30 };
  test.disable_feature = disabled_features;
  test.test_name = "vote_processor::tests::test_vote_signature";
  test.test_nonce  = 65;
  test.test_number = 1686;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "RXftGBEVvPWZeE4xGjVH8EXbHcVFQEatPw1euztTjHp",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 26858640UL;
  test_acc->result_lamports = 26858640UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1686_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1686_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1686_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1686_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarS1otHashes111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1686_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1686_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1686_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1686_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1686_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1686_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1686_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1686_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1686_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1686_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1687(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 98,92,83,33,114,108,62,117,55,109,15,112,29,76,111,75,127,56,123,30,122,89,128,82,121,110,90,77,120,124,78,27,87,106,79,105,24,116,118,80,61,125,2,113,26,103,126 };
  test.disable_feature = disabled_features;
  test.test_name = "vote_processor::tests::test_vote_signature";
  test.test_nonce  = 89;
  test.test_number = 1687;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "RXftGBEVvPWZeE4xGjVH8EXbHcVFQEatPw1euztTjHp",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1687_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1687_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1687_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1687_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarS1otHashes111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1687_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1687_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1687_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1687_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1687_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1687_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1687_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1687_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1687_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1687_raw_sz;
  test.expected_result = -10;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1688(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 76,2,77,122,98,80,15,128,114,26,127,87,118,113,30,111,90,79,110,83,56,106,78,89,62,126,92,116,27,125,61,121,55,75,112,29,120,24,82,108,117,109,103,123,105,33,124 };
  test.disable_feature = disabled_features;
  test.test_name = "vote_processor::tests::test_vote_signature";
  test.test_nonce  = 85;
  test.test_number = 1688;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "RXftGBEVvPWZeE4xGjVH8EXbHcVFQEatPw1euztTjHp",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 26858640UL;
  test_acc->result_lamports = 26858640UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1688_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1688_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1688_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1688_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarS1otHashes111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1688_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1688_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1688_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1688_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1688_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1688_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1688_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1688_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1688_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1688_raw_sz;
  test.expected_result = -26;
  test.custom_err = 1;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1689(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 15,24,113,105,116,117,55,87,122,30,120,118,77,112,62,127,56,26,110,126,27,29,98,75,111,121,82,123,76,114,33,128,2,89,79,61,108,80,109,103,125,78,90,92,106,83,124 };
  test.disable_feature = disabled_features;
  test.test_name = "vote_processor::tests::test_vote_signature";
  test.test_nonce  = 13;
  test.test_number = 1689;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "RXftGBEVvPWZeE4xGjVH8EXbHcVFQEatPw1euztTjHp",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 26858640UL;
  test_acc->result_lamports = 26858640UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1689_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1689_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1689_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1689_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarS1otHashes111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1689_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1689_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1689_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1689_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1689_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1689_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1689_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1689_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1689_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1689_raw_sz;
  test.expected_result = -8;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1690(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 30,125,29,112,106,61,108,123,128,76,77,98,78,109,121,83,113,79,111,75,127,124,15,110,55,82,118,56,120,103,105,87,26,89,90,117,122,24,2,62,114,126,92,80,27,116,33 };
  test.disable_feature = disabled_features;
  test.test_name = "vote_processor::tests::test_vote_signature";
  test.test_nonce  = 87;
  test.test_number = 1690;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "RXftGBEVvPWZeE4xGjVH8EXbHcVFQEatPw1euztTjHp",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 26858640UL;
  test_acc->result_lamports = 26858640UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1690_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1690_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1690_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1690_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarS1otHashes111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1690_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1690_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1690_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1690_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1690_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1690_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1690_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1690_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1690_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1690_raw_sz;
  test.expected_result = -26;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1691(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 125,83,112,76,128,61,27,116,78,122,82,79,80,118,127,105,29,90,89,126,33,109,124,24,120,103,92,106,121,62,55,111,15,2,30,113,77,75,87,98,56,123,110,108,26,117,114 };
  test.disable_feature = disabled_features;
  test.test_name = "vote_processor::tests::test_vote_signature";
  test.test_nonce  = 80;
  test.test_number = 1691;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "RXftGBEVvPWZeE4xGjVH8EXbHcVFQEatPw1euztTjHp",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 26858640UL;
  test_acc->result_lamports = 26858640UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1691_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1691_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1691_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1691_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarS1otHashes111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1691_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1691_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1691_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1691_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1691_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1691_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1691_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1691_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1691_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1691_raw_sz;
  test.expected_result = -26;
  test.custom_err = 2;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1692(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 125,83,112,76,128,61,27,116,78,122,82,79,80,118,127,105,29,90,89,126,33,109,124,24,120,103,92,106,121,62,55,111,15,2,30,113,77,75,87,98,56,123,110,108,26,117,114 };
  test.disable_feature = disabled_features;
  test.test_name = "vote_processor::tests::test_vote_signature";
  test.test_nonce  = 58;
  test.test_number = 1692;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "EQ4gajK4bBSJxRpChLvUFg3RxV94yWDwv6vFZmGBVfLk",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 26858640UL;
  test_acc->result_lamports = 26858640UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1692_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1692_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1692_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1692_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarS1otHashes111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1692_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1692_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1692_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1692_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1692_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1692_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1692_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1692_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1692_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1692_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1693(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 125,83,112,76,128,61,27,116,78,122,82,79,80,118,127,105,29,90,89,126,33,109,124,24,120,103,92,106,121,62,55,111,15,2,30,113,77,75,87,98,56,123,110,108,26,117,114 };
  test.disable_feature = disabled_features;
  test.test_name = "vote_processor::tests::test_vote_signature";
  test.test_nonce  = 77;
  test.test_number = 1693;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "EQ4gajK4bBSJxRpChLvUFg3RxV94yWDwv6vFZmGBVfLk",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 26858640UL;
  test_acc->result_lamports = 26858640UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1693_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1693_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1693_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1693_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarS1otHashes111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1693_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1693_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1693_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1693_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1693_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1693_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1693_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1693_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1693_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1693_raw_sz;
  test.expected_result = -26;
  test.custom_err = 2;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1694(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 125,83,112,76,128,61,27,116,78,122,82,79,80,118,127,105,29,90,89,126,33,109,124,24,120,103,92,106,121,62,55,111,15,2,30,113,77,75,87,98,56,123,110,108,26,117,114 };
  test.disable_feature = disabled_features;
  test.test_name = "vote_processor::tests::test_vote_signature";
  test.test_nonce  = 7;
  test.test_number = 1694;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "EQ4gajK4bBSJxRpChLvUFg3RxV94yWDwv6vFZmGBVfLk",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 26858640UL;
  test_acc->result_lamports = 26858640UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1694_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1694_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1694_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1694_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarS1otHashes111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1694_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1694_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1694_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1694_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1694_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1694_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1694_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1694_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1694_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1694_raw_sz;
  test.expected_result = -8;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1695(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 125,83,112,76,128,61,27,116,78,122,82,79,80,118,127,105,29,90,89,126,33,109,124,24,120,103,92,106,121,62,55,111,15,2,30,113,77,75,87,98,56,123,110,108,26,117,114 };
  test.disable_feature = disabled_features;
  test.test_name = "vote_processor::tests::test_vote_signature";
  test.test_nonce  = 82;
  test.test_number = 1695;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "EQ4gajK4bBSJxRpChLvUFg3RxV94yWDwv6vFZmGBVfLk",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 26858640UL;
  test_acc->result_lamports = 26858640UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1695_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1695_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1695_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1695_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarS1otHashes111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1695_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1695_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1695_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1695_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1695_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1695_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1695_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1695_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1695_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1695_raw_sz;
  test.expected_result = -26;
  test.custom_err = 1;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1696(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 125,83,112,76,128,61,27,116,78,122,82,79,80,118,127,105,29,90,89,126,33,109,124,24,120,103,92,106,121,62,55,111,15,2,30,113,77,75,87,98,56,123,110,108,26,117,114 };
  test.disable_feature = disabled_features;
  test.test_name = "vote_processor::tests::test_vote_signature";
  test.test_nonce  = 86;
  test.test_number = 1696;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "EQ4gajK4bBSJxRpChLvUFg3RxV94yWDwv6vFZmGBVfLk",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 26858640UL;
  test_acc->result_lamports = 26858640UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1696_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1696_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1696_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1696_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarS1otHashes111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1696_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1696_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1696_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1696_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1696_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1696_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1696_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1696_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1696_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1696_raw_sz;
  test.expected_result = -26;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1697(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 125,83,112,76,128,61,27,116,78,122,82,79,80,118,127,105,29,90,89,126,33,109,124,24,120,103,92,106,121,62,55,111,15,2,30,113,77,75,87,98,56,123,110,108,26,117,114 };
  test.disable_feature = disabled_features;
  test.test_name = "vote_processor::tests::test_vote_signature";
  test.test_nonce  = 88;
  test.test_number = 1697;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "EQ4gajK4bBSJxRpChLvUFg3RxV94yWDwv6vFZmGBVfLk",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1697_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1697_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1697_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1697_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarS1otHashes111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1697_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1697_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1697_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1697_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1697_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1697_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1697_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1697_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1697_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1697_raw_sz;
  test.expected_result = -10;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1698(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 108,124,113,103,82,123,62,117,109,126,98,78,29,33,112,118,116,55,105,106,15,24,121,89,128,76,75,120,87,27,61,30,111,80,2,114,122,79,92,56,90,127,83,77,125,110,26 };
  test.disable_feature = disabled_features;
  test.test_name = "vote_processor::tests::test_vote_state_withdraw";
  test.test_nonce  = 19;
  test.test_number = 1698;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 5;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "AZkz3vMWd2oMPk28CP4Qayn3YF4ZEhzC5NfudkSqAB6T",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 26858640UL;
  test_acc->result_lamports = 26858640UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1698_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1698_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1698_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1698_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "2Qg6QRRu5EMDgKt7RRET8queCB4qhHYjvtKDF793KDNe",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 26858640UL;
  test_acc->result_lamports = 26858640UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1698_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1698_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1698_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1698_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1698_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1698_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1698_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1698_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1698_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1698_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1698_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1698_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "J3hougktvitrEuMdn8gQkotvaqt8NGJSfr1MSbNUfz46",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1698_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1698_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1698_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1698_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1698_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1698_raw_sz;
  test.expected_result = -6;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1699(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 125,90,30,33,89,117,98,121,116,80,27,109,124,26,92,62,24,55,75,123,128,56,122,76,113,29,111,112,83,15,61,106,105,114,103,87,82,118,108,2,127,77,120,79,78,126,110 };
  test.disable_feature = disabled_features;
  test.test_name = "vote_processor::tests::test_vote_state_withdraw";
  test.test_nonce  = 32;
  test.test_number = 1699;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 5;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "AZkz3vMWd2oMPk28CP4Qayn3YF4ZEhzC5NfudkSqAB6T",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 26858640UL;
  test_acc->result_lamports = 26858640UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1699_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1699_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1699_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1699_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "2Qg6QRRu5EMDgKt7RRET8queCB4qhHYjvtKDF793KDNe",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 26858640UL;
  test_acc->result_lamports = 26858640UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1699_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1699_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1699_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1699_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1699_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1699_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1699_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1699_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1699_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1699_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1699_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1699_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "J3hougktvitrEuMdn8gQkotvaqt8NGJSfr1MSbNUfz46",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1699_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1699_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1699_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1699_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1699_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1699_raw_sz;
  test.expected_result = -6;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
