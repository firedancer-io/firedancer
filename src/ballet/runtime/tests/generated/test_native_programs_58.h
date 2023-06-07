#include "../fd_tests.h"
int test_1450(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 92,61,33,30,2,114,118,29,122,127,79,24,103,87,125,111,27,112,90,77,56,126,117,55,75,120,113,62,110,83,121,109,15,98,78,76,26,105,128,80,124,108,116,82,106,89,123 };
  test.disable_feature = disabled_features;
  test.test_name = "system_instruction_processor::tests::test_request_more_than_allowed_data_length";
  test.test_nonce  = 54;
  test.test_number = 1450;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 2;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111113VcBykePzEPKjsbbAh9ok6gURFwbJyiZtskb",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 50UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1450_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1450_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1450_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1450_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111113VcbKMdWHX6WCkR2JnBE5RAbh3a6ZvRoUi4w",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 50UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1450_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1450_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1450_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1450_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1450_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1450_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1451(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 92,61,33,30,2,114,118,29,122,127,79,24,103,87,125,111,27,112,90,77,56,126,117,55,75,120,113,62,110,83,121,109,15,98,78,76,26,105,128,80,124,108,116,82,106,89,123 };
  test.disable_feature = disabled_features;
  test.test_name = "system_instruction_processor::tests::test_request_more_than_allowed_data_length";
  test.test_nonce  = 54;
  test.test_number = 1451;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 2;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111113Xhi3v1C1EoogUaVGrYWLM8Lcr1w7rRJ4TGj",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 50UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1451_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1451_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1451_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1451_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111113Xi7PWzJJXWz9MPvQwZvffcTtdeSNo8XeHb5",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 50UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1451_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1451_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1451_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1451_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1451_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1451_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1452(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 128,33,117,92,62,90,24,77,103,30,98,122,120,125,26,89,55,108,80,118,78,29,83,106,126,110,109,124,87,123,112,105,61,56,27,116,82,111,121,114,15,127,75,76,79,2,113 };
  test.disable_feature = disabled_features;
  test.test_name = "system_instruction_processor::tests::test_request_more_than_allowed_data_length";
  test.test_nonce  = 43;
  test.test_number = 1452;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 2;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111113VcBykePzEPKjsbbAh9ok6gURFwbJyiZtskb",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1452_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1452_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1452_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1452_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111113VcbKMdWHX6WCkR2JnBE5RAbh3a6ZvRoUi4w",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1452_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1452_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1452_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1452_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1452_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1452_raw_sz;
  test.expected_result = -26;
  test.custom_err = 3;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1453(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 128,33,117,92,62,90,24,77,103,30,98,122,120,125,26,89,55,108,80,118,78,29,83,106,126,110,109,124,87,123,112,105,61,56,27,116,82,111,121,114,15,127,75,76,79,2,113 };
  test.disable_feature = disabled_features;
  test.test_name = "system_instruction_processor::tests::test_request_more_than_allowed_data_length";
  test.test_nonce  = 45;
  test.test_number = 1453;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 2;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111113Xhi3v1C1EoogUaVGrYWLM8Lcr1w7rRJ4TGj",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1453_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1453_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1453_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1453_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111113Xi7PWzJJXWz9MPvQwZvffcTtdeSNo8XeHb5",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1453_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1453_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1453_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1453_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1453_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1453_raw_sz;
  test.expected_result = -26;
  test.custom_err = 3;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1454(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 112,118,80,61,92,33,78,82,90,55,122,87,27,126,62,2,83,98,124,89,24,76,111,75,113,128,120,108,30,56,121,109,105,110,116,127,15,79,106,117,114,103,29,26,125,77,123 };
  test.disable_feature = disabled_features;
  test.test_name = "system_instruction_processor::tests::test_transfer_lamports_from_nonce_account_fail";
  test.test_nonce  = 45;
  test.test_number = 1454;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 2;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111113VeCfmZwUfwE4Fgks8GuQh76nC67bhGjp3LK",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1454_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1454_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1454_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1454_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "CktRuQ2mttgRGkXJtyksdKHjUdc2C4TgDzyB98oEzy8",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "CktRuQ2mttgRGkXJtyksdKHjUdc2C4TgDzyB98oEzy8",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1454_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1454_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1454_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1454_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1454_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1454_raw_sz;
  test.expected_result = -2;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1455(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 112,118,80,61,92,33,78,82,90,55,122,87,27,126,62,2,83,98,124,89,24,76,111,75,113,128,120,108,30,56,121,109,105,110,116,127,15,79,106,117,114,103,29,26,125,77,123 };
  test.disable_feature = disabled_features;
  test.test_name = "system_instruction_processor::tests::test_transfer_lamports_from_nonce_account_fail";
  test.test_nonce  = 46;
  test.test_number = 1455;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 2;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111113Xiv4ixWu6wM572nh7cmLJaiSCuStgYzoxDm",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1455_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1455_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1455_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1455_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "CktRuQ2mttgRGkXJtyksdKHjUdc2C4TgDzyB98oEzy8",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "CktRuQ2mttgRGkXJtyksdKHjUdc2C4TgDzyB98oEzy8",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1455_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1455_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1455_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1455_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1455_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1455_raw_sz;
  test.expected_result = -2;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1456(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 121,92,127,77,79,108,56,103,83,124,87,26,106,61,110,76,122,89,62,120,105,128,114,126,75,82,27,33,118,117,24,78,109,80,29,30,112,55,90,2,125,123,113,111,98,116,15 };
  test.disable_feature = disabled_features;
  test.test_name = "system_instruction_processor::tests::test_transfer_lamports";
  test.test_nonce  = 50;
  test.test_number = 1456;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 2;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111113VdoLAaqBPE3bNsKj3FV5NcyWQTcLkZWED1y",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1456_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1456_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1456_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1456_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "CktRuQ2mttgRGkXJtyksdKHjUdc2C4TgDzyB98oEzy8",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "CktRuQ2mttgRGkXJtyksdKHjUdc2C4TgDzyB98oEzy8",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1456_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1456_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1456_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1456_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1456_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1456_raw_sz;
  test.expected_result = -8;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1457(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 76,103,117,121,92,105,83,118,78,55,89,126,24,80,128,79,27,127,123,110,2,108,111,77,113,26,122,33,116,120,56,112,75,87,30,82,62,125,29,90,114,15,106,124,109,98,61 };
  test.disable_feature = disabled_features;
  test.test_name = "system_instruction_processor::tests::test_transfer_lamports";
  test.test_nonce  = 49;
  test.test_number = 1457;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 2;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111113VdoLAaqBPE3bNsKj3FV5NcyWQTcLkZWED1y",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1457_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1457_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1457_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1457_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "CktRuQ2mttgRGkXJtyksdKHjUdc2C4TgDzyB98oEzy8",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "CktRuQ2mttgRGkXJtyksdKHjUdc2C4TgDzyB98oEzy8",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1457_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1457_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1457_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1457_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1457_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1457_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1458(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 76,103,117,121,92,105,83,118,78,55,89,126,24,80,128,79,27,127,123,110,2,108,111,77,113,26,122,33,116,120,56,112,75,87,30,82,62,125,29,90,114,15,106,124,109,98,61 };
  test.disable_feature = disabled_features;
  test.test_name = "system_instruction_processor::tests::test_transfer_lamports";
  test.test_nonce  = 49;
  test.test_number = 1458;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 2;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111113XiWj7yQbpEAcEDMZ2bLzz6bARGwdjqmE7uR",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1458_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1458_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1458_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1458_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "CktRuQ2mttgRGkXJtyksdKHjUdc2C4TgDzyB98oEzy8",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "CktRuQ2mttgRGkXJtyksdKHjUdc2C4TgDzyB98oEzy8",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1458_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1458_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1458_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1458_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1458_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1458_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1459(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 76,103,117,121,92,105,83,118,78,55,89,126,24,80,128,79,27,127,123,110,2,108,111,77,113,26,122,33,116,120,56,112,75,87,30,82,62,125,29,90,114,15,106,124,109,98,61 };
  test.disable_feature = disabled_features;
  test.test_name = "system_instruction_processor::tests::test_transfer_lamports";
  test.test_nonce  = 50;
  test.test_number = 1459;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 2;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111113XiWj7yQbpEAcEDMZ2bLzz6bARGwdjqmE7uR",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1459_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1459_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1459_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1459_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "CktRuQ2mttgRGkXJtyksdKHjUdc2C4TgDzyB98oEzy8",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "CktRuQ2mttgRGkXJtyksdKHjUdc2C4TgDzyB98oEzy8",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1459_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1459_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1459_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1459_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1459_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1459_raw_sz;
  test.expected_result = -8;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1460(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 27,56,112,30,76,98,90,113,128,114,127,24,33,121,82,105,79,61,118,120,26,126,80,106,78,29,87,62,103,110,15,2,92,83,108,116,124,109,122,89,123,125,111,77,55,75,117 };
  test.disable_feature = disabled_features;
  test.test_name = "system_instruction_processor::tests::test_transfer_lamports";
  test.test_nonce  = 47;
  test.test_number = 1460;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 2;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111113VdoLAaqBPE3bNsKj3FV5NcyWQTcLkZWED1y",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 50UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1460_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1460_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1460_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1460_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "CktRuQ2mttgRGkXJtyksdKHjUdc2C4TgDzyB98oEzy8",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "CktRuQ2mttgRGkXJtyksdKHjUdc2C4TgDzyB98oEzy8",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 51UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1460_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1460_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1460_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1460_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1460_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1460_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1461(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 27,56,112,30,76,98,90,113,128,114,127,24,33,121,82,105,79,61,118,120,26,126,80,106,78,29,87,62,103,110,15,2,92,83,108,116,124,109,122,89,123,125,111,77,55,75,117 };
  test.disable_feature = disabled_features;
  test.test_name = "system_instruction_processor::tests::test_transfer_lamports";
  test.test_nonce  = 47;
  test.test_number = 1461;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 2;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111113XiWj7yQbpEAcEDMZ2bLzz6bARGwdjqmE7uR",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 50UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1461_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1461_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1461_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1461_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "CktRuQ2mttgRGkXJtyksdKHjUdc2C4TgDzyB98oEzy8",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "CktRuQ2mttgRGkXJtyksdKHjUdc2C4TgDzyB98oEzy8",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 51UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1461_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1461_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1461_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1461_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1461_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1461_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1462(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 61,92,29,127,120,103,83,78,2,124,125,116,118,15,114,75,62,112,113,87,26,33,79,123,109,30,106,110,77,105,126,82,98,122,24,56,90,117,128,27,89,121,80,108,111,76,55 };
  test.disable_feature = disabled_features;
  test.test_name = "system_instruction_processor::tests::test_transfer_lamports";
  test.test_nonce  = 48;
  test.test_number = 1462;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 2;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111113VdoLAaqBPE3bNsKj3FV5NcyWQTcLkZWED1y",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1462_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1462_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1462_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1462_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "CktRuQ2mttgRGkXJtyksdKHjUdc2C4TgDzyB98oEzy8",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "CktRuQ2mttgRGkXJtyksdKHjUdc2C4TgDzyB98oEzy8",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1462_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1462_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1462_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1462_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1462_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1462_raw_sz;
  test.expected_result = -26;
  test.custom_err = 1;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1463(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 61,92,29,127,120,103,83,78,2,124,125,116,118,15,114,75,62,112,113,87,26,33,79,123,109,30,106,110,77,105,126,82,98,122,24,56,90,117,128,27,89,121,80,108,111,76,55 };
  test.disable_feature = disabled_features;
  test.test_name = "system_instruction_processor::tests::test_transfer_lamports";
  test.test_nonce  = 48;
  test.test_number = 1463;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 2;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111113XiWj7yQbpEAcEDMZ2bLzz6bARGwdjqmE7uR",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1463_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1463_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1463_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1463_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "CktRuQ2mttgRGkXJtyksdKHjUdc2C4TgDzyB98oEzy8",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "CktRuQ2mttgRGkXJtyksdKHjUdc2C4TgDzyB98oEzy8",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1463_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1463_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1463_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1463_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1463_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1463_raw_sz;
  test.expected_result = -26;
  test.custom_err = 1;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1464(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 106,98,90,33,61,92,89,121,114,125,105,110,116,123,117,82,128,2,75,15,55,127,77,103,87,24,83,113,108,79,124,30,26,126,80,62,111,29,112,76,78,118,120,27,109,122,56 };
  test.disable_feature = disabled_features;
  test.test_name = "system_instruction_processor::tests::test_transfer_with_seed";
  test.test_nonce  = 53;
  test.test_number = 1464;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "tX5NNjnz1q8HGfU8Br4gPMVkzjxRZn2E7zrvMbTaXbA",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1464_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1464_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1464_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1464_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111113Vec1NZ3mxeQX8WC1DJKk1bE3yicrdyyPsef",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "8qbHbw2BbbTHBW1sbeqakYXVKRQM8Ne7pLK7m6CVfeR",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1464_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1464_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1464_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1464_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "CktRuQ2mttgRGkXJtyksdKHjUdc2C4TgDzyB98oEzy8",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "CktRuQ2mttgRGkXJtyksdKHjUdc2C4TgDzyB98oEzy8",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1464_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1464_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1464_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1464_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1464_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1464_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1465(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 106,98,90,33,61,92,89,121,114,125,105,110,116,123,117,82,128,2,75,15,55,127,77,103,87,24,83,113,108,79,124,30,26,126,80,62,111,29,112,76,78,118,120,27,109,122,56 };
  test.disable_feature = disabled_features;
  test.test_name = "system_instruction_processor::tests::test_transfer_with_seed";
  test.test_nonce  = 53;
  test.test_number = 1465;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "F9PhVKztY35ExWb8rnSi2CsUfrpAyiiL73DFVGVSEHQj",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1465_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1465_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1465_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1465_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111113XjKQKwdCPeXXyrDqCeBfd4qhzXx9dGEPnY7",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "8qbHbw2BbbTHBW1sbeqakYXVKRQM8Ne7pLK7m6CVfeR",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1465_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1465_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1465_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1465_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "CktRuQ2mttgRGkXJtyksdKHjUdc2C4TgDzyB98oEzy8",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "CktRuQ2mttgRGkXJtyksdKHjUdc2C4TgDzyB98oEzy8",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1465_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1465_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1465_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1465_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1465_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1465_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1466(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 127,24,114,2,116,112,98,110,109,77,120,92,87,30,27,90,89,83,108,33,103,111,126,106,117,121,128,125,61,79,62,118,82,55,78,56,15,123,75,26,80,29,105,124,122,113,76 };
  test.disable_feature = disabled_features;
  test.test_name = "system_instruction_processor::tests::test_transfer_with_seed";
  test.test_nonce  = 51;
  test.test_number = 1466;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "tX5NNjnz1q8HGfU8Br4gPMVkzjxRZn2E7zrvMbTaXbA",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 50UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1466_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1466_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1466_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1466_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111113Vec1NZ3mxeQX8WC1DJKk1bE3yicrdyyPsef",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "8qbHbw2BbbTHBW1sbeqakYXVKRQM8Ne7pLK7m6CVfeR",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1466_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1466_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1466_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1466_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "CktRuQ2mttgRGkXJtyksdKHjUdc2C4TgDzyB98oEzy8",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "CktRuQ2mttgRGkXJtyksdKHjUdc2C4TgDzyB98oEzy8",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 51UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1466_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1466_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1466_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1466_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1466_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1466_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1467(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 127,24,114,2,116,112,98,110,109,77,120,92,87,30,27,90,89,83,108,33,103,111,126,106,117,121,128,125,61,79,62,118,82,55,78,56,15,123,75,26,80,29,105,124,122,113,76 };
  test.disable_feature = disabled_features;
  test.test_name = "system_instruction_processor::tests::test_transfer_with_seed";
  test.test_nonce  = 51;
  test.test_number = 1467;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "F9PhVKztY35ExWb8rnSi2CsUfrpAyiiL73DFVGVSEHQj",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 50UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1467_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1467_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1467_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1467_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111113XjKQKwdCPeXXyrDqCeBfd4qhzXx9dGEPnY7",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "8qbHbw2BbbTHBW1sbeqakYXVKRQM8Ne7pLK7m6CVfeR",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1467_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1467_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1467_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1467_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "CktRuQ2mttgRGkXJtyksdKHjUdc2C4TgDzyB98oEzy8",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "CktRuQ2mttgRGkXJtyksdKHjUdc2C4TgDzyB98oEzy8",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 51UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1467_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1467_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1467_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1467_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1467_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1467_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1468(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 87,15,26,80,105,75,108,111,110,112,114,103,127,61,83,117,125,55,30,76,128,118,122,82,77,113,56,78,2,124,62,116,24,29,126,79,121,92,106,98,27,89,33,90,109,120,123 };
  test.disable_feature = disabled_features;
  test.test_name = "system_instruction_processor::tests::test_transfer_with_seed";
  test.test_nonce  = 52;
  test.test_number = 1468;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "tX5NNjnz1q8HGfU8Br4gPMVkzjxRZn2E7zrvMbTaXbA",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1468_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1468_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1468_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1468_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111113Vec1NZ3mxeQX8WC1DJKk1bE3yicrdyyPsef",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "8qbHbw2BbbTHBW1sbeqakYXVKRQM8Ne7pLK7m6CVfeR",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1468_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1468_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1468_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1468_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "CktRuQ2mttgRGkXJtyksdKHjUdc2C4TgDzyB98oEzy8",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "CktRuQ2mttgRGkXJtyksdKHjUdc2C4TgDzyB98oEzy8",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1468_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1468_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1468_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1468_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1468_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1468_raw_sz;
  test.expected_result = -26;
  test.custom_err = 1;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1469(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 87,15,26,80,105,75,108,111,110,112,114,103,127,61,83,117,125,55,30,76,128,118,122,82,77,113,56,78,2,124,62,116,24,29,126,79,121,92,106,98,27,89,33,90,109,120,123 };
  test.disable_feature = disabled_features;
  test.test_name = "system_instruction_processor::tests::test_transfer_with_seed";
  test.test_nonce  = 52;
  test.test_number = 1469;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "F9PhVKztY35ExWb8rnSi2CsUfrpAyiiL73DFVGVSEHQj",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1469_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1469_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1469_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1469_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111113XjKQKwdCPeXXyrDqCeBfd4qhzXx9dGEPnY7",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "8qbHbw2BbbTHBW1sbeqakYXVKRQM8Ne7pLK7m6CVfeR",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1469_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1469_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1469_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1469_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "CktRuQ2mttgRGkXJtyksdKHjUdc2C4TgDzyB98oEzy8",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "CktRuQ2mttgRGkXJtyksdKHjUdc2C4TgDzyB98oEzy8",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1469_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1469_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1469_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1469_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1469_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1469_raw_sz;
  test.expected_result = -26;
  test.custom_err = 1;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1470(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 123,98,118,106,126,113,79,24,26,121,76,120,128,75,92,87,112,122,127,33,116,114,117,82,124,77,2,108,110,55,83,80,15,105,56,111,27,78,89,90,62,29,103,109,30,125,61 };
  test.disable_feature = disabled_features;
  test.test_name = "tests::test_bpf_loader_finalize";
  test.test_nonce  = 19;
  test.test_number = 1470;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 1;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111112uFcGnkfwYRy55mCjhxGKsMaZTDbToAqFfV",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "BPFLoader2111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 16871040UL;
  test_acc->result_lamports = 16871040UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1470_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1470_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1470_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1470_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "BPFLoader2111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1470_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1470_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1471(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 121,125,105,15,116,78,114,127,55,90,27,98,79,24,62,77,76,80,89,103,112,30,111,61,82,118,2,124,120,87,83,117,122,56,29,128,126,113,92,108,33,106,109,123,26,75,110 };
  test.disable_feature = disabled_features;
  test.test_name = "tests::test_bpf_loader_finalize";
  test.test_nonce  = 28;
  test.test_number = 1471;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 1;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111112uFcGnkfwYRy55mCjhxGKsMaZTDbToAqFfV",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "BPFLoader2111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 16871040UL;
  test_acc->result_lamports = 16871040UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1471_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1471_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1471_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1471_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "BPFLoader2111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1471_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1471_raw_sz;
  test.expected_result = -4;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1472(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 62,30,78,110,76,108,55,128,123,92,112,121,75,15,122,29,98,103,87,120,80,111,117,125,27,116,124,24,82,106,79,127,89,2,33,105,118,90,114,56,83,113,109,77,126,26,61 };
  test.disable_feature = disabled_features;
  test.test_name = "tests::test_bpf_loader_finalize";
  test.test_nonce  = 1;
  test.test_number = 1472;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 0;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_base58_decode_32( "BPFLoader2111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1472_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1472_raw_sz;
  test.expected_result = -20;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1473(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 80,29,123,2,76,114,122,127,33,89,61,124,111,77,120,87,62,116,118,113,26,112,110,78,83,30,117,55,109,126,92,56,103,121,125,108,15,24,75,90,105,98,128,27,106,79,82 };
  test.disable_feature = disabled_features;
  test.test_name = "tests::test_bpf_loader_finalize";
  test.test_nonce  = 9;
  test.test_number = 1473;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 1;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111112uFcGnkfwYRy55mCjhxGKsMaZTDbToAqFfV",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "BPFLoader2111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 16871040UL;
  test_acc->result_lamports = 16871040UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1473_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1473_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1473_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1473_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "BPFLoader2111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1473_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1473_raw_sz;
  test.expected_result = -8;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1474(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 80,29,123,2,76,114,122,127,33,89,61,124,111,77,120,87,62,116,118,113,26,112,110,78,83,30,117,55,109,126,92,56,103,121,125,108,15,24,75,90,105,98,128,27,106,79,82 };
  test.disable_feature = disabled_features;
  test.test_name = "tests::test_bpf_loader_finalize";
  test.test_nonce  = 1;
  test.test_number = 1474;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 0;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_base58_decode_32( "BPFLoader2111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1474_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1474_raw_sz;
  test.expected_result = -20;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
