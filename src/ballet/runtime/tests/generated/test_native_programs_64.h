#include "../fd_tests.h"
int test_1600(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 80,125,76,110,123,33,98,127,26,62,108,82,83,109,105,87,122,77,113,117,121,116,61,90,114,24,118,15,55,112,79,30,92,106,126,78,111,89,2,75,124,56,128,120,103,29,27 };
  test.disable_feature = disabled_features;
  test.test_name = "vote_processor::tests::test_authorize_voter";
  test.test_nonce  = 47;
  test.test_number = 1600;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "EhRLca7sXhU8VrWuz2Vp7kzKkAavmLEB9gp6mKcwLdrK",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 26858640UL;
  test_acc->result_lamports = 26858640UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1600_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1600_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1600_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1600_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1600_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1600_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1600_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1600_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "AcAbcZeZpoTb7fBes9rjgoBnvpFT8ZNkJvKfq9catgA5",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1600_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1600_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1600_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1600_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1600_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1600_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1601(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 126,27,78,112,98,109,75,80,125,120,24,61,87,127,77,2,108,15,118,89,117,62,106,29,111,55,103,90,113,114,122,83,26,79,82,116,123,124,121,76,30,128,110,56,92,33,105 };
  test.disable_feature = disabled_features;
  test.test_name = "vote_processor::tests::test_authorize_voter";
  test.test_nonce  = 33;
  test.test_number = 1601;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "EhRLca7sXhU8VrWuz2Vp7kzKkAavmLEB9gp6mKcwLdrK",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 26858640UL;
  test_acc->result_lamports = 26858640UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1601_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1601_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1601_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1601_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1601_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1601_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1601_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1601_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "AcAbcZeZpoTb7fBes9rjgoBnvpFT8ZNkJvKfq9catgA5",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1601_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1601_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1601_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1601_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1601_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1601_raw_sz;
  test.expected_result = -26;
  test.custom_err = 5;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1602(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 111,30,76,103,123,118,29,83,78,89,128,98,122,56,79,114,92,109,125,126,105,2,90,75,26,62,117,80,124,106,61,110,112,108,55,24,27,82,127,77,87,33,120,113,116,121,15 };
  test.disable_feature = disabled_features;
  test.test_name = "vote_processor::tests::test_authorize_voter";
  test.test_nonce  = 77;
  test.test_number = 1602;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 4;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "EhRLca7sXhU8VrWuz2Vp7kzKkAavmLEB9gp6mKcwLdrK",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 26858640UL;
  test_acc->result_lamports = 26858640UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1602_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1602_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1602_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1602_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1602_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1602_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1602_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1602_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "AcAbcZeZpoTb7fBes9rjgoBnvpFT8ZNkJvKfq9catgA5",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1602_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1602_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1602_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1602_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarS1otHashes111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1602_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1602_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1602_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1602_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1602_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1602_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1603(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 105,89,33,56,77,78,126,118,27,87,61,80,83,123,117,127,98,76,108,121,113,55,111,125,75,128,122,124,110,29,112,116,109,103,92,114,120,106,26,30,15,79,24,2,90,62,82 };
  test.disable_feature = disabled_features;
  test.test_name = "vote_processor::tests::test_authorize_voter";
  test.test_nonce  = 58;
  test.test_number = 1603;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 4;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "EhRLca7sXhU8VrWuz2Vp7kzKkAavmLEB9gp6mKcwLdrK",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 26858640UL;
  test_acc->result_lamports = 26858640UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1603_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1603_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1603_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1603_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1603_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1603_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1603_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1603_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "AcAbcZeZpoTb7fBes9rjgoBnvpFT8ZNkJvKfq9catgA5",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1603_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1603_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1603_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1603_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarS1otHashes111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1603_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1603_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1603_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1603_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1603_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1603_raw_sz;
  test.expected_result = -8;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1604(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 105,89,33,56,77,78,126,118,27,87,61,80,83,123,117,127,98,76,108,121,113,55,111,125,75,128,122,124,110,29,112,116,109,103,92,114,120,106,26,30,15,79,24,2,90,62,82 };
  test.disable_feature = disabled_features;
  test.test_name = "vote_processor::tests::test_authorize_voter";
  test.test_nonce  = 57;
  test.test_number = 1604;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 4;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "3nhrMssWFm5wkVJRtimUX5fa3aZutgnWozUoZ2VzwJuZ",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 26858640UL;
  test_acc->result_lamports = 26858640UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1604_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1604_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1604_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1604_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1604_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1604_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1604_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1604_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "5wvxFgkBgkW9Bkx2csoLK5vPG8QFcubJ8aqYev7MiCoa",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1604_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1604_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1604_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1604_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarS1otHashes111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1604_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1604_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1604_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1604_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1604_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1604_raw_sz;
  test.expected_result = -8;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1605(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 105,89,33,56,77,78,126,118,27,87,61,80,83,123,117,127,98,76,108,121,113,55,111,125,75,128,122,124,110,29,112,116,109,103,92,114,120,106,26,30,15,79,24,2,90,62,82 };
  test.disable_feature = disabled_features;
  test.test_name = "vote_processor::tests::test_authorize_voter";
  test.test_nonce  = 75;
  test.test_number = 1605;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 4;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "3nhrMssWFm5wkVJRtimUX5fa3aZutgnWozUoZ2VzwJuZ",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 26858640UL;
  test_acc->result_lamports = 26858640UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1605_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1605_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1605_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1605_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1605_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1605_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1605_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1605_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "5wvxFgkBgkW9Bkx2csoLK5vPG8QFcubJ8aqYev7MiCoa",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1605_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1605_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1605_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1605_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarS1otHashes111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1605_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1605_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1605_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1605_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1605_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1605_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1606(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 29,125,114,80,87,24,122,123,56,109,118,2,76,106,127,110,30,105,113,55,15,92,116,89,83,62,27,82,111,112,61,128,98,121,79,75,77,103,108,124,78,120,117,26,33,126,90 };
  test.disable_feature = disabled_features;
  test.test_name = "vote_processor::tests::test_authorize_withdrawer";
  test.test_nonce  = 27;
  test.test_number = 1606;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "4BZ1fDB3QHfqJ2j7AcuaK6NjMvBbxhVGnGJKKDimoutw",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 26858640UL;
  test_acc->result_lamports = 26858640UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1606_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1606_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1606_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1606_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1606_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1606_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1606_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1606_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "2wPyGEdArPCU8cDrxKCNtt736Q7f5CKPQerUmLBXXqo9",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1606_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1606_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1606_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1606_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1606_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1606_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1607(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 61,117,27,120,103,77,124,75,126,33,109,106,90,15,125,114,111,29,56,87,110,78,98,79,55,122,2,112,128,30,127,80,123,118,82,89,76,24,92,26,62,105,108,121,113,83,116 };
  test.disable_feature = disabled_features;
  test.test_name = "vote_processor::tests::test_authorize_withdrawer";
  test.test_nonce  = 41;
  test.test_number = 1607;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "4BZ1fDB3QHfqJ2j7AcuaK6NjMvBbxhVGnGJKKDimoutw",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 26858640UL;
  test_acc->result_lamports = 26858640UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1607_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1607_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1607_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1607_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1607_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1607_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1607_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1607_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "2wPyGEdArPCU8cDrxKCNtt736Q7f5CKPQerUmLBXXqo9",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1607_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1607_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1607_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1607_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1607_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1607_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1608(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 77,56,26,87,111,121,24,82,116,127,128,89,112,118,103,106,80,122,2,113,83,78,123,125,29,90,61,27,92,76,30,79,108,110,114,15,98,109,62,117,75,55,126,124,105,33,120 };
  test.disable_feature = disabled_features;
  test.test_name = "vote_processor::tests::test_authorize_withdrawer";
  test.test_nonce  = 5;
  test.test_number = 1608;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "4BZ1fDB3QHfqJ2j7AcuaK6NjMvBbxhVGnGJKKDimoutw",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 26858640UL;
  test_acc->result_lamports = 26858640UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1608_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1608_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1608_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1608_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1608_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1608_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1608_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1608_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "2wPyGEdArPCU8cDrxKCNtt736Q7f5CKPQerUmLBXXqo9",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1608_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1608_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1608_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1608_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1608_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1608_raw_sz;
  test.expected_result = -8;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1609(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 113,121,92,114,29,105,103,126,61,30,79,76,27,80,120,127,62,109,77,87,75,24,112,108,122,55,2,83,56,82,125,118,123,78,117,90,33,116,106,15,124,26,128,111,110,98,89 };
  test.disable_feature = disabled_features;
  test.test_name = "vote_processor::tests::test_authorize_withdrawer";
  test.test_nonce  = 54;
  test.test_number = 1609;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 4;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "4BZ1fDB3QHfqJ2j7AcuaK6NjMvBbxhVGnGJKKDimoutw",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 26858640UL;
  test_acc->result_lamports = 26858640UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1609_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1609_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1609_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1609_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1609_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1609_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1609_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1609_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "2wPyGEdArPCU8cDrxKCNtt736Q7f5CKPQerUmLBXXqo9",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1609_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1609_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1609_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1609_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "6xjdhqaLLaFnjaPVpwgDVriz2kwQFjPW7f8WRQF1ox2q",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1609_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1609_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1609_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1609_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1609_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1609_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1610(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 129;
  uchar disabled_features[] = { 64,44,46,103,86,19,20,126,72,85,109,40,56,75,93,50,98,90,11,28,97,2,63,54,121,124,96,24,71,92,91,69,48,8,128,42,88,14,13,118,102,7,45,106,27,15,34,127,6,61,32,83,78,59,12,89,38,67,47,112,99,84,87,36,39,26,101,16,100,111,123,81,113,110,5,0,41,114,43,1,117,53,116,37,115,119,120,60,35,55,18,30,4,57,68,21,51,70,125,76,79,104,22,9,107,108,122,17,33,62,66,10,94,73,80,29,58,95,77,25,3,82,52,49,74,23,65,31,105 };
  test.disable_feature = disabled_features;
  test.test_name = "vote_processor::tests::test_authorize_withdrawer";
  test.test_nonce  = 69;
  test.test_number = 1610;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 4;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "4BZ1fDB3QHfqJ2j7AcuaK6NjMvBbxhVGnGJKKDimoutw",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 26858640UL;
  test_acc->result_lamports = 26858640UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1610_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1610_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1610_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1610_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1610_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1610_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1610_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1610_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "2wPyGEdArPCU8cDrxKCNtt736Q7f5CKPQerUmLBXXqo9",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1610_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1610_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1610_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1610_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "6xjdhqaLLaFnjaPVpwgDVriz2kwQFjPW7f8WRQF1ox2q",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1610_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1610_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1610_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1610_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1610_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1610_raw_sz;
  test.expected_result = -8;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1611(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 129;
  uchar disabled_features[] = { 53,23,25,56,44,91,113,46,68,121,40,96,30,87,99,71,20,32,5,128,2,37,126,104,43,73,80,55,63,119,8,122,39,109,118,77,9,105,79,14,67,13,6,86,52,112,27,108,22,95,7,36,107,15,100,125,1,24,76,34,101,49,33,0,115,18,74,102,16,120,97,62,3,10,92,45,93,85,59,58,82,90,54,57,75,29,12,11,19,66,60,89,117,31,81,98,123,114,110,69,88,116,106,41,70,4,64,84,48,42,78,65,26,38,28,51,50,47,103,127,35,17,61,94,72,111,21,83,124 };
  test.disable_feature = disabled_features;
  test.test_name = "vote_processor::tests::test_authorize_withdrawer";
  test.test_nonce  = 60;
  test.test_number = 1611;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 4;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "2KjtgnBp9GdhPQuZ2NtoSAhSHzXts4tzhxWDLq5frskD",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 26858640UL;
  test_acc->result_lamports = 26858640UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1611_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1611_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1611_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1611_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1611_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1611_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1611_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1611_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "9G5TLqZP8xHw89ocrAabn3ftsCjgm1rBEM1j8rXGaoX7",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1611_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1611_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1611_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1611_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "7ZVVhhz5Tb6gvzcCgRXpDwMFB3obECVotDHfbV4TUCYo",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1611_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1611_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1611_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1611_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1611_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1611_raw_sz;
  test.expected_result = -8;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1612(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 53,23,25,56,44,91,113,46,68,121,40,96,30,87,99,71,20,32,5,128,2,37,126,104,43,73,80,55,63,119,8,122,39,109,118,77,9,105,79,14,67,13,6,86,52,112,27,108,22,95,7,36,107,15,100,125,1,24,76,34,101,49,33,0,115,18,74,102,16,120,97,62,3,10,92,45,93,85,59,58,82,90,54,57,75,29,12,11,19,66,60,89,117,31,81,98,123,114,110,69,88,116,106,41,70,4,64,84,48,42,78,65,26,38,28,51,50,47,103,127,35,17,61,94,72,111,21,83,124 };
  test.disable_feature = disabled_features;
  test.test_name = "vote_processor::tests::test_authorize_withdrawer";
  test.test_nonce  = 44;
  test.test_number = 1612;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 4;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "2KjtgnBp9GdhPQuZ2NtoSAhSHzXts4tzhxWDLq5frskD",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 26858640UL;
  test_acc->result_lamports = 26858640UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1612_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1612_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1612_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1612_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1612_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1612_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1612_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1612_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "9G5TLqZP8xHw89ocrAabn3ftsCjgm1rBEM1j8rXGaoX7",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1612_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1612_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1612_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1612_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "7ZVVhhz5Tb6gvzcCgRXpDwMFB3obECVotDHfbV4TUCYo",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1612_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1612_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1612_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1612_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1612_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1612_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1613(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 53,23,25,56,44,91,113,46,68,121,40,96,30,87,99,71,20,32,5,128,2,37,126,104,43,73,80,55,63,119,8,122,39,109,118,77,9,105,79,14,67,13,6,86,52,112,27,108,22,95,7,36,107,15,100,125,1,24,76,34,101,49,33,0,115,18,74,102,16,120,97,62,3,10,92,45,93,85,59,58,82,90,54,57,75,29,12,11,19,66,60,89,117,31,81,98,123,114,110,69,88,116,106,41,70,4,64,84,48,42,78,65,26,38,28,51,50,47,103,127,35,17,61,94,72,111,21,83,124 };
  test.disable_feature = disabled_features;
  test.test_name = "vote_processor::tests::test_authorize_withdrawer";
  test.test_nonce  = 20;
  test.test_number = 1613;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "2KjtgnBp9GdhPQuZ2NtoSAhSHzXts4tzhxWDLq5frskD",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 26858640UL;
  test_acc->result_lamports = 26858640UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1613_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1613_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1613_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1613_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1613_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1613_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1613_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1613_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "9G5TLqZP8xHw89ocrAabn3ftsCjgm1rBEM1j8rXGaoX7",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1613_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1613_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1613_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1613_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1613_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1613_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1614(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 53,23,25,56,44,91,113,46,68,121,40,96,30,87,99,71,20,32,5,128,2,37,126,104,43,73,80,55,63,119,8,122,39,109,118,77,9,105,79,14,67,13,6,86,52,112,27,108,22,95,7,36,107,15,100,125,1,24,76,34,101,49,33,0,115,18,74,102,16,120,97,62,3,10,92,45,93,85,59,58,82,90,54,57,75,29,12,11,19,66,60,89,117,31,81,98,123,114,110,69,88,116,106,41,70,4,64,84,48,42,78,65,26,38,28,51,50,47,103,127,35,17,61,94,72,111,21,83,124 };
  test.disable_feature = disabled_features;
  test.test_name = "vote_processor::tests::test_authorize_withdrawer";
  test.test_nonce  = 30;
  test.test_number = 1614;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "2KjtgnBp9GdhPQuZ2NtoSAhSHzXts4tzhxWDLq5frskD",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 26858640UL;
  test_acc->result_lamports = 26858640UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1614_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1614_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1614_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1614_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1614_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1614_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1614_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1614_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "9G5TLqZP8xHw89ocrAabn3ftsCjgm1rBEM1j8rXGaoX7",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1614_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1614_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1614_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1614_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1614_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1614_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1615(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 53,23,25,56,44,91,113,46,68,121,40,96,30,87,99,71,20,32,5,128,2,37,126,104,43,73,80,55,63,119,8,122,39,109,118,77,9,105,79,14,67,13,6,86,52,112,27,108,22,95,7,36,107,15,100,125,1,24,76,34,101,49,33,0,115,18,74,102,16,120,97,62,3,10,92,45,93,85,59,58,82,90,54,57,75,29,12,11,19,66,60,89,117,31,81,98,123,114,110,69,88,116,106,41,70,4,64,84,48,42,78,65,26,38,28,51,50,47,103,127,35,17,61,94,72,111,21,83,124 };
  test.disable_feature = disabled_features;
  test.test_name = "vote_processor::tests::test_authorize_withdrawer";
  test.test_nonce  = 4;
  test.test_number = 1615;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "2KjtgnBp9GdhPQuZ2NtoSAhSHzXts4tzhxWDLq5frskD",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 26858640UL;
  test_acc->result_lamports = 26858640UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1615_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1615_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1615_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1615_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1615_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1615_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1615_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1615_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "9G5TLqZP8xHw89ocrAabn3ftsCjgm1rBEM1j8rXGaoX7",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1615_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1615_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1615_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1615_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1615_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1615_raw_sz;
  test.expected_result = -8;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1616(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 33,78,76,116,82,98,123,27,90,87,112,62,89,121,24,103,113,111,55,128,92,106,114,109,122,15,56,120,26,30,80,83,110,77,79,105,75,61,126,125,118,127,124,108,117,2,29 };
  test.disable_feature = disabled_features;
  test.test_name = "vote_processor::tests::test_initialize_vote_account";
  test.test_nonce  = 4;
  test.test_number = 1616;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 4;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "FMDHs4QPdMWN1hqgh4E1Cvkw1474LYyCsRj8USokyikB",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1616_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1616_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1616_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1616_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1616_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1616_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1616_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1616_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1616_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1616_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1616_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1616_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "A6P4r5NVGqpqea8MK5AJXi2vg52AG37hhSabo3q57dir",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1616_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1616_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1616_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1616_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1616_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1616_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1617(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 33,2,120,30,80,27,82,92,118,117,90,114,113,76,24,103,26,111,127,106,123,122,79,77,15,110,78,98,112,121,128,55,126,83,62,125,89,109,124,87,56,116,75,61,29,105,108 };
  test.disable_feature = disabled_features;
  test.test_name = "vote_processor::tests::test_initialize_vote_account";
  test.test_nonce  = 46;
  test.test_number = 1617;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 4;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "FMDHs4QPdMWN1hqgh4E1Cvkw1474LYyCsRj8USokyikB",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1617_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1617_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1617_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1617_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1617_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1617_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1617_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1617_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1617_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1617_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1617_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1617_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "A6P4r5NVGqpqea8MK5AJXi2vg52AG37hhSabo3q57dir",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1617_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1617_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1617_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1617_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1617_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1617_raw_sz;
  test.expected_result = -4;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1618(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 82,15,121,120,108,125,30,116,80,92,89,2,109,83,62,106,127,128,79,110,90,55,124,56,29,112,118,98,77,123,113,114,122,61,126,76,24,33,103,87,78,105,117,75,26,27,111 };
  test.disable_feature = disabled_features;
  test.test_name = "vote_processor::tests::test_initialize_vote_account";
  test.test_nonce  = 30;
  test.test_number = 1618;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 4;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "FMDHs4QPdMWN1hqgh4E1Cvkw1474LYyCsRj8USokyikB",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1618_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1618_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1618_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1618_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1618_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1618_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1618_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1618_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1618_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1618_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1618_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1618_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "A6P4r5NVGqpqea8MK5AJXi2vg52AG37hhSabo3q57dir",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1618_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1618_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1618_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1618_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1618_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1618_raw_sz;
  test.expected_result = -9;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1619(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 106,80,109,56,113,78,117,124,120,103,125,108,30,82,123,98,2,111,118,116,76,26,75,127,122,87,89,77,110,112,33,105,92,90,121,62,114,61,24,27,79,15,83,55,128,29,126 };
  test.disable_feature = disabled_features;
  test.test_name = "vote_processor::tests::test_initialize_vote_account";
  test.test_nonce  = 59;
  test.test_number = 1619;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 4;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "FMDHs4QPdMWN1hqgh4E1Cvkw1474LYyCsRj8USokyikB",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1619_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1619_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1619_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1619_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1619_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1619_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1619_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1619_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1619_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1619_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1619_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1619_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "A6P4r5NVGqpqea8MK5AJXi2vg52AG37hhSabo3q57dir",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1619_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1619_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1619_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1619_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1619_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1619_raw_sz;
  test.expected_result = -8;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1620(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 106,80,109,56,113,78,117,124,120,103,125,108,30,82,123,98,2,111,118,116,76,26,75,127,122,87,89,77,110,112,33,105,92,90,121,62,114,61,24,27,79,15,83,55,128,29,126 };
  test.disable_feature = disabled_features;
  test.test_name = "vote_processor::tests::test_initialize_vote_account";
  test.test_nonce  = 22;
  test.test_number = 1620;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 4;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "3QNGKcjdyHUpB8M7GUWNpkSGkseKS4kEQHEj8Z8Zv518",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1620_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1620_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1620_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1620_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1620_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1620_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1620_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1620_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1620_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1620_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1620_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1620_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "ETQYNKemnD6ZGyZMYnb4CCUTpuyj15vN1WRNkEbA7xwT",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1620_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1620_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1620_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1620_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1620_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1620_raw_sz;
  test.expected_result = -9;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1621(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 106,80,109,56,113,78,117,124,120,103,125,108,30,82,123,98,2,111,118,116,76,26,75,127,122,87,89,77,110,112,33,105,92,90,121,62,114,61,24,27,79,15,83,55,128,29,126 };
  test.disable_feature = disabled_features;
  test.test_name = "vote_processor::tests::test_initialize_vote_account";
  test.test_nonce  = 32;
  test.test_number = 1621;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 4;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "3QNGKcjdyHUpB8M7GUWNpkSGkseKS4kEQHEj8Z8Zv518",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1621_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1621_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1621_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1621_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1621_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1621_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1621_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1621_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1621_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1621_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1621_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1621_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "ETQYNKemnD6ZGyZMYnb4CCUTpuyj15vN1WRNkEbA7xwT",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1621_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1621_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1621_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1621_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1621_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1621_raw_sz;
  test.expected_result = -4;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1622(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 106,80,109,56,113,78,117,124,120,103,125,108,30,82,123,98,2,111,118,116,76,26,75,127,122,87,89,77,110,112,33,105,92,90,121,62,114,61,24,27,79,15,83,55,128,29,126 };
  test.disable_feature = disabled_features;
  test.test_name = "vote_processor::tests::test_initialize_vote_account";
  test.test_nonce  = 50;
  test.test_number = 1622;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 4;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "3QNGKcjdyHUpB8M7GUWNpkSGkseKS4kEQHEj8Z8Zv518",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1622_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1622_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1622_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1622_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1622_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1622_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1622_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1622_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1622_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1622_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1622_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1622_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "ETQYNKemnD6ZGyZMYnb4CCUTpuyj15vN1WRNkEbA7xwT",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1622_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1622_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1622_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1622_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1622_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1622_raw_sz;
  test.expected_result = -8;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1623(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 106,80,109,56,113,78,117,124,120,103,125,108,30,82,123,98,2,111,118,116,76,26,75,127,122,87,89,77,110,112,33,105,92,90,121,62,114,61,24,27,79,15,83,55,128,29,126 };
  test.disable_feature = disabled_features;
  test.test_name = "vote_processor::tests::test_initialize_vote_account";
  test.test_nonce  = 6;
  test.test_number = 1623;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 4;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "3QNGKcjdyHUpB8M7GUWNpkSGkseKS4kEQHEj8Z8Zv518",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1623_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1623_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1623_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1623_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1623_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1623_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1623_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1623_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1623_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1623_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1623_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1623_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "ETQYNKemnD6ZGyZMYnb4CCUTpuyj15vN1WRNkEbA7xwT",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1623_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1623_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1623_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1623_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1623_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1623_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1624(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 118,127,83,105,114,79,87,128,75,126,110,121,77,30,82,98,103,109,111,108,124,29,27,55,116,24,120,106,2,56,90,125,76,62,122,123,113,112,15,26,61,80,33,92,117,89,78 };
  test.disable_feature = disabled_features;
  test.test_name = "vote_processor::tests::test_spoofed_vote";
  test.test_nonce  = 1;
  test.test_number = 1624;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 6;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1624_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1624_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1624_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1624_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "BadVote111111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "BadVote111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1624_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1624_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1624_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1624_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1624_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1624_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1624_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1624_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111112cMQwSC9qirWGjZM6gLGwW69X22mqwLLGP",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1624_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1624_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1624_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1624_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarEpochSchedu1e111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1624_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1624_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1624_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1624_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarS1otHashes111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1624_acc_5_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1624_acc_5_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1624_acc_5_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1624_acc_5_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1624_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1624_raw_sz;
  test.expected_result = -47;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
