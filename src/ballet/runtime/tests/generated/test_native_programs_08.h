#include "../fd_tests.h"
int test_200(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 1;
  uchar disabled_features[] = { 89 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_deactivate_delinquent::old_behavior";
  test.test_nonce  = 307;
  test.test_number = 200;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "11111113R2cuenjG5nFubqX9Wzuukdin2YfGQVzu5",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_200_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_200_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_200_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_200_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "111111131h1vYVSYuKP6AhS86fbRdMw9XHiZAvAaj",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_200_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_200_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_200_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_200_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111112cMQwSC9qirWGjZM6gLGwW69X22mqwLLGP",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_200_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_200_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_200_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_200_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_200_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_200_raw_sz;
  test.expected_result = -26;
  test.custom_err = 11;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_201(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 1;
  uchar disabled_features[] = { 89 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_deactivate_delinquent::old_behavior";
  test.test_nonce  = 326;
  test.test_number = 201;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "11111113R2cuenjG5nFubqX9Wzuukdin2YfGQVzu5",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_201_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_201_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_201_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_201_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "111111131h1vYVSYuKP6AhS86fbRdMw9XHiZAvAaj",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_201_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_201_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_201_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_201_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111112cMQwSC9qirWGjZM6gLGwW69X22mqwLLGP",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_201_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_201_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_201_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_201_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_201_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_201_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_202(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 1;
  uchar disabled_features[] = { 89 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_deactivate_delinquent::old_behavior";
  test.test_nonce  = 368;
  test.test_number = 202;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111111krqkKqVQPfWW9FCSfjJjrffkbz5pVXaoUb",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_202_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_202_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_202_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_202_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "111111131h1vYVSYuKP6AhS86fbRdMw9XHiZAvAaj",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_202_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_202_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_202_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_202_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111112cMQwSC9qirWGjZM6gLGwW69X22mqwLLGP",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_202_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_202_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_202_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_202_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_202_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_202_raw_sz;
  test.expected_result = -26;
  test.custom_err = 10;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_203(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 1;
  uchar disabled_features[] = { 89 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_deactivate_delinquent::old_behavior";
  test.test_nonce  = 40;
  test.test_number = 203;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "11111113R2cuenjG5nFubqX9Wzuukdin2YfGQVzu5",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_203_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_203_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_203_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_203_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "111111131h1vYVSYuKP6AhS86fbRdMw9XHiZAvAaj",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_203_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_203_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_203_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_203_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111112cMQwSC9qirWGjZM6gLGwW69X22mqwLLGP",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_203_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_203_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_203_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_203_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_203_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_203_raw_sz;
  test.expected_result = -26;
  test.custom_err = 9;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_204(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 1;
  uchar disabled_features[] = { 89 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_deactivate_delinquent::old_behavior";
  test.test_nonce  = 410;
  test.test_number = 204;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "11111113R2cuenjG5nFubqX9Wzuukdin2YfGQVzu5",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_204_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_204_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_204_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_204_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "111111131h1vYVSYuKP6AhS86fbRdMw9XHiZAvAaj",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_204_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_204_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_204_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_204_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111112cMQwSC9qirWGjZM6gLGwW69X22mqwLLGP",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_204_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_204_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_204_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_204_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_204_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_204_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_205(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 1;
  uchar disabled_features[] = { 89 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_deactivate_delinquent::old_behavior";
  test.test_nonce  = 444;
  test.test_number = 205;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "11111113R2cuenjG5nFubqX9Wzuukdin2YfGQVzu5",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_205_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_205_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_205_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_205_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "111111131h1vYVSYuKP6AhS86fbRdMw9XHiZAvAaj",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_205_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_205_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_205_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_205_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111112cMQwSC9qirWGjZM6gLGwW69X22mqwLLGP",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_205_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_205_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_205_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_205_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_205_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_205_raw_sz;
  test.expected_result = -26;
  test.custom_err = 11;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_206(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 1;
  uchar disabled_features[] = { 89 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_deactivate_delinquent::old_behavior";
  test.test_nonce  = 4;
  test.test_number = 206;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "11111113R2cuenjG5nFubqX9Wzuukdin2YfGQVzu5",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_206_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_206_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_206_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_206_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "111111131h1vYVSYuKP6AhS86fbRdMw9XHiZAvAaj",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_206_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_206_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_206_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_206_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111112cMQwSC9qirWGjZM6gLGwW69X22mqwLLGP",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_206_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_206_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_206_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_206_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_206_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_206_raw_sz;
  test.expected_result = -26;
  test.custom_err = 9;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_207(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 1;
  uchar disabled_features[] = { 89 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_deactivate_delinquent::old_behavior";
  test.test_nonce  = 90;
  test.test_number = 207;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "11111113R2cuenjG5nFubqX9Wzuukdin2YfGQVzu5",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_207_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_207_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_207_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_207_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "111111131h1vYVSYuKP6AhS86fbRdMw9XHiZAvAaj",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_207_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_207_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_207_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_207_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111112cMQwSC9qirWGjZM6gLGwW69X22mqwLLGP",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_207_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_207_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_207_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_207_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_207_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_207_raw_sz;
  test.expected_result = -26;
  test.custom_err = 9;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_208(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 83,111,124,75,79,121,114,123,128,117,112,24,56,30,113,118,90,15,103,26,89,80,126,78,110,105,2,55,87,108,122,27,77,98,33,120,116,82,125,106,61,29,127,76,109,92,62 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_deactivate::new_behavior";
  test.test_nonce  = 357;
  test.test_number = 208;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 5;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "2kvxarsQX4ASbDs1iByMhs1P5zbKZ3SFiRw8DyGfi3TV",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1000000000UL;
  test_acc->result_lamports = 1000000000UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_208_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_208_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_208_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_208_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "BKynbPvMCWMpCxdY5nf7ox7tTMycTGzcs4bgqCvL1mh5",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_208_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_208_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_208_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_208_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_208_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_208_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_208_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_208_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_208_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_208_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_208_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_208_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "StakeConfig11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_208_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_208_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_208_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_208_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_208_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_208_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_209(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 83,111,124,75,79,121,114,123,128,117,112,24,56,30,113,118,90,15,103,26,89,80,126,78,110,105,2,55,87,108,122,27,77,98,33,120,116,82,125,106,61,29,127,76,109,92,62 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_deactivate::new_behavior";
  test.test_nonce  = 367;
  test.test_number = 209;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 5;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "hQibvR1UZYnM7u76WYrs6MYCXxMLWx2uMVujFWZierf",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1000000000UL;
  test_acc->result_lamports = 1000000000UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_209_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_209_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_209_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_209_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "9HLQ9erQw2up1WiYD1ctN2LnGihBrSxJYwkDk2LVNJTm",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_209_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_209_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_209_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_209_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_209_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_209_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_209_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_209_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_209_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_209_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_209_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_209_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "StakeConfig11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_209_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_209_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_209_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_209_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_209_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_209_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_210(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 83,111,124,75,79,121,114,123,128,117,112,24,56,30,113,118,90,15,103,26,89,80,126,78,110,105,2,55,87,108,122,27,77,98,33,120,116,82,125,106,61,29,127,76,109,92,62 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_deactivate::new_behavior";
  test.test_nonce  = 11;
  test.test_number = 210;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 5;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "2kvxarsQX4ASbDs1iByMhs1P5zbKZ3SFiRw8DyGfi3TV",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1000000000UL;
  test_acc->result_lamports = 1000000000UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_210_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_210_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_210_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_210_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "BKynbPvMCWMpCxdY5nf7ox7tTMycTGzcs4bgqCvL1mh5",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_210_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_210_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_210_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_210_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_210_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_210_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_210_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_210_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_210_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_210_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_210_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_210_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "StakeConfig11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_210_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_210_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_210_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_210_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_210_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_210_raw_sz;
  test.expected_result = -4;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_211(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 83,111,124,75,79,121,114,123,128,117,112,24,56,30,113,118,90,15,103,26,89,80,126,78,110,105,2,55,87,108,122,27,77,98,33,120,116,82,125,106,61,29,127,76,109,92,62 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_deactivate::new_behavior";
  test.test_nonce  = 215;
  test.test_number = 211;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 5;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "2kvxarsQX4ASbDs1iByMhs1P5zbKZ3SFiRw8DyGfi3TV",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1000000000UL;
  test_acc->result_lamports = 1000000000UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_211_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_211_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_211_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_211_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "BKynbPvMCWMpCxdY5nf7ox7tTMycTGzcs4bgqCvL1mh5",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_211_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_211_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_211_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_211_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_211_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_211_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_211_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_211_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_211_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_211_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_211_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_211_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "StakeConfig11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_211_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_211_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_211_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_211_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_211_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_211_raw_sz;
  test.expected_result = -4;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_212(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 83,111,124,75,79,121,114,123,128,117,112,24,56,30,113,118,90,15,103,26,89,80,126,78,110,105,2,55,87,108,122,27,77,98,33,120,116,82,125,106,61,29,127,76,109,92,62 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_deactivate::new_behavior";
  test.test_nonce  = 422;
  test.test_number = 212;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 5;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "2kvxarsQX4ASbDs1iByMhs1P5zbKZ3SFiRw8DyGfi3TV",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1000000000UL;
  test_acc->result_lamports = 1000000000UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_212_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_212_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_212_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_212_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "BKynbPvMCWMpCxdY5nf7ox7tTMycTGzcs4bgqCvL1mh5",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_212_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_212_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_212_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_212_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_212_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_212_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_212_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_212_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_212_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_212_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_212_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_212_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "StakeConfig11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_212_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_212_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_212_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_212_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_212_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_212_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_213(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 83,111,124,75,79,121,114,123,128,117,112,24,56,30,113,118,90,15,103,26,89,80,126,78,110,105,2,55,87,108,122,27,77,98,33,120,116,82,125,106,61,29,127,76,109,92,62 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_deactivate::new_behavior";
  test.test_nonce  = 484;
  test.test_number = 213;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 5;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "2kvxarsQX4ASbDs1iByMhs1P5zbKZ3SFiRw8DyGfi3TV",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1000000000UL;
  test_acc->result_lamports = 1000000000UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_213_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_213_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_213_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_213_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "BKynbPvMCWMpCxdY5nf7ox7tTMycTGzcs4bgqCvL1mh5",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_213_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_213_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_213_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_213_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_213_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_213_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_213_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_213_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_213_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_213_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_213_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_213_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "StakeConfig11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_213_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_213_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_213_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_213_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_213_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_213_raw_sz;
  test.expected_result = -26;
  test.custom_err = 2;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_214(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 83,111,124,75,79,121,114,123,128,117,112,24,56,30,113,118,90,15,103,26,89,80,126,78,110,105,2,55,87,108,122,27,77,98,33,120,116,82,125,106,61,29,127,76,109,92,62 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_deactivate::new_behavior";
  test.test_nonce  = 11;
  test.test_number = 214;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 5;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "hQibvR1UZYnM7u76WYrs6MYCXxMLWx2uMVujFWZierf",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1000000000UL;
  test_acc->result_lamports = 1000000000UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_214_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_214_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_214_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_214_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "9HLQ9erQw2up1WiYD1ctN2LnGihBrSxJYwkDk2LVNJTm",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_214_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_214_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_214_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_214_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_214_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_214_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_214_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_214_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_214_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_214_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_214_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_214_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "StakeConfig11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_214_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_214_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_214_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_214_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_214_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_214_raw_sz;
  test.expected_result = -4;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_215(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 83,111,124,75,79,121,114,123,128,117,112,24,56,30,113,118,90,15,103,26,89,80,126,78,110,105,2,55,87,108,122,27,77,98,33,120,116,82,125,106,61,29,127,76,109,92,62 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_deactivate::new_behavior";
  test.test_nonce  = 244;
  test.test_number = 215;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 5;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "hQibvR1UZYnM7u76WYrs6MYCXxMLWx2uMVujFWZierf",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1000000000UL;
  test_acc->result_lamports = 1000000000UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_215_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_215_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_215_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_215_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "9HLQ9erQw2up1WiYD1ctN2LnGihBrSxJYwkDk2LVNJTm",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_215_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_215_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_215_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_215_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_215_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_215_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_215_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_215_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_215_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_215_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_215_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_215_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "StakeConfig11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_215_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_215_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_215_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_215_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_215_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_215_raw_sz;
  test.expected_result = -4;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_216(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 83,111,124,75,79,121,114,123,128,117,112,24,56,30,113,118,90,15,103,26,89,80,126,78,110,105,2,55,87,108,122,27,77,98,33,120,116,82,125,106,61,29,127,76,109,92,62 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_deactivate::new_behavior";
  test.test_nonce  = 441;
  test.test_number = 216;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 5;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "hQibvR1UZYnM7u76WYrs6MYCXxMLWx2uMVujFWZierf",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1000000000UL;
  test_acc->result_lamports = 1000000000UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_216_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_216_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_216_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_216_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "9HLQ9erQw2up1WiYD1ctN2LnGihBrSxJYwkDk2LVNJTm",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_216_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_216_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_216_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_216_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_216_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_216_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_216_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_216_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_216_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_216_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_216_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_216_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "StakeConfig11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_216_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_216_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_216_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_216_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_216_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_216_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_217(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 83,111,124,75,79,121,114,123,128,117,112,24,56,30,113,118,90,15,103,26,89,80,126,78,110,105,2,55,87,108,122,27,77,98,33,120,116,82,125,106,61,29,127,76,109,92,62 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_deactivate::new_behavior";
  test.test_nonce  = 506;
  test.test_number = 217;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 5;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "hQibvR1UZYnM7u76WYrs6MYCXxMLWx2uMVujFWZierf",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1000000000UL;
  test_acc->result_lamports = 1000000000UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_217_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_217_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_217_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_217_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "9HLQ9erQw2up1WiYD1ctN2LnGihBrSxJYwkDk2LVNJTm",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_217_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_217_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_217_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_217_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_217_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_217_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_217_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_217_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_217_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_217_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_217_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_217_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "StakeConfig11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_217_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_217_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_217_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_217_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_217_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_217_raw_sz;
  test.expected_result = -26;
  test.custom_err = 2;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_218(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 1;
  uchar disabled_features[] = { 89 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_deactivate::old_behavior";
  test.test_nonce  = 417;
  test.test_number = 218;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 5;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "9hQxDqD5exE8Kq45Rzp6Qxa6kcvsVUpu7L4cmLNfFjJj",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_218_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_218_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_218_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_218_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "D9kyKjhKjqsGoUqWXjxMXyV82xDo3qNNnXK66uXZnnLp",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_218_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_218_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_218_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_218_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_218_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_218_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_218_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_218_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_218_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_218_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_218_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_218_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "StakeConfig11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_218_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_218_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_218_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_218_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_218_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_218_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_219(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 56,128,118,15,122,108,106,127,98,61,55,87,78,109,89,26,30,123,33,24,92,82,2,126,79,114,105,77,113,90,80,117,116,111,121,62,103,29,125,76,75,124,120,27,110,83,112 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_deactivate::old_behavior";
  test.test_nonce  = 378;
  test.test_number = 219;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 5;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "G4QCZPTXS9mvh14HjTDFxFAWfDGSeVVMJLKcMo2RqbxR",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_219_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_219_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_219_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_219_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "GbyegxSFtBspJA7xvbH62orotuzotGCGXf8sMJkNX7Y2",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_219_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_219_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_219_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_219_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_219_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_219_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_219_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_219_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_219_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_219_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_219_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_219_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "StakeConfig11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_219_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_219_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_219_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_219_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_219_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_219_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_220(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 1;
  uchar disabled_features[] = { 89 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_deactivate::old_behavior";
  test.test_nonce  = 13;
  test.test_number = 220;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 5;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "9hQxDqD5exE8Kq45Rzp6Qxa6kcvsVUpu7L4cmLNfFjJj",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_220_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_220_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_220_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_220_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "D9kyKjhKjqsGoUqWXjxMXyV82xDo3qNNnXK66uXZnnLp",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_220_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_220_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_220_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_220_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_220_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_220_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_220_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_220_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_220_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_220_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_220_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_220_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "StakeConfig11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_220_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_220_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_220_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_220_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_220_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_220_raw_sz;
  test.expected_result = -4;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_221(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 1;
  uchar disabled_features[] = { 89 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_deactivate::old_behavior";
  test.test_nonce  = 330;
  test.test_number = 221;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 5;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "9hQxDqD5exE8Kq45Rzp6Qxa6kcvsVUpu7L4cmLNfFjJj",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_221_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_221_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_221_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_221_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "D9kyKjhKjqsGoUqWXjxMXyV82xDo3qNNnXK66uXZnnLp",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_221_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_221_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_221_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_221_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_221_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_221_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_221_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_221_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_221_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_221_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_221_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_221_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "StakeConfig11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_221_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_221_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_221_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_221_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_221_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_221_raw_sz;
  test.expected_result = -4;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_222(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 1;
  uchar disabled_features[] = { 89 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_deactivate::old_behavior";
  test.test_nonce  = 482;
  test.test_number = 222;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 5;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "9hQxDqD5exE8Kq45Rzp6Qxa6kcvsVUpu7L4cmLNfFjJj",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_222_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_222_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_222_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_222_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "D9kyKjhKjqsGoUqWXjxMXyV82xDo3qNNnXK66uXZnnLp",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_222_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_222_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_222_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_222_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_222_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_222_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_222_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_222_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_222_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_222_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_222_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_222_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "StakeConfig11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_222_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_222_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_222_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_222_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_222_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_222_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_223(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 1;
  uchar disabled_features[] = { 89 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_deactivate::old_behavior";
  test.test_nonce  = 535;
  test.test_number = 223;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 5;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "9hQxDqD5exE8Kq45Rzp6Qxa6kcvsVUpu7L4cmLNfFjJj",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_223_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_223_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_223_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_223_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "D9kyKjhKjqsGoUqWXjxMXyV82xDo3qNNnXK66uXZnnLp",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_223_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_223_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_223_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_223_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_223_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_223_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_223_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_223_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_223_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_223_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_223_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_223_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "StakeConfig11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_223_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_223_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_223_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_223_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_223_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_223_raw_sz;
  test.expected_result = -26;
  test.custom_err = 2;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_224(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 56,128,118,15,122,108,106,127,98,61,55,87,78,109,89,26,30,123,33,24,92,82,2,126,79,114,105,77,113,90,80,117,116,111,121,62,103,29,125,76,75,124,120,27,110,83,112 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_deactivate::old_behavior";
  test.test_nonce  = 13;
  test.test_number = 224;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 5;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "G4QCZPTXS9mvh14HjTDFxFAWfDGSeVVMJLKcMo2RqbxR",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_224_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_224_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_224_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_224_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "GbyegxSFtBspJA7xvbH62orotuzotGCGXf8sMJkNX7Y2",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_224_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_224_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_224_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_224_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_224_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_224_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_224_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_224_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_224_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_224_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_224_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_224_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "StakeConfig11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_224_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_224_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_224_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_224_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_224_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_224_raw_sz;
  test.expected_result = -4;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
