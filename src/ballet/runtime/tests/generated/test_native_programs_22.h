#include "../fd_tests.h"
int test_550(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 1;
  uchar disabled_features[] = { 89 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_redelegate::old_behavior";
  test.test_nonce  = 516;
  test.test_number = 550;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 5;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "11111116djSnXB2wXVGT4xDLsfTnkp1p4cCxHAfRq",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 4565761UL;
  test_acc->result_lamports = 4565761UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_550_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_550_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_550_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_550_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111117353mdUKehx9GW6JNHznGt5oSZs9fWkVkB",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "111111124ANgfWJnvRSBJtCAimdSi4NafgAP4bfd5R",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_550_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_550_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_550_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_550_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111116EPqoQskEM2Pddp8KTL9JdYEBZMGF3aq7V",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_550_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_550_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_550_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_550_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "StakeConfig11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_550_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_550_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_550_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_550_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111115RidqCHAoz6dzmXxGcfWLNzevYqNpaRAUo",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_550_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_550_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_550_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_550_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_550_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_550_raw_sz;
  test.expected_result = -7;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_551(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 1;
  uchar disabled_features[] = { 89 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_redelegate::old_behavior";
  test.test_nonce  = 522;
  test.test_number = 551;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 5;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "11111116djSnXB2wXVGT4xDLsfTnkp1p4cCxHAfRq",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 4565761UL;
  test_acc->result_lamports = 2282880UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_551_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_551_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_551_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_551_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111117353mdUKehx9GW6JNHznGt5oSZs9fWkVkB",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 2282923UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_551_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_551_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_551_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_551_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111116EPqoQskEM2Pddp8KTL9JdYEBZMGF3aq7V",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_551_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_551_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_551_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_551_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "StakeConfig11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_551_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_551_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_551_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_551_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111115RidqCHAoz6dzmXxGcfWLNzevYqNpaRAUo",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_551_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_551_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_551_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_551_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_551_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_551_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_552(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 1;
  uchar disabled_features[] = { 89 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_redelegate::old_behavior";
  test.test_nonce  = 525;
  test.test_number = 552;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 5;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "11111116djSnXB2wXVGT4xDLsfTnkp1p4cCxHAfRq",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 4565761UL;
  test_acc->result_lamports = 4565761UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_552_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_552_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_552_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_552_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111117353mdUKehx9GW6JNHznGt5oSZs9fWkVkB",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_552_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_552_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_552_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_552_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111116EPqoQskEM2Pddp8KTL9JdYEBZMGF3aq7V",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_552_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_552_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_552_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_552_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "StakeConfig11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_552_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_552_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_552_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_552_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111115RidqCHAoz6dzmXxGcfWLNzevYqNpaRAUo",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_552_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_552_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_552_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_552_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_552_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_552_raw_sz;
  test.expected_result = -4;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_553(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 1;
  uchar disabled_features[] = { 89 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_redelegate::old_behavior";
  test.test_nonce  = 530;
  test.test_number = 553;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 5;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "11111116djSnXB2wXVGT4xDLsfTnkp1p4cCxHAfRq",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 4565761UL;
  test_acc->result_lamports = 4565761UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_553_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_553_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_553_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_553_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111117353mdUKehx9GW6JNHznGt5oSZs9fWkVkB",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_553_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_553_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_553_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_553_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111116EPqoQskEM2Pddp8KTL9JdYEBZMGF3aq7V",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_553_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_553_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_553_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_553_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "StakeConfig11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_553_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_553_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_553_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_553_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111115RidqCHAoz6dzmXxGcfWLNzevYqNpaRAUo",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_553_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_553_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_553_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_553_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_553_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_553_raw_sz;
  test.expected_result = -4;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_554(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 1;
  uchar disabled_features[] = { 89 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_redelegate::old_behavior";
  test.test_nonce  = 531;
  test.test_number = 554;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 5;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "11111116djSnXB2wXVGT4xDLsfTnkp1p4cCxHAfRq",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 4565803UL;
  test_acc->result_lamports = 2282922UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_554_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_554_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_554_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_554_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111117353mdUKehx9GW6JNHznGt5oSZs9fWkVkB",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 2282881UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_554_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_554_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_554_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_554_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111116EPqoQskEM2Pddp8KTL9JdYEBZMGF3aq7V",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_554_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_554_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_554_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_554_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "StakeConfig11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_554_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_554_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_554_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_554_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111115RidqCHAoz6dzmXxGcfWLNzevYqNpaRAUo",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_554_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_554_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_554_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_554_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_554_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_554_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_555(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 1;
  uchar disabled_features[] = { 89 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_redelegate::old_behavior";
  test.test_nonce  = 540;
  test.test_number = 555;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 5;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "11111116djSnXB2wXVGT4xDLsfTnkp1p4cCxHAfRq",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 4565761UL;
  test_acc->result_lamports = 4565761UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_555_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_555_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_555_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_555_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111117353mdUKehx9GW6JNHznGt5oSZs9fWkVkB",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111112EDpmHDkzfw25kigLLFxQqCBFQHbxqTFSz3",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_555_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_555_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_555_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_555_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111116EPqoQskEM2Pddp8KTL9JdYEBZMGF3aq7V",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_555_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_555_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_555_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_555_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "StakeConfig11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_555_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_555_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_555_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_555_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111115RidqCHAoz6dzmXxGcfWLNzevYqNpaRAUo",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_555_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_555_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_555_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_555_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_555_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_555_raw_sz;
  test.expected_result = -7;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_556(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 1;
  uchar disabled_features[] = { 89 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_redelegate::old_behavior";
  test.test_nonce  = 541;
  test.test_number = 556;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 5;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "11111116djSnXB2wXVGT4xDLsfTnkp1p4cCxHAfRq",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 4565761UL;
  test_acc->result_lamports = 4565761UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_556_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_556_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_556_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_556_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111117353mdUKehx9GW6JNHznGt5oSZs9fWkVkB",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 4565761UL;
  test_acc->result_lamports = 4565761UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_556_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_556_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_556_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_556_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111116EPqoQskEM2Pddp8KTL9JdYEBZMGF3aq7V",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_556_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_556_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_556_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_556_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "StakeConfig11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_556_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_556_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_556_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_556_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111115RidqCHAoz6dzmXxGcfWLNzevYqNpaRAUo",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_556_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_556_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_556_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_556_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_556_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_556_raw_sz;
  test.expected_result = -9;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_557(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 1;
  uchar disabled_features[] = { 89 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_redelegate::old_behavior";
  test.test_nonce  = 544;
  test.test_number = 557;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 5;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "11111116djSnXB2wXVGT4xDLsfTnkp1p4cCxHAfRq",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 4565761UL;
  test_acc->result_lamports = 4565761UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_557_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_557_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_557_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_557_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111117353mdUKehx9GW6JNHznGt5oSZs9fWkVkB",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_557_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_557_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_557_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_557_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111116EPqoQskEM2Pddp8KTL9JdYEBZMGF3aq7V",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_557_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_557_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_557_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_557_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "StakeConfig11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_557_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_557_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_557_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_557_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111115RidqCHAoz6dzmXxGcfWLNzevYqNpaRAUo",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_557_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_557_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_557_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_557_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_557_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_557_raw_sz;
  test.expected_result = -4;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_558(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 1;
  uchar disabled_features[] = { 89 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_redelegate::old_behavior";
  test.test_nonce  = 549;
  test.test_number = 558;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 5;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "11111116djSnXB2wXVGT4xDLsfTnkp1p4cCxHAfRq",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 4565761UL;
  test_acc->result_lamports = 4565761UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_558_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_558_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_558_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_558_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111117353mdUKehx9GW6JNHznGt5oSZs9fWkVkB",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_558_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_558_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_558_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_558_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111116EPqoQskEM2Pddp8KTL9JdYEBZMGF3aq7V",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_558_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_558_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_558_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_558_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "StakeConfig11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_558_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_558_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_558_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_558_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111115RidqCHAoz6dzmXxGcfWLNzevYqNpaRAUo",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_558_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_558_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_558_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_558_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_558_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_558_raw_sz;
  test.expected_result = -4;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_559(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 1;
  uchar disabled_features[] = { 89 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_redelegate::old_behavior";
  test.test_nonce  = 551;
  test.test_number = 559;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 5;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "11111116djSnXB2wXVGT4xDLsfTnkp1p4cCxHAfRq",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 4565761UL;
  test_acc->result_lamports = 4565761UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_559_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_559_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_559_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_559_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111117353mdUKehx9GW6JNHznGt5oSZs9fWkVkB",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_559_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_559_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_559_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_559_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111116EPqoQskEM2Pddp8KTL9JdYEBZMGF3aq7V",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_559_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_559_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_559_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_559_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "StakeConfig11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_559_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_559_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_559_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_559_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111115RidqCHAoz6dzmXxGcfWLNzevYqNpaRAUo",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_559_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_559_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_559_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_559_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_559_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_559_raw_sz;
  test.expected_result = -7;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_560(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 1;
  uchar disabled_features[] = { 89 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_redelegate::old_behavior";
  test.test_nonce  = 556;
  test.test_number = 560;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 5;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "11111116djSnXB2wXVGT4xDLsfTnkp1p4cCxHAfRq",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 4565761UL;
  test_acc->result_lamports = 4565761UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_560_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_560_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_560_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_560_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111117353mdUKehx9GW6JNHznGt5oSZs9fWkVkB",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 4565761UL;
  test_acc->result_lamports = 4565761UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_560_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_560_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_560_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_560_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111116EPqoQskEM2Pddp8KTL9JdYEBZMGF3aq7V",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_560_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_560_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_560_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_560_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "StakeConfig11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_560_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_560_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_560_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_560_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111115RidqCHAoz6dzmXxGcfWLNzevYqNpaRAUo",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_560_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_560_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_560_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_560_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_560_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_560_raw_sz;
  test.expected_result = -9;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_561(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 1;
  uchar disabled_features[] = { 89 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_redelegate::old_behavior";
  test.test_nonce  = 557;
  test.test_number = 561;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 5;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "11111116djSnXB2wXVGT4xDLsfTnkp1p4cCxHAfRq",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_561_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_561_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_561_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_561_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111117353mdUKehx9GW6JNHznGt5oSZs9fWkVkB",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_561_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_561_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_561_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_561_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111116EPqoQskEM2Pddp8KTL9JdYEBZMGF3aq7V",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_561_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_561_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_561_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_561_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "StakeConfig11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_561_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_561_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_561_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_561_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111115RidqCHAoz6dzmXxGcfWLNzevYqNpaRAUo",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_561_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_561_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_561_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_561_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_561_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_561_raw_sz;
  test.expected_result = -4;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_562(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 1;
  uchar disabled_features[] = { 89 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_redelegate::old_behavior";
  test.test_nonce  = 560;
  test.test_number = 562;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 5;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "11111116djSnXB2wXVGT4xDLsfTnkp1p4cCxHAfRq",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 4565761UL;
  test_acc->result_lamports = 4565761UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_562_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_562_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_562_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_562_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111117353mdUKehx9GW6JNHznGt5oSZs9fWkVkB",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_562_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_562_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_562_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_562_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111116EPqoQskEM2Pddp8KTL9JdYEBZMGF3aq7V",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_562_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_562_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_562_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_562_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "StakeConfig11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_562_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_562_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_562_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_562_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111115RidqCHAoz6dzmXxGcfWLNzevYqNpaRAUo",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_562_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_562_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_562_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_562_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_562_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_562_raw_sz;
  test.expected_result = -7;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_563(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 1;
  uchar disabled_features[] = { 89 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_redelegate::old_behavior";
  test.test_nonce  = 562;
  test.test_number = 563;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 5;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "11111116djSnXB2wXVGT4xDLsfTnkp1p4cCxHAfRq",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_563_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_563_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_563_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_563_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111117353mdUKehx9GW6JNHznGt5oSZs9fWkVkB",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_563_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_563_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_563_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_563_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111116EPqoQskEM2Pddp8KTL9JdYEBZMGF3aq7V",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_563_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_563_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_563_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_563_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "StakeConfig11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_563_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_563_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_563_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_563_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111115RidqCHAoz6dzmXxGcfWLNzevYqNpaRAUo",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_563_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_563_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_563_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_563_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_563_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_563_raw_sz;
  test.expected_result = -4;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_564(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 1;
  uchar disabled_features[] = { 89 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_redelegate::old_behavior";
  test.test_nonce  = 563;
  test.test_number = 564;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 5;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "11111116djSnXB2wXVGT4xDLsfTnkp1p4cCxHAfRq",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 4565761UL;
  test_acc->result_lamports = 4565761UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_564_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_564_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_564_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_564_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111117353mdUKehx9GW6JNHznGt5oSZs9fWkVkB",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_564_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_564_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_564_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_564_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111116EPqoQskEM2Pddp8KTL9JdYEBZMGF3aq7V",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_564_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_564_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_564_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_564_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "StakeConfig11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_564_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_564_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_564_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_564_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111115RidqCHAoz6dzmXxGcfWLNzevYqNpaRAUo",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_564_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_564_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_564_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_564_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_564_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_564_raw_sz;
  test.expected_result = -26;
  test.custom_err = 13;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_565(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 1;
  uchar disabled_features[] = { 89 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_redelegate::old_behavior";
  test.test_nonce  = 569;
  test.test_number = 565;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 5;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "11111116djSnXB2wXVGT4xDLsfTnkp1p4cCxHAfRq",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 4565761UL;
  test_acc->result_lamports = 4565761UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_565_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_565_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_565_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_565_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111117353mdUKehx9GW6JNHznGt5oSZs9fWkVkB",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_565_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_565_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_565_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_565_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111116EPqoQskEM2Pddp8KTL9JdYEBZMGF3aq7V",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_565_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_565_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_565_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_565_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "StakeConfig11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_565_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_565_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_565_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_565_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111115RidqCHAoz6dzmXxGcfWLNzevYqNpaRAUo",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_565_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_565_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_565_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_565_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_565_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_565_raw_sz;
  test.expected_result = -26;
  test.custom_err = 13;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_566(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 1;
  uchar disabled_features[] = { 89 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_redelegate::old_behavior";
  test.test_nonce  = 574;
  test.test_number = 566;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 5;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "11111116djSnXB2wXVGT4xDLsfTnkp1p4cCxHAfRq",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 4565761UL;
  test_acc->result_lamports = 4565761UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_566_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_566_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_566_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_566_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111117353mdUKehx9GW6JNHznGt5oSZs9fWkVkB",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_566_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_566_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_566_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_566_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111116EPqoQskEM2Pddp8KTL9JdYEBZMGF3aq7V",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_566_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_566_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_566_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_566_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "StakeConfig11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_566_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_566_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_566_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_566_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111115RidqCHAoz6dzmXxGcfWLNzevYqNpaRAUo",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_566_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_566_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_566_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_566_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_566_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_566_raw_sz;
  test.expected_result = -26;
  test.custom_err = 13;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_567(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 1;
  uchar disabled_features[] = { 89 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_redelegate::old_behavior";
  test.test_nonce  = 574;
  test.test_number = 567;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 5;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "11111116djSnXB2wXVGT4xDLsfTnkp1p4cCxHAfRq",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 4565761UL;
  test_acc->result_lamports = 4565761UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_567_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_567_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_567_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_567_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111117353mdUKehx9GW6JNHznGt5oSZs9fWkVkB",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_567_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_567_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_567_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_567_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111116EPqoQskEM2Pddp8KTL9JdYEBZMGF3aq7V",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_567_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_567_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_567_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_567_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "StakeConfig11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_567_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_567_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_567_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_567_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111115RidqCHAoz6dzmXxGcfWLNzevYqNpaRAUo",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_567_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_567_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_567_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_567_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_567_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_567_raw_sz;
  test.expected_result = -26;
  test.custom_err = 13;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_568(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 1;
  uchar disabled_features[] = { 89 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_redelegate::old_behavior";
  test.test_nonce  = 579;
  test.test_number = 568;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 5;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "11111116djSnXB2wXVGT4xDLsfTnkp1p4cCxHAfRq",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 4565761UL;
  test_acc->result_lamports = 4565761UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_568_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_568_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_568_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_568_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111117353mdUKehx9GW6JNHznGt5oSZs9fWkVkB",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_568_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_568_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_568_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_568_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111116EPqoQskEM2Pddp8KTL9JdYEBZMGF3aq7V",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_568_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_568_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_568_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_568_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "StakeConfig11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_568_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_568_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_568_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_568_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111115RidqCHAoz6dzmXxGcfWLNzevYqNpaRAUo",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_568_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_568_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_568_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_568_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_568_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_568_raw_sz;
  test.expected_result = -26;
  test.custom_err = 13;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_569(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 1;
  uchar disabled_features[] = { 89 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_redelegate::old_behavior";
  test.test_nonce  = 583;
  test.test_number = 569;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 5;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "11111116djSnXB2wXVGT4xDLsfTnkp1p4cCxHAfRq",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 4565760UL;
  test_acc->result_lamports = 2282880UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_569_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_569_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_569_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_569_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111117353mdUKehx9GW6JNHznGt5oSZs9fWkVkB",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 2282880UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_569_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_569_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_569_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_569_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111116EPqoQskEM2Pddp8KTL9JdYEBZMGF3aq7V",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_569_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_569_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_569_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_569_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "StakeConfig11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_569_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_569_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_569_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_569_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111115RidqCHAoz6dzmXxGcfWLNzevYqNpaRAUo",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_569_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_569_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_569_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_569_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_569_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_569_raw_sz;
  test.expected_result = -26;
  test.custom_err = 12;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_570(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 1;
  uchar disabled_features[] = { 89 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_redelegate::old_behavior";
  test.test_nonce  = 585;
  test.test_number = 570;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 5;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "11111116djSnXB2wXVGT4xDLsfTnkp1p4cCxHAfRq",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 4565761UL;
  test_acc->result_lamports = 4565761UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_570_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_570_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_570_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_570_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111117353mdUKehx9GW6JNHznGt5oSZs9fWkVkB",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_570_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_570_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_570_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_570_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111116EPqoQskEM2Pddp8KTL9JdYEBZMGF3aq7V",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_570_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_570_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_570_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_570_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "StakeConfig11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_570_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_570_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_570_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_570_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111115RidqCHAoz6dzmXxGcfWLNzevYqNpaRAUo",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_570_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_570_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_570_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_570_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_570_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_570_raw_sz;
  test.expected_result = -26;
  test.custom_err = 13;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_571(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 1;
  uchar disabled_features[] = { 89 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_redelegate::old_behavior";
  test.test_nonce  = 588;
  test.test_number = 571;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 5;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "11111116djSnXB2wXVGT4xDLsfTnkp1p4cCxHAfRq",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 4565761UL;
  test_acc->result_lamports = 4565761UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_571_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_571_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_571_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_571_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111117353mdUKehx9GW6JNHznGt5oSZs9fWkVkB",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_571_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_571_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_571_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_571_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111115q4EpJaTXAZWpCg3J2zppWGSZ46KXozzo9",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_571_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_571_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_571_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_571_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "StakeConfig11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_571_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_571_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_571_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_571_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111115RidqCHAoz6dzmXxGcfWLNzevYqNpaRAUo",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_571_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_571_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_571_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_571_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_571_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_571_raw_sz;
  test.expected_result = -26;
  test.custom_err = 14;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_572(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 1;
  uchar disabled_features[] = { 89 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_redelegate::old_behavior";
  test.test_nonce  = 589;
  test.test_number = 572;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 5;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "11111116djSnXB2wXVGT4xDLsfTnkp1p4cCxHAfRq",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 4565760UL;
  test_acc->result_lamports = 2282880UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_572_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_572_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_572_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_572_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111117353mdUKehx9GW6JNHznGt5oSZs9fWkVkB",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 2282880UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_572_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_572_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_572_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_572_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111116EPqoQskEM2Pddp8KTL9JdYEBZMGF3aq7V",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_572_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_572_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_572_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_572_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "StakeConfig11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_572_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_572_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_572_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_572_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111115RidqCHAoz6dzmXxGcfWLNzevYqNpaRAUo",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_572_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_572_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_572_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_572_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_572_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_572_raw_sz;
  test.expected_result = -26;
  test.custom_err = 12;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_573(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 1;
  uchar disabled_features[] = { 89 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_redelegate::old_behavior";
  test.test_nonce  = 591;
  test.test_number = 573;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 5;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "11111116djSnXB2wXVGT4xDLsfTnkp1p4cCxHAfRq",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 4565761UL;
  test_acc->result_lamports = 4565761UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_573_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_573_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_573_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_573_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111117353mdUKehx9GW6JNHznGt5oSZs9fWkVkB",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_573_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_573_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_573_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_573_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111115q4EpJaTXAZWpCg3J2zppWGSZ46KXozzo9",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_573_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_573_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_573_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_573_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "StakeConfig11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_573_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_573_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_573_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_573_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111115RidqCHAoz6dzmXxGcfWLNzevYqNpaRAUo",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_573_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_573_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_573_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_573_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_573_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_573_raw_sz;
  test.expected_result = -26;
  test.custom_err = 14;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_574(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 1;
  uchar disabled_features[] = { 89 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_redelegate::old_behavior";
  test.test_nonce  = 61;
  test.test_number = 574;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 5;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "11111116djSnXB2wXVGT4xDLsfTnkp1p4cCxHAfRq",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 4565761UL;
  test_acc->result_lamports = 4565761UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_574_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_574_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_574_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_574_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111117353mdUKehx9GW6JNHznGt5oSZs9fWkVkB",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_574_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_574_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_574_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_574_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111116EPqoQskEM2Pddp8KTL9JdYEBZMGF3aq7V",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_574_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_574_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_574_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_574_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "StakeConfig11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_574_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_574_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_574_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_574_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111Af7Udc9v3L82dQM5b4zee1Xt77Be4czzbH",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_574_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_574_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_574_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_574_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_574_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_574_raw_sz;
  test.expected_result = -8;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
