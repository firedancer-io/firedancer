#include "../fd_tests.h"
int test_1291(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  test.bt = "   2: solana_config_program::config_processor::tests::test_process_store_fail_account0_not_signer             at ./src/config_processor.rs:294:9   3: solana_config_program::config_processor::tests::test_process_store_fail_account0_not_signer::{{closure}}             at ./src/config_processor.rs:285:54   4: core::ops::function::FnOnce::call_once             at /rustc/cc66ad468955717ab92600c770da8c1601a4ff33/library/core/src/ops/function.rs:250:5   5: core::ops::function::FnOnce::call_once             at /rustc/cc66ad468955717ab92600c770da8c1601a4ff33/library/core/src/ops/function.rs:250:5";
  test.test_name = "config_processor::tests::test_process_store_fail_account0_not_signer";
  test.test_number = 1291;
  test.sysvar_cache.clock = "";
  test.sysvar_cache.epoch_schedule = "";
  test.sysvar_cache.epoch_rewards = "";
  test.sysvar_cache.fees = "";
  test.sysvar_cache.rent = "";
  test.sysvar_cache.slot_hashes = "";
  test.sysvar_cache.stake_history = "";
  test.sysvar_cache.slot_history = "";
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 2;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

 // {'clock': '', 'epoch_schedule': '', 'epoch_rewards': '', 'fees': '', 'rent': '', 'slot_hashes': '', 'recent_blockhashes': '', 'stake_history': '', 'last_restart_slot': ''}
  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "254s5Mqz5u559uTyvbjaixHcxbq5oupiSnaSn7Uz3Kh3",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->result_owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->result_executable= 0;
  test_acc->rent_epoch      = 0;
  test_acc->result_rent_epoch      = 0;
  static uchar const fd_flamenco_native_prog_test_1291_acc_0_data[] = { 0x00,0x15,0xcd,0x5b,0x07,0x00,0x00,0x00,0x00 };
  test_acc->data            = fd_flamenco_native_prog_test_1291_acc_0_data;
  test_acc->data_len        = 9UL;
  static uchar const fd_flamenco_native_prog_test_1291_acc_0_post_data[] = { 0x00,0x15,0xcd,0x5b,0x07,0x00,0x00,0x00,0x00 };
  test_acc->result_data     = fd_flamenco_native_prog_test_1291_acc_0_post_data;
  test_acc->result_data_len = 9UL;
  test_acc++;
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "NativeLoader1111111111111111111111111111111",  (uchar *) &test_acc->owner);
  fd_base58_decode_32( "NativeLoader1111111111111111111111111111111",  (uchar *) &test_acc->result_owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->result_executable= 0;
  test_acc->rent_epoch      = 0;
  test_acc->result_rent_epoch      = 0;
  test_acc++;
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  static uchar const fd_flamenco_native_prog_test_1291_raw[] = { 0x00,0x00,0x00,0x01,0x02,0x0f,0xe6,0x60,0xe4,0x46,0xd6,0x49,0xaa,0x19,0x0f,0x4d,0xa9,0xb9,0xd4,0x1a,0x07,0xaf,0x45,0xf7,0x8d,0xa3,0xb3,0x23,0x98,0x9c,0xb8,0x05,0x06,0x5f,0xa5,0x17,0x5a,0x03,0x06,0x4a,0xa3,0x00,0x2f,0x74,0xdc,0xc8,0x6e,0x43,0x31,0x0f,0x0c,0x05,0x2a,0xf8,0xc5,0xda,0x27,0xf6,0x10,0x40,0x19,0xa3,0x23,0xef,0xa0,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x01,0x01,0x01,0x00,0x09,0x00,0x2a,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };
  test.raw_tx = fd_flamenco_native_prog_test_1291_raw;
  test.raw_tx_len = 115UL;
  test.expected_result = -8;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
// https://explorer.solana.com/tx/inspector?message=AAABAg%2FmYORG1kmqGQ9NqbnUGgevRfeNo7MjmJy4BQZfpRdaAwZKowAvdNzIbkMxDwwFKvjF2if2EEAZoyPvoAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEBAQAJACoAAAAAAAAA
