#include "fd_tests.h"
#include <stdio.h>
#include <unistd.h>

#ifdef _DISABLE_OPTIMIZATION
#pragma GCC optimize ("O0")
#endif

/* copied from test_funk_txn.c */
static fd_funk_txn_xid_t *
fd_funk_txn_xid_set_unique( fd_funk_txn_xid_t * xid ) {
  static FD_TLS ulong tag = 0UL;
  xid->ul[0] = fd_log_app_id();
  xid->ul[1] = fd_log_thread_id();
  xid->ul[2] = ++tag;
# if FD_HAS_X86
  xid->ul[3] = (ulong)fd_tickcount();
# else
  xid->ul[3] = 0UL;
# endif
  return xid;
}

void fd_executor_test_suite_new( fd_executor_test_suite_t* suite ) {
  suite->wksp = fd_wksp_new_anonymous( FD_SHMEM_GIGANTIC_PAGE_SZ, 15, 0, "wksp", 0UL );
  if ( FD_UNLIKELY( NULL == suite->wksp ) )
    FD_LOG_ERR(( "failed to create an anonymous local workspace" ));

  void* shmem = fd_wksp_alloc_laddr( suite->wksp, fd_funk_align(), fd_funk_footprint(), 1 );
  if ( FD_UNLIKELY( NULL == shmem ) )
    FD_LOG_ERR(( "failed to allocate a funky" ));
  ulong index_max = 1000000;   // Maximum size (count) of master index
  ulong xactions_max = 100;   // Maximum size (count) of transaction index
  char  hostname[64];
  gethostname(hostname, sizeof(hostname));
  ulong hashseed = fd_hash(0, hostname, strnlen(hostname, sizeof(hostname)));
  suite->funk = fd_funk_join(fd_funk_new(shmem, 1, hashseed, xactions_max, index_max));
  if ( FD_UNLIKELY( !suite->funk ) ) {
    fd_wksp_free_laddr(shmem);
    FD_LOG_ERR(( "failed to allocate a funky" ));
  }

  /* Set up allocators */
  fd_alloc_fun_t allocf = (fd_alloc_fun_t)fd_alloc_malloc;
  void*          allocf_args = fd_wksp_laddr_fast( suite->wksp, suite->funk->alloc_gaddr );
  fd_free_fun_t  freef = (fd_free_fun_t)fd_alloc_free;

  suite->allocf = allocf;
  suite->allocf_arg = allocf_args;
  suite->freef = freef;

  memset(&suite->features, 1, sizeof(suite->features));
}

int fd_executor_run_test(
  fd_executor_test_t*       test,
  fd_executor_test_suite_t* suite) {

  /* Create a new global context to execute this test in */
  uchar* global_mem = (uchar*)fd_alloca_check( FD_GLOBAL_CTX_ALIGN, FD_GLOBAL_CTX_FOOTPRINT );
  fd_memset( global_mem, 0, FD_GLOBAL_CTX_FOOTPRINT );
  fd_global_ctx_t* global = fd_global_ctx_join( fd_global_ctx_new( global_mem ) );
  if ( FD_UNLIKELY( NULL == global ) ) {
    FD_LOG_ERR(( "failed to join a global context" ));
  }

  global->allocf = suite->allocf;
  global->allocf_arg = suite->allocf_arg;
  global->freef = suite->freef;
  global->funk = suite->funk;
  global->wksp = suite->wksp;

  memcpy(&global->features, &suite->features, sizeof(suite->features));
  if (test->disable_cnt > 0) {
    for (uint i = 0; i < test->disable_cnt; i++)
      ((uchar *) &global->features)[test->disable_feature[i]] = 0;
  }

  char *acc_mgr_mem = fd_alloca_check(FD_ACC_MGR_ALIGN, FD_ACC_MGR_FOOTPRINT);
  memset(acc_mgr_mem, 0, sizeof(FD_ACC_MGR_FOOTPRINT));
  global->acc_mgr = fd_acc_mgr_join( fd_acc_mgr_new( acc_mgr_mem, global, FD_ACC_MGR_FOOTPRINT ) );

  /* Prepare a new Funk transaction to execute this test in */
  fd_funk_txn_xid_t xid;
  fd_funk_txn_xid_set_unique( &xid );
  global->funk_txn = fd_funk_txn_prepare( global->funk, NULL, &xid, 0 );
  if ( NULL == global->funk_txn ) {
    FD_LOG_ERR(( "failed to prepare funk transaction" ));
  }

  /* Insert all the accounts into the database */
  for ( ulong i = 0; i < test->accs_len; i++ ) {
    if ((test->accs[ i ].lamports == 0) && (test->accs[ i ].data_len == 0) && memcmp(global->solana_system_program, test->accs[i].owner.hash, 32 ) == 0)
      continue;
    fd_solana_account_t acc = {
      .data = (uchar*) test->accs[ i ].data,
      .data_len = test->accs[ i ].data_len,
      .executable = test->accs[ i ].executable,
      .lamports = test->accs[ i ].lamports,
      .owner = test->accs[ i ].owner,
      .rent_epoch = test->accs[ i ].rent_epoch,
    };
    fd_acc_mgr_write_structured_account( global->acc_mgr, global->funk_txn, global->bank.solana_bank.slot, &test->accs[i].pubkey, &acc);

    if (memcmp(&global->sysvar_recent_block_hashes, &test->accs[i].pubkey, sizeof(test->accs[i].pubkey)) == 0) {
      fd_recent_block_hashes_new( &global->bank.recent_block_hashes );
      fd_bincode_decode_ctx_t ctx2;
      ctx2.data = acc.data,
      ctx2.dataend = acc.data + acc.data_len;
      ctx2.allocf = global->allocf;
      ctx2.allocf_arg = global->allocf_arg;
      if ( fd_recent_block_hashes_decode( &global->bank.recent_block_hashes, &ctx2 ) ) {
        FD_LOG_WARNING(("fd_recent_block_hashes_decode failed"));
        return FD_EXECUTOR_INSTR_ERR_INVALID_ACC_DATA;
      }
    }
  }

  /* Parse the raw transaction */

  uchar txn_parse_out_buf[FD_TXN_MAX_SZ];
  ulong txn_sz = fd_txn_parse_core( test->raw_tx, test->raw_tx_len, txn_parse_out_buf, NULL, NULL, 1 );
  if ( txn_sz == 0 || txn_sz > FD_TXN_MAX_SZ ) {
    FD_LOG_WARNING(("Failed test %d: %s: failed to parse transaction", test->test_number,test->test_name));
    fd_funk_txn_cancel( suite->funk, global->funk_txn, 0 );
    return -1;
  }

  fd_txn_t*       txn_descriptor = (fd_txn_t*)txn_parse_out_buf;
  fd_txn_instr_t* instr    = &txn_descriptor->instr[0];

  /* Execute the transaction and check the result */
  fd_rawtxn_b_t              raw_txn_b = {
    .raw    = (void*)test->raw_tx,
    .txn_sz = (ushort)test->raw_tx_len,
  };
  transaction_ctx_t          txn_ctx = {
    .global         = global,
    .txn_descriptor = txn_descriptor,
    .txn_raw        = &raw_txn_b,
  };

  instruction_ctx_t          ctx = {
    .global         = global,
    .instr          = instr,
    .txn_ctx        = &txn_ctx,
  };
  execute_instruction_func_t exec_instr_func = fd_executor_lookup_native_program( global, &test->program_id );
  int exec_result = exec_instr_func( ctx );
  if ( exec_result != test->expected_result ) {
    FD_LOG_WARNING(( "Failed test %d: %s (nonce: %d): expected transaction result %d, got %d", test->test_number, test->test_name, test->test_nonce, test->expected_result , exec_result));
    return -1;
  }

  if ( exec_result == FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR ) {
    if ( ctx.txn_ctx->custom_err != test->custom_err) {
      FD_LOG_WARNING(( "Failed test %d: %s (nonce: %d): expected custom error inner value of %d, got %d", test->test_number, test->test_name, test->test_nonce, test->custom_err, ctx.txn_ctx->custom_err ));
      return -1;
    }
  }

  if (FD_EXECUTOR_INSTR_SUCCESS == exec_result) {
    /* Confirm account updates */
    for ( ulong i = 0; i < test->accs_len; i++ ) {
      ulong sz = 0;
      int err = 0;
      char * raw_acc_data = (char*) fd_acc_mgr_view_data(ctx.global->acc_mgr, ctx.global->funk_txn, (fd_pubkey_t *) &test->accs[i].pubkey, &sz, &err);
      if (NULL == raw_acc_data) {
        if ((test->accs[ i ].lamports == 0) && (test->accs[ i ].data_len == 0))
          continue;
        FD_LOG_WARNING(( "bad dog.. no donut..  Ask josh to take a look at this"));
        return err;
      }
      fd_account_meta_t *m = (fd_account_meta_t *) raw_acc_data;
      void* d = (void *)(raw_acc_data + m->hlen);

      if (m->info.lamports != test->accs[i].result_lamports) {
        FD_LOG_WARNING(( "Failed test %d: %s (nonce: %d): expected lamports %ld, got %ld", test->test_number, test->test_name, test->test_nonce, test->accs[i].result_lamports, m->info.lamports));
        return -666;
      }
      if (m->dlen != test->accs[i].result_data_len) {
        FD_LOG_WARNING(( "Failed test %d: %s (nonce: %d): size mismatch (expected %lu, got %lu)",
                         test->test_number, test->test_name, test->test_nonce,
                         test->accs[i].result_data_len, m->dlen ));
        return -777;
      }
      if (memcmp(d, test->accs[i].result_data, test->accs[i].result_data_len)) {
        FD_LOG_WARNING(( "Failed test %d: %s: account missmatch", test->test_number, test->test_name));
      {
        FILE * fd = fopen("actual.bin", "wb");
        fwrite(d, 1, m->dlen, fd);
        fclose(fd);
      }
      {
        FILE * fd = fopen("expected.bin", "wb");
        fwrite(test->accs[i].result_data, 1, test->accs[i].result_data_len, fd);
        fclose(fd);
      }
        return -888;
      }
    }
  }

  /* Revert the Funk transaction */
  fd_funk_txn_cancel( suite->funk, global->funk_txn, 0 );

  FD_LOG_NOTICE(("Passed test %d: %s (nonce: %d)", test->test_number, test->test_name, test->test_nonce));

  return 0;
}

extern int run_test(int idx, fd_executor_test_suite_t *suite);

int main(int argc, char **argv) {
  fd_boot( &argc, &argv );

  long test_start = fd_env_strip_cmdline_long(&argc, &argv, "--start", NULL, 0);
  long test_end = fd_env_strip_cmdline_long(&argc, &argv, "--end", NULL, 1777);
  long do_test = fd_env_strip_cmdline_long(&argc, &argv, "--test", NULL, -1);
  const char * filter = fd_env_strip_cmdline_cstr(&argc, &argv, "--filter", NULL, NULL);
  const char * net = fd_env_strip_cmdline_cstr(&argc, &argv, "--net", NULL, NULL);

  if (-1 != do_test)
    test_start = test_end = do_test;

  /* Initialize the test suite */
  fd_executor_test_suite_t suite;
  fd_executor_test_suite_new( &suite );

  if (NULL != net)  {
    if (!strncmp(net, "main", 4))
      enable_mainnet(&suite.features);
    else if (!strncmp(net, "test", 4))
      enable_testnet(&suite.features);
    else if (!strncmp(net, "dev", 3))
      enable_devnet(&suite.features);
  } else
    memset(&suite.features, 1, sizeof(suite.features));

  if (NULL != filter) {
    suite.filter = filter;
    if (regcomp(&suite.filter_ex, filter, REG_EXTENDED | REG_ICASE) !=0 ) {
      FD_LOG_ERR(("regular expression failed to compile"));
    }
  } else
    suite.filter = NULL;

  int ret = 0;
  for (long i = test_start; i <= test_end; i++)  {
    int r = run_test((int)i, &suite);
    if ((r != 0) && (r != -9999)) {
      FD_LOG_NOTICE( ("test %ld returned %d", i, r)) ;
      ret = r;
    }
  }

  fd_log_flush();
  fd_halt();

  return ret;
}

int
fd_executor_test_suite_check_filter(fd_executor_test_suite_t *suite, fd_executor_test_t *test) {
  if (NULL != suite->filter)
    return regexec(&suite->filter_ex, test->test_name, 0, NULL, 0);
  return 0;
}
