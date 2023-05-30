#include "fd_tests.h"
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
    if (test->accs[ i ].lamports == 0)
      continue;
    fd_solana_account_t acc = {
      .data = test->accs[ i ].data,
      .data_len = test->accs[ i ].data_len,
      .executable = test->accs[ i ].executable,
      .lamports = test->accs[ i ].lamports,
      .owner = test->accs[ i ].owner,
      .rent_epoch = test->accs[ i ].rent_epoch,
    };
    fd_acc_mgr_write_structured_account( global->acc_mgr, global->funk_txn, global->bank.solana_bank.slot, &test->accs[i].pubkey, &acc);
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
  instruction_ctx_t          ctx = {
    .global         = global,
    .instr          = instr,
    .txn_descriptor = txn_descriptor,
    .txn_raw        = &raw_txn_b,
  };
  execute_instruction_func_t exec_instr_func = fd_executor_lookup_native_program( global, &test->program_id );
  int exec_result = exec_instr_func( ctx );
  if ( exec_result != test->expected_result ) {
    FD_LOG_WARNING(( "Failed test %d: %s: expected transaction result %d, got %d", test->test_number, test->test_name, test->expected_result , exec_result));
    return -1;
  }

  /* Revert the Funk transaction */
  fd_funk_txn_cancel( suite->funk, global->funk_txn, 0 );

  FD_LOG_WARNING(("Passed test %d: %s", test->test_number, test->test_name));

  return 0;
}

extern int run_test(int idx, fd_executor_test_suite_t *suite);

int main(int argc, char **argv) {
  fd_boot( &argc, &argv );

  long test_start = fd_env_strip_cmdline_long(&argc, &argv, "--start", NULL, 0);
  long test_end = fd_env_strip_cmdline_long(&argc, &argv, "--end", NULL, 373);
  long do_test = fd_env_strip_cmdline_long(&argc, &argv, "--test", NULL, -1);
  const char * filter = fd_env_strip_cmdline_cstr(&argc, &argv, "--filter", NULL, NULL);

  if (-1 != do_test) 
    test_start = test_end = do_test;

  /* Initialize the test suite */
  fd_executor_test_suite_t suite;
  fd_executor_test_suite_new( &suite );

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

  FD_LOG_NOTICE( ("all done" ));

  return ret;
}

int 
fd_executor_test_suite_check_filter(fd_executor_test_suite_t *suite, fd_executor_test_t *test) {
  if (NULL != suite->filter)
    return regexec(&suite->filter_ex, test->test_name, 0, NULL, 0);
  return 0;
}
