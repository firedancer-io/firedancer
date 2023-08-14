#include "fd_tests.h"
#include "../sysvar/fd_sysvar.h"
#include "../../../ballet/base58/fd_base58.h"
#include "../../fd_flamenco.h"
#include <stdio.h>
#include <unistd.h>
#include "../../types/fd_types_yaml.h"

#ifdef _DISABLE_OPTIMIZATION
#pragma GCC optimize ("O0")
#endif

const char *verbose = NULL;
const char *fail_fast = NULL;

static ulong scratch_mb = 0UL;

uchar do_leakcheck = 0;
const char * do_dump = NULL;

int fd_alloc_fprintf( fd_alloc_t * join, FILE *       stream );


static int
fd_account_pretty_print( fd_global_ctx_t const * global,
                         uchar const             owner[ static 32 ],
                         uchar const *           data,
                         ulong                   data_sz,
                         FILE *                  file ) {

  FD_SCRATCH_SCOPED_FRAME;

  fd_bincode_decode_ctx_t decode = {
    .data    = data,
    .dataend = data + data_sz,
    .valloc  = fd_scratch_virtual()
  };

  fd_flamenco_yaml_t * yaml =
    fd_flamenco_yaml_init( fd_flamenco_yaml_new(
      fd_scratch_alloc( fd_flamenco_yaml_align(), fd_flamenco_yaml_footprint() ) ),
      file );
  FD_TEST( yaml );

  if( 0==memcmp( owner, global->solana_vote_program, 32UL ) ) {
    fd_vote_state_versioned_t vote_state[1];
    int err = fd_vote_state_versioned_decode( vote_state, &decode );
    if( FD_UNLIKELY( err!=0 ) ) return err;

    fd_vote_state_versioned_walk( yaml, vote_state, fd_flamenco_yaml_walk, NULL, 0U );
    err = ferror( file );
    if( FD_UNLIKELY( err!=0 ) ) return err;
  } else {
    fwrite( "???", 1, 3, file );
  }

  /* No need to destroy structures, using fd_scratch allocator */

  fd_flamenco_yaml_delete( yaml );
  return 0;
}

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
  memset(suite, 0, sizeof(*suite));

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

  /* Create scratch allocator */

  ulong  smax = scratch_mb << 20;
  void * smem = fd_wksp_alloc_laddr( suite->wksp, fd_scratch_smem_align(), smax, 1UL );
  if( FD_UNLIKELY( !smem ) ) FD_LOG_ERR(( "Failed to alloc scratch mem" ));

# define SCRATCH_DEPTH (4UL)
  static ulong fmem[ SCRATCH_DEPTH ] __attribute((aligned(FD_SCRATCH_FMEM_ALIGN)));

  fd_scratch_attach( smem, fmem, smax, SCRATCH_DEPTH );

  /* Set up allocators */
  if (do_leakcheck) {
    suite->valloc = fd_libc_alloc_virtual();
  } else {
    fd_alloc_t * alloc = fd_alloc_join( fd_wksp_laddr_fast( suite->wksp, suite->funk->alloc_gaddr ), 0UL );
    FD_TEST( alloc );
    suite->valloc = fd_alloc_virtual( alloc );
  }

  fd_features_enable_v17(&suite->features);
}

int fd_executor_run_test(
  fd_executor_test_t*       test,
  fd_executor_test_suite_t* suite) {

  /* Create a new global context to execute this test in */
  uchar* global_mem = (uchar*)fd_alloca_check( FD_GLOBAL_CTX_ALIGN, FD_GLOBAL_CTX_FOOTPRINT );
  fd_memset( global_mem, 0, FD_GLOBAL_CTX_FOOTPRINT );
  fd_global_ctx_t* global = fd_global_ctx_join( fd_global_ctx_new( global_mem ) );
  if ( FD_UNLIKELY( NULL == global ) )
    FD_LOG_ERR(( "failed to join a global context" ));

  fd_firedancer_banks_new(&global->bank);

  int ret = 0;
  global->valloc     = suite->valloc;
  global->funk       = suite->funk;
  global->funk_wksp  = suite->wksp;
  global->local_wksp = suite->wksp;

  global->bank.rent.lamports_per_uint8_year = 3480;
  global->bank.rent.exemption_threshold = 2;
  global->bank.rent.burn_percent = 50;

  memcpy(&global->features, &suite->features, sizeof(suite->features));
  if (test->disable_cnt > 0) {
    for (uint i = 0; i < test->disable_cnt; i++)
      ((ulong *) fd_type_pun( &global->features ))[test->disable_feature[i]] = 0;
  }

  char *acc_mgr_mem = fd_alloca_check(FD_ACC_MGR_ALIGN, FD_ACC_MGR_FOOTPRINT);
  memset(acc_mgr_mem, 0, sizeof(FD_ACC_MGR_FOOTPRINT));
  global->acc_mgr = (fd_acc_mgr_t*)( fd_acc_mgr_new( acc_mgr_mem, global, FD_ACC_MGR_FOOTPRINT ) );

  /* Prepare a new Funk transaction to execute this test in */
  fd_funk_txn_xid_t xid;
  fd_funk_txn_xid_set_unique( &xid );
  global->funk_txn = fd_funk_txn_prepare( global->funk, NULL, &xid, 1 );
  if ( NULL == global->funk_txn )
    FD_LOG_ERR(( "failed to prepare funk transaction" ));
  // TODO: nasty hack to prevent clock overwrite for
  // 1 particular test: test_redelegate_consider_balance_changes
  int num_clock = 0;
  do {
    /* Insert all the accounts into the database */
    for ( ulong i = 0; i < test->accs_len; i++ ) {
      if ((test->accs[ i ].lamports == 0) && (test->accs[ i ].data_len == 0) && memcmp(global->solana_system_program, test->accs[i].owner.hash, 32 ) == 0)
        continue;
      if (memcmp(&test->accs[i].pubkey, global->sysvar_clock, sizeof(fd_pubkey_t)) == 0) {
        num_clock++;
      }
      fd_solana_account_t acc = {
        .data = (uchar*) test->accs[ i ].data,
        .data_len = test->accs[ i ].data_len,
        .executable = test->accs[ i ].executable,
        .lamports = test->accs[ i ].lamports,
        .owner = test->accs[ i ].owner,
        .rent_epoch = test->accs[ i ].rent_epoch,
      };
      if (fd_acc_mgr_write_structured_account( global->acc_mgr, global->funk_txn, global->bank.slot, &test->accs[i].pubkey, &acc) !=0) {
        FD_LOG_ERR(("Error writing test account"));
      }

      if (memcmp(&global->sysvar_recent_block_hashes, &test->accs[i].pubkey, sizeof(test->accs[i].pubkey)) == 0) {
        fd_recent_block_hashes_new( &global->bank.recent_block_hashes );
        fd_bincode_decode_ctx_t ctx2;
        ctx2.data = acc.data,
        ctx2.dataend = acc.data + acc.data_len;
        ctx2.valloc  = global->valloc;
        if ( fd_recent_block_hashes_decode( &global->bank.recent_block_hashes, &ctx2 ) ) {
          FD_LOG_WARNING(("fd_recent_block_hashes_decode failed"));
          ret = FD_EXECUTOR_INSTR_ERR_INVALID_ACC_DATA;
          goto fd_executor_run_cleanup;
        }
      }
    }

    global->bank.slot = 200880004;

    // // TODO: are these required now?
    // if ( strcmp(test->sysvar_cache.clock, "") ) {
    //   fd_sol_sysvar_clock_t clk;
    //   ulong          sz = fd_sol_sysvar_clock_size( &clk );

    //   uchar decoded[64];
    //   fd_base58_decode_64(test->sysvar_cache.clock, decoded);
    //   ulong arr[64 / sizeof(ulong)];
    //   memcpy(arr, decoded, sizeof(decoded));
    //   for (ulong i = 0; i < sizeof(ulong) / 2; i++) {
    //     ulong t = arr[i];
    //     arr[i] = arr[sizeof(ulong) - 1 - i];
    //     arr[sizeof(ulong) - 1 - i] = t;
    //   }
    //   unsigned char *enc = fd_alloca( 1, sz );
    //   memcpy( enc, arr, sz );
    //   fd_sysvar_set_override(global, global->sysvar_owner, (fd_pubkey_t*)global->sysvar_clock, enc, sz, global->bank.slot);

    // }

    /* Parse the raw transaction */

    uchar txn_parse_out_buf[FD_TXN_MAX_SZ];
    ulong txn_sz = fd_txn_parse_core( test->raw_tx, test->raw_tx_len, txn_parse_out_buf, NULL, NULL, 1 );
    if ( txn_sz == 0 || txn_sz > FD_TXN_MAX_SZ ) {
      FD_LOG_WARNING(("Failed test %d: %s: failed to parse transaction", test->test_number,test->test_name));
      ret = -1;
      break;
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
    if (ctx.txn_ctx->txn_descriptor->acct_addr_cnt == test->accs_len + 1) {
      ctx.txn_ctx->txn_descriptor->acct_addr_cnt = (ushort)test->accs_len;
    }

    execute_instruction_func_t exec_instr_func = fd_executor_lookup_native_program( global, &test->program_id );
    if (NULL == exec_instr_func) {
      char buf[50];
      fd_base58_encode_32((uchar *) &test->program_id, NULL, buf);

      FD_LOG_WARNING(( "Failed test %d: %s: fd_executor_lookup_native_program failed: %s", test->test_number, test->test_name, buf));
      ret = -1;
      break;
    }
    int exec_result = exec_instr_func( ctx );
    if ( exec_result != test->expected_result ) {
      FD_LOG_WARNING(( "Failed test %d: %s: expected transaction result %d, got %d: %s", test->test_number, test->test_name, test->expected_result , exec_result
                       , (NULL != verbose) ? test->bt : ""));
      ret = -1;
      break;
    }

    if ( exec_result == FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR ) {
      if ( ctx.txn_ctx->custom_err != test->custom_err) {
        FD_LOG_WARNING(( "Failed test %d: %s: expected custom error inner value of %d, got %d: %s", test->test_number, test->test_name, test->custom_err, ctx.txn_ctx->custom_err , (NULL != verbose) ? test->bt : ""));
        ret = -1;
        break;
      }
    }

    if (FD_EXECUTOR_INSTR_SUCCESS == exec_result) {
      /* Confirm account updates */
      for ( ulong i = 0; i < test->accs_len; i++ ) {
        int    err = 0;
        char * raw_acc_data = (char*) fd_acc_mgr_view_data(ctx.global->acc_mgr, ctx.global->funk_txn, (fd_pubkey_t *) &test->accs[i].pubkey, NULL, &err);
        if (NULL == raw_acc_data) {
          if ((test->accs[ i ].lamports == 0) && (test->accs[ i ].data_len == 0))
            continue;
          FD_LOG_WARNING(( "bad dog.. no donut..  Ask josh to take a look at this"));
          ret = err;
          break;
        }
        if (memcmp(&test->accs[i].pubkey, global->sysvar_clock, sizeof(fd_pubkey_t)) == 0) {
          if (--num_clock) {
            continue;
          }
        }
        fd_account_meta_t *m = (fd_account_meta_t *) raw_acc_data;
        void*              d = (void *)(raw_acc_data + m->hlen);

        if (m->info.lamports != test->accs[i].result_lamports) {
          FD_LOG_WARNING(( "Failed test %d: %s: expected lamports %ld, got %ld: %s", test->test_number, test->test_name, test->accs[i].result_lamports, m->info.lamports, (NULL != verbose) ? test->bt : ""));
          ret = -666;
          break;
        }
        if (m->info.executable != test->accs[i].result_executable) {
          FD_LOG_WARNING(( "Failed test %d: %s: expected executable %u, got %u: %s", test->test_number, test->test_name, test->accs[i].result_executable, m->info.executable, (NULL != verbose) ? test->bt : ""));
          ret = -667;
          break;
        }
        if (m->info.rent_epoch != test->accs[i].result_rent_epoch) {
          FD_LOG_WARNING(( "Failed test %d: %s: expected rent_epoch %ld, got %ld: %s", test->test_number, test->test_name, test->accs[i].result_rent_epoch, m->info.rent_epoch, (NULL != verbose) ? test->bt : ""));
          ret = -668;
          break;
        }
        if (memcmp(&m->info.owner, &test->accs[i].result_owner, sizeof(fd_pubkey_t)) != 0) {
          FD_LOG_WARNING(( "Failed test %d: %s: owner missmatch: %s", test->test_number, test->test_name,  (NULL != verbose) ? test->bt : ""));
          ret = -668;
          break;
        }

        if(   ( m->dlen != test->accs[i].result_data_len )
           || ( 0 != memcmp(d, test->accs[i].result_data, test->accs[i].result_data_len) ) ) {

          FD_LOG_WARNING(( "Failed test %d: %s: account_index: %d   account missmatch: %s", test->test_number, test->test_name, i, (NULL != verbose) ? test->bt : ""));

          if (do_dump) {
            /* Dump expected account bin */
            do {
              char buf[ PATH_MAX ];
              snprintf( buf, PATH_MAX, "test_%lu_account_%32J_expected.bin", test->test_number, test->accs[i].pubkey.key );
              FILE * file = fopen( buf, "wb" );
              if (NULL != file) {
                FD_TEST( test->accs[i].result_data_len
                  == fwrite( test->accs[i].result_data, 1, test->accs[i].result_data_len, file ) );
                fclose( file );
              }
            } while(0);

            /* Dump actual account bin */
            do {
              char buf[ PATH_MAX ];
              snprintf( buf, PATH_MAX, "test_%lu_account_%32J_actual.bin", test->test_number, test->accs[i].pubkey.key );
              FILE * file = fopen( buf, "wb" );
              if (NULL != file) {
                FD_TEST( m->dlen
                  == fwrite( d, 1, m->dlen, file ) );
                fclose( file );
              }
            } while(0);

            /* Dump YAML serialization of expected account */
            do {
              char buf[ PATH_MAX ];
              snprintf( buf, PATH_MAX, "test_%lu_account_%32J_expected.yml", test->test_number, test->accs[i].pubkey.key );
              FILE * file = fopen( buf, "wb" );
              if (NULL != file) {

                fd_scratch_push();
                fd_flamenco_yaml_t * yaml =
                  fd_flamenco_yaml_init( fd_flamenco_yaml_new(
                      fd_scratch_alloc( fd_flamenco_yaml_align(), fd_flamenco_yaml_footprint() ) ),
                    file );
                FD_TEST( yaml );
                fd_account_pretty_print( global, test->accs[i].owner.key, test->accs[i].result_data, test->accs[i].result_data_len, file );
                fd_scratch_pop();

                fclose( file );
              }
            } while(0);

            /* Dump YAML serialization of actual account */
            do {
              char buf[ PATH_MAX ];
              snprintf( buf, PATH_MAX, "test_%lu_account_%32J_actual.yml", test->test_number, test->accs[i].pubkey.key );
              FILE * file = fopen( buf, "wb" );
              if (NULL != file) {

                fd_scratch_push();
                fd_flamenco_yaml_t * yaml =
                  fd_flamenco_yaml_init( fd_flamenco_yaml_new(
                      fd_scratch_alloc( fd_flamenco_yaml_align(), fd_flamenco_yaml_footprint() ) ),
                    file );
                FD_TEST( yaml );
                fd_account_pretty_print( global, test->accs[i].owner.key, d, m->dlen, file );
                fd_scratch_pop();

                fclose( file );
              }
            } while(0);

            /* Print instructions on how to diff */
            FD_LOG_WARNING(( "HEX DIFF:\n  vimdiff <(xxd -c 32 test_%lu_account_%32J_expected.bin) <(xxd -c 32 test_%lu_account_%32J_actual.bin)",
                test->test_number, test->accs[i].pubkey.key, test->test_number, test->accs[i].pubkey.key ));

            /* Print instructions on how to diff */
            FD_LOG_WARNING(( "YAML DIFF:\n  vimdiff test_%lu_account_%32J_expected.yml test_%lu_account_%32J_actual.yml",
                test->test_number, test->accs[i].pubkey.key, test->test_number, test->accs[i].pubkey.key ));

          }

          ret = -777;
          break;
        }
      }
    }

    if (ret != FD_EXECUTOR_INSTR_SUCCESS) {
      break;
    }
    if (NULL == fail_fast)
      FD_LOG_NOTICE(("Passed test %d: %s", test->test_number, test->test_name));
  } while (false);

  /* Revert the Funk transaction */
fd_executor_run_cleanup:
  fd_funk_txn_cancel( suite->funk, global->funk_txn, 0 );
  fd_bincode_destroy_ctx_t destroy_ctx = { .valloc = global->valloc };
  fd_firedancer_banks_destroy(&global->bank, &destroy_ctx);
  return ret;
}

int
main( int     argc,
      char ** argv ) {
  fd_boot         ( &argc, &argv );
  fd_flamenco_boot( &argc, &argv );

  ulong        test_start       = fd_env_strip_cmdline_ulong( &argc, &argv, "--start",            NULL, 0UL       );
  ulong        test_end         = fd_env_strip_cmdline_ulong( &argc, &argv, "--end",              NULL, ULONG_MAX );
  long         do_test          = fd_env_strip_cmdline_long ( &argc, &argv, "--test",             NULL, -1        );
  char const * filter           = fd_env_strip_cmdline_cstr ( &argc, &argv, "--filter",           NULL, NULL      );
               verbose          = fd_env_strip_cmdline_cstr ( &argc, &argv, "--verbose",          NULL, NULL      );
               fail_fast        = fd_env_strip_cmdline_cstr ( &argc, &argv, "--fail_fast",        NULL, NULL      );
               do_dump          = fd_env_strip_cmdline_cstr ( &argc, &argv, "--do_dump",          NULL, NULL      );
  char *       ignore_fail      = (char *)fd_env_strip_cmdline_cstr ( &argc, &argv, "--ignore_fail",      NULL, NULL      ); /* UGLY!!! */
  char const * ignore_fail_file = fd_env_strip_cmdline_cstr ( &argc, &argv, "--ignore_fail_file", NULL, NULL      );
               scratch_mb       = fd_env_strip_cmdline_ulong( &argc, &argv, "--scratch-mb",       NULL, 1024      );

  if (-1 != do_test)
    test_start = test_end = (ulong)do_test;

  /* Initialize the test suite */
  fd_executor_test_suite_t suite;
  fd_executor_test_suite_new( &suite );

  if (NULL != ignore_fail_file) {
    FILE *fp = fopen(ignore_fail_file, "r");
    if (NULL != fp) {
      char buf[255];
      while (NULL != fgets(buf, sizeof(buf), fp)) {
        ulong i = (ulong) atoi(buf);
        if (i < (sizeof(suite.ignore_fail) / sizeof(suite.ignore_fail[0])))
          suite.ignore_fail[i] = 1;
      }
      fclose(fp);
    }
  }

  if (NULL != ignore_fail) {
    char *tok = strtok(ignore_fail, " ,");
    while (NULL != tok) {
      ulong i = (ulong) atoi(tok);
      if (i < (sizeof(suite.ignore_fail) / sizeof(suite.ignore_fail[0])))
        suite.ignore_fail[i] = 1;
      tok = strtok(NULL, " ,");
    }
  }

  fd_features_enable_all(&suite.features);

  if (NULL != filter) {
    suite.filter = filter;
    if (regcomp(&suite.filter_ex, filter, REG_EXTENDED | REG_ICASE) !=0 ) {
      FD_LOG_ERR(("regular expression failed to compile"));
    }
  } else
    suite.filter = NULL;

  int ret = 0;

  /* Loop through tests */
  ulong executed_cnt = 0UL;
  ulong success_cnt = 0UL;
  ulong ignored_cnt = 0UL;
  for( ulong idx = test_start; idx <= test_end; idx++ ) {
    if( FD_UNLIKELY( idx >= test_cnt ) )
      break;
    int r = tests[ idx ]( &suite );
    if ((r != 0) && (r != -9999)) {
      if (suite.ignore_fail[idx])
        ignored_cnt++;
      else {
        ret = r;
        if (NULL != fail_fast)
          break;
      }
    }
    if( r != -9999 ) {
      executed_cnt++;
      if( r == 0 ) success_cnt++;
    }
  }

  FD_LOG_NOTICE(( "Progress: %lu/%lu tests (%lu tests failed but ignored)", success_cnt, executed_cnt, ignored_cnt ));

  if (NULL != filter)
    regfree(&suite.filter_ex);

  /* Free test suite */
  fd_wksp_free_laddr( fd_scratch_detach( NULL ) );

  fd_log_flush();
  fd_flamenco_halt();
  fd_halt();
  return ret;
}

int
fd_executor_test_suite_check_filter(fd_executor_test_suite_t *suite, fd_executor_test_t *test) {
  if (NULL != suite->filter)
    return regexec(&suite->filter_ex, test->test_name, 0, NULL, 0);
  return 0;
}
