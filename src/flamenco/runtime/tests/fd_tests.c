#include "fd_tests.h"
#include "../sysvar/fd_sysvar.h"
#include "../../../ballet/base58/fd_base58.h"
#include "../../../ballet/base64/fd_base64.h"
#include "../../fd_flamenco.h"
#include <errno.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <signal.h>
#include "../../types/fd_types_yaml.h"
#include "../fd_system_ids.h"
#include "../fd_blockstore.h"
#include "../program/fd_bpf_program_util.h"

const char *verbose = NULL;
const char *fail_fast = NULL;

static ulong scratch_mb = 0UL;
long fail_before = -1;

uchar do_leakcheck = 0;
const char * do_dump = NULL;

int fd_alloc_fprintf( fd_alloc_t * join, FILE *       stream );


static int
fd_account_pretty_print( uchar const             owner[ static 32 ],
                         uchar const *           data,
                         ulong                   data_sz,
  FILE *                  file ) {

  FD_SCRATCH_SCOPE_BEGIN {

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

    if( 0==memcmp( owner, fd_solana_vote_program_id.key, sizeof(fd_pubkey_t) ) ) {
      fd_vote_state_versioned_t vote_state[1];
      int err = fd_vote_state_versioned_decode( vote_state, &decode );
      if( FD_UNLIKELY( err!=0 ) ) return err;
      fd_vote_state_versioned_walk( yaml, vote_state, fd_flamenco_yaml_walk, NULL, 0U );
    } else if( 0==memcmp( owner, fd_solana_bpf_loader_upgradeable_program_id.key, sizeof(fd_pubkey_t) ) ) {
      fd_bpf_upgradeable_loader_state_t stake_state[1];
      int err = fd_bpf_upgradeable_loader_state_decode( stake_state, &decode );
      if( FD_UNLIKELY( err!=0 ) ) return err;
      fd_bpf_upgradeable_loader_state_walk( yaml, stake_state, fd_flamenco_yaml_walk, NULL, 0U );
    } else if( 0==memcmp( owner, fd_solana_stake_program_id.key, sizeof(fd_pubkey_t) ) ) {
      fd_stake_state_v2_t stake_state[1];
      int err = fd_stake_state_v2_decode( stake_state, &decode );
      if( FD_UNLIKELY( err!=0 ) ) return err;
      fd_stake_state_v2_walk( yaml, stake_state, fd_flamenco_yaml_walk, NULL, 0U );
    } else {
      fwrite( "???", 1, 3, file );
    }
    int err = ferror( file );
    if( FD_UNLIKELY( err!=0 ) ) return err;

    /* No need to destroy structures, using fd_scratch allocator */

    fd_flamenco_yaml_delete( yaml );
  } FD_SCRATCH_SCOPE_END;
  return 0;
}

/* copied from test_funk_txn.c */
static fd_funk_txn_xid_t *
fd_funk_txn_xid_set_unique( fd_funk_txn_xid_t * xid ) {
  static FD_TL ulong tag = 0UL;
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

  shmem = fd_wksp_alloc_laddr(
    suite->wksp, fd_blockstore_align(), fd_blockstore_footprint(), FD_BLOCKSTORE_MAGIC );
  if( shmem == NULL )
    FD_LOG_ERR( ( "failed to allocate a blockstore" ) );
  ulong tmp_shred_max = 1UL << 15;
  int   lg_txn_max    = 10;
  ulong slot_history_max = 10;
  suite->blockstore      = fd_blockstore_join(fd_blockstore_new( shmem, 1, hashseed, tmp_shred_max, slot_history_max, lg_txn_max ) );
  if( suite->blockstore == NULL ) {
    fd_wksp_free_laddr( shmem );
    FD_LOG_ERR( ( "failed to allocate a blockstore" ) );
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

  fd_features_enable_all( &suite->features );
}

static void
log_test_fail( fd_executor_test_t *             test,
               fd_executor_test_suite_t const * suite,
               char const *                     fmt,
               ... ) {
  static FD_TL char buf[ 0x2000 ];
  va_list ap;
  va_start( ap, fmt );
  vsnprintf( buf, sizeof(buf), fmt, ap );
  va_end( ap );
  if( suite->ignore_fail[ test->test_number ] ) {
    FD_LOG_NOTICE(( "Failed test %d (%s) (ignored): %s", test->test_number, test->test_name, buf ));
  } else {
    FD_LOG_WARNING(( "Failed test %d (%s) (not_ignored): %s", test->test_number, test->test_name, buf ));
    if (NULL != fail_fast) {
      // There must be a better way of doing this...
      int in_gdb = 0;
      FILE *fp = fopen("/proc/self/status", "r");
      if (NULL != fp) {
        char buf[255];
        while (NULL != fgets(buf, sizeof(buf), fp)) {
          char *p = strtok(buf, ":");
          if (NULL == p) continue;
          if (strcmp(p, "TracerPid") == 0) {
            p = strtok(NULL, ":");
            if (strlen(p) != 3 && p[1] != '0')
              in_gdb = 1;
            break;
          }
        }
        fclose(fp);
      }
      if (in_gdb)
        kill(getpid(), SIGTRAP);
    }
  }
}

static void
load_sysvar_cache( fd_exec_slot_ctx_t * slot_ctx,
                   uchar const       pubkey[ static 32 ],
                   char const *      base64 ) {

  /* Get upper bound for size of sysvar data */

  ulong base64_len  = strlen( base64 );
  ulong max_data_sz = 3UL + base64_len/2UL;  /* TODO add fd_base64_decoded_sz */

  /* Allocate funk record */

  FD_BORROWED_ACCOUNT_DECL(acc);
  int err = fd_acc_mgr_modify( slot_ctx->acc_mgr, slot_ctx->funk_txn, (fd_pubkey_t *)pubkey, 1, max_data_sz, acc);
  FD_TEST( !err );

  /* Decode Base64 into funk record */

  long sz = fd_base64_decode( acc->data, base64, base64_len );
  FD_TEST( sz>=0 );

  /* Set metadata */

  fd_memcpy( acc->meta->info.owner, fd_sysvar_owner_id.key, 32UL );
  acc->meta->info.lamports = 1UL;  /* chicken-and-egg problem: don't know rent, so can't find rent-exempt balance */
  acc->meta->dlen = (ulong)sz;
}

/* TODO: hack to ignore sysvars in account mismatches */

int fd_executor_run_test(
  fd_executor_test_t*       test,
  fd_executor_test_suite_t* suite) {

  FD_LOG_INFO(("Running test %d: %s", test->test_number, test->test_name));

  /* Create a new slot_ctx context to execute this test in */

  uchar * epoch_ctx_mem = (uchar *)fd_alloca_check( FD_EXEC_EPOCH_CTX_ALIGN, FD_EXEC_EPOCH_CTX_FOOTPRINT );
  fd_exec_epoch_ctx_t * epoch_ctx = fd_exec_epoch_ctx_join( fd_exec_epoch_ctx_new( epoch_ctx_mem ) );

  uchar * slot_ctx_mem = (uchar *)fd_alloca_check( FD_EXEC_SLOT_CTX_ALIGN, FD_EXEC_SLOT_CTX_FOOTPRINT );
  fd_exec_slot_ctx_t * slot_ctx = fd_exec_slot_ctx_join( fd_exec_slot_ctx_new( slot_ctx_mem ) );
  slot_ctx->epoch_ctx = epoch_ctx;

  if ( FD_UNLIKELY( NULL == slot_ctx ) )
    FD_LOG_ERR(( "failed to join a slot context" ));

  int ret = 0;
  slot_ctx->valloc     = suite->valloc;

  epoch_ctx->epoch_bank.rent.lamports_per_uint8_year = 3480;
  epoch_ctx->epoch_bank.rent.exemption_threshold = 2;
  epoch_ctx->epoch_bank.rent.burn_percent = 50;

  memcpy(&slot_ctx->epoch_ctx->features, &suite->features, sizeof(suite->features));
  if (test->disable_cnt > 0) {
    for (uint i = 0; i < test->disable_cnt; i++)
      ((ulong *) fd_type_pun( &epoch_ctx->features ))[test->disable_feature[i]] = ULONG_MAX;
  }

  fd_acc_mgr_t _acc_mgr[1];
  slot_ctx->acc_mgr = fd_acc_mgr_new( _acc_mgr, suite->funk );
  slot_ctx->blockstore = suite->blockstore;

  /* Prepare a new Funk transaction to execute this test in */
  fd_funk_txn_xid_t xid;
  fd_funk_txn_xid_set_unique( &xid );
  slot_ctx->funk_txn = fd_funk_txn_prepare( slot_ctx->acc_mgr->funk, NULL, &xid, 1 );
  if ( NULL == slot_ctx->funk_txn )
    FD_LOG_ERR(( "failed to prepare funk transaction" ));

  fd_sysvar_rent_init(slot_ctx);

  // TODO: nasty hack to prevent clock overwrite for
  // 1 particular test: test_redelegate_consider_balance_changes
  int num_clock = 0;
  do {
    /* Insert all the accounts into the database */
    for ( ulong i = 0; i < test->accs_len; i++ ) {
      // TODO: adding this makes the system tests fail
      // why does this account need to be skipped?
      // if ((test->accs[ i ].lamports == 0) && (test->accs[ i ].data_len == 0) && memcmp(global->solana_system_program, test->accs[i].owner.hash, 32 ) == 0) {
      //   continue;
      // }
      if (memcmp(&test->accs[i].pubkey, fd_sysvar_clock_id.key, sizeof(fd_pubkey_t)) == 0) {
        num_clock++;
      }

      /* Insert account */

      fd_pubkey_t const * acc_key  = &test->accs[ i ].pubkey;
      FD_BORROWED_ACCOUNT_DECL(rec);
      int err = fd_acc_mgr_modify( slot_ctx->acc_mgr, slot_ctx->funk_txn, acc_key, 1, test->accs[i].data_len, rec);
      FD_TEST( !err );

      rec->meta->dlen            = test->accs[ i ].data_len;
      rec->meta->info.lamports   = test->accs[ i ].lamports;
      rec->meta->info.rent_epoch = test->accs[ i ].rent_epoch;
      memcpy( rec->meta->info.owner, test->accs[ i ].owner.uc, 32UL );
      rec->meta->info.executable = (char)test->accs[ i ].executable;
      if( test->accs[ i ].data_len )
        memcpy( rec->data, test->accs[ i ].data, test->accs[ i ].data_len );

      err = fd_acc_mgr_commit_raw( slot_ctx->acc_mgr, rec->rec, acc_key, rec->meta, slot_ctx );
      FD_TEST( !err );

      /* wtf ... */
      if (memcmp(fd_sysvar_recent_block_hashes_id.key, &test->accs[i].pubkey, sizeof(test->accs[i].pubkey)) == 0) {
        fd_recent_block_hashes_new( &slot_ctx->slot_bank.recent_block_hashes );
        fd_bincode_decode_ctx_t ctx2;
        ctx2.data    = rec->data,
        ctx2.dataend = rec->data + rec->meta->dlen;
        ctx2.valloc  = slot_ctx->valloc;
        if ( fd_recent_block_hashes_decode( &slot_ctx->slot_bank.recent_block_hashes, &ctx2 ) ) {
          FD_LOG_WARNING(("fd_recent_block_hashes_decode failed"));
          ret = FD_EXECUTOR_INSTR_ERR_INVALID_ACC_DATA;
          goto fd_executor_run_cleanup;
        }
      }
    }

    slot_ctx->slot_bank.slot = 200880004;

    /* Load sysvar cache */
    if( 0!=strcmp( test->sysvar_cache.clock, "" ) )
      load_sysvar_cache( slot_ctx, fd_sysvar_clock_id.key, test->sysvar_cache.clock );
    if( 0!=strcmp( test->sysvar_cache.epoch_schedule, "" ) )
      load_sysvar_cache( slot_ctx, fd_sysvar_epoch_schedule_id.key, test->sysvar_cache.epoch_schedule );
    if( 0!=strcmp( test->sysvar_cache.epoch_rewards, "" ) )
      load_sysvar_cache( slot_ctx, fd_sysvar_epoch_rewards_id.key, test->sysvar_cache.epoch_rewards );
    if( 0!=strcmp( test->sysvar_cache.fees, "" ) )
      load_sysvar_cache( slot_ctx, fd_sysvar_fees_id.key, test->sysvar_cache.fees );
    if( 0!=strcmp( test->sysvar_cache.rent, "" ) )
      load_sysvar_cache( slot_ctx, fd_sysvar_rent_id.key, test->sysvar_cache.rent );
    if( 0!=strcmp( test->sysvar_cache.slot_hashes, "" ) )
      load_sysvar_cache( slot_ctx, fd_sysvar_slot_hashes_id.key, test->sysvar_cache.slot_hashes );
    //if( 0!=strcmp( test->sysvar_cache.recent_block_hashes, "" ) )
    //  load_sysvar_cache( global, global->sysvar_recent_block_hashes, test->sysvar_cache.recent_block_hashes );
    if( 0!=strcmp( test->sysvar_cache.stake_history, "" ) )
      load_sysvar_cache( slot_ctx, fd_sysvar_stake_history_id.key, test->sysvar_cache.stake_history );
    if( 0!=strcmp( test->sysvar_cache.slot_history, "" ) )
      load_sysvar_cache( slot_ctx, fd_sysvar_slot_history_id.key, test->sysvar_cache.slot_history );

    /* Restore slot number
       TODO The slot number should not be in bank */
    do {
      fd_sol_sysvar_clock_t clock[1];
      if( fd_sysvar_clock_read( clock, slot_ctx ) ) {
        slot_ctx->slot_bank.slot = clock->slot;
        *slot_ctx->sysvar_cache.clock = *clock;
      }
    } while(0);

    /* Restore rent sysvar */
    do {
      fd_rent_t rent[1];
      fd_rent_new(rent);
      if( fd_sysvar_rent_read( rent, slot_ctx ) ) {
        *slot_ctx->sysvar_cache.rent = *rent;
      }
    } while(0);

    fd_bpf_scan_and_create_bpf_program_cache_entry( slot_ctx, slot_ctx->funk_txn);

    /* Restore slot hashes sysvar */
    do {
      fd_slot_hashes_t slot_hashes[1];
      if( fd_sysvar_slot_hashes_read( slot_hashes, slot_ctx ) )
        *slot_ctx->sysvar_cache.slot_hashes = *slot_hashes;
    } while(0);


    /* Parse the raw transaction */
    uchar txn_parse_out_buf[FD_TXN_MAX_SZ];
    ulong payload_sz = 0;
    memset(txn_parse_out_buf, 0, FD_TXN_MAX_SZ);
    ulong txn_sz = fd_txn_parse_core( test->raw_tx, test->raw_tx_len, txn_parse_out_buf, NULL, &payload_sz, 1 );
    if ( txn_sz == 0 || txn_sz > FD_TXN_MAX_SZ ) {
      FD_LOG_WARNING(("Failed test %d: %s: failed to parse transaction", test->test_number, test->test_name));
      ret = -1;
      break;
    }

    fd_txn_t * txn_descriptor = (fd_txn_t*)txn_parse_out_buf;
    fd_txn_instr_t const * txn_instr    = &txn_descriptor->instr[0];

    /* Execute the transaction and check the result */
    fd_rawtxn_b_t              raw_txn_b = {
      .raw    = (void*)test->raw_tx,
      .txn_sz = (ushort)test->raw_tx_len,
    };
    fd_exec_txn_ctx_t txn_ctx;
    memset(&txn_ctx, 0, sizeof(txn_ctx));

    fd_exec_txn_ctx_new( &txn_ctx );

    txn_ctx.epoch_ctx       = epoch_ctx;
    txn_ctx.slot_ctx        = slot_ctx;
    txn_ctx.acc_mgr         = slot_ctx->acc_mgr;
    txn_ctx.valloc          = slot_ctx->valloc;
    txn_ctx.funk_txn        = slot_ctx->funk_txn;
    txn_ctx.txn_descriptor  = txn_descriptor;
    txn_ctx._txn_raw        = &raw_txn_b;
    txn_ctx.instr_stack_sz = 0;
    txn_ctx.compute_meter   = 200000;

    fd_exec_txn_ctx_setup( &txn_ctx, txn_descriptor, &raw_txn_b );

    fd_executor_setup_accessed_accounts_for_txn( &txn_ctx );
    fd_executor_setup_borrowed_accounts_for_txn( &txn_ctx );

    fd_instr_info_t instr;
    fd_convert_txn_instr_to_instr( (fd_txn_t const *)txn_descriptor, &raw_txn_b, txn_instr, txn_ctx.accounts, txn_ctx.borrowed_accounts, &instr );

    if (fail_before == test->test_number)
      kill(getpid(), SIGTRAP);

    int exec_result = fd_execute_instr( &txn_ctx, &instr );
    fd_execute_txn_finalize( slot_ctx, &txn_ctx, exec_result );

    if ( exec_result != test->expected_result ) {
      if (NULL != verbose)
        log_test_fail( test, suite, "expected transaction result %d, got %d: %s", test->expected_result, exec_result, test->bt );
      else
        log_test_fail( test, suite, "expected transaction result %d, got %d", test->expected_result, exec_result );
      ret = -1;
      break;
    }

    if ( exec_result == FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR ) {
      if ( txn_ctx.custom_err != test->custom_err) {
        log_test_fail( test, suite, "expected custom error value %d, got %d: %s", test->custom_err, txn_ctx.custom_err, (!!verbose) ? test->bt : "" );
        ret = -1;
        break;
      }
    }

    if (FD_EXECUTOR_INSTR_SUCCESS == exec_result) {

      // if (fd_executor_txn_check( slot_ctx, &txn_ctx ) != FD_EXECUTOR_INSTR_SUCCESS)
      //   log_test_fail(test, suite,  "bad dog.. no donut..  Ask josh to take a look at this test");

      /* Confirm account updates */
      for ( ulong i = 0; i < test->accs_len; i++ ) {
        if( fd_pubkey_is_sysvar_id( &test->accs[i].pubkey ) ) continue;

        int    err = 0;
        char * raw_acc_data = (char*) fd_acc_mgr_view_raw( slot_ctx->acc_mgr, slot_ctx->funk_txn, (fd_pubkey_t *) &test->accs[i].pubkey, NULL, &err);
        if (NULL == raw_acc_data) {
          if ((test->accs[ i ].result_lamports != 0)) {
            log_test_fail( test, suite, "expected lamports %ld, found empty account: %s", test->accs[i].result_lamports, (NULL != verbose) ? test->bt : "");
            ret = -666;
            break;
          }
          if ((test->accs[ i ].lamports == 0) && (test->accs[ i ].data_len == 0))
            continue;
          FD_LOG_WARNING(( "bad dog.. no donut..  Ask josh to take a look at this"));
          ret = err;
          break;
        }
        if (memcmp(&test->accs[i].pubkey, fd_sysvar_clock_id.key, sizeof(fd_pubkey_t)) == 0) {
          if (--num_clock) {
            continue;
          }
        }
        fd_account_meta_t *m = (fd_account_meta_t *) raw_acc_data;
        void*              d = (void *)(raw_acc_data + m->hlen);

        if (m->info.lamports != test->accs[i].result_lamports) {
          log_test_fail( test, suite, "account %ld: expected lamports %ld, got %ld: %s", i, test->accs[i].result_lamports, m->info.lamports, (NULL != verbose) ? test->bt : "");
          ret = -666;
          break;
        }
        if (m->info.executable != test->accs[i].result_executable) {
          log_test_fail( test, suite, "account %ld: expected executable %u, got %u: %s", i, test->accs[i].result_executable, m->info.executable, (NULL != verbose) ? test->bt : "");
          ret = -667;
          break;
        }
        if (m->info.rent_epoch != test->accs[i].result_rent_epoch) {
          log_test_fail( test, suite, "account %ld: expected rent_epoch %ld, got %ld: %s", i, test->accs[i].result_rent_epoch, m->info.rent_epoch, (NULL != verbose) ? test->bt : "");
          ret = -668;
          break;
        }
        if (memcmp(&m->info.owner, &test->accs[i].result_owner, sizeof(fd_pubkey_t)) != 0) {
          log_test_fail( test, suite, "account %ld: expected owner %32J, got %32J: %s", i, test->accs[i].result_owner.key, m->info.owner, (NULL != verbose) ? test->bt : "" );
          ret = -668;
          break;
        }
        FD_TEST( (!!test->accs[i].result_data_len) ^ (!test->accs[i].result_data) );
        if (test->accs[i].result_data_len == 0 && m->dlen != 0) {
          log_test_fail( test, suite, "account %ld: expected data len %ld, got %ld: %s", i, test->accs[i].result_data_len, m->dlen, (NULL != verbose) ? test->bt : "");
          ret = -669;
          break;
        }
        if(   ( m->dlen > 0 ) && (
              ( m->dlen != test->accs[i].result_data_len )
           || ( 0 != memcmp(d, test->accs[i].result_data, test->accs[i].result_data_len) ) ) ) {

          log_test_fail( test, suite, "account_index: %d   account missmatch: %s", i, (NULL != verbose) ? test->bt : "");

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
              FILE * file = fopen( buf, "w" );
              if (NULL != file) {

                fd_scratch_push();
                fd_flamenco_yaml_t * yaml =
                  fd_flamenco_yaml_init( fd_flamenco_yaml_new(
                      fd_scratch_alloc( fd_flamenco_yaml_align(), fd_flamenco_yaml_footprint() ) ),
                    file );
                FD_TEST( yaml );
                fd_account_pretty_print( test->accs[i].owner.key, test->accs[i].result_data, test->accs[i].result_data_len, file );
                fd_scratch_pop();

                fclose( file );
              }
            } while(0);

            /* Dump YAML serialization of actual account */
            do {
              char buf[ PATH_MAX ];
              snprintf( buf, PATH_MAX, "test_%lu_account_%32J_actual.yml", test->test_number, test->accs[i].pubkey.key );
              FILE * file = fopen( buf, "w" );
              if (NULL != file) {

                fd_scratch_push();
                fd_flamenco_yaml_t * yaml =
                  fd_flamenco_yaml_init( fd_flamenco_yaml_new(
                      fd_scratch_alloc( fd_flamenco_yaml_align(), fd_flamenco_yaml_footprint() ) ),
                    file );
                FD_TEST( yaml );
                fd_account_pretty_print( test->accs[i].owner.key, d, m->dlen, file );
                fd_scratch_pop();

                fclose( file );
              }
            } while(0);

            /* Print instructions on how to diff */
            FD_LOG_WARNING(( "HEX DIFF:\n  vimdiff <(xxd -c 32 test_%lu_account_%32J_actual.bin) <(xxd -c 32 test_%lu_account_%32J_expected.bin)",
                test->test_number, test->accs[i].pubkey.key, test->test_number, test->accs[i].pubkey.key ));

            /* Print instructions on how to diff */
            FD_LOG_WARNING(( "YAML DIFF:\n  vimdiff test_%lu_account_%32J_actual.yml test_%lu_account_%32J_expected.yml",
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
      FD_LOG_INFO(("Passed test %d: %s", test->test_number, test->test_name));
  } while (false);

  /* Revert the Funk transaction */
fd_executor_run_cleanup:
  fd_funk_txn_cancel( suite->funk, slot_ctx->funk_txn, 0 );
  fd_bincode_destroy_ctx_t destroy_ctx = { .valloc = slot_ctx->valloc };
  fd_slot_bank_destroy(&slot_ctx->slot_bank, &destroy_ctx);
  return ret;
}

int
main( int     argc,
      char ** argv
 ) {
  fd_boot         ( &argc, &argv );
  fd_flamenco_boot( &argc, &argv );

  ulong        test_start       = fd_env_strip_cmdline_ulong( &argc, &argv, "--start",            NULL, 0UL       );
  ulong        test_end         = fd_env_strip_cmdline_ulong( &argc, &argv, "--end",              NULL, ULONG_MAX );
  long         do_test          = fd_env_strip_cmdline_long ( &argc, &argv, "--test",             NULL, -1        );
  char const * filter           = fd_env_strip_cmdline_cstr ( &argc, &argv, "--filter",           NULL, NULL      );
               verbose          = fd_env_strip_cmdline_cstr ( &argc, &argv, "--verbose",          NULL, NULL      );
               fail_fast        = fd_env_strip_cmdline_cstr ( &argc, &argv, "--fail_fast",        NULL, NULL      );
               do_dump          = fd_env_strip_cmdline_cstr ( &argc, &argv, "--do_dump",          NULL, NULL      );
               scratch_mb       = fd_env_strip_cmdline_ulong( &argc, &argv, "--scratch-mb",       NULL, 1024      );
               fail_before      = fd_env_strip_cmdline_long ( &argc, &argv, "--fail_before",      NULL, -1        );

  if (-1 != do_test)
    test_start = test_end = (ulong)do_test;

  /* Initialize the test suite */
  fd_executor_test_suite_t suite;
  fd_executor_test_suite_new( &suite );

  /* Read list of ignored tests */
  do {
    FILE * fp = fopen( "src/flamenco/runtime/tests/ignore_fail", "r" );
    if( FD_UNLIKELY( !fp ) ) FD_LOG_ERR(( "fopen(src/flamenco/runtime/tests/ignore_fail, r) failed: %s", strerror(errno) ));
    else {
      char buf[ 256 ];
      while( NULL != fgets( buf, sizeof(buf), fp ) ) {
        ulong i = fd_cstr_to_ulong( buf );
        //FD_LOG_DEBUG(( "Ignoring test %lu", i ));
        if( i < (sizeof(suite.ignore_fail) / sizeof(suite.ignore_fail[0])) )
          suite.ignore_fail[ i ] = 1;
      }
      fclose( fp );
    }
  } while(0);

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
      if( r == 0 ) {
        if( suite.ignore_fail[idx] ) {
          FD_LOG_NOTICE(( "Removing %lu from ignore fail 🎉", idx ));
          suite.ignore_fail[idx] = 0;
        }
        success_cnt++;
      }
    }
  }

  ulong regressions = executed_cnt - success_cnt - ignored_cnt;

  FD_LOG_NOTICE(( "Progress: %lu/%lu tests (%lu tests failed but ignored, %lu(%f%%) regressions)", success_cnt, executed_cnt, ignored_cnt, regressions,  100.0 * ((double) regressions / (double) executed_cnt) ));

  if (NULL != filter)
    regfree(&suite.filter_ex);

  /* Update ignore fail list */
  do {
    FILE * fp = fopen( "src/flamenco/runtime/tests/ignore_fail", "w" );
    if( FD_UNLIKELY( !fp ) ) FD_LOG_ERR(( "fopen(src/flamenco/runtime/tests/ignore_fail, w) failed: %s", strerror(errno) ));
    else {
      for( ulong i = 0; i < (sizeof(suite.ignore_fail) / sizeof(suite.ignore_fail[0])); i++ ) {
        if( suite.ignore_fail[ i ] )
          fprintf( fp, "%lu\n", i );
      }
      fclose( fp );
    }
  } while(0);

  /* Free test suite */
  fd_wksp_free_laddr( fd_scratch_detach( NULL ) );

  if( ret==0 ) FD_LOG_NOTICE(( "pass" ));
  else         FD_LOG_NOTICE(( "fail" ));
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
