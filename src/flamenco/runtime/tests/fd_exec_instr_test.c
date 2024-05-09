#include "fd_exec_test.pb.h"
#undef FD_SCRATCH_USE_HANDHOLDING
#define FD_SCRATCH_USE_HANDHOLDING 1
#include "fd_exec_instr_test.h"
#include "../fd_acc_mgr.h"
#include "../fd_account.h"
#include "../fd_executor.h"
#include "../program/fd_bpf_loader_v3_program.h"
#include "../program/fd_bpf_program_util.h"
#include "../context/fd_exec_epoch_ctx.h"
#include "../context/fd_exec_slot_ctx.h"
#include "../context/fd_exec_txn_ctx.h"
#include "../sysvar/fd_sysvar_recent_hashes.h"
#include "../sysvar/fd_sysvar_cache.c"
#include "../../../funk/fd_funk.h"
#include "../../../util/bits/fd_float.h"
#include <assert.h>

#pragma GCC diagnostic ignored "-Wformat-extra-args"

/* LOGFMT_REPORT is the log prefix for instruction processing tests */

#define LOGFMT_REPORT "%s"
static FD_TL char _report_prefix[65] = {0};

#define REPORTV( level, fmt, ... ) \
  FD_LOG_##level(( LOGFMT_REPORT fmt, _report_prefix, __VA_ARGS__ ))

#define REPORT( level, fmt ) REPORTV( level, fmt, 0 )

#define REPORT_ACCTV( level, addr, fmt, ... )                                  \
  do {                                                                         \
    char         _acct_log_private_addr[ FD_BASE58_ENCODED_32_SZ ];            \
    void const * _acct_log_private_addr_ptr = (addr);                          \
    fd_acct_addr_cstr( _acct_log_private_addr, _acct_log_private_addr_ptr );        \
    REPORTV( level, "account %-44s: " fmt, _acct_log_private_addr, __VA_ARGS__ ); \
  } while(0);

#define REPORT_ACCT( level, addr, fmt ) REPORT_ACCTV( level, addr, fmt, 0 )

/* Define routine to sort accounts to support query-by-pubkey via
   binary search. */

#define SORT_NAME sort_pubkey_p
#define SORT_KEY_T void const *
#define SORT_BEFORE(a,b) ( memcmp( (a), (b), sizeof(fd_pubkey_t) )<0 )
#include "../../../util/tmpl/fd_sort.c"
#include "../../vm/fd_vm_context.h"

struct __attribute__((aligned(32UL))) fd_exec_instr_test_runner_private {
  fd_funk_t * funk;
};

ulong
fd_exec_instr_test_runner_align( void ) {
  return alignof(fd_exec_instr_test_runner_t);
}

ulong
fd_exec_instr_test_runner_footprint( void ) {
  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, alignof(fd_exec_instr_test_runner_t), sizeof(fd_exec_instr_test_runner_t) );
  l = FD_LAYOUT_APPEND( l, fd_funk_align(),                      fd_funk_footprint()                 );
  return l;
}

fd_exec_instr_test_runner_t *
fd_exec_instr_test_runner_new( void * mem,
                               ulong  wksp_tag ) {
  FD_SCRATCH_ALLOC_INIT( l, mem );
  void * runner_mem = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_exec_instr_test_runner_t), sizeof(fd_exec_instr_test_runner_t) );
  void * funk_mem   = FD_SCRATCH_ALLOC_APPEND( l, fd_funk_align(),                      fd_funk_footprint()                 );
  FD_SCRATCH_ALLOC_FINI( l, alignof(fd_exec_instr_test_runner_t) );

  ulong txn_max = 4+fd_tile_cnt();
  ulong rec_max = 1024UL;
  fd_funk_t * funk = fd_funk_join( fd_funk_new( funk_mem, wksp_tag, (ulong)fd_tickcount(), txn_max, rec_max ) );
  if( FD_UNLIKELY( !funk ) ) {
    FD_LOG_WARNING(( "fd_funk_new() failed" ));
    return NULL;
  }
  fd_funk_start_write( funk );

  fd_exec_instr_test_runner_t * runner = runner_mem;
  runner->funk = funk;
  return runner;
}

void *
fd_exec_instr_test_runner_delete( fd_exec_instr_test_runner_t * runner ) {
  if( FD_UNLIKELY( !runner ) ) return NULL;
  fd_funk_delete( fd_funk_leave( runner->funk ) );
  runner->funk = NULL;
  return runner;
}

static int
fd_double_is_normal( double dbl ) {
  ulong x = fd_dblbits( dbl );
  int is_denorm =
    ( fd_dblbits_bexp( x ) == 0 ) |
    ( fd_dblbits_mant( x ) != 0 );
  int is_inf =
    ( fd_dblbits_bexp( x ) == 2047 ) &
    ( fd_dblbits_mant( x ) ==    0 );
  int is_nan =
    ( fd_dblbits_bexp( x ) == 2047 ) &
    ( fd_dblbits_mant( x ) !=    0 );
  return !( is_denorm | is_inf | is_nan );
}

static int
_load_account( fd_borrowed_account_t *           acc,
               fd_acc_mgr_t *                    acc_mgr,
               fd_funk_txn_t *                   funk_txn,
               fd_exec_test_acct_state_t const * state ) {
  fd_borrowed_account_init( acc );
  ulong size = 0UL;
  if( state->data ) size = state->data->size;

  fd_pubkey_t pubkey[1];  memcpy( pubkey, state->address, sizeof(fd_pubkey_t) );

  /* Account must not yet exist */
  if( FD_UNLIKELY( fd_acc_mgr_view_raw( acc_mgr, funk_txn, pubkey, NULL, NULL ) ) )
    return 0;

  assert( acc_mgr->funk );
  assert( acc_mgr->funk->magic == FD_FUNK_MAGIC );
  int err = fd_acc_mgr_modify( /* acc_mgr     */ acc_mgr,
                               /* txn         */ funk_txn,
                               /* pubkey      */ pubkey,
                               /* do_create   */ 1,
                               /* min_data_sz */ size,
                               acc );
  assert( err==FD_ACC_MGR_SUCCESS );
  fd_memcpy( acc->data, state->data->bytes, size );

  acc->starting_lamports     = state->lamports;
  acc->starting_dlen         = size;
  acc->meta->info.lamports   = state->lamports;
  acc->meta->info.executable = state->executable;
  acc->meta->info.rent_epoch = state->rent_epoch;
  acc->meta->dlen            = size;
  memcpy( acc->meta->info.owner, state->owner, sizeof(fd_pubkey_t) );

  return 1;
}

static int
_context_create( fd_exec_instr_test_runner_t *        runner,
                 fd_exec_instr_ctx_t *                ctx,
                 fd_exec_test_instr_context_t const * test_ctx ) {

  memset( ctx, 0, sizeof(fd_exec_instr_ctx_t) );

  fd_funk_t * funk = runner->funk;

  /* Generate unique ID for funk txn */

  static FD_TL ulong xid_seq = 0UL;

  fd_funk_txn_xid_t xid[1] = {0};
  xid->ul[0] = fd_log_app_id();
  xid->ul[1] = fd_log_thread_id();
  xid->ul[2] = xid_seq++;
  xid->ul[3] = (ulong)fd_tickcount();

  /* Create temporary funk transaction and scratch contexts */

  fd_funk_txn_t * funk_txn = fd_funk_txn_prepare( funk, NULL, xid, 1 );
  fd_scratch_push();

  ulong vote_acct_max = 128UL;

  /* Allocate contexts */
  uchar *               epoch_ctx_mem = fd_scratch_alloc( fd_exec_epoch_ctx_align(), fd_exec_epoch_ctx_footprint( vote_acct_max ) );
  uchar *               slot_ctx_mem  = fd_scratch_alloc( FD_EXEC_SLOT_CTX_ALIGN,  FD_EXEC_SLOT_CTX_FOOTPRINT  );
  uchar *               txn_ctx_mem   = fd_scratch_alloc( FD_EXEC_TXN_CTX_ALIGN,   FD_EXEC_TXN_CTX_FOOTPRINT   );

  fd_exec_epoch_ctx_t * epoch_ctx     = fd_exec_epoch_ctx_join( fd_exec_epoch_ctx_new( epoch_ctx_mem, vote_acct_max ) );
  fd_exec_slot_ctx_t *  slot_ctx      = fd_exec_slot_ctx_join ( fd_exec_slot_ctx_new ( slot_ctx_mem, fd_scratch_virtual() ) );
  fd_exec_txn_ctx_t *   txn_ctx       = fd_exec_txn_ctx_join  ( fd_exec_txn_ctx_new  ( txn_ctx_mem   ) );

  assert( epoch_ctx );
  assert( slot_ctx  );

  /* Initial variables */
  txn_ctx->loaded_accounts_data_size_limit = MAX_LOADED_ACCOUNTS_DATA_SIZE_BYTES;
  txn_ctx->heap_size = FD_VM_DEFAULT_HEAP_SZ;

  /* Set up epoch context */
  fd_epoch_bank_t * epoch_bank = fd_exec_epoch_ctx_epoch_bank( epoch_ctx );
  epoch_bank->rent.lamports_per_uint8_year = 3480;
  epoch_bank->rent.exemption_threshold = 2;
  epoch_bank->rent.burn_percent = 50;

  /* Restore feature flags */

  fd_exec_test_feature_set_t const * feature_set = &test_ctx->epoch_context.features;

  fd_features_disable_all( &epoch_ctx->features );
  for( ulong j=0UL; j < feature_set->features_count; j++ ) {
    ulong                   prefix = feature_set->features[j];
    fd_feature_id_t const * id     = fd_feature_id_query( prefix );
    if( FD_UNLIKELY( !id ) ) {
      FD_LOG_WARNING(( "unsupported feature ID 0x%016lx", prefix ));
      return 0;
    }
    /* Enabled since genesis */
    fd_features_set( &epoch_ctx->features, id, 0UL );
  }

  /* Create account manager */

  fd_acc_mgr_t * acc_mgr = fd_acc_mgr_new( fd_scratch_alloc( FD_ACC_MGR_ALIGN, FD_ACC_MGR_FOOTPRINT ), funk );
  assert( acc_mgr );

  /* Set up slot context */

  slot_ctx->epoch_ctx = epoch_ctx;
  slot_ctx->funk_txn  = funk_txn;
  slot_ctx->acc_mgr   = acc_mgr;

  /* TODO: Restore slot_bank */

  fd_slot_bank_new( &slot_ctx->slot_bank );
  fd_block_block_hash_entry_t * recent_block_hashes = deq_fd_block_block_hash_entry_t_alloc( slot_ctx->valloc, FD_SYSVAR_RECENT_HASHES_CAP );
  slot_ctx->slot_bank.recent_block_hashes.hashes = recent_block_hashes;
  fd_block_block_hash_entry_t * recent_block_hash = deq_fd_block_block_hash_entry_t_push_tail_nocopy( recent_block_hashes );
  fd_memset( recent_block_hash, 0, sizeof(fd_block_block_hash_entry_t) );

  /* Set up txn context */

  txn_ctx->epoch_ctx               = epoch_ctx;
  txn_ctx->slot_ctx                = slot_ctx;
  txn_ctx->funk_txn                = funk_txn;
  txn_ctx->acc_mgr                 = acc_mgr;
  txn_ctx->valloc                  = fd_scratch_virtual();
  txn_ctx->compute_unit_limit      = test_ctx->cu_avail;
  txn_ctx->compute_unit_price      = 0;
  txn_ctx->compute_meter           = test_ctx->cu_avail;
  txn_ctx->prioritization_fee_type = FD_COMPUTE_BUDGET_PRIORITIZATION_FEE_TYPE_DEPRECATED;
  txn_ctx->custom_err              = UINT_MAX;
  txn_ctx->instr_stack_sz          = 0;
  txn_ctx->executable_cnt          = 0;
  txn_ctx->paid_fees               = 0;
  txn_ctx->num_instructions        = 0;
  txn_ctx->dirty_vote_acc          = 0;
  txn_ctx->dirty_stake_acc         = 0;
  txn_ctx->failed_instr            = NULL;
  txn_ctx->capture_ctx             = NULL;
  txn_ctx->vote_accounts_pool      = NULL;

  memset( txn_ctx->_txn_raw, 0, sizeof(fd_rawtxn_b_t) );
  memset( txn_ctx->return_data.program_id.key, 0, sizeof(fd_pubkey_t) );
  txn_ctx->return_data.len         = 0;


  /* Set up instruction context */

  fd_instr_info_t * info = fd_scratch_alloc( alignof(fd_instr_info_t), sizeof(fd_instr_info_t) );
  assert( info );
  memset( info, 0, sizeof(fd_instr_info_t) );

  if( test_ctx->data ) {
    info->data_sz = (ushort)test_ctx->data->size;
    info->data    = test_ctx->data->bytes;
  }

  memcpy( info->program_id_pubkey.uc, test_ctx->program_id, sizeof(fd_pubkey_t) );

  /* Prepare borrowed account table (correctly handles aliasing) */

  if( FD_UNLIKELY( test_ctx->accounts_count > 128 ) ) {
    /* TODO remove this hardcoded constant */
    REPORT( NOTICE, "too many accounts" );
    return 0;
  }

  fd_borrowed_account_t * borrowed_accts = txn_ctx->borrowed_accounts;
  fd_memset( borrowed_accts, 0, test_ctx->accounts_count * sizeof(fd_borrowed_account_t) );
  txn_ctx->accounts_cnt = test_ctx->accounts_count;
  for ( uint i = 0; i < test_ctx->accounts_count; i++ ) {
    memcpy( &(txn_ctx->accounts[i]), test_ctx->accounts[i].address, sizeof(fd_pubkey_t) );
  }
  fd_txn_t * txn_descriptor = (fd_txn_t *) fd_scratch_alloc( fd_txn_align(), fd_txn_footprint(0, 0) );
  fd_memset(txn_descriptor, 0, sizeof(txn_descriptor));
  txn_descriptor->acct_addr_cnt = (ushort) test_ctx->accounts_count;
  txn_descriptor->addr_table_adtl_cnt = 0;
  txn_ctx->txn_descriptor = txn_descriptor;

  /* Load accounts into database */

  assert( acc_mgr->funk );
  for( ulong j=0UL; j < test_ctx->accounts_count; j++ ) {
    if( !_load_account( &borrowed_accts[j], acc_mgr, funk_txn, &test_ctx->accounts[j] ) )
      return 0;
  }

  /* Load in executable accounts */
  for( ulong i = 0; i < txn_ctx->accounts_cnt; i++ ) {
    if ( FD_UNLIKELY( 0 == memcmp(borrowed_accts[i].const_meta->info.owner, fd_solana_bpf_loader_upgradeable_program_id.key, sizeof(fd_pubkey_t)) ) ) {
      fd_bpf_upgradeable_loader_state_t program_loader_state;
      int err = 0;
      if( FD_UNLIKELY( !read_bpf_upgradeable_loader_state_for_program( txn_ctx, (uchar) i, &program_loader_state, &err ) ) ) {
        continue;
      }

      fd_pubkey_t * programdata_acc = &program_loader_state.inner.program.programdata_address;
      fd_borrowed_account_t * executable_account = fd_borrowed_account_init( &txn_ctx->executable_accounts[txn_ctx->executable_cnt] );
      fd_acc_mgr_view(txn_ctx->acc_mgr, txn_ctx->funk_txn, programdata_acc, executable_account);
      txn_ctx->executable_cnt++;
    }
  }

  /* Add accounts to bpf program cache */
  fd_bpf_scan_and_create_bpf_program_cache_entry( slot_ctx, funk_txn );

  /* Restore sysvar cache */

  fd_sysvar_cache_restore( slot_ctx->sysvar_cache, acc_mgr, funk_txn );

  /* Fill missing sysvar cache values with defaults */
  /* Note: these default values are obtained by sysvar defaults from solfuzz-agave */

  // https://github.com/firedancer-io/solfuzz-agave/blob/agave-v2.0/src/lib.rs#L466-L474
  if( !slot_ctx->sysvar_cache->has_clock ) {
    slot_ctx->sysvar_cache->has_clock                        = 1;
    slot_ctx->sysvar_cache->val_clock->slot                  = 10UL;
    slot_ctx->sysvar_cache->val_clock->epoch_start_timestamp = 0;
    slot_ctx->sysvar_cache->val_clock->epoch                 = 0UL;
    slot_ctx->sysvar_cache->val_clock->leader_schedule_epoch = 0UL;
    slot_ctx->sysvar_cache->val_clock->unix_timestamp        = 0;
  }
  // https://github.com/firedancer-io/solfuzz-agave/blob/agave-v2.0/src/lib.rs#L476-L483
  if( !slot_ctx->sysvar_cache->has_epoch_schedule ) {
    slot_ctx->sysvar_cache->has_epoch_schedule                              = 1;
    slot_ctx->sysvar_cache->val_epoch_schedule->slots_per_epoch             = MAX_SLOTS_CNT;
    slot_ctx->sysvar_cache->val_epoch_schedule->leader_schedule_slot_offset = MAX_SLOTS_CNT;
    slot_ctx->sysvar_cache->val_epoch_schedule->warmup                      = 1;
    slot_ctx->sysvar_cache->val_epoch_schedule->first_normal_epoch          = 14UL;
    slot_ctx->sysvar_cache->val_epoch_schedule->first_normal_slot           = 524256UL;
  }
  // https://github.com/firedancer-io/solfuzz-agave/blob/agave-v2.0/src/lib.rs#L487-L500
  if( !slot_ctx->sysvar_cache->has_rent ) { 
    slot_ctx->sysvar_cache->has_rent                          = 1;
    slot_ctx->sysvar_cache->val_rent->lamports_per_uint8_year = 3480UL;
    slot_ctx->sysvar_cache->val_rent->exemption_threshold     = 2.0;
    slot_ctx->sysvar_cache->val_rent->burn_percent            = 50;
  }

  /* Handle undefined behavior if sysvars are malicious (!!!) */

  /* A NaN rent exemption threshold is U.B. in Solana Labs */
  fd_rent_t const * rent = fd_sysvar_cache_rent( slot_ctx->sysvar_cache );
  if( rent ) {
    if( ( !fd_double_is_normal( rent->exemption_threshold ) ) |
        ( rent->exemption_threshold     <      0.0 ) |
        ( rent->exemption_threshold     >    999.0 ) |
        ( rent->lamports_per_uint8_year > UINT_MAX ) |
        ( rent->burn_percent            >      100 ) )
      return 0;

    /* Override epoch bank settings */
    epoch_bank->rent = *rent;
  }

  /* Override most recent blockhash if given */
  fd_recent_block_hashes_t const * rbh = fd_sysvar_cache_recent_block_hashes( slot_ctx->sysvar_cache );
  if( rbh && !deq_fd_block_block_hash_entry_t_empty( rbh->hashes ) ) {
    fd_block_block_hash_entry_t const * last = deq_fd_block_block_hash_entry_t_peek_tail_const( rbh->hashes );
    if( last ) {
      *recent_block_hash = *last;
      slot_ctx->slot_bank.lamports_per_signature = last->fee_calculator.lamports_per_signature;
    }
  }

  /* Load instruction accounts */

  if( FD_UNLIKELY( test_ctx->instr_accounts_count > 128 ) ) {
    /* TODO remove this hardcoded constant */
    REPORT( NOTICE, "too many instruction accounts" );
    return 0;
  }

  uchar acc_idx_seen[256] = {0};
  for( ulong j=0UL; j < test_ctx->instr_accounts_count; j++ ) {
    uint index = test_ctx->instr_accounts[j].index;
    if( index >= test_ctx->accounts_count ) {
      REPORTV( NOTICE, "instruction account index out of range (%u > %u)", index, test_ctx->instr_accounts_count );
      return 0;
    }

    fd_borrowed_account_t * acc = &borrowed_accts[ index ];
    uint flags = 0;
    flags |= test_ctx->instr_accounts[j].is_writable ? FD_INSTR_ACCT_FLAGS_IS_WRITABLE : 0;
    flags |= test_ctx->instr_accounts[j].is_signer   ? FD_INSTR_ACCT_FLAGS_IS_SIGNER   : 0;

    info->borrowed_accounts[j] = acc;
    info->acct_flags       [j] = (uchar)flags;
    memcpy( info->acct_pubkeys[j].uc, acc->pubkey, sizeof(fd_pubkey_t) );
    info->acct_txn_idxs[j]     = (uchar) index;

    if (acc_idx_seen[index]) {
      info->is_duplicate[j] = 1;
    }
    acc_idx_seen[index] = 1;
  }
  info->acct_cnt = (uchar)test_ctx->instr_accounts_count;

  bool found_program_id = false;
  for( uint i = 0; i < test_ctx->accounts_count; i++ ) {
    if( 0 == memcmp(test_ctx->accounts[i].address, test_ctx->program_id, sizeof(fd_pubkey_t)) ) {
      info->program_id = (uchar) i;
      found_program_id = true;
      break;
    }
  }
  if( !found_program_id ) {
    FD_LOG_WARNING(("Unable to find program_id in accounts"));
  }

  ctx->epoch_ctx = epoch_ctx;
  ctx->slot_ctx  = slot_ctx;
  ctx->txn_ctx   = txn_ctx;
  ctx->funk_txn  = funk_txn;
  ctx->acc_mgr   = acc_mgr;
  ctx->valloc    = fd_scratch_virtual();
  ctx->instr     = info;

  return 1;
}

static void
_context_destroy( fd_exec_instr_test_runner_t * runner,
                  fd_exec_instr_ctx_t *         ctx ) {
  if( !ctx ) return;
  fd_exec_slot_ctx_t *  slot_ctx  = ctx->slot_ctx;
  if( !slot_ctx ) return;
  fd_exec_epoch_ctx_t * epoch_ctx = slot_ctx->epoch_ctx;
  fd_acc_mgr_t *        acc_mgr   = slot_ctx->acc_mgr;
  fd_funk_txn_t *       funk_txn  = slot_ctx->funk_txn;

  fd_exec_slot_ctx_delete ( fd_exec_slot_ctx_leave ( slot_ctx  ) );
  fd_exec_epoch_ctx_delete( fd_exec_epoch_ctx_leave( epoch_ctx ) );
  fd_acc_mgr_delete( acc_mgr );
  fd_scratch_pop();
  fd_funk_txn_cancel( runner->funk, funk_txn, 1 );

  ctx->slot_ctx = NULL;
}

/* fd_exec_instr_fixture_diff_t compares a test fixture against the
   actual execution results. */

struct fd_exec_instr_fixture_diff {
  fd_exec_instr_ctx_t *                ctx;
  fd_exec_test_instr_context_t const * input;
  fd_exec_test_instr_effects_t const * expected;
  int                                  exec_result;

  int has_diff;
};

typedef struct fd_exec_instr_fixture_diff fd_exec_instr_fixture_diff_t;

static int
_diff_acct( fd_exec_test_acct_state_t const * want,
            fd_borrowed_account_t const *     have ) {

  int diff = 0;

  assert( 0==memcmp( want->address, have->pubkey->uc, sizeof(fd_pubkey_t) ) );

  if( want->lamports != have->meta->info.lamports ) {
    REPORT_ACCTV( NOTICE, want->address, "expected %lu lamports, got %lu",
                  want->lamports, have->meta->info.lamports );
    diff = 1;
  }

  if( want->data->size != have->meta->dlen ) {
    REPORT_ACCTV( NOTICE, want->address, "expected data sz %u, got %lu",
                  want->data->size, have->meta->dlen );
    diff = 1;
  }

  if( want->executable != have->meta->info.executable ) {
    REPORT_ACCTV( NOTICE, want->address, "expected account to be %s, but is %s",
                  (want->executable           ) ? "executable" : "not executable",
                  (have->meta->info.executable) ? "executable" : "not executable" );
    diff = 1;
  }

  if( want->rent_epoch != have->meta->info.rent_epoch ) {
    REPORT_ACCTV( NOTICE, want->address, "expected rent epoch %lu, got %lu",
                  want->rent_epoch, have->meta->info.rent_epoch );
    diff = 1;
  }

  if( 0!=memcmp( want->owner, have->meta->info.owner, sizeof(fd_pubkey_t) ) ) {
    char a[ FD_BASE58_ENCODED_32_SZ ];
    char b[ FD_BASE58_ENCODED_32_SZ ];
    REPORT_ACCTV( NOTICE, want->address, "expected owner %s, got %s",
                  fd_acct_addr_cstr( a, want->owner            ),
                  fd_acct_addr_cstr( b, have->meta->info.owner ) );
    diff = 1;
  }

  if( 0!=memcmp( want->data->bytes, have->data, want->data->size ) ) {
    REPORT_ACCT( NOTICE, want->address, "data mismatch" );
    diff = 1;
  }

  return diff;
}

static void
_unexpected_acct_modify_in_fixture( fd_exec_instr_fixture_diff_t * check,
                                    void const *                   pubkey ) {

  /* At this point, an account was reported as modified in the test
     fixture, but no changes were seen locally. */

  check->has_diff = 1;

  REPORT_ACCT( NOTICE, pubkey, "expected changes, but none found" );
}

static void
_unexpected_acct_modify_locally( fd_exec_instr_fixture_diff_t * check,
                                 fd_borrowed_account_t const *  have ) {

  /* At this point, an account was reported as modified locally, but no
     changes contained in fixture.  Thus, diff against the original
     state in the fixture. */

  /* Find matching test input */

  fd_exec_test_instr_context_t const * input = check->input;

  fd_exec_test_acct_state_t * want = NULL;
  for( ulong i=0UL; i < input->accounts_count; i++ ) {
    fd_exec_test_acct_state_t * acct_state = &input->accounts[i];
    if( 0==memcmp( acct_state->address, have->pubkey, sizeof(fd_pubkey_t) ) ) {
      want = acct_state;
      break;
    }
  }
  if( FD_UNLIKELY( !want ) ) {
    check->has_diff = 1;

    REPORT_ACCT( NOTICE, have->pubkey, "found unexpected changes" );
    /* TODO: dump the account that changed unexpectedly */
    return;
  }

  /* Compare against original state */

  check->has_diff |= _diff_acct( want, have );
}

static void
_diff_effects( fd_exec_instr_fixture_diff_t * check ) {

  fd_exec_instr_ctx_t *                ctx         = check->ctx;
  fd_exec_test_instr_effects_t const * expected    = check->expected;
  int                                  exec_result = check->exec_result;

  if( expected->result != exec_result ) {
    check->has_diff = 1;
    REPORTV( NOTICE, "expected result (%d-%s), got (%d-%s)",
             expected->result, fd_executor_instr_strerror( expected->result ),
             exec_result,      fd_executor_instr_strerror( exec_result      ) );

    if( ( expected->result == FD_EXECUTOR_INSTR_SUCCESS ) |
        ( exec_result      == FD_EXECUTOR_INSTR_SUCCESS ) ) {
      /* If one (and only one) of the results is success, stop diffing
         for sake of brevity. */
      return;
    }
  }
  else if( ( exec_result==FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR    ) &
           ( expected->custom_err != ctx->txn_ctx->custom_err ) ) {
    check->has_diff = 1;
    REPORTV( NOTICE, "expected custom error %d, got %d",
             expected->custom_err, ctx->txn_ctx->custom_err );
    return;
  }

  /* Sort the transaction's write-locked accounts */

  void const ** modified_pubkeys =
      fd_scratch_alloc( alignof(void *), ctx->txn_ctx->accounts_cnt * sizeof(void *) );
  ulong modified_acct_cnt = 0UL;

  for( ulong i=0UL; i < ctx->txn_ctx->accounts_cnt; i++ ) {
    fd_borrowed_account_t * acc = &ctx->txn_ctx->borrowed_accounts[i];
    if( acc->meta )  /* instruction took a writable handle? */
      modified_pubkeys[ modified_acct_cnt++ ] = &acc->pubkey->uc;
  }

  sort_pubkey_p_inplace( modified_pubkeys, modified_acct_cnt );

  /* Bitmask of which transaction accounts we've visited */

  ulong   visited_sz = fd_ulong_align_up( modified_acct_cnt, 64UL )>>3;
  ulong * visited    = fd_scratch_alloc( alignof(ulong), visited_sz );
  fd_memset( visited, 0, visited_sz );

  /* Verify each of the expected accounts */

  for( ulong i=0UL; i < expected->modified_accounts_count; i++ ) {
    fd_exec_test_acct_state_t const * want = &expected->modified_accounts[i];

    if( FD_UNLIKELY( !want->has_address ) ) {
      REPORTV( WARNING, "modified account #%lu missing an address", i );
      check->has_diff = 1;
      continue;
    }
    void const * query = want->address;
    ulong idx = sort_pubkey_p_search_geq( modified_pubkeys, modified_acct_cnt, query );
    if( FD_UNLIKELY( idx >= modified_acct_cnt ) ) {
      _unexpected_acct_modify_in_fixture( check, query );
      continue;
    }

    if( FD_UNLIKELY( 0!=memcmp( modified_pubkeys[idx], query, sizeof(fd_pubkey_t) ) ) ) {
      _unexpected_acct_modify_in_fixture( check, query );
      continue;
    }

    visited[ idx>>6 ] |= fd_ulong_mask_bit( idx&63UL );

    ulong acct_laddr = ( (ulong)modified_pubkeys[idx] - offsetof( fd_borrowed_account_t, pubkey ) );
    fd_borrowed_account_t const * acct = (fd_borrowed_account_t const *)acct_laddr;

    check->has_diff |= _diff_acct( want, acct );
  }

  /* Visit accounts that were write-locked locally, but are not in
     expected list */

  for( ulong i=0UL; i < modified_acct_cnt; i++ ) {
    ulong acct_laddr = ( (ulong)modified_pubkeys[i] - offsetof( fd_borrowed_account_t, pubkey ) );
    fd_borrowed_account_t const * acct = (fd_borrowed_account_t const *)acct_laddr;

    int was_visited = !!( visited[ i>>6 ] & fd_ulong_mask_bit( i&63UL ) );
    if( FD_UNLIKELY( !was_visited ) )
      _unexpected_acct_modify_locally( check, acct );
  }

  /* TODO: Capture account side effects outside of the access list by
           looking at the funk record delta (technically a scheduling
           violation) */
}

int
fd_exec_instr_fixture_run( fd_exec_instr_test_runner_t *        runner,
                           fd_exec_test_instr_fixture_t const * test,
                           char const *                         log_name ) {

  fd_exec_instr_ctx_t ctx[1];
  if( FD_UNLIKELY( !_context_create( runner, ctx, &test->input ) ) )
    return 0;

  fd_pubkey_t program_id[1];  memcpy( program_id, test->input.program_id, sizeof(fd_pubkey_t) );
  fd_exec_instr_fn_t native_prog_fn = fd_executor_lookup_native_program( program_id );

  int exec_result;
  if( FD_LIKELY( native_prog_fn ) ) {
    exec_result = native_prog_fn( *ctx );
  } else {
    char program_id_cstr[ FD_BASE58_ENCODED_32_SZ ];
    REPORTV( NOTICE, "execution failed (program %s not found)",
             fd_acct_addr_cstr( program_id_cstr, test->input.program_id ) );
    exec_result = FD_EXECUTOR_INSTR_ERR_UNSUPPORTED_PROGRAM_ID;
  }

  int has_diff;
  do {
    /* Compare local execution results against fixture */

    fd_cstr_printf( _report_prefix, sizeof(_report_prefix), NULL, "%s: ", log_name );

    fd_exec_instr_fixture_diff_t diff =
      { .ctx         = ctx,
        .input       = &test->input,
        .expected    = &test->output,
        .exec_result = exec_result };
    _diff_effects( &diff );

    _report_prefix[0] = '\0';

    has_diff = diff.has_diff;
  } while(0);

  _context_destroy( runner, ctx );
  return !has_diff;
}

FD_FN_PURE static bool
fd_instr_info_sum_account_lamports_no_crash( fd_instr_info_t const * instr ) {
  ulong total_lamports = 0;

  for( ulong i = 0; i < instr->acct_cnt; i++ ) {

    if( instr->borrowed_accounts[i] == NULL ) {
      continue;
    }

    if( ( instr->is_duplicate[i]                          ) |
        ( instr->borrowed_accounts[i]->const_meta == NULL ) ) {
      continue;
    }

    ulong acct_lamports = instr->borrowed_accounts[i]->const_meta->info.lamports;

    if( FD_UNLIKELY( __builtin_uaddl_overflow( total_lamports, acct_lamports, &total_lamports ) ) ) {
      FD_LOG_WARNING(("Sum of lamports exceeds UL MAX", total_lamports));
      return false;
    }
  }
  return true;
}

ulong
fd_exec_instr_test_run( fd_exec_instr_test_runner_t *        runner,
                        fd_exec_test_instr_context_t const * input,
                        fd_exec_test_instr_effects_t **      output,
                        void *                               output_buf,
                        ulong                                output_bufsz ) {

  /* Convert the Protobuf inputs to a fd_exec context */

  fd_exec_instr_ctx_t ctx[1];
  if( !_context_create( runner, ctx, input ) )
    return 0UL;

  fd_instr_info_t * instr = (fd_instr_info_t *) ctx->instr;

  /* Check lamports beforehand to ensure we don't crash during test execution */
  if (!fd_instr_info_sum_account_lamports_no_crash(instr)) {
    _context_destroy( runner, ctx );
    return 0UL;
  }

  /* Execute the test */
  int exec_result = fd_execute_instr(ctx->txn_ctx, instr);

  /* Allocate space to capture outputs */

  ulong output_end = (ulong)output_buf + output_bufsz;
  FD_SCRATCH_ALLOC_INIT( l, output_buf );

  fd_exec_test_instr_effects_t * effects =
    FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_exec_test_instr_effects_t),
                                sizeof (fd_exec_test_instr_effects_t) );
  if( FD_UNLIKELY( _l > output_end ) ) {
    _context_destroy( runner, ctx );
    return 0UL;
  }
  fd_memset( effects, 0, sizeof(fd_exec_test_instr_effects_t) );

  /* Capture error code */

  if( exec_result )
    effects->result = -exec_result;
  else
    effects->result = 0;
  effects->cu_avail = ctx->txn_ctx->compute_meter;

  if( exec_result == FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR ) {
    effects->has_custom_err = 1;
    effects->custom_err     = ctx->txn_ctx->custom_err;
  }

  /* Allocate space for captured accounts */

  fd_funk_t *     funk     = runner->funk;
  fd_funk_txn_t * funk_txn = ctx->funk_txn;

  ulong modified_acct_cnt = ctx->txn_ctx->accounts_cnt;

  fd_exec_test_acct_state_t * modified_accts =
    FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_exec_test_acct_state_t),
                                sizeof (fd_exec_test_acct_state_t) * modified_acct_cnt );
  if( FD_UNLIKELY( _l > output_end ) ) {
    _context_destroy( runner, ctx );
    return 0;
  }
  effects->modified_accounts       = modified_accts;
  effects->modified_accounts_count = 0UL;

  /* Capture borrowed accounts */

  for( ulong j=0UL; j < ctx->txn_ctx->accounts_cnt; j++ ) {
    fd_borrowed_account_t * acc = &ctx->txn_ctx->borrowed_accounts[j];
    if( !acc->meta ) continue;

    ulong modified_idx = effects->modified_accounts_count;
    assert( modified_idx < modified_acct_cnt );

    fd_exec_test_acct_state_t * out_acct = &effects->modified_accounts[ modified_idx ];
    memset( out_acct, 0, sizeof(fd_exec_test_acct_state_t) );
    /* Copy over account content */

    out_acct->has_address = 1;
    memcpy( out_acct->address, acc->pubkey, sizeof(fd_pubkey_t) );

    out_acct->has_lamports = 1;
    out_acct->lamports     = acc->meta->info.lamports;

    out_acct->data =
      FD_SCRATCH_ALLOC_APPEND( l, alignof(pb_bytes_array_t),
                                  PB_BYTES_ARRAY_T_ALLOCSIZE( acc->const_meta->dlen ) );
    if( FD_UNLIKELY( _l > output_end ) ) {
      _context_destroy( runner, ctx );
      return 0UL;
    }
    out_acct->data->size = (pb_size_t)acc->const_meta->dlen;
    fd_memcpy( out_acct->data->bytes, acc->const_data, acc->const_meta->dlen );

    out_acct->has_executable = 1;
    out_acct->executable     = acc->meta->info.executable;

    out_acct->has_rent_epoch = 1;
    out_acct->rent_epoch     = acc->meta->info.rent_epoch;

    out_acct->has_owner = 1;
    memcpy( out_acct->owner, acc->meta->info.owner, sizeof(fd_pubkey_t) );

    effects->modified_accounts_count++;

    /* Delete funk record */
    fd_funk_rec_key_t rec_key = fd_acc_funk_key( acc->pubkey );
    fd_funk_rec_t const * rec_ = fd_funk_rec_query( funk, funk_txn, &rec_key );
    fd_funk_rec_t * rec = fd_funk_rec_modify( funk, rec_ );
    fd_funk_rec_remove( funk, rec, 1 );
  }

  /* TODO verify that there are no outstanding funk records */

  ulong actual_end = FD_SCRATCH_ALLOC_FINI( l, 1UL );
  _context_destroy( runner, ctx );

  *output = effects;
  return actual_end - (ulong)output_buf;
}
