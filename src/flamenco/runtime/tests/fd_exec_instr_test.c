
#include "generated/invoke.pb.h"
#undef FD_SCRATCH_USE_HANDHOLDING
#define FD_SCRATCH_USE_HANDHOLDING 1
#include "fd_exec_instr_test.h"
#include "../fd_acc_mgr.h"
#include "../fd_account.h"
#include "../fd_executor.h"
#include "../fd_runtime.h"
#include "../program/fd_bpf_loader_program.h"
#include "../program/fd_bpf_program_util.h"
#include "../program/fd_builtin_programs.h"
#include "../context/fd_exec_epoch_ctx.h"
#include "../context/fd_exec_slot_ctx.h"
#include "../context/fd_exec_txn_ctx.h"
#include "../sysvar/fd_sysvar_recent_hashes.h"
#include "../sysvar/fd_sysvar_last_restart_slot.h"
#include "../sysvar/fd_sysvar_slot_hashes.h"
#include "../sysvar/fd_sysvar_stake_history.h"
#include "../sysvar/fd_sysvar_epoch_rewards.h"
#include "../../../funk/fd_funk.h"
#include "../../../util/bits/fd_float.h"
#include "../../../ballet/sbpf/fd_sbpf_loader.h"
#include "../../../ballet/elf/fd_elf.h"
#include "../../vm/fd_vm.h"
#include <assert.h>
#include "../sysvar/fd_sysvar_cache.h"
#include "../sysvar/fd_sysvar_epoch_schedule.h"
#include "../sysvar/fd_sysvar_clock.h"
#include "../../../ballet/pack/fd_pack.h"
#include "fd_vm_test.h"

#pragma GCC diagnostic ignored "-Wformat-extra-args"

/* LOGFMT_REPORT is the log prefix for instruction processing tests */

#define LOGFMT_REPORT "%s"
static FD_TL char _report_prefix[100] = {0};

#define REPORTV( level, fmt, ... ) \
  FD_LOG_##level(( LOGFMT_REPORT fmt, _report_prefix, __VA_ARGS__ ))

#define REPORT( level, fmt ) REPORTV( level, fmt, 0 )

#define REPORT_ACCTV( level, addr, fmt, ... )                                  \
  do {                                                                         \
    char         _acct_log_private_addr[ FD_BASE58_ENCODED_32_SZ ];            \
    void const * _acct_log_private_addr_ptr = (addr);                          \
    fd_acct_addr_cstr( _acct_log_private_addr, _acct_log_private_addr_ptr );        \
    REPORTV( level, " account %s: " fmt, _acct_log_private_addr, __VA_ARGS__ ); \
  } while(0);

#define REPORT_ACCT( level, addr, fmt ) REPORT_ACCTV( level, addr, fmt, 0 )

/* Define routine to sort accounts to support query-by-pubkey via
   binary search. */

#define SORT_NAME sort_pubkey_p
#define SORT_KEY_T void const *
#define SORT_BEFORE(a,b) ( memcmp( (a), (b), sizeof(fd_pubkey_t) )<0 )
#include "../../../util/tmpl/fd_sort.c"
#include "../../vm/fd_vm_base.h"

struct __attribute__((aligned(32UL))) fd_exec_instr_test_runner_private {
  fd_funk_t * funk;
  fd_spad_t * spad;
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
                               void * spad_mem,
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

  fd_exec_instr_test_runner_t * runner = runner_mem;
  runner->funk = funk;

  /* Create spad */
  runner->spad = fd_spad_join( fd_spad_new( spad_mem, fd_spad_footprint( MAX_TX_ACCOUNT_LOCKS * fd_ulong_align_up( FD_ACC_TOT_SZ_MAX, FD_ACCOUNT_REC_ALIGN ) ) ) );
  return runner;
}

void *
fd_exec_instr_test_runner_delete( fd_exec_instr_test_runner_t * runner ) {
  if( FD_UNLIKELY( !runner ) ) return NULL;
  fd_funk_delete( fd_funk_leave( runner->funk ) );
  runner->funk = NULL;
  runner->spad = NULL;
  return runner;
}

static int
fd_double_is_normal( double dbl ) {
  ulong x = fd_dblbits( dbl );
  int is_denorm =
    ( fd_dblbits_bexp( x ) == 0 ) &
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
  if( FD_UNLIKELY( fd_acc_mgr_view_raw( acc_mgr, funk_txn, pubkey, NULL, NULL, NULL) ) )
    return 0;

  assert( acc_mgr->funk );
  assert( acc_mgr->funk->magic == FD_FUNK_MAGIC );
  fd_funk_start_write( acc_mgr->funk );
  int err = fd_acc_mgr_modify( /* acc_mgr     */ acc_mgr,
                               /* txn         */ funk_txn,
                               /* pubkey      */ pubkey,
                               /* do_create   */ 1,
                               /* min_data_sz */ size,
                               acc );
  assert( err==FD_ACC_MGR_SUCCESS );
  if( state->data ) fd_memcpy( acc->data, state->data->bytes, size );

  acc->starting_lamports     = state->lamports;
  acc->starting_dlen         = size;
  acc->meta->info.lamports   = state->lamports;
  acc->meta->info.executable = state->executable;
  acc->meta->info.rent_epoch = state->rent_epoch;
  acc->meta->dlen            = size;
  memcpy( acc->meta->info.owner, state->owner, sizeof(fd_pubkey_t) );

  /* make the account read-only by default */
  acc->meta = NULL;
  acc->data = NULL;
  acc->rec  = NULL;
  fd_funk_end_write( acc_mgr->funk );

  return 1;
}

static int
_load_txn_account( fd_borrowed_account_t *           acc,
                   fd_acc_mgr_t *                    acc_mgr,
                   fd_funk_txn_t *                   funk_txn,
                   fd_exec_test_acct_state_t const * state ) {
  // In the Agave transaction fuzzing harness, accounts with 0 lamports are not saved in the accounts db.
  // When they are fetched for transactions, the fields of the account are 0-set.
  fd_exec_test_acct_state_t account_state_to_save = FD_EXEC_TEST_ACCT_STATE_INIT_ZERO;
  memcpy( account_state_to_save.address, state->address, sizeof(fd_pubkey_t) );

  // Restore the account state if it has lamports
  if( state->lamports ) {
    account_state_to_save = *state;
  }

  return _load_account( acc, acc_mgr, funk_txn, &account_state_to_save );
}

int
_restore_feature_flags( fd_exec_epoch_ctx_t *              epoch_ctx,
                        fd_exec_test_feature_set_t const * feature_set ) {
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
  return 1;
}

int
fd_exec_test_instr_context_create( fd_exec_instr_test_runner_t *        runner,
                                   fd_exec_instr_ctx_t *                ctx,
                                   fd_exec_test_instr_context_t const * test_ctx,
                                   fd_alloc_t *                         alloc,
                                   bool                                 is_syscall ) {
  memset( ctx, 0, sizeof(fd_exec_instr_ctx_t) );

  fd_funk_t * funk = runner->funk;

  /* Generate unique ID for funk txn */

  fd_funk_txn_xid_t xid[1] = {0};
  xid[0] = fd_funk_generate_xid();

  /* Create temporary funk transaction and scratch contexts */

  fd_funk_start_write( funk );
  fd_funk_txn_t * funk_txn = fd_funk_txn_prepare( funk, NULL, xid, 1 );
  fd_funk_end_write( funk );
  fd_scratch_push();

  ulong vote_acct_max = MAX_TX_ACCOUNT_LOCKS;

  /* Allocate contexts */
  uchar *               epoch_ctx_mem = fd_scratch_alloc( fd_exec_epoch_ctx_align(), fd_exec_epoch_ctx_footprint( vote_acct_max ) );
  uchar *               slot_ctx_mem  = fd_scratch_alloc( FD_EXEC_SLOT_CTX_ALIGN,  FD_EXEC_SLOT_CTX_FOOTPRINT  );
  uchar *               txn_ctx_mem   = fd_scratch_alloc( FD_EXEC_TXN_CTX_ALIGN,   FD_EXEC_TXN_CTX_FOOTPRINT   );

  fd_exec_epoch_ctx_t * epoch_ctx     = fd_exec_epoch_ctx_join( fd_exec_epoch_ctx_new( epoch_ctx_mem, vote_acct_max ) );
  fd_exec_slot_ctx_t *  slot_ctx      = fd_exec_slot_ctx_join ( fd_exec_slot_ctx_new ( slot_ctx_mem, fd_alloc_virtual( alloc ) ) );
  fd_exec_txn_ctx_t *   txn_ctx       = fd_exec_txn_ctx_join  ( fd_exec_txn_ctx_new  ( txn_ctx_mem   ) );

  assert( epoch_ctx );
  assert( slot_ctx  );

  ctx->slot_ctx   = slot_ctx;
  ctx->txn_ctx    = txn_ctx;
  txn_ctx->valloc = slot_ctx->valloc;

  /* Initial variables */
  txn_ctx->loaded_accounts_data_size_limit = FD_VM_LOADED_ACCOUNTS_DATA_SIZE_LIMIT;
  txn_ctx->heap_size                       = FD_VM_HEAP_DEFAULT;

  /* Set up epoch context. Defaults obtained from GenesisConfig::Default() */
  fd_epoch_bank_t * epoch_bank = fd_exec_epoch_ctx_epoch_bank( epoch_ctx );
  epoch_bank->rent.lamports_per_uint8_year = 3480;
  epoch_bank->rent.exemption_threshold = 2;
  epoch_bank->rent.burn_percent = 50;

  /* Create account manager */

  fd_acc_mgr_t * acc_mgr = fd_acc_mgr_new( fd_scratch_alloc( FD_ACC_MGR_ALIGN, FD_ACC_MGR_FOOTPRINT ), funk );
  assert( acc_mgr );

  /* Set up slot context */

  slot_ctx->epoch_ctx = epoch_ctx;
  slot_ctx->funk_txn  = funk_txn;
  slot_ctx->acc_mgr   = acc_mgr;

  /* Restore feature flags */

  fd_exec_test_feature_set_t const * feature_set = &test_ctx->epoch_context.features;
  if( !_restore_feature_flags( epoch_ctx, feature_set ) ) {
    return 0;
  }

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
  txn_ctx->instr_err_idx           = INT_MAX;
  txn_ctx->capture_ctx             = NULL;
  txn_ctx->vote_accounts_pool      = NULL;
  txn_ctx->accounts_resize_delta   = 0;
  txn_ctx->instr_info_cnt          = 0;
  txn_ctx->instr_trace_length      = 0;
  txn_ctx->exec_err                = 0;
  txn_ctx->exec_err_kind           = FD_EXECUTOR_ERR_KIND_EBPF;

  memset( txn_ctx->_txn_raw, 0, sizeof(fd_rawtxn_b_t) );
  memset( txn_ctx->return_data.program_id.key, 0, sizeof(fd_pubkey_t) );
  txn_ctx->return_data.len         = 0;
  txn_ctx->spad                    = runner->spad;

  /* Set up instruction context */

  fd_instr_info_t * info = fd_valloc_malloc( fd_scratch_virtual(), 8UL, sizeof(fd_instr_info_t) );
  assert( info );
  memset( info, 0, sizeof(fd_instr_info_t) );

  if( test_ctx->data ) {
    info->data_sz = (ushort)test_ctx->data->size;
    info->data    = test_ctx->data->bytes;
  }

  memcpy( info->program_id_pubkey.uc, test_ctx->program_id, sizeof(fd_pubkey_t) );

  /* Prepare borrowed account table (correctly handles aliasing) */

  if( FD_UNLIKELY( test_ctx->accounts_count > MAX_TX_ACCOUNT_LOCKS ) ) {
    REPORT( NOTICE, "too many accounts" );
    return 0;
  }

  fd_borrowed_account_t * borrowed_accts = txn_ctx->borrowed_accounts;
  fd_memset( borrowed_accts, 0, test_ctx->accounts_count * sizeof(fd_borrowed_account_t) );
  txn_ctx->accounts_cnt = test_ctx->accounts_count;
  for ( uint i = 0; i < test_ctx->accounts_count; i++ ) {
    memcpy( &(txn_ctx->accounts[i]), test_ctx->accounts[i].address, sizeof(fd_pubkey_t) );
  }
  fd_txn_t * txn_descriptor = (fd_txn_t *) fd_scratch_alloc( fd_txn_align(), fd_txn_footprint(1, 0) );
  fd_memset(txn_descriptor, 0, fd_txn_footprint(1, 0) );
  txn_descriptor->acct_addr_cnt = (ushort) test_ctx->accounts_count;
  txn_descriptor->addr_table_adtl_cnt = 0;
  txn_ctx->txn_descriptor = txn_descriptor;

  /* Precompiles are allowed to read data from all instructions.
     We need to at least set pointers to the current instruction.
     Note: for simplicity we point the entire raw tx data to the
     instruction data, this is probably something we can improve. */
  txn_descriptor->instr_cnt = 1;
  txn_ctx->_txn_raw->raw = info->data;
  txn_descriptor->instr[0].data_off = 0;
  txn_descriptor->instr[0].data_sz = info->data_sz;

  /* Load accounts into database */

  assert( acc_mgr->funk );
  for( ulong j=0UL; j < test_ctx->accounts_count; j++ ) {
    if( !_load_account( &borrowed_accts[j], acc_mgr, funk_txn, &test_ctx->accounts[j] ) ) {
      return 0;
    }

    if( borrowed_accts[j].const_meta ) {
      uchar * data = fd_spad_alloc( txn_ctx->spad, FD_ACCOUNT_REC_ALIGN, FD_ACC_TOT_SZ_MAX );
      ulong   dlen = borrowed_accts[j].const_meta->dlen;
      fd_memcpy( data, borrowed_accts[j].const_meta, sizeof(fd_account_meta_t)+dlen );
      borrowed_accts[j].const_meta = (fd_account_meta_t*)data;
      borrowed_accts[j].const_data = data + sizeof(fd_account_meta_t);
    }
  }

  /* Load in executable accounts */
  for( ulong i = 0; i < txn_ctx->accounts_cnt; i++ ) {
    if ( memcmp( borrowed_accts[i].const_meta->info.owner, fd_solana_bpf_loader_deprecated_program_id.key, sizeof(fd_pubkey_t) ) != 0
      && memcmp( borrowed_accts[i].const_meta->info.owner, fd_solana_bpf_loader_program_id.key, sizeof(fd_pubkey_t) ) != 0
      && memcmp( borrowed_accts[i].const_meta->info.owner, fd_solana_bpf_loader_upgradeable_program_id.key, sizeof(fd_pubkey_t) ) != 0
      && memcmp( borrowed_accts[i].const_meta->info.owner, fd_solana_bpf_loader_v4_program_id.key, sizeof(fd_pubkey_t) ) != 0
    ) {
      continue;
    }

    fd_account_meta_t const * meta = borrowed_accts[i].const_meta ? borrowed_accts[i].const_meta : borrowed_accts[i].meta;
    if (meta == NULL) {
      static const fd_account_meta_t sentinel = { .magic = FD_ACCOUNT_META_MAGIC };
      borrowed_accts[i].const_meta        = &sentinel;
      borrowed_accts[i].starting_lamports = 0UL;
      borrowed_accts[i].starting_dlen     = 0UL;
      continue;
    }

    if( meta->info.executable ) {
      FD_BORROWED_ACCOUNT_DECL(owner_borrowed_account);
      int err = fd_acc_mgr_view( txn_ctx->acc_mgr, txn_ctx->funk_txn, (fd_pubkey_t *)meta->info.owner, owner_borrowed_account );
      if( FD_UNLIKELY( err ) ) {
        borrowed_accts[i].starting_owner_dlen = 0;
      } else {
        borrowed_accts[i].starting_owner_dlen = owner_borrowed_account->const_meta->dlen;
      }
    }

    if ( FD_UNLIKELY( 0 == memcmp(meta->info.owner, fd_solana_bpf_loader_upgradeable_program_id.key, sizeof(fd_pubkey_t)) ) ) {
      fd_bpf_upgradeable_loader_state_t program_loader_state = {0};
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
  fd_funk_start_write( acc_mgr->funk );
  fd_bpf_scan_and_create_bpf_program_cache_entry( slot_ctx, funk_txn );
  fd_funk_end_write( acc_mgr->funk );

  /* Restore sysvar cache */
  fd_sysvar_cache_restore( slot_ctx->sysvar_cache, acc_mgr, funk_txn );

  /* Fill missing sysvar cache values with defaults */
  /* We create mock accounts for each of the sysvars and hardcode the data fields before loading it into the account manager */
  /* We use Agave sysvar defaults for data field values */

  /* Clock */
  // https://github.com/firedancer-io/solfuzz-agave/blob/agave-v2.0/src/lib.rs#L466-L474
  if( !slot_ctx->sysvar_cache->has_clock ) {
    slot_ctx->sysvar_cache->has_clock = 1;
    fd_sol_sysvar_clock_t sysvar_clock = {
                                          .slot = 10,
                                          .epoch_start_timestamp = 0,
                                          .epoch = 0,
                                          .leader_schedule_epoch = 0,
                                          .unix_timestamp = 0
                                        };
    memcpy( slot_ctx->sysvar_cache->val_clock, &sysvar_clock, sizeof(fd_sol_sysvar_clock_t) );
  }

  /* Epoch schedule */
  // https://github.com/firedancer-io/solfuzz-agave/blob/agave-v2.0/src/lib.rs#L476-L483
  if ( !slot_ctx->sysvar_cache->has_epoch_schedule ) {
    slot_ctx->sysvar_cache->has_epoch_schedule = 1;
    fd_epoch_schedule_t sysvar_epoch_schedule = {
                                                  .slots_per_epoch = 432000,
                                                  .leader_schedule_slot_offset = 432000,
                                                  .warmup = 1,
                                                  .first_normal_epoch = 14,
                                                  .first_normal_slot = 524256
                                                };
    memcpy( slot_ctx->sysvar_cache->val_epoch_schedule, &sysvar_epoch_schedule, sizeof(fd_epoch_schedule_t) );
  }

  /* Rent */
  // https://github.com/firedancer-io/solfuzz-agave/blob/agave-v2.0/src/lib.rs#L487-L500
  if ( !slot_ctx->sysvar_cache->has_rent ) {
    slot_ctx->sysvar_cache->has_rent = 1;
    fd_rent_t sysvar_rent = {
                              .lamports_per_uint8_year = 3480,
                              .exemption_threshold = 2.0,
                              .burn_percent = 50
                            };
    memcpy( slot_ctx->sysvar_cache->val_rent, &sysvar_rent, sizeof(fd_rent_t) );
  }

  if ( !slot_ctx->sysvar_cache->has_last_restart_slot ) {
    slot_ctx->sysvar_cache->has_last_restart_slot = 1;

    fd_sol_sysvar_last_restart_slot_t restart = {.slot = 5000};

    memcpy( slot_ctx->sysvar_cache->val_last_restart_slot, &restart, sizeof(fd_sol_sysvar_last_restart_slot_t) );
  }

  /* Set slot bank variables */
  slot_ctx->slot_bank.slot = fd_sysvar_cache_clock( slot_ctx->sysvar_cache )->slot;

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
      slot_ctx->prev_lamports_per_signature = last->fee_calculator.lamports_per_signature;
    }
  }

  /* Load instruction accounts */

  if( FD_UNLIKELY( test_ctx->instr_accounts_count > MAX_TX_ACCOUNT_LOCKS ) ) {
    REPORT( NOTICE, "too many instruction accounts" );
    return 0;
  }

  uchar acc_idx_seen[256] = {0};
  for( ulong j=0UL; j < test_ctx->instr_accounts_count; j++ ) {
    uint index = test_ctx->instr_accounts[j].index;
    if( index >= test_ctx->accounts_count ) {
      REPORTV( NOTICE, " instruction account index out of range (%u > %u)", index, test_ctx->instr_accounts_count );
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

    if( test_ctx->instr_accounts[j].is_writable ) {
      acc->meta = (void *)acc->const_meta;
      acc->data = (void *)acc->const_data;
      acc->rec  = (void *)acc->const_rec;
    }

    if (acc_idx_seen[index]) {
      info->is_duplicate[j] = 1;
    }
    acc_idx_seen[index] = 1;
  }
  info->acct_cnt = (uchar)test_ctx->instr_accounts_count;

  //  FIXME: Specifically for CPI syscalls, flag guard this?
  fd_instr_info_sum_account_lamports( info, &info->starting_lamports_h, &info->starting_lamports_l );

  /* The remaining checks enforce that the program is one of the accounts and
    owned by native loader. */
  bool found_program_id = false;
  for( uint i = 0; i < test_ctx->accounts_count; i++ ) {
    if( 0 == memcmp( test_ctx->accounts[i].address, test_ctx->program_id, sizeof(fd_pubkey_t) ) ) {
      info->program_id = (uchar) i;
      found_program_id = true;
      break;
    }
  }

  /* Aborting is only important for instr execution */
  if( !is_syscall && !found_program_id ) {
    FD_LOG_NOTICE(( " Unable to find program_id in accounts" ));
    return 0;
  }

  ctx->epoch_ctx = epoch_ctx;
  ctx->funk_txn  = funk_txn;
  ctx->acc_mgr   = acc_mgr;
  ctx->valloc    = fd_scratch_virtual();
  ctx->instr     = info;

  fd_log_collector_init( &ctx->txn_ctx->log_collector, 1 );
  fd_base58_encode_32( ctx->instr->program_id_pubkey.uc, NULL, ctx->program_id_base58 );

  return 1;
}

static void
_add_to_data(uchar ** data, void const * to_add, ulong size) {
  while( size-- ) {
    **data = *(uchar *)to_add;
    (*data)++;
    to_add = (uchar *)to_add + 1;
  }
}

static void
_add_compact_u16(uchar ** data, ushort to_add) {
  fd_bincode_encode_ctx_t encode_ctx = { .data = *data, .dataend = *data + 3 };  // Up to 3 bytes
  fd_bincode_compact_u16_encode( &to_add, &encode_ctx );
  *data = (uchar *) encode_ctx.data;
}

static fd_execute_txn_task_info_t *
_txn_context_create_and_exec( fd_exec_instr_test_runner_t *      runner,
                              fd_exec_slot_ctx_t *               slot_ctx,
                              fd_exec_test_txn_context_t const * test_ctx ) {
  uchar empty_bytes[64] = { 0 };
  fd_funk_t * funk = runner->funk;

  /* Generate unique ID for funk txn */

  fd_funk_txn_xid_t xid[1] = {0};
  xid[0] = fd_funk_generate_xid();

  /* Create temporary funk transaction and scratch contexts */

  fd_funk_start_write( runner->funk );
  fd_funk_txn_t * funk_txn = fd_funk_txn_prepare( funk, NULL, xid, 1 );
  fd_funk_end_write( runner->funk );

  ulong vote_acct_max = MAX_TX_ACCOUNT_LOCKS;

  /* Allocate contexts */
  uchar *               epoch_ctx_mem = fd_scratch_alloc( fd_exec_epoch_ctx_align(), fd_exec_epoch_ctx_footprint( vote_acct_max ) );
  fd_exec_epoch_ctx_t * epoch_ctx     = fd_exec_epoch_ctx_join( fd_exec_epoch_ctx_new( epoch_ctx_mem, vote_acct_max ) );

  assert( epoch_ctx );
  assert( slot_ctx  );

  /* Set up epoch context */
  fd_epoch_bank_t * epoch_bank = fd_exec_epoch_ctx_epoch_bank( epoch_ctx );

  /* Create account manager */
  fd_acc_mgr_t * acc_mgr = fd_acc_mgr_new( fd_scratch_alloc( FD_ACC_MGR_ALIGN, FD_ACC_MGR_FOOTPRINT ), funk );
  assert( acc_mgr );

  /* Set up slot context */

  slot_ctx->epoch_ctx = epoch_ctx;
  slot_ctx->funk_txn  = funk_txn;
  slot_ctx->acc_mgr   = acc_mgr;

  /* Restore feature flags */

  fd_exec_test_feature_set_t const * feature_set = &test_ctx->epoch_ctx.features;
  if( !_restore_feature_flags( epoch_ctx, feature_set ) ) {
    return NULL;
  }

  /* Restore slot bank */
  fd_slot_bank_new( &slot_ctx->slot_bank );

  /* Initialize builtin accounts */
  fd_funk_start_write( runner->funk );
  fd_builtin_programs_init( slot_ctx );
  fd_funk_end_write( runner->funk );

  /* Load account states into funk (note this is different from the account keys):
    Account state = accounts to populate Funk
    Account keys = account keys that the transaction needs */
  for( ulong i = 0; i < test_ctx->tx.message.account_shared_data_count; i++ ) {
    /* Load the accounts into the account manager
       Borrowed accounts get reset anyways - we just need to load the account somewhere */
    FD_BORROWED_ACCOUNT_DECL(acc);
    _load_txn_account( acc, acc_mgr, funk_txn, &test_ctx->tx.message.account_shared_data[i] );
  }

  /* Restore sysvar cache */
  fd_sysvar_cache_restore( slot_ctx->sysvar_cache, acc_mgr, funk_txn );

  /* Add accounts to bpf program cache */
  fd_funk_start_write( runner->funk );
  fd_bpf_scan_and_create_bpf_program_cache_entry( slot_ctx, funk_txn );

  /* Default slot */
  ulong slot = test_ctx->slot_ctx.slot ? test_ctx->slot_ctx.slot : 10; // Arbitrary default > 0

  /* Set slot bank variables (defaults obtained from GenesisConfig::default() in Agave) */
  slot_ctx->slot_bank.slot                                            = slot;
  slot_ctx->slot_bank.prev_slot                                       = slot_ctx->slot_bank.slot - 1; // Can underflow, but its fine since it will correctly be ULONG_MAX
  slot_ctx->slot_bank.fee_rate_governor.burn_percent                  = 50;
  slot_ctx->slot_bank.fee_rate_governor.min_lamports_per_signature    = 0;
  slot_ctx->slot_bank.fee_rate_governor.max_lamports_per_signature    = 0;
  slot_ctx->slot_bank.fee_rate_governor.target_lamports_per_signature = 10000;
  slot_ctx->slot_bank.fee_rate_governor.target_signatures_per_slot    = 20000;
  slot_ctx->slot_bank.lamports_per_signature                          = 5000;
  slot_ctx->prev_lamports_per_signature                               = 5000;

  /* Set epoch bank variables if not present (defaults obtained from GenesisConfig::default() in Agave) */
  fd_epoch_schedule_t default_epoch_schedule = {
                                                .slots_per_epoch             = 432000,
                                                .leader_schedule_slot_offset = 432000,
                                                .warmup                      = 1,
                                                .first_normal_epoch          = 14,
                                                .first_normal_slot           = 524256
                                               };
  fd_rent_t           default_rent           = {
                                                .lamports_per_uint8_year     = 3480,
                                                .exemption_threshold         = 2.0,
                                                .burn_percent                = 50
                                               };
  epoch_bank->epoch_schedule      = default_epoch_schedule;
  epoch_bank->rent_epoch_schedule = default_epoch_schedule;
  epoch_bank->rent                = default_rent;
  epoch_bank->ticks_per_slot      = 64;
  epoch_bank->slots_per_year      = SECONDS_PER_YEAR * (1000000000.0 / (double)6250000) / (double)epoch_bank->ticks_per_slot;

  // Override default values if provided
  if( slot_ctx->sysvar_cache->has_epoch_schedule ) {
    epoch_bank->epoch_schedule      = *slot_ctx->sysvar_cache->val_epoch_schedule;
    epoch_bank->rent_epoch_schedule = *slot_ctx->sysvar_cache->val_epoch_schedule;
  }

  if( slot_ctx->sysvar_cache->has_rent ) {
    epoch_bank->rent = *slot_ctx->sysvar_cache->val_rent;
  }

  /* Provde default slot hashes of size 1 if not provided */
  if( !slot_ctx->sysvar_cache->has_slot_hashes ) {
    fd_slot_hash_t * slot_hashes = deq_fd_slot_hash_t_alloc( fd_scratch_virtual(), 1 );
    fd_slot_hash_t * dummy_elem = deq_fd_slot_hash_t_push_tail_nocopy( slot_hashes );
    memset( dummy_elem, 0, sizeof(fd_slot_hash_t) );
    fd_slot_hashes_t default_slot_hashes = { .hashes = slot_hashes };
    fd_sysvar_slot_hashes_init( slot_ctx, &default_slot_hashes );
  }

  /* Provide default stake history if not provided */
  if( !slot_ctx->sysvar_cache->has_stake_history ) {
    // Provide a 0-set default entry
    fd_stake_history_entry_t entry = {0};
    fd_sysvar_stake_history_init( slot_ctx );
    fd_sysvar_stake_history_update( slot_ctx, &entry );
  }

  /* Provide default last restart slot sysvar if not provided */
  if( !slot_ctx->sysvar_cache->has_last_restart_slot ) {
    fd_sysvar_last_restart_slot_init( slot_ctx );
  }

  /* Provide a default clock if not present */
  if( !slot_ctx->sysvar_cache->has_clock ) {
    fd_sysvar_clock_init( slot_ctx );
    fd_sysvar_clock_update( slot_ctx );
  }

  /* Epoch schedule and rent get set from the epoch bank */
  fd_sysvar_epoch_schedule_init( slot_ctx );
  fd_sysvar_rent_init( slot_ctx );

  /* Set the epoch rewards sysvar if partition epoch rewards feature is enabled

     TODO: The init parameters are not exactly conformant with Agave's epoch rewards sysvar. We should
     be calling `fd_begin_partitioned_rewards` with the same parameters as Agave. However,
     we just need the `active` field to be conformant due to a single Stake program check.
     THIS MAY CHANGE IN THE FUTURE. If there are other parts of transaction execution that use
     the epoch rewards sysvar, we may need to update this.
  */
  if ( (
      FD_FEATURE_ACTIVE( slot_ctx, enable_partitioned_epoch_reward ) ||
      FD_FEATURE_ACTIVE( slot_ctx, partitioned_epoch_rewards_superfeature )
      ) && !slot_ctx->sysvar_cache->has_epoch_rewards ) {
    fd_point_value_t point_value = {0};
    fd_hash_t const * last_hash = test_ctx->blockhash_queue_count > 0 ? (fd_hash_t const *)test_ctx->blockhash_queue[0]->bytes : (fd_hash_t const *)empty_bytes;
    fd_sysvar_epoch_rewards_init( slot_ctx, 0UL, 0UL, 2UL, 1UL, point_value, last_hash);
  }

  /* Restore sysvar cache (again, since we may need to provide default sysvars) */
  fd_sysvar_cache_restore( slot_ctx->sysvar_cache, acc_mgr, funk_txn );

  /* A NaN rent exemption threshold is U.B. in Solana Labs */
  fd_rent_t const * rent = fd_sysvar_cache_rent( slot_ctx->sysvar_cache );
  if( ( !fd_double_is_normal( rent->exemption_threshold ) ) |
      ( rent->exemption_threshold     <      0.0 ) |
      ( rent->exemption_threshold     >    999.0 ) |
      ( rent->lamports_per_uint8_year > UINT_MAX ) |
      ( rent->burn_percent            >      100 ) )
    return NULL;

  /* Blockhash queue is given in txn message. We need to populate the following three:
     - slot_ctx->slot_bank.block_hash_queue (TODO: Does more than just the last_hash need to be populated?)
     - sysvar_cache_recent_block_hashes
     - slot_ctx->slot_bank.recent_block_hashes */
  ulong num_blockhashes = test_ctx->blockhash_queue_count;

  /* Recent blockhashes init */
  fd_block_block_hash_entry_t * recent_block_hashes = deq_fd_block_block_hash_entry_t_alloc( slot_ctx->valloc, FD_SYSVAR_RECENT_HASHES_CAP );

  /* Blockhash queue init */
  slot_ctx->slot_bank.block_hash_queue.max_age   = FD_BLOCKHASH_QUEUE_MAX_ENTRIES;
  slot_ctx->slot_bank.block_hash_queue.ages_root = NULL;
  slot_ctx->slot_bank.block_hash_queue.ages_pool = fd_hash_hash_age_pair_t_map_alloc( slot_ctx->valloc, 400 );
  slot_ctx->slot_bank.block_hash_queue.last_hash = fd_valloc_malloc( slot_ctx->valloc, FD_HASH_ALIGN, FD_HASH_FOOTPRINT );

  // Save lamports per signature for most recent blockhash, if sysvar cache contains recent block hashes
  fd_recent_block_hashes_t const * rbh = fd_sysvar_cache_recent_block_hashes( slot_ctx->sysvar_cache );
  if( rbh && !deq_fd_block_block_hash_entry_t_empty( rbh->hashes ) ) {
    fd_block_block_hash_entry_t const * last = deq_fd_block_block_hash_entry_t_peek_head_const( rbh->hashes );
    if( last ) {
      slot_ctx->slot_bank.lamports_per_signature = last->fee_calculator.lamports_per_signature;
      slot_ctx->prev_lamports_per_signature      = last->fee_calculator.lamports_per_signature;
    }
  }

  // Clear and reset recent block hashes sysvar
  slot_ctx->sysvar_cache->has_recent_block_hashes         = 1;
  slot_ctx->sysvar_cache->val_recent_block_hashes->hashes = recent_block_hashes;
  slot_ctx->slot_bank.recent_block_hashes.hashes          = recent_block_hashes;

  // Blockhash_queue[end] = last (latest) hash
  // Blockhash_queue[0] = genesis hash
  if( num_blockhashes > 0 ) {
    memcpy( &epoch_bank->genesis_hash, test_ctx->blockhash_queue[0]->bytes, sizeof(fd_hash_t) );

    for( ulong i = 0; i < num_blockhashes; ++i ) {
      // Recent block hashes cap is 150 (actually 151), while blockhash queue capacity is 300 (actually 301)
      fd_block_block_hash_entry_t blockhash_entry;
      memcpy( &blockhash_entry.blockhash, test_ctx->blockhash_queue[i]->bytes, sizeof(fd_hash_t) );
      slot_ctx->slot_bank.poh = blockhash_entry.blockhash;
      fd_sysvar_recent_hashes_update( slot_ctx );
    }
  } else {
    // Add a default empty blockhash and use it as genesis
    num_blockhashes = 1;
    memcpy( &epoch_bank->genesis_hash, empty_bytes, sizeof(fd_hash_t) );
    fd_block_block_hash_entry_t blockhash_entry;
    memcpy( &blockhash_entry.blockhash, empty_bytes, sizeof(fd_hash_t) );
    slot_ctx->slot_bank.poh = blockhash_entry.blockhash;
    fd_sysvar_recent_hashes_update( slot_ctx );
  }
  fd_funk_end_write( runner->funk );

  /* Create the raw txn (https://solana.com/docs/core/transactions#transaction-size) */
  uchar * txn_raw_begin = fd_scratch_alloc( alignof(uchar), 10000 ); // max txn size is 1232 but we allocate extra for safety
  uchar * txn_raw_cur_ptr = txn_raw_begin;

  /* Compact array of signatures (https://solana.com/docs/core/transactions#transaction)
     Note that although documentation interchangably refers to the signature cnt as a compact-u16
     and a u8, the max signature cnt is capped at 48 (due to txn size limits), so u8 and compact-u16
     is represented the same way anyways and can be parsed identically. */
  // Note: always create a valid txn with 1+ signatures, add an empty signature if none is provided
  uchar signature_cnt = fd_uchar_max( 1, (uchar) test_ctx->tx.signatures_count );
  _add_to_data( &txn_raw_cur_ptr, &signature_cnt, sizeof(uchar) );
  for( uchar i = 0; i < signature_cnt; ++i ) {
    _add_to_data( &txn_raw_cur_ptr, test_ctx->tx.signatures && test_ctx->tx.signatures[i] ? test_ctx->tx.signatures[i]->bytes : empty_bytes, FD_TXN_SIGNATURE_SZ );
  }

  /* Message */
  /* For v0 transactions, the highest bit of the num_required_signatures is set, and an extra byte is used for the version.
     https://solanacookbook.com/guides/versioned-transactions.html#versioned-transactions-transactionv0

     We will always create a transaction with at least 1 signature, and cap the signature count to 127 to avoid
     collisions with the header_b0 tag. */
  uchar num_required_signatures = fd_uchar_max( 1, fd_uchar_min( 127, (uchar) test_ctx->tx.message.header.num_required_signatures ) );
  if( !test_ctx->tx.message.is_legacy ) {
    uchar header_b0 = (uchar) 0x80UL;
    _add_to_data( &txn_raw_cur_ptr, &header_b0, sizeof(uchar) );
  }

  /* Header (3 bytes) (https://solana.com/docs/core/transactions#message-header) */
  _add_to_data( &txn_raw_cur_ptr, &num_required_signatures, sizeof(uchar) );
  _add_to_data( &txn_raw_cur_ptr, &test_ctx->tx.message.header.num_readonly_signed_accounts, sizeof(uchar) );
  _add_to_data( &txn_raw_cur_ptr, &test_ctx->tx.message.header.num_readonly_unsigned_accounts, sizeof(uchar) );

  /* Compact array of account addresses (https://solana.com/docs/core/transactions#compact-array-format) */
  // Array length is a compact u16
  ushort num_acct_keys = (ushort) test_ctx->tx.message.account_keys_count;
  _add_compact_u16( &txn_raw_cur_ptr, num_acct_keys );
  for( ushort i = 0; i < num_acct_keys; ++i ) {
    _add_to_data( &txn_raw_cur_ptr, test_ctx->tx.message.account_keys[i]->bytes, sizeof(fd_pubkey_t) );
  }

  /* Recent blockhash (32 bytes) (https://solana.com/docs/core/transactions#recent-blockhash) */
  // Note: add an empty blockhash if none is provided
  _add_to_data( &txn_raw_cur_ptr, test_ctx->tx.message.recent_blockhash ? test_ctx->tx.message.recent_blockhash->bytes : empty_bytes, sizeof(fd_hash_t) );

  /* Compact array of instructions (https://solana.com/docs/core/transactions#array-of-instructions) */
  // Instruction count is a compact u16
  ushort instr_count = (ushort) test_ctx->tx.message.instructions_count;
  _add_compact_u16( &txn_raw_cur_ptr, instr_count );
  for( ushort i = 0; i < instr_count; ++i ) {
    // Program ID index
    uchar program_id_index = (uchar) test_ctx->tx.message.instructions[i].program_id_index;
    _add_to_data( &txn_raw_cur_ptr, &program_id_index, sizeof(uchar) );

    // Compact array of account addresses
    ushort acct_count = (ushort) test_ctx->tx.message.instructions[i].accounts_count;
    _add_compact_u16( &txn_raw_cur_ptr, acct_count );
    for( ushort j = 0; j < acct_count; ++j ) {
      uchar account_index = (uchar) test_ctx->tx.message.instructions[i].accounts[j];
      _add_to_data( &txn_raw_cur_ptr, &account_index, sizeof(uchar) );
    }

    // Compact array of 8-bit data
    pb_bytes_array_t * data = test_ctx->tx.message.instructions[i].data;
    if( data ) {
      ushort data_len = (ushort) data->size;
      _add_compact_u16( &txn_raw_cur_ptr, data_len );
      _add_to_data( &txn_raw_cur_ptr, data->bytes, data_len );
    } else {
      _add_compact_u16( &txn_raw_cur_ptr, 0 );
    }
  }

  /* Address table lookups (N/A for legacy transactions) */
  ushort addr_table_cnt = 0;
  if( !test_ctx->tx.message.is_legacy ) {
    /* Compact array of address table lookups (https://solanacookbook.com/guides/versioned-transactions.html#compact-array-of-address-table-lookups) */
    // NOTE: The diagram is slightly wrong - the account key is a 32 byte pubkey, not a u8
    addr_table_cnt = (ushort) test_ctx->tx.message.address_table_lookups_count;
    _add_compact_u16( &txn_raw_cur_ptr, addr_table_cnt );
    for( ushort i = 0; i < addr_table_cnt; ++i ) {
      // Account key
      _add_to_data( &txn_raw_cur_ptr, test_ctx->tx.message.address_table_lookups[i].account_key, sizeof(fd_pubkey_t) );

      // Compact array of writable indexes
      ushort writable_count = (ushort) test_ctx->tx.message.address_table_lookups[i].writable_indexes_count;
      _add_compact_u16( &txn_raw_cur_ptr, writable_count );
      for( ushort j = 0; j < writable_count; ++j ) {
        uchar writable_index = (uchar) test_ctx->tx.message.address_table_lookups[i].writable_indexes[j];
        _add_to_data( &txn_raw_cur_ptr, &writable_index, sizeof(uchar) );
      }

      // Compact array of readonly indexes
      ushort readonly_count = (ushort) test_ctx->tx.message.address_table_lookups[i].readonly_indexes_count;
      _add_compact_u16( &txn_raw_cur_ptr, readonly_count );
      for( ushort j = 0; j < readonly_count; ++j ) {
        uchar readonly_index = (uchar) test_ctx->tx.message.address_table_lookups[i].readonly_indexes[j];
        _add_to_data( &txn_raw_cur_ptr, &readonly_index, sizeof(uchar) );
      }
    }
  }

  /* Set up txn descriptor from raw data */
  fd_txn_t * txn_descriptor = (fd_txn_t *) fd_scratch_alloc( fd_txn_align(), fd_txn_footprint( instr_count, addr_table_cnt ) );
  ushort txn_raw_sz = (ushort) (txn_raw_cur_ptr - txn_raw_begin);
  if( !fd_txn_parse( txn_raw_begin, txn_raw_sz, txn_descriptor, NULL ) ) {
    FD_LOG_WARNING(("could not parse txn descriptor"));
    return NULL;
  }

  /* Run txn preparation phases and execution
     NOTE: This should be modified accordingly if transaction setup logic changes */
  fd_txn_p_t * txn = fd_scratch_alloc( alignof(fd_txn_p_t), sizeof(fd_txn_p_t) );
  memcpy( txn->payload, txn_raw_begin, txn_raw_sz );
  txn->payload_sz = (ulong) txn_raw_sz;
  txn->flags = FD_TXN_P_FLAGS_SANITIZE_SUCCESS;
  memcpy( txn->_, txn_descriptor, fd_txn_footprint( instr_count, addr_table_cnt ) );

  fd_execute_txn_task_info_t * task_info = fd_scratch_alloc( alignof(fd_execute_txn_task_info_t), sizeof(fd_execute_txn_task_info_t) );
  memset( task_info, 0, sizeof(fd_execute_txn_task_info_t) );
  task_info->txn = txn;

  fd_tpool_t tpool[1];
  tpool->worker_cnt = 1;
  tpool->worker_max = 1;

  fd_runtime_prepare_txns_start( slot_ctx, task_info, txn, 1UL );

  /* Setup the spad for account allocation */
  task_info->txn_ctx->spad = runner->spad;

  fd_runtime_pre_execute_check( task_info );

  if( !task_info->exec_res ) {
    task_info->txn->flags |= FD_TXN_P_FLAGS_EXECUTE_SUCCESS;
    task_info->exec_res    = fd_execute_txn( task_info->txn_ctx );
  }

  slot_ctx->slot_bank.collected_execution_fees += task_info->txn_ctx->execution_fee;
  slot_ctx->slot_bank.collected_priority_fees  += task_info->txn_ctx->priority_fee;
  slot_ctx->slot_bank.collected_rent           += task_info->txn_ctx->collected_rent;
  return task_info;
}

void
fd_exec_test_instr_context_destroy( fd_exec_instr_test_runner_t * runner,
                                    fd_exec_instr_ctx_t *         ctx,
                                    fd_wksp_t *                   wksp,
                                    fd_alloc_t *                  alloc ) {
  if( !ctx ) return;
  fd_exec_slot_ctx_t *  slot_ctx  = (fd_exec_slot_ctx_t *)ctx->slot_ctx;
  if( !slot_ctx ) return;
  fd_acc_mgr_t *        acc_mgr   = slot_ctx->acc_mgr;
  fd_funk_txn_t *       funk_txn  = slot_ctx->funk_txn;

  // Free alloc
  if( alloc ) {
    fd_wksp_free_laddr( fd_alloc_delete( fd_alloc_leave( alloc ) ) );
  }

  // Detach from workspace
  fd_wksp_detach( wksp );

  fd_exec_slot_ctx_free( slot_ctx );
  fd_acc_mgr_delete( acc_mgr );
  fd_scratch_pop();

  fd_funk_start_write( runner->funk );
  fd_funk_txn_cancel( runner->funk, funk_txn, 1 );
  fd_funk_end_write( runner->funk );

  ctx->slot_ctx = NULL;
}

static void
_txn_context_destroy( fd_exec_instr_test_runner_t * runner,
                      fd_exec_slot_ctx_t *          slot_ctx,
                      fd_wksp_t *                   wksp,
                      fd_alloc_t *                  alloc ) {
  if( !slot_ctx ) return; // This shouldn't be false either
  fd_acc_mgr_t *        acc_mgr   = slot_ctx->acc_mgr;
  fd_funk_txn_t *       funk_txn  = slot_ctx->funk_txn;

  // Free alloc
  if( alloc ) {
    fd_wksp_free_laddr( fd_alloc_delete( fd_alloc_leave( alloc ) ) );
  }

  // Detach from workspace
  fd_wksp_detach( wksp );

  fd_exec_slot_ctx_free( slot_ctx );
  fd_acc_mgr_delete( acc_mgr );

  fd_funk_start_write( runner->funk );
  fd_funk_txn_cancel( runner->funk, funk_txn, 1 );
  fd_funk_end_write( runner->funk );
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

  if( !want->data && have->meta->dlen > 0 ) {
    REPORT_ACCTV( NOTICE, want->address, "expected no data, but got %lu bytes",
                  have->meta->dlen );
    diff = 1;
  }

  if( want->data && want->data->size != have->meta->dlen ) {
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

  if( want->data && 0!=memcmp( want->data->bytes, have->data, want->data->size ) ) {
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
    REPORTV( NOTICE, " expected result (%d-%s), got (%d-%s)",
             expected->result, fd_executor_instr_strerror( -expected->result ),
             exec_result,      fd_executor_instr_strerror( -exec_result      ) );

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
    REPORTV( NOTICE, " expected custom error %u, got %u",
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

  /* Check return data */
  ulong data_sz = expected->return_data ? expected->return_data->size : 0UL; /* support expected->return_data==NULL */
  if (data_sz != ctx->txn_ctx->return_data.len) {
    check->has_diff = 1;
    REPORTV( WARNING, " expected return data size %lu, got %lu",
             (ulong) data_sz, ctx->txn_ctx->return_data.len );
  }
  else if (data_sz > 0 ) {
    if( memcmp( expected->return_data->bytes, ctx->txn_ctx->return_data.data, expected->return_data->size ) ) {
      check->has_diff = 1;
      REPORT( WARNING, " return data mismatch" );
    }
  }

  /* TODO: Capture account side effects outside of the access list by
           looking at the funk record delta (technically a scheduling
           violation) */
}

static fd_sbpf_syscalls_t *
lookup_syscall_func( fd_sbpf_syscalls_t *syscalls,
                     const char *syscall_name,
                     size_t len) {
  ulong i;

  if (!syscall_name) return NULL;

  for (i = 0; i < fd_sbpf_syscalls_slot_cnt(); ++i) {
    if (!fd_sbpf_syscalls_key_inval(syscalls[i].key) && syscalls[i].name && strlen(syscalls[i].name) == len) {
      if (!memcmp(syscalls[i].name, syscall_name, len)) {
        return syscalls + i;
      }
    }
  }

  return NULL;
}

int
fd_exec_instr_fixture_run( fd_exec_instr_test_runner_t *        runner,
                           fd_exec_test_instr_fixture_t const * test,
                           char const *                         log_name ) {
  fd_wksp_t *  wksp  = fd_wksp_attach( "wksp" );
  fd_alloc_t * alloc = fd_alloc_join( fd_alloc_new( fd_wksp_alloc_laddr( wksp, fd_alloc_align(), fd_alloc_footprint(), 2 ), 2 ), 0 );
  fd_exec_instr_ctx_t ctx[1];
  if( FD_UNLIKELY( !fd_exec_test_instr_context_create( runner, ctx, &test->input, alloc, false ) ) ) {
    fd_exec_test_instr_context_destroy( runner, ctx, wksp, alloc );
    return 0;
  }

  fd_instr_info_t * instr = (fd_instr_info_t *) ctx->instr;

  /* Execute the test */
  int exec_result = fd_execute_instr(ctx->txn_ctx, instr);

  int has_diff;
  do {
    /* Compare local execution results against fixture */

    fd_cstr_printf( _report_prefix, sizeof(_report_prefix), NULL, "%s: ", log_name );

    fd_exec_instr_fixture_diff_t diff =
      { .ctx         = ctx,
        .input       = &test->input,
        .expected    = &test->output,
        .exec_result = -exec_result };
    _diff_effects( &diff );

    _report_prefix[0] = '\0';

    has_diff = diff.has_diff;
  } while(0);

  fd_exec_test_instr_context_destroy( runner, ctx, wksp, alloc );
  return !has_diff;
}

ulong
fd_exec_instr_test_run( fd_exec_instr_test_runner_t * runner,
                        void const *                  input_,
                        void **                       output_,
                        void *                        output_buf,
                        ulong                         output_bufsz ) {
  fd_exec_test_instr_context_t const * input  = fd_type_pun_const( input_ );
  fd_exec_test_instr_effects_t **      output = fd_type_pun( output_ );
  fd_wksp_t *  wksp  = fd_wksp_attach( "wksp" );
  fd_alloc_t * alloc = fd_alloc_join( fd_alloc_new( fd_wksp_alloc_laddr( wksp, fd_alloc_align(), fd_alloc_footprint(), 2 ), 2 ), 0 );

  /* Convert the Protobuf inputs to a fd_exec context */
  fd_exec_instr_ctx_t ctx[1];
  if( !fd_exec_test_instr_context_create( runner, ctx, input, alloc, false ) ) {
    fd_exec_test_instr_context_destroy( runner, ctx, wksp, alloc );
    return 0UL;
  }

  fd_instr_info_t * instr = (fd_instr_info_t *) ctx->instr;

  /* Execute the test */
  int exec_result = fd_execute_instr(ctx->txn_ctx, instr);

  /* Allocate space to capture outputs */

  ulong output_end = (ulong)output_buf + output_bufsz;
  FD_SCRATCH_ALLOC_INIT( l, output_buf );

  fd_exec_test_instr_effects_t * effects =
    FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_exec_test_instr_effects_t),
                                sizeof (fd_exec_test_instr_effects_t) );
  if( FD_UNLIKELY( _l > output_end ) ) {
    fd_exec_test_instr_context_destroy( runner, ctx, wksp, alloc );
    return 0UL;
  }
  fd_memset( effects, 0, sizeof(fd_exec_test_instr_effects_t) );

  /* Capture error code */

  effects->result   = -exec_result;
  effects->cu_avail = ctx->txn_ctx->compute_meter;

  if( exec_result == FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR ) {
    effects->custom_err     = ctx->txn_ctx->custom_err;
  }

  /* Allocate space for captured accounts */
  ulong modified_acct_cnt = ctx->txn_ctx->accounts_cnt;

  fd_exec_test_acct_state_t * modified_accts =
    FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_exec_test_acct_state_t),
                                sizeof (fd_exec_test_acct_state_t) * modified_acct_cnt );
  if( FD_UNLIKELY( _l > output_end ) ) {
    fd_exec_test_instr_context_destroy( runner, ctx, wksp, alloc );
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

    memcpy( out_acct->address, acc->pubkey, sizeof(fd_pubkey_t) );
    out_acct->lamports     = acc->const_meta->info.lamports;
    out_acct->data =
      FD_SCRATCH_ALLOC_APPEND( l, alignof(pb_bytes_array_t),
                                  PB_BYTES_ARRAY_T_ALLOCSIZE( acc->const_meta->dlen ) );
    if( FD_UNLIKELY( _l > output_end ) ) {
      fd_exec_test_instr_context_destroy( runner, ctx, wksp, alloc );
      return 0UL;
    }
    out_acct->data->size = (pb_size_t)acc->const_meta->dlen;
    fd_memcpy( out_acct->data->bytes, acc->const_data, acc->const_meta->dlen );

    out_acct->executable     = acc->const_meta->info.executable;
    out_acct->rent_epoch     = acc->const_meta->info.rent_epoch;
    memcpy( out_acct->owner, acc->const_meta->info.owner, sizeof(fd_pubkey_t) );

    effects->modified_accounts_count++;
  }

  /* Capture return data */
  fd_txn_return_data_t * return_data = &ctx->txn_ctx->return_data;
  effects->return_data = FD_SCRATCH_ALLOC_APPEND(l, alignof(pb_bytes_array_t),
                              PB_BYTES_ARRAY_T_ALLOCSIZE( return_data->len ) );
  if( FD_UNLIKELY( _l > output_end ) ) {
    fd_exec_test_instr_context_destroy( runner, ctx, wksp, alloc );
    return 0UL;
  }
  effects->return_data->size = (pb_size_t)return_data->len;
  fd_memcpy( effects->return_data->bytes, return_data->data, return_data->len );

  ulong actual_end = FD_SCRATCH_ALLOC_FINI( l, 1UL );
  fd_exec_test_instr_context_destroy( runner, ctx, wksp, alloc );

  *output = effects;
  return actual_end - (ulong)output_buf;
}

ulong
fd_exec_txn_test_run( fd_exec_instr_test_runner_t * runner, // Runner only contains funk instance, so we can borrow instr test runner
                      void const *                  input_,
                      void **                       output_,
                      void *                        output_buf,
                      ulong                         output_bufsz ) {
  fd_exec_test_txn_context_t const * input  = fd_type_pun_const( input_ );
  fd_exec_test_txn_result_t **       output = fd_type_pun( output_ );

  FD_SCRATCH_SCOPE_BEGIN {
    /* Initialize memory */
    fd_wksp_t *           wksp          = fd_wksp_attach( "wksp" );
    fd_alloc_t *          alloc         = fd_alloc_join( fd_alloc_new( fd_wksp_alloc_laddr( wksp, fd_alloc_align(), fd_alloc_footprint(), 2 ), 2 ), 0 );
    uchar *               slot_ctx_mem  = fd_scratch_alloc( FD_EXEC_SLOT_CTX_ALIGN,  FD_EXEC_SLOT_CTX_FOOTPRINT  );
    fd_exec_slot_ctx_t *  slot_ctx      = fd_exec_slot_ctx_join ( fd_exec_slot_ctx_new ( slot_ctx_mem, fd_alloc_virtual( alloc ) ) );

    /* Create and exec transaction */
    fd_execute_txn_task_info_t * task_info = _txn_context_create_and_exec( runner, slot_ctx, input );
    if( task_info == NULL ) {
      _txn_context_destroy( runner, slot_ctx, wksp, alloc );
      return 0UL;
    }
    fd_exec_txn_ctx_t * txn_ctx = task_info->txn_ctx;

    int exec_res = task_info->exec_res;

    /* Start saving txn exec results */
    FD_SCRATCH_ALLOC_INIT( l, output_buf );
    ulong output_end = (ulong)output_buf + output_bufsz;

    fd_exec_test_txn_result_t * txn_result =
    FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_exec_test_txn_result_t),
                                  sizeof (fd_exec_test_txn_result_t) );
    if( FD_UNLIKELY( _l > output_end ) ) {
      abort();
    }
    fd_memset( txn_result, 0, sizeof(fd_exec_test_txn_result_t) );

    /* Capture basic results fields */
    txn_result->executed                          = task_info->txn->flags & FD_TXN_P_FLAGS_EXECUTE_SUCCESS;
    txn_result->sanitization_error                = !( task_info->txn->flags & FD_TXN_P_FLAGS_SANITIZE_SUCCESS );
    txn_result->has_resulting_state               = false;
    txn_result->resulting_state.acct_states_count = 0;
    txn_result->is_ok                             = !exec_res;
    txn_result->status                            = (uint32_t) -exec_res;
    txn_result->instruction_error                 = 0;
    txn_result->instruction_error_index           = 0;
    txn_result->custom_error                      = 0;
    txn_result->executed_units                    = txn_ctx->compute_unit_limit - txn_ctx->compute_meter;
    txn_result->has_fee_details                   = false;

    if( txn_result->sanitization_error ) {
      /* If exec_res was an instruction error, capture the error number and idx */
      if( exec_res == FD_RUNTIME_TXN_ERR_INSTRUCTION_ERROR ) {
        txn_result->instruction_error = (uint32_t) -task_info->txn_ctx->exec_err;
        txn_result->instruction_error_index = (uint32_t) task_info->txn_ctx->instr_err_idx;

        /* 
        TODO: precompile error codes are not conformant, so we're ignoring custom error codes for them for now. This should be revisited in the future. 
        For now, only precompiles throw custom error codes, so we can ignore all custom error codes thrown in the sanitization phase. If this changes,
        this logic will have to be revisited.

        if( task_info->txn_ctx->exec_err == FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR ) {
          txn_result->custom_error = txn_ctx->custom_err;
        } 
        */
      }
      ulong actual_end = FD_SCRATCH_ALLOC_FINI( l, 1UL );
      _txn_context_destroy( runner, slot_ctx, wksp, alloc );

      *output = txn_result;
      return actual_end - (ulong)output_buf;
    }

    txn_result->has_fee_details                   = true;
    txn_result->fee_details.transaction_fee       = slot_ctx->slot_bank.collected_execution_fees;
    txn_result->fee_details.prioritization_fee    = slot_ctx->slot_bank.collected_priority_fees;

    /* Rent is only collected on successfully loaded transactions */
    txn_result->rent                              = txn_ctx->collected_rent;

    /* At this point, the transaction has executed */
    if( exec_res ) {
      /* Instruction error index must be set for the txn error to be an instruction error */
      if( txn_ctx->instr_err_idx != INT32_MAX ) {
        txn_result->status = (uint32_t) -FD_RUNTIME_TXN_ERR_INSTRUCTION_ERROR;
        txn_result->instruction_error = (uint32_t) -exec_res;
        txn_result->instruction_error_index = (uint32_t) txn_ctx->instr_err_idx;
        if( exec_res == FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR ) {
          txn_result->custom_error = txn_ctx->custom_err;
        }
      } else {
        txn_result->status = (uint32_t) -exec_res;
      }
    }

    if( txn_ctx->return_data.len > 0 ) {
      txn_result->return_data = FD_SCRATCH_ALLOC_APPEND( l, alignof(pb_bytes_array_t),
                                      PB_BYTES_ARRAY_T_ALLOCSIZE( txn_ctx->return_data.len ) );
      if( FD_UNLIKELY( _l > output_end ) ) {
        abort();
      }

      txn_result->return_data->size = (pb_size_t)txn_ctx->return_data.len;
      fd_memcpy( txn_result->return_data->bytes, txn_ctx->return_data.data, txn_ctx->return_data.len );
    }

    /* Allocate space for captured accounts */
    ulong modified_acct_cnt = txn_ctx->accounts_cnt;

    txn_result->has_resulting_state         = true;
    txn_result->resulting_state.acct_states =
      FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_exec_test_acct_state_t),
                                  sizeof (fd_exec_test_acct_state_t) * modified_acct_cnt );
    if( FD_UNLIKELY( _l > output_end ) ) {
      abort();
    }

    /* Capture borrowed accounts */
    for( ulong j=0UL; j < txn_ctx->accounts_cnt; j++ ) {
      fd_borrowed_account_t * acc = &txn_ctx->borrowed_accounts[j];
      if( !acc->meta ) continue;

      ulong modified_idx = txn_result->resulting_state.acct_states_count;
      assert( modified_idx < modified_acct_cnt );

      fd_exec_test_acct_state_t * out_acct = &txn_result->resulting_state.acct_states[ modified_idx ];
      memset( out_acct, 0, sizeof(fd_exec_test_acct_state_t) );
      /* Copy over account content */

      memcpy( out_acct->address, acc->pubkey, sizeof(fd_pubkey_t) );

      out_acct->lamports = acc->const_meta->info.lamports;

      if( acc->const_meta->dlen > 0 ) {
        out_acct->data =
          FD_SCRATCH_ALLOC_APPEND( l, alignof(pb_bytes_array_t),
                                      PB_BYTES_ARRAY_T_ALLOCSIZE( acc->const_meta->dlen ) );
        if( FD_UNLIKELY( _l > output_end ) ) {
          abort();
        }
        out_acct->data->size = (pb_size_t)acc->const_meta->dlen;
        fd_memcpy( out_acct->data->bytes, acc->const_data, acc->const_meta->dlen );
      }

      out_acct->executable     = acc->const_meta->info.executable;
      out_acct->rent_epoch     = acc->const_meta->info.rent_epoch;
      memcpy( out_acct->owner, acc->const_meta->info.owner, sizeof(fd_pubkey_t) );

      txn_result->resulting_state.acct_states_count++;
    }

    ulong actual_end = FD_SCRATCH_ALLOC_FINI( l, 1UL );
    _txn_context_destroy( runner, slot_ctx, wksp, alloc );

    *output = txn_result;
    return actual_end - (ulong)output_buf;
  } FD_SCRATCH_SCOPE_END;
}


ulong
fd_sbpf_program_load_test_run( FD_PARAM_UNUSED fd_exec_instr_test_runner_t * runner,
                               void const *                  input_,
                               void **                       output_,
                               void *                        output_buf,
                               ulong                         output_bufsz ) {
  fd_exec_test_elf_loader_ctx_t const * input  = fd_type_pun_const( input_ );
  fd_exec_test_elf_loader_effects_t **  output = fd_type_pun( output_ );

  fd_sbpf_elf_info_t info;
  fd_valloc_t valloc = fd_scratch_virtual();

  if ( FD_UNLIKELY( !input->has_elf || !input->elf.data ) ){
    return 0UL;
  }

  ulong elf_sz = input->elf_sz;
  void const * _bin;

  /* elf_sz will be passed as arguments to elf loader functions.
     pb decoder allocates memory for elf.data based on its actual size,
     not elf_sz !.
     If elf_sz is larger than the size of actual elf data, this may result
     in out-of-bounds accesses which will upset ASAN (however intentional).
     So in this case we just copy the data into a memory region of elf_sz bytes

     ! The decoupling of elf_sz and the actual binary size is intentional to test
      underflow/overflow behavior */
  if ( elf_sz > input->elf.data->size ){
    void * tmp = fd_valloc_malloc( valloc, 1UL, elf_sz );
    if ( FD_UNLIKELY( !tmp ) ){
      return 0UL;
    }
    fd_memcpy( tmp, input->elf.data->bytes, input->elf.data->size );
    _bin = tmp;
  } else {
    _bin = input->elf.data->bytes;
  }

  // Allocate space for captured effects
  ulong output_end = (ulong)output_buf + output_bufsz;
  FD_SCRATCH_ALLOC_INIT( l, output_buf );

  fd_exec_test_elf_loader_effects_t * elf_effects =
    FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_exec_test_elf_loader_effects_t),
                                sizeof (fd_exec_test_elf_loader_effects_t) );
  if( FD_UNLIKELY( _l > output_end ) ) {
    /* return 0 on fuzz-specific failures */
    return 0UL;
  }
  fd_memset( elf_effects, 0, sizeof(fd_exec_test_elf_loader_effects_t) );

  /* wrap the loader code in do-while(0) block so that we can exit
     immediately if execution fails at any point */

  do{

    if( FD_UNLIKELY( !fd_sbpf_elf_peek( &info, _bin, elf_sz, input->deploy_checks ) ) ) {
      /* return incomplete effects on execution failures */
      break;
    }

    void* rodata = fd_valloc_malloc( valloc, FD_SBPF_PROG_RODATA_ALIGN, info.rodata_footprint );
    FD_TEST( rodata );

    fd_sbpf_program_t * prog = fd_sbpf_program_new( fd_valloc_malloc( valloc, fd_sbpf_program_align(), fd_sbpf_program_footprint( &info ) ), &info, rodata );
    FD_TEST( prog );

    fd_sbpf_syscalls_t * syscalls = fd_sbpf_syscalls_new( fd_valloc_malloc( valloc, fd_sbpf_syscalls_align(), fd_sbpf_syscalls_footprint() ));
    FD_TEST( syscalls );

    fd_vm_syscall_register_all( syscalls, 0 );

    int res = fd_sbpf_program_load( prog, _bin, elf_sz, syscalls, input->deploy_checks );
    if( FD_UNLIKELY( res ) ) {
      break;
    }

    fd_memset( elf_effects, 0, sizeof(fd_exec_test_elf_loader_effects_t) );
    elf_effects->rodata_sz = prog->rodata_sz;

    // Load rodata section
    elf_effects->rodata = FD_SCRATCH_ALLOC_APPEND(l, 8UL, PB_BYTES_ARRAY_T_ALLOCSIZE( prog->rodata_sz ));
    if( FD_UNLIKELY( _l > output_end ) ) {
      return 0UL;
    }
    elf_effects->rodata->size = (pb_size_t) prog->rodata_sz;
    fd_memcpy( &(elf_effects->rodata->bytes), prog->rodata, prog->rodata_sz );

    elf_effects->text_cnt = prog->text_cnt;
    elf_effects->text_off = prog->text_off;

    elf_effects->entry_pc = prog->entry_pc;


    pb_size_t calldests_sz = (pb_size_t) fd_sbpf_calldests_cnt( prog->calldests);
    elf_effects->calldests_count = calldests_sz;
    elf_effects->calldests = FD_SCRATCH_ALLOC_APPEND(l, 8UL, calldests_sz * sizeof(uint64_t));
    if( FD_UNLIKELY( _l > output_end ) ) {
      return 0UL;
    }

    ulong i = 0;
    for(ulong target_pc = fd_sbpf_calldests_const_iter_init(prog->calldests); !fd_sbpf_calldests_const_iter_done(target_pc);
    target_pc = fd_sbpf_calldests_const_iter_next(prog->calldests, target_pc)) {
      elf_effects->calldests[i] = target_pc;
      ++i;
    }
  } while(0);

  ulong actual_end = FD_SCRATCH_ALLOC_FINI( l, 1UL );

  *output = elf_effects;
  return actual_end - (ulong) output_buf;
}

static fd_exec_test_instr_effects_t const * cpi_exec_effects = NULL;

ulong
fd_exec_vm_syscall_test_run( fd_exec_instr_test_runner_t * runner,
                             void const *                  input_,
                             void **                       output_,
                             void *                        output_buf,
                             ulong                         output_bufsz ) {
  fd_exec_test_syscall_context_t const * input =  fd_type_pun_const( input_ );
  fd_exec_test_syscall_effects_t **      output = fd_type_pun( output_ );
  fd_wksp_t *  wksp  = fd_wksp_attach( "wksp" );
  fd_alloc_t * alloc = fd_alloc_join( fd_alloc_new( fd_wksp_alloc_laddr( wksp, fd_alloc_align(), fd_alloc_footprint(), 2 ), 2 ), 0 );

  /* Create execution context */
  const fd_exec_test_instr_context_t * input_instr_ctx = &input->instr_ctx;
  fd_exec_instr_ctx_t ctx[1];
  // Skip extra checks for non-CPI syscalls
  int is_cpi            = !strncmp( (const char *)input->syscall_invocation.function_name.bytes, "sol_invoke_signed", 17 );
  int skip_extra_checks = !is_cpi;

  if( !fd_exec_test_instr_context_create( runner, ctx, input_instr_ctx, alloc, skip_extra_checks ) )
    goto error;
  fd_valloc_t valloc = fd_scratch_virtual();

  /* Capture outputs */
  ulong output_end = (ulong)output_buf + output_bufsz;
  FD_SCRATCH_ALLOC_INIT( l, output_buf );
  fd_exec_test_syscall_effects_t * effects =
    FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_exec_test_syscall_effects_t),
                                sizeof (fd_exec_test_syscall_effects_t) );
  if( FD_UNLIKELY( _l > output_end ) ) {
    goto error;
  }

  if (input->vm_ctx.return_data.program_id && input->vm_ctx.return_data.program_id->size == sizeof(fd_pubkey_t)) {
    fd_memcpy( ctx->txn_ctx->return_data.program_id.uc, input->vm_ctx.return_data.program_id->bytes, sizeof(fd_pubkey_t) );
    ctx->txn_ctx->return_data.len = input->vm_ctx.return_data.data->size;
    fd_memcpy( ctx->txn_ctx->return_data.data, input->vm_ctx.return_data.data->bytes, ctx->txn_ctx->return_data.len );
  }

  *effects = (fd_exec_test_syscall_effects_t) FD_EXEC_TEST_SYSCALL_EFFECTS_INIT_ZERO;

  /* Set up the VM instance */
  fd_sha256_t _sha[1];
  fd_sha256_t * sha = fd_sha256_join( fd_sha256_new( _sha ) );
  fd_sbpf_syscalls_t * syscalls = fd_sbpf_syscalls_new( fd_valloc_malloc( valloc, fd_sbpf_syscalls_align(), fd_sbpf_syscalls_footprint() ) );
  fd_vm_syscall_register_all( syscalls, 0 );

  /* Pull out the memory regions */
  if( !input->has_vm_ctx ) {
    goto error;
  }
  if( input->has_exec_effects ){
    cpi_exec_effects = &input->exec_effects;
  }

  ulong rodata_sz = input->vm_ctx.rodata ? input->vm_ctx.rodata->size : 0UL;
  uchar * rodata = fd_valloc_malloc( valloc, 8UL, rodata_sz );
  if ( input->vm_ctx.rodata != NULL ) {
    fd_memcpy( rodata, input->vm_ctx.rodata->bytes, rodata_sz );
  }

  /* Load input data regions */
  fd_vm_input_region_t * input_regions = NULL;
  uint input_regions_count = 0U;
  if( !!(input->vm_ctx.input_data_regions_count) ) {
    input_regions       = fd_valloc_malloc( valloc, alignof(fd_vm_input_region_t), sizeof(fd_vm_input_region_t) * input->vm_ctx.input_data_regions_count );
    input_regions_count = setup_vm_input_regions( input_regions, input->vm_ctx.input_data_regions, input->vm_ctx.input_data_regions_count, valloc );
    if ( !input_regions_count ) {
      goto error;
    }
  }

  if( input->vm_ctx.heap_max > FD_VM_HEAP_MAX ) {
    goto error;
  }

  fd_vm_t * vm = fd_vm_join( fd_vm_new( fd_valloc_malloc( valloc, fd_vm_align(), fd_vm_footprint() ) ) );
  if ( !vm ) {
    goto error;
  }

  /* If the program ID account owner is the v1 BPF loader, then alignment is disabled (controlled by
     the `is_deprecated` flag) */
  uchar program_id_idx = ctx->instr->program_id;
  uchar is_deprecated = ( program_id_idx < ctx->txn_ctx->accounts_cnt ) && 
                        ( !memcmp( ctx->txn_ctx->borrowed_accounts[program_id_idx].const_meta->info.owner, fd_solana_bpf_loader_deprecated_program_id.key, sizeof(fd_pubkey_t) ) );

  fd_vm_init(
    vm,
    ctx,
    input->vm_ctx.heap_max,
    ctx->txn_ctx->compute_meter,
    rodata,
    rodata_sz,
    NULL, // TODO
    0, // TODO
    0, // TODO
    0, // TODO, text_sz
    0, // TODO
    NULL, // TODO
    syscalls,
    NULL, // TODO
    sha,
    input_regions,
    input_regions_count,
    NULL,
    is_deprecated,
    FD_FEATURE_ACTIVE( ctx->slot_ctx, bpf_account_data_direct_mapping ) );

  // Setup the vm state for execution
  if( fd_vm_setup_state_for_execution( vm ) != FD_VM_SUCCESS ) {
    goto error;
  }

  // Override some execution state values from the syscall fuzzer input
  // This is so we can test if the syscall mutates any of these erroneously
  vm->reg[0] = input->vm_ctx.r0;
  vm->reg[1] = input->vm_ctx.r1;
  vm->reg[2] = input->vm_ctx.r2;
  vm->reg[3] = input->vm_ctx.r3;
  vm->reg[4] = input->vm_ctx.r4;
  vm->reg[5] = input->vm_ctx.r5;
  vm->reg[6] = input->vm_ctx.r6;
  vm->reg[7] = input->vm_ctx.r7;
  vm->reg[8] = input->vm_ctx.r8;
  vm->reg[9] = input->vm_ctx.r9;
  vm->reg[10] = input->vm_ctx.r10;
  vm->reg[11] = input->vm_ctx.r11;

  // Override initial part of the heap, if specified the syscall fuzzer input
  if( input->syscall_invocation.heap_prefix ) {
    fd_memcpy( vm->heap, input->syscall_invocation.heap_prefix->bytes,
               fd_ulong_min(input->syscall_invocation.heap_prefix->size, vm->heap_max) );
  }

  // Override initial part of the stack, if specified the syscall fuzzer input
  if( input->syscall_invocation.stack_prefix ) {
    fd_memcpy( vm->stack, input->syscall_invocation.stack_prefix->bytes,
               fd_ulong_min(input->syscall_invocation.stack_prefix->size, FD_VM_STACK_MAX) );
  }

  // Propogate the acc_regions_meta to the vm
  vm->acc_region_metas = fd_valloc_malloc( valloc, alignof(fd_vm_acc_region_meta_t), sizeof(fd_vm_acc_region_meta_t) * input->vm_ctx.input_data_regions_count );
  setup_vm_acc_region_metas( vm->acc_region_metas, vm, vm->instr_ctx );

  // Look up the syscall to execute
  char * syscall_name = (char *)input->syscall_invocation.function_name.bytes;
  fd_sbpf_syscalls_t const * syscall = lookup_syscall_func(syscalls, syscall_name, input->syscall_invocation.function_name.size);
  if( !syscall ) {
    goto error;
  }

  /* Actually invoke the syscall */
  int stack_push_err = fd_instr_stack_push( ctx->txn_ctx, (fd_instr_info_t *)ctx->instr );
  if( FD_UNLIKELY( stack_push_err ) ) {
      FD_LOG_WARNING(( "instr stack push err" ));
      goto error;
  }
  int syscall_err = syscall->func( vm, vm->reg[1], vm->reg[2], vm->reg[3], vm->reg[4], vm->reg[5], &vm->reg[0] );
  int stack_pop_err = fd_instr_stack_pop( ctx->txn_ctx, ctx->instr );
  if( FD_UNLIKELY( stack_pop_err ) ) {
      FD_LOG_WARNING(( "instr stack pop err" ));
      goto error;
  }
  if( syscall_err ) {
    /*  In the CPI syscall, certain checks are performed out of order between Firedancer and Agave's
        implementation. Certain checks in FD (whose error codes mapped below)
        do not have a (sequentially) equivalent one in Agave. Thus, it doesn't make sense
        to declare a mismatch if Firedancer fails such a check when Agave doesn't, as long
        as both end up error'ing out at some point. We also have other metrics (namely CU count)
        to rely on. */

    /*  Certain pre-flight checks are not performed in Agave. These manifest as
        access violations in Agave. The agave_access_violation_mask bitset sets
        the error codes that are expected to be access violations in Agave. */
    if( is_cpi &&
      ( syscall_err == FD_VM_ERR_SYSCALL_TOO_MANY_SIGNERS ||
        syscall_err == FD_VM_ERR_SYSCALL_INSTRUCTION_TOO_LARGE ||
        syscall_err == FD_VM_ERR_SYSCALL_MAX_INSTRUCTION_ACCOUNTS_EXCEEDED ||
        syscall_err == FD_VM_ERR_SYSCALL_MAX_INSTRUCTION_ACCOUNT_INFOS_EXCEEDED ) ) {

      /* FD performs pre-flight checks that manifest as access violations in Agave */
      vm->instr_ctx->txn_ctx->exec_err      = FD_VM_ERR_EBPF_ACCESS_VIOLATION;
      vm->instr_ctx->txn_ctx->exec_err_kind = FD_EXECUTOR_ERR_KIND_EBPF;
    }

    fd_log_collector_program_failure( vm->instr_ctx );
  }

  /* Capture the effects */
  int exec_err = vm->instr_ctx->txn_ctx->exec_err;
  effects->error = 0;
  if( syscall_err ) {
    if( exec_err==0 ) {
      FD_LOG_WARNING(( "TODO: syscall returns error, but exec_err not set. this is probably missing a log." ));
      effects->error = -1;
    } else {
      effects->error = (exec_err <= 0) ? -exec_err : -1;

      /* Map error kind, equivalent to:
          effects->error_kind = (fd_exec_test_err_kind_t)(vm->instr_ctx->txn_ctx->exec_err_kind + 1); */
      switch (vm->instr_ctx->txn_ctx->exec_err_kind) {
        case FD_EXECUTOR_ERR_KIND_EBPF:
          effects->error_kind = FD_EXEC_TEST_ERR_KIND_EBPF;
          break;
        case FD_EXECUTOR_ERR_KIND_SYSCALL:
          effects->error_kind = FD_EXEC_TEST_ERR_KIND_SYSCALL;
          break;
        case FD_EXECUTOR_ERR_KIND_INSTR:
          effects->error_kind = FD_EXEC_TEST_ERR_KIND_INSTRUCTION;
          break;
        default:
          effects->error_kind = FD_EXEC_TEST_ERR_KIND_UNSPECIFIED;
          break;
      }
    }
  }
  effects->r0 = syscall_err ? 0 : vm->reg[0]; // Save only on success
  effects->cu_avail = (ulong)vm->cu;

  if( vm->heap_max ) {
    effects->heap = FD_SCRATCH_ALLOC_APPEND(
      l, alignof(uint), PB_BYTES_ARRAY_T_ALLOCSIZE( vm->heap_max ) );
    if( FD_UNLIKELY( _l > output_end ) ) {
      goto error;
    }
    effects->heap->size = (uint)vm->heap_max;
    fd_memcpy( effects->heap->bytes, vm->heap, vm->heap_max );
  } else {
    effects->heap = NULL;
  }

  effects->stack = FD_SCRATCH_ALLOC_APPEND(
    l, alignof(uint), PB_BYTES_ARRAY_T_ALLOCSIZE( FD_VM_STACK_MAX ) );
    if( FD_UNLIKELY( _l > output_end ) ) {
      goto error;
    }
  effects->stack->size = (uint)FD_VM_STACK_MAX;
  fd_memcpy( effects->stack->bytes, vm->stack, FD_VM_STACK_MAX );

  if( vm->rodata_sz ) {
    effects->rodata = FD_SCRATCH_ALLOC_APPEND(
      l, alignof(uint), PB_BYTES_ARRAY_T_ALLOCSIZE( rodata_sz ) );
    if( FD_UNLIKELY( _l > output_end ) ) {
      goto error;
    }
    effects->rodata->size = (uint)rodata_sz;
    fd_memcpy( effects->rodata->bytes, vm->rodata, rodata_sz );
  } else {
    effects->rodata = NULL;
  }

  effects->frame_count = vm->frame_cnt;

  fd_log_collector_t * log = &vm->instr_ctx->txn_ctx->log_collector;
  /* Only collect log on valid errors (i.e., != -1). Follows
     https://github.com/firedancer-io/solfuzz-agave/blob/99758d3c4f3a342d56e2906936458d82326ae9a8/src/utils/err_map.rs#L148 */
  if( effects->error != -1 && log->buf_sz ) {
    effects->log = FD_SCRATCH_ALLOC_APPEND(
      l, alignof(uchar), PB_BYTES_ARRAY_T_ALLOCSIZE( log->buf_sz ) );
    if( FD_UNLIKELY( _l > output_end ) ) {
      goto error;
    }
    effects->log->size = (uint)fd_log_collector_debug_sprintf( log, (char *)effects->log->bytes, 0 );
  } else {
    effects->log = NULL;
  }

  /* Capture input regions */
  effects->inputdata = NULL; /* Deprecated, using input_data_regions instead */
  ulong tmp_end = FD_SCRATCH_ALLOC_FINI( l, 1UL );
  ulong input_regions_size = load_from_vm_input_regions( vm->input_mem_regions,
                                                        vm->input_mem_regions_cnt,
                                                        &effects->input_data_regions,
                                                        &effects->input_data_regions_count,
                                                        (void *)tmp_end,
                                                        fd_ulong_sat_sub( output_end, tmp_end ) );

  if( !!vm->input_mem_regions_cnt && !effects->input_data_regions ) {
    goto error;
  }

  /* Return the effects */
  ulong actual_end = tmp_end + input_regions_size;
  fd_exec_test_instr_context_destroy( runner, ctx, wksp, alloc );
  cpi_exec_effects = NULL;

  *output = effects;
  return actual_end - (ulong)output_buf;

error:
  fd_exec_test_instr_context_destroy( runner, ctx, wksp, alloc );
  cpi_exec_effects = NULL;
  return 0;
}

/* Stubs fd_execute_instr for binaries compiled with
   `-Xlinker --wrap=fd_execute_instr` */
int
__wrap_fd_execute_instr( fd_exec_txn_ctx_t * txn_ctx,
                         fd_instr_info_t *   instr_info )
{
    static const pb_byte_t zero_blk[32] = {0};

    if( cpi_exec_effects == NULL ) {
      FD_LOG_WARNING(( "fd_execute_instr is disabled" ));
      return FD_EXECUTOR_INSTR_SUCCESS;
    }

    // Iterate through instruction accounts
    for( ushort i = 0UL; i < instr_info->acct_cnt; ++i ) {
      uchar idx_in_txn = instr_info->acct_txn_idxs[i];
      fd_pubkey_t * acct_pubkey = &instr_info->acct_pubkeys[i];

      fd_borrowed_account_t * acct = NULL;
      /* Find (first) account in cpi_exec_effects->modified_accounts that matches pubkey */
      for( uint j = 0UL; j < cpi_exec_effects->modified_accounts_count; ++j ) {
        fd_exec_test_acct_state_t * acct_state = &cpi_exec_effects->modified_accounts[j];
        if( memcmp( acct_state->address, acct_pubkey, sizeof(fd_pubkey_t) ) != 0 ) continue;

        /* Fetch borrowed account */
        /* First check if account is read-only.
           TODO: Once direct mapping is enabled we _technically_ don't need
                 this check */

        if( fd_txn_borrowed_account_view_idx( txn_ctx, idx_in_txn, &acct ) ) {
          break;
        }
        if( acct->meta == NULL ){
          break;
        }

        /* Now borrow mutably (with resize) */
        int err = fd_txn_borrowed_account_modify_idx( txn_ctx,
                                                      idx_in_txn,
                                                      /* Do not reallocate if data is not going to be modified */
                                                      acct_state->data ? acct_state->data->size : 0UL,
                                                      &acct );
        if( err ) break;

        /* Update account state */
        acct->meta->info.lamports = acct_state->lamports;
        acct->meta->info.executable = acct_state->executable;
        acct->meta->info.rent_epoch = acct_state->rent_epoch;

        /* TODO: use lower level API (i.e., fd_borrowed_account_resize) to avoid memcpy here */
        if( acct_state->data ){
          fd_memcpy( acct->data, acct_state->data->bytes, acct_state->data->size );
          acct->meta->dlen = acct_state->data->size;
        }

        /* Follow solfuzz-agave, which skips if pubkey is malformed */
        if( memcmp( acct_state->owner, zero_blk, sizeof(fd_pubkey_t) ) != 0 ) {
          fd_memcpy( acct->meta->info.owner, acct_state->owner, sizeof(fd_pubkey_t) );
        }

        break;
      }
    }
    return FD_EXECUTOR_INSTR_SUCCESS;
}
