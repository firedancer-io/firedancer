
#include "generated/invoke.pb.h"
#undef FD_SCRATCH_USE_HANDHOLDING
#define FD_SCRATCH_USE_HANDHOLDING 1
#include "fd_exec_instr_test.h"
#include "../fd_acc_mgr.h"
#include "../fd_account.h"
#include "../fd_executor.h"
#include "../fd_runtime.h"
#include "../program/fd_bpf_loader_v3_program.h"
#include "../program/fd_bpf_program_util.h"
#include "../program/fd_builtin_programs.h"
#include "../context/fd_exec_epoch_ctx.h"
#include "../context/fd_exec_slot_ctx.h"
#include "../context/fd_exec_txn_ctx.h"
#include "../sysvar/fd_sysvar_recent_hashes.h"
#include "../../../funk/fd_funk.h"
#include "../../../util/bits/fd_float.h"
#include "../../../ballet/sbpf/fd_sbpf_loader.h"
#include "../../../ballet/elf/fd_elf.h"
#include "../../vm/fd_vm.h"
#include <assert.h>
#include "../sysvar/fd_sysvar_cache.h"
#include "../sysvar/fd_sysvar_epoch_schedule.h"
#include "../sysvar/fd_sysvar_clock.h"

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
    REPORTV( level, "account %s: " fmt, _acct_log_private_addr, __VA_ARGS__ ); \
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

static void
_txn_collect_rent( fd_exec_txn_ctx_t * txn_ctx ) {
  /* Copied from fd_runtime_collect_rent. Requires some modifications from fd_runtime_collect_rent */
  fd_exec_slot_ctx_t * slot_ctx = txn_ctx->slot_ctx;
  fd_epoch_bank_t const * epoch_bank = fd_exec_epoch_ctx_epoch_bank( slot_ctx->epoch_ctx );
  fd_epoch_schedule_t const * schedule = &epoch_bank->epoch_schedule;

  ulong slot = slot_ctx->slot_bank.slot;
  ulong epoch = fd_slot_to_epoch(schedule, slot, NULL);

  for( ulong i = 0; i < txn_ctx->accounts_cnt; ++i ) {
    FD_BORROWED_ACCOUNT_DECL(acc);

    // Obtain writable handle to account
    if( fd_acc_mgr_modify( txn_ctx->acc_mgr, txn_ctx->funk_txn, &txn_ctx->accounts[i], 0, 0UL, acc ) ) {
      continue;
    }

    /* Filter accounts that we've already visited */
    if (acc->const_meta->info.rent_epoch <= epoch || FD_FEATURE_ACTIVE(slot_ctx, set_exempt_rent_epoch_max)) {
      /* Actually invoke rent collection */
      fd_runtime_collect_rent_account(slot_ctx, acc->meta, acc->pubkey, epoch);
    }
  }
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
  if( state->data ) fd_memcpy( acc->data, state->data->bytes, size );

  acc->starting_lamports     = state->lamports;
  acc->starting_dlen         = size;
  acc->meta->info.lamports   = state->lamports;
  acc->meta->info.executable = state->executable;
  acc->meta->info.rent_epoch = state->rent_epoch;
  acc->meta->dlen            = size;
  memcpy( acc->meta->info.owner, state->owner, sizeof(fd_pubkey_t) );

  return 1;
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

static int
_instr_context_create( fd_exec_instr_test_runner_t *        runner,
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

  fd_funk_txn_t * funk_txn = fd_funk_txn_prepare( funk, NULL, xid, 1 );
  fd_scratch_push();

  ulong vote_acct_max = 128UL;

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
  txn_ctx->heap_size = FD_VM_HEAP_SIZE;

  /* Set up epoch context */
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

  txn_ctx->instr_info_pool         = fd_instr_info_pool_join( fd_instr_info_pool_new(
    fd_valloc_malloc( fd_scratch_virtual(), fd_instr_info_pool_align( ), fd_instr_info_pool_footprint( FD_MAX_INSTRUCTION_TRACE_LENGTH ) ),
    FD_MAX_INSTRUCTION_TRACE_LENGTH
  ) );

  txn_ctx->instr_trace_length      = 0;

  memset( txn_ctx->_txn_raw, 0, sizeof(fd_rawtxn_b_t) );
  memset( txn_ctx->return_data.program_id.key, 0, sizeof(fd_pubkey_t) );
  txn_ctx->return_data.len         = 0;


  /* Set up instruction context */

  fd_instr_info_t * info = fd_executor_acquire_instr_info_elem( txn_ctx );
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
    if( !_load_account( &borrowed_accts[j], acc_mgr, funk_txn, &test_ctx->accounts[j] ) )
      return 0;
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
  fd_bpf_scan_and_create_bpf_program_cache_entry( slot_ctx, funk_txn );

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

  /* This function is used to create context both for instructions and for syscalls,
     however some of the remaining checks are only relevant for program instructions. */
  if( !is_syscall ) {
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
    if( !found_program_id ) {
      REPORT( NOTICE, "Unable to find program_id in accounts" );
      return 0;
    }

    /* For native programs, check that the owner is the native loader */
    fd_pubkey_t * const program_id = &txn_ctx->accounts[info->program_id];
    fd_exec_instr_fn_t native_prog_fn = fd_executor_lookup_native_program( program_id );
    if( native_prog_fn && 0 != memcmp( test_ctx->accounts[info->program_id].owner, &fd_solana_native_loader_id, sizeof(fd_pubkey_t) ) ) {
      REPORT( NOTICE, "Native program owner is not NativeLoader" );
      return 0;
    }
  }

  ctx->epoch_ctx = epoch_ctx;
  ctx->funk_txn  = funk_txn;
  ctx->acc_mgr   = acc_mgr;
  ctx->valloc    = fd_scratch_virtual();
  ctx->instr     = info;

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

static int
_txn_context_create( fd_exec_instr_test_runner_t *      runner,
                     fd_exec_txn_ctx_t *                txn_ctx,
                     fd_exec_slot_ctx_t *               slot_ctx,
                     fd_exec_test_txn_context_t const * test_ctx ) {
  fd_funk_t * funk = runner->funk;

  /* Generate unique ID for funk txn */

  fd_funk_txn_xid_t xid[1] = {0};
  xid[0] = fd_funk_generate_xid();

  /* Create temporary funk transaction and scratch contexts */

  fd_funk_txn_t * funk_txn = fd_funk_txn_prepare( funk, NULL, xid, 1 );

  ulong vote_acct_max = 128UL;

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
    return 0;
  }

  /* Restore slot bank */
  fd_slot_bank_new( &slot_ctx->slot_bank );

  /* Initialize builtin accounts */
  fd_builtin_programs_init( slot_ctx );

  /* Load account states into funk (note this is different from the account keys):
    Account state = accounts to populate Funk
    Account keys = account keys that the transaction needs */
  for( ulong i = 0; i < test_ctx->tx.message.account_shared_data_count; i++ ) {
    // Load the accounts into the account manager
    // Borrowed accounts get reset anyways - we just need to load the account somewhere
    FD_BORROWED_ACCOUNT_DECL(acc);
    _load_account( acc, acc_mgr, funk_txn, &test_ctx->tx.message.account_shared_data[i] );
  }

  /* Restore sysvar cache */
  fd_sysvar_cache_restore( slot_ctx->sysvar_cache, acc_mgr, funk_txn );

  /* Add accounts to bpf program cache */
  fd_bpf_scan_and_create_bpf_program_cache_entry( slot_ctx, funk_txn );

  /* Clock MUST be provided in account state since Agave's default clock uses the current
     unix timestamp, which may be used by some programs we fuzz with and cause false mismatches */
  if( !slot_ctx->sysvar_cache->has_clock ) {
    FD_LOG_WARNING(( "Clock sysvar account not provided in account shared data" ));
    return 0;
  }

  /* Sanity check to ensure provided slot matches clock slot */
  if( slot_ctx->sysvar_cache->val_clock->slot != test_ctx->slot_ctx.slot ) {
    FD_LOG_WARNING(( "Clock slot does not match provided slot ctx slot" ));
    return 0;
  }

  /* Set slot bank variables (defaults obtained from GenesisConfig::default() in Agave) */
  slot_ctx->slot_bank.slot                                            = test_ctx->slot_ctx.slot;
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
  epoch_bank->epoch_schedule = default_epoch_schedule;
  epoch_bank->rent           = default_rent;
  epoch_bank->ticks_per_slot = 64;

  // Override default values if provided
  if( slot_ctx->sysvar_cache->has_epoch_schedule ) {
    epoch_bank->epoch_schedule = *slot_ctx->sysvar_cache->val_epoch_schedule;
  }
  if( slot_ctx->sysvar_cache->has_rent ) {
    epoch_bank->rent = *slot_ctx->sysvar_cache->val_rent;
  }

  fd_sysvar_epoch_schedule_init( slot_ctx );
  fd_sysvar_rent_init( slot_ctx );

  /* Restore sysvar cache (again, since we may need to provide default sysvars) */
  fd_sysvar_cache_restore( slot_ctx->sysvar_cache, acc_mgr, funk_txn );

  /* A NaN rent exemption threshold is U.B. in Solana Labs */
  fd_rent_t const * rent = fd_sysvar_cache_rent( slot_ctx->sysvar_cache );
  if( ( !fd_double_is_normal( rent->exemption_threshold ) ) |
      ( rent->exemption_threshold     <      0.0 ) |
      ( rent->exemption_threshold     >    999.0 ) |
      ( rent->lamports_per_uint8_year > UINT_MAX ) |
      ( rent->burn_percent            >      100 ) )
    return 0;

  /* Blockhash queue is given in txn message. We need to populate the following three:
     - slot_ctx->slot_bank.block_hash_queue (TODO: Does more than just the last_hash need to be populated?)
     - sysvar_cache_recent_block_hashes
     - slot_ctx->slot_bank.recent_block_hashes */
  ulong num_blockhashes = test_ctx->blockhash_queue_count;

  /* Recent blockhashes init */
  fd_block_block_hash_entry_t * recent_block_hashes = deq_fd_block_block_hash_entry_t_alloc( fd_scratch_virtual(), FD_SYSVAR_RECENT_HASHES_CAP );

  /* Blockhash queue init */
  slot_ctx->slot_bank.block_hash_queue.max_age   = test_ctx->max_age;
  slot_ctx->slot_bank.block_hash_queue.ages_pool = fd_hash_hash_age_pair_t_map_alloc( fd_scratch_virtual(), 400 );
  slot_ctx->slot_bank.block_hash_queue.last_hash = fd_scratch_alloc( alignof(fd_hash_t), sizeof(fd_hash_t) );

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
      blockhash_entry.fee_calculator.lamports_per_signature = slot_ctx->slot_bank.lamports_per_signature;
      if( i + FD_SYSVAR_RECENT_HASHES_CAP >= num_blockhashes ) {
        // Need to push entries to deque head so most recent blockhash is at idx 0
        deq_fd_block_block_hash_entry_t_push_head( recent_block_hashes, blockhash_entry );
      }

      // Register blockhash in queue
      register_blockhash( slot_ctx, &blockhash_entry.blockhash );
    }
  }

  /* Create the raw txn (https://solana.com/docs/core/transactions#transaction-size) */
  uchar * txn_raw_begin = fd_scratch_alloc( alignof(uchar), FD_TXN_MTU );
  uchar * txn_raw_cur_ptr = txn_raw_begin;

  /* Compact array of signatures (https://solana.com/docs/core/transactions#transaction)
     Note that although documentation interchangably refers to the signature cnt as a compact-u16
     and a u8, the max signature cnt is capped at 48 (due to txn size limits), so u8 and compact-u16
     is represented the same way anyways and can be parsed identically. */
  uchar signature_cnt = (uchar) test_ctx->tx.signatures_count;
  _add_to_data( &txn_raw_cur_ptr, &signature_cnt, sizeof(uchar) );
  for( uchar i = 0; i < signature_cnt; ++i ) {
    _add_to_data( &txn_raw_cur_ptr, test_ctx->tx.signatures[i]->bytes, FD_TXN_SIGNATURE_SZ );
  }

  /* Message */
  /* For v0 transactions, the highest bit of the num_required_signatures is set, and an extra byte is used for the version.
     https://solanacookbook.com/guides/versioned-transactions.html#versioned-transactions-transactionv0 */
  uchar num_required_signatures = (uchar) test_ctx->tx.message.header.num_required_signatures;
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
  _add_to_data( &txn_raw_cur_ptr, test_ctx->tx.message.recent_blockhash->bytes, sizeof(fd_hash_t) );

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
    return 0;
  }

  /* Set up txn_raw */
  fd_rawtxn_b_t raw_txn[1] = {{.raw = txn_raw_begin, .txn_sz = txn_raw_sz}};

  /* Run txn preparation phases
     NOTE: This should be modified accordingly if transaction setup logic changes */
  int res = fd_execute_txn_prepare_phase1( slot_ctx, txn_ctx, txn_descriptor, raw_txn );
  if (res != 0) {
    FD_LOG_WARNING(("could not prepare txn (phase 1 failed)"));
    return 0;
  }

  txn_ctx->funk_txn = funk_txn;

  // fd_execute_txn_prepare_phase2 is deprecated so we use fd_runtime_prepare_txns_phase2_tpool instead
  fd_funk_end_write( funk );

  fd_txn_p_t txn[1];
  memcpy( txn->payload, txn_raw_begin, txn_raw_sz );
  txn->payload_sz = (ulong) txn_raw_sz;
  txn->meta = 0;
  txn->flags = 0;
  memcpy( txn->_, txn_descriptor, fd_txn_footprint( instr_count, addr_table_cnt ) );

  fd_execute_txn_task_info_t task_info[1]; memset( task_info, 0, sizeof(fd_execute_txn_task_info_t) );
  task_info->txn_ctx = txn_ctx;
  task_info->txn = txn;
  txn->flags = 2;

  fd_tpool_t tpool[1];
  tpool->worker_cnt = 1;
  tpool->worker_max = 1;

  res = fd_runtime_prepare_txns_phase2_tpool( slot_ctx, task_info, 1, NULL, NULL, tpool, 1 );
  fd_funk_start_write( funk );
  if (res != 0) {
    FD_LOG_WARNING(("could not prepare txn (phase 2 failed)"));
    return 0;
  }
  res = fd_execute_txn_prepare_phase3( slot_ctx, txn_ctx, txn );
  if (res != 0) {
    FD_LOG_WARNING(("could not prepare txn (phase 3 failed)"));
    return 0;
  }

  res = fd_execute_txn_prepare_phase4( slot_ctx, txn_ctx );
  if (res != 0) {
    FD_LOG_WARNING(("could not prepare txn (phase 4 failed)"));
    return 0;
  }

  return 1;
}

static void
_instr_context_destroy( fd_exec_instr_test_runner_t * runner,
                        fd_exec_instr_ctx_t *         ctx,
                        fd_wksp_t *                   wksp,
                        fd_alloc_t *                  alloc ) {
  if( !ctx ) return;
  fd_exec_slot_ctx_t *  slot_ctx  = ctx->slot_ctx;
  if( !slot_ctx ) return;
  fd_acc_mgr_t *        acc_mgr   = slot_ctx->acc_mgr;
  fd_funk_txn_t *       funk_txn  = slot_ctx->funk_txn;

  // Free any allocated borrowed account data
  for( ulong i = 0; i < ctx->txn_ctx->accounts_cnt; ++i ) {
    fd_borrowed_account_t * acc = &ctx->txn_ctx->borrowed_accounts[i];
    void * borrowed_account_mem = fd_borrowed_account_destroy( acc );
    fd_wksp_t * belongs_to_wksp = fd_wksp_containing( borrowed_account_mem );
    if( belongs_to_wksp ) {
      fd_wksp_free_laddr( borrowed_account_mem );
    }
  }

  // Free instr info pool (since its also wksp-allocated)
  if( ctx->txn_ctx->instr_info_pool ) {
    void * instr_info_mem = fd_instr_info_pool_delete( fd_instr_info_pool_leave( ctx->txn_ctx->instr_info_pool ) );
    fd_wksp_t * belongs_to_wksp = fd_wksp_containing( instr_info_mem );
    if( belongs_to_wksp ) {
      fd_wksp_free_laddr( instr_info_mem );
    }
  }

  // Free alloc
  if( alloc ) {
    fd_wksp_free_laddr( fd_alloc_delete( fd_alloc_leave( alloc ) ) );
  }

  // Detach from workspace
  fd_wksp_detach( wksp );

  fd_exec_slot_ctx_free( slot_ctx );
  fd_acc_mgr_delete( acc_mgr );
  fd_scratch_pop();
  fd_funk_txn_cancel( runner->funk, funk_txn, 1 );

  ctx->slot_ctx = NULL;
}

static void
_txn_context_destroy( fd_exec_instr_test_runner_t * runner,
                      fd_exec_txn_ctx_t *           txn_ctx,
                      fd_exec_slot_ctx_t *          slot_ctx,
                      fd_wksp_t *                   wksp,
                      fd_alloc_t *                  alloc ) {
  if( !txn_ctx ) return; // This shouldn't be false
  if( !slot_ctx ) return; // This shouldn't be false either
  fd_acc_mgr_t *        acc_mgr   = slot_ctx->acc_mgr;
  fd_funk_txn_t *       funk_txn  = slot_ctx->funk_txn;

  // Free any allocated borrowed account data
  for( ulong i = 0; i < txn_ctx->accounts_cnt; ++i ) {
    fd_borrowed_account_t * acc = &txn_ctx->borrowed_accounts[i];
    void * borrowed_account_mem = fd_borrowed_account_destroy( acc );
    fd_wksp_t * belongs_to_wksp = fd_wksp_containing( borrowed_account_mem );
    if( belongs_to_wksp ) {
      fd_wksp_free_laddr( borrowed_account_mem );
    }
  }

  // Free instr info pool (since its also wksp-allocated)
  if( txn_ctx->instr_info_pool ) {
    void * instr_info_mem = fd_instr_info_pool_delete( fd_instr_info_pool_leave( txn_ctx->instr_info_pool ) );
    fd_wksp_t * belongs_to_wksp = fd_wksp_containing( instr_info_mem );

    // Only free instr info mem if it was wksp-allocated
    if( belongs_to_wksp ) {
      fd_wksp_free_laddr( instr_info_mem );
    }
  }

  // Free alloc
  if( alloc ) {
    fd_wksp_free_laddr( fd_alloc_delete( fd_alloc_leave( alloc ) ) );
  }

  // Detach from workspace
  fd_wksp_detach( wksp );

  fd_exec_slot_ctx_free( slot_ctx );
  fd_acc_mgr_delete( acc_mgr );
  fd_funk_txn_cancel( runner->funk, funk_txn, 1 );
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
    REPORTV( NOTICE, "expected result (%d-%s), got (%d-%s)",
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
    REPORTV( WARNING, "expected return data size %lu, got %lu",
             (ulong) data_sz, ctx->txn_ctx->return_data.len );
  }
  else if (data_sz > 0 ) {
    check->has_diff = memcmp( expected->return_data->bytes, ctx->txn_ctx->return_data.data, expected->return_data->size );
    REPORT( WARNING, "return data mismatch" );
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
  if( FD_UNLIKELY( !_instr_context_create( runner, ctx, &test->input, alloc, false ) ) ) {
    _instr_context_destroy( runner, ctx, wksp, alloc );
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

  _instr_context_destroy( runner, ctx, wksp, alloc );
  return !has_diff;
}

ulong
fd_exec_instr_test_run( fd_exec_instr_test_runner_t *        runner,
                        fd_exec_test_instr_context_t const * input,
                        fd_exec_test_instr_effects_t **      output,
                        void *                               output_buf,
                        ulong                                output_bufsz ) {
  fd_wksp_t *  wksp  = fd_wksp_attach( "wksp" );
  fd_alloc_t * alloc = fd_alloc_join( fd_alloc_new( fd_wksp_alloc_laddr( wksp, fd_alloc_align(), fd_alloc_footprint(), 2 ), 2 ), 0 );

  /* Convert the Protobuf inputs to a fd_exec context */
  fd_exec_instr_ctx_t ctx[1];
  if( !_instr_context_create( runner, ctx, input, alloc, false ) ) {
    _instr_context_destroy( runner, ctx, wksp, alloc );
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
    _instr_context_destroy( runner, ctx, wksp, alloc );
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
    effects->custom_err     = ctx->txn_ctx->custom_err;
  }

  /* Allocate space for captured accounts */
  ulong modified_acct_cnt = ctx->txn_ctx->accounts_cnt;

  fd_exec_test_acct_state_t * modified_accts =
    FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_exec_test_acct_state_t),
                                sizeof (fd_exec_test_acct_state_t) * modified_acct_cnt );
  if( FD_UNLIKELY( _l > output_end ) ) {
    _instr_context_destroy( runner, ctx, wksp, alloc );
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
    out_acct->lamports     = acc->meta->info.lamports;
    out_acct->data =
      FD_SCRATCH_ALLOC_APPEND( l, alignof(pb_bytes_array_t),
                                  PB_BYTES_ARRAY_T_ALLOCSIZE( acc->const_meta->dlen ) );
    if( FD_UNLIKELY( _l > output_end ) ) {
      _instr_context_destroy( runner, ctx, wksp, alloc );
      return 0UL;
    }
    out_acct->data->size = (pb_size_t)acc->const_meta->dlen;
    fd_memcpy( out_acct->data->bytes, acc->const_data, acc->const_meta->dlen );

    out_acct->executable     = acc->meta->info.executable;
    out_acct->rent_epoch     = acc->meta->info.rent_epoch;
    memcpy( out_acct->owner, acc->meta->info.owner, sizeof(fd_pubkey_t) );

    effects->modified_accounts_count++;
  }

  /* Capture return data */
  fd_txn_return_data_t * return_data = &ctx->txn_ctx->return_data;
  effects->return_data = FD_SCRATCH_ALLOC_APPEND(l, alignof(pb_bytes_array_t),
                              PB_BYTES_ARRAY_T_ALLOCSIZE( return_data->len ) );
  if( FD_UNLIKELY( _l > output_end ) ) {
    _instr_context_destroy( runner, ctx, wksp, alloc );
    return 0UL;
  }
  effects->return_data->size = (pb_size_t)return_data->len;
  fd_memcpy( effects->return_data->bytes, return_data->data, return_data->len );

  ulong actual_end = FD_SCRATCH_ALLOC_FINI( l, 1UL );
  _instr_context_destroy( runner, ctx, wksp, alloc );

  *output = effects;
  return actual_end - (ulong)output_buf;
}

ulong
fd_exec_txn_test_run( fd_exec_instr_test_runner_t *        runner, // Runner only contains funk instance, so we can borrow instr test runner
                      fd_exec_test_txn_context_t const *   input,
                      fd_exec_test_txn_result_t **         output,
                      void *                               output_buf,
                      ulong                                output_bufsz ) {
  FD_SCRATCH_SCOPE_BEGIN {
    /* Initialize memory */
    fd_wksp_t *           wksp          = fd_wksp_attach( "wksp" );
    fd_alloc_t *          alloc         = fd_alloc_join( fd_alloc_new( fd_wksp_alloc_laddr( wksp, fd_alloc_align(), fd_alloc_footprint(), 2 ), 2 ), 0 );
    fd_exec_txn_ctx_t *   txn_ctx       = fd_scratch_alloc( FD_EXEC_TXN_CTX_ALIGN, FD_EXEC_TXN_CTX_FOOTPRINT );
    uchar *               slot_ctx_mem  = fd_scratch_alloc( FD_EXEC_SLOT_CTX_ALIGN,  FD_EXEC_SLOT_CTX_FOOTPRINT  );
    fd_exec_slot_ctx_t *  slot_ctx      = fd_exec_slot_ctx_join ( fd_exec_slot_ctx_new ( slot_ctx_mem, fd_alloc_virtual( alloc ) ) );

    if( !_txn_context_create( runner, txn_ctx, slot_ctx, input ) ) {
      _txn_context_destroy( runner, txn_ctx, slot_ctx, wksp, alloc );
      return 0UL;
    }

    /* Execute txn */
    int exec_res = fd_execute_txn( txn_ctx );

    /* Collect rent */
    _txn_collect_rent( txn_ctx );

    /* Start saving txn exec results */
    FD_SCRATCH_ALLOC_INIT( l, output_buf );
    ulong output_end = (ulong)output_buf + output_bufsz;

    fd_exec_test_txn_result_t * txn_result =
    FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_exec_test_txn_result_t),
                                  sizeof (fd_exec_test_txn_result_t) );
    if( FD_UNLIKELY( _l > output_end ) ) {
      _txn_context_destroy( runner, txn_ctx, slot_ctx, wksp, alloc );
      return 0UL;
    }
    fd_memset( txn_result, 0, sizeof(fd_exec_test_txn_result_t) );

    /* Allocate space for captured accounts */
    ulong modified_acct_cnt  = txn_ctx->accounts_cnt;

    fd_exec_test_acct_state_t * modified_accts =
      FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_exec_test_acct_state_t),
                                  sizeof (fd_exec_test_acct_state_t) * modified_acct_cnt );
    if( FD_UNLIKELY( _l > output_end ) ) {
      _txn_context_destroy( runner, txn_ctx, slot_ctx, wksp, alloc );
      return 0;
    }
    txn_result->has_resulting_state               = true;
    txn_result->resulting_state.acct_states       = modified_accts;
    txn_result->resulting_state.acct_states_count = 0;

    // TODO: txn_result->resulting_state->rent_debits

    /* Capture borrowed accounts */

    for( ulong j=0UL; j < txn_ctx->accounts_cnt; j++ ) {
      fd_borrowed_account_t * acc = &txn_ctx->borrowed_accounts[j];
      if( !acc->const_meta ) continue;

      ulong modified_idx = txn_result->resulting_state.acct_states_count;
      assert( modified_idx < modified_acct_cnt );

      fd_exec_test_acct_state_t * out_acct = &txn_result->resulting_state.acct_states[ modified_idx ];
      memset( out_acct, 0, sizeof(fd_exec_test_acct_state_t) );
      /* Copy over account content */

      memcpy( out_acct->address, acc->pubkey, sizeof(fd_pubkey_t) );

      out_acct->lamports = acc->const_meta->info.lamports;

      out_acct->data =
        FD_SCRATCH_ALLOC_APPEND( l, alignof(pb_bytes_array_t),
                                    PB_BYTES_ARRAY_T_ALLOCSIZE( acc->const_meta->dlen ) );
      if( FD_UNLIKELY( _l > output_end ) ) {
        _txn_context_destroy( runner, txn_ctx, slot_ctx, wksp, alloc );
        return 0UL;
      }
      out_acct->data->size = (pb_size_t)acc->const_meta->dlen;
      fd_memcpy( out_acct->data->bytes, acc->const_data, acc->const_meta->dlen );

      out_acct->executable     = acc->const_meta->info.executable;
      out_acct->rent_epoch     = acc->const_meta->info.rent_epoch;
      memcpy( out_acct->owner, acc->const_meta->info.owner, sizeof(fd_pubkey_t) );

      txn_result->resulting_state.acct_states_count++;

      // TODO: Figure out rent debits
    }

    txn_result->executed = 1;
    txn_result->rent = txn_ctx->slot_ctx->slot_bank.collected_rent;
    txn_result->is_ok = !exec_res;
    txn_result->status = (uint32_t) -exec_res;
    txn_result->return_data = FD_SCRATCH_ALLOC_APPEND( l, alignof(pb_bytes_array_t),
                                    PB_BYTES_ARRAY_T_ALLOCSIZE( txn_ctx->return_data.len ) );
    if( FD_UNLIKELY( _l > output_end ) ) {
      _txn_context_destroy( runner, txn_ctx, slot_ctx, wksp, alloc );
      return 0UL;
    }

    txn_result->return_data->size = (pb_size_t)txn_ctx->return_data.len;
    fd_memcpy( txn_result->return_data->bytes, txn_ctx->return_data.data, txn_ctx->return_data.len );

    txn_result->executed_units = txn_ctx->compute_unit_limit - txn_ctx->compute_meter;
    txn_result->has_fee_details = true;
    txn_result->fee_details.transaction_fee = txn_ctx->slot_ctx->slot_bank.collected_execution_fees;
    txn_result->fee_details.prioritization_fee = txn_ctx->slot_ctx->slot_bank.collected_priority_fees;

    ulong actual_end = FD_SCRATCH_ALLOC_FINI( l, 1UL );
    _txn_context_destroy( runner, txn_ctx, slot_ctx, wksp, alloc );

    *output = txn_result;
    return actual_end - (ulong)output_buf;
  } FD_SCRATCH_SCOPE_END;
}


ulong
fd_sbpf_program_load_test_run( FD_PARAM_UNUSED fd_exec_instr_test_runner_t * runner,
                               fd_exec_test_elf_loader_ctx_t const * input,
                               fd_exec_test_elf_loader_effects_t **  output,
                               void *                                output_buf,
                               ulong                                 output_bufsz ){
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

ulong
fd_exec_vm_syscall_test_run( fd_exec_instr_test_runner_t *          runner,
                             fd_exec_test_syscall_context_t const * input,
                             fd_exec_test_syscall_effects_t **      output,
                             void *                                 output_buf,
                             ulong                                  output_bufsz ) {
  fd_wksp_t *  wksp  = fd_wksp_attach( "wksp" );
  fd_alloc_t * alloc = fd_alloc_join( fd_alloc_new( fd_wksp_alloc_laddr( wksp, fd_alloc_align(), fd_alloc_footprint(), 2 ), 2 ), 0 );

  /* Create execution context */
  const fd_exec_test_instr_context_t * input_instr_ctx = &input->instr_ctx;
  fd_exec_instr_ctx_t ctx[1];
  if( !_instr_context_create( runner, ctx, input_instr_ctx, alloc, true ) )
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
  fd_memset( effects, 0, sizeof(fd_exec_test_instr_effects_t) );

  /* Set up the VM instance */
  fd_sha256_t _sha[1];
  fd_sha256_t * sha = fd_sha256_join( fd_sha256_new( _sha ) );
  fd_sbpf_syscalls_t * syscalls = fd_sbpf_syscalls_new( fd_valloc_malloc( valloc, fd_sbpf_syscalls_align(), fd_sbpf_syscalls_footprint() ) );
  fd_vm_syscall_register_all( syscalls, 0 );

  /* Pull out the memory regions */
  if( !input->has_vm_ctx || !input->vm_ctx.rodata ) {
    goto error;
  }
  uchar * rodata = input->vm_ctx.rodata->bytes;
  ulong rodata_sz = input->vm_ctx.rodata->size;

  /* Concatenate the input data regions into the flat input memory region */
  ulong input_data_sz = 0;
  for ( ulong i=0; i<input->vm_ctx.input_data_regions_count; i++ ) {
    if( !input->vm_ctx.input_data_regions[i].content ) {
      continue;
    }
    input_data_sz += input->vm_ctx.input_data_regions[i].content->size;
  }
  uchar * input_data = fd_valloc_malloc( valloc, alignof(uchar), input_data_sz );
  uchar * input_data_ptr = input_data;
  for ( ulong i=0; i<input->vm_ctx.input_data_regions_count; i++ ) {
    pb_bytes_array_t * array = input->vm_ctx.input_data_regions[i].content;
    if( !input->vm_ctx.input_data_regions[i].content ) {
      continue;
    }
    fd_memcpy( input_data_ptr, array->bytes, array->size );
    input_data_ptr += array->size;
  }
  if( input_data_ptr != (input_data + input_data_sz) ) {
    goto error;
  }

  if (input->vm_ctx.heap_max > FD_VM_HEAP_DEFAULT) {
    goto error;
  }

  fd_vm_t * vm = fd_vm_join( fd_vm_new( fd_valloc_malloc( valloc, fd_vm_align(), fd_vm_footprint() ) ) );
  if ( !vm ) {
    goto error;
  }
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
    input_data,
    input_data_sz,
    NULL, // TODO
    sha);

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

  vm->check_align = input->vm_ctx.check_align;
  vm->check_size = input->vm_ctx.check_size;

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

  // Look up the syscall to execute
  char * syscall_name = (char *)input->syscall_invocation.function_name.bytes;
  fd_sbpf_syscalls_t const * syscall = lookup_syscall_func(syscalls, syscall_name, input->syscall_invocation.function_name.size);
  if( !syscall ) {
    goto error;
  }

  /* Actually invoke the syscall */
  int syscall_err = syscall->func( vm, vm->reg[1], vm->reg[2], vm->reg[3], vm->reg[4], vm->reg[5], &vm->reg[0] );

  /* Capture the effects */
  effects->error = -syscall_err;
  effects->r0 = vm->reg[0];
  effects->cu_avail = (ulong)vm->cu;

  effects->heap = FD_SCRATCH_ALLOC_APPEND(
    l, alignof(uchar), PB_BYTES_ARRAY_T_ALLOCSIZE( vm->heap_max ) );
  effects->heap->size = (uint)vm->heap_max;
  fd_memcpy( effects->heap->bytes, vm->heap, vm->heap_max );

  effects->stack = FD_SCRATCH_ALLOC_APPEND(
    l, alignof(uchar), PB_BYTES_ARRAY_T_ALLOCSIZE( FD_VM_STACK_MAX ) );
  effects->stack->size = (uint)FD_VM_STACK_MAX;
  fd_memcpy( effects->stack->bytes, vm->stack, FD_VM_STACK_MAX );

  if( input_data_sz ) {
    effects->inputdata = FD_SCRATCH_ALLOC_APPEND(
      l, alignof(uchar), PB_BYTES_ARRAY_T_ALLOCSIZE( input_data_sz ) );
    effects->inputdata->size = (uint)input_data_sz;
    fd_memcpy( effects->inputdata->bytes, vm->input, input_data_sz );
  } else {
    effects->inputdata = NULL;
  }

  effects->frame_count = vm->frame_cnt;

  if( vm->log_sz ) {
    effects->log = FD_SCRATCH_ALLOC_APPEND(
      l, alignof(uchar), PB_BYTES_ARRAY_T_ALLOCSIZE( vm->log_sz ) );
    effects->log->size = (uint)vm->log_sz;
    fd_memcpy( effects->log->bytes, vm->log, vm->log_sz );
  } else {
    effects->log = NULL;
  }

  /* Return the effects */
  ulong actual_end = FD_SCRATCH_ALLOC_FINI( l, 1UL );
  _instr_context_destroy( runner, ctx, wksp, alloc );

  *output = effects;
  return actual_end - (ulong)output_buf;

error:
  _instr_context_destroy( runner, ctx, wksp, alloc );
  return 0;
}
