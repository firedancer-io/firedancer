#include "fd_svm_mini.h"
#include "../runtime/sysvar/fd_sysvar_rent.h"
#include "../runtime/sysvar/fd_sysvar_epoch_schedule.h"
#include "../runtime/sysvar/fd_sysvar_clock.h"
#include "../runtime/sysvar/fd_sysvar_stake_history.h"
#include "fd_accdb_mini.h"
#include "fd_progcache_mini.h"

#define DEFAULT_LAMPORTS_PER_UINT8_YEAR (3480UL)
#define DEFAULT_EXEMPTION_THRESHOLD     (2.0)

#define DEFAULT_SLOTS_PER_EPOCH (432000UL)

static void
init_features( fd_svm_view_t * env ) {
  fd_features_t * features = fd_bank_features_modify( env->bank );
  fd_features_disable_all( features );
}

static void
init_rent( fd_svm_view_t * env ) {
  fd_rent_t rent = {
    .lamports_per_uint8_year = DEFAULT_LAMPORTS_PER_UINT8_YEAR,
    .exemption_threshold     = DEFAULT_EXEMPTION_THRESHOLD,
    .burn_percent            = 50
  };

  fd_bank_rent_set( env->bank, rent );
  fd_sysvar_rent_write( env->bank, env->accdb, &env->xid, NULL, &rent );
}

static void
init_epoch_schedule( fd_svm_view_t * view ) {
  fd_epoch_schedule_t epoch_schedule = {
    .slots_per_epoch             = DEFAULT_SLOTS_PER_EPOCH,
    .leader_schedule_slot_offset = DEFAULT_SLOTS_PER_EPOCH,
    .warmup                      = 0,
    .first_normal_epoch          = 0UL,
    .first_normal_slot           = 0UL
  };

  fd_bank_epoch_schedule_set( view->bank, epoch_schedule );
  fd_sysvar_epoch_schedule_write( view->bank, view->accdb, &view->xid, NULL, &epoch_schedule );
}

static void
init_clock( fd_svm_view_t * env ) {
  fd_sysvar_clock_init( env->bank, env->accdb, &env->xid, NULL );
}

static void
init_stake_history( fd_svm_view_t * env ) {
  fd_sysvar_stake_history_init( env->bank, env->accdb, &env->xid, NULL );
}

static void
init_vote_states( fd_svm_view_t * env ) {
  ulong max_vote_accounts = env->mini->limits.max_vote_accounts;

  fd_vote_states_t * vote_states = fd_bank_vote_states_locking_modify( env->bank );
  vote_states = fd_vote_states_join( fd_vote_states_new( vote_states, max_vote_accounts, 999UL ) );
  fd_bank_vote_states_end_locking_modify( env->bank );

  fd_vote_states_t * vote_states_prev = fd_bank_vote_states_prev_locking_modify( env->bank );
  vote_states_prev = fd_vote_states_join( fd_vote_states_new( vote_states_prev, max_vote_accounts, 999UL ) );
  fd_bank_vote_states_prev_end_locking_modify( env->bank );

  fd_vote_states_t * vote_states_prev_prev = fd_bank_vote_states_prev_prev_locking_modify( env->bank );
  vote_states_prev_prev = fd_vote_states_join( fd_vote_states_new( vote_states_prev_prev, max_vote_accounts, 999UL ) );
  fd_bank_vote_states_prev_prev_end_locking_modify( env->bank );
}

static void
init_blockhash_queue( fd_svm_view_t * env ) {
  ulong slot = fd_bank_slot_get( env->bank );
  ulong h0   = fd_ulong_hash( slot );
  ulong h1   = fd_ulong_hash( h0   );
  ulong h2   = fd_ulong_hash( h1   );
  ulong h3   = fd_ulong_hash( h2   );

  fd_blockhashes_t * bhq = fd_blockhashes_init( fd_bank_block_hash_queue_modify( env->bank ), 1UL );

  fd_hash_t dummy_hash = { .ul={ h0, h1, h2, h3 } };
  fd_blockhash_info_t * info = fd_blockhashes_push_new( bhq, &dummy_hash );
  info->fee_calculator.lamports_per_signature = 5000;
}

static void
init_root_view( fd_svm_view_t * view ) {
  init_features       ( view );
  init_rent           ( view );
  init_epoch_schedule ( view );
  init_clock          ( view );
  init_stake_history  ( view );
  init_blockhash_queue( view );
  init_vote_states    ( view );
}

static fd_svm_view_t *
create_view( fd_svm_mini_t * mini,
             fd_bank_t *     bank ) {
  fd_svm_view_t * view = aligned_alloc( alignof(fd_svm_view_t), sizeof(fd_svm_view_t) );
  if( FD_UNLIKELY( !view ) ) return NULL;
  mini->view_cnt++;
  bank->refcnt++;
  return view;
}

static void
free_view( fd_svm_view_t * view ) {
  if( FD_UNLIKELY( !view ||
                   !view->bank ||
                   !view->mini ) ) {
    FD_LOG_CRIT(( "invalid free" ));
  }
  if( FD_UNLIKELY( !view->bank->refcnt ) ) {
    FD_LOG_CRIT(( "ivnalid bank refcnt" ));
  }
  if( FD_UNLIKELY( !view->mini->view_cnt ) ) {
    FD_LOG_CRIT(( "invalid mini view_cnt" ));
  }
  view->bank->refcnt--;
  view->mini->view_cnt--;
  free( view );
}

fd_svm_mini_t *
fd_svm_mini_create( fd_svm_mini_limits_t const * user_limits,
                    char const *                 name,
                    ulong                        root_slot ) {

  /* Derive params */

  ulong name_len;
  if( FD_UNLIKELY( !name ||
                   !*name ||
                   (name_len = strlen( name )) > FD_SHMEM_NAME_MAX-16UL ) ) {
    FD_LOG_WARNING(( "invalid name parameter" ));
    return NULL;
  }
  char wksp_name_accdb    [ FD_SHMEM_NAME_MAX ];
  char wksp_name_progcache[ FD_SHMEM_NAME_MAX ];
  fd_cstr_fini( fd_cstr_append_cstr( fd_cstr_append_text( fd_cstr_init(
      wksp_name_accdb ), name, name_len ), "_accdb" ) );
  fd_cstr_fini( fd_cstr_append_cstr( fd_cstr_append_text( fd_cstr_init(
      wksp_name_progcache ), name, name_len ), "_progcache" ) );

  if( FD_UNLIKELY( !user_limits ) ) {
    FD_LOG_WARNING(( "NULL limits" ));
    return NULL;
  }
  fd_svm_mini_limits_t limits = *user_limits;
  if( !limits.max_accounts       ) limits.max_accounts       = fd_svm_mini_limits_default.max_accounts;
  if( !limits.accdb_heap_sz      ) limits.accdb_heap_sz      = fd_svm_mini_limits_default.accdb_heap_sz;
  if( !limits.max_progcache_recs ) limits.max_progcache_recs = fd_svm_mini_limits_default.max_progcache_recs;
  if( !limits.progcache_heap_sz  ) limits.progcache_heap_sz  = fd_svm_mini_limits_default.progcache_heap_sz;
  if( !limits.max_vote_accounts  ) limits.max_vote_accounts  = fd_svm_mini_limits_default.max_vote_accounts;
  if( !limits.max_live_slots     ) limits.max_live_slots     = fd_svm_mini_limits_default.max_live_slots;
  if( !limits.max_frozen_slots   ) limits.max_frozen_slots   = fd_svm_mini_limits_default.max_frozen_slots;

  /* Allocate objects */

  fd_svm_mini_t *       svm            = NULL;
  void *                banks_mem      = NULL;
  fd_accdb_mini_t *     accdb_mini     = NULL;
  fd_progcache_mini_t * progcache_mini = NULL;

  svm = aligned_alloc( alignof(fd_svm_mini_t), sizeof(fd_svm_mini_t) );
  if( FD_UNLIKELY( !svm ) ) goto oom;
  memset( svm, 0, sizeof(fd_svm_mini_t) );

  accdb_mini = fd_accdb_mini_create(
      svm->accdb_mini,
      limits.max_accounts,
      limits.max_live_slots,
      wksp_name_accdb,
      limits.accdb_heap_sz,
      1UL );
  if( FD_UNLIKELY( !accdb_mini ) ) goto fail;

  progcache_mini = fd_progcache_mini_create(
      svm->progcache_mini,
      limits.max_progcache_recs,
      limits.max_live_slots,
      wksp_name_progcache,
      limits.progcache_heap_sz,
      1UL );
  if( FD_UNLIKELY( !progcache_mini ) ) goto fail;

  ulong max_total_banks = limits.max_live_slots + limits.max_frozen_slots;
  banks_mem = aligned_alloc( fd_banks_align(), fd_banks_footprint( max_total_banks, limits.max_live_slots ) );
  if( FD_UNLIKELY( !banks_mem ) ) goto oom;
  svm->banks = fd_banks_join( fd_banks_new( banks_mem, max_total_banks, limits.max_live_slots, 0, 1UL ) );
  if( FD_UNLIKELY( !svm->banks ) ) FD_LOG_ERR(( "out of memory: failed to allocate fd_banks_t" ));

  svm->limits = limits;
  fd_accdb_mini_join_admin    ( svm->accdb_mini,     svm->accdb_admin     );
  fd_progcache_mini_join_admin( svm->progcache_mini, svm->progcache_admin );

  /* Initial state */

  fd_stake_delegations_t * stake_delegations = fd_banks_stake_delegations_root_query( svm->banks );
  fd_stake_delegations_join( fd_stake_delegations_new( stake_delegations, 1UL, 0 ) );

  fd_bank_t * root_bank = fd_banks_init_bank( svm->banks );
  if( FD_UNLIKELY( !root_bank ) ) FD_LOG_CRIT(( "fd_banks_init_bank failed" ));
  fd_bank_slot_set( root_bank, root_slot );

  fd_svm_view_t * root_view = create_view( svm, root_bank );
  if( FD_UNLIKELY( !root_view ) ) goto oom;
  init_root_view( root_view );

  /* Undo failed creation */

oom:
  FD_LOG_WARNING(( "failed to create svm_mini: out of memory (malloc failed)" ));
fail:
  free( svm       );
  free( banks_mem );
  if( accdb_mini     ) fd_accdb_mini_destroy    ( accdb_mini     );
  if( progcache_mini ) fd_progcache_mini_destroy( progcache_mini );
  return NULL;
}

void
fd_svm_mini_destroy( fd_svm_mini_t * svm ) {
  fd_progcache_admin_leave( svm->progcache_admin, NULL );
  fd_progcache_mini_destroy( svm->progcache_mini );
  fd_accdb_admin_leave( svm->accdb_admin, NULL );
  fd_accdb_mini_destroy( svm->accdb_mini );
  free( fd_banks_delete( fd_banks_leave( svm->banks ) ) );
  free( svm );
}

fd_svm_view_t *
fd_svm_mini_join_root( fd_svm_mini_t * svm ) {
}

fd_svm_view_t *
fd_svm_view_fork( fd_svm_view_t * view,
                  ulong           slot ) {
  fd_svm_mini_t *   mini = view->mini;
  fd_bank_t *       bank = view->bank;
  fd_funk_txn_xid_t xid  = view->xid;
  if( FD_UNLIKELY( !( bank->flags & FD_BANK_FLAGS_FROZEN ) ) ) {
    FD_LOG_CRIT(( "refusing to create fork: bank (xid %lu:%lu) is not frozen", xid.ul[0], xid.ul[1] ));
  }

  fd_bank_t * new_bank = fd_banks_new_bank( mini->banks, bank->idx, fd_log_wallclock() );
  if( FD_UNLIKELY( !new_bank ) ) {
    FD_LOG_CRIT(( "failed to create fork: no free banks" ));
  }
  if( FD_UNLIKELY( !fd_banks_clone_from_parent( mini->banks, new_bank->idx, bank->idx ) ) ) {
    FD_LOG_CRIT(( "fd_banks_clone_from_parent failed" ));
  }

  fd_epoch_schedule_t const * epoch_schedule = fd_bank_epoch_schedule_query( new_bank );
  ulong epoch = fd_slot_to_epoch( epoch_schedule, slot, NULL );
  fd_bank_epoch_set( new_bank, epoch );

  fd_funk_txn_xid_t new_xid = { .ul = { slot, new_bank->bank_seq } };
  fd_accdb_attach_child        ( mini->accdb_admin,     &xid, &new_xid );
  fd_progcache_txn_attach_child( mini->progcache_admin, &xid, &new_xid );

  fd_svm_view_t * new_view = create_view( mini, new_bank );
  if( FD_UNLIKELY( !new_view ) ) {
    FD_LOG_CRIT(( "out of memory: failed to allocate svm_view" ));
  }
  new_view->mini          = mini;
  new_view->bank          = new_bank;
  new_view->runtime_stack = NULL;
  fd_accdb_mini_join_user    ( mini->accdb_mini,     new_view->accdb     );
  fd_progcache_mini_join_user( mini->progcache_mini, new_view->progcache );
  new_view->xid = new_xid;

  return new_view;
}

void
fd_svm_view_advance_root( fd_svm_view_t * view ) {

  /* Destruct view */

  fd_funk_txn_xid_t xid  = view->xid;
  fd_bank_t *       bank = view->bank;


}

void
fd_svm_view_leave( fd_svm_view_t * view ) {
}

void
fd_svm_view_delete( fd_svm_view_t * view ) {
}
