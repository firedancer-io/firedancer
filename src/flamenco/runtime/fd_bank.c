#include "fd_bank.h"
#include "fd_runtime_const.h"
#include "../rewards/fd_stake_rewards.h"

fd_lthash_value_t const *
fd_bank_lthash_locking_query( fd_bank_t * bank ) {
  fd_rwlock_read( &bank->data->lthash_lock );
  return &bank->data->f.lthash;
}

void
fd_bank_lthash_end_locking_query( fd_bank_t * bank ) {
  fd_rwlock_unread( &bank->data->lthash_lock );
}

fd_lthash_value_t *
fd_bank_lthash_locking_modify( fd_bank_t * bank ) {
  fd_rwlock_write( &bank->data->lthash_lock );
  return &bank->data->f.lthash;
}

void
fd_bank_lthash_end_locking_modify( fd_bank_t * bank ) {
  fd_rwlock_unwrite( &bank->data->lthash_lock );
}

ulong
fd_banks_align( void ) {
  return FD_BANKS_ALIGN;
}

static fd_bank_data_t *
fd_banks_get_bank_pool( fd_banks_t * banks_data ) {
  return fd_type_pun( (uchar *)banks_data + banks_data->pool_offset );
}

static fd_bank_idx_seq_t *
fd_banks_get_dead_banks_deque( fd_banks_t * banks_data ) {
  return fd_type_pun( (uchar *)banks_data + banks_data->dead_banks_deque_offset );
}

static fd_epoch_leaders_t *
fd_banks_get_epoch_leaders( fd_banks_t * banks_data ) {
  return fd_type_pun( (uchar *)banks_data + banks_data->epoch_leaders_offset );
}

static fd_stake_delegations_t *
fd_banks_get_stake_delegations( fd_banks_t * banks_data ) {
  return fd_type_pun( (uchar *)banks_data + banks_data->stake_delegations_offset );
}

static fd_bank_cost_tracker_t *
fd_banks_get_cost_tracker_pool( fd_banks_t * banks_data ) {
  return fd_type_pun( (uchar *)banks_data + banks_data->cost_tracker_pool_offset );
}

static fd_stake_rewards_t *
fd_banks_get_stake_rewards( fd_banks_t * banks_data ) {
  return fd_type_pun( (uchar *)banks_data + banks_data->stake_rewards_offset );
}

static fd_vote_stakes_t *
fd_banks_get_vote_stakes( fd_banks_t * banks_data ) {
  return fd_type_pun( (uchar *)banks_data + banks_data->vote_stakes_pool_offset );
}

fd_vote_stakes_t *
fd_bank_vote_stakes( fd_bank_t const * bank ) {
  fd_banks_t * banks_data = fd_type_pun( (uchar *)bank->data - bank->data->banks_data_offset );
  return fd_banks_get_vote_stakes( banks_data );
}

fd_stake_delegations_t *
fd_bank_stake_delegations_modify( fd_bank_t * bank ) {
  fd_banks_t * banks_data = fd_type_pun( (uchar *)bank->data - bank->data->banks_data_offset );
  return fd_banks_get_stake_delegations( banks_data );
}

fd_stake_rewards_t const *
fd_bank_stake_rewards_query( fd_bank_t * bank ) {
  fd_banks_t * banks_data = fd_type_pun( (uchar *)bank->data - bank->data->banks_data_offset );
  return fd_type_pun_const( fd_banks_get_stake_rewards( banks_data ) );
}

fd_stake_rewards_t *
fd_bank_stake_rewards_modify( fd_bank_t * bank ) {
  fd_banks_t * banks_data = fd_type_pun( (uchar *)bank->data - bank->data->banks_data_offset );
  return fd_banks_get_stake_rewards( banks_data );
}

fd_epoch_leaders_t const *
fd_bank_epoch_leaders_query( fd_bank_t const * bank ) {
  if( FD_UNLIKELY( bank->data->epoch_leaders_idx==ULONG_MAX ) ) {
    return NULL;
  }
  fd_banks_t * banks_data = fd_type_pun( (uchar *)bank->data - bank->data->banks_data_offset );
  return (fd_epoch_leaders_t const *)fd_type_pun( (uchar *)fd_banks_get_epoch_leaders( banks_data ) + bank->data->epoch_leaders_idx * banks_data->epoch_leaders_footprint );
}

fd_epoch_leaders_t *
fd_bank_epoch_leaders_modify( fd_bank_t * bank ) {
  ulong idx = bank->data->f.epoch % 2UL;
  bank->data->epoch_leaders_idx = idx;
  fd_banks_t * banks_data = fd_type_pun( (uchar *)bank->data - bank->data->banks_data_offset );
  return (fd_epoch_leaders_t *)fd_type_pun( (uchar *)fd_banks_get_epoch_leaders( banks_data ) + idx * banks_data->epoch_leaders_footprint );
}

fd_top_votes_t const *
fd_bank_top_votes_t_1_query( fd_bank_t const * bank ) {
  return fd_type_pun_const( bank->data->top_votes_t_1_mem );
}

fd_top_votes_t *
fd_bank_top_votes_t_1_modify( fd_bank_t * bank ) {
  return fd_type_pun( bank->data->top_votes_t_1_mem );
}

fd_top_votes_t const *
fd_bank_top_votes_t_2_query( fd_bank_t const * bank ) {
  return fd_type_pun_const( bank->data->top_votes_t_2_mem );
}

fd_top_votes_t *
fd_bank_top_votes_t_2_modify( fd_bank_t * bank ) {
  return fd_type_pun( bank->data->top_votes_t_2_mem );
}

fd_cost_tracker_t *
fd_bank_cost_tracker_modify( fd_bank_t * bank ) {
  fd_banks_t * banks_data = fd_type_pun( (uchar *)bank->data - bank->data->banks_data_offset );
  fd_bank_cost_tracker_t * cost_tracker_pool = fd_banks_get_cost_tracker_pool( banks_data );
  FD_TEST( bank->data->cost_tracker_pool_idx!=fd_bank_cost_tracker_pool_idx_null( cost_tracker_pool ) );
  uchar * cost_tracker_mem = fd_bank_cost_tracker_pool_ele( cost_tracker_pool, bank->data->cost_tracker_pool_idx )->data;
  return fd_type_pun( cost_tracker_mem );
}

fd_cost_tracker_t const *
fd_bank_cost_tracker_query( fd_bank_t * bank ) {
  fd_banks_t * banks_data = fd_type_pun( (uchar *)bank->data - bank->data->banks_data_offset );
  fd_bank_cost_tracker_t * cost_tracker_pool = fd_banks_get_cost_tracker_pool( banks_data );
  FD_TEST( bank->data->cost_tracker_pool_idx!=fd_bank_cost_tracker_pool_idx_null( cost_tracker_pool ) );
  uchar * cost_tracker_mem = fd_bank_cost_tracker_pool_ele( cost_tracker_pool, bank->data->cost_tracker_pool_idx )->data;
  return fd_type_pun_const( cost_tracker_mem );
}

FD_FN_PURE fd_bank_t *
fd_banks_root( fd_bank_t *  bank_l,
               fd_banks_t * banks ) {
  fd_bank_data_t * bank_data = fd_banks_pool_ele( fd_banks_get_bank_pool( banks ), banks->root_idx );
  if( FD_UNLIKELY( !bank_data ) ) {
    return NULL;
  }
  bank_l->data  = bank_data;
  return bank_l;
}

fd_bank_t *
fd_banks_bank_query( fd_bank_t *  bank_l,
                     fd_banks_t * banks,
                     ulong        bank_idx ) {
  fd_bank_data_t * bank_data = fd_banks_pool_ele( fd_banks_get_bank_pool( banks ), bank_idx );
  if( FD_UNLIKELY( !(bank_data->flags&FD_BANK_FLAGS_INIT) ) ) return NULL;
  bank_l->data  = bank_data;
  return bank_l;
}

fd_bank_t *
fd_banks_get_parent( fd_bank_t *  bank_l,
                     fd_banks_t * banks,
                     fd_bank_t *  bank ) {
  if( FD_UNLIKELY( bank->data->parent_idx==ULONG_MAX ) ) return NULL;
  bank_l->data  = fd_banks_pool_ele( fd_banks_get_bank_pool( banks ), bank->data->parent_idx );
  return bank_l;
}

int
fd_banks_is_full( fd_banks_t * banks ) {
  return fd_banks_pool_free( fd_banks_get_bank_pool( banks ) )==0UL ||
         fd_bank_cost_tracker_pool_free( fd_banks_get_cost_tracker_pool( banks ) )==0UL;
}

ulong
fd_banks_pool_used_cnt( fd_banks_t * banks ) {
  return fd_banks_pool_used( fd_banks_get_bank_pool( banks ) );
}

ulong
fd_banks_pool_max_cnt( fd_banks_t * banks ) {
  return fd_banks_pool_max( fd_banks_get_bank_pool( banks ) );
}

void
fd_banks_stake_delegations_evict_bank_fork( fd_banks_t * banks,
                                            fd_bank_t *  bank ) {
  if( bank->data->stake_delegations_fork_id!=USHORT_MAX ) {
    fd_stake_delegations_t * sd = fd_banks_get_stake_delegations( banks );
    fd_stake_delegations_evict_fork( sd, bank->data->stake_delegations_fork_id );
    bank->data->stake_delegations_fork_id = USHORT_MAX;
  }
}

ulong
fd_banks_footprint( ulong max_total_banks,
                    ulong max_fork_width,
                    ulong max_stake_accounts,
                    ulong max_vote_accounts ) {

  /* max_fork_width is used in the macro below. */

  ulong epoch_leaders_footprint = FD_EPOCH_LEADERS_FOOTPRINT( max_vote_accounts, FD_RUNTIME_SLOTS_PER_EPOCH );
  ulong expected_stake_accounts = fd_ulong_min( max_stake_accounts, FD_RUNTIME_EXPECTED_STAKE_ACCOUNTS );
  ulong expected_vote_accounts  = fd_ulong_min( max_vote_accounts, FD_RUNTIME_EXPECTED_VOTE_ACCOUNTS );

  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, fd_banks_align(),                  sizeof(fd_banks_t) );
  l = FD_LAYOUT_APPEND( l, fd_stake_delegations_align(),      fd_stake_delegations_footprint( max_stake_accounts, expected_stake_accounts, max_total_banks ) );
  l = FD_LAYOUT_APPEND( l, FD_EPOCH_LEADERS_ALIGN,            2UL * epoch_leaders_footprint );
  l = FD_LAYOUT_APPEND( l, fd_banks_pool_align(),             fd_banks_pool_footprint( max_total_banks ) );
  l = FD_LAYOUT_APPEND( l, fd_banks_dead_align(),             fd_banks_dead_footprint() );
  l = FD_LAYOUT_APPEND( l, fd_bank_cost_tracker_pool_align(), fd_bank_cost_tracker_pool_footprint( max_fork_width ) );
  l = FD_LAYOUT_APPEND( l, fd_stake_rewards_align(),          fd_stake_rewards_footprint( max_stake_accounts, expected_stake_accounts, max_fork_width ) );
  l = FD_LAYOUT_APPEND( l, fd_vote_stakes_align(),            fd_vote_stakes_footprint( max_vote_accounts, fd_ulong_min( max_vote_accounts, expected_vote_accounts ), max_fork_width ) );
  return FD_LAYOUT_FINI( l, fd_banks_align() );
}

void *
fd_banks_new( void * shmem,
              ulong  max_total_banks,
              ulong  max_fork_width,
              ulong  max_stake_accounts,
              ulong  max_vote_accounts,
              int    larger_max_cost_per_block,
              ulong  seed ) {
  if( FD_UNLIKELY( !shmem ) ) {
    FD_LOG_WARNING(( "NULL shmem" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shmem, fd_banks_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned shmem" ));
    return NULL;
  }

  if( FD_UNLIKELY( max_total_banks>FD_BANKS_MAX_BANKS ) ) {
    FD_LOG_WARNING(( "max_total_banks is too large" ));
    return NULL;
  }
  if( FD_UNLIKELY( max_fork_width>FD_BANKS_MAX_BANKS ) ) {
    FD_LOG_WARNING(( "max_fork_width is too large" ));
    return NULL;
  }

  ulong epoch_leaders_footprint = FD_EPOCH_LEADERS_FOOTPRINT( max_vote_accounts, FD_RUNTIME_SLOTS_PER_EPOCH );
  ulong expected_stake_accounts = fd_ulong_min( max_stake_accounts, FD_RUNTIME_EXPECTED_STAKE_ACCOUNTS );
  ulong expected_vote_accounts  = fd_ulong_min( max_vote_accounts, FD_RUNTIME_EXPECTED_VOTE_ACCOUNTS );

  FD_SCRATCH_ALLOC_INIT( l, shmem );
  fd_banks_t * banks_data             = FD_SCRATCH_ALLOC_APPEND( l, fd_banks_align(),                  sizeof(fd_banks_t) );
  void *            stake_delegations_mem  = FD_SCRATCH_ALLOC_APPEND( l, fd_stake_delegations_align(),      fd_stake_delegations_footprint( max_stake_accounts, expected_stake_accounts, max_total_banks ) );
  void *            epoch_leaders_mem      = FD_SCRATCH_ALLOC_APPEND( l, FD_EPOCH_LEADERS_ALIGN,            2UL * epoch_leaders_footprint );
  void *            pool_mem               = FD_SCRATCH_ALLOC_APPEND( l, fd_banks_pool_align(),             fd_banks_pool_footprint( max_total_banks ) );
  void *            dead_banks_deque_mem   = FD_SCRATCH_ALLOC_APPEND( l, fd_banks_dead_align(),             fd_banks_dead_footprint() );
  void *            cost_tracker_pool_mem  = FD_SCRATCH_ALLOC_APPEND( l, fd_bank_cost_tracker_pool_align(), fd_bank_cost_tracker_pool_footprint( max_fork_width ) );
  void *            stake_rewards_pool_mem = FD_SCRATCH_ALLOC_APPEND( l, fd_stake_rewards_align(),          fd_stake_rewards_footprint( max_stake_accounts, expected_stake_accounts, max_fork_width ) );
  void *            vote_stakes_mem        = FD_SCRATCH_ALLOC_APPEND( l, fd_vote_stakes_align(),            fd_vote_stakes_footprint( max_vote_accounts, expected_vote_accounts, max_fork_width ) );

  if( FD_UNLIKELY( FD_SCRATCH_ALLOC_FINI( l, fd_banks_align() ) != (ulong)banks_data + fd_banks_footprint( max_total_banks, max_fork_width, max_stake_accounts, max_vote_accounts ) ) ) {
    FD_LOG_WARNING(( "fd_banks_new: bad layout" ));
    return NULL;
  }

  void * pool = fd_banks_pool_new( pool_mem, max_total_banks );
  if( FD_UNLIKELY( !pool ) ) {
    FD_LOG_WARNING(( "Failed to create bank pool" ));
    return NULL;
  }

  fd_bank_data_t * bank_pool = fd_banks_pool_join( pool );
  if( FD_UNLIKELY( !bank_pool ) ) {
    FD_LOG_WARNING(( "Failed to join bank pool" ));
    return NULL;
  }

  /* Mark all of the banks as not initialized. */
  for( ulong i=0UL; i<max_total_banks; i++ ) {
    fd_bank_data_t * bank = fd_banks_pool_ele( bank_pool, i );
    if( FD_UNLIKELY( !bank ) ) {
      FD_LOG_WARNING(( "Failed to get bank" ));
      return NULL;
    }
    bank->flags = 0UL;
  }

  fd_bank_idx_seq_t * banks_dead_deque = fd_banks_dead_join( fd_banks_dead_new( dead_banks_deque_mem ) );
  if( FD_UNLIKELY( !banks_dead_deque ) ) {
    FD_LOG_WARNING(( "Failed to create banks dead deque" ));
    return NULL;
  }
  banks_data->dead_banks_deque_offset = (ulong)banks_dead_deque - (ulong)banks_data;

  banks_data->epoch_leaders_offset    = (ulong)epoch_leaders_mem - (ulong)banks_data;
  banks_data->epoch_leaders_footprint = epoch_leaders_footprint;
  banks_data->pool_offset             = (ulong)bank_pool - (ulong)banks_data;

  /* Create the pools for the non-inlined fields.  Also new() and join()
     each of the elements in the pool as well as set up the lock for
     each of the pools. */

  fd_stake_delegations_t * stake_delegations = fd_stake_delegations_join( fd_stake_delegations_new( stake_delegations_mem, seed, max_stake_accounts, expected_stake_accounts, max_total_banks ) );
  if( FD_UNLIKELY( !stake_delegations ) ) {
    FD_LOG_WARNING(( "Unable to create stake delegations root" ));
    return NULL;
  }
  banks_data->stake_delegations_offset = (ulong)stake_delegations - (ulong)banks_data;

  fd_bank_cost_tracker_t * cost_tracker_pool = fd_bank_cost_tracker_pool_join( fd_bank_cost_tracker_pool_new( cost_tracker_pool_mem, max_fork_width ) );
  if( FD_UNLIKELY( !cost_tracker_pool ) ) {
    FD_LOG_WARNING(( "Failed to create cost tracker pool" ));
    return NULL;
  }
  banks_data->cost_tracker_pool_offset = (ulong)cost_tracker_pool - (ulong)banks_data;

  for( ulong i=0UL; i<max_fork_width; i++ ) {
    fd_bank_cost_tracker_t * cost_tracker = fd_bank_cost_tracker_pool_ele( cost_tracker_pool, i );
    if( FD_UNLIKELY( !fd_cost_tracker_join( fd_cost_tracker_new( cost_tracker->data, larger_max_cost_per_block, seed ) ) ) ) {
      FD_LOG_WARNING(( "Failed to create cost tracker" ));
      return NULL;
    }
  }

  fd_stake_rewards_t * stake_rewards = fd_stake_rewards_join( fd_stake_rewards_new( stake_rewards_pool_mem, max_stake_accounts, fd_ulong_min( max_stake_accounts, FD_RUNTIME_EXPECTED_STAKE_ACCOUNTS ), max_fork_width, seed ) );
  if( FD_UNLIKELY( !stake_rewards ) ) {
    FD_LOG_WARNING(( "Failed to create stake rewards" ));
    return NULL;
  }
  banks_data->stake_rewards_offset = (ulong)stake_rewards - (ulong)banks_data;


  fd_vote_stakes_t * vote_stakes = fd_vote_stakes_join( fd_vote_stakes_new( vote_stakes_mem, max_vote_accounts, fd_ulong_min( max_vote_accounts, FD_RUNTIME_EXPECTED_VOTE_ACCOUNTS ), max_fork_width, seed ) );
  if( FD_UNLIKELY( !vote_stakes ) ) {
    FD_LOG_WARNING(( "Failed to create vote stakes" ));
    return NULL;
  }
  banks_data->vote_stakes_pool_offset = (ulong)vote_stakes - (ulong)banks_data;

  /* For each bank, set the offset back to banks_data and initialize
     per-bank state. */

  fd_bank_cost_tracker_t * cost_tracker_pool_init = fd_banks_get_cost_tracker_pool( banks_data );

  for( ulong i=0UL; i<max_total_banks; i++ ) {

    fd_bank_data_t * bank = fd_banks_pool_ele( bank_pool, i );

    fd_rwlock_new( &bank->lthash_lock );

    bank->banks_data_offset = (ulong)bank - (ulong)banks_data;

    if( i==0UL ) {
      FD_TEST( fd_top_votes_join( fd_top_votes_new( bank->top_votes_t_1_mem, FD_RUNTIME_MAX_VOTE_ACCOUNTS_VAT, seed ) ) );
      FD_TEST( fd_top_votes_join( fd_top_votes_new( bank->top_votes_t_2_mem, FD_RUNTIME_MAX_VOTE_ACCOUNTS_VAT, seed ) ) );
    }

    bank->cost_tracker_pool_idx = fd_bank_cost_tracker_pool_idx_null( cost_tracker_pool_init );
  }

  banks_data->max_total_banks    = max_total_banks;
  banks_data->max_fork_width     = max_fork_width;
  banks_data->max_stake_accounts = max_stake_accounts;
  banks_data->max_vote_accounts  = max_vote_accounts;
  banks_data->root_idx           = ULONG_MAX;
  banks_data->bank_seq           = 0UL;

  FD_COMPILER_MFENCE();
  FD_VOLATILE( banks_data->magic ) = FD_BANKS_MAGIC;
  FD_COMPILER_MFENCE();

  return shmem;
}

fd_banks_t *
fd_banks_join( void * banks_data_mem ) {
  fd_banks_t * banks_data  = (fd_banks_t *)banks_data_mem;

  if( FD_UNLIKELY( !banks_data ) ) {
    FD_LOG_WARNING(( "NULL banks data" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)banks_data, fd_banks_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned banks" ));
    return NULL;
  }

  if( FD_UNLIKELY( banks_data->magic!=FD_BANKS_MAGIC ) ) {
    FD_LOG_WARNING(( "Invalid banks magic" ));
    return NULL;
  }

  ulong expected_stake_accounts = fd_ulong_min( banks_data->max_stake_accounts, FD_RUNTIME_EXPECTED_STAKE_ACCOUNTS );
  ulong expected_vote_accounts  = fd_ulong_min( banks_data->max_vote_accounts, FD_RUNTIME_EXPECTED_VOTE_ACCOUNTS );

  FD_SCRATCH_ALLOC_INIT( l, banks_data );
  banks_data                   = FD_SCRATCH_ALLOC_APPEND( l, fd_banks_align(),                  sizeof(fd_banks_t) );
  void * stake_delegations_mem = FD_SCRATCH_ALLOC_APPEND( l, fd_stake_delegations_align(),      fd_stake_delegations_footprint( banks_data->max_stake_accounts, expected_stake_accounts, banks_data->max_total_banks ) );
  void * epoch_leaders_mem     = FD_SCRATCH_ALLOC_APPEND( l, FD_EPOCH_LEADERS_ALIGN,            2UL * banks_data->epoch_leaders_footprint );
  void * pool_mem              = FD_SCRATCH_ALLOC_APPEND( l, fd_banks_pool_align(),             fd_banks_pool_footprint( banks_data->max_total_banks ) );
  void * dead_banks_deque_mem  = FD_SCRATCH_ALLOC_APPEND( l, fd_banks_dead_align(),             fd_banks_dead_footprint() );
  void * cost_tracker_pool_mem = FD_SCRATCH_ALLOC_APPEND( l, fd_bank_cost_tracker_pool_align(), fd_bank_cost_tracker_pool_footprint( banks_data->max_fork_width ) );
  void * stake_rewards_mem     = FD_SCRATCH_ALLOC_APPEND( l, fd_stake_rewards_align(),          fd_stake_rewards_footprint( banks_data->max_stake_accounts, expected_stake_accounts, banks_data->max_fork_width ) );
  void * vote_stakes_mem       = FD_SCRATCH_ALLOC_APPEND( l, fd_vote_stakes_align(),            fd_vote_stakes_footprint( banks_data->max_vote_accounts, expected_vote_accounts, banks_data->max_fork_width ) );

  FD_SCRATCH_ALLOC_FINI( l, fd_banks_align() );

  fd_bank_data_t * banks_pool = fd_banks_get_bank_pool( banks_data );
  if( FD_UNLIKELY( !banks_pool ) ) {
    FD_LOG_WARNING(( "Failed to join bank pool" ));
    return NULL;
  }

  if( FD_UNLIKELY( banks_pool!=fd_banks_pool_join( pool_mem ) ) ) {
    FD_LOG_WARNING(( "Failed to join bank pool" ));
    return NULL;
  }

  fd_bank_idx_seq_t * banks_dead_deque = fd_banks_dead_join( dead_banks_deque_mem );
  if( FD_UNLIKELY( !banks_dead_deque ) ) {
    FD_LOG_WARNING(( "Failed to join banks dead deque" ));
    return NULL;
  }

  if( FD_UNLIKELY( epoch_leaders_mem!=fd_banks_get_epoch_leaders( banks_data ) ) ) {
    FD_LOG_WARNING(( "Failed to join epoch leaders mem" ));
    return NULL;
  }

  if( FD_UNLIKELY( stake_delegations_mem!=fd_banks_get_stake_delegations( banks_data ) ) ) {
    FD_LOG_WARNING(( "Failed to join stake delegations root mem" ));
    return NULL;
  }

  fd_bank_cost_tracker_t * cost_tracker_pool = fd_banks_get_cost_tracker_pool( banks_data );
  if( FD_UNLIKELY( !cost_tracker_pool ) ) {
    FD_LOG_WARNING(( "Failed to join cost tracker pool" ));
    return NULL;
  }

  if( FD_UNLIKELY( cost_tracker_pool!=fd_bank_cost_tracker_pool_join( cost_tracker_pool_mem ) ) ) {
    FD_LOG_WARNING(( "Failed to join cost tracker pool" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_stake_rewards_join( stake_rewards_mem ) ) ) {
    FD_LOG_WARNING(( "Failed to join stake rewards" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_vote_stakes_join( vote_stakes_mem ) ) ) {
    FD_LOG_WARNING(( "Failed to join vote stakes" ));
    return NULL;
  }

  return banks_data;
}

fd_bank_t *
fd_banks_init_bank( fd_bank_t *  bank_l,
                    fd_banks_t * banks ) {

  fd_bank_data_t * bank_pool = fd_banks_get_bank_pool( banks );
  FD_CRIT( fd_banks_pool_free( bank_pool )!=0UL, "invariant violation: no free bank pool elements" );

  fd_bank_data_t * bank = fd_banks_pool_ele_acquire( bank_pool );
  bank->bank_seq = FD_ATOMIC_FETCH_AND_ADD( &banks->bank_seq, 1UL );

  ulong null_idx    = fd_banks_pool_idx_null( bank_pool );
  bank->idx         = fd_banks_pool_idx( bank_pool, bank );
  bank->next        = null_idx;
  bank->parent_idx  = null_idx;
  bank->child_idx   = null_idx;
  bank->sibling_idx = null_idx;

  fd_memset( &bank->f, 0, sizeof(bank->f) );
  bank->stake_rewards_fork_id             = UCHAR_MAX;
  bank->stake_delegations_fork_id         = USHORT_MAX;
  bank->epoch_leaders_idx                 = ULONG_MAX;
  bank->cost_tracker_pool_idx             = fd_bank_cost_tracker_pool_idx_null( fd_banks_get_cost_tracker_pool( banks ) );
  bank->first_fec_set_received_nanos      = fd_log_wallclock();
  bank->preparation_begin_nanos           = 0L;
  bank->first_transaction_scheduled_nanos = 0L;
  bank->last_transaction_finished_nanos   = 0L;

  fd_vote_stakes_t * vote_stakes = fd_banks_get_vote_stakes( banks );
  bank->vote_stakes_fork_id      = fd_vote_stakes_get_root_idx( vote_stakes );

  fd_stake_delegations_t * stake_delegations = fd_banks_get_stake_delegations( banks );
  bank->stake_delegations_fork_id            = fd_stake_delegations_new_fork( stake_delegations );

  bank->flags |= FD_BANK_FLAGS_INIT | FD_BANK_FLAGS_REPLAYABLE | FD_BANK_FLAGS_FROZEN;
  bank->refcnt = 0UL;

  banks->root_idx = bank->idx;

  bank_l->data  = bank;
  return bank_l;
}

fd_bank_t *
fd_banks_clone_from_parent( fd_bank_t *  bank_l,
                            fd_banks_t * banks,
                            ulong        child_bank_idx ) {

  fd_bank_data_t * bank_pool  = fd_banks_get_bank_pool( banks );
  fd_bank_data_t * child_bank = fd_banks_pool_ele( bank_pool, child_bank_idx );
  FD_CRIT( child_bank->flags&FD_BANK_FLAGS_INIT, "invariant violation: bank is not initialized" );

  fd_bank_data_t * parent_bank = fd_banks_pool_ele( bank_pool, child_bank->parent_idx );
  FD_CRIT( parent_bank->flags&FD_BANK_FLAGS_FROZEN, "invariant violation: parent bank is not frozen" );

  fd_bank_cost_tracker_t * cost_tracker_pool = fd_banks_get_cost_tracker_pool( banks );
  FD_CRIT( fd_bank_cost_tracker_pool_free( cost_tracker_pool )!=0UL, "invariant violation: no free cost tracker pool elements" );
  child_bank->cost_tracker_pool_idx = fd_bank_cost_tracker_pool_idx_acquire( cost_tracker_pool );

  fd_memcpy( child_bank->top_votes_t_1_mem, parent_bank->top_votes_t_1_mem, FD_TOP_VOTES_MAX_FOOTPRINT );
  fd_memcpy( child_bank->top_votes_t_2_mem, parent_bank->top_votes_t_2_mem, FD_TOP_VOTES_MAX_FOOTPRINT );

  child_bank->f                         = parent_bank->f;
  child_bank->epoch_leaders_idx         = parent_bank->epoch_leaders_idx;
  child_bank->vote_stakes_fork_id       = parent_bank->vote_stakes_fork_id;
  child_bank->stake_rewards_fork_id     = parent_bank->stake_rewards_fork_id;
  child_bank->stake_delegations_fork_id = fd_stake_delegations_new_fork( fd_banks_get_stake_delegations( banks ) );
  child_bank->f.block_height             = parent_bank->f.block_height + 1UL;
  child_bank->f.tick_height              = parent_bank->f.max_tick_height;
  child_bank->f.parent_slot              = parent_bank->f.slot;
  child_bank->f.parent_signature_cnt     = parent_bank->f.signature_count;
  child_bank->f.prev_bank_hash           = parent_bank->f.bank_hash;
  child_bank->f.execution_fees           = 0UL;
  child_bank->f.priority_fees            = 0UL;
  child_bank->f.tips                     = 0UL;
  child_bank->f.signature_count          = 0UL;
  child_bank->f.total_compute_units_used = 0UL;
  child_bank->f.shred_cnt                = 0UL;
  child_bank->f.txn_count                = 0UL;
  child_bank->f.nonvote_txn_count        = 0UL;
  child_bank->f.failed_txn_count         = 0UL;
  child_bank->f.nonvote_failed_txn_count = 0UL;
  child_bank->f.identity_vote_idx        = ULONG_MAX;

  child_bank->flags |= FD_BANK_FLAGS_REPLAYABLE;

  bank_l->data  = child_bank;
  return bank_l;
}

/* fd_bank_stake_delegation_apply_deltas applies all of the stake
   delegations for the entire direct ancestry from the bank to the
   root into a full fd_stake_delegations_t object. */

static inline void
fd_bank_stake_delegation_apply_deltas( fd_banks_t *             banks,
                                       fd_bank_t *              bank,
                                       fd_stake_delegations_t * stake_delegations ) {

  /* Naively what we want to do is iterate from the old root to the new
     root and apply the delta to the full state iteratively. */

  /* First, gather all of the pool indicies that we want to apply deltas
     for in reverse order starting from the new root. We want to exclude
     the old root since its delta has been applied previously. */
  ushort pool_indices[ banks->max_total_banks ];
  ulong  pool_indices_len = 0UL;

  fd_bank_data_t * bank_pool = fd_banks_get_bank_pool( banks );

  fd_bank_data_t * curr_bank = fd_banks_pool_ele( bank_pool, bank->data->idx );
  while( !!curr_bank ) {
    if( curr_bank->stake_delegations_fork_id!=USHORT_MAX ) {
      pool_indices[pool_indices_len++] = curr_bank->stake_delegations_fork_id;
    }
    curr_bank = fd_banks_pool_ele( bank_pool, curr_bank->parent_idx );
  }

  /* We have populated all of the indicies that we need to apply deltas
     from in reverse order. */

  for( ulong i=pool_indices_len; i>0; i-- ) {
    ushort idx = pool_indices[i-1UL];
    fd_stake_delegations_apply_fork_delta( stake_delegations, idx );
  }
}

static inline void
fd_bank_stake_delegation_mark_deltas( fd_banks_t *             banks,
                                      fd_bank_t *              bank,
                                      fd_stake_delegations_t * stake_delegations ) {

  ushort pool_indices[ banks->max_total_banks ];
  ulong  pool_indices_len = 0UL;

  fd_bank_data_t * bank_pool = fd_banks_get_bank_pool( banks );

  fd_bank_data_t * curr_bank = fd_banks_pool_ele( bank_pool, bank->data->idx );
  while( !!curr_bank ) {
    if( curr_bank->stake_delegations_fork_id!=USHORT_MAX ) {
      pool_indices[pool_indices_len++] = curr_bank->stake_delegations_fork_id;
    }
    curr_bank = fd_banks_pool_ele( bank_pool, curr_bank->parent_idx );
  }

  for( ulong i=pool_indices_len; i>0; i-- ) {
    ushort idx = pool_indices[i-1UL];
    fd_stake_delegations_mark_delta( stake_delegations, idx );
  }
}

static inline void
fd_bank_stake_delegation_unmark_deltas( fd_banks_t *             banks,
                                        fd_bank_t *              bank,
                                        fd_stake_delegations_t * stake_delegations ) {

  ushort pool_indices[ banks->max_total_banks ];
  ulong  pool_indices_len = 0UL;

  fd_bank_data_t * bank_pool = fd_banks_get_bank_pool( banks );

  fd_bank_data_t * curr_bank = fd_banks_pool_ele( bank_pool, bank->data->idx );
  while( !!curr_bank ) {
    if( curr_bank->stake_delegations_fork_id!=USHORT_MAX ) {
      pool_indices[pool_indices_len++] = curr_bank->stake_delegations_fork_id;
    }
    curr_bank = fd_banks_pool_ele( bank_pool, curr_bank->parent_idx );
  }

  for( ulong i=pool_indices_len; i>0; i-- ) {
    ushort idx = pool_indices[i-1UL];
    fd_stake_delegations_unmark_delta( stake_delegations, idx );
  }
}


fd_stake_delegations_t *
fd_bank_stake_delegations_frontier_query( fd_banks_t * banks,
                                          fd_bank_t *  bank ) {
  fd_stake_delegations_t * stake_delegations = fd_banks_get_stake_delegations( banks );
  fd_bank_stake_delegation_mark_deltas( banks, bank, stake_delegations );

  return stake_delegations;
}

void
fd_bank_stake_delegations_end_frontier_query( fd_banks_t * banks,
                                              fd_bank_t *  bank ) {
  fd_stake_delegations_t * stake_delegations = fd_banks_get_stake_delegations( banks );
  fd_bank_stake_delegation_unmark_deltas( banks, bank, stake_delegations );
}


fd_stake_delegations_t *
fd_banks_stake_delegations_root_query( fd_banks_t * banks ) {
  return fd_banks_get_stake_delegations( banks );
}

void
fd_banks_advance_root( fd_banks_t * banks,
                       ulong        root_bank_idx ) {

  fd_bank_data_t * bank_pool = fd_banks_get_bank_pool( banks );

  ulong null_idx = fd_banks_pool_idx_null( bank_pool );

  /* We want to replace the old root with the new root. This means we
     have to remove banks that aren't descendants of the new root. */

  fd_bank_t old_root[1];
  if( FD_UNLIKELY( !fd_banks_root( old_root, banks ) ) ) {
    FD_LOG_CRIT(( "invariant violation: old root is NULL" ));
  }

  if( FD_UNLIKELY( old_root->data->refcnt!=0UL ) ) {
    FD_LOG_CRIT(( "refcnt for old root bank at index %lu is nonzero: %lu", old_root->data->idx, old_root->data->refcnt ));
  }

  fd_bank_t new_root[1];
  if( FD_UNLIKELY( !fd_banks_bank_query( new_root, banks, root_bank_idx ) ) ) {
    FD_LOG_CRIT(( "invariant violation: new root is NULL" ));
  }

  if( FD_UNLIKELY( new_root->data->parent_idx!=old_root->data->idx ) ) {
    FD_LOG_CRIT(( "invariant violation: trying to advance root bank by more than one" ));
  }

  fd_stake_delegations_t * stake_delegations = fd_banks_get_stake_delegations( banks );
  fd_bank_stake_delegation_apply_deltas( banks, new_root, stake_delegations );

  fd_stake_delegations_evict_fork( stake_delegations, new_root->data->stake_delegations_fork_id );
  new_root->data->stake_delegations_fork_id = USHORT_MAX;

  /* Now that the deltas have been applied, we can remove all nodes
     that are not direct descendants of the new root. */
  fd_bank_data_t * head = fd_banks_pool_ele( bank_pool, old_root->data->idx );
  head->next            = fd_banks_pool_idx_null( bank_pool );
  fd_bank_data_t * tail = head;

  while( head ) {
    fd_bank_data_t * child = fd_banks_pool_ele( bank_pool, head->child_idx );

    while( FD_LIKELY( child ) ) {

      if( FD_LIKELY( child!=new_root->data ) ) {
        if( FD_UNLIKELY( child->refcnt!=0UL ) ) {
          FD_LOG_CRIT(( "refcnt for child bank at index %lu is %lu", child->idx, child->refcnt ));
        }

        /* Update tail pointers */
        tail->next = child->idx;
        tail       = fd_banks_pool_ele( bank_pool, tail->next );
        tail->next = fd_banks_pool_idx_null( bank_pool );
      }

      child = fd_banks_pool_ele( bank_pool, child->sibling_idx );
    }

    fd_bank_data_t * next = fd_banks_pool_ele( bank_pool, head->next );

    /* It is possible for a bank that never finished replaying to be
       pruned away.  If the bank was never frozen, then it's possible
       that the bank still owns a cost tracker pool element.  If this
       is the case, we need to release the pool element. */
    fd_bank_cost_tracker_t * cost_tracker_pool = fd_banks_get_cost_tracker_pool( banks );
    if( head->cost_tracker_pool_idx!=fd_bank_cost_tracker_pool_idx_null( cost_tracker_pool ) ) {
      FD_TEST( !(head->flags&FD_BANK_FLAGS_FROZEN) && head->flags&FD_BANK_FLAGS_REPLAYABLE );
      FD_LOG_DEBUG(( "releasing cost tracker pool element for bank at index %lu", head->idx ));
      fd_bank_cost_tracker_pool_idx_release( cost_tracker_pool, head->cost_tracker_pool_idx );
      head->cost_tracker_pool_idx = fd_bank_cost_tracker_pool_idx_null( cost_tracker_pool );
    }

    head->stake_rewards_fork_id = UCHAR_MAX;
    head->vote_stakes_fork_id = USHORT_MAX;

    if( head->stake_delegations_fork_id!=USHORT_MAX ) {
      fd_stake_delegations_evict_fork( stake_delegations, head->stake_delegations_fork_id );
      head->stake_delegations_fork_id = USHORT_MAX;
    }

    head->flags = 0UL;
    fd_banks_pool_ele_release( bank_pool, head );
    head = next;
  }

  /* new_root is detached from old_root and becomes the only root.
     Clear sibling_idx too so traversals cannot follow a stale link to
     a bank index that was just pruned and later reused. */
  new_root->data->parent_idx  = null_idx;
  new_root->data->sibling_idx = null_idx;
  banks->root_idx             = new_root->data->idx;

  fd_vote_stakes_t * vote_stakes = fd_banks_get_vote_stakes( banks );
  fd_vote_stakes_advance_root( vote_stakes, new_root->data->vote_stakes_fork_id );
}

/* Is the fork tree starting at the given bank entirely eligible for
   pruning?  Returns 1 for yes, 0 for no.

   See comment in fd_replay_tile.c for more details on safe pruning. */
static int
fd_banks_subtree_can_be_pruned( fd_bank_data_t * bank_pool,
                                fd_bank_data_t * bank ) {

  if( bank->refcnt!=0UL ) return 0;

  /* Recursively check all children. */
  ulong child_idx = bank->child_idx;
  while( child_idx!=fd_banks_pool_idx_null( bank_pool ) ) {
    fd_bank_data_t * child = fd_banks_pool_ele( bank_pool, child_idx );
    if( !fd_banks_subtree_can_be_pruned( bank_pool, child ) ) return 0;
    child_idx = child->sibling_idx;
  }

  return 1;
}

int
fd_banks_advance_root_prepare( fd_banks_t * banks,
                               ulong        target_bank_idx,
                               ulong *      advanceable_bank_idx_out ) {
  /* TODO: An optimization here is to do a single traversal of the tree
     that would mark minority forks as dead while accumulating
     refcnts to determine which bank is the highest advanceable. */

  fd_bank_data_t * bank_pool = fd_banks_get_bank_pool( banks );

  fd_bank_t root[1];
  if( FD_UNLIKELY( !fd_banks_root( root, banks ) ) ) {
    FD_LOG_WARNING(( "failed to get root bank" ));
    return 0;
  }

  /* Early exit if target is the same as the old root. */
  if( FD_UNLIKELY( root->data->idx==target_bank_idx ) ) {
    FD_LOG_WARNING(( "target bank_idx %lu is the same as the old root's bank index %lu", target_bank_idx, root->data->idx ));
    return 0;
  }

  /* Early exit if the root bank still has a reference to it, we can't
     advance from it unti it's released. */
  if( FD_UNLIKELY( root->data->refcnt!=0UL ) ) {
    return 0;
  }

  fd_bank_data_t * target_bank = fd_banks_pool_ele( bank_pool, target_bank_idx );
  if( FD_UNLIKELY( !target_bank ) ) {
    FD_LOG_CRIT(( "failed to get bank for valid pool idx %lu", target_bank_idx ));
  }

  /* Mark every node from the target bank up through its parents to the
     root as being rooted.  We also need to figure out the oldest,
     non-rooted ancestor of the target bank since we only want to
     advance our root bank by one. */
  fd_bank_data_t * curr = target_bank;
  fd_bank_data_t * prev = NULL;
  while( curr && curr!=root->data ) {
    curr->flags |= FD_BANK_FLAGS_ROOTED;
    prev         = curr;
    curr         = fd_banks_pool_ele( bank_pool, curr->parent_idx );
  }

  /* If we didn't reach the old root or there is no parent, target is
     not a descendant. */
  if( FD_UNLIKELY( !curr || prev->parent_idx!=root->data->idx ) ) {
    FD_LOG_CRIT(( "invariant violation: target bank_idx %lu is not a direct descendant of root bank_idx %lu %lu %lu", target_bank_idx, root->data->idx, prev->idx, prev->parent_idx ));
  }

  curr = root->data;
  while( curr && (curr->flags&FD_BANK_FLAGS_ROOTED) && curr!=target_bank ) { /* curr!=target_bank to avoid abandoning good forks. */
    fd_bank_data_t * rooted_child = NULL;
    ulong            child_idx    = curr->child_idx;
    while( child_idx!=fd_banks_pool_idx_null( bank_pool ) ) {
      fd_bank_data_t * child_bank = fd_banks_pool_ele( bank_pool, child_idx );
      if( child_bank->flags&FD_BANK_FLAGS_ROOTED ) rooted_child = child_bank;
      child_idx = child_bank->sibling_idx;
    }
    curr = rooted_child;
  }

  /* We will at most advance our root bank by one.  This means we can
     advance our root bank by one if each of the siblings of the
     potential new root are eligible for pruning.  Each of the sibling
     subtrees can be pruned if the subtrees have no active references on
     their bank. */
  ulong advance_candidate_idx = prev->idx;
  ulong child_idx = root->data->child_idx;
  while( child_idx!=fd_banks_pool_idx_null( bank_pool ) ) {
    fd_bank_data_t * child_bank = fd_banks_pool_ele( bank_pool, child_idx );
    if( child_idx!=advance_candidate_idx ) {
      if( !fd_banks_subtree_can_be_pruned( bank_pool, child_bank ) ) {
        return 0;
      }
    }
    child_idx = child_bank->sibling_idx;
  }

  *advanceable_bank_idx_out = advance_candidate_idx;
  return 1;
}

fd_bank_t *
fd_banks_new_bank( fd_bank_t *  bank_l,
                   fd_banks_t * banks,
                   ulong        parent_bank_idx,
                   long         now ) {

  fd_bank_data_t * bank_pool = fd_banks_get_bank_pool( banks );
  FD_CRIT( fd_banks_pool_free( bank_pool )!=0UL, "invariant violation: no free bank indices available" );

  ulong            child_bank_idx = fd_banks_pool_idx_acquire( bank_pool );
  fd_bank_data_t * child_bank     = fd_banks_pool_ele( bank_pool, child_bank_idx );
  FD_CRIT( !(child_bank->flags&FD_BANK_FLAGS_INIT), "invariant violation: bank for bank index is already initialized" );

  ulong null_idx = fd_banks_pool_idx_null( bank_pool );

  child_bank->bank_seq    = FD_ATOMIC_FETCH_AND_ADD( &banks->bank_seq, 1UL );
  child_bank->idx         = child_bank_idx;
  child_bank->parent_idx  = null_idx;
  child_bank->child_idx   = null_idx;
  child_bank->sibling_idx = null_idx;
  child_bank->next        = null_idx;
  child_bank->flags       = FD_BANK_FLAGS_INIT;
  child_bank->refcnt      = 0UL;

  child_bank->stake_delegations_fork_id = USHORT_MAX;

  /* Then make sure that the parent bank is valid and frozen. */

  fd_bank_data_t * parent_bank = fd_banks_pool_ele( bank_pool, parent_bank_idx );
  FD_CRIT( parent_bank->flags&FD_BANK_FLAGS_INIT, "invariant violation: parent bank for bank index is uninitialized" );
  FD_CRIT( !(parent_bank->flags&FD_BANK_FLAGS_DEAD), "invariant violation: parent bank for bank index is dead" );
  /* Link node->parent */
  child_bank->parent_idx = parent_bank_idx;
  /* Link parent->node and sibling->node */
  if( FD_LIKELY( parent_bank->child_idx==null_idx ) ) {
    /* This is the first child so set as left-most child */
    parent_bank->child_idx = child_bank_idx;

  } else {
    /* Already have children so iterate to right-most sibling. */
    fd_bank_data_t * curr_bank = fd_banks_pool_ele( bank_pool, parent_bank->child_idx );
    while( curr_bank->sibling_idx != null_idx ) curr_bank = fd_banks_pool_ele( bank_pool, curr_bank->sibling_idx );
    /* Link to right-most sibling. */
    curr_bank->sibling_idx = child_bank_idx;
  }

  child_bank->first_fec_set_received_nanos      = now;
  child_bank->first_transaction_scheduled_nanos = 0L;
  child_bank->last_transaction_finished_nanos   = 0L;

  bank_l->data  = child_bank;
  return bank_l;
}

/* Mark everything in the fork tree starting at the given bank dead. */

static void
fd_banks_subtree_mark_dead( fd_banks_t *     banks,
                            fd_bank_data_t * bank_pool,
                            fd_bank_data_t * bank ) {
  if( FD_UNLIKELY( !bank ) ) FD_LOG_CRIT(( "invariant violation: bank is NULL" ));

  bank->flags |= FD_BANK_FLAGS_DEAD;
  fd_banks_dead_push_head( fd_banks_get_dead_banks_deque( banks ), (fd_bank_idx_seq_t){ .idx = bank->idx, .seq = bank->bank_seq } );

  /* Recursively mark all children as dead. */
  ulong child_idx = bank->child_idx;
  while( child_idx!=fd_banks_pool_idx_null( bank_pool ) ) {
    fd_bank_data_t * child = fd_banks_pool_ele( bank_pool, child_idx );
    fd_banks_subtree_mark_dead( banks, bank_pool, child );
    child_idx = child->sibling_idx;
  }
}

void
fd_banks_mark_bank_dead( fd_banks_t * banks,
                         ulong        bank_idx ) {
  fd_bank_data_t * bank = fd_banks_pool_ele( fd_banks_get_bank_pool( banks ), bank_idx );
  fd_banks_subtree_mark_dead( banks, fd_banks_get_bank_pool( banks ), bank );
}

int
fd_banks_prune_one_dead_bank( fd_banks_t *                   banks,
                              fd_banks_prune_cancel_info_t * cancel ) {
  fd_bank_idx_seq_t * dead_banks_queue = fd_banks_get_dead_banks_deque( banks );
  fd_bank_data_t *    bank_pool        = fd_banks_get_bank_pool( banks );
  ulong               null_idx         = fd_banks_pool_idx_null( bank_pool );
  while( !fd_banks_dead_empty( dead_banks_queue ) ) {
    fd_bank_idx_seq_t * head = fd_banks_dead_peek_head( dead_banks_queue );
    fd_bank_data_t * bank = fd_banks_pool_ele( bank_pool, head->idx );
    if( !bank->flags || bank->bank_seq!=head->seq ) {
      fd_banks_dead_pop_head( dead_banks_queue );
      continue;
    } else if( bank->refcnt!=0UL ) {
      break;
    }

    FD_LOG_DEBUG(( "pruning dead bank (idx=%lu)", bank->idx ));

    /* There are a few cases to consider:
       1. The to-be-pruned bank is the left-most child of the parent.
          This means that the parent bank's child idx is the
          to-be-pruned bank.  In this case, we can simply make the
          left-most sibling of the to-be-pruned bank the new left-most
          child (set parent's banks child idx to the sibling).  The
          sibling pointer can be null if the to-be-pruned bank is an
          only child of the parent.
       2. The to-be-pruned bank is some right child of the parent.  In
          this case, the child bank which has a sibling pointer to the
          to-be-pruned bank needs to be updated to point to the sibling
          of the to-be-pruned bank.  The sibling can even be null if the
          to-be-pruned bank is the right-most child of the parent.
    */

    FD_TEST( bank->child_idx==null_idx );
    fd_bank_data_t * parent_bank = fd_banks_pool_ele( bank_pool, bank->parent_idx );
    if( parent_bank->child_idx==bank->idx ) {
      /* Case 1: left-most child */
      parent_bank->child_idx = bank->sibling_idx;
    } else {
      /* Case 2: some right child */
      fd_bank_data_t * curr_bank = fd_banks_pool_ele( bank_pool, parent_bank->child_idx );
      while( curr_bank->sibling_idx!=bank->idx ) curr_bank = fd_banks_pool_ele( bank_pool, curr_bank->sibling_idx );
      curr_bank->sibling_idx = bank->sibling_idx;
    }
    bank->parent_idx  = null_idx;
    bank->sibling_idx = null_idx;

    if( FD_UNLIKELY( bank->cost_tracker_pool_idx!=null_idx ) ) {
      fd_bank_cost_tracker_pool_idx_release( fd_banks_get_cost_tracker_pool( banks ), bank->cost_tracker_pool_idx );
      bank->cost_tracker_pool_idx = null_idx;
    }

    fd_stake_delegations_t * stake_delegations = fd_banks_get_stake_delegations( banks );
    fd_stake_delegations_evict_fork( stake_delegations, bank->stake_delegations_fork_id );
    bank->stake_delegations_fork_id = USHORT_MAX;

    bank->stake_rewards_fork_id = UCHAR_MAX;

    int needs_cancel = !!(bank->flags&FD_BANK_FLAGS_REPLAYABLE);
    if( FD_LIKELY( needs_cancel ) ) {
      cancel->txncache_fork_id = bank->txncache_fork_id;
      cancel->slot             = bank->f.slot;
      cancel->bank_idx         = bank->idx;
    }

    bank->flags = 0UL;

    fd_banks_pool_ele_release( bank_pool, bank );
    fd_banks_dead_pop_head( dead_banks_queue );
    return 1+needs_cancel;
  }
  return 0;
}

void
fd_banks_mark_bank_frozen( fd_banks_t * banks,
                           fd_bank_t *  bank ) {
  /* TODO: Get rid of banks param */
  FD_CRIT( !(bank->data->flags&FD_BANK_FLAGS_FROZEN), "invariant violation: cost tracker pool index is null" );
  bank->data->flags |= FD_BANK_FLAGS_FROZEN;

  FD_CRIT( bank->data->cost_tracker_pool_idx!=ULONG_MAX, "invariant violation: cost tracker pool index is null" );
  fd_bank_cost_tracker_pool_idx_release( fd_banks_get_cost_tracker_pool( banks ), bank->data->cost_tracker_pool_idx );
  bank->data->cost_tracker_pool_idx = ULONG_MAX;
}

static void
fd_banks_get_frontier_private( fd_bank_data_t * bank_pool,
                               ulong            bank_idx,
                               ulong *          frontier_indices_out,
                               ulong *          frontier_cnt_out ) {
  if( bank_idx==fd_banks_pool_idx_null( bank_pool ) ) return;

  fd_bank_data_t * bank = fd_banks_pool_ele( bank_pool, bank_idx );

  if( bank->child_idx==fd_banks_pool_idx_null( bank_pool ) ) {
    if( !(bank->flags&(FD_BANK_FLAGS_FROZEN|FD_BANK_FLAGS_DEAD)) ) {
      frontier_indices_out[*frontier_cnt_out] = bank->idx;
      (*frontier_cnt_out)++;
    }
  } else {
    fd_banks_get_frontier_private( bank_pool, bank->child_idx, frontier_indices_out, frontier_cnt_out );
  }
  fd_banks_get_frontier_private( bank_pool, bank->sibling_idx, frontier_indices_out, frontier_cnt_out );
}

void
fd_banks_get_frontier( fd_banks_t * banks,
                       ulong *      frontier_indices_out,
                       ulong *      frontier_cnt_out ) {
  *frontier_cnt_out = 0UL;
  fd_bank_data_t * bank_pool = fd_banks_get_bank_pool( banks );
  fd_banks_get_frontier_private( bank_pool, banks->root_idx, frontier_indices_out, frontier_cnt_out );
}

void
fd_banks_clear_bank( fd_banks_t * banks,
                     fd_bank_t *  bank,
                     ulong        max_vote_accounts ) {

  fd_memset( &bank->data->f, 0, sizeof(bank->data->f) );

  fd_top_votes_init( fd_type_pun( bank->data->top_votes_t_1_mem ) );
  fd_top_votes_init( fd_type_pun( bank->data->top_votes_t_2_mem ) );

  /* We need to acquire a cost tracker element. */
  fd_bank_cost_tracker_t * cost_tracker_pool = fd_banks_get_cost_tracker_pool( banks );
  if( FD_UNLIKELY( bank->data->cost_tracker_pool_idx!=fd_bank_cost_tracker_pool_idx_null( cost_tracker_pool ) ) ) {
    fd_bank_cost_tracker_pool_idx_release( cost_tracker_pool, bank->data->cost_tracker_pool_idx );
  }
  bank->data->cost_tracker_pool_idx = fd_bank_cost_tracker_pool_idx_acquire( cost_tracker_pool );

  fd_vote_stakes_t * vote_stakes = fd_banks_get_vote_stakes( banks );
  fd_vote_stakes_new( vote_stakes, max_vote_accounts, max_vote_accounts, banks->max_fork_width, 999UL );
}
