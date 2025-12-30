#include "fd_bank.h"
#include "fd_runtime_const.h"

ulong
fd_bank_align( void ) {
  return alignof(fd_bank_t);
}

ulong
fd_bank_footprint( void ) {
  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, fd_bank_align(), sizeof(fd_bank_t) );
  return FD_LAYOUT_FINI( l, fd_bank_align() );
}

/* Bank accesssors */

#define HAS_COW_1(type, name, footprint, align, has_lock)                                                          \
  type const *                                                                                                     \
  fd_bank_##name##_locking_query( fd_bank_t * bank ) {                                                             \
    fd_rwlock_read( &bank->name##_lock );                                                                          \
    /* If the pool element hasn't been setup yet, then return NULL */                                              \
    fd_bank_##name##_t * name##_pool = fd_bank_get_##name##_pool( bank );                                          \
    if( FD_UNLIKELY( name##_pool==NULL ) ) {                                                                       \
      FD_LOG_CRIT(( "NULL " #name " pool" ));                                                                      \
    }                                                                                                              \
    if( bank->name##_pool_idx==fd_bank_##name##_pool_idx_null( name##_pool ) ) {                                   \
      return NULL;                                                                                                 \
    }                                                                                                              \
    fd_bank_##name##_t * bank_##name = fd_bank_##name##_pool_ele( name##_pool, bank->name##_pool_idx );            \
    return (type *)bank_##name->data;                                                                              \
  }                                                                                                                \
  void                                                                                                             \
  fd_bank_##name##_end_locking_query( fd_bank_t * bank ) {                                                         \
    fd_rwlock_unread( &bank->name##_lock );                                                                        \
  }                                                                                                                \
  type *                                                                                                           \
  fd_bank_##name##_locking_modify( fd_bank_t * bank ) {                                                            \
    fd_rwlock_write( &bank->name##_lock );                                                                         \
    /* If the dirty flag is set, then we already have a pool element */                                            \
    /* that was copied over for the current bank. We can simply just */                                            \
    /* query the pool element and return it. */                                                                    \
    fd_bank_##name##_t * name##_pool = fd_bank_get_##name##_pool( bank );                                          \
    if( FD_UNLIKELY( name##_pool==NULL ) ) {                                                                       \
      FD_LOG_CRIT(( "NULL " #name " pool" ));                                                                      \
    }                                                                                                              \
    if( bank->name##_dirty ) {                                                                                     \
      fd_bank_##name##_t * bank_##name = fd_bank_##name##_pool_ele( name##_pool, bank->name##_pool_idx );          \
      return (type *)bank_##name->data;                                                                            \
    }                                                                                                              \
    fd_rwlock_write( fd_bank_get_##name##_pool_lock( bank ) );                                                     \
    if( FD_UNLIKELY( !fd_bank_##name##_pool_free( name##_pool ) ) ) {                                              \
      FD_LOG_CRIT(( "Failed to acquire " #name " pool element: pool is full" ));                                   \
    }                                                                                                              \
    fd_bank_##name##_t * child_##name = fd_bank_##name##_pool_ele_acquire( name##_pool );                          \
    fd_rwlock_unwrite( fd_bank_get_##name##_pool_lock( bank ) );                                                   \
    /* If the dirty flag has not been set yet, we need to allocated a */                                           \
    /* new pool element and copy over the data from the parent idx.   */                                           \
    /* We also need to mark the dirty flag. */                                                                     \
    ulong child_idx = fd_bank_##name##_pool_idx( name##_pool, child_##name );                                      \
    if( bank->name##_pool_idx!=fd_bank_##name##_pool_idx_null( name##_pool ) ) {                                   \
      fd_bank_##name##_t * parent_##name = fd_bank_##name##_pool_ele( name##_pool, bank->name##_pool_idx );        \
      fd_memcpy( child_##name->data, parent_##name->data, fd_bank_##name##_footprint );                            \
    }                                                                                                              \
    bank->name##_pool_idx = child_idx;                                                                             \
    bank->name##_dirty    = 1;                                                                                     \
    return (type *)child_##name->data;                                                                             \
  }                                                                                                                \
  void                                                                                                             \
  fd_bank_##name##_end_locking_modify( fd_bank_t * bank ) {                                                        \
    fd_rwlock_unwrite( &bank->name##_lock );                                                                       \
  }

#define HAS_LOCK_0(type, name)                                    \
  type const *                                                    \
  fd_bank_##name##_query( fd_bank_t const * bank ) {              \
    return (type const *)fd_type_pun_const( bank->non_cow.name ); \
  }                                                               \
  type *                                                          \
  fd_bank_##name##_modify( fd_bank_t * bank ) {                   \
    return (type *)fd_type_pun( bank->non_cow.name );             \
  }

#define HAS_LOCK_1(type, name)                                    \
  type const *                                                    \
  fd_bank_##name##_locking_query( fd_bank_t * bank ) {            \
    fd_rwlock_read( &bank->name##_lock );                         \
    return (type const *)fd_type_pun_const( bank->non_cow.name ); \
  }                                                               \
  type *                                                          \
  fd_bank_##name##_locking_modify( fd_bank_t * bank ) {           \
    fd_rwlock_write( &bank->name##_lock );                        \
    return (type *)fd_type_pun( bank->non_cow.name );             \
  }                                                               \
  void                                                            \
  fd_bank_##name##_end_locking_query( fd_bank_t * bank ) {        \
    fd_rwlock_unread( &bank->name##_lock );                       \
  }                                                               \
  void                                                            \
  fd_bank_##name##_end_locking_modify( fd_bank_t * bank ) {       \
    fd_rwlock_unwrite( &bank->name##_lock );                      \
  }

#define HAS_COW_0(type, name, footprint, align, has_lock) \
  HAS_LOCK_##has_lock(type, name)                         \
  void                                                    \
  fd_bank_##name##_set( fd_bank_t * bank, type value ) {  \
    FD_STORE( type, bank->non_cow.name, value );          \
  }                                                       \
  type                                                    \
  fd_bank_##name##_get( fd_bank_t const * bank ) {        \
    type val = FD_LOAD( type, bank->non_cow.name );       \
    return val;                                           \
  }

#define X(type, name, footprint, align, cow, limit_fork_width, has_lock) \
  HAS_COW_##cow(type, name, footprint, align, has_lock)
FD_BANKS_ITER(X)
#undef X
#undef HAS_COW_0
#undef HAS_COW_1
#undef HAS_LOCK_0
#undef HAS_LOCK_1

/**********************************************************************/

ulong
fd_banks_align( void ) {
  /* TODO: The magic number here can probably be removed. */
  return 128UL;
}

ulong
fd_banks_footprint( ulong max_total_banks,
                    ulong max_fork_width ) {

  /* max_fork_width is used in the macro below. */

  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, fd_banks_align(),                           sizeof(fd_banks_t) );
  l = FD_LAYOUT_APPEND( l, fd_banks_pool_align(),                      fd_banks_pool_footprint( max_total_banks ) );
  l = FD_LAYOUT_APPEND( l, fd_bank_epoch_rewards_pool_align(),         fd_bank_epoch_rewards_pool_footprint( max_fork_width ) );
  l = FD_LAYOUT_APPEND( l, fd_bank_epoch_leaders_pool_align(),         fd_bank_epoch_leaders_pool_footprint( max_fork_width ) );
  l = FD_LAYOUT_APPEND( l, fd_bank_vote_states_pool_align(),           fd_bank_vote_states_pool_footprint( max_total_banks ) );
  l = FD_LAYOUT_APPEND( l, fd_bank_vote_states_prev_pool_align(),      fd_bank_vote_states_prev_pool_footprint( max_fork_width ) );
  l = FD_LAYOUT_APPEND( l, fd_bank_vote_states_prev_prev_pool_align(), fd_bank_vote_states_prev_prev_pool_footprint( max_fork_width ) );
  l = FD_LAYOUT_APPEND( l, fd_bank_cost_tracker_pool_align(),          fd_bank_cost_tracker_pool_footprint( max_fork_width ) );
  return FD_LAYOUT_FINI( l, fd_banks_align() );
}

void *
fd_banks_new( void * shmem,
              ulong  max_total_banks,
              ulong  max_fork_width,
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

  /* First, layout the banks and the pool used by fd_banks_t. */
  FD_SCRATCH_ALLOC_INIT( l, shmem );
  fd_banks_t * banks                          = FD_SCRATCH_ALLOC_APPEND( l, fd_banks_align(),                           sizeof(fd_banks_t) );
  void *       pool_mem                       = FD_SCRATCH_ALLOC_APPEND( l, fd_banks_pool_align(),                      fd_banks_pool_footprint( max_total_banks ) );
  void *       epoch_rewards_pool_mem         = FD_SCRATCH_ALLOC_APPEND( l, fd_bank_epoch_rewards_pool_align(),         fd_bank_epoch_rewards_pool_footprint( max_fork_width ) );
  void *       epoch_leaders_pool_mem         = FD_SCRATCH_ALLOC_APPEND( l, fd_bank_epoch_leaders_pool_align(),         fd_bank_epoch_leaders_pool_footprint( max_fork_width ) );
  void *       vote_states_pool_mem           = FD_SCRATCH_ALLOC_APPEND( l, fd_bank_vote_states_pool_align(),           fd_bank_vote_states_pool_footprint( max_total_banks ) );
  void *       vote_states_prev_pool_mem      = FD_SCRATCH_ALLOC_APPEND( l, fd_bank_vote_states_prev_pool_align(),      fd_bank_vote_states_prev_pool_footprint( max_fork_width ) );
  void *       vote_states_prev_prev_pool_mem = FD_SCRATCH_ALLOC_APPEND( l, fd_bank_vote_states_prev_prev_pool_align(), fd_bank_vote_states_prev_prev_pool_footprint( max_fork_width ) );
  void *       cost_tracker_pool_mem          = FD_SCRATCH_ALLOC_APPEND( l, fd_bank_cost_tracker_pool_align(),          fd_bank_cost_tracker_pool_footprint( max_fork_width ) );

  fd_rwlock_new( &banks->rwlock );

  if( FD_UNLIKELY( FD_SCRATCH_ALLOC_FINI( l, fd_banks_align() ) != (ulong)banks + fd_banks_footprint( max_total_banks, max_fork_width ) ) ) {
    FD_LOG_WARNING(( "fd_banks_new: bad layout" ));
    return NULL;
  }

  void * pool = fd_banks_pool_new( pool_mem, max_total_banks );
  if( FD_UNLIKELY( !pool ) ) {
    FD_LOG_WARNING(( "Failed to create bank pool" ));
    return NULL;
  }

  fd_bank_t * bank_pool = fd_banks_pool_join( pool );
  if( FD_UNLIKELY( !bank_pool ) ) {
    FD_LOG_WARNING(( "Failed to join bank pool" ));
    return NULL;
  }

  /* Mark all of the banks as not initialized. */
  for( ulong i=0UL; i<max_total_banks; i++ ) {
    fd_bank_t * bank = fd_banks_pool_ele( bank_pool, i );
    if( FD_UNLIKELY( !bank ) ) {
      FD_LOG_WARNING(( "Failed to get bank" ));
      return NULL;
    }
    bank->flags = 0UL;
  }

  /* Assign offset of the bank pool to the banks object. */
  fd_banks_set_bank_pool( banks, bank_pool );


  /* Create the pools for the non-inlined fields.  Also new() and join()
     each of the elements in the pool as well as set up the lock for
     each of the pools. */

  fd_rwlock_new( &banks->epoch_rewards_pool_lock );
  fd_bank_epoch_rewards_t * epoch_rewards_pool = fd_bank_epoch_rewards_pool_join( fd_bank_epoch_rewards_pool_new( epoch_rewards_pool_mem, max_fork_width ) );
  if( FD_UNLIKELY( !epoch_rewards_pool ) ) {
    FD_LOG_WARNING(( "Failed to create epoch rewards pool" ));
    return NULL;
  }
  fd_banks_set_epoch_rewards_pool( banks, epoch_rewards_pool );
  for( ulong i=0UL; i<max_fork_width; i++ ) {
    fd_bank_epoch_rewards_t * epoch_rewards = fd_bank_epoch_rewards_pool_ele( epoch_rewards_pool, i );
    if( FD_UNLIKELY( !fd_epoch_rewards_join( fd_epoch_rewards_new( epoch_rewards->data, FD_RUNTIME_MAX_STAKE_ACCOUNTS, seed ) ) ) ) {
      FD_LOG_WARNING(( "Failed to create epoch rewards" ));
      return NULL;
    }
  }

  fd_rwlock_new( &banks->epoch_leaders_pool_lock );
  fd_bank_epoch_leaders_t * epoch_leaders_pool = fd_bank_epoch_leaders_pool_join( fd_bank_epoch_leaders_pool_new( epoch_leaders_pool_mem, max_fork_width ) );
  if( FD_UNLIKELY( !epoch_leaders_pool ) ) {
    FD_LOG_WARNING(( "Failed to create epoch leaders pool" ));
    return NULL;
  }
  fd_banks_set_epoch_leaders_pool( banks, epoch_leaders_pool );

  fd_rwlock_new( &banks->vote_states_pool_lock );
  fd_bank_vote_states_t * vote_states_pool = fd_bank_vote_states_pool_join( fd_bank_vote_states_pool_new( vote_states_pool_mem, max_total_banks ) );
  if( FD_UNLIKELY( !vote_states_pool ) ) {
    FD_LOG_WARNING(( "Failed to create vote states pool" ));
    return NULL;
  }
  fd_banks_set_vote_states_pool( banks, vote_states_pool );
  for( ulong i=0UL; i<max_total_banks; i++ ) {
    fd_bank_vote_states_t * vote_states = fd_bank_vote_states_pool_ele( vote_states_pool, i );
    if( FD_UNLIKELY( !fd_vote_states_join( fd_vote_states_new( vote_states->data, FD_RUNTIME_MAX_VOTE_ACCOUNTS, seed ) ) ) ) {
      FD_LOG_WARNING(( "Failed to create vote states" ));
      return NULL;
    }
  }

  fd_rwlock_new( &banks->vote_states_prev_pool_lock );
  fd_bank_vote_states_prev_t * vote_states_prev_pool = fd_bank_vote_states_prev_pool_join( fd_bank_vote_states_prev_pool_new( vote_states_prev_pool_mem, max_fork_width ) );
  if( FD_UNLIKELY( !vote_states_prev_pool ) ) {
    FD_LOG_WARNING(( "Failed to create vote states prev pool" ));
    return NULL;
  }
  fd_banks_set_vote_states_prev_pool( banks, vote_states_prev_pool );
  for( ulong i=0UL; i<max_fork_width; i++ ) {
    fd_bank_vote_states_prev_t * vote_states_prev = fd_bank_vote_states_prev_pool_ele( vote_states_prev_pool, i );
    if( FD_UNLIKELY( !fd_vote_states_join( fd_vote_states_new( vote_states_prev->data, FD_RUNTIME_MAX_VOTE_ACCOUNTS, seed ) ) ) ) {
      FD_LOG_WARNING(( "Failed to create vote states prev" ));
      return NULL;
    }
  }

  fd_rwlock_new( &banks->vote_states_prev_prev_pool_lock );
  fd_bank_vote_states_prev_prev_t * vote_states_prev_prev_pool = fd_bank_vote_states_prev_prev_pool_join( fd_bank_vote_states_prev_prev_pool_new( vote_states_prev_prev_pool_mem, max_fork_width ) );
  if( FD_UNLIKELY( !vote_states_prev_prev_pool ) ) {
    FD_LOG_WARNING(( "Failed to create vote states prev prev pool" ));
    return NULL;
  }
  fd_banks_set_vote_states_prev_prev_pool( banks, vote_states_prev_prev_pool );
  for( ulong i=0UL; i<max_fork_width; i++ ) {
    fd_bank_vote_states_prev_prev_t * vote_states_prev_prev = fd_bank_vote_states_prev_prev_pool_ele( vote_states_prev_prev_pool, i );
    if( FD_UNLIKELY( !fd_vote_states_join( fd_vote_states_new( vote_states_prev_prev->data, FD_RUNTIME_MAX_VOTE_ACCOUNTS, seed ) ) ) ) {
      FD_LOG_WARNING(( "Failed to create vote states prev prev" ));
      return NULL;
    }
  }

  fd_bank_cost_tracker_t * cost_tracker_pool = fd_bank_cost_tracker_pool_join( fd_bank_cost_tracker_pool_new( cost_tracker_pool_mem, max_fork_width ) );
  if( FD_UNLIKELY( !cost_tracker_pool ) ) {
    FD_LOG_WARNING(( "Failed to create cost tracker pool" ));
    return NULL;
  }
  fd_banks_set_cost_tracker_pool( banks, cost_tracker_pool );
  for( ulong i=0UL; i<max_fork_width; i++ ) {
    fd_bank_cost_tracker_t * cost_tracker = fd_bank_cost_tracker_pool_ele( cost_tracker_pool, i );
    if( FD_UNLIKELY( !fd_cost_tracker_join( fd_cost_tracker_new( cost_tracker->data, larger_max_cost_per_block, seed ) ) ) ) {
      FD_LOG_WARNING(( "Failed to create cost tracker" ));
      return NULL;
    }
  }

  /* For each bank, we need to set the offset of the pools and locks
     for each of the non-inlined fields. */

  for( ulong i=0UL; i<max_total_banks; i++ ) {

    fd_bank_t * bank = fd_banks_pool_ele( bank_pool, i );

    fd_bank_epoch_rewards_t * epoch_rewards_pool = fd_banks_get_epoch_rewards_pool( banks );
    fd_bank_set_epoch_rewards_pool( bank, epoch_rewards_pool );
    fd_bank_set_epoch_rewards_pool_lock( bank, &banks->epoch_rewards_pool_lock );

    fd_bank_epoch_leaders_t * epoch_leaders_pool = fd_banks_get_epoch_leaders_pool( banks );
    fd_bank_set_epoch_leaders_pool( bank, epoch_leaders_pool );
    fd_bank_set_epoch_leaders_pool_lock( bank, &banks->epoch_leaders_pool_lock );

    fd_bank_vote_states_t * vote_states_pool = fd_banks_get_vote_states_pool( banks );
    fd_bank_set_vote_states_pool( bank, vote_states_pool );
    fd_bank_set_vote_states_pool_lock( bank, &banks->vote_states_pool_lock );

    fd_bank_vote_states_prev_t * vote_states_prev_pool = fd_banks_get_vote_states_prev_pool( banks );
    fd_bank_set_vote_states_prev_pool( bank, vote_states_prev_pool );
    fd_bank_set_vote_states_prev_pool_lock( bank, &banks->vote_states_prev_pool_lock );

    fd_bank_vote_states_prev_prev_t * vote_states_prev_prev_pool = fd_banks_get_vote_states_prev_prev_pool( banks );
    fd_bank_set_vote_states_prev_prev_pool( bank, vote_states_prev_prev_pool );
    fd_bank_set_vote_states_prev_prev_pool_lock( bank, &banks->vote_states_prev_prev_pool_lock );

    fd_bank_cost_tracker_t * cost_tracker_pool = fd_banks_get_cost_tracker_pool( banks );
    fd_bank_set_cost_tracker_pool( bank, cost_tracker_pool );

    if( FD_UNLIKELY( fd_stake_delegations_join( fd_stake_delegations_new( bank->stake_delegations_delta, seed, FD_STAKE_DELEGATIONS_MAX_PER_SLOT, 1 ) ) ) ) {
      FD_LOG_WARNING(( "Failed to create stake delegations" ));
      return NULL;
    }
  }

  banks->max_total_banks = max_total_banks;
  banks->max_fork_width  = max_fork_width;
  banks->root_idx        = ULONG_MAX;
  banks->bank_seq        = 0UL;  /* FIXME randomize across runs? */

  if( FD_UNLIKELY( !fd_stake_delegations_new( banks->stake_delegations_root, 0UL, FD_RUNTIME_MAX_STAKE_ACCOUNTS, 0 ) ) ) {
    FD_LOG_WARNING(( "Unable to create stake delegations root" ));
    return NULL;
  }

  FD_COMPILER_MFENCE();
  FD_VOLATILE( banks->magic ) = FD_BANKS_MAGIC;
  FD_COMPILER_MFENCE();

  return shmem;
}

fd_banks_t *
fd_banks_join( void * mem ) {
  fd_banks_t * banks = (fd_banks_t *)mem;

  if( FD_UNLIKELY( !banks ) ) {
    FD_LOG_WARNING(( "NULL banks" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)banks, fd_banks_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned banks" ));
    return NULL;
  }

  if( FD_UNLIKELY( banks->magic!=FD_BANKS_MAGIC ) ) {
    FD_LOG_WARNING(( "Invalid banks magic" ));
    return NULL;
  }

  FD_SCRATCH_ALLOC_INIT( l, banks );
  banks                                 = FD_SCRATCH_ALLOC_APPEND( l, fd_banks_align(),                           sizeof(fd_banks_t) );
  void * pool_mem                       = FD_SCRATCH_ALLOC_APPEND( l, fd_banks_pool_align(),                      fd_banks_pool_footprint( banks->max_total_banks ) );
  void * epoch_rewards_pool_mem         = FD_SCRATCH_ALLOC_APPEND( l, fd_bank_epoch_rewards_pool_align(),         fd_bank_epoch_rewards_pool_footprint( banks->max_fork_width ) );
  void * epoch_leaders_pool_mem         = FD_SCRATCH_ALLOC_APPEND( l, fd_bank_epoch_leaders_pool_align(),         fd_bank_epoch_leaders_pool_footprint( banks->max_fork_width ) );
  void * vote_states_pool_mem           = FD_SCRATCH_ALLOC_APPEND( l, fd_bank_vote_states_pool_align(),           fd_bank_vote_states_pool_footprint( banks->max_total_banks ) );
  void * vote_states_prev_pool_mem      = FD_SCRATCH_ALLOC_APPEND( l, fd_bank_vote_states_prev_pool_align(),      fd_bank_vote_states_prev_pool_footprint( banks->max_fork_width ) );
  void * vote_states_prev_prev_pool_mem = FD_SCRATCH_ALLOC_APPEND( l, fd_bank_vote_states_prev_prev_pool_align(), fd_bank_vote_states_prev_prev_pool_footprint( banks->max_fork_width ) );
  void * cost_tracker_pool_mem          = FD_SCRATCH_ALLOC_APPEND( l, fd_bank_cost_tracker_pool_align(),          fd_bank_cost_tracker_pool_footprint( banks->max_fork_width ) );

  FD_SCRATCH_ALLOC_FINI( l, fd_banks_align() );

  fd_bank_t * banks_pool = fd_banks_get_bank_pool( banks );
  if( FD_UNLIKELY( !banks_pool ) ) {
    FD_LOG_WARNING(( "Failed to join bank pool" ));
    return NULL;
  }

  if( FD_UNLIKELY( banks_pool!=fd_banks_pool_join( pool_mem ) ) ) {
    FD_LOG_WARNING(( "Failed to join bank pool" ));
    return NULL;
  }

  fd_bank_epoch_rewards_t * epoch_rewards_pool = fd_banks_get_epoch_rewards_pool( banks );
  if( FD_UNLIKELY( !epoch_rewards_pool ) ) {
    FD_LOG_WARNING(( "Failed to join epoch rewards pool" ));
    return NULL;
  }

  if( FD_UNLIKELY( epoch_rewards_pool!=fd_bank_epoch_rewards_pool_join( epoch_rewards_pool_mem ) ) ) {
    FD_LOG_WARNING(( "Failed to join epoch rewards pool" ));
    return NULL;
  }

  fd_bank_epoch_leaders_t * epoch_leaders_pool = fd_banks_get_epoch_leaders_pool( banks );
  if( FD_UNLIKELY( !epoch_leaders_pool ) ) {
    FD_LOG_WARNING(( "Failed to join epoch leaders pool" ));
    return NULL;
  }

  if( FD_UNLIKELY( epoch_leaders_pool!=fd_bank_epoch_leaders_pool_join( epoch_leaders_pool_mem ) ) ) {
    FD_LOG_WARNING(( "Failed to join epoch leaders pool" ));
    return NULL;
  }

  fd_bank_vote_states_t * vote_states_pool = fd_banks_get_vote_states_pool( banks );
  if( FD_UNLIKELY( !vote_states_pool ) ) {
    FD_LOG_WARNING(( "Failed to join vote states pool" ));
    return NULL;
  }

  if( FD_UNLIKELY( vote_states_pool!=fd_bank_vote_states_pool_join( vote_states_pool_mem ) ) ) {
    FD_LOG_WARNING(( "Failed to join vote states pool" ));
    return NULL;
  }

  fd_bank_vote_states_prev_t * vote_states_prev_pool = fd_banks_get_vote_states_prev_pool( banks );
  if( FD_UNLIKELY( !vote_states_prev_pool ) ) {
    FD_LOG_WARNING(( "Failed to join vote states prev pool" ));
    return NULL;
  }

  if( FD_UNLIKELY( vote_states_prev_pool!=fd_bank_vote_states_prev_pool_join( vote_states_prev_pool_mem ) ) ) {
    FD_LOG_WARNING(( "Failed to join vote states prev pool" ));
    return NULL;
  }

  fd_bank_vote_states_prev_prev_t * vote_states_prev_prev_pool = fd_banks_get_vote_states_prev_prev_pool( banks );
  if( FD_UNLIKELY( !vote_states_prev_prev_pool ) ) {
    FD_LOG_WARNING(( "Failed to join vote states prev prev pool" ));
    return NULL;
  }

  if( FD_UNLIKELY( vote_states_prev_prev_pool!=fd_bank_vote_states_prev_prev_pool_join( vote_states_prev_prev_pool_mem ) ) ) {
    FD_LOG_WARNING(( "Failed to join vote states prev prev pool" ));
    return NULL;
  }


  fd_bank_cost_tracker_t * cost_tracker_pool = fd_banks_get_cost_tracker_pool( banks );
  if( FD_UNLIKELY( !cost_tracker_pool ) ) {
    FD_LOG_WARNING(( "Failed to join cost tracker pool" ));
    return NULL;
  }

  if( FD_UNLIKELY( cost_tracker_pool!=fd_bank_cost_tracker_pool_join( cost_tracker_pool_mem ) ) ) {
    FD_LOG_WARNING(( "Failed to join cost tracker pool" ));
    return NULL;
  }


  return banks;
}

void *
fd_banks_leave( fd_banks_t * banks ) {

  if( FD_UNLIKELY( !banks ) ) {
    FD_LOG_WARNING(( "NULL banks" ));
    return NULL;
  }

  return (void *)banks;
}

void *
fd_banks_delete( void * shmem ) {

  if( FD_UNLIKELY( !shmem ) ) {
    FD_LOG_WARNING(( "NULL banks" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned((ulong)shmem, fd_banks_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned banks" ));
    return NULL;
  }

  fd_banks_t * banks = (fd_banks_t *)shmem;
  banks->magic = 0UL;

  return shmem;
}

fd_bank_t *
fd_banks_init_bank( fd_banks_t * banks ) {

  if( FD_UNLIKELY( !banks ) ) {
    FD_LOG_WARNING(( "NULL banks" ));
    return NULL;
  }

  fd_bank_t * bank_pool = fd_banks_get_bank_pool( banks );

  fd_rwlock_write( &banks->rwlock );

  if( FD_UNLIKELY( !fd_banks_pool_free( bank_pool ) ) ) {
    FD_LOG_WARNING(( "Failed to acquire bank" ));
    fd_rwlock_unwrite( &banks->rwlock );
    return NULL;
  }
  fd_bank_t * bank = fd_banks_pool_ele_acquire( bank_pool );
  bank->bank_seq = FD_ATOMIC_FETCH_AND_ADD( &banks->bank_seq, 1UL );

  #define HAS_COW_1(type, name, footprint)

  #define HAS_COW_0(type, name, footprint) \
    fd_memset( bank->non_cow.name, 0, footprint );

  #define X(type, name, footprint, align, cow, limit_fork_width, has_lock) \
    HAS_COW_##cow(type, name, footprint)
  FD_BANKS_ITER(X)
  #undef X
  #undef HAS_COW_0
  #undef HAS_COW_1

  ulong null_idx    = fd_banks_pool_idx_null( bank_pool );
  bank->idx         = fd_banks_pool_idx( bank_pool, bank );
  bank->next        = null_idx;
  bank->parent_idx  = null_idx;
  bank->child_idx   = null_idx;
  bank->sibling_idx = null_idx;

  /* For all non-inlined fields make sure that each field is marked
     as not dirty and that the locks are initialized. */

  bank->epoch_rewards_pool_idx         = fd_bank_epoch_rewards_pool_idx_null( fd_banks_get_epoch_rewards_pool( banks ) );
  bank->epoch_rewards_dirty            = 0;
  fd_rwlock_new( &bank->epoch_rewards_lock );

  bank->epoch_leaders_pool_idx         = fd_bank_epoch_leaders_pool_idx_null( fd_banks_get_epoch_leaders_pool( banks ) );
  bank->epoch_leaders_dirty            = 0;
  fd_rwlock_new( &bank->epoch_leaders_lock );

  bank->vote_states_pool_idx           = fd_bank_vote_states_pool_idx_null( fd_banks_get_vote_states_pool( banks ) );
  bank->vote_states_dirty              = 0;
  fd_rwlock_new( &bank->vote_states_lock );

  bank->vote_states_prev_pool_idx      = fd_bank_vote_states_prev_pool_idx_null( fd_banks_get_vote_states_prev_pool( banks ) );
  bank->vote_states_prev_dirty         = 0;
  fd_rwlock_new( &bank->vote_states_prev_lock );

  bank->vote_states_prev_prev_pool_idx = fd_bank_vote_states_prev_prev_pool_idx_null( fd_banks_get_vote_states_prev_prev_pool( banks ) );
  bank->vote_states_prev_prev_dirty    = 0;
  fd_rwlock_new( &bank->vote_states_prev_prev_lock );

  bank->cost_tracker_pool_idx = fd_bank_cost_tracker_pool_idx_null( fd_bank_get_cost_tracker_pool( bank ) );
  fd_rwlock_new( &bank->cost_tracker_lock );

  bank->stake_delegations_delta_dirty = 0;
  fd_rwlock_new( &bank->stake_delegations_delta_lock );


  #define HAS_LOCK_1(name) \
    fd_rwlock_new( &bank->name##_lock );
  #define HAS_LOCK_0(name)

  #define X(type, name, footprint, align, cow, limit_fork_width, has_lock) HAS_LOCK_##has_lock(name)
  FD_BANKS_ITER(X)
  #undef X
  #undef HAS_LOCK_0
  #undef HAS_LOCK_1

  bank->flags |= FD_BANK_FLAGS_INIT | FD_BANK_FLAGS_REPLAYABLE | FD_BANK_FLAGS_FROZEN;
  bank->refcnt = 0UL;

  bank->first_fec_set_received_nanos      = fd_log_wallclock();
  bank->preparation_begin_nanos           = 0L;
  bank->first_transaction_scheduled_nanos = 0L;
  bank->last_transaction_finished_nanos   = 0L;

  /* Now that the node is inserted, update the root */

  banks->root_idx = bank->idx;

  fd_rwlock_unwrite( &banks->rwlock );
  return bank;
}

fd_bank_t *
fd_banks_clone_from_parent( fd_banks_t * banks,
                            ulong        child_bank_idx,
                            ulong        parent_bank_idx ) {
  fd_rwlock_write( &banks->rwlock );

  fd_bank_t * bank_pool = fd_banks_get_bank_pool( banks );
  if( FD_UNLIKELY( !bank_pool ) ) {
    FD_LOG_CRIT(( "invariant violation: failed to get bank pool" ));
  }

  /* Make sure that the bank is valid. */

  fd_bank_t * child_bank = fd_banks_pool_ele( bank_pool, child_bank_idx );
  if( FD_UNLIKELY( !child_bank ) ) {
    FD_LOG_CRIT(( "Invariant violation: bank for bank index %lu does not exist", child_bank_idx ));
  }
  if( FD_UNLIKELY( !(child_bank->flags&FD_BANK_FLAGS_INIT) ) ) {
    FD_LOG_CRIT(( "Invariant violation: bank for bank index %lu is not initialized", child_bank_idx ));
  }

  /* Then make sure that the parent bank is valid and frozen. */

  fd_bank_t * parent_bank = fd_banks_pool_ele( bank_pool, parent_bank_idx );
  if( FD_UNLIKELY( !parent_bank ) ) {
    FD_LOG_CRIT(( "Invariant violation: parent bank for bank index %lu does not exist", parent_bank_idx ));
  }
  if( FD_UNLIKELY( !(parent_bank->flags&FD_BANK_FLAGS_FROZEN) ) ) {
    FD_LOG_CRIT(( "Invariant violation: parent bank for bank index %lu is not frozen", parent_bank_idx ));
  }

  /* We want to copy over the fields from the parent to the child,
     except for the fields which correspond to the header of the bank
     struct which either are used for internal memory managment or are
     fields which are not copied over from the parent bank (e.g. stake
     delegations delta and the cost tracker).  We can take advantage of
     the fact that those fields are laid out at the top of the bank
     struct. */

  child_bank->non_cow = parent_bank->non_cow;

  child_bank->epoch_rewards_dirty    = 0;
  child_bank->epoch_rewards_pool_idx = parent_bank->epoch_rewards_pool_idx;
  fd_rwlock_new( &child_bank->epoch_rewards_lock );

  child_bank->epoch_leaders_dirty    = 0;
  child_bank->epoch_leaders_pool_idx = parent_bank->epoch_leaders_pool_idx;
  fd_rwlock_new( &child_bank->epoch_leaders_lock );

  child_bank->vote_states_dirty    = 0;
  child_bank->vote_states_pool_idx = parent_bank->vote_states_pool_idx;
  fd_rwlock_new( &child_bank->vote_states_lock );

  child_bank->vote_states_prev_dirty    = 0;
  child_bank->vote_states_prev_pool_idx = parent_bank->vote_states_prev_pool_idx;
  fd_rwlock_new( &child_bank->vote_states_prev_lock );

  child_bank->vote_states_prev_prev_dirty    = 0;
  child_bank->vote_states_prev_prev_pool_idx = parent_bank->vote_states_prev_prev_pool_idx;
  fd_rwlock_new( &child_bank->vote_states_prev_prev_lock );

  child_bank->stake_delegations_delta_dirty = 0;
  fd_rwlock_new( &child_bank->stake_delegations_delta_lock );

  /* The cost tracker pool needs to be set for the child bank and then
     a cost tracker pool element needs to be acquired. */

  fd_bank_cost_tracker_t * cost_tracker_pool = fd_bank_get_cost_tracker_pool( child_bank );
  if( FD_UNLIKELY( fd_bank_cost_tracker_pool_free( cost_tracker_pool )==0UL ) ) {
    FD_LOG_CRIT(( "invariant violation: no free cost tracker pool elements" ));
  }
  child_bank->cost_tracker_pool_idx = fd_bank_cost_tracker_pool_idx_acquire( cost_tracker_pool );
  fd_rwlock_new( &child_bank->cost_tracker_lock );

  /* Setup locks for new bank as free. */
  #define HAS_LOCK_1(name) \
    fd_rwlock_unwrite(&child_bank->name##_lock);
  #define HAS_LOCK_0(name)

  #define X(type, name, footprint, align, cow, limit_fork_width, has_lock) \
    HAS_LOCK_##has_lock(name)
  FD_BANKS_ITER(X)
  #undef X
  #undef HAS_LOCK_0
  #undef HAS_LOCK_1

  /* If the parent bank is dead, then we also need to mark the child
     bank as being a dead block. */
  if( FD_UNLIKELY( parent_bank->flags & FD_BANK_FLAGS_DEAD ) ) {
    child_bank->flags |= FD_BANK_FLAGS_DEAD;
  }

  child_bank->refcnt = 0UL;

  /* Now the child bank is replayable. */
  child_bank->flags |= FD_BANK_FLAGS_REPLAYABLE;

  fd_rwlock_unwrite( &banks->rwlock );

  return child_bank;
}

/* Apply a fd_stake_delegations_t into the root. This assumes that there
   are no in-between, un-applied banks between the root and the bank
   being applied. This also assumes that the stake delegation object
   that is being applied is a delta. */

static inline void
fd_banks_stake_delegations_apply_delta( fd_bank_t *              bank,
                                        fd_stake_delegations_t * stake_delegations_base ) {

  if( !bank->stake_delegations_delta_dirty ) {
    return;
  }

  fd_stake_delegations_t * stake_delegations_delta = fd_stake_delegations_join( bank->stake_delegations_delta );
  if( FD_UNLIKELY( !stake_delegations_delta ) ) {
    FD_LOG_CRIT(( "Failed to join stake delegations delta" ));
  }

  fd_stake_delegations_iter_t iter_[1];
  for( fd_stake_delegations_iter_t * iter = fd_stake_delegations_iter_init( iter_, stake_delegations_delta );
       !fd_stake_delegations_iter_done( iter );
       fd_stake_delegations_iter_next( iter ) ) {
    fd_stake_delegation_t const * stake_delegation = fd_stake_delegations_iter_ele( iter );
    if( FD_LIKELY( !stake_delegation->is_tombstone ) ) {
      fd_stake_delegations_update(
          stake_delegations_base,
          &stake_delegation->stake_account,
          &stake_delegation->vote_account,
          stake_delegation->stake,
          stake_delegation->activation_epoch,
          stake_delegation->deactivation_epoch,
          stake_delegation->credits_observed,
          stake_delegation->warmup_cooldown_rate
      );
    } else {
      fd_stake_delegations_remove( stake_delegations_base, &stake_delegation->stake_account );
    }
  }
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
  ulong pool_indicies[ banks->max_total_banks ];
  ulong pool_indicies_len = 0UL;

  fd_bank_t * bank_pool = fd_banks_get_bank_pool( banks );

  ulong curr_idx = fd_banks_pool_idx( bank_pool, bank );
  while( curr_idx!=fd_banks_pool_idx_null( bank_pool ) ) {
    pool_indicies[pool_indicies_len++] = curr_idx;
    fd_bank_t * curr_bank = fd_banks_pool_ele( bank_pool, curr_idx );
    curr_idx = curr_bank->parent_idx;
  }

  /* We have populated all of the indicies that we need to apply deltas
     from in reverse order. */

  for( ulong i=pool_indicies_len; i>0; i-- ) {
    ulong idx = pool_indicies[i-1UL];
    fd_banks_stake_delegations_apply_delta( fd_banks_pool_ele( bank_pool, idx ), stake_delegations );
  }
}

fd_stake_delegations_t *
fd_bank_stake_delegations_frontier_query( fd_banks_t * banks, fd_bank_t * bank ) {

  fd_rwlock_write( &banks->rwlock );

  /* First copy the rooted state into the frontier. */
  memcpy( banks->stake_delegations_frontier, banks->stake_delegations_root, FD_STAKE_DELEGATIONS_FOOTPRINT );

  /* Now apply all of the updates from the bank and all of its
     ancestors in order to the frontier. */
  fd_stake_delegations_t * stake_delegations = fd_stake_delegations_join( banks->stake_delegations_frontier );
  fd_bank_stake_delegation_apply_deltas( banks, bank, stake_delegations );

  fd_rwlock_unwrite( &banks->rwlock );

  return stake_delegations;
}

fd_stake_delegations_t *
fd_banks_stake_delegations_root_query( fd_banks_t * banks ) {
  return fd_stake_delegations_join( banks->stake_delegations_root );
}

fd_bank_t const *
fd_banks_advance_root( fd_banks_t * banks,
                       ulong        root_bank_idx ) {

  fd_rwlock_write( &banks->rwlock );

  fd_bank_t * bank_pool = fd_banks_get_bank_pool( banks );

  ulong null_idx = fd_banks_pool_idx_null( bank_pool );

  /* We want to replace the old root with the new root. This means we
     have to remove banks that aren't descendants of the new root. */

  fd_bank_t const * old_root = fd_banks_root( banks );
  if( FD_UNLIKELY( !old_root ) ) {
    FD_LOG_CRIT(( "invariant violation: old root is NULL" ));
  }

  if( FD_UNLIKELY( old_root->refcnt!=0UL ) ) {
    FD_LOG_CRIT(( "refcnt for old root bank at index %lu is nonzero: %lu", old_root->idx, old_root->refcnt ));
  }

  fd_bank_t * new_root = fd_banks_bank_query( banks, root_bank_idx );
  if( FD_UNLIKELY( !new_root ) ) {
    FD_LOG_CRIT(( "invariant violation: new root is NULL" ));
  }

  if( FD_UNLIKELY( new_root->parent_idx!=old_root->idx ) ) {
    FD_LOG_CRIT(( "invariant violation: trying to advance root bank by more than one" ));
  }

  fd_stake_delegations_t * stake_delegations = fd_stake_delegations_join( banks->stake_delegations_root );
  fd_bank_stake_delegation_apply_deltas( banks, new_root, stake_delegations );
  new_root->stake_delegations_delta_dirty = 0;

  /* Now that the deltas have been applied, we can remove all nodes
     that are not direct descendants of the new root. */
  fd_bank_t * head = fd_banks_pool_ele( bank_pool, old_root->idx );
  head->next       = fd_banks_pool_idx_null( bank_pool );
  fd_bank_t * tail = head;

  while( head ) {
    fd_bank_t * child = fd_banks_pool_ele( bank_pool, head->child_idx );

    while( FD_LIKELY( child ) ) {

      if( FD_LIKELY( child!=new_root ) ) {
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

    fd_bank_t * next = fd_banks_pool_ele( bank_pool, head->next );

    /* Decide if we need to free any CoW fields. We free a CoW member
       from its pool if the dirty flag is set unless it is the same
       pool that the new root uses.

       If the new root did not have the dirty bit set, that means the node
       didn't own the pool index. Change the ownership to the new root. */
    fd_rwlock_write( &new_root->epoch_rewards_lock );
    fd_bank_epoch_rewards_t * epoch_rewards_pool = fd_bank_get_epoch_rewards_pool( new_root );
    if( head->epoch_rewards_dirty && head->epoch_rewards_pool_idx!=new_root->epoch_rewards_pool_idx && head->flags&FD_BANK_FLAGS_REPLAYABLE ) {
      fd_rwlock_write( &banks->epoch_rewards_pool_lock );
      fd_bank_epoch_rewards_pool_idx_release( epoch_rewards_pool, head->epoch_rewards_pool_idx );
      fd_rwlock_unwrite( &banks->epoch_rewards_pool_lock );
    } else if( new_root->epoch_rewards_pool_idx!=fd_bank_epoch_rewards_pool_idx_null( epoch_rewards_pool ) ) {
      new_root->epoch_rewards_dirty = 1;
    }
    fd_rwlock_unwrite( &new_root->epoch_rewards_lock );

    fd_rwlock_write( &new_root->epoch_leaders_lock );
    fd_bank_epoch_leaders_t * epoch_leaders_pool = fd_bank_get_epoch_leaders_pool( new_root );
    if( head->epoch_leaders_dirty && head->epoch_leaders_pool_idx!=new_root->epoch_leaders_pool_idx && head->flags&FD_BANK_FLAGS_REPLAYABLE ) {
      fd_rwlock_write( &banks->epoch_leaders_pool_lock );
      fd_bank_epoch_leaders_pool_idx_release( epoch_leaders_pool, head->epoch_leaders_pool_idx );
      fd_rwlock_unwrite( &banks->epoch_leaders_pool_lock );
    } else if( new_root->epoch_leaders_pool_idx!=fd_bank_epoch_leaders_pool_idx_null( epoch_leaders_pool ) ) {
      new_root->epoch_leaders_dirty = 1;
    }
    fd_rwlock_unwrite( &new_root->epoch_leaders_lock );

    fd_rwlock_write( &new_root->vote_states_lock );
    fd_bank_vote_states_t * vote_states_pool = fd_bank_get_vote_states_pool( new_root );
    if( head->vote_states_dirty && head->vote_states_pool_idx!=new_root->vote_states_pool_idx && head->flags&FD_BANK_FLAGS_REPLAYABLE ) {
      fd_rwlock_write( &banks->vote_states_pool_lock );
      fd_bank_vote_states_pool_idx_release( vote_states_pool, head->vote_states_pool_idx );
      fd_rwlock_unwrite( &banks->vote_states_pool_lock );
    } else if( new_root->vote_states_pool_idx!=fd_bank_vote_states_pool_idx_null( vote_states_pool ) ) {
      new_root->vote_states_dirty = 1;
    }
    fd_rwlock_unwrite( &new_root->vote_states_lock );

    fd_rwlock_write( &new_root->vote_states_prev_lock );
    fd_bank_vote_states_prev_t * vote_states_prev_pool = fd_bank_get_vote_states_prev_pool( new_root );
    if( head->vote_states_prev_dirty && head->vote_states_prev_pool_idx!=new_root->vote_states_prev_pool_idx && head->flags&FD_BANK_FLAGS_REPLAYABLE ) {
      fd_rwlock_write( &banks->vote_states_prev_pool_lock );
      fd_bank_vote_states_prev_pool_idx_release( vote_states_prev_pool, head->vote_states_prev_pool_idx );
      fd_rwlock_unwrite( &banks->vote_states_prev_pool_lock );
    } else if( new_root->vote_states_prev_pool_idx!=fd_bank_vote_states_prev_pool_idx_null( vote_states_prev_pool ) ) {
      new_root->vote_states_prev_dirty = 1;
    }
    fd_rwlock_unwrite( &new_root->vote_states_prev_lock );

    fd_rwlock_write( &new_root->vote_states_prev_prev_lock );
    fd_bank_vote_states_prev_prev_t * vote_states_prev_prev_pool = fd_bank_get_vote_states_prev_prev_pool( new_root );
    if( head->vote_states_prev_prev_dirty && head->vote_states_prev_prev_pool_idx!=new_root->vote_states_prev_prev_pool_idx && head->flags&FD_BANK_FLAGS_REPLAYABLE ) {
      fd_rwlock_write( &banks->vote_states_prev_prev_pool_lock );
      fd_bank_vote_states_prev_prev_pool_idx_release( vote_states_prev_prev_pool, head->vote_states_prev_prev_pool_idx );
      fd_rwlock_unwrite( &banks->vote_states_prev_prev_pool_lock );
    } else if( new_root->vote_states_prev_prev_pool_idx!=fd_bank_vote_states_prev_prev_pool_idx_null( vote_states_prev_prev_pool ) ) {
      new_root->vote_states_prev_prev_dirty = 1;
    }
    fd_rwlock_unwrite( &new_root->vote_states_prev_prev_lock );

    /* It is possible for a bank that never finished replaying to be
       pruned away.  If the bank was never frozen, then it's possible
       that the bank still owns a cost tracker pool element.  If this
       is the case, we need to release the pool element. */
    if( head->cost_tracker_pool_idx!=fd_bank_cost_tracker_pool_idx_null( fd_bank_get_cost_tracker_pool( head )) ) {
      FD_TEST( !(head->flags&FD_BANK_FLAGS_FROZEN) && head->flags&FD_BANK_FLAGS_REPLAYABLE );
      FD_LOG_DEBUG(( "releasing cost tracker pool element for bank at index %lu at slot %lu", head->idx, fd_bank_slot_get( head ) ));
      fd_bank_cost_tracker_pool_idx_release( fd_bank_get_cost_tracker_pool( head ), head->cost_tracker_pool_idx );
      head->cost_tracker_pool_idx = fd_bank_cost_tracker_pool_idx_null( fd_bank_get_cost_tracker_pool( head ) );
    }

    head->flags = 0UL;
    fd_banks_pool_ele_release( bank_pool, head );
    head = next;
  }

  new_root->parent_idx = null_idx;
  banks->root_idx      = new_root->idx;

  fd_rwlock_unwrite( &banks->rwlock );

  return new_root;
}

void
fd_banks_clear_bank( fd_banks_t * banks, fd_bank_t * bank ) {

  fd_rwlock_read( &banks->rwlock );
  /* Get the parent bank. */
  fd_bank_t * parent_bank = fd_banks_pool_ele( fd_banks_get_bank_pool( banks ), bank->parent_idx );

  fd_memset( &bank->non_cow, 0, sizeof(bank->non_cow) );

  fd_bank_epoch_rewards_t * epoch_rewards_pool = fd_bank_get_epoch_rewards_pool( bank );
  if( bank->epoch_rewards_dirty ) {
    fd_bank_epoch_rewards_pool_idx_release( epoch_rewards_pool, bank->epoch_rewards_pool_idx );
    bank->epoch_rewards_dirty = 0;
    bank->epoch_rewards_pool_idx = parent_bank ? parent_bank->epoch_rewards_pool_idx : fd_bank_epoch_rewards_pool_idx_null( epoch_rewards_pool );
  }

  fd_bank_epoch_leaders_t * epoch_leaders_pool = fd_bank_get_epoch_leaders_pool( bank );
  if( bank->epoch_leaders_dirty ) {
    fd_bank_epoch_leaders_pool_idx_release( epoch_leaders_pool, bank->epoch_leaders_pool_idx );
    bank->epoch_leaders_dirty = 0;
    bank->epoch_leaders_pool_idx = parent_bank ? parent_bank->epoch_leaders_pool_idx : fd_bank_epoch_leaders_pool_idx_null( epoch_leaders_pool );
  }

  fd_bank_vote_states_t * vote_states_pool = fd_bank_get_vote_states_pool( bank );
  if( bank->vote_states_dirty ) {
    fd_bank_vote_states_pool_idx_release( vote_states_pool, bank->vote_states_pool_idx );
    bank->vote_states_dirty = 0;
    bank->vote_states_pool_idx = parent_bank ? parent_bank->vote_states_pool_idx : fd_bank_vote_states_pool_idx_null( vote_states_pool );
  }

  fd_bank_vote_states_prev_t * vote_states_prev_pool = fd_bank_get_vote_states_prev_pool( bank );
  if( bank->vote_states_prev_dirty ) {
    fd_bank_vote_states_prev_pool_idx_release( vote_states_prev_pool, bank->vote_states_prev_pool_idx );
    bank->vote_states_prev_dirty = 0;
    bank->vote_states_prev_pool_idx = parent_bank ? parent_bank->vote_states_prev_pool_idx : fd_bank_vote_states_prev_pool_idx_null( vote_states_prev_pool );
  }

  fd_bank_vote_states_prev_prev_t * vote_states_prev_prev_pool = fd_bank_get_vote_states_prev_prev_pool( bank );
  if( bank->vote_states_prev_prev_dirty ) {
    fd_bank_vote_states_prev_prev_pool_idx_release( vote_states_prev_prev_pool, bank->vote_states_prev_prev_pool_idx );
    bank->vote_states_prev_prev_dirty = 0;
    bank->vote_states_prev_prev_pool_idx = parent_bank ? parent_bank->vote_states_prev_prev_pool_idx : fd_bank_vote_states_prev_prev_pool_idx_null( vote_states_prev_prev_pool );
  }

  /* We need to acquire a cost tracker element. */
  fd_bank_cost_tracker_t * cost_tracker_pool = fd_bank_get_cost_tracker_pool( bank );
  if( FD_UNLIKELY( bank->cost_tracker_pool_idx!=fd_bank_cost_tracker_pool_idx_null( cost_tracker_pool ) ) ) {
    fd_bank_cost_tracker_pool_idx_release( cost_tracker_pool, bank->cost_tracker_pool_idx );
  }
  bank->cost_tracker_pool_idx = fd_bank_cost_tracker_pool_idx_acquire( cost_tracker_pool );
  fd_rwlock_unwrite( &bank->cost_tracker_lock );

  bank->stake_delegations_delta_dirty = 0;
  fd_rwlock_unwrite( &bank->stake_delegations_delta_lock );

  fd_rwlock_unread( &banks->rwlock );
}

/* Is the fork tree starting at the given bank entirely eligible for
   pruning?  Returns 1 for yes, 0 for no.

   See comment in fd_replay_tile.c for more details on safe pruning. */
static int
fd_banks_subtree_can_be_pruned( fd_bank_t * bank_pool, fd_bank_t * bank ) {
  if( FD_UNLIKELY( !bank ) ) {
    FD_LOG_CRIT(( "invariant violation: bank is NULL" ));
  }

  if( bank->refcnt!=0UL ) {
    return 0;
  }

  /* Recursively check all children. */
  ulong child_idx = bank->child_idx;
  while( child_idx!=fd_banks_pool_idx_null( bank_pool ) ) {
    fd_bank_t * child = fd_banks_pool_ele( bank_pool, child_idx );
    if( !fd_banks_subtree_can_be_pruned( bank_pool, child ) ) {
      return 0;
    }
    child_idx = child->sibling_idx;
  }

  return 1;
}

/* Mark everything in the fork tree starting at the given bank dead. */

static void
fd_banks_subtree_mark_dead( fd_bank_t * bank_pool, fd_bank_t * bank ) {
  if( FD_UNLIKELY( !bank ) ) {
    FD_LOG_CRIT(( "invariant violation: bank is NULL" ));
  }
  if( FD_UNLIKELY( bank->flags & FD_BANK_FLAGS_ROOTED ) ) {
    FD_LOG_CRIT(( "invariant violation: bank for idx %lu is rooted", bank->idx ));
  }

  bank->flags |= FD_BANK_FLAGS_DEAD;

  /* Recursively mark all children as dead. */
  ulong child_idx = bank->child_idx;
  while( child_idx!=fd_banks_pool_idx_null( bank_pool ) ) {
    fd_bank_t * child = fd_banks_pool_ele( bank_pool, child_idx );
    fd_banks_subtree_mark_dead( bank_pool, child );
    child_idx = child->sibling_idx;
  }
}

int
fd_banks_advance_root_prepare( fd_banks_t * banks,
                               ulong        target_bank_idx,
                               ulong *      advanceable_bank_idx_out ) {
  /* TODO: An optimization here is to do a single traversal of the tree
     that would mark minority forks as dead while accumulating
     refcnts to determine which bank is the highest advanceable. */

  fd_bank_t * bank_pool = fd_banks_get_bank_pool( banks );
  fd_rwlock_read( &banks->rwlock );

  fd_bank_t * root = fd_banks_root( banks );
  if( FD_UNLIKELY( !root ) ) {
    FD_LOG_WARNING(( "failed to get root bank" ));
    fd_rwlock_unread( &banks->rwlock );
    return 0;
  }

  /* Early exit if target is the same as the old root. */
  if( FD_UNLIKELY( root->idx==target_bank_idx ) ) {
    FD_LOG_WARNING(( "target bank_idx %lu is the same as the old root's bank index %lu", target_bank_idx, root->idx ));
    fd_rwlock_unread( &banks->rwlock );
    return 0;
  }

  /* Early exit if the root bank still has a reference to it, we can't
     advance from it unti it's released. */
  if( FD_UNLIKELY( root->refcnt!=0UL ) ) {
    fd_rwlock_unread( &banks->rwlock );
    return 0;
  }

  fd_bank_t * target_bank = fd_banks_pool_ele( bank_pool, target_bank_idx );
  if( FD_UNLIKELY( !target_bank ) ) {
    FD_LOG_CRIT(( "failed to get bank for valid pool idx %lu", target_bank_idx ));
  }

  /* Mark every node from the target bank up through its parents to the
     root as being rooted.  We also need to figure out the oldest,
     non-rooted ancestor of the target bank since we only want to
     advance our root bank by one. */
  fd_bank_t * curr = target_bank;
  fd_bank_t * prev = NULL;
  while( curr && curr!=root ) {
    curr->flags |= FD_BANK_FLAGS_ROOTED;
    prev         = curr;
    curr         = fd_banks_pool_ele( bank_pool, curr->parent_idx );
  }

  /* If we didn't reach the old root or there is no parent, target is
     not a descendant. */
  if( FD_UNLIKELY( !curr || prev->parent_idx!=root->idx ) ) {
    FD_LOG_CRIT(( "invariant violation: target bank_idx %lu is not a direct descendant of root bank_idx %lu %lu %lu", target_bank_idx, root->idx, prev->idx, prev->parent_idx ));
  }

  curr = root;
  while( curr && (curr->flags&FD_BANK_FLAGS_ROOTED) && curr!=target_bank ) { /* curr!=target_bank to avoid abandoning good forks. */
    fd_bank_t * rooted_child = NULL;
    ulong       child_idx    = curr->child_idx;
    while( child_idx!=fd_banks_pool_idx_null( bank_pool ) ) {
      fd_bank_t * child_bank = fd_banks_pool_ele( bank_pool, child_idx );
      if( child_bank->flags&FD_BANK_FLAGS_ROOTED ) {
        rooted_child = child_bank;
      } else {
        /* This is a minority fork. */
        FD_LOG_DEBUG(( "abandoning minority fork on bank idx %lu", child_bank->idx ));
        fd_banks_subtree_mark_dead( bank_pool, child_bank );
      }
      child_idx = child_bank->sibling_idx;
    }
    curr = rooted_child;
  }

  /* We should mark the old root bank as dead. */
  root->flags |= FD_BANK_FLAGS_DEAD;

  /* We will at most advance our root bank by one.  This means we can
     advance our root bank by one if each of the siblings of the
     potential new root are eligible for pruning.  Each of the sibling
     subtrees can be pruned if the subtrees have no active references on
     their bank. */
  ulong advance_candidate_idx = prev->idx;
  ulong child_idx = root->child_idx;
  while( child_idx!=fd_banks_pool_idx_null( bank_pool ) ) {
    fd_bank_t * child_bank = fd_banks_pool_ele( bank_pool, child_idx );
    if( child_idx!=advance_candidate_idx ) {
      if( !fd_banks_subtree_can_be_pruned( bank_pool, child_bank ) ) {
        fd_rwlock_unread( &banks->rwlock );
        return 0;
      }
    }
    child_idx = child_bank->sibling_idx;
  }

  *advanceable_bank_idx_out = advance_candidate_idx;
  fd_rwlock_unread( &banks->rwlock );
  return 1;
}

fd_bank_t *
fd_banks_new_bank( fd_banks_t * banks,
                   ulong        parent_bank_idx,
                   long         now ) {

  fd_rwlock_write( &banks->rwlock );

  fd_bank_t * bank_pool = fd_banks_get_bank_pool( banks );
  if( FD_UNLIKELY( !bank_pool ) ) {
    FD_LOG_CRIT(( "invariant violation: failed to get bank pool" ));
  }

  if( FD_UNLIKELY( fd_banks_pool_free( bank_pool )==0UL ) ) {
    FD_LOG_CRIT(( "invariant violation: no free bank indices available" ));
  }

  ulong child_bank_idx = fd_banks_pool_idx_acquire( bank_pool );

  /* Make sure that the bank is valid. */

  fd_bank_t * child_bank = fd_banks_pool_ele( bank_pool, child_bank_idx );
  if( FD_UNLIKELY( !child_bank ) ) {
    FD_LOG_CRIT(( "Invariant violation: bank for bank index %lu does not exist", child_bank_idx ));
  }
  if( FD_UNLIKELY( child_bank->flags&FD_BANK_FLAGS_INIT ) ) {
    FD_LOG_CRIT(( "Invariant violation: bank for bank index %lu is already initialized", child_bank_idx ));
  }

  ulong null_idx = fd_banks_pool_idx_null( bank_pool );

  child_bank->bank_seq    = FD_ATOMIC_FETCH_AND_ADD( &banks->bank_seq, 1UL );
  child_bank->idx         = child_bank_idx;
  child_bank->parent_idx  = null_idx;
  child_bank->child_idx   = null_idx;
  child_bank->sibling_idx = null_idx;
  child_bank->next        = null_idx;
  child_bank->flags       = FD_BANK_FLAGS_INIT;

  /* Then make sure that the parent bank is valid and frozen. */

  fd_bank_t * parent_bank = fd_banks_pool_ele( bank_pool, parent_bank_idx );
  if( FD_UNLIKELY( !parent_bank ) ) {
    FD_LOG_CRIT(( "Invariant violation: parent bank for bank index %lu does not exist", parent_bank_idx ));
  }
  if( FD_UNLIKELY( !(parent_bank->flags&FD_BANK_FLAGS_INIT) ) ) {
    FD_LOG_CRIT(( "Invariant violation: parent bank with index %lu is uninitialized", parent_bank_idx ));
  }

  /* Link node->parent */

  child_bank->parent_idx = parent_bank_idx;

  /* Link parent->node and sibling->node */

  if( FD_LIKELY( parent_bank->child_idx==null_idx ) ) {

    /* This is the first child so set as left-most child */

    parent_bank->child_idx = child_bank_idx;

  } else {
    /* Already have children so iterate to right-most sibling. */

    fd_bank_t * curr_bank = fd_banks_pool_ele( bank_pool, parent_bank->child_idx );
    if( FD_UNLIKELY( !curr_bank ) ) {
      FD_LOG_CRIT(( "Invariant violation: child bank for bank index %lu does not exist", parent_bank->child_idx ));
    }
    while( curr_bank->sibling_idx != null_idx ) curr_bank = fd_banks_pool_ele( bank_pool, curr_bank->sibling_idx );

    /* Link to right-most sibling. */

    curr_bank->sibling_idx = child_bank_idx;
  }

  child_bank->first_fec_set_received_nanos = now;
  child_bank->first_transaction_scheduled_nanos = 0L;
  child_bank->last_transaction_finished_nanos = 0L;

  fd_rwlock_unwrite( &banks->rwlock );
  return child_bank;
}

void
fd_banks_mark_bank_dead( fd_banks_t * banks,
                         fd_bank_t *  bank ) {
  fd_rwlock_write( &banks->rwlock );

  fd_banks_subtree_mark_dead( fd_banks_get_bank_pool( banks ), bank );

  fd_rwlock_unwrite( &banks->rwlock );
}

void
fd_banks_mark_bank_frozen( fd_banks_t * banks,
                           fd_bank_t *  bank ) {
  if( FD_UNLIKELY( bank->flags&FD_BANK_FLAGS_FROZEN ) ) {
    FD_LOG_CRIT(( "invariant violation: bank for idx %lu is already frozen", bank->idx ));
  }

  fd_rwlock_write( &banks->rwlock );
  bank->flags |= FD_BANK_FLAGS_FROZEN;

  if( FD_UNLIKELY( bank->cost_tracker_pool_idx==fd_bank_cost_tracker_pool_idx_null( fd_bank_get_cost_tracker_pool( bank ) ) ) ) {
    FD_LOG_CRIT(( "invariant violation: cost tracker pool index is null" ));
  }
  fd_bank_cost_tracker_pool_idx_release( fd_bank_get_cost_tracker_pool( bank ), bank->cost_tracker_pool_idx );
  bank->cost_tracker_pool_idx = fd_bank_cost_tracker_pool_idx_null( fd_bank_get_cost_tracker_pool( bank ) );
  fd_rwlock_unwrite( &banks->rwlock );
}
