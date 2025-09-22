#include "fd_bank.h"
#include "fd_runtime_const.h"
#include "sysvar/fd_sysvar_epoch_schedule.h"

#define DEQUE_NAME bfs
#define DEQUE_T    ulong
#include "../../util/tmpl/fd_deque_dynamic.c"

static inline ulong *
fd_banks_bfs_init( fd_banks_t * banks ) {
  return bfs_join( bfs_new( (uchar *)banks + banks->bfs_offset, banks->max_total_banks ) );
}

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
    if( FD_UNLIKELY( !fd_bank_##name##_pool_free( name##_pool ) ) ) {                                              \
      FD_LOG_CRIT(( "Failed to acquire " #name " pool element: pool is full" ));                                   \
    }                                                                                                              \
    fd_bank_##name##_t * child_##name = fd_bank_##name##_pool_ele_acquire( name##_pool );                          \
    if( FD_UNLIKELY( !child_##name ) ) {                                                                           \
      FD_LOG_CRIT(( "Failed to acquire " #name " pool element" ));                                                 \
    }                                                                                                              \
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


#define HAS_LOCK_0(type, name) \
  type const *                                             \
  fd_bank_##name##_query( fd_bank_t const * bank ) {       \
    return (type const *)fd_type_pun_const( bank->name );  \
  }                                                        \
  type *                                                   \
  fd_bank_##name##_modify( fd_bank_t * bank ) {            \
    return (type *)fd_type_pun( bank->name );              \
  }

#define HAS_LOCK_1(type, name)                              \
  type const *                                              \
  fd_bank_##name##_locking_query( fd_bank_t * bank ) {      \
    fd_rwlock_read( &bank->name##_lock );                   \
    return (type const *)fd_type_pun_const( bank->name );   \
  }                                                         \
  type *                                                    \
  fd_bank_##name##_locking_modify( fd_bank_t * bank ) {     \
    fd_rwlock_write( &bank->name##_lock );                  \
    return (type *)fd_type_pun( bank->name );               \
  }                                                         \
  void                                                      \
  fd_bank_##name##_end_locking_query( fd_bank_t * bank ) {  \
    fd_rwlock_unread( &bank->name##_lock );                 \
  }                                                         \
  void                                                      \
  fd_bank_##name##_end_locking_modify( fd_bank_t * bank ) { \
    fd_rwlock_unwrite( &bank->name##_lock );                \
  }

#define HAS_COW_0(type, name, footprint, align, has_lock)   \
  HAS_LOCK_##has_lock(type, name)                           \
  void                                                      \
  fd_bank_##name##_set( fd_bank_t * bank, type value ) {    \
    FD_STORE( type, bank->name, value );                    \
  }                                                         \
  type                                                      \
  fd_bank_##name##_get( fd_bank_t const * bank ) {          \
    type val = FD_LOAD( type, bank->name );                 \
    return val;                                             \
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
                    ulong max_fork_width FD_PARAM_UNUSED ) {

  /* max_fork_width is used in the macro below. */

  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, fd_banks_align(), sizeof(fd_banks_t) );
  l = FD_LAYOUT_APPEND( l, bfs_align(),      bfs_footprint( max_total_banks ) );
  l = FD_LAYOUT_APPEND( l, fd_bank_align(),  fd_bank_footprint() * max_total_banks );

  /* Need to count the footprint for all of the CoW pools. The footprint
     on each CoW pool depends on if the field limits the fork width. */

  #define HAS_COW_1_LIMIT_1(name) \
    l = FD_LAYOUT_APPEND( l, fd_bank_##name##_pool_align(), fd_bank_##name##_pool_footprint( max_fork_width ) );

  #define HAS_COW_1_LIMIT_0(name) \
    l = FD_LAYOUT_APPEND( l, fd_bank_##name##_pool_align(), fd_bank_##name##_pool_footprint( max_total_banks ) );

  /* Do nothing for these. */
  #define HAS_COW_0_LIMIT_0(name)

  #define X(type, name, footprint, align, cow, limit_fork_width, has_lock)  \
    HAS_COW_##cow##_LIMIT_##limit_fork_width(name)
  FD_BANKS_ITER(X)
  #undef X
  #undef HAS_COW_0_LIMIT_0
  #undef HAS_COW_1_LIMIT_0
  #undef HAS_COW_1_LIMIT_1

  return FD_LAYOUT_FINI( l, fd_banks_align() );
}

void *
fd_banks_new( void * shmem,
              ulong  max_total_banks,
              ulong  max_fork_width ) {

  fd_banks_t * banks = (fd_banks_t *)shmem;

  if( FD_UNLIKELY( !banks ) ) {
    FD_LOG_WARNING(( "NULL banks" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)banks, fd_banks_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned banks" ));
    return NULL;
  }

  /* Set the rwlock to unlocked. */
  fd_rwlock_unwrite( &banks->rwlock );

  /* First, layout the banks and the pool/map used by fd_banks_t. */
  FD_SCRATCH_ALLOC_INIT( l, banks );
  banks            = FD_SCRATCH_ALLOC_APPEND( l, fd_banks_align(), sizeof(fd_banks_t) );
  void * bfs_mem   = FD_SCRATCH_ALLOC_APPEND( l, bfs_align(),      bfs_footprint( max_total_banks ) );
  void * array_mem = FD_SCRATCH_ALLOC_APPEND( l, fd_bank_align(),  fd_bank_footprint() * max_total_banks );

  /* Need to layout all of the CoW pools. */
  #define HAS_COW_1_LIMIT_1(name) \
    void * name##_pool_mem = FD_SCRATCH_ALLOC_APPEND( l, fd_bank_##name##_pool_align(), fd_bank_##name##_pool_footprint( max_fork_width ) );

  #define HAS_COW_1_LIMIT_0(name) \
    void * name##_pool_mem = FD_SCRATCH_ALLOC_APPEND( l, fd_bank_##name##_pool_align(), fd_bank_##name##_pool_footprint( max_total_banks ) );

  /* Do nothing for these. */
  #define HAS_COW_0_LIMIT_0(name)

  #define X(type, name, footprint, align, cow, limit_fork_width, has_lock) \
    HAS_COW_##cow##_LIMIT_##limit_fork_width(name)
  FD_BANKS_ITER(X)
  #undef X
  #undef HAS_COW_0_LIMIT_0
  #undef HAS_COW_1_LIMIT_0
  #undef HAS_COW_1_LIMIT_1

  if( FD_UNLIKELY( FD_SCRATCH_ALLOC_FINI( l, fd_banks_align() ) != (ulong)banks + fd_banks_footprint( max_total_banks, max_fork_width ) ) ) {
    FD_LOG_WARNING(( "fd_banks_new: bad layout" ));
    return NULL;
  }

  /* Mark all banks as invalid and assign their fork indicies */
  fd_bank_t * bank_array = fd_type_pun( array_mem );
  for( ulong i=0UL; i<max_total_banks; i++ ) {
    fd_bank_t * bank = bank_array + i;
    bank->is_valid = 0;
    bank->fork_idx = i;
  }
  banks->bank_array_offset = (ulong)array_mem - (ulong)banks;

  banks->bfs_offset = (ulong)bfs_mem - (ulong)banks;
  if( FD_UNLIKELY( !fd_banks_bfs_init( banks ) ) ) {
    FD_LOG_WARNING(( "Failed to initialize BFS" ));
    return NULL;
  }

  /* Now, call _new() and _join() for all of the CoW pools. */
  #define HAS_COW_1_LIMIT_1(name)                                                     \
    void * name##_mem = fd_bank_##name##_pool_new( name##_pool_mem, max_fork_width ); \
    if( FD_UNLIKELY( !name##_mem ) ) {                                                \
      FD_LOG_WARNING(( "Failed to create " #name " pool" ));                          \
      return NULL;                                                                    \
    }                                                                                 \
    fd_bank_##name##_t * name##_pool = fd_bank_##name##_pool_join( name##_pool_mem ); \
    if( FD_UNLIKELY( !name##_pool ) ) {                                               \
      FD_LOG_WARNING(( "Failed to join " #name " pool" ));                            \
      return NULL;                                                                    \
    }                                                                                 \
    fd_banks_set_##name##_pool( banks, name##_pool );

  #define HAS_COW_1_LIMIT_0(name)                                                      \
    void * name##_mem = fd_bank_##name##_pool_new( name##_pool_mem, max_total_banks ); \
    if( FD_UNLIKELY( !name##_mem ) ) {                                                 \
      FD_LOG_WARNING(( "Failed to create " #name " pool" ));                           \
      return NULL;                                                                     \
    }                                                                                  \
    fd_bank_##name##_t * name##_pool = fd_bank_##name##_pool_join( name##_pool_mem );  \
    if( FD_UNLIKELY( !name##_pool ) ) {                                                \
      FD_LOG_WARNING(( "Failed to join " #name " pool" ));                             \
      return NULL;                                                                     \
    }                                                                                  \
    fd_banks_set_##name##_pool( banks, name##_pool );

  /* Do nothing for these. */
  #define HAS_COW_0_LIMIT_0(name)

  #define X(type, name, footprint, align, cow, limit_fork_width, has_lock) \
    HAS_COW_##cow##_LIMIT_##limit_fork_width(name)
  FD_BANKS_ITER(X)
  #undef X
  #undef HAS_COW_0_LIMIT_0
  #undef HAS_COW_1_LIMIT_1
  #undef HAS_COW_1_LIMIT_0

  banks->max_total_banks = max_total_banks;
  banks->max_fork_width  = max_fork_width;
  banks->root_idx        = ULONG_MAX;

  if( FD_UNLIKELY( !fd_stake_delegations_new( banks->stake_delegations_root, FD_RUNTIME_MAX_STAKE_ACCOUNTS, 0 ) ) ) {
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
  banks            = FD_SCRATCH_ALLOC_APPEND( l, fd_banks_align(), sizeof(fd_banks_t) );
  void * bfs_mem   = FD_SCRATCH_ALLOC_APPEND( l, bfs_align(),      bfs_footprint( banks->max_total_banks ) );
  void * array_mem = FD_SCRATCH_ALLOC_APPEND( l, fd_bank_align(),  fd_bank_footprint() * banks->max_total_banks );


  /* Need to layout all of the CoW pools. */
  #define HAS_COW_1_LIMIT_1(name) \
    void * name##_pool_mem = FD_SCRATCH_ALLOC_APPEND( l, fd_bank_##name##_pool_align(), fd_bank_##name##_pool_footprint( banks->max_fork_width ) );

  #define HAS_COW_1_LIMIT_0(name) \
    void * name##_pool_mem = FD_SCRATCH_ALLOC_APPEND( l, fd_bank_##name##_pool_align(), fd_bank_##name##_pool_footprint( banks->max_total_banks ) );

  /* Don't need to layout if not CoW. */
  #define HAS_COW_0_LIMIT_0(name)

  #define X(type, name, footprint, align, cow, limit_fork_width, has_lock) \
    HAS_COW_##cow##_LIMIT_##limit_fork_width(name)
  FD_BANKS_ITER(X)
  #undef X
  #undef HAS_COW_0_LIMIT_0
  #undef HAS_COW_1_LIMIT_0
  #undef HAS_COW_1_LIMIT_1

  FD_SCRATCH_ALLOC_FINI( l, fd_banks_align() );

  if( FD_UNLIKELY( banks->bfs_offset != (ulong)bfs_mem - (ulong)banks ) ) {
    FD_LOG_WARNING(( "bfs offset mismatch" ));
    return NULL;
  }

  if( FD_UNLIKELY( banks->bank_array_offset != (ulong)array_mem - (ulong)banks ) ) {
    FD_LOG_WARNING(( "bank array offset mismatch" ));
    return NULL;
  }

  /* Now, call _join() for all of the CoW pools. */
  #define HAS_COW_1(name)                                                             \
    fd_bank_##name##_t * name##_pool = fd_banks_get_##name##_pool( banks );           \
    if( FD_UNLIKELY( !name##_pool ) ) {                                               \
      FD_LOG_WARNING(( "Failed to join " #name " pool" ));                            \
      return NULL;                                                                    \
    }                                                                                 \
    if( FD_UNLIKELY( name##_pool!=fd_bank_##name##_pool_join( name##_pool_mem ) ) ) { \
      FD_LOG_WARNING(( "Failed to join " #name " pool" ));                            \
      return NULL;                                                                    \
    }

  /* Do nothing when the field is not CoW. */
  #define HAS_COW_0(name)

  #define X(type, name, footprint, align, cow, limit_fork_width, has_lock) \
    HAS_COW_##cow(name)
  FD_BANKS_ITER(X)
  #undef X
  #undef HAS_COW_0
  #undef HAS_COW_1


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
fd_banks_init_bank( fd_banks_t * banks,
                    ulong        fork_idx ) {

  if( FD_UNLIKELY( !banks ) ) {
    FD_LOG_CRIT(( "NULL banks" ));
  }

  fd_rwlock_write( &banks->rwlock );

  fd_bank_t * bank = fd_banks_bank_mem_query( banks, fork_idx );
  if( FD_UNLIKELY( bank->is_valid==1 ) ) {
    FD_LOG_CRIT(( "bank for fork idx %lu at slot %lu already exists", fork_idx, fd_bank_slot_get( bank ) ));
  }

  memset( bank, 0, fd_bank_footprint() );
  bank->parent_idx  = ULONG_MAX;
  bank->child_idx   = ULONG_MAX;
  bank->sibling_idx = ULONG_MAX;
  bank->is_valid    = 1;

  /* Set all CoW fields to null. */
  #define HAS_COW_1(name)                                                             \
    fd_bank_##name##_t * name##_pool = fd_banks_get_##name##_pool( banks );           \
    fd_bank_set_##name##_pool( bank, name##_pool );                                   \
    bank->name##_pool_idx            = fd_bank_##name##_pool_idx_null( name##_pool ); \
    bank->name##_dirty               = 0;

  /* Do nothing for these. */
  #define HAS_COW_0(name)

  #define HAS_LOCK_1(name) \
    fd_rwlock_unwrite(&bank->name##_lock);
  #define HAS_LOCK_0(name)

  #define X(type, name, footprint, align, cow, limit_fork_width, has_lock) \
    HAS_COW_##cow(name);                                                   \
    HAS_LOCK_##has_lock(name)
  FD_BANKS_ITER(X)
  #undef X
  #undef HAS_COW_0
  #undef HAS_COW_1
  #undef HAS_LOCK_0
  #undef HAS_LOCK_1

  bank->flags  = FD_BANK_FLAGS_INIT;
  bank->refcnt = 0UL;

  /* Now that the node is inserted, update the root */

  banks->root_idx = fork_idx;

  fd_rwlock_unwrite( &banks->rwlock );
  return bank;
}

fd_bank_t *
fd_banks_clone_from_parent( fd_banks_t * banks,
                            ulong        fork_idx,
                            ulong        parent_fork_idx ) {

  fd_rwlock_write( &banks->rwlock );

  /* See if we already recovered the bank. */

  fd_bank_t * new_bank = fd_banks_bank_mem_query( banks, fork_idx );
  if( FD_UNLIKELY( new_bank->is_valid==1 ) ) {
    FD_LOG_CRIT(( "bank for fork idx %lu at slot %lu already exists", fork_idx, fd_bank_slot_get( new_bank ) ));
  }

  /* First query for the parent bank. */

  fd_bank_t * parent_bank = fd_banks_bank_query( banks, parent_fork_idx );
  if( FD_UNLIKELY( !parent_bank ) ) {
    FD_LOG_CRIT(( "parent bank for fork idx %lu is not valid", parent_fork_idx ));
  }

  /* Link the parent of the current bank. */

  new_bank->parent_idx    = parent_fork_idx;
  new_bank->child_idx     = ULONG_MAX;
  new_bank->sibling_idx   = ULONG_MAX;
  new_bank->is_valid      = 1;

  /* Link parent->node and sibling->node */

  if( FD_LIKELY( parent_bank->child_idx==ULONG_MAX ) ) {

    /* This is the first child so set as left-most child */

    parent_bank->child_idx = fork_idx;

  } else {

    /* Already have children so iterate to right-most sibling. */

    fd_bank_t * curr_bank = fd_banks_bank_query( banks, parent_bank->child_idx );
    if( FD_UNLIKELY( !curr_bank ) ) {
      FD_LOG_CRIT(( "child bank for fork idx %lu is not valid", parent_bank->child_idx ));
    }
    while( curr_bank->sibling_idx!=ULONG_MAX ) curr_bank = fd_banks_bank_query( banks, curr_bank->sibling_idx );

    /* Link to right-most sibling. */

    curr_bank->sibling_idx = fork_idx;

  }

  /* We want to copy over the fields from the parent to the child,
     except for the fields which correspond to the header of the bank
     struct which is used for pool and map management. We can take
     advantage of the fact that those fields are laid out at the top
     of the bank struct.

     TODO: We don't need to copy over the stake delegations delta. */

  memcpy( (uchar *)new_bank + FD_BANK_HEADER_SIZE, (uchar *)parent_bank + FD_BANK_HEADER_SIZE, sizeof(fd_bank_t) - FD_BANK_HEADER_SIZE );

  /* Setup all of the CoW fields. */
  #define HAS_COW_1(name)                                                   \
    new_bank->name##_pool_idx        = parent_bank->name##_pool_idx;        \
    new_bank->name##_dirty           = 0UL;                                 \
    fd_bank_##name##_t * name##_pool = fd_banks_get_##name##_pool( banks ); \
    fd_bank_set_##name##_pool( new_bank, name##_pool );

  /* Do nothing if not CoW. */
  #define HAS_COW_0(name)

  /* Setup locks for new bank as free. */
  #define HAS_LOCK_1(name) \
    fd_rwlock_unwrite(&new_bank->name##_lock);
  #define HAS_LOCK_0(name)

  #define X(type, name, footprint, align, cow, limit_fork_width, has_lock) \
    HAS_COW_##cow(name);                                                   \
    HAS_LOCK_##has_lock(name)
  FD_BANKS_ITER(X)
  #undef X
  #undef HAS_COW_0
  #undef HAS_COW_1
  #undef HAS_LOCK_0
  #undef HAS_LOCK_1

  new_bank->flags = FD_BANK_FLAGS_INIT;
  /* If the parent bank is dead, then we also need to mark the child
     bank as being a dead block. */
  if( FD_UNLIKELY( parent_bank->flags & FD_BANK_FLAGS_DEAD ) ) {
    new_bank->flags |= FD_BANK_FLAGS_DEAD;
  }

  new_bank->refcnt = 0UL;

  /* Delta field does not need to be copied over. The dirty flag just
     needs to be cleared if it was set. */
  new_bank->stake_delegations_delta_dirty = 0;
  fd_rwlock_unwrite( &new_bank->stake_delegations_delta_lock );

  fd_rwlock_unwrite( &banks->rwlock );

  return new_bank;
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

  /* We want to do is iterate from the old root to the new root and
     apply the delta to the full state iteratively. */

  /* First, gather all of the pool indicies that we want to apply deltas
     for in reverse order starting from the new root.  We want to
     exclude the old root since its delta has been applied
     previously. */

  ulong pool_indicies[ banks->max_total_banks ];
  ulong pool_indicies_len = 0UL;

  ulong curr_idx = bank->fork_idx;
  while( curr_idx!=ULONG_MAX ) {
    pool_indicies[ pool_indicies_len++ ] = curr_idx;
    fd_bank_t * curr_bank = fd_banks_bank_query( banks, curr_idx );
    curr_idx = curr_bank->parent_idx;
  }

  /* We have populated all of the indicies that we need to apply deltas
     from in reverse order. */

  for( ulong i=pool_indicies_len; i>0UL; i-- ) {
    ulong idx = pool_indicies[ i-1UL ];
    fd_banks_stake_delegations_apply_delta( fd_banks_bank_query( banks, idx ), stake_delegations );
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
                       ulong        root_fork_idx ) {

  fd_rwlock_write( &banks->rwlock );

  /* We want to replace the old root with the new root. This means we
     have to remove banks that aren't descendants of the new root. */

  fd_bank_t const * old_root = fd_banks_bank_query( banks, banks->root_idx );
  if( FD_UNLIKELY( !old_root ) ) {
    FD_LOG_CRIT(( "old root bank for fork idx %lu is not valid", banks->root_idx ));
  }

  if( FD_UNLIKELY( old_root->refcnt!=0UL ) ) {
    FD_LOG_CRIT(( "refcnt for old root bank is %lu", old_root->refcnt ));
  }

  fd_bank_t * new_root = fd_banks_bank_query( banks, root_fork_idx );
  if( FD_UNLIKELY( !new_root ) ) {
    FD_LOG_CRIT(( "new root bank for fork idx %lu is not valid", root_fork_idx ));
  }

  fd_stake_delegations_t * stake_delegations = fd_stake_delegations_join( banks->stake_delegations_root );
  fd_bank_stake_delegation_apply_deltas( banks, new_root, stake_delegations );
  new_root->stake_delegations_delta_dirty = 0;

  /* Now that the deltas have been applied, we can iterate through the
     left-child, right-sibling tree iteratively and mark all nodes that
     are not direct descendants of the new root as dead and free any
     associated pool elements. */

  ulong * frontier_set = fd_banks_bfs_init( banks );
  bfs_push_head( frontier_set, old_root->fork_idx );

  while( !bfs_empty( frontier_set ) ) {
    ulong       curr_idx  = bfs_pop_tail( frontier_set );
    fd_bank_t * curr_bank = fd_banks_bank_query( banks, curr_idx );
    if( FD_UNLIKELY( !curr_bank ) ) {
      FD_LOG_CRIT(( "invariant violation: bank at fork idx %lu is not valid", curr_idx ));
    }

    if( FD_UNLIKELY( curr_idx==root_fork_idx ) ) {
      /* Only add sibling to the frontier set, and don't mark new root
         as invalid. */
      if( curr_bank->sibling_idx!=ULONG_MAX ) {
        bfs_push_head( frontier_set, curr_bank->sibling_idx );
        curr_bank->sibling_idx = ULONG_MAX;
      }
    } else {
      /* Mark bank as invalid. */
      curr_bank->is_valid = 0;
      if( curr_bank->child_idx!=ULONG_MAX )   bfs_push_head( frontier_set, curr_bank->child_idx );
      if( curr_bank->sibling_idx!=ULONG_MAX ) bfs_push_head( frontier_set, curr_bank->sibling_idx );

      /* Decide if we need to free any CoW fields. We free a CoW member
        from its pool if the dirty flag is set unless it is the same
        pool that the new root uses. */
      #define HAS_COW_1(name)                                                         \
      if( curr_bank->name##_dirty && curr_bank->name##_pool_idx!=new_root->name##_pool_idx ) {  \
        fd_bank_##name##_t * name##_pool = fd_banks_get_##name##_pool( banks );       \
        fd_bank_##name##_pool_idx_release( name##_pool, curr_bank->name##_pool_idx ); \
      }
      /* Do nothing for these. */
      #define HAS_COW_0(name)

      #define X(type, name, footprint, align, cow, limit_fork_width, has_lock) \
        HAS_COW_##cow(name)
      FD_BANKS_ITER(X)
      #undef X
      #undef HAS_COW_0
      #undef HAS_COW_1
    }
  }

  /* Update the root index for banks and mark the new root as having no
     parent bank. */
  banks->root_idx      = root_fork_idx;
  new_root->parent_idx = ULONG_MAX;

  fd_rwlock_unwrite( &banks->rwlock );

  return new_root;
}

void
fd_banks_clear_bank( fd_banks_t * banks, fd_bank_t * bank ) {

  fd_rwlock_read( &banks->rwlock );
  /* Get the parent bank. */
  fd_bank_t * parent_bank = fd_banks_bank_query( banks, bank->parent_idx );

  #define HAS_COW_1(type, name, footprint)                                                                                  \
    fd_bank_##name##_t * name##_pool = fd_bank_get_##name##_pool( bank );                                                   \
    if( bank->name##_dirty ) {                                                                                              \
      /* If the dirty flag is set, then we have a pool allocated for */                                                     \
      /* this specific bank. We need to release the pool index and   */                                                     \
      /* assign the bank to the idx corresponding to the parent.     */                                                     \
      fd_bank_##name##_pool_idx_release( name##_pool, bank->name##_pool_idx );                                              \
      bank->name##_dirty    = 0;                                                                                            \
      bank->name##_pool_idx = parent_bank ? parent_bank->name##_pool_idx : fd_bank_##name##_pool_idx_null( name##_pool );   \
    }

  #define HAS_COW_0(type, name, footprint) \
    fd_memset( bank->name, 0, footprint );

  #define X(type, name, footprint, align, cow, limit_fork_width, has_lock) \
    HAS_COW_##cow(type, name, footprint)
  FD_BANKS_ITER(X)
  #undef X
  #undef HAS_COW_0
  #undef HAS_COW_1

  fd_rwlock_unread( &banks->rwlock );
}

/* Is the fork tree starting at the given bank entirely eligible for
   pruning?  Returns 1 for yes, 0 for no.

   See comment in fd_replay_tile.c for more details on safe pruning. */
static int
fd_banks_subtree_can_be_pruned( fd_banks_t * banks, fd_bank_t * bank ) {
  if( FD_UNLIKELY( !bank ) ) {
    FD_LOG_CRIT(( "invariant violation: bank is NULL" ));
  }

  if( bank->refcnt!=0UL ) {
    return 0;
  }

  /* Recursively check all children. */
  ulong child_idx = bank->child_idx;
  while( child_idx!=ULONG_MAX ) {
    fd_bank_t * child = fd_banks_bank_query( banks, child_idx );
    if( FD_UNLIKELY( !child ) ) {
      FD_LOG_CRIT(( "invariant violation: child bank is NULL" ));
    }
    if( !fd_banks_subtree_can_be_pruned( banks, child ) ) {
      return 0;
    }
    child_idx = child->sibling_idx;
  }

  return 1;
}

/* Mark everything in the fork tree starting at the given bank dead. */

static void
fd_banks_subtree_mark_dead( fd_banks_t * banks, fd_bank_t * bank ) {
  if( FD_UNLIKELY( !bank ) ) {
    FD_LOG_CRIT(( "invariant violation: bank is NULL" ));
  }
  if( FD_UNLIKELY( bank->flags & FD_BANK_FLAGS_ROOTED ) ) {
    FD_LOG_CRIT(( "invariant violation: bank is rooted" ));
  }

  bank->flags |= FD_BANK_FLAGS_DEAD;

  /* Recursively mark all children as dead. */
  ulong child_idx = bank->child_idx;
  while( child_idx!=ULONG_MAX ) {
    fd_bank_t * child = fd_banks_bank_query( banks, child_idx );
    if( FD_UNLIKELY( !child ) ) {
      FD_LOG_CRIT(( "invariant violation: child bank is NULL" ));
    }
    fd_banks_subtree_mark_dead( banks, child );
    child_idx = child->sibling_idx;
  }
}

int
fd_banks_publish_prepare( fd_banks_t * banks,
                          ulong        target_fork_idx,
                          ulong *      publishable_fork_idx_out ) {
  /* TODO: An optimization here is to do a single traversal of the tree
     that would mark minority forks as dead while accumulating
     refcnts to determine which bank is the highest publishable. */

  if( FD_UNLIKELY( !banks ) ) {
    FD_LOG_CRIT(( "invariant violation: banks is NULL" ));
  }

  if( FD_UNLIKELY( !publishable_fork_idx_out ) ) {
    FD_LOG_CRIT(( "invariant violation: publishable_fork_idx_out is NULL" ));
  }

  fd_rwlock_read( &banks->rwlock );

  if( FD_UNLIKELY( target_fork_idx==banks->root_idx ) ) {
    FD_LOG_WARNING(( "target fork idx is the same as the old root" ));
    fd_rwlock_unread( &banks->rwlock );
    return 0;
  }

  fd_bank_t * root = fd_banks_bank_query( banks, banks->root_idx );
  if( FD_UNLIKELY( !root ) ) {
    FD_LOG_CRIT(( "failed to get root bank" ));
  }

  fd_bank_t * target_bank = fd_banks_bank_query( banks, target_fork_idx );
  if( FD_UNLIKELY( !target_bank ) ) {
    FD_LOG_CRIT(( "target fork idx is not valid" ));
  }

  /* Mark every node from the target bank up through its parents to the
     root as being rooted. */
  fd_bank_t * curr = target_bank;
  fd_bank_t * prev = NULL;
  while( curr ) {
    curr->flags |= FD_BANK_FLAGS_ROOTED;
    prev         = curr;
    curr         = fd_banks_bank_query( banks, curr->parent_idx );
  }

  /* If we didn't reach the old root, target is not a descendant. */
  if( FD_UNLIKELY( prev!=root ) ) {
    FD_LOG_CRIT(( "target fork idx is not a descendant of root" ));
  }

  /* We know that the majority fork that is not getting pruned off is
     the child of the target bank.  All other child/sibling nodes off of
     the other nodes that were just marked as root are minority forks
     which should be pruned off. */

  /* Now traverse from root towards target and find the highest
     block that can be pruned. */
  fd_bank_t *  highest_publishable_bank  = NULL;
  fd_bank_t *  publishable_bank          = NULL;
  fd_bank_t *  prune_candidate           = root;
  int          found_publishable_block   = 0;
  while( prune_candidate && prune_candidate->flags & FD_BANK_FLAGS_ROOTED ) {
    fd_bank_t * rooted_child_bank = NULL;

    if( prune_candidate->refcnt!=0UL ) {
      break;
    }

    /* For this node to be pruned, all minority forks that branch off
       from it must be entirely eligible for pruning.  A fork is
       eligible for pruning if there are no outstanding references to
       any of the nodes on the fork.  This means checking all children
       (except for the one on the rooted fork) and their entire
       subtrees. */
    int all_minority_forks_can_be_pruned = 1;
    ulong child_idx = prune_candidate->child_idx;
    while( child_idx!=ULONG_MAX ) {
      fd_bank_t * sibling = fd_banks_bank_query( banks, child_idx );
      if( sibling->flags & FD_BANK_FLAGS_ROOTED ) {
        rooted_child_bank = sibling;
      } else if( sibling->parent_idx!=target_fork_idx ) {
        /* This is a minority fork. */
        if( !fd_banks_subtree_can_be_pruned( banks, sibling ) ) {
          all_minority_forks_can_be_pruned = 0;
          break;
        }
      }
      child_idx = sibling->sibling_idx;
    }

    if( !all_minority_forks_can_be_pruned ) {
      break;
    }

    highest_publishable_bank  = prune_candidate;
    publishable_bank          = prune_candidate;
    prune_candidate           = rooted_child_bank;
    found_publishable_block   = 1;
  }

  int advanced_publishable_block = 0;
  if( FD_LIKELY( found_publishable_block ) ) {
    /* Find the rooted child of the highest block that can be pruned.
       That's where we can publish to. */
    fd_bank_t * rooted_child_bank = NULL;
    ulong child_idx = publishable_bank->child_idx;
    while( child_idx!=ULONG_MAX ) {
      fd_bank_t * sibling = fd_banks_bank_query( banks, child_idx );
      if( sibling->flags & FD_BANK_FLAGS_ROOTED ) {
        rooted_child_bank = sibling;
        break;
      }
      child_idx = sibling->sibling_idx;
    }
    if( FD_LIKELY( rooted_child_bank ) ) {
      highest_publishable_bank = rooted_child_bank;
    }

    /* Write output. */
    *publishable_fork_idx_out = highest_publishable_bank->fork_idx;

   if( FD_LIKELY( highest_publishable_bank->fork_idx!=root->fork_idx ) ) {
     advanced_publishable_block = 1;
   }

  }

  /* At this point the highest publishable bank has been identified. */

  /* Now mark all minority forks as being dead.  This involves
     traversing the tree down from the old root through its descendants
     that are marked as rooted.  Any child/sibling nodes of these rooted
     nodes are minority forks which should be marked as dead. */

  curr = root;
  while( curr && curr->flags & FD_BANK_FLAGS_ROOTED ) {
    fd_bank_t * rooted_child_bank = NULL;
    ulong       child_idx         = curr->child_idx;
    while( child_idx!=ULONG_MAX ) {
      fd_bank_t * sibling = fd_banks_bank_query( banks, child_idx );
      if( sibling->flags & FD_BANK_FLAGS_ROOTED ) {
        rooted_child_bank = sibling;
      } else if( sibling->parent_idx!=target_fork_idx ) {
        /* This is a minority fork.  Every node in the subtree should
           be marked as dead.  We know that it is a minority fork
           this node is not a child of the new target root. */
        fd_banks_subtree_mark_dead( banks, sibling );
      }
      child_idx = sibling->sibling_idx;
    }
    curr = rooted_child_bank;
  }

  fd_rwlock_unread( &banks->rwlock );
  return advanced_publishable_block;
}

void
fd_banks_mark_bank_dead( fd_banks_t * banks,
                         fd_bank_t *  bank ) {
  fd_rwlock_write( &banks->rwlock );

  fd_banks_subtree_mark_dead( banks, bank );

  fd_rwlock_unwrite( &banks->rwlock );
}

int
fd_banks_validate( fd_banks_t * banks ) {
  fd_rwlock_read( &banks->rwlock );

  /* First check that the number of elements acquired by the CoW pools
     is not greater than the number of elements in the bank pool. */
  #define HAS_COW_1(type, name, footprint)                                                                                                                                                      \
  fd_bank_##name##_t * name##_pool = fd_bank_get_##name##_pool( bank );                                                                                                                         \
  if( fd_bank_##name##_pool_used( name##_pool ) > fd_bank_pool_used( bank_pool ) ) {                                                                                                            \
    FD_LOG_WARNING(( "Invariant violation: %s pool has more elements acquired than the bank pool %lu %lu", #name, fd_bank_##name##_pool_used( name##_pool ), fd_bank_pool_used( bank_pool ) )); \
    fd_rwlock_unread( &banks->rwlock );                                                                                                                                                         \
    return 1;                                                                                                                                                                                   \
  }                                                                                                                                                                                             \

  #define HAS_COW_0(type, name, footprint)

  #define X(type, name, footprint, align, cow, limit_fork_width, has_lock) \
    HAS_COW_##cow(type, name, footprint)                                   \
  FD_BANKS_ITER(X)
  #undef X
  #undef HAS_COW_0
  #undef HAS_COW_1
  fd_rwlock_unread( &banks->rwlock );

  return 0;
}
