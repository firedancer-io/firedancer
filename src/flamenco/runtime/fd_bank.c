#include "fd_bank.h"
#include "sysvar/fd_sysvar_epoch_schedule.h"

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
fd_banks_footprint( ulong max_total_banks, ulong FD_PARAM_UNUSED max_fork_width ) {

  /* max_fork_width is used in the macro below. */

  ulong map_chain_cnt = fd_ulong_pow2_up( max_total_banks );

  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, fd_banks_align(),      sizeof(fd_banks_t) );
  l = FD_LAYOUT_APPEND( l, fd_banks_pool_align(), fd_banks_pool_footprint( max_total_banks ) );
  l = FD_LAYOUT_APPEND( l, fd_banks_map_align(),  fd_banks_map_footprint( map_chain_cnt ) );

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
fd_banks_new( void * shmem, ulong max_total_banks, ulong max_fork_width ) {

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

  ulong map_chain_cnt = fd_ulong_pow2_up( max_total_banks );

  /* First, layout the banks and the pool/map used by fd_banks_t. */
  FD_SCRATCH_ALLOC_INIT( l, banks );
  banks           = FD_SCRATCH_ALLOC_APPEND( l, fd_banks_align(),      sizeof(fd_banks_t) );
  void * pool_mem = FD_SCRATCH_ALLOC_APPEND( l, fd_banks_pool_align(), fd_banks_pool_footprint( max_total_banks ) );
  void * map_mem  = FD_SCRATCH_ALLOC_APPEND( l, fd_banks_map_align(),  fd_banks_map_footprint( map_chain_cnt ) );

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

  fd_banks_set_bank_pool( banks, bank_pool );

  void * map = fd_banks_map_new( map_mem, map_chain_cnt, 999UL );
  if( FD_UNLIKELY( !map ) ) {
    FD_LOG_WARNING(( "Failed to create bank map" ));
    return NULL;
  }

  fd_banks_map_t * bank_map = fd_banks_map_join( map_mem );
  if( FD_UNLIKELY( !bank_map ) ) {
    FD_LOG_WARNING(( "Failed to join bank map" ));
    return NULL;
  }

  fd_banks_set_bank_map( banks, bank_map );

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
  banks->magic           = FD_BANKS_MAGIC;

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

  ulong map_chain_cnt = fd_ulong_pow2_up( banks->max_total_banks );

  FD_SCRATCH_ALLOC_INIT( l, banks );
  banks           = FD_SCRATCH_ALLOC_APPEND( l, fd_banks_align(),      sizeof(fd_banks_t) );
  void * pool_mem = FD_SCRATCH_ALLOC_APPEND( l, fd_banks_pool_align(), fd_banks_pool_footprint( banks->max_total_banks ) );
  void * map_mem  = FD_SCRATCH_ALLOC_APPEND( l, fd_banks_map_align(),  fd_banks_map_footprint( map_chain_cnt ) );

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

  fd_bank_t * banks_pool = fd_banks_get_bank_pool( banks );
  if( FD_UNLIKELY( !banks_pool ) ) {
    FD_LOG_WARNING(( "Failed to join bank pool" ));
    return NULL;
  }

  if( FD_UNLIKELY( banks_pool!=fd_banks_pool_join( pool_mem ) ) ) {
    FD_LOG_WARNING(( "Failed to join bank pool" ));
    return NULL;
  }

  fd_banks_map_t * bank_map = fd_banks_get_bank_map( banks );
  if( FD_UNLIKELY( !bank_map ) ) {
    FD_LOG_WARNING(( "Failed to join bank map" ));
    return NULL;
  }

  if( FD_UNLIKELY( bank_map!=fd_banks_map_join( map_mem ) ) ) {
    FD_LOG_WARNING(( "Failed to join bank map" ));
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
fd_banks_init_bank( fd_banks_t * banks, ulong slot ) {

  if( FD_UNLIKELY( !banks ) ) {
    FD_LOG_WARNING(( "NULL banks" ));
    return NULL;
  }

  fd_bank_t *      bank_pool = fd_banks_get_bank_pool( banks );
  fd_banks_map_t * bank_map  = fd_banks_get_bank_map( banks );

  fd_bank_t * bank = fd_banks_pool_ele_acquire( bank_pool );
  if( FD_UNLIKELY( bank==NULL ) ) {
    FD_LOG_WARNING(( "Failed to acquire bank" ));
    return NULL;
  }

  memset( bank, 0, fd_bank_footprint() );

  ulong null_idx = fd_banks_pool_idx_null( bank_pool );
  bank->slot_       = slot;
  bank->next        = null_idx;
  bank->parent_idx  = null_idx;
  bank->child_idx   = null_idx;
  bank->sibling_idx = null_idx;

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
    HAS_COW_##cow(name);                                 \
    HAS_LOCK_##has_lock(name)
  FD_BANKS_ITER(X)
  #undef X
  #undef HAS_COW_0
  #undef HAS_COW_1
  #undef HAS_LOCK_0
  #undef HAS_LOCK_1

  fd_banks_map_ele_insert( bank_map, bank, bank_pool );

  /* Now that the node is inserted, update the root */

  banks->root     = slot;
  banks->root_idx = fd_banks_pool_idx( bank_pool, bank );

  return bank;
}

fd_bank_t *
fd_banks_get_bank( fd_banks_t * banks, ulong slot ) {

  fd_bank_t *      bank_pool = fd_banks_get_bank_pool( banks );
  fd_banks_map_t * bank_map  = fd_banks_get_bank_map( banks );

  ulong idx = fd_banks_map_idx_query_const( bank_map, &slot, ULONG_MAX, bank_pool );
  if( FD_UNLIKELY( idx==ULONG_MAX ) ) {
    FD_LOG_WARNING(( "Failed to get bank idx for slot %lu", slot ));
    return NULL;
  }

  fd_bank_t * bank = fd_banks_pool_ele( bank_pool, idx );
  if( FD_UNLIKELY( !bank ) ) {
    FD_LOG_WARNING(( "Failed to get bank for slot %lu", slot ));
    return NULL;
  }

  return bank;
}


fd_bank_t *
fd_banks_clone_from_parent( fd_banks_t * banks,
                            ulong        slot,
                            ulong        parent_slot ) {

  fd_rwlock_write( &banks->rwlock );

  fd_bank_t *      bank_pool = fd_banks_get_bank_pool( banks );
  fd_banks_map_t * bank_map  = fd_banks_get_bank_map( banks );

  /* See if we already recovered the bank */

  fd_bank_t * old_bank = fd_banks_map_ele_query( bank_map, &slot, NULL, bank_pool );
  if( FD_UNLIKELY( !!old_bank ) ) {
    FD_LOG_CRIT(( "Invariant violation: bank for slot %lu already exists", slot ));
  }

  /* First query for the parent bank */

  fd_bank_t * parent_bank = fd_banks_map_ele_query( bank_map, &parent_slot, NULL, bank_pool );

  if( FD_UNLIKELY( !parent_bank ) ) {
    FD_LOG_WARNING(( "Failed to get bank for parent slot %lu", parent_slot ));
    fd_rwlock_unwrite( &banks->rwlock );
    return NULL;
  }

  if( FD_UNLIKELY( fd_bank_slot_get( parent_bank ) != parent_slot ) ) {
    FD_LOG_WARNING(( "Parent slot mismatch" ));
    fd_rwlock_unwrite( &banks->rwlock );
    return NULL;
  }

  ulong parent_idx = fd_banks_pool_idx( bank_pool, parent_bank );

  /* Now acquire a new bank */

  FD_LOG_NOTICE(( "slot: %lu, fd_banks_pool_max: %lu, fd_banks_pool_free: %lu", slot, fd_banks_pool_max( bank_pool ), fd_banks_pool_free( bank_pool ) ));

  if( FD_UNLIKELY( !fd_banks_pool_free( bank_pool ) ) ) {
    FD_LOG_WARNING(( "No free banks" ));
    fd_rwlock_unwrite( &banks->rwlock );
    return NULL;
  }

  fd_bank_t * new_bank = fd_banks_pool_ele_acquire( bank_pool );
  if( FD_UNLIKELY( !new_bank ) ) {
    FD_LOG_WARNING(( "Failed to acquire bank" ));
    fd_rwlock_unwrite( &banks->rwlock );
    return NULL;
  }

  ulong null_idx = fd_banks_pool_idx_null( bank_pool );

  new_bank->slot_       = slot;
  new_bank->next        = null_idx;
  new_bank->parent_idx  = null_idx;
  new_bank->child_idx   = null_idx;
  new_bank->sibling_idx = null_idx;

  fd_banks_map_ele_insert( bank_map, new_bank, bank_pool );

  ulong child_idx = fd_banks_pool_idx( bank_pool, new_bank );

  /* Link node->parent */

  new_bank->parent_idx = parent_idx;

  /* Link parent->node and sibling->node */

  if( FD_LIKELY( parent_bank->child_idx == null_idx ) ) {

    /* This is the first child so set as left-most child */

    parent_bank->child_idx = child_idx;

  } else {

    /* Already have children so iterate to right-most sibling. */

    fd_bank_t * curr_bank = fd_banks_pool_ele( bank_pool, parent_bank->child_idx );
    while( curr_bank->sibling_idx != null_idx ) curr_bank = fd_banks_pool_ele( bank_pool, curr_bank->sibling_idx );

    /* Link to right-most sibling. */

    curr_bank->sibling_idx = child_idx;

  }

  /* We want to copy over the fields from the parent to the child,
     except for the fields which correspond to the header of the bank
     struct which is used for pool and map management. We can take
     advantage of the fact that those fields are laid out at the top
     of the bank struct. */

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
    HAS_COW_##cow(name);                                 \
    HAS_LOCK_##has_lock(name)
  FD_BANKS_ITER(X)
  #undef X
  #undef HAS_COW_0
  #undef HAS_COW_1
  #undef HAS_LOCK_0
  #undef HAS_LOCK_1

  fd_rwlock_unwrite( &banks->rwlock );

  return new_bank;
}

static fd_bank_t * FD_FN_UNUSED
fd_banks_remove_children( fd_banks_t * banks, fd_bank_t * bank ) {
  fd_rwlock_write( &banks->rwlock );

  fd_bank_t *      bank_pool = fd_banks_get_bank_pool( banks );
  fd_banks_map_t * bank_map  = fd_banks_get_bank_map( banks );

  ulong null_idx = fd_banks_pool_idx_null( bank_pool );

  /* Remove the children from the map. */
  if( bank->child_idx!=null_idx ) {
    fd_bank_t * child = fd_banks_pool_ele( bank_pool, bank->child_idx );
    bank_pool


  }

  fd_rwlock_unwrite( &banks->rwlock );
}

fd_bank_t const *
fd_banks_publish( fd_banks_t * banks, ulong slot ) {

  fd_rwlock_write( &banks->rwlock );

  fd_bank_t *      bank_pool = fd_banks_get_bank_pool( banks );
  fd_banks_map_t * bank_map  = fd_banks_get_bank_map( banks );

  ulong null_idx = fd_banks_pool_idx_null( bank_pool );

  /* We want to replace the old root with the new root. This means we
     have to remove banks that aren't descendants of the new root. */

  fd_bank_t const * old_root = fd_banks_root( banks );
  if( FD_UNLIKELY( !old_root ) ) {
    FD_LOG_WARNING(( "Failed to get root bank" ));
    fd_rwlock_unwrite( &banks->rwlock );
    return NULL;
  }

  fd_bank_t * new_root = fd_banks_map_ele_query( bank_map, &slot, NULL, bank_pool );
  if( FD_UNLIKELY( !new_root ) ) {
    FD_LOG_WARNING(( "Failed to get new root bank" ));
    fd_rwlock_unwrite( &banks->rwlock );
    return NULL;
  }

  fd_bank_t * head = fd_banks_map_ele_remove( bank_map, &old_root->slot_, NULL, bank_pool );
  head->next       = fd_banks_pool_idx_null( bank_pool );
  fd_bank_t * tail = head;

  while( head ) {
    fd_bank_t * child = fd_banks_pool_ele( bank_pool, head->child_idx );

    while( FD_LIKELY( child ) ) {

      if( FD_LIKELY( child!=new_root ) ) {

        /* Remove the child from the map first and push onto the
           frontier list that needs to be iterated through */
        tail->next = fd_banks_map_idx_remove(
            bank_map,
            &child->slot_,
            fd_banks_pool_idx_null( bank_pool ),
            bank_pool );

        tail       = fd_banks_pool_ele( bank_pool, tail->next );
        tail->next = fd_banks_pool_idx_null( bank_pool );

      }

      child = fd_banks_pool_ele( bank_pool, child->sibling_idx );
    }

    fd_bank_t * next = fd_banks_pool_ele( bank_pool, head->next );

    /* Decide if we need to free any CoW fields. We free a CoW member
       from its pool if the dirty flag is set unless it is the same
       pool that the new root uses. */
    #define HAS_COW_1(name)                                                          \
      if( head->name##_dirty && head->name##_pool_idx!=new_root->name##_pool_idx ) { \
        fd_bank_##name##_t * name##_pool = fd_banks_get_##name##_pool( banks );      \
        fd_bank_##name##_pool_idx_release( name##_pool, head->name##_pool_idx );     \
      }
    /* Do nothing for these. */
    #define HAS_COW_0(name)

    #define X(type, name, footprint, align, cow, limit_fork_width, has_lock) \
      HAS_COW_##cow(name)
    FD_BANKS_ITER(X)
    #undef X
    #undef HAS_COW_0
    #undef HAS_COW_1

    fd_banks_pool_ele_release( bank_pool, head );
    head = next;
  }

  /* If the new root did not have the dirty bit set, that means the node
     didn't own the pool index. Change the ownership to the new root. */
  #define HAS_COW_1(name)                                                            \
    fd_bank_##name##_t * name##_pool = fd_banks_get_##name##_pool( banks );          \
    if( new_root->name##_pool_idx!=fd_bank_##name##_pool_idx_null( name##_pool ) ) { \
      new_root->name##_dirty = 1;                                                    \
    }
  /* Do nothing if not CoW. */
  #define HAS_COW_0(name)

  #define X(type, name, footprint, align, cow, limit_fork_width, has_lock) \
    HAS_COW_##cow(name)
  FD_BANKS_ITER(X)
  #undef X
  #undef HAS_COW_0
  #undef HAS_COW_1

  new_root->parent_idx = null_idx;
  banks->root_idx      = fd_banks_map_idx_query( bank_map, &slot, null_idx, bank_pool );
  banks->root          = slot;

  fd_rwlock_unwrite( &banks->rwlock );

  return new_root;
}

void
fd_banks_clear_bank( fd_banks_t * banks, fd_bank_t * bank ) {

  /* Get the parent bank. */
  fd_bank_t * parent_bank = fd_banks_pool_ele( fd_banks_get_bank_pool( banks ), bank->parent_idx );

  #define HAS_COW_1(type, name, footprint)                                                                                  \
    fd_bank_##name##_t * name##_pool = fd_bank_get_##name##_pool( bank );                                                   \
    if( bank->name##_dirty ) {                                                                                              \
      /* If the dirty flag is set, then we have a pool allocated for */                                                     \
      /* this specific bank. We need to release the pool index and   */                                                     \
      /* assign the bank to the idx corresponding to the parent.     */                                                     \
      fd_bank_##name##_pool_idx_release( name##_pool, bank->name##_pool_idx );                                              \
      bank->name##_dirty    = 0;                                                                                            \
      bank->name##_pool_idx = !!parent_bank ? parent_bank->name##_pool_idx : fd_bank_##name##_pool_idx_null( name##_pool ); \
    }

  #define HAS_COW_0(type, name, footprint) \
    fd_memset( bank->name, 0, footprint );

  #define X(type, name, footprint, align, cow, limit_fork_width, has_lock) \
    HAS_COW_##cow(type, name, footprint)
  FD_BANKS_ITER(X)
  #undef X
  #undef HAS_COW_0
  #undef HAS_COW_1
}

fd_bank_t *
fd_banks_rekey_root_bank( fd_banks_t * banks, ulong slot ) {

  if( FD_UNLIKELY( !banks ) ) {
    FD_LOG_WARNING(( "Banks is NULL" ));
    return NULL;
  }

  if( FD_UNLIKELY( banks->root_idx==fd_banks_pool_idx_null( fd_banks_get_bank_pool( banks ) ) ) ) {
    FD_LOG_WARNING(( "Root bank does not exist" ));
    return NULL;
  }

  fd_bank_t * bank = fd_banks_pool_ele( fd_banks_get_bank_pool( banks ), banks->root_idx );
  if( FD_UNLIKELY( !bank ) ) {
    FD_LOG_WARNING(( "Failed to get root bank" ));
    return NULL;
  }

  /* Once we validated that there is a valid root bank, we can remove
     the bank from the map and insert it with the new key. */
  bank = fd_banks_map_ele_remove( fd_banks_get_bank_map( banks ), &bank->slot_, NULL, fd_banks_get_bank_pool( banks ) );
  if( FD_UNLIKELY( !bank ) ) {
    FD_LOG_WARNING(( "Failed to remove root bank" ));
    return NULL;
  }

  bank->slot_ = slot;

  if( FD_UNLIKELY( !fd_banks_map_ele_insert( fd_banks_get_bank_map( banks ), bank, fd_banks_get_bank_pool( banks ) ) ) ) {
    FD_LOG_WARNING(( "Failed to insert root bank" ));
    return NULL;
  }

  return bank;
}
