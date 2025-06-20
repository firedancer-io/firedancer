#include "fd_bank.h"
#include "../../util/fd_util_base.h"


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

#define ACQUIRE_READ_0( name ) (void)bank;
#define ACQUIRE_READ_1( name ) fd_rwlock_read( &bank->name##_lock );
#define ACQUIRE_WRITE_0( name ) (void)bank;
#define ACQUIRE_WRITE_1( name ) fd_rwlock_write( &bank->name##_lock );
#define RELEASE_READ_0( name ) (void)bank;
#define RELEASE_READ_1( name ) fd_rwlock_unread( &bank->name##_lock );
#define RELEASE_WRITE_0( name ) (void)bank;
#define RELEASE_WRITE_1( name ) fd_rwlock_unwrite( &bank->name##_lock );

#define HAS_COW_1(type, name, footprint, align, has_lock)                                                          \
  type const *                                                                                                     \
  fd_bank_##name##_query( fd_bank_t * bank ) {                                                                     \
    ACQUIRE_READ_##has_lock( name );                                                                               \
    /* If the pool element hasn't been setup yet, then return NULL */                                              \
    if( bank->name##_pool_idx==fd_bank_##name##_pool_idx_null( bank->name##_pool ) ) {                             \
      return NULL;                                                                                                 \
    }                                                                                                              \
    fd_bank_##name##_t * bank_##name = fd_bank_##name##_pool_ele( bank->name##_pool, bank->name##_pool_idx );      \
    return (type *)bank_##name->data;                                                                              \
  }                                                                                                                \
  type *                                                                                                           \
  fd_bank_##name##_modify( fd_bank_t * bank ) {                                                                    \
    ACQUIRE_WRITE_##has_lock( name );                                                                              \
    /* If the dirty flag is set, then we already have a pool element */                                            \
    /* that was copied over for the current bank. We can simply just */                                            \
    /* query the pool element and return it. */                                                                    \
    if( FD_UNLIKELY( bank->name##_pool==NULL ) ) {                                                                 \
      FD_LOG_CRIT(( "NULL " #name " pool" ));                                                                      \
    }                                                                                                              \
    if( bank->name##_dirty ) {                                                                                     \
      fd_bank_##name##_t * bank_##name = fd_bank_##name##_pool_ele( bank->name##_pool, bank->name##_pool_idx );    \
      return (type *)bank_##name->data;                                                                            \
    }                                                                                                              \
    fd_bank_##name##_t * child_##name = fd_bank_##name##_pool_ele_acquire( bank->name##_pool );                    \
    if( FD_UNLIKELY( !child_##name ) ) {                                                                           \
      FD_LOG_CRIT(( "Failed to acquire " #name " pool element" ));                                                 \
    }                                                                                                              \
    /* If the dirty flag has not been set yet, we need to allocated a */                                           \
    /* new pool element and copy over the data from the parent idx.   */                                           \
    /* We also need to mark the dirty flag.                           */                                           \
    ulong child_idx = fd_bank_##name##_pool_idx( bank->name##_pool, child_##name );                                \
    if( bank->name##_pool_idx!=fd_bank_##name##_pool_idx_null( bank->name##_pool ) ) {                             \
      fd_bank_##name##_t * parent_##name = fd_bank_##name##_pool_ele( bank->name##_pool, bank->name##_pool_idx );  \
      memcpy( child_##name->data, parent_##name->data, fd_bank_##name##_footprint );                               \
    }                                                                                                              \
    bank->name##_pool_idx = child_idx;                                                                             \
    bank->name##_dirty    = 1;                                                                                     \
    return (type *)child_##name->data;                                                                             \
  }                                                                                                                \
  void                                                                                                             \
  fd_bank_##name##_end_query( fd_bank_t * bank ) {                                                                 \
    RELEASE_READ_##has_lock( name );                                                                               \
  }                                                                                                                \
  void                                                                                                             \
  fd_bank_##name##_end_modify( fd_bank_t * bank ) {                                                                \
    RELEASE_WRITE_##has_lock( name );                                                                              \
  }                                                                                                               \
  void                                                                                                             \
  fd_bank_##name##_set( fd_bank_t * bank, type value ) {                                                           \
    (void)bank; (void)value;                                                                                       \
    FD_LOG_CRIT(( "fd_bank_##name##_set: not implemented" ));                                                      \
  }                                                                                                                \
  type                                                                                                             \
  fd_bank_##name##_get( fd_bank_t * bank ) {                                                                       \
    (void)bank;                                                                                                    \
    FD_LOG_CRIT(( "fd_bank_##name##_get: not implemented" ));                                                      \
  }

#define HAS_COW_0(type, name, footprint, align, has_lock)   \
  type const *                                              \
  fd_bank_##name##_query( fd_bank_t * bank ) {              \
    ACQUIRE_READ_##has_lock( name );                        \
    return (type const *)fd_type_pun_const( bank->name );   \
  }                                                         \
  type *                                                    \
  fd_bank_##name##_modify( fd_bank_t * bank ) {             \
    ACQUIRE_WRITE_##has_lock( name );                       \
    return (type *)fd_type_pun( bank->name );               \
  }                                                         \
  void                                                      \
  fd_bank_##name##_end_query( fd_bank_t * bank ) {          \
    RELEASE_READ_##has_lock( name );                        \
  }                                                         \
  void                                                      \
  fd_bank_##name##_end_modify( fd_bank_t * bank ) {         \
    RELEASE_WRITE_##has_lock( name );                       \
  }                                                         \
  void                                                      \
  fd_bank_##name##_set( fd_bank_t * bank, type value ) {    \
    FD_STORE( type, bank->name, value );                    \
  }                                                         \
  type                                                      \
  fd_bank_##name##_get( fd_bank_t * bank ) {                \
    ACQUIRE_READ_##has_lock( name );                        \
    type val = FD_LOAD( type, bank->name );                 \
    RELEASE_READ_##has_lock( name );                        \
    return val;                                             \
  }

#define X(type, name, footprint, align, cow, has_lock) \
  HAS_COW_##cow(type, name, footprint, align, has_lock)
FD_BANKS_ITER(X)
#undef X
#undef HAS_COW_0
#undef HAS_COW_1
#undef HAS_LOCK_0
#undef HAS_LOCK_1
#undef ACQUIRE_READ_0
#undef ACQUIRE_READ_1
#undef ACQUIRE_WRITE_0
#undef ACQUIRE_WRITE_1
#undef RELEASE_READ_0
#undef RELEASE_READ_1
#undef RELEASE_WRITE_0
#undef RELEASE_WRITE_1

/**********************************************************************/

ulong
fd_banks_align( void ) {
  return 128UL;
}

ulong
fd_banks_footprint( ulong max_banks ) {

  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, fd_banks_align(),      sizeof(fd_banks_t) );
  l = FD_LAYOUT_APPEND( l, fd_banks_pool_align(), fd_banks_pool_footprint( max_banks ) );
  l = FD_LAYOUT_APPEND( l, fd_banks_map_align(),  fd_banks_map_footprint( max_banks ) );

  /* Need to count the footprint for all of the CoW pools. */
  #define HAS_COW_1(name) \
    l = FD_LAYOUT_APPEND( l, fd_bank_##name##_pool_align(), fd_bank_##name##_pool_footprint( max_banks ) );

  /* Do nothing for these. */
  #define HAS_COW_0(name)

  #define X(type, name, footprint, align, cow, has_lock) \
    HAS_COW_##cow(name)
  FD_BANKS_ITER(X)
  #undef X
  #undef HAS_COW_0
  #undef HAS_COW_1

  return FD_LAYOUT_FINI( l, fd_banks_align() );
}

void *
fd_banks_new( void * shmem, ulong max_banks ) {

  fd_banks_t * banks = (fd_banks_t *)shmem;

  if( FD_UNLIKELY( !banks ) ) {
    FD_LOG_WARNING(( "NULL banks" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)banks, fd_banks_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned banks" ));
    return NULL;
  }

  fd_memset( banks, 0, fd_banks_footprint( max_banks ) );

  /* First, layout the banks and the pool/map used by fd_banks_t. */
  FD_SCRATCH_ALLOC_INIT( l, banks );
  banks           = FD_SCRATCH_ALLOC_APPEND( l, fd_banks_align(),      sizeof(fd_banks_t) );
  void * pool_mem = FD_SCRATCH_ALLOC_APPEND( l, fd_banks_pool_align(), fd_banks_pool_footprint( max_banks ) );
  void * map_mem  = FD_SCRATCH_ALLOC_APPEND( l, fd_banks_map_align(),  fd_banks_map_footprint( max_banks ) );

  /* Need to layout all of the CoW pools. */
  #define HAS_COW_1(name) \
    void * name##_pool_mem = FD_SCRATCH_ALLOC_APPEND( l, fd_bank_##name##_pool_align(), fd_bank_##name##_pool_footprint( max_banks ) ); \
    memset( name##_pool_mem, 0, fd_bank_##name##_pool_footprint( max_banks ) );

  /* Do nothing for these. */
  #define HAS_COW_0(name)

  #define X(type, name, footprint, align, cow, has_lock) \
    HAS_COW_##cow(name)
  FD_BANKS_ITER(X)
  #undef X
  #undef HAS_COW_0
  #undef HAS_COW_1

  if( FD_UNLIKELY( FD_SCRATCH_ALLOC_FINI( l, fd_banks_align() ) != (ulong)banks + fd_banks_footprint( max_banks ) ) ) {
    FD_LOG_WARNING(( "fd_banks_new: bad layout" ));
    return NULL;
  }

  void * pool = fd_banks_pool_new( pool_mem, max_banks );
  if( FD_UNLIKELY( !pool ) ) {
    FD_LOG_WARNING(( "Failed to create bank pool" ));
    return NULL;
  }

  banks->pool = fd_banks_pool_join( pool );
  if( FD_UNLIKELY( !pool ) ) {
    FD_LOG_WARNING(( "Failed to join bank pool" ));
    return NULL;
  }

  void * map = fd_banks_map_new( map_mem, max_banks, 999UL );
  if( FD_UNLIKELY( !map ) ) {
    FD_LOG_WARNING(( "Failed to create bank map" ));
    return NULL;
  }

  banks->map = fd_banks_map_join( map_mem );
  if( FD_UNLIKELY( !banks->map ) ) {
    FD_LOG_WARNING(( "Failed to join bank map" ));
    return NULL;
  }

  /* Now, call _new() and _join() for all of the CoW pools. */
  #define HAS_COW_1(name)                                                         \
    banks->name##_pool = fd_bank_##name##_pool_new( name##_pool_mem, max_banks ); \
    if( FD_UNLIKELY( !banks->name##_pool ) ) {                                    \
      FD_LOG_WARNING(( "Failed to create " #name " pool" ));                      \
      return NULL;                                                                \
    }                                                                             \
    banks->name##_pool = fd_bank_##name##_pool_join( name##_pool_mem );           \
    if( FD_UNLIKELY( !banks->name##_pool ) ) {                                    \
      FD_LOG_WARNING(( "Failed to join " #name " pool" ));                        \
      return NULL;                                                                \
    }

  /* Do nothing for these. */
  #define HAS_COW_0(name)

  #define X(type, name, footprint, align, cow, has_lock) \
    HAS_COW_##cow(name)
  FD_BANKS_ITER(X)
  #undef X
  #undef HAS_COW_0
  #undef HAS_COW_1

  banks->max_banks = max_banks;
  banks->magic     = FD_BANKS_MAGIC;

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
  banks           = FD_SCRATCH_ALLOC_APPEND( l, fd_banks_align(),      sizeof(fd_banks_t) );
  void * pool_mem = FD_SCRATCH_ALLOC_APPEND( l, fd_banks_pool_align(), fd_banks_pool_footprint( banks->max_banks ) );
  void * map_mem  = FD_SCRATCH_ALLOC_APPEND( l, fd_banks_map_align(),  fd_banks_map_footprint( banks->max_banks ) );

  /* Need to layout all of the CoW pools. */
  #define HAS_COW_1(name) \
    void * name##_pool_mem = FD_SCRATCH_ALLOC_APPEND( l, fd_bank_##name##_pool_align(), fd_bank_##name##_pool_footprint( banks->max_banks ) );

  /* Do nothing for these. */
  #define HAS_COW_0(name)

  #define X(type, name, footprint, align, cow, has_lock) \
    HAS_COW_##cow(name)
  FD_BANKS_ITER(X)
  #undef X
  #undef HAS_COW_0
  #undef HAS_COW_1

  FD_SCRATCH_ALLOC_FINI( l, fd_banks_align() );

  banks->pool = fd_banks_pool_join( pool_mem );
  if( FD_UNLIKELY( !banks->pool ) ) {
    FD_LOG_WARNING(( "Failed to join bank pool" ));
    return NULL;
  }

  banks->map = fd_banks_map_join( map_mem );
  if( FD_UNLIKELY( !banks->map ) ) {
    FD_LOG_WARNING(( "Failed to join bank map" ));
    return NULL;
  }

  /* Now, call _join() for all of the CoW pools. */
  #define HAS_COW_1(name)                                                         \
    banks->name##_pool = fd_bank_##name##_pool_join( name##_pool_mem );           \
    if( FD_UNLIKELY( !banks->name##_pool ) ) {                                    \
      FD_LOG_WARNING(( "Failed to join " #name " pool" ));                        \
      return NULL;                                                                \
    }

  /* Do nothing for these. */
  #define HAS_COW_0(name)

  #define X(type, name, footprint, align, cow, has_lock) \
    HAS_COW_##cow(name)
  FD_BANKS_ITER(X)
  #undef X
  #undef HAS_COW_0
  #undef HAS_COW_1


  return banks;
}

fd_bank_t *
fd_banks_init_bank( fd_banks_t * banks, ulong slot ) {

  if( FD_UNLIKELY( !banks ) ) {
    FD_LOG_WARNING(( "NULL banks" ));
    return NULL;
  }

  fd_bank_t * bank = fd_banks_pool_ele_acquire( banks->pool );
  if( FD_UNLIKELY( bank==NULL ) ) {
    FD_LOG_WARNING(( "Failed to acquire bank" ));
    return NULL;
  }

  memset( bank, 0, fd_bank_footprint() );

  ulong null_idx = fd_banks_pool_idx_null( banks->pool );
  bank->slot        = slot;
  bank->next        = null_idx;
  bank->parent_idx  = null_idx;
  bank->child_idx   = null_idx;
  bank->sibling_idx = null_idx;

  /* Set all CoW fields to null. */
  #define HAS_COW_1(name)                                                         \
    bank->name##_pool     = banks->name##_pool;                                   \
    FD_TEST( bank->name##_pool );                                                 \
    bank->name##_pool_idx = fd_bank_##name##_pool_idx_null( banks->name##_pool ); \
    bank->name##_dirty    = 0;

  /* Do nothing for these. */
  #define HAS_COW_0(name)

  #define HAS_LOCK_1(name) \
    fd_rwlock_unwrite(&bank->name##_lock);
  #define HAS_LOCK_0(name)

  #define X(type, name, footprint, align, cow, has_lock) \
    HAS_COW_##cow(name);                                 \
    HAS_LOCK_##has_lock(name)
  FD_BANKS_ITER(X)
  #undef X
  #undef HAS_COW_0
  #undef HAS_COW_1
  #undef HAS_LOCK_0
  #undef HAS_LOCK_1

  fd_banks_map_ele_insert( banks->map, bank, banks->pool );

  /* Now that the node is inserted, update the root */

  banks->root     = slot;
  banks->root_idx = fd_banks_pool_idx( banks->pool, bank );

  return bank;
}

fd_bank_t *
fd_banks_get_bank( fd_banks_t * banks, ulong slot ) {

  return fd_banks_map_ele_query( banks->map, &slot, NULL, banks->pool );
}


fd_bank_t *
fd_banks_clone_from_parent( fd_banks_t * banks,
                            ulong        slot,
                            ulong        parent_slot ) {

  /* First query for the parent bank */

  fd_bank_t * parent_bank = fd_banks_map_ele_query( banks->map, &parent_slot, NULL, banks->pool );

  if( FD_UNLIKELY( !parent_bank ) ) {
    FD_LOG_WARNING(( "Failed to get bank" ));
    return NULL;
  }

  if( FD_UNLIKELY( parent_bank->slot != parent_slot ) ) {
    FD_LOG_WARNING(( "Parent slot mismatch" ));
    return NULL;
  }

  ulong parent_idx = fd_banks_pool_idx( banks->pool, parent_bank );

  /* Now acquire a new bank */

  fd_bank_t * new_bank = fd_banks_pool_ele_acquire( banks->pool );
  if( FD_UNLIKELY( !new_bank ) ) {
    FD_LOG_WARNING(( "Failed to acquire bank" ));
    return NULL;
  }

  ulong null_idx = fd_banks_pool_idx_null( banks->pool );

  memset( new_bank, 0, fd_bank_footprint() );
  new_bank->slot        = slot;
  new_bank->next        = null_idx;
  new_bank->parent_idx  = null_idx;
  new_bank->child_idx   = null_idx;
  new_bank->sibling_idx = null_idx;

  fd_banks_map_ele_insert( banks->map, new_bank, banks->pool );

  ulong child_idx = fd_banks_pool_idx( banks->pool, new_bank );

  /* Link node->parent */

  new_bank->parent_idx = parent_idx;

  /* Link parent->node and sibling->node */

  if( FD_LIKELY( parent_bank->child_idx == null_idx ) ) {

    /* This is the first child so set as left-most child */

    parent_bank->child_idx = child_idx;

  } else {

    /* Already have children so iterate to right-most sibling. */

    fd_bank_t * curr_bank = fd_banks_pool_ele( banks->pool, parent_bank->child_idx );
    while( curr_bank->sibling_idx != null_idx ) curr_bank = fd_banks_pool_ele( banks->pool, curr_bank->sibling_idx );

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
  #define HAS_COW_1(name)                                     \
    new_bank->name##_pool_idx = parent_bank->name##_pool_idx; \
    new_bank->name##_dirty    = 0UL;                          \
    new_bank->name##_pool     = banks->name##_pool;

  /* Do nothing for these. */
  #define HAS_COW_0(name)

  /* Setup locks for new bank as free. */
  #define HAS_LOCK_1(name) \
    fd_rwlock_unwrite(&new_bank->name##_lock);
  #define HAS_LOCK_0(name)

  #define X(type, name, footprint, align, cow, has_lock) \
    HAS_COW_##cow(name);                                 \
    HAS_LOCK_##has_lock(name)
  FD_BANKS_ITER(X)
  #undef X
  #undef HAS_COW_0
  #undef HAS_COW_1
  #undef HAS_LOCK_0
  #undef HAS_LOCK_1

  return new_bank;
}

fd_bank_t const *
fd_banks_publish( fd_banks_t * banks, ulong slot ) {

  ulong null_idx = fd_banks_pool_idx_null( banks->pool );

  /* We want to replace the old root with the new root. This means we
     have to remove banks that aren't descendants of the new root. */

  fd_bank_t const * old_root = fd_banks_root( banks );
  if( FD_UNLIKELY( !old_root ) ) {
    FD_LOG_WARNING(( "Failed to get root bank" ));
    return NULL;
  }

  fd_bank_t * new_root = fd_banks_map_ele_query( banks->map, &slot, NULL, banks->pool );
  if( FD_UNLIKELY( !new_root ) ) {
    FD_LOG_WARNING(( "Failed to get new root bank" ));
    return NULL;
  }

  fd_bank_t * head = fd_banks_map_ele_remove( banks->map, &old_root->slot, NULL, banks->pool );
  head->next        = fd_banks_pool_idx_null( banks->pool );
  fd_bank_t * tail  = head;

  while( head ) {
    fd_bank_t * child = fd_banks_pool_ele( banks->pool, head->child_idx );

    while( FD_LIKELY( child ) ) {

      if( FD_LIKELY( child != new_root ) ) {

        /* Remove the child from the map first and push onto the
           frontier list that needs to be iterated thorugh */
        tail->next = fd_banks_map_idx_remove( banks->map,
                                              &child->slot,
                                              fd_banks_pool_idx_null( banks->pool ),
                                              banks->pool );

        tail       = fd_banks_pool_ele( banks->pool, tail->next );
        tail->next = fd_banks_pool_idx_null( banks->pool );

      }

      child = fd_banks_pool_ele( banks->pool, child->sibling_idx );
    }

    fd_bank_t * next = fd_banks_pool_ele( banks->pool, head->next );

    /* Decide if we need to free any CoW fields. */
    #define HAS_COW_1(name)                                                             \
      if( head->name##_dirty && head->name##_pool_idx!=new_root->name##_pool_idx ) {    \
        fd_bank_##name##_pool_idx_release( banks->name##_pool, head->name##_pool_idx ); \
      }
    /* Do nothing for these. */
    #define HAS_COW_0(name)

    #define X(type, name, footprint, align, cow, has_lock) \
      HAS_COW_##cow(name)
    FD_BANKS_ITER(X)
    #undef X
    #undef HAS_COW_0
    #undef HAS_COW_1


    fd_banks_pool_ele_release( banks->pool, head );
    head = next;
  }

  /* Need to update the root to be the owner of any CoW fields. */
  #define HAS_COW_1(name)                                                                   \
    if( new_root->name##_pool_idx!=fd_bank_##name##_pool_idx_null( banks->name##_pool ) ) { \
      new_root->name##_dirty = 1;                                                           \
    }
  /* Do nothing for these. */
  #define HAS_COW_0(name)

  #define X(type, name, footprint, align, cow, has_lock) \
    HAS_COW_##cow(name)
  FD_BANKS_ITER(X)
  #undef X
  #undef HAS_COW_0
  #undef HAS_COW_1

  new_root->parent_idx = null_idx;
  banks->root_idx      = fd_banks_map_idx_query( banks->map, &slot, null_idx, banks->pool );
  banks->root          = slot;

  return new_root;

}
