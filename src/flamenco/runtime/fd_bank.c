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

#define X(type, name, footprint, align)                                                                            \
  type * fd_bank_##name##_query( fd_banks_t * banks, fd_bank_t * bank ) {                                          \
    /* If the pool element hasn't been setup yet, then return NULL */                                              \
    if( bank->name##_pool_idx==fd_bank_##name##_pool_idx_null( banks->name##_pool ) ) {                            \
      return NULL;                                                                                                 \
    }                                                                                                              \
    fd_bank_##name##_t * bank_##name = fd_bank_##name##_pool_ele( banks->name##_pool, bank->name##_pool_idx );     \
    return (type *)bank_##name->data;                                                                              \
  }                                                                                                                \
  type * fd_bank_##name##_modify( fd_banks_t * banks, fd_bank_t * bank ) {                                         \
    /* If the dirty flag is set, then we already have a pool element */                                            \
    /* that was copied over for the current bank. We can simply just */                                            \
    /* query the pool element and return it. */                                                                    \
    if( bank->name##_dirty ) {                                                                                     \
      fd_bank_##name##_t * bank_##name = fd_bank_##name##_pool_ele( banks->name##_pool, bank->name##_pool_idx );   \
      return (type *)bank_##name->data;                                                                            \
    }                                                                                                              \
    fd_bank_##name##_t * child_##name = fd_bank_##name##_pool_ele_acquire( banks->name##_pool );                   \
    if( FD_UNLIKELY( !child_##name ) ) {                                                                           \
      FD_LOG_CRIT(( "Failed to acquire " #name " pool element" ));                                                 \
    }                                                                                                              \
    /* If the dirty flag has not been set yet, we need to allocated a */                                           \
    /* new pool element and copy over the data from the parent idx.   */                                           \
    /* We also need to mark the dirty flag.                           */                                           \
    ulong child_idx = fd_bank_##name##_pool_idx( banks->name##_pool, child_##name );                               \
    if( bank->name##_pool_idx!=fd_bank_##name##_pool_idx_null( banks->name##_pool ) ) {                            \
      fd_bank_##name##_t * parent_##name = fd_bank_##name##_pool_ele( banks->name##_pool, bank->name##_pool_idx ); \
      memcpy( child_##name->data, parent_##name->data, fd_bank_##name##_footprint );                               \
    }                                                                                                              \
    bank->name##_pool_idx = child_idx;                                                                             \
    bank->name##_dirty    = 1;                                                                                     \
    return (type *)child_##name->data;                                                                             \
  }
FD_BANKS_COW_ITER(X)
#undef X


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
  #define X(type, name, footprint, align) \
    l = FD_LAYOUT_APPEND( l, fd_bank_##name##_pool_align(), fd_bank_##name##_pool_footprint( max_banks ) );
  FD_BANKS_COW_ITER(X)
  #undef X

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
  #define X(type, name, footprint, align)                                                                                               \
    void * name##_pool_mem = FD_SCRATCH_ALLOC_APPEND( l, fd_bank_##name##_pool_align(), fd_bank_##name##_pool_footprint( max_banks ) ); \
    memset( name##_pool_mem, 0, fd_bank_##name##_pool_footprint( max_banks ) );
  FD_BANKS_COW_ITER(X)
  #undef X

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

  /* Now, new join all of the CoW pools. */
  #define X(type, name, footprint, align)                                         \
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
  FD_BANKS_COW_ITER(X)
  #undef X

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
  #define X(type, name, footprint, align) \
    void * name##_pool_mem = FD_SCRATCH_ALLOC_APPEND( l, fd_bank_##name##_pool_align(), fd_bank_##name##_pool_footprint( banks->max_banks ) );
  FD_BANKS_COW_ITER(X)
  #undef X
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

  #define X(type, name, footprint, align) \
    banks->name##_pool = fd_bank_##name##_pool_join( name##_pool_mem ); \
    if( FD_UNLIKELY( !banks->name##_pool ) ) { \
      FD_LOG_WARNING(( "Failed to join " #name " pool" )); \
      return NULL; \
    }
  FD_BANKS_COW_ITER(X)
  #undef X

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
  #define X(type, name, footprint, align)                                         \
    bank->name##_pool_idx = fd_bank_##name##_pool_idx_null( banks->name##_pool ); \
    bank->name##_dirty    = 0;
  FD_BANKS_COW_ITER(X)
  #undef X

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

  /* Copy over fields from parent to child */

  /* TODO: Turn this into one giant memcpy. */
  memcpy( new_bank->block_hash_queue, parent_bank->block_hash_queue, 50000UL );
  new_bank->fee_rate_governor           = parent_bank->fee_rate_governor;
  new_bank->capitalization              = parent_bank->capitalization;
  new_bank->lamports_per_signature      = parent_bank->lamports_per_signature;
  new_bank->prev_lamports_per_signature = parent_bank->prev_lamports_per_signature;
  new_bank->transaction_count           = parent_bank->transaction_count;
  new_bank->parent_signature_cnt        = parent_bank->parent_signature_cnt;
  new_bank->tick_height                 = parent_bank->tick_height;
  new_bank->max_tick_height             = parent_bank->max_tick_height;
  new_bank->hashes_per_tick             = parent_bank->hashes_per_tick;
  new_bank->ns_per_slot                 = parent_bank->ns_per_slot;
  new_bank->ticks_per_slot              = parent_bank->ticks_per_slot;
  new_bank->genesis_creation_time       = parent_bank->genesis_creation_time;
  new_bank->slots_per_year              = parent_bank->slots_per_year;
  new_bank->inflation                   = parent_bank->inflation;
  new_bank->total_epoch_stake           = parent_bank->total_epoch_stake;
  new_bank->eah_start_slot              = parent_bank->eah_start_slot;
  new_bank->eah_stop_slot               = parent_bank->eah_stop_slot;
  new_bank->block_height                = parent_bank->block_height;
  new_bank->epoch_account_hash          = parent_bank->epoch_account_hash;
  new_bank->execution_fees              = parent_bank->execution_fees;
  new_bank->priority_fees               = parent_bank->priority_fees;
  new_bank->signature_cnt               = parent_bank->signature_cnt;
  new_bank->use_prev_epoch_stake        = parent_bank->use_prev_epoch_stake;
  new_bank->poh                         = parent_bank->poh;

  /* Setup all of the CoW fields. */
  #define X(type, name, footprint, align)                     \
    new_bank->name##_pool_idx = parent_bank->name##_pool_idx; \
    new_bank->name##_dirty    = 0UL;
  FD_BANKS_COW_ITER(X)
  #undef X

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
    #define X(type, name, footprint, align)                                             \
      if( head->name##_dirty && head->name##_pool_idx!=new_root->name##_pool_idx ) {    \
        fd_bank_##name##_pool_idx_release( banks->name##_pool, head->name##_pool_idx ); \
      }
    FD_BANKS_COW_ITER(X)
    #undef X

    fd_banks_pool_ele_release( banks->pool, head );
    head = next;
  }

  /* Need to update the root to be the owner of any CoW fields. */
  #define X(type, name, footprint, align) \
    if( new_root->name##_pool_idx!=fd_bank_##name##_pool_idx_null( banks->name##_pool ) ) { \
      new_root->name##_dirty = 1;                                                           \
    }
  FD_BANKS_COW_ITER(X)
  #undef X

  new_root->parent_idx = null_idx;
  banks->root_idx      = fd_banks_map_idx_query( banks->map, &slot, null_idx, banks->pool );
  banks->root          = slot;

  return new_root;

}
