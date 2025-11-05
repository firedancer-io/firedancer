#include "fd_tower_forks.h"
#include "fd_tower.h"

void *
fd_forks_new( void * shmem, ulong slot_max, ulong voter_max ) {
  if( FD_UNLIKELY( !shmem ) ) {
    FD_LOG_WARNING(( "NULL mem" ));
    return NULL;
  }

  fd_wksp_t * wksp = fd_wksp_containing( shmem );
  if( FD_UNLIKELY( !wksp ) ) {
    FD_LOG_WARNING(( "shmem must be part of a workspace" ));
    return NULL;
  }

  ulong footprint = fd_forks_footprint( slot_max, voter_max );
  if( FD_UNLIKELY( !footprint ) ) {
    FD_LOG_WARNING(( "bad slot_max (%lu)", slot_max ));
    return NULL;
  }
  /* verify aligned to fd_forks_align() */
  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shmem, fd_forks_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned mem" ));
    return NULL;
  }

  ulong interval_max = fd_ulong_pow2_up( FD_LOCKOUT_ENTRY_MAX*slot_max*voter_max );
  int   lg_slot_max  = fd_ulong_find_msb( fd_ulong_pow2_up( slot_max ) ) + 1;

  FD_SCRATCH_ALLOC_INIT( l, shmem );
  fd_forks_t * forks              = FD_SCRATCH_ALLOC_APPEND( l, fd_forks_align(),                  sizeof(fd_forks_t)                                  );
  void *       tower_forks        = FD_SCRATCH_ALLOC_APPEND( l, fd_tower_forks_align(),            fd_tower_forks_footprint   ( lg_slot_max )          );
  void *       leaves_map         = FD_SCRATCH_ALLOC_APPEND( l, fd_tower_leaves_map_align(),       fd_tower_leaves_map_footprint ( slot_max )          );
  void *       leaves_dlist       = FD_SCRATCH_ALLOC_APPEND( l, fd_tower_leaves_dlist_align(),     fd_tower_leaves_dlist_footprint()                   );
  void *       leaves_pool        = FD_SCRATCH_ALLOC_APPEND( l, fd_tower_leaves_pool_align(),      fd_tower_leaves_pool_footprint( slot_max )          );
  void *       lockout_slots_map  = FD_SCRATCH_ALLOC_APPEND( l, fd_lockout_slots_map_align(),      fd_lockout_slots_map_footprint( slot_max )          );
  void *       lockout_slots_pool = FD_SCRATCH_ALLOC_APPEND( l, fd_lockout_slots_pool_align(),     fd_lockout_slots_pool_footprint    ( interval_max ) );
  void *       lockout_itrvl_map  = FD_SCRATCH_ALLOC_APPEND( l, fd_lockout_intervals_map_align(),  fd_lockout_intervals_map_footprint ( interval_max ) );
  void *       lockout_itrvl_pool = FD_SCRATCH_ALLOC_APPEND( l, fd_lockout_intervals_pool_align(), fd_lockout_intervals_pool_footprint( interval_max ) );
  FD_TEST( FD_SCRATCH_ALLOC_FINI( l, fd_forks_align() ) == (ulong)shmem + footprint );

  forks->tower_forks            = fd_tower_forks_join           ( fd_tower_forks_new           ( tower_forks, lg_slot_max ) );
  forks->tower_leaves_map       = fd_tower_leaves_map_join      ( fd_tower_leaves_map_new      ( leaves_map,  slot_max, 0 ) );
  forks->tower_leaves_pool      = fd_tower_leaves_pool_join     ( fd_tower_leaves_pool_new     ( leaves_pool, slot_max    ) );
  forks->tower_leaves_dlist     = fd_tower_leaves_dlist_join    ( fd_tower_leaves_dlist_new    ( leaves_dlist             ) );
  forks->lockout_slots_map      = fd_lockout_slots_map_join     ( fd_lockout_slots_map_new     ( lockout_slots_map,  slot_max,     0 ) );
  forks->lockout_slots_pool     = fd_lockout_slots_pool_join    ( fd_lockout_slots_pool_new    ( lockout_slots_pool, interval_max    ) );
  forks->lockout_intervals_map  = fd_lockout_intervals_map_join ( fd_lockout_intervals_map_new ( lockout_itrvl_map,  interval_max, 0 ) );
  forks->lockout_intervals_pool = fd_lockout_intervals_pool_join( fd_lockout_intervals_pool_new( lockout_itrvl_pool, interval_max    ) );

  FD_TEST( forks->tower_forks );
  FD_TEST( forks->tower_leaves_map );
  FD_TEST( forks->tower_leaves_pool );
  FD_TEST( forks->tower_leaves_dlist );
  FD_TEST( forks->lockout_slots_map );
  FD_TEST( forks->lockout_slots_pool );
  FD_TEST( forks->lockout_intervals_map );
  FD_TEST( forks->lockout_intervals_pool );
  return shmem;
}

fd_forks_t *
fd_forks_join( void * shforks ) {
  return shforks;
}


int
is_ancestor( fd_tower_forks_t * forks,
             ulong              slot,
             ulong              ancestor_slot ) {
  fd_tower_forks_t * anc = fd_tower_forks_query( forks, slot, NULL );
  while( FD_LIKELY( anc ) ) {
    if( FD_LIKELY( anc->parent_slot == ancestor_slot ) ) return 1;
    anc = anc->parent_slot == ULONG_MAX ? NULL : fd_tower_forks_query( forks, anc->parent_slot, NULL );
  }
  return 0;
}

int
fd_forks_is_slot_ancestor( fd_forks_t * forks,
                           ulong        descendant_slot,
                           ulong        ancestor_slot ) {
  return is_ancestor( forks->tower_forks, descendant_slot, ancestor_slot );
}

int
fd_forks_is_slot_descendant( fd_forks_t * forks,
                             ulong        ancestor_slot,
                             ulong        descendant_slot ) {
  return is_ancestor( forks->tower_forks, descendant_slot, ancestor_slot );
}

ulong
fd_forks_lowest_common_ancestor( fd_forks_t * forks,
                                 ulong        slot1,
                                 ulong        slot2 ) {
  fd_tower_forks_t * fork1 = fd_tower_forks_query( forks->tower_forks, slot1, NULL );
  fd_tower_forks_t * fork2 = fd_tower_forks_query( forks->tower_forks, slot2, NULL );

  while( FD_LIKELY( fork1 && fork2 ) ) {
    if( FD_UNLIKELY( fork1->slot == fork2->slot ) ) return fork1->slot;
    if( fork1->slot > fork2->slot                 ) fork1 = fd_tower_forks_query( forks->tower_forks, fork1->parent_slot, NULL );
    else                                            fork2 = fd_tower_forks_query( forks->tower_forks, fork2->parent_slot, NULL );
  }
  FD_LOG_CRIT(( "invalid forks" ));
}

fd_hash_t const *
fd_forks_canonical_block_id( fd_forks_t * forks,
                             ulong        slot ) {
  fd_tower_forks_t * fork = fd_tower_forks_query( forks->tower_forks, slot, NULL );
  if( FD_UNLIKELY( !fork ) ) return NULL;
  if     ( FD_LIKELY( fork->confirmed ) ) return &fork->confirmed_block_id;
  else if( FD_LIKELY( fork->voted     ) ) return &fork->voted_block_id;
  else                                    return &fork->replayed_block_id;
}

void
fd_forks_link( fd_forks_t * forks, ulong slot, ulong parent_slot ) {
  fd_tower_forks_t * fork = fd_tower_forks_insert( forks->tower_forks, slot );
  if( FD_UNLIKELY( !fork ) ) return;
  fork->parent_slot = parent_slot;
  fork->slot        = slot;
}

fd_tower_forks_t *
fd_forks_confirmed( fd_tower_forks_t * fork,
                    fd_hash_t const  * block_id ) {
  fork->confirmed          = 1;
  fork->confirmed_block_id = *block_id;
  return fork;
}

fd_tower_forks_t *
fd_forks_voted( fd_tower_forks_t * fork,
                fd_hash_t const  * block_id ) {
  fork->voted             = 1;
  fork->voted_block_id    = *block_id;
  return fork;
}
fd_tower_forks_t *
fd_forks_replayed( fd_forks_t *       forks,
                   fd_tower_forks_t * fork,
                   ulong              bank_idx,
                   fd_hash_t const  * block_id ) {
  fork->bank_idx          = bank_idx;
  fork->replayed_block_id = *block_id;

  fd_tower_leaf_t * parent;
  if( ( parent = fd_tower_leaves_map_ele_remove( forks->tower_leaves_map, &fork->parent_slot, NULL, forks->tower_leaves_pool ) ) ) {
    fd_tower_leaves_dlist_ele_remove( forks->tower_leaves_dlist, parent, forks->tower_leaves_pool );
    fd_tower_leaves_pool_ele_release( forks->tower_leaves_pool,  parent );
  }
  fd_tower_leaf_t * leaf = fd_tower_leaves_pool_ele_acquire( forks->tower_leaves_pool );
  leaf->slot = fork->slot;
  fd_tower_leaves_map_ele_insert( forks->tower_leaves_map, leaf, forks->tower_leaves_pool );
  fd_tower_leaves_dlist_ele_push_tail( forks->tower_leaves_dlist, leaf, forks->tower_leaves_pool );

  return fork;
}

fd_tower_forks_t *
fd_forks_insert( fd_forks_t *      forks,
                 ulong             slot,
                 ulong             parent_slot ) {
  fd_tower_forks_t * fork = fd_tower_forks_insert( forks->tower_forks, slot );
  if( FD_UNLIKELY( !fork ) ) return NULL;

  memset( fork, 0, sizeof(fd_tower_forks_t) );
  fork->parent_slot = parent_slot;
  fork->slot        = slot;
  return fork;
}

fd_tower_forks_t *
fd_forks_query( fd_forks_t * forks, ulong slot ) {
  return fd_tower_forks_query( forks->tower_forks, slot, NULL );
}

int
fd_forks_remove( fd_forks_t * forks, ulong slot ) {
  fd_tower_forks_t * fork = fd_tower_forks_query( forks->tower_forks, slot, NULL );
  if( FD_UNLIKELY( !fork ) ) return 0;
  fd_tower_forks_remove( forks->tower_forks, fork );
  fd_tower_leaf_t * leaf = fd_tower_leaves_map_ele_remove( forks->tower_leaves_map, &slot, NULL, forks->tower_leaves_pool );
  if( FD_UNLIKELY( leaf ) ) {
    fd_tower_leaves_dlist_ele_remove( forks->tower_leaves_dlist, leaf, forks->tower_leaves_pool );
    fd_tower_leaves_pool_ele_release( forks->tower_leaves_pool,  leaf );
  }
  return 1; /* success */
}

void
fd_forks_lockouts_add( fd_forks_t * forks, ulong fork_slot, fd_hash_t const * vote_account_pubkey, fd_tower_accts_t * accts ) {
  uchar __attribute__((aligned(FD_TOWER_ALIGN))) scratch[ FD_TOWER_FOOTPRINT ];
  fd_tower_t * scratch_tower = fd_tower_join( fd_tower_new( scratch ) );

  fd_tower_from_vote_acc( scratch_tower, accts->data );

  for( fd_tower_iter_t iter = fd_tower_iter_init( scratch_tower );
                             !fd_tower_iter_done( scratch_tower, iter );
                       iter = fd_tower_iter_next( scratch_tower, iter ) ) {
    fd_tower_t * vote    = fd_tower_iter_ele( scratch_tower, iter );
    ulong interval_start = vote->slot;
    ulong interval_end   = vote->slot + (1UL << vote->conf);
    ulong key = fd_lockout_interval_key( fork_slot, interval_end );

    if( !fd_lockout_intervals_map_ele_query( forks->lockout_intervals_map, &key, NULL, forks->lockout_intervals_pool ) ) {
      /* No other pubkey has yet created [fork_slot, interval_end], so we can add this interval to the slot map linkedlist */
      fd_lockout_slots_t * slot = fd_lockout_slots_pool_ele_acquire( forks->lockout_slots_pool );
      /* map multi, multiple keys for the same fork_slot */
      slot->fork_slot = fork_slot;
      slot->interval_end = interval_end;
      FD_TEST( fd_lockout_slots_map_ele_insert( forks->lockout_slots_map, slot, forks->lockout_slots_pool ) );
    }

    fd_lockout_intervals_t * interval = fd_lockout_intervals_pool_ele_acquire( forks->lockout_intervals_pool );
    interval->key                 = key;
    interval->vote_account_pubkey = *vote_account_pubkey;
    interval->interval_start      = interval_start;
    FD_TEST( fd_lockout_intervals_map_ele_insert( forks->lockout_intervals_map, interval, forks->lockout_intervals_pool ) );
  }
}

void
fd_forks_lockouts_clear( fd_forks_t * forks, ulong fork_slot ) {
  for( fd_lockout_slots_t * slot_interval = fd_lockout_slots_map_ele_remove( forks->lockout_slots_map, &fork_slot, NULL, forks->lockout_slots_pool );
                            slot_interval;
                            slot_interval = fd_lockout_slots_map_ele_remove( forks->lockout_slots_map, &fork_slot, NULL, forks->lockout_slots_pool ) ) {
    ulong key = fd_lockout_interval_key( fork_slot, slot_interval->interval_end );
    for( fd_lockout_intervals_t * itrvl = fd_lockout_intervals_map_ele_remove( forks->lockout_intervals_map, &key, NULL, forks->lockout_intervals_pool );
                                  itrvl;
                                  itrvl = fd_lockout_intervals_map_ele_remove( forks->lockout_intervals_map, &key, NULL, forks->lockout_intervals_pool ) ) {
      fd_lockout_intervals_pool_ele_release( forks->lockout_intervals_pool, itrvl );
    }
    fd_lockout_slots_pool_ele_release( forks->lockout_slots_pool, slot_interval );
  }
}
