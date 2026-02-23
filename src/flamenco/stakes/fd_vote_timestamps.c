#include "fd_vote_timestamps.h"
#include "fd_vote_timestamps_private.h"

ulong
fd_vote_timestamps_align( void ) {
  return 128UL;
}

ulong
fd_vote_timestamps_footprint( ulong max_live_slots,
                              uchar max_snaps,
                              ulong max_vote_accs ) {
  ulong map_chain_cnt = 2048UL;

  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, fd_vote_timestamps_align(), sizeof(fd_vote_timestamps_t) );
  l = FD_LAYOUT_APPEND( l, fork_pool_align(),          fork_pool_footprint( max_live_slots ) );
  l = FD_LAYOUT_APPEND( l, index_pool_align(),         index_pool_footprint( max_vote_accs ) );
  l = FD_LAYOUT_APPEND( l, index_map_align(),          index_map_footprint( map_chain_cnt ) );
  l = FD_LAYOUT_APPEND( l, snapshot_key_dlist_align(), snapshot_key_dlist_footprint() );
  l = FD_LAYOUT_APPEND( l, snapshot_key_pool_align(),  snapshot_key_pool_footprint( max_snaps ) );
  l = FD_LAYOUT_APPEND( l, evict_map_align(),          evict_map_footprint( max_vote_accs ) );
  for( uchar i=0; i<max_snaps; i++ ) {
    l = FD_LAYOUT_APPEND( l, snapshot_map_align(),     snapshot_map_footprint( map_chain_cnt ) );
    l = FD_LAYOUT_APPEND( l, alignof(snapshot_ele_t),  sizeof(snapshot_ele_t)*max_vote_accs );
  }
  return FD_LAYOUT_FINI( l, fd_vote_timestamps_align() );
}

void *
fd_vote_timestamps_new( void * shmem,
                        ulong  max_live_slots,
                        ulong  max_snaps,
                        ulong  max_vote_accs,
                        ulong  seed ) {
  if( FD_UNLIKELY( !shmem ) ) {
    FD_LOG_WARNING(( "NULL mem" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shmem, fd_vote_timestamps_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned mem" ));
    return NULL;
  }

  ulong map_chain_cnt = 2048UL;

  FD_SCRATCH_ALLOC_INIT( l, shmem );
  fd_vote_timestamps_t * vote_timestamps         = FD_SCRATCH_ALLOC_APPEND( l, fd_vote_timestamps_align(), sizeof(fd_vote_timestamps_t) );
  void *                 fork_pool_mem           = FD_SCRATCH_ALLOC_APPEND( l, fork_pool_align(),          fork_pool_footprint( max_live_slots ) );
  void *                 index_pool_mem          = FD_SCRATCH_ALLOC_APPEND( l, index_pool_align(),         index_pool_footprint( max_vote_accs ) );
  void *                 index_map_mem           = FD_SCRATCH_ALLOC_APPEND( l, index_map_align(),          index_map_footprint( map_chain_cnt ) );
  void *                 snapshot_keys_dlist_mem = FD_SCRATCH_ALLOC_APPEND( l, snapshot_key_dlist_align(), snapshot_key_dlist_footprint() );
  void *                 snapshot_keys_pool_mem  = FD_SCRATCH_ALLOC_APPEND( l, snapshot_key_pool_align(),  snapshot_key_pool_footprint( max_snaps ) );
  void *                 evict_map_mem           = FD_SCRATCH_ALLOC_APPEND( l, evict_map_align(),          evict_map_footprint( max_vote_accs ) );

  fork_ele_t * fork_pool = fork_pool_join( fork_pool_new( fork_pool_mem, max_live_slots ) );
  if( FD_UNLIKELY( !fork_pool ) ) {
    FD_LOG_WARNING(( "Failed to create vote timestamp pool" ));
    return NULL;
  }

  index_ele_t * index_pool = index_pool_join( index_pool_new( index_pool_mem, max_vote_accs ) );
  if( FD_UNLIKELY( !index_pool ) ) {
    FD_LOG_WARNING(( "Failed to create vote timestamp index pool" ));
    return NULL;
  }

  index_map_t * index_map = index_map_join( index_map_new( index_map_mem, max_vote_accs, seed ) );
  if( FD_UNLIKELY( !index_map ) ) {
    FD_LOG_WARNING(( "Failed to create vote timestamp index map" ));
    return NULL;
  }

  evict_map_t * evict_map = evict_map_join( evict_map_new( evict_map_mem, max_vote_accs, seed ) );
  if( FD_UNLIKELY( !evict_map ) ) {
    FD_LOG_WARNING(( "Failed to create vote timestamp evict map" ));
    return NULL;
  }

  vote_timestamps->fork_pool_offset  = (ulong)fork_pool - (ulong)shmem;
  vote_timestamps->index_pool_offset = (ulong)index_pool - (ulong)shmem;
  vote_timestamps->index_map_offset  = (ulong)index_map - (ulong)shmem;
  vote_timestamps->evict_map_offset  = (ulong)evict_map - (ulong)shmem;

  snapshot_key_ele_t * snapshot_keys_pool = snapshot_key_pool_join( snapshot_key_pool_new( snapshot_keys_pool_mem, max_snaps ) );
  if( FD_UNLIKELY( !snapshot_keys_pool ) ) {
    FD_LOG_WARNING(( "Failed to create vote timestamp snapshot keys pool" ));
    return NULL;
  }
  FD_LOG_WARNING(("SNAPSHOT KEYS POOL FREE: %lu", snapshot_key_pool_free( snapshot_keys_pool )));

  snapshot_key_dlist_t * snapshot_keys = snapshot_key_dlist_join( snapshot_key_dlist_new( snapshot_keys_dlist_mem ) );
  if( FD_UNLIKELY( !snapshot_keys ) ) {
    FD_LOG_WARNING(( "Failed to create vote timestamp snapshot keys" ));
    return NULL;
  }

  FD_LOG_WARNING(("SNAPSHOT KEYS POOL FREE: %lu", snapshot_key_pool_free( snapshot_keys_pool )));

  for( uchar i=0; i<max_snaps; i++ ) {
    snapshot_key_ele_t * key = snapshot_key_pool_ele( snapshot_keys_pool, i );
    void * snapshots_ele_map_mem = FD_SCRATCH_ALLOC_APPEND( l, snapshot_map_align(), snapshot_map_footprint( map_chain_cnt ) );
    void * snapshots_mem         = FD_SCRATCH_ALLOC_APPEND( l, alignof(snapshot_ele_t), sizeof(snapshot_ele_t)*max_vote_accs );
    key->offset = (ulong)snapshots_mem - (ulong)vote_timestamps;

    snapshot_map_t * snapshot_map = snapshot_map_join( snapshot_map_new( snapshots_ele_map_mem, map_chain_cnt, seed ) );
    if( FD_UNLIKELY( !snapshot_map ) ) {
      FD_LOG_WARNING(( "Failed to create vote timestamp snapshot ele map" ));
      return NULL;
    }

    key->map_offset = (ulong)snapshot_map - (ulong)vote_timestamps;
  }
  FD_SCRATCH_ALLOC_FINI( l, fd_vote_timestamps_align() );

  vote_timestamps->snapshot_keys_dlist_offset = (ulong)snapshot_keys - (ulong)shmem;
  vote_timestamps->snapshot_keys_pool_offset  = (ulong)snapshot_keys_pool - (ulong)shmem;

  snapshot_key_ele_t * skp = fd_vote_timestamps_get_snapshot_keys_pool( vote_timestamps );
  snapshot_key_ele_t * skp_2 = (snapshot_key_ele_t *)((uchar *)shmem + vote_timestamps->snapshot_keys_pool_offset);

  FD_LOG_WARNING(("SNAPSHOT KEYS POOL FREE: %lu", snapshot_key_pool_free( skp )));
  FD_LOG_WARNING(("SNAPSHOT KEYS POOL FREE: %lu", snapshot_key_pool_free( skp_2 )));
  FD_LOG_WARNING(("SNAPSHOT KEYS POOL FREE: %lu", snapshot_key_pool_free( snapshot_keys_pool )));


  return shmem;
}

fd_vote_timestamps_t *
fd_vote_timestamps_join( void * shmem ) {
  return (fd_vote_timestamps_t *)shmem;
}

ushort
fd_vote_timestamps_init( fd_vote_timestamps_t * vote_ts,
                         ulong                  slot,
                         ushort                 epoch ) {
  /* Allocate a new fork and snapshot for the root. */

  fork_ele_t * pool     = fd_vote_timestamps_get_fork_pool( vote_ts );
  fork_ele_t * fork     = fork_pool_ele_acquire( pool );
  ushort       fork_idx = (ushort)fork_pool_idx( pool, fork );

  vote_ts->root_idx = fork_idx;
  fork->parent_idx  = USHORT_MAX;
  fork->child_idx   = USHORT_MAX;
  fork->sibling_idx = USHORT_MAX;
  fork->slot        = slot;
  fork->epoch       = epoch;

  snapshot_key_ele_t *   snapshot_keys_pool  = fd_vote_timestamps_get_snapshot_keys_pool( vote_ts );
  snapshot_key_dlist_t * snapshot_keys_dlist = fd_vote_timestamps_get_snapshot_keys_dlist( vote_ts );
  snapshot_key_ele_t *   new_key             = snapshot_key_pool_ele_acquire( snapshot_keys_pool );
  ulong                  snapshot_idx        = snapshot_key_pool_idx( snapshot_keys_pool, new_key );
  fork->snapshot_idx = (uchar)snapshot_idx;

  snapshot_key_dlist_ele_push_tail( snapshot_keys_dlist, new_key, snapshot_keys_pool );
  snapshot_map_t * snapshot_map = fd_vote_timestamps_get_snapshot_map( vote_ts, fork->snapshot_idx );
  snapshot_map_reset( snapshot_map );

  return fork_idx;
}

ushort
fd_vote_timestamps_attach_child( fd_vote_timestamps_t * vote_ts,
                                 ushort                 parent_fork_idx,
                                 ulong                  slot,
                                 ushort                 epoch ) {

  fork_ele_t * pool = fd_vote_timestamps_get_fork_pool( vote_ts );

  FD_CRIT( fork_pool_free( pool )!=0UL, "No free slots in vote timestamp pool" );

  fork_ele_t * child     = fork_pool_ele_acquire( pool );
  ushort       child_idx = (ushort)fork_pool_idx( pool, child );


  fork_ele_t * parent = fork_pool_ele( pool, parent_fork_idx );
  FD_CRIT( parent, "parent fork idx not found" );

  child->parent_idx = parent_fork_idx;

  if( FD_LIKELY( parent->child_idx==USHORT_MAX ) ) {
    parent->child_idx = child_idx;
  } else {
    fork_ele_t * curr = fork_pool_ele( pool, parent->child_idx );
    /* Assign child as the sibling pointer of rightmost child. */
    while( curr->sibling_idx!=USHORT_MAX ) {
      curr = fork_pool_ele( pool, curr->sibling_idx );
    }
    curr->sibling_idx = child_idx;
  }

  child->sibling_idx  = USHORT_MAX;
  child->child_idx    = USHORT_MAX;
  child->slot         = slot;
  child->epoch        = epoch;
  child->deltas_cnt   = 0UL;
  child->snapshot_idx = UCHAR_MAX;

  return child_idx;
}

static void
apply_root_delta( fd_vote_timestamps_t *    vote_ts,
                  fork_ele_t * new_root,
                  fork_ele_t * old_root ) {

  index_ele_t * index_pool = fd_vote_timestamps_get_index_pool( vote_ts );

  snapshot_map_t * snapshot_map = fd_vote_timestamps_get_snapshot_map( vote_ts, old_root->snapshot_idx );
  snapshot_ele_t *     snapshot     = fd_vote_timestamps_get_snapshot( vote_ts, old_root->snapshot_idx );

  /* NOTE: It's okay for the snapshot to have the incorrect slot age
     here because we don't use the slot age after the snapshot is
     computed. */
  for( ushort i=0; i<new_root->deltas_cnt; i++ ) {
    /* There is a nice property that timestamps always increase for the
       same pubkey on the same fork.  When a pubkey is evicted from the
       index, then we will clear all entries for that pubkey in all
       snapshots in the case it gets renewed. */
    delta_ele_t * delta = &new_root->deltas[i];

    index_ele_t * ele = index_pool_ele( index_pool, delta->pubkey_idx );
    ele->refcnt--;

    snapshot_ele_t * snapshot_ele = snapshot_map_ele_query( snapshot_map, &delta->pubkey_idx, NULL, snapshot );
    if( FD_LIKELY( snapshot_ele ) ) {
      snapshot_ele->idx       = delta->pubkey_idx;
      snapshot_ele->timestamp = delta->timestamp;
      snapshot_ele->slot_age  = new_root->slot - old_root->slot;
    } else {
      snapshot_ele            = &snapshot[delta->pubkey_idx];
      snapshot_ele->idx       = delta->pubkey_idx;
      snapshot_ele->timestamp = delta->timestamp;
      snapshot_ele->slot_age  = new_root->slot - old_root->slot;
      snapshot_map_ele_insert( snapshot_map, snapshot_ele, snapshot );
    }
  }
  /* We no longer need the deltas here so we can clear them. */
  new_root->deltas_cnt = 0;
}

void
fd_vote_timestamps_advance_root( fd_vote_timestamps_t * vote_ts,
                                 ushort                 new_root_idx ) {
  fork_ele_t * pool     = fd_vote_timestamps_get_fork_pool( vote_ts );
  fork_ele_t * new_root = fork_pool_ele( pool, new_root_idx );
  fork_ele_t * head     = fork_pool_ele( pool, vote_ts->root_idx );

  FD_CRIT( new_root->parent_idx==vote_ts->root_idx, "new root is not a child of the current root" );

  snapshot_key_ele_t * snapshot_keys_pool = fd_vote_timestamps_get_snapshot_keys_pool( vote_ts );
  snapshot_key_ele_t * old_root_key       = snapshot_key_pool_ele( snapshot_keys_pool, head->snapshot_idx );
  if( FD_UNLIKELY( new_root->snapshot_idx!=UCHAR_MAX ) ) {
    /* If the new root has a snapshot, we just need to decrement the
       refcnt of all deltas in the new root and release the snapshot
       for the old root. */
    old_root_key->fork_idx = USHORT_MAX;
    head->snapshot_idx     = UCHAR_MAX;

    index_ele_t * index_pool = fd_vote_timestamps_get_index_pool( vote_ts );
    for( ushort i=0; i<new_root->deltas_cnt; i++ ) {
      delta_ele_t * delta = &new_root->deltas[i];
      index_ele_t * ele   = index_pool_ele( index_pool, delta->pubkey_idx );
      ele->refcnt--;
    }
    new_root->deltas_cnt = 0;

    snapshot_key_dlist_t * dlist = fd_vote_timestamps_get_snapshot_keys_dlist( vote_ts );
    snapshot_key_dlist_idx_remove( dlist, head->snapshot_idx, snapshot_keys_pool );
    snapshot_key_pool_ele_release( snapshot_keys_pool, old_root_key );
  } else {
    /* This means that we need to apply the delta from the new root onto
       the old root's snapshot.  Then transfer ownership of the snapshot
       to the new_root. */
    FD_LOG_WARNING(("ADVANCING ROOT TO NODE WITHOUT SNAPSHOT"));
    apply_root_delta( vote_ts, new_root, head );

    old_root_key->fork_idx = new_root_idx;
    new_root->snapshot_idx = head->snapshot_idx;
    head->snapshot_idx     = UCHAR_MAX;
  }

  head->next = USHORT_MAX;
  fork_ele_t * tail = head;
  while( head ) {
    fork_ele_t * child = fork_pool_ele( pool, head->child_idx );

    while( FD_LIKELY( child ) ) {

      if( FD_LIKELY( child!=new_root ) ) {

        /* Update tail pointers */
        tail->next = (ushort)fork_pool_idx( pool, child );
        tail       = fork_pool_ele( pool, tail->next );
        tail->next = USHORT_MAX;
      }

      child = fork_pool_ele( pool, child->sibling_idx );
    }

    fork_ele_t * next = fork_pool_ele( pool, head->next );

    if( FD_UNLIKELY( head->snapshot_idx!=UCHAR_MAX ) ) {
      snapshot_key_ele_t * key = snapshot_key_pool_ele( snapshot_keys_pool, head->snapshot_idx );
      key->fork_idx      = USHORT_MAX;
      head->snapshot_idx = UCHAR_MAX;
      snapshot_key_dlist_t * dlist = fd_vote_timestamps_get_snapshot_keys_dlist( vote_ts );
      snapshot_key_dlist_idx_remove( dlist, head->snapshot_idx, snapshot_keys_pool );
      snapshot_key_pool_ele_release( snapshot_keys_pool, key );
    }

    index_ele_t * index_pool = fd_vote_timestamps_get_index_pool( vote_ts );
    for( ushort i=0; i<head->deltas_cnt; i++ ) {
      delta_ele_t * delta = &head->deltas[i];
      index_ele_t * ele = index_pool_ele( index_pool, delta->pubkey_idx );
      ele->refcnt--;
    }
    head->deltas_cnt = 0;

    fork_pool_ele_release( pool, head );
    head = next;
  }

  new_root->parent_idx = USHORT_MAX;
  vote_ts->root_idx    = new_root_idx;

  /* Now clear all evictable entries from the index.  Only remove the
     entry if it has no references. */
  uint evict_cnt = 0U;
  uint evict_idxs[ USHORT_MAX ];
  index_ele_t * index_pool = fd_vote_timestamps_get_index_pool( vote_ts );
  index_map_t * index_map  = fd_vote_timestamps_get_index_map( vote_ts );
  evict_map_t * evict_map  = fd_vote_timestamps_get_evict_map( vote_ts );
  for( evict_map_iter_t iter = evict_map_iter_init( evict_map, index_pool );
       !evict_map_iter_done( iter, evict_map, index_pool );
       iter = evict_map_iter_next( iter, evict_map, index_pool ) ) {
    index_ele_t * ele = evict_map_iter_ele( iter, evict_map, index_pool );
    evict_idxs[ evict_cnt ] = (uint)index_pool_idx( index_pool, ele );
    evict_cnt++;
  }

  for( uint i=0; i<evict_cnt; i++ ) {
    index_ele_t * ele = index_pool_ele( index_pool, evict_idxs[i] );
    if( FD_UNLIKELY( ele->refcnt>0 ) ) continue;

    evict_map_ele_remove( evict_map, &index_pool_ele( index_pool, evict_idxs[i] )->pubkey, NULL, index_pool );
    index_map_ele_remove( index_map, &index_pool_ele( index_pool, evict_idxs[i] )->pubkey, NULL, index_pool );
    index_pool_ele_release( index_pool, ele );
  }

}

void
fd_vote_timestamps_insert( fd_vote_timestamps_t * vote_ts,
                           ushort                 fork_idx,
                           fd_pubkey_t            pubkey,
                           ulong                  timestamp,
                           ulong                  stake ) {
  /* First update and query index.  Figure out pubkey index if not one
     exists, otherwise allocate a new entry in the index. */
  index_ele_t * index_pool = fd_vote_timestamps_get_index_pool( vote_ts );
  index_map_t * index_map  = fd_vote_timestamps_get_index_map( vote_ts );

  fork_ele_t * fork_pool = fd_vote_timestamps_get_fork_pool( vote_ts );
  fork_ele_t * fork      = fork_pool_ele( fork_pool, fork_idx );

  index_ele_t * ele = index_map_ele_query( index_map, &pubkey, NULL, index_pool );
  if( FD_LIKELY( ele ) ) {
    ele->refcnt++;
  } else {
    FD_LOG_NOTICE(("INSERTING NEW ELE"));
    ele = index_pool_ele_acquire( index_pool );
    ele->pubkey = pubkey;
    ele->refcnt = 1UL;
    ele->epoch_stakes[ fork->epoch % 2UL ] = stake;
    FD_TEST( index_map_ele_insert( index_map, ele, index_pool ) );
  }

  uint pubkey_idx = (uint)index_pool_idx( index_pool, ele );

  /* Now just add the entry to the delta list. */
  delta_ele_t * delta = &fork->deltas[ fork->deltas_cnt ];
  delta->timestamp  = timestamp;
  delta->pubkey_idx = pubkey_idx;
  fork->deltas_cnt++;

}

void
fd_vote_timestamps_insert_root( fd_vote_timestamps_t * vote_ts,
                                fd_pubkey_t            pubkey,
                                ulong                  timestamp,
                                ulong                  stake ) {

  /* First update and query index.  Figure out pubkey index if not one
     exists, otherwise allocate a new entry in the index. */
  index_ele_t * index_pool = fd_vote_timestamps_get_index_pool( vote_ts );
  index_map_t * index_map  = fd_vote_timestamps_get_index_map( vote_ts );

  fork_ele_t * fork_pool = fd_vote_timestamps_get_fork_pool( vote_ts );
  fork_ele_t * fork      = fork_pool_ele( fork_pool, vote_ts->root_idx );

  index_ele_t * ele = index_pool_ele_acquire( index_pool );
  ele->pubkey = pubkey;
  ele->refcnt = 0UL;
  ele->epoch_stakes[ fork->epoch % 2UL ] = stake;

  FD_TEST( index_map_ele_insert( index_map, ele, index_pool ) );
  uint pubkey_idx = (uint)index_pool_idx( index_pool, ele );

  snapshot_ele_t *     snapshot     = fd_vote_timestamps_get_snapshot( vote_ts, fork->snapshot_idx );
  snapshot_map_t * snapshot_map = fd_vote_timestamps_get_snapshot_map( vote_ts, fork->snapshot_idx );

  snapshot_ele_t * snapshot_ele = &snapshot[pubkey_idx];
  snapshot_ele->idx             = pubkey_idx;
  snapshot_ele->timestamp       = timestamp;
  snapshot_ele->slot_age        = 0;
  snapshot_map_ele_insert( snapshot_map, snapshot_ele, snapshot );
}

static uchar
prune_and_get_snapshot( fd_vote_timestamps_t * vote_ts,
                        ushort                 fork_idx,
                        ushort *               parent_snapshot_path,
                        ushort *               parent_snapshot_path_cnt ) {
  /* A reasonable eviction policy here is LRU eviction with some tweaks:
     1. Never evict the root snapshot
     2. Don't evict the "best" snapshot (closest to the fork idx) */
  fork_ele_t * fork_pool = fd_vote_timestamps_get_fork_pool( vote_ts );
  fork_ele_t * fork      = fork_pool_ele( fork_pool, fork_idx );
  fork_ele_t * root      = fork_pool_ele( fork_pool, vote_ts->root_idx );

  /* Find best snapshot to build off of.  Always prioritize the least
     amount of deltas.  This is purely a policy decision. */
  parent_snapshot_path[ *parent_snapshot_path_cnt ] = (ushort)fork_pool_idx( fork_pool, fork );
  (*parent_snapshot_path_cnt)++;

  fork_ele_t * curr = fork;
  while( curr->snapshot_idx==UCHAR_MAX ) {
    curr = fork_pool_ele( fork_pool, curr->parent_idx );
    parent_snapshot_path[*parent_snapshot_path_cnt] = (ushort)fork_pool_idx( fork_pool, curr );
    (*parent_snapshot_path_cnt)++;
  }

  uchar best_snapshot_idx = curr->snapshot_idx;
  uchar root_snapshot_idx = root->snapshot_idx;

  FD_LOG_NOTICE(("PATH CNT %u BEST %u, ROOT %u", *parent_snapshot_path_cnt, best_snapshot_idx, root_snapshot_idx));

  snapshot_key_dlist_t * snapshot_keys_dlist = fd_vote_timestamps_get_snapshot_keys_dlist( vote_ts );
  snapshot_key_ele_t *   snapshot_keys_pool  = fd_vote_timestamps_get_snapshot_keys_pool( vote_ts );

  FD_LOG_WARNING(("SNAPSHOT KEYS POOL FREE: %lu", snapshot_key_pool_free( snapshot_keys_pool )));

  if( FD_UNLIKELY( snapshot_key_pool_free( snapshot_keys_pool )==0UL ) ) {
    FD_LOG_NOTICE(("NO FREE SNAPSHOT KEYS"));
    /* If there are no free slots in the pool, we need to evict. */

    snapshot_key_ele_t * key = snapshot_key_dlist_ele_pop_head( snapshot_keys_dlist, snapshot_keys_pool );
    uchar                idx = (uchar)snapshot_key_pool_idx( snapshot_keys_pool, key );
    /* TODO: MAKE IT SO THE ROOTED BANK ISN'T IN THE DLIST */
    if( idx==root_snapshot_idx || idx==best_snapshot_idx ) {
      snapshot_key_dlist_ele_push_tail( snapshot_keys_dlist, key, snapshot_keys_pool );
      key = snapshot_key_dlist_ele_pop_head( snapshot_keys_dlist, snapshot_keys_pool );
      idx = (uchar)snapshot_key_pool_idx( snapshot_keys_pool, key );
    }
    if( idx==root_snapshot_idx || idx==best_snapshot_idx ) {
      snapshot_key_dlist_ele_push_tail( snapshot_keys_dlist, key, snapshot_keys_pool );
      key = snapshot_key_dlist_ele_pop_head( snapshot_keys_dlist, snapshot_keys_pool );
      idx = (uchar)snapshot_key_pool_idx( snapshot_keys_pool, key );
    }
    FD_LOG_NOTICE(("EVICTED KEY IDX: %u", idx));
    fork_ele_t * fork = fork_pool_ele( fork_pool, key->fork_idx );
    fork->snapshot_idx = UCHAR_MAX;
    key->fork_idx      = USHORT_MAX;
    snapshot_key_pool_ele_release( snapshot_keys_pool, key );
  }

  snapshot_key_ele_t * new_key = snapshot_key_pool_ele_acquire( snapshot_keys_pool );
  new_key->fork_idx = fork_idx;
  FD_LOG_NOTICE(("SNAPSHOT KEY IDX: %u", (uchar)snapshot_key_pool_idx( snapshot_keys_pool, new_key )));
  snapshot_key_dlist_ele_push_tail( snapshot_keys_dlist, new_key, snapshot_keys_pool );
  return (uchar)snapshot_key_pool_idx( snapshot_keys_pool, new_key );
}

static void
apply_snapshot( fd_vote_timestamps_t * vote_ts,
                snapshot_ele_t *     snapshot,
                snapshot_map_t * snapshot_map,
                ulong                base_slot,
                snapshot_ele_t *     prev_snapshot,
                snapshot_map_t * prev_snapshot_map,
                ulong                prev_slot ) {

  (void)vote_ts;
  //evict_map_t * evict_map = fd_vote_timestamps_get_evict_map( vote_ts );
  //index_ele_t * index_pool = fd_vote_timestamps_get_index_pool( vote_ts );

  for( snapshot_map_iter_t iter = snapshot_map_iter_init( prev_snapshot_map, prev_snapshot );
       !snapshot_map_iter_done( iter, prev_snapshot_map, prev_snapshot );
       iter = snapshot_map_iter_next( iter, prev_snapshot_map, prev_snapshot ) ) {
    uint ele_idx = (uint)snapshot_map_iter_idx( iter, prev_snapshot_map, prev_snapshot );

    snapshot_ele_t * snapshot_ele = snapshot_map_ele_query( snapshot_map, &ele_idx, NULL, snapshot );
    if( FD_LIKELY( snapshot_ele ) ) continue;
    snapshot_ele            = &snapshot[ele_idx];
    snapshot_ele->idx       = (uint)ele_idx;
    snapshot_ele->timestamp = prev_snapshot[ele_idx].timestamp;
    snapshot_ele->slot_age  = snapshot_ele->slot_age + (base_slot - prev_slot);
    snapshot_map_ele_insert( snapshot_map, snapshot_ele, snapshot );
  }
}

static void
apply_delta( ulong                     base_slot,
             snapshot_ele_t *          snapshot,
             snapshot_map_t *      snapshot_map,
             fork_ele_t * fork ) {

  FD_LOG_NOTICE(("APPLYING DELTAS %u", fork->deltas_cnt));
  for( ushort i=0; i<fork->deltas_cnt; i++ ) {
    /* We have the property that timestamps are always increasing for
       the same pubkey.  When a pubkey is evicted from the index, then
       we will clear all entries for that pubkey in all snapshots in the
       case it gets renewed. */
    delta_ele_t * delta = &fork->deltas[i];
    snapshot_ele_t * snapshot_ele = snapshot_map_ele_query( snapshot_map, &delta->pubkey_idx, NULL, snapshot );
    if( FD_UNLIKELY( snapshot_ele ) ) {
      /* If it is already found do nothing */
    } else {
      snapshot_ele            = &snapshot[delta->pubkey_idx];
      snapshot_ele->idx       = delta->pubkey_idx;
      snapshot_ele->timestamp = delta->timestamp;
      snapshot_ele->slot_age  = base_slot - fork->slot;
      FD_LOG_WARNING(("APPLYING DELTAS %u %lu", delta->pubkey_idx, snapshot_ele->timestamp));
      snapshot_map_ele_insert( snapshot_map, snapshot_ele, snapshot );
    }
  }
}

ulong
fd_vote_timestamps_get_timestamp( fd_vote_timestamps_t * vote_ts,
                                  ushort                 fork_idx ) {
  fork_ele_t * fork_pool = fd_vote_timestamps_get_fork_pool( vote_ts );
  fork_ele_t * fork      = fork_pool_ele( fork_pool, fork_idx );

  ushort path[ USHORT_MAX ];
  ushort path_cnt = 0;
  fork->snapshot_idx = prune_and_get_snapshot( vote_ts, fork_idx, path, &path_cnt );
  FD_LOG_NOTICE(("snapshot idx: %u", fork->snapshot_idx));
  snapshot_ele_t * snapshot     = fd_vote_timestamps_get_snapshot( vote_ts, fork->snapshot_idx );
  snapshot_map_t * snapshot_map = fd_vote_timestamps_get_snapshot_map( vote_ts, fork->snapshot_idx );
  snapshot_map_reset( snapshot_map );

  /* We now have the path of all of the vote timestamp entries that we
     have to apply.  We also have the snapshot index that we can use to
     get the timestamp.  We want to iterate backwards through the fork
     indices and apply the deltas. */
  for( ushort i=0; i<path_cnt-1; i++ ) {
    FD_LOG_WARNING(("APPLYING DELTAS FOR INDEX %u", path[i]));
    apply_delta( fork->slot, snapshot, snapshot_map, fork_pool_ele( fork_pool, path[i] ) );
  }
  fork_ele_t * curr_fork = fork_pool_ele( fork_pool, path[path_cnt-1] );

  /* Finally, we need to apply the previous snapshot to the current
     snapshot. */
  snapshot_ele_t * prev_snapshot     = fd_vote_timestamps_get_snapshot( vote_ts, curr_fork->snapshot_idx );
  snapshot_map_t * prev_snapshot_map = fd_vote_timestamps_get_snapshot_map( vote_ts, curr_fork->snapshot_idx );
  apply_snapshot( vote_ts, snapshot, snapshot_map, fork->slot, prev_snapshot, prev_snapshot_map, curr_fork->slot );

  index_ele_t * index_pool = fd_vote_timestamps_get_index_pool( vote_ts );

  /* Iterate through the snapshot to get the stake for each pubkey. */

  ulong ts_ele_cnt = 0UL;
  uint128 total_stake = 0UL;
  for( snapshot_map_iter_t iter = snapshot_map_iter_init( snapshot_map, snapshot );
       !snapshot_map_iter_done( iter, snapshot_map, snapshot );
       iter = snapshot_map_iter_next( iter, snapshot_map, snapshot ) ) {
    uint             ele_idx      = (uint)snapshot_map_iter_idx( iter, snapshot_map, snapshot );
    snapshot_ele_t * snapshot_ele = snapshot_map_iter_ele( iter, snapshot_map, snapshot );
    index_ele_t *    ele          = index_pool_ele( index_pool, ele_idx );

    ulong stake      = ele->epoch_stakes[ fork->epoch % 2UL ];
    ulong timestamp  = snapshot_ele->timestamp;
    ulong slot_delta = snapshot_ele->slot_age;

    /* TODO:FIXME: get the right slot duration on boot */
    ulong offset   = fd_ulong_sat_mul( 400e9, slot_delta );
    ulong estimate = timestamp + (offset / ((ulong)1e9));
    FD_LOG_NOTICE(("IDX %u DISTANCE %lu TIMESTAMP %lu ESTIMATE %lu STAKE %lu", ele_idx, slot_delta, timestamp, estimate, stake));

    vote_ts->ts_eles[ ts_ele_cnt ] = (ts_est_ele_t){
      .timestamp = estimate,
      .stake     = { .ud=stake },
    };
    ts_ele_cnt++;

    total_stake += stake;
  }

  sort_stake_ts_inplace( vote_ts->ts_eles, ts_ele_cnt );

  /* Populate estimate with the stake-weighted median timestamp.
    https://github.com/anza-xyz/agave/blob/v2.3.7/runtime/src/stake_weighted_timestamp.rs#L59-L68 */
  uint128 stake_accumulator = 0;
  ulong   estimate          = 0UL;
  for( ulong i=0UL; i<ts_ele_cnt; i++ ) {
    stake_accumulator = fd_uint128_sat_add( stake_accumulator, vote_ts->ts_eles[i].stake.ud );
    if( stake_accumulator>(total_stake/2UL) ) {
      estimate = vote_ts->ts_eles[ i ].timestamp;
      break;
    }
  }
  return estimate;

  /* TODO: Let the runtime handle the timestamp adjusting. */

}
