#include "fd_gossip_purged.h"
#include "../../util/rng/fd_rng.h"

struct fd_gossip_purged_private {
  fd_crds_purged_t *            pool;
  purged_treap_t *              treap;
  replaced_dlist_t *            replaced_dlist;
  failed_inserts_dlist_t *      failed_inserts_dlist;
  no_contact_info_dlist_t *     no_contact_info_dlist;

  /* Per-origin-pubkey map (MAP_MULTI) for no_contact_info entries.
     When we learn a contact info for a pubkey, we drain all
     associated hashes from the purged treap so peers re-send them.
     Elements live in the purged pool above. */
  nci_origin_map_t *            nci_origin_map;

  fd_gossip_purged_metrics_t    metrics[1];

  ulong magic; /* ==FD_GOSSIP_PURGED_MAGIC */
};

static const long STAKED_EXPIRE_DURATION_NANOS = 432000L*400L*1000L*1000L;
static const long REPLACED_EXPIRE_DURATION_NANOS = 60L*1000L*1000L*1000L;
static const long FAILED_INSERTS_EXPIRE_DURATION_NANOS = 60L*1000L*1000L*1000L;

FD_FN_CONST ulong
fd_gossip_purged_align( void ) {
  return FD_GOSSIP_PURGED_ALIGN;
}

FD_FN_CONST ulong
fd_gossip_purged_footprint( ulong purged_max ) {
  ulong nci_origin_max = fd_ulong_pow2_up( purged_max/4UL );
  ulong l;
  l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, FD_GOSSIP_PURGED_ALIGN,        sizeof(fd_gossip_purged_t) );
  l = FD_LAYOUT_APPEND( l, purged_pool_align(),           purged_pool_footprint( purged_max ) );
  l = FD_LAYOUT_APPEND( l, purged_treap_align(),          purged_treap_footprint( purged_max ) );
  l = FD_LAYOUT_APPEND( l, replaced_dlist_align(),        replaced_dlist_footprint() );
  l = FD_LAYOUT_APPEND( l, failed_inserts_dlist_align(),  failed_inserts_dlist_footprint() );
  l = FD_LAYOUT_APPEND( l, no_contact_info_dlist_align(), no_contact_info_dlist_footprint() );
  l = FD_LAYOUT_APPEND( l, nci_origin_map_align(),        nci_origin_map_footprint( nci_origin_max ) );
  return FD_LAYOUT_FINI( l, FD_GOSSIP_PURGED_ALIGN );
}

void *
fd_gossip_purged_new( void *     shmem,
                      fd_rng_t * rng,
                      ulong      purged_max ) {
  if( FD_UNLIKELY( !shmem ) ) {
    FD_LOG_WARNING(( "NULL shmem" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shmem, fd_gossip_purged_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned shmem" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_pow2( purged_max ) ) ) {
    FD_LOG_WARNING(( "purged_max must be a power of 2" ));
    return NULL;
  }

  if( FD_UNLIKELY( !rng ) ) {
    FD_LOG_WARNING(( "NULL rng" ));
    return NULL;
  }

  ulong nci_origin_max = fd_ulong_pow2_up( purged_max/4UL );

  FD_SCRATCH_ALLOC_INIT( l, shmem );
  fd_gossip_purged_t * purged       = FD_SCRATCH_ALLOC_APPEND( l, FD_GOSSIP_PURGED_ALIGN,          sizeof(fd_gossip_purged_t) );
  void * _pool                      = FD_SCRATCH_ALLOC_APPEND( l, purged_pool_align(),              purged_pool_footprint( purged_max ) );
  void * _treap                     = FD_SCRATCH_ALLOC_APPEND( l, purged_treap_align(),             purged_treap_footprint( purged_max ) );
  void * _replaced_dlist            = FD_SCRATCH_ALLOC_APPEND( l, replaced_dlist_align(),           replaced_dlist_footprint() );
  void * _failed_inserts_dlist      = FD_SCRATCH_ALLOC_APPEND( l, failed_inserts_dlist_align(),     failed_inserts_dlist_footprint() );
  void * _nci_dlist                 = FD_SCRATCH_ALLOC_APPEND( l, no_contact_info_dlist_align(),    no_contact_info_dlist_footprint() );
  void * _nci_origin_map            = FD_SCRATCH_ALLOC_APPEND( l, nci_origin_map_align(),           nci_origin_map_footprint( nci_origin_max ) );
  FD_TEST( FD_SCRATCH_ALLOC_FINI( l, FD_GOSSIP_PURGED_ALIGN ) == (ulong)shmem + fd_gossip_purged_footprint( purged_max ) );

  purged->pool = purged_pool_join( purged_pool_new( _pool, purged_max ) );
  FD_TEST( purged->pool );

  purged->treap = purged_treap_join( purged_treap_new( _treap, purged_max ) );
  FD_TEST( purged->treap );
  purged_treap_seed( purged->pool, purged_max, fd_rng_ulong( rng ) );

  purged->replaced_dlist = replaced_dlist_join( replaced_dlist_new( _replaced_dlist ) );
  FD_TEST( purged->replaced_dlist );

  purged->failed_inserts_dlist = failed_inserts_dlist_join( failed_inserts_dlist_new( _failed_inserts_dlist ) );
  FD_TEST( purged->failed_inserts_dlist );

  purged->no_contact_info_dlist = no_contact_info_dlist_join( no_contact_info_dlist_new( _nci_dlist ) );
  FD_TEST( purged->no_contact_info_dlist );

  purged->nci_origin_map = nci_origin_map_join( nci_origin_map_new( _nci_origin_map, nci_origin_max, fd_rng_ulong( rng ) ) );
  FD_TEST( purged->nci_origin_map );

  memset( purged->metrics, 0, sizeof(fd_gossip_purged_metrics_t) );

  FD_COMPILER_MFENCE();
  FD_VOLATILE( purged->magic ) = FD_GOSSIP_PURGED_MAGIC;
  FD_COMPILER_MFENCE();

  return (void *)purged;
}

fd_gossip_purged_t *
fd_gossip_purged_join( void * shpurged ) {
  if( FD_UNLIKELY( !shpurged ) ) {
    FD_LOG_WARNING(( "NULL shpurged" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shpurged, fd_gossip_purged_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned shpurged" ));
    return NULL;
  }

  fd_gossip_purged_t * purged = (fd_gossip_purged_t *)shpurged;

  if( FD_UNLIKELY( purged->magic!=FD_GOSSIP_PURGED_MAGIC ) ) {
    FD_LOG_WARNING(( "bad magic" ));
    return NULL;
  }

  return purged;
}

fd_gossip_purged_metrics_t const *
fd_gossip_purged_metrics( fd_gossip_purged_t const * purged ) {
  return purged->metrics;
}

ulong
fd_gossip_purged_len( fd_gossip_purged_t const * purged ) {
  return purged_pool_used( purged->pool );
}

static fd_crds_purged_t *
acquire_ele( fd_gossip_purged_t * purged,
             uchar const *        hash,
             ulong                hash_prefix,
             long                 now ) {
  fd_crds_purged_t * ele;
  if( FD_UNLIKELY( !purged_pool_free( purged->pool ) ) ) {
    if( FD_LIKELY( !replaced_dlist_is_empty( purged->replaced_dlist, purged->pool ) ) ) {
      ele = replaced_dlist_ele_pop_head( purged->replaced_dlist, purged->pool );
    } else if( FD_LIKELY( !failed_inserts_dlist_is_empty( purged->failed_inserts_dlist, purged->pool ) ) ) {
      ele = failed_inserts_dlist_ele_pop_head( purged->failed_inserts_dlist, purged->pool );
    } else {
      ele = no_contact_info_dlist_ele_pop_head( purged->no_contact_info_dlist, purged->pool );
      nci_origin_map_ele_remove_fast( purged->nci_origin_map, ele, purged->pool );
    }
    purged_treap_ele_remove( purged->treap, ele, purged->pool );
    purged->metrics->purged_evicted_cnt++;
  } else {
    ele = purged_pool_ele_acquire( purged->pool );
    purged->metrics->purged_cnt++;
  }

  fd_memcpy( ele->hash, hash, 32UL );
  ele->treap.hash_prefix      = hash_prefix;
  ele->expire.wallclock_nanos = now;
  purged_treap_ele_insert( purged->treap, ele, purged->pool );
  return ele;
}

void
fd_gossip_purged_insert_replaced( fd_gossip_purged_t * purged,
                                  uchar const *        hash,
                                  long                 now ) {
  ulong hash_prefix = fd_ulong_load_8( hash );
  if( FD_UNLIKELY( purged_treap_ele_query( purged->treap, hash_prefix, purged->pool ) ) ) return;

  fd_crds_purged_t * ele = acquire_ele( purged, hash, hash_prefix, now );
  replaced_dlist_ele_push_tail( purged->replaced_dlist, ele, purged->pool );
}

void
fd_gossip_purged_insert_failed_insert( fd_gossip_purged_t * purged,
                                       uchar const *        hash,
                                       long                 now ) {
  ulong hash_prefix = fd_ulong_load_8( hash );
  if( FD_UNLIKELY( purged_treap_ele_query( purged->treap, hash_prefix, purged->pool ) ) ) return;

  fd_crds_purged_t * ele = acquire_ele( purged, hash, hash_prefix, now );
  failed_inserts_dlist_ele_push_tail( purged->failed_inserts_dlist, ele, purged->pool );
}

void
fd_gossip_purged_insert_no_contact_info( fd_gossip_purged_t * purged,
                                         uchar const *        origin,
                                         uchar const *        hash,
                                         long                 now ) {
  ulong hash_prefix = fd_ulong_load_8( hash );
  if( FD_UNLIKELY( purged_treap_ele_query( purged->treap, hash_prefix, purged->pool ) ) ) return;

  fd_crds_purged_t * ele = acquire_ele( purged, hash, hash_prefix, now );
  fd_memcpy( ele->origin.uc, origin, 32UL );
  no_contact_info_dlist_ele_push_tail( purged->no_contact_info_dlist, ele, purged->pool );
  nci_origin_map_ele_insert( purged->nci_origin_map, ele, purged->pool );
}

void
fd_gossip_purged_drain_no_contact_info( fd_gossip_purged_t * purged,
                                        uchar const *        origin ) {
  /* Iterate all entries in the MAP_MULTI chain for this origin,
     removing each one.  We use idx-based iteration so we can
     capture the next index before removing the current element
     (which clobbers its chain pointers). */
  fd_pubkey_t const * key = (fd_pubkey_t const *)origin;
  ulong idx = nci_origin_map_idx_query_const( purged->nci_origin_map, key, ULONG_MAX, purged->pool );
  while( idx!=ULONG_MAX ) {
    ulong next_idx = nci_origin_map_idx_next_const( idx, ULONG_MAX, purged->pool );
    fd_crds_purged_t * entry = &purged->pool[ idx ];

    nci_origin_map_ele_remove_fast( purged->nci_origin_map, entry, purged->pool );
    no_contact_info_dlist_ele_remove( purged->no_contact_info_dlist, entry, purged->pool );
    purged_treap_ele_remove( purged->treap, entry, purged->pool );
    purged_pool_ele_release( purged->pool, entry );

    purged->metrics->purged_cnt--;
    idx = next_idx;
  }
}

void
fd_gossip_purged_expire( fd_gossip_purged_t * purged,
                         long                 now ) {
  while( !replaced_dlist_is_empty( purged->replaced_dlist, purged->pool ) ) {
    fd_crds_purged_t * head = replaced_dlist_ele_peek_head( purged->replaced_dlist, purged->pool );

    if( FD_LIKELY( head->expire.wallclock_nanos>now-REPLACED_EXPIRE_DURATION_NANOS ) ) break;

    replaced_dlist_ele_pop_head( purged->replaced_dlist, purged->pool );
    purged_treap_ele_remove( purged->treap, head, purged->pool );
    purged_pool_ele_release( purged->pool, head );

    purged->metrics->purged_cnt--;
    purged->metrics->purged_expired_cnt++;
  }

  while( !failed_inserts_dlist_is_empty( purged->failed_inserts_dlist, purged->pool ) ) {
    fd_crds_purged_t * head = failed_inserts_dlist_ele_peek_head( purged->failed_inserts_dlist, purged->pool );

    /* Agave uses 20 seconds here for failed inserts, but it's a little
       bit short and causes occasional bandwidth jittering.  Use 60
       seconds instead. */
    if( FD_LIKELY( head->expire.wallclock_nanos>now-FAILED_INSERTS_EXPIRE_DURATION_NANOS ) ) break;

    failed_inserts_dlist_ele_pop_head( purged->failed_inserts_dlist, purged->pool );
    purged_treap_ele_remove( purged->treap, head, purged->pool );
    purged_pool_ele_release( purged->pool, head );

    purged->metrics->purged_cnt--;
    purged->metrics->purged_expired_cnt++;
  }

  while( !no_contact_info_dlist_is_empty( purged->no_contact_info_dlist, purged->pool ) ) {
    fd_crds_purged_t * head = no_contact_info_dlist_ele_peek_head( purged->no_contact_info_dlist, purged->pool );

    /* Super long expiry time ... these don't get expired from peer
       tables since they can last up to ~2 days, so we would otherwise
       keep re-requesting these.  Reasonable to just fill the LRU with
       them and let them cycle off then, or of course once we learn the
       contact info of whoever the origin was. */
    if( FD_LIKELY( head->expire.wallclock_nanos>now-STAKED_EXPIRE_DURATION_NANOS ) ) break;

    no_contact_info_dlist_ele_pop_head( purged->no_contact_info_dlist, purged->pool );
    purged_treap_ele_remove( purged->treap, head, purged->pool );
    nci_origin_map_ele_remove_fast( purged->nci_origin_map, head, purged->pool );
    purged_pool_ele_release( purged->pool, head );

    purged->metrics->purged_cnt--;
    purged->metrics->purged_expired_cnt++;
  }
}

fd_gossip_purged_mask_iter_t *
fd_gossip_purged_mask_iter_init( fd_gossip_purged_t const * purged,
                                 ulong                      mask,
                                 uint                       mask_bits,
                                 uchar                      iter_mem[ static 16UL ] ) {
  ulong start_hash, end_hash;
  fd_gossip_purged_generate_masks( mask, mask_bits, &start_hash, &end_hash );

  fd_gossip_purged_mask_iter_t * it = (fd_gossip_purged_mask_iter_t *)iter_mem;
  it->end_hash                      = end_hash;
  it->idx                           = purged_treap_idx_ge( purged->treap, start_hash, purged->pool );
  return it;
}

fd_gossip_purged_mask_iter_t *
fd_gossip_purged_mask_iter_next( fd_gossip_purged_mask_iter_t * it,
                                 fd_gossip_purged_t const *     purged ) {
  fd_crds_purged_t const * val = purged_treap_ele_fast_const( it->idx, purged->pool );
  it->idx                      = val->treap.next;
  return it;
}

int
fd_gossip_purged_mask_iter_done( fd_gossip_purged_mask_iter_t * it,
                                 fd_gossip_purged_t const *     purged ) {
  fd_crds_purged_t const * val = purged_treap_ele_fast_const( it->idx, purged->pool );
  return purged_treap_idx_is_null( it->idx ) || (it->end_hash<val->treap.hash_prefix);
}

uchar const *
fd_gossip_purged_mask_iter_hash( fd_gossip_purged_mask_iter_t * it,
                                 fd_gossip_purged_t const *     purged ) {
  fd_crds_purged_t const * val = purged_treap_ele_fast_const( it->idx, purged->pool );
  return val->hash;
}
