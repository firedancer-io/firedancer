#include "fd_active_set.h"
#include "fd_bloom.h"
#include "fd_active_set_private.h"
#include "fd_gossip_txbuild.h"
#include "fd_gossip_types.h"
#include "fd_gossip_wpeer_sampler.h"
#include "crds/fd_crds.h"


struct fd_active_set_bucket_entry {
  uchar               pubkey[ 32UL ];
  fd_bloom_t *        bloom;
  ulong               entry_idx;
  fd_gossip_txbuild_t push_state[ 1UL ];

  ulong pool_next;

  struct {
    ulong prev;
    ulong next;
  } insert_dlist;

  struct {
    long  wallclock_nanos;
    ulong prev;
    ulong next;
  } last_hit;

};

typedef struct fd_active_set_bucket_entry fd_active_set_bucket_entry_t;

#define POOL_NAME entry_pool
#define POOL_T    fd_active_set_bucket_entry_t
#define POOL_NEXT pool_next
#include "../../util/tmpl/fd_pool.c"

#define DLIST_NAME  bucket_insert_dlist
#define DLIST_ELE_T fd_active_set_bucket_entry_t
#define DLIST_PREV  insert_dlist.prev
#define DLIST_NEXT  insert_dlist.next
#include "../../util/tmpl/fd_dlist.c"

#define DLIST_NAME  last_hit
#define DLIST_ELE_T fd_active_set_bucket_entry_t
#define DLIST_PREV  last_hit.prev
#define DLIST_NEXT  last_hit.next

#include "../../util/tmpl/fd_dlist.c"

struct fd_active_set_bucket_private {
  bucket_insert_dlist_t *        insert_dlist;
  wpeer_sampler_t *              sampler;
  ulong                          cnt;
};

typedef struct fd_active_set_bucket_private fd_active_set_bucket_t;


#define BUCKET_ENTRY_IDX_SENTINEL (USHORT_MAX)
FD_STATIC_ASSERT( FD_ACTIVE_SET_PEERS_PER_BUCKET<BUCKET_ENTRY_IDX_SENTINEL, "ushort not large enough to hold bucket entry index space" );

struct peer_meta {
  ulong  stake;
  ushort bucket_idx[FD_ACTIVE_SET_STAKE_BUCKETS]; /* bucket_idx[i] == BUCKET_ENTRY_IDX_SENTINEL if not in bucket i */
};

typedef struct peer_meta peer_meta_t;
typedef peer_meta_t peer_metas_t[ CRDS_MAX_CONTACT_INFO ];

struct __attribute__((aligned(FD_ACTIVE_SET_ALIGN))) fd_active_set_private {
  fd_active_set_bucket_t *       buckets[ FD_ACTIVE_SET_STAKE_BUCKETS ];
  fd_active_set_bucket_entry_t * entry_pool;
  last_hit_t *                   last_hit;
  peer_metas_t                   peer_metas;

  fd_rng_t * rng;
  ulong      magic; /* ==FD_ACTIVE_SET_MAGIC */
};

ulong
peer_bucket_score( ulong stake,
                   ulong bucket ) {
  ulong peer_bucket = fd_active_set_stake_bucket( stake );
  ulong score       = fd_ulong_sat_add( fd_ulong_min( bucket, peer_bucket ), 1UL );

  return score*score;
}

FD_FN_CONST ulong
fd_active_set_align( void ) {
  return FD_ACTIVE_SET_ALIGN;
}

FD_FN_CONST ulong
fd_active_set_footprint( void ) {
  ulong l;
  l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, FD_ACTIVE_SET_ALIGN, sizeof(fd_active_set_t) );
  l = FD_LAYOUT_APPEND( l, FD_BLOOM_ALIGN,      FD_ACTIVE_SET_MAX_PEERS*fd_bloom_footprint( 0.1, 32768UL ) );
  l = FD_LAYOUT_APPEND( l, entry_pool_align(),  entry_pool_footprint( FD_ACTIVE_SET_MAX_PEERS ) );
  l = FD_LAYOUT_APPEND( l, last_hit_align(),    last_hit_footprint() );

  for( ulong i=0UL; i<FD_ACTIVE_SET_STAKE_BUCKETS; i++ ) {
    l = FD_LAYOUT_APPEND( l, alignof(fd_active_set_bucket_t), sizeof(fd_active_set_bucket_t) );
    l = FD_LAYOUT_APPEND( l, bucket_insert_dlist_align(),     bucket_insert_dlist_footprint() );
    l = FD_LAYOUT_APPEND( l, wpeer_sampler_align(),           wpeer_sampler_footprint( CRDS_MAX_CONTACT_INFO ) );
  }

  return FD_LAYOUT_FINI( l, FD_ACTIVE_SET_ALIGN );
}

void *
fd_active_set_new( void *     shmem,
                   fd_rng_t * rng ) {
  if( FD_UNLIKELY( !shmem ) ) {
    FD_LOG_WARNING(( "NULL shmem" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shmem, fd_active_set_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned shmem" ));
    return NULL;
  }

  ulong bloom_footprint = fd_bloom_footprint( 0.1, 32768UL );

  FD_SCRATCH_ALLOC_INIT( l, shmem );
  fd_active_set_t * as         = FD_SCRATCH_ALLOC_APPEND( l, FD_ACTIVE_SET_ALIGN, sizeof(fd_active_set_t) );
  uchar *           _blooms    = FD_SCRATCH_ALLOC_APPEND( l, FD_BLOOM_ALIGN,      FD_ACTIVE_SET_MAX_PEERS*bloom_footprint );
  void *           _entry_pool = FD_SCRATCH_ALLOC_APPEND( l, entry_pool_align(),  entry_pool_footprint( FD_ACTIVE_SET_MAX_PEERS ) );
  void *           _last_hit   = FD_SCRATCH_ALLOC_APPEND( l, last_hit_align(),    last_hit_footprint() );

  as->entry_pool = entry_pool_join( entry_pool_new( _entry_pool, FD_ACTIVE_SET_MAX_PEERS ) );
  FD_TEST( as->entry_pool );

  as->last_hit   = last_hit_join( last_hit_new( _last_hit ) );
  FD_TEST( as->last_hit );

  as->rng = rng;
  for( ulong i=0UL; i<FD_ACTIVE_SET_STAKE_BUCKETS; i++ ) {

    as->buckets[i]           = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_active_set_bucket_t), sizeof(fd_active_set_bucket_t) );
    void * _insert_dlist     = FD_SCRATCH_ALLOC_APPEND( l, bucket_insert_dlist_align(),     bucket_insert_dlist_footprint() );
    void * _bucket_sampler   = FD_SCRATCH_ALLOC_APPEND( l, wpeer_sampler_align(),           wpeer_sampler_footprint( CRDS_MAX_CONTACT_INFO ) );

    fd_active_set_bucket_t * bucket = as->buckets[ i ];
    bucket->cnt = 0UL;

    bucket->insert_dlist = bucket_insert_dlist_join( bucket_insert_dlist_new( _insert_dlist ) );
    FD_TEST( bucket->insert_dlist );

    bucket->sampler = wpeer_sampler_join( wpeer_sampler_new( _bucket_sampler, CRDS_MAX_CONTACT_INFO ) );
    FD_TEST( bucket->sampler );

  }

  for( ulong i=0UL; i<FD_ACTIVE_SET_MAX_PEERS; i++ ) {
    fd_active_set_bucket_entry_t * peer = entry_pool_ele( as->entry_pool, i );

    peer->bloom = fd_bloom_join( fd_bloom_new( _blooms, rng, 0.1, 32768UL ) );
    if( FD_UNLIKELY( !peer->bloom ) ) {
      FD_LOG_WARNING(( "failed to create bloom filter" ));
      return NULL;
    }
    _blooms += bloom_footprint;
  }
  FD_TEST( FD_SCRATCH_ALLOC_FINI( l, FD_ACTIVE_SET_ALIGN ) == (ulong)shmem + fd_active_set_footprint() );

  FD_COMPILER_MFENCE();
  FD_VOLATILE( as->magic ) = FD_ACTIVE_SET_MAGIC;
  FD_COMPILER_MFENCE();

  return (void *)as;
}

fd_active_set_t *
fd_active_set_join( void * shas ) {
  if( FD_UNLIKELY( !shas ) ) {
    FD_LOG_WARNING(( "NULL shas" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shas, fd_active_set_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned shas" ));
    return NULL;
  }

  fd_active_set_t * as = (fd_active_set_t *)shas;

  if( FD_UNLIKELY( as->magic!=FD_ACTIVE_SET_MAGIC ) ) {
    FD_LOG_WARNING(( "bad magic" ));
    return NULL;
  }

  return as;
}

ulong
fd_active_set_nodes( fd_active_set_t *          active_set,
                     uchar const *              identity_pubkey,
                     ulong                      identity_stake,
                     uchar const *              origin,
                     ulong                      origin_stake,
                     int                        ignore_prunes_if_peer_is_origin,
                     long                       now,
                     fd_active_set_push_state_t out_push_states[ static FD_ACTIVE_SET_PEERS_PER_BUCKET ] ) {
  ulong                    bucket_idx = fd_active_set_stake_bucket( fd_ulong_min( identity_stake, origin_stake ) );
  fd_active_set_bucket_t * bucket     = active_set->buckets[ bucket_idx ];

  int identity_eq_origin = !memcmp( identity_pubkey, origin, 32UL );

  ulong out_idx = 0UL;
  bucket_insert_dlist_iter_t it = bucket_insert_dlist_iter_fwd_init( bucket->insert_dlist, active_set->entry_pool );
  for( ; !bucket_insert_dlist_iter_done        ( it, bucket->insert_dlist, active_set->entry_pool );
         it = bucket_insert_dlist_iter_fwd_next( it, bucket->insert_dlist, active_set->entry_pool ) ) {
    fd_active_set_bucket_entry_t * peer = bucket_insert_dlist_iter_ele( it, bucket->insert_dlist, active_set->entry_pool );

    int must_push_if_peer_is_origin = ignore_prunes_if_peer_is_origin && !memcmp( peer->pubkey, origin, 32UL );
    int must_push_own_values        = identity_eq_origin && !memcmp( peer->pubkey, identity_pubkey, 32UL ); /* why ? */
    if( FD_UNLIKELY( fd_bloom_contains( peer->bloom, origin, 32UL ) && !must_push_own_values && !must_push_if_peer_is_origin ) ) continue;

    out_push_states[ out_idx++ ] = (fd_active_set_push_state_t){
      .txbuild  = peer->push_state,
      .crds_idx = peer->entry_idx
    };

    peer->last_hit.wallclock_nanos = now;
    last_hit_ele_remove   ( active_set->last_hit, peer, active_set->entry_pool );
    last_hit_ele_push_tail( active_set->last_hit, peer, active_set->entry_pool );
  }
  return out_idx;
}

void
fd_active_set_prune( fd_active_set_t * active_set,
                     uchar const *     push_dest,
                     uchar const *     origin,
                     ulong             origin_stake,
                     uchar const *     identity_pubkey,
                     ulong             identity_stake ) {
  if( FD_UNLIKELY( !memcmp( identity_pubkey, origin, 32UL ) ) ) return;

  ulong                    bucket_idx = fd_active_set_stake_bucket( fd_ulong_min( identity_stake, origin_stake ) );
  fd_active_set_bucket_t * bucket     = active_set->buckets[ bucket_idx ];

  bucket_insert_dlist_iter_t it = bucket_insert_dlist_iter_fwd_init( bucket->insert_dlist, active_set->entry_pool );
  for( ; !bucket_insert_dlist_iter_done        ( it, bucket->insert_dlist, active_set->entry_pool );
         it = bucket_insert_dlist_iter_fwd_next( it, bucket->insert_dlist, active_set->entry_pool ) ) {
    fd_active_set_bucket_entry_t * peer = bucket_insert_dlist_iter_ele( it, bucket->insert_dlist, active_set->entry_pool);
    if( FD_UNLIKELY( !memcmp( peer->pubkey, push_dest, 32UL ) ) ) {
      fd_bloom_insert( peer->bloom, origin, 32UL );
      return;
    }
  }
}

void
fd_active_set_rotate( fd_active_set_t *            active_set,
                      fd_crds_t *                  crds,
                      long                         now,
                      fd_active_set_push_state_t * out_maybe_flush )  {
  ulong num_bloom_filter_items = fd_ulong_max( fd_crds_peer_count( crds ), 512UL );

  ulong                    bucket_idx = fd_rng_ulong_roll( active_set->rng, 25UL );
  fd_active_set_bucket_t * bucket     = active_set->buckets[ bucket_idx ];

  ulong                          replace_idx;
  fd_active_set_bucket_entry_t * replace;

  out_maybe_flush->txbuild  = NULL;
  out_maybe_flush->crds_idx = ULONG_MAX;

  ulong crds_idx = wpeer_sampler_sample( bucket->sampler, active_set->rng );
  if( FD_UNLIKELY( crds_idx==SAMPLE_IDX_SENTINEL ) ) return;

  if( FD_LIKELY( bucket->cnt==FD_ACTIVE_SET_PEERS_PER_BUCKET ) ) {
    replace_idx = bucket_insert_dlist_idx_pop_head( bucket->insert_dlist, active_set->entry_pool );
    replace     = entry_pool_ele( active_set->entry_pool, replace_idx );

    ulong crds_idx = replace->entry_idx;

    out_maybe_flush->txbuild  = replace->push_state;
    out_maybe_flush->crds_idx = crds_idx;
    last_hit_idx_remove( active_set->last_hit, replace_idx, active_set->entry_pool );

    /* Replaced peer needs to be reinserted into bucket's sampler */
    peer_meta_t *      e     = &active_set->peer_metas[ crds_idx ];
    ulong                  score = peer_bucket_score( e->stake, bucket_idx );
    e->bucket_idx[ bucket_idx ]  = BUCKET_ENTRY_IDX_SENTINEL;
    wpeer_sampler_upd( bucket->sampler, score, crds_idx );
  } else {
    FD_TEST( !!entry_pool_free( active_set->entry_pool ) );
    replace_idx = entry_pool_idx_acquire( active_set->entry_pool );
    replace     = entry_pool_ele( active_set->entry_pool, replace_idx );
    fd_gossip_txbuild_init( replace->push_state, FD_GOSSIP_MESSAGE_PUSH );
  }

  wpeer_sampler_upd( bucket->sampler, 0UL, crds_idx );

  peer_meta_t * e             = &active_set->peer_metas[ crds_idx ];
  e->bucket_idx[ bucket_idx ] = (ushort)replace_idx;

  fd_contact_info_t const * new_peer = fd_crds_contact_info_idx_lookup( crds, crds_idx );

  replace->entry_idx                = crds_idx;
  replace->last_hit.wallclock_nanos = now;
  fd_bloom_initialize( replace->bloom,  num_bloom_filter_items );
  fd_bloom_insert    ( replace->bloom,  new_peer->pubkey.uc, 32UL );
  fd_memcpy          ( replace->pubkey, new_peer->pubkey.uc, 32UL );
  
  bucket->cnt = fd_ulong_min( bucket->cnt+1UL, FD_ACTIVE_SET_PEERS_PER_BUCKET );
  bucket_insert_dlist_idx_push_tail( bucket->insert_dlist, replace_idx, active_set->entry_pool );

  last_hit_idx_push_tail( active_set->last_hit, replace_idx, active_set->entry_pool );
}

void
fd_active_set_peer_insert( fd_active_set_t * active_set, ulong idx, ulong stake ) {
  /* if IDX is reused, we assumed it was cleaned up with remove peer */
  peer_meta_t * e = &active_set->peer_metas[idx];

  e->stake = stake;
  for( ulong j=0UL; j<FD_ACTIVE_SET_STAKE_BUCKETS; j++ ) {
    e->bucket_idx[j]                 = BUCKET_ENTRY_IDX_SENTINEL;
    wpeer_sampler_t * bucket_sampler = active_set->buckets[j]->sampler;
    ulong             score          = peer_bucket_score( stake, j );
    FD_TEST( !wpeer_sampler_upd( bucket_sampler, score, idx ) );
  }
}

ulong
fd_active_set_peer_remove( fd_active_set_t *          active_set,
                           ulong                      idx,
                           fd_active_set_push_state_t out_evicted_states[ static FD_ACTIVE_SET_STAKE_BUCKETS ] ) {
  ulong flush_cnt = 0UL;
  peer_meta_t * e = &active_set->peer_metas[idx];
  for( ulong j=0UL; j<FD_ACTIVE_SET_STAKE_BUCKETS; j++ ) {

    if( FD_UNLIKELY( e->bucket_idx[j]==BUCKET_ENTRY_IDX_SENTINEL ) ) continue;
    fd_active_set_bucket_t *       bucket = active_set->buckets[j];
    fd_active_set_bucket_entry_t * entry  = entry_pool_ele( active_set->entry_pool, e->bucket_idx[j] );

    fd_active_set_push_state_t * must_flush = &out_evicted_states[flush_cnt++];
    must_flush->txbuild                     = entry->push_state;
    must_flush->crds_idx                    = idx;

    bucket_insert_dlist_idx_remove( bucket->insert_dlist, e->bucket_idx[j], active_set->entry_pool );
    FD_TEST( !!bucket->cnt );
    bucket->cnt--;

    last_hit_idx_remove   ( active_set->last_hit,   e->bucket_idx[j], active_set->entry_pool );
    entry_pool_idx_release( active_set->entry_pool, e->bucket_idx[j] );

    wpeer_sampler_upd( bucket->sampler, 0UL, idx );
  }

  return flush_cnt;
}

void
fd_active_set_peer_update_stake( fd_active_set_t * active_set, ulong idx, ulong new_stake ) {
  peer_meta_t * e = &active_set->peer_metas[idx];

  e->stake = new_stake;
  for( ulong j=0UL; j<FD_ACTIVE_SET_STAKE_BUCKETS; j++ ) {
    /* If peer is in a stake bucket, re-scoring is handled when
       it is removed from bucket in fd_active_set_rotate */
    if( FD_UNLIKELY( e->bucket_idx[j]!=BUCKET_ENTRY_IDX_SENTINEL ) ) continue;
    ulong             score          = peer_bucket_score( new_stake, j );
    wpeer_sampler_t * bucket_sampler = active_set->buckets[j]->sampler;
    FD_TEST( !wpeer_sampler_upd( bucket_sampler, score, idx ) );
  }
}

int
fd_active_set_flush_stale_advance( fd_active_set_t *            active_set,
                                   long                         stale_if_before,
                                   long                         now,
                                   fd_active_set_push_state_t * maybe_flush ) {
  if( FD_LIKELY( last_hit_is_empty( active_set->last_hit, active_set->entry_pool ) ) ) return 0;

  fd_active_set_bucket_entry_t * peer = last_hit_ele_peek_head( active_set->last_hit, active_set->entry_pool );
  if( FD_LIKELY( peer->last_hit.wallclock_nanos>=stale_if_before ) ) return 0;
  maybe_flush->txbuild  = peer->push_state;
  maybe_flush->crds_idx = peer->entry_idx;
  peer->last_hit.wallclock_nanos = now;
  last_hit_ele_pop_head ( active_set->last_hit, active_set->entry_pool );
  last_hit_ele_push_tail( active_set->last_hit, peer, active_set->entry_pool );
  return 1;

}
