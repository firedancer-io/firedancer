#include "fd_prune_finder.h"
#include "../../util/log/fd_log.h"

/* Maximum number of origins tracked in the outer map.  Matches
   Agave's ReceivedCache capacity of 2 * CRDS_UNIQUE_PUBKEY_CAPACITY. */
#define FD_PRUNE_FINDER_ORIGIN_MAX (16384UL)

/* Maximum number of relayers tracked per origin.  Matches Agave's
   ReceivedCacheEntry::CAPACITY.  When the inner map is full, new
   relayers are silently dropped (score-0 entries are pruned first,
   so an attacker cannot displace good relayers). */
#define FD_PRUNE_FINDER_RELAYER_MAX (50UL)

/* Minimum number of fresh (num_dups==0) messages recorded for an
   origin before a prune decision is made.  Matches Agave's
   ReceivedCache::MIN_NUM_UPSERTS. */
#define FD_PRUNE_FINDER_MIN_NUM_UPSERTS (20UL)

/* Minimum number of relayers to keep (never pruned) per origin,
   regardless of score or stake.  Matches Agave's
   CRDS_GOSSIP_PRUNE_MIN_INGRESS_NODES. */
#define FD_PRUNE_FINDER_MIN_INGRESS_NODES (2UL)

/* Fraction of stake that must be covered before additional relayers
   can be pruned.  min_ingress_stake = min(identity_stake, origin_stake)
   * FD_PRUNE_FINDER_STAKE_THRESHOLD_PCT / 100.  Matches Agave's
   CRDS_GOSSIP_PRUNE_STAKE_THRESHOLD_PCT = 0.15. */
#define FD_PRUNE_FINDER_STAKE_THRESHOLD_PCT (15UL)

/* Number of duplicates below which a relayer is considered timely
   (its score is incremented).  Matches Agave's
   ReceivedCacheEntry::NUM_DUPS_THRESHOLD. */
#define FD_PRUNE_FINDER_NUM_DUPS_THRESHOLD (2UL)

struct pubkey_private {
  uchar b[ 32UL ];
};

typedef struct pubkey_private pubkey_private_t;

/* fd_prune_relayer stores the score for a single relayer within an
   origin entry.  The score counts how many times this relayer was
   among the first NUM_DUPS_THRESHOLD (2) to deliver a message from
   this origin.  relayer_stake is cached at insertion time. */

struct fd_prune_relayer {
  uchar pubkey[ 32UL ];
  ulong score;
  ulong stake;
};

typedef struct fd_prune_relayer fd_prune_relayer_t;

/* fd_prune_origin is an entry in the outer map, keyed by origin
   pubkey.  It tracks all known relayers for that origin and the
   number of fresh (num_dups==0) messages received. */

struct fd_prune_origin {
  pubkey_private_t origin_pubkey;

  ulong num_upserts;
  ulong origin_stake;
  ulong relayers_cnt;
  fd_prune_relayer_t relayers[ FD_PRUNE_FINDER_RELAYER_MAX ];

  ulong pool_next;

  ulong map_next;
  ulong map_prev;

  ulong lru_prev;
  ulong lru_next;
};

typedef struct fd_prune_origin fd_prune_origin_t;

#define POOL_NAME pool
#define POOL_NEXT pool_next
#define POOL_T    fd_prune_origin_t
#include "../../util/tmpl/fd_pool.c"

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-value"
#define DLIST_NAME  lru_list
#define DLIST_ELE_T fd_prune_origin_t
#define DLIST_PREV  lru_prev
#define DLIST_NEXT  lru_next
#include "../../util/tmpl/fd_dlist.c"
#pragma GCC diagnostic pop

#define MAP_NAME  origin_map
#define MAP_ELE_T fd_prune_origin_t
#define MAP_KEY_T pubkey_private_t
#define MAP_KEY   origin_pubkey
#define MAP_IDX_T ulong
#define MAP_NEXT  map_next
#define MAP_PREV  map_prev
#define MAP_KEY_HASH(k,s) ((s) ^ fd_ulong_load_8( (k)->b ))
#define MAP_KEY_EQ(k0,k1) (!memcmp((k0)->b, (k1)->b, 32UL))
#define MAP_OPTIMIZE_RANDOM_ACCESS_REMOVAL 1
#include "../../util/tmpl/fd_map_chain.c"

/* Maximum number of (destination, origin) pairs that can be buffered
   between record and pop_prune calls.  17 push values * 50 relayers
   per origin = 850 worst case. */
#define FD_PRUNE_FINDER_PENDING_MAX (850UL)

struct fd_prune_pending {
  uchar relayer[ 32UL ];
  uchar origin[ 32UL ];
};

struct fd_prune_finder_private {
  fd_prune_origin_t * pool;
  origin_map_t *      origins;
  lru_list_t *        lru;

  uchar identity_pubkey[ 32UL ];
  ulong identity_stake;

  ulong                   pending_cnt;
  ulong                   pending_read;
  struct fd_prune_pending pending[ FD_PRUNE_FINDER_PENDING_MAX ];
};

FD_FN_CONST ulong
fd_prune_finder_align( void ) {
  return 128UL;
}

FD_FN_CONST ulong
fd_prune_finder_footprint( void ) {
  ulong chain_cnt = origin_map_chain_cnt_est( FD_PRUNE_FINDER_ORIGIN_MAX );
  ulong l;
  l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, alignof(fd_prune_finder_t), sizeof(fd_prune_finder_t)                    );
  l = FD_LAYOUT_APPEND( l, pool_align(),               pool_footprint( FD_PRUNE_FINDER_ORIGIN_MAX ) );
  l = FD_LAYOUT_APPEND( l, origin_map_align(),         origin_map_footprint( chain_cnt )            );
  l = FD_LAYOUT_APPEND( l, lru_list_align(),           lru_list_footprint()                         );
  l = FD_LAYOUT_FINI( l, fd_prune_finder_align() );
  return l;
}

void *
fd_prune_finder_new( void * shmem ) {
  if( FD_UNLIKELY( !shmem ) ) return NULL;
  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shmem, fd_prune_finder_align() ) ) ) return NULL;

  ulong chain_cnt = origin_map_chain_cnt_est( FD_PRUNE_FINDER_ORIGIN_MAX );

  FD_SCRATCH_ALLOC_INIT( l, shmem );
  fd_prune_finder_t * pf = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_prune_finder_t), sizeof(fd_prune_finder_t)                   );
  void * pool_mem        = FD_SCRATCH_ALLOC_APPEND( l, pool_align(),               pool_footprint( FD_PRUNE_FINDER_ORIGIN_MAX ) );
  void * map_mem         = FD_SCRATCH_ALLOC_APPEND( l, origin_map_align(),         origin_map_footprint( chain_cnt )            );
  void * lru_mem         = FD_SCRATCH_ALLOC_APPEND( l, lru_list_align(),           lru_list_footprint()                         );

  pf->pool    = pool_join( pool_new( pool_mem, FD_PRUNE_FINDER_ORIGIN_MAX ) );
  FD_TEST( pf->pool );
  pf->origins = origin_map_join( origin_map_new( map_mem, chain_cnt, 0UL ) );
  FD_TEST( pf->origins );
  pf->lru     = lru_list_join( lru_list_new( lru_mem ) );
  FD_TEST( pf->lru );

  fd_memset( pf->identity_pubkey, 0, 32UL );
  pf->identity_stake = 0UL;

  pf->pending_cnt  = 0UL;
  pf->pending_read = 0UL;

  return pf;
}

fd_prune_finder_t *
fd_prune_finder_join( void * shpf ) {
  return (fd_prune_finder_t *)shpf;
}

void
fd_prune_finder_set_identity( fd_prune_finder_t * pf,
                              uchar const *       identity_pubkey,
                              ulong               identity_stake ) {
  fd_memcpy( pf->identity_pubkey, identity_pubkey, 32UL );
  pf->identity_stake = identity_stake;
}

static inline fd_prune_relayer_t *
find_relayer( fd_prune_origin_t * origin,
              uchar const *       relayer_pubkey ) {
  for( ulong i=0UL; i<origin->relayers_cnt; i++ ) {
    if( FD_UNLIKELY( !memcmp( origin->relayers[ i ].pubkey, relayer_pubkey, 32UL ) ) ) {
      return &origin->relayers[ i ];
    }
  }
  return NULL;
}

static inline fd_prune_relayer_t *
insert_relayer( fd_prune_origin_t * origin,
                uchar const *       relayer_pubkey,
                ulong               score,
                ulong               relayer_stake ) {
  if( FD_UNLIKELY( origin->relayers_cnt>=FD_PRUNE_FINDER_RELAYER_MAX ) ) return NULL;
  fd_prune_relayer_t * r = &origin->relayers[ origin->relayers_cnt++ ];
  fd_memcpy( r->pubkey, relayer_pubkey, 32UL );
  r->score = score;
  r->stake = relayer_stake;
  return r;
}

#define SORT_NAME             sort_relayers_desc
#define SORT_KEY_T            fd_prune_relayer_t
#define SORT_BEFORE(a,b)      ((a).score>(b).score || ((a).score==(b).score && (a).stake>(b).stake))
#define SORT_QUICK_SWAP_MINIMIZE 1
#include "../../util/tmpl/fd_sort.c"

/* do_prune executes the prune decision for a single origin entry.
   Sorts relayers by (score, stake) descending, keeps at least
   min_ingress_nodes (2) and enough stake to cover min_ingress_stake,
   then appends (destination, origin) pairs for the remaining relayers
   to the pending buffer.  Resets the origin entry afterward. */

static void
do_prune( fd_prune_finder_t * pf,
          fd_prune_origin_t * origin ) {
  ulong cnt = origin->relayers_cnt;
  if( FD_UNLIKELY( !cnt ) ) {
    origin->num_upserts  = 0UL;
    origin->relayers_cnt = 0UL;
    return;
  }

  sort_relayers_desc_insert( origin->relayers, cnt );

  /* Compute min_ingress_stake = min(identity_stake, origin_stake) * 15/100.
     Relayers covering the top min_ingress_nodes and enough cumulative
     stake to meet min_ingress_stake are kept; the rest are pruned. */
  ulong min_base = fd_ulong_min( pf->identity_stake, origin->origin_stake );
  ulong min_ingress_stake = min_base * FD_PRUNE_FINDER_STAKE_THRESHOLD_PCT / 100UL;

  ulong cum_stake = 0UL;

  for( ulong i=0UL; i<cnt; i++ ) {
    fd_prune_relayer_t * r = &origin->relayers[ i ];

    if( FD_LIKELY( i<FD_PRUNE_FINDER_MIN_INGRESS_NODES ) ) {
      cum_stake += r->stake;
      continue;
    }

    if( FD_LIKELY( cum_stake<min_ingress_stake ) ) {
      cum_stake += r->stake;
      continue;
    }

    /* Filter out origin == relayer (per Agave) */
    if( FD_UNLIKELY( !memcmp( r->pubkey, origin->origin_pubkey.b, 32UL ) ) ) continue;

    FD_TEST( pf->pending_cnt<FD_PRUNE_FINDER_PENDING_MAX );
    struct fd_prune_pending * p = &pf->pending[ pf->pending_cnt++ ];
    fd_memcpy( p->relayer, r->pubkey, 32UL );
    fd_memcpy( p->origin, origin->origin_pubkey.b, 32UL );
  }

  /* Reset the origin entry (matching Agave's std::mem::take). */
  origin->num_upserts  = 0UL;
  origin->relayers_cnt = 0UL;
}

void
fd_prune_finder_record( fd_prune_finder_t * pf,
                        uchar const *       origin_pubkey,
                        ulong               origin_stake,
                        uchar const *       relayer_pubkey,
                        ulong               relayer_stake,
                        ulong               num_dups ) {
  fd_prune_origin_t * origin = origin_map_ele_query( pf->origins,
                                                     fd_type_pun_const( origin_pubkey ),
                                                     NULL,
                                                     pf->pool );

  if( FD_UNLIKELY( !origin ) ) {
    if( FD_LIKELY( pool_free( pf->pool ) ) ) {
      origin = pool_ele_acquire( pf->pool );
    } else {
      origin = lru_list_ele_pop_head( pf->lru, pf->pool );
      origin_map_ele_remove( pf->origins, &origin->origin_pubkey, NULL, pf->pool );
    }

    origin->num_upserts  = 0UL;
    origin->relayers_cnt = 0UL;
    origin->origin_stake = origin_stake;
    fd_memcpy( origin->origin_pubkey.b, origin_pubkey, 32UL );

    origin_map_ele_insert( pf->origins, origin, pf->pool );
    lru_list_ele_push_tail( pf->lru, origin, pf->pool );
  } else {
    lru_list_ele_remove( pf->lru, origin, pf->pool );
    lru_list_ele_push_tail( pf->lru, origin, pf->pool );
    origin->origin_stake = origin_stake;
  }

  if( FD_UNLIKELY( !num_dups ) ) origin->num_upserts++;

  if( FD_LIKELY( num_dups<FD_PRUNE_FINDER_NUM_DUPS_THRESHOLD ) ) {
    fd_prune_relayer_t * r = find_relayer( origin, relayer_pubkey );
    if( FD_LIKELY( r ) ) {
      r->score++;
      r->stake = relayer_stake;
    } else {
      insert_relayer( origin, relayer_pubkey, 1UL, relayer_stake );
    }
  } else {
    /* Late delivery (num_dups >= 2): insert with score 0 if room.
       Do not increment score — prevents spoofed addresses from
       penalizing a good relayer.  But do ensure the relayer is in
       the map so it can be pruned later. */
    fd_prune_relayer_t * r = find_relayer( origin, relayer_pubkey );
    if( FD_UNLIKELY( !r ) ) {
      insert_relayer( origin, relayer_pubkey, 0UL, relayer_stake );
    } else {
      r->stake = relayer_stake;
    }
  }

  if( FD_UNLIKELY( origin->num_upserts>=FD_PRUNE_FINDER_MIN_NUM_UPSERTS ) ) {
    do_prune( pf, origin );
  }
}

int
fd_prune_finder_pop_prune( fd_prune_finder_t * pf,
                           uchar const **      out_relayer,
                           uchar const **      out_origin ) {
  if( FD_UNLIKELY( pf->pending_read>=pf->pending_cnt ) ) {
    pf->pending_read = 0UL;
    pf->pending_cnt  = 0UL;
    return 0;
  }

  struct fd_prune_pending * p = &pf->pending[ pf->pending_read++ ];
  *out_relayer = p->relayer;
  *out_origin  = p->origin;
  return 1;
}
