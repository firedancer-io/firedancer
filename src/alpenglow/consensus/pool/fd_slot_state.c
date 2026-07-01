#include "fd_slot_state.h"

/* ---------------------------------------------------------------------------
   Backing pools / maps (util generics)

   per-hash stake map  : keyed by fd_hash_t, value Stake.  Used for both
                         voted_stakes.notar and voted_stakes.notar_fallback
                         (two independent maps of the same element type).
   parents map         : keyed by fd_hash_t, value ParentStatus (int).  Also
                         used (map-as-set) for pending_safe_to_notar and
                         sent_safe_to_notar — the element carries a presence
                         field per logical set.
   notar-fallback votes: keyed by (validator, hash) — mirrors
                         Vec<BTreeMap<BlockHash, NotarFallbackVote>>.

   All element structs reserve a `next` field for the pool free-list and the
   map_chain chain pointers (the canonical fd_ghost.c idiom). */

/* hashstake_ele_t: one per (map, block_hash) running stake total. */

struct hashstake_ele {
  fd_hash_t hash;  /* map key */
  ulong     next;  /* pool / map_chain reserved */
  ulong     stake; /* running stake total */
};
typedef struct hashstake_ele hashstake_ele_t;

#define POOL_NAME hashstake_pool
#define POOL_T    hashstake_ele_t
#include "../../../util/tmpl/fd_pool.c"

#define MAP_NAME               hashstake_map
#define MAP_ELE_T              hashstake_ele_t
#define MAP_KEY                hash
#define MAP_KEY_T              fd_hash_t
#define MAP_KEY_EQ(k0,k1)      (!memcmp((k0),(k1),sizeof(fd_hash_t)))
#define MAP_KEY_HASH(key,seed) (fd_hash((seed),(key),sizeof(fd_hash_t)))
#define MAP_NEXT               next
#include "../../../util/tmpl/fd_map_chain.c"

/* hashflag_ele_t: a per-block_hash element carrying a small set of boolean
   flags.  Backs both the `parents` BTreeMap<BlockHash,ParentStatus> and the
   pending/sent safe-to-notar BTreeSets, collapsed into one element keyed by
   hash so we use a single pool/map.  parent_status is FD_SLOT_STATE_PARENT_*
   (NONE == logically absent from the parents map); pending / sent are 0/1
   set-membership flags. */

struct hashflag_ele {
  fd_hash_t hash;          /* map key */
  ulong     next;          /* pool / map_chain reserved */
  int       parent_status; /* FD_SLOT_STATE_PARENT_* (NONE == not in parents map) */
  int       pending;       /* in pending_safe_to_notar */
  int       sent;          /* in sent_safe_to_notar */
};
typedef struct hashflag_ele hashflag_ele_t;

#define POOL_NAME hashflag_pool
#define POOL_T    hashflag_ele_t
#include "../../../util/tmpl/fd_pool.c"

#define MAP_NAME               hashflag_map
#define MAP_ELE_T              hashflag_ele_t
#define MAP_KEY                hash
#define MAP_KEY_T              fd_hash_t
#define MAP_KEY_EQ(k0,k1)      (!memcmp((k0),(k1),sizeof(fd_hash_t)))
#define MAP_KEY_HASH(key,seed) (fd_hash((seed),(key),sizeof(fd_hash_t)))
#define MAP_NEXT               next
#include "../../../util/tmpl/fd_map_chain.c"

/* nfvote_ele_t: a notar-fallback vote keyed by (validator, hash).  Mirrors
   the Vec<BTreeMap<BlockHash, NotarFallbackVote>> — i.e. one entry per
   (validator index, block hash) pair.  The composite key is the 8-byte
   validator index followed by the 32-byte hash. */

struct nfvote_key {
  ulong     validator;
  fd_hash_t hash;
};
typedef struct nfvote_key nfvote_key_t;

struct nfvote_ele {
  nfvote_key_t             key;  /* map key (validator, hash) */
  ulong                    next; /* pool / map_chain reserved */
  fd_notar_fallback_vote_t vote;
};
typedef struct nfvote_ele nfvote_ele_t;

#define POOL_NAME nfvote_pool
#define POOL_T    nfvote_ele_t
#include "../../../util/tmpl/fd_pool.c"

#define MAP_NAME               nfvote_map
#define MAP_ELE_T              nfvote_ele_t
#define MAP_KEY                key
#define MAP_KEY_T              nfvote_key_t
#define MAP_KEY_EQ(k0,k1)      (((k0)->validator==(k1)->validator) && !memcmp((k0)->hash.uc,(k1)->hash.uc,sizeof(fd_hash_t)))
#define MAP_KEY_HASH(key,seed) (fd_hash((seed),(key),sizeof(nfvote_key_t)))
#define MAP_NEXT               next
#include "../../../util/tmpl/fd_map_chain.c"

typedef hashstake_ele_t hashstake_pool_t;
typedef hashflag_ele_t  hashflag_pool_t;
typedef nfvote_ele_t    nfvote_pool_t;

/* ---------------------------------------------------------------------------
   Per-validator inline vote slot.

   Mirrors the per-validator Option<NotarVote>/Option<SkipVote>/... fields of
   SlotVotes.  The five concrete votes plus their presence flags are stored
   inline, indexed by ValidatorIndex.  notar_fallback is NOT here — it is
   per-(validator,hash) and lives in the nfvote map. */

struct slotvote {
  fd_notar_vote_t   notar;
  fd_skip_vote_t    skip;
  fd_skip_fallback_vote_t skip_fallback;
  fd_final_vote_t   finalize;
  uchar             has_notar;
  uchar             has_skip;
  uchar             has_skip_fallback;
  uchar             has_finalize;
};
typedef struct slotvote slotvote_t;

/* ---------------------------------------------------------------------------
   SlotCertificates (fixed inline).

   At most one of each single-cert kind, plus a fixed array of
   notar-fallback certs (one per distinct notarized-fallback block hash). */

#define FD_SLOT_STATE_NF_CERT_MAX (32UL)

struct slot_certs {
  int                      has_notar;         fd_notar_cert_t      notar;
  int                      has_skip;          fd_skip_cert_t       skip;
  int                      has_fast_finalize; fd_fast_final_cert_t fast_finalize;
  int                      has_finalize;      fd_final_cert_t      finalize;
  ulong                    nf_cnt;
  fd_notar_fallback_cert_t nf[ FD_SLOT_STATE_NF_CERT_MAX ];
};
typedef struct slot_certs slot_certs_t;

/* ---------------------------------------------------------------------------
   fd_slot_state top struct (relocatable wksp object).

   Holds only gaddrs / scalars / inline POD.  The per-validator slotvote array
   and the pools/maps are bump-allocated contiguously after this struct, in
   the canonical fd_ghost.c layout. */

struct __attribute__((aligned(128UL))) fd_slot_state {
  ulong wksp_gaddr; /* gaddr of this struct in its backing wksp */

  ulong slot;          /* the slot this state is for                    */
  ulong own_id;        /* our own ValidatorIndex (epoch_info.own_id)    */
  ulong validator_max; /* capacity of the per-validator vote array      */
  int   sent_safe_to_skip;

  /* scalar voted-stake totals (SlotVotedStake scalars) */
  ulong skip_stake;
  ulong skip_fallback_stake;
  ulong finalize_stake;
  ulong notar_or_skip_stake;
  ulong top_notar_stake;

  /* inline certificates (SlotCertificates) */
  slot_certs_t certs;

  /* gaddrs of bump-allocated regions */
  ulong votes_gaddr;          /* slotvote_t[ validator_max ]      */
  ulong notar_stake_pool_gaddr;
  ulong notar_stake_map_gaddr;
  ulong nf_stake_pool_gaddr;
  ulong nf_stake_map_gaddr;
  ulong flag_pool_gaddr;      /* parents + pending/sent s2n sets  */
  ulong flag_map_gaddr;
  ulong nfvote_pool_gaddr;    /* notar-fallback votes             */
  ulong nfvote_map_gaddr;
};

/* ---------------------------------------------------------------------------
   wksp accessors (fd_ghost.c idiom). */

FD_FN_PURE static inline fd_wksp_t *
ss_wksp( fd_slot_state_t const * ss ) {
  return (fd_wksp_t *)( ((ulong)ss) - ss->wksp_gaddr );
}

static inline slotvote_t *
votes( fd_slot_state_t * ss ) {
  return (slotvote_t *)fd_wksp_laddr_fast( ss_wksp( ss ), ss->votes_gaddr );
}
static inline slotvote_t const *
votes_const( fd_slot_state_t const * ss ) {
  return (slotvote_t const *)fd_wksp_laddr_fast( ss_wksp( ss ), ss->votes_gaddr );
}

static inline hashstake_pool_t * notar_stake_pool( fd_slot_state_t * ss ) { return (hashstake_pool_t *)fd_wksp_laddr_fast( ss_wksp( ss ), ss->notar_stake_pool_gaddr ); }
static inline hashstake_map_t *  notar_stake_map ( fd_slot_state_t * ss ) { return (hashstake_map_t  *)fd_wksp_laddr_fast( ss_wksp( ss ), ss->notar_stake_map_gaddr  ); }
static inline hashstake_pool_t * nf_stake_pool   ( fd_slot_state_t * ss ) { return (hashstake_pool_t *)fd_wksp_laddr_fast( ss_wksp( ss ), ss->nf_stake_pool_gaddr    ); }
static inline hashstake_map_t *  nf_stake_map    ( fd_slot_state_t * ss ) { return (hashstake_map_t  *)fd_wksp_laddr_fast( ss_wksp( ss ), ss->nf_stake_map_gaddr     ); }
static inline hashflag_pool_t *  flag_pool       ( fd_slot_state_t * ss ) { return (hashflag_pool_t  *)fd_wksp_laddr_fast( ss_wksp( ss ), ss->flag_pool_gaddr        ); }
static inline hashflag_map_t *   flag_map        ( fd_slot_state_t * ss ) { return (hashflag_map_t   *)fd_wksp_laddr_fast( ss_wksp( ss ), ss->flag_map_gaddr         ); }
static inline nfvote_pool_t *    nfvote_pool     ( fd_slot_state_t * ss ) { return (nfvote_pool_t    *)fd_wksp_laddr_fast( ss_wksp( ss ), ss->nfvote_pool_gaddr      ); }
static inline nfvote_map_t *     nfvote_map      ( fd_slot_state_t * ss ) { return (nfvote_map_t     *)fd_wksp_laddr_fast( ss_wksp( ss ), ss->nfvote_map_gaddr       ); }

/* const variants for query-only paths */
static inline hashstake_pool_t const * notar_stake_pool_const( fd_slot_state_t const * ss ) { return (hashstake_pool_t const *)fd_wksp_laddr_fast( ss_wksp( ss ), ss->notar_stake_pool_gaddr ); }
static inline hashstake_map_t  const * notar_stake_map_const ( fd_slot_state_t const * ss ) { return (hashstake_map_t  const *)fd_wksp_laddr_fast( ss_wksp( ss ), ss->notar_stake_map_gaddr  ); }
static inline hashstake_pool_t const * nf_stake_pool_const   ( fd_slot_state_t const * ss ) { return (hashstake_pool_t const *)fd_wksp_laddr_fast( ss_wksp( ss ), ss->nf_stake_pool_gaddr    ); }
static inline hashstake_map_t  const * nf_stake_map_const    ( fd_slot_state_t const * ss ) { return (hashstake_map_t  const *)fd_wksp_laddr_fast( ss_wksp( ss ), ss->nf_stake_map_gaddr     ); }
static inline nfvote_pool_t    const * nfvote_pool_const     ( fd_slot_state_t const * ss ) { return (nfvote_pool_t    const *)fd_wksp_laddr_fast( ss_wksp( ss ), ss->nfvote_pool_gaddr      ); }
static inline nfvote_map_t     const * nfvote_map_const      ( fd_slot_state_t const * ss ) { return (nfvote_map_t     const *)fd_wksp_laddr_fast( ss_wksp( ss ), ss->nfvote_map_gaddr       ); }

/* ---------------------------------------------------------------------------
   Sizing helpers. */

/* Each map needs enough chains for its element capacity.  The per-hash maps
   and the flag map are bounded by the number of distinct block hashes (small
   for a single slot); the notar-fallback vote map is bounded by
   validator_max * (a few distinct hashes).  We size all hash-keyed pools to a
   small multiple of validator_max for headroom (a single slot has at most a
   handful of competing block hashes, but per (validator) entries dominate the
   nfvote map). */

static inline ulong
hash_ele_max( ulong validator_max ) {
  return fd_ulong_pow2_up( fd_ulong_max( validator_max, 16UL ) );
}

ulong
fd_slot_state_align( void ) {
  return alignof(fd_slot_state_t);
}

ulong
fd_slot_state_footprint( ulong validator_max ) {
  if( FD_UNLIKELY( validator_max==0UL || validator_max>FD_AGGSIG_MAX_SIGNERS ) ) return 0UL;

  ulong hmax = hash_ele_max( validator_max );      /* per-hash element capacity */
  ulong nmax = fd_ulong_pow2_up( validator_max );  /* notar-fallback vote capacity */

  ulong hstake_chain = hashstake_map_chain_cnt_est( hmax );
  ulong flag_chain   = hashflag_map_chain_cnt_est ( hmax );
  ulong nfvote_chain = nfvote_map_chain_cnt_est   ( nmax );

  return FD_LAYOUT_FINI(
    FD_LAYOUT_APPEND(
    FD_LAYOUT_APPEND(
    FD_LAYOUT_APPEND(
    FD_LAYOUT_APPEND(
    FD_LAYOUT_APPEND(
    FD_LAYOUT_APPEND(
    FD_LAYOUT_APPEND(
    FD_LAYOUT_APPEND(
    FD_LAYOUT_APPEND(
    FD_LAYOUT_APPEND(
    FD_LAYOUT_INIT,
      alignof(fd_slot_state_t),  sizeof(fd_slot_state_t)                       ),
      alignof(slotvote_t),       sizeof(slotvote_t)*validator_max              ),
      hashstake_pool_align(),    hashstake_pool_footprint( hmax )              ),
      hashstake_map_align(),     hashstake_map_footprint ( hstake_chain )      ),
      hashstake_pool_align(),    hashstake_pool_footprint( hmax )              ),
      hashstake_map_align(),     hashstake_map_footprint ( hstake_chain )      ),
      hashflag_pool_align(),     hashflag_pool_footprint ( hmax )              ),
      hashflag_map_align(),      hashflag_map_footprint  ( flag_chain )        ),
      nfvote_pool_align(),       nfvote_pool_footprint   ( nmax )              ),
      nfvote_map_align(),        nfvote_map_footprint    ( nfvote_chain )      ),
    fd_slot_state_align() );
}

void *
fd_slot_state_new( void * mem, ulong slot, ulong own_id, ulong validator_max, ulong seed ) {

  if( FD_UNLIKELY( !mem ) ) {
    FD_LOG_WARNING(( "NULL mem" ));
    return NULL;
  }
  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)mem, fd_slot_state_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned mem" ));
    return NULL;
  }
  ulong footprint = fd_slot_state_footprint( validator_max );
  if( FD_UNLIKELY( !footprint ) ) {
    FD_LOG_WARNING(( "bad validator_max (%lu)", validator_max ));
    return NULL;
  }
  fd_wksp_t * wksp = fd_wksp_containing( mem );
  if( FD_UNLIKELY( !wksp ) ) {
    FD_LOG_WARNING(( "mem must be part of a workspace" ));
    return NULL;
  }

  fd_memset( mem, 0, footprint );

  ulong hmax = hash_ele_max( validator_max );
  ulong nmax = fd_ulong_pow2_up( validator_max );
  ulong hstake_chain = hashstake_map_chain_cnt_est( hmax );
  ulong flag_chain   = hashflag_map_chain_cnt_est ( hmax );
  ulong nfvote_chain = nfvote_map_chain_cnt_est   ( nmax );

  FD_SCRATCH_ALLOC_INIT( l, mem );
  fd_slot_state_t * ss               = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_slot_state_t), sizeof(fd_slot_state_t)              );
  void *            votes_mem        = FD_SCRATCH_ALLOC_APPEND( l, alignof(slotvote_t),      sizeof(slotvote_t)*validator_max     );
  void *            notar_stake_pool = FD_SCRATCH_ALLOC_APPEND( l, hashstake_pool_align(),   hashstake_pool_footprint( hmax )     );
  void *            notar_stake_map  = FD_SCRATCH_ALLOC_APPEND( l, hashstake_map_align(),    hashstake_map_footprint ( hstake_chain ) );
  void *            nf_stake_pool    = FD_SCRATCH_ALLOC_APPEND( l, hashstake_pool_align(),   hashstake_pool_footprint( hmax )     );
  void *            nf_stake_map     = FD_SCRATCH_ALLOC_APPEND( l, hashstake_map_align(),    hashstake_map_footprint ( hstake_chain ) );
  void *            flag_pool        = FD_SCRATCH_ALLOC_APPEND( l, hashflag_pool_align(),    hashflag_pool_footprint ( hmax )     );
  void *            flag_map         = FD_SCRATCH_ALLOC_APPEND( l, hashflag_map_align(),     hashflag_map_footprint  ( flag_chain ) );
  void *            nfvote_pool      = FD_SCRATCH_ALLOC_APPEND( l, nfvote_pool_align(),      nfvote_pool_footprint   ( nmax )     );
  void *            nfvote_map       = FD_SCRATCH_ALLOC_APPEND( l, nfvote_map_align(),       nfvote_map_footprint    ( nfvote_chain ) );
  FD_TEST( FD_SCRATCH_ALLOC_FINI( l, fd_slot_state_align() ) == (ulong)mem + footprint );

  (void)votes_mem; /* zeroed by memset; nothing further to format */

  ss->wksp_gaddr        = fd_wksp_gaddr_fast( wksp, ss );
  ss->slot              = slot;
  ss->own_id            = own_id;
  ss->validator_max     = validator_max;
  ss->sent_safe_to_skip = 0;
  ss->skip_stake          = 0UL;
  ss->skip_fallback_stake = 0UL;
  ss->finalize_stake      = 0UL;
  ss->notar_or_skip_stake = 0UL;
  ss->top_notar_stake     = 0UL;
  memset( &ss->certs, 0, sizeof(slot_certs_t) );

  ss->votes_gaddr            = fd_wksp_gaddr_fast( wksp, votes_mem );
  ss->notar_stake_pool_gaddr = fd_wksp_gaddr_fast( wksp, hashstake_pool_join( hashstake_pool_new( notar_stake_pool, hmax             ) ) );
  ss->notar_stake_map_gaddr  = fd_wksp_gaddr_fast( wksp, hashstake_map_join ( hashstake_map_new ( notar_stake_map,  hstake_chain, seed ) ) );
  ss->nf_stake_pool_gaddr    = fd_wksp_gaddr_fast( wksp, hashstake_pool_join( hashstake_pool_new( nf_stake_pool,    hmax             ) ) );
  ss->nf_stake_map_gaddr     = fd_wksp_gaddr_fast( wksp, hashstake_map_join ( hashstake_map_new ( nf_stake_map,     hstake_chain, seed ) ) );
  ss->flag_pool_gaddr        = fd_wksp_gaddr_fast( wksp, hashflag_pool_join ( hashflag_pool_new ( flag_pool,        hmax             ) ) );
  ss->flag_map_gaddr         = fd_wksp_gaddr_fast( wksp, hashflag_map_join  ( hashflag_map_new  ( flag_map,         flag_chain,  seed ) ) );
  ss->nfvote_pool_gaddr      = fd_wksp_gaddr_fast( wksp, nfvote_pool_join   ( nfvote_pool_new   ( nfvote_pool,      nmax             ) ) );
  ss->nfvote_map_gaddr       = fd_wksp_gaddr_fast( wksp, nfvote_map_join    ( nfvote_map_new    ( nfvote_map,       nfvote_chain, seed ) ) );

  return mem;
}

fd_slot_state_t *
fd_slot_state_join( void * mem ) {
  fd_slot_state_t * ss = (fd_slot_state_t *)mem;
  if( FD_UNLIKELY( !ss ) ) {
    FD_LOG_WARNING(( "NULL mem" ));
    return NULL;
  }
  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)ss, fd_slot_state_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned mem" ));
    return NULL;
  }
  return ss;
}

void *
fd_slot_state_leave( fd_slot_state_t const * ss ) {
  if( FD_UNLIKELY( !ss ) ) {
    FD_LOG_WARNING(( "NULL ss" ));
    return NULL;
  }
  return (void *)ss;
}

void *
fd_slot_state_delete( void * mem ) {
  if( FD_UNLIKELY( !mem ) ) {
    FD_LOG_WARNING(( "NULL mem" ));
    return NULL;
  }
  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)mem, fd_slot_state_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned mem" ));
    return NULL;
  }
  return mem;
}

/* ---------------------------------------------------------------------------
   Internal helpers. */

/* hashstake_get returns the running stake for hash in the given (pool,map),
   or 0 if absent (BTreeMap::get(hash).unwrap_or(0)). */

static ulong
hashstake_get( hashstake_map_t const *  map,
               hashstake_pool_t const * pool,
               fd_hash_t const *        hash ) {
  hashstake_ele_t const * e = hashstake_map_ele_query_const( map, hash, NULL, pool );
  return e ? e->stake : 0UL;
}

/* hashstake_add adds stake to hash's running total in (pool,map), inserting a
   fresh zero entry if absent (BTreeMap::entry().or_default() += stake), and
   returns the new total. */

static ulong
hashstake_add( hashstake_map_t *  map,
               hashstake_pool_t * pool,
               fd_hash_t const *  hash,
               ulong              stake ) {
  hashstake_ele_t * e = hashstake_map_ele_query( map, hash, NULL, pool );
  if( FD_UNLIKELY( !e ) ) {
    e = hashstake_pool_ele_acquire( pool );
    e->hash  = *hash;
    e->stake = 0UL;
    hashstake_map_ele_insert( map, e, pool );
  }
  e->stake += stake;
  return e->stake;
}

/* flag_get returns the flag element for hash, or NULL if absent. */

static hashflag_ele_t *
flag_get( fd_slot_state_t * ss, fd_hash_t const * hash ) {
  return hashflag_map_ele_query( flag_map( ss ), hash, NULL, flag_pool( ss ) );
}

/* flag_get_or_insert returns the flag element for hash, inserting a fresh
   zeroed one if absent. */

static hashflag_ele_t *
flag_get_or_insert( fd_slot_state_t * ss, fd_hash_t const * hash ) {
  hashflag_ele_t * e = flag_get( ss, hash );
  if( FD_UNLIKELY( !e ) ) {
    e = hashflag_pool_ele_acquire( flag_pool( ss ) );
    e->hash          = *hash;
    e->parent_status = FD_SLOT_STATE_PARENT_NONE;
    e->pending       = 0;
    e->sent          = 0;
    hashflag_map_ele_insert( flag_map( ss ), e, flag_pool( ss ) );
  }
  return e;
}

/* sent_safe_to_notar returns 1 iff hash is in sent_safe_to_notar. */

static int
is_sent_safe_to_notar( fd_slot_state_t * ss, fd_hash_t const * hash ) {
  hashflag_ele_t const * e = flag_get( ss, hash );
  return e && e->sent;
}

/* out_push_* helpers append to the caller-provided output arrays. */

static void
out_push_cert( fd_slot_state_outputs_t * out, fd_cert_t const * cert ) {
  if( !out ) return;
  FD_TEST( out->certs_cnt < out->certs_max );
  out->certs[ out->certs_cnt++ ] = *cert;
}

static void
out_push_safe_to_notar( fd_slot_state_outputs_t * out, ulong slot, fd_hash_t const * hash ) {
  if( !out ) return;
  FD_TEST( out->events_cnt < out->events_max );
  fd_pool_event_t * ev = &out->events[ out->events_cnt++ ];
  ev->kind       = FD_POOL_EVENT_SAFE_TO_NOTAR;
  ev->block.slot = slot;
  ev->block.hash = *hash;
}

static void
out_push_safe_to_skip( fd_slot_state_outputs_t * out, ulong slot ) {
  if( !out ) return;
  FD_TEST( out->events_cnt < out->events_max );
  fd_pool_event_t * ev = &out->events[ out->events_cnt++ ];
  ev->kind       = FD_POOL_EVENT_SAFE_TO_SKIP;
  ev->block.slot = slot;
  memset( ev->block.hash.uc, 0, sizeof(fd_hash_t) );
}

static void
out_push_repair( fd_slot_state_outputs_t * out, ulong slot, fd_hash_t const * hash ) {
  if( !out ) return;
  FD_TEST( out->repairs_cnt < out->repairs_max );
  fd_block_id_t * b = &out->repairs[ out->repairs_cnt++ ];
  b->slot = slot;
  b->hash = *hash;
}

/* ---------------------------------------------------------------------------
   Vote collection (SlotVotes::*_votes): gather all matching concrete votes
   into a caller buffer for cert construction.  Returns the count. */

static ulong
collect_notar_votes( fd_slot_state_t * ss, fd_hash_t const * hash, fd_notar_vote_t * out ) {
  slotvote_t const * v = votes_const( ss );
  ulong cnt = 0UL;
  for( ulong i=0UL; i<ss->validator_max; i++ ) {
    if( v[i].has_notar && !memcmp( v[i].notar.block_hash.uc, hash->uc, sizeof(fd_hash_t) ) ) {
      out[ cnt++ ] = v[i].notar;
    }
  }
  return cnt;
}

static ulong
collect_nf_votes( fd_slot_state_t * ss, fd_hash_t const * hash, fd_notar_fallback_vote_t * out ) {
  /* Iterate the nfvote map, selecting entries matching hash, ordered by
     ascending validator index to mirror the Rust per-validator iteration. */
  ulong cnt = 0UL;
  nfvote_map_t const *  map  = nfvote_map_const( ss );
  nfvote_pool_t const * pool = nfvote_pool_const( ss );
  for( ulong i=0UL; i<ss->validator_max; i++ ) {
    nfvote_key_t k; k.validator = i; k.hash = *hash;
    nfvote_ele_t const * e = nfvote_map_ele_query_const( map, &k, NULL, pool );
    if( e ) out[ cnt++ ] = e->vote;
  }
  return cnt;
}

static ulong
collect_skip_votes( fd_slot_state_t * ss, fd_skip_vote_t * out ) {
  slotvote_t const * v = votes_const( ss );
  ulong cnt = 0UL;
  for( ulong i=0UL; i<ss->validator_max; i++ ) if( v[i].has_skip ) out[ cnt++ ] = v[i].skip;
  return cnt;
}

static ulong
collect_skip_fallback_votes( fd_slot_state_t * ss, fd_skip_fallback_vote_t * out ) {
  slotvote_t const * v = votes_const( ss );
  ulong cnt = 0UL;
  for( ulong i=0UL; i<ss->validator_max; i++ ) if( v[i].has_skip_fallback ) out[ cnt++ ] = v[i].skip_fallback;
  return cnt;
}

static ulong
collect_final_votes( fd_slot_state_t * ss, fd_final_vote_t * out ) {
  slotvote_t const * v = votes_const( ss );
  ulong cnt = 0UL;
  for( ulong i=0UL; i<ss->validator_max; i++ ) if( v[i].has_finalize ) out[ cnt++ ] = v[i].finalize;
  return cnt;
}

/* ---------------------------------------------------------------------------
   is_notar_fallback (SlotState::is_notar_fallback). */

FD_FN_PURE int
fd_slot_state_is_notar_fallback( fd_slot_state_t const * ss, fd_hash_t const * block_hash ) {
  slot_certs_t const * c = &ss->certs;
  for( ulong i=0UL; i<c->nf_cnt; i++ ) {
    if( !memcmp( c->nf[i].block_hash.uc, block_hash->uc, sizeof(fd_hash_t) ) ) return 1;
  }
  return 0;
}

/* ---------------------------------------------------------------------------
   check_safe_to_notar (SlotState::check_safe_to_notar).

   Returns FD_SLOT_STATE_S2N_*.  Mutates the pending / sent safe-to-notar
   sets exactly as the Rust reference does. */

static int
check_safe_to_notar( fd_slot_state_t * ss, fd_hash_t const * block_hash, fd_epoch_info_t const * epoch_info ) {
  ulong notar_stake = hashstake_get( notar_stake_map( ss ), notar_stake_pool( ss ), block_hash );
  ulong skip_stake  = ss->skip_stake;

  if( !fd_epoch_info_is_weakest_quorum( epoch_info, notar_stake ) ) {
    return FD_SLOT_STATE_S2N_AWAITING;
  }
  if( !fd_epoch_info_is_weak_quorum( epoch_info, notar_stake )
      && !fd_epoch_info_is_quorum( epoch_info, notar_stake + skip_stake ) ) {
    flag_get_or_insert( ss, block_hash )->pending = 1;
    return FD_SLOT_STATE_S2N_AWAITING;
  }

  /* check parent condition */
  hashflag_ele_t * pe = flag_get( ss, block_hash );
  if( !pe || pe->parent_status==FD_SLOT_STATE_PARENT_NONE ) {
    return FD_SLOT_STATE_S2N_MISSING_BLOCK;
  }
  if( pe->parent_status != FD_SLOT_STATE_PARENT_CERTIFIED ) {
    return FD_SLOT_STATE_S2N_AWAITING;
  }

  /* check own vote */
  slotvote_t * v   = votes( ss );
  ulong        own = ss->own_id;
  int          has_skip  = v[own].has_skip;
  int          has_notar = v[own].has_notar;

  if( has_skip ) {
    hashflag_ele_t * e = flag_get_or_insert( ss, block_hash );
    e->pending = 0;
    e->sent    = 1;
    return FD_SLOT_STATE_S2N_SAFE_TO_NOTAR;
  }
  if( has_notar ) {
    if( memcmp( v[own].notar.block_hash.uc, block_hash->uc, sizeof(fd_hash_t) ) ) {
      hashflag_ele_t * e = flag_get_or_insert( ss, block_hash );
      e->pending = 0;
      e->sent    = 1;
      return FD_SLOT_STATE_S2N_SAFE_TO_NOTAR;
    }
    return FD_SLOT_STATE_S2N_AWAITING;
  }
  /* (None, None): neither skip nor notar from us yet */
  flag_get_or_insert( ss, block_hash )->pending = 1;
  return FD_SLOT_STATE_S2N_AWAITING;
}

/* process_pending_safe_to_notar re-evaluates every block currently in
   pending_safe_to_notar (and not yet sent), mirroring the
   `for hash in self.pending_safe_to_notar.clone()` loops in
   SlotState::add_vote / count_skip_stake.  A snapshot of the pending hashes
   is taken first (into a local fixed buffer) so the iteration is decoupled
   from check_safe_to_notar's mutations of the flag map.  At most one distinct
   pending hash per validator can exist, but in practice a slot has only a
   handful of competing block hashes, so the snapshot buffer is bounded by a
   small fixed cap.  Any hashes beyond the cap are processed on a subsequent
   call (the pending set persists). */

#define FD_SLOT_STATE_PENDING_SNAPSHOT_MAX (64UL)

static void
process_pending_safe_to_notar( fd_slot_state_t *         ss,
                               ulong                     slot,
                               fd_epoch_info_t const *   epoch_info,
                               fd_slot_state_outputs_t * out ) {
  fd_hash_t snap[ FD_SLOT_STATE_PENDING_SNAPSHOT_MAX ];
  ulong     snap_cnt = 0UL;

  hashflag_map_t *  map  = flag_map( ss );
  hashflag_pool_t * pool = flag_pool( ss );
  for( hashflag_map_iter_t it = hashflag_map_iter_init( map, pool );
       !hashflag_map_iter_done( it, map, pool );
       it = hashflag_map_iter_next( it, map, pool ) ) {
    hashflag_ele_t const * e = hashflag_map_iter_ele_const( it, map, pool );
    if( e->pending && !e->sent ) {
      if( FD_LIKELY( snap_cnt<FD_SLOT_STATE_PENDING_SNAPSHOT_MAX ) ) snap[ snap_cnt++ ] = e->hash;
    }
  }

  for( ulong i=0UL; i<snap_cnt; i++ ) {
    if( is_sent_safe_to_notar( ss, &snap[i] ) ) continue;
    switch( check_safe_to_notar( ss, &snap[i], epoch_info ) ) {
    case FD_SLOT_STATE_S2N_SAFE_TO_NOTAR: out_push_safe_to_notar( out, slot, &snap[i] ); break;
    case FD_SLOT_STATE_S2N_MISSING_BLOCK: out_push_repair       ( out, slot, &snap[i] ); break;
    default: break;
    }
  }
}

/* ---------------------------------------------------------------------------
   count_notar_stake (SlotState::count_notar_stake). */

static void
count_notar_stake( fd_slot_state_t *         ss,
                   ulong                     slot,
                   fd_hash_t const *         block_hash,
                   ulong                     stake,
                   fd_epoch_info_t const *   epoch_info,
                   fd_slot_state_outputs_t * out ) {
  /* increment stake */
  ulong notar_stake = hashstake_add( notar_stake_map( ss ), notar_stake_pool( ss ), block_hash, stake );
  ss->notar_or_skip_stake += stake;
  ss->top_notar_stake = fd_ulong_max( notar_stake, ss->top_notar_stake );

  /* check quorums */
  if( !is_sent_safe_to_notar( ss, block_hash ) ) {
    switch( check_safe_to_notar( ss, block_hash, epoch_info ) ) {
    case FD_SLOT_STATE_S2N_SAFE_TO_NOTAR: out_push_safe_to_notar( out, slot, block_hash ); break;
    case FD_SLOT_STATE_S2N_MISSING_BLOCK: out_push_repair       ( out, slot, block_hash ); break;
    default: break;
    }
  }
  if( !ss->sent_safe_to_skip
      && fd_epoch_info_is_weak_quorum( epoch_info, ss->notar_or_skip_stake - ss->top_notar_stake )
      && votes( ss )[ ss->own_id ].has_notar ) {
    out_push_safe_to_skip( out, slot );
    ss->sent_safe_to_skip = 1;
  }

  ulong nf_stake = hashstake_get( nf_stake_map( ss ), nf_stake_pool( ss ), block_hash );
  if( fd_epoch_info_is_quorum( epoch_info, nf_stake + notar_stake )
      && !fd_slot_state_is_notar_fallback( ss, block_hash ) ) {
    fd_notar_vote_t          notar_buf[ FD_AGGSIG_MAX_SIGNERS ];
    fd_notar_fallback_vote_t nf_buf   [ FD_AGGSIG_MAX_SIGNERS ];
    ulong nv_cnt = collect_notar_votes( ss, block_hash, notar_buf );
    ulong nf_cnt = collect_nf_votes   ( ss, block_hash, nf_buf    );
    FD_TEST( ss->certs.nf_cnt < FD_SLOT_STATE_NF_CERT_MAX );
    fd_cert_t cert; cert.discriminant = FD_CERT_TYPE_NOTAR_FALLBACK;
    FD_TEST( fd_notar_fallback_cert_try_new( &cert.inner.notar_fallback,
                                             nv_cnt ? notar_buf : NULL, nv_cnt,
                                             nf_cnt ? nf_buf    : NULL, nf_cnt,
                                             fd_epoch_info_validators( epoch_info ),
                                             epoch_info->validator_cnt )==FD_CERT_SUCCESS );
    out_push_cert( out, &cert );
  }
  if( fd_epoch_info_is_quorum( epoch_info, notar_stake ) && !ss->certs.has_notar ) {
    fd_notar_vote_t notar_buf[ FD_AGGSIG_MAX_SIGNERS ];
    ulong nv_cnt = collect_notar_votes( ss, block_hash, notar_buf );
    fd_cert_t cert; cert.discriminant = FD_CERT_TYPE_NOTAR;
    FD_TEST( fd_notar_cert_try_new( &cert.inner.notar, notar_buf, nv_cnt,
                                    fd_epoch_info_validators( epoch_info ),
                                    epoch_info->validator_cnt )==FD_CERT_SUCCESS );
    out_push_cert( out, &cert );
  }
  if( fd_epoch_info_is_strong_quorum( epoch_info, notar_stake ) && !ss->certs.has_fast_finalize ) {
    fd_notar_vote_t notar_buf[ FD_AGGSIG_MAX_SIGNERS ];
    ulong nv_cnt = collect_notar_votes( ss, block_hash, notar_buf );
    fd_cert_t cert; cert.discriminant = FD_CERT_TYPE_FAST_FINAL;
    FD_TEST( fd_fast_final_cert_try_new( &cert.inner.fast_final, notar_buf, nv_cnt,
                                         fd_epoch_info_validators( epoch_info ),
                                         epoch_info->validator_cnt )==FD_CERT_SUCCESS );
    out_push_cert( out, &cert );
  }
}

/* ---------------------------------------------------------------------------
   count_notar_fallback_stake (SlotState::count_notar_fallback_stake). */

static void
count_notar_fallback_stake( fd_slot_state_t *         ss,
                            fd_hash_t const *         block_hash,
                            ulong                     stake,
                            fd_epoch_info_t const *   epoch_info,
                            fd_slot_state_outputs_t * out ) {
  ulong nf_stake    = hashstake_add( nf_stake_map( ss ), nf_stake_pool( ss ), block_hash, stake );
  ulong notar_stake = hashstake_get( notar_stake_map( ss ), notar_stake_pool( ss ), block_hash );
  if( fd_epoch_info_is_quorum( epoch_info, nf_stake + notar_stake )
      && !fd_slot_state_is_notar_fallback( ss, block_hash ) ) {
    fd_notar_vote_t          notar_buf[ FD_AGGSIG_MAX_SIGNERS ];
    fd_notar_fallback_vote_t nf_buf   [ FD_AGGSIG_MAX_SIGNERS ];
    ulong nv_cnt = collect_notar_votes( ss, block_hash, notar_buf );
    ulong nf_cnt = collect_nf_votes   ( ss, block_hash, nf_buf    );
    fd_cert_t cert; cert.discriminant = FD_CERT_TYPE_NOTAR_FALLBACK;
    FD_TEST( fd_notar_fallback_cert_try_new( &cert.inner.notar_fallback,
                                             nv_cnt ? notar_buf : NULL, nv_cnt,
                                             nf_cnt ? nf_buf    : NULL, nf_cnt,
                                             fd_epoch_info_validators( epoch_info ),
                                             epoch_info->validator_cnt )==FD_CERT_SUCCESS );
    out_push_cert( out, &cert );
  }
}

/* ---------------------------------------------------------------------------
   count_skip_stake (SlotState::count_skip_stake). */

static void
count_skip_stake( fd_slot_state_t *         ss,
                  ulong                     slot,
                  ulong                     stake,
                  int                       fallback,
                  fd_epoch_info_t const *   epoch_info,
                  fd_slot_state_outputs_t * out ) {
  if( fallback ) ss->skip_fallback_stake += stake;
  else           ss->skip_stake          += stake;

  /* re-evaluate any blocks pending safe-to-notar (skip stake may now satisfy
     the notar+skip quorum branch). */
  process_pending_safe_to_notar( ss, slot, epoch_info, out );

  ulong total_skip_stake = ss->skip_stake + ss->skip_fallback_stake;
  if( fd_epoch_info_is_quorum( epoch_info, total_skip_stake ) && !ss->certs.has_skip ) {
    fd_skip_vote_t          skip_buf[ FD_AGGSIG_MAX_SIGNERS ];
    fd_skip_fallback_vote_t sf_buf  [ FD_AGGSIG_MAX_SIGNERS ];
    ulong skip_cnt = collect_skip_votes         ( ss, skip_buf );
    ulong sf_cnt   = collect_skip_fallback_votes( ss, sf_buf   );
    fd_cert_t cert; cert.discriminant = FD_CERT_TYPE_SKIP;
    FD_TEST( fd_skip_cert_try_new( &cert.inner.skip,
                                   skip_cnt ? skip_buf : NULL, skip_cnt,
                                   sf_cnt   ? sf_buf   : NULL, sf_cnt,
                                   fd_epoch_info_validators( epoch_info ),
                                   epoch_info->validator_cnt )==FD_CERT_SUCCESS );
    out_push_cert( out, &cert );
  }
  if( !ss->sent_safe_to_skip
      && fd_epoch_info_is_weak_quorum( epoch_info, ss->notar_or_skip_stake - ss->top_notar_stake )
      && votes( ss )[ ss->own_id ].has_notar ) {
    out_push_safe_to_skip( out, slot );
    ss->sent_safe_to_skip = 1;
  }
}

/* ---------------------------------------------------------------------------
   count_finalize_stake (SlotState::count_finalize_stake). */

static void
count_finalize_stake( fd_slot_state_t *         ss,
                      ulong                     stake,
                      fd_epoch_info_t const *   epoch_info,
                      fd_slot_state_outputs_t * out ) {
  ss->finalize_stake += stake;
  if( fd_epoch_info_is_quorum( epoch_info, ss->finalize_stake ) && !ss->certs.has_finalize ) {
    fd_final_vote_t final_buf[ FD_AGGSIG_MAX_SIGNERS ];
    ulong f_cnt = collect_final_votes( ss, final_buf );
    fd_cert_t cert; cert.discriminant = FD_CERT_TYPE_FINAL;
    FD_TEST( fd_final_cert_try_new( &cert.inner.final_, final_buf, f_cnt,
                                    fd_epoch_info_validators( epoch_info ),
                                    epoch_info->validator_cnt )==FD_CERT_SUCCESS );
    out_push_cert( out, &cert );
  }
}

/* ---------------------------------------------------------------------------
   add_cert (SlotState::add_cert). */

void
fd_slot_state_add_cert( fd_slot_state_t * ss, fd_cert_t const * cert ) {
  switch( cert->discriminant ) {
  case FD_CERT_TYPE_NOTAR:
    ss->certs.has_notar = 1;
    ss->certs.notar     = cert->inner.notar;
    break;
  case FD_CERT_TYPE_NOTAR_FALLBACK:
    if( !fd_slot_state_is_notar_fallback( ss, &cert->inner.notar_fallback.block_hash ) ) {
      FD_TEST( ss->certs.nf_cnt < FD_SLOT_STATE_NF_CERT_MAX );
      ss->certs.nf[ ss->certs.nf_cnt++ ] = cert->inner.notar_fallback;
    }
    break;
  case FD_CERT_TYPE_SKIP:
    ss->certs.has_skip = 1;
    ss->certs.skip     = cert->inner.skip;
    break;
  case FD_CERT_TYPE_FAST_FINAL:
    ss->certs.has_fast_finalize = 1;
    ss->certs.fast_finalize     = cert->inner.fast_final;
    break;
  case FD_CERT_TYPE_FINAL:
    ss->certs.has_finalize = 1;
    ss->certs.finalize     = cert->inner.final_;
    break;
  default:
    FD_LOG_ERR(( "invalid cert discriminant %u", cert->discriminant ));
  }
}

/* ---------------------------------------------------------------------------
   add_vote (SlotState::add_vote). */

void
fd_slot_state_add_vote( fd_slot_state_t *         ss,
                        fd_ag_vote_t const *      vote,
                        ulong                     voter_stake,
                        fd_epoch_info_t const *   epoch_info,
                        fd_slot_state_outputs_t * out ) {
  ulong slot  = fd_vote_slot ( vote );
  ulong voter = fd_vote_signer( vote );
  FD_TEST( voter < ss->validator_max );
  slotvote_t * v = votes( ss );

  switch( vote->discriminant ) {

  case FD_VOTE_TYPE_NOTAR: {
    fd_hash_t const * h = &vote->inner.notar.block_hash;
    count_notar_stake( ss, slot, h, voter_stake, epoch_info, out );
    v[voter].notar     = vote->inner.notar;
    v[voter].has_notar = 1;
    break;
  }

  case FD_VOTE_TYPE_NOTAR_FALLBACK: {
    fd_hash_t const * h = &vote->inner.notar_fallback.block_hash;
    count_notar_fallback_stake( ss, h, voter_stake, epoch_info, out );
    /* insert into the (validator,hash) nfvote map; assert no prior entry */
    nfvote_key_t k; k.validator = voter; k.hash = *h;
    FD_TEST( !nfvote_map_ele_query( nfvote_map( ss ), &k, NULL, nfvote_pool( ss ) ) );
    nfvote_ele_t * e = nfvote_pool_ele_acquire( nfvote_pool( ss ) );
    e->key  = k;
    e->vote = vote->inner.notar_fallback;
    nfvote_map_ele_insert( nfvote_map( ss ), e, nfvote_pool( ss ) );
    break;
  }

  case FD_VOTE_TYPE_SKIP:
    v[voter].skip     = vote->inner.skip;
    v[voter].has_skip = 1;
    ss->notar_or_skip_stake += voter_stake;
    count_skip_stake( ss, slot, voter_stake, 0, epoch_info, out );
    break;

  case FD_VOTE_TYPE_SKIP_FALLBACK:
    v[voter].skip_fallback     = vote->inner.skip_fallback;
    v[voter].has_skip_fallback = 1;
    count_skip_stake( ss, slot, voter_stake, 1, epoch_info, out );
    break;

  case FD_VOTE_TYPE_FINAL:
    v[voter].finalize     = vote->inner.final_;
    v[voter].has_finalize = 1;
    count_finalize_stake( ss, voter_stake, epoch_info, out );
    break;

  default:
    FD_LOG_ERR(( "invalid vote discriminant %u", vote->discriminant ));
  }

  /* our own vote might have made a block safe-to-notar */
  if( voter==ss->own_id ) {
    process_pending_safe_to_notar( ss, slot, epoch_info, out );
  }
}

/* ---------------------------------------------------------------------------
   notify_parent_known / notify_parent_certified. */

void
fd_slot_state_notify_parent_known( fd_slot_state_t * ss, fd_hash_t const * hash ) {
  hashflag_ele_t * e = flag_get_or_insert( ss, hash );
  if( e->parent_status==FD_SLOT_STATE_PARENT_NONE ) e->parent_status = FD_SLOT_STATE_PARENT_KNOWN;
}

fd_notify_parent_result_t
fd_slot_state_notify_parent_certified( fd_slot_state_t *       ss,
                                       fd_hash_t const *       hash,
                                       fd_epoch_info_t const * epoch_info ) {
  fd_notify_parent_result_t res; memset( &res, 0, sizeof(res) ); res.kind = FD_NOTIFY_PARENT_NONE;

  hashflag_ele_t * e = flag_get( ss, hash );
  FD_TEST( e && e->parent_status!=FD_SLOT_STATE_PARENT_NONE ); /* "parent not known" */
  e->parent_status = FD_SLOT_STATE_PARENT_CERTIFIED;

  if( e->sent ) return res; /* already sent safe-to-notar */

  switch( check_safe_to_notar( ss, hash, epoch_info ) ) {
  case FD_SLOT_STATE_S2N_SAFE_TO_NOTAR:
    res.kind             = FD_NOTIFY_PARENT_EVENT;
    res.inner.event.kind = FD_POOL_EVENT_SAFE_TO_NOTAR;
    res.inner.event.block.slot = ss->slot;
    res.inner.event.block.hash = *hash;
    break;
  case FD_SLOT_STATE_S2N_MISSING_BLOCK:
    res.kind               = FD_NOTIFY_PARENT_REPAIR;
    res.inner.repair.slot  = ss->slot;
    res.inner.repair.hash  = *hash;
    break;
  default: break;
  }
  return res;
}

/* ---------------------------------------------------------------------------
   check_slashable_offence (SlotState::check_slashable_offence). */

FD_FN_PURE fd_slashable_offence_t
fd_slot_state_check_slashable_offence( fd_slot_state_t const * ss, fd_ag_vote_t const * vote ) {
  fd_slashable_offence_t r; r.kind = FD_SLASHABLE_NONE; r.validator = 0UL; r.slot = 0UL;
  ulong slot  = fd_vote_slot ( vote );
  ulong voter = fd_vote_signer( vote );
  slotvote_t const * v = votes_const( ss );

  switch( vote->discriminant ) {

  case FD_VOTE_TYPE_NOTAR:
    if( v[voter].has_skip ) {
      r.kind = FD_SLASHABLE_SKIP_AND_NOTARIZE; r.validator = voter; r.slot = slot; return r;
    }
    if( v[voter].has_notar
        && memcmp( vote->inner.notar.block_hash.uc, v[voter].notar.block_hash.uc, sizeof(fd_hash_t) ) ) {
      r.kind = FD_SLASHABLE_NOTAR_DIFFERENT_HASH; r.validator = voter; r.slot = slot; return r;
    }
    break;

  case FD_VOTE_TYPE_NOTAR_FALLBACK:
    if( v[voter].has_finalize ) {
      r.kind = FD_SLASHABLE_NOTAR_FALLBACK_AND_FINALIZE; r.validator = voter; r.slot = slot; return r;
    }
    break;

  case FD_VOTE_TYPE_SKIP:
    if( v[voter].has_finalize ) {
      r.kind = FD_SLASHABLE_SKIP_AND_FINALIZE; r.validator = voter; r.slot = slot; return r;
    } else if( v[voter].has_notar ) {
      r.kind = FD_SLASHABLE_SKIP_AND_NOTARIZE; r.validator = voter; r.slot = slot; return r;
    }
    break;

  case FD_VOTE_TYPE_SKIP_FALLBACK:
    if( v[voter].has_finalize ) {
      r.kind = FD_SLASHABLE_SKIP_AND_FINALIZE; r.validator = voter; r.slot = slot; return r;
    }
    break;

  case FD_VOTE_TYPE_FINAL: {
    if( v[voter].has_skip || v[voter].has_skip_fallback ) {
      r.kind = FD_SLASHABLE_SKIP_AND_FINALIZE; r.validator = voter; r.slot = slot; return r;
    }
    /* any notar-fallback vote by voter -> NotarFallbackAndFinalize */
    nfvote_map_t const *  map  = nfvote_map_const( ss );
    nfvote_pool_t const * pool = nfvote_pool_const( ss );
    /* scan distinct hashes is unbounded; instead scan the map for voter. The
       map is keyed by (validator,hash); iterate all and match validator. */
    for( nfvote_map_iter_t it = nfvote_map_iter_init( map, pool );
         !nfvote_map_iter_done( it, map, pool );
         it = nfvote_map_iter_next( it, map, pool ) ) {
      nfvote_ele_t const * e = nfvote_map_iter_ele_const( it, map, pool );
      if( e->key.validator==voter ) {
        r.kind = FD_SLASHABLE_NOTAR_FALLBACK_AND_FINALIZE; r.validator = voter; r.slot = slot; return r;
      }
    }
    break;
  }

  default:
    FD_LOG_ERR(( "invalid vote discriminant %u", vote->discriminant ));
  }
  return r;
}

/* ---------------------------------------------------------------------------
   should_ignore_vote (SlotState::should_ignore_vote). */

FD_FN_PURE int
fd_slot_state_should_ignore_vote( fd_slot_state_t const * ss, fd_ag_vote_t const * vote ) {
  ulong voter = fd_vote_signer( vote );
  slotvote_t const * v = votes_const( ss );
  switch( vote->discriminant ) {
  case FD_VOTE_TYPE_NOTAR:
    return (int)v[voter].has_notar;
  case FD_VOTE_TYPE_NOTAR_FALLBACK: {
    nfvote_key_t k; k.validator = voter; k.hash = vote->inner.notar_fallback.block_hash;
    return nfvote_map_ele_query_const( nfvote_map_const( ss ), &k, NULL, nfvote_pool_const( ss ) ) != NULL;
  }
  case FD_VOTE_TYPE_SKIP:
  case FD_VOTE_TYPE_SKIP_FALLBACK:
    return (int)( v[voter].has_skip || v[voter].has_skip_fallback );
  case FD_VOTE_TYPE_FINAL:
    return (int)v[voter].has_finalize;
  default:
    FD_LOG_ERR(( "invalid vote discriminant %u", vote->discriminant ));
  }
  return 0;
}

/* ---------------------------------------------------------------------------
   Accessors. */

FD_FN_PURE ulong fd_slot_state_slot( fd_slot_state_t const * ss ) { return ss->slot; }

FD_FN_PURE ulong
fd_slot_state_notar_stake( fd_slot_state_t const * ss, fd_hash_t const * block_hash ) {
  return hashstake_get( notar_stake_map_const( ss ), notar_stake_pool_const( ss ), block_hash );
}

FD_FN_PURE ulong
fd_slot_state_notar_fallback_stake( fd_slot_state_t const * ss, fd_hash_t const * block_hash ) {
  return hashstake_get( nf_stake_map_const( ss ), nf_stake_pool_const( ss ), block_hash );
}

FD_FN_PURE ulong fd_slot_state_skip_stake          ( fd_slot_state_t const * ss ) { return ss->skip_stake;          }
FD_FN_PURE ulong fd_slot_state_skip_fallback_stake ( fd_slot_state_t const * ss ) { return ss->skip_fallback_stake; }
FD_FN_PURE ulong fd_slot_state_finalize_stake      ( fd_slot_state_t const * ss ) { return ss->finalize_stake;      }
FD_FN_PURE ulong fd_slot_state_notar_or_skip_stake ( fd_slot_state_t const * ss ) { return ss->notar_or_skip_stake; }
FD_FN_PURE ulong fd_slot_state_top_notar_stake     ( fd_slot_state_t const * ss ) { return ss->top_notar_stake;     }

FD_FN_PURE int
fd_slot_state_has_notar_vote( fd_slot_state_t const * ss, ulong v ) {
  return (int)votes_const( ss )[ v ].has_notar;
}

FD_FN_PURE int fd_slot_state_has_notar_cert        ( fd_slot_state_t const * ss ) { return ss->certs.has_notar;         }
FD_FN_PURE int fd_slot_state_has_skip_cert         ( fd_slot_state_t const * ss ) { return ss->certs.has_skip;          }
FD_FN_PURE int fd_slot_state_has_fast_finalize_cert( fd_slot_state_t const * ss ) { return ss->certs.has_fast_finalize; }
FD_FN_PURE int fd_slot_state_has_finalize_cert     ( fd_slot_state_t const * ss ) { return ss->certs.has_finalize;      }
