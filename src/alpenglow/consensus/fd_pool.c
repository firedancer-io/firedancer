#include "fd_pool.h"
#include "pool/fd_finality_tracker.h"
#include "pool/fd_parent_ready_tracker.h"
#include "pool/fd_slot_state.h"

/* ---------------------------------------------------------------------------
   slot_states: BTreeMap<Slot, SlotState>.

   Each live slot owns a wksp-backed fd_slot_state region.  We pre-allocate a
   contiguous arena of slot_max fixed-size slot_state regions (each of
   fd_slot_state_footprint(validator_max)) and bind one to each pool entry by
   gaddr, mirroring how fd_ghost binds a vtr_dlist per block.  A slotent_t is
   the BTreeMap value; it carries the gaddr of its slot_state plus the per-slot
   certificate and own-vote storage the pool needs for standstill recovery
   (the slot_state itself does not expose its stored certs / votes, so the
   pool keeps its own copy as each cert / own vote is added). */

/* sc_certs_t mirrors the subset of SlotCertificates the pool re-broadcasts
   (get_certs / get_final_certs): one of each single-cert kind plus an array
   of notar-fallback certs. */

#define FD_POOL_NF_CERT_MAX (32UL)

struct sc_certs {
  int                      has_notar;         fd_notar_cert_t      notar;
  int                      has_skip;          fd_skip_cert_t       skip;
  int                      has_fast_finalize; fd_fast_final_cert_t fast_finalize;
  int                      has_finalize;      fd_final_cert_t      finalize;
  ulong                    nf_cnt;
  fd_notar_fallback_cert_t nf[ FD_POOL_NF_CERT_MAX ];
};
typedef struct sc_certs sc_certs_t;

/* sc_own_votes_t mirrors the own (epoch_info.own_id()) votes get_own_votes
   re-broadcasts: notar / skip / skip_fallback / final (one each) plus the
   per-hash notar-fallback votes.  These are the votes the local validator
   itself cast (signer == own_id). */

#define FD_POOL_OWN_NF_VOTE_MAX (8UL)

struct sc_own_votes {
  int                      has_notar;         fd_notar_vote_t          notar;
  int                      has_skip;          fd_skip_vote_t           skip;
  int                      has_skip_fallback; fd_skip_fallback_vote_t  skip_fallback;
  int                      has_finalize;      fd_final_vote_t          finalize;
  ulong                    nf_cnt;
  fd_notar_fallback_vote_t nf[ FD_POOL_OWN_NF_VOTE_MAX ];
};
typedef struct sc_own_votes sc_own_votes_t;

struct slotent {
  ulong          slot;       /* map key: the slot                          */
  ulong          next;       /* pool / map_chain reserved                  */
  ulong          ss_gaddr;   /* gaddr of this slot's fd_slot_state region  */
  sc_certs_t     certs;      /* pool-side copy of created certificates     */
  sc_own_votes_t own_votes;  /* pool-side copy of own (own_id) votes       */
};
typedef struct slotent slotent_t;

#define POOL_NAME slotent_pool
#define POOL_T    slotent_t
#include "../../util/tmpl/fd_pool.c"

#define MAP_NAME               slotent_map
#define MAP_ELE_T              slotent_t
#define MAP_KEY                slot
#define MAP_KEY_T              ulong
#define MAP_KEY_EQ(k0,k1)      ((*(k0))==(*(k1)))
#define MAP_KEY_HASH(key,seed) (fd_ulong_hash( (*(key)) ^ (seed) ))
#define MAP_NEXT               next
#include "../../util/tmpl/fd_map_chain.c"

typedef slotent_t slotent_pool_t;

/* ---------------------------------------------------------------------------
   s2n_waiting_parent_cert: BTreeMap<BlockId, BlockId>.

   Keyed by the parent block id; value is the child (slot, hash) that is
   waiting for the parent's notar(-fallback) cert. */

struct s2nent {
  fd_block_id_t parent; /* map key: the awaited parent block id */
  ulong         next;   /* pool / map_chain reserved            */
  fd_block_id_t child;  /* the waiting child block id           */
};
typedef struct s2nent s2nent_t;

#define POOL_NAME s2nent_pool
#define POOL_T    s2nent_t
#include "../../util/tmpl/fd_pool.c"

#define MAP_NAME               s2nent_map
#define MAP_ELE_T              s2nent_t
#define MAP_KEY                parent
#define MAP_KEY_T              fd_block_id_t
#define MAP_KEY_EQ(k0,k1)      (fd_block_id_eq((k0),(k1)))
#define MAP_KEY_HASH(key,seed) (fd_hash((seed),(key),sizeof(fd_block_id_t)))
#define MAP_NEXT               next
#include "../../util/tmpl/fd_map_chain.c"

typedef s2nent_t s2nent_pool_t;

/* ---------------------------------------------------------------------------
   fd_pool top struct (relocatable wksp object).

   Holds only gaddrs / scalars.  The embedded fd_epoch_info_t, the slot_state
   arena, the two pools/maps and the two trackers are bump-allocated
   contiguously after this struct in the canonical fd_ghost.c layout. */

struct __attribute__((aligned(128UL))) fd_pool {
  ulong wksp_gaddr;     /* gaddr of this struct in its backing wksp */

  ulong slot_max;       /* capacity of the slot_state arena / slotent pool */
  ulong validator_max;  /* per-slot validator capacity                     */
  ulong seed;           /* seed used to (re)format slot_state regions      */
  ulong ss_footprint;   /* per-region fd_slot_state footprint              */

  /* gaddrs of bump-allocated regions */
  ulong ss_arena_gaddr;     /* slot_state arena: slot_max regions        */
  ulong slotent_pool_gaddr;
  ulong slotent_map_gaddr;
  ulong s2n_pool_gaddr;
  ulong s2n_map_gaddr;
  ulong finality_gaddr;     /* fd_finality_tracker                       */
  ulong parent_ready_gaddr; /* fd_parent_ready_tracker                   */
};

/* ---------------------------------------------------------------------------
   wksp accessors (fd_ghost.c idiom). */

FD_FN_PURE static inline fd_wksp_t *
pool_wksp( fd_pool_t const * pool ) {
  return (fd_wksp_t *)( ((ulong)pool) - pool->wksp_gaddr );
}

static inline slotent_pool_t *  slotent_pool( fd_pool_t const * pool ) { return (slotent_pool_t *)fd_wksp_laddr_fast( pool_wksp( pool ), pool->slotent_pool_gaddr ); }
static inline slotent_map_t *   slotent_map ( fd_pool_t const * pool ) { return (slotent_map_t  *)fd_wksp_laddr_fast( pool_wksp( pool ), pool->slotent_map_gaddr  ); }
static inline s2nent_pool_t *   s2n_pool    ( fd_pool_t const * pool ) { return (s2nent_pool_t  *)fd_wksp_laddr_fast( pool_wksp( pool ), pool->s2n_pool_gaddr     ); }
static inline s2nent_map_t *    s2n_map     ( fd_pool_t const * pool ) { return (s2nent_map_t   *)fd_wksp_laddr_fast( pool_wksp( pool ), pool->s2n_map_gaddr      ); }
static inline fd_finality_tracker_t *     finality    ( fd_pool_t const * pool ) { return (fd_finality_tracker_t     *)fd_wksp_laddr_fast( pool_wksp( pool ), pool->finality_gaddr     ); }
static inline fd_parent_ready_tracker_t * parent_ready( fd_pool_t const * pool ) { return (fd_parent_ready_tracker_t *)fd_wksp_laddr_fast( pool_wksp( pool ), pool->parent_ready_gaddr ); }

/* slot_state_region returns the laddr of the i-th slot_state region in the
   arena (i in [0,slot_max)). */

static inline void *
slot_state_region( fd_pool_t const * pool, ulong i ) {
  uchar * arena = (uchar *)fd_wksp_laddr_fast( pool_wksp( pool ), pool->ss_arena_gaddr );
  return arena + i*pool->ss_footprint;
}

/* slotent_ss returns a join to the slot_state owned by entry e. */

static inline fd_slot_state_t *
slotent_ss( fd_pool_t const * pool, slotent_t const * e ) {
  return fd_slot_state_join( fd_wksp_laddr_fast( pool_wksp( pool ), e->ss_gaddr ) );
}

/* ---------------------------------------------------------------------------
   Sizing. */

ulong
fd_pool_align( void ) {
  return alignof(fd_pool_t);
}

ulong
fd_pool_footprint( ulong slot_max,
                   ulong validator_max,
                   ulong blockid_max ) {
  if( FD_UNLIKELY( slot_max==0UL || validator_max==0UL || blockid_max==0UL ) ) return 0UL;

  ulong ss_fp = fd_slot_state_footprint( validator_max );
  if( FD_UNLIKELY( !ss_fp ) ) return 0UL;

  ulong se_max       = fd_ulong_pow2_up( slot_max );
  ulong se_chain     = slotent_map_chain_cnt_est( se_max );
  ulong s2n_max      = fd_ulong_pow2_up( blockid_max );
  ulong s2n_chain    = s2nent_map_chain_cnt_est( s2n_max );

  return FD_LAYOUT_FINI(
    FD_LAYOUT_APPEND(
    FD_LAYOUT_APPEND(
    FD_LAYOUT_APPEND(
    FD_LAYOUT_APPEND(
    FD_LAYOUT_APPEND(
    FD_LAYOUT_APPEND(
    FD_LAYOUT_APPEND(
    FD_LAYOUT_APPEND(
    FD_LAYOUT_INIT,
      alignof(fd_pool_t),                sizeof(fd_pool_t)                                      ),
      fd_slot_state_align(),             ss_fp*slot_max                                         ),
      slotent_pool_align(),              slotent_pool_footprint( se_max )                       ),
      slotent_map_align(),               slotent_map_footprint ( se_chain )                     ),
      s2nent_pool_align(),               s2nent_pool_footprint ( s2n_max )                      ),
      s2nent_map_align(),                s2nent_map_footprint  ( s2n_chain )                    ),
      fd_finality_tracker_align(),       fd_finality_tracker_footprint( slot_max, blockid_max ) ),
      fd_parent_ready_tracker_align(),   fd_parent_ready_tracker_footprint( slot_max )          ),
    fd_pool_align() );
}

void *
fd_pool_new( void *                      mem,
             ulong                       slot_max,
             ulong                       validator_max,
             ulong                       blockid_max,
             ulong                       seed,
             ulong                       root_slot,
             fd_hash_t const *           root_block_hash ) {

  if( FD_UNLIKELY( !mem ) ) {
    FD_LOG_WARNING(( "NULL mem" ));
    return NULL;
  }
  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)mem, fd_pool_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned mem" ));
    return NULL;
  }
  ulong footprint = fd_pool_footprint( slot_max, validator_max, blockid_max );
  if( FD_UNLIKELY( !footprint ) ) {
    FD_LOG_WARNING(( "bad slot_max/validator_max/blockid_max (%lu/%lu/%lu)", slot_max, validator_max, blockid_max ));
    return NULL;
  }
  fd_wksp_t * wksp = fd_wksp_containing( mem );
  if( FD_UNLIKELY( !wksp ) ) {
    FD_LOG_WARNING(( "mem must be part of a workspace" ));
    return NULL;
  }

  fd_memset( mem, 0, footprint );

  ulong ss_fp     = fd_slot_state_footprint( validator_max );
  ulong se_max    = fd_ulong_pow2_up( slot_max );
  ulong se_chain  = slotent_map_chain_cnt_est( se_max );
  ulong s2n_max   = fd_ulong_pow2_up( blockid_max );
  ulong s2n_chain = s2nent_map_chain_cnt_est( s2n_max );

  FD_SCRATCH_ALLOC_INIT( l, mem );
  fd_pool_t * pool         = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_pool_t),              sizeof(fd_pool_t)                                      );
  void *      ss_arena     = FD_SCRATCH_ALLOC_APPEND( l, fd_slot_state_align(),           ss_fp*slot_max                                         );
  void *      se_pool      = FD_SCRATCH_ALLOC_APPEND( l, slotent_pool_align(),            slotent_pool_footprint( se_max )                       );
  void *      se_map       = FD_SCRATCH_ALLOC_APPEND( l, slotent_map_align(),             slotent_map_footprint ( se_chain )                     );
  void *      s2n_p        = FD_SCRATCH_ALLOC_APPEND( l, s2nent_pool_align(),             s2nent_pool_footprint ( s2n_max )                      );
  void *      s2n_m        = FD_SCRATCH_ALLOC_APPEND( l, s2nent_map_align(),              s2nent_map_footprint  ( s2n_chain )                    );
  void *      fin_mem      = FD_SCRATCH_ALLOC_APPEND( l, fd_finality_tracker_align(),     fd_finality_tracker_footprint( slot_max, blockid_max ) );
  void *      pr_mem       = FD_SCRATCH_ALLOC_APPEND( l, fd_parent_ready_tracker_align(), fd_parent_ready_tracker_footprint( slot_max )          );
  FD_TEST( FD_SCRATCH_ALLOC_FINI( l, fd_pool_align() ) == (ulong)mem + footprint );

  pool->wksp_gaddr    = fd_wksp_gaddr_fast( wksp, pool );
  pool->slot_max      = slot_max;
  pool->validator_max = validator_max;
  pool->seed          = seed;
  pool->ss_footprint  = ss_fp;

  pool->ss_arena_gaddr     = fd_wksp_gaddr_fast( wksp, ss_arena );
  pool->slotent_pool_gaddr = fd_wksp_gaddr_fast( wksp, slotent_pool_join( slotent_pool_new( se_pool, se_max          ) ) );
  pool->slotent_map_gaddr  = fd_wksp_gaddr_fast( wksp, slotent_map_join ( slotent_map_new ( se_map,  se_chain,  seed ) ) );
  pool->s2n_pool_gaddr     = fd_wksp_gaddr_fast( wksp, s2nent_pool_join ( s2nent_pool_new ( s2n_p,   s2n_max         ) ) );
  pool->s2n_map_gaddr      = fd_wksp_gaddr_fast( wksp, s2nent_map_join  ( s2nent_map_new  ( s2n_m,   s2n_chain, seed ) ) );
  pool->finality_gaddr     = fd_wksp_gaddr_fast( wksp, fd_finality_tracker_join( fd_finality_tracker_new( fin_mem, slot_max, blockid_max, seed, root_slot, root_block_hash ) ) );

  fd_parent_ready_tracker_t * pr = fd_parent_ready_tracker_join( fd_parent_ready_tracker_new( pr_mem, slot_max, seed ) );
  if( root_slot==0UL ) fd_parent_ready_tracker_default  ( pr );                            /* genesis  */
  else                 fd_parent_ready_tracker_seed_root( pr, root_slot, root_block_hash ); /* snapshot */
  pool->parent_ready_gaddr = fd_wksp_gaddr_fast( wksp, pr );

  return mem;
}

fd_pool_t *
fd_pool_join( void * mem ) {
  fd_pool_t * pool = (fd_pool_t *)mem;
  if( FD_UNLIKELY( !pool ) ) {
    FD_LOG_WARNING(( "NULL mem" ));
    return NULL;
  }
  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)pool, fd_pool_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned mem" ));
    return NULL;
  }
  return pool;
}

void *
fd_pool_leave( fd_pool_t const * pool ) {
  if( FD_UNLIKELY( !pool ) ) {
    FD_LOG_WARNING(( "NULL pool" ));
    return NULL;
  }
  return (void *)pool;
}

void *
fd_pool_delete( void * mem ) {
  if( FD_UNLIKELY( !mem ) ) {
    FD_LOG_WARNING(( "NULL mem" ));
    return NULL;
  }
  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)mem, fd_pool_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned mem" ));
    return NULL;
  }
  return mem;
}

/* ---------------------------------------------------------------------------
   slot_state map access. */

/* slotent_query returns the slot entry for slot, or NULL if absent. */

static slotent_t *
slotent_query( fd_pool_t * pool, ulong slot ) {
  return slotent_map_ele_query( slotent_map( pool ), &slot, NULL, slotent_pool( pool ) );
}

FD_FN_PURE static slotent_t const *
slotent_query_const( fd_pool_t const * pool, ulong slot ) {
  return slotent_map_ele_query_const( slotent_map( pool ), &slot, NULL, slotent_pool( pool ) );
}

/* get_slot_state mutably accesses the SlotState for slot, creating a fresh
   one (formatting its arena region) if none exists.  Mirrors
   PoolImpl::slot_state.  Returns NULL only if the slotent pool is exhausted. */

static fd_slot_state_t *
get_slot_state( fd_pool_t * pool, ulong slot, fd_validator_epoch_info_t const * ei ) {
  slotent_t * e = slotent_query( pool, slot );
  if( FD_LIKELY( e ) ) return slotent_ss( pool, e );

  if( FD_UNLIKELY( !slotent_pool_free( slotent_pool( pool ) ) ) ) {
    FD_LOG_WARNING(( "slot_state pool exhausted (slot_max=%lu)", pool->slot_max ));
    return NULL;
  }

  e = slotent_pool_ele_acquire( slotent_pool( pool ) );
  ulong idx = slotent_pool_idx( slotent_pool( pool ), e );
  e->slot = slot;
  memset( &e->certs,     0, sizeof(sc_certs_t)     );
  memset( &e->own_votes, 0, sizeof(sc_own_votes_t) );

  void * region = slot_state_region( pool, idx );
  e->ss_gaddr = fd_wksp_gaddr_fast( pool_wksp( pool ),
                                    fd_slot_state_new( region, slot, ei->own_id, pool->validator_max, pool->seed ) );
  slotent_map_ele_insert( slotent_map( pool ), e, slotent_pool( pool ) );
  return slotent_ss( pool, e );
}

/* ---------------------------------------------------------------------------
   Output sink helpers. */

static void
out_push_evt( fd_pool_out_t * out, fd_pool_evt_t const * ev ) {
  if( !out ) return;
  FD_TEST( out->events_cnt < out->events_max );
  out->events[ out->events_cnt++ ] = *ev;
}

static void
out_push_cert_created( fd_pool_out_t * out, fd_cert_t const * cert ) {
  fd_pool_evt_t ev;
  ev.kind       = FD_POOL_EVT_CERT_CREATED;
  ev.inner.cert = *cert;
  out_push_evt( out, &ev );
}

static void
out_push_safe_to_notar( fd_pool_out_t * out, fd_block_id_t const * block ) {
  fd_pool_evt_t ev;
  ev.kind        = FD_POOL_EVT_SAFE_TO_NOTAR;
  ev.inner.block = *block;
  out_push_evt( out, &ev );
}

static void
out_push_safe_to_skip( fd_pool_out_t * out, ulong slot ) {
  fd_pool_evt_t ev;
  ev.kind       = FD_POOL_EVT_SAFE_TO_SKIP;
  ev.inner.slot = slot;
  out_push_evt( out, &ev );
}

static void
out_push_parent_ready( fd_pool_out_t * out, ulong slot, fd_block_id_t const * parent ) {
  FD_TEST( fd_alpenglow_is_start_of_window( slot ) );
  fd_pool_evt_t ev;
  ev.kind                       = FD_POOL_EVT_PARENT_READY;
  ev.inner.parent_ready.slot    = slot;
  ev.inner.parent_ready.parent  = *parent;
  out_push_evt( out, &ev );
}

static void
out_push_repair( fd_pool_out_t * out, fd_block_id_t const * block ) {
  if( !out ) return;
  FD_TEST( out->repairs_cnt < out->repairs_max );
  out->repairs[ out->repairs_cnt++ ] = *block;
}

/* ---------------------------------------------------------------------------
   send_parent_ready_events (PoolImpl::send_parent_ready_events). */

static void
send_parent_ready_events( fd_pool_out_t *           out,
                          fd_parent_ready_t const * prs,
                          ulong                     pr_cnt ) {
  for( ulong i=0UL; i<pr_cnt; i++ ) {
    out_push_parent_ready( out, prs[i].slot, &prs[i].parent );
  }
}

/* ---------------------------------------------------------------------------
   pool-side cert / own-vote bookkeeping (for get_certs / get_own_votes). */

/* slotent_record_cert mirrors how the slot_state stores a created cert, but
   keeps the pool's own copy so recover_from_standstill can re-emit it (the
   slot_state does not expose its stored certs). */

static void
slotent_record_cert( slotent_t * e, fd_cert_t const * cert ) {
  sc_certs_t * c = &e->certs;
  switch( cert->discriminant ) {
  case FD_CERT_TYPE_NOTAR:
    c->has_notar = 1; c->notar = cert->inner.notar; break;
  case FD_CERT_TYPE_NOTAR_FALLBACK: {
    for( ulong i=0UL; i<c->nf_cnt; i++ ) {
      if( !memcmp( c->nf[i].block_hash.uc, cert->inner.notar_fallback.block_hash.uc, sizeof(fd_hash_t) ) ) return;
    }
    FD_TEST( c->nf_cnt < FD_POOL_NF_CERT_MAX );
    c->nf[ c->nf_cnt++ ] = cert->inner.notar_fallback;
    break;
  }
  case FD_CERT_TYPE_SKIP:
    c->has_skip = 1; c->skip = cert->inner.skip; break;
  case FD_CERT_TYPE_FAST_FINAL:
    c->has_fast_finalize = 1; c->fast_finalize = cert->inner.fast_final; break;
  case FD_CERT_TYPE_FINAL:
    c->has_finalize = 1; c->finalize = cert->inner.final_; break;
  default:
    FD_LOG_ERR(( "invalid cert discriminant %u", cert->discriminant ));
  }
}

/* slotent_record_own_vote records a vote cast by the local validator
   (signer == own_id) so get_own_votes can re-broadcast it. */

static void
slotent_record_own_vote( slotent_t * e, fd_ag_vote_t const * vote ) {
  sc_own_votes_t * v = &e->own_votes;
  switch( vote->discriminant ) {
  case FD_VOTE_TYPE_NOTAR:
    v->has_notar = 1; v->notar = vote->inner.notar; break;
  case FD_VOTE_TYPE_NOTAR_FALLBACK:
    if( v->nf_cnt < FD_POOL_OWN_NF_VOTE_MAX ) v->nf[ v->nf_cnt++ ] = vote->inner.notar_fallback;
    break;
  case FD_VOTE_TYPE_SKIP:
    v->has_skip = 1; v->skip = vote->inner.skip; break;
  case FD_VOTE_TYPE_SKIP_FALLBACK:
    v->has_skip_fallback = 1; v->skip_fallback = vote->inner.skip_fallback; break;
  case FD_VOTE_TYPE_FINAL:
    v->has_finalize = 1; v->finalize = vote->inner.final_; break;
  default:
    FD_LOG_ERR(( "invalid vote discriminant %u", vote->discriminant ));
  }
}

/* ---------------------------------------------------------------------------
   prune (PoolImpl::prune). */

static void
prune( fd_pool_t * pool ) {
  ulong first_unpruned = fd_finality_tracker_first_unpruned_slot( finality( pool ) );

  /* drop slot_states for slots < first_unpruned.  Repeated scan-and-remove
     since iteration must not run alongside removes. */
  for(;;) {
    int   found     = 0;
    ulong drop_slot = 0UL;
    slotent_map_t  * map = slotent_map ( pool );
    slotent_pool_t * spl = slotent_pool( pool );
    for( slotent_map_iter_t it = slotent_map_iter_init( map, spl );
         !slotent_map_iter_done( it, map, spl );
         it = slotent_map_iter_next( it, map, spl ) ) {
      slotent_t const * e = slotent_map_iter_ele_const( it, map, spl );
      if( e->slot < first_unpruned ) { drop_slot = e->slot; found = 1; break; }
    }
    if( !found ) break;
    slotent_t * e = slotent_map_ele_remove( slotent_map( pool ), &drop_slot, NULL, slotent_pool( pool ) );
    FD_TEST( e );
    slotent_pool_ele_release( slotent_pool( pool ), e );
  }

  fd_parent_ready_tracker_prune( parent_ready( pool ), first_unpruned );
  /* finality tracker prunes its own state internally */
}

/* ---------------------------------------------------------------------------
   handle_finalization (PoolImpl::handle_finalization).

   Wires the finality tracker's FinalizationEvent into the parent_ready
   tracker (decomposed inputs), emits the resulting parent-ready events, and
   prunes. */

static void
handle_finalization( fd_pool_t *                     pool,
                     fd_finalization_event_t const * fe,
                     fd_pool_out_t *                 out ) {
  fd_parent_ready_t prs[ FD_PARENT_READY_OUT_MAX ];
  ulong             pr_cnt = 0UL;
  fd_parent_ready_tracker_handle_finalization( parent_ready( pool ),
                                               fe->has_finalized, &fe->finalized,
                                               fe->implicitly_finalized, fe->if_cnt,
                                               fe->implicitly_skipped,   fe->is_cnt,
                                               prs, &pr_cnt );
  send_parent_ready_events( out, prs, pr_cnt );
  prune( pool );
}

/* ---------------------------------------------------------------------------
   add_valid_cert (PoolImpl::add_valid_cert).

   Adds the (assumed-valid) cert, performs the resulting finality / parent-
   ready / safe-to-notar handover, and emits CertCreated.  Returns
   FD_POOL_SUCCESS, or FD_POOL_ERR_FULL if slot_state allocation fails. */

static int
add_valid_cert( fd_pool_t *                       pool,
                fd_cert_t const *                 cert,
                fd_validator_epoch_info_t const * ei,
                fd_pool_out_t *                   out ) {
  ulong slot = fd_cert_slot( cert );

  fd_slot_state_t * ss = get_slot_state( pool, slot, ei );
  if( FD_UNLIKELY( !ss ) ) return FD_POOL_ERR_FULL;
  fd_slot_state_add_cert( ss, cert );

  /* keep the pool's own copy for standstill recovery */
  slotent_record_cert( slotent_query( pool, slot ), cert );

  switch( cert->discriminant ) {

  case FD_CERT_TYPE_NOTAR:
  case FD_CERT_TYPE_NOTAR_FALLBACK: {
    fd_hash_t const * block_hash = fd_cert_block_hash( cert );
    fd_block_id_t     block_id; block_id.slot = slot; block_id.hash = *block_hash;

    if( cert->discriminant==FD_CERT_TYPE_NOTAR ) {
      fd_finalization_event_t fe[1];
      fd_finality_tracker_mark_notarized( finality( pool ), &block_id, fe );
      handle_finalization( pool, fe, out );
    }

    /* potentially notify child waiting for safe-to-notar */
    s2nent_t * waiting = s2nent_map_ele_query( s2n_map( pool ), &block_id, NULL, s2n_pool( pool ) );
    if( waiting ) {
      fd_block_id_t child = waiting->child;
      s2nent_map_ele_remove( s2n_map( pool ), &block_id, NULL, s2n_pool( pool ) );
      s2nent_pool_ele_release( s2n_pool( pool ), waiting );

      fd_slot_state_t * child_ss = get_slot_state( pool, child.slot, ei );
      if( FD_UNLIKELY( !child_ss ) ) return FD_POOL_ERR_FULL;
      fd_notify_parent_result_t r = fd_slot_state_notify_parent_certified( child_ss, &child.hash, ei->epoch );
      if( r.kind==FD_NOTIFY_PARENT_EVENT ) {
        out_push_safe_to_notar( out, &r.inner.event.block );
      } else if( r.kind==FD_NOTIFY_PARENT_REPAIR ) {
        out_push_repair( out, &r.inner.repair );
      }
    }

    /* add block to parent-ready tracker, emit any new parents */
    fd_parent_ready_t prs[ FD_PARENT_READY_OUT_MAX ];
    ulong             pr_cnt = 0UL;
    fd_parent_ready_tracker_mark_notar_fallback( parent_ready( pool ), &block_id, prs, &pr_cnt );
    send_parent_ready_events( out, prs, pr_cnt );

    /* repair this block, if necessary */
    out_push_repair( out, &block_id );
    break;
  }

  case FD_CERT_TYPE_SKIP: {
    fd_parent_ready_t prs[ FD_PARENT_READY_OUT_MAX ];
    ulong             pr_cnt = 0UL;
    fd_parent_ready_tracker_mark_skipped( parent_ready( pool ), slot, prs, &pr_cnt );
    send_parent_ready_events( out, prs, pr_cnt );
    break;
  }

  case FD_CERT_TYPE_FAST_FINAL: {
    fd_block_id_t block_id; block_id.slot = slot; block_id.hash = *fd_cert_block_hash( cert );
    fd_finalization_event_t fe[1];
    fd_finality_tracker_mark_fast_finalized( finality( pool ), &block_id, fe );
    handle_finalization( pool, fe, out );
    break;
  }

  case FD_CERT_TYPE_FINAL: {
    fd_finalization_event_t fe[1];
    fd_finality_tracker_mark_finalized( finality( pool ), slot, fe );
    handle_finalization( pool, fe, out );
    break;
  }

  default:
    FD_LOG_ERR(( "invalid cert discriminant %u", cert->discriminant ));
  }

  /* send to votor for broadcasting.  NOTE: prune() above may have removed
     this slot's entry; CertCreated does not depend on the slot_state. */
  out_push_cert_created( out, cert );
  return FD_POOL_SUCCESS;
}

/* ---------------------------------------------------------------------------
   add_cert (PoolImpl::add_cert). */

int
fd_pool_add_cert( fd_pool_t *                       pool,
                  fd_cert_t       const *           cert,
                  fd_validator_epoch_info_t const * ei,
                  fd_pool_out_t *                   out ) {
  ulong slot = fd_cert_slot( cert );

  /* check if the certificate is a duplicate */
  fd_slot_state_t * ss = get_slot_state( pool, slot, ei );
  if( FD_UNLIKELY( !ss ) ) return FD_POOL_ERR_FULL;
  int duplicate = 0;
  switch( cert->discriminant ) {
  case FD_CERT_TYPE_NOTAR:          duplicate = fd_slot_state_has_notar_cert        ( ss );                                          break;
  case FD_CERT_TYPE_NOTAR_FALLBACK: duplicate = fd_slot_state_is_notar_fallback     ( ss, fd_cert_block_hash( cert ) );             break;
  case FD_CERT_TYPE_SKIP:           duplicate = fd_slot_state_has_skip_cert         ( ss );                                          break;
  case FD_CERT_TYPE_FAST_FINAL:     duplicate = fd_slot_state_has_fast_finalize_cert( ss );                                          break;
  case FD_CERT_TYPE_FINAL:          duplicate = fd_slot_state_has_finalize_cert     ( ss );                                          break;
  default:                          FD_LOG_ERR(( "invalid cert discriminant %u", cert->discriminant ));
  }

  if( FD_LIKELY( duplicate ) ) return FD_POOL_ERR_DUPLICATE;

  /* ignore old and far-in-the-future certificates */
  ulong slot_far_in_future = fd_pool_finalized_slot( pool ) + 2UL*FD_ALPENGLOW_SLOTS_PER_EPOCH;
  if( FD_UNLIKELY( slot < fd_pool_first_unpruned_slot( pool ) || slot >= slot_far_in_future ) ) return FD_POOL_ERR_SLOT_OUT_OF_BOUNDS;

  /* verify stake threshold & signature */
  if( FD_UNLIKELY( !fd_cert_check_threshold( cert, ei->epoch ) ) ) return FD_POOL_ERR_THRESHOLD_NOT_MET;

  if( FD_UNLIKELY( !fd_cert_check_sig( cert, ei->epoch ) ) ) return FD_POOL_ERR_INVALID_SIGNATURE;

  return add_valid_cert( pool, cert, ei, out );
}

/* ---------------------------------------------------------------------------
   add_vote (PoolImpl::add_vote). */

int
fd_pool_add_vote( fd_pool_t *                       pool,
                  fd_ag_vote_t const *              vote,
                  fd_validator_epoch_info_t const * ei,
                  fd_pool_out_t *                   out,
                  fd_slashable_offence_t *          out_offence ) {
  ulong slot = fd_vote_slot( vote );

  /* ignore old and far-in-the-future votes */
  ulong slot_far_in_future = fd_pool_finalized_slot( pool ) + 2UL*FD_ALPENGLOW_SLOTS_PER_EPOCH;
  if( slot < fd_pool_first_unpruned_slot( pool ) || slot >= slot_far_in_future ) {
    return FD_POOL_ERR_SLOT_OUT_OF_BOUNDS;
  }

  /* reject votes from validators outside the current epoch's set */
  ulong signer = fd_vote_signer( vote );
  if( signer >= ei->epoch->validator_cnt ) {
    return FD_POOL_ERR_UNKNOWN_SIGNER;
  }

  /* verify signature */
  fd_validator_info_t const * v = fd_epoch_info_validator( ei->epoch, signer );
  if( !fd_vote_check_sig( vote, &v->voting_pubkey ) ) {
    return FD_POOL_ERR_INVALID_SIGNATURE;
  }

  ulong voter_stake = v->stake;

  fd_slot_state_t * ss = get_slot_state( pool, slot, ei );
  if( FD_UNLIKELY( !ss ) ) return FD_POOL_ERR_FULL;

  /* slashable / duplicate checks (slashable first, per Rust) */
  fd_slashable_offence_t off = fd_slot_state_check_slashable_offence( ss, vote );
  if( off.kind!=FD_SLASHABLE_NONE ) {
    if( out_offence ) *out_offence = off;
    return FD_POOL_ERR_SLASHABLE;
  }
  if( fd_slot_state_should_ignore_vote( ss, vote ) ) {
    return FD_POOL_ERR_DUPLICATE;
  }

  /* actually add the vote (collects new certs / events / repairs) */
  fd_cert_t       certs_buf  [ 4 ];
  fd_pool_event_t events_buf [ 16 ];
  fd_block_id_t   repairs_buf[ 16 ];
  fd_slot_state_outputs_t so;
  so.certs   = certs_buf;   so.certs_cnt   = 0UL; so.certs_max   = 4UL;
  so.events  = events_buf;  so.events_cnt  = 0UL; so.events_max  = 16UL;
  so.repairs = repairs_buf; so.repairs_cnt = 0UL; so.repairs_max = 16UL;

  fd_slot_state_add_vote( ss, vote, voter_stake, ei->epoch, &so );

  /* record own votes for standstill recovery */
  if( signer==ei->own_id ) {
    slotent_record_own_vote( slotent_query( pool, slot ), vote );
  }

  /* handle resulting events.  add_valid_cert may prune / reallocate slot
     states, so consume the slot_state outputs (taken by value) first. */
  for( ulong i=0UL; i<so.events_cnt; i++ ) {
    if( so.events[i].kind==FD_POOL_EVENT_SAFE_TO_NOTAR ) out_push_safe_to_notar( out, &so.events[i].block );
    else                                                 out_push_safe_to_skip ( out, so.events[i].block.slot );
  }
  for( ulong i=0UL; i<so.repairs_cnt; i++ ) {
    out_push_repair( out, &so.repairs[i] );
  }
  for( ulong i=0UL; i<so.certs_cnt; i++ ) {
    int err = add_valid_cert( pool, &so.certs[i], ei, out );
    //FD_LOG_NOTICE(("add_vote CAUSED CERT GENERATION! slot %lu, signer %lu, voter_stake %lu, err %d", slot, signer, voter_stake, err));
    if( FD_UNLIKELY( err ) ) return err;
  }

  return FD_POOL_SUCCESS;
}

/* ---------------------------------------------------------------------------
   add_block (PoolImpl::add_block). */

void
fd_pool_add_block( fd_pool_t *                       pool,
                   fd_block_id_t const *             block_id,
                   fd_block_id_t const *             parent_id,
                   fd_validator_epoch_info_t const * ei,
                   fd_pool_out_t *                   out ) {
  FD_TEST( block_id->slot > parent_id->slot );

  /* finality tracker parent edge -> parent-ready handover */
  fd_finalization_event_t fe[1];
  fd_finality_tracker_add_parent( finality( pool ), block_id, parent_id, fe );
  handle_finalization( pool, fe, out );

  fd_slot_state_t * ss = get_slot_state( pool, block_id->slot, ei );
  if( FD_UNLIKELY( !ss ) ) return;
  fd_slot_state_notify_parent_known( ss, &block_id->hash );

  /* if the parent is already notar-fallback, certify immediately;
     otherwise park the child waiting for the parent's cert. */
  slotent_t * parent_ent = slotent_query( pool, parent_id->slot );
  if( parent_ent ) {
    fd_slot_state_t * parent_ss = slotent_ss( pool, parent_ent );
    if( fd_slot_state_is_notar_fallback( parent_ss, &parent_id->hash ) ) {
      fd_slot_state_t * child_ss = get_slot_state( pool, block_id->slot, ei );
      if( FD_UNLIKELY( !child_ss ) ) return;
      fd_notify_parent_result_t r = fd_slot_state_notify_parent_certified( child_ss, &block_id->hash, ei->epoch );
      if( r.kind==FD_NOTIFY_PARENT_EVENT ) {
        out_push_safe_to_notar( out, &r.inner.event.block );
      } else if( r.kind==FD_NOTIFY_PARENT_REPAIR ) {
        out_push_repair( out, &r.inner.repair );
      }
      return;
    }
  }

  /* park: s2n_waiting_parent_cert.insert(parent_id, block_id) */
  s2nent_t * e = s2nent_map_ele_query( s2n_map( pool ), parent_id, NULL, s2n_pool( pool ) );
  if( !e ) {
    FD_TEST( s2nent_pool_free( s2n_pool( pool ) ) );
    e = s2nent_pool_ele_acquire( s2n_pool( pool ) );
    e->parent = *parent_id;
    s2nent_map_ele_insert( s2n_map( pool ), e, s2n_pool( pool ) );
  }
  e->child = *block_id;
}

/* ---------------------------------------------------------------------------
   recover_from_standstill (PoolImpl::recover_from_standstill).

   get_final_certs(slot) ++ get_certs(slot.next()..) and
   get_own_votes(slot.next()..). */

static void
push_cert( fd_cert_t * certs, ulong * cnt, ulong max, int discriminant, void const * inner, ulong inner_sz ) {
  FD_TEST( *cnt < max );
  fd_cert_t * c = &certs[ (*cnt)++ ];
  c->discriminant = (uint)discriminant;
  memcpy( &c->inner, inner, inner_sz );
}

void
fd_pool_recover_from_standstill( fd_pool_t *     pool,
                                 fd_pool_out_t * out,
                                 fd_cert_t *     certs, ulong * certs_cnt, ulong certs_max,
                                 fd_ag_vote_t *  votes, ulong * votes_cnt, ulong votes_max ) {
  ulong slot = fd_pool_finalized_slot( pool );
  *certs_cnt = 0UL;
  *votes_cnt = 0UL;

  /* get_final_certs(slot): prefer fast-final, else final + notar. */
  slotent_t const * fe = slotent_query_const( pool, slot );
  if( fe ) {
    sc_certs_t const * c = &fe->certs;
    if( c->has_fast_finalize ) {
      push_cert( certs, certs_cnt, certs_max, FD_CERT_TYPE_FAST_FINAL, &c->fast_finalize, sizeof(c->fast_finalize) );
    } else if( c->has_finalize && c->has_notar ) {
      push_cert( certs, certs_cnt, certs_max, FD_CERT_TYPE_FINAL, &c->finalize, sizeof(c->finalize) );
      push_cert( certs, certs_cnt, certs_max, FD_CERT_TYPE_NOTAR, &c->notar,    sizeof(c->notar)    );
    }
  }
  FD_TEST( *certs_cnt > 0UL ); /* "no final cert" */

  /* get_certs(slot.next()..) + get_own_votes(slot.next()..): iterate every
     live slot strictly above `slot`.  Order is unspecified (matches the
     Rust tests, which match by kind, not position). */
  slotent_map_t  *  map = slotent_map ( pool );
  slotent_pool_t *  spl = slotent_pool( pool );
  for( slotent_map_iter_t it = slotent_map_iter_init( map, spl );
       !slotent_map_iter_done( it, map, spl );
       it = slotent_map_iter_next( it, map, spl ) ) {
    slotent_t const * e = slotent_map_iter_ele_const( it, map, spl );
    if( e->slot <= slot ) continue;

    sc_certs_t const * c = &e->certs;
    if( c->has_finalize      ) push_cert( certs, certs_cnt, certs_max, FD_CERT_TYPE_FINAL,      &c->finalize,      sizeof(c->finalize)      );
    if( c->has_fast_finalize ) push_cert( certs, certs_cnt, certs_max, FD_CERT_TYPE_FAST_FINAL, &c->fast_finalize, sizeof(c->fast_finalize) );
    if( c->has_notar         ) push_cert( certs, certs_cnt, certs_max, FD_CERT_TYPE_NOTAR,      &c->notar,         sizeof(c->notar)         );
    for( ulong i=0UL; i<c->nf_cnt; i++ ) push_cert( certs, certs_cnt, certs_max, FD_CERT_TYPE_NOTAR_FALLBACK, &c->nf[i], sizeof(c->nf[i]) );
    if( c->has_skip          ) push_cert( certs, certs_cnt, certs_max, FD_CERT_TYPE_SKIP,       &c->skip,          sizeof(c->skip)          );

    sc_own_votes_t const * ov = &e->own_votes;
    if( ov->has_finalize ) { FD_TEST( *votes_cnt<votes_max ); votes[ *votes_cnt   ].discriminant=FD_VOTE_TYPE_FINAL;          votes[ (*votes_cnt)++ ].inner.final_        = ov->finalize;      }
    if( ov->has_notar    ) { FD_TEST( *votes_cnt<votes_max ); votes[ *votes_cnt   ].discriminant=FD_VOTE_TYPE_NOTAR;          votes[ (*votes_cnt)++ ].inner.notar         = ov->notar;         }
    for( ulong i=0UL; i<ov->nf_cnt; i++ ) { FD_TEST( *votes_cnt<votes_max ); votes[ *votes_cnt ].discriminant=FD_VOTE_TYPE_NOTAR_FALLBACK; votes[ (*votes_cnt)++ ].inner.notar_fallback = ov->nf[i]; }
    if( ov->has_skip          ) { FD_TEST( *votes_cnt<votes_max ); votes[ *votes_cnt ].discriminant=FD_VOTE_TYPE_SKIP;          votes[ (*votes_cnt)++ ].inner.skip          = ov->skip;          }
    if( ov->has_skip_fallback ) { FD_TEST( *votes_cnt<votes_max ); votes[ *votes_cnt ].discriminant=FD_VOTE_TYPE_SKIP_FALLBACK; votes[ (*votes_cnt)++ ].inner.skip_fallback = ov->skip_fallback; }
  }

  /* emit the standstill event (slot == finalized_slot.next()) */
  fd_pool_evt_t ev;
  ev.kind       = FD_POOL_EVT_STANDSTILL;
  ev.inner.slot = slot + 1UL;
  out_push_evt( out, &ev );
}

/* ---------------------------------------------------------------------------
   Accessors. */

FD_FN_PURE ulong
fd_pool_finalized_slot( fd_pool_t const * pool ) {
  return fd_finality_tracker_highest_finalized_slot( finality( pool ) );
}

FD_FN_PURE ulong
fd_pool_first_unpruned_slot( fd_pool_t const * pool ) {
  return fd_finality_tracker_first_unpruned_slot( finality( pool ) );
}

fd_block_id_t const *
fd_pool_parents_ready( fd_pool_t * pool, ulong slot, ulong * cnt ) {
  return fd_parent_ready_tracker_parents_ready( parent_ready( pool ), slot, cnt );
}

int
fd_pool_is_parent_ready( fd_pool_t * pool, ulong slot, fd_block_id_t const * parent ) {
  ulong cnt = 0UL;
  fd_block_id_t const * ready = fd_parent_ready_tracker_parents_ready( parent_ready( pool ), slot, &cnt );
  for( ulong i=0UL; i<cnt; i++ ) {
    if( fd_block_id_eq( &ready[i], parent ) ) return 1;
  }
  return 0;
}

FD_FN_PURE int
fd_pool_has_notar_or_fallback_cert( fd_pool_t const * pool, ulong slot ) {
  slotent_t const * e = slotent_query_const( pool, slot );
  if( !e ) return 0;
  return e->certs.has_notar || e->certs.nf_cnt>0UL;
}

int
fd_pool_get_notarized_block( fd_pool_t const * pool, ulong slot, fd_hash_t * out_hash ) {
  slotent_t const * e = slotent_query_const( pool, slot );
  if( !e || !e->certs.has_notar ) return 0;
  if( out_hash ) *out_hash = e->certs.notar.block_hash;
  return 1;
}

FD_FN_PURE int
fd_pool_has_final_cert( fd_pool_t const * pool, ulong slot ) {
  slotent_t const * e = slotent_query_const( pool, slot );
  if( !e ) return 0;
  return e->certs.has_fast_finalize || e->certs.has_finalize;
}

FD_FN_PURE int
fd_pool_has_notar_cert( fd_pool_t const * pool, ulong slot ) {
  slotent_t const * e = slotent_query_const( pool, slot );
  return e && e->certs.has_notar;
}

FD_FN_PURE int
fd_pool_has_skip_cert( fd_pool_t const * pool, ulong slot ) {
  slotent_t const * e = slotent_query_const( pool, slot );
  return e && e->certs.has_skip;
}

FD_FN_PURE int
fd_pool_contains_slot( fd_pool_t const * pool, ulong slot ) {
  return slotent_query_const( pool, slot )!=NULL;
}
