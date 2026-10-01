#include "fd_pack_dual_lane.h"

/* Bundle-lane entry states */
#define BSTATE_PENDING 0 /* in pack */
#define BSTATE_AWAIT   1 /* scheduled, outcome not yet known */
#define BSTATE_LANDED  2
#define BSTATE_FAILED  3 /* failed in execution, or left pack unscheduled */

struct ent {
  int   used;
  uint  next;         /* hash chain link, index+1, 0 terminates */
  uint  twin;         /* paired entry, index+1, 0 if unpaired */
  int   lane;
  int   done;         /* verdict emitted */
  int   bstate;       /* bundle lane only */
  long  insert_ns;
  long  sched_ns;
  ulong sched_slot;
  ulong txn_offer;    /* bundle lane only */
  ulong bundle_offer; /* bundle lane only */
  ulong obs_id;       /* bundle lane only */
  uchar sig[ 64 ];
};
typedef struct ent ent_t;

struct fd_pack_dual {
  ulong ent_max;
  ulong cursor;
  ulong evicted_young;
  ulong pair_cnt;

  fd_pack_dual_verdict_fn_t verdict_fn;
  void *                    verdict_ctx;

  uint  * head; /* ent_max buckets, keyed by signature */
  ent_t * ent;  /* ent_max */
};

FD_FN_CONST ulong
fd_pack_dual_align( void ) {
  return 64UL;
}

FD_FN_CONST ulong
fd_pack_dual_footprint( ulong ent_max ) {
  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, 64UL,           sizeof(fd_pack_dual_t) );
  l = FD_LAYOUT_APPEND( l, alignof(uint),  ent_max*sizeof(uint)   );
  l = FD_LAYOUT_APPEND( l, alignof(ent_t), ent_max*sizeof(ent_t)  );
  return FD_LAYOUT_FINI( l, fd_pack_dual_align() );
}

void *
fd_pack_dual_new( void * mem,
                  ulong  ent_max ) {
  if( FD_UNLIKELY( !mem ) ) return NULL;
  if( FD_UNLIKELY( ent_max<2UL || ent_max>(1UL<<31) || !fd_ulong_is_pow2( ent_max ) ) ) return NULL;

  FD_SCRATCH_ALLOC_INIT( l, mem );
  fd_pack_dual_t * dual = FD_SCRATCH_ALLOC_APPEND( l, 64UL,           sizeof(fd_pack_dual_t) );
  uint  *          head = FD_SCRATCH_ALLOC_APPEND( l, alignof(uint),  ent_max*sizeof(uint)   );
  ent_t *          ent  = FD_SCRATCH_ALLOC_APPEND( l, alignof(ent_t), ent_max*sizeof(ent_t)  );
  FD_SCRATCH_ALLOC_FINI( l, fd_pack_dual_align() );

  memset( dual, 0, sizeof(fd_pack_dual_t) );
  dual->ent_max = ent_max;
  memset( head, 0, ent_max*sizeof(uint)  );
  memset( ent,  0, ent_max*sizeof(ent_t) );
  return mem;
}

fd_pack_dual_t *
fd_pack_dual_join( void * mem ) {
  FD_SCRATCH_ALLOC_INIT( l, mem );
  fd_pack_dual_t * dual = FD_SCRATCH_ALLOC_APPEND( l, 64UL, sizeof(fd_pack_dual_t) );
  ulong ent_max = dual->ent_max;
  dual->head = FD_SCRATCH_ALLOC_APPEND( l, alignof(uint),  ent_max*sizeof(uint)  );
  dual->ent  = FD_SCRATCH_ALLOC_APPEND( l, alignof(ent_t), ent_max*sizeof(ent_t) );
  FD_SCRATCH_ALLOC_FINI( l, fd_pack_dual_align() );
  dual->verdict_fn  = NULL;
  dual->verdict_ctx = NULL;
  return dual;
}

void
fd_pack_dual_set_verdict_cb( fd_pack_dual_t *          dual,
                             fd_pack_dual_verdict_fn_t fn,
                             void *                    ctx ) {
  dual->verdict_fn  = fn;
  dual->verdict_ctx = ctx;
}

static inline ulong
bucket( fd_pack_dual_t const * dual,
        ulong                  sig8 ) {
  return fd_ulong_hash( sig8 ) & (dual->ent_max-1UL);
}

/* Decides the pair (t, b) if possible, or unconditionally if forced.
   Emits the verdict and marks both entries done. */

static void
evaluate( fd_pack_dual_t * dual,
          ent_t *          t,
          ent_t *          b,
          int              forced ) {
  if( FD_UNLIKELY( t->done | b->done ) ) return;

  long ts = t->sched_ns;
  long bs = b->sched_ns;
  int  bundle_landed_first = (b->bstate==BSTATE_LANDED) & ((!ts) | (bs<=ts));

  int verdict;
  if( bundle_landed_first ) {
    verdict = FD_PACK_DUAL_VERDICT_BUNDLE_WON;
  } else if( ts ) {
    /* If the bundle was scheduled first, its outcome decides */
    if( FD_UNLIKELY( (b->bstate==BSTATE_AWAIT) & (bs!=0L) & (bs<ts) & (!forced) ) ) return;
    verdict = FD_PACK_DUAL_VERDICT_TPU_WON;
  } else {
    /* The TPU copy may still be scheduled later */
    if( !forced ) return;
    verdict = FD_PACK_DUAL_VERDICT_NEITHER;
  }

  fd_pack_dual_pair_t pair[1];
  pair->verdict      = verdict;
  pair->tpu_offer    = b->txn_offer;
  pair->bundle_offer = b->bundle_offer;
  switch( verdict ) {
    case FD_PACK_DUAL_VERDICT_BUNDLE_WON: pair->slot = b->sched_slot; break;
    case FD_PACK_DUAL_VERDICT_TPU_WON:    pair->slot = t->sched_slot; break;
    default:                              pair->slot = bs ? b->sched_slot : ULONG_MAX; break;
  }
  pair->tpu_arrival_ns    = t->insert_ns;
  pair->tpu_sched_ns      = ts;
  pair->bundle_arrival_ns = b->insert_ns;
  pair->bundle_sched_ns   = bs;

  t->done = 1;
  b->done = 1;
  if( FD_LIKELY( dual->verdict_fn ) ) dual->verdict_fn( dual->verdict_ctx, pair );
}

static inline void
evaluate_ent( fd_pack_dual_t * dual,
              ent_t *          e,
              int              forced ) {
  if( !e->twin || e->done ) return;
  ent_t * o = dual->ent + (e->twin-1U);
  if( e->lane==FD_PACK_DUAL_LANE_TPU ) evaluate( dual, e, o, forced );
  else                                 evaluate( dual, o, e, forced );
}

static void
evict( fd_pack_dual_t * dual,
       ulong            idx,
       long             now ) {
  ent_t * e = dual->ent + idx;
  evaluate_ent( dual, e, 1 );
  if( e->twin ) dual->ent[ e->twin-1U ].twin = 0U;
  if( now - e->insert_ns < FD_PACK_DUAL_MIN_RETENTION_NS ) dual->evicted_young++;

  uint * link = dual->head + bucket( dual, fd_ulong_load_8( e->sig ) );
  while( *link!=(uint)idx+1U ) {
    if( FD_UNLIKELY( !*link ) ) FD_LOG_CRIT(( "dual lane entry missing from chain" ));
    link = &dual->ent[ *link-1U ].next;
  }
  *link = e->next;
  memset( e, 0, sizeof(ent_t) );
}

/* Allocates and links a new entry for sig in lane, pairing it with the
   most recent unpaired entry of the other lane with the same
   signature.  Returns the entry and sets *paired. */

static ent_t *
insert( fd_pack_dual_t * dual,
        uchar const *    sig,
        int              lane,
        long             now,
        int *            paired ) {
  ulong idx = dual->cursor;
  dual->cursor = (dual->cursor+1UL) & (dual->ent_max-1UL);
  if( FD_UNLIKELY( dual->ent[ idx ].used ) ) evict( dual, idx, now );

  ulong   b       = bucket( dual, fd_ulong_load_8( sig ) );
  ent_t * partner = NULL;
  for( uint i=dual->head[ b ]; i; i=dual->ent[ i-1U ].next ) {
    ent_t * c = dual->ent + (i-1U);
    if( (c->lane==lane) | (!!c->twin) | c->done || memcmp( c->sig, sig, 64UL ) ) continue;
    if( !partner || c->insert_ns>=partner->insert_ns ) partner = c;
  }

  ent_t * e = dual->ent + idx;
  e->used       = 1;
  e->lane       = lane;
  e->bstate     = BSTATE_PENDING;
  e->insert_ns  = now;
  e->sched_slot = ULONG_MAX;
  memcpy( e->sig, sig, 64UL );
  e->next = dual->head[ b ];
  dual->head[ b ] = (uint)idx+1U;

  *paired = !!partner;
  if( partner ) {
    e->twin       = (uint)(partner-dual->ent)+1U;
    partner->twin = (uint)idx+1U;
    dual->pair_cnt++;
  }
  return e;
}

int
fd_pack_dual_insert_tpu( fd_pack_dual_t * dual,
                         uchar const      sig[ static 64 ],
                         long             now ) {
  int paired;
  ent_t * e = insert( dual, sig, FD_PACK_DUAL_LANE_TPU, now, &paired );
  if( paired ) evaluate_ent( dual, e, 0 );
  return paired;
}

int
fd_pack_dual_insert_bundle( fd_pack_dual_t * dual,
                            uchar const      sig[ static 64 ],
                            ulong            txn_offer,
                            ulong            bundle_offer,
                            ulong            bundle_obs_id,
                            long             now ) {
  int paired;
  ent_t * e = insert( dual, sig, FD_PACK_DUAL_LANE_BUNDLE, now, &paired );
  e->txn_offer    = txn_offer;
  e->bundle_offer = bundle_offer;
  e->obs_id       = bundle_obs_id;
  if( paired ) evaluate_ent( dual, e, 0 );
  return paired;
}

void
fd_pack_dual_tpu_scheduled( fd_pack_dual_t * dual,
                            uchar const      sig[ static 64 ],
                            long             now,
                            ulong            slot ) {
  for( uint i=dual->head[ bucket( dual, fd_ulong_load_8( sig ) ) ]; i; ) {
    ent_t * e = dual->ent + (i-1U);
    i = e->next;
    if( (e->lane!=FD_PACK_DUAL_LANE_TPU) | (!!e->sched_ns) || memcmp( e->sig, sig, 64UL ) ) continue;
    e->sched_ns   = now;
    e->sched_slot = slot;
    evaluate_ent( dual, e, 0 );
  }
}

void
fd_pack_dual_bundle_scheduled( fd_pack_dual_t * dual,
                               ulong            sig8,
                               ulong            bundle_obs_id,
                               long             now,
                               ulong            slot ) {
  for( uint i=dual->head[ bucket( dual, sig8 ) ]; i; ) {
    ent_t * e = dual->ent + (i-1U);
    i = e->next;
    if( (e->lane!=FD_PACK_DUAL_LANE_BUNDLE) | (e->obs_id!=bundle_obs_id) | (!!e->sched_ns) | (fd_ulong_load_8( e->sig )!=sig8) ) continue;
    e->sched_ns   = now;
    e->sched_slot = slot;
    e->bstate     = BSTATE_AWAIT;
    evaluate_ent( dual, e, 0 );
  }
}

void
fd_pack_dual_bundle_done( fd_pack_dual_t * dual,
                          ulong            sig8,
                          ulong            bundle_obs_id,
                          int              landed ) {
  for( uint i=dual->head[ bucket( dual, sig8 ) ]; i; ) {
    ent_t * e = dual->ent + (i-1U);
    i = e->next;
    if( (e->lane!=FD_PACK_DUAL_LANE_BUNDLE) | (e->obs_id!=bundle_obs_id) | (fd_ulong_load_8( e->sig )!=sig8) ) continue;
    if( (e->bstate==BSTATE_LANDED) | (e->bstate==BSTATE_FAILED) ) continue;
    e->bstate = landed ? BSTATE_LANDED : BSTATE_FAILED;
    evaluate_ent( dual, e, 0 );
  }
}

ulong fd_pack_dual_evicted_young( fd_pack_dual_t const * dual ) { return dual->evicted_young; }
ulong fd_pack_dual_pair_cnt     ( fd_pack_dual_t const * dual ) { return dual->pair_cnt;      }
