#include "ag_pool.h"
#include "ag_slot_state.h"
#include "ag_finality_tracker.h"
#include "ag_parent_ready_tracker.h"

#define QUEUE_NAME pool_events
#define QUEUE_T    ag_pool_event_t
#include "../../util/tmpl/fd_queue_dynamic.c"

/* repair_events are notifications that a block has reached SafeToNotar
   (or stronger) status.  It does not necessarily trigger actual repair
   requests if we already have the block... (that is the responsibility
   of the repair tile to answer).  */

#define QUEUE_NAME repair_events
#define QUEUE_T    ag_block_id_t
#include "../../util/tmpl/fd_queue_dynamic.c"

/* Protocol bounds (< 20% byzantine stake) on what burst adds push onto
   queues drained to empty before the next add:

   - IMPLICITLY_FINALIZED / SKIPPED: once per slot of the window
   - SAFE_TO_NOTAR of waiting children: 3 hashes per child slot (stake
     arithmetic), and correct nodes notar a child only at its parent's
     slot+1 or a window start, for each of up to burst certified
     parents
   - PARENT_READY: once per window start (ready flag), plus one per add
     moving the window
   - per add: 4 of CERT_CREATED, SAFE_TO_NOTAR and SAFE_TO_SKIP
   - repair: 4 block ids per add (3 created certs, 1 missing block) */

#define POOL_EVENT_MAX(slot_max,burst) ( (slot_max)                                                                 \
                                       + 3UL*( ((slot_max)+AG_SLOTS_PER_WINDOW-1UL)/AG_SLOTS_PER_WINDOW + (burst) ) \
                                       +     ( ((slot_max)+AG_SLOTS_PER_WINDOW-1UL)/AG_SLOTS_PER_WINDOW + (burst) ) \
                                       + 4UL*(burst) )
#define REPAIR_EVENT_MAX(burst)        ( 4UL*(burst) )

struct slot_state_ele {
  ulong           slot;
  ulong           next;
  ag_slot_state_t slot_state;
};
typedef struct slot_state_ele slot_state_ele_t;

#define POOL_NAME slot_state_pool
#define POOL_T    slot_state_ele_t
#include "../../util/tmpl/fd_pool.c"

#define MAP_NAME               slot_state_map
#define MAP_ELE_T              slot_state_ele_t
#define MAP_KEY                slot
#define MAP_KEY_T              ulong
#define MAP_KEY_EQ(k0,k1)      ((*(k0))==(*(k1)))
#define MAP_KEY_HASH(key,seed) (fd_ulong_hash( (*(key)) ^ (seed) ))
#define MAP_NEXT               next
#include "../../util/tmpl/fd_map_chain.c"

struct s2n_waiting_parent_cert_ele {
  ag_block_id_t parent;
  ulong         next;
  ulong         prev;
  ag_block_id_t child;
};
typedef struct s2n_waiting_parent_cert_ele s2n_waiting_parent_cert_ele_t;

#define POOL_NAME s2n_waiting_parent_cert_pool
#define POOL_T    s2n_waiting_parent_cert_ele_t
#include "../../util/tmpl/fd_pool.c"

#define MAP_NAME                           s2n_waiting_parent_cert_map
#define MAP_ELE_T                          s2n_waiting_parent_cert_ele_t
#define MAP_KEY                            parent.slot
#define MAP_KEY_HASH(key,seed)             (fd_ulong_hash( (*(key)) ^ (seed) ))
#define MAP_NEXT                           next
#define MAP_MULTI                          1
#define MAP_OPTIMIZE_RANDOM_ACCESS_REMOVAL 1
#include "../../util/tmpl/fd_map_chain.c"

struct slot_states {
  slot_state_ele_t * pool;
  slot_state_map_t * map;
  ag_slot_states_t   shared;
};
typedef struct slot_states slot_states_t;

struct s2n_waiting_parent_cert {
  s2n_waiting_parent_cert_ele_t * pool;
  s2n_waiting_parent_cert_map_t * map;
};
typedef struct s2n_waiting_parent_cert s2n_waiting_parent_cert_t;

struct __attribute__((aligned(128UL))) ag_pool {
  ulong slot_max;

  slot_states_t *             slot_states;
  ag_parent_ready_tracker_t * parent_ready_tracker;
  ag_finality_tracker_t *     finality_tracker;
  s2n_waiting_parent_cert_t * s2n_waiting_parent_cert;

  ag_pool_event_t * pool_events;
  ag_block_id_t *   repair_events;

  struct {
    ag_parent_ready_t * parent_readys;
    ag_block_id_t *     implicitly_finalized;
    ulong *             implicitly_skipped;
  } scratch;
};

ulong
ag_pool_align( void ) {
  return alignof(ag_pool_t);
}

ulong
ag_pool_footprint( ulong slot_max,
                   ulong burst ) {
  if( FD_UNLIKELY( slot_max<AG_SLOTS_PER_WINDOW+AG_REWARD_SLOT_DELTA || slot_max>UINT_MAX/(AG_VAT_MAX*AG_SLOT_VOTE_SIG_MAX) ) ) return 0UL;

  ulong slot_chain_cnt  = slot_state_map_chain_cnt_est( slot_max );
  ulong sig_max         = slot_max*AG_VAT_MAX*AG_SLOT_VOTE_SIG_MAX;
  ulong notar_max       = slot_max*AG_VAT_MAX;
  ulong notar_chain_cnt = ag_vote_stake_map_chain_cnt_est( notar_max );
  ulong nf_max          = slot_max*AG_NOTAR_FALLBACK_HASH_MAX;
  ulong nf_chain_cnt    = ag_vote_stake_map_chain_cnt_est( nf_max );
  ulong s2n_max         = slot_max*AG_EQVOC_BLOCK_HASH_MAX;
  ulong s2n_chain_cnt   = s2n_waiting_parent_cert_map_chain_cnt_est( s2n_max );
  ulong ready_max       = slot_max + AG_SLOTS_PER_WINDOW + 1UL; /* [root-AG_REWARD_SLOT_DELTA-AG_SLOTS_PER_WINDOW, root+slot_max-AG_REWARD_SLOT_DELTA] */
  ulong event_max       = POOL_EVENT_MAX( slot_max, burst );
  ulong repair_max      = REPAIR_EVENT_MAX( burst );

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
      alignof(ag_pool_t),                   sizeof(ag_pool_t)                                       ),
      alignof(slot_states_t),               sizeof(slot_states_t)                                   ),
      slot_state_pool_align(),              slot_state_pool_footprint( slot_max )                   ),
      slot_state_map_align(),               slot_state_map_footprint ( slot_chain_cnt )             ),
      fd_bls_sig_pool_align(),              fd_bls_sig_pool_footprint( sig_max )                    ),
      ag_vote_stake_pool_align(),           ag_vote_stake_pool_footprint( notar_max )               ),
      ag_vote_stake_map_align(),            ag_vote_stake_map_footprint ( notar_chain_cnt )         ),
      ag_vote_stake_pool_align(),           ag_vote_stake_pool_footprint( nf_max )                  ),
      ag_vote_stake_map_align(),            ag_vote_stake_map_footprint ( nf_chain_cnt )            ),
      ag_parent_ready_tracker_align(),      ag_parent_ready_tracker_footprint( ready_max )          ),
      ag_finality_tracker_align(),          ag_finality_tracker_footprint( slot_max )               ),
      alignof(s2n_waiting_parent_cert_t),   sizeof(s2n_waiting_parent_cert_t)                       ),
      s2n_waiting_parent_cert_pool_align(), s2n_waiting_parent_cert_pool_footprint( s2n_max )       ),
      s2n_waiting_parent_cert_map_align(),  s2n_waiting_parent_cert_map_footprint ( s2n_chain_cnt ) ),
      pool_events_align(),                  pool_events_footprint( event_max )                      ),
      repair_events_align(),                repair_events_footprint( repair_max )                   ),
      alignof(ag_parent_ready_t),           sizeof(ag_parent_ready_t) * slot_max                    ),
      alignof(ag_block_id_t),               sizeof(ag_block_id_t)     * slot_max                    ),
      alignof(ulong),                       sizeof(ulong)             * slot_max                    ),
    ag_pool_align() );
}

void *
ag_pool_new( void * mem,
             ulong  slot_max,
             ulong  burst,
             ulong  seed ) {
  if( FD_UNLIKELY( !mem ) ) {
    FD_LOG_WARNING(( "NULL mem" ));
    return NULL;
  }
  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)mem, ag_pool_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned mem" ));
    return NULL;
  }
  ulong footprint = ag_pool_footprint( slot_max, burst );
  if( FD_UNLIKELY( !footprint ) ) {
    FD_LOG_WARNING(( "bad slot_max (%lu)", slot_max ));
    return NULL;
  }
  fd_memset( mem, 0, footprint );

  ulong s2n_max         = slot_max*AG_EQVOC_BLOCK_HASH_MAX;
  ulong slot_chain_cnt  = slot_state_map_chain_cnt_est( slot_max );
  ulong sig_max         = slot_max*AG_VAT_MAX*AG_SLOT_VOTE_SIG_MAX;
  ulong notar_max       = slot_max*AG_VAT_MAX;
  ulong notar_chain_cnt = ag_vote_stake_map_chain_cnt_est( notar_max );
  ulong nf_max          = slot_max*AG_NOTAR_FALLBACK_HASH_MAX;
  ulong nf_chain_cnt    = ag_vote_stake_map_chain_cnt_est( nf_max );
  ulong s2n_chain_cnt   = s2n_waiting_parent_cert_map_chain_cnt_est( s2n_max );
  ulong ready_max       = slot_max + AG_SLOTS_PER_WINDOW + 1UL;
  ulong event_max       = POOL_EVENT_MAX( slot_max, burst );
  ulong repair_max      = REPAIR_EVENT_MAX( burst );


  FD_SCRATCH_ALLOC_INIT( l, mem );
  ag_pool_t * pool                         = FD_SCRATCH_ALLOC_APPEND( l, alignof(ag_pool_t),                   sizeof(ag_pool_t)                                       );
  void *      slot_states                  = FD_SCRATCH_ALLOC_APPEND( l, alignof(slot_states_t),               sizeof(slot_states_t)                                   );
  void *      slot_state_pool              = FD_SCRATCH_ALLOC_APPEND( l, slot_state_pool_align(),              slot_state_pool_footprint( slot_max )                   );
  void *      slot_state_map               = FD_SCRATCH_ALLOC_APPEND( l, slot_state_map_align(),               slot_state_map_footprint ( slot_chain_cnt )             );
  void *      bls_sig_pool                 = FD_SCRATCH_ALLOC_APPEND( l, fd_bls_sig_pool_align(),              fd_bls_sig_pool_footprint( sig_max )                    );
  void *      notar_hash_stake_pool        = FD_SCRATCH_ALLOC_APPEND( l, ag_vote_stake_pool_align(),           ag_vote_stake_pool_footprint( notar_max )               );
  void *      notar_hash_stake_map         = FD_SCRATCH_ALLOC_APPEND( l, ag_vote_stake_map_align(),            ag_vote_stake_map_footprint ( notar_chain_cnt )         );
  void *      nf_hash_stake_pool           = FD_SCRATCH_ALLOC_APPEND( l, ag_vote_stake_pool_align(),           ag_vote_stake_pool_footprint( nf_max )                  );
  void *      nf_hash_stake_map            = FD_SCRATCH_ALLOC_APPEND( l, ag_vote_stake_map_align(),            ag_vote_stake_map_footprint ( nf_chain_cnt )            );
  void *      parent_ready_tracker         = FD_SCRATCH_ALLOC_APPEND( l, ag_parent_ready_tracker_align(),      ag_parent_ready_tracker_footprint( ready_max )          );
  void *      finality_tracker             = FD_SCRATCH_ALLOC_APPEND( l, ag_finality_tracker_align(),          ag_finality_tracker_footprint( slot_max )               );
  void *      s2n_waiting_parent_cert      = FD_SCRATCH_ALLOC_APPEND( l, alignof(s2n_waiting_parent_cert_t),   sizeof(s2n_waiting_parent_cert_t)                       );
  void *      s2n_waiting_parent_cert_pool = FD_SCRATCH_ALLOC_APPEND( l, s2n_waiting_parent_cert_pool_align(), s2n_waiting_parent_cert_pool_footprint( s2n_max )       );
  void *      s2n_waiting_parent_cert_map  = FD_SCRATCH_ALLOC_APPEND( l, s2n_waiting_parent_cert_map_align(),  s2n_waiting_parent_cert_map_footprint ( s2n_chain_cnt ) );
  void *      pool_events                  = FD_SCRATCH_ALLOC_APPEND( l, pool_events_align(),                  pool_events_footprint( event_max )                      );
  void *      repair_events                = FD_SCRATCH_ALLOC_APPEND( l, repair_events_align(),                repair_events_footprint( repair_max )                   );
  void *      parent_ready_scratch         = FD_SCRATCH_ALLOC_APPEND( l, alignof(ag_parent_ready_t),           sizeof(ag_parent_ready_t) * slot_max                    );
  void *      implicitly_finalized_scratch = FD_SCRATCH_ALLOC_APPEND( l, alignof(ag_block_id_t),               sizeof(ag_block_id_t)     * slot_max                    );
  void *      implicitly_skipped_scratch   = FD_SCRATCH_ALLOC_APPEND( l, alignof(ulong),                       sizeof(ulong)             * slot_max                    );
  FD_TEST( FD_SCRATCH_ALLOC_FINI( l, ag_pool_align() ) == (ulong)mem + footprint );

  pool->slot_states                                        = (slot_states_t *)slot_states;
  pool->slot_states->pool                                  = slot_state_pool_join   ( slot_state_pool_new   ( slot_state_pool,       slot_max              ) );
  pool->slot_states->map                                   = slot_state_map_join    ( slot_state_map_new    ( slot_state_map,        slot_chain_cnt, seed  ) );
  pool->slot_states->shared.bls_sig_pool                   = fd_bls_sig_pool_join   ( fd_bls_sig_pool_new   ( bls_sig_pool,          sig_max               ) );
  pool->slot_states->shared.notar_hash_stake_pool          = ag_vote_stake_pool_join( ag_vote_stake_pool_new( notar_hash_stake_pool, notar_max             ) );
  pool->slot_states->shared.notar_hash_stake_map           = ag_vote_stake_map_join ( ag_vote_stake_map_new ( notar_hash_stake_map,  notar_chain_cnt, seed ) );
  pool->slot_states->shared.notar_fallback_hash_stake_pool = ag_vote_stake_pool_join( ag_vote_stake_pool_new( nf_hash_stake_pool,    nf_max                ) );
  pool->slot_states->shared.notar_fallback_hash_stake_map  = ag_vote_stake_map_join ( ag_vote_stake_map_new ( nf_hash_stake_map,     nf_chain_cnt, seed    ) );
  pool->slot_states->shared.prev_epoch_info                = NULL;
  pool->slot_states->shared.prev_epoch_rank                = USHORT_MAX;
  pool->slot_states->shared.prev_epoch_slot                = ULONG_MAX;
  pool->slot_states->shared.curr_epoch_info                = NULL;
  pool->slot_states->shared.curr_epoch_rank                = USHORT_MAX;
  pool->slot_states->shared.curr_epoch_slot                = ULONG_MAX;
  pool->slot_states->shared.next_epoch_info                = NULL;
  pool->slot_states->shared.next_epoch_rank                = USHORT_MAX;
  pool->slot_states->shared.next_epoch_slot                = ULONG_MAX;
  pool->slot_states->shared.bls_verify_cnt                 = 0UL;
  pool->slot_states->shared.bls_verify_start               = 0L;

  pool->parent_ready_tracker = ag_parent_ready_tracker_join( ag_parent_ready_tracker_new( parent_ready_tracker, ready_max, seed ) );

  pool->finality_tracker = ag_finality_tracker_join( ag_finality_tracker_new( finality_tracker, slot_max, seed ) );

  pool->s2n_waiting_parent_cert       = (s2n_waiting_parent_cert_t *)s2n_waiting_parent_cert;
  pool->s2n_waiting_parent_cert->pool = s2n_waiting_parent_cert_pool_join( s2n_waiting_parent_cert_pool_new( s2n_waiting_parent_cert_pool, s2n_max                            ) );
  pool->s2n_waiting_parent_cert->map  = s2n_waiting_parent_cert_map_join ( s2n_waiting_parent_cert_map_new ( s2n_waiting_parent_cert_map,  s2n_chain_cnt, seed ) );

  pool->pool_events   = pool_events_join  ( pool_events_new  ( pool_events,   event_max  ) );
  pool->repair_events = repair_events_join( repair_events_new( repair_events, repair_max ) );

  pool->slot_max = slot_max;


  pool->scratch.parent_readys        = (ag_parent_ready_t *)parent_ready_scratch;
  pool->scratch.implicitly_finalized = (ag_block_id_t *)implicitly_finalized_scratch;
  pool->scratch.implicitly_skipped   = (ulong *)implicitly_skipped_scratch;


  return mem;
}

ag_pool_t *
ag_pool_join( void * mem ) {
  ag_pool_t * pool = (ag_pool_t *)mem;
  if( FD_UNLIKELY( !pool ) ) {
    FD_LOG_WARNING(( "NULL mem" ));
    return NULL;
  }
  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)pool, ag_pool_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned mem" ));
    return NULL;
  }
  return pool;
}

void *
ag_pool_leave( ag_pool_t const * pool ) {
  if( FD_UNLIKELY( !pool ) ) {
    FD_LOG_WARNING(( "NULL pool" ));
    return NULL;
  }
  return (void *)pool;
}

void *
ag_pool_delete( void * mem ) {
  if( FD_UNLIKELY( !mem ) ) {
    FD_LOG_WARNING(( "NULL mem" ));
    return NULL;
  }
  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)mem, ag_pool_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned mem" ));
    return NULL;
  }
  return mem;
}

void
ag_pool_init( ag_pool_t *           self,
              ag_block_id_t const * root ) {
  ag_finality_tracker_init( self->finality_tracker, root->slot );
  self->parent_ready_tracker->root = fd_ulong_sat_sub( root->slot, AG_REWARD_SLOT_DELTA+AG_SLOTS_PER_WINDOW );

  ulong ready_cnt = ag_parent_ready_tracker_mark_notar_fallback( self->parent_ready_tracker, root, self->scratch.parent_readys );
  for( ulong i=0UL; i<ready_cnt; i++ ) {
    pool_events_push( self->pool_events, (ag_pool_event_t){ .kind = AG_POOL_EVENT_PARENT_READY, .parent_ready = self->scratch.parent_readys[i] } );
  }
}

void
ag_pool_fini( ag_pool_t * self ) {
  ag_finality_tracker_fini( self->finality_tracker );
  self->parent_ready_tracker->root = ULONG_MAX;
}

FD_FN_CONST char const *
ag_pool_strerror( int err ) {
  switch( err ) {
  case AG_POOL_SUCCESS:                return "success";
  case AG_POOL_ERR_SLOT_OUT_OF_BOUNDS: return "slot is either too old or too far in the future";
  case AG_POOL_ERR_DUPLICATE:          return "duplicate vote or cert";
  case AG_POOL_ERR_SLASHABLE:          return "vote constitutes a slashable offence";
  case AG_POOL_ERR_CERT_VERIFY:        return "cert failed the signature or threshold check";
  default:                             return "unknown";
  }
}

FD_FN_PURE long
ag_pool_vote_verify_start( ag_pool_t const * self ) {
  return self->slot_states->shared.bls_verify_start;
}

FD_FN_PURE ag_pool_metrics_t
ag_pool_metrics( ag_pool_t const * self ) {
  return (ag_pool_metrics_t){
    .slot_state_pool_used = slot_state_pool_used( self->slot_states->pool ),
    .slot_state_pool_free = slot_state_pool_free( self->slot_states->pool ),
    .finalized_slot       = ag_pool_finalized_slot( self ),
    .pool_events_cnt      = pool_events_cnt( self->pool_events ),
    .bls_verify_cnt       = self->slot_states->shared.bls_verify_cnt
  };
}

static ag_slot_state_t *
slot_state( ag_pool_t * self,
            ulong       slot ) {
  slot_state_ele_t * ele = slot_state_map_ele_query( self->slot_states->map, &slot, NULL, self->slot_states->pool );
  if( FD_LIKELY( ele ) ) return &ele->slot_state;

  ag_slot_states_t *      states = &self->slot_states->shared;
  ag_epoch_info_t const * info   = fd_ptr_if  ( slot>=states->next_epoch_slot, states->next_epoch_info, fd_ptr_if  ( slot>=states->curr_epoch_slot, states->curr_epoch_info, states->prev_epoch_info ) );
  ulong                   rank   = fd_ulong_if( slot>=states->next_epoch_slot, states->next_epoch_rank, fd_ulong_if( slot>=states->curr_epoch_slot, states->curr_epoch_rank, states->prev_epoch_rank ) );

  FD_TEST( info );
  FD_TEST( slot_state_pool_free( self->slot_states->pool ) );

  ele       = slot_state_pool_ele_acquire( self->slot_states->pool );
  ele->slot = slot;
  ag_slot_state_null( &ele->slot_state, states );
  ele->slot_state.slot     = slot;
  ele->slot_state.own_rank = rank;
  slot_state_map_ele_insert( self->slot_states->map, ele, self->slot_states->pool );
  return &ele->slot_state;
}

static inline ag_finalization_event_t
finalization_event_default( ag_pool_t * self ) {
  return ag_finalization_event_default( self->scratch.implicitly_finalized, self->scratch.implicitly_skipped );
}

static void
handle_finalization( ag_pool_t *                     self,
                     ag_finalization_event_t const * event ) {
  FD_TEST( pool_events_avail( self->pool_events )>=event->implicitly_finalized_cnt+event->implicitly_skipped_cnt );
  for( ulong i=0UL; i<event->implicitly_finalized_cnt; i++ ) pool_events_push( self->pool_events, (ag_pool_event_t){ .kind = AG_POOL_EVENT_IMPLICITLY_FINALIZED, .implicitly_finalized = event->implicitly_finalized[i] } );
  for( ulong i=0UL; i<event->implicitly_skipped_cnt;   i++ ) pool_events_push( self->pool_events, (ag_pool_event_t){ .kind = AG_POOL_EVENT_IMPLICITLY_SKIPPED,   .implicitly_skipped   = event->implicitly_skipped  [i] } );
  ulong first_unpruned_slot = ag_finality_tracker_first_unpruned_slot( self->finality_tracker );
  ulong retained_slot       = fd_ulong_sat_sub( first_unpruned_slot, AG_REWARD_SLOT_DELTA );
  for( ulong slot = fd_ulong_sat_sub( self->parent_ready_tracker->root, AG_REWARD_SLOT_DELTA ); slot<retained_slot; slot++ ) {
    slot_state_ele_t * ele = slot_state_map_ele_remove( self->slot_states->map, &slot, NULL, self->slot_states->pool );
    if( FD_LIKELY( ele ) ) {
      ag_slot_state_null( &ele->slot_state, &self->slot_states->shared );
      slot_state_pool_ele_release( self->slot_states->pool, ele );
    }
    s2n_waiting_parent_cert_ele_t * waiter;
    while( (waiter = s2n_waiting_parent_cert_map_ele_remove( self->s2n_waiting_parent_cert->map, &slot, NULL, self->s2n_waiting_parent_cert->pool )) ) s2n_waiting_parent_cert_pool_ele_release( self->s2n_waiting_parent_cert->pool, waiter );
  }
  ag_parent_ready_tracker_prune( self->parent_ready_tracker, fd_ulong_sat_sub( first_unpruned_slot, AG_REWARD_SLOT_DELTA+AG_SLOTS_PER_WINDOW ) );
}

static void
add_verified_cert( ag_pool_t *       self,
                   ag_cert_t const * cert,
                   fd_bls_set_t *    bad ) {
  ulong slot = ag_cert_slot( cert );

  ag_slot_state_add_cert( slot_state( self, slot ), cert );

  switch( cert->kind ) {
  case AG_CERT_KIND_FINAL: {
    ag_finalization_event_t finalization_event = finalization_event_default( self );
    ag_finality_tracker_mark_finalized( self->finality_tracker, slot, &finalization_event );
    handle_finalization( self, &finalization_event );
    break;
  }

  case AG_CERT_KIND_FAST_FINAL:
  case AG_CERT_KIND_NOTAR:
  case AG_CERT_KIND_NOTAR_FALLBACK: {
    uchar const * block_hash = ag_cert_block_hash( cert );
    ag_block_id_t block_id   = ag_block_id( slot, block_hash );
    if( FD_UNLIKELY( cert->kind==AG_CERT_KIND_FAST_FINAL ) ) {
      ag_finalization_event_t finalization_event = finalization_event_default( self );
      ag_finality_tracker_mark_fast_finalized( self->finality_tracker, &block_id, &finalization_event );
      handle_finalization( self, &finalization_event );
    }
    if( FD_LIKELY( cert->kind==AG_CERT_KIND_NOTAR ) ) {
      ag_finalization_event_t finalization_event = finalization_event_default( self );
      ag_finality_tracker_mark_notarized( self->finality_tracker, &block_id, &finalization_event );
      handle_finalization( self, &finalization_event );
    }

    ag_slot_states_t *              states = &self->slot_states->shared;
    s2n_waiting_parent_cert_ele_t * next;
    for( s2n_waiting_parent_cert_ele_t * child = s2n_waiting_parent_cert_map_ele_query( self->s2n_waiting_parent_cert->map, &slot, NULL, self->s2n_waiting_parent_cert->pool );
                                         child;
                                         child = next ) {
      next = (s2n_waiting_parent_cert_ele_t *)s2n_waiting_parent_cert_map_ele_next_const( child, NULL, self->s2n_waiting_parent_cert->pool );
      if( FD_LIKELY( !ag_block_id_eq( &child->parent, &block_id ) ) ) continue;
      ag_block_id_t child_id = child->child; /* copy before the release below */
      s2n_waiting_parent_cert_map_ele_remove_fast( self->s2n_waiting_parent_cert->map, child, self->s2n_waiting_parent_cert->pool );
      s2n_waiting_parent_cert_pool_ele_release( self->s2n_waiting_parent_cert->pool, child );

      ag_slot_state_t * child_state = slot_state( self, child_id.slot );
      fd_bls_set_t      bad_child[ fd_bls_set_word_cnt ];
      int output = ag_slot_state_notify_parent_certified( child_state, states, child_id.hash, bad_child );
      if( FD_LIKELY( fd_ptr_if( child_id.slot>=states->next_epoch_slot, states->next_epoch_info, fd_ptr_if( child_id.slot>=states->curr_epoch_slot, states->curr_epoch_info, states->prev_epoch_info ) )==fd_ptr_if( slot>=states->next_epoch_slot, states->next_epoch_info, fd_ptr_if( slot>=states->curr_epoch_slot, states->curr_epoch_info, states->prev_epoch_info ) ) ) ) fd_bls_set_union( bad, bad, bad_child );
      switch( output ) {
      case -1: repair_events_push( self->repair_events, child_id ); break;
      case  0: break;
      case  1: pool_events_push( self->pool_events, (ag_pool_event_t){ .kind = AG_POOL_EVENT_SAFE_TO_NOTAR, .safe_to_notar = child_id } ); break;
      }
    }

    ulong ready_cnt = ag_parent_ready_tracker_mark_notar_fallback( self->parent_ready_tracker, &block_id, self->scratch.parent_readys );
    for( ulong i=0UL; i<ready_cnt; i++ ) {
      pool_events_push( self->pool_events, (ag_pool_event_t){ .kind = AG_POOL_EVENT_PARENT_READY, .parent_ready = self->scratch.parent_readys[i] } );
    }

    repair_events_push( self->repair_events, block_id );
    break;
  }

  case AG_CERT_KIND_SKIP: {
    ulong ready_cnt = ag_parent_ready_tracker_mark_skipped( self->parent_ready_tracker, slot, self->scratch.parent_readys );
    for( ulong i=0UL; i<ready_cnt; i++ ) {
      pool_events_push( self->pool_events, (ag_pool_event_t){ .kind = AG_POOL_EVENT_PARENT_READY, .parent_ready = self->scratch.parent_readys[i] } );
    }
    break;
  }

  default:
    FD_LOG_ERR(( "invalid cert kind %u", cert->kind ));
  }

  ag_pool_event_t event = { .kind = AG_POOL_EVENT_CERT_CREATED, .cert_created = *cert };
  pool_events_push( self->pool_events, event );
}

void
ag_pool_advance_epoch( ag_pool_t *             self,
                       ag_epoch_info_t const * epoch_info,
                       ulong                   epoch_rank,
                       ulong                   epoch_slot ) {
  ag_slot_states_t * states = &self->slot_states->shared;
  if( FD_UNLIKELY( !states->curr_epoch_info ) ) {
    states->curr_epoch_info = epoch_info;
    states->curr_epoch_rank = epoch_rank;
    states->curr_epoch_slot = epoch_slot;
  } else if( FD_UNLIKELY( !states->next_epoch_info ) ) {
    states->next_epoch_info = epoch_info;
    states->next_epoch_rank = epoch_rank;
    states->next_epoch_slot = epoch_slot;
  } else {
    states->prev_epoch_info = states->curr_epoch_info;
    states->prev_epoch_slot = states->curr_epoch_slot;
    states->prev_epoch_rank = states->curr_epoch_rank;
    states->curr_epoch_info = states->next_epoch_info;
    states->curr_epoch_slot = states->next_epoch_slot;
    states->curr_epoch_rank = states->next_epoch_rank;
    states->next_epoch_info = epoch_info;
    states->next_epoch_rank = epoch_rank;
    states->next_epoch_slot = epoch_slot;
  }
}

void
ag_pool_set_rank( ag_pool_t * self,
                  ulong       epoch_slot,
                  ulong       epoch_rank ) {
  ag_slot_states_t * states = &self->slot_states->shared;
  if     ( epoch_slot==states->prev_epoch_slot ) states->prev_epoch_rank = epoch_rank;
  else if( epoch_slot==states->curr_epoch_slot ) states->curr_epoch_rank = epoch_rank;
  else if( epoch_slot==states->next_epoch_slot ) states->next_epoch_rank = epoch_rank;
  else FD_LOG_CRIT(( "no epoch starts at slot %lu", epoch_slot ));

  slot_state_map_t * map  = self->slot_states->map;
  slot_state_ele_t * pool = self->slot_states->pool;
  for( slot_state_map_iter_t iter = slot_state_map_iter_init( map, pool );
                                   !slot_state_map_iter_done( iter, map, pool );
                             iter = slot_state_map_iter_next( iter, map, pool ) ) {
    ag_slot_state_t * slot_state = &slot_state_map_iter_ele( iter, map, pool )->slot_state;
    ulong             slot       = slot_state->slot;
    ulong             rank       = fd_ulong_if( slot>=states->next_epoch_slot, states->next_epoch_rank, fd_ulong_if( slot>=states->curr_epoch_slot, states->curr_epoch_rank, states->prev_epoch_rank ) );
    if( FD_UNLIKELY( slot_state->own_rank!=rank ) ) ag_slot_state_set_own_rank( slot_state, rank );
  }
}

int
ag_pool_add_cert( ag_pool_t *       self,
                  ag_cert_t const * cert,
                  int               verified,
                  fd_bls_set_t *    bad ) {
  ulong slot = ag_cert_slot( cert );
  fd_bls_set_null( bad );

  ulong slot_far_in_future = ag_finality_tracker_first_unpruned_slot( self->finality_tracker ) + self->slot_max - AG_REWARD_SLOT_DELTA;
  if( FD_UNLIKELY( slot<ag_finality_tracker_first_unpruned_slot( self->finality_tracker ) || slot>=slot_far_in_future ) ) return AG_POOL_ERR_SLOT_OUT_OF_BOUNDS;

  ag_slot_states_t const * states     = &self->slot_states->shared;
  ag_epoch_info_t const *  epoch_info = fd_ptr_if( slot>=states->next_epoch_slot, states->next_epoch_info, fd_ptr_if( slot>=states->curr_epoch_slot, states->curr_epoch_info, states->prev_epoch_info ) );
  if( FD_UNLIKELY( !epoch_info ) ) return AG_POOL_ERR_SLOT_OUT_OF_BOUNDS;

  ag_slot_state_t * state = slot_state( self, slot );
  int duplicate = 0;
  switch( cert->kind ) {
  case AG_CERT_KIND_FINAL:          duplicate = state->certs.finalize.slot!=ULONG_MAX;                                break;
  case AG_CERT_KIND_FAST_FINAL:     duplicate = state->certs.fast_finalize.slot!=ULONG_MAX;                           break;
  case AG_CERT_KIND_NOTAR:          duplicate = state->certs.notar.slot!=ULONG_MAX;                                   break;
  case AG_CERT_KIND_NOTAR_FALLBACK: duplicate = ag_slot_state_is_notar_fallback( state, ag_cert_block_hash( cert ) ); break;
  case AG_CERT_KIND_SKIP:           duplicate = state->certs.skip.slot!=ULONG_MAX;                                    break;
  default:                          FD_LOG_CRIT(( "unreachable" ));
  }
  if( FD_UNLIKELY( duplicate ) ) return AG_POOL_ERR_DUPLICATE;

  int err = AG_CERT_VERIFY_SUCCESS;
  if( FD_LIKELY( !verified ) ) err = ag_cert_verify( cert, epoch_info );
  self->slot_states->shared.bls_verify_cnt += (ulong)( !verified && err!=AG_CERT_VERIFY_ERR_THRESHOLD );
  if( FD_UNLIKELY( err ) ) return AG_POOL_ERR_CERT_VERIFY;

  switch( cert->kind ) { /* a skip cert excludes finalization certs, Lemmas 23 and 28 */
  case AG_CERT_KIND_FINAL:
  case AG_CERT_KIND_FAST_FINAL:     FD_CHECK_CRIT( state->certs.skip.slot==ULONG_MAX, "consensus safety violation" );                                                   break;
  case AG_CERT_KIND_NOTAR:
  case AG_CERT_KIND_NOTAR_FALLBACK:                                                                                                                                     break;
  case AG_CERT_KIND_SKIP:           FD_CHECK_CRIT( state->certs.finalize.slot==ULONG_MAX && state->certs.fast_finalize.slot==ULONG_MAX, "consensus safety violation" ); break;
  default:                          FD_LOG_CRIT(( "unreachable" ));
  }

  add_verified_cert( self, cert, bad );
  return AG_POOL_SUCCESS;
}

int
ag_pool_add_vote( ag_pool_t *       self,
                  ag_vote_t const * vote,
                  fd_bls_set_t *    bad,
                  uchar *           quorum_reached ) {
  ulong slot = ag_vote_slot( vote );
  fd_bls_set_null( bad );
  *quorum_reached = 0;
  self->slot_states->shared.bls_verify_start = 0L;

  ulong first_unpruned_slot = ag_finality_tracker_first_unpruned_slot( self->finality_tracker );
  ulong retained_slot       = fd_ulong_sat_sub( first_unpruned_slot, AG_REWARD_SLOT_DELTA );
  ulong slot_far_in_future  = first_unpruned_slot + self->slot_max - AG_REWARD_SLOT_DELTA;
  if( FD_UNLIKELY( slot<retained_slot || slot>=slot_far_in_future ) ) {
    return AG_POOL_ERR_SLOT_OUT_OF_BOUNDS;
  }
  ag_slot_states_t *      states     = &self->slot_states->shared;
  ag_epoch_info_t const * epoch_info = fd_ptr_if( slot>=states->next_epoch_slot, states->next_epoch_info, fd_ptr_if( slot>=states->curr_epoch_slot, states->curr_epoch_info, states->prev_epoch_info ) );
  if( FD_UNLIKELY( !epoch_info ) ) {
    return AG_POOL_ERR_SLOT_OUT_OF_BOUNDS;
  }

  ulong             voter       = ag_vote_rank( vote );
  ag_slot_state_t * slot_state_ = slot_state( self, slot );
  ulong             voter_stake = ag_epoch_info_validator( epoch_info, voter )->stake;

  if       ( FD_UNLIKELY( ag_slot_state_check_slashable_offence( slot_state_, states, vote )!=AG_SLASHABLE_NONE ) ) {
    return AG_POOL_ERR_SLASHABLE;
  } else if( FD_UNLIKELY( ag_slot_state_should_ignore_vote( slot_state_, states, vote ) ) ) {
    return AG_POOL_ERR_DUPLICATE;
  }
  if( FD_UNLIKELY( !blst_p2_affine_in_g2( ag_vote_sig( vote ) ) ) ) {
    fd_bls_set_insert( bad, voter );
    return AG_POOL_SUCCESS;
  }

  ag_cert_t     cert_events  [ AG_SLOT_STATE_OUT_CERT_MAX   ]; ulong cert_event_cnt;
  ag_block_id_t safe_to_notar[ AG_SLOT_STATE_OUT_EVENT_MAX  ]; ulong safe_to_notar_cnt;
  ulong         safe_to_skip [ AG_SLOT_STATE_OUT_EVENT_MAX  ]; ulong safe_to_skip_cnt;
  ag_block_id_t repair_events[ AG_SLOT_STATE_OUT_REPAIR_MAX ]; ulong repair_event_cnt;
  ag_slot_state_add_vote( slot_state_, states, vote, voter_stake, cert_events, &cert_event_cnt, safe_to_notar, &safe_to_notar_cnt, safe_to_skip, &safe_to_skip_cnt, repair_events, &repair_event_cnt, bad );

  for( ulong i=0UL; i<cert_event_cnt;    i++ ) { add_verified_cert( self, &cert_events[i], bad ); *quorum_reached = fd_uchar_set_bit( *quorum_reached, (int)cert_events[i].kind ); }
  for( ulong i=0UL; i<safe_to_notar_cnt; i++ ) { pool_events_push  ( self->pool_events,   (ag_pool_event_t){ .kind = AG_POOL_EVENT_SAFE_TO_NOTAR, .safe_to_notar = safe_to_notar[i] } ); *quorum_reached = fd_uchar_set_bit( *quorum_reached, AG_POOL_QUORUM_REACHED_SAFE_TO_NOTAR ); }
  for( ulong i=0UL; i<safe_to_skip_cnt;  i++ ) { pool_events_push  ( self->pool_events,   (ag_pool_event_t){ .kind = AG_POOL_EVENT_SAFE_TO_SKIP,  .safe_to_skip  = safe_to_skip [i] } ); *quorum_reached = fd_uchar_set_bit( *quorum_reached, AG_POOL_QUORUM_REACHED_SAFE_TO_SKIP  ); }
  for( ulong i=0UL; i<repair_event_cnt;  i++ ) { repair_events_push( self->repair_events, repair_events[i] ); }
  return AG_POOL_SUCCESS;
}

ag_slot_state_t const *
ag_pool_slot_state( ag_pool_t const * self,
                    ulong             slot ) {
  slot_state_ele_t const * ele = slot_state_map_ele_query_const( self->slot_states->map, &slot, NULL, self->slot_states->pool );
  return ele ? &ele->slot_state : NULL;
}

ag_slot_states_t const *
ag_pool_slot_states( ag_pool_t const * self ) {
  return &self->slot_states->shared;
}

int
ag_pool_add_block( ag_pool_t *           self,
                   ag_block_id_t const * block_id,
                   ag_block_id_t const * parent_id,
                   fd_bls_set_t *        bad ) {
  fd_bls_set_null( bad );

  ulong         slot        = block_id->slot;
  uchar const * block_hash  = block_id->hash;
  ulong         parent_slot = parent_id->slot;
  uchar const * parent_hash = parent_id->hash;

  ulong slot_far_in_future = ag_finality_tracker_first_unpruned_slot( self->finality_tracker ) + self->slot_max - AG_REWARD_SLOT_DELTA;
  if( FD_UNLIKELY( slot<ag_finality_tracker_first_unpruned_slot( self->finality_tracker ) || slot>=slot_far_in_future ) ) return AG_POOL_ERR_SLOT_OUT_OF_BOUNDS;
  ag_slot_states_t * states = &self->slot_states->shared;
  if( FD_UNLIKELY( !fd_ptr_if( slot>=states->next_epoch_slot, states->next_epoch_info, fd_ptr_if( slot>=states->curr_epoch_slot, states->curr_epoch_info, states->prev_epoch_info ) ) ) ) return AG_POOL_ERR_SLOT_OUT_OF_BOUNDS;

  ag_finalization_event_t finalization_event = finalization_event_default( self );
  ag_finality_tracker_add_parent( self->finality_tracker, block_id, parent_id, &finalization_event );
  handle_finalization( self, &finalization_event );
  if( FD_UNLIKELY( slot<fd_ulong_sat_sub( ag_finality_tracker_first_unpruned_slot( self->finality_tracker ), AG_REWARD_SLOT_DELTA ) ) ) return AG_POOL_SUCCESS; /* pruned by the parent link */

  ag_slot_state_notify_parent_known( slot_state( self, slot ), block_hash );
  slot_state_ele_t * parent_state_ = slot_state_map_ele_query( self->slot_states->map, &parent_slot, NULL, self->slot_states->pool );
  ag_slot_state_t *  parent_state  = parent_state_ ? &parent_state_->slot_state : NULL;
  if( FD_LIKELY( parent_state && ag_slot_state_is_notar_fallback_or_stronger( parent_state, parent_hash ) ) ) {
    int output = ag_slot_state_notify_parent_certified( slot_state( self, slot ), states, block_hash, bad );
    switch( output ) {
    case -1: repair_events_push( self->repair_events, *block_id ); return AG_POOL_SUCCESS;
    case  0: return AG_POOL_SUCCESS;
    case  1: pool_events_push( self->pool_events, (ag_pool_event_t){ .kind = AG_POOL_EVENT_SAFE_TO_NOTAR, .safe_to_notar = *block_id } ); return AG_POOL_SUCCESS;
    }
  }

  if( FD_UNLIKELY( parent_slot<fd_ulong_sat_sub( ag_finality_tracker_first_unpruned_slot( self->finality_tracker ), AG_REWARD_SLOT_DELTA ) ) ) return AG_POOL_SUCCESS; /* the parent can no longer certify */
  for( s2n_waiting_parent_cert_ele_t const * ele = s2n_waiting_parent_cert_map_ele_query_const( self->s2n_waiting_parent_cert->map, &parent_slot, NULL, self->s2n_waiting_parent_cert->pool );
                                             ele;
                                             ele = s2n_waiting_parent_cert_map_ele_next_const( ele, NULL, self->s2n_waiting_parent_cert->pool ) ) {
    if( FD_UNLIKELY( ag_block_id_eq( &ele->child, block_id ) ) ) return AG_POOL_SUCCESS;
  }
  FD_TEST( s2n_waiting_parent_cert_pool_free( self->s2n_waiting_parent_cert->pool ) );
  s2n_waiting_parent_cert_ele_t * ele = s2n_waiting_parent_cert_pool_ele_acquire( self->s2n_waiting_parent_cert->pool );
  ele->parent = *parent_id;
  ele->child  = *block_id;
  s2n_waiting_parent_cert_map_ele_insert( self->s2n_waiting_parent_cert->map, ele, self->s2n_waiting_parent_cert->pool );

  return AG_POOL_SUCCESS;
}

FD_STATIC_ASSERT( AG_NOTAR_FALLBACK_CERT_MAX==4UL && AG_NOTAR_FALLBACK_VOTE_MAX==3UL, standstill_iter_idx );

ag_pool_standstill_iter_t *
ag_pool_standstill_iter_init( ag_pool_standstill_iter_t * iter,
                              ag_pool_t const *           self ) {
  iter->finalized = ag_pool_finalized_slot( self );
  iter->slot      = iter->finalized;
  iter->idx       = 0UL;
  return ag_pool_standstill_iter_next( iter, self );
}

ag_pool_standstill_iter_t *
ag_pool_standstill_iter_next( ag_pool_standstill_iter_t * iter,
                              ag_pool_t const *           self ) {
  ulong slot_far_in_future = ag_finality_tracker_first_unpruned_slot( self->finality_tracker ) + self->slot_max - AG_REWARD_SLOT_DELTA;
  for( ; iter->slot<slot_far_in_future; iter->slot++, iter->idx = 0UL ) {
    slot_state_ele_t const * slot_state_ = slot_state_map_ele_query_const( self->slot_states->map, &iter->slot, NULL, self->slot_states->pool );
    if( FD_UNLIKELY( !slot_state_ ) ) continue;

    ag_slot_certs_t const * certs         = &slot_state_->slot_state.certs;
    ag_slot_votes_t const * votes         = &slot_state_->slot_state.votes;
    ulong                   slot          = slot_state_->slot_state.slot;
    ulong                   own_rank      = slot_state_->slot_state.own_rank;
    ushort                  shred_version = slot_state_->slot_state.shred_version;
    ulong                   idx           = iter->idx;
    int                     finalized     = slot==iter->finalized;
    int                     fast_final    = certs->fast_finalize.slot!=ULONG_MAX;
    int                     final         = certs->finalize.slot!=ULONG_MAX && ( !finalized || ( !fast_final && certs->notar.slot!=ULONG_MAX ) );
    int                     notar         = certs->notar.slot   !=ULONG_MAX && ( !finalized || final );
    ulong                   nf_cert       = fd_ulong_max( idx, 3UL  ) - 3UL;
    ulong                   nf_vote       = fd_ulong_max( idx, 11UL ) - 11UL;

    iter->is_vote = 0;
    if( FD_UNLIKELY( idx<1UL && final      ) ) { iter->idx = 1UL; iter->cert = (ag_cert_t){ .kind = AG_CERT_KIND_FINAL,      .final      = certs->finalize      }; return iter; }
    if( FD_UNLIKELY( idx<2UL && fast_final ) ) { iter->idx = 2UL; iter->cert = (ag_cert_t){ .kind = AG_CERT_KIND_FAST_FINAL, .fast_final = certs->fast_finalize }; return iter; }
    if( FD_LIKELY  ( idx<3UL && notar      ) ) { iter->idx = 3UL; iter->cert = (ag_cert_t){ .kind = AG_CERT_KIND_NOTAR,      .notar      = certs->notar         }; return iter; }
    if( FD_UNLIKELY( finalized ) ) continue;
    if( FD_UNLIKELY( nf_cert<certs->notar_fallback_cnt ) ) { iter->idx = 4UL+nf_cert; iter->cert = (ag_cert_t){ .kind = AG_CERT_KIND_NOTAR_FALLBACK, .notar_fallback = certs->notar_fallback[ nf_cert ] }; return iter; }
    if( FD_UNLIKELY( idx<8UL && certs->skip.slot!=ULONG_MAX ) ) { iter->idx = 8UL; iter->cert = (ag_cert_t){ .kind = AG_CERT_KIND_SKIP, .skip = certs->skip }; return iter; }

    if( FD_UNLIKELY( own_rank==USHORT_MAX ) ) continue; /* unstaked */
    iter->is_vote = 1;
    if( FD_UNLIKELY( idx<9UL && fd_bls_set_test( votes->notar_set, own_rank ) ) ) {
      iter->idx  = 9UL;
      iter->vote = (ag_vote_t){ .kind = AG_VOTE_KIND_NOTAR, .notar = { .slot = slot, .sig = fd_bls_sig_pool_ele_const( self->slot_states->shared.bls_sig_pool, votes->notar_sig_idx[ own_rank ] )->sig, .rank = (ushort)own_rank, .shred_version = shred_version } };
      memcpy( iter->vote.notar.block_hash, ag_vote_stake_pool_ele_const( self->slot_states->shared.notar_hash_stake_pool, votes->notar_hash_stake_idx[ own_rank ] )->block_id.hash, sizeof(ag_block_hash_t) );
      return iter;
    }
    if( FD_LIKELY  ( idx<10UL && fd_bls_set_test( votes->finalize_agg.set, own_rank ) ) ) { iter->idx = 10UL; iter->vote = (ag_vote_t){ .kind = AG_VOTE_KIND_FINAL, .final = { .slot = slot, .sig = fd_bls_sig_pool_ele_const( self->slot_states->shared.bls_sig_pool, votes->finalize_sig_idx[ own_rank ] )->sig, .rank = (ushort)own_rank, .shred_version = shred_version } }; return iter; }
    if( FD_UNLIKELY( idx<11UL && fd_bls_set_test( votes->skip_agg.set,     own_rank ) ) ) { iter->idx = 11UL; iter->vote = (ag_vote_t){ .kind = AG_VOTE_KIND_SKIP,  .skip  = { .slot = slot, .sig = fd_bls_sig_pool_ele_const( self->slot_states->shared.bls_sig_pool, votes->skip_sig_idx    [ own_rank ] )->sig, .rank = (ushort)own_rank, .shred_version = shred_version } }; return iter; }
    if( FD_UNLIKELY( nf_vote<votes->notar_fallback_sig_cnt[ own_rank ] ) ) {
      iter->idx  = 12UL+nf_vote;
      iter->vote = (ag_vote_t){ .kind = AG_VOTE_KIND_NOTAR_FALLBACK, .notar_fallback = { .slot = slot, .sig = fd_bls_sig_pool_ele_const( self->slot_states->shared.bls_sig_pool, votes->notar_fallback_sig_idx[ own_rank ][ nf_vote ] )->sig, .rank = (ushort)own_rank, .shred_version = shred_version } };
      memcpy( iter->vote.notar_fallback.block_hash, ag_vote_stake_pool_ele_const( self->slot_states->shared.notar_fallback_hash_stake_pool, votes->notar_fallback_hash_stake_idx[ own_rank ][ nf_vote ] )->block_id.hash, sizeof(ag_block_hash_t) );
      return iter;
    }
    if( FD_UNLIKELY( idx<15UL && fd_bls_set_test( votes->skip_fallback_agg.set, own_rank ) ) ) { iter->idx = 15UL; iter->vote = (ag_vote_t){ .kind = AG_VOTE_KIND_SKIP_FALLBACK, .skip_fallback = { .slot = slot, .sig = fd_bls_sig_pool_ele_const( self->slot_states->shared.bls_sig_pool, votes->skip_fallback_sig_idx[ own_rank ] )->sig, .rank = (ushort)own_rank, .shred_version = shred_version } }; return iter; }
  }
  iter->slot = ULONG_MAX;
  return iter;
}

FD_FN_PURE int
ag_pool_standstill_iter_done( ag_pool_standstill_iter_t const * iter ) {
  return iter->slot==ULONG_MAX;
}

FD_FN_PURE ulong
ag_pool_finalized_slot( ag_pool_t const * self ) {
  return ag_finality_tracker_highest_finalized_slot( self->finality_tracker );
}

FD_FN_PURE uchar const *
ag_pool_finalized_block_hash( ag_pool_t const * self ) {
  return ag_finality_tracker_highest_finalized_block_hash( self->finality_tracker );
}

ulong
ag_pool_parents_ready( ag_pool_t const * self,
                       ulong             slot,
                       ag_block_id_t *   out,
                       ulong             out_max ) {
  return ag_parent_ready_tracker_parents_ready( self->parent_ready_tracker, slot, out, out_max );
}

ag_block_id_t
ag_pool_wait_for_parent_ready( ag_pool_t * self,
                               ulong       slot ) {
  return ag_parent_ready_tracker_wait_for_parent_ready( self->parent_ready_tracker, slot );
}

int
ag_pool_poll_pool_event( ag_pool_t *       self,
                         ag_pool_event_t * event ) {
  if( FD_LIKELY( pool_events_empty( self->pool_events ) ) ) return 0;
  *event = pool_events_pop( self->pool_events );
  if( FD_LIKELY( event->kind!=AG_POOL_EVENT_PARENT_READY ) ) return 1;
  ag_parent_ready_state_t * state = ag_parent_ready_state_map_ele_query( self->parent_ready_tracker->states.map, &event->parent_ready.slot, NULL, self->parent_ready_tracker->states.pool );
  if( FD_LIKELY( state ) ) state->ready = 0; /* NULL if pruned while queued */
  return 1;
}

int
ag_pool_poll_repair_event( ag_pool_t *     self,
                           ag_block_id_t * block ) {
  if( FD_LIKELY( repair_events_empty( self->repair_events ) ) ) return 0;
  *block = repair_events_pop( self->repair_events );
  return 1;
}
