#include "fd_votor_loop.h"

#define BLOCK_REPLAYED  (0)
#define PARENT_READY    (1)
#define BLOCK_NOTARIZED (2)
#define TIMEOUT         (3)
#define SAFE_TO_NOTAR   (4)
#define SAFE_TO_SKIP    (5)

struct vote_event {
  uchar     reason;
  fd_vote_t vote;
};
typedef struct vote_event vote_event_t;

#define QUEUE_NAME vote_events
#define QUEUE_T    vote_event_t
#include "../../util/tmpl/fd_queue_dynamic.c"

struct slot_state_ele {
  ulong slot;
  ulong next;

  int             voted;
  int             voted_notar;
  fd_block_hash_t voted_notar_hash;
  int             bad_window;
  int             block_notarized;
  fd_block_hash_t block_notarized_hash;
  int             pending_block;
  fd_block_info_t pending_block_info;
  int             retired;

  long timeout;

  struct { ulong prev; ulong next; } pending_dlist;
  struct { ulong prev; ulong next; } timeout_dlist;
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
#define MAP_KEY_HASH(key,seed) (fd_ulong_hash((*(key))^(seed)))
#define MAP_NEXT               next
#include "../../util/tmpl/fd_map_chain.c"

#define DLIST_NAME  pending_dlist
#define DLIST_ELE_T slot_state_ele_t
#define DLIST_PREV  pending_dlist.prev
#define DLIST_NEXT  pending_dlist.next
#include "../../util/tmpl/fd_dlist.c"

#define DLIST_NAME  timeout_dlist
#define DLIST_ELE_T slot_state_ele_t
#define DLIST_PREV  timeout_dlist.prev
#define DLIST_NEXT  timeout_dlist.next
#include "../../util/tmpl/fd_dlist.c"

struct slot_states {
  slot_state_ele_t * pool;
  slot_state_map_t * map;
};
typedef struct slot_states slot_states_t;

#define SORT_NAME        slot_sort
#define SORT_KEY_T       ulong
#define SORT_BEFORE(a,b) ((a)<(b))
#include "../../util/tmpl/fd_sort.c"

struct epoch_bls_key {
  ulong start_slot;
  ulong rank;
  long  ns_per_slot;
  uchar bls_key[ FD_BLS_PUB_COMPRESSED_SZ ];
  int   has_bls_key;
};
typedef struct epoch_bls_key epoch_bls_key_t;

struct __attribute__((aligned(128UL))) fd_votor_loop {
  ulong          slot_max;
  long           now;
  ulong          root;
  ushort         shred_version;
  long           ns_per_slot;

  slot_states_t *             slot_states;
  fd_parent_ready_tracker_t * parent_ready_tracker; /* Definition 15 over the certs received */
  ulong                       highest_final_slot;
  long                        highest_final_ts; /* when highest_final_slot last rose */
  ulong                       catchup_vote_slot; /* first slot worth a vote while catching up, 0 if none */

  fd_bls_sign_fn bls_sign_fn;
  void *         bls_sign_ctx;
  ulong          failover_vote_bound; /* we cast no vote at or below this slot, ULONG_MAX when none */

  epoch_bls_key_t prev_epoch;
  epoch_bls_key_t curr_epoch;
  epoch_bls_key_t next_epoch;

  vote_event_t *    vote_events;
  pending_dlist_t * pending_dlist;
  timeout_dlist_t * timeout_dlist[ FD_VOTOR_SLOTS_PER_WINDOW ];

  struct {
    ulong *             slots;
    fd_parent_ready_t * parent_readys;
  } scratch;
};

static slot_state_ele_t *
state_mut( fd_votor_loop_t * self,
           ulong             slot ) {
  slot_state_ele_t * ele = slot_state_map_ele_query( self->slot_states->map, &slot, NULL, self->slot_states->pool );
  if( FD_LIKELY( ele ) ) return ele;

  FD_TEST( slot_state_pool_free( self->slot_states->pool ) );

  ele          = slot_state_pool_ele_acquire( self->slot_states->pool );
  fd_memset( ele, 0, sizeof(slot_state_ele_t) );
  ele->slot    = slot;
  ele->timeout = LONG_MAX;
  slot_state_map_ele_insert( self->slot_states->map, ele, self->slot_states->pool );
  return ele;
}

static void
push_vote( fd_votor_loop_t * self,
           fd_vote_t         vote,
           uchar             reason ) {
  FD_TEST( !vote_events_full( self->vote_events ) );
  vote_events_push( self->vote_events, (vote_event_t){ .reason = reason, .vote = vote } );
}

FD_FN_PURE static epoch_bls_key_t const *
own_epoch( fd_votor_loop_t const * self,
           ulong                   slot ) {
  if( FD_UNLIKELY( slot>=self->next_epoch.start_slot ) ) return &self->next_epoch;
  if( FD_LIKELY( slot>=self->curr_epoch.start_slot ) ) return &self->curr_epoch;
  return &self->prev_epoch;
}

/* No crashed-leader timeout.  Agave tracks one, but with
   delta_first_fec_set = delta_block its deadline lands on the first
   slot's timeout, so it never skips a window earlier. */

static void
set_timeouts( fd_votor_loop_t * self,
              ulong             slot ) {
  FD_TEST( fd_is_start_of_window( slot ) );

  long ns_per_slot = own_epoch( self, slot )->ns_per_slot; /* the window's own epoch, not the latest one announced */
  if( FD_UNLIKELY( !ns_per_slot ) ) ns_per_slot = self->ns_per_slot;

  /* Section 4.1: after DELTA_STANDSTILL without a new finalization, the
     skip timeout grows 5% per window past the finalized slot. */

  long delta_timeout = FD_VOTOR_DELTA_TIMEOUT_NS;
  if( FD_UNLIKELY( self->now-self->highest_final_ts>=FD_VOTOR_DELTA_STANDSTILL_NS ) ) {
    for( ulong w=fd_ulong_sat_sub( slot, self->highest_final_slot )/FD_VOTOR_SLOTS_PER_WINDOW; w && delta_timeout<FD_VOTOR_DELTA_TIMEOUT_MAX_NS; w-- ) delta_timeout += delta_timeout/20L;
    delta_timeout = fd_long_min( delta_timeout, FD_VOTOR_DELTA_TIMEOUT_MAX_NS );
  }
  long deadline = self->now + delta_timeout + ns_per_slot;

  for( ulong s=slot; s<slot+FD_VOTOR_SLOTS_PER_WINDOW; s++ ) {
    deadline += fd_long_if( fd_is_start_of_window( s ), 0L, ns_per_slot );

    /* A slot's deadline is now plus an offset fixed by its position in the
       window, so each position's list fills in deadline order and its head
       is its earliest timer.  The walk back from the tail only runs if the
       slot length changed (block duration feature activation), or the clock
       stepped back. */

    slot_state_ele_t * ele  = state_mut( self, s );
    timeout_dlist_t *  list = self->timeout_dlist[ s%FD_VOTOR_SLOTS_PER_WINDOW ];
    slot_state_ele_t * pool = self->slot_states->pool;
    if( FD_LIKELY( ele->timeout!=LONG_MAX ) ) {
      if( FD_LIKELY( ele->timeout<=deadline ) ) continue;
      timeout_dlist_ele_remove( list, ele, pool );
    }
    ele->timeout = deadline;

    timeout_dlist_iter_t iter = timeout_dlist_iter_rev_init( list, pool );
    while( FD_UNLIKELY( !timeout_dlist_iter_done( iter, list, pool ) && timeout_dlist_iter_ele( iter, list, pool )->timeout>deadline ) ) {
      iter = timeout_dlist_iter_rev_next( iter, list, pool );
    }
    if( FD_LIKELY( !timeout_dlist_iter_done( iter, list, pool ) ) ) timeout_dlist_ele_insert_after( list, ele, timeout_dlist_iter_ele( iter, list, pool ), pool );
    else                                                            timeout_dlist_ele_push_head   ( list, ele, pool );
  }
}

static slot_state_ele_t *
next_timeout( fd_votor_loop_t const * self ) {
  slot_state_ele_t * pool = self->slot_states->pool;
  slot_state_ele_t * head = NULL;
  for( ulong k=0UL; k<FD_VOTOR_SLOTS_PER_WINDOW; k++ ) {
    if( FD_LIKELY( timeout_dlist_is_empty( self->timeout_dlist[ k ], pool ) ) ) continue;
    slot_state_ele_t * ele = timeout_dlist_ele_peek_head( self->timeout_dlist[ k ], pool );
    if( !head || ele->timeout<head->timeout ) head = ele;
  }
  return head;
}

ulong
fd_votor_loop_align( void ) {
  return alignof(fd_votor_loop_t);
}

ulong
fd_votor_loop_footprint( ulong slot_max ) {
  if( FD_UNLIKELY( slot_max<FD_VOTOR_SLOTS_PER_WINDOW ) ) return 0UL;
  ulong events_max = slot_max*( FD_VOTOR_NOTAR_FALLBACK_CERT_MAX + 1UL /* notar */ + 1UL /* skip */ );
  ulong slot_state_chain_cnt = slot_state_map_chain_cnt_est( slot_max );
  ulong ready_max            = slot_max + 2UL*FD_VOTOR_SLOTS_PER_WINDOW + 1UL; /* see fd_votor_pool_footprint, plus the window below first_unpruned_slot */
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
      alignof(fd_votor_loop_t), sizeof(fd_votor_loop_t)                             ),
      alignof(slot_states_t),   sizeof(slot_states_t)                               ),
      slot_state_pool_align(),  slot_state_pool_footprint( slot_max )               ),
      slot_state_map_align(),   slot_state_map_footprint ( slot_state_chain_cnt )   ),
      pending_dlist_align(),    pending_dlist_footprint()                           ),
      timeout_dlist_align(),    timeout_dlist_footprint()*FD_VOTOR_SLOTS_PER_WINDOW ),
      vote_events_align(),      vote_events_footprint( events_max )                 ),
      alignof(ulong),           sizeof(ulong)*slot_max                              ),
      fd_parent_ready_tracker_align(), fd_parent_ready_tracker_footprint( ready_max ) ),
      alignof(fd_parent_ready_t), sizeof(fd_parent_ready_t)*slot_max                ),
    fd_votor_loop_align() );
}

void *
fd_votor_loop_new( void * mem,
                   ulong  slot_max,
                   ulong  seed ) {
  if( FD_UNLIKELY( !mem ) ) {
    FD_LOG_WARNING(( "NULL mem" ));
    return NULL;
  }
  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)mem, fd_votor_loop_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned mem" ));
    return NULL;
  }
  ulong footprint = fd_votor_loop_footprint( slot_max );
  if( FD_UNLIKELY( !footprint ) ) {
    FD_LOG_WARNING(( "bad slot_max (%lu)", slot_max ));
    return NULL;
  }
  fd_memset( mem, 0, footprint );

  ulong events_max           = slot_max*( FD_VOTOR_NOTAR_FALLBACK_CERT_MAX + 1UL /* notar */ + 1UL /* skip */ );
  ulong slot_state_chain_cnt = slot_state_map_chain_cnt_est( slot_max );
  ulong ready_max            = slot_max + 2UL*FD_VOTOR_SLOTS_PER_WINDOW + 1UL;

  FD_SCRATCH_ALLOC_INIT( l, mem );
  fd_votor_loop_t * votor            = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_votor_loop_t), sizeof(fd_votor_loop_t)                             );
  void *            slot_states      = FD_SCRATCH_ALLOC_APPEND( l, alignof(slot_states_t),   sizeof(slot_states_t)                               );
  void *            slot_state_pool  = FD_SCRATCH_ALLOC_APPEND( l, slot_state_pool_align(),  slot_state_pool_footprint( slot_max )               );
  void *            slot_state_map   = FD_SCRATCH_ALLOC_APPEND( l, slot_state_map_align(),   slot_state_map_footprint ( slot_state_chain_cnt )   );
  void *            pending_dlist    = FD_SCRATCH_ALLOC_APPEND( l, pending_dlist_align(),    pending_dlist_footprint()                           );
  uchar *           timeout_dlist    = FD_SCRATCH_ALLOC_APPEND( l, timeout_dlist_align(),    timeout_dlist_footprint()*FD_VOTOR_SLOTS_PER_WINDOW );
  void *            vote_events      = FD_SCRATCH_ALLOC_APPEND( l, vote_events_align(),      vote_events_footprint( events_max )                 );
  void *            slot_scratch     = FD_SCRATCH_ALLOC_APPEND( l, alignof(ulong),           sizeof(ulong)*slot_max                              );
  void *            ready_tracker    = FD_SCRATCH_ALLOC_APPEND( l, fd_parent_ready_tracker_align(), fd_parent_ready_tracker_footprint( ready_max ) );
  void *            ready_scratch    = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_parent_ready_t), sizeof(fd_parent_ready_t)*slot_max                );
  FD_TEST( FD_SCRATCH_ALLOC_FINI( l, fd_votor_loop_align() ) == (ulong)mem + footprint );

  votor->slot_max                = slot_max;
  votor->now                     = 0L;
  votor->root                    = ULONG_MAX;
  votor->shred_version           = 0;
  votor->ns_per_slot             = 0L;
  votor->bls_sign_fn             = NULL;
  votor->bls_sign_ctx            = NULL;
  votor->slot_states             = (slot_states_t *)slot_states;
  votor->slot_states->pool       = slot_state_pool_join( slot_state_pool_new( slot_state_pool, slot_max                  ) );
  votor->slot_states->map        = slot_state_map_join ( slot_state_map_new ( slot_state_map,  slot_state_chain_cnt, seed ) );
  votor->highest_final_slot      = ULONG_MAX;
  votor->highest_final_ts        = 0L;
  votor->catchup_vote_slot       = 0UL;
  votor->prev_epoch              = (epoch_bls_key_t){ .start_slot = ULONG_MAX, .rank = USHORT_MAX };
  votor->curr_epoch              = (epoch_bls_key_t){ .start_slot = ULONG_MAX, .rank = USHORT_MAX };
  votor->next_epoch              = (epoch_bls_key_t){ .start_slot = ULONG_MAX, .rank = USHORT_MAX };
  votor->failover_vote_bound     = ULONG_MAX;
  votor->vote_events             = vote_events_join( vote_events_new( vote_events, events_max ) );
  votor->pending_dlist           = pending_dlist_join( pending_dlist_new( pending_dlist ) );
  for( ulong k=0UL; k<FD_VOTOR_SLOTS_PER_WINDOW; k++ ) votor->timeout_dlist[ k ] = timeout_dlist_join( timeout_dlist_new( timeout_dlist+k*timeout_dlist_footprint() ) );
  votor->scratch.slots           = (ulong *)slot_scratch;
  votor->parent_ready_tracker    = fd_parent_ready_tracker_join( fd_parent_ready_tracker_new( ready_tracker, ready_max, seed ) );
  votor->scratch.parent_readys   = (fd_parent_ready_t *)ready_scratch;

  return mem;
}

fd_votor_loop_t *
fd_votor_loop_join( void * mem ) {
  fd_votor_loop_t * votor = (fd_votor_loop_t *)mem;
  if( FD_UNLIKELY( !votor ) ) {
    FD_LOG_WARNING(( "NULL mem" ));
    return NULL;
  }
  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)votor, fd_votor_loop_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned mem" ));
    return NULL;
  }
  return votor;
}

void *
fd_votor_loop_leave( fd_votor_loop_t const * self ) {
  if( FD_UNLIKELY( !self ) ) {
    FD_LOG_WARNING(( "NULL votor" ));
    return NULL;
  }
  return (void *)self;
}

void *
fd_votor_loop_delete( void * mem ) {
  if( FD_UNLIKELY( !mem ) ) {
    FD_LOG_WARNING(( "NULL mem" ));
    return NULL;
  }
  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)mem, fd_votor_loop_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned mem" ));
    return NULL;
  }
  return mem;
}

void
fd_votor_loop_init( fd_votor_loop_t *     self,
                    fd_block_id_t const * root,
                    long                  now,
                    long                  ns_per_slot,
                    ushort                shred_version,
                    fd_bls_sign_fn        sign_fn,
                    void *                sign_ctx ) {
  FD_TEST( sign_fn );
  self->now                     = now;
  self->root                    = root->slot;
  self->shred_version           = shred_version;
  self->ns_per_slot             = ns_per_slot;
  self->bls_sign_fn             = sign_fn;
  self->bls_sign_ctx            = sign_ctx;

  slot_state_ele_t * state       = state_mut( self, root->slot );
  state->voted                   = 1;
  state->voted_notar             = 1;
  state->block_notarized         = 1;
  state->retired                 = 1;
  memcpy( &state->voted_notar_hash,     &root->hash, sizeof(fd_block_hash_t) );
  memcpy( &state->block_notarized_hash, &root->hash, sizeof(fd_block_hash_t) );

  for( ulong s=fd_first_slot_in_window( root->slot ); s<root->slot; s++ ) {
    slot_state_ele_t * below = state_mut( self, s );
    below->voted               = 1;
    below->retired             = 1;
  }

  self->highest_final_slot = root->slot;
  self->highest_final_ts   = now;

  ulong ready_cnt;
  self->parent_ready_tracker->root = fd_ulong_sat_sub( fd_first_slot_in_window( fd_ulong_sat_sub( root->slot, FD_VOTOR_REWARD_SLOT_DELTA ) ), FD_VOTOR_SLOTS_PER_WINDOW );
  ready_cnt = fd_parent_ready_tracker_mark_notar_fallback( self->parent_ready_tracker, root, self->scratch.parent_readys );
  for( ulong i=0UL; i<ready_cnt; i++ ) fd_parent_ready_state_map_ele_query( self->parent_ready_tracker->states.map, &self->scratch.parent_readys[i].slot, NULL, self->parent_ready_tracker->states.pool )->ready = 0;
}

void
fd_votor_loop_fini( fd_votor_loop_t * self ) {
  self->root                    = ULONG_MAX;
  self->highest_final_slot      = ULONG_MAX;
}

FD_FN_PURE fd_votor_loop_metrics_t
fd_votor_loop_metrics( fd_votor_loop_t const * self ) {
  return (fd_votor_loop_metrics_t){
    .slot_state_pool_used    = slot_state_pool_used( self->slot_states->pool ),
    .slot_state_pool_free    = slot_state_pool_free( self->slot_states->pool ),
    .highest_final_slot      = self->highest_final_slot,
    .vote_events_cnt         = vote_events_cnt( self->vote_events )
  };
}

FD_FN_PURE static int
is_retired( fd_votor_loop_t const * self,
            ulong                   slot ) {
  slot_state_ele_t const * ele = slot_state_map_ele_query_const( self->slot_states->map, &slot, NULL, self->slot_states->pool );
  return ele && ele->retired;
}

FD_FN_PURE static int
has_voted( fd_votor_loop_t const * self,
           ulong                   slot ) {
  slot_state_ele_t const * ele = slot_state_map_ele_query_const( self->slot_states->map, &slot, NULL, self->slot_states->pool );
  return ele && ele->voted;
}

FD_FN_PURE static ulong
first_unpruned_slot( fd_votor_loop_t const * self ) {
  return fd_first_slot_in_window( fd_ulong_sat_sub( self->highest_final_slot, FD_VOTOR_REWARD_SLOT_DELTA ) );
}

/* Returns whether slot is at or below our vote bound. */

FD_FN_PURE static int
below_failover_vote_bound( fd_votor_loop_t const * self,
                           ulong                   slot ) {
  return self->failover_vote_bound!=ULONG_MAX && slot<=self->failover_vote_bound;
}

static int
should_ignore_pool_event( fd_votor_loop_t const *       self,
                          fd_votor_pool_event_t const * event ) {
  ulong slot;
  switch( event->kind ) {
  case FD_VOTOR_POOL_EVENT_PARENT_READY:  slot = event->parent_ready.slot;             break;
  case FD_VOTOR_POOL_EVENT_SAFE_TO_NOTAR: slot = event->safe_to_notar.slot;            break;
  case FD_VOTOR_POOL_EVENT_SAFE_TO_SKIP:  slot = event->safe_to_skip;                  break;
  case FD_VOTOR_POOL_EVENT_CERT_CREATED:  slot = fd_cert_slot( &event->cert_created ); break;
  default:                                FD_LOG_CRIT(( "unreachable" ));
  }
  switch( event->kind ) {
  case FD_VOTOR_POOL_EVENT_CERT_CREATED:  return slot<first_unpruned_slot( self );
  case FD_VOTOR_POOL_EVENT_PARENT_READY:
  case FD_VOTOR_POOL_EVENT_SAFE_TO_NOTAR:
  case FD_VOTOR_POOL_EVENT_SAFE_TO_SKIP: return slot<first_unpruned_slot( self ) || is_retired( self, slot );
  default:                               FD_LOG_CRIT(( "unreachable" ));
  }
}

static void
try_final( fd_votor_loop_t *       self,
           ulong                   slot,
           fd_block_hash_t const * hash ) {
  FD_TEST( slot>=first_unpruned_slot( self ) );
  if( FD_UNLIKELY( below_failover_vote_bound( self, slot ) ) ) return;
  epoch_bls_key_t const * epoch = own_epoch( self, slot );

  slot_state_ele_t const * state = slot_state_map_ele_query_const( self->slot_states->map, &slot, NULL, self->slot_states->pool );
  int notarized   = state && state->block_notarized && !memcmp( &state->block_notarized_hash, hash, sizeof(fd_block_hash_t) );
  int voted_notar = state && state->voted_notar     && !memcmp( &state->voted_notar_hash,     hash, sizeof(fd_block_hash_t) );
  int not_bad     = !( state && state->bad_window );
  if( FD_LIKELY( notarized && voted_notar && not_bad ) ) {
    state_mut( self, slot )->retired = 1;
    if( FD_UNLIKELY( !epoch->has_bls_key || slot<self->catchup_vote_slot ) ) return;
    fd_vote_t vote = fd_vote_construct_final( self->bls_sign_fn, self->bls_sign_ctx, epoch->bls_key, slot, (ushort)epoch->rank, self->shred_version );
    push_vote( self, vote, BLOCK_NOTARIZED );
  }
}

static int
try_notar( fd_votor_loop_t *       self,
           ulong                   slot,
           fd_block_info_t const * block_info,
           uchar                   reason ) {
  FD_TEST( slot>=first_unpruned_slot( self ) );
  epoch_bls_key_t const * epoch = own_epoch( self, slot );
  if( FD_UNLIKELY( !epoch->has_bls_key       ) ) return 0;
  if( FD_UNLIKELY( has_voted( self, slot ) ) ) return 0;
  if( FD_UNLIKELY( below_failover_vote_bound( self, slot ) ) ) return 0;

  fd_block_hash_t hash;
  memcpy( &hash, &block_info->hash, sizeof(fd_block_hash_t) );
  fd_block_id_t parent = block_info->parent;

  if( FD_UNLIKELY( fd_is_start_of_window( slot ) ) ) {
    if( FD_UNLIKELY( !fd_parent_ready_tracker_is_parent_ready( self->parent_ready_tracker, slot, &parent ) ) ) return 0;
  } else {
    if( FD_UNLIKELY( parent.slot!=slot-1UL ) ) return 0;
    slot_state_ele_t const * parent_state = slot_state_map_ele_query_const( self->slot_states->map, &parent.slot, NULL, self->slot_states->pool );
    if( FD_UNLIKELY( !parent_state || !parent_state->voted_notar                                      ) ) return 0;
    if( FD_UNLIKELY( memcmp( &parent_state->voted_notar_hash, &parent.hash, sizeof(fd_block_hash_t) )!=0 ) ) return 0;
  }

  if( FD_LIKELY( slot>=self->catchup_vote_slot ) ) {
    fd_vote_t vote = fd_vote_construct_notar( self->bls_sign_fn, self->bls_sign_ctx, epoch->bls_key, slot, &hash, (ushort)epoch->rank, self->shred_version );
    push_vote( self, vote, reason );
  }

  slot_state_ele_t * state = state_mut( self, slot );
  if( FD_UNLIKELY( state->pending_block ) ) pending_dlist_ele_remove( self->pending_dlist, state, self->slot_states->pool );
  state->voted         = 1;
  state->voted_notar   = 1;
  state->pending_block = 0;
  memcpy( &state->voted_notar_hash, &hash, sizeof(fd_block_hash_t) );

  try_final( self, slot, &hash );
  return 1;
}

static void
try_skip_window( fd_votor_loop_t * self,
                 ulong             slot,
                 uchar             reason ) {
  FD_TEST( slot>=first_unpruned_slot( self ) );

  ulong window_start = fd_first_slot_in_window( slot );
  for( ulong s=window_start; s<window_start+FD_VOTOR_SLOTS_PER_WINDOW; s++ ) {
    epoch_bls_key_t const * epoch = own_epoch( self, s );
    if( FD_UNLIKELY( !epoch->has_bls_key  ) ) continue;
    if( FD_UNLIKELY( has_voted( self, s ) ) ) continue;
    if( FD_UNLIKELY( below_failover_vote_bound( self, s ) ) ) continue;

    slot_state_ele_t * state = state_mut( self, s );
    state->voted             = 1;
    state->bad_window        = 1;

    if( FD_UNLIKELY( s<self->catchup_vote_slot ) ) continue;

    fd_vote_t vote = fd_vote_construct_skip( self->bls_sign_fn, self->bls_sign_ctx, epoch->bls_key, s, (ushort)epoch->rank, self->shred_version );
    push_vote( self, vote, reason );
  }
}

static void
check_pending_blocks( fd_votor_loop_t * self,
                      uchar             reason ) {
  slot_state_map_t * map   = self->slot_states->map;
  slot_state_ele_t * pool  = self->slot_states->pool;
  ulong *            slots = self->scratch.slots;
  ulong              cnt   = 0UL;

  for( pending_dlist_iter_t iter = pending_dlist_iter_fwd_init( self->pending_dlist, pool );
                                  !pending_dlist_iter_done( iter, self->pending_dlist, pool );
                            iter = pending_dlist_iter_fwd_next( iter, self->pending_dlist, pool ) ) {
    slot_state_ele_t const * ele = pending_dlist_iter_ele_const( iter, self->pending_dlist, pool );
    if( FD_LIKELY( cnt<self->slot_max ) ) slots[ cnt++ ] = ele->slot;
  }
  slot_sort_inplace( slots, cnt );

  for( ulong i=0UL; i<cnt; i++ ) {
    slot_state_ele_t const * ele = slot_state_map_ele_query_const( map, &slots[i], NULL, pool );
    if( FD_LIKELY( ele && ele->pending_block ) ) try_notar( self, slots[i], &ele->pending_block_info, reason );
  }
}

static void
prune( fd_votor_loop_t * self ) {
  ulong first_unpruned = first_unpruned_slot( self );
  for( ulong slot=self->root; slot<first_unpruned; slot++ ) {
    slot_state_ele_t * ele = slot_state_map_ele_remove( self->slot_states->map, &slot, NULL, self->slot_states->pool );
    if( FD_LIKELY( ele ) ) {
      if( FD_UNLIKELY( ele->pending_block     ) ) pending_dlist_ele_remove( self->pending_dlist, ele, self->slot_states->pool );
      if( FD_LIKELY  ( ele->timeout!=LONG_MAX ) ) timeout_dlist_ele_remove( self->timeout_dlist[ slot%FD_VOTOR_SLOTS_PER_WINDOW ], ele, self->slot_states->pool );
      slot_state_pool_ele_release( self->slot_states->pool, ele );
    }
  }
  self->root = first_unpruned;
  fd_parent_ready_tracker_prune( self->parent_ready_tracker, fd_ulong_sat_sub( first_unpruned, FD_VOTOR_SLOTS_PER_WINDOW ) ); /* parents of the window at first_unpruned */
}

static fd_cert_t const *
handle_cert_created( fd_votor_loop_t * self,
                     fd_cert_t const * cert ) {
  ulong slot = fd_cert_slot( cert );

  switch( cert->kind ) {

  case FD_CERT_KIND_FINAL:
  case FD_CERT_KIND_FAST_FINAL:
    if( FD_LIKELY( slot>self->highest_final_slot ) ) {
      self->highest_final_slot = slot;
      self->highest_final_ts   = self->now;
    }
    set_timeouts( self, fd_first_slot_in_window( slot ) );
    prune( self );
    break;

  case FD_CERT_KIND_NOTAR: {
    fd_block_hash_t const * hash = fd_cert_block_hash( cert );

    slot_state_ele_t * state = state_mut( self, slot );
    state->block_notarized   = 1;
    memcpy( &state->block_notarized_hash, hash, sizeof(fd_block_hash_t) );

    try_final( self, slot, hash );
    break;
  }

  case FD_CERT_KIND_NOTAR_FALLBACK:
  case FD_CERT_KIND_SKIP:
    break;

  default:
    FD_LOG_CRIT(( "unreachable" ));
  }

  return fd_ptr_if( slot>=self->catchup_vote_slot, cert, NULL );
}

void
fd_votor_loop_advance_epoch( fd_votor_loop_t * self,
                             long              ns_per_slot,
                             ulong             epoch_rank,
                             ulong             epoch_slot,
                             uchar const       bls_key[ FD_BLS_PUB_COMPRESSED_SZ ] ) {
  epoch_bls_key_t epoch = { .start_slot = epoch_slot, .rank = epoch_rank, .ns_per_slot = ns_per_slot, .has_bls_key = !!bls_key };
  if( FD_LIKELY( bls_key ) ) memcpy( epoch.bls_key, bls_key, FD_BLS_PUB_COMPRESSED_SZ );

  if( FD_UNLIKELY( self->curr_epoch.start_slot==ULONG_MAX ) ) {
    self->curr_epoch = epoch;
  } else if( FD_UNLIKELY( self->next_epoch.start_slot==ULONG_MAX ) ) {
    self->next_epoch = epoch;
  } else {
    self->prev_epoch = self->curr_epoch;
    self->curr_epoch = self->next_epoch;
    self->next_epoch = epoch;
  }
}

void
fd_votor_loop_arm_skip_timeouts( fd_votor_loop_t * self,
                                 long              now ) {
  FD_TEST( self->root!=ULONG_MAX );
  self->now              = fd_long_max( self->now, now );
  self->highest_final_ts = self->now;
  set_timeouts( self, fd_first_slot_in_window( self->root ) );
}

static epoch_bls_key_t *
epoch_starting_at( fd_votor_loop_t * self,
                   ulong             epoch_slot ) {
  if( epoch_slot==self->prev_epoch.start_slot ) return &self->prev_epoch;
  if( epoch_slot==self->curr_epoch.start_slot ) return &self->curr_epoch;
  if( epoch_slot==self->next_epoch.start_slot ) return &self->next_epoch;
  FD_LOG_CRIT(( "no epoch starts at slot %lu", epoch_slot ));
}

void
fd_votor_loop_set_bls_key( fd_votor_loop_t * self,
                           ulong             epoch_slot,
                           uchar const       bls_key[ FD_BLS_PUB_COMPRESSED_SZ ] ) {
  epoch_bls_key_t * epoch = epoch_starting_at( self, epoch_slot );
  epoch->has_bls_key = !!bls_key;
  if( FD_LIKELY( bls_key ) ) memcpy( epoch->bls_key, bls_key, FD_BLS_PUB_COMPRESSED_SZ );
  if( FD_LIKELY( bls_key ) ) check_pending_blocks( self, BLOCK_REPLAYED );
}

void
fd_votor_loop_update_own_rank( fd_votor_loop_t * self,
                               ulong             epoch_slot,
                               ulong             epoch_rank ) {
  epoch_starting_at( self, epoch_slot )->rank = epoch_rank;
}

fd_cert_t const *
fd_votor_loop_handle_pool_event( fd_votor_loop_t *             self,
                                 fd_votor_pool_event_t const * event,
                                 long                          now ) {
  self->now = now;

  /* Definition 15 over the certs received, a fast-finalization cert is
     a notarization cert (Table 6).  Ahead of the ignore filter, a cert
     just below first_unpruned_slot can still ready its window start.  A
     window start that gains a ready parent may unblock a pending block. */

  if( FD_UNLIKELY( event->kind==FD_VOTOR_POOL_EVENT_CERT_CREATED ) ) {
    fd_cert_t const * cert      = &event->cert_created;
    ulong             ready_cnt = 0UL;
    switch( cert->kind ) {
    case FD_CERT_KIND_FINAL:          break;
    case FD_CERT_KIND_FAST_FINAL:
    case FD_CERT_KIND_NOTAR:
    case FD_CERT_KIND_NOTAR_FALLBACK: {
      fd_block_id_t block_id = fd_block_id( fd_cert_slot( cert ), fd_cert_block_hash( cert )->uc );
      ready_cnt = fd_parent_ready_tracker_mark_notar_fallback( self->parent_ready_tracker, &block_id, self->scratch.parent_readys );
      break;
    }
    case FD_CERT_KIND_SKIP:           ready_cnt = fd_parent_ready_tracker_mark_skipped( self->parent_ready_tracker, fd_cert_slot( cert ), self->scratch.parent_readys ); break;
    default:                          FD_LOG_CRIT(( "unreachable" ));
    }
    for( ulong i=0UL; i<ready_cnt; i++ ) fd_parent_ready_state_map_ele_query( self->parent_ready_tracker->states.map, &self->scratch.parent_readys[i].slot, NULL, self->parent_ready_tracker->states.pool )->ready = 0;
    if( FD_UNLIKELY( ready_cnt ) ) check_pending_blocks( self, PARENT_READY );
  }

  if( FD_UNLIKELY( should_ignore_pool_event( self, event ) ) ) return NULL;

  switch( event->kind ) {

  case FD_VOTOR_POOL_EVENT_PARENT_READY: {
    check_pending_blocks( self, PARENT_READY );
    set_timeouts( self, event->parent_ready.slot );
    break;
  }

  case FD_VOTOR_POOL_EVENT_SAFE_TO_NOTAR: {
    ulong                   slot  = event->safe_to_notar.slot;
    fd_block_hash_t const * hash  = &event->safe_to_notar.hash;
    /* No fallback vote at or below the vote bound. */
    if( FD_UNLIKELY( below_failover_vote_bound( self, slot ) ) ) { try_skip_window( self, slot, SAFE_TO_NOTAR ); break; }
    epoch_bls_key_t const * epoch = own_epoch( self, slot );
    if( FD_UNLIKELY( !epoch->has_bls_key ) ) break;
    if( FD_LIKELY( slot>=self->catchup_vote_slot ) ) {
      fd_vote_t vote = fd_vote_construct_notar_fallback( self->bls_sign_fn, self->bls_sign_ctx, epoch->bls_key, slot, hash, (ushort)epoch->rank, self->shred_version );
      push_vote( self, vote, SAFE_TO_NOTAR );
    }
    try_skip_window( self, slot, SAFE_TO_NOTAR );
    state_mut( self, slot )->bad_window = 1;
    break;
  }

  case FD_VOTOR_POOL_EVENT_SAFE_TO_SKIP: {
    ulong                   slot  = event->safe_to_skip;
    /* No fallback vote at or below the vote bound. */
    if( FD_UNLIKELY( below_failover_vote_bound( self, slot ) ) ) { try_skip_window( self, slot, SAFE_TO_SKIP ); break; }
    epoch_bls_key_t const * epoch = own_epoch( self, slot );
    if( FD_UNLIKELY( !epoch->has_bls_key ) ) break;
    if( FD_LIKELY( slot>=self->catchup_vote_slot ) ) {
      fd_vote_t vote = fd_vote_construct_skip_fallback( self->bls_sign_fn, self->bls_sign_ctx, epoch->bls_key, slot, (ushort)epoch->rank, self->shred_version );
      push_vote( self, vote, SAFE_TO_SKIP );
    }
    try_skip_window( self, slot, SAFE_TO_SKIP );
    state_mut( self, slot )->bad_window = 1;
    break;
  }

  case FD_VOTOR_POOL_EVENT_CERT_CREATED:
    return handle_cert_created( self, &event->cert_created );

  default:
    FD_LOG_ERR(( "invalid pool event kind %d", event->kind ));
  }
  return NULL;
}

void
fd_votor_loop_process_replay( fd_votor_loop_t *       self,
                              ulong                   slot,
                              fd_block_info_t const * block_info ) {
  if( FD_UNLIKELY( slot<first_unpruned_slot( self ) || is_retired( self, slot ) ) ) return;

  if( FD_UNLIKELY( has_voted( self, slot ) ) ) {
    FD_LOG_WARNING(( "not voting for block in slot %lu, already voted", slot ));
    return;
  }
  if( FD_LIKELY( try_notar( self, slot, block_info, BLOCK_REPLAYED ) ) ) {
    check_pending_blocks( self, BLOCK_REPLAYED );
  } else {
    slot_state_ele_t * state  = state_mut( self, slot );
    if( FD_LIKELY( !state->pending_block ) ) pending_dlist_ele_push_tail( self->pending_dlist, state, self->slot_states->pool );
    state->pending_block      = 1;
    state->pending_block_info = *block_info;
  }
}

ulong
fd_votor_loop_advance_cert_wmark( fd_votor_loop_t * self,
                                  ulong             cert_slot,
                                  int               final ) {
  ulong slot = fd_ulong_max( fd_ulong_sat_sub( cert_slot+1UL, self->slot_max ), fd_ulong_if( final, fd_ulong_sat_sub( cert_slot+1UL, FD_VOTOR_REWARD_SLOT_DELTA ), 0UL ) );
  self->catchup_vote_slot = fd_ulong_max( self->catchup_vote_slot, slot );
  return self->catchup_vote_slot;
}

void
fd_votor_loop_handle_skip_timeout( fd_votor_loop_t * self,
                                   ulong             slot ) {
  if( FD_UNLIKELY( slot<first_unpruned_slot( self ) || is_retired( self, slot ) ) ) return;

  if( FD_UNLIKELY( !has_voted( self, slot ) ) ) try_skip_window( self, slot, TIMEOUT );
}

int
fd_votor_loop_poll_skip_timeout( fd_votor_loop_t * self,
                                 long              now,
                                 ulong *           slot ) {
  self->now = now;

  slot_state_ele_t * ele = next_timeout( self );
  if( FD_LIKELY( !ele || ele->timeout>now ) ) return 0;
  timeout_dlist_ele_remove( self->timeout_dlist[ ele->slot%FD_VOTOR_SLOTS_PER_WINDOW ], ele, self->slot_states->pool );
  ele->timeout = LONG_MAX;

  *slot = ele->slot;
  return 1;
}

FD_FN_PURE long
fd_votor_loop_next_skip_timeout( fd_votor_loop_t const * self ) {
  slot_state_ele_t const * head = next_timeout( self );
  return head ? head->timeout : LONG_MAX;
}

int
fd_votor_loop_poll_vote( fd_votor_loop_t * self,
                         fd_vote_t *       vote,
                         uchar *           reason ) {
  if( FD_LIKELY( vote_events_empty( self->vote_events ) ) ) return 0;
  vote_event_t event = vote_events_pop( self->vote_events );
  *vote   = event.vote;
  *reason = event.reason;
  return 1;
}

/* advance_root raises the finality anchor to slot and prunes below it, if
   slot is past the anchor. */

static void
advance_root( fd_votor_loop_t * self,
              ulong             slot ) {
  if( FD_UNLIKELY( self->highest_final_slot==ULONG_MAX || slot<=self->highest_final_slot ) ) return;
  self->highest_final_slot = slot;
  self->highest_final_ts   = self->now;
  prune( self );
}

void
fd_votor_loop_failover_set_vote_bound( fd_votor_loop_t * self,
                                       ulong             bound ) {
  self->failover_vote_bound = self->failover_vote_bound==ULONG_MAX ? bound : fd_ulong_max( self->failover_vote_bound, bound );
}

ulong
fd_votor_loop_failover_get_vote_bound( fd_votor_loop_t const * self ) {
  return self->failover_vote_bound;
}

int
fd_votor_loop_failover_hist_export( fd_votor_loop_t * self,
                                    ulong             last_leader_slot,
                                    fd_votor_hist_t * out ) {
  out->last_leader_slot = last_leader_slot;
  out->vote_bound       = self->failover_vote_bound;
  out->rec_cnt          = 0UL;
  if( FD_UNLIKELY( self->highest_final_slot==ULONG_MAX ) ) {
    out->anchor = 0UL;
    return 0;
  }

  slot_state_map_t * map   = self->slot_states->map;
  slot_state_ele_t * pool  = self->slot_states->pool;
  ulong *            slots = self->scratch.slots;
  ulong              first = first_unpruned_slot( self );
  ulong              cnt   = 0UL;
  for( slot_state_map_iter_t iter = slot_state_map_iter_init( map, pool );
                                   !slot_state_map_iter_done( iter, map, pool );
                             iter = slot_state_map_iter_next( iter, map, pool ) ) {
    slot_state_ele_t const * ele = slot_state_map_iter_ele_const( iter, map, pool );
    if( FD_LIKELY( ele->voted && ele->slot>=first && cnt<self->slot_max ) ) slots[ cnt++ ] = ele->slot;
  }
  slot_sort_inplace( slots, cnt );

  /* If there are too many voted slots, we drop whole windows from the
     bottom and raise the anchor past them. */
  ulong lo = 0UL;
  while( cnt-lo>FD_VOTOR_HIST_MAX ) {
    ulong next_window = fd_first_slot_in_window( slots[ lo ] )+FD_VOTOR_SLOTS_PER_WINDOW;
    while( lo<cnt && slots[ lo ]<next_window ) lo++;
  }
  int truncated = lo>0UL;
  out->anchor = self->highest_final_slot;
  if( FD_UNLIKELY( truncated ) ) out->anchor = fd_ulong_max( out->anchor, fd_first_slot_in_window( slots[ lo ] )+FD_VOTOR_REWARD_SLOT_DELTA );

  for( ulong i=lo; i<cnt; i++ ) {
    slot_state_ele_t const * ele = slot_state_map_ele_query_const( map, &slots[ i ], NULL, pool );
    fd_votor_hist_rec_t *    rec = &out->rec[ out->rec_cnt++ ];
    rec->slot  = ele->slot;
    rec->flags = (uchar)( FD_VOTOR_HIST_FLAG_VOTED |
                          fd_uint_if( ele->voted_notar, FD_VOTOR_HIST_FLAG_VOTED_NOTAR, 0U ) |
                          fd_uint_if( ele->bad_window,  FD_VOTOR_HIST_FLAG_BAD_WINDOW,  0U ) |
                          fd_uint_if( ele->retired,     FD_VOTOR_HIST_FLAG_RETIRED,     0U ) );
    if( ele->voted_notar ) fd_memcpy( &rec->notar_hash, &ele->voted_notar_hash, sizeof(fd_block_hash_t) );
    else                   fd_memset( &rec->notar_hash, 0,                      sizeof(fd_block_hash_t) );
  }
  return truncated;
}

ulong
fd_votor_loop_failover_hist_adopt( fd_votor_loop_t *       self,
                                   fd_votor_hist_t const * hist ) {

  /* Dry-run: */

  slot_state_map_t * map   = self->slot_states->map;
  slot_state_ele_t * pool  = self->slot_states->pool;
  ulong              first = fd_votor_hist_first_slot( fd_ulong_max( self->highest_final_slot, hist->anchor ) );
  ulong              free  = slot_state_pool_free( pool );
  if( hist->anchor>self->highest_final_slot ) {
    for( slot_state_map_iter_t iter = slot_state_map_iter_init( map, pool );
                                     !slot_state_map_iter_done( iter, map, pool );
                               iter = slot_state_map_iter_next( iter, map, pool ) ) {
      ulong slot = slot_state_map_iter_ele_const( iter, map, pool )->slot;
      free += slot>=self->root && slot<first;
    }
  }
  /* Account for exactly what advance_root prunes before changing state. */
  for( ulong i=0UL; i<hist->rec_cnt; i++ ) {
    ulong slot = hist->rec[ i ].slot;
    if( slot<first || slot_state_map_ele_query_const( map, &slot, NULL, pool ) ) continue;
    if( FD_UNLIKELY( !free ) ) return ULONG_MAX;
    free--;
  }

  /* A newer anchor prunes the skip timeouts of the windows below it. */
  int set_anchor_timeouts = hist->anchor>self->highest_final_slot && next_timeout( self );
  if( set_anchor_timeouts ) {
    for( ulong s=fd_first_slot_in_window( hist->anchor ); s<fd_first_slot_in_window( hist->anchor )+FD_VOTOR_SLOTS_PER_WINDOW; s++ ) {
      if( slot_state_map_ele_query_const( map, &s, NULL, pool ) ) continue;
      int imported = 0;
      for( ulong i=0UL; i<hist->rec_cnt; i++ ) imported |= hist->rec[ i ].slot==s;
      if( imported ) continue;
      if( FD_UNLIKELY( !free ) ) return ULONG_MAX;
      free--;
    }
  }

  /* Mutation: */

  advance_root( self, hist->anchor );
  if( set_anchor_timeouts ) set_timeouts( self, fd_first_slot_in_window( hist->anchor ) );
  /* Later pruning must visit records imported below the startup cursor. */
  self->root = fd_ulong_min( self->root, first );
  /* Take the exporter's vote bound as well. */
  if( FD_UNLIKELY( hist->vote_bound!=ULONG_MAX ) ) fd_votor_loop_failover_set_vote_bound( self, hist->vote_bound );
  ulong conflicts = 0UL;
  for( ulong i=0UL; i<hist->rec_cnt; i++ ) {
    fd_votor_hist_rec_t const * rec = &hist->rec[ i ];
    if( FD_UNLIKELY( rec->slot<first ) ) continue;
    slot_state_ele_t * state = state_mut( self, rec->slot );
    if( rec->flags & FD_VOTOR_HIST_FLAG_VOTED_NOTAR ) {
      if( FD_UNLIKELY( state->voted_notar && !fd_memeq( &state->voted_notar_hash, &rec->notar_hash, sizeof(fd_block_hash_t) ) ) ) conflicts++;
      state->voted_notar = 1;
      fd_memcpy( &state->voted_notar_hash, &rec->notar_hash, sizeof(fd_block_hash_t) );
    }
    if( !state->voted ) {
      if( FD_UNLIKELY( state->pending_block ) ) pending_dlist_ele_remove( self->pending_dlist, state, self->slot_states->pool );
      state->pending_block = 0;
      state->voted         = 1;
    }
    state->bad_window |= !!( rec->flags & FD_VOTOR_HIST_FLAG_BAD_WINDOW );
    state->retired    |= !!( rec->flags & FD_VOTOR_HIST_FLAG_RETIRED    );
  }
  return conflicts;
}
