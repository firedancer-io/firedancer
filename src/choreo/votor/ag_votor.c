#include "ag_votor.h"

struct vote_event {
  uchar     reason;
  ag_vote_t vote;
};
typedef struct vote_event vote_event_t;

#define QUEUE_NAME vote_events
#define QUEUE_T    vote_event_t
#include "../../util/tmpl/fd_queue_dynamic.c"

#define QUEUE_NAME cert_events
#define QUEUE_T    ag_cert_t
#include "../../util/tmpl/fd_queue_dynamic.c"

/* AG_VOTOR_SLOT_VOTE_MAX bounds the distinct votes votor casts in a
   slot: a notar or skip, a final, the notar fallbacks and a skip
   fallback. */

#define AG_VOTOR_SLOT_VOTE_MAX (2UL+AG_EQVOC_BLOCK_HASH_MAX+1UL)

struct slot_state_ele {
  ulong slot;
  ulong next;

  int             voted;
  int             voted_notar;
  ag_block_hash_t voted_notar_hash;
  int             bad_window;
  int             block_notarized;
  ag_block_hash_t block_notarized_hash;
  int             pending_block;
  ag_block_info_t pending_block_info;
  int             retired;

  uchar           vote_cnt; /* votes cast in this slot, for the vote history file */
  uchar           vote_kind[ AG_VOTOR_SLOT_VOTE_MAX ];
  ag_block_hash_t vote_hash[ AG_VOTOR_SLOT_VOTE_MAX ]; /* notar and notar fallback */

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
#define MAP_KEY_HASH(key,seed) (fd_ulong_hash( (*(key)) ^ (seed) ))
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
  uchar bls_key[ FD_BLS_PUB_COMPRESSED_SZ ];
  int   has_bls_key;
};
typedef struct epoch_bls_key epoch_bls_key_t;

struct __attribute__((aligned(128UL))) ag_votor {
  ulong          slot_max;
  long           now;
  ulong          root;
  ushort         shred_version;
  long           ns_per_slot;
  fd_bls_sign_fn bls_sign_fn;
  void *         bls_sign_ctx;

  slot_states_t *             slot_states;
  ag_parent_ready_tracker_t * parent_ready_tracker; /* Definition 15 over the certs received */
  ulong           highest_final_cert_slot;
  ulong           wait_to_vote_slot; /* sign no votes in slots below this */

  epoch_bls_key_t prev_epoch;
  epoch_bls_key_t curr_epoch;
  epoch_bls_key_t next_epoch;

  vote_event_t *    vote_events;
  ag_cert_t *       cert_events;
  pending_dlist_t * pending_dlist;
  timeout_dlist_t * timeout_dlist[ AG_SLOTS_PER_WINDOW ];

  struct {
    ulong *             slots;
    ag_parent_ready_t * parent_readys;
  } scratch;
};

FD_FN_PURE static inline int
timer_idle( slot_state_ele_t const * ele ) {
  return ele->timeout==LONG_MAX;
}

static slot_state_ele_t *
state_mut( ag_votor_t * self,
           ulong        slot ) {
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
push_vote( ag_votor_t * self,
           ag_vote_t    vote,
           uchar        reason ) {
  FD_TEST( !vote_events_full( self->vote_events ) );
  vote_events_push( self->vote_events, (vote_event_t){ .reason = reason, .vote = vote } );

  slot_state_ele_t * state = state_mut( self, ag_vote_slot( &vote ) );
  uchar const *      hash  = ag_block_hash_null;
  if( vote.kind==AG_VOTE_KIND_NOTAR          ) hash = vote.notar.block_hash;
  if( vote.kind==AG_VOTE_KIND_NOTAR_FALLBACK ) hash = vote.notar_fallback.block_hash;
  for( ulong i=0UL; i<state->vote_cnt; i++ ) {
    if( state->vote_kind[ i ]==vote.kind && !memcmp( state->vote_hash[ i ], hash, sizeof(ag_block_hash_t) ) ) return;
  }
  FD_TEST( state->vote_cnt<AG_VOTOR_SLOT_VOTE_MAX );
  state->vote_kind[ state->vote_cnt ] = (uchar)vote.kind;
  memcpy( state->vote_hash[ state->vote_cnt ], hash, sizeof(ag_block_hash_t) );
  state->vote_cnt++;
}

/* A slot's deadline is now plus an offset fixed by its position in the
   window, so each position's list fills in deadline order and its head
   is its earliest timer.  The walk back from the tail only runs if the
   slot length changed (block duration feature activation), or the clock
   stepped back. */

static void
set_timeout( ag_votor_t *       self,
             slot_state_ele_t * ele,
             long               deadline ) {
  timeout_dlist_t *  list = self->timeout_dlist[ ele->slot%AG_SLOTS_PER_WINDOW ];
  slot_state_ele_t * pool = self->slot_states->pool;
  if( FD_LIKELY( !timer_idle( ele ) ) ) {
    if( FD_LIKELY( ele->timeout<=deadline ) ) return;
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

/* No crashed-leader timeout.  Agave tracks one, but with
   delta_first_fec_set = delta_block its deadline lands on the first
   slot's timeout, so it never skips a window earlier. */

static void
set_timeouts( ag_votor_t * self,
              ulong        slot ) {
  FD_TEST( ag_is_start_of_window( slot ) );

  long deadline = self->now + AG_DELTA_TIMEOUT_NS + self->ns_per_slot;

  for( ulong s=slot; s<slot+AG_SLOTS_PER_WINDOW; s++ ) {
    deadline += fd_long_if( ag_is_start_of_window( s ), 0L, self->ns_per_slot );
    set_timeout( self, state_mut( self, s ), deadline );
  }
}

static slot_state_ele_t *
timeout_head( ag_votor_t const * self ) {
  slot_state_ele_t * pool = self->slot_states->pool;
  slot_state_ele_t * head = NULL;
  for( ulong k=0UL; k<AG_SLOTS_PER_WINDOW; k++ ) {
    if( FD_LIKELY( timeout_dlist_is_empty( self->timeout_dlist[ k ], pool ) ) ) continue;
    slot_state_ele_t * ele = timeout_dlist_ele_peek_head( self->timeout_dlist[ k ], pool );
    if( !head || ele->timeout<head->timeout ) head = ele;
  }
  return head;
}

ulong
ag_votor_align( void ) {
  return alignof(ag_votor_t);
}

ulong
ag_votor_footprint( ulong slot_max ) {
  if( FD_UNLIKELY( slot_max<AG_SLOTS_PER_WINDOW ) ) return 0UL;
  ulong events_max = slot_max*( AG_NOTAR_FALLBACK_CERT_MAX + 1UL /* notar */ + 1UL /* skip */ ); /* a standstill bundle, see ag_pool_footprint */
  ulong slot_state_chain_cnt = slot_state_map_chain_cnt_est( slot_max );
  ulong ready_max            = slot_max + 2UL*AG_SLOTS_PER_WINDOW + 1UL; /* see ag_pool_footprint, plus the window below first_unpruned_slot */
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
    FD_LAYOUT_INIT,
      alignof(ag_votor_t),      sizeof(ag_votor_t)                                ),
      alignof(slot_states_t),   sizeof(slot_states_t)                             ),
      slot_state_pool_align(),  slot_state_pool_footprint( slot_max )             ),
      slot_state_map_align(),   slot_state_map_footprint ( slot_state_chain_cnt ) ),
      pending_dlist_align(),    pending_dlist_footprint()                         ),
      timeout_dlist_align(),    timeout_dlist_footprint()*AG_SLOTS_PER_WINDOW     ),
      vote_events_align(),      vote_events_footprint( events_max )               ),
      cert_events_align(),      cert_events_footprint( events_max )               ),
      alignof(ulong),           sizeof(ulong)*slot_max                            ),
      ag_parent_ready_tracker_align(), ag_parent_ready_tracker_footprint( ready_max ) ),
      alignof(ag_parent_ready_t), sizeof(ag_parent_ready_t)*slot_max              ),
    ag_votor_align() );
}

void *
ag_votor_new( void * mem,
              ulong  slot_max,
              ulong  seed ) {
  if( FD_UNLIKELY( !mem ) ) {
    FD_LOG_WARNING(( "NULL mem" ));
    return NULL;
  }
  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)mem, ag_votor_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned mem" ));
    return NULL;
  }
  ulong footprint = ag_votor_footprint( slot_max );
  if( FD_UNLIKELY( !footprint ) ) {
    FD_LOG_WARNING(( "bad slot_max (%lu)", slot_max ));
    return NULL;
  }
  fd_memset( mem, 0, footprint );

  ulong events_max           = slot_max*( AG_NOTAR_FALLBACK_CERT_MAX + 1UL /* notar */ + 1UL /* skip */ );
  ulong slot_state_chain_cnt = slot_state_map_chain_cnt_est( slot_max );
  ulong ready_max            = slot_max + 2UL*AG_SLOTS_PER_WINDOW + 1UL;

  FD_SCRATCH_ALLOC_INIT( l, mem );
  ag_votor_t * votor            = FD_SCRATCH_ALLOC_APPEND( l, alignof(ag_votor_t),      sizeof(ag_votor_t)                                );
  void *       slot_states      = FD_SCRATCH_ALLOC_APPEND( l, alignof(slot_states_t),   sizeof(slot_states_t)                             );
  void *       slot_state_pool  = FD_SCRATCH_ALLOC_APPEND( l, slot_state_pool_align(),  slot_state_pool_footprint( slot_max )             );
  void *       slot_state_map   = FD_SCRATCH_ALLOC_APPEND( l, slot_state_map_align(),   slot_state_map_footprint ( slot_state_chain_cnt ) );
  void *       pending_dlist    = FD_SCRATCH_ALLOC_APPEND( l, pending_dlist_align(),    pending_dlist_footprint()                         );
  uchar *      timeout_dlist    = FD_SCRATCH_ALLOC_APPEND( l, timeout_dlist_align(),    timeout_dlist_footprint()*AG_SLOTS_PER_WINDOW     );
  void *       vote_events      = FD_SCRATCH_ALLOC_APPEND( l, vote_events_align(),      vote_events_footprint( events_max )               );
  void *       cert_events      = FD_SCRATCH_ALLOC_APPEND( l, cert_events_align(),      cert_events_footprint( events_max )               );
  void *       slot_scratch     = FD_SCRATCH_ALLOC_APPEND( l, alignof(ulong),           sizeof(ulong)*slot_max                            );
  void *       ready_tracker    = FD_SCRATCH_ALLOC_APPEND( l, ag_parent_ready_tracker_align(), ag_parent_ready_tracker_footprint( ready_max ) );
  void *       ready_scratch    = FD_SCRATCH_ALLOC_APPEND( l, alignof(ag_parent_ready_t), sizeof(ag_parent_ready_t)*slot_max              );
  FD_TEST( FD_SCRATCH_ALLOC_FINI( l, ag_votor_align() ) == (ulong)mem + footprint );

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
  votor->highest_final_cert_slot = ULONG_MAX;
  votor->wait_to_vote_slot       = 0UL;
  votor->prev_epoch              = (epoch_bls_key_t){ .start_slot = ULONG_MAX, .rank = USHORT_MAX };
  votor->curr_epoch              = (epoch_bls_key_t){ .start_slot = ULONG_MAX, .rank = USHORT_MAX };
  votor->next_epoch              = (epoch_bls_key_t){ .start_slot = ULONG_MAX, .rank = USHORT_MAX };
  votor->vote_events             = vote_events_join( vote_events_new( vote_events, events_max ) );
  votor->cert_events             = cert_events_join( cert_events_new( cert_events, events_max ) );
  votor->pending_dlist           = pending_dlist_join( pending_dlist_new( pending_dlist ) );
  for( ulong k=0UL; k<AG_SLOTS_PER_WINDOW; k++ ) votor->timeout_dlist[ k ] = timeout_dlist_join( timeout_dlist_new( timeout_dlist+k*timeout_dlist_footprint() ) );
  votor->scratch.slots           = (ulong *)slot_scratch;
  votor->parent_ready_tracker    = ag_parent_ready_tracker_join( ag_parent_ready_tracker_new( ready_tracker, ready_max, seed ) );
  votor->scratch.parent_readys   = (ag_parent_ready_t *)ready_scratch;

  return mem;
}

ag_votor_t *
ag_votor_join( void * mem ) {
  ag_votor_t * votor = (ag_votor_t *)mem;
  if( FD_UNLIKELY( !votor ) ) {
    FD_LOG_WARNING(( "NULL mem" ));
    return NULL;
  }
  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)votor, ag_votor_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned mem" ));
    return NULL;
  }
  return votor;
}

void *
ag_votor_leave( ag_votor_t const * votor ) {
  if( FD_UNLIKELY( !votor ) ) {
    FD_LOG_WARNING(( "NULL votor" ));
    return NULL;
  }
  return (void *)votor;
}

void *
ag_votor_delete( void * mem ) {
  if( FD_UNLIKELY( !mem ) ) {
    FD_LOG_WARNING(( "NULL mem" ));
    return NULL;
  }
  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)mem, ag_votor_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned mem" ));
    return NULL;
  }
  return mem;
}

void
ag_votor_init( ag_votor_t *          self,
               ag_block_id_t const * root,
               long                  now,
               long                  ns_per_slot,
               ushort                shred_version,
               fd_bls_sign_fn        sign_fn,
               void *                sign_ctx ) {
  FD_TEST( sign_fn );
  ulong slot = root->slot;
  self->now                     = now;
  self->root                    = slot;
  self->shred_version           = shred_version;
  self->ns_per_slot             = ns_per_slot;
  self->bls_sign_fn             = sign_fn;
  self->bls_sign_ctx            = sign_ctx;

  slot_state_ele_t * state       = state_mut( self, slot );
  state->voted                   = 1;
  state->voted_notar             = 1;
  state->block_notarized         = 1;
  state->retired                 = 1;
  memcpy( state->voted_notar_hash,     root->hash, sizeof(ag_block_hash_t) );
  memcpy( state->block_notarized_hash, root->hash, sizeof(ag_block_hash_t) );

  for( ulong s=ag_first_slot_in_window( slot ); s<slot; s++ ) {
    slot_state_ele_t * below = state_mut( self, s );
    below->voted               = 1;
    below->retired             = 1;
  }

  self->highest_final_cert_slot = slot;

  ulong ready_cnt;
  self->parent_ready_tracker->root = fd_ulong_sat_sub( ag_first_slot_in_window( fd_ulong_sat_sub( slot, AG_REWARD_SLOT_DELTA ) ), AG_SLOTS_PER_WINDOW );
  ag_parent_ready_tracker_mark_notar_fallback( self->parent_ready_tracker, root, self->scratch.parent_readys, &ready_cnt );
  for( ulong i=0UL; i<ready_cnt; i++ ) ag_parent_ready_tracker_delivered( self->parent_ready_tracker, self->scratch.parent_readys[i].slot );

  set_timeouts( self, ag_first_slot_in_window( slot ) );
}

void
ag_votor_fini( ag_votor_t * self ) {
  self->root                    = ULONG_MAX;
  self->highest_final_cert_slot = ULONG_MAX;
}

FD_FN_PURE ag_votor_metrics_t
ag_votor_metrics( ag_votor_t const * self ) {
  return (ag_votor_metrics_t){
    .slot_state_pool_used    = slot_state_pool_used( self->slot_states->pool ),
    .slot_state_pool_free    = slot_state_pool_free( self->slot_states->pool ),
    .highest_final_cert_slot = self->highest_final_cert_slot,
    .vote_events_cnt         = vote_events_cnt( self->vote_events )
  };
}

FD_FN_PURE static epoch_bls_key_t const *
own_epoch( ag_votor_t const * self,
           ulong              slot ) {
  if( FD_UNLIKELY( slot>=self->next_epoch.start_slot ) ) return &self->next_epoch;
  if( FD_LIKELY( slot>=self->curr_epoch.start_slot ) ) return &self->curr_epoch;
  return &self->prev_epoch;
}

FD_FN_PURE static int
is_retired( ag_votor_t const * self,
            ulong              slot ) {
  slot_state_ele_t const * ele = slot_state_map_ele_query_const( self->slot_states->map, &slot, NULL, self->slot_states->pool );
  return ele && ele->retired;
}

FD_FN_PURE static int
has_voted( ag_votor_t const * self,
           ulong              slot ) {
  slot_state_ele_t const * ele = slot_state_map_ele_query_const( self->slot_states->map, &slot, NULL, self->slot_states->pool );
  return ele && ele->voted;
}

FD_FN_PURE static ulong
first_unpruned_slot( ag_votor_t const * self ) {
  return ag_first_slot_in_window( fd_ulong_sat_sub( self->highest_final_cert_slot, AG_REWARD_SLOT_DELTA ) );
}

static int
should_ignore_pool_event( ag_votor_t const *      self,
                          ag_pool_event_t const * event ) {
  ulong slot;
  switch( event->kind ) {
  case AG_POOL_EVENT_PARENT_READY:  slot = event->parent_ready.slot;             break;
  case AG_POOL_EVENT_SAFE_TO_NOTAR: slot = event->safe_to_notar.slot;            break;
  case AG_POOL_EVENT_SAFE_TO_SKIP:  slot = event->safe_to_skip;                  break;
  case AG_POOL_EVENT_CERT_CREATED:  slot = ag_cert_slot( &event->cert_created ); break;
  case AG_POOL_EVENT_STANDSTILL:    slot = event->standstill.slot;               break;
  default:                          FD_LOG_CRIT(( "unreachable" ));
  }
  switch( event->kind ) {
  case AG_POOL_EVENT_STANDSTILL:    return 0;
  case AG_POOL_EVENT_CERT_CREATED:  return slot<first_unpruned_slot( self );
  case AG_POOL_EVENT_PARENT_READY:
  case AG_POOL_EVENT_SAFE_TO_NOTAR:
  case AG_POOL_EVENT_SAFE_TO_SKIP:  return slot<first_unpruned_slot( self ) || is_retired( self, slot );
  default:                          FD_LOG_CRIT(( "unreachable" ));
  }
}

static void
try_final( ag_votor_t *          self,
           ulong                 slot,
           ag_block_hash_t const hash ) {
  FD_TEST( slot>=first_unpruned_slot( self ) );
  epoch_bls_key_t const * epoch = own_epoch( self, slot );

  slot_state_ele_t const * state = slot_state_map_ele_query_const( self->slot_states->map, &slot, NULL, self->slot_states->pool );
  int notarized   = state && state->block_notarized && !memcmp( state->block_notarized_hash, hash, sizeof(ag_block_hash_t) );
  int voted_notar = state && state->voted_notar     && !memcmp( state->voted_notar_hash,     hash, sizeof(ag_block_hash_t) );
  int not_bad     = !( state && state->bad_window );
  if( FD_LIKELY( notarized && voted_notar && not_bad ) ) {
    state_mut( self, slot )->retired = 1;
    if( FD_UNLIKELY( !epoch->has_bls_key || slot<self->wait_to_vote_slot ) ) return;
    ag_vote_t vote = ag_vote_construct_final( self->bls_sign_fn, self->bls_sign_ctx, epoch->bls_key, slot, (ushort)epoch->rank, self->shred_version );
    push_vote( self, vote, AG_VOTOR_REASON_BLOCK_NOTARIZED );
  }
}

static int
try_notar( ag_votor_t *            self,
           ulong                   slot,
           ag_block_info_t const * block_info,
           uchar                   reason ) {
  FD_TEST( slot>=first_unpruned_slot( self ) );
  epoch_bls_key_t const * epoch = own_epoch( self, slot );
  if( FD_UNLIKELY( has_voted( self, slot ) ) ) return 0;

  ag_block_hash_t hash;
  memcpy( hash, block_info->hash, sizeof(ag_block_hash_t) );
  ag_block_id_t parent = block_info->parent;

  if( FD_UNLIKELY( ag_is_start_of_window( slot ) ) ) {
    if( FD_UNLIKELY( !ag_parent_ready_tracker_is_parent_ready( self->parent_ready_tracker, slot, &parent ) ) ) return 0;
  } else {
    if( FD_UNLIKELY( parent.slot!=slot-1UL ) ) return 0;
    slot_state_ele_t const * parent_state = slot_state_map_ele_query_const( self->slot_states->map, &parent.slot, NULL, self->slot_states->pool );
    if( FD_UNLIKELY( !parent_state || !parent_state->voted_notar                                      ) ) return 0;
    if( FD_UNLIKELY( memcmp( parent_state->voted_notar_hash, parent.hash, sizeof(ag_block_hash_t) )!=0 ) ) return 0;
  }

  if( FD_LIKELY( epoch->has_bls_key && slot>=self->wait_to_vote_slot ) ) {
    ag_vote_t vote = ag_vote_construct_notar( self->bls_sign_fn, self->bls_sign_ctx, epoch->bls_key, slot, hash, (ushort)epoch->rank, self->shred_version );
    push_vote( self, vote, reason );
  }

  slot_state_ele_t * state = state_mut( self, slot );
  if( FD_UNLIKELY( state->pending_block ) ) pending_dlist_ele_remove( self->pending_dlist, state, self->slot_states->pool );
  state->voted         = 1;
  state->voted_notar   = 1;
  state->pending_block = 0;
  memcpy( state->voted_notar_hash, hash, sizeof(ag_block_hash_t) );

  try_final( self, slot, hash );
  return 1;
}

static void
try_skip_window( ag_votor_t * self,
                 ulong        slot,
                 uchar        reason ) {
  FD_TEST( slot>=first_unpruned_slot( self ) );

  ulong window_start = ag_first_slot_in_window( slot );
  for( ulong s=window_start; s<window_start+AG_SLOTS_PER_WINDOW; s++ ) {
    if( FD_UNLIKELY( has_voted( self, s ) ) ) continue;

    slot_state_ele_t * state = state_mut( self, s );
    state->voted             = 1;
    state->bad_window        = 1;

    epoch_bls_key_t const * epoch = own_epoch( self, s );
    if( FD_UNLIKELY( !epoch->has_bls_key || s<self->wait_to_vote_slot ) ) continue;

    ag_vote_t vote = ag_vote_construct_skip( self->bls_sign_fn, self->bls_sign_ctx, epoch->bls_key, s, (ushort)epoch->rank, self->shred_version );
    push_vote( self, vote, reason );
  }
}

static void
check_pending_blocks( ag_votor_t * self,
                      uchar        reason ) {
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
prune( ag_votor_t * self ) {
  ulong first_unpruned = first_unpruned_slot( self );
  for( ulong slot=self->root; slot<first_unpruned; slot++ ) {
    slot_state_ele_t * ele = slot_state_map_ele_remove( self->slot_states->map, &slot, NULL, self->slot_states->pool );
    if( FD_LIKELY( ele ) ) {
      if( FD_UNLIKELY( ele->pending_block   ) ) pending_dlist_ele_remove( self->pending_dlist, ele, self->slot_states->pool );
      if( FD_LIKELY  ( !timer_idle( ele )   ) ) timeout_dlist_ele_remove( self->timeout_dlist[ slot%AG_SLOTS_PER_WINDOW ], ele, self->slot_states->pool );
      slot_state_pool_ele_release( self->slot_states->pool, ele );
    }
  }
  self->root = first_unpruned;
  ag_parent_ready_tracker_prune( self->parent_ready_tracker, fd_ulong_sat_sub( first_unpruned, AG_SLOTS_PER_WINDOW ) ); /* parents of the window at first_unpruned */
}

static void
handle_cert_created( ag_votor_t *      self,
                     ag_cert_t const * cert ) {
  ulong slot = ag_cert_slot( cert );

  switch( cert->kind ) {

  case AG_CERT_KIND_FINAL:
  case AG_CERT_KIND_FAST_FINAL:
    set_timeouts( self, ag_first_slot_in_window( slot ) );

    self->highest_final_cert_slot = fd_ulong_max( self->highest_final_cert_slot, slot );
    prune( self );
    break;

  case AG_CERT_KIND_NOTAR: {
    uchar const * hash = ag_cert_block_hash( cert );

    slot_state_ele_t * state = state_mut( self, slot );
    state->block_notarized   = 1;
    memcpy( state->block_notarized_hash, hash, sizeof(ag_block_hash_t) );

    try_final( self, slot, hash );
    break;
  }

  case AG_CERT_KIND_NOTAR_FALLBACK:
  case AG_CERT_KIND_SKIP:
    break;

  default:
    FD_LOG_CRIT(( "unreachable" ));
  }

  FD_TEST( !cert_events_full( self->cert_events ) );
  cert_events_push( self->cert_events, *cert );
}

void
ag_votor_advance_epoch( ag_votor_t *       self,
                        long               ns_per_slot,
                        ulong              epoch_rank,
                        ulong              epoch_slot,
                        ag_bls_key_t const bls_key ) {
  epoch_bls_key_t epoch = { .start_slot = epoch_slot, .rank = epoch_rank, .has_bls_key = !!bls_key };
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
  self->ns_per_slot = ns_per_slot;
}

static epoch_bls_key_t *
epoch_starting_at( ag_votor_t * self,
                   ulong        epoch_slot ) {
  if( epoch_slot==self->prev_epoch.start_slot ) return &self->prev_epoch;
  if( epoch_slot==self->curr_epoch.start_slot ) return &self->curr_epoch;
  if( epoch_slot==self->next_epoch.start_slot ) return &self->next_epoch;
  FD_LOG_CRIT(( "no epoch starts at slot %lu", epoch_slot ));
}

void
ag_votor_set_bls_key( ag_votor_t *       self,
                      ulong              epoch_slot,
                      ag_bls_key_t const bls_key ) {
  epoch_bls_key_t * epoch = epoch_starting_at( self, epoch_slot );
  epoch->has_bls_key = !!bls_key;
  if( FD_LIKELY( bls_key ) ) memcpy( epoch->bls_key, bls_key, FD_BLS_PUB_COMPRESSED_SZ );
}

void
ag_votor_set_rank( ag_votor_t * self,
                   ulong        epoch_slot,
                   ulong        epoch_rank ) {
  epoch_starting_at( self, epoch_slot )->rank = epoch_rank;
}

void
ag_votor_wait_to_vote( ag_votor_t * self,
                       ulong        wait_to_vote_slot ) {
  self->wait_to_vote_slot = fd_ulong_max( self->wait_to_vote_slot, wait_to_vote_slot );
  slot_state_map_t const * map  = self->slot_states->map;
  slot_state_ele_t *       pool = self->slot_states->pool;
  for( slot_state_map_iter_t iter = slot_state_map_iter_init( map, pool );
                                   !slot_state_map_iter_done( iter, map, pool );
                             iter = slot_state_map_iter_next( iter, map, pool ) ) {
    slot_state_ele_t * state = slot_state_map_iter_ele( iter, map, pool );
    if( state->voted ) self->wait_to_vote_slot = fd_ulong_max( self->wait_to_vote_slot, ag_first_slot_in_window( state->slot )+AG_SLOTS_PER_WINDOW );
    state->vote_cnt = 0;
  }
}

void
ag_votor_handle_pool_event( ag_votor_t *            self,
                            ag_pool_event_t const * event,
                            long                    now ) {
  self->now = now;

  /* Definition 15 over the certs received, a fast-finalization cert is
     a notarization cert (Table 6).  Ahead of the ignore filter, a cert
     just below first_unpruned_slot can still ready its window start.  A
     window start that gains a ready parent may unblock a pending block. */

  if( FD_UNLIKELY( event->kind==AG_POOL_EVENT_CERT_CREATED ) ) {
    ag_cert_t const * cert      = &event->cert_created;
    ulong             ready_cnt = 0UL;
    switch( cert->kind ) {
    case AG_CERT_KIND_FINAL:          break;
    case AG_CERT_KIND_FAST_FINAL:
    case AG_CERT_KIND_NOTAR:
    case AG_CERT_KIND_NOTAR_FALLBACK: {
      ag_block_id_t block_id = ag_block_id( ag_cert_slot( cert ), ag_cert_block_hash( cert ) );
      ag_parent_ready_tracker_mark_notar_fallback( self->parent_ready_tracker, &block_id, self->scratch.parent_readys, &ready_cnt );
      break;
    }
    case AG_CERT_KIND_SKIP:           ag_parent_ready_tracker_mark_skipped( self->parent_ready_tracker, ag_cert_slot( cert ), self->scratch.parent_readys, &ready_cnt ); break;
    default:                          FD_LOG_CRIT(( "unreachable" ));
    }
    for( ulong i=0UL; i<ready_cnt; i++ ) ag_parent_ready_tracker_delivered( self->parent_ready_tracker, self->scratch.parent_readys[i].slot );
    if( FD_UNLIKELY( ready_cnt ) ) check_pending_blocks( self, AG_VOTOR_REASON_PARENT_READY );
  }

  if( FD_UNLIKELY( should_ignore_pool_event( self, event ) ) ) return;

  switch( event->kind ) {

  case AG_POOL_EVENT_PARENT_READY: {
    check_pending_blocks( self, AG_VOTOR_REASON_PARENT_READY );
    set_timeouts( self, event->parent_ready.slot );
    break;
  }

  case AG_POOL_EVENT_SAFE_TO_NOTAR: {
    ulong                   slot  = event->safe_to_notar.slot;
    uchar const *           hash  = event->safe_to_notar.hash;
    epoch_bls_key_t const * epoch = own_epoch( self, slot );
    if( FD_LIKELY( epoch->has_bls_key && slot>=self->wait_to_vote_slot ) ) {
      ag_vote_t vote = ag_vote_construct_notar_fallback( self->bls_sign_fn, self->bls_sign_ctx, epoch->bls_key, slot, hash, (ushort)epoch->rank, self->shred_version );
      push_vote( self, vote, AG_VOTOR_REASON_SAFE_TO_NOTAR );
    }
    try_skip_window( self, slot, AG_VOTOR_REASON_SAFE_TO_NOTAR );
    state_mut( self, slot )->bad_window = 1;
    break;
  }

  case AG_POOL_EVENT_SAFE_TO_SKIP: {
    ulong                   slot  = event->safe_to_skip;
    epoch_bls_key_t const * epoch = own_epoch( self, slot );
    if( FD_LIKELY( epoch->has_bls_key && slot>=self->wait_to_vote_slot ) ) {
      ag_vote_t vote = ag_vote_construct_skip_fallback( self->bls_sign_fn, self->bls_sign_ctx, epoch->bls_key, slot, (ushort)epoch->rank, self->shred_version );
      push_vote( self, vote, AG_VOTOR_REASON_SAFE_TO_SKIP );
    }
    try_skip_window( self, slot, AG_VOTOR_REASON_SAFE_TO_SKIP );
    state_mut( self, slot )->bad_window = 1;
    break;
  }

  case AG_POOL_EVENT_CERT_CREATED:
    handle_cert_created( self, &event->cert_created );
    break;

  case AG_POOL_EVENT_STANDSTILL: {
    ag_standstill_t const * standstill = &event->standstill;
    FD_TEST( cert_events_avail( self->cert_events )>=standstill->cert_cnt );
    for( ulong i=0UL; i<standstill->cert_cnt; i++ ) cert_events_push( self->cert_events, standstill->certs[i] );
    FD_TEST( vote_events_avail( self->vote_events )>=standstill->vote_cnt );
    for( ulong i=0UL; i<standstill->vote_cnt; i++ ) vote_events_push( self->vote_events, (vote_event_t){ .reason = UCHAR_MAX, .vote = standstill->votes[i] } );
    break;
  }

  default:
    FD_LOG_ERR(( "invalid pool event kind %d", event->kind ));
  }
}

void
ag_votor_process_replay( ag_votor_t *            self,
                         ulong                   slot,
                         ag_block_info_t const * block_info ) {
  if( FD_UNLIKELY( slot<first_unpruned_slot( self ) || is_retired( self, slot ) ) ) return;

  if( FD_UNLIKELY( has_voted( self, slot ) ) ) {
    FD_LOG_WARNING(( "not voting for block in slot %lu, already voted", slot ));
    return;
  }
  if( FD_LIKELY( try_notar( self, slot, block_info, AG_VOTOR_REASON_BLOCK_REPLAYED ) ) ) {
    check_pending_blocks( self, AG_VOTOR_REASON_BLOCK_REPLAYED );
  } else {
    slot_state_ele_t * state  = state_mut( self, slot );
    if( FD_LIKELY( !state->pending_block ) ) pending_dlist_ele_push_tail( self->pending_dlist, state, self->slot_states->pool );
    state->pending_block      = 1;
    state->pending_block_info = *block_info;
  }
}

void
ag_votor_handle_skip_timeout( ag_votor_t * self,
                              ulong        slot ) {
  if( FD_UNLIKELY( slot<first_unpruned_slot( self ) || is_retired( self, slot ) ) ) return;

  if( FD_UNLIKELY( !has_voted( self, slot ) ) ) try_skip_window( self, slot, AG_VOTOR_REASON_TIMEOUT );
}

int
ag_votor_poll_skip_timeout( ag_votor_t * self,
                            long         now,
                            ulong *      slot ) {
  self->now = now;

  slot_state_ele_t * ele = timeout_head( self );
  if( FD_LIKELY( !ele || ele->timeout>now ) ) return 0;
  timeout_dlist_ele_remove( self->timeout_dlist[ ele->slot%AG_SLOTS_PER_WINDOW ], ele, self->slot_states->pool );
  ele->timeout = LONG_MAX;

  *slot = ele->slot;
  return 1;
}

FD_FN_PURE long
ag_votor_next_skip_timeout( ag_votor_t const * self ) {
  slot_state_ele_t const * head = timeout_head( self );
  return head ? head->timeout : LONG_MAX;
}

int
ag_votor_poll_vote( ag_votor_t * self,
                    ag_vote_t *  vote,
                    uchar *      reason ) {
  if( FD_LIKELY( vote_events_empty( self->vote_events ) ) ) return 0;
  vote_event_t event = vote_events_pop( self->vote_events );
  *vote   = event.vote;
  *reason = event.reason;
  return 1;
}

int
ag_votor_poll_cert( ag_votor_t * self,
                    ag_cert_t *  cert ) {
  if( FD_LIKELY( cert_events_empty( self->cert_events ) ) ) return 0;
  *cert = cert_events_pop( self->cert_events );
  return 1;
}

int
ag_votor_vote_history( ag_votor_t const *       self,
                       ag_vote_history_file_t * out ) {
  static uchar const history_kind[] = {
    [ AG_VOTE_KIND_NOTAR          ] = AG_VOTE_HISTORY_KIND_NOTAR,
    [ AG_VOTE_KIND_FINAL          ] = AG_VOTE_HISTORY_KIND_FINAL,
    [ AG_VOTE_KIND_SKIP           ] = AG_VOTE_HISTORY_KIND_SKIP,
    [ AG_VOTE_KIND_NOTAR_FALLBACK ] = AG_VOTE_HISTORY_KIND_NOTAR_FALLBACK,
    [ AG_VOTE_KIND_SKIP_FALLBACK  ] = AG_VOTE_HISTORY_KIND_SKIP_FALLBACK,
  };
  uint const voted   = (1U<<AG_VOTE_KIND_NOTAR) | (1U<<AG_VOTE_KIND_SKIP);
  uint const skipped = (1U<<AG_VOTE_KIND_SKIP)  | (1U<<AG_VOTE_KIND_NOTAR_FALLBACK) | (1U<<AG_VOTE_KIND_SKIP_FALLBACK);

  ulong root = self->highest_final_cert_slot;
  FD_TEST( root!=ULONG_MAX ); /* initialized */

  slot_state_map_t const * map  = self->slot_states->map;
  slot_state_ele_t const * pool = self->slot_states->pool;
  ulong                    hi   = root;
  for( slot_state_map_iter_t iter = slot_state_map_iter_init( map, pool );
                                   !slot_state_map_iter_done( iter, map, pool );
                             iter = slot_state_map_iter_next( iter, map, pool ) ) {
    hi = fd_ulong_max( hi, slot_state_map_iter_ele_const( iter, map, pool )->slot );
  }

  out->root                     = root;
  out->voted_cnt                = 0UL;
  out->voted_skip_fallback_cnt  = 0UL;
  out->skipped_cnt              = 0UL;
  out->its_over_cnt             = 0UL;
  out->voted_notar_cnt          = 0UL;
  out->voted_notar_fallback_cnt = 0UL;
  out->notarized_blocks_cnt     = 0UL;
  out->parent_ready_cnt         = 0UL;
  out->votes_cast_cnt           = 0UL;

# define PUSH( arr, cnt, max, val ) do {                                    \
    if( FD_UNLIKELY( (cnt)>=(max) ) ) return AG_VOTE_HISTORY_FILE_ERR_FULL; \
    (arr)[ (cnt)++ ] = (val);                                               \
  } while(0)

  for( ulong slot=root; slot<=hi; slot++ ) {
    slot_state_ele_t const * s = slot_state_map_ele_query_const( map, &slot, NULL, pool );
    if( !s ) continue;

    uint cast = 0U; /* bit AG_VOTE_KIND_* of each kind cast in slot */
    for( ulong j=0UL; j<s->vote_cnt; j++ ) {
      uint                   kind  = s->vote_kind[ j ];
      ag_block_id_t          block = ag_block_id( slot, s->vote_hash[ j ] );           /* null hash but for notar and notar fallback */
      ag_vote_history_vote_t vote  = { .kind = history_kind[ kind ], .block = block }; /* shred_version 0, as Agave */
      PUSH( out->votes_cast, out->votes_cast_cnt, AG_VOTE_HISTORY_VOTE_MAX, vote );
      if( kind==AG_VOTE_KIND_NOTAR          ) PUSH( out->voted_notar,          out->voted_notar_cnt,          AG_VOTE_HISTORY_BLOCK_MAX, block );
      if( kind==AG_VOTE_KIND_NOTAR_FALLBACK ) PUSH( out->voted_notar_fallback, out->voted_notar_fallback_cnt, AG_VOTE_HISTORY_BLOCK_MAX, block );
      cast |= 1U<<kind;
    }
    if( cast & voted                            ) PUSH( out->voted,               out->voted_cnt,               AG_VOTE_HISTORY_SLOT_MAX, slot );
    if( cast & (1U<<AG_VOTE_KIND_SKIP_FALLBACK) ) PUSH( out->voted_skip_fallback, out->voted_skip_fallback_cnt, AG_VOTE_HISTORY_SLOT_MAX, slot );
    if( cast & skipped                          ) PUSH( out->skipped,             out->skipped_cnt,             AG_VOTE_HISTORY_SLOT_MAX, slot );
    if( cast & (1U<<AG_VOTE_KIND_FINAL)         ) PUSH( out->its_over,            out->its_over_cnt,            AG_VOTE_HISTORY_SLOT_MAX, slot );

    if( s->block_notarized ) PUSH( out->notarized_blocks, out->notarized_blocks_cnt, AG_VOTE_HISTORY_BLOCK_MAX, ag_block_id( slot, s->block_notarized_hash ) );
  }

# undef PUSH

  /* The ready parents of the window starts from root up to the one
     after the highest slot votor keeps state for */

  ag_block_id_t parents[ AG_VOTE_HISTORY_PARENT_READY_MAX ];
  for( ulong slot=ag_first_slot_in_window( root ); slot<=hi+AG_SLOTS_PER_WINDOW; slot+=AG_SLOTS_PER_WINDOW ) {
    if( slot<root ) continue;
    ulong cnt = ag_parent_ready_tracker_parents_ready( self->parent_ready_tracker, slot, parents, AG_VOTE_HISTORY_PARENT_READY_MAX );
    if( FD_UNLIKELY( cnt>AG_VOTE_HISTORY_PARENT_READY_MAX-out->parent_ready_cnt ) ) return AG_VOTE_HISTORY_FILE_ERR_FULL;
    for( ulong j=0UL; j<cnt; j++ ) out->parent_ready[ out->parent_ready_cnt++ ] = (ag_vote_history_parent_ready_t){ .slot = slot, .block = parents[ j ] };
  }

  return AG_VOTE_HISTORY_FILE_SUCCESS;
}
