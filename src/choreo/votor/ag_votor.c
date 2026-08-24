#include "ag_votor.h"

#define QUEUE_NAME vote_events
#define QUEUE_T    ag_event_vote_t
#include "../../util/tmpl/fd_queue_dynamic.c"

#define QUEUE_NAME cert_events
#define QUEUE_T    ag_event_cert_t
#include "../../util/tmpl/fd_queue_dynamic.c"

#define PARENTS_READY_MAX (AG_SLOTS_PER_WINDOW*AG_NOTAR_FALLBACK_CERT_MAX+1UL)

struct slot_state_ele {
  ulong slot;
  ulong next;

  int             voted;
  int             voted_notar;
  ag_block_hash_t voted_notar_hash;
  int             bad_window;
  int             block_notarized;
  ag_block_hash_t block_notarized_hash;
  ag_block_id_t   parents_ready[ PARENTS_READY_MAX ];
  ulong           parents_ready_cnt;
  int             received_shred;
  int             pending_block;
  ag_block_info_t pending_block_info;
  int             retired;

  long timeout;
  long timeout_crashed_leader;

  struct { ulong prev; ulong next; } pending_link;
  struct { ulong prev; ulong next; } timeout_link;
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
#define DLIST_PREV  pending_link.prev
#define DLIST_NEXT  pending_link.next
#include "../../util/tmpl/fd_dlist.c"

#define DLIST_NAME  timeout_dlist
#define DLIST_ELE_T slot_state_ele_t
#define DLIST_PREV  timeout_link.prev
#define DLIST_NEXT  timeout_link.next
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

struct __attribute__((aligned(128UL))) ag_votor {
  long   now;
  ulong  seq;
  ulong  root;
  ulong  slot_max;
  ushort shred_version;

  slot_states_t * slot_states;
  ulong           highest_final_cert_slot;

  ulong        curr_epoch_rank;
  ulong        curr_epoch_slot;
  ulong        next_epoch_rank;
  ulong        next_epoch_slot;
  ag_bls_sec_t bls_sec;

  ag_event_vote_t * vote_events;
  ag_event_cert_t * cert_events;
  pending_dlist_t * pending_dlist;
  timeout_dlist_t * timeout_dlist;

  struct {
    ulong * slots;
  } scratch;
};

FD_FN_PURE static inline int
timer_idle( slot_state_ele_t const * ele ) {
  return ele->timeout==LONG_MAX && ele->timeout_crashed_leader==LONG_MAX;
}

static slot_state_ele_t *
state_mut( ag_votor_t * self,
           ulong        slot ) {
  slot_state_ele_t * ele = slot_state_map_ele_query( self->slot_states->map, &slot, NULL, self->slot_states->pool );
  if( FD_LIKELY( ele ) ) return ele;

  FD_TEST( slot_state_pool_free( self->slot_states->pool ) );

  ele                         = slot_state_pool_ele_acquire( self->slot_states->pool );
  fd_memset( ele, 0, sizeof(slot_state_ele_t) );
  ele->slot                   = slot;
  ele->timeout                = LONG_MAX;
  ele->timeout_crashed_leader = LONG_MAX;
  slot_state_map_ele_insert( self->slot_states->map, ele, self->slot_states->pool );
  return ele;
}

static void
set_timeouts( ag_votor_t * self,
              ulong        slot ) {
  FD_TEST( ag_is_start_of_window( slot ) );

  long deadline = self->now + AG_DELTA_TIMEOUT_NS + AG_DELTA_FIRST_SLICE_NS;

  slot_state_ele_t * start      = state_mut( self, slot );
  int                start_idle = timer_idle( start );
  start->timeout_crashed_leader = fd_long_min( start->timeout_crashed_leader, deadline );
  if( FD_UNLIKELY( start_idle ) ) timeout_dlist_ele_push_tail( self->timeout_dlist, start, self->slot_states->pool );

  for( ulong s=slot; s<slot+AG_SLOTS_PER_WINDOW; s++ ) {
    deadline += fd_long_if( ag_is_start_of_window( s ),
                            fd_long_max( AG_DELTA_BLOCK_NS-AG_DELTA_FIRST_SLICE_NS, 0L ),
                            AG_DELTA_BLOCK_NS );
    slot_state_ele_t * state = state_mut( self, s );
    int                idle  = timer_idle( state );
    state->timeout           = fd_long_min( state->timeout, deadline );
    if( FD_LIKELY( idle ) ) timeout_dlist_ele_push_tail( self->timeout_dlist, state, self->slot_states->pool );
  }
}

ulong
ag_votor_align( void ) {
  return alignof(ag_votor_t);
}

ulong
ag_votor_footprint( ulong slot_max ) {
  if( FD_UNLIKELY( slot_max<AG_SLOTS_PER_WINDOW ) ) return 0UL;

  ulong events_max = 2UL*slot_max;

  ulong slot_state_chain_cnt = slot_state_map_chain_cnt_est( slot_max );

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
    FD_LAYOUT_INIT,
      alignof(ag_votor_t),      sizeof(ag_votor_t)                                ),
      alignof(slot_states_t),   sizeof(slot_states_t)                             ),
      slot_state_pool_align(),  slot_state_pool_footprint( slot_max )             ),
      slot_state_map_align(),   slot_state_map_footprint ( slot_state_chain_cnt ) ),
      pending_dlist_align(),    pending_dlist_footprint()                         ),
      timeout_dlist_align(),    timeout_dlist_footprint()                         ),
      vote_events_align(),     vote_events_footprint( events_max )             ),
      cert_events_align(),     cert_events_footprint( events_max )             ),
      alignof(ulong),           sizeof(ulong)*slot_max                            ),
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

  ulong events_max          = 2UL*slot_max;
  ulong slot_state_chain_cnt = slot_state_map_chain_cnt_est( slot_max );

  FD_SCRATCH_ALLOC_INIT( l, mem );
  ag_votor_t * votor            = FD_SCRATCH_ALLOC_APPEND( l, alignof(ag_votor_t),      sizeof(ag_votor_t)                                );
  void *       slot_states      = FD_SCRATCH_ALLOC_APPEND( l, alignof(slot_states_t),   sizeof(slot_states_t)                             );
  void *       slot_state_pool  = FD_SCRATCH_ALLOC_APPEND( l, slot_state_pool_align(),  slot_state_pool_footprint( slot_max )             );
  void *       slot_state_map   = FD_SCRATCH_ALLOC_APPEND( l, slot_state_map_align(),   slot_state_map_footprint ( slot_state_chain_cnt ) );
  void *       pending_dlist    = FD_SCRATCH_ALLOC_APPEND( l, pending_dlist_align(),    pending_dlist_footprint()                         );
  void *       timeout_dlist    = FD_SCRATCH_ALLOC_APPEND( l, timeout_dlist_align(),    timeout_dlist_footprint()                         );
  void *       vote_events     = FD_SCRATCH_ALLOC_APPEND( l, vote_events_align(),     vote_events_footprint( events_max )             );
  void *       cert_events     = FD_SCRATCH_ALLOC_APPEND( l, cert_events_align(),     cert_events_footprint( events_max )             );
  void *       slot_scratch     = FD_SCRATCH_ALLOC_APPEND( l, alignof(ulong),           sizeof(ulong)*slot_max                            );
  FD_TEST( FD_SCRATCH_ALLOC_FINI( l, ag_votor_align() ) == (ulong)mem + footprint );

  votor->slot_states       = (slot_states_t *)slot_states;
  votor->slot_states->pool = slot_state_pool_join( slot_state_pool_new( slot_state_pool, slot_max                  ) );
  votor->slot_states->map  = slot_state_map_join ( slot_state_map_new ( slot_state_map,  slot_state_chain_cnt, seed ) );

  votor->pending_dlist = pending_dlist_join( pending_dlist_new( pending_dlist ) );
  votor->timeout_dlist = timeout_dlist_join( timeout_dlist_new( timeout_dlist ) );

  ag_votor_fini( votor );

  votor->curr_epoch_rank = 0UL;
  votor->curr_epoch_slot = ULONG_MAX;
  votor->next_epoch_rank = 0UL;
  votor->next_epoch_slot = ULONG_MAX;


  votor->vote_events = vote_events_join( vote_events_new( vote_events, events_max ) );
  votor->cert_events = cert_events_join( cert_events_new( cert_events, events_max ) );

  votor->seq = 0UL;

  votor->slot_max = slot_max;


  votor->scratch.slots = (ulong *)slot_scratch;

  return mem;
}

static ushort
own_rank( ag_votor_t const * self,
          ulong              slot ) {
  return (ushort)fd_ulong_if( slot>=self->next_epoch_slot, self->next_epoch_rank, self->curr_epoch_rank );
}

void
ag_votor_advance_epoch( ag_votor_t * self,
                        ulong        epoch_rank,
                        ulong        epoch_slot ) {
  if( FD_UNLIKELY( self->curr_epoch_slot==ULONG_MAX ) ) {
    self->curr_epoch_rank = epoch_rank;
    self->curr_epoch_slot = epoch_slot;
  } else if( FD_UNLIKELY( self->next_epoch_slot==ULONG_MAX ) ) {
    self->next_epoch_rank = epoch_rank;
    self->next_epoch_slot = epoch_slot;
  } else {
    self->curr_epoch_rank = self->next_epoch_rank;
    self->curr_epoch_slot = self->next_epoch_slot;
    self->next_epoch_rank = epoch_rank;
    self->next_epoch_slot = epoch_slot;
  }
}

void
ag_votor_set_bls_key( ag_votor_t *       self,
                      ag_bls_sec_t const bls_key ) {
  FD_TEST( bls_key );
  fd_memcpy( self->bls_sec, bls_key, AG_BLS_SEC_SZ );
}

void
ag_votor_set_shred_version( ag_votor_t * self,
                            ushort       shred_version ) {
  self->shred_version = shred_version;
}

void
ag_votor_init( ag_votor_t * self,
               ulong        slot,
               long         now ) {
  self->now                     = now;
  self->root                    = slot;
  self->highest_final_cert_slot = slot;

  slot_state_ele_t * state       = state_mut( self, slot );
  state->voted                   = 1;
  state->voted_notar             = 1;
  state->block_notarized         = 1;
  state->parents_ready[ 0 ].slot = slot;
  state->parents_ready_cnt       = 1UL;
  state->retired                 = 1;

  set_timeouts( self, ag_first_slot_in_window( slot ) );
}

void
ag_votor_fini( ag_votor_t * self ) {
  self->root                    = ULONG_MAX;
  self->highest_final_cert_slot = ULONG_MAX;
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

FD_FN_PURE static int
received_shred( ag_votor_t const * self,
                ulong              slot ) {
  slot_state_ele_t const * ele = slot_state_map_ele_query_const( self->slot_states->map, &slot, NULL, self->slot_states->pool );
  return ele && ele->received_shred;
}

FD_FN_PURE static ulong
first_unpruned_slot( ag_votor_t const * self ) {
  return ag_first_slot_in_window( self->highest_final_cert_slot );
}

FD_FN_PURE static ulong
pool_event_slot( ag_event_pool_t const * event ) {
  switch( event->kind ) {
  case AG_EVENT_POOL_PARENT_READY:  return event->parent_ready.slot;
  case AG_EVENT_POOL_SAFE_TO_NOTAR: return event->safe_to_notar.slot;
  case AG_EVENT_POOL_SAFE_TO_SKIP:  return event->safe_to_skip;
  case AG_EVENT_POOL_CERT_CREATED:  return ag_cert_slot( &event->cert_created );
  case AG_EVENT_POOL_STANDSTILL:    return event->standstill.slot;
  default:                          __builtin_unreachable();
  }
}

static int
should_ignore_pool_event( ag_votor_t const *      self,
                          ag_event_pool_t const * event ) {
  ulong slot = pool_event_slot( event );
  switch( event->kind ) {
  case AG_EVENT_POOL_STANDSTILL:    return 0;
  case AG_EVENT_POOL_CERT_CREATED:  return slot<first_unpruned_slot( self );
  case AG_EVENT_POOL_PARENT_READY:
  case AG_EVENT_POOL_SAFE_TO_NOTAR:
  case AG_EVENT_POOL_SAFE_TO_SKIP:  return slot<first_unpruned_slot( self ) || is_retired( self, slot );
  default:                          __builtin_unreachable();
  }
}

static void
try_final( ag_votor_t *          self,
           ulong                 slot,
           ag_block_hash_t const hash ) {
  FD_TEST( slot>=first_unpruned_slot( self ) );

  slot_state_ele_t const * state = slot_state_map_ele_query_const( self->slot_states->map, &slot, NULL, self->slot_states->pool );
  int notarized   = state && state->block_notarized && !memcmp( state->block_notarized_hash, hash, sizeof(ag_block_hash_t) );
  int voted_notar = state && state->voted_notar     && !memcmp( state->voted_notar_hash,     hash, sizeof(ag_block_hash_t) );
  int not_bad     = !( state && state->bad_window );
  if( FD_LIKELY( notarized && voted_notar && not_bad ) ) {
    ag_vote_t vote; ag_vote_new_final( &vote, slot, self->bls_sec, own_rank( self, slot ), self->shred_version );
    FD_TEST( !vote_events_full( self->vote_events ) );
    vote_events_push( self->vote_events, (ag_event_vote_t){ .seq = self->seq++, .ts = self->now, .vote = vote } );
    state_mut( self, slot )->retired = 1;
  }
}

static int
try_notar( ag_votor_t *            self,
           ulong                   slot,
           ag_block_info_t const * block_info ) {
  FD_TEST( slot>=first_unpruned_slot( self ) );
  if( FD_UNLIKELY( has_voted( self, slot ) ) ) return 0;

  ag_block_hash_t hash;
  memcpy( hash, block_info->hash, sizeof(ag_block_hash_t) );
  ag_block_id_t parent = block_info->parent;

  if( FD_UNLIKELY( ag_is_start_of_window( slot ) ) ) {
    slot_state_ele_t const * state        = slot_state_map_ele_query_const( self->slot_states->map, &slot, NULL, self->slot_states->pool );
    int                      valid_parent = 0;
    if( FD_LIKELY( state ) ) {
      for( ulong i=0UL; i<state->parents_ready_cnt; i++ ) {
        if( FD_UNLIKELY( ag_block_id_eq( &state->parents_ready[i], &parent ) ) ) { valid_parent = 1; break; }
      }
    }
    if( FD_UNLIKELY( !valid_parent ) ) return 0;
  } else {
    if( FD_UNLIKELY( parent.slot!=slot-1UL ) ) return 0;
    slot_state_ele_t const * parent_state = slot_state_map_ele_query_const( self->slot_states->map, &parent.slot, NULL, self->slot_states->pool );
    if( FD_UNLIKELY( !parent_state || !parent_state->voted_notar                                      ) ) return 0;
    if( FD_UNLIKELY( memcmp( parent_state->voted_notar_hash, parent.hash, sizeof(ag_block_hash_t) )!=0 ) ) return 0;
  }

  ag_vote_t vote; ag_vote_new_notar( &vote, slot, hash, self->bls_sec, own_rank( self, slot ), self->shred_version );
  FD_TEST( !vote_events_full( self->vote_events ) );
  vote_events_push( self->vote_events, (ag_event_vote_t){ .seq = self->seq++, .ts = self->now, .vote = vote } );

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
                 ulong        slot ) {
  FD_TEST( slot>=first_unpruned_slot( self ) );

  ulong window_start = ag_first_slot_in_window( slot );
  for( ulong s=window_start; s<window_start+AG_SLOTS_PER_WINDOW; s++ ) {
    if( FD_UNLIKELY( has_voted( self, s ) ) ) continue;

    slot_state_ele_t * state = state_mut( self, s );
    state->voted             = 1;
    state->bad_window        = 1;

    ag_vote_t vote; ag_vote_new_skip( &vote, s, self->bls_sec, own_rank( self, s ), self->shred_version );
    FD_TEST( !vote_events_full( self->vote_events ) );
    vote_events_push( self->vote_events, (ag_event_vote_t){ .seq = self->seq++, .ts = self->now, .vote = vote } );
  }
}

static void
check_pending_blocks( ag_votor_t * self ) {
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
    if( FD_LIKELY( ele && ele->pending_block ) ) try_notar( self, slots[i], &ele->pending_block_info );
  }
}

static void
prune( ag_votor_t * self ) {
  ulong first_unpruned = first_unpruned_slot( self );
  for( ulong slot=self->root; slot<first_unpruned; slot++ ) {
    slot_state_ele_t * ele = slot_state_map_ele_remove( self->slot_states->map, &slot, NULL, self->slot_states->pool );
    if( FD_LIKELY( ele ) ) {
      if( FD_UNLIKELY( ele->pending_block   ) ) pending_dlist_ele_remove( self->pending_dlist, ele, self->slot_states->pool );
      if( FD_LIKELY  ( !timer_idle( ele )   ) ) timeout_dlist_ele_remove( self->timeout_dlist, ele, self->slot_states->pool );
      slot_state_pool_ele_release( self->slot_states->pool, ele );
    }
  }
  self->root = first_unpruned;
}

static void
handle_cert_created( ag_votor_t *      self,
                     ag_cert_t const * cert ) {
  ulong slot = ag_cert_slot( cert );

  switch( cert->kind ) {

  case AG_CERT_KIND_NOTAR: {
    uchar const * hash = ag_cert_block_hash( cert );

    slot_state_ele_t * state = state_mut( self, slot );
    state->block_notarized   = 1;
    memcpy( state->block_notarized_hash, hash, sizeof(ag_block_hash_t) );

    try_final( self, slot, hash );
    break;
  }

  case AG_CERT_KIND_FINAL:
  case AG_CERT_KIND_FAST_FINAL:
    set_timeouts( self, ag_first_slot_in_window( slot ) );

    self->highest_final_cert_slot = fd_ulong_max( self->highest_final_cert_slot, slot );
    prune( self );
    break;

  case AG_CERT_KIND_SKIP:
  case AG_CERT_KIND_NOTAR_FALLBACK:
    break;

  default:
    FD_LOG_ERR(( "invalid cert kind %u", cert->kind ));
  }

  FD_TEST( !cert_events_full( self->cert_events ) );
  cert_events_push( self->cert_events, (ag_event_cert_t){ .seq = self->seq++, .ts = self->now, .cert = *cert } );
}

void
ag_votor_handle_pool_event( ag_votor_t *            self,
                            ag_event_pool_t const * event,
                            long                    now ) {
  self->now = now;

  if( FD_UNLIKELY( should_ignore_pool_event( self, event ) ) ) return;

  switch( event->kind ) {

  case AG_EVENT_POOL_PARENT_READY: {
    ulong                 slot   = event->parent_ready.slot;
    ag_block_id_t const * parent = &event->parent_ready.parent;

    slot_state_ele_t * state = state_mut( self, slot );
    int                dup   = 0;
    for( ulong i=0UL; i<state->parents_ready_cnt; i++ ) {
      if( FD_UNLIKELY( ag_block_id_eq( &state->parents_ready[i], parent ) ) ) { dup = 1; break; }
    }
    if( FD_LIKELY( !dup ) ) {
      FD_TEST( state->parents_ready_cnt<PARENTS_READY_MAX );
      state->parents_ready[ state->parents_ready_cnt++ ] = *parent;
    }

    check_pending_blocks( self );
    set_timeouts( self, slot );
    break;
  }

  case AG_EVENT_POOL_SAFE_TO_NOTAR: {
    ulong         slot = event->safe_to_notar.slot;
    uchar const * hash = event->safe_to_notar.hash;

    ag_vote_t vote; ag_vote_new_notar_fallback( &vote, slot, hash, self->bls_sec, own_rank( self, slot ), self->shred_version );
    FD_TEST( !vote_events_full( self->vote_events ) );
    vote_events_push( self->vote_events, (ag_event_vote_t){ .seq = self->seq++, .ts = self->now, .vote = vote } );
    try_skip_window( self, slot );
    state_mut( self, slot )->bad_window = 1;
    break;
  }

  case AG_EVENT_POOL_SAFE_TO_SKIP: {
    ulong slot = event->safe_to_skip;

    ag_vote_t vote; ag_vote_new_skip_fallback( &vote, slot, self->bls_sec, own_rank( self, slot ), self->shred_version );
    FD_TEST( !vote_events_full( self->vote_events ) );
    vote_events_push( self->vote_events, (ag_event_vote_t){ .seq = self->seq++, .ts = self->now, .vote = vote } );
    try_skip_window( self, slot );
    state_mut( self, slot )->bad_window = 1;
    break;
  }

  case AG_EVENT_POOL_CERT_CREATED:
    handle_cert_created( self, &event->cert_created );
    break;

  case AG_EVENT_POOL_STANDSTILL: {
    ag_standstill_t const * standstill = &event->standstill;
    FD_TEST( cert_events_avail( self->cert_events )>=standstill->cert_cnt );
    for( ulong i=0UL; i<standstill->cert_cnt; i++ ) cert_events_push( self->cert_events, (ag_event_cert_t){ .seq = self->seq++, .ts = self->now, .cert = standstill->certs[i] } );
    FD_TEST( vote_events_avail( self->vote_events )>=standstill->vote_cnt );
    for( ulong i=0UL; i<standstill->vote_cnt; i++ ) vote_events_push( self->vote_events, (ag_event_vote_t){ .seq = self->seq++, .ts = self->now, .vote = standstill->votes[i] } );
    break;
  }

  default:
    FD_LOG_ERR(( "invalid pool event kind %d", event->kind ));
  }
}

void
ag_votor_handle_block_event( ag_votor_t *             self,
                             ag_event_block_t const * event ) {
  ulong slot = event->slot;
  if( FD_UNLIKELY( slot<=self->highest_final_cert_slot || is_retired( self, slot ) ) ) return;

  switch( event->kind ) {
  case AG_EVENT_BLOCK_FIRST_SHRED:
    state_mut( self, slot )->received_shred = 1;
    break;

  case AG_EVENT_BLOCK_INVALID_BLOCK:
    FD_LOG_WARNING(( "invalid block from leader for slot %lu, skipping window", slot ));
    try_skip_window( self, slot );
    break;

  default:
    FD_LOG_ERR(( "invalid block event kind %d", event->kind ));
  }
}

void
ag_votor_handle_replay_event( ag_votor_t *              self,
                              ag_event_replay_t const * event ) {
  ulong slot = event->slot;
  if( FD_UNLIKELY( slot<=self->highest_final_cert_slot || is_retired( self, slot ) ) ) return;

  switch( event->kind ) {
  case AG_EVENT_REPLAY_COMPLETED:
    if( FD_UNLIKELY( has_voted( self, slot ) ) ) {
      FD_LOG_WARNING(( "not voting for block in slot %lu, already voted", slot ));
      return;
    }
    if( FD_LIKELY( try_notar( self, slot, &event->block_info ) ) ) {
      check_pending_blocks( self );
    } else {
      slot_state_ele_t * state  = state_mut( self, slot );
      if( FD_LIKELY( !state->pending_block ) ) pending_dlist_ele_push_tail( self->pending_dlist, state, self->slot_states->pool );
      state->pending_block      = 1;
      state->pending_block_info = event->block_info;
    }
    break;

  case AG_EVENT_REPLAY_DEAD:
    FD_LOG_WARNING(( "replay marked slot %lu dead, skipping window", slot ));
    try_skip_window( self, slot );
    break;

  default:
    FD_LOG_ERR(( "invalid replay event kind %d", event->kind ));
  }
}

void
ag_votor_handle_timeout_event( ag_votor_t *               self,
                               ag_event_timeout_t const * event ) {
  ulong slot = event->slot;
  if( FD_UNLIKELY( slot<=self->highest_final_cert_slot || is_retired( self, slot ) ) ) return;

  switch( event->kind ) {
  case AG_EVENT_TIMEOUT:
    if( FD_UNLIKELY( !has_voted( self, slot ) ) ) try_skip_window( self, slot );
    break;

  case AG_EVENT_TIMEOUT_CRASHED_LEADER:
    if( FD_UNLIKELY( !received_shred( self, slot ) && !has_voted( self, slot ) ) ) try_skip_window( self, slot );
    break;

  default:
    FD_LOG_ERR(( "invalid timeout kind %d", event->kind ));
  }
}

int
ag_votor_poll_timeout_event( ag_votor_t *         self,
                             long                 now,
                             ag_event_timeout_t * event ) {
  self->now = now;

  slot_state_ele_t * pool = self->slot_states->pool;

  for( timeout_dlist_iter_t iter = timeout_dlist_iter_fwd_init( self->timeout_dlist, pool );
                                  !timeout_dlist_iter_done( iter, self->timeout_dlist, pool );
                            iter = timeout_dlist_iter_fwd_next( iter, self->timeout_dlist, pool ) ) {
    slot_state_ele_t * ele = timeout_dlist_iter_ele( iter, self->timeout_dlist, pool );

    int kind;
    if     ( FD_UNLIKELY( ele->timeout_crashed_leader<=now ) ) { kind = AG_EVENT_TIMEOUT_CRASHED_LEADER; ele->timeout_crashed_leader = LONG_MAX; }
    else if( FD_UNLIKELY( ele->timeout               <=now ) ) { kind = AG_EVENT_TIMEOUT;        ele->timeout                = LONG_MAX; }
    else continue;

    event->seq  = self->seq++;
    event->ts   = self->now;
    event->kind = kind;
    event->slot = ele->slot;
    if( FD_UNLIKELY( timer_idle( ele ) ) ) timeout_dlist_ele_remove( self->timeout_dlist, ele, pool );
    return 1;
  }
  return 0;
}

int
ag_votor_poll_vote_event( ag_votor_t *      self,
                          ag_event_vote_t * event ) {
  if( FD_LIKELY( vote_events_empty( self->vote_events ) ) ) return 0;
  *event = vote_events_pop( self->vote_events );
  return 1;
}

int
ag_votor_poll_cert_event( ag_votor_t *      self,
                          ag_event_cert_t * event ) {
  if( FD_LIKELY( cert_events_empty( self->cert_events ) ) ) return 0;
  *event = cert_events_pop( self->cert_events );
  return 1;
}
