#include "ag_votor.h"

#define POOL_NAME slot_pool
#define POOL_T    ag_votor_slot_state_t
#define POOL_NEXT next
#include "../../util/tmpl/fd_pool.c"

#define MAP_NAME               slot_map
#define MAP_ELE_T              ag_votor_slot_state_t
#define MAP_KEY                slot
#define MAP_KEY_T              ulong
#define MAP_KEY_EQ(k0,k1)      ((*(k0))==(*(k1)))
#define MAP_KEY_HASH(key,seed) (fd_ulong_hash((*(key))^(seed)))
#define MAP_NEXT               next
#include "../../util/tmpl/fd_map_chain.c"

typedef ag_votor_slot_state_t slot_pool_t;

struct __attribute__((aligned(128UL))) ag_votor {
  slot_pool_t *  slot_pool;
  slot_map_t *   slot_map;

  ushort         validator_index;
  ag_aggsig_sk_t voting_key;
  ulong          highest_final_cert_slot;

  ag_votor_out_t out;
};

ulong
ag_votor_align( void ) {
  return alignof(ag_votor_t);
}

ulong
ag_votor_footprint( ulong slot_max ) {
  slot_max = fd_ulong_pow2_up( slot_max );
  ulong chain_cnt = slot_map_chain_cnt_est( slot_max );
  return FD_LAYOUT_FINI(
    FD_LAYOUT_APPEND(
    FD_LAYOUT_APPEND(
    FD_LAYOUT_APPEND(
    FD_LAYOUT_INIT,
      alignof(ag_votor_t), sizeof(ag_votor_t)            ),
      slot_pool_align(),   slot_pool_footprint( slot_max ) ),
      slot_map_align(),    slot_map_footprint ( chain_cnt ) ),
    ag_votor_align() );
}

static ag_votor_slot_state_t *
slot_state_mut( ag_votor_t * self,
                ulong        slot ) {
  slot_pool_t * pool = self->slot_pool;
  slot_map_t  * map  = self->slot_map;
  ag_votor_slot_state_t * s = slot_map_ele_query( map, &slot, NULL, pool );
  if( FD_LIKELY( s ) ) return s;

  FD_TEST( slot_pool_free( pool ) );
  s = slot_pool_ele_acquire( pool );

  fd_memset( s, 0, sizeof(ag_votor_slot_state_t) );
  s->slot = slot;
  slot_map_ele_insert( map, s, pool );
  return s;
}

static ag_votor_slot_state_t const *
slot_state_query_const( ag_votor_t const * self,
                        ulong              slot ) {
  return slot_map_ele_query_const( self->slot_map, &slot, NULL, self->slot_pool );
}

static void
out_push_vote( ag_votor_t *      self,
               ag_vote_t const * vote ) {
  ag_votor_out_t * out = &self->out;
  FD_TEST( out->msg_cnt < AG_VOTOR_OUT_MSG_MAX );
  ag_consensus_message_t * m = &out->msgs[ out->msg_cnt++ ];
  m->kind = AG_CONSENSUS_MESSAGE_VOTE;
  m->inner.vote   = *vote;
}

static void
out_push_cert( ag_votor_t *      self,
               ag_cert_t const * cert ) {
  ag_votor_out_t * out = &self->out;
  FD_TEST( out->msg_cnt < AG_VOTOR_OUT_MSG_MAX );
  ag_consensus_message_t * m = &out->msgs[ out->msg_cnt++ ];
  m->kind = AG_CONSENSUS_MESSAGE_CERT;
  m->inner.cert   = *cert;
}

static void
out_push_timeout( ag_votor_t * self,
                  uint         kind,
                  ulong        slot ) {
  ag_votor_out_t * out = &self->out;
  FD_TEST( out->timeout_cnt < AG_VOTOR_OUT_TIMEOUT_MAX );
  ag_votor_timeout_t * t = &out->timeouts[ out->timeout_cnt++ ];
  t->kind = kind;
  t->slot = slot;
}

static void
out_reset( ag_votor_t * self ) {
  self->out.msg_cnt     = 0UL;
  self->out.timeout_cnt = 0UL;
}

/* Predicates (Votor::is_retired / has_voted / received_shred). */

static int
is_retired( ag_votor_t * self,
            ulong        slot ) {
  ag_votor_slot_state_t const * s = slot_state_query_const( self, slot );
  return s && s->retired;
}

static int
has_voted( ag_votor_t * self,
           ulong        slot ) {
  ag_votor_slot_state_t const * s = slot_state_query_const( self, slot );
  return s && s->voted;
}

static int
received_shred( ag_votor_t * self,
                ulong        slot ) {
  ag_votor_slot_state_t const * s = slot_state_query_const( self, slot );
  return s && s->received_shred;
}

static ulong
first_unpruned_slot( ag_votor_t const * self ) {
  return ag_alpenglow_first_slot_in_window( self->highest_final_cert_slot );
}

static void
set_timeouts( ag_votor_t * self,
              ulong        slot ) {
  FD_TEST( ag_alpenglow_is_start_of_window( slot ) );
  out_push_timeout( self, AG_VOTOR_TIMEOUT_CRASHED_LEADER, slot );
  ulong last = ag_alpenglow_last_slot_in_window( slot );
  for( ulong s=slot; s<=last; s++ ) {
    out_push_timeout( self, AG_VOTOR_TIMEOUT_TIMEOUT, s );
  }
}

static void
try_final( ag_votor_t *      self,
           ulong             slot,
           fd_hash_t const * hash ) {
  FD_TEST( slot >= first_unpruned_slot( self ) );
  ag_votor_slot_state_t const * s = slot_state_query_const( self, slot );
  int notarized   = s && s->has_block_notarized && !memcmp( s->block_notarized.uc, hash->uc, sizeof(fd_hash_t) );
  int voted_notar = s && s->has_voted_notar     && !memcmp( s->voted_notar.uc,     hash->uc, sizeof(fd_hash_t) );
  int not_bad     = !( s && s->bad_window );
  if( notarized && voted_notar && not_bad ) {
    ag_vote_t vote;
    ag_vote_new_final( &vote, slot, &self->voting_key, self->validator_index );
    out_push_vote( self, &vote );
    slot_state_mut( self, slot )->retired = 1;
  }
}

static int
try_notar( ag_votor_t *          self,
           ulong                 slot,
           ag_block_id_t const * block_id,
           ag_block_id_t const * parent_block_id ) {
  FD_TEST( slot >= first_unpruned_slot( self ) );
  fd_hash_t const * hash        = &block_id->hash;
  ulong             parent_slot = parent_block_id->slot;
  fd_hash_t const * parent_hash = &parent_block_id->hash;
  ulong             first_slot  = ag_alpenglow_first_slot_in_window( slot );

  if( slot==first_slot ) {
    int valid_parent = 0;
    ag_votor_slot_state_t const * s = slot_state_query_const( self, slot );
    if( s ) {
      for( ulong i=0UL; i<s->parents_ready_cnt; i++ ) {
        if( ag_block_id_eq( &s->parents_ready[i], parent_block_id ) ) { valid_parent = 1; break; }
      }
    }
    if( !valid_parent ) return 0;
  } else {
    if( parent_slot != slot-1UL ) return 0;
    ag_votor_slot_state_t const * ps = slot_state_query_const( self, parent_slot );
    int matches = ps && ps->has_voted_notar && !memcmp( ps->voted_notar.uc, parent_hash->uc, sizeof(fd_hash_t) );
    if( !matches ) return 0;
  }

  ag_vote_t vote;
  ag_vote_new_notar( &vote, slot, hash, &self->voting_key, self->validator_index );
  FD_BASE58_ENCODE_32_BYTES( hash->uc, hash_cstr );
  FD_LOG_NOTICE(( "try_notar slot=%lu hash=%s", slot, hash_cstr ));
  out_push_vote( self, &vote );

  ag_votor_slot_state_t * state = slot_state_mut( self, slot );
  state->voted             = 1;
  state->has_voted_notar   = 1;
  state->voted_notar       = *hash;
  state->has_pending_block = 0;

  try_final( self, slot, hash );
  return 1;
}

static void
try_skip_window( ag_votor_t * self,
                 ulong        slot ) {
  FD_TEST( slot >= first_unpruned_slot( self ) );
  ulong first = ag_alpenglow_first_slot_in_window( slot );
  ulong last  = ag_alpenglow_last_slot_in_window( slot );
  for( ulong s=first; s<=last; s++ ) {
    if( has_voted( self, s ) ) continue;
    ag_votor_slot_state_t * state = slot_state_mut( self, s );
    state->voted      = 1;
    state->bad_window = 1;
    ag_vote_t vote;
    ag_vote_new_skip( &vote, s, &self->voting_key, self->validator_index );

    out_push_vote( self, &vote );
  }
}

static void
check_pending_blocks( ag_votor_t * self ) {
  slot_pool_t * pool = self->slot_pool;
  slot_map_t  * map  = self->slot_map;

  for( slot_map_iter_t iter = slot_map_iter_init( map, pool );
       !slot_map_iter_done( iter, map, pool );
       iter = slot_map_iter_next( iter, map, pool ) ) {
    ag_votor_slot_state_t * s = slot_map_iter_ele( iter, map, pool );
    if( !s->has_pending_block ) continue;
    ulong         slot            = s->slot;
    ag_block_id_t block_id        = s->pending_block_id;
    ag_block_id_t parent_block_id = s->pending_parent_block_id;
    try_notar( self, slot, &block_id, &parent_block_id );
  }
}

static void
prune( ag_votor_t * self ) {
  slot_pool_t * pool   = self->slot_pool;
  slot_map_t  * map    = self->slot_map;
  ulong         cutoff = first_unpruned_slot( self );

  int again = 1;
  while( again ) {
    again = 0;
    for( slot_map_iter_t iter = slot_map_iter_init( map, pool );
         !slot_map_iter_done( iter, map, pool );
         iter = slot_map_iter_next( iter, map, pool ) ) {
      ag_votor_slot_state_t * s = slot_map_iter_ele( iter, map, pool );
      if( s->slot < cutoff ) {
        slot_map_ele_remove( map, &s->slot, NULL, pool );
        slot_pool_ele_release( pool, s );
        again = 1;
        break;
      }
    }
  }
}

static void
handle_cert_created( ag_votor_t *      votor,
                     ag_cert_t const * cert ) {
  switch( cert->kind ) {
  case AG_CERT_TYPE_NOTAR: {
    fd_hash_t const * hash = ag_cert_block_hash( cert );
    ulong             slot = ag_cert_slot( cert );

    ag_votor_slot_state_t * s = slot_state_mut( votor, slot );
    s->has_block_notarized = 1;
    s->block_notarized     = *hash;
    try_final( votor, slot, hash );
    break;
  }
  case AG_CERT_TYPE_FINAL:
  case AG_CERT_TYPE_FAST_FINAL: {
    ulong slot = ag_cert_slot( cert );

    set_timeouts( votor, ag_alpenglow_first_slot_in_window( slot ) );

    votor->highest_final_cert_slot = fd_ulong_max( votor->highest_final_cert_slot, slot );
    prune( votor );
    break;
  }
  default:
    break;
  }
  out_push_cert( votor, cert );
}

static ulong
pool_event_slot( ag_pool_event_t const * event ) {
  switch( event->kind ) {
  case AG_POOL_EVENT_PARENT_READY:  return event->inner.parent_ready.slot;
  case AG_POOL_EVENT_SAFE_TO_NOTAR: return event->inner.safe_to_notar.slot;
  case AG_POOL_EVENT_SAFE_TO_SKIP:  return event->inner.safe_to_skip;
  case AG_POOL_EVENT_CERT_CREATED:  return ag_cert_slot( &event->inner.cert_created );
  default:                          return event->inner.standstill;
  }
}

static int
should_ignore_pool_event( ag_votor_t *            votor,
                          ag_pool_event_t const * event ) {
  ulong slot = pool_event_slot( event );
  switch( event->kind ) {
  case AG_POOL_EVENT_STANDSTILL:
    return 0;
  case AG_POOL_EVENT_CERT_CREATED:
    return slot < first_unpruned_slot( votor );
  default:
    return slot < first_unpruned_slot( votor ) || is_retired( votor, slot );
  }
}

void
ag_votor_handle_pool_event( ag_votor_t *            votor,
                            ag_pool_event_t const * event ) {
  out_reset( votor );
  if( should_ignore_pool_event( votor, event ) ) return;

  switch( event->kind ) {

  case AG_POOL_EVENT_PARENT_READY: {
    ulong               slot   = event->inner.parent_ready.slot;
    ag_block_id_t const parent = event->inner.parent_ready.parent;
    ag_votor_slot_state_t * s = slot_state_mut( votor, slot );

    int present = 0;
    for( ulong i=0UL; i<s->parents_ready_cnt; i++ ) {
      if( ag_block_id_eq( &s->parents_ready[i], &parent ) ) { present = 1; break; }
    }
    if( !present ) {
      FD_TEST( s->parents_ready_cnt < AG_VOTOR_PARENTS_READY_MAX );
      s->parents_ready[ s->parents_ready_cnt++ ] = parent;
    }
    check_pending_blocks( votor );
    set_timeouts( votor, slot );
    break;
  }

  case AG_POOL_EVENT_SAFE_TO_NOTAR: {
    ag_block_id_t const blk = event->inner.safe_to_notar;
    ag_vote_t vote;
    ag_vote_new_notar_fallback( &vote, blk.slot, &blk.hash, &votor->voting_key, votor->validator_index );
    out_push_vote( votor, &vote );
    try_skip_window( votor, blk.slot );
    slot_state_mut( votor, blk.slot )->bad_window = 1;
    break;
  }

  case AG_POOL_EVENT_SAFE_TO_SKIP: {
    ulong slot = event->inner.safe_to_skip;
    ag_vote_t vote;
    ag_vote_new_skip_fallback( &vote, slot, &votor->voting_key, votor->validator_index );
    out_push_vote( votor, &vote );
    try_skip_window( votor, slot );
    slot_state_mut( votor, slot )->bad_window = 1;
    break;
  }

  case AG_POOL_EVENT_CERT_CREATED:
    handle_cert_created( votor, &event->inner.cert_created );
    break;

  case AG_POOL_EVENT_STANDSTILL:
    /* PoolEvent::Standstill carries Vec<Cert> + Vec<Vote> in Rust; here the
       recovery bundle is conveyed via ag_pool_recover_from_standstill's
       output buffers (see ag_pool.h), so there is nothing to re-broadcast
       from the event itself. */
    break;

  default:
    break;
  }
}

void
ag_votor_handle_blockstore_event( ag_votor_t *                        votor,
                                  ag_votor_blockstore_event_t const * event ) {
  out_reset( votor );
  ulong slot;
  switch( event->kind ) {
  case AG_VOTOR_BLOCKSTORE_EVENT_FIRST_SHRED:   slot = event->inner.first_shred;   break;
  case AG_VOTOR_BLOCKSTORE_EVENT_INVALID_BLOCK: slot = event->inner.invalid_block; break;
  default:                                      slot = event->inner.block.slot;    break;
  }

  if( slot <= votor->highest_final_cert_slot || is_retired( votor, slot ) ) return;

  switch( event->kind ) {

  case AG_VOTOR_BLOCKSTORE_EVENT_FIRST_SHRED:
    slot_state_mut( votor, slot )->received_shred = 1;
    break;

  case AG_VOTOR_BLOCKSTORE_EVENT_INVALID_BLOCK:
    try_skip_window( votor, slot );
    break;

  case AG_VOTOR_BLOCKSTORE_EVENT_BLOCK: {
    ag_block_id_t const block_id        = event->inner.block.block_id;
    ag_block_id_t const parent_block_id = event->inner.block.parent_block_id;
    if( has_voted( votor, slot ) ) return;
    if( try_notar( votor, slot, &block_id, &parent_block_id ) ) {
      check_pending_blocks( votor );
    } else {
      ag_votor_slot_state_t * s = slot_state_mut( votor, slot );
      s->has_pending_block        = 1;
      s->pending_block_id         = block_id;
      s->pending_parent_block_id  = parent_block_id;
    }
    break;
  }

  default:
    break;
  }
}

void
ag_votor_handle_timeout_event( ag_votor_t *               votor,
                               ag_votor_timeout_t const * event ) {
  out_reset( votor );
  ulong slot = event->slot;
  if( slot <= votor->highest_final_cert_slot || is_retired( votor, slot ) ) return;

  switch( event->kind ) {
  case AG_VOTOR_TIMEOUT_TIMEOUT:
    if( !has_voted( votor, slot ) ) try_skip_window( votor, slot );
    break;
  case AG_VOTOR_TIMEOUT_CRASHED_LEADER:
    if( !received_shred( votor, slot ) && !has_voted( votor, slot ) ) try_skip_window( votor, slot );
    break;
  default:
    break;
  }
}

void *
ag_votor_new( void *                 shmem,
              ulong                  slot_max,
              ushort                 validator_index,
              ag_aggsig_sk_t const * voting_key,
              ulong                  seed ) {

  if( FD_UNLIKELY( !shmem ) ) {
    FD_LOG_WARNING(( "NULL mem" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shmem, ag_votor_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned mem" ));
    return NULL;
  }

  ulong footprint = ag_votor_footprint( slot_max );
  if( FD_UNLIKELY( !footprint ) ) {
    FD_LOG_WARNING(( "bad slot_max (%lu)", slot_max ));
    return NULL;
  }

  fd_memset( shmem, 0, footprint );

  slot_max        = fd_ulong_pow2_up( slot_max );
  ulong chain_cnt = slot_map_chain_cnt_est( slot_max );

  FD_SCRATCH_ALLOC_INIT( l, shmem );
  ag_votor_t * votor     = FD_SCRATCH_ALLOC_APPEND( l, alignof(ag_votor_t), sizeof(ag_votor_t)              );
  void *       slot_pool = FD_SCRATCH_ALLOC_APPEND( l, slot_pool_align(),   slot_pool_footprint( slot_max ) );
  void *       slot_map  = FD_SCRATCH_ALLOC_APPEND( l, slot_map_align(),    slot_map_footprint ( chain_cnt) );
  FD_TEST( FD_SCRATCH_ALLOC_FINI( l, ag_votor_align() ) == (ulong)shmem + footprint );

  votor->slot_pool               = slot_pool_join( slot_pool_new( slot_pool, slot_max        ) );
  votor->slot_map                = slot_map_join ( slot_map_new ( slot_map,  chain_cnt, seed ) );
  votor->validator_index         = validator_index;
  votor->voting_key              = *voting_key;
  votor->highest_final_cert_slot = 0UL;

  {
    ag_votor_slot_state_t * g = slot_state_mut( votor, 0UL  );
    fd_hash_t genesis_hash; fd_memset( &genesis_hash, 0, sizeof(fd_hash_t) );
    g->voted                = 1;
    g->has_voted_notar      = 1;
    g->voted_notar          = genesis_hash;
    g->has_block_notarized  = 1;
    g->block_notarized      = genesis_hash;
    g->parents_ready_cnt    = 1UL;
    g->parents_ready[0].slot = 0UL;
    g->parents_ready[0].hash = genesis_hash;
    g->retired              = 1;
  }

  set_timeouts( votor, 0UL );

  return shmem;
}

ag_votor_t *
ag_votor_join( void * shvotor ) {
  ag_votor_t * votor = (ag_votor_t *)shvotor;

  if( FD_UNLIKELY( !votor ) ) {
    FD_LOG_WARNING(( "NULL votor" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)votor, ag_votor_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned votor" ));
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
ag_votor_delete( void * shvotor ) {
  if( FD_UNLIKELY( !shvotor ) ) {
    FD_LOG_WARNING(( "NULL votor" ));
    return NULL;
  }
  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shvotor, ag_votor_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned votor" ));
    return NULL;
  }
  return shvotor;
}

ag_votor_out_t const *
ag_votor_out( ag_votor_t const * votor ) {
  return &votor->out;
}

ulong
ag_votor_validator_index( ag_votor_t const * votor ) {
  return votor->validator_index;
}

ulong
ag_votor_highest_final_cert_slot( ag_votor_t const * votor ) {
  return votor->highest_final_cert_slot;
}

ag_votor_slot_state_t const *
ag_votor_slot_state( ag_votor_t const * votor,
                     ulong              slot ) {
  return slot_state_query_const( votor, slot );
}

int
ag_consensus_message_de( ag_consensus_message_t * out,
                         uchar const *            payload,
                         ulong                    sz ) {
  if( FD_UNLIKELY( sz<sizeof(uint) ) ) return -1;
  uint kind = FD_LOAD( uint, payload );
  payload += sizeof(uint); sz -= sizeof(uint);

  switch( kind ) {
  case AG_CONSENSUS_MESSAGE_VOTE: {
    if( FD_UNLIKELY( sz<sizeof(uint) ) ) return -1;
    ag_vote_t const * vote = (ag_vote_t const *)fd_type_pun_const( payload );
    ulong need;
    switch( vote->kind ) {
    case AG_VOTE_TYPE_NOTAR:
    case AG_VOTE_TYPE_NOTAR_FALLBACK: need = sizeof(uint)+sizeof(ag_notar_vote_t); break;
    case AG_VOTE_TYPE_SKIP:
    case AG_VOTE_TYPE_SKIP_FALLBACK:
    case AG_VOTE_TYPE_FINAL:          need = sizeof(uint)+sizeof(ag_final_vote_t); break;
    default: return -1;
    }
    if( FD_UNLIKELY( sz<need ) ) return -1;
    out->kind = AG_CONSENSUS_MESSAGE_VOTE;
    fd_memcpy( &out->inner.vote, payload, need );
    return 0;
  }
  case AG_CONSENSUS_MESSAGE_CERT: {
    int err = ag_cert_de( &out->inner.cert, payload, sz );
    if( FD_UNLIKELY( err!=AG_CERT_DE_SUCCESS ) ) return -1;
    out->kind = AG_CONSENSUS_MESSAGE_CERT;
    return 0;
  }
  default: return -1;
  }
}
