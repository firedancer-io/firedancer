#include "fd_votor.h"

/* The votor is identity-agnostic: it signs votes (the signature covers only
   kind/slot/block_hash, never the signer rank) but leaves the signer field
   unset.  The tile stamps the real rank per the vote's slot epoch when it
   drains the output (fd_vote_set_signer), so the votor needs no own_id. */

#define VOTOR_SIGNER_UNSET ((ushort)0)

/* Per-slot state pool + map keyed by slot.  Built directly on the lowest-level
   util generics (fd_pool + fd_map_chain), mirroring the canonical fd_ghost
   instantiation pattern. */

#define POOL_NAME slot_pool
#define POOL_T    fd_votor_slot_state_t
#define POOL_NEXT next
#include "../../util/tmpl/fd_pool.c"

#define MAP_NAME               slot_map
#define MAP_ELE_T              fd_votor_slot_state_t
#define MAP_KEY                slot
#define MAP_KEY_T              ulong
#define MAP_KEY_EQ(k0,k1)      ((*(k0))==(*(k1)))
#define MAP_KEY_HASH(key,seed) (fd_ulong_hash( (*(key)) ^ (seed) ))
#define MAP_NEXT               next
#include "../../util/tmpl/fd_map_chain.c"

typedef fd_votor_slot_state_t slot_pool_t;

/* fd_votor_t is the top-level structure.  Following the canonical fd_ghost
   layout it holds only ulong gaddrs (for the slot pool and map) plus inline
   scalar state.  The structures are bump-allocated contiguously from the
   fd_votor_t * pointer:

   --------------------------- <- fd_votor_t *
   | fd_votor_t              |
   ---------------------------
   | slot_pool               |
   ---------------------------
   | slot_map                |
   --------------------------- */

struct __attribute__((aligned(128UL))) fd_votor {
  ulong          wksp_gaddr;             /* wksp gaddr of fd_votor in the backing wksp */
  ulong          slot_pool_gaddr;        /* memory offset of the slot_pool             */
  ulong          slot_map_gaddr;         /* memory offset of the slot_map              */

  fd_aggsig_sk_t voting_key;             /* BLS secret key used to sign votes          */
  ulong          highest_final_cert_slot;/* Votor::highest_final_cert_slot             */
};

/* wksp returns the local join to the wksp backing the votor. */

FD_FN_PURE static inline fd_wksp_t *
wksp( fd_votor_t const * votor ) {
  return (fd_wksp_t *)( ((ulong)votor) - votor->wksp_gaddr );
}

static inline slot_pool_t *
slot_pool( fd_votor_t * votor ) {
  return (slot_pool_t *)fd_wksp_laddr_fast( wksp( votor ), votor->slot_pool_gaddr );
}

static inline slot_pool_t const *
slot_pool_const( fd_votor_t const * votor ) {
  return (slot_pool_t const *)fd_wksp_laddr_fast( wksp( votor ), votor->slot_pool_gaddr );
}

static inline slot_map_t *
slot_map( fd_votor_t * votor ) {
  return (slot_map_t *)fd_wksp_laddr_fast( wksp( votor ), votor->slot_map_gaddr );
}

static inline slot_map_t const *
slot_map_const( fd_votor_t const * votor ) {
  return (slot_map_t const *)fd_wksp_laddr_fast( wksp( votor ), votor->slot_map_gaddr );
}

/* ---------------------------------------------------------------------- */
/* Constructors                                                           */
/* ---------------------------------------------------------------------- */

ulong
fd_votor_align( void ) {
  return alignof(fd_votor_t);
}

ulong
fd_votor_footprint( ulong slot_max ) {
  slot_max = fd_ulong_pow2_up( slot_max );
  ulong chain_cnt = slot_map_chain_cnt_est( slot_max );
  return FD_LAYOUT_FINI(
    FD_LAYOUT_APPEND(
    FD_LAYOUT_APPEND(
    FD_LAYOUT_APPEND(
    FD_LAYOUT_INIT,
      alignof(fd_votor_t), sizeof(fd_votor_t)            ),
      slot_pool_align(),   slot_pool_footprint( slot_max ) ),
      slot_map_align(),    slot_map_footprint ( chain_cnt ) ),
    fd_votor_align() );
}

/* slot_state_mut returns a mutable reference to slot's state, inserting a
   default (zeroed) state if none exists yet (Votor::state_mut). */

static fd_votor_slot_state_t *
slot_state_mut( fd_votor_t * votor, ulong slot ) {
  slot_pool_t * pool = slot_pool( votor );
  slot_map_t  * map  = slot_map ( votor );
  fd_votor_slot_state_t * s = slot_map_ele_query( map, &slot, NULL, pool );
  if( FD_LIKELY( s ) ) return s;

  FD_TEST( slot_pool_free( pool ) ); /* votor full */
  s = slot_pool_ele_acquire( pool );
  /* zero everything but preserve pool/map bookkeeping fields after init */
  fd_memset( s, 0, sizeof(fd_votor_slot_state_t) );
  s->slot = slot;
  slot_map_ele_insert( map, s, pool );
  return s;
}

/* slot_state queries slot's state, or NULL if none exists (Votor::slots.get). */

static fd_votor_slot_state_t const *
slot_state_query_const( fd_votor_t const * votor, ulong slot ) {
  return slot_map_ele_query_const( slot_map_const( votor ), &slot, NULL, slot_pool_const( votor ) );
}

/* ---------------------------------------------------------------------- */
/* Out-buffer append helpers                                              */
/* ---------------------------------------------------------------------- */

static void
out_push_vote( fd_votor_out_t * out, fd_ag_vote_t const * vote ) {
  FD_TEST( out->msg_cnt < out->msg_max );
  fd_consensus_message_t * m = &out->msgs[ out->msg_cnt++ ];
  m->discriminant = FD_CONSENSUS_MESSAGE_VOTE;
  m->inner.vote   = *vote;
}

static void
out_push_cert( fd_votor_out_t * out, fd_cert_t const * cert ) {
  FD_TEST( out->msg_cnt < out->msg_max );
  fd_consensus_message_t * m = &out->msgs[ out->msg_cnt++ ];
  m->discriminant = FD_CONSENSUS_MESSAGE_CERT;
  m->inner.cert   = *cert;
}

static void
out_push_msg( fd_votor_out_t * out, fd_consensus_message_t const * msg ) {
  FD_TEST( out->msg_cnt < out->msg_max );
  out->msgs[ out->msg_cnt++ ] = *msg;
}

static void
out_push_timeout( fd_votor_out_t * out, uint kind, ulong slot ) {
  FD_TEST( out->timeout_cnt < out->timeout_max );
  fd_votor_timeout_t * t = &out->timeouts[ out->timeout_cnt++ ];
  t->kind = kind;
  t->slot = slot;
}

/* ---------------------------------------------------------------------- */
/* Predicates (Votor::is_retired / has_voted / received_shred)            */
/* ---------------------------------------------------------------------- */

static int
is_retired( fd_votor_t * votor, ulong slot ) {
  fd_votor_slot_state_t const * s = slot_state_query_const( votor, slot );
  return s && s->retired;
}

static int
has_voted( fd_votor_t * votor, ulong slot ) {
  fd_votor_slot_state_t const * s = slot_state_query_const( votor, slot );
  return s && s->voted;
}

static int
received_shred( fd_votor_t * votor, ulong slot ) {
  fd_votor_slot_state_t const * s = slot_state_query_const( votor, slot );
  return s && s->received_shred;
}

/* first_unpruned_slot is the first slot whose state is still retained, i.e.
   the start of the leader window containing highest_final_cert_slot
   (Votor::first_unpruned_slot). */

static ulong
first_unpruned_slot( fd_votor_t const * votor ) {
  return fd_alpenglow_first_slot_in_window( votor->highest_final_cert_slot );
}

/* ---------------------------------------------------------------------- */
/* set_timeouts / try_* / check_pending_blocks / prune                    */
/* ---------------------------------------------------------------------- */

/* set_timeouts emits the timeouts for the leader window starting at slot
   (Votor::set_timeouts).  The Rust version spawns a timer task that, after
   DELTA_TIMEOUT + DELTA_FIRST_SLICE, fires TimeoutCrashedLeader(slot) and then,
   stepping by DELTA_BLOCK per slot, fires Timeout(s) for every slot in the
   window.  The C port simply emits the corresponding fd_votor_timeout_t's; the
   tile attaches the actual deadlines.  Panics (FD_TEST) if slot is not the
   start of a window. */

static void
set_timeouts( fd_votor_t *     votor,
              ulong            slot,
              fd_votor_out_t * out ) {
  (void)votor;
  FD_TEST( fd_alpenglow_is_start_of_window( slot ) );
  out_push_timeout( out, FD_VOTOR_TIMEOUT_CRASHED_LEADER, slot );
  ulong last = fd_alpenglow_last_slot_in_window( slot );
  for( ulong s=slot; s<=last; s++ ) {
    out_push_timeout( out, FD_VOTOR_TIMEOUT_TIMEOUT, s );
  }
}

/* Forward decls (mutual recursion try_notar <-> check_pending_blocks). */

static int  try_notar          ( fd_votor_t * votor, ulong slot, fd_block_id_t const * block_id, fd_block_id_t const * parent_block_id, fd_votor_out_t * out );
static void try_skip_window     ( fd_votor_t * votor, ulong slot, fd_votor_out_t * out );
static void check_pending_blocks( fd_votor_t * votor, fd_votor_out_t * out );

/* try_final sends a finalization vote for (slot,hash) if the conditions are
   met (Votor::try_final).  The bad_window flag (not_bad) is the load-bearing
   slashing invariant: once any skip / notar-fallback / skip-fallback set
   bad_window for a slot, Final is permanently disabled for it. */

static void
try_final( fd_votor_t *      votor,
           ulong             slot,
           fd_hash_t const * hash,
           fd_votor_out_t *  out ) {
  FD_TEST( slot >= first_unpruned_slot( votor ) );
  fd_votor_slot_state_t const * s = slot_state_query_const( votor, slot );
  int notarized   = s && s->has_block_notarized && !memcmp( s->block_notarized.uc, hash->uc, sizeof(fd_hash_t) );
  int voted_notar = s && s->has_voted_notar     && !memcmp( s->voted_notar.uc,     hash->uc, sizeof(fd_hash_t) );
  int not_bad     = !( s && s->bad_window );
  if( notarized && voted_notar && not_bad ) {
    fd_ag_vote_t vote;
    fd_vote_new_final( &vote, slot, &votor->voting_key, VOTOR_SIGNER_UNSET );
    out_push_vote( out, &vote );
    slot_state_mut( votor, slot )->retired = 1;
  }
}

/* try_notar sends a notar vote for the given block if the conditions are met
   (Votor::try_notar).  Returns 1 iff we decided to send a notar vote.

   The first-slot-of-window rule: the block's parent must be in this slot's
   parents_ready set.  The non-first-slot rule: the parent must be the
   immediately-previous slot AND we must have voted notar for that exact parent
   hash. */

static int
try_notar( fd_votor_t *          votor,
           ulong                 slot,
           fd_block_id_t const * block_id,
           fd_block_id_t const * parent_block_id,
           fd_votor_out_t *      out ) {
  FD_TEST( slot >= first_unpruned_slot( votor ) );
  fd_hash_t const * hash        = &block_id->hash;
  ulong             parent_slot = parent_block_id->slot;
  fd_hash_t const * parent_hash = &parent_block_id->hash;
  ulong             first_slot  = fd_alpenglow_first_slot_in_window( slot );

  if( slot==first_slot ) {
    int valid_parent = 0;
    fd_votor_slot_state_t const * s = slot_state_query_const( votor, slot );
    if( s ) {
      for( ulong i=0UL; i<s->parents_ready_cnt; i++ ) {
        if( fd_block_id_eq( &s->parents_ready[i], parent_block_id ) ) { valid_parent = 1; break; }
      }
    }
    if( !valid_parent ) return 0;
  } else {
    if( parent_slot != slot-1UL ) return 0;
    fd_votor_slot_state_t const * ps = slot_state_query_const( votor, parent_slot );
    int matches = ps && ps->has_voted_notar && !memcmp( ps->voted_notar.uc, parent_hash->uc, sizeof(fd_hash_t) );
    if( !matches ) return 0;
  }

  fd_ag_vote_t vote;
  fd_vote_new_notar( &vote, slot, hash, &votor->voting_key, VOTOR_SIGNER_UNSET );
  FD_BASE58_ENCODE_32_BYTES( hash->uc, hash_cstr );
  FD_LOG_NOTICE(( "try_notar slot=%lu hash=%s", slot, hash_cstr ));
  out_push_vote( out, &vote );

  fd_votor_slot_state_t * state = slot_state_mut( votor, slot );
  state->voted             = 1;
  state->has_voted_notar   = 1;
  state->voted_notar       = *hash;
  state->has_pending_block = 0;

  try_final( votor, slot, hash, out );
  return 1;
}

/* try_skip_window sends skip votes for all unvoted slots in the window that
   slot belongs to (Votor::try_skip_window).  Each cast sets voted=1 and
   bad_window=1 (the slashing invariant). */

static void
try_skip_window( fd_votor_t *     votor,
                 ulong            slot,
                 fd_votor_out_t * out ) {
  FD_TEST( slot >= first_unpruned_slot( votor ) );
  ulong first = fd_alpenglow_first_slot_in_window( slot );
  ulong last  = fd_alpenglow_last_slot_in_window( slot );
  for( ulong s=first; s<=last; s++ ) {
    if( has_voted( votor, s ) ) continue;
    fd_votor_slot_state_t * state = slot_state_mut( votor, s );
    state->voted      = 1;
    state->bad_window = 1;
    fd_ag_vote_t vote;
    fd_vote_new_skip( &vote, s, &votor->voting_key, VOTOR_SIGNER_UNSET );
    FD_LOG_NOTICE(( "try_skip_window slot=%lu", s ));
    out_push_vote( out, &vote );
  }
}

/* check_pending_blocks tries to vote on any pending blocks now
   (Votor::check_pending_blocks).  It snapshots the set of slots with a pending
   block, then calls try_notar for each (re-reading the pending block each
   time, since a prior try_notar may have cleared it). */

static void
check_pending_blocks( fd_votor_t *     votor,
                      fd_votor_out_t * out ) {
  slot_pool_t * pool = slot_pool( votor );
  slot_map_t  * map  = slot_map ( votor );

  /* Collect slots with a pending block.  We iterate the map and snapshot the
     slot keys; try_notar can mutate state (and clear pending_block) but does
     not remove map entries, so the iteration set stays valid. */

  for( slot_map_iter_t iter = slot_map_iter_init( map, pool );
       !slot_map_iter_done( iter, map, pool );
       iter = slot_map_iter_next( iter, map, pool ) ) {
    fd_votor_slot_state_t * s = slot_map_iter_ele( iter, map, pool );
    if( !s->has_pending_block ) continue;
    ulong         slot            = s->slot;
    fd_block_id_t block_id        = s->pending_block_id;
    fd_block_id_t parent_block_id = s->pending_parent_block_id;
    try_notar( votor, slot, &block_id, &parent_block_id, out );
  }
}

/* prune drops voting state for slots below first_unpruned_slot
   (Votor::prune, which is slots = slots.split_off(&first_unpruned_slot())). */

static void
prune( fd_votor_t * votor ) {
  slot_pool_t * pool   = slot_pool( votor );
  slot_map_t  * map    = slot_map ( votor );
  ulong         cutoff = first_unpruned_slot( votor );

  /* Iterate the map; for each slot < cutoff, remove it from the map and
     release it back to the pool.  Because removing an element invalidates the
     current iterator, we restart the scan whenever we remove one. */

  int again = 1;
  while( again ) {
    again = 0;
    for( slot_map_iter_t iter = slot_map_iter_init( map, pool );
         !slot_map_iter_done( iter, map, pool );
         iter = slot_map_iter_next( iter, map, pool ) ) {
      fd_votor_slot_state_t * s = slot_map_iter_ele( iter, map, pool );
      if( s->slot < cutoff ) {
        slot_map_ele_remove( map, &s->slot, NULL, pool );
        slot_pool_ele_release( pool, s );
        again = 1;
        break;
      }
    }
  }
}

/* ---------------------------------------------------------------------- */
/* handle_cert_created                                                    */
/* ---------------------------------------------------------------------- */

/* handle_cert_created updates state based on a newly created cert and
   re-broadcasts it (Votor::handle_cert_created). */

static void
handle_cert_created( fd_votor_t *      votor,
                     fd_cert_t const * cert,
                     fd_votor_out_t *  out ) {
  switch( cert->discriminant ) {
  case FD_CERT_TYPE_NOTAR: {
    fd_hash_t const * hash = fd_cert_block_hash( cert );
    ulong             slot = fd_cert_slot( cert );
    /* need to mark notarized BEFORE trying finalization */
    fd_votor_slot_state_t * s = slot_state_mut( votor, slot );
    s->has_block_notarized = 1;
    s->block_notarized     = *hash;
    try_final( votor, slot, hash, out );
    break;
  }
  case FD_CERT_TYPE_FINAL:
  case FD_CERT_TYPE_FAST_FINAL: {
    ulong slot = fd_cert_slot( cert );
    /* makes sure we eventually vote skip for these slots, even if we never
       issued a ParentReady for this window */
    set_timeouts( votor, fd_alpenglow_first_slot_in_window( slot ), out );
    /* Votor can already be pruned upon regular final cert */
    votor->highest_final_cert_slot = fd_ulong_max( votor->highest_final_cert_slot, slot );
    prune( votor );
    break;
  }
  default:
    break;
  }
  out_push_cert( out, cert );
}

/* ---------------------------------------------------------------------- */
/* should_ignore_pool_event                                               */
/* ---------------------------------------------------------------------- */

static ulong
pool_event_slot( fd_votor_pool_event_t const * event ) {
  switch( event->discriminant ) {
  case FD_VOTOR_POOL_EVENT_PARENT_READY:  return event->inner.parent_ready.slot;
  case FD_VOTOR_POOL_EVENT_SAFE_TO_NOTAR: return event->inner.safe_to_notar.slot;
  case FD_VOTOR_POOL_EVENT_SAFE_TO_SKIP:  return event->inner.safe_to_skip;
  case FD_VOTOR_POOL_EVENT_CERT_CREATED:  return fd_cert_slot( &event->inner.cert_created );
  default:                                return event->inner.standstill.slot; /* Standstill */
  }
}

static int
should_ignore_pool_event( fd_votor_t *                  votor,
                          fd_votor_pool_event_t const * event ) {
  ulong slot = pool_event_slot( event );
  switch( event->discriminant ) {
  case FD_VOTOR_POOL_EVENT_STANDSTILL:
    return 0; /* never ignored */
  case FD_VOTOR_POOL_EVENT_CERT_CREATED:
    return slot < first_unpruned_slot( votor );
  default: /* ParentReady / SafeToNotar / SafeToSkip */
    return slot < first_unpruned_slot( votor ) || is_retired( votor, slot );
  }
}

/* ---------------------------------------------------------------------- */
/* Public handlers                                                        */
/* ---------------------------------------------------------------------- */

void
fd_votor_handle_pool_event( fd_votor_t *                  votor,
                            fd_votor_pool_event_t const * event,
                            fd_votor_out_t *              out ) {
  if( should_ignore_pool_event( votor, event ) ) return;

  switch( event->discriminant ) {

  case FD_VOTOR_POOL_EVENT_PARENT_READY: {
    ulong               slot   = event->inner.parent_ready.slot;
    fd_block_id_t const parent = event->inner.parent_ready.parent;
    fd_votor_slot_state_t * s = slot_state_mut( votor, slot );
    /* insert parent into parents_ready (set semantics: dedup) */
    int present = 0;
    for( ulong i=0UL; i<s->parents_ready_cnt; i++ ) {
      if( fd_block_id_eq( &s->parents_ready[i], &parent ) ) { present = 1; break; }
    }
    if( !present ) {
      FD_TEST( s->parents_ready_cnt < FD_VOTOR_PARENTS_READY_MAX );
      s->parents_ready[ s->parents_ready_cnt++ ] = parent;
    }
    check_pending_blocks( votor, out );
    set_timeouts( votor, slot, out );
    break;
  }

  case FD_VOTOR_POOL_EVENT_SAFE_TO_NOTAR: {
    fd_block_id_t const blk = event->inner.safe_to_notar;
    fd_ag_vote_t vote;
    fd_vote_new_notar_fallback( &vote, blk.slot, &blk.hash, &votor->voting_key, VOTOR_SIGNER_UNSET );
    out_push_vote( out, &vote );
    try_skip_window( votor, blk.slot, out );
    slot_state_mut( votor, blk.slot )->bad_window = 1;
    break;
  }

  case FD_VOTOR_POOL_EVENT_SAFE_TO_SKIP: {
    ulong slot = event->inner.safe_to_skip;
    fd_ag_vote_t vote;
    fd_vote_new_skip_fallback( &vote, slot, &votor->voting_key, VOTOR_SIGNER_UNSET );
    out_push_vote( out, &vote );
    try_skip_window( votor, slot, out );
    slot_state_mut( votor, slot )->bad_window = 1;
    break;
  }

  case FD_VOTOR_POOL_EVENT_CERT_CREATED:
    handle_cert_created( votor, &event->inner.cert_created, out );
    break;

  case FD_VOTOR_POOL_EVENT_STANDSTILL: {
    /* re-broadcast the recovery bundle (certs then votes) verbatim */
    for( ulong i=0UL; i<event->inner.standstill.bundle_cnt; i++ ) {
      out_push_msg( out, &event->inner.standstill.bundle[i] );
    }
    break;
  }

  default:
    break;
  }
}

void
fd_votor_handle_blockstore_event( fd_votor_t *                        votor,
                                  fd_votor_blockstore_event_t const * event,
                                  fd_votor_out_t *                    out ) {
  ulong slot;
  switch( event->discriminant ) {
  case FD_VOTOR_BLOCKSTORE_EVENT_FIRST_SHRED:   slot = event->inner.first_shred;   break;
  case FD_VOTOR_BLOCKSTORE_EVENT_INVALID_BLOCK: slot = event->inner.invalid_block; break;
  default:                                      slot = event->inner.block.slot;    break;
  }

  if( slot <= votor->highest_final_cert_slot || is_retired( votor, slot ) ) return;

  switch( event->discriminant ) {

  case FD_VOTOR_BLOCKSTORE_EVENT_FIRST_SHRED:
    slot_state_mut( votor, slot )->received_shred = 1;
    break;

  case FD_VOTOR_BLOCKSTORE_EVENT_INVALID_BLOCK:
    try_skip_window( votor, slot, out );
    break;

  case FD_VOTOR_BLOCKSTORE_EVENT_BLOCK: {
    fd_block_id_t const block_id        = event->inner.block.block_id;
    fd_block_id_t const parent_block_id = event->inner.block.parent_block_id;
    if( has_voted( votor, slot ) ) return; /* already voted */
    if( try_notar( votor, slot, &block_id, &parent_block_id, out ) ) {
      check_pending_blocks( votor, out );
    } else {
      fd_votor_slot_state_t * s = slot_state_mut( votor, slot );
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
fd_votor_handle_timeout_event( fd_votor_t *               votor,
                               fd_votor_timeout_t const * event,
                               fd_votor_out_t *           out ) {
  ulong slot = event->slot;
  if( slot <= votor->highest_final_cert_slot || is_retired( votor, slot ) ) return;

  switch( event->kind ) {
  case FD_VOTOR_TIMEOUT_TIMEOUT:
    if( !has_voted( votor, slot ) ) try_skip_window( votor, slot, out );
    break;
  case FD_VOTOR_TIMEOUT_CRASHED_LEADER:
    if( !received_shred( votor, slot ) && !has_voted( votor, slot ) ) try_skip_window( votor, slot, out );
    break;
  default:
    break;
  }
}

/* ---------------------------------------------------------------------- */
/* new / join / leave / delete + accessors                               */
/* ---------------------------------------------------------------------- */

void *
fd_votor_new( void *                 shmem,
              ulong                  slot_max,
              fd_aggsig_sk_t const * voting_key,
              ulong                  seed,
              fd_votor_out_t *       out ) {

  if( FD_UNLIKELY( !shmem ) ) {
    FD_LOG_WARNING(( "NULL mem" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shmem, fd_votor_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned mem" ));
    return NULL;
  }

  ulong footprint = fd_votor_footprint( slot_max );
  if( FD_UNLIKELY( !footprint ) ) {
    FD_LOG_WARNING(( "bad slot_max (%lu)", slot_max ));
    return NULL;
  }

  fd_wksp_t * ws = fd_wksp_containing( shmem );
  if( FD_UNLIKELY( !ws ) ) {
    FD_LOG_WARNING(( "shmem must be part of a workspace" ));
    return NULL;
  }

  fd_memset( shmem, 0, footprint );

  slot_max        = fd_ulong_pow2_up( slot_max );
  ulong chain_cnt = slot_map_chain_cnt_est( slot_max );

  FD_SCRATCH_ALLOC_INIT( l, shmem );
  fd_votor_t * votor     = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_votor_t), sizeof(fd_votor_t)              );
  void *       slot_pool = FD_SCRATCH_ALLOC_APPEND( l, slot_pool_align(),   slot_pool_footprint( slot_max ) );
  void *       slot_map  = FD_SCRATCH_ALLOC_APPEND( l, slot_map_align(),    slot_map_footprint ( chain_cnt) );
  FD_TEST( FD_SCRATCH_ALLOC_FINI( l, fd_votor_align() ) == (ulong)shmem + footprint );

  votor->wksp_gaddr              = fd_wksp_gaddr_fast( ws, votor );
  votor->slot_pool_gaddr         = fd_wksp_gaddr_fast( ws, slot_pool_join( slot_pool_new( slot_pool, slot_max             ) ) );
  votor->slot_map_gaddr          = fd_wksp_gaddr_fast( ws, slot_map_join ( slot_map_new ( slot_map,  chain_cnt, seed      ) ) );
  votor->voting_key              = *voting_key;
  votor->highest_final_cert_slot = 0UL; /* Slot::genesis() */

  /* Pre-populate the dummy genesis block's state (Votor::new): voted=true,
     voted_notar = GENESIS_BLOCK_HASH (all-zero), block_notarized =
     GENESIS_BLOCK_HASH, parents_ready = {(genesis, GENESIS_BLOCK_HASH)},
     retired = true. */

  {
    fd_votor_slot_state_t * g = slot_state_mut( votor, 0UL /* Slot::genesis() */ );
    fd_hash_t genesis_hash; fd_memset( &genesis_hash, 0, sizeof(fd_hash_t) ); /* GENESIS_BLOCK_HASH */
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

  /* set_timeouts(Slot::new(0)) */
  if( FD_LIKELY( out ) ) set_timeouts( votor, 0UL, out );

  return shmem;
}

fd_votor_t *
fd_votor_join( void * shvotor ) {
  fd_votor_t * votor = (fd_votor_t *)shvotor;

  if( FD_UNLIKELY( !votor ) ) {
    FD_LOG_WARNING(( "NULL votor" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)votor, fd_votor_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned votor" ));
    return NULL;
  }

  return votor;
}

void *
fd_votor_leave( fd_votor_t const * votor ) {
  if( FD_UNLIKELY( !votor ) ) {
    FD_LOG_WARNING(( "NULL votor" ));
    return NULL;
  }
  return (void *)votor;
}

void *
fd_votor_delete( void * shvotor ) {
  if( FD_UNLIKELY( !shvotor ) ) {
    FD_LOG_WARNING(( "NULL votor" ));
    return NULL;
  }
  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shvotor, fd_votor_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned votor" ));
    return NULL;
  }
  return shvotor;
}

ulong
fd_votor_highest_final_cert_slot( fd_votor_t const * votor ) {
  return votor->highest_final_cert_slot;
}

fd_votor_slot_state_t const *
fd_votor_slot_state( fd_votor_t const * votor, ulong slot ) {
  return slot_state_query_const( votor, slot );
}
