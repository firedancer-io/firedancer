#define _GNU_SOURCE /* syscall, RENAME_EXCHANGE */
#include "fd_tower_tile.h"
#include "../../choreo/tower/fd_tower_file.h"
#include <linux/futex.h>
#include "generated/fd_tower_tile_seccomp.h"

#include "../../choreo/eqvoc/fd_eqvoc.h"
#include "../../choreo/ghost/fd_ghost.h"
#include "../../choreo/hfork/fd_hfork.h"
#include "../../choreo/votes/fd_votes.h"
#include "../../choreo/tower/fd_tower.h"
#include "../../choreo/tower/fd_tower_serdes.h"
#include "../../choreo/tower/fd_tower_stakes.h"
#include "../../disco/fd_txn_p.h"
#include "../../disco/events/generated/fd_event_gen.h"
#include "../../disco/shred/fd_shred_tile.h"
#include "../../disco/keyguard/fd_keyguard.h"
#include "../../disco/keyguard/fd_keyload.h"
#include "../../disco/keyguard/fd_keyswitch.h"
#include "../../disco/metrics/fd_metrics.h"
#include "../../disco/node_info/fd_node_info.h"
#include "../../disco/topo/fd_topo.h"
#include "../../disco/fd_txn_m.h"
#include "../../discof/replay/fd_replay_tile.h"
#include "../../flamenco/leaders/fd_multi_epoch_leaders.h"
#include "../../flamenco/runtime/fd_bank.h"
#include "../../flamenco/leaders/fd_multi_epoch_leaders.h"
#include "../../flamenco/runtime/fd_system_ids.h"
#include "../../flamenco/runtime/sysvar/fd_sysvar_slot_history.h"
#include "../../flamenco/runtime/program/vote/fd_vote_state_versioned.h"
#include "../../flamenco/runtime/program/vote/fd_vote_codec_tmpl.h"
#include "../../util/pod/fd_pod.h"
#include "../../util/fd_hash32.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/syscall.h>

/* The Tower tile broadly processes three classes of frags, leading to
   three distinct kinds of frag processing:

   1. Processing vote _accounts_ (after replaying a block)

      When Replay finishes executing a block, Tower reads back the vote
      account state for every staked validator.  This is deterministic:
      the vote account state is the result of executing all vote txns in
      the block through the vote program, so it is guaranteed to
      converge with Agave's view of the same accounts.  Tower uses these
      accounts to run the fork choice rule (fd_ghost) and TowerBFT
      (fd_tower).

   2. Processing vote _transactions_ (at arbitrary points in time)

      Tower also receives vote txns from Gossip and TPU.  These arrive
      at arbitrary, nondeterministic times because Gossip and TPU are
      both unreliable mediums: there's no guarantee we observe all the
      same vote txns as Agave (nor another Firedancer, for that matter).

      Tower is stricter than Agave when validating these vote txns (e.g.
      we use is_simple_vote which requires at most two signers, whereas
      Agave's Gossip vote parser does not).  Being stricter is
      acceptable given vote txns from Gossip and TPU are inherently
      unreliable, so dropping a small number of votes that Agave allows
      but Firedancer does not is not significant to convergence.

      However, these same vote txns are (redundantly) transmitted as
      part of a block as well ie. through Replay.  The validation of
      these Replay-sourced vote txns _is_ one-to-one with Agave (namely
      the Vote Program), and critical for convergence.  Specifically, we
      only process Replay vote txns that have been successfully executed
      when counting them towards confirmations.

      The guarantee is "eventual consistency": even though individual
      Gossip or TPU vote txns may be lost, we are guaranteed to
      "eventually" confirm a block and converge with Agave as long as we
      receive the block and replay its contained vote txns, because our
      vote programs match 1-1.  Gossip / TPU can provide a fast-path for
      earlier confirmations as well as a source of security via
      redundancy in case we are not receiving the blocks from the rest
      of the network.

      The processing of vote txns is important to (as already alluded)
      fd_votes and fd_hfork.

  3. Processing "other" frags.  Vote account and vote transaction
     processing (1 and 2 above) is the meat and potatoes, but Tower also
     processes several auxiliary frag types:

      a. Duplicate shred gossip messages (from the gossip tile): Tower
         receives duplicate shred proofs from other validators via
         gossip.  These proofs arrive in chunks (fd_eqvoc_chunk_insert)
         and are reassembled and cryptographically verified before being
         accepted.

      b. Epoch stake updates (from the replay tile): Tower receives
         epoch stake information to maintain the leader schedule via
         fd_stake_ci, which is needed by eqvoc for signature
         verification of shred proofs.

      c. Shred version (from the ipecho tile): Tower receives the shred
         version from ipecho to configure eqvoc's shred version
         filtering for proof verification.

      d. Shreds (from the shred tile): Tower checks incoming shreds for
         equivocation via fd_eqvoc.  If two conflicting shreds are
         detected for the same FEC set, Tower constructs a duplicate
         proof and publishes it (FD_TOWER_SIG_SLOT_DUPLICATE).

      e. Slot dead (from the replay tile): Tower records a NULL bank
         hash for dead slots in the hard fork detector (fd_hfork).

   Tower signals to other tiles about events that occur as a result of
   those three modes, such as what block to vote on, what block to reset
   onto as leader, what block got rooted, what blocks are duplicates,
   and what blocks are confirmed.

   In general, Tower uses "block_id" as the identifier for a block.  The
   block_id is the merkle root of the last FEC set for a block.  Unlike
   slot numbers, this is guaranteed to be unique for a given block and
   is therefore a canonical identifier because slot numbers can identify
   multiple blocks, if a leader equivocates (produces multiple blocks
   for the same slot), whereas it is not feasible for a leader to
   produce block_id collisions.

   However, the block_id was only introduced into the Solana protocol
   recently, and TowerBFT still uses the "legacy" identifier of slot
   numbers for blocks.  So the tile (and relevant modules) will use
   block_id when possible to interface with the protocol but otherwise
   fallback to slot number when block_id is unsupported due to limits of
   the protocol. */

#define LOGGING 0

#define IN_KIND_DEDUP  (0)
#define IN_KIND_EPOCH  (1)
#define IN_KIND_REPLAY (2)
#define IN_KIND_GOSSIP (3)
#define IN_KIND_IPECHO (4)
#define IN_KIND_SHRED  (5)
#define IN_KIND_SIGN   (6)

#define OUT_IDX 0 /* only a single out link tower_out */

#include "fd_tower_tile_private.h"

/* Compile-time dependency injection.  This macro defaults to the
   production implementation defined below.  Tests can #define it before
   #include-ing this file to substitute a mock. */

#ifndef QUERY_TOWERS
#define QUERY_TOWERS query_towers
#endif

#ifndef QUERY_VOTERS
#define QUERY_VOTERS query_voters
#endif

ulong QUERY_TOWERS( fd_tower_tile_t *, fd_replay_slot_completed_t *, fd_ghost_blk_t *, int *, ulong *, ushort * );
void  QUERY_VOTERS( fd_tower_tile_t *, fd_replay_slot_completed_t *, ulong );

/* vote_account_config extracts configuration of this validator's vote
   account (on-chain state).  data points to the first byte of the
   vote account's data.  Sets:
   - *authority_out to the selected authorized voter's public key
   - *authority_idx_out to the tile's auth_vtr index (matches sign tile)
     or ULONG_MAX it the authorized voter is the node identity
     or LONG_MAX if it matches neither
   - *node_pubkey to the vote account's pubkey
  Returns 1 if the validator has a key for the found vote authority,
  and 0 otherwise. */

static int
vote_account_config( fd_tower_tile_t * ctx,
                     uchar const *     data,
                     ulong             data_sz,
                     ulong             epoch,
                     fd_pubkey_t *     authority_out,
                     ulong *           authority_idx_out,
                     fd_pubkey_t *     node_pubkey_out ) {

  fd_vote_state_versioned_t vsv[1];
  FD_CHECK_CRIT( fd_vote_state_versioned_deserialize( vsv, data, data_sz ), "unable to decode vote state versioned" );

  fd_pubkey_t const * auth_vtr_addr = NULL;
  switch( vsv->kind ) {
    case fd_vote_state_versioned_enum_v1_14_11:
      *node_pubkey_out = vsv->v1_14_11.node_pubkey;
      for( fd_vote_authorized_voters_treap_rev_iter_t iter = fd_vote_authorized_voters_treap_rev_iter_init( vsv->v1_14_11.authorized_voters.treap, vsv->v1_14_11.authorized_voters.pool );
           !fd_vote_authorized_voters_treap_rev_iter_done( iter );
           iter = fd_vote_authorized_voters_treap_rev_iter_next( iter, vsv->v1_14_11.authorized_voters.pool ) ) {
        fd_vote_authorized_voter_t * ele = fd_vote_authorized_voters_treap_rev_iter_ele( iter, vsv->v1_14_11.authorized_voters.pool );
        if( FD_LIKELY( ele->epoch<=epoch ) ) {
          auth_vtr_addr = &ele->pubkey;
          break;
        }
      }
      break;
    case fd_vote_state_versioned_enum_v3:
      *node_pubkey_out = vsv->v3.node_pubkey;
      for( fd_vote_authorized_voters_treap_rev_iter_t iter = fd_vote_authorized_voters_treap_rev_iter_init( vsv->v3.authorized_voters.treap, vsv->v3.authorized_voters.pool );
          !fd_vote_authorized_voters_treap_rev_iter_done( iter );
          iter = fd_vote_authorized_voters_treap_rev_iter_next( iter, vsv->v3.authorized_voters.pool ) ) {
        fd_vote_authorized_voter_t * ele = fd_vote_authorized_voters_treap_rev_iter_ele( iter, vsv->v3.authorized_voters.pool );
        if( FD_LIKELY( ele->epoch<=epoch ) ) {
          auth_vtr_addr = &ele->pubkey;
          break;
        }
      }
      break;
    case fd_vote_state_versioned_enum_v4:
      *node_pubkey_out = vsv->v4.node_pubkey;
      for( fd_vote_authorized_voters_treap_rev_iter_t iter = fd_vote_authorized_voters_treap_rev_iter_init( vsv->v4.authorized_voters.treap, vsv->v4.authorized_voters.pool );
          !fd_vote_authorized_voters_treap_rev_iter_done( iter );
          iter = fd_vote_authorized_voters_treap_rev_iter_next( iter, vsv->v4.authorized_voters.pool ) ) {
        fd_vote_authorized_voter_t * ele = fd_vote_authorized_voters_treap_rev_iter_ele( iter, vsv->v4.authorized_voters.pool );
        if( FD_LIKELY( ele->epoch<=epoch ) ) {
          auth_vtr_addr = &ele->pubkey;
          break;
        }
      }
      break;
    default:
      FD_LOG_CRIT(( "unsupported vote state versioned discriminant: %u", vsv->kind ));
  }

  FD_CHECK_CRIT( auth_vtr_addr, "unable to find authorized voter, likely corrupt vote account state" );
  *authority_out = *auth_vtr_addr;

  if( fd_pubkey_eq( auth_vtr_addr, ctx->identity_key ) ) {
    *authority_idx_out = ULONG_MAX;
    return 1;
  }

  auth_vtr_t * auth_vtr = auth_vtr_query( ctx->auth_vtr, *auth_vtr_addr, NULL );
  if( FD_LIKELY( auth_vtr ) ) {
    *authority_idx_out = auth_vtr->paths_idx;
    return 1;
  }

  *authority_idx_out = LONG_MAX;
  return 0;
}

static void
update_metrics_eqvoc( fd_tower_tile_t * ctx,
                      int               err ) {
  ctx->metrics.eqvoc_success += (ulong)(err==FD_EQVOC_SUCCESS);
  ctx->metrics.eqvoc_err     += (ulong)(err<0);
}

static void
update_metrics_ghost( fd_tower_tile_t * ctx,
                      int               err ) {
  ctx->metrics.ghost[ FD_METRICS_ENUM_GHOST_VOTE_RESULT_V_SUCCESS_IDX       ] += (ulong)(err==FD_GHOST_SUCCESS);
  ctx->metrics.ghost[ FD_METRICS_ENUM_GHOST_VOTE_RESULT_V_NOT_VOTED_IDX     ] += (ulong)(err==FD_GHOST_ERR_NOT_VOTED);
  ctx->metrics.ghost[ FD_METRICS_ENUM_GHOST_VOTE_RESULT_V_TOO_OLD_IDX       ] += (ulong)(err==FD_GHOST_ERR_VOTE_TOO_OLD);
  ctx->metrics.ghost[ FD_METRICS_ENUM_GHOST_VOTE_RESULT_V_ALREADY_VOTED_IDX ] += (ulong)(err==FD_GHOST_ERR_ALREADY_VOTED);
}

static void
update_metrics_hfork( fd_tower_tile_t * ctx,
                      int               hfork_err,
                      ulong             slot,
                      fd_hash_t const * block_id ) {
  switch( hfork_err ) {
  case FD_HFORK_SUCCESS_MATCHED:
    ctx->metrics.hfork[ FD_METRICS_ENUM_HARD_FORK_VOTE_RESULT_V_SUCCESS_MATCHED_IDX ]++;
    ctx->metrics.hfork_matched_slot = fd_ulong_max( ctx->metrics.hfork_matched_slot, slot );
    break;
  case FD_HFORK_SUCCESS:
    ctx->metrics.hfork[ FD_METRICS_ENUM_HARD_FORK_VOTE_RESULT_V_SUCCESS_IDX ]++;
    break;
  case FD_HFORK_ERR_MISMATCHED:
    ctx->metrics.hfork[ FD_METRICS_ENUM_HARD_FORK_VOTE_RESULT_V_MISMATCHED_IDX ]++;
    if( FD_UNLIKELY( ctx->hard_fork_fatal ) ) {
      FD_BASE58_ENCODE_32_BYTES( block_id->uc, _block_id );
      FD_LOG_ERR(( "HARD FORK DETECTED for slot %lu block ID `%s`", slot, _block_id ));
    }
    ctx->metrics.hfork_mismatched_slot = fd_ulong_max( ctx->metrics.hfork_mismatched_slot, slot );
    break;
  case FD_HFORK_ERR_UNKNOWN_VTR:
    ctx->metrics.hfork[ FD_METRICS_ENUM_HARD_FORK_VOTE_RESULT_V_UNKNOWN_VOTER_IDX ]++;
    break;
  case FD_HFORK_ERR_ALREADY_VOTED:
    ctx->metrics.hfork[ FD_METRICS_ENUM_HARD_FORK_VOTE_RESULT_V_ALREADY_VOTED_IDX ]++;
    break;
  case FD_HFORK_ERR_VOTE_TOO_OLD:
    ctx->metrics.hfork[ FD_METRICS_ENUM_HARD_FORK_VOTE_RESULT_V_TOO_OLD_IDX ]++;
    break;
  default:
    FD_LOG_ERR(( "unhandled hfork_err %d", hfork_err ));
  }
}

static void
update_metrics_vote_slot( fd_tower_tile_t * ctx,
                          int               err ) {
  ctx->metrics.vote_slots[ FD_METRICS_ENUM_VOTE_SLOT_RESULT_V_SUCCESS_IDX       ] += (ulong)(err==FD_VOTES_SUCCESS);
  ctx->metrics.vote_slots[ FD_METRICS_ENUM_VOTE_SLOT_RESULT_V_TOO_NEW_IDX       ] += (ulong)(err==FD_VOTES_ERR_VOTE_TOO_NEW);
  ctx->metrics.vote_slots[ FD_METRICS_ENUM_VOTE_SLOT_RESULT_V_UNKNOWN_VOTER_IDX   ] += (ulong)(err==FD_VOTES_ERR_UNKNOWN_VTR);
  ctx->metrics.vote_slots[ FD_METRICS_ENUM_VOTE_SLOT_RESULT_V_ALREADY_VOTED_IDX ] += (ulong)(err==FD_VOTES_ERR_ALREADY_VOTED);
}

static int
event_level_from_tower( int tower_level ) {
  switch( tower_level ) {
  case FD_TOWER_SLOT_CONFIRMED_PROPAGATED: return FD_EVENT_SLOT_CONFIRMED_LEVEL_PROPAGATED;
  case FD_TOWER_SLOT_CONFIRMED_DUPLICATE:  return FD_EVENT_SLOT_CONFIRMED_LEVEL_DUPLICATE;
  case FD_TOWER_SLOT_CONFIRMED_OPTIMISTIC: return FD_EVENT_SLOT_CONFIRMED_LEVEL_OPTIMISTIC;
  case FD_TOWER_SLOT_CONFIRMED_SUPER:      return FD_EVENT_SLOT_CONFIRMED_LEVEL_SUPER;
  default: FD_LOG_ERR(( "unexpected tower confirmation level %d", tower_level ));
  }
}

static void
report_slot_confirmed( ulong             bank_seq,
                       ulong             slot,
                       fd_hash_t const * block_id,
                       ulong             stake,
                       ulong             total_stake,
                       int               valid,
                       int               level,
                       int               forward ) {
  fd_event_slot_confirmed_t ev = {
    .bank_seq    = bank_seq,
    .slot        = slot,
    .stake       = stake,
    .total_stake = total_stake,
    .valid       = valid,
    .level       = level,
    .forward     = forward,
  };
  fd_memcpy( ev.block_id, block_id->uc, sizeof(fd_hash_t) );
  fd_event_report_slot_confirmed( &ev );
}

struct block_equivocated_args {
  ulong             slot;
  ulong             parent_slot;
  ulong             epoch;
  fd_hash_t const * block_id;          /* our replayed block (or the just-replayed block) */
  fd_hash_t const * sibling_block_id;  /* conflicting block; NULL if unknown (shred proof) */
  fd_hash_t const * bank_hash;         /* our block's bank hash; NULL if not replayed locally */
  fd_hash_t const * block_hash;        /* our block's last microblock hash; NULL if not replayed locally */
  ulong             bank_seq;          /* our replayed bank seq; 0 if no local bank */
  int               is_leader;
  int               our_block_voted;
  int               our_block_confirmed;
  ulong             block_stake;       /* stake voted on our replayed block; 0 if none/unknown */
  ulong             sibling_stake;     /* stake on the conflicting block; 0 if unknown */
  ulong             total_stake;       /* 0 if unknown */
  int               detection;
};
typedef struct block_equivocated_args block_equivocated_args_t;

static ulong
votes_stake( fd_tower_tile_t * ctx, ulong slot, fd_hash_t const * block_id ) {
  fd_votes_blk_t * vb = fd_votes_query( ctx->votes, slot, block_id );
  return vb ? vb->stake : 0UL;
}

static int
our_block_confirmed( fd_tower_blk_t const * blk ) {
  return blk && blk->confirmed && 0==memcmp( &blk->replayed_block_id, &blk->confirmed_block_id, sizeof(fd_hash_t) );
}

static void
report_block_equivocated( block_equivocated_args_t const * a ) {
  fd_event_block_equivocated_t ev = {
    .slot                = a->slot,
    .parent_slot         = a->parent_slot,
    .epoch               = a->epoch,
    .bank_seq            = a->bank_seq,
    .is_leader           = a->is_leader,
    .our_block_voted     = a->our_block_voted,
    .our_block_confirmed = a->our_block_confirmed,
    .block_stake         = a->block_stake,
    .sibling_stake       = a->sibling_stake,
    .total_stake         = a->total_stake,
    .detection           = a->detection,
  };
  fd_memcpy( ev.block_id, a->block_id->uc, sizeof(fd_hash_t) );
  if( FD_LIKELY( a->sibling_block_id ) ) fd_memcpy( ev.sibling_block_id, a->sibling_block_id->uc, sizeof(fd_hash_t) );
  if( FD_LIKELY( a->bank_hash        ) ) fd_memcpy( ev.bank_hash,        a->bank_hash->uc,        sizeof(fd_hash_t) );
  if( FD_LIKELY( a->block_hash       ) ) fd_memcpy( ev.block_hash,       a->block_hash->uc,       sizeof(fd_hash_t) );
  fd_event_report_block_equivocated( &ev );
}

static void
publish_slot_confirmed( fd_tower_tile_t * ctx,
                        ulong             slot,
                        fd_hash_t const * block_id,
                        ulong             total_stake ) {

  fd_tower_blk_t * tower_blk = fd_tower_blocks_query( ctx->tower, slot );
  fd_ghost_blk_t * ghost_blk = fd_ghost_query( ctx->ghost, block_id );
  fd_votes_blk_t * votes_blk = fd_votes_query( ctx->votes, slot, block_id );
  if( FD_UNLIKELY( !votes_blk ) ) return;

  static double const ratios[FD_TOWER_SLOT_CONFIRMED_LEVEL_CNT] = FD_TOWER_SLOT_CONFIRMED_RATIOS;
  int const           levels[FD_TOWER_SLOT_CONFIRMED_LEVEL_CNT] = FD_TOWER_SLOT_CONFIRMED_LEVELS;
  for( int i = 0; i < FD_TOWER_SLOT_CONFIRMED_LEVEL_CNT; i++ ) {
    if( FD_LIKELY( fd_uchar_extract_bit( votes_blk->flags, i ) ) ) continue; /* already contiguously confirmed */
    double ratio = (double)votes_blk->stake / (double)total_stake;
    if( FD_LIKELY( ratio <= ratios[i] ) ) break; /* threshold not met */

    /* If the ghost_blk is missing, then we know this is a forward
       confirmation (ie. we haven't replayed the block yet). */

    if( FD_UNLIKELY( !ghost_blk ) ) {
      if( fd_uchar_extract_bit( votes_blk->flags, i+4 ) ) continue; /* already forward confirmed */
      votes_blk->flags = fd_uchar_set_bit( votes_blk->flags, i+4 );
      publishes_push_head( ctx->publishes, (publish_t){ .sig = FD_TOWER_SIG_SLOT_CONFIRMED, .msg = { .slot_confirmed = (fd_tower_slot_confirmed_t){ .level = levels[i], .fwd = 1, .slot = votes_blk->key.slot, .block_id = votes_blk->key.block_id } } } );
      report_slot_confirmed( 0UL, votes_blk->key.slot, &votes_blk->key.block_id, votes_blk->stake, total_stake, 1 /* valid */, event_level_from_tower( levels[ i ] ), 1 /* forward */ );

      /* If we have a tower_blk for the slot when the ghost_blk is
         missing, we usually replayed an equivocating block_id that is
         not the confirmed_block_id.  The exception: ghost also prunes
         blocks we replayed whose fork lost, so an identical block_id
         means the cluster duplicate-confirmed a block our root already
         passed. Consensus divergence; halt deliberately.  Only
         relevant for the duplicate confirmed level. */

      if( FD_UNLIKELY( levels[i]==FD_TOWER_SLOT_CONFIRMED_DUPLICATE && tower_blk ) ) {
        if( FD_UNLIKELY( 0==memcmp( &tower_blk->replayed_block_id, &votes_blk->key.block_id, sizeof(fd_hash_t) ) ) ) {
          FD_BASE58_ENCODE_32_BYTES( votes_blk->key.block_id.uc, dup_blk_id );
          FD_LOG_CRIT(( "cluster duplicate-confirmed block %s (slot %lu), which we replayed but pruned: our root conflicts with the cluster", dup_blk_id, votes_blk->key.slot ));
        }
        tower_blk->confirmed          = 1;
        tower_blk->confirmed_block_id = votes_blk->key.block_id;
        FD_BASE58_ENCODE_32_BYTES( tower_blk->replayed_block_id.uc, eqvoc_blk_id );
        FD_LOG_DEBUG(( "[%s] equivocation detected via forward-confirmed block id mismatch (replayed before confirmed). slot: %lu. block_id: %s", __func__, votes_blk->key.slot, eqvoc_blk_id ));
        fd_ghost_eqvoc( ctx->ghost, &tower_blk->replayed_block_id );
        report_block_equivocated( &(block_equivocated_args_t){
          .slot = votes_blk->key.slot, .parent_slot = tower_blk->parent_slot, .epoch = tower_blk->epoch,
          .block_id = &tower_blk->replayed_block_id, .sibling_block_id = &votes_blk->key.block_id,
          .bank_hash = &tower_blk->bank_hash, .block_hash = &tower_blk->block_hash,
          .is_leader = tower_blk->leader, .our_block_voted = tower_blk->voted, .our_block_confirmed = our_block_confirmed( tower_blk ),
          .block_stake = votes_stake( ctx, votes_blk->key.slot, &tower_blk->replayed_block_id ),
          .sibling_stake = votes_blk->stake, .total_stake = total_stake,
          .detection = FD_EVENT_BLOCK_EQUIVOCATED_DETECTION_CONFIRM_MISMATCH } );
      }
      continue;
    }

    /* Otherwise if they are present, then we know this is not a forward
       confirmation and thus we have replayed and confirmed the block,
       which also implies we have replayed and confirmed all its
       ancestors.  So we publish confirmations for all its ancestors
       (short-circuiting at the first ancestor already confirmed).

       We use ghost to walk up the ancestry and also mark ghost and
       tower blocks as confirmed as we walk if this is the duplicate
       confirmation level. */

    fd_ghost_blk_t * ghost_anc = ghost_blk;
    fd_tower_blk_t * tower_anc = tower_blk;
    fd_votes_blk_t * votes_anc = votes_blk;
    while( FD_LIKELY( ghost_anc ) ) {

      tower_anc = fd_tower_blocks_query( ctx->tower, ghost_anc->slot );
      votes_anc = fd_votes_query( ctx->votes, ghost_anc->slot, &ghost_anc->id );
      if( FD_UNLIKELY( !tower_anc || !votes_anc ) ) break;

      /* Terminate at the first ancestor that has already reached this
         confirmation level. */

      if( FD_LIKELY( fd_uchar_extract_bit( votes_anc->flags, i ) ) ) break;

      /* Mark the ancestor as confirmed at this level, before reporting,
         so a duplicate-level row reflects the eligibility it restores.
         If this is the duplicate confirmation level, also mark the ghost
         and tower blocks as confirmed. */

      votes_anc->flags = fd_uchar_set_bit( votes_anc->flags, i );
      if( FD_UNLIKELY( levels[i]==FD_TOWER_SLOT_CONFIRMED_PROPAGATED ) ) {
        tower_anc->propagated = 1;
      }
      if( FD_UNLIKELY( levels[i]==FD_TOWER_SLOT_CONFIRMED_DUPLICATE ) ) {
        tower_anc->confirmed          = 1;
        tower_anc->confirmed_block_id = ghost_anc->id;
        fd_ghost_confirm( ctx->ghost, &ghost_anc->id );
        if( FD_UNLIKELY( memcmp( &tower_anc->replayed_block_id, &ghost_anc->id, sizeof(fd_hash_t) ) ) ) {
          FD_BASE58_ENCODE_32_BYTES( tower_anc->replayed_block_id.uc, eqvoc_blk_id );
          FD_LOG_DEBUG(( "[%s] equivocation detected via ancestor duplicate confirmation. slot: %lu. block_id: %s", __func__, ghost_anc->slot, eqvoc_blk_id ));
          fd_ghost_eqvoc( ctx->ghost, &tower_anc->replayed_block_id );
          report_block_equivocated( &(block_equivocated_args_t){
            .slot = ghost_anc->slot, .parent_slot = tower_anc->parent_slot, .epoch = tower_anc->epoch,
            .block_id = &tower_anc->replayed_block_id, .sibling_block_id = &ghost_anc->id,
            .bank_hash = &tower_anc->bank_hash, .block_hash = &tower_anc->block_hash,
            .bank_seq = 0UL,
            .is_leader = tower_anc->leader, .our_block_voted = tower_anc->voted, .our_block_confirmed = our_block_confirmed( tower_anc ),
            .block_stake = votes_stake( ctx, ghost_anc->slot, &tower_anc->replayed_block_id ),
            .sibling_stake = votes_anc->stake, .total_stake = total_stake,
            .detection = FD_EVENT_BLOCK_EQUIVOCATED_DETECTION_CONFIRM_MISMATCH } );
        }
      }

      publishes_push_head( ctx->publishes, (publish_t){ .sig = FD_TOWER_SIG_SLOT_CONFIRMED, .msg = { .slot_confirmed = (fd_tower_slot_confirmed_t){ .level = levels[i], .fwd = 0, .slot = ghost_anc->slot, .block_id = ghost_anc->id } } } );
      if( FD_LIKELY( !fd_uchar_extract_bit( votes_anc->flags, i+4 ) ) ) {
        /* Skip telemetry report if already forward reported. */
        report_slot_confirmed( ghost_anc->bank_seq, ghost_anc->slot, &ghost_anc->id, votes_anc->stake, total_stake, ghost_anc->valid, event_level_from_tower( levels[ i ] ), 0 /* not forward */ );
      }
      /* Walk up to next ancestor. */

      ghost_anc = fd_ghost_parent( ctx->ghost, ghost_anc );
    }
  }
}

static void
publish_slot_done( fd_tower_tile_t *            ctx,
                   fd_replay_slot_completed_t * slot_completed,
                   fd_tower_out_t *             out,
                   int                          found,
                   ulong                        our_vote_acct_bal,
                   ushort                       our_vote_acct_com,
                   ulong                        tsorig FD_PARAM_UNUSED,
                   fd_stem_context_t *          stem FD_PARAM_UNUSED ) {

  publish_t * pub = publishes_push_head_nocopy( ctx->publishes );
  pub->sig = FD_TOWER_SIG_SLOT_DONE;

  fd_tower_slot_done_t * msg = &pub->msg.slot_done;
  msg->replay_slot           = slot_completed->slot;
  msg->active_fork_cnt       = fd_ghost_width( ctx->ghost );
  msg->vote_slot             = out->vote_slot;
  msg->reset_slot            = out->reset_slot;
  msg->reset_block_id        = out->reset_block_id;
  msg->reset_bank_seq        = out->reset_bank_seq;
  msg->root_slot             = out->root_slot;
  msg->root_block_id         = out->root_block_id;
  msg->replay_bank_idx       = slot_completed->bank_idx;
  msg->replay_bank_seq       = slot_completed->bank_seq;
  msg->vote_acct_bal         = our_vote_acct_bal;
  msg->vote_acct_com         = our_vote_acct_com;

  ulong       authority_idx = ULONG_MAX;
  fd_pubkey_t authority[1];
  fd_pubkey_t identity[1];
  /* Refuse to vote if we don't have a matching vote authority key */
  int found_authority  = found && vote_account_config( ctx, ctx->our_vote_acct, ctx->our_vote_acct_sz, slot_completed->epoch, authority, &authority_idx, identity );
  /* Refuse to vote if our node identity does not match the one
     specified in the vote account (hot spare check) */
  int identity_matches = found_authority && fd_pubkey_eq( identity, ctx->identity_key );
  msg->is_voting = found_authority && identity_matches;

  if( FD_LIKELY( out->vote_slot!=ULONG_MAX &&
                 found_authority &&
                 identity_matches &&
                 !fd_tower_vote_empty( ctx->tower->votes ) ) ) {
    /* The reason to use a historical blockhash and not the most recent
       one is because if a vote txn lands on another validator, they
       may not have finished processing the slot and therefore the
       newest blockhash may not be available to the leader yet; this is
       especially true for the first leader block in a rotation. */
    msg->has_vote_txn = 1;
    fd_txn_p_t       txn[1];
    fd_tower_blk_t * parent_tower_blk = fd_tower_blocks_query( ctx->tower, slot_completed->parent_slot );
    FD_TEST( parent_tower_blk );
    fd_hash_t const * recent_blockhash = &parent_tower_blk->block_hash;
    fd_tower_to_vote_txn( ctx->tower, &out->vote_bank_hash, &out->vote_block_id, recent_blockhash, ctx->identity_key, authority, ctx->vote_account, txn );
    FD_TEST( !fd_tower_vote_empty( ctx->tower->votes ) );
    FD_TEST( txn->payload_sz && txn->payload_sz<=FD_TPU_MTU );
    fd_memcpy( msg->vote_txn, txn->payload, txn->payload_sz );
    FD_TEST( fd_txn_parse_simple_vote( TXN(txn), txn->payload, &ctx->compact_tower_sync_serde ) );
    ctx->tower_file_dirty   = 1;
    msg->vote_txn_sz        = txn->payload_sz;
    msg->authority_idx      = authority_idx;
    msg->vote_created_nanos = fd_log_wallclock();
  } else {
    msg->has_vote_txn = 0;
  }
}

static void
publish_slot_ignored( fd_tower_tile_t *            ctx,
                      fd_replay_slot_completed_t * slot_completed,
                      ulong                        tsorig FD_PARAM_UNUSED,
                      fd_stem_context_t *          stem FD_PARAM_UNUSED ) {
  publishes_push_head( ctx->publishes, (publish_t){
    .sig = FD_TOWER_SIG_SLOT_IGNORED,
    .msg = { .slot_ignored = { .slot = slot_completed->slot, .bank_idx = slot_completed->bank_idx } }
  });
}

static void
publish_slot_rooted( fd_tower_tile_t * ctx,
                     ulong             slot,
                     fd_hash_t const * block_id ) {
  publishes_push_head( ctx->publishes, (publish_t){
    .sig = FD_TOWER_SIG_SLOT_ROOTED,
    .msg = { .slot_rooted = { .slot = slot, .block_id = *block_id } }
  });
}

static void
publish_slot_duplicate( fd_tower_tile_t *                ctx,
                        fd_gossip_duplicate_shred_t const chunks[static FD_EQVOC_CHUNK_CNT],
                        ulong                            slot ) {
  publish_t * pub = publishes_push_head_nocopy( ctx->publishes );
  pub->sig        = FD_TOWER_SIG_SLOT_DUPLICATE;
  memcpy( pub->msg.slot_duplicate.chunks, chunks, sizeof(pub->msg.slot_duplicate.chunks) );

  /* If we already have a tower blk for this just-proved duplicate
     slot, then we know we have replayed one of the equivocating
     blocks.  So determine:

     1. whether we already know what is the confirmed block_id
     2. if our replayed_block_id is the confirmed_block_id

     If either 1. or 2. are false (with 2. contingent on 1.), then
     mark the replayed block as eqvoc in ghost. */

  fd_tower_blk_t * tower_blk = fd_tower_blocks_query( ctx->tower, slot );
  int eqvoc = tower_blk && (!tower_blk->confirmed || memcmp( &tower_blk->replayed_block_id, &tower_blk->confirmed_block_id, sizeof(fd_hash_t) ) );
  if( FD_LIKELY( eqvoc ) ) {
    FD_BASE58_ENCODE_32_BYTES( tower_blk->replayed_block_id.uc, eqvoc_blk_id );
    FD_LOG_DEBUG(( "[%s] equivocation detected via duplicate shred proof. slot: %lu. block_id: %s", __func__, slot, eqvoc_blk_id ));
    fd_ghost_eqvoc( ctx->ghost, &tower_blk->replayed_block_id );
    report_block_equivocated( &(block_equivocated_args_t){
      .slot = slot, .parent_slot = tower_blk->parent_slot, .epoch = tower_blk->epoch,
      .block_id = &tower_blk->replayed_block_id, .sibling_block_id = NULL /* unknown */,
      .bank_hash = &tower_blk->bank_hash, .block_hash = &tower_blk->block_hash,
      .is_leader = tower_blk->leader, .our_block_voted = tower_blk->voted, .our_block_confirmed = our_block_confirmed( tower_blk ),
      .block_stake = votes_stake( ctx, slot, &tower_blk->replayed_block_id ),
      .detection = FD_EVENT_BLOCK_EQUIVOCATED_DETECTION_SHRED_PROOF } );
  }
}

static void
count_vote_acc( fd_tower_tile_t *            ctx,
                fd_replay_slot_completed_t * slot_completed,
                fd_ghost_blk_t *             ghost_blk,
                fd_pubkey_t const *          vote_acc,
                ulong                        stake,
                uchar const *                data,
                ulong                        data_sz ) {

  fd_tower_count_vote( ctx->tower, vote_acc, stake, data, data_sz );

  fd_tower_vtr_t const * vtr = fd_tower_vtr_peek_tail_const( ctx->tower->vtrs );

  /* 1. Update forks with lockouts. */

  fd_tower_lockos_insert( ctx->tower, slot_completed->slot, vote_acc, vtr->votes );

  /* 2. Count the last vote slot in the vote state towards ghost. */

  ulong vote_slot = fd_tower_vote_empty( vtr->votes ) ? ULONG_MAX : fd_tower_vote_peek_tail_const( vtr->votes )->slot;
  if( FD_LIKELY( vote_slot!=ULONG_MAX && /* has voted */
                 vote_slot>=fd_ghost_root( ctx->ghost )->slot ) ) { /* vote not too old */

    fd_ghost_blk_t * ancestor_blk = fd_ghost_slot_ancestor( ctx->ghost, ghost_blk, vote_slot ); /* FIXME potentially slow */

    if( FD_UNLIKELY( !ancestor_blk ) ) {
      FD_BASE58_ENCODE_32_BYTES( vote_acc->key, vote_acc_cstr );
      FD_LOG_CRIT(( "missing ancestor. replay slot %lu vote slot %lu voter %s", slot_completed->slot, vote_slot, vote_acc_cstr ));
    }

    int ghost_err = fd_ghost_count_vote( ctx->ghost, ancestor_blk, vote_acc, stake, vote_slot );
    update_metrics_ghost( ctx, ghost_err );
  }

  FD_TEST( !fd_vote_account_node_pubkey( data, data_sz, &ctx->id_keys[ctx->vtr_cnt] ) );
  ctx->vote_accs[ctx->vtr_cnt] = *vote_acc;
  ctx->vtr_cnt++;
}

/* Query all the relevant towers for running Tower rules on this slot:

   1. staked voter set from banks
   2. vote accounts (for each staked voter, which contains their tower)
      from accountsDB. */

FD_FN_UNUSED ulong
query_towers( fd_tower_tile_t *            ctx,
              fd_replay_slot_completed_t * slot_completed,
              fd_ghost_blk_t *             ghost_blk,
              int *                        found_our_vote_acct,
              ulong *                      our_vote_acct_bal,
              ushort *                     our_vote_acct_com ) {

  ulong total_stake    = 0UL;
  ulong prev_voter_idx = ULONG_MAX;

  fd_bank_t * bank = fd_banks_bank_query( ctx->banks, slot_completed->bank_idx );
  if( FD_UNLIKELY( !bank ) ) FD_LOG_CRIT(( "invariant violation: bank %lu is missing", slot_completed->bank_idx ));

  fd_vote_stakes_t * vote_stakes = fd_bank_vote_stakes( bank );
  ulong              fork_id     = bank->vote_stakes_fork_id;
  uchar __attribute__((aligned(FD_VOTE_STAKES_ITER_ALIGN))) iter_mem[ FD_VOTE_STAKES_ITER_FOOTPRINT ];

#define BATCH 64UL
  fd_pubkey_t   vote_accs[ BATCH ];
  ulong         stakes[ BATCH ];
  uchar const * pubkeys[ BATCH ];
  int           writable[ BATCH ];
  fd_acc_t      accs[ BATCH ];

  fd_vote_stakes_iter_t * iter = fd_vote_stakes_iter_init( vote_stakes, fork_id, FD_VOTE_STAKES_ITER_T_2, iter_mem );
  while( !fd_vote_stakes_iter_done( vote_stakes, fork_id, FD_VOTE_STAKES_ITER_T_2, iter ) ) {
    ulong batch_n = 0UL;
    while( !fd_vote_stakes_iter_done( vote_stakes, fork_id, FD_VOTE_STAKES_ITER_T_2, iter ) && batch_n<BATCH ) {
      uchar is_valid;
      fd_vote_stakes_iter_ele( vote_stakes, fork_id, FD_VOTE_STAKES_ITER_T_2, iter,
                               &vote_accs[ batch_n ], NULL, &stakes[ batch_n ],
                               NULL, NULL, NULL, &is_valid, NULL, NULL, NULL );
      fd_vote_stakes_iter_next( vote_stakes, fork_id, FD_VOTE_STAKES_ITER_T_2, iter );
      total_stake += stakes[ batch_n ];
      if( FD_UNLIKELY( !is_valid ) ) continue;
      pubkeys[ batch_n ]  = vote_accs[ batch_n ].uc;
      writable[ batch_n ] = 0;
      batch_n++;
    }
    if( FD_UNLIKELY( !batch_n ) ) continue;

    fd_accdb_acquire( ctx->accdb, bank->accdb_fork_id, batch_n, pubkeys, writable, accs );

    for( ulong j=0UL; j<batch_n; j++ ) {
      FD_TEST( accs[ j ].lamports && fd_vsv_is_correct_size_owner_and_init( accs[ j ].owner, accs[ j ].data, accs[ j ].data_len ) );
      count_vote_acc( ctx, slot_completed, ghost_blk, &vote_accs[ j ], stakes[ j ], accs[ j ].data, accs[ j ].data_len );
      prev_voter_idx = fd_tower_stakes_insert( ctx->tower, slot_completed->slot, &vote_accs[ j ], stakes[ j ], prev_voter_idx );
    }

    fd_accdb_release( ctx->accdb, batch_n, accs );
  }
#undef BATCH

  /* Reconcile our local tower with the on-chain tower (stored inside
     our vote account).

     Skip reconciliation on the first replay_slot_completed if booted
     with wait_for_supermajority.  This prevents spurious lockout_check
     failures (slot <= last_vote_slot) and threshold_check failures
     (deep stale tower with no voter support) */

  *our_vote_acct_bal   = ULONG_MAX;
  *our_vote_acct_com   = USHORT_MAX;
  *found_our_vote_acct = 0;
  fd_acc_t reconcile_ro = fd_accdb_read_one( ctx->accdb, bank->accdb_fork_id, ctx->vote_account->uc );
  if( FD_LIKELY( reconcile_ro.lamports ) ) {
    *found_our_vote_acct = 1;
    ctx->our_vote_acct_sz = fd_ulong_min( reconcile_ro.data_len, FD_VOTE_STATE_DATA_MAX );
    *our_vote_acct_bal = reconcile_ro.lamports;
    FD_TEST( !fd_vote_account_commission_bps( reconcile_ro.data,
                                               reconcile_ro.data_len,
                                               FD_FEATURE_ACTIVE_BANK( bank, commission_rate_in_basis_points ),
                                               our_vote_acct_com ) );
    fd_memcpy( ctx->our_vote_acct, reconcile_ro.data, ctx->our_vote_acct_sz );
    int skip_reconcile = !ctx->init && ctx->wfs;
    if( FD_LIKELY( !skip_reconcile ) ) {
      ulong root;
      fd_tower_vote_remove_all( ctx->scratch_tower );
      fd_tower_from_vote_acc( ctx->scratch_tower, &root, ctx->our_vote_acct, ctx->our_vote_acct_sz );
      fd_tower_reconcile( ctx->tower, ctx->scratch_tower, root );
    } else {
      FD_LOG_NOTICE(( "wait_for_supermajority: skipping tower reconcile on init slot %lu", slot_completed->slot ));
    }
  }
  fd_accdb_unread_one( ctx->accdb, &reconcile_ro );

  return total_stake;
}

/* validate_vote_txn is the C equivalent of Agave's
   parse_vote_transaction.  Returns the vote account on success, NULL
   on failure.  Deserializes the vote instruction into ctx->scratch_ix.

   https://github.com/anza-xyz/agave/blob/v2.3.7/sdk/src/transaction/versioned/mod.rs#L79 */

static fd_pubkey_t const *
validate_vote_txn( fd_tower_tile_t * ctx,
                   fd_txn_t const *  txn,
                   uchar const *     payload ) {

  if( FD_UNLIKELY( !txn->instr_cnt ) ) return NULL;
  fd_txn_instr_t const * instr = &txn->instr[ 0 ];

  fd_pubkey_t const * accs = (fd_pubkey_t const *)fd_type_pun_const( payload + txn->acct_addr_off );
  if( FD_UNLIKELY( 0!=memcmp( &accs[ instr->program_id ], &fd_solana_vote_program_id, FD_TXN_ACCT_ADDR_SZ ) ) ) return NULL;

  uchar const * instr_data = payload + instr->data_off;
  if( FD_UNLIKELY( !fd_vote_instruction_deserialize( &ctx->scratch_ix, instr_data, instr->data_sz ) ) ) return NULL;

  if( FD_UNLIKELY( !instr->acct_cnt ) ) return NULL;
  uchar const * instr_accts = payload + instr->acct_off;
  return (fd_pubkey_t const *)fd_type_pun_const( &accs[ instr_accts[ 0 ] ] );
}

/* count_vote_txn counts vote txns from Gossip, TPU and Replay.  Note
   these txns have already been parsed and sigverified before they are
   sent to tower.  In addition, vote txns coming from Replay have also
   been successfully executed.  They are counted towards hfork and votes
   (see point 2 in the top-level documentation). */

static void
count_vote_txn( fd_tower_tile_t * ctx,
                fd_txn_t const *  txn,
                uchar const *     payload ) {

  /* We are a little stricter than Agave here because Agave only does
     the is_simple_vote check on replay vote txns, whereas we are doing
     the check on both replay and gossip / TPU vote txns.

     Being a little stricter with non-replay vote txns is ok because
     even if we drop some votes that Agave would consider valid
     (unlikely unless they were sent by an actively malicious
     validator), gossip votes are in general considered unreliable and
     ultimately consensus (fork choice, tower rules, rooting, etc.) is
     reached with vote accounts updated by replaying blocks.

     See: https://github.com/anza-xyz/agave/blob/v4.1.0-beta.1/runtime/src/bank_utils.rs#L54 */

  if( FD_UNLIKELY( !fd_txn_is_simple_vote_transaction( txn, payload ) ) ) { ctx->metrics.votes[ FD_METRICS_ENUM_VOTE_TXN_RESULT_V_NOT_SIMPLE_VOTE_IDX ]++; return; }

  fd_pubkey_t const * vote_acc = validate_vote_txn( ctx, txn, payload );
  if( FD_UNLIKELY( !vote_acc ) ) { ctx->metrics.votes[ FD_METRICS_ENUM_VOTE_TXN_RESULT_V_BAD_DESER_IDX ]++; return; }

  /* Filter any non-TowerSync vote instructions.  For gossip / TPU this
     filters deprecated vote kinds; for replay this shouldn't happen
     after SIMD-0138 is activated. */

  /* TODO SECURITY ensure SIMD-0138 is activated */

  if( FD_UNLIKELY( ctx->scratch_ix.discriminant!=fd_vote_instruction_enum_tower_sync && ctx->scratch_ix.discriminant!=fd_vote_instruction_enum_tower_sync_switch ) ) {
    ctx->metrics.votes[ FD_METRICS_ENUM_VOTE_TXN_RESULT_V_NOT_TOWER_SYNC_IDX ]++;
    return;
  }

  fd_tower_sync_t * tower_sync = &ctx->scratch_ix.tower_sync; /* this is safe, because TowerSyncSwitch is the same as TowerSync except with 32-bytes appended */
  if( FD_UNLIKELY(  tower_sync->lockouts_cnt>FD_TOWER_VOTE_MAX ) ) { ctx->metrics.votes[ FD_METRICS_ENUM_VOTE_TXN_RESULT_V_BAD_TOWER_IDX  ]++; return; }
  if( FD_UNLIKELY( !tower_sync->lockouts_cnt                   ) ) { ctx->metrics.votes[ FD_METRICS_ENUM_VOTE_TXN_RESULT_V_EMPTY_TOWER_IDX ]++; return; }

  fd_tower_vote_remove_all( ctx->scratch_tower );
  for( ulong i = 0; i < tower_sync->lockouts_cnt; i++ ) {
    fd_vote_lockout_t const * lockout = deq_fd_vote_lockout_t_peek_index_const( tower_sync->lockouts, i );
    fd_tower_vote_push_tail( ctx->scratch_tower, (fd_tower_vote_t){ .slot = lockout->slot, .conf = lockout->confirmation_count } );
  }

  /* Validate the tower. */

  fd_tower_vote_t const * prev = fd_tower_vote_peek_head_const( ctx->scratch_tower );
  if( FD_UNLIKELY( prev->conf > FD_TOWER_VOTE_MAX ) ) { ctx->metrics.votes[ FD_METRICS_ENUM_VOTE_TXN_RESULT_V_BAD_TOWER_IDX ]++; return; }

  fd_tower_vote_iter_t iter = fd_tower_vote_iter_next( ctx->scratch_tower, fd_tower_vote_iter_init( ctx->scratch_tower ) );
  for( ; !fd_tower_vote_iter_done( ctx->scratch_tower, iter ); iter = fd_tower_vote_iter_next( ctx->scratch_tower, iter ) ) {
    fd_tower_vote_t const * vote = fd_tower_vote_iter_ele( ctx->scratch_tower, iter );
    if( FD_UNLIKELY( vote->slot <= prev->slot        ) ) { ctx->metrics.votes[ FD_METRICS_ENUM_VOTE_TXN_RESULT_V_BAD_TOWER_IDX ]++; return; }
    if( FD_UNLIKELY( vote->conf >= prev->conf        ) ) { ctx->metrics.votes[ FD_METRICS_ENUM_VOTE_TXN_RESULT_V_BAD_TOWER_IDX ]++; return; }
    if( FD_UNLIKELY( vote->conf >  FD_TOWER_VOTE_MAX ) ) { ctx->metrics.votes[ FD_METRICS_ENUM_VOTE_TXN_RESULT_V_BAD_TOWER_IDX ]++; return; }
    prev = vote;
  }

  if( FD_UNLIKELY( 0==memcmp( &tower_sync->block_id, &hash_null, sizeof(fd_hash_t) ) ) ) { ctx->metrics.votes[ FD_METRICS_ENUM_VOTE_TXN_RESULT_V_UNKNOWN_BLOCK_ID_IDX ]++; return; };

  /* The vote txn contains a block id and bank hash for their last vote
     slot in the tower.  Agave always counts the last vote.

     https://github.com/anza-xyz/agave/blob/v2.3.7/core/src/cluster_info_vote_listener.rs#L476-L487 */

  fd_tower_vote_t const * their_last_vote = fd_tower_vote_peek_tail_const( ctx->scratch_tower );
  fd_hash_t const *       their_block_id  = &tower_sync->block_id;
  fd_hash_t const *       their_bank_hash = &tower_sync->hash;

  /* Return early if their last vote is too old. */

  if( FD_UNLIKELY( their_last_vote->slot <= ctx->tower->root ) ) { ctx->metrics.votes[ FD_METRICS_ENUM_VOTE_TXN_RESULT_V_TOO_OLD_IDX ]++; return; }

  /* Determine the epoch of the vote slot and look up the voter's stake
     for that epoch.  Votes can be at most 1 epoch ahead of root. */

  fd_epoch_leaders_t const * lsched = fd_multi_epoch_leaders_get_lsched_for_slot( ctx->mleaders, their_last_vote->slot );
  if( FD_UNLIKELY( !lsched ) ) { ctx->metrics.votes[ FD_METRICS_ENUM_VOTE_TXN_RESULT_V_BAD_DESER_IDX ]++; return; } /* no leader schedule to resolve the vote's epoch */
  ulong vote_epoch = lsched->epoch;

  epoch_vtr_t *     epoch_vtr_pool = NULL;
  epoch_vtr_map_t * epoch_vtr_map  = NULL;
  ulong             total_stake    = 0UL;
  if(      FD_LIKELY( vote_epoch==ctx->root_epoch     ) ) { epoch_vtr_pool = ctx->root_epoch_vtr_pool; epoch_vtr_map = ctx->root_epoch_vtr_map; total_stake = ctx->root_epoch_total_stake; }
  else if( FD_LIKELY( vote_epoch==ctx->root_epoch + 1 ) ) { epoch_vtr_pool = ctx->next_epoch_vtr_pool; epoch_vtr_map = ctx->next_epoch_vtr_map; total_stake = ctx->next_epoch_total_stake; }
  else                                                    { ctx->metrics.votes[ FD_METRICS_ENUM_VOTE_TXN_RESULT_V_NOT_STAKED_IDX ]++; return;   }
  epoch_vtr_t * vtr = epoch_vtr_map_ele_query( epoch_vtr_map, vote_acc, NULL, epoch_vtr_pool );
  if( FD_UNLIKELY( !vtr ) ) { ctx->metrics.votes[ FD_METRICS_ENUM_VOTE_TXN_RESULT_V_NOT_STAKED_IDX ]++; return; }

  /* Verify the authorized voter for this vote account at vote_epoch is
     among the txn signers.  Mirrors Agave's cluster_info_vote_listener
     check.  authorized_voter is cached on the epoch_vtr by
     query_voters; an all-zero value means we couldn't read it. */

  if( FD_UNLIKELY( 0==memcmp( &vtr->auth_vtr, &pubkey_null, sizeof(fd_pubkey_t) ) ) ) { ctx->metrics.votes[ FD_METRICS_ENUM_VOTE_TXN_RESULT_V_BAD_SIGNER_IDX ]++; return; }
  fd_pubkey_t const * accs = (fd_pubkey_t const *)fd_type_pun_const( payload + txn->acct_addr_off );
  int signer_ok = 0;
  for( ulong i=0; i<txn->signature_cnt; i++ ) {
    if( 0==memcmp( &accs[i], &vtr->auth_vtr, sizeof(fd_pubkey_t) ) ) { signer_ok = 1; break; }
  }
  if( FD_UNLIKELY( !signer_ok ) ) { ctx->metrics.votes[ FD_METRICS_ENUM_VOTE_TXN_RESULT_V_BAD_SIGNER_IDX ]++; return; }

  /* The txn passed all per-txn validation; we will now count its
     individual vote slots (per-slot metrics below). */

  ctx->metrics.votes[ FD_METRICS_ENUM_VOTE_TXN_RESULT_V_SUCCESS_IDX ]++;

  int hfork_err = fd_hfork_count_vote( ctx->hfork, vote_acc, their_block_id, their_bank_hash, their_last_vote->slot, vtr->stake, total_stake );
  update_metrics_hfork( ctx, hfork_err, their_last_vote->slot, their_block_id );

  /* One voter lookup, shared by every slot of this txn (the voter set
     only changes at epoch boundaries, outside this function). */
  fd_votes_vtr_t * votes_vtr = fd_votes_vtr_query( ctx->votes, vote_acc );

  int votes_err = fd_votes_count_vote_vtr( ctx->votes, votes_vtr, vtr->stake, their_last_vote->slot, their_block_id );
  update_metrics_vote_slot( ctx, votes_err );
  if( FD_LIKELY( votes_err==FD_VOTES_SUCCESS ) ) publish_slot_confirmed( ctx, their_last_vote->slot, their_block_id, total_stake );

  /* Agave decides to count intermediate vote slots in the tower iff:

     1. they've replayed the slot
     2. their replay bank hash matches the vote's bank hash.

     This guarantees the intermediate slots they are counting are in
     fact for the correct ancestry (in case of equivocation).  We do the
     same thing, but using block ids instead of bank hashes.

     It's possible we haven't yet replayed this slot being voted on
     because gossip votes can be ahead of our replay.

     https://github.com/anza-xyz/agave/blob/v2.3.7/core/src/cluster_info_vote_listener.rs#L483-L487 */

  fd_tower_blk_t const * our_blk = fd_tower_blocks_query( ctx->tower, their_last_vote->slot );
  if( FD_UNLIKELY( !our_blk ) ) {
     /* we haven't replayed this block yet */
    ctx->metrics.gate_int[ FD_METRICS_ENUM_VOTE_INTERMEDIATE_GATE_V_UNKNOWN_SLOT_IDX ]++;
    return;
  };
  fd_hash_t const * our_block_id = fd_tower_blk_canonical_block_id( our_blk );
  if( FD_UNLIKELY( 0!=memcmp( our_block_id, their_block_id, sizeof(fd_hash_t) ) ) ) { ctx->metrics.gate_int[ FD_METRICS_ENUM_VOTE_INTERMEDIATE_GATE_V_UNKNOWN_BLOCK_ID_IDX ]++; return; } /* we don't recognize this block id */

  /* At this point, we know we have replayed the same slot and also have
     a matching block id, so we can count the intermediate votes. */

  ctx->metrics.gate_int[ FD_METRICS_ENUM_VOTE_INTERMEDIATE_GATE_V_PROCEED_IDX ]++;

  int skipped_last_vote = 0;
  for( fd_tower_vote_iter_t iter = fd_tower_vote_iter_init_rev( ctx->scratch_tower       );
                                  !fd_tower_vote_iter_done_rev( ctx->scratch_tower, iter );
                            iter = fd_tower_vote_iter_prev    ( ctx->scratch_tower, iter ) ) {
    if( FD_UNLIKELY( !skipped_last_vote ) ) { skipped_last_vote = 1; continue; }
    fd_tower_vote_t const * their_intermediate_vote = fd_tower_vote_iter_ele_const( ctx->scratch_tower, iter );

    /* If we don't recognize an intermediate vote slot in their tower,
       it means their tower either:

       1. Contains intermediate vote slots that are too old (older than
          our root) so we already pruned them for tower_forks.  Normally
          if the descendant (last vote slot) is in tower forks, then all
          of its ancestors should be in there too.

       2. Is invalid.  Even though at this point we have successfully
          sigverified and deserialized their vote txn, the tower itself
          might still be invalid because unlike TPU vote txns, we have
          not plumbed through the vote program, but obviously gossip
          votes do not so we need to do some light validation here.

       We could throwaway this voter's tower, but we handle it the same
       way as Agave which is to just skip this intermediate vote slot:

       https://github.com/anza-xyz/agave/blob/v2.3.7/core/src/cluster_info_vote_listener.rs#L513-L518 */

    if( FD_UNLIKELY( their_intermediate_vote->slot <= ctx->tower->root ) ) { ctx->metrics.vote_slots[ FD_METRICS_ENUM_VOTE_SLOT_RESULT_V_TOO_OLD_IDX ]++; continue; }

    fd_tower_blk_t const * tower_blk = fd_tower_blocks_query( ctx->tower, their_intermediate_vote->slot );
    if( FD_UNLIKELY( !tower_blk ) ) { ctx->metrics.vote_slots[ FD_METRICS_ENUM_VOTE_SLOT_RESULT_V_UNKNOWN_SLOT_IDX ]++; continue; }

    /* Otherwise, we count the vote using our own block id for that slot
       (again, mirroring what Agave does albeit with bank hashes).

       Agave uses the current root bank's total stake when counting vote
       txns from gossip / replay:

       https://github.com/anza-xyz/agave/blob/v2.3.7/core/src/cluster_info_vote_listener.rs#L500 */

    fd_hash_t const * intermediate_block_id = fd_tower_blk_canonical_block_id( tower_blk );
    int votes_err = fd_votes_count_vote_vtr( ctx->votes, votes_vtr, vtr->stake, their_intermediate_vote->slot, intermediate_block_id );
    update_metrics_vote_slot( ctx, votes_err );
    if( FD_LIKELY( votes_err==FD_VOTES_SUCCESS ) ) publish_slot_confirmed( ctx, their_intermediate_vote->slot, intermediate_block_id, total_stake );
  }
}

/* Query the staked voters in the provided epoch:

   1. identity keys (aka. node pubkeys)
   2. vote account addresses
   3. associated stake (for the epoch)
   4. authorized voter (for the epoch) */

static ulong
query_epoch_voters( fd_tower_tile_t *      ctx,
                    ulong                  epoch,
                    int                    iter_kind,
                    fd_accdb_fork_id_t     accdb_fork_id,
                    fd_vote_stakes_t *     vote_stakes,
                    ulong                  vote_stakes_fork_id,
                    epoch_vtr_t *          pool,
                    epoch_vtr_map_t *      map,
                    int                    update_id_keys_vote_accs ) {

  epoch_vtr_pool_reset( pool );
  epoch_vtr_map_reset( map );
  ulong total_stake = 0UL;
  fd_vote_stakes_iter_t * iter = fd_vote_stakes_iter_init( vote_stakes, vote_stakes_fork_id, iter_kind, ctx->iter_mem );
  while( !fd_vote_stakes_iter_done( vote_stakes, vote_stakes_fork_id, iter_kind, iter ) ) {
    fd_pubkey_t pubkey;
    ulong       stake;
    fd_vote_stakes_iter_ele( vote_stakes, vote_stakes_fork_id, iter_kind, iter, &pubkey, NULL, &stake,
                             NULL, NULL, NULL, NULL, NULL, NULL, NULL );
    fd_vote_stakes_iter_next( vote_stakes, vote_stakes_fork_id, iter_kind, iter );
    total_stake += stake;
    epoch_vtr_t * vtr = epoch_vtr_pool_ele_acquire( pool );
    vtr->vote_acc = pubkey;
    vtr->stake    = stake;
    memset( &vtr->auth_vtr, 0, sizeof(fd_pubkey_t) );

    /* Cache the authorized voter for target_epoch.  Leaves
       auth_vtr all-zero if the vote account is unreadable —
       count_vote_txn will reject txns whose signer can't match. */

    fd_acc_t ro = fd_accdb_read_one( ctx->accdb, accdb_fork_id, pubkey.uc );
    if( FD_LIKELY( ro.lamports && fd_vsv_is_correct_size_owner_and_init( ro.owner, ro.data, ro.data_len ) ) ) {
      fd_pubkey_t identity[1];
      ulong dummy_idx;
      vote_account_config( ctx, ro.data, ro.data_len, epoch, &vtr->auth_vtr, &dummy_idx, identity );
      if( update_id_keys_vote_accs ) {
        FD_TEST( 0==fd_vote_account_node_pubkey( ro.data, ro.data_len, &ctx->id_keys[ctx->vtr_cnt] ) ); /* check vote account is not corrupt */
        ctx->vote_accs[ctx->vtr_cnt] = pubkey;
        ctx->vtr_cnt++;
      }
    }
    fd_accdb_unread_one( ctx->accdb, &ro );

    epoch_vtr_map_ele_insert( map, vtr, pool );
  }
  return total_stake;
}

/* Update the cached voters for both the currently rooted epoch and the
   next epoch, to allow processing vote transactions for vote slots that
   span both these epochs. */

FD_FN_UNUSED void
query_voters( fd_tower_tile_t *            ctx,
              fd_replay_slot_completed_t * slot_completed,
              ulong                        epoch ) {
  if( FD_LIKELY( ctx->banks ) ) {
    fd_bank_t * bank = fd_banks_bank_query( ctx->banks, slot_completed->bank_idx );
    if( FD_UNLIKELY( !bank ) ) FD_LOG_CRIT(( "invariant violation: bank %lu is missing", slot_completed->bank_idx ));

    ctx->vtr_cnt = 0;
    fd_vote_stakes_t * vote_stakes = fd_bank_vote_stakes( bank );
    ctx->root_epoch_total_stake = query_epoch_voters( ctx, epoch,     FD_VOTE_STAKES_ITER_T_2, bank->accdb_fork_id, vote_stakes, bank->vote_stakes_fork_id, ctx->root_epoch_vtr_pool, ctx->root_epoch_vtr_map, 1 );
    ctx->next_epoch_total_stake = query_epoch_voters( ctx, epoch+1UL, FD_VOTE_STAKES_ITER_T_1, bank->accdb_fork_id, vote_stakes, bank->vote_stakes_fork_id, ctx->next_epoch_vtr_pool, ctx->next_epoch_vtr_map, 0 );
  }
  ctx->root_epoch = epoch;

  fd_eqvoc_update_voters( ctx->eqvoc, ctx->id_keys,   ctx->vtr_cnt );
  fd_hfork_update_voters( ctx->hfork, ctx->vote_accs, ctx->vtr_cnt );
  fd_votes_update_voters( ctx->votes, ctx->vote_accs, ctx->vtr_cnt );
}

static void
clear_votes( fd_tower_t * tower ) {
  for( ulong i=0UL; i<tower->blk_max; i++ ) tower->blk_pool[ i ].voted = 0; /* blocks stay voted after their votes expire */
  fd_tower_vote_remove_all( tower->votes );
}

static ulong
vote_history_ahead( fd_tower_t *            tower,
                    fd_ghost_t *            ghost,
                    fd_tower_file_t const * file ) {
  fd_tower_blk_t const * root_blk = fd_tower_blocks_query( tower, file->root );
  int   ahead   = file->root>tower->root && ( !root_blk || !fd_ghost_query( ghost, &root_blk->replayed_block_id ) );
  ulong wait    = file->votes[ file->votes_cnt-1UL ].slot+1UL;
  int   missing = 0;
  for( ulong i=0UL; i<file->votes_cnt; i++ ) {
    fd_tower_vote_t const * vote = &file->votes[ i ];
    fd_tower_blk_t  const * blk  = fd_tower_blocks_query( tower, vote->slot );
    missing |= vote->slot>tower->root && ( !blk || !fd_ghost_query( ghost, &blk->replayed_block_id ) );
    if( missing ) {
      ahead = 1;
      wait  = fd_ulong_max( wait, vote->slot+(1UL<<vote->conf)+1UL );
    }
  }
  return ahead ? wait : 0UL;
}

static ulong
vote_history_floor( fd_tower_t const *             tower,
                    fd_tower_file_t const *        file,
                    fd_slot_history_view_t const * slot_history ) {
  ulong floor = 0UL;
  for( ulong i=0UL; i<file->votes_cnt; i++ ) {
    fd_tower_vote_t const * vote = &file->votes[ i ];
    if( vote->slot<=tower->root && fd_sysvar_slot_history_find_slot( slot_history, vote->slot )==FD_SLOT_HISTORY_SLOT_NOT_FOUND ) {
      floor = fd_ulong_max( floor, vote->slot+(1UL<<vote->conf)+1UL );
    }
  }
  return floor;
}

static void
adopt_vote_history( fd_tower_tile_t * ctx ) {
  /* A minor note is that adopt_vote_history ignores the tower
     file's latest vote timestamp. The only downside of this is that
     if the Firedancer validator's wallclock is behind the tower
     file's latest vote timestamp, its votes will land, but will not
     execute successfully.  This will self-heal when the wallclock of
     the switched-to validator catches up to the tower file's latest
     vote timestamp. */

  fd_tower_t *            tower = ctx->tower;
  fd_tower_file_t const * file  = &ctx->vote_history;
  ulong                   last  = file->votes[ file->votes_cnt-1UL ].slot;

  /* The old validator may have voted for a different copy of this slot
     than the one we replayed.  Agave only compares slot numbers: so we
     keep the vote and treat it as a vote for our copy. */
  fd_tower_blk_t const * last_blk = fd_tower_blocks_query( tower, last );
  if( FD_UNLIKELY( last_blk && !fd_hash_eq( &last_blk->bank_hash, &file->bank_hash ) ) ) {
    FD_LOG_WARNING(( "set-identity: last vote %lu in vote history is for a different bank than we replayed", last ));
  }

  fd_tower_vote_remove_all( ctx->scratch_tower );
  for( ulong i=0UL; i<file->votes_cnt; i++ ) {
    fd_tower_vote_t const * vote = &file->votes[ i ];
    fd_tower_blk_t  const * blk  = fd_tower_blocks_query( tower, vote->slot );
    if( FD_UNLIKELY( vote->slot>tower->root && ( !blk || !fd_ghost_query( ctx->ghost, &blk->replayed_block_id ) ) ) ) break;
    fd_tower_vote_push_tail( ctx->scratch_tower, *vote );
  }
  if( FD_LIKELY( !fd_tower_vote_empty( ctx->scratch_tower ) && !fd_tower_vote_empty( tower->votes ) &&
                 fd_tower_vote_peek_tail_const( tower->votes )->slot<=fd_tower_vote_peek_tail_const( ctx->scratch_tower )->slot ) ) clear_votes( tower );
  fd_tower_blk_t const * root_blk = fd_tower_blocks_query( tower, file->root );
  int root_replayed = file->root<=tower->root || ( root_blk && fd_ghost_query( ctx->ghost, &root_blk->replayed_block_id ) );
  fd_tower_reconcile( tower, ctx->scratch_tower, root_replayed ? file->root : tower->root );
}

/* check_vote_history runs on each replayed slot while a vote history
   is pending.  Our tower takes the history's votes on blocks we have
   replayed as they arrive.  The history stops pending once all of its
   votes and root are replayed, or it is behind our root, or its
   missing blocks still haven't been replayed when their lockouts
   expire.  We don't vote until votes that are missing, or were on an
   abandoned fork, would no longer lock us out. */

static void
check_vote_history( fd_tower_tile_t *                  ctx,
                    fd_replay_slot_completed_t const * slot_completed ) {
  fd_tower_t *            tower = ctx->tower;
  fd_tower_file_t const * file  = &ctx->vote_history;
  ulong                   last  = file->votes[ file->votes_cnt-1UL ].slot;

  /* If the tower file has votes that are behind our view of the root,
     and has votes which were on abandoned forks, then we may need to
     wait to vote to avoid violating lockout. */
  ulong floor = 0UL;
  fd_bank_t * bank = fd_banks_bank_query( ctx->banks, slot_completed->bank_idx );
  FD_TEST( bank );
  ulong                  sz;
  uchar const *          data = fd_sysvar_cache_data_query( &bank->f.sysvar_cache, &fd_sysvar_slot_history_id, &sz );
  fd_slot_history_view_t slot_history[1];
  if( FD_LIKELY( data && fd_sysvar_slot_history_view( slot_history, data, sz ) ) ) floor = vote_history_floor( tower, file, slot_history );

  /* If the tower file is ahead of what we have replayed, we need to
     wait to catch up (or for lockout to expire) to make sure we aren't
     accidentally violating lockout or double voting. */
  ulong wait = vote_history_ahead( tower, ctx->ghost, file );
  if( FD_LIKELY( last>tower->root ) ) adopt_vote_history( ctx );
  if( FD_UNLIKELY( wait && slot_completed->slot<wait ) ) {
    ulong wait_to_vote_slot = fd_ulong_max( wait, floor );
    if( FD_UNLIKELY( tower->wait_to_vote_slot!=wait_to_vote_slot ) ) FD_LOG_INFO(( "set-identity: vote history is ahead of replay, not voting below slot %lu", wait_to_vote_slot ));
    tower->wait_to_vote_slot = wait_to_vote_slot;
    return;
  }

/* Either:
   1. The tower file is behind our root, so drop it.
   2. The tower file was ahead, but its missing blocks never arrived
      and their lockouts have expired, so drop the votes on them.
   3. All of its blocks are replayed, so it is fully adopted.

   In every case we still don't vote until any of its votes on
   abandoned forks stop locking us out. */
  if     ( FD_UNLIKELY( last<=tower->root ) ) FD_LOG_NOTICE(( "set-identity: vote history is behind root %lu (last vote %lu)", tower->root, last ));
  else if( FD_UNLIKELY( wait              ) ) FD_LOG_WARNING(( "set-identity: vote history blocks were never replayed, dropping the votes on them" ));
  else                                        FD_LOG_NOTICE(( "set-identity: restored vote history, last vote %lu, root %lu", last, tower->root ));
  ctx->vote_history_pending = 0;
  tower->wait_to_vote_slot  = fd_ulong_max( wait, floor );
}

static void
replay_slot_completed( fd_tower_tile_t *            ctx,
                       fd_replay_slot_completed_t * slot_completed,
                       ulong                        tsorig,
                       fd_stem_context_t *          stem ) {

  /* If the slot has already been replayed, we can just ignore it (but
     refresh bank_seq so confirmations reference the surviving row, and
     release the bank ref). */
  fd_ghost_blk_t * replayed = fd_ghost_query( ctx->ghost, &slot_completed->block_id );
  if( FD_UNLIKELY( replayed ) ) {
    replayed->bank_seq = slot_completed->bank_seq;
    publish_slot_ignored( ctx, slot_completed, tsorig, stem );
    return;
  }

  /* Sanity checks. */

  FD_TEST( 0!=memcmp( &slot_completed->block_id, &hash_null, sizeof(fd_hash_t) ) );

  fd_tower_stakes_remove( ctx->tower, slot_completed->slot ); /* no-op for 99% of cases except for eqvoc */
  fd_tower_vtr_t * tower_voters = ctx->tower->vtrs;
  fd_tower_vtr_remove_all( tower_voters );
  ctx->vtr_cnt = 0;

  /* Insert into ghost. */

  fd_ghost_blk_t * ghost_blk;
  if( FD_UNLIKELY( !ctx->init ) ) {

    /* This is the first replay_slot_completed (ie. the snapshot or
       genesis slot), so initialize the ghost root. */

    ghost_blk = fd_ghost_init( ctx->ghost, slot_completed->bank_seq, slot_completed->slot, &slot_completed->block_id );

  } else if ( FD_UNLIKELY( !fd_ghost_query( ctx->ghost, &slot_completed->parent_block_id ) )) {

  /* Due to asynchronous frag processing, it's possible this block from
     replay_slot_completed is on a minority fork Tower already pruned
     after publishing a new root. */

    ctx->metrics.ignored_cnt++;
    ctx->metrics.ignored_slot = slot_completed->slot;
    publish_slot_ignored( ctx, slot_completed, tsorig, stem );
    report_slot_confirmed( slot_completed->bank_seq, slot_completed->slot, &slot_completed->block_id, 0UL /* stake */, 0UL /* total_stake */, 1 /* valid */, FD_EVENT_SLOT_CONFIRMED_LEVEL_IGNORED, 0 /* not forward */ );
    return; /* short-circuit processing this slot */

  } else {

    /* Common case. */

    ghost_blk = fd_ghost_insert( ctx->ghost, slot_completed->bank_seq, slot_completed->slot, &slot_completed->block_id, &slot_completed->parent_block_id );
  }
  FD_TEST( ghost_blk );

  /* Insert into tower. */

  fd_tower_blk_t * eqvoc_tower_blk = NULL;
  if( FD_UNLIKELY( eqvoc_tower_blk = fd_tower_blocks_query( ctx->tower, slot_completed->slot ) ) ) {

    /* If eqvoc_tower_blk is not NULL, then we know this slot
       equivocates (there are multiple blocks in the slot).

       Replay processes at most 2 equivocating blocks for a given slot,
       and the latter block is guaranteed to be confirmed.

       At this point, we know we are processing the latter block, so we
       record that in the tower_blk. */

    fd_tower_lockos_remove( ctx->tower, slot_completed->slot );

    ctx->metrics.eqvoc_cnt++;
    ctx->metrics.eqvoc_slot = fd_ulong_max( ctx->metrics.eqvoc_slot, slot_completed->slot );

    fd_ghost_confirm( ctx->ghost, &slot_completed->block_id );
    FD_BASE58_ENCODE_32_BYTES( eqvoc_tower_blk->replayed_block_id.uc, eqvoc_blk_id );
    FD_LOG_DEBUG(( "[%s] equivocation detected via duplicate replay. slot: %lu. block_id: %s", __func__, slot_completed->slot, eqvoc_blk_id ));
    fd_ghost_eqvoc( ctx->ghost, &eqvoc_tower_blk->replayed_block_id );
    report_block_equivocated( &(block_equivocated_args_t){
      .slot = slot_completed->slot, .parent_slot = eqvoc_tower_blk->parent_slot, .epoch = eqvoc_tower_blk->epoch,
      .block_id = &eqvoc_tower_blk->replayed_block_id, .sibling_block_id = &slot_completed->block_id,
      .bank_hash = &eqvoc_tower_blk->bank_hash, .block_hash = &eqvoc_tower_blk->block_hash,
      .bank_seq = 0UL, .is_leader = eqvoc_tower_blk->leader,
      .our_block_voted = eqvoc_tower_blk->voted, .our_block_confirmed = our_block_confirmed( eqvoc_tower_blk ),
      .block_stake   = votes_stake( ctx, slot_completed->slot, &eqvoc_tower_blk->replayed_block_id ),
      .sibling_stake = votes_stake( ctx, slot_completed->slot, &slot_completed->block_id ),
      .total_stake   = ghost_blk->total_stake,
      .detection = FD_EVENT_BLOCK_EQUIVOCATED_DETECTION_DUPLICATE_REPLAY } );

    eqvoc_tower_blk->parent_slot       = slot_completed->parent_slot;
    eqvoc_tower_blk->bank_hash         = slot_completed->bank_hash;
    eqvoc_tower_blk->block_hash        = slot_completed->block_hash;
    eqvoc_tower_blk->replayed_block_id = slot_completed->block_id;
  } else {

    /* Otherwise this is the first replay of this block, so insert a new
       tower_blk. */

    fd_tower_blk_t * tower_blk   = fd_tower_blocks_insert( ctx->tower, slot_completed->slot, slot_completed->parent_slot );
    tower_blk->parent_slot       = slot_completed->parent_slot;
    tower_blk->epoch             = slot_completed->epoch;
    tower_blk->bank_hash         = slot_completed->bank_hash;
    tower_blk->block_hash        = slot_completed->block_hash;
    tower_blk->replayed          = 1;
    tower_blk->replayed_block_id = slot_completed->block_id;
    tower_blk->voted             = 0;
    tower_blk->confirmed         = 0;
    tower_blk->leader            = slot_completed->is_leader;
    tower_blk->propagated        = 0;

    /* Set the prev_leader_slot. */

    if( FD_UNLIKELY( tower_blk->leader ) ) {
      tower_blk->prev_leader_slot = slot_completed->slot;
    } else if ( FD_UNLIKELY( ghost_blk==fd_ghost_root( ctx->ghost ) ) ) {
      tower_blk->prev_leader_slot = ULONG_MAX;
    } else {
      fd_tower_blk_t * parent_tower_blk = fd_tower_blocks_query( ctx->tower, slot_completed->parent_slot );
      FD_TEST( parent_tower_blk );
      tower_blk->prev_leader_slot = parent_tower_blk->prev_leader_slot;
    }

    fd_votes_blk_t * fwd_votes_blk = fd_votes_query( ctx->votes, slot_completed->slot, NULL );
    if( FD_UNLIKELY( fwd_votes_blk && fd_uchar_extract_bit( fwd_votes_blk->flags, FD_TOWER_SLOT_CONFIRMED_DUPLICATE+4 ) ) ) {

      /* A block_id for this slot was forward-confirmed at the duplicate
         level before replay (publish_slot_confirmed ran when no
         ghost_blk existed).  Resolve the pending confirmation now. */

      tower_blk->confirmed          = 1;
      tower_blk->confirmed_block_id = fwd_votes_blk->key.block_id;

      if( FD_LIKELY( 0==memcmp( &tower_blk->replayed_block_id, &fwd_votes_blk->key.block_id, sizeof(fd_hash_t) ) ) ) {

        /* The forward-confirmed block_id matches what we replayed. */

        fd_ghost_confirm( ctx->ghost, &slot_completed->block_id );

      } else {

        /* The forward-confirmed block_id differs from what we replayed,
           so our replayed block is an equivocating sibling. */

        FD_BASE58_ENCODE_32_BYTES( slot_completed->block_id.uc, eqvoc_blk_id );
        FD_LOG_DEBUG(( "[%s] equivocation detected via forward-confirmed block id mismatch (confirmed before replayed). slot: %lu. block_id: %s", __func__, slot_completed->slot, eqvoc_blk_id ));
        fd_ghost_eqvoc( ctx->ghost, &slot_completed->block_id );
        report_block_equivocated( &(block_equivocated_args_t){
          .slot = slot_completed->slot, .parent_slot = slot_completed->parent_slot, .epoch = slot_completed->epoch,
          .block_id = &slot_completed->block_id, .sibling_block_id = &fwd_votes_blk->key.block_id,
          .bank_hash = &slot_completed->bank_hash, .block_hash = &slot_completed->block_hash,
          .bank_seq = slot_completed->bank_seq, .is_leader = slot_completed->is_leader,
          .our_block_confirmed = 0,
          .block_stake = votes_stake( ctx, slot_completed->slot, &slot_completed->block_id ),
          .sibling_stake = fwd_votes_blk->stake,
          .detection = FD_EVENT_BLOCK_EQUIVOCATED_DETECTION_CONFIRM_MISMATCH } );
      }

    } else if( FD_UNLIKELY( fd_eqvoc_proof_verified( ctx->eqvoc, slot_completed->slot ) ) ) {

      /* Eqvoc already detected equivocation for this slot (via shreds
         or gossip before replay).  Mark the ghost block invalid. */

      FD_BASE58_ENCODE_32_BYTES( slot_completed->block_id.uc, eqvoc_blk_id );
      FD_LOG_DEBUG(( "[%s] equivocation detected via eqvoc shred proof before replay. slot: %lu. block_id: %s", __func__, slot_completed->slot, eqvoc_blk_id ));
      fd_ghost_eqvoc( ctx->ghost, &slot_completed->block_id );
      report_block_equivocated( &(block_equivocated_args_t){
        .slot = slot_completed->slot, .parent_slot = slot_completed->parent_slot, .epoch = slot_completed->epoch,
        .block_id = &slot_completed->block_id, .sibling_block_id = NULL /* unknown */,
        .bank_hash = &slot_completed->bank_hash, .block_hash = &slot_completed->block_hash,
        .bank_seq = slot_completed->bank_seq, .is_leader = slot_completed->is_leader,
        .block_stake = votes_stake( ctx, slot_completed->slot, &slot_completed->block_id ),
        .detection = FD_EVENT_BLOCK_EQUIVOCATED_DETECTION_SHRED_PROOF } );
    }
  }

  if( FD_UNLIKELY( !ctx->init ) ) {
    ctx->metrics.init_slot = slot_completed->slot;
    ctx->tower->root       = slot_completed->slot;
    fd_votes_publish( ctx->votes, slot_completed->slot );
  }

  /* Count the vote accounts and reconcile our own vote account. */

  ulong  our_vote_acct_bal = ULONG_MAX;
  ushort our_vote_acct_com = USHORT_MAX;
  int    found             = 0;
  ghost_blk->total_stake = QUERY_TOWERS( ctx, slot_completed, ghost_blk, &found, &our_vote_acct_bal, &our_vote_acct_com );

  /* Capture the values needed for the processed event now: advancing the
     root below (fd_ghost_publish) can prune ghost_blk if this block was
     replayed on a minority fork, freeing it before we report. */

  ulong processed_stake       = ghost_blk->stake;
  ulong processed_total_stake = ghost_blk->total_stake;
  int   processed_valid       = ghost_blk->valid;

  /* The first replay_slot_completed msg is used to initialize the tower
     tile's various structures. */

  if( FD_UNLIKELY( !ctx->init ) ) {
    ctx->init = 1;
    QUERY_VOTERS( ctx, slot_completed, slot_completed->epoch );
  }

  /* Insert into hard fork detector. */

  fd_epoch_leaders_t const * lsched = fd_multi_epoch_leaders_get_lsched_for_slot( ctx->mleaders, slot_completed->slot );
  int hfork_flag = fd_hfork_record_our_bank_hash( ctx->hfork, &slot_completed->block_id, &slot_completed->bank_hash, fd_ulong_if( lsched->epoch==ctx->root_epoch, ctx->root_epoch_total_stake, ctx->next_epoch_total_stake ) );
  update_metrics_hfork( ctx, hfork_flag, slot_completed->slot, &slot_completed->block_id );

  if( FD_UNLIKELY( ctx->vote_history_pending ) ) check_vote_history( ctx, slot_completed );

  /* Determine reset, vote, and root slots.  There may not be a vote or
     root slot but there is always a reset slot. */

  fd_tower_out_t out = { .vote_slot = ULONG_MAX, .root_slot = ULONG_MAX };
  out.flags = fd_tower_vote_and_reset( ctx->tower,      ctx->ghost,          ctx->votes,
                                       &out.reset_slot, &out.reset_block_id, &out.reset_bank_seq,
                                       &out.vote_slot,  &out.vote_block_id,  &out.vote_bank_hash,
                                       &out.root_slot,  &out.root_block_id );
  if( FD_LIKELY( out.vote_slot!=ULONG_MAX ) ) { /* if there is a vote slot we record it. */
    fd_tower_blk_t * vote_tower_blk = fd_tower_blocks_query( ctx->tower, out.vote_slot );
    vote_tower_blk->voted           = 1;
    vote_tower_blk->voted_block_id  = out.vote_block_id;
  }

  /* Publish structures if there is a new root. */

  if( FD_UNLIKELY( out.root_slot!=ULONG_MAX ) ) {
    if( FD_UNLIKELY( 0==memcmp( &out.root_block_id, &hash_null, sizeof(fd_hash_t) ) ) ) {
      FD_LOG_CRIT(( "invariant violation: root block id is null at slot %lu", out.root_slot ));
    }

    fd_tower_blk_t * newr_tower_blk = fd_tower_blocks_query( ctx->tower, out.root_slot );
    FD_TEST( newr_tower_blk );

    /* It is a Solana consensus protocol invariant that a validator must
       make at least one root in an epoch, so the root's epoch cannot
       advance by more than one.  Compare against root_epoch, the epoch
       voters were last indexed for, since reconcile can move tower->root
       into the next epoch without publishing a root. */

    FD_TEST( ctx->root_epoch==newr_tower_blk->epoch || ctx->root_epoch+1==newr_tower_blk->epoch  ); /* root can only move forward one epoch */

    /* Publish votes: 1. reindex if it's a new epoch. 2. publish the new
       root to votes. */

    if( FD_UNLIKELY( ctx->root_epoch+1==newr_tower_blk->epoch ) ) {
      FD_TEST( newr_tower_blk->epoch==slot_completed->epoch ); /* new root's epoch must be same as current slot_completed */
      QUERY_VOTERS( ctx, slot_completed, newr_tower_blk->epoch );
    }
    fd_votes_publish( ctx->votes, out.root_slot );

    /* Publish tower_blocks and tower_stakes by removing any entries
       older than the new root.  Start from the ghost root, which trails
       tower->root when reconcile moved it. */

    for( ulong slot = fd_ghost_root( ctx->ghost )->slot; slot < out.root_slot; slot++ ) {
      fd_tower_blocks_remove( ctx->tower, slot );
      fd_tower_lockos_remove( ctx->tower, slot );
      fd_tower_stakes_remove( ctx->tower, slot );
    }

    /* Publish roots by walking up the ghost ancestry to publish new root
       frags for intermediate slots we couldn't vote for. */

    fd_ghost_blk_t * newr = fd_ghost_query( ctx->ghost, &out.root_block_id );
    fd_ghost_blk_t * oldr = fd_ghost_root( ctx->ghost );

    if( FD_UNLIKELY( !newr ) ) {
      FD_BASE58_ENCODE_32_BYTES( out.root_block_id.uc, root_blk_id );
      FD_LOG_ERR(( "new root block %s (slot %lu) is not in ghost: our root conflicts with the cluster", root_blk_id, out.root_slot ));
    }

    /* oldr is not guaranteed to be the immediate parent of newr, but is
       rather an arbitrary ancestor.  This can happen if we couldn't
       vote for those intermediate slot(s).  We publish those slots as
       intermediate roots. */

    fd_ghost_blk_t * intr = newr;
    while( FD_LIKELY( intr!=oldr ) ) {
      publish_slot_rooted( ctx, intr->slot, &intr->id );
      report_slot_confirmed( intr->bank_seq, intr->slot, &intr->id, intr->stake, intr->total_stake, intr->valid, FD_EVENT_SLOT_CONFIRMED_LEVEL_ROOTED, 0 /* not forward */ );
      intr = fd_ghost_parent( ctx->ghost, intr );
    }

    /* Publish ghost. */

    fd_ghost_publish( ctx->ghost, newr );

    /* Update the new root. */

    ctx->tower->root = out.root_slot;
  }

  /* Publish a slot_done frag to tower_out. */

  publish_slot_done( ctx, slot_completed, &out, found, our_vote_acct_bal, our_vote_acct_com, tsorig, stem );
  report_slot_confirmed( slot_completed->bank_seq, slot_completed->slot, &slot_completed->block_id, processed_stake, processed_total_stake, processed_valid, FD_EVENT_SLOT_CONFIRMED_LEVEL_PROCESSED, 0 /* not forward */ );

  /* Write out metrics. */

  ctx->metrics.replay_slot    = slot_completed->slot;
  if( FD_LIKELY( out.vote_slot!=ULONG_MAX ) ) ctx->metrics.last_vote_slot = out.vote_slot;
  ctx->metrics.last_vote_slot = fd_ulong_if( out.vote_slot!=ULONG_MAX, out.vote_slot, ctx->metrics.last_vote_slot );
  ctx->metrics.reset_slot     = out.reset_slot; /* always set */
  ctx->metrics.root_slot      = ctx->tower->root;

  /* Fork-decision axis: fd_tower_vote_and_reset sets exactly one of these
     five fork flags, except in the two no-vote-yet short-circuits (case 0a
     and 0b) where it sets no flags.  Those are distinguished by vote_slot:
     0a does not vote (vote_slot==ULONG_MAX), 0b votes (vote_slot set). */

  if(      fd_uchar_extract_bit( out.flags, FD_TOWER_FLAG_ANCESTOR_ROLLBACK ) ) ctx->metrics.fork[ FD_METRICS_ENUM_TOWER_FORK_DECISION_V_ANCESTOR_ROLLBACK_IDX ]++;
  else if( fd_uchar_extract_bit( out.flags, FD_TOWER_FLAG_SIBLING_CONFIRMED ) ) ctx->metrics.fork[ FD_METRICS_ENUM_TOWER_FORK_DECISION_V_SIBLING_CONFIRMED_IDX ]++;
  else if( fd_uchar_extract_bit( out.flags, FD_TOWER_FLAG_SAME_FORK         ) ) ctx->metrics.fork[ FD_METRICS_ENUM_TOWER_FORK_DECISION_V_SAME_FORK_IDX         ]++;
  else if( fd_uchar_extract_bit( out.flags, FD_TOWER_FLAG_SWITCH_PASS       ) ) ctx->metrics.fork[ FD_METRICS_ENUM_TOWER_FORK_DECISION_V_SWITCH_PASS_IDX       ]++;
  else if( fd_uchar_extract_bit( out.flags, FD_TOWER_FLAG_SWITCH_FAIL       ) ) ctx->metrics.fork[ FD_METRICS_ENUM_TOWER_FORK_DECISION_V_SWITCH_FAIL_IDX       ]++;
  else if( out.vote_slot!=ULONG_MAX                                          ) ctx->metrics.fork[ FD_METRICS_ENUM_TOWER_FORK_DECISION_V_EMPTY_TOWER_VOTE_IDX   ]++;
  else                                                                         ctx->metrics.fork[ FD_METRICS_ENUM_TOWER_FORK_DECISION_V_NO_VOTE_NOT_RECENT_IDX ]++;

  /* Vote-gate axis: if a votable block was selected, it is gated by the
     lockout/threshold/propagated checks (at most one fails) or it passes
     all of them and we vote.  If no votable block was selected, there is
     no candidate to gate. */

  if(      out.vote_slot!=ULONG_MAX                                            ) ctx->metrics.gate[ FD_METRICS_ENUM_TOWER_VOTE_GATE_V_VOTED_IDX           ]++;
  else if( fd_uchar_extract_bit( out.flags, FD_TOWER_FLAG_LOCKOUT_FAIL    )    ) ctx->metrics.gate[ FD_METRICS_ENUM_TOWER_VOTE_GATE_V_LOCKOUT_FAIL_IDX    ]++;
  else if( fd_uchar_extract_bit( out.flags, FD_TOWER_FLAG_THRESHOLD_FAIL  )    ) ctx->metrics.gate[ FD_METRICS_ENUM_TOWER_VOTE_GATE_V_THRESHOLD_FAIL_IDX  ]++;
  else if( fd_uchar_extract_bit( out.flags, FD_TOWER_FLAG_PROPAGATED_FAIL )    ) ctx->metrics.gate[ FD_METRICS_ENUM_TOWER_VOTE_GATE_V_PROPAGATED_FAIL_IDX ]++;
  else                                                                          ctx->metrics.gate[ FD_METRICS_ENUM_TOWER_VOTE_GATE_V_NO_CANDIDATE_IDX     ]++;

  /* Log out structures. */

  char cstr[4096]; ulong cstr_sz;
  FD_LOG_DEBUG(( "\n\n%s", fd_ghost_to_cstr( ctx->ghost, fd_ghost_root( ctx->ghost ), cstr, sizeof(cstr), &cstr_sz ) ));
  FD_LOG_DEBUG(( "\n\n%s", fd_tower_to_cstr( ctx->tower, cstr ) ));
}

FD_FN_CONST static inline ulong
scratch_align( void ) {
  return 128UL;
}

FD_FN_PURE static inline ulong
scratch_footprint( fd_topo_tile_t const * tile ) {
  ulong slot_max    = fd_ulong_pow2_up( tile->tower.max_live_slots );
  ulong blk_max     = slot_max * EQVOC_MAX;
  ulong fec_max     = slot_max * tile->tower.max_shreds_per_block / FD_FEC_SHRED_CNT;
  ulong pub_max     = slot_max * FD_TOWER_SLOT_CONFIRMED_LEVEL_CNT;

  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, alignof(fd_tower_tile_t), sizeof(fd_tower_tile_t)                                       );
  l = FD_LAYOUT_APPEND( l, auth_vtr_align(),         auth_vtr_footprint()                                          );
  /* auth_vtr_keyswitch */
  l = FD_LAYOUT_APPEND( l, fd_eqvoc_align(),         fd_eqvoc_footprint( slot_max, fec_max, PER_VTR_MAX, VTR_MAX ) );
  l = FD_LAYOUT_APPEND( l, fd_ghost_align(),         fd_ghost_footprint( blk_max, VTR_MAX )                        );
  l = FD_LAYOUT_APPEND( l, fd_hfork_align(),         fd_hfork_footprint( PER_VTR_MAX, VTR_MAX )                    );
  l = FD_LAYOUT_APPEND( l, fd_votes_align(),         fd_votes_footprint( slot_max, VTR_MAX )                       );
  l = FD_LAYOUT_APPEND( l, fd_tower_align(),         fd_tower_footprint( slot_max, VTR_MAX )                       );
  l = FD_LAYOUT_APPEND( l, fd_tower_vote_align(),    fd_tower_vote_footprint()                                     );
  l = FD_LAYOUT_APPEND( l, publishes_align(),        publishes_footprint( pub_max )                                );
  l = FD_LAYOUT_APPEND( l, fd_accdb_align(),         fd_accdb_footprint( tile->tower.max_live_slots, 0 )              );
  ulong epoch_vtr_chain_cnt = epoch_vtr_map_chain_cnt_est( VTR_MAX );
  l = FD_LAYOUT_APPEND( l, epoch_vtr_pool_align(),         epoch_vtr_pool_footprint( VTR_MAX )                     );
  l = FD_LAYOUT_APPEND( l, epoch_vtr_map_align(),          epoch_vtr_map_footprint( epoch_vtr_chain_cnt )          );
  l = FD_LAYOUT_APPEND( l, epoch_vtr_pool_align(),         epoch_vtr_pool_footprint( VTR_MAX )                     );
  l = FD_LAYOUT_APPEND( l, epoch_vtr_map_align(),          epoch_vtr_map_footprint( epoch_vtr_chain_cnt )          );
  return FD_LAYOUT_FINI( l, scratch_align() );
}

/* init_choreo allocates and initializes all choreo consensus structures
   from scratch memory.  scratch must be at least scratch_footprint
   bytes aligned to scratch_align().  The seed field at the start of
   scratch must be pre-initialized (eg. by privileged_init).  Returns a
   handle to the fd_tower_tile_t in scratch. */

static fd_tower_tile_t *
init_choreo( void                 * scratch,
             fd_topo_t const      * topo,
             fd_topo_tile_t const * tile ) {
  ulong slot_max    = fd_ulong_pow2_up( tile->tower.max_live_slots );
  ulong blk_max     = slot_max * EQVOC_MAX;
  ulong fec_max     = slot_max * tile->tower.max_shreds_per_block / FD_FEC_SHRED_CNT;
  ulong pub_max     = slot_max * FD_TOWER_SLOT_CONFIRMED_LEVEL_CNT;

  void * _accdb_shmem = fd_topo_obj_laddr( topo, tile->tower.accdb_obj_id );
  fd_accdb_shmem_t * accdb_shmem = fd_accdb_shmem_join( _accdb_shmem );
  FD_TEST( accdb_shmem );

  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_tower_tile_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_tower_tile_t), sizeof(fd_tower_tile_t)                                       );
  void  * auth_vtr      = FD_SCRATCH_ALLOC_APPEND( l, auth_vtr_align(),         auth_vtr_footprint()                                          );
  void  * eqvoc         = FD_SCRATCH_ALLOC_APPEND( l, fd_eqvoc_align(),         fd_eqvoc_footprint( slot_max, fec_max, PER_VTR_MAX, VTR_MAX ) );
  void  * ghost         = FD_SCRATCH_ALLOC_APPEND( l, fd_ghost_align(),         fd_ghost_footprint( blk_max, VTR_MAX )                        );
  void  * hfork         = FD_SCRATCH_ALLOC_APPEND( l, fd_hfork_align(),         fd_hfork_footprint( PER_VTR_MAX, VTR_MAX )                    );
  void  * votes         = FD_SCRATCH_ALLOC_APPEND( l, fd_votes_align(),         fd_votes_footprint( slot_max, VTR_MAX )                       );
  void  * tower         = FD_SCRATCH_ALLOC_APPEND( l, fd_tower_align(),         fd_tower_footprint( slot_max, VTR_MAX )                       );
  void  * scratch_tower = FD_SCRATCH_ALLOC_APPEND( l, fd_tower_vote_align(),    fd_tower_vote_footprint()                                     );
  void  * publishes     = FD_SCRATCH_ALLOC_APPEND( l, publishes_align(),        publishes_footprint( pub_max )                                );
  void  * accdb         = FD_SCRATCH_ALLOC_APPEND( l, fd_accdb_align(),         fd_accdb_footprint( tile->tower.max_live_slots, 0 )              );
  ulong epoch_vtr_chain_cnt = epoch_vtr_map_chain_cnt_est( VTR_MAX );
  void  * root_epoch_vtr_pool   = FD_SCRATCH_ALLOC_APPEND( l, epoch_vtr_pool_align(),         epoch_vtr_pool_footprint( VTR_MAX )             );
  void  * root_epoch_vtr_map    = FD_SCRATCH_ALLOC_APPEND( l, epoch_vtr_map_align(),          epoch_vtr_map_footprint( epoch_vtr_chain_cnt )  );
  void  * next_epoch_vtr_pool   = FD_SCRATCH_ALLOC_APPEND( l, epoch_vtr_pool_align(),         epoch_vtr_pool_footprint( VTR_MAX )             );
  void  * next_epoch_vtr_map    = FD_SCRATCH_ALLOC_APPEND( l, epoch_vtr_map_align(),          epoch_vtr_map_footprint( epoch_vtr_chain_cnt )  );
  ulong scratch_top = FD_SCRATCH_ALLOC_FINI( l, scratch_align() );
  if( FD_UNLIKELY( scratch_top > (ulong)scratch + scratch_footprint( tile ) ) )
    FD_LOG_ERR(( "scratch overflow %lu %lu %lu", scratch_top - (ulong)scratch - scratch_footprint( tile ), scratch_top, (ulong)scratch + scratch_footprint( tile ) ));
  (void)auth_vtr; /* privileged_init */
  ctx->eqvoc              = fd_eqvoc_join              ( fd_eqvoc_new              ( eqvoc, slot_max, fec_max, PER_VTR_MAX, VTR_MAX, ctx->seed ) );
  ctx->ghost              = fd_ghost_join              ( fd_ghost_new              ( ghost, blk_max, VTR_MAX, ctx->seed )                        );
  ctx->hfork              = fd_hfork_join              ( fd_hfork_new              ( hfork, PER_VTR_MAX, VTR_MAX, ctx->seed )                    );
  ctx->votes              = fd_votes_join              ( fd_votes_new              ( votes, slot_max, VTR_MAX, ctx->seed )                       );
  ctx->tower              = fd_tower_join              ( fd_tower_new              ( tower, slot_max, VTR_MAX, ctx->seed )                       );
  ctx->scratch_tower      = fd_tower_vote_join         ( fd_tower_vote_new         ( scratch_tower )                                             );
  ctx->publishes          = publishes_join             ( publishes_new             ( publishes, pub_max )                                        );
  fd_sleep_t * accdb_sleep = topo->sleep_obj_id!=ULONG_MAX ? fd_sleep_join( fd_topo_obj_laddr( topo, topo->sleep_obj_id ) ) : NULL;
  ctx->accdb              = fd_accdb_join              ( fd_accdb_new              ( accdb, _accdb_shmem, FD_ACCDB_FD_RW, 0UL, NULL, accdb_sleep, fd_topo_find_tile( topo, "accdb", 0UL ), 0 ) );
  ctx->mleaders           = fd_multi_epoch_leaders_join( fd_multi_epoch_leaders_new( ctx->mleaders_mem )                                         );
  ctx->root_epoch_vtr_pool = epoch_vtr_pool_join( epoch_vtr_pool_new( root_epoch_vtr_pool, VTR_MAX ) );
  ctx->root_epoch_vtr_map  = epoch_vtr_map_join ( epoch_vtr_map_new ( root_epoch_vtr_map,  epoch_vtr_chain_cnt, ctx->seed ) );
  ctx->next_epoch_vtr_pool = epoch_vtr_pool_join( epoch_vtr_pool_new( next_epoch_vtr_pool, VTR_MAX ) );
  ctx->next_epoch_vtr_map  = epoch_vtr_map_join ( epoch_vtr_map_new ( next_epoch_vtr_map,  epoch_vtr_chain_cnt, ctx->seed ) );

  FD_TEST( ctx->eqvoc );
  FD_TEST( ctx->ghost );
  FD_TEST( ctx->hfork );
  FD_TEST( ctx->votes );
  FD_TEST( ctx->tower );
  FD_TEST( ctx->scratch_tower );
  FD_TEST( ctx->publishes );
  FD_TEST( ctx->accdb );
  FD_TEST( ctx->mleaders );
  FD_TEST( ctx->root_epoch_vtr_pool );
  FD_TEST( ctx->root_epoch_vtr_map  );
  FD_TEST( ctx->next_epoch_vtr_pool );
  FD_TEST( ctx->next_epoch_vtr_map  );

  memset( ctx->duplicate_chunks, 0, sizeof(ctx->duplicate_chunks) );
  memset( &ctx->compact_tower_sync_serde, 0, sizeof(ctx->compact_tower_sync_serde) );
  memset( ctx->vote_txn, 0, sizeof(ctx->vote_txn) );
  ctx->vote_history_pending = 0;

  ctx->halt_signing     = 0;
  ctx->tower_file_dirty = 0;
  ctx->hard_fork_fatal  = tile->tower.hard_fork_fatal;
  ctx->wfs              = tile->tower.wait_for_supermajority;
  ctx->shred_version    = 0;
  ctx->init             = 0;
  ctx->root_epoch       = ULONG_MAX;

  memset( &ctx->metrics, 0, sizeof(ctx->metrics) );
  ctx->metrics.last_vote_slot = ULONG_MAX;

  return ctx;
}

/* tower_file_names writes the staging (name[0]) and live (name[1])
   tower file names for the identity, from the file name template tmpl,
   which can have {identity}. */

static void
tower_file_names( char const * tmpl,
                  char const * identity_b58,
                  char         name[ static 2 ][ PATH_MAX ] ) {
  char const * at = strstr( tmpl, "{identity}" );
  if( FD_LIKELY( at ) ) FD_TEST( fd_cstr_printf_check( name[ 1 ], PATH_MAX, NULL, "%.*s%s%s", (int)(at-tmpl), tmpl, identity_b58, at+sizeof("{identity}")-1UL ) );
  else                  fd_cstr_ncpy( name[ 1 ], tmpl, PATH_MAX );
  FD_TEST( fd_cstr_printf_check( name[ 0 ], PATH_MAX, NULL, "%s.new", name[ 1 ] ) );
}

/* tower_file_write saves our last vote the way Agave does, so an
   operator can move it to another validator with set-identity.  The
   file is signed by the identity, so it is only written while the sign
   tile is known to hold the same identity key as we do. */

static void
tower_file_write( fd_tower_tile_t * ctx ) {
  /* The first write after a set-identity gives the files the name of
     the new identity.  A file that already has that name is exchanged
     with ours, not replaced. */

  FD_BASE58_ENCODE_32_BYTES( ctx->identity_key->uc, identity_key_b58 );
  char name[ 2 ][ PATH_MAX ];
  tower_file_names( ctx->tower_name_tmpl, identity_key_b58, name );
  if( FD_UNLIKELY( strcmp( name[ 1 ], ctx->tower_name[ 1 ] ) ) ) {
    for( ulong i=0UL; i<2UL; i++ ) {
      if( FD_LIKELY( !syscall( SYS_renameat2, ctx->tower_dir_fd, ctx->tower_name[ i ], ctx->tower_dir_fd, name[ i ], RENAME_NOREPLACE ) ) ) continue;
      if( FD_UNLIKELY( errno!=EEXIST || syscall( SYS_renameat2, ctx->tower_dir_fd, ctx->tower_name[ i ], ctx->tower_dir_fd, name[ i ], RENAME_EXCHANGE ) ) )
        FD_LOG_ERR(( "renameat2(%s, %s) failed (%i-%s)", ctx->tower_name[ i ], name[ i ], errno, fd_io_strerror( errno ) ));
      FD_LOG_WARNING(( "tower file %s already existed, it is now %s", name[ i ], ctx->tower_name[ i ] ));
    }
    FD_LOG_NOTICE(( "tower file %s renamed to %s for the new identity", ctx->tower_name[ 1 ], name[ 1 ] ));
    memcpy( ctx->tower_name, name, sizeof(name) );
  }

  uchar buf[ FD_TOWER_FILE_MAX ];
  ulong sz = fd_tower_file_ser( &ctx->compact_tower_sync_serde, ctx->identity_key, buf );
  fd_keyguard_client_sign( ctx->keyguard_client, buf+FD_TOWER_FILE_SIG_OFF, buf+FD_TOWER_FILE_DATA_OFF, sz-FD_TOWER_FILE_DATA_OFF, FD_KEYGUARD_SIGN_TYPE_ED25519 );

  if( FD_UNLIKELY( pwrite( ctx->tower_fd[ 0 ], buf, sz, 0L )!=(long)sz ) ) FD_LOG_ERR(( "pwrite(%s) failed (%i-%s)", ctx->tower_name[ 0 ], errno, fd_io_strerror( errno ) ));
  if( FD_UNLIKELY( ftruncate( ctx->tower_fd[ 0 ], (long)sz ) ) )           FD_LOG_ERR(( "ftruncate(%s) failed (%i-%s)", ctx->tower_name[ 0 ], errno, fd_io_strerror( errno ) ));
  if( FD_UNLIKELY( syscall( SYS_renameat2, ctx->tower_dir_fd, ctx->tower_name[ 0 ], ctx->tower_dir_fd, ctx->tower_name[ 1 ], RENAME_EXCHANGE ) ) )
    FD_LOG_ERR(( "renameat2(%s, %s) failed (%i-%s)", ctx->tower_name[ 0 ], ctx->tower_name[ 1 ], errno, fd_io_strerror( errno ) ));
  int staging = ctx->tower_fd[ 0 ]; ctx->tower_fd[ 0 ] = ctx->tower_fd[ 1 ]; ctx->tower_fd[ 1 ] = staging;
  ctx->tower_file_dirty = 0;
}

static void
during_housekeeping( fd_tower_tile_t * ctx ) {
  if( FD_UNLIKELY( ctx->tower_file_dirty && !ctx->halt_signing && ctx->tower_dir_fd!=-1 ) ) tower_file_write( ctx );

  if( FD_UNLIKELY( fd_keyswitch_state_query( ctx->auth_vtr_keyswitch )==FD_KEYSWITCH_STATE_UNHALT_PENDING ) ) {
    if( fd_keyswitch_param_query( ctx->auth_vtr_keyswitch )==FD_KEYSWITCH_PARAM_AV_CLEAR ) ctx->halt_signing = 0;
    fd_keyswitch_state( ctx->auth_vtr_keyswitch, FD_KEYSWITCH_STATE_UNLOCKED );
  }

  if( FD_UNLIKELY( fd_keyswitch_state_query( ctx->auth_vtr_keyswitch )==FD_KEYSWITCH_STATE_SWITCH_PENDING ) ) {
    ulong param = fd_keyswitch_param_query( ctx->auth_vtr_keyswitch );
    if( FD_LIKELY( param==FD_KEYSWITCH_PARAM_AV_ADD ) ) {
      fd_pubkey_t pubkey = *(fd_pubkey_t const *)fd_type_pun_const( ctx->auth_vtr_keyswitch->bytes );
      if( FD_UNLIKELY( auth_vtr_query( ctx->auth_vtr, pubkey, NULL ) ) ) FD_LOG_CRIT(( "keyswitch: duplicate authorized voter key, keys not synced up with sign tile" ));
      if( FD_UNLIKELY( ctx->auth_vtr_path_cnt==FD_KEYGUARD_AUTH_VOTERS_MAX ) ) FD_LOG_CRIT(( "keyswitch: too many authorized voters, keys not synced up with sign tile" ));

      auth_vtr_t * auth_vtr = auth_vtr_insert( ctx->auth_vtr, pubkey );
      auth_vtr->paths_idx = ctx->auth_vtr_path_cnt;
      ctx->auth_vtr_path_cnt++;
    } else if( FD_LIKELY( param==FD_KEYSWITCH_PARAM_AV_CLEAR ) ) {
      ctx->halt_signing = 1;
      auth_vtr_clear( ctx->auth_vtr );
      ctx->auth_vtr_path_cnt = 0UL;
      if( FD_UNLIKELY( !publishes_empty( ctx->publishes ) ) ) return;
      ctx->auth_vtr_keyswitch->result = ctx->out_seq;
    } else {
      FD_LOG_CRIT(( "keyswitch: unexpected authorized voter operation %lu", param ));
    }
    fd_keyswitch_state( ctx->auth_vtr_keyswitch, FD_KEYSWITCH_STATE_COMPLETED );
  }

  if( FD_UNLIKELY( fd_keyswitch_state_query( ctx->identity_keyswitch )==FD_KEYSWITCH_STATE_UNHALT_PENDING ) ) {
    FD_LOG_DEBUG(( "keyswitch: unhalting signing" ));
    FD_CHECK_CRIT( ctx->halt_signing, "state machine corruption" );
    ctx->halt_signing = 0;
    fd_keyswitch_state( ctx->identity_keyswitch, FD_KEYSWITCH_STATE_COMPLETED );
  }

  if( FD_UNLIKELY( fd_keyswitch_state_query( ctx->identity_keyswitch )==FD_KEYSWITCH_STATE_SWITCH_PENDING ) ) {
    ulong seq_must_complete = fd_keyswitch_param_query( ctx->identity_keyswitch );
    if( FD_UNLIKELY( fd_seq_lt( ctx->replay_in_seq, seq_must_complete ) ) ) return;

    if( FD_LIKELY( !ctx->halt_signing ) ) FD_LOG_DEBUG(( "keyswitch: halting signing" ));
    ctx->halt_signing = 1;
    if( FD_UNLIKELY( !publishes_empty( ctx->publishes ) ) ) return;

    int identity_changed = !!memcmp( ctx->identity_key, ctx->identity_keyswitch->bytes, 32UL );
    memcpy( ctx->identity_key, ctx->identity_keyswitch->bytes, 32UL );
    if( identity_changed ) {
      clear_votes( ctx->tower );
      ctx->tower->wait_to_vote_slot = 0UL;
      ctx->vote_history_pending     = !!FD_LOAD( ulong, ctx->identity_keyswitch->bytes+32UL );
      if( ctx->vote_history_pending ) memcpy( &ctx->vote_history, ctx->identity_keyswitch->bytes+40UL, sizeof(fd_tower_file_t) );
    }
    FD_BASE58_ENCODE_32_BYTES( ctx->identity_key->uc, pubkey_str );
    FD_LOG_INFO(( "my identity key: %s (key switched)", pubkey_str ));
    ctx->identity_keyswitch->result = ctx->out_seq;
    fd_keyswitch_state( ctx->identity_keyswitch, FD_KEYSWITCH_STATE_COMPLETED );
  }
}

static inline void
metrics_write( fd_tower_tile_t * ctx ) {
  fd_accdb_flush_metrics( ctx->accdb );

  FD_MCNT_SET( TOWER, FRAG_NOT_READY_DROPPED, ctx->metrics.not_ready );

  FD_MCNT_SET  ( TOWER, FRAG_IGNORED,  ctx->metrics.ignored_cnt  );
  FD_MGAUGE_SET( TOWER, SLOT_LAST_IGNORED, ctx->metrics.ignored_slot );

  FD_MGAUGE_SET( TOWER, REPLAY_SLOT, ctx->metrics.replay_slot    );
  FD_MGAUGE_SET( TOWER, VOTE_SLOT,   ctx->metrics.last_vote_slot );
  FD_MGAUGE_SET( TOWER, RESET_SLOT,  ctx->metrics.reset_slot     );
  FD_MGAUGE_SET( TOWER, ROOT_SLOT,   ctx->metrics.root_slot      );
  FD_MGAUGE_SET( TOWER, INIT_SLOT,   ctx->metrics.init_slot      );

  FD_MCNT_ENUM_COPY( TOWER, FORK_DECISION, ctx->metrics.fork );
  FD_MCNT_ENUM_COPY( TOWER, VOTE_GATE,     ctx->metrics.gate );

  FD_MCNT_ENUM_COPY( TOWER, VOTE_TXN,               ctx->metrics.votes      );
  FD_MCNT_ENUM_COPY( TOWER, VOTE_SLOT_COUNTED,      ctx->metrics.vote_slots );
  FD_MCNT_ENUM_COPY( TOWER, VOTE_INTERMEDIATE_GATE, ctx->metrics.gate_int   );

  ulong eqvoc_proof[ FD_METRICS_ENUM_EQVOC_PROOF_RESULT_CNT ];
  eqvoc_proof[ FD_METRICS_ENUM_EQVOC_PROOF_RESULT_V_SUCCESS_IDX ] = ctx->metrics.eqvoc_success;
  eqvoc_proof[ FD_METRICS_ENUM_EQVOC_PROOF_RESULT_V_ERROR_IDX   ] = ctx->metrics.eqvoc_err;
  FD_MCNT_ENUM_COPY( TOWER, EQVOC_PROOF, eqvoc_proof );

  FD_MCNT_ENUM_COPY( TOWER, GHOST_VOTE, ctx->metrics.ghost );

  FD_MCNT_ENUM_COPY( TOWER, HARD_FORK_VOTE, ctx->metrics.hfork );

  FD_MGAUGE_SET( TOWER, HARD_FORK_MATCHED_SLOT,    ctx->metrics.hfork_matched_slot    );
  FD_MGAUGE_SET( TOWER, HARD_FORK_MISMATCHED_SLOT, ctx->metrics.hfork_mismatched_slot );

  FD_ACCDB_METRICS_WRITE( TOWER, fd_accdb_metrics( ctx->accdb ) );
}

static inline void
after_credit( fd_tower_tile_t *   ctx,
              fd_stem_context_t * stem,
              int *               opt_poll_in,
              int *               charge_busy ) {
  if( FD_LIKELY( !publishes_empty( ctx->publishes ) ) ) {
    publish_t * pub = publishes_pop_head_nocopy( ctx->publishes );
    memcpy( fd_chunk_to_laddr( ctx->out_mem, ctx->out_chunk ), &pub->msg, sizeof(fd_tower_msg_t) );
    fd_stem_publish( stem, OUT_IDX, pub->sig, ctx->out_chunk, sizeof(fd_tower_msg_t), 0UL, fd_frag_meta_ts_comp( fd_tickcount() ), fd_frag_meta_ts_comp( fd_tickcount() ) );
    ctx->out_chunk = fd_dcache_compact_next( ctx->out_chunk, sizeof(fd_tower_msg_t), ctx->out_chunk0, ctx->out_wmark );
    ctx->out_seq   = stem->seqs[ OUT_IDX ];
    *opt_poll_in   = 0; /* drain the publishes */
    *charge_busy   = 1;
  }
}

static inline int
before_frag( fd_tower_tile_t * ctx,
             ulong             in_idx,
             ulong             seq,
             ulong             sig ) {
  switch( ctx->in_kind[ in_idx ] ) {
  case IN_KIND_GOSSIP: return sig!=FD_GOSSIP_UPDATE_TAG_DUPLICATE_SHRED;
  case IN_KIND_REPLAY: {
    int filter = sig!=REPLAY_SIG_SLOT_COMPLETED && sig!=REPLAY_SIG_SLOT_DEAD && sig!=REPLAY_SIG_TXN_EXECUTED;
    if( filter ) ctx->replay_in_seq = seq+1UL;
    return filter;
  }
  case IN_KIND_SHRED:  return fd_shred_sig_src( sig )!=SHRED_SIG_SRC_TURBINE && fd_shred_sig_src( sig )!=SHRED_SIG_SRC_REPAIR;
  default:             return 0;
  }
}

static inline int
returnable_frag( fd_tower_tile_t *   ctx,
                 ulong               in_idx,
                 ulong               seq,
                 ulong               sig,
                 ulong               chunk,
                 ulong               sz,
                 ulong               ctl FD_PARAM_UNUSED,
                 ulong               tsorig,
                 ulong               tspub FD_PARAM_UNUSED,
                 fd_stem_context_t * stem ) {

  if( FD_UNLIKELY( !ctx->in[ in_idx ].mcache_only && ( chunk<ctx->in[ in_idx ].chunk0 || chunk>ctx->in[ in_idx ].wmark || sz>ctx->in[ in_idx ].mtu ) ) )
    FD_LOG_ERR(( "chunk %lu %lu from in %d corrupt, not in range [%lu,%lu]", chunk, sz, ctx->in_kind[ in_idx ], ctx->in[ in_idx ].chunk0, ctx->in[ in_idx ].wmark ));

  switch( ctx->in_kind[ in_idx ] ) {
  case IN_KIND_DEDUP:{
    if( FD_UNLIKELY( !ctx->init ) ) {
      /* we cannot backpressure vote txns on boot, without risking a
         deadlock on the snapshot load pipeline. */
      ctx->metrics.not_ready++;
      return 0;
    }
    fd_txn_m_t * txnm = (fd_txn_m_t *)fd_chunk_to_laddr( ctx->in[in_idx].mem, chunk );
    count_vote_txn( ctx, fd_txn_m_txn_t_const( txnm ), fd_txn_m_payload_const( txnm ) );
    return 0;
  }
  case IN_KIND_EPOCH: {
    fd_epoch_info_msg_t const * msg = fd_chunk_to_laddr_const( ctx->in[ in_idx ].mem, chunk );
    FD_TEST( msg->staked_vote_cnt<=MAX_STAKE_WEIGHTS );
    FD_TEST( msg->staked_id_cnt<=MAX_STAKE_WEIGHTS );
    fd_multi_epoch_leaders_epoch_msg_init( ctx->mleaders, msg );
    fd_multi_epoch_leaders_epoch_msg_fini( ctx->mleaders );
    return 0;
  }
  case IN_KIND_GOSSIP: {
    if( FD_UNLIKELY( !ctx->init ) ) { ctx->metrics.not_ready++; return 0; } /* don't backpressure gossip on boot */
    if( FD_LIKELY( sig==FD_GOSSIP_UPDATE_TAG_DUPLICATE_SHRED ) ) {
      fd_gossip_update_message_t const  * msg             = (fd_gossip_update_message_t const *)fd_type_pun_const( fd_chunk_to_laddr_const( ctx->in[ in_idx ].mem, chunk ) );
      fd_gossip_duplicate_shred_t const * duplicate_shred = msg->duplicate_shred;
      fd_pubkey_t const                 * from            = (fd_pubkey_t const *)fd_type_pun_const( msg->origin );
      fd_epoch_leaders_t const *          lsched          = fd_multi_epoch_leaders_get_lsched_for_slot( ctx->mleaders, duplicate_shred->slot );
      if( FD_UNLIKELY( !lsched ) ) { ctx->metrics.not_ready++; return 0; }
      int eqvoc_err = fd_eqvoc_chunk_insert( ctx->eqvoc, ctx->tower->root, ctx->shred_version, lsched, from, duplicate_shred, ctx->duplicate_chunks );
      update_metrics_eqvoc( ctx, eqvoc_err );
      if( FD_UNLIKELY( eqvoc_err==FD_EQVOC_SUCCESS ) ) {
        publish_slot_duplicate( ctx, ctx->duplicate_chunks, duplicate_shred->slot );
      }
    }
    return 0;
  }
  case IN_KIND_IPECHO: {
    FD_TEST( sig && sig<=USHORT_MAX );
    ctx->shred_version = (ushort)sig;
    return 0;
  }
  case IN_KIND_REPLAY: {
    switch( sig ) {
    case REPLAY_SIG_SLOT_COMPLETED:;
      if( FD_UNLIKELY( ctx->halt_signing ) ) return 1; /* backpressure replay_slot_completed during halt_signing. */
      fd_replay_slot_completed_t * slot_completed = (fd_replay_slot_completed_t *)fd_type_pun( fd_chunk_to_laddr( ctx->in[ in_idx ].mem, chunk ) );
      /* Return frags until the epoch schedule is loaded.  The epoch
         schedule frag (replay_epoch link) can arrive after this
         slot frag (replay_out link) because they travel on different
         links with no cross-link ordering guarantee. */
      if( FD_UNLIKELY( !fd_multi_epoch_leaders_get_lsched_for_slot( ctx->mleaders, slot_completed->slot ) ) ) return 1;
      replay_slot_completed( ctx, slot_completed, tsorig, stem );
      break;
    case REPLAY_SIG_SLOT_DEAD:;
      fd_replay_slot_dead_t * slot_dead = (fd_replay_slot_dead_t *)fd_chunk_to_laddr( ctx->in[ in_idx ].mem, chunk );
      if( FD_UNLIKELY( slot_dead->slot < ctx->tower->root ) ) break; /* ignore dead slots before root */
      fd_epoch_leaders_t const * lsched = fd_multi_epoch_leaders_get_lsched_for_slot( ctx->mleaders, slot_dead->slot );
      FD_TEST( lsched );
      FD_TEST( lsched->epoch==ctx->root_epoch || lsched->epoch==ctx->root_epoch + 1 );
      ulong total_stake = fd_ulong_if( lsched->epoch==ctx->root_epoch, ctx->root_epoch_total_stake, ctx->next_epoch_total_stake );
      int hfork_flag = fd_hfork_record_our_bank_hash( ctx->hfork, &slot_dead->block_id, NULL, total_stake );
      update_metrics_hfork( ctx, hfork_flag, slot_dead->slot, &slot_dead->block_id );
      break;
    case REPLAY_SIG_TXN_EXECUTED:;
      FD_TEST( ctx->init ); /* replay_txn_executed should never be received before replay_slot_completed, which sets init to 1. */
      fd_replay_txn_executed_t * txn_executed = fd_type_pun( fd_chunk_to_laddr( ctx->in[in_idx].mem, chunk ) );
      if( FD_UNLIKELY( !txn_executed->is_committable || txn_executed->is_fees_only || txn_executed->txn_err ) ) break;
      count_vote_txn( ctx, TXN(txn_executed->txn), txn_executed->txn->payload );
      break;
    default:
      break;
    }
    ctx->replay_in_seq = seq+1UL;
    return 0;
  }
  case IN_KIND_SHRED: {
    if( FD_LIKELY( fd_shred_sig_src( sig )==SHRED_SIG_SRC_TURBINE || fd_shred_sig_src( sig )==SHRED_SIG_SRC_REPAIR ) ) {
      fd_shred_base_t * msg       = (fd_shred_base_t *)fd_type_pun( fd_chunk_to_laddr( ctx->in[ in_idx ].mem, chunk ) );
      fd_shred_t      * shred     = &msg->shred;
      int               eqvoc_err = fd_eqvoc_shred_insert( ctx->eqvoc, fd_shred_sig_res( sig )==SHRED_SIG_RESULT_EQVOC, shred, ctx->duplicate_chunks );
      update_metrics_eqvoc( ctx, eqvoc_err );
      if( FD_UNLIKELY( eqvoc_err==FD_EQVOC_SUCCESS ) ) publish_slot_duplicate( ctx, ctx->duplicate_chunks, shred->slot );
    }
    return 0;
  }
  default: FD_LOG_ERR(( "unexpected input kind %d", ctx->in_kind[ in_idx ] ));
  }
}

static void
privileged_init( fd_topo_t const *      topo,
                 fd_topo_tile_t const * tile ) {
  void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );
  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_tower_tile_t * ctx      = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_tower_tile_t),   sizeof(fd_tower_tile_t)        );
  void            * auth_vtr = FD_SCRATCH_ALLOC_APPEND( l, auth_vtr_align(), auth_vtr_footprint() );
  ulong scratch_top = FD_SCRATCH_ALLOC_FINI( l, scratch_align() );
  if( FD_UNLIKELY( scratch_top > (ulong)scratch + scratch_footprint( tile ) ) )
    FD_LOG_ERR(( "scratch overflow %lu %lu %lu", scratch_top - (ulong)scratch - scratch_footprint( tile ), scratch_top, (ulong)scratch + scratch_footprint( tile ) ));

  FD_TEST( fd_rng_secure( &ctx->seed, sizeof(ctx->seed) ) );

  if( FD_UNLIKELY( !strcmp( tile->tower.identity_key, "" ) ) ) FD_LOG_ERR(( "missing [paths.identity_key]" ));
  ctx->identity_key[ 0 ] = *(fd_pubkey_t const *)fd_type_pun_const( fd_keyload_load( tile->tower.identity_key, /* pubkey only: */ 1 ) );

  /* The vote key can be specified either directly as a base58 encoded
     pubkey, or as a file path.  We first try to decode as a pubkey. */

  uchar * vote_key = fd_base58_decode_32( tile->tower.vote_account, ctx->vote_account->uc );
  if( FD_UNLIKELY( !vote_key ) ) {
    if( FD_UNLIKELY( !strcmp( tile->tower.vote_account, "" ) ) ) FD_LOG_ERR(( "missing [paths.vote_account]" ));
    ctx->vote_account[ 0 ] = *(fd_pubkey_t const *)fd_type_pun_const( fd_keyload_load( tile->tower.vote_account, /* pubkey only: */ 1 ) );
  }

  ulong node_info_obj_id = fd_pod_query_ulong( topo->props, "node_info", ULONG_MAX ); FD_TEST( node_info_obj_id!=ULONG_MAX );
  fd_node_info_box_t * node_info = fd_node_info_box_join( fd_topo_obj_laddr( topo, node_info_obj_id ) );  FD_TEST( node_info );
  fd_node_info_write_begin( node_info );
  node_info->info.vote_account = *ctx->vote_account;
  fd_node_info_write_end( node_info );

  ctx->auth_vtr = auth_vtr_join( auth_vtr_new( auth_vtr ) );
  for( ulong i=0UL; i<tile->tower.authorized_voter_paths_cnt; i++ ) {
    fd_pubkey_t pubkey = *(fd_pubkey_t const *)fd_type_pun_const( fd_keyload_load( tile->tower.authorized_voter_paths[ i ], /* pubkey only: */ 1 ) );
    if( FD_UNLIKELY( auth_vtr_query( ctx->auth_vtr, pubkey, NULL ) ) ) {
      FD_BASE58_ENCODE_32_BYTES( pubkey.uc, pubkey_b58 );
      FD_LOG_ERR(( "authorized voter key duplicate %s", pubkey_b58 ));
    }

    auth_vtr_t * auth_vtr = auth_vtr_insert( ctx->auth_vtr, pubkey );
    auth_vtr->paths_idx = i;
  }
  ctx->auth_vtr_path_cnt = tile->tower.authorized_voter_paths_cnt;

  /* The tower file, see tower_file_write. */

  ctx->tower_dir_fd  = -1;
  ctx->tower_fd[ 0 ] = -1;
  ctx->tower_fd[ 1 ] = -1;
  if( FD_LIKELY( tile->tower.tower_path[ 0 ] ) ) {
    char path[ PATH_MAX ];
    fd_cstr_ncpy( path, tile->tower.tower_path, PATH_MAX );
    char * slash = strrchr( path, '/' ); /* absolute, {identity} only in the file name, see fd_config_parse.c */
    FD_TEST( slash );
    fd_cstr_ncpy( ctx->tower_name_tmpl, slash+1, PATH_MAX );
    slash[ slash==path ] = '\0'; /* path is now the directory, "/" stays "/" */

    FD_BASE58_ENCODE_32_BYTES( ctx->identity_key->uc, identity_key_b58 );
    tower_file_names( ctx->tower_name_tmpl, identity_key_b58, ctx->tower_name );

    ctx->tower_dir_fd = open( path, O_RDONLY|O_DIRECTORY );
    if( FD_UNLIKELY( -1==ctx->tower_dir_fd ) ) FD_LOG_ERR(( "open(`%s`) failed (%i-%s)", path, errno, fd_io_strerror( errno ) ));
    for( ulong i=0UL; i<2UL; i++ ) {
      ctx->tower_fd[ i ] = openat( ctx->tower_dir_fd, ctx->tower_name[ i ], O_WRONLY|O_CREAT, 0644 );
      if( FD_UNLIKELY( -1==ctx->tower_fd[ i ] ) ) FD_LOG_ERR(( "open(`%s/%s`) failed (%i-%s)", path, ctx->tower_name[ i ], errno, fd_io_strerror( errno ) ));
    }
  }
}

static void
unprivileged_init( fd_topo_t const *      topo,
                   fd_topo_tile_t const * tile ) {
  void *            scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );
  fd_tower_tile_t * ctx     = init_choreo( scratch, topo, tile );

  ctx->wksp               = topo->workspaces[ topo->objs[ tile->tile_obj_id ].wksp_id ].wksp;
  ctx->identity_keyswitch = fd_keyswitch_join( fd_topo_obj_laddr( topo, tile->id_keyswitch_obj_id ) );
  ctx->auth_vtr_keyswitch = fd_keyswitch_join( fd_topo_obj_laddr( topo, tile->av_keyswitch_obj_id ) );

  FD_TEST( ctx->wksp  );
  FD_TEST( ctx->identity_keyswitch );
  FD_TEST( ctx->auth_vtr_keyswitch );
  FD_TEST( ctx->auth_vtr );

  ulong banks_obj_id = fd_pod_query_ulong( topo->props, "banks", ULONG_MAX );
  FD_TEST( banks_obj_id!=ULONG_MAX );
  ctx->banks = fd_banks_join( fd_topo_obj_laddr( topo, banks_obj_id ) );
  FD_TEST( ctx->banks );

  FD_TEST( tile->in_cnt<sizeof(ctx->in_kind)/sizeof(ctx->in_kind[0]) );
  for( ulong i=0UL; i<tile->in_cnt; i++ ) {
    fd_topo_link_t const * link = &topo->links[ tile->in_link_id[ i ] ];
    fd_topo_wksp_t const * link_wksp = &topo->workspaces[ topo->objs[ link->dcache_obj_id ].wksp_id ];

    if     ( FD_LIKELY( !strcmp( link->name, "dedup_resolv"  ) ) ) ctx->in_kind[ i ] = IN_KIND_DEDUP;
    else if( FD_LIKELY( !strcmp( link->name, "replay_epoch"  ) ) ) ctx->in_kind[ i ] = IN_KIND_EPOCH;
    else if( FD_LIKELY( !strcmp( link->name, "gossip_misc"   ) ) ) ctx->in_kind[ i ] = IN_KIND_GOSSIP;
    else if( FD_LIKELY( !strcmp( link->name, "ipecho_out"    ) ) ) ctx->in_kind[ i ] = IN_KIND_IPECHO;
    else if( FD_LIKELY( !strcmp( link->name, "replay_out"    ) ) ) ctx->in_kind[ i ] = IN_KIND_REPLAY;
    else if( FD_LIKELY( !strcmp( link->name, "shred_out"     ) ) ) ctx->in_kind[ i ] = IN_KIND_SHRED;
    else if( FD_LIKELY( !strcmp( link->name, "sign_tower"    ) ) ) ctx->in_kind[ i ] = IN_KIND_SIGN;
    else FD_LOG_ERR(( "tower tile has unexpected input link %lu %s", i, link->name ));

    ctx->in[ i ].mcache_only = !link->mtu;
    if( FD_LIKELY( !ctx->in[ i ].mcache_only ) ) {
      ctx->in[ i ].mem    = link_wksp->wksp;
      ctx->in[ i ].mtu    = link->mtu;
      ctx->in[ i ].chunk0 = fd_dcache_compact_chunk0( ctx->in[ i ].mem, link->dcache );
      ctx->in[ i ].wmark  = fd_dcache_compact_wmark ( ctx->in[ i ].mem, link->dcache, link->mtu );
    }
  }

  ctx->out_mem       = topo->workspaces[ topo->objs[ topo->links[ tile->out_link_id[ 0 ] ].dcache_obj_id ].wksp_id ].wksp;
  ctx->out_chunk0    = fd_dcache_compact_chunk0( ctx->out_mem, topo->links[ tile->out_link_id[ 0 ] ].dcache );
  ctx->out_wmark     = fd_dcache_compact_wmark ( ctx->out_mem, topo->links[ tile->out_link_id[ 0 ] ].dcache, topo->links[ tile->out_link_id[ 0 ] ].mtu );
  ctx->out_chunk     = ctx->out_chunk0;
  ctx->out_seq       = 0UL;
  ctx->replay_in_seq = 0UL;

  ulong sign_in_idx  = fd_topo_find_tile_in_link ( topo, tile, "sign_tower", tile->kind_id );
  ulong sign_out_idx = fd_topo_find_tile_out_link( topo, tile, "tower_sign", tile->kind_id );
  if( FD_LIKELY( sign_in_idx!=ULONG_MAX && sign_out_idx!=ULONG_MAX ) ) {
    fd_topo_link_t const * sign_in  = &topo->links[ tile->in_link_id [ sign_in_idx  ] ];
    fd_topo_link_t const * sign_out = &topo->links[ tile->out_link_id[ sign_out_idx ] ];
    fd_sleep_t * sleep = topo->sleep_obj_id!=ULONG_MAX ? fd_sleep_join( fd_topo_obj_laddr( topo, topo->sleep_obj_id ) ) : NULL;
    FD_TEST( fd_keyguard_client_join( fd_keyguard_client_new( ctx->keyguard_client, sign_out->mcache, sign_out->dcache, sign_in->mcache, sign_in->dcache,
                                                              sign_out->mtu, sign_in->mtu, sleep, sign_out->id, fd_topo_find_link_consumer( topo, sign_out ) ) ) );
  } else {
    ctx->tower_dir_fd = -1; /* no signer (forktest), the tower file is not written */
  }

  FD_BASE58_ENCODE_32_BYTES( ctx->vote_account->uc, vote_account_b58 );
  FD_BASE58_ENCODE_32_BYTES( ctx->identity_key->uc, identity_key_b58 );
  FD_LOG_INFO(( "my vote account: %s", vote_account_b58 ));
  FD_LOG_INFO(( "my identity key: %s", identity_key_b58 ));
}

static ulong
populate_allowed_seccomp( fd_topo_t const *      topo,
                          fd_topo_tile_t const * tile,
                          ulong                  out_cnt,
                          struct sock_filter *   out ) {
  void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );
  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_tower_tile_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_tower_tile_t), sizeof(fd_tower_tile_t) );

  populate_sock_filter_policy_fd_tower_tile( out_cnt, out, (uint)fd_log_private_logfile_fd(), (uint)ctx->tower_dir_fd, (uint)ctx->tower_fd[ 0 ], (uint)ctx->tower_fd[ 1 ], FD_ACCDB_FD_RW );
  return sock_filter_policy_fd_tower_tile_instr_cnt;
}

static ulong
populate_allowed_fds( fd_topo_t const *      topo,
                      fd_topo_tile_t const * tile,
                      ulong                  out_fds_cnt,
                      int *                  out_fds ) {
  void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );
  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_tower_tile_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_tower_tile_t), sizeof(fd_tower_tile_t) );

  if( FD_UNLIKELY( out_fds_cnt<6UL ) ) FD_LOG_ERR(( "out_fds_cnt %lu", out_fds_cnt ));

  ulong out_cnt = 0UL;
  out_fds[ out_cnt++ ] = 2; /* stderr */
  if( FD_LIKELY( -1!=fd_log_private_logfile_fd() ) )
    out_fds[ out_cnt++ ] = fd_log_private_logfile_fd(); /* logfile */
  if( FD_LIKELY( -1!=ctx->tower_dir_fd ) ) {
    out_fds[ out_cnt++ ] = ctx->tower_dir_fd;
    out_fds[ out_cnt++ ] = ctx->tower_fd[ 0 ];
    out_fds[ out_cnt++ ] = ctx->tower_fd[ 1 ];
  }
  out_fds[ out_cnt++ ] = FD_ACCDB_FD_RW; /* accounts database */

  return out_cnt;
}

#define STEM_BURST (2UL)        /* MAX( slot_confirmed, slot_rooted AND (slot_done OR slot_ignored) ) */
#define STEM_LAZY  (128L*3000L) /* see explanation in fd_pack */

#define STEM_CALLBACK_CONTEXT_TYPE        fd_tower_tile_t
#define STEM_CALLBACK_CONTEXT_ALIGN       alignof(fd_tower_tile_t)
#define STEM_CALLBACK_DURING_HOUSEKEEPING during_housekeeping
#define STEM_CALLBACK_METRICS_WRITE       metrics_write
#define STEM_CALLBACK_AFTER_CREDIT        after_credit
#define STEM_CALLBACK_BEFORE_FRAG         before_frag
#define STEM_CALLBACK_RETURNABLE_FRAG     returnable_frag

#include "../../disco/stem/fd_stem.c"

static ulong
max_event_sz( fd_topo_tile_t const * tile FD_PARAM_UNUSED ) {
  return sizeof(fd_event_slot_confirmed_t) > sizeof(fd_event_block_equivocated_t) ?
         sizeof(fd_event_slot_confirmed_t) : sizeof(fd_event_block_equivocated_t);
}

fd_topo_run_tile_t fd_tile_tower = {
  .name                     = "tower",
  .allow_renameat           = 1, /* tower_file_write */
  .max_event_sz             = max_event_sz,
  .populate_allowed_seccomp = populate_allowed_seccomp,
  .populate_allowed_fds     = populate_allowed_fds,
  .scratch_align            = scratch_align,
  .scratch_footprint        = scratch_footprint,
  .unprivileged_init        = unprivileged_init,
  .privileged_init          = privileged_init,
  .run                      = stem_run,
};
