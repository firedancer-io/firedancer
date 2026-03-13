#include "fd_tower_tile.h"
#include "generated/fd_tower_tile_seccomp.h"

#include "../../choreo/eqvoc/fd_eqvoc.h"
#include "../../choreo/ghost/fd_ghost.h"
#include "../../choreo/hfork/fd_hfork.h"
#include "../../choreo/votes/fd_votes.h"
#include "../../choreo/tower/fd_tower.h"
#include "../../choreo/tower/fd_tower_voters.h"
#include "../../choreo/tower/fd_tower_blocks.h"
#include "../../choreo/tower/fd_tower_serdes.h"
#include "../../choreo/tower/fd_tower_stakes.h"
#include "../../disco/fd_txn_p.h"
#include "../../disco/keyguard/fd_keyload.h"
#include "../../disco/keyguard/fd_keyswitch.h"
#include "../../disco/metrics/fd_metrics.h"
#include "../../disco/topo/fd_topo.h"
#include "../../disco/fd_txn_m.h"
#include "../../discof/fd_accdb_topo.h"
#include "../../discof/replay/fd_replay_tile.h"
#include "../../flamenco/accdb/fd_accdb_sync.h"
#include "../../flamenco/accdb/fd_accdb_pipe.h"
#include "../../flamenco/leaders/fd_multi_epoch_leaders.h"
#include "../../flamenco/runtime/fd_bank.h"
#include "../../flamenco/runtime/program/vote/fd_vote_state_versioned.h"
#include "../../util/pod/fd_pod.h"

#include <errno.h>
#include <fcntl.h>
#include <unistd.h>

/* The tower tile is responsible for two things:

   1. running the fork choice (fd_ghost) and TowerBFT (fd_tower) rules
      after replaying a block.
   2. listening to gossip (duplicate shred and vote messages) and
      monitoring for duplicate or duplicate confirmed blocks (fd_votes).

   Tower signals to other tiles about events that occur as a result of
   those two above events, such as what block to vote on, what block to
   reset onto as leader, what block got rooted, what blocks are
   duplicates and what blocks are confirmed.

   In general, tower uses the block_id as the identifier for blocks. The
   block_id is the merkle root of the last FEC set for a block.  This is
   guaranteed to be unique for a given block and is the canonical
   identifier over the slot number because unlike slot numbers, if a
   leader equivocates (produces multiple blocks for the same slot) the
   block_id can disambiguate the blocks.

   However, the block_id was only introduced into the Solana protocol
   recently, and TowerBFT still uses the "legacy" identifier of slot
   numbers for blocks.  So the tile (and relevant modules) will use
   block_id when possible to interface with the protocol but otherwise
   falling back to slot number when block_id is unsupported. */

#define LOGGING 0

#define IN_KIND_DEDUP  (0)
#define IN_KIND_EPOCH  (1)
#define IN_KIND_REPLAY (2)
#define IN_KIND_GOSSIP (3)
#define IN_KIND_IPECHO (4)
#define IN_KIND_SHRED  (5)

#define OUT_IDX 0 /* only a single out link tower_out */
#define AUTH_VTR_LG_MAX (5) /* The Solana Vote Interface supports up to 32 authorized voters. */
FD_STATIC_ASSERT( 1<<AUTH_VTR_LG_MAX==32, AUTH_VTR_LG_MAX );

/* Tower processes at most 2 equivocating blocks for a given slot: the
   first block is the first one we observe for a slot, and the second
   block is the one that gets duplicate confirmed.  Most of the time,
   they are the same (ie. the block we first saw is the block that gets
   duplicate confirmed), but we size for the worst case which is every
   block in slot_max equivocates and we always see 2 blocks for every
   slot. */

#define EQVOC_MAX (2)

/* The Alpenglow VAT caps the voting set of validators to 2000.  Only
   the top 2000 voters by stake will be counted towards consensus rules.
   Firedancer uses the same bound for TowerBFT.

   https://github.com/solana-foundation/solana-improvement-documents/blob/main/proposals/0357-alpenglow_validator_admission_ticket.md */

#define VTR_MAX (2000) /* the maximum # of unique voters ie. node pubkeys. */

/* PER_VTR_MAX controls how many "entries" a validator is allowed to
   occupy in various vote-tracking structures.  This is set somewhat
   arbitrarily based on expected worst-case usage by an honest validator
   and is set to guard against a malicious spamming validator attempting
   to fill up Firedancer structures. */

#define PER_VTR_MAX (512) /* the maximum amount of slot history the sysvar retains */

struct publish {
  ulong          sig;
  fd_tower_msg_t msg;
};
typedef struct publish publish_t;

#define DEQUE_NAME publishes
#define DEQUE_T    publish_t
#include "../../util/tmpl/fd_deque_dynamic.c"

struct auth_vtr {
  fd_pubkey_t addr;      /* map key, vote account address */
  uint        hash;      /* reserved for use by fd_map */
  ulong       paths_idx; /* index in authorized voter paths */
};
typedef struct auth_vtr auth_vtr_t;

#define MAP_NAME               auth_vtr
#define MAP_T                  auth_vtr_t
#define MAP_LG_SLOT_CNT        AUTH_VTR_LG_MAX
#define MAP_KEY                addr
#define MAP_KEY_T              fd_pubkey_t
#define MAP_KEY_NULL           (fd_pubkey_t){0}
#define MAP_KEY_EQUAL(k0,k1)   (!(memcmp((k0).key,(k1).key,sizeof(fd_pubkey_t))))
#define MAP_KEY_INVAL(k)       (MAP_KEY_EQUAL((k),MAP_KEY_NULL))
#define MAP_KEY_EQUAL_IS_SLOW  1
#define MAP_KEY_HASH(k)        ((uint)fd_ulong_hash( fd_ulong_load_8( (k).uc ) ))
#include "../../util/tmpl/fd_map.c"

#define AUTH_VOTERS_MAX (16UL)

typedef struct {
  int         mcache_only;
  fd_wksp_t * mem;
  ulong       chunk0;
  ulong       wmark;
  ulong       mtu;
} in_ctx_t;

struct fd_tower_tile {
  ulong            seed; /* map seed */
  int              checkpt_fd;
  int              restore_fd;
  fd_pubkey_t      identity_key[1];
  fd_pubkey_t      vote_account[1];
  ulong            auth_vtr_path_cnt;  /* number of authorized voter paths passed to tile */
  uchar            our_vote_acct[FD_VOTE_STATE_DATA_MAX]; /* buffer for reading back our own vote acct data */
  ulong            our_vote_acct_sz;

  /* owned joins */

  fd_wksp_t *      wksp; /* workspace */
  fd_keyswitch_t * identity_keyswitch;
  auth_vtr_t *     auth_vtr;
  fd_keyswitch_t * auth_vtr_keyswitch; /* authorized voter keyswitch */

  fd_eqvoc_t * eqvoc;
  fd_ghost_t * ghost;
  fd_hfork_t * hfork;
  fd_votes_t * votes;
  fd_tower_t * tower;

  fd_tower_t *        scratch_tower; /* spare tower used during processing */
  fd_tower_blocks_t * tower_blocks;
  fd_tower_lockos_t * tower_lockos;
  fd_tower_stakes_t * tower_stakes; /* tracks the stakes for each voter in the epoch per fork */
  fd_tower_voters_t * tower_voters;

  publish_t *                publishes; /* deque of slot_confirmed msgs queued for publishing */
  fd_multi_epoch_leaders_t * mleaders; /* multi-epoch leaders */

  /* borrowed joins */

  fd_banks_t      banks[1];
  fd_accdb_user_t accdb[1];

  /* static structures */

  fd_gossip_duplicate_shred_t   chunks[FD_EQVOC_CHUNK_CNT];
  fd_compact_tower_sync_serde_t compact_tower_sync_serde;
  uchar                         vote_txn[FD_TPU_PARSED_MTU];

  uchar __attribute__((aligned(FD_MULTI_EPOCH_LEADERS_ALIGN))) mleaders_mem[ FD_MULTI_EPOCH_LEADERS_FOOTPRINT ];

  /* metadata */

  int    halt_signing;
  int    hard_fork_fatal;
  ushort shred_version;
  ulong  init_slot; /* initial slot (either genesis or snapshot slot) */
  ulong  root_slot; /* monotonically increasing contiguous root slot */

  /* in/out link setup */

  int      in_kind[ 64UL ];
  in_ctx_t in     [ 64UL ];

  fd_wksp_t * out_mem;
  ulong       out_chunk0;
  ulong       out_wmark;
  ulong       out_chunk;
  ulong       out_seq;

  /* metrics */

  struct {

    ulong slot_ignored_cnt;
    ulong slot_ignored_gauge;
    ulong slot_eqvoced_cnt;
    ulong slot_eqvoced_gauge;

    ulong replay_slot;
    ulong vote_slot;
    ulong reset_slot;
    ulong root_slot;
    ulong init_slot;

    ulong ancestor_rollback;
    ulong sibling_confirmed;
    ulong same_fork;
    ulong switch_pass;
    ulong switch_fail;
    ulong lockout_fail;
    ulong threshold_fail;
    ulong propagated_fail;

    ulong vote_txn_bad_deser;
    ulong vote_txn_not_tower_sync;
    ulong vote_txn_empty_tower;
    ulong vote_txn_unknown_slot;
    ulong vote_txn_unknown_block_id;

    ulong eqvoc_success_merkle;
    ulong eqvoc_success_meta;
    ulong eqvoc_success_last;
    ulong eqvoc_success_overlap;
    ulong eqvoc_success_chained;

    ulong eqvoc_err_serde;
    ulong eqvoc_err_slot;
    ulong eqvoc_err_version;
    ulong eqvoc_err_type;
    ulong eqvoc_err_merkle;
    ulong eqvoc_err_signature;

    ulong eqvoc_err_chunk_cnt;
    ulong eqvoc_err_chunk_idx;
    ulong eqvoc_err_chunk_len;

    ulong eqvoc_err_ignored_from;
    ulong eqvoc_err_ignored_slot;

    ulong eqvoc_proof_constructed;
    ulong eqvoc_proof_verified;

    ulong hfork_matched_slot;
    ulong hfork_mismatched_slot;
  } metrics;
};
typedef struct fd_tower_tile fd_tower_tile_t;

static void
update_eqvoc_metrics( fd_tower_tile_t * ctx,
                      int               err ) {
  switch( err ) {

  case FD_EQVOC_SUCCESS: break;

  case FD_EQVOC_SUCCESS_MERKLE:  ctx->metrics.eqvoc_success_merkle++;  break;
  case FD_EQVOC_SUCCESS_META:    ctx->metrics.eqvoc_success_meta++;    break;
  case FD_EQVOC_SUCCESS_LAST:    ctx->metrics.eqvoc_success_last++;    break;
  case FD_EQVOC_SUCCESS_OVERLAP: ctx->metrics.eqvoc_success_overlap++; break;
  case FD_EQVOC_SUCCESS_CHAINED: ctx->metrics.eqvoc_success_chained++; break;

  case FD_EQVOC_ERR_SERDE:   ctx->metrics.eqvoc_err_serde++;     break;
  case FD_EQVOC_ERR_SLOT:    ctx->metrics.eqvoc_err_slot++;      break;
  case FD_EQVOC_ERR_VERSION: ctx->metrics.eqvoc_err_version++;   break;
  case FD_EQVOC_ERR_TYPE:    ctx->metrics.eqvoc_err_type++;      break;
  case FD_EQVOC_ERR_MERKLE:  ctx->metrics.eqvoc_err_merkle++;    break;
  case FD_EQVOC_ERR_SIG:     ctx->metrics.eqvoc_err_signature++; break;

  case FD_EQVOC_ERR_CHUNK_CNT: ctx->metrics.eqvoc_err_chunk_cnt++; break;
  case FD_EQVOC_ERR_CHUNK_IDX: ctx->metrics.eqvoc_err_chunk_idx++; break;
  case FD_EQVOC_ERR_CHUNK_LEN: ctx->metrics.eqvoc_err_chunk_len++; break;

  case FD_EQVOC_ERR_IGNORED_FROM: ctx->metrics.eqvoc_err_ignored_from++; break;
  case FD_EQVOC_ERR_IGNORED_SLOT: ctx->metrics.eqvoc_err_ignored_slot++; break;

  default: FD_LOG_ERR(( "unhandled eqvoc err %d", err ));
  }
}

static void
update_hfork_metrics( fd_tower_tile_t *      ctx,
                      fd_hfork_blk_t const * blk,
                      ulong                  slot,
                      fd_hash_t const *      block_id ) {
  if     ( FD_LIKELY  ( blk->flag > 0 ) ) ctx->metrics.hfork_matched_slot = fd_ulong_max( ctx->metrics.hfork_matched_slot, slot );
  else if( FD_UNLIKELY( blk->flag < 0 ) ) {
    ctx->metrics.hfork_mismatched_slot = fd_ulong_max( ctx->metrics.hfork_mismatched_slot, slot );
    FD_BASE58_ENCODE_32_BYTES( block_id->uc, _block_id );
    if( FD_UNLIKELY( ctx->hard_fork_fatal ) ) FD_LOG_ERR    (( "HARD FORK DETECTED for slot %lu block ID `%s`", slot, _block_id ));
    else                                      FD_LOG_WARNING(( "HARD FORK DETECTED for slot %lu block ID `%s`", slot, _block_id ));
  }
}

static void
confirm_block( fd_tower_tile_t * ctx,
               fd_tower_blk_t *  tower_blk,
               fd_ghost_blk_t *  ghost_blk,
               fd_votes_blk_t *  votes_blk,
               ulong             total_stake ) {

  static double const ratios[FD_TOWER_SLOT_CONFIRMED_LEVEL_CNT] = FD_TOWER_SLOT_CONFIRMED_RATIOS;
  int const           levels[FD_TOWER_SLOT_CONFIRMED_LEVEL_CNT] = FD_TOWER_SLOT_CONFIRMED_LEVELS;
  for( int i = 0; i < FD_TOWER_SLOT_CONFIRMED_LEVEL_CNT; i++ ) {
    if( FD_LIKELY( fd_uchar_extract_bit( votes_blk->flags, i ) ) ) continue; /* already contiguously confirmed */
    double ratio = (double)votes_blk->stake / (double)total_stake;
    if( FD_LIKELY( ratio < ratios[i] ) ) break; /* threshold not met */

    /* If ghost is missing, then we know this is a forward
       confirmation (ie. we haven't replayed the block yet). */

    if( FD_UNLIKELY( !ghost_blk ) ) {
      if( fd_uchar_extract_bit( votes_blk->flags, i+4 ) ) continue; /* already forward confirmed */
      votes_blk->flags = fd_uchar_set_bit( votes_blk->flags, i+4 );
      publishes_push_head( ctx->publishes, (publish_t){ .sig = FD_TOWER_SIG_SLOT_CONFIRMED, .msg = { .slot_confirmed = (fd_tower_slot_confirmed_t){ .level = levels[i], .fwd = 1, .slot = votes_blk->key.slot, .block_id = votes_blk->key.block_id } } } );

      if( FD_LIKELY( tower_blk ) ) {
        /* implies we replayed one version of the slot that is not the
           duplicate confirmed version */
        tower_blk->confirmed          = 1;
        tower_blk->confirmed_block_id = votes_blk->key.block_id;
      }
      continue;
    }

    /* Otherwise if they are present, then we know this is not a forward
       confirmation and thus we have replayed and confirmed the block,
       which also implies we have replayed and confirmed its ancestry.
       So publish confirmations for all ancestors (short-circuit at the
       first ancestor that was already confirmed).

       We use ghost to walk up the ancestry and also mark ghost and
       tower blocks as confirmed as we walk if this is the duplicate
       confirmation level. */

    fd_ghost_blk_t * ghost_anc = ghost_blk;
    fd_tower_blk_t * tower_anc = tower_blk;
    fd_votes_blk_t * votes_anc = votes_blk;
    while( FD_LIKELY( ghost_anc ) ) {

      tower_anc = fd_tower_blocks_query( ctx->tower_blocks, ghost_anc->slot );
      votes_anc = fd_votes_query( ctx->votes, ghost_anc->slot, &ghost_anc->id );
      if( FD_UNLIKELY( !tower_anc || !votes_anc ) ) break;

      /* Terminate at the first ancestor that has already reached this
         confirmation level. */

      if( FD_LIKELY( fd_uchar_extract_bit( votes_anc->flags, i ) ) ) break;

      /* Mark the ancestor as confirmed at this level.  If this is the
         duplicate confirmation level, also mark the ghost and tower
         blocks as confirmed. */

      votes_anc->flags = fd_uchar_set_bit( votes_anc->flags, i );
      publishes_push_head( ctx->publishes, (publish_t){ .sig = FD_TOWER_SIG_SLOT_CONFIRMED, .msg = { .slot_confirmed = (fd_tower_slot_confirmed_t){ .level = levels[i], .fwd = 0, .slot = ghost_anc->slot, .block_id = ghost_anc->id } } } );
      if( FD_UNLIKELY( levels[i]==FD_TOWER_SLOT_CONFIRMED_PROPAGATED ) ) {
        tower_anc->propagated = 1;
      }
      if( FD_UNLIKELY( levels[i]==FD_TOWER_SLOT_CONFIRMED_DUPLICATE ) ) {
        tower_anc->confirmed          = 1;
        tower_anc->confirmed_block_id = ghost_anc->id;
      }

      /* Walk up to next ancestor. */

      ghost_anc = fd_ghost_parent( ctx->ghost, ghost_anc );
    }
  }
}

/* count_vote counts vote txns from Gossip, TPU and Replay.  Note these
   txns have already been parsed and sigverified before they are sent to
   tower.  Replay votes have been successfully executed.  They are
   counted towards votes and hfork (see point 2 in the top-level
   documentation). */

static void
count_vote( fd_tower_tile_t * ctx,
            fd_txn_t const *  txn,
            uchar const *     payload ) {

  /* We are a little stricter than Agave here when validating the vote
     because we use the same validation as pack ie. is_simple_vote which
     includes a check that there are at most two signers, whereas
     Agave's gossip vote parser does not perform that same check (the
     only two signers are the identity key and vote authority, which may
     optionally be the same).

     Being a little stricter here is ok because even if we drop some
     votes with extraneous signers that Agave would consider valid
     (unlikely), gossip votes are in general considered unreliable and
     ultimately consensus is reached through replaying the vote txns.

     The remaining checks mirror Agave as closely as possible (and are
     documented throughout below). */

  if( FD_UNLIKELY( !fd_txn_is_simple_vote_transaction( txn, payload ) ) ) return;

  /* TODO check the authorized voter for this vote account (from epoch
     stakes) is one of the signers. */

  /* Filter any non-TowerSync vote txns. */

  /* TODO SECURITY ensure SIMD-0138 is activated */

  fd_txn_instr_t const * instr      = &txn->instr[0];
  uchar const *          instr_data = payload + instr->data_off;
  uint                   kind       = fd_uint_load_4_fast( instr_data );
  if( FD_UNLIKELY( kind != FD_VOTE_IX_KIND_TOWER_SYNC && kind != FD_VOTE_IX_KIND_TOWER_SYNC_SWITCH ) ) { ctx->metrics.vote_txn_not_tower_sync++; return; };

  /* Deserialize the TowerSync out of the vote txn. */

  int err = fd_compact_tower_sync_de( &ctx->compact_tower_sync_serde, instr_data + sizeof(uint), instr->data_sz - sizeof(uint) );
  if( FD_UNLIKELY( err==-1 ) ) { ctx->metrics.vote_txn_bad_deser++; return; }
  ulong slot = ctx->compact_tower_sync_serde.root;
  fd_tower_remove_all( ctx->scratch_tower );
  for( ulong i = 0; i < ctx->compact_tower_sync_serde.lockouts_cnt; i++ ) {
    slot += ctx->compact_tower_sync_serde.lockouts[i].offset;
    fd_tower_push_tail( ctx->scratch_tower, (fd_tower_vote_t){ .slot = slot, .conf = ctx->compact_tower_sync_serde.lockouts[i].confirmation_count } );
  }
  if( FD_UNLIKELY( 0==memcmp( &ctx->compact_tower_sync_serde.block_id, &hash_null, sizeof(fd_hash_t) ) ) ) { ctx->metrics.vote_txn_unknown_block_id++; return; };

  fd_pubkey_t const * accs     = (fd_pubkey_t const *)fd_type_pun_const( payload + txn->acct_addr_off );
  fd_pubkey_t const * vote_acc = NULL;
  if( FD_UNLIKELY( txn->signature_cnt==1 ) ) vote_acc = (fd_pubkey_t const *)fd_type_pun_const( &accs[1] ); /* identity and authority same, account idx 1 is the vote account address */
  else                                       vote_acc = (fd_pubkey_t const *)fd_type_pun_const( &accs[2] ); /* identity and authority diff, account idx 2 is the vote account address */

  /* Return early if their tower is empty. */

  if( FD_UNLIKELY( fd_tower_empty( ctx->scratch_tower ) ) ) { ctx->metrics.vote_txn_empty_tower++; return; };

  /* The vote txn contains a block id and bank hash for their last vote
     slot in the tower.  Agave always counts the last vote.

     https://github.com/anza-xyz/agave/blob/v2.3.7/core/src/cluster_info_vote_listener.rs#L476-L487 */

  fd_tower_vote_t const * their_last_vote = fd_tower_peek_tail_const( ctx->scratch_tower );
  fd_hash_t const *       their_block_id  = &ctx->compact_tower_sync_serde.block_id;
  fd_hash_t const *       their_bank_hash = &ctx->compact_tower_sync_serde.hash;

  /* Similar to what Agave does in cluster_info_vote_listener, we use
     the stake associated with a vote account as of our current root's
     epoch (which could potentially be a different epoch than the vote
     we are counting or when we observe the vote).  They default stake
     to 0 for voters who are not found. */

  fd_tower_stakes_vtr_xid_t xid = { .addr = *vote_acc, .slot = ctx->root_slot };
  fd_tower_stakes_vtr_t *   vtr = fd_tower_stakes_vtr_map_ele_query( ctx->tower_stakes->vtr_map, &xid, NULL, ctx->tower_stakes->vtr_pool );
  if( FD_UNLIKELY( !vtr ) ) return; /* voter is not staked in current root's epoch */

  ulong their_stake = vtr->stake;
  ulong total_stake = fd_ghost_root( ctx->ghost )->total_stake;

  fd_hfork_blk_t * hfork_blk = fd_hfork_count_vote( ctx->hfork, vote_acc, their_block_id, their_bank_hash, their_last_vote->slot, their_stake, total_stake );
  if( FD_UNLIKELY( hfork_blk ) ) update_hfork_metrics( ctx, hfork_blk, their_last_vote->slot, their_block_id );

  fd_tower_blk_t * forks_blk = fd_tower_blk_query( ctx->tower_blocks->blk_map, their_last_vote->slot, NULL );
  fd_ghost_blk_t * ghost_blk = fd_ghost_query( ctx->ghost, their_block_id );
  fd_votes_blk_t * votes_blk = fd_votes_count_vote( ctx->votes, vote_acc, their_last_vote->slot, their_block_id );
  if( FD_LIKELY( votes_blk ) ) confirm_block( ctx, forks_blk, ghost_blk, votes_blk, total_stake );

  /* Agave decides to count intermediate vote slots in the tower only if
     1. they've replayed the slot and 2. their replay bank hash matches
     the vote's bank hash.  We do the same thing, but using block_ids
     instead of bank hashes.

     It's possible we haven't yet replayed this slot being voted on
     because gossip votes can be ahead of our replay.

     https://github.com/anza-xyz/agave/blob/v2.3.7/core/src/cluster_info_vote_listener.rs#L483-L487 */

  if( FD_UNLIKELY( !forks_blk ) ) { ctx->metrics.vote_txn_unknown_slot++; return; }; /* we haven't replayed this block yet */
  fd_hash_t const * our_block_id = fd_tower_blocks_canonical_block_id( ctx->tower_blocks, their_last_vote->slot );
  if( FD_UNLIKELY( 0!=memcmp( our_block_id, their_block_id, sizeof(fd_hash_t) ) ) ) { ctx->metrics.vote_txn_unknown_block_id++; return; } /* we don't recognize this block id */

  /* At this point, we know we have replayed the same slot and also have
     a matching block id, so we can count the intermediate votes. */

  int skipped_last_vote = 0;
  for( fd_tower_iter_t iter = fd_tower_iter_init_rev( ctx->scratch_tower       );
                             !fd_tower_iter_done_rev( ctx->scratch_tower, iter );
                       iter = fd_tower_iter_prev    ( ctx->scratch_tower, iter ) ) {
    if( FD_UNLIKELY( !skipped_last_vote ) ) { skipped_last_vote = 1; continue; }
    fd_tower_vote_t const * their_intermediate_vote = fd_tower_iter_ele_const( ctx->scratch_tower, iter );

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

    fd_tower_blk_t * fork = fd_tower_blocks_query( ctx->tower_blocks, their_intermediate_vote->slot );
    if( FD_UNLIKELY( !fork ) ) { ctx->metrics.vote_txn_unknown_slot++; continue; }

    /* Otherwise, we count the vote using our own block id for that slot
       (again, mirroring what Agave does albeit with bank hashes).

       Agave uses the current root bank's total stake when counting vote
       txns from gossip / replay:

       https://github.com/anza-xyz/agave/blob/v2.3.7/core/src/cluster_info_vote_listener.rs#L500 */

    fd_hash_t const * intermediate_block_id  = fd_tower_blocks_canonical_block_id( ctx->tower_blocks, their_intermediate_vote->slot );
    fd_votes_blk_t  * intermediate_votes_blk = fd_votes_count_vote( ctx->votes, vote_acc, their_intermediate_vote->slot, intermediate_block_id );
    fd_ghost_blk_t  * intermediate_ghost_blk = fd_ghost_query( ctx->ghost, intermediate_block_id );
    fd_tower_blk_t  * intermediate_tower_blk = fd_tower_blocks_query( ctx->tower_blocks, their_intermediate_vote->slot );
    if( FD_LIKELY( intermediate_votes_blk ) ) confirm_block( ctx, intermediate_tower_blk, intermediate_ghost_blk, intermediate_votes_blk, total_stake );
  }
}

static int
deser_auth_vtr( fd_tower_tile_t * ctx,
                ulong             epoch,
                int               vote_acc_found,
                fd_pubkey_t *     authority_out,
                ulong *           authority_idx_out ) {

  if( FD_UNLIKELY( !vote_acc_found ) ) return 0;

  fd_bincode_decode_ctx_t decode_ctx = {
    .data    = ctx->our_vote_acct,
    .dataend = ctx->our_vote_acct + ctx->our_vote_acct_sz,
  };

  uchar __attribute__((aligned(FD_VOTE_STATE_VERSIONED_ALIGN))) vote_state_versioned[ FD_VOTE_STATE_VERSIONED_FOOTPRINT ];

  fd_vote_state_versioned_t * vsv = fd_vote_state_versioned_decode( vote_state_versioned, &decode_ctx );
  FD_CRIT( vsv, "unable to decode vote state versioned" );

  fd_pubkey_t const * auth_vtr_addr = NULL;
  switch( vsv->discriminant ) {
    case fd_vote_state_versioned_enum_v1_14_11:
      for( fd_vote_authorized_voters_treap_rev_iter_t iter = fd_vote_authorized_voters_treap_rev_iter_init( vsv->inner.v1_14_11.authorized_voters.treap, vsv->inner.v1_14_11.authorized_voters.pool );
           !fd_vote_authorized_voters_treap_rev_iter_done( iter );
           iter = fd_vote_authorized_voters_treap_rev_iter_next( iter, vsv->inner.v1_14_11.authorized_voters.pool ) ) {
        fd_vote_authorized_voter_t * ele = fd_vote_authorized_voters_treap_rev_iter_ele( iter, vsv->inner.v1_14_11.authorized_voters.pool );
        if( FD_LIKELY( ele->epoch<=epoch ) ) {
          auth_vtr_addr = &ele->pubkey;
          break;
        }
      }
      break;
    case fd_vote_state_versioned_enum_v3:
      for( fd_vote_authorized_voters_treap_rev_iter_t iter = fd_vote_authorized_voters_treap_rev_iter_init( vsv->inner.v3.authorized_voters.treap, vsv->inner.v3.authorized_voters.pool );
          !fd_vote_authorized_voters_treap_rev_iter_done( iter );
          iter = fd_vote_authorized_voters_treap_rev_iter_next( iter, vsv->inner.v3.authorized_voters.pool ) ) {
        fd_vote_authorized_voter_t * ele = fd_vote_authorized_voters_treap_rev_iter_ele( iter, vsv->inner.v3.authorized_voters.pool );
        if( FD_LIKELY( ele->epoch<=epoch ) ) {
          auth_vtr_addr = &ele->pubkey;
          break;
        }
      }
      break;
    case fd_vote_state_versioned_enum_v4:
      for( fd_vote_authorized_voters_treap_rev_iter_t iter = fd_vote_authorized_voters_treap_rev_iter_init( vsv->inner.v4.authorized_voters.treap, vsv->inner.v4.authorized_voters.pool );
          !fd_vote_authorized_voters_treap_rev_iter_done( iter );
          iter = fd_vote_authorized_voters_treap_rev_iter_next( iter, vsv->inner.v4.authorized_voters.pool ) ) {
        fd_vote_authorized_voter_t * ele = fd_vote_authorized_voters_treap_rev_iter_ele( iter, vsv->inner.v4.authorized_voters.pool );
        if( FD_LIKELY( ele->epoch<=epoch ) ) {
          auth_vtr_addr = &ele->pubkey;
          break;
        }
      }
      break;
    default:
      FD_LOG_CRIT(( "unsupported vote state versioned discriminant: %u", vsv->discriminant ));
  }

  FD_CRIT( auth_vtr_addr, "unable to find authorized voter, likely corrupt vote account state" );

  if( fd_pubkey_eq( auth_vtr_addr, ctx->identity_key ) ) {
    *authority_idx_out = ULONG_MAX;
    *authority_out     = *auth_vtr_addr;
    return 1;
  }

  auth_vtr_t * auth_vtr = auth_vtr_query( ctx->auth_vtr, *auth_vtr_addr, NULL );
  if( FD_LIKELY( auth_vtr ) ) {
    *authority_idx_out = auth_vtr->paths_idx;
    *authority_out     = *auth_vtr_addr;
    return 1;
  }

  return 0;
}

static ulong
update_voters( fd_tower_tile_t * ctx,

               ulong             bank_idx,
               ulong             slot ) {

  fd_bank_t bank[1];
  if( FD_UNLIKELY( !fd_banks_bank_query( bank, ctx->banks, bank_idx ) ) ) FD_LOG_CRIT(( "invariant violation: bank %lu is missing", bank_idx ));

  fd_tower_voters_t * tower_voters = ctx->tower_voters;
  fd_tower_voters_remove_all( tower_voters );

  ulong total_stake    = 0UL;
  ulong prev_voter_idx = ULONG_MAX;

  fd_accdb_ro_pipe_t ro_pipe[1];
  fd_funk_txn_xid_t  xid = { .ul = { slot, bank_idx } };
  fd_accdb_ro_pipe_init( ro_pipe, ctx->accdb, &xid );

  fd_top_votes_t const * top_votes_t_2 = fd_bank_top_votes_t_2_query( bank );
  uchar __attribute__((aligned(FD_TOP_VOTES_ITER_ALIGN))) iter_mem[ FD_TOP_VOTES_ITER_FOOTPRINT ];

  ulong pending_cnt = 0UL;
  fd_top_votes_iter_t * iter = fd_top_votes_iter_init( top_votes_t_2, iter_mem );
  for(;;) {
    if( FD_UNLIKELY( fd_top_votes_iter_done( top_votes_t_2, iter ) ) ) {
      if( !pending_cnt ) break;
      fd_accdb_ro_pipe_flush( ro_pipe );
    } else {
      fd_pubkey_t vote_acc;
      ulong       stake;
      int         is_valid = fd_top_votes_iter_ele( top_votes_t_2, iter, &vote_acc, NULL, &stake, NULL, NULL, NULL );
      fd_top_votes_iter_next( top_votes_t_2, iter );
      if( FD_UNLIKELY( !is_valid ) ) continue;

      fd_accdb_ro_pipe_enqueue( ro_pipe, vote_acc.key );
      pending_cnt++;
    }

    fd_accdb_ro_t * ro;
    while( (ro = fd_accdb_ro_pipe_poll( ro_pipe )) ) {
      pending_cnt--;
      fd_pubkey_t const * vote_acc = fd_accdb_ref_address( ro );

      ulong stake;
      int   is_valid = fd_top_votes_query( top_votes_t_2, vote_acc, NULL, &stake, NULL, NULL, NULL );
      if( FD_UNLIKELY( !is_valid ) ) continue;
      FD_TEST( fd_accdb_ref_lamports( ro ) && fd_vsv_is_correct_size_and_initialized( ro->meta ) );

      total_stake += stake;

      fd_tower_voters_t acct = { .id_key   = fd_vsv_get_node_account( fd_accdb_ref_data_const( ro ) ),
                                 .vote_acc = *vote_acc,
                                 .stake    = stake };
      fd_memcpy( acct.data, fd_accdb_ref_data_const( ro ), fd_ulong_min( fd_accdb_ref_data_sz( ro ), FD_VOTE_STATE_DATA_MAX ) );
      fd_tower_voters_push_tail( tower_voters, acct );
      prev_voter_idx = fd_tower_stakes_insert( ctx->tower_stakes, slot, vote_acc, stake, prev_voter_idx );
    }
  }

  fd_accdb_ro_pipe_fini( ro_pipe );

  return total_stake;
}

static void
replay_slot_completed( fd_tower_tile_t *            ctx,
                       fd_replay_slot_completed_t * slot_completed,
                       ulong                        tsorig,
                       fd_stem_context_t *          stem ) {

  /* Sanity checks. */

  FD_TEST( 0!=memcmp( &slot_completed->block_id, &hash_null, sizeof(fd_hash_t) ) );
  FD_TEST( ctx->init_slot==ULONG_MAX || 0!=memcmp( &slot_completed->block_id, &hash_null, sizeof(fd_hash_t) ) );

  /* Update voters. */

  fd_tower_stakes_remove( ctx->tower_stakes, slot_completed->slot ); /* no-op for 99% of cases except for eqvoc */
  ulong total_stake = update_voters( ctx, slot_completed->bank_idx, slot_completed->slot );

  /* The first replay_slot_completed is always either the snapshot slot
     or genesis slot, which we use to initialize our slot and
     epoch-related metadata. */

  if( FD_UNLIKELY( ctx->init_slot==ULONG_MAX ) ) {
    ctx->init_slot = slot_completed->slot;
    ctx->root_slot = slot_completed->slot;
    fd_votes_publish( ctx->votes, slot_completed->slot );
    fd_votes_update_voters( ctx->votes, ctx->tower_voters, ctx->tower_stakes, slot_completed->slot );
    fd_eqvoc_update_voters( ctx->eqvoc, ctx->tower_voters );
    fd_hfork_update_voters( ctx->hfork, ctx->tower_voters );
  }

  /* Due to asynchronous frag processing, it's possible this block from
     replay_slot_completed is on a minority fork Tower already pruned
     after publishing a new root. */

  if( FD_UNLIKELY( slot_completed->slot!=ctx->init_slot && !fd_ghost_query( ctx->ghost, &slot_completed->parent_block_id ) ) ) {
    ctx->metrics.slot_ignored_cnt++;
    ctx->metrics.slot_ignored_gauge = slot_completed->slot;

    /* Still need to return a message to replay so the refcnt on the
       bank is decremented. */

    fd_tower_slot_ignored_t * msg = fd_chunk_to_laddr( ctx->out_mem, ctx->out_chunk );
    msg->slot     = slot_completed->slot;
    msg->bank_idx = slot_completed->bank_idx;

    fd_stem_publish( stem, OUT_IDX, FD_TOWER_SIG_SLOT_IGNORED, ctx->out_chunk, sizeof(fd_tower_slot_ignored_t), 0UL, tsorig, fd_frag_meta_ts_comp( fd_tickcount() ) );
    ctx->out_chunk = fd_dcache_compact_next( ctx->out_chunk, sizeof(fd_tower_slot_ignored_t), ctx->out_chunk0, ctx->out_wmark );
    ctx->out_seq   = stem->seqs[ OUT_IDX ];
    return;
  }

  /* Reconcile our local tower with the on-chain tower (stored inside
     our vote account). */

  ulong our_vote_acct_bal = ULONG_MAX;
  int found = 0;
  fd_funk_txn_xid_t xid = { .ul = { slot_completed->slot, slot_completed->bank_idx } };
  fd_accdb_ro_t ro[1];
  if( FD_LIKELY( fd_accdb_open_ro( ctx->accdb, ro, &xid, ctx->vote_account ) ) ) {
    found = 1;
    ctx->our_vote_acct_sz = fd_ulong_min( fd_accdb_ref_data_sz( ro ), FD_VOTE_STATE_DATA_MAX );
    our_vote_acct_bal = fd_accdb_ref_lamports( ro );
    fd_memcpy( ctx->our_vote_acct, fd_accdb_ref_data_const( ro ), ctx->our_vote_acct_sz );
    fd_accdb_close_ro( ctx->accdb, ro );
    fd_tower_reconcile( ctx->tower, ctx->root_slot, ctx->our_vote_acct );
  }

  /* Check for equivocation (already received a replay_slot_completed
     for this slot). */

  fd_tower_blk_t * eqvoc_tower_blk = NULL;
  if( FD_UNLIKELY( eqvoc_tower_blk = fd_tower_blocks_query( ctx->tower_blocks, slot_completed->slot ) ) ) {

    /* As fd_replay_slot_completed guarantees, we process at most 2
       equivocating blocks for a given slot.  fd_tower_{...} only stores
       one version of a block (by design, given the tower protocol's
       limitations ... see notes in fd_tower_blocks.h).  We also know
       when seeing the same slot a second time that second block is
       confirmed, also guaranteed by fd_replay_slot_completed ... see
       notes in fd_replay_tile.h).

       So we retain the existing tower_block we have (which contains the
       first voted_block_id if we did indeed vote for it).  We update
       the replayed_block_id to the newer replayed version, and also
       update the parent if it is different.  We clear out the slot from
       the other tower adjacent structures, and re-insert into them with
       the confirmed version of the slot. */

    FD_TEST( eqvoc_tower_blk->confirmed ); /* check the confirmed bit is set (second replay_slot_completed version must be confirmed) */
    fd_tower_lockos_remove( ctx->tower_lockos, slot_completed->slot );
    eqvoc_tower_blk->parent_slot       = slot_completed->parent_slot;
    eqvoc_tower_blk->replayed_block_id = slot_completed->block_id;

    ctx->metrics.slot_eqvoced_cnt++;
    ctx->metrics.slot_eqvoced_gauge = slot_completed->slot;
  } else {

    /* Otherwise this is the first replay of this block, so insert a new
       tower_blk. */

    fd_tower_blk_t * tower_blk   = fd_tower_blocks_insert( ctx->tower_blocks, slot_completed->slot, slot_completed->parent_slot );
    tower_blk->parent_slot       = slot_completed->parent_slot;
    tower_blk->epoch             = slot_completed->epoch;
    tower_blk->replayed          = 1;
    tower_blk->replayed_block_id = slot_completed->block_id;
    tower_blk->voted             = 0;
    tower_blk->confirmed         = 0;
    tower_blk->leader            = slot_completed->is_leader;
    tower_blk->propagated        = 0;

    /* Set the prev_leader_slot. */

    if( FD_UNLIKELY( tower_blk->leader ) ) {
      tower_blk->prev_leader_slot = slot_completed->parent_slot;
    } else if ( FD_UNLIKELY( ctx->init_slot==slot_completed->slot ) ) {
      tower_blk->prev_leader_slot = ULONG_MAX;
    } else {
      fd_tower_blk_t * parent_tower_blk = fd_tower_blocks_query( ctx->tower_blocks, slot_completed->parent_slot );
      FD_TEST( parent_tower_blk );
      tower_blk->prev_leader_slot = parent_tower_blk->prev_leader_slot;
    }
  }

  /* Insert into ghost */

  fd_ghost_blk_t * ghost_blk = fd_ghost_insert( ctx->ghost, &slot_completed->block_id, fd_ptr_if( slot_completed->slot!=ctx->init_slot, &slot_completed->parent_block_id, NULL ), slot_completed->slot );
  ghost_blk->total_stake = total_stake;

  /* Insert into hard fork detector. */

  fd_hfork_blk_t * hfork_blk = fd_hfork_record_our_bank_hash( ctx->hfork, &slot_completed->block_id, &slot_completed->bank_hash, fd_ghost_root( ctx->ghost )->total_stake );
  if( FD_UNLIKELY( hfork_blk->flag ) ) update_hfork_metrics( ctx, hfork_blk, slot_completed->slot, &slot_completed->block_id );

  fd_tower_voters_t * tower_voters = ctx->tower_voters;
  for( fd_tower_voters_iter_t iter = fd_tower_voters_iter_init( tower_voters );
                                    !fd_tower_voters_iter_done( tower_voters, iter );
                              iter = fd_tower_voters_iter_next( tower_voters, iter ) ) {
    fd_tower_voters_t * acct = fd_tower_voters_iter_ele( tower_voters, iter );

    /* 1. Update forks with lockouts. */

    fd_tower_lockos_insert( ctx->tower_lockos, slot_completed->slot, &acct->vote_acc, acct );

    /* 2. Count the last vote slot in the vote state towards ghost. */

    ulong vote_slot = fd_vote_acc_vote_slot( acct->data );
    if( FD_LIKELY( vote_slot!=ULONG_MAX && /* has voted */
                   vote_slot>=fd_ghost_root( ctx->ghost )->slot ) ) { /* vote not too old */

      /* We search up the ghost ancestry to find the ghost block for
          this vote slot.  In Agave, they look this value up using a
          hashmap of slot->bank hash ("fork progress"), but that
          approach only works because they dump and repair (so there's
          only ever one canonical bank hash).  We retain multiple block
          ids, both the original and confirmed one. */

      fd_ghost_blk_t * ancestor_blk = fd_ghost_slot_ancestor( ctx->ghost, ghost_blk, vote_slot ); /* FIXME potentially slow */

      /* It is impossible for ancestor_blk to be missing, because
          these are vote accounts on a given fork, not vote txns across
          forks.  So we know these towers must contain slots we know
          about as long as they are >= root, which we checked above. */

      if( FD_UNLIKELY( !ancestor_blk ) ) {
        FD_BASE58_ENCODE_32_BYTES( acct->vote_acc.key, pubkey_b58 );
        FD_LOG_CRIT(( "missing ancestor. replay slot %lu vote slot %lu voter %s", slot_completed->slot, vote_slot, pubkey_b58 ));
      }

      fd_ghost_count_vote( ctx->ghost, ancestor_blk, &acct->vote_acc, acct->stake, vote_slot );
    }
  }

  /* Determine reset, vote, and root slots.  There may not be a vote or
     root slot but there is always a reset slot. */

  fd_tower_out_t out = fd_tower_vote_and_reset( ctx->tower, ctx->tower_blocks, ctx->tower_lockos, ctx->tower_stakes, ctx->tower_voters, ctx->ghost, ctx->votes );

  /* Update forks if there is a vote slot. */

  if( FD_LIKELY( out.vote_slot!=ULONG_MAX ) ) {

    /* We might not be voting for the current replay slot because the
       best_blk (according to ghost) could be another fork. */

    fd_tower_blk_t * vote_tower_blk = fd_tower_blocks_query( ctx->tower_blocks, out.vote_slot );
    vote_tower_blk->voted           = 1;
    vote_tower_blk->voted_block_id  = out.vote_block_id;
  }

  /* Publish structures if there is a new root. */

  if( FD_UNLIKELY( out.root_slot!=ULONG_MAX ) ) {
    if( FD_UNLIKELY( 0==memcmp( &out.root_block_id, &hash_null, sizeof(fd_hash_t) ) ) ) {
      FD_LOG_CRIT(( "invariant violation: root block id is null at slot %lu", out.root_slot ));
    }

    fd_tower_blk_t * oldr_tower_blk = fd_tower_blocks_query( ctx->tower_blocks, ctx->root_slot );
    fd_tower_blk_t * newr_tower_blk = fd_tower_blocks_query( ctx->tower_blocks, out.root_slot );
    FD_TEST( oldr_tower_blk );
    FD_TEST( newr_tower_blk );

    /* It is a Solana consensus protocol invariant that a validator must
       make at least one root in an epoch, so the root's epoch cannot
       advance by more than one.  */

    FD_TEST( oldr_tower_blk->epoch==newr_tower_blk->epoch || oldr_tower_blk->epoch+1==newr_tower_blk->epoch  ); /* root can only move forward one epoch */

    /* Publish votes: 1. reindex if it's a new epoch. 2. publish the new
       root to votes. */

    if( FD_UNLIKELY( oldr_tower_blk->epoch+1==newr_tower_blk->epoch ) ) {
      FD_TEST( newr_tower_blk->epoch==slot_completed->epoch ); /* new root's epoch must be same as current slot_completed */
      fd_votes_update_voters( ctx->votes, ctx->tower_voters, ctx->tower_stakes, out.root_slot );
      fd_eqvoc_update_voters( ctx->eqvoc, ctx->tower_voters );
      fd_hfork_update_voters( ctx->hfork, ctx->tower_voters );
    }
    fd_votes_publish( ctx->votes, out.root_slot );

    /* Publish tower_blocks and tower_stakes: 1. remove any entries
       older than the new root. */

    for( ulong slot = ctx->root_slot; slot < out.root_slot; slot++ ) {
      fd_tower_blocks_remove( ctx->tower_blocks, slot );
      fd_tower_lockos_remove( ctx->tower_lockos, slot );
      fd_tower_stakes_remove( ctx->tower_stakes, slot );
    }

    /* Publish ghost.  1. walk up the ghost ancestry to publish new root
       frags for intermediate slots we couldn't vote for.  2. publish
       the new root to ghost. */

    fd_ghost_blk_t * newr = fd_ghost_query( ctx->ghost, &out.root_block_id );
    fd_ghost_blk_t * oldr = fd_ghost_root( ctx->ghost );

    /* It's possible our new root skips intermediate slot(s) between our
       old root.  This can happen if we couldn't vote for those
       intermediate slot(s) but ended up making a new root that is their
       descendant.  We publish these as intermediate roots. */

    fd_ghost_blk_t * intr = newr;
    while( FD_LIKELY( intr!=oldr ) ) {
      publishes_push_head( ctx->publishes, (publish_t){ .sig = FD_TOWER_SIG_SLOT_ROOTED, .msg = { .slot_rooted = { .slot = intr->slot, .block_id = intr->id } } } );
      intr = fd_ghost_parent( ctx->ghost, intr );
    }
    fd_ghost_publish( ctx->ghost, newr );

    /* Update the new root. */

    ctx->root_slot = out.root_slot;
  }

  /* Publish a slot_done frag to tower_out. */

  fd_tower_slot_done_t * msg = fd_chunk_to_laddr( ctx->out_mem, ctx->out_chunk );
  msg->replay_slot           = slot_completed->slot;
  msg->active_fork_cnt       = fd_ghost_active_fork_cnt( ctx->ghost );
  msg->vote_slot             = out.vote_slot;
  msg->reset_slot            = out.reset_slot;
  msg->reset_block_id        = out.reset_block_id;
  msg->root_slot             = out.root_slot;
  msg->root_block_id         = out.root_block_id;
  msg->replay_bank_idx       = slot_completed->bank_idx;
  msg->vote_acct_bal         = our_vote_acct_bal;

  /* Populate slot_done with a vote txn representing our current tower
     (regardless of whether there was a new vote slot or not).

     TODO only do this on refresh_last_vote? */

  ulong       authority_idx = ULONG_MAX;
  fd_pubkey_t authority[1];
  int         found_authority = deser_auth_vtr( ctx, slot_completed->epoch, found, authority, &authority_idx );

  if( FD_LIKELY( found_authority ) ) {
    msg->has_vote_txn = 1;
    fd_txn_p_t          txn[1];
    fd_tower_to_vote_txn( ctx->tower, ctx->root_slot, &slot_completed->bank_hash, &slot_completed->block_id, &slot_completed->block_hash, ctx->identity_key, authority, ctx->vote_account, txn );
    FD_TEST( !fd_tower_empty( ctx->tower ) );
    FD_TEST( txn->payload_sz && txn->payload_sz<=FD_TPU_MTU );
    fd_memcpy( msg->vote_txn, txn->payload, txn->payload_sz );
    msg->vote_txn_sz   = txn->payload_sz;
    msg->authority_idx = authority_idx;
  } else {
    msg->has_vote_txn = 0;
  }

  msg->tower_cnt = 0UL;
  if( FD_LIKELY( found ) ) msg->tower_cnt = fd_tower_with_lat_from_vote_acc( msg->tower, ctx->our_vote_acct );

  fd_stem_publish( stem, OUT_IDX, FD_TOWER_SIG_SLOT_DONE, ctx->out_chunk, sizeof(fd_tower_slot_done_t), 0UL, tsorig, fd_frag_meta_ts_comp( fd_tickcount() ) );
  ctx->out_chunk = fd_dcache_compact_next( ctx->out_chunk, sizeof(fd_tower_slot_done_t), ctx->out_chunk0, ctx->out_wmark );
  ctx->out_seq   = stem->seqs[ OUT_IDX ];

  /* Write out metrics. */

  ctx->metrics.replay_slot = slot_completed->slot;
  ctx->metrics.vote_slot   = out.vote_slot;
  ctx->metrics.reset_slot  = out.reset_slot; /* always set */
  ctx->metrics.root_slot   = ctx->root_slot;
  ctx->metrics.init_slot   = ctx->init_slot;

  ctx->metrics.ancestor_rollback += (ulong)fd_uchar_extract_bit( out.flags, FD_TOWER_FLAG_ANCESTOR_ROLLBACK );
  ctx->metrics.sibling_confirmed += (ulong)fd_uchar_extract_bit( out.flags, FD_TOWER_FLAG_SIBLING_CONFIRMED );
  ctx->metrics.same_fork         += (ulong)fd_uchar_extract_bit( out.flags, FD_TOWER_FLAG_SAME_FORK         );
  ctx->metrics.switch_pass       += (ulong)fd_uchar_extract_bit( out.flags, FD_TOWER_FLAG_SWITCH_PASS       );
  ctx->metrics.switch_fail       += (ulong)fd_uchar_extract_bit( out.flags, FD_TOWER_FLAG_SWITCH_FAIL       );
  ctx->metrics.lockout_fail      += (ulong)fd_uchar_extract_bit( out.flags, FD_TOWER_FLAG_LOCKOUT_FAIL      );
  ctx->metrics.threshold_fail    += (ulong)fd_uchar_extract_bit( out.flags, FD_TOWER_FLAG_THRESHOLD_FAIL    );
  ctx->metrics.propagated_fail   += (ulong)fd_uchar_extract_bit( out.flags, FD_TOWER_FLAG_PROPAGATED_FAIL   );

  /* Log out structures. */

  char cstr[4096]; ulong cstr_sz;
  FD_LOG_DEBUG(( "\n\n%s", fd_ghost_to_cstr( ctx->ghost, fd_ghost_root( ctx->ghost ), cstr, sizeof(cstr), &cstr_sz ) ));
  FD_LOG_DEBUG(( "\n\n%s", fd_tower_to_cstr( ctx->tower, ctx->root_slot, cstr ) ));
}

FD_FN_CONST static inline ulong
scratch_align( void ) {
  return 128UL;
}

FD_FN_PURE static inline ulong
scratch_footprint( fd_topo_tile_t const * tile ) {
  ulong slot_max    = fd_ulong_pow2_up( tile->tower.max_live_slots );
  ulong per_vtr_max = PER_VTR_MAX;
  ulong vtr_max     = fd_ulong_pow2_up( VTR_MAX );
  ulong blk_max     = slot_max * EQVOC_MAX;
  ulong fec_max     = slot_max * FD_SHRED_BLK_MAX / FD_FEC_SHRED_CNT;
  ulong pub_max     = slot_max * FD_TOWER_SLOT_CONFIRMED_LEVEL_CNT;

  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, alignof(fd_tower_tile_t), sizeof(fd_tower_tile_t)                                       );
  l = FD_LAYOUT_APPEND( l, auth_vtr_align(),         auth_vtr_footprint()                                          );
  /* auth_vtr_keyswitch */
  l = FD_LAYOUT_APPEND( l, fd_eqvoc_align(),         fd_eqvoc_footprint( slot_max, fec_max, per_vtr_max, vtr_max ) );
  l = FD_LAYOUT_APPEND( l, fd_ghost_align(),         fd_ghost_footprint( blk_max, vtr_max )                        );
  l = FD_LAYOUT_APPEND( l, fd_hfork_align(),         fd_hfork_footprint( slot_max, vtr_max )                       );
  l = FD_LAYOUT_APPEND( l, fd_votes_align(),         fd_votes_footprint( slot_max, vtr_max )                       );
  l = FD_LAYOUT_APPEND( l, fd_tower_align(),         fd_tower_footprint()                                          );
  l = FD_LAYOUT_APPEND( l, fd_tower_align(),         fd_tower_footprint()                                          );
  l = FD_LAYOUT_APPEND( l, fd_tower_blocks_align(),  fd_tower_blocks_footprint( slot_max )                         );
  l = FD_LAYOUT_APPEND( l, fd_tower_lockos_align(),  fd_tower_lockos_footprint( slot_max, vtr_max )                );
  l = FD_LAYOUT_APPEND( l, fd_tower_stakes_align(),  fd_tower_stakes_footprint( slot_max, vtr_max )                );
  l = FD_LAYOUT_APPEND( l, fd_tower_voters_align(),  fd_tower_voters_footprint( vtr_max )                          );
  l = FD_LAYOUT_APPEND( l, publishes_align(),        publishes_footprint( pub_max )                                );
  return FD_LAYOUT_FINI( l, scratch_align() );
}

static void
during_housekeeping( fd_tower_tile_t * ctx ) {
  if( FD_UNLIKELY( fd_keyswitch_state_query( ctx->auth_vtr_keyswitch )==FD_KEYSWITCH_STATE_UNHALT_PENDING ) ) {
    fd_keyswitch_state( ctx->auth_vtr_keyswitch, FD_KEYSWITCH_STATE_UNLOCKED );
  }

  if( FD_UNLIKELY( fd_keyswitch_state_query( ctx->auth_vtr_keyswitch )==FD_KEYSWITCH_STATE_SWITCH_PENDING ) ) {
    fd_pubkey_t pubkey = *(fd_pubkey_t const *)fd_type_pun_const( ctx->auth_vtr_keyswitch->bytes );
    if( FD_UNLIKELY( auth_vtr_query( ctx->auth_vtr, pubkey, NULL ) ) ) FD_LOG_CRIT(( "keyswitch: duplicate authorized voter key, keys not synced up with sign tile" ));
    if( FD_UNLIKELY( ctx->auth_vtr_path_cnt==AUTH_VOTERS_MAX ) ) FD_LOG_CRIT(( "keyswitch: too many authorized voters, keys not synced up with sign tile" ));

    auth_vtr_t * auth_vtr = auth_vtr_insert( ctx->auth_vtr, pubkey );
    auth_vtr->paths_idx = ctx->auth_vtr_path_cnt;
    ctx->auth_vtr_path_cnt++;
    fd_keyswitch_state( ctx->auth_vtr_keyswitch, FD_KEYSWITCH_STATE_COMPLETED );
  }

  /* FIXME: Currently, the tower tile doesn't support set-identity with
     a tower file.  When support for a tower file is added, we need to
     swap the file that is running and sync it to the local state of
     the tower.  Because a tower file is not supported, if another
     validator was running with the identity that was switched to, then
     it is possible that the original validator and the fallback (this
     node), may have tower files which are out of sync.  This could lead
     to consensus violations such as double voting or duplicate
     confirmations.  Currently it is unsafe for a validator operator to
     switch identities without a 512 slot delay: the reason for this
     delay is to account for the worst case number of slots a vote
     account can be locked out for. */

  if( FD_UNLIKELY( fd_keyswitch_state_query( ctx->identity_keyswitch )==FD_KEYSWITCH_STATE_UNHALT_PENDING ) ) {
    FD_LOG_DEBUG(( "keyswitch: unhalting signing" ));
    FD_CRIT( ctx->halt_signing, "state machine corruption" );
    ctx->halt_signing = 0;
    fd_keyswitch_state( ctx->identity_keyswitch, FD_KEYSWITCH_STATE_COMPLETED );
  }

  if( FD_UNLIKELY( fd_keyswitch_state_query( ctx->identity_keyswitch )==FD_KEYSWITCH_STATE_SWITCH_PENDING ) ) {
    FD_LOG_DEBUG(( "keyswitch: halting signing" ));
    memcpy( ctx->identity_key, ctx->identity_keyswitch->bytes, 32UL );
    fd_keyswitch_state( ctx->identity_keyswitch, FD_KEYSWITCH_STATE_COMPLETED );
    ctx->halt_signing = 1;
    ctx->identity_keyswitch->result  = ctx->out_seq;
  }
}

static inline void
metrics_write( fd_tower_tile_t * ctx ) {
  FD_MCNT_SET  ( TOWER, SLOT_IGNORED_CNT,   ctx->metrics.slot_ignored_cnt   );
  FD_MGAUGE_SET( TOWER, SLOT_IGNORED_GAUGE, ctx->metrics.slot_ignored_gauge );

  FD_MGAUGE_SET( TOWER, REPLAY_SLOT,  ctx->metrics.replay_slot  );
  FD_MGAUGE_SET( TOWER, VOTE_SLOT,    ctx->metrics.vote_slot    );
  FD_MGAUGE_SET( TOWER, RESET_SLOT,   ctx->metrics.reset_slot   );
  FD_MGAUGE_SET( TOWER, ROOT_SLOT,    ctx->metrics.root_slot    );
  FD_MGAUGE_SET( TOWER, INIT_SLOT,    ctx->metrics.init_slot    );

  FD_MCNT_SET( TOWER, ANCESTOR_ROLLBACK, ctx->metrics.ancestor_rollback );
  FD_MCNT_SET( TOWER, SIBLING_CONFIRMED, ctx->metrics.sibling_confirmed );
  FD_MCNT_SET( TOWER, SAME_FORK,         ctx->metrics.same_fork         );
  FD_MCNT_SET( TOWER, SWITCH_PASS,       ctx->metrics.switch_pass       );
  FD_MCNT_SET( TOWER, SWITCH_FAIL,       ctx->metrics.switch_fail       );
  FD_MCNT_SET( TOWER, LOCKOUT_FAIL,      ctx->metrics.lockout_fail      );
  FD_MCNT_SET( TOWER, THRESHOLD_FAIL,    ctx->metrics.threshold_fail    );
  FD_MCNT_SET( TOWER, PROPAGATED_FAIL,   ctx->metrics.propagated_fail   );

  FD_MCNT_SET( TOWER, VOTE_TXN_BAD_DESER,            ctx->metrics.vote_txn_bad_deser            );
  FD_MCNT_SET( TOWER, VOTE_TXN_NOT_TOWER_SYNC,  ctx->metrics.vote_txn_not_tower_sync  );
  FD_MCNT_SET( TOWER, VOTE_TXN_EMPTY_TOWER,     ctx->metrics.vote_txn_empty_tower     );
  FD_MCNT_SET( TOWER, VOTE_TXN_UNKNOWN_SLOT,    ctx->metrics.vote_txn_unknown_slot    );
  FD_MCNT_SET( TOWER, VOTE_TXN_UNKNOWN_BLOCK_ID, ctx->metrics.vote_txn_unknown_block_id );

  FD_MCNT_SET( TOWER, EQVOC_SUCCESS_MERKLE,  ctx->metrics.eqvoc_success_merkle  );
  FD_MCNT_SET( TOWER, EQVOC_SUCCESS_META,    ctx->metrics.eqvoc_success_meta    );
  FD_MCNT_SET( TOWER, EQVOC_SUCCESS_LAST,    ctx->metrics.eqvoc_success_last    );
  FD_MCNT_SET( TOWER, EQVOC_SUCCESS_OVERLAP, ctx->metrics.eqvoc_success_overlap );
  FD_MCNT_SET( TOWER, EQVOC_SUCCESS_CHAINED, ctx->metrics.eqvoc_success_chained );

  FD_MCNT_SET( TOWER, EQVOC_ERR_SERDE,     ctx->metrics.eqvoc_err_serde     );
  FD_MCNT_SET( TOWER, EQVOC_ERR_SLOT,      ctx->metrics.eqvoc_err_slot      );
  FD_MCNT_SET( TOWER, EQVOC_ERR_VERSION,   ctx->metrics.eqvoc_err_version   );
  FD_MCNT_SET( TOWER, EQVOC_ERR_TYPE,      ctx->metrics.eqvoc_err_type      );
  FD_MCNT_SET( TOWER, EQVOC_ERR_MERKLE,    ctx->metrics.eqvoc_err_merkle    );
  FD_MCNT_SET( TOWER, EQVOC_ERR_SIGNATURE, ctx->metrics.eqvoc_err_signature );

  FD_MCNT_SET( TOWER, EQVOC_ERR_CHUNK_CNT, ctx->metrics.eqvoc_err_chunk_cnt );
  FD_MCNT_SET( TOWER, EQVOC_ERR_CHUNK_IDX, ctx->metrics.eqvoc_err_chunk_idx );
  FD_MCNT_SET( TOWER, EQVOC_ERR_CHUNK_LEN, ctx->metrics.eqvoc_err_chunk_len );

  FD_MCNT_SET( TOWER, EQVOC_ERR_IGNORED_FROM, ctx->metrics.eqvoc_err_ignored_from );
  FD_MCNT_SET( TOWER, EQVOC_ERR_IGNORED_SLOT, ctx->metrics.eqvoc_err_ignored_slot );

  FD_MCNT_SET( TOWER, EQVOC_PROOF_CONSTRUCTED, ctx->metrics.eqvoc_proof_constructed );
  FD_MCNT_SET( TOWER, EQVOC_PROOF_VERIFIED,    ctx->metrics.eqvoc_proof_verified    );

  FD_MGAUGE_SET( TOWER, HFORK_MATCHED_SLOT,    ctx->metrics.hfork_matched_slot    );
  FD_MGAUGE_SET( TOWER, HFORK_MISMATCHED_SLOT, ctx->metrics.hfork_mismatched_slot );
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
    *opt_poll_in = 0; /* drain the publishes */
    *charge_busy = 1;
  }
}

static inline int
returnable_frag( fd_tower_tile_t *   ctx,
                 ulong               in_idx,
                 ulong               seq FD_PARAM_UNUSED,
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
  case IN_KIND_DEDUP: {
    if( FD_UNLIKELY( ctx->root_slot==ULONG_MAX ) ) return 1;
    fd_txn_m_t * txnm = (fd_txn_m_t *)fd_chunk_to_laddr( ctx->in[in_idx].mem, chunk );
    FD_TEST( txnm->payload_sz<=FD_TPU_MTU );
    FD_TEST( txnm->txn_t_sz<=FD_TXN_MAX_SZ );
    count_vote( ctx, fd_txn_m_txn_t_const( txnm ), fd_txn_m_payload_const( txnm ) );
    return 0;
  }
  case IN_KIND_EPOCH: {
    fd_multi_epoch_leaders_epoch_msg_init( ctx->mleaders, fd_chunk_to_laddr_const( ctx->in[ in_idx ].mem, chunk ) );
    fd_multi_epoch_leaders_epoch_msg_fini( ctx->mleaders );
    return 0;
  }
  case IN_KIND_GOSSIP: {
    if( FD_LIKELY( sig==FD_GOSSIP_UPDATE_TAG_DUPLICATE_SHRED ) ) {
      fd_gossip_update_message_t const  * msg             = (fd_gossip_update_message_t const *)fd_type_pun_const( fd_chunk_to_laddr_const( ctx->in[ in_idx ].mem, chunk ) );
      fd_gossip_duplicate_shred_t const * duplicate_shred = msg->duplicate_shred;
      fd_pubkey_t const                 * from            = (fd_pubkey_t const *)fd_type_pun_const( msg->origin );
      fd_epoch_leaders_t const *          lsched          = fd_multi_epoch_leaders_get_lsched_for_slot( ctx->mleaders, duplicate_shred->slot );
      fd_tower_slot_duplicate_t         * out             = fd_chunk_to_laddr( ctx->out_mem, ctx->out_chunk );
      int eqvoc_err = fd_eqvoc_chunk_insert( ctx->eqvoc, ctx->shred_version, ctx->root_slot, lsched, from, duplicate_shred, out->chunks );
      update_eqvoc_metrics( ctx, eqvoc_err );
      if( FD_UNLIKELY( eqvoc_err>0 ) ) {
        ctx->metrics.eqvoc_proof_verified++;
        fd_stem_publish( stem, OUT_IDX, FD_TOWER_SIG_SLOT_DUPLICATE, ctx->out_chunk, sizeof(fd_tower_slot_duplicate_t), 0UL, tsorig, fd_frag_meta_ts_comp( fd_tickcount() ) );
        ctx->out_chunk = fd_dcache_compact_next( ctx->out_chunk, sizeof(fd_tower_slot_duplicate_t), ctx->out_chunk0, ctx->out_wmark );
        ctx->out_seq = stem->seqs[ OUT_IDX ];
      }
    }
    return 0;
  }
  case IN_KIND_IPECHO: {
    FD_TEST( sig!=0UL && sig<=USHORT_MAX );
    ctx->shred_version = (ushort)sig;
    return 0;
  }
  case IN_KIND_REPLAY: {
    /* In the case that the tower tile is halting signing, we don't
       want to process any replay fragments that will cause us to
       produce a vote txn. */
    if( FD_UNLIKELY( ctx->halt_signing ) ) return 1;

    if( FD_LIKELY( sig==REPLAY_SIG_TXN_EXECUTED ) ) {

      /* Agave only counts replay vote txns that executed successfully.
         https://github.com/anza-xyz/agave/blob/v3.1.8/runtime/src/bank_utils.rs#L53 */

      fd_replay_txn_executed_t * txn_executed = fd_type_pun( fd_chunk_to_laddr( ctx->in[in_idx].mem, chunk ) );
      if( FD_UNLIKELY( !txn_executed->is_committable || txn_executed->is_fees_only || txn_executed->txn_err ) ) return 0;
      count_vote( ctx, TXN(txn_executed->txn), txn_executed->txn->payload );
    } else if( FD_LIKELY( sig==REPLAY_SIG_SLOT_COMPLETED ) ) {
      fd_replay_slot_completed_t * slot_completed = (fd_replay_slot_completed_t *)fd_type_pun( fd_chunk_to_laddr( ctx->in[ in_idx ].mem, chunk ) );
      replay_slot_completed( ctx, slot_completed, tsorig, stem );
    } else if( FD_LIKELY( sig==REPLAY_SIG_SLOT_DEAD ) ) {
      fd_replay_slot_dead_t * slot_dead = (fd_replay_slot_dead_t *)fd_chunk_to_laddr( ctx->in[ in_idx ].mem, chunk );
      fd_hfork_blk_t * hfork_blk = fd_hfork_record_our_bank_hash( ctx->hfork, &slot_dead->block_id, NULL, fd_ghost_root( ctx->ghost )->total_stake );
      update_hfork_metrics( ctx, hfork_blk, slot_dead->slot, &slot_dead->block_id );
    }
    return 0;
  }
  case IN_KIND_SHRED: {
    if( FD_LIKELY( sz==FD_SHRED_MIN_SZ || sz==FD_SHRED_MAX_SZ ) ) { /* TODO depends on pending shred_out changes */
      fd_shred_t                * shred = (fd_shred_t *)fd_type_pun( fd_chunk_to_laddr( ctx->in[ in_idx ].mem, chunk ) );
      fd_tower_slot_duplicate_t * out   = fd_chunk_to_laddr( ctx->out_mem, ctx->out_chunk );
      fd_epoch_leaders_t const * lsched = fd_multi_epoch_leaders_get_lsched_for_slot( ctx->mleaders, shred->slot );
      int eqvoc_err = fd_eqvoc_shred_insert( ctx->eqvoc, ctx->shred_version, ctx->root_slot, lsched, shred, out->chunks );
      update_eqvoc_metrics( ctx, eqvoc_err );
      if( FD_UNLIKELY( eqvoc_err>0 ) ) {
        ctx->metrics.eqvoc_proof_constructed++;
        fd_stem_publish( stem, OUT_IDX, FD_TOWER_SIG_SLOT_DUPLICATE, ctx->out_chunk, sizeof(fd_tower_slot_duplicate_t), 0UL, tsorig, fd_frag_meta_ts_comp( fd_tickcount() ) );
        ctx->out_chunk = fd_dcache_compact_next( ctx->out_chunk, sizeof(fd_tower_slot_duplicate_t), ctx->out_chunk0, ctx->out_wmark );
        ctx->out_seq = stem->seqs[ OUT_IDX ];
      }
    }
    return 0;
  }
  default: {
    FD_LOG_ERR(( "unexpected input kind %d", ctx->in_kind[ in_idx ] ));
  }
  }
}

static void
privileged_init( fd_topo_t *      topo,
                 fd_topo_tile_t * tile ) {
  void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );
  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_tower_tile_t * ctx      = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_tower_tile_t),   sizeof(fd_tower_tile_t)        );
  void            * auth_vtr = FD_SCRATCH_ALLOC_APPEND( l, auth_vtr_align(), auth_vtr_footprint() );
  FD_SCRATCH_ALLOC_FINI( l, scratch_align() );

  FD_TEST( fd_rng_secure( &ctx->seed, sizeof(ctx->seed) ) );

  if( FD_UNLIKELY( !strcmp( tile->tower.identity_key, "" ) ) ) FD_LOG_ERR(( "identity_key_path not set" ));
  ctx->identity_key[ 0 ] = *(fd_pubkey_t const *)fd_type_pun_const( fd_keyload_load( tile->tower.identity_key, /* pubkey only: */ 1 ) );

  /* The vote key can be specified either directly as a base58 encoded
     pubkey, or as a file path.  We first try to decode as a pubkey. */

  uchar * vote_key = fd_base58_decode_32( tile->tower.vote_account, ctx->vote_account->uc );
  if( FD_UNLIKELY( !vote_key ) ) ctx->vote_account[ 0 ] = *(fd_pubkey_t const *)fd_type_pun_const( fd_keyload_load( tile->tower.vote_account, /* pubkey only: */ 1 ) );

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

  /* The tower file is used to checkpt and restore the state of the
     local tower. */

  char path[ PATH_MAX ];
  FD_BASE58_ENCODE_32_BYTES( ctx->identity_key->uc, identity_key_b58 );
  FD_TEST( fd_cstr_printf_check( path, sizeof(path), NULL, "%s/tower-1_9-%s.bin.new", tile->tower.base_path, identity_key_b58 ) );
  ctx->checkpt_fd = open( path, O_WRONLY|O_CREAT|O_TRUNC, 0600 );
  if( FD_UNLIKELY( -1==ctx->checkpt_fd ) ) FD_LOG_ERR(( "open(`%s`) failed (%i-%s)", path, errno, fd_io_strerror( errno ) ));

  FD_TEST( fd_cstr_printf_check( path, sizeof(path), NULL, "%s/tower-1_9-%s.bin", tile->tower.base_path, identity_key_b58 ) );
  ctx->restore_fd = open( path, O_RDONLY );
  if( FD_UNLIKELY( -1==ctx->restore_fd && errno!=ENOENT ) ) FD_LOG_ERR(( "open(`%s`) failed (%i-%s)", path, errno, fd_io_strerror( errno ) ));
}

static void
unprivileged_init( fd_topo_t *      topo,
                   fd_topo_tile_t * tile ) {
  ulong slot_max    = fd_ulong_pow2_up( tile->tower.max_live_slots );
  ulong per_vtr_max = PER_VTR_MAX;
  ulong vtr_max     = fd_ulong_pow2_up( VTR_MAX );
  ulong blk_max     = slot_max * EQVOC_MAX;
  ulong fec_max     = slot_max * FD_SHRED_BLK_MAX / FD_FEC_SHRED_CNT;
  ulong pub_max     = slot_max * FD_TOWER_SLOT_CONFIRMED_LEVEL_CNT;

  void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );
  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_tower_tile_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_tower_tile_t), sizeof(fd_tower_tile_t)                                       );
  void  * auth_vtr      = FD_SCRATCH_ALLOC_APPEND( l, auth_vtr_align(),         auth_vtr_footprint()                                          );
  void  * eqvoc         = FD_SCRATCH_ALLOC_APPEND( l, fd_eqvoc_align(),         fd_eqvoc_footprint( slot_max, fec_max, per_vtr_max, vtr_max ) );
  void  * ghost         = FD_SCRATCH_ALLOC_APPEND( l, fd_ghost_align(),         fd_ghost_footprint( blk_max, vtr_max )                        );
  void  * hfork         = FD_SCRATCH_ALLOC_APPEND( l, fd_hfork_align(),         fd_hfork_footprint( slot_max, vtr_max )                       );
  void  * votes         = FD_SCRATCH_ALLOC_APPEND( l, fd_votes_align(),         fd_votes_footprint( slot_max, vtr_max )                       );
  void  * tower         = FD_SCRATCH_ALLOC_APPEND( l, fd_tower_align(),         fd_tower_footprint()                                          );
  void  * scratch_tower = FD_SCRATCH_ALLOC_APPEND( l, fd_tower_align(),         fd_tower_footprint()                                          );
  void  * tower_blocks  = FD_SCRATCH_ALLOC_APPEND( l, fd_tower_blocks_align(),  fd_tower_blocks_footprint( slot_max )                         );
  void  * tower_lockos  = FD_SCRATCH_ALLOC_APPEND( l, fd_tower_lockos_align(),  fd_tower_lockos_footprint( slot_max, vtr_max )                );
  void  * tower_stakes  = FD_SCRATCH_ALLOC_APPEND( l, fd_tower_stakes_align(),  fd_tower_stakes_footprint( slot_max, vtr_max )                );
  void  * tower_voters  = FD_SCRATCH_ALLOC_APPEND( l, fd_tower_voters_align(),  fd_tower_voters_footprint( vtr_max )                          );
  void  * publishes     = FD_SCRATCH_ALLOC_APPEND( l, publishes_align(),        publishes_footprint( pub_max )                                );
  FD_SCRATCH_ALLOC_FINI( l, scratch_align() );

  ctx->wksp               = topo->workspaces[ topo->objs[ tile->tile_obj_id ].wksp_id ].wksp;
  ctx->identity_keyswitch = fd_keyswitch_join( fd_topo_obj_laddr( topo, tile->id_keyswitch_obj_id ) );
  ctx->auth_vtr_keyswitch = fd_keyswitch_join( fd_topo_obj_laddr( topo, tile->av_keyswitch_obj_id ) );
  (void)auth_vtr; /* privileged_init */
  ctx->eqvoc              = fd_eqvoc_join       ( fd_eqvoc_new       ( eqvoc, slot_max, fec_max, slot_max, vtr_max, ctx->seed )              );
  ctx->ghost              = fd_ghost_join       ( fd_ghost_new       ( ghost, blk_max, vtr_max, ctx->seed )                                  );
  ctx->hfork              = fd_hfork_join       ( fd_hfork_new       ( hfork, slot_max, vtr_max, ctx->seed ) );
  ctx->votes              = fd_votes_join       ( fd_votes_new       ( votes, slot_max, vtr_max, ctx->seed )                                  );
  ctx->tower              = fd_tower_join       ( fd_tower_new       ( tower )                                                                 );
  ctx->scratch_tower      = fd_tower_join       ( fd_tower_new       ( scratch_tower )                                                         );
  ctx->tower_blocks       = fd_tower_blocks_join( fd_tower_blocks_new( tower_blocks, slot_max, ctx->seed )                                     );
  ctx->tower_lockos       = fd_tower_lockos_join( fd_tower_lockos_new( tower_lockos, slot_max, vtr_max, ctx->seed )                          );
  ctx->tower_stakes       = fd_tower_stakes_join( fd_tower_stakes_new( tower_stakes, slot_max, vtr_max, ctx->seed )                            );
  ctx->tower_voters       = fd_tower_voters_join( fd_tower_voters_new( tower_voters, vtr_max )                                               );
  ctx->publishes          = publishes_join      ( publishes_new      ( publishes, pub_max )                                                    );
  ctx->mleaders           = fd_multi_epoch_leaders_join( fd_multi_epoch_leaders_new( ctx->mleaders_mem ) );

  FD_TEST( ctx->wksp  );
  FD_TEST( ctx->identity_keyswitch );
  FD_TEST( ctx->auth_vtr_keyswitch );
  FD_TEST( ctx->auth_vtr );
  FD_TEST( ctx->eqvoc );
  FD_TEST( ctx->ghost );
  FD_TEST( ctx->hfork );
  FD_TEST( ctx->votes );
  FD_TEST( ctx->tower );
  FD_TEST( ctx->scratch_tower );
  FD_TEST( ctx->tower_blocks );
  FD_TEST( ctx->tower_lockos );
  FD_TEST( ctx->tower_stakes );
  FD_TEST( ctx->tower_voters );
  FD_TEST( ctx->publishes );

  memset( ctx->chunks, 0, sizeof(ctx->chunks) );
  memset( &ctx->compact_tower_sync_serde, 0, sizeof(ctx->compact_tower_sync_serde) );
  memset( ctx->vote_txn, 0, sizeof(ctx->vote_txn) );

  ctx->halt_signing    = 0;
  ctx->hard_fork_fatal = tile->tower.hard_fork_fatal;
  ctx->shred_version   = 0;
  ctx->init_slot       = ULONG_MAX;
  ctx->root_slot       = ULONG_MAX;

  ulong banks_obj_id = fd_pod_query_ulong( topo->props, "banks", ULONG_MAX );
  FD_TEST( banks_obj_id!=ULONG_MAX );
  ulong banks_locks_obj_id = fd_pod_query_ulong( topo->props, "banks_locks", ULONG_MAX );
  FD_TEST( banks_locks_obj_id!=ULONG_MAX );
  FD_TEST( fd_banks_join( ctx->banks, fd_topo_obj_laddr( topo, banks_obj_id ), fd_topo_obj_laddr( topo, banks_locks_obj_id ) ) );

  fd_accdb_init_from_topo( ctx->accdb, topo, tile, tile->tower.accdb_max_depth );

  FD_TEST( tile->in_cnt<sizeof(ctx->in_kind)/sizeof(ctx->in_kind[0]) );
  for( ulong i=0UL; i<tile->in_cnt; i++ ) {
    fd_topo_link_t * link = &topo->links[ tile->in_link_id[ i ] ];
    fd_topo_wksp_t * link_wksp = &topo->workspaces[ topo->objs[ link->dcache_obj_id ].wksp_id ];

    if     ( FD_LIKELY( !strcmp( link->name, "dedup_resolv"  ) ) ) ctx->in_kind[ i ] = IN_KIND_DEDUP;
    else if( FD_LIKELY( !strcmp( link->name, "replay_epoch"  ) ) ) ctx->in_kind[ i ] = IN_KIND_EPOCH;
    else if( FD_LIKELY( !strcmp( link->name, "gossip_out"    ) ) ) ctx->in_kind[ i ] = IN_KIND_GOSSIP;
    else if( FD_LIKELY( !strcmp( link->name, "ipecho_out"    ) ) ) ctx->in_kind[ i ] = IN_KIND_IPECHO;
    else if( FD_LIKELY( !strcmp( link->name, "replay_out"    ) ) ) ctx->in_kind[ i ] = IN_KIND_REPLAY;
    else if( FD_LIKELY( !strcmp( link->name, "shred_out"     ) ) ) ctx->in_kind[ i ] = IN_KIND_SHRED;
    else     FD_LOG_ERR(( "tower tile has unexpected input link %lu %s", i, link->name ));

    ctx->in[ i ].mcache_only = !link->mtu;
    if( FD_LIKELY( !ctx->in[ i ].mcache_only ) ) {
      ctx->in[ i ].mem    = link_wksp->wksp;
      ctx->in[ i ].mtu    = link->mtu;
      ctx->in[ i ].chunk0 = fd_dcache_compact_chunk0( ctx->in[ i ].mem, link->dcache );
      ctx->in[ i ].wmark  = fd_dcache_compact_wmark ( ctx->in[ i ].mem, link->dcache, link->mtu );
    }
  }

  ctx->out_mem    = topo->workspaces[ topo->objs[ topo->links[ tile->out_link_id[ 0 ] ].dcache_obj_id ].wksp_id ].wksp;
  ctx->out_chunk0 = fd_dcache_compact_chunk0( ctx->out_mem, topo->links[ tile->out_link_id[ 0 ] ].dcache );
  ctx->out_wmark  = fd_dcache_compact_wmark ( ctx->out_mem, topo->links[ tile->out_link_id[ 0 ] ].dcache, topo->links[ tile->out_link_id[ 0 ] ].mtu );
  ctx->out_chunk  = ctx->out_chunk0;
  ctx->out_seq    = 0UL;

  memset( &ctx->metrics, 0, sizeof(ctx->metrics) );
}

static ulong
populate_allowed_seccomp( fd_topo_t const *      topo,
                          fd_topo_tile_t const * tile,
                          ulong                  out_cnt,
                          struct sock_filter *   out ) {
  void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );
  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_tower_tile_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_tower_tile_t), sizeof(fd_tower_tile_t) );

  populate_sock_filter_policy_fd_tower_tile( out_cnt, out, (uint)fd_log_private_logfile_fd(), (uint)ctx->checkpt_fd, (uint)ctx->restore_fd );
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

  if( FD_UNLIKELY( out_fds_cnt<4UL ) ) FD_LOG_ERR(( "out_fds_cnt %lu", out_fds_cnt ));

  ulong out_cnt = 0UL;
  out_fds[ out_cnt++ ] = 2; /* stderr */
  if( FD_LIKELY( -1!=fd_log_private_logfile_fd() ) )
    out_fds[ out_cnt++ ] = fd_log_private_logfile_fd(); /* logfile */
  if( FD_LIKELY( ctx->checkpt_fd!=-1 ) ) out_fds[ out_cnt++ ] = ctx->checkpt_fd;
  if( FD_LIKELY( ctx->restore_fd!=-1 ) ) out_fds[ out_cnt++ ] = ctx->restore_fd;
  return out_cnt;
}

#define STEM_BURST (2UL)        /* MAX( slot_confirmed, slot_rooted AND (slot_done OR slot_ignored) ) */
#define STEM_LAZY  (128L*3000L) /* see explanation in fd_pack */

#define STEM_CALLBACK_CONTEXT_TYPE        fd_tower_tile_t
#define STEM_CALLBACK_CONTEXT_ALIGN       alignof(fd_tower_tile_t)
#define STEM_CALLBACK_DURING_HOUSEKEEPING during_housekeeping
#define STEM_CALLBACK_METRICS_WRITE       metrics_write
#define STEM_CALLBACK_AFTER_CREDIT        after_credit
#define STEM_CALLBACK_RETURNABLE_FRAG     returnable_frag

#include "../../disco/stem/fd_stem.c"

fd_topo_run_tile_t fd_tile_tower = {
  .name                     = "tower",
  .populate_allowed_seccomp = populate_allowed_seccomp,
  .populate_allowed_fds     = populate_allowed_fds,
  .scratch_align            = scratch_align,
  .scratch_footprint        = scratch_footprint,
  .unprivileged_init        = unprivileged_init,
  .privileged_init          = privileged_init,
  .run                      = stem_run,
};
