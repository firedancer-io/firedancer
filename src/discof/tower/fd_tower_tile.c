#include "fd_tower_tile.h"
#include "generated/fd_tower_tile_seccomp.h"

#include "../../choreo/ghost/fd_ghost.h"
#include "../../choreo/hfork/fd_hfork.h"
#include "../../choreo/notar/fd_notar.h"
#include "../../choreo/tower/fd_tower.h"
#include "../../choreo/tower/fd_tower_accts.h"
#include "../../choreo/tower/fd_tower_forks.h"
#include "../../choreo/tower/fd_tower_serde.h"
#include "../../disco/fd_txn_p.h"
#include "../../disco/keyguard/fd_keyload.h"
#include "../../disco/metrics/fd_metrics.h"
#include "../../disco/topo/fd_topo.h"
#include "../../disco/fd_txn_m.h"
#include "../../choreo/tower/fd_epoch_stakes.h"
#include "../../discof/restore/utils/fd_ssmsg.h"
#include "../../discof/replay/fd_exec.h"
#include "../../discof/replay/fd_replay_tile.h"
#include "../../flamenco/accdb/fd_accdb_impl_v1.h"
#include "../../flamenco/accdb/fd_accdb_sync.h"
#include "../../flamenco/runtime/fd_bank.h"
#include "../../util/pod/fd_pod.h"

#include <errno.h>
#include <fcntl.h>

/* The tower tile is responsible for two things:

   1. running the fork choice (fd_ghost) and TowerBFT (fd_tower) rules
      after replaying a block.
   2. listening to gossip (duplicate shred and vote messages) and
      monitoring for duplicate or duplicate confirmed blocks (fd_notar).

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

#define IN_KIND_DEDUP   (0)
#define IN_KIND_EXEC    (1)
#define IN_KIND_REPLAY  (2)

#define VOTE_TXN_SIG_MAX (2UL) /* validator identity and vote authority */

struct notif {
  ulong     slot;
  int       kind;
  fd_hash_t block_id; /* for notar confirmations only */
};
typedef struct notif notif_t;

#define DEQUE_NAME notif
#define DEQUE_T    notif_t
#include "../../util/tmpl/fd_deque_dynamic.c"

static const fd_hash_t manifest_block_id = { .ul = { 0xf17eda2ce7b1d } }; /* FIXME manifest_block_id */

typedef struct {
  fd_wksp_t * mem;
  ulong       chunk0;
  ulong       wmark;
  ulong       mtu;
} in_ctx_t;

typedef struct {
  fd_wksp_t * wksp; /* workspace */

  ulong       seed; /* map seed */
  int         checkpt_fd;
  int         restore_fd;
  fd_pubkey_t identity_key[1];
  fd_pubkey_t vote_account[1];
  uchar       our_vote_acct[FD_VOTE_STATE_DATA_MAX]; /* buffer for reading back our own vote acct data */

  /* structures owned by tower tile */

  fd_forks_t *        forks;
  fd_ghost_t *        ghost;
  fd_hfork_t *        hfork;
  fd_notar_t *        notar;
  fd_tower_t *        tower;
  fd_tower_t *        tower_spare; /* spare tower used during processing */
  notif_t *           notif;       /* deque of confirmation notifications queued for publishing */
  fd_tower_accts_t  * tower_accts; /* deque of accts, stake, and pubkey for the currently replayed slot */
  fd_epoch_stakes_t * slot_stakes; /* tracks the stakes for each voter in the epoch per fork */

  /* external joins owned by replay tile */

  fd_banks_t      banks[1];
  fd_accdb_user_t accdb[1];

  /* frag-related structures (consume and publish) */

  uchar                         vote_txn[FD_TPU_PARSED_MTU];
  fd_sha512_t *                 vote_sha[VOTE_TXN_SIG_MAX];
  fd_compact_tower_sync_serde_t compact_tower_sync_serde;
  fd_snapshot_manifest_t        manifest;
  fd_replay_slot_completed_t    replay_slot_completed;

  /* slot watermarks */

  ulong init_slot; /* initial slot from genesis or snapshot */
  ulong root_slot; /* monotonically increasing contiguous tower root slot */
  ulong conf_slot; /* monotonically increasing contiguous confirmed slot */

  /* in/out link setup */

  int      in_kind[ 64UL ];
  in_ctx_t in     [ 64UL ];

  fd_wksp_t * out_mem;
  ulong       out_chunk0;
  ulong       out_wmark;
  ulong       out_chunk;

  /* metrics */

  struct ctx_metrics_t {
    ulong vote_txn_invalid;
    ulong vote_txn_ignored;
    ulong vote_txn_mismatch;

    ulong ancestor_rollback;
    ulong sibling_confirmed;
    ulong same_fork;
    ulong switch_pass;
    ulong switch_fail;
    ulong lockout_fail;
    ulong threshold_fail;
    ulong propagated_fail;

    ulong slot_ignored;

    fd_hfork_metrics_t hard_forks;
  } metrics;
} ctx_t;

FD_FN_CONST static inline ulong
scratch_align( void ) {
  return 128UL;
}

FD_FN_PURE static inline ulong
scratch_footprint( FD_PARAM_UNUSED fd_topo_tile_t const * tile ) {
  ulong slot_max     = tile->tower.max_live_slots;
  FD_LOG_DEBUG(( "hfork footprint %lu", fd_hfork_footprint( slot_max, FD_VOTER_MAX ) ));
  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, alignof(ctx_t),          sizeof(ctx_t)                                        );
  l = FD_LAYOUT_APPEND( l, fd_ghost_align(),        fd_ghost_footprint( 2*slot_max, FD_VOTER_MAX )       );
  l = FD_LAYOUT_APPEND( l, fd_hfork_align(),        fd_hfork_footprint( slot_max, FD_VOTER_MAX )         );
  l = FD_LAYOUT_APPEND( l, fd_notar_align(),        fd_notar_footprint( tile->tower.max_vote_lookahead ) );
  l = FD_LAYOUT_APPEND( l, fd_tower_align(),        fd_tower_footprint()                                 );
  l = FD_LAYOUT_APPEND( l, fd_tower_accts_align(),  fd_tower_accts_footprint( FD_VOTER_MAX )             );
  l = FD_LAYOUT_APPEND( l, fd_forks_align(),        fd_forks_footprint( slot_max, FD_VOTER_MAX )         );
  l = FD_LAYOUT_APPEND( l, fd_tower_align(),        fd_tower_footprint()                                 ); /* ctx->tower_spare */
  l = FD_LAYOUT_APPEND( l, fd_epoch_stakes_align(), fd_epoch_stakes_footprint( slot_max )                );
  l = FD_LAYOUT_APPEND( l, notif_align(),           notif_footprint( slot_max )                          );
  return FD_LAYOUT_FINI( l, scratch_align() );
}

static inline void
metrics_write( ctx_t * ctx ) {
  FD_MCNT_SET( TOWER, VOTE_TXN_INVALID,  ctx->metrics.vote_txn_invalid  );
  FD_MCNT_SET( TOWER, VOTE_TXN_IGNORED,  ctx->metrics.vote_txn_ignored  );
  FD_MCNT_SET( TOWER, VOTE_TXN_MISMATCH, ctx->metrics.vote_txn_mismatch );

  FD_MCNT_SET( TOWER, ANCESTOR_ROLLBACK, ctx->metrics.ancestor_rollback );
  FD_MCNT_SET( TOWER, SIBLING_CONFIRMED, ctx->metrics.sibling_confirmed );
  FD_MCNT_SET( TOWER, SAME_FORK,         ctx->metrics.same_fork         );
  FD_MCNT_SET( TOWER, SWITCH_PASS,       ctx->metrics.switch_pass       );
  FD_MCNT_SET( TOWER, SWITCH_FAIL,       ctx->metrics.switch_fail       );
  FD_MCNT_SET( TOWER, LOCKOUT_FAIL,      ctx->metrics.lockout_fail      );
  FD_MCNT_SET( TOWER, THRESHOLD_FAIL,    ctx->metrics.threshold_fail    );
  FD_MCNT_SET( TOWER, PROPAGATED_FAIL,   ctx->metrics.propagated_fail   );

  FD_MCNT_SET( TOWER, SLOT_IGNORED,        ctx->metrics.slot_ignored      );
  FD_MCNT_SET( TOWER, HARD_FORKS_SEEN,     ctx->metrics.hard_forks.seen   );
  FD_MCNT_SET( TOWER, HARD_FORKS_PRUNED,   ctx->metrics.hard_forks.pruned );

  FD_MGAUGE_SET( TOWER, HARD_FORKS_ACTIVE, ctx->metrics.hard_forks.active    );
}

static void
publish_slot_confirmed( ctx_t *             ctx,
                        fd_stem_context_t * stem,
                        ulong               tsorig,
                        ulong               slot,
                        fd_hash_t const *   block_id,
                        ulong               bank_idx,
                        int                 kind ) {
  fd_tower_slot_confirmed_t * msg = fd_chunk_to_laddr( ctx->out_mem, ctx->out_chunk );
  msg->slot                       = slot;
  msg->block_id                   = *block_id;
  msg->bank_idx                   = bank_idx;
  msg->kind                       = kind;
  fd_stem_publish( stem, 0UL, FD_TOWER_SIG_SLOT_CONFIRMED, ctx->out_chunk, sizeof(fd_tower_slot_confirmed_t), 0UL, tsorig, fd_frag_meta_ts_comp( fd_tickcount() ) );
  ctx->out_chunk = fd_dcache_compact_next( ctx->out_chunk, sizeof(fd_tower_slot_confirmed_t), ctx->out_chunk0, ctx->out_wmark );
}

static void
contiguous_confirm( ctx_t *             ctx,
                    ulong               slot,
                    ulong               wmark,
                    int                 kind ) {

  /* For optimistic and rooted confirmations, confirming a slot means
     all ancestors are confirmed too, so we need to publish any skipped
     ancestors (confirmations can be out-of-order and roots can be
     skipped due to lockout). */

  ulong cnt      = 0;
  ulong ancestor = slot;
  while( FD_UNLIKELY( ancestor > wmark ) ) {
    fd_tower_forks_t * fork = fd_forks_query( ctx->forks, ancestor );
    if( FD_UNLIKELY( !fork ) ) break; /* rooted past this ancestor */
    if( FD_UNLIKELY( !notif_avail( ctx->notif ) ) ) FD_LOG_CRIT(( "attempted to confirm %lu slots more than slot max %lu", cnt, notif_max( ctx->notif ) )); /* should be impossible */
    notif_push_tail( ctx->notif, (notif_t){ .slot = ancestor, .kind = kind } );
    cnt++;
    ancestor = fork->parent_slot;
  }
}

static void
notar_confirm( ctx_t *             ctx,
               fd_notar_blk_t *    notar_blk ) {

  /* Record any confirmations in our tower forks structure and also
     publish slot_confirmed frags indicating confirmations to consumers.

     See documentation in fd_tower_tile.h for guarantees. */

  if( FD_LIKELY( notar_blk->dup_conf && !notar_blk->dup_notif ) ) {
    if( FD_UNLIKELY( !notif_avail( ctx->notif ) ) ) FD_LOG_CRIT(( "attempted to confirm more than slot max %lu", notif_max( ctx->notif ) )); /* should be impossible */
    notif_push_head( ctx->notif, (notif_t){ .slot = notar_blk->slot, .kind = FD_TOWER_SLOT_CONFIRMED_DUPLICATE, .block_id = notar_blk->block_id } );
    notar_blk->dup_notif = 1;

    fd_tower_forks_t * fork = fd_forks_query( ctx->forks, notar_blk->slot ); /* ensure fork exists */
    if( FD_UNLIKELY( !fork ) ) return; /* a slot can be duplicate confirmed by gossip votes before replay */
    fd_forks_confirmed( fork, &notar_blk->block_id );
  }
  if( FD_LIKELY( notar_blk->opt_conf ) ) {
    if( FD_UNLIKELY( !notar_blk->opt_notif ) ) {
      if( FD_UNLIKELY( !notif_avail( ctx->notif ) ) ) FD_LOG_CRIT(( "attempted to confirm more than slot max %lu", notif_max( ctx->notif ) )); /* should be impossible */
      notif_push_head( ctx->notif, (notif_t){ .slot = notar_blk->slot, .kind = FD_TOWER_SLOT_CONFIRMED_CLUSTER, .block_id = notar_blk->block_id } );
      notar_blk->opt_notif = 1;
    }
    fd_tower_forks_t * fork = fd_forks_query( ctx->forks, notar_blk->slot );
    if( FD_UNLIKELY( fork && notar_blk->slot > ctx->conf_slot ) ) {
      contiguous_confirm( ctx, notar_blk->slot, ctx->conf_slot, FD_TOWER_SLOT_CONFIRMED_OPTIMISTIC );
      ctx->conf_slot = notar_blk->slot;
    }
  }
}

static void
count_vote_txn( ctx_t *             ctx,
                fd_txn_t const *    txn,
                uchar const *       payload ) {

  /* Count vote txns from resolv and replay.  Note these txns have
     already been parsed and sigverified, so the only thing tower needs
     to do is filter for votes.

     We are a little stricter than Agave here when validating the vote
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

  if( FD_UNLIKELY( !fd_txn_is_simple_vote_transaction( txn, payload ) ) ) { ctx->metrics.vote_txn_invalid++; return; }

  /* TODO check the authorized voter for this vote account (from epoch
     stakes) is one of the signers */

  /* Filter any non-tower sync votes. */

  fd_txn_instr_t const * instr      = &txn->instr[0];
  uchar const *          instr_data = payload + instr->data_off;
  uint                   kind       = fd_uint_load_4_fast( instr_data );
  if( FD_UNLIKELY( kind != FD_VOTE_IX_KIND_TOWER_SYNC && kind != FD_VOTE_IX_KIND_TOWER_SYNC_SWITCH ) ) { ctx->metrics.vote_txn_ignored++; return; };

  /* Deserialize the CompactTowerSync. */

  int err = fd_compact_tower_sync_deserialize( &ctx->compact_tower_sync_serde, instr_data + sizeof(uint), instr->data_sz - sizeof(uint) );
  if( FD_UNLIKELY( err == -1 ) ) { ctx->metrics.vote_txn_invalid++; return; }
  ulong slot = ctx->compact_tower_sync_serde.root;
  fd_tower_remove_all( ctx->tower_spare );
  for( ulong i = 0; i < ctx->compact_tower_sync_serde.lockouts_cnt; i++ ) {
    slot += ctx->compact_tower_sync_serde.lockouts[i].offset;
    fd_tower_push_tail( ctx->tower_spare, (fd_tower_vote_t){ .slot = slot, .conf = ctx->compact_tower_sync_serde.lockouts[i].confirmation_count } );
  }
  if( FD_UNLIKELY( 0==memcmp( &ctx->compact_tower_sync_serde.block_id, &hash_null, sizeof(fd_hash_t) ) ) ) { ctx->metrics.vote_txn_invalid++; return; };

  fd_pubkey_t const * accs     = (fd_pubkey_t const *)fd_type_pun_const( payload + txn->acct_addr_off );
  fd_pubkey_t const * vote_acc = NULL;
  if( FD_UNLIKELY( txn->signature_cnt==1 ) ) vote_acc = (fd_pubkey_t const *)fd_type_pun_const( &accs[1] ); /* identity and authority same, account idx 1 is the vote account address */
  else                                       vote_acc = (fd_pubkey_t const *)fd_type_pun_const( &accs[2] ); /* identity and authority diff, account idx 2 is the vote account address */

  /* Return early if their tower is empty. */

  if( FD_UNLIKELY( fd_tower_empty( ctx->tower_spare ) ) ) { ctx->metrics.vote_txn_ignored++; return; };

  /* The vote txn contains a block id and bank hash for their last vote
     slot in the tower.  Agave always counts the last vote.

     https://github.com/anza-xyz/agave/blob/v2.3.7/core/src/cluster_info_vote_listener.rs#L476-L487 */

  fd_tower_vote_t const * their_last_vote = fd_tower_peek_tail_const( ctx->tower_spare );
  fd_hash_t const *       their_block_id  = &ctx->compact_tower_sync_serde.block_id;
  fd_hash_t const *       their_bank_hash = &ctx->compact_tower_sync_serde.hash;

  /* Similar to what Agave does in cluster_info_vote_listener, we use
     the stake associated with a vote account as of our current root
     (which could potentially be a different epoch than the vote we are
     counting or when we observe the vote).  They default stake to 0 for
     voters who are not found. */

  ulong total_stake = fd_ghost_root( ctx->ghost )->total_stake;

  fd_voter_stake_key_t stake_key = { .vote_account = *vote_acc, .slot = ctx->root_slot };
  fd_voter_stake_t *   stake     = fd_voter_stake_map_ele_query( ctx->slot_stakes->voter_stake_map, &stake_key, NULL, ctx->slot_stakes->voter_stake_pool );

  fd_hfork_count_vote( ctx->hfork, vote_acc, their_block_id, their_bank_hash, their_last_vote->slot, stake ? stake->stake : 0, total_stake, &ctx->metrics.hard_forks );

  fd_notar_blk_t * notar_blk   = fd_notar_count_vote( ctx->notar, total_stake, vote_acc, their_last_vote->slot, their_block_id );
  if( FD_LIKELY( notar_blk ) ) notar_confirm( ctx, notar_blk );

  fd_tower_forks_t * fork = fd_tower_forks_query( ctx->forks->tower_forks, their_last_vote->slot, NULL );
  if( FD_UNLIKELY( !fork ) ) { ctx->metrics.vote_txn_ignored++; return; /* we haven't replayed this slot yet */ };

  fd_hash_t const * our_block_id = fd_forks_canonical_block_id( ctx->forks, their_last_vote->slot );
  if( FD_UNLIKELY( 0!=memcmp( our_block_id, their_block_id, sizeof(fd_hash_t) ) ) ) { ctx->metrics.vote_txn_mismatch++; return; }

  /* Agave decides to count intermediate vote slots in the tower only if
     1. they've replayed the slot and 2. their replay bank hash matches
     the vote's bank hash.  We do the same thing, but using block_ids.

     It's possible we haven't yet replayed this slot being voted on
     because gossip votes can be ahead of our replay.

     https://github.com/anza-xyz/agave/blob/v2.3.7/core/src/cluster_info_vote_listener.rs#L483-L487 */

  int skipped_last_vote = 0;
  for( fd_tower_iter_t iter = fd_tower_iter_init_rev( ctx->tower_spare       );
                             !fd_tower_iter_done_rev( ctx->tower_spare, iter );
                       iter = fd_tower_iter_prev    ( ctx->tower_spare, iter ) ) {
    if( FD_UNLIKELY( !skipped_last_vote ) ) { skipped_last_vote = 1; continue; }
    fd_tower_vote_t const * their_intermediate_vote = fd_tower_iter_ele_const( ctx->tower_spare, iter );

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

    fd_tower_forks_t * fork = fd_forks_query( ctx->forks, their_intermediate_vote->slot );
    if( FD_UNLIKELY( !fork ) ) { ctx->metrics.vote_txn_ignored++; continue; }

    /* Otherwise, we count the vote using our own block id for that slot
       (again, mirroring what Agave does albeit with bank hashes).

       Agave uses the current root bank's total stake when counting
       vote txns from gossip / replay:

       https://github.com/anza-xyz/agave/blob/v2.3.7/core/src/cluster_info_vote_listener.rs#L500 */


    fd_notar_blk_t * notar_blk = fd_notar_count_vote( ctx->notar, total_stake, vote_acc, their_intermediate_vote->slot, fd_forks_canonical_block_id( ctx->forks, their_intermediate_vote->slot ) );
    if( FD_LIKELY( notar_blk ) ) notar_confirm( ctx, notar_blk );
  }
}

ulong
query_acct_stake_from_bank( fd_tower_accts_t *  tower_accts_deque,
                            fd_epoch_stakes_t * epoch_stakes,
                            fd_bank_t *         bank,
                            ulong               slot ) {
  ulong total_stake = 0;
  fd_vote_states_t const * vote_states = fd_bank_vote_states_locking_query( bank );
  fd_vote_states_iter_t iter_[1];
  ulong prev_voter_idx = ULONG_MAX;
  for( fd_vote_states_iter_t * iter = fd_vote_states_iter_init( iter_, vote_states );
                                     !fd_vote_states_iter_done( iter );
                                      fd_vote_states_iter_next( iter ) ) {
    fd_vote_state_ele_t const * vote_state = fd_vote_states_iter_ele( iter );
    if( FD_UNLIKELY( vote_state->stake_t_2 == 0 ) ) continue; /* skip unstaked vote accounts */
    fd_pubkey_t const * vote_account_pubkey = &vote_state->vote_account;
    fd_tower_accts_push_tail( tower_accts_deque, (fd_tower_accts_t){ .addr = *vote_account_pubkey, .stake = vote_state->stake_t_2 } );
    prev_voter_idx = fd_epoch_stakes_slot_stakes_add( epoch_stakes, slot, vote_account_pubkey, vote_state->stake_t_2, prev_voter_idx );
    total_stake += vote_state->stake_t_2;
  }
  fd_bank_vote_states_end_locking_query( bank );
  return total_stake;
}

/* query accdb for the vote state (vote account data) of the given vote
   account address as of xid.  Returns 1 if found, 0 otherwise.

   If opt_acc_bal is not NULL, it will be set to the account balance in
   lamports of the queried account, if found. */

static int
query_vote_state_from_accdb( fd_accdb_user_t *         accdb,
                             fd_funk_txn_xid_t const * xid,
                             fd_pubkey_t const *       vote_acc,
                             ulong *                   opt_acc_bal,
                             uchar                     buf[static FD_VOTE_STATE_DATA_MAX] ) {
  for(;;) {
    fd_accdb_peek_t peek[1];
    if( FD_UNLIKELY( !fd_accdb_peek( accdb, peek, xid, vote_acc->uc ) ) ) return 0;

    ulong data_sz = fd_accdb_ref_data_sz( peek->acc );
    if( FD_UNLIKELY( data_sz > FD_VOTE_STATE_DATA_MAX ) ) {
      FD_BASE58_ENCODE_32_BYTES( vote_acc->uc, acc_cstr );
      FD_LOG_CRIT(( "vote account %s exceeds FD_VOTE_STATE_DATA_MAX. dlen %lu > %lu", acc_cstr, data_sz, FD_VOTE_STATE_DATA_MAX ));
    }
    fd_memcpy( buf, fd_accdb_ref_data_const( peek->acc ), data_sz );

    fd_ulong_store_if( !!opt_acc_bal, opt_acc_bal, fd_accdb_ref_lamports( peek->acc ) );

    if( FD_LIKELY( fd_accdb_peek_test( peek ) ) ) break;
    FD_SPIN_PAUSE();
  }
  return 1;
}

static void
replay_slot_completed( ctx_t *                      ctx,
                       fd_replay_slot_completed_t * slot_completed,
                       ulong                        tsorig,
                       fd_stem_context_t *          stem ) {

  /* Initialize slot watermarks on the first replay_slot_completed. */

  if( FD_UNLIKELY( ctx->init_slot == ULONG_MAX ) ) {
    ctx->init_slot = slot_completed->slot;
    ctx->root_slot = slot_completed->slot;
    ctx->conf_slot = slot_completed->slot;
  }

    if( FD_UNLIKELY( 0==memcmp( &slot_completed->block_id.uc, &hash_null, sizeof(fd_hash_t) ) ) ) {
      FD_LOG_CRIT(( "replay_slot_completed slot %lu block id is null", slot_completed->slot ));
    }

  /* This is a temporary patch for equivocation. */

  if( FD_UNLIKELY( fd_forks_query( ctx->forks, slot_completed->slot ) ) ) {
    FD_BASE58_ENCODE_32_BYTES( slot_completed->block_id.uc, block_id );
    FD_LOG_WARNING(( "tower ignoring replay of equivocating slot %lu %s", slot_completed->slot, block_id ));

    /* Still need to return a message to replay so the refcnt on the bank is decremented. */
    fd_tower_slot_ignored_t * msg = fd_chunk_to_laddr( ctx->out_mem, ctx->out_chunk );
    msg->slot     = slot_completed->slot;
    msg->bank_idx = slot_completed->bank_idx;

    fd_stem_publish( stem, 0UL, FD_TOWER_SIG_SLOT_IGNORED, ctx->out_chunk, sizeof(fd_tower_slot_ignored_t), 0UL, tsorig, fd_frag_meta_ts_comp( fd_tickcount() ) );
    ctx->out_chunk = fd_dcache_compact_next( ctx->out_chunk, sizeof(fd_tower_slot_ignored_t), ctx->out_chunk0, ctx->out_wmark );
    return;
  }

  /* Initialize the xid. */

  fd_funk_txn_xid_t xid = { .ul = { slot_completed->slot, slot_completed->bank_idx } };

  /* Query our on-chain vote acct and reconcile with our local tower. */

  ulong our_vote_acct_bal = ULONG_MAX;
  int found = query_vote_state_from_accdb( ctx->accdb, &xid, ctx->vote_account, &our_vote_acct_bal, ctx->our_vote_acct );
  if( FD_LIKELY( found ) ) {
    fd_tower_reconcile( ctx->tower, ctx->root_slot, ctx->our_vote_acct );
    /* Sanity check that most recent vote in tower exists in tower forks */
    fd_tower_vote_t const * last_vote = fd_tower_peek_tail_const( ctx->tower );
    FD_TEST( !last_vote || fd_forks_query( ctx->forks, last_vote->slot ) );
  }

  /* Insert the vote acct addrs and stakes from the bank into accts. */

  fd_tower_accts_remove_all( ctx->tower_accts );
  fd_bank_t bank[1];
  if( FD_UNLIKELY( !fd_banks_bank_query( bank, ctx->banks, slot_completed->bank_idx ) ) ) FD_LOG_CRIT(( "invariant violation: bank %lu is missing", slot_completed->bank_idx ));
  ulong total_stake = query_acct_stake_from_bank( ctx->tower_accts, ctx->slot_stakes, bank, slot_completed->slot );

  /* Insert the just replayed block into forks. */

  FD_TEST( !fd_forks_query( ctx->forks, slot_completed->slot ) );
  fd_tower_forks_t * fork = fd_forks_insert( ctx->forks, slot_completed->slot, slot_completed->parent_slot );
  fork->parent_slot       = slot_completed->parent_slot;
  fork->confirmed         = 0;
  fork->voted             = 0;
  fork->replayed_block_id = slot_completed->block_id;
  fork->bank_idx          = slot_completed->bank_idx;
  fd_forks_replayed( ctx->forks, fork, slot_completed->bank_idx, &slot_completed->block_id );
  fd_forks_lockouts_clear( ctx->forks, slot_completed->parent_slot );

  /* Insert the just replayed block into ghost. */

  fd_hash_t const * parent_block_id = &slot_completed->parent_block_id;
  if( FD_UNLIKELY( slot_completed->parent_slot==ctx->init_slot ) ) parent_block_id = &manifest_block_id;
  if( FD_UNLIKELY( slot_completed->slot       ==ctx->init_slot ) ) parent_block_id = NULL;

  if( FD_UNLIKELY( parent_block_id && !fd_ghost_query( ctx->ghost, parent_block_id ) ) ) {

    /* Rare occurrence where replay executes a block down a minority fork
       that we have pruned.  Due to a race in reading frags, replay may
       believe the minority fork exists and is still executable,  and
       executes the block and delivers it to tower.  Tower should ignore
       this block as it's parent no longer exists. */

    FD_BASE58_ENCODE_32_BYTES( parent_block_id->uc, parent_block_id_cstr );
    FD_LOG_WARNING(( "replay likely lagging tower publish, executed slot %lu is missing parent block id %s, excluding from ghost", slot_completed->slot, parent_block_id_cstr ));
    ctx->metrics.slot_ignored++;

    /* Still need to return a message to replay so the refcnt on the
       bank is decremented. */

    fd_tower_slot_ignored_t * msg = fd_chunk_to_laddr( ctx->out_mem, ctx->out_chunk );
    msg->slot     = slot_completed->slot;
    msg->bank_idx = slot_completed->bank_idx;

    fd_stem_publish( stem, 0UL, FD_TOWER_SIG_SLOT_IGNORED, ctx->out_chunk, sizeof(fd_tower_slot_ignored_t), 0UL, tsorig, fd_frag_meta_ts_comp( fd_tickcount() ) );
    ctx->out_chunk = fd_dcache_compact_next( ctx->out_chunk, sizeof(fd_tower_slot_ignored_t), ctx->out_chunk0, ctx->out_wmark );
    return;
  }

  fd_ghost_blk_t * ghost_blk = fd_ghost_insert( ctx->ghost, &slot_completed->block_id, parent_block_id, slot_completed->slot );
  ghost_blk->total_stake     = total_stake;

  /* Iterate vote accounts. */

  for( fd_tower_accts_iter_t iter = fd_tower_accts_iter_init( ctx->tower_accts       );
                                   !fd_tower_accts_iter_done( ctx->tower_accts, iter );
                             iter = fd_tower_accts_iter_next( ctx->tower_accts, iter ) ) {
    fd_tower_accts_t *  acct     = fd_tower_accts_iter_ele( ctx->tower_accts, iter );
    fd_pubkey_t const * vote_acc = &acct->addr;

    if( FD_UNLIKELY( !query_vote_state_from_accdb( ctx->accdb, &xid, vote_acc, NULL, acct->data ) ) ) {
      FD_BASE58_ENCODE_32_BYTES( vote_acc->uc, acc_cstr );
      FD_LOG_CRIT(( "vote account in bank->vote_states not found. slot %lu address: %s", slot_completed->slot, acc_cstr ));
    };

    /* 1. Update forks with lockouts. */

    fd_forks_lockouts_add( ctx->forks, slot_completed->slot, &acct->addr, acct );

    /* 2. Count the last vote slot in the vote state towards ghost. */

    ulong vote_slot = fd_voter_vote_slot( acct->data );
    if( FD_UNLIKELY( vote_slot==ULONG_MAX                          ) ) continue; /* hasn't voted */
    if( FD_UNLIKELY( vote_slot < fd_ghost_root( ctx->ghost )->slot ) ) continue; /* vote too old */

    /* We search up the ghost ancestry to find the ghost block for this
       vote slot.  In Agave, they look this value up using a hashmap of
       slot->block_id ("fork progress"), but that approach only works
       because they dump and repair (so there's only ever one canonical
       block id).  We retain multiple block ids, both the original and
       confirmed one. */

    fd_ghost_blk_t * ancestor_blk = fd_ghost_slot_ancestor( ctx->ghost, ghost_blk, vote_slot ); /* FIXME potentially slow */

    /* It is impossible for ancestor to be missing, because these are
       vote accounts on a given fork, not vote txns across forks.  So we
       know these towers must contain slots we know about (as long as
       they are >= root, which we checked above). */

    if( FD_UNLIKELY( !ancestor_blk ) ) {
      FD_BASE58_ENCODE_32_BYTES( acct->addr.key, pubkey_b58 );
      FD_LOG_CRIT(( "missing ancestor. replay slot %lu vote slot %lu voter %s", slot_completed->slot, vote_slot, pubkey_b58 ));
    }

    fd_ghost_count_vote( ctx->ghost, ancestor_blk, &acct->addr, acct->stake, vote_slot );
  }

  /* Insert the just replayed block into hard fork detector. */

  fd_hfork_record_our_bank_hash( ctx->hfork, &slot_completed->block_id, &slot_completed->bank_hash, fd_ghost_root( ctx->ghost )->total_stake );

  /* fd_notar requires some bookkeeping when there is a new epoch. */

  if( FD_UNLIKELY( ctx->notar->epoch==ULONG_MAX || slot_completed->epoch > ctx->notar->epoch ) ) {
    fd_notar_advance_epoch( ctx->notar, ctx->tower_accts, slot_completed->epoch );
  }

  /* Check if gossip votes already confirmed the fork's block_id (gossip
     can be ahead of replay - this is tracked by fd_notar). */

  fd_notar_slot_t * notar_slot = fd_notar_slot_query( ctx->notar->slot_map, slot_completed->slot, NULL );
  if( FD_UNLIKELY( notar_slot )) { /* optimize for replay keeping up (being ahead of gossip votes) */
    for( ulong i = 0; i < notar_slot->block_ids_cnt; i++ ) {
      fd_notar_blk_t * notar_blk = fd_notar_blk_query( ctx->notar->blk_map, notar_slot->block_ids[i], NULL );
      FD_TEST( notar_blk ); /* block_ids_cnt corrupt */
      if( FD_LIKELY( notar_blk->dup_conf ) ) {
        fork->confirmed          = 1;
        fork->confirmed_block_id = notar_blk->block_id;
        break;
      }
    }
  }

  /* We replayed an unconfirmed duplicate, warn for now.  Follow-up PR
     will implement eviction and repair of the correct one. */

  if( FD_UNLIKELY( fork->confirmed && 0!=memcmp( &fork->confirmed_block_id, &fork->replayed_block_id, sizeof(fd_hash_t) ) ) ) {
    FD_BASE58_ENCODE_32_BYTES( slot_completed->block_id.key, block_id_b58 );
    FD_BASE58_ENCODE_32_BYTES( fork->confirmed_block_id.key, confirmed_block_id_b58 );
    FD_LOG_WARNING(( "replayed an unconfirmed duplicate %lu. ours %s. confirmed %s.", slot_completed->slot, block_id_b58, confirmed_block_id_b58 ));
  }

  /* Determine reset, vote, and root slots.  There may not be a vote or
     root slot but there is always a reset slot. */

  fd_tower_out_t out = fd_tower_vote_and_reset( ctx->tower, ctx->tower_accts, ctx->slot_stakes, ctx->forks, ctx->ghost, ctx->notar );

  /* Write out metrics for vote / reset reasons. */

  ctx->metrics.ancestor_rollback += (ulong)fd_uchar_extract_bit( out.flags, FD_TOWER_FLAG_ANCESTOR_ROLLBACK );
  ctx->metrics.sibling_confirmed += (ulong)fd_uchar_extract_bit( out.flags, FD_TOWER_FLAG_SIBLING_CONFIRMED );
  ctx->metrics.same_fork         += (ulong)fd_uchar_extract_bit( out.flags, FD_TOWER_FLAG_SAME_FORK         );
  ctx->metrics.switch_pass       += (ulong)fd_uchar_extract_bit( out.flags, FD_TOWER_FLAG_SWITCH_PASS       );
  ctx->metrics.switch_fail       += (ulong)fd_uchar_extract_bit( out.flags, FD_TOWER_FLAG_SWITCH_FAIL       );
  ctx->metrics.lockout_fail      += (ulong)fd_uchar_extract_bit( out.flags, FD_TOWER_FLAG_LOCKOUT_FAIL      );
  ctx->metrics.threshold_fail    += (ulong)fd_uchar_extract_bit( out.flags, FD_TOWER_FLAG_THRESHOLD_FAIL    );
  ctx->metrics.propagated_fail   += (ulong)fd_uchar_extract_bit( out.flags, FD_TOWER_FLAG_PROPAGATED_FAIL   );

  /* Update forks if there is a vote slot. */

  if( FD_LIKELY( out.vote_slot!=ULONG_MAX ) ) {
    fd_tower_forks_t * fork = fd_forks_query( ctx->forks, out.vote_slot );
    FD_TEST( fork ); /* we must have replayed every slot we voted for */
    fd_forks_voted( fork, &out.vote_block_id );
  }

  /* Publish according structures if there is a root */

  if( FD_UNLIKELY( out.root_slot!=ULONG_MAX ) ) {

    if( FD_UNLIKELY( 0==memcmp( &out.root_block_id, &hash_null, sizeof(fd_hash_t) ) ) ) {
      FD_LOG_CRIT(( "invariant violation: root block id is null at slot %lu", out.root_slot ));
    }

    /* forks */

    for(ulong slot = ctx->root_slot; slot < out.root_slot; slot++ ) {
      fd_tower_forks_t * fork = fd_forks_query ( ctx->forks, slot );
      if( FD_LIKELY( fork ) )   fd_forks_remove( ctx->forks, slot );
      fd_epoch_stakes_slot_t * slot_stakes = fd_epoch_stakes_slot_map_query    ( ctx->slot_stakes->slot_stakes_map, slot, NULL );
      if( FD_LIKELY( slot_stakes ) )         fd_epoch_stakes_slot_stakes_remove( ctx->slot_stakes, slot_stakes );
    }

    /* ghost */

    fd_ghost_blk_t * newr = fd_ghost_query( ctx->ghost, &out.root_block_id );
    if( FD_UNLIKELY( !newr ) ) { /* a block id we rooted is missing from ghost */
      FD_BASE58_ENCODE_32_BYTES( out.root_block_id.uc, block_id_cstr );
      FD_LOG_CRIT(( "missing root block id %s at slot %lu", block_id_cstr, out.root_slot ));
    }
    fd_ghost_publish( ctx->ghost, newr );

    /* notar */

    fd_notar_advance_wmark( ctx->notar, out.root_slot );

    /* Rooting implies optimistic confirmation in the Firedancer API, so
       we need to make sure to publish the optimistic frags before the
       rooted frags.  In most cases this is a no-op because gossip votes
       already triggered optimistic confirmation.

       TODO include replay votes in optimistic conf vote counting. */

    contiguous_confirm( ctx, out.root_slot, ctx->conf_slot, FD_TOWER_SLOT_CONFIRMED_OPTIMISTIC );
    contiguous_confirm( ctx, out.root_slot, ctx->root_slot, FD_TOWER_SLOT_CONFIRMED_ROOTED     );

    /* Update slot watermarks. */

    ctx->root_slot = out.root_slot;
  }

  /* Publish a slot_done frag to tower_out. */

  fd_tower_slot_done_t * msg = fd_chunk_to_laddr( ctx->out_mem, ctx->out_chunk );
  msg->replay_slot           = slot_completed->slot;
  msg->active_fork_cnt       = fd_tower_leaves_pool_used( ctx->forks->tower_leaves_pool );
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

  fd_lockout_offset_t lockouts[FD_TOWER_VOTE_MAX];
  fd_txn_p_t          txn[1];
  fd_tower_to_vote_txn( ctx->tower, ctx->root_slot, lockouts, &slot_completed->bank_hash, &slot_completed->block_hash, ctx->identity_key, ctx->identity_key, ctx->vote_account, txn );
  FD_TEST( !fd_tower_empty( ctx->tower ) );
  FD_TEST( txn->payload_sz && txn->payload_sz<=FD_TPU_MTU );
  fd_memcpy( msg->vote_txn, txn->payload, txn->payload_sz );
  msg->vote_txn_sz = txn->payload_sz;

  msg->tower_cnt = 0UL;
  if( FD_LIKELY( found ) ) msg->tower_cnt = fd_tower_with_lat_from_vote_acc( msg->tower, ctx->our_vote_acct );

  fd_stem_publish( stem, 0UL, FD_TOWER_SIG_SLOT_DONE, ctx->out_chunk, sizeof(fd_tower_slot_done_t), 0UL, tsorig, fd_frag_meta_ts_comp( fd_tickcount() ) );
  ctx->out_chunk = fd_dcache_compact_next( ctx->out_chunk, sizeof(fd_tower_slot_done_t), ctx->out_chunk0, ctx->out_wmark );

# if LOGGING
  fd_ghost_print( ctx->ghost, fd_ghost_root( ctx->ghost ) );
  fd_tower_print( ctx->tower, fd_ghost_root( ctx->ghost )->slot );
# endif
}

static inline void
after_credit( ctx_t *             ctx,
              fd_stem_context_t * stem,
              int *               opt_poll_in FD_PARAM_UNUSED,
              int *               charge_busy ) {
  if( FD_LIKELY( !notif_empty( ctx->notif ) ) ) {

    /* Contiguous confirmations are pushed to tail in order from child
       to ancestor, so we pop from tail to publish confirmations in
       order from ancestor to child.  */

    notif_t ancestor = notif_pop_tail( ctx->notif );
    if( FD_UNLIKELY( ancestor.kind == FD_TOWER_SLOT_CONFIRMED_CLUSTER || ancestor.kind == FD_TOWER_SLOT_CONFIRMED_DUPLICATE ) ) {

      /* Duplicate confirmations and cluster confirmations were sourced
         from notar (through gossip txns and replay txns) so we need to
         use the block_id from the notif recorded at the time of the
         confirmation */

      publish_slot_confirmed( ctx, stem, fd_frag_meta_ts_comp( fd_tickcount() ), ancestor.slot, &ancestor.block_id, ULONG_MAX, ancestor.kind );
    } else {
      fd_tower_forks_t * fork = fd_tower_forks_query( ctx->forks->tower_forks, ancestor.slot, NULL );
      if( FD_UNLIKELY( !fork ) ) FD_LOG_CRIT(( "missing fork for ancestor %lu", ancestor.slot ));
      publish_slot_confirmed( ctx, stem, fd_frag_meta_ts_comp( fd_tickcount() ), ancestor.slot, fd_forks_canonical_block_id( ctx->forks, ancestor.slot ), fork->bank_idx, ancestor.kind );
    }
    *opt_poll_in = 0; /* drain the confirmations */
    *charge_busy = 1;
  }
}

static inline int
returnable_frag( ctx_t *             ctx,
                 ulong               in_idx,
                 ulong               seq FD_PARAM_UNUSED,
                 ulong               sig,
                 ulong               chunk,
                 ulong               sz,
                 ulong               ctl FD_PARAM_UNUSED,
                 ulong               tsorig,
                 ulong               tspub FD_PARAM_UNUSED,
                 fd_stem_context_t * stem ) {

  if( FD_UNLIKELY( chunk<ctx->in[ in_idx ].chunk0 || chunk>ctx->in[ in_idx ].wmark || sz>ctx->in[ in_idx ].mtu ) )
    FD_LOG_ERR(( "chunk %lu %lu from in %d corrupt, not in range [%lu,%lu]", chunk, sz, ctx->in_kind[ in_idx ], ctx->in[ in_idx ].chunk0, ctx->in[ in_idx ].wmark ));

  switch( ctx->in_kind[ in_idx ] ) {
  case IN_KIND_DEDUP: {
    if( FD_UNLIKELY( ctx->root_slot==ULONG_MAX ) ) return 1;
    fd_txn_m_t * txnm = (fd_txn_m_t *)fd_chunk_to_laddr( ctx->in[in_idx].mem, chunk );
    FD_TEST( txnm->payload_sz<=FD_TPU_MTU );
    FD_TEST( txnm->txn_t_sz<=FD_TXN_MAX_SZ );
    count_vote_txn( ctx, fd_txn_m_txn_t_const( txnm ), fd_txn_m_payload_const( txnm ) );
    return 0;
  }
  case IN_KIND_EXEC: {
    if( FD_LIKELY( (sig>>32)==FD_EXEC_TT_TXN_EXEC ) ) {
      fd_exec_txn_exec_msg_t * msg = fd_chunk_to_laddr( ctx->in[in_idx].mem, chunk );
      count_vote_txn( ctx, TXN(&msg->txn), msg->txn.payload );
    }
    return 0;
  }
  case IN_KIND_REPLAY: {
    if( FD_LIKELY( sig==REPLAY_SIG_SLOT_COMPLETED ) ) {
      fd_memcpy( &ctx->replay_slot_completed, fd_chunk_to_laddr( ctx->in[ in_idx ].mem, chunk ), sizeof(fd_replay_slot_completed_t) );
      replay_slot_completed( ctx, &ctx->replay_slot_completed, tsorig, stem );
    } else if ( FD_LIKELY( sig==REPLAY_SIG_SLOT_DEAD ) ) {
      fd_replay_slot_dead_t * slot_dead = (fd_replay_slot_dead_t *)fd_chunk_to_laddr( ctx->in[ in_idx ].mem, chunk );
      fd_hfork_record_our_bank_hash( ctx->hfork, &slot_dead->block_id, NULL, fd_ghost_root( ctx->ghost )->total_stake );
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
  ctx_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof(ctx_t), sizeof(ctx_t) );
  FD_SCRATCH_ALLOC_FINI( l, scratch_align() );

  FD_TEST( fd_rng_secure( &ctx->seed, sizeof(ctx->seed) ) );

  if( FD_UNLIKELY( !strcmp( tile->tower.identity_key, "" ) ) ) FD_LOG_ERR(( "identity_key_path not set" ));
  ctx->identity_key[ 0 ] = *(fd_pubkey_t const *)fd_type_pun_const( fd_keyload_load( tile->tower.identity_key, /* pubkey only: */ 1 ) );

  /* The vote key can be specified either directly as a base58 encoded
     pubkey, or as a file path.  We first try to decode as a pubkey. */

  uchar * vote_key = fd_base58_decode_32( tile->tower.vote_account, ctx->vote_account->uc );
  if( FD_UNLIKELY( !vote_key ) ) ctx->vote_account[ 0 ] = *(fd_pubkey_t const *)fd_type_pun_const( fd_keyload_load( tile->tower.vote_account, /* pubkey only: */ 1 ) );

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
  ulong  slot_max     = tile->tower.max_live_slots;
  void * scratch      = fd_topo_obj_laddr( topo, tile->tile_obj_id );
  FD_SCRATCH_ALLOC_INIT( l, scratch );
  ctx_t * ctx   = FD_SCRATCH_ALLOC_APPEND( l, alignof(ctx_t),           sizeof(ctx_t)                                        );
  void  * ghost = FD_SCRATCH_ALLOC_APPEND( l, fd_ghost_align(),         fd_ghost_footprint( 2*slot_max, FD_VOTER_MAX )       );
  void  * hfork = FD_SCRATCH_ALLOC_APPEND( l, fd_hfork_align(),         fd_hfork_footprint( slot_max, FD_VOTER_MAX )         );
  void  * notar = FD_SCRATCH_ALLOC_APPEND( l, fd_notar_align(),         fd_notar_footprint( tile->tower.max_vote_lookahead ) );
  void  * tower = FD_SCRATCH_ALLOC_APPEND( l, fd_tower_align(),         fd_tower_footprint()                                 );
  void  * accts = FD_SCRATCH_ALLOC_APPEND( l, fd_tower_accts_align(),   fd_tower_accts_footprint( FD_VOTER_MAX )             );
  void  * forks = FD_SCRATCH_ALLOC_APPEND( l, fd_forks_align(),         fd_forks_footprint( slot_max, FD_VOTER_MAX )         );
  void  * spare = FD_SCRATCH_ALLOC_APPEND( l, fd_tower_align(),         fd_tower_footprint()                                 );
  void  * stake = FD_SCRATCH_ALLOC_APPEND( l, fd_epoch_stakes_align(),  fd_epoch_stakes_footprint( slot_max )                 );
  void  * notif = FD_SCRATCH_ALLOC_APPEND( l, notif_align(),            notif_footprint( slot_max )                          );
  FD_SCRATCH_ALLOC_FINI( l, scratch_align() );

  ctx->wksp        = topo->workspaces[ topo->objs[ tile->tile_obj_id ].wksp_id ].wksp;
  ctx->ghost       = fd_ghost_join       ( fd_ghost_new       ( ghost, 2*slot_max, FD_VOTER_MAX, 42UL ) ); /* FIXME seed */
  ctx->hfork       = fd_hfork_join       ( fd_hfork_new       ( hfork, slot_max, FD_VOTER_MAX, ctx->seed, tile->tower.hard_fork_fatal ) );
  ctx->notar       = fd_notar_join       ( fd_notar_new       ( notar, tile->tower.max_vote_lookahead ) );
  ctx->tower       = fd_tower_join       ( fd_tower_new       ( tower                                 ) );
  ctx->tower_accts = fd_tower_accts_join ( fd_tower_accts_new ( accts, FD_VOTER_MAX                   ) );
  ctx->forks       = fd_forks_join       ( fd_forks_new       ( forks, slot_max, FD_VOTER_MAX         ) );
  ctx->tower_spare = fd_tower_join       ( fd_tower_new       ( spare                                 ) );
  ctx->slot_stakes = fd_epoch_stakes_join( fd_epoch_stakes_new( stake, slot_max                       ) );
  ctx->notif       = notif_join          ( notif_new          ( notif, slot_max                       ) );
  FD_TEST( ctx->ghost );
  FD_TEST( ctx->hfork );
  FD_TEST( ctx->notar );
  FD_TEST( ctx->tower );
  FD_TEST( ctx->forks );
  FD_TEST( ctx->tower_spare );
  FD_TEST( ctx->tower_accts );
  FD_TEST( ctx->slot_stakes );
  FD_TEST( ctx->notif );

  for( ulong i = 0; i<VOTE_TXN_SIG_MAX; i++ ) {
    fd_sha512_t * sha = fd_sha512_join( fd_sha512_new( FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_sha512_t), sizeof(fd_sha512_t) ) ) );
    FD_TEST( sha );
    ctx->vote_sha[i] = sha;
  }

  ctx->init_slot = ULONG_MAX;
  ctx->root_slot = ULONG_MAX;
  ctx->conf_slot = ULONG_MAX;

  memset( &ctx->metrics, 0, sizeof( struct ctx_metrics_t ) );

  ulong banks_obj_id = fd_pod_query_ulong( topo->props, "banks", ULONG_MAX );
  FD_TEST( banks_obj_id!=ULONG_MAX );
  ulong banks_locks_obj_id = fd_pod_query_ulong( topo->props, "banks_locks", ULONG_MAX );
  FD_TEST( banks_locks_obj_id!=ULONG_MAX );
  FD_TEST( fd_banks_join( ctx->banks, fd_topo_obj_laddr( topo, banks_obj_id ), fd_topo_obj_laddr( topo, banks_locks_obj_id ) ) );

  ulong funk_obj_id = fd_pod_query_ulong( topo->props, "funk", ULONG_MAX );
  FD_TEST( funk_obj_id!=ULONG_MAX );
  FD_TEST( fd_accdb_user_v1_init( ctx->accdb, fd_topo_obj_laddr( topo, funk_obj_id ) ) );

  FD_TEST( tile->in_cnt<sizeof(ctx->in_kind)/sizeof(ctx->in_kind[0]) );
  for( ulong i=0UL; i<tile->in_cnt; i++ ) {
    fd_topo_link_t * link = &topo->links[ tile->in_link_id[ i ] ];
    fd_topo_wksp_t * link_wksp = &topo->workspaces[ topo->objs[ link->dcache_obj_id ].wksp_id ];

    if     ( FD_LIKELY( !strcmp( link->name, "dedup_resolv" ) ) ) ctx->in_kind[ i ] = IN_KIND_DEDUP;
    else if( FD_LIKELY( !strcmp( link->name, "replay_exec"  ) ) ) ctx->in_kind[ i ] = IN_KIND_EXEC;
    else if( FD_LIKELY( !strcmp( link->name, "replay_out"   ) ) ) ctx->in_kind[ i ] = IN_KIND_REPLAY;
    else     FD_LOG_ERR(( "tower tile has unexpected input link %lu %s", i, link->name ));

    ctx->in[ i ].mem    = link_wksp->wksp;
    ctx->in[ i ].mtu    = link->mtu;
    ctx->in[ i ].chunk0 = fd_dcache_compact_chunk0( ctx->in[ i ].mem, link->dcache );
    ctx->in[ i ].wmark  = fd_dcache_compact_wmark ( ctx->in[ i ].mem, link->dcache, link->mtu );
  }

  ctx->out_mem    = topo->workspaces[ topo->objs[ topo->links[ tile->out_link_id[ 0 ] ].dcache_obj_id ].wksp_id ].wksp;
  ctx->out_chunk0 = fd_dcache_compact_chunk0( ctx->out_mem, topo->links[ tile->out_link_id[ 0 ] ].dcache );
  ctx->out_wmark  = fd_dcache_compact_wmark ( ctx->out_mem, topo->links[ tile->out_link_id[ 0 ] ].dcache, topo->links[ tile->out_link_id[ 0 ] ].mtu );
  ctx->out_chunk  = ctx->out_chunk0;
}

static ulong
populate_allowed_seccomp( fd_topo_t const *      topo,
                          fd_topo_tile_t const * tile,
                          ulong                  out_cnt,
                          struct sock_filter *   out ) {
  void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );
  FD_SCRATCH_ALLOC_INIT( l, scratch );
  ctx_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof(ctx_t), sizeof(ctx_t) );

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
  ctx_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof(ctx_t), sizeof(ctx_t) );

  if( FD_UNLIKELY( out_fds_cnt<4UL ) ) FD_LOG_ERR(( "out_fds_cnt %lu", out_fds_cnt ));

  ulong out_cnt = 0UL;
  out_fds[ out_cnt++ ] = 2; /* stderr */
  if( FD_LIKELY( -1!=fd_log_private_logfile_fd() ) )
    out_fds[ out_cnt++ ] = fd_log_private_logfile_fd(); /* logfile */
  if( FD_LIKELY( ctx->checkpt_fd!=-1 ) ) out_fds[ out_cnt++ ] = ctx->checkpt_fd;
  if( FD_LIKELY( ctx->restore_fd!=-1 ) ) out_fds[ out_cnt++ ] = ctx->restore_fd;
  return out_cnt;
}

#define STEM_BURST (2UL) /* slot_conf AND (slot_done OR slot_ignored) */
/* See explanation in fd_pack */
#define STEM_LAZY  (128L*3000L)

#define STEM_CALLBACK_CONTEXT_TYPE    ctx_t
#define STEM_CALLBACK_CONTEXT_ALIGN   alignof(ctx_t)
#define STEM_CALLBACK_METRICS_WRITE   metrics_write
#define STEM_CALLBACK_AFTER_CREDIT    after_credit
#define STEM_CALLBACK_RETURNABLE_FRAG returnable_frag

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
