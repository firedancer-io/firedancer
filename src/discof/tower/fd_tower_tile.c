#include "fd_tower_tile.h"
#include "generated/fd_tower_tile_seccomp.h"

#include "../genesis/fd_genesi_tile.h"
#include "../../choreo/ghost/fd_ghost.h"
#include "../../choreo/notar/fd_notar.h"
#include "../../choreo/tower/fd_tower.h"
#include "../../choreo/tower/fd_tower_accts.h"
#include "../../choreo/tower/fd_tower_forks.h"
#include "../../choreo/tower/fd_tower_serde.h"
#include "../../disco/keyguard/fd_keyload.h"
#include "../../disco/metrics/fd_metrics.h"
#include "../../disco/topo/fd_topo.h"
#include "../../disco/fd_txn_m.h"
#include "../../discof/restore/utils/fd_ssmsg.h"
#include "../../discof/replay/fd_replay_tile.h"
#include "../../flamenco/fd_flamenco_base.h"
#include "../../flamenco/gossip/fd_gossip_types.h"

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

#define IN_KIND_GENESIS (0)
#define IN_KIND_GOSSIP  (1)
#define IN_KIND_REPLAY  (2)
#define IN_KIND_SNAP    (3)

#define VOTE_TXN_SIG_MAX (2UL) /* validator identity and vote authority */

#define DEQUE_NAME slots
#define DEQUE_T    ulong
#include "../../util/tmpl/fd_deque_dynamic.c"

static const fd_hash_t manifest_block_id = { .ul = { 0xf17eda2ce7b1d } }; /* FIXME manifest_block_id */

typedef struct {
  fd_wksp_t * mem;
  ulong       chunk0;
  ulong       wmark;
  ulong       mtu;
} in_ctx_t;

typedef struct {
  ulong       seed;  /* map seed */
  fd_pubkey_t identity_key[1];
  fd_pubkey_t vote_account[1];
  int         checkpt_fd;
  int         restore_fd;

  /* structures owned by tower tile */

  fd_ghost_t *       ghost;
  fd_notar_t *       notar;
  fd_tower_t *       tower;
  fd_tower_accts_t * tower_accts;
  fd_tower_forks_t * tower_forks;
  fd_tower_t *       tower_spare; /* spare tower used during processing */
  ulong *            slots;       /* deque of slot number for internal processing */

  /* frag-related structures (consume and publish) */

  uchar                         gossip_vote_txn[FD_TPU_PARSED_MTU];
  fd_sha512_t *                 gossip_vote_sha[VOTE_TXN_SIG_MAX];
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

  struct {
    ulong ancestor_rollback;
    ulong sibling_confirmed;
    ulong same_fork;
    ulong switch_pass;
    ulong switch_fail;
    ulong lockout_fail;
    ulong threshold_fail;
    ulong propagated_fail;
  } metrics;
} ctx_t;

FD_FN_CONST static inline ulong
scratch_align( void ) {
  return 128UL;
}

FD_FN_PURE static inline ulong
scratch_footprint( FD_PARAM_UNUSED fd_topo_tile_t const * tile ) {
  ulong slot_max    = tile->tower.slot_max;
  int   lg_slot_max = fd_ulong_find_msb( fd_ulong_pow2_up( slot_max ) ) + 1;
  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, alignof(ctx_t),         sizeof(ctx_t)                                  );
  l = FD_LAYOUT_APPEND( l, fd_ghost_align(),       fd_ghost_footprint( 2*slot_max, FD_VOTER_MAX ) );
  l = FD_LAYOUT_APPEND( l, fd_notar_align(),       fd_notar_footprint( slot_max )                 );
  l = FD_LAYOUT_APPEND( l, fd_tower_align(),       fd_tower_footprint()                           );
  l = FD_LAYOUT_APPEND( l, fd_tower_accts_align(), fd_tower_accts_footprint( FD_VOTER_MAX )       );
  l = FD_LAYOUT_APPEND( l, fd_tower_forks_align(), fd_tower_forks_footprint( lg_slot_max )        );
  l = FD_LAYOUT_APPEND( l, fd_tower_align(),       fd_tower_footprint()                           );
  l = FD_LAYOUT_APPEND( l, slots_align(),          slots_footprint( slot_max )                    );
  return FD_LAYOUT_FINI( l, scratch_align() );
}

static inline void
metrics_write( ctx_t * ctx ) {
  FD_MCNT_SET( TOWER, ANCESTOR_ROLLBACK, ctx->metrics.ancestor_rollback );
  FD_MCNT_SET( TOWER, SIBLING_CONFIRMED, ctx->metrics.sibling_confirmed );
  FD_MCNT_SET( TOWER, SAME_FORK,         ctx->metrics.same_fork         );
  FD_MCNT_SET( TOWER, SWITCH_PASS,       ctx->metrics.switch_pass       );
  FD_MCNT_SET( TOWER, SWITCH_FAIL,       ctx->metrics.switch_fail       );
  FD_MCNT_SET( TOWER, LOCKOUT_FAIL,      ctx->metrics.lockout_fail      );
  FD_MCNT_SET( TOWER, THRESHOLD_FAIL,    ctx->metrics.threshold_fail    );
  FD_MCNT_SET( TOWER, PROPAGATED_FAIL,   ctx->metrics.propagated_fail   );
}

static void
publish_slot_confirmed( ctx_t *             ctx,
                        fd_stem_context_t * stem,
                        ulong               tsorig,
                        ulong               slot,
                        fd_hash_t const *   block_id,
                        int                 kind ) {
  fd_tower_slot_confirmed_t * msg = fd_chunk_to_laddr( ctx->out_mem, ctx->out_chunk );
  msg->slot                       = slot;
  msg->block_id                   = *block_id;
  msg->kind                       = kind;
  fd_stem_publish( stem, 0UL, FD_TOWER_SIG_SLOT_CONFIRMED, ctx->out_chunk, sizeof(fd_tower_slot_confirmed_t), 0UL, tsorig, fd_frag_meta_ts_comp( fd_tickcount() ) );
  ctx->out_chunk = fd_dcache_compact_next( ctx->out_chunk, sizeof(fd_tower_slot_confirmed_t), ctx->out_chunk0, ctx->out_wmark );
}

static void
contiguous_confirm( ctx_t *             ctx,
                    fd_stem_context_t * stem,
                    ulong               tsorig,
                    ulong               slot,
                    ulong               wmark,
                    int                 kind ) {

  /* For optimistic and rooted confirmations, confirming a slot means
     all ancestors are confirmed too, so we need to publish any skipped
     ancestors (confirmations can be out-of-order and roots can be
     skipped due to lockout). */

  ulong ancestor = slot;
  while( FD_UNLIKELY( ancestor > wmark ) ) {
    fd_tower_forks_t * fork = fd_tower_forks_query( ctx->tower_forks, ancestor, NULL );
    if( FD_UNLIKELY( !fork ) ) break; /* rooted past this ancestor */
    slots_push_tail( ctx->slots, ancestor );
    ancestor = fork->parent_slot;
  }
  while( FD_LIKELY( !slots_empty( ctx->slots ) ) ) {
    ulong             ancestor = slots_pop_tail( ctx->slots );
    fd_hash_t const * block_id = fd_tower_forks_canonical_block_id( ctx->tower_forks, ancestor );
    if( FD_UNLIKELY( !block_id ) ) FD_LOG_CRIT(( "missing block id for ancestor %lu", ancestor ));
    publish_slot_confirmed( ctx, stem, tsorig, ancestor, block_id, kind );
  }
}

static void
notar_confirm( ctx_t *             ctx,
               fd_stem_context_t * stem,
               ulong               tsorig,
               fd_notar_blk_t *    notar_blk ) {

  /* Record any confirmations in our tower forks structure and also
     publish slot_confirmed frags indicating confirmations to consumers.

     See documentation in fd_tower_tile.h for guarantees. */

  if( FD_LIKELY( notar_blk->dup_conf ) ) {
    fd_tower_forks_t * fork = fd_tower_forks_query( ctx->tower_forks, notar_blk->slot, NULL ); /* ensure fork exists */
    if( FD_UNLIKELY( !fork           ) ) return; /* a slot may be already duplicate confirmed over gossip votes before replay */
    if( FD_LIKELY  ( fork->confirmed ) ) return; /* already published confirmed frag */
    fork->confirmed          = 1;
    fork->confirmed_block_id = notar_blk->block_id;
    publish_slot_confirmed( ctx, stem, tsorig, notar_blk->slot, &notar_blk->block_id, FD_TOWER_SLOT_CONFIRMED_DUPLICATE );
  }
  if( FD_LIKELY( notar_blk->opt_conf ) ) {
    publish_slot_confirmed( ctx, stem, tsorig, notar_blk->slot, &notar_blk->block_id, FD_TOWER_SLOT_CONFIRMED_CLUSTER );
    fd_tower_forks_t * fork = fd_tower_forks_query( ctx->tower_forks, notar_blk->slot, NULL );
    if( FD_UNLIKELY( fork && fork->replayed && notar_blk->slot > ctx->conf_slot ) ) {
      contiguous_confirm( ctx, stem, tsorig, notar_blk->slot, ctx->conf_slot, FD_TOWER_SLOT_CONFIRMED_OPTIMISTIC );
      ctx->conf_slot = notar_blk->slot;
    }
  }
}

static void
gossip_vote( ctx_t *                  ctx,
             fd_gossip_vote_t const * vote,
             ulong                    tsorig,
             fd_stem_context_t *      stem ) {

  /* Parse the gossip vote txn and check it's a vote txn. */

  uchar const * payload    = vote->txn;
  ulong         payload_sz = vote->txn_sz;
  ulong         sz         = fd_txn_parse_core( vote->txn, vote->txn_sz, ctx->gossip_vote_txn, NULL, NULL );
  if( FD_UNLIKELY( sz==0 ) ) return;
  fd_txn_t * txn = (fd_txn_t *)ctx->gossip_vote_txn;
  if( FD_UNLIKELY( !fd_txn_is_simple_vote_transaction( txn, vote->txn ) ) ) return; /* TODO Agave doesn't have the same validation of <=2 signatures */

  /* Filter any non-tower sync votes. */

  fd_txn_instr_t * instr      = &txn->instr[0];
  uchar const *    instr_data = vote->txn + instr->data_off;
  uint             kind       = fd_uint_load_4_fast( instr_data );
  if( FD_UNLIKELY( kind != FD_VOTE_IX_KIND_TOWER_SYNC && kind != FD_VOTE_IX_KIND_TOWER_SYNC_SWITCH ) ) return;

  /* Sigverify the vote txn. */

  uchar const * msg    = payload + txn->message_off;
  ulong         msg_sz = (ulong)payload_sz - txn->message_off;
  uchar const * sigs   = payload + txn->signature_off;
  uchar const * accts  = payload + txn->acct_addr_off;
  if( FD_UNLIKELY( txn->signature_cnt == 0 ) ) return;
  int err = fd_ed25519_verify_batch_single_msg( msg, msg_sz, sigs, accts, ctx->gossip_vote_sha, txn->signature_cnt );
  if( FD_UNLIKELY( err != FD_ED25519_SUCCESS ) ) return;

  /* Deserialize the CompactTowerSync. */

  err = fd_compact_tower_sync_deserialize( &ctx->compact_tower_sync_serde, instr_data + sizeof(uint), instr->data_sz - sizeof(uint) ); /* FIXME validate */
  if( FD_UNLIKELY( err == -1 ) ) return;
  ulong slot = ctx->compact_tower_sync_serde.root;
  fd_tower_remove_all( ctx->tower_spare );
  for( ulong i = 0; i < ctx->compact_tower_sync_serde.lockouts_cnt; i++ ) {
    slot += ctx->compact_tower_sync_serde.lockouts[i].offset;
    fd_tower_push_tail( ctx->tower_spare, (fd_tower_vote_t){ .slot = slot, .conf = ctx->compact_tower_sync_serde.lockouts[i].confirmation_count } );
  }
  if( FD_UNLIKELY( 0==memcmp( &ctx->compact_tower_sync_serde.block_id, &hash_null, sizeof(fd_hash_t) ) ) ) return;

  fd_pubkey_t const * addrs = (fd_pubkey_t const *)fd_type_pun_const( accts );
  fd_pubkey_t const * addr  = NULL;
  if( FD_UNLIKELY( txn->signature_cnt==1 ) ) addr = (fd_pubkey_t const *)fd_type_pun_const( &addrs[1] ); /* identity and authority same, account idx 1 is the vote account address */
  else                                       addr = (fd_pubkey_t const *)fd_type_pun_const( &addrs[2] ); /* identity and authority diff, account idx 2 is the vote account address */

  /* Return early if their tower is empty. */

  if( FD_UNLIKELY( fd_tower_empty( ctx->tower_spare ) ) ) return;

  /* The vote txn contains a block id and bank hash for their last vote
     slot in the tower.  Agave always counts the last vote.

     https://github.com/anza-xyz/agave/blob/v2.3.7/core/src/cluster_info_vote_listener.rs#L476-L487 */

  fd_tower_vote_t const * their_last_vote = fd_tower_peek_tail_const( ctx->tower_spare );
  fd_hash_t const *       their_block_id  = &ctx->compact_tower_sync_serde.block_id;

  ulong            total_stake = fd_ghost_root( ctx->ghost )->total_stake;
  fd_notar_blk_t * notar_blk   = fd_notar_count_vote( ctx->notar, total_stake, addr, their_last_vote->slot, their_block_id );
  if( FD_LIKELY( notar_blk ) ) notar_confirm( ctx, stem, tsorig, notar_blk );

  fd_hash_t const * our_block_id = fd_tower_forks_canonical_block_id( ctx->tower_forks, their_last_vote->slot );
  if( FD_UNLIKELY( !our_block_id || 0!=memcmp( our_block_id, their_block_id, sizeof(fd_hash_t) ) ) ) return;

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

    fd_hash_t const * our_block_id = fd_tower_forks_canonical_block_id( ctx->tower_forks, their_intermediate_vote->slot );
    if( FD_UNLIKELY( !our_block_id ) ) continue;

    /* Otherwise, we count the vote using our own block id for that slot
       (again, mirroring what Agave does albeit with bank hashes).

       Agave uses the current root bank's total stake when counting
       vote txns from gossip / replay:

       https://github.com/anza-xyz/agave/blob/v2.3.7/core/src/cluster_info_vote_listener.rs#L500 */


    fd_notar_blk_t * notar_blk = fd_notar_count_vote( ctx->notar, total_stake, addr, their_last_vote->slot, their_block_id );
    if( FD_LIKELY( notar_blk ) ) notar_confirm( ctx, stem, tsorig, notar_blk );
  }
}

static void
replay_slot_completed( ctx_t *                      ctx,
                       fd_replay_slot_completed_t * slot_info,
                       ulong                        tsorig,
                       fd_stem_context_t *          stem ) {

  /* fd_notar requires some bookkeeping when there is a new epoch. */

  if( FD_UNLIKELY( ctx->notar->epoch==ULONG_MAX || slot_info->epoch > ctx->notar->epoch ) ) {
    fd_notar_advance_epoch( ctx->notar, ctx->tower_accts, slot_info->epoch );
  }

  /* Insert the just replayed block into ghost. */

  fd_hash_t const * parent_block_id = &slot_info->parent_block_id;
  if( FD_UNLIKELY( slot_info->parent_slot==ctx->init_slot ) ) parent_block_id = &manifest_block_id;
  fd_ghost_blk_t * ghost_blk = fd_ghost_insert( ctx->ghost, &slot_info->block_id, parent_block_id, slot_info->slot );

  /* Insert the just replayed block into tower forks. */

  FD_TEST( !fd_tower_forks_query( ctx->tower_forks, slot_info->slot, NULL ) );
  fd_tower_forks_t * fork = fd_tower_forks_insert( ctx->tower_forks, slot_info->slot );

  /* Check if gossip votes already confirmed a block id (via notar). */

  fork->confirmed              = 0;
  fd_notar_slot_t * notar_slot = fd_notar_slot_query( ctx->notar->slot_map, slot_info->slot, NULL );
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

  /* Record the replayed block id. */

  fork->replayed          = 1;
  fork->replayed_block_id = slot_info->block_id;
  fork->parent_slot       = slot_info->parent_slot;

  /* We replayed an unconfirmed duplicate, warn for now.  Follow-up PR
     will implement eviction and repair of the correct one. */

  if( FD_UNLIKELY( fork->confirmed && 0!=memcmp( &fork->confirmed_block_id, &fork->replayed_block_id, sizeof(fd_hash_t) ) ) ) {
    FD_LOG_WARNING(( "replayed an unconfirmed duplicate %lu. ours %s. confirmed %s.", slot_info->slot, FD_BASE58_ENC_32_ALLOCA( &slot_info->block_id ), FD_BASE58_ENC_32_ALLOCA( &fork->confirmed_block_id ) ));
  }

  /* Iterate all the vote accounts to count votes towards fork choice
     (fd_ghost) and confirmation (fd_notar) and also reconcile our local
     tower with our on-chain one (fd_tower_reconcile).

     TODO replace with direct funk query */

  ulong total_stake = 0;
  for( fd_tower_accts_iter_t iter = fd_tower_accts_iter_init( ctx->tower_accts       );
                                   !fd_tower_accts_iter_done( ctx->tower_accts, iter );
                             iter = fd_tower_accts_iter_next( ctx->tower_accts, iter ) ) {
    fd_tower_accts_t const * acct = fd_tower_accts_iter_ele( ctx->tower_accts, iter );

    total_stake += acct->stake;

    /* If this is our vote acc, reconcile with our local tower. */

    if( FD_UNLIKELY( 0==memcmp( &acct->addr, ctx->vote_account, sizeof(fd_pubkey_t) ) ) ) fd_tower_reconcile( ctx->tower, ctx->root_slot, acct->data );

    /* Deserialize the last vote slot from this vote account's tower. */

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

    if( FD_UNLIKELY( !ancestor_blk ) ) FD_LOG_CRIT(( "missing ancestor. replay slot %lu vote slot %lu voter %s", slot_info->slot, vote_slot, FD_BASE58_ENC_32_ALLOCA( &acct->addr ) ));

    /* Count the vote toward ghost, notar and total_stake. */

    fd_ghost_count_vote( ctx->ghost, ancestor_blk, &acct->addr, acct->stake, vote_slot );

    /* TODO count TPU vote txns towards notar */
  }
  if( FD_UNLIKELY( fd_ghost_root( ctx->ghost )->total_stake==0 ) ) fd_ghost_root( ctx->ghost )->total_stake = total_stake;
  ghost_blk->total_stake = total_stake;

  /* Determine reset, vote, and root slots.  There may not be a vote or
     root slot but there is always a reset slot. */

  fd_tower_slot_done_t * msg = fd_chunk_to_laddr( ctx->out_mem, ctx->out_chunk );
  fd_tower_out_t         out = fd_tower_vote_and_reset( ctx->tower, ctx->tower_accts, ctx->tower_forks, ctx->ghost, ctx->notar );
  msg->vote_slot             = out.vote_slot;
  msg->reset_slot            = out.reset_slot;
  msg->reset_block_id        = out.reset_block_id;
  msg->root_slot             = out.root_slot;
  msg->root_block_id         = out.root_block_id;

  /* Write out metrics for vote / reset reasons. */

  ctx->metrics.ancestor_rollback += (ulong)fd_uchar_extract_bit( out.flags, 0 );
  ctx->metrics.sibling_confirmed += (ulong)fd_uchar_extract_bit( out.flags, 1 );
  ctx->metrics.same_fork         += (ulong)fd_uchar_extract_bit( out.flags, 2 );
  ctx->metrics.lockout_fail      += (ulong)fd_uchar_extract_bit( out.flags, 3 );
  ctx->metrics.switch_pass       += (ulong)fd_uchar_extract_bit( out.flags, 4 );
  ctx->metrics.switch_fail       += (ulong)fd_uchar_extract_bit( out.flags, 5 );
  ctx->metrics.threshold_fail    += (ulong)fd_uchar_extract_bit( out.flags, 6 );
  ctx->metrics.propagated_fail   += (ulong)fd_uchar_extract_bit( out.flags, 7 );

  /* Create a vote_txn with the current tower (regardless of whether
     there was a new vote slot or not). */

  /* TODO only do this on refresh_last_vote? */

  fd_lockout_offset_t lockouts[ FD_TOWER_VOTE_MAX ];
  fd_txn_p_t txn[1];
  fd_tower_to_vote_txn( ctx->tower, out.root_slot, lockouts, &slot_info->bank_hash, &slot_info->block_hash, ctx->identity_key, ctx->identity_key, ctx->vote_account, txn );
  FD_TEST( !fd_tower_empty( ctx->tower ) );
  FD_TEST( txn->payload_sz && txn->payload_sz<=FD_TPU_MTU );
  fd_memcpy( msg->vote_txn, txn->payload, txn->payload_sz );
  msg->vote_txn_sz = txn->payload_sz;
  msg->vote_slot   = out.vote_slot;

  fd_stem_publish( stem, 0UL, FD_TOWER_SIG_SLOT_DONE, ctx->out_chunk, sizeof(fd_tower_slot_done_t), 0UL, tsorig, fd_frag_meta_ts_comp( fd_tickcount() ) );
  ctx->out_chunk = fd_dcache_compact_next( ctx->out_chunk, sizeof(fd_tower_slot_done_t), ctx->out_chunk0, ctx->out_wmark );

  /* Publish according structures if there is a root */

  if( FD_UNLIKELY( out.root_slot!=ULONG_MAX ) ) {
    fd_ghost_blk_t * newr = fd_ghost_query( ctx->ghost, &out.root_block_id );
    FD_TEST( newr );
    fd_ghost_publish( ctx->ghost, newr );
    fd_notar_advance_wmark( ctx->notar, out.root_slot );
    for(ulong slot = ctx->root_slot; slot < out.root_slot; slot++ ) {
      fd_tower_forks_t * fork = fd_tower_forks_query( ctx->tower_forks, slot, NULL );
      if( FD_LIKELY( fork ) ) fd_tower_forks_remove( ctx->tower_forks, fork );
    }

    /* Rooting implies optimistic confirmation in the Firedancer API, so
       we need to make sure to publish the optimistic frags before the
       rooted frags.  In most cases this is a no-op because gossip votes
       already triggered optimistic confirmation.

       TODO include replay votes in optimistic conf vote counting. */

    contiguous_confirm( ctx, stem, tsorig, out.root_slot, ctx->root_slot, FD_TOWER_SLOT_CONFIRMED_OPTIMISTIC );
    contiguous_confirm( ctx, stem, tsorig, out.root_slot, ctx->root_slot, FD_TOWER_SLOT_CONFIRMED_ROOTED     );
    ctx->root_slot = out.root_slot;
  }

# if LOGGING
  fd_ghost_print( ctx->ghost, fd_ghost_root( ctx->ghost ) );
  fd_tower_print( ctx->tower, fd_ghost_root( ctx->ghost )->slot );
# endif
}

static void
init_genesis( ctx_t * ctx ) {
  FD_TEST( ctx->init_slot==ULONG_MAX );
  FD_TEST( ctx->root_slot==ULONG_MAX );
  FD_TEST( ctx->conf_slot==ULONG_MAX );
  ctx->init_slot = 0;
  ctx->root_slot = 0;
  ctx->conf_slot = 0;

  fd_ghost_insert( ctx->ghost, &manifest_block_id, NULL, 0 );
  fd_tower_forks_t * fork  = fd_tower_forks_insert( ctx->tower_forks, 0 );
  fork->confirmed          = 1;
  fork->confirmed_block_id = manifest_block_id;
}

static void
snapshot_done( ctx_t *                        ctx,
               fd_snapshot_manifest_t const * manifest ) {
  FD_TEST( ctx->init_slot==ULONG_MAX );
  FD_TEST( ctx->root_slot==ULONG_MAX );
  FD_TEST( ctx->conf_slot==ULONG_MAX );
  ctx->init_slot = manifest->slot;
  ctx->root_slot = manifest->slot;
  ctx->conf_slot = manifest->slot;

  fd_ghost_insert( ctx->ghost, &manifest_block_id, NULL, manifest->slot );
  fd_tower_forks_t * fork = fd_tower_forks_insert( ctx->tower_forks, manifest->slot );
  fork->confirmed          = 1;
  fork->confirmed_block_id = manifest_block_id;
}

static inline int
returnable_frag( ctx_t *             ctx,
                 ulong               in_idx,
                 ulong               seq FD_PARAM_UNUSED,
                 ulong               sig,
                 ulong               chunk,
                 ulong               sz,
                 ulong               ctl,
                 ulong               tsorig,
                 ulong               tspub FD_PARAM_UNUSED,
                 fd_stem_context_t * stem ) {


  switch( ctx->in_kind[ in_idx ] ) {
  case IN_KIND_GENESIS: {
    if( FD_LIKELY( sig==GENESI_SIG_BOOTSTRAP_COMPLETED ) ) init_genesis( ctx );
    return 0;
  }
  case IN_KIND_SNAP: {
    if( FD_UNLIKELY( fd_ssmsg_sig_message( sig )==FD_SSMSG_DONE ) ) snapshot_done( ctx, &ctx->manifest );
    else {
      if( FD_UNLIKELY( chunk<ctx->in[ in_idx ].chunk0 || chunk>ctx->in[ in_idx ].wmark || sz>ctx->in[ in_idx ].mtu ) )
        FD_LOG_ERR(( "chunk %lu %lu from in %d corrupt, not in range [%lu,%lu]", chunk, sz, ctx->in_kind[ in_idx ], ctx->in[ in_idx ].chunk0, ctx->in[ in_idx ].wmark ));

      fd_memcpy( &ctx->manifest, fd_chunk_to_laddr( ctx->in[ in_idx ].mem, chunk ), sizeof(fd_snapshot_manifest_t) );
    }
    return 0;
  }
  case IN_KIND_GOSSIP: {
    if( FD_UNLIKELY( chunk<ctx->in[ in_idx ].chunk0 || chunk>ctx->in[ in_idx ].wmark || sz>ctx->in[ in_idx ].mtu ) )
      FD_LOG_ERR(( "chunk %lu %lu from in %d corrupt, not in range [%lu,%lu]", chunk, sz, ctx->in_kind[ in_idx ], ctx->in[ in_idx ].chunk0, ctx->in[ in_idx ].wmark ));
    if( FD_UNLIKELY( ctx->root_slot==ULONG_MAX ) ) return 1;
    if( FD_UNLIKELY( sig==FD_GOSSIP_UPDATE_TAG_VOTE ) ) {
      fd_gossip_vote_t const * vote = &((fd_gossip_update_message_t const *)fd_chunk_to_laddr( ctx->in[ in_idx ].mem, chunk ))->vote;
      gossip_vote( ctx, vote, tsorig, stem );
    }
    return 0;
  }
  case IN_KIND_REPLAY: {
    if( FD_UNLIKELY( chunk<ctx->in[ in_idx ].chunk0 || chunk>ctx->in[ in_idx ].wmark || sz>ctx->in[ in_idx ].mtu ) )
      FD_LOG_ERR(( "chunk %lu %lu from in %d corrupt, not in range [%lu,%lu]", chunk, sz, ctx->in_kind[ in_idx ], ctx->in[ in_idx ].chunk0, ctx->in[ in_idx ].wmark ));
    if( FD_UNLIKELY( ctx->root_slot==ULONG_MAX ) ) return 1;
    if( FD_LIKELY( sig==REPLAY_SIG_SLOT_COMPLETED ) ) {
      fd_memcpy( &ctx->replay_slot_completed, fd_chunk_to_laddr( ctx->in[ in_idx ].mem, chunk ), sizeof(fd_replay_slot_completed_t) );
    } else if( FD_LIKELY( sig==REPLAY_SIG_VOTE_STATE ) ) {
      if( FD_UNLIKELY( fd_frag_meta_ctl_som( ctl ) ) ) fd_tower_accts_remove_all( ctx->tower_accts );
      fd_replay_tower_t * vote_state = fd_chunk_to_laddr( ctx->in[ in_idx ].mem, chunk );
      fd_tower_accts_t acct = { .addr = vote_state->key, .stake = vote_state->stake };
      fd_memcpy( acct.data, vote_state->acc, vote_state->acc_sz );
      fd_tower_accts_push_tail( ctx->tower_accts, acct );
      if( FD_UNLIKELY( fd_frag_meta_ctl_eom( ctl ) ) ) replay_slot_completed( ctx, &ctx->replay_slot_completed /* FIXME this seems racy */, tsorig, stem );
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

  FD_TEST( fd_rng_secure( &ctx->seed, 8 ) );

  if( FD_UNLIKELY( !strcmp( tile->tower.identity_key, "" ) ) ) FD_LOG_ERR(( "identity_key_path not set" ));
  ctx->identity_key[ 0 ] = *(fd_pubkey_t const *)fd_type_pun_const( fd_keyload_load( tile->tower.identity_key, /* pubkey only: */ 1 ) );

  /* The vote key can be specified either directly as a base58 encoded
     pubkey, or as a file path.  We first try to decode as a pubkey. */

  uchar * vote_key = fd_base58_decode_32( tile->tower.vote_account, ctx->vote_account->uc );
  if( FD_UNLIKELY( !vote_key ) ) ctx->vote_account[ 0 ] = *(fd_pubkey_t const *)fd_type_pun_const( fd_keyload_load( tile->tower.vote_account, /* pubkey only: */ 1 ) );

  /* The tower file is used to checkpt and restore the state of the
     local tower. */

  char path[ PATH_MAX ];
  FD_TEST( fd_cstr_printf_check( path, sizeof(path), NULL, "%s/tower-1_9-%s.bin.new", tile->tower.base_path, FD_BASE58_ENC_32_ALLOCA( ctx->identity_key->uc ) ) );
  ctx->checkpt_fd = open( path, O_WRONLY|O_CREAT|O_TRUNC, 0600 );
  if( FD_UNLIKELY( -1==ctx->checkpt_fd ) ) FD_LOG_ERR(( "open(`%s`) failed (%i-%s)", path, errno, fd_io_strerror( errno ) ));

  FD_TEST( fd_cstr_printf_check( path, sizeof(path), NULL, "%s/tower-1_9-%s.bin", tile->tower.base_path, FD_BASE58_ENC_32_ALLOCA( ctx->identity_key->uc ) ) );
  ctx->restore_fd = open( path, O_RDONLY );
  if( FD_UNLIKELY( -1==ctx->restore_fd && errno!=ENOENT ) ) FD_LOG_ERR(( "open(`%s`) failed (%i-%s)", path, errno, fd_io_strerror( errno ) ));
}

static void
unprivileged_init( fd_topo_t *      topo,
                   fd_topo_tile_t * tile ) {
  void * scratch     = fd_topo_obj_laddr( topo, tile->tile_obj_id );
  ulong  slot_max    = tile->tower.slot_max;
  int    lg_slot_max = fd_ulong_find_msb( fd_ulong_pow2_up( slot_max ) ) + 1;
  FD_SCRATCH_ALLOC_INIT( l, scratch );
  ctx_t * ctx   = FD_SCRATCH_ALLOC_APPEND( l, alignof(ctx_t),         sizeof(ctx_t)                                  );
  void  * ghost = FD_SCRATCH_ALLOC_APPEND( l, fd_ghost_align(),       fd_ghost_footprint( 2*slot_max, FD_VOTER_MAX ) );
  void  * notar = FD_SCRATCH_ALLOC_APPEND( l, fd_notar_align(),       fd_notar_footprint( slot_max )                 );
  void  * tower = FD_SCRATCH_ALLOC_APPEND( l, fd_tower_align(),       fd_tower_footprint()                           );
  void  * accts = FD_SCRATCH_ALLOC_APPEND( l, fd_tower_accts_align(), fd_tower_accts_footprint( FD_VOTER_MAX )       );
  void  * forks = FD_SCRATCH_ALLOC_APPEND( l, fd_tower_forks_align(), fd_tower_forks_footprint( lg_slot_max )        );
  void  * spare = FD_SCRATCH_ALLOC_APPEND( l, fd_tower_align(),       fd_tower_footprint()                           );
  void  * slots = FD_SCRATCH_ALLOC_APPEND( l, slots_align(),          slots_footprint( slot_max )                    );
  FD_SCRATCH_ALLOC_FINI( l, scratch_align() );

  ctx->ghost       = fd_ghost_join      ( fd_ghost_new      ( ghost, 2*slot_max, FD_VOTER_MAX, 42UL ) ); /* FIXME seed */
  ctx->notar       = fd_notar_join      ( fd_notar_new      ( notar, slot_max                       ) );
  ctx->tower       = fd_tower_join      ( fd_tower_new      ( tower                                 ) );
  ctx->tower_accts = fd_tower_accts_join( fd_tower_accts_new( accts, FD_VOTER_MAX                   ) );
  ctx->tower_forks = fd_tower_forks_join( fd_tower_forks_new( forks, lg_slot_max                    ) );
  ctx->tower_spare = fd_tower_join      ( fd_tower_new      ( spare                                 ) );
  ctx->slots       = slots_join         ( slots_new         ( slots, slot_max                       ) );
  FD_TEST( ctx->ghost );
  FD_TEST( ctx->notar );
  FD_TEST( ctx->tower );
  FD_TEST( ctx->tower_accts );
  FD_TEST( ctx->tower_forks );
  FD_TEST( ctx->tower_spare );

  for( ulong i = 0; i<VOTE_TXN_SIG_MAX; i++ ) {
    fd_sha512_t * sha = fd_sha512_join( fd_sha512_new( FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_sha512_t), sizeof(fd_sha512_t) ) ) );
    FD_TEST( sha );
    ctx->gossip_vote_sha[i] = sha;
  }

  ctx->init_slot = ULONG_MAX;
  ctx->root_slot = ULONG_MAX;
  ctx->conf_slot = ULONG_MAX;

  FD_TEST( tile->in_cnt<sizeof(ctx->in_kind)/sizeof(ctx->in_kind[0]) );
  for( ulong i=0UL; i<tile->in_cnt; i++ ) {
    fd_topo_link_t * link = &topo->links[ tile->in_link_id[ i ] ];
    fd_topo_wksp_t * link_wksp = &topo->workspaces[ topo->objs[ link->dcache_obj_id ].wksp_id ];

    if     ( FD_LIKELY( !strcmp( link->name, "genesi_out"   ) ) ) ctx->in_kind[ i ] = IN_KIND_GENESIS;
    else if( FD_LIKELY( !strcmp( link->name, "gossip_out"   ) ) ) ctx->in_kind[ i ] = IN_KIND_GOSSIP;
    else if( FD_LIKELY( !strcmp( link->name, "replay_out"   ) ) ) ctx->in_kind[ i ] = IN_KIND_REPLAY;
    else if( FD_LIKELY( !strcmp( link->name, "snapin_manif" ) ) ) ctx->in_kind[ i ] = IN_KIND_SNAP;
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

#define STEM_BURST (1UL) /* FIXME needs to be configured at runtime with max_unrooted_slots */

#define STEM_CALLBACK_CONTEXT_TYPE    ctx_t
#define STEM_CALLBACK_CONTEXT_ALIGN   alignof(ctx_t)
#define STEM_CALLBACK_METRICS_WRITE   metrics_write
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
