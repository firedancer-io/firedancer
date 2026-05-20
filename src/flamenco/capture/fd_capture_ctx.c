#include "fd_capture_ctx.h"
#include "fd_solcap_writer.h"
#include "../../tango/mcache/fd_mcache.h"
#include "../../tango/dcache/fd_dcache.h"
#include "../../tango/fd_tango_base.h"
#include "../../tango/fseq/fd_fseq.h"
#include "../runtime/fd_runtime.h"
#include "../runtime/fd_bank.h"
#include "../../ballet/txn/fd_txn.h"

void *
fd_capture_ctx_new( void * mem ) {
  if( FD_UNLIKELY( !mem ) ) {
    FD_LOG_WARNING(( "NULL mem" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)mem, fd_capture_ctx_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned mem" ));
    return NULL;
  }

  FD_SCRATCH_ALLOC_INIT( l, mem );
  fd_capture_ctx_t *   capture_ctx = FD_SCRATCH_ALLOC_APPEND( l, fd_capture_ctx_align(),   sizeof(fd_capture_ctx_t) );
  fd_solcap_writer_t * capture     = FD_SCRATCH_ALLOC_APPEND( l, fd_solcap_writer_align(), fd_solcap_writer_footprint() );
  FD_TEST( FD_SCRATCH_ALLOC_FINI( l, fd_capture_ctx_align() ) == (ulong)mem + fd_capture_ctx_footprint() );

  fd_memset( capture_ctx, 0, sizeof(fd_capture_ctx_t) );
  fd_memset(capture, 0, sizeof(fd_solcap_writer_t));

  /* Link the capture writer to the context */
  capture_ctx->capture = capture;

  /* memset(0) leaves current_block_diff_category at 0 = SYSVAR; force
     it to NONE so non-txn account writes outside an explicit region
     don't get spuriously bucketed. */
  capture_ctx->current_block_diff_category = FD_CAPTURE_RUNTIME_BLOCK_DIFF_NONE;

  FD_COMPILER_MFENCE();
  FD_VOLATILE( capture_ctx->magic ) = FD_CAPTURE_CTX_MAGIC;
  FD_COMPILER_MFENCE();

  return mem;
}

fd_capture_ctx_t *
fd_capture_ctx_join( void * mem ) {
  if( FD_UNLIKELY( !mem ) ) {
    FD_LOG_WARNING(( "NULL block" ));
    return NULL;
  }

  fd_capture_ctx_t * ctx = (fd_capture_ctx_t *) mem;

  if( FD_UNLIKELY( ctx->magic!=FD_CAPTURE_CTX_MAGIC ) ) {
    FD_LOG_WARNING(( "bad magic" ));
    return NULL;
  }

  return ctx;
}

void *
fd_capture_ctx_leave( fd_capture_ctx_t * ctx) {
  if( FD_UNLIKELY( !ctx ) ) {
    FD_LOG_WARNING(( "NULL block" ));
    return NULL;
  }

  if( FD_UNLIKELY( ctx->magic!=FD_CAPTURE_CTX_MAGIC ) ) {
    FD_LOG_WARNING(( "bad magic" ));
    return NULL;
  }

  return (void *) ctx;
}

void *
fd_capture_ctx_delete( void * mem ) {
  if( FD_UNLIKELY( !mem ) ) {
    FD_LOG_WARNING(( "NULL mem" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)mem, fd_capture_ctx_align() ) ) )  {
    FD_LOG_WARNING(( "misaligned mem" ));
    return NULL;
  }

  fd_capture_ctx_t * hdr = (fd_capture_ctx_t *)mem;
  if( FD_UNLIKELY( hdr->magic!=FD_CAPTURE_CTX_MAGIC ) ) {
    FD_LOG_WARNING(( "bad magic" ));
    return NULL;
  }

  FD_COMPILER_MFENCE();
  FD_VOLATILE( hdr->magic ) = 0UL;
  FD_COMPILER_MFENCE();

  return mem;
}


static void
wait_to_write_solcap_msg( fd_capture_link_buf_t * buf ) {
  if( FD_LIKELY( buf->fseq ) ) {
    while( FD_UNLIKELY( fd_seq_diff( buf->seq, fd_fseq_query( buf->fseq ) ) > 2L ) ) {
      FD_SPIN_PAUSE();
    }
  }
}

static uint
valid_slot_range(fd_capture_ctx_t * ctx,
                 ulong              slot ) {
  /* When solcap_start_slot is 0 (not set), capture all slots */
  if( FD_LIKELY( ctx->solcap_start_slot == 0UL ) ) {
    return 1;
  }
  if( FD_UNLIKELY( slot < ctx->solcap_start_slot ) ) {
    return 0;
  }
  return 1;
}

/* wait_to_write_event_msg: producer back-pressure for the event link.
   Unlike solcap (hard-coded threshold of 2 — every write blocked),
   this lets the producer use most of the deep ring before spinning,
   so the validator only stalls if the event tile is genuinely stuck. */
static void
wait_to_write_event_msg( fd_capture_link_buf_t * buf ) {
  if( FD_LIKELY( buf->fseq ) ) {
    long lag_max = (long)buf->depth - 128L; /* reserve 128 slots of margin */
    if( FD_UNLIKELY( lag_max < 2L ) ) lag_max = 2L;
    while( FD_UNLIKELY( fd_seq_diff( buf->seq, fd_fseq_query( buf->fseq ) ) > lag_max ) ) {
      FD_SPIN_PAUSE();
    }
  }
}

void
fd_capture_link_write_bank_event( fd_capture_ctx_t * ctx,
                                  ulong              slot,
                                  fd_hash_t const *  bank_hash,
                                  fd_hash_t const *  prev_bank_hash,
                                  fd_hash_t const *  accounts_lt_hash_checksum,
                                  fd_hash_t const *  poh_hash,
                                  ulong              signature_cnt ) {
  if( FD_LIKELY( !ctx || !ctx->capture_bank_events || !ctx->bank_capture_link ) ) return;

  fd_capture_link_buf_t * buf = ctx->bank_capture_link;
  wait_to_write_event_msg( buf );

  uchar * dst = (uchar *)fd_chunk_to_laddr( buf->mem, buf->chunk );
  fd_capture_bank_event_msg_t msg = {0};
  fd_memcpy( msg.bank_hash,                 bank_hash,                 32UL );
  fd_memcpy( msg.prev_bank_hash,            prev_bank_hash,            32UL );
  fd_memcpy( msg.accounts_lt_hash_checksum, accounts_lt_hash_checksum, 32UL );
  fd_memcpy( msg.poh_hash,                  poh_hash,                  32UL );
  msg.slot          = slot;
  msg.signature_cnt = signature_cnt;
  fd_memcpy( dst, &msg, sizeof(msg) );

  ulong ctl = fd_frag_meta_ctl( 0UL, 1UL, 1UL, 0UL );
  fd_mcache_publish( buf->mcache, buf->depth, buf->seq, 0UL, buf->chunk, sizeof(msg), ctl, 0UL, 0UL );
  buf->chunk = fd_dcache_compact_next( buf->chunk, sizeof(msg), buf->chunk0, buf->wmark );
  buf->seq++;
}

void
fd_capture_link_write_stake_event( fd_capture_ctx_t *  ctx,
                                   fd_pubkey_t const * pubkey,
                                   fd_pubkey_t const * voter_pubkey,
                                   ulong               stake,
                                   ulong               activation_epoch,
                                   ulong               deactivation_epoch,
                                   ulong               credits_observed,
                                   ulong               slot,
                                   int                 removed ) {
  if( FD_LIKELY( !ctx || !ctx->capture_stake_events || !ctx->stake_capture_link ) ) return;

  fd_capture_link_buf_t * buf = ctx->stake_capture_link;
  wait_to_write_event_msg( buf );

  uchar * dst = (uchar *)fd_chunk_to_laddr( buf->mem, buf->chunk );
  fd_capture_stake_event_msg_t msg = {0};
  fd_memcpy( msg.pubkey, pubkey, 32UL );
  if( voter_pubkey ) fd_memcpy( msg.voter_pubkey, voter_pubkey, 32UL );
  msg.stake              = stake;
  msg.activation_epoch   = activation_epoch;
  msg.deactivation_epoch = deactivation_epoch;
  msg.credits_observed   = credits_observed;
  msg.slot               = slot;
  msg.removed            = (uchar)!!removed;
  fd_memcpy( dst, &msg, sizeof(msg) );

  ulong ctl = fd_frag_meta_ctl( 0UL, 1UL, 1UL, 0UL );
  fd_mcache_publish( buf->mcache, buf->depth, buf->seq, 0UL, buf->chunk, sizeof(msg), ctl, 0UL, 0UL );
  buf->chunk = fd_dcache_compact_next( buf->chunk, sizeof(msg), buf->chunk0, buf->wmark );
  buf->seq++;
}

void
fd_capture_link_write_vote_event( fd_capture_ctx_t *  ctx,
                                  fd_pubkey_t const * pubkey,
                                  ulong               last_vote_slot,
                                  long                last_vote_timestamp,
                                  ulong               slot,
                                  int                 invalidated ) {
  if( FD_LIKELY( !ctx || !ctx->capture_vote_events || !ctx->vote_capture_link ) ) return;

  fd_capture_link_buf_t * buf = ctx->vote_capture_link;
  wait_to_write_event_msg( buf );

  uchar * dst = (uchar *)fd_chunk_to_laddr( buf->mem, buf->chunk );
  fd_capture_vote_event_msg_t msg = {0};
  fd_memcpy( msg.pubkey, pubkey, 32UL );
  msg.last_vote_slot      = last_vote_slot;
  msg.last_vote_timestamp = last_vote_timestamp;
  msg.slot                = slot;
  msg.invalidated         = (uchar)!!invalidated;
  fd_memcpy( dst, &msg, sizeof(msg) );

  ulong ctl = fd_frag_meta_ctl( 0UL, 1UL, 1UL, 0UL );
  fd_mcache_publish( buf->mcache, buf->depth, buf->seq, 0UL, buf->chunk, sizeof(msg), ctl, 0UL, 0UL );
  buf->chunk = fd_dcache_compact_next( buf->chunk, sizeof(msg), buf->chunk0, buf->wmark );
  buf->seq++;
}

void
fd_capture_link_write_vote_txn( fd_capture_ctx_t *                  ctx,
                                fd_pubkey_t const *                 vote_account,
                                fd_pubkey_t const *                 voter,
                                fd_hash_t const *                   bank_hash,
                                fd_hash_t const *                   block_id,
                                uchar const *                       signature,
                                ulong                               slot,
                                ulong                               root_slot,
                                long                                timestamp,
                                int                                 has_root,
                                int                                 has_timestamp,
                                int                                 has_block_id,
                                uint                                ix_variant,
                                fd_capture_vote_lockout_t const *   lockouts,
                                ulong                               lockouts_cnt ) {
  if( FD_LIKELY( !ctx || !ctx->capture_vote_txn_events || !ctx->vote_txn_capture_link ) ) return;

  fd_capture_link_buf_t * buf = ctx->vote_txn_capture_link;
  wait_to_write_event_msg( buf );

  uchar * dst = (uchar *)fd_chunk_to_laddr( buf->mem, buf->chunk );
  fd_capture_vote_txn_event_msg_t msg = {0};
  if( vote_account ) fd_memcpy( msg.vote_account, vote_account, 32UL );
  if( voter        ) fd_memcpy( msg.voter,        voter,        32UL );
  if( bank_hash    ) fd_memcpy( msg.bank_hash,    bank_hash,    32UL );
  if( block_id     ) fd_memcpy( msg.block_id,     block_id,     32UL );
  if( signature    ) fd_memcpy( msg.signature,    signature,    64UL );
  msg.slot          = slot;
  msg.root_slot     = root_slot;
  msg.timestamp     = timestamp;
  msg.has_root      = (uchar)!!has_root;
  msg.has_timestamp = (uchar)!!has_timestamp;
  msg.has_block_id  = (uchar)!!has_block_id;
  msg.ix_variant    = (uchar)ix_variant;
  ulong cap = lockouts_cnt > FD_CAPTURE_VOTE_TXN_TOWER_MAX ? FD_CAPTURE_VOTE_TXN_TOWER_MAX : lockouts_cnt;
  msg.lockouts_cnt  = (uchar)cap;
  if( cap && lockouts ) fd_memcpy( msg.lockouts, lockouts, cap*sizeof(fd_capture_vote_lockout_t) );
  fd_memcpy( dst, &msg, sizeof(msg) );

  ulong ctl = fd_frag_meta_ctl( 0UL, 1UL, 1UL, 0UL );
  fd_mcache_publish( buf->mcache, buf->depth, buf->seq, 0UL, buf->chunk, sizeof(msg), ctl, 0UL, 0UL );
  buf->chunk = fd_dcache_compact_next( buf->chunk, sizeof(msg), buf->chunk0, buf->wmark );
  buf->seq++;
}

/* Helper: negate-to-positive for FD_RUNTIME_*_ERR_* codes.  0 → 0; non-zero
   negatives become their absolute value; positives left as-is (defensive). */
static inline uint
runtime_err_abs( int err ) {
  return (uint)( err < 0 ? -err : err );
}

void
fd_capture_link_write_runtime_txn( fd_capture_ctx_t *         ctx,
                                   struct fd_txn_in  const *  txn_in,
                                   struct fd_txn_out const *  txn_out,
                                   struct fd_bank    const *  bank ) {
  if( FD_LIKELY( !ctx ) ) return;

  /* Drain the per-txn diff buffer either way; if reporting is disabled
     we still need to reset for the next dispatched txn. */
  ulong diff_cnt = ctx->current_txn_diff_cnt;
  ctx->current_txn_diff_cnt = 0UL;

  if( FD_LIKELY( !ctx->capture_runtime_txn_events || !ctx->runtime_txn_capture_link ) ) return;

  fd_capture_link_buf_t * buf = ctx->runtime_txn_capture_link;
  wait_to_write_event_msg( buf );

  uchar * dst = (uchar *)fd_chunk_to_laddr( buf->mem, buf->chunk );
  fd_capture_runtime_txn_event_msg_t msg = {0};

  /* Identity — signature lives in the txn payload at the signature_off
     offset; blockhash + slot from txn_out / bank. */
  if( txn_in && txn_in->txn ) {
    fd_txn_t const * t   = TXN( txn_in->txn );
    uchar const *    sig = (uchar const *)txn_in->txn->payload + t->signature_off;
    fd_memcpy( msg.signature, sig, 64UL );
  }
  fd_memcpy( msg.blockhash,       txn_out->details.blockhash.uc,    32UL );
  fd_memcpy( msg.dispatch_fec_mr, ctx->current_txn_dispatch_fec_mr, 32UL );
  msg.slot      = bank ? bank->f.slot : 0UL;
  msg.txn_idx   = ctx->current_txn_idx;
  /* bundle_id isn't currently surfaced on fd_txn_in_t; left at 0 for now.
     is_bundle lives on txn_in->bundle.is_bundle. */
  msg.bundle_id = 0UL;

  /* Result flags (0/1) */
  msg.is_simple_vote = (uchar)( txn_out->details.is_simple_vote ? 1U : 0U );
  msg.is_bundle      = (uchar)( (txn_in && txn_in->bundle.is_bundle) ? 1U : 0U );
  msg.is_committable = (uchar)( txn_out->err.is_committable     ? 1U : 0U );
  msg.is_fees_only   = (uchar)( txn_out->err.is_fees_only        ? 1U : 0U );

  /* Errors — stored as absolute value (FD_RUNTIME_*_ERR_* are negative). */
  msg.txn_err       = runtime_err_abs( txn_out->err.txn_err );
  msg.exec_err      = runtime_err_abs( txn_out->err.exec_err );
  msg.exec_err_kind = runtime_err_abs( txn_out->err.exec_err_kind );
  msg.exec_err_idx  = runtime_err_abs( txn_out->err.exec_err_idx );
  msg.custom_err    = txn_out->err.custom_err;

  /* Compute budget */
  fd_compute_budget_details_t const * cb = &txn_out->details.compute_budget;
  msg.compute_unit_limit              = cb->compute_unit_limit;
  msg.compute_unit_price              = cb->compute_unit_price;
  msg.compute_units_consumed          = cb->compute_unit_limit > cb->compute_meter
                                          ? cb->compute_unit_limit - cb->compute_meter
                                          : 0UL;
  msg.heap_size                       = (uint)cb->heap_size;
  msg.loaded_accounts_data_size       = txn_out->details.loaded_accounts_data_size;
  msg.loaded_accounts_data_size_limit = cb->loaded_accounts_data_size_limit;
  msg.accounts_resize_delta           = txn_out->details.accounts_resize_delta;
  msg.num_builtin_instrs              = (uint)cb->num_builtin_instrs;
  msg.num_non_builtin_instrs          = (uint)cb->num_non_builtin_instrs;

  /* Fees */
  msg.execution_fee   = txn_out->details.execution_fee;
  msg.priority_fee    = txn_out->details.priority_fee;
  msg.tips            = txn_out->details.tips;
  msg.signature_count = (uint)txn_out->details.signature_count;

  /* Cost tracker */
  fd_usage_cost_details_t const * cost = &txn_out->details.txn_cost.transaction;
  msg.cost_signature                    = cost->signature_cost;
  msg.cost_write_lock                   = cost->write_lock_cost;
  msg.cost_data_bytes                   = cost->data_bytes_cost;
  msg.cost_programs_execution           = cost->programs_execution_cost;
  msg.cost_loaded_accounts_data_size    = cost->loaded_accounts_data_size_cost;
  msg.cost_allocated_accounts_data_size = cost->allocated_accounts_data_size;

  /* Per-stage timing */
  msg.prep_start_ns   = txn_out->details.prep_start_timestamp;
  msg.load_start_ns   = txn_out->details.load_start_timestamp;
  msg.exec_start_ns   = txn_out->details.exec_start_timestamp;
  msg.commit_start_ns = txn_out->details.commit_start_timestamp;

  /* Account diffs.  Drain ctx->current_txn_diffs[] populated during commit
     and fill in the stake/vote flags by looking up each pubkey's slot in
     txn_out->accounts. */
  ulong cap_diffs = diff_cnt < FD_CAPTURE_RUNTIME_TXN_MAX_ACCOUNT_DIFFS
                      ? diff_cnt
                      : FD_CAPTURE_RUNTIME_TXN_MAX_ACCOUNT_DIFFS;
  msg.account_diff_cnt = cap_diffs;

  /* Split txn_out->accounts.keys[] into writable / readonly arrays. */
  ulong w_cnt = 0UL, r_cnt = 0UL;
  for( ulong j = 0UL; j < txn_out->accounts.cnt; j++ ) {
    if( txn_out->accounts.is_writable[ j ] ) {
      if( w_cnt < FD_CAPTURE_RUNTIME_TXN_MAX_ACCOUNTS ) {
        fd_memcpy( msg.writable_accounts[ w_cnt++ ], txn_out->accounts.keys[ j ].uc, 32UL );
      }
    } else {
      if( r_cnt < FD_CAPTURE_RUNTIME_TXN_MAX_ACCOUNTS ) {
        fd_memcpy( msg.readonly_accounts[ r_cnt++ ], txn_out->accounts.keys[ j ].uc, 32UL );
      }
    }
  }
  msg.writable_accounts_cnt = w_cnt;
  msg.readonly_accounts_cnt = r_cnt;

  for( ulong i = 0UL; i < cap_diffs; i++ ) {
    fd_capture_runtime_txn_account_diff_t * d = &msg.account_diffs[ i ];
    fd_memcpy( d, &ctx->current_txn_diffs[ i ], sizeof(*d) );
    /* Fill flags via pubkey lookup in txn_out->accounts.keys[]. */
    for( ulong j = 0UL; j < txn_out->accounts.cnt; j++ ) {
      if( 0 == memcmp( d->pubkey, txn_out->accounts.keys[ j ].uc, 32UL ) ) {
        d->stake_update = (uchar)( txn_out->accounts.stake_update[ j ] ? 1U : 0U );
        d->vote_update  = (uchar)( txn_out->accounts.vote_update [ j ] ? 1U : 0U );
        d->new_vote     = (uchar)( txn_out->accounts.new_vote    [ j ] ? 1U : 0U );
        d->rm_vote      = (uchar)( txn_out->accounts.rm_vote     [ j ] ? 1U : 0U );
        break;
      }
    }
  }

  fd_memcpy( dst, &msg, sizeof(msg) );

  ulong ctl = fd_frag_meta_ctl( 0UL, 1UL, 1UL, 0UL );
  fd_mcache_publish( buf->mcache, buf->depth, buf->seq, 0UL, buf->chunk, sizeof(msg), ctl, 0UL, 0UL );
  buf->chunk = fd_dcache_compact_next( buf->chunk, sizeof(msg), buf->chunk0, buf->wmark );
  buf->seq++;
}

void
fd_capture_link_runtime_block_append_diff( fd_capture_ctx_t *               ctx,
                                           int                              category,
                                           fd_pubkey_t const *              pubkey,
                                           fd_solana_account_meta_t const * info,
                                           ulong                            data_sz ) {
  if( FD_LIKELY( !ctx || !ctx->capture_runtime_block_events ) ) return;

  fd_capture_runtime_block_account_diff_t * arr;
  ulong *                                   cnt_p;
  ulong                                     cap;
  switch( category ) {
    case FD_CAPTURE_RUNTIME_BLOCK_DIFF_SYSVAR:
      arr   = ctx->current_block_sysvar_diffs;
      cnt_p = &ctx->current_block_sysvar_diffs_cnt;
      cap   = FD_CAPTURE_RUNTIME_BLOCK_SYSVAR_DIFFS_MAX;
      break;
    case FD_CAPTURE_RUNTIME_BLOCK_DIFF_VOTE_REWARD:
      arr   = ctx->current_block_vote_reward_diffs;
      cnt_p = &ctx->current_block_vote_reward_diffs_cnt;
      cap   = FD_CAPTURE_RUNTIME_BLOCK_VOTE_REWARD_DIFFS_MAX;
      break;
    case FD_CAPTURE_RUNTIME_BLOCK_DIFF_STAKE_REWARD:
      arr   = ctx->current_block_stake_reward_diffs;
      cnt_p = &ctx->current_block_stake_reward_diffs_cnt;
      cap   = FD_CAPTURE_RUNTIME_BLOCK_STAKE_REWARD_DIFFS_MAX;
      break;
    case FD_CAPTURE_RUNTIME_BLOCK_DIFF_FEE_REWARD:
      arr   = ctx->current_block_fee_reward_diffs;
      cnt_p = &ctx->current_block_fee_reward_diffs_cnt;
      cap   = FD_CAPTURE_RUNTIME_BLOCK_FEE_REWARD_DIFFS_MAX;
      break;
    case FD_CAPTURE_RUNTIME_BLOCK_DIFF_OTHER:
      arr   = ctx->current_block_other_diffs;
      cnt_p = &ctx->current_block_other_diffs_cnt;
      cap   = FD_CAPTURE_RUNTIME_BLOCK_OTHER_DIFFS_MAX;
      break;
    default:
      return;
  }
  if( FD_UNLIKELY( *cnt_p >= cap ) ) return;   /* truncate silently */

  fd_capture_runtime_block_account_diff_t * d = &arr[ (*cnt_p)++ ];
  if( pubkey ) fd_memcpy( d->pubkey, pubkey,      32UL );
  if( info   ) {
    fd_memcpy( d->owner, info->owner, 32UL );
    d->lamports   = info->lamports;
    d->executable = (uchar)( info->executable ? 1U : 0U );
  }
  d->data_sz = data_sz;
}

void
fd_capture_link_runtime_block_append_fec_mr( fd_capture_ctx_t * ctx,
                                             uchar const *      mr ) {
  if( FD_LIKELY( !ctx || !ctx->capture_runtime_block_events || !mr ) ) return;
  if( FD_UNLIKELY( ctx->current_block_fec_merkle_roots_cnt >= FD_CAPTURE_RUNTIME_BLOCK_FEC_MRS_MAX ) ) return;
  fd_memcpy( ctx->current_block_fec_merkle_roots[ ctx->current_block_fec_merkle_roots_cnt++ ], mr, 32UL );
}

void
fd_capture_link_write_runtime_block( fd_capture_ctx_t *                       ctx,
                                     fd_capture_runtime_block_info_t const *  info ) {
  if( FD_LIKELY( !ctx ) ) return;

  /* Drain all buffers either way; if reporting is disabled we still
     want to reset for the next slot. */
  ulong sysvar_cnt        = ctx->current_block_sysvar_diffs_cnt;
  ulong vote_reward_cnt   = ctx->current_block_vote_reward_diffs_cnt;
  ulong stake_reward_cnt  = ctx->current_block_stake_reward_diffs_cnt;
  ulong fee_reward_cnt    = ctx->current_block_fee_reward_diffs_cnt;
  ulong other_cnt         = ctx->current_block_other_diffs_cnt;
  ulong fec_mr_cnt        = ctx->current_block_fec_merkle_roots_cnt;
  ulong fees_burned       = ctx->current_block_fees_burned;
  ulong leader_fee_reward = ctx->current_block_leader_fee_reward;
  ctx->current_block_sysvar_diffs_cnt       = 0UL;
  ctx->current_block_vote_reward_diffs_cnt  = 0UL;
  ctx->current_block_stake_reward_diffs_cnt = 0UL;
  ctx->current_block_fee_reward_diffs_cnt   = 0UL;
  ctx->current_block_other_diffs_cnt        = 0UL;
  ctx->current_block_fec_merkle_roots_cnt   = 0UL;
  ctx->current_block_fees_burned            = 0UL;
  ctx->current_block_leader_fee_reward      = 0UL;

  if( FD_LIKELY( !ctx->capture_runtime_block_events || !ctx->runtime_block_capture_link ) ) return;

  fd_capture_link_buf_t * buf = ctx->runtime_block_capture_link;
  wait_to_write_event_msg( buf );

  uchar * dst = (uchar *)fd_chunk_to_laddr( buf->mem, buf->chunk );
  fd_capture_runtime_block_event_msg_t msg = {0};

  if( info->block_id                  ) fd_memcpy( msg.block_id,                  info->block_id,                  32UL );
  if( info->parent_block_id           ) fd_memcpy( msg.parent_block_id,           info->parent_block_id,           32UL );
  if( info->leader                    ) fd_memcpy( msg.leader,                    info->leader,                    32UL );
  if( info->bank_hash                 ) fd_memcpy( msg.bank_hash,                 info->bank_hash,                 32UL );
  if( info->prev_bank_hash            ) fd_memcpy( msg.prev_bank_hash,            info->prev_bank_hash,            32UL );
  if( info->accounts_lt_hash_checksum ) fd_memcpy( msg.accounts_lt_hash_checksum, info->accounts_lt_hash_checksum, 32UL );
  if( info->poh_hash                  ) fd_memcpy( msg.poh_hash,                  info->poh_hash,                  32UL );
  if( info->blockhash                 ) fd_memcpy( msg.blockhash,                 info->blockhash,                 32UL );

  msg.slot                    = info->slot;
  msg.parent_slot             = info->parent_slot;
  msg.num_signatures          = info->num_signatures;
  msg.tick_height             = info->tick_height;
  msg.fees_collected            = info->fees_collected;
  /* fees_burned/leader_fee_reward come from settle_fees-side stash;
     prefer that over caller-supplied info fields if non-zero. */
  msg.fees_burned               = fees_burned       ? fees_burned       : info->fees_burned;
  msg.leader_fee_reward         = leader_fee_reward ? leader_fee_reward : info->leader_fee_reward;
  msg.priority_fees_total       = info->priority_fees_total;
  msg.compute_units_consumed    = info->compute_units_consumed;
  msg.capitalization            = info->capitalization;
  msg.total_effective_stake     = info->total_effective_stake;
  msg.total_activating_stake    = info->total_activating_stake;
  msg.total_deactivating_stake  = info->total_deactivating_stake;
  msg.total_epoch_stake         = info->total_epoch_stake;
  msg.transaction_count         = info->transaction_count;

  msg.epoch               = info->epoch;
  msg.num_transactions    = info->num_transactions;
  msg.num_successful_txns = info->num_successful_txns;
  msg.num_failed_txns     = info->num_failed_txns;
  msg.ticks_in_block      = info->ticks_in_block;
  msg.block_produced      = (uchar)( info->block_produced ? 1U : 0U );

  msg.sysvar_diffs_cnt       = sysvar_cnt;
  msg.vote_reward_diffs_cnt  = vote_reward_cnt;
  msg.stake_reward_diffs_cnt = stake_reward_cnt;
  msg.fee_reward_diffs_cnt   = fee_reward_cnt;
  msg.other_diffs_cnt        = other_cnt;
  msg.fec_merkle_roots_cnt   = fec_mr_cnt;
  if( sysvar_cnt       ) fd_memcpy( msg.sysvar_diffs,       ctx->current_block_sysvar_diffs,       sysvar_cnt       * sizeof(fd_capture_runtime_block_account_diff_t) );
  if( vote_reward_cnt  ) fd_memcpy( msg.vote_reward_diffs,  ctx->current_block_vote_reward_diffs,  vote_reward_cnt  * sizeof(fd_capture_runtime_block_account_diff_t) );
  if( stake_reward_cnt ) fd_memcpy( msg.stake_reward_diffs, ctx->current_block_stake_reward_diffs, stake_reward_cnt * sizeof(fd_capture_runtime_block_account_diff_t) );
  if( fee_reward_cnt   ) fd_memcpy( msg.fee_reward_diffs,   ctx->current_block_fee_reward_diffs,   fee_reward_cnt   * sizeof(fd_capture_runtime_block_account_diff_t) );
  if( other_cnt        ) fd_memcpy( msg.other_diffs,        ctx->current_block_other_diffs,        other_cnt        * sizeof(fd_capture_runtime_block_account_diff_t) );
  if( fec_mr_cnt       ) fd_memcpy( msg.fec_merkle_roots,   ctx->current_block_fec_merkle_roots,   fec_mr_cnt       * 32UL );

  fd_memcpy( dst, &msg, sizeof(msg) );

  ulong ctl = fd_frag_meta_ctl( 0UL, 1UL, 1UL, 0UL );
  fd_mcache_publish( buf->mcache, buf->depth, buf->seq, 0UL, buf->chunk, sizeof(msg), ctl, 0UL, 0UL );
  buf->chunk = fd_dcache_compact_next( buf->chunk, sizeof(msg), buf->chunk0, buf->wmark );
  buf->seq++;
}

void
fd_capture_link_write_account_event( fd_capture_ctx_t *               ctx,
                                     uchar const *                    signature,
                                     fd_pubkey_t const *              key,
                                     fd_solana_account_meta_t const * info,
                                     ulong                            slot,
                                     ulong                            data_sz ) {
  if( FD_LIKELY( !ctx || !ctx->capture_account_events || !ctx->event_capture_link ) ) return;

  fd_capture_link_buf_t * buf = ctx->event_capture_link;
  wait_to_write_event_msg( buf );

  uchar * dst = (uchar *)fd_chunk_to_laddr( buf->mem, buf->chunk );
  fd_capture_account_event_msg_t msg = {0};
  fd_memcpy( msg.pubkey,    key,         32UL );
  fd_memcpy( msg.owner,     info->owner, 32UL );
  if( signature ) fd_memcpy( msg.signature, signature, 64UL );
  msg.lamports   = info->lamports;
  msg.slot       = slot;
  msg.data_sz    = data_sz;
  msg.executable = info->executable;
  fd_memcpy( dst, &msg, sizeof(msg) );

  ulong ctl = fd_frag_meta_ctl( 0UL, 1UL, 1UL, 0UL );
  fd_mcache_publish( buf->mcache, buf->depth, buf->seq, 0UL, buf->chunk, sizeof(msg), ctl, 0UL, 0UL );
  buf->chunk = fd_dcache_compact_next( buf->chunk, sizeof(msg), buf->chunk0, buf->wmark );
  buf->seq++;
}

void
fd_capture_link_write_account_update_buf( fd_capture_ctx_t *               ctx,
                                          ulong                            txn_idx,
                                          fd_pubkey_t const *              key,
                                          fd_solana_account_meta_t const * info,
                                          ulong                            slot,
                                          uchar const *                    data,
                                          ulong                            data_sz ) {

  if( FD_UNLIKELY( !ctx || !ctx->capctx_type.buf ) ) FD_LOG_ERR(( "NULL ctx (%p) or buf (%p)", (void *)ctx, (void *)ctx->capctx_type.buf ));
  if( FD_UNLIKELY( !valid_slot_range( ctx, slot ) ) ) return;

  fd_capture_link_buf_t * buf = ctx->capctx_type.buf;
  wait_to_write_solcap_msg( buf );

  ulong msg_sz = sizeof(fd_solcap_buf_msg_t) + sizeof(fd_solcap_account_update_hdr_t);

  uchar * dst = (uchar *)fd_chunk_to_laddr( buf->mem, buf->chunk );
  char * ptr = (char *)dst;

  fd_solcap_buf_msg_t msg = {
    .sig     = SOLCAP_WRITE_ACCOUNT,
    .slot    = slot,
    .txn_idx = txn_idx,
  };
  fd_memcpy( ptr, &msg, sizeof(fd_solcap_buf_msg_t) );
  ptr += sizeof(fd_solcap_buf_msg_t);

  fd_solcap_account_update_hdr_t account_hdr = {
    .key     = *key,
    .info    = *info,
    .data_sz = data_sz,
  };

  fd_memcpy( ptr, &account_hdr, sizeof(fd_solcap_account_update_hdr_t) );

  ulong write_cnt = (data_sz + SOLCAP_WRITE_ACCOUNT_DATA_MTU - 1) / SOLCAP_WRITE_ACCOUNT_DATA_MTU;
  if( data_sz == 0 ) write_cnt = 0;

  int has_data = (write_cnt > 0);
  ulong ctl = fd_frag_meta_ctl( 0UL, 1UL, has_data ? 0UL : 1UL, 0UL );
  fd_mcache_publish( buf->mcache, buf->depth, buf->seq, 0UL, buf->chunk, msg_sz, ctl, 0UL, 0UL );
  buf->chunk = fd_dcache_compact_next( buf->chunk, msg_sz, buf->chunk0, buf->wmark );
  buf->seq++;

  if( !has_data ) return;

  for ( ulong i = 0; i < write_cnt; i++ ) {
    wait_to_write_solcap_msg( buf );

    dst = (uchar *)fd_chunk_to_laddr( buf->mem, buf->chunk );
    ptr = (char *)dst;

    ulong fragment_data_sz = SOLCAP_WRITE_ACCOUNT_DATA_MTU;
    int is_last = (i == write_cnt - 1);

    if( is_last ) {
      fragment_data_sz = data_sz - i * SOLCAP_WRITE_ACCOUNT_DATA_MTU;
    }

    fd_memcpy( ptr, data + i * SOLCAP_WRITE_ACCOUNT_DATA_MTU, fragment_data_sz );

    msg_sz = fragment_data_sz;

    ctl = fd_frag_meta_ctl( 0UL, 0UL, is_last ? 1UL : 0UL, 0UL );

    fd_mcache_publish( buf->mcache, buf->depth, buf->seq, 0UL, buf->chunk, msg_sz, ctl, 0UL, 0UL );
    buf->chunk = fd_dcache_compact_next( buf->chunk, msg_sz, buf->chunk0, buf->wmark );
    buf->seq++;
  }

}

void
fd_capture_link_write_account_update_file( fd_capture_ctx_t *               ctx,
                                           ulong                            txn_idx,
                                           fd_pubkey_t const *              key,
                                           fd_solana_account_meta_t const * info,
                                           ulong                            slot,
                                           uchar const *                    data,
                                           ulong                            data_sz ) {
  if( FD_UNLIKELY( !ctx || !ctx->capture ) ) return;
  if( FD_UNLIKELY( !valid_slot_range( ctx, slot ) ) ) return;

  fd_solcap_writer_t * writer = ctx->capture;

  /* Prepare message header */
  fd_solcap_buf_msg_t msg_hdr = {
    .sig = SOLCAP_WRITE_ACCOUNT,
    .slot = slot,
    .txn_idx = txn_idx,
  };

  /* Prepare account update header */
  fd_solcap_account_update_hdr_t account_update = {
    .key = *key,
    .info = *info,
    .data_sz = data_sz,
  };

  /* Write the header (EPB + internal header + account metadata) */
  uint block_len = fd_solcap_write_account_hdr( writer, &msg_hdr, &account_update );

  /* Write the account data */
  fd_solcap_write_data( writer, data, data_sz );

  /* Write the footer */
  fd_solcap_write_ftr( writer, block_len );
}

void
fd_capture_link_write_bank_preimage_buf( fd_capture_ctx_t * ctx,
                                         ulong              slot,
                                         fd_hash_t const *  bank_hash,
                                         fd_hash_t const *  prev_bank_hash,
                                         fd_hash_t const *  accounts_lt_hash_checksum,
                                         fd_hash_t const *  poh_hash,
                                         ulong              signature_cnt) {
  if( FD_UNLIKELY( !ctx || !ctx->capctx_type.buf ) ) FD_LOG_ERR(( "NULL ctx (%p) or buf (%p)", (void *)ctx, (void *)ctx->capctx_type.buf ));
  if ( FD_UNLIKELY( !valid_slot_range( ctx, slot ) ) ) return;

  fd_capture_link_buf_t * buf = ctx->capctx_type.buf;

  wait_to_write_solcap_msg( buf );

  uchar * dst = (uchar *)fd_chunk_to_laddr( buf->mem, buf->chunk );
  char * ptr = (char *)dst;

  fd_solcap_buf_msg_t msg = {
    .sig = SOLCAP_WRITE_BANK_PREIMAGE,
    .slot = slot,
    .txn_idx = 0
  };
  fd_memcpy( ptr, &msg, sizeof(fd_solcap_buf_msg_t) );
  ptr += sizeof(fd_solcap_buf_msg_t);

  fd_solcap_bank_preimage_t bank_preimage = {
    .bank_hash = *bank_hash,
    .prev_bank_hash = *prev_bank_hash,
    .accounts_lt_hash_checksum = *accounts_lt_hash_checksum,
    .poh_hash = *poh_hash,
    .signature_cnt = signature_cnt
  };
  fd_memcpy( ptr, &bank_preimage, sizeof(fd_solcap_bank_preimage_t) );
  ulong ctl = fd_frag_meta_ctl( 0UL, 1UL, 1UL, 0UL );
  fd_mcache_publish( buf->mcache, buf->depth, buf->seq, 0UL, buf->chunk, sizeof(fd_solcap_buf_msg_t) + sizeof(fd_solcap_bank_preimage_t), ctl, 0UL, 0UL );
  buf->chunk = fd_dcache_compact_next( buf->chunk, sizeof(fd_solcap_buf_msg_t) + sizeof(fd_solcap_bank_preimage_t), buf->chunk0, buf->wmark );
  buf->seq++;
}

void
fd_capture_link_write_bank_preimage_file( fd_capture_ctx_t * ctx,
                                          ulong              slot,
                                          fd_hash_t const *  bank_hash,
                                          fd_hash_t const *  prev_bank_hash,
                                          fd_hash_t const *  accounts_lt_hash_checksum,
                                          fd_hash_t const *  poh_hash,
                                          ulong              signature_cnt ) {
  if( FD_UNLIKELY( !ctx || !ctx->capture ) ) return;
  if ( FD_UNLIKELY( !valid_slot_range( ctx, slot ) ) ) return;

  fd_solcap_writer_t * writer = ctx->capture;

  fd_solcap_buf_msg_t msg_hdr = {
    .sig = SOLCAP_WRITE_BANK_PREIMAGE,
    .slot = slot,
    .txn_idx = 0
  };

  fd_solcap_bank_preimage_t bank_preimage = {
    .bank_hash = *bank_hash,
    .prev_bank_hash = *prev_bank_hash,
    .accounts_lt_hash_checksum = *accounts_lt_hash_checksum,
    .poh_hash = *poh_hash,
    .signature_cnt = signature_cnt
  };

  uint block_len = fd_solcap_write_bank_preimage( writer, &msg_hdr, &bank_preimage );

  fd_solcap_write_ftr( writer, block_len );
}

void
fd_capture_link_write_stake_rewards_begin_buf( fd_capture_ctx_t * ctx,
                                               ulong              slot,
                                               ulong              payout_epoch,
                                               ulong              reward_epoch,
                                               ulong              inflation_lamports,
                                               ulong              total_points ) {
  if( FD_UNLIKELY( !ctx || !ctx->capctx_type.buf ) ) FD_LOG_ERR(( "NULL ctx (%p) or buf (%p)", (void *)ctx, (void *)ctx->capctx_type.buf ));
  if ( FD_UNLIKELY( !valid_slot_range( ctx, slot ) ) ) return;

  fd_capture_link_buf_t * buf = ctx->capctx_type.buf;

  wait_to_write_solcap_msg( buf );

  uchar * dst = (uchar *)fd_chunk_to_laddr( buf->mem, buf->chunk );
  char * ptr = (char *)dst;

  fd_solcap_buf_msg_t msg = {
    .sig = SOLCAP_STAKE_REWARDS_BEGIN,
    .slot = slot,
    .txn_idx = 0
  };

  fd_memcpy( ptr, &msg, sizeof(fd_solcap_buf_msg_t) );
  ptr += sizeof(fd_solcap_buf_msg_t);

  fd_solcap_stake_rewards_begin_t stake_rewards_begin = {
    .payout_epoch = payout_epoch,
    .reward_epoch = reward_epoch,
    .inflation_lamports = inflation_lamports,
    .total_points = total_points
  };
  fd_memcpy( ptr, &stake_rewards_begin, sizeof(fd_solcap_stake_rewards_begin_t) );
  ulong ctl = fd_frag_meta_ctl( 0UL, 1UL, 1UL, 0UL );
  fd_mcache_publish( buf->mcache, buf->depth, buf->seq, 0UL, buf->chunk, sizeof(fd_solcap_buf_msg_t) + sizeof(fd_solcap_stake_rewards_begin_t), ctl, 0UL, 0UL );
  buf->chunk = fd_dcache_compact_next( buf->chunk, sizeof(fd_solcap_buf_msg_t) + sizeof(fd_solcap_stake_rewards_begin_t), buf->chunk0, buf->wmark );
  buf->seq++;
}

void
fd_capture_link_write_stake_rewards_begin_file( fd_capture_ctx_t * ctx,
                                                ulong              slot,
                                                ulong              payout_epoch,
                                                ulong              reward_epoch,
                                                ulong              inflation_lamports,
                                                ulong              total_points ) {
  if( FD_UNLIKELY( !ctx || !ctx->capture ) ) return;
  if ( FD_UNLIKELY( !valid_slot_range( ctx, slot ) ) ) return;

  fd_solcap_writer_t * writer = ctx->capture;

  fd_solcap_buf_msg_t msg_hdr = {
    .sig = SOLCAP_STAKE_REWARDS_BEGIN,
    .slot = slot,
    .txn_idx = 0
  };

  fd_solcap_stake_rewards_begin_t stake_rewards_begin = {
    .payout_epoch = payout_epoch,
    .reward_epoch = reward_epoch,
    .inflation_lamports = inflation_lamports,
    .total_points = total_points
  };

  uint block_len = fd_solcap_write_stake_rewards_begin( writer, &msg_hdr, &stake_rewards_begin );

  fd_solcap_write_ftr( writer, block_len );
}

void
fd_capture_link_write_stake_reward_event_buf( fd_capture_ctx_t * ctx,
                                              ulong              slot,
                                              fd_pubkey_t        stake_acc_addr,
                                              fd_pubkey_t        vote_acc_addr,
                                              uint               commission,
                                              long               vote_rewards,
                                              long               stake_rewards,
                                              long               new_credits_observed ) {
  if( FD_UNLIKELY( !ctx || !ctx->capctx_type.buf ) ) FD_LOG_ERR(( "NULL ctx (%p) or buf (%p)", (void *)ctx, (void *)ctx->capctx_type.buf ));
  if ( FD_UNLIKELY( !valid_slot_range( ctx, slot ) ) ) return;

  fd_capture_link_buf_t * buf = ctx->capctx_type.buf;

  wait_to_write_solcap_msg( buf );

  uchar * dst = (uchar *)fd_chunk_to_laddr( buf->mem, buf->chunk );
  char * ptr = (char *)dst;

  fd_solcap_buf_msg_t msg = {
    .sig = SOLCAP_STAKE_REWARD_EVENT,
    .slot = slot,
    .txn_idx = 0
  };
  fd_memcpy( ptr, &msg, sizeof(fd_solcap_buf_msg_t) );
  ptr += sizeof(fd_solcap_buf_msg_t);

  fd_solcap_stake_reward_event_t stake_reward_event = {
    .stake_acc_addr = stake_acc_addr,
    .vote_acc_addr = vote_acc_addr,
    .commission = commission,
    .vote_rewards = vote_rewards,
    .stake_rewards = stake_rewards,
    .new_credits_observed = new_credits_observed
  };
  fd_memcpy( ptr, &stake_reward_event, sizeof(fd_solcap_stake_reward_event_t) );
  ulong ctl = fd_frag_meta_ctl( 0UL, 1UL, 1UL, 0UL );
  fd_mcache_publish( buf->mcache, buf->depth, buf->seq, 0UL, buf->chunk, sizeof(fd_solcap_buf_msg_t) + sizeof(fd_solcap_stake_reward_event_t), ctl, 0UL, 0UL );
  buf->chunk = fd_dcache_compact_next( buf->chunk, sizeof(fd_solcap_buf_msg_t) + sizeof(fd_solcap_stake_reward_event_t), buf->chunk0, buf->wmark );
  buf->seq++;
}

void
fd_capture_link_write_stake_reward_event_file( fd_capture_ctx_t * ctx,
                                              ulong              slot,
                                              fd_pubkey_t        stake_acc_addr,
                                              fd_pubkey_t        vote_acc_addr,
                                              uint               commission,
                                              long               vote_rewards,
                                              long               stake_rewards,
                                              long               new_credits_observed ) {
  if( FD_UNLIKELY( !ctx || !ctx->capture ) ) return;
  if ( FD_UNLIKELY( !valid_slot_range( ctx, slot ) ) ) return;

  fd_solcap_writer_t * writer = ctx->capture;

  fd_solcap_buf_msg_t msg_hdr = {
    .sig = SOLCAP_STAKE_REWARD_EVENT,
    .slot = slot,
    .txn_idx = 0
  };

  fd_solcap_stake_reward_event_t stake_reward_event = {
    .stake_acc_addr = stake_acc_addr,
    .vote_acc_addr = vote_acc_addr,
    .commission = commission,
    .vote_rewards = vote_rewards,
    .stake_rewards = stake_rewards,
    .new_credits_observed = new_credits_observed
  };
  uint block_len = fd_solcap_write_stake_reward_event( writer, &msg_hdr, &stake_reward_event );
  fd_solcap_write_ftr( writer, block_len );
}

void
fd_capture_link_write_stake_account_payout_buf( fd_capture_ctx_t * ctx,
                                                ulong              slot,
                                                fd_pubkey_t        stake_acc_addr,
                                                ulong              update_slot,
                                                ulong              lamports,
                                                long               lamports_delta,
                                                ulong              credits_observed,
                                                long               credits_observed_delta,
                                                ulong              delegation_stake,
                                                long               delegation_stake_delta ) {
  if( FD_UNLIKELY( !ctx || !ctx->capctx_type.buf ) ) FD_LOG_ERR(( "NULL ctx (%p) or buf (%p)", (void *)ctx, (void *)ctx->capctx_type.buf ));
  if ( FD_UNLIKELY( !valid_slot_range( ctx, slot ) ) ) return;

  fd_capture_link_buf_t * buf = ctx->capctx_type.buf;

  wait_to_write_solcap_msg( buf );

  uchar * dst = (uchar *)fd_chunk_to_laddr( buf->mem, buf->chunk );
  char * ptr = (char *)dst;

  fd_solcap_buf_msg_t msg = {
    .sig = SOLCAP_STAKE_ACCOUNT_PAYOUT,
    .slot = slot,
    .txn_idx = 0
  };
  fd_memcpy( ptr, &msg, sizeof(fd_solcap_buf_msg_t) );
  ptr += sizeof(fd_solcap_buf_msg_t);

  fd_solcap_stake_account_payout_t stake_account_payout = {
    .stake_acc_addr = stake_acc_addr,
    .update_slot = update_slot,
    .lamports = lamports,
    .lamports_delta = lamports_delta,
    .credits_observed = credits_observed,
    .credits_observed_delta = credits_observed_delta,
    .delegation_stake = delegation_stake,
    .delegation_stake_delta = delegation_stake_delta,
  };
  fd_memcpy( ptr, &stake_account_payout, sizeof(fd_solcap_stake_account_payout_t) );
  ulong ctl = fd_frag_meta_ctl( 0UL, 1UL, 1UL, 0UL );
  fd_mcache_publish( buf->mcache, buf->depth, buf->seq, 0UL, buf->chunk, sizeof(fd_solcap_buf_msg_t) + sizeof(fd_solcap_stake_account_payout_t), ctl, 0UL, 0UL );
  buf->chunk = fd_dcache_compact_next( buf->chunk, sizeof(fd_solcap_buf_msg_t) + sizeof(fd_solcap_stake_account_payout_t), buf->chunk0, buf->wmark );
  buf->seq++;
}

void
fd_capture_link_write_stake_account_payout_file( fd_capture_ctx_t * ctx,
                                                ulong              slot,
                                                fd_pubkey_t        stake_acc_addr,
                                                ulong              update_slot,
                                                ulong              lamports,
                                                long               lamports_delta,
                                                ulong              credits_observed,
                                                long               credits_observed_delta,
                                                ulong              delegation_stake,
                                                long               delegation_stake_delta ) {
  if( FD_UNLIKELY( !ctx || !ctx->capture ) ) return;
  if( FD_UNLIKELY( !valid_slot_range( ctx, slot ) ) ) return;

  fd_solcap_writer_t * writer = ctx->capture;

  fd_solcap_buf_msg_t msg_hdr = {
    .sig = SOLCAP_STAKE_ACCOUNT_PAYOUT,
    .slot = slot,
    .txn_idx = 0
  };

  fd_solcap_stake_account_payout_t stake_account_payout = {
    .stake_acc_addr = stake_acc_addr,
    .update_slot = update_slot,
    .lamports = lamports,
    .lamports_delta = lamports_delta,
    .credits_observed = credits_observed,
    .credits_observed_delta = credits_observed_delta,
    .delegation_stake = delegation_stake,
    .delegation_stake_delta = delegation_stake_delta,
  };
  uint block_len = fd_solcap_write_stake_account_payout( writer, &msg_hdr, &stake_account_payout );
  fd_solcap_write_ftr( writer, block_len );
}
