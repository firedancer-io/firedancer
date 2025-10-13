#include "../../disco/topo/fd_topo.h"
#include "../../util/pod/fd_pod.h"
#include "../../util/log/fd_log.h"

#include <stdio.h>

#include "../../flamenco/runtime/context/fd_capture_ctx.h"
#include "../../flamenco/capture/fd_solcap_writer.h"

/* The capture context tile is responsible for managing capture context
   for debugging runtime execution. It handles initialization and cleanup
   of capture contexts used by other tiles. */


struct fd_capture_tile_ctx {
  ulong tile_idx;

  /* Capture context management */
  fd_capture_ctx_t * capture_ctx;
  fd_capctx_buf_t * capctx_buf;

  FILE * file;
};

typedef struct fd_capture_tile_ctx fd_capture_tile_ctx_t;



FD_FN_CONST static inline ulong
scratch_align( void ) {
  return 128UL;
}

FD_FN_PURE static inline ulong
scratch_footprint( fd_topo_tile_t const * tile ) {
  (void)tile;
  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, alignof(fd_capture_tile_ctx_t), sizeof(fd_capture_tile_ctx_t) );
  l = FD_LAYOUT_APPEND( l, fd_capture_ctx_align(), fd_capture_ctx_footprint() );
  return FD_LAYOUT_FINI( l, scratch_align() );
}

ulong
fd_capctx_buf_reader_aquire_lock( fd_capctx_buf_t * capctx_buf ) {
  ulong reader_idx = capctx_buf->reader_idx;
  ulong next_read_idx = reader_idx + 1;
  ulong buf_idx = next_read_idx % FD_CAPCTX_BUF_CNT;

  if ( next_read_idx == FD_VOLATILE_CONST( capctx_buf->writer_idx ) ||
       FD_VOLATILE_CONST( capctx_buf->reserve_flags[buf_idx] ) != 1U ) {
    return ULONG_MAX;
  }

  return buf_idx;
}

void
fd_capctx_buf_reader_release_lock( fd_capctx_buf_t * capctx_buf,
                                   ulong buf_idx ) {
  /* Clear the reserve flag and update reader index */
  FD_ATOMIC_CAS( &capctx_buf->reserve_flags[buf_idx], 1U, 0U );
  FD_ATOMIC_FETCH_AND_ADD( &capctx_buf->reader_idx, 1UL );
}


void
fd_capctx_buf_process_msg(fd_capture_ctx_t * capture_ctx,
                          ulong sig,
                          char * actual_data ) {
    switch ( sig ) {
    case SIG_SOLCAP_WRITE_ACCOUNT:
      {
        /* Read account update data directly from buffer */
        char * read_ptr = actual_data;
        fd_pubkey_t * key = (fd_pubkey_t *)read_ptr;
        read_ptr += sizeof(fd_pubkey_t);

        fd_solana_account_meta_t * info = (fd_solana_account_meta_t *)read_ptr;
        read_ptr += sizeof(fd_solana_account_meta_t);

        ulong * data_sz = (ulong *)read_ptr;
        read_ptr += sizeof(ulong);

        uchar * data = (uchar *)read_ptr;

        fd_solcap_write_account( capture_ctx->capture, key, info, data, *data_sz );
        break;
      }
    case SIG_SOLCAP_STAKE_ACCOUNT_PAYOUT:
      {
        fd_solcap_buf_msg_stake_account_payout_t * stake_account_payout = (fd_solcap_buf_msg_stake_account_payout_t *)actual_data;
        fd_solcap_write_stake_account_payout( capture_ctx->capture, &stake_account_payout->stake_acc_addr, stake_account_payout->update_slot, stake_account_payout->lamports, stake_account_payout->lamports_delta, stake_account_payout->credits_observed, stake_account_payout->credits_observed_delta, stake_account_payout->delegation_stake, stake_account_payout->delegation_stake_delta );
        break;
      }
    case SIG_SOLCAP_STAKE_REWARDS_BEGIN:
      {
        fd_solcap_buf_msg_stake_rewards_begin_t * stake_rewards_begin = (fd_solcap_buf_msg_stake_rewards_begin_t *)actual_data;
        fd_solcap_writer_stake_rewards_begin( capture_ctx->capture, stake_rewards_begin->payout_epoch, stake_rewards_begin->reward_epoch, stake_rewards_begin->inflation_lamports, stake_rewards_begin->total_points );
        break;
      }
    case SIG_SOLCAP_WRITE_BANK_PREIMAGE:
      {
        fd_solcap_buf_msg_bank_preimage_t * bank_preimage = (fd_solcap_buf_msg_bank_preimage_t *)actual_data;
        fd_solcap_write_bank_preimage( capture_ctx->capture, bank_preimage->bank_hash, bank_preimage->prev_bank_hash, bank_preimage->account_delta_hash, bank_preimage->accounts_lt_hash_checksum, bank_preimage->poh_hash, bank_preimage->signature_cnt );
        break;
      }
    case SIG_SOLCAP_WRITE_STAKE_REWARD_EVENT:
      {
        fd_solcap_buf_msg_stake_reward_event_t * stake_reward_event = (fd_solcap_buf_msg_stake_reward_event_t *)actual_data;
        fd_solcap_write_stake_reward_event( capture_ctx->capture, &stake_reward_event->stake_acc_addr, &stake_reward_event->vote_acc_addr, stake_reward_event->commission, stake_reward_event->vote_rewards, stake_reward_event->stake_rewards, stake_reward_event->new_credits_observed );
        break;
      }
    case SIG_SOLCAP_WRITE_VOTE_ACCOUNT_PAYOUT:
      {
        fd_solcap_buf_msg_vote_account_payout_t * vote_account_payout = (fd_solcap_buf_msg_vote_account_payout_t *)actual_data;
        fd_solcap_write_vote_account_payout( capture_ctx->capture, &vote_account_payout->vote_acc_addr, vote_account_payout->update_slot, vote_account_payout->lamports, vote_account_payout->lamports_delta );
        break;
      }
    case SIG_SOLCAP_SET_SLOT:
      {
        fd_solcap_buf_msg_set_slot_t * set_slot = (fd_solcap_buf_msg_set_slot_t *)actual_data;
        fd_solcap_writer_set_slot( capture_ctx->capture, set_slot->slot );
        break;
      }
    case SIG_SOLCAP_FLUSH:
      {
        fd_solcap_writer_flush( capture_ctx->capture );
        break;
      }
    default:
      FD_LOG_NOTICE(("read and write indices: %lu %lu", capture_ctx->capctx_buf->reader_idx + 1, FD_VOLATILE( capture_ctx->capctx_buf->writer_idx ) ));
      FD_LOG_ERR(( "Unknown signal: %lu", sig ));
      break;
  }
}


static inline void
after_credit( fd_capture_tile_ctx_t * ctx,
              fd_stem_context_t *    stem,
              int *                  opt_poll_in,
              int *                  charge_busy ) {
  (void)ctx;
  (void)stem;
  (void)opt_poll_in;
  (void)charge_busy;

  fd_capctx_buf_t * capctx_buf = ctx->capture_ctx->capctx_buf;

  ulong buf_idx = fd_capctx_buf_reader_aquire_lock( capctx_buf );
  if ( buf_idx == ULONG_MAX ) {
    return;
  }

  fd_solcap_buf_msg_t * msg = (fd_solcap_buf_msg_t *)&capctx_buf->buffer[buf_idx * FD_CAPCTX_BUF_MTU];
  char * actual_data = (char *)msg + sizeof(ushort);  /* Skip past sig to get to actual data */

  fd_capctx_buf_process_msg( ctx->capture_ctx, msg->sig, actual_data);

  fd_capctx_buf_reader_release_lock( capctx_buf, buf_idx );
}

static void
privileged_init( fd_topo_t *      topo,
                 fd_topo_tile_t * tile ) {
  void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );

  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_capture_tile_ctx_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_capture_tile_ctx_t), sizeof(fd_capture_tile_ctx_t) );
  void * _capture_ctx         = FD_SCRATCH_ALLOC_APPEND( l, fd_capture_ctx_align(), fd_capture_ctx_footprint() );

  ctx->tile_idx = tile->kind_id;

  ulong capctx_buf_obj_id = fd_pod_query_ulong( topo->props, "capctx_buf", ULONG_MAX );
  FD_LOG_NOTICE(( "Replay tile querying capctx_buf_obj_id: %lu", capctx_buf_obj_id ));
  FD_TEST( capctx_buf_obj_id!=ULONG_MAX );
  ctx->capctx_buf = fd_capctx_buf_join( fd_topo_obj_laddr( topo, capctx_buf_obj_id ) );
  FD_TEST( ctx->capctx_buf );

  /* Initialize capture context */
  ctx->capture_ctx = fd_capture_ctx_join( fd_capture_ctx_new( _capture_ctx ) );
  FD_TEST( ctx->capture_ctx );
  FD_LOG_NOTICE(( "Replay tile querying solcap_capture: %s", tile->capctx.solcap_capture ));
  ctx->file = fopen( tile->capctx.solcap_capture, "w+" );
  FD_TEST( ctx->file );
  FD_TEST( ctx->capture_ctx->capture );
  ctx->capture_ctx->solcap_start_slot = 0UL;
  fd_solcap_writer_init( ctx->capture_ctx->capture, ctx->file );

  ctx->capture_ctx->capctx_buf = ctx->capctx_buf;

  ulong scratch_top = FD_SCRATCH_ALLOC_FINI( l, scratch_align() );
  if( FD_UNLIKELY( scratch_top > (ulong)scratch + scratch_footprint( tile ) ) )
    FD_LOG_ERR(( "scratch overflow %lu %lu %lu", scratch_top - (ulong)scratch - scratch_footprint( tile ), scratch_top, (ulong)scratch + scratch_footprint( tile ) ));
}


#define STEM_BURST (1UL)
#define STEM_LAZY  (50UL)

#define STEM_CALLBACK_CONTEXT_TYPE  fd_capture_tile_ctx_t
#define STEM_CALLBACK_CONTEXT_ALIGN alignof(fd_capture_tile_ctx_t)

#define STEM_CALLBACK_AFTER_CREDIT    after_credit

#include "../../disco/stem/fd_stem.c"

fd_topo_run_tile_t fd_tile_captur = {
  .name                     = "captur",
  .scratch_align            = scratch_align,
  .scratch_footprint        = scratch_footprint,
  .privileged_init          = privileged_init,
  .run                      = stem_run
};
