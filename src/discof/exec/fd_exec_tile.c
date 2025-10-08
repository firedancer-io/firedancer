#include "../../disco/tiles.h"
#include "generated/fd_exec_tile_seccomp.h"

#include "../../util/pod/fd_pod_format.h"
#include "../../disco/fd_txn_m.h"
#include "../../discof/replay/fd_exec.h"
#include "../../discof/replay/fd_vote_tracker.h"
#include "../../flamenco/runtime/context/fd_capture_ctx.h"
#include "../../flamenco/runtime/fd_bank.h"
#include "../../flamenco/runtime/fd_runtime.h"
#include "../../disco/metrics/fd_metrics.h"

#include "../../funk/fd_funk.h"

/* The exec tile is responsible for executing single transactions. The
   tile recieves a parsed transaction (fd_txn_p_t) and an identifier to
   which bank to execute against (index into the bank pool). With this,
   the exec tile is able to identify the correct bank and accounts db
   handle (funk_txn) to execute the transaction against.  The exec tile
   then commits the results of the transaction to the accounts db and
   makes any necessary updates to the bank. */

typedef struct link_ctx {
  ulong       idx;
  fd_wksp_t * mem;
  ulong       chunk;
  ulong       chunk0;
  ulong       wmark;
} link_ctx_t;

typedef struct fd_exec_tile_ctx {

  ulong                 tile_idx;

  /* link-related data structures. */
  link_ctx_t            replay_in[ 1 ];
  link_ctx_t            send_in[ 1 ];
  link_ctx_t            exec_replay_out[ 1 ]; /* TODO: Remove with solcap v2 */

  fd_bank_hash_cmp_t *  bank_hash_cmp;

  fd_spad_t *           exec_spad;
  fd_wksp_t *           exec_spad_wksp;

  /* Data structures related to managing and executing the transaction.
     The fd_txn_p_t is refreshed with every transaction and is sent
     from the dispatch/replay tile. The fd_exec_txn_ctx_t * is a valid
     local join that lives in the top-most frame of the spad that is
     setup when the exec tile is booted; its members are refreshed on
     the slot/epoch boundary. */
  fd_exec_txn_ctx_t *   txn_ctx;

  /* Capture context for debugging runtime execution. */
  fd_capture_ctx_t *    capture_ctx;
  uchar *               solcap_publish_buffer_ptr;
  ulong                 account_updates_flushed;

  /* A transaction can be executed as long as there is a valid handle to
     a funk_txn and a bank. These are queried from fd_banks_t and
     fd_funk_t.
     TODO: These should probably be made read-only handles. */
  fd_banks_t *          banks;
  fd_funk_t             funk[ 1 ];

  fd_txncache_t *       txncache;

  fd_vote_tracker_t *   vote_tracker;
  fd_signature_t        vote_signature[ 1 ];

  /* We need to ensure that all solcap updates have been published
     before this message. */
  int                   pending_txn_finalized_msg;
} fd_exec_tile_ctx_t;

FD_FN_CONST static inline ulong
scratch_align( void ) {
  return 128UL;
}

FD_FN_PURE static inline ulong
scratch_footprint( fd_topo_tile_t const * tile ) {
  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, alignof(fd_exec_tile_ctx_t), sizeof(fd_exec_tile_ctx_t)                         );
  l = FD_LAYOUT_APPEND( l, fd_capture_ctx_align(),      fd_capture_ctx_footprint()                         );
  l = FD_LAYOUT_APPEND( l, fd_txncache_align(),         fd_txncache_footprint( tile->exec.max_live_slots ) );
  l = FD_LAYOUT_APPEND( l, fd_vote_tracker_align(),     fd_vote_tracker_footprint() );
  return FD_LAYOUT_FINI( l, scratch_align() );
}

static int
before_frag( fd_exec_tile_ctx_t * ctx,
             ulong                in_idx FD_FN_UNUSED,
             ulong                seq    FD_FN_UNUSED,
             ulong                sig ) {
  return (sig&0xFFFFFFFFUL)!=ctx->tile_idx;
}

static void
during_frag( fd_exec_tile_ctx_t * ctx,
             ulong                in_idx,
             ulong                seq FD_PARAM_UNUSED,
             ulong                sig,
             ulong                chunk,
             ulong                sz,
             ulong                ctl FD_PARAM_UNUSED ) {
  if( FD_LIKELY( in_idx==ctx->replay_in->idx ) ) {
    if( FD_UNLIKELY( chunk < ctx->replay_in->chunk0 || chunk > ctx->replay_in->wmark ) ) {
      FD_LOG_ERR(( "chunk %lu %lu corrupt, not in range [%lu,%lu]",
                   chunk,
                   sz,
                   ctx->replay_in->chunk0,
                   ctx->replay_in->wmark ));
    }
    if( FD_LIKELY( (sig>>32)==FD_REPLAY_EXEC_NEW_TXN_SIG ) ) {
      fd_exec_txn_msg_t * txn = (fd_exec_txn_msg_t *)fd_chunk_to_laddr( ctx->replay_in->mem, chunk );

      ctx->txn_ctx->exec_err = fd_runtime_prepare_and_execute_txn(
          ctx->banks,
          txn->bank_idx,
          ctx->txn_ctx,
          &txn->txn,
          ctx->exec_spad,
          ctx->capture_ctx,
          1 );
    } else {
      FD_LOG_CRIT(( "Unknown signature %lu", sig ));
    }
  }
  else if( FD_LIKELY( in_idx==ctx->send_in->idx ) ) {
    fd_txn_m_t * txnm    = fd_type_pun( fd_chunk_to_laddr( ctx->send_in->mem, chunk ) );
    uchar *      payload = ((uchar *)txnm) + sizeof(fd_txn_m_t);
    uchar        txn_mem[ FD_TXN_MAX_SZ ] __attribute__((aligned(alignof(fd_txn_t))));
    fd_txn_t *   txn = (fd_txn_t *)txn_mem;
    if( FD_UNLIKELY( !fd_txn_parse( payload, txnm->payload_sz, txn_mem, NULL ) ) ) {
      FD_LOG_CRIT(( "Could not parse txn from send tile" ));
    }
    FD_STATIC_ASSERT( sizeof(*ctx->vote_signature) == FD_TXN_SIGNATURE_SZ, sizeof );
    fd_memcpy( ctx->vote_signature, payload + txn->signature_off, FD_TXN_SIGNATURE_SZ );
  }
  else FD_LOG_ERR(( "invalid in_idx %lu", in_idx ));
}

static void
after_frag( fd_exec_tile_ctx_t * ctx,
            ulong                in_idx,
            ulong                seq    FD_PARAM_UNUSED,
            ulong                sig,
            ulong                sz     FD_PARAM_UNUSED,
            ulong                tsorig FD_PARAM_UNUSED,
            ulong                tspub  FD_PARAM_UNUSED,
            fd_stem_context_t *  stem   FD_PARAM_UNUSED ) {
  if( FD_LIKELY( in_idx==ctx->replay_in->idx ) ) {
    if( FD_LIKELY( (sig>>32)==FD_REPLAY_EXEC_NEW_TXN_SIG ) ) {
      /* At this point we can assume that the transaction is done
         executing.  Commit the transaction back to funk. */

      fd_bank_t * bank = fd_banks_bank_query( ctx->banks, ctx->txn_ctx->bank_idx );
      if( FD_UNLIKELY( !bank ) ) {
        FD_LOG_CRIT(( "Could not find bank for slot %lu", ctx->txn_ctx->slot ));
      }
      ctx->txn_ctx->bank = bank;

      fd_funk_txn_xid_t xid = (fd_funk_txn_xid_t){ .ul = { fd_bank_slot_get( bank ), fd_bank_slot_get( bank ) } };

      /* Query the vote signature against the recently generated vote txn
        signatures.  If the query is successful, then we have seen our
        own vote transaction and this should be marked in the bank. */
      uchar * txn_signature = ctx->txn_ctx->txn.payload + TXN( &ctx->txn_ctx->txn )->signature_off;
      if( fd_vote_tracker_query_sig( ctx->vote_tracker, (fd_signature_t *)txn_signature ) ) {
        FD_ATOMIC_FETCH_AND_ADD( fd_bank_has_identity_vote_modify( bank ), 1 );
      }

      if( FD_LIKELY( ctx->txn_ctx->flags & FD_TXN_P_FLAGS_EXECUTE_SUCCESS ) ) {
          fd_runtime_finalize_txn(
            ctx->funk,
            ctx->txncache,
            &xid,
            ctx->txn_ctx,
            bank,
            ctx->capture_ctx );
      } else {
        /* This means that we should mark the block as dead. */
        fd_banks_mark_bank_dead( ctx->banks, bank );
      }

      /* Notify the replay tile that we are done with this txn. */
      ctx->pending_txn_finalized_msg = 1;
    } else {
      FD_LOG_ERR(( "Unknown message signature %lu", sig ));
    }
  }
  else if( FD_LIKELY( in_idx==ctx->send_in->idx ) ) {
    /* This means that the send tile has signed and sent a vote.  Add
       this vote to the vote tracker. */
    fd_vote_tracker_insert( ctx->vote_tracker, ctx->vote_signature );
  }
  else FD_LOG_ERR(( "invalid in_idx %lu", in_idx ));
}

static void
unprivileged_init( fd_topo_t *      topo,
                   fd_topo_tile_t * tile ) {

  /********************************************************************/
  /* validate allocations                                             */
  /********************************************************************/

  void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );

  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_exec_tile_ctx_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_exec_tile_ctx_t), sizeof(fd_exec_tile_ctx_t) );
  void * capture_ctx_mem   = FD_SCRATCH_ALLOC_APPEND( l, fd_capture_ctx_align(),      fd_capture_ctx_footprint() );
  void * _txncache         = FD_SCRATCH_ALLOC_APPEND( l, fd_txncache_align(),         fd_txncache_footprint( tile->exec.max_live_slots ) );
  void * vote_tracker_mem  = FD_SCRATCH_ALLOC_APPEND( l, fd_vote_tracker_align(),     fd_vote_tracker_footprint() );
  ulong  scratch_alloc_mem = FD_SCRATCH_ALLOC_FINI( l, scratch_align() );

  if( FD_UNLIKELY( scratch_alloc_mem - (ulong)scratch  - scratch_footprint( tile ) ) ) {
    FD_LOG_ERR( ( "Scratch_alloc_mem did not match scratch_footprint diff: %lu alloc: %lu footprint: %lu",
      scratch_alloc_mem - (ulong)scratch - scratch_footprint( tile ),
      scratch_alloc_mem,
      (ulong)scratch + scratch_footprint( tile ) ) );
  }

  /********************************************************************/
  /* validate links                                                   */
  /********************************************************************/

  ctx->tile_idx = tile->kind_id;

  /* First find and setup the in-link from replay to exec. */
  ctx->replay_in->idx = fd_topo_find_tile_in_link( topo, tile, "replay_exec", 0UL );
  FD_TEST( ctx->replay_in->idx!=ULONG_MAX );
  fd_topo_link_t * replay_in_link = &topo->links[ tile->in_link_id[ ctx->replay_in->idx ] ];
  FD_TEST( replay_in_link!=NULL );
  ctx->replay_in->mem    = topo->workspaces[ topo->objs[ replay_in_link->dcache_obj_id ].wksp_id ].wksp;
  ctx->replay_in->chunk0 = fd_dcache_compact_chunk0( ctx->replay_in->mem, replay_in_link->dcache );
  ctx->replay_in->wmark  = fd_dcache_compact_wmark( ctx->replay_in->mem, replay_in_link->dcache, replay_in_link->mtu );
  ctx->replay_in->chunk  = ctx->replay_in->chunk0;

  ulong send_tile_cnt = fd_topo_tile_name_cnt( topo, "send" );
  if( send_tile_cnt>0UL ) {
    ctx->send_in->idx = fd_topo_find_tile_in_link( topo, tile, "send_txns", 0UL );
    FD_TEST( ctx->send_in->idx!=ULONG_MAX );
    fd_topo_link_t * send_in_link = &topo->links[ tile->in_link_id[ ctx->send_in->idx ] ];
    ctx->send_in->mem    = topo->workspaces[ topo->objs[ send_in_link->dcache_obj_id ].wksp_id ].wksp;
    ctx->send_in->chunk0 = fd_dcache_compact_chunk0( ctx->send_in->mem, send_in_link->dcache );
    ctx->send_in->wmark  = fd_dcache_compact_wmark( ctx->send_in->mem, send_in_link->dcache, send_in_link->mtu );
    ctx->send_in->chunk  = ctx->send_in->chunk0;
  }

  ctx->exec_replay_out->idx = fd_topo_find_tile_out_link( topo, tile, "exec_replay", ctx->tile_idx );
  if( FD_LIKELY( ctx->exec_replay_out->idx!=ULONG_MAX ) ) {
    fd_topo_link_t * exec_replay_link = &topo->links[ tile->out_link_id[ ctx->exec_replay_out->idx ] ];
    ctx->exec_replay_out->mem    = topo->workspaces[ topo->objs[ exec_replay_link->dcache_obj_id ].wksp_id ].wksp;
    ctx->exec_replay_out->chunk0 = fd_dcache_compact_chunk0( ctx->exec_replay_out->mem, exec_replay_link->dcache );
    ctx->exec_replay_out->wmark  = fd_dcache_compact_wmark( ctx->exec_replay_out->mem, exec_replay_link->dcache, exec_replay_link->mtu );
    ctx->exec_replay_out->chunk  = ctx->exec_replay_out->chunk0;
  }

  /********************************************************************/
  /* banks                                                            */
  /********************************************************************/

  ulong banks_obj_id = fd_pod_queryf_ulong( topo->props, ULONG_MAX, "banks" );
  if( FD_UNLIKELY( banks_obj_id==ULONG_MAX ) ) {
    FD_LOG_ERR(( "Could not find topology object for banks" ));
  }

  ctx->banks = fd_banks_join( fd_topo_obj_laddr( topo, banks_obj_id ) );
  if( FD_UNLIKELY( !ctx->banks ) ) {
    FD_LOG_ERR(( "Failed to join banks" ));
  }

  /********************************************************************/
  /* spad allocator                                                   */
  /********************************************************************/

  ulong exec_spad_obj_id = fd_pod_queryf_ulong( topo->props, ULONG_MAX, "exec_spad.%lu", ctx->tile_idx );
  if( FD_UNLIKELY( exec_spad_obj_id==ULONG_MAX ) ) {
    FD_LOG_ERR(( "Could not find topology object for exec spad" ));
  }

  ctx->exec_spad = fd_spad_join( fd_topo_obj_laddr( topo, exec_spad_obj_id ) );
  if( FD_UNLIKELY( !ctx->exec_spad ) ) {
    FD_LOG_ERR(( "Failed to join exec spad" ));
  }
  ctx->exec_spad_wksp = fd_wksp_containing( ctx->exec_spad );

  /********************************************************************/
  /* bank hash cmp                                                    */
  /********************************************************************/

  ulong bank_hash_cmp_obj_id = fd_pod_queryf_ulong( topo->props, ULONG_MAX, "bh_cmp" );
  if( FD_UNLIKELY( bank_hash_cmp_obj_id==ULONG_MAX ) ) {
    FD_LOG_ERR(( "Could not find topology object for bank hash cmp" ));
  }
  ctx->bank_hash_cmp = fd_bank_hash_cmp_join( fd_topo_obj_laddr( topo, bank_hash_cmp_obj_id ) );
  if( FD_UNLIKELY( !ctx->bank_hash_cmp ) ) {
    FD_LOG_ERR(( "Failed to join bank hash cmp" ));
  }

  /********************************************************************/
  /* funk-specific setup                                              */
  /********************************************************************/

  FD_TEST( fd_funk_join( ctx->funk, fd_topo_obj_laddr( topo, tile->exec.funk_obj_id ) ) );

  /********************************************************************/
  /* setup txncache                                                   */
  /********************************************************************/

  void * _txncache_shmem = fd_topo_obj_laddr( topo, tile->exec.txncache_obj_id );
  fd_txncache_shmem_t * txncache_shmem = fd_txncache_shmem_join( _txncache_shmem );
  FD_TEST( txncache_shmem );
  ctx->txncache = fd_txncache_join( fd_txncache_new( _txncache, txncache_shmem ) );
  FD_TEST( ctx->txncache );

  /********************************************************************/
  /* setup txn ctx                                                    */
  /********************************************************************/

  fd_spad_push( ctx->exec_spad );
  uchar * txn_ctx_mem         = fd_spad_alloc_check( ctx->exec_spad, FD_EXEC_TXN_CTX_ALIGN, FD_EXEC_TXN_CTX_FOOTPRINT );
  ctx->txn_ctx                = fd_exec_txn_ctx_join( fd_exec_txn_ctx_new( txn_ctx_mem ), ctx->exec_spad, ctx->exec_spad_wksp );
  ctx->txn_ctx->funk[0]       = *ctx->funk;
  ctx->txn_ctx->status_cache  = ctx->txncache;
  ctx->txn_ctx->bank_hash_cmp = ctx->bank_hash_cmp;
  ctx->txn_ctx->spad          = ctx->exec_spad;
  ctx->txn_ctx->spad_wksp     = ctx->exec_spad_wksp;

  /********************************************************************/
  /* Vote tracker                                                    */
  /********************************************************************/

  ctx->vote_tracker = fd_vote_tracker_join( fd_vote_tracker_new( vote_tracker_mem, 0UL ) );
  if( FD_UNLIKELY( !ctx->vote_tracker ) ) {
    FD_LOG_ERR(( "Failed to join and create vote tracker object" ));
  }

  /********************************************************************/
  /* Capture context                                                 */
  /********************************************************************/

  ctx->capture_ctx               = NULL;
  ctx->solcap_publish_buffer_ptr = NULL;
  ctx->account_updates_flushed   = 0UL;
  if( FD_UNLIKELY( strlen( tile->exec.solcap_capture ) || strlen( tile->exec.dump_proto_dir ) ) ) {
    ctx->capture_ctx = fd_capture_ctx_join( fd_capture_ctx_new( capture_ctx_mem ) );

    if( strlen( tile->exec.dump_proto_dir ) ) {
      ctx->capture_ctx->dump_proto_output_dir = tile->exec.dump_proto_dir;
      ctx->capture_ctx->dump_proto_start_slot = tile->exec.capture_start_slot;
      ctx->capture_ctx->dump_instr_to_pb      = tile->exec.dump_instr_to_pb;
      ctx->capture_ctx->dump_txn_to_pb        = tile->exec.dump_txn_to_pb;
      ctx->capture_ctx->dump_syscall_to_pb    = tile->exec.dump_syscall_to_pb;
      ctx->capture_ctx->dump_elf_to_pb        = tile->exec.dump_elf_to_pb;
    }

    if( strlen( tile->exec.solcap_capture ) ) {
      ctx->capture_ctx->capture_txns      = 0;
      ctx->capture_ctx->solcap_start_slot = tile->exec.capture_start_slot;
      ctx->account_updates_flushed        = 0;
      ctx->solcap_publish_buffer_ptr      = ctx->capture_ctx->account_updates_buffer;
    }
  }

  ctx->pending_txn_finalized_msg = 0;
}

/* Publish the next account update event buffered in the capture tile to the replay tile

   TODO: remove this when solcap v2 is here. */
static void
publish_next_capture_ctx_account_update( fd_exec_tile_ctx_t * ctx,
                                         fd_stem_context_t *  stem ) {
  if( FD_UNLIKELY( !ctx->capture_ctx ) ) {
    return;
  }

  /* Copy the account update event to the buffer */
  ulong chunk     = ctx->exec_replay_out->chunk;
  uchar * out_ptr = fd_chunk_to_laddr( ctx->exec_replay_out->mem, chunk );
  fd_capture_ctx_account_update_msg_t * msg = (fd_capture_ctx_account_update_msg_t *)ctx->solcap_publish_buffer_ptr;
  memcpy( out_ptr, msg, sizeof(fd_capture_ctx_account_update_msg_t) );
  ctx->solcap_publish_buffer_ptr += sizeof(fd_capture_ctx_account_update_msg_t);
  out_ptr                        += sizeof(fd_capture_ctx_account_update_msg_t);

  /* Copy the data to the buffer */
  ulong data_sz = msg->data_sz;
  memcpy( out_ptr, ctx->solcap_publish_buffer_ptr, data_sz );
  ctx->solcap_publish_buffer_ptr += data_sz;
  out_ptr                        += data_sz;

  /* Stem publish the account update event */
  ulong msg_sz = sizeof(fd_capture_ctx_account_update_msg_t) + msg->data_sz;
  fd_stem_publish( stem, ctx->exec_replay_out->idx, FD_EXEC_REPLAY_SOLCAP_UPDATE_SIG, chunk, msg_sz, 0UL, 0UL, 0UL );
  ctx->exec_replay_out->chunk = fd_dcache_compact_next(
    chunk,
    msg_sz,
    ctx->exec_replay_out->chunk0,
    ctx->exec_replay_out->wmark );

  /* Advance the number of account updates flushed */
  ctx->account_updates_flushed++;

  /* If we have published all the account updates, reset the buffer pointer and length */
  if( ctx->account_updates_flushed == ctx->capture_ctx->account_updates_len ) {
    ctx->capture_ctx->account_updates_buffer_ptr = ctx->capture_ctx->account_updates_buffer;
    ctx->solcap_publish_buffer_ptr               = ctx->capture_ctx->account_updates_buffer;
    ctx->capture_ctx->account_updates_len        = 0UL;
    ctx->account_updates_flushed                 = 0UL;
  }
}

/* Publish the txn finalized message to the replay tile */
static void
publish_txn_finalized_msg( fd_exec_tile_ctx_t * ctx,
                           fd_stem_context_t *  stem ) {
  fd_exec_replay_txn_finalized_msg_t * msg = (fd_exec_replay_txn_finalized_msg_t *)
    fd_chunk_to_laddr( ctx->exec_replay_out->mem, ctx->exec_replay_out->chunk );
  msg->exec_tile_id = (uchar)ctx->tile_idx;
  msg->bank_idx     = ctx->txn_ctx->bank_idx;

  fd_stem_publish(
    stem,
    ctx->exec_replay_out->idx,
    FD_EXEC_REPLAY_TXN_FINALIZED_SIG,
    ctx->exec_replay_out->chunk,
    sizeof(fd_exec_replay_txn_finalized_msg_t),
    0UL,
    0UL,
    0UL );

  ctx->exec_replay_out->chunk = fd_dcache_compact_next(
    ctx->exec_replay_out->chunk,
    sizeof(fd_exec_replay_txn_finalized_msg_t),
    ctx->exec_replay_out->chunk0,
    ctx->exec_replay_out->wmark );

  ctx->pending_txn_finalized_msg = 0;
}

static void
after_credit( fd_exec_tile_ctx_t * ctx,
              fd_stem_context_t *  stem,
              int *                opt_poll_in,
              int *                charge_busy FD_PARAM_UNUSED ) {
  /* If we have outstanding account updates to send to solcap, send them.
     Note that we set opt_poll_in to 0 here because we must not consume
     any more fragments from the exec tiles before publishing our messages,
     so that solcap updates are not interleaved between slots.
   */
  if( FD_UNLIKELY( ctx->capture_ctx && ctx->account_updates_flushed < ctx->capture_ctx->account_updates_len ) ) {
    publish_next_capture_ctx_account_update( ctx, stem );
    *opt_poll_in = 0;
  } else if( ctx->pending_txn_finalized_msg ) {
    publish_txn_finalized_msg( ctx, stem );
    *opt_poll_in = 0;
  }
}

static ulong
populate_allowed_seccomp( fd_topo_t const *      topo FD_PARAM_UNUSED,
                          fd_topo_tile_t const * tile FD_PARAM_UNUSED,
                          ulong                  out_cnt,
                          struct sock_filter *   out ) {
  populate_sock_filter_policy_fd_exec_tile( out_cnt, out, (uint)fd_log_private_logfile_fd() );
  return sock_filter_policy_fd_exec_tile_instr_cnt;
}

static ulong
populate_allowed_fds( fd_topo_t const *      topo FD_PARAM_UNUSED,
                      fd_topo_tile_t const * tile FD_PARAM_UNUSED,
                      ulong                  out_fds_cnt,
                      int *                  out_fds ) {

  if( FD_UNLIKELY( out_fds_cnt<2UL ) ) FD_LOG_ERR(( "out_fds_cnt %lu", out_fds_cnt ));

  ulong out_cnt = 0UL;
  out_fds[ out_cnt++ ] = 2; /* stderr */
  if( FD_LIKELY( -1!=fd_log_private_logfile_fd() ) )
    out_fds[ out_cnt++ ] = fd_log_private_logfile_fd(); /* logfile */
  return out_cnt;
}

#define STEM_BURST (1UL)
/* Right now, depth of the replay_exec link and depth of the exec_replay
   links is 16K.  At 1M TPS, that's ~16ms to fill.  But we also want to
   be conservative here, so we use 1ms. */
#define STEM_LAZY  (1000000UL)

#define STEM_CALLBACK_CONTEXT_TYPE  fd_exec_tile_ctx_t
#define STEM_CALLBACK_CONTEXT_ALIGN alignof(fd_exec_tile_ctx_t)

#define STEM_CALLBACK_BEFORE_FRAG  before_frag
#define STEM_CALLBACK_AFTER_CREDIT after_credit
#define STEM_CALLBACK_DURING_FRAG  during_frag
#define STEM_CALLBACK_AFTER_FRAG   after_frag

#include "../../disco/stem/fd_stem.c"

fd_topo_run_tile_t fd_tile_execor = {
    .name                     = "exec",
    .loose_footprint          = 0UL,
    .populate_allowed_seccomp = populate_allowed_seccomp,
    .populate_allowed_fds     = populate_allowed_fds,
    .scratch_align            = scratch_align,
    .scratch_footprint        = scratch_footprint,
    .unprivileged_init        = unprivileged_init,
    .run                      = stem_run,
};
