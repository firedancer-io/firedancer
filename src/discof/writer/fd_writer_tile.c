#define _GNU_SOURCE
#include "../../disco/tiles.h"
#include "generated/fd_writer_tile_seccomp.h"

#include "../../util/pod/fd_pod_format.h"

#include "../../flamenco/runtime/fd_bank.h"
#include "../../flamenco/runtime/fd_runtime.h"
#include "../../discof/replay/fd_exec.h"

#include "../../funk/fd_funk.h"

struct fd_writer_tile_in_ctx {
  fd_wksp_t * mem;
  ulong       chunk0;
  ulong       wmark;
};
typedef struct fd_writer_tile_in_ctx fd_writer_tile_in_ctx_t;

/* fd_writer_tile_out_ctx_t is used by the writer tile to send account updates
   to the replay tile for solcap writing.

   TODO: remove this when solcap v2 is here. */
struct fd_writer_tile_out_ctx {
  ulong            idx;

  fd_frag_meta_t * mcache;
  ulong *          sync;
  ulong            depth;
  ulong            seq;

  fd_wksp_t *      mem;
  ulong            chunk0;
  ulong            wmark;
  ulong            chunk;
};
typedef struct fd_writer_tile_out_ctx fd_writer_tile_out_ctx_t;

struct fd_writer_tile_ctx {
  fd_wksp_t *                 wksp;
  fd_spad_t *                 spad;
  ulong                       tile_cnt;
  ulong                       tile_idx;
  ulong                       exec_tile_cnt;

  /* Capture ctx */
  fd_capture_ctx_t *          capture_ctx;
  FILE *                      capture_file;
  uchar *                     solcap_publish_buffer_ptr;
  ulong                       account_updates_flushed;

  /* Local join of Funk.  R/W. */
  fd_funk_t                   funk[1];
  fd_funk_txn_t *             funk_txn;

  /* Link management. */
  fd_writer_tile_in_ctx_t     exec_writer_in[ FD_PACK_MAX_BANK_TILES ];
  fd_writer_tile_out_ctx_t    writer_replay_out[1];
  fd_writer_tile_out_ctx_t    capture_replay_out[1];

  /* Local joins of exec spads.  Read-only. */
  fd_spad_t *                 exec_spad[ FD_PACK_MAX_BANK_TILES ];
  fd_wksp_t *                 exec_spad_wksp[ FD_PACK_MAX_BANK_TILES ];

  /* Local joins of exec tile txn ctx.  Read-only. */
  fd_exec_txn_ctx_t *         txn_ctx[ FD_PACK_MAX_BANK_TILES ];

  /* Local join of bank manager.  R/W. */
  fd_banks_t *                 banks;
  fd_bank_t *                  bank;

  /* Buffers to hold fragments received during during_frag */
  fd_exec_writer_boot_msg_t boot_msg;
  fd_exec_writer_txn_msg_t  txn_msg;

  /* Buffer to hold the writer->replay notification that a txn has been finalized.
     We need to store it here before publishing it, because we need to ensure that
     all solcap updates have been published before this message. */
  fd_writer_replay_txn_finalized_msg_t txn_finalized_buffer;
  int                                  pending_txn_finalized_msg;
};
typedef struct fd_writer_tile_ctx fd_writer_tile_ctx_t;

FD_FN_CONST static inline ulong
scratch_align( void ) {
  return 128UL;
}

FD_FN_PURE static inline ulong
scratch_footprint( fd_topo_tile_t const * tile ) {
  (void)tile;
  ulong l = FD_LAYOUT_INIT;
  l       = FD_LAYOUT_APPEND( l, alignof(fd_writer_tile_ctx_t),  sizeof(fd_writer_tile_ctx_t) );
  l       = FD_LAYOUT_APPEND( l, FD_CAPTURE_CTX_ALIGN, FD_CAPTURE_CTX_FOOTPRINT );
  l       = FD_LAYOUT_APPEND( l, fd_spad_align(), fd_spad_footprint( FD_RUNTIME_TRANSACTION_FINALIZATION_FOOTPRINT ) );
  return FD_LAYOUT_FINI( l, scratch_align() );
}

static void
join_txn_ctx( fd_writer_tile_ctx_t * ctx,
              ulong                  exec_tile_idx,
              uint                   txn_ctx_offset ) {

  ulong exec_spad_gaddr = fd_wksp_gaddr( ctx->exec_spad_wksp[ exec_tile_idx ], ctx->exec_spad[ exec_tile_idx ] );
  if( FD_UNLIKELY( !exec_spad_gaddr ) ) {
    FD_LOG_CRIT(( "Unable to get gaddr of exec_spad %lu", exec_tile_idx ));
  }

  ulong   txn_ctx_gaddr = exec_spad_gaddr + txn_ctx_offset;
  uchar * txn_ctx_laddr = fd_wksp_laddr( ctx->exec_spad_wksp[ exec_tile_idx ], txn_ctx_gaddr );
  if( FD_UNLIKELY( !txn_ctx_laddr ) ) {
    FD_LOG_CRIT(( "Unable to get laddr of the txn ctx at gaddr 0x%lx from exec_spad %lu", txn_ctx_gaddr, exec_tile_idx ));
  }

  ctx->txn_ctx[ exec_tile_idx ] = fd_exec_txn_ctx_join( txn_ctx_laddr,
                                                        ctx->exec_spad[ exec_tile_idx ],
                                                        ctx->exec_spad_wksp[ exec_tile_idx ] );
  if( FD_UNLIKELY( !ctx->txn_ctx[ exec_tile_idx ] ) ) {
    FD_LOG_CRIT(( "Unable to join txn ctx at gaddr 0x%lx laddr 0x%lx from exec_spad %lu", txn_ctx_gaddr, (ulong)txn_ctx_laddr, exec_tile_idx ));
  }
}

/* Publish the next account update event buffered in the capture tile to the replay tile

   TODO: remove this when solcap v2 is here. */
static void
publish_next_capture_ctx_account_update( fd_writer_tile_ctx_t * ctx, fd_stem_context_t * stem ) {
  if( FD_UNLIKELY( !ctx->capture_ctx ) ) {
    return;
  }

  /* Copy the account update event to the buffer */
  ulong chunk     = ctx->capture_replay_out->chunk;
  uchar * out_ptr = fd_chunk_to_laddr( ctx->capture_replay_out->mem, chunk );
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
  fd_stem_publish( stem, ctx->capture_replay_out->idx, 0UL, chunk, msg_sz, 0UL, 0UL, 0UL );
  ctx->capture_replay_out->chunk = fd_dcache_compact_next(
    chunk,
    msg_sz,
    ctx->capture_replay_out->chunk0,
    ctx->capture_replay_out->wmark );

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
publish_txn_finalized_msg( fd_writer_tile_ctx_t * ctx, fd_stem_context_t * stem ) {
  if( FD_UNLIKELY( !ctx->pending_txn_finalized_msg ) ) {
    return;
  }

  /* Copy the txn finalized message to the buffer */
  uchar * out_ptr = fd_chunk_to_laddr( ctx->writer_replay_out->mem, ctx->writer_replay_out->chunk );
  memcpy( out_ptr, &ctx->txn_finalized_buffer, sizeof(fd_writer_replay_txn_finalized_msg_t) );

  /* Publish the txn finalized message */
  fd_stem_publish(
    stem,
    ctx->writer_replay_out->idx,
    0UL,
    ctx->writer_replay_out->chunk,
    sizeof(fd_writer_replay_txn_finalized_msg_t),
    0UL,
    0UL,
    0UL );
  ctx->writer_replay_out->chunk = fd_dcache_compact_next(
    ctx->writer_replay_out->chunk,
    sizeof(fd_writer_replay_txn_finalized_msg_t),
    ctx->writer_replay_out->chunk0,
    ctx->writer_replay_out->wmark );
  ctx->pending_txn_finalized_msg = 0;
}

static void
after_credit( fd_writer_tile_ctx_t * ctx,
              fd_stem_context_t * stem,
              int *               opt_poll_in,
              int *               charge_busy ) {
  (void)charge_busy;

  /* If we have outstanding account updates to send to solcap, send them.
     Note that we set opt_poll_in to 0 here because we must not consume
     any more fragments from the exec tiles before publishing our messages,
     so that solcap updates are not interleaved between slots.
   */
  if( ctx->capture_ctx && ctx->account_updates_flushed < ctx->capture_ctx->account_updates_len ) {
    publish_next_capture_ctx_account_update( ctx, stem );
    *opt_poll_in = 0;
  } else if ( ctx->pending_txn_finalized_msg ) {
    publish_txn_finalized_msg( ctx, stem );
    *opt_poll_in = 0;
  }
}

static int
before_frag( fd_writer_tile_ctx_t * ctx,
             ulong                  in_idx,
             ulong                  seq,
             ulong                  sig ) {

  /* Round-robin.

     The usual round-robin strategy of returning
     (seq % ctx->tile_cnt) != ctx->tile_idx
     here suffers somewhat from a sort of convoy effect.
     This is because exec tiles do not proceed to the next transaction
     until transaction finalization has been done.  In other words, exec
     tiles block on writer tiles, rather than truly pipelining.  As a
     result, when all the exec tiles publish to seq 0, the 0th writer
     tile becomes busy, and all exec tiles block on it.  Then writer
     tile 1 becomes busy, while all other writer tiles sit idle.  So on
     and so forth.

     So we offset by in_idx to try to mitigate this.
   */
  return ((seq+in_idx) % ctx->tile_cnt) != ctx->tile_idx && sig != FD_WRITER_BOOT_SIG; /* The boot message should go through to all writer tiles. */
}

static void
during_frag( fd_writer_tile_ctx_t * ctx,
             ulong                  in_idx,
             ulong                  seq FD_PARAM_UNUSED,
             ulong                  sig,
             ulong                  chunk,
             ulong                  sz,
             ulong                  ctl FD_PARAM_UNUSED ) {

  fd_writer_tile_in_ctx_t * in_ctx = &(ctx->exec_writer_in[ in_idx ]);

  if( FD_UNLIKELY( chunk < in_ctx->chunk0 || chunk > in_ctx->wmark ) ) {
    FD_LOG_CRIT(( "chunk %lu %lu corrupt, not in range [%lu,%lu]",
                  chunk,
                  sz,
                  in_ctx->chunk0,
                  in_ctx->wmark ));
  }

  if( FD_UNLIKELY( sig == FD_WRITER_BOOT_SIG ) ) {
    fd_exec_writer_boot_msg_t * msg = fd_type_pun( fd_chunk_to_laddr( in_ctx->mem, chunk ) );
    ctx->boot_msg = *msg;
  }

  if( FD_LIKELY( sig == FD_WRITER_TXN_SIG ) ) {
    fd_exec_writer_txn_msg_t * msg = fd_type_pun( fd_chunk_to_laddr( in_ctx->mem, chunk ) );
    ctx->txn_msg = *msg;
  }
}

static void
after_frag( fd_writer_tile_ctx_t * ctx,
            ulong                  in_idx,
            ulong                  seq FD_PARAM_UNUSED,
            ulong                  sig,
            ulong                  sz FD_PARAM_UNUSED,
            ulong                  tsorig FD_PARAM_UNUSED,
            ulong                  tspub FD_PARAM_UNUSED,
            fd_stem_context_t *    stem FD_PARAM_UNUSED ) {

  /* Process messages from exec tiles. */

  if( FD_UNLIKELY( sig == FD_WRITER_BOOT_SIG ) ) {
    fd_exec_writer_boot_msg_t * msg = &ctx->boot_msg;
    join_txn_ctx( ctx, in_idx, msg->txn_ctx_offset );
    ulong txn_ctx_cnt = 0UL;
    for( ulong i=0UL; i<ctx->exec_tile_cnt; i++ ) {
      txn_ctx_cnt += fd_ulong_if( ctx->txn_ctx[ i ]!=NULL, 1UL, 0UL );
    }
    if( txn_ctx_cnt==ctx->exec_tile_cnt ) {
      FD_LOG_INFO(( "writer tile %lu fully booted", ctx->tile_idx ));
    }
    return;
  }

  if( FD_LIKELY( sig == FD_WRITER_TXN_SIG ) ) {
    fd_exec_writer_txn_msg_t * msg = &ctx->txn_msg;
    if( FD_UNLIKELY( msg->exec_tile_id!=in_idx ) ) {
      FD_LOG_CRIT(( "exec_tile_id %u should be == in_idx %lu", msg->exec_tile_id, in_idx ));
    }
    fd_exec_txn_ctx_t * txn_ctx = ctx->txn_ctx[ in_idx ];

    ctx->bank = fd_banks_get_bank_idx( ctx->banks, txn_ctx->bank_idx );
    if( FD_UNLIKELY( !ctx->bank ) ) {
      FD_LOG_CRIT(( "Could not find bank for slot %lu", txn_ctx->slot ));
    }

    if( !ctx->funk_txn || txn_ctx->slot != ctx->funk_txn->xid.ul[0] ) {
      fd_funk_txn_map_t * txn_map = fd_funk_txn_map( ctx->funk );
      if( FD_UNLIKELY( !txn_map->map ) ) {
        FD_LOG_CRIT(( "Could not find valid funk transaction map" ));
      }
      fd_funk_txn_xid_t xid = { .ul = { fd_bank_slot_get( ctx->bank ), fd_bank_slot_get( ctx->bank ) } };
      fd_funk_txn_start_read( ctx->funk );
      ctx->funk_txn = fd_funk_txn_query( &xid, txn_map );
      if( FD_UNLIKELY( !ctx->funk_txn ) ) {
        FD_LOG_CRIT(( "Could not find valid funk transaction" ));
      }
      fd_funk_txn_end_read( ctx->funk );
    }

    txn_ctx->spad      = ctx->exec_spad[ in_idx ];
    txn_ctx->spad_wksp = ctx->exec_spad_wksp[ in_idx ];
    txn_ctx->bank      = ctx->bank;

    if( FD_LIKELY( txn_ctx->flags & FD_TXN_P_FLAGS_EXECUTE_SUCCESS ) ) {
        fd_runtime_finalize_txn(
          ctx->funk,
          ctx->funk_txn,
          txn_ctx,
          ctx->bank,
          ctx->capture_ctx );
    } else {
      /* This means that we should mark the block as dead. */
      fd_banks_mark_bank_dead( ctx->banks, ctx->bank );
    }

    /* Notify the replay tile that we are done with this txn. */
    ctx->txn_finalized_buffer.exec_tile_id = msg->exec_tile_id;
    ctx->pending_txn_finalized_msg = 1;
    return;
  }

  FD_LOG_CRIT(( "Unknown sig %lu", sig ));
}

static void
unprivileged_init( fd_topo_t *      topo,
                   fd_topo_tile_t * tile ) {

  /********************************************************************/
  /* Validate allocations                                             */
  /********************************************************************/

  void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );

  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_writer_tile_ctx_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_writer_tile_ctx_t), sizeof(fd_writer_tile_ctx_t) );
  void * capture_ctx_mem     = FD_SCRATCH_ALLOC_APPEND( l, FD_CAPTURE_CTX_ALIGN, FD_CAPTURE_CTX_FOOTPRINT );
  void * spad_mem            = FD_SCRATCH_ALLOC_APPEND( l, fd_spad_align(), fd_spad_footprint( FD_RUNTIME_TRANSACTION_FINALIZATION_FOOTPRINT ) );
  ulong scratch_alloc_mem    = FD_SCRATCH_ALLOC_FINI( l, scratch_align() );
  if( FD_UNLIKELY( scratch_alloc_mem - (ulong)scratch  - scratch_footprint( tile ) ) ) {
    FD_LOG_CRIT( ( "scratch_alloc_mem did not match scratch_footprint diff: %lu alloc: %lu footprint: %lu",
      scratch_alloc_mem - (ulong)scratch - scratch_footprint( tile ),
      scratch_alloc_mem,
      (ulong)scratch + scratch_footprint( tile ) ) );
  }
  fd_memset( ctx, 0, sizeof(*ctx) );
  ctx->wksp = topo->workspaces[ topo->objs[ tile->tile_obj_id ].wksp_id ].wksp;
  ctx->spad = fd_spad_join( fd_spad_new( spad_mem, FD_RUNTIME_TRANSACTION_FINALIZATION_FOOTPRINT ) );

  /********************************************************************/
  /* Links                                                            */
  /********************************************************************/

  ctx->tile_cnt = fd_topo_tile_name_cnt( topo, tile->name );
  ctx->tile_idx = tile->kind_id;

  ulong exec_tile_cnt = fd_topo_tile_name_cnt( topo, "exec" );
  ctx->exec_tile_cnt  = exec_tile_cnt;

  /* Find and setup all the exec_writer links. */
  if( FD_UNLIKELY( exec_tile_cnt!=tile->in_cnt ) ) {
    FD_LOG_CRIT(( "Expecting one exec_writer link per exec tile but found %lu links and %lu tiles", tile->in_cnt, exec_tile_cnt ));
  }
  for( ulong i=0UL; i<tile->in_cnt; i++ ) {
    ulong exec_writer_idx = fd_topo_find_tile_in_link( topo, tile, "exec_writer", i );
    if( FD_UNLIKELY( exec_writer_idx==ULONG_MAX ) ) {
      FD_LOG_CRIT(( "Could not find exec_writer in-link %lu", i ));
    }
    fd_topo_link_t * exec_writer_in_link = &topo->links[ tile->in_link_id[ i ] ];
    if( FD_UNLIKELY( !exec_writer_in_link ) ) {
      FD_LOG_CRIT(( "Invalid exec_writer in-link %lu", i ));
    }
    ctx->exec_writer_in[ i ].mem    = topo->workspaces[ topo->objs[ exec_writer_in_link->dcache_obj_id ].wksp_id ].wksp;
    ctx->exec_writer_in[ i ].chunk0 = fd_dcache_compact_chunk0( ctx->exec_writer_in[ i ].mem, exec_writer_in_link->dcache );
    ctx->exec_writer_in[ i ].wmark  = fd_dcache_compact_wmark( ctx->exec_writer_in[ i ].mem,
                                                               exec_writer_in_link->dcache,
                                                               exec_writer_in_link->mtu );
  }

  /********************************************************************/
  /* Spad                                                             */
  /********************************************************************/

  /* Join all of the exec spads. */
  for( ulong i=0UL; i<exec_tile_cnt; i++ ) {
    ulong exec_spad_obj_id = fd_pod_queryf_ulong( topo->props, ULONG_MAX, "exec_spad.%lu", i );
    if( FD_UNLIKELY( exec_spad_obj_id==ULONG_MAX ) ) {
      FD_LOG_CRIT(( "Could not find topology object for exec_spad.%lu", i ));
    }

    ctx->exec_spad[ i ] = fd_spad_join( fd_topo_obj_laddr( topo, exec_spad_obj_id ) );
    if( FD_UNLIKELY( !ctx->exec_spad[ i ] ) ) {
      FD_LOG_CRIT(( "Failed to join exec_spad.%lu", i ));
    }
    ctx->exec_spad_wksp[ i ] = fd_wksp_containing( ctx->exec_spad[ i ] );
    if( FD_UNLIKELY( !ctx->exec_spad_wksp[ i ] ) ) {
      FD_LOG_CRIT(( "Failed to find wksp for exec_spad.%lu", i ));
    }
  }

  /********************************************************************/
  /* Funk                                                             */
  /********************************************************************/

  if( FD_UNLIKELY( !fd_funk_join( ctx->funk, fd_topo_obj_laddr( topo, tile->writer.funk_obj_id ) ) ) ) {
    FD_LOG_ERR(( "Failed to join database cache" ));
  }

  /********************************************************************/
  /* Bank                                                             */
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
  /* Capture ctx                                                     */
  /********************************************************************/
  if( strlen( tile->writer.solcap_capture ) ) {
    ctx->capture_ctx                    = fd_capture_ctx_new( capture_ctx_mem );
    ctx->capture_ctx->capture_txns      = 0;
    ctx->capture_ctx->solcap_start_slot = tile->writer.capture_start_slot;
    ctx->pending_txn_finalized_msg      = 0;
    ctx->account_updates_flushed        = 0;
    ctx->solcap_publish_buffer_ptr      = ctx->capture_ctx->account_updates_buffer;
  }

  /********************************************************************************/
  /* writer_replay output link for notifying replay of txn finalization           */
  /********************************************************************************/

  ctx->writer_replay_out->idx = fd_topo_find_tile_out_link( topo, tile, "writ_repl", ctx->tile_idx );
  if( FD_LIKELY( ctx->writer_replay_out->idx!=ULONG_MAX ) ) {
    fd_topo_link_t * writer_replay_link = &topo->links[ tile->out_link_id[ ctx->writer_replay_out->idx ] ];
    ctx->writer_replay_out->mcache = writer_replay_link->mcache;
    ctx->writer_replay_out->sync   = fd_mcache_seq_laddr( ctx->writer_replay_out->mcache );
    ctx->writer_replay_out->depth  = fd_mcache_depth( ctx->writer_replay_out->mcache );
    ctx->writer_replay_out->seq    = fd_mcache_seq_query( ctx->writer_replay_out->sync );
    ctx->writer_replay_out->mem    = topo->workspaces[ topo->objs[ writer_replay_link->dcache_obj_id ].wksp_id ].wksp;
    ctx->writer_replay_out->chunk0 = fd_dcache_compact_chunk0( ctx->writer_replay_out->mem, writer_replay_link->dcache );
    ctx->writer_replay_out->wmark  = fd_dcache_compact_wmark( ctx->writer_replay_out->mem, writer_replay_link->dcache, writer_replay_link->mtu );
    ctx->writer_replay_out->chunk  = ctx->writer_replay_out->chunk0;
  }

  /********************************************************************************/
  /* capture_replay output link for notifying replay's solcap of account updates */
  /********************************************************************************/

  ctx->capture_replay_out->idx = fd_topo_find_tile_out_link( topo, tile, "capt_replay", ctx->tile_idx );
  if( FD_UNLIKELY( ctx->capture_replay_out->idx!=ULONG_MAX ) ) {
    fd_topo_link_t * capture_replay_link = &topo->links[ tile->out_link_id[ ctx->capture_replay_out->idx ] ];
    ctx->capture_replay_out->mcache = capture_replay_link->mcache;
    ctx->capture_replay_out->sync   = fd_mcache_seq_laddr( ctx->capture_replay_out->mcache );
    ctx->capture_replay_out->depth  = fd_mcache_depth( ctx->capture_replay_out->mcache );
    ctx->capture_replay_out->seq    = fd_mcache_seq_query( ctx->capture_replay_out->sync );
    ctx->capture_replay_out->mem    = topo->workspaces[ topo->objs[ capture_replay_link->dcache_obj_id ].wksp_id ].wksp;
    ctx->capture_replay_out->chunk0 = fd_dcache_compact_chunk0( ctx->capture_replay_out->mem, capture_replay_link->dcache );
    ctx->capture_replay_out->wmark  = fd_dcache_compact_wmark( ctx->capture_replay_out->mem, capture_replay_link->dcache, capture_replay_link->mtu );
    ctx->capture_replay_out->chunk  = ctx->capture_replay_out->chunk0;
  }
}

static ulong
populate_allowed_seccomp( fd_topo_t const *      topo,
                          fd_topo_tile_t const * tile,
                          ulong                  out_cnt,
                          struct sock_filter *   out ) {
  (void)topo;
  (void)tile;

  populate_sock_filter_policy_fd_writer_tile( out_cnt, out, (uint)fd_log_private_logfile_fd() );
  return sock_filter_policy_fd_writer_tile_instr_cnt;
}

static ulong
populate_allowed_fds( fd_topo_t const *      topo,
                      fd_topo_tile_t const * tile,
                      ulong                  out_fds_cnt,
                      int *                  out_fds ) {
  (void)topo;
  (void)tile;

  if( FD_UNLIKELY( out_fds_cnt<2UL ) ) FD_LOG_ERR(( "out_fds_cnt %lu", out_fds_cnt ));

  ulong out_cnt = 0UL;
  out_fds[ out_cnt++ ] = 2; /* stderr */
  if( FD_LIKELY( -1!=fd_log_private_logfile_fd() ) )
    out_fds[ out_cnt++ ] = fd_log_private_logfile_fd(); /* logfile */
  return out_cnt;
}

#define STEM_BURST (1UL)

/* STEM_LAZY is calculated as cr_max/(frag production rate * 1.5).  We
   have cr_max ~ 16K and frag production rate ~ 1M/s.  In reality, we
   probably need more than one writer tile to get to 1M TPS, so we
   forget about the 1.5 factor. That gives O(10^7 ns). */
#define STEM_LAZY  ((long)1e7)

#define STEM_CALLBACK_CONTEXT_TYPE  fd_writer_tile_ctx_t
#define STEM_CALLBACK_CONTEXT_ALIGN alignof(fd_writer_tile_ctx_t)

#define STEM_CALLBACK_AFTER_CREDIT after_credit
#define STEM_CALLBACK_BEFORE_FRAG  before_frag
#define STEM_CALLBACK_DURING_FRAG  during_frag
#define STEM_CALLBACK_AFTER_FRAG   after_frag

#include "../../disco/stem/fd_stem.c"

fd_topo_run_tile_t fd_tile_writer = {
    .name                     = "writer",
    .loose_footprint          = 0UL,
    .populate_allowed_seccomp = populate_allowed_seccomp,
    .populate_allowed_fds     = populate_allowed_fds,
    .scratch_align            = scratch_align,
    .scratch_footprint        = scratch_footprint,
    .unprivileged_init        = unprivileged_init,
    .run                      = stem_run,
};
