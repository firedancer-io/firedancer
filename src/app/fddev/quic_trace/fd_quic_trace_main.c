/* This directory provides the 'fddev quic-trace' subcommand.

   The goal of quic-trace is to tap QUIC traffic on a live system, which
   requires encryption keys and other annoying connection state.

   quic-trace does this by tapping into the shared memory segments of an
   fd_quic_tile running on the same host.  It does so strictly read-only
   to minimize impact to a production system.

   This file (fd_quic_trace_main.c) provides the glue code required to
   join remote fd_quic_tile objects.

   fd_quic_trace_rx_tile.c provides a fd_tango consumer for incoming
   QUIC packets. */

#include "fd_quic_trace.h"
#include "../fddev.h"
#include "../../fdctl/run/tiles/fd_quic_tile.h"
#include "../../../tango/fseq/fd_fseq.h"

/* Define global variables */

fd_quic_ctx_t         fd_quic_trace_ctx;
fd_quic_ctx_t const * fd_quic_trace_ctx_remote;
ulong                 fd_quic_trace_ctx_raddr;
ulong **              fd_quic_trace_target_fseq;
ulong volatile *      fd_quic_trace_link_metrics;

void
quic_trace_cmd_args( int *    pargc,
                     char *** pargv,
                     args_t * args ) {
  (void)pargc; (void)pargv; (void)args;
}

void
quic_trace_cmd_fn( args_t *         args,
                   config_t * const config ) {
  (void)args;

  fd_topo_t * topo = &config->topo;
  fd_topo_join_workspaces( topo, FD_SHMEM_JOIN_MODE_READ_ONLY );
  fd_topo_fill( topo );

  fd_topo_tile_t * quic_tile = NULL;
  for( ulong tile_idx=0UL; tile_idx < topo->tile_cnt; tile_idx++ ) {
    if( 0==strcmp( topo->tiles[ tile_idx ].name, "quic" ) ) {
      quic_tile = &topo->tiles[ tile_idx ];
      break;
    }
  }
  if( !quic_tile ) FD_LOG_ERR(( "QUIC tile not found in topology" ));

  /* Ugly: fd_quic_ctx_t uses non-relocatable object addressing.
     We need to rebase pointers.  foreign_{...} refer to the original
     objects in shared memory, local_{...} refer to translated copies. */

  void *                quic_tile_base   = fd_topo_obj_laddr( topo, quic_tile->tile_obj_id );
  fd_quic_ctx_t const * foreign_quic_ctx = quic_tile_base;
  fd_quic_ctx_t * quic_ctx = &fd_quic_trace_ctx;
  *quic_ctx                = *foreign_quic_ctx;
  fd_quic_trace_ctx_remote =  foreign_quic_ctx;

  ulong quic_raddr = (ulong)foreign_quic_ctx->quic;
  ulong ctx_raddr  = quic_raddr - fd_ulong_align_up( sizeof(fd_quic_ctx_t), fd_ulong_max( alignof(fd_quic_ctx_t), fd_quic_align() ) );
  fd_quic_trace_ctx_raddr = ctx_raddr;

  FD_LOG_INFO(( "fd_quic_tile state at %p in tile address space", (void *)ctx_raddr ));
  FD_LOG_INFO(( "fd_quic_tile state at %p in local address space", quic_tile_base ));

  quic_ctx->reasm = (void *)( (ulong)quic_tile_base + (ulong)quic_ctx->reasm - ctx_raddr );
  quic_ctx->stem  = (void *)( (ulong)quic_tile_base + (ulong)quic_ctx->stem  - ctx_raddr );
  quic_ctx->quic  = (void *)( (ulong)quic_tile_base + (ulong)quic_ctx->quic  - ctx_raddr );

  fd_topo_link_t * net_quic = &topo->links[ quic_tile->in_link_id[ 0 ] ];
  quic_ctx->in_mem = topo->workspaces[ topo->objs[ net_quic->dcache_obj_id ].wksp_id ].wksp;
  FD_LOG_INFO(( "net->quic link at %p", (void *)quic_ctx->in_mem ));

  /* Join shared memory objects
     Mostly nops but verifies object magic numbers to ensure that
     derived pointers are correct. */

  FD_LOG_INFO(( "Joining fd_quic" ));
  fd_quic_t * quic = fd_quic_join( quic_ctx->quic );
  if( !quic ) FD_LOG_ERR(( "Failed to join fd_quic" ));

  /* Locate original fseq objects
     These are monitored to ensure the trace RX tile doesn't skip ahead
     of the quic tile. */
  fd_quic_trace_target_fseq = malloc( quic_tile->in_cnt * sizeof(ulong) );
  for( ulong i=0UL; i<quic_tile->in_cnt; i++ ) {
    fd_quic_trace_target_fseq[ i ] = quic_tile->in_link_fseq[ i ];
  }

  /* Redirect metadata writes to dummy buffers.
     Without this hack, stem_run would attempt to write metadata updates
     into the target topology which is read-only. */

  /* ... redirect metric updates */
  ulong * metrics = aligned_alloc( FD_METRICS_ALIGN, FD_METRICS_FOOTPRINT( quic_tile->in_cnt, quic_tile->out_cnt ) );
  if( !metrics ) FD_LOG_ERR(( "out of memory" ));
  fd_memset( metrics, 0, FD_METRICS_FOOTPRINT( quic_tile->in_cnt, quic_tile->out_cnt ) );
  fd_metrics_register( metrics );

  /* ... redirect fseq updates */
  for( ulong i=0UL; i<quic_tile->in_cnt; i++ ) {
    if( !quic_tile->in_link_poll[ i ] ) continue;
    void * fseq_mem = aligned_alloc( fd_fseq_align(), fd_fseq_footprint() );
    if( !fseq_mem ) FD_LOG_ERR(( "out of memory" ));
    quic_tile->in_link_fseq[ i ] = fd_fseq_join( fd_fseq_new( fseq_mem, ULONG_MAX ) );
  }

  fd_quic_trace_link_metrics = fd_metrics_link_in( fd_metrics_base_tl, 0 );

  /* Join net->quic link consumer */

  FD_LOG_NOTICE(( "quic-trace starting ..." ));
  fd_topo_run_tile_t * rx_tile = &fd_tile_quic_trace_rx;
  rx_tile->privileged_init( topo, quic_tile );
  rx_tile->run( topo, quic_tile );
}
