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
#include "../../../disco/quic/fd_quic_tile.h"
#include "../../../waltz/quic/log/fd_quic_log_user.h"

/* Define global variables */

fd_quic_ctx_t         fd_quic_trace_ctx;
fd_quic_ctx_t const * fd_quic_trace_ctx_remote;
ulong                 fd_quic_trace_ctx_raddr;
ulong **              fd_quic_trace_target_fseq;
ulong volatile *      fd_quic_trace_link_metrics;
void const *          fd_quic_trace_log_base;

#define EVENT_STREAM 0
#define EVENT_ERROR  1

void
quic_trace_cmd_args( int *    pargc,
                     char *** pargv,
                     args_t * args ) {
  char const * event = fd_env_strip_cmdline_cstr( pargc, pargv, "--event", NULL, "stream" );
  if( 0==strcmp( event, "stream" ) ) {
    args->quic_trace.event = EVENT_STREAM;
  } else if( 0==strcmp( event, "error" ) ) {
    args->quic_trace.event = EVENT_ERROR;
  } else {
    FD_LOG_ERR(( "Unsupported QUIC event type \"%s\"", event ));
  }
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

  /* Locate log buffer */

  void * log = (void *)( (ulong)quic + quic->layout.log_off );
  fd_quic_log_rx_t log_rx[1];
  FD_LOG_DEBUG(( "Joining quic_log" ));
  if( FD_UNLIKELY( !fd_quic_log_rx_join( log_rx, log ) ) ) {
    FD_LOG_ERR(( "fd_quic_log_rx_join failed" ));
  }
  fd_quic_trace_log_base = log_rx->base;

  /* Redirect metadata writes to dummy buffers.
     Without this hack, stem_run would attempt to write metadata updates
     into the target topology which is read-only. */

  /* ... redirect metric updates */
  ulong * metrics = aligned_alloc( FD_METRICS_ALIGN, FD_METRICS_FOOTPRINT( quic_tile->in_cnt, quic_tile->out_cnt ) );
  if( !metrics ) FD_LOG_ERR(( "out of memory" ));
  fd_memset( metrics, 0, FD_METRICS_FOOTPRINT( quic_tile->in_cnt, quic_tile->out_cnt ) );
  fd_metrics_register( metrics );

  fd_quic_trace_link_metrics = fd_metrics_link_in( fd_metrics_base_tl, 0 );

  /* Join net->quic link consumer */

  FD_LOG_NOTICE(( "quic-trace starting ..." ));
  switch( args->quic_trace.event ) {
  case EVENT_STREAM:
    fd_quic_trace_rx_tile( net_quic->mcache );
    break;
  case EVENT_ERROR:
    fd_quic_trace_log_tile( log_rx->mcache );
    break;
  default:
    __builtin_unreachable();
  }

  fd_quic_log_rx_leave( log_rx );
}
