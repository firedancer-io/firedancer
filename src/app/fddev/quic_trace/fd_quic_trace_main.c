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
#include "../../../disco/stem/fd_stem.h"
#include "../../../tango/fseq/fd_fseq.h"

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

  /* Only works with 1 QUIC tile for now */
  FD_TEST( fd_topo_tile_name_cnt( topo, "quic" )==1UL );
  fd_topo_tile_t * quic_tile = &topo->tiles[ fd_topo_find_tile( topo, "quic", 0UL ) ];

  /* Ugly: fd_quic_ctx_t uses non-relocatable object addressing.
     We need to rebase pointers.  foreign_{...} refer to the original
     objects in shared memory, local_{...} refer to translated copies. */

  fd_quic_trace_tile_ctx_t ctx = {0};

  void *                quic_tile_base   = fd_topo_obj_laddr( topo, quic_tile->tile_obj_id );
  fd_quic_ctx_t const * foreign_quic_ctx = quic_tile_base;
  FD_TEST( foreign_quic_ctx->magic == FD_QUIC_TILE_CTX_MAGIC );
  ctx.remote_ctx = foreign_quic_ctx;
  FD_LOG_INFO(( "fd_quic_tile state at %p in tile address space", foreign_quic_ctx->self ));
  FD_LOG_INFO(( "fd_quic_tile state at %p in local address space", quic_tile_base ));

  ulong in_cnt = 0UL;
  for( ulong i=0UL; i<topo->link_cnt; i++ ) {
    if( !strcmp( topo->links[ i ].name, "net_quic" ) ) in_cnt++;
  }

  fd_frag_meta_t const ** in_mcache = aligned_alloc( alignof( fd_frag_meta_t ), in_cnt * sizeof(fd_frag_meta_t *) );
  FD_TEST( in_mcache );
  for( ulong i=0UL; i<topo->link_cnt; i++ ) {
    if( !strcmp( topo->links[ i ].name, "net_quic" ) ) in_mcache[ i ] = topo->links[ i ].mcache;
  }

  /* Locate original fseq objects
     These are monitored to ensure the trace RX tile doesn't skip ahead
     of the quic tile. */
  for( ulong i=0UL; i<in_cnt; i++ ) {
    ctx.target_fseq[ i ] = quic_tile->in_link_fseq[ i ];
  }

  ulong * _in_fseq = aligned_alloc( alignof( ulong ), in_cnt * sizeof(ulong) );
  ulong ** in_fseq = aligned_alloc( 8, in_cnt * sizeof(ulong*) );
  for( ulong i=0UL; i<in_cnt; i++ ) {
    in_fseq[ i ] = &_in_fseq[ i ];
  }

  ctx.in_mem[ 0 ] = aligned_alloc( 8, in_cnt * sizeof(fd_wksp_t *) );

  fd_rng_t rng[1];
  FD_TEST( fd_rng_join( fd_rng_new( rng, 0, 0UL ) ) );

  ulong * metrics = aligned_alloc( FD_METRICS_ALIGN, FD_METRICS_FOOTPRINT( in_cnt, 0UL ) );
  FD_TEST( metrics );
  fd_metrics_register( metrics );

  quic_trace_run( in_cnt,
                  in_mcache,
                  in_fseq,
                  0UL,
                  NULL,
                  0UL,
                  NULL,
                  NULL,
                  1UL,
                  0L,
                  rng,
                  fd_alloca( STEM_SCRATCH_ALIGN, stem_scratch_footprint( in_cnt, 0UL, 0UL ) ),
                  &ctx );
}
