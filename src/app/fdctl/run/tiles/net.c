#include "tiles.h"
#include "../../fdctl.h"
#include "../run.h"

#include "../../../../disco/fd_disco.h"
#include "../../../../tango/xdp/fd_xsk_private.h"

#include <linux/unistd.h>


static void
init( fd_tile_args_t * args ) {
  const uchar * tile_pod = args->wksp_pod[ 0 ];

  FD_LOG_INFO(( "loading %s", "xsk" ));
  args->xsk = fd_xsk_join( fd_wksp_pod_map1( tile_pod, "xsk%lu", args->tile_idx ) );
  if( FD_UNLIKELY( !args->xsk ) ) FD_LOG_ERR(( "fd_xsk_join failed" ));

  char lo_xsk_name[32];
  snprintf1( lo_xsk_name, 32, "lo_xsk%lu", args->tile_idx );
  args->lo_xsk = NULL;
  if( FD_UNLIKELY( fd_pod_query_cstr( tile_pod, lo_xsk_name, NULL ) ) ) {
    FD_LOG_INFO(( "loading %s", lo_xsk_name ));
    args->lo_xsk = fd_xsk_join( fd_wksp_pod_map( tile_pod, lo_xsk_name ) );
    if( FD_UNLIKELY( !args->lo_xsk ) ) FD_LOG_ERR(( "fd_xsk_join (lo) failed" ));
  }

  /* calling fd_tempo_tick_per_ns requires nanosleep, it is cached with
     a FD_ONCE */
  fd_tempo_tick_per_ns( NULL );
}

static void
run( fd_tile_args_t * args ) {
  const uchar * tile_pod = args->wksp_pod[ 0 ];
  const uchar * mux_pod  = args->wksp_pod[ 1 ];

  ulong xsk_aio_cnt = 1;
  fd_xsk_aio_t * xsk_aio[2] = { fd_xsk_aio_join( fd_wksp_pod_map1( tile_pod, "xsk_aio%lu", args->tile_idx ), args->xsk ), NULL };
  if( FD_UNLIKELY( args->lo_xsk ) ) {
    xsk_aio[1] = fd_xsk_aio_join( fd_wksp_pod_map1( tile_pod, "lo_xsk_aio%lu", args->tile_idx ), args->lo_xsk );
    xsk_aio_cnt += 1;
  }

  ulong cnt = fd_pod_query_ulong( mux_pod, "net-cnt", 0UL );
  if( FD_UNLIKELY( !cnt ) ) FD_LOG_ERR(( "net-cnt not set" ));

  fd_rng_t _rng[ 1 ];
  fd_net_tile( fd_cnc_join( fd_wksp_pod_map1( tile_pod, "cnc%lu", args->tile_idx ) ),
               (ulong)args->pid,
               1,
               (const fd_frag_meta_t **)&(fd_frag_meta_t*){ fd_mcache_join( fd_wksp_pod_map( mux_pod, "mcache" ) ) },
               &(ulong*){ fd_fseq_join( fd_wksp_pod_map1( mux_pod, "net-in-fseq%lu", args->tile_idx ) ) },
               cnt,
               args->tile_idx,
               xsk_aio_cnt,
               xsk_aio,
               fd_mcache_join( fd_wksp_pod_map1( mux_pod, "net-out-mcache%lu", args->tile_idx ) ),
               fd_dcache_join( fd_wksp_pod_map1( mux_pod, "net-out-dcache%lu", args->tile_idx ) ),
               0,
               0,
               fd_rng_join( fd_rng_new( _rng, 0, 0UL ) ),
               fd_alloca( FD_NET_TILE_SCRATCH_ALIGN, FD_NET_TILE_SCRATCH_FOOTPRINT( 1, 0 ) ) );
}

static long allow_syscalls[] = {
  __NR_write,  /* logging */
  __NR_fsync,  /* logging, WARNING and above fsync immediately */
  __NR_sendto, /* performance optimization for send/recv path, should be investigated */
};

static workspace_kind_t allow_workspaces[] = {
  wksp_net,          /* the tile itself */
  wksp_netmux_inout, /* receive from mux, send to mux */
};

static ulong
allow_fds( fd_tile_args_t * args,
           ulong            out_fds_sz,
           int *            out_fds ) {
  if( FD_UNLIKELY( out_fds_sz < 4 ) ) FD_LOG_ERR(( "out_fds_sz %lu", out_fds_sz ));
  out_fds[ 0 ] = 2; /* stderr */
  out_fds[ 1 ] = 3; /* logfile */
  out_fds[ 2 ] = args->xsk->xsk_fd;
  out_fds[ 3 ] = args->lo_xsk ? args->lo_xsk->xsk_fd : -1;
  return args->lo_xsk ? 4 : 3;
}

fd_tile_config_t net = {
  .name                 = "net",
  .allow_workspaces_cnt = sizeof(allow_workspaces)/sizeof(allow_workspaces[ 0 ]),
  .allow_workspaces     = allow_workspaces,
  .allow_syscalls_cnt   = sizeof(allow_syscalls)/sizeof(allow_syscalls[ 0 ]),
  .allow_syscalls       = allow_syscalls,
  .allow_fds            = allow_fds,
  .init                 = init,
  .run                  = run,
};
