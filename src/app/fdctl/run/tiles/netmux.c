#include "tiles.h"
#include "../../fdctl.h"
#include "../run.h"

#include "../../../../disco/fd_disco.h"

#include <linux/unistd.h>

static void
init( fd_tile_args_t * args ) {
  (void)args;

  /* calling fd_tempo_tick_per_ns requires nanosleep, it is cached with
     a FD_ONCE */
  fd_tempo_tick_per_ns( NULL );
}

static void
run( fd_tile_args_t * args ) {
  const uchar * tile_pod = args->wksp_pod[ 0 ];
  const uchar * mux_pod  = args->wksp_pod[ 1 ];

  ulong net_tile_cnt = fd_pod_query_ulong( mux_pod, "net-cnt", 0UL );
  if( FD_UNLIKELY( !net_tile_cnt ) ) FD_LOG_ERR(( "net_tile_cnt not set" ));
  ulong quic_tile_cnt = fd_pod_query_ulong( mux_pod, "quic-cnt", 0UL );
  if( FD_UNLIKELY( !quic_tile_cnt ) ) FD_LOG_ERR(( "quic_tile_cnt not set" ));
  ulong shred_tile_cnt = 1UL;

  ulong in_cnt = net_tile_cnt + quic_tile_cnt + shred_tile_cnt;
  fd_frag_meta_t const ** in_mcache = (fd_frag_meta_t const **)fd_alloca( alignof(fd_frag_meta_t const *), sizeof(fd_frag_meta_t const *)*in_cnt );
  ulong ** in_fseq = (ulong **)fd_alloca( alignof(ulong *), sizeof(ulong *)*in_cnt );
  FD_TEST( in_mcache && in_fseq );

  for( ulong i=0; i<net_tile_cnt; i++ ) {
    in_mcache[ i ] = fd_mcache_join( fd_wksp_pod_map1( mux_pod, "net-out-mcache%lu", i ) );
    in_fseq[ i ] = fd_fseq_join( fd_wksp_pod_map1( mux_pod, "net-out-fseq%lu", i ) );
  }
  for( ulong i=0; i<quic_tile_cnt; i++ ) {
    in_mcache[ net_tile_cnt + i ] = fd_mcache_join( fd_wksp_pod_map1( mux_pod, "quic-out-mcache%lu", i ) );
    in_fseq[ net_tile_cnt + i ] = fd_fseq_join( fd_wksp_pod_map1( mux_pod, "quic-out-fseq%lu", i ) );
  }
  in_mcache[ net_tile_cnt + quic_tile_cnt ] = fd_mcache_join( fd_wksp_pod_map( mux_pod, "shred-out-mcache" ) );
  in_fseq  [ net_tile_cnt + quic_tile_cnt ] = fd_fseq_join  ( fd_wksp_pod_map( mux_pod, "shred-out-fseq"   ) );

  fd_mux_callbacks_t callbacks[1] = { 0 };
  fd_rng_t _rng[ 1 ];
  fd_mux_tile( fd_cnc_join( fd_wksp_pod_map( tile_pod, "cnc" ) ),
               (ulong)args->pid,
               FD_MUX_FLAG_DEFAULT,
               in_cnt,
               in_mcache,
               in_fseq,
               fd_mcache_join( fd_wksp_pod_map( mux_pod, "mcache" ) ),
               0, /* no reliable consumers, consumers are unreliable */
               NULL,
               1UL, /* burst */
               0,
               0,
               fd_rng_join( fd_rng_new( _rng, 0, 0UL ) ),
               fd_alloca( FD_MUX_TILE_SCRATCH_ALIGN, FD_MUX_TILE_SCRATCH_FOOTPRINT( in_cnt, 0 ) ),
               NULL,
               callbacks );
}

static long allow_syscalls[] = {
  __NR_write, /* logging */
  __NR_fsync, /* logging, WARNING and above fsync immediately */
};

static workspace_kind_t allow_workspaces[] = {
  wksp_netmux,       /* the tile itself */
  wksp_netmux_inout, /* receive from producers, send to consumers */
};

static ulong
allow_fds( fd_tile_args_t * args,
           ulong            out_fds_sz,
           int *            out_fds ) {
  (void)args;
  if( FD_UNLIKELY( out_fds_sz < 2 ) ) FD_LOG_ERR(( "out_fds_sz %lu", out_fds_sz ));
  out_fds[ 0 ] = 2; /* stderr */
  out_fds[ 1 ] = 3; /* logfile */
  return 2;
}

fd_tile_config_t netmux = {
  .name                 = "netmux",
  .allow_workspaces_cnt = sizeof(allow_workspaces)/sizeof(allow_workspaces[ 0 ]),
  .allow_workspaces     = allow_workspaces,
  .allow_syscalls_cnt   = sizeof(allow_syscalls)/sizeof(allow_syscalls[ 0 ]),
  .allow_syscalls       = allow_syscalls,
  .allow_fds            = allow_fds,
  .init                 = init,
  .run                  = run,
};
