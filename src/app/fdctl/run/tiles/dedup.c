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
  const uchar * in_pod   = args->wksp_pod[ 1 ];
  const uchar * out_pod  = args->wksp_pod[ 2 ];

  ulong in_cnt = fd_pod_query_ulong( in_pod, "cnt", 0UL );
  if( FD_UNLIKELY( !in_cnt ) ) FD_LOG_ERR(( "in_cnt not set" ));

  fd_frag_meta_t const ** in_mcache = (fd_frag_meta_t const **)fd_alloca( alignof(fd_frag_meta_t const *), sizeof(fd_frag_meta_t const *)*in_cnt );
  const uchar ** in_dcache = (const uchar **)fd_alloca( alignof(ulong *), sizeof(ulong *)*in_cnt );
  ulong ** in_fseq = (ulong **)fd_alloca( alignof(ulong *), sizeof(ulong *)*in_cnt );
  if( FD_UNLIKELY( !in_mcache || !in_dcache || !in_fseq ) ) FD_LOG_ERR(( "fd_alloca failed" ));

  for( ulong i=0; i<in_cnt; i++ ) {
    in_mcache[i] = fd_mcache_join( fd_wksp_pod_map1( in_pod, "mcache%lu", i ) );
    in_dcache[i] = fd_dcache_join( fd_wksp_pod_map1( in_pod, "dcache%lu", i ) );
    in_fseq[i]   = fd_fseq_join  ( fd_wksp_pod_map1( in_pod, "fseq%lu",   i ) );
  }

  ulong tcache_depth = fd_pod_query_ulong( tile_pod, "tcache_depth", 0UL );
  if( FD_UNLIKELY( !tcache_depth ) ) FD_LOG_ERR(( "tcache_depth not set" ));

  fd_rng_t _rng[1];
  fd_dedup_tile( fd_cnc_join( fd_wksp_pod_map( tile_pod, "cnc" ) ),
                 (ulong)args->pid,
                 in_cnt,
                 in_mcache,
                 in_fseq,
                 in_dcache,
                 fd_tcache_join( fd_tcache_new( fd_wksp_alloc_laddr( fd_wksp_containing( tile_pod ), FD_TCACHE_ALIGN, FD_TCACHE_FOOTPRINT( tcache_depth, 0 ), 1UL ), tcache_depth, 0 ) ),
                 fd_mcache_join( fd_wksp_pod_map( out_pod, "mcache" ) ),
                 fd_dcache_join( fd_wksp_pod_map( out_pod, "dcache" ) ),
                 1,
                 &(ulong*){ fd_fseq_join( fd_wksp_pod_map( out_pod, "fseq" ) ) },
                 0,
                 0,
                 fd_rng_join( fd_rng_new( _rng, 0, 0UL ) ),
                 fd_alloca( FD_DEDUP_TILE_SCRATCH_ALIGN, FD_DEDUP_TILE_SCRATCH_FOOTPRINT( in_cnt, 1 ) ) );
}

static long allow_syscalls[] = {
  __NR_write, /* logging */
  __NR_fsync, /* logging, WARNING and above fsync immediately */
};

static workspace_kind_t allow_workspaces[] = {
  wksp_dedup,        /* the tile itself */
  wksp_verify_dedup, /* receive path */
  wksp_dedup_pack,   /* send path */
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

fd_tile_config_t dedup = {
  .name                 = "dedup",
  .allow_workspaces_cnt = sizeof(allow_workspaces)/sizeof(allow_workspaces[ 0 ]),
  .allow_workspaces     = allow_workspaces,
  .allow_syscalls_cnt   = sizeof(allow_syscalls)/sizeof(allow_syscalls[ 0 ]),
  .allow_syscalls       = allow_syscalls,
  .allow_fds            = allow_fds,
  .init                 = init,
  .run                  = run,
};
