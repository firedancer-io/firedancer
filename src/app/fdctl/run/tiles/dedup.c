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
  ulong in_cnt = fd_pod_query_ulong( args->in_pod, "cnt", 0UL );

  fd_frag_meta_t const ** in_mcache = (fd_frag_meta_t const **)fd_alloca( alignof(fd_frag_meta_t const *), sizeof(fd_frag_meta_t const *)*in_cnt );
  const uchar ** in_dcache = (const uchar **)fd_alloca( alignof(ulong *), sizeof(ulong *)*in_cnt );
  ulong ** in_fseq = (ulong **)fd_alloca( alignof(ulong *), sizeof(ulong *)*in_cnt );
  if( FD_UNLIKELY( !in_mcache || !in_dcache || !in_fseq ) ) FD_LOG_ERR(( "fd_alloca failed" ));

  for( ulong i=0; i<in_cnt; i++ ) {
    char mcache[32], fseq[32], dcache[32];
    snprintf( mcache, 32, "mcache%lu", i );
    snprintf( fseq,   32, "fseq%lu",   i );
    snprintf( dcache, 32, "dcache%lu", i );

    in_mcache[i] = fd_mcache_join( fd_wksp_pod_map( args->in_pod, mcache ) );
    in_dcache[i] = fd_dcache_join( fd_wksp_pod_map( args->in_pod, dcache ) );
    in_fseq[i]   = fd_fseq_join  ( fd_wksp_pod_map( args->in_pod, fseq   ) );
  }

  ulong tcache_depth = fd_pod_query_ulong( args->tile_pod, "tcache_depth", 0UL );

  fd_rng_t _rng[1];
  fd_dedup_tile( fd_cnc_join( fd_wksp_pod_map( args->tile_pod, "cnc" ) ),
                 (ulong)args->pid,
                 in_cnt,
                 in_mcache,
                 in_fseq,
                 in_dcache,
                 fd_tcache_join( fd_tcache_new( fd_wksp_alloc_laddr( fd_wksp_containing( args->tile_pod ), FD_TCACHE_ALIGN, FD_TCACHE_FOOTPRINT( tcache_depth, 0 ), 1UL ), tcache_depth, 0 ) ),
                 fd_mcache_join( fd_wksp_pod_map( args->out_pod, "mcache" ) ),
                 fd_dcache_join( fd_wksp_pod_map( args->out_pod, "dcache" ) ),
                 1,
                 &(ulong*){ fd_fseq_join( fd_wksp_pod_map( args->out_pod, "fseq" ) ) },
                 0,
                 0,
                 fd_rng_join( fd_rng_new( _rng, 0, 0UL ) ),
                 fd_alloca( FD_DEDUP_TILE_SCRATCH_ALIGN, FD_DEDUP_TILE_SCRATCH_FOOTPRINT( in_cnt, 1 ) ) );
}

static long allow_syscalls[] = {
  __NR_write,     /* logging */
  __NR_fsync,     /* logging, WARNING and above fsync immediately */
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
  .name              = "dedup",
  .in_wksp           = "verify_dedup",
  .out_wksp          = "dedup_pack",
  .allow_syscalls_sz = sizeof(allow_syscalls)/sizeof(allow_syscalls[ 0 ]),
  .allow_syscalls    = allow_syscalls,
  .allow_fds         = allow_fds,
  .init              = init,
  .run               = run,
};
