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
  char mcache[32], fseq[32], dcache[32];
  snprintf( mcache, sizeof(mcache), "mcache%lu", args->tile_idx );
  snprintf( fseq,   sizeof(fseq),   "fseq%lu",   args->tile_idx );
  snprintf( dcache, sizeof(dcache), "dcache%lu", args->tile_idx );

  fd_sha512_t _sha[1];
  fd_rng_t    _rng[1];
  fd_verify_tile( fd_cnc_join( fd_wksp_pod_map( args->tile_pod, "cnc" ) ),
                  (ulong)args->pid,
                  1,
                  (const fd_frag_meta_t **)&(fd_frag_meta_t*){ fd_mcache_join( fd_wksp_pod_map( args->in_pod, mcache ) ) },
                  &(ulong*){ fd_fseq_join( fd_wksp_pod_map( args->in_pod, fseq ) ) },
                  (const uchar**)&(uchar*){ fd_dcache_join( fd_wksp_pod_map( args->in_pod, dcache ) ) },
                  fd_sha512_join( fd_sha512_new( _sha ) ),
                  fd_tcache_join( fd_tcache_new( fd_wksp_alloc_laddr( fd_wksp_containing( args->tile_pod ), FD_TCACHE_ALIGN, FD_TCACHE_FOOTPRINT( 16UL, 64UL ), 1UL ), 16UL, 64UL ) ),
                  fd_mcache_join( fd_wksp_pod_map( args->out_pod, mcache ) ),
                  fd_dcache_join( fd_wksp_pod_map( args->out_pod, dcache ) ),
                  1,
                  &(ulong*){ fd_fseq_join( fd_wksp_pod_map( args->out_pod, fseq ) ) },
                  0,
                  0,
                  fd_rng_join( fd_rng_new( _rng, 0, 0UL ) ),
                  fd_alloca( FD_VERIFY_TILE_SCRATCH_ALIGN, FD_VERIFY_TILE_SCRATCH_FOOTPRINT( 1UL, 1UL ) ) );
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

fd_tile_config_t verify = {
  .name              = "verify",
  .in_wksp           = "quic_verify",
  .out_wksp          = "verify_dedup",
  .allow_syscalls_sz = sizeof(allow_syscalls)/sizeof(allow_syscalls[ 0 ]),
  .allow_syscalls    = allow_syscalls,
  .allow_fds         = allow_fds,
  .init              = init,
  .run               = run,
};
