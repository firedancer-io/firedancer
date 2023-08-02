#include "fd_frank.h"

#include <stdio.h>

#include <sys/stat.h>
#include <linux/unistd.h>

static void
run( fd_frank_args_t * args ) {
  /* Join the IPC objects needed this tile instance */

  FD_LOG_INFO(( "joining cnc" ));
  fd_cnc_t * cnc = fd_cnc_join( fd_wksp_pod_map( args->tile_pod, "cnc" ) );
  if( FD_UNLIKELY( !cnc ) ) FD_LOG_ERR(( "fd_cnc_join failed" ));
  if( FD_UNLIKELY( fd_cnc_signal_query( cnc )!=FD_CNC_SIGNAL_BOOT ) ) FD_LOG_ERR(( "cnc not in boot state" ));
  ulong * cnc_diag = (ulong *)fd_cnc_app_laddr( cnc );
  if( FD_UNLIKELY( !cnc_diag ) ) FD_LOG_ERR(( "fd_cnc_app_laddr failed" ));
  int in_backp = 1;

  FD_COMPILER_MFENCE();
  FD_VOLATILE( cnc_diag[ FD_FRANK_CNC_DIAG_IN_BACKP    ] ) = 1UL;
  FD_VOLATILE( cnc_diag[ FD_FRANK_CNC_DIAG_BACKP_CNT   ] ) = 0UL;
  FD_VOLATILE( cnc_diag[ FD_FRANK_CNC_DIAG_HA_FILT_CNT ] ) = 0UL;
  FD_VOLATILE( cnc_diag[ FD_FRANK_CNC_DIAG_HA_FILT_SZ  ] ) = 0UL;
  FD_VOLATILE( cnc_diag[ FD_FRANK_CNC_DIAG_SV_FILT_CNT ] ) = 0UL;
  FD_VOLATILE( cnc_diag[ FD_FRANK_CNC_DIAG_SV_FILT_SZ  ] ) = 0UL;
  FD_COMPILER_MFENCE();

  FD_LOG_INFO(( "joining mcache%lu", args->tile_idx ));
  char path[ 32 ];
  snprintf( path, sizeof(path), "mcache%lu", args->tile_idx );
  fd_frag_meta_t * mcache = fd_mcache_join( fd_wksp_pod_map( args->in_pod, path ) );
  if( FD_UNLIKELY( !mcache ) ) FD_LOG_ERR(( "fd_mcache_join failed" ));
  ulong   depth = fd_mcache_depth( mcache );
  ulong * sync  = fd_mcache_seq_laddr( mcache );
  ulong   seq   = fd_mcache_seq_query( sync );

  FD_LOG_INFO(( "joining dcache%lu", args->tile_idx ));
  snprintf( path, sizeof(path), "dcache%lu", args->tile_idx );
  uchar * dcache = fd_dcache_join( fd_wksp_pod_map( args->in_pod, path ) );
  if( FD_UNLIKELY( !dcache ) ) FD_LOG_ERR(( "fd_dcache_join failed" ));
  fd_wksp_t * wksp = fd_wksp_containing( dcache ); /* chunks are referenced relative to the containing workspace */
  if( FD_UNLIKELY( !wksp ) ) FD_LOG_ERR(( "fd_wksp_containing failed" ));
  ulong   chunk0 = fd_dcache_compact_chunk0( wksp, dcache );
  ulong   wmark  = fd_dcache_compact_wmark ( wksp, dcache, 1542UL ); /* FIXME: MTU? SAFETY CHECK THE FOOTPRINT? */
  ulong   chunk  = chunk0;

  FD_LOG_INFO(( "joining fseq%lu", args->tile_idx ));
  snprintf( path, sizeof(path), "fseq%lu", args->tile_idx );
  ulong * fseq = fd_fseq_join( fd_wksp_pod_map( args->in_pod, path ) );
  if( FD_UNLIKELY( !fseq ) ) FD_LOG_ERR(( "fd_fseq_join failed" ));
  ulong * fseq_diag = (ulong *)fd_fseq_app_laddr( fseq );
  if( FD_UNLIKELY( !fseq_diag ) ) FD_LOG_ERR(( "fd_fseq_app_laddr failed" ));
  FD_VOLATILE( fseq_diag[ FD_FSEQ_DIAG_SLOW_CNT ] ) = 0UL; /* Managed by the fctl */

  /* Setup local objects used by this tile */

  FD_LOG_INFO(( "configuring flow control" ));
  ulong cr_max    = fd_pod_query_ulong( args->tile_pod, "cr_max",    0UL );
  ulong cr_resume = fd_pod_query_ulong( args->tile_pod, "cr_resume", 0UL );
  ulong cr_refill = fd_pod_query_ulong( args->tile_pod, "cr_refill", 0UL );
  long  lazy      = fd_pod_query_long ( args->tile_pod, "lazy",      0L  );
  FD_LOG_INFO(( "cr_max    %lu", cr_max    ));
  FD_LOG_INFO(( "cr_resume %lu", cr_resume ));
  FD_LOG_INFO(( "cr_refill %lu", cr_refill ));
  FD_LOG_INFO(( "lazy      %li", lazy      ));

  fd_fctl_t * fctl = fd_fctl_cfg_done( fd_fctl_cfg_rx_add( fd_fctl_join( fd_fctl_new( fd_alloca( FD_FCTL_ALIGN,
                                                                                                 fd_fctl_footprint( 1UL ) ),
                                                                                      1UL ) ),
                                                           depth, fseq, &fseq_diag[ FD_FSEQ_DIAG_SLOW_CNT ] ),
                                       1UL /*cr_burst*/, cr_max, cr_resume, cr_refill );
  if( FD_UNLIKELY( !fctl ) ) FD_LOG_ERR(( "Unable to create flow control" ));
  FD_LOG_INFO(( "using cr_burst %lu, cr_max %lu, cr_resume %lu, cr_refill %lu",
                fd_fctl_cr_burst( fctl ), fd_fctl_cr_max( fctl ), fd_fctl_cr_resume( fctl ), fd_fctl_cr_refill( fctl ) ));

  ulong cr_avail = 0UL;

  if( lazy<=0L ) lazy = fd_tempo_lazy_default( depth );
  FD_LOG_INFO(( "using lazy %li ns", lazy ));
  ulong async_min = fd_tempo_async_min( lazy, 1UL /*event_cnt*/, (float)fd_tempo_tick_per_ns( NULL ) );
  if( FD_UNLIKELY( !async_min ) ) FD_LOG_ERR(( "bad lazy" ));

  uint seed = fd_pod_query_uint( args->tile_pod, "seed", (uint)fd_tile_id() ); /* use app tile_id as default */
  FD_LOG_INFO(( "creating rng (seed %u)", seed ));
  fd_rng_t _rng[ 1 ];
  fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, seed, 0UL ) );
  if( FD_UNLIKELY( !rng ) ) FD_LOG_ERR(( "fd_rng_join failed" ));

  /* FIXME: PROBABLY SHOULD PUT THIS IN WORKSPACE */
# define TCACHE_DEPTH   (16UL) /* Should be ~1/2-1/4 MAP_CNT */
# define TCACHE_MAP_CNT (64UL) /* Power of two */
  uchar tcache_mem[ FD_TCACHE_FOOTPRINT( TCACHE_DEPTH, TCACHE_MAP_CNT ) ] __attribute__((aligned(FD_TCACHE_ALIGN)));
  fd_tcache_t * tcache  = fd_tcache_join( fd_tcache_new( tcache_mem, TCACHE_DEPTH, TCACHE_MAP_CNT ) );
  ulong   tcache_depth   = fd_tcache_depth       ( tcache );
  ulong   tcache_map_cnt = fd_tcache_map_cnt     ( tcache );
  ulong * _tcache_sync   = fd_tcache_oldest_laddr( tcache );
  ulong * _tcache_ring   = fd_tcache_ring_laddr  ( tcache );
  ulong * _tcache_map    = fd_tcache_map_laddr   ( tcache );
  ulong   tcache_oldest  = FD_VOLATILE_CONST( *_tcache_sync );

  ulong accum_ha_filt_cnt = 0UL; ulong accum_ha_filt_sz = 0UL;

  fd_sha512_t _sha[1];
  fd_sha512_t * sha = fd_sha512_join( fd_sha512_new( _sha ) );
  if( FD_UNLIKELY( !sha ) ) FD_LOG_ERR(( "fd_sha512 join failed" ));

  ulong accum_sv_filt_cnt = 0UL; ulong accum_sv_filt_sz = 0UL;

  /* Start verifying */

  FD_LOG_INFO(( "verify(%lu) run", args->tile_idx ));

  long now  = fd_tickcount();
  long then = now;            /* Do housekeeping on first iteration of run loop */
  fd_cnc_signal( cnc, FD_CNC_SIGNAL_RUN );
  for(;;) {

    /* Do housekeeping at a low rate in the background */

    if( FD_UNLIKELY( (now-then)>=0L ) ) {

      /* Send synchronization info */
      fd_mcache_seq_update( sync, seq );
      FD_COMPILER_MFENCE();
      FD_VOLATILE( *_tcache_sync ) = tcache_oldest;
      FD_COMPILER_MFENCE();

      /* Send diagnostic info */
      fd_cnc_heartbeat( cnc, now );
      FD_COMPILER_MFENCE();
      FD_VOLATILE( cnc_diag[ FD_FRANK_CNC_DIAG_HA_FILT_CNT ] ) = FD_VOLATILE_CONST( cnc_diag[ FD_FRANK_CNC_DIAG_HA_FILT_CNT ] ) + accum_ha_filt_cnt;
      FD_VOLATILE( cnc_diag[ FD_FRANK_CNC_DIAG_HA_FILT_SZ  ] ) = FD_VOLATILE_CONST( cnc_diag[ FD_FRANK_CNC_DIAG_HA_FILT_SZ  ] ) + accum_ha_filt_sz;
      FD_VOLATILE( cnc_diag[ FD_FRANK_CNC_DIAG_SV_FILT_CNT ] ) = FD_VOLATILE_CONST( cnc_diag[ FD_FRANK_CNC_DIAG_SV_FILT_CNT ] ) + accum_sv_filt_cnt;
      FD_VOLATILE( cnc_diag[ FD_FRANK_CNC_DIAG_SV_FILT_SZ  ] ) = FD_VOLATILE_CONST( cnc_diag[ FD_FRANK_CNC_DIAG_SV_FILT_SZ  ] ) + accum_sv_filt_sz;
      FD_COMPILER_MFENCE();
      accum_ha_filt_cnt = 0UL;
      accum_ha_filt_sz  = 0UL;
      accum_sv_filt_cnt = 0UL;
      accum_sv_filt_sz  = 0UL;

      /* Receive command-and-control signals */
      ulong s = fd_cnc_signal_query( cnc );
      if( FD_UNLIKELY( s!=FD_CNC_SIGNAL_RUN ) ) {
        if( FD_UNLIKELY( s!=FD_CNC_SIGNAL_HALT ) ) FD_LOG_ERR(( "Unexpected signal" ));
        break;
      }

      /* Receive flow control credits */
      cr_avail = fd_fctl_tx_cr_update( fctl, cr_avail, seq );
      if( FD_UNLIKELY( in_backp ) ) {
        if( FD_LIKELY( cr_avail ) ) {
          FD_VOLATILE( cnc_diag[ FD_FRANK_CNC_DIAG_IN_BACKP ] ) = 0UL;
          in_backp = 0;
        }
      }

      /* Reload housekeeping timer */
      then = now + (long)fd_tempo_async_reload( rng, async_min );
    }

    /* Check if we are backpressured */
    if( FD_UNLIKELY( !cr_avail ) ) {
      if( FD_UNLIKELY( !in_backp ) ) {
        FD_VOLATILE( cnc_diag[ FD_FRANK_CNC_DIAG_IN_BACKP  ] ) = 1UL;
        FD_VOLATILE( cnc_diag[ FD_FRANK_CNC_DIAG_BACKP_CNT ] ) = FD_VOLATILE_CONST( cnc_diag[ FD_FRANK_CNC_DIAG_BACKP_CNT ] )+1UL;
        in_backp = 1;
      }
      FD_SPIN_PAUSE();
      now = fd_tickcount();
      continue;
    }

    /* Placeholder for sig verify */
    (void)_tcache_map;
    (void)_tcache_ring;
    (void)tcache_depth;
    (void)tcache_map_cnt;
    (void)chunk;
    (void)wmark;
    now = fd_tickcount();
  }
}

static long allow_syscalls[] = {
  __NR_write,     /* logging */
  __NR_futex,     /* logging, glibc fprintf unfortunately uses a futex internally */
  __NR_fsync,     /* logging, WARNING and above fsync immediately */
  __NR_nanosleep, /* fd_tempo_tick_per_ns calibration */
};

fd_frank_task_t frank_verify = {
  .name     = "verify",
  .in_wksp  = "quic_verify",
  .out_wksp = "verify_dedup",
  .close_fd_start = 4, /* stdin, stdout, stderr, logfile */
  .allow_syscalls_sz = sizeof(allow_syscalls)/sizeof(allow_syscalls[ 0 ]),
  .allow_syscalls = allow_syscalls,
  .init = NULL,
  .run  = run,
};
