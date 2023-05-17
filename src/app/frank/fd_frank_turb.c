#include "fd_frank.h"
#include <stdio.h>

#if FD_HAS_FRANK

int
fd_frank_turb_task( int     argc,
                    char ** argv ) {
  (void)argc;
  fd_log_thread_set( argv[0] );
  FD_LOG_INFO(( "turb init" ));

  /* Parse "command line" arguments */

  char const * pod_gaddr = argv[1];
  char const * cfg_path  = argv[2];

  /* Load up the configuration for this frank instance */

  FD_LOG_INFO(( "using configuration in pod %s at path %s", pod_gaddr, cfg_path ));
  uchar const * pod     = fd_wksp_pod_attach( pod_gaddr );
  uchar const * cfg_pod = fd_pod_query_subpod( pod, cfg_path );
  if( FD_UNLIKELY( !cfg_pod ) ) FD_LOG_ERR(( "path not found" ));

  /* Join the IPC objects needed this tile instance */

  FD_LOG_INFO(( "joining %s.turb.cnc", cfg_path ));
  fd_cnc_t * cnc = fd_cnc_join( fd_wksp_pod_map( cfg_pod, "turb.cnc" ) );
  if( FD_UNLIKELY( !cnc ) ) FD_LOG_ERR(( "fd_cnc_join failed" ));
  if( FD_UNLIKELY( fd_cnc_signal_query( cnc )!=FD_CNC_SIGNAL_BOOT ) ) FD_LOG_ERR(( "cnc not in boot state" ));
  /* FIXME: CNC DIAG REGION? */

  /* QoS on 4 slots, each slot has 2 queues, one for data shreds, one for code shreds */
  /* FIXME: CONSTANT DEFINITION MAY BE BETTER PUTTING IN fd_frank.h */
  #define FD_FRANK_TURB_SLOT_CNT  (4UL)
  #define FD_FRANK_TURB_BUFF_CNT  (2UL)
  #define FD_FRANK_TURB_PATH_MAX  (128UL) 
  char sub_path[FD_FRANK_TURB_PATH_MAX+1];
  sub_path[FD_FRANK_TURB_PATH_MAX] = 0; /* ensure cstr terminates */
  fd_frag_meta_t const * mcache         ;
  ulong                  depth          ;
  ulong const *          sync           ;
  ulong                  seq            ;
  fd_frag_meta_t const * mline          ;
  uchar *                dcache         ;
  ulong                  chunk0         ;
  ulong                  wmark          ;
  ulong                  chunk          ;
  ulong *                fseq           ;
  ulong *                fseq_diag      ;
  ulong                  accum_pub_cnt  ;
  ulong                  accum_pub_sz   ;
  ulong                  accum_ovrnp_cnt;
  ulong                  accum_ovrnr_cnt;
  (void) chunk;
  (void) wmark;

  snprintf(sub_path, FD_FRANK_TURB_PATH_MAX, "turb.mcache");
  FD_LOG_INFO(( "joining %s.%s", cfg_path, sub_path));
  mcache = fd_mcache_join( fd_wksp_pod_map( cfg_pod, sub_path ) );
  if( FD_UNLIKELY( !mcache ) ) FD_LOG_ERR(( "fd_mcache_join failed" ));
  depth  = fd_mcache_depth          ( mcache );
  sync   = fd_mcache_seq_laddr_const( mcache );
  seq    = fd_mcache_seq_query      ( sync   );
  mline  = mcache + 
                                fd_mcache_line_idx( seq, depth );

  snprintf(sub_path, FD_FRANK_TURB_PATH_MAX, "turb.dcache");
  FD_LOG_INFO(( "joining %s.%s", cfg_path, sub_path ));
  dcache = fd_dcache_join( fd_wksp_pod_map( cfg_pod, sub_path ) );
  if( FD_UNLIKELY( !dcache ) ) FD_LOG_ERR(( "fd_dcache_join failed" ));
  fd_wksp_t * wksp = fd_wksp_containing( dcache ); /* chunks are referenced relative to the containing workspace */
  if( FD_UNLIKELY( !wksp ) ) FD_LOG_ERR(( "fd_wksp_containing failed" ));
  chunk0  = fd_dcache_compact_chunk0( wksp, dcache );
  wmark   = fd_dcache_compact_wmark ( wksp, dcache, 1542UL ); /* FIXME: MTU? SAFETY CHECK THE FOOTPRINT? */
  chunk   = chunk0;

  snprintf(sub_path, FD_FRANK_TURB_PATH_MAX, "turb.fseq");
  FD_LOG_INFO(( "joining %s.%s", cfg_path, sub_path ));
  fseq = fd_fseq_join( fd_wksp_pod_map( cfg_pod, sub_path ) );
  if( FD_UNLIKELY( !fseq ) ) FD_LOG_ERR(( "fd_fseq_join failed" ));
  fseq_diag = (ulong *)fd_fseq_app_laddr( fseq );
  if( FD_UNLIKELY( !fseq_diag ) ) FD_LOG_ERR(( "fd_fseq_app_laddr failed" ));
  FD_COMPILER_MFENCE();
  FD_VOLATILE( fseq_diag[ FD_FSEQ_DIAG_PUB_CNT   ] ) = 0UL; 
  FD_VOLATILE( fseq_diag[ FD_FSEQ_DIAG_PUB_SZ    ] ) = 0UL;
  FD_VOLATILE( fseq_diag[ FD_FSEQ_DIAG_OVRNP_CNT ] ) = 0UL;
  FD_VOLATILE( fseq_diag[ FD_FSEQ_DIAG_OVRNR_CNT ] ) = 0UL;
  FD_COMPILER_MFENCE();
  accum_pub_cnt    = 0UL;
  accum_pub_sz     = 0UL;
  accum_ovrnp_cnt  = 0UL;
  accum_ovrnr_cnt  = 0UL;

  /* Setup local objects used by this tile */

  long lazy = fd_pod_query_long( cfg_pod, "turb.lazy", 0L );
  FD_LOG_INFO(( "configuring flow control (%s.turb.lazy %li)", cfg_path, lazy ));
  if( lazy<=0L ) lazy = fd_tempo_lazy_default( depth );
  FD_LOG_INFO(( "using lazy %li ns", lazy ));
  ulong async_min = fd_tempo_async_min( lazy, 1UL /*event_cnt*/, (float)fd_tempo_tick_per_ns( NULL ) );
  if( FD_UNLIKELY( !async_min ) ) FD_LOG_ERR(( "bad lazy" ));

  uint seed = fd_pod_query_uint( cfg_pod, "turb.seed", (uint)fd_tile_id() ); /* use app tile_id as default */
  FD_LOG_INFO(( "creating rng (%s.turb.seed %u)", cfg_path, seed ));
  fd_rng_t _rng[ 1 ];
  fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, seed, 0UL ) );
  if( FD_UNLIKELY( !rng ) ) FD_LOG_ERR(( "fd_rng_join failed" ));

  /* Start turbing */

  FD_LOG_INFO(( "turb run" ));

  long now  = fd_tickcount();
  long then = now;            /* Do housekeeping on first iteration of run loop */
  fd_cnc_signal( cnc, FD_CNC_SIGNAL_RUN );
  for(;;) {

    /* Do housekeeping at a low rate in the background */
    now = fd_tickcount();
    if( FD_UNLIKELY( (now-then)>=0L ) ) {

      for( ulong slot_idx=0UL; slot_idx<FD_FRANK_TURB_SLOT_CNT; slot_idx++ ) {
        for( ulong buff_idx=0UL; buff_idx<FD_FRANK_TURB_BUFF_CNT; buff_idx++ ) {
          /* Send flow control credits */
          fd_fctl_rx_cr_return( fseq, seq );

          FD_COMPILER_MFENCE();
          fseq_diag[ FD_FSEQ_DIAG_PUB_CNT   ] += accum_pub_cnt  ;
          fseq_diag[ FD_FSEQ_DIAG_PUB_SZ    ] += accum_pub_sz   ;
          fseq_diag[ FD_FSEQ_DIAG_OVRNP_CNT ] += accum_ovrnp_cnt;
          fseq_diag[ FD_FSEQ_DIAG_OVRNR_CNT ] += accum_ovrnr_cnt;
          FD_COMPILER_MFENCE();
          accum_pub_cnt   = 0UL;
          accum_pub_sz    = 0UL;
          accum_ovrnp_cnt = 0UL;
          accum_ovrnr_cnt = 0UL;
        }
      }
      
      /* Send diagnostic info */
      fd_cnc_heartbeat( cnc, now );

      /* Receive command-and-control signals */
      ulong s = fd_cnc_signal_query( cnc );
      if( FD_UNLIKELY( s!=FD_CNC_SIGNAL_RUN ) ) {
        if( FD_UNLIKELY( s!=FD_CNC_SIGNAL_HALT ) ) FD_LOG_ERR(( "Unexpected signal" ));
        break;
      }

      /* Reload housekeeping timer */
      then = now + (long)fd_tempo_async_reload( rng, async_min );
    }

    /* See if there are any transactions waiting to be queued for turbine propagation */
    ulong seq_found = fd_frag_meta_seq_query( mline );
    long  diff      = fd_seq_diff( seq_found, seq );
    if( FD_UNLIKELY( diff ) ) { /* caught up or overrun, optimize for expected sequence number ready */
      if( FD_LIKELY( diff<0L ) ) { /* caught up */
        FD_SPIN_PAUSE();
        goto next_work_loop;
      }
      /* overrun by dedup tile ... recover */
      accum_ovrnp_cnt++;
      seq = seq_found;
      /* can keep processing from the new seq */
    }
    ulong sz = (ulong)mline->sz;

    /* At this point, we have started receiving frag seq with details in
      mline at time now.  Speculatively processs it here. */
    
    /* Placeholder for speculative turb operations 
    
    
    */

    /* Check that we weren't overrun while processing */
    seq_found = fd_frag_meta_seq_query( mline );
    if( FD_UNLIKELY( fd_seq_ne( seq_found, seq ) ) ) {
      accum_ovrnr_cnt++;
      seq = seq_found;
      goto next_work_loop;
    }

    /* Placeholder for non-speculative turb operations */
    accum_pub_cnt++;
    accum_pub_sz += sz;

    /* Wind up for the next iteration */
    seq   = fd_seq_inc( seq, 1UL );
    mline = mcache + fd_mcache_line_idx( seq, depth );

    next_work_loop:;
  }

  /* Clean up */
  
  fd_cnc_signal( cnc, FD_CNC_SIGNAL_BOOT );
  FD_LOG_INFO(( "turb fini" ));
  fd_rng_delete    ( fd_rng_leave   ( rng     ) );
  fd_wksp_pod_unmap( fd_fseq_leave  ( fseq    ) );
  fd_wksp_pod_unmap( fd_dcache_leave( dcache  ) );
  fd_wksp_pod_unmap( fd_mcache_leave( mcache  ) );
  fd_wksp_pod_unmap( fd_cnc_leave   ( cnc     ) );
  fd_wksp_pod_detach( pod );
  return 0;
}

#else

int
fd_frank_turb_task( int     argc,
                    char ** argv ) {
  (void)argc; (void)argv;
  FD_LOG_WARNING(( "unsupported for this build target" ));
  return 1;
}

#endif
