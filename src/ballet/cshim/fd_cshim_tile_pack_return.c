#include "fd_cshim_tile.h"

int
fd_cshim_pack_return( int argc,
                      char ** argv ) {
  if( FD_UNLIKELY( argc!=4 ) ) {
    FD_LOG_ERR(( "fd_cshim_pack_return expects 4 arguments, but got %d", argc ));
  }

  FD_LOG_INFO(( "fd_cshim_pack_return initializing" ));

  /* Parse file descriptor numbers */
  char * fd_shim_ctl_cstr = argv[0];
  char * fd_shim_msg_cstr = argv[1];

  int fd_shim_ctl = fd_cstr_to_int( fd_shim_ctl_cstr );
  int fd_shim_msg = fd_cstr_to_int( fd_shim_msg_cstr );

  if( FD_UNLIKELY( fd_shim_ctl<=0 || fd_shim_msg<=0 ) ) {
    FD_LOG_ERR(( "fd_cshim_pack_return: invalid shim file descriptors" ));
  }

  /* Open/create shm objects holding shim channel */
  fd_cshim_chan_t tx;
  fd_cshim_chan_open_fd( &tx, fd_shim_ctl, fd_shim_msg );

  /* Boot internal modules */
  fd_shmem_private_boot( NULL, NULL );

  FD_LOG_INFO(( "fd_cshim_pack_return initialized" ));

  /* Parse "command line" arguments */

  char const * pod_gaddr = argv[2];
  char const * cfg_path  = argv[3];

  /* Load up the configuration for frank instance */

  FD_LOG_INFO(( "using configuration in pod %s at path %s", pod_gaddr, cfg_path ));
  uchar const * pod     = fd_wksp_pod_attach( pod_gaddr );
  uchar const * cfg_pod = fd_pod_query_subpod( pod, cfg_path );
  if( FD_UNLIKELY( !cfg_pod ) ) FD_LOG_ERR(( "path not found" ));

  /* Join the IPC objects needed this tile instance */

  FD_LOG_INFO(( "joining %s.pack.out-mcache", cfg_path ));
  fd_frag_meta_t * mcache = fd_mcache_join( fd_wksp_pod_map( cfg_pod, "pack.out-mcache" ) );
  if( FD_UNLIKELY( !mcache ) ) FD_LOG_ERR(( "fd_mcache_join failed" ));
  ulong         depth = fd_mcache_depth( mcache );
  ulong const * sync  = fd_mcache_seq_laddr_const( mcache );
  ulong         seq   = fd_mcache_seq_query( sync );

  fd_frag_meta_t const * mline = mcache + fd_mcache_line_idx( seq, depth );
  /* Note (chunks are referenced relative to the containing workspace
     currently and there is just one workspace).  (FIXME: VALIDATE
     COMMON WORKSPACE FOR THESE) */
  fd_wksp_t * wksp = fd_wksp_containing( mcache );
  if( FD_UNLIKELY( !wksp ) ) FD_LOG_ERR(( "fd_wksp_containing failed" ));

  FD_LOG_INFO(( "joining %s.pack.out-dcache", cfg_path ));
  uchar * dcache = fd_dcache_join( fd_wksp_pod_map( cfg_pod, "pack.out-dcache" ) );
  if( FD_UNLIKELY( !dcache ) ) FD_LOG_ERR(( "fd_dcache_join failed" ));

  FD_LOG_INFO(( "joining %s.pack.return-fseq", cfg_path ));
  ulong * fseq = fd_fseq_join( fd_wksp_pod_map( cfg_pod, "pack.return-fseq" ) );
  if( FD_UNLIKELY( !fseq ) ) FD_LOG_ERR(( "fd_fseq_join failed" ));
  ulong * fseq_diag = (ulong *)fd_fseq_app_laddr( fseq );
  if( FD_UNLIKELY( !fseq_diag ) ) FD_LOG_ERR(( "fd_fseq_app_laddr failed" ));
  FD_COMPILER_MFENCE();
  FD_VOLATILE( fseq_diag[ FD_FSEQ_DIAG_PUB_CNT   ] ) = 0UL;
  FD_VOLATILE( fseq_diag[ FD_FSEQ_DIAG_PUB_SZ    ] ) = 0UL;
  FD_VOLATILE( fseq_diag[ FD_FSEQ_DIAG_FILT_CNT  ] ) = 0UL;
  FD_VOLATILE( fseq_diag[ FD_FSEQ_DIAG_FILT_SZ   ] ) = 0UL;
  FD_VOLATILE( fseq_diag[ FD_FSEQ_DIAG_OVRNP_CNT ] ) = 0UL;
  FD_VOLATILE( fseq_diag[ FD_FSEQ_DIAG_OVRNR_CNT ] ) = 0UL;
  FD_VOLATILE( fseq_diag[ FD_FSEQ_DIAG_SLOW_CNT  ] ) = 0UL; /* Managed by the fctl */
  FD_COMPILER_MFENCE();
  ulong accum_pub_cnt   = 0UL;
  ulong accum_pub_sz    = 0UL;
  ulong accum_ovrnp_cnt = 0UL;
  ulong accum_ovrnr_cnt = 0UL;

  /* Setup local objects used by this tile */

  long lazy = fd_tempo_lazy_default( depth );
  FD_LOG_INFO(( "using lazy %li ns", lazy ));
  ulong async_min = fd_tempo_async_min( lazy, 1UL /*event_cnt*/, (float)fd_tempo_tick_per_ns( NULL ) );

  uint seed = (uint)fd_tile_id();
  fd_rng_t _rng[ 1 ];
  fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, seed, 0UL ) );
  if( FD_UNLIKELY( !rng ) ) FD_LOG_ERR(( "fd_rng_join failed" ));

  /* Start forwarding scheduled txns */

  FD_LOG_INFO(( "running pack return" ));

  long now  = fd_tickcount();
  long then = now;            /* Do housekeeping on first iteration of run loop */

  for(;;) {

    /* Do housekeeping at a low rate in the background */

    if( FD_UNLIKELY( (now-then)>=0L ) ) {
      /*
        begin pack in related
      */

      FD_COMPILER_MFENCE();
      FD_VOLATILE( fseq_diag[ FD_FSEQ_DIAG_PUB_CNT   ] ) += accum_pub_cnt;
      FD_VOLATILE( fseq_diag[ FD_FSEQ_DIAG_PUB_SZ    ] ) += accum_pub_sz;
      FD_VOLATILE( fseq_diag[ FD_FSEQ_DIAG_OVRNP_CNT ] ) += accum_ovrnp_cnt;
      FD_VOLATILE( fseq_diag[ FD_FSEQ_DIAG_OVRNR_CNT ] ) += accum_ovrnr_cnt;
      FD_COMPILER_MFENCE();
      accum_pub_cnt   = 0UL;
      accum_pub_sz    = 0UL;
      accum_ovrnp_cnt = 0UL;
      accum_ovrnr_cnt = 0UL;

      fd_fseq_update( fseq, seq );

      /*
        end pack in related
      */

      /* Reload housekeeping timer */
      then = now + (long)fd_tempo_async_reload( rng, async_min );
    }

    /* See if there are any new transactions */
    ulong seq_found = fd_frag_meta_seq_query( mline );
    long  diff      = fd_seq_diff( seq_found, seq );
    if( FD_UNLIKELY( diff ) ) { /* caught up or overrun, optimize for expected sequence number ready */
      if( FD_LIKELY( diff<0L ) ) { /* caught up */
        FD_SPIN_PAUSE();
        now = fd_tickcount();
        continue;
      }
      /* overrun by dedup tile ... recover */
      accum_ovrnp_cnt++;
      seq = seq_found;
      /* can keep processing from the new seq */
    }

    /* At this point, we have started receiving frag seq with details in
       mline at time now.  Speculatively processs it here. */

    fd_txn_p_t const * txn = fd_chunk_to_laddr_const( wksp, mline->chunk );

    /* TODO(ripatel): Would be nice to get rid of stack buffer and copy to shm directly.
       Requires addl. flexibility in the shim API to write and commit in different fn calls. */

    ulong txn_sz = txn->payload_sz;
    if( FD_UNLIKELY( txn_sz>FD_MTU ) ) {
      FD_LOG_WARNING(( "fd_cshim_pack_return: found invalid tx with large MTU (%lu bytes)", txn_sz ));
      now = fd_tickcount();
      continue;
    }

    /* We've parsed the txn at this point but Labs BankingStage only accepts raw payloads.
       First two bytes are payload size. */
    uchar txn_payload[16+FD_MTU];
    *(ulong *)( txn_payload+0UL ) = txn_sz;
    *(ulong *)( txn_payload+8UL ) = mline->sig;
    fd_memcpy( txn_payload+16, txn->payload, txn_sz );

    /* Check that we weren't overrun while processing */
    seq_found = fd_frag_meta_seq_query( mline );
    if( FD_UNLIKELY( fd_seq_ne( seq_found, seq ) ) ) {
      accum_ovrnr_cnt++;
      seq = seq_found;
      now = fd_tickcount();
      continue;
    }

    accum_pub_cnt++;
    accum_pub_sz += txn_sz;

    /* Copy out to shim */
    fd_cshim_chan_sendmsg( &tx, txn_payload, 16+txn_sz );

    /* Wind up for the next iteration */
    seq   = fd_seq_inc( seq, 1UL );
    mline = mcache + fd_mcache_line_idx( seq, depth );
  }

  /* TODO Clean up */
  fd_wksp_pod_detach( pod );
  return 0;
}
