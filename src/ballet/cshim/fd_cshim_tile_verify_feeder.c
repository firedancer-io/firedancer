#include "fd_cshim_tile.h"

#define FD_FRANK_VERIFY_CNT_MAX       (128)
#define FD_FRANK_CNC_DIAG_IN_BACKP    FD_CNC_DIAG_IN_BACKP  /* ==0 */
#define FD_FRANK_CNC_DIAG_BACKP_CNT   FD_CNC_DIAG_BACKP_CNT /* ==1 */
#define FD_FRANK_CNC_DIAG_HA_FILT_CNT (2UL)                 /* updated by verify tile, frequently in ha situations, never o.w. */
#define FD_FRANK_CNC_DIAG_HA_FILT_SZ  (3UL)                 /* " */
#define FD_FRANK_CNC_DIAG_SV_FILT_CNT (4UL)                 /* ", ideally never */
#define FD_FRANK_CNC_DIAG_SV_FILT_SZ  (5UL)                 /* " */

int
fd_cshim_verify_feeder( int     argc,
                        char ** argv ) {
  if( FD_UNLIKELY( argc < 5 ) ) {
    FD_LOG_ERR(( "fd_cshim_verify_feeder expects at least 5 arguments, but got %d", argc ));
  }

  FD_LOG_INFO(( "fd_frank_verify feeder initializing" ));

  /* Parse file descriptor numbers */
  char * fd_shim_ctl_cstr = argv[0];
  char * fd_shim_msg_cstr = argv[1];

  int fd_shim_ctl = fd_cstr_to_int( fd_shim_ctl_cstr );
  int fd_shim_msg = fd_cstr_to_int( fd_shim_msg_cstr );

  if( FD_UNLIKELY( fd_shim_ctl<=0 || fd_shim_msg<=0 ) ) {
    FD_LOG_ERR(( "fd_cshim_verify_feeder: invalid shim file descriptors" ));
  }

  /* Open/create shm objects holding shim channel */
  fd_cshim_chan_t rx;
  fd_cshim_chan_open_fd( &rx, fd_shim_ctl, fd_shim_msg );

  fd_shmem_private_boot  ( NULL, NULL );

  char const * pod_gaddr = argv[2];
  char const * cfg_path  = argv[3];

  /* Load up the configuration for frank instance */

  FD_LOG_INFO(( "using configuration in pod %s at path %s", pod_gaddr, cfg_path ));
  uchar const * pod     = fd_wksp_pod_attach( pod_gaddr );
  uchar const * cfg_pod = fd_pod_query_subpod( pod, cfg_path );
  if( FD_UNLIKELY( !cfg_pod ) ) FD_LOG_ERR(( "path not found" ));

  /* Join the IPC objects needed this tile instance */

  uchar const * verify_pods = fd_pod_query_subpod( cfg_pod, "verifyin" );
  if( FD_UNLIKELY( !verify_pods ) ) FD_LOG_ERR(( "%s.verifyin path not found", cfg_path ));

  char const * verify_name     [FD_FRANK_VERIFY_CNT_MAX];
  uchar const * verify_pod     [FD_FRANK_VERIFY_CNT_MAX];
  fd_cnc_t * cnc               [FD_FRANK_VERIFY_CNT_MAX];
  ulong * cnc_diag             [FD_FRANK_VERIFY_CNT_MAX];
  int in_backp                 [FD_FRANK_VERIFY_CNT_MAX];
  fd_frag_meta_t * mcache      [FD_FRANK_VERIFY_CNT_MAX];
  ulong   depth                [FD_FRANK_VERIFY_CNT_MAX];
  ulong * sync                 [FD_FRANK_VERIFY_CNT_MAX];
  ulong   seq                  [FD_FRANK_VERIFY_CNT_MAX];
  uchar * dcache               [FD_FRANK_VERIFY_CNT_MAX];
  fd_wksp_t *  wksp            [FD_FRANK_VERIFY_CNT_MAX];
  ulong      chunk0            [FD_FRANK_VERIFY_CNT_MAX];
  ulong      wmark             [FD_FRANK_VERIFY_CNT_MAX];
  ulong      chunk             [FD_FRANK_VERIFY_CNT_MAX];
  ulong     * fseq             [FD_FRANK_VERIFY_CNT_MAX];
  ulong * fseq_diag            [FD_FRANK_VERIFY_CNT_MAX];
  ulong cr_max                 [FD_FRANK_VERIFY_CNT_MAX];
  ulong cr_resume              [FD_FRANK_VERIFY_CNT_MAX];
  ulong cr_refill              [FD_FRANK_VERIFY_CNT_MAX];
  long  lazy                   [FD_FRANK_VERIFY_CNT_MAX];
  fd_fctl_t * fctl             [FD_FRANK_VERIFY_CNT_MAX];
  ulong cr_avail               [FD_FRANK_VERIFY_CNT_MAX];
  ulong async_min              [FD_FRANK_VERIFY_CNT_MAX];
  uint seed                    [FD_FRANK_VERIFY_CNT_MAX];
  fd_rng_t _rng                [FD_FRANK_VERIFY_CNT_MAX][ 1 ];
  fd_rng_t * rng               [FD_FRANK_VERIFY_CNT_MAX];
  ulong accum_ha_filt_cnt      [FD_FRANK_VERIFY_CNT_MAX];
  ulong accum_ha_filt_sz       [FD_FRANK_VERIFY_CNT_MAX];
  ulong accum_sv_filt_cnt      [FD_FRANK_VERIFY_CNT_MAX];
  ulong accum_sv_filt_sz       [FD_FRANK_VERIFY_CNT_MAX];
  long next_house_keeping_time [FD_FRANK_VERIFY_CNT_MAX];

  uint vfy_cnt = (uint)argc - 4U;
  for (uint vfy_idx = 0; vfy_idx < vfy_cnt; vfy_idx++ ) {
    verify_name[vfy_idx] = argv[4+vfy_idx];
    FD_LOG_INFO(( "verifyin.%s init", verify_name[vfy_idx] ));

    /* Load up the configuration for this frank instance */

    verify_pod[vfy_idx] = fd_pod_query_subpod( verify_pods, verify_name[vfy_idx] );
    if( FD_UNLIKELY( !verify_pod[vfy_idx] ) ) FD_LOG_ERR(( "%s.verifyin.%s path not found", cfg_path, verify_name[vfy_idx] ));

    /* Join the IPC objects needed this tile instance */

    FD_LOG_INFO(( "joining %s.verifyin.%s.cnc", cfg_path, verify_name[vfy_idx] ));
    cnc[vfy_idx] = fd_cnc_join( fd_wksp_pod_map( verify_pod[vfy_idx], "cnc" ) );
    if( FD_UNLIKELY( !cnc[vfy_idx] ) ) FD_LOG_ERR(( "fd_cnc_join failed" ));
    cnc_diag[vfy_idx] = (ulong *)fd_cnc_app_laddr( cnc[vfy_idx] );
    if( FD_UNLIKELY( !cnc_diag[vfy_idx] ) ) FD_LOG_ERR(( "fd_cnc_app_laddr failed" ));
    in_backp[vfy_idx] = 1;

    FD_COMPILER_MFENCE();
    FD_VOLATILE( cnc_diag[vfy_idx][ FD_FRANK_CNC_DIAG_IN_BACKP    ] ) = 1UL;
    FD_VOLATILE( cnc_diag[vfy_idx][ FD_FRANK_CNC_DIAG_BACKP_CNT   ] ) = 0UL;
    FD_VOLATILE( cnc_diag[vfy_idx][ FD_FRANK_CNC_DIAG_HA_FILT_CNT ] ) = 0UL;
    FD_VOLATILE( cnc_diag[vfy_idx][ FD_FRANK_CNC_DIAG_HA_FILT_SZ  ] ) = 0UL;
    FD_VOLATILE( cnc_diag[vfy_idx][ FD_FRANK_CNC_DIAG_SV_FILT_CNT ] ) = 0UL;
    FD_VOLATILE( cnc_diag[vfy_idx][ FD_FRANK_CNC_DIAG_SV_FILT_SZ  ] ) = 0UL;
    FD_COMPILER_MFENCE();

    FD_LOG_INFO(( "joining %s.verifyin.%s.mcache", cfg_path, verify_name[vfy_idx] ));
    mcache[vfy_idx] = fd_mcache_join( fd_wksp_pod_map( verify_pod[vfy_idx], "mcache" ) );
    if( FD_UNLIKELY( !mcache[vfy_idx] ) ) FD_LOG_ERR(( "fd_mcache_join failed" ));
    depth[vfy_idx] = fd_mcache_depth    ( mcache[vfy_idx] ); //WW <= 8192
    sync[vfy_idx]  = fd_mcache_seq_laddr( mcache[vfy_idx] );
    seq[vfy_idx]   = fd_mcache_seq_query( sync[vfy_idx]   );

    FD_LOG_INFO(( "joining %s.verifyin.%s.dcache", cfg_path, verify_name[vfy_idx] ));
    dcache[vfy_idx] = fd_dcache_join( fd_wksp_pod_map( verify_pod[vfy_idx], "dcache" ) );
    if( FD_UNLIKELY( !dcache[vfy_idx] ) ) FD_LOG_ERR(( "fd_dcache_join failed" ));
    wksp[vfy_idx] = fd_wksp_containing( dcache[vfy_idx] ); /* chunks are referenced relative to the containing workspace */
    if( FD_UNLIKELY( !wksp[vfy_idx] ) ) FD_LOG_ERR(( "fd_wksp_containing failed" ));
    chunk0[vfy_idx] = fd_dcache_compact_chunk0( wksp[vfy_idx], dcache[vfy_idx] );
    wmark [vfy_idx] = fd_dcache_compact_wmark ( wksp[vfy_idx], dcache[vfy_idx], FD_SHIM_MSG_SZ );
    chunk [vfy_idx] = chunk0[vfy_idx];

    FD_LOG_INFO(( "joining %s.verifyin.%s.fseq", cfg_path, verify_name[vfy_idx] ));
    fseq[vfy_idx] = fd_fseq_join( fd_wksp_pod_map( verify_pod[vfy_idx], "fseq" ) );
    if( FD_UNLIKELY( !fseq[vfy_idx] ) ) FD_LOG_ERR(( "fd_fseq_join failed" ));
    fseq_diag[vfy_idx] = (ulong *)fd_fseq_app_laddr( fseq[vfy_idx] );
    if( FD_UNLIKELY( !fseq_diag[vfy_idx] ) ) FD_LOG_ERR(( "fd_fseq_app_laddr failed for vfy_idx=%u", vfy_idx ));
    FD_VOLATILE( fseq_diag[ FD_FSEQ_DIAG_SLOW_CNT ] ) = 0UL; /* Managed by the fctl */

    /* Setup local objects used by this tile */

    FD_LOG_INFO(( "configuring flow control" ));
    cr_max    [vfy_idx] = fd_pod_query_ulong( verify_pod[vfy_idx], "cr_max",    0UL );
    cr_resume [vfy_idx] = fd_pod_query_ulong( verify_pod[vfy_idx], "cr_resume", 0UL );
    cr_refill [vfy_idx] = fd_pod_query_ulong( verify_pod[vfy_idx], "cr_refill", 0UL );
    lazy      [vfy_idx] = fd_pod_query_long ( verify_pod[vfy_idx], "lazy",      0L  );
    FD_LOG_INFO(( "%s.verifyin.%s.cr_max    %lu", cfg_path, verify_name[vfy_idx], cr_max    [vfy_idx]));
    FD_LOG_INFO(( "%s.verifyin.%s.cr_resume %lu", cfg_path, verify_name[vfy_idx], cr_resume [vfy_idx]));
    FD_LOG_INFO(( "%s.verifyin.%s.cr_refill %lu", cfg_path, verify_name[vfy_idx], cr_refill [vfy_idx]));
    FD_LOG_INFO(( "%s.verifyin.%s.lazy      %li", cfg_path, verify_name[vfy_idx], lazy      [vfy_idx]));

    fctl[vfy_idx] =  fd_fctl_cfg_done(
                          fd_fctl_cfg_rx_add(
                            fd_fctl_join(
                              fd_fctl_new(
                                fd_alloca(
                                  FD_FCTL_ALIGN,
                                  fd_fctl_footprint( 1UL )
                                ),
                                1UL
                              )
                            ),
                            depth[vfy_idx],
                            fseq[vfy_idx],
                            &fseq_diag[vfy_idx][ FD_FSEQ_DIAG_SLOW_CNT ]
                          ),
                          1UL /*cr_burst*/,
                          cr_max   [vfy_idx],
                          cr_resume[vfy_idx],
                          cr_refill[vfy_idx]
                        );
    if( FD_UNLIKELY( !fctl[vfy_idx] ) ) FD_LOG_ERR(( "Unable to create flow control for vfy_idx=%u", vfy_idx ));
    FD_LOG_INFO(( "for vfy_idx=%u, using cr_burst %lu, cr_max %lu, cr_resume %lu, cr_refill %lu",
                  vfy_idx,
                  fd_fctl_cr_burst  ( fctl[vfy_idx] ),
                  fd_fctl_cr_max    ( fctl[vfy_idx] ),
                  fd_fctl_cr_resume ( fctl[vfy_idx] ),
                  fd_fctl_cr_refill ( fctl[vfy_idx] )
                ));

    cr_avail[vfy_idx] = 0UL;

    if( lazy[vfy_idx]<=0L ) lazy[vfy_idx] = fd_tempo_lazy_default( depth[vfy_idx] );
    FD_LOG_INFO(( "using lazy %li ns", lazy[vfy_idx] ));
    async_min[vfy_idx] = fd_tempo_async_min( lazy[vfy_idx], 1UL /*event_cnt*/, (float)fd_tempo_tick_per_ns( NULL ) );
    if( FD_UNLIKELY( !async_min[vfy_idx] ) ) FD_LOG_ERR(( "bad lazy" ));

    seed[vfy_idx] = fd_pod_query_uint( verify_pod[vfy_idx], "seed", (uint)fd_tile_id() ); /* use app tile_id as default */
    FD_LOG_INFO(( "creating rng (%s.verify.%s.seed %u)", cfg_path, verify_name[vfy_idx], seed[vfy_idx] ));
    rng [vfy_idx] = fd_rng_join( fd_rng_new( _rng[vfy_idx], seed[vfy_idx], 0UL ) );
    if( FD_UNLIKELY( !rng[vfy_idx] ) ) FD_LOG_ERR(( "fd_rng_join failed" ));

    accum_ha_filt_cnt [vfy_idx] = 0UL;
    accum_ha_filt_sz  [vfy_idx] = 0UL;
    accum_sv_filt_cnt [vfy_idx] = 0UL;
    accum_sv_filt_sz  [vfy_idx] = 0UL;
  }

  /* Start verifying */

  long curr_time               = fd_tickcount();
  for ( uint vfy_idx = 0; vfy_idx < vfy_cnt; vfy_idx++ ) {
    fd_cnc_signal( cnc[vfy_idx], FD_CNC_SIGNAL_RUN );
    next_house_keeping_time[vfy_idx] = curr_time;
    FD_LOG_INFO(( "verifyin.%s run", verify_name[vfy_idx] ));
  }

  for(;;) {
    for ( uint vfy_idx = 0; vfy_idx < vfy_cnt; vfy_idx++ ) {
      /* Do housekeeping at a low rate in the background */
      if( FD_UNLIKELY( curr_time >= next_house_keeping_time[vfy_idx] ) ) {
          /* Send synchronization info */
          fd_mcache_seq_update( sync[vfy_idx], seq[vfy_idx] );

          /* Send diagnostic info */
          fd_cnc_heartbeat( cnc[vfy_idx], curr_time );
          FD_COMPILER_MFENCE();
          FD_VOLATILE( cnc_diag[vfy_idx][ FD_FRANK_CNC_DIAG_HA_FILT_CNT ] ) = FD_VOLATILE_CONST( cnc_diag[vfy_idx][ FD_FRANK_CNC_DIAG_HA_FILT_CNT ] ) + accum_ha_filt_cnt[vfy_idx];
          FD_VOLATILE( cnc_diag[vfy_idx][ FD_FRANK_CNC_DIAG_HA_FILT_SZ  ] ) = FD_VOLATILE_CONST( cnc_diag[vfy_idx][ FD_FRANK_CNC_DIAG_HA_FILT_SZ  ] ) + accum_ha_filt_sz [vfy_idx];
          FD_VOLATILE( cnc_diag[vfy_idx][ FD_FRANK_CNC_DIAG_SV_FILT_CNT ] ) = FD_VOLATILE_CONST( cnc_diag[vfy_idx][ FD_FRANK_CNC_DIAG_SV_FILT_CNT ] ) + accum_sv_filt_cnt[vfy_idx];
          FD_VOLATILE( cnc_diag[vfy_idx][ FD_FRANK_CNC_DIAG_SV_FILT_SZ  ] ) = FD_VOLATILE_CONST( cnc_diag[vfy_idx][ FD_FRANK_CNC_DIAG_SV_FILT_SZ  ] ) + accum_sv_filt_sz [vfy_idx];
          FD_COMPILER_MFENCE();
          accum_ha_filt_cnt [vfy_idx] = 0UL;
          accum_ha_filt_sz  [vfy_idx] = 0UL;
          accum_sv_filt_cnt [vfy_idx] = 0UL;
          accum_sv_filt_sz  [vfy_idx] = 0UL;

          /* Receive command-and-control signals */
          ulong s = fd_cnc_signal_query( cnc[vfy_idx] );
          if( FD_UNLIKELY( s!=FD_CNC_SIGNAL_RUN ) ) {
            if( FD_UNLIKELY( s!=FD_CNC_SIGNAL_HALT ) ) FD_LOG_ERR(( "Unexpected signal" ));
            break;
          }

          /* Receive flow control credits */
          cr_avail[vfy_idx] = fd_fctl_tx_cr_update( fctl[vfy_idx], cr_avail[vfy_idx], seq[vfy_idx] );
          if( FD_UNLIKELY( in_backp[vfy_idx] ) ) {
            if( FD_LIKELY( cr_avail[vfy_idx] ) ) {
              FD_VOLATILE( cnc_diag[vfy_idx][ FD_FRANK_CNC_DIAG_IN_BACKP ] ) = 0UL;
              in_backp[vfy_idx] = 0;
            }
          }

        /* Reload housekeeping timer */
        next_house_keeping_time[vfy_idx] = curr_time + (long)fd_tempo_async_reload( rng[vfy_idx], async_min[vfy_idx] );
      }

      /* Check if we are backpressured */
      if( FD_UNLIKELY( !cr_avail[vfy_idx] ) ) {
        if( FD_UNLIKELY( !in_backp[vfy_idx] ) ) {
          FD_VOLATILE( cnc_diag[vfy_idx][ FD_FRANK_CNC_DIAG_IN_BACKP  ] ) = 1UL;
          FD_VOLATILE( cnc_diag[vfy_idx][ FD_FRANK_CNC_DIAG_BACKP_CNT ] ) = FD_VOLATILE_CONST( cnc_diag[vfy_idx][ FD_FRANK_CNC_DIAG_BACKP_CNT ] )+1UL;
          in_backp[vfy_idx] = 1;
        }
        //No pause, check next verifier instead: FD_SPIN_PAUSE();
        curr_time = fd_tickcount();
        continue;
      }

      ulong   tsorig = fd_frag_meta_ts_comp( fd_tickcount() );

      fd_cshim_chan_msg_t shm_msg;
      fd_cshim_chan_recvmsg(&rx, &shm_msg);

      /* shim payload layout

         [ mcache sig ] (8 bytes)
         [ payload    ] (? bytes) */

      ulong   mcache_sig  = *((ulong *)shm_msg.payload);
      uchar * txn_payload =            shm_msg.payload    + 8;
      ulong   txn_size    =            shm_msg.payload_sz - 8UL;

      /* dcache msg layout

         [ payload      ] (? bytes)
         [ pad-align 2B ] (? bytes)
         [ fd_txn_t     ] (? bytes)
         [ payload_sz   ] (2B) */

      uchar *  dcache_chunk_laddr = (uchar *)fd_chunk_to_laddr( wksp[vfy_idx], chunk[vfy_idx] );
      /* FIXME: Bound checks */
      fd_memcpy( dcache_chunk_laddr, (const void *) txn_payload, txn_size );

      uchar * dest_ptr = dcache_chunk_laddr + txn_size;
      dest_ptr = (uchar *) fd_ulong_align_up( (ulong) dest_ptr, 2UL );
      ulong parsed_sz = fd_txn_parse( dcache_chunk_laddr, txn_size, dest_ptr, NULL );
      if( FD_UNLIKELY( !parsed_sz ) ) {
        FD_LOG_WARNING(( "Parsing the transaction (size=%lu) failed. First bytes of payload are %02hhx %02hhx %02hhx %02hhx", txn_size,
              txn_payload[ 0 ],
              txn_payload[ 1 ],
              txn_payload[ 2 ],
              txn_payload[ 3 ] ));
        continue;
      }
      fd_txn_t * txn_ptr = (fd_txn_t *) dest_ptr;

#if DETAILED_LOGGING
      FD_LOG_NOTICE(( "Signature cnt: %hhu, blockhash off %hu", txn_ptr->signature_cnt, txn_ptr->recent_blockhash_off ));
#else
      (void) txn_ptr;
#endif

      dest_ptr += parsed_sz;
      *(ushort*)dest_ptr = (ushort) txn_size;
      dest_ptr += 2UL;

      ulong tspub    = fd_frag_meta_ts_comp( fd_tickcount() );
      ulong msg_sz   = (ulong)(dest_ptr - dcache_chunk_laddr);
      ulong ctl      = fd_frag_meta_ctl( rx.rseq, 1, 1, 0 );
      fd_mcache_publish( mcache[vfy_idx], depth[vfy_idx], seq[vfy_idx], mcache_sig, chunk[vfy_idx], msg_sz, ctl, tsorig, tspub );

      chunk[vfy_idx] = fd_dcache_compact_next( chunk[vfy_idx], msg_sz, chunk0[vfy_idx], wmark[vfy_idx] );
      seq[vfy_idx]   = fd_seq_inc( seq[vfy_idx], 1UL );
      cr_avail[vfy_idx]--;
      curr_time = fd_tickcount();
    }
  }

  /* Clean up */
  for ( uint vfy_idx = 0; vfy_idx < vfy_cnt; vfy_idx++ ) {
    FD_LOG_INFO(( "verify.%s fini", verify_name[vfy_idx]  ));
    fd_cnc_signal     ( cnc[vfy_idx],  FD_CNC_SIGNAL_BOOT  );
    fd_rng_delete     ( fd_rng_leave   ( rng   [vfy_idx]  ));
    fd_fctl_delete    ( fd_fctl_leave  ( fctl  [vfy_idx]  ));
    fd_wksp_pod_unmap ( fd_fseq_leave  ( fseq  [vfy_idx]  ));
    fd_wksp_pod_unmap ( fd_dcache_leave( dcache[vfy_idx]  ));
    fd_wksp_pod_unmap ( fd_mcache_leave( mcache[vfy_idx]  ));
    fd_wksp_pod_unmap ( fd_cnc_leave   ( cnc   [vfy_idx]  ));
  }
  fd_wksp_pod_detach( pod );
  return 0;
}
