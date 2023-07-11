#include "fd_frank.h"
#include "../../util/net/fd_eth.h"
#include "../../util/net/fd_ip4.h"
#include "../../util/net/fd_udp.h"
#include "../../ballet/txn/fd_txn.h"

#if FD_HAS_FRANK

int
fd_frank_parser_task( int     argc,
                      char ** argv ) {
  (void)argc;
  fd_log_thread_set( argv[0] );
  char const * parser_name = argv[0];
  FD_LOG_INFO(( "parser.%s init", parser_name ));

  /* Parse "command line" arguments */

  char const * pod_gaddr = argv[1];
  char const * cfg_path  = argv[2];

  /* Load up the configuration for this frank instance */
  FD_LOG_INFO(( "using configuration in pod %s at path %s", pod_gaddr, cfg_path ));
  uchar const * pod     = fd_wksp_pod_attach( pod_gaddr );
  uchar const * cfg_pod = fd_pod_query_subpod( pod, cfg_path );
  if( FD_UNLIKELY( !cfg_pod ) ) FD_LOG_ERR(( "path not found" ));

  /* cnc */
  FD_LOG_INFO(( "joining %s.parser.%s.cnc", cfg_path, parser_name ));
  fd_cnc_t * parser_cnc = fd_cnc_join( fd_wksp_pod_map( cfg_pod, "parser.cnc" ) );
  if( FD_UNLIKELY( !parser_cnc ) ) FD_LOG_ERR(( "fd_cnc_join failed" ));
  if( FD_UNLIKELY( fd_cnc_app_sz( parser_cnc )<64UL ) ) { FD_LOG_WARNING(( "cnc app sz must be at least 64" )); return 1; }
  if( FD_UNLIKELY( fd_cnc_signal_query( parser_cnc )!=FD_CNC_SIGNAL_BOOT ) ) FD_LOG_ERR(( "cnc not in boot state" ));
  ulong * parser_cnc_diag = (ulong *)fd_cnc_app_laddr( parser_cnc );

  /* sentinel_mcache */
  FD_LOG_INFO(( "joining %s.parser.%s.sentinel_mcache", cfg_path, parser_name ));
  fd_frag_meta_t * sentinel_mcache = fd_mcache_join( fd_wksp_pod_map( cfg_pod, "parser.sentinel_mcache" ) );
  if( FD_UNLIKELY( !sentinel_mcache ) ) FD_LOG_ERR(( "fd_mcache_join failed" ));
  ulong const *  sentinel_sync  = fd_mcache_seq_laddr_const( sentinel_mcache );
  ulong sentinel_seq = fd_mcache_seq_query( sentinel_sync );

  /* fseq_diag */
  FD_LOG_INFO(( "joining %s.replay.fseq", cfg_path ));
  ulong * replay_fseq = fd_fseq_join( fd_wksp_pod_map( cfg_pod, "replay.fseq" ) );
  if( FD_UNLIKELY( !replay_fseq ) ) FD_LOG_ERR(( "fd_fseq_join failed" ));
  ulong * replay_fseq_diag = (ulong *)fd_fseq_app_laddr( replay_fseq );
  if( FD_UNLIKELY( !replay_fseq_diag ) ) FD_LOG_ERR(( "fd_fseq_app_laddr failed" ));
  FD_COMPILER_MFENCE();
  FD_VOLATILE( replay_fseq_diag[ FD_FSEQ_DIAG_PUB_CNT   ] ) = 0UL;
  FD_VOLATILE( replay_fseq_diag[ FD_FSEQ_DIAG_PUB_SZ    ] ) = 0UL;
  FD_VOLATILE( replay_fseq_diag[ FD_FSEQ_DIAG_FILT_CNT  ] ) = 0UL;
  FD_VOLATILE( replay_fseq_diag[ FD_FSEQ_DIAG_FILT_SZ   ] ) = 0UL;
  FD_VOLATILE( replay_fseq_diag[ FD_FSEQ_DIAG_OVRNP_CNT ] ) = 0UL;
  FD_VOLATILE( replay_fseq_diag[ FD_FSEQ_DIAG_OVRNR_CNT ] ) = 0UL;
  FD_VOLATILE( replay_fseq_diag[ FD_FSEQ_DIAG_SLOW_CNT  ] ) = 0UL; /* Managed by the fctl */
  FD_COMPILER_MFENCE();
  ulong in_accum_pub_cnt   = 0UL;
  ulong in_accum_pub_sz    = 0UL;
  ulong in_accum_ovrnp_cnt = 0UL;
  ulong in_accum_ovrnr_cnt = 0UL;

  /* Demo: txn random corruption */
  int demo_txn_rand_corrupt = fd_pod_query_int( cfg_pod, "demo.txn_rand_corrupt", 0 );
  if( !!demo_txn_rand_corrupt ) FD_LOG_WARNING(("demo_txn_rand_corrupt enabled!"));

  /* Demo: txn broadcast */
  int demo_txn_broadcast = fd_pod_query_int( cfg_pod, "demo.txn_broadcast", 0 );
  FD_LOG_NOTICE(( "%s.demo.txn_broadcast %d", cfg_path, demo_txn_broadcast ));

  /* rng */
  uint parser_seed = fd_pod_query_uint( cfg_pod, "parser.seed", (uint)fd_tile_id() ); /* use app tile_id as default */

  /* replay mcache / dcache */
  FD_LOG_INFO(( "joining %s.replay.mcache", cfg_path ));
  fd_frag_meta_t * replay_mcache = fd_mcache_join( fd_wksp_pod_map( cfg_pod, "replay.mcache" ) );
  FD_LOG_INFO(( "joining %s.replay.dcache", cfg_path ));
  uchar * replay_dcache = fd_dcache_join( fd_wksp_pod_map( cfg_pod, "replay.dcache" ) );

  /* wksp */
  fd_wksp_t * wksp = fd_wksp_containing( replay_dcache );

  /* Hook up to parser cnc */
  fd_cnc_t * cnc = parser_cnc;

  /* Command and control */
  ulong * cnc_diag = (ulong *)fd_cnc_app_laddr( cnc );
  ulong cnc_diag_pkt_cnt = 0ULL;
  ulong cnc_diag_txn_cnt = 0ULL;
    /* in_backp==1, backp_cnt==0 indicates waiting for initial credits,
      cleared during first housekeeping if credits available */
  ulong cnc_diag_in_backp      = 1UL;
  ulong cnc_diag_backp_cnt     = 0UL;
  cnc_diag[ FD_CNC_DIAG_IN_BACKP                   ] = 0UL;
  cnc_diag[ FD_CNC_DIAG_BACKP_CNT                  ] = 0UL;
  
  /* Hook up to replay mcache */
  fd_frag_meta_t const * mcache = replay_mcache;
  ulong                  depth  = fd_mcache_depth( mcache );
  ulong const *          sync   = fd_mcache_seq_laddr_const( mcache );
  ulong                  seq    = fd_mcache_seq_query( sync );
  fd_frag_meta_t const * mline = mcache + fd_mcache_line_idx( seq, depth );

  /* Hook up to replay flow control */
  ulong * fseq = replay_fseq;

  long lazy = fd_pod_query_long ( cfg_pod, "parser.lazy", 0L );

  uchar const * verify_pods = fd_pod_query_subpod( cfg_pod, "verifyin" );
  ulong verify_cnt = fd_pod_cnt_subpod( verify_pods );
  FD_LOG_INFO(( "%lu verify found", verify_cnt ));

  fd_frag_meta_t ** verify_mcache = (fd_frag_meta_t **)
  fd_alloca( alignof(fd_frag_meta_t *), sizeof(fd_frag_meta_t *)*verify_cnt );
  if( FD_UNLIKELY( !verify_mcache ) ) FD_LOG_ERR(( "fd_alloca failed" ));

  ulong * verify_seq = (ulong *)fd_alloca( alignof(ulong), sizeof(ulong)*verify_cnt );
  if( FD_UNLIKELY( !verify_seq ) ) FD_LOG_ERR(( "fd_alloca failed" ));

  ulong ** verify_fseq = (ulong **)fd_alloca( alignof(ulong *), sizeof(ulong *)*verify_cnt );
  if( FD_UNLIKELY( !verify_fseq ) ) FD_LOG_ERR(( "fd_alloca failed" ));
  ulong ** verify_fseq_diag = (ulong **)fd_alloca( alignof(ulong *), sizeof(ulong *)*verify_cnt );
  if( FD_UNLIKELY( !verify_fseq_diag ) ) FD_LOG_ERR(( "fd_alloca failed" ));

  /* output flow control state */
  fd_fctl_t ** verify_fctl      = (fd_fctl_t **)fd_alloca( alignof(fd_fctl_t *), sizeof(fd_fctl_t *)*verify_cnt );
  ulong     *  verify_cr_avail  = (ulong *)fd_alloca( alignof(ulong), sizeof(ulong)*verify_cnt );
  ulong        verify_cr_max    = fd_pod_query_ulong( cfg_pod, "parser.cr_max",    0UL );
  ulong        verify_cr_resume = fd_pod_query_ulong( cfg_pod, "parser.cr_resume", 0UL );
  ulong        verify_cr_refill = fd_pod_query_ulong( cfg_pod, "parser.cr_refill", 0UL );

  ulong verify_idx = 0UL;
  for( fd_pod_iter_t iter = fd_pod_iter_init( verify_pods ); !fd_pod_iter_done( iter ); iter = fd_pod_iter_next( iter ) ) {
    fd_pod_info_t info = fd_pod_iter_info( iter );
    if( FD_UNLIKELY( info.val_type!=FD_POD_VAL_TYPE_SUBPOD ) ) continue;
    char const  * verify_name =                info.key;
    uchar const * verify_pod  = (uchar const *)info.val;

    FD_LOG_INFO(( "joining %s.verify.%s.mcache", cfg_path, verify_name ));
    verify_mcache[ verify_idx ] = fd_mcache_join( fd_wksp_pod_map( verify_pod, "mcache" ) );
    if( FD_UNLIKELY( !verify_mcache[ verify_idx ] ) ) FD_LOG_ERR(( "fd_mcache_join failed" ));
    ulong const *  verify_sync  = fd_mcache_seq_laddr_const( verify_mcache[ verify_idx ] );
    verify_seq[ verify_idx ]    = fd_mcache_seq_query( verify_sync );

    FD_LOG_INFO(( "joining %s.verify.%s.fseq", cfg_path, verify_name ));
    verify_fseq[ verify_idx ] = fd_fseq_join( fd_wksp_pod_map( verify_pod, "fseq" ) );
    if( FD_UNLIKELY( !verify_fseq[ verify_idx ] ) ) FD_LOG_ERR(( "fd_fseq_join failed" ));
    verify_fseq_diag[ verify_idx ] = (ulong *)fd_fseq_app_laddr( verify_fseq[ verify_idx ] );
    if( FD_UNLIKELY( !verify_fseq_diag[ verify_idx ] ) ) FD_LOG_ERR(( "fd_fseq_app_laddr failed" ));
    FD_VOLATILE( verify_fseq_diag[ verify_idx ][ FD_FSEQ_DIAG_SLOW_CNT ] ) = 0UL; /* Managed by the fctl */

    verify_cr_avail[ verify_idx ] = 0UL;

    verify_fctl[ verify_idx ] = fd_fctl_cfg_done( fd_fctl_cfg_rx_add( fd_fctl_join( fd_fctl_new( fd_alloca( FD_FCTL_ALIGN,
                                                                                                  fd_fctl_footprint( 1UL ) ),
                                                                                        1UL ) ),
                                                            fd_mcache_depth(verify_mcache[ verify_idx ]), verify_fseq[ verify_idx ], &verify_fseq_diag[ verify_idx ][ FD_FSEQ_DIAG_SLOW_CNT ]),
                                                            // vin_fseq_diag[ FD_FSEQ_DIAG_SLOW_CNT ] ),
                                        1UL /*cr_burst*/, verify_cr_max, verify_cr_resume, verify_cr_refill );
    if( FD_UNLIKELY( !verify_fctl[ verify_idx ] ) ) FD_LOG_ERR(( "Unable to create flow control [%lu]", verify_idx ));
    FD_LOG_INFO(( "verify.%s using cr_burst %lu, cr_max %lu, cr_resume %lu, cr_refill %lu for verifyin %s", verify_name,
                  fd_fctl_cr_burst( verify_fctl[ verify_idx ] ), fd_fctl_cr_max( verify_fctl[ verify_idx ] ), fd_fctl_cr_resume( verify_fctl[ verify_idx ] ), fd_fctl_cr_refill( verify_fctl[ verify_idx ] ), verify_name ));

    FD_LOG_NOTICE(( "cr_max[%lu] %lu", verify_idx, fd_fctl_cr_max( verify_fctl[ verify_idx ] ) ));

    if( lazy<=0L ) lazy = fd_tempo_lazy_default( fd_mcache_depth(verify_mcache[ verify_idx ]) );
    FD_LOG_NOTICE(( "verify.%s using lazy %li ns", verify_name, lazy ));
    verify_idx++;
  }
  FD_TEST(verify_idx == verify_cnt);

  /* Hook up to the random number generator */
  fd_rng_t _rng[1];
  fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, parser_seed, 0UL ) );

  /* Txn parsing counters */
  fd_txn_parse_counters_t counters_opt[1];
  
  /* Verify round-robin */
  ulong verify_rrb_i = 0UL;

  /* Configure housekeeping */
  ulong async_min = fd_tempo_async_min( lazy, 1UL /*event_cnt*/, (float)fd_tempo_tick_per_ns( NULL ) );
  if( FD_UNLIKELY( !async_min ) ) FD_LOG_ERR(( "bad lazy" ));
  long now  = fd_tickcount();
  long then = now; /* Do housekeeping on first iteration of run loop */

  /* Main loop */
  fd_cnc_signal( cnc, FD_CNC_SIGNAL_RUN );
  FD_LOG_NOTICE(("parser running ... (verify_cnt %lu)", verify_cnt));

  for(;;) {

    /* Housekeeping */
    if( FD_UNLIKELY( (now-then)>=0L ) ) {
      /* Send flow control credits */
      fd_fctl_rx_cr_return( fseq, seq );
      /* Send diagnostic info */
      fd_cnc_heartbeat( cnc, fd_tickcount() );
      /* Receive command-and-control signals */
      ulong s = fd_cnc_signal_query( cnc );
      if( FD_UNLIKELY( s!=FD_CNC_SIGNAL_RUN ) ) {
        if( FD_UNLIKELY( s!=FD_CNC_SIGNAL_HALT ) ) FD_LOG_ERR(( "Unexpected signal" ));
        break;
      }
      
      /* Update basic cnc stats */
      FD_COMPILER_MFENCE();
      cnc_diag[ FD_CNC_DIAG_IN_BACKP             ]  = cnc_diag_in_backp;
      cnc_diag[ FD_CNC_DIAG_BACKP_CNT            ] += cnc_diag_backp_cnt;
      FD_COMPILER_MFENCE();
      cnc_diag_backp_cnt     = 0UL;

      /* Send synchronization info */
      FD_COMPILER_MFENCE();
      FD_VOLATILE( replay_fseq_diag[ FD_FSEQ_DIAG_PUB_CNT   ] ) += in_accum_pub_cnt;
      FD_VOLATILE( replay_fseq_diag[ FD_FSEQ_DIAG_PUB_SZ    ] ) += in_accum_pub_sz;
      FD_VOLATILE( replay_fseq_diag[ FD_FSEQ_DIAG_OVRNP_CNT ] ) += in_accum_ovrnp_cnt;
      FD_VOLATILE( replay_fseq_diag[ FD_FSEQ_DIAG_OVRNR_CNT ] ) += in_accum_ovrnr_cnt;
      FD_VOLATILE( parser_cnc_diag[ FD_FRANK_PARSER_CNC_DIAG_PUB_CNT ] ) += cnc_diag_txn_cnt;
      FD_COMPILER_MFENCE();
      in_accum_pub_cnt   = 0UL;
      in_accum_pub_sz    = 0UL;
      in_accum_ovrnp_cnt = 0UL;
      in_accum_ovrnr_cnt = 0UL;
      cnc_diag_txn_cnt = 0UL;

      /* Receive flow control credits */
      for(ulong verify_i=0; verify_i<verify_cnt; verify_i++) {
        /* Send synchronization info */
        fd_mcache_seq_update( fd_mcache_seq_laddr( verify_mcache[ verify_i ] ), verify_seq[ verify_i ] );
        verify_cr_avail[ verify_i ] = fd_fctl_tx_cr_update( verify_fctl[ verify_i ], verify_cr_avail[ verify_i ], verify_seq[ verify_i ] );
      }
      fd_mcache_seq_update( fd_mcache_seq_laddr( sentinel_mcache ), sentinel_seq );

      /* Reload housekeeping timer */
      then = now + (long)fd_tempo_async_reload( rng, async_min );
    }

    /* Note: the backpressure check below still works in the case of demo_txn_broadcast */
    /* Search for the next available verify tile */
    ulong verify_i = 0UL;
    while( verify_i < verify_cnt) {
      if( FD_LIKELY( !!verify_cr_avail[ verify_rrb_i ] ) ) { break; }
      /* move to the next verify tile */
      verify_rrb_i += 1UL; if( verify_rrb_i >= verify_cnt ) { verify_rrb_i = 0UL; }
      /* increase the count */
      verify_i += 1UL;
    }

    /* Check if we are backpressured.  If so, count any transition into
      a backpressured regime and spin to wait for flow control credits
      to return.  We don't do a fully atomic update here as it is only
      diagnostic and it will still be correct the usual case where
      individual diagnostic counters aren't used by writers in
      different threads of execution.  We only count the transition
      from not backpressured to backpressured. */

    if( FD_UNLIKELY( verify_i >= verify_cnt ) ) {
      cnc_diag_backp_cnt += (ulong)!cnc_diag_in_backp;
      cnc_diag_in_backp   = 1UL;
      FD_SPIN_PAUSE();
      /* Try to reload credits */
      for(ulong v_i=0; v_i<verify_cnt; v_i++) {
        verify_cr_avail[ v_i ] = fd_fctl_tx_cr_update( verify_fctl[ v_i ], verify_cr_avail[ v_i ], verify_seq[ v_i ] );
      }
      now = fd_tickcount();
      continue;
    }
    cnc_diag_in_backp = 0UL;

    /* Wait for seq */
    ulong seq_found = fd_frag_meta_seq_query( mline );
    long  diff      = fd_seq_diff( seq_found, seq );
    if( FD_UNLIKELY( diff ) ) { /* caught up or overrun, optimize for expected sequence number ready */
      if( FD_LIKELY( diff < 0L ) ) {
        FD_SPIN_PAUSE();
        now = fd_tickcount();
        continue;
      }
      FD_LOG_WARNING(("Overrun while polling"));
      seq = seq_found;
      /* can keep processing from the new seq */
    }
    ulong sz    = (ulong)mline->sz;
    ulong chunk = mline->chunk;
    ulong ctl = mline->ctl;
    ulong sig = mline->sig;
    ulong tsorig = mline->tsorig;
    ulong tspub = mline->tspub;
    now = fd_tickcount();

    /* Increment counters */
    in_accum_pub_cnt++;
    in_accum_pub_sz+=sz;
    
    /* Process the received fragment */
    ulong p0 = (ulong) fd_chunk_to_laddr_const( wksp, chunk );
    uchar const * p = (uchar const *)p0;

    /* Calculate offsets */
    ulong msg_end = p0 + sz;
    ulong payload_sz = (ulong) (*((ushort*)(msg_end-sizeof(ushort))));

    /* Parse txn */
    fd_txn_t * txn = (fd_txn_t *)( fd_ulong_align_up( p0 + payload_sz, 2UL ) );
    ulong txn_sz = fd_txn_parse( p, payload_sz, txn, counters_opt );

    /* Count processed packets */
    cnc_diag_pkt_cnt += 1ULL;

    if( FD_LIKELY( txn_sz ) ) {
      /* randomly corrupt the txn's msg (if enabled) */
      if( !!demo_txn_rand_corrupt ) {
        ulong const v_sig = *(ulong const *)(p + txn->signature_off);
        txn->acct_addr_off = (ushort)(txn->acct_addr_off - (ushort)(v_sig & 0x1UL));
      }
      /* Publish to the appropriate mcache */
      ulong out_sig     = sig;
      // ulong out_sig     = (ulong)verif;
      ulong out_chunk   = chunk;
      ulong out_sz      = sz;
      ulong out_ctl     = ctl;
      ulong out_tsorig  = tsorig;
      ulong out_tspub   = tspub;
      if( !!demo_txn_broadcast ) {
        for(ulong v_i=0; v_i<verify_cnt; v_i++) {
          if( FD_LIKELY( !!verify_cr_avail[ v_i ] ) ) {
            fd_mcache_publish( verify_mcache[ v_i ], fd_mcache_depth(verify_mcache[ v_i ]), verify_seq[ v_i ],
                              out_sig, out_chunk, out_sz, out_ctl, out_tsorig, out_tspub );
            fd_mcache_publish( sentinel_mcache, fd_mcache_depth(sentinel_mcache), sentinel_seq,
                              out_sig, out_chunk, out_sz, out_ctl, out_tsorig, out_tspub );
            sentinel_seq = fd_seq_inc( sentinel_seq, 1UL );
            /* Windup for the next iteration */
            verify_seq[ v_i ] = fd_seq_inc( verify_seq[ v_i ], 1UL );
            verify_cr_avail[ v_i ]--;
            /* count processed transactions */
            cnc_diag_txn_cnt += 1ULL;
          }
        }
      }
      else {
        ulong curr_depth  = fd_mcache_depth(verify_mcache[ verify_rrb_i ]);
        ulong curr_seq    = verify_seq[ verify_rrb_i ];
        ulong curr_credit = verify_cr_avail[ verify_rrb_i ];
        fd_mcache_publish( verify_mcache[ verify_rrb_i ], curr_depth, curr_seq,
                          out_sig, out_chunk, out_sz, out_ctl, out_tsorig, out_tspub );
        fd_mcache_publish( sentinel_mcache, fd_mcache_depth(sentinel_mcache), sentinel_seq,
                          out_sig, out_chunk, out_sz, out_ctl, out_tsorig, out_tspub );
        sentinel_seq = fd_seq_inc( sentinel_seq, 1UL );
        /* Windup for the next iteration */
        curr_seq = fd_seq_inc( curr_seq, 1UL );
        curr_credit--;
        /* count processed transactions */
        cnc_diag_txn_cnt += 1ULL;
        /* Windup for the next iteration */
        verify_seq[ verify_rrb_i ] = curr_seq;
        verify_cr_avail[ verify_rrb_i ] = curr_credit;
        verify_rrb_i += 1UL; if( verify_rrb_i>= verify_cnt ) { verify_rrb_i = 0UL; }
      }
    }
      
    /* Check that we weren't overrun while processing */
    ulong seq_found2 = fd_frag_meta_seq_query( mline );
    if( FD_UNLIKELY( fd_seq_ne( seq_found2, seq ) ) ) {
      FD_LOG_ERR(( "Overrun while reading" ));
      FD_TEST( 0 );
    }

    /* Wind up for the next iteration */
    seq = fd_seq_inc( seq, 1UL );
    mline = mcache + fd_mcache_line_idx( seq, depth );
    now = fd_tickcount();
  }

  /* cleanup */
  fd_rng_delete( fd_rng_leave( rng ) );
  fd_wksp_pod_unmap( fd_cnc_leave   ( parser_cnc    ) );
  fd_wksp_pod_unmap( fd_mcache_leave( replay_mcache ) );
  fd_wksp_pod_unmap( fd_dcache_leave( replay_dcache ) );
  fd_wksp_pod_unmap( fd_fseq_leave  ( replay_fseq   ) );
  fd_wksp_pod_unmap( fd_mcache_leave( sentinel_mcache ) );
  for( ulong v_i = 0; v_i < verify_cnt; v_i++ ) {
    fd_wksp_pod_unmap( fd_mcache_leave( verify_mcache[ v_i ] ) );
    fd_wksp_pod_unmap( fd_fseq_leave  (   verify_fseq[ v_i ] ) );
    fd_fctl_delete   ( fd_fctl_leave  (   verify_fctl[ v_i ] ) );
  }
  fd_rng_delete( fd_rng_leave( rng ) );
  fd_cnc_signal( cnc, FD_CNC_SIGNAL_BOOT );
  return 0;
}

#else

int
fd_frank_parser_task( int     argc,
                      char ** argv ) {
  (void)argc; (void)argv;
  FD_LOG_WARNING(( "unsupported for this build target" ));
  return 1;
}

#endif
