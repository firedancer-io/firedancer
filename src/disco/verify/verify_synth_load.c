#include <math.h>

int
fd_app_verify_task( int     argc,
                      char ** argv ) {
  (void)argc;
  fd_log_thread_set( argv[0] );
  char const * verify_name = argv[0];
  FD_LOG_INFO(( "verify.%s init", verify_name ));
  
  /* Parse "command line" arguments */

  char const * pod_gaddr = argv[1];

  /* Load up the configuration for this app instance */

  FD_LOG_INFO(( "using configuration in pod %s at path %s", pod_gaddr, cfg_path ));
  uchar const * pod     = fd_wksp_pod_attach( pod_gaddr );
  uchar const * cfg_pod = fd_pod_query_subpod( pod, cfg_path );
  if( FD_UNLIKELY( !cfg_pod ) ) FD_LOG_ERR(( "path not found" ));

  uchar const * verify_pods = fd_pod_query_subpod( cfg_pod, "verify" );
  if( FD_UNLIKELY( !verify_pods ) ) FD_LOG_ERR(( "%s.verify path not found", cfg_path ));

  uchar const * verify_pod = fd_pod_query_subpod( verify_pods, verify_name );
  if( FD_UNLIKELY( !verify_pod ) ) FD_LOG_ERR(( "%s.verify.%s path not found", cfg_path, verify_name ));

  /* Join the IPC objects needed this tile instance */

  FD_LOG_INFO(( "joining %s.verify.%s.cnc", cfg_path, verify_name ));
  fd_cnc_t * cnc = fd_cnc_join( fd_wksp_pod_map( verify_pod, "cnc" ) );
  if( FD_UNLIKELY( !cnc ) ) FD_LOG_ERR(( "fd_cnc_join failed" ));
  if( FD_UNLIKELY( fd_cnc_signal_query( cnc )!=FD_CNC_SIGNAL_BOOT ) ) FD_LOG_ERR(( "cnc not in boot state" ));
  ulong * cnc_diag = (ulong *)fd_cnc_app_laddr( cnc );
  if( FD_UNLIKELY( !cnc_diag ) ) FD_LOG_ERR(( "fd_cnc_app_laddr failed" ));
  int in_backp = 1;

  FD_COMPILER_MFENCE();
  FD_VOLATILE( cnc_diag[ FD_APP_CNC_DIAG_IN_BACKP    ] ) = 1UL;
  FD_VOLATILE( cnc_diag[ FD_APP_CNC_DIAG_BACKP_CNT   ] ) = 0UL;
  FD_VOLATILE( cnc_diag[ FD_APP_CNC_DIAG_HA_FILT_CNT ] ) = 0UL;
  FD_VOLATILE( cnc_diag[ FD_APP_CNC_DIAG_HA_FILT_SZ  ] ) = 0UL;
  FD_VOLATILE( cnc_diag[ FD_APP_CNC_DIAG_SV_FILT_CNT ] ) = 0UL;
  FD_VOLATILE( cnc_diag[ FD_APP_CNC_DIAG_SV_FILT_SZ  ] ) = 0UL;
  FD_COMPILER_MFENCE();

  FD_LOG_INFO(( "joining %s.verify.%s.mcache", cfg_path, verify_name ));
  fd_frag_meta_t * mcache = fd_mcache_join( fd_wksp_pod_map( verify_pod, "mcache" ) );
  if( FD_UNLIKELY( !mcache ) ) FD_LOG_ERR(( "fd_mcache_join failed" ));
  ulong   depth = fd_mcache_depth( mcache );
  ulong * sync  = fd_mcache_seq_laddr( mcache );
  ulong   seq   = fd_mcache_seq_query( sync );

  FD_LOG_INFO(( "joining %s.verify.%s.dcache", cfg_path, verify_name ));
  uchar * dcache = fd_dcache_join( fd_wksp_pod_map( verify_pod, "dcache" ) );
  if( FD_UNLIKELY( !dcache ) ) FD_LOG_ERR(( "fd_dcache_join failed" ));
  fd_wksp_t * wksp = fd_wksp_containing( dcache ); /* chunks are referenced relative to the containing workspace */
  if( FD_UNLIKELY( !wksp ) ) FD_LOG_ERR(( "fd_wksp_containing failed" ));
  ulong   chunk0 = fd_dcache_compact_chunk0( wksp, dcache );
  ulong   wmark  = fd_dcache_compact_wmark ( wksp, dcache, 1542UL ); /* FIXME: MTU? SAFETY CHECK THE FOOTPRINT? */
  ulong   chunk  = chunk0;

  FD_LOG_INFO(( "joining %s.verify.%s.fseq", cfg_path, verify_name ));
  ulong * fseq = fd_fseq_join( fd_wksp_pod_map( verify_pod, "fseq" ) );
  if( FD_UNLIKELY( !fseq ) ) FD_LOG_ERR(( "fd_fseq_join failed" ));
  ulong * fseq_diag = (ulong *)fd_fseq_app_laddr( fseq );
  if( FD_UNLIKELY( !fseq_diag ) ) FD_LOG_ERR(( "fd_fseq_app_laddr failed" ));
  FD_VOLATILE( fseq_diag[ FD_FSEQ_DIAG_SLOW_CNT ] ) = 0UL; /* Managed by the fctl */

  /* Setup local objects used by this tile */

  FD_LOG_INFO(( "configuring flow control" ));
  ulong cr_max    = fd_pod_query_ulong( verify_pod, "cr_max",    0UL );
  ulong cr_resume = fd_pod_query_ulong( verify_pod, "cr_resume", 0UL );
  ulong cr_refill = fd_pod_query_ulong( verify_pod, "cr_refill", 0UL );
  long  lazy      = fd_pod_query_long ( verify_pod, "lazy",      0L  );
  FD_LOG_INFO(( "%s.verify.%s.cr_max    %lu", cfg_path, verify_name, cr_max    ));
  FD_LOG_INFO(( "%s.verify.%s.cr_resume %lu", cfg_path, verify_name, cr_resume ));
  FD_LOG_INFO(( "%s.verify.%s.cr_refill %lu", cfg_path, verify_name, cr_refill ));
  FD_LOG_INFO(( "%s.verify.%s.lazy      %li", cfg_path, verify_name, lazy      ));

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

  uint seed = fd_pod_query_uint( verify_pod, "seed", (uint)fd_tile_id() ); /* use app tile_id as default */
  FD_LOG_INFO(( "creating rng (%s.verify.%s.seed %u)", cfg_path, verify_name, seed ));
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

  FD_LOG_INFO(( "verify.%s run", verify_name ));

# define SYNTH_LOAD 1
# if SYNTH_LOAD

  /* We assume that the distribution layer has parsed the incoming
     packets and stripped them down to a 32 byte public key, 64 byte
     signature (just 1 signature, which is typical though there are
     bursts where averages up to ~1.4 signatures are seen).  (FIXME:
     PROBABLY SHOULD DEDUCT SOME EXTRA BYTES FOR THE QUIC HEADER
     OVERHEAD AND SIGNATURE CNT FROM THE WORST CASE HERE.)  For every
     possible size then, we precomp a packet for each size with a valid
     signature to serve as our reference traffic. */

# define MSG_SZ_MIN (0UL)
# define MSG_SZ_MAX (1232UL-64UL-32UL)
  ulong ref_msg_mem_footprint = 0UL;
  for( ulong msg_sz=MSG_SZ_MIN; msg_sz<=MSG_SZ_MAX; msg_sz++ ) ref_msg_mem_footprint += fd_ulong_align_up( msg_sz + 96UL, 128UL );
  uchar * ref_msg_mem = fd_alloca( 128UL, ref_msg_mem_footprint );
  if( FD_UNLIKELY( !ref_msg_mem ) ) FD_LOG_ERR(( "fd_alloc failed" ));

  uchar * ref_msg[ MSG_SZ_MAX - MSG_SZ_MIN + 1UL ];
  for( ulong msg_sz=MSG_SZ_MIN; msg_sz<=MSG_SZ_MAX; msg_sz++ ) {
    ref_msg[ msg_sz - MSG_SZ_MIN ] = ref_msg_mem;
    uchar * public_key = ref_msg_mem;
    uchar * sig        = public_key  + 32UL;
    uchar * msg        = sig         + 64UL;
    ref_msg_mem += fd_ulong_align_up( msg_sz + 96UL, 128UL );

    /* Generate a public_key / private_key pair for this message */

    ulong private_key[4]; for( ulong i=0UL; i<4UL; i++ ) private_key[i] = fd_rng_ulong( rng );
    fd_ed25519_public_from_private( public_key, private_key, sha );

    /* Make a random message */
    for( ulong b=0UL; b<msg_sz; b++ ) msg[b] = fd_rng_uchar( rng );

    /* Sign it */
    fd_ed25519_sign( sig, msg, msg_sz, public_key, private_key, sha );
  }

  /* Sanity check the ref messages verify */
  for( ulong msg_sz=MSG_SZ_MIN; msg_sz<=MSG_SZ_MAX; msg_sz++ ) {
    uchar * public_key = ref_msg[ msg_sz - MSG_SZ_MIN ];
    uchar * sig        = public_key + 32UL;
    uchar * msg        = sig        + 64UL;
    FD_TEST( fd_ed25519_verify( msg, msg_sz, sig, public_key, sha )==FD_ED25519_SUCCESS );
  }
#endif

  long now  = fd_tickcount();
  long then = now;            /* Do housekeeping on first iteration of run loop */

# if SYNTH_LOAD

  ulong ha_cnt       = fd_pod_query_ulong( verify_pod, "ha-cnt",      fd_pod_query_ulong( cfg_pod, "verify.ha-cnt",      2UL    ) );
  float burst_avg    = fd_pod_query_float( verify_pod, "burst-avg",   fd_pod_query_float( cfg_pod, "verify.burst-avg",   324.f  ) );
  ulong msg_max      = fd_pod_query_ulong( verify_pod, "msg-max",     fd_pod_query_ulong( cfg_pod, "verify.msg-max",     MSG_SZ_MAX ) );
  ulong msg_framing  = fd_pod_query_ulong( verify_pod, "msg-framing", fd_pod_query_ulong( cfg_pod, "verify.msg-framing", 70UL+32UL+64UL ) );
  float pkt_bw       = fd_pod_query_float( verify_pod, "pkt-bw",      fd_pod_query_float( cfg_pod, "verify.pkt-bw",      1e9f   ) );
  float dup_frac     = fd_pod_query_float( verify_pod, "dup-frac",    fd_pod_query_float( cfg_pod, "verify.dup-frac",    0.01f  ) );
  float dup_avg_age  = fd_pod_query_float( verify_pod, "dup-avg-age", fd_pod_query_float( cfg_pod, "verify.dup-avg-age", 0.0f   ) );
  float errsv_frac   = fd_pod_query_float( verify_pod, "errsv-frac",  fd_pod_query_float( cfg_pod, "verify.errsv-frac",  1e-3f  ) );
  FD_LOG_NOTICE(( "burst-avg %f msg-max %lu msg-framing %lu pkt-bw %e dup-frac %f dup-avg-age %f errsv-frac %e",
                  (double)burst_avg, msg_max, msg_framing, (double)pkt_bw, (double)dup_frac, (double)dup_avg_age, (double)errsv_frac ));

  float burst_bw    = pkt_bw
                    / (1.f - ((((float)msg_framing)/((float)burst_avg)) / expm1f( -((float)msg_max)/((float)burst_avg) )));
  float tick_per_ns = (float)fd_tempo_tick_per_ns( NULL );
  float burst_tau   = (tick_per_ns*burst_avg)*(8e9f/burst_bw);
  int   ctl_som     = 1;
  ulong burst_ts    = 0UL;  /* Irrelevant value at init */
  long  burst_next  = then;
  ulong burst_rem;
  do {
    burst_next +=        (long)(0.5f + burst_tau*fd_rng_float_exp( rng ));
    burst_rem   = (ulong)(long)(0.5f + burst_avg*fd_rng_float_exp( rng ));
  } while( FD_UNLIKELY( !burst_rem ) );

  uint  dup_thresh   = (uint)(0.5f + dup_frac*(float)(1UL<<32));
  uint  errsv_thresh = (uint)(0.5f + errsv_frac*(float)(1UL<<32));

  ulong tx_idx  = fd_tile_idx();
  uint  dup_seq = 0U;
  ulong ha_tag  = fd_rng_ulong( rng );

# endif

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
      FD_VOLATILE( cnc_diag[ FD_APP_CNC_DIAG_HA_FILT_CNT ] ) = FD_VOLATILE_CONST( cnc_diag[ FD_APP_CNC_DIAG_HA_FILT_CNT ] ) + accum_ha_filt_cnt;
      FD_VOLATILE( cnc_diag[ FD_APP_CNC_DIAG_HA_FILT_SZ  ] ) = FD_VOLATILE_CONST( cnc_diag[ FD_APP_CNC_DIAG_HA_FILT_SZ  ] ) + accum_ha_filt_sz;
      FD_VOLATILE( cnc_diag[ FD_APP_CNC_DIAG_SV_FILT_CNT ] ) = FD_VOLATILE_CONST( cnc_diag[ FD_APP_CNC_DIAG_SV_FILT_CNT ] ) + accum_sv_filt_cnt;
      FD_VOLATILE( cnc_diag[ FD_APP_CNC_DIAG_SV_FILT_SZ  ] ) = FD_VOLATILE_CONST( cnc_diag[ FD_APP_CNC_DIAG_SV_FILT_SZ  ] ) + accum_sv_filt_sz;
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
          FD_VOLATILE( cnc_diag[ FD_APP_CNC_DIAG_IN_BACKP ] ) = 0UL;
          in_backp = 0;
        }
      }

      /* Reload housekeeping timer */
      then = now + (long)fd_tempo_async_reload( rng, async_min );
    }

    /* Check if we are backpressured */
    if( FD_UNLIKELY( !cr_avail ) ) {
      if( FD_UNLIKELY( !in_backp ) ) {
        FD_VOLATILE( cnc_diag[ FD_APP_CNC_DIAG_IN_BACKP  ] ) = 1UL;
        FD_VOLATILE( cnc_diag[ FD_APP_CNC_DIAG_BACKP_CNT ] ) = FD_VOLATILE_CONST( cnc_diag[ FD_APP_CNC_DIAG_BACKP_CNT ] )+1UL;
        in_backp = 1;
      }
      FD_SPIN_PAUSE();
      now = fd_tickcount();
      continue;
    }

#   if SYNTH_LOAD
    /* Check if we are waiting for the next burst to start */

    if( FD_LIKELY( ctl_som ) ) {
      if( FD_UNLIKELY( now<burst_next ) ) { /* Optimize for burst starting */
        FD_SPIN_PAUSE();
        now = fd_tickcount();
        continue;
      }
      /* We just "started receiving" the first bytes of the next burst
         from the redudant "NIC".  Record the timestamp. */
      burst_ts = fd_frag_meta_ts_comp( burst_next );
    }
    ulong msg_sz = fd_ulong_min( burst_rem, msg_max );
    burst_rem -= msg_sz;
    int ctl_eom = !burst_rem;
    int ctl_err = 0;

    int   is_dup = fd_rng_uint( rng ) < dup_thresh;
    uint  age    = is_dup ? (uint)(int)(1.0f + dup_avg_age*fd_rng_float_exp( rng )) : 0U;
    dup_seq += (uint)!is_dup;
    ulong meta_sig = fd_ulong_hash( (((ulong)tx_idx)<<32) | ((ulong)(dup_seq-age)) ); /* See note below */

    ulong   ctl    = fd_frag_meta_ctl( tx_idx, ctl_som, ctl_eom, ctl_err );
    ulong   tsorig = burst_ts;

    for( ulong ha_idx=0UL; ha_idx<ha_cnt; ha_idx++ ) {
    //if( ... probability of loss on this ha ... ) continue; /* FIXME: ADD HA LOSS MODEL */

      /* We are in the process of "receiving" a burst fragment from the
         one of the redundant "NIC"s.  Compute the details of the
         synthetic fragment and fill the data region with a suitable
         test pattern as fast as we can. */

      /* We assume the layer feeding us has already aligned the udp
         payload on the chunk boundary (such that udp_payload-8 is UDP
         header, udp_payload-28 is IP4 header, udp_payload-32 is VLAN
         tag, udp_payload-46 is ethernet header, udp_payload-54 is
         preamble, udp_payload+msg_sz is crc and udp_payload+msg_sz+4 is
         IFG and udp_payload_msg_sz+12 is last logical wire byte).  We
         don't bother to fill these in from synthetic data as we ignore
         them here (the previous layers should have already validated
         them).  This implicity assumes that runt and jumbo frames have
         been discarded upstream. */

      /*ulong chunk  = ... already at location where next packet will be written ...; */
      /*ulong tspub  = ... set "after" finished receiving from the "NIC" ...; */

      uchar *       udp_payload = (uchar *)fd_chunk_to_laddr( wksp, chunk );
      uchar *       d           = udp_payload;
      uchar const * s           = ref_msg[ msg_sz ];
      for( ulong off=0UL; off<32UL+64UL+msg_sz; off+=128UL ) {
        __m256i avx0 = _mm256_load_si256( (__m256i const *)(s     ) );
        __m256i avx1 = _mm256_load_si256( (__m256i const *)(s+32UL) );
        __m256i avx2 = _mm256_load_si256( (__m256i const *)(s+64UL) );
        __m256i avx3 = _mm256_load_si256( (__m256i const *)(s+96UL) );
        _mm256_store_si256( (__m256i *)(d     ), avx0 );
        _mm256_store_si256( (__m256i *)(d+32UL), avx1 );
        _mm256_store_si256( (__m256i *)(d+64UL), avx2 );
        _mm256_store_si256( (__m256i *)(d+96UL), avx3 );
        s += 128UL;
        d += 128UL;
      }

      /* We just "finished receiving" the next fragment of the burst
         from the "NIC".  udp_payload points to:
            public_key(32) | sig(64) | msg(msg_sz)
         Lightweight parse the packet. */

      ulong const * public_key = (ulong const *) udp_payload;
      ulong const * sig        = (ulong const *)(udp_payload + 32UL);
      uchar const * msg        = (uchar const *)(udp_payload + 96UL);

      /* Sig is already effectively a cryptographically secure hash of
         public_key/private_key and message and sz.  So use this to do a
         quick dedup of ha traffic (FIXME: POTENTIAL DOS ATTACK IF
         SOMEBODY COULD INTERCEPT TRAFFIC AND SUBMIT PACKETS WITH SAME
         PUBLIC KEY, SIG AND GARBAGE MESSAGE AHEAD OF THE TRAFFIC ...
         SEEMS UNLKELY AS THEY WOULD EITHER BE BEHIND THE INBOUND OR BE
         A MITM THAT COULD JUST DISCARD INBOUND TRAFFIC).

         When running synthetic load though, we only have a very limited
         set of messages and this dedup will be overly aggressive (as it
         will spuriously matching earlier synthetic packets since they
         are not resigned continuously)  So we just mock this up for the
         time being. */

      int ha_dup;
      FD_TCACHE_INSERT( ha_dup, tcache_oldest, _tcache_ring, tcache_depth, _tcache_map, tcache_map_cnt, ha_tag );
      if( FD_UNLIKELY( ha_dup ) ) { /* optimize for the non dup case */
        accum_ha_filt_cnt++;
        accum_ha_filt_sz += msg_framing + msg_sz;
        now = fd_tickcount();
        continue;
      }

      /* We appear to have a message to verify.  So verify it.

         When running synthetic load, the synthetic data will not fail
         at this point so we fake up some configurable rate of errors to
         stress out the monitoring.  (We could also slightly more
         expensively get the same effect by corrupting the udp_payload
         region before the verify.) */

      int err = fd_ed25519_verify( msg, msg_sz, sig, public_key, sha );

      FD_TEST( !err ); /* These should always pass here */
      if( FD_UNLIKELY( fd_rng_uint( rng )<=errsv_thresh ) ) { /* And model random failures at some low rate */
        accum_sv_filt_cnt++;
        accum_sv_filt_sz += msg_framing + msg_sz;
        now = fd_tickcount();
        continue;
      }

      /* Packet looks superficially good.  Forward it.  If somebody is
         opening multiple connections (which would potentially flow
         steered to different verify tiles) and spammed these
         connections with the same transaction, ha dedup here is likely
         to miss that.   But the dedup tile that muxes all the inputs
         will take care of that.  (The use of QUIC and the like should
         also strongly reduce the economic incentives for this
         behavior.)

         When running synthetic load, we have the same problem we had
         above.  So we use a signature that will match with the desired
         probability. */

      /* Note that sig is now guaranteed to be not FD_TCACHE_TAG_NULL
         and we use the least significant 64-bits of the SHA-512 hash
         for dedup purposes. */

      now = fd_tickcount();
      ulong tspub = fd_frag_meta_ts_comp( now );
      fd_mcache_publish( mcache, depth, seq, meta_sig, chunk, msg_framing+msg_sz, ctl, tsorig, tspub );

      chunk = fd_dcache_compact_next( chunk, msg_framing + msg_sz, chunk0, wmark );
      seq   = fd_seq_inc( seq, 1UL );
      cr_avail--;
    }
    ha_tag++;

    /* Wind up for the next iteration */

    if( FD_UNLIKELY( !ctl_eom ) ) ctl_som = 0;
    else {
      ctl_som = 1;
      do {
        burst_next +=        (long)(0.5f + burst_tau*fd_rng_float_exp( rng ));
        burst_rem   = (ulong)(long)(0.5f + burst_avg*fd_rng_float_exp( rng ));
      } while( FD_UNLIKELY( !burst_rem ) );
    }
#   else
    /* Placeholder for sig verify */
    (void)_tcache_map;
    (void)_tcache_ring;
    (void)tcache_depth;
    (void)tcache_map_cnt;
    (void)chunk;
    (void)wmark;
    now = fd_tickcount();
#   endif
  }

  /* Clean up */

  fd_cnc_signal( cnc, FD_CNC_SIGNAL_BOOT );
  FD_LOG_INFO(( "verify.%s fini", verify_name ));
  fd_sha512_delete ( fd_sha512_leave( sha    ) );
  fd_tcache_delete ( fd_tcache_leave( tcache ) );
  fd_rng_delete    ( fd_rng_leave   ( rng    ) );
  fd_fctl_delete   ( fd_fctl_leave  ( fctl   ) );
  fd_wksp_pod_unmap( fd_fseq_leave  ( fseq   ) );
  fd_wksp_pod_unmap( fd_dcache_leave( dcache ) );
  fd_wksp_pod_unmap( fd_mcache_leave( mcache ) );
  fd_wksp_pod_unmap( fd_cnc_leave   ( cnc    ) );
  fd_wksp_pod_detach( pod );
  return 0;
}
