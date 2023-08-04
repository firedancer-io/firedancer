#include "fd_frank.h"
#include "../../ballet/txn/fd_txn.h"

#include <stdio.h>

#include <sys/stat.h>
#include <linux/unistd.h>

static void
run( fd_frank_args_t * args ) {
  /*
   * Join the IPC objects needed this tile instance
   */

  /* In IPC objects */
  FD_LOG_INFO(( "joining mcache%lu", args->tile_idx ));
  char path[ 32 ];
  snprintf( path, sizeof(path), "mcache%lu", args->tile_idx );
  fd_frag_meta_t * vin_mcache = fd_mcache_join( fd_wksp_pod_map( args->in_pod, path ) );
  if( FD_UNLIKELY( !vin_mcache ) ) FD_LOG_ERR(( "fd_mcache_join failed" ));
  ulong   vin_mcache_depth = fd_mcache_depth    ( vin_mcache      );
  ulong * vin_mcache_sync  = fd_mcache_seq_laddr( vin_mcache      );
  ulong   vin_mcache_seq   = fd_mcache_seq_query( vin_mcache_sync );
  fd_frag_meta_t const * vin_mline = vin_mcache + fd_mcache_line_idx( vin_mcache_seq, vin_mcache_depth );

  FD_LOG_INFO(( "joining dcache%lu", args->tile_idx ));
  snprintf( path, sizeof(path), "dcache%lu", args->tile_idx );
  uchar * vin_dcache = fd_dcache_join( fd_wksp_pod_map( args->in_pod, path ) );
  if( FD_UNLIKELY( !vin_dcache ) ) FD_LOG_ERR(( "fd_dcache_join failed" ));
  fd_wksp_t * vin_wksp = fd_wksp_containing( vin_dcache ); /* chunks are referenced relative to the containing workspace */
  if( FD_UNLIKELY( !vin_wksp ) ) FD_LOG_ERR(( "fd_wksp_containing failed" ));

  FD_LOG_INFO(( "joining fseq%lu", args->tile_idx ));
  snprintf( path, sizeof(path), "fseq%lu", args->tile_idx );
  ulong * vin_fseq = fd_fseq_join( fd_wksp_pod_map( args->in_pod, path ) );
  if( FD_UNLIKELY( !vin_fseq ) ) FD_LOG_ERR(( "fd_fseq_join failed" ));
  ulong * vin_fseq_diag = (ulong *)fd_fseq_app_laddr( vin_fseq );
  if( FD_UNLIKELY( !vin_fseq_diag ) ) FD_LOG_ERR(( "fd_fseq_app_laddr failed" ));
  FD_COMPILER_MFENCE();
  FD_VOLATILE( vin_fseq_diag[ FD_FSEQ_DIAG_PUB_CNT   ] ) = 0UL;
  FD_VOLATILE( vin_fseq_diag[ FD_FSEQ_DIAG_PUB_SZ    ] ) = 0UL;
  FD_VOLATILE( vin_fseq_diag[ FD_FSEQ_DIAG_FILT_CNT  ] ) = 0UL;
  FD_VOLATILE( vin_fseq_diag[ FD_FSEQ_DIAG_FILT_SZ   ] ) = 0UL;
  FD_VOLATILE( vin_fseq_diag[ FD_FSEQ_DIAG_OVRNP_CNT ] ) = 0UL;
  FD_VOLATILE( vin_fseq_diag[ FD_FSEQ_DIAG_OVRNR_CNT ] ) = 0UL;
  FD_VOLATILE( vin_fseq_diag[ FD_FSEQ_DIAG_SLOW_CNT  ] ) = 0UL; /* Managed by the fctl */
  FD_COMPILER_MFENCE();
  ulong vin_accum_pub_cnt   = 0UL;
  ulong vin_accum_pub_sz    = 0UL;
  ulong vin_accum_ovrnp_cnt = 0UL;
  ulong vin_accum_ovrnr_cnt = 0UL;

  /* Setup local objects used by this tile */

  FD_LOG_INFO(( "configuring flow control" ));
  ulong vin_cr_max    = fd_pod_query_ulong( args->tile_pod, "cr_max",    0UL );
  ulong vin_cr_resume = fd_pod_query_ulong( args->tile_pod, "cr_resume", 0UL );
  ulong vin_cr_refill = fd_pod_query_ulong( args->tile_pod, "cr_refill", 0UL );
  long  vin_lazy      = fd_pod_query_long ( args->tile_pod, "lazy",      0L  );
  FD_LOG_INFO(( "verifyin.%lu.cr_max    %lu", args->tile_idx, vin_cr_max    ));
  FD_LOG_INFO(( "verifyin.%lu.cr_resume %lu", args->tile_idx, vin_cr_resume ));
  FD_LOG_INFO(( "verifyin.%lu.cr_refill %lu", args->tile_idx, vin_cr_refill ));
  FD_LOG_INFO(( "verifyin.%lu.lazy      %li", args->tile_idx, vin_lazy      ));

  fd_fctl_t * vin_fctl = fd_fctl_cfg_done( fd_fctl_cfg_rx_add( fd_fctl_join( fd_fctl_new( fd_alloca( FD_FCTL_ALIGN,
                                                                                                     fd_fctl_footprint( 1UL ) ),
                                                                                          1UL ) ),
                                                               vin_mcache_depth, vin_fseq, &vin_fseq_diag[ FD_FSEQ_DIAG_SLOW_CNT ] ),
                                           1UL /*cr_burst*/, vin_cr_max, vin_cr_resume, vin_cr_refill );
  if( FD_UNLIKELY( !vin_fctl ) ) FD_LOG_ERR(( "Unable to create flow control" ));
  FD_LOG_INFO(( "using cr_burst %lu, cr_max %lu, cr_resume %lu, cr_refill %lu for verifyin %lu",
      fd_fctl_cr_burst( vin_fctl ), fd_fctl_cr_max( vin_fctl ), fd_fctl_cr_resume( vin_fctl ), fd_fctl_cr_refill( vin_fctl ), args->tile_idx ));

  if( vin_lazy<=0L ) vin_lazy = fd_tempo_lazy_default( vin_mcache_depth );
  FD_LOG_INFO(( "using lazy %li ns", vin_lazy ));
  ulong vin_async_min = fd_tempo_async_min( vin_lazy, 1UL /*event_cnt*/, (float)fd_tempo_tick_per_ns( NULL ) );
  if( FD_UNLIKELY( !vin_async_min ) ) FD_LOG_ERR(( "bad vin_lazy" ));

  /* Out IPC objects */
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
  snprintf( path, sizeof(path), "mcache%lu", args->tile_idx );
  fd_frag_meta_t * mcache = fd_mcache_join( fd_wksp_pod_map( args->out_pod, path ) );
  if( FD_UNLIKELY( !mcache ) ) FD_LOG_ERR(( "fd_mcache_join failed" ));
  ulong   depth = fd_mcache_depth( mcache );
  ulong * sync  = fd_mcache_seq_laddr( mcache );
  ulong   seq   = fd_mcache_seq_query( sync );

  FD_LOG_INFO(( "joining dcache%lu", args->tile_idx ));
  snprintf( path, sizeof(path), "dcache%lu", args->tile_idx );
  uchar * dcache = fd_dcache_join( fd_wksp_pod_map( args->out_pod, path ) );
  if( FD_UNLIKELY( !dcache ) ) FD_LOG_ERR(( "fd_dcache_join failed" ));
  fd_wksp_t * wksp = fd_wksp_containing( dcache ); /* chunks are referenced relative to the containing workspace */
  if( FD_UNLIKELY( !wksp ) ) FD_LOG_ERR(( "fd_wksp_containing failed" ));
  ulong   chunk0 = fd_dcache_compact_chunk0( wksp, dcache );
  ulong   wmark  = fd_dcache_compact_wmark ( wksp, dcache, 1542UL ); /* FIXME: MTU? SAFETY CHECK THE FOOTPRINT? */
  ulong   chunk  = chunk0;

  FD_LOG_INFO(( "joining fseq%lu", args->tile_idx ));
  snprintf( path, sizeof(path), "fseq%lu", args->tile_idx );
  ulong * fseq = fd_fseq_join( fd_wksp_pod_map( args->out_pod, path ) );
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
  ulong async_min = fd_tempo_async_min( lazy, 1UL /*event_cnt*/, (float)args->tick_per_ns );
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

  ulong sigvfy_pass_cnt =0UL;
  ulong sigvfy_fail_cnt =0UL;
  (void)sigvfy_pass_cnt;
  (void)sigvfy_fail_cnt;
  for(;;) {

    /* Do housekeeping at a low rate in the background */

    if( FD_UNLIKELY( (now-then)>=0L ) ) {
      /*
        begin verifyin related
      */

      /* Send flow control credits */
      fd_fctl_rx_cr_return( vin_fseq, vin_mcache_seq );

      /* Send synchronization info */

      FD_COMPILER_MFENCE();
      FD_VOLATILE( vin_fseq_diag[ FD_FSEQ_DIAG_PUB_CNT   ] ) += vin_accum_pub_cnt;
      FD_VOLATILE( vin_fseq_diag[ FD_FSEQ_DIAG_PUB_SZ    ] ) += vin_accum_pub_sz;
      FD_VOLATILE( vin_fseq_diag[ FD_FSEQ_DIAG_OVRNP_CNT ] ) += vin_accum_ovrnp_cnt;
      FD_VOLATILE( vin_fseq_diag[ FD_FSEQ_DIAG_OVRNR_CNT ] ) += vin_accum_ovrnr_cnt;
      FD_COMPILER_MFENCE();
      vin_accum_pub_cnt   = 0UL;
      vin_accum_pub_sz    = 0UL;
      vin_accum_ovrnp_cnt = 0UL;
      vin_accum_ovrnr_cnt = 0UL;

      /*
        end verifyin related
      */

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

    /* See if there are any transactions waiting to be packed */
    __m128i vin_seq_sig = fd_frag_meta_seq_sig_query( vin_mline );
    ulong vin_seq_found = fd_frag_meta_sse0_seq( vin_seq_sig );
    long  vin_diff      = fd_seq_diff( vin_seq_found, vin_mcache_seq );
    if( FD_UNLIKELY( vin_diff ) ) { /* caught up or overrun, optimize for expected sequence number ready */
      if( FD_LIKELY( vin_diff < 0L ) ) {
        FD_SPIN_PAUSE();
        now = fd_tickcount();
        continue;
      }
      vin_accum_ovrnp_cnt++;
      vin_mcache_seq = vin_seq_found;
      /* can keep processing from the new seq */
    }

    ulong vin_sig_found = fd_frag_meta_sse0_sig( vin_seq_sig );
    if( FD_UNLIKELY( vin_sig_found ) ) { /* This is a dummy mcache entry to keep frags from getting overrun, do not process */
      vin_mcache_seq   = fd_seq_inc( vin_mcache_seq, 1UL );
      vin_mline = vin_mcache + fd_mcache_line_idx( vin_mcache_seq, vin_mcache_depth );
      continue;
    }

    now = fd_tickcount();

    /* At this point, we have started receiving frag seq with details in
       mline at time now.  Speculatively processs it here. */
    ulong vin_data_sz    = (ulong)vin_mline->sz;
    uchar *  vin_dcache_chunk_laddr = (uchar *)fd_chunk_to_laddr( vin_wksp, vin_mline->chunk );
    uchar *  udp_payload = (uchar *)fd_chunk_to_laddr( wksp, chunk );
    memcpy(udp_payload, vin_dcache_chunk_laddr, vin_data_sz);

    /* Check that we weren't overrun while processing */
    vin_seq_found = fd_frag_meta_seq_query( vin_mline );
    if( FD_UNLIKELY( fd_seq_ne( vin_seq_found, vin_mcache_seq ) ) ) {
      vin_accum_ovrnr_cnt++;
      FD_LOG_INFO(( "verifyin.%lu ovrnr encountered:   vin_mcache_seq=%lu   vin_seq_found=%lu   vin_accum_ovrnr_cnt=%lu", args->tile_idx, vin_mcache_seq, vin_seq_found, vin_accum_ovrnr_cnt ));
      vin_mcache_seq = vin_seq_found;
      now = fd_tickcount();
      continue;
    }

    vin_accum_pub_cnt++;
    vin_accum_pub_sz += vin_data_sz;

    /* Wind up for the next iteration for verifyin */
    vin_mcache_seq   = fd_seq_inc( vin_mcache_seq, 1UL );
    vin_mline = vin_mcache + fd_mcache_line_idx( vin_mcache_seq, vin_mcache_depth );

    ushort payload_sz = *(ushort*) (udp_payload + vin_data_sz - sizeof(ushort));
    fd_txn_t * txn = (fd_txn_t*) fd_ulong_align_up( (ulong)(udp_payload) + payload_sz, 2UL );

    ulong const * public_key = (ulong const *)(udp_payload + txn->acct_addr_off);
    ulong const * sig        = (ulong const *)(udp_payload + txn->signature_off);
    uchar const * msg        = (uchar const *)(udp_payload + txn->message_off);
    ulong msg_sz             = (ulong)payload_sz - txn->message_off;

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

    ulong ha_tag = *sig;
    int ha_dup;
    FD_TCACHE_INSERT( ha_dup, tcache_oldest, _tcache_ring, tcache_depth, _tcache_map, tcache_map_cnt, ha_tag );
    if( FD_UNLIKELY( ha_dup ) ) { /* optimize for the non dup case */
      accum_ha_filt_cnt++;
      accum_ha_filt_sz += payload_sz; //WW accum_ha_filt_sz += msg_framing + msg_sz;
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
    if (err) {
      sigvfy_fail_cnt ++;
      //FD_LOG_WARNING(( "fd_ed25519_verify failed for mcache[%lu], fail/pass: %lu/%lu",
      //  vin_seq_found, sigvfy_fail_cnt, sigvfy_pass_cnt ));
      now = fd_tickcount();
      continue;
    }
    else {
      sigvfy_pass_cnt ++;
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
    int   ctl_som  = 1;
    int   ctl_eom  = 1;
    ulong   ctl    = fd_frag_meta_ctl( 0, ctl_som, ctl_eom, 0 );
    ulong   tsorig = tspub;
    fd_mcache_publish( mcache, depth, seq, ha_tag, chunk, vin_data_sz, ctl, tsorig, tspub );

    chunk = fd_dcache_compact_next( chunk, vin_data_sz, chunk0, wmark );
    seq   = fd_seq_inc( seq, 1UL );
    cr_avail--;

    if( FD_UNLIKELY( !ctl_eom ) ) ctl_som = 0;
    else {
      ctl_som = 1;
    }
  }
}

static long allow_syscalls[] = {
  __NR_write,     /* logging */
  __NR_fsync,     /* logging, WARNING and above fsync immediately */
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
