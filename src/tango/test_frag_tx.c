#include "fd_tango.h"

#if FD_HAS_HOSTED && FD_HAS_AVX

#include <math.h> /* For expm1f */

FD_STATIC_ASSERT( FD_CHUNK_SZ==64UL, unit_test );

/* This test uses the mcache application region for holding the rx flow
   controls.  We'll use a cache line pair for each reliable rx_seq (as
   these are all written frequently by different rx's).  We store the tx
   backpressure counters in the tx's cnc app region and the rx overrun
   counters in the rx's cnc app region so all tx's and rx's (regardless
   of being reliable or not) have a remotely monitorable backpressure
   and overrun counters. */

#define TX_MAX (128UL) /* Less than FD_FRAG_META_ORIG_MAX */
#define RX_MAX (128UL)

static uchar fctl_mem[ FD_FCTL_FOOTPRINT( RX_MAX ) ] __attribute__((aligned(FD_FCTL_ALIGN)));

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

# define TEST(c) do if( FD_UNLIKELY( !(c) ) ) { FD_LOG_WARNING(( "FAIL: " #c )); return 1; } while(0)

  char const * _cnc    = fd_env_strip_cmdline_cstr ( &argc, &argv, "--cnc",    NULL,                 NULL ); /* (req) cnc */
  char const * _mcache = fd_env_strip_cmdline_cstr ( &argc, &argv, "--mcache", NULL,                 NULL ); /* (req) mcache */
  char const * _dcache = fd_env_strip_cmdline_cstr ( &argc, &argv, "--dcache", NULL,                 NULL ); /* (req) dcache */
  char const * _init   = fd_env_strip_cmdline_cstr ( &argc, &argv, "--init",   NULL,                 NULL ); /* (opt) init seq */
  ulong        tx_idx  = fd_env_strip_cmdline_ulong( &argc, &argv, "--tx-idx", NULL,                  0UL ); /* (opt) origin */
  ulong        rx_cnt  = fd_env_strip_cmdline_ulong( &argc, &argv, "--rx-cnt", NULL,                  0UL ); /* (opt) num rel rx for tx */
  uint         seed    = fd_env_strip_cmdline_uint ( &argc, &argv, "--seed",   NULL, (uint)fd_tickcount() ); /* (opt) rng seed */

  if( FD_UNLIKELY( !_cnc          ) ) FD_LOG_ERR(( "--cnc not specified" ));
  if( FD_UNLIKELY( !_mcache       ) ) FD_LOG_ERR(( "--mcache not specified" ));
  if( FD_UNLIKELY( !_dcache       ) ) FD_LOG_ERR(( "--dcache not specified" ));
  if( FD_UNLIKELY( tx_idx>=TX_MAX ) ) FD_LOG_ERR(( "--tx-idx too large for this unit-test" ));
  if( FD_UNLIKELY( rx_cnt> RX_MAX ) ) FD_LOG_ERR(( "--rx-cnt too large for this unit-test" ));

  /* burst_avg is the average number of synthetic payload bytes in a
     packet burst (0 min, exponentially distributed).  A burst's data
     bytes are sent as zero or more packets containing pkt_payload_max
     bytes followed by a one packet containing [1,pkt_payload_max]
     bytes.  All the packets in a burst are sent in rapid succession.
     Packets have a constant number of bytes overhead for various
     headers and footers (pkt_framing).

     pkt_bw is the average rate packet bandwidth (i.e. burst data bytes
     plus packet framing bytes) in bit/second (with 8 bit bytes).

     E.g. pkt_bw <= 1e9, pkt_framing = 84, pkt_payload_max = 1472 would
     accurately and precisely describe a 1G Ethernet link that runs UDP
     / IP4 / VLAN tagged non-Jumbo Ethernet packets at up to line rate.
     pkt_bw <= 1e9 comes from 1G Ethernet, pkt_framing = 84 from 8 byte
     preamble + 14 byte Ethernet header + 4 byte VLAN tag + 20 byte IP4
     header (without options) + 8 byte UDP header + 4 byte
     frame-check-sequence + 12 byte interframe gap, 1472 comes from a
     1500 byte MTU (maximum Ethernet payload size) - 20 byte IP4 header
     (without options) - 8 byte UDP header. */

  float burst_avg       = fd_env_strip_cmdline_float( &argc, &argv, "--burst-avg",       NULL, 1472.f );
  ulong pkt_payload_max = fd_env_strip_cmdline_ulong( &argc, &argv, "--pkt-payload-max", NULL, 1472UL );
  ulong pkt_framing     = fd_env_strip_cmdline_ulong( &argc, &argv, "--pkt-framing",     NULL,   84UL );
  float pkt_bw          = fd_env_strip_cmdline_float( &argc, &argv, "--pkt-bw",          NULL,  50e9f );

  FD_LOG_NOTICE(( "Configuring synthetic load (--burst-avg %g B --pkt-framing %lu B --pkt-payload-max %lu B --pkt-bw %g b/s)",
                  (double)burst_avg, pkt_framing, pkt_payload_max, (double)pkt_bw ));

  /* 2.1e17 ~ LONG_MAX / 43.668 is such that an exponentially
     distributed random from the util/rng API with an average in
     (0,2.1e17) will practically never overflow when rounded to a long. */

  if( FD_UNLIKELY( !((0.f<burst_avg) & (burst_avg<2.1e17f)) ) ) FD_LOG_ERR(( "--burst-avg out of range" ));

  if( FD_UNLIKELY( !pkt_payload_max ) ) FD_LOG_ERR(( "Zero --pkt-payload-max" ));

  ulong pkt_max = pkt_framing + pkt_payload_max;
  if( FD_UNLIKELY( (pkt_max<pkt_framing) | (pkt_max>(ulong)USHORT_MAX) ) )
    FD_LOG_ERR(( "Too large --pkt-framing + --pkt-payload-max" ));

  if( FD_UNLIKELY( !(0.f<pkt_bw) ) ) FD_LOG_ERR(( "--pkt-bw out of range" ));

  /* Compute the average rate of the burst payload bytes.  Note that the
     average number of packet framing bytes in a burst is very well
     approximated (exact in the limit of continuum arithmetic) by:

       integral_{0,infinity} dburst_sz pkt_framing ceil( burst_sz / pkt_payload_max ) burst_pdf( burst_sz )

    where burst_pdf( burst_sz ) in this range is:

       (1/burst_avg) exp( -burst_sz / burst_avg )

    This can be analytically solved to produce:

       pkt_framing / ( 1 - exp( -pkt_payload_max / burst_avg ) )

    Note that in the limit pkt_payload_max >> burst_avg, the denominator
    is asymptotically 1 such that the amount of framing per burst is
    just pkt_framing in this limit (as it should be as virtually all
    bursts just fit into a single packet).

    In the limit pkt_payload_max << burst_avg, the denominator is
    asympotically such that the number average number of framing bytes
    per burst is pkt_framing (burst_avg / pkt_payload_max).  This is also
    as expected as in this limit the bursts are so large they are mostly
    received via the large number of leading MTU packets.

    Given the average number of payload bytes per burst is burst_avg,
    burst packetization yields the total number of packet bytes per
    burst (i.e. including framing overheads) to be relatively larger
    than the number of payload bytes per burst (i.e. not including
    framing overheads) by:

       1 - (pkt_framing/burst_avg) / expm1(-pkt_payload_max/burst_avg)

    where we've converted the denominator to be more numerically
    accurate, especially in the limit burst_avg >> pkt_payload_max. */

  float burst_bw = pkt_bw
                 / (1.f - ((((float)pkt_framing)/((float)burst_avg)) / expm1f( -((float)pkt_payload_max)/((float)burst_avg) )));

  /* See note above about 2.1e17 */

  float burst_tau = burst_avg*(8.f*1e9f/burst_bw); /* Avg time in ns between bursts (8 bit/byte, 1e9 ns/s), bw in bit/s */
  if( FD_UNLIKELY( !(burst_tau<2.1e17f) ) ) FD_LOG_ERR(( "--pkt-bw out of range" ));

  FD_LOG_NOTICE(( "Creating rng --seed %u", seed ));

  fd_rng_t _rng[1]; fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, seed, 0UL ) );

  FD_LOG_NOTICE(( "Joining to --cnc %s", _cnc ));

  fd_cnc_t * cnc = fd_cnc_join( fd_wksp_map( _cnc ) );
  if( FD_UNLIKELY( !cnc ) ) FD_LOG_ERR(( "join failed" ));

  FD_LOG_NOTICE(( "Joining to monitoring" ));

  ulong diag_footprint = rx_cnt*sizeof(ulong);
  if( FD_UNLIKELY( fd_cnc_app_sz( cnc ) < diag_footprint ) ) FD_LOG_ERR(( "increase cnc app sz to at least %lu", diag_footprint ));
  ulong * diag_backp = (ulong *)fd_cnc_app_laddr( cnc );

  FD_LOG_NOTICE(( "Joining to --mcache %s", _mcache ));

  fd_frag_meta_t * mcache = fd_mcache_join( fd_wksp_map( _mcache ) );
  if( FD_UNLIKELY( !mcache ) ) FD_LOG_ERR(( "join failed" ));

  ulong   depth   = fd_mcache_depth    ( mcache );
  ulong * _tx_seq = fd_mcache_seq_laddr( mcache );
  uchar * app     = fd_mcache_app_laddr( mcache );
  ulong   app_sz  = fd_mcache_app_sz   ( mcache );

  ulong tx_seq = _init ? fd_cstr_to_ulong( _init ) : fd_mcache_seq_query( _tx_seq );

  FD_LOG_NOTICE(( "Joining to --dcache %s", _dcache ));

  uchar * dcache = fd_dcache_join( fd_wksp_map( _dcache ) );
  if( FD_UNLIKELY( !dcache ) ) FD_LOG_ERR(( "join failed" ));

  void * base = fd_wksp_containing( dcache );
  if( FD_UNLIKELY( !base ) ) FD_LOG_ERR(( "fd_wksp_containing failed" ));

  if( FD_UNLIKELY( !fd_dcache_compact_is_safe( base, dcache, pkt_max, depth ) ) )
    FD_LOG_ERR(( "--dcache not compatible with wksp base, --pkt-framing, --pkt-payload-max and --mcache depth" ));

  ulong chunk0 = fd_dcache_compact_chunk0( base, dcache );
  ulong wmark  = fd_dcache_compact_wmark ( base, dcache, pkt_max );
  ulong chunk  = chunk0; /* FIXME: command line / auto recover this from dcache app region for clean dcache recovery too */

  FD_LOG_NOTICE(( "Configuring fctl for --rx-cnt %lu reliable consumers", rx_cnt ));

  if( FD_UNLIKELY( rx_cnt*128UL>app_sz ) ) FD_LOG_ERR(( "increase mcache app_sz to at least %lu", rx_cnt*128UL ));

  fd_fctl_t * fctl = fd_fctl_join( fd_fctl_new( fctl_mem, rx_cnt ) );
  if( FD_UNLIKELY( !fctl ) ) FD_LOG_ERR(( "join failed" ));

  uchar * fctl_top = app;
  for( ulong rx_idx=0UL; rx_idx<rx_cnt; rx_idx++ ) {
    ulong * rx_lseq = (ulong *)fctl_top; fctl_top += 128UL;
    if( FD_UNLIKELY( !fd_fctl_cfg_rx_add( fctl, depth, rx_lseq, &diag_backp[ rx_idx ] ) ) )
      FD_LOG_ERR(( "fd_fctl_cfg_rx_add failed" ));
    diag_backp[ rx_idx ] = 0UL;
  }

  /* cr_burst is 1 because we only send at most 1 fragment metadata
     between checking cr_avail.  We use defaults cr_max, cr_resume and
     cr_refill. */
  if( FD_UNLIKELY( !fd_fctl_cfg_done( fctl, 1UL, 0UL, 0UL, 0UL ) ) ) FD_LOG_ERR(( "fd_fctl_cfg_done failed" ));
  FD_LOG_NOTICE(( "cr_burst %lu cr_max %lu cr_resume %lu cr_refill %lu",
                  fd_fctl_cr_burst( fctl ), fd_fctl_cr_max( fctl ), fd_fctl_cr_resume( fctl ), fd_fctl_cr_refill( fctl ) ));

  ulong async_min = 1UL<<7;
  ulong async_rem = 1UL; /* Do housekeeping on the first iteration */
  ulong cr_avail  = 0UL;

  FD_LOG_NOTICE(( "Running --init %lu (%s)", tx_seq, _init ? "manual" : "auto" ));

  long  then = fd_log_wallclock();
  ulong iter = 0UL;

  int   ctl_som    = 1;
  long  burst_next = then;
  ulong burst_rem;
  do {
    burst_next += (long)(0.5f + burst_tau*fd_rng_float_exp( rng ));
    burst_rem   = (ulong)(long)(0.5f + burst_avg*fd_rng_float_exp( rng ));
  } while( FD_UNLIKELY( !burst_rem ) );
  ulong tsorig = 0UL; /* Irrelevant value at init */

  fd_cnc_signal( cnc, FD_CNC_SIGNAL_RUN );
  for(;;) {

    /* Do housekeeping in the background */

    async_rem--;
    if( FD_UNLIKELY( !async_rem ) ) {

      /* Send synchronization info */

      fd_mcache_seq_update( _tx_seq, tx_seq );

      /* Send monitoring info */

      long now = fd_log_wallclock();
      fd_cnc_heartbeat( cnc, now );

      long dt = now - then;
      if( FD_UNLIKELY( dt > (long)1e9 ) ) {
        float mfps = (1e3f*(float)iter) / (float)dt;
        FD_LOG_NOTICE(( "%7.3f Mfrag/s tx", (double)mfps ));
        for( ulong rx_idx=0UL; rx_idx<rx_cnt; rx_idx++ ) {
          ulong * rx_backp = fd_fctl_rx_backp_laddr( fctl, rx_idx );
          FD_LOG_NOTICE(( "backp[%lu] %lu", rx_idx, *rx_backp ));
          *rx_backp = 0UL;
        }
        then = now;
        iter = 0UL;
      }

      /* Receive command-and-control signals */

      ulong s = fd_cnc_signal_query( cnc );
      if( FD_UNLIKELY( s!=FD_CNC_SIGNAL_RUN ) ) {
        if( FD_LIKELY( s==FD_CNC_SIGNAL_HALT ) ) break;
        char buf[ FD_CNC_SIGNAL_CSTR_BUF_MAX ];
        FD_LOG_WARNING(( "Unexpected signal %s (%lu) received; trying to resume", fd_cnc_signal_cstr( s, buf ), s ));
        fd_cnc_signal( cnc, FD_CNC_SIGNAL_RUN );
      }

      /* Receive flow control credits */

      cr_avail = fd_fctl_tx_cr_update( fctl, cr_avail, tx_seq );

      async_rem = fd_async_reload( rng, async_min );
    }

    /* Check if we are backpressured */

    if( FD_UNLIKELY( !cr_avail ) ) {
      FD_SPIN_PAUSE();
      continue;
    }

    /* Check if we are waiting for the next burst to start */

    if( FD_LIKELY( ctl_som ) ) {
      if( FD_UNLIKELY( fd_log_wallclock()<burst_next ) ) { /* Opt for start */
        FD_SPIN_PAUSE(); /* Debatable given fd_log_wallclock overhead */
        continue;
      }
      /* We just "started receiving" the first bytes of the next burst
         from the "NIC".  Record the timestamp. */
      tsorig = fd_frag_meta_ts_comp( fd_tickcount() );
    }

    /* We are in the process of "receiving" a fragment from the NIC.
       Compute the details of the synthetic fragment and fill the data
       region with a suitable test pattern as fast as we can.  Note that
       the dcache region pointed by chunk through the double cache line
       region marked by sz is currently not marked as visible and has
       room for up to "MTU" worth of double chunks free.  So we can
       write it at our hearts content.  Since we align frag starts to
       double chunk boundaries, we are safe to tail clobber (which
       further speeds up test pattern generation as this amortizes loop
       overhead, flattens tail branches and only write to the dcache in
       complete double cache lines.  We don't care if this is written
       atomic or not. */
    /* FIXME: THROW IN RANDOM CTL_ERR TO MODEL DETECTED PKT CORRUPTION
       AND OPTION TO DO RANDOM SILENT ERRORS IN PAYLOAD  */

    ulong frag_sz = fd_ulong_min( burst_rem, pkt_payload_max );
    burst_rem -= frag_sz;
    int ctl_eom = !burst_rem;
    int ctl_err = 0;

    ulong sig    = tx_seq; /* Test pattern */
  /*ulong chunk  = ... already at location where next packet will be written ...; */
    ulong sz     = pkt_framing + frag_sz;
    ulong ctl    = fd_frag_meta_ctl( tx_idx, ctl_som, ctl_eom, ctl_err );
  /*ulong tsorig = ... set at burst start ...; */
  /*ulong tspub  = ... set "after" finished receiving from the "NIC" ...; */

    uchar * p   = (uchar *)fd_chunk_to_laddr( base, chunk );
    __m256i avx = _mm256_set1_epi64x( (long)tx_seq );
    for( ulong off=0UL; off<sz; off+=128UL ) {
      _mm256_store_si256( (__m256i *)(p     ), avx );
      _mm256_store_si256( (__m256i *)(p+32UL), avx );
      _mm256_store_si256( (__m256i *)(p+64UL), avx );
      _mm256_store_si256( (__m256i *)(p+96UL), avx );
      p += 128UL;
    }

    /* We just "finished receiving" the next fragment of the burst from
       the "NIC".  Publish to consumers as frag tx_seq.  This implicitly
       unpublishes frag tx_seq-depth (cyclic) at the same time. */

    ulong tspub = fd_frag_meta_ts_comp( fd_tickcount() );

#   define PUBLISH_STYLE 0

#   if PUBLISH_STYLE==0 /* Incompatible with WAIT_STYLE==2 */

    fd_mcache_publish( mcache, depth, tx_seq, sig, chunk, sz, ctl, tsorig, tspub );

#   elif PUBLISH_STYLE==1 /* Incompatible with WAIT_STYLE==2 */

    fd_mcache_publish_sse( mcache, depth, tx_seq, sig, chunk, sz, ctl, tsorig, tspub );

#   else /* Compatible with all wait styles, requires target with atomic
            aligned AVX load/store support */

    fd_mcache_publish_avx( mcache, depth, tx_seq, sig, chunk, sz, ctl, tsorig, tspub );

#   endif

    /* Wind up for the next iteration */

    chunk  = fd_dcache_compact_next( chunk, sz, chunk0, wmark );
    tx_seq = fd_seq_inc( tx_seq, 1UL );
    cr_avail--;

    if( FD_UNLIKELY( !ctl_eom ) ) ctl_som = 0;
    else {
      ctl_som = 1;
      do {
        burst_next += (long)(0.5f + burst_tau*fd_rng_float_exp( rng ));
        burst_rem   = (ulong)(long)(0.5f + burst_avg*fd_rng_float_exp( rng ));
      } while( FD_UNLIKELY( !burst_rem ) );
    }

    iter++;
  }

  FD_LOG_NOTICE(( "Cleaning up" ));

  fd_fctl_delete( fd_fctl_leave( fctl ) );
  fd_wksp_unmap( fd_dcache_leave( dcache ) );
  fd_wksp_unmap( fd_mcache_leave( mcache ) );
  fd_cnc_signal( cnc, FD_CNC_SIGNAL_BOOT );
  fd_wksp_unmap( fd_cnc_leave( cnc ) );
  fd_rng_delete( fd_rng_leave( rng ) );

# undef TEST

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}

#else

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );
  FD_LOG_WARNING(( "skip: unit test requires FD_HAS_HOSTED and FD_HAS_AVX capabilities" ));
  fd_halt();
  return 0;
}

#endif
