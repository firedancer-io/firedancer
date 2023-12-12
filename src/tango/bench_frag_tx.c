#include "fd_tango.h"

#if FD_HAS_HOSTED && FD_HAS_AVX

/* FIXME: UPDATE TO TIME BASED HOUSEKEEPING */

#include <math.h> /* For expm1f */

FD_STATIC_ASSERT( FD_CHUNK_SZ==64UL, unit_test );

#define RX_MAX (128UL) /* Max _reliable_ (arb unreliable) */

static uchar  fctl_mem[ FD_FCTL_FOOTPRINT( RX_MAX ) ] __attribute__((aligned(FD_FCTL_ALIGN)));
static char * _fseq[ RX_MAX ];

#define FD_CNC_DIAG_IN_BACKP   (0UL)
#define FD_CNC_DIAG_BACKP_CNT  (1UL)

#define FD_FSEQ_DIAG_PUB_CNT   (0UL)
#define FD_FSEQ_DIAG_PUB_SZ    (1UL)
#define FD_FSEQ_DIAG_FILT_CNT  (2UL)
#define FD_FSEQ_DIAG_FILT_SZ   (3UL)
#define FD_FSEQ_DIAG_OVRNP_CNT (4UL)
#define FD_FSEQ_DIAG_OVRNR_CNT (5UL)
#define FD_FSEQ_DIAG_SLOW_CNT  (6UL)

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  char const * _cnc    = fd_env_strip_cmdline_cstr ( &argc, &argv, "--cnc",    NULL, NULL                 ); /* (req) cnc */
  char const * _mcache = fd_env_strip_cmdline_cstr ( &argc, &argv, "--mcache", NULL, NULL                 ); /* (req) mcache */
  char const * _dcache = fd_env_strip_cmdline_cstr ( &argc, &argv, "--dcache", NULL, NULL                 ); /* (req) dcache */
  char const * _fseqs  = fd_env_strip_cmdline_cstr ( &argc, &argv, "--fseqs",  NULL, ""                   ); /* (opt) rx fseqs */
  char const * _init   = fd_env_strip_cmdline_cstr ( &argc, &argv, "--init",   NULL, NULL                 ); /* (opt) init seq */
  ulong        tx_idx  = fd_env_strip_cmdline_ulong( &argc, &argv, "--tx-idx", NULL, 0UL                  ); /* (opt) origin */
  uint         seed    = fd_env_strip_cmdline_uint ( &argc, &argv, "--seed",   NULL, (uint)fd_tickcount() ); /* (opt) rng seed */
  int          lazy    = fd_env_strip_cmdline_int  ( &argc, &argv, "--lazy",   NULL, 7                    ); /* (opt) lazyiness */

  if( FD_UNLIKELY( !_cnc                         ) ) FD_LOG_ERR(( "--cnc not specified" ));
  if( FD_UNLIKELY( !_mcache                      ) ) FD_LOG_ERR(( "--mcache not specified" ));
  if( FD_UNLIKELY( !_dcache                      ) ) FD_LOG_ERR(( "--dcache not specified" ));
  if( FD_UNLIKELY( tx_idx>=FD_FRAG_META_ORIG_MAX ) ) FD_LOG_ERR(( "--tx-idx too large" ));

  ulong rx_cnt = fd_cstr_tokenize( _fseq, RX_MAX, (char *)_fseqs, ',' ); /* Note: argv isn't const to okay to cast away const */
  if( FD_UNLIKELY( rx_cnt>RX_MAX ) ) FD_LOG_ERR(( "--rx-cnt too large for this unit-test" ));

  /* burst_avg is the average number of synthetic payload bytes in a
     packet burst (0 min, exponentially distributed).  A burst's data
     bytes are sent as zero or more packets containing pkt_payload_max
     bytes followed by a one packet containing [1,pkt_payload_max]
     bytes.  All the packets in a burst are sent in rapid succession.
     Packets have a constant number of bytes overhead for various
     headers and footers (pkt_framing).

     E.g. pkt_framing = 70, pkt_payload_max = 1472 would describe an
     Ethernet link that runs UDP / IP4 / VLAN tagged non-Jumbo Ethernet
     packets.  pkt_framing = 70 comes from from 8 byte preamble + 14
     byte Ethernet header + 4 byte VLAN tag + 20 byte IP4 header
     (without options) + 8 byte UDP header + 4 byte frame-check-sequence
     + 12 byte interframe gap, 1472 comes from a 1500 byte MTU (maximum
     Ethernet payload size) - 20 byte IP4 header (without options) - 8
     byte UDP header. */

# define RANDOMIZE_BURSTS 0
  float burst_avg       = fd_env_strip_cmdline_float( &argc, &argv, "--burst-avg",       NULL, 1472.f );
  ulong pkt_payload_max = fd_env_strip_cmdline_ulong( &argc, &argv, "--pkt-payload-max", NULL, 1472UL );
  ulong pkt_framing     = fd_env_strip_cmdline_ulong( &argc, &argv, "--pkt-framing",     NULL,   70UL );

  FD_LOG_NOTICE(( "Configuring synthetic load (--burst-avg %g B --pkt-framing %lu B --pkt-payload-max %lu B,",
                  (double)burst_avg, pkt_framing, pkt_payload_max ));

  /* 2.1e17 ~ LONG_MAX / 43.668 is such that an exponentially
     distributed random from the util/rng API with an average in
     (0,2.1e17) will practically never overflow when rounded to a long. */

  if( FD_UNLIKELY( !((0.f<burst_avg) & (burst_avg<2.1e17f)) ) ) FD_LOG_ERR(( "--burst-avg out of range" ));

  if( FD_UNLIKELY( !pkt_payload_max ) ) FD_LOG_ERR(( "Zero --pkt-payload-max" ));

  ulong pkt_max = pkt_framing + pkt_payload_max;
  if( FD_UNLIKELY( (pkt_max<pkt_framing) | (pkt_max>(ulong)USHORT_MAX) ) )
    FD_LOG_ERR(( "Too large --pkt-framing + --pkt-payload-max" ));

  FD_LOG_NOTICE(( "Creating rng --seed %u", seed ));

  fd_rng_t _rng[1]; fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, seed, 0UL ) );

  FD_LOG_NOTICE(( "Joining to --cnc %s", _cnc ));

  fd_cnc_t * cnc = fd_cnc_join( fd_wksp_map( _cnc ) );
  if( FD_UNLIKELY( !cnc                      ) ) FD_LOG_ERR(( "join failed" ));
  if( FD_UNLIKELY( fd_cnc_app_sz( cnc )<16UL ) ) FD_LOG_ERR(( "cnc app sz must be at least 16" ));

  ulong * cnc_diag = (ulong *)fd_cnc_app_laddr( cnc );
  int     in_backp = 1;
  FD_VOLATILE( cnc_diag[ FD_CNC_DIAG_IN_BACKP  ] ) = 1UL;
  FD_VOLATILE( cnc_diag[ FD_CNC_DIAG_BACKP_CNT ] ) = 0UL;

  FD_LOG_NOTICE(( "Joining to --mcache %s", _mcache ));

  fd_frag_meta_t * mcache = fd_mcache_join( fd_wksp_map( _mcache ) );
  if( FD_UNLIKELY( !mcache ) ) FD_LOG_ERR(( "join failed" ));

  ulong   depth = fd_mcache_depth    ( mcache );
  ulong * sync  = fd_mcache_seq_laddr( mcache );

  ulong seq = _init ? fd_cstr_to_ulong( _init ) : fd_mcache_seq_query( sync );

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

  FD_LOG_NOTICE(( "Configuring flow control (rx_cnt %lu)", rx_cnt ));

  fd_fctl_t * fctl = fd_fctl_join( fd_fctl_new( fctl_mem, rx_cnt ) );
  if( FD_UNLIKELY( !fctl ) ) FD_LOG_ERR(( "join failed" ));

  for( ulong rx_idx=0UL; rx_idx<rx_cnt; rx_idx++ ) {

    FD_LOG_NOTICE(( "Joining to reliable rx %lu fseq %s", rx_idx, _fseq[ rx_idx ] ));
    ulong * fseq = fd_fseq_join( fd_wksp_map( _fseq[ rx_idx ] ) );
    if( FD_UNLIKELY( !fseq ) ) FD_LOG_ERR(( "join failed" ));
    ulong * fseq_diag = (ulong *)fd_fseq_app_laddr( fseq );

    if( FD_UNLIKELY( !fd_fctl_cfg_rx_add( fctl, depth, fseq, &fseq_diag[ FD_FSEQ_DIAG_SLOW_CNT ] ) ) )
      FD_LOG_ERR(( "fd_fctl_cfg_rx_add failed" ));

    FD_VOLATILE( fseq_diag[ FD_FSEQ_DIAG_SLOW_CNT ] ) = 0UL;
  }

  /* cr_burst is 1 because we only send at most 1 fragment metadata
     between checking cr_avail.  We use defaults for cr_max, cr_resume
     and cr_refill. */
  if( FD_UNLIKELY( !fd_fctl_cfg_done( fctl, 1UL, 0UL, 0UL, 0UL ) ) ) FD_LOG_ERR(( "fd_fctl_cfg_done failed" ));
  FD_LOG_NOTICE(( "cr_burst %lu cr_max %lu cr_resume %lu cr_refill %lu",
                  fd_fctl_cr_burst( fctl ), fd_fctl_cr_max( fctl ), fd_fctl_cr_resume( fctl ), fd_fctl_cr_refill( fctl ) ));

  ulong cr_avail = 0UL;

  FD_LOG_NOTICE(( "Running --tx-idx %lu --init %lu (%s) --lazy %i", tx_idx, seq, _init ? "manual" : "auto", lazy ));

  ulong async_min = 1UL << lazy;
  ulong async_rem = 1UL; /* Do housekeeping on the first iteration */

  long  then = fd_log_wallclock();
  ulong iter = 0UL;

  int ctl_som = 1;

  ulong burst_rem;
# if RANDOMIZE_BURSTS
  do { burst_rem = (ulong)(long)(0.5f + burst_avg*fd_rng_float_exp( rng )); } while( FD_UNLIKELY( !burst_rem ) );
# else
  ulong _burst_avg = (ulong)(ulong)burst_avg;
  burst_rem = _burst_avg;
# endif

  fd_cnc_signal( cnc, FD_CNC_SIGNAL_RUN );
  for(;;) {

    /* Do housekeeping in the background */
    if( FD_UNLIKELY( !async_rem ) ) {

      /* Send synchronization info */
      fd_mcache_seq_update( sync, seq );

      /* Send diagnostic info */
      long now = fd_log_wallclock();
      fd_cnc_heartbeat( cnc, now );

      long dt = now - then;
      if( FD_UNLIKELY( dt > (long)1e9 ) ) {
        float mfps = (1e3f*(float)iter) / (float)dt;
        FD_LOG_NOTICE(( "%7.3f Mfrag/s tx (in_backp %lu backp_cnt %lu)", (double)mfps,
                        FD_VOLATILE_CONST( cnc_diag[ FD_CNC_DIAG_IN_BACKP  ] ),
                        FD_VOLATILE_CONST( cnc_diag[ FD_CNC_DIAG_BACKP_CNT ] ) ));
        for( ulong rx_idx=0UL; rx_idx<rx_cnt; rx_idx++ ) {
          ulong * slow = fd_fctl_rx_slow_laddr( fctl, rx_idx );
          FD_LOG_NOTICE(( "slow%lu %lu", rx_idx, FD_VOLATILE_CONST( *slow ) ));
          FD_VOLATILE( *slow ) = 0UL;
        }
        FD_VOLATILE( cnc_diag[ FD_CNC_DIAG_BACKP_CNT ] ) = 0UL;
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
      cr_avail = fd_fctl_tx_cr_update( fctl, cr_avail, seq );
      if( FD_UNLIKELY( in_backp ) ) {
        if( FD_LIKELY( cr_avail ) ) {
          FD_VOLATILE( cnc_diag[ FD_CNC_DIAG_IN_BACKP ] ) = 0UL;
          in_backp = 0;
        }
      }

      /* Reload housekeeping timer */
      async_rem = fd_tempo_async_reload( rng, async_min );
    }
    async_rem--;

    /* Check if we are backpressured */
    if( FD_UNLIKELY( !cr_avail ) ) {
      if( FD_UNLIKELY( !in_backp ) ) {
        FD_VOLATILE( cnc_diag[ FD_CNC_DIAG_IN_BACKP  ] ) = 0UL;
        FD_VOLATILE( cnc_diag[ FD_CNC_DIAG_BACKP_CNT ] ) = FD_VOLATILE_CONST( cnc_diag[ FD_CNC_DIAG_BACKP_CNT ] ) + 1UL;
        in_backp = 1;
      }
      FD_SPIN_PAUSE();
      continue;
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
       complete double cache lines).  We don't care if this is written
       atomic or not. */

    ulong frag_sz = fd_ulong_min( burst_rem, pkt_payload_max );
    burst_rem -= frag_sz;
    int ctl_eom = !burst_rem;
    int ctl_err = 0;

    ulong sig    = seq; /* Test pattern */
  /*ulong chunk  = ... already at location where next packet will be written ...; */
    ulong sz     = pkt_framing + frag_sz;
    ulong ctl    = fd_frag_meta_ctl( tx_idx, ctl_som, ctl_eom, ctl_err );
    ulong tsorig = 0UL;
    ulong tspub  = 0UL;

    uchar * p   = (uchar *)fd_chunk_to_laddr( base, chunk );
    __m256i avx = _mm256_set1_epi64x( (long)seq );
    for( ulong off=0UL; off<sz; off+=128UL ) {
      _mm256_store_si256( (__m256i *)(p     ), avx );
      _mm256_store_si256( (__m256i *)(p+32UL), avx );
      _mm256_store_si256( (__m256i *)(p+64UL), avx );
      _mm256_store_si256( (__m256i *)(p+96UL), avx );
      p += 128UL;
    }

    /* We just "finished receiving" the next fragment of the burst from
       the "NIC".  Publish to consumers as frag seq.  This implicitly
       unpublishes frag seq-depth (cyclic) at the same time. */

#   define PUBLISH_STYLE 0

#   if PUBLISH_STYLE==0 /* Incompatible with WAIT_STYLE==2 */

    fd_mcache_publish( mcache, depth, seq, sig, chunk, sz, ctl, tsorig, tspub );

#   elif PUBLISH_STYLE==1 /* Incompatible with WAIT_STYLE==2 */

    fd_mcache_publish_sse( mcache, depth, seq, sig, chunk, sz, ctl, tsorig, tspub );

#   else /* Compatible with all wait styles, requires target with atomic
            aligned AVX load/store support */

    fd_mcache_publish_avx( mcache, depth, seq, sig, chunk, sz, ctl, tsorig, tspub );

#   endif

    /* Wind up for the next iteration */

    chunk = fd_dcache_compact_next( chunk, sz, chunk0, wmark );
    seq   = fd_seq_inc( seq, 1UL );
    cr_avail--;
    iter++;
#   if RANDOMIZE_BURSTS
    if( FD_UNLIKELY( ctl_eom ) )
      do burst_rem = (ulong)(long)(0.5f + burst_avg*fd_rng_float_exp( rng )); while( FD_UNLIKELY( !burst_rem ) );
#   else
    burst_rem = fd_ulong_if( ctl_eom, _burst_avg, burst_rem );
#   endif
    ctl_som = ctl_eom;
  }

  FD_LOG_NOTICE(( "Cleaning up" ));

  while( rx_cnt ) fd_wksp_unmap( fd_fctl_rx_seq_laddr( fctl, --rx_cnt ) );
  fd_fctl_delete( fd_fctl_leave( fctl ) );
  fd_wksp_unmap( fd_dcache_leave( dcache ) );
  fd_wksp_unmap( fd_mcache_leave( mcache ) );
  fd_cnc_signal( cnc, FD_CNC_SIGNAL_BOOT );
  fd_wksp_unmap( fd_cnc_leave( cnc ) );
  fd_rng_delete( fd_rng_leave( rng ) );

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
