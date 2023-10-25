#include "../fd_disco.h"

#if FD_HAS_HOSTED && FD_HAS_AVX

#include <math.h> /* For expm1f */

FD_STATIC_ASSERT( FD_MUX_CNC_SIGNAL_ACK==4UL, unit_test );

FD_STATIC_ASSERT( FD_MUX_TILE_IN_MAX ==8192UL, unit_test );
FD_STATIC_ASSERT( FD_MUX_TILE_OUT_MAX==8192UL, unit_test );

FD_STATIC_ASSERT( FD_MUX_TILE_SCRATCH_ALIGN==128UL, unit_test );

struct test_cfg {
  fd_wksp_t * wksp;

  ulong       tx_cnt;
  long        tx_lazy;
  uchar *     tx_cnc_mem;      ulong tx_cnc_footprint;
  uchar *     tx_rng_mem;      ulong tx_rng_footprint;
  uchar *     tx_fseq_mem;     ulong tx_fseq_footprint;
  uchar *     tx_mcache_mem;   ulong tx_mcache_footprint;
  uchar *     tx_dcache_mem;   ulong tx_dcache_footprint;
  uchar *     tx_fctl_mem;     ulong tx_fctl_footprint;

  uchar *     mux_cnc_mem;
  uchar *     mux_mcache_mem;
  uchar *     mux_scratch_mem;
  ulong       mux_cr_max;
  long        mux_lazy;
  uint        mux_seed;

  ulong       rx_cnt;
  int         rx_lazy;
  uchar *     rx_cnc_mem;      ulong rx_cnc_footprint;
  uchar *     rx_rng_mem;      ulong rx_rng_footprint;
  uchar *     rx_fseq_mem;     ulong rx_fseq_footprint;

  ulong       pkt_framing;
  ulong       pkt_payload_max;
  float       burst_tau;
  float       burst_avg;
};

typedef struct test_cfg test_cfg_t;

/* TX tile ************************************************************/

/* This uses the same methodology as test_frag_tx.c to inject test
   traffic into a MUX tile.  See test_frag_tx.c for more details */

static int
tx_tile_main( int     argc,
              char ** argv ) {
  ulong        tx_idx = (ulong)(uint)argc;
  test_cfg_t * cfg    = (test_cfg_t *)argv;
  fd_wksp_t *  wksp   = cfg->wksp;

  /* Hook up to tx command-and-control */
  fd_cnc_t * cnc      = fd_cnc_join( cfg->tx_cnc_mem + tx_idx*cfg->tx_cnc_footprint );
  ulong *    cnc_diag = (ulong *)fd_cnc_app_laddr( cnc );
  int        in_backp = 1;

  FD_VOLATILE( cnc_diag[ FD_CNC_DIAG_IN_BACKP  ] ) = 1UL;
  FD_VOLATILE( cnc_diag[ FD_CNC_DIAG_BACKP_CNT ] ) = 0UL;

  /* Hook up to the tx mcache */
  fd_frag_meta_t * mcache = fd_mcache_join( cfg->tx_mcache_mem + tx_idx*cfg->tx_mcache_footprint );
  ulong            depth  = fd_mcache_depth( mcache );
  ulong *          sync   = fd_mcache_seq_laddr( mcache );
  ulong            seq    = fd_mcache_seq_query( sync );

  /* Hook up to the tx dcache */
  uchar * dcache = fd_dcache_join( cfg->tx_dcache_mem + tx_idx*cfg->tx_dcache_footprint );
  ulong   chunk0 = fd_dcache_compact_chunk0( wksp, dcache );
  ulong   wmark  = fd_dcache_compact_wmark ( wksp, dcache, cfg->pkt_framing + cfg->pkt_payload_max );
  ulong   chunk  = chunk0;

  /* Hook up to the tx flow control inputs */
  ulong * fseq      = fd_fseq_join( cfg->tx_fseq_mem + tx_idx*cfg->tx_fseq_footprint );
  ulong * fseq_diag = (ulong *)fd_fseq_app_laddr( fseq );

  FD_VOLATILE( fseq_diag[ FD_FSEQ_DIAG_SLOW_CNT ] ) = 0UL;

  /* Hook up to the tx flow control state */
  fd_fctl_t * fctl = fd_fctl_join( cfg->tx_fctl_mem + tx_idx*cfg->tx_fctl_footprint );
  fd_fctl_cfg_rx_add( fctl, depth, fseq, &fseq_diag[ FD_FSEQ_DIAG_SLOW_CNT ] );
  fd_fctl_cfg_done( fctl, 1UL, 0UL, 0UL, 0UL );
  ulong cr_avail = 0UL;

  /* Hook up to the random number generator */
  fd_rng_t * rng = fd_rng_join( cfg->tx_rng_mem + tx_idx*cfg->tx_rng_footprint );

  /* Configure housekeeping */
  float tick_per_ns = (float)fd_tempo_tick_per_ns( NULL );
  ulong async_min   = fd_tempo_async_min( cfg->tx_lazy ? cfg->tx_lazy : fd_tempo_lazy_default( depth ),
                                          1UL /*event_cnt*/, tick_per_ns );
  if( FD_UNLIKELY( !async_min ) ) FD_LOG_ERR(( "bad --tx-lazy" ));

  long  now  = fd_tickcount();
  long  then = now;            /* Do housekeeping on first iteration of run loop */

  long  diag_interval = (long)(1e9f*tick_per_ns);
  long  diag_last     = now;
  ulong diag_iter     = 0UL;

  /* Configure the synthetic load model */
  ulong pkt_framing     = cfg->pkt_framing;
  ulong pkt_payload_max = cfg->pkt_payload_max;
  float burst_tau       = cfg->burst_tau;
  float burst_avg       = cfg->burst_avg;

  int   ctl_som    = 1;
  ulong burst_ts   = 0UL;  /* Irrelevant value at init */
  long  burst_next = then;
  ulong burst_rem;
  do {
    burst_next +=        (long)(0.5f + burst_tau*fd_rng_float_exp( rng ));
    burst_rem   = (ulong)(long)(0.5f + burst_avg*fd_rng_float_exp( rng ));
  } while( FD_UNLIKELY( !burst_rem ) );

  fd_cnc_signal( cnc, FD_CNC_SIGNAL_RUN );
  for(;;) {

    /* Do housekeeping at a low rate in the background */

    if( FD_UNLIKELY( (now-then)>=0L ) ) {

      /* Send synchronization info */
      fd_mcache_seq_update( sync, seq );

      /* Send diagnostic info */
      fd_cnc_heartbeat( cnc, now );

      long dt = now - diag_last;
      if( FD_UNLIKELY( dt>=diag_interval ) ) {
        float mfps = ((1e3f*tick_per_ns)*(float)diag_iter) / (float)dt;
        FD_LOG_NOTICE(( "%7.3f Mfrag/s tx (in_backp %lu backp_cnt %lu slow_cnt %lu)", (double)mfps,
                        FD_VOLATILE_CONST( cnc_diag[ FD_CNC_DIAG_IN_BACKP  ] ),
                        FD_VOLATILE_CONST( cnc_diag[ FD_CNC_DIAG_BACKP_CNT ] ),
                        fseq_diag[ FD_FSEQ_DIAG_SLOW_CNT ] ));
        FD_VOLATILE( cnc_diag [ FD_CNC_DIAG_BACKP_CNT ] ) = 0UL;
        FD_VOLATILE( fseq_diag[ FD_FSEQ_DIAG_SLOW_CNT ] ) = 0UL;
        diag_last = now;
        diag_iter = 0UL;
      }

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
          FD_VOLATILE( cnc_diag[ FD_CNC_DIAG_IN_BACKP ] ) = 0UL;
          in_backp = 0;
        }
      }

      /* Reload housekeeping timer */
      then = now + (long)fd_tempo_async_reload( rng, async_min );
    }

    /* Check if we are backpressured */
    if( FD_UNLIKELY( !cr_avail ) ) {
      if( FD_UNLIKELY( !in_backp ) ) {
        FD_VOLATILE( cnc_diag[ FD_CNC_DIAG_IN_BACKP  ] ) = 0UL;
        FD_VOLATILE( cnc_diag[ FD_CNC_DIAG_BACKP_CNT ] ) = FD_VOLATILE_CONST( cnc_diag[ FD_CNC_DIAG_BACKP_CNT ] ) + 1UL;
        in_backp = 1;
      }
      FD_SPIN_PAUSE();
      now = fd_tickcount();
      continue;
    }

    /* Check if we are waiting for the next burst to start */

    if( FD_LIKELY( ctl_som ) ) {
      if( FD_UNLIKELY( now<burst_next ) ) { /* Optimize for burst starting */
        FD_SPIN_PAUSE();
        now = fd_tickcount();
        continue;
      }
      /* We just "started receiving" the first bytes of the next burst
         from the "NIC".  Record the timestamp. */
      burst_ts = fd_frag_meta_ts_comp( burst_next );
    }

    /* We are in the process of "receiving" a burst fragment from the
       "NIC".  Compute the details of the synthetic fragment and fill
       the data region with a suitable test pattern as fast as we can. */

    ulong frag_sz = fd_ulong_min( burst_rem, pkt_payload_max );
    burst_rem -= frag_sz;

    int ctl_eom = !burst_rem;
    int ctl_err = 0;

    ulong sig    = seq; /* Test pattern */
  /*ulong chunk  = ... already at location where next packet will be written ...; */
    ulong sz     = pkt_framing + frag_sz;
    ulong ctl    = fd_frag_meta_ctl( tx_idx, ctl_som, ctl_eom, ctl_err );
    ulong tsorig = burst_ts;
  /*ulong tspub  = ... set "after" finished receiving from the "NIC" ...; */

    uchar * p   = (uchar *)fd_chunk_to_laddr( wksp, chunk );
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

    now = fd_tickcount();
    ulong tspub = fd_frag_meta_ts_comp( now );
    fd_mcache_publish( mcache, depth, seq, sig, chunk, sz, ctl, tsorig, tspub );

    /* Wind up for the next iteration */

    chunk = fd_dcache_compact_next( chunk, sz, chunk0, wmark );
    seq   = fd_seq_inc( seq, 1UL );
    cr_avail--;
    if( FD_UNLIKELY( !ctl_eom ) ) ctl_som = 0;
    else {
      ctl_som = 1;
      do {
        burst_next +=        (long)(0.5f + burst_tau*fd_rng_float_exp( rng ));
        burst_rem   = (ulong)(long)(0.5f + burst_avg*fd_rng_float_exp( rng ));
      } while( FD_UNLIKELY( !burst_rem ) );
    }
    diag_iter++;
  }

  fd_cnc_signal( cnc, FD_CNC_SIGNAL_BOOT );
  return 0;
}

/* MUX tile ***********************************************************/

static int
mux_tile_main( int     argc,
               char ** argv ) {
  (void)argc;
  test_cfg_t * cfg = (test_cfg_t *)argv;

  if( FD_UNLIKELY( cfg->tx_cnt>128UL ) ) FD_LOG_ERR(( "update unit test for this large a tx_cnt" ));
  if( FD_UNLIKELY( cfg->rx_cnt>128UL ) ) FD_LOG_ERR(( "update unit test for this large a rx_cnt" ));

  fd_cnc_t * cnc = fd_cnc_join( cfg->mux_cnc_mem );

  fd_frag_meta_t const * tx_mcache[ 128 ];
  for( ulong tx_idx=0UL; tx_idx<cfg->tx_cnt; tx_idx++ )
    tx_mcache[ tx_idx ] = fd_mcache_join( cfg->tx_mcache_mem + tx_idx*cfg->tx_mcache_footprint );

  ulong * tx_fseq[ 128 ];
  for( ulong tx_idx=0UL; tx_idx<cfg->tx_cnt; tx_idx++ )
    tx_fseq[ tx_idx ] = fd_fseq_join( cfg->tx_fseq_mem + tx_idx*cfg->tx_fseq_footprint );

  fd_frag_meta_t * mux_mcache = fd_mcache_join( cfg->mux_mcache_mem );

  ulong * rx_fseq[ 128 ];
  for( ulong rx_idx=0UL; rx_idx<cfg->rx_cnt; rx_idx++ )
    rx_fseq[ rx_idx ] = fd_fseq_join( cfg->rx_fseq_mem + rx_idx*cfg->rx_fseq_footprint );

  fd_rng_t _rng[1];
  fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, cfg->mux_seed, 0UL ) );

  fd_mux_callbacks_t callbacks = {0};
  int err = fd_mux_tile( cnc, FD_MUX_FLAG_DEFAULT, cfg->tx_cnt, tx_mcache, tx_fseq, mux_mcache, cfg->rx_cnt, rx_fseq,
                         1UL, cfg->mux_cr_max, cfg->mux_lazy, rng, cfg->mux_scratch_mem, NULL, &callbacks );
  if( FD_UNLIKELY( err ) ) FD_LOG_ERR(( "fd_mux_tile failed (%i)", err ));

  fd_rng_delete( fd_rng_leave( rng ) );
  for( ulong rx_idx=cfg->rx_cnt; rx_idx; rx_idx-- ) fd_fseq_leave  ( rx_fseq  [ rx_idx-1UL ] );
  fd_mcache_leave( mux_mcache );
  for( ulong tx_idx=cfg->tx_cnt; tx_idx; tx_idx-- ) fd_fseq_leave  ( tx_fseq  [ tx_idx-1UL ] );
  for( ulong tx_idx=cfg->tx_cnt; tx_idx; tx_idx-- ) fd_mcache_leave( tx_mcache[ tx_idx-1UL ] );
  fd_cnc_leave( cnc );
  return 0;
}

/* RX tile ************************************************************/

/* This uses the same methodology as test_frag_rx.c to process test
   traffic from multiple TX tiles via a MUX tile.  See test_frag_rx.c
   for more details */

static int
rx_tile_main( int     argc,
              char ** argv ) {
  ulong        rx_idx = (ulong)(uint)argc;
  test_cfg_t * cfg    = (test_cfg_t *)argv;
  fd_wksp_t *  wksp   = cfg->wksp;

  /* Hook up to rx cnc */
  fd_cnc_t * cnc = fd_cnc_join( cfg->rx_cnc_mem + rx_idx*cfg->rx_cnc_footprint );

  /* Hook up to mux mcache */
  fd_frag_meta_t const * mcache = fd_mcache_join( cfg->mux_mcache_mem );
  ulong                  depth  = fd_mcache_depth( mcache );
  ulong const *          sync   = fd_mcache_seq_laddr_const( mcache );
  ulong                  seq    = fd_mcache_seq_query( sync );

  /* Hook up to mux flow control */
  ulong * fseq = fd_fseq_join( cfg->rx_fseq_mem + rx_idx*cfg->rx_fseq_footprint );

  /* Hook up to the random number generator */
  fd_rng_t * rng = fd_rng_join( cfg->rx_rng_mem + rx_idx*cfg->rx_rng_footprint );

  /* Configure housekeeping */
  ulong async_min = 1UL << cfg->rx_lazy;
  ulong async_rem = 1UL; /* Do housekeeping on first iteration */

  long  then = fd_log_wallclock();
  ulong iter = 0UL;

  fd_cnc_signal( cnc, FD_CNC_SIGNAL_RUN );
  for(;;) {

    /* Wait for frag seq while doing housekeeping in the background */

    fd_frag_meta_t const * mline;
    ulong                  seq_found;
    long                   diff;

    ulong sig;
    ulong chunk;
    ulong sz;
    ulong ctl;
    ulong tsorig;
    ulong tspub;
    FD_MCACHE_WAIT_REG( sig, chunk, sz, ctl, tsorig, tspub, mline, seq_found, diff, async_rem, mcache, depth, seq );
    if( FD_UNLIKELY( !async_rem ) ) {

      /* Send flow control credits */
      fd_fctl_rx_cr_return( fseq, seq );

      /* Send diagnostic info */
      long now = fd_log_wallclock();
      fd_cnc_heartbeat( cnc, now );

      long dt = now - then;
      if( FD_UNLIKELY( dt > (long)1e9 ) ) {
        float mfps = (1e3f*(float)iter) / (float)dt;
        FD_LOG_NOTICE(( "%7.3f Mfrag/s rx", (double)mfps ));
        then = now;
        iter = 0UL;
      }

      /* Receive command-and-control signals */
      ulong s = fd_cnc_signal_query( cnc );
      if( FD_UNLIKELY( s!=FD_CNC_SIGNAL_RUN ) ) {
        if( FD_UNLIKELY( s!=FD_CNC_SIGNAL_HALT ) ) FD_LOG_ERR(( "Unexpected signal" ));
        break;
      }

      /* Reload housekeeping timer */
      async_rem = fd_tempo_async_reload( rng, async_min );
      continue;
    }

    if( FD_UNLIKELY( diff ) ) FD_LOG_ERR(( "Overrun while polling" ));

    /* Process the received fragment (FIXME: also validate continuity of
       the individual tx streams via sig too, validate control bits, add
       latency and bandwidth stats). */

    (void)ctl; (void)tsorig; (void)tspub;

    uchar const * p = (uchar const *)fd_chunk_to_laddr_const( wksp, chunk );
    __m256i avx = _mm256_set1_epi64x( (long)sig );
    int mask0 = -1;
    int mask1 = -1;
    int mask2 = -1;
    int mask3 = -1;
    for( ulong off=0UL; off<sz; off+=128UL ) {
      mask0 &= _mm256_movemask_epi8( _mm256_cmpeq_epi8( _mm256_load_si256( (__m256i *) p       ), avx ) );
      mask1 &= _mm256_movemask_epi8( _mm256_cmpeq_epi8( _mm256_load_si256( (__m256i *)(p+32UL) ), avx ) );
      mask2 &= _mm256_movemask_epi8( _mm256_cmpeq_epi8( _mm256_load_si256( (__m256i *)(p+64UL) ), avx ) );
      mask3 &= _mm256_movemask_epi8( _mm256_cmpeq_epi8( _mm256_load_si256( (__m256i *)(p+96UL) ), avx ) );
      p += 128UL;
    }

    /* Check that we weren't overrun while processing. */
    seq_found = fd_frag_meta_seq_query( mline );
    if( FD_UNLIKELY( fd_seq_ne( seq_found, seq ) ) ) FD_LOG_ERR(( "Overrun while reading" ));

    /* Validate that the frag payload was as expected */
    int corrupt = ((mask0 & mask1 & mask2 & mask3)!=-1);
    if( FD_UNLIKELY( corrupt ) ) FD_LOG_ERR(( "Corrupt payload received" ));

    /* Wind up for the next iteration */
    seq = fd_seq_inc( seq, 1UL );
    iter++;
  }

  fd_cnc_signal( cnc, FD_CNC_SIGNAL_BOOT );
  return 0;
}

/* CNC tile ***********************************************************/

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  uint rng_seq = 0U;
  fd_rng_t _rng[1]; fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, rng_seq++, 0UL ) );

  FD_TEST( fd_mux_tile_scratch_align()==FD_MUX_TILE_SCRATCH_ALIGN );
  FD_TEST( !fd_mux_tile_scratch_footprint( FD_MUX_TILE_IN_MAX +1UL, 1UL ) );
  FD_TEST( !fd_mux_tile_scratch_footprint( 1UL, FD_MUX_TILE_OUT_MAX+1UL ) );
  for( ulong iter_rem=10000000UL; iter_rem; iter_rem-- ) {
    ulong in_cnt  = fd_rng_ulong_roll( rng, FD_MUX_TILE_IN_MAX +1UL );
    ulong out_cnt = fd_rng_ulong_roll( rng, FD_MUX_TILE_OUT_MAX+1UL );
    FD_TEST( fd_mux_tile_scratch_footprint( in_cnt, out_cnt )==FD_MUX_TILE_SCRATCH_FOOTPRINT( in_cnt, out_cnt ) );
  }

  ulong cpu_idx = fd_tile_cpu_id( fd_tile_idx() );
  if( cpu_idx>=fd_shmem_cpu_cnt() ) cpu_idx = 0UL;

  char const * _page_sz   = fd_env_strip_cmdline_cstr ( &argc, &argv, "--page-sz",    NULL, "gigantic"                   );
  ulong        page_cnt   = fd_env_strip_cmdline_ulong( &argc, &argv, "--page-cnt",   NULL, 1UL                          );
  ulong        numa_idx   = fd_env_strip_cmdline_ulong( &argc, &argv, "--numa-idx",   NULL, fd_shmem_numa_idx( cpu_idx ) );
  ulong        tx_cnt     = fd_env_strip_cmdline_ulong( &argc, &argv, "--tx-cnt",     NULL, 2UL                          );
  ulong        tx_depth   = fd_env_strip_cmdline_ulong( &argc, &argv, "--tx-depth",   NULL, 32768UL                      );
  ulong        tx_mtu     = fd_env_strip_cmdline_ulong( &argc, &argv, "--tx-mtu",     NULL, 1472UL                       );
  long         tx_lazy    = fd_env_strip_cmdline_long ( &argc, &argv, "--tx-lazy",    NULL, 0L                           );
  ulong        mux_depth  = fd_env_strip_cmdline_ulong( &argc, &argv, "--mux-depth",  NULL, 32768UL                      );
  ulong        mux_cr_max = fd_env_strip_cmdline_ulong( &argc, &argv, "--mux-cr-max", NULL, 0UL /* use default */        );
  long         mux_lazy   = fd_env_strip_cmdline_long ( &argc, &argv, "--mux-lazy",   NULL, 0L /* use default */         );
  ulong        rx_cnt     = fd_env_strip_cmdline_ulong( &argc, &argv, "--rx-cnt",     NULL, 2UL                          );
  int          rx_lazy    = fd_env_strip_cmdline_int  ( &argc, &argv, "--rx-lazy",    NULL, 7                            );
  long         duration   = fd_env_strip_cmdline_long ( &argc, &argv, "--duration",   NULL, (long)10e9                   );

  float burst_avg       = fd_env_strip_cmdline_float( &argc, &argv, "--burst-avg",       NULL, 1472.f );
  ulong pkt_payload_max = fd_env_strip_cmdline_ulong( &argc, &argv, "--pkt-payload-max", NULL, 1472UL );
  ulong pkt_framing     = fd_env_strip_cmdline_ulong( &argc, &argv, "--pkt-framing",     NULL,   70UL );
  float pkt_bw          = fd_env_strip_cmdline_float( &argc, &argv, "--pkt-bw",          NULL,  25e9f );

  ulong page_sz = fd_cstr_to_shmem_page_sz( _page_sz );
  if( FD_UNLIKELY( !page_sz                   ) ) FD_LOG_ERR(( "unsupported --page-sz" ));
  if( FD_UNLIKELY( !tx_cnt                    ) ) FD_LOG_ERR(( "tx_cnt should be positive" ));
  if( FD_UNLIKELY( !rx_cnt                    ) ) FD_LOG_ERR(( "rx_cnt should be positive" ));
  if( FD_UNLIKELY( tx_cnt>FD_MUX_TILE_IN_MAX  ) ) FD_LOG_ERR(( "--tx-cnt too large for this unit test" ));
  if( FD_UNLIKELY( rx_cnt>FD_MUX_TILE_OUT_MAX ) ) FD_LOG_ERR(( "--rx-cnt too large for this unit test" ));

  ulong tile_cnt = 1UL+tx_cnt+1UL+rx_cnt; /* 1 main(cnc,this) + tx_cnt tx_mains + 1 mux_main + rx_cnt rx_mains */
  if( FD_UNLIKELY( fd_tile_cnt()<tile_cnt ) ) FD_LOG_ERR(( "this unit test requires at least %lu tiles", tile_cnt ));

  FD_LOG_NOTICE(( "Configuring synthetic load (--burst-avg %g B --pkt-framing %lu B --pkt-payload-max %lu B --pkt-bw %g b/s)",
                  (double)burst_avg, pkt_framing, pkt_payload_max, (double)pkt_bw ));

  if( FD_UNLIKELY( !((0.f<burst_avg) & (burst_avg<2.1e17f)) ) ) FD_LOG_ERR(( "--burst-avg out of range" ));

  if( FD_UNLIKELY( !pkt_payload_max ) ) FD_LOG_ERR(( "Zero --pkt-payload-max" ));

  ulong pkt_max = pkt_framing + pkt_payload_max;
  if( FD_UNLIKELY( (pkt_max<pkt_framing) | (pkt_max>(ulong)USHORT_MAX) ) )
    FD_LOG_ERR(( "Too large --pkt-framing + --pkt-payload-max" ));

  if( FD_UNLIKELY( !(0.f<pkt_bw) ) ) FD_LOG_ERR(( "--pkt-bw out of range" ));

  float burst_bw = pkt_bw
                 / (1.f - ((((float)pkt_framing)/((float)burst_avg)) / expm1f( -((float)pkt_payload_max)/((float)burst_avg) )));

  float tick_per_ns = (float)fd_tempo_tick_per_ns( NULL );
  float burst_tau   = (tick_per_ns*burst_avg)*(8e9f/burst_bw); /* Avg time btw bursts in tick (8 b/B, 1e9 ns/s, bw b/s) */
  if( FD_UNLIKELY( !(burst_tau<2.1e17f) ) ) FD_LOG_ERR(( "--pkt-bw out of range" ));

  FD_LOG_NOTICE(( "Creating workspace with --page-cnt %lu --page-sz %s pages on --numa-idx %lu", page_cnt, _page_sz, numa_idx ));
  fd_wksp_t * wksp = fd_wksp_new_anonymous( page_sz, page_cnt, fd_shmem_cpu_idx( numa_idx ), "wksp", 0UL );
  FD_TEST( wksp );

  FD_LOG_NOTICE(( "Creating cncs (--tx-cnt %lu, mux-cnt 1, --rx-cnt %lu, app-sz 64)", tx_cnt, rx_cnt ));
  ulong   cnc_footprint = fd_cnc_footprint( 64UL ); /* Room for 8 64-bit diagnostic counters */
  uchar * cnc_mem       = (uchar *)fd_wksp_alloc_laddr( wksp, fd_cnc_align(), cnc_footprint*(tx_cnt+1UL+rx_cnt), 1UL );
  FD_TEST( cnc_mem );

  FD_LOG_NOTICE(( "Creating fseqs" ));
  ulong   fseq_footprint = fd_fseq_footprint();
  uchar * fseq_mem       = (uchar *)fd_wksp_alloc_laddr( wksp, fd_fseq_align(), fseq_footprint*(tx_cnt+rx_cnt), 1UL );
  FD_TEST( fseq_mem );

  FD_LOG_NOTICE(( "Creating rngs" ));
  ulong   rng_align     = fd_ulong_max( fd_rng_align(), 128UL ); /* overalign to avoid false sharing */
  ulong   rng_footprint = fd_ulong_align_up( fd_rng_footprint(), rng_align );
  uchar * rng_mem       = (uchar *)fd_wksp_alloc_laddr( wksp, rng_align, rng_footprint*(tx_cnt+rx_cnt), 1UL );
  FD_TEST( rng_mem );

  FD_LOG_NOTICE(( "Creating tx mcaches (--tx-depth %lu, app-sz 0)", tx_depth ));
  ulong   tx_mcache_footprint = fd_mcache_footprint( tx_depth, 0UL ); /* No app region for the mcache */
  uchar * tx_mcache_mem       = (uchar *)fd_wksp_alloc_laddr( wksp, fd_mcache_align(), tx_mcache_footprint*tx_cnt, 1UL );
  FD_TEST( tx_mcache_mem );

  FD_LOG_NOTICE(( "Creating tx dcaches (--tx-mtu %lu, tx-burst 1, tx-compact 1, app-sz 0)", tx_mtu ));
  ulong   tx_data_sz          = fd_dcache_req_data_sz( tx_mtu, tx_depth, 1UL, 1  ); FD_TEST( tx_data_sz );
  ulong   tx_dcache_footprint = fd_dcache_footprint( tx_data_sz, 0UL ); /* No app region for the dcache */
  uchar * tx_dcache_mem       = (uchar *)fd_wksp_alloc_laddr( wksp, fd_dcache_align(), tx_dcache_footprint*tx_cnt, 1UL );
  FD_TEST( tx_dcache_mem );

  FD_LOG_NOTICE(( "Creating tx fctls (--tx-depth %lu, app-sz 0)", tx_depth ));
  ulong   tx_fctl_align     = fd_ulong_max( fd_fctl_align(), 128UL ); /* overalign to avoid false sharing */
  ulong   tx_fctl_footprint = fd_ulong_align_up( fd_fctl_footprint( 1UL ), tx_fctl_align );
  uchar * tx_fctl_mem       = (uchar *)fd_wksp_alloc_laddr( wksp, tx_fctl_align, tx_fctl_footprint*tx_cnt, 1UL );
  FD_TEST( tx_fctl_mem );

  FD_LOG_NOTICE(( "Creating mux mcache (--mux-depth %lu, app-sz 0)", mux_depth ));
  ulong   mux_mcache_footprint = fd_mcache_footprint( mux_depth, 0UL ); /* No app region for the mcache */
  uchar * mux_mcache_mem       = (uchar *)fd_wksp_alloc_laddr( wksp, fd_mcache_align(), mux_mcache_footprint, 1UL );
  FD_TEST( mux_mcache_mem );

  FD_LOG_NOTICE(( "Creating mux scratch" ));
  ulong   mux_scratch_footprint = fd_mux_tile_scratch_footprint( tx_cnt, rx_cnt );
  uchar * mux_scratch_mem       = (uchar *)fd_wksp_alloc_laddr( wksp, fd_mux_tile_scratch_align(), mux_scratch_footprint, 1UL );
  FD_TEST( mux_scratch_mem );

  long now = fd_tickcount();

  test_cfg_t cfg[1];

  cfg->wksp = wksp;

  cfg->tx_cnt        = tx_cnt;
  cfg->tx_lazy       = tx_lazy;
  cfg->tx_cnc_mem    = cnc_mem;       cfg->tx_cnc_footprint    = cnc_footprint;
  cfg->tx_rng_mem    = rng_mem;       cfg->tx_rng_footprint    = rng_footprint;
  cfg->tx_fseq_mem   = fseq_mem;      cfg->tx_fseq_footprint   = fseq_footprint;
  cfg->tx_mcache_mem = tx_mcache_mem; cfg->tx_mcache_footprint = tx_mcache_footprint;
  cfg->tx_dcache_mem = tx_dcache_mem; cfg->tx_dcache_footprint = tx_dcache_footprint;
  cfg->tx_fctl_mem   = tx_fctl_mem;   cfg->tx_fctl_footprint   = tx_fctl_footprint;

  cfg->mux_cnc_mem     = cnc_mem + tx_cnt*cnc_footprint;
  cfg->mux_mcache_mem  = mux_mcache_mem;
  cfg->mux_scratch_mem = mux_scratch_mem;
  cfg->mux_cr_max      = mux_cr_max;
  cfg->mux_lazy        = mux_lazy;
  cfg->mux_seed        = rng_seq++;

  cfg->rx_cnt      = rx_cnt;
  cfg->rx_lazy     = rx_lazy;
  cfg->rx_cnc_mem  = cnc_mem  + (tx_cnt+1UL)*cnc_footprint;  cfg->rx_cnc_footprint  = cnc_footprint;
  cfg->rx_rng_mem  = rng_mem  +  tx_cnt     *rng_footprint;  cfg->rx_rng_footprint  = rng_footprint;
  cfg->rx_fseq_mem = fseq_mem +  tx_cnt     *fseq_footprint; cfg->rx_fseq_footprint = fseq_footprint;
  
  cfg->pkt_framing     = pkt_framing;
  cfg->pkt_payload_max = pkt_payload_max;
  cfg->burst_tau       = burst_tau;
  cfg->burst_avg       = burst_avg;

  for( ulong tx_idx=0UL; tx_idx<tx_cnt; tx_idx++ ) {
    ulong tx_seq0 = fd_rng_ulong( rng );
    FD_TEST( fd_cnc_new   ( cfg->tx_cnc_mem    + tx_idx*cfg->tx_cnc_footprint,    64UL, 0UL, now         ) );
    FD_TEST( fd_rng_new   ( cfg->tx_rng_mem    + tx_idx*cfg->tx_rng_footprint,    rng_seq++, 0UL         ) );
    FD_TEST( fd_fseq_new  ( cfg->tx_fseq_mem   + tx_idx*cfg->tx_fseq_footprint,   tx_seq0                ) );
    FD_TEST( fd_mcache_new( cfg->tx_mcache_mem + tx_idx*cfg->tx_mcache_footprint, tx_depth, 0UL, tx_seq0 ) );
    FD_TEST( fd_dcache_new( cfg->tx_dcache_mem + tx_idx*cfg->tx_dcache_footprint, tx_data_sz, 0UL        ) );
    FD_TEST( fd_fctl_new  ( cfg->tx_fctl_mem   + tx_idx*cfg->tx_fctl_footprint,   1UL                    ) );
  }

  ulong mux_seq0 = fd_rng_ulong( rng );
  FD_TEST( fd_cnc_new   ( cfg->mux_cnc_mem,    64UL, 1UL, now           ) );
  FD_TEST( fd_mcache_new( cfg->mux_mcache_mem, mux_depth, 0UL, mux_seq0 ) );

  for( ulong rx_idx=0UL; rx_idx<rx_cnt; rx_idx++ ) {
    FD_TEST( fd_cnc_new ( cfg->rx_cnc_mem  + rx_idx*cfg->rx_cnc_footprint,  64UL, 2UL, now ) );
    FD_TEST( fd_rng_new ( cfg->rx_rng_mem  + rx_idx*cfg->rx_rng_footprint,  rng_seq++, 0UL ) );
    FD_TEST( fd_fseq_new( cfg->rx_fseq_mem + rx_idx*cfg->rx_fseq_footprint, mux_seq0       ) );
  }

  FD_LOG_NOTICE(( "Booting" ));

  fd_cnc_t * cnc[ FD_TILE_MAX ];
  for( ulong tile_idx=1UL; tile_idx<tile_cnt; tile_idx++ ) {
    cnc[ tile_idx ]= fd_cnc_join( cnc_mem + (tile_idx-1UL)*cnc_footprint );
    FD_TEST( cnc[ tile_idx ] );
  }

  for( ulong tile_idx=tile_cnt-1UL; tile_idx>0UL; tile_idx-- ) { /* reverse order to bring rxs -> mux -> txs */
    fd_tile_task_t tile_main;
    int            argc;
    char **        argv = (char **)fd_type_pun( cfg );
    if(      tile_idx<= tx_cnt      ) { tile_main =  tx_tile_main; argc = (int)(uint)(tile_idx-1UL);        }
    else if( tile_idx==(tx_cnt+1UL) ) { tile_main = mux_tile_main; argc = 0;                                }
    else                              { tile_main =  rx_tile_main; argc = (int)(uint)(tile_idx-tx_cnt-2UL); }
    FD_TEST( fd_tile_exec_new( tile_idx, tile_main, argc, argv ) );
  }

  for( ulong tile_idx=1UL; tile_idx<tile_cnt; tile_idx++ )
    FD_TEST( fd_cnc_wait( cnc[ tile_idx ], FD_CNC_SIGNAL_BOOT, (long)5e9, NULL )==FD_CNC_SIGNAL_RUN );

  FD_LOG_NOTICE(( "Running (--duration %li ns, --tx-lazy %li ns, --mux-cr-max %lu, --mux-lazy %li ns, --rx-lazy %i)",
                  duration, tx_lazy, mux_cr_max, mux_lazy, rx_lazy ));

  /* FIXME: DO MONITORING WHILE RUNNING */
  fd_log_sleep( duration );

  FD_LOG_NOTICE(( "Halting" ));

  for( ulong tile_idx=1UL; tile_idx<tile_cnt; tile_idx++ ) {
    FD_TEST( !fd_cnc_open( cnc[ tile_idx ] ) );
    fd_cnc_signal( cnc[ tile_idx ], FD_CNC_SIGNAL_HALT );
    fd_cnc_close( cnc[ tile_idx ] );
  }

  for( ulong tile_idx=1UL; tile_idx<tile_cnt; tile_idx++ )
    FD_TEST( fd_cnc_wait( cnc[ tile_idx ], FD_CNC_SIGNAL_HALT, (long)5e9, NULL )==FD_CNC_SIGNAL_BOOT );

  for( ulong tile_idx=1UL; tile_idx<tile_cnt; tile_idx++ ) {
    int ret;
    FD_TEST( !fd_tile_exec_delete( fd_tile_exec( tile_idx ), &ret ) );
    FD_TEST( !ret );
  }

  for( ulong tile_idx=1UL; tile_idx<tile_cnt; tile_idx++ ) FD_TEST( fd_cnc_leave( cnc[ tile_idx ] ) );

  FD_LOG_NOTICE(( "Cleaning up" ));

  for( ulong rx_idx=0UL; rx_idx<rx_cnt; rx_idx++ ) {
    FD_TEST( fd_fseq_delete( cfg->rx_fseq_mem + rx_idx*cfg->rx_fseq_footprint ) );
    FD_TEST( fd_rng_delete ( cfg->rx_rng_mem  + rx_idx*cfg->rx_rng_footprint  ) );
    FD_TEST( fd_cnc_delete ( cfg->rx_cnc_mem  + rx_idx*cfg->rx_cnc_footprint  ) );
  }

  FD_TEST( fd_mcache_delete( cfg->mux_mcache_mem ) );
  FD_TEST( fd_cnc_delete   ( cfg->mux_cnc_mem    ) );

  for( ulong tx_idx=0UL; tx_idx<tx_cnt; tx_idx++ ) {
    FD_TEST( fd_fctl_delete  ( cfg->tx_fctl_mem   + tx_idx*cfg->tx_fctl_footprint   ) );
    FD_TEST( fd_dcache_delete( cfg->tx_dcache_mem + tx_idx*cfg->tx_dcache_footprint ) );
    FD_TEST( fd_mcache_delete( cfg->tx_mcache_mem + tx_idx*cfg->tx_mcache_footprint ) );
    FD_TEST( fd_fseq_delete  ( cfg->tx_fseq_mem   + tx_idx*cfg->tx_fseq_footprint   ) );
    FD_TEST( fd_rng_delete   ( cfg->tx_rng_mem    + tx_idx*cfg->tx_rng_footprint    ) );
    FD_TEST( fd_cnc_delete   ( cfg->tx_cnc_mem    + tx_idx*cfg->tx_cnc_footprint    ) );
  }

  fd_wksp_free_laddr( mux_scratch_mem );
  fd_wksp_free_laddr( mux_mcache_mem  );
  fd_wksp_free_laddr( tx_fctl_mem     );
  fd_wksp_free_laddr( tx_dcache_mem   );
  fd_wksp_free_laddr( tx_mcache_mem   );
  fd_wksp_free_laddr( rng_mem         );
  fd_wksp_free_laddr( fseq_mem        );
  fd_wksp_free_laddr( cnc_mem         );

  fd_wksp_delete_anonymous( wksp );

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

