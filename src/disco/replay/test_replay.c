#include "../fd_disco.h"

#if FD_HAS_HOSTED

FD_STATIC_ASSERT( FD_REPLAY_CNC_SIGNAL_ACK==4UL, unit_test );

FD_STATIC_ASSERT( FD_REPLAY_CNC_DIAG_CHUNK_IDX    ==2UL, unit_test );
FD_STATIC_ASSERT( FD_REPLAY_CNC_DIAG_PCAP_DONE    ==3UL, unit_test );
FD_STATIC_ASSERT( FD_REPLAY_CNC_DIAG_PCAP_PUB_CNT ==4UL, unit_test );
FD_STATIC_ASSERT( FD_REPLAY_CNC_DIAG_PCAP_PUB_SZ  ==5UL, unit_test );
FD_STATIC_ASSERT( FD_REPLAY_CNC_DIAG_PCAP_FILT_CNT==6UL, unit_test );
FD_STATIC_ASSERT( FD_REPLAY_CNC_DIAG_PCAP_FILT_SZ ==7UL, unit_test );

FD_STATIC_ASSERT( FD_REPLAY_TILE_OUT_MAX==8192UL, unit_test );

FD_STATIC_ASSERT( FD_REPLAY_TILE_SCRATCH_ALIGN==128UL, unit_test );

struct test_cfg {
  fd_wksp_t *  wksp;

  fd_cnc_t *       tx_cnc;
  char const *     tx_pcap;
  ulong            tx_mtu;
  ulong            tx_orig;
  fd_frag_meta_t * tx_mcache;
  uchar *          tx_dcache;
  ulong            tx_cr_max;
  long             tx_lazy;
  uint             tx_seed;

  fd_cnc_t *       rx_cnc;
  ulong *          rx_fseq;
  uint             rx_seed;
  int              rx_lazy;
};

typedef struct test_cfg test_cfg_t;

/* TX tile ************************************************************/

static int
tx_tile_main( int     argc,
              char ** argv ) {
  (void)argc;
  test_cfg_t * cfg = (test_cfg_t *)argv;

  fd_rng_t _rng[1];
  fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, cfg->tx_seed, 0UL ) );

  uchar scratch[ FD_REPLAY_TILE_SCRATCH_FOOTPRINT( 1UL ) ] __attribute__((aligned( FD_REPLAY_TILE_SCRATCH_ALIGN )));

  FD_TEST( !fd_replay_tile( cfg->tx_cnc, cfg->tx_pcap, cfg->tx_mtu, cfg->tx_orig, cfg->tx_mcache, cfg->tx_dcache,
                            1UL, &cfg->rx_fseq, cfg->tx_cr_max, cfg->tx_lazy, rng, scratch ) );

  fd_rng_delete( fd_rng_leave( rng ) );
  return 0;
}

/* RX tile ************************************************************/

static int
rx_tile_main( int     argc,
              char ** argv ) {
  ulong        rx_idx = (ulong)argc;
  test_cfg_t * cfg    = (test_cfg_t *)argv;
  fd_wksp_t *  wksp   = cfg->wksp;
  (void)rx_idx;

  /* Hook up to rx cnc */
  fd_cnc_t * cnc = cfg->rx_cnc;

  /* Hook up to tx mcache */
  fd_frag_meta_t const * mcache = cfg->tx_mcache;
  ulong                  depth  = fd_mcache_depth( mcache );
  ulong const *          sync   = fd_mcache_seq_laddr_const( mcache );
  ulong                  seq    = fd_mcache_seq_query( sync );

  /* Hook up to tx flow control */
  ulong * fseq = cfg->rx_fseq;

  /* Hook up to the random number generator */
  fd_rng_t _rng[1];
  fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, cfg->rx_seed, 0UL ) );

  /* Configure housekeeping */
  ulong async_min = 1UL << cfg->rx_lazy;
  ulong async_rem = 1UL; /* Do housekeeping on first iteration */

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
      fd_cnc_heartbeat( cnc, fd_tickcount() );

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

    /* Process the received fragment */

    uchar const * p = (uchar const *)fd_chunk_to_laddr_const( wksp, chunk );
#   if 1
    (void)ctl; (void)sz; (void)sig; (void)tsorig; (void)tspub; (void)p;
#   else
    (void)tsorig; (void)tspub;
    FD_LOG_NOTICE(( "orig %4lu sz %5lu sig %016lx\n\t"
                    "%02x: " FD_LOG_HEX16_FMT "\n\t"
                    "%02x: " FD_LOG_HEX16_FMT "\n\t"
                    "%02x: " FD_LOG_HEX16_FMT "\n\t"
                    "%02x: " FD_LOG_HEX16_FMT "\n\t"
                    "%02x: " FD_LOG_HEX16_FMT "\n\t"
                    "%02x: " FD_LOG_HEX16_FMT "\n\t"
                    "%02x: " FD_LOG_HEX16_FMT "\n\t"
                    "%02x: " FD_LOG_HEX16_FMT,
                    fd_frag_meta_ctl_orig( ctl ), sz, sig,
                      0U, FD_LOG_HEX16_FMT_ARGS( p     ),
                     16U, FD_LOG_HEX16_FMT_ARGS( p+ 16 ),
                     32U, FD_LOG_HEX16_FMT_ARGS( p+ 32 ),
                     48U, FD_LOG_HEX16_FMT_ARGS( p+ 48 ),
                     64U, FD_LOG_HEX16_FMT_ARGS( p+ 64 ),
                     80U, FD_LOG_HEX16_FMT_ARGS( p+ 80 ),
                     96U, FD_LOG_HEX16_FMT_ARGS( p+ 96 ),
                    112U, FD_LOG_HEX16_FMT_ARGS( p+112 ) ));
#   endif

    /* Check that we weren't overrun while processing. */
    seq_found = fd_frag_meta_seq_query( mline );
    if( FD_UNLIKELY( fd_seq_ne( seq_found, seq ) ) ) FD_LOG_ERR(( "Overrun while reading" ));

    /* Wind up for the next iteration */
    seq = fd_seq_inc( seq, 1UL );
  }

  fd_rng_delete( fd_rng_leave( rng ) );
  fd_cnc_signal( cnc, FD_CNC_SIGNAL_BOOT );
  return 0;
}

/* MAIN tail **********************************************************/

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );
  
  uint rng_seq = 0U;
  fd_rng_t _rng[1]; fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, rng_seq++, 0UL ) );

  FD_TEST( fd_replay_tile_scratch_align()==FD_REPLAY_TILE_SCRATCH_ALIGN );
  FD_TEST( !fd_replay_tile_scratch_footprint( FD_REPLAY_TILE_OUT_MAX+1UL ) );
  for( ulong iter_rem=10000000UL; iter_rem; iter_rem-- ) {
    ulong out_cnt = fd_rng_ulong_roll( rng, FD_REPLAY_TILE_OUT_MAX+1UL );
    FD_TEST( fd_replay_tile_scratch_footprint( out_cnt )==FD_REPLAY_TILE_SCRATCH_FOOTPRINT( out_cnt ) );
  }

  ulong cpu_idx = fd_tile_cpu_id( fd_tile_idx() );
  if( cpu_idx>fd_shmem_cpu_cnt() ) cpu_idx = 0UL;

  char const * _page_sz  = fd_env_strip_cmdline_cstr ( &argc, &argv, "--page-sz",   NULL, "gigantic"                   );
  ulong        page_cnt  = fd_env_strip_cmdline_ulong( &argc, &argv, "--page-cnt",  NULL, 1UL                          );
  ulong        numa_idx  = fd_env_strip_cmdline_ulong( &argc, &argv, "--numa-idx",  NULL, fd_shmem_numa_idx( cpu_idx ) );
  char const * tx_pcap   = fd_env_strip_cmdline_cstr ( &argc, &argv, "--tx-pcap",   NULL, NULL                         );
  ulong        tx_mtu    = fd_env_strip_cmdline_ulong( &argc, &argv, "--tx-mtu",    NULL, 1542UL                       );
  ulong        tx_orig   = fd_env_strip_cmdline_ulong( &argc, &argv, "--tx-orig",   NULL, 0UL                          );
  ulong        tx_depth  = fd_env_strip_cmdline_ulong( &argc, &argv, "--tx-depth",  NULL, 32768UL                      );
  ulong        tx_cr_max = fd_env_strip_cmdline_ulong( &argc, &argv, "--tx-cr-max", NULL, 0UL /* use default */        );
  long         tx_lazy   = fd_env_strip_cmdline_long ( &argc, &argv, "--tx-lazy",   NULL, 0L /* use default */         );
  int          rx_lazy   = fd_env_strip_cmdline_int  ( &argc, &argv, "--rx-lazy",   NULL, 7                            );
  long         duration  = fd_env_strip_cmdline_long ( &argc, &argv, "--duration",  NULL, (long)10e9                   );

  ulong page_sz = fd_cstr_to_shmem_page_sz( _page_sz );
  if( FD_UNLIKELY( !page_sz ) ) FD_LOG_ERR(( "unsupported --page-sz"  ));
  if( FD_UNLIKELY( !tx_pcap ) ) FD_LOG_ERR(( "--tx-pcap not specified" ));

  if( FD_UNLIKELY( fd_tile_cnt()<3UL ) ) FD_LOG_ERR(( "this unit test requires at least 3 tiles" ));

  long  hb0  = fd_tickcount();
  ulong seq0 = fd_rng_ulong( rng );

  test_cfg_t cfg[1];

  FD_LOG_NOTICE(( "Creating workspace (--page-cnt %lu, --page-sz %s, --numa-idx %lu)", page_cnt, _page_sz, numa_idx ));
  cfg->wksp = fd_wksp_new_anonymous( page_sz, page_cnt, fd_shmem_cpu_idx( numa_idx ), "wksp", 0UL );
  FD_TEST( cfg->wksp );

  FD_LOG_NOTICE(( "Creating tx cnc (app_sz 64, type 0, heartbeat0 %li)", hb0 ));
  cfg->tx_cnc = fd_cnc_join( fd_cnc_new( fd_wksp_alloc_laddr( cfg->wksp, fd_cnc_align(), fd_cnc_footprint( 64UL ), 1UL ),
                             64UL, 0UL, hb0 ) );
  FD_TEST( cfg->tx_cnc );

  cfg->tx_pcap = tx_pcap;
  cfg->tx_mtu  = tx_mtu;
  cfg->tx_orig = tx_orig;

  FD_LOG_NOTICE(( "Creating tx mcache (--tx-depth %lu, app_sz 0, seq0 %lu)", tx_depth, seq0 ));
  cfg->tx_mcache = fd_mcache_join( fd_mcache_new( fd_wksp_alloc_laddr( cfg->wksp,
                                                                       fd_mcache_align(), fd_mcache_footprint( tx_depth, 0UL ),
                                                                       1UL ),
                                                  tx_depth, 0UL, seq0 ) );
  FD_TEST( cfg->tx_mcache );

  FD_LOG_NOTICE(( "Creating tx dcache (--tx-mtu %lu, burst 1, compact 1, app_sz 0)", tx_mtu ));
  ulong tx_data_sz = fd_dcache_req_data_sz( tx_mtu, tx_depth, 1UL, 1 ); FD_TEST( tx_data_sz );
  cfg->tx_dcache = fd_dcache_join( fd_dcache_new( fd_wksp_alloc_laddr( cfg->wksp,
                                                                       fd_dcache_align(), fd_dcache_footprint( tx_data_sz, 0UL ),
                                                                       1UL ),
                                                  tx_data_sz, 0UL ) );
  FD_TEST( cfg->tx_dcache );

  cfg->tx_cr_max = tx_cr_max;
  cfg->tx_lazy   = tx_lazy;
  cfg->tx_seed   = rng_seq++;

  FD_LOG_NOTICE(( "Creating rx cnc (app_sz 64, type 1, heartbeat0 %li)", hb0 ));
  cfg->rx_cnc = fd_cnc_join( fd_cnc_new( fd_wksp_alloc_laddr( cfg->wksp, fd_cnc_align(), fd_cnc_footprint( 64UL ), 1UL ),
                                         64UL, 1UL, hb0 ) );
  FD_TEST( cfg->rx_cnc );

  FD_LOG_NOTICE(( "Creating rx fseq (seq0 %lu)", seq0 ));
  cfg->rx_fseq = fd_fseq_join( fd_fseq_new( fd_wksp_alloc_laddr( cfg->wksp, fd_fseq_align(), fd_fseq_footprint(), 1UL ), seq0 ) );
  FD_TEST( cfg->rx_fseq );

  cfg->rx_seed = rng_seq++;
  cfg->rx_lazy = rx_lazy;

  FD_LOG_NOTICE(( "Booting" ));

  fd_tile_exec_t * rx_exec = fd_tile_exec_new( 2UL, rx_tile_main, 0, (char **)fd_type_pun( cfg ) ); FD_TEST( rx_exec );
  fd_tile_exec_t * tx_exec = fd_tile_exec_new( 1UL, tx_tile_main, 0, (char **)fd_type_pun( cfg ) ); FD_TEST( tx_exec );

  FD_TEST( fd_cnc_wait( cfg->tx_cnc, FD_CNC_SIGNAL_BOOT, (long)5e9, NULL )==FD_CNC_SIGNAL_RUN );
  FD_TEST( fd_cnc_wait( cfg->rx_cnc, FD_CNC_SIGNAL_BOOT, (long)5e9, NULL )==FD_CNC_SIGNAL_RUN );

  FD_LOG_NOTICE(( "Running (--duration %li ns, --tx-lazy %li ns, --tx-cr-max %lu, tx_seed %u, --rx-lazy %i)",
                  duration, tx_lazy, tx_cr_max, cfg->tx_seed, rx_lazy ));

  ulong const * tx_cnc_diag = (ulong const *)fd_cnc_app_laddr( cfg->tx_cnc );

  long now  = fd_log_wallclock();
  long next = now;
  long done = now + duration;
  for(;;) {
    long now = fd_log_wallclock();
    if( FD_UNLIKELY( (now-done) >= 0L ) ) {
      FD_LOG_NOTICE(( "pcap replay did not finish before duration" ));
      break;
    }
    if( FD_UNLIKELY( (now-next) >= 0L ) ) {
      FD_COMPILER_MFENCE();
      /* FIXME: add RX_FSEQ / TX_FSEQ / RX_CNC / OTHER TX_CNC stats to
         monitoring, more pretty printing, etc */
      ulong pcap_done = tx_cnc_diag[ FD_REPLAY_CNC_DIAG_PCAP_DONE     ];
      ulong pub_cnt   = tx_cnc_diag[ FD_REPLAY_CNC_DIAG_PCAP_PUB_CNT  ];
      ulong pub_sz    = tx_cnc_diag[ FD_REPLAY_CNC_DIAG_PCAP_PUB_SZ   ];
      ulong filt_cnt  = tx_cnc_diag[ FD_REPLAY_CNC_DIAG_PCAP_FILT_CNT ];
      ulong filt_sz   = tx_cnc_diag[ FD_REPLAY_CNC_DIAG_PCAP_FILT_SZ  ];
      FD_COMPILER_MFENCE();
      FD_LOG_NOTICE(( "monitor\n\t"
                      "tx: pub_cnt %20lu pub_sz %20lu filt_cnt %20lu filt_sz %20lu",
                      pub_cnt, pub_sz, filt_cnt, filt_sz ));
      if( FD_UNLIKELY( pcap_done ) ) {
        FD_LOG_NOTICE(( "pcap replay finished before duration" ));
        break;
      }
      next += (long)1e9;
    }
    FD_YIELD();
  }

  FD_LOG_NOTICE(( "Halting" ));

  FD_TEST( !fd_cnc_open( cfg->tx_cnc ) );
  FD_TEST( !fd_cnc_open( cfg->rx_cnc ) );

  fd_cnc_signal( cfg->tx_cnc, FD_CNC_SIGNAL_HALT );
  fd_cnc_signal( cfg->rx_cnc, FD_CNC_SIGNAL_HALT );

  FD_TEST( fd_cnc_wait( cfg->tx_cnc, FD_CNC_SIGNAL_HALT, (long)5e9, NULL )==FD_CNC_SIGNAL_BOOT );
  FD_TEST( fd_cnc_wait( cfg->rx_cnc, FD_CNC_SIGNAL_HALT, (long)5e9, NULL )==FD_CNC_SIGNAL_BOOT );

  fd_cnc_close( cfg->tx_cnc );
  fd_cnc_close( cfg->rx_cnc );

  int ret;
  FD_TEST( !fd_tile_exec_delete( tx_exec, &ret ) ); FD_TEST( !ret );
  FD_TEST( !fd_tile_exec_delete( rx_exec, &ret ) ); FD_TEST( !ret );

  FD_LOG_NOTICE(( "Cleaning up" ));
  
  fd_wksp_free_laddr( fd_fseq_delete  ( fd_fseq_leave  ( cfg->rx_fseq   ) ) );
  fd_wksp_free_laddr( fd_cnc_delete   ( fd_cnc_leave   ( cfg->rx_cnc    ) ) );
  fd_wksp_free_laddr( fd_dcache_delete( fd_dcache_leave( cfg->tx_dcache ) ) );
  fd_wksp_free_laddr( fd_mcache_delete( fd_mcache_leave( cfg->tx_mcache ) ) );
  fd_wksp_free_laddr( fd_cnc_delete   ( fd_cnc_leave   ( cfg->tx_cnc    ) ) );

  fd_wksp_delete_anonymous( cfg->wksp );

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
  FD_LOG_WARNING(( "skip: unit test requires FD_HAS_HOSTED capabilities" ));
  fd_halt();
  return 0;
}

#endif

