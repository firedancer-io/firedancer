#include "../../util/fd_util.h"

#if FD_HAS_HOSTED && FD_HAS_X86 && FD_HAS_OPENSSL

#include "fd_quic.h"
#include "../../tango/xdp/fd_xdp.h"
#include "../../util/net/fd_eth.h"
#include "../../util/net/fd_ip4.h"
#include "../../ballet/base58/fd_base58.h"
#include "../../ballet/txn/fd_txn.h"

FD_STATIC_ASSERT( FD_QUIC_CNC_DIAG_CHUNK_IDX        ==2UL, unit_test );
FD_STATIC_ASSERT( FD_QUIC_CNC_DIAG_TPU_PUB_CNT      ==3UL, unit_test );
FD_STATIC_ASSERT( FD_QUIC_CNC_DIAG_TPU_PUB_SZ       ==4UL, unit_test );
FD_STATIC_ASSERT( FD_QUIC_CNC_DIAG_TPU_CONN_LIVE_CNT==5UL, uint_test );

FD_STATIC_ASSERT( FD_QUIC_TILE_SCRATCH_ALIGN==128UL, unit_test );

struct test_cfg {
  fd_wksp_t * wksp;

  fd_xsk_t *     xsk;
  fd_xsk_aio_t * xsk_aio;

  fd_cnc_t *         tx_cnc;
  ulong              tx_mtu;
  ulong              tx_orig;
  fd_frag_meta_t *   tx_mcache;
  uchar *            tx_dcache;
  long               tx_lazy;
  uint               tx_seed;
  fd_quic_t *        tx_quic;
  fd_quic_config_t * tx_quic_cfg;

  fd_cnc_t *       rx_cnc;
  ulong *          rx_fseq;
  int              rx_lazy;
  uint             rx_seed;
};

typedef struct test_cfg test_cfg_t;

/* RX tile ************************************************************/

static int
rx_tile_main( int     argc,
              char ** argv ) {
  (void)argc;
  test_cfg_t * cfg = (test_cfg_t *)argv;

  fd_wksp_t * wksp = cfg->wksp;

  /* Hook up to rx cnc */
  fd_cnc_t * cnc = cfg->rx_cnc;

  /* Hook up to tx mcache */
  fd_frag_meta_t const * mcache = cfg->tx_mcache;
  ulong                  depth  = fd_mcache_depth( mcache );
  ulong const *          sync   = fd_mcache_seq_laddr_const( mcache );
  ulong                  seq    = fd_mcache_seq_query( sync );

  /* Hook up to rx seq report */
  ulong * fseq = cfg->rx_fseq;

  /* Hook up to the random number generator */
  fd_rng_t _rng[1];
  fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, cfg->rx_seed, 0UL ) );

  /* Configure housekeeping */
  ulong async_min = 1UL << cfg->rx_lazy;
  ulong async_rem = 1UL; /* Do housekeeping on first iteration */

  ulong txn_idx = 0UL;

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

    /* Check that we weren't overrun while polling */
    if( FD_UNLIKELY( diff ) ) { /* caught up or overrun, optimize for expected sequence number ready */
      if( FD_LIKELY( diff < 0L ) ) {
        FD_SPIN_PAUSE();
        continue;
      }
      seq = seq_found;
      /* can keep processing from the new seq */
      /* TODO make QUIC tile respect backpressure instead? */
    }

    /* Process the received txn */

    uchar const * p = (uchar const *)fd_chunk_to_laddr_const( wksp, chunk );
    (void)ctl; (void)sig; (void)tsorig; (void)tspub;

    static FD_TLS fd_txn_parse_counters_t txn_parse_counters = {0};
    uchar __attribute__((aligned(alignof(fd_txn_t)))) txn_buf[ FD_TXN_MAX_SZ ];
    fd_txn_t * txn = NULL;
    if( FD_LIKELY( fd_txn_parse( p, sz, txn_buf, &txn_parse_counters ) ) )
      txn = (fd_txn_t *)txn_buf;

    char txn_sig_cstr[ FD_BASE58_ENCODED_32_SZ ];
    txn_sig_cstr[ 0 ] = '\0';

    if( FD_LIKELY( txn ) ) {
      uchar const * txn_sig = fd_txn_get_signatures( txn, p )[0];
      fd_base58_encode_32( txn_sig, NULL, txn_sig_cstr );
    }

    /* Check that we weren't overrun while processing */

    seq_found = fd_frag_meta_seq_query( mline );
    if( FD_UNLIKELY( fd_seq_ne( seq_found, seq ) ) )
      continue;

    /* Wind up for the next iteration */
    seq = fd_seq_inc( seq, 1UL );

    /* Check for corruption */

    if( FD_UNLIKELY( !txn ) ) {
      FD_LOG_WARNING(( "Received invalid txn from QUIC" ));
      continue;
    }

    /* Print txn sig to user */

    FD_LOG_NOTICE(( "Received txn no=%lu sig=%s", ++txn_idx, txn_sig_cstr ));
  }

  fd_cnc_signal( cnc, FD_CNC_SIGNAL_BOOT );
  return 0;
}

/* QUIC tile **********************************************************/

static int
tx_tile_main( int     argc,
                char ** argv ) {
  (void)argc;
  test_cfg_t * cfg = (test_cfg_t *)argv;

  fd_rng_t _rng[1];
  fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, cfg->tx_seed, 0UL ) );

  ulong scratch_footprint = fd_quic_tile_scratch_footprint( fd_mcache_depth( cfg->tx_mcache ) );
  void * scratch = fd_alloca( FD_QUIC_TILE_SCRATCH_ALIGN, scratch_footprint );
  FD_TEST( scratch );

  FD_TEST( !fd_quic_tile(
      cfg->tx_cnc,
      cfg->tx_orig,
      cfg->tx_quic,
      cfg->xsk_aio,
      cfg->tx_mcache,
      cfg->tx_dcache,
      cfg->tx_lazy,
      rng,
      scratch ) );

  fd_rng_delete( fd_rng_leave( rng ) );
  return 0;
}

/* MAIN tile **********************************************************/

int main( int     argc,
          char ** argv ) {
  fd_boot( &argc, &argv );

  uint rng_seq = 0U;
  fd_rng_t _rng[1]; fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, rng_seq++, 0UL ) );

  FD_TEST( fd_quic_tile_scratch_align()==FD_QUIC_TILE_SCRATCH_ALIGN );

  ulong cpu_idx = fd_tile_cpu_id( fd_tile_idx() );
  if( cpu_idx>fd_shmem_cpu_cnt() ) cpu_idx = 0UL;

  ulong        tx_mtu       =       fd_env_strip_cmdline_ulong ( &argc, &argv, "--tx-mtu",         NULL, FD_TPU_MTU                   );
  ulong        tx_orig      =       fd_env_strip_cmdline_ulong ( &argc, &argv, "--tx-orig",        NULL, 0UL                          );
  ulong        tx_depth     =       fd_env_strip_cmdline_ulong ( &argc, &argv, "--tx-depth",       NULL, 32768UL                      );
  char const * _page_sz     =       fd_env_strip_cmdline_cstr  ( &argc, &argv, "--page-sz",        NULL, "gigantic"                   );
  ulong        page_cnt     =       fd_env_strip_cmdline_ulong ( &argc, &argv, "--page-cnt",       NULL, 1UL                          );
  ulong        numa_idx     =       fd_env_strip_cmdline_ulong ( &argc, &argv, "--numa-idx",       NULL, fd_shmem_numa_idx( cpu_idx ) );
  long         tx_lazy      =       fd_env_strip_cmdline_long  ( &argc, &argv, "--tx-lazy",        NULL, 0L /* use default */         );
  int          rx_lazy      =       fd_env_strip_cmdline_int   ( &argc, &argv, "--rx-lazy",        NULL, 7                            );
  long         duration     = (long)fd_env_strip_cmdline_double( &argc, &argv, "--duration",       NULL, (long)10e9                   );
  ulong        xdp_mtu      =       fd_env_strip_cmdline_ulong ( &argc, &argv, "--xdp-mtu",        NULL, 2048UL                       );
  ulong        xdp_depth    =       fd_env_strip_cmdline_ulong ( &argc, &argv, "--xdp-depth",      NULL, 1024UL                       );
  char const * iface        =       fd_env_strip_cmdline_cstr  ( &argc, &argv, "--iface",          NULL, NULL                         );
  uint         ifqueue      =       fd_env_strip_cmdline_uint  ( &argc, &argv, "--ifqueue",        NULL, 0U                           );
  char const * _listen_addr =       fd_env_strip_cmdline_cstr  ( &argc, &argv, "--listen",         NULL, NULL                         );
  uint         udp_port     =       fd_env_strip_cmdline_uint  ( &argc, &argv, "--port",           NULL, 8080U                        );
  char const * _hwaddr      =       fd_env_strip_cmdline_cstr  ( &argc, &argv, "--hwaddr",         NULL, NULL                         );
  char const * _gateway     =       fd_env_strip_cmdline_cstr  ( &argc, &argv, "--gateway",        NULL, NULL                         );

  char const * app_name = "test_quic";

  ulong page_sz = fd_cstr_to_shmem_page_sz( _page_sz );
  if( FD_UNLIKELY( !page_sz ) )
    FD_LOG_ERR(( "unsupported --page-sz"  ));

  if( FD_UNLIKELY( fd_tile_cnt()<3UL ) )
    FD_LOG_ERR(( "this unit test requires at least 3 tiles" ));

  if( FD_UNLIKELY( !iface ) )
    FD_LOG_ERR(( "missing --iface" ));

  if( FD_UNLIKELY( !_listen_addr ) )
    FD_LOG_ERR(( "missing --listen" ));
  uint listen_addr;
  if( FD_UNLIKELY( !fd_cstr_to_ip4_addr( _listen_addr, &listen_addr ) ) )
    FD_LOG_ERR(( "invalid IPv4 address \"%s\"", _listen_addr ));

  if( FD_UNLIKELY( udp_port<=0 || udp_port>USHORT_MAX ) )
    FD_LOG_ERR(( "invalid UDP port %d", udp_port ));

  if( FD_UNLIKELY( !_hwaddr  ) ) FD_LOG_ERR(( "missing --hwaddr" ));
  uchar hwaddr[ 6 ]={0};
  if( FD_UNLIKELY( !fd_cstr_to_mac_addr( _hwaddr,  hwaddr  ) ) )
    FD_LOG_ERR(( "invalid hwaddr \"%s\"",  _hwaddr  ));

  if( FD_UNLIKELY( !_gateway ) ) FD_LOG_ERR(( "missing --gateway" ));
  uchar gateway[ 6 ]={0};
  if( FD_UNLIKELY( !fd_cstr_to_mac_addr( _gateway, gateway ) ) )
    FD_LOG_ERR(( "invalid gateway \"%s\"", _gateway ));

  fd_quic_limits_t quic_limits = {0};
  if( FD_UNLIKELY( !fd_quic_limits_from_env( &argc, &argv, &quic_limits  ) ) )
    FD_LOG_ERR(( "invalid QUIC limits" ));

  long  hb0  = fd_tickcount();
  ulong seq0 = fd_rng_ulong( rng );

  test_cfg_t cfg[1];
  memset( cfg, 0, sizeof(test_cfg_t) );

  FD_LOG_NOTICE(( "Creating workspace (--page-cnt %lu, --page-sz %s, --numa-idx %lu)", page_cnt, _page_sz, numa_idx ));
  cfg->wksp = fd_wksp_new_anonymous( page_sz, page_cnt, fd_shmem_cpu_idx( numa_idx ), "wksp", 0UL );
  FD_TEST( cfg->wksp );

  FD_LOG_NOTICE(( "Creating tx cnc (app_sz 64, type 0, heartbeat0 %li)", hb0 ));
  cfg->tx_cnc = fd_cnc_join( fd_cnc_new( fd_wksp_alloc_laddr( cfg->wksp, fd_cnc_align(), fd_cnc_footprint( 64UL ), 1UL ),
                             64UL, 0UL, hb0 ) );
  FD_TEST( cfg->tx_cnc );

  cfg->tx_mtu  = tx_mtu;
  cfg->tx_orig = tx_orig;

  FD_LOG_NOTICE(( "Creating tx mcache (--tx-depth %lu, app_sz 0, seq0 %lu)", tx_depth, seq0 ));
  cfg->tx_mcache = fd_mcache_join( fd_mcache_new( fd_wksp_alloc_laddr( cfg->wksp,
                                                                       fd_mcache_align(), fd_mcache_footprint( tx_depth, 0UL ),
                                                                       1UL ),
                                                  tx_depth, 0UL, seq0 ) );
  FD_TEST( cfg->tx_mcache );

  FD_LOG_NOTICE(( "Creating tx dcache (--tx-mtu %lu, burst 1, compact 1, app_sz 0)", tx_mtu ));
  ulong tx_app_sz  = fd_quic_dcache_app_footprint( tx_depth );
  ulong tx_data_sz = fd_dcache_req_data_sz( tx_mtu, tx_depth, 1UL, 1 ); FD_TEST( tx_data_sz );
  cfg->tx_dcache = fd_dcache_join( fd_dcache_new( fd_wksp_alloc_laddr( cfg->wksp,
                                                                       fd_dcache_align(), fd_dcache_footprint( tx_data_sz, 0UL ),
                                                                       1UL ),
                                                  tx_data_sz, tx_app_sz ) );
  FD_TEST( cfg->tx_dcache );

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

  FD_LOG_NOTICE(( "Creating xsk (depth %lu)", xdp_depth ));
  ulong xsk_footprint = fd_xsk_footprint( xdp_mtu, xdp_depth, xdp_depth, xdp_depth, xdp_depth );
  void * shxsk = fd_xsk_new( fd_wksp_alloc_laddr( cfg->wksp, fd_xsk_align(), xsk_footprint, 1UL ),
                              xdp_mtu, xdp_depth, xdp_depth, xdp_depth, xdp_depth );
  FD_TEST( shxsk );

  FD_LOG_NOTICE(( "Binding xsk (iface %s ifqueue %u)", iface, ifqueue ));
  FD_TEST( fd_xsk_bind( shxsk, app_name, iface, ifqueue ) );

  FD_LOG_NOTICE(( "Listening on " FD_IP4_ADDR_FMT ":%u",
                  FD_IP4_ADDR_FMT_ARGS( listen_addr ), udp_port ));
  FD_TEST( 0==fd_xdp_listen_udp_port( app_name, listen_addr, udp_port, 0U ) );

  FD_LOG_NOTICE(( "Joining xsk" ));
  cfg->xsk = fd_xsk_join( shxsk );
  FD_TEST( cfg->xsk );

  FD_LOG_NOTICE(( "Creating xsk_aio" ));
  ulong xsk_aio_footprint = fd_xsk_aio_footprint( xdp_depth, xdp_depth );
  cfg->xsk_aio = fd_xsk_aio_join( fd_xsk_aio_new( fd_wksp_alloc_laddr( cfg->wksp, fd_xsk_aio_align(), xsk_aio_footprint, 1UL ),
                                                  xdp_depth, xdp_depth ),
                                  cfg->xsk );
  FD_TEST( cfg->xsk_aio );

  FD_LOG_NOTICE(( "Creating QUIC" ));
  ulong quic_footprint = fd_quic_footprint( &quic_limits );
  FD_LOG_NOTICE(( "QUIC footprint: %lu KiB", quic_footprint/1024UL ));
  cfg->tx_quic = fd_quic_new(
    fd_wksp_alloc_laddr( cfg->wksp, fd_quic_align(), quic_footprint, 1UL ),
    &quic_limits );
  FD_TEST( cfg->tx_quic );

  FD_LOG_NOTICE(( "Configuring QUIC "));
  fd_quic_config_t * quic_cfg = fd_quic_get_config( cfg->tx_quic );
  FD_TEST( quic_cfg );

  FD_TEST( fd_quic_config_from_env( &argc, &argv, quic_cfg ) );

  quic_cfg->role = FD_QUIC_ROLE_SERVER;

  strcpy( quic_cfg->sni, "test_quic_tile" );
  quic_cfg->net.ip_addr         = (uint)listen_addr;
  quic_cfg->net.listen_udp_port = (ushort)udp_port;

  memcpy( quic_cfg->link.src_mac_addr, hwaddr,  6UL );
  memcpy( quic_cfg->link.dst_mac_addr, gateway, 6UL );

  fd_aio_t _aio_rx[1];
  fd_quic_set_aio_net_tx( cfg->tx_quic, fd_xsk_aio_get_tx     ( cfg->xsk_aio ) );
  fd_xsk_aio_set_rx     ( cfg->xsk_aio, fd_quic_get_aio_net_rx( cfg->tx_quic, _aio_rx ) );

  FD_LOG_NOTICE(( "Joining QUIC" ));
  FD_TEST( fd_quic_join( cfg->tx_quic ) );

  FD_LOG_NOTICE(( "Booting" ));

  fd_tile_exec_t * rx_exec = fd_tile_exec_new( 2UL, rx_tile_main, 0, (char **)fd_type_pun( cfg ) ); FD_TEST( rx_exec );
  fd_tile_exec_t * tx_exec = fd_tile_exec_new( 1UL, tx_tile_main, 0, (char **)fd_type_pun( cfg ) ); FD_TEST( tx_exec );

  FD_TEST( fd_cnc_wait( cfg->tx_cnc, FD_CNC_SIGNAL_BOOT, (long)5e9, NULL )==FD_CNC_SIGNAL_RUN );
  FD_TEST( fd_cnc_wait( cfg->rx_cnc, FD_CNC_SIGNAL_BOOT, (long)5e9, NULL )==FD_CNC_SIGNAL_RUN );

  FD_LOG_NOTICE(( "Running (--duration %li ns, --tx-lazy %li ns, tx_seed %u, --rx-lazy %i)",
                  duration, tx_lazy, cfg->tx_seed, rx_lazy ));

  ulong const * tx_cnc_diag = (ulong const *)fd_cnc_app_laddr( cfg->tx_cnc );

  long now  = fd_log_wallclock();
  long next = now;
  long done = now + duration;
  for(;;) {
    long now = fd_log_wallclock();
    if( FD_UNLIKELY( (now-done) >= 0L ) ) {
      FD_LOG_NOTICE(( "test duration finished" ));
      break;
    }
    if( FD_UNLIKELY( (now-next) >= 0L ) ) {
      FD_COMPILER_MFENCE();
      /* FIXME: add RX_FSEQ / TX_FSEQ / RX_CNC / OTHER TX_CNC stats to
         monitoring, more pretty printing, etc */
      ulong pub_cnt   = tx_cnc_diag[ FD_QUIC_CNC_DIAG_TPU_PUB_CNT  ];
      ulong pub_sz    = tx_cnc_diag[ FD_QUIC_CNC_DIAG_TPU_PUB_SZ   ];
      FD_COMPILER_MFENCE();
      //FD_LOG_NOTICE(( "monitor\n\t"
      //                "tx: pub_cnt %20lu pub_sz %20lu",
      //                pub_cnt, pub_sz ));
      (void)pub_sz; (void)pub_cnt;
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

  int ret;
  FD_TEST( !fd_tile_exec_delete( tx_exec, &ret ) ); FD_TEST( !ret );
  FD_TEST( !fd_tile_exec_delete( rx_exec, &ret ) ); FD_TEST( !ret );

  FD_LOG_NOTICE(( "Cleaning up" ));

  FD_TEST( 0==fd_xdp_release_udp_port( app_name, (uint)listen_addr, udp_port ) );

  fd_wksp_free_laddr( (void *)cfg->tx_quic_cfg                                );
  fd_wksp_free_laddr( fd_quic_delete   (    (fd_quic_t *)( cfg->tx_quic   ) ) );
  fd_wksp_free_laddr( fd_xsk_aio_delete( fd_xsk_aio_leave( cfg->xsk_aio   ) ) );
  fd_wksp_free_laddr( fd_xsk_delete    ( fd_xsk_leave    ( cfg->xsk       ) ) );
  fd_wksp_free_laddr( fd_fseq_delete   ( fd_fseq_leave   ( cfg->rx_fseq   ) ) );
  fd_wksp_free_laddr( fd_cnc_delete    ( fd_cnc_leave    ( cfg->rx_cnc    ) ) );
  fd_wksp_free_laddr( fd_dcache_delete ( fd_dcache_leave ( cfg->tx_dcache ) ) );
  fd_wksp_free_laddr( fd_mcache_delete ( fd_mcache_leave ( cfg->tx_mcache ) ) );
  fd_wksp_free_laddr( fd_cnc_delete    ( fd_cnc_leave    ( cfg->tx_cnc    ) ) );

  fd_wksp_delete_anonymous( cfg->wksp );

  fd_rng_delete( fd_rng_leave( rng ) );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}

#else /* FD_HAS_HOSTED && FD_HAS_X86 */

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );
  FD_LOG_WARNING(( "skip: unit test requires FD_HAS_HOSTED, FD_HAS_X86, FD_HAS_OPENSSL capabilities" ));
  fd_halt();
  return 0;
}

#endif /* FD_HAS_HOSTED && FD_HAS_X86 && FD_HAS_OPENSSL */
