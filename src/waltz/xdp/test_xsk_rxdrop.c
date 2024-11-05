#include "fd_xsk.h"
#include "fd_xsk_aio.h"
#include "fd_xdp_redirect_user.h"
#include "../../util/fd_util.h"
#include "../../util/net/fd_ip4.h"
#include "../../tango/cnc/fd_cnc.h"
#include "../../tango/tempo/fd_tempo.h"

#include <assert.h>  /* assert */
#include <errno.h>   /* errno */
#include <signal.h>  /* signal */
#include <stdio.h>   /* fopen */
#include <unistd.h>  /* close */

#include <sys/types.h>
#include <sys/socket.h>     /* socket */
#include <sys/ioctl.h>      /* ioctl */
#include <net/if.h>         /* struct ifreq */
#include <netinet/in.h>     /* struct sockaddr_in */
#include <linux/ethtool.h>  /* ETHTOOL_GCHANNELS */
#include <linux/sockios.h>  /* SIOCETHTOOL */
#include <linux/if.h>       /* struct ifreq */
#include <linux/if_xdp.h>   /* XDP_ZEROCOPY */

static char const help_str[] =
  "\n"
  "test_xsk_rxdrop counts incoming AF_XDP traffic.\n"
  "\n"
  "This tool is usually used to benchmark the fd_xsk receive path\n"
  "with the help of an external packet generator.\n"
  "\n"
  "Tile 0 prints statistics to the command line.\n"
  "Each other tile handles one AF_XDP RX queue.\n"
  "`ethtool -l <interface>` displays the number of queues.\n"
  "\n"
  "Usage: fd_xsk_rxdrop [args...]\n"
  "\n"
  "  --iface      Name of network device to attach to\n"
  "  --addr       IPv4 listen address.  Defaults to first IPv4 address\n"
  "  --port       UDP port to listen on\n"
  "  --xdp-mode   XDP mode (skb/drv/hw)\n"
  "  --xsk-mode   AF_XDP bind mode (copy/zerocopy)\n"
  "\n"
  "  --rx-cnt     Number of RX tiles\n"
  "  --tile-cpus  Tile index to CPU mapping\n"
  "  --page-sz    Workspace page size (gigantic/huge/normal)\n"
  "  --numa-idx   Workspace NUMA index (default is local to tile 0)\n"
  "\n";

#define MAX_QUEUES_PER_TILE (16u)

static uint
get_first_ip4_addr( char const * iface ) {
  struct ifreq ifr = {0};
  strncpy( ifr.ifr_name, iface, IFNAMSIZ );
  ifr.ifr_addr.sa_family = AF_INET;

  int fd        = socket( AF_INET, SOCK_DGRAM, 0 );
  int ioctl_res = ioctl( fd, SIOCGIFADDR, &ifr );
  int ioctl_err = errno;
  close( fd );

  if( ioctl_res!=0 ) {
    FD_LOG_ERR(( "Failed to detect IPv4 address of interface: ioctl(SIOCGIFADDR) failed (%d-%s)",
                 ioctl_err, fd_io_strerror( ioctl_err ) ));
  }

  struct sockaddr_in * sin = fd_type_pun( &ifr.ifr_addr );
  return sin->sin_addr.s_addr;
}

static uint
get_rx_queue_cnt( char const * iface ) {

  struct ethtool_channels channels = {0};
  channels.cmd = ETHTOOL_GCHANNELS;

  struct ifreq ifr = {0};
  strncpy( ifr.ifr_name, iface, IF_NAMESIZE );
  ifr.ifr_data = fd_type_pun( &channels );

  int fd        = socket( AF_INET, SOCK_DGRAM, 0 );
  int ioctl_res = ioctl( fd, SIOCETHTOOL, &ifr );
  int ioctl_err = errno;
  close( fd );

  if( ioctl_res!=0 ) {
    if( ioctl_err == EOPNOTSUPP ) return 1;
    FD_LOG_ERR(( "ioctl(ETHTOOL_GCHANNELS) failed (%d-%s)",
                 ioctl_err, fd_io_strerror( ioctl_err ) ));
  }

  return fd_uint_max( channels.rx_count, channels.combined_count );
}

static int
get_net_numa_idx( char const * iface ) {

  char path[ PATH_MAX ];
  assert( fd_cstr_printf_check( path, sizeof(path), NULL, "/sys/class/net/%s/device/numa_node", iface ) );

  FILE * file = fopen( path, "r" );
  if( FD_UNLIKELY( !file ) ) {
    if( errno == ENOENT ) return 0;
    FD_LOG_ERR(( "fopen(%s) failed (%d-%s)", path, errno, fd_io_strerror( errno ) ));
  }

  int numa_idx;
  if( FD_UNLIKELY( 1!=fscanf( file, "%d", &numa_idx ) ) ) {
    int err = feof( file ) ? -1 : ferror( file );
    FD_LOG_ERR(( "fscanf(%s) failed (%d-%s)", path, err, fd_io_strerror( err ) ));
  }

  fclose( file );
  return numa_idx;
}

static volatile int rxdrop_shutdown;

static void
rxdrop_stop( int sig ) {
  (void)sig;
  rxdrop_shutdown = 1;
}

struct fd_rxdrop_src_cfg {
  uint if_queue;
};

typedef struct fd_rxdrop_src_cfg fd_rxdrop_src_cfg_t;

struct fd_rxdrop_tile_cfg {
  fd_rxdrop_src_cfg_t src_cfg[ MAX_QUEUES_PER_TILE ];
  uint                src_cnt;
  fd_tile_exec_t *    exec;
  char *              argv[2];
  void *              cnc_mem;
};

typedef struct fd_rxdrop_tile_cfg fd_rxdrop_tile_cfg_t;

struct fd_rxdrop_cfg {
  fd_wksp_t * wksp;

  uint if_idx;
  int  xsk_map_fd;
  uint bind_flags;

  ulong frame_sz;
  ulong fr_depth;
  ulong rx_depth;
  ulong tx_depth;
  ulong cr_depth;
  ulong aio_depth;
};

typedef struct fd_rxdrop_cfg fd_rxdrop_cfg_t;

struct fd_rxdrop_metrics {
  ulong pkt_cnt;
};

typedef struct fd_rxdrop_metrics fd_rxdrop_metrics_t;

struct fd_rxdrop_cnc_app {
  ulong pkt_cnt;
};

typedef struct fd_rxdrop_cnc_app fd_rxdrop_cnc_app_t;

static int
rxdrop_aio_send( void *                    ctx,
                 fd_aio_pkt_info_t const * batch,
                 ulong                     batch_cnt,
                 ulong *                   opt_batch_idx,
                 int                       flush ) {
  (void)batch; (void)opt_batch_idx; (void)flush;
  fd_rxdrop_metrics_t * metrics = ctx;
  metrics->pkt_cnt += batch_cnt;
  return 0;
}

static int
rxdrop_tile( int     argc,
             char ** argv ) {
  (void)argc;
  fd_rxdrop_cfg_t *      cfg      = fd_type_pun( argv[0] );
  fd_rxdrop_tile_cfg_t * tile_cfg = fd_type_pun( argv[1] );
  fd_wksp_t *            wksp     = cfg->wksp;
  fd_cnc_t *             cnc      = fd_cnc_join( tile_cfg->cnc_mem );

  fd_rxdrop_cnc_app_t volatile * cnc_app    = fd_cnc_app_laddr( cnc );
  fd_rxdrop_metrics_t            metrics[1] = {{0}};

  /* Initialize */

  fd_rng_t _rng[1];
  fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, (uint)fd_tickcount() * (uint)fd_tile_idx(), 0UL ) );

  uint   src_cnt   = tile_cfg->src_cnt;
  ulong  frame_sz  = cfg->frame_sz;
  ulong  fr_depth  = cfg->fr_depth;
  ulong  rx_depth  = cfg->rx_depth;
  ulong  tx_depth  = cfg->tx_depth;
  ulong  cr_depth  = cfg->cr_depth;
  ulong  aio_depth = cfg->aio_depth;

  ulong xsk_footprint = fd_xsk_footprint( frame_sz, fr_depth, rx_depth, tx_depth, cr_depth );
  ulong aio_footprint = fd_xsk_aio_footprint( tx_depth, aio_depth );

  fd_aio_t _aio[1];
  fd_aio_t * aio = fd_aio_join( fd_aio_new( _aio, metrics, rxdrop_aio_send ) );
  FD_TEST( aio );

  struct src {
    fd_xsk_t *     xsk;
    fd_xsk_aio_t * xsk_aio;
  };
  struct src src_list[ MAX_QUEUES_PER_TILE ] = {0};

  for( uint src_idx=0U; src_idx<src_cnt; src_idx++ ) {
    fd_rxdrop_src_cfg_t * src_cfg = tile_cfg->src_cfg + src_idx;
    struct src *          src     = src_list          + src_idx;

    uint   if_queue = src_cfg->if_queue;
    void * xsk_mem  = fd_wksp_alloc_laddr( wksp, fd_xsk_align(),     xsk_footprint, 1UL );
    void * aio_mem  = fd_wksp_alloc_laddr( wksp, fd_xsk_aio_align(), aio_footprint, 1UL );

    src->xsk = fd_xsk_join( fd_xsk_new( xsk_mem, frame_sz, fr_depth, rx_depth, tx_depth, cr_depth ) );
    if( FD_UNLIKELY( !src->xsk ) ) FD_LOG_ERR(( "fd_xsk_new failed" ));

    if( FD_UNLIKELY( !fd_xsk_init( src->xsk, cfg->if_idx, if_queue, cfg->bind_flags ) ) ) {
      FD_LOG_ERR(( "fd_xsk_init failed" ));
    }

    if( FD_UNLIKELY( !fd_xsk_activate( src->xsk, cfg->xsk_map_fd ) ) ) {
      FD_LOG_ERR(( "fd_xsk_activate failed" ));
    }

    src->xsk_aio = fd_xsk_aio_join( fd_xsk_aio_new( aio_mem, tx_depth, aio_depth ), src->xsk );
    if( FD_UNLIKELY( !src->xsk_aio ) ) FD_LOG_ERR(( "fd_xsk_aio_new failed" ));

    fd_xsk_aio_set_rx( src->xsk_aio, aio );
  }

  /* Configure housekeeping */
  float tick_per_ns = (float)fd_tempo_tick_per_ns( NULL );
  long  lazy        = 1e6;  /* 1ms */
  ulong async_min   = fd_tempo_async_min( lazy, 1UL, tick_per_ns );

  long  now  = fd_tickcount();
  long  then = now;            /* Do housekeeping on first iteration of run loop */

  /* Run loop */

  fd_cnc_signal( cnc, FD_CNC_SIGNAL_RUN  );
  uint src_idx = 0U;
  for(;;) {
    /* Do housekeeping at a low rate in the background */

    if( FD_UNLIKELY( (now-then)>=0L ) ) {
      fd_cnc_heartbeat( cnc, now );

      ulong s = fd_cnc_signal_query( cnc );
      if( FD_UNLIKELY( s!=FD_CNC_SIGNAL_RUN ) ) {
        if( FD_LIKELY( s==FD_CNC_SIGNAL_HALT ) ) break;
        char buf[ FD_CNC_SIGNAL_CSTR_BUF_MAX ];
        FD_LOG_ERR(( "Unexpected signal: %lu-%s", s, fd_cnc_signal_cstr( s, buf ) ));
      }

      cnc_app->pkt_cnt += metrics->pkt_cnt;
      metrics->pkt_cnt  = 0UL;

      /* Reload housekeeping timer */
      then = now + (long)fd_tempo_async_reload( rng, async_min );
    }

    fd_xsk_aio_t * xsk_aio = src_list[ src_idx ].xsk_aio;
    fd_xsk_aio_service( xsk_aio );

    /* Wind up for the next iteration */

    now = fd_tickcount();
    src_idx++;
    src_idx = fd_uint_if( src_idx>=src_cnt, 0U, src_idx );
  }

  /* Shut down */

  fd_cnc_signal( cnc, FD_CNC_SIGNAL_BOOT );
  fd_aio_delete( fd_aio_leave( aio ) );

  for( uint src_idx=0U; src_idx<src_cnt; src_idx++ ) {
    struct src * src = src_list + src_idx;
    if( FD_UNLIKELY( !fd_xsk_deactivate( src->xsk, cfg->xsk_map_fd ) ) ) {
      FD_LOG_WARNING(( "fd_xsk_deactivate failed" ));
    }
    fd_wksp_free_laddr( fd_xsk_aio_delete( fd_xsk_aio_leave( src->xsk_aio ) ) );
    fd_wksp_free_laddr( fd_xsk_delete    ( fd_xsk_leave    ( src->xsk     ) ) );
  }

  fd_rng_delete( fd_rng_leave( rng ) );

  return 0;
}

int
main( int     argc,
      char ** argv ) {

  for( int i=0; i<argc; i++ ) {
    if( strcmp( argv[i], "--help" ) == 0 ) {
      puts( help_str );
      return 0;
    }
  }

  fd_boot( &argc, &argv );

  ulong cpu_idx = fd_tile_cpu_id( fd_tile_idx() );
  if( cpu_idx>fd_shmem_cpu_cnt() ) cpu_idx = 0UL;
  ulong cpu_numa_idx = fd_shmem_numa_idx( cpu_idx );

  char const * _page_sz    = fd_env_strip_cmdline_cstr  ( &argc, &argv, "--page-sz",   NULL, "gigantic"   );
  ulong        page_cnt    = fd_env_strip_cmdline_ulong ( &argc, &argv, "--page-cnt",  NULL, 1UL          );
  ulong        numa_idx    = fd_env_strip_cmdline_ulong ( &argc, &argv, "--numa-idx",  NULL, cpu_numa_idx );
  char const * iface       = fd_env_strip_cmdline_cstr  ( &argc, &argv, "--iface",     NULL, NULL         );
  char const * ip4_cstr    = fd_env_strip_cmdline_cstr  ( &argc, &argv, "--addr",      NULL, NULL         );
  uint         port        = fd_env_strip_cmdline_ushort( &argc, &argv, "--port",      NULL, 0            );
  uint         rx_tile_cnt = fd_env_strip_cmdline_uint  ( &argc, &argv, "--rx-cnt",    NULL, 1U           );
  char const * xdp_mode    = fd_env_strip_cmdline_cstr  ( &argc, &argv, "--xdp-mode",  NULL, NULL         );
  char const * xsk_mode    = fd_env_strip_cmdline_cstr  ( &argc, &argv, "--xsk-mode",  NULL, NULL         );
  ulong        frame_sz    = fd_env_strip_cmdline_ulong ( &argc, &argv, "--frame-sz",  NULL, 2048UL       );
  ulong        fr_depth    = fd_env_strip_cmdline_ulong ( &argc, &argv, "--fr-depth",  NULL, 1024UL       );
  ulong        rx_depth    = fd_env_strip_cmdline_ulong ( &argc, &argv, "--rx-depth",  NULL, 1024UL       );
  ulong        tx_depth    = fd_env_strip_cmdline_ulong ( &argc, &argv, "--tx-depth",  NULL, 1024UL       );
  ulong        cr_depth    = fd_env_strip_cmdline_ulong ( &argc, &argv, "--cr-depth",  NULL, 1024UL       );
  ulong        aio_depth   = fd_env_strip_cmdline_ulong ( &argc, &argv, "--aio-depth", NULL, 1024UL       );

  /* Validate command-line args */

  if( FD_UNLIKELY( !iface ) ) FD_LOG_ERR(( "Missing --iface" ));
  if( FD_UNLIKELY( !port  ) ) FD_LOG_ERR(( "Missing --port"  ));

  if( FD_UNLIKELY( fd_tile_cnt()<2 ) ) FD_LOG_ERR(( "test_xsk_rxdrop requires at least 2 tiles" ));

  uint ip4_addr;
  if( ip4_cstr ) {
    if( FD_UNLIKELY( !fd_cstr_to_ip4_addr( ip4_cstr, &ip4_addr ) ) ) {
      FD_LOG_ERR(( "Invalid IPv4 address: %s", ip4_cstr ));
    }
  } else {
    ip4_addr = get_first_ip4_addr( iface );
  }

  if( FD_UNLIKELY( !fd_ulong_is_pow2( fr_depth ) ) ) FD_LOG_ERR(( "invalid --fr-depth (must be a power of 2)" ));
  if( FD_UNLIKELY( !fd_ulong_is_pow2( rx_depth ) ) ) FD_LOG_ERR(( "invalid --rx-depth (must be a power of 2)" ));
  if( FD_UNLIKELY( !fd_ulong_is_pow2( tx_depth ) ) ) FD_LOG_ERR(( "invalid --tx-depth (must be a power of 2)" ));
  if( FD_UNLIKELY( !fd_ulong_is_pow2( cr_depth ) ) ) FD_LOG_ERR(( "invalid --cr-depth (must be a power of 2)" ));
  if( FD_UNLIKELY( !fd_ulong_is_pow2( frame_sz ) ) ) FD_LOG_ERR(( "invalid --frame-sz (must be a power of 2)" ));

  uint if_idx = if_nametoindex( iface );
  if( FD_UNLIKELY( !if_idx ) ) FD_LOG_ERR(( "if_nametoindex(%s) failed (%d-%s)", iface, errno, fd_io_strerror( errno ) ));

  uint if_queue_cnt = get_rx_queue_cnt( iface );
  FD_LOG_NOTICE(( "Binding to interface %s (%u RX queue%s)", iface, if_queue_cnt, if_queue_cnt!=1 ? "s" : "" ));
  assert( if_queue_cnt > 0 );

  if( FD_UNLIKELY( rx_tile_cnt < 1 ) ) {
    FD_LOG_ERR(( "Must at least have one RX tile" ));
  }
  if( FD_UNLIKELY( rx_tile_cnt > if_queue_cnt ) ) {
    FD_LOG_WARNING(( "Requested --rx-cnt %u but %s has only %u channels ... decreasing", rx_tile_cnt, iface, if_queue_cnt ));
    rx_tile_cnt = if_queue_cnt;
  }

  int if_numa_idx = get_net_numa_idx( iface );
  if( FD_UNLIKELY( if_numa_idx >= 0 && numa_idx != (uint)if_numa_idx ) ) {
    FD_LOG_WARNING(( "Interface %s is local to NUMA %d but wksp is on NUMA %lu", iface, if_numa_idx, numa_idx ));
  }

  uint xdp_flags = 0;
  if( !xdp_mode ) {}
  else if( !strcmp( xdp_mode, "skb" ) ) xdp_flags |= XDP_FLAGS_SKB_MODE;
  else if( !strcmp( xdp_mode, "drv" ) ) xdp_flags |= XDP_FLAGS_DRV_MODE;
  else if( !strcmp( xdp_mode, "hw"  ) ) xdp_flags |= XDP_FLAGS_HW_MODE;
  else FD_LOG_ERR(( "invalid --xdp-mode `%s`", xdp_mode ));

  uint bind_flags = XDP_USE_NEED_WAKEUP;
  if( !xsk_mode ) {}
  else if( !strcmp( xsk_mode, "copy"     ) ) bind_flags |= XDP_COPY;
  else if( !strcmp( xsk_mode, "zerocopy" ) ) bind_flags |= XDP_ZEROCOPY;
  else FD_LOG_ERR(( "invalid --xsk-mode `%s`", xsk_mode ));

  ulong xsk_footprint = fd_xsk_footprint( frame_sz, fr_depth, rx_depth, tx_depth, cr_depth );
  ulong aio_footprint = fd_xsk_aio_footprint( tx_depth, aio_depth );

  if( FD_UNLIKELY( !xsk_footprint ) ) FD_LOG_ERR(( "Invalid parameters for fd_xsk_t" ));
  if( FD_UNLIKELY( !aio_footprint ) ) FD_LOG_ERR(( "Invalid parameters for fd_xsk_aio_t" ));

  /* Allocate objects */

  static fd_rxdrop_tile_cfg_t tile_cfg_list[ FD_TILE_MAX ];  /* a bit wasteful */

  /* Assign channels to tiles round robin */

  ulong rx_tile_idx = 0UL;
  for( uint queue_idx=0UL; queue_idx<if_queue_cnt; queue_idx++ ) {

    fd_rxdrop_tile_cfg_t * tile_cfg = tile_cfg_list + rx_tile_idx;
    uint                   src_idx  = tile_cfg->src_cnt++;
    fd_rxdrop_src_cfg_t *  src      = tile_cfg->src_cfg + src_idx;

    if( FD_UNLIKELY( src_idx >= MAX_QUEUES_PER_TILE ) ) {
      FD_LOG_ERR(( "Too many queues per tile (max %u)", MAX_QUEUES_PER_TILE ));
    }
    src->if_queue = queue_idx;

    rx_tile_idx++;
    rx_tile_idx = fd_ulong_if( rx_tile_idx>=rx_tile_cnt, 0UL, rx_tile_idx );
  }

  /* Create XDP related BPF objects */

  fd_xdp_session_t xdp_session[1];
  if( FD_UNLIKELY( !fd_xdp_session_init( xdp_session ) ) ) {
    FD_LOG_ERR(( "fd_xdp_session_init() failed" ));
  }

  fd_xdp_link_session_t link_session[1];
  if( FD_UNLIKELY( !fd_xdp_link_session_init( link_session, xdp_session, if_idx, xdp_flags ) ) ) {
    FD_LOG_ERR(( "fd_xdp_link_session_init() failed" ));
  }

  static fd_rxdrop_cfg_t cfg[1];
  cfg->if_idx     = if_idx;
  cfg->xsk_map_fd = link_session->xsk_map_fd;
  cfg->bind_flags = bind_flags;
  cfg->frame_sz   = frame_sz;
  cfg->fr_depth   = fr_depth;
  cfg->rx_depth   = rx_depth;
  cfg->tx_depth   = tx_depth;
  cfg->cr_depth   = cr_depth;
  cfg->aio_depth  = aio_depth;

  /* Install XDP listener */

  int listen_ok = 0==fd_xdp_listen_udp_port( xdp_session, ip4_addr, (ushort)port, 0U /* proto */ );
  if( FD_UNLIKELY( !listen_ok ) ) {
    FD_LOG_ERR(( "fd_xdp_listen_udp_port(" FD_IP4_ADDR_FMT ":%u) failed (%d-%s)",
                 FD_IP4_ADDR_FMT_ARGS( ip4_addr ), port, errno, fd_io_strerror( errno ) ));
  }

  /* Launch tiles */

  FD_LOG_NOTICE(( "Creating workspace (--page-cnt %lu, --page-sz %s, --numa-idx %lu)", page_cnt, _page_sz, numa_idx ));
  fd_wksp_t * wksp =
    fd_wksp_new_anonymous( fd_cstr_to_shmem_page_sz( _page_sz ), page_cnt, fd_shmem_cpu_idx( numa_idx ), "wksp", 0UL );
  FD_TEST( wksp );
  cfg->wksp = wksp;

  fd_cnc_t * cnc_list[ MAX_QUEUES_PER_TILE ] = {0};

  for( ulong j=0UL; j<rx_tile_cnt; j++ ) {
    fd_rxdrop_tile_cfg_t * tile_cfg = tile_cfg_list + j;
    tile_cfg->argv[0] = (char *)cfg;
    tile_cfg->argv[1] = (char *)tile_cfg;
    tile_cfg->cnc_mem = fd_cnc_new( fd_wksp_alloc_laddr( wksp, fd_cnc_align(), fd_cnc_footprint( sizeof(fd_rxdrop_cnc_app_t) ), 1UL ), sizeof(fd_rxdrop_cnc_app_t), 1UL, fd_tickcount() );
    FD_TEST( tile_cfg->cnc_mem );
    cnc_list[ j ] = fd_cnc_join( tile_cfg->cnc_mem );

    fd_tile_exec_t * exec = fd_tile_exec_new( 1+j, rxdrop_tile, 2, tile_cfg->argv );
    if( FD_UNLIKELY( !exec ) ) FD_LOG_ERR(( "fd_tile_exec_new failed" ));
    tile_cfg->exec = exec;
  }

  /* Wait for tiles to boot */

  for( ulong j=0UL; j<rx_tile_cnt; j++ ) {
    FD_TEST( fd_cnc_wait( cnc_list[ j ], FD_CNC_SIGNAL_BOOT, LONG_MAX, NULL )==FD_CNC_SIGNAL_RUN );
  }

  signal( SIGINT, rxdrop_stop );

  FD_LOG_NOTICE(( "Listening on " FD_IP4_ADDR_FMT ":%u", FD_IP4_ADDR_FMT_ARGS( ip4_addr ), port ));

  /* Metrics tile (very crude) */

  ulong old_pkt_cnt = 0UL;
  while( !rxdrop_shutdown ) {
    sleep(1);

    ulong pkt_cnt = 0UL;
    for( ulong j=0UL; j<rx_tile_cnt; j++ ) {
      fd_rxdrop_cnc_app_t volatile const * cnc_app = fd_cnc_app_laddr_const( cnc_list[j] );
      pkt_cnt += cnc_app->pkt_cnt;
    }
    ulong delta = pkt_cnt - old_pkt_cnt;
    old_pkt_cnt = pkt_cnt;

    FD_LOG_NOTICE(( "%lu", delta ));
  }

  /* Clean up */

  FD_LOG_NOTICE(( "Shutting down ..." ));

  for( ulong j=0UL; j<rx_tile_cnt; j++ ) {
    FD_TEST( !fd_cnc_open( cnc_list[ j ] ) );
    fd_cnc_signal( cnc_list[ j ], FD_CNC_SIGNAL_HALT );
    fd_cnc_close( cnc_list[ j ] );

    fd_tile_exec_delete( tile_cfg_list[j].exec, NULL );
    fd_wksp_free_laddr( fd_cnc_delete( fd_cnc_leave( cnc_list[ j ] ) ) );
  }

  fd_xdp_link_session_fini( link_session );
  fd_xdp_session_fini( xdp_session );

  fd_wksp_delete_anonymous( wksp );

  fd_halt();
  return 0;
}
