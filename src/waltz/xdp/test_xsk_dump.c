#include "fd_xsk.h"
#include "fd_xsk_aio.h"
#include "fd_xdp_redirect_user.h"
#include "../../util/fd_util.h"
#include "../../util/net/fd_ip4.h"

#include <assert.h>  /* assert */
#include <errno.h>   /* errno */
#include <stdio.h>   /* fopen */
#include <unistd.h>  /* close */

#include <sys/types.h>
#include <sys/socket.h>     /* socket */
#include <sys/ioctl.h>      /* ioctl */
#include <net/if.h>         /* struct ifreq */
#include <netinet/in.h>     /* struct sockaddr_in */
#include <linux/if.h>       /* struct ifreq */
#include <linux/if_xdp.h>   /* XDP_ZEROCOPY */

static char const help_str[] =
  "\n"
  "test_xsk_dump logs incoming AF_XDP traffic.\n"
  "Warning: Logged packets are dropped.\n"
  "\n"
  "Usage: fd_xsk_rxdrop [args...]\n"
  "\n"
  "  --iface      Name of network device to attach to\n"
  "  --ifqueue    Interface queue index\n"
  "  --addr       IPv4 listen address.  Defaults to first IPv4 address\n"
  "  --port       UDP port to listen on\n"
  "  --xdp-mode   XDP mode (skb/drv/hw)\n"
  "  --xsk-mode   AF_XDP bind mode (copy/zerocopy)\n"
  "\n"
  "  --page-sz    Workspace page size (gigantic/huge/normal)\n"
  "  --numa-idx   Workspace NUMA index (default is local to tile 0)\n"
  "\n";

#define MAX_QUEUES_PER_TILE (16)

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

static int
aio_dump( void *                    ctx,
          fd_aio_pkt_info_t const * batch,
          ulong                     batch_cnt,
          ulong *                   opt_batch_idx,
          int                       flush ) {
  (void)ctx; (void)flush; (void)opt_batch_idx;
  for( ulong j=0UL; j<batch_cnt; j++ ) {
    FD_LOG_HEXDUMP_NOTICE(( "Packet", batch[j].buf, batch[j].buf_sz ));
  }
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
  uint         if_queue    = fd_env_strip_cmdline_uint  ( &argc, &argv, "--ifqueue",   NULL, 0U           );
  char const * ip4_cstr    = fd_env_strip_cmdline_cstr  ( &argc, &argv, "--addr",      NULL, NULL         );
  uint         port        = fd_env_strip_cmdline_ushort( &argc, &argv, "--port",      NULL, 0            );
  char const * xdp_mode    = fd_env_strip_cmdline_cstr  ( &argc, &argv, "--xdp-mode",  NULL, NULL         );
  char const * xsk_mode    = fd_env_strip_cmdline_cstr  ( &argc, &argv, "--xsk-mode",  NULL, NULL         );
  ulong        frame_sz    = fd_env_strip_cmdline_ulong ( &argc, &argv, "--frame-sz",  NULL, 2048UL       );
  ulong        fr_depth    = fd_env_strip_cmdline_ulong ( &argc, &argv, "--fr-depth",  NULL, 128UL        );
  ulong        rx_depth    = fd_env_strip_cmdline_ulong ( &argc, &argv, "--rx-depth",  NULL, 128UL        );
  ulong        tx_depth    = fd_env_strip_cmdline_ulong ( &argc, &argv, "--tx-depth",  NULL, 128UL        );
  ulong        cr_depth    = fd_env_strip_cmdline_ulong ( &argc, &argv, "--cr-depth",  NULL, 128UL        );
  ulong        aio_depth   = fd_env_strip_cmdline_ulong ( &argc, &argv, "--aio-depth", NULL, 32UL         );

  /* Validate command-line args */

  if( FD_UNLIKELY( !iface ) ) FD_LOG_ERR(( "Missing --iface" ));
  if( FD_UNLIKELY( !port  ) ) FD_LOG_ERR(( "Missing --port"  ));

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

  FD_LOG_NOTICE(( "Binding to interface %s queue %u", iface, if_queue ));

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

  /* Create XDP related BPF objects */

  fd_xdp_session_t xdp_session[1];
  if( FD_UNLIKELY( !fd_xdp_session_init( xdp_session ) ) ) {
    FD_LOG_ERR(( "fd_xdp_session_init() failed" ));
  }

  fd_xdp_link_session_t link_session[1];
  if( FD_UNLIKELY( !fd_xdp_link_session_init( link_session, xdp_session, if_idx, xdp_flags ) ) ) {
    FD_LOG_ERR(( "fd_xdp_link_session_init() failed" ));
  }
  int xsk_map_fd = link_session->xsk_map_fd;

  /* Install XDP listener */

  int listen_ok = 0==fd_xdp_listen_udp_port( xdp_session, ip4_addr, (ushort)port, 0U /* proto */ );
  if( FD_UNLIKELY( !listen_ok ) ) {
    FD_LOG_ERR(( "fd_xdp_listen_udp_port(" FD_IP4_ADDR_FMT ":%u) failed (%d-%s)",
                 FD_IP4_ADDR_FMT_ARGS( ip4_addr ), port, errno, fd_io_strerror( errno ) ));
  }

  /* Run */

  FD_LOG_NOTICE(( "Creating workspace (--page-cnt %lu, --page-sz %s, --numa-idx %lu)", page_cnt, _page_sz, numa_idx ));
  fd_wksp_t * wksp =
    fd_wksp_new_anonymous( fd_cstr_to_shmem_page_sz( _page_sz ), page_cnt, fd_shmem_cpu_idx( numa_idx ), "wksp", 0UL );
  FD_TEST( wksp );

  void * xsk_mem  = fd_wksp_alloc_laddr( wksp, fd_xsk_align(),     xsk_footprint, 1UL );
  void * aio_mem  = fd_wksp_alloc_laddr( wksp, fd_xsk_aio_align(), aio_footprint, 1UL );

  fd_xsk_t * xsk = fd_xsk_join( fd_xsk_new( xsk_mem, frame_sz, fr_depth, rx_depth, tx_depth, cr_depth ) );
  if( FD_UNLIKELY( !xsk ) ) FD_LOG_ERR(( "fd_xsk_new failed" ));

  if( FD_UNLIKELY( !fd_xsk_init( xsk, if_idx, if_queue, bind_flags ) ) ) {
    FD_LOG_ERR(( "fd_xsk_init failed" ));
  }

  if( FD_UNLIKELY( !fd_xsk_activate( xsk, xsk_map_fd ) ) ) {
    FD_LOG_ERR(( "fd_xsk_activate failed" ));
  }

  fd_xsk_aio_t * xsk_aio = fd_xsk_aio_join( fd_xsk_aio_new( aio_mem, tx_depth, aio_depth ), xsk );
  if( FD_UNLIKELY( !xsk_aio ) ) FD_LOG_ERR(( "fd_xsk_aio_new failed" ));

  fd_aio_t _aio[1];
  fd_aio_t * aio = fd_aio_join( fd_aio_new( _aio, NULL, aio_dump ) );
  FD_TEST( aio );

  fd_xsk_aio_set_rx( xsk_aio, aio );

  FD_LOG_NOTICE(( "Listening on " FD_IP4_ADDR_FMT ":%u", FD_IP4_ADDR_FMT_ARGS( ip4_addr ), port ));

  for(;;) {
    fd_xsk_aio_service( xsk_aio );
  }

  /* Clean up */

  FD_LOG_NOTICE(( "Shutting down ..." ));

  fd_aio_delete( fd_aio_leave( aio ) );
  if( FD_UNLIKELY( !fd_xsk_deactivate( xsk, xsk_map_fd ) ) ) {
    FD_LOG_WARNING(( "fd_xsk_deactivate failed" ));
  }
  fd_wksp_free_laddr( fd_xsk_aio_delete( fd_xsk_aio_leave( xsk_aio ) ) );
  fd_wksp_free_laddr( fd_xsk_delete    ( fd_xsk_leave    ( xsk     ) ) );
  fd_xdp_link_session_fini( link_session );
  fd_xdp_session_fini( xdp_session );

  fd_wksp_delete_anonymous( wksp );

  fd_halt();
  return 0;
}
