#include <math.h>

#include <linux/if_xdp.h>

#include "../../../util/fd_util_base.h"
#include "../../../util/net/fd_eth.h"
#include "../../../util/net/fd_ip4.h"

#include "../fd_quic.h"
#include "fd_quic_test_helpers.h"

#include "../../xdp/fd_xsk.h"
#include "../../xdp/fd_xsk_aio.h"
#include "../../xdp/fd_xdp_redirect_user.h"

int server_complete = 0;

/* server connection received in callback */
fd_quic_conn_t * server_conn = NULL;

int
main( int argc, char ** argv ) {
  fd_boot( &argc, &argv );

  ulong cpu_idx = fd_tile_cpu_id( fd_tile_idx() );
  if( cpu_idx>=fd_shmem_cpu_cnt() ) cpu_idx = 0UL;

  char const * app_name     = fd_env_strip_cmdline_cstr  ( &argc, &argv, "--app-name",     NULL, "test_quic_server"         );
  char const * _page_sz     = fd_env_strip_cmdline_cstr  ( &argc, &argv, "--page-sz",      NULL, "gigantic"                 );
  ulong        page_cnt     = fd_env_strip_cmdline_ulong ( &argc, &argv, "--page-cnt",     NULL, 1UL                        );
  ulong        numa_idx     = fd_env_strip_cmdline_ulong ( &argc, &argv, "--numa-idx",     NULL, fd_shmem_numa_idx(cpu_idx) );
  char const * iface        = fd_env_strip_cmdline_cstr  ( &argc, &argv, "--iface",        NULL, NULL                       );
  uint         ifqueue      = fd_env_strip_cmdline_uint  ( &argc, &argv, "--ifqueue",      NULL, 0U                         );
  char const * _src_mac     = fd_env_strip_cmdline_cstr  ( &argc, &argv, "--src-mac",      NULL, NULL                       );
  char const * _dst_mac     = fd_env_strip_cmdline_cstr  ( &argc, &argv, "--dst-mac",      NULL, NULL                       );
  char const * _listen_ip   = fd_env_strip_cmdline_cstr  ( &argc, &argv, "--listen-ip",    NULL, NULL                       );
  ushort       listen_port  = fd_env_strip_cmdline_ushort( &argc, &argv, "--listen-port",  NULL, 0U                         );
  ulong        xsk_frame_sz = fd_env_strip_cmdline_ulong ( &argc, &argv, "--xsk-frame-sz", NULL, 2048UL                     );
  ulong        xsk_rx_depth = fd_env_strip_cmdline_ulong ( &argc, &argv, "--xsk-rx-depth", NULL, 1024UL                     );
  ulong        xsk_tx_depth = fd_env_strip_cmdline_ulong ( &argc, &argv, "--xsk-tx-depth", NULL, 1024UL                     );
  ulong        xsk_pkt_cnt  = fd_env_strip_cmdline_ulong ( &argc, &argv, "--xsk-pkt-cnt",  NULL,   32UL                     );

  ulong page_sz = fd_cstr_to_shmem_page_sz( _page_sz );
  if( FD_UNLIKELY( !page_sz ) ) FD_LOG_ERR(( "unsupported --page-sz" ));

  if( FD_UNLIKELY( !_src_mac    ) ) FD_LOG_ERR(( "missing --src-mac"     ));
  if( FD_UNLIKELY( !_dst_mac    ) ) FD_LOG_ERR(( "missing --dst-mac"     ));
  if( FD_UNLIKELY( !_listen_ip  ) ) FD_LOG_ERR(( "missing --listen-ip"   ));
  if( FD_UNLIKELY( !listen_port ) ) FD_LOG_ERR(( "missing --listen-port" ));

  uchar src_mac[6];
  if( FD_UNLIKELY( !fd_cstr_to_mac_addr( _src_mac, src_mac ) ) ) FD_LOG_ERR(( "invalid --src-mac" ));
  uchar dst_mac[6];
  if( FD_UNLIKELY( !fd_cstr_to_mac_addr( _dst_mac, dst_mac ) ) ) FD_LOG_ERR(( "invalid --dst-mac" ));
  uint listen_ip = 0;
  if( FD_UNLIKELY( !fd_cstr_to_ip4_addr( _listen_ip, &listen_ip ) ) ) FD_LOG_ERR(( "invalid --listen-ip" ));

  fd_quic_limits_t quic_limits = {0};
  fd_quic_limits_from_env( &argc, &argv, &quic_limits);

  FD_LOG_NOTICE(( "Creating workspace with --page-cnt %lu --page-sz %s pages on --numa-idx %lu", page_cnt, _page_sz, numa_idx ));
  fd_wksp_t * wksp = fd_wksp_new_anonymous( page_sz, page_cnt, fd_shmem_cpu_idx( numa_idx ), "wksp", 0UL );
  FD_TEST( wksp );

  FD_LOG_NOTICE(( "Creating server QUIC" ));
  fd_quic_t * quic = fd_quic_new_anonymous( wksp, &quic_limits, FD_QUIC_ROLE_SERVER );
  FD_TEST( quic );

  /* Transport params:
       original_destination_connection_id (0x00)         :   len(0)
       max_idle_timeout (0x01)                           : * 60000
       stateless_reset_token (0x02)                      :   len(0)
       max_udp_payload_size (0x03)                       :   0
       initial_max_data (0x04)                           : * 1048576
       initial_max_stream_data_bidi_local (0x05)         : * 1048576
       initial_max_stream_data_bidi_remote (0x06)        : * 1048576
       initial_max_stream_data_uni (0x07)                : * 1048576
       initial_max_streams_bidi (0x08)                   : * 128
       initial_max_streams_uni (0x09)                    : * 128
       ack_delay_exponent (0x0a)                         : * 3
       max_ack_delay (0x0b)                              : * 25
       disable_active_migration (0x0c)                   :   0
       preferred_address (0x0d)                          :   len(0)
       active_connection_id_limit (0x0e)                 : * 8
       initial_source_connection_id (0x0f)               : * len(8) ec 73 1b 41 a0 d5 c6 fe
       retry_source_connection_id (0x10)                 :   len(0) */

  fd_quic_config_t * quic_config = &quic->config;
  FD_TEST( quic_config );

  quic_config->role = FD_QUIC_ROLE_SERVER;
  fd_quic_config_from_env( &argc, &argv, quic_config );

  memcpy( quic_config->link.src_mac_addr, src_mac, 6UL );
  memcpy( quic_config->link.dst_mac_addr, dst_mac, 6UL );

  quic_config->net.ip_addr         = listen_ip;
  quic_config->net.listen_udp_port = listen_port;

  ulong xsk_sz   = fd_xsk_footprint( xsk_frame_sz, xsk_rx_depth, xsk_rx_depth, xsk_tx_depth, xsk_tx_depth );

  FD_LOG_NOTICE(( "Creating XSK" ));
  void * xsk_mem = fd_wksp_alloc_laddr( wksp, fd_xsk_align(), xsk_sz, 1UL );
  FD_TEST( fd_xsk_new( xsk_mem, xsk_frame_sz, xsk_rx_depth, xsk_rx_depth, xsk_tx_depth, xsk_tx_depth ) );

  FD_LOG_NOTICE(( "Binding XSK (--iface %s, --ifqueue %u)", iface, ifqueue ));
  FD_TEST( fd_xsk_bind( xsk_mem, app_name, iface, ifqueue ) );

  FD_LOG_NOTICE(( "Joining XSK" ));
  fd_xsk_t * xsk = fd_xsk_join( xsk_mem );
  FD_TEST( xsk );

  FD_LOG_NOTICE(( "Creating fd_xsk_aio" ));
  void * xsk_aio_mem =
    fd_wksp_alloc_laddr( wksp, fd_xsk_aio_align(), fd_xsk_aio_footprint( xsk_tx_depth, xsk_pkt_cnt ), 1UL );
  FD_TEST( fd_xsk_aio_new( xsk_aio_mem, xsk_tx_depth, xsk_pkt_cnt ) );

  fd_xsk_aio_t * xsk_aio = fd_xsk_aio_join( xsk_aio_mem, xsk );
  FD_TEST( xsk_aio );

  FD_LOG_NOTICE(( "Adding UDP listener (" FD_IP4_ADDR_FMT ":%u)",
                  FD_IP4_ADDR_FMT_ARGS( listen_ip ), listen_port ));
  FD_TEST( 0==fd_xdp_listen_udp_port( app_name, listen_ip, listen_port, 0 ) );

  FD_LOG_NOTICE(( "Wiring up QUIC and XSK" ));
  fd_xsk_aio_set_rx( xsk_aio, fd_quic_get_aio_net_rx( quic ) );

  FD_LOG_NOTICE(( "Initializing QUIC" ));
  FD_TEST( fd_quic_init( quic ) );

  /* TODO support pcap if requested */

  /* do general processing */
  while(1) {
    fd_quic_service( quic );

    fd_xsk_aio_service( xsk_aio );
  }

  FD_TEST( fd_quic_fini( quic ) );

  fd_wksp_free_laddr( fd_quic_delete   ( fd_quic_leave   ( quic    ) ) );
  fd_wksp_free_laddr( fd_xsk_aio_delete( fd_xsk_aio_leave( xsk_aio ) ) );
  fd_wksp_free_laddr( fd_xsk_delete    ( fd_xsk_leave    ( xsk     ) ) );

  fd_wksp_delete_anonymous( wksp );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}

