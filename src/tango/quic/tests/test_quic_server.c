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

#include "../../../ballet/x509/fd_x509_mock.h"

int server_complete = 0;

/* server connection received in callback */
fd_quic_conn_t * server_conn = NULL;

int
main( int argc, char ** argv ) {
  fd_boot( &argc, &argv );

  ulong cpu_idx = fd_tile_cpu_id( fd_tile_idx() );
  if( cpu_idx>=fd_shmem_cpu_cnt() ) cpu_idx = 0UL;

  char const * _page_sz = fd_env_strip_cmdline_cstr  ( &argc, &argv, "--page-sz",  NULL, "gigantic"                 );
  ulong        page_cnt = fd_env_strip_cmdline_ulong ( &argc, &argv, "--page-cnt", NULL, 1UL                        );
  ulong        numa_idx = fd_env_strip_cmdline_ulong ( &argc, &argv, "--numa-idx", NULL, fd_shmem_numa_idx(cpu_idx) );

  ulong page_sz = fd_cstr_to_shmem_page_sz( _page_sz );
  if( FD_UNLIKELY( !page_sz ) ) FD_LOG_ERR(( "unsupported --page-sz" ));

  fd_quic_limits_t quic_limits = {0};
  fd_quic_limits_from_env( &argc, &argv, &quic_limits);

  FD_LOG_NOTICE(( "Creating workspace with --page-cnt %lu --page-sz %s pages on --numa-idx %lu", page_cnt, _page_sz, numa_idx ));
  fd_wksp_t * wksp = fd_wksp_new_anonymous( page_sz, page_cnt, fd_shmem_cpu_idx( numa_idx ), "wksp", 0UL );
  FD_TEST( wksp );

  FD_LOG_NOTICE(( "Creating server QUIC" ));
  fd_quic_t * quic = fd_quic_new_anonymous( wksp, &quic_limits, FD_QUIC_ROLE_SERVER );
  FD_TEST( quic );

  fd_quic_udpsock_t _udpsock[1];
  fd_quic_udpsock_t * udpsock = fd_quic_udpsock_create( _udpsock, &argc, &argv, wksp, fd_quic_get_aio_net_rx( quic ) );
  FD_TEST( udpsock );

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
  quic_config->retry = 1;
  FD_TEST( fd_quic_config_from_env( &argc, &argv, quic_config ) );

  memcpy( quic_config->link.src_mac_addr, udpsock->self_mac, 6UL );
  quic_config->net.ip_addr         = udpsock->listen_ip;
  quic_config->net.listen_udp_port = udpsock->listen_port;
  fd_quic_set_aio_net_tx( quic, udpsock->aio );
  uchar pkey[32]        = {
      137, 115, 254, 55, 116, 55, 118, 19,  151, 66,  229, 24, 188, 62,  99,  209,
      162, 16,  6,   7,  24,  81, 152, 128, 139, 234, 170, 93, 88,  204, 245, 205,
  };
  uchar pubkey[32]      = { 44, 174, 25,  39, 43, 255, 200, 81, 55, 73, 10,  113, 174, 91, 223, 80,
                            50, 51,  102, 25, 63, 110, 36,  28, 51, 11, 174, 179, 110, 8,  25,  152 };
  FD_LOG_HEXDUMP_NOTICE(( "Solana private key", pkey, 32 ));  /* TODO use base-58 format specifier */
  FD_LOG_HEXDUMP_NOTICE(( "Solana public key", pubkey, 32 ));  /* TODO use base-58 format specifier */
  quic->cert_key_object = EVP_PKEY_new_raw_private_key( EVP_PKEY_ED25519, NULL, pkey, 32UL );

  /* Generate X509 certificate */
  fd_sha512_t sha[1];
  uchar cert_asn1[ FD_X509_MOCK_CERT_SZ ];
  fd_x509_mock_cert( cert_asn1, pkey, 123UL, sha );
  do {
    uchar const * cert_ptr = cert_asn1;
    quic->cert_object = d2i_X509( NULL, &cert_ptr, FD_X509_MOCK_CERT_SZ );
    FD_TEST( quic->cert_object );
  } while(0);
  fd_memset( sha, 0, sizeof(fd_sha512_t) );

  FD_LOG_NOTICE(( "Initializing QUIC" ));
  FD_TEST( fd_quic_init( quic ) );

  /* TODO support pcap if requested */

  /* do general processing */
  while(1) {
    fd_quic_service( quic );
    fd_quic_udpsock_service( udpsock );
  }

  FD_TEST( fd_quic_fini( quic ) );

  fd_wksp_free_laddr( fd_quic_delete( fd_quic_leave( quic ) ) );
  fd_quic_udpsock_destroy( udpsock );
  fd_wksp_delete_anonymous( wksp );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
