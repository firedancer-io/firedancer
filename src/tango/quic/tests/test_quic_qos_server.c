#include <math.h>

#include <linux/if_xdp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

#include "../../../util/fd_util_base.h"
#include "../../../util/net/fd_eth.h"
#include "../../../util/net/fd_ip4.h"
#include "../../../util/rng/fd_rng.h"

#include "../fd_quic.h"
#include "../tls/fd_quic_tls.h"
#include "fd_quic_test_helpers.h"

#include "../../xdp/fd_xdp_redirect_user.h"
#include "../../xdp/fd_xsk.h"
#include "../../xdp/fd_xsk_aio.h"

#include "../../../ballet/ed25519/fd_ed25519_openssl.h"
#include "../../../ballet/x509/fd_x509.h"

#include "../../stake/fd_stake.h"

#include "../fd_quic_qos.h"

int server_complete = 0;

void
conn_new( fd_quic_conn_t * conn, void * ctx ) {
  fd_quic_qos_conn_new( (fd_quic_qos_t *)ctx, conn );
}

void
conn_evict( fd_quic_conn_t * conn, void * ctx ) {
  fd_quic_qos_conn_new( (fd_quic_qos_t *)ctx, conn );
}

int
save_x509_cert_to_pem_file( X509 * cert, const char * pem_file ) {
  FILE * pem_fp = fopen( pem_file, "wb" );
  if ( FD_UNLIKELY( pem_fp == NULL ) ) return 1;
  if ( FD_UNLIKELY( !PEM_write_X509( pem_fp, cert ) ) ) return 1;
  if ( FD_UNLIKELY( fclose( pem_fp ) ) ) return 1;
  return 0;
}

EVP_PKEY *
get_public_key_from_pem( const char * filename ) {
  BIO * bio = BIO_new_file( filename, "r" );
  if ( bio == NULL ) { return NULL; }

  X509 * x509 = PEM_read_bio_X509( bio, NULL, NULL, NULL );
  if ( x509 == NULL ) {
    BIO_free( bio );
    return NULL;
  }

  EVP_PKEY * pkey = X509_get_pubkey( x509 );
  BIO_free( bio );

  return pkey;
}

int
main( int argc, char ** argv ) {
  fd_boot( &argc, &argv );

  ulong cpu_idx = fd_tile_cpu_id( fd_tile_idx() );
  if ( cpu_idx >= fd_shmem_cpu_cnt() ) cpu_idx = 0UL;

  /* clang-format off */
  char const * _page_sz = fd_env_strip_cmdline_cstr( &argc, &argv, "--page-sz", NULL, "gigantic" );
  ulong        page_cnt = fd_env_strip_cmdline_ulong( &argc, &argv, "--page-cnt", NULL, 1UL );
  ulong        numa_idx = fd_env_strip_cmdline_ulong( &argc, &argv, "--numa-idx", NULL, fd_shmem_numa_idx( cpu_idx ) );
  /* clang-format on */

  ulong page_sz = fd_cstr_to_shmem_page_sz( _page_sz );
  if ( FD_UNLIKELY( !page_sz ) ) FD_LOG_ERR( ( "unsupported --page-sz" ) );

  fd_quic_limits_t quic_limits = { 0 };
  fd_quic_limits_from_env( &argc, &argv, &quic_limits );

  FD_LOG_NOTICE( ( "Creating workspace with --page-cnt %lu --page-sz %s pages on --numa-idx %lu",
                   page_cnt,
                   _page_sz,
                   numa_idx ) );
  fd_wksp_t * wksp =
      fd_wksp_new_anonymous( page_sz, page_cnt, fd_shmem_cpu_idx( numa_idx ), "wksp", 0UL );
  FD_TEST( wksp );

  FD_LOG_NOTICE( ( "Creating server QUIC" ) );
  fd_quic_t * quic = fd_quic_new_anonymous( wksp, &quic_limits, FD_QUIC_ROLE_SERVER );
  FD_TEST( quic );
  quic->cb.conn_new = conn_new;

  fd_quic_udpsock_t   _udpsock[1];
  fd_quic_udpsock_t * udpsock =
      fd_quic_udpsock_create( _udpsock, &argc, &argv, wksp, fd_quic_get_aio_net_rx( quic ) );
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
  FD_TEST( fd_quic_config_from_env( &argc, &argv, quic_config ) );

  memcpy( quic_config->link.src_mac_addr, udpsock->self_mac, 6UL );
  quic_config->net.ip_addr         = udpsock->listen_ip;
  quic_config->net.listen_udp_port = udpsock->listen_port;

  uchar pkey[32] = {
      137, 115, 254, 55, 116, 55, 118, 19,  151, 66,  229, 24, 188, 62,  99,  209,
      162, 16,  6,   7,  24,  81, 152, 128, 139, 234, 170, 93, 88,  204, 245, 205,
  };
  quic->cert_key_object = fd_ed25519_pkey_from_private( pkey );
  quic->cert_object     = fd_x509_gen_solana_cert( quic->cert_key_object );

  EVP_PKEY * pk = get_public_key_from_pem( "cert.pem" );
  uchar      pk_buf[32];
  size_t     len;
  EVP_PKEY_get_raw_public_key( pk, NULL, &len );
  FD_LOG_NOTICE( ( "len %lu", len ) );
  EVP_PKEY_get_raw_public_key( pk, pk_buf, &len );
  FD_LOG_HEXDUMP_NOTICE( ( "pk_buf", pk_buf, len ) );

  if ( FD_UNLIKELY( save_x509_cert_to_pem_file( quic->cert_object, "cert.pem" ) ) ) {
    FD_LOG_ERR( ( "failed to save solana pubkey into cert.pem" ) );
  }

  fd_quic_set_aio_net_tx( quic, udpsock->aio );

  if ( FD_UNLIKELY( argc > 1 ) ) FD_LOG_ERR( ( "unrecognized argument: %s", argv[1] ) );

  FD_LOG_NOTICE( ( "Initializing QUIC" ) );
  FD_TEST( fd_quic_init( quic ) );

  fd_quic_qos_limits_t qos_limits = { .min_streams   = FD_QUIC_QOS_DEFAULT_MIN_STREAMS,
                                      .max_streams   = FD_QUIC_QOS_DEFAULT_MAX_STREAMS,
                                      .total_streams = FD_QUIC_QOS_DEFAULT_TOTAL_STREAMS,
                                      .lg_priv_conns    = 0,
                                      .lg_unpriv_conns  = 0 };
  void *               mem =
      fd_wksp_alloc_laddr( wksp, fd_quic_qos_align(), fd_quic_qos_footprint( &qos_limits ), 42UL );
  fd_quic_qos_t * qos = fd_quic_qos_join( fd_quic_qos_new( mem, &qos_limits ) );
  FD_TEST( qos );

  fd_stake_pubkey_t pubkey = {
      .pubkey = {44, 174, 25, 39, 43, 255, 200, 81, 55, 73, 10, 113, 174, 91, 223, 80,
                 50, 51, 102, 25, 63, 110, 36, 28, 51, 11, 174, 179, 110, 8, 25, 152}
  };
  fd_stake_staked_node_t * staked_node =
      fd_stake_staked_node_insert( qos->stake->staked_nodes, pubkey );
  staked_node->stake = 1;

  fd_stake_pubkey_t pubkey2 = {
      .pubkey = {250, 56, 248, 84, 190, 46, 154, 76, 15, 72, 181, 205, 32, 96, 128, 213,
                 158, 33, 81, 193, 63, 154, 93, 254, 15, 81, 32, 175, 54, 60, 179, 224}
  };
  fd_stake_staked_node_t * staked_node2 =
      fd_stake_staked_node_insert( qos->stake->staked_nodes, pubkey2 );
  staked_node2->stake = 2;

  // conn_evict()

  /* do general processing */
  // while ( 1 ) {
  //   fd_quic_service( quic );
  //   fd_quic_udpsock_service( udpsock );
  // }

  FD_TEST( fd_quic_fini( quic ) );

  fd_wksp_free_laddr( fd_quic_delete( fd_quic_leave( quic ) ) );
  fd_quic_udpsock_destroy( udpsock );
  fd_wksp_delete_anonymous( wksp );

  FD_LOG_NOTICE( ( "pass" ) );
  fd_halt();
  return 0;
}
