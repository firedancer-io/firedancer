#include <math.h>

#include <linux/if_xdp.h>

#include "../../../util/fd_util_base.h"
#include "../../../util/net/fd_eth.h"
#include "../../../util/net/fd_ip4.h"

#include "../fd_quic.h"
#include "fd_quic_test_helpers.h"

#include "../tls/fd_quic_tls.h"

#include "../../xdp/fd_xdp_redirect_user.h"
#include "../../xdp/fd_xsk.h"
#include "../../xdp/fd_xsk_aio.h"

#include "../../../ballet/ed25519/fd_ed25519_openssl.h"
#include "../../../ballet/x509/fd_x509.h"

#define FD_DEBUG_MODE 1

#define STAKE_LG_SLOT_CNT 1

static FD_TLS ulong conn_seq = 0UL;

struct test_quic_qos_ctx {
  fd_stake_t *    stake;
  fd_quic_qos_t * quic_qos;
  fd_rng_t *      rng;
};
typedef struct test_quic_qos_ctx test_quic_qos_ctx_t;

void
test_quic_qos_conn_new( fd_quic_conn_t * conn, void * _ctx ) {
  conn->local_conn_id       = ++conn_seq;
  test_quic_qos_ctx_t * ctx = (test_quic_qos_ctx_t *)_ctx;

  fd_stake_pubkey_t   pubkey     = { 0 };
  fd_stake_pubkey_t * pubkey_ptr = &pubkey;
  int verify_result = fd_quic_tls_get_pubkey( conn->tls_hs, pubkey.pubkey, FD_STAKE_PUBKEY_SZ );
  if ( FD_UNLIKELY( verify_result != X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT ) ) {
    FD_DEBUG( FD_LOG_WARNING( ( "Failed to get conn: %lu's pubkey", conn->local_conn_id ) ) );
    pubkey_ptr = NULL;
  }
  fd_quic_qos_conn_new( ctx->quic_qos, ctx->stake, ctx->rng, conn, pubkey_ptr );
}

void
test_quic_qos_conn_final( fd_quic_conn_t * conn, void * _ctx ) {
  FD_LOG_NOTICE(("releasing"));
  test_quic_qos_ctx_t * ctx   = (test_quic_qos_ctx_t *)_ctx;
  fd_quic_qos_pq_t *    pq    = ctx->quic_qos->pq;
  fd_quic_qos_pq_t *    query = fd_quic_qos_pq_query( pq, conn->local_conn_id, NULL );
  if ( FD_UNLIKELY( ( query ) ) ) { /* most connections likely unstaked */
    fd_quic_qos_pq_remove( pq, query );
  }
}

void
test_quic_qos_stream_receive( fd_quic_stream_t * stream,
                              void *             ctx,
                              uchar const *      data,
                              ulong              data_sz,
                              ulong              offset,
                              int                fin ) {
  (void)ctx;

  FD_LOG_NOTICE( ( "server rx stream data stream=%lu size=%lu offset=%lu fin=%d",
                   stream->stream_id,
                   data_sz,
                   offset,
                   fin ) );
  FD_LOG_HEXDUMP_NOTICE( ( "received data", data, data_sz ) );
}

int
main( int argc, char ** argv ) {
  fd_boot( &argc, &argv );

  ulong cpu_idx = fd_tile_cpu_id( fd_tile_idx() );
  if ( cpu_idx >= fd_shmem_cpu_cnt() ) cpu_idx = 0UL;

  char const * _page_sz = fd_env_strip_cmdline_cstr( &argc, &argv, "--page-sz", NULL, "gigantic" );
  ulong        page_cnt = fd_env_strip_cmdline_ulong( &argc, &argv, "--page-cnt", NULL, 1UL );
  ulong        numa_idx =
      fd_env_strip_cmdline_ulong( &argc, &argv, "--numa-idx", NULL, fd_shmem_numa_idx( cpu_idx ) );

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

  /* initialize stakes*/
  ulong   stake_footprint = fd_stake_footprint( STAKE_LG_SLOT_CNT );
  uchar * stake_mem = (uchar *)fd_wksp_alloc_laddr( wksp, fd_stake_align(), stake_footprint, 1UL );
  FD_TEST( stake_mem );
  fd_stake_t *      stake        = fd_stake_join( fd_stake_new( stake_mem, STAKE_LG_SLOT_CNT ) );
  fd_stake_node_t * staked_nodes = fd_stake_nodes_laddr( stake );
  FD_TEST( stake );
  FD_TEST( staked_nodes );
  FD_LOG_NOTICE( ( "stake: %p, footprint: %lu", (void *)stake, stake_footprint ) );
  FD_LOG_NOTICE( ( "  ->staked_nodes: %p", (void *)staked_nodes ) );

  fd_stake_pubkey_t pubkey = {
      .pubkey = {0x55, 0xc8, 0x0e, 0xa6, 0x55, 0xe2, 0xc2, 0x7a, 0xec, 0xef, 0xb0,
                 0x4e, 0x2b, 0x86, 0xcb, 0x9e, 0x73, 0x0d, 0x09, 0x49, 0x75, 0xc8,
                 0xc9, 0xa6, 0x81, 0xf1, 0x54, 0x6c, 0x7c, 0x40, 0x11, 0x7d}
  };
  fd_stake_node_t * insert = fd_stake_node_insert( staked_nodes, pubkey );
  insert->stake            = 42UL;
  fd_stake_node_t * query  = fd_stake_node_query( staked_nodes, pubkey, NULL );
  FD_TEST( query );
  FD_TEST( !memcmp( query->key.pubkey, query->key.pubkey, FD_TXN_PUBKEY_SZ ) );
  FD_TEST( insert->stake == query->stake );

  /* initialize QoS */
  fd_quic_qos_limits_t qos_limits = {
      .min_streams   = FD_QUIC_QOS_DEFAULT_MIN_STREAMS,
      .max_streams   = FD_QUIC_QOS_DEFAULT_MAX_STREAMS,
      .total_streams = FD_QUIC_QOS_DEFAULT_TOTAL_STREAMS,
      // .pq_lg_slot_cnt = fd_ulong_find_msb(quic_limits.conn_cnt >> 1),
      .pq_lg_slot_cnt = 1,
      // .lru_depth      = quic_limits.conn_cnt >> 1,
      .lru_depth = 1,
  };
  ulong   qos_footprint = fd_quic_qos_footprint( &qos_limits );
  uchar * qos_mem = (uchar *)fd_wksp_alloc_laddr( wksp, fd_quic_qos_align(), qos_footprint, 1UL );
  FD_TEST( qos_mem );
  fd_quic_qos_t * qos = fd_quic_qos_join( fd_quic_qos_new( qos_mem, &qos_limits ) );
  FD_TEST( qos );
  FD_TEST( qos->pq );
  FD_TEST( qos->lru );
  FD_LOG_NOTICE( ( "qos: %p, footprint %lu", (void *)qos_mem, qos_footprint ) );
  FD_LOG_NOTICE( ( "  ->pq:  %p", (void *)qos->pq ) );
  FD_LOG_NOTICE( ( "  ->lru: %p", (void *)qos->lru ) );

  fd_quic_t * quic = fd_quic_new_anonymous( wksp, &quic_limits, FD_QUIC_ROLE_SERVER );
  FD_TEST( quic );
  FD_LOG_NOTICE( ( "quic %p, footprint: %lu", (void *)quic, fd_quic_footprint( &quic_limits ) ) );

  fd_quic_udpsock_t   _udpsock[1];
  fd_quic_udpsock_t * udpsock =
      fd_quic_udpsock_create( _udpsock, &argc, &argv, wksp, fd_quic_get_aio_net_rx( quic ) );
  FD_TEST( udpsock );

  fd_quic_config_t * quic_config = &quic->config;
  FD_TEST( quic_config );

  quic_config->role          = FD_QUIC_ROLE_SERVER;
  quic_config->retry         = 1;
  quic_config->verify_peer   = 1;
  quic_config->verify_depth  = 0;
  quic_config->verify_strict = 0;
  FD_TEST( fd_quic_config_from_env( &argc, &argv, quic_config ) );

  memcpy( quic_config->link.src_mac_addr, udpsock->self_mac, 6UL );
  quic_config->net.ip_addr         = udpsock->listen_ip;
  quic_config->net.listen_udp_port = udpsock->listen_port;
  fd_quic_set_aio_net_tx( quic, udpsock->aio );
  uchar server_pkey[32] = {
      137, 115, 254, 55, 116, 55, 118, 19,  151, 66,  229, 24, 188, 62,  99,  209,
      162, 16,  6,   7,  24,  81, 152, 128, 139, 234, 170, 93, 88,  204, 245, 205,
  };
  uchar server_pubkey[32] = { 44,  174, 25, 39,  43,  255, 200, 81,  55, 73, 10,
                              113, 174, 91, 223, 80,  50,  51,  102, 25, 63, 110,
                              36,  28,  51, 11,  174, 179, 110, 8,   25, 152 };
  FD_LOG_HEXDUMP_NOTICE(
      ( "server: private key", server_pkey, 32 ) ); /* TODO use base-58 format specifier */
  FD_LOG_HEXDUMP_NOTICE(
      ( "server: public key", server_pubkey, 32 ) ); /* TODO use base-58 format specifier */
  quic->cert_key_object = fd_ed25519_pkey_from_private( server_pkey );
  quic->cert_object     = fd_x509_gen_solana_cert( quic->cert_key_object );

  FILE * cert_file = fopen( "cert.pem", "wb" );
  PEM_write_X509( cert_file, quic->cert_object );
  fclose( cert_file );

  if ( FD_UNLIKELY( argc > 1 ) ) FD_LOG_ERR( ( "unrecognized argument: %s", argv[1] ) );

  FD_LOG_NOTICE( ( "Initializing QUIC" ) );
  FD_TEST( fd_quic_init( quic ) );

  fd_rng_t   _rng[1];
  fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, 0U, 0UL ) );

  test_quic_qos_ctx_t ctx = { .stake = stake, .quic_qos = qos, .rng = rng };
  quic->cb.quic_ctx       = &ctx;
  quic->cb.conn_new       = test_quic_qos_conn_new;
  quic->cb.stream_receive = test_quic_qos_stream_receive;
  quic->cb.conn_final     = test_quic_qos_conn_final;

  while ( 1 ) {
    fd_quic_service( quic );
    fd_quic_udpsock_service( udpsock );
  }

  FD_TEST( fd_quic_fini( quic ) );

  fd_wksp_free_laddr( fd_quic_delete( fd_quic_leave( quic ) ) );
  fd_quic_udpsock_destroy( udpsock );
  fd_wksp_delete_anonymous( wksp );

  FD_LOG_NOTICE( ( "pass" ) );
  fd_halt();
  return 0;
}
