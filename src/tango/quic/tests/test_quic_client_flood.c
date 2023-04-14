#include "../fd_quic.h"

#include <stdlib.h>

#include "../../xdp/fd_xdp.h"
#include "../../../ballet/sha512/fd_sha512.h"
#include "../../../ballet/ed25519/fd_ed25519.h"
#include "../../../util/fd_util.h"
#include "../../../util/net/fd_eth.h"
#include "../../../util/net/fd_ip4.h"

extern uchar pkt_full[];
extern ulong pkt_full_sz;

fd_quic_stream_t * cur_stream = NULL;

void
my_stream_notify_cb( fd_quic_stream_t * stream, void * ctx, int type ) {
  (void)ctx;
  (void)type;
  FD_LOG_DEBUG(( "notify_cb" ));
  if( cur_stream == stream ) {
    cur_stream = NULL;
  }
}

void
my_stream_receive_cb( fd_quic_stream_t * stream,
                      void *             ctx,
                      uchar const *      data,
                      ulong              data_sz,
                      ulong              offset,
                      int                fin ) {
  (void)ctx;
  (void)stream;
  (void)fin;

  FD_LOG_DEBUG(( "received data from peer (size=%lu offset=%lu)", data_sz, offset ));
  FD_LOG_HEXDUMP_DEBUG(( "stream data", data, data_sz ));
}

fd_quic_conn_t * client_conn = NULL;

int client_complete = 0;

/* Client handshake complete */
void my_handshake_complete( fd_quic_conn_t * conn, void * vp_context ) {
  (void)conn;
  (void)vp_context;

  FD_LOG_INFO(( "client handshake complete" ));
  client_complete = 1;
}

/* Connection closed */
void my_connection_closed( fd_quic_conn_t * conn, void * vp_context ) {
  (void)conn;
  (void)vp_context;

  FD_LOG_INFO(( "client conn closed" ));
  client_conn     = NULL;
  client_complete = 1;
}

ulong
test_clock( void * ctx ) {
  (void)ctx;
  return (ulong)fd_log_wallclock();
}

void
run_quic_client(
  fd_quic_t *    quic,
  fd_xsk_aio_t * xsk_aio,
  uint           dst_ip,
  ushort         dst_port) {

# define MSG_SZ_MIN (1UL)
# define MSG_SZ_MAX (1232UL-64UL-32UL)
# define MSG_SIZE_RANGE (MSG_SZ_MAX - MSG_SZ_MIN + 1UL)
  fd_aio_pkt_info_t batches[MSG_SIZE_RANGE][1];

  do {
    /* Reset locals */
    client_conn     = NULL;
    client_complete = 0;

    fd_quic_callbacks_t * client_cb = fd_quic_get_callbacks( quic );
    client_cb->conn_hs_complete = my_handshake_complete;
    client_cb->conn_final       = my_connection_closed;
    client_cb->stream_receive   = my_stream_receive_cb;
    client_cb->stream_notify    = my_stream_notify_cb;
    client_cb->now              = test_clock;
    client_cb->now_ctx          = NULL;

    /* use XSK XDP AIO for QUIC ingress/egress */
    fd_aio_t _quic_aio[1];
    fd_xsk_aio_set_rx     ( xsk_aio, fd_quic_get_aio_net_rx( quic, _quic_aio ) );
    fd_quic_set_aio_net_tx( quic,    fd_xsk_aio_get_tx     ( xsk_aio )         );

    FD_TEST( fd_quic_join( quic ) );

    FD_LOG_NOTICE(( "Starting QUIC client" ));

    /* make a connection from client to the server */
    client_conn = fd_quic_connect( quic, dst_ip, dst_port, NULL );

    /* do general processing */
    while ( !client_complete ) {
      fd_quic_service( quic );
      fd_xsk_aio_service( xsk_aio );
    }

    if( !client_conn ) {
      FD_LOG_WARNING(( "QUIC handshake failed" ));
      break;
    }
    FD_LOG_NOTICE(( "QUIC handshake complete" ));

    FD_TEST( client_conn->state == FD_QUIC_CONN_STATE_ACTIVE );

    /* create and sign fake ref message txns */
    /* generate a message for every possible message size, using code from fd_frank_verify_synth_load */
    fd_rng_t _rng[ 1 ];
    uint seed = (uint)fd_tile_id();
    fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, seed, 0UL ) );
    if( FD_UNLIKELY( !rng ) ) FD_LOG_ERR(( "fd_rng_join failed" ));

    fd_sha512_t _sha[1];
    fd_sha512_t * sha = fd_sha512_join( fd_sha512_new( _sha ) );
    if( FD_UNLIKELY( !sha ) ) FD_LOG_ERR(( "fd_sha512 join failed" ));

    ulong ref_msg_mem_footprint = 0UL;
    for( ulong msg_sz=MSG_SZ_MIN; msg_sz<=MSG_SZ_MAX; msg_sz++ ) ref_msg_mem_footprint += fd_ulong_align_up( msg_sz + 96UL, 128UL );
    uchar * ref_msg_mem = fd_alloca( 128UL, ref_msg_mem_footprint );
    if( FD_UNLIKELY( !ref_msg_mem ) ) FD_LOG_ERR(( "fd_alloc failed" ));

    uchar * ref_msg[ MSG_SZ_MAX - MSG_SZ_MIN + 1UL ];
    for( ulong msg_sz=MSG_SZ_MIN; msg_sz<=MSG_SZ_MAX; msg_sz++ ) {
      /* ref_msg[i] is a pointer to the message with size i */
      ref_msg[ msg_sz - MSG_SZ_MIN ] = ref_msg_mem;
      uchar * public_key = ref_msg_mem;
      uchar * sig        = public_key  + 32UL;
      uchar * msg        = sig         + 64UL;
      ref_msg_mem += fd_ulong_align_up( msg_sz + 96UL, 128UL );

      /* Generate a public_key / private_key pair for this message */
      ulong private_key[4]; for( ulong i=0UL; i<4UL; i++ ) private_key[i] = fd_rng_ulong( rng );
      fd_ed25519_public_from_private( public_key, private_key, sha );

      /* Make a random message */
      for( ulong b=0UL; b<msg_sz; b++ ) msg[b] = fd_rng_uchar( rng );

      /* Sign it */
      fd_ed25519_sign( sig, msg, msg_sz, public_key, private_key, sha );
    }

    /* Sanity check the ref messages verify */
    for( ulong msg_sz=MSG_SZ_MIN; msg_sz<=MSG_SZ_MAX; msg_sz++ ) {
      uchar * public_key = ref_msg[ msg_sz - MSG_SZ_MIN ];
      uchar * sig        = public_key + 32UL;
      uchar * msg        = sig        + 64UL;
      FD_TEST( fd_ed25519_verify( msg, msg_sz, sig, public_key, sha )==FD_ED25519_SUCCESS );
    }

    /* Create the QUIC batches, each with a single message in. */
    for( ulong msg_sz=MSG_SZ_MIN; msg_sz<=MSG_SZ_MAX; msg_sz++ ) {
      batches[msg_sz - MSG_SZ_MIN]->buf = ref_msg[ msg_sz - MSG_SZ_MIN ];
      batches[msg_sz - MSG_SZ_MIN]->buf_sz = (ushort)msg_sz;
    }

    fd_sha512_delete ( fd_sha512_leave( sha    ) );
    fd_rng_delete    ( fd_rng_leave   ( rng    ) );
  } while(0);

  ulong sent   = 0;
  long  t0     = fd_log_wallclock();
  ulong msg_sz = MSG_SZ_MIN;

  cur_stream = NULL;

  /* Continually send data while we have a valid connection */
  while(1) {
    if ( !client_conn ) {
      break;
    }

    fd_quic_service( quic );
    fd_xsk_aio_service( xsk_aio );

    /* obtain a free stream */
    while(1) {

      if( cur_stream ) {
        int rc = fd_quic_stream_send( cur_stream, batches[msg_sz - MSG_SZ_MIN], 1 /* batch_sz */, 1 /* fin */ ); /* fin: close stream after sending. last byte of transmission */
        FD_LOG_DEBUG(( "fd_quic_stream_send returned %d", rc ));

        if( rc == 1 ) {
          sent++;
          /* successful - stream will begin closing */
          /* stream and meta will be recycled when quic notifies the stream
             is closed via my_stream_notify_cb */

          msg_sz++;
          if ( msg_sz == MSG_SZ_MAX ) {
            msg_sz = MSG_SZ_MIN;
          }
          cur_stream = NULL;
        } else {
          /* did not send, did not start finalize, so stream is still available */
          break;
        }
      } else {
        if( client_conn ) {
          cur_stream = fd_quic_conn_new_stream( client_conn, FD_QUIC_TYPE_UNIDIR );
        }
        break;
      }

      if( client_conn && !cur_stream ) {
        cur_stream = fd_quic_conn_new_stream( client_conn, FD_QUIC_TYPE_UNIDIR );
      }
    }

    long t1 = fd_log_wallclock();
    if( t1 >= t0 ) {
      printf( "streams: %lu  cur_stream: %p\n", sent, (void*)cur_stream ); fflush( stdout );
      sent = 0;
      t0 = t1 + (long)1e9;
    }
  }

  do {
    /* close the connections */
    if( client_conn ) {
      fd_quic_conn_close( client_conn, 0 );
      client_conn = NULL;
    }

    fd_quic_leave( quic );

    FD_LOG_NOTICE(( "Finished QUIC client" ));
  } while(0);
}

int
main( int argc, char ** argv ) {
  fd_boot( &argc, &argv );

  ulong cpu_idx = fd_tile_cpu_id( fd_tile_idx() );
  if( cpu_idx>=fd_shmem_cpu_cnt() ) cpu_idx = 0UL;

  char const * _page_sz  = fd_env_strip_cmdline_cstr  ( &argc, &argv, "--page-sz",        NULL, "gigantic"                   );
  ulong        page_cnt  = fd_env_strip_cmdline_ulong ( &argc, &argv, "--page-cnt",       NULL, 1UL                          );
  ulong        numa_idx  = fd_env_strip_cmdline_ulong ( &argc, &argv, "--numa-idx",       NULL, fd_shmem_numa_idx(cpu_idx)   );
  ulong        xdp_mtu   = fd_env_strip_cmdline_ulong ( &argc, &argv, "--xdp-mtu",        NULL, 2048UL                       );
  ulong        xdp_depth = fd_env_strip_cmdline_ulong ( &argc, &argv, "--xdp-depth",      NULL, 1024UL                       );
  char const * iface     = fd_env_strip_cmdline_cstr  ( &argc, &argv, "--iface",          NULL, NULL                         );
  uint         ifqueue   = fd_env_strip_cmdline_uint  ( &argc, &argv, "--ifqueue",        NULL, 0U                           );
  char const * _src_ip   = fd_env_strip_cmdline_cstr  ( &argc, &argv, "--src-ip",         NULL, NULL                         );
  char const * _dst_ip   = fd_env_strip_cmdline_cstr  ( &argc, &argv, "--dst-ip",         NULL, NULL                         );
  uint         src_port  = fd_env_strip_cmdline_uint  ( &argc, &argv, "--src-port",       NULL, 8080U                        );
  uint         dst_port  = fd_env_strip_cmdline_uint  ( &argc, &argv, "--dst-port",       NULL, 9001U                        );
  char const * _hwaddr   = fd_env_strip_cmdline_cstr  ( &argc, &argv, "--hwaddr",         NULL, NULL                         );
  char const * _gateway  = fd_env_strip_cmdline_cstr  ( &argc, &argv, "--gateway",        NULL, NULL                         );
  char const * bpf_dir   = fd_env_strip_cmdline_cstr  ( &argc, &argv, "--bpf-dir",        NULL, "test_quic"                  );

  ulong page_sz = fd_cstr_to_shmem_page_sz( _page_sz );
  if( FD_UNLIKELY( !page_sz ) ) FD_LOG_ERR(( "unsupported --page-sz" ));

  if( FD_UNLIKELY( !_src_ip  ) ) FD_LOG_ERR(( "missing --src-ip"   ));
  if( FD_UNLIKELY( !src_port ) ) FD_LOG_ERR(( "missing --src-port" ));
  if( FD_UNLIKELY( !_dst_ip  ) ) FD_LOG_ERR(( "missing --dst-ip"   ));
  if( FD_UNLIKELY( !dst_port ) ) FD_LOG_ERR(( "missing --dst-port" ));

  if( FD_UNLIKELY( !_hwaddr  ) ) FD_LOG_ERR(( "missing --hwaddr" ));
  uchar hwaddr[ 6 ]={0};
  if( FD_UNLIKELY( !fd_cstr_to_mac_addr( _hwaddr,  hwaddr  ) ) )
    FD_LOG_ERR(( "invalid hwaddr \"%s\"",  _hwaddr  ));

  if( FD_UNLIKELY( !_gateway ) ) FD_LOG_ERR(( "missing --gateway" ));
  uchar gateway[ 6 ]={0};
  if( FD_UNLIKELY( !fd_cstr_to_mac_addr( _gateway, gateway ) ) )
    FD_LOG_ERR(( "invalid gateway \"%s\"", _gateway ));

  uint src_ip;
  if( FD_UNLIKELY( !fd_cstr_to_ip4_addr( _src_ip, &src_ip  ) ) ) FD_LOG_ERR(( "invalid --src-ip" ));
  uint dst_ip;
  if( FD_UNLIKELY( !fd_cstr_to_ip4_addr( _dst_ip, &dst_ip  ) ) ) FD_LOG_ERR(( "invalid --dst-ip" ));

  FD_LOG_NOTICE(( "Creating workspace with --page-cnt %lu --page-sz %s pages on --numa-idx %lu", page_cnt, _page_sz, numa_idx ));
  fd_wksp_t * wksp = fd_wksp_new_anonymous( page_sz, page_cnt, fd_shmem_cpu_idx( numa_idx ), "wksp", 0UL );
  FD_TEST( wksp );

  fd_quic_limits_t quic_limits = {0};
  fd_quic_limits_from_env( &argc, &argv, &quic_limits );
  quic_limits.conn_id_sparsity = 4.0;

  ulong quic_footprint = fd_quic_footprint( &quic_limits );
  FD_TEST( quic_footprint );
  FD_LOG_NOTICE(( "QUIC footprint: %lu bytes", quic_footprint ));

  FD_LOG_NOTICE(( "Creating client QUIC" ));
  fd_quic_t * quic = fd_quic_new(
      fd_wksp_alloc_laddr( wksp, fd_quic_align(), fd_quic_footprint( &quic_limits ), 1UL ),
      &quic_limits );
  FD_TEST( quic );

  fd_quic_config_t * client_cfg = fd_quic_get_config( quic );

  client_cfg->role = FD_QUIC_ROLE_CLIENT;

  FD_TEST( fd_quic_config_from_env( &argc, &argv, client_cfg ) );

  memcpy( client_cfg->link.dst_mac_addr, gateway, 6UL );
  memcpy( client_cfg->link.src_mac_addr, hwaddr,  6UL );

  client_cfg->net.ip_addr           = src_ip;
  client_cfg->net.ephem_udp_port.lo = (ushort)src_port;
  client_cfg->net.ephem_udp_port.hi = (ushort)(src_port + 1);

  /* create a new XSK instance */
  ulong xsk_sz   = fd_xsk_footprint( xdp_mtu, xdp_depth, xdp_depth, xdp_depth, xdp_depth );

  FD_LOG_NOTICE(( "Creating XSK" ));
  void * xsk_mem = fd_wksp_alloc_laddr( wksp, fd_xsk_align(), xsk_sz, 1UL );
  FD_TEST( fd_xsk_new( xsk_mem, xdp_mtu, xdp_depth, xdp_depth, xdp_depth, xdp_depth ) );

  FD_LOG_NOTICE(( "Binding XSK (--iface %s, --ifqueue %u)", iface, ifqueue ));
  FD_TEST( fd_xsk_bind( xsk_mem, bpf_dir, iface, ifqueue ) );

  FD_LOG_NOTICE(( "Joining XSK" ));
  fd_xsk_t * xsk = fd_xsk_join( xsk_mem );
  FD_TEST( xsk );

  FD_LOG_NOTICE(( "Creating fd_xsk_aio" ));
  void * xsk_aio_mem =
    fd_wksp_alloc_laddr( wksp,fd_xsk_aio_align(), fd_xsk_aio_footprint( xdp_depth, xdp_depth ), 1UL );
  FD_TEST( fd_xsk_aio_new( xsk_aio_mem, xdp_depth, xdp_depth ) );

  fd_xsk_aio_t * xsk_aio = fd_xsk_aio_join( xsk_aio_mem, xsk );
  FD_TEST( xsk_aio );

  /* add udp port to xdp map */
  uint proto = 1;
  FD_TEST( 0==fd_xdp_listen_udp_port( bpf_dir, src_ip, src_port, proto ) );

  /* loop continually, so that if the connection dies we try again */
  while (1) {
    run_quic_client( quic, xsk_aio, dst_ip, (ushort)dst_port );
  }

  fd_quic_delete( quic );

  fd_wksp_free_laddr( xsk_aio_mem );
  fd_wksp_free_laddr( xsk_mem     );

  fd_wksp_delete_anonymous( wksp );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
