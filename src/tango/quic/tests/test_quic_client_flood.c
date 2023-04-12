#include "../fd_quic.h"

#include <stdlib.h>

#include "../../xdp/fd_xdp.h"
#include "../../../ballet/sha512/fd_sha512.h"
#include "../../../ballet/ed25519/fd_ed25519.h"
#include "../../../util/fd_util.h"
#include "../../../util/net/fd_eth.h"
#include "../../../util/net/fd_ip4.h"

typedef struct my_stream_meta my_stream_meta_t;
struct my_stream_meta {
  fd_quic_stream_t * stream;
  my_stream_meta_t * next;
};

my_stream_meta_t * meta_free;

/* populate meta_free with free stream meta */
void
populate_stream_meta( ulong sz ) {
  my_stream_meta_t * prev = NULL;

  for( ulong j = 0; j < sz; ++j ) {
    my_stream_meta_t * meta = (my_stream_meta_t*)malloc( sizeof( my_stream_meta_t ) );
    meta->stream = NULL;
    meta->next   = NULL;
    if( !prev ) {
      meta_free = meta;
    } else {
      prev->next  = meta;
    }

    prev = meta;
  }
}

/* get free stream meta */
my_stream_meta_t *
get_stream_meta( void ) {
  my_stream_meta_t * meta = meta_free;
  if( meta ) {
    meta_free  = meta->next;
    meta->next = NULL;
  }
  return meta;
}

/* push stream meta into front of free list */
void
free_stream_meta( my_stream_meta_t * meta ) {
  meta->next  = meta_free;
  meta_free = meta;
}

my_stream_meta_t * stream_avail = NULL;

/* get count of free streams */
uint
get_free_count( void ) {
  uint count = 0u;
  my_stream_meta_t * cur = stream_avail;
  while( cur ) {
    count ++;
    cur = cur->next;
  }
  return count;
}

/* get free stream */
my_stream_meta_t *
get_stream( void ) {
  my_stream_meta_t * meta = stream_avail;
  if( meta ) {
    stream_avail = meta->next;
    meta->next   = NULL;
  }
  return meta;
}

/* push stream meta into front of free list */
void
free_stream( my_stream_meta_t * meta ) {
  meta->next   = stream_avail;
  stream_avail = meta;
}

void
populate_streams( ulong sz, fd_quic_conn_t * conn ) {
  for( ulong j = 0; j < sz; ++j ) {
    /* get free stream meta */
    my_stream_meta_t * meta = get_stream_meta();

    /* obtain stream */
    fd_quic_stream_t * stream =
      fd_quic_conn_new_stream( conn, FD_QUIC_TYPE_UNIDIR );

    /* set context on stream to meta */
    /* stream here is null */
    fd_quic_stream_set_context( stream, meta );

    /* populate meta */
    meta->stream = stream;

    /* insert into avail list */
    free_stream( meta );
  }
}

extern uchar pkt_full[];
extern ulong pkt_full_sz;

void
my_stream_notify_cb( fd_quic_stream_t * stream, void * ctx, int type ) {
  (void)stream;
  my_stream_meta_t * meta = (my_stream_meta_t*)ctx;
  switch( type ) {
    case FD_QUIC_NOTIFY_END:
      FD_LOG_DEBUG(( "stream end" ));

      FD_TEST( !stream->conn->server );

      /* obtain new stream */
      fd_quic_stream_t * new_stream =
        fd_quic_conn_new_stream( stream->conn, FD_QUIC_TYPE_UNIDIR );
      FD_TEST( new_stream );

      /* set context on stream to meta */
      fd_quic_stream_set_context( new_stream, meta );

      /* populate meta */
      meta->stream = new_stream;

      /* return meta */
      free_stream( meta );
      break;

    default:
      FD_LOG_INFO(( "stream notify: %#x", type ));
      break;
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
  fd_log_flush();

  client_complete = 1;
}

/* Connection closed */
void my_connection_closed( fd_quic_conn_t * conn, void * vp_context ) {
  (void)conn;
  (void)vp_context;

  FD_LOG_INFO(( "client conn closed" ));
  fd_log_flush();

  client_conn = NULL;
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

  /* make a connection from client to the server */
  client_conn = fd_quic_connect( quic, dst_ip, dst_port, NULL );

  /* do general processing */
  while ( !client_complete ) {
    fd_quic_service( quic );
    fd_xsk_aio_service( xsk_aio );
  }
  FD_LOG_NOTICE(( "Client handshake complete" ));

  /* populate free streams */
  populate_stream_meta( quic->limits.stream_cnt              );
  populate_streams    ( quic->limits.stream_cnt, client_conn );

  /* create and sign fake ref message txns */
  /* generate a message for every possible message size, using code from fd_frank_verify_synth_load */
  fd_rng_t _rng[ 1 ];
  uint seed = (uint)fd_tile_id();
  fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, seed, 0UL ) );
  if( FD_UNLIKELY( !rng ) ) FD_LOG_ERR(( "fd_rng_join failed" ));

  fd_sha512_t _sha[1];
  fd_sha512_t * sha = fd_sha512_join( fd_sha512_new( _sha ) );
  if( FD_UNLIKELY( !sha ) ) FD_LOG_ERR(( "fd_sha512 join failed" ));

  #define MSG_SZ_MIN (0UL)
  #define MSG_SZ_MAX (1232UL-64UL-32UL)
  #define MSG_SIZE_RANGE (MSG_SZ_MAX - MSG_SZ_MIN + 1UL)

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
  fd_aio_pkt_info_t batches[MSG_SIZE_RANGE][1];
  for( ulong msg_sz=MSG_SZ_MIN; msg_sz<=MSG_SZ_MAX; msg_sz++ ) {
    batches[msg_sz - MSG_SZ_MIN]->buf = ref_msg[ msg_sz - MSG_SZ_MIN ];
    batches[msg_sz - MSG_SZ_MIN]->buf_sz = (ushort)msg_sz;
  }

  /* Continually send data while we have a valid connection */
  for ( ulong msg_sz=MSG_SZ_MIN; msg_sz<=MSG_SZ_MAX; msg_sz++ ) {
    fd_quic_service( quic );
    fd_xsk_aio_service( xsk_aio );

    if ( !client_conn ) {
      break;
    }

    /* obtain an free stream */
    my_stream_meta_t * meta = get_stream();

    if( meta ) {
      fd_quic_stream_t * stream = meta->stream;

      int rc = fd_quic_stream_send( stream, batches[msg_sz - MSG_SZ_MIN], 1 /* batch_sz */, 1 /* fin */ ); /* fin: close stream after sending. last byte of transmission */
      FD_LOG_DEBUG(( "fd_quic_stream_send returned %d", rc ));

      if( rc == 1 ) {
        /* successful - stream will begin closing */
        /* stream and meta will be recycled when quic notifies the stream
           is closed via my_stream_notify_cb */
      } else {
        /* did not send, did not start finalize, so stream is still available */
        free_stream( meta );
      }
    } else {
      FD_LOG_ERR(( "unable to send. no streams available" ));
    }

    if ( msg_sz == MSG_SZ_MAX ) {
      msg_sz = MSG_SZ_MIN;
    }
  }

  /* close the connections */
  fd_quic_conn_close( client_conn, 0 );
  fd_sha512_delete ( fd_sha512_leave( sha    ) );
  fd_rng_delete    ( fd_rng_leave   ( rng    ) );

  fd_quic_leave( quic );
}

int
main( int argc, char ** argv ) {
  fd_boot( &argc, &argv );

  ulong cpu_idx = fd_tile_cpu_id( fd_tile_idx() );
  if( cpu_idx>=fd_shmem_cpu_cnt() ) cpu_idx = 0UL;

  char const * _page_sz  = fd_env_strip_cmdline_cstr  ( &argc, &argv, "--page-sz",        NULL, "gigantic"                 );
  ulong        page_cnt  = fd_env_strip_cmdline_ulong ( &argc, &argv, "--page-cnt",       NULL, 1UL                        );
  ulong        numa_idx  = fd_env_strip_cmdline_ulong ( &argc, &argv, "--numa-idx",       NULL, fd_shmem_numa_idx(cpu_idx) );
  ulong        xdp_mtu   = fd_env_strip_cmdline_ulong ( &argc, &argv, "--xdp-mtu",        NULL, 2048UL                       );
  ulong        xdp_depth = fd_env_strip_cmdline_ulong ( &argc, &argv, "--xdp-depth",      NULL, 1024UL                       );
  char const * iface     = fd_env_strip_cmdline_cstr  ( &argc, &argv, "--iface",          NULL, NULL                         );
  uint         ifqueue   = fd_env_strip_cmdline_uint  ( &argc, &argv, "--ifqueue",        NULL, 0U                           );
  char const * _src_ip   = fd_env_strip_cmdline_cstr  ( &argc, &argv, "--src-ip",         NULL, NULL                       );
  char const * _dst_ip   = fd_env_strip_cmdline_cstr  ( &argc, &argv, "--dst-ip",         NULL, NULL                       );
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
