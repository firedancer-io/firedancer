#include "../fd_quic.h"

#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#include "../../xdp/fd_xdp.h"
#include "../../../ballet/sha512/fd_sha512.h"
#include "../../../ballet/ed25519/fd_ed25519.h"
#include "../../../util/net/fd_eth.h"
#include "../../../util/net/fd_ip4.h"

#define BUF_SZ (1<<20)
#define LG_FRAME_SIZE 11
#define FRAME_SIZE (1<<LG_FRAME_SIZE)

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
  printf( "before obtaining stream. count: %u\n", get_free_count() );

  my_stream_meta_t * meta = stream_avail;
  if( meta ) {
    stream_avail = meta->next;
    meta->next   = NULL;
  }

  printf( "after obtaining stream. count: %u\n", get_free_count() );

  return meta;
}

/* push stream meta into front of free list */
void
free_stream( my_stream_meta_t * meta ) {
  printf( "before freeing stream. count: %u\n", get_free_count() );

  meta->next   = stream_avail;
  stream_avail = meta;

  printf( "freed stream. count: %u\n", get_free_count() );
  fflush( stdout );
}

void
populate_streams( ulong sz, fd_quic_conn_t * conn ) {
  for( ulong j = 0; j < sz; ++j ) {
    printf("populating streams\n");
    fflush( stdout );

    /* get free stream meta */
    my_stream_meta_t * meta = get_stream_meta();
    printf("meta: %p\n", (void*)meta);
    fflush( stdout );

    printf("conn: %p\n", (void*)conn);
    printf("conn state: %d\n", conn->state);
    fflush( stdout );

    /* obtain stream */
    fd_quic_stream_t * stream =
      fd_quic_conn_new_stream( conn, FD_QUIC_TYPE_UNIDIR );

    printf("stream: %p", (void*)stream);
    fflush( stdout );

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
      printf( "reclaiming stream\n" );
      fflush( stdout );

      if( stream->conn->server ) {
        /* This should never happen */
        printf( "SERVER\n" );
        fflush( stdout );
      } else {
        printf( "CLIENT\n" );
        fflush( stdout );

        /* obtain new stream */
        fd_quic_stream_t * new_stream =
          fd_quic_conn_new_stream( stream->conn, FD_QUIC_TYPE_UNIDIR );

        if( !new_stream ) {
          fprintf( stderr, "fd_quic_conn_new_stream returned NULL\n" );
          exit(1);
        }

        /* set context on stream to meta */
        fd_quic_stream_set_context( new_stream, meta );

        /* populate meta */
        meta->stream = new_stream;

        /* return meta */
        free_stream( meta );
      }
      break;

    default:
      printf( "NOTIFY: %x\n", type );
      fflush( stdout );
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

ulong test_clock( void * ctx ) {
  (void)ctx;

  struct timespec ts;
  clock_gettime( CLOCK_REALTIME, &ts );

  return (ulong)ts.tv_sec * (ulong)1e9 + (ulong)ts.tv_nsec;
}

void create_and_run_quic_client(
  fd_quic_config_t * quic_config,
  fd_xsk_aio_t * xsk_aio,
  uint dst_ip,
  ushort dst_port) {

  fd_quic_t * client_quic = new_quic( quic_config );

  /* use XSK XDP AIO for QUIC ingress/egress */
  fd_aio_t ingress = *fd_quic_get_aio_net_in( client_quic );
  fd_xsk_aio_set_rx( xsk_aio, &ingress );
  fd_aio_t egress = *fd_xsk_aio_get_tx( xsk_aio );
  fd_quic_set_aio_net_out( client_quic, &egress );

  /* set the callback for handshake complete */
  fd_quic_set_cb_conn_handshake_complete( client_quic, my_handshake_complete );
  fd_quic_set_cb_conn_final( client_quic, my_connection_closed );

  /* make a connection from client to the server */
  client_conn = fd_quic_connect( client_quic, dst_ip, dst_port );

  /* do general processing */
  while ( !client_complete ) {
    fd_quic_service( client_quic );
    fd_xsk_aio_service( xsk_aio );
  }
  printf( "***** client handshake complete *****\n" );

  /* populate free streams */
  populate_stream_meta( quic_config->max_concur_streams );
  populate_streams( quic_config->max_concur_streams, client_conn );

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
    fd_quic_service( client_quic );
    fd_xsk_aio_service( xsk_aio );

    if ( !client_conn ) {
      break;
    }

    /* obtain an free stream */
    my_stream_meta_t * meta = get_stream();

    if( meta ) {
      fd_quic_stream_t * stream = meta->stream;

      int rc = fd_quic_stream_send( stream, batches[msg_sz - MSG_SZ_MIN], 1 /* batch_sz */, 1 /* fin */ ); /* fin: close stream after sending. last byte of transmission */
      printf( "fd_quic_stream_send returned %d\n", rc );

      if( rc == 1 ) {
        /* successful - stream will begin closing */
        /* stream and meta will be recycled when quic notifies the stream
           is closed via my_stream_notify_cb */
      } else {
        /* did not send, did not start finalize, so stream is still available */
        free_stream( meta );
      }
    } else {
      printf( "unable to send - no streams available\n" );
      fflush( stdout );
    }

    if ( msg_sz == MSG_SZ_MAX ) {
      msg_sz = MSG_SZ_MIN;
    }
  }

  /* close the connections */
  fd_quic_conn_close( client_conn, 0 );
  fd_sha512_delete ( fd_sha512_leave( sha    ) );
  fd_rng_delete    ( fd_rng_leave   ( rng    ) );

  fd_quic_delete( client_quic );

}

int
main( int argc, char ** argv ) {
  fd_boot( &argc, &argv );

  ulong cpu_idx = fd_tile_cpu_id( fd_tile_idx() );
  if( cpu_idx>=fd_shmem_cpu_cnt() ) cpu_idx = 0UL;

  char const * _page_sz       = fd_env_strip_cmdline_cstr  ( &argc, &argv, "--page-sz",        NULL, "gigantic"                 );
  ulong        page_cnt       = fd_env_strip_cmdline_ulong ( &argc, &argv, "--page-cnt",       NULL, 1UL                        );
  ulong        numa_idx       = fd_env_strip_cmdline_ulong ( &argc, &argv, "--numa-idx",       NULL, fd_shmem_numa_idx(cpu_idx) );
  char const * iface          = fd_env_strip_cmdline_cstr  ( &argc, &argv, "--iface",          NULL, NULL                       );
  uint         ifqueue        = fd_env_strip_cmdline_uint  ( &argc, &argv, "--ifqueue",        NULL, 0U                         );
  char const * _src_mac       = fd_env_strip_cmdline_cstr  ( &argc, &argv, "--src-mac",        NULL, NULL                       );
  char const * _src_ip        = fd_env_strip_cmdline_cstr  ( &argc, &argv, "--src-ip",         NULL, NULL                       );
  ushort       src_port       = fd_env_strip_cmdline_ushort( &argc, &argv, "--src-port",       NULL, 0U                         );
  char const * _dst_mac       = fd_env_strip_cmdline_cstr  ( &argc, &argv, "--dst-mac",        NULL, NULL                       );
  char const * _dst_ip        = fd_env_strip_cmdline_cstr  ( &argc, &argv, "--dst-ip",         NULL, NULL                       );
  ushort       dst_port       = fd_env_strip_cmdline_ushort( &argc, &argv, "--dst-port",       NULL, 0U                         );

  ulong page_sz = fd_cstr_to_shmem_page_sz( _page_sz );
  if( FD_UNLIKELY( !page_sz ) ) FD_LOG_ERR(( "unsupported --page-sz" ));

  if( FD_UNLIKELY( !_src_mac ) ) FD_LOG_ERR(( "missing --src-mac"  ));
  if( FD_UNLIKELY( !_src_ip  ) ) FD_LOG_ERR(( "missing --src-ip"   ));
  if( FD_UNLIKELY( !src_port ) ) FD_LOG_ERR(( "missing --src-port" ));
  if( FD_UNLIKELY( !_dst_mac ) ) FD_LOG_ERR(( "missing --dst-mac"  ));
  if( FD_UNLIKELY( !_dst_ip  ) ) FD_LOG_ERR(( "missing --dst-ip"   ));
  if( FD_UNLIKELY( !dst_port ) ) FD_LOG_ERR(( "missing --dst-port" ));

  uchar src_mac[6];
  if( FD_UNLIKELY( !fd_cstr_to_mac_addr( _src_mac, src_mac ) ) ) FD_LOG_ERR(( "invalid --src-mac" ));
  uchar dst_mac[6];
  if( FD_UNLIKELY( !fd_cstr_to_mac_addr( _dst_mac, dst_mac ) ) ) FD_LOG_ERR(( "invalid --dst-mac" ));
  uint src_ip;
  if( FD_UNLIKELY( !fd_cstr_to_ip4_addr( _src_ip, &src_ip  ) ) ) FD_LOG_ERR(( "invalid --src-ip" ));
  uint dst_ip;
  if( FD_UNLIKELY( !fd_cstr_to_ip4_addr( _dst_ip, &dst_ip  ) ) ) FD_LOG_ERR(( "invalid --dst-ip" ));

  fd_quic_limits_t quic_limits = {0};
  fd_quic_limits_from_env( &argc, &argv, &quic_limits);

  FD_LOG_NOTICE(( "Creating workspace with --page-cnt %lu --page-sz %s pages on --numa-idx %lu", page_cnt, _page_sz, numa_idx ));
  fd_wksp_t * wksp = fd_wksp_new_anonymous( page_sz, page_cnt, fd_shmem_cpu_idx( numa_idx ), "wksp", 0UL );
  FD_TEST( wksp );

  /* Transport params:
     - original_destination_connection_id (0x00)         :   len(0)
     - max_idle_timeout (0x01)                           : * 60000
     - stateless_reset_token (0x02)                      :   len(0)
     - max_udp_payload_size (0x03)                       :   0
     - initial_max_data (0x04)                           : * 1048576
     - initial_max_stream_data_bidi_local (0x05)         : * 1048576
     - initial_max_stream_data_bidi_remote (0x06)        : * 1048576
     - initial_max_stream_data_uni (0x07)                : * 1048576
     - initial_max_streams_bidi (0x08)                   : * 128
     - initial_max_streams_uni (0x09)                    : * 128
     - ack_delay_exponent (0x0a)                         : * 3
     - max_ack_delay (0x0b)                              : * 25
     - disable_active_migration (0x0c)                   :   0
     - preferred_address (0x0d)                          :   len(0)
     - active_connection_id_limit (0x0e)                 : * 8
     - initial_source_connection_id (0x0f)               : * len(8) ec 73 1b 41 a0 d5 c6 fe
     - retry_source_connection_id (0x10)                 :   len(0) */

  fd_quic_transport_params_t tp = {
    .max_idle_timeout                            = 60000,
    .max_idle_timeout_present                    = 1,
    .initial_max_data                            = 1048576,
    .initial_max_data_present                    = 1,
    .initial_max_stream_data_bidi_local          = 1048576,
    .initial_max_stream_data_bidi_local_present  = 1,
    .initial_max_stream_data_bidi_remote         = 1048576,
    .initial_max_stream_data_bidi_remote_present = 1,
    .initial_max_stream_data_uni                 = 1048576,
    .initial_max_stream_data_uni_present         = 1,
    .initial_max_streams_bidi                    = 1000,
    .initial_max_streams_bidi_present            = 1,
    .initial_max_streams_uni                     = 1000,
    .initial_max_streams_uni_present             = 1,
    .ack_delay_exponent                          = 3,
    .ack_delay_exponent_present                  = 1,
    .max_ack_delay                               = 25,
    .max_ack_delay_present                       = 1,
    .active_connection_id_limit                  = 8,
    .active_connection_id_limit_present          = 1
  };

  tp->initial_max_streams_bidi = quic_max_stream_cnt;
  tp->initial_max_streams_uni  = quic_max_stream_cnt;

  /* QUIC configuration */
  fd_quic_config_t quic_config = {0};

  quic_config.transport_params      = tp;

  strcpy( quic_config.cert_file, "cert.pem" );
  strcpy( quic_config.key_file,  "key.pem"  );

  fd_quic_callbacks_t quic_cb = {
    .stream_receive = my_stream_receive_cb,
    .stream_notify  = my_stream_notify_cb,

    .now     = test_clock,
    .now_ctx = NULL
  };

  fd_memcpy( quic_config.net.default_route_mac, dft_route_mac, 6 );
  fd_memcpy( quic_config.net.src_mac, src_mac, 6 );

  /* hostname, ip_addr, udp port */
  fd_quic_host_cfg_t client_cfg = { "client_host", src_ip, src_port };

  quic_config.host_cfg = client_cfg;
  quic_config.udp_ephem.lo = src_port;
  quic_config.udp_ephem.hi = (ushort)(src_port + 1);

  /* create a new XSK instance */
  ulong frame_sz = FRAME_SIZE;
  ulong depth    = 1ul << 10ul;
  ulong xsk_sz   = fd_xsk_footprint( frame_sz, depth, depth, depth, depth );

  FD_LOG_NOTICE(( "Creating XSK" ));
  void * xsk_mem = fd_wksp_alloc_laddr( wksp, fd_xsk_align(), xsk_sz, 1UL );
  FD_TEST( fd_xsk_new( xsk_mem, frame_sz, depth, depth, depth, depth ) );

  FD_LOG_NOTICE(( "Binding XSK (--iface %s, --ifqueue %u)", iface, ifqueue ));
  FD_TEST( fd_xsk_bind( xsk_mem, app_name, iface, ifqueue ) );

  FD_LOG_NOTICE(( "Joining XSK" ));
  fd_xsk_t * xsk = fd_xsk_join( xsk_mem );
  FD_TEST( xsk );

  FD_LOG_NOTICE(( "Creating fd_xsk_aio" ));
  void * xsk_aio_mem =
    fd_wksp_alloc_laddr( wksp,fd_xsk_aio_align(), fd_xsk_aio_footprint( depth, xsk_pkt_cnt ) ) );
  FD_TEST( fd_xsk_aio_new( xsk_aio_mem, depth, xsk_pkt_cnt ) );

  fd_xsk_aio_t * xsk_aio = fd_xsk_aio_join( xsk_aio_mem, xsk );
  FD_TEST( xsk_aio );

  /* add udp port to xdp map */
  uint proto = 1;
  FD_TEST( 0==fd_xdp_listen_udp_port( app_name, src_ip, src_port, proto ) );

  /* loop continually, so that if the connection dies we try again */
  while (1) {
    create_and_run_quic_client(&quic_config, xsk_aio, dst_ip, dst_port );
  }

  fd_wksp_free_laddr( xsk_aio_mem );
  fd_wksp_free_laddr( xsk_mem     );

  fd_wksp_delete_anonymous( wksp );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
