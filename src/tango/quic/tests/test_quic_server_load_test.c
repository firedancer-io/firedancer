#include "../fd_quic.h"

#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#include "../../xdp/fd_xdp.h"

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
get_stream_meta() {
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
get_free_count() {
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
get_stream() {
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

  printf( "my_stream_receive_cb : received data from peer. size: %lu  offset: %lu\n",
      (ulong)data_sz, (ulong)offset );
  printf( "%s\n", data );

}

void
parse_mac( uchar * dst, char const * src ) {
  uint a[6] = {0};
  int r = sscanf( src, "%x:%x:%x:%x:%x:%x", a, a+1, a+2, a+3, a+4, a+5 );
  if( r != 6 ) {
    FD_LOG_ERR(( "Invalid MAC address: %s", src ));
  }

  for( size_t j = 0; j < 6; ++j ) {
    dst[j] = (uchar)a[j];
  }
}

void
parse_ipv4_addr( uint * dst, char const * src ) {
  uint a[4] = {0};
  int r = sscanf( src, "%u.%u.%u.%u", a, a+1, a+2, a+3 );
  if( r != 4 ) {
    FD_LOG_ERR(( "Invalid ipv4 address: %s", src ));
  }

  *dst = ( a[0] << 030 ) | ( a[1] << 020 ) | ( a[2] << 010 ) | a[3];
}

fd_quic_conn_t * client_conn = NULL;

fd_quic_t *
new_quic( fd_quic_config_t * quic_config ) {

  ulong  align    = fd_quic_align();
  ulong  fp       = fd_quic_footprint( BUF_SZ,
                                       BUF_SZ,
                                       quic_config->max_concur_streams,
                                       quic_config->max_in_flight_acks,
                                       quic_config->max_concur_conns,
                                       quic_config->max_concur_conn_ids );
  void * mem      = malloc( fp + align );
  ulong smem     = (ulong)mem;
  ulong memalign = smem % align;
  void * aligned  = ((uchar*)mem) + ( memalign == 0 ? 0 : ( align - memalign ) );

  fd_quic_t * quic = fd_quic_new( aligned,
                                  BUF_SZ,
                                  BUF_SZ,
                                  quic_config->max_concur_streams,
                                  quic_config->max_in_flight_acks,
                                  quic_config->max_concur_conns,
                                  quic_config->max_concur_conn_ids );
  FD_TEST( quic );

  fd_quic_init( quic, quic_config );

  return quic;
}

int client_complete = 0;

/* Client handshake complete */
void my_handshake_complete( fd_quic_conn_t * conn, void * vp_context ) {
  (void)conn;
  (void)vp_context;

  printf( "client handshake complete\n" );
  fflush( stdout );

  client_complete = 1;
}

/* Connection closed */
void my_connection_closed( fd_quic_conn_t * conn, void * vp_context ) {
  (void)conn;
  (void)vp_context;

  printf( "client connection closed\n" );
  fflush( stdout );

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
  /* TODO: re-connect if connection dies. up to us to check the status of this. callback which notifies you if the connection fails */
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

  /* TODO: replace with actual txns */
  char buf[512] = "Hello world!\x00-   ";
  fd_aio_pkt_info_t batch[1] = {{ buf, sizeof( buf ) }};

  /* Continually send data while we have a valid connection */
  while ( client_conn ) {
    fd_quic_service( client_quic );
    fd_xsk_aio_service( xsk_aio );

    buf[12] = ' ';
    //buf[15] = (char)( ( j / 10 ) + '0' );
    buf[16] = (char)( ( 1 % 10 ) + '0' );

    /* obtain an free stream */
    my_stream_meta_t * meta = get_stream();

    if( meta ) {
      fd_quic_stream_t * stream = meta->stream;

      int rc = fd_quic_stream_send( stream, batch, 1 /* batch_sz */, 1 /* fin */ ); /* fin: close stream after sending. last byte of transmission */
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
  }

  /* close the connections */
  fd_quic_conn_close( client_conn, 0 );

  fd_quic_delete( client_quic );

}

int
main( int argc, char ** argv ) {
  (void)argc;
  (void)argv;
  // Transport params:
  //   original_destination_connection_id (0x00)         :   len(0)
  //   max_idle_timeout (0x01)                           : * 60000
  //   stateless_reset_token (0x02)                      :   len(0)
  //   max_udp_payload_size (0x03)                       :   0
  //   initial_max_data (0x04)                           : * 1048576
  //   initial_max_stream_data_bidi_local (0x05)         : * 1048576
  //   initial_max_stream_data_bidi_remote (0x06)        : * 1048576
  //   initial_max_stream_data_uni (0x07)                : * 1048576
  //   initial_max_streams_bidi (0x08)                   : * 128
  //   initial_max_streams_uni (0x09)                    : * 128
  //   ack_delay_exponent (0x0a)                         : * 3
  //   max_ack_delay (0x0b)                              : * 25
  //   disable_active_migration (0x0c)                   :   0
  //   preferred_address (0x0d)                          :   len(0)
  //   active_connection_id_limit (0x0e)                 : * 8
  //   initial_source_connection_id (0x0f)               : * len(8) ec 73 1b 41 a0 d5 c6 fe
  //   retry_source_connection_id (0x10)                 :   len(0)

  /* all zeros transport params is a reasonable default */
  fd_quic_transport_params_t tp[1] = {0};

  /* establish these parameters as "present" */
  tp->max_idle_timeout                               = 60000;
  tp->max_idle_timeout_present                       = 1;
  tp->initial_max_data                               = 1048576;
  tp->initial_max_data_present                       = 1;
  tp->initial_max_stream_data_bidi_local             = 1048576;
  tp->initial_max_stream_data_bidi_local_present     = 1;
  tp->initial_max_stream_data_bidi_remote            = 1048576;
  tp->initial_max_stream_data_bidi_remote_present    = 1;
  tp->initial_max_stream_data_uni                    = 1048576;
  tp->initial_max_stream_data_uni_present            = 1;
  tp->initial_max_streams_bidi                       = 1000;
  tp->initial_max_streams_bidi_present               = 1;
  tp->initial_max_streams_uni                        = 1000;
  tp->initial_max_streams_uni_present                = 1;
  tp->ack_delay_exponent                             = 3;
  tp->ack_delay_exponent_present                     = 1;
  tp->max_ack_delay                                  = 25;
  tp->max_ack_delay_present                          = 1;
  tp->active_connection_id_limit                     = 8;
  tp->active_connection_id_limit_present             = 1;

  /* Configuration */
  char const * app_name     = "quic_load_test";
  char const * intf         = "";
  uint ifqueue              = 0;
  uint dst_ip               = 0;
  ushort dst_port           = 0;
  uint src_ip               = 0;
  uchar src_mac[6];
  ushort src_port           = 0;
  uchar dft_route_mac[6];
  ulong xsk_pkt_cnt         = 16;
  uint quic_max_stream_cnt = 1000;

  for( int i = 1; i < argc; ++i ) {
    /* --intf */
    if( strcmp( argv[i], "--intf" ) == 0 ) {
      if( i+1 < argc ) {
        intf = argv[i+1];
        i++;
        continue;
      } else {
        fprintf( stderr, "--intf requires a value\n" );
        exit(1);
      }
    }
    if( strcmp( argv[i], "--src-ip" ) == 0 ) {
      if( i+1 < argc ) {
        parse_ipv4_addr( &src_ip, argv[i+1] );
        i++;
      } else {
        fprintf( stderr, "--src-ip requires a value\n" );
        exit(1);
      }
    }
    if( strcmp( argv[i], "--src-mac" ) == 0 ) {
      if( i+1 < argc ) {
        parse_mac( src_mac, argv[i+1] );
        i++;
      } else {
        fprintf( stderr, "--src-mac requires a value\n" );
        exit(1);
      }
    }
    if( strcmp( argv[i], "--src-port" ) == 0 ) {
      if( i+1 < argc ) {
        src_port = (ushort)strtoul( argv[i+1], NULL, 10 );
        i++;
      } else {
        fprintf( stderr, "--src-port requires a value\n" );
        exit(1);
      }
    }
    if( strcmp( argv[i], "--dst-ip" ) == 0 ) {
      if( i+1 < argc ) {
        parse_ipv4_addr( &dst_ip, argv[i+1] );
        i++;
      } else {
        fprintf( stderr, "--dst-ip requires a value\n" );
        exit(1);
      }
    }
    if( strcmp( argv[i], "--dst-port" ) == 0 ) {
      if( i+1 < argc ) {
        dst_port = (ushort)strtoul( argv[i+1], NULL, 10 );
        i++;
      } else {
        fprintf( stderr, "--dst-port requires a value\n" );
        exit(1);
      }
    }
    if( strcmp( argv[i], "--dft-route-mac" ) == 0 ) {
      if( i+1 < argc ) {
        parse_mac( dft_route_mac, argv[i+1] );
        i++;
      } else {
        fprintf( stderr, "--dft-route-mac requires a value\n" );
        exit(1);
      }
    }
    if( strcmp( argv[i], "--ifqueue" ) == 0 ) {
      if( i+1 < argc ) {
        ifqueue = (uint)strtoul( argv[i+1], NULL, 10 );
        i++;
      } else {
        fprintf( stderr, "--ifqueue requires a value\n" );
        exit(1);
      }
    }
    if( strcmp( argv[i], "--app-name" ) == 0 ) {
      if( i+1 < argc ) {
        app_name = argv[i+1];
      } else {
        fprintf( stderr, "--app-name requires a value\n" );
        exit(1);
      }
    }
    if( strcmp( argv[i], "--xsk-pkt-cnt" ) == 0 ) {
      if( i+1 < argc ) {
        xsk_pkt_cnt = strtoul( argv[i+1], NULL, 10 );
        i++;
      } else {
        fprintf( stderr, "--xsk-pkt-cnt requires a value\n" );
        exit(1);
      }
    }
    if( strcmp( argv[i], "--quic-max-stream-cnt" ) == 0 ) {
      if( i+1 < argc ) {
        quic_max_stream_cnt = (uint)strtoul( argv[i+1], NULL, 10 );
        i++;
      } else {
        fprintf( stderr, "--quic-max-stream-cnt requires a value\n" );
        exit(1);
      }
    }
  }

  tp->initial_max_streams_bidi = quic_max_stream_cnt;
  tp->initial_max_streams_uni  = quic_max_stream_cnt;

  /* QUIC configuration */
  fd_quic_config_t quic_config = {0};

  quic_config.transport_params      = tp;
  quic_config.max_concur_conns      = 10;
  quic_config.max_concur_conn_ids   = 10;
  quic_config.max_concur_streams    = quic_max_stream_cnt;
  quic_config.max_concur_handshakes = 10;
  quic_config.max_in_flight_pkts    = quic_max_stream_cnt;
  quic_config.max_in_flight_acks    = quic_max_stream_cnt;
  quic_config.conn_id_sparsity      = 4;

  strcpy( quic_config.cert_file, "cert.pem" );
  strcpy( quic_config.key_file,  "key.pem"  );

  quic_config.cb_stream_receive     = my_stream_receive_cb;
  quic_config.cb_stream_notify      = my_stream_notify_cb;

  quic_config.now_fn  = test_clock;
  quic_config.now_ctx = NULL;

  quic_config.tx_buf_sz = 1ul << 20ul;

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

  void * xsk_mem = aligned_alloc( fd_xsk_align(), xsk_sz );
  if( !fd_xsk_new( xsk_mem, frame_sz, depth, depth, depth, depth ) ) {
    fprintf( stderr, "Failed to create fd_xsk. Aborting\n" );
    exit(1);
  }

  /* bind the XKS instance */
  if( !fd_xsk_bind( xsk_mem, app_name, intf, ifqueue ) ) {
    fprintf( stderr, "Failed to bind %s to interface %s, with queue %u\n",
        app_name, intf, ifqueue );
    exit(1);
  }

  /* join */
  fd_xsk_t * xsk = fd_xsk_join( xsk_mem );

  /* new xsk_aio */
  void * xsk_aio_mem = aligned_alloc( fd_xsk_aio_align(), fd_xsk_aio_footprint( depth, xsk_pkt_cnt ) );
  if( !fd_xsk_aio_new( xsk_aio_mem, depth, xsk_pkt_cnt ) ) {
    fprintf( stderr, "Failed to create xsk_aio_mem\n" );
    exit(1);
  }

  fd_xsk_aio_t * xsk_aio = fd_xsk_aio_join( xsk_aio_mem, xsk );
  if( !xsk_aio ) {
    fprintf( stderr, "Failed to join xsk_aio_mem\n" );
    exit(1);
  }

  /* add udp port to xdp map */
  uint proto = 1;
  if( fd_xdp_listen_udp_port( app_name, src_ip, src_port, proto ) < 0 ) {
    fprintf( stderr, "unable to listen on given src udp port\n" );
    exit(1);
  }

  /* loop continually, so that if the connection dies we try again */
  while (1) {
    create_and_run_quic_client(&quic_config, xsk_aio, dst_ip, dst_port);
  }

  printf( "Finished\n" );

  return 0;
}
