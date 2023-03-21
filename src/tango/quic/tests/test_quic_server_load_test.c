#include "../fd_quic.h"

#include <stdio.h>
#include <stdlib.h>

#include "fd_pcap.h"
#include "../../xdp/fd_xsk.h"
#include "../../xdp/fd_xsk_aio.h"
#include "../../xdp/fd_xdp_redirect_user.h"

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
    /* get free stream meta */
    my_stream_meta_t * meta = get_stream_meta();

    /* obtain stream */
    fd_quic_stream_t * stream =
      fd_quic_conn_new_stream( conn, FD_QUIC_TYPE_UNIDIR );

    /* set context on stream to meta */
    fd_quic_stream_set_context( stream, meta );

    /* populate meta */
    meta->stream = stream;

    /* insert into avail list */
    free_stream( meta );
  }
}

void
write_shb( FILE * file ) {
  pcap_shb_t shb[1] = {{ 0x0A0D0D0A, sizeof( pcap_shb_t ), 0x1A2B3C4D, 1, 0, (ulong)-1, sizeof( pcap_shb_t ) }};
  ulong rc = fwrite( shb, sizeof(shb), 1, file );
  if( rc != 1 ) {
    abort();
  }
}

void
write_idb( FILE * file ) {
  pcap_idb_t idb[1] = {{ 0x00000001, sizeof( pcap_idb_t ), 1, 0, 0, sizeof( pcap_idb_t ) }};
  ulong rc = fwrite( idb, sizeof(idb), 1, file );
  if( rc != 1 ) {
    abort();
  }
}

void
write_epb( FILE * file, uchar * buf, uint buf_sz, ulong ts ) {
  if( buf_sz == 0 ) return;

  uint ts_lo = (uint)ts;
  uint ts_hi = (uint)( ts >> 32u );

  uint align_sz = ( ( buf_sz - 1u ) | 0x03u ) + 1u;
  uint tot_len  = align_sz + (uint)sizeof( pcap_epb_t ) + 4;
  pcap_epb_t epb[1] = {{
    0x00000006,
    tot_len,
    0, /* intf id */
    ts_hi,
    ts_lo,
    buf_sz,
    buf_sz }};

  ulong rc = fwrite( epb, sizeof( epb ), 1, file );
  if( rc != 1 ) {
    abort();
  }

  rc = fwrite( buf, buf_sz, 1, file );
  if( rc != 1 ) {
    abort();
  }

  if( align_sz > buf_sz ) {
    /* write padding */
    uchar pad[4] = {0};
    fwrite( pad, align_sz - buf_sz, 1, file );
  }

  rc = fwrite( &tot_len, 4, 1, file );
  if( rc != 1 ) {
    abort();
  }

}


extern uchar pkt_full[];
extern ulong pkt_full_sz;

ulong
aio_cb( void * context, fd_aio_pkt_info_t * batch, ulong batch_sz ) {
  (void)context;

  printf( "aio_cb callback\n" );
  for( ulong j = 0; j < batch_sz; ++j ) {
    printf( "batch %d\n", (int)j );
    uchar const * data = (uchar const *)batch[j].buf;
    for( ulong k = 0; k < batch[j].buf_sz; ++k ) {
      printf( "%2.2x ", (uint)data[k] );
    }
    printf( "\n\n" );
  }

  fflush( stdout );

  return batch_sz; /* consumed all */
}

uchar fail = 0;

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

/* pcap aio pipe */
struct aio_pipe {
  fd_aio_t * aio;
  FILE *     file;
};
typedef struct aio_pipe aio_pipe_t;


int
pipe_aio_receive( void * vp_ctx, fd_aio_pkt_info_t const * batch, ulong batch_sz, ulong * opt_batch_idx ) {
  static ulong ts = 0;
  ts += 100000ul;

  aio_pipe_t * pipe = (aio_pipe_t*)vp_ctx;

#if 1
  for( unsigned j = 0; j < batch_sz; ++j ) {
    write_epb( pipe->file, batch[j].buf, (unsigned)batch[j].buf_sz, ts );
  }
  fflush( pipe->file );
#endif

  /* forward */
  return fd_aio_send( pipe->aio, batch, batch_sz, opt_batch_idx );
}


/* global "clock" */
ulong now = 123;

ulong test_clock( void * ctx ) {
  (void)ctx;
  return now;
}

int
main( int argc, char ** argv ) {
  FILE * pcap = fopen( "test_quic_hs.pcapng", "wb" );
  if( !pcap ) abort();

  write_shb( pcap );
  write_idb( pcap );

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
  tp->initial_max_streams_bidi                       = 10;
  tp->initial_max_streams_bidi_present               = 1;
  tp->initial_max_streams_uni                        = 10;
  tp->initial_max_streams_uni_present                = 1;
  tp->ack_delay_exponent                             = 3;
  tp->ack_delay_exponent_present                     = 1;
  tp->max_ack_delay                                  = 25;
  tp->max_ack_delay_present                          = 1;
  tp->active_connection_id_limit                     = 8;
  tp->active_connection_id_limit_present             = 1;

  fd_quic_config_t quic_config = {0};

  quic_config.transport_params      = tp;
  quic_config.max_concur_conns      = 10;
  quic_config.max_concur_conn_ids   = 10;
  quic_config.max_concur_streams    = 10;
  quic_config.max_concur_handshakes = 10;
  quic_config.max_in_flight_pkts    = 100;
  quic_config.max_in_flight_acks    = 100;
  quic_config.conn_id_sparsity      = 4;

  strcpy( quic_config.cert_file, "cert.pem" );
  strcpy( quic_config.key_file,  "key.pem"  );

  quic_config.cb_stream_receive     = my_stream_receive_cb;
  quic_config.cb_stream_notify      = my_stream_notify_cb;

  quic_config.now_fn  = test_clock;
  quic_config.now_ctx = NULL;

  quic_config.tx_buf_sz = 1ul << 20ul;

  /* XDP config */
  char const * intf        = "";
  float        f_batch_sz  = 128;
  uint         src_ip;
  uchar        src_mac[6];
  uchar        dft_route_mac[6];

  /* TODO: parse command-line arguments */

  char const * app_name    = "quic_load_test";
  uint         ifqueue     = 0;
  ulong        xsk_pkt_cnt = 16;
  uint         udp_port    = 4433;
  uint         proto       = 0;

  fd_quic_host_cfg_t client_cfg = { "client_host", 0xc01a1a1au, 2001 };

  quic_config.host_cfg = client_cfg;
  fd_quic_t * client_quic = new_quic( &quic_config );

  /* create a new XSK instance */
  ulong frame_sz = FRAME_SIZE;
  ulong depth    = 1ul << 20ul;
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
  /* TODO how do we specify the port? */
  if( fd_xdp_listen_udp_port( app_name, src_ip, udp_port, proto ) < 0 ) {
    fprintf( stderr, "unable to listen on given udp port\n" );
    exit(1);
  }

  /* use XSK XDP AIO for QUIC ingress/egress */
  fd_aio_t ingress = *fd_quic_get_aio_net_in( client_quic );
  fd_xsk_aio_set_rx( xsk_aio, &ingress );
  fd_aio_t egress = *fd_xsk_aio_get_tx( xsk_aio );
  fd_quic_set_aio_net_out( client_quic, &egress );

  /* set the callback for handshake complete */
  fd_quic_set_cb_conn_handshake_complete( client_quic, my_handshake_complete );

  /* make a connection from client to frank */
  uint frank_ip_addr = parse_id; /* TODO */
  uint frank_quic_udp_port = 93838383; /* TODO */
  fd_quic_conn_t * client_conn = fd_quic_connect( client_quic, frank_ip_addr, frank_quic_udp_port );
  (void)client_conn;

  /* do general processing */
  for( ulong j = 0; j < 20; j++ ) {
    ulong next_wakeup = fd_quic_get_next_wakeup( client_quic );

    if( next_wakeup == ~(ulong)0 ) {
      printf( "client has no schedule\n" );
      break;
    }

    if( next_wakeup > now ) now = next_wakeup;

    printf( "running services at %lu\n", (ulong)next_wakeup );
    fd_quic_service( client_quic );

    if( client_complete ) {
      printf( "***** client handshake complete *****\n" );

      break;
    }
  }

  for( ulong j = 0; j < 20; j++ ) {
    ulong next_wakeup = fd_quic_get_next_wakeup( client_quic );

    if( next_wakeup == ~(ulong)0 ) {
      printf( "client has no schedule\n" );
      break;
    }

    now = next_wakeup;

    fd_quic_service( client_quic );
  }

  /* populate free streams */
  /* TODO: what is this 10 here? */
  populate_stream_meta( 10 );
  populate_streams( 10, client_conn );

  char buf[512] = "Hello world!\x00-   ";
  fd_aio_pkt_info_t batch[1] = {{ buf, sizeof( buf ) }};

  for( unsigned j = 0; j < 5000; ++j ) {
    ulong next_wakeup = fd_quic_get_next_wakeup( client_quic );

    if( next_wakeup == ~(ulong)0 ) {
      printf( "client has no schedule\n" );
      break;
    }

    if( next_wakeup > now ) now = next_wakeup;

    printf( "running services at %lu\n", (ulong)next_wakeup );
    fflush( stdout );

    fd_quic_service( client_quic );

    buf[12] = ' ';
    //buf[15] = (char)( ( j / 10 ) + '0' );
    buf[16] = (char)( ( j % 10 ) + '0' );

    /* obtain an free stream */
    my_stream_meta_t * meta = get_stream();

    if( meta ) {
      fd_quic_stream_t * stream = meta->stream;

      printf( "sending: %d\n", (int)j );

      if( (j&1) == 0 ) {
        printf( "even\n" );
        fflush( stdout );
      }

      int rc = fd_quic_stream_send( stream, batch, 1 /* batch_sz */, 1 /* fin */ );
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

  /* allow acks to go */
  for( unsigned j = 0; j < 10; ++j ) {
    ulong next_wakeup = fd_quic_get_next_wakeup( client_quic );

    if( next_wakeup == ~(ulong)0 ) {
      /* indicates no schedule, which is correct after connection
         instances have been reclaimed */
      printf( "Finished cleaning up connections\n" );
      break;
    }

    if( next_wakeup > now ) now = next_wakeup;

    printf( "running services at %lu\n", (ulong)next_wakeup );
    fd_quic_service( client_quic );

  }

  fd_quic_delete( client_quic );

  if( fail ) {
    fprintf( stderr, "FAIL\n" );
    exit(1);
  }

  printf( "PASS\n" );

  return 0;
}


