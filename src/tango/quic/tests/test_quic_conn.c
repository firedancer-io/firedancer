#include "../fd_quic.h"

#include <stdio.h>
#include <stdlib.h>

#include "fd_pcap.h"

#define BUF_SZ (1<<20)

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

static void
bkp() {
  __asm__ __volatile__( "nop" );
}

void
populate_streams( ulong sz, fd_quic_conn_t * conn ) {
  for( ulong j = 0; j < sz; ++j ) {
    /* get free stream meta */
    my_stream_meta_t * meta = get_stream_meta();

    /* obtain stream */
    fd_quic_stream_t * stream =
      fd_quic_conn_new_stream( conn, FD_QUIC_TYPE_UNIDIR );

    if( !stream ) {
      bkp();
      fprintf( stderr, "Failed to obtain a stream\n" );
      exit(1);
    }

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

  ulong expected_data_sz = 512ul;

  printf( "my_stream_receive_cb : received data from peer. size: %lu  offset: %lu\n",
      (ulong)data_sz, (ulong)offset );
  printf( "%s\n", data );

  if( data_sz != 512 ) {
    fprintf( stderr, "my_stream_receive_cb : data wrong size. Is: %lu, expected: %lu\n",
        data_sz, expected_data_sz );
    fail = 1;
  } else {
    if( memcmp( data, "Hello world", 11u ) != 0 ) {
      fprintf( stderr, "my_stream_receive_cb : value received incorrect" );
      fail = 1;
    }
  }
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


struct my_context {
  int server;
};
typedef struct my_context my_context_t;

int server_complete = 0;
int client_complete = 0;

/* server connection received in callback */
fd_quic_conn_t * server_conn = NULL;
fd_quic_conn_t * client_conn = NULL;

void
my_cb_conn_final( fd_quic_conn_t * conn,
                  void *           context ) {
  (void)context;

  fd_quic_conn_t ** ppconn = (fd_quic_conn_t**)fd_quic_conn_get_context( conn );;
  if( ppconn ) {
    *ppconn = NULL;
  }
}

void my_connection_new( fd_quic_conn_t * conn, void * vp_context ) {
  (void)conn;
  (void)vp_context;

  printf( "server handshake complete\n" );
  fflush( stdout );

  server_complete = 1;
  server_conn = conn;

  fd_quic_conn_set_context( conn, &server_conn );
}

void my_handshake_complete( fd_quic_conn_t * conn, void * vp_context ) {
  (void)conn;
  (void)vp_context;

  printf( "client handshake complete\n" );
  fflush( stdout );

  client_complete = 1;

  fd_quic_conn_set_context( conn, &client_conn );
}


/* pcap aio pipe */
struct aio_pipe {
  fd_aio_t const * aio;
  FILE *           file;
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
  fd_quic_transport_params_t base_tp[1] = {0};

#define MAX_STREAMS 10

  /* establish these parameters as "present" */
  base_tp->max_idle_timeout                               = 60000;
  base_tp->max_idle_timeout_present                       = 1;
  base_tp->initial_max_data                               = 1048576;
  base_tp->initial_max_data_present                       = 1;
  base_tp->initial_max_stream_data_bidi_local             = 1048576;
  base_tp->initial_max_stream_data_bidi_local_present     = 1;
  base_tp->initial_max_stream_data_bidi_remote            = 1048576;
  base_tp->initial_max_stream_data_bidi_remote_present    = 1;
  base_tp->initial_max_stream_data_uni                    = 1048576;
  base_tp->initial_max_stream_data_uni_present            = 1;
  base_tp->initial_max_streams_bidi                       = 0;
  base_tp->initial_max_streams_bidi_present               = 1;
  base_tp->initial_max_streams_uni                        = 0;
  base_tp->initial_max_streams_uni_present                = 1;
  base_tp->ack_delay_exponent                             = 3;
  base_tp->ack_delay_exponent_present                     = 1;
  base_tp->max_ack_delay                                  = 25;
  base_tp->max_ack_delay_present                          = 1;
  base_tp->active_connection_id_limit                     = 8;
  base_tp->active_connection_id_limit_present             = 1;

  /* all zeros transport params is a reasonable default */
  fd_quic_transport_params_t client_tp[1] = {base_tp[0]};

  /* establish these parameters as "present" */
  client_tp->initial_max_streams_bidi                       = MAX_STREAMS;
  client_tp->initial_max_streams_bidi_present               = 1;
  client_tp->initial_max_streams_uni                        = MAX_STREAMS;
  client_tp->initial_max_streams_uni_present                = 1;

  fd_quic_transport_params_t server_tp[1] = {base_tp[0]};
  server_tp->initial_max_streams_bidi                       = MAX_STREAMS;
  server_tp->initial_max_streams_bidi_present               = 1;
  server_tp->initial_max_streams_uni                        = MAX_STREAMS;
  server_tp->initial_max_streams_uni_present                = 1;

  fd_quic_config_t client_config = {0};

  client_config.transport_params      = client_tp;
  client_config.max_concur_conns      = 10;
  client_config.max_concur_conn_ids   = 10;
  client_config.max_concur_streams    = MAX_STREAMS;
  client_config.max_concur_handshakes = 10;
  client_config.max_in_flight_pkts    = 100;
  client_config.max_in_flight_acks    = 100;
  client_config.conn_id_sparsity      = 4;
  client_config.udp_ephem.lo          = 4435;
  client_config.udp_ephem.hi          = 4440;

  strcpy( client_config.cert_file,   "cert.pem" );
  strcpy( client_config.key_file,    "key.pem"  );
  strcpy( client_config.keylog_file, "keylog.log" );

  client_config.cb_stream_receive     = my_stream_receive_cb;
  client_config.cb_stream_notify      = my_stream_notify_cb;
  client_config.cb_conn_final         = my_cb_conn_final;

  client_config.now_fn  = test_clock;
  client_config.now_ctx = NULL;

  fd_quic_config_t server_config = {0};

  server_config.transport_params      = server_tp;
  server_config.max_concur_conns      = 10;
  server_config.max_concur_conn_ids   = 10;
  server_config.max_concur_streams    = MAX_STREAMS;
  server_config.max_concur_handshakes = 10;
  server_config.max_in_flight_pkts    = 100;
  server_config.max_in_flight_acks    = 100;
  server_config.conn_id_sparsity      = 4;

  strcpy( server_config.cert_file, "cert.pem" );
  strcpy( server_config.key_file,  "key.pem"  );

  server_config.cb_stream_receive     = my_stream_receive_cb;
  server_config.cb_stream_notify      = my_stream_notify_cb;
  server_config.cb_conn_final         = my_cb_conn_final;

  server_config.now_fn  = test_clock;
  server_config.now_ctx = NULL;

  fd_quic_host_cfg_t server_cfg = { "server_host", 0x0a000001u, 4434 };
  fd_quic_host_cfg_t client_cfg = { "client_host", 0xc01a1a1au, 2001 };

  client_config.host_cfg = client_cfg;
  fd_quic_t * client_quic = new_quic( &client_config );

  server_config.host_cfg = server_cfg;
  fd_quic_t * server_quic = new_quic( &server_config );

  /* make use aio to point quic directly at quic */
  fd_aio_t const * aio_n2q = fd_quic_get_aio_net_in( server_quic );
  fd_aio_t const * aio_q2n = fd_quic_get_aio_net_in( client_quic );

#if 0
  fd_quic_set_aio_net_out( server_quic, aio_q2n );
  fd_quic_set_aio_net_out( client_quic, aio_n2q );
#else
  /* create a pipe for catching data as it passes thru */
  aio_pipe_t pipe[2] = { { aio_n2q, pcap }, { aio_q2n, pcap } };

  fd_aio_t * aio[2];
  uchar aio_mem[2][128] = {0};

  if( fd_aio_footprint() > sizeof( aio_mem[0] ) ) {
    FD_LOG_WARNING(( "aio footprint: %lu", fd_aio_footprint() ));
    FD_LOG_ERR(( "fd_aio_footprint returned value larger than reserved memory" ));
  }

  aio[0] = fd_aio_join( fd_aio_new( aio_mem[0], &pipe[0], pipe_aio_receive ) );
  aio[1] = fd_aio_join( fd_aio_new( aio_mem[1], &pipe[1], pipe_aio_receive ) );

  fd_quic_set_aio_net_out( server_quic, aio[1] );
  fd_quic_set_aio_net_out( client_quic, aio[0] );
#endif

  /* set up server_quic as server */
  fd_quic_listen( server_quic );

  /* set the callback for new connections */
  fd_quic_set_cb_conn_new( server_quic, my_connection_new );

  /* set the callback for handshake complete */
  fd_quic_set_cb_conn_handshake_complete( client_quic, my_handshake_complete );

  /* make a connection from client to server */
  client_conn = fd_quic_connect( client_quic, server_cfg.ip_addr, server_cfg.udp_port );
  (void)client_conn;

  /* do general processing */
  for( ulong j = 0; j < 20; j++ ) {
    ulong ct = fd_quic_get_next_wakeup( client_quic );
    ulong st = fd_quic_get_next_wakeup( server_quic );
    ulong next_wakeup = fd_ulong_min( ct, st );

    if( next_wakeup == ~(ulong)0 ) {
      printf( "client and server have no schedule\n" );
      break;
    }

    if( next_wakeup > now ) now = next_wakeup;

    printf( "running services at %lu\n", (ulong)next_wakeup );
    fd_quic_service( client_quic );
    fd_quic_service( server_quic );

    if( server_complete && client_complete ) {
      printf( "***** both handshakes complete *****\n" );

      break;
    }
  }

  for( ulong j = 0; j < 20; j++ ) {
    ulong ct = fd_quic_get_next_wakeup( client_quic );
    ulong st = fd_quic_get_next_wakeup( server_quic );
    ulong next_wakeup = fd_ulong_min( ct, st );

    if( next_wakeup == ~(ulong)0 ) {
      printf( "client and server have no schedule\n" );
      break;
    }

    now = next_wakeup;

    fd_quic_service( client_quic );
    fd_quic_service( server_quic );
  }

  uint k = 1;

  /* populate free streams */
  populate_stream_meta( MAX_STREAMS );
  populate_streams( MAX_STREAMS, client_conn );

  char buf[512] = "Hello world!\x00-   ";
  fd_aio_pkt_info_t batch[1] = {{ buf, sizeof( buf ) }};

  int status = 0;

  for( unsigned j = 0; j < 1000000000 && k < 100 && client_conn; ++j ) {
    my_stream_meta_t * meta = NULL;
    now += 50000;

    fd_quic_service( client_quic );
    if( (j%1)==0 )
      fd_quic_service( server_quic );

    buf[12] = ' ';
    buf[15] = (char)( ( k / 10 ) + '0' );
    buf[16] = (char)( ( k % 10 ) + '0' );

    switch( status ) {
      case 0:

        /* obtain an free stream */
        meta = get_stream();

        if( meta ) {
          fd_quic_stream_t * stream = meta->stream;

          printf( "sending: %d\n", (int)k );

          int rc = fd_quic_stream_send( stream, batch, 1 /* batch_sz */, 1 /* fin */ );

          if( rc == 1 ) {
            /* successful - stream will begin closing */
            /* stream and meta will be recycled when quic notifies the stream
               is closed via my_stream_notify_cb */
            k++;
            if( (k%50) == 0 ) {
              // close client
              status = 1;

              fd_quic_conn_close( client_conn, 0 /* app defined reason code */ );
            }
          } else {
            /* did not send, did not start finalize, so stream is still available */
            free_stream( meta );

            printf( "send failed\n" );
            fflush( stdout );
          }
        } else {
          printf( "unable to send - no streams available\n" );
          fflush( stdout );
        }
        break;

      case 1:
        // wait for connection to close
        if( !client_conn ) {
          printf( "client closed\n" );
          break;
        }
    }

  }

  printf( "client_conn: %p\n", (void*)client_conn );
  printf( "server_conn: %p\n", (void*)server_conn );
  fflush( stdout );

  /* give server connection a chance to close */
  for( int j = 0; j < 1000; ++j ) {
    ulong next_wakeup = fd_quic_get_next_wakeup( server_quic );

    if( next_wakeup == ~(ulong)0 ) {
      printf( "server has no schedule\n" );
      break;
    }

    now = next_wakeup;

    fd_quic_service( server_quic );
  }

  printf( "client_conn: %p\n", (void*)client_conn );
  printf( "server_conn: %p\n", (void*)server_conn );
  fflush( stdout );

  fd_quic_delete( server_quic );
  fd_quic_delete( client_quic );

  if( fail ) {
    fprintf( stderr, "FAIL\n" );
    exit(1);
  }

  printf( "PASS\n" );

  return 0;
}


