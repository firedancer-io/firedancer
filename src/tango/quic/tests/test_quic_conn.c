#include "../fd_quic.h"

#include <stdio.h>
#include <stdlib.h>

#include "fd_pcap.h"
#include "test_helpers.c"

#define BUF_SZ (1<<20)

int state           = 0;
int server_complete = 0;
int client_complete = 0;

/* server connection received in callback */
fd_quic_conn_t * server_conn = NULL;
fd_quic_conn_t * client_conn = NULL;

/* this is slow */
int
rand_256() {
  static uint  j     = 56u;
  static ulong rnd64 = 0u;
  j = (j+8)&63u;

  if( j == 0 ) {
    fd_quic_crypto_rand( (void*)&rnd64, 8u );
  }

  return ( rnd64 >> j ) & 255u;
}


typedef struct my_stream_meta my_stream_meta_t;
struct my_stream_meta {
  fd_quic_stream_t * stream;
  my_stream_meta_t * next;
};

my_stream_meta_t * meta_mem;
my_stream_meta_t * meta_free;
ulong              meta_sz;

/* populate meta_free with free stream meta */
void
populate_stream_meta( ulong sz ) {
  my_stream_meta_t * prev = NULL;

  meta_mem = (my_stream_meta_t*)malloc( sz * sizeof( my_stream_meta_t ) );
  meta_sz  = sz;

  for( ulong j = 0; j < sz; ++j ) {
    my_stream_meta_t * meta = &meta_mem[j];
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
  FD_LOG_DEBUG(( "before obtaining stream. count: %u", get_free_count() ));

  my_stream_meta_t * meta = stream_avail;
  if( meta ) {
    stream_avail = meta->next;
    meta->next   = NULL;
  }

  FD_LOG_DEBUG(( "after obtaining stream. count: %u", get_free_count() ));

  return meta;
}

/* push stream meta into front of free list */
void
free_stream( my_stream_meta_t * meta ) {
  FD_LOG_DEBUG(( "before freeing stream. count: %u", get_free_count() ));

  meta->next   = stream_avail;
  stream_avail = meta;

  FD_LOG_DEBUG(( "freed stream. count: %u", get_free_count() ));
  fd_log_flush();
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
      FD_LOG_ERR(( "Failed to obtain a stream" ));
    }

    /* set context on stream to meta */
    fd_quic_stream_set_context( stream, meta );

    /* populate meta */
    meta->stream = stream;

    /* insert into avail list */
    free_stream( meta );
  }
}

/* obtain all free stream meta, clear the stream, and
   deallocate */
void
free_all_streams() {
  my_stream_meta_t * prev = NULL;

  meta_mem = (my_stream_meta_t*)malloc( meta_sz * sizeof( my_stream_meta_t ) );

  for( ulong j = 0; j < meta_sz; ++j ) {
    my_stream_meta_t * meta = &meta_mem[j];
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

extern uchar pkt_full[];
extern ulong pkt_full_sz;

ulong
aio_cb( void * context, fd_aio_pkt_info_t * batch, ulong batch_sz ) {
  (void)context;

  FD_LOG_DEBUG(( "aio_cb callback" ));
  for( ulong j = 0; j < batch_sz; ++j ) {
    FD_LOG_DEBUG(( "batch %d", (int)j ));
    FD_LOG_HEXDUMP_DEBUG(( "batch data", batch[ j ].buf, batch[ j ].buf_sz ));
  }
  fd_log_flush();

  return batch_sz; /* consumed all */
}

uchar fail = 0;

void
my_stream_notify_cb( fd_quic_stream_t * stream, void * ctx, int type ) {
  (void)stream;
  my_stream_meta_t * meta = (my_stream_meta_t*)ctx;
  switch( type ) {
    case FD_QUIC_NOTIFY_END:
      FD_LOG_DEBUG(( "reclaiming stream" ));
      fd_log_flush();

      if( stream->conn->server ) {
        FD_LOG_DEBUG(( "SERVER" ));
        fd_log_flush();
      } else {
        FD_LOG_DEBUG(( "CLIENT" ));
        fd_log_flush();

        if( client_conn && state == 0 ) {
          /* obtain new stream */
          fd_quic_stream_t * new_stream =
            fd_quic_conn_new_stream( client_conn, FD_QUIC_TYPE_UNIDIR );
          FD_TEST( new_stream );

          /* set context on stream to meta */
          fd_quic_stream_set_context( new_stream, meta );

          /* populate meta */
          meta->stream = new_stream;

          /* return meta */
          free_stream( meta );
        }
      }
      break;

    default:
      FD_LOG_DEBUG(( "NOTIFY: %#x", type ));
      fd_log_flush();
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

  ulong expected_data_sz = 512ul;

  FD_LOG_INFO(( "received data from peer. size: %lu offset: %lu\n",
                data_sz, offset ));
  FD_LOG_HEXDUMP_DEBUG(( "received data", data, data_sz ));

  if( FD_UNLIKELY( data_sz!=512UL ) ) {
    FD_LOG_WARNING(( "data wrong size. Is: %lu, expected: %lu",
                     data_sz, expected_data_sz ));
    fail = 1;
    return;
  }

  if( FD_UNLIKELY( 0!=memcmp( data, "Hello world", 11u ) ) ) {
    FD_LOG_WARNING(( "value received incorrect" ));
    fail = 1;
    return;
  }

  FD_LOG_DEBUG(( "recv ok" ));
}


struct my_context {
  int server;
};
typedef struct my_context my_context_t;

void
my_cb_conn_final( fd_quic_conn_t * conn,
                  void *           context ) {
  (void)context;

  if( !conn->server ) {
    /* remove all invalidated stream objects */
    free_all_streams();
  }

  fd_quic_conn_t ** ppconn = (fd_quic_conn_t**)fd_quic_conn_get_context( conn );
  if( ppconn ) {
    FD_LOG_NOTICE(( "my_cb_conn_final %p SUCCESS", (void*)*ppconn ));
    *ppconn = NULL;
  } else {
    FD_LOG_WARNING(( "my_cb_conn_final FAIL" ));
  }
}

void
my_connection_new( fd_quic_conn_t * conn,
                   void *           vp_context ) {
  (void)vp_context;

  FD_LOG_NOTICE(( "server handshake complete" ));

  server_complete = 1;
  server_conn = conn;

  fd_quic_conn_set_context( conn, &server_conn );
}

void
my_handshake_complete( fd_quic_conn_t * conn,
                       void *           vp_context ) {
  (void)vp_context;

  FD_LOG_NOTICE(( "client handshake complete" ));
  fd_log_flush();

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
  if( rand_256() < 256 ) {
    return fd_aio_send( pipe->aio, batch, batch_sz, opt_batch_idx );
  } else {
    if( opt_batch_idx ) {
      *opt_batch_idx = batch_sz;
    }
    return FD_AIO_SUCCESS;
  }
}


/* global "clock" */
ulong now = (ulong)1e18;

ulong test_clock( void * ctx ) {
  (void)ctx;
  return now;
}

int
main( int argc, char ** argv ) {
  fd_boot( &argc, &argv );

  ulong cpu_idx = fd_tile_cpu_id( fd_tile_idx() );
  if( cpu_idx>fd_shmem_cpu_cnt() ) cpu_idx = 0UL;

  char const * _page_sz  = fd_env_strip_cmdline_cstr ( &argc, &argv, "--page-sz",   NULL, "gigantic"                   );
  ulong        page_cnt  = fd_env_strip_cmdline_ulong( &argc, &argv, "--page-cnt",  NULL, 2UL                          );
  ulong        numa_idx  = fd_env_strip_cmdline_ulong( &argc, &argv, "--numa-idx",  NULL, fd_shmem_numa_idx( cpu_idx ) );
  char const * _pcap     = fd_env_strip_cmdline_cstr ( &argc, &argv, "--pcap",      NULL, "test_quic_hs.pcapng"        );

  ulong page_sz = fd_cstr_to_shmem_page_sz( _page_sz );
  if( FD_UNLIKELY( !page_sz ) ) FD_LOG_ERR(( "unsupported --page-sz" ));

  FD_LOG_NOTICE(( "Creating workspace (--page-cnt %lu, --page-sz %s, --numa-idx %lu)", page_cnt, _page_sz, numa_idx ));
  fd_wksp_t * wksp = fd_wksp_new_anonymous( page_sz, page_cnt, fd_shmem_cpu_idx( numa_idx ), "wksp", 0UL );
  FD_TEST( wksp );

  fd_quic_limits_t const quic_limits = {
    .conn_cnt         = 10,
    .conn_id_cnt      = 10,
    .conn_id_sparsity = 4.0,
    .handshake_cnt    = 10,
    .stream_cnt       = 10,
    .inflight_pkt_cnt = 1024,
    .tx_buf_sz        = 1<<14,
    .rx_buf_sz        = 1<<14
  };

  ulong quic_footprint = fd_quic_footprint( &quic_limits );
  FD_TEST( quic_footprint );
  FD_LOG_NOTICE(( "QUIC footprint: %lu bytes", quic_footprint ));

  FD_LOG_NOTICE(( "Creating server QUIC" ));
  fd_quic_t * server_quic = fd_quic_new(
      fd_wksp_alloc_laddr( wksp, fd_quic_align(), fd_quic_footprint( &quic_limits ), 1UL ),
      &quic_limits );
  FD_TEST( server_quic );

  FD_LOG_NOTICE(( "Creating client QUIC" ));
  fd_quic_t * client_quic = fd_quic_new(
      fd_wksp_alloc_laddr( wksp, fd_quic_align(), fd_quic_footprint( &quic_limits ), 1UL ),
      &quic_limits );
  FD_TEST( client_quic );

  FD_LOG_NOTICE(( "Writing to pcap: %s", _pcap ));
  FILE * pcap = fopen( _pcap, "wb" );
  FD_TEST( pcap );

  write_shb( pcap );
  write_idb( pcap );

  fd_quic_config_t * client_config = fd_quic_get_config( client_quic );

  client_config->link.src_mac_addr[ 0 ] = 0x01;
  client_config->link.dst_mac_addr[ 0 ] = 0x02;

  client_config->net.ip_addr           = 0xc01a1a1au;
  client_config->net.ephem_udp_port.lo = 4435;
  client_config->net.ephem_udp_port.hi = 4440;

  client_config->net.listen_udp_port  = 2002;
  client_config->link.src_mac_addr[0] = 0x01;
  client_config->link.dst_mac_addr[0] = 0x02;
  client_config->idle_timeout         = (ulong)1e8;

  strcpy( client_config->cert_file,   "cert.pem"   );
  strcpy( client_config->key_file,    "key.pem"    );
  strcpy( client_config->keylog_file, "keylog.log" );

  client_config->idle_timeout = 5e6;

  fd_quic_callbacks_t * client_cb = fd_quic_get_callbacks( client_quic );

  client_cb->conn_hs_complete = my_handshake_complete;
  client_cb->stream_receive   = my_stream_receive_cb;
  client_cb->stream_notify    = my_stream_notify_cb;
  client_cb->conn_final       = my_cb_conn_final;

  client_cb->now     = test_clock;
  client_cb->now_ctx = NULL;

  fd_quic_config_t * server_config = fd_quic_get_config( server_quic );

  server_config->link.src_mac_addr[ 0 ] = 0x02;
  server_config->link.dst_mac_addr[ 0 ] = 0x01;

  server_config->net.ip_addr         = 0x0a000001u;
  server_config->net.listen_udp_port = 2001;

  server_config->link.src_mac_addr[0] = 0x01;
  server_config->link.dst_mac_addr[0] = 0x02;
  server_config->idle_timeout         = (ulong)1e8;

  strcpy( server_config->cert_file, "cert.pem" );
  strcpy( server_config->key_file,  "key.pem"  );

  server_config->idle_timeout = 5e6;

  fd_quic_callbacks_t * server_cb = fd_quic_get_callbacks( server_quic );

  server_cb->conn_new       = my_connection_new;
  server_cb->stream_receive = my_stream_receive_cb;
  server_cb->stream_notify  = my_stream_notify_cb;
  server_cb->conn_final     = my_cb_conn_final;

  server_cb->now     = test_clock;
  server_cb->now_ctx = NULL;

  /* make use aio to point quic directly at quic */
  fd_aio_t _aio[2];
  fd_aio_t const * aio_n2q = fd_quic_get_aio_net_rx( server_quic, &_aio[ 0 ] );
  fd_aio_t const * aio_q2n = fd_quic_get_aio_net_rx( client_quic, &_aio[ 1 ] );

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

  fd_quic_set_aio_net_tx( server_quic, aio[1] );
  fd_quic_set_aio_net_tx( client_quic, aio[0] );
#endif

  server_quic->config.role = FD_QUIC_ROLE_SERVER;
  client_quic->config.role = FD_QUIC_ROLE_CLIENT;

  FD_TEST( fd_quic_join( client_quic ) );
  FD_TEST( fd_quic_join( server_quic ) );

  uint k = 1;

  /* populate free streams */
  populate_stream_meta( quic_limits.stream_cnt );

  char buf[512] = "Hello world!\x00-   ";
  fd_aio_pkt_info_t batch[1] = {{ buf, sizeof( buf ) }};

  int done  = 0;

  state = 1;

  ulong j = 0;
  while( k < 4000 && !done ) {
    j++;

    my_stream_meta_t * meta = NULL;
    now += 50000;

    fd_quic_service( client_quic );

    if( (j%1)==0 ) {
      fd_quic_service( server_quic );
    }

    buf[12] = ' ';
    buf[15] = (char)( ( k / 10 ) + '0' );
    buf[16] = (char)( ( k % 10 ) + '0' );

    /* connection torn down? */
    if( !client_conn ) {
      state = 1; /* start a new one */
    }

    switch( state ) {
      case 0:

        /* obtain a free stream */
        meta = get_stream();

        if( meta ) {
          fd_quic_stream_t * stream = meta->stream;

          FD_LOG_DEBUG(( "sending: %d", (int)k ));

          int rc = fd_quic_stream_send( stream, batch, 1 /* batch_sz */, 1 /* fin */ );

          if( rc == 1 ) {
            /* successful - stream will begin closing */
            /* stream and meta will be recycled when quic notifies the stream
               is closed via my_stream_notify_cb */
            k++;
            if( (k%2) == 0 ) {
              // close client
              state = 1;

              fd_quic_conn_close( client_conn, 0 /* app defined reason code */ );
            }
          } else {
            /* did not send, did not start finalize, so stream is still available */
            free_stream( meta );

            FD_LOG_WARNING(( "send failed" ));
            fd_log_flush();
          }
        } else {
          FD_LOG_WARNING(( "unable to send - no streams available" ));
          fd_log_flush();
        }
        break;

      case 1:
        // wait for connection to close
        if( !client_conn ) {
          FD_LOG_INFO(( "client closed. opening new" ));

          /* new handshake starting */
          client_complete = 0;

          /* start new connection */
          client_conn = fd_quic_connect(
              client_quic,
              server_quic->config.net.ip_addr,
              server_quic->config.net.listen_udp_port,
              server_quic->config.sni );

          if( !client_quic ) {
            FD_LOG_ERR(( "fd_quic_connect failed" ));
          }

          fd_quic_conn_set_context( client_conn, &client_conn );

          state = 2;
        }

        break;

      case 2:
        if( client_complete ) {
          FD_LOG_INFO(( "new connection completed handshake" ));

          state = 0;

          populate_streams( quic_limits.stream_cnt, client_conn );
        }

        break;

      default:
        done = 1;
    }

  }

  FD_LOG_INFO(( "client_conn: %p", (void*)client_conn ));
  FD_LOG_INFO(( "server_conn: %p", (void*)server_conn ));
  fd_log_flush();

  /* give server connection a chance to close */
  for( int j = 0; j < 1000; ++j ) {
    ulong next_wakeup = fd_quic_get_next_wakeup( server_quic );

    if( next_wakeup == ~(ulong)0 ) {
      FD_LOG_INFO(( "server has no schedule "));
      break;
    }

    now = next_wakeup;

    fd_quic_service( server_quic );
  }

  FD_LOG_INFO(( "client_conn: %p", (void*)client_conn ));
  FD_LOG_INFO(( "server_conn: %p", (void*)server_conn ));
  fd_log_flush();

  fd_quic_delete( server_quic );
  fd_quic_delete( client_quic );

  if( fail ) FD_LOG_ERR(( "fail" ));
  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}


