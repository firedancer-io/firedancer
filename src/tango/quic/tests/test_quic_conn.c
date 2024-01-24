#include "../fd_quic.h"
#include "fd_quic_test_helpers.h"

/* test_quic_conn repeatedly opens and closes QUIC connections. */

#include <stdlib.h>

int state           = 0;
int server_complete = 0;
int client_complete = 0;

/* server connection received in callback */
fd_quic_conn_t * server_conn = NULL;
fd_quic_conn_t * client_conn = NULL;

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
free_all_streams( void ) {
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

uchar fail = 0;

void
my_stream_notify_cb( fd_quic_stream_t * stream, void * ctx, int type ) {
  (void)stream;
  my_stream_meta_t * meta = (my_stream_meta_t*)ctx;
  switch( type ) {
    case FD_QUIC_NOTIFY_END:
      FD_LOG_DEBUG(( "reclaiming stream" ));

      if( stream->conn->server ) {
        FD_LOG_DEBUG(( "SERVER" ));
      } else {
        FD_LOG_DEBUG(( "CLIENT" ));

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
    FD_LOG_INFO(( "my_cb_conn_final %p SUCCESS", (void*)*ppconn ));
    *ppconn = NULL;
  } else {
    FD_LOG_WARNING(( "my_cb_conn_final FAIL" ));
  }
}

void
my_connection_new( fd_quic_conn_t * conn,
                   void *           vp_context ) {
  (void)vp_context;

  FD_LOG_INFO(( "server handshake complete" ));

  server_complete = 1;
  server_conn = conn;

  fd_quic_conn_set_context( conn, &server_conn );
}

void
my_handshake_complete( fd_quic_conn_t * conn,
                       void *           vp_context ) {
  (void)vp_context;

  FD_LOG_INFO(( "client handshake complete" ));

  client_complete = 1;

  fd_quic_conn_set_context( conn, &client_conn );
}

/* global "clock" */
ulong now = (ulong)1e18;

ulong test_clock( void * ctx ) {
  (void)ctx;
  return now;
}

int
main( int argc, char ** argv ) {

  fd_boot          ( &argc, &argv );
  fd_quic_test_boot( &argc, &argv );

  fd_rng_t _rng[1]; fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, 0U, 0UL ) );

  ulong cpu_idx = fd_tile_cpu_id( fd_tile_idx() );
  if( cpu_idx>fd_shmem_cpu_cnt() ) cpu_idx = 0UL;

  char const * _page_sz  = fd_env_strip_cmdline_cstr ( &argc, &argv, "--page-sz",   NULL, "gigantic"                   );
  ulong        page_cnt  = fd_env_strip_cmdline_ulong( &argc, &argv, "--page-cnt",  NULL, 2UL                          );
  ulong        numa_idx  = fd_env_strip_cmdline_ulong( &argc, &argv, "--numa-idx",  NULL, fd_shmem_numa_idx( cpu_idx ) );

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
    .stream_cnt       = { 0, 0, 10, 0 },
    .inflight_pkt_cnt = 1024,
    .tx_buf_sz        = 1<<14
  };

  ulong quic_footprint = fd_quic_footprint( &quic_limits );
  FD_TEST( quic_footprint );
  FD_LOG_NOTICE(( "QUIC footprint: %lu bytes", quic_footprint ));

  FD_LOG_NOTICE(( "Creating server QUIC" ));
  fd_quic_t * server_quic = fd_quic_new_anonymous( wksp, &quic_limits, FD_QUIC_ROLE_SERVER, rng );
  FD_TEST( server_quic );

  FD_LOG_NOTICE(( "Creating client QUIC" ));
  fd_quic_t * client_quic = fd_quic_new_anonymous( wksp, &quic_limits, FD_QUIC_ROLE_CLIENT, rng );
  FD_TEST( client_quic );

  fd_quic_config_t * client_config = &client_quic->config;
  client_config->idle_timeout = 5e6;

  client_quic->cb.conn_hs_complete = my_handshake_complete;
  client_quic->cb.stream_receive   = my_stream_receive_cb;
  client_quic->cb.stream_notify    = my_stream_notify_cb;
  client_quic->cb.conn_final       = my_cb_conn_final;

  client_quic->cb.now     = test_clock;
  client_quic->cb.now_ctx = NULL;

  fd_quic_config_t * server_config = &server_quic->config;
  server_config->idle_timeout = 5e6;

  server_quic->cb.conn_new       = my_connection_new;
  server_quic->cb.stream_receive = my_stream_receive_cb;
  server_quic->cb.stream_notify  = my_stream_notify_cb;
  server_quic->cb.conn_final     = my_cb_conn_final;

  server_quic->cb.now     = test_clock;
  server_quic->cb.now_ctx = NULL;

  server_quic->config.initial_rx_max_stream_data = 1<<14;
  client_quic->config.initial_rx_max_stream_data = 1<<14;

  FD_LOG_NOTICE(( "Creating virtual pair" ));
  fd_quic_virtual_pair_t vp;
  fd_quic_virtual_pair_init( &vp, server_quic, client_quic );

  FD_LOG_NOTICE(( "Initializing QUICs" ));
  FD_TEST( fd_quic_init( client_quic ) );
  FD_TEST( fd_quic_init( server_quic ) );

  uint k = 1;

  /* populate free streams */
  populate_stream_meta( quic_limits.stream_cnt[ FD_QUIC_STREAM_TYPE_UNI_CLIENT ] );

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
          }
        } else {
          FD_LOG_WARNING(( "unable to send - no streams available" ));
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

          populate_streams( quic_limits.stream_cnt[ FD_QUIC_STREAM_TYPE_UNI_CLIENT ], client_conn );
        }

        break;

      default:
        done = 1;
    }

  }

  FD_LOG_INFO(( "client_conn: %p", (void*)client_conn ));
  FD_LOG_INFO(( "server_conn: %p", (void*)server_conn ));

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

  FD_LOG_NOTICE(( "Cleaning up" ));
  fd_quic_virtual_pair_fini( &vp );
  fd_wksp_free_laddr( fd_quic_delete( fd_quic_leave( fd_quic_fini( server_quic ) ) ) );
  fd_wksp_free_laddr( fd_quic_delete( fd_quic_leave( fd_quic_fini( client_quic ) ) ) );
  fd_wksp_delete_anonymous( wksp );
  fd_rng_delete( fd_rng_leave( rng ) );

  FD_LOG_NOTICE(( "pass" ));
  fd_quic_test_halt();
  fd_halt();
  return 0;
}
