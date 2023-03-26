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
aio_cb( void *              context,
        fd_aio_pkt_info_t * batch,
        ulong               batch_sz ) {
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

int server_complete = 0;
int client_complete = 0;

/* server connection received in callback */
fd_quic_conn_t * server_conn = NULL;

void
my_connection_new( fd_quic_conn_t * conn,
                   void *           vp_context ) {
  (void)vp_context;

  FD_LOG_NOTICE(( "server handshake complete" ));
  fd_log_flush();

  server_complete = 1;
  server_conn = conn;
}

void
my_handshake_complete( fd_quic_conn_t * conn,
                       void *           vp_context ) {
  (void)conn;
  (void)vp_context;

  FD_LOG_NOTICE(( "client handshake complete" ));
  fd_log_flush();

  client_complete = 1;
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

static void
init_quic( fd_quic_t *  quic,
           char const * hostname,
           uint         ip_addr,
           uint         udp_port ) {

  FD_LOG_NOTICE(( "Configuring QUIC \"%s\"", hostname ));

  fd_quic_config_t * quic_config = fd_quic_get_config( quic );

  strcpy ( quic_config->cert_file, "cert.pem" );
  strcpy ( quic_config->key_file,  "key.pem"  );
  strncpy( quic_config->sni,       hostname, FD_QUIC_SNI_LEN );

  quic_config->net.ip_addr         = ip_addr;
  quic_config->net.listen_udp_port = (ushort)udp_port;

  quic_config->net.ephem_udp_port.lo = 4219;
  quic_config->net.ephem_udp_port.hi = 4220;

  fd_quic_callbacks_t * quic_cb = fd_quic_get_callbacks( quic );

  quic_cb->stream_receive = my_stream_receive_cb;
  quic_cb->stream_notify  = my_stream_notify_cb;

  quic_cb->now     = test_clock;
  quic_cb->now_ctx = NULL;
}

int
main( int argc, char ** argv ) {
  fd_boot( &argc, &argv );

  ulong cpu_idx = fd_tile_cpu_id( fd_tile_idx() );
  if( cpu_idx>fd_shmem_cpu_cnt() ) cpu_idx = 0UL;

  char const * _page_sz  = fd_env_strip_cmdline_cstr ( &argc, &argv, "--page-sz",   NULL, "gigantic"                   );
  ulong        page_cnt  = fd_env_strip_cmdline_ulong( &argc, &argv, "--page-cnt",  NULL, 2UL                          );
  ulong        numa_idx  = fd_env_strip_cmdline_ulong( &argc, &argv, "--numa-idx",  NULL, fd_shmem_numa_idx( cpu_idx ) );
  char const * _pcap     = fd_env_strip_cmdline_cstr ( &argc, &argv, "--pcap",      NULL, "test_quic_streams.pcapng"   );

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
    .inflight_pkt_cnt = 100,
    .tx_buf_sz        = 1<<20,
    .rx_buf_sz        = 1<<20
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

  init_quic( server_quic, "server_host", 0x0a000001u, 4434 );
  init_quic( client_quic, "client_host", 0xc01a1a1au, 2001 );

  server_quic->config.role = FD_QUIC_ROLE_SERVER;
  client_quic->config.role = FD_QUIC_ROLE_CLIENT;

  server_quic->join.cb.conn_new         = my_connection_new;
  client_quic->join.cb.conn_hs_complete = my_handshake_complete;

  /* make use aio to point quic directly at quic */
  fd_aio_t const * aio_n2q = fd_quic_get_aio_net_rx( server_quic );
  fd_aio_t const * aio_q2n = fd_quic_get_aio_net_rx( client_quic );

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

  FD_TEST( fd_quic_join( server_quic ) );
  FD_TEST( fd_quic_join( client_quic ) );

  /* make a connection from client to server */
  fd_quic_conn_t * client_conn = fd_quic_connect(
      client_quic,
      server_quic->config.net.ip_addr,
      server_quic->config.net.listen_udp_port,
      server_quic->config.sni );

  /* do general processing */
  for( ulong j = 0; j < 20; j++ ) {
    ulong ct = fd_quic_get_next_wakeup( client_quic );
    ulong st = fd_quic_get_next_wakeup( server_quic );
    ulong next_wakeup = fd_ulong_min( ct, st );

    if( next_wakeup == ~(ulong)0 ) {
      FD_LOG_INFO(( "client and server have no schedule" ));
      break;
    }

    if( next_wakeup > now ) now = next_wakeup;

    FD_LOG_INFO(( "running services at %lu", next_wakeup ));
    fd_quic_service( client_quic );
    fd_quic_service( server_quic );

    if( server_complete && client_complete ) {
      FD_LOG_INFO(( "***** both handshakes complete *****" ));
      break;
    }
  }

  for( ulong j = 0; j < 20; j++ ) {
    ulong ct = fd_quic_get_next_wakeup( client_quic );
    ulong st = fd_quic_get_next_wakeup( server_quic );
    ulong next_wakeup = fd_ulong_min( ct, st );

    if( next_wakeup == ~(ulong)0 ) {
      FD_LOG_INFO(( "client and server have no schedule" ));
      break;
    }

    now = next_wakeup;

    fd_quic_service( client_quic );
    fd_quic_service( server_quic );
  }

  /* populate free streams */
  populate_stream_meta( 10 );
  populate_streams( 10, client_conn );

  char buf[512] = "Hello world!\x00-   ";
  fd_aio_pkt_info_t batch[1] = {{ buf, sizeof( buf ) }};

  for( unsigned j = 0; j < 5000; ++j ) {
    ulong ct = fd_quic_get_next_wakeup( client_quic );
    ulong st = fd_quic_get_next_wakeup( server_quic );
    ulong next_wakeup = fd_ulong_min( ct, st );

    if( next_wakeup == ~(ulong)0 ) {
      FD_LOG_INFO(( "client and server have no schedule" ));
      break;
    }

    if( next_wakeup > now ) now = next_wakeup;

    FD_LOG_INFO(( "running services at %lu", next_wakeup ));
    fd_log_flush();

    fd_quic_service( client_quic );
    fd_quic_service( server_quic );

    buf[12] = ' ';
    //buf[15] = (char)( ( j / 10 ) + '0' );
    buf[16] = (char)( ( j % 10 ) + '0' );

    /* obtain an free stream */
    my_stream_meta_t * meta = get_stream();

    if( meta ) {
      fd_quic_stream_t * stream = meta->stream;

      FD_LOG_DEBUG(( "sending: %d", (int)j ));

      if( (j&1) == 0 ) {
        FD_LOG_DEBUG(( "even" ));
        fd_log_flush();
      }

      int rc = fd_quic_stream_send( stream, batch, 1 /* batch_sz */, 1 /* fin */ );
      FD_LOG_INFO(( "fd_quic_stream_send returned %d", rc ));

      if( rc == 1 ) {
        /* successful - stream will begin closing */
        /* stream and meta will be recycled when quic notifies the stream
           is closed via my_stream_notify_cb */
      } else {
        /* did not send, did not start finalize, so stream is still available */
        free_stream( meta );
      }
    } else {
      FD_LOG_WARNING(( "unable to send - no streams available" ));
      fd_log_flush();
    }
  }

  /* close the connections */
  fd_quic_conn_close( client_conn, 0 );
  fd_quic_conn_close( server_conn, 0 );

  /* allow acks to go */
  for( unsigned j = 0; j < 10; ++j ) {
    ulong ct = fd_quic_get_next_wakeup( client_quic );
    ulong st = fd_quic_get_next_wakeup( server_quic );
    ulong next_wakeup = fd_ulong_min( ct, st );

    if( next_wakeup == ~(ulong)0 ) {
      /* indicates no schedule, which is correct after connection
         instances have been reclaimed */
      FD_LOG_INFO(( "Finished cleaning up connections" ));
      break;
    }

    if( next_wakeup > now ) now = next_wakeup;

    FD_LOG_INFO(( "running services at %lu", next_wakeup ));
    fd_quic_service( client_quic );
    fd_quic_service( server_quic );
  }

  fd_quic_delete( server_quic );
  fd_quic_delete( client_quic );

  if( fail ) FD_LOG_ERR(( "fail" ));
  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}


