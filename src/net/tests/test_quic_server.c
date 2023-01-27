#include "../fd_quic.h"

#include <stdio.h>
#include <stdlib.h>

#include "fd_pcap.h"


void
write_shb( FILE * file ) {
  pcap_shb_t shb[1] = {{ 0x0A0D0D0A, sizeof( pcap_shb_t ), 0x1A2B3C4D, 1, 0, (uint64_t)-1, sizeof( pcap_shb_t ) }};
  size_t rc = fwrite( shb, sizeof(shb), 1, file );
  if( rc != 1 ) {
    abort();
  }
}

void
write_idb( FILE * file ) {
  pcap_idb_t idb[1] = {{ 0x00000001, sizeof( pcap_idb_t ), 1, 0, 0, sizeof( pcap_idb_t ) }};
  size_t rc = fwrite( idb, sizeof(idb), 1, file );
  if( rc != 1 ) {
    abort();
  }
}

void
write_epb( FILE * file, uchar * buf, unsigned buf_sz, uint64_t ts ) {
  if( buf_sz == 0 ) return;

  uint32_t ts_lo = (uint32_t)ts;
  uint32_t ts_hi = (uint32_t)( ts >> 32u );

  unsigned align_sz = ( ( buf_sz - 1u ) | 0x03u ) + 1u;
  unsigned tot_len  = align_sz + (unsigned)sizeof( pcap_epb_t ) + 4;
  pcap_epb_t epb[1] = {{
    0x00000006,
    tot_len,
    0, /* intf id */
    ts_hi,
    ts_lo,
    buf_sz,
    buf_sz }};

  size_t rc = fwrite( epb, sizeof( epb ), 1, file );
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


extern uchar  pkt_full[];
extern size_t pkt_full_sz;

size_t
aio_cb( void * context, fd_aio_buffer_t * batch, size_t batch_sz ) {
  (void)context;

  printf( "aio_cb callback\n" );
  for( size_t j = 0; j < batch_sz; ++j ) {
    printf( "batch %d\n", (int)j );
    uchar const * data = (uchar const *)batch[j].data;
    for( size_t k = 0; k < batch[j].data_sz; ++k ) {
      printf( "%2.2x ", (unsigned)data[k] );
    }
    printf( "\n\n" );
  }

  fflush( stdout );

  return batch_sz; /* consumed all */
}

void
my_stream_receive_cb( fd_quic_stream_t * stream,
                      void *             ctx,
                      uchar const *      data,
                      size_t             data_sz,
                      uint64_t           offset ) {
  (void)ctx;
  (void)stream;

  printf( "my_stream_receive_cb : received data from peer. size: %lu  offset: %lu\n",
      (long unsigned)data_sz, (long unsigned)offset );
  printf( "%s\n", data );
}

fd_quic_t *
new_quic( fd_quic_config_t * quic_config ) {

  ulong  align    = fd_quic_align();
  ulong  fp       = fd_quic_footprint( quic_config );
  void * mem      = malloc( fp + align );
  size_t smem     = (size_t)mem;
  size_t memalign = smem % align;
  void * aligned  = ((uchar*)mem) + ( memalign == 0 ? 0 : ( align - memalign ) );

  fd_quic_t * quic = fd_quic_new( aligned, quic_config );
  if( quic == NULL ) {
    printf( "fd_quic_new returned NULL\n" );
    exit(1);
  }

  return quic;
}


struct my_context {
  int server;
};
typedef struct my_context my_context_t;

int server_complete = 0;
int client_complete = 0;

/* server connetion received in callback */
fd_quic_conn_t * server_conn = NULL;

void my_connection_new( fd_quic_conn_t * conn, void * vp_context ) {
  (void)conn;
  (void)vp_context;

  printf( "server handshake complete\n" );
  fflush( stdout );

  server_complete = 1;
  server_conn = conn;
}

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


size_t
pipe_aio_receive( void * vp_ctx, fd_aio_buffer_t * batch, size_t batch_sz ) {
  static uint64_t ts = 0;
  ts += 100000ul;

  aio_pipe_t * pipe = (aio_pipe_t*)vp_ctx;

#if 1
  for( unsigned j = 0; j < batch_sz; ++j ) {
    write_epb( pipe->file, batch[j].data, (unsigned)batch[j].data_sz, ts );
  }
  fflush( pipe->file );
#endif

  /* forward */
  return fd_aio_send( pipe->aio, batch, batch_sz );
}


/* global "clock" */
uint64_t test_clock( void * ctx ) {
  return clock_gettime;
}

struct fd_xdp_tx {
  size_t     pool_sz;
  uint64_t * frame_stack;
  size_t     frame_stack_idx;
  uint64_t   frame_size;
};
typedef struct fd_xdp_tx fd_xdp_tx_t;

void
fd_xdp_tx_init( fd_xdp_tx_t * pool, fd_xdp_config_t * config ) {
  pool->pool_sz         = config->fill_ring_size + config->tx_ring_size;
  pool->frame_stack     = (uint64_t*)malloc( pool_sz * sizeof(uint64_t) );
  pool->frame_stack_idx = 0;
  pool->frame_size      = config->frame_size;

  for( size_t j = 0; j < pool_sz; ++j ) {
    pool->frame_stack[pool->frame_stack_idx] = j*pool->frame_size; // push an index onto the frame stack
    pool->frame_stack_idx++;
  }
}


uchar *
fd_xdp_tx_get_tx_buffer( fd_xdp_tx_t * pool, fd_xdp_t * xdp ) {
  size_t completed = 0;

  /* if we have no available buffers, wait for a completion */
  while( pool->frame_stack_idx == 0 ) {
    /* poll for completed frames
       loads directly onto the stack */
    completed = fd_xdp_tx_complete( xdp, pool->frame_stack + pool->frame_stack_idx, pool->pool_sz - pool->frame_stack_idx );
    pool->frame_stack_idx += completed;
  }

  /* pop a frame off the stack */
  pool->frame_stack_idx--;
  uint64_t frame_offset = pool->frame_stack[pool->frame_stack_idx];

  return (uchar*)( xdp->umem.addr + frame_offset );
}


void
fd_xdp_tx_reclaim( fd_xdp_tx_t * pool, fd_xdp_t * xdp ) {
  /* poll for completed frames
     loads directly onto the stack */
  pool->frame_stack_idx += fd_xdp_tx_complete( xdp,
                                               pool->frame_stack + pool->frame_stack_idx,
                                               pool->pool_sz - pool->frame_stack_idx );
}


/* transmit a buffer

   returns the number of buffers queued */
size_t
fd_xdp_tx_buffer( fd_xdp_t * xdp, uchar * buffer, unsigned pkt_sz ) {
  uint64_t frame_offset = (size_t)buffer - (size_t)xdp->umem.addr;
  fd_xdp_frame_meta_t meta[1] = {{ frame_offset, pkt_sz, 0 }};
  return fd_xdp_tx_enqueue( xdp, meta, 1u );
}


/* receive */
struct fd_xdp_rx {
};
typedef struct fd_xdp_rx fd_xdp_rx_t;


size_t
fd_xdp_rx( fd_xdp_t * xdp, fd_xdp_rx_t * xdp_rx ) {
  size_t cnt = fd_xdp_rx_complete( xdp, &xdp_rx->meta[0], xdp_rx->meta_cap );
  xdp_rx->meta_sz = cnt;
  return cnt;
}


uchar *
fd_xdp_rx_get_buffer( fd_xdp_t * xdp, fd_xdp_rx_t * xdp_rx, size_t idx ) {
  return xdp_rx->frame_memory + xdp_rx->meta[j].offset;
}


void
fd_xdp_rx_return( fd_xdp_t * xdp, fd_xdp_rx_t * xdp_rx ) {
  size_t     meta_sz = xdp_rx->meta_sz;
  uint64_t * rtn_idx = xdp_rx->rtn_idx;
  for( size_t j = 0; j < meta_sz; ++j ) {
    rtn_idx[j] = xdp_rx->meta[j].offset;
  }
  fd_xdp_rx_enqueue( xdp, rtn_idx, meta_sz );
}


int
main( int argc, char ** argv ) {
  FILE * pcap = fopen( "test_quic_hs.pcapng", "wb" );
  if( !pcap ) abort();

  write_shb( pcap );
  write_idb( pcap );

  (void)argc;
  (void)argv;

  /* confiugre xdp */
  char const * intf = "";
  float f_pkt_sz    = 64;
  float f_delay_ms  = 0.0f;
  float f_batch_sz  = 128;

  for( int i = 1; i < argc; ++i ) {
    // --intf
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
    if( strcmp( argv[i], "--pkt-sz" ) == 0 ) {
      if( i+1 < argc ) {
        f_pkt_sz = strtof( argv[i+1], NULL );
      } else {
        fprintf( stderr, "--pkt-sz requires a value\n" );
        exit(1);
      }
    }
    if( strcmp( argv[i], "--delay-ms" ) == 0 ) {
      if( i+1 < argc ) {
        f_batch_sz = strtof( argv[i+1], NULL );
      } else {
        fprintf( stderr, "--delay-ms requires a value\n" );
        exit(1);
      }
    }
    if( strcmp( argv[i], "--batch-sz" ) == 0 ) {
      if( i+1 < argc ) {
        f_batch_sz = strtof( argv[i+1], NULL );
      } else {
        fprintf( stderr, "--batch-sz requires a value\n" );
        exit(1);
      }
    }
  }

  int64_t pkt_sz   = (int64_t)roundf( f_pkt_sz );
  int64_t delay_ns = (int64_t)roundf( f_delay_ms * 1e6f );
  int64_t batch_sz = (int64_t)roundf( f_batch_sz );

  printf( "xdp test parms:\n" );

  printf( "--intf %s\n", intf );
  printf( "--pkt-sz %ld\n", pkt_sz );
  printf( "--delay-ms %f\n", (double)delay_ns * 1e-6 );
  printf( "--batch-sz %ld\n", batch_sz );

  fd_xdp_config_t config;
  fd_xdp_config_init( &config );

#define LG_FRAME_SIZE 11
#define FRAME_SIZE (1<<LG_FRAME_SIZE)

  config.bpf_pin_dir = "/sys/fs/bpf";
  config.bpf_pgm_file = "fd_xdp_bpf_udp.o";
  //config.xdp_mode = XDP_FLAGS_SKB_MODE;
  config.xdp_mode = XDP_FLAGS_DRV_MODE;
  //config.xdp_mode = XDP_FLAGS_HW_MODE;
  config.frame_size = 2048;
  config.tx_ring_size = 256;
  config.completion_ring_size = 256;

  fd_xdp_t * xdp = new_fd_xdp( intf, &config );

  if( !xdp ) {
    fprintf( stderr, "Failed to create fd_xdp. Aborting\n" );
    exit(1);
  }

  fd_xdp_add_key( xdp, 4433 );

  fd_xdp_tx_t pool;

  fd_xdp_tx_init( &pool, &config );


  fd_xdp_frame_meta_t *meta = (fd_xdp_frame_meta_t*)malloc( (size_t)batch_sz * sizeof(fd_xdp_frame_meta_t) );


  /* configure quic */

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
  tp->initial_max_streams_bidi                       = 128;
  tp->initial_max_streams_bidi_present               = 1;
  tp->initial_max_streams_uni                        = 128;
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

  quic_config.cert_file             = "cert.pem";
  quic_config.key_file              = "key.pem";

  quic_config.cb_stream_receive     = my_stream_receive_cb;

  quic_config.now_fn  = test_clock;
  quic_config.now_ctx = NULL;

  fd_quic_host_cfg_t server_cfg = { "server_host", 0x0a000001u, 4434 };

  quic_config.host_cfg = server_cfg;
  fd_quic_t * server_quic = new_quic( &quic_config );

  /* make use aio to point quic directly at quic */
  fd_aio_t * aio_n2q = fd_quic_get_aio_net_in( server_quic );

#if 0
  fd_quic_set_aio_net_out( server_quic, aio_q2n );
  fd_quic_set_aio_net_out( client_quic, aio_n2q );
#else
  /* create a pipe for catching data as it passes thru */
  aio_pipe_t pipe[2] = { { aio_n2q, pcap }, { aio_q2n, pcap } };

  fd_aio_t aio[2] = { { pipe_aio_receive, (void*)&pipe[0] }, { pipe_aio_receive, (void*)&pipe[1] } };

  fd_quic_set_aio_net_out( server_quic, &aio[1] );
#endif

  /* set up server_quic as server */
  fd_quic_listen( server_quic );

  /* set the callback for new connections */
  fd_quic_set_cb_conn_new( server_quic, my_connection_new );

  /* do general processing */
  while(1) {
    fd_quic_service( server_quic );
  }


  fd_quic_delete( server_quic );

  return 0;
}


