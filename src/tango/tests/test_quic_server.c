#include <stdio.h>
#include <stdlib.h>

#include <math.h>

#include <linux/if_xdp.h>

#include "../../util/fd_util_base.h"

#include "../quic/tests/fd_pcap.h"

#include "../xdp/fd_xdp.h"
#include "../xdp/fd_xdp_aio.h"

#include "../quic/fd_quic.h"


#define LG_FRAME_SIZE 11
#define FRAME_SIZE (1<<LG_FRAME_SIZE)

/* parse a mac address */
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

/* parse a mac address */
void
parse_ipv4_addr( uint * dst, char const * src ) {
  uint a[4] = {0};
  int r = sscanf( src, "%u.%u.%u.%u", a, a+1, a+2, a+3 );
  if( r != 4 ) {
    FD_LOG_ERR(( "Invalid ipv4 address: %s", src ));
  }

  *dst = ( a[0] << 030 ) | ( a[1] << 020 ) | ( a[2] << 010 ) | a[3];
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
write_epb( FILE * file, uchar * buf, unsigned buf_sz, ulong ts ) {
  if( buf_sz == 0 ) return;

  uint ts_lo = (uint)ts;
  uint ts_hi = (uint)( ts >> 32u );

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


extern uchar  pkt_full[];
extern ulong pkt_full_sz;

ulong
aio_cb( void * context, fd_aio_buffer_t * batch, ulong batch_sz ) {
  (void)context;

  printf( "aio_cb callback\n" );
  for( ulong j = 0; j < batch_sz; ++j ) {
    printf( "batch %d\n", (int)j );
    uchar const * data = (uchar const *)batch[j].data;
    for( ulong k = 0; k < batch[j].data_sz; ++k ) {
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
                      ulong             data_sz,
                      ulong           offset ) {
  (void)ctx;
  (void)stream;

  printf( "my_stream_receive_cb : received data from peer. size: %lu  offset: %lu\n",
      (ulong)data_sz, (ulong)offset );
  printf( "%s\n", data );
}

fd_quic_t *
new_quic( fd_quic_config_t * quic_config ) {

  ulong  align    = fd_quic_align();
  ulong  fp       = fd_quic_footprint( quic_config );
  void * mem      = malloc( fp + align );
  ulong smem     = (ulong)mem;
  ulong memalign = smem % align;
  void * aligned  = ((uchar*)mem) + ( memalign == 0 ? 0 : ( align - memalign ) );

  fd_quic_t * quic = fd_quic_new( aligned, quic_config );
  FD_TEST( quic );
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

  FD_LOG_NOTICE(( "client handshake complete" ));

  client_complete = 1;
}


/* pcap aio pipe */
struct aio_pipe {
  fd_aio_t * aio;
  FILE *     file;
};
typedef struct aio_pipe aio_pipe_t;


ulong
pipe_aio_receive( void * vp_ctx, fd_aio_buffer_t * batch, ulong batch_sz ) {
  static ulong ts = 0;
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
ulong test_clock( void * ctx ) {
  (void)ctx;

  struct timespec ts;
  clock_gettime( CLOCK_REALTIME, &ts );

  return (ulong)ts.tv_sec * (ulong)1e9 + (ulong)ts.tv_nsec;
}


int
main( int argc, char ** argv ) {
  FILE * pcap = fopen( "test_quic_service.pcapng", "wb" );
  if( !pcap ) abort();

  write_shb( pcap );
  write_idb( pcap );

  (void)argc;
  (void)argv;

  /* confiugre xdp */
  char const * intf        = "";
  float        f_batch_sz  = 128;
  uint         src_ip;
  uchar        src_mac[6];
  uchar        dft_route_mac[6];

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
    if( strcmp( argv[i], "--batch-sz" ) == 0 ) {
      if( i+1 < argc ) {
        f_batch_sz = strtof( argv[i+1], NULL );
      } else {
        fprintf( stderr, "--batch-sz requires a value\n" );
        exit(1);
      }
    }
    if( strcmp( argv[i], "--src-ip" ) == 0 ) {
      if( i+1 < argc ) {
        parse_ipv4_addr( &src_ip, argv[i+1] );
      } else {
        fprintf( stderr, "--src-ip requires a value\n" );
        exit(1);
      }
    }
    if( strcmp( argv[i], "--src-mac" ) == 0 ) {
      if( i+1 < argc ) {
        parse_mac( src_mac, argv[i+1] );
      } else {
        fprintf( stderr, "--src-mac requires a value\n" );
        exit(1);
      }
    }
    if( strcmp( argv[i], "--dft-route-mac" ) == 0 ) {
      if( i+1 < argc ) {
        parse_mac( dft_route_mac, argv[i+1] );
      } else {
        fprintf( stderr, "--dft-route-mac requires a value\n" );
        exit(1);
      }
    }
  }

  long batch_sz = (long)roundf( f_batch_sz );

  printf( "xdp test parms:\n" );

  printf( "--intf %s\n", intf );
  printf( "--batch-sz %ld\n", batch_sz );


  /* configure quic */

  /* Transport params:
       original_destination_connection_id (0x00)         :   len(0)
       max_idle_timeout (0x01)                           : * 60000
       stateless_reset_token (0x02)                      :   len(0)
       max_udp_payload_size (0x03)                       :   0
       initial_max_data (0x04)                           : * 1048576
       initial_max_stream_data_bidi_local (0x05)         : * 1048576
       initial_max_stream_data_bidi_remote (0x06)        : * 1048576
       initial_max_stream_data_uni (0x07)                : * 1048576
       initial_max_streams_bidi (0x08)                   : * 128
       initial_max_streams_uni (0x09)                    : * 128
       ack_delay_exponent (0x0a)                         : * 3
       max_ack_delay (0x0b)                              : * 25
       disable_active_migration (0x0c)                   :   0
       preferred_address (0x0d)                          :   len(0)
       active_connection_id_limit (0x0e)                 : * 8
       initial_source_connection_id (0x0f)               : * len(8) ec 73 1b 41 a0 d5 c6 fe
       retry_source_connection_id (0x10)                 :   len(0) */

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

  fd_memcpy( quic_config.net.default_route_mac, dft_route_mac, 6 );
  fd_memcpy( quic_config.net.src_mac, src_mac, 6 );

  fd_quic_host_cfg_t server_cfg = { "server_host", src_ip, 4433 };

  quic_config.host_cfg = server_cfg;
  fd_quic_t * server_quic = new_quic( &quic_config );

  /* set up xdp */
  fd_xdp_config_t config;
  fd_xdp_config_init( &config );

  config.bpf_pin_dir = "/sys/fs/bpf";
  config.bpf_pgm_file = "fd_xdp_bpf_udp.o";
  /* xdp_mode alternatives:
       XDP_FLAGS_SKB_MODE
       XDP_FLAGS_DRV_MODE
       XDP_FLAGS_HW_MODE */
  config.xdp_mode = XDP_FLAGS_SKB_MODE;
  config.frame_size = FRAME_SIZE;

  /* new xdp */
  void * xdp_mem = aligned_alloc( fd_xdp_align(), fd_xdp_footprint( &config ) );
  fd_xdp_t * xdp = fd_xdp_new( xdp_mem, intf, &config );
  if( !xdp ) {
    fprintf( stderr, "Failed to create fd_xdp. Aborting\n" );
    exit(1);
  }

  size_t aio_batch_sz = 32;

  /* new xdp_aio */
  void * xdp_aio_mem = aligned_alloc( fd_xdp_aio_align(), fd_xdp_aio_footprint( xdp, aio_batch_sz ) );
  fd_xdp_aio_t * xdp_aio = fd_xdp_aio_new( xdp_aio_mem, xdp, aio_batch_sz );
  if( !xdp_aio ) {
    fprintf( stderr, "Failed to create xdp_aio_mem\n" );
    exit(1);
  }

  /* add udp port to xdp map */
  fd_xdp_add_key( xdp, 4433 );

  /* set up aio ingress */
  fd_aio_t ingress = *fd_quic_get_aio_net_in( server_quic );
  fd_xdp_aio_ingress_set( xdp_aio, &ingress );

  fd_aio_t egress = *fd_xdp_aio_egress_get( xdp_aio );

#if 1
  /* set up egress */
  fd_quic_set_aio_net_out( server_quic, &egress );
#else
  /* create a pipe for catching data as it passes thru */
  aio_pipe_t pipe[2] = { { ingress, pcap }, { egress, pcap } };

  fd_aio_t aio[2] = { { pipe_aio_receive, (void*)&pipe[0] }, { pipe_aio_receive, (void*)&pipe[1] } };

  fd_quic_set_aio_net_out( server_quic, &aio[1] );
#endif

  /* set up server_quic as server */
  fd_quic_listen( server_quic );

  /* set the callback for new connections */
  fd_quic_set_cb_conn_new( server_quic, my_connection_new );

  /* do general processing */
  while(1) {
    /* service quic */
    fd_quic_service( server_quic );

    /* service xdp */
    fd_xdp_aio_service( xdp_aio );
  }


  fd_quic_delete( server_quic );

  return 0;
}


