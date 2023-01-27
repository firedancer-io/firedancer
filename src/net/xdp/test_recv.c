#include <stdint.h>
#include <sys/mman.h>
#include <unistd.h>
#include <linux/if_xdp.h>
#include <net/if.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <linux/if_link.h>
#include <linux/types.h>
#include <poll.h>
#include <arpa/inet.h>
#include <math.h>
#include <time.h>

#include "fd_xdp.h"
#include "fd_xdp_private.h"

#define DEFAULT_COMP_RING_SIZE 32
#define DEFAULT_FILL_RING_SIZE 1024
#define DEFAULT_RX_RING_SIZE 1024
#define DEFAULT_TX_RING_SIZE 1024

#define LG_FRAME_SIZE 11
#define FRAME_SIZE (1<<LG_FRAME_SIZE)
#define NUM_FRAMES 2048

int64_t
gettime() {
  struct timespec ts;
  clock_gettime( CLOCK_REALTIME, &ts );

  return (int64_t)ts.tv_sec * (int64_t)1e9 + (int64_t)ts.tv_nsec;
}

typedef struct
  __attribute__((__packed__))
{
  uint8_t  eth_dst[6];
  uint8_t  eth_src[6];
  uint16_t eth_proto;

  // ip
  uint8_t  ip_hdrlen;
  uint8_t  ip_tos;
  uint16_t ip_tot_len;
  uint16_t ip_id;
  uint16_t ip_frag_off;
  uint8_t  ip_ttl;
  uint8_t  ip_proto;
  uint16_t ip_check;
  uint32_t ip_src;
  uint32_t ip_dst;

  // udp
  uint16_t udp_src;
  uint16_t udp_dst;
  uint16_t udp_len;
  uint16_t udp_check;

  // datagram
  uint32_t x;
  uint8_t  text[16];
  uint8_t  pad[64];
} packet_t;


void
calc_check( packet_t * pkt ) {
  uint64_t check = 0;

  check += pkt->ip_hdrlen;
  check += (uint32_t)pkt->ip_tos << (uint32_t)8;
  check += pkt->ip_tot_len;
  check += pkt->ip_id;
  check += pkt->ip_frag_off;
  check += pkt->ip_ttl;
  check += (uint32_t)pkt->ip_proto << (uint32_t)8;
  check += pkt->ip_src;
  check += pkt->ip_dst;

  pkt->ip_check = (uint16_t)( 0xffffu - (unsigned)( check % 0xffffu ) );
}


int
main( int argc, char **argv ) {
  char const * intf = "";
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
    if( strcmp( argv[i], "--batch-sz" ) == 0 ) {
      if( i+1 < argc ) {
        f_batch_sz = strtof( argv[i+1], NULL );
      } else {
        fprintf( stderr, "--batch-sz requires a value\n" );
        exit(1);
      }
    }
  }

  uint64_t batch_sz = (uint64_t)roundf( f_batch_sz );

  printf( "xdp test parms:\n" );

  printf( "--intf %s\n", intf );
  printf( "--batch-sz %ld\n", batch_sz );

  fd_xdp_config_t config;
  fd_xdp_config_init( &config );

  config.bpf_pin_dir = "/sys/fs/bpf";
  config.bpf_pgm_file = "fd_xdp_bpf_udp.o";
  config.xdp_mode = XDP_FLAGS_SKB_MODE;
  //config.xdp_mode = XDP_FLAGS_DRV_MODE;
  //config.xdp_mode = XDP_FLAGS_HW_MODE;
  config.frame_size = FRAME_SIZE;

  fd_xdp_t * xdp = new_fd_xdp( intf, &config );

  if( !xdp ) {
    fprintf( stderr, "Failed to create fd_xdp. Aborting\n" );
    exit(1);
  }

  fd_xdp_add_key( xdp, 42421 );
  fd_xdp_add_key( xdp, 42423 );
  fd_xdp_add_key( xdp, 42425 );

  float tot_bytes = 0;
  float tot_pkt   = 0;
  float tot_batch = 0;

  uint64_t out_duration = (uint64_t)1e9;
  uint64_t t0 = (uint64_t)gettime();
  uint64_t t1 = t0 + 1;
  uint64_t tn = t0 + out_duration;

  uint64_t frame_memory = fd_xdp_get_frame_memory( xdp );

  fd_xdp_frame_meta_t * meta     = (fd_xdp_frame_meta_t*)malloc( batch_sz * sizeof( fd_xdp_frame_meta_t ) );
  uint64_t *            complete = (uint64_t*)           malloc( batch_sz * sizeof( uint64_t ) );
  unsigned              expected = 0; (void)expected;

  // fill up fill ring
  for( size_t j = 0; j < ( config.fill_ring_size >> 1 ); ++j ) {
    uint64_t frame_offset = j * FRAME_SIZE;

      //uint64_t offs = frame_offset;
      //uint8_t * status = (uint8_t *)( frame_memory + offs + 2016 );
      //*status = 0;

    fd_xdp_rx_enqueue( xdp, &frame_offset, 1 );
  }
  fflush( stdout );

  // wait for first RX
  printf( "Waiting for first packet\n" );
  printf( "  Don't forget ethtool\n" );
  printf( "    sudo ethtool -L enp59s0f1 combined 1\n" );
  fflush( stdout );

  size_t avail = 0;
  do {
    avail = fd_xdp_rx_complete( xdp, &meta[0], 1 );
  } while( avail == 0 );

  // ignore them
  for( size_t j = 0; j < avail; ++j ) {
    complete[j] = meta[j].offset;
  }
  fd_xdp_rx_enqueue( xdp, &complete[0], avail );

  printf( "First packet received\n" );
  fflush( stdout );

  uint64_t frame_mask = FRAME_SIZE - 1;
  while(1) {
    // wait for RX
    size_t avail = 0;
    do {
      avail = fd_xdp_rx_complete( xdp, &meta[0], batch_sz );
    } while( avail == 0 );

    //for( size_t j = 0; j < avail; ++j ) {
    //  uint64_t offs = meta[j].offset & ~frame_mask;
    //  uint8_t * status = (uint8_t *)( frame_memory + offs + 2016 );
    //  if( *status != 0 ) {
    //    printf( "%u incorrect buffer status: %2.2x\n", __LINE__,  *status ); fflush( stdout );
    //  }

    //  printf( "dequeued %lu\n", ( offs >> LG_FRAME_SIZE ) );

    //  *status = 1;
    //}
    //fflush( stdout );

    t1 = (uint64_t)gettime();

    for( size_t j = 0; j < avail; ++j ) {
      tot_bytes += (float)meta[j].sz;

      // decode packet
#if 1
      packet_t * pkt = (packet_t*)( frame_memory + meta[j].offset );
      (void)pkt;
#else
      packet_t pkt[1];
      static uint64_t last_offset = 42;
      if( last_offset == meta[j].offset ) {
        printf( "same frame!\n" ); fflush( stdout );
        //exit(1);
      }
      last_offset = meta[j].offset;

      memcpy( &pkt[0], (void*)( frame_memory + meta[j].offset ), sizeof( packet_t ) );
#endif

#if 0
      if( pkt->x != expected ) {
        printf( "missed: %d  expected: %u  got: %u\n", pkt->x - expected, expected, pkt->x );
        fflush( stdout );
      }

      expected = pkt->x + 1;
#endif

      //printf( "got packet with index: %u  (%u)\n", (unsigned)pkt->x, (unsigned)( meta[j].offset / FRAME_SIZE ) );

      // return packet

      //uint64_t offs = meta[j].offset & ~frame_mask;
      //uint8_t * status = (uint8_t *)( frame_memory + offs + 2016 );
      //if( *status != 1 ) {
      //  printf( "%u incorrect buffer status: %2.2x\n", __LINE__,  *status ); fflush( stdout );
      //}
      //*status = 0;
      //printf( "complete: %lu\n", meta[j].offset >> LG_FRAME_SIZE );

      complete[j] = meta[j].offset & ~frame_mask;
    }
    //fflush( stdout );
    tot_pkt += (float)avail;
    tot_batch += 1;

    // replenish
    fd_xdp_rx_enqueue( xdp, &complete[0], avail );

    if( t1 >= tn ) {
      float dt = (float)( t1 - t0 ) * 1e-9f;
      printf( "byte rate:   %f\n", (double)( tot_bytes / dt ) );
      printf( "packet rate: %f\n", (double)( tot_pkt   / dt ) );
      printf( "batch rate:  %f\n", (double)( tot_batch / dt ) );

      tot_bytes = tot_pkt = tot_batch = 0;

      t0 = t1;
      tn = (uint64_t)gettime() + out_duration;
    }

    //usleep(100);
  }

  // close down
  delete_fd_xdp( xdp );

  return 0;
}


