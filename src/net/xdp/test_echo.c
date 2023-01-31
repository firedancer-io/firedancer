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
  uint8_t  text[64];
  uint8_t  pad[64];
  uint8_t  pad1[1024];
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

  pkt->ip_check = (uint16_t)( 0xffffu ^ ( check % 0xffffu ) );
}

void
calc_check2( packet_t * pkt ) {
#define STAGE(N) \
  uint32_t x##N = 0u; \
  memcpy( &x##N, (char*)&pkt->ip_hdrlen + (N<<2u), 4u )

  STAGE(0);
  STAGE(1);
  STAGE(2);
  STAGE(3);
  STAGE(4);

  uint64_t check0 = (uint64_t)x0 + (uint64_t)x1 + (uint64_t)x2 + (uint64_t)x3 + (uint64_t)x4;
  uint64_t check1 = ( check0 & 0xffffffffu ) + ( check0 >> 32u );
  uint64_t check2 = ( check1 & 0xffffu )     + ( check1 >> 16u );
  uint64_t check3 = ( check2 & 0xffffu )     + ( check2 >> 16u );

  if( check3 != 0xffffu ) {
    printf( "ip checksums don't match\n" );
    exit(1);
  }
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

  void * xdp_mem = aligned_alloc( fd_xdp_align(), fd_xdp_footprint( &config ) );

  fd_xdp_t * xdp = fd_xdp_new( xdp_mem, intf, &config );

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

  uint64_t rx_cnt       = config.rx_ring_size;
  uint64_t tx_cnt       = config.tx_ring_size;

  fd_xdp_frame_meta_t * meta     = (fd_xdp_frame_meta_t*)malloc( batch_sz * sizeof( fd_xdp_frame_meta_t ) );
  unsigned              expected = 0; (void)expected;

  // enqueue rx frames for receive
  for( size_t j = 0; j < rx_cnt; ++j ) {
    uint64_t frame_offset = j * FRAME_SIZE;

    fd_xdp_rx_enqueue( xdp, &frame_offset, 1 );
  }

  // set up a stack of tx frames
  uint64_t * frame_stack     = (uint64_t*)malloc( tx_cnt * sizeof(uint64_t) );
  size_t     frame_stack_idx = 0;
  uint64_t   frame_size      = config.frame_size;

  for( size_t j = 0; j < tx_cnt; ++j ) {
    size_t k = rx_cnt + j;
    frame_stack[frame_stack_idx] = k*frame_size; // push an index onto the frame stack
    frame_stack_idx++;
  }

  // wait for first RX
  printf( "Waiting for first packet\n" );
  printf( "  Don't forget ethtool\n" );
  printf( "    sudo ethtool -L enp59s0f1 combined 1\n" );
  fflush( stdout );

  while(1) {
    // wait for RX
    size_t avail = 0;
    do {
      avail = fd_xdp_rx_complete( xdp, &meta[0], batch_sz );
    } while( avail == 0 );

    t1 = (uint64_t)gettime();

    for( size_t j = 0; j < avail; ++j ) {
      tot_bytes += (float)meta[j].sz;

      /* echo back here */
      packet_t * rx_pkt = (packet_t*)( xdp->umem.addr + meta[j].offset );
      printf( "received packet %x:%u -> %x:%u\n",
          (unsigned)rx_pkt->ip_src, (unsigned)rx_pkt->udp_src,
          (unsigned)rx_pkt->ip_dst, (unsigned)rx_pkt->udp_dst );

      uint64_t pkt_sz = meta[j].sz;

      /* obtain a tx frame */
      if( frame_stack_idx > 0 ) {
        frame_stack_idx--;

        uint64_t frame_offset = frame_stack[frame_stack_idx];

        //packet_t tx_pkt[1];
        void * buf = (void*)( xdp->umem.addr + frame_offset );
        packet_t * tx_pkt = buf;

        /* copy packet into buffer */
        memcpy( tx_pkt, rx_pkt, (size_t)meta[j].sz );

        /* switch eth, ip and udp, src and dst */
        memcpy(  tx_pkt->eth_src,  rx_pkt->eth_dst, 6 );
        memcpy(  tx_pkt->eth_dst,  rx_pkt->eth_src, 6 );
        memcpy( &tx_pkt->ip_src,  &rx_pkt->ip_dst,  4 );
        memcpy( &tx_pkt->ip_dst,  &rx_pkt->ip_src,  4 );

        /* make the ports the same */
        uint16_t port = htons( 42425u );
        memcpy( &tx_pkt->udp_dst, &port, 2 );
        memcpy( &tx_pkt->udp_src, &port, 2 );

        uint16_t udp_check = 0u; /* no udp checksum */
        memcpy( &tx_pkt->udp_check, &udp_check, 2 );

        /* calculate checksum */
        tx_pkt->ip_check = 0u;
        calc_check( tx_pkt );
        calc_check2( tx_pkt );

        //__asm__( "" : : : "memory" );

        //memcpy( buf, tx_pkt, pkt_sz );

        /* enqueue */
        fd_xdp_frame_meta_t tx_meta = { frame_offset, (unsigned)pkt_sz, 0 };

        size_t queued = fd_xdp_tx_enqueue( xdp, &tx_meta, 1 );
        if( queued == 0 ) {
          /* we didn't queue anything, put frame back on stack */
          printf( "send failed\n" );

          /* this is redundant */
          frame_stack[frame_stack_idx] = frame_offset;

          /* adjust frame pointer */
          frame_stack_idx++;
        }
      }
    }

    tot_pkt += (float)avail;
    tot_batch += 1;

    // replenish rx
    size_t enq_rc = fd_xdp_rx_enqueue2( xdp, meta, avail );

    if( enq_rc < avail ) {
      printf( "fd_xdp_rx_enqueue2 did not enqueue all frames\n" );
      exit(1);
    }

    // replenish tx
    uint64_t tx_completed = fd_xdp_tx_complete( xdp, frame_stack + frame_stack_idx, tx_cnt - frame_stack_idx );
    frame_stack_idx += tx_completed;

    if( tx_completed ) {
      printf( "tx completed: %u\n", (unsigned)tx_completed );
      fflush( stdout );
    }

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
  fd_xdp_delete( xdp );

  // free memory
  free( xdp_mem );

  return 0;
}


