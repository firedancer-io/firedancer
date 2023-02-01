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
  uchar  eth_dst[6];
  uchar  eth_src[6];
  ushort eth_proto;

  // ip
  uchar  ip_hdrlen;
  uchar  ip_tos;
  ushort ip_tot_len;
  ushort ip_id;
  ushort ip_frag_off;
  uchar  ip_ttl;
  uchar  ip_proto;
  ushort ip_check;
  uint ip_src;
  uint ip_dst;

  // udp
  ushort udp_src;
  ushort udp_dst;
  ushort udp_len;
  ushort udp_check;

  // datagram
  uchar  text[64];
  uchar  pad[64];
  uchar  pad1[1024];
} packet_t;


void
calc_check( packet_t * pkt ) {
  ulong check = 0;

  check += pkt->ip_hdrlen;
  check += (uint)pkt->ip_tos << (uint)8;
  check += pkt->ip_tot_len;
  check += pkt->ip_id;
  check += pkt->ip_frag_off;
  check += pkt->ip_ttl;
  check += (uint)pkt->ip_proto << (uint)8;
  check += pkt->ip_src;
  check += pkt->ip_dst;

  pkt->ip_check = (ushort)( 0xffffu ^ ( check % 0xffffu ) );
}

void
calc_check2( packet_t * pkt ) {
#define STAGE(N) \
  uint x##N = 0u; \
  fd_memcpy( &x##N, (char*)&pkt->ip_hdrlen + (N<<2u), 4u )

  STAGE(0);
  STAGE(1);
  STAGE(2);
  STAGE(3);
  STAGE(4);

  ulong check0 = (ulong)x0 + (ulong)x1 + (ulong)x2 + (ulong)x3 + (ulong)x4;
  ulong check1 = ( check0 & 0xffffffffu ) + ( check0 >> 32u );
  ulong check2 = ( check1 & 0xffffu )     + ( check1 >> 16u );
  ulong check3 = ( check2 & 0xffffu )     + ( check2 >> 16u );

  FD_TEST( check3==0xFFFFU );
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

  ulong batch_sz = (ulong)roundf( f_batch_sz );

  FD_LOG_NOTICE(( "xdp test parms:" ));

  FD_LOG_NOTICE(( "--intf %s",      intf     ));
  FD_LOG_NOTICE(( "--batch-sz %ld", batch_sz ));

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

  ulong out_duration = (ulong)1e9;
  ulong t0 = (ulong)gettime();
  ulong t1 = t0 + 1;
  ulong tn = t0 + out_duration;

  ulong rx_cnt       = config.rx_ring_size;
  ulong tx_cnt       = config.tx_ring_size;

  fd_xdp_frame_meta_t * meta     = (fd_xdp_frame_meta_t*)malloc( batch_sz * sizeof( fd_xdp_frame_meta_t ) );
  unsigned              expected = 0; (void)expected;

  // enqueue rx frames for receive
  for( ulong j = 0; j < rx_cnt; ++j ) {
    ulong frame_offset = j * FRAME_SIZE;

    fd_xdp_rx_enqueue( xdp, &frame_offset, 1 );
  }

  // set up a stack of tx frames
  ulong * frame_stack     = (ulong*)malloc( tx_cnt * sizeof(ulong) );
  ulong     frame_stack_idx = 0;
  ulong   frame_size      = config.frame_size;

  for( ulong j = 0; j < tx_cnt; ++j ) {
    ulong k = rx_cnt + j;
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
    ulong avail = 0;
    do {
      avail = fd_xdp_rx_complete( xdp, &meta[0], batch_sz );
    } while( avail == 0 );

    t1 = (ulong)gettime();

    for( ulong j = 0; j < avail; ++j ) {
      tot_bytes += (float)meta[j].sz;

      /* echo back here */
      packet_t * rx_pkt = (packet_t*)( xdp->umem.addr + meta[j].offset );
      printf( "received packet %x:%u -> %x:%u\n",
          (unsigned)rx_pkt->ip_src, (unsigned)rx_pkt->udp_src,
          (unsigned)rx_pkt->ip_dst, (unsigned)rx_pkt->udp_dst );

      ulong pkt_sz = meta[j].sz;

      /* obtain a tx frame */
      if( frame_stack_idx > 0 ) {
        frame_stack_idx--;

        ulong frame_offset = frame_stack[frame_stack_idx];

        //packet_t tx_pkt[1];
        void * buf = (void*)( xdp->umem.addr + frame_offset );
        packet_t * tx_pkt = buf;

        /* copy packet into buffer */
        fd_memcpy( tx_pkt, rx_pkt, (ulong)meta[j].sz );

        /* switch eth, ip and udp, src and dst */
        fd_memcpy(  tx_pkt->eth_src,  rx_pkt->eth_dst, 6 );
        fd_memcpy(  tx_pkt->eth_dst,  rx_pkt->eth_src, 6 );
        fd_memcpy( &tx_pkt->ip_src,  &rx_pkt->ip_dst,  4 );
        fd_memcpy( &tx_pkt->ip_dst,  &rx_pkt->ip_src,  4 );

        /* make the ports the same */
        ushort port = htons( 42425u );
        fd_memcpy( &tx_pkt->udp_dst, &port, 2 );
        fd_memcpy( &tx_pkt->udp_src, &port, 2 );

        ushort udp_check = 0u; /* no udp checksum */
        fd_memcpy( &tx_pkt->udp_check, &udp_check, 2 );

        /* calculate checksum */
        tx_pkt->ip_check = 0u;
        calc_check( tx_pkt );
        calc_check2( tx_pkt );

        //__asm__( "" : : : "memory" );

        //memcpy( buf, tx_pkt, pkt_sz );

        /* enqueue */
        fd_xdp_frame_meta_t tx_meta = { frame_offset, (unsigned)pkt_sz, 0 };

        ulong queued = fd_xdp_tx_enqueue( xdp, &tx_meta, 1 );
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
    ulong enq_rc = fd_xdp_rx_enqueue2( xdp, meta, avail );

    if( enq_rc < avail ) {
      printf( "fd_xdp_rx_enqueue2 did not enqueue all frames\n" );
      exit(1);
    }

    // replenish tx
    ulong tx_completed = fd_xdp_tx_complete( xdp, frame_stack + frame_stack_idx, tx_cnt - frame_stack_idx );
    frame_stack_idx += tx_completed;

    if( tx_completed ) {
      FD_LOG_NOTICE(( "tx completed: %lu", tx_completed ));
    }

    if( t1 >= tn ) {
      float dt = (float)( t1 - t0 ) * 1e-9f;
      FD_LOG_NOTICE(( "byte rate:   %f", (double)( tot_bytes / dt ) ));
      FD_LOG_NOTICE(( "packet rate: %f", (double)( tot_pkt   / dt ) ));
      FD_LOG_NOTICE(( "batch rate:  %f", (double)( tot_batch / dt ) ));

      tot_bytes = tot_pkt = tot_batch = 0;

      t0 = t1;
      tn = (ulong)gettime() + out_duration;
    }

    //usleep(100);
  }

  // close down
  fd_xdp_delete( xdp );

  // free memory
  free( xdp_mem );

  return 0;
}


