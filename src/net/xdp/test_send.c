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
  uint8_t  text[1500];
  uint8_t  pad[64];
} packet_t;


#if 0
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

  pkt->ip_check = 0xffff - ( check % 0xffff );
}
#else
void
calc_check( packet_t * pkt ) {
  pkt->ip_check = 0;

#define STAGE(N) \
  uint32_t x##N; \
  memcpy( &x##N, (char*)pkt + (N<<2), 4 )

  STAGE(0);
  STAGE(1);
  STAGE(2);
  STAGE(3);
  STAGE(4);

  uint64_t check0 = x0 + x1 + x2 + x3 + x4;
  uint32_t check1 = (uint32_t)check0 + ( (uint32_t)( check0 >> 32u ) );
  uint16_t check2 = (uint16_t)( (uint16_t)check1 + ( (uint16_t)( check1 >> 16u ) ) );

  pkt->ip_check = check2;
}
#endif


int
main( int argc, char **argv ) {
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

  config.bpf_pgm_file = "bpf.o";
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

#define IP_ADDR_(a,b,c,d,_) ( _((a),0x00) + _((b),0x08) + _((c),0x10) + _((d),0x18) )
#define IP_ADDR_SHIFT(u,v) ( (uint32_t)(u)<<(uint32_t)(v) )
#define IP_ADDR(a,b,c,d) IP_ADDR_(a,b,c,d,IP_ADDR_SHIFT)

  // construct udp
  packet_t pkt = {
    //.eth_dst     = { 0x64, 0x3f, 0x5f, 0xa0, 0xba, 0x00 }, // 64:3f:5f:a0:ba:00
    //.eth_src     = { 0x64, 0x3f, 0x5f, 0xa1, 0x19, 0x60 }, // 64:3f:5f:a1:19:60
    .eth_dst     = { 0x24, 0x8a, 0x07, 0xab, 0xa5, 0x85 },
    .eth_src     = { 0x24, 0x8a, 0x07, 0x8f, 0xa2, 0x9d }, // 24:8a:07:8f:a2:9d
    .eth_proto   = htons( 0x0800 ),

    .ip_hdrlen   = 0x45,
    .ip_tos      = 0,
    .ip_tot_len  = htons( (uint16_t)( pkt_sz - 14 ) ),
    .ip_id       = 0,
    .ip_frag_off = 0,
    .ip_ttl      = 64,
    .ip_proto    = 17,
    .ip_check    = 0,
    .ip_src      = IP_ADDR( 10,10,10,10 ),
    .ip_dst      = IP_ADDR( 10,10,10,11 ),

    .udp_src     = htons( 42424 ),
    .udp_dst     = htons( 42424 ),
    .udp_len     = htons( (uint16_t)( pkt_sz - 14 - 20 ) ),
    .udp_check   = 0,
    
    .x           = 0,
    .text        = "test"
  };

  uint16_t ip_id = 160;

  size_t     pool_sz         = config.fill_ring_size + config.tx_ring_size;
  uint64_t * frame_stack     = (uint64_t*)malloc( pool_sz * sizeof(uint64_t) );
  size_t     frame_stack_idx = 0;
  uint64_t   frame_size      = config.frame_size;

  for( size_t j = 0; j < pool_sz; ++j ) {
    frame_stack[frame_stack_idx] = j*frame_size; // push an index onto the frame stack
    frame_stack_idx++;
  }

  fd_xdp_frame_meta_t *meta = (fd_xdp_frame_meta_t*)malloc( (size_t)batch_sz * sizeof(fd_xdp_frame_meta_t) );
  size_t meta_idx = 0;
  size_t completed = 0;
  while(1) {
    // obtain an unused frame
    //int64_t t0 = gettime();
    while( frame_stack_idx == 0 ) {
      /* poll for completed frames
         loads directly onto the stack */
      completed = fd_xdp_tx_complete( xdp, frame_stack + frame_stack_idx, pool_sz - frame_stack_idx );
      frame_stack_idx += completed;
    }
    //int64_t t1 = gettime();

    //int64_t dt = t1 - t0;
    //if( dt > 1000 ) {
      //printf( "spent %ld waiting for completed frames\n", dt ); fflush( stdout );
    //}

    /* pop a frame off the stack */
    frame_stack_idx--;
    uint64_t frame_offset = frame_stack[frame_stack_idx];

    void * buffer = (void*)( xdp->umem.addr + frame_offset );

    /* copy packet into buffer */
    memcpy( buffer, &pkt, (size_t)pkt_sz );

    /* calculate checksum */
    calc_check( buffer );

#if 0
    //struct xdp_desc pkt_desc = { i*FRAME_SIZE, 14 + 20 + 8 + 4 + 16 /* len */, 0 /* options */ };
    struct xdp_desc pkt_desc = { i*FRAME_SIZE, pkt_sz, 0 /* options */ };

    FD_RING_TEST_ENQUEUE(*xdp,tx,pkt_desc);

    //if( fd_xdp_tx_need_wakeup( xdp ) ) {
      sendto(xdp->xdp_sock,NULL,0,MSG_DONTWAIT,NULL,0); // can send a batch before calling sendto
    //}
#else
    meta[meta_idx++] = (fd_xdp_frame_meta_t){ frame_offset, (unsigned)pkt_sz, 0 };

    if( (size_t)meta_idx == (size_t)batch_sz ) {
      fd_xdp_frame_meta_t *p = meta;
      size_t remain = (size_t)batch_sz;
      __asm__ __volatile__( "" : : : "memory" );
      size_t queued = fd_xdp_tx_enqueue( xdp, p, remain );
      if( queued != remain ) {
        //printf( "queued: %lu  remain: %lu\n", (unsigned long)queued, (unsigned long)remain ); fflush( stdout );
        do {
          queued = fd_xdp_tx_enqueue( xdp, p, remain );
          p += queued;
          remain -= queued;

          /* reclaim */
          completed = fd_xdp_tx_complete( xdp, frame_stack + frame_stack_idx, pool_sz - frame_stack_idx );
          frame_stack_idx += completed;
        } while( remain );
      }

      /* batch complete */
      meta_idx = 0;

      /* reclaim */
      completed = fd_xdp_tx_complete( xdp, frame_stack + frame_stack_idx, pool_sz - frame_stack_idx );
      frame_stack_idx += completed;
    }
#endif

    pkt.ip_id = htons(ip_id++);
    pkt.x++;
  }

  if( meta_idx ) {
    fd_xdp_frame_meta_t *p = meta;
    size_t remain = meta_idx;
    do {
      size_t queued = fd_xdp_tx_enqueue( xdp, p, remain );
      //printf( "queued: %lu  remain: %lu\n", (unsigned long)queued, (unsigned long)remain ); fflush( stdout );
      p += queued;
      remain -= queued;
    } while( remain );
  }

  // wait for completion
  // TODO implement
  sleep( 1 );

  // close down
  delete_fd_xdp( xdp );

  return 0;
}


