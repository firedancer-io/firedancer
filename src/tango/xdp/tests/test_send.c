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
#include <linux/if_link.h>
#include <linux/types.h>
#include <poll.h>
#include <arpa/inet.h>
#include <math.h>
#include <time.h>

#include "../fd_xdp.h"
#include "../fd_xdp_private.h"
#include "../../../util/fd_util.h"

#define DEFAULT_COMP_RING_SIZE 32
#define DEFAULT_FILL_RING_SIZE 1024
#define DEFAULT_RX_RING_SIZE 1024
#define DEFAULT_TX_RING_SIZE 1024

#define NUM_FRAMES 2048

long
gettime( void ) {
  struct timespec ts;
  clock_gettime( CLOCK_REALTIME, &ts );

  return (long)ts.tv_sec * (long)1e9 + (long)ts.tv_nsec;
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
  uint   ip_src;
  uint   ip_dst;

  // udp
  ushort udp_src;
  ushort udp_dst;
  ushort udp_len;
  ushort udp_check;

  // datagram
  uint x;
  uchar  text[1500];
  uchar  pad[64];
} packet_t;


#if 0
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

  pkt->ip_check = 0xffff - ( check % 0xffff );
}
#else
void
calc_check( packet_t * pkt ) {
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

  pkt->ip_check = (ushort)( check3 ^ 0xffffu );
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

  long pkt_sz   = (long)roundf( f_pkt_sz );
  long delay_ns = (long)roundf( f_delay_ms * 1e6f );
  long batch_sz = (long)roundf( f_batch_sz );

  FD_LOG_NOTICE(( "xdp test parms:" ));

  FD_LOG_NOTICE(( "--intf %s",      intf                    ));
  FD_LOG_NOTICE(( "--pkt-sz %ld",   pkt_sz                  ));
  FD_LOG_NOTICE(( "--delay-ms %f",  (double)delay_ns * 1e-6 ));
  FD_LOG_NOTICE(( "--batch-sz %ld", batch_sz                ));

  fd_xdp_config_t config;
  fd_xdp_config_init( &config );

  config.bpf_pin_dir = "/sys/fs/bpf";
  config.bpf_pgm_file = "fd_xdp_bpf_udp.o";
  config.xdp_mode = XDP_FLAGS_SKB_MODE;
  //config.xdp_mode = XDP_FLAGS_DRV_MODE;
  //config.xdp_mode = XDP_FLAGS_HW_MODE;
  config.frame_size = 2048;
  config.tx_ring_size = 256;
  config.completion_ring_size = 256;

  void * xdp_mem = aligned_alloc( fd_xdp_align(), fd_xdp_footprint( &config ) );

  fd_xdp_t * xdp = fd_xdp_new( xdp_mem, intf, &config );
  FD_TEST( xdp );

#define IP_ADDR_(a,b,c,d,_) ( _((a),0x00) + _((b),0x08) + _((c),0x10) + _((d),0x18) )
#define IP_ADDR_SHIFT(u,v) ( (uint)(u)<<(uint)(v) )
#define IP_ADDR(a,b,c,d) IP_ADDR_(a,b,c,d,IP_ADDR_SHIFT)

  // construct udp
  packet_t pkt = {
    //.eth_dst     = { 0x64, 0x3f, 0x5f, 0xa0, 0xba, 0x00 }, // 64:3f:5f:a0:ba:00
    //.eth_src     = { 0x64, 0x3f, 0x5f, 0xa1, 0x19, 0x60 }, // 64:3f:5f:a1:19:60
    .eth_dst     = { 0x24, 0x8a, 0x07, 0x87, 0x22, 0xff }, // 24:8a:07:87:22:ff
    .eth_src     = { 0x24, 0x8a, 0x07, 0x8f, 0xa2, 0x9d }, // 24:8a:07:8f:a2:9d
    .eth_proto   = htons( 0x0800 ),

    .ip_hdrlen   = 0x45,
    .ip_tos      = 0,
    .ip_tot_len  = htons( (ushort)( pkt_sz - 14 ) ),
    .ip_id       = 0,
    .ip_frag_off = 0,
    .ip_ttl      = 64,
    .ip_proto    = 17,
    .ip_check    = 0,
    .ip_src      = IP_ADDR( 10,10,10,10 ),
    .ip_dst      = IP_ADDR( 7,199,14,113 ),
// 7.199.14.197.42425

    .udp_src     = htons( 42424 ),
    .udp_dst     = htons( 42425 ),
    .udp_len     = htons( (ushort)( pkt_sz - 14 - 20 ) ),
    .udp_check   = 0,

    .x           = 0,
    .text        = "test"
  };

  ushort ip_id = 160;

  ulong     pool_sz         = config.fill_ring_size + config.tx_ring_size;
  ulong * frame_stack     = (ulong*)malloc( pool_sz * sizeof(ulong) );
  ulong     frame_stack_idx = 0;
  ulong   frame_size      = config.frame_size;

  for( ulong j = 0; j < pool_sz; ++j ) {
    frame_stack[frame_stack_idx] = j*frame_size; // push an index onto the frame stack
    frame_stack_idx++;
  }

  fd_xdp_frame_meta_t *meta = (fd_xdp_frame_meta_t*)malloc( (ulong)batch_sz * sizeof(fd_xdp_frame_meta_t) );
  ulong meta_idx = 0;
  ulong completed = 0;
  while(1) {
    // obtain an unused frame
    //long t0 = gettime();
    while( frame_stack_idx == 0 ) {
      /* poll for completed frames
         loads directly onto the stack */
      completed = fd_xdp_tx_complete( xdp, frame_stack + frame_stack_idx, pool_sz - frame_stack_idx );
      frame_stack_idx += completed;
    }
    //long t1 = gettime();

    //long dt = t1 - t0;
    //if( dt > 1000 ) {
      //printf( "spent %ld waiting for completed frames\n", dt ); fflush( stdout );
    //}

    /* pop a frame off the stack */
    frame_stack_idx--;
    ulong frame_offset = frame_stack[frame_stack_idx];

    void * buffer = (void*)( xdp->umem.addr + frame_offset );

    /* copy packet into buffer */
    fd_memcpy( buffer, &pkt, (ulong)pkt_sz );

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

    if( (ulong)meta_idx == (ulong)batch_sz ) {
      fd_xdp_frame_meta_t *p = meta;
      ulong remain = (ulong)batch_sz;
      __asm__ __volatile__( "" : : : "memory" );
      ulong queued = fd_xdp_tx_enqueue( xdp, p, remain );
      if( queued != remain ) {
        //printf( "queued: %lu  remain: %lu\n", (ulong)queued, (ulong)remain ); fflush( stdout );
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
    ulong remain = meta_idx;
    do {
      ulong queued = fd_xdp_tx_enqueue( xdp, p, remain );
      //printf( "queued: %lu  remain: %lu\n", (ulong)queued, (ulong)remain ); fflush( stdout );
      p += queued;
      remain -= queued;
    } while( remain );
  }

  // wait for completion
  // TODO implement
  sleep( 1 );

  // close down
  fd_xdp_delete( xdp );

  // free memory
  free( xdp_mem );

  return 0;
}


