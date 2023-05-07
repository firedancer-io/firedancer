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

#define LG_FRAME_SIZE 11
#define FRAME_SIZE (1<<LG_FRAME_SIZE)
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
  uint ip_src;
  uint ip_dst;

  // udp
  ushort udp_src;
  ushort udp_dst;
  ushort udp_len;
  ushort udp_check;

  // datagram
  uint x;
  uchar  text[16];
  uchar  pad[64];
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

  pkt->ip_check = (ushort)( 0xffffu - (unsigned)( check % 0xffffu ) );
}


int
main( int argc, char **argv ) {
  char const * intf       = "";
  float        f_batch_sz = 128;
  uint         intf_queue = 0;

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
    if( strcmp( argv[i], "--intf-queue" ) == 0 ) {
      if( i+1 < argc ) {
        intf_queue = (uint)strtoul( argv[i+1], NULL, 0 );
      } else {
        fprintf( stderr, "--intf-queue requires a value\n" );
        exit(1);
      }
    }
  }

  ulong batch_sz = (ulong)roundf( f_batch_sz );

  printf( "xdp test parms:\n" );

  printf( "--intf %s\n",       intf );
  printf( "--batch-sz %ld\n",  batch_sz );
  printf( "--intf-queue %u\n", intf_queue );

  fd_xdp_config_t config;
  fd_xdp_config_init( &config );

  config.bpf_pin_dir = "/sys/fs/bpf";
  config.bpf_pgm_file = "fd_xdp_bpf_udp.o";
  config.xdp_mode = XDP_FLAGS_SKB_MODE;
  //config.xdp_mode = XDP_FLAGS_DRV_MODE;
  //config.xdp_mode = XDP_FLAGS_HW_MODE;
  config.frame_size = FRAME_SIZE;
  config.intf_queue = intf_queue;

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

  ulong frame_memory = fd_xdp_get_frame_memory( xdp );

  fd_xdp_frame_meta_t * meta     = (fd_xdp_frame_meta_t*)malloc( batch_sz * sizeof( fd_xdp_frame_meta_t ) );
  ulong *            complete = (ulong*)           malloc( batch_sz * sizeof( ulong ) );
  unsigned              expected = 0; (void)expected;

  // fill up fill ring
  for( ulong j = 0; j < ( config.fill_ring_size >> 1 ); ++j ) {
    ulong frame_offset = j * FRAME_SIZE;

      //ulong offs = frame_offset;
      //uchar * status = (uchar *)( frame_memory + offs + 2016 );
      //*status = 0;

    fd_xdp_rx_enqueue( xdp, &frame_offset, 1 );
  }
  fflush( stdout );

  // wait for first RX
  printf( "Waiting for first packet\n" );
  printf( "  Don't forget ethtool\n" );
  printf( "    sudo ethtool -L enp59s0f1 combined 1\n" );
  fflush( stdout );

  ulong avail = 0;
  do {
    avail = fd_xdp_rx_complete( xdp, &meta[0], 1 );
  } while( avail == 0 );

  // ignore them
  for( ulong j = 0; j < avail; ++j ) {
    complete[j] = meta[j].offset;
  }
  fd_xdp_rx_enqueue( xdp, &complete[0], avail );

  printf( "First packet received\n" );
  fflush( stdout );

  ulong frame_mask = FRAME_SIZE - 1;
  while(1) {
    // wait for RX
    ulong avail = 0;
    do {
      avail = fd_xdp_rx_complete( xdp, &meta[0], batch_sz );
    } while( avail == 0 );

    //for( ulong j = 0; j < avail; ++j ) {
    //  ulong offs = meta[j].offset & ~frame_mask;
    //  uchar * status = (uchar *)( frame_memory + offs + 2016 );
    //  if( *status != 0 ) {
    //    printf( "%u incorrect buffer status: %2.2x\n", __LINE__,  *status ); fflush( stdout );
    //  }

    //  printf( "dequeued %lu\n", ( offs >> LG_FRAME_SIZE ) );

    //  *status = 1;
    //}
    //fflush( stdout );

    t1 = (ulong)gettime();

    for( ulong j = 0; j < avail; ++j ) {
      tot_bytes += (float)meta[j].sz;

      // decode packet
#if 1
      packet_t * pkt = (packet_t*)( frame_memory + meta[j].offset );
      (void)pkt;
#else
      packet_t pkt[1];
      static ulong last_offset = 42;
      if( last_offset == meta[j].offset ) {
        printf( "same frame!\n" ); fflush( stdout );
        //exit(1);
      }
      last_offset = meta[j].offset;

      fd_memcpy( &pkt[0], (void*)( frame_memory + meta[j].offset ), sizeof( packet_t ) );
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

      //ulong offs = meta[j].offset & ~frame_mask;
      //uchar * status = (uchar *)( frame_memory + offs + 2016 );
      //if( *status != 1 ) {
      //  printf( "%u incorrect buffer status: %2.2x\n", __LINE__,  *status ); fflush( stdout );
      //}
      //*status = 0;
      //printf( "complete: %lu\n", meta[j].offset >> LG_FRAME_SIZE );

      uchar src_ip[4];
      uchar dst_ip[4];
      fd_memcpy( src_ip, &pkt->ip_src, 4 );
      fd_memcpy( dst_ip, &pkt->ip_dst, 4 );
      printf( "packet received: %2.2u.%2.2u.%2.2u.%2.2u:%u -> %2.2u.%2.2u.%2.2u.%2.2u:%u \n",
          (uint)src_ip[0],
          (uint)src_ip[1],
          (uint)src_ip[2],
          (uint)src_ip[3],
          (uint)pkt->udp_src,
          (uint)dst_ip[0],
          (uint)dst_ip[1],
          (uint)dst_ip[2],
          (uint)dst_ip[3],
          (uint)pkt->udp_dst );

      complete[j] = meta[j].offset & ~frame_mask;
    }
    //fflush( stdout );
    tot_pkt += (float)avail;
    tot_batch += 1;

    // replenish
    fd_xdp_rx_enqueue( xdp, &complete[0], avail );

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


