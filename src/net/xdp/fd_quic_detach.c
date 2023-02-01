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

#include "../../util/fd_util_base.h"

void
detach( int ifindex ) {
  uint id = 0;
  int err = 0;
  err = bpf_get_link_xdp_id( ifindex, &id, 0 /* xpd flags */ );
  if( err ) {
    fprintf( stderr, "Error in bpf_get_link_xdp_id: %d\n", err );
    exit(1);
  }

  if( !id ) {
    fprintf( stderr, "No program on interface\n" );
    exit(1);
  }

  printf( "Prog id %d found on interface index %d\n", id, ifindex );

  // workaround for Mellanox cards
  err = bpf_set_link_xdp_fd( ifindex, -1, XDP_FLAGS_SKB_MODE );
  if( err ) {
    fprintf( stderr, "Error in bpf_set_link_xdp_fd\n" );
    exit(1);
  }

  err = bpf_set_link_xdp_fd( ifindex, -1, 0 );
  if( err ) {
    fprintf( stderr, "Error in bpf_set_link_xdp_fd\n" );
    exit(1);
  }

  printf( "Program removed\n" );
}


int
main( int argc, char **argv ) {
  char const * intf = "";

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
  }

  printf( "%s parms:\n", argv[0] );

  printf( "--intf %s\n", intf );

  // find interface
  unsigned ifindex = if_nametoindex( intf );
  if( ifindex == 0 ) {
    fprintf( stderr, "Unable to find interface %s: %d %s\n", intf, errno, strerror( errno ) );
    exit(1);
  }

  printf( "index of interface %s: %d\n", intf, ifindex ); fflush( stdout );

  detach( (int)ifindex );

  printf( "success!\n" );

  return 0;
}


