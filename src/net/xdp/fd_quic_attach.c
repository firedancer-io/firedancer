#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "fd_xdp.h"
#include "fd_xdp_private.h"


int
main( int argc, char **argv ) {
  char const * intf         = "";
  char const * bpf_pgm      = NULL;
  char const * bpf_pin_name = "fd_bpf_pin";
  char const * bpf_pin_dir  = "/sys/fs/bpf/firedancer";

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

    // --bpf-pgm
    if( strcmp( argv[i], "--bpf-pgm" ) == 0 ) {
      if( i+1 < argc ) {
        bpf_pgm = argv[i+1];
        i++;
        continue;
      } else {
        fprintf( stderr, "--bpf-pgm requires a value\n" );
        exit(1);
      }
    }

    // --bpf-pin-name
    if( strcmp( argv[i], "--bpf-pin-name" ) == 0 ) {
      if( i+1 < argc ) {
        bpf_pin_name = argv[i+1];
        i++;
        continue;
      } else {
        fprintf( stderr, "--bpf-pin-name requires a value\n" );
        exit(1);
      }
    }

    // --bpf-pin-dir
    if( strcmp( argv[i], "--bpf-pin-dir" ) == 0 ) {
      if( i+1 < argc ) {
        bpf_pin_dir = argv[i+1];
        i++;
        continue;
      } else {
        fprintf( stderr, "--bpf-pin-dir requires a value\n" );
        exit(1);
      }
    }
  }

  if( bpf_pgm == NULL ) {
    fprintf( stderr, "please specify the bpf program file via argument --bpf-pgm\n" );
    exit(1);
  }

  printf( "%s parms:\n", argv[0] );

  printf( "--intf %s\n",         intf );
  printf( "--bpf-pgm %s\n",      bpf_pgm );
  printf( "--bpf-pin-name %s\n", bpf_pin_name );
  printf( "--bpf-pin-dir %s\n",  bpf_pin_dir );

  int rc = fd_bpf_install( bpf_pgm, intf, bpf_pin_dir, bpf_pin_name, 0, 0 );
  if( rc != 0 ) {
    fprintf( stderr, "fd_bpf_install failed with rc: %d\n", rc );
    exit(1);
  }

  return 0;
}


