#include <stdio.h>
#include <stdlib.h>

#include "fd_quic_transport_params.h"

int
main( int argc, char ** argv ) {
  fd_quic_dump_transport_param_desc( stdout );

  return 0;
}

