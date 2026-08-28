#include "../../disco/fd_disco_base.h"
#include "fd_rdisp_mq.h"


int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}

