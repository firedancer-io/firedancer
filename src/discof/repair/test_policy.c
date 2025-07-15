#include "fd_policy.h"

int
main( int argc, char ** argv ) {
  fd_boot( &argc, &argv );

  fd_halt();
}
