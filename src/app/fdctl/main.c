#include "fdctl.h"

#include "configure/configure.h"

configure_stage_t * STAGES[ CONFIGURE_STAGE_COUNT ] = {
  &large_pages,
  &shmem,
  &sysctl,
  &xdp,
  &xdp_leftover,
  &ethtool,
  &workspace_leftover,
  &workspace,
  NULL,
  NULL,
  NULL,
  NULL,
};

int
main( int     argc,
      char ** argv ) {
  main1( argc, argv );
}
