#include "fd_stake_rewards.h"

int main( int argc, char * * argv ) {
  fd_boot( &argc, &argv );

  FD_LOG_WARNING(("FOOTPRINT %lu", fd_stake_rewards_footprint( 200000000UL, 32UL, 2<<20UL )));


  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
