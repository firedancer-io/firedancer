#include "fd_leaders.h"

FD_STATIC_ASSERT( alignof(fd_epoch_leaders_t)<=FD_EPOCH_LEADERS_ALIGN, alignment );


static uchar leaders_buf[ 16384UL ] __attribute__((aligned(FD_EPOCH_LEADERS_ALIGN)));

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  fd_epoch_leaders_new( leaders_buf, pub_cnt, sched_cnt );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
