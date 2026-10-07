#include "fd_identity_transition.h"

/* Synthetic local bookkeeping benchmark, not validator throughput or
   transition latency.  Compiler fences are shared by both loops. */
static __attribute__((noinline)) long
measure( int   observed,
         ulong count ) {
  fd_identity_counter_t counter = {0};
  ulong baseline = 0UL;
  long start = fd_log_wallclock();
  for( ulong i=0UL; i<count; i++ ) {
    ulong slot = i & 65535UL;
    baseline = slot;
    __asm__ volatile( "" : "+m"(baseline), "+m"(counter) : : "memory" );
    if( observed ) fd_identity_submitted( &counter, slot );
    __asm__ volatile( "" : "+m"(baseline), "+m"(counter) : : "memory" );
  }
  long elapsed = fd_log_wallclock()-start;
  FD_LOG_NOTICE(( "checksum %lu", observed ? counter.slot+counter.has_slot : baseline ));
  return elapsed;
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );
  ulong count = 100000000UL;
  for( ulong repeat=0UL; repeat<5UL; repeat++ ) {
    long baseline = measure( 0, count );
    long observed = measure( 1, count );
    FD_LOG_NOTICE(( "baseline %.3f ns/op observed %.3f ns/op delta %.3f ns/op",
                    (double)baseline/(double)count, (double)observed/(double)count,
                    (double)(observed-baseline)/(double)count ));
  }
  fd_halt();
  return 0;
}
