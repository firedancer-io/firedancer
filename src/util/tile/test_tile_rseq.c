#define _GNU_SOURCE
#include "../fd_util.h"

#include <errno.h>
#include <sched.h>
#include <unistd.h>
#include <sys/syscall.h>
#if defined(__has_include) && __has_include(<sys/rseq.h>)
#include <sys/rseq.h>
#define TEST_HAS_GLIBC_RSEQ 1
#else
#define TEST_HAS_GLIBC_RSEQ 0
#endif


/* Checks sched_getcpu is correct on every allowed CPU after pinning. */

static void
check_getcpu( void ) {
  cpu_set_t all[1];
  FD_TEST( !sched_getaffinity( 0, sizeof(cpu_set_t), all ) );
  ulong checked = 0UL;
  for( ulong cpu=0UL; cpu<CPU_SETSIZE && checked<8UL; cpu++ ) {
    if( !CPU_ISSET( cpu, all ) ) continue;
    cpu_set_t one[1]; CPU_ZERO( one ); CPU_SET( cpu, one );
    FD_TEST( !sched_setaffinity( 0, sizeof(cpu_set_t), one ) );
    FD_TEST( (ulong)sched_getcpu()==cpu );
    checked++;
  }
  FD_TEST( checked );
  FD_TEST( !sched_setaffinity( 0, sizeof(cpu_set_t), all ) );
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

#if TEST_HAS_GLIBC_RSEQ
  uint rseq_size = __rseq_size;
#else
  uint rseq_size = 0U;
#endif
  int registered = !!rseq_size;
  FD_LOG_NOTICE(( "glibc rseq registered: %d (size %u)", registered, rseq_size ));

  check_getcpu();
#if FD_HAS_X86 && TEST_HAS_GLIBC_RSEQ
  FD_TEST( fd_tile_rseq_unregister()==registered );
  FD_TEST( fd_tile_rseq_unregister()==0 );

  /* The kernel no longer has a registration for this thread: an
     unregister of any area now fails with EINVAL.  Only meaningful if
     glibc had registered one (the kernel may lack rseq altogether). */
  if( registered ) {
    struct rseq dummy __attribute__((aligned(32))) = {0};
    FD_TEST( -1==syscall( SYS_rseq, &dummy, 32U, RSEQ_FLAG_UNREGISTER, 0x53053053U ) && errno==EINVAL );
  }
#else
  FD_TEST( fd_tile_rseq_unregister()==0 ); /* no glibc rseq area, or not x86-64 */
#endif

  check_getcpu();

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
