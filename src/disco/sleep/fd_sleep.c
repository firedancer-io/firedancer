#define _GNU_SOURCE
#include "fd_sleep.h"

#include "../../tango/tempo/fd_tempo.h"

#include <errno.h>
#include <time.h>
#include <linux/futex.h>
#include <sys/syscall.h>
#include <unistd.h>

FD_FN_CONST ulong fd_sleep_align    ( void ) { return FD_SLEEP_ALIGN;    }
FD_FN_CONST ulong fd_sleep_footprint( void ) { return sizeof(fd_sleep_t); }

void *
fd_sleep_new( void * shmem ) {
  if( FD_UNLIKELY( !shmem ) ) {
    FD_LOG_WARNING(( "NULL shmem" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shmem, fd_sleep_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned shmem" ));
    return NULL;
  }

  fd_sleep_t * sleep = (fd_sleep_t *)shmem;
  fd_memset( sleep, 0, fd_sleep_footprint() );
  for( ulong i=0UL; i<FD_SLEEP_TILE_MAX; i++ ) sleep->tile[ i ].word = 1UL; /* running */

  FD_COMPILER_MFENCE();
  FD_VOLATILE( sleep->magic ) = FD_SLEEP_MAGIC;
  FD_COMPILER_MFENCE();

  return shmem;
}

fd_sleep_t *
fd_sleep_join( void * shsleep ) {
  if( FD_UNLIKELY( !shsleep ) ) {
    FD_LOG_WARNING(( "NULL shsleep" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shsleep, fd_sleep_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned shsleep" ));
    return NULL;
  }

  fd_sleep_t * sleep = (fd_sleep_t *)shsleep;

  if( FD_UNLIKELY( sleep->magic!=FD_SLEEP_MAGIC ) ) {
    FD_LOG_WARNING(( "bad magic" ));
    return NULL;
  }

  return sleep;
}

int
fd_sleep_park_wait( ulong * word,
                    long    deadline_ticks ) {
  static double tick_per_ns = 0.0;
  if( FD_UNLIKELY( tick_per_ns==0.0 ) ) tick_per_ns = fd_tempo_tick_per_ns( NULL );

  long remaining = (long)((double)(deadline_ticks-fd_tickcount())/tick_per_ns);
  if( FD_UNLIKELY( remaining<=0L ) ) return FD_SLEEP_UNPARK_DEADLINE;

  /* Absolute timeout: preemption before the syscall cannot stretch
     the sleep */
  struct timespec ts;
  clock_gettime( CLOCK_MONOTONIC, &ts );
  long abs_ns = ts.tv_sec*(long)1e9 + ts.tv_nsec + remaining;
  ts.tv_sec  = abs_ns/(long)1e9;
  ts.tv_nsec = abs_ns%(long)1e9;

  long res = syscall( SYS_futex, (uint *)word, FUTEX_WAIT_BITSET, 0U, &ts, NULL, FUTEX_BITSET_MATCH_ANY );
  if( FD_UNLIKELY( -1L==res && errno==ETIMEDOUT ) ) return FD_SLEEP_UNPARK_DEADLINE;
  return FD_SLEEP_UNPARK_RING; /* 0, EAGAIN (word already 1) or EINTR */
}

void
fd_sleep_wake_one( ulong * word ) {
  FD_VOLATILE( word[0] ) = 1UL;
  long res = syscall( SYS_futex, (uint *)word, FUTEX_WAKE, 1, NULL, NULL, 0 );
  if( FD_UNLIKELY( -1L==res ) ) FD_LOG_ERR(( "futex(FUTEX_WAKE) failed (%i-%s)", errno, fd_io_strerror( errno ) ));
}
