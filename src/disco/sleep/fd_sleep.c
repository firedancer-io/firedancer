#define _GNU_SOURCE
#include "fd_sleep.h"
#include "../topo/fd_topo.h"

#include <errno.h>
#include <float.h>
#include <time.h>
#include <linux/futex.h>
#include <sys/syscall.h>
#include <unistd.h>

FD_FN_CONST ulong fd_sleep_align    ( void ) { return FD_SLEEP_ALIGN;    }
FD_FN_CONST ulong fd_sleep_footprint( void ) { return sizeof(fd_sleep_t); }

void *
fd_sleep_new( void * shmem,
              double tick_per_ns ) {
  if( FD_UNLIKELY( !shmem ) ) {
    FD_LOG_WARNING(( "NULL shmem" ));
    return NULL;
  }

  if( FD_UNLIKELY( !(tick_per_ns>0.0 && tick_per_ns<=DBL_MAX) ) ) {
    FD_LOG_WARNING(( "bad tick_per_ns" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shmem, fd_sleep_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned shmem" ));
    return NULL;
  }

  fd_sleep_t * sleep = (fd_sleep_t *)shmem;
  fd_memset( sleep, 0, fd_sleep_footprint() );
  for( ulong i=0UL; i<FD_SLEEP_TILE_MAX; i++ ) sleep->tile[ i ].word = 1UL; /* running */
  sleep->tick_per_ns = tick_per_ns;

  FD_COMPILER_MFENCE();
  FD_VOLATILE( sleep->magic ) = FD_SLEEP_MAGIC;
  FD_COMPILER_MFENCE();

  return shmem;
}

ulong
fd_sleep_wake_table( fd_sleep_wake_t *      wake,
                     struct fd_topo const * topo,
                     ulong                  link_id ) {
  if( FD_UNLIKELY( topo->sleep_obj_id==ULONG_MAX ) ) return 0UL;
  ulong mask[ FD_SLEEP_BITS_CNT ] = {0};
  for( ulong i=0UL; i<topo->tile_cnt; i++ ) {
    fd_topo_tile_t const * consumer = &topo->tiles[ i ];
    for( ulong j=0UL; j<consumer->in_cnt; j++ ) {
      if( FD_UNLIKELY( consumer->in_link_id[ j ]==link_id && consumer->in_link_poll[ j ] ) ) {
        mask[ consumer->id>>6 ] |= 1UL<<(consumer->id&63UL);
      }
    }
  }

  ulong cnt = 0UL;
  for( ulong w=0UL; w<FD_SLEEP_BITS_CNT; w++ ) {
    if( FD_UNLIKELY( mask[ w ] ) ) wake[ cnt++ ] = (fd_sleep_wake_t){ .w=w, .mask=mask[ w ] };
  }
  return cnt;
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
fd_sleep_park_wait( fd_sleep_t const * sleep,
                    ulong *            word,
                    long               deadline_ticks ) {
  /* Absolute timeout, anchored on a clock read taken before the tick
     read: preemption anywhere after can only shorten the sleep, never
     stretch it past deadline_ticks */
  struct timespec ts;
  clock_gettime( CLOCK_MONOTONIC, &ts );
  long remaining = (long)((double)(deadline_ticks-fd_tickcount())/sleep->tick_per_ns);
  if( FD_UNLIKELY( remaining<=0L ) ) return FD_SLEEP_UNPARK_DEADLINE;
  long abs_ns = ts.tv_sec*(long)1e9 + ts.tv_nsec + remaining;
  ts.tv_sec  = abs_ns/(long)1e9;
  ts.tv_nsec = abs_ns%(long)1e9;

  for(;;) {
    long res = syscall( SYS_futex, (uint *)word, FUTEX_WAIT_BITSET, 0U, &ts, NULL, FUTEX_BITSET_MATCH_ANY );
    if( FD_LIKELY( !res ) ) return FD_SLEEP_UNPARK_RING;

    switch( errno ) {
      case ETIMEDOUT: return FD_SLEEP_UNPARK_DEADLINE;
      case EAGAIN:    return FD_SLEEP_UNPARK_RING;  /* word already 1 */
      case EINTR:     continue;                     /* signal: same absolute timeout */
      default: FD_LOG_ERR(( "futex(FUTEX_WAIT_BITSET) failed (%i-%s)", errno, fd_io_strerror( errno ) ));
    }
  }
}

void
fd_sleep_wake_one( ulong * word ) {
  FD_VOLATILE( word[0] ) = 1UL;
  long res = syscall( SYS_futex, (uint *)word, FUTEX_WAKE, 1, NULL, NULL, 0 );
  if( FD_UNLIKELY( -1L==res ) ) FD_LOG_ERR(( "futex(FUTEX_WAKE) failed (%i-%s)", errno, fd_io_strerror( errno ) ));
}
