#ifndef HEADER_fd_src_flamenco_fd_rwlock_h
#define HEADER_fd_src_flamenco_fd_rwlock_h

/* A very simple read-write spin lock. */

#include "../util/fd_util_base.h"
#include "../util/sanitize/fd_tsa.h"
#include "../util/racesan/fd_racesan_target.h"
#include <stdatomic.h>

#define FD_RWLOCK_WRITE_LOCK ((ushort)0xFFFF)

struct FD_CAPABILITY("fd_rwlock") fd_rwlock {
  atomic_ushort value; /* 0: Unlocked
                          1..=0xFFFE: Locked by N readers
                          0xFFFF: Write locked */
};

typedef struct fd_rwlock fd_rwlock_t;

static inline fd_rwlock_t *
fd_rwlock_new( fd_rwlock_t * lock ) FD_NO_THREAD_SAFETY_ANALYSIS {
  atomic_store_explicit( &lock->value, 0, memory_order_relaxed );
  return lock;
}

static inline void
fd_rwlock_write( fd_rwlock_t * lock ) FD_ACQUIRE( lock ) FD_NO_THREAD_SAFETY_ANALYSIS {
  for(;;) {
    ushort value = atomic_load_explicit( &lock->value, memory_order_relaxed );
    fd_racesan_hook( "rwlock_write:pre_cas" );
    if( FD_LIKELY( !value ) ) {
      ushort expected = 0;
      if( FD_LIKELY( atomic_compare_exchange_weak_explicit( &lock->value, &expected, FD_RWLOCK_WRITE_LOCK, memory_order_acquire, memory_order_relaxed ) ) ) {
        fd_racesan_hook( "rwlock_write:post_acquire" );
        return;
      }
    }
    FD_SPIN_PAUSE();
  }
}

static inline void
fd_rwlock_unwrite( fd_rwlock_t * lock ) FD_RELEASE( lock ) FD_NO_THREAD_SAFETY_ANALYSIS {
  fd_racesan_hook( "rwlock_unwrite:pre_release" );
  atomic_store_explicit( &lock->value, 0, memory_order_release );
}

static inline void
fd_rwlock_demote( fd_rwlock_t * lock ) FD_RELEASE( lock ) FD_ACQUIRE_SHARED( lock ) FD_NO_THREAD_SAFETY_ANALYSIS {
  fd_racesan_hook( "rwlock_demote:pre_release" );
  atomic_store_explicit( &lock->value, 1, memory_order_release );
}

static inline void
fd_rwlock_read( fd_rwlock_t * lock ) FD_ACQUIRE_SHARED( lock ) FD_NO_THREAD_SAFETY_ANALYSIS {
  for(;;) {
    ushort value = atomic_load_explicit( &lock->value, memory_order_relaxed );
    fd_racesan_hook( "rwlock_read:pre_cas" );
    if( FD_LIKELY( value<0xFFFE ) ) {
      ushort expected = value;
      if( FD_LIKELY( atomic_compare_exchange_weak_explicit( &lock->value, &expected, (ushort)(value+1), memory_order_acquire, memory_order_relaxed ) ) ) {
        fd_racesan_hook( "rwlock_read:post_acquire" );
        return;
      }
    }
    FD_SPIN_PAUSE();
  }
}

/* fd_rwlock_tryread attempts to acquire a shared read lock without
   spinning.  Returns 1 on success, 0 on failure (lock is write-held
   or contended). */

static inline int
fd_rwlock_tryread( fd_rwlock_t * lock ) FD_TRY_ACQUIRE_SHARED(1, lock) FD_NO_THREAD_SAFETY_ANALYSIS {
  ushort value = atomic_load_explicit( &lock->value, memory_order_relaxed );
  fd_racesan_hook( "rwlock_tryread:pre_cas" );
  if( FD_UNLIKELY( value>=0xFFFE ) ) return 0;
  ushort expected = value;
  if( FD_UNLIKELY( !atomic_compare_exchange_strong_explicit( &lock->value, &expected, (ushort)(value+1), memory_order_acquire, memory_order_relaxed ) ) ) return 0;
  return 1;
}

static inline int
fd_rwlock_trywrite( fd_rwlock_t * lock ) FD_TRY_ACQUIRE(1, lock) FD_NO_THREAD_SAFETY_ANALYSIS {
  fd_racesan_hook( "rwlock_trywrite:pre_cas" );
  ushort expected = 0;
  if( FD_UNLIKELY( !atomic_compare_exchange_strong_explicit( &lock->value, &expected, FD_RWLOCK_WRITE_LOCK, memory_order_acquire, memory_order_relaxed ) ) ) return 0;
  return 1;
}

static inline void
fd_rwlock_unread( fd_rwlock_t * lock ) FD_RELEASE_SHARED( lock ) FD_NO_THREAD_SAFETY_ANALYSIS {
  fd_racesan_hook( "rwlock_unread:pre_release" );
  atomic_fetch_sub_explicit( &lock->value, 1, memory_order_release );
}

#endif /* HEADER_fd_src_flamenco_fd_rwlock_h */
