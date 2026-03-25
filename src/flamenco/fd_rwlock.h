#ifndef HEADER_fd_src_flamenco_fd_rwlock_h
#define HEADER_fd_src_flamenco_fd_rwlock_h

/* A very simple read-write spin lock. */

#include "../util/fd_util_base.h"
#include "../util/sanitize/fd_tsa.h"
#include "../util/racesan/fd_racesan_target.h"

#define FD_RWLOCK_WRITE_LOCK ((ushort)0xFFFF)

struct FD_CAPABILITY("fd_rwlock") fd_rwlock {
  ushort value; /* Bits 0..16 are

                    0: Unlocked
                    1..=0xFFFE: Locked by N readers
                    0xFFFF: Write locked */
};

typedef struct fd_rwlock fd_rwlock_t;

static inline fd_rwlock_t *
fd_rwlock_new( fd_rwlock_t * lock ) FD_NO_THREAD_SAFETY_ANALYSIS {
  lock->value = 0;
  return lock;
}

static inline void
fd_rwlock_write( fd_rwlock_t * lock ) FD_ACQUIRE( lock )  FD_NO_THREAD_SAFETY_ANALYSIS {
# if FD_HAS_THREADS
  for(;;) {
    ushort value = lock->value;
    fd_racesan_hook( "rwlock_write:pre_cas" );
    if( FD_LIKELY( !value ) ) {
      if( FD_LIKELY( FD_ATOMIC_CAS( &lock->value, 0, 0xFFFF )==0 ) ) {
        FD_COMPILER_MFENCE();
        fd_racesan_hook( "rwlock_write:post_acquire" );
        return;
      }
    }
    FD_SPIN_PAUSE();
  }
# else
  lock->value = 0xFFFF;
  FD_COMPILER_MFENCE();
# endif
}

static inline void
fd_rwlock_unwrite( fd_rwlock_t * lock ) FD_RELEASE( lock ) FD_NO_THREAD_SAFETY_ANALYSIS {
  fd_racesan_hook( "rwlock_unwrite:pre_release" );
  FD_COMPILER_MFENCE();
  FD_VOLATILE( lock->value ) = 0;
}

static inline void
fd_rwlock_demote( fd_rwlock_t * lock ) FD_RELEASE( lock ) FD_ACQUIRE_SHARED( lock ) FD_NO_THREAD_SAFETY_ANALYSIS {
  fd_racesan_hook( "rwlock_demote:pre_release" );
  FD_COMPILER_MFENCE();
  FD_VOLATILE( lock->value ) = 1;
}

static inline void
fd_rwlock_read( fd_rwlock_t * lock ) FD_ACQUIRE_SHARED( lock ) FD_NO_THREAD_SAFETY_ANALYSIS  {
# if FD_HAS_THREADS
  for(;;) {
    ushort value = lock->value;
    fd_racesan_hook( "rwlock_read:pre_cas" );
    if( FD_LIKELY( value<0xFFFE ) ) {
      if( FD_LIKELY( FD_ATOMIC_CAS( &lock->value, value, value+1 )==value ) ) {
        FD_COMPILER_MFENCE();
        fd_racesan_hook( "rwlock_read:post_acquire" );
        return;
      }
    }
    FD_SPIN_PAUSE();
  }
# else
  lock->value++;
  FD_COMPILER_MFENCE();
# endif
}

/* fd_rwlock_tryread attempts to acquire a shared read lock without
   spinning.  Returns 1 on success, 0 on failure (lock is write-held
   or contended). */

static inline int
fd_rwlock_tryread( fd_rwlock_t * lock ) FD_TRY_ACQUIRE_SHARED(1, lock) FD_NO_THREAD_SAFETY_ANALYSIS {
# if FD_HAS_THREADS
  ushort value = lock->value;
  fd_racesan_hook( "rwlock_tryread:pre_cas" );
  if( FD_UNLIKELY( value>=0xFFFE ) ) return 0;
  if( FD_UNLIKELY( FD_ATOMIC_CAS( &lock->value, value, (ushort)(value+1) )!=value ) ) return 0;
  FD_COMPILER_MFENCE();
  return 1;
# else
  lock->value++;
  FD_COMPILER_MFENCE();
  return 1;
# endif
}

static inline int
fd_rwlock_trywrite( fd_rwlock_t * lock ) FD_TRY_ACQUIRE(1, lock) FD_NO_THREAD_SAFETY_ANALYSIS {
# if FD_HAS_THREADS
  fd_racesan_hook( "rwlock_trywrite:pre_cas" );
  if( FD_UNLIKELY( FD_ATOMIC_CAS( &lock->value, 0, FD_RWLOCK_WRITE_LOCK )!=0 ) ) return 0;
  FD_COMPILER_MFENCE();
  return 1;
# else
  if( FD_UNLIKELY( lock->value ) ) return 0;
  lock->value = FD_RWLOCK_WRITE_LOCK;
  FD_COMPILER_MFENCE();
  return 1;
# endif
}

static inline void
fd_rwlock_unread( fd_rwlock_t * lock ) FD_RELEASE_SHARED( lock ) FD_NO_THREAD_SAFETY_ANALYSIS {
  fd_racesan_hook( "rwlock_unread:pre_release" );
  FD_COMPILER_MFENCE();
# if FD_HAS_THREADS
  FD_ATOMIC_FETCH_AND_SUB( &lock->value, 1 );
# else
  lock->value--;
# endif
}

#endif /* HEADER_fd_src_flamenco_fd_rwlock_h */
