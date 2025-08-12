#ifndef HEADER_fd_src_flamenco_rwlock_recursive_h
#define HEADER_fd_src_flamenco_rwlock_recursive_h

/* A very simple recursive/reentrant read-write spin lock:
   - Reentrant: the same thread can acquire the lock multiple times (up
     to 32 nested levels)
   - Supports read-read, write-write, and write-read nesting
   - Does NOT support read-write upgrades

   Read-write upgrades are intentionally unsupported because it is a
   recipe for deadlocks.  We could in theory implement a try_upgrade,
   but that requires the caller to do try-unlock-relock-recompute style
   programming.

   This is a pandora's box that should only be accessed if you need to
   overcome a much much bigger evil. */

#include "../util/log/fd_log.h"

/* We could easily support a deeper nesting, but does anyone really need
   more than 32?  Putting in a limit allows us to catch lock leakage
   more quickly. */
#define FD_RWLOCK_RECURSIVE_MAX_DEPTH 32U

/* An alternative here is simply having an owner field and a state
   field, where state is interpreted as

   0x0000: Unlocked
   0x0001-0x7FFF: Number of active readers (1..32767)
   0x8000-0xFFFF: Write locked, -0x8000+1 to obtain the number of
   recursive write locks

   and we won't keep track of the number of recursive read locks.  This
   will work just fine assuming the caller uses the lock correctly, i.e.
   doesn't lock and unlock in the wrong order and doesn't infinitely
   recurse read locks.

   We choose the following format because the separate counter for
   recursive read locks allows us to detect cases where the recursive
   unlocking didn't match the recursive locking, or cases where there
   were way too many recursive read locks.  It's a lightweight bug
   detector. */
struct fd_rwlock_recursive {
  volatile ulong  write_owner;      /* Write lock owner thread ID (0 if no write owner) */
  volatile ushort state;            /* Lock state:
                                       0x0000: Unlocked
                                       0x0001-0xFFFE: Number of active readers (1..65534)
                                       0xFFFF: Write locked */
  volatile uchar  write_count;      /* Number of recursive write locks held by write owner */
  volatile uchar  write_read_count; /* Number of recursive read locks held by write owner */

  uchar _pad[64UL-sizeof(ulong)-sizeof(ushort)-sizeof(uchar)-sizeof(uchar)];
};

typedef struct fd_rwlock_recursive fd_rwlock_recursive_t;

FD_PROTOTYPES_BEGIN

static inline ulong
fd_rwlock_recursive_tid( void ) {
  return (fd_log_tid()<<12)+fd_log_thread_id();
}

static inline void
fd_rwlock_recursive_new( fd_rwlock_recursive_t * lock ) {
  lock->state            = 0;
  lock->write_owner      = 0;
  lock->write_count      = 0;
  lock->write_read_count = 0;
}

static inline void
fd_rwlock_recursive_wlock( fd_rwlock_recursive_t * lock ) {
#if FD_HAS_THREADS
  ulong tid = fd_rwlock_recursive_tid();

  /* Already own write lock */
  if( FD_LIKELY( lock->write_owner==tid ) ) {
    if( FD_UNLIKELY( (lock->write_count+lock->write_read_count)>=FD_RWLOCK_RECURSIVE_MAX_DEPTH ) ) {
      FD_LOG_CRIT(( "recursion depth exceeded (%u >= %u)", (uint)(lock->write_count+lock->write_read_count), FD_RWLOCK_RECURSIVE_MAX_DEPTH ));
    }
    lock->write_count++;
    /* No need to fence here, we're already holding the lock */
    return;
  }

  /* Acquire write lock */
  for(;;) {
    ushort cur_state = FD_VOLATILE_CONST( lock->state );

    if( cur_state==0 ) {
      /* Unlocked - can acquire write lock immediately */
      if( FD_LIKELY( FD_ATOMIC_CAS( &lock->state, 0, 0xFFFF )==0 ) ) {
        lock->write_owner      = tid;
        lock->write_count      = 1;
        lock->write_read_count = 0;
        FD_COMPILER_MFENCE();
        return;
      }
    }

    /* Either write locked or has readers - wait

       If we ourselves held a read lock coming into this, we'd deadlock
       here. */
    FD_SPIN_PAUSE();
  }
#else
  if( lock->write_owner == 1 ) {
    lock->write_count++;
  } else {
    lock->state            = 0xFFFF;
    lock->write_owner      = 1;
    lock->write_count      = 1;
    lock->write_read_count = 0;
  }
#endif
}

static inline void
fd_rwlock_recursive_rlock( fd_rwlock_recursive_t * lock ) {
#if FD_HAS_THREADS
  ulong tid = fd_rwlock_recursive_tid();

  /* Already own write lock - just track as nested read */
  if( FD_LIKELY( lock->write_owner==tid ) ) {
    if( FD_UNLIKELY( (lock->write_count+lock->write_read_count)>=FD_RWLOCK_RECURSIVE_MAX_DEPTH ) ) {
      FD_LOG_CRIT(( "recursion depth exceeded (%u >= %u)", (uint)(lock->write_count+lock->write_read_count), FD_RWLOCK_RECURSIVE_MAX_DEPTH ));
    }
    lock->write_read_count++;
    /* No need to fence here, we're already holding the lock */
    return;
  }

  /* Normal read lock acquisition */
  for(;;) {
    ushort cur_state = FD_VOLATILE_CONST( lock->state );

    if( cur_state<0xFFFE ) {
      /* Not write locked and room for more readers */
      if( FD_LIKELY( FD_ATOMIC_CAS( &lock->state, cur_state, cur_state+1 )==cur_state ) ) {
        FD_COMPILER_MFENCE();
        return;
      }
    } else if( FD_UNLIKELY( cur_state==0xFFFE ) ) {
      FD_LOG_CRIT(( "too many read lock acquisitions" ));
    }

    FD_SPIN_PAUSE();
  }
#else
  if( lock->write_owner == 1 ) {
    /* We own write lock */
    lock->write_read_count++;
  } else {
    /* Normal read lock */
    lock->state++;
  }
#endif
}

static inline void
fd_rwlock_recursive_unlock( fd_rwlock_recursive_t * lock, int is_write ) {
  FD_COMPILER_MFENCE();

#if FD_HAS_THREADS
  ulong tid = fd_rwlock_recursive_tid();

  /* Check if we own the write lock */
  if( lock->write_owner==tid ) {
    if( FD_UNLIKELY( (lock->write_count+lock->write_read_count)==0 ) ) {
      FD_LOG_CRIT(( "unlock with zero lock count" ));
    }

    /* Decrement the appropriate counter based on lock type */
    if( is_write ) {
      if( FD_UNLIKELY( lock->write_count == 0 ) ) {
        FD_LOG_CRIT(( "write unlock with zero write count" ));
      }
      lock->write_count--;
    } else {
      if( FD_UNLIKELY( lock->write_read_count == 0 ) ) {
        FD_LOG_CRIT(( "read unlock with zero read count" ));
      }
      lock->write_read_count--;
    }

    if( FD_UNLIKELY( lock->write_count==0 && lock->write_read_count>0 ) ) {
      FD_LOG_CRIT(( "write unlock with zero write count and non-zero read count" ));
    }

    if( lock->write_count==0 ) {
      /* Last unlock - release write lock entirely */
      lock->write_owner = 0;
      FD_COMPILER_MFENCE();
      lock->state = 0;
    }
    /* else: still have nested locks, maintain write lock */
  } else {
    /* Must be a plain read lock */
    if( FD_UNLIKELY( is_write ) ) {
      FD_LOG_CRIT(( "write unlock without holding write lock" ));
    }
    FD_ATOMIC_FETCH_AND_SUB( &lock->state, 1 );
  }
#else
  if( lock->write_owner == 1 ) {
    if( is_write ) {
      lock->write_count--;
    } else {
      lock->write_read_count--;
    }
    if( (lock->write_count+lock->write_read_count)==0 ) {
      lock->write_owner = 0;
      lock->state       = 0;
    }
  } else {
    lock->state--;
  }
#endif
}

static inline void fd_rwlock_recursive_wunlock( fd_rwlock_recursive_t * lock ) {
  fd_rwlock_recursive_unlock( lock, 1 );
}

static inline void fd_rwlock_recursive_runlock( fd_rwlock_recursive_t * lock ) {
  fd_rwlock_recursive_unlock( lock, 0 );
}

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_rwlock_recursive_h */
