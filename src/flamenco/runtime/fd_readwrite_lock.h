#ifndef HEADER_fd_src_flamenco_runtime_fd_readwrite_lock_h
#define HEADER_fd_src_flamenco_runtime_fd_readwrite_lock_h

#include "../fd_flamenco_base.h"

struct __attribute__((aligned(64UL))) fd_readwrite_lock {
  /* -1 = write locked, 0 = unlocked, >0 = read lock count */
  volatile int lock;
  volatile uint seqnum;
};

typedef struct fd_readwrite_lock fd_readwrite_lock_t;

/* fd_blockstore_{align,footprint} return FD_BLOCKSTORE_{ALIGN,FOOTPRINT}. */

static inline FD_FN_CONST ulong
fd_readwrite_align( void ) { return alignof(fd_readwrite_lock_t); }

static inline FD_FN_CONST ulong
fd_readwrite_footprint( void ) { return sizeof(fd_readwrite_lock_t); }

static inline void *
fd_readwrite_new( void * shmem ) {
  fd_readwrite_lock_t * lock = (fd_readwrite_lock_t *)shmem;
  lock->lock = 0;
  lock->seqnum = 0;
  return lock;
}

static inline fd_readwrite_lock_t *
fd_readwrite_join( void * shreadwrite ) {
  return (fd_readwrite_lock_t *)shreadwrite;
}

static inline void *
fd_readwrite_leave( fd_readwrite_lock_t * lock ) {
  return lock;
}

static inline void *
fd_readwrite_delete( void * shreadwrite ) {
  return shreadwrite;
}

static inline void
fd_readwrite_start_read( fd_readwrite_lock_t * lock ) {
# if FD_HAS_THREADS
  for(;;) {
    register int l = lock->lock;
    if( FD_UNLIKELY( l < 0 || FD_ATOMIC_CAS( &lock->lock, l, l+1 ) != l ) ) {
      FD_YIELD();
      continue;
    }
    break;
  }
  FD_COMPILER_MFENCE();
# else
  lock->lock++;
# endif
}

static inline void
fd_readwrite_end_read( fd_readwrite_lock_t * lock ) {
# if FD_HAS_THREADS
  FD_COMPILER_MFENCE();
  for(;;) {
    register int l = lock->lock;
    if( FD_UNLIKELY( l <= 0 ) ) {
      FD_LOG_CRIT(( "fd_readwrite_end_read called without fd_readwrite_start_read" ));
    }
    if( FD_UNLIKELY( FD_ATOMIC_CAS( &lock->lock, l, l-1 ) != l ) ) {
      FD_YIELD();
      continue;
    }
    break;
  }
# else
  lock->lock--;
# endif
}

static inline void
fd_readwrite_start_write( fd_readwrite_lock_t * lock ) {
# if FD_HAS_THREADS
  for(;;) {
    register int l = lock->lock;
    if( FD_UNLIKELY( l != 0 || FD_ATOMIC_CAS( &lock->lock, l, -1 ) != l ) ) {
      FD_YIELD();
      continue;
    }
    break;
  }
# else
  lock->lock = -1;
# endif
  FD_COMPILER_MFENCE();
  lock->seqnum++;
  FD_COMPILER_MFENCE();
}

static inline void
fd_readwrite_end_write( fd_readwrite_lock_t * lock ) {
  FD_COMPILER_MFENCE();
  lock->seqnum++;
  FD_COMPILER_MFENCE();
# if FD_HAS_THREADS
  for(;;) {
    register int l = lock->lock;
    if( FD_UNLIKELY( l >= 0 ) ) {
      FD_LOG_CRIT(( "fd_readwrite_end_write called without fd_readwrite_start_write" ));
    }
    if( FD_UNLIKELY( FD_ATOMIC_CAS( &lock->lock, l, 0 ) != l ) ) {
      FD_YIELD();
      continue;
    }
    break;
  }
# else
  lock->lock = 0;
# endif
}

/* The pattern for concurrent reads is:
   for(;;) {
     uint seqnum;
     if( FD_UNLIKELY( fd_readwrite_start_concur_read( lock, &seqnum ) ) ) continue;
     ... read some data
     if( FD_UNLIKELY( fd_readwrite_check_concur_read( lock, seqnum ) ) ) continue;
     return;
   }
*/

static inline int
fd_readwrite_start_concur_read( fd_readwrite_lock_t * lock, uint * seqnum ) {
  *seqnum = lock->seqnum;
  FD_COMPILER_MFENCE();
  return ( lock->lock < 0 ? 1 : 0 );
}

static inline int
fd_readwrite_check_concur_read( fd_readwrite_lock_t * lock, uint seqnum ) {
  FD_COMPILER_MFENCE();
  return ( ( (int)(seqnum != lock->seqnum) | (int)(lock->lock < 0) ) ? 1 : 0 );
}

#endif /* HEADER_fd_src_flamenco_runtime_fd_readwrite_lock_h */
