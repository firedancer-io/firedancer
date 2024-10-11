#ifndef HEADER_fd_src_flamenco_runtime_fd_rwseq_lock_h
#define HEADER_fd_src_flamenco_runtime_fd_rwseq_lock_h

#include "../fd_flamenco_base.h"
#include "../fd_rwlock.h"

struct __attribute__((aligned(64UL))) fd_rwseq_lock {
  fd_rwlock_t rwlock;
  volatile uint seqnum;
};

typedef struct fd_rwseq_lock fd_rwseq_lock_t;

static inline FD_FN_CONST ulong
fd_rwseq_align( void ) { return alignof(fd_rwseq_lock_t); }

static inline FD_FN_CONST ulong
fd_rwseq_footprint( void ) { return sizeof(fd_rwseq_lock_t); }

static inline void *
fd_rwseq_new( void * shmem ) {
  fd_rwseq_lock_t * lock = (fd_rwseq_lock_t *)shmem;
  lock->rwlock.value = 0;
  lock->seqnum = 0;
  return lock;
}

static inline fd_rwseq_lock_t *
fd_rwseq_join( void * shrwseq ) {
  return (fd_rwseq_lock_t *)shrwseq;
}

static inline void *
fd_rwseq_leave( fd_rwseq_lock_t * lock ) {
  return lock;
}

static inline void *
fd_rwseq_delete( void * shrwseq ) {
  return shrwseq;
}

static inline void
fd_rwseq_start_read( fd_rwseq_lock_t * lock ) {
  fd_rwlock_read( &lock->rwlock );
}

static inline void
fd_rwseq_end_read( fd_rwseq_lock_t * lock ) {
  fd_rwlock_unread( &lock->rwlock );
}

static inline void
fd_rwseq_start_write( fd_rwseq_lock_t * lock ) {
  fd_rwlock_write( &lock->rwlock );
  FD_COMPILER_MFENCE();
  lock->seqnum++;
  FD_COMPILER_MFENCE();
}

static inline void
fd_rwseq_end_write( fd_rwseq_lock_t * lock ) {
  FD_COMPILER_MFENCE();
  lock->seqnum++;
  FD_COMPILER_MFENCE();
  fd_rwlock_unwrite( &lock->rwlock );
}

/* The pattern for concurrent reads is:
   for(;;) {
     uint seqnum;
     if( FD_UNLIKELY( fd_rwseq_start_concur_read( lock, &seqnum ) ) ) continue;
     ... read some data
     if( FD_UNLIKELY( fd_rwseq_check_concur_read( lock, seqnum ) ) ) continue;
     return;
   }
*/

static inline int
fd_rwseq_start_concur_read( fd_rwseq_lock_t * lock, uint * seqnum ) {
  *seqnum = lock->seqnum;
  FD_COMPILER_MFENCE();
  return ( lock->rwlock.value==0xFFFF ? 1 : 0 );
}

static inline int
fd_rwseq_check_concur_read( fd_rwseq_lock_t * lock, uint seqnum ) {
  FD_COMPILER_MFENCE();
  return ( (int)(seqnum != lock->seqnum) | (int)( lock->rwlock.value==0xFFFF ? 1 : 0 ) );
}

#endif /* HEADER_fd_src_flamenco_runtime_fd_rwseq_lock_h */
