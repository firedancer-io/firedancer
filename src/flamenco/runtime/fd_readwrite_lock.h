#ifndef HEADER_fd_src_flamenco_runtime_fd_readwrite_lock_h
#define HEADER_fd_src_flamenco_runtime_fd_readwrite_lock_h

struct __attribute__((aligned(64UL))) fd_readwrite_lock {
  volatile uint readcount;
  volatile uint writecount;
  volatile uint innerlock;
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
  lock->readcount = 0;
  lock->writecount = 0;
  lock->innerlock = 0;
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
fd_readwrite_private_lock( fd_readwrite_lock_t * lock ) {
#if FD_HAS_ATOMIC
  /* Use a spin lock to protect the counters */
  for(;;) {
    FD_COMPILER_MFENCE();
    uint t = FD_ATOMIC_CAS( &lock->innerlock, 0, 1 );
    FD_COMPILER_MFENCE();
    if( FD_LIKELY( !t ) ) return;
  }
#else
  (void)lock;
#endif
}

static inline void
fd_readwrite_private_unlock( fd_readwrite_lock_t * lock ) {
#if FD_HAS_ATOMIC
  FD_COMPILER_MFENCE();
  lock->innerlock = 0;
  FD_COMPILER_MFENCE();
#else
  (void)lock;
#endif
}

static inline void
fd_readwrite_start_read( fd_readwrite_lock_t * lock ) {
  for(;;) {
    fd_readwrite_private_lock( lock );
    if( FD_LIKELY( !lock->writecount ) ) {
      lock->readcount++;
      FD_TEST(lock->readcount < 1000U);
      fd_readwrite_private_unlock( lock );
      return;
    }
    fd_readwrite_private_unlock( lock );
    FD_YIELD();
  }
}

static inline void
fd_readwrite_end_read( fd_readwrite_lock_t * lock ) {
  fd_readwrite_private_lock( lock );
  lock->readcount--;
  FD_TEST(lock->readcount < 1000U);
  fd_readwrite_private_unlock( lock );
}

static inline void
fd_readwrite_start_write( fd_readwrite_lock_t * lock ) {
  for(;;) {
    fd_readwrite_private_lock( lock );
    if( FD_LIKELY( (!lock->readcount) & (!lock->writecount) ) ) {
      lock->writecount++;
      FD_TEST(lock->writecount == 1U);
      fd_readwrite_private_unlock( lock );
      return;
    }
    fd_readwrite_private_unlock( lock );
    FD_YIELD();
  }
}

static inline void
fd_readwrite_end_write( fd_readwrite_lock_t * lock ) {
  fd_readwrite_private_lock( lock );
  lock->writecount--;
  FD_TEST(lock->writecount == 0U);
  fd_readwrite_private_unlock( lock );
}

#endif /* HEADER_fd_src_flamenco_runtime_fd_readwrite_lock_h */
