#ifndef HEADER_fd_util_mutex_h
#define HEADER_fd_util_mutex_h

#include "fd_util_base.h"

/* A simple mutex */

struct fd_mutex {
  uchar lock;
};
typedef struct fd_mutex fd_mutex_t;

FD_PROTOTYPES_BEGIN

static inline void
fd_mutex_lock( fd_mutex_t * mutex ) {
#if FD_HAS_THREADS
  for(;;) {
    uchar value = FD_VOLATILE_CONST(mutex->lock);
    if( FD_LIKELY( !value ) ) {
      if( FD_LIKELY( FD_ATOMIC_CAS( &mutex->lock, 0, 1 )==0 ) ) return;
    }
    FD_SPIN_PAUSE();
  }
#else
  mutex->lock = 1;
#endif
  FD_COMPILER_MFENCE();
}

static inline void
fd_mutex_unlock( fd_mutex_t * mutex ) {
  FD_COMPILER_MFENCE();
  FD_VOLATILE( mutex->lock ) = 0;
}

static inline void
fd_mutex_guard_cleanup( fd_mutex_t ** mutex ) {
  fd_mutex_unlock( *mutex );
}

#define FD_MUTEX_GUARD_BEGIN( _mutex ) do {                                           \
  fd_mutex_t * mutex_guard __attribute__((cleanup(fd_mutex_guard_cleanup))) = _mutex; \
  fd_mutex_lock( mutex_guard );                                                       \
  do

#define FD_MUTEX_GUARD_END while(0); } while(0)

FD_PROTOTYPES_END

#endif /* HEADER_fd_util_mutex_h */
