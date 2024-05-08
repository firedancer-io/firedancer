#ifndef HEADER_fd_src_disco_bank_rwlock_h
#define HEADER_fd_src_disco_bank_rwlock_h

/* A very simple read-write spin lock. */

#include "../fd_disco_base.h"
#include "../../util/fd_util_base.h"

struct fd_rwlock {
  ushort value; /* Bits 0..16 are

                    0: Unlocked
                    1..=0xFFFE: Locked by N readers
                    0xFFFF: Write locked */
};

typedef struct fd_rwlock fd_rwlock_t;

static inline void
fd_rwlock_write( fd_rwlock_t * lock ) {
  for(;;) {
    ushort value = lock->value;
    if( FD_LIKELY( !value ) ) {
      if( FD_LIKELY( !FD_ATOMIC_CAS( &lock->value, 0, 0xFFFF ) ) ) return;
    }
    FD_SPIN_PAUSE();
  }
  FD_COMPILER_MFENCE();
}

static inline void
fd_rwlock_unwrite( fd_rwlock_t * lock ) {
  FD_COMPILER_MFENCE();
  lock->value = 0;
}

static inline void
fd_rwlock_read( fd_rwlock_t * lock ) {
  for(;;) {
    ushort value = lock->value;
    if( FD_UNLIKELY( value!=0xFFFE ) ) {
      if( FD_LIKELY( FD_ATOMIC_CAS( &lock->value, value, value+1 )==value ) ) {
        return;
      }
    }
    FD_SPIN_PAUSE();
  }
  FD_COMPILER_MFENCE();
}

static inline void
fd_rwlock_unread( fd_rwlock_t * lock ) {
  FD_COMPILER_MFENCE();
  FD_ATOMIC_FETCH_AND_SUB( &lock->value, 1 );
}

#endif /* HEADER_fd_src_disco_bank_rwlock_h */
