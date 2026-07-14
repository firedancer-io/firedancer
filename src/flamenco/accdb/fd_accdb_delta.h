#ifndef HEADER_fd_src_flamenco_accdb_fd_accdb_delta_h
#define HEADER_fd_src_flamenco_accdb_fd_accdb_delta_h

#include "../../util/fd_util.h"

/* fd_accdb_delta is a concurrent, separately-chained set of pubkeys
   changed since the last full snapshot boundary.  Entries are never
   removed individually: the accdb tile resets the complete structure at
   the next full snapshot boundary.  Readers iterate the chains, so an
   entry only becomes visible after its initializing writer publishes it
   through the chain-head CAS. */

#define FD_ACCDB_DELTA_MAGIC (0xf17eda2ce7fc2c11UL)
#define FD_ACCDB_DELTA_ALIGN (128UL)

struct fd_accdb_delta_ele {
  uchar pubkey[ 32UL ];
  uint  next;
};
typedef struct fd_accdb_delta_ele fd_accdb_delta_ele_t;

FD_STATIC_ASSERT( sizeof(fd_accdb_delta_ele_t)==36UL, delta_ele_sz      );
FD_STATIC_ASSERT( __builtin_offsetof(fd_accdb_delta_ele_t, next)==32UL, delta_ele_next_off );

struct fd_accdb_delta {
  ulong magic;
  ulong max;
  ulong chain_cnt;
  ulong seed;

  /* head is the next bump index.  head>max is the graceful overflow
     state.  reset_pending gates new insertions while the accdb tile waits
     for active inserters to drain. */
  ulong head          __attribute__((aligned(64)));
  ulong reset_pending __attribute__((aligned(64)));
  ulong active        __attribute__((aligned(64)));

  ulong chain_off;
  ulong ele_off;
};
typedef struct fd_accdb_delta fd_accdb_delta_t;

FD_PROTOTYPES_BEGIN

FD_FN_CONST ulong fd_accdb_delta_align     ( void );
FD_FN_CONST ulong fd_accdb_delta_footprint ( ulong max );

void * fd_accdb_delta_new   ( void * shmem, ulong max, ulong seed );
fd_accdb_delta_t * fd_accdb_delta_join  ( void * shmem );

/* insert returns 1 when the pubkey is present (inserted or already
   present) and -1 after capacity overflow.  Concurrent duplicate races
   can consume unreachable bump slots, but at most one entry is linked.
   The caller must hold a writer bracket (writer_enter through
   writer_leave), which prevents a reset from racing the insertion. */
int fd_accdb_delta_insert( fd_accdb_delta_t * delta,
                           uchar const         pubkey[ 32 ] );

void fd_accdb_delta_writer_enter( fd_accdb_delta_t * delta );
void fd_accdb_delta_writer_leave( fd_accdb_delta_t * delta );

/* reset_begin gates new insertions.  reset_try returns zero until all
   inserters have drained; once drained it clears chains/head, opens the
   gate, and returns one. */
void fd_accdb_delta_reset_begin( fd_accdb_delta_t * delta );
int  fd_accdb_delta_reset_try  ( fd_accdb_delta_t * delta );

static inline ulong
fd_accdb_delta_head( fd_accdb_delta_t const * delta ) {
  return __atomic_load_n( &delta->head, __ATOMIC_ACQUIRE );
}

static inline int
fd_accdb_delta_overflowed( fd_accdb_delta_t const * delta ) {
  return fd_accdb_delta_head( delta )>delta->max;
}

FD_FN_PURE static inline uint *
fd_accdb_delta_chain( fd_accdb_delta_t * delta ) {
  return (uint *)( (uchar *)delta + delta->chain_off );
}

FD_FN_PURE static inline fd_accdb_delta_ele_t *
fd_accdb_delta_ele( fd_accdb_delta_t * delta ) {
  return (fd_accdb_delta_ele_t *)( (uchar *)delta + delta->ele_off );
}

FD_PROTOTYPES_END

#endif
