#ifndef HEADER_fd_src_disco_wait_info_fd_wait_info_h
#define HEADER_fd_src_disco_wait_info_fd_wait_info_h

/* fd_wait_info provides a shared topology object that holds the data
   the `wait` command needs to determine a safe restart window.

   Expects a single producer and one or more consumers.  Reads are
   lock-free via the seqlock helpers below. */

#include "../../util/log/fd_log.h"

#define FD_WAIT_INFO_MAGIC (0xf17eda2c57490000UL) /* firedancer wi ver 0 */

struct fd_wait_info {
  /* Health */
  int   caught_up;

  /* Leader gap */
  ulong reset_slot;
  ulong next_leader_slot;           /* 0 -> no upcoming leader slots */
  ulong leader_slot;                /* non-zero when actively leading */
  ulong epoch_end_slot;
  ulong slots_per_epoch;
  ulong ns_per_slot;

  /* Delinquent stake */
  ulong delinquent_stake_lamports;
  ulong cluster_active_stake_lamports;

  /* Snapshot status */
  int   snap_active;                  /* 1 while snapmk tile is writing */
  ulong snap_finished_full;
  ulong snap_finished_incr;
};

typedef struct fd_wait_info fd_wait_info_t;

struct fd_wait_info_box {
  ulong magic;     /* ==FD_WAIT_INFO_MAGIC */
  uint  seq;       /* lsb==1 implies active write */

  fd_wait_info_t info;
};

typedef struct fd_wait_info_box fd_wait_info_box_t;

FD_PROTOTYPES_BEGIN

static inline void *
fd_wait_info_box_new( void * shmem ) {
  fd_wait_info_box_t * wi = (fd_wait_info_box_t *)shmem;
  if( FD_UNLIKELY( !wi ) ) {
    FD_LOG_WARNING(( "NULL shmem" ));
    return NULL;
  }
  fd_memset( wi, 0, sizeof(fd_wait_info_box_t) );
  FD_VOLATILE( wi->magic ) = FD_WAIT_INFO_MAGIC;
  return (void *)wi;
}

static inline fd_wait_info_box_t *
fd_wait_info_box_join( void * shwi ) {
  if( FD_UNLIKELY( !shwi ) ) {
    FD_LOG_WARNING(( "NULL shwi" ));
    return NULL;
  }
  fd_wait_info_box_t * wi = (fd_wait_info_box_t *)shwi;
  if( FD_UNLIKELY( wi->magic!=FD_WAIT_INFO_MAGIC ) ) {
    FD_LOG_WARNING(( "bad magic" ));
    return NULL;
  }
  return wi;
}

/* fd_wait_info_try_read attempts a single consistent read.
   Returns dst on success, NULL if a write was in progress. */

static inline fd_wait_info_t *
fd_wait_info_try_read( fd_wait_info_t *           dst,
                       fd_wait_info_box_t const * src ) {
  FD_COMPILER_MFENCE();
  uint seq0 = FD_VOLATILE_CONST( src->seq );
  FD_COMPILER_MFENCE();
  if( FD_UNLIKELY( seq0 & 1U ) ) return NULL;
  memcpy( dst, &src->info, sizeof(fd_wait_info_t) );
  FD_COMPILER_MFENCE();
  uint seq1 = FD_VOLATILE_CONST( src->seq );
  FD_COMPILER_MFENCE();
  if( FD_LIKELY( seq0==seq1 ) ) return dst;
  return NULL;
}

static inline void
fd_wait_info_write_begin( fd_wait_info_box_t * dst ) {
  FD_COMPILER_MFENCE();
  FD_VOLATILE( dst->seq ) = dst->seq + 1U;
  FD_COMPILER_MFENCE();
}

static inline void
fd_wait_info_write_end( fd_wait_info_box_t * dst ) {
  FD_COMPILER_MFENCE();
  FD_VOLATILE( dst->seq ) = dst->seq + 1U;
  FD_COMPILER_MFENCE();
}

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_disco_wait_info_fd_wait_info_h */
