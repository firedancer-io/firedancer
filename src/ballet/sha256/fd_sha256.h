#ifndef HEADER_fd_src_ballet_sha256_fd_sha256_h
#define HEADER_fd_src_ballet_sha256_fd_sha256_h

/* fd_sha256 provides APIs for SHA-256 hashing of messages. */

#include "../fd_ballet_base.h"

/* FD_SHA256_{ALIGN,FOOTPRINT} describe the alignment and footprint needed
   for a memory region to hold a fd_sha256_t.  ALIGN is a positive
   integer power of 2.  FOOTPRINT is a multiple of align.  ALIGN is
   recommended to be at least double cache line to mitigate various
   kinds of false sharing.  These are provided to facilitate compile
   time declarations. */

#define FD_SHA256_ALIGN     (128UL)
#define FD_SHA256_FOOTPRINT (128UL)

/* A fd_sha256_t should be treated as an opaque handle of a sha256
   calculation state.  (It technically isn't here facilitate compile
   time declarations of fd_sha256_t memory.) */

#define FD_SHA256_MAGIC (0xF17EDA2CE54A2560) /* FIREDANCE SHA256 V0 */

/* FD_SHA256_HASH_SZ is the size of a hash in bytes.
   It is equal to the internal state size of SHA-256 */

#define FD_SHA256_HASH_SZ (32UL)

/* FD_SHA256_BLOCK_SZ is the block size of SHA-256. */

#define FD_SHA256_BLOCK_SZ (64UL)

struct __attribute__((aligned(FD_SHA256_ALIGN))) fd_sha256_private {

  /* This point is 128-byte aligned */

  uchar buf[FD_SHA256_BLOCK_SZ];

  /* This point is 64-byte aligned */

  uint state[8];

  /* This point is 32-byte aligned */

  ulong magic;    /* ==FD_SH256_MAGIC */
  ulong buf_used; /* Number of buffered bytes, in [0,FD_SHA256_BLOCK_SZ) */
  ulong bit_cnt;  /* How many bits have been appended total */

  /* Padding to 128-byte here */
};

typedef struct fd_sha256_private fd_sha256_t;

FD_PROTOTYPES_BEGIN

/* fd_sha256_{align,footprint,new,join,leave,delete} usage is identical to
   that of their fd_sha512 counterparts.  See ../sha512/fd_sha512.h */

FD_FN_CONST ulong
fd_sha256_align( void );

FD_FN_CONST ulong
fd_sha256_footprint( void );

// Synchronization functions
// =========================

void *
fd_sha256_new( void * shmem );

fd_sha256_t *
fd_sha256_join( void * shsha );

void *
fd_sha256_leave( fd_sha256_t * sha );

void *
fd_sha256_delete( void * shsha );

// Simple interface
// ================

/* fd_sha256_init starts a sha256 calculation.  sha is assumed to be a
   current local join to a sha256 calculation state with no other
   concurrent operation that would modify the state while this is
   executing.  Any preexisting state for an in-progress or recently
   completed calculation will be discarded.  Returns sha (on return, sha
   will have the state of a new in-progress calculation). */

fd_sha256_t *
fd_sha256_init( fd_sha256_t * sha );

/* fd_sha256_append adds sz bytes locally pointed to by data an
   in-progress sha256 calculation.  sha, data and sz are assumed to be
   valid (i.e. sha is a current local join to a sha256 calculation state
   with no other concurrent operations that would modify the state while
   this is executing, data points to the first of the sz bytes and will
   be unmodified while this is running with no interest retained after
   return ... data==NULL is fine if sz==0).  Returns sha (on return, sha
   will have the updated state of the in-progress calculation).

   It does not matter how the user group data bytes for a sha256
   calculation; the final hash will be identical.  It is preferable for
   performance to try to append as many bytes as possible as a time
   though.  It is also preferable for performance if sz is a multiple of
   64 for all but the last append (it is also preferable if sz is less
   than 56 for the last append). */

fd_sha256_t *
fd_sha256_append( fd_sha256_t * sha,
                  void const *  data,
                  ulong         sz );

/* fd_sha256_fini finishes a a sha256 calculation.  sha and hash are
   assumed to be valid (i.e. sha is a local join to a sha256 calculation
   state that has an in-progress calculation with no other concurrent
   operations that would modify the state while this is executing and
   hash points to the first byte of a 32-byte memory region where the
   result of the calculation should be stored).  Returns hash (on
   return, there will be no calculation in-progress on sha and 32-byte
   buffer pointed to by hash will be populated with the calculation
   result). */

void *
fd_sha256_fini( fd_sha256_t * sha,
                void *        hash );

// Advanced interface
// ==================

/* FD_SHA256_INIT_n are the eight 32-bit integers that comprise the initial hash state.
   Note that the byte order of each integer is reversed (little-endian). */

#define FD_SHA256_INIT_0 (0x6a09e667U)
#define FD_SHA256_INIT_1 (0xbb67ae85U)
#define FD_SHA256_INIT_2 (0x3c6ef372U)
#define FD_SHA256_INIT_3 (0xa54ff53aU)
#define FD_SHA256_INIT_4 (0x510e527fU)
#define FD_SHA256_INIT_5 (0x9b05688cU)
#define FD_SHA256_INIT_6 (0x1f83d9abU)
#define FD_SHA256_INIT_7 (0x5be0cd19U)

/* fd_sha256_init_state loads the 32 byte initial state value into the given buffer. */

static inline void fd_sha256_init_state( uchar * state ) {
  uint * s = (uint *)state;
  s[0] = FD_SHA256_INIT_0;
  s[1] = FD_SHA256_INIT_1;
  s[2] = FD_SHA256_INIT_2;
  s[3] = FD_SHA256_INIT_3;
  s[4] = FD_SHA256_INIT_4;
  s[5] = FD_SHA256_INIT_5;
  s[6] = FD_SHA256_INIT_6;
  s[7] = FD_SHA256_INIT_7;
}

/* fd_sha256_core invokes the internal block function of SHA-256 block_cnt times.
   For each iteration, reads and advances the block ptr by one block and updates state.

   state is a buffer of size FD_SHA256_HASH_SZ.
   block is a buffer of size FD_SHA256_BLOCK_SZ times block_cnt.
   The state and block buffers must not overlap. */

void
fd_sha256_core( uchar       * FD_RESTRICT state,
                uchar const * FD_RESTRICT block,
                ulong                     block_cnt );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_ballet_sha256_fd_sha256_h */
