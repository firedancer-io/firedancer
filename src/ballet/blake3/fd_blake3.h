#ifndef HEADER_fd_src_ballet_blake3_fd_blake3_h
#define HEADER_fd_src_ballet_blake3_fd_blake3_h

/* fd_blake3 provides APIs for BLAKE3 hashing of messages. */

#include "../fd_ballet_base.h"
#include "blake3.h"

/* FD_BLAKE3_{ALIGN,FOOTPRINT} describe the alignment and footprint needed
   for a memory region to hold a fd_blake3_t.  ALIGN is a positive
   integer power of 2.  FOOTPRINT is a multiple of align.  ALIGN is
   recommended to be at least double cache line to mitigate various
   kinds of false sharing.  These are provided to facilitate compile
   time declarations. */

#define FD_BLAKE3_ALIGN     (128UL)
#define FD_BLAKE3_FOOTPRINT (1920UL)

/* A fd_blake3_t should be treated as an opaque handle of a blake3
   calculation state.  (It technically isn't here facilitate compile
   time declarations of fd_blake3_t memory.) */

#define FD_BLAKE3_MAGIC (0xF17EDA2CEB1A4E30) /* FIREDANCE BLAKE3 V0 */

struct __attribute__((aligned(FD_BLAKE3_ALIGN))) fd_blake3_private {
  blake3_hasher hasher;

  ulong magic;    /* ==FD_BLAKE3_MAGIC */
};

typedef struct fd_blake3_private fd_blake3_t;

FD_PROTOTYPES_BEGIN

/* fd_blake3_{align,footprint,new,join,leave,delete} usage is identical to
   that of their fd_sha512 counterparts.  See ../sha512/fd_sha512.h */

FD_FN_CONST ulong
fd_blake3_align( void );

FD_FN_CONST ulong
fd_blake3_footprint( void );

void *
fd_blake3_new( void * shmem );

fd_blake3_t *
fd_blake3_join( void * shsha );

void *
fd_blake3_leave( fd_blake3_t * sha );

void *
fd_blake3_delete( void * shsha );

/* fd_blake3_init starts a blake3 calculation.  sha is assumed to be a
   current local join to a blake3 calculation state with no other
   concurrent operation that would modify the state while this is
   executing.  Any preexisting state for an in-progress or recently
   completed calculation will be discarded.  Returns sha (on return, sha
   will have the state of a new in-progress calculation). */

fd_blake3_t *
fd_blake3_init( fd_blake3_t * sha );

/* fd_blake3_append adds sz bytes locally pointed to by data an
   in-progress blake3 calculation.  sha, data and sz are assumed to be
   valid (i.e. sha is a current local join to a blake3 calculation state
   with no other concurrent operations that would modify the state while
   this is executing, data points to the first of the sz bytes and will
   be unmodified while this is running with no interest retained after
   return ... data==NULL is fine if sz==0).  Returns sha (on return, sha
   will have the updated state of the in-progress calculation).

   It does not matter how the user group data bytes for a blake3
   calculation; the final hash will be identical.  It is preferable for
   performance to try to append as many bytes as possible as a time
   though.  It is also preferable for performance if sz is a multiple of
   64 for all but the last append (it is also preferable if sz is less
   than 56 for the last append). */

fd_blake3_t *
fd_blake3_append( fd_blake3_t * sha,
                  void const *  data,
                  ulong         sz );

/* fd_blake3_fini finishes a a blake3 calculation.  sha and hash are
   assumed to be valid (i.e. sha is a local join to a blake3 calculation
   state that has an in-progress calculation with no other concurrent
   operations that would modify the state while this is executing and
   hash points to the first byte of a 32-byte memory region where the
   result of the calculation should be stored).  Returns hash (on
   return, there will be no calculation in-progress on sha and 32-byte
   buffer pointed to by hash will be populated with the calculation
   result). */

void *
fd_blake3_fini( fd_blake3_t * sha,
                void *        hash );

/* fd_blake3_fini_512 is the same as fd_blake3_fini, but returns
   a 512-bit hash value instead of 256-bit. */

void *
fd_blake3_fini_512( fd_blake3_t * sha,
                    void *        hash );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_ballet_blake3_fd_blake3_h */
