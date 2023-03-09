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

/* FD_SHA256_{LG_HASH_SZ,HASH_SZ} describe the size of a SHA256 hash
   in bytes.  HASH_SZ==2^LG_HASH_SZ==32. */

#define FD_SHA256_LG_HASH_SZ (5)
#define FD_SHA256_HASH_SZ    (32UL) /* == 2^FD_SHA256_LG_HASH_SZ, explicit to workaround compiler limitations */

/* A fd_sha256_t should be treated as an opaque handle of a sha256
   calculation state.  (It technically isn't here facilitate compile
   time declarations of fd_sha256_t memory.) */

#define FD_SHA256_MAGIC (0xF17EDA2CE54A2560) /* FIREDANCE SHA256 V0 */

/* FD_SHA256_PRIVATE_{LG_BUF_MAX,BUF_MAX} describe the size of the
   internal buffer used by the sha256 computation object.  This is for
   internal use only.  BUF_MAX==2^LG_BUF_MAX==2*FD_SHA256_HASH_SZ==64. */

#define FD_SHA256_PRIVATE_LG_BUF_MAX (6)
#define FD_SHA256_PRIVATE_BUF_MAX    (64UL) /* == 2^FD_SHA256_PRIVATE_LG_BUF_MAX, explicit to workaround compiler limitations */

struct __attribute__((aligned(FD_SHA256_ALIGN))) fd_sha256_private {

  /* This point is 128-byte aligned */

  uchar buf[ FD_SHA256_PRIVATE_BUF_MAX ];

  /* This point is 64-byte aligned */

  uint  state[ FD_SHA256_HASH_SZ / sizeof(uint) ];

  /* This point is 32-byte aligned */

  ulong magic;    /* ==FD_SHA256_MAGIC */
  ulong buf_used; /* Number of buffered bytes, in [0,FD_SHA256_BUF_MAX) */
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

void *
fd_sha256_new( void * shmem );

fd_sha256_t *
fd_sha256_join( void * shsha );

void *
fd_sha256_leave( fd_sha256_t * sha );

void *
fd_sha256_delete( void * shsha );

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

/* fd_sha256_hash is a streamlined implementation of:

     fd_sha256_t sha[1];
     return fd_sha256_fini( fd_sha256_append( fd_sha256_init( sha ), data, sz ), hash )

   This can be faster for small messages because it can eliminate
   function call overheads, branches, copies and data marshalling under
   the hood (things like binary Merkle tree construction were designed
   do lots of such operations). */

void *
fd_sha256_hash( void const * data,
                ulong        sz,
                void *       hash );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_ballet_sha256_fd_sha256_h */
