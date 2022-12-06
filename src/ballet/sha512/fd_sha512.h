#ifndef HEADER_fd_src_ballet_sha512_fd_sha512_h
#define HEADER_fd_src_ballet_sha512_fd_sha512_h

/* fd_sha512 provides APIs for SHA-512 hashing of messages. */

#include "../fd_ballet_base.h"

/* FD_SHA512_{ALIGN,FOOTPRINT} describe the alignment and footprint needed
   for a memory region to hold a fd_sha512_t.  ALIGN is a positive
   integer power of 2.  FOOTPRINT is a multiple of align.  ALIGN is
   recommended to be at least double cache line to mitigate various
   kinds of false sharing.  These are provided to facilitate compile
   time declarations. */

#define FD_SHA512_ALIGN     (128UL)
#define FD_SHA512_FOOTPRINT (256UL)

/* A fd_sha512_t should be treated as an opaque handle of a sha512
   calculation state.  (It technically isn't here facilitate compile
   time declarations of fd_sha512_t memory.) */

#define FD_SHA512_MAGIC (0xF17EDA2CE54A5120) /* FIREDANCE SHA512 V0 */

/* FD_SHA512_HASH_SZ returns the size of a hash in bytes. */

#define FD_SHA512_HASH_SZ (64UL)

/* FD_SHA512_BUF_MAX is the size of the internal hash buffer. */

#define FD_SHA512_BUF_MAX (128UL)

struct __attribute__((aligned(FD_SHA512_ALIGN))) fd_sha512_private {

  /* This point is 128-byte aligned */

  uchar buf[FD_SHA512_BUF_MAX]; /* Buffered message bytes (these have not been added to the hash yet), indexed [0,buf_used) */

  /* This point is 128-byte aligned */

  ulong state[8]; /* Current state of the hash */

  /* This point is 64-byte aligned */

  ulong magic;      /* ==FD_SHA512_MAGIC */
  ulong buf_used;   /* Number of buffered bytes, in [0,FD_SHA512_BUF_MAX) */
  ulong bit_cnt_lo; /* How many bits have been appended total (lower 64-bit) */
  ulong bit_cnt_hi; /* "                                      (upper 64-bit) */

  /* Padding to 128-byte here */
};

typedef struct fd_sha512_private fd_sha512_t;

FD_PROTOTYPES_BEGIN

/* fd_sha512_{align,footprint} give the needed alignment and footprint
   of a memory region suitable to hold a sha512 calculation state.
   Declaration / aligned_alloc / fd_alloca friendly (e.g. a memory
   region declared as "fd_sha512_t _sha[1];", or created by
   "aligned_alloc(alignof(fd_sha512_t),sizeof(fd_sha512_t))" or created
   by "fd_alloca(alignof(fd_sha512_t),sizeof(fd_sha512_t))" will all
   automatically have the needed alignment and footprint).
   fd_sha512_{align,footprint} return the same value as
   FD_SHA512_{ALIGN,FOOTPRINT}.

   fd_sha512_new formats memory region with suitable alignment and
   footprint suitable for holding a sha512 calculation state.  Assumes
   shmem points on the caller to the first byte of the memory region
   owned by the caller to use.  Returns shmem on success and NULL on
   failure (logs details).  The memory region will be owned by the state
   on successful return.  The caller is not joined on return.

   fd_sha512_join joins the caller to a sha512 calculation state.
   Assumes shsha points to the first byte of the memory region holding
   the state.  Returns a local handle to the join on success (this is
   not necessarily a simple cast of the address) and NULL on failure
   (logs details).

   fd_sha512_leave leaves the caller's current local join to a sha512
   calculation state.  Returns a pointer to the memory region holding
   the state on success (this is not necessarily a simple cast of the
   address) and NULL on failure (logs details).  The caller is not
   joined on successful return.

   fd_sha512_delete unformats a memory region that holds a sha512
   calculation state.  Assumes shsha points on the caller to the first
   byte of the memory region holding the state and that nobody is
   joined.  Returns a pointer to the memory region on success and NULL
   on failure (logs details).  The caller has ownership of the memory
   region on successful return. */

FD_FN_CONST ulong
fd_sha512_align( void );

FD_FN_CONST ulong
fd_sha512_footprint( void );

void *
fd_sha512_new( void * shmem );

fd_sha512_t *
fd_sha512_join( void * shsha );

void *
fd_sha512_leave( fd_sha512_t * sha );

void *
fd_sha512_delete( void * shsha );

/* fd_sha512_init starts a sha512 calculation.  sha is assumed to be a
   current local join to a sha512 calculation state with no other
   concurrent operation that would modify the state while this is
   executing.  Any preexisting state for an in-progress or recently
   completed calculation will be discarded.  Returns sha (on return, sha
   will have the state of a new in-progress calculation). */

fd_sha512_t *
fd_sha512_init( fd_sha512_t * sha );

/* fd_sha512_append adds sz bytes locally pointed to by data an
   in-progress sha512 calculation.  sha, data and sz are assumed to be
   valid (i.e. sha is a current local join to a sha512 calculation state
   with no other concurrent operations that would modify the state while
   this is executing, data points to the first of the sz bytes and will
   be unmodified while this is running with no interest retained after
   return ... data==NULL is fine if sz==0).  Returns sha (on return, sha
   will have the updated state of the in-progress calculation).

   It does not matter how the user group data bytes for a sha512
   calculation; the final hash will be identical.  It is preferable for
   performance to try to append as many bytes as possible as a time
   though.  It is also preferable for performance if sz is a multiple of
   128 for all but the last append (it is also preferable if sz is less
   than 112 for the last append). */

fd_sha512_t *
fd_sha512_append( fd_sha512_t * sha,
                  void const *  data,
                  ulong         sz );

/* fd_sha512_fini finishes a a sha512 calculation.  sha and hash are
   assumed to be valid (i.e. sha is a local join to a sha512 calculation
   state that has an in-progress calculation with no other concurrent
   operations that would modify the state while this is executing and
   hash points to the first byte of a 64-byte memory region where the
   result of the calculation should be stored).  Returns hash (on
   return, there will be no calculation in-progress on sha and 64-byte
   buffer pointed to by hash will be populated with the calculation
   result). */

void *
fd_sha512_fini( fd_sha512_t * sha,
                void *        hash );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_ballet_sha512_fd_sha512_h */
