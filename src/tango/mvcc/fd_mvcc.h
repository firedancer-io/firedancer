#ifndef HEADER_fd_src_tango_mvcc_fd_mvcc_h
#define HEADER_fd_src_tango_mvcc_fd_mvcc_h

#include "../../util/fd_util.h"

/* A fd_mvcc_t provides functionality for lock-free synchronization of
   single producer multiple consumer data. It is strictly less general
   than the MVCC used in various DBMS
   [https://dl.acm.org/doi/pdf/10.1145/356842.356846], but it is
   conceptually similar in that it uses a version number to detect
   conflicts.

   Write steps,

    1. Writer increments version number
    2. Writer updates data
    3. Writer increments version number

  If the version number is odd, a write is in progress.  When reading,

    1. Reader reads version number
    2. Reader reads data
    3. Reader reads version number again

  If the version numbers retrieved in steps 1 and 3 are different, the
  read is invalid as a partial write was in progress.  Typically, the
  reader should simply retry the read.

  A mvcc has an application defined app region where the versioned data
  structure can be stored, although it does not need to be, the
  producer and consumers should agree on what is being synchronized.

  Note this is similar to how producers / consumers synchronize across
  mcache / dcache.

  TODO: Hardware fencing */

/* FD_MVCC_{ALIGN,FOOTPRINT} describe the alignment and footprint of a
   fd_mvcc_t.  ALIGN is a positive integer power of 2.  FOOTPRINT is a
   multiple of ALIGN.  ALIGN is recommended to be at least double cache
   line to mitigate various kinds of false sharing.  app_sz is assumed
   to be valid (e.g. will not require a footprint larger than
   ULONG_MAX).  These are provided to facilitate compile time
   declarations. */

#define FD_MVCC_ALIGN (128UL)
#define FD_MVCC_FOOTPRINT( app_sz )                                   \
  FD_LAYOUT_FINI( FD_LAYOUT_APPEND( FD_LAYOUT_APPEND( FD_LAYOUT_INIT, \
    FD_MVCC_ALIGN,     64UL     ),                                    \
    FD_MVCC_APP_ALIGN, (app_sz) ),                                    \
    FD_MVCC_ALIGN )

/* FD_MVCC_APP_ALIGN describes the alignment and footprint of a
   fd_mvcc_t's application region.  This is a power of 2 of the minimal
   malloc alignment (typically 8) and at most FD_MVCC_ALIGN. */

#define FD_MVCC_APP_ALIGN (64UL)

#define FD_MVCC_MAGIC (0xf17eda2c37ecc000UL) /* firedancer mvc ver 0 */

struct __attribute__((aligned(FD_MVCC_ALIGN))) fd_mvcc {
  ulong magic;     /* ==FD_MVCC_MAGIC */
  ulong app_sz;
  ulong version;
  /* Padding to FD_MVCC_APP_ALIGN here */
  /* app_sz bytes here */
  /* Padding to FD_MVCC_ALIGN here */
};

typedef struct fd_mvcc fd_mvcc_t;

FD_PROTOTYPES_BEGIN

/* fd_mvcc_{align,footprint} return the required alignment and footprint
   of a memory region suitable for use as a mvcc.  fd_mvcc_align returns
   FD_MVCC_ALIGN.  If footprint is larger than ULONG_MAX, footprint will
   silently return 0 (and thus can be used by the caller to validate the
   mvcc configuration parameters). */

FD_FN_CONST ulong
fd_mvcc_align( void );

FD_FN_CONST ulong
fd_mvcc_footprint( ulong app_sz );

/* fd_mvcc_new formats an unused memory region for use as a mvcc.
   Assumes shmem is a non-NULL pointer to this region in the local
   address space with the required footprint and alignment.  The mvcc
   application region will be initialized to zero.  Returns shmem (and
   the memory region it points to will be formatted as a mvcc, caller is
   not joined) and NULL on failure (logs details).  Reasons for failure
   include an obviously bad shmem region or app_sz. */

void *
fd_mvcc_new( void * shmem,
             ulong  app_sz );

/* fd_mvcc_join joins the caller to the mvcc.  shmvcc points to the
   first byte of the memory region backing the mvcc in the caller's
   address space.  Returns a pointer in the local address space to the
   mvcc on success (this should not be assumed to be just a cast of
   shmvcc) or NULL on failure (logs details).  Reasons for failure
   include the shmvcc is obviously not a local pointer to a memory
   region holding a mvcc.  Every successful join should have a matching
   leave.  The lifetime of the join is until the matching leave or
   caller's thread group is terminated. */

fd_mvcc_t *
fd_mvcc_join( void * shmvcc );

/* fd_mvcc_leave leaves a current local join.  Returns a pointer to the
   underlying shared memory region on success (this should not be
   assumed to be just a cast of mvcc) and NULL on failure (logs
   details). Reasons for failure include mvcc is NULL. */

void *
fd_mvcc_leave( fd_mvcc_t const * mvcc );

/* fd_mvcc_delete unformats a memory region used as a mvcc.  Assumes
   nobody is joined to the region.  Returns a pointer to the underlying
   shared memory region or NULL if used obviously in error (e.g. shmvcc
   obviously does not point to a mvcc ... logs details).  The ownership
   of the memory region is transferred to the caller on success. */

void *
fd_mvcc_delete( void * shmvcc );

/* fd_mvcc_app_sz returns the size of a the mvcc's application region.
   Assumes mvcc is a current local join. */

FD_FN_PURE static inline ulong fd_mvcc_app_sz( fd_mvcc_t const * mvcc ) { return mvcc->app_sz; }

/* fd_mvcc_app_laddr returns local address of the mvcc's application
   region.  This will have FD_MVCC_APP_ALIGN alignment and room for at
   least fd_mvcc_app_sz( mvcc ) bytes.  Assumes mvcc is a current local
   join.  fd_mvcc_app_laddr_const is for const correctness.  The return
   values are valid for the lifetime of the local join. */

FD_FN_CONST static inline void *       fd_mvcc_app_laddr      ( fd_mvcc_t *       mvcc ) { return (void *      )(((ulong)mvcc)+64UL); }
FD_FN_CONST static inline void const * fd_mvcc_app_laddr_const( fd_mvcc_t const * mvcc ) { return (void const *)(((ulong)mvcc)+64UL); }

/* fd_mvcc_version_query returns the value of the mvcc's version as of
   some point in time between when this was called and when this
   returned.  Assumes mvcc is a current local join.  This acts as a
   compiler memory fence.  Any reads from the mvcc must consist of a
   pair of version queries, one before and one after the reads are
   performed.  If the version numbers do not match, the read was not
   successful and should be retried. */

static inline ulong
fd_mvcc_version_query( fd_mvcc_t const * mvcc ) {
  FD_COMPILER_MFENCE();
  ulong version = FD_VOLATILE_CONST( mvcc->version );
  FD_COMPILER_MFENCE();
  return version;
}

/* fd_mvcc_{begin,end}_write increment the version number of the mvcc to
   mark that a write is in progress or has completed respectively.  If a
   write is in progress, any reads during that time are invalid. Assumes
   mvcc is a local join.  This acts a compiler memory fence. Any writes
   to data being versioned must occur between a pair of {begin,end}
   calls. These calls should not be interleaved, or made across threads,
   or within a thread because of an async signal handler. */
static inline void
fd_mvcc_begin_write( fd_mvcc_t * mvcc ) {
  FD_ATOMIC_FETCH_AND_ADD( &mvcc->version, 1 );
  FD_COMPILER_MFENCE();
}

static inline void
fd_mvcc_end_write( fd_mvcc_t * mvcc ) {
  FD_COMPILER_MFENCE();
  FD_ATOMIC_FETCH_AND_ADD( &mvcc->version, 1 );
}

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_tango_mvcc_fd_mvcc_h */
