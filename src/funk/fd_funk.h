#ifndef HEADER_fd_src_funk_fd_funk_h
#define HEADER_fd_src_funk_fd_funk_h

#include "fd_funk_base.h" /* Includes ../util/fd_util.h */

#if FD_HAS_HOSTED && FD_HAS_X86

/* The HOSTED and X86 requirement is inherited from wksp (which
   currently requires these).  There is very little in here that
   actually requires HOSTED or X86 capabilities though. */

/* FD_FUNK_{ALIGN,FOOTPRINT} describe the alignment and footprint needed
   for a funk.  ALIGN should be a positive integer power of 2.
   FOOTPRINT is multiple of ALIGN.  These are provided to facilitate
   compile time declarations.  */

#define FD_FUNK_ALIGN     (128UL)
#define FD_FUNK_FOOTPRINT (128UL)

/* The details of a fd_funk_private are exposed here to facilitate
   inlining various operations. */

#define FD_FUNK_MAGIC (0xf17eda2ce7fc2c00UL) /* firedancer funk version 0 */

struct __attribute__((aligned(FD_FUNK_ALIGN))) fd_funk_private {
  ulong magic;      /* ==FD_FUNK_MAGIC */
  ulong funk_gaddr; /* wksp gaddr of this in the backing wksp, non-zero gaddr */
  ulong wksp_tag;   /* Tag to use for wksp allocations, in [1,FD_WKSP_ALLOC_TAG_MAX] */
  ulong seed;       /* Seed for various hashing function used under the hood, arbitrary */
  /* Padding to FD_FUNK_ALIGN here */
};

FD_PROTOTYPES_BEGIN

/* Constructors */

/* fd_funk_{align,footprint} return FD_FUNK_{ALIGN,FOOTPRINT}. */

FD_FN_CONST ulong
fd_funk_align( void );

FD_FN_CONST ulong
fd_funk_footprint( void );

/* fd_wksp_new formats an unused wksp allocation with the appropriate
   alignment and footprint as a funk.  Caller is not joined on return.
   Returns shmem on success and NULL on failure (shmem NULL, shmem
   misaligned, wksp_tag not in [1,FD_WKSP_ALLOC_TAG_MAX], shmem is not
   backed by a wksp ...  logs details).  A workspace can be used by
   multiple funk concurrently.  They will dynamically share the
   underlying workspace (along with any other non-funk usage) but will
   otherwise act as completely separate non-conflicting funks.  To help
   with various diagnostics, garbage collection and what not, all
   allocations to the underlying wksp are tagged with the given tag (in
   [1,FD_WKSP_ALLOC_TAG_MAX]).  Ideally, the tag used here should be
   distinct from all other tags used by this workspace but this is not
   required. */

void *
fd_funk_new( void * shmem,
             ulong  wksp_tag,
             ulong  seed );

/* fd_funk_join joins the caller to a funk instance.  shfunk points to
   the first byte of the memory region backing the funk in the caller's
   address space.  Returns an opaque handle of the join on success
   (IMPORTANT! DO NOT ASSUME THIS IS A CAST OF SHFUNK) and NULL on
   failure (NULL shfunk, misaligned shfunk, shfunk is not backed by a
   wksp, bad magic, ... logs details).  Every successful join should
   have a matching leave.  The lifetime of the join is until the
   matching leave or the thread group is terminated (joins are local to
   a thread group). */

fd_funk_t *
fd_funk_join( void * shfunk );

/* fd_funk_leave leaves an existing join.  Returns the underlying
   shfunk (IMPORTANT! DO NOT ASSUME THIS IS A CAST OF FUNK) on success
   and NULL on failure.  Reasons for failure include funk is NULL (logs
   details). */

void *
fd_funk_leave( fd_funk_t * funk );

/* fd_funk_delete unformats a wksp allocation used as a funk
   (additionally frees all wksp allocations used by that funk).  Assumes
   nobody is or will be joined to the funk.  Returns shmem on success
   and NULL on failure (logs details).  Reasons for failure include
   shfunk is NULL, misaligned shfunk, shfunk is not backed by a
   workspace, etc. */

void *
fd_funk_delete( void * shfunk );

/* Accessors */

/* fd_funk_wksp returns the local join to the wksp backing the funk.
   The lifetime of the returned pointer is at least as long as the
   lifetime of the local join.  Assumes funk is a current local join. */

FD_FN_PURE static inline fd_wksp_t * fd_funk_wksp( fd_funk_t * funk ) { return (fd_wksp_t *)(((ulong)funk) - funk->funk_gaddr); }

/* fd_funk_wksp_tag returns the workspace allocation tag used by the
   funk for its wksp allocations.  Will be in [1,FD_WKSP_ALLOC_TAG_MAX].
   Assumes funk is a current local join. */

FD_FN_PURE static inline ulong fd_funk_wksp_tag( fd_funk_t * funk ) { return funk->wksp_tag; }

/* fd_funk_seed returns the seed used by the funk for the hash functions
   it uses under the hood.  Arbitrary value.  Assumes funk is a current
   local join. */

FD_FN_PURE static inline ulong fd_funk_seed( fd_funk_t * funk ) { return funk->seed; }

/* Misc */

/* fd_funk_verify verifies the integrity of funk.  Returns
   FD_FUNK_SUCCESS if funk appears to be intact and FD_FUNK_ERR_INVAL
   otherwise (logs details).  Assumes funk is a current local join (NULL
   returns FD_FUNK_ERR_INVAL and logs details.) */

int
fd_funk_verify( fd_funk_t * funk );

FD_PROTOTYPES_END

#endif /* FD_HAS_HOSTED && FD_HAS_X86 */

#endif /* HEADER_fd_src_funk_fd_funk_h */
