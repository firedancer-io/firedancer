#ifndef HEADER_fd_src_funk_fd_funk_val_h
#define HEADER_fd_src_funk_fd_funk_val_h

/* This provides APIs for managing funk record values.  It is generally
   not meant to be included directly.  Use fd_funk.h instead. */

#include "fd_funk_rec.h" /* Includes fd_funk_txn.h, fd_funk_base.h */

/* FD_FUNK_REC_VAL_MAX is the maximum size of a record value. */

#define FD_FUNK_REC_VAL_MAX (UINT_MAX)
#define FD_FUNK_VAL_ALIGN   (8UL)

FD_PROTOTYPES_BEGIN

/* Accessors */

/* fd_funk_val_{sz,max} returns the current size of the value associated
   with a record and the amount of wksp allocated currently for a value.
   Assumes funk is a current local join.  These value might change on
   subsequent calls if the record is resized.
   0<=sz<=max<=FD_FUNK_REC_VAL_MAX. */

FD_FN_PURE static inline ulong                /* Current size of the record's value in bytes */
fd_funk_val_sz( fd_funk_rec_t const * rec ) { /* Assumes pointer in caller's address space to a live funk record */
  return (ulong)rec->val_sz; /* Covers the marked ERASE case too */
}

FD_FN_PURE static inline ulong                 /* Current size of the record's value allocation in bytes */
fd_funk_val_max( fd_funk_rec_t const * rec ) { /* Assumes pointer in caller's address space to a live funk record */
  return (ulong)rec->val_max; /* Covers the marked ERASE case too */
}

/* fd_funk_val returns a pointer in the caller's address space to the
   current value associated with a record.  fd_funk_rec_val_const is a
   const-correct version.  There are sz bytes at the returned pointer.
   IMPORTANT SAFETY TIP!  There are _no_ alignment guarantees on the
   returned value.  Returns NULL if the record has a zero sz (which also
   covers the case where rec has been marked ERASE).  max 0 implies val
   NULL and vice versa.  Assumes no concurrent operations on rec. */

FD_FN_PURE static inline void *             /* Lifetime is the lesser of rec or the value size is modified */
fd_funk_val( fd_funk_rec_t const * rec,     /* Assumes pointer in caller's address space to a live funk record */
             fd_wksp_t const *     wksp ) { /* ==fd_funk_wksp( funk ) where funk is a current local join */
  ulong val_gaddr = rec->val_gaddr;
  if( !val_gaddr ) return NULL; /* Covers the marked ERASE case too */ /* TODO: consider branchless */
  return fd_wksp_laddr_fast( wksp, val_gaddr );
}

FD_FN_PURE static inline void const *             /* Lifetime is the lesser of rec or the value size is modified */
fd_funk_val_const( fd_funk_rec_t const * rec,     /* Assumes pointer in caller's address space to a live funk record */
                   fd_wksp_t const *     wksp ) { /* ==fd_funk_wksp( funk ) where funk is a current local join */
  ulong val_gaddr = rec->val_gaddr;
  if( !val_gaddr ) return NULL; /* Covers the marked ERASE case too */ /* TODO: consider branchless */
  return fd_wksp_laddr_fast( wksp, val_gaddr );
}

/* fd_funk_val_truncate resizes a record to be new_val_sz bytes in
   size.

   This function is optimized for the user knowing the actual long term
   record size when they call this.

   Regardless of the current and new value sizes, this will
   always attempt to resize the record in order to minimize the amount
   of excess allocation used by the record.  So this function should be
   assumed to kill any existing pointers into this record's value
   storage.

   Returns a pointer to the value memory on success and NULL on
   failure.  If opt_err is non-NULL, on return, *opt_err will hold
   FD_FUNK_SUCCESS if successful or a FD_FUNK_ERR_* code on
   failure.  Reasons for failure include FD_FUNK_ERR_INVAL (NULL
   rec, too large new_val_sz, rec is marked ERASE) and
   FD_FUNK_ERR_MEM (allocation failure, need a larger wksp).  On
   failure, the current value is unchanged.

   Assumes no concurrent operations on rec. */

void *                                            /* Returns record value on success, NULL on failure */
fd_funk_val_truncate( fd_funk_rec_t * rec,        /* Assumed in caller's address space to a live funk record (NULL returns NULL) */
                      fd_alloc_t *    alloc,      /* ==fd_funk_alloc( funk, wksp ) */
                      fd_wksp_t *     wksp,       /* ==fd_funk_wksp( funk ) where funk is current local join */
                      ulong           align,      /* Must be a power of 2. 0 uses the fd_funk_alloc_malloc default alignment. */
                      ulong           sz,         /* Should be in [0,FD_FUNK_REC_VAL_MAX] (returns NULL otherwise) */
                      int *           opt_err );  /* If non-NULL, *opt_err returns operation error code */

/* Misc */

/* fd_funk_val_init sets a record with uninitialized value metadata to
   the NULL value.  Meant for internal use. */

static inline fd_funk_rec_t *                /* Returns rec */
fd_funk_val_init( fd_funk_rec_t * rec ) { /* Assumed record in caller's address space with uninitialized value metadata */
  rec->val_sz      = 0U;
  rec->val_max     = 0U;
  rec->val_gaddr   = 0UL;
  return rec;
}

/* fd_funk_val_flush sets a record to the NULL value, discarding the
   current value if any.  Meant for internal use. */

static inline fd_funk_rec_t *               /* Returns rec */
fd_funk_val_flush( fd_funk_rec_t * rec,     /* Assumed live funk record in caller's address space */
                   fd_alloc_t *    alloc,   /* ==fd_funk_alloc( funk, wksp ) */
                   fd_wksp_t *     wksp ) { /* ==fd_funk_wksp( funk ) where funk is a current local join */
  ulong val_gaddr = rec->val_gaddr;
  fd_funk_val_init( rec );
  FD_COMPILER_MFENCE(); /* Make sure we don't double free on crash recovery */
  if( val_gaddr ) fd_alloc_free( alloc, fd_wksp_laddr_fast( wksp, val_gaddr ) );
  return rec;
}

/* fd_funk_val_verify verifies the record values.  Returns
   FD_FUNK_SUCCESS if the values appear intact and FD_FUNK_ERR_INVAL if
   not (logs details).  Meant to be called as part of fd_funk_verify.
   As such, it assumes funk is non-NULL, fd_funk_{wksp,rec_map,wksp_tag}
   have been verified to work and the rec_map has been verified. */

int
fd_funk_val_verify( fd_funk_t * funk );

FD_PROTOTYPES_END

/* TODO: Retune fd_alloc and fd_wksp for Solana record size optimized
   size classes and transition point to fd_wksp backing. */

#endif /* HEADER_fd_src_funk_fd_funk_val_h */
