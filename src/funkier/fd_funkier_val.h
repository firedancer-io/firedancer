#ifndef HEADER_fd_src_funk_fd_funkier_val_h
#define HEADER_fd_src_funk_fd_funkier_val_h

/* This provides APIs for managing funk record values.  It is generally
   not meant to be included directly.  Use fd_funk.h instead. */

#include "fd_funkier_rec.h" /* Includes fd_funkier_txn.h, fd_funkier_base.h */

/* FD_FUNKIER_REC_VAL_MAX is the maximum size of a record value. */

#define FD_FUNKIER_REC_VAL_MAX UINT_MAX
#define FD_FUNKIER_VAL_ALIGN 8UL

FD_PROTOTYPES_BEGIN

/* Accessors */

/* fd_funkier_val_{sz,max} returns the current size of the value associated
   with a record and the amount of wksp allocated currently for a value.
   Assumes funk is a current local join.  These value might change on
   subsequent calls if the record is resized.
   0<=sz<=max<=FD_FUNKIER_REC_VAL_MAX. */

FD_FN_PURE static inline ulong                /* Current size of the record's value in bytes */
fd_funkier_val_sz( fd_funkier_rec_t const * rec ) { /* Assumes pointer in caller's address space to a live funk record */
  return (ulong)rec->val_sz; /* Covers the marked ERASE case too */
}

FD_FN_PURE static inline ulong                 /* Current size of the record's value allocation in bytes */
fd_funkier_val_max( fd_funkier_rec_t const * rec ) { /* Assumes pointer in caller's address space to a live funk record */
  return (ulong)rec->val_max; /* Covers the marked ERASE case too */
}

/* fd_funkier_val returns a pointer in the caller's address space to the
   current value associated with a record.  fd_funkier_rec_val_const is a
   const-correct version.  There are sz bytes at the returned pointer.
   IMPORTANT SAFETY TIP!  There are _no_ alignment guarantees on the
   returned value.  Returns NULL if the record has a zero sz (which also
   covers the case where rec has been marked ERASE).  max 0 implies val
   NULL and vice versa.  Assumes no concurrent operations on rec. */

FD_FN_PURE static inline void *             /* Lifetime is the lesser of rec or the value size is modified */
fd_funkier_val( fd_funkier_rec_t const * rec,     /* Assumes pointer in caller's address space to a live funk record */
                fd_wksp_t const *        wksp ) { /* ==fd_funkier_wksp( funk ) where funk is a current local join */
  ulong val_gaddr = rec->val_gaddr;
  if( !val_gaddr ) return NULL; /* Covers the marked ERASE case too */ /* TODO: consider branchless */
  return fd_wksp_laddr_fast( wksp, val_gaddr );
}

FD_FN_PURE static inline void const *             /* Lifetime is the lesser of rec or the value size is modified */
fd_funkier_val_const( fd_funkier_rec_t const * rec,     /* Assumes pointer in caller's address space to a live funk record */
                      fd_wksp_t const *        wksp ) { /* ==fd_funkier_wksp( funk ) where funk is a current local join */
  ulong val_gaddr = rec->val_gaddr;
  if( !val_gaddr ) return NULL; /* Covers the marked ERASE case too */ /* TODO: consider branchless */
  return fd_wksp_laddr_fast( wksp, val_gaddr );
}

/* fd_funkier_val_truncate resizes a record to be new_val_sz bytes in
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
   FD_FUNKIER_SUCCESS if successful or a FD_FUNKIER_ERR_* code on
   failure.  Reasons for failure include FD_FUNKIER_ERR_INVAL (NULL
   rec, too large new_val_sz, rec is marked ERASE) and
   FD_FUNKIER_ERR_MEM (allocation failure, need a larger wksp).  On
   failure, the current value is unchanged.

   Assumes no concurrent operations on rec. */

void *                                               /* Returns record value on success, NULL on failure */
fd_funkier_val_truncate( fd_funkier_rec_t * rec,     /* Assumed in caller's address space to a live funk record (NULL returns NULL) */
                         ulong              new_val_sz, /* Should be in [0,FD_FUNKIER_REC_VAL_MAX] (returns NULL otherwise) */
                         fd_alloc_t *       alloc,      /* ==fd_funkier_alloc( funk, wksp ) */
                         fd_wksp_t *        wksp,       /* ==fd_funkier_wksp( funk ) where funk is current local join */
                         int *              opt_err );  /* If non-NULL, *opt_err returns operation error code */

/* Misc */

/* fd_funkier_val_init sets a record with uninitialized value metadata to
   the NULL value.  Meant for internal use. */

static inline fd_funkier_rec_t *                /* Returns rec */
fd_funkier_val_init( fd_funkier_rec_t * rec ) { /* Assumed record in caller's address space with uninitialized value metadata */
  rec->val_sz      = 0U;
  rec->val_max     = 0U;
  rec->val_gaddr   = 0UL;
  return rec;
}

/* fd_funkier_val_flush sets a record to the NULL value, discarding the
   current value if any.  Meant for internal use. */

static inline fd_funkier_rec_t *                  /* Returns rec */
fd_funkier_val_flush( fd_funkier_rec_t * rec,     /* Assumed live funk record in caller's address space */
                      fd_alloc_t *       alloc,   /* ==fd_funkier_alloc( funk, wksp ) */
                      fd_wksp_t *        wksp ) { /* ==fd_funkier_wksp( funk ) where funk is a current local join */
  ulong val_gaddr = rec->val_gaddr;
  fd_funkier_val_init( rec );
  if( val_gaddr ) fd_alloc_free( alloc, fd_wksp_laddr_fast( wksp, val_gaddr ) );
  return rec;
}

#ifdef FD_FUNKIER_HANDHOLDING

/* fd_funkier_val_verify verifies the record values.  Returns
   FD_FUNKIER_SUCCESS if the values appear intact and FD_FUNKIER_ERR_INVAL if
   not (logs details).  Meant to be called as part of fd_funkier_verify.
   As such, it assumes funk is non-NULL, fd_funkier_{wksp,rec_map,wksp_tag}
   have been verified to work and the rec_map has been verified. */

int
fd_funkier_val_verify( fd_funkier_t * funk );

#endif

FD_PROTOTYPES_END

/* TODO: Retune fd_alloc and fd_wksp for Solana record size optimized
   size classes and transition point to fd_wksp backing. */

#endif /* HEADER_fd_src_funk_fd_funkier_val_h */
