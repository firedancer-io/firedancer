#ifndef HEADER_fd_src_funk_fd_funk_val_h
#define HEADER_fd_src_funk_fd_funk_val_h

/* This provides APIs for managing funk record values.  It is generally
   not meant to be included directly.  Use fd_funk.h instead. */

#include "fd_funk_rec.h" /* Includes fd_funk_txn.h, fd_funk_base.h */

/* FD_FUNK_REC_VAL_MAX is the maximum size of a record value. */

#define FD_FUNK_REC_VAL_MAX UINT_MAX

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

FD_FN_PURE static inline void *         /* Lifetime is the lesser of rec or the value size is modified */
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

/* fd_funk_val_safe copies out the record value into a buffer
 * allocated by the valloc. The result should eventually be freed by
 * the same valloc. This API is safe in the presence of concurrent writes. */

void *
fd_funk_val_safe( fd_funk_rec_t const * rec,     /* Assumes pointer in caller's address space to a live funk record */
                  fd_wksp_t const *     wksp,
                  fd_valloc_t           valloc,
                  ulong *               result_len );


/* fd_funk_rec_read reads bytes [off,off+sz) and returns a pointer to
   the requested data on success and NULL on failure.  Reasons for
   failure include NULL rec, 0 sz, [off,off+sz) does not overlap
   completely val, NULL wksp, marked ERASE.  Assumes no concurrent
   operations on rec.

   The returned pointer is in the caller's address space and, if
   non-NULL, the value at the pointer is stable for its lifetime or
   until it it is modified.

   IMPORTANT SAFETY TIP!  There are _no_ alignment guarantees on the
   returned value (even if off itself is aligned).

   Note that if reading two overlapping regions of a record, the return
   pointers can overlap (along these will also overlap the regions
   returned by the above accessors).  Further, if the region is changed
   by a below write, the value at the returned pointers will immediately
   reflect those writes.  (That is, the returned pointers are zero copy
   into the actual value data of the record.)  */

FD_FN_PURE static inline void const *            /* Lifetime is lesser of current local join, the record or val is resized */
fd_funk_val_read( fd_funk_rec_t const * rec,     /* Assumes pointer in caller's address space to a live funk record
                                                    (NULL returns NULL) */
                  ulong                 off,     /* Should be in [0,sz] */
                  ulong                 sz,      /* Should be in [1,val_sz-off] */
                  fd_wksp_t const *     wksp ) { /* ==fd_funk_wksp( funk ) where funk is current local join */

  ulong end = off + sz;

  if( FD_UNLIKELY( (!rec) | (end<=off) | (!wksp) ) ||             /* NULL rec, sz==0 or off+sz wrapped, NULL wksp */
      FD_UNLIKELY( (end>(ulong)rec->val_sz)      ) ) return NULL; /* Read past end (covers marked ERASE case too) */

  return fd_wksp_laddr_fast( wksp, rec->val_gaddr + off );
}

/* Operations */

/* fd_funk_rec_write writes record bytes [off,off+sz) and returns rec on
   success and NULL on failure.

   data points to the bytes to sz write.  [data,data+sz) should not
   overlap with the current value bytes [off,off+sz) but otherwise can
   point anywhere valid in the caller's address space.

   The write retains no interest in data on return.  sz 0 is considered
   a no-op regardless of anything else and immediately returns rec.

   Reasons for failure include NULL rec, NULL data with non-zero sz,
   [data,data+sz) wraps, [off,off+sz) does not overlap with the record
   completely, [data,data+sz) overlaps with [off,off+sz).  Assumes no
   concurrent operations on rec or data. */

FD_FN_UNUSED static fd_funk_rec_t *           /* Returns rec on success, NULL on failure */ /* Workaround -Winline */
fd_funk_val_write( fd_funk_rec_t *   rec,     /* Assumed in caller's address space to live funk record (NULL returns NULL) */
                   ulong             off,     /* First byte of record to write, in [0,val_sz], NULL if too large */
                   ulong             sz,      /* Number of bytes to write, 0 is a no-op, in [0,val_sz-off], NULL if too large */
                   void const *      data,    /* Assumed in caller's address space, NULL okay if sz 0 */
                   fd_wksp_t const * wksp ) { /* ==fd_funk_wksp( funk ) where funk is current local join */

  if( FD_UNLIKELY( !sz ) ) return rec; /* Empty write request */

  ulong end = off + sz;

  ulong d0 = (ulong)data;
  ulong d1 = d0 + sz;

  if( FD_UNLIKELY( (!rec) | (end<off) | (!data) | (d1<d0) | (!wksp) ) || /* NULL rec, off+sz wrapped, NULL data w sz!=0, data wrapped, NULL wksp */
      FD_UNLIKELY( end > (ulong)rec->val_max                         ) ) return NULL; /* too large (covers marked ERASE case too) */

  ulong v0 = (ulong)fd_wksp_laddr_fast( wksp, rec->val_gaddr + off );
  ulong v1 = v0 + sz;

  if( FD_UNLIKELY( !((d1<=v0) | (d0>=v1)) ) ) return NULL; /* data overlaps with val */

  fd_memcpy( (void *)v0, data, sz );

  if ( FD_UNLIKELY( end > (ulong)rec->val_sz ) )
    rec->val_sz = (uint)end;

  return rec;
}

/* fd_funk_val_copy copies sz bytes starting at data into the record
   value, replacing the existing record value.  rec's value will be able
   to accommodate at least sz_est in the future without resizing on
   return.  If sz_est is 0 on entry, it will be be set to sz as a
   reasonable default before any argument checking.

   data points to the bytes to write.  [data,data+sz) should not overlap
   with the existing record but can otherwise can point anywhere valid
   in the caller's address space.

   This generally will resize the record value to something at least
   sz_est so this function should be assumed to kill any existing
   pointers into this record's value storage.  Note that sz_est==0 will
   set the record to the NULL val.  And sz==0 with sz_est!=0 can be used
   to preallocate record sizes with a NULL initial value.

   Returns rec on success and NULL on failure.  If opt_err is non-NULL,
   on return, *opt_err will hold FD_FUNK_SUCCESS if successful or a
   FD_FUNK_ERR_* code on failure.  Reasons for failure include
   FD_FUNK_ERR_INVAL (NULL rec, NULL data with non-zero sz, NULL alloc,
   NULL wksp, data region wraps, sz>sz_est, sz_est too large, rec is
   marked as ERASE, data region overlaps the existing val allocation)
   and FD_FUNK_ERR_MEM (allocation failure, need a larger wksp).  On
   failure, the current value is unchanged.

   Assumes no concurrent operations on rec or data.  The copy retains no
   interest in data on return. */

fd_funk_rec_t *                              /* Returns rec on success, NULL on failure */
fd_funk_val_copy( fd_funk_rec_t * rec,       /* Assumed in caller's address space to live funk record (NULL returns NULL) */
                  void const *    data,      /* Points to first byte to copy in caller's address space, NULL okay if sz 0 */
                  ulong           sz,        /* Number of bytes to copy, in [0,sz_est], NULL if too large */
                  ulong           sz_est,    /* Est final size, 0 means use sz, in [sz,FD_FUNK_REC_VAL_MAX], NULL if too large */
                  fd_alloc_t *    alloc,     /* ==fd_funk_alloc( funk, wksp ) */
                  fd_wksp_t *     wksp,      /* ==fd_funk_wksp( funk ) where funk is current local join */
                  int *           opt_err );  /* If non-NULL, *opt_err returns operation error code */

/* fd_funk_val_append appends sz bytes starting at data to the end of
   the record rec.  [data,data+sz) should not overlap with the existing
   value allocation but can otherwise can point anywhere valid in the
   caller's address space.

   This might need to resize the record value so this function should be
   assumed to kill any existing pointers into this record's value
   storage.  Unlike copy above and truncate below, this function does
   try to minimize the amount of value allocations it might do.

   Returns rec on success and NULL on failure.  If opt_err is non-NULL,
   on return, *opt_err will hold FD_FUNK_SUCCESS if successful or a
   FD_FUNK_ERR_* code on failure.  Reasons for failure include
   FD_FUNK_ERR_INVAL (NULL rec, NULL data with non-zero sz,
   [data,data+sz) wraps, NULL alloc, NULL wksp, rec marked ERASE, sz too
   large, data region overlaps with existing record value allocation)
   and FD_FUNK_ERR_MEM (allocation failure, need a larger wksp).  On
   failure, the current value is unchanged.

   Assumes no concurrent operations on rec or data.  The append retains
   no interest in data on return.  sz 0 is considered a no-op regardless
   of anything else and immediately returns rec / SUCCESS. */

fd_funk_rec_t *                                /* Returns rec on success, NULL on failure */
fd_funk_val_append( fd_funk_rec_t * rec,       /* Assumed in caller's address space to a live funk record (NULL returns NULL) */
                    void const *    data,      /* Points to first byte to append in caller's address space, NULL okay if sz 0 */
                    ulong           sz,        /* Number of bytes to append, 0 is a no-op, NULL if too large */
                    fd_alloc_t *    alloc,     /* ==fd_funk_alloc( funk, wksp ) */
                    fd_wksp_t *     wksp,      /* ==fd_funk_wksp( funk ) where funk is current local join */
                    int *           opt_err ); /* If non-NULL, *opt_err returns operation error code */

/* fd_funk_val_truncate resizes a record to be new_val_sz bytes in size.

   This function is optimized for the user knowing the actual long term
   record size when they call this.  So avoid using this to
   incrementally increase a size of a value by a constant amount over
   time.  See append above for that.

   Likewise, regardless of the current and new value sizes, this will
   always attempt to resize the record in order to minimize the amount
   of excess allocation used by the record.  So this function should be
   assumed to kill any existing pointers into this record's value
   storage.

   Returns rec on success and NULL on failure.  If opt_err is non-NULL,
   on return, *opt_err will hold FD_FUNK_SUCCESS if successful or a
   FD_FUNK_ERR_* code on failure.  Reasons for failure include
   FD_FUNK_ERR_INVAL (NULL rec, too large new_val_sz, rec is marked
   ERASE) and FD_FUNK_ERR_MEM (allocation failure, need a larger wksp).
   On failure, the current value is unchanged.

   Assumes no concurrent operations on rec. */

fd_funk_rec_t *                                   /* Returns rec on success, NULL on failure */
fd_funk_val_truncate( fd_funk_rec_t * rec,        /* Assumed in caller's address space to a live funk record (NULL returns NULL) */
                      ulong           new_val_sz, /* Should be in [0,FD_FUNK_REC_VAL_MAX] (returns NULL otherwise) */
                      fd_alloc_t *    alloc,      /* ==fd_funk_alloc( funk, wksp ) */
                      fd_wksp_t *     wksp,       /* ==fd_funk_wksp( funk ) where funk is current local join */
                      int *           opt_err );  /* If non-NULL, *opt_err returns operation error code */

/* Misc */

/* fd_funk_val_init sets a record with uninitialized value metadata to
   the NULL value.  Meant for internal use. */

static inline fd_funk_rec_t *             /* Returns rec */
fd_funk_val_init( fd_funk_rec_t * rec ) { /* Assumed record in caller's address space with uninitialized value metadata */
  rec->val_sz    = 0U;
  rec->val_max   = 0U;
  rec->val_gaddr = 0UL;
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
