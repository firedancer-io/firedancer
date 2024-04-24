#include "fd_funk.h"

fd_funk_rec_t *
fd_funk_val_copy( fd_funk_rec_t * rec,
                  void const *    data,
                  ulong           sz,
                  ulong           sz_est,
                  fd_alloc_t *    alloc,
                  fd_wksp_t *     wksp,
                  int *           opt_err ) {

  /* Check input args */

  sz_est = fd_ulong_if( !sz_est, sz, sz_est ); /* Use reasonable default for sz_est */

  ulong d0 = (ulong)data;
  ulong d1 = d0 + sz;

  if( FD_UNLIKELY( (!rec) | ((!data) & (!!sz)) | (!alloc) | (!wksp) |         /* NULL rec,NULL data w sz!=0,NULL alloc,NULL wksp */
                   (d1<d0) | (sz>sz_est) | (sz_est>FD_FUNK_REC_VAL_MAX) ) ) { /* data wraps, too large sz, too large sz_est */
    fd_int_store_if( !!opt_err, opt_err, FD_FUNK_ERR_INVAL );
    return NULL;
  }

  ulong val_max   = (ulong)rec->val_max;
  ulong val_gaddr = rec->val_gaddr;

  ulong v0 = val_max ? (ulong)fd_wksp_laddr_fast( wksp, val_gaddr ) : 0UL; /* Technically don't need trinary */
  ulong v1 = v0 + val_max;

  if( FD_UNLIKELY( ((!!sz) & (!!val_max) & (!((d1<=v0) | (d0>=v1)))) |     /* data overlaps val alloc */
                   (!!(rec->flags & FD_FUNK_REC_FLAG_ERASE))         ) ) { /* marked erase */
    fd_int_store_if( !!opt_err, opt_err, FD_FUNK_ERR_INVAL );
    return NULL;
  }

  uchar * val = (uchar *)v0;

  if( FD_UNLIKELY( !sz_est ) ) {

    /* User requested to flush the existing value */

    fd_funk_val_flush( rec, alloc, wksp );

  } else {

    /* User requested to allocate at least sz_est for value.  Allocate
       space for the copy.  If allocation fails, we do any remaining
       data copy into the current allocation (if possible).  Otherwise,
       we copy the data into the new space, free the old space (if any)
       and switch the value to the new space.  We do the alloc first
       such that if it fails, we haven't affected the state. */

    ulong   new_val_max;
    uchar * new_val = (uchar *)fd_alloc_malloc_at_least( alloc, 1UL, sz_est, &new_val_max );

    if( FD_UNLIKELY( !new_val ) ) { /* Fallback on in-place */

      new_val_max = rec->val_max;
      if( FD_UNLIKELY( new_val_max < sz ) ) { /* Fallback failed too */
        fd_int_store_if( !!opt_err, opt_err, FD_FUNK_ERR_MEM );
        return NULL;
      }

    } else { /* Out-of-place */

      rec->val_max   = (uint)fd_ulong_min( new_val_max, FD_FUNK_REC_VAL_MAX );
      rec->val_gaddr = fd_wksp_gaddr_fast( wksp, new_val );

      if( val ) fd_alloc_free( alloc, val );
      val = new_val;

    }

    /* At this point we have room for the copy, do the copy, clear out
       trailing padding to be on the safe side and update the value
       size. */

    if( FD_LIKELY( sz ) ) fd_memcpy( val, data, sz );
    fd_memset( val + sz, 0, new_val_max - sz );
    rec->val_sz = (uint)sz;

  }

  fd_int_store_if( !!opt_err, opt_err, FD_FUNK_SUCCESS );
  return rec;
}

fd_funk_rec_t *
fd_funk_val_append( fd_funk_rec_t * rec,
                    void const *    data,
                    ulong           sz,
                    fd_alloc_t *    alloc,
                    fd_wksp_t *     wksp,
                    int *           opt_err ) {

  /* Check input args */

  if( FD_UNLIKELY( !sz ) ) { /* Empty append request */
    fd_int_store_if( !!opt_err, opt_err, FD_FUNK_SUCCESS );
    return rec;
  }

  ulong d0 = (ulong)data;
  ulong d1 = d0 + sz;

  if( FD_UNLIKELY( (!rec) | (!d0) | (d1<d0) | (!alloc) | (!wksp) ) ) { /* NULL rec, NULL data, data wrap, NULL alloc, NULL wksp */
    fd_int_store_if( !!opt_err, opt_err, FD_FUNK_ERR_INVAL );
    return NULL;
  }

  ulong val_sz    = (ulong)rec->val_sz;
  ulong val_max   = (ulong)rec->val_max;
  ulong val_gaddr = rec->val_gaddr;

  ulong new_val_sz = val_sz + sz;

  ulong v0 = val_max ? (ulong)fd_wksp_laddr_fast( wksp, val_gaddr ) : 0UL; /* Technically don't need trinary */
  ulong v1 = v0 + val_max;

  if( FD_UNLIKELY( (new_val_sz<val_sz) | (new_val_sz>FD_FUNK_REC_VAL_MAX) |     /* too large sz */
                   ((!!val_max) & (!((d1<=v0) | (d0>=v1))))               |     /* data overlaps with val alloc */
                   (!!(rec->flags & FD_FUNK_REC_FLAG_ERASE))              ) ) { /* marked erase */
    fd_int_store_if( !!opt_err, opt_err, FD_FUNK_ERR_INVAL );
    return NULL;
  }

  uchar * val = (uchar *)v0;

  /* If we need to resize val or do the initial allocation of val),
     compute target new size, allocate a new region of at least the
     target new size, copy the current value into it, free the old one
     and update the value.  We use malloc_at_least with 1 alignment to
     pack wksp memory as tight as possible. */

  if( FD_UNLIKELY( new_val_sz > val_max ) ) {

    ulong new_val_max = fd_ulong_min( fd_alloc_max_expand( val_max, 1UL, new_val_sz ), FD_FUNK_REC_VAL_MAX );
    if( FD_UNLIKELY( new_val_max<=val_max ) ) { /* Already expanded as much as possible */
      fd_int_store_if( !!opt_err, opt_err, FD_FUNK_ERR_INVAL );
      return NULL;
    }

    uchar * new_val = (uchar *)fd_alloc_malloc_at_least( alloc, 1UL, new_val_max, &new_val_max );
    if( FD_UNLIKELY( !new_val ) ) { /* Allocation failure */
      fd_int_store_if( !!opt_err, opt_err, FD_FUNK_ERR_MEM );
      return NULL;
    }

    if( val_sz ) fd_memcpy( new_val, val, val_sz ); /* Copy the existing val */
    fd_memset( new_val + val_sz, 0, new_val_max - val_sz ); /* Clear out trailing padding to be on the safe side */
    fd_alloc_free( alloc, val ); /* Free the old val */

    rec->val_max   = (uint)fd_ulong_min( new_val_max, FD_FUNK_REC_VAL_MAX );
    rec->val_gaddr = fd_wksp_gaddr_fast( wksp, new_val );

    val = new_val;

  }

  /* At this point, we have room to do the append.  Do the append.
     Trailing padding was cleared out previously. */

  fd_memcpy( val+val_sz, data, sz );

  rec->val_sz = (uint)new_val_sz;

  fd_int_store_if( !!opt_err, opt_err, FD_FUNK_SUCCESS );
  return rec;
}

fd_funk_rec_t *
fd_funk_val_truncate( fd_funk_rec_t * rec,
                      ulong           new_val_sz,
                      fd_alloc_t *    alloc,
                      fd_wksp_t *     wksp,
                      int *           opt_err ) {

  /* Check input args */

  if( FD_UNLIKELY( (!rec) | (new_val_sz>FD_FUNK_REC_VAL_MAX) | (!alloc) | (!wksp) ) ||  /* NULL rec,too big,NULL alloc,NULL wksp */
      FD_UNLIKELY( rec->flags & FD_FUNK_REC_FLAG_ERASE                            ) ) { /* Marked erase */
    fd_int_store_if( !!opt_err, opt_err, FD_FUNK_ERR_INVAL );
    return NULL;
  }

  ulong val_sz = (ulong)rec->val_sz;

  if( FD_UNLIKELY( !new_val_sz ) ) {

    /* User asked to truncate to 0.  Flush the any existing value. */

    fd_funk_val_flush( rec, alloc, wksp );

  } else if( FD_LIKELY( new_val_sz > val_sz ) ) {

    /* User requested to increase the value size.  We presume they are
       asking for a specific size (as opposed to bumping up the size ala
       append) so we don't build in extra padding to amortize the cost
       of future truncates.  Note that new_val_sz is at least 1 at this
       point but val_sz / val_gaddr could be zero / zero. */

    ulong   val_max   = (ulong)rec->val_max;
    ulong   val_gaddr = rec->val_gaddr;
    uchar * val       = val_max ? fd_wksp_laddr_fast( wksp, val_gaddr ) : NULL; /* TODO: branchless */

    ulong   new_val_max;
    uchar * new_val = (uchar *)fd_alloc_malloc_at_least( alloc, 1UL, new_val_sz, &new_val_max );
    if( FD_UNLIKELY( !new_val ) ) { /* Allocation failure! */
      fd_int_store_if( !!opt_err, opt_err, FD_FUNK_ERR_MEM );
      return NULL;
    }

    if( val_sz ) fd_memcpy( new_val, val, val_sz ); /* Copy the existing value */
    fd_memset( new_val + val_sz, 0, new_val_max - val_sz ); /* Clear out trailing padding to be on the safe side */

    /* Order of updates is important for fd_funk_val_safe */
    rec->val_gaddr = fd_wksp_gaddr_fast( wksp, new_val );
    rec->val_sz    = (uint)new_val_sz;
    rec->val_max   = (uint)fd_ulong_min( new_val_max, FD_FUNK_REC_VAL_MAX );

    if( val ) fd_alloc_free( alloc, val ); /* Free the old value (if any) */

  } else {

    /* User requested to reduce the value size or keep it the same.
       Even though we could in principle just set rec->val_sz to its new
       value, we do a new allocation as it is still (usually) O(1),
       presumably the caller knew it wanted a particular size and that
       the resize might free up resources needed in the future.  Note
       that new_val_sz is at least 1, val_sz at least 2 and val_gaddr is
       non-zero at this point. */

    uchar * val = (uchar *)fd_wksp_laddr_fast( wksp, rec->val_gaddr );

    ulong   new_val_max;
    uchar * new_val = (uchar *)fd_alloc_malloc_at_least( alloc, 1UL, new_val_sz, &new_val_max );

    if( FD_UNLIKELY( !new_val ) ) { /* Fallback on in-place */

      new_val_max = (ulong)rec->val_max;

      fd_memset( val + new_val_sz, 0, new_val_max - new_val_sz ); /* Clear out the trailing padding to be on the safe side */

      rec->val_sz = (uint)new_val_sz;

    } else { /* Out of place */

      fd_memcpy( new_val, val, new_val_sz ); /* Copy the (truncated) existing value */
      fd_memset( new_val + new_val_sz, 0, new_val_max - new_val_sz ); /* Clear out the trailing padding to be on the safe side */

      /* Order of updates is important for fd_funk_val_safe */
      rec->val_sz    = (uint)new_val_sz;
      rec->val_max   = (uint)fd_ulong_min( new_val_max, FD_FUNK_REC_VAL_MAX );
      rec->val_gaddr = fd_wksp_gaddr_fast( wksp, new_val );

      if( val ) fd_alloc_free( alloc, val ); /* Free the old value (if any) */
    }

  }

  fd_int_store_if( !!opt_err, opt_err, FD_FUNK_SUCCESS );
  return rec;
}

void *
fd_funk_val_safe( fd_funk_rec_t const * rec,     /* Assumes pointer in caller's address space to a live funk record */
                  fd_wksp_t const *     wksp,
                  fd_valloc_t           valloc,
                  ulong *               result_len ) {
  uint val_sz = rec->val_sz;
  *result_len = val_sz;
  if( !val_sz ) return NULL;
  void * res = fd_valloc_malloc( valloc, 1U, val_sz );
  /* Note that this memcpy may copy recently freed memory, but it
     won't crash, which is the important thing */
  fd_memcpy( res, fd_wksp_laddr_fast( wksp, rec->val_gaddr ), val_sz );
  return res;
}

int
fd_funk_val_verify( fd_funk_t * funk ) {
  fd_wksp_t *     wksp     = fd_funk_wksp( funk );          /* Previously verified */
  fd_funk_rec_t * rec_map  = fd_funk_rec_map( funk, wksp ); /* Previously verified */
  ulong           wksp_tag = funk->wksp_tag;                /* Previously verified */

  /* At this point, rec_map has been extensively verified */

# define TEST(c) do {                                                                           \
    if( FD_UNLIKELY( !(c) ) ) { FD_LOG_WARNING(( "FAIL: %s", #c )); return FD_FUNK_ERR_INVAL; } \
  } while(0)

  /* Iterate over all records in use */

  for( fd_funk_rec_map_iter_t iter = fd_funk_rec_map_iter_init( rec_map );
       !fd_funk_rec_map_iter_done( rec_map, iter );
       iter = fd_funk_rec_map_iter_next( rec_map, iter ) ) {
    fd_funk_rec_t * rec = fd_funk_rec_map_iter_ele( rec_map, iter );

    /* Make sure values look sane */
    /* TODO: consider doing an alias analysis on allocated values?
       (tricky to do algo efficient in place) */

    ulong val_sz    = (ulong)rec->val_sz;
    ulong val_max   = (ulong)rec->val_max;
    ulong val_gaddr = rec->val_gaddr;

    TEST( val_sz<=val_max );

    if( rec->flags & FD_FUNK_REC_FLAG_ERASE ) {
      TEST( !val_max   );
      TEST( !val_gaddr );
    } else {
      TEST( val_max<=FD_FUNK_REC_VAL_MAX );
      if( !val_gaddr ) TEST( !val_max );
      else {
        TEST( (0UL<val_max) & (val_max<=FD_FUNK_REC_VAL_MAX) );
        TEST( fd_wksp_tag( wksp, val_gaddr )==wksp_tag );
      }
    }
  }

# undef TEST

  return FD_FUNK_SUCCESS;
}
