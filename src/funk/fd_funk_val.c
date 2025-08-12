#include "fd_funk.h"

void *
fd_funk_val_truncate( fd_funk_rec_t * rec,
                      fd_alloc_t *    alloc,
                      fd_wksp_t *     wksp,
                      ulong           align,
                      ulong           sz,
                      int *           opt_err ) {

  /* Check input args */

  if( FD_UNLIKELY( (!rec) | (sz>FD_FUNK_REC_VAL_MAX) | (!alloc) | (!wksp) ) ||  /* NULL rec,too big,NULL alloc,NULL wksp */
      FD_UNLIKELY( rec->flags & FD_FUNK_REC_FLAG_ERASE                    ) ||  /* Marked erase */
      FD_UNLIKELY( !fd_ulong_is_pow2( align ) & (align != 0UL)            ) ) { /* Align is not a power of 2 or == 0 */
    fd_int_store_if( !!opt_err, opt_err, FD_FUNK_ERR_INVAL );
    return NULL;
  }

  ulong val_sz = (ulong)rec->val_sz;
  ulong val_max = (ulong)rec->val_max;

  if( FD_UNLIKELY( !sz ) ) {

    /* User asked to truncate to 0.  Flush the any existing value. */

    fd_funk_val_flush( rec, alloc, wksp );

    fd_int_store_if( !!opt_err, opt_err, FD_FUNK_SUCCESS );
    return NULL;

  } else if( FD_LIKELY( sz > val_max ) ) {

    /* User requested to increase the value size.  We presume they are
       asking for a specific size (as opposed to bumping up the size ala
       append) so we don't build in extra padding to amortize the cost
       of future truncates.  Note that new_val_sz is at least 1 at this
       point but val_sz / val_gaddr could be zero / zero. */

    ulong   val_gaddr = rec->val_gaddr;
    uchar * val       = val_max ? fd_wksp_laddr_fast( wksp, val_gaddr ) : NULL; /* TODO: branchless */

    /* NOTE: if the align is 0, we use the default alignment for
       fd_alloc_malloc_at_least */
    ulong   new_val_max;
    uchar * new_val = fd_alloc_malloc_at_least( alloc, align, sz, &new_val_max );
    if( FD_UNLIKELY( !new_val ) ) { /* Allocation failure! */
      fd_int_store_if( !!opt_err, opt_err, FD_FUNK_ERR_MEM );
      return NULL;
    }

    if( val_sz ) fd_memcpy( new_val, val, val_sz ); /* Copy the existing value */
    fd_memset( new_val + val_sz, 0, new_val_max - val_sz ); /* Clear out trailing padding to be on the safe side */

    rec->val_gaddr = fd_wksp_gaddr_fast( wksp, new_val );
    rec->val_sz    = (uint)sz;
    rec->val_max   = (uint)fd_ulong_min( new_val_max, FD_FUNK_REC_VAL_MAX );

    if( val ) fd_alloc_free( alloc, val ); /* Free the old value (if any) */

    fd_int_store_if( !!opt_err, opt_err, FD_FUNK_SUCCESS );
    return new_val;

  } else {

    /* Just set the new size */

    rec->val_sz = (uint)sz;

    fd_int_store_if( !!opt_err, opt_err, FD_FUNK_SUCCESS );
    return (uchar *)fd_wksp_laddr_fast( wksp, rec->val_gaddr );

  }
}

int
fd_funk_val_verify( fd_funk_t * funk ) {
  fd_wksp_t * wksp = fd_funk_wksp( funk );
  ulong wksp_tag = funk->shmem->wksp_tag;

  /* At this point, rec_map has been extensively verified */

# define TEST(c) do {                                                                           \
    if( FD_UNLIKELY( !(c) ) ) { FD_LOG_WARNING(( "FAIL: %s", #c )); return FD_FUNK_ERR_INVAL; } \
  } while(0)

  /* Iterate over all records in use */

  fd_funk_all_iter_t iter[1];
  for( fd_funk_all_iter_new( funk, iter ); !fd_funk_all_iter_done( iter ); fd_funk_all_iter_next( iter ) ) {
    fd_funk_rec_t const * rec = fd_funk_all_iter_ele_const( iter );

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
