#include "fd_funk.h"

#if FD_HAS_HOSTED && FD_HAS_X86

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

#endif /* FD_HAS_HOSTED && FD_HAS_X86 */
