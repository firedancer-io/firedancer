#include "fd_reedsol.h"
#include "fd_reedsol_internal.h"
/* Include the constants in one central spot */
#define INCLUDE_CONSTANTS
#if FD_HAS_GFNI
#include "fd_reedsol_arith_gfni.h"
#elif FD_HAS_AVX
#include "fd_reedsol_arith_avx2.h"
#else
#include "fd_reedsol_arith_none.h"
#endif

void fd_reedsol_encode_fini( fd_reedsol_t * rs ) {
#if FD_HAS_GFNI
  if( FD_LIKELY( (rs->data_shred_cnt==32UL) & (rs->parity_shred_cnt==32UL ) ) )
    fd_reedsol_encode_32_32( rs->shred_sz, rs->encode.data_shred, rs->encode.parity_shred, rs->scratch );
  else
#endif
    if( FD_UNLIKELY( rs->data_shred_cnt<=16UL ) )
      fd_reedsol_encode_16( rs->shred_sz, rs->encode.data_shred, rs->data_shred_cnt, rs->encode.parity_shred, rs->parity_shred_cnt );
    else if( FD_LIKELY( rs->data_shred_cnt<=32UL ) )
      fd_reedsol_encode_32( rs->shred_sz, rs->encode.data_shred, rs->data_shred_cnt, rs->encode.parity_shred, rs->parity_shred_cnt );
    else if( FD_LIKELY( rs->data_shred_cnt<=64UL ) )
      fd_reedsol_encode_64( rs->shred_sz, rs->encode.data_shred, rs->data_shred_cnt, rs->encode.parity_shred, rs->parity_shred_cnt );
    else
      fd_reedsol_encode_128( rs->shred_sz, rs->encode.data_shred, rs->data_shred_cnt, rs->encode.parity_shred, rs->parity_shred_cnt );

  rs->data_shred_cnt   = 0UL;
  rs->parity_shred_cnt = 0UL;
}


int fd_reedsol_recover_fini( fd_reedsol_t * rs ) {
  /* How many shreds do we need to consider in order to find
     rs->data_shred_cnt un-erased? */
  ulong unerased = 0UL;
  ulong i=0UL;

  ulong data_shred_cnt   = rs->data_shred_cnt;
  ulong parity_shred_cnt = rs->parity_shred_cnt;
  rs->data_shred_cnt   = 0UL;
  rs->parity_shred_cnt = 0UL;

  for( ; i<data_shred_cnt + parity_shred_cnt; i++ ) {
    unerased += !rs->recover.erased[ i ];
    if( unerased==data_shred_cnt ) break;
  }
  if( FD_UNLIKELY( unerased != data_shred_cnt ) ) return FD_REEDSOL_ERR_INSUFFICIENT;

  /* if( FD_LIKELY( i==data_shred_cnt ) ) {
     // Common case: we have all of the data shreds
       if( FD_UNLIKELY( i<=16UL ) )
         return fd_reedsol_recover_first_16( rs->shred_sz, rs->recover.shred, data_shred_cnt, parity_shred_cnt );
       if( FD_LIKELY( i<=32UL ) )
         return fd_reedsol_recover_first_32( rs->shred_sz, rs->recover.shred, data_shred_cnt, parity_shred_cnt );
       if( FD_LIKELY( i<=64UL ) )
         return fd_reedsol_recover_first_64( rs->shred_sz, rs->recover.shred, data_shred_cnt, parity_shred_cnt );
       return fd_reedsol_recover_first_128(  rs->shred_sz, rs->recover.shred, data_shred_cnt, parity_shred_cnt );
     } */

  if( FD_UNLIKELY( i<16UL ) )
    return fd_reedsol_recover_var_16( rs->shred_sz, rs->recover.shred, data_shred_cnt, parity_shred_cnt, rs->recover.erased );
  if( FD_LIKELY(   i<32UL ) )
    return fd_reedsol_recover_var_32( rs->shred_sz, rs->recover.shred, data_shred_cnt, parity_shred_cnt, rs->recover.erased );
  if( FD_LIKELY(   i<64UL ) )
    return fd_reedsol_recover_var_64( rs->shred_sz, rs->recover.shred, data_shred_cnt, parity_shred_cnt, rs->recover.erased );
  if( FD_LIKELY(   i<128UL ) )
    return fd_reedsol_recover_var_128( rs->shred_sz, rs->recover.shred, data_shred_cnt, parity_shred_cnt, rs->recover.erased );
  return fd_reedsol_recover_var_256( rs->shred_sz, rs->recover.shred, data_shred_cnt, parity_shred_cnt, rs->recover.erased );
}
