#include "fd_reedsol_private.h"

/* Include the constants in one central spot */

#if FD_REEDSOL_ARITH_IMPL==0
FD_IMPORT_BINARY( fd_reedsol_arith_consts_generic_mul, "src/ballet/reedsol/constants/generic_constants.bin" );
#elif FD_REEDSOL_ARITH_IMPL==1
FD_IMPORT_BINARY( fd_reedsol_arith_consts_avx_mul, "src/ballet/reedsol/constants/avx2_constants.bin" );
#else
FD_IMPORT_BINARY( fd_reedsol_arith_consts_gfni_mul, "src/ballet/reedsol/constants/gfni_constants.bin" );
#endif

void
fd_reedsol_encode_fini( fd_reedsol_t * rs ) {

# if FD_REEDSOL_ARITH_IMPL==2
  if( FD_LIKELY( (rs->data_shred_cnt==32UL) & (rs->parity_shred_cnt==32UL ) ) )
    fd_reedsol_private_encode_32_32( rs->shred_sz, rs->encode.data_shred, rs->encode.parity_shred, rs->scratch );
  else
# endif
  if( FD_UNLIKELY( rs->data_shred_cnt<=16UL ) )
    fd_reedsol_private_encode_16 ( rs->shred_sz, rs->encode.data_shred, rs->data_shred_cnt, rs->encode.parity_shred, rs->parity_shred_cnt );
  else if( FD_LIKELY( rs->data_shred_cnt<=32UL ) )
    fd_reedsol_private_encode_32 ( rs->shred_sz, rs->encode.data_shred, rs->data_shred_cnt, rs->encode.parity_shred, rs->parity_shred_cnt );
  else if( FD_LIKELY( rs->data_shred_cnt<=64UL ) )
    fd_reedsol_private_encode_64 ( rs->shred_sz, rs->encode.data_shred, rs->data_shred_cnt, rs->encode.parity_shred, rs->parity_shred_cnt );
  else
      fd_reedsol_private_encode_128( rs->shred_sz, rs->encode.data_shred, rs->data_shred_cnt, rs->encode.parity_shred, rs->parity_shred_cnt );

  rs->data_shred_cnt   = 0UL;
  rs->parity_shred_cnt = 0UL;
}

int
fd_reedsol_recover_fini( fd_reedsol_t * rs ) {

  ulong data_shred_cnt   = rs->data_shred_cnt;
  ulong parity_shred_cnt = rs->parity_shred_cnt;

  rs->data_shred_cnt   = 0UL;
  rs->parity_shred_cnt = 0UL;

  /* How many shreds do we need to consider in order to find
     rs->data_shred_cnt un-erased? */

  ulong unerased = 0UL;
  ulong i        = 0UL;
  for( ; i<data_shred_cnt + parity_shred_cnt; i++ ) {
    unerased += !rs->recover.erased[ i ];
    if( unerased==data_shred_cnt ) break;
  }
  if( FD_UNLIKELY( unerased!=data_shred_cnt ) ) return FD_REEDSOL_ERR_PARTIAL;

# if 0 /* TODO: Add first variant for slightly more performance */
  if( FD_LIKELY( i==data_shred_cnt ) ) {
    // Common case: we have all of the data shreds
    if( FD_UNLIKELY( i<=16UL ) )
      return fd_reedsol_private_recover_first_16( rs->shred_sz, rs->recover.shred, data_shred_cnt, parity_shred_cnt );
    if( FD_LIKELY( i<=32UL ) )
      return fd_reedsol_private_recover_first_32( rs->shred_sz, rs->recover.shred, data_shred_cnt, parity_shred_cnt );
    if( FD_LIKELY( i<=64UL ) )
      return fd_reedsol_private_recover_first_64( rs->shred_sz, rs->recover.shred, data_shred_cnt, parity_shred_cnt );
    return fd_reedsol_private_recover_first_128(  rs->shred_sz, rs->recover.shred, data_shred_cnt, parity_shred_cnt );
  }
# endif

  if( FD_UNLIKELY( i<16UL ) )
    return fd_reedsol_private_recover_var_16( rs->shred_sz, rs->recover.shred, data_shred_cnt, parity_shred_cnt, rs->recover.erased );
  if( FD_LIKELY(   i<32UL ) )
    return fd_reedsol_private_recover_var_32( rs->shred_sz, rs->recover.shred, data_shred_cnt, parity_shred_cnt, rs->recover.erased );
  if( FD_LIKELY(   i<64UL ) )
    return fd_reedsol_private_recover_var_64( rs->shred_sz, rs->recover.shred, data_shred_cnt, parity_shred_cnt, rs->recover.erased );
  if( FD_LIKELY(   i<128UL ) )
    return fd_reedsol_private_recover_var_128( rs->shred_sz, rs->recover.shred, data_shred_cnt, parity_shred_cnt, rs->recover.erased );

  return fd_reedsol_private_recover_var_256( rs->shred_sz, rs->recover.shred, data_shred_cnt, parity_shred_cnt, rs->recover.erased );
}

char const *
fd_reedsol_strerror( int err ) {
  switch( err ) {
  case FD_REEDSOL_SUCCESS:     return "success";
  case FD_REEDSOL_ERR_CORRUPT: return "corrupt";
  case FD_REEDSOL_ERR_PARTIAL: return "partial";
  default: break;
  }
  return "unknown";
}
