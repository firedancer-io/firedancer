#include "fd_reedsol_private.h"
#include "../../util/sanitize/fd_msan.h"

#define FD_REEDSOL_32_32_PREFETCH_THRESH (896UL)

/* Include the constants in one central spot */

#if FD_REEDSOL_ARITH_IMPL==0
FD_IMPORT_BINARY( fd_reedsol_arith_consts_generic_mul, "src/ballet/reedsol/constants/generic_constants.bin" );
#elif FD_REEDSOL_ARITH_IMPL==1
FD_IMPORT_BINARY( fd_reedsol_arith_consts_avx_mul, "src/ballet/reedsol/constants/avx2_constants.bin" );
#elif FD_REEDSOL_ARITH_IMPL==4
FD_IMPORT_BINARY( fd_reedsol_arith_consts_neon_mul, "src/ballet/reedsol/constants/neon_constants.bin" );
#else
FD_IMPORT_BINARY( fd_reedsol_arith_consts_gfni_mul, "src/ballet/reedsol/constants/gfni_constants.bin" );
#if FD_REEDSOL_ARITH_IMPL==3
FD_IMPORT_BINARY( fd_reedsol_arith_consts_gfni_mul_avx512, "src/ballet/reedsol/constants/gfni_constants_avx512.bin" );
#endif
#endif

void
fd_reedsol_encode_fini( fd_reedsol_t * rs ) {

  # if FD_REEDSOL_ARITH_IMPL==3
  if( FD_LIKELY( (rs->data_shred_cnt==32UL) & (rs->parity_shred_cnt==32UL ) ) ) {
    if( FD_LIKELY( rs->shred_sz>=FD_REEDSOL_32_32_PREFETCH_THRESH ) )
      fd_reedsol_private_encode_32_32_zmm_prefetch( rs->shred_sz, rs->encode.data_shred, rs->encode.parity_shred, rs->scratch );
    else if( FD_LIKELY( rs->shred_sz>=64UL ) )
      fd_reedsol_private_encode_32_32_zmm( rs->shred_sz, rs->encode.data_shred, rs->encode.parity_shred, rs->scratch );
    else
      fd_reedsol_private_encode_32_32( rs->shred_sz, rs->encode.data_shred, rs->encode.parity_shred, rs->scratch );
    for( ulong i=0UL; i<rs->parity_shred_cnt; i++ ) fd_msan_unpoison( rs->encode.parity_shred[ i ], rs->shred_sz );
  } else
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

# if FD_REEDSOL_ARITH_IMPL==3
  if( FD_LIKELY( (data_shred_cnt==32UL) & (parity_shred_cnt==32UL) ) ) {
    ulong data_erased_cnt   = 0UL;
    ulong parity_erased_cnt = 0UL;
    for( ulong j=0UL; j<32UL; j++ ) {
      data_erased_cnt   += rs->recover.erased[      j ];
      parity_erased_cnt += rs->recover.erased[ 32UL+j ];
    }

    if( FD_LIKELY( (!data_erased_cnt) & (parity_erased_cnt==32UL) ) ) {
      if( FD_LIKELY( rs->shred_sz>=FD_REEDSOL_32_32_PREFETCH_THRESH ) )
        fd_reedsol_private_encode_32_32_zmm_prefetch( rs->shred_sz, (uchar const * const *)rs->recover.shred, rs->recover.shred+32UL, rs->scratch );
      else if( FD_LIKELY( rs->shred_sz>=64UL ) )
        fd_reedsol_private_encode_32_32_zmm( rs->shred_sz, (uchar const * const *)rs->recover.shred, rs->recover.shred+32UL, rs->scratch );
      else
        fd_reedsol_private_encode_32_32( rs->shred_sz, (uchar const * const *)rs->recover.shred, rs->recover.shred+32UL, rs->scratch );
      for( ulong j=0UL; j<32UL; j++ ) fd_msan_unpoison( rs->recover.shred[ 32UL+j ], rs->shred_sz );
      return FD_REEDSOL_SUCCESS;
    }

    if( FD_LIKELY( !(data_erased_cnt | parity_erased_cnt) ) ) {
      int corrupt;
      if( FD_LIKELY( rs->shred_sz>=FD_REEDSOL_32_32_PREFETCH_THRESH ) )
        corrupt = fd_reedsol_private_verify_32_32_zmm_prefetch( rs->shred_sz, (uchar const * const *)rs->recover.shred, rs->recover.shred+32UL, rs->scratch );
      else if( FD_LIKELY( rs->shred_sz>=64UL ) )
        corrupt = fd_reedsol_private_verify_32_32_zmm( rs->shred_sz, (uchar const * const *)rs->recover.shred, rs->recover.shred+32UL, rs->scratch );
      else if( FD_LIKELY( rs->shred_sz>32UL ) )
        corrupt = fd_reedsol_private_verify_32_32_zmm_mask( rs->shred_sz, (uchar const * const *)rs->recover.shred, rs->recover.shred+32UL, rs->scratch );
      else
        corrupt = fd_reedsol_private_verify_32_32( rs->shred_sz, (uchar const * const *)rs->recover.shred, rs->recover.shred+32UL, rs->scratch );
      return fd_int_if( corrupt, FD_REEDSOL_ERR_CORRUPT, FD_REEDSOL_SUCCESS );
    }

    if( FD_LIKELY( !data_erased_cnt ) ) {
      int corrupt;
      if( FD_LIKELY( rs->shred_sz>=FD_REEDSOL_32_32_PREFETCH_THRESH ) )
        corrupt = fd_reedsol_private_recover_first_32_32_zmm_prefetch( rs->shred_sz, (uchar const * const *)rs->recover.shred, rs->recover.shred+32UL, rs->scratch, rs->recover.erased+32UL );
      else if( FD_LIKELY( rs->shred_sz>=64UL ) )
        corrupt = fd_reedsol_private_recover_first_32_32_zmm( rs->shred_sz, (uchar const * const *)rs->recover.shred, rs->recover.shred+32UL, rs->scratch, rs->recover.erased+32UL );
      else
        corrupt = fd_reedsol_private_recover_first_32_32( rs->shred_sz, (uchar const * const *)rs->recover.shred, rs->recover.shred+32UL, rs->scratch, rs->recover.erased+32UL );
      for( ulong j=0UL; j<32UL; j++ ) if( rs->recover.erased[ 32UL+j ] ) fd_msan_unpoison( rs->recover.shred[ 32UL+j ], rs->shred_sz );
      return fd_int_if( corrupt, FD_REEDSOL_ERR_CORRUPT, FD_REEDSOL_SUCCESS );
    }

    if( FD_UNLIKELY( (data_erased_cnt==32UL) & (!parity_erased_cnt) ) ) {
      if( FD_LIKELY( rs->shred_sz>=FD_REEDSOL_32_32_PREFETCH_THRESH ) )
        fd_reedsol_private_recover_data_32_32_zmm_prefetch( rs->shred_sz, (uchar const * const *)(rs->recover.shred+32UL), rs->recover.shred, rs->scratch );
      else if( FD_LIKELY( rs->shred_sz>=64UL ) )
        fd_reedsol_private_recover_data_32_32_zmm( rs->shred_sz, (uchar const * const *)(rs->recover.shred+32UL), rs->recover.shred, rs->scratch );
      else
        fd_reedsol_private_recover_data_32_32( rs->shred_sz, (uchar const * const *)(rs->recover.shred+32UL), rs->recover.shred, rs->scratch );
      for( ulong j=0UL; j<32UL; j++ ) fd_msan_unpoison( rs->recover.shred[ j ], rs->shred_sz );
      return FD_REEDSOL_SUCCESS;
    }
  }
# endif

  if( FD_UNLIKELY( i<16UL ) ) {
#   if FD_REEDSOL_ARITH_IMPL==3
    if( FD_LIKELY( rs->shred_sz>=64UL ) )
      return fd_reedsol_private_recover_var_16_zmm( rs->shred_sz, rs->recover.shred, data_shred_cnt, parity_shred_cnt, rs->recover.erased );
#   endif
    return fd_reedsol_private_recover_var_16( rs->shred_sz, rs->recover.shred, data_shred_cnt, parity_shred_cnt, rs->recover.erased );
  }
  if( FD_LIKELY(   i<32UL ) ) {
#   if FD_REEDSOL_ARITH_IMPL==3
    if( FD_LIKELY( rs->shred_sz>=64UL ) )
      return fd_reedsol_private_recover_var_32_zmm( rs->shred_sz, rs->recover.shred, data_shred_cnt, parity_shred_cnt, rs->recover.erased );
#   endif
    return fd_reedsol_private_recover_var_32( rs->shred_sz, rs->recover.shred, data_shred_cnt, parity_shred_cnt, rs->recover.erased );
  }
  if( FD_LIKELY(   i<64UL ) ) {
#   if FD_REEDSOL_ARITH_IMPL==3
    if( FD_LIKELY( rs->shred_sz>=64UL ) )
      return fd_reedsol_private_recover_var_64_zmm( rs->shred_sz, rs->recover.shred, data_shred_cnt, parity_shred_cnt, rs->recover.erased );
#   endif
    return fd_reedsol_private_recover_var_64( rs->shred_sz, rs->recover.shred, data_shred_cnt, parity_shred_cnt, rs->recover.erased );
  }
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
