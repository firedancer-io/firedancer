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
    fd_reedsol_encode_32_32( rs->shred_sz, (uchar const * *)rs->data_shred, rs->parity_shred, rs->scratch );
  else
#endif
    if( FD_UNLIKELY( rs->data_shred_cnt<=16UL ) )
      fd_reedsol_encode_16( rs->shred_sz, (uchar const * *)rs->data_shred, rs->data_shred_cnt, rs->parity_shred, rs->parity_shred_cnt );
    else if( FD_LIKELY( rs->data_shred_cnt<=32UL ) )
      fd_reedsol_encode_32( rs->shred_sz, (uchar const * *)rs->data_shred, rs->data_shred_cnt, rs->parity_shred, rs->parity_shred_cnt );
    else if( FD_LIKELY( rs->data_shred_cnt<=64UL ) )
      fd_reedsol_encode_64( rs->shred_sz, (uchar const * *)rs->data_shred, rs->data_shred_cnt, rs->parity_shred, rs->parity_shred_cnt );
    else
      fd_reedsol_encode_128( rs->shred_sz, (uchar const * *)rs->data_shred, rs->data_shred_cnt, rs->parity_shred, rs->parity_shred_cnt );

  rs->data_shred_cnt = 0UL;
  rs->parity_shred_cnt = 0UL;
}
