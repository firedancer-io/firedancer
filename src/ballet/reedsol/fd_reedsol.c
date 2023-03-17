#include "fd_reedsol.h"
#include "fd_reedsol_internal.h"

void fd_reedsol_encode_fini( fd_reedsol_t * rs ) {
#if FD_HAS_GFNI
  if( FD_LIKELY( (rs->data_shred_cnt==32UL) & (rs->parity_shred_cnt==32UL ) ) )
    fd_reedsol_encode_32_32( rs->shred_sz, (uchar const * *)rs->data_shred, rs->parity_shred, rs->scratch );
  else
    fd_reedsol_encode( rs->shred_sz, (uchar const * *)rs->data_shred, rs->data_shred_cnt, rs->parity_shred, rs->parity_shred_cnt );
#else
  fd_reedsol_encode( rs->shred_sz, (uchar const * *)rs->data_shred, rs->data_shred_cnt, rs->parity_shred, rs->parity_shred_cnt );
#endif

  rs->data_shred_cnt = 0UL;
  rs->parity_shred_cnt = 0UL;
}
