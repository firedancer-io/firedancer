#ifndef HEADER_fd_src_ballet_reedsol_fd_reedsol_internal_h
#define HEADER_fd_src_ballet_reedsol_fd_reedsol_internal_h
#include "../../util/fd_util_base.h"

/* Contains function declarations for the interal encoding functions. */

void fd_reedsol_encode( ulong                 shred_sz,
                        uchar const * const * data_shred,
                        ulong                 data_shred_cnt,
                        uchar       * const * parity_shred,
                        ulong                 parity_shred_cnt );
#if FD_HAS_GFNI
void fd_reedsol_encode_32_32( ulong                 shred_sz,
                              uchar const * const * data_shred,
                              uchar       * const * parity_shred,
                              uchar       *         _scratch );
#endif

#endif /* HEADER_fd_src_ballet_reedsol_fd_reedsol_internal_h */
