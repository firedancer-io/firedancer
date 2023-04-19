#ifndef HEADER_fd_src_ballet_reedsol_fd_reedsol_internal_h
#define HEADER_fd_src_ballet_reedsol_fd_reedsol_internal_h
#include "../../util/fd_util_base.h"

/* Contains function declarations for the interal encoding functions. */

/* FALLTHRU: Tells the compiler that falling through to the next case
   of the switch statement is intentional and not a bug.  When brutality
   is turned on, this must be used.  Clang an GCC differ on what
   annotations they accept, but this works for both. */
#define FALLTHRU __attribute__((fallthrough));

/* fd_reedsol_encode_{n} requires that data_shred_cnt <= n */
void fd_reedsol_encode_16(  ulong                 shred_sz,
                            uchar const * const * data_shred,
                            ulong                 data_shred_cnt,
                            uchar       * const * parity_shred,
                            ulong                 parity_shred_cnt );
void fd_reedsol_encode_32(  ulong                 shred_sz,
                            uchar const * const * data_shred,
                            ulong                 data_shred_cnt,
                            uchar       * const * parity_shred,
                            ulong                 parity_shred_cnt );
void fd_reedsol_encode_64(  ulong                 shred_sz,
                            uchar const * const * data_shred,
                            ulong                 data_shred_cnt,
                            uchar       * const * parity_shred,
                            ulong                 parity_shred_cnt );
void fd_reedsol_encode_128( ulong                 shred_sz,
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
