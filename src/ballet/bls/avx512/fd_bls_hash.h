#ifndef HEADER_fd_src_ballet_bls_avx512_fd_bls_hash_h
#define HEADER_fd_src_ballet_bls_avx512_fd_bls_hash_h

#include "fd_bls_miller.h"

FD_PROTOTYPES_BEGIN
void fd_bls_hash_to_g2( uchar const * msg, ulong msg_sz,
                                uchar const * dst, ulong dst_sz, fd_bls_hash_t * out );
int fd_bls_fp2_sqrt_rns( fd_bls_fp2_t * out, fd_bls_fp2_t const * x );
int fd_bls_g2_decompress_rns( fd_bls_fp2_t * ox, fd_bls_fp2_t * oy,
                              ulong const x_re[6], ulong const x_im[6], int sign_bit );
FD_PROTOTYPES_END
#endif
