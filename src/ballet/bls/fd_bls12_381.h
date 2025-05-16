#ifndef HEADER_fd_src_ballet_bls_fd_bls12_381_h
#define HEADER_fd_src_ballet_bls_fd_bls12_381_h

#include "../fd_ballet_base.h"

#define FD_BLS_SUCCESS ( 0) /* Operation was successful */
#define FD_BLS_FAILURE (-1) /* Operation failed */

FD_PROTOTYPES_BEGIN

int
fd_bls12_381_g1_add_syscall( uchar       r[48],
                             uchar const p[48],
                             uchar const q[48] );


uchar * FD_FN_SENSITIVE
fd_bls12_381_public_from_private( uchar       public_key [ 96 ],
                                  uchar const private_key[ 32 ] );

uchar * FD_FN_SENSITIVE
fd_bls12_381_sign( uchar         sig[ 192 ],
                   uchar const   msg[], /* msg_sz */
                   ulong         msg_sz,
                   /* uchar const   public_key[ 96 ], */
                   uchar const   private_key[ 32 ] );

int
fd_bls12_381_verify( uchar const   msg[], /* msg_sz */
                     ulong         msg_sz,
                     uchar const   sig[ 192 ],
                     uchar const   public_key[ 96 ] );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_ballet_bls_fd_bls12_381_h */
