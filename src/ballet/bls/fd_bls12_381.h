#ifndef HEADER_fd_src_ballet_bls_fd_bls12_381_h
#define HEADER_fd_src_ballet_bls_fd_bls12_381_h

#include "../fd_ballet_base.h"

/* Max size for the pairing function */
#define FD_BLS12_381_PAIRING_BATCH_SZ (8UL)

FD_PROTOTYPES_BEGIN

/* BLS12-381 Syscalls.

   The functions fd_bls12_381_*_syscall are all designed to be invoked
   by fd_vm_syscall* and they all follow the same structure.

   Parameters are unaligned byte arrays:
   - G1 point: 96 bytes (coordinates X, Y, each 48 bytes)
   - Compressed G1 point: 48 bytes
   - Scalar: 32 bytes
   - G2 point: 96*2 (coordinates X, Y, each 96 bytes)
   - Compressed G2 point: 48*2 bytes
   - GT element (pairing result): 48*12 bytes

   The big_endian parameter determines how the byte arrays are read
   and written: 1 for big endian, 0 for little endian.

   Return value is 0 on success, -1 on failure. */

/* fd_bls12_381_g1_decompress_syscall decompresses the G1 point `a`
   into `r`.
   Input and output are expected to be big endian if big_endian==1,
   or little endian if big_endian==0.
   The function returns 0 on success, -1 if `a` is not a G1 point. */
int
fd_bls12_381_g1_decompress_syscall( uchar       r[ 96 ], /* G1 point */
                                    uchar const a[ 48 ], /* Compressed G1 point */
                                    int         big_endian );

/* fd_bls12_381_g1_validate_syscall validates the G1 point `a`.
   Input is expected to be big endian if big_endian==1,
   or little endian if big_endian==0.
   The function returns 0 on success, -1 if `a` is not a G1 point. */
int
fd_bls12_381_g1_validate_syscall( uchar const a[ 96 ], /* G1 point */
                                  int         big_endian );

/* fd_bls12_381_g1_add_syscall computes r = a + b in G1.
   Inputs and output are expected to be big endian if big_endian==1,
   or little endian if big_endian==0.
   The function returns 0 on success, -1 if `a` or `b` are not on
   the curve (note: for performance reasons, we're not checking
   that `a` and `b` are in G1). */
int
fd_bls12_381_g1_add_syscall( uchar       r[ 96 ], /* G1 point */
                             uchar const a[ 96 ], /* G1 point */
                             uchar const b[ 96 ], /* G1 point */
                             int         big_endian );

/* fd_bls12_381_g1_sub_syscall computes r = a - b in G1.
   Inputs and output are expected to be big endian if big_endian==1,
   or little endian if big_endian==0.
   The function returns 0 on success, -1 if `a` or `b` are not on
   the curve (note: for performance reasons, we're not checking
   that `a` and `b` are in G1). */
int
fd_bls12_381_g1_sub_syscall( uchar       r[ 96 ], /* G1 point */
                             uchar const a[ 96 ], /* G1 point */
                             uchar const b[ 96 ], /* G1 point */
                             int         big_endian );

/* fd_bls12_381_g1_mul_syscall computes r = n * a in G1.
   Inputs and output are expected to be big endian if big_endian==1,
   or little endian if big_endian==0.
   The function returns 0 on success, -1 if `a` is not in G1. */
int
fd_bls12_381_g1_mul_syscall( uchar       r[ 96 ], /* G1 point */
                             uchar const a[ 96 ], /* G1 point */
                             uchar const n[ 32 ], /* Scalar */
                             int         big_endian );

/* fd_bls12_381_g2_decompress_syscall decompresses the G2 point `a`
   into `r`.
   Input and output are expected to be big endian if big_endian==1,
   or little endian if big_endian==0.
   The function returns 0 on success, -1 if `a` is not a G2 point. */
int
fd_bls12_381_g2_decompress_syscall( uchar       r[ 96*2 ], /* G2 point */
                                    uchar const a[ 48*2 ], /* Compressed G2 point */
                                    int         big_endian );

/* fd_bls12_381_g2_validate_syscall validates the G2 point `a`.
   Input is expected to be big endian if big_endian==1,
   or little endian if big_endian==0.
   The function returns 0 on success, -1 if `a` is not a G2 point. */
int
fd_bls12_381_g2_validate_syscall( uchar const a[ 96*2 ], /* G2 point */
                                  int         big_endian );

/* fd_bls12_381_g2_add_syscall computes r = a + b in G2.
   Inputs and output are expected to be big endian if big_endian==1,
   or little endian if big_endian==0.
   The function returns 0 on success, -1 if `a` or `b` are not on
   the curve (note: for performance reasons, we're not checking
   that `a` and `b` are in G2). */
int
fd_bls12_381_g2_add_syscall( uchar       r[ 96*2 ], /* G2 point */
                             uchar const a[ 96*2 ], /* G2 point */
                             uchar const b[ 96*2 ], /* G2 point */
                             int         big_endian );

/* fd_bls12_381_g2_sub_syscall computes r = a - b in G2.
   Inputs and output are expected to be big endian if big_endian==1,
   or little endian if big_endian==0.
   The function returns 0 on success, -1 if `a` or `b` are not on
   the curve (note: for performance reasons, we're not checking
   that `a` and `b` are in G2). */
int
fd_bls12_381_g2_sub_syscall( uchar       r[ 96*2 ], /* G2 point */
                             uchar const a[ 96*2 ], /* G2 point */
                             uchar const b[ 96*2 ], /* G2 point */
                             int         big_endian );

/* fd_bls12_381_g2_mul_syscall computes r = n * a in G2.
   Inputs and output are expected to be big endian if big_endian==1,
   or little endian if big_endian==0.
   The function returns 0 on success, -1 if `a` is not in G2. */
int
fd_bls12_381_g2_mul_syscall( uchar       r[ 96*2 ], /* G2 point */
                             uchar const a[ 96*2 ], /* G2 point */
                             uchar const n[ 32 ],   /* Scalar */
                             int         big_endian );

/* fd_bls12_381_pairing_syscall computes the pairing r = e( a[], b[] ),
   where a, b are array of size n of G1, G2 points respectively.
   Inputs and output are expected to be big endian if big_endian==1,
   or little endian if big_endian==0.
   The function returns 0 on success, -1 on failure. Failures include
   n>FD_BLS12_381_PAIRING_BATCH_SZ, any point in `a` not in G1, any
   point in `b` not in G2.
   Note: if n==0, the result of the pairing is r=1 in GT and the function
   returns 0==success. */
int
fd_bls12_381_pairing_syscall( uchar       r[ 48*12 ], /* GT element */
                              uchar const a[], /* 96*n - array of n G1 points */
                              uchar const b[], /* 96*2*n - array of n G2 points */
                              ulong const n,
                              int         big_endian );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_ballet_bls_fd_bls12_381_h */
