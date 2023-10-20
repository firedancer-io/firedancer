#ifndef HEADER_fd_src_ballet_bn254_fd_bn254_h
#define HEADER_fd_src_ballet_bn254_fd_bn254_h

/* fd_bn254 implements utility functions for the bn254 (alt_bn128) curve. It currently wraps libff. */

#include "../fd_ballet_base.h"

FD_PROTOTYPES_BEGIN

#define FD_BN254_ALIGN                   (16UL)
#define FD_BN254_G1_FOOTPRINT            (64UL)
#define FD_BN254_G2_FOOTPRINT            (128UL)
#define FD_BN254_G1_COMPRESSED_FOOTPRINT (32UL)
#define FD_BN254_G2_COMPRESSED_FOOTPRINT (64UL)
#define FD_BN254_BIGINT_FOOTPRINT        (32UL)

struct __attribute__((aligned(FD_BN254_ALIGN))) fd_bn254_point_g1 {
  uchar v[ FD_BN254_G1_FOOTPRINT ];
};
typedef struct fd_bn254_point_g1 fd_bn254_point_g1_t;

struct __attribute__((aligned(FD_BN254_ALIGN))) fd_bn254_point_g2 {
  uchar v[ FD_BN254_G2_FOOTPRINT ];
};
typedef struct fd_bn254_point_g2 fd_bn254_point_g2_t;

struct __attribute__((aligned(FD_BN254_ALIGN))) fd_bn254_point_g1_compressed {
  uchar v[ FD_BN254_G1_COMPRESSED_FOOTPRINT ];
};
typedef struct fd_bn254_point_g1_compressed fd_bn254_point_g1_compressed_t;

struct __attribute__((aligned(FD_BN254_ALIGN))) fd_bn254_point_g2_compressed {
  uchar v[ FD_BN254_G2_COMPRESSED_FOOTPRINT ];
};
typedef struct fd_bn254_point_g2_compressed fd_bn254_point_g2_compressed_t;

struct __attribute__((aligned(FD_BN254_ALIGN))) fd_bn254_bigint {
  uchar v[ FD_BN254_BIGINT_FOOTPRINT ];
};
typedef struct fd_bn254_bigint fd_bn254_bigint_t;

/* Return true if the point is on the curve */
int fd_bn254_g1_check( fd_bn254_point_g1_t const * p );

/* Extract the X coordinate from the point */
void fd_bn254_g1_compress( fd_bn254_point_g1_t const * in, fd_bn254_point_g1_compressed_t * out );

/* Recover the X,Y pair from X */
void fd_bn254_g1_decompress( fd_bn254_point_g1_compressed_t const * in, fd_bn254_point_g1_t * out );

/* Return true if the point is on the curve */
int fd_bn254_g2_check( fd_bn254_point_g2_t const * p );

/* Extract the X coordinate from the point */
void fd_bn254_g2_compress( fd_bn254_point_g2_t const * in, fd_bn254_point_g2_compressed_t * out );

/* Recover the X,Y pair from X */
void fd_bn254_g2_decompress( fd_bn254_point_g2_compressed_t const * in, fd_bn254_point_g2_t * out );

/* Add two points */
void fd_bn254_g1_add( fd_bn254_point_g1_t const * x, fd_bn254_point_g1_t const * y, fd_bn254_point_g1_t * z );

/* Multiply a point by an integer */
void fd_bn254_g1_mult( fd_bn254_point_g1_t const * x, fd_bn254_bigint_t const * y, fd_bn254_point_g1_t * z );

/* Return true if the points are a pairing */
int fd_bn254_pairing( fd_bn254_point_g1_t const * x, fd_bn254_point_g2_t const * y );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_ballet_bn254_fd_bn254_h */
