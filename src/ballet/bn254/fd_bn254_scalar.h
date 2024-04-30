#ifndef HEADER_fd_src_ballet_bn254_fd_bn254_scalar_h
#define HEADER_fd_src_ballet_bn254_fd_bn254_scalar_h

/* Implementation of the BN254 scalar field, based on fiat-crypto.

   This covers 2 main use cases:
   - scalar validation, used e.g. in BN254 point scalar mul
   - scalar arithmetic, used e.g. to compute Poseidon hash

   The primary consumer is Firedancer VM (Solana syscalls).
   Therefore, input is little endian and already aligned. */

#include "../fd_ballet_base.h"
#include "../bigint/fd_uint256.h"
#include "../fiat-crypto/bn254_scalar_64.c"

/* The implementation is based on fiat-crypto.
   Unfortunately mul is dramatically slow on gcc, so we reimplemented
   it in ballet/bigint/uint256_mul.h, based on uint128.
   When uint128 is not available we fall back on fiat-crypto. */
#define USE_FIAT_CRYPTO_MUL !FD_HAS_INT128

/* fd_bn254_scalar represents a scalar as a buffer of 32 bytes,
   or equivalently (on little endian platforms) an array of 4 ulong. */
typedef fd_uint256_t fd_bn254_scalar_t;

/* const r, used to validate a scalar field element.
   NOT Montgomery.
   0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001 */
static const fd_bn254_scalar_t fd_bn254_const_r[1] = {{{
  0x43e1f593f0000001, 0x2833e84879b97091, 0xb85045b68181585d, 0x30644e72e131a029,
}}};

/* const 1/r for CIOS mul */
static const ulong fd_bn254_const_r_inv = 0xC2E1F593EFFFFFFFUL;

FD_PROTOTYPES_BEGIN

/* fd_bn254_scalar_validate validates that the input scalar s
   is between 0 and r-1, included.
   This function works on 32-byte input buffer with no memory
   copies (assuming both platform and input are little endian). */
static inline int
fd_bn254_scalar_validate( fd_bn254_scalar_t const * s ) {
  return fd_uint256_cmp( s, fd_bn254_const_r ) < 0;
}

static inline fd_bn254_scalar_t *
fd_bn254_scalar_from_mont( fd_bn254_scalar_t *       r,
                           fd_bn254_scalar_t const * a ) {
  fiat_bn254_scalar_from_montgomery( r->limbs, a->limbs );
  return r;
}

static inline fd_bn254_scalar_t *
fd_bn254_scalar_to_mont( fd_bn254_scalar_t *       r,
                         fd_bn254_scalar_t const * a ) {
  fiat_bn254_scalar_to_montgomery( r->limbs, a->limbs );
  return r;
}

static inline fd_bn254_scalar_t *
fd_bn254_scalar_add( fd_bn254_scalar_t *       r,
                     fd_bn254_scalar_t const * a,
                     fd_bn254_scalar_t const * b ) {
  fiat_bn254_scalar_add( r->limbs, a->limbs, b->limbs );
  return r;
}

#if USE_FIAT_CRYPTO_MUL

static inline fd_bn254_scalar_t *
fd_bn254_scalar_mul( fd_bn254_scalar_t *       r,
                     fd_bn254_scalar_t const * a,
                     fd_bn254_scalar_t const * b ) {
  fiat_bn254_scalar_mul( r->limbs, a->limbs, b->limbs );
  return r;
}

static inline fd_bn254_scalar_t *
fd_bn254_scalar_sqr( fd_bn254_scalar_t *       r,
                     fd_bn254_scalar_t const * a ) {
  fiat_bn254_scalar_square( r->limbs, a->limbs );
  return r;
}

#else

FD_UINT256_FP_MUL_IMPL(fd_bn254_scalar, fd_bn254_const_r, fd_bn254_const_r_inv)

static inline fd_bn254_scalar_t *
fd_bn254_scalar_sqr( fd_bn254_scalar_t *       r,
                     fd_bn254_scalar_t const * a ) {
  return fd_bn254_scalar_mul( r, a, a );
}

#endif

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_ballet_bn254_fd_bn254_scalar_h */
