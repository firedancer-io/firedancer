extern "C" {
#include "fd_bn254.h"
}

#include <libff/algebra/curves/alt_bn128/alt_bn128_fields.hpp>
#include <libff/algebra/curves/alt_bn128/alt_bn128_g1.hpp>
#include <libff/algebra/curves/alt_bn128/alt_bn128_g2.hpp>
#include <libff/algebra/curves/alt_bn128/alt_bn128_init.hpp>
#include <libff/algebra/curves/alt_bn128/alt_bn128_pairing.hpp>
#include <libff/algebra/curves/alt_bn128/alt_bn128_pp.hpp>

#define FD_BN254_FIELD_FOOTPRINT 32

static bool didinit = false;

void
fd_bn254_g1_compress( fd_bn254_point_g1 const * in, fd_bn254_point_g1_compressed * out ) {
  /* Just pick off the X coordinate */
  fd_memcpy(out->v, in->v, FD_BN254_FIELD_FOOTPRINT);
}

static void
fd_bn254_Fq_sol_to_native(uchar const * sol, libff::alt_bn128_Fq * X) {
  FD_STATIC_ASSERT( sizeof(X->mont_repr.data) == FD_BN254_FIELD_FOOTPRINT, fd_ballet );
  /* Convert big-endian to little-endian while copying */
  uchar * t = (uchar *)X->mont_repr.data;
  for (ulong i = 0; i < FD_BN254_FIELD_FOOTPRINT; ++i)
    t[FD_BN254_FIELD_FOOTPRINT-1U-i] = sol[i];
}

static void
fd_bn254_Fq_native_to_sol(libff::alt_bn128_Fq const * X, uchar * sol) {
  FD_STATIC_ASSERT( sizeof(X->mont_repr.data) == FD_BN254_FIELD_FOOTPRINT, fd_ballet );
  /* Convert little-endian to big-endian while copying */
  const uchar * t = (const uchar *)X->mont_repr.data;
  for (ulong i = 0; i < FD_BN254_FIELD_FOOTPRINT; ++i)
    sol[i] = t[FD_BN254_FIELD_FOOTPRINT-1U-i];
}

void
fd_bn254_g1_decompress( fd_bn254_point_g1_compressed const * in, fd_bn254_point_g1 * out ) {
  if (!didinit) {
    libff::init_alt_bn128_fields();
    didinit = true;
  }
  /* Recover Y coordinate from X */
  libff::alt_bn128_Fq X;
  fd_bn254_Fq_sol_to_native(in->v, &X);
  libff::alt_bn128_Fq X2(X);
  X2.squared();
  libff::alt_bn128_Fq X3_plus_b = X*X2 + libff::alt_bn128_coeff_b;
  libff::alt_bn128_Fq Y(X3_plus_b.sqrt());
  libff::alt_bn128_Fq negY = -Y;
  if (negY.mont_repr < Y.mont_repr) Y = negY;
  fd_bn254_Fq_native_to_sol(&X, out->v);
  fd_bn254_Fq_native_to_sol(&Y, out->v + FD_BN254_FIELD_FOOTPRINT);
}

void
fd_bn254_g2_compress( fd_bn254_point_g2 const * in, fd_bn254_point_g2_compressed * out ) {
  /* Just pick off the X coordinate */
  fd_memcpy(out->v, in->v, FD_BN254_G2_COMPRESSED_FOOTPRINT);
}

static void
fd_bn254_Fq2_sol_to_native(uchar const * sol, libff::alt_bn128_Fq2 * X) {
  fd_bn254_Fq_sol_to_native(sol, &X->c0);
  fd_bn254_Fq_sol_to_native(sol + FD_BN254_G2_COMPRESSED_FOOTPRINT, &X->c1);
}

static void
fd_bn254_Fq2_native_to_sol(libff::alt_bn128_Fq2 const * X, uchar * sol) {
  fd_bn254_Fq_native_to_sol(&X->c0, sol);
  fd_bn254_Fq_native_to_sol(&X->c1, sol + FD_BN254_G2_COMPRESSED_FOOTPRINT);
}

void
fd_bn254_g2_decompress( fd_bn254_point_g2_compressed const * in, fd_bn254_point_g2 * out ) {
  if (!didinit) {
    libff::init_alt_bn128_fields();
    didinit = true;
  }
  /* Recover Y coordinate from X */
  libff::alt_bn128_Fq2 X;
  fd_bn254_Fq2_sol_to_native(in->v, &X);
  libff::alt_bn128_Fq2 X2(X);
  X2.squared();
  libff::alt_bn128_Fq2 X3_plus_b = X*X2 + libff::alt_bn128_twist_coeff_b;
  libff::alt_bn128_Fq2 Y(X3_plus_b.sqrt());
  libff::alt_bn128_Fq2 negY = -Y;
  if (negY.c0.mont_repr < Y.c0.mont_repr) Y = negY;
  fd_bn254_Fq2_native_to_sol(&X, out->v);
  fd_bn254_Fq2_native_to_sol(&Y, out->v + 2U*FD_BN254_FIELD_FOOTPRINT);
}
