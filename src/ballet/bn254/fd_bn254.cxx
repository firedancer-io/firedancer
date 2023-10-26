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

static void
fd_bn254_Fq_sol_to_libff(uchar const * sol, libff::alt_bn128_Fq * X) {
  libff::bigint<libff::alt_bn128_r_limbs> bi;
  FD_STATIC_ASSERT( sizeof(bi.data) == FD_BN254_FIELD_FOOTPRINT, fd_ballet );
  /* Convert big-endian to little-endian while copying */
  uchar * t = (uchar *)(bi.data);
  for (ulong i = 0; i < FD_BN254_FIELD_FOOTPRINT; ++i)
    t[FD_BN254_FIELD_FOOTPRINT-1U-i] = sol[i];
  t[FD_BN254_FIELD_FOOTPRINT-1U] &= (uchar)(~((1<<6) | (1<<7)));
  new (X) libff::alt_bn128_Fq(bi);
}

static void
fd_bn254_Fq_libff_to_sol(libff::alt_bn128_Fq const * X, uchar * sol) {
  libff::bigint<libff::alt_bn128_r_limbs> bi;
  FD_STATIC_ASSERT( sizeof(bi.data) == FD_BN254_FIELD_FOOTPRINT, fd_ballet );
  bi = X->as_bigint();
  /* Convert little-endian to big-endian while copying */
  const uchar * t = (const uchar *)bi.data;
  for (ulong i = 0; i < FD_BN254_FIELD_FOOTPRINT; ++i)
    sol[i] = t[FD_BN254_FIELD_FOOTPRINT-1U-i];
}

static void
fd_bn254_Fq2_sol_to_libff(uchar const * sol, libff::alt_bn128_Fq2 * X) {
  fd_bn254_Fq_sol_to_libff(sol, &X->c1);
  fd_bn254_Fq_sol_to_libff(sol + FD_BN254_FIELD_FOOTPRINT, &X->c0);
}

static void
fd_bn254_Fq2_libff_to_sol(libff::alt_bn128_Fq2 const * X, uchar * sol) {
  fd_bn254_Fq_libff_to_sol(&X->c1, sol);
  fd_bn254_Fq_libff_to_sol(&X->c0, sol + FD_BN254_FIELD_FOOTPRINT);
}

static libff::alt_bn128_G1
fd_bn254_g1_sol_to_libff( fd_bn254_point_g1_t const * p ) {
  libff::alt_bn128_Fq X;
  fd_bn254_Fq_sol_to_libff(p->v, &X);
  libff::alt_bn128_Fq Y;
  fd_bn254_Fq_sol_to_libff(p->v + FD_BN254_FIELD_FOOTPRINT, &Y);
  return libff::alt_bn128_G1(X, Y, libff::alt_bn128_Fq::one());
}

static void
fd_bn254_g1_libff_to_sol( libff::alt_bn128_G1 g, fd_bn254_point_g1_t * p ) {
  g.to_affine_coordinates();
  fd_bn254_Fq_libff_to_sol(&g.X, p->v);
  fd_bn254_Fq_libff_to_sol(&g.Y, p->v + FD_BN254_FIELD_FOOTPRINT);
}

static libff::alt_bn128_G2
fd_bn254_g2_sol_to_libff( fd_bn254_point_g2_t const * p ) {
  libff::alt_bn128_Fq2 X;
  fd_bn254_Fq2_sol_to_libff(p->v, &X);
  libff::alt_bn128_Fq2 Y;
  fd_bn254_Fq2_sol_to_libff(p->v + 2U*FD_BN254_FIELD_FOOTPRINT, &Y);
  return libff::alt_bn128_G2(X, Y, libff::alt_bn128_Fq2::one());
}

/*
static void
fd_bn254_g2_libff_to_sol( libff::alt_bn128_G2 g, fd_bn254_point_g2_t * p ) {
  g.to_affine_coordinates();
  fd_bn254_Fq2_libff_to_sol(&g.X, p->v);
  fd_bn254_Fq2_libff_to_sol(&g.Y, p->v + 2U*FD_BN254_FIELD_FOOTPRINT);
}
*/

static libff::bigint<libff::alt_bn128_r_limbs>
fd_bn254_bigint_sol_to_libff(fd_bn254_bigint_t const * sol) {
  libff::bigint<libff::alt_bn128_r_limbs> bi;
  FD_STATIC_ASSERT( sizeof(bi.data) == FD_BN254_BIGINT_FOOTPRINT, fd_ballet );
  /* Convert big-endian to little-endian while copying */
  uchar * t = (uchar *)(bi.data);
  for (ulong i = 0; i < FD_BN254_FIELD_FOOTPRINT; ++i)
    t[FD_BN254_BIGINT_FOOTPRINT-1U-i] = sol->v[i];
  return bi;
}

int
fd_bn254_g1_check( fd_bn254_point_g1_t const * p ) {
  if (!didinit) {
    libff::init_alt_bn128_params();
    didinit = true;
  }
  return fd_bn254_g1_sol_to_libff(p).is_well_formed();
}

void
fd_bn254_g1_compress( fd_bn254_point_g1 const * in, fd_bn254_point_g1_compressed * out ) {
  /* Just pick off the X coordinate */
  fd_memcpy(out->v, in->v, FD_BN254_FIELD_FOOTPRINT);
  /* Use the flag to indicate whether Y is negative */
  if ((in->v[FD_BN254_FIELD_FOOTPRINT*2U - 1U] & 1))
    out->v[0] |= (uchar)(1<<7);
}

void
fd_bn254_g1_decompress( fd_bn254_point_g1_compressed const * in, fd_bn254_point_g1 * out ) {
  if (!didinit) {
    libff::init_alt_bn128_params();
    didinit = true;
  }
  /* Recover Y coordinate from X */
  libff::alt_bn128_Fq X;
  fd_bn254_Fq_sol_to_libff(in->v, &X);
  libff::alt_bn128_Fq X2(X);
  X2.square();
  libff::alt_bn128_Fq X3_plus_b = X*X2 + libff::alt_bn128_coeff_b;
  libff::alt_bn128_Fq Y(X3_plus_b.sqrt());
  if (!(in->v[0] & (uchar)(1<<7)))
    Y = -Y;
  fd_bn254_Fq_libff_to_sol(&X, out->v);
  fd_bn254_Fq_libff_to_sol(&Y, out->v + FD_BN254_FIELD_FOOTPRINT);
}

int
fd_bn254_g2_check( fd_bn254_point_g2_t const * p ) {
  if (!didinit) {
    libff::init_alt_bn128_params();
    didinit = true;
  }
  return fd_bn254_g2_sol_to_libff(p).is_well_formed();
}

void
fd_bn254_g2_compress( fd_bn254_point_g2 const * in, fd_bn254_point_g2_compressed * out ) {
  /* Just pick off the X coordinate */
  fd_memcpy(out->v, in->v, 2U*FD_BN254_FIELD_FOOTPRINT);
  /* Use the flag to indicate whether Y.c0 is negative */
  if ((in->v[FD_BN254_FIELD_FOOTPRINT*3U - 1U] & 1))
    out->v[0] |= (uchar)(1<<7);
}

void
fd_bn254_g2_decompress( fd_bn254_point_g2_compressed const * in, fd_bn254_point_g2 * out ) {
  if (!didinit) {
    libff::init_alt_bn128_params();
    didinit = true;
  }
  /* Recover Y coordinate from X */
  libff::alt_bn128_Fq2 X;
  fd_bn254_Fq2_sol_to_libff(in->v, &X);
  libff::alt_bn128_Fq2 X2(X);
  X2.square();
  libff::alt_bn128_Fq2 X3_plus_b = X*X2 + libff::alt_bn128_twist_coeff_b;
  libff::alt_bn128_Fq2 Y(X3_plus_b.sqrt());
  if ((in->v[0] & (uchar)(1<<7)))
    Y = -Y;
  fd_bn254_Fq2_libff_to_sol(&X, out->v);
  fd_bn254_Fq2_libff_to_sol(&Y, out->v + 2U*FD_BN254_FIELD_FOOTPRINT);
}

void
fd_bn254_g1_add( fd_bn254_point_g1_t const * x, fd_bn254_point_g1_t const * y, fd_bn254_point_g1_t * z ) {
  if (!didinit) {
    libff::init_alt_bn128_params();
    didinit = true;
  }
  fd_bn254_g1_libff_to_sol( fd_bn254_g1_sol_to_libff(x) + fd_bn254_g1_sol_to_libff(y), z );
}

void
fd_bn254_g1_mult( fd_bn254_point_g1_t const * x, fd_bn254_bigint_t const * y, fd_bn254_point_g1_t * z ) {
  if (!didinit) {
    libff::init_alt_bn128_params();
    didinit = true;
  }
  fd_bn254_g1_libff_to_sol( fd_bn254_bigint_sol_to_libff(y) * fd_bn254_g1_sol_to_libff(x), z );
}

int
fd_bn254_pairing( fd_bn254_point_g1_t const * p_1, fd_bn254_point_g2_t const * q_1,
                  fd_bn254_point_g1_t const * p_2, fd_bn254_point_g2_t const * q_2) {
  if (!didinit) {
    libff::init_alt_bn128_params();
    didinit = true;
  }
  auto p_1_pre = libff::alt_bn128_precompute_G1(fd_bn254_g1_sol_to_libff(p_1));
  auto q_1_pre = libff::alt_bn128_precompute_G2(fd_bn254_g2_sol_to_libff(q_1));
  auto p_2_pre = libff::alt_bn128_precompute_G1(fd_bn254_g1_sol_to_libff(p_2));
  auto q_2_pre = libff::alt_bn128_precompute_G2(fd_bn254_g2_sol_to_libff(q_2));
  auto r = libff::alt_bn128_final_exponentiation(libff::alt_bn128_double_miller_loop(p_1_pre, q_1_pre, p_2_pre, q_2_pre));
  return r == libff::alt_bn128_GT::one();
}
