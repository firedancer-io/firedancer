/* Included by fd_bn254_g1.c and fd_bn254_g2.c, should not be used elsewhere. */

/* Rundown of the BN254 GLV implementation:

   Context: https://bitcointalk.org/index.php?topic=3238.msg45565#msg45565

   BN254 is a "pairing-friendly" curve E: y^2 = x^3 + 3 over a prime field
   Fp, where:
    p = 21888242871839275222246405745257275088696311157297823662689037894645226208583

   The group G1 = E(Fp) has prime order:
    r = 21888242871839275222246405745257275088548364400416034343698204186575808495617

   A naive approach to scalar multiplication, [s]P, requires ~256 doublings
   and ~128 additions (double-and-add) in the worst case. The GLV method
   takes advantage of an easy to compute endomorphism to cut this roughly
   in half.

   For BN254, there exists a cube root of unity beta in Fp such that:
    phi: (x, y) -> (beta * x, y)
   is an endomorphism of E.
   That is, if point P = (x, y) is on the curve, then phi(P) = (beta * x, y)
   is also on the curve, since (beta*x)^3 = beta^3 * x^3) = x^3,
   so the curve equation is preserved.

   phi satisfies phi(P) = [lambda]P where lambda is a cube root of unity
   modulo r (the group order we defined above^):
    lambda = 4407920970296243842393367215006156084916469457145843978461
             (a root of X^2 + X + 1 = 0 mod r)

   Computing phi(P) = (beta * x, y) costs just one FP multiplication, but
   is equivalent to a full scalar multiplication by the ~254-bit scalar lambda.

   We want to "decompose" the input scalar in a way where a majority of the
   effort is re-used by the lambda computation, leaving the remaining operations
   smaller and faster to perform. Given a scalar s, we want to find small
   k1, k2 (each ~128-bit) such that:
    s = k1 + k2 * lambda (mod r)
   Then: [s]P = [k1]P + [k2](lambda * P) = [k1]P + [k2]phi(P).

   Using the "Straus-Shamir trick", https://pmc.ncbi.nlm.nih.gov/articles/PMC9028562/#app1-sensors-22-03083,
   this requires only ~128 doublings + ~128 additions instead of ~256 doublings.

   To decompose the scalar, we have a 2-dimensional lattice
    L = { (a, b) in Z^2 : a + b*lambda = 0 (mod r) }

   A reduced basis of L is given by three magnitudes:
    N_A = 147946756881789319000765030803803410728  (~128 bits, 2 limbs)
    N_B = 9931322734385697763                      (~64 bits, 1 limb)
    N_C = 147946756881789319010696353538189108491  (~128 bits, 2 limbs)

   These are arranged differently depending on the group.
   G1:
    | +N_A  +N_B |
    | -N_B  +N_C |
   G2:
    | -N_C  -N_B |
    | +N_B  -N_A |

   We avoid big integer divisions by r using Babai's algorithm with
   precomputed fixed-point inverses:
    b1 = (s * g1) >> 256, where for group:
                      G1: g1 = round(2^256 * N_C / r)
                      G2: g1 = round(2^256 * N_A / r)
    b2 = (s * g2) >> 256  g2 = round(2^256 * N_B / r), 66-bit, 2 limbs)

   Then:
    G1: k1 = s - b1*N_A - b2*N_B,  k2 = b1*N_B - b2*N_C
    G2: k1 = s - b1*N_C - b2*N_B,  k2 = b2*N_A - b1*N_B

   For G1, k1 >= 0 always, k2 may be negative.
   For G2, both k1 and k2 may be negative. */

/* beta in Montgomery form.
   0x30644e72e131a0295e6dd9e7e0acccb0c28f069fbb966e3de4bd44e5607cfd48 */
const fd_bn254_fp_t fd_bn254_const_beta_mont[1] = {{{
  0x3350c88e13e80b9cUL, 0x7dce557cdb5e56b9UL, 0x6001b4b8b615564aUL, 0x2682e617020217e0UL
}}};

/* Lattice constants, see glv.py */
const ulong na[ 2 ] = { 0x8211bbeb7d4f1128UL, 0x6f4d8248eeb859fcUL };
const ulong nb[ 1 ] = { 0x89d3256894d213e3UL };
const ulong nc[ 2 ] = { 0x0be4e1541221250bUL, 0x6f4d8248eeb859fdUL };

/* g2 = round(2^256 * N_B / r), 66-bit (2 limbs). Same for G1 and G2. */
const ulong g2_const[ 2 ] = { 0xd91d232ec7e0b3d7UL, 0x0000000000000002UL };

/* Multiply 4-limb scalar s by a 3-limb constant g.
   Returns top 3 limbs. */
static inline void
fd_bn254_glv_sxg3( ulong                   out[ 3 ],
                   fd_bn254_scalar_t const * s,
                   ulong const               g[ 3 ] ) {
  uint128 s0 = s->limbs[0];
  uint128 s1 = s->limbs[1];
  uint128 s2 = s->limbs[2];
  uint128 s3 = s->limbs[3];
  uint128 acc;
  acc = s0 * g[ 0 ];
  acc = s1 * g[ 0 ] + s0 * g[ 1 ]               + (ulong)(acc >> 64);
  acc = s2 * g[ 0 ] + s1 * g[ 1 ] + s0 * g[ 2 ] + (ulong)(acc >> 64);
  acc = s3 * g[ 0 ] + s2 * g[ 1 ] + s1 * g[ 2 ] + (ulong)(acc >> 64);
  acc =               s3 * g[ 1 ] + s2 * g[ 2 ] + (ulong)(acc >> 64); out[ 0 ] = (ulong)acc;
  acc =                             s3 * g[ 2 ] + (ulong)(acc >> 64); out[ 1 ] = (ulong)acc;
  acc =                                           (ulong)(acc >> 64); out[ 2 ] = (ulong)acc;
}

/* Same, but for a 2-limb constant g. */
static inline void
fd_bn254_glv_sxg2( ulong                   out[ 2 ],
                   fd_bn254_scalar_t const * s,
                   ulong             const   g[ 2 ] ) {
  uint128 s0 = s->limbs[0];
  uint128 s1 = s->limbs[1];
  uint128 s2 = s->limbs[2];
  uint128 s3 = s->limbs[3];
  uint128 acc;
  acc = s0 * g[ 0 ];
  acc = s1 * g[ 0 ] + s0 * g[ 1 ] + (ulong)(acc >> 64);
  acc = s2 * g[ 0 ] + s1 * g[ 1 ] + (ulong)(acc >> 64);
  acc = s3 * g[ 0 ] + s2 * g[ 1 ] + (ulong)(acc >> 64);
  acc =               s3 * g[ 1 ] + (ulong)(acc >> 64); out[ 0 ] = (ulong)acc;
  acc =                             (ulong)(acc >> 64); out[ 1 ] = (ulong)acc;
}

/* Multiply 3-limb a by 2-limb n, store low 4 limbs into out. */
static inline void
fd_bn254_glv_mul3x2( ulong     out[ 4 ],
                     ulong const a[ 3 ],
                     ulong const n[ 2 ] ) {
  uint128 acc;
  acc = (uint128)a[ 0 ] * n[ 0 ];                                                 out[ 0 ] = (ulong)acc;
  acc = (uint128)a[ 1 ] * n[ 0 ] + (uint128)a[ 0 ] * n[ 1 ] + (ulong)(acc >> 64); out[ 1 ] = (ulong)acc;
  acc = (uint128)a[ 2 ] * n[ 0 ] + (uint128)a[ 1 ] * n[ 1 ] + (ulong)(acc >> 64); out[ 2 ] = (ulong)acc;
  acc =                            (uint128)a[ 2 ] * n[ 1 ] + (ulong)(acc >> 64); out[ 3 ] = (ulong)acc;
}

/* Multiply 3-limb by 1-limb, store into 4-limb. */
static inline void
fd_bn254_glv_mul3x1( ulong     out[ 4 ],
                     ulong const a[ 3 ],
                     ulong const n[ 1 ] ) {
  uint128 acc;
  acc = (uint128)a[ 0 ] * n[ 0 ];                      out[ 0 ] = (ulong)acc;
  acc = (uint128)a[ 1 ] * n[ 0 ] + (ulong)(acc >> 64); out[ 1 ] = (ulong)acc;
  acc = (uint128)a[ 2 ] * n[ 0 ] + (ulong)(acc >> 64); out[ 2 ] = (ulong)acc;
  acc =                            (ulong)(acc >> 64); out[ 3 ] = (ulong)acc;
}

/* Multiply 2-limb by 2-limb, store into 4-limb. */
static inline void
fd_bn254_glv_mul2x2( ulong     out[ 4 ],
                     ulong const a[ 2 ],
                     ulong const n[ 2 ] ) {
  uint128 acc;
  acc = (uint128)a[ 0 ] * n[ 0 ];                                                 out[ 0 ] = (ulong)acc;
  acc = (uint128)a[ 1 ] * n[ 0 ] + (uint128)a[ 0 ] * n[ 1 ] + (ulong)(acc >> 64); out[ 1 ] = (ulong)acc;
  acc =                            (uint128)a[ 1 ] * n[ 1 ] + (ulong)(acc >> 64); out[ 2 ] = (ulong)acc;
  acc =                                                       (ulong)(acc >> 64); out[ 3 ] = (ulong)acc;
}

/* Multiply 2-limb by 1-limb, stores 3-limbs. */
static inline void
fd_bn254_glv_mul2x1( ulong     out[ 3 ],
                     ulong const a[ 2 ],
                     ulong const n[ 1 ] ) {
  uint128 acc;
  acc = (uint128)a[ 0 ] * n[ 0 ];                      out[ 0 ] = (ulong)acc;
  acc = (uint128)a[ 1 ] * n[ 0 ] + (ulong)(acc >> 64); out[ 1 ] = (ulong)acc;
  acc =                            (ulong)(acc >> 64); out[ 2 ] = (ulong)acc;
}

/* 4-limb addition: out = a + b.  Returns carry. */
static inline ulong
fd_bn254_glv_add4( ulong     out[ 4 ],
                   ulong const a[ 4 ],
                   ulong const b[ 4 ] ) {
  ulong carry = 0;
  for( int j = 0; j < 4; j++ ) {
    uint128 acc = (uint128)a[ j ] + b[ j ] + carry;
    out[ j ] = (ulong)acc;
    carry    = (ulong)(acc >> 64);
  }
  return carry;
}

/* 4-limb subtraction: out = a - b.  Returns borrow (1 if a < b). */
static inline ulong
fd_bn254_glv_sub4( ulong     out[ 4 ],
                   ulong const a[ 4 ],
                   ulong const b[ 4 ] ) {
  ulong borrow = 0;
  for( int j = 0; j < 4; j++ ) {
    ulong av = a[ j ];
    ulong bv = b[ j ];
    ulong diff = av - bv - borrow;
    borrow = ( av < bv || (borrow && av == bv) ) ? 1UL : 0UL;
    out[ j ] = diff;
  }
  return borrow;
}

/* Two's complement negation of a 4-limb value in-place. */
static inline void
fd_bn254_glv_negate4( ulong v[ 4 ] ) {
  ulong carry = 1;
  for( int j = 0; j < 4; j++ ) {
    uint128 sum = (uint128)(~v[ j ]) + carry;
    v[ j ] = (ulong)sum;
    carry  = (ulong)(sum >> 64);
  }
}
