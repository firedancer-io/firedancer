#ifndef HEADER_fd_src_ballet_ed25519_fd_ed25519_private_h
#error "Do not include this directly; use fd_ed25519_private.h"
#endif

/* A fd_ed25519_fe_t stores an ed25519 field element in a 26/25 10-limb
   representation stored in 10 32-bit ints. */

union fd_ed25519_fe_private {
  int limb[10];
};

typedef union fd_ed25519_fe_private fd_ed25519_fe_t;

FD_PROTOTYPES_BEGIN

/* fd_ed25519_fe_frombytes packs a fd_ed25519_fe_t from a flat 255-bit
   representation.  s points to a 32-byte region with the 255-bit bit
   number in little endian form (top bit of s ignored).  Returns h and,
   on return, the fe pointed to by h will be populated with the result. */

fd_ed25519_fe_t *
fd_ed25519_fe_frombytes( fd_ed25519_fe_t * h,
                         uchar const *     s );

/* fd_ed25519_fe_tobytes unpacks a fd_ed25519_fe_t into a flat 256-bit
   representation.  Returns s and, on return, the 32-byte memory region
   whose first byte is pointed to by s, will be populated with the
   result in little endian order.

   Preconditions:
     |h| bounded by 1.1*2^26,1.1*2^25,1.1*2^26,1.1*2^25,etc. */

uchar *
fd_ed25519_fe_tobytes( uchar *                 s,
                       fd_ed25519_fe_t const * h );

/* fd_ed25519_fe_copy computes h = f.  In-place operation fine.  Returns
   h and, on return, the result will be stored in the fe pointed to by
   h.  This currently does not optimize implicitly the case of h==f. */

static inline fd_ed25519_fe_t *
fd_ed25519_fe_copy( fd_ed25519_fe_t *       h,
                    fd_ed25519_fe_t const * f ) {
  h->limb[0] = f->limb[0]; h->limb[1] = f->limb[1];
  h->limb[2] = f->limb[2]; h->limb[3] = f->limb[3];
  h->limb[4] = f->limb[4]; h->limb[5] = f->limb[5];
  h->limb[6] = f->limb[6]; h->limb[7] = f->limb[7];
  h->limb[8] = f->limb[8]; h->limb[9] = f->limb[9];
  return h;
}

/* fd_ed25519_fe_0 initializes the fe pointed to by h to 0.  Returns h
   and the fe pointed to by h will be 0 on return. */

static inline fd_ed25519_fe_t *
fd_ed25519_fe_0( fd_ed25519_fe_t * h ) {
  h->limb[0] = 0; h->limb[1] = 0;
  h->limb[2] = 0; h->limb[3] = 0;
  h->limb[4] = 0; h->limb[5] = 0;
  h->limb[6] = 0; h->limb[7] = 0;
  h->limb[8] = 0; h->limb[9] = 0;
  return h;
}

/* fd_ed25519_fe_1 initializes the fe pointed to by h to 1.  Returns h
   and the fe pointed to by h will be 1 on return. */

static inline fd_ed25519_fe_t *
fd_ed25519_fe_1( fd_ed25519_fe_t * h ) {
  h->limb[0] = 1; h->limb[1] = 0;
  h->limb[2] = 0; h->limb[3] = 0;
  h->limb[4] = 0; h->limb[5] = 0;
  h->limb[6] = 0; h->limb[7] = 0;
  h->limb[8] = 0; h->limb[9] = 0;
  return h;
}

static inline fd_ed25519_fe_t *
fd_ed25519_fe_2( fd_ed25519_fe_t * h ) {
  h->limb[0] = 2; h->limb[1] = 0;
  h->limb[2] = 0; h->limb[3] = 0;
  h->limb[4] = 0; h->limb[5] = 0;
  h->limb[6] = 0; h->limb[7] = 0;
  h->limb[8] = 0; h->limb[9] = 0;
  return h;
}
/* fd_ed25519_fe_rand initializes h to a random field element whose
   limbs are normalized (approximately uniform random distributed).
   Returns h and, on return, the result will be stored in the fe pointed
   to by h.  rng is a local join to random number generator to use.
   Consumes 10 slots in the rng sequence. */

FD_FN_UNUSED static fd_ed25519_fe_t * /* Work around -Winline */
fd_ed25519_fe_rng( fd_ed25519_fe_t * h,
                   fd_rng_t *        rng ) {
  uint m26 = (uint)FD_ULONG_MASK_LSB(26); uint m25 = (uint)FD_ULONG_MASK_LSB(25);
  h->limb[0] = (int)(fd_rng_uint( rng ) & m26); h->limb[1] = (int)(fd_rng_uint( rng ) & m25);
  h->limb[2] = (int)(fd_rng_uint( rng ) & m26); h->limb[3] = (int)(fd_rng_uint( rng ) & m25);
  h->limb[4] = (int)(fd_rng_uint( rng ) & m26); h->limb[5] = (int)(fd_rng_uint( rng ) & m25);
  h->limb[6] = (int)(fd_rng_uint( rng ) & m26); h->limb[7] = (int)(fd_rng_uint( rng ) & m25);
  h->limb[8] = (int)(fd_rng_uint( rng ) & m26); h->limb[9] = (int)(fd_rng_uint( rng ) & m25);
  return h;
}

/* fd_ed25519_fe_add computes h = f + g.  In place operation is fine.
   Returns h and, on return, the result will be stored in the fe pointed
   to by h.  This currently does not optimize implicitly the case of
   f==g.

   Preconditions:
      |f| bounded by 1.1*2^25,1.1*2^24,1.1*2^25,1.1*2^24,etc.
      |g| bounded by 1.1*2^25,1.1*2^24,1.1*2^25,1.1*2^24,etc.

   Postconditions:
      |h| bounded by 1.1*2^26,1.1*2^25,1.1*2^26,1.1*2^25,etc. */

FD_FN_UNUSED static fd_ed25519_fe_t * /* Work around -Winline */
fd_ed25519_fe_add( fd_ed25519_fe_t *       h,
                   fd_ed25519_fe_t const * f,
                   fd_ed25519_fe_t const * g ) {
  h->limb[0] = f->limb[0] + g->limb[0]; h->limb[1] = f->limb[1] + g->limb[1];
  h->limb[2] = f->limb[2] + g->limb[2]; h->limb[3] = f->limb[3] + g->limb[3];
  h->limb[4] = f->limb[4] + g->limb[4]; h->limb[5] = f->limb[5] + g->limb[5];
  h->limb[6] = f->limb[6] + g->limb[6]; h->limb[7] = f->limb[7] + g->limb[7];
  h->limb[8] = f->limb[8] + g->limb[8]; h->limb[9] = f->limb[9] + g->limb[9];
  return h;
}

/* fd_ed25519_fe_sub computes h = f - g.  In place operation is fine.
   Returns h and, on return, the result will be stored in the fe pointed
   to by h.  This currently does not optimize implicitly the case of
   f==g.

   Preconditions:
      |f| bounded by 1.1*2^25,1.1*2^24,1.1*2^25,1.1*2^24,etc.
      |g| bounded by 1.1*2^25,1.1*2^24,1.1*2^25,1.1*2^24,etc.

   Postconditions:
      |h| bounded by 1.1*2^26,1.1*2^25,1.1*2^26,1.1*2^25,etc. */

FD_FN_UNUSED static fd_ed25519_fe_t * /* Work around -Winline */
fd_ed25519_fe_sub( fd_ed25519_fe_t *       h,
                   fd_ed25519_fe_t const * f,
                   fd_ed25519_fe_t const * g ) {
  h->limb[0] = f->limb[0] - g->limb[0]; h->limb[1] = f->limb[1] - g->limb[1];
  h->limb[2] = f->limb[2] - g->limb[2]; h->limb[3] = f->limb[3] - g->limb[3];
  h->limb[4] = f->limb[4] - g->limb[4]; h->limb[5] = f->limb[5] - g->limb[5];
  h->limb[6] = f->limb[6] - g->limb[6]; h->limb[7] = f->limb[7] - g->limb[7];
  h->limb[8] = f->limb[8] - g->limb[8]; h->limb[9] = f->limb[9] - g->limb[9];
  return h;
}

/* fd_ed25519_fe_mul computes h = f * g.  In place operation is fine.
   Returns h and, on return, the result will be stored in the fe pointed
   to by h.  This currently does not optimize implicitly the case of
   f==g.  If appropriate, use fd_ed25519_fe_sq below or detect and
   manually select at run time.

   Preconditions:
      |f| bounded by 1.65*2^26,1.65*2^25,1.65*2^26,1.65*2^25,etc.
      |g| bounded by 1.65*2^26,1.65*2^25,1.65*2^26,1.65*2^25,etc.

   Postconditions:
      |h| bounded by 1.01*2^25,1.01*2^24,1.01*2^25,1.01*2^24,etc. */

fd_ed25519_fe_t *
fd_ed25519_fe_mul( fd_ed25519_fe_t *       h,
                   fd_ed25519_fe_t const * f,
                   fd_ed25519_fe_t const * g );

/* fd_ed25519_fe_sq computes h = f^2.  In place operation is fine.  This
   is faster than computing this via fd_ed25519_fe_mul above.  Returns h
   and, on return, the result will be stored in the fe pointed to by h.

   Preconditions:
      |f| bounded by 1.65*2^26,1.65*2^25,1.65*2^26,1.65*2^25,etc.
      |g| bounded by 1.65*2^26,1.65*2^25,1.65*2^26,1.65*2^25,etc.

   Postconditions:
      |h| bounded by 1.01*2^25,1.01*2^24,1.01*2^25,1.01*2^24,etc. */

fd_ed25519_fe_t *
fd_ed25519_fe_sq( fd_ed25519_fe_t *       h,
                  fd_ed25519_fe_t const * f );

/* fd_ed25519_fe_invert computes out = z^-1 = z^(2^255-20).  In place
   operation is fine.  Returns out and, on return, the result will be
   stored in the fe pointed to by out. */

fd_ed25519_fe_t *
fd_ed25519_fe_invert( fd_ed25519_fe_t *       out,
                      fd_ed25519_fe_t const * z );

/* fd_ed25519_fe_neg computes h = -f.  In-place operation fine.  Returns
   h and, on return, the result will be stored in the fe pointed to by
   h.  This currently does not optimize implicitly the case of h==f. */

static inline fd_ed25519_fe_t *
fd_ed25519_fe_neg( fd_ed25519_fe_t *       h,
                   fd_ed25519_fe_t const * f ) {
  h->limb[0] = -f->limb[0]; h->limb[1] = -f->limb[1];
  h->limb[2] = -f->limb[2]; h->limb[3] = -f->limb[3];
  h->limb[4] = -f->limb[4]; h->limb[5] = -f->limb[5];
  h->limb[6] = -f->limb[6]; h->limb[7] = -f->limb[7];
  h->limb[8] = -f->limb[8]; h->limb[9] = -f->limb[9];
  return h;
}

/* fd_ed25519_fe_if computes h = c ? f : g.  In-place operation fine.
   Returns h and, on return, the result will be stored in the fe pointed
   to by h.  This currently does not optimize implicitly the case of
   h==f and tries to have a deterministic timing. */

FD_FN_UNUSED static fd_ed25519_fe_t * /* Work around -Winline */
fd_ed25519_fe_if( fd_ed25519_fe_t *       h,
                  int                     c,
                  fd_ed25519_fe_t const * f,
                  fd_ed25519_fe_t const * g ) {
  int m  = -!!c;

  int f0 = f->limb[0]; int f1 = f->limb[1];
  int f2 = f->limb[2]; int f3 = f->limb[3];
  int f4 = f->limb[4]; int f5 = f->limb[5];
  int f6 = f->limb[6]; int f7 = f->limb[7];
  int f8 = f->limb[8]; int f9 = f->limb[9];

  int g0 = g->limb[0]; int g1 = g->limb[1];
  int g2 = g->limb[2]; int g3 = g->limb[3];
  int g4 = g->limb[4]; int g5 = g->limb[5];
  int g6 = g->limb[6]; int g7 = g->limb[7];
  int g8 = g->limb[8]; int g9 = g->limb[9];

  h->limb[0] = g0 ^ (m & (g0 ^ f0)); h->limb[1] = g1 ^ (m & (g1 ^ f1));
  h->limb[2] = g2 ^ (m & (g2 ^ f2)); h->limb[3] = g3 ^ (m & (g3 ^ f3));
  h->limb[4] = g4 ^ (m & (g4 ^ f4)); h->limb[5] = g5 ^ (m & (g5 ^ f5));
  h->limb[6] = g6 ^ (m & (g6 ^ f6)); h->limb[7] = g7 ^ (m & (g7 ^ f7));
  h->limb[8] = g8 ^ (m & (g8 ^ f8)); h->limb[9] = g9 ^ (m & (g9 ^ f9));
  return h;
}

/* fd_ed25519_swap_if swaps f and g if c.  Tries to have a deterministic
   timing. */

FD_FN_UNUSED static void /* Work around -Winline */
fd_ed25519_fe_swap_if( fd_ed25519_fe_t * f,
                       fd_ed25519_fe_t * g,
                       int               c ) {
  int m  = -!!c;

  int h0 = m & (f->limb[0] ^ g->limb[0]);
  int h1 = m & (f->limb[1] ^ g->limb[1]);
  int h2 = m & (f->limb[2] ^ g->limb[2]);
  int h3 = m & (f->limb[3] ^ g->limb[3]);
  int h4 = m & (f->limb[4] ^ g->limb[4]);
  int h5 = m & (f->limb[5] ^ g->limb[5]);
  int h6 = m & (f->limb[6] ^ g->limb[6]);
  int h7 = m & (f->limb[7] ^ g->limb[7]);
  int h8 = m & (f->limb[8] ^ g->limb[8]);
  int h9 = m & (f->limb[9] ^ g->limb[9]);

  f->limb[0] ^= h0; g->limb[0] ^= h0;
  f->limb[1] ^= h1; g->limb[1] ^= h1;
  f->limb[2] ^= h2; g->limb[2] ^= h2;
  f->limb[3] ^= h3; g->limb[3] ^= h3;
  f->limb[4] ^= h4; g->limb[4] ^= h4;
  f->limb[5] ^= h5; g->limb[5] ^= h5;
  f->limb[6] ^= h6; g->limb[6] ^= h6;
  f->limb[7] ^= h7; g->limb[7] ^= h7;
  f->limb[8] ^= h8; g->limb[8] ^= h8;
  f->limb[9] ^= h9; g->limb[9] ^= h9;
}

/* fd_ed25519_fe_isnonzero returns 1 if f is not zero and 0 otherwise.

   Preconditions:
      |f| bounded by 1.1*2^26,1.1*2^25,1.1*2^26,1.1*2^25,etc. */

static inline int
fd_ed25519_fe_isnonzero( fd_ed25519_fe_t const * f ) {
  uchar s[32]; fd_ed25519_fe_tobytes( s, f );
  static uchar const zero[32];
  return !!memcmp( s, zero, 32UL );
}

/* fd_ed25519_fe_isnegative returns 1 if f is in {1,3,5,...,q-2} and 0
   otherwise.

   Preconditions:
      |f| bounded by 1.1*2^26,1.1*2^25,1.1*2^26,1.1*2^25,etc. */

static inline int
fd_ed25519_fe_isnegative( fd_ed25519_fe_t const * f ) {
  uchar s[32]; fd_ed25519_fe_tobytes( s, f );
  return ((int)(uint)s[0]) & 1;
}

/* fd_ed25519_fe_sq2 computes h = 2 f^2.  In place operation is fine.
   This is faster than computing this via fd_ed25519_fe_mul above.
   Returns h and, on return, the result will be stored in the fe pointed
   to by h.

   Preconditions:
      |f| bounded by 1.65*2^26,1.65*2^25,1.65*2^26,1.65*2^25,etc.

   Postconditions:
      |h| bounded by 1.01*2^25,1.01*2^24,1.01*2^25,1.01*2^24,etc. */

fd_ed25519_fe_t *
fd_ed25519_fe_sq2( fd_ed25519_fe_t *       h,
                   fd_ed25519_fe_t const * f );

/* fd_ed25519_fe_pow22523 computes out = z^(2^252-3).  In place
   operation is fine.  Returns out and, on return, the result will be
   stored in the fe pointed to by out. */

fd_ed25519_fe_t *
fd_ed25519_fe_pow22523( fd_ed25519_fe_t *       out,
                        fd_ed25519_fe_t const * z );

/* fd_ed25519_fe_mul4 is equivalent to:
     fd_ed25519_fe_mul( ha, fa, ga );
     fd_ed25519_fe_mul( hb, fb, gb );
     fd_ed25519_fe_mul( hc, fc, gc );
     fd_ed25519_fe_mul( hd, fd, gd );
   Similarly for fe_mul2 and fe_mul3.  The outputs should not overlap. */

static inline void
fd_ed25519_fe_mul2( fd_ed25519_fe_t * ha, fd_ed25519_fe_t const * fa, fd_ed25519_fe_t const * ga,
                    fd_ed25519_fe_t * hb, fd_ed25519_fe_t const * fb, fd_ed25519_fe_t const * gb ) {
  fd_ed25519_fe_mul( ha, fa, ga );
  fd_ed25519_fe_mul( hb, fb, gb );
}

static inline void
fd_ed25519_fe_mul3( fd_ed25519_fe_t * ha, fd_ed25519_fe_t const * fa, fd_ed25519_fe_t const * ga,
                    fd_ed25519_fe_t * hb, fd_ed25519_fe_t const * fb, fd_ed25519_fe_t const * gb,
                    fd_ed25519_fe_t * hc, fd_ed25519_fe_t const * fc, fd_ed25519_fe_t const * gc ) {
  fd_ed25519_fe_mul( ha, fa, ga );
  fd_ed25519_fe_mul( hb, fb, gb );
  fd_ed25519_fe_mul( hc, fc, gc );
}

static inline void
fd_ed25519_fe_mul4( fd_ed25519_fe_t * ha, fd_ed25519_fe_t const * fa, fd_ed25519_fe_t const * ga,
                    fd_ed25519_fe_t * hb, fd_ed25519_fe_t const * fb, fd_ed25519_fe_t const * gb,
                    fd_ed25519_fe_t * hc, fd_ed25519_fe_t const * fc, fd_ed25519_fe_t const * gc,
                    fd_ed25519_fe_t * hd, fd_ed25519_fe_t const * fd, fd_ed25519_fe_t const * gd ) {
  fd_ed25519_fe_mul( ha, fa, ga );
  fd_ed25519_fe_mul( hb, fb, gb );
  fd_ed25519_fe_mul( hc, fc, gc );
  fd_ed25519_fe_mul( hd, fd, gd );
}

/* fd_ed25519_fe_sqn4 is equivalent to:
     if( na==1L ) fd_ed25519_fe_sq( ha, fa ); else fd_ed25519_fe_sq2( ha, fa );
     if( nb==1L ) fd_ed25519_fe_sq( hb, fb ); else fd_ed25519_fe_sq2( hb, fb );
     if( nc==1L ) fd_ed25519_fe_sq( hc, fc ); else fd_ed25519_fe_sq2( hc, fc );
     if( nd==1L ) fd_ed25519_fe_sq( hd, fd ); else fd_ed25519_fe_sq2( hd, fd );
   Similarly for fe_sqn2 and fe_sqn3.  The outputs should not overlap. */

static inline void
fd_ed25519_fe_sqn2( fd_ed25519_fe_t * ha, fd_ed25519_fe_t const * fa, long na,    /* Should be 1 or 2 */
                    fd_ed25519_fe_t * hb, fd_ed25519_fe_t const * fb, long nb ) { /* " */
  if( na==1L ) fd_ed25519_fe_sq( ha, fa ); else fd_ed25519_fe_sq2( ha, fa );
  if( nb==1L ) fd_ed25519_fe_sq( hb, fb ); else fd_ed25519_fe_sq2( hb, fb );
}

static inline void
fd_ed25519_fe_sqn3( fd_ed25519_fe_t * ha, fd_ed25519_fe_t const * fa, long na,    /* Should be 1 or 2 */
                    fd_ed25519_fe_t * hb, fd_ed25519_fe_t const * fb, long nb,    /* " */
                    fd_ed25519_fe_t * hc, fd_ed25519_fe_t const * fc, long nc ) { /* " */
  if( na==1L ) fd_ed25519_fe_sq( ha, fa ); else fd_ed25519_fe_sq2( ha, fa );
  if( nb==1L ) fd_ed25519_fe_sq( hb, fb ); else fd_ed25519_fe_sq2( hb, fb );
  if( nc==1L ) fd_ed25519_fe_sq( hc, fc ); else fd_ed25519_fe_sq2( hc, fc );
}

static inline void
fd_ed25519_fe_sqn4( fd_ed25519_fe_t * ha, fd_ed25519_fe_t const * fa, long na,    /* Should be 1 or 2 */
                    fd_ed25519_fe_t * hb, fd_ed25519_fe_t const * fb, long nb,    /* " */
                    fd_ed25519_fe_t * hc, fd_ed25519_fe_t const * fc, long nc,    /* " */
                    fd_ed25519_fe_t * hd, fd_ed25519_fe_t const * fd, long nd ) { /* " */
  if( na==1L ) fd_ed25519_fe_sq( ha, fa ); else fd_ed25519_fe_sq2( ha, fa );
  if( nb==1L ) fd_ed25519_fe_sq( hb, fb ); else fd_ed25519_fe_sq2( hb, fb );
  if( nc==1L ) fd_ed25519_fe_sq( hc, fc ); else fd_ed25519_fe_sq2( hc, fc );
  if( nd==1L ) fd_ed25519_fe_sq( hd, fd ); else fd_ed25519_fe_sq2( hd, fd );
}

#define FD_ED25519_FE_POW25523_2_FAST 0

static inline void
fd_ed25519_fe_pow22523_2( fd_ed25519_fe_t * out0, fd_ed25519_fe_t const * z0,
                          fd_ed25519_fe_t * out1, fd_ed25519_fe_t const * z1 ) {
  fd_ed25519_fe_pow22523( out0, z0 );
  fd_ed25519_fe_pow22523( out1, z1 );
}

/* fd_ed25519_fe_mul121666 computes h = f * 121666.  In place operation
   is fine.  Returns h and, on return, the result will be stored in the
   fe pointed to by h. */

void
fd_ed25519_fe_mul121666( fd_ed25519_fe_t *       h,
                         fd_ed25519_fe_t const * f );

int
fd_ed25519_fe_sqrt_ratio( fd_ed25519_fe_t *       h,
                          fd_ed25519_fe_t const * f,
                          fd_ed25519_fe_t const * g );

static inline void
fd_ed25519_fe_abs( fd_ed25519_fe_t *       h,
                   fd_ed25519_fe_t const * f ) {
  fd_ed25519_fe_t fneg[1];
  fd_ed25519_fe_neg( fneg, f );
  fd_ed25519_fe_if( h, fd_ed25519_fe_isnegative( f ), fneg, f );
}

FD_PROTOTYPES_END

