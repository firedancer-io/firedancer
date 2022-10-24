#ifndef HEADER_fd_src_ballet_ed25519_fd_ed25519_private_h
#error "Do not include this directly; use fd_ed25519_private.h"
#endif

#include "../../../util/simd/fd_avx.h"

/* See ../ref/fd_ed25519_fe.h for documentation of these APIs */

struct fd_ed25519_fe_private {
  int limb[16] __attribute__((aligned(64))); /* only 0:9 matter */
};

typedef struct fd_ed25519_fe_private fd_ed25519_fe_t;

FD_PROTOTYPES_BEGIN

fd_ed25519_fe_t *
fd_ed25519_fe_frombytes( fd_ed25519_fe_t * h,
                         uchar const *     s );

uchar *
fd_ed25519_fe_tobytes( uchar *                 s,
                       fd_ed25519_fe_t const * h );

static inline fd_ed25519_fe_t *
fd_ed25519_fe_copy( fd_ed25519_fe_t *       h,
                    fd_ed25519_fe_t const * f ) {
  wi_t h07 = wi_ld( f->limb ); wi_t h89 = wi_ld( f->limb+8 );
  wi_st( h->limb, h07 );       wi_st( h->limb+8, h89 );
  return h;
}

static inline fd_ed25519_fe_t *
fd_ed25519_fe_0( fd_ed25519_fe_t * h ) {
  wi_t z = wi_zero();
  wi_st( h->limb, z ); wi_st( h->limb+8, z );
  return h;
}

static inline fd_ed25519_fe_t *
fd_ed25519_fe_1( fd_ed25519_fe_t * h ) {
  wi_t z = wi_zero();
  wi_st( h->limb, z ); wi_st( h->limb+8, z );
  h->limb[0] = 1;
  return h;
}

static inline fd_ed25519_fe_t *
fd_ed25519_fe_rng( fd_ed25519_fe_t * h,
                   fd_rng_t *        rng ) {
  uint m26 = (uint)FD_MASK_LSB(26); uint m25 = (uint)FD_MASK_LSB(25);
  h->limb[0] = (int)(fd_rng_uint( rng ) & m26); h->limb[1] = (int)(fd_rng_uint( rng ) & m25);
  h->limb[2] = (int)(fd_rng_uint( rng ) & m26); h->limb[3] = (int)(fd_rng_uint( rng ) & m25);
  h->limb[4] = (int)(fd_rng_uint( rng ) & m26); h->limb[5] = (int)(fd_rng_uint( rng ) & m25);
  h->limb[6] = (int)(fd_rng_uint( rng ) & m26); h->limb[7] = (int)(fd_rng_uint( rng ) & m25);
  h->limb[8] = (int)(fd_rng_uint( rng ) & m26); h->limb[9] = (int)(fd_rng_uint( rng ) & m25);
  return h;
}

static inline fd_ed25519_fe_t *
fd_ed25519_fe_add( fd_ed25519_fe_t *       h,
                   fd_ed25519_fe_t const * f,
                   fd_ed25519_fe_t const * g ) {
  wi_t f07 = wi_ld( f->limb );   wi_t f89 = wi_ld( f->limb+8 );
  wi_t g07 = wi_ld( g->limb );   wi_t g89 = wi_ld( g->limb+8 );
  wi_t h07 = wi_add( f07, g07 ); wi_t h89 = wi_add( f89, g89 );
  wi_st( h->limb, h07 );         wi_st( h->limb+8, h89 );
  return h;
}

static inline fd_ed25519_fe_t *
fd_ed25519_fe_sub( fd_ed25519_fe_t *       h,
                   fd_ed25519_fe_t const * f,
                   fd_ed25519_fe_t const * g ) {
  wi_t f07 = wi_ld( f->limb );   wi_t f89 = wi_ld( f->limb+8 );
  wi_t g07 = wi_ld( g->limb );   wi_t g89 = wi_ld( g->limb+8 );
  wi_t h07 = wi_sub( f07, g07 ); wi_t h89 = wi_sub( f89, g89 );
  wi_st( h->limb, h07 );         wi_st( h->limb+8, h89 );
  return h;
}

fd_ed25519_fe_t *
fd_ed25519_fe_mul( fd_ed25519_fe_t *       h,
                   fd_ed25519_fe_t const * f,
                   fd_ed25519_fe_t const * g );

fd_ed25519_fe_t *
fd_ed25519_fe_sq( fd_ed25519_fe_t *       h,
                  fd_ed25519_fe_t const * f );

fd_ed25519_fe_t *
fd_ed25519_fe_invert( fd_ed25519_fe_t *       out,
                      fd_ed25519_fe_t const * z );

static inline fd_ed25519_fe_t *
fd_ed25519_fe_neg( fd_ed25519_fe_t *       h,
                   fd_ed25519_fe_t const * f ) {
  wi_t f07 = wi_ld( f->limb ); wi_t f89 = wi_ld( f->limb+8 );
  wi_t z   = wi_zero();
  wi_t h07 = wi_sub( z, f07 ); wi_t h89 = wi_sub( z, f89 );
  wi_st( h->limb, h07 );       wi_st( h->limb+8, h89 );
  return h;
}

static inline fd_ed25519_fe_t *
fd_ed25519_fe_if( fd_ed25519_fe_t *       h,
                  int                     c,
                  fd_ed25519_fe_t const * f,
                  fd_ed25519_fe_t const * g ) {
  wi_t f07 = wi_ld( f->limb );     wi_t f89 = wi_ld( f->limb+8 );
  wi_t g07 = wi_ld( g->limb );     wi_t g89 = wi_ld( g->limb+8 );
  wc_t m   = wc_bcast( c );
  wi_t h07 = wi_if( m, f07, g07 ); wi_t h89 = wi_if( m, f89, g89 );
  wi_st( h->limb, h07 );           wi_st( h->limb+8, h89 );
  return h;
}

static inline int
fd_ed25519_fe_isnonzero( fd_ed25519_fe_t const * f ) {
  uchar s[32] __attribute((aligned(32))); fd_ed25519_fe_tobytes( s, f );
  wi_t s07 = wi_ld( (int const *)s );
  return !wc_all( wi_eq( s07, wi_zero() ) );
}

static inline int
fd_ed25519_fe_isnegative( fd_ed25519_fe_t const * f ) {
  uchar s[32]; fd_ed25519_fe_tobytes( s, f );
  return ((int)(uint)s[0]) & 1;
}

fd_ed25519_fe_t *
fd_ed25519_fe_sq2( fd_ed25519_fe_t *       h,
                   fd_ed25519_fe_t const * f );

fd_ed25519_fe_t *
fd_ed25519_fe_pow22523( fd_ed25519_fe_t *       out,
                        fd_ed25519_fe_t const * z );

#define FD_ED25519_FE_VMUL_FAST 1

void
fd_ed25519_fe_vmul( fd_ed25519_fe_t * ha, fd_ed25519_fe_t const * fa, fd_ed25519_fe_t const * ga,
                    fd_ed25519_fe_t * hb, fd_ed25519_fe_t const * fb, fd_ed25519_fe_t const * gb,
                    fd_ed25519_fe_t * hc, fd_ed25519_fe_t const * fc, fd_ed25519_fe_t const * gc,
                    fd_ed25519_fe_t * hd, fd_ed25519_fe_t const * fd, fd_ed25519_fe_t const * gd );

void
fd_ed25519_fe_vsqn( fd_ed25519_fe_t * ha, fd_ed25519_fe_t const * fa, long na,
                    fd_ed25519_fe_t * hb, fd_ed25519_fe_t const * fb, long nb,
                    fd_ed25519_fe_t * hc, fd_ed25519_fe_t const * fc, long nc,
                    fd_ed25519_fe_t * hd, fd_ed25519_fe_t const * fd, long nd );

FD_PROTOTYPES_END

