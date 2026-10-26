#include "../fd_bls.h"
#include "fd_bls_g1.h"
#include "fd_bls_hash.h"
#include "fd_bls_g2.h"
#include "fd_bls_final.h"
#include "fd_bls_constants.h"

static int
fp_is_zero( fd_bls_fp_t const * a ) {
  fd_bls_fp_t z; fd_bls_fp_zero( &z );
  return fd_bls_fp_equal( a, &z );
}

static int
fp_is_one( fd_bls_fp_t const * a ) {
  fd_bls_fp_t one; fd_bls_fp_one( &one );
  return fd_bls_fp_equal( a, &one );
}

static void
fp_to_blst( blst_fp * out, fd_bls_fp_t const * in ) {
  ulong u[6]; fd_bls_fp_to_uint64( u, in ); blst_fp_from_uint64( out, u );
}

static void
pub_from_affine( fd_bls_pub_t * out, blst_p1_affine const * in ) {
  if( FD_UNLIKELY( blst_p1_affine_is_inf( in ) ) ) { fd_memset( out, 0, sizeof(*out) ); return; }
  fd_bls_fp_from_mont_batch( &out->x, (ulong const *)in, 2 ); fd_bls_fp_one( &out->z );
}

static void
pub_to_rns_affine( fd_bls_g1_rns_affine_t * out, fd_bls_pub_t const * in ) {
  out->x=in->x; out->y=in->y;
  if( FD_UNLIKELY( !fp_is_one( &in->z ) ) ) {
    ulong u[6], ui[6]; fd_bls_fp_to_uint64( u, &in->z ); fd_bls_fp_inv_canon( ui, u );
    fd_bls_fp_t zi; fd_bls_fp_from_uint64(&zi,ui); fd_bls_fp_mul(&out->x,&out->x,&zi); fd_bls_fp_mul(&out->y,&out->y,&zi);
  }
}

static void
sig_to_rns_affine( fd_bls_g2_rns_affine_t * out, fd_bls_sig_t const * in ) {
  out->x=in->x; out->y=in->y; fd_bls_fp2_t one; fd_bls_fp2_one(&one);
  if( FD_UNLIKELY( !fd_bls_fp2_equal(&in->z,&one) ) ) { fd_bls_fp2_t zi; fd_bls_fp2_inverse(&zi,&in->z); fd_bls_fp2_mul(&out->x,&out->x,&zi); fd_bls_fp2_mul(&out->y,&out->y,&zi); }
}

static void
hash_from_affine( fd_bls_hash_t * out, blst_p2_affine const * in ) {
  fd_bls_fp_from_mont_batch( &out->x.c[0], (ulong const *)in, 4 );
}

static void
hash_to_affine( blst_p2_affine * out, fd_bls_hash_t const * in ) {
  fp_to_blst( &out->x.fp[0], &in->x.c[0] ); fp_to_blst( &out->x.fp[1], &in->x.c[1] );
  fp_to_blst( &out->y.fp[0], &in->y.c[0] ); fp_to_blst( &out->y.fp[1], &in->y.c[1] );
}

static void
sig_from_affine( fd_bls_sig_t * out, blst_p2_affine const * in ) {
  if( FD_UNLIKELY( blst_p2_affine_is_inf( in ) ) ) { fd_memset( out, 0, sizeof(*out) ); return; }
  hash_from_affine( (fd_bls_hash_t *)out, in ); fd_bls_fp2_one( &out->z );
}

static void
be48_from_limbs( uchar out[48], ulong const l[6] ) {
  for( int i=0; i<6; i++ ) {
    ulong v = l[5-i];
    for( int b=0; b<8; b++ ) out[8*i+b] = (uchar)( v >> (56-8*b) );
  }
}

/* blst sgn0_pty_mod_384 "pty" bit: canonical y > (p-1)/2. */
static int
fp_canon_is_big( ulong const y[6] ) {
  ulong borrow = 0UL, top = y[5]>>63;
  for( int i=0; i<6; i++ ) {
    ulong yi = (y[i]<<1) | (i ? y[i-1]>>63 : 0UL);
    ulong pi = fd_bls_field_modulus_limbs[i];
    ulong d  = yi - pi;
    borrow   = (ulong)( (yi < pi) | (d < borrow) );
  }
  return (int)( top | (borrow^1UL) );
}

/* Affine canonical limbs of a projective G1 point; returns 0 for the
   identity. */
static int
pub_affine_canon( ulong x[6], ulong y[6], fd_bls_pub_t const * in ) {
  if( FD_UNLIKELY( fp_is_zero( &in->z ) ) ) return 0;
  fd_bls_fp_t ax = in->x, ay = in->y;
  if( FD_UNLIKELY( !fp_is_one( &in->z ) ) ) {
    ulong u[6], ui[6]; fd_bls_fp_t zinv;
    fd_bls_fp_to_uint64( u, &in->z ); fd_bls_fp_inv_canon( ui, u ); fd_bls_fp_from_uint64( &zinv, ui );
    fd_bls_fp_mul( &ax, &ax, &zinv ); fd_bls_fp_mul( &ay, &ay, &zinv );
  }
  fd_bls_fp_to_uint64( x, &ax ); fd_bls_fp_to_uint64( y, &ay );
  return 1;
}

/* Affine canonical limbs of a projective G2 point (x0,x1,y0,y1); returns 0
   for the identity. */
static int
sig_affine_canon( ulong l[4][6], fd_bls_sig_t const * in ) {
  if( FD_UNLIKELY( fp_is_zero( &in->z.c[0] ) && fp_is_zero( &in->z.c[1] ) ) ) return 0;
  fd_bls_fp2_t ax = in->x, ay = in->y, one; fd_bls_fp2_one( &one );
  if( FD_UNLIKELY( !fd_bls_fp2_equal( &in->z, &one ) ) ) {
    fd_bls_fp2_t zinv; fd_bls_fp2_inverse( &zinv, &in->z );
    fd_bls_fp2_mul( &ax, &ax, &zinv ); fd_bls_fp2_mul( &ay, &ay, &zinv );
  }
  fd_bls_fp_to_uint64( l[0], &ax.c[0] ); fd_bls_fp_to_uint64( l[1], &ax.c[1] );
  fd_bls_fp_to_uint64( l[2], &ay.c[0] ); fd_bls_fp_to_uint64( l[3], &ay.c[1] );
  return 1;
}

static int
limbs_are_zero( ulong const l[6] ) { return !(l[0]|l[1]|l[2]|l[3]|l[4]|l[5]); }

/* --- secret keys --- */

void
fd_bls_sec_to_pub( fd_bls_sec_t const * sec,
                   fd_bls_pub_t *       pub ) {
  blst_p1 p; blst_p1_affine a; blst_sk_to_pk_in_g1( &p, sec ); blst_p1_to_affine( &a, &p ); pub_from_affine( pub, &a );
}

void
fd_bls_sec_derive( fd_bls_sec_t * sec,
                   uchar const *  ikm,
                   ulong          ikm_sz ) {
  FD_TEST( ikm_sz>=32UL );
  blst_keygen( sec, ikm, ikm_sz, NULL, 0UL );
}

void
fd_bls_sec_sign( fd_bls_sec_t const * sec,
                 uchar const *        msg,
                 ulong                msg_sz,
                 fd_bls_sig_t *       sig ) {
  fd_bls_hash_t hash_native; blst_p2_affine hash_affine; blst_p2 hash, out; blst_p2_affine out_affine;
  fd_bls_hash_msg( msg, msg_sz, &hash_native ); hash_to_affine( &hash_affine, &hash_native );
  blst_p2_from_affine( &hash, &hash_affine ); blst_sign_pk_in_g1( &out, &hash, sec );
  blst_p2_to_affine( &out_affine, &out ); sig_from_affine( sig, &out_affine );
}


/* --- public keys (G1) --- */

void
fd_bls_pub_compress( fd_bls_pub_t const * pub,
                     uchar                buf[ static FD_BLS_PUB_COMPRESSED_SZ ] ) {
  ulong x[6], y[6];
  if( FD_UNLIKELY( !pub_affine_canon( x, y, pub ) ) ) {         /* blst_p1_affine_compress of infinity */
    fd_memset( buf, 0, FD_BLS_PUB_COMPRESSED_SZ ); buf[0] = 0xc0; return;
  }
  be48_from_limbs( buf, x );
  buf[0] |= (uchar)( 0x80 | ( fp_canon_is_big( y ) << 5 ) );
}

void
fd_bls_pub_add( fd_bls_pub_t *       out,
                fd_bls_pub_t const * a,
                fd_bls_pub_t const * b ) {
  if( FD_UNLIKELY( fd_bls_pub_is_inf( a ) ) ) { *out = *b; return; }
  if( FD_UNLIKELY( fd_bls_pub_is_inf( b ) ) ) { *out = *a; return; }
  fd_bls_pub_t q = *b; *out = *a; fd_bls_g1_add( &out->x, &q.x );
}

void
fd_bls_pub_neg( fd_bls_pub_t *       out,
                fd_bls_pub_t const * a ) {
  *out = *a; fd_bls_fp_neg( &out->y, &out->y );
}

int
fd_bls_pub_is_inf( fd_bls_pub_t const * pub ) {
  return fp_is_zero( &pub->z );
}

int
fd_bls_pub_eq( fd_bls_pub_t const * a,
                   fd_bls_pub_t const * b ) {
  if( fd_bls_pub_is_inf( a ) | fd_bls_pub_is_inf( b ) ) return fd_bls_pub_is_inf( a ) & fd_bls_pub_is_inf( b );
  fd_bls_fp_t ax,bx,ay,by; fd_bls_fp_mul( &ax,&a->x,&b->z ); fd_bls_fp_mul( &bx,&b->x,&a->z );
  fd_bls_fp_mul( &ay,&a->y,&b->z ); fd_bls_fp_mul( &by,&b->y,&a->z ); return fd_bls_fp_equal(&ax,&bx)&fd_bls_fp_equal(&ay,&by);
}

static void
fd_bls_pub_add_many( fd_bls_pub_t *               out,
                     fd_bls_pub_t const * const * pubs,
                     ulong                        pub_cnt ) {
  fd_bls_g1_sum_batch( out, pubs, pub_cnt );
}

void
fd_bls_pub_sum( fd_bls_pub_t *       out,
                fd_bls_pub_t const * pubs,
                fd_bls_set_t const * set ) {
  fd_bls_pub_t const * pub_ptr[ FD_BLS_SET_MAX ];
  ulong                pub_cnt = 0UL;
  for( ulong rank = fd_bls_set_const_iter_init( set );
                   !fd_bls_set_const_iter_done( rank );
             rank = fd_bls_set_const_iter_next( set, rank ) )
    pub_ptr[ pub_cnt++ ] = pubs+rank;
  fd_bls_pub_add_many( out, pub_ptr, pub_cnt );
}

void
fd_bls_pub_sum_cached( fd_bls_pub_t *       out,
                       fd_bls_pub_t const * pubs,
                       ulong                pub_cnt,
                       fd_bls_set_t const * set,
                       fd_bls_pub_t const * full ) {
  if( FD_LIKELY( !full || 2UL*fd_bls_set_cnt( set )<=pub_cnt ) ) {
    fd_bls_pub_sum( out, pubs, set );
    return;
  }

  fd_bls_pub_t const * missing[ FD_BLS_SET_MAX ];
  ulong                missing_cnt = 0UL;
  for( ulong rank=0UL; rank<pub_cnt; rank++ )
    if( !fd_bls_set_test( set, rank ) ) missing[ missing_cnt++ ] = pubs+rank;
  fd_bls_pub_add_many( out, missing, missing_cnt );
  fd_bls_pub_neg( out, out );
  fd_bls_pub_add( out, full, out );
}

/* --- signatures (G2) --- */

void
fd_bls_sig_ser( fd_bls_sig_t const * sig,
                uchar                buf[ static FD_BLS_SIG_SZ ] ) {
  ulong l[4][6];
  if( FD_UNLIKELY( !sig_affine_canon( l, sig ) ) ) {            /* blst_p2_affine_serialize of infinity */
    fd_memset( buf, 0, FD_BLS_SIG_SZ ); buf[0] = 0x40; return;
  }
  be48_from_limbs( buf,     l[1] ); be48_from_limbs( buf+48,  l[0] );
  be48_from_limbs( buf+96,  l[3] ); be48_from_limbs( buf+144, l[2] );
}

void
fd_bls_sig_compress( fd_bls_sig_t const * sig,
                     uchar                buf[ static FD_BLS_SIG_COMPRESSED_SZ ] ) {
  ulong l[4][6];
  if( FD_UNLIKELY( !sig_affine_canon( l, sig ) ) ) {            /* blst_p2_affine_compress of infinity */
    fd_memset( buf, 0, FD_BLS_SIG_COMPRESSED_SZ ); buf[0] = 0xc0; return;
  }
  be48_from_limbs( buf, l[1] ); be48_from_limbs( buf+48, l[0] );
  /* blst sgn0_pty_mont_384x sign: im!=0 ? big(im) : big(re). */
  int big = limbs_are_zero( l[3] ) ? fp_canon_is_big( l[2] ) : fp_canon_is_big( l[3] );
  buf[0] |= (uchar)( 0x80 | ( big << 5 ) );
}

/* Native signature decoding with exactly blst_p2_deserialize /
   blst_p2_uncompress acceptance semantics (flag bits, field range,
   infinity encodings, on-curve), followed by the native subgroup check
   where the API requires it. */

static int
fp_from_be48( ulong out[6], uchar const in[48], int clear_top3 ) {
  for( int i=0; i<6; i++ ) {
    ulong v = 0UL;
    for( int b=0; b<8; b++ ) v = (v<<8) | (ulong)in[ (5-i)*8 + b ];
    out[i] = v;
  }
  if( clear_top3 ) out[5] &= (~0UL)>>3;
  for( int i=5; i>=0; i-- ) {                                   /* value < p ? */
    if( out[i]<fd_bls_field_modulus_limbs[i] ) return 1;
    if( out[i]>fd_bls_field_modulus_limbs[i] ) return 0;
  }
  return 0;
}

static int
bytes_are_zero( uchar const * b, ulong sz ) {
  uchar acc = 0;
  for( ulong i=0UL; i<sz; i++ ) acc |= b[i];
  return !acc;
}

#define SIG_DECODE_OK   (0)
#define SIG_DECODE_INF  (1)
#define SIG_DECODE_FAIL (-1)

/* blst_p2_uncompress on a 96-byte compressed encoding. */
static int
sig_decode_compressed( fd_bls_sig_t * sig, uchar const in[96] ) {
  uchar in0 = in[0];
  if( FD_UNLIKELY( !(in0 & 0x80) ) ) return SIG_DECODE_FAIL;
  if( FD_UNLIKELY( in0 & 0x40 ) ) {
    if( !(in0 & 0x3f) && bytes_are_zero( in+1, 95UL ) ) return SIG_DECODE_INF;
    return SIG_DECODE_FAIL;
  }
  ulong x_im[6], x_re[6];
  if( FD_UNLIKELY( !fp_from_be48( x_im, in,    1 ) ) ) return SIG_DECODE_FAIL;
  if( FD_UNLIKELY( !fp_from_be48( x_re, in+48, 0 ) ) ) return SIG_DECODE_FAIL;
  if( FD_UNLIKELY( fd_bls_g2_decompress_rns( &sig->x, &sig->y, x_re, x_im, (in0>>5)&1 ) ) ) return SIG_DECODE_FAIL;
  fd_bls_fp2_one( &sig->z );
  return SIG_DECODE_OK;
}

/* blst_p2_deserialize on a 192-byte encoding. */
static int
sig_decode( fd_bls_sig_t * sig, uchar const in[192] ) {
  uchar in0 = in[0];
  if( (in0 & 0xe0)==0 ) {
    ulong l[4][6];
    if( FD_UNLIKELY( !fp_from_be48( l[0], in,     1 ) ) ) return SIG_DECODE_FAIL; /* x.im */
    if( FD_UNLIKELY( !fp_from_be48( l[1], in+48,  0 ) ) ) return SIG_DECODE_FAIL; /* x.re */
    if( FD_UNLIKELY( !fp_from_be48( l[2], in+96,  0 ) ) ) return SIG_DECODE_FAIL; /* y.im */
    if( FD_UNLIKELY( !fp_from_be48( l[3], in+144, 0 ) ) ) return SIG_DECODE_FAIL; /* y.re */
    fd_bls_fp_from_uint64( &sig->x.c[1], l[0] );
    fd_bls_fp_from_uint64( &sig->x.c[0], l[1] );
    fd_bls_fp_from_uint64( &sig->y.c[1], l[2] );
    fd_bls_fp_from_uint64( &sig->y.c[0], l[3] );
    fd_bls_fp2_t xxx, yy, t;                                   /* y^2 == x^3 + 4(1+u) ? */
    fd_bls_fp2_sqr( &t, &sig->x );
    fd_bls_fp2_mul( &xxx, &t, &sig->x );
    fd_bls_fp_t four; fd_bls_fp_mul_small( &four, &fd_bls_one, 4U );
    fd_bls_fp_add( &xxx.c[0], &xxx.c[0], &four );
    fd_bls_fp_add( &xxx.c[1], &xxx.c[1], &four );
    fd_bls_fp2_sqr( &yy, &sig->y );
    if( FD_UNLIKELY( !fd_bls_fp2_equal( &xxx, &yy ) ) ) return SIG_DECODE_FAIL;
    fd_bls_fp2_one( &sig->z );
    return SIG_DECODE_OK;
  }
  if( in0 & 0x80 ) return sig_decode_compressed( sig, in );
  if( (in0 & 0x40) && !(in0 & 0x3f) && bytes_are_zero( in+1, 191UL ) ) return SIG_DECODE_INF;
  return SIG_DECODE_FAIL;
}

static int
sig_decode_finish( fd_bls_sig_t * sig, int rc, int check ) {
  if( FD_UNLIKELY( rc==SIG_DECODE_FAIL ) ) return -1;
  if( FD_UNLIKELY( rc==SIG_DECODE_INF ) ) { fd_memset( sig, 0, sizeof(*sig) ); return 0; }
  if( check && FD_UNLIKELY( !fd_bls_g2_validate_affine( &sig->x, &sig->y ) ) ) return -1;
  return 0;
}

/* Native public key decoding with blst_p1_uncompress /
   blst_p1_deserialize semantics, then the native G1 subgroup check.
   fd_bls_pub_de additionally rejects the identity and (as before) any
   uncompressed encoding with the compressed, infinity or sort flag set. */
static int
pub_decode_xy( fd_bls_pub_t * pub, ulong const xl[6], ulong const * yl, int sign_bit ) {
  fd_bls_fp_from_uint64( &pub->x, xl );
  fd_bls_fp_t rhs, t;
  fd_bls_fp_mul( &t, &pub->x, &pub->x );
  fd_bls_fp_mul( &rhs, &t, &pub->x );
  fd_bls_fp_t four; fd_bls_fp_mul_small( &four, &fd_bls_one, 4U );
  fd_bls_fp_add( &rhs, &rhs, &four );                       /* x^3 + 4 */
  if( yl ) {
    fd_bls_fp_from_uint64( &pub->y, yl );
    fd_bls_fp_t yy; fd_bls_fp_mul( &yy, &pub->y, &pub->y );
    if( FD_UNLIKELY( !fd_bls_fp_equal( &yy, &rhs ) ) ) return -1;
  } else {
    if( FD_UNLIKELY( !fd_bls_fp_sqrt_rns( &pub->y, &rhs ) ) ) return -1;
    ulong yc[6]; fd_bls_fp_to_uint64( yc, &pub->y );
    /* blst sgn0 "pty" bit: y > (p-1)/2  <=>  2y >= p+1  <=>  2y > p
       (2y is even and p odd, so 2y != p). */
    ulong borrow = 0UL, top = yc[5]>>63;
    for( int i=0; i<6; i++ ) {
      ulong yi = (yc[i]<<1) | (i ? yc[i-1]>>63 : 0UL);
      ulong pi = fd_bls_field_modulus_limbs[i];
      ulong d  = yi - pi;
      borrow   = (ulong)( (yi < pi) | (d < borrow) );
    }
    int big = (int)( top | (borrow^1UL) );                   /* 2y >= p */
    if( big ^ sign_bit ) {                                    /* y <- p - y, canonical */
      ulong b2 = 0UL;
      for( int i=0; i<6; i++ ) {
        ulong pi = fd_bls_field_modulus_limbs[i], yi = yc[i];
        ulong d  = pi - yi - b2;
        b2       = (ulong)( (pi < yi) | ((pi - yi) < b2) );
        yc[i]    = d;
      }
    }
    /* Re-encode from canonical limbs so decoded keys have the same RNS
       representative as every other entry path (callers memcmp keys). */
    fd_bls_fp_from_uint64( &pub->y, yc );
  }
  fd_bls_fp_one( &pub->z );
  return 0;
}

int
fd_bls_pub_de_unchecked( fd_bls_pub_t * pub,
                         uchar const    buf[ static FD_BLS_PUB_SZ ] ) {
  fd_bls_pub_t p[1];
  ulong xl[6], yl[6];
  uchar in0 = buf[0];
  int rc;

  if( (in0 & 0xe0)==0 ) {
    if( FD_UNLIKELY( !fp_from_be48( xl, buf, 1 ) || !fp_from_be48( yl, buf+48, 0 ) ) ) return -1;
    rc = pub_decode_xy( p, xl, yl, 0 );
  } else if( in0 & 0x80 ) { /* blst_p1_deserialize also accepts a compressed point */
    if( FD_UNLIKELY( in0 & 0x40 ) ) {
      if( !(in0 & 0x3f) && bytes_are_zero( buf+1, 47UL ) ) {
        fd_memset( pub, 0, sizeof(*pub) );
        return 0;
      }
      return -1;
    }
    if( FD_UNLIKELY( !fp_from_be48( xl, buf, 1 ) ) ) return -1;
    rc = pub_decode_xy( p, xl, NULL, (in0>>5)&1 );
  } else if( (in0 & 0x40) && !(in0 & 0x3f) && bytes_are_zero( buf+1, 95UL ) ) {
    fd_memset( pub, 0, sizeof(*pub) );
    return 0;
  } else {
    return -1;
  }

  if( FD_UNLIKELY( rc || fp_is_zero( &p->x ) ) ) return -1; /* match blst's (0,+-2) rejection */
  *pub = *p;
  return 0;
}

int
fd_bls_pub_de( fd_bls_pub_t * pub,
               uchar const *  buf,
               ulong          buf_sz ) {
  fd_bls_pub_t p[1];
  ulong xl[6], yl[6];
  int rc;
  switch( buf_sz ) {
  case FD_BLS_PUB_COMPRESSED_SZ: {
    uchar in0 = buf[0];
    if( FD_UNLIKELY( !(in0 & 0x80) || (in0 & 0x40) ) ) return -1; /* not compressed, or infinity (rejected) */
    if( FD_UNLIKELY( !fp_from_be48( xl, buf, 1 ) ) ) return -1;
    rc = pub_decode_xy( p, xl, NULL, (in0>>5)&1 );
    break;
  }
  case FD_BLS_PUB_SZ:
    if( FD_UNLIKELY( buf[0] & 0xe0 ) ) return -1;                  /* compressed/infinity/sort flags */
    if( FD_UNLIKELY( !fp_from_be48( xl, buf, 1 ) || !fp_from_be48( yl, buf+48, 0 ) ) ) return -1;
    rc = pub_decode_xy( p, xl, yl, 0 );
    break;
  default: return -1;
  }
  if( FD_UNLIKELY( rc ) ) return -1;
  if( FD_UNLIKELY( fp_is_zero( &p->x ) ) ) return -1;               /* (0,+-2) is not in G1 */
  if( FD_UNLIKELY( !fd_bls_g1_in_g1_affine( &p->x, &p->y ) ) ) return -1;
  *pub = *p;
  return 0;
}

int
fd_bls_sig_de( fd_bls_sig_t * sig,
               uchar const    buf[ static FD_BLS_SIG_SZ ] ) {
  fd_bls_sig_t s[1];
  int rc = sig_decode_finish( s, sig_decode( s, buf ), 1 );
  if( FD_LIKELY( !rc ) ) *sig = *s;
  return rc;
}

int
fd_bls_sig_de_unchecked( fd_bls_sig_t * sig,
                         uchar const    buf[ static FD_BLS_SIG_SZ ] ) {
  fd_bls_sig_t s[1];
  int rc = sig_decode_finish( s, sig_decode( s, buf ), 0 );
  if( FD_LIKELY( !rc ) ) *sig = *s;
  return rc;
}

int
fd_bls_sig_de_compressed( fd_bls_sig_t * sig,
                          uchar const    buf[ static FD_BLS_SIG_COMPRESSED_SZ ] ) {
  fd_bls_sig_t s[1];
  int rc = sig_decode_finish( s, sig_decode_compressed( s, buf ), 1 );
  if( FD_LIKELY( !rc ) ) *sig = *s;
  return rc;
}

void
fd_bls_sig_add( fd_bls_sig_t *       out,
                fd_bls_sig_t const * a,
                fd_bls_sig_t const * b ) {
  if( FD_UNLIKELY( fd_bls_sig_is_inf( a ) ) ) { *out = *b; return; }
  if( FD_UNLIKELY( fd_bls_sig_is_inf( b ) ) ) { *out = *a; return; }
  /* fd_bls_sig_t and the projective layout are identical {x,y,z}; the
     addition reads both inputs before writing, so out may alias a or b. */
  fd_bls_g2_add_projective( (fd_bls_p2_projective_t *)out, (fd_bls_p2_projective_t const *)a,
                            (fd_bls_p2_projective_t const *)b );
}

void
fd_bls_sig_neg( fd_bls_sig_t *       out,
                fd_bls_sig_t const * a ) {
  *out = *a; fd_bls_fp2_neg( &out->y, &out->y );
}

int
fd_bls_sig_validate( fd_bls_sig_t const * sig ) {
  if( FD_UNLIKELY( fd_bls_sig_is_inf( sig ) ) ) return 1;
  fd_bls_g2_rns_affine_t a; sig_to_rns_affine( &a, sig );
  return fd_bls_g2_validate_affine( &a.x, &a.y );
}

int
fd_bls_sig_is_inf( fd_bls_sig_t const * sig ) {
  return fp_is_zero( &sig->z.c[0] ) & fp_is_zero( &sig->z.c[1] );
}

int
fd_bls_sig_eq( fd_bls_sig_t const * a,
               fd_bls_sig_t const * b ) {
  if( fd_bls_sig_is_inf(a) | fd_bls_sig_is_inf(b) ) return fd_bls_sig_is_inf(a)&fd_bls_sig_is_inf(b);
  fd_bls_fp2_t ax,bx,ay,by; fd_bls_fp2_mul(&ax,&a->x,&b->z); fd_bls_fp2_mul(&bx,&b->x,&a->z);
  fd_bls_fp2_mul(&ay,&a->y,&b->z); fd_bls_fp2_mul(&by,&b->y,&a->z); return fd_bls_fp2_equal(&ax,&bx)&fd_bls_fp2_equal(&ay,&by);
}

/* Sum signatures.  Affine (decoded) inputs use two alternating complete
   mixed-add chains (independent work for the out-of-order core, 11 Fp2
   products per add instead of 15), merged with one projective add.
   Mixed-representation inputs use sequential complete adds. */
static void
fd_bls_sig_add_many( fd_bls_sig_t *               out,
                     fd_bls_sig_t const * const * sigs,
                     ulong                        sig_cnt ) {
  while( sig_cnt && fd_bls_sig_is_inf( sigs[0] ) ) { sigs++; sig_cnt--; }
  if( FD_UNLIKELY( !sig_cnt ) ) { fd_memset( out, 0, sizeof(fd_bls_sig_t) ); return; }

  fd_bls_fp2_t one; fd_bls_fp2_one( &one );
  int affine = 1;
  for( ulong i=0UL; i<sig_cnt; i++ )
    affine &= fd_bls_sig_is_inf( sigs[i] ) | fd_bls_fp2_equal( &sigs[i]->z, &one );
  if( FD_UNLIKELY( !affine ) ) {
    fd_bls_sig_t acc = *sigs[0];
    for( ulong i=1UL; i<sig_cnt; i++ ) fd_bls_sig_add( &acc, &acc, sigs[i] );
    *out = acc;
    return;
  }

  /* fd_bls_sig_t and fd_bls_p2_projective_t share the {x,y,z} layout. */
  fd_bls_p2_projective_t acc[2];
  fd_memcpy( &acc[0], sigs[0], sizeof(acc[0]) );
  ulong i = 1UL;
  while( i<sig_cnt && fd_bls_sig_is_inf( sigs[i] ) ) i++;
  if( FD_UNLIKELY( i==sig_cnt ) ) { fd_memcpy( out, &acc[0], sizeof(*out) ); return; }
  fd_memcpy( &acc[1], sigs[i++], sizeof(acc[1]) );
  int lane = 0;
  for( ; i<sig_cnt; i++ ) {
    if( FD_UNLIKELY( fd_bls_sig_is_inf( sigs[i] ) ) ) continue;
    fd_bls_g2_add_affine( &acc[lane], &acc[lane], &sigs[i]->x, &sigs[i]->y );
    lane ^= 1;
  }
  fd_bls_g2_add_projective( &acc[0], &acc[0], &acc[1] );
  fd_memcpy( out, &acc[0], sizeof(*out) );
}

/* --- hash-to-curve --- */

void
fd_bls_hash_msg( uchar const *  msg,
                 ulong          msg_sz,
                 fd_bls_hash_t * hash ) {
  fd_bls_hash_to_g2( msg, msg_sz, (uchar const *)FD_BLS_DST,
                             FD_BLS_DST_SZ, hash );
}

int
fd_bls_hash_eq( fd_bls_hash_t const * a,
                fd_bls_hash_t const * b ) {
  return fd_bls_fp2_equal( &a->x, &b->x ) & fd_bls_fp2_equal( &a->y, &b->y );
}

static int
fd_bls_hash_is_inf( fd_bls_hash_t const * hash ) {
  return fp_is_zero( &hash->x.c[0] ) & fp_is_zero( &hash->x.c[1] ) & fp_is_zero( &hash->y.c[0] ) & fp_is_zero( &hash->y.c[1] );
}

fd_bls_agg_t *
fd_bls_agg_null( fd_bls_agg_t * agg ) {
  fd_memset( &agg->pub, 0, sizeof(fd_bls_pub_t) );
  fd_memset( &agg->sig, 0, sizeof(fd_bls_sig_t) );
  fd_bls_set_null( agg->set );
  return agg;
}

fd_bls_agg_t *
fd_bls_agg_construct( fd_bls_agg_t *       agg,
                      fd_bls_pub_t const * pub,
                      fd_bls_sig_t const * sig,
                      fd_bls_set_t const * set ) {
  fd_bls_pub_t const * pub_ptr[ FD_BLS_SET_MAX ];
  fd_bls_sig_t const * sig_ptr[ FD_BLS_SET_MAX ];
  ulong                cnt = 0UL;
  fd_bls_set_copy( agg->set, set );
  for( ulong rank = fd_bls_set_const_iter_init( set );
                   !fd_bls_set_const_iter_done( rank );
             rank = fd_bls_set_const_iter_next( set, rank ) ) {
    pub_ptr[ cnt ] = pub+rank;
    sig_ptr[ cnt ] = sig+rank;
    cnt++;
  }
  fd_bls_pub_add_many( &agg->pub, pub_ptr, cnt );
  fd_bls_sig_add_many( &agg->sig, sig_ptr, cnt );
  return agg;
}

static int
fd_bls_verify_hash_pair( fd_bls_hash_t const * h,
                         fd_bls_pub_t const *  pub,
                         fd_bls_hash_t const * h_fallback,
                         fd_bls_pub_t const *  pub_fallback,
                         fd_bls_sig_t const *  sig ) {
  ulong pair_cnt = 1UL + !!pub_fallback;
  if( FD_UNLIKELY( fd_bls_hash_is_inf( h ) || fd_bls_pub_is_inf( pub ) ||
                   (pub_fallback && (fd_bls_hash_is_inf( h_fallback ) || fd_bls_pub_is_inf( pub_fallback ))) ||
                   fd_bls_sig_is_inf( sig ) ) ) return 0;

  fd_bls_g1_rns_affine_t p[3]; fd_bls_g2_rns_affine_t q[3];
  pub_to_rns_affine( p, pub ); q[0]=*(fd_bls_g2_rns_affine_t const *)h;
  if( pub_fallback ) { pub_to_rns_affine( p+1, pub_fallback ); q[1]=*(fd_bls_g2_rns_affine_t const *)h_fallback; }
  p[pair_cnt]=(fd_bls_g1_rns_affine_t){ fd_bls_neg_g1_x, fd_bls_neg_g1_y };
  sig_to_rns_affine( q+pair_cnt, sig );
  return fd_bls_pairing_finalverify_rns( p, q, pair_cnt+1UL )==1;
}

int
fd_bls_agg_verify_hashed( fd_bls_hash_t const * h,
                          fd_bls_pub_t const *  pub,
                          fd_bls_sig_t const *  sig ) {
  return fd_bls_verify_hash_pair( h, pub, NULL, NULL, sig );
}

int
fd_bls_agg_verify( uchar const *        msg,
                   ulong                msg_sz,
                   fd_bls_pub_t const * pub,
                   fd_bls_sig_t const * sig ) {
  fd_bls_hash_t h[1];
  fd_bls_hash_msg( msg, msg_sz, h );
  return fd_bls_agg_verify_hashed( h, pub, sig );
}

int
fd_bls_agg_verify_pair( uchar const *        msg,
                        ulong                msg_sz,
                        fd_bls_pub_t const * pub,
                        uchar const *        msg_fallback,
                        ulong                msg_fallback_sz,
                        fd_bls_pub_t const * pub_fallback,
                        fd_bls_sig_t const * sig ) {
  if( FD_UNLIKELY( !msg_fallback || !pub_fallback ) ) return 0;
  fd_bls_hash_t h[1], h_fallback[1];
  fd_bls_hash_msg( msg,          msg_sz,          h );
  fd_bls_hash_msg( msg_fallback, msg_fallback_sz, h_fallback );
  return fd_bls_verify_hash_pair( h, pub, h_fallback, pub_fallback, sig );
}

/* GT value of the aggregate e(pub,h)*e(-g1,sig) (identity factors skipped);
   the aggregate is valid iff it is one and neither point is the identity. */
static void
fd_bls_agg_gt( fd_bls_fp12_t *       gt,
               fd_bls_hash_t const * h,
               fd_bls_pub_t const *  pub,
               fd_bls_sig_t const *  sig ) {
  fd_bls_g1_rns_affine_t p[2]; fd_bls_g2_rns_affine_t q[2]; ulong cnt = 0UL;
  if( FD_LIKELY( !fd_bls_pub_is_inf( pub ) ) ) {
    pub_to_rns_affine( p+cnt, pub ); q[cnt] = *(fd_bls_g2_rns_affine_t const *)h; cnt++;
  }
  if( FD_LIKELY( !fd_bls_sig_is_inf( sig ) ) ) {
    p[cnt] = (fd_bls_g1_rns_affine_t){ fd_bls_neg_g1_x, fd_bls_neg_g1_y };
    sig_to_rns_affine( q+cnt, sig ); cnt++;
  }
  if( FD_UNLIKELY( !cnt ) ) { fd_bls_fp12_one( gt ); return; }
  FD_TEST( fd_bls_pairing_rns( gt, p, q, cnt )==1 );
}

static int
fd_bls_agg_gt_ok( fd_bls_fp12_t const * gt,
                  fd_bls_pub_t const *  pub,
                  fd_bls_sig_t const *  sig ) {
  return fd_bls_fp12_is_one( gt ) && !fd_bls_pub_is_inf( pub ) && !fd_bls_sig_is_inf( sig );
}

/* The parent GT value factors as left*right.  Compute the left aggregate's
   GT value once, derive right = parent/left with a cyclotomic conjugate
   (inversion in GT) and one Fp12 multiply, and recurse into every invalid
   half.  Each tree node costs one pairing, and scattered bad signers never
   fall back to a linear scan. */
static void
fd_bls_agg_bisect_run( fd_bls_hash_t const *      h,
                       fd_bls_pub_t const * const pub[],
                       fd_bls_sig_t const * const sig[],
                       ushort const *             rank,
                       ulong                      lo,
                       ulong                      hi,
                       fd_bls_pub_t const *       sum_pub,
                       fd_bls_sig_t const *       sum_sig,
                       fd_bls_fp12_t const *      gt,
                       fd_bls_set_t *             bad ) {
  if( FD_UNLIKELY( hi-lo==1UL ) ) { fd_bls_set_insert( bad, rank[lo] ); return; }
  ulong mid = lo + (hi-lo)/2UL;

  fd_bls_pub_t lpub, hpub; fd_bls_sig_t lsig, hsig;
  fd_bls_pub_add_many( &lpub, pub+lo, mid-lo );
  fd_bls_sig_add_many( &lsig, sig+lo, mid-lo );
  fd_bls_pub_neg( &hpub, &lpub ); fd_bls_pub_add( &hpub, &hpub, sum_pub );
  fd_bls_sig_neg( &hsig, &lsig ); fd_bls_sig_add( &hsig, &hsig, sum_sig );

  fd_bls_fp12_t lgt, hgt;
  fd_bls_agg_gt( &lgt, h, &lpub, &lsig );
  hgt = lgt;
  for( int i=6; i<12; i++ ) fd_bls_fp_neg( &hgt.c[i], &hgt.c[i] ); /* lgt^-1 */
  fd_bls_fp12_mul( &hgt, &hgt, gt );                                /* parent/left */

  int l_ok = fd_bls_agg_gt_ok( &lgt, &lpub, &lsig );
  int h_ok = fd_bls_agg_gt_ok( &hgt, &hpub, &hsig );
  if( FD_UNLIKELY( !l_ok ) ) fd_bls_agg_bisect_run( h, pub, sig, rank, lo, mid, &lpub, &lsig, &lgt, bad );
  if( FD_UNLIKELY( !h_ok ) ) fd_bls_agg_bisect_run( h, pub, sig, rank, mid, hi, &hpub, &hsig, &hgt, bad );
}

static fd_bls_set_t *
fd_bls_agg_verify_bisect( fd_bls_agg_t const *  agg,
                          fd_bls_hash_t const * h,
                          fd_bls_fp12_t const * gt,
                          fd_bls_pub_t const *  pub,
                          fd_bls_sig_t const *  sig,
                          fd_bls_set_t *        bad ) {
  fd_bls_set_null( bad );
  ulong cnt = fd_bls_set_cnt( agg->set );
  if( FD_UNLIKELY( !cnt ) ) return bad;
  fd_bls_pub_t const * pubs [ FD_BLS_SET_MAX ];
  fd_bls_sig_t const * sigs [ FD_BLS_SET_MAX ];
  ushort               ranks[ FD_BLS_SET_MAX ];
  ulong n = 0UL;
  for( ulong r = fd_bls_set_const_iter_init( agg->set );
            !fd_bls_set_const_iter_done( r );
         r = fd_bls_set_const_iter_next( agg->set, r ) ) {
    pubs[n] = pub+r; sigs[n] = sig+r; ranks[n] = (ushort)r; n++;
  }
  fd_bls_agg_bisect_run( h, pubs, sigs, ranks, 0UL, n, &agg->pub, &agg->sig, gt, bad );
  return bad;
}

int
fd_bls_agg_verify_subtract( fd_bls_agg_t *       agg,
                            uchar const *        msg,
                            ulong                msg_sz,
                            fd_bls_pub_t const * pub,
                            fd_bls_sig_t const * sig,
                            fd_bls_set_t *       bad ) {
  fd_bls_hash_t h; fd_bls_fp12_t gt;
  fd_bls_hash_msg( msg, msg_sz, &h );
  fd_bls_agg_gt( &gt, &h, &agg->pub, &agg->sig );
  if( FD_LIKELY( fd_bls_agg_gt_ok( &gt, &agg->pub, &agg->sig ) ) ) { fd_bls_set_null( bad ); return 0; }
  fd_bls_agg_verify_bisect( agg, &h, &gt, pub, sig, bad );
  fd_bls_agg_t sub = { 0 };
  fd_bls_agg_construct( &sub, pub, sig, bad );
  fd_bls_pub_neg( &sub.pub, &sub.pub ); fd_bls_pub_add( &agg->pub, &agg->pub, &sub.pub );
  fd_bls_sig_neg( &sub.sig, &sub.sig ); fd_bls_sig_add( &agg->sig, &agg->sig, &sub.sig );
  fd_bls_set_subtract( agg->set, agg->set, bad );
  if( FD_UNLIKELY( fd_bls_pub_is_inf( &agg->pub ) ) ) return -1;
  return 0;
}
