#include "fd_bls_rns.h"
#include "fd_bls_field.h"
#include "fd_bls_miller.h"
#include "fd_bls_final.h"
#include "../fd_bls.h"
#include "../../../util/fd_util.h"
#include "../../../third_party/blst/bindings/blst.h"

#if FD_HAS_THREADS
#include <pthread.h>
#endif

static long
median101( long t[101] ) {
  for( int i=1; i<101; i++ ) for( int j=i; j && t[j-1]>t[j]; j-- ) {
    long tmp=t[j-1]; t[j-1]=t[j]; t[j]=tmp;
  }
  return t[50];
}

static void
expect( fd_bls_fp_t const * x,
        ulong const           m1[8],
        ulong const           m2[8] ) {
  ulong got1[8] __attribute__((aligned(64)));
  ulong got2[8] __attribute__((aligned(64)));
  wwv_st( got1, x->m1 );
  wwv_st( got2, x->m2 );
  FD_TEST( !memcmp( got1, m1, 8UL*sizeof(ulong) ) );
  FD_TEST( !memcmp( got2, m2, 8UL*sizeof(ulong) ) );
}

static void
to_blst_fp12( blst_fp12 *             out,
              fd_bls_fp12_t const * in ) {
  for( int i=0; i<12; i++ ) {
    ulong normal[6];
    fd_bls_fp_to_uint64( normal, &in->c[i] );
    blst_fp_from_uint64( ((blst_fp *)out)+i, normal );
  }
}

static void
hash_to_blst( blst_p2_affine * out, fd_bls_hash_t const * in ) {
  ulong u[6];
  fd_bls_fp_to_uint64( u, &in->x.c[0] ); blst_fp_from_uint64( &out->x.fp[0], u );
  fd_bls_fp_to_uint64( u, &in->x.c[1] ); blst_fp_from_uint64( &out->x.fp[1], u );
  fd_bls_fp_to_uint64( u, &in->y.c[0] ); blst_fp_from_uint64( &out->y.fp[0], u );
  fd_bls_fp_to_uint64( u, &in->y.c[1] ); blst_fp_from_uint64( &out->y.fp[1], u );
}

static void
from_blst_fp12( fd_bls_fp12_t * out,
                blst_fp12 const * in ) {
  for( int i=0; i<12; i++ ) {
    ulong normal[6];
    blst_uint64_from_fp( normal, ((blst_fp const *)in)+i );
    fd_bls_fp_from_uint64( &out->c[i], normal );
  }
}

static void
normal_g1_from_blst( fd_bls_g1_affine_t * out,
                     blst_p1_affine const * in ) {
  blst_uint64_from_fp( out->x, &in->x );
  blst_uint64_from_fp( out->y, &in->y );
}

static void
normal_g2_from_blst( fd_bls_g2_affine_t * out,
                     blst_p2_affine const * in ) {
  blst_uint64_from_fp( out->x[0], &in->x.fp[0] );
  blst_uint64_from_fp( out->x[1], &in->x.fp[1] );
  blst_uint64_from_fp( out->y[0], &in->y.fp[0] );
  blst_uint64_from_fp( out->y[1], &in->y.fp[1] );
}

/* sgn0 of an Fp2 element (RFC 9380 section 4.1). */

static int
fp2_sgn0( blst_fp2 const * a ) {
  ulong re[6], im[6];
  blst_uint64_from_fp( re, &a->fp[0] );
  blst_uint64_from_fp( im, &a->fp[1] );
  int re_zero = !(re[0]|re[1]|re[2]|re[3]|re[4]|re[5]);
  return (int)( (re[0]&1UL) | (ulong)( re_zero & (int)(im[0]&1UL) ) );
}

/* map_to_curve on SSWU collision pairs: u0 != u1 with
   map_to_curve(u0) == map_to_curve(u1), so the E' addition of the two
   images is a doubling of distinct Jacobian representatives.  Regression:
   the doubling test used to compare U2-U1 against zero with
   fd_bls_fp_equal, whose 40p redundancy window misses the +40p offset of
   an fp_sub output, and returned the point at infinity instead of 2P. */

static void
test_map_to_curve_collisions( void ) {
  ulong const two[6] = { 2UL,0UL,0UL,0UL,0UL,0UL };
  ulong const one[6] = { 1UL,0UL,0UL,0UL,0UL,0UL };
  blst_fp2 z;                                                /* Z = -(2+u) */
  blst_fp_from_uint64( &z.fp[0], two ); blst_fp_cneg( &z.fp[0], &z.fp[0], 1 );
  blst_fp_from_uint64( &z.fp[1], one ); blst_fp_cneg( &z.fp[1], &z.fp[1], 1 );
  blst_fp2 z_inv; blst_fp2_inverse( &z_inv, &z );
  blst_fp2 one2; fd_memset( &one2, 0, sizeof(one2) ); blst_fp_from_uint64( &one2.fp[0], one );

  ulong prng = 0x452821e638d01377UL;
  ulong found = 0UL;
  for( ulong tried=0UL; tried<4096UL && found<32UL; tried++ ) {
    ulong l[2][6];
    for( int j=0; j<2; j++ ) for( int k=0; k<6; k++ ) {
      prng = prng*0x9e3779b97f4a7c15UL + 0xda942042e4dd58b5UL;
      l[j][k] = prng;
    }
    l[0][5] &= 0x0fffffffffffffffUL; l[1][5] &= 0x0fffffffffffffffUL;   /* < p */
    blst_fp2 u0, t0, t1, u1sq, u1;
    blst_fp_from_uint64( &u0.fp[0], l[0] ); blst_fp_from_uint64( &u0.fp[1], l[1] );
    /* Z*u1^2 = -1 - Z*u0^2 makes the SSWU denominators agree */
    blst_fp2_sqr( &t0, &u0 ); blst_fp2_mul( &t0, &t0, &z );
    blst_fp2_add( &t1, &t0, &one2 ); blst_fp2_cneg( &t1, &t1, 1 );
    blst_fp2_mul( &u1sq, &t1, &z_inv );
    if( !blst_fp2_sqrt( &u1, &u1sq ) ) continue;
    if( fp2_sgn0( &u1 )!=fp2_sgn0( &u0 ) ) blst_fp2_cneg( &u1, &u1, 1 );
    blst_p2 m0, m1;
    blst_map_to_g2( &m0, &u0, NULL );
    blst_map_to_g2( &m1, &u1, NULL );
    if( !blst_p2_is_equal( &m0, &m1 ) ) continue;
    found++;

    fd_bls_fp2_t u[2];
    blst_fp2 const * uu[2] = { &u0, &u1 };
    for( int i=0; i<2; i++ ) for( int j=0; j<2; j++ ) {
      ulong normal[6];
      blst_uint64_from_fp( normal, &uu[i]->fp[j] );
      fd_bls_fp_from_uint64( &u[i].c[j], normal );
    }
    fd_bls_hash_t got[1];
    fd_bls_hash_to_g2_from_field( got, u );
    blst_p2 ref; blst_map_to_g2( &ref, &u0, &u1 );
    blst_p2_affine ref_aff; blst_p2_to_affine( &ref_aff, &ref );
    blst_p2_affine got_aff; hash_to_blst( &got_aff, got );
    FD_TEST( blst_p2_affine_is_equal( &got_aff, &ref_aff ) );
  }
  FD_TEST( found>=8UL );
}

/* ---- Differential tests of the public fd_bls API against blst ----

   Every public operation is cross-checked against the reference (blst)
   semantics: accept/reject decisions of all deserializers and verifiers,
   and byte-exact serialized/compressed outputs of every produced point.
   These are representation-independent, so they keep holding while the
   internal field/curve arithmetic is restructured. */

static void
rand_bytes( fd_rng_t * rng,
            uchar *    buf,
            ulong      sz ) {
  for( ulong i=0UL; i<sz; i++ ) buf[ i ] = fd_rng_uchar( rng );
}

static void
rand_fp( fd_rng_t * rng,
         blst_fp *  out ) {
  ulong l[6];
  for( int i=0; i<6; i++ ) l[i] = fd_rng_ulong( rng );
  l[5] &= 0x0fffffffffffffffUL; /* < p */
  blst_fp_from_uint64( out, l );
}

static int
ref_pub_de( blst_p1_affine * out,
            uchar const *    in,
            ulong            in_sz ) {
  BLST_ERROR err;
  switch( in_sz ) {
  case FD_BLS_PUB_COMPRESSED_SZ: err = blst_p1_uncompress( out, in ); break;
  case FD_BLS_PUB_SZ:
    if( in[0]&0xA0U ) return 0;
    err = blst_p1_deserialize( out, in );
    break;
  default: return 0;
  }
  return err==BLST_SUCCESS && !blst_p1_affine_is_inf( out ) && blst_p1_affine_in_g1( out );
}

static void
check_pub( fd_bls_pub_t const * pub,
           blst_p1 const *      ref ) {
  blst_p1_affine a; blst_p1_to_affine( &a, ref );
  uchar want[ 48 ], got[ 48 ];
  blst_p1_affine_compress( want, &a );
  fd_bls_pub_compress( pub, got );
  FD_TEST( !memcmp( want, got, sizeof(want) ) );
  FD_TEST( fd_bls_pub_is_inf( pub )==!!blst_p1_is_inf( ref ) );
}

static void
check_sig( fd_bls_sig_t const * sig,
           blst_p2 const *      ref ) {
  blst_p2_affine a; blst_p2_to_affine( &a, ref );
  uchar want[ 192 ], got[ 192 ];
  blst_p2_affine_serialize( want, &a );
  fd_bls_sig_ser( sig, got );
  FD_TEST( !memcmp( want, got, 192UL ) );
  blst_p2_affine_compress( want, &a );
  fd_bls_sig_compress( sig, got );
  FD_TEST( !memcmp( want, got, 96UL ) );
  FD_TEST( fd_bls_sig_is_inf( sig )==!!blst_p2_is_inf( ref ) );
}

static ulong diff_cnt[ 2 ][ 3 ]; /* [accepted][pub_de,sig_de,sig_de_c] */

static void
diff_pub_de( uchar const * buf,
             ulong         sz ) {
  blst_p1_affine ra; fd_bls_pub_t got;
  int want = ref_pub_de( &ra, buf, sz );
  int ok   = fd_bls_pub_de( &got, buf, sz )==0;
  FD_TEST( ok==want );
  diff_cnt[ ok ][ 0 ]++;
  if( ok ) { blst_p1 rp; blst_p1_from_affine( &rp, &ra ); check_pub( &got, &rp ); }

  if( sz==FD_BLS_PUB_SZ ) {
    blst_p1_affine rua;
    int want_u = blst_p1_deserialize( &rua, buf )==BLST_SUCCESS;
    int ok_u   = fd_bls_pub_de_unchecked( &got, buf )==0;
    FD_TEST( ok_u==want_u );
    if( ok_u ) { blst_p1 rp; blst_p1_from_affine( &rp, &rua ); check_pub( &got, &rp ); }
  }
}

static void
diff_sig_de( uchar const buf[ 192 ] ) {
  blst_p2_affine ra; fd_bls_sig_t got; blst_p2 rp;
  int want = blst_p2_deserialize( &ra, buf )==BLST_SUCCESS;
  int ok_u = fd_bls_sig_de_unchecked( &got, buf )==0;
  FD_TEST( ok_u==want );
  if( ok_u ) {
    blst_p2_from_affine( &rp, &ra );
    check_sig( &got, &rp );
    FD_TEST( fd_bls_sig_validate( &got )==!!blst_p2_affine_in_g2( &ra ) );
  }
  want = want && blst_p2_affine_in_g2( &ra );
  int ok = fd_bls_sig_de( &got, buf )==0;
  FD_TEST( ok==want );
  diff_cnt[ ok ][ 1 ]++;
  if( ok ) check_sig( &got, &rp );
}

static void
diff_sig_de_c( uchar const buf[ 96 ] ) {
  blst_p2_affine ra; fd_bls_sig_t got;
  int want = blst_p2_uncompress( &ra, buf )==BLST_SUCCESS && blst_p2_affine_in_g2( &ra );
  int ok   = fd_bls_sig_de_compressed( &got, buf )==0;
  FD_TEST( ok==want );
  diff_cnt[ ok ][ 2 ]++;
  if( ok ) { blst_p2 rp; blst_p2_from_affine( &rp, &ra ); check_sig( &got, &rp ); }
}

static void
flip_bit( fd_rng_t * rng,
          uchar *    buf,
          ulong      sz ) {
  buf[ fd_rng_ulong_roll( rng, sz ) ] ^= (uchar)( 1U << fd_rng_uint_roll( rng, 8U ) );
}

#define DIFF_KEY_CNT (8UL)
#define DIFF_MSG_CNT (12UL)

static void
test_api_differential( fd_rng_t * rng ) {
  static uchar const dst[] = FD_BLS_DST;
  blst_scalar  sk [ DIFF_KEY_CNT ];
  blst_p1      rpk[ DIFF_KEY_CNT ];
  fd_bls_sec_t fsk[ DIFF_KEY_CNT ];
  fd_bls_pub_t fpk[ DIFF_KEY_CNT ];

  for( ulong i=0UL; i<DIFF_KEY_CNT; i++ ) {
    uchar ikm[ 32 ]; rand_bytes( rng, ikm, sizeof(ikm) );
    blst_keygen( sk+i, ikm, sizeof(ikm), NULL, 0UL );
    fd_bls_sec_derive( fsk+i, ikm, sizeof(ikm) );
    FD_TEST( !memcmp( sk+i, fsk+i, sizeof(blst_scalar) ) );
    blst_sk_to_pk_in_g1( rpk+i, sk+i );
    fd_bls_sec_to_pub( fsk+i, fpk+i );
    check_pub( fpk+i, rpk+i );

    blst_p1_affine a; blst_p1_to_affine( &a, rpk+i );
    uchar ser[ 128 ], comp[ 48 ];
    fd_memset( ser, 0, sizeof(ser) );
    blst_p1_affine_serialize( ser, &a );
    blst_p1_affine_compress( comp, &a );
    diff_pub_de( ser, 96UL );
    diff_pub_de( comp, 48UL );
    fd_bls_pub_t t;
    FD_TEST( !fd_bls_pub_de( &t, comp, 48UL ) && fd_bls_pub_eq( &t, fpk+i ) );
    FD_TEST( !memcmp( &t, fpk+i, sizeof(t) ) );  /* representation is deterministic */
    FD_TEST( !fd_bls_pub_de( &t, ser,  96UL ) && fd_bls_pub_eq( &t, fpk+i ) );
    FD_TEST( !memcmp( &t, fpk+i, sizeof(t) ) );
    for( ulong k=0UL; k<4UL; k++ ) {
      uchar s2[ 96 ]; fd_memcpy( s2, ser,  96UL ); flip_bit( rng, s2, 96UL ); diff_pub_de( s2, 96UL );
      uchar c2[ 48 ]; fd_memcpy( c2, comp, 48UL ); flip_bit( rng, c2, 48UL ); diff_pub_de( c2, 48UL );
    }
    uchar c3[ 48 ]; fd_memcpy( c3, comp, 48UL ); c3[0] ^= 0x20; diff_pub_de( c3, 48UL ); /* -P */
    for( ulong sz=0UL; sz<=sizeof(ser); sz++ )
      if( sz!=48UL && sz!=96UL ) FD_TEST( fd_bls_pub_de( &t, ser, sz )==-1 );
  }

  uchar msg[ 2 ][ 1024 ];
  for( ulong trial=0UL; trial<DIFF_MSG_CNT; trial++ ) {
    ulong        sz[2];
    blst_p2      rh[2], rsig[2];
    fd_bls_hash_t fh[2];
    fd_bls_sig_t fsig[2];
    ulong        ki[2] = { fd_rng_ulong_roll( rng, DIFF_KEY_CNT ), fd_rng_ulong_roll( rng, DIFF_KEY_CNT ) };
    for( ulong m=0UL; m<2UL; m++ ) {
      if( trial==0UL && m==0UL ) sz[m] = 0UL;
      else if( trial==1UL && m==0UL ) sz[m] = 1000UL;
      else sz[m] = 1UL+fd_rng_ulong_roll( rng, 256UL );
      rand_bytes( rng, msg[m], sz[m] );
      if( m==1UL ) msg[1][0] = (uchar)( (sz[0] ? msg[0][0] : 0) ^ 0x5a ); /* distinct from msg[0] */
      blst_hash_to_g2( rh+m, msg[m], sz[m], dst, sizeof(dst)-1UL, NULL, 0UL );
      fd_bls_hash_msg( msg[m], sz[m], fh+m );
      blst_p2_affine ha, ga; blst_p2_to_affine( &ha, rh+m ); hash_to_blst( &ga, fh+m );
      FD_TEST( blst_p2_affine_is_equal( &ha, &ga ) );
      FD_TEST( fd_bls_hash_eq( fh+m, fh+m ) );

      blst_sign_pk_in_g1( rsig+m, rh+m, sk+ki[m] );
      fd_bls_sec_sign( fsk+ki[m], msg[m], sz[m], fsig+m );
      check_sig( fsig+m, rsig+m );
      FD_TEST( fd_bls_sig_validate( fsig+m ) );

      blst_p2_affine sa; blst_p2_to_affine( &sa, rsig+m );
      uchar ser[ 192 ], comp[ 96 ];
      blst_p2_affine_serialize( ser, &sa ); blst_p2_affine_compress( comp, &sa );
      diff_sig_de( ser ); diff_sig_de_c( comp );
      fd_bls_sig_t ts;
      FD_TEST( !fd_bls_sig_de_compressed( &ts, comp ) && fd_bls_sig_eq( &ts, fsig+m ) );
      FD_TEST( !memcmp( &ts, fsig+m, sizeof(ts) ) ); /* representation is deterministic */
      FD_TEST( !fd_bls_sig_de( &ts, ser ) && fd_bls_sig_eq( &ts, fsig+m ) );
      FD_TEST( !memcmp( &ts, fsig+m, sizeof(ts) ) );
      { uchar c192[ 192 ]; fd_memset( c192, 0, sizeof(c192) ); fd_memcpy( c192, comp, 96UL ); /* compressed inside 192B */
        FD_TEST( !fd_bls_sig_de( &ts, c192 ) && !memcmp( &ts, fsig+m, sizeof(ts) ) ); }
      for( ulong k=0UL; k<2UL; k++ ) {
        uchar s2[ 192 ]; fd_memcpy( s2, ser,  192UL ); flip_bit( rng, s2, 192UL ); diff_sig_de( s2 );
        uchar c2[ 96 ];  fd_memcpy( c2, comp, 96UL );  flip_bit( rng, c2, 96UL );  diff_sig_de_c( c2 );
      }
      uchar c3[ 96 ]; fd_memcpy( c3, comp, 96UL ); c3[0] ^= 0x20; diff_sig_de_c( c3 ); /* -S */
      uchar s3[ 192 ]; rand_bytes( rng, s3, 192UL ); fd_memcpy( s3, comp, 96UL ); diff_sig_de( s3 ); /* compressed in 192B */
    }
    FD_TEST( !fd_bls_hash_eq( fh, fh+1 ) );

    ulong i = ki[0], j = ki[1];
    FD_TEST( fd_bls_agg_verify( msg[0], sz[0], fpk+i, fsig )==1 );
    FD_TEST( fd_bls_agg_verify_hashed( fh, fpk+i, fsig )==1 );
    FD_TEST( fd_bls_agg_verify_hashed( fh+1, fpk+j, fsig+1 )==1 );
    FD_TEST( fd_bls_agg_verify( msg[1], sz[1], fpk+i, fsig )==0 );                       /* wrong message */
    FD_TEST( fd_bls_agg_verify( msg[0], sz[0], fpk+(i+1UL)%DIFF_KEY_CNT, fsig )==0 );   /* wrong key     */
    FD_TEST( fd_bls_agg_verify( msg[0], sz[0], fpk+i, fsig+1 )==0 );                     /* wrong sig     */

    fd_bls_sig_t fagg; blst_p2 ragg;
    fd_bls_sig_add( &fagg, fsig, fsig+1 ); blst_p2_add_or_double( &ragg, rsig, rsig+1 ); check_sig( &fagg, &ragg );
    FD_TEST( fd_bls_sig_validate( &fagg ) );
    FD_TEST( fd_bls_agg_verify_pair( msg[0], sz[0], fpk+i, msg[1], sz[1], fpk+j, &fagg )==1 );
    FD_TEST( fd_bls_agg_verify_pair( msg[1], sz[1], fpk+j, msg[0], sz[0], fpk+i, &fagg )==1 );
    FD_TEST( fd_bls_agg_verify_pair( msg[0], sz[0], fpk+j, msg[1], sz[1], fpk+i, &fagg )==(i==j) );
    FD_TEST( fd_bls_agg_verify_pair( msg[0], sz[0], fpk+i, msg[1], sz[1], fpk+j, fsig )==0 );
    FD_TEST( fd_bls_agg_verify_pair( msg[0], sz[0], fpk+i, NULL, 0UL, fpk+j, &fagg )==0 );
    FD_TEST( fd_bls_agg_verify_pair( msg[0], sz[0], fpk+i, msg[1], sz[1], NULL, &fagg )==0 );

    /* Projective (z!=1) operands through add/double, verify and validate. */
    fd_bls_sig_t fs2; blst_p2 rs2;
    fd_bls_sig_add( &fs2, fsig, fsig ); blst_p2_add_or_double( &rs2, rsig, rsig ); check_sig( &fs2, &rs2 );
    fd_bls_pub_t fp2; blst_p1 rp2;
    fd_bls_pub_add( &fp2, fpk+i, fpk+i ); blst_p1_add_or_double( &rp2, rpk+i, rpk+i ); check_pub( &fp2, &rp2 );
    FD_TEST( fd_bls_agg_verify( msg[0], sz[0], &fp2, &fs2 )==1 );
    FD_TEST( fd_bls_agg_verify( msg[0], sz[0], &fp2, fsig )==0 );
    FD_TEST( fd_bls_sig_validate( &fs2 ) );
    fd_bls_sig_t fs3; blst_p2 rs3;
    fd_bls_sig_add( &fs3, &fs2, &fagg ); blst_p2_add_or_double( &rs3, &rs2, &ragg ); check_sig( &fs3, &rs3 );
    fd_bls_sig_add( &fs3, &fs3, &fs3 ); blst_p2_add_or_double( &rs3, &rs3, &rs3 ); check_sig( &fs3, &rs3 );

    /* Negation and the identity. */
    fd_bls_sig_t fneg, finf, ft;
    fd_bls_sig_neg( &fneg, fsig ); fd_bls_sig_add( &finf, fsig, &fneg );
    blst_p2 rneg = rsig[0]; blst_p2_cneg( &rneg, 1 ); check_sig( &fneg, &rneg );
    blst_p2 rinf; blst_p2_add_or_double( &rinf, rsig, &rneg ); check_sig( &finf, &rinf );
    FD_TEST( fd_bls_sig_is_inf( &finf ) );
    FD_TEST( fd_bls_sig_validate( &finf ) );
    FD_TEST( fd_bls_agg_verify( msg[0], sz[0], fpk+i, &finf )==0 );
    fd_bls_sig_add( &ft, &finf, fsig ); check_sig( &ft, rsig );
    fd_bls_sig_add( &ft, fsig, &finf ); check_sig( &ft, rsig );
    fd_bls_sig_add( &ft, &fs2, &fneg ); check_sig( &ft, rsig ); /* 2S-S, projective minus affine */
    fd_bls_pub_t fpn, fpinf, fpt;
    fd_bls_pub_neg( &fpn, fpk+i ); fd_bls_pub_add( &fpinf, fpk+i, &fpn );
    blst_p1 rpn = rpk[i]; blst_p1_cneg( &rpn, 1 ); check_pub( &fpn, &rpn );
    blst_p1 rpinf; blst_p1_add_or_double( &rpinf, rpk+i, &rpn ); check_pub( &fpinf, &rpinf );
    FD_TEST( fd_bls_pub_is_inf( &fpinf ) );
    FD_TEST( fd_bls_agg_verify( msg[0], sz[0], &fpinf, fsig )==0 );
    fd_bls_pub_add( &fpt, &fp2, &fpn ); check_pub( &fpt, rpk+i ); /* 2P-P */
    FD_TEST( fd_bls_agg_verify( msg[0], sz[0], &fpt, fsig )==1 );

    fd_bls_pub_t fps; blst_p1 rps;
    fd_bls_pub_add( &fps, fpk+i, fpk+j ); blst_p1_add_or_double( &rps, rpk+i, rpk+j ); check_pub( &fps, &rps );
    fd_bls_pub_add( &fps, &fps, &fp2 );   blst_p1_add_or_double( &rps, &rps, &rp2 );   check_pub( &fps, &rps );
    FD_TEST( fd_bls_pub_eq( &fp2, &fp2 ) ); FD_TEST( !fd_bls_pub_eq( &fp2, fpk+i ) ); FD_TEST( fd_bls_pub_eq( &fpt, fpk+i ) );
    FD_TEST( fd_bls_sig_eq( &fs2, &fs2 ) ); FD_TEST( !fd_bls_sig_eq( &fs2, fsig ) );
  }

  /* pub_sum over random subsets (affine and projective inputs), aggregate
     construction, and bad-signer isolation. */
  uchar m[ 32 ]; rand_bytes( rng, m, sizeof(m) );
  uchar m_bad[ 32 ]; fd_memcpy( m_bad, m, sizeof(m) ); m_bad[ 7 ] ^= 1;
  fd_bls_sig_t fsig[ DIFF_KEY_CNT ];
  fd_bls_pub_t fpkp[ DIFF_KEY_CNT ];
  blst_p1      rpkp[ DIFF_KEY_CNT ];
  for( ulong i=0UL; i<DIFF_KEY_CNT; i++ ) {
    fd_bls_sec_sign( fsk+i, m, sizeof(m), fsig+i );
    fd_bls_pub_add( fpkp+i, fpk+i, fpk+i ); blst_p1_add_or_double( rpkp+i, rpk+i, rpk+i );
  }
  fd_bls_set_t full_set[ fd_bls_set_word_cnt ]; fd_bls_set_range( full_set, 0UL, DIFF_KEY_CNT );
  fd_bls_pub_t full, fullp;
  fd_bls_pub_sum( &full,  fpk,  full_set );
  fd_bls_pub_sum( &fullp, fpkp, full_set );
  for( ulong trial=0UL; trial<8UL; trial++ ) {
    fd_bls_set_t set[ fd_bls_set_word_cnt ]; fd_bls_set_null( set );
    blst_p1 rsum, rsump; fd_memset( &rsum, 0, sizeof(rsum) ); fd_memset( &rsump, 0, sizeof(rsump) );
    for( ulong i=0UL; i<DIFF_KEY_CNT; i++ ) {
      if( trial>=2UL && !fd_rng_uint_roll( rng, 2U ) ) continue;
      if( trial==0UL && i ) continue; /* single element */
      fd_bls_set_insert( set, i );
      blst_p1_add_or_double( &rsum,  &rsum,  rpk+i  );
      blst_p1_add_or_double( &rsump, &rsump, rpkp+i );
    }
    fd_bls_pub_t fsum;
    fd_bls_pub_sum(        &fsum, fpk,  set );                         check_pub( &fsum, &rsum  );
    fd_bls_pub_sum_cached( &fsum, fpk,  DIFF_KEY_CNT, set, &full  );   check_pub( &fsum, &rsum  );
    fd_bls_pub_sum_cached( &fsum, fpk,  DIFF_KEY_CNT, set, NULL   );   check_pub( &fsum, &rsum  );
    fd_bls_pub_sum(        &fsum, fpkp, set );                         check_pub( &fsum, &rsump );
    fd_bls_pub_sum_cached( &fsum, fpkp, DIFF_KEY_CNT, set, &fullp );   check_pub( &fsum, &rsump );
  }
  {
    fd_bls_set_t set[ fd_bls_set_word_cnt ]; fd_bls_set_null( set );
    fd_bls_pub_t fsum; fd_bls_pub_sum( &fsum, fpk, set ); FD_TEST( fd_bls_pub_is_inf( &fsum ) );
  }

  /* Batched aggregate summation (two mixed-add chains in G1 and G2) against
     sequential complete additions and blst: odd/even counts, identity
     entries in any position, cancellation to the identity, and the
     projective-input fallback. */
  {
    ulong const  M = 11UL;
    fd_bls_pub_t bp[ 11 ]; fd_bls_sig_t bs[ 11 ];
    blst_p1      rp[ 11 ]; blst_p2      rs[ 11 ];
    for( ulong t=0UL; t<64UL; t++ ) {
      for( ulong i=0UL; i<M; i++ ) {
        ulong k = fd_rng_ulong_roll( rng, DIFF_KEY_CNT );
        bp[i] = fpk[k]; rp[i] = rpk[k];
        bs[i] = fsig[k];
        { uchar sb[ 192 ]; fd_bls_sig_ser( fsig+k, sb ); blst_p2_affine a; FD_TEST( blst_p2_deserialize( &a, sb )==BLST_SUCCESS ); blst_p2_from_affine( &rs[i], &a ); }
        uint mode = fd_rng_uint_roll( rng, 8U );
        if( mode==0U ) { fd_memset( &bp[i], 0, sizeof(bp[i]) ); fd_memset( &rp[i], 0, sizeof(rp[i]) );
                         fd_memset( &bs[i], 0, sizeof(bs[i]) ); fd_memset( &rs[i], 0, sizeof(rs[i]) ); }      /* identity */
        if( mode==1U && t>=32UL ) { fd_bls_pub_add( &bp[i], &bp[i], &bp[i] ); blst_p1_add_or_double( &rp[i], &rp[i], &rp[i] );
                                    fd_bls_sig_add( &bs[i], &bs[i], &bs[i] ); blst_p2_add_or_double( &rs[i], &rs[i], &rs[i] ); } /* projective */
        if( mode==2U && i ) { bp[i] = bp[i-1]; rp[i] = rp[i-1]; bs[i] = bs[i-1]; rs[i] = rs[i-1];
                              fd_bls_pub_neg( &bp[i], &bp[i] ); blst_p1_cneg( &rp[i], 1 );
                              fd_bls_sig_neg( &bs[i], &bs[i] ); blst_p2_cneg( &rs[i], 1 ); }                         /* cancels previous */
      }
      fd_bls_set_t set[ fd_bls_set_word_cnt ]; fd_bls_set_null( set );
      ulong cnt = t<M+1UL ? t : 1UL+fd_rng_ulong_roll( rng, M );
      for( ulong i=0UL; i<cnt; i++ ) fd_bls_set_insert( set, i );
      fd_bls_agg_t agg[1]; fd_bls_agg_construct( agg, bp, bs, set );
      blst_p1 ep; blst_p2 es; fd_memset( &ep, 0, sizeof(ep) ); fd_memset( &es, 0, sizeof(es) );
      fd_bls_pub_t qp; fd_bls_sig_t qs; fd_memset( &qp, 0, sizeof(qp) ); fd_memset( &qs, 0, sizeof(qs) );
      for( ulong i=0UL; i<cnt; i++ ) {
        blst_p1_add_or_double( &ep, &ep, &rp[i] ); blst_p2_add_or_double( &es, &es, &rs[i] );
        fd_bls_pub_add( &qp, &qp, &bp[i] );        fd_bls_sig_add( &qs, &qs, &bs[i] );
      }
      check_pub( &agg->pub, &ep ); check_sig( &agg->sig, &es );
      FD_TEST( fd_bls_pub_eq( &agg->pub, &qp ) && fd_bls_sig_eq( &agg->sig, &qs ) );
      fd_bls_pub_t sp; fd_bls_pub_sum( &sp, bp, set ); check_pub( &sp, &ep );
    }
  }

  fd_bls_set_t all[ fd_bls_set_word_cnt ]; fd_bls_set_null( all );
  for( ulong i=0UL; i<DIFF_KEY_CNT; i++ ) fd_bls_set_insert( all, i );
  fd_bls_agg_t agg[1];
  fd_bls_set_t bad[ fd_bls_set_word_cnt ];
  fd_bls_agg_construct( agg, fpk, fsig, all );
  FD_TEST( fd_bls_agg_verify( m, sizeof(m), &agg->pub, &agg->sig )==1 );
  FD_TEST( fd_bls_agg_verify_subtract( agg, m, sizeof(m), fpk, fsig, bad )==0 );
  FD_TEST( fd_bls_set_cnt( bad )==0UL && fd_bls_set_cnt( agg->set )==DIFF_KEY_CNT );

  fd_bls_sig_t sigs[ DIFF_KEY_CNT ];
  for( ulong i=0UL; i<DIFF_KEY_CNT; i++ ) sigs[ i ] = fsig[ i ];
  fd_bls_sec_sign( fsk+1, m_bad, sizeof(m_bad), sigs+1 );
  fd_bls_sec_sign( fsk+5, m_bad, sizeof(m_bad), sigs+5 );
  fd_bls_agg_construct( agg, fpk, sigs, all );
  FD_TEST( fd_bls_agg_verify( m, sizeof(m), &agg->pub, &agg->sig )==0 );
  FD_TEST( fd_bls_agg_verify_subtract( agg, m, sizeof(m), fpk, sigs, bad )==0 );
  FD_TEST( fd_bls_set_cnt( bad )==2UL && fd_bls_set_test( bad, 1UL ) && fd_bls_set_test( bad, 5UL ) );
  FD_TEST( fd_bls_set_cnt( agg->set )==DIFF_KEY_CNT-2UL );
  FD_TEST( fd_bls_agg_verify( m, sizeof(m), &agg->pub, &agg->sig )==1 );
}

static void
be_from_limbs( uchar out[ 48 ],
               ulong const l[ 6 ] ) {
  for( int i=0; i<48; i++ ) out[ i ] = (uchar)( l[ 5-i/8 ] >> (8*(7-(i%8))) );
}

static void
test_api_invalid_encodings( fd_rng_t * rng ) {
  uchar buf[ 192 ];

  /* G1: random compressed encodings (about half on the curve, none in
     G1, about a fifth with x>=p) and random flag/data combinations. */
  for( ulong t=0UL; t<64UL; t++ ) {
    rand_bytes( rng, buf, 48UL ); buf[0] = (uchar)( (buf[0]&0x3f) | 0x80 );
    diff_pub_de( buf, 48UL );
  }
  for( ulong t=0UL; t<32UL; t++ ) {
    rand_bytes( rng, buf, 96UL ); diff_pub_de( buf, 96UL ); diff_pub_de( buf, 48UL );
    buf[0] &= 0x1f; diff_pub_de( buf, 96UL );
  }
  /* G1: on-curve points outside G1. */
  ulong const four[6] = { 4UL, 0UL, 0UL, 0UL, 0UL, 0UL };
  blst_fp b1; blst_fp_from_uint64( &b1, four );
  for( ulong found=0UL, t=0UL; found<48UL && t<1024UL; t++ ) {
    blst_p1_affine a; blst_fp rhs;
    rand_fp( rng, &a.x );
    blst_fp_sqr( &rhs, &a.x ); blst_fp_mul( &rhs, &rhs, &a.x ); blst_fp_add( &rhs, &rhs, &b1 );
    if( !blst_fp_sqrt( &a.y, &rhs ) ) continue;
    FD_TEST( blst_p1_affine_on_curve( &a ) && !blst_p1_affine_in_g1( &a ) );
    found++;
    blst_p1_affine_serialize( buf, &a ); diff_pub_de( buf, 96UL );
    blst_p1_affine_compress( buf, &a );  diff_pub_de( buf, 48UL );
    buf[0] ^= 0x20;                      diff_pub_de( buf, 48UL );
    /* Cofactor-cleared multiple (in G1): must be accepted. */
    blst_p1 pj, pc; blst_p1_from_affine( &pj, &a );
    uchar const h_eff[8] = { 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0xd2 }; /* 1-z, little endian */
    blst_p1_mult( &pc, &pj, h_eff, 64UL );
    blst_p1_affine ac; blst_p1_to_affine( &ac, &pc );
    if( !blst_p1_affine_is_inf( &ac ) ) {
      FD_TEST( blst_p1_affine_in_g1( &ac ) );
      blst_p1_affine_serialize( buf, &ac ); diff_pub_de( buf, 96UL );
      blst_p1_affine_compress( buf, &ac );  diff_pub_de( buf, 48UL );
    }
  }
  /* G1: x=p, x=p-1 boundaries and identity encodings. */
  uchar p_be[ 48 ]; be_from_limbs( p_be, fd_bls_field_modulus_limbs );
  fd_memcpy( buf, p_be, 48UL ); buf[0] |= 0x80; diff_pub_de( buf, 48UL ); buf[0] |= 0x20; diff_pub_de( buf, 48UL );
  fd_memcpy( buf, p_be, 48UL ); buf[47]--; buf[0] |= 0x80; diff_pub_de( buf, 48UL );
  fd_memcpy( buf, p_be, 48UL ); fd_memcpy( buf+48, p_be, 48UL ); diff_pub_de( buf, 96UL );
  fd_memset( buf, 0, 96UL ); buf[0] = 0xc0; diff_pub_de( buf, 48UL ); diff_pub_de( buf, 96UL );
  buf[0] = 0x40; diff_pub_de( buf, 96UL ); diff_pub_de( buf, 48UL );
  buf[0] = 0x00; diff_pub_de( buf, 96UL ); buf[0] = 0x80; diff_pub_de( buf, 48UL );
  buf[0] = 0xc0; buf[47] = 1; diff_pub_de( buf, 48UL );

  /* G2: random encodings. */
  for( ulong t=0UL; t<64UL; t++ ) {
    rand_bytes( rng, buf, 96UL ); buf[0] = (uchar)( (buf[0]&0x3f) | 0x80 );
    diff_sig_de_c( buf );
  }
  for( ulong t=0UL; t<32UL; t++ ) {
    rand_bytes( rng, buf, 192UL ); diff_sig_de( buf ); diff_sig_de_c( buf );
    buf[0] &= 0x1f; diff_sig_de( buf );
  }
  /* G2: on-curve points outside G2 (affine and projective). */
  blst_fp2 b2; blst_fp_from_uint64( &b2.fp[0], four ); blst_fp_from_uint64( &b2.fp[1], four );
  for( ulong found=0UL, t=0UL; found<24UL && t<1024UL; t++ ) {
    blst_p2_affine a; blst_fp2 rhs;
    rand_fp( rng, &a.x.fp[0] ); rand_fp( rng, &a.x.fp[1] );
    blst_fp2_sqr( &rhs, &a.x ); blst_fp2_mul( &rhs, &rhs, &a.x ); blst_fp2_add( &rhs, &rhs, &b2 );
    if( !blst_fp2_sqrt( &a.y, &rhs ) ) continue;
    FD_TEST( blst_p2_affine_on_curve( &a ) && !blst_p2_affine_in_g2( &a ) );
    found++;
    blst_p2_affine_serialize( buf, &a ); diff_sig_de( buf );
    fd_bls_sig_t s, s2; blst_p2 rp, rp2;
    FD_TEST( !fd_bls_sig_de_unchecked( &s, buf ) );
    blst_p2_from_affine( &rp, &a );
    fd_bls_sig_add( &s2, &s, &s ); blst_p2_add_or_double( &rp2, &rp, &rp ); check_sig( &s2, &rp2 );
    FD_TEST( fd_bls_sig_validate( &s2 )==!!blst_p2_in_g2( &rp2 ) );
    FD_TEST( !fd_bls_sig_validate( &s2 ) );
    blst_p2_affine_compress( buf, &a ); diff_sig_de_c( buf );
    buf[0] ^= 0x20; diff_sig_de_c( buf );
  }
  /* G2: boundaries and identity encodings. */
  fd_memset( buf, 0, 192UL );
  fd_memcpy( buf, p_be, 48UL ); buf[0] |= 0x80; diff_sig_de_c( buf );
  fd_memset( buf, 0, 192UL ); fd_memcpy( buf+48, p_be, 48UL ); buf[0] |= 0x80; diff_sig_de_c( buf );
  fd_memset( buf, 0, 192UL ); fd_memcpy( buf+144, p_be, 48UL ); diff_sig_de( buf );
  fd_memset( buf, 0, 192UL ); buf[0] = 0xc0; diff_sig_de_c( buf ); diff_sig_de( buf );
  buf[0] = 0x40; diff_sig_de( buf ); diff_sig_de_c( buf );
  buf[0] = 0x00; diff_sig_de( buf ); buf[0] = 0x80; diff_sig_de_c( buf );
  buf[0] = 0xc0; buf[95] = 1; diff_sig_de_c( buf ); diff_sig_de( buf );
  fd_memset( buf, 0, 192UL ); buf[0] = 0x40; buf[191] = 1; diff_sig_de( buf );
  fd_memset( buf, 0, 192UL ); buf[0] = 0xc0;
  { fd_bls_sig_t s; FD_TEST( !fd_bls_sig_de_compressed( &s, buf ) ); FD_TEST( fd_bls_sig_is_inf( &s ) && fd_bls_sig_validate( &s ) ); }
}

#if FD_HAS_THREADS

/* hash_msg from several threads at once must match the single-threaded
   (and blst) result.  Race regression: psi_affine (three calls in the
   cofactor clear of every hash_msg) used to build its Frobenius
   constants on first use into function-local statics guarded by a plain
   static int, so the first hash_msg calls on concurrent tiles raced on
   the flag and the constants (a C11 data race; nothing orders the flag
   store after the constant stores).  The result comparison only fails if
   a thread actually observed half-initialized constants, which is rare;
   the race itself is reported deterministically by ThreadSanitizer when
   this test and the backend are built with -fsanitize=thread.  This must
   run before anything else in the process reaches the native
   hash-to-G2 code, so that any lazy first-use initialization happens
   inside the concurrent region. */

#define HASH_CONC_THREAD_CNT (4UL)
#define HASH_CONC_MSG_CNT    (8UL)

static ulong
hash_conc_msg( ulong   t,
               uchar * msg ) {
  ulong msg_sz = 1UL + (t*7UL) % 63UL;
  for( ulong i=0UL; i<msg_sz; i++ ) msg[ i ] = (uchar)(t*31UL + i*17UL);
  return msg_sz;
}

typedef struct {
  pthread_barrier_t * start;
  fd_bls_hash_t       out[ HASH_CONC_MSG_CNT ];
} hash_conc_ctx_t;

static void *
hash_conc_main( void * _ctx ) {
  hash_conc_ctx_t * ctx = _ctx;
  int barrier_result = pthread_barrier_wait( ctx->start );
  FD_TEST( !barrier_result || barrier_result==PTHREAD_BARRIER_SERIAL_THREAD );
  for( ulong t=0UL; t<HASH_CONC_MSG_CNT; t++ ) {
    uchar msg[ 64 ];
    ulong msg_sz = hash_conc_msg( t, msg );
    fd_bls_hash_msg( msg, msg_sz, ctx->out+t );
  }
  return NULL;
}

static void
test_hash_msg_concurrent( void ) {
  static hash_conc_ctx_t ctx[ HASH_CONC_THREAD_CNT ];
  pthread_barrier_t start;
  FD_TEST( !pthread_barrier_init( &start, NULL, (uint)HASH_CONC_THREAD_CNT ) );
  pthread_t threads[ HASH_CONC_THREAD_CNT ];
  for( ulong i=0UL; i<HASH_CONC_THREAD_CNT; i++ ) {
    ctx[ i ].start = &start;
    FD_TEST( !pthread_create( &threads[ i ], NULL, hash_conc_main, &ctx[ i ] ) );
  }
  for( ulong i=0UL; i<HASH_CONC_THREAD_CNT; i++ ) FD_TEST( !pthread_join( threads[ i ], NULL ) );
  FD_TEST( !pthread_barrier_destroy( &start ) );

  for( ulong t=0UL; t<HASH_CONC_MSG_CNT; t++ ) {
    uchar msg[ 64 ];
    ulong msg_sz = hash_conc_msg( t, msg );
    fd_bls_hash_t ref[1];
    fd_bls_hash_msg( msg, msg_sz, ref );
    blst_p2 p[1]; blst_p2_affine aff[1];
    blst_hash_to_g2( p, msg, msg_sz, (uchar const *)FD_BLS_DST, FD_BLS_DST_SZ, NULL, 0UL );
    blst_p2_to_affine( aff, p );
    blst_p2_affine got; hash_to_blst( &got, ref );
    FD_TEST( blst_p2_affine_is_equal( &got, aff ) );
    for( ulong i=0UL; i<HASH_CONC_THREAD_CNT; i++ )
      FD_TEST( !memcmp( ctx[ i ].out+t, ref, sizeof(fd_bls_hash_t) ) );
  }
}

#endif /* FD_HAS_THREADS */

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );
  int bench = fd_env_strip_cmdline_contains( &argc, &argv, "--bench" );

#if FD_HAS_THREADS
  test_hash_msg_concurrent(); /* first G2 hash in the process, see above */
#endif

  ulong const a[6] = { 123456789UL, 0UL, 0UL, 0UL, 0UL, 0UL };
  ulong const b[6] = { 987654321UL, 0UL, 0UL, 0UL, 0UL, 0UL };
  ulong const a1[8] = { 76364767677820UL, 341317748576781UL, 701197476756044UL, 14189792410071UL, 214699632840735UL, 689001428834808UL, 745589276694811UL, 506767015893104UL };
  ulong const a2[8] = { 513754426342079UL, 1056553983341405UL, 1048634274480633UL, 1092973117028272UL, 823180530120069UL, 922508489854401UL, 1095903830852418UL, 150137002075864UL };
  ulong const b1[8] = { 1092133567381595UL, 593359782008167UL, 124523681674413UL, 420002951362691UL, 381097621680901UL, 371490821368839UL, 463092927381382UL, 280396628211731UL };
  ulong const b2[8] = { 519086872459755UL, 438152945194009UL, 919860490761103UL, 60900471685656UL, 110723224996835UL, 358752432548811UL, 572919953720852UL, 588188896764704UL };
  ulong const c1[8] = { 277308246776731UL, 577481257347083UL, 90959109564192UL, 725921282476275UL, 1009833741461758UL, 61104099621559UL, 580609561492213UL, 760811924845715UL };
  ulong const c2[8] = { 678563601006820UL, 89045698410381UL, 129132908732247UL, 263293375596051UL, 414115650968632UL, 503307363257033UL, 545396070234415UL, 686954640914705UL };

  fd_bls_fp_t ar, br, cr;
  fd_bls_fp_from_uint64( &ar, a );
  fd_bls_fp_from_uint64( &br, b );
  expect( &ar, a1, a2 );
  expect( &br, b1, b2 );
  ulong roundtrip[6];
  fd_bls_fp_to_uint64( roundtrip, &ar );
  FD_TEST( !memcmp( roundtrip, a, sizeof(a) ) );
  fd_bls_fp_to_uint64( roundtrip, &br );
  FD_TEST( !memcmp( roundtrip, b, sizeof(b) ) );
  fd_bls_fp_mul( &cr, &ar, &br );
  expect( &cr, c1, c2 );

  fd_bls_fp_t one, identity;
  fd_bls_fp_one( &one );
  fd_bls_fp_mul( &identity, &ar, &one );
  ulong const i1[8] = { 875909906340822UL, 360617026990273UL, 600365738960708UL, 734973616245734UL, 534266515125129UL, 904054785939657UL, 504852527554801UL, 1024953831931218UL };
  ulong const i2[8] = { 174216029891577UL, 530570771293766UL, 850971667885324UL, 73240393623386UL, 1004126063843614UL, 612427962045160UL, 494946582557490UL, 856441705901549UL };
  expect( &identity, i1, i2 );

  fd_bls_fp2_t x2, y2, z2;
  ulong n[6] = {5UL,0UL,0UL,0UL,0UL,0UL}; fd_bls_fp_from_uint64( &x2.c[0], n );
  n[0] = 2UL; fd_bls_fp_from_uint64( &x2.c[1], n );
  n[0] = 7UL; fd_bls_fp_from_uint64( &y2.c[0], n );
  n[0] = 3UL; fd_bls_fp_from_uint64( &y2.c[1], n );
  fd_bls_fp2_mul( &z2, &x2, &y2 );
  ulong znormal[6];
  fd_bls_fp_to_uint64( znormal, &z2.c[0] ); FD_TEST( znormal[0]==29UL );
  fd_bls_fp_to_uint64( znormal, &z2.c[1] ); FD_TEST( znormal[0]==29UL );
  fd_bls_fp2_sqr( &z2, &x2 );
  fd_bls_fp_to_uint64( znormal, &z2.c[0] ); FD_TEST( znormal[0]==21UL );
  fd_bls_fp_to_uint64( znormal, &z2.c[1] ); FD_TEST( znormal[0]==20UL );

  fd_bls_fp12_t x12, y12, z12;
  for( int i=0; i<12; i++ ) {
    fd_memset( n, 0, sizeof(n) ); n[0] = (ulong)(i+1);
    fd_bls_fp_from_uint64( &x12.c[i], n );
    n[0] = (ulong)(3*i+2);
    fd_bls_fp_from_uint64( &y12.c[i], n );
  }
  blst_fp12 bx, by, bref, bgot;
  to_blst_fp12( &bx, &x12 );
  to_blst_fp12( &by, &y12 );
  blst_fp12_mul( &bref, &bx, &by );
  fd_bls_fp12_mul( &z12, &x12, &y12 );
  to_blst_fp12( &bgot, &z12 );
  FD_TEST( blst_fp12_is_equal( &bref, &bgot ) );
  blst_fp12_sqr( &bref, &bx );
  fd_bls_fp12_sqr( &z12, &x12 );
  to_blst_fp12( &bgot, &z12 );
  FD_TEST( blst_fp12_is_equal( &bref, &bgot ) );
  for( ulong power=1UL; power<=3UL; power++ ) {
    blst_fp12_frobenius_map( &bref, &bx, power );
    fd_bls_fp12_frobenius( &z12, &x12, power );
    to_blst_fp12( &bgot, &z12 );
    FD_TEST( blst_fp12_is_equal( &bref, &bgot ) );
  }
  blst_fp12_inverse( &bref, &bx );
  fd_bls_fp12_inverse( &z12, &x12 );
  to_blst_fp12( &bgot, &z12 );
  FD_TEST( blst_fp12_is_equal( &bref, &bgot ) );
  fd_bls_fp12_mul( &y12, &x12, &z12 );
  FD_TEST( fd_bls_fp12_is_one( &y12 ) );
  for( ulong value=1UL; value<=32UL; value++ ) {
    for( int i=0; i<12; i++ ) fd_bls_fp_zero( &x12.c[i] );
    ulong scalar[6] = { value, 0UL, 0UL, 0UL, 0UL, 0UL };
    fd_bls_fp_from_uint64( &x12.c[0], scalar );
    to_blst_fp12( &bx, &x12 );
    blst_fp12_inverse( &bref, &bx );
    fd_bls_fp12_inverse( &z12, &x12 );
    to_blst_fp12( &bgot, &z12 );
    FD_TEST( blst_fp12_is_equal( &bref, &bgot ) );
  }

  uchar ikm[32] = {0}; ikm[0] = 7U;
  blst_scalar sk;
  blst_keygen( &sk, ikm, sizeof(ikm), NULL, 0UL );
  blst_p1 pk;
  blst_p1_affine pairing_p[2];
  blst_sk_to_pk_in_g1( &pk, &sk );
  blst_p1_to_affine( &pairing_p[0], &pk );
  blst_p1 neg_g = *blst_p1_generator();
  blst_p1_cneg( &neg_g, 1 );
  blst_p1_to_affine( &pairing_p[1], &neg_g );

  static uchar const msg[] = "avx512 bls test message A";
  static uchar const dst[] = "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";
  blst_p2 hash, sig;
  blst_p2_affine pairing_q[2];
  blst_hash_to_g2( &hash, msg, sizeof(msg)-1UL, dst, sizeof(dst)-1UL, NULL, 0UL );
  blst_p2_to_affine( &pairing_q[0], &hash );
  blst_sign_pk_in_g1( &sig, &hash, &sk );
  blst_p2_to_affine( &pairing_q[1], &sig );

  fd_bls_g1_affine_t pairing_pn[2];
  fd_bls_g2_affine_t pairing_qn[2];
  for( int i=0; i<2; i++ ) {
    normal_g1_from_blst( pairing_pn+i, pairing_p+i );
    normal_g2_from_blst( pairing_qn+i, pairing_q+i );
  }

  blst_p1_affine const * pp[2] = { &pairing_p[0], &pairing_p[1] };
  blst_p2_affine const * qq[2] = { &pairing_q[0], &pairing_q[1] };
  blst_miller_loop_n( &bref, qq, pp, 2UL );
  FD_TEST( blst_fp12_finalverify( &bref, blst_fp12_one() ) );
  blst_final_exp( &bx, &bref );
  from_blst_fp12( &x12, &bx );
  fd_bls_fp12_cyclotomic_sqr( &z12, &x12 );
  to_blst_fp12( &bgot, &z12 );
  blst_fp12_cyclotomic_sqr( &by, &bx );
  FD_TEST( blst_fp12_is_equal( &by, &bgot ) );
  for( int i=0; i<64; i++ ) {
    fd_bls_fp12_cyclotomic_sqr( &z12, &z12 );
    blst_fp12_cyclotomic_sqr( &by, &by );
    to_blst_fp12( &bgot, &z12 );
    if( FD_UNLIKELY( !blst_fp12_is_equal( &by, &bgot ) ) )
      FD_LOG_ERR(( "repeated cyclotomic square mismatch at iteration %d", i ));
  }
  FD_TEST( fd_bls_pairing_finalverify( pairing_pn, pairing_qn, 2UL )==1 );
  FD_TEST( fd_bls_pairing_finalverify_mont( pairing_p, pairing_q, 2UL )==1 );
  FD_TEST( fd_bls_pairing_finalverify_checked( pairing_pn, pairing_qn, 2UL, 2UL )==1 );
  static fd_bls_g2_prepared_t prepared[1];
  FD_TEST( fd_bls_g2_prepare( prepared, pairing_qn )==0 );
  FD_TEST( fd_bls_pairing_finalverify_prepared_checked(
               pairing_pn, prepared, pairing_pn+1, pairing_qn+1 )==1 );

  /* Find a deterministic small-x point on y^2=x^3+(4+4i).  A generic
     point on the full twist is not in its prime-order subgroup.  This
     exercises the subgroup check independently of wire decoding and of
     the pairing equation. */
  blst_fp2 curve_b = {0};
  ulong four[6] = {4UL,0UL,0UL,0UL,0UL,0UL};
  blst_fp_from_uint64( &curve_b.fp[0], four );
  blst_fp_from_uint64( &curve_b.fp[1], four );
  blst_p2_affine non_subgroup;
  fd_memset( &non_subgroup, 0, sizeof(non_subgroup) );
  int found_non_subgroup = 0;
  for( ulong xi=1UL; xi<256UL && !found_non_subgroup; xi++ ) {
    ulong x_normal[6] = {xi,0UL,0UL,0UL,0UL,0UL};
    blst_fp_from_uint64( &non_subgroup.x.fp[0], x_normal );
    blst_fp2 x2, rhs;
    blst_fp2_sqr( &x2, &non_subgroup.x );
    blst_fp2_mul( &rhs, &x2, &non_subgroup.x );
    blst_fp2_add( &rhs, &rhs, &curve_b );
    if( blst_fp2_sqrt( &non_subgroup.y, &rhs ) &&
        !blst_p2_affine_in_g2( &non_subgroup ) ) found_non_subgroup = 1;
  }
  FD_TEST( found_non_subgroup );
  FD_TEST( blst_p2_affine_on_curve( &non_subgroup ) );
  FD_TEST( !blst_p2_affine_in_g2( &non_subgroup ) );
  fd_bls_g2_affine_t checked_q;
  normal_g2_from_blst( &checked_q, &non_subgroup );
  FD_TEST( fd_bls_pairing_finalverify_checked( pairing_pn, &checked_q, 1UL, 1UL )==0 );
  FD_TEST( fd_bls_pairing_finalverify_prepared_checked(
               pairing_pn, prepared, pairing_pn+1, &checked_q )==0 );

  static uchar const bad_msg[] = "avx512 bls test message B";
  blst_hash_to_g2( &hash, bad_msg, sizeof(bad_msg)-1UL, dst, sizeof(dst)-1UL, NULL, 0UL );
  blst_p2_to_affine( &pairing_q[0], &hash );
  normal_g2_from_blst( &pairing_qn[0], &pairing_q[0] );
  FD_TEST( fd_bls_pairing_finalverify( pairing_pn, pairing_qn, 2UL )==0 );
  FD_TEST( fd_bls_pairing_finalverify_mont( pairing_p, pairing_q, 2UL )==0 );
  FD_TEST( fd_bls_g2_prepare( prepared, pairing_qn )==0 );
  FD_TEST( fd_bls_pairing_finalverify_prepared_checked(
               pairing_pn, prepared, pairing_pn+1, pairing_qn+1 )==0 );

  if( bench ) {
    /* Restore the valid hash and benchmark only the already-validated native
       pairing-product primitive. */
    blst_hash_to_g2( &hash, msg, sizeof(msg)-1UL, dst, sizeof(dst)-1UL, NULL, 0UL );
    blst_p2_to_affine( &pairing_q[0], &hash );
    normal_g2_from_blst( &pairing_qn[0], &pairing_q[0] );
    FD_TEST( fd_bls_g2_prepare( prepared, pairing_qn )==0 );
    long c_samples[101], prepared_samples[101], prepare_samples[101];
    long c_miller_samples[101], c_final_samples[101], c_isone_samples[101];
    long c_inverse_samples[101], blst_samples[101];
    for( int sample=0; sample<101; sample++ ) {
      long then = fd_log_wallclock();
      FD_TEST( fd_bls_pairing_finalverify( pairing_pn, pairing_qn, 2UL )==1 );
      c_samples[sample] = fd_log_wallclock()-then;
      then = fd_log_wallclock();
      FD_TEST( fd_bls_pairing_finalverify_prepared_checked(
                   pairing_pn, prepared, pairing_pn+1, pairing_qn+1 )==1 );
      prepared_samples[sample] = fd_log_wallclock()-then;
      then = fd_log_wallclock();
      FD_TEST( fd_bls_g2_prepare( prepared, pairing_qn )==0 );
      prepare_samples[sample] = fd_log_wallclock()-then;
      fd_bls_fp12_t m0, m1, mp, mf;
      then = fd_log_wallclock();
      fd_bls_miller_loop( &m0, &pairing_pn[0], &pairing_qn[0] );
      fd_bls_miller_loop( &m1, &pairing_pn[1], &pairing_qn[1] );
      fd_bls_fp12_mul( &mp, &m0, &m1 );
      c_miller_samples[sample] = fd_log_wallclock()-then;
      then = fd_log_wallclock();
      fd_bls_final_exp( &mf, &mp );
      c_final_samples[sample] = fd_log_wallclock()-then;
      then = fd_log_wallclock();
      FD_TEST( fd_bls_fp12_is_one( &mf ) );
      c_isone_samples[sample] = fd_log_wallclock()-then;
      then = fd_log_wallclock();
      fd_bls_fp12_inverse( &mf, &mp );
      c_inverse_samples[sample] = fd_log_wallclock()-then;
      then = fd_log_wallclock();
      blst_miller_loop_n( &bref, qq, pp, 2UL );
      FD_TEST( blst_fp12_finalverify( &bref, blst_fp12_one() ) );
      blst_samples[sample] = fd_log_wallclock()-then;
    }
    FD_LOG_NOTICE(( "pair-product median: native %.3f ms, BLST %.3f ms",
                    (double)median101( c_samples )/1e6, (double)median101( blst_samples )/1e6 ));
    FD_LOG_NOTICE(( "prepared hash pair: verify %.3f ms, one-time prepare %.3f ms",
                    (double)median101( prepared_samples )/1e6, (double)median101( prepare_samples )/1e6 ));
    FD_LOG_NOTICE(( "native split: Miller product %.3f ms, final exponent %.3f ms",
                    (double)median101( c_miller_samples )/1e6, (double)median101( c_final_samples )/1e6 ));
    FD_LOG_NOTICE(( "RNS identity check: %.3f ms", (double)median101( c_isone_samples )/1e6 ));
    FD_LOG_NOTICE(( "FP12 inverse: %.3f ms", (double)median101( c_inverse_samples )/1e6 ));
  }

  fd_bls_fp_t line[6] = { y12.c[0], y12.c[1], y12.c[2], y12.c[3], y12.c[8], y12.c[9] };
  for( int i=0; i<12; i++ ) fd_bls_fp_zero( &y12.c[i] );
  y12.c[0]=line[0]; y12.c[1]=line[1]; y12.c[2]=line[2]; y12.c[3]=line[3]; y12.c[8]=line[4]; y12.c[9]=line[5];
  to_blst_fp12( &by, &y12 );
  blst_fp12_mul( &bref, &bx, &by );
  fd_bls_fp12_mul_sparse( &z12, &x12, line );
  to_blst_fp12( &bgot, &z12 );
  FD_TEST( blst_fp12_is_equal( &bref, &bgot ) );

  /* Exercise the paired real/imaginary kernels on changing residue patterns,
     including their supported in-place forms.  Small canonical inputs still
     expand to full-width residues in both rotated RNS bases. */
  ulong prng = 0x243f6a8885a308d3UL;
  for( int iteration=0; iteration<32; iteration++ ) {
    for( int i=0; i<12; i++ ) {
      prng = prng*0x9e3779b97f4a7c15UL + 0xda942042e4dd58b5UL;
      fd_memset( n, 0, sizeof(n) ); n[0] = prng;
      fd_bls_fp_from_uint64( &x12.c[i], n );
      prng = prng*0x9e3779b97f4a7c15UL + 0xda942042e4dd58b5UL;
      n[0] = prng;
      fd_bls_fp_from_uint64( &y12.c[i], n );
    }
    to_blst_fp12( &bx, &x12 );
    to_blst_fp12( &by, &y12 );

    blst_fp12_mul( &bref, &bx, &by );
    fd_bls_fp12_mul( &x12, &x12, &y12 );
    to_blst_fp12( &bgot, &x12 );
    FD_TEST( blst_fp12_is_equal( &bref, &bgot ) );

    blst_fp12_sqr( &bref, &by );
    fd_bls_fp12_sqr( &y12, &y12 );
    to_blst_fp12( &bgot, &y12 );
    FD_TEST( blst_fp12_is_equal( &bref, &bgot ) );

    fd_bls_fp_t sparse_line[6] = {
      x12.c[0], x12.c[1], x12.c[2], x12.c[3], x12.c[8], x12.c[9]
    };
    for( int i=0; i<12; i++ ) fd_bls_fp_zero( &z12.c[i] );
    z12.c[0]=sparse_line[0]; z12.c[1]=sparse_line[1];
    z12.c[2]=sparse_line[2]; z12.c[3]=sparse_line[3];
    z12.c[8]=sparse_line[4]; z12.c[9]=sparse_line[5];
    to_blst_fp12( &bx, &x12 );
    to_blst_fp12( &by, &z12 );
    blst_fp12_mul( &bref, &bx, &by );
    fd_bls_fp12_mul_sparse( &x12, &x12, sparse_line );
    to_blst_fp12( &bgot, &x12 );
    FD_TEST( blst_fp12_is_equal( &bref, &bgot ) );
  }

  test_map_to_curve_collisions();

  /* map_to_curve on random field pairs (QR and non-QR branches of the
     sqrt_ratio select, both sign choices), and on u values with u=0 and
     zero components, against blst. */
  {
    fd_rng_t _r2[1]; fd_rng_t * r2 = fd_rng_join( fd_rng_new( _r2, 0x6d6170U, 0UL ) );
    for( ulong it=0UL; it<256UL; it++ ) {
      blst_fp2 bu[2];
      for( int i=0; i<2; i++ ) for( int j=0; j<2; j++ ) rand_fp( r2, &bu[i].fp[j] );
      if( it==0UL ) fd_memset( &bu[0], 0, sizeof(bu[0]) );
      if( it==1UL ) fd_memset( &bu[1], 0, sizeof(bu[1]) );
      if( it==2UL ) fd_memset( &bu[0].fp[1], 0, sizeof(blst_fp) );
      if( it==3UL ) fd_memset( &bu[1].fp[0], 0, sizeof(blst_fp) );
      if( it==4UL ) { fd_memset( &bu[0], 0, sizeof(bu[0]) ); fd_memset( &bu[1], 0, sizeof(bu[1]) ); }
      fd_bls_fp2_t fu[2];
      for( int i=0; i<2; i++ ) for( int j=0; j<2; j++ ) {
        ulong normal[6]; blst_uint64_from_fp( normal, &bu[i].fp[j] ); fd_bls_fp_from_uint64( &fu[i].c[j], normal );
      }
      fd_bls_hash_t got[1];
      fd_bls_hash_to_g2_from_field( got, fu );
      blst_p2 ref; blst_map_to_g2( &ref, &bu[0], &bu[1] );
      blst_p2_affine ref_aff; blst_p2_to_affine( &ref_aff, &ref );
      blst_p2_affine got_aff; hash_to_blst( &got_aff, got );
      FD_TEST( blst_p2_affine_is_equal( &got_aff, &ref_aff ) );
    }
    fd_rng_delete( fd_rng_leave( r2 ) );
  }

  fd_rng_t _rng[1]; fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, 0x5eedU, 0UL ) );

  /* Variable-time base-field inverse against blst. */
  for( ulong it=0UL; it<4096UL; it++ ) {
    ulong x[6], got[6], want[6];
    blst_fp bx; rand_fp( rng, &bx ); blst_uint64_from_fp( x, &bx );
    if( it<4UL ) { fd_memset( x, 0, sizeof(x) ); x[0] = it; }                      /* 0,1,2,3 */
    if( it==4UL ) { fd_memcpy( x, fd_bls_field_modulus_limbs, sizeof(x) ); x[0] -= 1UL; } /* p-1 */
    if( it==5UL ) { fd_memcpy( x, fd_bls_field_modulus_limbs, sizeof(x) ); x[0] -= 2UL; } /* p-2 */
    blst_fp_from_uint64( &bx, x );
    blst_fp_inverse( &bx, &bx ); blst_uint64_from_fp( want, &bx );
    fd_bls_fp_inv_canon( got, x );
    FD_TEST( !memcmp( got, want, sizeof(want) ) );
  }

  /* Export of redundant representatives: random field ops against blst,
     including values that reach the top of the 40p redundancy window
     (sums of many products before reduction, small multiples). */
  for( ulong it=0UL; it<4096UL; it++ ) {
    blst_fp ba, bb, bc; rand_fp( rng, &ba ); rand_fp( rng, &bb );
    ulong ua[6], ub[6], got[6], want[6];
    blst_uint64_from_fp( ua, &ba ); blst_uint64_from_fp( ub, &bb );
    fd_bls_fp_t fa, fb, fc;
    fd_bls_fp_from_uint64( &fa, ua ); fd_bls_fp_from_uint64( &fb, ub );
    fd_bls_fp_to_uint64( got, &fa ); FD_TEST( !memcmp( got, ua, sizeof(ua) ) );
    switch( it%6UL ) {
    case 0: fd_bls_fp_mul( &fc, &fa, &fb ); blst_fp_mul( &bc, &ba, &bb ); break;
    case 1: fd_bls_fp_add( &fc, &fa, &fb ); blst_fp_add( &bc, &ba, &bb ); break;
    case 2: fd_bls_fp_sub( &fc, &fa, &fb ); blst_fp_sub( &bc, &ba, &bb ); break;
    case 3: fd_bls_fp_mul_small( &fc, &fa, 108U ); { blst_fp t; ulong n[6]={108UL,0,0,0,0,0}; blst_fp_from_uint64( &t, n ); blst_fp_mul( &bc, &ba, &t ); } break;
    case 4: { fd_bls_fp_wide_t w; fd_bls_fp_wide_offset( &w ); blst_fp acc; fd_memset( &acc, 0, sizeof(acc) );
              for( int k=0; k<12; k++ ) { fd_bls_fp_wide_addmul( &w, &fa, &fb ); blst_fp t; blst_fp_mul( &t, &ba, &bb ); blst_fp_add( &acc, &acc, &t ); }
              fd_bls_fp_reduce_wide( &fc, &w ); bc = acc; } break;
    default: fd_bls_fp_neg( &fc, &fa ); blst_fp_cneg( &bc, &ba, 1 ); break;
    }
    blst_uint64_from_fp( want, &bc );
    fd_bls_fp_to_uint64( got, &fc ); FD_TEST( !memcmp( got, want, sizeof(want) ) );
    fd_bls_fp_t fz; fd_bls_fp_sub( &fz, &fc, &fc ); fd_bls_fp_to_uint64( got, &fz );
    FD_TEST( !(got[0]|got[1]|got[2]|got[3]|got[4]|got[5]) );
    FD_TEST( fd_bls_fp_equal( &fc, &fc ) && !fd_bls_fp_equal( &fc, &fa )==!!memcmp( want, ua, sizeof(ua) ) );
  }
  test_api_differential( rng );
  test_api_invalid_encodings( rng );
  fd_rng_delete( fd_rng_leave( rng ) );
  FD_LOG_NOTICE(( "differential decodes (accept/reject): pub_de %lu/%lu sig_de %lu/%lu sig_de_compressed %lu/%lu",
                  diff_cnt[1][0], diff_cnt[0][0], diff_cnt[1][1], diff_cnt[0][1], diff_cnt[1][2], diff_cnt[0][2] ));
  for( int i=0; i<3; i++ ) FD_TEST( diff_cnt[1][i]>=16UL && diff_cnt[0][i]>=32UL );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
