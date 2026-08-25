#include "fd_vroom_rns.h"
#include "fd_vroom_field.h"
#include "fd_vroom_miller.h"
#include "fd_vroom_final.h"
#include "../fd_vroom.h"
#include "../../../util/fd_util.h"
#include "../../../third_party/blst/bindings/blst.h"

#if FD_HAS_AVX512

static void
expect( fd_vroom_fp_t const * x,
        ulong const           m1[8],
        ulong const           m2[8] ) {
  ulong got1[8] __attribute__((aligned(64)));
  ulong got2[8] __attribute__((aligned(64)));
  _mm512_store_si512( (__m512i *)got1, x->m1 );
  _mm512_store_si512( (__m512i *)got2, x->m2 );
  FD_TEST( !memcmp( got1, m1, 8UL*sizeof(ulong) ) );
  FD_TEST( !memcmp( got2, m2, 8UL*sizeof(ulong) ) );
}

static void
to_blst_fp12( blst_fp12 *             out,
              fd_vroom_fp12_t const * in ) {
  for( int i=0; i<12; i++ ) {
    ulong normal[6];
    fd_vroom_fp_to_uint64( normal, &in->c[i] );
    blst_fp_from_uint64( ((blst_fp *)out)+i, normal );
  }
}

static void
from_blst_fp12( fd_vroom_fp12_t * out,
                blst_fp12 const * in ) {
  for( int i=0; i<12; i++ ) {
    ulong normal[6];
    blst_uint64_from_fp( normal, ((blst_fp const *)in)+i );
    fd_vroom_fp_from_uint64( &out->c[i], normal );
  }
}

static void
normal_g1_from_blst( fd_vroom_g1_affine_t * out,
                     blst_p1_affine const * in ) {
  blst_uint64_from_fp( out->x, &in->x );
  blst_uint64_from_fp( out->y, &in->y );
}

static void
normal_g2_from_blst( fd_vroom_g2_affine_t * out,
                     blst_p2_affine const * in ) {
  blst_uint64_from_fp( out->x[0], &in->x.fp[0] );
  blst_uint64_from_fp( out->x[1], &in->x.fp[1] );
  blst_uint64_from_fp( out->y[0], &in->y.fp[0] );
  blst_uint64_from_fp( out->y[1], &in->y.fp[1] );
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );
  int bench = fd_env_strip_cmdline_contains( &argc, &argv, "--bench" );

  ulong const a[6] = { 123456789UL, 0UL, 0UL, 0UL, 0UL, 0UL };
  ulong const b[6] = { 987654321UL, 0UL, 0UL, 0UL, 0UL, 0UL };
  ulong const a1[8] = { 76364767677820UL, 341317748576781UL, 701197476756044UL, 14189792410071UL, 214699632840735UL, 689001428834808UL, 745589276694811UL, 506767015893104UL };
  ulong const a2[8] = { 513754426342079UL, 1056553983341405UL, 1048634274480633UL, 1092973117028272UL, 823180530120069UL, 922508489854401UL, 1095903830852418UL, 150137002075864UL };
  ulong const b1[8] = { 1092133567381595UL, 593359782008167UL, 124523681674413UL, 420002951362691UL, 381097621680901UL, 371490821368839UL, 463092927381382UL, 280396628211731UL };
  ulong const b2[8] = { 519086872459755UL, 438152945194009UL, 919860490761103UL, 60900471685656UL, 110723224996835UL, 358752432548811UL, 572919953720852UL, 588188896764704UL };
  ulong const c1[8] = { 277308246776731UL, 577481257347083UL, 90959109564192UL, 725921282476275UL, 1009833741461758UL, 61104099621559UL, 580609561492213UL, 760811924845715UL };
  ulong const c2[8] = { 678563601006820UL, 89045698410381UL, 129132908732247UL, 263293375596051UL, 414115650968632UL, 503307363257033UL, 545396070234415UL, 686954640914705UL };

  fd_vroom_fp_t ar, br, cr;
  fd_vroom_fp_from_uint64( &ar, a );
  fd_vroom_fp_from_uint64( &br, b );
  expect( &ar, a1, a2 );
  expect( &br, b1, b2 );
  ulong roundtrip[6];
  fd_vroom_fp_to_uint64( roundtrip, &ar );
  FD_TEST( !memcmp( roundtrip, a, sizeof(a) ) );
  fd_vroom_fp_to_uint64( roundtrip, &br );
  FD_TEST( !memcmp( roundtrip, b, sizeof(b) ) );
  fd_vroom_fp_mul( &cr, &ar, &br );
  expect( &cr, c1, c2 );

  fd_vroom_fp_t one, identity;
  fd_vroom_fp_one( &one );
  fd_vroom_fp_mul( &identity, &ar, &one );
  ulong const i1[8] = { 875909906340822UL, 360617026990273UL, 600365738960708UL, 734973616245734UL, 534266515125129UL, 904054785939657UL, 504852527554801UL, 1024953831931218UL };
  ulong const i2[8] = { 174216029891577UL, 530570771293766UL, 850971667885324UL, 73240393623386UL, 1004126063843614UL, 612427962045160UL, 494946582557490UL, 856441705901549UL };
  expect( &identity, i1, i2 );

  fd_vroom_fp2_t x2, y2, z2;
  ulong n[6] = {5UL,0UL,0UL,0UL,0UL,0UL}; fd_vroom_fp_from_uint64( &x2.c[0], n );
  n[0] = 2UL; fd_vroom_fp_from_uint64( &x2.c[1], n );
  n[0] = 7UL; fd_vroom_fp_from_uint64( &y2.c[0], n );
  n[0] = 3UL; fd_vroom_fp_from_uint64( &y2.c[1], n );
  fd_vroom_fp2_mul( &z2, &x2, &y2 );
  ulong znormal[6];
  fd_vroom_fp_to_uint64( znormal, &z2.c[0] ); FD_TEST( znormal[0]==29UL );
  fd_vroom_fp_to_uint64( znormal, &z2.c[1] ); FD_TEST( znormal[0]==29UL );
  fd_vroom_fp2_sqr( &z2, &x2 );
  fd_vroom_fp_to_uint64( znormal, &z2.c[0] ); FD_TEST( znormal[0]==21UL );
  fd_vroom_fp_to_uint64( znormal, &z2.c[1] ); FD_TEST( znormal[0]==20UL );

  fd_vroom_fp12_t x12, y12, z12;
  for( int i=0; i<12; i++ ) {
    fd_memset( n, 0, sizeof(n) ); n[0] = (ulong)(i+1);
    fd_vroom_fp_from_uint64( &x12.c[i], n );
    n[0] = (ulong)(3*i+2);
    fd_vroom_fp_from_uint64( &y12.c[i], n );
  }
  blst_fp12 bx, by, bref, bgot;
  to_blst_fp12( &bx, &x12 );
  to_blst_fp12( &by, &y12 );
  blst_fp12_mul( &bref, &bx, &by );
  fd_vroom_fp12_mul( &z12, &x12, &y12 );
  to_blst_fp12( &bgot, &z12 );
  FD_TEST( blst_fp12_is_equal( &bref, &bgot ) );
  blst_fp12_sqr( &bref, &bx );
  fd_vroom_fp12_sqr( &z12, &x12 );
  to_blst_fp12( &bgot, &z12 );
  FD_TEST( blst_fp12_is_equal( &bref, &bgot ) );
  for( ulong power=1UL; power<=3UL; power++ ) {
    blst_fp12_frobenius_map( &bref, &bx, power );
    fd_vroom_fp12_frobenius_c( &z12, &x12, power );
    to_blst_fp12( &bgot, &z12 );
    FD_TEST( blst_fp12_is_equal( &bref, &bgot ) );
  }
  blst_fp12_inverse( &bref, &bx );
  fd_vroom_fp12_inverse_c( &z12, &x12 );
  to_blst_fp12( &bgot, &z12 );
  FD_TEST( blst_fp12_is_equal( &bref, &bgot ) );
  fd_vroom_fp12_mul( &y12, &x12, &z12 );
  FD_TEST( fd_vroom_fp12_is_one_c( &y12 ) );
  for( ulong value=1UL; value<=32UL; value++ ) {
    for( int i=0; i<12; i++ ) fd_vroom_fp_zero( &x12.c[i] );
    ulong scalar[6] = { value, 0UL, 0UL, 0UL, 0UL, 0UL };
    fd_vroom_fp_from_uint64( &x12.c[0], scalar );
    to_blst_fp12( &bx, &x12 );
    blst_fp12_inverse( &bref, &bx );
    fd_vroom_fp12_inverse_c( &z12, &x12 );
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

  static uchar const msg[] = "dependency-free VROOM C";
  static uchar const dst[] = "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";
  blst_p2 hash, sig;
  blst_p2_affine pairing_q[2];
  blst_hash_to_g2( &hash, msg, sizeof(msg)-1UL, dst, sizeof(dst)-1UL, NULL, 0UL );
  blst_p2_to_affine( &pairing_q[0], &hash );
  blst_sign_pk_in_g1( &sig, &hash, &sk );
  blst_p2_to_affine( &pairing_q[1], &sig );

  fd_vroom_g1_affine_t pairing_pn[2];
  fd_vroom_g2_affine_t pairing_qn[2];
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
  fd_vroom_fp12_cyclotomic_sqr( &z12, &x12 );
  to_blst_fp12( &bgot, &z12 );
  blst_fp12_cyclotomic_sqr( &by, &bx );
  FD_TEST( blst_fp12_is_equal( &by, &bgot ) );
  for( int i=0; i<64; i++ ) {
    fd_vroom_fp12_cyclotomic_sqr( &z12, &z12 );
    blst_fp12_cyclotomic_sqr( &by, &by );
    to_blst_fp12( &bgot, &z12 );
    if( FD_UNLIKELY( !blst_fp12_is_equal( &by, &bgot ) ) )
      FD_LOG_ERR(( "repeated cyclotomic square mismatch at iteration %d", i ));
  }
  FD_TEST( fd_vroom_pairing_finalverify_c( pairing_pn, pairing_qn, 2UL )==1 );
  FD_TEST( fd_vroom_pairing_finalverify_normal( pairing_pn, pairing_qn, 2UL )==1 );
  FD_TEST( fd_vroom_pairing_finalverify( pairing_p, pairing_q, 2UL )==1 );
  FD_TEST( fd_vroom_pairing_finalverify_checked( pairing_p, pairing_q, 2UL, 2UL )==1 );
  static fd_vroom_g2_prepared_t prepared[1];
  FD_TEST( fd_vroom_g2_prepare_normal( prepared, pairing_qn )==0 );
  FD_TEST( fd_vroom_pairing_finalverify_prepared_normal_checked(
               pairing_pn, prepared, pairing_pn+1, pairing_qn+1 )==1 );
  FD_TEST( fd_vroom_g2_prepare( prepared, pairing_q )==0 );
  FD_TEST( fd_vroom_pairing_finalverify_prepared_checked(
               pairing_p, prepared, pairing_p+1, pairing_q+1 )==1 );

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
  blst_p2_affine checked_q = pairing_q[0];
  checked_q = non_subgroup;
  FD_TEST( fd_vroom_pairing_finalverify_checked( pairing_p, &checked_q, 1UL, 1UL )==0 );
  FD_TEST( fd_vroom_pairing_finalverify_prepared_checked(
               pairing_p, prepared, pairing_p+1, &checked_q )==0 );

  static uchar const bad_msg[] = "dependency-free VROOM D";
  blst_hash_to_g2( &hash, bad_msg, sizeof(bad_msg)-1UL, dst, sizeof(dst)-1UL, NULL, 0UL );
  blst_p2_to_affine( &pairing_q[0], &hash );
  normal_g2_from_blst( &pairing_qn[0], &pairing_q[0] );
  FD_TEST( fd_vroom_pairing_finalverify_c( pairing_pn, pairing_qn, 2UL )==0 );
  FD_TEST( fd_vroom_g2_prepare_normal( prepared, pairing_qn )==0 );
  FD_TEST( fd_vroom_pairing_finalverify_prepared_normal_checked(
               pairing_pn, prepared, pairing_pn+1, pairing_qn+1 )==0 );

  if( bench ) {
    /* Restore the valid hash and benchmark only the already-validated native
       pairing-product primitive. */
    blst_hash_to_g2( &hash, msg, sizeof(msg)-1UL, dst, sizeof(dst)-1UL, NULL, 0UL );
    blst_p2_to_affine( &pairing_q[0], &hash );
    normal_g2_from_blst( &pairing_qn[0], &pairing_q[0] );
    FD_TEST( fd_vroom_g2_prepare_normal( prepared, pairing_qn )==0 );
    long c_samples[101], prepared_samples[101], prepare_samples[101];
    long c_miller_samples[101], c_final_samples[101], c_isone_samples[101];
    long c_inverse_samples[101], blst_samples[101];
    for( int sample=0; sample<101; sample++ ) {
      long then = fd_log_wallclock();
      FD_TEST( fd_vroom_pairing_finalverify_c( pairing_pn, pairing_qn, 2UL )==1 );
      c_samples[sample] = fd_log_wallclock()-then;
      then = fd_log_wallclock();
      FD_TEST( fd_vroom_pairing_finalverify_prepared_normal_checked(
                   pairing_pn, prepared, pairing_pn+1, pairing_qn+1 )==1 );
      prepared_samples[sample] = fd_log_wallclock()-then;
      then = fd_log_wallclock();
      FD_TEST( fd_vroom_g2_prepare_normal( prepared, pairing_qn )==0 );
      prepare_samples[sample] = fd_log_wallclock()-then;
      fd_vroom_fp12_t m0, m1, mp, mf;
      then = fd_log_wallclock();
      fd_vroom_miller_loop_c( &m0, &pairing_pn[0], &pairing_qn[0] );
      fd_vroom_miller_loop_c( &m1, &pairing_pn[1], &pairing_qn[1] );
      fd_vroom_fp12_mul( &mp, &m0, &m1 );
      c_miller_samples[sample] = fd_log_wallclock()-then;
      then = fd_log_wallclock();
      fd_vroom_final_exp_c( &mf, &mp );
      c_final_samples[sample] = fd_log_wallclock()-then;
      then = fd_log_wallclock();
      FD_TEST( fd_vroom_fp12_is_one_c( &mf ) );
      c_isone_samples[sample] = fd_log_wallclock()-then;
      then = fd_log_wallclock();
      fd_vroom_fp12_inverse_c( &mf, &mp );
      c_inverse_samples[sample] = fd_log_wallclock()-then;
      then = fd_log_wallclock();
      blst_miller_loop_n( &bref, qq, pp, 2UL );
      FD_TEST( blst_fp12_finalverify( &bref, blst_fp12_one() ) );
      blst_samples[sample] = fd_log_wallclock()-then;
    }
    for( int i=1; i<101; i++ ) for( int j=i; j && c_samples[j-1]>c_samples[j]; j-- ) {
      long t=c_samples[j-1]; c_samples[j-1]=c_samples[j]; c_samples[j]=t;
    }
    for( int i=1; i<101; i++ ) for( int j=i; j && prepared_samples[j-1]>prepared_samples[j]; j-- ) {
      long t=prepared_samples[j-1]; prepared_samples[j-1]=prepared_samples[j]; prepared_samples[j]=t;
    }
    for( int i=1; i<101; i++ ) for( int j=i; j && prepare_samples[j-1]>prepare_samples[j]; j-- ) {
      long t=prepare_samples[j-1]; prepare_samples[j-1]=prepare_samples[j]; prepare_samples[j]=t;
    }
    for( int i=1; i<101; i++ ) for( int j=i; j && c_miller_samples[j-1]>c_miller_samples[j]; j-- ) {
      long t=c_miller_samples[j-1]; c_miller_samples[j-1]=c_miller_samples[j]; c_miller_samples[j]=t;
    }
    for( int i=1; i<101; i++ ) for( int j=i; j && c_final_samples[j-1]>c_final_samples[j]; j-- ) {
      long t=c_final_samples[j-1]; c_final_samples[j-1]=c_final_samples[j]; c_final_samples[j]=t;
    }
    for( int i=1; i<101; i++ ) for( int j=i; j && c_isone_samples[j-1]>c_isone_samples[j]; j-- ) {
      long t=c_isone_samples[j-1]; c_isone_samples[j-1]=c_isone_samples[j]; c_isone_samples[j]=t;
    }
    for( int i=1; i<101; i++ ) for( int j=i; j && c_inverse_samples[j-1]>c_inverse_samples[j]; j-- ) {
      long t=c_inverse_samples[j-1]; c_inverse_samples[j-1]=c_inverse_samples[j]; c_inverse_samples[j]=t;
    }
    for( int i=1; i<101; i++ ) for( int j=i; j && blst_samples[j-1]>blst_samples[j]; j-- ) {
      long t=blst_samples[j-1]; blst_samples[j-1]=blst_samples[j]; blst_samples[j]=t;
    }
    FD_LOG_NOTICE(( "pair-product median: generated C %.3f ms, BLST %.3f ms",
                    (double)c_samples[50]/1e6, (double)blst_samples[50]/1e6 ));
    FD_LOG_NOTICE(( "prepared hash pair: verify %.3f ms, one-time prepare %.3f ms",
                    (double)prepared_samples[50]/1e6, (double)prepare_samples[50]/1e6 ));
    FD_LOG_NOTICE(( "generated C split: Miller product %.3f ms, final exponent %.3f ms",
                    (double)c_miller_samples[50]/1e6, (double)c_final_samples[50]/1e6 ));
    FD_LOG_NOTICE(( "RNS identity check: %.3f ms", (double)c_isone_samples[50]/1e6 ));
    FD_LOG_NOTICE(( "current FP12 inverse transition: %.3f ms",
                    (double)c_inverse_samples[50]/1e6 ));
  }

  fd_vroom_fp_t line[6] = { y12.c[0], y12.c[1], y12.c[2], y12.c[3], y12.c[8], y12.c[9] };
  for( int i=0; i<12; i++ ) fd_vroom_fp_zero( &y12.c[i] );
  y12.c[0]=line[0]; y12.c[1]=line[1]; y12.c[2]=line[2]; y12.c[3]=line[3]; y12.c[8]=line[4]; y12.c[9]=line[5];
  to_blst_fp12( &by, &y12 );
  blst_fp12_mul( &bref, &bx, &by );
  fd_vroom_fp12_mul_sparse( &z12, &x12, line );
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
      fd_vroom_fp_from_uint64( &x12.c[i], n );
      prng = prng*0x9e3779b97f4a7c15UL + 0xda942042e4dd58b5UL;
      n[0] = prng;
      fd_vroom_fp_from_uint64( &y12.c[i], n );
    }
    to_blst_fp12( &bx, &x12 );
    to_blst_fp12( &by, &y12 );

    blst_fp12_mul( &bref, &bx, &by );
    fd_vroom_fp12_mul( &x12, &x12, &y12 );
    to_blst_fp12( &bgot, &x12 );
    FD_TEST( blst_fp12_is_equal( &bref, &bgot ) );

    blst_fp12_sqr( &bref, &by );
    fd_vroom_fp12_sqr( &y12, &y12 );
    to_blst_fp12( &bgot, &y12 );
    FD_TEST( blst_fp12_is_equal( &bref, &bgot ) );

    fd_vroom_fp_t sparse_line[6] = {
      x12.c[0], x12.c[1], x12.c[2], x12.c[3], x12.c[8], x12.c[9]
    };
    for( int i=0; i<12; i++ ) fd_vroom_fp_zero( &z12.c[i] );
    z12.c[0]=sparse_line[0]; z12.c[1]=sparse_line[1];
    z12.c[2]=sparse_line[2]; z12.c[3]=sparse_line[3];
    z12.c[8]=sparse_line[4]; z12.c[9]=sparse_line[5];
    to_blst_fp12( &bx, &x12 );
    to_blst_fp12( &by, &z12 );
    blst_fp12_mul( &bref, &bx, &by );
    fd_vroom_fp12_mul_sparse( &x12, &x12, sparse_line );
    to_blst_fp12( &bgot, &x12 );
    FD_TEST( blst_fp12_is_equal( &bref, &bgot ) );
  }

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}

#else
int main( void ) { return 0; }
#endif
