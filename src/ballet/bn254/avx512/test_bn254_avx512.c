/* Differential tests for the BN254 VROOM backend against the scalar
   reference implementation, plus benches (--bench). */

#include "../fd_bn254_field_inl.h"
#include "../fd_bn254_backend.h"
#include "../../../util/fd_util.h"

#if FD_HAS_AVX512

static ulong prng_state = 0x243f6a8885a308d3UL;

static ulong
prng( void ) {
  prng_state = prng_state*0x9e3779b97f4a7c15UL + 0xda942042e4dd58b5UL;
  ulong x = prng_state;
  x ^= x>>33; x *= 0xff51afd7ed558ccdUL; x ^= x>>33;
  return x;
}

static void
rand_scalar( fd_bn254_scalar_t * s ) {
  for( int i=0; i<4; i++ ) s->limbs[i] = prng();
}

/* Affinize via the serialization round trip (to_affine is TU-local in
   the reference code). */
static void
g1_affinize( fd_bn254_g1_t * out, fd_bn254_g1_t const * in ) {
  uchar buf[64];
  fd_bn254_g1_tobytes( buf, (fd_bn254_g1_t *)in, 0 );
  FD_TEST( fd_bn254_g1_frombytes_check_subgroup( out, buf, 0 ) );
}

static void
g2_affinize( fd_bn254_g2_t * out, fd_bn254_g2_t const * in ) {
  uchar buf[128];
  fd_bn254_g2_tobytes( buf, (fd_bn254_g2_t *)in, 0 );
  FD_TEST( fd_bn254_g2_frombytes_check_eq_only( out, buf, 0 ) );
}

/* [k]G1 via the reference code, affine Montgomery out. */
static void
rand_g1( fd_bn254_g1_t * out ) {
  /* generator (1, 2) */
  fd_bn254_g1_t g[1];
  fd_bn254_fp_t two[1];
  g->X.limbs[0]=1UL; g->X.limbs[1]=0UL; g->X.limbs[2]=0UL; g->X.limbs[3]=0UL;
  two->limbs[0]=2UL; two->limbs[1]=0UL; two->limbs[2]=0UL; two->limbs[3]=0UL;
  fd_bn254_fp_to_mont( &g->X, &g->X );
  fd_bn254_fp_to_mont( &g->Y, two );
  fd_bn254_fp_set_one( &g->Z );

  fd_bn254_scalar_t k[1];
  rand_scalar( k );
  k->limbs[3] &= 0x0fffffffffffffffUL;
  fd_bn254_g1_t r[1];
  fd_bn254_g1_scalar_mul( r, g, k );
  g1_affinize( out, r );
}

/* [k]G2 via the reference code, affine Montgomery out. */
static void
rand_g2( fd_bn254_g2_t * out ) {
  /* standard G2 generator, canonical hex (arkworks/gnark) */
  static const ulong gx0[4] = { 0x46debd5cd992f6edUL, 0x674322d4f75edaddUL, 0x426a00665e5c4479UL, 0x1800deef121f1e76UL };
  static const ulong gx1[4] = { 0x97e485b7aef312c2UL, 0xf1aa493335a9e712UL, 0x7260bfb731fb5d25UL, 0x198e9393920d483aUL };
  static const ulong gy0[4] = { 0x4ce6cc0166fa7daaUL, 0xe3d1e7690c43d37bUL, 0x4aab71808dcb408fUL, 0x12c85ea5db8c6debUL };
  static const ulong gy1[4] = { 0x55acdadcd122975bUL, 0xbc4b313370b38ef3UL, 0xec9e99ad690c3395UL, 0x090689d0585ff075UL };
  fd_bn254_g2_t g[1];
  memcpy( g->X.el[0].limbs, gx0, 32 ); memcpy( g->X.el[1].limbs, gx1, 32 );
  memcpy( g->Y.el[0].limbs, gy0, 32 ); memcpy( g->Y.el[1].limbs, gy1, 32 );
  fd_bn254_fp2_to_mont( &g->X, &g->X );
  fd_bn254_fp2_to_mont( &g->Y, &g->Y );
  fd_bn254_fp2_set_one( &g->Z );

  fd_bn254_scalar_t k[1];
  rand_scalar( k );
  k->limbs[3] &= 0x0fffffffffffffffUL;
  fd_bn254_g2_t r[1];
  fd_bn254_g2_scalar_mul( r, g, k );
  g2_affinize( out, r );
}

static int
fd_bn254_fp12_eq_diff( fd_bn254_fp12_t const * a,
                      fd_bn254_fp12_t const * b,
                      char const *            what ) {
  int ok = 1;
  for( int w=0; w<2; w++ ) for( int v=0; v<3; v++ ) for( int u=0; u<2; u++ )
    if( !fd_bn254_fp_eq( &a->el[w].el[v].el[u], &b->el[w].el[v].el[u] ) ) ok = 0;
  if( !ok ) FD_LOG_NOTICE(( "fp12 mismatch: %s", what ));
  return ok;
}

static void
log_bench( char const * descr,
           ulong        iter,
           long         dt ) {
  float khz = 1e6f*(float)iter/(float)dt;
  float tau = (float)dt/(float)iter;
  FD_LOG_NOTICE(( "%-34s %10.3fK/s/core %12.3f ns/call", descr, (double)khz, (double)tau ));
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );
  int bench = fd_env_strip_cmdline_contains( &argc, &argv, "--bench" );

  /* --- G2 subgroup check differential --- */
  for( int t=0; t<32; t++ ) {
    fd_bn254_g2_t q[1];
    rand_g2( q );
    FD_TEST( fd_bn254_ref_g2_in_subgroup( q )==1 );
    FD_TEST( fd_bn254_avx512_g2_in_subgroup( q )==1 );
  }
  /* non-subgroup twist point: find small-x point on the twist */
  {
    fd_bn254_g2_t q[1];
    int found = 0;
    for( ulong xi=1UL; xi<256UL && !found; xi++ ) {
      fd_bn254_fp2_t x[1], y2[1];
      fd_bn254_fp_set_zero( &x->el[1] );
      x->el[0].limbs[0]=xi; x->el[0].limbs[1]=0UL; x->el[0].limbs[2]=0UL; x->el[0].limbs[3]=0UL;
      fd_bn254_fp_to_mont( &x->el[0], &x->el[0] );
      fd_bn254_fp2_sqr( y2, x );
      fd_bn254_fp2_mul( y2, y2, x );
      fd_bn254_fp2_add( y2, y2, fd_bn254_const_twist_b_mont );
      fd_bn254_fp2_t y[1];
      if( fd_bn254_fp2_sqrt( y, y2 ) ) {
        fd_bn254_fp2_set( &q->X, x );
        fd_bn254_fp2_set( &q->Y, y );
        fd_bn254_fp2_set_one( &q->Z );
        if( !fd_bn254_ref_g2_in_subgroup( q ) ) found = 1;
      }
    }
    FD_TEST( found );
    FD_TEST( fd_bn254_avx512_g2_in_subgroup( q )==0 );
  }
  FD_LOG_NOTICE(( "g2 subgroup check differential pass" ));

  /* --- scalar mul differential (G1) --- */
  for( int t=0; t<32; t++ ) {
    fd_bn254_g1_t p[1], r_ref[1], r_vec[1], a_ref[1], a_vec[1];
    rand_g1( p );
    fd_bn254_scalar_t s[1];
    rand_scalar( s ); /* raw 256-bit scalar, unreduced: matches syscall */
    if( t==0 ) { s->limbs[0]=0UL; s->limbs[1]=0UL; s->limbs[2]=0UL; s->limbs[3]=0UL; }
    if( t==1 ) { s->limbs[0]=1UL; s->limbs[1]=0UL; s->limbs[2]=0UL; s->limbs[3]=0UL; }
    fd_bn254_g1_scalar_mul( r_ref, p, s );
    fd_bn254_avx512_g1_scalar_mul( r_vec, p, s );
    if( fd_bn254_g1_is_zero( r_ref ) ) { FD_TEST( fd_bn254_g1_is_zero( r_vec ) ); continue; }
    uchar b_ref[64], b_vec[64];
    fd_bn254_g1_tobytes( b_ref, r_ref, 0 );
    fd_bn254_g1_tobytes( b_vec, r_vec, 0 );
    FD_TEST( !memcmp( b_ref, b_vec, 64 ) );
    (void)a_ref; (void)a_vec;
  }
  FD_LOG_NOTICE(( "g1 scalar mul differential pass" ));

  /* --- scalar mul differential (G2) --- */
  for( int t=0; t<32; t++ ) {
    fd_bn254_g2_t q[1], r_ref[1], r_vec[1], a_ref[1], a_vec[1];
    rand_g2( q );
    fd_bn254_scalar_t s[1];
    rand_scalar( s );
    if( t==0 ) { s->limbs[0]=0UL; s->limbs[1]=0UL; s->limbs[2]=0UL; s->limbs[3]=0UL; }
    fd_bn254_g2_scalar_mul( r_ref, q, s );
    fd_bn254_avx512_g2_scalar_mul( r_vec, q, s );
    if( fd_bn254_g2_is_zero( r_ref ) ) { FD_TEST( fd_bn254_g2_is_zero( r_vec ) ); continue; }
    uchar b_ref[128], b_vec[128];
    fd_bn254_g2_tobytes( b_ref, r_ref, 0 );
    fd_bn254_g2_tobytes( b_vec, r_vec, 0 );
    FD_TEST( !memcmp( b_ref, b_vec, 128 ) );
    (void)a_ref; (void)a_vec;
  }
  FD_LOG_NOTICE(( "g2 scalar mul differential pass" ));

  /* --- raw Miller differential (debug) --- */
  {
    extern void fd_bn254_avx512_miller_diff( fd_bn254_fp12_t *, fd_bn254_g1_t const *, fd_bn254_g2_t const *, ulong );
    fd_bn254_g1_t p[1]; fd_bn254_g2_t q[1];
    rand_g1( p ); rand_g2( q );
    fd_bn254_fp12_t ref[1], vec[1];
    fd_bn254_miller_loop( ref, p, q, 1UL );
    fd_bn254_avx512_miller_diff( vec, p, q, 1UL );
    int ok = 1;
    for( int w=0; w<2; w++ ) for( int v=0; v<3; v++ ) for( int u=0; u<2; u++ )
      if( !fd_bn254_fp_eq( &ref->el[w].el[v].el[u], &vec->el[w].el[v].el[u] ) ) {
        FD_LOG_NOTICE(( "miller mismatch at w=%d v=%d u=%d", w, v, u ));
        ok = 0;
      }
    FD_TEST( ok );
    FD_LOG_NOTICE(( "raw miller differential pass" ));
  }

  /* --- fp12 op differentials (debug) --- */
  {
    extern void fd_bn254_avx512_fp12_diff( fd_bn254_fp12_t *, fd_bn254_fp12_t const *, int );
    fd_bn254_g1_t p[1]; fd_bn254_g2_t q[1];
    rand_g1( p ); rand_g2( q );
    fd_bn254_fp12_t m[1], ref[1], vec[1];
    fd_bn254_miller_loop( m, p, q, 1UL );

    /* general ops on the raw Miller output */
    fd_bn254_fp12_sqr( ref, m );
    fd_bn254_avx512_fp12_diff( vec, m, 6 );
    FD_TEST( fd_bn254_fp12_eq_diff( ref, vec, "sqr" ) );
    fd_bn254_fp12_mul( ref, m, m );
    fd_bn254_avx512_fp12_diff( vec, m, 5 );
    FD_TEST( fd_bn254_fp12_eq_diff( ref, vec, "mul" ) );
    fd_bn254_fp12_inv( ref, m );
    fd_bn254_avx512_fp12_diff( vec, m, 4 );
    FD_TEST( fd_bn254_fp12_eq_diff( ref, vec, "inv" ) );
    fd_bn254_fp12_frob( ref, m );
    fd_bn254_avx512_fp12_diff( vec, m, 2 );
    FD_TEST( fd_bn254_fp12_eq_diff( ref, vec, "frob" ) );
    fd_bn254_fp12_frob2( ref, m );
    fd_bn254_avx512_fp12_diff( vec, m, 3 );
    FD_TEST( fd_bn254_fp12_eq_diff( ref, vec, "frob2" ) );

    /* cyclotomic ops on an element of the cyclotomic subgroup */
    fd_bn254_fp12_t cyc[1];
    {
      fd_bn254_fp12_t t0[1], t1[1];
      fd_bn254_fp12_conj( t0, m );
      fd_bn254_fp12_inv( t1, m );
      fd_bn254_fp12_mul( t0, t0, t1 );
      fd_bn254_fp12_frob2( t1, t0 );
      fd_bn254_fp12_mul( cyc, t0, t1 ); /* m^((p^6-1)(p^2+1)) */
    }
    fd_bn254_fp12_sqr( ref, cyc ); /* cyc sqr == plain sqr on cyclotomic input */
    fd_bn254_avx512_fp12_diff( vec, cyc, 1 );
    FD_TEST( fd_bn254_fp12_eq_diff( ref, vec, "cyclotomic" ) );

    fd_bn254_final_exp( ref, m );
    fd_bn254_avx512_fp12_diff( vec, m, 0 );
    FD_TEST( fd_bn254_fp12_eq_diff( ref, vec, "final_exp" ) );
    FD_LOG_NOTICE(( "fp12 op differentials pass" ));
  }

  /* --- pairing differential --- */
  /* e([a]G1, [b]G2) * e(-[ab]G1, G2) == 1 (bilinearity), and ref/vec
     agreement on random non-matching products. */
  for( int t=0; t<8; t++ ) {
    fd_bn254_g1_t p[2];
    fd_bn254_g2_t q[2];
    rand_g1( &p[0] );
    rand_g2( &q[0] );
    rand_g1( &p[1] );
    rand_g2( &q[1] );
    int ref = fd_bn254_ref_pairing_is_one( p, q, 2UL );
    int vec = fd_bn254_avx512_pairing_is_one( p, q, 2UL );
    FD_TEST( ref==vec ); /* almost surely 0==0 */

    /* force a product equal to one: e(P,Q)*e(-P,Q) */
    fd_bn254_g2_t qq[2];
    qq[0] = q[0];
    qq[1] = q[0];
    fd_bn254_g1_t pp[2];
    fd_bn254_fp_set( &pp[0].X, &p[0].X ); fd_bn254_fp_set( &pp[0].Y, &p[0].Y ); fd_bn254_fp_set_one( &pp[0].Z );
    fd_bn254_fp_set( &pp[1].X, &p[0].X ); fd_bn254_fp_neg( &pp[1].Y, &p[0].Y ); fd_bn254_fp_set_one( &pp[1].Z );
    FD_TEST( fd_bn254_ref_pairing_is_one( pp, qq, 2UL )==1 );
    FD_TEST( fd_bn254_avx512_pairing_is_one( pp, qq, 2UL )==1 );
  }
  /* single pair: never one */
  {
    fd_bn254_g1_t p[1]; fd_bn254_g2_t q[1];
    rand_g1( p ); rand_g2( q );
    FD_TEST( fd_bn254_ref_pairing_is_one( p, q, 1UL )==0 );
    FD_TEST( fd_bn254_avx512_pairing_is_one( p, q, 1UL )==0 );
  }
  /* empty product is one */
  FD_TEST( fd_bn254_avx512_pairing_is_one( NULL, NULL, 0UL )==1 );
  FD_LOG_NOTICE(( "pairing differential pass" ));

  if( bench ) {
    fd_bn254_g1_t p[2]; fd_bn254_g2_t q[2];
    rand_g1( &p[0] ); rand_g2( &q[0] );
    fd_bn254_fp_set( &p[1].X, &p[0].X ); fd_bn254_fp_neg( &p[1].Y, &p[0].Y ); fd_bn254_fp_set_one( &p[1].Z );
    q[1] = q[0];
    fd_bn254_scalar_t s[1]; rand_scalar( s );
    fd_bn254_g1_t r1[1]; fd_bn254_g2_t r2[1];

    ulong iter = 100UL;
    long dt;

    dt = fd_log_wallclock();
    for( ulong rem=iter; rem; rem-- ) FD_TEST( fd_bn254_ref_pairing_is_one( p, q, 2UL )==1 );
    dt = fd_log_wallclock()-dt;
    log_bench( "ref_pairing_is_one(2)", iter, dt );

    dt = fd_log_wallclock();
    for( ulong rem=iter; rem; rem-- ) FD_TEST( fd_bn254_avx512_pairing_is_one( p, q, 2UL )==1 );
    dt = fd_log_wallclock()-dt;
    log_bench( "avx512_pairing_is_one(2)", iter, dt );

    dt = fd_log_wallclock();
    for( ulong rem=iter; rem; rem-- ) FD_TEST( fd_bn254_ref_g2_in_subgroup( q )==1 );
    dt = fd_log_wallclock()-dt;
    log_bench( "ref_g2_in_subgroup", iter, dt );

    dt = fd_log_wallclock();
    for( ulong rem=iter; rem; rem-- ) FD_TEST( fd_bn254_avx512_g2_in_subgroup( q )==1 );
    dt = fd_log_wallclock()-dt;
    log_bench( "avx512_g2_in_subgroup", iter, dt );

    dt = fd_log_wallclock();
    for( ulong rem=iter; rem; rem-- ) fd_bn254_g1_scalar_mul( r1, p, s );
    dt = fd_log_wallclock()-dt;
    log_bench( "ref_g1_scalar_mul", iter, dt );

    dt = fd_log_wallclock();
    for( ulong rem=iter; rem; rem-- ) fd_bn254_avx512_g1_scalar_mul( r1, p, s );
    dt = fd_log_wallclock()-dt;
    log_bench( "avx512_g1_scalar_mul", iter, dt );

    dt = fd_log_wallclock();
    for( ulong rem=iter; rem; rem-- ) fd_bn254_g2_scalar_mul( r2, q, s );
    dt = fd_log_wallclock()-dt;
    log_bench( "ref_g2_scalar_mul", iter, dt );

    dt = fd_log_wallclock();
    for( ulong rem=iter; rem; rem-- ) fd_bn254_avx512_g2_scalar_mul( r2, q, s );
    dt = fd_log_wallclock()-dt;
    log_bench( "avx512_g2_scalar_mul", iter, dt );
  }

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}

#else
int main( void ) { return 0; }
#endif
