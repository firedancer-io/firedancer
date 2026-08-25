#include "../fd_ballet.h"
#include "fd_bls.h"

/* Benchmarks for the fd_bls API surface used by the Alpenglow certificate
   and signature paths: aggregate verification (hash-to-G2 plus the pairing
   check), public key and signature aggregation, and serialization.  Each
   benchmark first exercises its correctness contract, then reports
   ns/call through the shared log_bench format. */

static void
log_bench( char const * descr,
           ulong        iter,
           long         dt ) {
  float khz = 1e6f *(float)iter/(float)dt;
  float tau = (float)dt /(float)iter;
  FD_LOG_NOTICE(( "%-34s %10.3fK/s/core %12.3f ns/call", descr, (double)khz, (double)tau ));
}

/* Fixture message stand-ins: the certificate base and fallback payloads. */

static uchar const MSG[ 32 ]    = "alpenglow certificate benchmsg01";
static uchar const MSG_FB[ 32 ] = "alpenglow cert fallback benchm2";

#define SUM_KEY_CNT FD_BLS_SET_MAX

/* fd_bls_key_init sets sec to a deterministic in-range test scalar. */

static void
fd_bls_key_init( fd_bls_sec_t * sk,
                 ulong           i ) {
  fd_memset( sk, 0, FD_BLS_SEC_SZ );
  sk->b[ 0 ] = (uchar)( i+1UL );
  sk->b[ 1 ] = (uchar)( i*7UL+1UL );
  sk->b[ 2 ] = (uchar)( i*13UL+3UL );
}

static void
test_hash_msg( void ) {
  fd_bls_hash_t h[1], h2[1];
  fd_bls_hash_msg( MSG, sizeof(MSG), h );
  fd_bls_hash_msg( MSG, sizeof(MSG), h2 );
  FD_TEST( !memcmp( h, h2, sizeof(fd_bls_hash_t) ) ); /* deterministic */

  /* Native-vs-blst differential: fd_bls_hash_msg (the AVX-512 native
     hash-to-curve when enabled, the blst fallback otherwise) must be
     byte-for-byte identical to blst_hash_to_g2 affinized — same algorithm,
     same SSWU, same isogeny, same Budroni-Pintore cofactor clear — for the
     fixture messages plus 134 deterministic pseudo-random messages. */
  for( ulong t=0UL; t<136UL; t++ ) {
    uchar msg[ 64 ]; ulong msg_sz;
    if( t<2UL ) {
      msg_sz = t ? sizeof(MSG_FB) : sizeof(MSG);
      fd_memcpy( msg, t ? MSG_FB : MSG, msg_sz );
    } else {
      msg_sz = 1UL + (t*7UL) % 63UL;
      for( ulong i=0UL; i<msg_sz; i++ ) msg[i] = (uchar)(t*31UL + i*17UL);
    }
    fd_bls_hash_msg( msg, msg_sz, h2 );
    blst_p2 p[1];
    blst_hash_to_g2( p, msg, msg_sz, (uchar const *)FD_BLS_DST,
                     FD_BLS_DST_SZ, NULL, 0UL );
    blst_p2_affine aff[1];
    blst_p2_to_affine( aff, p );
    FD_TEST( !memcmp( h2, aff, sizeof(fd_bls_hash_t) ) );
  }

  ulong iter = 300UL;
  long dt = fd_log_wallclock();
  for( ulong rem=iter; rem; rem-- ) fd_bls_hash_msg( MSG, sizeof(MSG), h2 );
  dt = fd_log_wallclock() - dt;
  log_bench( "fd_bls_hash_msg", iter, dt );
}

static void
test_verify( fd_bls_pub_t const * pub,
             fd_bls_sig_t const * sig,
             fd_bls_pub_t const * pub_fb,
             fd_bls_sig_t const * sig_fb,
             fd_bls_sig_t const * sig_pair ) {
  /* aggregate verification: correctness contract first */
  FD_TEST(  fd_bls_agg_verify( MSG,    sizeof(MSG),    pub,    sig ) );
  FD_TEST( !fd_bls_agg_verify( MSG,    sizeof(MSG),    pub_fb, sig ) ); /* wrong key */
  FD_TEST( !fd_bls_agg_verify( MSG_FB, sizeof(MSG_FB), pub,    sig ) ); /* wrong msg */

  fd_bls_hash_t h[1];
  fd_bls_hash_msg( MSG, sizeof(MSG), h );
  FD_TEST(  fd_bls_agg_verify_hashed( h, pub, sig ) );
  FD_TEST( !fd_bls_agg_verify_hashed( h, pub_fb, sig ) );

  FD_TEST(  fd_bls_agg_verify_pair( MSG,    sizeof(MSG),    pub,
                                    MSG_FB, sizeof(MSG_FB), pub_fb, sig_pair ) );
  FD_TEST( !fd_bls_agg_verify_pair( MSG,    sizeof(MSG),    pub,
                                    MSG_FB, sizeof(MSG_FB), pub_fb, sig_fb ) );

  ulong iter = 100UL;
  long dt;
  dt = fd_log_wallclock();
  for( ulong rem=iter; rem; rem-- ) fd_bls_agg_verify_hashed( h, pub, sig );
  dt = fd_log_wallclock() - dt;
  log_bench( "fd_bls_agg_verify_hashed", iter, dt );

  dt = fd_log_wallclock();
  for( ulong rem=iter; rem; rem-- ) FD_TEST( fd_bls_agg_verify( MSG, sizeof(MSG), pub, sig ) );
  dt = fd_log_wallclock() - dt;
  log_bench( "fd_bls_agg_verify", iter, dt );

  dt = fd_log_wallclock();
  for( ulong rem=iter; rem; rem-- ) FD_TEST( fd_bls_agg_verify_pair( MSG, sizeof(MSG), pub, MSG_FB, sizeof(MSG_FB), pub_fb, sig_pair ) );
  dt = fd_log_wallclock() - dt;
  log_bench( "fd_bls_agg_verify_pair", iter, dt );
}

/* pub_sum differential: the native fold must match a reference blst
   add chain for several set masks (including the empty/singleton shapes,
   complement-heavy shapes, and adversarial negating pairs whose partial
   sums pass through the point at infinity mid-aggregation). */
static void
test_pub_sum( fd_bls_pub_t const * pubs,
              ulong                 key_cnt ) {
  static ulong const MASKS[] = { 0UL, 1UL, 0x5555555555555555UL,
                                 0xaaaaaaaaaaaaaaaaUL, 0xf0f0f0f0f0f0f0f0UL,
                                 0x0f0f0f0f0f0f0f0fUL, ~0UL };
  ulong nmasks = sizeof(MASKS)/sizeof(MASKS[0]);

  for( ulong m=0UL; m<nmasks; m++ ) {
    fd_bls_set_t set[ fd_bls_set_word_cnt ]; fd_bls_set_null( set );
    for( ulong r=0UL; r<key_cnt && r<64UL; r++ )
      if( (MASKS[m]>>r) & 1UL ) fd_bls_set_insert( set, r );

    fd_bls_pub_t got[1]; fd_memset( got, 0, sizeof(fd_bls_pub_t) );
    fd_bls_pub_sum( got, pubs, set );

    /* reference: the exact blst loop */
    blst_p1 ref[1]; fd_memset( ref, 0, sizeof(fd_bls_pub_t) );
    for( ulong rank = fd_bls_set_const_iter_init( set );
                     !fd_bls_set_const_iter_done( rank );
               rank = fd_bls_set_const_iter_next( set, rank ) )
      blst_p1_add_or_double( ref, ref, (blst_p1 const *)(pubs+rank) );

    FD_TEST( blst_p1_is_equal( (blst_p1 const *)got, ref ) );
  }

  /* adversarial: negating pairs (transient infinity mid-fold) */
  fd_bls_pub_t np[2];
  fd_bls_sec_t sk[1]; fd_bls_key_init( sk, 999UL );
  fd_bls_pub_t tp[1]; fd_bls_sec_to_pub( sk, tp );
  fd_memcpy( &np[0], tp, sizeof(fd_bls_pub_t) );
  fd_memcpy( &np[1], tp, sizeof(fd_bls_pub_t) );
  blst_p1_cneg( (blst_p1 *)(void *)&np[1], 1 );
  fd_bls_set_t set2[ fd_bls_set_word_cnt ]; fd_bls_set_null( set2 );
  fd_bls_set_insert( set2, 0 ); fd_bls_set_insert( set2, 1 );
  fd_bls_pub_t got[1]; fd_memset( got, 0, sizeof(fd_bls_pub_t) );
  fd_bls_pub_sum( got, np, set2 );
  FD_TEST( fd_bls_pub_is_inf( got ) ); /* P + (-P) == infinity */

  /* full-set fold: native must equal the blst chain over all keys */
  fd_bls_set_t all[ fd_bls_set_word_cnt ]; fd_bls_set_full( all );
  fd_bls_pub_t got_all[1]; fd_memset( got_all, 0, sizeof(fd_bls_pub_t) );
  fd_bls_pub_sum( got_all, pubs, all );
  blst_p1 ref[1]; fd_memset( ref, 0, sizeof(fd_bls_pub_t) );
  for( ulong r=0UL; r<key_cnt; r++ )
    blst_p1_add_or_double( ref, ref, (blst_p1 const *)(pubs+r) );
  FD_TEST( blst_p1_is_equal( (blst_p1 const *)got_all, ref ) );

  ulong iter = 20UL;
  long dt = fd_log_wallclock();
  for( ulong rem=iter; rem; rem-- ) fd_bls_pub_sum( got_all, pubs, all );
  dt = fd_log_wallclock() - dt;
  log_bench( "fd_bls_pub_sum_all_2000", iter, dt );

  fd_bls_set_t sparse[ fd_bls_set_word_cnt ]; fd_bls_set_null( sparse );
  for( ulong r=0UL; r<100UL; r++ ) fd_bls_set_insert( sparse, r*20UL );
  fd_bls_pub_t got_sp[1]; fd_memset( got_sp, 0, sizeof(fd_bls_pub_t) );
  dt = fd_log_wallclock();
  for( ulong rem=iter; rem; rem-- ) fd_bls_pub_sum( got_sp, pubs, sparse );
  dt = fd_log_wallclock() - dt;
  log_bench( "fd_bls_pub_sum_sparse_100", iter, dt );

  fd_bls_set_t comp[ fd_bls_set_word_cnt ]; fd_bls_set_full( comp );
  for( ulong r=0UL; r<100UL; r++ ) fd_bls_set_remove( comp, r*20UL );
  fd_bls_pub_t got_cm[1]; fd_memset( got_cm, 0, sizeof(fd_bls_pub_t) );
  dt = fd_log_wallclock();
  for( ulong rem=iter; rem; rem-- ) fd_bls_pub_sum( got_cm, pubs, comp );
  dt = fd_log_wallclock() - dt;
  log_bench( "fd_bls_pub_sum_complement_1900", iter, dt );
}

/* sig_validate differential: valid sigs accepted; an on-curve twist
   point OUTSIDE the order-r subgroup rejected; aggregated sigs accepted;
   infinity semantics match blst. */
static void
test_sig_validate( fd_bls_sig_t const * sig,
                   fd_bls_sig_t const * sig_agg ) {
  FD_TEST( fd_bls_sig_validate( sig ) );
  FD_TEST( fd_bls_sig_validate( sig_agg ) );

  /* Find an x on the twist whose y exists but which is NOT in the r-order
     subgroup (an on-curve, non-subgroup point) — the native and blst
     validators must both reject it. */
  blst_fp2 x; fd_memset( &x, 0, sizeof(x) );
  for( ulong t=1UL; t<200UL; t++ ) {
    ulong tv[6]; fd_memset( tv, 0, sizeof(tv) ); tv[0] = t;
    blst_fp_from_uint64( &x.fp[0], tv );
    fd_bls_hash_t probe[1];
    /* y^2 = x^3 + 4(1+i) via the public API */
    blst_fp2 four; ulong f4[6] = { 4UL,0,0,0,0,0 };
    blst_fp_from_uint64( &four.fp[0], f4 );
    blst_fp_from_uint64( &four.fp[1], f4 );
    blst_fp2 x3, rhs, y;
    blst_fp2_sqr( &x3, &x );
    blst_fp2_mul( &x3, &x3, &x );
    blst_fp2_add( &rhs, &x3, &four );
    if( !blst_fp2_sqrt( &y, &rhs ) ) continue;
    probe->x = x; probe->y = y;
    if( !blst_p2_affine_in_g2( probe ) ) {
      blst_p2 np[1];
      blst_p2_from_affine( np, probe );
      FD_TEST( !fd_bls_sig_validate( np ) );
      FD_TEST( !blst_p2_in_g2( np ) );
      break;
    }
  }

  /* infinity: native must match blst exactly */
  fd_bls_sig_t inf[1]; fd_memset( inf, 0, sizeof(fd_bls_sig_t) );
  FD_TEST( !!fd_bls_sig_validate( inf )==!!blst_p2_in_g2( (blst_p2 const *)inf ) );

  ulong iter = 200UL;
  long dt = fd_log_wallclock();
  for( ulong rem=iter; rem; rem-- ) fd_bls_sig_validate( sig );
  dt = fd_log_wallclock() - dt;
  log_bench( "fd_bls_sig_validate", iter, dt );
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  /* deterministic keys and signature fixtures */
  fd_bls_sec_t  sec[1];  fd_bls_key_init( sec, 1UL );
  fd_bls_pub_t  pub[1];  fd_bls_sec_to_pub( sec, pub );
  fd_bls_sig_t  sig[1];  fd_bls_sec_sign( sec, MSG, sizeof(MSG), sig );

  fd_bls_sec_t  sec_fb[1]; fd_bls_key_init( sec_fb, 2UL );
  fd_bls_pub_t  pub_fb[1]; fd_bls_sec_to_pub( sec_fb, pub_fb );
  fd_bls_sig_t  sig_fb[1]; fd_bls_sec_sign( sec_fb, MSG_FB, sizeof(MSG_FB), sig_fb );

  /* sig_pair: aggregate of two signatures over their own messages, under
     a SECOND key pair so the pair-verify fixtures line up with pub2/pub3 */
  fd_bls_sec_t sk2[1], sk3[1];
  fd_bls_key_init( sk2, 3UL ); fd_bls_key_init( sk3, 4UL );
  fd_bls_pub_t pub2[1], pub3[1];
  fd_bls_sec_to_pub( sk2, pub2 ); fd_bls_sec_to_pub( sk3, pub3 );
  fd_bls_sig_t s0[1], s1[1];
  fd_bls_sec_sign( sk2, MSG,    sizeof(MSG),    s0 );
  fd_bls_sec_sign( sk3, MSG_FB, sizeof(MSG_FB), s1 );
  fd_bls_sig_t sig_pair[1];
  fd_memcpy( sig_pair, s0, sizeof(fd_bls_sig_t) );
  fd_bls_sig_add( sig_pair, sig_pair, s1 );
  test_verify( pub2, s0, pub3, s1, sig_pair );

  test_hash_msg( );

  /* aggregation over the full set */
  fd_bls_pub_t pubs[ SUM_KEY_CNT ];
  fd_bls_sig_t sigs[ SUM_KEY_CNT ];
  for( ulong i=0UL; i<SUM_KEY_CNT; i++ ) {
    fd_bls_sec_t sk[1]; fd_bls_key_init( sk, 100UL+i );
    fd_bls_sec_to_pub( sk, pubs+i );
    fd_bls_sec_sign( sk, MSG, sizeof(MSG), sigs+i );
  }
  test_pub_sum( pubs, SUM_KEY_CNT );

  /* an aggregated signature for the sig_validate differential */
  fd_bls_sig_t sig_agg[1]; fd_memcpy( sig_agg, sig, sizeof(fd_bls_sig_t) );
  fd_bls_sig_add( sig_agg, sig_agg, sig_fb );
  test_sig_validate( sig, sig_agg );

  /* pub_add / sig_add correctness + benches */
  fd_bls_pub_t pa[1];
  fd_bls_pub_t p_ref[1]; fd_memcpy( p_ref, pub, sizeof(fd_bls_pub_t) );
  blst_p1_add_or_double( (blst_p1 *)(void *)p_ref, (blst_p1 const *)p_ref, (blst_p1 const *)pub_fb );
  fd_bls_pub_add( pa, pub, pub_fb );
  FD_TEST( fd_bls_pub_eq( pa, p_ref ) );

  fd_bls_sig_t sa[1];
  fd_bls_sig_t s_ref[1]; fd_memcpy( s_ref, sig, sizeof(fd_bls_sig_t) );
  blst_p2_add_or_double( (blst_p2 *)(void *)s_ref, (blst_p2 const *)s_ref, (blst_p2 const *)sig_fb );
  fd_bls_sig_add( sa, sig, sig_fb );
  FD_TEST( fd_bls_sig_eq( sa, s_ref ) );

  ulong iter = 20000UL;
  long dt;
  dt = fd_log_wallclock();
  for( ulong rem=iter; rem; rem-- ) fd_bls_pub_add( pa, pub, pub_fb );
  dt = fd_log_wallclock() - dt;
  log_bench( "fd_bls_pub_add", iter, dt );

  iter = 20000UL;
  dt = fd_log_wallclock();
  for( ulong rem=iter; rem; rem-- ) fd_bls_sig_add( sa, sig, sig_fb );
  dt = fd_log_wallclock() - dt;
  log_bench( "fd_bls_sig_add", iter, dt );

  /* serde suite */
  uchar buf[ FD_BLS_SIG_SZ ];
  fd_bls_sig_t de[1];
  fd_bls_sig_ser( sig, buf );
  FD_TEST( !fd_bls_sig_de( de, buf ) );
  FD_TEST( fd_bls_sig_eq( de, sig ) );
  FD_TEST( !fd_bls_sig_de_unchecked( de, buf ) );
  FD_TEST( fd_bls_sig_eq( de, sig ) );
  uchar cbuf[ FD_BLS_SIG_COMPRESSED_SZ ];
  fd_bls_sig_compress( sig, cbuf );
  FD_TEST( !fd_bls_sig_de_compressed( de, cbuf ) );
  FD_TEST( fd_bls_sig_eq( de, sig ) );

  iter = 20000UL;
  dt = fd_log_wallclock();
  for( ulong rem=iter; rem; rem-- ) fd_bls_sig_ser( sig, buf );
  dt = fd_log_wallclock() - dt;
  log_bench( "fd_bls_sig_ser", iter, dt );

  dt = fd_log_wallclock();
  for( ulong rem=iter; rem; rem-- ) { fd_bls_sig_ser( sig, buf ); fd_bls_sig_de( de, buf ); }
  dt = fd_log_wallclock() - dt;
  log_bench( "fd_bls_sig_de", iter, dt );

  dt = fd_log_wallclock();
  for( ulong rem=iter; rem; rem-- ) fd_bls_sig_compress( sig, cbuf );
  dt = fd_log_wallclock() - dt;
  log_bench( "fd_bls_sig_compress", iter, dt );

  dt = fd_log_wallclock();
  for( ulong rem=iter; rem; rem-- ) fd_bls_sig_de_compressed( de, cbuf );
  dt = fd_log_wallclock() - dt;
  log_bench( "fd_bls_sig_de_compressed", iter, dt );

  dt = fd_log_wallclock();
  for( ulong rem=iter; rem; rem-- ) { uchar b2[FD_BLS_SIG_SZ]; fd_bls_sig_ser( sig_agg, b2 ); fd_bls_sig_de( de, b2 ); }
  dt = fd_log_wallclock() - dt;
  log_bench( "fd_bls_sig_ser_projective", iter, dt );

  dt = fd_log_wallclock();
  for( ulong rem=iter; rem; rem-- ) fd_bls_sig_compress( sig_agg, cbuf );
  dt = fd_log_wallclock() - dt;
  log_bench( "fd_bls_sig_compress_projective", iter, dt );

  uchar pbuf[ FD_BLS_PUB_SZ ];
  fd_bls_pub_t pde[1];
  fd_bls_pub_ser( pub, pbuf );
  FD_TEST( !fd_bls_pub_de( pde, pbuf, FD_BLS_PUB_SZ ) );
  FD_TEST( fd_bls_pub_eq( pde, pub ) );
  uchar pcbuf[ FD_BLS_PUB_COMPRESSED_SZ ];
  fd_bls_pub_compress( pub, pcbuf );
  FD_TEST( !fd_bls_pub_de_compressed( pde, pcbuf ) );
  FD_TEST( fd_bls_pub_eq( pde, pub ) );

  iter = 100000UL;
  dt = fd_log_wallclock();
  for( ulong rem=iter; rem; rem-- ) fd_bls_pub_ser( pub, pbuf );
  dt = fd_log_wallclock() - dt;
  log_bench( "fd_bls_pub_ser", iter, dt );

  iter = 20000UL;
  dt = fd_log_wallclock();
  for( ulong rem=iter; rem; rem-- ) fd_bls_pub_de( pde, pbuf, FD_BLS_PUB_SZ );
  dt = fd_log_wallclock() - dt;
  log_bench( "fd_bls_pub_de_affine", iter, dt );

  dt = fd_log_wallclock();
  for( ulong rem=iter; rem; rem-- ) fd_bls_pub_compress( pub, pcbuf );
  dt = fd_log_wallclock() - dt;
  log_bench( "fd_bls_pub_compress", iter, dt );

  dt = fd_log_wallclock();
  for( ulong rem=iter; rem; rem-- ) fd_bls_pub_de_compressed( pde, pcbuf );
  dt = fd_log_wallclock() - dt;
  log_bench( "fd_bls_pub_de_compressed", iter, dt );

  dt = fd_log_wallclock();
  for( ulong rem=iter; rem; rem-- ) { uchar b2[FD_BLS_PUB_SZ]; fd_bls_pub_ser( pa, b2 ); fd_bls_pub_de( pde, b2, FD_BLS_PUB_SZ ); }
  dt = fd_log_wallclock() - dt;
  log_bench( "fd_bls_pub_ser_projective", iter, dt );

  dt = fd_log_wallclock();
  for( ulong rem=iter; rem; rem-- ) fd_bls_pub_compress( pa, pcbuf );
  dt = fd_log_wallclock() - dt;
  log_bench( "fd_bls_pub_compress_projective", iter, dt );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
