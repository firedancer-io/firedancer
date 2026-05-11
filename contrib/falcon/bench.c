/* bench.c - microbenchmark harness for contrib/falcon.
 *
 * Reports three tables, in the same row order as Tables 1, 2, 3 of
 * the paper (and prefixed with "TABLE 1/2/3" so they map 1:1):
 *   1. Verify, standards-compliant variants.  ns/call + speedup vs
 *      `falcon_ref_xkcp` (the 1.00x baseline).
 *   2. Verify, non-standard KTP256 variants. ns/call + speedup vs
 *      the same baseline as Table 1.
 *   3. Subcomponent breakdown for the four "repeated" variants
 *      (the ones that appear in both Table 1/2 and in Table 3):
 *      decode + hash-to-point + mul, ns and percent of row total.
 *
 * For the 4 repeated variants the Table 1/2 totals are *derived* from
 * the Table 3 subparts (dec + h2p + mul), so every row that names the
 * same implementation reports the same number across all three tables.
 * Variants that appear in only one table (e.g. falcon_ref, falcon_x86,
 * falcon_avx512_from_ref, the *_barrett rows) are timed end-to-end.
 *
 * Usage:
 *   ./bench               # default 20000 iterations per batch
 *   ./bench --iter N      # override
 */

#include "falcon.h"
#include "falcon_avx512_common.h"
#include "test_vectors.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* Pornin internals (vendor/falcon-round3) -- exposed for the
 * subcomponent table. */
extern size_t falcon_inner_modq_decode  ( uint16_t * x, unsigned logn,
                                          void const * in, size_t max_in_len );
extern size_t falcon_inner_comp_decode  ( int16_t  * x, unsigned logn,
                                          void const * in, size_t max_in_len );
extern void   falcon_inner_to_ntt_monty ( uint16_t * h, unsigned logn );
extern int    falcon_inner_verify_raw   ( uint16_t const * c0,
                                          int16_t  const * s2,
                                          uint16_t const * h,
                                          unsigned logn, uint8_t * tmp );

extern void   hash_to_point_xkcp        ( uint16_t * out,
                                          uint8_t const * in, size_t in_len );
/* fa512_hash_to_point (AVX-512 vectorized rejection sampling, standard
 * SHAKE256) and fa512_hash_to_point_ktp256 are declared by
 * falcon_avx512_common.h. */

extern int    falcon_avx512_bench_mul   ( falcon_fq_t        const * c,
                                          falcon_pubkey_t    const * pubk,
                                          falcon_signature_t const * sig );

static double
now_ns( void ) {
  struct timespec ts;
  clock_gettime( CLOCK_MONOTONIC, &ts );
  return (double)ts.tv_sec * 1e9 + (double)ts.tv_nsec;
}

#define BENCH_BATCH( BODY, ITER, OUT ) do {                                  \
    double best = 1e30;                                                      \
    for( int _b=0; _b<3; _b++ ) {                                            \
      double t0 = now_ns();                                                  \
      for( unsigned long _i=0; _i<(ITER); _i++ ) { BODY; }                   \
      double t1 = now_ns();                                                  \
      double per = ( t1 - t0 ) / (double)(ITER);                             \
      if( per < best ) best = per;                                           \
    }                                                                        \
    (OUT) = best;                                                            \
  } while(0)

static int g_sink;
#define SINK( x ) do { g_sink ^= (int)(uintptr_t)(x); } while(0)

/* ---------- Verify benches (for non-repeated rows only) ---------- */

#define BENCH_VERIFY_FN( NAME )                                                                  \
  static double bench_verify_##NAME( unsigned long iter ) {                                      \
    uint8_t m[ 2048 ]; size_t ml; double r;                                                      \
    BENCH_BATCH( ({                                                                              \
      SINK( NAME##_crypto_sign_open( m, &ml, tv_sm, tv_sm_len, tv_pubkey ) );                    \
    }), iter, r );                                                                               \
    return r;                                                                                    \
  }

BENCH_VERIFY_FN( falcon_ref                       )
BENCH_VERIFY_FN( falcon_avx512_from_ref           )
BENCH_VERIFY_FN( falcon_x86                       )
BENCH_VERIFY_FN( falcon_x86_ktp256                )
BENCH_VERIFY_FN( falcon_avx512_barrett            )
BENCH_VERIFY_FN( falcon_avx512_barrett_alwaysred  )
BENCH_VERIFY_FN( falcon_avx512_barrett_ktp256     )

/* ---------- Subcomponent benches ----------
 * Time the three measurable stages of the verifier in isolation, for
 * the rows of Table 3:
 *   - decode: pubkey + signature parsing (Pornin codec or AVX-512)
 *   - h2p:    hash-to-point (XKCP SHAKE / AVX-512 SHAKE / KTP256)
 *   - mul:    two forward NTTs + Hadamard + inverse NTT + norm check
 */

static uint16_t g_h_decoded     [ 512 ];
static int16_t  g_s2_decoded    [ 512 ];
static uint16_t g_c_xkcp        [ 512 ];
static falcon_pubkey_t    g_pubk_avx[1];
static falcon_signature_t g_sig_avx [1];
static falcon_fq_t        g_c_avx_pornin [ 512 + 16 ] __attribute__((aligned(64)));

static void
prep_subparts( void ) {
  if( falcon_inner_modq_decode( g_h_decoded, 9, tv_pubkey + 1, FALCON_PUBKEY_SIZE - 1 )
      != FALCON_PUBKEY_SIZE - 1 ) { fprintf( stderr, "modq_decode failed\n" ); exit( 1 ); }
  size_t sig_len = ( (size_t)tv_sm[ 0 ] << 8 ) | (size_t)tv_sm[ 1 ];
  uint8_t const * esig = tv_sm + 2 + 40 + TV_MSG_LEN;
  if( falcon_inner_comp_decode( g_s2_decoded, 9, esig + 1, sig_len - 1 )
      != sig_len - 1 ) { fprintf( stderr, "comp_decode failed\n" ); exit( 1 ); }

  fa512_parse_pk     ( g_pubk_avx, tv_pubkey + 1 );
  fa512_parse_comp_s2( g_sig_avx->s2, esig + 1, sig_len - 1 );

  hash_to_point_xkcp( g_c_xkcp, tv_sm + 2, 40 + TV_MSG_LEN );
  for( int i=0; i<512; i++ ) g_c_avx_pornin[ i ] = (falcon_fq_t)g_c_xkcp[ i ];
}

/* decode */

static double
bench_decode_pornin( unsigned long iter ) {
  size_t  sig_len = ( (size_t)tv_sm[ 0 ] << 8 ) | (size_t)tv_sm[ 1 ];
  uint8_t const * esig = tv_sm + 2 + 40 + TV_MSG_LEN;
  uint16_t h [ 512 ]; int16_t  s2[ 512 ];
  double r;
  BENCH_BATCH( ({
    SINK( falcon_inner_modq_decode( h,  9, tv_pubkey + 1, FALCON_PUBKEY_SIZE - 1 ) );
    SINK( falcon_inner_comp_decode( s2, 9, esig + 1, sig_len - 1 ) );
  }), iter, r );
  return r;
}

static double
bench_decode_avx512( unsigned long iter ) {
  size_t  sig_len = ( (size_t)tv_sm[ 0 ] << 8 ) | (size_t)tv_sm[ 1 ];
  uint8_t const * esig = tv_sm + 2 + 40 + TV_MSG_LEN;
  falcon_pubkey_t    pubk[1]; falcon_signature_t sig [1];
  double r;
  BENCH_BATCH( ({
    SINK( fa512_parse_pk     ( pubk, tv_pubkey + 1 ) );
    SINK( fa512_parse_comp_s2( sig->s2, esig + 1, sig_len - 1 ) );
  }), iter, r );
  return r;
}

/* hash-to-point */

static double
bench_h2p_xkcp( unsigned long iter ) {
  uint16_t c[ 512 ]; double r;
  BENCH_BATCH( ({ hash_to_point_xkcp( c, tv_sm + 2, 40 + TV_MSG_LEN ); SINK( c[ 0 ] ); }), iter, r );
  return r;
}

static double
bench_h2p_avx512( unsigned long iter ) {
  /* +16 slack: fa512_hash_to_point ends each iteration with a 16-lane
   * masked-store at `c+i` where `i<N` may equal `N-1`. */
  falcon_fq_t c[ 512 + 16 ] __attribute__((aligned(64))); double r;
  BENCH_BATCH( ({ fa512_hash_to_point( c, tv_sm + 2, tv_sm + 2 + 40, TV_MSG_LEN ); SINK( c[ 0 ] ); }), iter, r );
  return r;
}

static double
bench_h2p_ktp256( unsigned long iter ) {
  uint16_t c[ 512 ]; double r;
  BENCH_BATCH( ({ fa512_hash_to_point_ktp256( c, tv_sm + 2, 40 + TV_MSG_LEN ); SINK( c[ 0 ] ); }), iter, r );
  return r;
}

/* mul (full multiplication step) */

static double
bench_mul_pornin( unsigned long iter ) {
  uint16_t h[ 512 ]; uint16_t c[ 512 ]; uint8_t tmp[ 2 * 512 ];
  double r;
  BENCH_BATCH( ({
    memcpy( h, g_h_decoded, sizeof h );
    memcpy( c, g_c_xkcp,    sizeof c );
    falcon_inner_to_ntt_monty( h, 9 );
    SINK( falcon_inner_verify_raw( c, g_s2_decoded, h, 9, tmp ) );
  }), iter, r );
  return r;
}

static double
bench_mul_avx512( unsigned long iter ) {
  double r;
  BENCH_BATCH( ({ SINK( falcon_avx512_bench_mul( g_c_avx_pornin, g_pubk_avx, g_sig_avx ) ); }), iter, r );
  return r;
}

/* ---------- Correctness ---------- */

static int
correctness( void ) {
  uint8_t m[ 2048 ]; size_t ml = 0;
  if( falcon_ref_crypto_sign_open            ( m, &ml, tv_sm, tv_sm_len, tv_pubkey ) ) return 1;
  if( falcon_ref_xkcp_crypto_sign_open       ( m, &ml, tv_sm, tv_sm_len, tv_pubkey ) ) return 2;
  if( falcon_avx512_from_ref_crypto_sign_open( m, &ml, tv_sm, tv_sm_len, tv_pubkey ) ) return 3;
  if( falcon_x86_crypto_sign_open            ( m, &ml, tv_sm, tv_sm_len, tv_pubkey ) ) return 4;
  if( falcon_avx512_barrett_crypto_sign_open ( m, &ml, tv_sm, tv_sm_len, tv_pubkey ) ) return 5;
  if( falcon_avx512_barrett_alwaysred_crypto_sign_open( m, &ml, tv_sm, tv_sm_len, tv_pubkey ) ) return 7;
  if( falcon_avx512_crypto_sign_open         ( m, &ml, tv_sm, tv_sm_len, tv_pubkey ) ) return 6;
  return 0;
}

/* ---------- Output ----------
 * Three tables, one row per implementation, mapping 1:1 to the LaTeX
 * tables in the paper.  The fastest row of each table is suffixed
 * "[fastest]" so a downstream script can find it.  The four "repeated"
 * rows (falcon_ref_xkcp, falcon_ref_ktp256, falcon_avx512,
 * falcon_avx512_ktp256) carry the same ns value across Tables 1/2 and
 * Table 3 because they're synthesised from the same subparts. */

static void
emit_table1_verify( double v_ref, double v_ref_xkcp, double v_avx_fr,
                    double v_x86, double v_avx_b,   double v_avx ) {
  double const ref = v_ref_xkcp;
  printf( "\n=== TABLE 1: Verify (standards-compliant), ns/call ===\n" );
  printf( "  %-46s %10s %8s\n", "Implementation", "ns/call", "x ref" );
  printf( "  %-46s %10.1f %7.2fx\n", "falcon_ref",                                 v_ref,      ref / v_ref      );
  printf( "  %-46s %10.1f %7.2fx  (baseline)\n", "falcon_ref_xkcp",                v_ref_xkcp, 1.00              );
  printf( "  %-46s %10.1f %7.2fx\n", "falcon_avx512_from_ref (Pornin Montgomery)", v_avx_fr,   ref / v_avx_fr   );
  printf( "  %-46s %10.1f %7.2fx\n", "falcon_x86 (auto-vec C, Shoup)",             v_x86,      ref / v_x86      );
  printf( "  %-46s %10.1f %7.2fx\n", "falcon_avx512_barrett (Barrett)",            v_avx_b,    ref / v_avx_b    );
  printf( "  %-46s %10.1f %7.2fx  [fastest]\n", "falcon_avx512 (Shoup, recommended)", v_avx,   ref / v_avx      );
}

static void
emit_table2_ktp256( double v_ref_xkcp,
                    double v_ref_ktp, double v_x86_ktp,
                    double v_avx_b_ktp, double v_avx_ktp ) {
  double const ref = v_ref_xkcp;
  printf( "\n=== TABLE 2: Verify (KTP256, non-standard), ns/call ===\n" );
  printf( "  %-46s %10s %8s\n", "Implementation", "ns/call", "x ref" );
  printf( "  %-46s %10.1f %7.2fx\n", "falcon_ref_ktp256",            v_ref_ktp,    ref / v_ref_ktp    );
  printf( "  %-46s %10.1f %7.2fx\n", "falcon_x86_ktp256",            v_x86_ktp,    ref / v_x86_ktp    );
  printf( "  %-46s %10.1f %7.2fx\n", "falcon_avx512_barrett_ktp256", v_avx_b_ktp,  ref / v_avx_b_ktp  );
  printf( "  %-46s %10.1f %7.2fx  [fastest]\n", "falcon_avx512_ktp256 (Shoup)", v_avx_ktp, ref / v_avx_ktp );
}

static void
print_subparts_row( char const * name, char const * tag,
                    double dec, double h2p, double mul, double ref ) {
  double sum = dec + h2p + mul;
  printf( "  %-30s %8.1f %5.1f%%  %8.1f %5.1f%%  %8.1f %5.1f%%  %9.1f  %5.2fx%s\n",
          name,
          dec, 100.0 * dec / sum,
          h2p, 100.0 * h2p / sum,
          mul, 100.0 * mul / sum,
          sum, ref / sum,
          tag );
}

static void
emit_table3_subparts( double dec_p, double dec_a,
                      double h_xkcp, double h_avx, double h_ktp,
                      double mul_p,  double mul_a ) {
  /* Baseline = falcon_ref_xkcp subparts sum (the same number reported
   * for falcon_ref_xkcp in Table 1). */
  double const ref = dec_p + h_xkcp + mul_p;
  printf( "\n=== TABLE 3: Subcomponent breakdown ===\n" );
  printf( "  %-30s %8s %6s  %8s %6s  %8s %6s  %9s  %6s\n",
          "Variant", "decode", "%", "h2p", "%", "mul", "%", "sum", "x ref" );
  print_subparts_row( "falcon_ref_xkcp",        "",            dec_p, h_xkcp, mul_p, ref );
  print_subparts_row( "falcon_ref_ktp256",      "",            dec_p, h_ktp,  mul_p, ref );
  print_subparts_row( "falcon_avx512",          "",            dec_a, h_avx,  mul_a, ref );
  print_subparts_row( "falcon_avx512_ktp256",   "  [fastest]", dec_a, h_ktp,  mul_a, ref );
}

int
main( int argc, char ** argv ) {
  unsigned long iter = 20000;
  for( int i=1; i<argc; i++ ) {
    if( !strcmp( argv[ i ], "--iter" ) && i+1<argc )           iter = strtoul( argv[ ++i ], NULL, 10 );
    else if( !strcmp( argv[ i ], "-h" ) || !strcmp( argv[ i ], "--help" ) ) {
      fprintf( stderr,
               "usage: %s [--iter N]\n"
               "  --iter N   number of iterations per batch (default 20000)\n",
               argv[ 0 ] );
      return 0;
    }
    else { fprintf( stderr, "unknown arg %s\n", argv[ i ] ); return 1; }
  }

  tv_make_signed_message();
  if( !tv_sm_len ) { fprintf( stderr, "tv_make_signed_message failed\n" ); return 1; }
  int rc = correctness();
  if( rc ) { fprintf( stderr, "correctness failed (rc=%d)\n", rc ); return 1; }
  fprintf( stderr, "correctness: ok, iter=%lu\n", iter );
  prep_subparts();

  /* Subparts (Table 3): measured once, used to derive the totals for
   * the 4 repeated rows of Tables 1 and 2. */
  double s_dec_p  = bench_decode_pornin ( iter );
  double s_dec_a  = bench_decode_avx512 ( iter );
  double s_h_xkcp = bench_h2p_xkcp      ( iter );
  double s_h_avx  = bench_h2p_avx512    ( iter );
  double s_h_ktp  = bench_h2p_ktp256    ( iter );
  double s_mul_p  = bench_mul_pornin    ( iter );
  double s_mul_a  = bench_mul_avx512    ( iter );

  /* Derived totals for the four repeated impls. */
  double v_ref_xkcp = s_dec_p + s_h_xkcp + s_mul_p;
  double v_ref_ktp  = s_dec_p + s_h_ktp  + s_mul_p;
  double v_avx      = s_dec_a + s_h_avx  + s_mul_a;
  double v_avx_ktp  = s_dec_a + s_h_ktp  + s_mul_a;

  /* Non-repeated impls: end-to-end verify timing. */
  double v_ref        = bench_verify_falcon_ref                  ( iter );
  double v_avx_fr     = bench_verify_falcon_avx512_from_ref      ( iter );
  double v_x86        = bench_verify_falcon_x86                  ( iter );
  double v_x86_ktp    = bench_verify_falcon_x86_ktp256           ( iter );
  double v_avx_b      = bench_verify_falcon_avx512_barrett       ( iter );
  double v_avx_b_ar   = bench_verify_falcon_avx512_barrett_alwaysred( iter );
  double v_avx_b_ktp  = bench_verify_falcon_avx512_barrett_ktp256( iter );

  emit_table1_verify( v_ref, v_ref_xkcp, v_avx_fr, v_x86, v_avx_b, v_avx );

  /* Diagnostic: lazy-reduction attribution.  Same NTT skeleton and same
   * Barrett fq_mul as falcon_avx512_barrett, but with always-reduced
   * add/sub.  Comparing v_avx_b vs v_avx_b_ar isolates lazy reduction;
   * v_avx_b_ar vs v_avx_fr isolates the skeleton at fixed eager
   * reduction (the latter uses Pornin Montgomery so the skeleton bound
   * is loose, but it brackets the answer). */
  printf( "\n=== Diagnostic: lazy reduction vs NTT skeleton ===\n" );
  printf( "  %-46s %10.1f %7.2fx\n",
          "falcon_avx512_barrett_alwaysred",
          v_avx_b_ar, v_ref_xkcp / v_avx_b_ar );

  emit_table2_ktp256( v_ref_xkcp, v_ref_ktp, v_x86_ktp, v_avx_b_ktp, v_avx_ktp );
  emit_table3_subparts( s_dec_p, s_dec_a, s_h_xkcp, s_h_avx, s_h_ktp, s_mul_p, s_mul_a );
  printf( "\n" );
  return 0;
}
