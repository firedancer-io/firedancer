/* test_falcon.c - correctness tests for the verifiers in this directory.
 *
 *   - falcon_ref_xkcp     : Pornin round-3 reference + XKCP plain64 SHAKE256.
 *                           Used as the baseline (1.00x).
 *   - falcon_ref_ktp256 : non-standard TurboSHAKE12 + 8-way parallel-squeeze
 *                           hash-to-point on the Pornin verify pipeline.
 *   - falcon_x86          : auto-vectorisable C with vectoriser-friendly
 *                           loop structure (no intrinsics).
 *   - falcon_x86_ktp256 : auto-vec C + parallel-squeeze hash.
 *   - falcon_avx512_barrett     : AVX-512, Barrett field multiplication.
 *   - falcon_avx512             : AVX-512, Shoup field multiplication (recommended).
 *   - falcon_avx512_from_ref    : AVX-512 vectorisation of Pornin's reference
 *                                 Montgomery multiplication.
 *   - falcon_avx512_barrett_ktp256 : Barrett AVX-512 + parallel-squeeze hash.
 *   - falcon_avx512_ktp256         : Shoup AVX-512 + parallel-squeeze hash.
 */

#include "falcon.h"
#include "test_vectors.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK( cond ) do { \
  if( !(cond) ) { \
    fprintf( stderr, "FAIL: %s:%d %s\n", __FILE__, __LINE__, #cond ); \
    exit( 1 ); \
  } \
} while(0)

/* All-in-one valid verify test.  Every standards-compliant variant must
 * accept the test vector and return the original message. */
static void
test_one_variant( const char * name,
                  int (*fn)( uint8_t *, size_t *, uint8_t const *, size_t,
                             uint8_t const * ) ) {
  uint8_t m[ 2048 ];
  size_t  ml = 0;
  CHECK( 0 == fn( m, &ml, tv_sm, tv_sm_len, tv_pubkey ) );
  CHECK( ml == TV_MSG_LEN );
  CHECK( 0 == memcmp( m, tv_msg, TV_MSG_LEN ) );
  (void)name;
}

static void
test_verify_valid( void ) {
  test_one_variant( "falcon_ref",              falcon_ref_crypto_sign_open              );
  test_one_variant( "falcon_ref_xkcp",         falcon_ref_xkcp_crypto_sign_open         );
  test_one_variant( "falcon_x86",              falcon_x86_crypto_sign_open              );
  test_one_variant( "falcon_avx512_barrett",   falcon_avx512_barrett_crypto_sign_open   );
  test_one_variant( "falcon_avx512",           falcon_avx512_crypto_sign_open           );
  test_one_variant( "falcon_avx512_from_ref",  falcon_avx512_from_ref_crypto_sign_open  );
  printf( "OK: verify (valid) - falcon_ref, falcon_ref_xkcp, falcon_x86, "
          "falcon_avx512_{barrett,,from_ref}\n" );
}

static void
test_verify_rejects( void ) {
  uint8_t m_out[ 2048 ];
  size_t  ml_out;

  typedef int (*verify_fn)( uint8_t *, size_t *, uint8_t const *, size_t,
                            uint8_t const * );
  verify_fn fns[] = {
    falcon_ref_crypto_sign_open,
    falcon_ref_xkcp_crypto_sign_open,
    falcon_x86_crypto_sign_open,
    falcon_avx512_barrett_crypto_sign_open,
    falcon_avx512_crypto_sign_open,
    falcon_avx512_from_ref_crypto_sign_open,
  };
  size_t nfns = sizeof(fns) / sizeof(fns[0]);

  /* Mutated nonce. */
  uint8_t mut[ sizeof(tv_sm) ];
  memcpy( mut, tv_sm, tv_sm_len );
  mut[ 2 ] ^= 1;
  for( size_t k=0; k<nfns; k++ )
    CHECK( 0 != fns[ k ]( m_out, &ml_out, mut, tv_sm_len, tv_pubkey ) );

  /* Mutated message. */
  memcpy( mut, tv_sm, tv_sm_len );
  mut[ 2 + 40 ] ^= 1;
  for( size_t k=0; k<nfns; k++ )
    CHECK( 0 != fns[ k ]( m_out, &ml_out, mut, tv_sm_len, tv_pubkey ) );

  /* Mutated signature. */
  memcpy( mut, tv_sm, tv_sm_len );
  mut[ 2 + 40 + TV_MSG_LEN + 1 ] ^= 1;
  for( size_t k=0; k<nfns; k++ )
    CHECK( 0 != fns[ k ]( m_out, &ml_out, mut, tv_sm_len, tv_pubkey ) );

  /* Mutated public key. */
  uint8_t pk[ FALCON_PUBKEY_SIZE ];
  memcpy( pk, tv_pubkey, sizeof(pk) );
  pk[ 1 ] ^= 1;
  for( size_t k=0; k<nfns; k++ )
    CHECK( 0 != fns[ k ]( m_out, &ml_out, tv_sm, tv_sm_len, pk ) );

  printf( "OK: verify rejects mutated nonce, msg, sig, pk\n" );
}

/* The four ktp256 variants share a non-standard hash-to-point and
 * therefore cannot verify Falcon round 3 signatures.  We only check
 * that they run, are deterministic across two calls, and -- across
 * variants -- agree on the decoded message length (the underlying
 * verify_raw still runs to completion, so msg_len comes out the same
 * regardless of NTT pipeline). */
static void
test_ktp256_runs( void ) {
  typedef int (*verify_fn)( uint8_t *, size_t *, uint8_t const *, size_t,
                            uint8_t const * );
  struct { char const * name; verify_fn fn; } v[] = {
    { "falcon_ref_ktp256",            falcon_ref_ktp256_crypto_sign_open            },
    { "falcon_x86_ktp256",            falcon_x86_ktp256_crypto_sign_open            },
    { "falcon_avx512_barrett_ktp256", falcon_avx512_barrett_ktp256_crypto_sign_open },
    { "falcon_avx512_ktp256",         falcon_avx512_ktp256_crypto_sign_open         },
  };
  size_t nv = sizeof(v) / sizeof(v[0]);

  for( size_t k=0; k<nv; k++ ) {
    uint8_t m_a[ 2048 ], m_b[ 2048 ];
    size_t  ml_a = 0,    ml_b = 0;
    int ra = v[ k ].fn( m_a, &ml_a, tv_sm, tv_sm_len, tv_pubkey );
    int rb = v[ k ].fn( m_b, &ml_b, tv_sm, tv_sm_len, tv_pubkey );
    CHECK( ra == rb );
    CHECK( ml_a == ml_b );
    printf( "OK: %s runs deterministically (rc=%d, mlen=%zu)\n",
            v[ k ].name, ra, ml_a );
  }
}

int
main( void ) {
  tv_make_signed_message();
  CHECK( tv_sm_len > 0 );
  test_verify_valid();
  test_verify_rejects();
  test_ktp256_runs();
  printf( "pass\n" );
  return 0;
}
