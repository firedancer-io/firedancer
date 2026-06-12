/* Tests are run through `make run-test-vectors` and are available at:
   https://github.com/firedancer-io/test-vectors/tree/main/instr/fixtures/zk_sdk

   This unit test just runs an instance of pubkey_validity. */
#include "fd_zksdk_private.h"
#include "../hex/fd_hex.h"
#include "../ed25519/fd_curve25519_scalar.h"

#include "instructions/test_fd_zksdk_pubkey_validity.h"

// turn on/off benches
#define BENCH 0

#if BENCH
static void
log_bench( char const * descr,
           ulong        iter,
           long         dt ) {
  float khz = 1e6f *(float)iter/(float)dt;
  float tau = (float)dt /(float)iter;
  FD_LOG_NOTICE(( "%-31s %11.3fK/s/core %10.3f ns/call", descr, (double)khz, (double)tau ));
}
#endif

/* Regression test for the audit finding: when pubkey2 is the identity point
   (all-zero compressed), handle2 must still be included in the MSM.

   The bug (pre-fix): the verifier skipped pub2 and handle2 from the MSM
   whenever pubkey2 was the identity.  With y_r=1, y_x=1, the construction
     Y_0 = G+H,  Y_1 = G,  Y_2 = 0,  z_r = c+1,  z_x = 1
   satisfies the old 7-point MSM for *any* challenge c because all
   c-dependent terms cancel.  A forged proof can therefore be built for any
   handle2 by computing a fresh c from the transcript that hashes in that
   particular handle2.  The fixed verifier adds a -c*w^2*handle2 term which
   breaks the cancellation for handle2 != 0.

   The test constructs:
     A. proof_0:  valid proof for handle2 = 0              -- must PASS (always)
     B. proof_G:  forged proof for handle2 = G (z_r=c_G+1) -- must FAIL (after fix)
     C. proof_H:  forged proof for handle2 = H (z_r=c_H+1) -- must FAIL (after fix)

   Proof_G and proof_H would have passed the buggy verifier (all c-terms cancel
   in the old 7-point MSM), but the fix's extra -c*w^2*handle2 term prevents it. */
static void
test_grp_ciph_2h_validity_pubkey2_zero( void ) {
  /* Compressed-point encodings for the common parameters */
  uchar pubkey1[32], pubkey2[32], comm[32], handle1[32];
  fd_ristretto255_point_compress( pubkey1, fd_zksdk_basepoint_G ); /* G         */
  fd_memset( pubkey2, 0, 32 );                                     /* 0 (ident) */
  fd_ristretto255_point_compress( comm,    fd_zksdk_basepoint_H ); /* H         */
  fd_memcpy( handle1, pubkey1, 32 );                               /* G  (=1*G) */

  /* Proof commitment points shared by all three proofs:
       Y_0 = G+H,  Y_1 = G,  Y_2 = 0  (blinding: y_r=1, y_x=1) */
  fd_ristretto255_point_t pt[1];
  uchar y0[32], y1[32], y2[32];
  fd_ristretto255_point_add( pt, fd_zksdk_basepoint_G, fd_zksdk_basepoint_H );
  fd_ristretto255_point_compress( y0, pt );
  fd_memcpy( y1, pubkey1, 32 );
  fd_memset( y2, 0, 32 );

  /* build_proof: derive the transcript challenge for a given handle2, then set
     z_r = c+1, z_x = 1.  The transcript order matches the verifier exactly. */
# define build_proof( proof_, handle2_ ) do {                                    \
    grp_ciph_2h_t _gc[1];                                                        \
    fd_memcpy( _gc->commitment,        comm,       32 );                         \
    fd_memcpy( _gc->handles[0].handle, handle1,    32 );                         \
    fd_memcpy( _gc->handles[1].handle, (handle2_), 32 );                         \
    fd_zksdk_transcript_t _tr[1];                                                \
    fd_zksdk_transcript_init( _tr, FD_TRANSCRIPT_LITERAL(                        \
      "grouped-ciphertext-validity-2-handles-instruction") );                    \
    /* grouped_ciphertext_validity_hash_context() */                             \
    fd_zksdk_transcript_append_pubkey( _tr, FD_TRANSCRIPT_LITERAL("first-pubkey"),        pubkey1 ); \
    fd_zksdk_transcript_append_pubkey( _tr, FD_TRANSCRIPT_LITERAL("second-pubkey"),       pubkey2 ); \
    fd_zksdk_transcript_append_message( _tr, FD_TRANSCRIPT_LITERAL("grouped-ciphertext"), \
                                        (uchar *)_gc, sizeof(grp_ciph_2h_t) );  \
    fd_zksdk_transcript_domsep_grp_ciph_val_proof( _tr, 2 );                    \
    FD_TEST( fd_zksdk_transcript_validate_and_append_point( _tr,                 \
               FD_TRANSCRIPT_LITERAL("Y_0"), y0 ) == FD_TRANSCRIPT_SUCCESS );   \
    FD_TEST( fd_zksdk_transcript_validate_and_append_point( _tr,                 \
               FD_TRANSCRIPT_LITERAL("Y_1"), y1 ) == FD_TRANSCRIPT_SUCCESS );   \
    fd_zksdk_transcript_append_point( _tr, FD_TRANSCRIPT_LITERAL("Y_2"), y2 );  \
    uchar _c[32];                                                                \
    fd_zksdk_transcript_challenge_scalar( _c, _tr, FD_TRANSCRIPT_LITERAL("c") ); \
    fd_memcpy( (proof_)->y0, y0, 32 );                                           \
    fd_memcpy( (proof_)->y1, y1, 32 );                                           \
    fd_memcpy( (proof_)->y2, y2, 32 );                                           \
    fd_curve25519_scalar_add( (proof_)->zr, fd_curve25519_scalar_one, _c );      \
    fd_curve25519_scalar_set( (proof_)->zx, fd_curve25519_scalar_one );          \
  } while(0)

  fd_zksdk_grp_ciph_2h_val_proof_t   proof[1];
  fd_zksdk_grp_ciph_2h_val_context_t ctx[1];
  fd_memcpy( ctx->pubkey1, pubkey1, 32 );
  fd_memcpy( ctx->pubkey2, pubkey2, 32 );
  fd_memcpy( ctx->grouped_ciphertext->commitment,        comm,    32 );
  fd_memcpy( ctx->grouped_ciphertext->handles[0].handle, handle1, 32 );

  /* Case A -- valid proof for handle2=0, must PASS. */
  uchar h2_zero[32]; fd_memset( h2_zero, 0, 32 );
  build_proof( proof, h2_zero );
  fd_memcpy( ctx->grouped_ciphertext->handles[1].handle, h2_zero, 32 );
  FD_TEST( fd_zksdk_instr_verify_proof_grouped_ciphertext_2_handles_validity( ctx, proof ) == FD_ZKSDK_VERIFY_PROOF_SUCCESS );

  /* Case B -- forged proof for handle2=G, must FAIL.
     z_r is computed for the transcript that includes handle2=G, so all
     c-dependent terms still cancel in the old (pre-fix) 7-point MSM.
     The fix adds the -c*w^2*G term which breaks the cancellation. */
  build_proof( proof, pubkey1 );   /* pubkey1 == G */
  fd_memcpy( ctx->grouped_ciphertext->handles[1].handle, pubkey1, 32 );
  FD_TEST( fd_zksdk_instr_verify_proof_grouped_ciphertext_2_handles_validity( ctx, proof ) == FD_ZKSDK_VERIFY_PROOF_ERROR );

  /* Case C -- forged proof for handle2=H, same argument with a different point. */
  build_proof( proof, comm );      /* comm == H */
  fd_memcpy( ctx->grouped_ciphertext->handles[1].handle, comm, 32 );
  FD_TEST( fd_zksdk_instr_verify_proof_grouped_ciphertext_2_handles_validity( ctx, proof ) == FD_ZKSDK_VERIFY_PROOF_ERROR );

# undef build_proof

  FD_LOG_NOTICE(( "test_grp_ciph_2h_validity_pubkey2_zero... ok" ));
}

FD_FN_UNUSED static void
test_pubkey_validity( FD_FN_UNUSED fd_rng_t * rng ) {
  char * hex = tx_pubkey_validity;
  ulong hex_sz = strlen(tx_pubkey_validity);
  ulong offset = instr_offset_pubkey_validity;
  ulong context_sz = fd_zksdk_context_sz[FD_ZKSDK_INSTR_VERIFY_PUBKEY_VALIDITY];

  // load test data
  uchar tx[ 1232 ];
  fd_hex_decode( tx, hex, hex_sz/2 );
  uchar * context = tx+offset+1;
  uchar * proof   = context+context_sz;

  // valid
  FD_TEST( fd_zksdk_instr_verify_proof_pubkey_validity( context, proof )==FD_ZKSDK_VERIFY_PROOF_SUCCESS );

  // invalid proof
  proof[1 + context_sz] ^= 0xff;
  FD_TEST( fd_zksdk_instr_verify_proof_pubkey_validity( context, proof )==FD_ZKSDK_VERIFY_PROOF_ERROR );
  proof[1 + context_sz] ^= 0xff;

  FD_LOG_NOTICE(( "test_pubkey_validity... ok" ));
  /* Benchmarks */
#if BENCH
  ulong iter = 10000UL;
  long dt = fd_log_wallclock();
  for( ulong rem=iter; rem; rem-- ) {
    FD_COMPILER_FORGET( proof ); FD_COMPILER_FORGET( context );
    fd_zksdk_instr_verify_proof_pubkey_validity( context, proof );
  }
  dt = fd_log_wallclock() - dt;
  log_bench( "fd_zksdk_instr_verify_proof_pubkey_validity", iter, dt );
#endif
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );
  fd_rng_t _rng[1]; fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, 0U, 0UL ) );

  test_pubkey_validity( rng );
  test_grp_ciph_2h_validity_pubkey2_zero();

  FD_LOG_NOTICE(( "pass" ));
  fd_rng_delete( fd_rng_leave( rng ) );
  fd_halt();
  return 0;
}
