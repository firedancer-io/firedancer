#include "../fd_zksdk_private.h"

/* https://github.com/solana-program/zk-elgamal-proof/blob/zk-sdk%40v5.0.1/zk-sdk/src/sigma_proofs/batched_grouped_ciphertext_validity/handles_3.rs#L180 */
static inline void
batched_grouped_ciphertext_validity_hash_context(
  fd_zksdk_transcript_t * transcript,
  uchar const             pubkey1 [ 32 ],
  uchar const             pubkey2 [ 32 ],
  uchar const             pubkey3 [ 32 ],
  grp_ciph_3h_t const *   grouped_ciphertext_lo,
  grp_ciph_3h_t const *   grouped_ciphertext_hi ) {
  fd_zksdk_transcript_append_pubkey ( transcript, FD_TRANSCRIPT_LITERAL("first-pubkey"),  pubkey1 );
  fd_zksdk_transcript_append_pubkey ( transcript, FD_TRANSCRIPT_LITERAL("second-pubkey"), pubkey2 );
  fd_zksdk_transcript_append_pubkey ( transcript, FD_TRANSCRIPT_LITERAL("third-pubkey"),  pubkey3 );
  fd_zksdk_transcript_append_message( transcript, FD_TRANSCRIPT_LITERAL("grouped-ciphertext-lo"), (uchar *)grouped_ciphertext_lo, sizeof(grp_ciph_3h_t) );
  fd_zksdk_transcript_append_message( transcript, FD_TRANSCRIPT_LITERAL("grouped-ciphertext-hi"), (uchar *)grouped_ciphertext_hi, sizeof(grp_ciph_3h_t) );
}

/* https://github.com/solana-program/zk-elgamal-proof/blob/zk-sdk%40v5.0.1/zk-sdk/src/sigma_proofs/batched_grouped_ciphertext_validity/handles_3.rs#L111 */
static inline int
fd_zksdk_verify_proof_batched_grouped_ciphertext_3_handles_validity(
  fd_zksdk_grp_ciph_3h_val_proof_t const * proof,
  uchar const                              pubkey1    [ 32 ],
  uchar const                              pubkey2    [ 32 ],
  uchar const                              pubkey3    [ 32 ],
  grp_ciph_3h_t const *                    grouped_ciphertext_lo,
  grp_ciph_3h_t const *                    grouped_ciphertext_hi,
  fd_zksdk_transcript_t *                  transcript ) {

  /* https://github.com/solana-program/zk-elgamal-proof/blob/zk-sdk%40v5.0.1/zk-sdk/src/sigma_proofs/batched_grouped_ciphertext_validity/handles_3.rs#L123-L129 */
  if( FD_UNLIKELY( fd_memeq( pubkey1,                        fd_ristretto255_compressed_zero, 32 )
                || fd_memeq( pubkey2,                        fd_ristretto255_compressed_zero, 32 )
                || fd_memeq( grouped_ciphertext_lo->commitment, fd_ristretto255_compressed_zero, 32 )
                || fd_memeq( grouped_ciphertext_hi->commitment, fd_ristretto255_compressed_zero, 32 ) ) ) {
    return FD_ZKSDK_VERIFY_PROOF_ERROR;
  }

  /* https://github.com/solana-program/zk-elgamal-proof/blob/zk-sdk%40v5.0.1/zk-sdk/src/sigma_proofs/batched_grouped_ciphertext_validity/handles_3.rs#L131-L139 */
  batched_grouped_ciphertext_validity_hash_context( transcript, pubkey1, pubkey2, pubkey3, grouped_ciphertext_lo, grouped_ciphertext_hi );
  fd_zksdk_transcript_domsep_batched_grp_ciph_val_proof( transcript, 3 );

  /* https://github.com/solana-program/zk-elgamal-proof/blob/zk-sdk%40v5.0.1/zk-sdk/src/sigma_proofs/batched_grouped_ciphertext_validity/handles_3.rs#L141 */
  uchar t[ 32 ];
  fd_zksdk_transcript_challenge_scalar( t, transcript, FD_TRANSCRIPT_LITERAL("t") );

  /* https://github.com/solana-program/zk-elgamal-proof/blob/zk-sdk%40v5.0.1/zk-sdk/src/sigma_proofs/batched_grouped_ciphertext_validity/handles_3.rs#L143-L177
     Note: in our impl, t is embedded in the final MSM. */
  return fd_zksdk_verify_proof_direct_grouped_ciphertext_3_handles_validity(
    proof,
    pubkey1,
    pubkey2,
    pubkey3,
    grouped_ciphertext_lo->commitment,
    grouped_ciphertext_lo->handles[0].handle,
    grouped_ciphertext_lo->handles[1].handle,
    grouped_ciphertext_lo->handles[2].handle,
    grouped_ciphertext_hi->commitment,
    grouped_ciphertext_hi->handles[0].handle,
    grouped_ciphertext_hi->handles[1].handle,
    grouped_ciphertext_hi->handles[2].handle,
    t,
    1,
    transcript
  );
}

/* https://github.com/solana-program/zk-elgamal-proof/blob/zk-sdk%40v5.0.1/zk-sdk/src/zk_elgamal_proof_program/proof_data/batched_grouped_ciphertext_validity/handles_3.rs#L138 */
int
fd_zksdk_instr_verify_proof_batched_grouped_ciphertext_3_handles_validity( void const * _context, void const * _proof ) {
  fd_zksdk_transcript_t transcript[1];
  fd_zksdk_transcript_init( transcript, FD_TRANSCRIPT_LITERAL("batched-grouped-ciphertext-validity-3-handles-instruction") );

  fd_zksdk_batched_grp_ciph_3h_val_context_t const * context = _context;
  fd_zksdk_batched_grp_ciph_3h_val_proof_t const *   proof   = _proof;
  return fd_zksdk_verify_proof_batched_grouped_ciphertext_3_handles_validity(
    proof,
    context->pubkey1,
    context->pubkey2,
    context->pubkey3,
    context->grouped_ciphertext_lo,
    context->grouped_ciphertext_hi,
    transcript
  );
}
