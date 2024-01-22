#ifndef HEADER_fd_src_flamenco_runtime_program_zk_token_fd_transcript_h
#define HEADER_fd_src_flamenco_runtime_program_zk_token_fd_transcript_h

// https://github.com/solana-labs/solana/blob/v1.17.13/zk-token-sdk/src/transcript.rs#L83

#include "../../../../fd_flamenco_base.h"
#include "../merlin/fd_merlin.h"
#include "../../../../../ballet/ed25519/fd_ristretto255_ge.h"

#define FD_TRANSCRIPT_SUCCESS 0
#define FD_TRANSCRIPT_ERROR   1

#define fd_zktpp_transcript_t fd_merlin_transcript_t
#define FD_TRANSCRIPT_LITERAL FD_MERLIN_LITERAL

FD_PROTOTYPES_BEGIN

#define fd_zktpp_transcript_init fd_merlin_transcript_init
#define fd_zktpp_transcript_append_message fd_merlin_transcript_append_message

/* Challenge:
   - scalar
*/

static inline uchar *
fd_zktpp_transcript_challenge_scalar( uchar                   scalar[ static 32 ],
                                      fd_zktpp_transcript_t * transcript,
                                      char const * const      label,
                                      uint const              label_len ) {
  uchar unreduced[ 64 ];
  fd_merlin_transcript_challenge_bytes( transcript, label, label_len, unreduced, 64 );
  return fd_ed25519_sc_reduce(scalar, unreduced);
}

/* Append message:
   - point
   - validate_and_append_point
   - pubkey
   - ciphertext (twisted elgamal 64 bytes: handle + commitment)
   - commitment
   - handle
   - scalar
 */

static inline void
fd_zktpp_transcript_append_point( fd_zktpp_transcript_t * transcript,
                                  char const * const      label,
                                  uint const              label_len,
                                  uchar const             point[ static 32 ] ) {
  fd_merlin_transcript_append_message( transcript, label, label_len, point, 32 );
}

static inline int FD_FN_UNUSED
fd_zktpp_transcript_validate_and_append_point( fd_zktpp_transcript_t * transcript,
                                               char const * const      label,
                                               uint const              label_len,
                                               uchar const             point[ static 32 ] ) {
  if ( FD_UNLIKELY( fd_memeq( point, fd_ristretto255_compressed_zero, 32 ) ) ) {
    return FD_TRANSCRIPT_ERROR;
  }
  fd_zktpp_transcript_append_point( transcript, label, label_len, point );
  return FD_TRANSCRIPT_SUCCESS;
}

static inline void
fd_zktpp_transcript_append_pubkey( fd_zktpp_transcript_t * transcript,
                                   char const * const      label,
                                   uint const              label_len,
                                   uchar const             pubkey[ static 32 ] ) {
  fd_merlin_transcript_append_message( transcript, label, label_len, pubkey, 32 );
}

static inline void
fd_zktpp_transcript_append_ciphertext( fd_zktpp_transcript_t * transcript,
                                       char const * const      label,
                                       uint const              label_len,
                                       uchar const             ciphertext[ static 64 ] ) {
  fd_merlin_transcript_append_message( transcript, label, label_len, ciphertext, 64 );
}

static inline void
fd_zktpp_transcript_append_commitment( fd_zktpp_transcript_t * transcript,
                                       char const * const      label,
                                       uint const              label_len,
                                       uchar const             commitment[ static 32 ] ) {
  fd_merlin_transcript_append_message( transcript, label, label_len, commitment, 32 );
}

static inline void
fd_zktpp_transcript_append_handle( fd_zktpp_transcript_t * transcript,
                                   char const * const      label,
                                   uint const              label_len,
                                   uchar const             handle[ static 32 ] ) {
  fd_merlin_transcript_append_message( transcript, label, label_len, handle, 32 );
}

static inline void
fd_zktpp_transcript_append_scalar( fd_zktpp_transcript_t * transcript,
                                   char const * const      label,
                                   uint const              label_len,
                                   uchar const             scalar[ static 32 ] ) {
  fd_merlin_transcript_append_message( transcript, label, label_len, scalar, 32 );
}

/* Domain separator:
   - innerproduct
   - equality_proof
   - zero_balance_proof
   - grouped_ciphertext_validity_proof
   - batched_grouped_ciphertext_validity_proof
   - pubkey_proof
 */

static inline void
fd_zktpp_transcript_domsep_innerproduct( fd_zktpp_transcript_t * transcript,
                                         ulong const             n ) {
  fd_merlin_transcript_append_message( transcript, FD_TRANSCRIPT_LITERAL("dom-sep"), (uchar *)FD_TRANSCRIPT_LITERAL("ipp v1") );
  fd_merlin_transcript_append_u64( transcript, FD_TRANSCRIPT_LITERAL("n"), n );
}

static inline void
fd_zktpp_transcript_domsep_equality_proof( fd_zktpp_transcript_t * transcript ) {
  fd_merlin_transcript_append_message( transcript, FD_TRANSCRIPT_LITERAL("dom-sep"), (uchar *)FD_TRANSCRIPT_LITERAL("equality-proof") );
}

static inline void
fd_zktpp_transcript_domsep_zero_balance_proof( fd_zktpp_transcript_t * transcript ) {
  fd_merlin_transcript_append_message( transcript, FD_TRANSCRIPT_LITERAL("dom-sep"), (uchar *)FD_TRANSCRIPT_LITERAL("zero-balance-proof") );
}

static inline void
fd_zktpp_transcript_domsep_grp_ciph_val_proof( fd_zktpp_transcript_t * transcript ) {
  fd_merlin_transcript_append_message( transcript, FD_TRANSCRIPT_LITERAL("dom-sep"), (uchar *)FD_TRANSCRIPT_LITERAL("validity-proof") );
}

static inline void
fd_zktpp_transcript_domsep_batched_grp_ciph_val_proof( fd_zktpp_transcript_t * transcript ) {
  fd_merlin_transcript_append_message( transcript, FD_TRANSCRIPT_LITERAL("dom-sep"), (uchar *)FD_TRANSCRIPT_LITERAL("batched-validity-proof") );
}

static inline void
fd_zktpp_transcript_domsep_pubkey_proof( fd_zktpp_transcript_t * transcript ) {
  fd_merlin_transcript_append_message( transcript, FD_TRANSCRIPT_LITERAL("dom-sep"), (uchar *)FD_TRANSCRIPT_LITERAL("pubkey-proof") );
}

FD_PROTOTYPES_END
#endif /* HEADER_fd_src_flamenco_runtime_program_zk_token_fd_transcript_h */
