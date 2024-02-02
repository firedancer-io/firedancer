#ifndef HEADER_fd_src_flamenco_runtime_program_zk_token_fd_transcript_h
#define HEADER_fd_src_flamenco_runtime_program_zk_token_fd_transcript_h

// https://github.com/solana-labs/solana/blob/v1.17.13/zk-token-sdk/src/transcript.rs#L83

#include "../../../../fd_flamenco_base.h"
#include "../merlin/fd_merlin.h"
#include "../bulletproofs/fd_bulletproofs.h"
#include "../../../../../ballet/ed25519/fd_ristretto255_ge.h"

#define fd_zktpp_transcript_t fd_merlin_transcript_t
#define FD_TRANSCRIPT_LITERAL FD_MERLIN_LITERAL

#define fd_zktpp_transcript_init                      fd_merlin_transcript_init
#define fd_zktpp_transcript_append_message            fd_merlin_transcript_append_message
#define fd_zktpp_transcript_append_point              fd_bulletproofs_transcript_append_point
#define fd_zktpp_transcript_validate_and_append_point fd_bulletproofs_transcript_validate_and_append_point
#define fd_zktpp_transcript_append_scalar             fd_bulletproofs_transcript_append_scalar
#define fd_zktpp_transcript_challenge_scalar          fd_bulletproofs_transcript_challenge_scalar

FD_PROTOTYPES_BEGIN

/* Append message:
   - pubkey
   - ciphertext (twisted elgamal 64 bytes: handle + commitment)
   - commitment
   - handle
 */

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

/* Domain separator:
   - equality_proof
   - zero_balance_proof
   - grouped_ciphertext_validity_proof
   - batched_grouped_ciphertext_validity_proof
   - pubkey_proof
 */

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
