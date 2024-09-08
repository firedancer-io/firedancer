#ifndef HEADER_fd_src_flamenco_runtime_program_zksdk_fd_transcript_h
#define HEADER_fd_src_flamenco_runtime_program_zksdk_fd_transcript_h

/* https://github.com/anza-xyz/agave/blob/v2.0.1/zk-sdk/src/transcript.rs */

#include "../../../../fd_flamenco_base.h"
#include "../merlin/fd_merlin.h"
#include "../rangeproofs/fd_rangeproofs.h"
#include "../../../../../ballet/ed25519/fd_ristretto255.h"

#define fd_zksdk_transcript_t fd_merlin_transcript_t
#define FD_TRANSCRIPT_LITERAL FD_MERLIN_LITERAL

#define fd_zksdk_transcript_init                      fd_merlin_transcript_init
#define fd_zksdk_transcript_append_message            fd_merlin_transcript_append_message
#define fd_zksdk_transcript_append_point              fd_rangeproofs_transcript_append_point
#define fd_zksdk_transcript_validate_and_append_point fd_rangeproofs_transcript_validate_and_append_point
#define fd_zksdk_transcript_append_scalar             fd_rangeproofs_transcript_append_scalar
#define fd_zksdk_transcript_challenge_scalar          fd_rangeproofs_transcript_challenge_scalar

FD_PROTOTYPES_BEGIN

/* Append message:
   - pubkey
   - ciphertext (twisted elgamal 64 bytes: handle + commitment)
   - commitment
   - handle
 */

static inline void
fd_zksdk_transcript_append_pubkey( fd_zksdk_transcript_t * transcript,
                                   char const * const      label,
                                   uint const              label_len,
                                   uchar const             pubkey[ 32 ] ) {
  fd_merlin_transcript_append_message( transcript, label, label_len, pubkey, 32 );
}

static inline void
fd_zksdk_transcript_append_ciphertext( fd_zksdk_transcript_t * transcript,
                                       char const * const      label,
                                       uint const              label_len,
                                       uchar const             ciphertext[ 64 ] ) {
  fd_merlin_transcript_append_message( transcript, label, label_len, ciphertext, 64 );
}

static inline void
fd_zksdk_transcript_append_commitment( fd_zksdk_transcript_t * transcript,
                                       char const * const      label,
                                       uint const              label_len,
                                       uchar const             commitment[ 32 ] ) {
  fd_merlin_transcript_append_message( transcript, label, label_len, commitment, 32 );
}

static inline void
fd_zksdk_transcript_append_handle( fd_zksdk_transcript_t * transcript,
                                   char const * const      label,
                                   uint const              label_len,
                                   uchar const             handle[ 32 ] ) {
  fd_merlin_transcript_append_message( transcript, label, label_len, handle, 32 );
}

/* 
 * Domain separators
 */

static inline void
fd_zksdk_transcript_domsep_ciph_ciph_eq_proof( fd_zksdk_transcript_t * transcript ) {
  fd_merlin_transcript_append_message( transcript, FD_TRANSCRIPT_LITERAL("dom-sep"), (uchar *)FD_TRANSCRIPT_LITERAL("ciphertext-ciphertext-equality-proof") );
}

static inline void
fd_zksdk_transcript_domsep_ciph_comm_eq_proof( fd_zksdk_transcript_t * transcript ) {
  fd_merlin_transcript_append_message( transcript, FD_TRANSCRIPT_LITERAL("dom-sep"), (uchar *)FD_TRANSCRIPT_LITERAL("ciphertext-commitment-equality-proof") );
}

static inline void
fd_zksdk_transcript_domsep_zero_ciphertext_proof( fd_zksdk_transcript_t * transcript ) {
  fd_merlin_transcript_append_message( transcript, FD_TRANSCRIPT_LITERAL("dom-sep"), (uchar *)FD_TRANSCRIPT_LITERAL("zero-ciphertext-proof") );
}

static inline void
fd_zksdk_transcript_domsep_grp_ciph_val_proof( fd_zksdk_transcript_t * transcript, ulong handles ) {
  fd_merlin_transcript_append_message( transcript, FD_TRANSCRIPT_LITERAL("dom-sep"), (uchar *)FD_TRANSCRIPT_LITERAL("validity-proof") );
  fd_merlin_transcript_append_u64    ( transcript, FD_TRANSCRIPT_LITERAL("handles"), handles );
}

static inline void
fd_zksdk_transcript_domsep_batched_grp_ciph_val_proof( fd_zksdk_transcript_t * transcript, ulong handles ) {
  fd_merlin_transcript_append_message( transcript, FD_TRANSCRIPT_LITERAL("dom-sep"), (uchar *)FD_TRANSCRIPT_LITERAL("batched-validity-proof") );
  fd_merlin_transcript_append_u64    ( transcript, FD_TRANSCRIPT_LITERAL("handles"), handles );
}

static inline void
fd_zksdk_transcript_domsep_percentage_with_cap_proof( fd_zksdk_transcript_t * transcript ) {
  fd_merlin_transcript_append_message( transcript, FD_TRANSCRIPT_LITERAL("dom-sep"), (uchar *)FD_TRANSCRIPT_LITERAL("percentage-with-cap-proof") );
}

static inline void
fd_zksdk_transcript_domsep_pubkey_proof( fd_zksdk_transcript_t * transcript ) {
  fd_merlin_transcript_append_message( transcript, FD_TRANSCRIPT_LITERAL("dom-sep"), (uchar *)FD_TRANSCRIPT_LITERAL("pubkey-proof") );
}

FD_PROTOTYPES_END
#endif /* HEADER_fd_src_flamenco_runtime_program_zksdk_fd_transcript_h */
