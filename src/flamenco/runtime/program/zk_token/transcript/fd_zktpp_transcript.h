#ifndef HEADER_fd_src_flamenco_runtime_program_zk_token_fd_transcript_h
#define HEADER_fd_src_flamenco_runtime_program_zk_token_fd_transcript_h

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

inline uchar *
fd_zktpp_transcript_challenge_scalar( uchar                   scalar[ static 32 ],
                                      fd_zktpp_transcript_t * transcript,
                                      char const * const      label,
                                      ulong                   label_len ) {
  uchar unreduced[ 64 ];
  fd_merlin_transcript_challenge_bytes( transcript, label, label_len, unreduced, 64 );
  return fd_ed25519_sc_reduce(scalar, unreduced);
}

inline void
fd_zktpp_transcript_append_point( fd_zktpp_transcript_t * transcript,
                                  char const * const      label,
                                  ulong                   label_len,
                                  uchar const             point[ static 32 ] ) {
  fd_merlin_transcript_append_message( transcript, label, label_len, point, 32 );
}

inline static int
fd_zktpp_transcript_validate_and_append_point( fd_zktpp_transcript_t * transcript,
                                               char const * const      label,
                                               ulong                   label_len,
                                               uchar const             point[ static 32 ] ) {
  if ( FD_UNLIKELY( fd_memeq( point, fd_ristretto255_compressed_zero, 32 ) ) ) {
    return FD_TRANSCRIPT_ERROR;
  }
  fd_zktpp_transcript_append_point( transcript, label, label_len, point );
  return FD_TRANSCRIPT_SUCCESS;
}

inline void
fd_zktpp_transcript_append_pubkey( fd_zktpp_transcript_t * transcript,
                                   char const * const      label,
                                   ulong                   label_len,
                                   uchar const             pubkey[ static 32 ] ) {
  fd_merlin_transcript_append_message( transcript, label, label_len, pubkey, 32 );
}

inline void
fd_zktpp_transcript_append_ciphertext( fd_zktpp_transcript_t * transcript,
                                       char const * const      label,
                                       ulong                   label_len,
                                       uchar const             ciphertext[ static 64 ] ) {
  fd_merlin_transcript_append_message( transcript, label, label_len, ciphertext, 64 );
}

inline void
fd_zktpp_transcript_append_commitment( fd_zktpp_transcript_t * transcript,
                                       char const * const      label,
                                       ulong                   label_len,
                                       uchar const             commitment[ static 32 ] ) {
  fd_merlin_transcript_append_message( transcript, label, label_len, commitment, 32 );
}

inline void
fd_zktpp_transcript_domsep_equality_proof( fd_zktpp_transcript_t * transcript ) {
  fd_merlin_transcript_append_message( transcript, FD_TRANSCRIPT_LITERAL("dom-sep"), (uchar *)FD_TRANSCRIPT_LITERAL("equality-proof") );
}

FD_PROTOTYPES_END
#endif /* HEADER_fd_src_flamenco_runtime_program_zk_token_fd_transcript_h */
