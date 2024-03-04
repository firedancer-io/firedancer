#ifndef HEADER_fd_src_flamenco_runtime_program_bulletproofs_fd_transcript_h
#define HEADER_fd_src_flamenco_runtime_program_bulletproofs_fd_transcript_h

/* https://github.com/dalek-cryptography/bulletproofs/blob/2.0.0/src/transcript.rs
   compatible with https://github.com/solana-labs/solana/blob/v1.17.13/zk-token-sdk/src/transcript.rs#L83 */

#include "../../../../fd_flamenco_base.h"
#include "../merlin/fd_merlin.h"
#include "../../../../../ballet/ed25519/fd_ristretto255.h"

#define FD_TRANSCRIPT_SUCCESS 0
#define FD_TRANSCRIPT_ERROR  -1

#define FD_TRANSCRIPT_LITERAL FD_MERLIN_LITERAL

FD_PROTOTYPES_BEGIN

/* Domain separators:
   - innerproduct proof
 */

static inline void
fd_bulletproofs_transcript_domsep_innerproduct( fd_merlin_transcript_t * transcript,
                                                ulong const             n ) {
  fd_merlin_transcript_append_message( transcript, FD_MERLIN_LITERAL("dom-sep"), (uchar *)FD_MERLIN_LITERAL("ipp v1") );
  fd_merlin_transcript_append_u64( transcript, FD_MERLIN_LITERAL("n"), n );
}

/* Append message:
   - point
   - validate_and_append_point
   - scalar
 */

static inline void
fd_bulletproofs_transcript_append_point( fd_merlin_transcript_t * transcript,
                                         char const * const       label,
                                         uint const               label_len,
                                         uchar const              point[ static 32 ] ) {
  fd_merlin_transcript_append_message( transcript, label, label_len, point, 32 );
}

static inline int
fd_bulletproofs_transcript_validate_and_append_point( fd_merlin_transcript_t * transcript,
                                                      char const * const       label,
                                                      uint const               label_len,
                                                      uchar const              point[ static 32 ] ) {
  if ( FD_UNLIKELY( fd_memeq( point, fd_ristretto255_compressed_zero, 32 ) ) ) {
    return FD_TRANSCRIPT_ERROR;
  }
  fd_bulletproofs_transcript_append_point( transcript, label, label_len, point );
  return FD_TRANSCRIPT_SUCCESS;
}

static inline void
fd_bulletproofs_transcript_append_scalar( fd_merlin_transcript_t * transcript,
                                          char const * const       label,
                                          uint const               label_len,
                                          uchar const              scalar[ static 32 ] ) {
  fd_merlin_transcript_append_message( transcript, label, label_len, scalar, 32 );
}

/* Challenge:
   - scalar
*/

static inline uchar *
fd_bulletproofs_transcript_challenge_scalar( uchar                    scalar[ static 32 ],
                                             fd_merlin_transcript_t * transcript,
                                             char const * const       label,
                                             uint const               label_len ) {
  uchar unreduced[ 64 ];
  fd_merlin_transcript_challenge_bytes( transcript, label, label_len, unreduced, 64 );
  return fd_curve25519_scalar_reduce(scalar, unreduced);
}

FD_PROTOTYPES_END
#endif /* HEADER_fd_src_flamenco_runtime_program_bulletproofs_fd_transcript_h */
