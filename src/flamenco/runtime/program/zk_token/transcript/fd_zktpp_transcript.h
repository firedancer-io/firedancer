#ifndef HEADER_fd_src_flamenco_runtime_program_zk_token_fd_transcript_h
#define HEADER_fd_src_flamenco_runtime_program_zk_token_fd_transcript_h

#include "../../../../fd_flamenco_base.h"
#include "../merlin/fd_merlin.h"

#define fd_zktpp_transcript_t fd_merlin_transcript_t

FD_PROTOTYPES_BEGIN

#define fd_zktpp_transcript_init fd_merlin_transcript_init

inline void
fd_zktpp_transcript_append_pubkey( fd_zktpp_transcript_t * transcript,
                                   char const * const      label,
                                   uchar const             pubkey[ static 32 ] ) {
  fd_merlin_transcript_commit_bytes( transcript, label, pubkey, 32 );
}

inline void
fd_zktpp_transcript_append_ciphertext( fd_zktpp_transcript_t * transcript,
                                       char const * const      label,
                                       uchar const             ciphertext[ static 64 ] ) {
  fd_merlin_transcript_commit_bytes( transcript, label, ciphertext, 64 );
}

inline void
fd_zktpp_transcript_append_commitment( fd_zktpp_transcript_t * transcript,
                                       char const * const      label,
                                       uchar const             commitment[ static 32 ] ) {
  fd_merlin_transcript_commit_bytes( transcript, label, commitment, 32 );
}

inline void
fd_zktpp_transcript_domsep_equality_proof( fd_zktpp_transcript_t * transcript ) {
  fd_merlin_transcript_commit_bytes( transcript, "dom-sep", (uchar *)"equality-proof", fd_litlen("equality-proof") );
}

FD_PROTOTYPES_END
#endif /* HEADER_fd_src_flamenco_runtime_program_zk_token_fd_transcript_h */
