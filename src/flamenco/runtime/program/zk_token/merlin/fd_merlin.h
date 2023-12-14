#ifndef HEADER_fd_src_flamenco_runtime_program_zk_token_fd_merlin_h
#define HEADER_fd_src_flamenco_runtime_program_zk_token_fd_merlin_h

#include "../../../../fd_flamenco_base.h"

struct merlin_strobe128 {
  union {
    ulong state[25];
    uchar state_bytes[200];
  };
  uchar pos;
  uchar pos_begin;
  uchar cur_flags;
};
typedef struct merlin_strobe128 merlin_strobe128_t;

struct merlin_transcript {
  merlin_strobe128_t sctx;
};
typedef struct merlin_transcript merlin_transcript_t;

FD_PROTOTYPES_BEGIN

void
fd_merlin_transcript_init( merlin_transcript_t * mctx,
                           char const *          label,
                           ulong                 label_len );

void
fd_merlin_transcript_commit_bytes( merlin_transcript_t * mctx,
                                   char const *          label,
                                   ulong                 label_len,
                                   uchar const *         data,
                                   ulong                 data_len );

void
fd_merlin_transcript_challenge_bytes( merlin_transcript_t * mctx,
                                      char const *          label,
                                      ulong                 label_len,
                                      uchar *               buffer,
                                      ulong                 buffer_len );

FD_PROTOTYPES_END
#endif /* HEADER_fd_src_flamenco_runtime_program_zk_token_fd_merlin_h */
