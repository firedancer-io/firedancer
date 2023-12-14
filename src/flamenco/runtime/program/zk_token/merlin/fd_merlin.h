#ifndef HEADER_fd_src_flamenco_runtime_program_zk_token_fd_merlin_h
#define HEADER_fd_src_flamenco_runtime_program_zk_token_fd_merlin_h

#include "../../../../fd_flamenco_base.h"

struct fd_merlin_strobe128 {
  union {
    ulong state[25];
    uchar state_bytes[200];
  };
  uchar pos;
  uchar pos_begin;
  uchar cur_flags;
};
typedef struct fd_merlin_strobe128 fd_merlin_strobe128_t;

struct fd_merlin_transcript {
  fd_merlin_strobe128_t sctx;
};
typedef struct fd_merlin_transcript fd_merlin_transcript_t;

FD_PROTOTYPES_BEGIN

/* same as strlen, but works with literals, ie hardcoded constant strings */
inline ulong fd_litlen(const char * const literal) {
  return sizeof(literal) - 1;
}

void
fd_merlin_transcript_init( fd_merlin_transcript_t * mctx,
                           char const * const       label );

void
fd_merlin_transcript_commit_bytes( fd_merlin_transcript_t * mctx,
                                   char const * const       label,
                                   uchar const *            data,
                                   ulong                    data_len );

void
fd_merlin_transcript_challenge_bytes( fd_merlin_transcript_t * mctx,
                                      char const * const       label,
                                      uchar *                  buffer,
                                      ulong                    buffer_len );

FD_PROTOTYPES_END
#endif /* HEADER_fd_src_flamenco_runtime_program_zk_token_fd_merlin_h */
