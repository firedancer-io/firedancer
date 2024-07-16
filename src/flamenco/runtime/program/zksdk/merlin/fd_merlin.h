#ifndef HEADER_fd_src_flamenco_runtime_program_zksdk_fd_merlin_h
#define HEADER_fd_src_flamenco_runtime_program_zksdk_fd_merlin_h

#include "../../../../fd_flamenco_base.h"

#define FD_MERLIN_LITERAL(STR) ("" STR), (sizeof(STR)-1)

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

void
fd_merlin_transcript_init( fd_merlin_transcript_t * mctx,
                           char const * const       label,
                           uint const               label_len );

void
fd_merlin_transcript_append_message( fd_merlin_transcript_t * mctx,
                                     char const * const       label,
                                     uint const               label_len,
                                     uchar const *            message,
                                     uint const               message_len );

void
fd_merlin_transcript_append_u64( fd_merlin_transcript_t * mctx,
                                 char const * const       label,
                                 uint const               label_len,
                                 ulong const              message_u64 );

void
fd_merlin_transcript_challenge_bytes( fd_merlin_transcript_t * mctx,
                                      char const * const       label,
                                      uint const               label_len,
                                      uchar *                  buffer,
                                      uint const               buffer_len );

FD_PROTOTYPES_END
#endif /* HEADER_fd_src_flamenco_runtime_program_zksdk_fd_merlin_h */
