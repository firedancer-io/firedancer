#ifndef HEADER_fd_src_flamenco_runtime_tests_fd_votor_harness_h
#define HEADER_fd_src_flamenco_runtime_tests_fd_votor_harness_h

#include "fd_solfuzz.h"

FD_PROTOTYPES_BEGIN

/* fd_solfuzz_votor_vote_deserialize decodes a protobuf
   VotorVoteDeserializeContext, deserializes its raw Alpenglow vote wire
   bytes, and returns protobuf-encoded VotorVoteDeserializeEffects for
   differential comparison.  A vote is valid if it passes the same
   checks Agave's wire decoder applies, plus the signature point checks
   FD's decoder applies. */

int
fd_solfuzz_votor_vote_deserialize( fd_solfuzz_runner_t * runner,
                                   uchar *               out,
                                   ulong *               out_sz,
                                   uchar const *         in,
                                   ulong                 in_sz );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_runtime_tests_fd_votor_harness_h */
