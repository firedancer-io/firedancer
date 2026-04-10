#ifndef HEADER_fd_src_flamenco_runtime_tests_fd_gossip_harness_h
#define HEADER_fd_src_flamenco_runtime_tests_fd_gossip_harness_h

#include "fd_solfuzz.h"

FD_PROTOTYPES_BEGIN

/* fd_solfuzz_gossip_message_deserialize deserializes a raw gossip wire
   message and returns a single byte: 1 if deserialization succeeded,
   0 otherwise.  Does not require a runner. */

int
fd_solfuzz_gossip_message_deserialize( uchar *       out,
                                       ulong *       out_sz,
                                       uchar const * in,
                                       ulong         in_sz );

/* fd_solfuzz_gossip_decode deserializes a raw gossip wire message and
   returns protobuf-encoded GossipEffects with the full decoded message
   structure for differential comparison.  All intermediate allocations
   use runner->spad. */

int
fd_solfuzz_gossip_decode( fd_solfuzz_runner_t * runner,
                          uchar *               out,
                          ulong *               out_sz,
                          uchar const *         in,
                          ulong                 in_sz );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_runtime_tests_fd_gossip_harness_h */
