#ifndef HEADER_fd_src_discof_failover_fd_failover_stream_h
#define HEADER_fd_src_discof_failover_fd_failover_stream_h

#include "fd_failover_proto.h"

struct fd_failover_consensus_cache {
  fd_failover_consensus_state_t msg;
  ulong                         peer_boot_id;
  int                           valid;
  uchar                         state[ FD_FAILOVER_STATE_MAX ];
};

typedef struct fd_failover_consensus_cache fd_failover_consensus_cache_t;

FD_PROTOTYPES_BEGIN

/* Validates one STATUS payload against the paired peer.
   `out` is left unchanged on failure. */
int
fd_failover_status_decode( fd_failover_status_t *      out,
                           fd_failover_hello_t const * peer,
                           ulong                       tx_seq,
                           uchar const *               payload,
                           ulong                       payload_sz );

/* Checks that a consensus state payload of the given mode decodes and
   ends at vote_slot.  Returns 1 when it does. */
int
fd_failover_state_tip_check( ulong         mode,
                             uchar const * state,
                             ulong         state_sz,
                             ulong         vote_slot );

/* Validates and retains the latest tower state from the active peer.
   `cache` must initially be zeroed and is left unchanged on failure. */
int
fd_failover_consensus_decode( fd_failover_consensus_cache_t * cache,
                              ulong                           self_role,
                              ulong                           mode,
                              fd_failover_hello_t const *     peer,
                              uchar const *                   payload,
                              ulong                           payload_sz );

/* Returns the number of slots between the current active peer's reported vote and retained tower. */
ulong
fd_failover_replication_lag( int                                  peer_status_valid,
                             fd_failover_status_t const *         peer_status,
                             ulong                                peer_boot_id,
                             fd_failover_consensus_cache_t const * cache );

/* Checks that a final tower is not older than the latest streamed one.
   link_seq is compared only when both came from the same peer boot. */

int
fd_failover_consensus_final_check( fd_failover_consensus_cache_t const * cache,
                                   ulong                                 peer_boot_id,
                                   ulong                                 term,
                                   ulong                                 link_seq,
                                   ulong                                 vote_slot,
                                   uchar const *                         state,
                                   ulong                                 state_sz );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_discof_failover_fd_failover_stream_h */
