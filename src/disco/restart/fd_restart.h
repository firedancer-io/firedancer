#ifndef HEADER_fd_src_choreo_restart_fd_restart_h
#define HEADER_fd_src_choreo_restart_fd_restart_h

/* fd_restart implements Solana's SIMD-0046, Optimistic cluster restart
   automation, also known as wen-restart.
   Protocol details:
     TODO, the protocol may still change and the agave code has not been
     finalized yet.
 */

#include "../../choreo/tower/fd_tower.h"
#include "../../flamenco/types/fd_types.h"

#define bits_per_uchar 8
#define bits_per_ulong ( 8 * sizeof(ulong) )

/* Protocol parameters of wen-restart */
#define HEAVIEST_FORK_THRESHOLD_DELTA_PERCENT     38UL
#define REPAIR_THRESHOLD_PERCENT                  42UL
#define WAIT_FOR_SUPERMAJORITY_THRESHOLD_PERCENT  80UL
#define LAST_VOTED_FORK_MAX_SLOTS                 0xFFFFUL

/* Implementation-specific parameters */
#define MAX_RESTART_PEERS                         40200UL
#define LAST_VOTED_FORK_PUBLISH_PERIOD_NS         10e9L
#define LAST_VOTED_FORK_MAX_BITMAP_BYTES          ( LAST_VOTED_FORK_MAX_SLOTS/bits_per_uchar+1 )
#define LAST_VOTED_FORK_MAX_MSG_BYTES             ( sizeof(fd_gossip_restart_last_voted_fork_slots_t)+LAST_VOTED_FORK_MAX_BITMAP_BYTES )

/* Wen-restart has 2 stages:
   one for finding the heaviest fork,
   another for disseminating the heaviest fork information */
typedef enum {
    WR_STATE_FIND_HEAVIEST_FORK     = 0,
    WR_STATE_AGREE_ON_HEAVIEST_FORK = 1,
    WR_STATE_DONE                   = 2
} fd_wen_restart_stage_t;

/* fd_restart_state_t contains all the states maintained by wen-restart.
   It is allocated within the `unprivileged_init` of the replay tile. */
struct fd_restart_state {
  fd_wen_restart_stage_t stage;

  /* States existed before wen-restart */
  ulong                  root;
  ulong                  total_stake;
  ulong                  num_vote_accts;
  fd_stake_weight_t      stake_weights[ MAX_RESTART_PEERS ];

  /* States maintained by the FIND_HEAVIEST_FORK stage of wen-restart */
  ulong                  total_active_stake;
  ulong                  slot_to_stake[ LAST_VOTED_FORK_MAX_SLOTS ];
  uchar                  last_voted_fork_slots_received[ MAX_RESTART_PEERS ];

  /* States maintained by the AGREE_ON_HEAVIEST_FORK stage of wen-restart */
  ulong                  heaviest_fork_slot;
  fd_hash_t              heaviest_fork_bank_hash;
};
typedef struct fd_restart_state fd_restart_state_t;

/* fd_restart_state_{align,footprint} return the required alignment and
   footprint of a memory region suitable for use as the wen-restart state. */
FD_FN_CONST static inline ulong
fd_restart_state_align( void ) {
  return alignof(fd_restart_state_t);
}

FD_FN_CONST static inline ulong
fd_restart_state_footprint( void ) {
  return sizeof(fd_restart_state_t);
}

/* fd_restart_init is called in the replay tile after a snapshot is loaded.
   The arguments of this function come from the loaded snapshot and provide
   the first few fields in fd_restart_state_t. This function fills buf_out
   and buf_len_out with a gossip message -- the first gossip message sent
   in the wen-restart protocol (fd_gossip_restart_last_voted_fork_slots_t). */
void
fd_restart_init( fd_restart_state_t * restart_state,
                 fd_vote_accounts_t const * accs,
                 fd_tower_t const * tower,
                 fd_slot_history_t const * slot_history,
                 fd_blockstore_t * blockstore,
                 uchar * buf_out,
                 ulong * buf_len_out );

/* fd_restart_recv_last_voted_fork_slots is called after receiving each
   gossip message of type fd_gossip_restart_last_voted_fork_slots_t from
   other validators. After receiving such messages from more than 80%
   (WAIT_FOR_SUPERMAJORITY_THRESHOLD_PERCENT) stake, this function will
   move wen-restart to the next stage, i.e., AGREE_ON_HEAVIEST_FORK. */
void
fd_restart_recv_last_voted_fork_slots( fd_restart_state_t * restart_state,
                                       fd_gossip_restart_last_voted_fork_slots_t * last_voted_msg,
                                       ulong * out_restart_slot );

#endif
