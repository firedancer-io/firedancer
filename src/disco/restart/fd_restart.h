#ifndef HEADER_fd_src_choreo_restart_fd_restart_h
#define HEADER_fd_src_choreo_restart_fd_restart_h

#include "../../choreo/tower/fd_tower.h"
#include "../../flamenco/types/fd_types.h"

#define bits_per_uchar 8
#define bits_per_ulong ( 8 * sizeof(ulong) )

#define HEAVIEST_FORK_THRESHOLD_DELTA_PERCENT     38UL
#define REPAIR_THRESHOLD_PERCENT                  42UL
#define WAIT_FOR_SUPERMAJORITY_THRESHOLD_PERCENT  80UL
#define MAX_RESTART_PEERS                         40200UL
#define LAST_VOTED_FORK_MAX_SLOTS                 0xFFFFUL
#define LAST_VOTED_FORK_MAX_BITMAP_BYTES          ( LAST_VOTED_FORK_MAX_SLOTS/bits_per_uchar+1 )
#define LAST_VOTED_FORK_MAX_MSG_BYTES             ( sizeof(fd_gossip_restart_last_voted_fork_slots_t)+LAST_VOTED_FORK_MAX_BITMAP_BYTES )

typedef enum {
    WR_STATE_FIND_HEAVIEST_FORK     = 0,
    WR_STATE_AGREE_ON_HEAVIEST_FORK = 1,
    WR_STATE_DONE                   = 2
} fd_wen_restart_stage_t;

struct fd_restart_state {
  fd_wen_restart_stage_t stage;

  /* Init */
  ulong                  root;
  ulong                  total_stake;
  ulong                  total_active_stake;
  ulong                  num_vote_accts;
  fd_stake_weight_t      stake_weights[ MAX_RESTART_PEERS ];

  /* WR_STATE_FIND_HEAVIEST_FORK */
  ulong                  heaviest_fork_slot;
  ulong                  slot_to_stake[ LAST_VOTED_FORK_MAX_SLOTS ];
  uchar                  last_voted_fork_slots_received[ MAX_RESTART_PEERS ];
};
typedef struct fd_restart_state fd_restart_state_t;

FD_FN_CONST static inline ulong
fd_restart_state_align( void ) {
  return alignof(fd_restart_state_t);
}

FD_FN_CONST static inline ulong
fd_restart_state_footprint( void ) {
  return sizeof(fd_restart_state_t);
}

void
fd_restart_init( fd_restart_state_t * restart_state,
                 fd_vote_accounts_t const * accs,
                 fd_tower_t const * tower,
                 fd_slot_history_t const * slot_history,
                 fd_blockstore_t * blockstore,
                 uchar * buf_out,
                 ulong * buf_len_out );

void
fd_restart_recv_last_voted_fork_slots( fd_restart_state_t * restart_state,
                                       fd_gossip_restart_last_voted_fork_slots_t * last_voted_msg );

#endif
