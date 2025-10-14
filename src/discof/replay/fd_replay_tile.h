#ifndef HEADER_fd_src_discof_replay_fd_replay_tile_h
#define HEADER_fd_src_discof_replay_fd_replay_tile_h

#include "../poh/fd_poh_tile.h"
#include "../../disco/tiles.h"
#include "../../flamenco/runtime/program/fd_vote_program.h"
#include "../../flamenco/types/fd_types_custom.h"

#define REPLAY_SIG_SLOT_COMPLETED (0)
#define REPLAY_SIG_ROOT_ADVANCED  (1)
#define REPLAY_SIG_VOTE_STATE     (2)
#define REPLAY_SIG_RESET          (3)
#define REPLAY_SIG_BECAME_LEADER  (4)

struct fd_replay_slot_completed {
  ulong slot;
  ulong root_slot;
  ulong epoch;
  ulong slot_in_epoch;
  ulong block_height;
  ulong parent_slot;

  fd_hash_t block_id;        /* block id (last FEC set's merkle root) of the slot received from replay */
  fd_hash_t parent_block_id; /* parent block id of the slot received from replay */
  fd_hash_t bank_hash;       /* bank hash of the slot received from replay */
  fd_hash_t block_hash;      /* last microblock header hash of slot received from replay */

  ulong transaction_count;
  ulong nonvote_txn_count;
  ulong failed_txn_count;
  ulong nonvote_failed_txn_count;
  ulong max_compute_units;
  ulong total_compute_units_used;
  ulong execution_fees;
  ulong priority_fees;
  ulong tips;
  ulong shred_count;

  long first_fec_set_received_nanos;      /* timestamp when replay received the first fec of the slot from turbine or repair */
  long preparation_begin_nanos;           /* timestamp when replay began preparing the state to begin execution of the slot */
  long first_transaction_scheduled_nanos; /* timestamp when replay first sent a transaction to be executed */
  long last_transaction_finished_nanos;   /* timestamp when replay received the last execution completion */
  long completion_time_nanos;             /* timestamp when replay completed finalizing the slot and notified tower */
};

typedef struct fd_replay_slot_completed fd_replay_slot_completed_t;

struct fd_replay_root_advanced {
  ulong bank_idx;
};

typedef struct fd_replay_root_advanced fd_replay_root_advanced_t;

/* The replay tile currently, on slot replay completion, sends vote
   states from the completed bank to the Tower tile so it can determine
   how to vote or advance consensus.  There are limits on the amount of
   data that can be sent over.  TODO: merge Tower & Replay tiles to
   remove this. */

#define FD_REPLAY_TOWER_VOTE_ACC_MAX (4096UL)
#define FD_REPLAY_TOWER_ACC_DATA_MAX (4096UL)

/* The replay tile sends the tower tile a copy of all the vote states
   (which contain towers) after each slot to run the TowerBFT rules. */

struct fd_replay_vote_state {
  fd_pubkey_t pubkey;
  ulong       stake;
  uchar       acc[ FD_VOTE_STATE_V3_SZ ];
  ulong       acc_sz;
};
typedef struct fd_replay_vote_state fd_replay_vote_state_t;

union fd_replay_message {
  fd_replay_slot_completed_t slot_completed;
  fd_replay_root_advanced_t  root_advanced;
  fd_poh_reset_t             reset;
  fd_became_leader_t         became_leader;
  fd_replay_vote_state_t     vote_state;
};

typedef union fd_replay_message fd_replay_message_t;

#endif /* HEADER_fd_src_discof_replay_fd_replay_tile_h */
