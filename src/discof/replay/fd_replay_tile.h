#ifndef HEADER_fd_src_discof_replay_fd_replay_tile_h
#define HEADER_fd_src_discof_replay_fd_replay_tile_h

#include "../poh/fd_poh_tile.h"
#include "../../disco/tiles.h"
#include "../../flamenco/types/fd_types_custom.h"

#define REPLAY_SIG_SLOT_COMPLETED (0)
#define REPLAY_SIG_ROOT_ADVANCED  (1)
#define REPLAY_SIG_RESET          (3)
#define REPLAY_SIG_BECAME_LEADER  (4)

struct fd_replay_slot_completed {
  ulong slot;
  ulong root_slot;
  ulong storage_slot;
  ulong epoch;
  ulong slot_in_epoch;
  ulong block_height;
  ulong parent_slot;

  fd_hash_t block_id;        /* block id (last FEC set's merkle root) of the slot received from replay */
  fd_hash_t parent_block_id; /* parent block id of the slot received from replay */
  fd_hash_t bank_hash;       /* bank hash of the slot received from replay */
  fd_hash_t block_hash;      /* last microblock header hash of slot received from replay */

  ulong transaction_count;

  struct {
    double initial;
    double terminal;
    double taper;
    double foundation;
    double foundation_term;
  } inflation;

  struct {
    ulong lamports_per_uint8_year;
    double exemption_threshold;
    uchar burn_percent;
  } rent;

  /* Reference to the bank for this completed slot.  TODO: We can
     eliminate non-timestamp fields and have consumers just use
     bank_idx. */
  ulong bank_idx;
  ulong parent_bank_idx; /* ULONG_MAX if unavailable */

  long first_fec_set_received_nanos;      /* timestamp when replay received the first fec of the slot from turbine or repair */
  long preparation_begin_nanos;           /* timestamp when replay began preparing the state to begin execution of the slot */
  long first_transaction_scheduled_nanos; /* timestamp when replay first sent a transaction to be executed */
  long last_transaction_finished_nanos;   /* timestamp when replay received the last execution completion */
  long completion_time_nanos;             /* timestamp when replay completed finalizing the slot and notified tower */

  int is_leader; /* whether we were leader for this slot */
  ulong identity_balance;

  struct {
    ulong block_cost;
    ulong vote_cost;
    ulong allocated_accounts_data_size;
    ulong block_cost_limit;
    ulong vote_cost_limit;
    ulong account_cost_limit;
  } cost_tracker;
};

typedef struct fd_replay_slot_completed fd_replay_slot_completed_t;

struct fd_replay_root_advanced {
  ulong bank_idx;
};

typedef struct fd_replay_root_advanced fd_replay_root_advanced_t;

union fd_replay_message {
  fd_replay_slot_completed_t  slot_completed;
  fd_replay_root_advanced_t   root_advanced;
  fd_poh_reset_t              reset;
  fd_became_leader_t          became_leader;
};

typedef union fd_replay_message fd_replay_message_t;

#endif /* HEADER_fd_src_discof_replay_fd_replay_tile_h */
