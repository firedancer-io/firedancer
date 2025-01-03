#ifndef HEADER_fd_src_choreo_restart_fd_restart_h
#define HEADER_fd_src_choreo_restart_fd_restart_h

/* fd_restart implements Solana's SIMD-0046, Optimistic cluster restart
   automation, which is also known as wen-restart. See protocol details at
   https://github.com/solana-foundation/solana-improvement-documents/pull/46
 */

#include "../../choreo/tower/fd_tower.h"
#include "../../flamenco/types/fd_types.h"

#define FD_RESTART_MAGIC_TAG                                128UL

/* Protocol parameters of wen-restart */
#define FD_RESTART_EPOCHS_MAX                               2UL
#define FD_RESTART_HEAVIEST_FORK_THRESHOLD_DELTA_PERCENT    38UL
#define FD_RESTART_WAIT_FOR_NEXT_EPOCH_THRESHOLD_PERCENT    33UL
#define FD_RESTART_WAIT_FOR_SUPERMAJORITY_THRESHOLD_PERCENT 80UL
#define FD_RESTART_LAST_VOTED_FORK_MAX_SLOTS                0xFFFFUL

/* Implementation-specific parameters */
#define FD_RESTART_MAX_PEERS               40200UL
#define FD_RESTART_MSG_PUBLISH_PERIOD_NS   10e9L
#define FD_RESTART_RAW_BITMAP_BYTES_MAX    8192UL /* 0xFFFF/8+1 */
#define FD_RESTART_PACKET_BITMAP_BYTES_MAX 824UL  /* PACKET_DATA_SIZE is 1232, and the rest of LAST_VOTED_FORK_SLOT needs 1232-824 bytes */
#define FD_RESTART_LINK_BYTES_MAX          ( sizeof(fd_gossip_restart_last_voted_fork_slots_t)+FD_RESTART_RAW_BITMAP_BYTES_MAX )

typedef enum {
    FD_RESTART_STAGE_WAIT_FOR_INIT                = 0,
    FD_RESTART_STAGE_FIND_HEAVIEST_FORK_SLOT_NUM  = 1,
    FD_RESTART_STAGE_FIND_HEAVIEST_FORK_BANK_HASH = 2,
    FD_RESTART_STAGE_GENERATE_SNAPSHOT            = 3,
    FD_RESTART_STAGE_DONE                         = 4
} fd_wen_restart_stage_t;

/* fd_restart_t contains all the states maintained by wen-restart.
   It is allocated within the `unprivileged_init` of the replay tile. */
struct fd_restart {
  fd_wen_restart_stage_t stage;

  /* States initialized at the beginning */
  ulong                  funk_root;
  ulong                  root_epoch;
  fd_hash_t              root_bank_hash;
  fd_epoch_schedule_t *  epoch_schedule;
  ulong                  total_stake[ FD_RESTART_EPOCHS_MAX ];
  ulong                  num_vote_accts[ FD_RESTART_EPOCHS_MAX ];
  fd_stake_weight_t      stake_weights[ FD_RESTART_EPOCHS_MAX ][ FD_RESTART_MAX_PEERS ];

  /* States maintained by the FIND_HEAVIEST_FORK_SLOT_NUM stage */
  ulong                  total_stake_received[ FD_RESTART_EPOCHS_MAX ];
  ulong                  total_stake_received_and_voted[ FD_RESTART_EPOCHS_MAX ];
  uchar                  last_voted_fork_slots_received[ FD_RESTART_EPOCHS_MAX ][ FD_RESTART_MAX_PEERS ];
  ulong                  slot_to_stake[ FD_RESTART_LAST_VOTED_FORK_MAX_SLOTS ]; /* the index is an offset from funk_root */

  /* States maintained by the FIND_HEAVIEST_FORK_BANK_HASH stage */
  fd_pubkey_t            my_pubkey;
  ulong                  heaviest_fork_slot;
  fd_hash_t              heaviest_fork_bank_hash;
  ulong                  heaviest_fork_ready;

  fd_pubkey_t            coordinator_pubkey;
  ulong                  coordinator_heaviest_fork_slot;
  fd_hash_t              coordinator_heaviest_fork_bank_hash;
  ulong                  coordinator_heaviest_fork_ready;
};
typedef struct fd_restart fd_restart_t;

/* fd_restart_{align,footprint} return the required alignment and
   footprint of a memory region suitable for use as the wen-restart state. */
FD_FN_CONST static inline ulong
fd_restart_align( void ) {
  return alignof(fd_restart_t);
}

FD_FN_CONST static inline ulong
fd_restart_footprint( void ) {
  return sizeof(fd_restart_t);
}

/* fd_restart_new formats an unused memory region for use as the state of
   wen-restart. mem is a non-NULL pointer to this region in the local address
   space with the required footprint and alignment. */
void *
fd_restart_new( void * mem );

/* fd_restart_join joins the caller to the wen-restart state. restart points
   to the first byte of the memory region backing the wen-restart state in the
   caller's address space.

   Returns a pointer in the local address space to wen-restart state on success. */
fd_restart_t *
fd_restart_join( void * restart );

/* fd_restart_init is called in the replay tile after a snapshot is loaded.
   The arguments of this function come from the loaded snapshot and provide
   the first few fields in fd_restart_t. This function fills out_buf
   and out_buf_len with a gossip message -- the first gossip message sent
   in the wen-restart protocol (fd_gossip_restart_last_voted_fork_slots_t). */
void
fd_restart_init( fd_restart_t * restart,
                 ulong funk_root,
                 fd_hash_t * root_bank_hash,
                 fd_vote_accounts_t const * epoch_stakes[],
                 fd_epoch_schedule_t * epoch_schedule,
                 int tower_checkpt_fileno,
                 fd_slot_history_t const * slot_history,
                 fd_pubkey_t * my_pubkey,
                 fd_pubkey_t * coordinator_pubkey,
                 uchar * out_buf,
                 ulong * out_buf_len );

/* fd_restart_recv_gossip_msg is invoked for each gossip message received.

   In case of a last_voted_fork_slots message, the function would check
   whether we have received such messages from more than 80% stake where
   80% is specified as WAIT_FOR_SUPERMAJORITY_THRESHOLD_PERCENT. If so,
   out_heaviest_fork_found would be set to 1, and the stage will be set
   to FD_RESTART_STAGE_FIND_HEAVIEST_FORK_BANK_HASH.

   In case of a heaviest_fork message, the function would check whether
   this message comes from the wen-restart coordinator, and if so, record
   the heaviest fork information in this message for later verification. */
void
fd_restart_recv_gossip_msg( fd_restart_t * restart,
                            void * gossip_msg,
                            ulong * out_heaviest_fork_found );

/* fd_restart_find_heaviest_fork_bank_hash will check whether the funk
   root happens to be the chosen heaviest fork slot. If so, it simply
   copies the funk root bank hash into the heaviest fork hash field of
   fd_restart_t. If not, it will set out_need_repair to 1, which will
   trigger a repair and repaly process from the funk root to the chosen
   heaviest fork slot in order to get the bank hash. */
void
fd_restart_find_heaviest_fork_bank_hash( fd_restart_t * restart,
                                         fd_funk_t * funk,
                                         ulong * out_need_repair );

/* fd_restart_verify_heaviest_fork is invoked repeatedly by the replay
   tile. It is a no-op if either the coordinator heaviest fork hash or
   the local heaviest fork hash is not ready. When both are ready, this
   function checks whether the two bank hashes match, and print an error
   message if the two mismatch.

   If we are the wen-restart coordinator, out_send will be set to 1 and
   out_buf will hold a message of type fd_gossip_restart_heaviest_fork_t,
   which will be sent out by the gossip tile. */
void
fd_restart_verify_heaviest_fork( fd_restart_t * restart,
                                 uchar * out_buf,
                                 ulong * out_send );

/* fd_restart_convert_runlength_to_raw_bitmap converts the bitmap in
   a last_voted_fork_slots message from the run length encoding into
   raw encoding. It is invoked in the gossip tile before forwarding
   this gossip message to the replay tile. Therefore, the replay tile
   could assume raw encoding of bitmap when processing the message.

   fd_restart_convert_raw_bitmap_to_runlength, reversely, converts a
   raw bitmap into run length encoding, which happens right before the
   gossip tile tries to send out a last_voted_fork_slots message. */
void
fd_restart_convert_runlength_to_raw_bitmap( fd_gossip_restart_last_voted_fork_slots_t * msg,
                                            uchar * out_bitmap,
                                            ulong * out_bitmap_len );

void
fd_restart_convert_raw_bitmap_to_runlength( fd_gossip_restart_last_voted_fork_slots_t * msg,
                                            fd_restart_run_length_encoding_inner_t * out_encoding );

/* fd_restart_tower_checkpt checkpoints the latest sent tower into a
   local file and it is invoked every time the replay tile sends out
   a tower vote; fd_restart_tower_restore reads this checkpoint file
   in fd_restart_init for the last_voted_fork_slot message sent out */
void
fd_restart_tower_checkpt( fd_hash_t const * vote_bank_hash,
                          fd_tower_t * tower,
                          int tower_checkpt_fileno );

void
fd_restart_tower_restore( fd_hash_t * vote_bank_hash,
                          ulong * tower_slots,
                          ulong * tower_height,
                          int tower_checkpt_fileno );
#endif
