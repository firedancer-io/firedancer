#ifndef HEADER_fd_src_choreo_restart_fd_restart_h
#define HEADER_fd_src_choreo_restart_fd_restart_h

/* fd_restart implements Solana's SIMD-0046, Optimistic cluster restart
   automation, which is also known as wen-restart.
   Protocol details: TODO
 */

#include "../../choreo/tower/fd_tower.h"
#include "../../flamenco/types/fd_types.h"

#define bits_per_uchar 8
#define bits_per_ulong ( 8 * sizeof(ulong) )
#define RESTART_MAGIC_TAG                         128UL

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
#define RESTART_MAX_MSG_BYTES                     LAST_VOTED_FORK_MAX_MSG_BYTES  // Assuming that this is larger than sizeof(fd_gossip_restart_heaviest_fork_t)

typedef enum {
    WR_STAGE_WAIT_FOR_INIT                = 0,
    WR_STAGE_FIND_HEAVIEST_FORK_SLOT_NUM  = 1,
    WR_STAGE_FIND_HEAVIEST_FORK_BANK_HASH = 2,
    WR_STAGE_GENERATE_SNAPSHOT            = 3,
    WR_STAGE_DONE                         = 4
} fd_wen_restart_stage_t;

/* fd_restart_t contains all the states maintained by wen-restart.
   It is allocated within the `unprivileged_init` of the replay tile. */
struct fd_restart {
  fd_wen_restart_stage_t stage;

  /* States initialized at the beginning */
  ulong                  funk_root;
  ulong                  tower_root;
  ulong                  total_stake;
  ulong                  num_vote_accts;
  fd_stake_weight_t      stake_weights[ MAX_RESTART_PEERS ];

  /* States maintained by the FIND_HEAVIEST_FORK_SLOT_NUM stage */
  ulong                  total_active_stake;
  ulong                  slot_to_stake[ LAST_VOTED_FORK_MAX_SLOTS ];
  uchar                  last_voted_fork_slots_received[ MAX_RESTART_PEERS ];

  /* States maintained by the FIND_HEAVIEST_FORK_BANK_HASH stage */
  fd_pubkey_t            my_pubkey;
  ulong                  heaviest_fork_slot;
  fd_hash_t              heaviest_fork_bank_hash;
  ulong                  heaviest_fork_ready;

  fd_pubkey_t            coordinator_pubkey;
  ulong                  coordinator_heaviest_fork_slot;
  fd_hash_t              coordinator_heaviest_fork_bank_hash;
  ulong                  coordinator_heaviest_fork_ready;
  ulong                  coordinator_heaviest_fork_sent;
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
                 fd_vote_accounts_t const * accs,
                 fd_tower_t const * tower,
                 fd_slot_history_t const * slot_history,
                 fd_funk_t * funk,
                 fd_blockstore_t * blockstore,
                 fd_pubkey_t * my_pubkey,
                 fd_pubkey_t * coordinator_pubkey,
                 uchar * out_buf,
                 ulong * out_buf_len );

/* fd_restart_recv_gossip_msg is invoked for each gossip message received.

   In case of a last_voted_fork_slots message, the function would check
   whether we have received such messages from more than 80% stake where
   80% is specified as WAIT_FOR_SUPERMAJORITY_THRESHOLD_PERCENT. If so,
   out_heaviest_fork_found would be set to 1, and the stage will be set
   to WR_STAGE_FIND_HEAVIEST_FORK_BANK_HASH.

   In case of a heaviest_fork message, the function would check whether
   this message comes from the wen-restart coordinator, and if so, record
   the heaviest fork information in this message for later verification. */
void
fd_restart_recv_gossip_msg( fd_restart_t * restart,
                            void * gossip_msg,
                            ulong * out_heaviest_fork_found );

/* fd_restart_find_heaviest_fork_bank_hash will check whether the bank
   hash of the chosen heaviest fork slot is already in the blockstore.
   If so, it simply copies this bank hash into the wen-restart state.
   If not, it will set out_need_repair to 1, which will trigger a repair
   and replay process in order to obtain the heaviest fork bank hash. */
void
fd_restart_find_heaviest_fork_bank_hash( fd_restart_t * restart,
                                         fd_funk_t * funk,
                                         fd_blockstore_t * blockstore,
                                         ulong * out_need_repair );

/* fd_restart_verify_heaviest_fork is invoked repeatedly by the replay
   tile. It is a no-op if either the coordinator heaviest fork hash or
   the local heaviest fork hash is not ready. When both are ready, this
   function checks whether the two bank hashes match, and print an error
   message if the two mismatch.

   If we are the wen-restart coordinator, out_send will be set to 1 and
   out_buf will hold a message of type fd_gossip_restart_heaviest_fork_t,
   which will be sent out by the gossip tile.
   */
void
fd_restart_verify_heaviest_fork( fd_restart_t * restart,
                                 uchar * out_buf,
                                 ulong * out_send );

#endif
