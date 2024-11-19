#ifndef HEADER_fd_src_disco_geyser_fd_geyser_h
#define HEADER_fd_src_disco_geyser_fd_geyser_h 1

#include "../../util/fd_util.h"
#include "../../flamenco/types/fd_types.h"
#include "../../flamenco/runtime/fd_blockstore.h"
#include "../shred/fd_stake_ci.h"
#include "../../app/fdctl/run/tiles/fd_replay_notif.h"

/* This API is the moral equivalent of the solana "plug-in" api. The
   purpose is to allow applications external to firedancer to
   interrogate the validator state efficiently in real time. As
   transactions are processed, callbacks are invoked
   asynchronously. Note that firedancer itself does not use this
   API. fd_geyser is meant for processes that do not wish to conform
   to the tile architecture.

   The callback pattern is:
   acct_fun                      - as each account is updated
   execute_fun                   = after each block is executed
   block_fun                     = after each block is executed
   | entry_fun                   - for each entry within a block
   | | txn_fun                   - for each transaction within an entry
   block_done_fun                = indicates that we done with callbacks for a block
*/

/* This callback is invoked immediately after a block execution. The
   useful fields on the notify message are:

   struct fd_replay_notif_msg {
       union {
           struct {
               ulong parent;              parent slot number
               ulong root;                current smr
               ulong slot;                executed slot number
               ulong height;
               fd_hash_t bank_hash;
               fd_hash_t block_hash;
               fd_pubkey_t identity;      identity of validator
               ulong transaction_count;   total transaction count
           } slot_exec;
       };
   };
   typedef struct fd_replay_notif_msg fd_replay_notif_msg_t;
*/
typedef void (*fd_geyser_execute_fun)(fd_replay_notif_msg_t const * msg, void * arg);

/* This callback supplies the raw block data and meta-data to the
   application. It is called on each block execution. The useful
   fields in the meta-data are:

   struct fd_block_map {
       ulong slot;
       ulong parent_slot;
       ulong child_slots[FD_BLOCKSTORE_CHILD_SLOT_MAX];
       ulong child_slot_cnt;

       ulong     height;
       fd_hash_t block_hash;
       fd_hash_t bank_hash;
       uchar     flags;             FD_BLOCK_FLAG_COMPLETED, etc.
       uchar     reference_tick;    the tick when the leader prepared the block.
       long      ts;                the wallclock time when we finished receiving the block.
   };
   typedef struct fd_block_map fd_block_map_t;
*/
typedef void (*fd_geyser_block_fun)(ulong slot, fd_block_map_t const * meta, fd_hash_t const * parent_hash, uchar const * data, ulong data_sz, void * arg);

/* This callback is invoked for each entry or microblock within a
 * block. The useful fields are:

   struct fd_microblock_hdr {
       ulong hash_cnt;                    Number of PoH hashes between this and last microblock
       uchar hash[ FD_SHA256_HASH_SZ ];   PoH state after evaluating this microblock
       ulong txn_cnt;                     Number of transactions in this microblock
   };
   typedef struct fd_microblock_hdr fd_microblock_hdr_t;
*/
typedef void (*fd_geyser_entry_fun)(ulong slot, fd_microblock_hdr_t * entry, void * arg);

/* This callback is invoked for each transaction within an entry. The
   transaction in raw and parsed form is given. The fd_txn_t data
   structure is too complicated to reproduce here. See
   src/ballet/txn/fd_txn.h for details.
*/
typedef void (*fd_geyser_txn_fun)(ulong slot, fd_txn_t const * txn, void const * raw, ulong txn_sz, void * arg);

/* This callback indicates that the nested pattern of callbacks for a
   block is complete. */
typedef void (*fd_geyser_block_done_fun)(ulong slot, void * arg);

/* This callback is invoked after each account update. This happens
   before the block callbacks. data is the account content. The useful
   fields in meta are:

   struct fd_solana_account_meta {
     ulong lamports;
     ulong rent_epoch;
     uchar owner[32];
     uchar executable;
   };
   typedef struct fd_solana_account_meta fd_solana_account_meta_t;

   struct fd_account_meta {
     uchar hash[32];
     ulong slot;
     fd_solana_account_meta_t info;
   };
   typedef struct fd_account_meta fd_account_meta_t;
*/
typedef void (*fd_geyser_acct_fun)(ulong slot, uchar txn_sig[64U], fd_hash_t const * address, fd_account_meta_t const * meta, void const * data, ulong data_sz, void * arg);

/* All arguments needed to construct a fd_geyser. Undesired callbacks can be set to NULL. */
struct fd_geyser_args {
  const char * funk_file;                    /* Shared memory backing file of account database */
  const char * blockstore_wksp;              /* Name of blockstore workspace */
  int          blockstore_fd;                /* File descriptor of blockstore */

  void * fun_arg;                            /* Generic callback argument */

  /* Called after each block execution */
  fd_geyser_execute_fun    execute_fun;      /* Slot numbers, bank hash */
  fd_geyser_block_fun      block_fun;        /* Raw block data, additional metadata */
  fd_geyser_entry_fun      entry_fun;        /* Every entry/microblock */
  fd_geyser_txn_fun        txn_fun;          /* Every individual transaction */
  fd_geyser_block_done_fun block_done_fun;   /* Called after block specific updates are done */

  /* Called as accounts are updated */
  fd_geyser_acct_fun       acct_fun;         /* Account written */
};

typedef struct fd_geyser_args fd_geyser_args_t;

typedef struct fd_geyser fd_geyser_t;

/* Memory footprint needed for a fd_geyser */
ulong fd_geyser_footprint( void );

/* Memory alignment needed for a fd_geyser */
ulong fd_geyser_align( void );

/* Construct a geyser object using the given memory */
void * fd_geyser_new( void * mem, fd_geyser_args_t * args );

/* Use an existing geyser object */
fd_geyser_t * fd_geyser_join( void * mem );

void * fd_geyser_leave( fd_geyser_t * self );

void * fd_geyser_delete( void * mem );

/* Check for updates in the firedancer shared memory
   channels. Appropriate callbacks are invoked. Backpressure is not
   implemented. If poll is not called often enough, blocks may get
   skipped.

   IMPORTANT: scratch memory is used to buffer blocks. Call
   fd_scratch_attach before polling. Provide enough memory for the
   largest possible block. For example:

   #define SMAX 1LU<<28
   uchar * smem = aligned_alloc( FD_SCRATCH_SMEM_ALIGN,
                                 fd_scratch_smem_footprint( SMAX ) );
   ulong fmem[16U];
   fd_scratch_attach( smem, fmem, SMAX, 16U );
*/
void fd_geyser_poll( fd_geyser_t * self );

/* Retrieve a historical block and replay all the callbacks for
   it. As with poll, scratch memory must be attached. */
void fd_geyser_replay_block( fd_geyser_t * ctx, ulong slotn );

/* Retrieve the current staking/leadership map. See
   src/disco/shred/fd_stake_ci.h for more details. */
fd_stake_ci_t * fd_geyser_stake_ci( fd_geyser_t * self );

#endif /* HEADER_fd_src_disco_geyser_fd_geyser_h */
