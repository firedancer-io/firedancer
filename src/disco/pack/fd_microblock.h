#ifndef HEADER_fd_src_ballet_pack_fd_microblock_h
#define HEADER_fd_src_ballet_pack_fd_microblock_h

#include "../../ballet/txn/fd_txn.h"

/* in bytes.  Defined this way to use the size field of mcache.  This
   only includes the transaction payload and the fd_txn_t portions of
   the microblock, as all the other portions (hash, etc) are generated
   by PoH later. */
#define MAX_MICROBLOCK_SZ USHORT_MAX

struct fd_entry_batch_meta {
  /* How many skipped slots we are building on top of.  If there were no
     skipped slots, (aka: this is slot 10, and the reset slot is slot 9,
     then the value should be 1). */
  ulong parent_offset;

  /* Tick in the slot indexed from [0, ticks_per_slot].  For ticks,
     which are sent ever 12,500 hashes, this will be 1 for the first
     tick, then 2, ... up to and including tick 64 for the last one.

     For microblocks, it will be 0 for microblocks that are sent before
     the first tick, etc, up to and including 63.  The range of allowed
     reference ticks is thus [0, 64], but can only be 0 for a microblock
     and can only be 64 for the last tick (when block_complete is true). */
  ulong reference_tick;

  /* Whether this is the last microblock in the slot or not.  The last
     microblock will always be an empty tick with no transactions in
     it. */
  int   block_complete;

  /* Chained merkle root needed by shred tile.  This is the merkle
     root of the last FEC set of the parent block (that's used as
     the chaining Merkle root for the first FEC set in the current
     block). */
  uchar parent_block_id[ 32 ];
  uchar parent_block_id_valid;
};
typedef struct fd_entry_batch_meta fd_entry_batch_meta_t;

struct fd_entry_batch_header {
  /* Number of hashes since the last entry batch that was published,
     in (0, hashes_per_tick].  Will be hashes_per_tick if and only
     if there were no microblocks sent between two empty ticks of the
     PoH. */
  ulong hashcnt_delta;

  /* The proof of history stamped hash of the entry batch. */
  uchar hash[32UL];

   /* Number of hashes in the entry batch.  Will be 0 for a tick,
      and (0, MAX_TXN_PER_MICROBLOCK] for a microblock. */
  ulong txn_cnt;
};
typedef struct fd_entry_batch_header fd_entry_batch_header_t;

struct __attribute__((aligned(64))) fd_txn_p {
  uchar payload[FD_TPU_MTU];
  ulong payload_sz;
  union {
   struct {
     uint non_execution_cus;
     uint requested_exec_plus_acct_data_cus;
   } pack_cu; /* Populated by pack. Bank reads these to populate the other struct of the union. */
   struct {
     uint rebated_cus; /* requested_exec_plus_acct_data_cus-actual used CUs. Pack reads this for CU rebating. */
     uint actual_consumed_cus; /* non_execution_cus+real execution CUs+real account data cus. PoH reads this for block CU counting. */
   } bank_cu; /* Populated by bank. */
   ulong blockhash_slot; /* Slot provided by resolv tile when txn arrives at the pack tile. Used when txn is in extra storage in pack. */
  };
  /* The time that the transaction arrived to the pack tile in ticks. Set by pack and intended to be read from a transaction on a pack->bank link. */
  long scheduler_arrival_time_nanos;
  /* Populated by pack, bank.  A combination of the bitfields
     FD_TXN_P_FLAGS_* defined above.  The bank sets the high byte with
     the transaction result code. */
  uint  flags;
  /* union {
    This would be ideal but doesn't work because of the flexible array member
    uchar _[FD_TXN_MAX_SZ];
    fd_txn_t txn;
  }; */
  /* Access with TXN macro below */
  uchar _[FD_TXN_MAX_SZ] __attribute__((aligned(alignof(fd_txn_t))));
};
typedef struct fd_txn_p fd_txn_p_t;

#define TXN(txn_p) ((fd_txn_t *)( (txn_p)->_ ))

/* fd_txn_e_t: An fd_txn_p_t with expanded address lookup tables */
struct __attribute__((aligned(64))) fd_txn_e {
   fd_txn_p_t     txnp[1];
   fd_acct_addr_t alt_accts[FD_TXN_ACCT_ADDR_MAX]; /* The used account is in the fd_txn_t*/
};
typedef struct fd_txn_e fd_txn_e_t;

#define MAX_TXN_PER_MICROBLOCK ((MAX_MICROBLOCK_SZ-sizeof(fd_entry_batch_meta_t))/sizeof(fd_txn_p_t))

/* FD_POH_SHRED_MTU is the size of the raw transaction portion of the
   largest microblock the pack tile will produce, plus the 48B of
   microblock header (hash and 2 ulongs) plus the fd_entry_batch_meta_t
   metadata. */
#define FD_POH_SHRED_MTU (sizeof(fd_entry_batch_meta_t) + sizeof(fd_entry_batch_header_t) + FD_TPU_MTU * MAX_TXN_PER_MICROBLOCK)

FD_STATIC_ASSERT( FD_POH_SHRED_MTU<=USHORT_MAX, poh_shred_mtu );

#endif /*HEADER_fd_src_ballet_pack_fd_microblock_h*/
