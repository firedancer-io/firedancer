#ifndef HEADER_fd_src_disco_pack_fd_microblock_h
#define HEADER_fd_src_disco_pack_fd_microblock_h

#include "../fd_txn_p.h"

/* in bytes.  Defined this way to use the size field of mcache.  This
   only includes the transaction payload and the fd_txn_t portions of
   the microblock, asTODO we are bound reliant on knowing the last shred in a slot im gonna cryryyy all the other portions (hash, etc) are generated
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
     block).  TODO: Remove. Not a good design. */
  uchar parent_block_id[ 32 ];
  uchar parent_block_id_valid;

  /* ALPENGLOW.  The frag carries one whole serialized BlockComponent
     block marker (a BlockHeader, BlockFooter or UpdateParent) instead
     of an entry batch.  A marker may not share a batch with entries --
     the batch's leading u64 is the entry count, and for a marker that
     count must be zero, which is what tells a replaying peer to parse
     the rest as a marker rather than as entries.  So the shred tile
     gives a marker frag a batch of its own, and takes the batch's
     leading u64 from the marker's own leading zero rather than from
     microblock_cnt.

     There is no entry header on a marker frag: the bytes after the meta
     are the serialized marker, starting at its u64 zero. */
  uchar block_marker;

  /* ALPENGLOW.  A metadata-only frag (no entry, no marker) whose only
     effect is to close whatever batch is currently pending.

     It exists because a marker may not share a batch with entries and
     the shred tile closes at most one batch per frag: on the frag
     carrying a marker it can either flush the pending entries or open
     the marker's batch, not both.  Under load pack emits thousands of
     tiny microblocks and the batch only seals at the watermark, so at
     block close there is almost always something pending -- without
     this the footer is dropped and every block is malformed.

     Emitted immediately before every marker.  If nothing is pending the
     shred tile early-returns and it costs nothing. */
  uchar batch_flush;
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

#define MAX_TXN_PER_MICROBLOCK ((MAX_MICROBLOCK_SZ-sizeof(fd_entry_batch_meta_t))/sizeof(fd_txn_e_t))

/* FD_POH_SHRED_MTU is the size of the raw transaction portion of the
   largest microblock the pack tile will produce, plus the 48B of
   microblock header (hash and 2 ulongs) plus the fd_entry_batch_meta_t
   metadata. */
#define FD_POH_SHRED_MTU (sizeof(fd_entry_batch_meta_t) + sizeof(fd_entry_batch_header_t) + FD_TPU_MTU * MAX_TXN_PER_MICROBLOCK)

FD_STATIC_ASSERT( FD_POH_SHRED_MTU<=USHORT_MAX, poh_shred_mtu );

#endif /*HEADER_fd_src_disco_pack_fd_microblock_h */
