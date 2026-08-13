#ifndef HEADER_fd_src_disco_shred_fd_shred_batch_h
#define HEADER_fd_src_disco_shred_fd_shred_batch_h

#include "../../util/fd_util_base.h"
#include "../shred/fd_shredder.h"

/* The shred tile partitions a block into batches of microblocks, and
   it partitions each batch into fixed-size FEC sets, with 32 data
   shreds and 32 parity shreds each.  Each batch is made up of an
   integer number of microblocks, which means that no microblock can
   cross the batch boundary, and that the last FEC set may need to be
   padded with 0s.  Since padding completes the payload of the last
   FEC set in the batch, and does not impact the batch itself, no FEC
   set can contain only padding.
   The number of FEC sets per batch is limited only by block-level
   limits, so the larger the value, the less relative padding overhead
   in every batch.  However, the larger the value, the longer it takes
   before the tile can start generating and sending FEC sets, unless
   you use some strange speculative tricks, which we do not use.
   Assuming n batches in a given block, the (upper-limit) quantity of
   FEC sets is determined by FD_SHRED_BATCH_FEC_SETS_WMARK for the
   first n-1 batches, and by FD_SHRED_BATCH_FEC_SETS_MAX for the last
   batch.  This is needed because when the microblock completing the
   block is received, we include it in the current batch irrespective
   of how full the batch might be.  The diagrams below (not at scale)
   show 2 FEC sets before the watermark (W), which indicates where to
   close the current batch, as well as 2 extra FEC sets available for
   the last batch in the block.

     Normal: (to be deprecated)
       +------------+------------+~~~~~~~~~~~+~~~~~~~~~~~~+
       |   FEC_set  |   FEC_set (W)    extra |      extra |
       +------------+------------+~~~~~~~~~~~+~~~~~~~~~~~~+

     Chained: (first n-1 batches)
       +-----------+-----------+~~~~~~~~~~+~~~~~~~~~~~+
       |   FEC_set |  FEC_set (W)   extra |     extra |
       +-----------+-----------+~~~~~~~~~~+~~~~~~~~~~~+

     Resigned: (last batch in block)
       +----------+----------+~~~~~~~~~~+~~~~~~~~~~+
       |  FEC_set | FEC_set (W)   extra |    extra |
       +----------+----------+~~~~~~~~~~+~~~~~~~~~~+

   The first n-1 batches are chained, whereas the last one in the
   block is (chained+)resigned, which means that each shred (and thus
   each FEC set) in the last batch has a smaller payload capacity.
   In order to size the region labeled extra, we need to consider the
   worst case scenario: we have buffered W-1 bytes using the chained
   watermark, when a max-size microblock arrives indicating it is the
   last in the block.  This situation can only happen when running in
   low-power mode, because otherwise the last microblock would be a
   tick, which is small, but it does not seem to be worth plumbing in
   that sort of logic just to save a little memory that would not
   pollute cache anyway.

   Note that this payload reduction does not affect normal FEC sets,
   which are scheduled to be deprecated at some point (TODO). */
#define FD_SHRED_BATCH_FEC_SETS_WMARK ( 2UL )
#define FD_SHRED_BATCH_FEC_SETS_EXTRA ( 2UL )
/* FD_SHRED_BATCH_FEC_SETS_MAX affects the value of STEM_BURST inside
   the shred tile (refer to its calculation for details). */
#define FD_SHRED_BATCH_FEC_SETS_MAX   ( FD_SHRED_BATCH_FEC_SETS_WMARK + FD_SHRED_BATCH_FEC_SETS_EXTRA )
/* Validate extra payload capacity.  Note that (chained+)resigned
   needs to take into considerations the watermark regression. */
#define FD_SHRED_BATCH_RESIGNED_WMARK_REGRESSION ( FD_SHRED_BATCH_FEC_SETS_WMARK * ( FD_SHREDDER_CHAINED_FEC_SET_PAYLOAD_SZ - FD_SHREDDER_RESIGNED_FEC_SET_PAYLOAD_SZ ) )
FD_STATIC_ASSERT( ( FD_SHRED_BATCH_FEC_SETS_EXTRA * FD_SHREDDER_NORMAL_FEC_SET_PAYLOAD_SZ   ) >= ( FD_POH_SHRED_MTU ), FD_SHRED_BATCH_FEC_SETS_EXTRA );
FD_STATIC_ASSERT( ( FD_SHRED_BATCH_FEC_SETS_EXTRA * FD_SHREDDER_CHAINED_FEC_SET_PAYLOAD_SZ  ) >= ( FD_POH_SHRED_MTU ), FD_SHRED_BATCH_FEC_SETS_EXTRA );
FD_STATIC_ASSERT( ( FD_SHRED_BATCH_FEC_SETS_EXTRA * FD_SHREDDER_RESIGNED_FEC_SET_PAYLOAD_SZ ) >= ( FD_POH_SHRED_MTU + FD_SHRED_BATCH_RESIGNED_WMARK_REGRESSION ), FD_SHRED_BATCH_FEC_SETS_EXTRA );

/* FD_SHRED_BATCH_WMARK: Following along the lines of dcache, batch
   microblocks until either the slot ends or the batch would exceed
   the corresponding watermark.  Only when the received microblock
   completes the block is the batch allowed to go beyond the given
   watermark, since all remaining FEC sets need to be generated and
   forwarded at once.  The watermark is relative to the beginning
   of the payload in the pending batch buffer (i.e. excluding the
   8 bytes needed for microblock_cnt in the batch header). */
#define FD_SHRED_BATCH_WMARK_NORMAL   ( FD_SHRED_BATCH_FEC_SETS_WMARK * FD_SHREDDER_NORMAL_FEC_SET_PAYLOAD_SZ   - 8UL )
#define FD_SHRED_BATCH_WMARK_CHAINED  ( FD_SHRED_BATCH_FEC_SETS_WMARK * FD_SHREDDER_CHAINED_FEC_SET_PAYLOAD_SZ  - 8UL )
#define FD_SHRED_BATCH_WMARK_RESIGNED ( FD_SHRED_BATCH_FEC_SETS_WMARK * FD_SHREDDER_RESIGNED_FEC_SET_PAYLOAD_SZ - 8UL )
/* Validate watermark payload capacity.  It must support at least
   FD_POH_SHRED_MTU bytes.  Prefer > to >= as a safety margin, to
   avoid any dependency on how we determine later on if the batch
   would exceed the watermark. */
FD_STATIC_ASSERT( ( FD_SHRED_BATCH_WMARK_NORMAL   ) > ( FD_POH_SHRED_MTU ), FD_SHRED_BATCH_WMARK_NORMAL   );
FD_STATIC_ASSERT( ( FD_SHRED_BATCH_WMARK_CHAINED  ) > ( FD_POH_SHRED_MTU ), FD_SHRED_BATCH_WMARK_CHAINED  );
FD_STATIC_ASSERT( ( FD_SHRED_BATCH_WMARK_RESIGNED ) > ( FD_POH_SHRED_MTU ), FD_SHRED_BATCH_WMARK_RESIGNED );
FD_STATIC_ASSERT( ( FD_SHRED_BATCH_WMARK_RESIGNED + FD_SHRED_BATCH_RESIGNED_WMARK_REGRESSION ) == ( FD_SHRED_BATCH_WMARK_CHAINED ), FD_SHRED_BATCH_RESIGNED_WMARK_REGRESSION );

/* There are three different raw buffer sizes depending on the FEC
   set type: normal, chained, and resigned (see fd_shredder.h for
   further details).  In order to support all three, we allocate the
   largest of them (i.e. normal).  TODO once normal FEC sets have
   been deprecated, replace NORMAL with CHAINED payload size in the
   calculation of FD_SHRED_BATCH_RAW_BUF_SZ below. */
#define FD_SHRED_BATCH_RAW_BUF_SZ     ( FD_SHRED_BATCH_FEC_SETS_MAX * FD_SHREDDER_NORMAL_FEC_SET_PAYLOAD_SZ )
/* Validate batch raw buffer size.  Note that (chained+)resigned
   needs to take into considerations the watermark regression. */
FD_STATIC_ASSERT( ( FD_SHRED_BATCH_RAW_BUF_SZ ) >= ( FD_SHRED_BATCH_WMARK_NORMAL   + FD_POH_SHRED_MTU ), FD_SHRED_BATCH_RAW_BUF_SZ );
FD_STATIC_ASSERT( ( FD_SHRED_BATCH_RAW_BUF_SZ ) >= ( FD_SHRED_BATCH_WMARK_CHAINED  + FD_POH_SHRED_MTU ), FD_SHRED_BATCH_RAW_BUF_SZ );
FD_STATIC_ASSERT( ( FD_SHRED_BATCH_RAW_BUF_SZ ) >= ( FD_SHRED_BATCH_WMARK_RESIGNED + FD_POH_SHRED_MTU + FD_SHRED_BATCH_RESIGNED_WMARK_REGRESSION ), FD_SHRED_BATCH_RAW_BUF_SZ );

/* FD_SHRED_BATCH_BLOCK_DATA_SZ_MAX is a conservative compile-time
   bound on entry bytes in a 32k-shred block (1024 chained FEC sets).
   It subtracts worst-case padding of about half the payload, plus
   last-batch resigned-size regression and 8-byte batch headers.
   Pack does not use this as its per-slot cap; that is
   fd_shred_batch_pack_data_max at become-leader.  This macro is the
   pre-leader default (FD_PACK_MAX_DATA_PER_BLOCK) and sizes skipped-
   tick buffers. */
FD_STATIC_ASSERT( ( FD_SHRED_BATCH_FEC_SETS_MAX ) == ( 4UL ), FD_SHRED_BATCH_FEC_SETS_MAX );
#define FD_SHRED_BATCH_BLOCK_DATA_OHEAD  (  512UL * FD_SHREDDER_CHAINED_FEC_SET_PAYLOAD_SZ + 8192UL + 8192UL )
FD_STATIC_ASSERT( ( FD_SHRED_BATCH_BLOCK_DATA_OHEAD ) < ( 1024UL * FD_SHREDDER_CHAINED_FEC_SET_PAYLOAD_SZ ), FD_SHRED_BATCH_BLOCK_DATA_OHEAD );
#define FD_SHRED_BATCH_BLOCK_DATA_SZ_MAX ( (1024UL-2UL) * FD_SHREDDER_CHAINED_FEC_SET_PAYLOAD_SZ - FD_SHRED_BATCH_BLOCK_DATA_OHEAD )

/* fd_shred_batch_pack_data_max: how many entry bytes (microblock
   headers + txn payloads, excluding empty ticks) pack can emit in a
   slot without producing more than slot_max_data_shreds.

   max_microblock_sz is the largest pack-produced entry: the 48-byte
   entry header plus (max txns per microblock)*FD_TPU_MTU.

   We shred by filling a batch until the next microblock would not
   fit in two chained FEC sets (WMARK_CHAINED = 2*C-8 payload bytes),
   then padding out that batch:
     - The first microblock of a slot is flushed immediately, using
       ceil( (8+max_microblock_sz)/C ) FEC sets.
     - Each later closed batch holds at least
       WMARK_CHAINED-max_microblock_sz entry bytes and uses 2 FEC sets.
     - The last batch is the leftover (at most wmark) plus the
       completing microblock, padded to resigned FEC sets:
       ceil( (wmark + 8 + max_microblock_sz) / R ).  Production
       finishes on an empty tick; low-power can finish on a
       max-size microblock.

   Empty ticks are not included; the caller should subtract
   48*(ticks_per_slot+skipped_ticks).  Returns 0 if the shred budget
   cannot cover the reserved FEC sets. */
FD_FN_CONST static inline ulong
fd_shred_batch_pack_data_max( ulong slot_max_data_shreds,
                              ulong max_microblock_sz ) {
  ulong const C     = FD_SHREDDER_CHAINED_FEC_SET_PAYLOAD_SZ;
  ulong const R     = FD_SHREDDER_RESIGNED_FEC_SET_PAYLOAD_SZ;
  ulong const wmark = FD_SHRED_BATCH_WMARK_CHAINED; /* 2*C - 8 */

  if( FD_UNLIKELY( max_microblock_sz>=wmark ) ) return 0UL;

  ulong fec_set_cnt          = slot_max_data_shreds / 32UL;
  ulong first_batch_fec_cnt  = ( 8UL + max_microblock_sz + C - 1UL ) / C;
  ulong last_batch_fec_cnt   = ( wmark + 8UL + max_microblock_sz + R - 1UL ) / R;
  if( FD_UNLIKELY( fec_set_cnt<first_batch_fec_cnt+last_batch_fec_cnt ) ) return 0UL;

  ulong middle_batch_fec_cnt = ( fec_set_cnt - first_batch_fec_cnt - last_batch_fec_cnt ) & ~1UL; /* even, 2 FEC per batch */
  ulong min_batch            = wmark - max_microblock_sz;
  return ( middle_batch_fec_cnt / 2UL ) * min_batch;
}

#endif /* HEADER_fd_src_disco_shred_fd_shred_batch_h */
