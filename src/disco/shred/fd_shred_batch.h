#ifndef HEADER_fd_src_disco_shred_fd_shred_batch_h
#define HEADER_fd_src_disco_shred_fd_shred_batch_h

#include "../../util/fd_util_base.h"
#include "../shred/fd_shredder.h"

/* The shred tile partitions a block into batches of microblocks,
   and it partitions each batch into fixed-size FEC sets, with 32
   data shreds and 32 parity shreds each.  For a given batch, only
   an integer number of microblocks are allowed, which means that
   no microblock can cross the batch boundary, and that the payload
   for the last FEC set needs to be padded with 0s.  The padding
   completes the payload of the last FEC set in the batch, not the
   batch itself.  Therefore, no FEC set can contain only 0s, and a
   a batch may contain less FEC sets than the allocated quantity.
   The number of FEC sets per batch is arbitrary.  The larger the
   value, the less padding overhead in every batch.  However, the
   larger the value, the longer it takes before the tile can start
   generating and sending FEC sets.  Assuming n batches in a given
   block, the (upper-limit) quantity of FEC sets is determined by
   FD_SHRED_BATCH_FEC_SETS_WMARK for batch ids [0, n-2], and by
   FD_SHRED_BATCH_FEC_SETS_MAX for batch id n-1.  This is needed
   because when the microblock completing the block is received,
   it must be included in the current batch irrespective of how
   full the latter might be.  The diagrams below (not at scale)
   show 2 FEC sets before the watermark (W), which indicates where
   to close the current batch, as well as 2 extra FEC sets that
   are available for the last batch in the block.

     Normal: (to be deprecated)
       +------------+------------+~~~~~~~~~~~+~~~~~~~~~~~~+
       |   FEC_set  |   FEC_set (W)    extra |      extra |
       +------------+------------+~~~~~~~~~~~+~~~~~~~~~~~~+

     Chained: (batch ids [0, n-2])
       +-----------+-----------+~~~~~~~~~~+~~~~~~~~~~~+
       |   FEC_set |  FEC_set (W)   extra |     extra |
       +-----------+-----------+~~~~~~~~~~+~~~~~~~~~~~+

     Resigned: (last batch in block)
       +----------+----------+~~~~~~~~~~+~~~~~~~~~~+
       |  FEC_set | FEC_set (W)   extra |    extra |
       +----------+----------+~~~~~~~~~~+~~~~~~~~~~+

   Batch ids [0, n-2] are chained, whereas batch id n-1 (the
   last one in the block) is (chained+)resigned, with a smaller
   payload capacity.  The transition between the two implies a
   watermark regression, requiring FD_SHRED_BATCH_FEC_SETS_EXTRA
   to be able to support (at least) FD_POH_SHRED_MTU bytes plus
   the watermark regression.  This payload reduction does not
   affect normal FEC sets, which are scheduled to be deprecated
   at some point (TODO). */
#define FD_SHRED_BATCH_FEC_SETS_WMARK ( 2UL )
#define FD_SHRED_BATCH_FEC_SETS_EXTRA ( 2UL )
/* FD_SHRED_BATCH_FEC_SETS_MAX affects the value of STEM_BURST
   inside the shred tile (refer to its calculation for details). */
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

/* Each block is limited to 32k parity shreds.  The number of parity
   shreds in each FEC set is always at least as many as the number of
   data shreds, so we do not need to consider the data shreds limit.
   Since each FEC set is now guaranteed to contain 32 shreds (note:
   32 data shreds and 32 parity shreds), the total maximum number of
   FEC sets is 1024 (32k/32).  We consider the payload capacity of
   chained FEC set as the raw capacity (which is smaller than normal
   FEC sets), and subtract from there the overheads.  The worst case
   padding overhead (OHEAD_PAD) can be approximated as one where the
   last FEC set in each batch contains 1 byte of data and the rest is
   all padded with 0s.  There is also a watermark regression overhead
   (OHEAD_REG) for the last batch when transitioning from chained to
   (chained+)resigned.  The batch header is 8 bytes, and the worst
   case header overhead (OHEAD_HDR) can be approximated as one were
   every batch has only 1 FEC set. */
#define FD_SHRED_BATCH_BLOCK_DATA_SZ_RAW    ( 1024UL * FD_SHREDDER_CHAINED_FEC_SET_PAYLOAD_SZ )
/* FD_SHRED_BATCH_BLOCK_DATA_OHEAD_PAD assumes that each batch may
   have up to 2 FEC sets before the watermark, which yields (1024/2)
   512 batches per block. */
FD_STATIC_ASSERT( ( FD_SHRED_BATCH_FEC_SETS_WMARK ) == ( 2UL ), FD_SHRED_BATCH_FEC_SETS_WMARK );
#define FD_SHRED_BATCH_BLOCK_DATA_OHEAD_PAD ( 512UL * ( FD_SHREDDER_CHAINED_FEC_SET_PAYLOAD_SZ - 1UL ) )
#define FD_SHRED_BATCH_BLOCK_DATA_OHEAD_REG ( FD_SHRED_BATCH_FEC_SETS_MAX * ( FD_SHREDDER_CHAINED_FEC_SET_PAYLOAD_SZ - FD_SHREDDER_RESIGNED_FEC_SET_PAYLOAD_SZ ) )
#define FD_SHRED_BATCH_BLOCK_DATA_OHEAD_HDR ( 1024UL * 8UL )
#define FD_SHRED_BATCH_BLOCK_DATA_OHEAD_ALL ( FD_SHRED_BATCH_BLOCK_DATA_OHEAD_PAD + FD_SHRED_BATCH_BLOCK_DATA_OHEAD_REG + FD_SHRED_BATCH_BLOCK_DATA_OHEAD_HDR )
#define FD_SHRED_BATCH_BLOCK_DATA_SZ_MAX    ( FD_SHRED_BATCH_BLOCK_DATA_SZ_RAW - FD_SHRED_BATCH_BLOCK_DATA_OHEAD_ALL )
FD_STATIC_ASSERT( ( FD_SHRED_BATCH_BLOCK_DATA_SZ_RAW ) > ( FD_SHRED_BATCH_BLOCK_DATA_OHEAD_ALL ), FD_SHRED_BATCH_BLOCK_DATA_SZ_MAX );

#endif /* HEADER_fd_src_disco_shred_fd_shred_batch_h */
