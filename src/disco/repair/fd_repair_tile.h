#ifndef HEADER_fd_src_disco_repair_fd_repair_tile_h
#define HEADER_fd_src_disco_repair_fd_repair_tile_h

#include "fd_repair_limits.h"

#include "../../disco/tiles.h"
#include "../../disco/shred/fd_shred_tile.h"

#define REPAIR_SIG_FEC (0UL)
#define REPAIR_SIG_BLK (1UL)

struct fd_repair_out_fec {
   ulong     slot;
   uint      fec_set_idx;
   fd_hash_t mr;
   fd_hash_t block_id;
   ulong     parent_slot;
   fd_hash_t parent_block_id;
   uint      update_parent_fec_idx; /* the fec_set_idx of the detected parentUpdate in the slot, 0 if none or undetected. */
   uchar     slot_complete : 1;
   uchar     data_complete : 1;
   uchar     is_leader     : 1;
   uchar     is_known      : 1; /* 0 if it's an eager repair blk, otherwise 1. */
   uchar     is_finalized  : 1;

   /* metrics */

   uchar     votor_repaired;            /* 1 if the FEC was delivered under a repaired by-id version of its slot, 0 under its turbine version, our leader blocks included */
   long      fec_completed_ts_nanos;    /* network arrival (wallclock ns) of the shred that completed this FEC, 0 if unavailable */
   ulong     highest_fec_complete_slot; /* highest slot with a FEC completed off the network, our leader FECs excluded: the cluster tip */
};
typedef struct fd_repair_out_fec fd_repair_out_fec_t;

/* fd_repair_out_blk is published to rserve when a block's slot-complete
   FEC is delivered.  merkle_roots holds the first 20B of each FEC
   root, starting at fec_off.  A block uses one or two consecutive frags
   on repair_rserve; each carries min(CHUNK_FEC_MAX,fec_set_cnt-fec_off)
   roots.  Offsets are 0 and, if needed, CHUNK_FEC_MAX.  This keeps each
   frag within mcache's ushort size.  Rserve exposes only complete records.
   The frag is variable length, see FD_REPAIR_BLOCK_SZ. */

#define FD_REPAIR_BLOCK_CHUNK_FEC_MAX (2048UL)
FD_STATIC_ASSERT( FD_REPAIR_FEC_MAX<=2UL*FD_REPAIR_BLOCK_CHUNK_FEC_MAX, repair_block_two_chunks );

struct fd_repair_out_blk {
  ulong     slot;
  fd_hash_t block_id;
  ulong     parent_slot;
  fd_hash_t parent_block_id;
  uint      fec_set_cnt;
  uint      fec_off;
  uchar     merkle_roots[ FD_REPAIR_BLOCK_CHUNK_FEC_MAX ][ FD_SHRED_MERKLE_NODE_SZ ];
};
typedef struct fd_repair_out_blk fd_repair_out_blk_t;

FD_STATIC_ASSERT( sizeof(fd_repair_out_blk_t)<=USHRT_MAX, repair_block_link_mtu );

#define FD_REPAIR_BLOCK_SZ(fec_set_cnt) (offsetof(fd_repair_out_blk_t, merkle_roots) + (ulong)(fec_set_cnt)*FD_SHRED_MERKLE_NODE_SZ)

#endif /* HEADER_fd_src_disco_repair_fd_repair_tile_h */
