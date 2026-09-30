#ifndef HEADER_fd_src_discof_repair_fd_blockdb_h
#define HEADER_fd_src_discof_repair_fd_blockdb_h

/* fd_blockdb stores metadata of completed blocks, keyed by
   (slot, block_id), for serving Alpenglow block id repair requests.
   Entries live in a fixed array and are overwritten oldest-first. */

#include "../../flamenco/fd_flamenco_base.h"
#include "../../disco/shred/fd_fec_set.h"
#include "../../ballet/bmtree/fd_bmtree.h"

#define FD_BLOCKDB_ALIGN (128UL)

/* The double-merkle tree has at most FD_FEC_BLK_MAX+1 leaves (FEC roots
   plus the parent-info leaf), so at most 12 layers and 11 proof nodes. */

#define FD_BLOCKDB_TREE_LAYER_MAX (12UL)
#define FD_BLOCKDB_PROOF_NODE_MAX (FD_BLOCKDB_TREE_LAYER_MAX-1UL)

struct fd_blockdb_key {
  ulong     slot;
  fd_hash_t block_id;
};
typedef struct fd_blockdb_key fd_blockdb_key_t;

FD_STATIC_ASSERT( sizeof(fd_blockdb_key_t)==40UL, fd_blockdb_key_t );

/* merkle_roots holds the first FD_SHRED_MERKLE_NODE_SZ bytes of each FEC
   set's merkle root, the only bytes the block id commits to.  Only the
   first fec_set_cnt entries are meaningful. */

struct fd_blockdb_blk {
  fd_blockdb_key_t key;
  ulong            parent_slot;
  fd_hash_t        parent_block_id;
  uint             fec_set_cnt;
  uint             next; /* map chain */
  uint             prev; /* map chain */
  uchar            merkle_roots[ FD_FEC_BLK_MAX ][ FD_SHRED_MERKLE_NODE_SZ ];
};
typedef struct fd_blockdb_blk fd_blockdb_blk_t;

struct fd_blockdb {
  ulong              ele_max;
  ulong              seq;     /* total inserts, next slot is seq%ele_max */
  fd_blockdb_blk_t * ele;
  void *             map;
  void *             tree;    /* scratch for building proofs */
};
typedef struct fd_blockdb fd_blockdb_t;

FD_PROTOTYPES_BEGIN

FD_FN_CONST static inline ulong
fd_blockdb_align( void ) {
  return FD_BLOCKDB_ALIGN;
}

/* fd_blockdb_footprint returns the footprint for ele_max entries, or 0
   if ele_max is zero or not less than UINT_MAX. */

ulong
fd_blockdb_footprint( ulong ele_max );

void *
fd_blockdb_new( void * shmem,
                ulong  ele_max,
                ulong  seed );

fd_blockdb_t *
fd_blockdb_join( void * shblockdb );

void *
fd_blockdb_leave( fd_blockdb_t const * blockdb );

void *
fd_blockdb_delete( void * shblockdb );

/* fd_blockdb_insert stores a block, overwriting the oldest entry when
   full.  Re-inserting an existing key updates it in place.
   merkle_roots points to fec_set_cnt 20B roots.  Returns NULL if
   fec_set_cnt is 0 or exceeds FD_FEC_BLK_MAX. */

fd_blockdb_blk_t *
fd_blockdb_insert( fd_blockdb_t *    blockdb,
                   ulong             slot,
                   fd_hash_t const * block_id,
                   ulong             parent_slot,
                   fd_hash_t const * parent_block_id,
                   uint              fec_set_cnt,
                   uchar const *     merkle_roots );

/* fd_blockdb_query returns the entry for (slot, block_id), or NULL.
   The pointer is invalidated by the next insert. */

fd_blockdb_blk_t const *
fd_blockdb_query( fd_blockdb_t const * blockdb,
                  ulong                slot,
                  fd_hash_t const *    block_id );

/* fd_blockdb_proof writes blk's double-merkle inclusion proof for leaf
   leaf_idx to proof, as 20B nodes from leaf to root.  Leaves are the FEC
   roots, then the parent-info leaf at fec_set_cnt.  Returns the node
   count, or -1 if leaf_idx>fec_set_cnt. */

int
fd_blockdb_proof( fd_blockdb_t *           blockdb,
                  fd_blockdb_blk_t const * blk,
                  ulong                    leaf_idx,
                  uchar                    proof[ FD_BLOCKDB_PROOF_NODE_MAX*FD_SHRED_MERKLE_NODE_SZ ] );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_discof_repair_fd_blockdb_h */
