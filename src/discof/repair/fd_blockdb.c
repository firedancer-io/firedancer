#include "fd_blockdb.h"
#include "../../ballet/sha256/fd_sha256.h"

#define MAP_NAME                           fd_blockdb_map
#define MAP_ELE_T                          fd_blockdb_blk_t
#define MAP_KEY_T                          fd_blockdb_key_t
#define MAP_KEY                            key
#define MAP_IDX_T                          uint
#define MAP_NEXT                           next
#define MAP_PREV                           prev
#define MAP_KEY_EQ(k0,k1)                  (!memcmp( (k0), (k1), sizeof(fd_blockdb_key_t) ))
#define MAP_KEY_HASH(key,seed)             fd_hash( (seed), (key), sizeof(fd_blockdb_key_t) )
#define MAP_OPTIMIZE_RANDOM_ACCESS_REMOVAL 1
#include "../../util/tmpl/fd_map_chain.c"

ulong
fd_blockdb_footprint( ulong ele_max ) {
  if( FD_UNLIKELY( !ele_max || ele_max>=UINT_MAX ) ) return 0UL;

  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, alignof(fd_blockdb_t),     sizeof(fd_blockdb_t)                                          );
  l = FD_LAYOUT_APPEND( l, alignof(fd_blockdb_blk_t), ele_max*sizeof(fd_blockdb_blk_t)                              );
  l = FD_LAYOUT_APPEND( l, fd_blockdb_map_align(),    fd_blockdb_map_footprint( fd_blockdb_map_chain_cnt_est( ele_max ) ) );
  l = FD_LAYOUT_APPEND( l, FD_BMTREE_COMMIT_ALIGN,    FD_BMTREE_COMMIT_FOOTPRINT( FD_BLOCKDB_TREE_LAYER_MAX )       );
  return FD_LAYOUT_FINI( l, fd_blockdb_align() );
}

void *
fd_blockdb_new( void * shmem,
                ulong  ele_max,
                ulong  seed ) {
  if( FD_UNLIKELY( !shmem ) ) {
    FD_LOG_WARNING(( "NULL mem" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shmem, fd_blockdb_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned mem" ));
    return NULL;
  }

  ulong footprint = fd_blockdb_footprint( ele_max );
  if( FD_UNLIKELY( !footprint ) ) {
    FD_LOG_WARNING(( "bad ele_max (%lu)", ele_max ));
    return NULL;
  }

  ulong chain_cnt = fd_blockdb_map_chain_cnt_est( ele_max );

  FD_SCRATCH_ALLOC_INIT( l, shmem );
  fd_blockdb_t *     blockdb = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_blockdb_t),     sizeof(fd_blockdb_t)                  );
  fd_blockdb_blk_t * ele     = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_blockdb_blk_t), ele_max*sizeof(fd_blockdb_blk_t)      );
  void *             map     = FD_SCRATCH_ALLOC_APPEND( l, fd_blockdb_map_align(),    fd_blockdb_map_footprint( chain_cnt ) );
  void *             tree    = FD_SCRATCH_ALLOC_APPEND( l, FD_BMTREE_COMMIT_ALIGN,    FD_BMTREE_COMMIT_FOOTPRINT( FD_BLOCKDB_TREE_LAYER_MAX ) );
  FD_TEST( FD_SCRATCH_ALLOC_FINI( l, fd_blockdb_align() )==(ulong)shmem + footprint );
  FD_TEST( fd_bmtree_depth( FD_FEC_BLK_MAX+1UL )==FD_BLOCKDB_TREE_LAYER_MAX );

  blockdb->ele_max = ele_max;
  blockdb->seq     = 0UL;
  blockdb->ele     = ele;
  blockdb->tree    = tree;
  blockdb->map     = fd_blockdb_map_new( map, chain_cnt, seed );
  if( FD_UNLIKELY( !blockdb->map ) ) return NULL;

  return shmem;
}

fd_blockdb_t *
fd_blockdb_join( void * shblockdb ) {
  if( FD_UNLIKELY( !shblockdb ) ) {
    FD_LOG_WARNING(( "NULL blockdb" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shblockdb, fd_blockdb_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned blockdb" ));
    return NULL;
  }

  fd_blockdb_t * blockdb = (fd_blockdb_t *)shblockdb;
  blockdb->map = fd_blockdb_map_join( blockdb->map );
  if( FD_UNLIKELY( !blockdb->map ) ) return NULL;

  return blockdb;
}

void *
fd_blockdb_leave( fd_blockdb_t const * blockdb ) {
  if( FD_UNLIKELY( !blockdb ) ) {
    FD_LOG_WARNING(( "NULL blockdb" ));
    return NULL;
  }

  return (void *)blockdb;
}

void *
fd_blockdb_delete( void * shblockdb ) {
  if( FD_UNLIKELY( !shblockdb ) ) {
    FD_LOG_WARNING(( "NULL blockdb" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shblockdb, fd_blockdb_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned blockdb" ));
    return NULL;
  }

  return shblockdb;
}

fd_blockdb_blk_t *
fd_blockdb_insert( fd_blockdb_t *    blockdb,
                   ulong             slot,
                   fd_hash_t const * block_id,
                   ulong             parent_slot,
                   fd_hash_t const * parent_block_id,
                   uint              fec_set_cnt,
                   uchar const *     merkle_roots ) {
  if( FD_UNLIKELY( !fec_set_cnt || fec_set_cnt>FD_FEC_BLK_MAX ) ) return NULL;

  fd_blockdb_map_t * map = (fd_blockdb_map_t *)blockdb->map;
  fd_blockdb_key_t   key = { .slot = slot, .block_id = *block_id };

  fd_blockdb_blk_t * blk = fd_blockdb_map_ele_query( map, &key, NULL, blockdb->ele );
  if( FD_LIKELY( !blk ) ) {
    /* Take the oldest slot, unlinking its previous occupant once the
       array has wrapped. */
    blk = blockdb->ele + (blockdb->seq % blockdb->ele_max);
    if( FD_LIKELY( blockdb->seq>=blockdb->ele_max ) ) fd_blockdb_map_ele_remove_fast( map, blk, blockdb->ele );
    blockdb->seq++;
    blk->key = key;
    fd_blockdb_map_ele_insert( map, blk, blockdb->ele );
  }

  blk->parent_slot     = parent_slot;
  blk->parent_block_id = *parent_block_id;
  blk->fec_set_cnt     = fec_set_cnt;
  fd_memcpy( blk->merkle_roots, merkle_roots, fec_set_cnt*FD_SHRED_MERKLE_NODE_SZ );
  return blk;
}

fd_blockdb_blk_t const *
fd_blockdb_query( fd_blockdb_t const * blockdb,
                  ulong                slot,
                  fd_hash_t const *    block_id ) {
  fd_blockdb_key_t key = { .slot = slot, .block_id = *block_id };
  return fd_blockdb_map_ele_query_const( (fd_blockdb_map_t const *)blockdb->map, &key, NULL, blockdb->ele );
}

int
fd_blockdb_proof( fd_blockdb_t *           blockdb,
                  fd_blockdb_blk_t const * blk,
                  ulong                    leaf_idx,
                  uchar                    proof[ FD_BLOCKDB_PROOF_NODE_MAX*FD_SHRED_MERKLE_NODE_SZ ] ) {
  if( FD_UNLIKELY( leaf_idx>blk->fec_set_cnt ) ) return -1;

  fd_bmtree_commit_t * tree = fd_bmtree_commit_init( blockdb->tree, FD_SHRED_MERKLE_NODE_SZ, FD_BMTREE_LONG_PREFIX_SZ, FD_BLOCKDB_TREE_LAYER_MAX );

  /* Only the first FD_SHRED_MERKLE_NODE_SZ bytes of a node are hashed,
     so a zero-padded root prefix is an exact leaf. */
  fd_bmtree_node_t leaf[1] = {0};
  for( uint k=0U; k<blk->fec_set_cnt; k++ ) {
    memcpy( leaf->hash, blk->merkle_roots[ k ], FD_SHRED_MERKLE_NODE_SZ );
    fd_bmtree_commit_append( tree, leaf, 1UL );
  }

  fd_sha256_t sha[1];
  fd_sha256_init  ( sha );
  fd_sha256_append( sha, &blk->parent_slot,       sizeof(ulong)     );
  fd_sha256_append( sha, blk->parent_block_id.uc, sizeof(fd_hash_t) );
  fd_sha256_append( sha, &blk->fec_set_cnt,       sizeof(uint)      );
  fd_sha256_fini  ( sha, leaf->hash );
  fd_bmtree_commit_append( tree, leaf, 1UL );

  fd_bmtree_commit_fini( tree );
  return fd_bmtree_get_proof( tree, proof, leaf_idx );
}
