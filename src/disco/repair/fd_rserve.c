#include "fd_rserve.h"
#include "../../ballet/sha256/fd_sha256.h"

static void
fd_rserve_rotation_secret( uchar       out[ 32 ],
                           uchar const master[ 32 ],
                           ulong       idx ) {
  uchar buf[ 40 ];
  memcpy( buf, master, 32UL );
  FD_STORE( ulong, buf+32UL, idx );
  fd_sha256_hash( buf, sizeof(buf), out );
}

static void
fd_rserve_token_compute( uchar               token[ 32 ],
                         uchar const         secret[ 32 ],
                         fd_pubkey_t const * from,
                         uint                ip4,
                         ushort              port ) {
  memcpy( token, "SOLANA_PING_PONG", 16UL );

  uchar buf[ 32UL + 32UL + 4UL + 2UL ];
  memcpy( buf,       secret,   32UL );
  memcpy( buf+32UL,  from->uc, 32UL );
  FD_STORE( uint,   buf+64UL, ip4  );
  FD_STORE( ushort, buf+68UL, port );

  uchar mac[ 32 ];
  fd_sha256_hash( buf, sizeof(buf), mac );
  memcpy( token+16UL, mac, 16UL );
}

ulong
fd_rserve_footprint( ulong ping_cache_entries ) {
  if( FD_UNLIKELY( !ping_cache_entries ) ) return 0UL;

  ulong ping_max = fd_ulong_pow2_up( ping_cache_entries );

  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, alignof(fd_rserve_t), sizeof(fd_rserve_t) );
  l = FD_LAYOUT_APPEND( l, ping_pool_align(),    ping_pool_footprint( ping_max ) );
  l = FD_LAYOUT_APPEND( l, ping_map_align(),     ping_map_footprint( ping_map_chain_cnt_est( ping_max ) ) );
  l = FD_LAYOUT_APPEND( l, ping_dlist_align(),   ping_dlist_footprint() );
  return FD_LAYOUT_FINI( l, fd_rserve_align() );
}

void *
fd_rserve_new( void * shmem,
               ulong  ping_cache_entries,
               ulong  seed,
               uchar const secret[ 32 ] ) {
  if( FD_UNLIKELY( !shmem ) ) {
    FD_LOG_WARNING(( "NULL mem" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shmem, fd_rserve_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned mem" ));
    return NULL;
  }

  ulong footprint = fd_rserve_footprint( ping_cache_entries );
  if( FD_UNLIKELY( !footprint ) ) {
    FD_LOG_WARNING(( "bad ping cache size (%lu)", ping_cache_entries ));
    return NULL;
  }

  ulong ping_max = fd_ulong_pow2_up( ping_cache_entries );

  FD_SCRATCH_ALLOC_INIT( l, shmem );
  void * rserve_mem     = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_rserve_t), sizeof(fd_rserve_t) );
  void * ping_pool_mem  = FD_SCRATCH_ALLOC_APPEND( l, ping_pool_align(),    ping_pool_footprint( ping_max ) );
  void * ping_map_mem   = FD_SCRATCH_ALLOC_APPEND( l, ping_map_align(),     ping_map_footprint( ping_map_chain_cnt_est( ping_max ) ) );
  void * ping_dlist_mem = FD_SCRATCH_ALLOC_APPEND( l, ping_dlist_align(),   ping_dlist_footprint() );

  fd_rserve_t * rserve = (fd_rserve_t *)rserve_mem;
  ping_pool_new( ping_pool_mem, ping_max );
  rserve->ping_pool  = fd_type_pun( ping_pool_mem );
  rserve->ping_map   = ping_map_join  ( ping_map_new  ( ping_map_mem,   ping_map_chain_cnt_est( ping_max ), seed ) );
  rserve->ping_dlist = ping_dlist_join( ping_dlist_new( ping_dlist_mem ) );

  /* Initialize rotating token secrets. */
  rserve->seed           = seed;
  rserve->token_idx      = 0UL;
  rserve->last_rotate_ts = 0UL;
  memcpy( rserve->secret_master, secret, 32UL );
  fd_rserve_rotation_secret( rserve->secret_cur, rserve->secret_master, 0UL );
  memcpy( rserve->secret_prev, rserve->secret_cur, 32UL );

  FD_TEST( FD_SCRATCH_ALLOC_FINI( l, fd_rserve_align() )==(ulong)shmem + footprint );

  return shmem;
}

fd_rserve_t *
fd_rserve_join( void * shrserve ) {
  if( FD_UNLIKELY( !shrserve ) ) {
    FD_LOG_WARNING(( "NULL rserve" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shrserve, fd_rserve_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned rserve" ));
    return NULL;
  }

  fd_rserve_t * rserve = (fd_rserve_t *)shrserve;
  rserve->ping_pool  = ping_pool_join ( rserve->ping_pool  );
  rserve->ping_map   = ping_map_join  ( rserve->ping_map   );
  rserve->ping_dlist = ping_dlist_join( rserve->ping_dlist );

  return (fd_rserve_t *)rserve;
}

void *
fd_rserve_leave( fd_rserve_t const * rserve ) {
  if( FD_UNLIKELY( !rserve ) ) {
    FD_LOG_WARNING(( "NULL rserve" ));
    return NULL;
  }

  return (void *)rserve;
}

void *
fd_rserve_delete( void * rserve ) {
  if( FD_UNLIKELY( !rserve ) ) {
    FD_LOG_WARNING(( "NULL rserve" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)rserve, fd_rserve_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned rserve" ));
    return NULL;
  }

  return rserve;
}

void
fd_rserve_ping_token( fd_rserve_t const * rserve,
                      uchar               token[ 32 ],
                      fd_pubkey_t const * from,
                      uint                ip4,
                      ushort              port ) {
  fd_rserve_token_compute( token, rserve->secret_cur, from, ip4, port );
}

static int
fd_rserve_secret_pong_verify( uchar const         secret[ 32 ],
                              uchar const       * pong_hash,
                              fd_pubkey_t const * from,
                              uint                ip4,
                              ushort              port ) {
  uchar token   [ 32 ];
  uchar preimage[ 16UL+32UL ];
  uchar expected[ 32 ];

  fd_rserve_token_compute( token, secret, from, ip4, port );
  memcpy( preimage,      "SOLANA_PING_PONG", 16UL );
  memcpy( preimage+16UL, token,              32UL );
  fd_sha256_hash( preimage, sizeof(preimage), expected );
  return !memcmp( expected, pong_hash, 32UL );
}

int
fd_rserve_pong_token_verify( fd_rserve_t const * rserve,
                             uchar const       * pong_hash,
                             fd_pubkey_t const * from,
                             uint                ip4,
                             ushort              port ) {
  if( FD_LIKELY( fd_rserve_secret_pong_verify( rserve->secret_cur,  pong_hash, from, ip4, port ) ) ) return 1;
  if( FD_LIKELY( fd_rserve_secret_pong_verify( rserve->secret_prev, pong_hash, from, ip4, port ) ) ) return 1;
  return 0;
}

void
fd_rserve_maybe_rotate( fd_rserve_t * rserve,
                        ulong         now_ns ) {
  if( FD_UNLIKELY( now_ns-rserve->last_rotate_ts > FD_RSERVE_TOKEN_ROTATE_NS ) ) {
    rserve->last_rotate_ts = now_ns;
    rserve->token_idx++;
    memcpy( rserve->secret_prev, rserve->secret_cur, 32UL );
    fd_rserve_rotation_secret( rserve->secret_cur, rserve->secret_master, rserve->token_idx );
  }
}

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
