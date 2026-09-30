#include "fd_blockdb.h"
#include "fd_repair.h"
#include "../../ballet/sha256/fd_sha256.h"

#define ELE_MAX (4UL)

static uchar mem[ 1UL<<20 ] __attribute__((aligned(FD_BLOCKDB_ALIGN)));
static uchar roots[ FD_FEC_BLK_MAX ][ FD_SHRED_MERKLE_NODE_SZ ];

static fd_hash_t
hash( uchar b ) {
  fd_hash_t h;
  memset( h.uc, b, sizeof(fd_hash_t) );
  return h;
}

static void
fill_roots( uchar b ) {
  for( ulong i=0UL; i<FD_FEC_BLK_MAX; i++ ) memset( roots[ i ], (int)(uchar)(b+i), FD_SHRED_MERKLE_NODE_SZ );
}

static void
check_blk( fd_blockdb_t const * db,
           ulong                slot,
           uchar                bid,
           ulong                parent_slot,
           uchar                parent_bid,
           uint                 fec_set_cnt,
           uchar                root_b ) {
  fd_hash_t block_id  = hash( bid );
  fd_hash_t parent_id = hash( parent_bid );
  fd_blockdb_blk_t const * blk = fd_blockdb_query( db, slot, &block_id );
  FD_TEST( blk );
  FD_TEST( blk->key.slot==slot );
  FD_TEST( !memcmp( &blk->key.block_id, &block_id, sizeof(fd_hash_t) ) );
  FD_TEST( blk->parent_slot==parent_slot );
  FD_TEST( !memcmp( &blk->parent_block_id, &parent_id, sizeof(fd_hash_t) ) );
  FD_TEST( blk->fec_set_cnt==fec_set_cnt );
  for( ulong i=0UL; i<fec_set_cnt; i++ ) {
    for( ulong j=0UL; j<FD_SHRED_MERKLE_NODE_SZ; j++ ) FD_TEST( blk->merkle_roots[ i ][ j ]==(uchar)(root_b+i) );
  }
}

static fd_blockdb_blk_t *
insert( fd_blockdb_t * db,
        ulong          slot,
        uchar          bid,
        ulong          parent_slot,
        uchar          parent_bid,
        uint           fec_set_cnt,
        uchar          root_b ) {
  fd_hash_t block_id  = hash( bid );
  fd_hash_t parent_id = hash( parent_bid );
  fill_roots( root_b );
  return fd_blockdb_insert( db, slot, &block_id, parent_slot, &parent_id, fec_set_cnt, (uchar const *)roots );
}

static int
has( fd_blockdb_t const * db,
     ulong                slot,
     uchar                bid ) {
  fd_hash_t block_id = hash( bid );
  return !!fd_blockdb_query( db, slot, &block_id );
}

/* block_id computes the double-merkle root the way the chainer does,
   from full 32B FEC roots. */

static uchar tree_mem[ FD_BMTREE_COMMIT_FOOTPRINT( 0UL ) ] __attribute__((aligned(FD_BMTREE_COMMIT_ALIGN)));

static fd_hash_t
block_id( fd_hash_t const * full_roots,
          uint              fec_set_cnt,
          ulong             parent_slot,
          fd_hash_t const * parent_block_id ) {
  fd_bmtree_commit_t * tree = fd_bmtree_commit_init( tree_mem, FD_SHRED_MERKLE_NODE_SZ, FD_BMTREE_LONG_PREFIX_SZ, 0UL );
  fd_bmtree_node_t leaf[1];
  for( uint k=0U; k<fec_set_cnt; k++ ) {
    memcpy( leaf->hash, full_roots[ k ].uc, sizeof(fd_hash_t) );
    fd_bmtree_commit_append( tree, leaf, 1UL );
  }
  fd_sha256_t sha[1];
  fd_sha256_init  ( sha );
  fd_sha256_append( sha, &parent_slot,           sizeof(ulong)     );
  fd_sha256_append( sha, parent_block_id->uc,    sizeof(fd_hash_t) );
  fd_sha256_append( sha, &fec_set_cnt,           sizeof(uint)      );
  fd_sha256_fini  ( sha, leaf->hash );
  fd_bmtree_commit_append( tree, leaf, 1UL );
  fd_hash_t bid;
  memcpy( bid.uc, fd_bmtree_commit_fini( tree ), sizeof(fd_hash_t) );
  return bid;
}

/* Every proof served for a block must parse with the client's
   deserializer and verify against the independently computed block id. */

static fd_hash_t full_roots[ FD_FEC_BLK_MAX ];

static void
test_proofs( fd_blockdb_t * db,
             fd_rng_t *     rng,
             uint           fec_set_cnt ) {
  ulong     slot      = 1000UL+fec_set_cnt;
  ulong     parent    = slot-1UL;
  fd_hash_t parent_id = hash( 0x77 );
  for( uint k=0U; k<fec_set_cnt; k++ ) {
    for( ulong j=0UL; j<sizeof(fd_hash_t); j++ ) full_roots[ k ].uc[ j ] = fd_rng_uchar( rng );
    memcpy( roots[ k ], full_roots[ k ].uc, FD_SHRED_MERKLE_NODE_SZ );
  }
  fd_hash_t bid = block_id( full_roots, fec_set_cnt, parent, &parent_id );

  fd_blockdb_blk_t const * blk = fd_blockdb_insert( db, slot, &bid, parent, &parent_id, fec_set_cnt, (uchar const *)roots );
  FD_TEST( blk );

  uchar proof[ FD_BLOCKDB_PROOF_NODE_MAX*FD_SHRED_MERKLE_NODE_SZ ];
  uchar buf[ AG_REPAIR_RESPONSE_MAX_SZ ];
  ag_repair_response_t res[1];
  ulong expected_len = fd_bmtree_depth( fec_set_cnt+1UL )-1UL;

  /* Parent-info leaf */
  int len = fd_blockdb_proof( db, blk, fec_set_cnt, proof );
  FD_TEST( len==(int)expected_len );
  ulong sz = ag_repair_parent_fec_count_ser( buf, sizeof(buf), fec_set_cnt, parent, &parent_id, proof, (ulong)len, 0xABCD1234U );
  FD_TEST( sz );
  FD_TEST( !ag_repair_response_de( res, buf, sz, FD_FEC_BLK_MAX ) );
  FD_TEST( res->kind==AG_REPAIR_RESPONSE_PARENT_FEC_SET_COUNT && res->nonce==0xABCD1234U );
  FD_TEST( res->parent_fec_set_res.fec_set_count==fec_set_cnt && res->parent_fec_set_res.parent_slot==parent );
  FD_TEST( !ag_repair_parent_fec_count_verify( &res->parent_fec_set_res, &bid ) );

  /* A wrong block id or a flipped proof bit must not verify */
  fd_hash_t other = bid; other.uc[ 0 ] ^= 1;
  FD_TEST( ag_repair_parent_fec_count_verify( &res->parent_fec_set_res, &other ) );
  if( len ) {
    res->parent_fec_set_res.parent_proof[ 0 ][ 0 ] ^= 1;
    FD_TEST( ag_repair_parent_fec_count_verify( &res->parent_fec_set_res, &bid ) );
  }

  /* Every FEC root leaf */
  for( uint k=0U; k<fec_set_cnt; k++ ) {
    len = fd_blockdb_proof( db, blk, k, proof );
    FD_TEST( len==(int)expected_len );
    sz = ag_repair_fec_set_root_ser( buf, sizeof(buf), blk->merkle_roots[ k ], proof, (ulong)len, k );
    FD_TEST( sz );
    FD_TEST( !ag_repair_response_de( res, buf, sz, FD_FEC_BLK_MAX ) );
    FD_TEST( res->kind==AG_REPAIR_RESPONSE_FEC_SET_ROOT && res->nonce==k );
    FD_TEST( !memcmp( res->fec_set_root.root, full_roots[ k ].uc, FD_SHRED_MERKLE_NODE_SZ ) );
    FD_TEST( !ag_repair_fec_set_root_verify( &res->fec_set_root, &bid, k*FD_FEC_SHRED_CNT, fec_set_cnt ) );
    if( fec_set_cnt>1U ) FD_TEST( ag_repair_fec_set_root_verify( &res->fec_set_root, &bid, ((k+1U)%fec_set_cnt)*FD_FEC_SHRED_CNT, fec_set_cnt ) );
  }

  /* Past the parent-info leaf */
  FD_TEST( fd_blockdb_proof( db, blk, fec_set_cnt+1UL, proof )==-1 );

  /* Serializers refuse a short buffer */
  FD_TEST( !ag_repair_fec_set_root_ser( buf, 8UL, blk->merkle_roots[ 0 ], proof, expected_len, 0U ) );
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  FD_TEST( !fd_blockdb_footprint( 0UL      ) );
  FD_TEST( !fd_blockdb_footprint( UINT_MAX ) );
  ulong footprint = fd_blockdb_footprint( ELE_MAX );
  FD_TEST( footprint && footprint<=sizeof(mem) );

  fd_blockdb_t * db = fd_blockdb_join( fd_blockdb_new( mem, ELE_MAX, 1234UL ) );
  FD_TEST( db );

  /* Empty */
  FD_TEST( !has( db, 10UL, 1 ) );

  /* Rejects bad fec_set_cnt */
  FD_TEST( !insert( db, 10UL, 1, 9UL, 9, 0U,                   0 ) );
  FD_TEST( !insert( db, 10UL, 1, 9UL, 9, FD_FEC_BLK_MAX+1U,    0 ) );
  FD_TEST( !has( db, 10UL, 1 ) );
  FD_TEST( db->seq==0UL );

  /* Insert and query, including two versions of one slot and a full
     FEC count */
  FD_TEST( insert( db, 10UL, 1, 9UL,  9, 3U,             10 ) );
  FD_TEST( insert( db, 10UL, 2, 8UL,  8, 5U,             20 ) );
  FD_TEST( insert( db, 11UL, 3, 10UL, 1, FD_FEC_BLK_MAX, 30 ) );
  check_blk( db, 10UL, 1, 9UL,  9, 3U,             10 );
  check_blk( db, 10UL, 2, 8UL,  8, 5U,             20 );
  check_blk( db, 11UL, 3, 10UL, 1, FD_FEC_BLK_MAX, 30 );
  FD_TEST( !has( db, 11UL, 1 ) ); /* same block id, other slot */
  FD_TEST( !has( db, 12UL, 3 ) );

  /* Re-insert updates in place without consuming a slot */
  fd_blockdb_blk_t * blk = insert( db, 10UL, 1, 7UL, 7, 4U, 40 );
  FD_TEST( blk );
  FD_TEST( db->seq==3UL );
  check_blk( db, 10UL, 1, 7UL, 7, 4U, 40 );

  /* Fill, then wrap: oldest entries are overwritten in insert order */
  FD_TEST( insert( db, 12UL, 4, 11UL, 3, 1U, 50 ) );
  FD_TEST( db->seq==4UL );
  FD_TEST( has( db, 10UL, 1 ) && has( db, 10UL, 2 ) && has( db, 11UL, 3 ) && has( db, 12UL, 4 ) );

  FD_TEST( insert( db, 13UL, 5, 12UL, 4, 2U, 60 ) );
  FD_TEST( !has( db, 10UL, 1 ) );
  FD_TEST( has( db, 10UL, 2 ) && has( db, 11UL, 3 ) && has( db, 12UL, 4 ) && has( db, 13UL, 5 ) );

  FD_TEST( insert( db, 14UL, 6, 13UL, 5, 2U, 70 ) );
  FD_TEST( !has( db, 10UL, 2 ) );
  check_blk( db, 11UL, 3, 10UL, 1, FD_FEC_BLK_MAX, 30 );
  check_blk( db, 12UL, 4, 11UL, 3, 1U,             50 );
  check_blk( db, 13UL, 5, 12UL, 4, 2U,             60 );
  check_blk( db, 14UL, 6, 13UL, 5, 2U,             70 );

  /* An evicted key can be inserted again */
  FD_TEST( insert( db, 10UL, 1, 9UL, 9, 3U, 80 ) );
  FD_TEST( !has( db, 11UL, 3 ) );
  check_blk( db, 10UL, 1, 9UL, 9, 3U, 80 );

  /* Many wraps keep exactly the newest ELE_MAX entries */
  for( ulong i=0UL; i<100UL; i++ ) FD_TEST( insert( db, 100UL+i, (uchar)i, 99UL+i, 0, 1U, (uchar)i ) );
  for( ulong i=0UL; i<100UL; i++ ) FD_TEST( has( db, 100UL+i, (uchar)i )==(i>=100UL-ELE_MAX) );

  /* Proofs, including odd leaf counts, powers of two, and the maximum */
  fd_rng_t _rng[1];
  fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, 42U, 0UL ) );
  uint const cnts[] = { 1U, 2U, 3U, 4U, 5U, 7U, 8U, 31U, 32U, 33U, 63U, 64U, 511U, 1023U, FD_FEC_BLK_MAX };
  for( ulong i=0UL; i<sizeof(cnts)/sizeof(cnts[0]); i++ ) test_proofs( db, rng, cnts[ i ] );
  fd_rng_delete( fd_rng_leave( rng ) );

  FD_TEST( fd_blockdb_delete( fd_blockdb_leave( db ) )==mem );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
