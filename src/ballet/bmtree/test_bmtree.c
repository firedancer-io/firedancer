#include "../fd_ballet.h"

#define REFERENCE_PROOF_SZ  (80UL)
#define REFERENCE_PROOF_CNT (11UL)

FD_IMPORT_BINARY( reference_proofs,         "src/ballet/bmtree/reference_proofs.bin"         );

#define MEMORY_SZ (70UL*1024UL*1024UL)
uchar memory[ MEMORY_SZ ] __attribute__((aligned(FD_BMTREE_COMMIT_ALIGN)));
uchar inc_proof[ 63*32 ];

/* Test tree-20 construction */
static void
test_bmtree20_commit( ulong        leaf_cnt,
                      void const * expected_root ) {
  fd_bmtree_commit_t _tree[1];
  fd_bmtree_commit_t * tree = fd_bmtree_commit_init( _tree, 20UL, 1UL, 0UL ); FD_TEST( tree==_tree );

  fd_bmtree_node_t leaf[1];
  fd_memset( leaf->hash, 0, 20UL );
  for( ulong i=0UL; i<leaf_cnt; i++ ) {
    FD_TEST( fd_bmtree_commit_leaf_cnt( tree )==i );
    FD_STORE( ulong, leaf->hash, i );
    FD_TEST( fd_bmtree_commit_append( tree, leaf, 1UL )==tree );
  }

  FD_TEST( fd_bmtree_commit_leaf_cnt( tree )==leaf_cnt );

  uchar * root = fd_bmtree_commit_fini( tree ); FD_TEST( !!root );

  FD_TEST( fd_bmtree_commit_leaf_cnt( tree )==leaf_cnt );

  if( FD_UNLIKELY( memcmp( root, expected_root, 20UL ) ) )
    FD_LOG_ERR(( "FAIL (leaf_cnt %lu)"
                 "\n\tGot"
                 "\n\t\t" FD_LOG_HEX20_FMT
                 "\n\tExpected"
                 "\n\t\t" FD_LOG_HEX20_FMT,
                 leaf_cnt, FD_LOG_HEX20_FMT_ARGS( root ), FD_LOG_HEX20_FMT_ARGS( expected_root ) ));
}
static void
test_bmtree20_commitp( ulong        leaf_cnt,
                       void const * expected_root ) {
  FD_TEST( fd_bmtree_commit_footprint( fd_bmtree_depth( leaf_cnt ) ) < MEMORY_SZ ); /* Otherwise increase MEMORY_SZ */
  fd_bmtree_commit_t * tree = fd_bmtree_commit_init( memory, 20UL, 1UL, fd_bmtree_depth( leaf_cnt ) );
  FD_TEST( tree );

  FD_LOG_NOTICE(( "leaf_cnt %lu", leaf_cnt ));

  /* Iterate over evens */
  fd_bmtree_node_t leaf[1];
  fd_memset( leaf->hash, 0, 20UL );
  for( ulong i=0UL; i<leaf_cnt; i += 2UL ) {
    FD_STORE( ulong, leaf->hash, i );
    FD_TEST( fd_bmtree_commitp_insert_with_proof( tree, i, leaf, NULL, 0, NULL ) );
  }
  /* Then insert the odds */
  for( ulong i=1UL; i<leaf_cnt; i += 2UL ) {
    FD_STORE( ulong, leaf->hash, i );
    FD_TEST( fd_bmtree_commitp_insert_with_proof( tree, i, leaf, NULL, 0, NULL ) );
  }

  uchar * root = fd_bmtree_commitp_fini( tree, leaf_cnt );
  FD_TEST( root );
  FD_TEST( fd_memeq( root, expected_root, 20UL ) );
}


static void
hash_leaf( fd_bmtree_node_t * leaf,
           char const *       leaf_cstr ) {
  FD_TEST( fd_bmtree_hash_leaf( leaf, leaf_cstr, strlen( leaf_cstr ), 1UL )==leaf );
}


static void
test_inclusion( ulong leaf_cnt ) {
  ulong const prefix_sz = FD_BMTREE_LONG_PREFIX_SZ;
  FD_TEST( 9 >= fd_bmtree_depth( leaf_cnt ) );
  ulong footprint = fd_bmtree_commit_footprint( 9UL );
  fd_bmtree_commit_t * tree = fd_bmtree_commit_init( memory, 20UL, prefix_sz, 9UL );
  uchar * _memory = (uchar*)fd_ulong_align_up( (ulong)(memory+footprint), FD_BMTREE_COMMIT_ALIGN );
  fd_bmtree_commit_t * ptree = fd_bmtree_commit_init( _memory, 20UL, prefix_sz, 9UL );

  fd_bmtree_node_t leaf[1];
  fd_memset( leaf->hash, 0, 20UL );
  for( ulong i=0UL; i<leaf_cnt; i++ ) {
    FD_TEST( fd_bmtree_commit_leaf_cnt( tree )==i );
    FD_STORE( ulong, leaf->hash, i );
    FD_TEST( fd_bmtree_commit_append( tree, leaf, 1UL )==tree );
  }
  uchar * root = fd_bmtree_commit_fini( tree );

  fd_bmtree_node_t proof_root[1];
  fd_bmtree_node_t root2[1];

  ulong depth = fd_bmtree_depth( leaf_cnt );
  for( ulong i=0UL; i<leaf_cnt; i++ ) {
    FD_STORE( ulong, leaf->hash, i );
    FD_TEST( (int)depth-1==fd_bmtree_get_proof( tree, inc_proof, i ) );
    FD_TEST( proof_root==fd_bmtree_from_proof( leaf, i, proof_root, inc_proof, depth-1UL, 20UL, prefix_sz ) );
    FD_TEST( fd_memeq( root, proof_root, 32UL ) );
    FD_TEST( fd_bmtree_commitp_insert_with_proof( ptree, i, leaf, inc_proof, depth-1, root2 ) );
    FD_TEST( fd_memeq( root, root2, 32UL ) );

    if( FD_LIKELY( leaf_cnt>1UL ) ) {
      inc_proof[ 1 ]++; /* Corrupt the proof */
      FD_TEST( proof_root==fd_bmtree_from_proof( leaf, i, proof_root, inc_proof, depth-1UL, 20UL, prefix_sz ) );
      FD_TEST( !fd_memeq( root, proof_root, 32UL ) );
      FD_TEST( !fd_bmtree_commitp_insert_with_proof( ptree, i, leaf, inc_proof, depth-1, NULL ) );
      inc_proof[ 1 ]--;
    } /* Otherwise the proof is empty, so there's nothing to corrupt */

    root[ 1 ]++; /* Corrupt the root */
    FD_TEST( proof_root==fd_bmtree_from_proof( leaf, i, proof_root, inc_proof, depth-1UL, 20UL, prefix_sz ) );
    FD_TEST( !fd_memeq( root, proof_root, 32UL ) );
    root[ 1 ]--;

    leaf->hash[ 1 ]++; /* Corrupt the leaf */
    FD_TEST( proof_root==fd_bmtree_from_proof( leaf, i, proof_root, inc_proof, depth-1UL, 20UL, prefix_sz ) );
    FD_TEST( !fd_memeq( root, proof_root, 32UL ) );
    FD_TEST( !fd_bmtree_commitp_insert_with_proof( ptree, i, leaf, inc_proof, depth-1, NULL ) );
    leaf->hash[ 1 ]--;
  }
  uchar * root3 = fd_bmtree_commitp_fini( ptree, leaf_cnt );
  FD_TEST( root3 );
  FD_TEST( fd_memeq( root, root3, 32UL ) );
  FD_TEST( !fd_bmtree_from_proof( leaf, 1234567UL, proof_root, inc_proof, depth-1UL, 20UL, prefix_sz ) );

}



int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  /* Internal checks */
  FD_TEST( fd_bmtree_commit_align()         ==FD_BMTREE_COMMIT_ALIGN            );
  FD_TEST( fd_bmtree_commit_footprint( 0UL )==FD_BMTREE_COMMIT_FOOTPRINT( 0UL ) );

  /* Iterate test fd_bmtree_depth, fd_bmtree_node_cnt against naive
     division algorithm */

  FD_TEST( fd_bmtree_depth(    0UL )==0UL );
  FD_TEST( fd_bmtree_depth(    1UL )==1UL );
  FD_TEST( fd_bmtree_node_cnt( 0UL )==0UL );
  FD_TEST( fd_bmtree_node_cnt( 1UL )==1UL );

  for( ulong leaf_cnt=1UL; leaf_cnt<=256UL; leaf_cnt++ ) test_inclusion( leaf_cnt );

  for( ulong leaf_cnt=2UL; leaf_cnt<10000000UL; leaf_cnt++ ) {
    ulong depth = 1UL;
    ulong nodes = 1UL;
    for( ulong i=leaf_cnt; i>1UL; i=(i+1UL) >> 1 ) { depth++; nodes += i; }
    FD_TEST( fd_bmtree_depth(    leaf_cnt )==depth );
    FD_TEST( fd_bmtree_node_cnt( leaf_cnt )==nodes );
  }


  /* Test 20-byte tree */

  /* Construct trees of different sizes. */
  test_bmtree20_commit (       1UL, "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" );
  test_bmtree20_commit (       2UL, "\x08\x11\x80\xe2\x59\x04\xa6\x23\xe5\x5c\x4a\x60\xc7\xfe\xd6\x7e\xe3\xd6\x7c\x4c" );
  test_bmtree20_commit (       3UL, "\x22\x50\xc2\x9d\x86\x90\xfa\x5c\x03\x94\x75\x17\x6d\x99\x06\xde\x2c\xc6\x0e\x79" );
  test_bmtree20_commit (      10UL, "\x42\x69\x92\xf5\x19\xee\x7e\x7b\xc2\xb6\x77\x6d\xc7\x82\x2d\x42\x68\x6a\xde\x25" );
  test_bmtree20_commit ( 1000000UL, "\x20\x61\x9a\x7a\xe4\x65\x27\x5a\x70\x9c\xa5\xc2\x8a\x21\x91\x6c\xdf\xf9\x0e\x26" ); /* TODO verify */
  test_bmtree20_commitp(       1UL, "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" );
  test_bmtree20_commitp(       2UL, "\x08\x11\x80\xe2\x59\x04\xa6\x23\xe5\x5c\x4a\x60\xc7\xfe\xd6\x7e\xe3\xd6\x7c\x4c" );
  test_bmtree20_commitp(       3UL, "\x22\x50\xc2\x9d\x86\x90\xfa\x5c\x03\x94\x75\x17\x6d\x99\x06\xde\x2c\xc6\x0e\x79" );
  test_bmtree20_commitp(      10UL, "\x42\x69\x92\xf5\x19\xee\x7e\x7b\xc2\xb6\x77\x6d\xc7\x82\x2d\x42\x68\x6a\xde\x25" );
  test_bmtree20_commitp( 1000000UL, "\x20\x61\x9a\x7a\xe4\x65\x27\x5a\x70\x9c\xa5\xc2\x8a\x21\x91\x6c\xdf\xf9\x0e\x26" ); /* TODO verify */

  /* FIXME: WRITE BETTER BENCHMARK */
  ulong bench_cnt = 1000000UL;
  long dt = -fd_log_wallclock();
  test_bmtree20_commit( bench_cnt, "\x20\x61\x9a\x7a\xe4\x65\x27\x5a\x70\x9c\xa5\xc2\x8a\x21\x91\x6c\xdf\xf9\x0e\x26" );
  dt += fd_log_wallclock();
  FD_LOG_NOTICE(( "%.3f ns/leaf @ %lu leaves", (double)((float)dt / (float)bench_cnt), bench_cnt ));

  /* Test 32-byte tree */

  // Source: https://github.com/solana-foundation/specs/blob/main/core/merkle-tree.md

  ulong leaf_cnt = 11UL;
  fd_bmtree_node_t leaf[ 11UL ];

  hash_leaf( leaf +  0, "my"     );
  hash_leaf( leaf +  1, "very"   );
  hash_leaf( leaf +  2, "eager"  );
  hash_leaf( leaf +  3, "mother" );
  hash_leaf( leaf +  4, "just"   );
  hash_leaf( leaf +  5, "served" );
  hash_leaf( leaf +  6, "us"     );
  hash_leaf( leaf +  7, "nine"   );
  hash_leaf( leaf +  8, "pizzas" );
  hash_leaf( leaf +  9, "make"   );
  hash_leaf( leaf + 10, "prime"  );

  fd_bmtree_commit_t _tree[1];
  fd_bmtree_commit_t * tree = fd_bmtree_commit_init( _tree, 32UL, 1UL, 0UL ); FD_TEST( tree==_tree );

  FD_TEST( fd_bmtree_commit_leaf_cnt( tree )==0UL );

  FD_TEST( fd_bmtree_commit_append( tree, leaf, leaf_cnt )==tree );

  FD_TEST( fd_bmtree_commit_leaf_cnt( tree )==leaf_cnt );

  uchar * root = fd_bmtree_commit_fini( tree );

  FD_TEST( fd_bmtree_commit_leaf_cnt( tree )==leaf_cnt );

# define _(v) ((uchar)0x##v)
  uchar const expected[FD_SHA256_HASH_SZ] = {
    _(b4),_(0c),_(84),_(75),_(46),_(fd),_(ce),_(ea),_(16),_(6f),_(92),_(7f),_(c4),_(6c),_(5c),_(a3),
    _(3c),_(36),_(38),_(23),_(6a),_(36),_(27),_(5c),_(13),_(46),_(d3),_(df),_(fb),_(84),_(e1),_(bc)
  };
# undef _

  if( FD_UNLIKELY( memcmp( root, expected, 32UL ) ) )
    FD_LOG_ERR(( "FAIL"
                 "\n\tGot"
                 "\n\t\t" FD_LOG_HEX16_FMT "  " FD_LOG_HEX16_FMT
                 "\n\tExpected"
                 "\n\t\t" FD_LOG_HEX16_FMT "  " FD_LOG_HEX16_FMT,
                 FD_LOG_HEX16_FMT_ARGS(     root ), FD_LOG_HEX16_FMT_ARGS(     root+16 ),
                 FD_LOG_HEX16_FMT_ARGS( expected ), FD_LOG_HEX16_FMT_ARGS( expected+16 ) ));


  tree = fd_bmtree_commit_init( memory, 20UL, 1UL, 5UL );
  FD_TEST( fd_bmtree_commit_append( tree, leaf, leaf_cnt )==tree );
  fd_bmtree_commit_fini( tree );

  for( ulong i=0UL; i<leaf_cnt; i++ ) {
    uchar proof[REFERENCE_PROOF_SZ];
    FD_TEST( 4UL==fd_bmtree_get_proof( tree, proof, i ) );

    FD_TEST( 0==memcmp( proof, reference_proofs + REFERENCE_PROOF_SZ*i, REFERENCE_PROOF_SZ ) );
  }

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}

