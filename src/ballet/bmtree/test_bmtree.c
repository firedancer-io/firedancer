#include "../fd_ballet.h"

FD_STATIC_ASSERT( FD_BMTREE20_HASH_SZ         ==  20UL, unit_test );
FD_STATIC_ASSERT( FD_BMTREE20_COMMIT_ALIGN    ==  32UL, unit_test );
FD_STATIC_ASSERT( FD_BMTREE20_COMMIT_FOOTPRINT==2048UL, unit_test );

FD_STATIC_ASSERT( FD_BMTREE32_HASH_SZ         ==  32UL, unit_test );
FD_STATIC_ASSERT( FD_BMTREE32_COMMIT_ALIGN    ==  32UL, unit_test );
FD_STATIC_ASSERT( FD_BMTREE32_COMMIT_FOOTPRINT==2048UL, unit_test );

FD_STATIC_ASSERT( FD_BMTREE20_COMMIT_ALIGN    ==alignof(fd_bmtree20_commit_t), unit_test );
FD_STATIC_ASSERT( FD_BMTREE20_COMMIT_FOOTPRINT==sizeof (fd_bmtree20_commit_t), unit_test );

FD_STATIC_ASSERT( FD_BMTREE32_COMMIT_ALIGN    ==alignof(fd_bmtree32_commit_t), unit_test );
FD_STATIC_ASSERT( FD_BMTREE32_COMMIT_FOOTPRINT==sizeof (fd_bmtree32_commit_t), unit_test );

/* Test tree-20 construction */

static void
test_bmtree20_commit( ulong        leaf_cnt,
                      void const * expected_root ) {
  fd_bmtree20_commit_t _tree[1];
  fd_bmtree20_commit_t * tree = fd_bmtree20_commit_init( _tree ); FD_TEST( tree==_tree );

  fd_bmtree20_node_t leaf[1];
  fd_memset( leaf->hash, 0, 20UL );
  for( ulong i=0UL; i<leaf_cnt; i++ ) {
    FD_TEST( fd_bmtree20_commit_leaf_cnt( tree )==i );
    FD_STORE( ulong, leaf->hash, i );
    FD_TEST( fd_bmtree20_commit_append( tree, leaf, 1UL )==tree );
  }

  FD_TEST( fd_bmtree20_commit_leaf_cnt( tree )==leaf_cnt );

  uchar * root = fd_bmtree20_commit_fini( tree ); FD_TEST( !!root );

  FD_TEST( fd_bmtree20_commit_leaf_cnt( tree )==leaf_cnt );

  if( FD_UNLIKELY( memcmp( root, expected_root, 20UL ) ) )
    FD_LOG_ERR(( "FAIL (leaf_cnt %lu)"
                 "\n\tGot"
                 "\n\t\t" FD_LOG_HEX20_FMT
                 "\n\tExpected"
                 "\n\t\t" FD_LOG_HEX20_FMT,
                 leaf_cnt, FD_LOG_HEX20_FMT_ARGS( root ), FD_LOG_HEX20_FMT_ARGS( expected_root ) ));
}

static void
hash_leaf( fd_bmtree32_node_t * leaf,
           char const *         leaf_cstr ) {
  FD_TEST( fd_bmtree32_hash_leaf( leaf, leaf_cstr, strlen( leaf_cstr ) )==leaf );
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  /* Internal checks */

  /* Iterate test fd_bmtree_depth against naive division algorithm */

  FD_TEST( fd_bmtree20_private_depth( 0UL )==0UL ); FD_TEST( fd_bmtree32_private_depth( 0UL )==0UL );
  FD_TEST( fd_bmtree20_private_depth( 1UL )==1UL ); FD_TEST( fd_bmtree32_private_depth( 1UL )==1UL );

  for( ulong node_cnt=2UL; node_cnt<10000000UL; node_cnt++ ) {
    ulong depth = 1UL;
    for( ulong i=node_cnt; i>1UL; i=(i+1UL) >> 1 ) depth++;
    FD_TEST( fd_bmtree20_private_depth( node_cnt )==depth ); FD_TEST( fd_bmtree32_private_depth( node_cnt )==depth );
  }

  /* Test 20-byte tree */

  FD_TEST( fd_bmtree20_commit_align()    ==FD_BMTREE20_COMMIT_ALIGN     );
  FD_TEST( fd_bmtree20_commit_footprint()==FD_BMTREE20_COMMIT_FOOTPRINT );

  /* Construct trees of different sizes. */
  test_bmtree20_commit(       1UL, "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" );
  test_bmtree20_commit(       2UL, "\x08\x11\x80\xe2\x59\x04\xa6\x23\xe5\x5c\x4a\x60\xc7\xfe\xd6\x7e\xe3\xd6\x7c\x4c" );
  test_bmtree20_commit(       3UL, "\x22\x50\xc2\x9d\x86\x90\xfa\x5c\x03\x94\x75\x17\x6d\x99\x06\xde\x2c\xc6\x0e\x79" );
  test_bmtree20_commit(      10UL, "\x42\x69\x92\xf5\x19\xee\x7e\x7b\xc2\xb6\x77\x6d\xc7\x82\x2d\x42\x68\x6a\xde\x25" );
  test_bmtree20_commit( 1000000UL, "\x20\x61\x9a\x7a\xe4\x65\x27\x5a\x70\x9c\xa5\xc2\x8a\x21\x91\x6c\xdf\xf9\x0e\x26" ); /* TODO verify */

  /* FIXME: WRITE BETTER BENCHMARK */
  ulong bench_cnt = 1000000UL;
  long dt = -fd_log_wallclock();
  test_bmtree20_commit( bench_cnt, "\x20\x61\x9a\x7a\xe4\x65\x27\x5a\x70\x9c\xa5\xc2\x8a\x21\x91\x6c\xdf\xf9\x0e\x26" );
  dt += fd_log_wallclock();
  FD_LOG_NOTICE(( "%.3f ns/leaf @ %lu leaves", (double)((float)dt / (float)bench_cnt), bench_cnt ));

  /* Test 32-byte tree */

  // Source: https://github.com/solana-foundation/specs/blob/main/core/merkle-tree.md

  ulong leaf_cnt = 11UL;
  fd_bmtree32_node_t leaf[ 11UL ];

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

  FD_TEST( fd_bmtree32_commit_align()    ==FD_BMTREE32_COMMIT_ALIGN     );
  FD_TEST( fd_bmtree32_commit_footprint()==FD_BMTREE32_COMMIT_FOOTPRINT );

  fd_bmtree32_commit_t _tree[1];
  fd_bmtree32_commit_t * tree = fd_bmtree32_commit_init( _tree ); FD_TEST( tree==_tree );

  FD_TEST( fd_bmtree32_commit_leaf_cnt( tree )==0UL );

  FD_TEST( fd_bmtree32_commit_append( tree, leaf, leaf_cnt )==tree );

  FD_TEST( fd_bmtree32_commit_leaf_cnt( tree )==leaf_cnt );

  uchar * root = fd_bmtree32_commit_fini( tree );

  FD_TEST( fd_bmtree32_commit_leaf_cnt( tree )==leaf_cnt );

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

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}

