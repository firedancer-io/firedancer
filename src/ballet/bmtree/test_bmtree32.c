#include "../fd_ballet.h"

FD_STATIC_ASSERT( FD_BMTREE32_NODE_SZ==FD_SHA256_HASH_SZ, alignment );

FD_STATIC_ASSERT( alignof(fd_bmtree32_node_t)==1UL, alignment );

static inline void
hash_leaf( fd_bmtree32_node_t leaf,
           char *             leaf_cstr ) {
  fd_bmtree32_hash_leaf( leaf, leaf_cstr, strlen( leaf_cstr ) );
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  // Source: https://github.com/solana-foundation/specs/blob/main/core/merkle-tree.md

  ulong leaf_cnt = 11UL;
  fd_bmtree32_node_t leaves[leaf_cnt];
  hash_leaf( leaves[ 0], "my"     );
  hash_leaf( leaves[ 1], "very"   );
  hash_leaf( leaves[ 2], "eager"  );
  hash_leaf( leaves[ 3], "mother" );
  hash_leaf( leaves[ 4], "just"   );
  hash_leaf( leaves[ 5], "served" );
  hash_leaf( leaves[ 6], "us"     );
  hash_leaf( leaves[ 7], "nine"   );
  hash_leaf( leaves[ 8], "pizzas" );
  hash_leaf( leaves[ 9], "make"   );
  hash_leaf( leaves[10], "prime"  );

  fd_bmtree32_commit_t * commit = fd_alloca( 32, fd_bmtree32_commit_footprint( leaf_cnt ) );

  fd_bmtree32_commit_init( commit, leaf_cnt );

  fd_bmtree32_commit_append( commit,
                              (fd_bmtree32_node_t const *)leaves,
                              leaf_cnt );

  uchar * root = (uchar *)fd_bmtree32_commit_fini( commit );

# define _(v) ((uchar)0x##v)
  uchar const expected[FD_SHA256_HASH_SZ] = {
    _(b4),_(0c),_(84),_(75),_(46),_(fd),_(ce),_(ea),_(16),_(6f),_(92),_(7f),_(c4),_(6c),_(5c),_(a3),
    _(3c),_(36),_(38),_(23),_(6a),_(36),_(27),_(5c),_(13),_(46),_(d3),_(df),_(fb),_(84),_(e1),_(bc)
  };
# undef _

  if( FD_UNLIKELY( memcmp( root, expected, FD_SHA256_HASH_SZ ) ) )
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
