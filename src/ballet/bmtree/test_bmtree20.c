#include "../fd_ballet.h"

FD_STATIC_ASSERT( alignof(fd_bmtree20_node_t)==1UL, alignment );

/* Convience macros for pretty-printing hex strings of 20 chars. */
#define FD_LOG_HEX20_FMT "%02x%02x%02x%02x %02x%02x%02x%02x %02x%02x%02x%02x %02x%02x%02x%02x %02x%02x%02x%02x"
#define FD_LOG_HEX20_FMT_ARGS(b)                                      \
  (uint)(((uchar const *)(b))[ 0]), (uint)(((uchar const *)(b))[ 1]), \
  (uint)(((uchar const *)(b))[ 2]), (uint)(((uchar const *)(b))[ 3]), \
  (uint)(((uchar const *)(b))[ 4]), (uint)(((uchar const *)(b))[ 5]), \
  (uint)(((uchar const *)(b))[ 6]), (uint)(((uchar const *)(b))[ 7]), \
  (uint)(((uchar const *)(b))[ 8]), (uint)(((uchar const *)(b))[ 9]), \
  (uint)(((uchar const *)(b))[10]), (uint)(((uchar const *)(b))[11]), \
  (uint)(((uchar const *)(b))[12]), (uint)(((uchar const *)(b))[13]), \
  (uint)(((uchar const *)(b))[14]), (uint)(((uchar const *)(b))[15]), \
  (uint)(((uchar const *)(b))[16]), (uint)(((uchar const *)(b))[17]), \
  (uint)(((uchar const *)(b))[18]), (uint)(((uchar const *)(b))[19])

/* Test tree construction */
static void
test_bmtree20_commit( ulong        leaf_cnt,
                       char const * expected_root ) {
  fd_bmtree20_commit_t * tree = fd_alloca( alignof(fd_bmtree20_commit_t), fd_bmtree20_commit_footprint( leaf_cnt ) );
  fd_bmtree20_commit_init( tree, leaf_cnt );

  for( ulong i=0; i<leaf_cnt; i++ ) {
    fd_bmtree20_node_t leaf = { 0 };
    *(ulong *) leaf = i;
    fd_bmtree20_commit_append( tree, (fd_bmtree20_node_t const *)&leaf, 1UL );
  }

  fd_bmtree20_node_t * root = fd_bmtree20_commit_fini( tree );
  FD_TEST( root!=NULL );

  if( FD_UNLIKELY( memcmp( root, expected_root, sizeof(fd_bmtree20_node_t) ) ) )
    FD_LOG_ERR(( "FAIL (leaf_cnt %lu)"
                 "\n\tGot"
                 "\n\t\t" FD_LOG_HEX20_FMT
                 "\n\tExpected"
                 "\n\t\t" FD_LOG_HEX20_FMT,
                 leaf_cnt, FD_LOG_HEX20_FMT_ARGS( root ), FD_LOG_HEX20_FMT_ARGS( expected_root ) ));
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  /* Sanity check fd_bmtree_depth */
  FD_TEST( fd_bmtree_depth( 0UL )==0UL );
  FD_TEST( fd_bmtree_depth( 1UL )==1UL );
  FD_TEST( fd_bmtree_depth( 2UL )==2UL );
  FD_TEST( fd_bmtree_depth( 3UL )==3UL );
  FD_TEST( fd_bmtree_depth( 4UL )==3UL );
  FD_TEST( fd_bmtree_depth( 5UL )==4UL );
  FD_TEST( fd_bmtree_depth( 6UL )==4UL );
  FD_TEST( fd_bmtree_depth( 7UL )==4UL );
  FD_TEST( fd_bmtree_depth( 8UL )==4UL );
  FD_TEST( fd_bmtree_depth( 9UL )==5UL );

  /* Iterate test fd_bmtree_depth against naive division algorithm */
  for( ulong node_cnt=2UL; node_cnt<10000000UL; node_cnt++ ) {
    ulong layers = 1;
    for( ulong i=node_cnt; i>1; i=(i+1)/2 ) {
      layers++;
    }
    FD_TEST( fd_bmtree_depth( node_cnt )==layers );
  }

  /* Construct trees of different sizes. */
  test_bmtree20_commit(       1UL, "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" );
  test_bmtree20_commit(       2UL, "\x08\x11\x80\xe2\x59\x04\xa6\x23\xe5\x5c\x4a\x60\xc7\xfe\xd6\x7e\xe3\xd6\x7c\x4c" );
  test_bmtree20_commit(       3UL, "\x22\x50\xc2\x9d\x86\x90\xfa\x5c\x03\x94\x75\x17\x6d\x99\x06\xde\x2c\xc6\x0e\x79" );
  test_bmtree20_commit(      10UL, "\x42\x69\x92\xf5\x19\xee\x7e\x7b\xc2\xb6\x77\x6d\xc7\x82\x2d\x42\x68\x6a\xde\x25" );
  test_bmtree20_commit( 1000000UL, "\x20\x61\x9a\x7a\xe4\x65\x27\x5a\x70\x9c\xa5\xc2\x8a\x21\x91\x6c\xdf\xf9\x0e\x26" ); /* TODO verify */

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
