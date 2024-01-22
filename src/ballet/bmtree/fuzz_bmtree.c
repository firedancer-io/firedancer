#if !FD_HAS_HOSTED
#error "This target requires FD_HAS_HOSTED"
#endif

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>

#include "../../util/fd_util.h"
#include "../../util/sanitize/fd_fuzz.h"
#include "fd_bmtree.h"

#define MAX_LEAF_CNT (256UL)
#define MAX_DEPTH (9UL)
#define MEMORY_SZ (70UL*1024UL*1024UL)

uchar * memory1;
uchar * memory2;
uchar *inc_proof;

void fuzz_exit( void ) {
  free( inc_proof ); 
  free( memory2 );
  free( memory1 );
  fd_halt();
}

int
LLVMFuzzerInitialize( int  *   argc,
                      char *** argv ) {
  /* Set up shell without signal handlers */
  putenv( "FD_LOG_BACKTRACE=0" );
  fd_boot( argc, argv );
  assert( !posix_memalign( (void **) &memory1, FD_BMTREE_COMMIT_ALIGN, MEMORY_SZ ) );
  assert( !posix_memalign( (void **) &memory2, FD_BMTREE_COMMIT_ALIGN, MEMORY_SZ ) );
  assert( inc_proof = malloc( 32UL * ( MAX_DEPTH - 1UL ) ));
  atexit( fuzz_exit );
  return 0;
}

static int
fuzz_bmtree( fd_bmtree_node_t const * leafs,
             ulong leaf_cnt,
             ulong hash_sz,
             ulong prefix_sz ) {

  /* figure out the footprint needed given the leaf_cnt */
  ulong depth = fd_bmtree_depth( leaf_cnt );

  if( FD_UNLIKELY( depth > MAX_DEPTH ) ) return -1;
  ulong footprint = fd_bmtree_commit_footprint( depth );

  /* check that we have enough memory, check for overflows along the way */
  uchar * memory_start = memory1;
  uchar * first_tree_end = memory_start+footprint;
  if( FD_UNLIKELY( first_tree_end<memory_start || (ulong)first_tree_end<footprint ) ) {
    return -1;
  }

  uchar * second_tree_start = (uchar *)fd_ulong_align_up( (ulong)first_tree_end, FD_BMTREE_COMMIT_ALIGN );
  if( FD_UNLIKELY( second_tree_start<first_tree_end ) ) {
    printf("FD_UNLIKELY( second_tree_start<first_tree_end )\n");
    return -1;
  }
  
  uchar * memory_end = second_tree_start+footprint;
  if( FD_UNLIKELY( memory_end<second_tree_start || (ulong)memory_end<footprint ) ) {
    printf("FD_UNLIKELY( memory_end<second_tree_start || memory_end<footprint )\n");
    return -1;
  }

  ulong memory_required = (ulong) (memory_end - memory_start);
  if( FD_UNLIKELY( memory_required > MEMORY_SZ ) ) {
    printf("FD_UNLIKELY( memory_required < MEMORY_SZ )\n");
    printf("%d < %d\n", memory_required, MEMORY_SZ);
    return -1;
  }

  /* create first tree from leafs */
  fd_bmtree_commit_t * tree = fd_bmtree_commit_init( memory1, hash_sz, prefix_sz, 0UL );
  assert( tree );

  /* no leaf has been appended thus far */
  assert( 0UL == fd_bmtree_commit_leaf_cnt( tree ) );

  /* append all leafs */
  assert( tree == fd_bmtree_commit_append( tree, leafs, leaf_cnt ) );

  /* tree has the expected amount of leafs */
  assert( leaf_cnt == fd_bmtree_commit_leaf_cnt( tree ) );

  /* commmit to the tree */
  uchar * root_1 = fd_bmtree_commit_fini( tree );
  assert( root_1 );

  assert( leaf_cnt == fd_bmtree_commit_leaf_cnt( tree ) );

  /* create second tree from proofs */
  fd_bmtree_commit_t * tree2 = fd_bmtree_commit_init( memory2, hash_sz, prefix_sz, depth );
  assert( tree2 );

  fd_bmtree_node_t proof_root_1[1];
  fd_bmtree_node_t proof_root_2[1];
  fd_bmtree_node_t leaf[1];

  for( ulong i=0UL; i<leaf_cnt; i++ ) {
    fd_memcpy( leaf, leafs+i, sizeof( fd_bmtree_node_t ) );

    int res = fd_bmtree_get_proof( tree, inc_proof, i );
    if ( res == -1 ) {
      FD_FUZZ_MUST_BE_COVERED;
      return 0;
    }
 
    assert( proof_root_1 == fd_bmtree_from_proof( leaf, i, proof_root_1, inc_proof, depth-1UL, hash_sz, prefix_sz ) );

    assert( fd_memeq( root_1, proof_root_1, hash_sz ) );

    assert( fd_bmtree_commitp_insert_with_proof( tree2, i, leaf, inc_proof, depth-1UL, proof_root_2 ) );

    assert( fd_memeq( root_1, proof_root_2, hash_sz ) );

    if( FD_LIKELY( leaf_cnt>1UL ) ) {
      FD_FUZZ_MUST_BE_COVERED;
      inc_proof[ 1 ]++; /* Corrupt the proof */
      assert( proof_root_1 == fd_bmtree_from_proof( leaf, i, proof_root_1, inc_proof, depth-1UL, hash_sz, prefix_sz ) );

      assert( !fd_memeq( root_1, proof_root_1, hash_sz ) );

      assert( !fd_bmtree_commitp_insert_with_proof( tree2, i, leaf, inc_proof, depth-1UL, NULL ) );

      inc_proof[ 1 ]--;
    } /* Otherwise the proof is empty, so there's nothing to corrupt */

    root_1[ 1 ]++; /* Corrupt the root */
    assert( proof_root_1 == fd_bmtree_from_proof( leaf, i, proof_root_1, inc_proof, depth-1UL, hash_sz, prefix_sz ) );

    assert( !fd_memeq( root_1, proof_root_1, hash_sz ) );

    root_1[ 1 ]--;

    leaf->hash[ 1 ]++; /* Corrupt the leaf */
    assert( proof_root_1 == fd_bmtree_from_proof( leaf, i, proof_root_1, inc_proof, depth-1UL, hash_sz, prefix_sz ) );

    assert( !fd_memeq( root_1, proof_root_1, hash_sz ) );

    assert( !fd_bmtree_commitp_insert_with_proof( tree2, i, leaf, inc_proof, depth-1UL, NULL ) );

    leaf->hash[ 1 ]--;
  }
  uchar * root_2 = fd_bmtree_commitp_fini( tree2, leaf_cnt );
  assert( root_2 );

  assert( fd_memeq( root_1, root_2, hash_sz ) );

  return 0;
}

struct bmtree_test {
  ulong leaf_cnt;
  uchar leaf_hashes[ ];
};
typedef struct bmtree_test bmtree_test_t;

int
LLVMFuzzerTestOneInput( uchar const * data,
                        ulong         size ) {
  if( FD_UNLIKELY( size<sizeof( bmtree_test_t ) ) ) return -1;
  bmtree_test_t * const test = ( bmtree_test_t * const ) data;
  ulong leaf_cnt = test->leaf_cnt % MAX_LEAF_CNT + 1UL;

  if( FD_UNLIKELY( size<sizeof( bmtree_test_t )+leaf_cnt*sizeof( fd_bmtree_node_t ) ) ) return -1;
  fd_bmtree_node_t const * leafs = ( fd_bmtree_node_t const * ) test->leaf_hashes;

  int result = fuzz_bmtree( leafs, leaf_cnt, 32UL, FD_BMTREE_SHORT_PREFIX_SZ );
  if ( result != 0 ) {
    return result;
  }

  result = fuzz_bmtree( leafs, leaf_cnt, 20UL, FD_BMTREE_LONG_PREFIX_SZ );

  FD_FUZZ_MUST_BE_COVERED;
  return result;
}
