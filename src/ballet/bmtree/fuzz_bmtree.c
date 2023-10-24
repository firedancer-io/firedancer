#if !FD_HAS_HOSTED
#error "This target requires FD_HAS_HOSTED"
#endif

#include <stdio.h>
#include <stdlib.h>

#include "../../util/fd_util.h"
#include "fd_bmtree.h"

int
LLVMFuzzerInitialize( int  *   argc,
                      char *** argv ) {
  /* Set up shell without signal handlers */
  putenv( "FD_LOG_BACKTRACE=0" );
  fd_boot( argc, argv );
  atexit( fd_halt );
  return 0;
}

#define MAX_LEAF_CNT (256UL)
#define MAX_DEPTH (9UL)
#define MEMORY_SZ (70UL*1024UL*1024UL)
uchar memory[ MEMORY_SZ ] __attribute__((aligned(FD_BMTREE_COMMIT_ALIGN)));
uchar inc_proof[ 32UL*( MAX_DEPTH-1UL ) ];

static int
fuzz_bmtree( fd_bmtree_node_t const * leafs,
             ulong leaf_cnt,
             ulong hash_sz,
             ulong prefix_sz ) {
  ulong depth = fd_bmtree_depth( leaf_cnt );
  if( FD_UNLIKELY( depth > MAX_DEPTH ) ) return -1;
  ulong footprint = fd_bmtree_commit_footprint( depth );

  /* check that we have enough memory, check for overflows alogn the way */
  ulong memory_start = ( ulong ) memory;
  ulong first_tree_end = memory_start+footprint;
  if( FD_UNLIKELY( first_tree_end<memory_start || first_tree_end<footprint ) ) return -1;
  ulong second_tree_start = fd_ulong_align_up( first_tree_end, FD_BMTREE_COMMIT_ALIGN );
  if( FD_UNLIKELY( second_tree_start<first_tree_end ) ) return -1;
  ulong memory_end = second_tree_start+footprint;
  if( FD_UNLIKELY( memory_end<second_tree_start || memory_end<footprint ) ) return -1;
  ulong memory_required = memory_end - memory_start;
  if( FD_UNLIKELY( memory_required < MEMORY_SZ ) ) return -1;

  /* create first tree from leafs */
  fd_bmtree_commit_t * tree = fd_bmtree_commit_init( memory, hash_sz, prefix_sz, 0UL );
  if( FD_UNLIKELY( tree==NULL ) ) {
    __builtin_trap();
  }

  if( FD_UNLIKELY( fd_bmtree_commit_leaf_cnt( tree )!=0UL ) ) {
    __builtin_trap();
  }

  if( FD_UNLIKELY( fd_bmtree_commit_append( tree, leafs, leaf_cnt )!=tree ) ) {
    __builtin_trap();
  }

  if( FD_UNLIKELY( fd_bmtree_commit_leaf_cnt( tree )!=leaf_cnt ) ) {
    __builtin_trap();
  }

  uchar * root_1 = fd_bmtree_commit_fini( tree );
  if( FD_UNLIKELY( root_1==NULL ) ) {
    __builtin_trap();
  }

  if( FD_UNLIKELY( fd_bmtree_commit_leaf_cnt( tree )!=leaf_cnt ) ) {
    __builtin_trap();
  }

  /* create second tree from proofs */
  fd_bmtree_commit_t * ptree = fd_bmtree_commit_init( memory, hash_sz, prefix_sz, depth );
  if( FD_UNLIKELY( ptree==NULL ) ) {
    __builtin_trap();
  }
  fd_bmtree_node_t proof_root_1[1];
  fd_bmtree_node_t proof_root_2[1];
  fd_bmtree_node_t leaf[1];

  for( ulong i=0UL; i<leaf_cnt; i++ ) {
    fd_memcpy( leaf, leafs+i, leaf_cnt*sizeof( fd_bmtree_node_t ) );

    if( FD_UNLIKELY( (int)depth-1!=fd_bmtree_get_proof( tree, inc_proof, i ) ) ) {
      __builtin_trap();
    }
    if( FD_UNLIKELY( proof_root_1!=fd_bmtree_from_proof( leaf, i, proof_root_1, inc_proof, depth-1UL, hash_sz, prefix_sz ) ) ) {
      __builtin_trap();
    }
    if( FD_UNLIKELY( !fd_memeq( root_1, proof_root_1, hash_sz ) ) ) {
      __builtin_trap();
    }
    if( FD_UNLIKELY( !fd_bmtree_commitp_insert_with_proof( ptree, i, leaf, inc_proof, depth-1UL, proof_root_2 ) ) ) {
      __builtin_trap();
    }
    if( FD_UNLIKELY( !fd_memeq( root_1, proof_root_2, hash_sz ) ) ) {
      __builtin_trap();
    }

    if( FD_LIKELY( leaf_cnt>1UL ) ) {
      inc_proof[ 1 ]++; /* Corrupt the proof */
      if( FD_UNLIKELY( proof_root_1!=fd_bmtree_from_proof( leaf, i, proof_root_1, inc_proof, depth-1UL, hash_sz, prefix_sz ) ) ) {
        __builtin_trap();
      }
      if( FD_UNLIKELY( fd_memeq( root_1, proof_root_1, hash_sz ) ) ) {
        __builtin_trap();
      }
      if( FD_UNLIKELY( fd_bmtree_commitp_insert_with_proof( ptree, i, leaf, inc_proof, depth-1UL, NULL ) ) ) {
        __builtin_trap();
      }
      inc_proof[ 1 ]--;
    } /* Otherwise the proof is empty, so there's nothing to corrupt */

    root_1[ 1 ]++; /* Corrupt the root */
    if( FD_UNLIKELY( proof_root_1!=fd_bmtree_from_proof( leaf, i, proof_root_1, inc_proof, depth-1UL, hash_sz, prefix_sz ) ) ) {
      __builtin_trap();
    }
    if( FD_UNLIKELY( fd_memeq( root_1, proof_root_1, hash_sz ) ) ) {
      __builtin_trap();
    }
    root_1[ 1 ]--;

    leaf->hash[ 1 ]++; /* Corrupt the leaf */
    if( FD_UNLIKELY( proof_root_1!=fd_bmtree_from_proof( leaf, i, proof_root_1, inc_proof, depth-1UL, hash_sz, prefix_sz ) ) ) {
      __builtin_trap();
    }
    if( FD_UNLIKELY( fd_memeq( root_1, proof_root_1, hash_sz ) ) ) {
      __builtin_trap();
    }
    if( FD_UNLIKELY( fd_bmtree_commitp_insert_with_proof( ptree, i, leaf, inc_proof, depth-1UL, NULL ) ) ) {
      __builtin_trap();
    }
    leaf->hash[ 1 ]--;
  }
  uchar * root_2 = fd_bmtree_commitp_fini( ptree, leaf_cnt );
  if( FD_UNLIKELY( root_2==NULL ) ) {
    __builtin_trap();
  }
  if( FD_UNLIKELY( fd_memeq( root_1, root_2, hash_sz ) ) ) {
    __builtin_trap();
  }

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
  if( FD_UNLIKELY( size<sizeof( bmtree_test_t ) ) ) return 0;
  bmtree_test_t * const test = ( bmtree_test_t * const ) data;
  ulong leaf_cnt = test->leaf_cnt % MAX_LEAF_CNT + 1UL;

  if( FD_UNLIKELY( size<sizeof( bmtree_test_t )+leaf_cnt*sizeof( fd_bmtree_node_t ) ) ) return 0;
  fd_bmtree_node_t const * leafs = ( fd_bmtree_node_t const * ) test->leaf_hashes;

  int result = fuzz_bmtree( leafs, leaf_cnt, 32UL, FD_BMTREE_SHORT_PREFIX_SZ );
  if( FD_UNLIKELY( result==-1 ) ) return -1;

  result = fuzz_bmtree( leafs, leaf_cnt, 20UL, FD_BMTREE_LONG_PREFIX_SZ );
  if( FD_UNLIKELY( result==-1 ) ) return -1;

  return 0;
}
