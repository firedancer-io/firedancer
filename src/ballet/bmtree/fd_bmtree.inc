#include "fd_bmtree.h"

#define BMTREE_(x)     FD_EXPAND_THEN_CONCAT4(fd_bmtree,BMTREE_VARIANT,_,x)
#define BMTREEU_(x)    FD_EXPAND_THEN_CONCAT4(FD_BMTREE,BMTREE_VARIANT,_,x)
#define BMTREE_NODE    BMTREE_(node_t)
#define BMTREE_COMMIT  BMTREE_(commit_t)
#define BMTREE_NODE_SZ BMTREEU_(NODE_SZ)

FD_STATIC_ASSERT( sizeof(BMTREE_NODE)==BMTREE_NODE_SZ, BMTREE_NODE_SZ );

void
BMTREE_(commit_init)( BMTREE_COMMIT * state,
                      ulong           leaf_cnt ) {
  state->leaf_idx = 0UL;
  state->leaf_cnt = leaf_cnt;
}

/* fd_bmtree*_merge: Derives a single branch node.

   Computes `SHA-256([0x01] | A | B)` and writes the result into out.
   Arbitrary pointer aliasing between out, A, B is permitted. */
static void
BMTREE_(merge)( BMTREE_NODE       * out,
                BMTREE_NODE const * A,
                BMTREE_NODE const * B ) {
  fd_sha256_t sha;
  fd_sha256_init( &sha );

  /* Prepend static one-byte prefix identifying a branch node. */
  uchar const prefix[1] = { FD_BMTREE_PREFIX_BRANCH };
  fd_sha256_append( &sha, &prefix, 1UL );
  /* Write tree nodes. */
  fd_sha256_append( &sha, A, sizeof(BMTREE_NODE) );
  fd_sha256_append( &sha, B, sizeof(BMTREE_NODE) );

  /* Write 32-byte hash result into temporary buffer. */
  uchar hash[FD_SHA256_HASH_SZ] __attribute__((aligned(FD_SHA256_ALIGN)));
  fd_sha256_fini( &sha, hash );

  /* Write tree node into out, discarding last few bytes. */
  fd_memcpy( out, hash, sizeof(BMTREE_NODE) );
}

/* fd_bmtree*_commit_insert: Accumulates a single leaf node into the tree.

   Updates `state->leaf_idx++`.
   U.B. if `state->leaf_idx` >= `state->leaf_cnt`.

   Maintains the invariant that the left node of the last node pair
   for each layer is copied to `state->node_buf`.

   This serves to allow the algorithm to derive a new parent branch node
   for any pair of children, once the (previously missing) right node
   becomes available. */
static void
BMTREE_(commit_insert)( BMTREE_COMMIT *     state,
                        BMTREE_NODE const * leaf ) {
  BMTREE_NODE tmp;
  fd_memcpy( &tmp, leaf, sizeof(tmp) );

  /* Walk the tree upwards from the bottom layer.

     `tmp` contains a previously missing right node
     which is used to derive a branch node,
     together with the previously buffered value in `node_buf`.

     Each iteration, merges that pair of nodes into a new branch node.
     Terminates if the new branch node is the left node of a pair. */

  ulong layer, cursor;
  for(
    /* `layer` starts at 0 (leaf nodes) and increments each iteration.
       `cursor` is the number of known nodes in the current layer. */
    layer=0UL, cursor=++state->leaf_idx;
    /* Continue while the right node in the last pair is available. */
              (cursor&1UL)==0UL;
    /* Move up one layer. */
    layer++,   cursor>>=1
  ) {
    BMTREE_(merge)( &tmp,
                    (BMTREE_NODE const *)&state->node_buf[ layer ],
                    (BMTREE_NODE const *)&tmp );
  }

  /* Note on correctness of the above loop:

     The termination condition is that bit zero (LSB) of `cursor` is 1.
     Because `cursor` shifts right every iteration, the loop terminates
     as long as any bit in `cursor` is set to 1. (i.e. `cursor!=0UL`) */

  /* Emplace left node (could be root node) into buffer. */
  fd_memcpy( &state->node_buf[ layer ], &tmp, sizeof(tmp) );
}

void
BMTREE_(commit_append)( BMTREE_COMMIT *     FD_RESTRICT state,
                        BMTREE_NODE const * FD_RESTRICT leaf,
                        ulong                           leaf_cnt ) {
  /* Edge case: Caller supplied too many leaf nodes. */
  if( FD_UNLIKELY( state->leaf_idx+leaf_cnt > state->leaf_cnt ) ) {
    leaf_cnt = state->leaf_cnt - state->leaf_idx;
  }

  /* Insert nodes one-by-one.
     Possible future optimization to hash pairs of two leaf nodes without copying. */
  while( leaf_cnt-- ) {
    BMTREE_(commit_insert)( state, leaf++ );
  }
}

/* fd_bmtree*_commit_fini finalizes a commitment calculation by
   deriving the root node. */

BMTREE_NODE *
BMTREE_(commit_fini)( BMTREE_COMMIT * FD_RESTRICT state ) {
  /* Edge case: Tree is incomplete or empty (caller bug) */
  if( FD_UNLIKELY( state->leaf_idx!=state->leaf_cnt ) ) return NULL;
  if( FD_UNLIKELY( state->leaf_cnt==0 ) )               return NULL;

  /* Pointer to root node. */
  BMTREE_NODE * root = &state->node_buf[ fd_bmtree_commit_buf_cnt( state->leaf_cnt )-1UL ];

  /* Further hashing required if leaf count is not a power of two. */
  if( FD_LIKELY( fd_ulong_popcnt( state->leaf_cnt )>1 ) ) {
    /* Start at the first layer where number of nodes is odd. */
    ulong layer     = (ulong)fd_ulong_find_lsb( state->leaf_cnt );
    ulong layer_cnt = state->leaf_cnt >> layer;

    /* Allocate temporary node. */
    BMTREE_NODE tmp;
    memcpy( &tmp, &state->node_buf[layer], sizeof(BMTREE_NODE) );

    /* Ascend until we reach the root node.
       Calculate branch nodes along the way. */
    while( layer_cnt>1UL ) {
      if( (layer_cnt&1UL)==1UL ) {
        /* Create branch nodes with one child node */
        BMTREE_(merge)( &tmp,
                        (BMTREE_NODE const *)&tmp,
                        (BMTREE_NODE const *)&tmp );
      } else {
        /* Create branch nodes with two child nodes */
        BMTREE_(merge)( &tmp,
                        (BMTREE_NODE const *)&state->node_buf[ layer ],
                        (BMTREE_NODE const *)&tmp );
      }
      layer++; layer_cnt=((layer_cnt+1UL)>>1);
    }

    /* Fix up root node. */
    fd_memcpy( root, &tmp, sizeof(tmp) );
  }

  return root;
}

#undef BMTREE_
#undef BMTREEU_
#undef BMTREE_NODE
#undef BMTREE_COMMIT
#undef BMTREE_NODE_SZ
