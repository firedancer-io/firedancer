#ifndef HEADER_fd_src_ballet_bmtree_fd_bmtree_h
#define HEADER_fd_src_ballet_bmtree_fd_bmtree_h

#include "../sha256/fd_sha256.h"

/* fd_bmtree{20,32} is a binary Merkle tree used in the Solana protocol.
   It uses the SHA-256 hash function.

   Specification:
   https://github.com/solana-foundation/specs/blob/main/core/merkle-tree.md

   It is generally used as a vector commitment scheme
   wherein the root node of the tree commits the vector of leaf nodes.

   All methods provided by this Merkle tree derive from these three
   basic operations.

     1. Construct leaf node:

        (leaf blob) -> (node)

     2. Construct branch node with two children:

        (node, node) -> (node)

     3. Construct branch node with one child:

        (node) -> (node)

   Example derived methods.
   (TODO not all of them are provided by this header file yet)

     4. Construct full tree:

        (vector of leaf blobs) -> (tree of nodes)

     5. Create inclusion proof from tree data

        (tree of nodes, node index) -> (inclusion proof)

     6. Verify node inclusion proof

        (node, root node, inclusion proof) -> (bool)

   **Topology**

   Tree topology has the following constraints:

    - All leaf nodes are in the bottom level

    - If a given layer `L`
      with number of nodes `L_n` ...

      ... has exactly one node,
          this one node is the root node
          and forms the uppermost layer.

      ... has more than one node
          ... and `L_n % 2 == 0`,
              the layer above contains n/2 nodes

          ... and `L_n % 2 == 1`,
              the layer above contains (n+1)/2 nodes.

   A simple algorithm to approach such a a tree is as follows:
   (Note that the code uses here uses an optimized approach)

    - Start with the smallest complete binary tree that has at least
       `n` leaf nodes.
    - Label the leaf nodes from left to right `L_0`, `L_1`, ... `L_(n-1)`
    - Delete any un-labeled leaf nodes, and then recursively delete any
      nodes with no children.
    - For any nodes with a single remaining child, duplicate the link to the child.
    - Each non-leaf node now has exactly two children, counting duplicates.

   Example: Tree with 1 leaf node (root node = leaf node)

    L0

   Example: Tree with 4 leaf nodes

           Iδ
          /  \
         /    \
       Iα      Iβ
      /  \    /  \
     L0  L1  L2  L3

   Example: Tree with 5 leaf nodes

              Iζ
             /  \
            /    \
           Iδ     Iε
          /  \     \\
         /    \     \\
       Iα      Iβ    Iγ
      /  \    /  \   ||
     L0  L1  L2  L3  L4

   **Construction**

   The input data is a vector of arbitrary-sized binary blobs.
   First, each blob is converted to a fixed-size leaf node by hashing
   the blob in the `FD_BMTREE_PREFIX_LEAF` hash domain.

   Then, the hash function is recursively applied over pairs of nodes
   until there is only one node left (the root).

   `fd_bmtree_32` uses the full SHA-256 digest for each tree node
   and is thus considered cryptographically secure.

   `fd_bmtree_20` uses SHA-256 digests truncated to 160 bits.

   **Inclusion Proofs**

   Inclusion proofs are used to verify whether a set of leaf nodes is
   part of a commitment (identified by the root node).

   At a high level, inclusion proofs present a sequence of hash
   instructions that when executed result in the root commitment.

   Inclusion proof size is O(log n) with regards to tree node count.

   Various types of inclusion proofs exist:

     - Single inclusion proofs (over one leaf node)
     - Range inclusion proofs (over a contiguous range of leaf nodes)
     - Sparse inclusion proofs (over an arbitrary subset of leaf nodes) */

#define FD_BMTREE_PREFIX_LEAF   (uchar)0x00
#define FD_BMTREE_PREFIX_BRANCH (uchar)0x01

/* FD_BMTREE20_NODE_SZ: Size in bytes of a SHA-256-160 tree node */
#define FD_BMTREE20_NODE_SZ (20UL)

/* FD_BMTREE32_NODE_SZ: Size in bytes of a SHA-256 tree node */
#define FD_BMTREE32_NODE_SZ (32UL)

/* fd_bmtree20_node_t is the hash of a SHA-256-160 tree node (20 bytes) */
typedef uchar fd_bmtree20_node_t[FD_BMTREE20_NODE_SZ];

/* fd_bmtree20_node_t is the hash of a SHA-256 tree node (32 bytes) */
typedef uchar fd_bmtree32_node_t[FD_BMTREE32_NODE_SZ];

/* fd_bmtree*_commit_t stores intermediate state used to compute the
   root of a binary Merkle tree built incrementally.

   It requires O(log n) space with regard to the number of nodes.

   During the accumulation phase, the data structure consumes all
   tree leaf nodes sequentially while calculating and buffering
   branch nodes of upper layers along the way.

   In the finalization phase, the buffered branch node data is hashed
   to derive the final root hash.

   The separation of the accumulation and finalization phases is
   required for trees with leaf counts that are not powers of two.
   Those contain at least one branch node with only one child node. */

struct __attribute__((aligned(32))) fd_bmtree20_commit {
  ulong leaf_idx;
  ulong leaf_cnt;
  fd_bmtree20_node_t node_buf[];
};
typedef struct fd_bmtree20_commit fd_bmtree20_commit_t;

struct __attribute__((aligned(32))) fd_bmtree32_commit {
  ulong leaf_idx;
  ulong leaf_cnt;
  fd_bmtree32_node_t node_buf[];
};
typedef struct fd_bmtree32_commit fd_bmtree32_commit_t;

/* Explanation of the above internal state in fd_bmtree*_commit:

   - `leaf_idx` contains the number of leaf nodes that have been
     accumulated so far. It is synonymous to the index of within
     the vector of leaf nodes.

     This is used to check how many branch nodes in the upper layers
     can be derived with the currently known information.

      The current depth of the layers above the leaf nodes is the
      number of times the `leaf_idx` is divisible by 2.

   - `leaf_cnt` is the expected number of leaf nodes (constant).

   - `node_buf` is indexed by layer, with 0 being the leaf layer.

     Given a layer `L` containing a vector of nodes known so far,
     `node_buf[L]` contains the right-most node in layer `L`
     (counting from the bottom) that is a left child of its parent.

     More precisely:
     The subset `L_left` contains all nodes with index `i` within that
     layer where `i%2==0`. Then, `node_buf[L]` contains the node with
     the largest index `i`within `L_left`.

   **Example**

   Step-by-step walkthrough of the internal state in SSA notation:

    Initialize
     - leaf_idx    <- 0

    Insert leaf `l_0`
     - node_buf[0] <- l_0
     - leaf_idx    <- 1

    Insert leaf `l_1`
     - b_0         <- hash_branch( node_buf[0], l_1 )
     - node_buf[1] <- b_0
     - leaf_idx    <- 2

    Insert leaf `l_2`
     - node_buf[0] <- l_2
     - leaf_idx    <- 3

    Insert leaf `l_3`
     - b_0         <- hash_branch( node_buf[0], l_3 )
     - b_1         <- hash_branch( node_buf[1], b_0 )
     - node_buf[2] <- b_1
     - leaf_idx    <- 4  */

FD_PROTOTYPES_BEGIN

/* fd_bmtree_depth returns the number of layers in a binary Merkle tree. */

FD_FN_CONST static inline ulong
fd_bmtree_depth( ulong leaf_cnt ) {
  if( FD_UNLIKELY( leaf_cnt<=1UL ) ) return leaf_cnt; /* optimize for non-trivial tree */

  return (ulong)fd_ulong_find_msb( leaf_cnt-1UL ) + 2UL;
}

/* fd_bmtree_commit_buf_cnt returns the number of nodes that
   a buffer minimally has to fit to compute the root. */

#define fd_bmtree_commit_buf_cnt fd_bmtree_depth

/* fd_bmtree*_commit_footprint returns the size
   occupied by a fd_bmtree*_commit_t. */

FD_FN_CONST static inline ulong
fd_bmtree20_commit_footprint( ulong leaf_cnt ) {
  return sizeof(fd_bmtree20_commit_t) + (fd_bmtree_commit_buf_cnt( leaf_cnt )*FD_BMTREE20_NODE_SZ);
}

FD_FN_CONST static inline ulong
fd_bmtree32_commit_footprint( ulong leaf_cnt ) {
  return sizeof(fd_bmtree32_commit_t) + (fd_bmtree_commit_buf_cnt( leaf_cnt )*FD_BMTREE32_NODE_SZ);
}

/* fd_bmtree*_commit_init: Initializes a vector commitment calculation */

void
fd_bmtree20_commit_init( fd_bmtree20_commit_t * commit,
                         ulong                  leaf_cnt );

void
fd_bmtree32_commit_init( fd_bmtree32_commit_t * commit,
                         ulong                  leaf_cnt );

/* fd_bmtree*_commit_append: Accumulates a range of leaf nodes. */

/* TODO: Provide an interface that allows the caller to extract
         any branch nodes created while appending */

void
fd_bmtree20_commit_append( fd_bmtree20_commit_t *     FD_RESTRICT commit,
                           fd_bmtree20_node_t const * FD_RESTRICT leaf,
                           ulong                                  leaf_cnt );

void
fd_bmtree32_commit_append( fd_bmtree32_commit_t *     FD_RESTRICT commit,
                           fd_bmtree32_node_t const * FD_RESTRICT leaf,
                           ulong                                  leaf_cnt );

/* fd_bmtree*_commit_fini: Seals the commitment calculation.

   Returns a pointer to the root node (within `commit->node_buf`).
   Returns NULL if the tree has no nodes or not all nodes have been appended. */

fd_bmtree20_node_t *
fd_bmtree20_commit_fini( fd_bmtree20_commit_t * FD_RESTRICT commit );

fd_bmtree32_node_t *
fd_bmtree32_commit_fini( fd_bmtree32_commit_t * FD_RESTRICT commit );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_ballet_bmtree_fd_bmtree_h */
