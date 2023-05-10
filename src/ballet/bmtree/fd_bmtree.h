#ifndef HEADER_fd_src_ballet_bmtree_fd_bmtree_h
#define HEADER_fd_src_ballet_bmtree_fd_bmtree_h

/* It is generally used as a vector commitment scheme wherein the root
   node of the tree commits the vector of leaf nodes.

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
    - For any nodes with a single remaining child, duplicate the link to
      the child.
    - Each non-leaf node now has exactly two children, counting
      duplicates.

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

#include "../../util/fd_util_base.h"

/* bmtree_node_t is the hash of a tree node (e.g. SHA256-160 / SHA256
   for a 20 / 32 byte node size).  We declare it this way to make the
   structure very AVX friendly and to allow SHA256 to write directly
   into the hash even if BMTREE_HASH_SZ isn't 32. */
struct __attribute__((aligned(32))) fd_bmtree_node {
  uchar hash[ 32 ]; /* Last bytes may not be meaningful */
};

typedef struct fd_bmtree_node fd_bmtree_node_t;

/* bmtree_hash_leaf computes `SHA-256([0x00]|data).  This is the first
   step in the creation of a Merkle tree.  Returns node.  U.B. if `node`
   and `data` overlap. */
fd_bmtree_node_t * fd_bmtree_hash_leaf( fd_bmtree_node_t * node, void const * data, ulong data_sz );

/* A fd_bmtree_commit_t stores intermediate state used to compute the
   root of a binary Merkle tree built incrementally.

   It theoretically requires O(log n) space with regard to the number of
   nodes, although n is currently capped (at an astronomical value), so
   it requires constant space.

   During the accumulation phase, the data structure consumes all tree
   leaf nodes sequentially while calculating and buffering branch nodes
   of upper layers along the way.

   In the finalization phase, the buffered branch node data is hashed to
   derive the final root hash.

   The separation of the accumulation and finalization phases is
   required for trees with leaf counts that are not powers of two.
   Those contain at least one branch node with only one child node.

   The node_buf is large enough to handle trees with ~2^63 leaves.  This
   is orders of magnitude more leaves are practical (it would take
   ~30,000 years at a rate of ~100 microsecond per leaf insert but if
   you are willing to wait to make a larger tree, increase 63 below). */

struct fd_bmtree_commit_private {
  /* Explanation of the above internal state in bmtree_commit_t:

     - `leaf_cnt` contains the number of leaf nodes that have been
     accumulated so far. It is synonymous to the index of within the
     vector of leaf nodes.

     This is used to check how many branch nodes in the upper layers can
     be derived with the currently known information.

     The current depth of the layers above the leaf nodes is the number
     of times the `leaf_cnt` is divisible by 2.

     - `node_buf` is indexed by layer, with 0 being the leaf layer.

     Given a layer `L` containing a vector of nodes known so far,
     `node_buf[L]` contains the right-most node in layer `L` (counting
     from the bottom) that is a left child of its parent.

     More precisely:

     The subset `L_left` contains all nodes with index `i` within that
     layer where `i%2==0`. Then, `node_buf[L]` contains the node with
     the largest index `i`within `L_left`.

   **Example**

   Step-by-step walkthrough of the internal state in SSA notation:

   Initialize
   - leaf_cnt    <- 0

   Insert leaf `l_0`
   - node_buf[0] <- l_0
   - leaf_cnt    <- 1

   Insert leaf `l_1`
   - b_0         <- hash_branch( node_buf[0], l_1 )
   - node_buf[1] <- b_0
   - leaf_cnt    <- 2

   Insert leaf `l_2`
   - node_buf[0] <- l_2
   - leaf_cnt    <- 3

   Insert leaf `l_3`
   - b_0         <- hash_branch( node_buf[0], l_3 )
   - b_1         <- hash_branch( node_buf[1], b_0 )
   - node_buf[2] <- b_1
   - leaf_cnt    <- 4  */
  ulong             leaf_cnt;         /* Number of leaves added so far */
  ulong             hash_sz;          /* <= 32 bytes */
  ulong             inclusion_proof_sz;
  fd_bmtree_node_t  node_buf[ 63UL ];
  fd_bmtree_node_t  inclusion_proofs[ 1 ]; /* Indexed [0, inclusion_proof_sz) */
};

typedef struct fd_bmtree_commit_private fd_bmtree_commit_t;

#define FD_BMTREE_COMMIT_FOOTPRINT (sizeof(fd_bmtree_commit_t))
#define FD_BMTREE_COMMIT_ALIGN                         (32UL)

FD_PROTOTYPES_BEGIN

/* bmtree_commit_{footprint,align} return the alignment and footprint
   required for a memory region to be used as a bmtree_commit_t. */
ulong          fd_bmtree_commit_align    ( void );
ulong          fd_bmtree_commit_footprint( void );

/* bmtree_commit_init starts a vector commitment calculation
 Assumes mem unused with required alignment and footprint.
 Returns mem as a bmtree_commit_t *, commit will be in a calc */
fd_bmtree_commit_t * fd_bmtree_commit_init     ( void * mem, ulong hash_sz, ulong inclusion_proof_sz );

/* bmtree_commit_leaf_cnt returns the number of leafs appeneded thus
   far.  Assumes state is valid. */
FD_FN_PURE static inline ulong fd_bmtree_commit_leaf_cnt ( fd_bmtree_commit_t const * bmt ) { return bmt->leaf_cnt; }

/* bmtree_depth returns the number of layers in a binary Merkle tree. */
FD_FN_CONST ulong fd_bmtree_depth( ulong leaf_cnt );

/* bmtree_commit_append appends a range of leaf nodes.  Assumes that
   leaf_cnt + new_leaf_cnt << 2^63 (which, unless planning on running
   for millenia, is always true). */
fd_bmtree_commit_t *                                                     /* Returns state */
fd_bmtree_commit_append( fd_bmtree_commit_t *                 state,           /* Assumed valid and in a calc */
                   fd_bmtree_node_t const * FD_RESTRICT new_leaf,        /* Indexed [0,new_leaf_cnt) */
                   ulong                          new_leaf_cnt );

/* bmtree_commit_fini seals the commitment calculation by deriving the
   root node.  Assumes state is valid, in calc on entry with at least
   one leaf in the tree.  The state will be valid but no longer in a
   calc on return.  Returns a pointer in the caller's address space to
   the first byte of a memory region of BMTREE_HASH_SZ with to the root
   hash on success.  The lifetime of the returned pointer is that of the
   state or until the memory used for state gets initialized for a new
   calc. */
uchar *        fd_bmtree_commit_fini     ( fd_bmtree_commit_t * bmt );


FD_PROTOTYPES_END
#endif /* HEADER_fd_src_ballet_bmtree_fd_bmtree_h */
