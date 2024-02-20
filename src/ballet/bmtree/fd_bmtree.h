#ifndef HEADER_fd_src_ballet_bmtree_fd_bmtree_h
#define HEADER_fd_src_ballet_bmtree_fd_bmtree_h

/* fd_bmtree provides APIs for working with binary Merkle trees that use
   the SHA256 hash function. */

#include "../../util/fd_util_base.h"
/* Binary Merkle trees are generally used as a vector commitment scheme
   wherein the root node of the tree commits the vector of leaf nodes.

   All methods provided by this Merkle tree derive from the following
   three basic operations:

     1. Construct leaf node:

        (leaf blob) -> (node)

     2. Construct branch node with two children:

        (node, node) -> (node)

     3. Construct branch node with one child:

        (node) -> (node)

   Example derived methods.
   (TODO now these all are more or less implemented, but not exactly as
   described. Is this distinction between basic and derived even useful
   though?)

     4. Construct full tree:

        (vector of leaf blobs) -> (tree of nodes)

     5. Create inclusion proof from tree data

        (tree of nodes, node index) -> (inclusion proof)

     6. Verify node inclusion proof

        (node, root node, inclusion proof) -> (bool)

   **Topology**

   Tree topology has the following constraints:

    - All leaf nodes are in the bottom level

    - If a given layer `l`
      with number of nodes `N_l` ...

      ... has exactly one node,
          this one node is the root node
          and forms the uppermost layer.

      ... has more than one node
          ... and `N_l % 2 == 0`,
              the layer above contains N_l/2 nodes

          ... and `N_l % 2 == 1`,
              the layer above contains (N_l+1)/2 nodes.

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


/* As of https://github.com/solana-labs/solana/pull/29339, Solana
   changed the second preimage resistance strategy to depend on whether
   it's the 20B shred tree or the 32B runtime tree.  In the 20B case,
   they prepend the full leaf_prefix (excluding the nul terminator).  In
   the 32B case, they just prepend a single 0x00 byte.  Similarly for
   internal nodes.  These prefixes are aligned and padded to facilitate
   use with AVX. */
#define FD_BMTREE_LONG_PREFIX_SZ  26UL
#define FD_BMTREE_SHORT_PREFIX_SZ 1UL
static uchar const fd_bmtree_leaf_prefix[32UL] __attribute__((aligned(32))) = "\x00SOLANA_MERKLE_SHREDS_LEAF";
static uchar const fd_bmtree_node_prefix[32UL] __attribute__((aligned(32))) = "\x01SOLANA_MERKLE_SHREDS_NODE";


/* bmtree_node_t is the hash of a tree node (e.g. SHA256-160 / SHA256
   for a 20 / 32 byte node size).  We declare it this way to make the
   structure very AVX friendly and to allow SHA256 to write directly
   into the hash even if BMTREE_HASH_SZ isn't 32. */
struct __attribute__((packed)) fd_bmtree_node {
  uchar hash[ 32 ]; /* Last bytes may not be meaningful */
};

typedef struct fd_bmtree_node fd_bmtree_node_t;

/* bmtree_hash_leaf computes `SHA-256(prefix|data), where prefix is the
   first prefix_sz bytes of fd_bmtree_leaf_prefix.  prefix_sz is
   typically FD_BMTREE_LONG_PREFIX_SZ or FD_BMTREE_SHORT_PREFIX_SZ.
   This is the first step in the creation of a Merkle tree.  Returns
   node.  U.B. if `node` and `data` overlap. */
fd_bmtree_node_t * fd_bmtree_hash_leaf( fd_bmtree_node_t * node, void const * data, ulong data_sz, ulong prefix_sz );

/* A fd_bmtree_commit_t stores intermediate state used to compute the
   root of a binary Merkle tree built incrementally.  It can be used for
   two different typed of calculations:
     * leaf-based commitment calculations  (fd_bmtree_commit_*)
     * proof-based commitment calculations (fd_bmtree_commitp_*)
    but only one at a time.

   For leaf-based commitment calculations, it theoretically requires
   O(log n) space with regard to the number of nodes, although n is
   currently capped (at an astronomical value), so it requires constant
   space.

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

   Step-by-step walkthrough of the internal state:

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

   Insert leaf `l_3
   - b_0         <- hash_branch( node_buf[0], l_3 )
   - b_1         <- hash_branch( node_buf[1], b_0 )
   - node_buf[2] <- b_1
   - leaf_cnt    <- 4

   inclusion_proofs stores hashes of internal nodes from previous
   computation.  If 0 <= i < inclusion_proof_sz, then
   inclusion_proofs[i] stores the hash at node i of the tree numbered
   in complete binary search tree order.  E.g.

                  3
                /   \
              1       5
             / \     //
            0   2   4

   This is a superset of what is stored in node_buf, but in order to not
   lose the log(n) cache utilization features when we don't care about
   inclusion proofs and are only trying to derive the root hash, we
   store them separately.

   In general, this binary search tree order is fairly friendly.  To
   find the layer of a node, you count the number of trailing 1 bits in
   its index.  To get the left/right child, you add/subtract 1<<layer.
   This ordering makes sense for these trees, because they grow up and
   to the right, the same way the numbers increase, so a node's index
   never changes as more leaves are added to the tree.

   The biggest subtlety comes when there are nodes with incomplete left
   subtrees, e.g.

                         7
                      /     \
                    /         \
                   3          ??
                 /   \        /
                1     5      9
               / \   / \    /
              0   2  4  6  8

   What number belongs in the ?? spot?  By binary search order, it
   should be 10.  The natural index of that node is 7+4=11 though.  The
   indexing gets very complicated and error-prone if we try to store it
   in 10, so we prefer to store it in 11.  That means the size of our
   storage depends only on the maximum number of layers we expect in
   the tree, which is somewhat convenient.  This does waste up to
   O(leaf_cnt) space though. */

  ulong             leaf_cnt;         /* Number of leaves added so far */
  ulong             hash_sz;          /* <= 32 bytes */
  ulong             prefix_sz;        /* <= 26 bytes */
  ulong             inclusion_proof_sz;
  fd_bmtree_node_t  node_buf[ 63UL ];
  /* Dense bit set. Array indexed [0, ceil((inclusion_proof_sz+1)/64)).
     Points to memory just after the end of the inclusion_proofs array
     and included in the footprint.  Only used or set in proof-based
     commits, because it's implicit in the leaf_cnt in leaf-based
     commits. */
  ulong *           inclusion_proofs_valid;
  /* inclusion_proofs is indexed [0, inclusion_proof_sz] where index
     inclusion_proof_sz is a dummy index used to avoid branches. */
  fd_bmtree_node_t  inclusion_proofs[ 1 ];
};

typedef struct fd_bmtree_commit_private fd_bmtree_commit_t;

#define FD_BMTREE_COMMIT_FOOTPRINT( inclusion_proof_layer_cnt ) ((((sizeof(fd_bmtree_commit_t) + \
                                                                 ((1UL<<(inclusion_proof_layer_cnt))-1UL)*sizeof(fd_bmtree_node_t)+\
                                                                 ((1UL<<(inclusion_proof_layer_cnt))+63UL)/64UL*sizeof(ulong))+31UL)/32UL) * 32UL)
#define FD_BMTREE_COMMIT_ALIGN                         (32UL)

FD_PROTOTYPES_BEGIN

/* bmtree_commit_{footprint,align} return the alignment and footprint
   required for a memory region to be used as a bmtree_commit_t.  If the
   tree does not exceed inclusion_proof_layer_cnt layers, then all
   inclusion proofs can be retrieved after finalization. */
ulong          fd_bmtree_commit_align    ( void );
ulong          fd_bmtree_commit_footprint( ulong inclusion_proof_layer_cnt );

/* bmtree_commit_init starts a vector commitment calculation of either
   type.  Assumes mem unused with required alignment and footprint.
   Returns mem as a bmtree_commit_t *, commit will be in a calc.
   prefix_sz is the size (in bytes) of the second-preimage resistance
   prefix used.  It's typically FD_BMTREE_LONG_PREFIX_SZ or
   FD_BMTREE_SHORT_PREFIX_SZ and must not be greater than
   FD_BMTREE_LONG_PREFIX_SZ.

   The calculation can also save some inclusion proof information such
   that if the final tree has no more than inclusion_proof_layer_cnt layers,
   inclusion proofs will be available for all leaves.  If the tree grows
   beyond inclusion_proof_layer_cnt layers, then inclusion proofs may
   not be available for any leaves.

   For proof-based commitments, inclusion_proof_layers must be at least
   as large as the number of layers in the tree.
   */
fd_bmtree_commit_t * fd_bmtree_commit_init     ( void * mem, ulong hash_sz, ulong prefix_sz, ulong inclusion_proof_layer_cnt );

/* bmtree_commit_leaf_cnt returns the number of leafs appended thus
   far.  Assumes state is valid. */
FD_FN_PURE static inline ulong fd_bmtree_commit_leaf_cnt ( fd_bmtree_commit_t const * bmt ) { return bmt->leaf_cnt; }

/* fd_bmtree_depth and fd_bmtree_node_cnt respectively return the number
   of layers and total number of nodes in a binary Merkle tree with
   leaf_cnt leaves. */
FD_FN_CONST ulong fd_bmtree_depth(    ulong leaf_cnt );
FD_FN_CONST ulong fd_bmtree_node_cnt( ulong leaf_cnt );

/* bmtree_commit_append appends a range of leaf nodes.  Assumes that
   leaf_cnt + new_leaf_cnt << 2^63 (which, unless planning on running
   for millennia, is always true). */
fd_bmtree_commit_t *                                                         /* Returns state */
fd_bmtree_commit_append( fd_bmtree_commit_t *                 state,         /* Assumed valid and in a leaf-based calc */
                         fd_bmtree_node_t const * FD_RESTRICT new_leaf,      /* Indexed [0,new_leaf_cnt) */
                         ulong                                new_leaf_cnt );

/* bmtree_commit_fini seals the commitment calculation by deriving the
   root node.  Assumes state is valid, in a leaf-based calc on entry
   with at least one leaf in the tree.  The state will be valid but no
   longer in a calc on return.  Returns a pointer in the caller's
   address space to the first byte of a memory region of BMTREE_HASH_SZ
   with to the root hash on success.  The lifetime of the returned
   pointer is that of the state or until the memory used for state gets
   initialized for a new calc. */
uchar * fd_bmtree_commit_fini( fd_bmtree_commit_t * state );


/* bmtree_get_proof writes an inclusion proof for the leaf
   with index leaf_idx to the memory at dest.  state must be a valid
   sealed bmtree commitment (leaf-based or proof-based) with at least
   leaf_idx+1 leaves.  state must have been initialized with
   inclusion_proof_layers_cnt >= the height of the tree, which you can
   get from fd_bmtree_depth( fd_bmtree_commit_leaf_cnt( state ) ).

   If these conditions are met, upon return, dest[ i ] for
   0<=i<hash_sz*(tree depth-1) will contain the inclusion proof, and the
   function will return the number of hashes written.  If
   inclusion_proof_layers_cnt was initialized to too small of a value,
   this function will return -1 and the memory pointed to by dest will
   not be modified.

   The inclusion proof is ordered from leaf to root but excludes the
   actual root of the tree. */
/* FIXME: Returning -1 is pretty bad here, but 0 is the legitimate
   proof size of a 1 node tree.  Is that case worth distinguishing? */
int
fd_bmtree_get_proof( fd_bmtree_commit_t * state,
                     uchar *              dest,
                     ulong                leaf_idx );

/* fd_bmtree_from_proof derives the root of a Merkle tree where the
   element with hash `leaf` is the leaf_idx^th leaf and proof+hash_sz*i
   contains its sibling at the ith level (counting from the bottom).
   The full root hash (i.e. untruncated regardless of hash_sz) will be
   stored in root upon return.
   Does not retain any read or write interests after returning, and it
   operates independently of normal tree construction, so it neither
   starts nor ends a calc, and it can safely be done in the middle of a
   calc.

   Memory regions should not overlap.

   The proof consists of proof_depth hashes, each hash_sz bytes
   concatenated with no padding ordered from leaf to root, excluding the
   root.

   Returns root if the proof is valid and NULL otherwise.  If the proof
   is invalid, the root will not be stored.  A proof can only be invalid
   if it is too short to possibly correspond to the leaf_idx^th node. */
/* TODO: Write the caching version of this */
fd_bmtree_node_t *
fd_bmtree_from_proof( fd_bmtree_node_t const * leaf,
                      ulong                    leaf_idx,
                      fd_bmtree_node_t *       root,
                      uchar const *            proof,
                      ulong                    proof_depth,
                      ulong                    hash_sz,
                      ulong                    prefix_sz );


/* fd_bmtree_commitp_insert_with_proof inserts a leaf at index idx in
   the proof-based calc, optionally with some proof.  Returns 1 if
   the leaf and proof are consistent with everything previously added to
   this calc, or 0 if not.

   fd_bmtree_depth( idx+1 ) must be <= inclusion_proof_layer_cnt used in
   init.

   Like all the other functions in this file that deal with inclusion
   proofs, the proof format is leaf to root, excluding the root, where
   each of the proof_depth hashes occupies hash_sz bytes and there is no
   padding.  Truncated proof_depths are fine and are interpreted as the
   first proof_depth elements of the proof, i.e. the ones closer to the
   leaf.  In particular, a proof_depth of 0 is fine, in which case
   proof==NULL is fine.

   If this returns success and opt_root is not NULL, the highest node
   (closest to the root) in the branch containing idx that is known will
   be written to the memory pointed to by opt_root.  In the case that
   the inclusion proof is full (contains all the nodes except the root),
   the node that is stored is the root of the tree; however, in general
   the tree can grow beyond this, so it isn't possible to guarantee that
   it is the root in other cases.  If the function returns failure (0)
   or opt_root==NULL, then the memory pointed to by opt_root will not be
   accessed.

   If this returns 0, the commitment state will not be modified.  If it
   returns 1, then the information provided will be cached to speed up
   other validations in this calc.

   Note that a return value of 1 does not necessarily imply the leaf is
   correct, as there may not be enough information to determine it yet.
   In that case, fd_bmtreep_fini or another call to fd_bmtreep_insert
   will return 0. */

int
fd_bmtree_commitp_insert_with_proof( fd_bmtree_commit_t *     state,
                                     ulong                    idx,
                                     fd_bmtree_node_t const * new_leaf,
                                     uchar            const * proof,
                                     ulong                    proof_depth,
                                     fd_bmtree_node_t       * opt_root );

/* fd_bmtree_commitp_fini finalizes a proof-based calc.  Returns the
   root of the tree if it can conclusively determine that the entire
   tree is correct for a commitment of leaf_cnt leaf nodes and NULL
   otherwise. */
uchar * fd_bmtree_commitp_fini( fd_bmtree_commit_t * state, ulong leaf_cnt );

FD_PROTOTYPES_END
#endif /* HEADER_fd_src_ballet_bmtree_fd_bmtree_h */
