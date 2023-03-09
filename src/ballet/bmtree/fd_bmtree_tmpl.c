/* This file declares a family of functions for different widths of
   binary Merkle trees based on the SHA-256 hash function.  It can be
   included multiple times to get different widths.  Example:

     #define BMTREE_NAME    bmt
     #define BMTREE_HASH_SZ 20
     #include "fd_bmtree_tmpl.c"

   will declare in the current compile unit a header only library
   with the folling APIs:
   
     // Public node API

     struct __attribute__((aligned(32))) bmt_node {
       uchar hash[ 32 ]; // Only first 20 bytes are meaningful
     };

     typedef struct bmt_node bmt_node_t;

     bmt_node_t * bmtree_hash_leaf( bmt_node_t * node, void const * data, ulong data_sz );

     // Public commit API

     struct bmt_commit;
     typedef struct bmt_commit bmt_commit_t;

     ulong          bmt_commit_align    ( void );
     ulong          bmt_commit_footprint( void );
     bmt_commit_t * bmt_commit_init     ( void * mem );
     ulong          bmt_commit_leaf_cnt ( bmt_commit_t const * bmt );
     bmt_commit_t * bmt_commit_append   ( bmt_commit_t * bmt, bmt_node_t const * leaf, ulong leaf_cnt );
     uchar *        bmt_commit_fini     ( bmt_commit_t * bmt );

   See comments below for more details.

   Widths 20 and 32 are used in the Solana protocol.  Specification:

   https://github.com/solana-foundation/specs/blob/main/core/merkle-tree.md

   It is generally used as a vector commitment scheme wherein the root
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

#include "../sha256/fd_sha256.h"

#if FD_HAS_AVX
/* FIXME: Ideally we wouldn't let this bleed into the invoking compile
   unit.  (This is somewhat a symptom of this being unnecessarily
   templatized at this point and can probably be cleaned up then.) */
#include <x86intrin.h>
#endif

#ifndef BMTREE_NAME
#error "Define BMTREE_NAME"
#endif

#ifndef BMTREE_HASH_SZ
#error "Define BMTREE_HASH_SZ"
#endif

#if !(1<=BMTREE_HASH_SZ && BMTREE_HASH_SZ<=32)
#error "Unsupported BMTREE_HASH_SZ"
#endif

#define BMTREE_(token) FD_EXPAND_THEN_CONCAT3(BMTREE_NAME,_,token)

/* bmtree_node_t is the hash of a tree node (e.g. SHA256-160 / SHA256
   for a 20 / 32 byte node size).  We declare it this way to make the
   structure very AVX friendly and to allow SHA256 to write directly
   into the hash even if BMTREE_HASH_SZ isn't 32. */

struct __attribute__((aligned(32))) BMTREE_(node) {
  uchar hash[ 32UL ];
};

typedef struct BMTREE_(node) BMTREE_(node_t);

/* A bmtree_commit_t stores intermediate state used to compute the
   root of a binary Merkle tree built incrementally.

   It requires O(log n) space with regard to the number of nodes.

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

struct BMTREE_(commit) {
  ulong           leaf_cnt;         /* Number of leaves added so far */
  BMTREE_(node_t) node_buf[ 63UL ];
};

typedef struct BMTREE_(commit) BMTREE_(commit_t);

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

FD_PROTOTYPES_BEGIN

/* bmtree_hash_leaf computes `SHA-256([0x00]|data).  This is the first
   step in the creation of a Merkle tree.  Returns node.  U.B. if `node`
   and `data` overlap. */

FD_FN_UNUSED static BMTREE_(node_t) * /* Work around -Winline */
BMTREE_(hash_leaf)( BMTREE_(node_t) * node,
                    void const *      data,
                    ulong             data_sz ) {

  /* FIXME: Ideally we'd use the streamlined SHA-256 variant here but it
     is pretty wonky from a usability perspective to require users to
     allow us this API prepend a zero to their data region.  See note
     below for other nasty performance drags here in the implementation
     details (the algorithm conceptually is very clever and sound but
     the implementation requirements did not take into any consideration
     how real world computers and hardware actually work). */

  static uchar const leaf[1] = { (uchar)0 };
  fd_sha256_t sha[1];
  fd_sha256_fini( fd_sha256_append( fd_sha256_append( fd_sha256_init( sha ), leaf, 1UL ), data, data_sz ), node->hash );
  return node;
}

/* bmtree_merge computes `SHA-256([0x01]|a->hash|b->hash)` and writes
   the (truncated as necessary) result into node->hash.  In-place
   operation fine.  Returns node. */

static inline BMTREE_(node_t) *
BMTREE_(private_merge)( BMTREE_(node_t)       * node,
                        BMTREE_(node_t) const * a,
                        BMTREE_(node_t) const * b ) {

  /* FIXME: As can be seen from the below, if we actually wanted to be
     fast, we'd not bother with 20 byte variant as we actually have to
     do more work for this given the SHA algorithm and the hardware work
     at a much coarser granularity (and it doesn't save any space in
     packets because you could just compute the 32 byte variant and then
     truncate the result to 20 bytes ... it'd be both faster and more
     secure).

     Further, we'd use a sane prefix (or maybe a suffix) length instead
     of a single byte (fine grained memory accesses are the death knell
     of real world performance ... it's actually more work for the CPU
     and hardware).

     And then, if we really cared, we'd probably replace the stock
     SHA256 implementation with a block level parallel SHA256 variant
     here and above.  This would have equivalent strength but be
     dramatically higher performance on real world software and
     hardware.

     And then, we could bake into the leaf / branch prefixes into the
     parallel block calcs to further reduce comp load and alignment
     swizzling.  This would make the calculation faster still in
     software and less area in hardware while preserving security.

     The net result would be a dramatically faster and significant more
     secure and less code in software and a lot easier to accelerate in
     hardware.

     In the meantime, we write abominations like the below to get some
     extra mileage out of commodity CPUs.  Practically helps speed this
     up tree construction low tens of percent in the large number of
     small leaves limit). */

# if FD_HAS_AVX

  __m256i avx_a = _mm256_load_si256( (__m256i const *)a );
  __m256i avx_b = _mm256_load_si256( (__m256i const *)b );

  uchar mem[96] __attribute__((aligned(32)));

  mem[31] = (uchar)1;
  _mm256_store_si256( (__m256i *)(mem+32UL), avx_a );
# if BMTREE_HASH_SZ==32
  _mm256_store_si256( (__m256i *)(mem+64UL), avx_b );
# else
  _mm256_storeu_si256( (__m256i *)(mem+32UL+BMTREE_HASH_SZ), avx_b );
# endif

  fd_sha256_hash( mem+31UL, 1UL+2UL*BMTREE_HASH_SZ, node );

  /* Consider FD_HAS_SSE only variant? */

# else

  static uchar const branch[1] = { (uchar)1 };
  fd_sha256_t sha[1];
  fd_sha256_fini( fd_sha256_append( fd_sha256_append( fd_sha256_append( fd_sha256_init( sha ),
                  branch, 1UL ), a->hash, BMTREE_HASH_SZ ), b->hash, BMTREE_HASH_SZ ), node->hash );

# endif

  return node;
}

/* bmtree_depth returns the number of layers in a binary Merkle tree. */

FD_FN_CONST static inline ulong
BMTREE_(private_depth)( ulong leaf_cnt ) {
  return fd_ulong_if( leaf_cnt<=1UL, leaf_cnt, (ulong)fd_ulong_find_msb( leaf_cnt-1UL ) + 2UL );
}

/* bmtree_commit_{footprint,align} return the alignment and footprint
   required for a memory region to be used as a bmtree_commit_t. */

FD_FN_CONST static inline ulong BMTREE_(commit_align)    ( void ) { return alignof(BMTREE_(commit_t)); }
FD_FN_CONST static inline ulong BMTREE_(commit_footprint)( void ) { return sizeof (BMTREE_(commit_t)); }

/* bmtree_commit_init starts a vector commitment calculation */

static inline BMTREE_(commit_t) *    /* Returns mem as a bmtree_commit_t *, commit will be in a calc */
BMTREE_(commit_init)( void * mem ) { /* Assumed unused with required alignment and footprint */
  BMTREE_(commit_t) * state = (BMTREE_(commit_t) *)mem;
  state->leaf_cnt = 0UL;
  return state;
}

/* bmtree_commit_leaf_cnt returns the number of leafs appeneded thus
   far.  Assumes state is valid. */

FD_FN_PURE static inline ulong BMTREE_(commit_leaf_cnt)( BMTREE_(commit_t) const * state ) { return state->leaf_cnt; }

/* bmtree_commit_append appends a range of leaf nodes.  Assumes that
   leaf_cnt + new_leaf_cnt << 2^63 (which, unless planning on running
   for millenia, is always true). */

static inline BMTREE_(commit_t) *                                            /* Returns state */
BMTREE_(commit_append)( BMTREE_(commit_t) *                 state,           /* Assumed valid and in a calc */
                        BMTREE_(node_t) const * FD_RESTRICT new_leaf,        /* Indexed [0,new_leaf_cnt) */
                        ulong                               new_leaf_cnt ) {
  ulong                         leaf_cnt = state->leaf_cnt;
  BMTREE_(node_t) * FD_RESTRICT node_buf = state->node_buf;

  for( ulong new_leaf_idx=0UL; new_leaf_idx<new_leaf_cnt; new_leaf_idx++ ) {

    /* Accumulates a single leaf node into the tree.

       Maintains the invariant that the left node of the last node pair
       for each layer is copied to `state->node_buf`.

       This serves to allow the algorithm to derive a new parent branch
       node for any pair of children, once the (previously missing)
       right node becomes available. */

    BMTREE_(node_t) tmp[1];
    *tmp = new_leaf[ new_leaf_idx ];

    /* Walk the tree upwards from the bottom layer.

       `tmp` contains a previously missing right node which is used to
       derive a branch node, together with the previously buffered value
       in `node_buf`.

       Each iteration, merges that pair of nodes into a new branch node.
       Terminates if the new branch node is the left node of a pair. */

    ulong layer  = 0UL;         /* `layer` starts at 0 (leaf nodes) and increments each iteration. */
    ulong cursor = ++leaf_cnt;  /* `cursor` is the number of known nodes in the current layer. */
    while( !(cursor & 1UL) ) {  /* Continue while the right node in the last pair is available. */
      BMTREE_(private_merge)( tmp, node_buf + layer, tmp );
      layer++; cursor>>=1;      /* Move up one layer. */
    }

    /* Note on correctness of the above loop: The termination condition
       is that bit zero (LSB) of `cursor` is 1.  Because `cursor` shifts
       right every iteration, the loop terminates as long as any bit in
       `cursor` is set to 1. (i.e. `cursor!=0UL`) */

    /* Emplace left node (could be root node) into buffer.  FIXME:
       Consider computing this location upfront and doing this inplace
       instead of copying at end? (Probably a wash.) */

    node_buf[ layer ] = *tmp;
  }

  state->leaf_cnt = leaf_cnt;
  return state;
}

/* bmtree_commit_fini seals the commitment calculation by deriving the
   root node.  Assumes state is valid, in calc on entry with at least
   one leaf in the tree.  The state will be valid but no longer in a
   calc on return.  Returns a pointer in the caller's address space to
   the first byte of a memory region of BMTREE_HASH_SZ with to the root
   hash on success.  The lifetime of the returned pointer is that of the
   state or until the memory used for state gets initialized for a new
   calc. */

static inline uchar *
BMTREE_(commit_fini)( BMTREE_(commit_t) * state ) {
  ulong             leaf_cnt = state->leaf_cnt;
  BMTREE_(node_t) * node_buf = state->node_buf;

  /* Pointer to root node. */
  BMTREE_(node_t) * root = node_buf + (BMTREE_(private_depth)( leaf_cnt ) - 1UL);

  /* Further hashing required if leaf count is not a power of two. */
  if( FD_LIKELY( !fd_ulong_is_pow2( leaf_cnt ) ) ) {

    /* Start at the first layer where number of nodes is odd. */
    ulong layer     = (ulong)fd_ulong_find_lsb( leaf_cnt );
    ulong layer_cnt = leaf_cnt >> layer;

    /* Allocate temporary node. */
    BMTREE_(node_t) tmp[1];
    *tmp = node_buf[layer];

    /* Ascend until we reach the root node.  Calculate branch nodes
       along the way.  We use the fd_ulong_if to encourage inlining of
       merge and unnecessary branch elimination by cmov. */
    while( layer_cnt>1UL ) {
      BMTREE_(node_t) const * tmp2 = (BMTREE_(node_t) const *)
        fd_ulong_if( layer_cnt & 1UL, (ulong)tmp /* 1 child */, (ulong)(node_buf+layer) /* 2 children */ ); /* cmov */
      BMTREE_(private_merge)( tmp, tmp2, tmp );
      layer++; layer_cnt = (layer_cnt+1UL) >> 1;
    }

    /* Fix up root node. */
    *root = *tmp;
  }

  return root->hash;
}

FD_PROTOTYPES_END

#undef BMTREE_

#undef BMTREE_HASH_SZ
#undef BMTREE_NAME
