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

   https://github.com/solana-foundation/specs/blob/main/core/merkle-tree.md */
#include "fd_bmtree.h"
#include "../sha256/fd_sha256.h"

#if FD_HAS_AVX
#include <x86intrin.h>
#endif


/* bmtree_hash_leaf computes `SHA-256([0x00]|data).  This is the first
   step in the creation of a Merkle tree.  Returns node.  U.B. if `node`
   and `data` overlap. */

fd_bmtree_node_t *
fd_bmtree_hash_leaf( fd_bmtree_node_t * node,
                    void const *       data,
                    ulong              data_sz ) {

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

static inline fd_bmtree_node_t *
fd_bmtree_private_merge( fd_bmtree_node_t       * node,
                         fd_bmtree_node_t const * a,
                         fd_bmtree_node_t const * b,
                         ulong                    hash_sz ) {

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
  _mm256_store_si256(  (__m256i *)(mem+32UL),         avx_a );
  _mm256_storeu_si256( (__m256i *)(mem+32UL+hash_sz), avx_b );

  fd_sha256_hash( mem+31UL, 1UL+2UL*hash_sz, node );

  /* Consider FD_HAS_SSE only variant? */

# else

  static uchar const branch[1] = { (uchar)1 };
  fd_sha256_t sha[1];
  fd_sha256_fini( fd_sha256_append( fd_sha256_append( fd_sha256_append( fd_sha256_init( sha ),
                  branch, 1UL ), a->hash, hash_sz ), b->hash, hash_sz ), node->hash );

# endif

  return node;
}

/* bmtree_depth returns the number of layers in a binary Merkle tree. */

FD_FN_CONST ulong
fd_bmtree_depth( ulong leaf_cnt ) {
  return fd_ulong_if( leaf_cnt<=1UL, leaf_cnt, (ulong)fd_ulong_find_msb( leaf_cnt-1UL ) + 2UL );
}

/* bmtree_commit_{footprint,align} return the alignment and footprint
   required for a memory region to be used as a bmtree_commit_t. */
FD_FN_CONST ulong fd_bmtree_commit_align    ( void ) { return alignof(fd_bmtree_commit_t); }
FD_FN_CONST ulong fd_bmtree_commit_footprint( void ) { return sizeof (fd_bmtree_commit_t); }


/* bmtree_commit_init starts a vector commitment calculation */

fd_bmtree_commit_t *    /* Returns mem as a bmtree_commit_t *, commit will be in a calc */
fd_bmtree_commit_init( void * mem,     /* Assumed unused with required alignment and footprint */
                       ulong hash_sz,
                       ulong inclusion_proof_sz ) {
  fd_bmtree_commit_t * state = (fd_bmtree_commit_t *) mem;
  state->leaf_cnt = 0UL;
  state->hash_sz = hash_sz;
  state->inclusion_proof_sz = inclusion_proof_sz;
  return state;
}


/* bmtree_commit_append appends a range of leaf nodes.  Assumes that
   leaf_cnt + new_leaf_cnt << 2^63 (which, unless planning on running
   for millenia, is always true). */

fd_bmtree_commit_t *                                            /* Returns state */
fd_bmtree_commit_append( fd_bmtree_commit_t *                 state,           /* Assumed valid and in a calc */
                        fd_bmtree_node_t const * FD_RESTRICT new_leaf,        /* Indexed [0,new_leaf_cnt) */
                        ulong                               new_leaf_cnt ) {
  ulong                         leaf_cnt = state->leaf_cnt;
  fd_bmtree_node_t * FD_RESTRICT node_buf = state->node_buf;

  for( ulong new_leaf_idx=0UL; new_leaf_idx<new_leaf_cnt; new_leaf_idx++ ) {

    /* Accumulates a single leaf node into the tree.

       Maintains the invariant that the left node of the last node pair
       for each layer is copied to `state->node_buf`.

       This serves to allow the algorithm to derive a new parent branch
       node for any pair of children, once the (previously missing)
       right node becomes available. */

    fd_bmtree_node_t tmp[1];
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
      fd_bmtree_private_merge( tmp, node_buf + layer, tmp, state->hash_sz );
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

uchar *
fd_bmtree_commit_fini( fd_bmtree_commit_t * state ) {
  ulong             leaf_cnt = state->leaf_cnt;
  fd_bmtree_node_t * node_buf = state->node_buf;

  /* Pointer to root node. */
  fd_bmtree_node_t * root = node_buf + (fd_bmtree_depth( leaf_cnt ) - 1UL);

  /* Further hashing required if leaf count is not a power of two. */
  if( FD_LIKELY( !fd_ulong_is_pow2( leaf_cnt ) ) ) {

    /* Start at the first layer where number of nodes is odd. */
    ulong layer     = (ulong)fd_ulong_find_lsb( leaf_cnt );
    ulong layer_cnt = leaf_cnt >> layer;

    /* Allocate temporary node. */
    fd_bmtree_node_t tmp[1];
    *tmp = node_buf[layer];

    /* Ascend until we reach the root node.  Calculate branch nodes
       along the way.  We use the fd_ulong_if to encourage inlining of
       merge and unnecessary branch elimination by cmov. */
    while( layer_cnt>1UL ) {
      fd_bmtree_node_t const * tmp2 = (fd_bmtree_node_t const *)
        fd_ulong_if( layer_cnt & 1UL, (ulong)tmp /* 1 child */, (ulong)(node_buf+layer) /* 2 children */ ); /* cmov */
      fd_bmtree_private_merge( tmp, tmp2, tmp, state->hash_sz );
      layer++; layer_cnt = (layer_cnt+1UL) >> 1;
    }

    /* Fix up root node. */
    *root = *tmp;
  }

  return root->hash;
}

