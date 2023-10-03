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

#define SET_NAME ipfset
#include "../../util/tmpl/fd_smallset.c"

#if FD_HAS_AVX
#include <x86intrin.h>
#endif



fd_bmtree_node_t *
fd_bmtree_hash_leaf( fd_bmtree_node_t * node,
                    void const *       data,
                    ulong              data_sz,
                    ulong              prefix_sz ) {

  /* FIXME: Ideally we'd use the streamlined SHA-256 variant here but it
     is pretty wonky from a usability perspective to require users to
     allow us this API prepend a zero to their data region.  See note
     below for other nasty performance drags here in the implementation
     details (the algorithm conceptually is very clever and sound but
     the implementation requirements did not take into any consideration
     how real world computers and hardware actually work). */

  fd_sha256_t sha[1];
  fd_sha256_fini( fd_sha256_append( fd_sha256_append( fd_sha256_init( sha ), fd_bmtree_leaf_prefix, prefix_sz ), data, data_sz ), node->hash );
  return node;
}

/* bmtree_merge computes `SHA-256(prefix|a->hash|b->hash)` and writes
   the full hash into node->hash (which can then be truncated as
   necessary).  prefix is the first prefix_sz bytes of
   fd_bmtree_node_prefix and is typically FD_BMTREE_LONG_PREFIX_SZ or
   FD_BMTREE_SHORT_PREFIX_SZ.  In-place operation fine.  Returns node.
   */

static inline fd_bmtree_node_t *
fd_bmtree_private_merge( fd_bmtree_node_t       * node,
                         fd_bmtree_node_t const * a,
                         fd_bmtree_node_t const * b,
                         ulong                    hash_sz,
                         ulong                    prefix_sz ) {

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

  __m256i avx_pre = _mm256_load_si256( (__m256i const *)fd_bmtree_node_prefix );
  __m256i avx_a   = _mm256_load_si256( (__m256i const *)a           );
  __m256i avx_b   = _mm256_load_si256( (__m256i const *)b           );

  uchar mem[96] __attribute__((aligned(32)));

  _mm256_store_si256(  (__m256i *)(mem),                     avx_pre );
  _mm256_storeu_si256( (__m256i *)(mem+prefix_sz),           avx_a   );
  _mm256_storeu_si256( (__m256i *)(mem+prefix_sz+hash_sz),   avx_b   );

  fd_sha256_hash( mem, prefix_sz+2UL*hash_sz, node );

  /* Consider FD_HAS_SSE only variant? */

# else

  fd_sha256_t sha[1];
  fd_sha256_fini( fd_sha256_append( fd_sha256_append( fd_sha256_append( fd_sha256_init( sha ),
                  fd_bmtree_node_prefix, prefix_sz ), a->hash, hash_sz ), b->hash, hash_sz ), node->hash );

# endif

  return node;
}

/* bmtree_depth returns the number of layers in a binary Merkle tree. */

FD_FN_CONST ulong
fd_bmtree_depth( ulong leaf_cnt ) {
  return fd_ulong_if( leaf_cnt<=1UL, leaf_cnt, (ulong)fd_ulong_find_msb( leaf_cnt-1UL ) + 2UL );
}

FD_FN_CONST ulong
fd_bmtree_node_cnt( ulong leaf_cnt ) {
  /* Compute the number of nodes in a tree with inclusion_proof_leaf_cnt
     leaves. Based on the proposition that layer l having N_l nodes
     implies the above layer has floor((N_l+1)/2) nodes, we know that
     the kth layer above has floor(((N_l+2^(k-1)+2^(k-2)+...+1)/2^k)
     nodes, which is floor((N_l+2^k - 1)/2^k) = 1+floor((N_l-1)/2^k)
     nodes.  We stop when we get to 1 node though.  It seems like there
     should be a bit-twiddling way to calculate this faster, especially
     given that you can go all the way to 64 and correct with a value
     that comes from the MSB, but I couldn't find it.  */
  if( FD_UNLIKELY( leaf_cnt==0UL ) ) return 0UL;
  ulong cnt = 0UL;
  leaf_cnt--;
  for( int i=0; i<64; i++ ) {
    ulong term = leaf_cnt>>i;
    cnt += term;
  }
  cnt += (ulong)(2+fd_ulong_find_msb_w_default(leaf_cnt, -1));
  return cnt;
}

/* bmtree_commit_{footprint,align} return the alignment and footprint
   required for a memory region to be used as a bmtree_commit_t. */
FD_FN_CONST ulong fd_bmtree_commit_align    ( void ) { return alignof(fd_bmtree_commit_t); }

FD_FN_CONST ulong
fd_bmtree_commit_footprint( ulong inclusion_proof_layer_cnt ) {
  /* A complete binary tree with n layers has (2^n)-1 nodes.  We keep 1
     extra bmtree_node_t (included in sizeof(fd_bmtree_commit_t)) to
     avoid branches when appending commits. */
  return fd_ulong_align_up( sizeof(fd_bmtree_commit_t) +
    ( (1UL<<inclusion_proof_layer_cnt)-1UL       )*sizeof(fd_bmtree_node_t) +
    (((1UL<<inclusion_proof_layer_cnt)+63UL)/64UL)*sizeof(ulong),
    fd_bmtree_commit_align() );
}


/* bmtree_commit_init starts a vector commitment calculation */

fd_bmtree_commit_t *    /* Returns mem as a bmtree_commit_t *, commit will be in a calc */
fd_bmtree_commit_init( void * mem,     /* Assumed unused with required alignment and footprint */
                       ulong hash_sz,
                       ulong prefix_sz,
                       ulong inclusion_proof_layer_cnt ) {
  fd_bmtree_commit_t * state = (fd_bmtree_commit_t *) mem;
  ulong inclusion_proof_sz  = (1UL<<inclusion_proof_layer_cnt) - 1UL;
  state->leaf_cnt           = 0UL;
  state->hash_sz            = hash_sz;
  state->prefix_sz          = prefix_sz;
  state->inclusion_proof_sz = inclusion_proof_sz;
  state->inclusion_proofs_valid = (ulong*)(state->inclusion_proofs + inclusion_proof_sz);
  fd_memset( state->inclusion_proofs_valid, 0, sizeof(ulong)*(1UL + inclusion_proof_sz/ipfset_MAX) );
  return state;
}


/* bmtree_commit_append appends a range of leaf nodes.  Assumes that
   leaf_cnt + new_leaf_cnt << 2^63 (which, unless planning on running
   for millenia, is always true). */

fd_bmtree_commit_t *                                            /* Returns state */
fd_bmtree_commit_append( fd_bmtree_commit_t *                 state,           /* Assumed valid and in a calc */
                         fd_bmtree_node_t const * FD_RESTRICT new_leaf,        /* Indexed [0,new_leaf_cnt) */
                         ulong                                new_leaf_cnt ) {
  ulong                          leaf_cnt = state->leaf_cnt;
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

    ulong layer   = 0UL;           /* `layer` starts at 0 (leaf nodes) and increments each iteration. */
    ulong inc_idx = 2UL*leaf_cnt;  /* `inc_idx` is the index of the current node in the inclusion proof array */
    ulong cursor  = ++leaf_cnt;    /* `cursor` is the number of known nodes in the current layer. */
    while( !(cursor & 1UL) ) {     /* Continue while the right node in the last pair is available. */
      state->inclusion_proofs[ fd_ulong_min( inc_idx, state->inclusion_proof_sz ) ] = *tmp;
      fd_bmtree_private_merge( tmp, node_buf + layer, tmp, state->hash_sz, state->prefix_sz );
      inc_idx -= 1UL<<layer; layer++; cursor>>=1;      /* Move up one layer. */
    }

    /* Note on correctness of the above loop: The termination condition
       is that bit zero (LSB) of `cursor` is 1.  Because `cursor` shifts
       right every iteration, the loop terminates as long as any bit in
       `cursor` is set to 1. (i.e. `cursor!=0UL`) */

    /* Emplace left node (could be root node) into buffer.  FIXME:
       Consider computing this location upfront and doing this inplace
       instead of copying at end? (Probably a wash.) */

    node_buf[ layer ] = *tmp;
    state->inclusion_proofs[ fd_ulong_min( inc_idx, state->inclusion_proof_sz ) ] = *tmp;
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
    ulong layer_cnt = leaf_cnt >> layer; /* number of nodes in this layer */
    ulong inc_idx   = (layer_cnt<<(layer+1UL)) - (1UL<<layer) - 1UL;

    /* Allocate temporary node. */
    fd_bmtree_node_t tmp[1];
    *tmp = node_buf[layer];

    /* Ascend until we reach the root node.  Calculate branch nodes
       along the way.  We use the fd_ulong_if to encourage inlining of
       merge and unnecessary branch elimination by cmov. */
    while( layer_cnt>1UL ) {
      fd_bmtree_node_t const * tmp2 = fd_ptr_if( layer_cnt & 1UL, &tmp[0] /* 1 child */, node_buf+layer /* 2 children */ ); /* cmov */
      fd_bmtree_private_merge( tmp, tmp2, tmp, state->hash_sz, state->prefix_sz );

      layer++; layer_cnt = (layer_cnt+1UL) >> 1;

      inc_idx   = (layer_cnt<<(layer+1UL)) - (1UL<<layer) - 1UL;
      state->inclusion_proofs[ fd_ulong_min( inc_idx, state->inclusion_proof_sz ) ] = *tmp;
    }

    /* Fix up root node. */
    *root = *tmp;
  }

  return root->hash;
}

int
fd_bmtree_get_proof( fd_bmtree_commit_t * state,
                     uchar *              dest,
                     ulong                leaf_idx ) {

  ulong leaf_cnt = state->leaf_cnt;
  ulong hash_sz  = state->hash_sz;

  if( FD_UNLIKELY( leaf_idx >= leaf_cnt ) ) return 0UL;

  ulong inc_idx   = leaf_idx * 2UL;
  ulong layer     = 0UL;
  ulong layer_cnt = state->leaf_cnt;

  while( layer_cnt>1UL ) {
    ulong sibling_idx = inc_idx ^ (1UL<<(layer+1UL));
    ulong max_idx_for_layer = fd_ulong_insert_lsb( (leaf_cnt - 1UL)<<1, 1+(int)layer, (1UL<<layer)-1UL );
    sibling_idx = fd_ulong_if( sibling_idx>max_idx_for_layer, inc_idx /* Double link */, sibling_idx );

    if( FD_UNLIKELY( sibling_idx>=state->inclusion_proof_sz ) ) return -1;
    fd_memcpy( dest + layer*hash_sz, state->inclusion_proofs + sibling_idx, hash_sz );

    layer++; layer_cnt = (layer_cnt+1UL)>>1;
    inc_idx = fd_ulong_insert_lsb( inc_idx, (int)layer+1, (1UL<<layer)-1UL );
  }

  return (int)layer;
}

fd_bmtree_node_t *
fd_bmtree_from_proof( fd_bmtree_node_t const * leaf,
                                    ulong                    leaf_idx,
                                    fd_bmtree_node_t *       root,
                                    uchar const *            proof,
                                    ulong                    proof_depth,
                                    ulong                    hash_sz,
                                    ulong                    prefix_sz ) {
  fd_bmtree_node_t tmp[2]; /* 0 stores the generated node, 1 stores the node from the proof */
  fd_bmtree_node_t * tmp_l;
  fd_bmtree_node_t * tmp_r;

  tmp[0] = *leaf;

  if( FD_UNLIKELY( proof_depth < fd_bmtree_depth( leaf_idx+1UL )-1UL ) ) return NULL;

  ulong inc_idx   = leaf_idx * 2UL;
  for( ulong layer=0UL; layer<proof_depth; layer++ ) {
    fd_memcpy( tmp+1, proof + layer*hash_sz, hash_sz );

    tmp_l = fd_ptr_if( 0UL==(inc_idx & (1UL<<(layer+1UL))), tmp+0, tmp+1 );
    tmp_r = fd_ptr_if( 0UL==(inc_idx & (1UL<<(layer+1UL))), tmp+1, tmp+0 );

    fd_bmtree_private_merge( tmp, tmp_l, tmp_r, hash_sz, prefix_sz );

    inc_idx = fd_ulong_insert_lsb( inc_idx, (int)layer+2, (2UL<<layer)-1UL );
  }
  return fd_memcpy( root, tmp, 32UL );
}


/* TODO: Make robust */
#define HAS(inc_idx) (ipfset_test( state->inclusion_proofs_valid[(inc_idx)/64UL], (inc_idx)%64UL ) )

int
fd_bmtree_commitp_insert_with_proof( fd_bmtree_commit_t *     state,
                                     ulong                    idx,
                                     fd_bmtree_node_t const * new_leaf,
                                     uchar            const * proof,
                                     ulong                    proof_depth,
                                     fd_bmtree_node_t       * opt_root ) {
  ulong inc_idx = 2UL * idx;
  ulong inclusion_proof_sz = state->inclusion_proof_sz;
  ulong hash_sz = state->hash_sz;

  if( FD_UNLIKELY( inc_idx >= inclusion_proof_sz ) ) return 0;

  state->node_buf[ 0 ] = *new_leaf;

  ulong layer=0UL;
  for( ; layer<proof_depth; layer++ ) {
    ulong sibling_idx = inc_idx ^ (2UL<<layer);
    if( FD_UNLIKELY( HAS(sibling_idx) && !fd_memeq( proof+hash_sz*layer, state->inclusion_proofs[sibling_idx].hash, hash_sz ) ) )
      return 0;
    if( FD_UNLIKELY( HAS(inc_idx) && !fd_memeq( state->node_buf[layer].hash, state->inclusion_proofs[ inc_idx ].hash, hash_sz ) ) )
      return 0;

    ulong parent_idx = fd_ulong_insert_lsb( inc_idx, (int)layer+2, (2UL<<layer)-1UL );

    if( HAS(sibling_idx) & HAS(inc_idx) ) state->node_buf[ layer+1UL ] = state->inclusion_proofs[ parent_idx ];
    else {
      fd_bmtree_node_t sibling;
      fd_memcpy( sibling.hash, proof+hash_sz*layer, hash_sz );

      fd_bmtree_node_t * tmp_l = fd_ptr_if( 0UL==(inc_idx & (2UL<<layer)), state->node_buf+layer, &sibling );
      fd_bmtree_node_t * tmp_r = fd_ptr_if( 0UL==(inc_idx & (2UL<<layer)), &sibling, state->node_buf+layer );

      fd_bmtree_private_merge( state->node_buf+layer+1UL, tmp_l, tmp_r, state->hash_sz, state->prefix_sz );
    }

    inc_idx = parent_idx;
  }

  for( ; layer<63UL; layer++ ) {
    if( (inc_idx|(2UL<<layer)) >= inclusion_proof_sz    ) break; /* Sibling out of bounds => At root */
    if( HAS( inc_idx ) | !HAS( inc_idx ^ (2UL<<layer) ) ) break; /* Not able to derive any more */

    fd_bmtree_node_t * sibling = state->inclusion_proofs + (inc_idx ^ (2UL<<layer));
    fd_bmtree_node_t * tmp_l = fd_ptr_if( 0UL==(inc_idx & (2UL<<layer)), state->node_buf+layer, sibling );
    fd_bmtree_node_t * tmp_r = fd_ptr_if( 0UL==(inc_idx & (2UL<<layer)), sibling, state->node_buf+layer );
    fd_bmtree_private_merge( state->node_buf+layer+1UL, tmp_l, tmp_r, state->hash_sz, state->prefix_sz );

    inc_idx = fd_ulong_insert_lsb( inc_idx, (int)layer+2, (2UL<<layer)-1UL );
  }
  /* TODO: Prove inc_idx < inclusion_proof_sz at this point */
  if( FD_UNLIKELY( HAS(inc_idx) &&
        !fd_memeq( state->node_buf[layer].hash, state->inclusion_proofs[ inc_idx ].hash, state->hash_sz ) ) )
    return 0;

  /* Cache the nodes from the main branch */
  inc_idx = 2UL * idx;
  for( ulong i=0UL; i<=layer; i++ ) {
    state->inclusion_proofs[ inc_idx ] = state->node_buf[ i ];
    state->inclusion_proofs_valid[inc_idx/64UL] |= ipfset_ele( inc_idx%64UL );
    inc_idx = fd_ulong_insert_lsb( inc_idx, (int)i+2, (2UL<<i)-1UL );
  }

  /* Cache the inclusion proof */
  inc_idx = 2UL * idx;
  for( ulong i=0UL; i<proof_depth; i++ ) {
    ulong sibling_idx = inc_idx ^ (2UL<<i);
    fd_memcpy( state->inclusion_proofs[ sibling_idx ].hash, proof+hash_sz*i, hash_sz );
    state->inclusion_proofs_valid[sibling_idx/64UL] |= ipfset_ele( sibling_idx%64UL );
    inc_idx = fd_ulong_insert_lsb( inc_idx, (int)i+2, (2UL<<i)-1UL );
  }

  if( FD_UNLIKELY( opt_root != NULL ) ) *opt_root = state->node_buf[ layer ];

  return 1;
}

uchar *
fd_bmtree_commitp_fini( fd_bmtree_commit_t * state, ulong leaf_cnt ) {
  ulong inclusion_proof_sz = state->inclusion_proof_sz;
  ulong hash_sz = state->hash_sz;
  fd_bmtree_node_t * node_buf = state->node_buf;

  if( FD_UNLIKELY( leaf_cnt==0UL ) ) return NULL;

  /* Further hashing required if leaf count is not a power of two. */
  if( FD_LIKELY( !fd_ulong_is_pow2( leaf_cnt ) ) ) {

    /* Start at the first layer where number of nodes is odd. */
    ulong layer     = (ulong)fd_ulong_find_lsb( leaf_cnt );
    ulong layer_cnt = leaf_cnt >> layer; /* number of nodes in this layer */
    ulong inc_idx   = (layer_cnt<<(layer+1UL)) - (1UL<<layer) - 1UL;

    /* When you go up and left in the tree, the index decreases.  If you
       are the left child of the parent (the only way you can go up and
       right), then bit 1<<(l+1) is unset, and going up and right will
       not change that.  This means that if you start at a leaf node in
       the right half of the tree (which is always the case for the last
       leaf node), then going up will never go past the next power of 2
       beyond the current one.  Since inclusion_proof_sz is a power of
       2, that means it suffices to check this once and not every time
       we go up the tree. */
    /* TODO: Make this argument more formal */
    if( FD_UNLIKELY( inc_idx >= inclusion_proof_sz ) ) return NULL;

    if( FD_UNLIKELY( !HAS(inc_idx) ) ) return NULL;
    node_buf[layer] = state->inclusion_proofs[inc_idx];

    /* Ascend until we reach the root node.  Calculate branch nodes
       along the way.  We use the fd_ulong_if to encourage inlining of
       merge and unnecessary branch elimination by cmov. */
    while( layer_cnt>1UL ) {
      /* If this is a 2-child parent, make sure we have the sibling. */
      if( FD_UNLIKELY( !(layer_cnt&1UL) & !HAS(inc_idx^(2UL<<layer)) ) ) return NULL;

      fd_bmtree_node_t const * tmp_l = fd_ptr_if( layer_cnt & 1UL, node_buf+layer /* 1 child */, state->inclusion_proofs + (inc_idx^(2UL<<layer))/* 2 children */ ); /* cmov */

      fd_bmtree_private_merge( node_buf+layer+1UL, tmp_l, node_buf+layer, hash_sz, state->prefix_sz );

      layer++; layer_cnt = (layer_cnt+1UL) >> 1;

      inc_idx   = (layer_cnt<<(layer+1UL)) - (1UL<<layer) - 1UL;

      if( FD_UNLIKELY( HAS( inc_idx ) && !fd_memeq( node_buf[layer].hash, state->inclusion_proofs[inc_idx].hash, hash_sz ) ) )
        return NULL;
    }

    /* Cache that path */
    layer     = (ulong)fd_ulong_find_lsb( leaf_cnt );
    layer_cnt = leaf_cnt >> layer; /* number of nodes in this layer */
    inc_idx   = (layer_cnt<<(layer+1UL)) - (1UL<<layer) - 1UL;
    while( layer_cnt>1UL ) {
      layer++; layer_cnt = (layer_cnt+1UL) >> 1;
      inc_idx   = (layer_cnt<<(layer+1UL)) - (1UL<<layer) - 1UL;

      state->inclusion_proofs[inc_idx] = node_buf[layer];
      state->inclusion_proofs_valid[inc_idx/64UL] |= ipfset_ele( inc_idx%64UL );
    }
  }

  /* Now check to make sure we have all the nodes we should */
  ulong root_idx = fd_ulong_pow2_up( leaf_cnt ) - 1UL;
  /* We should definitely have all nodes <= root_idx */
  ulong i=0UL;
  for( ; i<(root_idx+1UL)/64UL; i++ ) if( FD_UNLIKELY( !ipfset_is_full( state->inclusion_proofs_valid[i] ) ) ) return NULL;

  for( ulong layer=0UL; (1UL<<layer)-1UL < root_idx; layer++ ) {
    /* Loop over indices s.t. 64*( (root_idx+1)/64 ) <= index <=  that match the bit
       pattern 01..1 with `layer` 1s */
    ulong min_idx_for_layer = fd_ulong_insert_lsb( 64UL*((root_idx+1UL)/64UL), 1+(int)layer, (1UL<<layer)-1UL );
    ulong max_idx_for_layer = fd_ulong_insert_lsb( (leaf_cnt - 1UL)<<1,        1+(int)layer, (1UL<<layer)-1UL );
    for( ulong inc_idx=min_idx_for_layer; inc_idx<=max_idx_for_layer; inc_idx += 2UL<<layer ) {
      if( FD_UNLIKELY( !HAS(inc_idx) ) ) return NULL;
    }
  }
  /* If the root idx is less than 63, the previous loop doesn't check
     it. */
  if( !HAS( root_idx ) ) return NULL;

  state->leaf_cnt = leaf_cnt;
  return state->inclusion_proofs[root_idx].hash;
}
