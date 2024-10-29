#include "../../ballet/shred/fd_shred.h"
#include "../../ballet/shred/fd_fec_set.h"
#include "../../ballet/bmtree/fd_bmtree.h"
#include "../../ballet/sha512/fd_sha512.h"
#include "../../ballet/ed25519/fd_ed25519.h"
#include "../../ballet/reedsol/fd_reedsol.h"
#include "../metrics/fd_metrics.h"
#include "fd_fec_resolver.h"

#define SHRED_CNT_NOT_SET      (UINT_MAX/2U)

typedef union {
  fd_ed25519_sig_t u;
  ulong            l;
} wrapped_sig_t;

struct set_ctx;
typedef struct set_ctx set_ctx_t;

struct __attribute__((aligned(32UL))) set_ctx {
  wrapped_sig_t         sig;
  fd_fec_set_t *        set;
  fd_bmtree_commit_t  * tree;
  set_ctx_t *           prev;
  set_ctx_t *           next;
  ulong                 total_rx_shred_cnt;
  ulong                 fec_set_idx;
  /* The shred index of the first parity shred in this FEC set */
  ulong                 parity_idx0;
  uchar                 data_variant;
  uchar                 parity_variant;
  /* If this FEC set has resigned shreds, this is our signature of the
     root of the Merkle tree */
  wrapped_sig_t         retransmitter_sig;
};
typedef struct set_ctx set_ctx_t;

#define DEQUE_NAME freelist
#define DEQUE_T    fd_fec_set_t *
#include "../../util/tmpl/fd_deque_dynamic.c"

#define DEQUE_NAME bmtrlist
#define DEQUE_T    void *
#include "../../util/tmpl/fd_deque_dynamic.c"

static const wrapped_sig_t null_signature = {{0}};

#define MAP_KEY               sig
#define MAP_KEY_T             wrapped_sig_t
#define MAP_KEY_NULL          null_signature
#define MAP_KEY_EQUAL(k0,k1)  (!memcmp( (k0).u, (k1).u, FD_ED25519_SIG_SZ ))
#define MAP_KEY_INVAL(k)      MAP_KEY_EQUAL( k, MAP_KEY_NULL )
#define MAP_KEY_EQUAL_IS_SLOW 1
#define MAP_KEY_HASH(key)     ((MAP_HASH_T)fd_ulong_hash( key.l ))
#define MAP_MEMOIZE           0
#define MAP_NAME              ctx_map
#define MAP_T                 set_ctx_t
/* The prev and next fields of set_ctx_t thread a linked list through
   the map.  The map can move elements around during a deletion though,
   so we need to update the links when it does.  Thankfully it gives a
   perfect hook for doing so. */
#define MAP_MOVE(d,s)   do { \
                          set_ctx_t * _d = &(d); \
                          set_ctx_t * _s = &(s); \
                          _s->prev->next = _d;   \
                          _s->next->prev = _d;   \
                          *_d = *_s;             \
                        } while( 0 )
#include "../../util/tmpl/fd_map_dynamic.c"


struct __attribute__((aligned(FD_FEC_RESOLVER_ALIGN))) fd_fec_resolver {
  /* depth stores the number of FEC sets this resolver can track
     simultaneously.  done_depth stores the depth of the done tcache,
     i.e. the number of done FEC set keys that this resolver remembers.
     partial_depth stores the minimum size of the free FEC set list.
     completed_depth stores the size of the completed FEC set list. */
  ulong depth;
  ulong partial_depth;
  ulong complete_depth;
  ulong done_depth;

  /* expected_shred_version: discard all shreds with a shred version
     other than the specified value */
  ushort expected_shred_version;

  /* curr_map: A map (using fd_map_dynamic) from tags of signatures to
     the context object with its relevant data.  This map contains at
     most `depth` elements at any time, but to improve query performance,
     we size it at 2*depth. */
  set_ctx_t * curr_map;

  /* curr_ll_sentinel: The elements of curr_map also make
     essentially a circular doubly linked list using the next and prev
     fields.  To simplify the logic, we use a sentinel node that's
     stored here instead of in the map.  Thus, the head (newest) and the
     tail (oldest) of the linked list are the next and prev pointers of
     this context (respectively).  The other fields aren't used. */
  set_ctx_t curr_ll_sentinel[1];

  /* done: stores signatures of FEC sets that have recently been
     completed.  This is like a tcache, but with a non-ulong key and
     using a linked list instead of a ring buffer. Any new packets
     matching tags in this set can be ignored.  Since the data structure
     we need (map with linked list) is very similar to for curr_map, we
     just use the same fd_map_dynamic instantiation.  Only fields sig,
     prev, and next are used. */
  set_ctx_t * done_map;

  /* done_ll_sentinel: Analogous to curr_ll_sentinel, but for the done
     map instead of the current map. */
  set_ctx_t   done_ll_sentinel[1];

  /* free_list and complete_list are deques (using fd_deque_dynamic)
     that FEC sets that are not in contexts in curr_map.  Similarly,
     bmtree_free_list stores footprints for the bmtree objects that are
     not in contexts in curr_map.  These lists point to objects of
     indeterminate state and need to be cleared/reset when popped off.
     Invariant: at every entry and exit to fd_fec_resolver_add_shred:
     - free_list has between partial_depth and partial_depth+depth
       elements.
     - complete_list has complete_depth elements
     - bmtree_free_list has between 0 and depth elements
     (all these counts are inclusive). */
  fd_fec_set_t * * free_list;
  fd_fec_set_t * * complete_list;
  void         * * bmtree_free_list;

  /* signer is used to sign shreds that require a retransmitter
     signature.  sign_ctx is provided as the first argument to the
     function. */
  fd_fec_resolver_sign_fn * signer;
  void                    * sign_ctx;

  /* max_shred_idx is the exclusive upper bound for shred indices.  We
     need to reject any shred with an index >= max_shred_idx, but we
     also want to reject anything that is part of an FEC set where the
     highest index of a shred in the FEC set will be >= max_shred_idx.
     */
  ulong max_shred_idx;

  /* sha512 and reedsol are used for calculations while adding a shred.
     Their state outside a call to add_shred is indeterminate. */
  fd_sha512_t   sha512[1];
  fd_reedsol_t  reedsol[1];

  /* The footprint for the objects follows the struct and is in the same
     order as the pointers, namely:
       curr_map map
       done_map map
       free_list deque
       complete_list deque
       bmtree_free_list deque
       Actual footprint for bmtrees */
};

typedef struct fd_fec_resolver fd_fec_resolver_t;

ulong
fd_fec_resolver_footprint( ulong depth,
                           ulong partial_depth,
                           ulong complete_depth,
                           ulong done_depth ) {
  if( FD_UNLIKELY( (depth==0UL) | (partial_depth==0UL) | (complete_depth==0UL) | (done_depth==0UL) ) ) return 0UL;
  if( FD_UNLIKELY( (depth>=(1UL<<62)-1UL) | (done_depth>=(1UL<<62)-1UL ) ) ) return 0UL; /* prevent overflow */

  int lg_curr_map_cnt = fd_ulong_find_msb( depth      + 1UL ) + 2; /* See fd_tcache.h for the logic */
  int lg_done_map_cnt = fd_ulong_find_msb( done_depth + 1UL ) + 2; /*  ... behind the + 2. */

  ulong footprint_per_bmtree = fd_bmtree_commit_footprint( FD_SHRED_MERKLE_LAYER_CNT );

  ulong layout = FD_LAYOUT_INIT;
  layout = FD_LAYOUT_APPEND( layout, FD_FEC_RESOLVER_ALIGN,  sizeof(fd_fec_resolver_t)                      );
  layout = FD_LAYOUT_APPEND( layout, ctx_map_align(),        ctx_map_footprint( lg_curr_map_cnt )           );
  layout = FD_LAYOUT_APPEND( layout, ctx_map_align(),        ctx_map_footprint( lg_done_map_cnt )           );
  layout = FD_LAYOUT_APPEND( layout, freelist_align(),       freelist_footprint( depth+partial_depth+1UL )  );
  layout = FD_LAYOUT_APPEND( layout, freelist_align(),       freelist_footprint( complete_depth+1UL  )      );
  layout = FD_LAYOUT_APPEND( layout, bmtrlist_align(),       bmtrlist_footprint( depth+1UL )                );
  layout = FD_LAYOUT_APPEND( layout, FD_BMTREE_COMMIT_ALIGN, depth*footprint_per_bmtree                     );

  return FD_LAYOUT_FINI( layout, FD_FEC_RESOLVER_ALIGN );
}

ulong fd_fec_resolver_align( void ) { return FD_FEC_RESOLVER_ALIGN; }


void *
fd_fec_resolver_new( void                    * shmem,
                     fd_fec_resolver_sign_fn * signer,
                     void                    * sign_ctx,
                     ulong                     depth,
                     ulong                     partial_depth,
                     ulong                     complete_depth,
                     ulong                     done_depth,
                     fd_fec_set_t            * sets,
                     ushort                    expected_shred_version,
                     ulong                     max_shred_idx ) {
  if( FD_UNLIKELY( (depth==0UL) | (partial_depth==0UL) | (complete_depth==0UL) | (done_depth==0UL) ) ) return NULL;
  if( FD_UNLIKELY( (depth>=(1UL<<62)-1UL) | (done_depth>=(1UL<<62)-1UL ) ) ) return NULL;

  int lg_curr_map_cnt = fd_ulong_find_msb( depth      + 1UL ) + 2;
  int lg_done_map_cnt = fd_ulong_find_msb( done_depth + 1UL ) + 2;

  ulong footprint_per_bmtree = fd_bmtree_commit_footprint( FD_SHRED_MERKLE_LAYER_CNT );

  FD_SCRATCH_ALLOC_INIT( l, shmem );
  void * self        = FD_SCRATCH_ALLOC_APPEND( l, FD_FEC_RESOLVER_ALIGN,  sizeof(fd_fec_resolver_t)                       );
  void * curr        = FD_SCRATCH_ALLOC_APPEND( l, ctx_map_align(),        ctx_map_footprint( lg_curr_map_cnt )            );
  void * done        = FD_SCRATCH_ALLOC_APPEND( l, ctx_map_align(),        ctx_map_footprint( lg_done_map_cnt )            );
  void * free        = FD_SCRATCH_ALLOC_APPEND( l, freelist_align(),       freelist_footprint( depth+partial_depth+1UL )   );
  void * cmplst      = FD_SCRATCH_ALLOC_APPEND( l, freelist_align(),       freelist_footprint( complete_depth+1UL  )       );
  void * bmfree      = FD_SCRATCH_ALLOC_APPEND( l, bmtrlist_align(),       bmtrlist_footprint( depth+1UL )                 );
  void * bmfootprint = FD_SCRATCH_ALLOC_APPEND( l, FD_BMTREE_COMMIT_ALIGN, depth*footprint_per_bmtree                      );
  FD_SCRATCH_ALLOC_FINI( l, FD_FEC_RESOLVER_ALIGN );

  fd_fec_resolver_t * resolver = (fd_fec_resolver_t *)self;

  if( FD_UNLIKELY( !ctx_map_new  ( curr,   lg_curr_map_cnt         )) ) { FD_LOG_WARNING(( "curr map_new failed" )); return NULL; }
  if( FD_UNLIKELY( !ctx_map_new  ( done,   lg_done_map_cnt         )) ) { FD_LOG_WARNING(( "done map_new failed" )); return NULL; }
  if( FD_UNLIKELY( !freelist_new ( free,   depth+partial_depth+1UL )) ) { FD_LOG_WARNING(( "freelist_new failed" )); return NULL; }
  if( FD_UNLIKELY( !freelist_new ( cmplst, complete_depth+1UL      )) ) { FD_LOG_WARNING(( "freelist_new failed" )); return NULL; }
  if( FD_UNLIKELY( !bmtrlist_new ( bmfree, depth                   )) ) { FD_LOG_WARNING(( "bmtrlist_new failed" )); return NULL; }
  if( FD_UNLIKELY( !fd_sha512_new( (void *)resolver->sha512        )) ) { FD_LOG_WARNING(( "sha512_new failed"   )); return NULL; }

  /* Initialize all the lists */
  fd_fec_set_t * * free_list     = freelist_join( free   );
  fd_fec_set_t * * complete_list = freelist_join( cmplst );
  for( ulong i=0UL;                 i<depth+partial_depth;                i++ ) { freelist_push_tail( free_list,     sets+i ); }
  for( ulong i=depth+partial_depth; i<depth+partial_depth+complete_depth; i++ ) { freelist_push_tail( complete_list, sets+i ); }
  freelist_leave( complete_list );
  freelist_leave( free_list     );

  void * * bmtree_list = bmtrlist_join( bmfree );
  for( ulong i=0UL; i<depth; i++ ) { bmtrlist_push_tail( bmtree_list, (uchar *)bmfootprint + i*footprint_per_bmtree ); }
  bmtrlist_leave( bmtree_list );

  if( FD_UNLIKELY( expected_shred_version==(ushort)0 ) ) { FD_LOG_WARNING(( "expected shred version cannot be 0" )); return NULL; }

  resolver->curr_ll_sentinel->prev = resolver->curr_ll_sentinel;
  resolver->curr_ll_sentinel->next = resolver->curr_ll_sentinel;
  resolver->done_ll_sentinel->prev = resolver->done_ll_sentinel;
  resolver->done_ll_sentinel->next = resolver->done_ll_sentinel;

  resolver->depth                  = depth;
  resolver->partial_depth          = partial_depth;
  resolver->complete_depth         = complete_depth;
  resolver->done_depth             = done_depth;
  resolver->expected_shred_version = expected_shred_version;
  resolver->signer                 = signer;
  resolver->sign_ctx               = sign_ctx;
  resolver->max_shred_idx          = max_shred_idx;
  return shmem;
}

fd_fec_resolver_t *
fd_fec_resolver_join( void * shmem ) {
  fd_fec_resolver_t * resolver = (fd_fec_resolver_t *)shmem;
  ulong depth          = resolver->depth;
  ulong partial_depth  = resolver->partial_depth;
  ulong complete_depth = resolver->complete_depth;
  ulong done_depth     = resolver->done_depth;

  int lg_curr_map_cnt = fd_ulong_find_msb( depth      + 1UL ) + 2;
  int lg_done_map_cnt = fd_ulong_find_msb( done_depth + 1UL ) + 2;

  FD_SCRATCH_ALLOC_INIT( l, shmem );
  /*     self       */ FD_SCRATCH_ALLOC_APPEND( l, FD_FEC_RESOLVER_ALIGN,  sizeof(fd_fec_resolver_t)                     );
  void * curr        = FD_SCRATCH_ALLOC_APPEND( l, ctx_map_align(),        ctx_map_footprint( lg_curr_map_cnt )          );
  void * done        = FD_SCRATCH_ALLOC_APPEND( l, ctx_map_align(),        ctx_map_footprint( lg_done_map_cnt )          );
  void * free        = FD_SCRATCH_ALLOC_APPEND( l, freelist_align(),       freelist_footprint( depth+partial_depth+1UL ) );
  void * cmplst      = FD_SCRATCH_ALLOC_APPEND( l, freelist_align(),       freelist_footprint( complete_depth+1UL  )     );
  void * bmfree      = FD_SCRATCH_ALLOC_APPEND( l, bmtrlist_align(),       bmtrlist_footprint( depth+1UL )               );
  FD_SCRATCH_ALLOC_FINI( l, FD_FEC_RESOLVER_ALIGN );

  resolver->curr_map         = ctx_map_join  ( curr   ); if( FD_UNLIKELY( !resolver->curr_map         ) ) return NULL;
  resolver->done_map         = ctx_map_join  ( done   ); if( FD_UNLIKELY( !resolver->done_map         ) ) return NULL;
  resolver->free_list        = freelist_join ( free   ); if( FD_UNLIKELY( !resolver->free_list        ) ) return NULL;
  resolver->complete_list    = freelist_join ( cmplst ); if( FD_UNLIKELY( !resolver->complete_list    ) ) return NULL;
  resolver->bmtree_free_list = bmtrlist_join ( bmfree ); if( FD_UNLIKELY( !resolver->bmtree_free_list ) ) return NULL;
  if( FD_UNLIKELY( !fd_sha512_join( resolver->sha512 ) ) ) return NULL;

  return resolver;
}

/* Two helper functions for working with the linked lists that are
   threaded through maps.  Use them as follows:
      ctx_ll_insert( <sentinel corresponding to map>, ctx_map_insert( <map>, key ) );
      ctx_map_remove( <map>, ctx_ll_remove( <node to remove> ) );

  */
/* Removes r from the linked list */
static set_ctx_t *
ctx_ll_remove( set_ctx_t * r ) {
  r->next->prev = r->prev;
  r->prev->next = r->next;
  r->next = NULL;
  r->prev = NULL;
  return r;
}

/* Inserts c immediately after p.  Returns c. */
static set_ctx_t *
ctx_ll_insert( set_ctx_t * p, set_ctx_t * c ) {
  c->next = p->next;
  c->prev = p;
  p->next->prev = c;
  p->next       = c;
  return c;
}


int fd_fec_resolver_add_shred( fd_fec_resolver_t    * resolver,
                               fd_shred_t   const   * shred,
                               ulong                  shred_sz,
                               uchar        const   * leader_pubkey,
                               fd_fec_set_t const * * out_fec_set,
                               fd_shred_t   const * * out_shred ) {
  /* Unpack variables */
  ulong partial_depth = resolver->partial_depth;
  ulong done_depth    = resolver->done_depth;

  fd_fec_set_t * * free_list        = resolver->free_list;
  fd_fec_set_t * * complete_list    = resolver->complete_list;
  void         * * bmtree_free_list = resolver->bmtree_free_list;
  set_ctx_t    *   curr_map         = resolver->curr_map;
  set_ctx_t    *   done_map         = resolver->done_map;

  fd_reedsol_t * reedsol       = resolver->reedsol;
  fd_sha512_t  * sha512        = resolver->sha512;

  set_ctx_t    * curr_ll_sentinel = resolver->curr_ll_sentinel;
  set_ctx_t    * done_ll_sentinel = resolver->done_ll_sentinel;

  /* Invariants:
      * no key is in both the done map and the current map
      * each set pointer provided to the new function is in exactly one
          of curr_map, freelist, or complete_list
      * bmtree_free_list has exactly partial_depth fewer elements than
          freelist
   */
  wrapped_sig_t * w_sig = (wrapped_sig_t *)shred->signature;

  /* Immediately reject any shred with a 0 signature. */
  if( FD_UNLIKELY( ctx_map_key_inval( *w_sig ) ) ) return FD_FEC_RESOLVER_SHRED_REJECTED;

  /* Are we already done with this FEC set? */
  int found = !!ctx_map_query( done_map, *w_sig, NULL );

  if( found )  return FD_FEC_RESOLVER_SHRED_IGNORED; /* With no packet loss, we expect found==1 about 50% of the time */

  set_ctx_t * ctx = ctx_map_query( curr_map, *w_sig, NULL );

  fd_bmtree_node_t leaf[1];
  uchar variant    = shred->variant;
  uchar shred_type = fd_shred_type( variant );

  if( FD_UNLIKELY( (shred_type==FD_SHRED_TYPE_LEGACY_DATA) | (shred_type==FD_SHRED_TYPE_LEGACY_CODE) ) ) {
    /* Reject any legacy shreds */
    return FD_FEC_RESOLVER_SHRED_REJECTED;
  }

  if( FD_UNLIKELY( shred->version!=resolver->expected_shred_version ) ) return FD_FEC_RESOLVER_SHRED_REJECTED;
  if( FD_UNLIKELY( shred_sz<fd_shred_sz( shred )                    ) ) return FD_FEC_RESOLVER_SHRED_REJECTED;
  if( FD_UNLIKELY( shred->idx>=resolver->max_shred_idx              ) ) return FD_FEC_RESOLVER_SHRED_REJECTED;

  int is_data_shred = fd_shred_is_data( shred_type );

  if( !is_data_shred ) { /* Roughly 50/50 branch */
    if( FD_UNLIKELY( (shred->code.data_cnt>FD_REEDSOL_DATA_SHREDS_MAX) | (shred->code.code_cnt>FD_REEDSOL_PARITY_SHREDS_MAX) ) )
      return FD_FEC_RESOLVER_SHRED_REJECTED;
    if( FD_UNLIKELY( (shred->code.data_cnt==0UL) | (shred->code.code_cnt==0UL)                                               ) )
      return FD_FEC_RESOLVER_SHRED_REJECTED;
    if( FD_UNLIKELY( (ulong)shred->fec_set_idx+(ulong)shred->code.data_cnt>=resolver->max_shred_idx                          ) )
      return FD_FEC_RESOLVER_SHRED_REJECTED;
    if( FD_UNLIKELY( (ulong)shred->idx + (ulong)shred->code.code_cnt - (ulong)shred->code.idx>=resolver->max_shred_idx       ) )
      return FD_FEC_RESOLVER_SHRED_REJECTED;
  }


  /* For the purposes of the shred header, tree_depth means the number
     of nodes, counting the leaf but excluding the root.  For bmtree,
     depth means the number of layers, which counts both. */
  ulong tree_depth           = fd_shred_merkle_cnt( variant ); /* In [0, 15] */
  ulong reedsol_protected_sz = 1115UL + FD_SHRED_DATA_HEADER_SZ - FD_SHRED_SIGNATURE_SZ - FD_SHRED_MERKLE_NODE_SZ*tree_depth
                                      - FD_SHRED_MERKLE_ROOT_SZ*fd_shred_is_chained ( shred_type )
                                      - FD_SHRED_SIGNATURE_SZ  *fd_shred_is_resigned( shred_type); /* In [743, 1139] conservatively*/
  ulong data_merkle_protected_sz   = reedsol_protected_sz + FD_SHRED_MERKLE_ROOT_SZ*fd_shred_is_chained ( shred_type );
  ulong parity_merkle_protected_sz = reedsol_protected_sz + FD_SHRED_MERKLE_ROOT_SZ*fd_shred_is_chained ( shred_type )+FD_SHRED_CODE_HEADER_SZ-FD_ED25519_SIG_SZ;
  ulong merkle_protected_sz  = fd_ulong_if( is_data_shred, data_merkle_protected_sz, parity_merkle_protected_sz );

  fd_bmtree_hash_leaf( leaf, (uchar const *)shred + sizeof(fd_ed25519_sig_t), merkle_protected_sz, FD_BMTREE_LONG_PREFIX_SZ );

  /* in_type_idx is between [0, code.data_cnt) or [0, code.code_cnt),
     where data_cnt <= FD_REEDSOL_DATA_SHREDS_MAX and code_cnt <=
     FD_REEDSOL_PARITY_SHREDS_MAX.
     On the other hand, shred_idx, goes from [0, code.data_cnt +
     code.code_cnt), with all the data shreds having
     shred_idx < code.data_cnt and all the parity shreds having
     shred_idx >= code.data_cnt. */
  ulong in_type_idx = fd_ulong_if( is_data_shred, shred->idx - shred->fec_set_idx, shred->code.idx );
  ulong shred_idx   = fd_ulong_if( is_data_shred, in_type_idx, in_type_idx + shred->code.data_cnt  );

  if( FD_UNLIKELY( in_type_idx >= fd_ulong_if( is_data_shred, FD_REEDSOL_DATA_SHREDS_MAX, FD_REEDSOL_PARITY_SHREDS_MAX ) ) )
    return FD_FEC_RESOLVER_SHRED_REJECTED;
  /* This, combined with the check on shred->code.data_cnt implies that
     shred_idx is in [0, DATA_SHREDS_MAX+PARITY_SHREDS_MAX). */

  if( FD_UNLIKELY( tree_depth>FD_SHRED_MERKLE_LAYER_CNT-1UL             ) ) return FD_FEC_RESOLVER_SHRED_REJECTED;
  if( FD_UNLIKELY( fd_bmtree_depth( shred_idx+1UL ) > tree_depth+1UL ) ) return FD_FEC_RESOLVER_SHRED_REJECTED;

  if( FD_UNLIKELY( !ctx ) ) {
    /* This is the first shred in the FEC set */
    if( FD_UNLIKELY( freelist_cnt( free_list )<=partial_depth ) ) {
      /* Packet loss is really high and we have a lot of in-progress FEC
         sets that we haven't been able to finish.  Take the resources
         (FEC set and bmtree) from the oldest, and send the oldest FEC
         set to the back of the free list. */
      set_ctx_t * victim_ctx = resolver->curr_ll_sentinel->prev;

      /* Add this one that we're sacrificing to the done map to
         prevent the possibility of thrashing. */
      ctx_ll_insert( done_ll_sentinel, ctx_map_insert( done_map, victim_ctx->sig ) );
      if( FD_UNLIKELY( ctx_map_key_cnt( done_map ) > done_depth ) ) ctx_map_remove( done_map, ctx_ll_remove( done_ll_sentinel->prev ) );

      freelist_push_tail( free_list,        victim_ctx->set  );
      bmtrlist_push_tail( bmtree_free_list, victim_ctx->tree );

      /* Remove from linked list and then from the map */
      ctx_map_remove( curr_map, ctx_ll_remove( victim_ctx ) );

      FD_MCNT_INC( SHRED, FEC_SET_SPILLED, 1UL );
    }
    /* Now we know |free_list|>partial_depth and |bmtree_free_list|>1 */

    fd_fec_set_t * set_to_use = freelist_pop_head( free_list        );
    void         * bmtree_mem = bmtrlist_pop_head( bmtree_free_list );

    /* Now we need to derive the root of the Merkle tree and verify the
       signature to prevent a DOS attack just by sending lots of invalid
       shreds. */
    fd_bmtree_commit_t * tree;
    tree = fd_bmtree_commit_init( bmtree_mem, FD_SHRED_MERKLE_NODE_SZ, FD_BMTREE_LONG_PREFIX_SZ, FD_SHRED_MERKLE_LAYER_CNT );

    fd_bmtree_node_t _root[1];
    fd_shred_merkle_t const * proof = fd_shred_merkle_nodes( shred );
    int rv = fd_bmtree_commitp_insert_with_proof( tree, shred_idx, leaf, (uchar const *)proof, tree_depth, _root );
    if( FD_UNLIKELY( !rv ) ) {
      freelist_push_head( free_list,        set_to_use );
      bmtrlist_push_head( bmtree_free_list, bmtree_mem );
      FD_MCNT_INC( SHRED, SHRED_REJECTED_INITIAL, 1UL );
      return FD_FEC_RESOLVER_SHRED_REJECTED;
    }

    if( FD_UNLIKELY( FD_ED25519_SUCCESS != fd_ed25519_verify( _root->hash, 32UL, shred->signature, leader_pubkey, sha512 ) ) ) {
      freelist_push_head( free_list,        set_to_use );
      bmtrlist_push_head( bmtree_free_list, bmtree_mem );
      FD_MCNT_INC( SHRED, SHRED_REJECTED_INITIAL, 1UL );
      return FD_FEC_RESOLVER_SHRED_REJECTED;
    }

    /* This seems like a legitimate FEC set, so we can reserve some
       resources for it. */
    ctx = ctx_ll_insert( curr_ll_sentinel, ctx_map_insert( curr_map, *w_sig ) );
    ctx->set  = set_to_use;
    ctx->tree = tree;
    ctx->total_rx_shred_cnt = 0UL;
    ctx->data_variant   = fd_uchar_if(  is_data_shred, variant, fd_shred_variant( fd_shred_swap_type( shred_type ), (uchar)tree_depth ) );
    ctx->parity_variant = fd_uchar_if( !is_data_shred, variant, fd_shred_variant( fd_shred_swap_type( shred_type ), (uchar)tree_depth ) );

    if( FD_UNLIKELY( fd_shred_is_resigned( shred_type ) & !!(resolver->signer) ) ) {
      resolver->signer( resolver->sign_ctx, ctx->retransmitter_sig.u, _root->hash );
    } else {
      fd_memset( ctx->retransmitter_sig.u, 0, 64UL );
    }

    /* Reset the FEC set */
    ctx->set->data_shred_cnt   = SHRED_CNT_NOT_SET;
    ctx->set->parity_shred_cnt = SHRED_CNT_NOT_SET;
    d_rcvd_join( d_rcvd_new( d_rcvd_delete( d_rcvd_leave( ctx->set->data_shred_rcvd   ) ) ) );
    p_rcvd_join( p_rcvd_new( p_rcvd_delete( p_rcvd_leave( ctx->set->parity_shred_rcvd ) ) ) );

  } else {
    /* This is not the first shred in the set */
    /* First, check to make sure this is not a duplicate */
    int shred_dup = fd_int_if( is_data_shred, d_rcvd_test( ctx->set->data_shred_rcvd,   in_type_idx ),
                                              p_rcvd_test( ctx->set->parity_shred_rcvd, in_type_idx ) );

    if( FD_UNLIKELY( shred_dup ) ) return FD_FEC_RESOLVER_SHRED_IGNORED;

    /* Ensure that all the shreds in the FEC set have consistent
       variants.  They all must have the same tree_depth and the same
       chained/not chained, resigned/not resigned bits. */
    if( FD_UNLIKELY( variant!=fd_uchar_if( is_data_shred, ctx->data_variant, ctx->parity_variant ) ) ) {
      return FD_FEC_RESOLVER_SHRED_REJECTED;
    }

    fd_shred_merkle_t const * proof = fd_shred_merkle_nodes( shred );
    int rv = fd_bmtree_commitp_insert_with_proof( ctx->tree, shred_idx, leaf, (uchar const *)proof, tree_depth, NULL );
    if( !rv ) return FD_FEC_RESOLVER_SHRED_REJECTED;
  }

  if( FD_UNLIKELY( (ctx->set->data_shred_cnt==SHRED_CNT_NOT_SET) & (!is_data_shred) ) ) {
    ctx->set->data_shred_cnt   = shred->code.data_cnt;
    ctx->set->parity_shred_cnt = shred->code.code_cnt;
    ctx->parity_idx0           = shred->idx - in_type_idx;
    ctx->fec_set_idx           = shred->fec_set_idx;
  }

  /* At this point, the shred has passed Merkle validation and is new.
     We also know that ctx is a pointer to the slot for signature in the
     current map. */

  /* Copy the shred to memory the FEC resolver owns */
  uchar * dst = fd_ptr_if( is_data_shred, ctx->set->data_shreds[ in_type_idx ], ctx->set->parity_shreds[ in_type_idx ] );
  fd_memcpy( dst, shred, fd_shred_sz( shred ) );

  /* If the shred needs a retransmitter signature, set it */
  if( FD_UNLIKELY( fd_shred_is_resigned( shred_type ) ) ) {
    memcpy( dst + fd_shred_retransmitter_sig_off( (fd_shred_t *)dst ), ctx->retransmitter_sig.u, 64UL );
  }

  d_rcvd_insert_if( ctx->set->data_shred_rcvd,    is_data_shred, in_type_idx );
  p_rcvd_insert_if( ctx->set->parity_shred_rcvd, !is_data_shred, in_type_idx );
  ctx->total_rx_shred_cnt++;

  *out_shred = (fd_shred_t const *)dst;

  /* Do we have enough to begin reconstruction? */
  if( FD_LIKELY( ctx->total_rx_shred_cnt < ctx->set->data_shred_cnt ) ) return FD_FEC_RESOLVER_SHRED_OKAY;

  /* At this point, the FEC set is either valid or permanently invalid,
     so we can consider it done either way.  First though, since ctx_map_remove
     can change what's at *ctx, so unpack the values before we do that */
  fd_fec_set_t        * set            = ctx->set;
  fd_bmtree_commit_t  * tree           = ctx->tree;
  ulong                 fec_set_idx    = ctx->fec_set_idx;
  ulong                 parity_idx0    = ctx->parity_idx0;
  wrapped_sig_t         retran_sig     = ctx->retransmitter_sig;
  uchar                 parity_variant = ctx->parity_variant;
  uchar                 data_variant   = ctx->data_variant;

  ctx_ll_insert( done_ll_sentinel, ctx_map_insert( done_map, ctx->sig ) );
  if( FD_UNLIKELY( ctx_map_key_cnt( done_map ) > done_depth ) ) ctx_map_remove( done_map, ctx_ll_remove( done_ll_sentinel->prev ) );

  ctx_map_remove( curr_map, ctx_ll_remove( ctx ) );

  reedsol = fd_reedsol_recover_init( (void*)reedsol, reedsol_protected_sz );
  for( ulong i=0UL; i<set->data_shred_cnt; i++ ) {
    uchar * rs_payload = set->data_shreds[ i ] + sizeof(fd_ed25519_sig_t);
    if( d_rcvd_test( set->data_shred_rcvd, i ) ) fd_reedsol_recover_add_rcvd_shred  ( reedsol, 1, rs_payload );
    else                                         fd_reedsol_recover_add_erased_shred( reedsol, 1, rs_payload );
  }
  for( ulong i=0UL; i<set->parity_shred_cnt; i++ ) {
    uchar * rs_payload = set->parity_shreds[ i ] + FD_SHRED_CODE_HEADER_SZ;
    if( p_rcvd_test( set->parity_shred_rcvd, i ) ) fd_reedsol_recover_add_rcvd_shred  ( reedsol, 0, rs_payload );
    else                                           fd_reedsol_recover_add_erased_shred( reedsol, 0, rs_payload );
  }

  if( FD_UNLIKELY( FD_REEDSOL_SUCCESS != fd_reedsol_recover_fini( reedsol ) ) ) {
    /* A few lines up, we already checked to make sure it wasn't the
       insufficient case, so it must be the inconsistent case.  That
       means the leader signed a shred with invalid Reed-Solomon FEC
       set.  This shouldn't happen in practice, but we need to handle it
       for the malicious leader case.  This should probably be a
       slash-able offense. */
    freelist_push_tail( free_list,        set  );
    bmtrlist_push_tail( bmtree_free_list, tree );
    FD_MCNT_INC( SHRED, FEC_REJECTED_FATAL, 1UL );
    return FD_FEC_RESOLVER_SHRED_REJECTED;
  }

  uchar const * chained_root = fd_ptr_if( fd_shred_is_chained( shred_type ), (uchar *)shred+fd_shred_chain_offset( variant ), NULL );

  /* Iterate over recovered shreds, add them to the Merkle tree,
     populate headers and signatures. */
  for( ulong i=0UL; i<set->data_shred_cnt; i++ ) {
    if( !d_rcvd_test( set->data_shred_rcvd, i ) ) {
      fd_memcpy( set->data_shreds[i], shred, sizeof(fd_ed25519_sig_t) );
      if( FD_UNLIKELY( fd_shred_is_chained( shred_type ) ) ) {
        fd_memcpy( set->data_shreds[i]+fd_shred_chain_offset( data_variant ), chained_root, FD_SHRED_MERKLE_ROOT_SZ );
      }
      fd_bmtree_hash_leaf( leaf, set->data_shreds[i]+sizeof(fd_ed25519_sig_t), data_merkle_protected_sz, FD_BMTREE_LONG_PREFIX_SZ );
      if( FD_UNLIKELY( !fd_bmtree_commitp_insert_with_proof( tree, i, leaf, NULL, 0, NULL ) ) ) {
        freelist_push_tail( free_list,        set  );
        bmtrlist_push_tail( bmtree_free_list, tree );
        FD_MCNT_INC( SHRED, FEC_REJECTED_FATAL, 1UL );
        return FD_FEC_RESOLVER_SHRED_REJECTED;
      }

    }
  }

  for( ulong i=0UL; i<set->parity_shred_cnt; i++ ) {
    if( !p_rcvd_test( set->parity_shred_rcvd, i ) ) {
      fd_shred_t * p_shred = (fd_shred_t *)set->parity_shreds[i]; /* We can't parse because we haven't populated the header */
      fd_memcpy( p_shred->signature, shred->signature, sizeof(fd_ed25519_sig_t) );
      p_shred->variant       = parity_variant;
      p_shred->slot          = shred->slot;
      p_shred->idx           = (uint)(i + parity_idx0);
      p_shred->version       = shred->version;
      p_shred->fec_set_idx   = (uint)fec_set_idx;
      p_shred->code.data_cnt = (ushort)set->data_shred_cnt;
      p_shred->code.code_cnt = (ushort)set->parity_shred_cnt;
      p_shred->code.idx      = (ushort)i;

      if( FD_UNLIKELY( fd_shred_is_chained( shred_type ) ) ) {
        fd_memcpy( set->parity_shreds[i]+fd_shred_chain_offset( parity_variant ), chained_root, FD_SHRED_MERKLE_ROOT_SZ );
      }

      fd_bmtree_hash_leaf( leaf, set->parity_shreds[i]+ sizeof(fd_ed25519_sig_t), parity_merkle_protected_sz, FD_BMTREE_LONG_PREFIX_SZ );
      if( FD_UNLIKELY( !fd_bmtree_commitp_insert_with_proof( tree, set->data_shred_cnt + i, leaf, NULL, 0, NULL ) ) ) {
        freelist_push_tail( free_list,        set  );
        bmtrlist_push_tail( bmtree_free_list, tree );
        FD_MCNT_INC( SHRED, FEC_REJECTED_FATAL, 1UL );
        return FD_FEC_RESOLVER_SHRED_REJECTED;
      }
    }
  }

  /* Check that the whole Merkle tree is consistent. */
  if( FD_UNLIKELY( !fd_bmtree_commitp_fini( tree, set->data_shred_cnt + set->parity_shred_cnt ) ) ) {
    freelist_push_tail( free_list,        set  );
    bmtrlist_push_tail( bmtree_free_list, tree );
    FD_MCNT_INC( SHRED, FEC_REJECTED_FATAL, 1UL );
    return FD_FEC_RESOLVER_SHRED_REJECTED;
  }

  /* Check that all the fields that are supposed to be consistent across
     an FEC set actually are. */
  fd_shred_t const * base_data_shred   = fd_shred_parse( set->data_shreds  [ 0 ], FD_SHRED_MIN_SZ );
  fd_shred_t const * base_parity_shred = fd_shred_parse( set->parity_shreds[ 0 ], FD_SHRED_MAX_SZ );
  int reject = (!base_data_shred) | (!base_parity_shred);

  for( ulong i=1UL; (!reject) & (i<set->data_shred_cnt); i++ ) {
    /* Technically, we only need to re-parse the ones we recovered with
       Reedsol, but parsing is pretty cheap and the rest of the
       validation we need to do on all of them. */
    fd_shred_t const * parsed = fd_shred_parse( set->data_shreds[ i ], FD_SHRED_MIN_SZ );
    if( FD_UNLIKELY( !parsed ) ) { reject = 1; break; }
    reject |= parsed->variant         != base_data_shred->variant;
    reject |= parsed->slot            != base_data_shred->slot;
    reject |= parsed->version         != base_data_shred->version;
    reject |= parsed->fec_set_idx     != base_data_shred->fec_set_idx;
    reject |= parsed->data.parent_off != base_data_shred->data.parent_off;

    reject |= fd_shred_is_chained( fd_shred_type( parsed->variant ) ) &&
                !fd_memeq( (uchar *)parsed         +fd_shred_chain_offset( parsed->variant          ),
                           (uchar *)base_data_shred+fd_shred_chain_offset( base_data_shred->variant ), FD_SHRED_MERKLE_ROOT_SZ );
  }
  for( ulong i=0UL; (!reject) & (i<set->parity_shred_cnt); i++ ) {
    fd_shred_t const * parsed = fd_shred_parse( set->parity_shreds[ i ], FD_SHRED_MAX_SZ );
    if( FD_UNLIKELY( !parsed ) ) { reject = 1; break; }
    reject |= fd_shred_type( parsed->variant )       != fd_shred_swap_type( fd_shred_type( base_data_shred->variant ) );
    reject |= fd_shred_merkle_cnt( parsed->variant ) != fd_shred_merkle_cnt( base_data_shred->variant );
    reject |= parsed->slot                           != base_data_shred->slot;
    reject |= parsed->version                        != base_data_shred->version;
    reject |= parsed->fec_set_idx                    != base_data_shred->fec_set_idx;
    reject |= parsed->code.data_cnt                  != base_parity_shred->code.data_cnt;
    reject |= parsed->code.code_cnt                  != base_parity_shred->code.code_cnt;
    reject |= parsed->code.idx                       != (ushort)i;

    reject |= fd_shred_is_chained( fd_shred_type( parsed->variant ) ) &&
                !fd_memeq( (uchar *)parsed         +fd_shred_chain_offset( parsed->variant          ),
                           (uchar *)base_data_shred+fd_shred_chain_offset( base_data_shred->variant ), FD_SHRED_MERKLE_ROOT_SZ );
  }
  if( FD_UNLIKELY( reject ) ) {
    freelist_push_tail( free_list,        set  );
    bmtrlist_push_tail( bmtree_free_list, tree );
    FD_MCNT_INC( SHRED, FEC_REJECTED_FATAL, 1UL );
    return FD_FEC_RESOLVER_SHRED_REJECTED;
  }

  /* Populate missing Merkle proofs */
  for( ulong i=0UL; i<set->data_shred_cnt; i++ ) if( !d_rcvd_test( set->data_shred_rcvd, i ) )
    fd_bmtree_get_proof( tree, set->data_shreds[i]   + fd_shred_merkle_off( (fd_shred_t *)set->data_shreds[i] ), i );

  for( ulong i=0UL; i<set->parity_shred_cnt; i++ ) if( !p_rcvd_test( set->parity_shred_rcvd, i ) )
    fd_bmtree_get_proof( tree, set->parity_shreds[i] + fd_shred_merkle_off( (fd_shred_t *)set->parity_shreds[i] ), set->data_shred_cnt+i );

  /* Set the retransmitter signature for shreds that need one */
  if( FD_UNLIKELY( fd_shred_is_resigned( shred_type ) ) ) {
    for( ulong i=0UL; i<set->data_shred_cnt; i++ ) if( !d_rcvd_test( set->data_shred_rcvd, i ) )
      memcpy( set->data_shreds[i]   + fd_shred_retransmitter_sig_off( (fd_shred_t *)set->data_shreds[i]   ), retran_sig.u, 64UL );

    for( ulong i=0UL; i<set->parity_shred_cnt; i++ ) if( !p_rcvd_test( set->parity_shred_rcvd, i ) )
      memcpy( set->parity_shreds[i] + fd_shred_retransmitter_sig_off( (fd_shred_t *)set->parity_shreds[i] ), retran_sig.u, 64UL );
  }

  /* Finally... A valid FEC set.  Forward it along. */
  bmtrlist_push_tail( bmtree_free_list, tree );
  freelist_push_tail( complete_list, set );
  freelist_push_tail( free_list, freelist_pop_head( complete_list ) );

  *out_fec_set = set;

  return FD_FEC_RESOLVER_SHRED_COMPLETES;
}

void * fd_fec_resolver_leave( fd_fec_resolver_t * resolver ) {
  fd_sha512_leave( resolver->sha512           );
  bmtrlist_leave ( resolver->bmtree_free_list );
  freelist_leave ( resolver->complete_list    );
  freelist_leave ( resolver->free_list        );
  ctx_map_leave  ( resolver->done_map         );
  ctx_map_leave  ( resolver->curr_map         );

  return (void *)resolver;
}

void * fd_fec_resolver_delete( void * shmem ) {
  fd_fec_resolver_t * resolver = (fd_fec_resolver_t *)shmem;
  ulong depth          = resolver->depth;
  ulong partial_depth  = resolver->partial_depth;
  ulong complete_depth = resolver->complete_depth;
  ulong done_depth     = resolver->done_depth;

  int lg_curr_map_cnt = fd_ulong_find_msb( depth      + 1UL ) + 2;
  int lg_done_map_cnt = fd_ulong_find_msb( done_depth + 1UL ) + 2;

  FD_SCRATCH_ALLOC_INIT( l, shmem );
  /*     self       */ FD_SCRATCH_ALLOC_APPEND( l, FD_FEC_RESOLVER_ALIGN,  sizeof(fd_fec_resolver_t)                     );
  void * curr        = FD_SCRATCH_ALLOC_APPEND( l, ctx_map_align(),        ctx_map_footprint( lg_curr_map_cnt )          );
  void * done        = FD_SCRATCH_ALLOC_APPEND( l, ctx_map_align(),        ctx_map_footprint( lg_done_map_cnt )          );
  void * free        = FD_SCRATCH_ALLOC_APPEND( l, freelist_align(),       freelist_footprint( depth+partial_depth+1UL ) );
  void * cmplst      = FD_SCRATCH_ALLOC_APPEND( l, freelist_align(),       freelist_footprint( complete_depth+1UL  )     );
  void * bmfree      = FD_SCRATCH_ALLOC_APPEND( l, bmtrlist_align(),       bmtrlist_footprint( depth+1UL )               );
  FD_SCRATCH_ALLOC_FINI( l, FD_FEC_RESOLVER_ALIGN );

  fd_sha512_delete( resolver->sha512 );
  bmtrlist_delete ( bmfree           );
  freelist_delete ( cmplst           );
  freelist_delete ( free             );
  ctx_map_delete  ( done             );
  ctx_map_delete  ( curr             );

  return shmem;
}
