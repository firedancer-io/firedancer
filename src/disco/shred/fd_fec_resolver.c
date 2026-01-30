#include "../../ballet/shred/fd_shred.h"
#include "fd_fec_set.h"
#include "../../ballet/sha512/fd_sha512.h"
#include "../../ballet/reedsol/fd_reedsol.h"
#include "../metrics/fd_metrics.h"
#include "fd_fec_resolver.h"

typedef union {
  fd_ed25519_sig_t u;
  ulong            l;
} wrapped_sig_t;

typedef struct __attribute__((packed)) {
  ulong slot;
  uint fec_idx;
} slot_fec_pair_t;

struct __attribute__((aligned(32UL))) set_ctx {
  /* The leader's signature of the root of the Merkle tree of the shreds
     in this FEC set. */
  wrapped_sig_t         sig;

  union {
    /* When allocated, it's in a map_chain by signature and a treap
       by (shred, FEC set idx).  When it's not allocated, it is either
       in the free list or the completed list.  Both of those slists use
       free_next. */
    struct {
      uint              map_next;
      uint              map_prev;
      uint              treap_parent;
      uint              treap_left;
      uint              treap_right;
      uint              treap_prio;
    };
    struct {
      uint              free_next;
    };
  };

  ulong                 slot;
  uint                  fec_set_idx;

  uchar                 data_variant;
  uchar                 parity_variant;

  ulong                 total_rx_shred_cnt;

  fd_fec_set_t *        set;

  fd_bmtree_node_t      root;
  /* If this FEC set has resigned shreds, this is our signature of the
     root of the Merkle tree */
  wrapped_sig_t         retransmitter_sig;

  union {
    fd_bmtree_commit_t  tree[1];
    uchar               _footprint[ FD_BMTREE_COMMIT_FOOTPRINT( FD_SHRED_MERKLE_LAYER_CNT ) ] __attribute__((aligned(FD_BMTREE_COMMIT_ALIGN)));
  };
};
typedef struct set_ctx set_ctx_t;

#define MAP_NAME              ctx_map
#define MAP_KEY               sig
#define MAP_KEY_T             wrapped_sig_t
#define MAP_IDX_T             uint
#define MAP_NEXT              map_next
#define MAP_PREV              map_prev
#define MAP_ELE_T             set_ctx_t
#define MAP_KEY_EQ(k0,k1)    (!memcmp( (k0)->u, (k1)->u, FD_ED25519_SIG_SZ ))
#define MAP_KEY_HASH(key,s)  (fd_ulong_hash( (key)->l ^ (s) ))
#define MAP_OPTIMIZE_RANDOM_ACCESS_REMOVAL 1
#include "../../util/tmpl/fd_map_chain.c"


#define SLIST_NAME  ctx_list
#define SLIST_ELE_T set_ctx_t
#define SLIST_IDX_T uint
#define SLIST_NEXT  free_next
#include "../../util/tmpl/fd_slist.c"


static inline int
slot_fec_pair_compare( slot_fec_pair_t const * q,
                       set_ctx_t       const * e ) {
  /* It seems like
     return (int)( q->slot!=e->slot ?
                   q->slot    - e->slot :
                   q->fec_idx - e->fec_set_idx );
     should work, but I am concerned about overflow since this is all
     attacker controlled input. */
  if( FD_LIKELY( q->slot   !=e->slot        ) ) return fd_int_if( q->slot   <e->slot,        -1, 1 );
  if( FD_LIKELY( q->fec_idx!=e->fec_set_idx ) ) return fd_int_if( q->fec_idx<e->fec_set_idx, -1, 1 );
  return 0;
}

#define TREAP_NAME       ctx_treap
#define TREAP_T          set_ctx_t
#define TREAP_IDX_T      uint
#define TREAP_PARENT     treap_parent
#define TREAP_LEFT       treap_left
#define TREAP_RIGHT      treap_right
#define TREAP_PRIO       treap_prio
#define TREAP_LT(e0,e1)  (((e0)->slot < (e1)->slot) | ( ((e0)->slot==(e1)->slot) & ((e0)->fec_set_idx < (e1)->fec_set_idx)))
#define TREAP_QUERY_T    slot_fec_pair_t const *
#define TREAP_CMP(q,e)   slot_fec_pair_compare( (q), (e) )
#include "../../util/tmpl/fd_treap.c"



/* Once we're done with a FEC set, it goes into a map_chain and heap,
   both keyed by (slot, FEC set idx). */

struct done_ele {
  slot_fec_pair_t key;
  uint            heap_left; /* also used by pool when not allocated */
  uint            heap_right;
  uint            map_next;
  uint            map_prev;
  /* In order to save space in the done_map and make this struct 32
     bytes, we store a 32 bit validator-specific hash of the shred
     signature.  If a malicious leader equivocates and produces two FEC
     sets which have the same hash for us, a task which takes a decent
     but doable amount of effort, the only impact is that we would
     reject the shreds with SHRED_IGNORED instead of SHRED_EQUIOC, which
     is not a big deal.  It's documented that SHRED_EQUIVOC detection is
     on a best-effort basis. */
  uint           sig_hash;
};
typedef struct done_ele done_ele_t;

#define MAP_NAME              done_map
#define MAP_KEY               key
#define MAP_KEY_T             slot_fec_pair_t
#define MAP_IDX_T             uint
#define MAP_NEXT              map_next
#define MAP_PREV              map_prev
#define MAP_ELE_T             done_ele_t
#define MAP_KEY_EQ(k0,k1)     ( ((k0)->slot==(k1)->slot) & ((k0)->fec_idx==(k1)->fec_idx) )
#define MAP_KEY_HASH(key,s)  ((fd_ulong_hash( (key)->slot ^ (s) ) ^ fd_uint_hash( (key)->fec_idx ^ (uint)(s>>19) )))
#define MAP_OPTIMIZE_RANDOM_ACCESS_REMOVAL 1
#include "../../util/tmpl/fd_map_chain.c"

#define HEAP_NAME             done_heap
#define HEAP_IDX_T            uint
#define HEAP_LEFT             heap_left
#define HEAP_RIGHT            heap_right
#define HEAP_T                done_ele_t
#define HEAP_LT(e0,e1)       (((e0)->key.slot < (e1)->key.slot) | \
                            ( ((e0)->key.slot==(e1)->key.slot) & ((e0)->key.fec_idx < (e1)->key.fec_idx)))
#include "../../util/tmpl/fd_heap.c"

#define POOL_NAME             done_pool
#define POOL_T                done_ele_t
#define POOL_IDX_T            uint
#define POOL_NEXT             heap_left
#include "../../util/tmpl/fd_pool.c"

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

  /* ctx_pool: A flat array (not an fd_pool) of the set_ctx_t
     structures used to back ctx_map, ctx_treap, and the ctx
     freelists. */
  set_ctx_t * ctx_pool;

  /* ctx_map: A map (using fd_map_chain) from signatures to
     the context object with its relevant data for in progress FEC sets.
     This map contains at most `depth` elements at any time. */
  ctx_map_t * ctx_map;

  /* ctx_treap: A treap (using fd_treap) of the context objects for in
     progress FEC sets.  They are sorted by (slot, FEC index) from
     smallest to largest.  In the case of equivocation, multiple
     elements with the same key may be present, with no particular
     ordering between them. */
  ctx_treap_t ctx_treap[1];

  /* free_list and complete_list are slists (using fd_slist)
     of FEC set contexts that are not in ctx_map.  See the long comment
     in the header for why there are two.  In order to satisfy the
     invariants, technically we only need to store the FEC set memory,
     not the full context, but it's not that big of a difference
     (especially if partial_depth and complete_depth are small), and it
     simplifies memory management.

     Invariant: at every entry and exit to fd_fec_resolver_add_shred:
     - free_list has between partial_depth and partial_depth+depth
       elements.
     - complete_list has complete_depth elements
       (all these counts are inclusive). */
  ctx_list_t  free_list[1];
  ctx_list_t  complete_list[1];

  /* free_list_cnt: The number of items in free_list. */
  ulong free_list_cnt;

  /* done_pool: A pool (this time using fd_pool) of the done_ele_t
     elements that back done_map and done_heap.  Invariant: each element
     is either (i) released and in the pool, or (ii) in both the
     done_map and done_heap. */
  done_ele_t * done_pool;

  /* done_map: A map (using fd_map_chain) mapping (slot, fec_idx) to an
     element of done_pool.  Even in the presence of equivocation, a
     specific (slot, fec_idx) tuple occurs at most once in the map,
     and it's arbitrary which version is represented by sig_hash.  In
     the presence of equivocation, the right shreds are probably being
     delivered using repair, which will bypass reading the sig_hash
     field, so it doesn't really matter. */
  done_map_t * done_map;

  /* done_heap: A min heap (using fd_heap) based on (slot, fec_idx) used
     to stop tracking done elements older than slot_old, and for
     eviction in the unlikely case that we run out of elements in the
     done_map. */
  done_heap_t done_heap[1];

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

  /* slot_old: slot_old is the lowest slot for which shreds will be
     accepted.  That is any shred with slot<slot_old is rejected by
     add_shred with INGORED.  slot_old can only increase. */
  ulong slot_old;

  /* seed: done_map uses seed to compute a 32-bute hash of the FEC set's
     signature. */
  ulong seed;

  /* sha512 and reedsol are used for calculations while adding a shred.
     Their state outside a call to add_shred is indeterminate. */
  fd_sha512_t   sha512[1];
  fd_reedsol_t  reedsol[1];

  /* The footprint for the objects follows the struct and is in the same
     order as the pointers, namely:
       ctx_pool
       ctx_map
       done_pool
       done_map */
};

typedef struct fd_fec_resolver fd_fec_resolver_t;

FD_FN_PURE ulong
fd_fec_resolver_footprint( ulong depth,
                           ulong partial_depth,
                           ulong complete_depth,
                           ulong done_depth ) {
  if( FD_UNLIKELY( (depth==0UL) | (partial_depth==0UL) | (complete_depth==0UL) | (done_depth==0UL) ) ) return 0UL;
  if( FD_UNLIKELY( (depth>UINT_MAX) | (partial_depth>UINT_MAX) | (complete_depth>UINT_MAX)         ) ) return 0UL;

  ulong depth_sum = depth + partial_depth + complete_depth;
  if( FD_UNLIKELY( depth_sum>=UINT_MAX ) ) return 0UL;

  ulong ctx_chain_cnt  = ctx_map_chain_cnt_est ( depth      );
  ulong done_chain_cnt = done_map_chain_cnt_est( done_depth );

  ulong layout = FD_LAYOUT_INIT;
  layout = FD_LAYOUT_APPEND( layout, FD_FEC_RESOLVER_ALIGN,  sizeof(fd_fec_resolver_t)             );
  layout = FD_LAYOUT_APPEND( layout, alignof(set_ctx_t),     sizeof(set_ctx_t)*depth_sum           );
  layout = FD_LAYOUT_APPEND( layout, ctx_map_align(),        ctx_map_footprint  ( ctx_chain_cnt  ) );
  layout = FD_LAYOUT_APPEND( layout, done_pool_align(),      done_pool_footprint( done_depth     ) );
  layout = FD_LAYOUT_APPEND( layout, done_map_align(),       done_map_footprint ( done_chain_cnt ) );

  return FD_LAYOUT_FINI( layout, FD_FEC_RESOLVER_ALIGN );
}

FD_FN_CONST ulong fd_fec_resolver_align( void ) { return FD_FEC_RESOLVER_ALIGN; }


void *
fd_fec_resolver_new( void                    * shmem,
                     fd_fec_resolver_sign_fn * signer,
                     void                    * sign_ctx,
                     ulong                     depth,
                     ulong                     partial_depth,
                     ulong                     complete_depth,
                     ulong                     done_depth,
                     fd_fec_set_t            * sets,
                     ulong                     max_shred_idx,
                     ulong                     seed ) {
  if( FD_UNLIKELY( (depth==0UL) | (partial_depth==0UL) | (complete_depth==0UL) | (done_depth==0UL) ) ) return NULL;
  if( FD_UNLIKELY( (depth>UINT_MAX) | (partial_depth>UINT_MAX) | (complete_depth>UINT_MAX)         ) ) return NULL;

  ulong depth_sum = depth + partial_depth + complete_depth;
  if( FD_UNLIKELY( depth_sum>=UINT_MAX ) ) return NULL;

  ulong ctx_chain_cnt  = ctx_map_chain_cnt_est ( depth      );
  ulong done_chain_cnt = done_map_chain_cnt_est( done_depth );

                                                              /* round( 2^64 * ... */
  ulong seed0 = fd_ulong_hash( seed +  7640891576956012809UL );  /* sqrt(2)-1 */
  ulong seed1 = fd_ulong_hash( seed + 13503953896175478587UL );  /* sqrt(3)-1 */
  ulong seed2 = fd_ulong_hash( seed +  4354685564936845356UL );  /* sqrt(5)-2 */
  ulong seed3 = fd_ulong_hash( seed + 11912009170470909682UL );  /* sqrt(7)-2 */

  FD_SCRATCH_ALLOC_INIT( l, shmem );
  void * self        = FD_SCRATCH_ALLOC_APPEND( l, FD_FEC_RESOLVER_ALIGN,  sizeof(fd_fec_resolver_t)                 );
  void * _ctx_pool   = FD_SCRATCH_ALLOC_APPEND( l, alignof(set_ctx_t),     sizeof(set_ctx_t)*depth_sum               );
  void * _ctx_map    = FD_SCRATCH_ALLOC_APPEND( l, ctx_map_align(),        ctx_map_footprint  ( ctx_chain_cnt  ) );
  void * _done_pool  = FD_SCRATCH_ALLOC_APPEND( l, done_pool_align(),      done_pool_footprint( done_depth         ) );
  void * _done_map   = FD_SCRATCH_ALLOC_APPEND( l, done_map_align(),       done_map_footprint ( done_chain_cnt ) );
  FD_SCRATCH_ALLOC_FINI( l, FD_FEC_RESOLVER_ALIGN );

  fd_fec_resolver_t * resolver = (fd_fec_resolver_t *)self;
  void * _ctx_treap     = resolver->ctx_treap;
  void * _free_list     = resolver->free_list;
  void * _complete_list = resolver->complete_list;
  void * _done_heap     = resolver->done_heap;

  if( FD_UNLIKELY( !ctx_map_new  ( _ctx_map, ctx_chain_cnt, seed0   ) ) ) { FD_LOG_WARNING(( "ctx_map_new fail"   )); return NULL; }
  if( FD_UNLIKELY( !ctx_treap_new( _ctx_treap, depth_sum            ) ) ) { FD_LOG_WARNING(( "ctx_treap_new fail" )); return NULL; }
  if( FD_UNLIKELY( !ctx_list_new ( _free_list                       ) ) ) { FD_LOG_WARNING(( "ctx_list_new fail"  )); return NULL; }
  if( FD_UNLIKELY( !ctx_list_new ( _complete_list                   ) ) ) { FD_LOG_WARNING(( "ctx_list_new fail"  )); return NULL; }
  if( FD_UNLIKELY( !done_pool_new( _done_pool, done_depth           ) ) ) { FD_LOG_WARNING(( "done_pool_new fail" )); return NULL; }
  if( FD_UNLIKELY( !done_map_new ( _done_map, done_chain_cnt, seed1 ) ) ) { FD_LOG_WARNING(( "done_map_new fail"  )); return NULL; }
  if( FD_UNLIKELY( !done_heap_new( _done_heap, done_depth           ) ) ) { FD_LOG_WARNING(( "done_heap_new fail" )); return NULL; }

  set_ctx_t * ctx_pool = (set_ctx_t *)_ctx_pool;
  fd_memset( ctx_pool, '\0', sizeof(set_ctx_t)*depth_sum );
  for( ulong i=0UL; i<depth_sum; i++ ) ctx_pool[i].set = sets + i;
  ctx_treap_seed( ctx_pool, depth_sum, seed2 );

  /* Initialize all the lists */
  ctx_list_t * free_list     = ctx_list_join( _free_list     );    FD_TEST( free_list    ==resolver->free_list     );
  ctx_list_t * complete_list = ctx_list_join( _complete_list );    FD_TEST( complete_list==resolver->complete_list );

  for( ulong i=0UL;                 i<depth+partial_depth; i++ ) { ctx_list_idx_push_tail( free_list,     i, ctx_pool ); }
  for( ulong i=depth+partial_depth; i<depth_sum;           i++ ) { ctx_list_idx_push_tail( complete_list, i, ctx_pool ); }
  ctx_list_leave( complete_list );
  ctx_list_leave( free_list     );

  fd_sha512_new( resolver->sha512 );

  resolver->depth                  = depth;
  resolver->partial_depth          = partial_depth;
  resolver->complete_depth         = complete_depth;
  resolver->done_depth             = done_depth;
  resolver->expected_shred_version = 0;
  resolver->free_list_cnt          = depth+partial_depth;
  resolver->signer                 = signer;
  resolver->sign_ctx               = sign_ctx;
  resolver->max_shred_idx          = max_shred_idx;
  resolver->slot_old               = 0UL;
  resolver->seed                   = seed3;
  return shmem;
}

fd_fec_resolver_t *
fd_fec_resolver_join( void * shmem ) {
  fd_fec_resolver_t * resolver = (fd_fec_resolver_t *)shmem;
  ulong depth          = resolver->depth;
  ulong partial_depth  = resolver->partial_depth;
  ulong complete_depth = resolver->complete_depth;
  ulong done_depth     = resolver->done_depth;

  ulong depth_sum = depth + partial_depth + complete_depth;
  if( FD_UNLIKELY( depth_sum>=UINT_MAX ) ) return NULL;

  ulong ctx_chain_cnt  = ctx_map_chain_cnt_est ( depth      );
  ulong done_chain_cnt = done_map_chain_cnt_est( done_depth );

  FD_SCRATCH_ALLOC_INIT( l, shmem );
  /*     self     */   FD_SCRATCH_ALLOC_APPEND( l, FD_FEC_RESOLVER_ALIGN,  sizeof(fd_fec_resolver_t)             );
  void * _ctx_pool   = FD_SCRATCH_ALLOC_APPEND( l, alignof(set_ctx_t),     sizeof(set_ctx_t)*depth_sum           );
  void * _ctx_map    = FD_SCRATCH_ALLOC_APPEND( l, ctx_map_align(),        ctx_map_footprint  ( ctx_chain_cnt  ) );
  void * _done_pool  = FD_SCRATCH_ALLOC_APPEND( l, done_pool_align(),      done_pool_footprint( done_depth     ) );
  void * _done_map   = FD_SCRATCH_ALLOC_APPEND( l, done_map_align(),       done_map_footprint ( done_chain_cnt ) );
  FD_SCRATCH_ALLOC_FINI( l, FD_FEC_RESOLVER_ALIGN );

  resolver->ctx_pool  = (set_ctx_t *)_ctx_pool;
  resolver->ctx_map   = ctx_map_join  ( _ctx_map   );  if( FD_UNLIKELY( !resolver->ctx_map       ) ) return NULL;
  resolver->done_pool = done_pool_join( _done_pool );  if( FD_UNLIKELY( !resolver->done_pool     ) ) return NULL;
  resolver->done_map  = done_map_join ( _done_map  );  if( FD_UNLIKELY( !resolver->done_map      ) ) return NULL;
  if( FD_UNLIKELY(      ctx_treap_join( resolver->ctx_treap     )!=      resolver->ctx_treap     ) ) return NULL;
  if( FD_UNLIKELY(      ctx_list_join ( resolver->free_list     )!=      resolver->free_list     ) ) return NULL;
  if( FD_UNLIKELY(      ctx_list_join ( resolver->complete_list )!=      resolver->complete_list ) ) return NULL;
  if( FD_UNLIKELY(      done_heap_join( resolver->done_heap     )!=      resolver->done_heap     ) ) return NULL;
  if( FD_UNLIKELY(      fd_sha512_join( resolver->sha512        )!=      resolver->sha512        ) ) return NULL;

  return resolver;
}

void
fd_fec_resolver_set_shred_version( fd_fec_resolver_t * resolver,
                                   ushort              expected_shred_version ) {
  resolver->expected_shred_version = expected_shred_version;
}

void
fd_fec_resolver_advance_slot_old( fd_fec_resolver_t * resolver,
                                  ulong               slot_old ) {
  if( FD_UNLIKELY( slot_old <= resolver->slot_old ) ) return;
  resolver->slot_old = slot_old;

  /* Remove from done map */
  done_heap_t * done_heap = resolver->done_heap;
  done_map_t  * done_map  = resolver->done_map;
  done_ele_t  * done_pool = resolver->done_pool;

  while( done_heap_ele_cnt( done_heap ) ) {
    done_ele_t * min_ele = done_heap_ele_peek_min( done_heap, done_pool );
    if( FD_UNLIKELY( min_ele->key.slot>=slot_old ) ) break;
    done_map_ele_remove_fast( done_map,  min_ele, done_pool );
    done_heap_idx_remove_min( done_heap,          done_pool );
    done_pool_ele_release   ( done_pool, min_ele            );
  }

  /* Remove from in progress map */
  ctx_map_t   * ctx_map       = resolver->ctx_map;
  ctx_treap_t * ctx_treap     = resolver->ctx_treap;
  set_ctx_t   * ctx_pool      = resolver->ctx_pool;
  ctx_list_t  * free_list     = resolver->free_list;

  ctx_treap_fwd_iter_t next;
  for( ctx_treap_fwd_iter_t iter=ctx_treap_fwd_iter_init( ctx_treap, ctx_pool ); !ctx_treap_fwd_iter_done( iter ); iter=next ) {
    next = ctx_treap_fwd_iter_next( iter, ctx_pool );
    set_ctx_t * min_ele = ctx_treap_fwd_iter_ele( iter, ctx_pool );
    if( FD_UNLIKELY( min_ele->slot>=slot_old ) ) break;

    ctx_treap_ele_remove   ( ctx_treap, min_ele, ctx_pool );
    ctx_map_ele_remove_fast( ctx_map,   min_ele, ctx_pool );
    ctx_list_ele_push_head ( free_list, min_ele, ctx_pool );
    resolver->free_list_cnt++;
  }

}


int
fd_fec_resolver_add_shred( fd_fec_resolver_t         * resolver,
                           fd_shred_t const          * shred,
                           ulong                       shred_sz,
                           int                         is_repair,
                           uchar const               * leader_pubkey,
                           fd_fec_set_t const      * * out_fec_set,
                           fd_shred_t const        * * out_shred,
                           fd_bmtree_node_t          * out_merkle_root,
                           fd_fec_resolver_spilled_t * out_spilled      ) {
  /* Unpack variables */
  ulong partial_depth = resolver->partial_depth;

  ctx_list_t  * free_list     = resolver->free_list;
  ctx_list_t  * complete_list = resolver->complete_list;
  ctx_map_t   * ctx_map       = resolver->ctx_map;
  ctx_treap_t * ctx_treap     = resolver->ctx_treap;
  set_ctx_t   * ctx_pool      = resolver->ctx_pool;
  done_map_t  * done_map      = resolver->done_map;
  done_ele_t  * done_pool     = resolver->done_pool;
  done_heap_t * done_heap     = resolver->done_heap;

  fd_reedsol_t * reedsol       = resolver->reedsol;
  fd_sha512_t  * sha512        = resolver->sha512;

  /* Invariants:
      * each set_ctx_t is in exactly one of ctx_map, freelist, or
        complete_list */

  /* Is this shred for a slot we've already rooted or otherwise don't
     care about? */
  if( FD_UNLIKELY( shred->slot<resolver->slot_old ) ) return FD_FEC_RESOLVER_SHRED_IGNORED;

  /* Do a bunch of quick validity checks */
  if( FD_UNLIKELY( shred->version!=resolver->expected_shred_version            ) ) return FD_FEC_RESOLVER_SHRED_REJECTED;
  if( FD_UNLIKELY( shred_sz<fd_shred_sz( shred )                               ) ) return FD_FEC_RESOLVER_SHRED_REJECTED;
  if( FD_UNLIKELY( shred->idx>=resolver->max_shred_idx                         ) ) return FD_FEC_RESOLVER_SHRED_REJECTED;
  if( FD_UNLIKELY( shred->fec_set_idx>resolver->max_shred_idx-FD_FEC_SHRED_CNT ) ) return FD_FEC_RESOLVER_SHRED_REJECTED;

  uchar variant    = shred->variant;
  uchar shred_type = fd_shred_type( variant );

  int is_data_shred = fd_shred_is_data( shred_type );

  if( !is_data_shred ) { /* Roughly 50/50 branch */
    if( FD_UNLIKELY( (shred->code.data_cnt!=FD_FEC_SHRED_CNT) | (shred->code.code_cnt!=FD_FEC_SHRED_CNT) ) )
      return FD_FEC_RESOLVER_SHRED_REJECTED;
    if( FD_UNLIKELY( shred->code.idx>=FD_FEC_SHRED_CNT ) ) return FD_FEC_RESOLVER_SHRED_REJECTED;
  }

  if( FD_UNLIKELY( (shred_type==FD_SHRED_TYPE_LEGACY_DATA) | (shred_type==FD_SHRED_TYPE_LEGACY_CODE) ) ) {
    /* Reject any legacy shreds */
    return FD_FEC_RESOLVER_SHRED_REJECTED;
  }


  wrapped_sig_t const * w_sig = (wrapped_sig_t const *)shred->signature;

  /* Is this FEC set in progress? */
  set_ctx_t * ctx = ctx_map_ele_query( ctx_map, w_sig, NULL, ctx_pool );

  /* If it's not in progress and it's repair, we will allocate a context
     for it, assuming all the other checks pass.  If it's from Turbine,
     we'll be a little more sceptical about it: if we've already seen a
     FEC set for that same (slot, FEC set idx) pair, then we won't take
     it. */
  if( FD_UNLIKELY( (ctx==NULL) & (!is_repair) ) ) {
    /* Most likely, it's just done. */
    slot_fec_pair_t slot_fec_pair[1] = {{ .slot = shred->slot, .fec_idx = shred->fec_set_idx }};
    done_ele_t * done_ele = done_map_ele_query( done_map, slot_fec_pair, NULL, done_pool );
    if( FD_LIKELY( done_ele ) ) {
      ulong sig_hash = fd_hash( resolver->seed, w_sig, sizeof(wrapped_sig_t) );
      return fd_int_if( (uint)sig_hash==done_ele->sig_hash, FD_FEC_RESOLVER_SHRED_IGNORED, FD_FEC_RESOLVER_SHRED_EQUIVOC );
    }

    /* If it's not done, then check for the unlikely case we have it
       in progress with a different signature. */
    if( FD_UNLIKELY( ctx_treap_ele_query_const( ctx_treap, slot_fec_pair, ctx_pool ) ) ) return FD_FEC_RESOLVER_SHRED_EQUIVOC;
  }

  /* If we've made it here, then we'll keep this shred as long as
     it is valid. */

  fd_bmtree_node_t leaf[1];

  /* For the purposes of the shred header, tree_depth means the number
     of nodes, counting the leaf but excluding the root.  For bmtree,
     depth means the number of layers, which counts both. */
  ulong tree_depth           = fd_shred_merkle_cnt( variant ); /* In [0, 15] */
  ulong reedsol_protected_sz = 1115UL + FD_SHRED_DATA_HEADER_SZ - FD_SHRED_SIGNATURE_SZ - FD_SHRED_MERKLE_NODE_SZ*tree_depth
                                      - FD_SHRED_MERKLE_ROOT_SZ*fd_shred_is_chained ( shred_type )
                                      - FD_SHRED_SIGNATURE_SZ  *fd_shred_is_resigned( shred_type); /* In [743, 1139] conservatively*/
  ulong data_merkle_protected_sz   = reedsol_protected_sz + FD_SHRED_MERKLE_ROOT_SZ*fd_shred_is_chained( shred_type );
  ulong parity_merkle_protected_sz = reedsol_protected_sz + FD_SHRED_MERKLE_ROOT_SZ*fd_shred_is_chained( shred_type )
                                                          + FD_SHRED_CODE_HEADER_SZ - FD_ED25519_SIG_SZ;
  ulong merkle_protected_sz  = fd_ulong_if( is_data_shred, data_merkle_protected_sz, parity_merkle_protected_sz );

  fd_bmtree_hash_leaf( leaf, (uchar const *)shred + sizeof(fd_ed25519_sig_t), merkle_protected_sz, FD_BMTREE_LONG_PREFIX_SZ );

  /* in_type_idx is between [0, code.data_cnt) or [0, code.code_cnt),
     where data_cnt <= FD_FEC_SHRED_CNT and code_cnt <= FD_FEC_SHRED_CNT
     On the other hand, shred_idx, goes from [0, code.data_cnt +
     code.code_cnt), with all the data shreds having
     shred_idx < code.data_cnt and all the parity shreds having
     shred_idx >= code.data_cnt. */
  ulong in_type_idx = fd_ulong_if( is_data_shred, shred->idx - shred->fec_set_idx, shred->code.idx );
  ulong shred_idx   = fd_ulong_if( is_data_shred, in_type_idx, in_type_idx + shred->code.data_cnt  );

  if( FD_UNLIKELY( ( shred->fec_set_idx % FD_FEC_SHRED_CNT ) != 0UL ) ) return FD_FEC_RESOLVER_SHRED_REJECTED;
  if( FD_UNLIKELY( in_type_idx >= FD_FEC_SHRED_CNT ) )                  return FD_FEC_RESOLVER_SHRED_REJECTED;
  if( is_data_shred ) {
    /* if it has data complete, it must be the last one in the FEC. */
    if( FD_UNLIKELY( (shred->data.flags & FD_SHRED_DATA_FLAG_SLOT_COMPLETE) && ((1UL+shred->idx) % FD_FEC_SHRED_CNT) ) )
      return FD_FEC_RESOLVER_SHRED_REJECTED;
  }

  /* This, combined with the check on shred->code.data_cnt implies that
     shred_idx is in [0, 2*FD_FEC_SHRED_CNT). */

  if( FD_UNLIKELY( tree_depth>FD_SHRED_MERKLE_LAYER_CNT-1UL          ) ) return FD_FEC_RESOLVER_SHRED_REJECTED;
  if( FD_UNLIKELY( fd_bmtree_depth( shred_idx+1UL ) > tree_depth+1UL ) ) return FD_FEC_RESOLVER_SHRED_REJECTED;

  if( FD_UNLIKELY( !ctx ) ) { /* This is the first shred in the FEC set */

    if( FD_UNLIKELY( resolver->free_list_cnt<=partial_depth ) ) {
      /* Packet loss is really high and we have a lot of in-progress FEC
         sets that we haven't been able to finish.  Evict the context
         with the highest (slot, FEC idx).  This is the one that is the
         farthest away from what we're currently replaying, which means
         we have the longest time to request it via repair if we
         actually need it.  This also handles the case where a leader
         sends some shreds from their slots that are far in the future
         in this epoch. */
      set_ctx_t * victim_ctx = ctx_treap_rev_iter_ele( ctx_treap_rev_iter_init( ctx_treap, ctx_pool ), ctx_pool );

      if( FD_LIKELY( out_spilled ) ) {
        out_spilled->slot         = victim_ctx->slot;
        out_spilled->fec_set_idx  = victim_ctx->fec_set_idx;
        *out_spilled->merkle_root = victim_ctx->root;
      }

      fd_fec_set_t * set = victim_ctx->set;

      /* TODO: remove this log */
      FD_LOG_INFO(( "Spilled from fec_resolver in-progress map %lu %u, data_shreds_rcvd %x, parity_shreds_rcvd %x", victim_ctx->slot, victim_ctx->fec_set_idx, set->data_shred_rcvd, set->parity_shred_rcvd  ));

      /* Remove from treap and map, then add to free_list */
      ctx_treap_ele_remove   ( ctx_treap, victim_ctx, ctx_pool );
      ctx_map_ele_remove_fast( ctx_map,   victim_ctx, ctx_pool );

      ctx_list_ele_push_tail ( free_list, victim_ctx, ctx_pool );
      resolver->free_list_cnt++;

      FD_MCNT_INC( SHRED, FEC_SET_SPILLED, 1UL );
    }
    /* Now we know |free_list|>partial_depth */

    ctx = ctx_list_ele_pop_head( free_list, ctx_pool );
    resolver->free_list_cnt--;

    /* Now we need to derive the root of the Merkle tree and verify the
       signature to prevent a DOS attack just by sending lots of invalid
       shreds. */
    fd_bmtree_commit_t * tree;
    tree = fd_bmtree_commit_init( ctx->_footprint, FD_SHRED_MERKLE_NODE_SZ, FD_BMTREE_LONG_PREFIX_SZ, FD_SHRED_MERKLE_LAYER_CNT );
    FD_TEST( tree==ctx->tree );

    fd_bmtree_node_t _root[1];
    fd_shred_merkle_t const * proof = fd_shred_merkle_nodes( shred );
    int rv = fd_bmtree_commitp_insert_with_proof( tree, shred_idx, leaf, (uchar const *)proof, tree_depth, _root );
    if( FD_UNLIKELY( !rv ) ) {
      ctx_list_ele_push_head( free_list, ctx, ctx_pool );
      resolver->free_list_cnt++;
      FD_MCNT_INC( SHRED, SHRED_REJECTED_INITIAL, 1UL );
      return FD_FEC_RESOLVER_SHRED_REJECTED;
    }

    if( FD_UNLIKELY( FD_ED25519_SUCCESS != fd_ed25519_verify( _root->hash, 32UL, shred->signature, leader_pubkey, sha512 ) ) ) {
      ctx_list_ele_push_head( free_list, ctx, ctx_pool );
      resolver->free_list_cnt++;
      FD_MCNT_INC( SHRED, SHRED_REJECTED_INITIAL, 1UL );
      return FD_FEC_RESOLVER_SHRED_REJECTED;
    }

    /* This seems like a legitimate FEC set, so we populate the rest of
       the fields, then add it to the map and treap. */
    ctx->sig                = *w_sig;
    ctx->slot               = shred->slot;
    ctx->fec_set_idx        = shred->fec_set_idx;
    ctx->data_variant       = fd_uchar_if(  is_data_shred, variant, fd_shred_variant( fd_shred_swap_type( shred_type ), (uchar)tree_depth ) );
    ctx->parity_variant     = fd_uchar_if( !is_data_shred, variant, fd_shred_variant( fd_shred_swap_type( shred_type ), (uchar)tree_depth ) );
    ctx->total_rx_shred_cnt = 0UL;
    ctx->root               = *_root;

    if( FD_UNLIKELY( fd_shred_is_resigned( shred_type ) & !!(resolver->signer) ) ) {
      resolver->signer( resolver->sign_ctx, ctx->retransmitter_sig.u, _root->hash );
    } else {
      fd_memset( ctx->retransmitter_sig.u, 0, 64UL );
    }

    /* Reset the FEC set */
    ctx->set->data_shred_rcvd   = 0U;
    ctx->set->parity_shred_rcvd = 0U;

    ctx_map_ele_insert  ( ctx_map,   ctx, ctx_pool );
    ctx_treap_ele_insert( ctx_treap, ctx, ctx_pool );

    /* Copy the merkle root into the output arg. */
    if( FD_LIKELY( out_merkle_root ) ) memcpy( out_merkle_root, ctx->root.hash, sizeof(fd_bmtree_node_t) );

  } else {
    /* This is not the first shred in the set */
    /* First, check to make sure this is not a duplicate */
    int shred_dup = !!(fd_uint_if( is_data_shred, ctx->set->data_shred_rcvd, ctx->set->parity_shred_rcvd ) & (1U << in_type_idx));

    if( FD_UNLIKELY( shred_dup ) ) return FD_FEC_RESOLVER_SHRED_IGNORED;

    /* Ensure that all the shreds in the FEC set have consistent
       variants.  They all must have the same tree_depth and the same
       chained/not chained, resigned/not resigned bits. */
    if( FD_UNLIKELY( variant!=fd_uchar_if( is_data_shred, ctx->data_variant, ctx->parity_variant ) ) ) {
      return FD_FEC_RESOLVER_SHRED_REJECTED;
    }

    fd_shred_merkle_t const * proof = fd_shred_merkle_nodes( shred );
    int rv = fd_bmtree_commitp_insert_with_proof( ctx->tree, shred_idx, leaf, (uchar const *)proof, tree_depth, out_merkle_root );
    if( !rv ) return FD_FEC_RESOLVER_SHRED_REJECTED;
  }

  /* At this point, the shred has passed Merkle validation and is new.
     We also know that ctx is a pointer to the set_ctx_t where this
     shred belongs. */

  /* Copy the shred to memory the FEC resolver owns */
  uchar * dst = is_data_shred ? ctx->set->data_shreds[ in_type_idx ].b : ctx->set->parity_shreds[ in_type_idx ].b;
  fd_memcpy( dst, shred, fd_shred_sz( shred ) );

  /* If the shred needs a retransmitter signature, set it */
  if( FD_UNLIKELY( fd_shred_is_resigned( shred_type ) ) ) {
    memcpy( dst + fd_shred_retransmitter_sig_off( (fd_shred_t *)dst ), ctx->retransmitter_sig.u, 64UL );
  }

  ctx->set->data_shred_rcvd   |= (uint)(!!is_data_shred)<<in_type_idx;
  ctx->set->parity_shred_rcvd |= (uint)( !is_data_shred)<<in_type_idx;
  ctx->total_rx_shred_cnt++;

  *out_shred = (fd_shred_t const *)dst;

  /* Do we have enough to begin reconstruction? */
  if( FD_LIKELY( ctx->total_rx_shred_cnt < FD_FEC_SHRED_CNT ) ) return FD_FEC_RESOLVER_SHRED_OKAY;

  /* At this point, the FEC set is either valid or permanently invalid,
     so we can consider it done either way. */

  done_ele_t * done = NULL;
  if( FD_UNLIKELY( !done_pool_free( done_pool ) ) ) {
    /* Done map is full, so we'll forget about the oldest slot */
    ulong worst_idx = done_heap_idx_peek_min( done_heap );
    FD_TEST( worst_idx!=done_heap_idx_null() ); /* Done pool can't be empty and full at the same time */
    done_heap_idx_remove_min( done_heap,            done_pool );
    done_map_idx_remove_fast( done_map,  worst_idx, done_pool );
    done_pool_idx_release( done_pool, worst_idx );
    /* Now it's not empty */
  }

  /* If it's already in the done map, we don't need to re-insert it.
     It's not very clear what we should do if the sig_hashes differ, but
     this can only happen the second insert was a repair shred, and in
     that case, it gets bypassed anyway, so it doesn't really matter.
     We'll just keep the existing value in that case. */
  slot_fec_pair_t done_key[1] = {{ .slot = ctx->slot, .fec_idx = ctx->fec_set_idx }};
  if( FD_LIKELY( !done_map_ele_query( done_map, done_key, NULL, done_pool ) ) ) {
    done = done_pool_ele_acquire( done_pool );

    done->key.slot    = ctx->slot;
    done->key.fec_idx = ctx->fec_set_idx;
    done->sig_hash    = (uint)fd_hash( resolver->seed, w_sig, sizeof(wrapped_sig_t) );

    done_heap_ele_insert( done_heap, done, done_pool );
    done_map_ele_insert ( done_map,  done, done_pool );
  }


  ctx_map_ele_remove_fast( ctx_map,   ctx, ctx_pool );
  ctx_treap_ele_remove   ( ctx_treap, ctx, ctx_pool );
  /* At this point, ctx is not in any of the data structures, so we need
     to be sure to add it to one of the lists before exiting. */

  fd_fec_set_t       * set  = ctx->set;
  fd_bmtree_commit_t * tree = ctx->tree;

  reedsol = fd_reedsol_recover_init( (void*)reedsol, reedsol_protected_sz );
  for( ulong i=0UL; i<FD_FEC_SHRED_CNT; i++ ) {
    uchar * rs_payload = set->data_shreds[ i ].b + sizeof(fd_ed25519_sig_t);
    if( set->data_shred_rcvd&(1U<<i) ) fd_reedsol_recover_add_rcvd_shred  ( reedsol, 1, rs_payload );
    else                               fd_reedsol_recover_add_erased_shred( reedsol, 1, rs_payload );
  }
  for( ulong i=0UL; i<FD_FEC_SHRED_CNT; i++ ) {
    uchar * rs_payload = set->parity_shreds[ i ].b + FD_SHRED_CODE_HEADER_SZ;
    if( set->parity_shred_rcvd&(1U<<i) ) fd_reedsol_recover_add_rcvd_shred  ( reedsol, 0, rs_payload );
    else                                 fd_reedsol_recover_add_erased_shred( reedsol, 0, rs_payload );
  }

  if( FD_UNLIKELY( FD_REEDSOL_SUCCESS != fd_reedsol_recover_fini( reedsol ) ) ) {
    /* A few lines up, we already checked to make sure it wasn't the
       insufficient case, so it must be the inconsistent case.  That
       means the leader signed a shred with invalid Reed-Solomon FEC
       set.  This shouldn't happen in practice, but we need to handle it
       for the malicious leader case.  This should probably be a
       slash-able offense. */
    ctx_list_ele_push_tail( free_list, ctx, ctx_pool );
    resolver->free_list_cnt++;
    FD_MCNT_INC( SHRED, FEC_REJECTED_FATAL, 1UL );
    return FD_FEC_RESOLVER_SHRED_REJECTED;
  }

  uchar const * chained_root = fd_ptr_if( fd_shred_is_chained( shred_type ), (uchar *)shred+fd_shred_chain_off( variant ), NULL );

  /* Iterate over recovered shreds, add them to the Merkle tree,
     populate headers and signatures. */
  for( ulong i=0UL; i<FD_FEC_SHRED_CNT; i++ ) {
    if( !(set->data_shred_rcvd&(1U<<i)) ) {
      fd_memcpy( set->data_shreds[i].b, shred, sizeof(fd_ed25519_sig_t) );
      if( FD_LIKELY( fd_shred_is_chained( shred_type ) ) ) {
        fd_memcpy( set->data_shreds[i].b+fd_shred_chain_off( ctx->data_variant ), chained_root, FD_SHRED_MERKLE_ROOT_SZ );
      }
      fd_bmtree_hash_leaf( leaf, set->data_shreds[i].b+sizeof(fd_ed25519_sig_t), data_merkle_protected_sz, FD_BMTREE_LONG_PREFIX_SZ );
      if( FD_UNLIKELY( !fd_bmtree_commitp_insert_with_proof( tree, i, leaf, NULL, 0, NULL ) ) ) {
        ctx_list_ele_push_tail( free_list, ctx, ctx_pool );
        resolver->free_list_cnt++;
        FD_MCNT_INC( SHRED, FEC_REJECTED_FATAL, 1UL );
        return FD_FEC_RESOLVER_SHRED_REJECTED;
      }
    }
  }

  for( ulong i=0UL; i<FD_FEC_SHRED_CNT; i++ ) {
    if( !(set->parity_shred_rcvd&(1U<<i)) ) {
      fd_shred_t * p_shred = set->parity_shreds[i].s; /* We can't parse because we haven't populated the header */
      fd_memcpy( p_shred->signature, shred->signature, sizeof(fd_ed25519_sig_t) );
      p_shred->variant       = ctx->parity_variant;
      p_shred->slot          = shred->slot;
      p_shred->idx           = (uint)(i + ctx->fec_set_idx);
      p_shred->version       = shred->version;
      p_shred->fec_set_idx   = (uint)ctx->fec_set_idx;
      p_shred->code.data_cnt = (ushort)FD_FEC_SHRED_CNT;
      p_shred->code.code_cnt = (ushort)FD_FEC_SHRED_CNT;
      p_shred->code.idx      = (ushort)i;

      if( FD_LIKELY( fd_shred_is_chained( shred_type ) ) ) {
        fd_memcpy( set->parity_shreds[i].b+fd_shred_chain_off( ctx->parity_variant ), chained_root, FD_SHRED_MERKLE_ROOT_SZ );
      }

      fd_bmtree_hash_leaf( leaf, set->parity_shreds[i].b+sizeof(fd_ed25519_sig_t), parity_merkle_protected_sz, FD_BMTREE_LONG_PREFIX_SZ );
      if( FD_UNLIKELY( !fd_bmtree_commitp_insert_with_proof( tree, FD_FEC_SHRED_CNT + i, leaf, NULL, 0, NULL ) ) ) {
        ctx_list_ele_push_tail( free_list, ctx, ctx_pool );
        resolver->free_list_cnt++;
        FD_MCNT_INC( SHRED, FEC_REJECTED_FATAL, 1UL );
        return FD_FEC_RESOLVER_SHRED_REJECTED;
      }
    }
  }

  /* Check that the whole Merkle tree is consistent. */
  if( FD_UNLIKELY( !fd_bmtree_commitp_fini( tree, FD_FEC_SHRED_CNT + FD_FEC_SHRED_CNT ) ) ) {
    ctx_list_ele_push_tail( free_list, ctx, ctx_pool );
    resolver->free_list_cnt++;
    FD_MCNT_INC( SHRED, FEC_REJECTED_FATAL, 1UL );
    return FD_FEC_RESOLVER_SHRED_REJECTED;
  }

  /* Check that all the fields that are supposed to be consistent across
     an FEC set actually are. */
  fd_shred_t const * base_data_shred   = fd_shred_parse( set->data_shreds  [ 0 ].b, FD_SHRED_MIN_SZ );
  fd_shred_t const * base_parity_shred = fd_shred_parse( set->parity_shreds[ 0 ].b, FD_SHRED_MAX_SZ );
  int reject = (!base_data_shred) | (!base_parity_shred);

  for( ulong i=1UL; (!reject) & (i<FD_FEC_SHRED_CNT); i++ ) {
    /* Technically, we only need to re-parse the ones we recovered with
       Reedsol, but parsing is pretty cheap and the rest of the
       validation we need to do on all of them. */
    fd_shred_t const * parsed = fd_shred_parse( set->data_shreds[ i ].b, FD_SHRED_MIN_SZ );
    if( FD_UNLIKELY( !parsed ) ) { reject = 1; break; }
    reject |= parsed->variant         != base_data_shred->variant;
    reject |= parsed->slot            != base_data_shred->slot;
    reject |= parsed->version         != base_data_shred->version;
    reject |= parsed->fec_set_idx     != base_data_shred->fec_set_idx;
    reject |= parsed->data.parent_off != base_data_shred->data.parent_off;

    reject |= fd_shred_is_chained( fd_shred_type( parsed->variant ) ) &&
                !fd_memeq( (uchar *)parsed         +fd_shred_chain_off( parsed->variant          ),
                           (uchar *)base_data_shred+fd_shred_chain_off( base_data_shred->variant ), FD_SHRED_MERKLE_ROOT_SZ );
  }

  for( ulong i=0UL; (!reject) & (i<FD_FEC_SHRED_CNT); i++ ) {
    fd_shred_t const * parsed = fd_shred_parse( set->parity_shreds[ i ].b, FD_SHRED_MAX_SZ );
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
                !fd_memeq( (uchar *)parsed         +fd_shred_chain_off( parsed->variant          ),
                           (uchar *)base_data_shred+fd_shred_chain_off( base_data_shred->variant ), FD_SHRED_MERKLE_ROOT_SZ );
  }
  if( FD_UNLIKELY( reject ) ) {
    ctx_list_ele_push_tail( free_list, ctx, ctx_pool );
    resolver->free_list_cnt++;
    FD_MCNT_INC( SHRED, FEC_REJECTED_FATAL, 1UL );
    return FD_FEC_RESOLVER_SHRED_REJECTED;
  }

  /* Populate missing Merkle proofs */
  for( ulong i=0UL; i<FD_FEC_SHRED_CNT; i++   ) if( !( set->data_shred_rcvd&(1U<<i) ) )
    fd_bmtree_get_proof( tree, set->data_shreds[i].b   + fd_shred_merkle_off( set->data_shreds[i].s   ), i );

  for( ulong i=0UL; i<FD_FEC_SHRED_CNT; i++ ) if( !( set->parity_shred_rcvd&(1U<<i) ) )
    fd_bmtree_get_proof( tree, set->parity_shreds[i].b + fd_shred_merkle_off( set->parity_shreds[i].s ), FD_FEC_SHRED_CNT+i );

  /* Set the retransmitter signature for shreds that need one */
  if( FD_UNLIKELY( fd_shred_is_resigned( shred_type ) ) ) {
    for( ulong i=0UL; i<FD_FEC_SHRED_CNT; i++   ) if( !( set->data_shred_rcvd&(1U<<i) ) )
      memcpy( set->data_shreds[i].b   + fd_shred_retransmitter_sig_off( set->data_shreds[i].s   ), ctx->retransmitter_sig.u, 64UL );

    for( ulong i=0UL; i<FD_FEC_SHRED_CNT; i++ ) if( !( set->parity_shred_rcvd&(1U<<i) ) )
      memcpy( set->parity_shreds[i].b + fd_shred_retransmitter_sig_off( set->parity_shreds[i].s ), ctx->retransmitter_sig.u, 64UL );
  }

  /* Finally... A valid FEC set.  Forward it along. */
  ctx_list_ele_push_tail( complete_list, ctx, ctx_pool );
  ctx_list_idx_push_tail( free_list, ctx_list_idx_pop_head( complete_list, ctx_pool ), ctx_pool );
  resolver->free_list_cnt++;

  *out_fec_set = set;

  return FD_FEC_RESOLVER_SHRED_COMPLETES;
}


void * fd_fec_resolver_leave( fd_fec_resolver_t * resolver ) {
  fd_sha512_leave( resolver->sha512        );
  done_heap_leave( resolver->done_heap     );
  ctx_list_leave ( resolver->complete_list );
  ctx_list_leave ( resolver->free_list     );
  ctx_treap_leave( resolver->ctx_treap     );
  done_map_leave ( resolver->done_map      );
  done_pool_leave( resolver->done_pool     );
  ctx_map_leave  ( resolver->ctx_map       );

  return (void *)resolver;
}

void * fd_fec_resolver_delete( void * shmem ) {
  fd_fec_resolver_t * resolver = (fd_fec_resolver_t *)shmem;
  ulong depth          = resolver->depth;
  ulong partial_depth  = resolver->partial_depth;
  ulong complete_depth = resolver->complete_depth;
  ulong done_depth     = resolver->done_depth;

  ulong depth_sum      = depth + partial_depth + complete_depth;
  ulong ctx_chain_cnt  = ctx_map_chain_cnt_est ( depth      );
  ulong done_chain_cnt = done_map_chain_cnt_est( done_depth );

  FD_SCRATCH_ALLOC_INIT( l, shmem );
  /*     self      */  FD_SCRATCH_ALLOC_APPEND( l, FD_FEC_RESOLVER_ALIGN,  sizeof(fd_fec_resolver_t)                 );
  /*     _ctx_pool */  FD_SCRATCH_ALLOC_APPEND( l, alignof(set_ctx_t),     sizeof(set_ctx_t)*depth_sum               );
  void * _ctx_map    = FD_SCRATCH_ALLOC_APPEND( l, ctx_map_align(),        ctx_map_footprint  ( ctx_chain_cnt  ) );
  void * _done_pool  = FD_SCRATCH_ALLOC_APPEND( l, done_pool_align(),      done_pool_footprint( done_depth         ) );
  void * _done_map   = FD_SCRATCH_ALLOC_APPEND( l, done_map_align(),       done_map_footprint ( done_chain_cnt ) );
  FD_SCRATCH_ALLOC_FINI( l, FD_FEC_RESOLVER_ALIGN );

  fd_sha512_delete( resolver->sha512        );
  done_heap_delete( resolver->done_heap     );
  done_map_delete ( _done_map               );
  done_pool_delete( _done_pool              );
  ctx_list_delete ( resolver->complete_list );
  ctx_list_delete ( resolver->free_list     );
  ctx_treap_delete( resolver->ctx_treap     );
  ctx_map_delete  ( _ctx_map                );

  return shmem;
}
