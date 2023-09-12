#include "fd_shred.h"
#include "fd_fec_set.h"
#include "../../tango/tcache/fd_tcache.h"
#include "../bmtree/fd_bmtree.h"
#include "../sha512/fd_sha512.h"
#include "../ed25519/fd_ed25519.h"
#include "../reedsol/fd_reedsol.h"

#define INCLUSION_PROOF_LAYERS 10UL
#define SHRED_CNT_NOT_SET      (UINT_MAX/2U)

struct __attribute__((aligned(32UL))) set_ctx {
  ulong                 sig_tag;
  fd_fec_set_t *        set;
  fd_bmtree_commit_t  * tree;
  ulong                 next_tag;
  ulong                 prev_tag;
  uint                  total_rx_shred_cnt;
  uint                  parity_fec_set_idx;
};
typedef struct set_ctx set_ctx_t;

#define DEQUE_NAME freelist
#define DEQUE_T    set_ctx_t
#include "../../util/tmpl/fd_deque_dynamic.c"

#define MAP_KEY     sig_tag
#define MAP_MEMOIZE 0
#define MAP_NAME    ctx_map
#define MAP_T       set_ctx_t
#include "../../util/tmpl/fd_map_dynamic.c"


struct __attribute__((aligned(FD_FEC_RESOLVER_ALIGN))) fd_fec_resolver {
  /* depth stores the number of FEC sets this resolver can track
     simultaneously.  done_depth stores the depth of the done tcache,
     i.e. the number of done FEC sets that this resolver remembers. */
  ulong depth;
  ulong done_depth;

  /* done: stores tags of signatures of FEC sets that have recently been
     completed.  Any new packets matching tags in this set can be
     ignored.  This tcache has depth done_depth. */
  fd_tcache_t * done;

  /* curr_map: A map (using fd_map_dynamic) from tags of signatures to
     the context object with its relavant data.  This map contains at
     most `depth` elements at any time, but to improve query performace,
     we size it at 2*depth. */
  set_ctx_t   * curr_map;

  /* curr_{head,tail}_tag: The elements of curr_map also make
     essentially a doubly linked list using the next_tag and prev_tag
     fields.  Each contains the sig_tag field of the element that's one
     older/newer than it, respectively.  Head gives the sig_tag of the
     newest, and tail gives the sig_tag of the oldest. */
  ulong curr_head_tag;
  ulong curr_tail_tag;

  /* freelist: A deque (using fd_deque_dynamic) that stores the other
     set_ctx_t objects that are not in curr_ctx.  The max size of this
     list is depth. */
  set_ctx_t * freelist;

  fd_sha512_t   sha512[1];

  fd_reedsol_t  reedsol[1];

  uchar public_key[32]; /* FIXME: This should be per-block, not here */
};

#define SCRATCH_ALLOC( a, s ) (__extension__({                    \
    ulong _scratch_alloc = fd_ulong_align_up( scratch_top, (a) ); \
    scratch_top = _scratch_alloc + (s);                           \
    (void *)_scratch_alloc;                                       \
  }))
ulong
fd_fec_resolver_footprint( ulong depth, ulong done_depth ) {
  if( FD_UNLIKELY( !fd_ulong_is_pow2( depth ) ) ) return 0UL;
  int lg_depth = fd_ulong_find_msb( depth );

  ulong scratch_top = 0UL;
  SCRATCH_ALLOC( FD_FEC_RESOLVER_ALIGN,   sizeof(fd_fec_resolver_t)                                                  );
  SCRATCH_ALLOC( FD_TCACHE_ALIGN,         fd_tcache_footprint( done_depth, fd_tcache_map_cnt_default( done_depth ) ) );
  SCRATCH_ALLOC( ctx_map_align(),         ctx_map_footprint( lg_depth+1 )                                            );
  SCRATCH_ALLOC( freelist_align(),        freelist_footprint( depth )                                                );
  SCRATCH_ALLOC( FD_BMTREE_COMMIT_ALIGN,  depth*fd_bmtree_commit_footprint( INCLUSION_PROOF_LAYERS )                 );

  return fd_ulong_align_up( scratch_top, FD_FEC_RESOLVER_ALIGN );
}
ulong fd_fec_resolver_align    ( void        ) { return FD_FEC_RESOLVER_ALIGN; }

void *
fd_fec_resolver_new( void * shmem, ulong depth, ulong done_depth, fd_fec_set_t * sets, uchar const * public_key ) {
  if( FD_UNLIKELY( depth==0 ) ) return 0UL;
  if( FD_UNLIKELY( !fd_ulong_is_pow2( depth ) ) ) return 0UL;
  int lg_depth = fd_ulong_find_msb( depth );

  ulong done_map_cnt = fd_tcache_map_cnt_default( done_depth );

  ulong scratch_top = (ulong)shmem;
  void * self      = SCRATCH_ALLOC( FD_FEC_RESOLVER_ALIGN,  sizeof(fd_fec_resolver_t)                                  );
  void * done      = SCRATCH_ALLOC( FD_TCACHE_ALIGN,        fd_tcache_footprint( done_depth, done_map_cnt            ) );
  void * curr_map  = SCRATCH_ALLOC( ctx_map_align(),        ctx_map_footprint( lg_depth+1 )                            );
  void * _freelist = SCRATCH_ALLOC( freelist_align(),       freelist_footprint( depth )                                );
  void * trees     = SCRATCH_ALLOC( FD_BMTREE_COMMIT_ALIGN, depth*fd_bmtree_commit_footprint( INCLUSION_PROOF_LAYERS ) );

  fd_fec_resolver_t * resolver = (fd_fec_resolver_t *)self;

  if( FD_UNLIKELY( !fd_tcache_new( done,     done_depth, done_map_cnt )) ) { FD_LOG_WARNING(("tcache_new failed"  )); return NULL; }
  if( FD_UNLIKELY( !ctx_map_new(   curr_map, lg_depth+1               )) ) { FD_LOG_WARNING(("ctx_map_new failed" )); return NULL; }
  if( FD_UNLIKELY( !freelist_new( _freelist, depth                    )) ) { FD_LOG_WARNING(("freelist_new failed")); return NULL; }
  if( FD_UNLIKELY( !fd_sha512_new( (void *)resolver->sha512           )) ) { FD_LOG_WARNING(("sha512_new failed"  )); return NULL; }

  set_ctx_t * freelist = freelist_join( _freelist );
  for( ulong i=0UL; i<depth; i++ ) {
    set_ctx_t * ctx = freelist_peek_tail( freelist_insert_tail( freelist ) );
    ctx->sig_tag            = 0xAAAA0000UL + i;
    ctx->set                = sets+i;
    ctx->tree               = (fd_bmtree_commit_t *)( (uchar *)trees + i*fd_bmtree_commit_footprint( INCLUSION_PROOF_LAYERS ) );
    ctx->total_rx_shred_cnt = 0U;
    ctx->parity_fec_set_idx = 0U;
    ctx->next_tag           = 0UL;
    ctx->prev_tag           = 0UL;
  }

  freelist_leave( freelist );

  fd_memcpy( resolver->public_key, public_key, 32UL );

  resolver->curr_head_tag = 0UL;
  resolver->curr_tail_tag = 0UL;

  resolver->depth      = depth;
  resolver->done_depth = done_depth;
  return shmem;
}

fd_fec_resolver_t *
fd_fec_resolver_join( void * shmem ) {
  fd_fec_resolver_t * resolver = (fd_fec_resolver_t *)shmem;
  ulong depth      = resolver->depth;
  ulong done_depth = resolver->done_depth;

  int lg_depth = fd_ulong_find_msb( depth );

  ulong done_map_cnt = fd_tcache_map_cnt_default( done_depth );

  ulong scratch_top = (ulong)shmem;
  /*     self    */ SCRATCH_ALLOC( FD_FEC_RESOLVER_ALIGN,  sizeof(fd_fec_resolver_t)                       );
  void * done     = SCRATCH_ALLOC( FD_TCACHE_ALIGN,        fd_tcache_footprint( done_depth, done_map_cnt ) );
  void * curr_map = SCRATCH_ALLOC( ctx_map_align(),        ctx_map_footprint( lg_depth+1 )                 );
  void * freelist = SCRATCH_ALLOC( freelist_align(),       freelist_footprint( depth )                     );

  resolver->done     = fd_tcache_join( done );
  resolver->curr_map = ctx_map_join( curr_map );
  resolver->freelist = freelist_join( freelist );
  fd_sha512_join( resolver->sha512 );

  return resolver;
}

fd_fec_set_t const *
fd_fec_resolver_add_shred( fd_fec_resolver_t * resolver, fd_shred_t const * shred, ulong shred_sz ) {
  /* Unpack variables */
  fd_tcache_t  * done          = resolver->done;
  ulong          done_depth    = fd_tcache_depth(        done );
  ulong          done_map_cnt  = fd_tcache_map_cnt(      done );
  ulong        * done_oldest   = fd_tcache_oldest_laddr( done );
  ulong        * done_ring     = fd_tcache_ring_laddr(   done );
  ulong        * done_map      = fd_tcache_map_laddr(    done );

  set_ctx_t    * freelist      = resolver->freelist;
  set_ctx_t    * curr_map      = resolver->curr_map;

  fd_reedsol_t * reedsol       = resolver->reedsol;

  /* Invariants:
      * no key is in both the done tcache and the current tcache
      * each set pointer provided to the new function is in exactly one
          of curr_map and freelist
   */

  int dup = 0;
  /* Note: we identify FEC sets by the first 64 bits of their signature.
     Given how slow Ed25519 is and how short of a time these are
     relevant for, this seems safe, but we should research the issue
     further. */

  /* Are we already done with this FEC set? */
  /* TODO: xor this with something semi-secret to prevent someone from
     spending a lot of compute to make a shred with a 0 signature which
     would be interpreted as an invalid key. */
  ulong signature = fd_ulong_load_8( shred->signature );
  int found;
  ulong map_idx;

  (void)map_idx;
  FD_TCACHE_QUERY( found, map_idx, done_map, done_map_cnt, signature );
  if( found )  return NULL; /* With no packet loss, we expect found==1 about 50% of the time */

  set_ctx_t * ctx = ctx_map_query( curr_map, signature, NULL );

  fd_bmtree_node_t _leaf[1];
  uchar variant    = shred->variant;
  uchar shred_type = fd_shred_type( variant );

  ulong tree_depth           = fd_shred_merkle_cnt( variant );
  ulong reedsol_protected_sz = 1115UL - 20UL*tree_depth + 0x58UL - 0x40UL;
  ulong merkle_protected_sz  = reedsol_protected_sz + fd_ulong_if( shred_type==FD_SHRED_TYPE_MERKLE_DATA, 0UL, 0x59UL - 0x40UL );

  fd_bmtree_hash_leaf( _leaf, (uchar const *)shred + sizeof(fd_ed25519_sig_t), merkle_protected_sz, FD_BMTREE_LONG_PREFIX_SZ );

  /* code_idx: if this is a Merkle coding shred, the index of it in the
     Merkle array, otherwise 0. */
  ulong code_idx   = fd_ulong_if( shred_type==FD_SHRED_TYPE_MERKLE_DATA, 0UL, shred->code.idx );
  ulong shred_idx  = fd_ulong_if( shred_type==FD_SHRED_TYPE_MERKLE_DATA,
                                  shred->idx - shred->fec_set_idx,
                                  shred->code.data_cnt + code_idx );
  /* TODO: bounds check shred_pos. make sure proof depth has the right
       value */

  set_ctx_t _temp[1];
  if( FD_UNLIKELY( !ctx ) ) {
    /* This is the first shred in the FEC set */
    if( FD_LIKELY( freelist_cnt( freelist ) ) ) {
      ctx = _temp;
      *ctx = freelist_pop_head( freelist );
    } else {
      /* Packet loss is really high and we have a lot of in-progress FEC
         sets that we haven't been able to finish.  Take the oldest. */
      ulong oldest_key = resolver->curr_tail_tag;
      ctx = ctx_map_query( curr_map, oldest_key, NULL );
      if( FD_UNLIKELY( !ctx ) ) FD_LOG_ERR(( "data structures not in sync. Couldn't find %lx in the map", oldest_key ));
      resolver->curr_tail_tag = ctx->prev_tag;
      ctx_map_query( curr_map, ctx->prev_tag, NULL )->next_tag = 0UL;

      /* Add this one that we're sacrificing to the done tcache to
         prevent the possibility of thrashing. */
      FD_TCACHE_INSERT( dup, *done_oldest, done_ring, done_depth, done_map, done_map_cnt, ctx->sig_tag );
      *_temp = *ctx;
      ctx_map_remove( curr_map, ctx );
      ctx = _temp;
    }

    /* At this point, ctx is neither in the free list nor in curr_map.
       It has indeterminate state though. */


    /* Now we need to derive the root of the Merkle tree and verify the
       signature to prevent a DOS attack just by sending lots of invalid
       shreds. */
    fd_bmtree_commit_init( (void *)ctx->tree, FD_SHRED_MERKLE_NODE_SZ, FD_BMTREE_LONG_PREFIX_SZ, INCLUSION_PROOF_LAYERS );

    fd_bmtree_node_t _root[1];
    int rv = fd_bmtree_commitp_insert_with_proof( ctx->tree, shred_idx, _leaf,
                                               (uchar*)fd_shred_merkle_nodes( shred ), fd_shred_merkle_cnt( variant ), _root );
    if( FD_UNLIKELY( !rv ) ) {
      freelist_push_head( freelist, *ctx );
      return NULL;
    }

    if( FD_UNLIKELY( FD_ED25519_SUCCESS != fd_ed25519_verify( _root->hash, 32UL, shred->signature, resolver->public_key, resolver->sha512 ) ) ) {
      freelist_push_head( freelist, *ctx );
      return NULL;
    }

    /* This seems like a legitimate FEC set, so we can reserve some
       resources for it. */
    set_ctx_t * e = ctx_map_insert( curr_map, signature );
    e->set  = ctx->set;
    e->tree = ctx->tree;
    e->total_rx_shred_cnt = 0UL;

    e->next_tag = resolver->curr_head_tag;
    e->prev_tag = 0UL;
    /* If the list is not empty, update the prev pointer of the old
     * head.  Otherwise, assign the tail to this too. */
    if( FD_LIKELY( resolver->curr_head_tag ) ) ctx_map_query( curr_map, resolver->curr_head_tag, NULL )->prev_tag = signature;
    else                                                                                  resolver->curr_tail_tag = signature;

    resolver->curr_head_tag = signature;

    /* Reset the FEC set */
    e->set->data_shred_cnt   = SHRED_CNT_NOT_SET;
    e->set->parity_shred_cnt = SHRED_CNT_NOT_SET;
    d_present_join( d_present_new( d_present_delete( d_present_leave( e->set->data_shred_present   ) ) ) );
    p_present_join( p_present_new( p_present_delete( p_present_leave( e->set->parity_shred_present ) ) ) );

    ctx = e;
  } else {
    /* Validate Merkle proof, that it gives the right root. */
    int rv = fd_bmtree_commitp_insert_with_proof( ctx->tree, shred_idx, _leaf,
                                                  (uchar*)fd_shred_merkle_nodes( shred ), fd_shred_merkle_cnt( variant ), NULL );
    if( !rv ) return NULL;
  }

  /* At this point, the shred has passed Merkle validation.  We also
     know that ctx == ctx_map_query( curr_map, signature, NULL). */
  if( FD_UNLIKELY( (ctx->set->data_shred_cnt == SHRED_CNT_NOT_SET) & (shred_type==FD_SHRED_TYPE_MERKLE_CODE) ) ) {
    ctx->set->data_shred_cnt   = shred->code.data_cnt;
    ctx->set->parity_shred_cnt = shred->code.code_cnt;
    ctx->parity_fec_set_idx    = shred->fec_set_idx;
  }

  /* Check to make sure this is not a duplicate */
  dup = fd_int_if( shred_type==FD_SHRED_TYPE_MERKLE_DATA, d_present_test( ctx->set->data_shred_present,   shred_idx ),
                                                          p_present_test( ctx->set->parity_shred_present, code_idx ) );
  if( FD_UNLIKELY( dup ) ) return NULL;

  uchar * dst = fd_ptr_if( shred_type==FD_SHRED_TYPE_MERKLE_DATA, ctx->set->data_shreds[   shred_idx ],
                                                                  ctx->set->parity_shreds[ code_idx  ] );
  fd_memcpy( dst, shred, shred_sz );

  d_present_insert_if( ctx->set->data_shred_present,   shred_type==FD_SHRED_TYPE_MERKLE_DATA, shred_idx );
  p_present_insert_if( ctx->set->parity_shred_present, shred_type!=FD_SHRED_TYPE_MERKLE_DATA, code_idx  );
  ctx->total_rx_shred_cnt++;

  /* Do we have enough to begin reconstruction? */
  if( FD_LIKELY( ctx->total_rx_shred_cnt < ctx->set->data_shred_cnt ) ) return NULL;

  /* At this point, the FEC set is either valid or permanently invalid,
     so we can consider it done either way.  First though, since ctx_map_remove
     can change what's at *ctx, so unpack the values before we do that */
  fd_fec_set_t const  * set                = ctx->set;
  fd_bmtree_commit_t  * tree               = ctx->tree;
  uint                  parity_fec_set_idx = ctx->parity_fec_set_idx;

  freelist_push_tail( freelist, *ctx );

  /* Is this one first? */
  if( FD_UNLIKELY( signature==resolver->curr_head_tag ) ) resolver->curr_head_tag                                  = ctx->next_tag;
  else                                                    ctx_map_query( curr_map, ctx->prev_tag, NULL )->next_tag = ctx->next_tag;
  /* Is this one last? If it's the only one, it's both first and last. */
  if( FD_UNLIKELY( signature==resolver->curr_tail_tag ) ) resolver->curr_tail_tag                                  = ctx->prev_tag;
  else                                                    ctx_map_query( curr_map, ctx->next_tag, NULL )->prev_tag = ctx->prev_tag;

  ctx_map_remove( curr_map, ctx );
  FD_TCACHE_INSERT( dup, *done_oldest, done_ring, done_depth, done_map, done_map_cnt, signature );


  reedsol = fd_reedsol_recover_init( (void*)reedsol, reedsol_protected_sz );
  for( ulong i=0UL; i<set->data_shred_cnt; i++ ) {
    uchar * rs_payload = set->data_shreds[ i ] + sizeof(fd_ed25519_sig_t);
    if( d_present_test( set->data_shred_present, i ) ) fd_reedsol_recover_add_rcvd_shred(   reedsol, 1, rs_payload );
    else                                               fd_reedsol_recover_add_erased_shred( reedsol, 1, rs_payload );
  }
  for( ulong i=0UL; i<set->parity_shred_cnt; i++ ) {
    uchar * rs_payload = set->parity_shreds[ i ] + FD_SHRED_CODE_HEADER_SZ;
    if( p_present_test( set->parity_shred_present, i ) ) fd_reedsol_recover_add_rcvd_shred(   reedsol, 0, rs_payload );
    else                                                 fd_reedsol_recover_add_erased_shred( reedsol, 0, rs_payload );
  }

  if( FD_UNLIKELY( FD_REEDSOL_SUCCESS != fd_reedsol_recover_fini( reedsol ) ) ) {
    /* A few lines up, we already checked to make sure it wasn't the
       insufficient case, so it must be the inconsistent case.  That
       means the leader signed a shred with invalid Reed-Solomon FEC
       set.  This shouldn't happen in practice, but we need to handle it
       for the malicious leader case.  This should probably be a
       slash-able offense. */
    return NULL;
  }
  /* Iterate over recovered shreds, add them to the Merkle tree,
     populate headers and signatures. */
  for( ulong i=0UL; i<set->data_shred_cnt; i++ ) {
    if( !d_present_test( set->data_shred_present, i ) ) {
      fd_bmtree_hash_leaf( _leaf, set->data_shreds[i]+sizeof(fd_ed25519_sig_t), reedsol_protected_sz, FD_BMTREE_LONG_PREFIX_SZ );
      if( FD_UNLIKELY( !fd_bmtree_commitp_insert_with_proof( tree, i, _leaf, NULL, 0, NULL ) ) ) return NULL;

      fd_memcpy( set->data_shreds[i], shred, sizeof(fd_ed25519_sig_t) );
    }
  }
  for( ulong i=0UL; i<set->parity_shred_cnt; i++ ) {
    if( !p_present_test( set->parity_shred_present, i ) ) {
      fd_shred_t * p_shred = (fd_shred_t *)set->parity_shreds[i]; /* We can't parse because we haven't populated the header */
      fd_memcpy( p_shred->signature, shred->signature, sizeof(fd_ed25519_sig_t) );
      p_shred->variant       = fd_shred_variant( FD_SHRED_TYPE_MERKLE_CODE, (uchar)tree_depth );
      p_shred->slot          = shred->slot;
      p_shred->idx           = (uint)i + parity_fec_set_idx;
      p_shred->version       = shred->version;
      p_shred->fec_set_idx   = parity_fec_set_idx;
      p_shred->code.data_cnt = (ushort)set->data_shred_cnt;
      p_shred->code.code_cnt = (ushort)set->parity_shred_cnt;
      p_shred->code.idx      = (ushort)i;

      fd_bmtree_hash_leaf( _leaf, set->parity_shreds[i]+ sizeof(fd_ed25519_sig_t), reedsol_protected_sz+0x19UL, FD_BMTREE_LONG_PREFIX_SZ );
      if( FD_UNLIKELY( !fd_bmtree_commitp_insert_with_proof( tree, set->data_shred_cnt + i, _leaf, NULL, 0, NULL ) ) ) return NULL;
    }
  }

  if( FD_UNLIKELY( !fd_bmtree_commitp_fini( tree, set->data_shred_cnt + set->parity_shred_cnt ) ) ) return NULL;

  /* Populate missing Merkle proofs */
  for( ulong i=0UL; i<set->data_shred_cnt; i++ ) if( !d_present_test( set->data_shred_present, i ) )
    fd_bmtree_get_proof( tree, set->data_shreds[i] + fd_shred_merkle_off( fd_shred_variant( FD_SHRED_TYPE_MERKLE_DATA, (uchar)tree_depth ) ), i );

  for( ulong i=0UL; i<set->parity_shred_cnt; i++ ) if( !p_present_test( set->parity_shred_present, i ) )
    fd_bmtree_get_proof( tree, set->parity_shreds[i] + fd_shred_merkle_off( fd_shred_variant( FD_SHRED_TYPE_MERKLE_CODE, (uchar)tree_depth ) ), set->data_shred_cnt+i );

  /* Finally... A valid FEC set.  Forward it along. */
  return set;
}

void * fd_fec_resolver_leave( fd_fec_resolver_t * resolver ) {
  fd_sha512_leave( resolver->sha512   );
  freelist_leave(  resolver->freelist );
  ctx_map_leave(   resolver->curr_map );
  fd_tcache_leave( resolver->done     );

  return (void *)resolver;
}

void * fd_fec_resolver_delete( void * shmem ) {
  fd_fec_resolver_t * resolver = (fd_fec_resolver_t *)shmem;
  ulong depth      = resolver->depth;
  ulong done_depth = resolver->done_depth;

  int lg_depth = fd_ulong_find_msb( depth );

  ulong scratch_top = (ulong)shmem;
  /*     self    */ SCRATCH_ALLOC( FD_FEC_RESOLVER_ALIGN,  sizeof(fd_fec_resolver_t)                                              );
  void * done     = SCRATCH_ALLOC( FD_TCACHE_ALIGN,        fd_tcache_footprint( done_depth, fd_tcache_map_cnt_default( done_depth )) );
  void * curr_tc  = SCRATCH_ALLOC( FD_TCACHE_ALIGN,        fd_tcache_footprint( depth,      fd_tcache_map_cnt_default( depth      )) );
  void * curr_map = SCRATCH_ALLOC( ctx_map_align(),        ctx_map_footprint( lg_depth+1 )                                        );
  void * freelist = SCRATCH_ALLOC( freelist_align(),       freelist_footprint( depth )                                            );

  fd_sha512_delete( resolver->sha512   );
  freelist_delete(  freelist           );
  ctx_map_delete(   curr_map           );
  fd_tcache_delete( curr_tc            );
  fd_tcache_delete( done               );

  return shmem;
}
