#include "fd_shred.h"
#include "fd_fec_set.h"
#include "../../tango/tcache/fd_tcache.h"
#include "../bmtree/fd_bmtree.h"
#include "../sha512/fd_sha512.h"
#include "../ed25519/fd_ed25519.h"
#include "../reedsol/fd_reedsol.h"

#define INCLUSION_PROOF_LAYERS 10UL

extern uchar test_private_key[];

struct set_ctx {
  ulong          sig_tag;
  fd_fec_set_t * set;
  fd_bmtree_commit_t  * tree;
  ulong          total_rx_shred_cnt;
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

struct fd_fec_resolver {
  /* done: stores tags of signatures of FEC sets that have recently been
     completed.  Any new packets matching tags in this set can be
     ignored.  This tcache has depth done_depth. */
  fd_tcache_t * done;

  /* curr_tc: stores tags of signatures of FEC sets that are
     currently in progress.  If a tag is in curr_tc, it must also be in
     curr_ctx.  This tcache is used mostly for it's LRU properties, not
     for searching.  It tells us which element to remove from the map
     when we need to remove one.  The depth of this tcache is `depth` */
  fd_tcache_t * curr_tc;

  /* curr_map: A map (using fd_map_dynamic) from tags of signatures to
     the context object with its relavant data.  This map contains at
     most `depth` elements at any time, but to improve query performace,
     we size it at 2*depth. */
  set_ctx_t   * curr_map;

  /* freelist: Stores the other set_ctx_t objects that are not in
     curr_ctx.  The max size of this list is depth. */
  set_ctx_t * freelist;

  fd_sha512_t * sha512;

  fd_reedsol_t * reedsol;
};

ulong fd_fec_resolver_footprint( ulong depth );
ulong fd_fec_resolver_align    ( void        );

ulong fd_fec_resolver_new( void * shmem, ulong depth, fd_fec_set_t * sets );

fd_fec_resolver_t * fd_fec_resolver_join( void * shmem );

fd_fec_set_t *
fd_fec_resolver_add_shred( fd_fec_resolver_t * resolver, fd_shred_t const * shred, ulong shred_sz ) {
  /* Unpack variables */
  fd_tcache_t  * done          = resolver->done;
  ulong          done_depth    = fd_tcache_depth(        done );
  ulong          done_map_cnt  = fd_tcache_map_cnt(      done );
  ulong        * done_oldest   = fd_tcache_oldest_laddr( done );
  ulong        * done_ring     = fd_tcache_ring_laddr(   done );
  ulong        * done_map      = fd_tcache_map_laddr(    done );

  fd_tcache_t  * curr_tc       = resolver->curr_tc;
  ulong          curt_depth    = fd_tcache_depth(        curr_tc );
  ulong          curt_map_cnt  = fd_tcache_map_cnt(      curr_tc );
  ulong        * curt_oldest   = fd_tcache_oldest_laddr( curr_tc );
  ulong        * curt_ring     = fd_tcache_ring_laddr(   curr_tc );
  ulong        * curt_map      = fd_tcache_map_laddr(    curr_tc );

  set_ctx_t    * freelist      = resolver->freelist;
  set_ctx_t    * curr_map      = resolver->curr_map;

  fd_reedsol_t * reedsol       = resolver->reedsol;

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
  /* TODO: SHA 256 payload to leaf */
  uchar variant    = shred->variant;
  uchar shred_type = fd_shred_type( variant );

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
      ctx = ctx_map_query( curr_map, *curt_oldest, NULL );
      if( FD_UNLIKELY( !ctx ) ) FD_LOG_ERR(( "data structures not in sync" ));
      /* Add this one that we're sacrificing to the done tcache to
         prevent the possibility of thrashing. */
      FD_TCACHE_INSERT( dup, *done_oldest, done_ring, done_depth, done_map, done_map_cnt, ctx->sig_tag );
      ctx_map_remove( curr_map, ctx );
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

    if( FD_UNLIKELY( !fd_ed25519_verify( _root->hash, 32UL, shred->signature, test_private_key+32UL, resolver->sha512 ) ) ) {
      freelist_push_head( freelist, *ctx );
      return NULL;
    }

    /* This seems like a legitimate FEC set, so we can reserve some
       resources for it. */

    FD_TCACHE_INSERT( dup, *curt_oldest, curt_ring, curt_depth, curt_map, curt_map_cnt, signature );
    set_ctx_t * e = ctx_map_insert( curr_map, signature );
    e->set  = ctx->set;
    e->tree = ctx->tree;
    e->total_rx_shred_cnt = 0UL;

    /* Reset the FEC set */
    e->set->data_shred_cnt = 0UL;
    e->set->parity_shred_cnt = 0UL;
    d_present_join( d_present_new( d_present_delete( d_present_join( e->set->data_shred_present   ) ) ) );
    p_present_join( p_present_new( p_present_delete( p_present_join( e->set->parity_shred_present ) ) ) );

    ctx = e;
  } else {
    /* Validate Merkle proof, that it gives the right root. */
    int rv = fd_bmtree_commitp_insert_with_proof( ctx->tree, shred_idx, _leaf,
                                                  (uchar*)fd_shred_merkle_nodes( shred ), fd_shred_merkle_cnt( variant ), NULL );
    if( !rv ) return NULL;
  }

  /* At this point, the shred has passed Merkle validation.  We also
     know that ctx == ctx_map_query( curr_map, signature, NULL). */

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

  // FIXME: Wrong condition
  if( FD_LIKELY( ctx->total_rx_shred_cnt < ctx->set->data_shred_cnt ) ) return NULL;

  /* At this point, the FEC set is either valid or permanently invalid,
     so we can consider it done either way. */
  freelist_push_tail( freelist, *ctx );
  ctx_map_remove( curr_map, ctx );
  FD_TCACHE_INSERT( dup, *done_oldest, done_ring, done_depth, done_map, done_map_cnt, signature );

  /* TODO: Create reedsol, add all shreds */

  if( FD_UNLIKELY( FD_REEDSOL_OK != fd_reedsol_recover_fini( reedsol ) ) ) {
    /* A few lines up, we already checked to make sure it wasn't the
       insufficient case, so it must be the inconsistent case.  That
       means the leader signed a shred with invalid Reed-Solomon FEC
       set.  This shouldn't happen in practice, but we need to handle it
       for the malicious leader case.  This should probably be a
       slash-able offense. */
    return NULL;
  }
  /* Iterate over recovered shreds, add them to the Merkle tree.  If it
     fails return */

  /* Finally... A valid FEC set.  Forward it along. */
  return ctx->set;
}

void * fd_fec_resolver_leave( fd_fec_resolver_t * resolver );
void * fd_fec_resolver_delete( void * shmem );
