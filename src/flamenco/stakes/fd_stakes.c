#include "fd_stakes.h"

/* fd_stake_weights is a rbtree of fd_stake_weight_t, ordered by stake
   weight descending.  Keys can be node identities or vote accounts. */

struct fd_stake_weight_ele {
  fd_stake_weight_t ele;
  ulong             redblack_parent;
  ulong             redblack_left;
  ulong             redblack_right;
  int               redblack_color;
};
typedef struct fd_stake_weight_ele fd_stake_weight_ele_t;

FD_FN_PURE long
fd_stake_weights_compare( fd_stake_weight_ele_t * e0,
                          fd_stake_weight_ele_t * e1) {
  return (long)memcmp( &e0->ele.pub, &e1->ele.pub, 32UL );
}

#define REDBLK_NAME fd_stake_weights
#define REDBLK_T    fd_stake_weight_ele_t
#include "../../util/tmpl/fd_redblack.c"


/* fd_stakes_accum_by_node converts Stakes (unordered list of (vote acc,
   active stake) tuples) to StakedNodes (rbtree mapping (node identity)
   => (active stake) ordered by node identity).  Returns the tree root. */

static fd_stake_weight_ele_t *
fd_stakes_accum_by_node( fd_vote_accounts_t const * in,
                         fd_stake_weight_ele_t *    out_pool ) {

  /* Stakes::staked_nodes(&self: Stakes) -> HashMap<Pubkey, u64> */

  fd_vote_accounts_pair_t_mapnode_t * in_pool = in->vote_accounts_pool;
  fd_vote_accounts_pair_t_mapnode_t * in_root = in->vote_accounts_root;

  /* VoteAccounts::staked_nodes(&self: VoteAccounts) -> HashMap<Pubkey, u64> */

  /* For each active vote account, accumulate (node_identity, stake) by
     summing stake. */

  fd_stake_weight_ele_t * out_root = NULL;

  for( fd_vote_accounts_pair_t_mapnode_t * n = fd_vote_accounts_pair_t_map_minimum( in_pool, in_root );
                                           n;
                                           n = fd_vote_accounts_pair_t_map_successor( in_pool, n ) ) {

    /* ... filter(|(stake, _)| *stake != 0u64) */
    if( n->elem.stake == 0UL ) continue;

    /* Create scratch allocator for current scope */
    FD_SCRATCH_SCOPED_FRAME;  fd_valloc_t scratch = fd_scratch_virtual();

    /* Decode vote account */
    uchar const * vote_acc_data = n->elem.value.data;
    fd_bincode_decode_ctx_t decode_ctx = {
      .data    = vote_acc_data,
      .dataend = vote_acc_data + n->elem.value.data_len,
      .valloc  = scratch,
    };
    fd_vote_state_versioned_t vote_state_versioned;
    if( FD_UNLIKELY( 0!=fd_vote_state_versioned_decode( &vote_state_versioned, &decode_ctx ) ) ) {
      /* TODO can this occur on a real cluster? */
      FD_LOG_WARNING(( "Failed to deserialize vote account %32J", n->elem.key.key ));
      continue;
    }

    /* Extract node pubkey */
    fd_pubkey_t const * node_pubkey;
    switch( vote_state_versioned.discriminant ) {
    case fd_vote_state_versioned_enum_v0_23_5:
      node_pubkey = &vote_state_versioned.inner.v0_23_5.voting_node; break;
    case fd_vote_state_versioned_enum_current:
      node_pubkey = &vote_state_versioned.inner.current.voting_node; break;
    default:
      __builtin_unreachable();
    }

    /* Check if node identity was previously visited */
    fd_stake_weight_ele_t * query = fd_stake_weights_acquire( out_pool );
    FD_TEST( query );
    query->ele.pub = *node_pubkey;
    fd_stake_weight_ele_t * node = fd_stake_weights_find( out_pool, out_root, query );

    if( FD_UNLIKELY( node ) ) {
      /* Accumulate to previously created entry */
      fd_stake_weights_release( out_pool, query );
      node->ele.stake += n->elem.stake;
    } else {
      /* Create new entry */
      node = query;
      node->ele.stake = n->elem.stake;
      fd_stake_weights_insert( out_pool, &out_root, node );
    }

  }

  return out_root;
}

/* fd_stake_weight_sort sorts the given array of stake weights with
   length stakes_cnt by tuple (stake, pubkey) in descending order. */

FD_FN_CONST static int
fd_stakes_sort_before( fd_stake_weight_t a,
                       fd_stake_weight_t b ) {

  if( a.stake > b.stake ) return 1;
  if( a.stake < b.stake ) return 0;
  if( memcmp( &a.pub, &b.pub, 32UL )>0 ) return 1;
  return 0;
}

#define SORT_NAME        fd_stakes_sort
#define SORT_KEY_T       fd_stake_weight_t
#define SORT_BEFORE(a,b) fd_stakes_sort_before( (a), (b) )
#include "../../util/tmpl/fd_sort.c"

void
fd_stake_weight_sort( fd_stake_weight_t * stakes,
                      ulong               stakes_cnt ) {
  fd_stakes_sort_inplace( stakes, stakes_cnt );
}

/* fd_stakes_export_sorted converts StakedNodes (rbtree mapping
   (node identity) => (active stake) from fd_stakes_accum_by_node) to
   a list of fd_stake_weights_t. */

static ulong
fd_stakes_export( fd_stake_weight_ele_t const * const in_pool,
                  fd_stake_weight_ele_t const * const root,
                  fd_stake_weight_t *           const out ) {

  fd_stake_weight_t * out_end = out;

  for( fd_stake_weight_ele_t const * ele = fd_stake_weights_minimum( (fd_stake_weight_ele_t *)in_pool, (fd_stake_weight_ele_t *)root ); ele; ele = (fd_stake_weight_ele_t *)fd_stake_weights_successor( (fd_stake_weight_ele_t *)in_pool, (fd_stake_weight_ele_t *)ele ) ) {
    *out_end++ = ele->ele;
  }

  return (ulong)( out_end - out );
}

ulong
fd_stake_weights_by_node( fd_vote_accounts_t const * accs,
                          fd_stake_weight_t *        weights ) {

  /* Enter scratch frame for duration for function */

  if( FD_UNLIKELY( !fd_scratch_push_is_safe() ) ) {
    FD_LOG_WARNING(( "fd_scratch_push() failed" ));
    return ULONG_MAX;
  }

  FD_SCRATCH_SCOPED_FRAME;

  /* Estimate size required to store temporary data structures */

  /* TODO size is the wrong method name for this */
  ulong vote_acc_cnt = fd_vote_accounts_pair_t_map_size( accs->vote_accounts_pool, accs->vote_accounts_root );

  ulong rb_align     = fd_stake_weights_align();
  ulong rb_footprint = fd_stake_weights_footprint( vote_acc_cnt );

  if( FD_UNLIKELY( !fd_scratch_alloc_is_safe( rb_align, rb_footprint ) ) ) {
    FD_LOG_WARNING(( "insufficient scratch space: need %lu align %lu footprint",
                     rb_align, rb_footprint ));
    return ULONG_MAX;
  }

  /* Create rb tree */

  void * pool_mem = fd_scratch_alloc( rb_align, rb_footprint );
         pool_mem = fd_stake_weights_new( pool_mem, vote_acc_cnt );
  fd_stake_weight_ele_t * pool = fd_stake_weights_join( pool_mem );
  if( FD_UNLIKELY( !pool_mem ) ) FD_LOG_CRIT(( "fd_stake_weights_new() failed" ));

  /* Accumulate stakes to rb tree */

  fd_stake_weight_ele_t const * root = fd_stakes_accum_by_node( accs, pool );

  /* Export to sorted list */

  ulong weights_cnt = fd_stakes_export( pool, root, weights );
  fd_stake_weight_sort( weights, weights_cnt );
  return weights_cnt;
}
