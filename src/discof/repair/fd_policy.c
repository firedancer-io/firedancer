#include "fd_policy.h"

#define NONCE_NULL (UINT_MAX)

fd_repair_req_t *
fd_policy_req_next( fd_policy_t *     policy,
                fd_forest_t *     forest,
                fd_repair_t *     repair ) {
  if( FD_UNLIKELY( forest->root == ULONG_MAX ) ) return NULL;
  if( FD_UNLIKELY( policy->peers->cnt == 0   ) ) return NULL;

  fd_pubkey_t * peer = &policy->peers->arr[ policy->peers->idx++ % policy->peers->cnt ];

  fd_forest_ele_t      * pool     = fd_forest_pool( forest );
  fd_forest_orphaned_t * orphaned = fd_forest_orphaned( forest );

  for( fd_forest_orphaned_iter_t iter = fd_forest_orphaned_iter_init( orphaned, pool );
        !fd_forest_orphaned_iter_done( iter, orphaned, pool );
        iter = fd_forest_orphaned_iter_next( iter, orphaned, pool ) ) {
    fd_forest_ele_t * orphan = fd_forest_orphaned_iter_ele( iter, orphaned, pool );
    return fd_repair_orphan_req( repair, peer, orphan->slot, NONCE_NULL );
  }

  /* Every so often we'll need to reset the frontier iterator to the
     head of frontier, because we could end up traversing down a very
     long tree if we are far behind. */

  long now = fd_log_wallclock();
  if( FD_UNLIKELY( now - policy->tsref > policy->tsmax ) ) {
    // reset iterator to the beginning of the forest frontier
    policy->iterf = fd_forest_iter_init( forest );
    policy->tsref = fd_log_wallclock();
  }

  /* Our frontier is at the head of the turbine, so we should give
     turbine the chance to complete the shreds. !ele handles an edgecase
     where all frontier are fully complete and the iter is done */

  /* FIXME add back after forest rework */

  // fd_forest_ele_t const * ele = fd_forest_pool_ele_const( pool, ctx->repair_iter.ele_idx );
  // if( FD_LIKELY( !ele || ( ele->slot == fd_fseq_query( ctx->turbine_slot ) && ( now - ctx->tsreset ) < (long)30e6 ) ) ){
  //   return;
  // }

  fd_forest_ele_t const * ele = fd_forest_pool_ele_const( pool, policy->iterf.ele_idx );
  fd_repair_req_t * out = fd_ptr_if( policy->iterf.shred_idx == UINT_MAX,
                                     fd_repair_highest_shred_req( repair, peer, ele->slot, 0, NONCE_NULL ),
                                     fd_repair_shred_req( repair, peer, ele->slot, policy->iterf.shred_idx, NONCE_NULL ) );
  policy->iterf = fd_forest_iter_next( policy->iterf, forest );
  if( FD_UNLIKELY( fd_forest_iter_done( policy->iterf, forest ) ) ) policy->iterf = fd_forest_iter_init( forest );
  return out;
}
