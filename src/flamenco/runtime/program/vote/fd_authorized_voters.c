#include "fd_authorized_voters.h"
#include "fd_vote_state_v3.h"
#include "fd_vote_state_v4.h"

/**********************************************************************/
/* impl AuthorizedVoters                                              */
/**********************************************************************/

// https://github.com/anza-xyz/agave/blob/v2.0.1/sdk/program/src/vote/authorized_voters.rs#L17
fd_vote_authorized_voters_t *
fd_authorized_voters_new( ulong               epoch,
                          fd_pubkey_t const * pubkey,
                          uchar *             mem ) {

  FD_SCRATCH_ALLOC_INIT( l, mem );
  fd_vote_authorized_voters_t * authorized_voters = FD_SCRATCH_ALLOC_APPEND( l, fd_vote_authorized_voters_align(),       sizeof(fd_vote_authorized_voters_t) );
  void *                        pool_mem          = FD_SCRATCH_ALLOC_APPEND( l, fd_vote_authorized_voters_pool_align(),  fd_vote_authorized_voters_pool_footprint( FD_VOTE_AUTHORIZED_VOTERS_MIN ) );
  void *                        treap_mem         = FD_SCRATCH_ALLOC_APPEND( l, fd_vote_authorized_voters_treap_align(), fd_vote_authorized_voters_treap_footprint( FD_VOTE_AUTHORIZED_VOTERS_MIN ) );

  authorized_voters->pool  = fd_vote_authorized_voters_pool_join( fd_vote_authorized_voters_pool_new( pool_mem, FD_VOTE_AUTHORIZED_VOTERS_MIN ) );
  authorized_voters->treap = fd_vote_authorized_voters_treap_join( fd_vote_authorized_voters_treap_new( treap_mem, FD_VOTE_AUTHORIZED_VOTERS_MIN ) );
  if( 0 == fd_vote_authorized_voters_pool_free( authorized_voters->pool ) ) {
    FD_LOG_ERR(( "Authorized_voter pool is empty" ));
  }
  fd_vote_authorized_voter_t * ele = fd_vote_authorized_voters_pool_ele_acquire( authorized_voters->pool );
  ele->epoch  = epoch;
  ele->pubkey = *pubkey;
  ele->prio   = (ulong)&ele->pubkey;
  fd_vote_authorized_voters_treap_ele_insert( authorized_voters->treap, ele, authorized_voters->pool );
  return authorized_voters;
}

// Helper to create an empty AuthorizedVoters structure (for default/uninitialized states)
fd_vote_authorized_voters_t *
fd_authorized_voters_new_empty( uchar * mem ) {
  FD_SCRATCH_ALLOC_INIT( l, mem );
  fd_vote_authorized_voters_t * authorized_voters = FD_SCRATCH_ALLOC_APPEND( l, fd_vote_authorized_voters_align(),       sizeof(fd_vote_authorized_voters_t) );
  void *                        pool_mem          = FD_SCRATCH_ALLOC_APPEND( l, fd_vote_authorized_voters_pool_align(),  fd_vote_authorized_voters_pool_footprint( FD_VOTE_AUTHORIZED_VOTERS_MIN ) );
  void *                        treap_mem         = FD_SCRATCH_ALLOC_APPEND( l, fd_vote_authorized_voters_treap_align(), fd_vote_authorized_voters_treap_footprint( FD_VOTE_AUTHORIZED_VOTERS_MIN ) );

  authorized_voters->pool  = fd_vote_authorized_voters_pool_join( fd_vote_authorized_voters_pool_new( pool_mem, FD_VOTE_AUTHORIZED_VOTERS_MIN ) );
  authorized_voters->treap = fd_vote_authorized_voters_treap_join( fd_vote_authorized_voters_treap_new( treap_mem, FD_VOTE_AUTHORIZED_VOTERS_MIN ) );
  return authorized_voters;
}

int
fd_authorized_voters_is_empty( fd_vote_authorized_voters_t * self ) {
  return fd_vote_authorized_voters_treap_ele_cnt( self->treap ) == 0;
}

// https://github.com/anza-xyz/agave/blob/v2.0.1/sdk/program/src/vote/authorized_voters.rs#L80
int
fd_authorized_voters_contains( fd_vote_authorized_voters_t * self, ulong epoch ) {
  return !!fd_vote_authorized_voters_treap_ele_query( self->treap, epoch, self->pool );
}

// https://github.com/anza-xyz/agave/blob/v2.0.1/sdk/program/src/vote/authorized_voters.rs#L72
fd_vote_authorized_voter_t *
fd_authorized_voters_last( fd_vote_authorized_voters_t * self ) {
  fd_vote_authorized_voters_treap_rev_iter_t iter =
      fd_vote_authorized_voters_treap_rev_iter_init( self->treap, self->pool );
  return fd_vote_authorized_voters_treap_rev_iter_ele( iter, self->pool );
}

// https://github.com/anza-xyz/agave/blob/v2.0.1/sdk/program/src/vote/authorized_voters.rs#L43
void
fd_authorized_voters_purge_authorized_voters( fd_vote_authorized_voters_t * self,
                                              ulong                         current_epoch ) {

  // https://github.com/anza-xyz/agave/blob/v2.0.1/sdk/program/src/vote/authorized_voters.rs#L46
  ulong expired_keys[ FD_VOTE_AUTHORIZED_VOTERS_MIN ];
  ulong key_cnt                                     = 0;
  for( fd_vote_authorized_voters_treap_fwd_iter_t iter =
           fd_vote_authorized_voters_treap_fwd_iter_init( self->treap, self->pool );
       !fd_vote_authorized_voters_treap_fwd_iter_done( iter );
       iter = fd_vote_authorized_voters_treap_fwd_iter_next( iter, self->pool ) ) {
    fd_vote_authorized_voter_t * ele =
        fd_vote_authorized_voters_treap_fwd_iter_ele( iter, self->pool );
    if( ele->epoch < current_epoch ) expired_keys[key_cnt++] = ele->epoch;
  }

  // https://github.com/anza-xyz/agave/blob/v2.0.1/sdk/program/src/vote/authorized_voters.rs#L52
  for( ulong i = 0; i < key_cnt; i++ ) {
    fd_vote_authorized_voter_t * ele =
        fd_vote_authorized_voters_treap_ele_query( self->treap, expired_keys[i], self->pool );
    fd_vote_authorized_voters_treap_ele_remove( self->treap, ele, self->pool );
    fd_vote_authorized_voters_pool_ele_release( self->pool, ele );
  }

  // https://github.com/anza-xyz/agave/blob/v2.0.1/sdk/program/src/vote/authorized_voters.rs#L60
  FD_TEST( !fd_authorized_voters_is_empty( self ) );

}

// https://github.com/anza-xyz/agave/blob/v2.0.1/sdk/program/src/vote/authorized_voters.rs#L91
fd_vote_authorized_voter_t *
fd_authorized_voters_get_or_calculate_authorized_voter_for_epoch( fd_vote_authorized_voters_t * self,
                                                                  ulong                         epoch,
                                                                  int *                         existed ) {
  *existed                                  = 0;
  ulong                        latest_epoch = 0;
  fd_vote_authorized_voter_t * res =
      fd_vote_authorized_voters_treap_ele_query( self->treap, epoch, self->pool );
  // "predecessor" would be more big-O optimal here, but mirroring labs logic
  // https://github.com/anza-xyz/agave/blob/v2.0.1/sdk/program/src/vote/authorized_voters.rs#L93
  if( FD_UNLIKELY( !res ) ) {
    for( fd_vote_authorized_voters_treap_fwd_iter_t iter =
             fd_vote_authorized_voters_treap_fwd_iter_init( self->treap, self->pool );
         !fd_vote_authorized_voters_treap_fwd_iter_done( iter );
         iter = fd_vote_authorized_voters_treap_fwd_iter_next( iter, self->pool ) ) {
      fd_vote_authorized_voter_t * ele =
          fd_vote_authorized_voters_treap_fwd_iter_ele( iter, self->pool );
      if( ele->epoch < epoch && ( latest_epoch == 0 || ele->epoch > latest_epoch ) ) {
        latest_epoch = ele->epoch;
        res          = ele;
      }
    }
    *existed = 0;
    return res;
  } else {
    *existed = 1;
    return res;
  }
  return res;
}

// https://github.com/anza-xyz/agave/blob/v2.0.1/sdk/program/src/vote/authorized_voters.rs#L28
fd_vote_authorized_voter_t *
fd_authorized_voters_get_and_cache_authorized_voter_for_epoch( fd_vote_authorized_voters_t * self,
                                                               ulong                         epoch ) {
  int                          existed = 0;
  // https://github.com/anza-xyz/agave/blob/v2.0.1/sdk/program/src/vote/authorized_voters.rs#L29
  fd_vote_authorized_voter_t * res =
      fd_authorized_voters_get_or_calculate_authorized_voter_for_epoch( self, epoch, &existed );
  if( !res ) return NULL;
  // https://github.com/anza-xyz/agave/blob/v2.0.1/sdk/program/src/vote/authorized_voters.rs#L32
  if( !existed ) {
    /* insert cannot fail because !existed */
    if( 0 == fd_vote_authorized_voters_pool_free( self->pool) ) {
      FD_LOG_ERR(( "Authorized_voter pool is empty" ));
    }
    fd_vote_authorized_voter_t * ele = fd_vote_authorized_voters_pool_ele_acquire( self->pool );
    ele->epoch                       = epoch;
    ele->pubkey                      = res->pubkey;
    ele->prio                        = (ulong)&res->pubkey;
    // https://github.com/anza-xyz/agave/blob/v2.0.1/sdk/program/src/vote/authorized_voters.rs#L33
    fd_vote_authorized_voters_treap_ele_insert( self->treap, ele, self->pool );
  }
  return res;
}

int
fd_authorized_voters_get_and_update_authorized_voter( fd_vote_state_versioned_t * self,
                                                      ulong                       current_epoch,
                                                      fd_pubkey_t **              pubkey /* out */ ) {
  switch( self->discriminant ) {
    case fd_vote_state_versioned_enum_v3:
      return fd_vote_state_v3_get_and_update_authorized_voter( &self->inner.v3, current_epoch, pubkey );
    case fd_vote_state_versioned_enum_v4:
      return fd_vote_state_v4_get_and_update_authorized_voter( &self->inner.v4, current_epoch, pubkey );
    default:
      __builtin_unreachable();
  }
}
