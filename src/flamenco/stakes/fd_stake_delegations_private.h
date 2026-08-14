#ifndef HEADER_fd_src_flamenco_stakes_fd_stake_delegations_private_h
#define HEADER_fd_src_flamenco_stakes_fd_stake_delegations_private_h

FD_PROTOTYPES_BEGIN

/* Advance to the next live (in_use), non-tombstone root pool
   delegation, or to the watermark if none remain.  Redirects to the
   delta pool if there's a fork delta.  Inlined for the boundary hot
   path.  DO NOT un-inline. */

static inline void
fd_stake_delegations_iter_advance_private( fd_stake_delegations_iter_t * iter ) {
  while( iter->idx<iter->wmk ) {
    fd_stake_delegation_t * root_delegation = iter->root_pool+iter->idx;
    if( FD_LIKELY( root_delegation->in_use ) ) {
      fd_stake_delegation_t * ele = (root_delegation->delta_idx!=UINT_MAX) ? (iter->delta_pool+root_delegation->delta_idx) : root_delegation;
      if( FD_LIKELY( !ele->is_tombstone ) ) {
        iter->ele = ele;
        return;
      }
    }
    iter->idx++;
  }
  iter->ele = NULL;
}

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_stakes_fd_stake_delegations_private_h */
