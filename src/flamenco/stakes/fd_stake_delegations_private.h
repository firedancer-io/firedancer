#ifndef HEADER_fd_src_flamenco_stakes_fd_stake_delegations_private_h
#define HEADER_fd_src_flamenco_stakes_fd_stake_delegations_private_h

FD_PROTOTYPES_BEGIN

void
fd_stake_delegations_iter_read_disk_delta_private( fd_stake_delegations_iter_t * iter,
                                                   uint                          delta_idx );

void
fd_stake_delegations_iter_advance_disk_root_private( fd_stake_delegations_iter_t * iter );

/* Advance to the next live (in_use), non-tombstone root pool
   delegation, or to the watermark if none remain.  Redirects to the
   delta pool if there's a fork delta.  Inlined for the boundary hot
   path.  DO NOT un-inline. */

static inline void
fd_stake_delegations_iter_advance_private( fd_stake_delegations_iter_t * iter ) {
  while( iter->idx<iter->wmk ) {
    fd_stake_delegation_t * root_delegation = iter->root_pool+iter->idx;
    if( FD_LIKELY( root_delegation->in_use ) ) {
      if( FD_UNLIKELY( root_delegation->delta_idx!=UINT_MAX &&
                       (root_delegation->delta_idx & FD_STAKE_DELEGATIONS_DELTA_DISK_TAG) ) ) {
        fd_stake_delegations_iter_read_disk_delta_private( iter, root_delegation->delta_idx & FD_STAKE_DELEGATIONS_DELTA_IDX_MASK );
        if( FD_LIKELY( iter->ele ) ) return;
        iter->idx++;
        continue;
      }
      fd_stake_delegation_t * ele = root_delegation->delta_idx!=UINT_MAX ? iter->delta_pool+root_delegation->delta_idx : root_delegation;
      if( FD_LIKELY( !ele->is_tombstone ) ) {
        iter->ele = ele;
        return;
      }
    }
    iter->idx++;
  }
  fd_stake_delegations_iter_advance_disk_root_private( iter );
}

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_stakes_fd_stake_delegations_private_h */
