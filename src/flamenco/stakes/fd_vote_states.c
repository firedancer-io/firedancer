#include "fd_vote_states.h"

fd_vote_state_ele_t *
fd_vote_states_get_pool( fd_vote_states_t const * vote_states ) {
  FD_SCRATCH_ALLOC_INIT( l, vote_states );
  FD_SCRATCH_ALLOC_APPEND( l, fd_vote_states_align(), sizeof(fd_vote_states_t) );
  uchar * pool = FD_SCRATCH_ALLOC_APPEND( l, fd_vote_states_align(), fd_vote_states_footprint( vote_states->max_vote_accounts ) );
  return fd_vote_states_pool_join( pool );
}

fd_vote_state_map_t *
fd_vote_states_get_map( fd_vote_states_t const * vote_states ) {
  FD_SCRATCH_ALLOC_INIT( l, vote_states );
  FD_SCRATCH_ALLOC_APPEND( l, fd_vote_states_align(), sizeof(fd_vote_states_t) );
  FD_SCRATCH_ALLOC_APPEND( l, fd_vote_state_pool_align(), fd_vote_state_pool_footprint( vote_states->max_vote_accounts ) );
  ulong map_chain_cnt = fd_vote_state_map_chain_cnt_est( vote_states->max_vote_accounts );
  uchar * map = FD_SCRATCH_ALLOC_APPEND( l, fd_vote_state_map_align(), fd_vote_state_map_footprint( map_chain_cnt ) );
  return fd_vote_state_map_join( map );
}
