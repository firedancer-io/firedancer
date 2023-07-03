#include "fd_stake.h"

ulong
fd_stake_align( void ) {
  return FD_STAKE_ALIGN;
}

ulong
fd_stake_footprint( void ) {
  ulong l;
  l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, fd_stake_align(), sizeof( fd_stake_t ) );
  l = FD_LAYOUT_APPEND( l,
                        fd_stake_staked_node_align(),
                        fd_stake_staked_node_footprint( FD_STAKE_LG_MAX_STAKED_NODES ) );
  return FD_LAYOUT_FINI( l, fd_stake_align() );
}

void *
fd_stake_new( void * mem ) {
  FD_SCRATCH_ALLOC_INIT( l, mem );
  fd_stake_t * stake = FD_SCRATCH_ALLOC_APPEND( l, fd_stake_align(), sizeof( fd_stake_t ) );
  void *       _staked_node_map =
      FD_SCRATCH_ALLOC_APPEND( l,
                               fd_stake_staked_node_align(),
                               fd_stake_staked_node_footprint( FD_STAKE_LG_MAX_STAKED_NODES ) );
  fd_stake_staked_node_new( _staked_node_map, FD_STAKE_LG_MAX_STAKED_NODES );
  stake->version = 0;
  return mem;
}

fd_stake_t *
fd_stake_join( void * mem ) {
  FD_SCRATCH_ALLOC_INIT( l, mem );
  fd_stake_t * stake  = FD_SCRATCH_ALLOC_APPEND( l, fd_stake_align(), sizeof( fd_stake_t ) );
  stake->staked_nodes = fd_stake_staked_node_join(
      FD_SCRATCH_ALLOC_APPEND( l,
                               fd_stake_staked_node_align(),
                               fd_stake_staked_node_footprint( FD_STAKE_LG_MAX_STAKED_NODES ) ) );
  return stake;
}
