#include "fd_stake.h"

ulong
fd_stake_align( void ) {
  return FD_STAKE_ALIGN;
}

ulong
fd_stake_footprint( ulong lg_max_node_cnt ) {
  ulong l;
  l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, fd_stake_align(), sizeof( fd_stake_t ) );
  l = FD_LAYOUT_APPEND(
      l, fd_stake_staked_node_align(), fd_stake_staked_node_footprint( (int)lg_max_node_cnt ) );
  return FD_LAYOUT_FINI( l, fd_stake_align() );
}

void *
fd_stake_new( void * mem, ulong lg_max_node_cnt ) {
  FD_SCRATCH_ALLOC_INIT( l, mem );
  fd_stake_t * stake  = FD_SCRATCH_ALLOC_APPEND( l, fd_stake_align(), sizeof( fd_stake_t ) );
  stake->version = 0;
  stake->total_stake = 0;
  // stake->staked_nodes = fd_stake_staked_node_new(
  //     FD_SCRATCH_ALLOC_APPEND(
  //         l, fd_stake_staked_node_align(), fd_stake_staked_node_footprint( (int)lg_max_node_cnt ) ),
  //     (int)lg_max_node_cnt );
  void * _staked_nodes = FD_SCRATCH_ALLOC_APPEND( l, fd_stake_staked_node_align(), fd_stake_staked_node_footprint( (int)lg_max_node_cnt ) );
  FD_LOG_NOTICE(("staked_nodes %p", _staked_nodes));
  FD_LOG_NOTICE(("lg_max_node_cnt %lu", lg_max_node_cnt));
  stake->staked_nodes = fd_stake_staked_node_new( _staked_nodes, (int)lg_max_node_cnt );
  // void *  _something_else = FD_SCRATCH_ALLOC_APPEND( l, 128, 128 );
  // FD_LOG_ERR(("something else %p", _something_else));

  FD_SCRATCH_ALLOC_FINI( l, fd_stake_align() );
  return mem;
}

fd_stake_t *
fd_stake_join( void * mem ) {
  FD_SCRATCH_ALLOC_INIT( l, mem );
  fd_stake_t * stake  = FD_SCRATCH_ALLOC_APPEND( l, fd_stake_align(), sizeof( fd_stake_t ) );
  // FD_LOG_NOTICE(("footprint %lu", fd_stake_staked_node_footprint()));
  stake->staked_nodes = fd_stake_staked_node_join( stake->staked_nodes );
  FD_LOG_NOTICE(("version %p", (void *)&stake->version));
  FD_LOG_NOTICE(("total stake %p", (void *)&stake->total_stake));
  FD_LOG_NOTICE(("staked nodes %p", (void *)&stake->staked_nodes));
  FD_LOG_NOTICE(("version %lu", stake->version));
  FD_LOG_NOTICE(("total stake %lu", stake->total_stake));
  FD_LOG_NOTICE(("stake %lu", stake->staked_nodes[0].stake));
  FD_LOG_HEXDUMP_NOTICE(("staked nodes", stake->staked_nodes, fd_stake_staked_node_footprint( 16 ) ));
  FD_SCRATCH_ALLOC_FINI( l, fd_stake_align() );
  return stake;
}

ulong *
fd_stake_version( fd_stake_t * stake ) {
  return &stake->version;
}

void
fd_stake_update(fd_stake_t * stake, uchar * staked_nodes_ser, ulong sz) {
  FD_LOG_NOTICE(("updating stake"));
  fd_stake_staked_node_t * staked_nodes = stake->staked_nodes;
  fd_stake_staked_node_clear( staked_nodes );
  for ( ulong off = 0; off < sz; off += 40 ) {
    /* 32-byte aligned. dcache is 128-byte aligned. 128 % 32 = 0. */
    fd_stake_pubkey_t * pubkey = (fd_stake_pubkey_t *)(staked_nodes_ser + off);
    /* 8-byte aligned. 32 + 8 = 40. 40 % 8 = 0. */
    ulong * stake = (ulong *)( staked_nodes_ser + off + sizeof( fd_stake_t ) );
    /* staked node */
    fd_stake_staked_node_t * staked_node =
        fd_stake_staked_node_insert( staked_nodes, *pubkey );
    staked_node->stake = *stake;
    FD_LOG_HEXDUMP_NOTICE( ( "pubkey", pubkey, sizeof( fd_stake_pubkey_t ) ) );
    FD_LOG_NOTICE( ( "stake %lu", *stake ) );
  }
}
