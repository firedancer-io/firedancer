#include "fd_stake.h"

ulong
fd_stake_align( void ) {
  return FD_STAKE_ALIGN;
}

ulong
fd_stake_footprint( int lg_slot_cnt ) {
  if ( lg_slot_cnt <= 0 ) { return 0UL; }
  ulong l;
  l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, fd_stake_align(), sizeof( fd_stake_t ) );
  l = FD_LAYOUT_APPEND( l, fd_stake_node_align(), fd_stake_node_footprint( (int)lg_slot_cnt ) );
  return FD_LAYOUT_FINI( l, fd_stake_align() );
}

void *
fd_stake_new( void * shmem, int lg_slot_cnt ) {

  if ( FD_UNLIKELY( !shmem ) ) {
    FD_LOG_WARNING( ( "NULL shmem" ) );
    return NULL;
  }

  if ( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shmem, fd_stake_align() ) ) ) {
    FD_LOG_WARNING( ( "misaligned shmem" ) );
    return NULL;
  }

  ulong footprint = fd_stake_node_footprint( (int)lg_slot_cnt );
  if ( FD_UNLIKELY( !footprint ) ) {
    FD_LOG_WARNING( ( "bad lg_slot_cnt (%d): must be >=0", lg_slot_cnt ) );
    return NULL;
  }

  fd_memset( shmem, 0, footprint );

  fd_stake_t * stake = (fd_stake_t *)shmem;
  fd_mvcc_t    mvcc  = { .version = 0 };
  stake->mvcc        = mvcc;
  stake->total_stake = 0;
  /* note the map join happens inside `new`, because the offset from the start of the stake region
   * to map slot0 is stable across joins */
  fd_stake_node_t * staked_nodes =
      fd_stake_node_join( fd_stake_node_new( stake + sizeof( fd_stake_t ), lg_slot_cnt ) );
  stake->nodes_off = (ulong)staked_nodes - (ulong)stake;

  FD_COMPILER_MFENCE();
  FD_VOLATILE( stake->magic ) = FD_STAKE_MAGIC;
  FD_COMPILER_MFENCE();

  return shmem;
}

fd_stake_t *
fd_stake_join( void * shstake ) {

  if ( FD_UNLIKELY( !shstake ) ) {
    FD_LOG_WARNING( ( "NULL shstake" ) );
    return NULL;
  }

  if ( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shstake, fd_stake_align() ) ) ) {
    FD_LOG_WARNING( ( "misaligned shmem" ) );
    return NULL;
  }

  fd_stake_t * stake = (fd_stake_t *)shstake;
  if ( FD_UNLIKELY( stake->magic != FD_STAKE_MAGIC ) ) {
    FD_LOG_WARNING( ( "bad magic" ) );
    return NULL;
  }

  fd_stake_node_t * map_ptr = fd_stake_nodes_laddr( stake );
  fd_stake_node_join( map_ptr );

  return stake;
}

ulong
fd_stake_version( fd_stake_t * stake ) {
  FD_COMPILER_MFENCE();
  return stake->version;
}

ulong *
fd_stake_version_laddr( fd_stake_t * stake ) {
  return &stake->version;
}

fd_stake_node_t *
fd_stake_nodes_laddr( fd_stake_t * stake ) {
  return (fd_stake_node_t *)( (ulong)stake + stake->nodes_off );
}

/* fd_stake_version performs a fenced read of the version number. `fd_stake_t` is a single-producer,
 * multiple-consumer concurrency structure and an odd version number indicates the writer is
 * currently writing to the structure. */
void
fd_stake_update( fd_stake_t * stake, uchar * staked_nodes_ser, ulong sz ) {
  fd_mvcc_begin_write( &stake->mvcc );

  fd_stake_node_t * staked_nodes = fd_stake_nodes_laddr( stake );
  fd_stake_node_clear( staked_nodes );
  for ( ulong off = 0; off < sz; off += 40 ) {
    /* 32-byte aligned. dcache is 128-byte aligned. 128 % 32 = 0. */
    fd_stake_pubkey_t * pubkey = (fd_stake_pubkey_t *)( fd_type_pun( staked_nodes_ser + off ) );
    /* 8-byte aligned. 32 + 8 = 40. 40 % 8 = 0. */
    ulong * stake =
        (ulong *)( fd_type_pun( staked_nodes_ser + off + sizeof( fd_stake_pubkey_t ) ) );
    fd_stake_node_t * staked_node = fd_stake_node_insert( staked_nodes, *pubkey );
    if ( staked_node == NULL ) staked_node = fd_stake_node_query( staked_nodes, *pubkey, NULL );
    if ( staked_node == NULL ) {
      FD_LOG_HEXDUMP_WARNING( ( "failed to insert pubkey", pubkey, sizeof( fd_stake_pubkey_t ) ) );
      continue;
    }
    staked_node->stake = *stake;
  }

  fd_mvcc_end_write( &stake->mvcc );
}

void
fd_stake_dump( fd_stake_t * stake ) {
  fd_stake_node_t * staked_nodes = fd_stake_nodes_laddr( stake );
  for ( ulong i = 0; i < fd_stake_node_slot_cnt( staked_nodes ); i++ ) {
    fd_stake_node_t * staked_node = &staked_nodes[i];
    if ( !fd_stake_node_key_inval( staked_node->key ) ) {
      FD_LOG_NOTICE( ( "stake[%lu] = %lu", i, staked_node->stake ) );
    }
  }
}
