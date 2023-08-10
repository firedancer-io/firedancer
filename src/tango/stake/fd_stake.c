#include "../mvcc/fd_mvcc.h"
#include "fd_stake.h"
#include <stdio.h>

ulong
fd_stake_align( void ) {
  return FD_STAKE_ALIGN;
}

ulong
fd_stake_footprint( int lg_slot_cnt ) {
  if ( lg_slot_cnt <= 0 ) { return 0UL; }
  return fd_ulong_align_up( sizeof( fd_stake_t ) + fd_stake_node_footprint( lg_slot_cnt ),
                            fd_stake_align() );
}

void *
fd_stake_new( void * shmem, int lg_slot_cnt ) {

  if ( FD_UNLIKELY( !shmem ) ) {
    FD_LOG_WARNING( ( "NULL shmem" ) );
    return NULL;
  }

  if ( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shmem, fd_stake_align() ) ) ) {
    FD_LOG_NOTICE(("unaligned"));
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
  fd_stake_node_new( (uchar *)stake + sizeof( fd_stake_t ), lg_slot_cnt );

  FD_COMPILER_MFENCE();
  FD_VOLATILE( stake->magic ) = FD_STAKE_MAGIC;
  FD_COMPILER_MFENCE();

  return shmem;
}

fd_stake_t *
fd_stake_join( void * shstake ) {
  FD_TEST(shstake);

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

  uchar * shmap = (uchar *)shstake + sizeof( fd_stake_t );
  fd_stake_node_t * stake_node = fd_stake_node_join( shmap );
  stake->nodes_off = (ulong)stake_node - (ulong)stake;

  return stake;
}

fd_stake_node_t *
fd_stake_nodes_laddr( fd_stake_t * stake ) {
  return (fd_stake_node_t *)( (ulong)stake + stake->nodes_off );
}

void
fd_stake_deser( fd_stake_t * stake, uchar * data, ulong sz ) {
  fd_mvcc_begin_write( &stake->mvcc );

  fd_stake_node_t * staked_nodes = fd_stake_nodes_laddr( stake );
  fd_stake_node_clear( staked_nodes );
  ulong total_stake = 0;
  for ( ulong off = 0; off < sz; off += 40 ) {
    /* 32-byte aligned. dcache is 128-byte aligned. 128 % 32 = 0. */
    fd_stake_pubkey_t * pubkey = (fd_stake_pubkey_t *)( fd_type_pun( data + off ) );
    /* 8-byte aligned. 32 + 8 = 40. 40 % 8 = 0. */
    ulong stake =
        *(ulong *)( fd_type_pun( data + off + sizeof( fd_stake_pubkey_t ) ) );
    fd_stake_node_t * staked_node = fd_stake_node_insert( staked_nodes, *pubkey );
    if ( staked_node == NULL ) staked_node = fd_stake_node_query( staked_nodes, *pubkey, NULL );
    if ( staked_node == NULL ) {
      FD_LOG_HEXDUMP_WARNING( ( "failed to insert pubkey", pubkey, sizeof( fd_stake_pubkey_t ) ) );
      continue;
    }
    staked_node->stake = stake;
    total_stake += stake;
  }
  printf("writing total stake %lu\n", stake->total_stake);
  stake->total_stake = total_stake;

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
