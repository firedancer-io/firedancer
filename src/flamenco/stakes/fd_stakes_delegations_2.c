#include "fd_stakes_delegations_2.h"

#define POOL_NAME  fd_stake_delegation_pool
#define POOL_T     fd_stake_delegation_t
#define POOL_NEXT  next_
#define POOL_IDX_T uint
#include "../../util/tmpl/fd_pool.c"

#define MAP_NAME               fd_stake_delegation_map
#define MAP_KEY_T              fd_pubkey_t
#define MAP_ELE_T              fd_stake_delegation_t
#define MAP_KEY                stake_account
#define MAP_KEY_EQ(k0,k1)      (fd_pubkey_eq( k0, k1 ))
#define MAP_KEY_HASH(key,seed) (fd_funk_rec_key_hash1( key->uc, seed ))
#define MAP_NEXT               next_
#define MAP_IDX_T              uint
#include "../../util/tmpl/fd_map_chain.c"

#define DLIST_NAME             fork_dlist
#define DLIST_ELE_T            fd_stake_delegation_t
#define DLIST_PREV             prev
#define DLIST_NEXT             next
#include "../../util/tmpl/fd_dlist.c"

ulong
fd_stake_delegations_delta_align( void ) {
  return 128UL;
}

ulong
fd_stake_delegations_delta_footprint( ulong max_stake_accounts,
                                      ulong max_live_slots ) {
  ulong map_chain_cnt = fd_stake_delegation_map_chain_cnt_est( max_stake_accounts );

  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, fd_stake_delegations_delta_align(), sizeof(fd_stake_delegations_delta_t) );
  l = FD_LAYOUT_APPEND( l, fd_stake_delegation_pool_align(),   fd_stake_delegation_pool_footprint( max_stake_accounts ) );
  l = FD_LAYOUT_APPEND( l, fd_stake_delegation_map_align(),    fd_stake_delegation_map_footprint( map_chain_cnt ) );
  for( ushort i=0; i<max_live_slots; i++ ) {
    l = FD_LAYOUT_APPEND( l, fork_dlist_align(), fork_dlist_footprint() );
  }

  return FD_LAYOUT_FINI( l, fd_stake_delegations_delta_align() );
}

void *
fd_stake_delegations_delta_new( void * mem,
                                ulong  seed,
                                ulong  max_stake_accounts,
                                ulong  max_live_slots,
                                int    leave_tombstones ) {
  return mem;
}

// fd_stake_delegations_delta_t *
// fd_stake_delegations_delta_join( void * mem ) {
//   return mem;
// }

// ushort
// fd_stake_delegations_delta_new_fork( fd_stake_delegations_delta_t * stake_delegations ) {
//   return 0;
// }
