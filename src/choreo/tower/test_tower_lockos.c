#include "fd_tower_lockos.h"
#include "fd_tower_serdes.h"

void
mock_vote_acc( fd_hash_t const * pubkey, ulong stake, ulong vote, uint conf, fd_tower_voters_t * out ) {
  fd_vote_acc_t voter = {
    .kind = FD_VOTE_ACC_V3,
    .v3 = {
      .node_pubkey = *pubkey,
      .votes_cnt = 1,
      .votes = {
        { .slot = vote, .conf = conf },
      },
    }
  };

  memcpy( out->data, &voter, sizeof(fd_vote_acc_t) );
  out->stake = stake;
  out->vote_acc = *pubkey;
}

void
test_lockos( fd_wksp_t * wksp ) {
  ulong slot_max    = 64;
  ulong voter_max   = 16;

  void *              lockos_mem = fd_wksp_alloc_laddr( wksp, fd_tower_lockos_align(), fd_tower_lockos_footprint( slot_max, voter_max ), 1UL );
  fd_tower_lockos_t * lockos     = fd_tower_lockos_join( fd_tower_lockos_new( lockos_mem, slot_max, voter_max, 0UL ) );

  fd_tower_voters_t acct;
  ulong fork_slot = 1;
  ulong end_intervals[31];
  for( ulong i = 1; i < 32; i++ ) {
    ulong vote_slot = 50 - (i - 1);
    mock_vote_acc( &(fd_hash_t){.ul = {1}}, 100, vote_slot, (uint)i, &acct );
    fd_tower_lockos_insert( lockos, fork_slot, &acct.vote_acc, &acct );
    end_intervals[i - 1] = vote_slot + (1UL << (uint)i);
  }

  for( ulong i = 0; i < 31; i++ ) {
    ulong key = fd_tower_lockos_interval_key( fork_slot, end_intervals[i] );
    FD_TEST( fd_tower_lockos_interval_map_ele_query( lockos->interval_map, &key, NULL, lockos->interval_pool ) );
  }
  FD_TEST( fd_tower_lockos_slot_map_ele_query( lockos->slot_map, &fork_slot, NULL, lockos->slot_pool ) );


  ulong num_keys = 0;
  for( fd_tower_lockos_slot_t const * slot = fd_tower_lockos_slot_map_ele_query_const( lockos->slot_map, &fork_slot, NULL, lockos->slot_pool );
                                      slot;
                                      slot = fd_tower_lockos_slot_map_ele_next_const ( slot, NULL, lockos->slot_pool ) ) {
    ulong interval_end = slot->interval_end;
    ulong key          = fd_tower_lockos_interval_key( fork_slot, interval_end );
    num_keys++;

    /* Intervals are keyed by the end of the interval. */

    ulong num_pubkeys = 0;
    for( fd_tower_lockos_interval_t const * interval = fd_tower_lockos_interval_map_ele_query_const( lockos->interval_map, &key, NULL, lockos->interval_pool );
                                            interval;
                                            interval = fd_tower_lockos_interval_map_ele_next_const( interval, NULL, lockos->interval_pool ) ) {
      FD_TEST( memcmp( &interval->addr, &acct.vote_acc, sizeof(fd_hash_t) ) == 0 );
      num_pubkeys++;
    }
    FD_TEST( num_pubkeys == 1 );
  }
  FD_TEST( num_keys == 31 );


  fd_tower_lockos_remove( lockos, fork_slot );
  for( ulong i = 0; i < 31; i++ ) {
    ulong key = fd_tower_lockos_interval_key( fork_slot, end_intervals[i] );
    FD_TEST( !fd_tower_lockos_interval_map_ele_query( lockos->interval_map, &key, NULL, lockos->interval_pool ) );
  }
  FD_TEST( !fd_tower_lockos_slot_map_ele_query( lockos->slot_map, &fork_slot, NULL, lockos->slot_pool ) );
}

int
main( int argc, char ** argv ) {
  fd_boot( &argc, &argv );

  ulong       page_cnt = 1;
  char *      page_sz  = "gigantic";
  ulong       numa_idx = fd_shmem_numa_idx( 0 );
  fd_wksp_t * wksp     = fd_wksp_new_anonymous( fd_cstr_to_shmem_page_sz( page_sz ), page_cnt, fd_shmem_cpu_idx( numa_idx ), "wksp", 0UL );
  FD_TEST( wksp );

  test_lockos( wksp );

  fd_halt();
  return 0;
}
