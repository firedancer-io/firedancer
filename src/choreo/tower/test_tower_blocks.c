#include "fd_tower_blocks.h"
#include "fd_tower_voters.h"
#include "fd_tower_serdes.h"

void
make_vote_account( fd_hash_t const * pubkey, ulong stake, ulong vote, uint conf, fd_tower_voters_t * out ) {
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
  out->addr = *pubkey;
}

void
test_forks_lockouts( fd_wksp_t * wksp ) {
  ulong slot_max    = 64;
  ulong voter_max   = 16;

  void * forks_mem = fd_wksp_alloc_laddr( wksp, fd_tower_blocks_align(), fd_tower_blocks_footprint( slot_max, voter_max ), 1UL );
  fd_tower_blocks_t * forks = fd_tower_blocks_join( fd_tower_blocks_new( forks_mem, slot_max, voter_max ) );

  fd_tower_blocks_replayed( forks, fd_tower_blocks_insert( forks, 0, ULONG_MAX ), 0, &(fd_hash_t){.ul = {0}} );
  fd_tower_blocks_replayed( forks, fd_tower_blocks_insert( forks, 1, 0 ), 1, &(fd_hash_t){.ul = {1}} );
  fd_tower_blocks_replayed( forks, fd_tower_blocks_insert( forks, 2, 1 ), 2, &(fd_hash_t){.ul = {2}} );

  fd_tower_voters_t acct;
  ulong fork_slot = 1;
  ulong end_intervals[31];
  for( ulong i = 1; i < 32; i++ ) {
    ulong vote_slot = 50 - (i - 1);
    make_vote_account( &(fd_hash_t){.ul = {1}}, 100, vote_slot, (uint)i, &acct );
    fd_tower_blocks_lockouts_add( forks, fork_slot, &acct.addr, &acct );
    end_intervals[i - 1] = vote_slot + (1UL << (uint)i);
  }

  for( ulong i = 0; i < 31; i++ ) {
    ulong key = fd_lockout_interval_key( fork_slot, end_intervals[i] );
    FD_TEST( fd_lockout_intervals_map_ele_query( forks->lockout_intervals_map, &key, NULL, forks->lockout_intervals_pool ) );
  }
  FD_TEST( fd_lockout_slots_map_ele_query( forks->lockout_slots_map, &fork_slot, NULL, forks->lockout_slots_pool ) );


  ulong num_keys = 0;
  for( fd_lockout_slots_t const * slot = fd_lockout_slots_map_ele_query_const( forks->lockout_slots_map, &fork_slot, NULL, forks->lockout_slots_pool );
                                  slot;
                                  slot = fd_lockout_slots_map_ele_next_const ( slot, NULL, forks->lockout_slots_pool ) ) {
    ulong interval_end = slot->interval_end;
    ulong key = fd_lockout_interval_key( fork_slot, interval_end );
    num_keys++;

    /* Intervals are keyed by the end of the interval. */

    ulong num_pubkeys = 0;
    for( fd_lockout_intervals_t const * interval = fd_lockout_intervals_map_ele_query_const( forks->lockout_intervals_map, &key, NULL, forks->lockout_intervals_pool );
                                        interval;
                                        interval = fd_lockout_intervals_map_ele_next_const( interval, NULL, forks->lockout_intervals_pool ) ) {
      FD_TEST( memcmp( &interval->addr, &acct.addr, sizeof(fd_hash_t) ) == 0 );
      num_pubkeys++;
    }
    FD_TEST( num_pubkeys == 1 );
  }
  FD_TEST( num_keys == 31 );


  fd_tower_blocks_lockouts_clear( forks, fork_slot );
  for( ulong i = 0; i < 31; i++ ) {
    ulong key = fd_lockout_interval_key( fork_slot, end_intervals[i] );
    FD_TEST( !fd_lockout_intervals_map_ele_query( forks->lockout_intervals_map, &key, NULL, forks->lockout_intervals_pool ) );
  }
  FD_TEST( !fd_lockout_slots_map_ele_query( forks->lockout_slots_map, &fork_slot, NULL, forks->lockout_slots_pool ) );
}

int
main( int argc, char ** argv ) {
  fd_boot( &argc, &argv );

  ulong  page_cnt = 1;
  char * page_sz = "gigantic";
  ulong  numa_idx = fd_shmem_numa_idx( 0 );
  fd_wksp_t * wksp = fd_wksp_new_anonymous( fd_cstr_to_shmem_page_sz( page_sz ), page_cnt, fd_shmem_cpu_idx( numa_idx ), "wksp", 0UL );
  FD_TEST( wksp );

  test_forks_lockouts( wksp );

  fd_halt();
  return 0;
}
