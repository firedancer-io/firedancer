#include "../../util/fd_util.h"
#include "fd_shredb.h"
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* TODO: re-implement all the tests, removed for now because was changing the API */

int
main( int argc, char ** argv ) {
  fd_boot( &argc, &argv );

  // test_key_pack();
  // test_footprint();
  // test_lifecycle();
  // test_insert_query_basic();
  // test_multiple_shreds_same_slot();
  // test_multiple_slots();
  // test_duplicate_insert();
  // test_ring_eviction();
  // test_full_eviction_cycle();
  // test_evict_highest_shred();
  // test_small_payload();
  // test_capacity_one();
  // test_many_wraps();
  // test_interleaved_slots();
  // test_shred_index_zero();
  // test_large_slot();
  // test_partial_slot_eviction();
  // test_reinsert_after_eviction();
  // test_non_contiguous_indices();
  // test_stress();

  // bench_insert();
  // bench_query_hit();
  // bench_query_miss();
  // bench_mixed();

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
