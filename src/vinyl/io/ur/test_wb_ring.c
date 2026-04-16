#include "wb_ring.h"

/* LLM-generated tests */

static void
test_wb_ring_basic( void ) {
  wb_ring_t wb[1];

  /* Buffer capacity = 16, start at seq 0 */
  FD_TEST( wb_ring_init( wb, 0UL, 16UL ) );
  FD_TEST( wb_ring_seq0( wb )==0UL );
  FD_TEST( wb_ring_seq1( wb )==0UL );

  /* Allocate 10 bytes: part1 = [off 0, sz 10) */
  wb_ring_alloc( wb, 10UL );
  FD_TEST( wb_ring_seq0( wb )== 0UL );
  FD_TEST( wb_ring_seq1( wb )==10UL );
  FD_TEST( wb->sz1==10UL );

  /* Allocate 4 bytes: part1 extends to [off 0, sz 14) */
  wb_ring_alloc( wb, 4UL );
  FD_TEST( wb_ring_seq1( wb )==14UL );
  FD_TEST( wb->sz1==14UL );
}

/* This test triggers the exact bug path: wrap-around where r_sz > sz0
   causes part0 to be destroyed.  Before the fix, sz1 was not updated
   and wb_ring_seq1 would return the wrong value. */
static void
test_wb_ring_wrap_destroy_part0( void ) {
  wb_ring_t wb[1];

  /* Buffer capacity = 16, start at seq 100 */
  FD_TEST( wb_ring_init( wb, 100UL, 16UL ) );

  /* Fill part1 to near the end of the buffer.
     Alloc 14 bytes: part1 = [off 0, sz 14), seq range [100,114) */
  wb_ring_alloc( wb, 14UL );
  FD_TEST( wb_ring_seq1( wb )==114UL );
  FD_TEST( wb->off1==0UL );
  FD_TEST( wb->sz1 ==14UL );

  /* Now allocate 8 bytes.  14+8=22 > 16 (max), so this triggers the
     wrap-around path.  After moving part1 to part0 and left-extending:
       part0 = [off 0, sz 14), part1 empty at off 0
     Then r_sz=8 > sz0=14 is false, so we take the else (partial overlap).
     Actually let's set up a scenario where r_sz > sz0. */

  /* Reset and use a tighter scenario */
  FD_TEST( wb_ring_init( wb, 100UL, 16UL ) );

  /* Alloc 13 bytes: part1 = [off 0, sz 13), seq [100,113) */
  wb_ring_alloc( wb, 13UL );
  FD_TEST( wb_ring_seq1( wb )==113UL );

  /* Alloc 2 bytes: 13+2=15 <= 16, extends part1 to sz 15 */
  wb_ring_alloc( wb, 2UL );
  FD_TEST( wb_ring_seq1( wb )==115UL );
  FD_TEST( wb->sz1==15UL );
  FD_TEST( wb->off1==0UL );

  /* Now alloc 10 bytes.  15+10=25 > 16, triggers wrap-around.
     After wrap-around setup:
       part0 gets old part1: [off 0, sz 15), seq range adjusted
       part1 reset to [off 0, sz 0)
     Left-extend part0 to offset 0 (already at 0, no change):
       part0 = [off 0, sz 15)
     Now r_sz=10 < sz0=15, so this takes the else branch.
     We need r_sz > sz0.  Let's try with a larger allocation. */

  /* Alloc 16 bytes (the full buffer).  15+16=31 > 16, triggers wrap.
     After wrap: part0 = [off 0, sz 15).
     r_sz=16 > sz0=15: takes the TRUE branch (destroy part0).
     This is the buggy path. */
  wb_ring_alloc( wb, 16UL );

  /* Before the fix: sz1 would be 0, wb_ring_seq1 would return 115
     instead of 131.  After fix: sz1=16, wb_ring_seq1 returns 131. */
  FD_TEST( wb->sz1==16UL );
  FD_TEST( wb_ring_seq1( wb )==131UL );
  FD_TEST( wb->sz0==0UL );
}

/* Test the wrap-around partial overlap path (the else branch) for
   completeness. */
static void
test_wb_ring_wrap_partial_overlap( void ) {
  wb_ring_t wb[1];

  FD_TEST( wb_ring_init( wb, 200UL, 32UL ) );

  /* Fill part1 to near end: alloc 30 bytes */
  wb_ring_alloc( wb, 30UL );
  FD_TEST( wb_ring_seq1( wb )==230UL );
  FD_TEST( wb->sz1==30UL );

  /* Alloc 8 bytes: 30+8=38 > 32, triggers wrap.
     After wrap: part0 = [off 0, sz 30).
     r_sz=8 < sz0=30: else branch (partial overlap).
     sz1 should become 8. */
  wb_ring_alloc( wb, 8UL );
  FD_TEST( wb->sz1==8UL );
  FD_TEST( wb_ring_seq1( wb )==238UL );
  FD_TEST( wb->sz0==22UL );
  FD_TEST( wb->off0==8UL );
}

/* Test that wb_ring_seq_to_off works after the wrap+destroy path. */
static void
test_wb_ring_seq_to_off_after_wrap_destroy( void ) {
  wb_ring_t wb[1];

  FD_TEST( wb_ring_init( wb, 0UL, 16UL ) );

  /* Fill to near end */
  wb_ring_alloc( wb, 15UL );

  /* Trigger wrap + destroy: alloc 16 (full buffer) */
  wb_ring_alloc( wb, 16UL );

  /* After wrap+destroy, only part1 exists at [off 0, sz 16).
     seq1 = 15, sz1 = 16, so seq range is [15, 31).
     Verify seq_to_off for the start of part1. */
  ulong seq_start = wb->seq1;
  FD_TEST( wb_ring_seq_to_off( wb, seq_start )==wb->off1 );
  FD_TEST( wb_ring_seq_to_off( wb, seq_start + 8UL )==wb->off1 + 8UL );
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  test_wb_ring_basic();
  test_wb_ring_wrap_destroy_part0();
  test_wb_ring_wrap_partial_overlap();
  test_wb_ring_seq_to_off_after_wrap_destroy();

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
