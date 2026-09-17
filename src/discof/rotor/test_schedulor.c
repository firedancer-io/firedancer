#include "fd_schedulor.h"

#define SLOTV_MAX (64UL)
#define Q FD_SCHEDULOR_QUANTUM_NS /* all test times are whole quanta so they survive a quantum change */

#define PARENT  FD_SCHEDULOR_PARENT_TIMEOUT_NS
#define REQUEST FD_SCHEDULOR_REQUEST_TIMEOUT_NS

static uchar mem[ 1UL<<20 ] __attribute__((aligned(128UL)));

static fd_hash_t const ZERO = {0};

static fd_hash_t
bid( ulong n ) {
  fd_hash_t h = {0};
  memcpy( h.uc, &n, sizeof(ulong) );
  return h;
}

static fd_schedulor_t *
setup( void ) {
  ulong footprint = fd_schedulor_footprint( SLOTV_MAX );
  FD_TEST( footprint && footprint<=sizeof(mem) );
  fd_schedulor_t * s = fd_schedulor_join( fd_schedulor_new( mem, SLOTV_MAX, 42UL ) );
  FD_TEST( s );
  FD_TEST( !fd_schedulor_verify( s ) );
  FD_TEST( fd_schedulor_queued_cnt( s )==0UL );
  FD_TEST( fd_schedulor_next_timeout( s )==LONG_MAX );
  ulong slot; fd_hash_t block_id;
  FD_TEST( !fd_schedulor_block_pop( s, LONG_MAX, &slot, &block_id ) );
  return s;
}

static void
teardown( fd_schedulor_t * s ) {
  FD_TEST( !fd_schedulor_verify( s ) );
  FD_TEST( fd_schedulor_delete( fd_schedulor_leave( s ) )==mem );
}

/* Wrappers that verify after every mutation */

static void
insert( fd_schedulor_t * s, ulong slot, fd_hash_t const * block_id, long timeout ) {
  fd_schedulor_block_insert( s, slot, block_id, timeout );
  FD_TEST( fd_schedulor_block_query( s, slot, block_id ) );
  FD_TEST( !fd_schedulor_verify( s ) );
}

static void
remove_( fd_schedulor_t * s, ulong slot, fd_hash_t const * block_id ) {
  fd_schedulor_block_remove( s, slot, block_id );
  FD_TEST( !fd_schedulor_block_query( s, slot, block_id ) );
  FD_TEST( !fd_schedulor_verify( s ) );
}

/* pop_expect pops at now and asserts {slot, block_id} comes out, or
   nothing if slot is ULONG_MAX. */

static void
pop_expect( fd_schedulor_t * s, long now, ulong slot, fd_hash_t const * block_id ) {
  ulong     out_slot     = 0xdeadUL;
  fd_hash_t out_block_id = bid( 0xdeadUL );
  int rc = fd_schedulor_block_pop( s, now, &out_slot, &out_block_id );
  if( slot==ULONG_MAX ) {
    FD_TEST( !rc );
    FD_TEST( out_slot==0xdeadUL ); /* outputs untouched */
    return;
  }
  FD_TEST( rc );
  FD_TEST( out_slot==slot );
  FD_TEST( fd_hash_eq( &out_block_id, block_id ) );
  FD_TEST( !fd_schedulor_block_query( s, slot, block_id ) ); /* popped is forgotten */
  FD_TEST( !fd_schedulor_verify( s ) );
}

static void
test_footprint( void ) {
  FD_TEST( !fd_schedulor_footprint( 0UL ) );
  FD_TEST(  fd_schedulor_footprint( 1UL ) );
  FD_LOG_NOTICE(( "pass: footprint" ));
}

/* insert queues a check; pop when due forgets it.  The schedulor holds
   nothing about a popped block until the caller inserts it again with
   whatever timeout its policy picks. */

static void
test_lifecycle( void ) {
  fd_schedulor_t * s = setup();
  fd_hash_t b10 = bid( 10UL );

  FD_TEST( !fd_schedulor_block_query( s, 10UL, &b10 ) );
  insert( s, 10UL, &b10, 5*Q );
  FD_TEST( fd_schedulor_queued_cnt( s )==1UL && fd_schedulor_next_timeout( s )==5*Q );

  pop_expect( s, 4*Q, ULONG_MAX, NULL );                 /* not due */
  pop_expect( s, 5*Q, 10UL, &b10 );                      /* due, popped and forgotten */
  FD_TEST( fd_schedulor_queued_cnt( s )==0UL && fd_schedulor_next_timeout( s )==LONG_MAX );
  pop_expect( s, 100*Q, ULONG_MAX, NULL );

  /* caller asked for a parent: short sleep */
  insert( s, 10UL, &b10, 6*Q + PARENT );
  FD_TEST( fd_schedulor_next_timeout( s )==6*Q + PARENT );
  pop_expect( s, 6*Q + PARENT - 1L, ULONG_MAX, NULL );
  pop_expect( s, 6*Q + PARENT,      10UL, &b10 );

  /* caller did a fill pass: long sleep */
  long t = 7*Q + PARENT;
  insert( s, 10UL, &b10, t + REQUEST );
  FD_TEST( fd_schedulor_next_timeout( s )==t + REQUEST );
  pop_expect( s, t + REQUEST - 1L, ULONG_MAX, NULL );
  pop_expect( s, t + REQUEST,      10UL, &b10 );

  /* caller had nothing to do: it simply does not insert */
  FD_TEST( fd_schedulor_queued_cnt( s )==0UL );
  pop_expect( s, LONG_MAX, ULONG_MAX, NULL );

  /* later new work brings it back */
  insert( s, 10UL, &b10, 500*Q );
  pop_expect( s, 500*Q, 10UL, &b10 );

  /* remove of a block that is not queued is a no-op */
  remove_( s, 10UL, &b10 );
  FD_TEST( fd_schedulor_queued_cnt( s )==0UL );

  teardown( s );
  FD_LOG_NOTICE(( "pass: block lifecycle" ));
}

/* Blocks pop in timeout order; ties in one quantum pop lowest slot
   first; insert on a queued block is a no-op either way. */

static void
test_order( void ) {
  fd_schedulor_t * s = setup();
  fd_hash_t b10 = bid( 10UL ), b11 = bid( 11UL ), b12 = bid( 12UL );

  insert( s, 12UL, &b12, 5*Q        );
  insert( s, 10UL, &b10, 5*Q + 300L ); /* same quantum, lower slot */
  insert( s, 11UL, &b11, 2*Q + 999L );
  FD_TEST( fd_schedulor_queued_cnt( s )==3UL && fd_schedulor_next_timeout( s )==2*Q );

  pop_expect( s, 2*Q, 11UL, &b11 );
  pop_expect( s, 2*Q, ULONG_MAX, NULL );
  pop_expect( s, 5*Q, 10UL, &b10 );
  pop_expect( s, 5*Q, 12UL, &b12 );
  pop_expect( s, 5*Q, ULONG_MAX, NULL );

  /* park all three, then try to move one */
  insert( s, 11UL, &b11, 5*Q + REQUEST );
  insert( s, 10UL, &b10, 5*Q + REQUEST );
  insert( s, 12UL, &b12, 5*Q + REQUEST );
  pop_expect( s, 6*Q, ULONG_MAX, NULL );

  insert( s, 12UL, &b12, 6*Q ); /* earlier: ignored, a queued check keeps its time */
  FD_TEST( fd_schedulor_next_timeout( s )==5*Q + REQUEST );
  insert( s, 12UL, &b12, 9*Q + REQUEST ); /* later: ignored too */
  FD_TEST( fd_schedulor_next_timeout( s )==5*Q + REQUEST );
  FD_TEST( fd_schedulor_queued_cnt( s )==3UL );
  pop_expect( s, 6*Q, ULONG_MAX, NULL );

  pop_expect( s, 5*Q + REQUEST - 1L, ULONG_MAX, NULL );
  pop_expect( s, 5*Q + REQUEST,      10UL, &b10 );
  pop_expect( s, 5*Q + REQUEST,      11UL, &b11 );
  pop_expect( s, 5*Q + REQUEST,      12UL, &b12 );
  FD_TEST( fd_schedulor_queued_cnt( s )==0UL );

  teardown( s );
  FD_LOG_NOTICE(( "pass: timeout order, slot tie-break, insert on a queued block is a no-op" ));
}

/* The schedulor does not know what the tile is working on.  An insert
   for a popped block queues it again, and a later insert for the same
   block is a no-op until that check pops. */

static void
test_while_held( void ) {
  fd_schedulor_t * s = setup();
  fd_hash_t b30 = bid( 30UL );

  insert( s, 30UL, &b30, 0L );
  pop_expect( s, 0L, 30UL, &b30 );                           /* tile now works on it */
  FD_TEST( fd_schedulor_queued_cnt( s )==0UL );

  insert( s, 30UL, &b30, 1*Q );                              /* new work while the tile holds it */
  FD_TEST( fd_schedulor_queued_cnt( s )==1UL && fd_schedulor_next_timeout( s )==1*Q );

  insert( s, 30UL, &b30, 2*Q + REQUEST );                    /* tile finishes, asks for a long sleep: already queued, no-op */
  FD_TEST( fd_schedulor_next_timeout( s )==1*Q );
  pop_expect( s, 2*Q, 30UL, &b30 );                          /* the earlier check pops */

  insert( s, 30UL, &b30, 4*Q + REQUEST );
  FD_TEST( fd_schedulor_next_timeout( s )==4*Q + REQUEST );

  teardown( s );
  FD_LOG_NOTICE(( "pass: inserts for a block the tile holds" ));
}

/* Blocks are keyed by {slot, block_id}: the turbine version {slot, 0}
   and a verified version of the same slot are distinct, and the rename
   at finalization (remove {slot,0}, insert {slot,id}) moves the check
   to the new key.  A stale insert for a gone block just queues a check
   that pops normally; the tile finds nothing behind it and drops it. */

static void
test_versions( void ) {
  fd_schedulor_t * s = setup();
  fd_hash_t bA = bid( 0xAAUL ), bB = bid( 0xBBUL );

  insert( s, 20UL, &ZERO, 0L ); /* turbine */
  insert( s, 20UL, &bA,   0L ); /* verified */
  FD_TEST( fd_schedulor_queued_cnt( s )==2UL );
  FD_TEST( fd_schedulor_block_query( s, 20UL, &ZERO ) && fd_schedulor_block_query( s, 20UL, &bA ) );
  remove_( s, 20UL, &bA );      /* drops only the verified one */
  FD_TEST( fd_schedulor_queued_cnt( s )==1UL );
  FD_TEST( fd_schedulor_block_query( s, 20UL, &ZERO ) );
  pop_expect( s, 0L, 20UL, &ZERO );

  /* rename at finalization */
  insert ( s, 20UL, &ZERO, 1*Q );
  remove_( s, 20UL, &ZERO );
  insert ( s, 20UL, &bB, 2*Q );
  FD_TEST( fd_schedulor_queued_cnt( s )==1UL );
  pop_expect( s, 2*Q, 20UL, &bB );

  /* a stale insert for the old key is harmless */
  insert( s, 20UL, &ZERO, 3*Q + REQUEST );
  FD_TEST( fd_schedulor_queued_cnt( s )==1UL );
  pop_expect( s, 3*Q + REQUEST, 20UL, &ZERO );
  FD_TEST( fd_schedulor_queued_cnt( s )==0UL );

  /* remove and query on an unknown key */
  remove_( s, 21UL, &bA );
  FD_TEST( !fd_schedulor_block_query( s, 21UL, &bA ) );
  FD_TEST( fd_schedulor_queued_cnt( s )==0UL );

  teardown( s );
  FD_LOG_NOTICE(( "pass: blocks keyed by {slot, block_id}, rename, stale insert" ));
}

/* Every slotv has a check at once and they drain in slot order. */

static void
test_full( void ) {
  fd_schedulor_t * s = setup();

  for( ulong i=0UL; i<SLOTV_MAX; i++ ) { fd_hash_t b = bid( i+1UL ); insert( s, 1000UL-i, &b, 0L ); } /* reverse slot order, non-zero ids */
  FD_TEST( fd_schedulor_queued_cnt( s )==SLOTV_MAX );

  ulong prev_slot = 0UL;
  for( ulong i=0UL; i<SLOTV_MAX; i++ ) {
    ulong slot; fd_hash_t block_id;
    FD_TEST( fd_schedulor_block_pop( s, 0L, &slot, &block_id ) );
    FD_TEST( slot>prev_slot );
    FD_TEST( !fd_hash_eq( &block_id, &ZERO ) );
    prev_slot = slot;
    insert( s, slot, &block_id, REQUEST ); /* re-park each */
  }
  pop_expect( s, 0L, ULONG_MAX, NULL );
  FD_TEST( fd_schedulor_queued_cnt( s )==SLOTV_MAX );

  for( ulong i=0UL; i<SLOTV_MAX; i++ ) { fd_hash_t b = bid( i+1UL ); remove_( s, 1000UL-i, &b ); }
  FD_TEST( fd_schedulor_queued_cnt( s )==0UL );

  teardown( s );
  FD_LOG_NOTICE(( "pass: full block set drains in slot order" ));
}

/* publish drops every check at or below the new root, whatever its
   timeout, and leaves the rest untouched. */

static void
test_publish( void ) {
  fd_schedulor_t * s = setup();
  fd_hash_t b[ 6 ];
  for( ulong i=0UL; i<6UL; i++ ) { b[ i ] = bid( i+1UL ); insert( s, 10UL+i, &b[ i ], (long)( 5UL-i )*Q ); } /* later slots due sooner */
  insert( s, 12UL, &ZERO, 0L ); /* a second version of slot 12 */
  FD_TEST( fd_schedulor_queued_cnt( s )==7UL );

  fd_schedulor_publish( s, 9UL ); /* nothing at or below 9 */
  FD_TEST( !fd_schedulor_verify( s ) && fd_schedulor_queued_cnt( s )==7UL );

  fd_schedulor_publish( s, 12UL );
  FD_TEST( !fd_schedulor_verify( s ) && fd_schedulor_queued_cnt( s )==3UL );
  for( ulong i=0UL; i<3UL; i++ ) FD_TEST( !fd_schedulor_block_query( s, 10UL+i, &b[ i ] ) );
  FD_TEST( !fd_schedulor_block_query( s, 12UL, &ZERO ) );
  for( ulong i=3UL; i<6UL; i++ ) FD_TEST(  fd_schedulor_block_query( s, 10UL+i, &b[ i ] ) );
  FD_TEST( fd_schedulor_next_timeout( s )==0L ); /* slot 15 was due first and still is */
  pop_expect( s, 0L, 15UL, &b[ 5 ] );
  pop_expect( s, 1*Q, 14UL, &b[ 4 ] );
  pop_expect( s, 2*Q, 13UL, &b[ 3 ] );
  FD_TEST( fd_schedulor_queued_cnt( s )==0UL );

  fd_schedulor_publish( s, 100UL ); /* empty: no-op */
  FD_TEST( !fd_schedulor_verify( s ) );

  teardown( s );
  FD_LOG_NOTICE(( "pass: publish drops checks at or below the root" ));
}

int
main( int argc, char ** argv ) {
  fd_boot( &argc, &argv );

  test_footprint ();
  test_lifecycle ();
  test_order     ();
  test_while_held();
  test_versions  ();
  test_full      ();
  test_publish   ();

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
