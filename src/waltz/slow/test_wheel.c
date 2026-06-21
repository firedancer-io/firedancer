#include "fd_wheel.h"
#include "../../util/fd_util.h"
#include "../../util/tmpl/fd_unit_test.c"

FD_STATIC_ASSERT( FD_WHEEL_SHIFT( 0 )==11, wheel );
FD_STATIC_ASSERT( FD_WHEEL_SHIFT( 1 )==15, wheel );
FD_STATIC_ASSERT( FD_WHEEL_SHIFT( 2 )==19, wheel );
FD_STATIC_ASSERT( FD_WHEEL_SHIFT( 3 )==23, wheel );

FD_STATIC_ASSERT( FD_WHEEL_BUCKET( 0 )==   2048L, wheel );
FD_STATIC_ASSERT( FD_WHEEL_BUCKET( 1 )==  32768L, wheel );
FD_STATIC_ASSERT( FD_WHEEL_BUCKET( 2 )== 524288L, wheel );
FD_STATIC_ASSERT( FD_WHEEL_BUCKET( 3 )==8388608L, wheel );

FD_STATIC_ASSERT( FD_WHEEL_RANGE( 0 )==   1048576L, wheel );
FD_STATIC_ASSERT( FD_WHEEL_RANGE( 1 )==  16777216L, wheel );
FD_STATIC_ASSERT( FD_WHEEL_RANGE( 2 )== 268435456L, wheel );
FD_STATIC_ASSERT( FD_WHEEL_RANGE( 3 )==4294967296L, wheel );

#define TEST_POOL_CNT 64U

static fd_wheel_t       wheel[1];
static fd_wheel_timer_t pool[ TEST_POOL_CNT ];

static void
insert_timer( uint idx,
              long deadline ) {
  FD_TEST( idx<TEST_POOL_CNT );
  pool[ idx ].prev     = 0x11111111U;
  pool[ idx ].next     = 0x22222222U;
  pool[ idx ].deadline = deadline;
  pool[ idx ].dcid     = 0xC0FFEE0000000000UL | (ulong)idx;
  pool[ idx ].pktnum   = 0x12345UL + (ulong)idx;
  pool[ idx ].level    = 0x3UL;
  pool[ idx ].timer    = idx & 0x3U;
  fd_wheel_insert( wheel, &pool[ idx ] );
}

static void
assert_singleton_bucket( uint idx ) {
  fd_wheel_timer_t const * timer = &pool[ idx ];
  FD_TEST( timer->level<FD_WHEEL_LEVEL_CNT );
  uint slot = FD_WHEEL_SLOT( timer->level, timer->deadline );
  FD_TEST( wheel->map[ timer->level ][ slot ]==idx );
  FD_TEST( timer->prev==UINT_MAX );
  FD_TEST( timer->next==UINT_MAX );
}

static void
new_wheel( long now ) {
  fd_memset( pool, 0, sizeof(pool) );
  FD_TEST( fd_wheel_new( wheel, pool, now )==wheel );
}

static void
assert_empty_map( fd_wheel_t const * w ) {
  for( uint lvl=0U; lvl<FD_WHEEL_LEVEL_CNT; lvl++ ) {
    for( uint slot=0U; slot<FD_WHEEL_BUCKET_CNT; slot++ ) {
      FD_TEST( w->map[ lvl ][ slot ]==UINT_MAX );
    }
  }
}

FD_UNIT_TEST( lifecycle ) {
  long now  = 123456789L;
  long base = (long)fd_ulong_align_dn( (ulong)now, (ulong)FD_WHEEL_BUCKET( 0 ) );
  new_wheel( now );

  FD_TEST( wheel->pool==pool );
  FD_TEST( wheel->base==base );
  FD_TEST( fd_wheel_range()==FD_WHEEL_RANGE( FD_WHEEL_LEVEL_CNT-1 ) );
  assert_empty_map( wheel );

  FD_TEST( !fd_wheel_insert_is_safe( wheel, base-1L ) );
  FD_TEST(  fd_wheel_insert_is_safe( wheel, base ) );
  FD_TEST(  fd_wheel_insert_is_safe( wheel, base+fd_wheel_range()-1L ) );
  FD_TEST( !fd_wheel_insert_is_safe( wheel, base+fd_wheel_range() ) );

  FD_TEST( fd_wheel_delete( wheel )==wheel );
  FD_TEST( wheel->pool==NULL );
  FD_TEST( wheel->base==LONG_MAX );
}

FD_UNIT_TEST( insert_levels ) {
  struct {
    long offset;
    uint level;
  } cases[] = {
    { 0L,                         0U },
    { 1L,                         0U },
    { FD_WHEEL_BUCKET( 0 )-1L,    0U },
    { FD_WHEEL_BUCKET( 0 ),       0U },
    { FD_WHEEL_RANGE ( 0 )-1L,    0U },
    { FD_WHEEL_RANGE ( 0 ),       1U },
    { FD_WHEEL_RANGE ( 1 )-1L,    1U },
    { FD_WHEEL_RANGE ( 1 ),       2U },
    { FD_WHEEL_RANGE ( 2 )-1L,    2U },
    { FD_WHEEL_RANGE ( 2 ),       3U },
    { FD_WHEEL_RANGE ( 3 )-1L,    3U }
  };

  for( ulong i=0UL; i<sizeof(cases)/sizeof(cases[0]); i++ ) {
    new_wheel( 987654321L );
    long base     = wheel->base;
    long deadline = base + cases[ i ].offset;
    uint level    = cases[ i ].level;
    uint slot     = FD_WHEEL_SLOT( level, deadline );

    insert_timer( 0U, deadline );

    FD_TEST( pool[ 0 ].deadline==deadline );
    FD_TEST( pool[ 0 ].level==level );
    FD_TEST( wheel->map[ level ][ slot ]==0U );
    assert_singleton_bucket( 0U );
  }
}

FD_UNIT_TEST( insert_clamps ) {
  new_wheel( 7777777L );
  long base = wheel->base;

  struct {
    uint idx;
    long deadline;
    long clamped;
    uint level;
  } cases[] = {
    { 0U, LONG_MIN,                base,                      0U },
    { 1U, base-1234L,              base,                      0U },
    { 2U, base+fd_wheel_range(),   base+fd_wheel_range()-1L,  FD_WHEEL_LEVEL_CNT-1U },
    { 3U, LONG_MAX,                base+fd_wheel_range()-1L,  FD_WHEEL_LEVEL_CNT-1U }
  };

  for( ulong i=0UL; i<sizeof(cases)/sizeof(cases[0]); i++ ) {
    new_wheel( 7777777L );
    insert_timer( cases[ i ].idx, cases[ i ].deadline );
    FD_TEST( pool[ cases[ i ].idx ].deadline==cases[ i ].clamped );
    FD_TEST( pool[ cases[ i ].idx ].level==cases[ i ].level );
    assert_singleton_bucket( cases[ i ].idx );
  }
}

FD_UNIT_TEST( insert_lifo ) {
  new_wheel( 0L );
  long deadline = 1234L;
  uint level    = 0U;
  uint slot     = FD_WHEEL_SLOT( level, deadline );

  insert_timer( 0U, deadline );
  insert_timer( 1U, deadline );
  insert_timer( 2U, deadline );

  FD_TEST( wheel->map[ level ][ slot ]==2U );
  FD_TEST( pool[ 2 ].prev==UINT_MAX );
  FD_TEST( pool[ 2 ].next==1U );
  FD_TEST( pool[ 1 ].prev==2U );
  FD_TEST( pool[ 1 ].next==0U );
  FD_TEST( pool[ 0 ].prev==1U );
  FD_TEST( pool[ 0 ].next==UINT_MAX );
}

FD_UNIT_TEST( remove_links ) {
  new_wheel( 0L );
  long deadline = 1234L;
  uint level    = 0U;
  uint slot     = FD_WHEEL_SLOT( level, deadline );

  insert_timer( 0U, deadline );
  insert_timer( 1U, deadline );
  insert_timer( 2U, deadline );

  FD_TEST( fd_wheel_remove( wheel, &pool[ 1 ] )==&pool[ 1 ] );
  FD_TEST( wheel->map[ level ][ slot ]==2U );
  FD_TEST( pool[ 2 ].prev==UINT_MAX );
  FD_TEST( pool[ 2 ].next==0U );
  FD_TEST( pool[ 0 ].prev==2U );
  FD_TEST( pool[ 0 ].next==UINT_MAX );
  FD_TEST( pool[ 1 ].prev==UINT_MAX );
  FD_TEST( pool[ 1 ].next==UINT_MAX );

  FD_TEST( fd_wheel_remove( wheel, &pool[ 2 ] )==&pool[ 2 ] );
  FD_TEST( wheel->map[ level ][ slot ]==0U );
  FD_TEST( pool[ 0 ].prev==UINT_MAX );
  FD_TEST( pool[ 0 ].next==UINT_MAX );
  FD_TEST( pool[ 2 ].prev==UINT_MAX );
  FD_TEST( pool[ 2 ].next==UINT_MAX );

  FD_TEST( fd_wheel_remove( wheel, &pool[ 0 ] )==&pool[ 0 ] );
  FD_TEST( wheel->map[ level ][ slot ]==UINT_MAX );
  FD_TEST( pool[ 0 ].prev==UINT_MAX );
  FD_TEST( pool[ 0 ].next==UINT_MAX );

  insert_timer( 1U, FD_WHEEL_RANGE( 0 ) );
  FD_TEST( pool[ 1 ].level==1U );
  assert_singleton_bucket( 1U );
}

struct callback_log {
  uint cnt;
  uint idx[ TEST_POOL_CNT ];
  long deadline[ TEST_POOL_CNT ];
};

static void
record_callback( void *             ctx,
                 fd_wheel_timer_t * timer ) {
  struct callback_log * log = (struct callback_log *)ctx;
  FD_TEST( log->cnt<TEST_POOL_CNT );
  log->idx     [ log->cnt ] = (uint)( timer - pool );
  log->deadline[ log->cnt ] = timer->deadline;
  log->cnt++;
}

FD_UNIT_TEST( advance_timing ) {
  new_wheel( 0L );
  insert_timer( 0U, 0L );
  insert_timer( 1U, FD_WHEEL_BUCKET( 0 ) );
  insert_timer( 2U, FD_WHEEL_RANGE( 0 )+123L );

  struct callback_log log[1] = {{0}};

  fd_wheel_advance( wheel, FD_WHEEL_BUCKET( 0 )-1L, record_callback, log );
  FD_TEST( log->cnt==0U );
  FD_TEST( wheel->base==0L );

  fd_wheel_advance( wheel, FD_WHEEL_BUCKET( 0 ), record_callback, log );
  FD_TEST( wheel->base==FD_WHEEL_BUCKET( 0 ) );
  FD_TEST( log->cnt==1U );
  FD_TEST( log->idx[ 0 ]==0U );

  fd_wheel_advance( wheel, 2L*FD_WHEEL_BUCKET( 0 )-1L, record_callback, log );
  FD_TEST( log->cnt==1U );

  fd_wheel_advance( wheel, 2L*FD_WHEEL_BUCKET( 0 ), record_callback, log );
  FD_TEST( log->cnt==2U );
  FD_TEST( log->idx[ 1 ]==1U );

  long lvl1_bucket_end = FD_WHEEL_RANGE( 0 ) + FD_WHEEL_BUCKET( 1 );
  fd_wheel_advance( wheel, lvl1_bucket_end-1L, record_callback, log );
  FD_TEST( log->cnt==2U );

  fd_wheel_advance( wheel, lvl1_bucket_end, record_callback, log );
  FD_TEST( log->cnt==3U );
  FD_TEST( log->idx[ 2 ]==2U );
}

FD_UNIT_TEST( advance_buckets ) {
  new_wheel( 0L );
  insert_timer( 0U, 42L );
  insert_timer( 1U, 42L );
  insert_timer( 2U, FD_WHEEL_BUCKET( 0 ) );

  uint level0 = 0U;
  uint slot0  = FD_WHEEL_SLOT( level0, 42L );
  uint slot1  = FD_WHEEL_SLOT( level0, FD_WHEEL_BUCKET( 0 ) );
  FD_TEST( wheel->map[ level0 ][ slot0 ]==1U );
  FD_TEST( wheel->map[ level0 ][ slot1 ]==2U );

  struct callback_log log[1] = {{0}};
  fd_wheel_advance( wheel, FD_WHEEL_BUCKET( 0 ), record_callback, log );

  FD_TEST( log->cnt==2U );
  FD_TEST( log->idx[ 0 ]==1U );
  FD_TEST( log->idx[ 1 ]==0U );
  FD_TEST( wheel->map[ level0 ][ slot0 ]==UINT_MAX );
  FD_TEST( wheel->map[ level0 ][ slot1 ]==2U );

  fd_wheel_advance( wheel, 2L*FD_WHEEL_BUCKET( 0 ), record_callback, log );
  FD_TEST( log->cnt==3U );
  FD_TEST( log->idx[ 2 ]==2U );
  FD_TEST( wheel->map[ level0 ][ slot1 ]==UINT_MAX );
}

FD_UNIT_TEST( advance_nonzero_base ) {
  new_wheel( 987654321L );
  long base = wheel->base;

  insert_timer( 0U, base+42L );
  insert_timer( 1U, base+FD_WHEEL_RANGE( 0 )+123L );

  uint level0 = 0U;
  uint slot0  = FD_WHEEL_SLOT( level0, base+42L );
  FD_TEST( wheel->map[ level0 ][ slot0 ]==0U );
  FD_TEST( pool[ 1 ].level==1U );

  struct callback_log log[1] = {{0}};
  fd_wheel_advance( wheel, base+FD_WHEEL_BUCKET( 0 )-1L, record_callback, log );
  FD_TEST( log->cnt==0U );
  FD_TEST( wheel->base==base );

  fd_wheel_advance( wheel, base+FD_WHEEL_BUCKET( 0 ), record_callback, log );
  FD_TEST( wheel->base==base+FD_WHEEL_BUCKET( 0 ) );
  FD_TEST( log->cnt==1U );
  FD_TEST( log->idx[ 0 ]==0U );
  FD_TEST( wheel->map[ level0 ][ slot0 ]==UINT_MAX );

  long lvl1_deadline   = pool[ 1 ].deadline;
  long lvl1_bucket_end = (long)fd_ulong_align_up( (ulong)lvl1_deadline, (ulong)FD_WHEEL_BUCKET( 1 ) );
  fd_wheel_advance( wheel, lvl1_bucket_end-1L, record_callback, log );
  FD_TEST( log->cnt==1U );

  fd_wheel_advance( wheel, lvl1_bucket_end, record_callback, log );
  FD_TEST( log->cnt==2U );
  FD_TEST( log->idx[ 1 ]==1U );
}

FD_UNIT_TEST( advance_large_jump ) {
  new_wheel( 0L );
  insert_timer( 0U, FD_WHEEL_RANGE( 0 )-1L );
  insert_timer( 1U, FD_WHEEL_RANGE( 0 ) );
  insert_timer( 2U, FD_WHEEL_RANGE( 1 ) );
  insert_timer( 3U, FD_WHEEL_RANGE( 2 ) );

  FD_TEST( pool[ 0 ].level==0U );
  FD_TEST( pool[ 1 ].level==1U );
  FD_TEST( pool[ 2 ].level==2U );
  FD_TEST( pool[ 3 ].level==3U );

  struct callback_log log[1] = {{0}};
  fd_wheel_advance( wheel, 2L*fd_wheel_range(), record_callback, log );

  FD_TEST( log->cnt==4U );
  uint seen[ 4 ] = {0};
  for( uint i=0U; i<log->cnt; i++ ) {
    FD_TEST( log->idx[ i ]<4U );
    seen[ log->idx[ i ] ]++;
  }
  for( uint i=0U; i<4U; i++ ) FD_TEST( seen[ i ]==1 );
  assert_empty_map( wheel );
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );
  fd_unit_tests( argc, argv );
  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
