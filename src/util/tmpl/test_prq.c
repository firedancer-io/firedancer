#include "../fd_util.h"

struct event {
  long timeout;
  long timeout2; /* Used for implq test. Strictly positive */
  long val[3];
};

typedef struct event event_t;

#define PRQ_NAME eventq
#define PRQ_T    event_t
#include "fd_prq.c"

#define PRQ_NAME maxq
#define PRQ_T    event_t
#define PRQ_TIMEOUT_AFTER(x,y) ((x)<(y))
#include "fd_prq.c"


#define PRQ_NAME implq
#define PRQ_T    event_t
#define PRQ_EXPLICIT_TIMEOUT 0
/* Sort by timeout1/timeout2 decreasing, by cross multiplying */
#define PRQ_AFTER(x,y) (((x).timeout*(y).timeout2)<((y).timeout*(x).timeout2))
#include "fd_prq.c"

static int
test_heap( event_t * heap,
           ulong     cnt,
           ulong     max ) {
  FD_TEST( eventq_cnt( heap )==cnt );
  FD_TEST( eventq_max( heap )==max );
  FD_TEST( cnt<=max );
  for( ulong child=1UL; child<cnt; child++ ) {
    ulong parent = (child-1UL) >> 1;
    FD_TEST( heap[ parent ].timeout<=heap[ child ].timeout );
  }
  return 0;
}
static int
test_max_heap( event_t * heap,
               ulong     cnt,
               ulong     max ) {
  FD_TEST( maxq_cnt( heap )==cnt );
  FD_TEST( maxq_max( heap )==max );
  FD_TEST( cnt<=max );
  for( ulong child=1UL; child<cnt; child++ ) {
    ulong parent = (child-1UL) >> 1;
    FD_TEST( heap[ parent ].timeout>=heap[ child ].timeout );
  }
  return 0;
}
static int
test_implicit_heap( event_t * heap,
                    ulong     cnt,
                    ulong     max ) {
  FD_TEST( implq_cnt( heap )==cnt );
  FD_TEST( implq_max( heap )==max );
  FD_TEST( cnt<=max );
  for( ulong child=1UL; child<cnt; child++ ) {
    ulong parent = (child-1UL) >> 1;
    long double _parent = heap[ parent ].timeout / (long double) heap[ parent ].timeout2;
    long double _child  = heap[ child  ].timeout / (long double) heap[ child  ].timeout2;
    FD_TEST( _parent>=_child );
  }
  return 0;
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  fd_rng_t _rng[1]; fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, 0U, 0UL ) );

  ulong max = 1024UL; // FIXME: CURRENTLY SOME THINGS ARE 1024 CENTRIC IN TEST
//ulong max = fd_cstr_strip_cmdline_ulong( &argc, &argv, "--max", 1024UL );
//FD_LOG_NOTICE(( "--max %lu", max ));

  FD_LOG_NOTICE(( "Testing construction" ));

  ulong align     = eventq_align();
  ulong footprint = eventq_footprint( max );
  FD_TEST( fd_ulong_is_pow2( align ) );
  FD_TEST( fd_ulong_is_aligned( footprint, align ) );

  uchar _mem[ 65536 ];
  uchar * mem = (uchar *)fd_ulong_align_up( (ulong)_mem, align );
  if( FD_UNLIKELY( (mem+footprint) > (_mem+65536) ) ) {
    FD_LOG_WARNING(( "skip: update test to support larger --max" ));
    return 0;
  }

  FD_LOG_NOTICE(( "Testing accessors" ));

  void *    sheventq = eventq_new ( mem, max ); FD_TEST( sheventq==mem );
  event_t * heap     = eventq_join( sheventq ); FD_TEST( heap );

  FD_TEST( eventq_cnt( heap )==0UL );
  FD_TEST( eventq_max( heap )==max );

  FD_LOG_NOTICE(( "Testing insert" ));

  /* Schedule events in a quasi random order at a point in the future.
     Have some events collide. */

  for( ulong i=0UL; i<max; i++ ) {
    ulong j=0UL; for( ulong b=0UL; b<10UL; b++ ) j += ((i>>(9UL-b))&1UL) << b; /* FIXME: THIS IS 1024 CENTRIC */

    event_t event[1];
    event->timeout  = (long)((7UL*j+1UL)/8UL);
    event->timeout2 = 1L;
    for( ulong k=0UL; k<3UL; k++ ) event->val[k] = ((long)(k+2UL))*event->timeout;

    FD_TEST( eventq_insert( heap, event )==heap );

    if( FD_UNLIKELY( test_heap( heap, i+1UL, max ) ) ) return 1;
  }

  FD_LOG_NOTICE(( "Testing remove (min)" ));

  /* Make sure events are retrieved in a valid order */

  for( ulong i=0UL; i<max; i++ ) {
    long exp_timeout = (long)((7UL*i+1UL)/8UL);
    FD_TEST( heap->timeout==   exp_timeout );
    FD_TEST( heap->val[0] ==2L*exp_timeout );
    FD_TEST( heap->val[1] ==3L*exp_timeout );
    FD_TEST( heap->val[2] ==4L*exp_timeout );
    FD_TEST( eventq_remove_min( heap )==heap );
    if( FD_UNLIKELY( test_heap( heap, max-1UL-i, max ) ) ) return 1;
  }

  FD_LOG_NOTICE(( "Testing remove (random)" ));

  /* Schedule events in a quasi random order at a point in the future.
     Have some events collide. */

  for( ulong i=0UL; i<max; i++ ) {
    ulong j=0UL; for( ulong b=0UL; b<10UL; b++ ) j += ((i>>(9UL-b))&1UL) << b; /* FIXME: THIS IS 1024 CENTRIC */

    event_t event[1];
    event->timeout  = (long)((7UL*j+1UL)/8UL);
    event->timeout2 = 1L;
    event->val[0]   = (long)     j;
    event->val[1]   = (long)(2UL*j);
    event->val[2]   = (long)(3UL*j);

    FD_TEST( eventq_insert( heap, event )==heap );

    if( FD_UNLIKELY( test_heap( heap, i+1UL, max ) ) ) return 1;
  }

  /* Cancel half the events in a random order (and remember what we cancelled) */

  ulong skip_cnt = max>>1;
  ulong keep_cnt = max - skip_cnt;

  long skip[512]; /* FIXME: THIS IS 1024 CENTRIC */
  for( ulong j=0UL; j<skip_cnt; j++ ) {
    ulong k = (ulong)fd_rng_uint_roll( rng, (uint)eventq_cnt( heap ) );
    skip[j] = heap[k].val[0];
    FD_TEST( eventq_remove( heap, k )==heap );
    if( FD_UNLIKELY( test_heap( heap, max-1UL-j, max ) ) ) return 1;
  }

  /* Make sure remaining events are retrieved in a valid order */

  long last = LONG_MIN;
  for( ulong i=0UL; i<keep_cnt; i++ ) {
    for( ulong j=0UL; j<skip_cnt; j++ ) FD_TEST( heap->val[0] != skip[j] );
    FD_TEST( heap->timeout>=last );
    last = heap->timeout;

    FD_TEST( heap->timeout==(7L*heap->val[0]+1L)/8L );
    FD_TEST( heap->val[1] == 2L*heap->val[0]        );
    FD_TEST( heap->val[2] == 3L*heap->val[0]        );

    FD_TEST( eventq_remove_min( heap )==heap );
    if( FD_UNLIKELY( test_heap( heap, keep_cnt-1UL-i, max ) ) ) return 1;
  }

  FD_LOG_NOTICE(( "Testing remove (all)" ));

  for( ulong iter=0UL; iter<10UL; iter++ ) {
    ulong cnt = (ulong)fd_rng_uint_roll( rng, (uint)(max+1UL) );
    for( ulong i=0UL; i<cnt; i++ ) {
      event_t event[1];
      event->timeout  = (long)fd_rng_ulong( rng );
      event->timeout2 = (long)fd_rng_ulong( rng )+1L;
      event->val[0]   = (long)fd_rng_ulong( rng );
      event->val[1]   = (long)fd_rng_ulong( rng );
      event->val[2]   = (long)fd_rng_ulong( rng );
      FD_TEST( eventq_insert( heap, event )==heap );
      if( FD_UNLIKELY( test_heap( heap, i+1UL, max ) ) ) return 1;
    }
    FD_TEST( eventq_remove_all( heap )==heap );
    if( FD_UNLIKELY( test_heap( heap, 0UL, max ) ) ) return 1;
  } while(0);

  FD_LOG_NOTICE(( "Testing destruction" ));

  FD_TEST( eventq_leave ( heap     )==sheventq );
  FD_TEST( eventq_delete( sheventq )==mem      );

  FD_LOG_NOTICE(( "Testing max queue" ));
  sheventq = maxq_new ( mem, max ); FD_TEST( sheventq==mem );
  heap     = maxq_join( sheventq ); FD_TEST( heap );

  FD_TEST( maxq_cnt( heap )==0UL );
  FD_TEST( maxq_max( heap )==max );

  for( ulong i=0UL; i<max; i++ ) {
    ulong j=0UL; for( ulong b=0UL; b<10UL; b++ ) j += ((i>>(9UL-b))&1UL) << b; /* FIXME: THIS IS 1024 CENTRIC */

    event_t event[1];
    event->timeout  = (long)((7UL*j+1UL)/8UL);
    event->timeout2 = 1L;
    event->val[0]   = (long)     j;
    event->val[1]   = (long)(2UL*j);
    event->val[2]   = (long)(3UL*j);

    FD_TEST( maxq_insert( heap, event )==heap );

    if( FD_UNLIKELY( test_max_heap( heap, i+1UL, max ) ) ) return 1;
  }

  /* Cancel half the events in a random order (and remember what we cancelled) */
  for( ulong j=0UL; j<skip_cnt; j++ ) {
    ulong k = (ulong)fd_rng_uint_roll( rng, (uint)maxq_cnt( heap ) );
    skip[j] = heap[k].val[0];
    FD_TEST( maxq_remove( heap, k )==heap );
    if( FD_UNLIKELY( test_max_heap( heap, max-1UL-j, max ) ) ) return 1;
  }

  /* Make sure remaining events are retrieved in a valid order */

  last = LONG_MAX;
  for( ulong i=0UL; i<keep_cnt; i++ ) {
    for( ulong j=0UL; j<skip_cnt; j++ ) FD_TEST( heap->val[0] != skip[j] );
    FD_TEST( heap->timeout<=last );
    last = heap->timeout;

    FD_TEST( heap->timeout==(7L*heap->val[0]+1L)/8L );
    FD_TEST( heap->val[1] == 2L*heap->val[0]        );
    FD_TEST( heap->val[2] == 3L*heap->val[0]        );

    FD_TEST( maxq_remove_min( heap )==heap );
    if( FD_UNLIKELY( test_max_heap( heap, keep_cnt-1UL-i, max ) ) ) return 1;
  }
  FD_TEST( maxq_leave ( heap     )==sheventq );
  FD_TEST( maxq_delete( sheventq )==mem      );


  FD_LOG_NOTICE(( "Testing implicit queue" ));
  sheventq = implq_new ( mem, max ); FD_TEST( sheventq==mem );
  heap     = implq_join( sheventq ); FD_TEST( heap );

  FD_TEST( implq_cnt( heap )==0UL );
  FD_TEST( implq_max( heap )==max );

  for( ulong i=0UL; i<max; i++ ) {
    ulong j=0UL; for( ulong b=0UL; b<10UL; b++ ) j += ((i>>(9UL-b))&1UL) << b; /* FIXME: THIS IS 1024 CENTRIC */

    long denominator = (long)fd_rng_uint_roll( rng, 10000) + 1L;
    event_t event[1];
    event->timeout  = (long)((7UL*j+1UL)/8UL)*denominator;
    event->timeout2 = denominator;
    event->val[0]   = (long)     j;
    event->val[1]   = (long)(2UL*j);
    event->val[2]   = (long)(3UL*j);

    FD_TEST( implq_insert( heap, event )==heap );

    if( FD_UNLIKELY( test_implicit_heap( heap, i+1UL, max ) ) ) return 1;
  }

  /* Cancel half the events in a random order (and remember what we cancelled) */
  for( ulong j=0UL; j<skip_cnt; j++ ) {
    ulong k = (ulong)fd_rng_uint_roll( rng, (uint)implq_cnt( heap ) );
    skip[j] = heap[k].val[0];
    FD_TEST( implq_remove( heap, k )==heap );
    if( FD_UNLIKELY( test_implicit_heap( heap, max-1UL-j, max ) ) ) return 1;
  }

  /* Make sure remaining events are retrieved in a valid order */

  last = LONG_MAX;
  for( ulong i=0UL; i<keep_cnt; i++ ) {
    for( ulong j=0UL; j<skip_cnt; j++ ) FD_TEST( heap->val[0] != skip[j] );
    FD_TEST( heap->timeout/heap->timeout2<=last );
    last = heap->timeout/heap->timeout2;

    FD_TEST( heap->timeout/heap->timeout2 == (7L*heap->val[0]+1L)/8L );
    FD_TEST( heap->val[1] == 2L*heap->val[0]        );
    FD_TEST( heap->val[2] == 3L*heap->val[0]        );

    FD_TEST( implq_remove_min( heap )==heap );
    if( FD_UNLIKELY( test_implicit_heap( heap, keep_cnt-1UL-i, max ) ) ) return 1;
  }
  FD_TEST( implq_leave ( heap     )==sheventq );
  FD_TEST( implq_delete( sheventq )==mem      );

  fd_rng_delete( fd_rng_leave( rng ) );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}

