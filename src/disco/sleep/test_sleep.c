#include "fd_sleep.h"

#include "../topo/fd_topo.h"
#include "../../util/fd_util.h"
#include "../../tango/tempo/fd_tempo.h"

#include <pthread.h>

static uchar        shmem_mem[ sizeof(fd_sleep_t) ] __attribute__((aligned(FD_SLEEP_ALIGN)));
static fd_sleep_t * sleep;

#define HAMMER_ITER (100000UL)

static volatile int hammer_done;

/* Plays the mwaitx tile: whenever tile 1 is parked, ring and wake it.
   Extra wakes are absorbed, as in production. */

static void *
waker_thread( void * arg ) {
  (void)arg;
  while( !hammer_done ) {
    if( ( FD_VOLATILE_CONST( sleep->parked_bits[ 0 ] ) & 2UL ) &&
        !FD_VOLATILE_CONST( sleep->tile[ 1 ].word ) ) {
      fd_sleep_ring( sleep, 1UL );
      if( __atomic_exchange_n( &sleep->doorbell[ 0 ], 0UL, __ATOMIC_ACQUIRE ) & 2UL )
        fd_sleep_wake_one( &sleep->tile[ 1 ].word );
    } else {
      FD_SPIN_PAUSE();
    }
  }
  return NULL;
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  FD_TEST( fd_sleep_align()==FD_SLEEP_ALIGN );
  FD_TEST( fd_sleep_footprint()==sizeof(shmem_mem) );
  double tick_per_ns = fd_tempo_tick_per_ns( NULL );

  FD_TEST( !fd_sleep_new( NULL, tick_per_ns ) );
  FD_TEST( !fd_sleep_new( shmem_mem+8UL, tick_per_ns ) );
  FD_TEST( !fd_sleep_new( shmem_mem, 0.0 ) );
  FD_TEST( !fd_sleep_join( shmem_mem ) ); /* no magic yet */
  FD_TEST( fd_sleep_new( shmem_mem, tick_per_ns )==shmem_mem );
  sleep = fd_sleep_join( shmem_mem );
  FD_TEST( sleep );
  for( ulong i=0UL; i<FD_SLEEP_TILE_MAX; i++ ) FD_TEST( sleep->tile[ i ].word==1UL );

  /* wake_check rings only parked consumers in the mask */
  fd_sleep_wake_t wake[ 2 ] = { { .w=0UL, .mask=6UL }, { .w=1UL, .mask=1UL } };
  fd_sleep_wake_check( sleep, wake, 2UL );
  FD_TEST( !sleep->doorbell[ 0 ] && !sleep->doorbell[ 1 ] );        /* nobody parked   */
  sleep->parked_bits[ 0 ] = 4UL;
  sleep->parked_bits[ 1 ] = 1UL;
  fd_sleep_wake_check( sleep, wake, 2UL );
  FD_TEST( sleep->doorbell[ 0 ]==4UL && sleep->doorbell[ 1 ]==1UL ); /* parked&mask     */
  sleep->parked_bits[ 0 ] = 0UL; sleep->doorbell[ 0 ] = 0UL;
  sleep->parked_bits[ 1 ] = 0UL; sleep->doorbell[ 1 ] = 0UL;

  /* wake_table: polled consumers of one link, as (word,mask) pairs */
  static fd_topo_t topo[ 1 ];
  topo->sleep_obj_id = ULONG_MAX;
  topo->tile_cnt     = 70UL;
  for( ulong i=0UL; i<topo->tile_cnt; i++ ) { topo->tiles[ i ].id = i; topo->tiles[ i ].in_cnt = 0UL; }
  topo->tiles[  2 ].in_cnt = 2UL; topo->tiles[  2 ].in_link_id[ 0 ] = 7UL; topo->tiles[  2 ].in_link_poll[ 0 ] = 1;
  /**/                            topo->tiles[  2 ].in_link_id[ 1 ] = 8UL; topo->tiles[  2 ].in_link_poll[ 1 ] = 1;
  topo->tiles[  5 ].in_cnt = 1UL; topo->tiles[  5 ].in_link_id[ 0 ] = 7UL; topo->tiles[  5 ].in_link_poll[ 0 ] = 0; /* unpolled: no wake */
  topo->tiles[ 65 ].in_cnt = 1UL; topo->tiles[ 65 ].in_link_id[ 0 ] = 7UL; topo->tiles[ 65 ].in_link_poll[ 0 ] = 1; /* second word */
  fd_sleep_wake_t table[ FD_SLEEP_BITS_CNT ];
  FD_TEST( fd_sleep_wake_table( table, topo, 7UL )==0UL ); /* no sleep object: nothing to ring */
  topo->sleep_obj_id = 0UL;
  FD_TEST( fd_sleep_wake_table( table, topo, 9UL )==0UL ); /* no consumers */
  FD_TEST( fd_sleep_wake_table( table, topo, 8UL )==1UL && table[ 0 ].w==0UL && table[ 0 ].mask==(1UL<<2) );
  FD_TEST( fd_sleep_wake_table( table, topo, 7UL )==2UL );
  FD_TEST( table[ 0 ].w==0UL && table[ 0 ].mask==(1UL<<2) );
  FD_TEST( table[ 1 ].w==1UL && table[ 1 ].mask==(1UL<<1) );

  /* deadline: no waker, absolute timeout honored.  Ten 2ms parks in a
     row: a preemption inside one park can shorten that park, but not
     eat half of the total. */
  long t0 = fd_tickcount();
  for( ulong i=0UL; i<10UL; i++ ) {
    FD_VOLATILE( sleep->tile[ 0 ].word ) = 0UL;
    FD_TEST( fd_sleep_park_wait( sleep, &sleep->tile[ 0 ].word, fd_tickcount()+(long)(2e6*tick_per_ns) )==FD_SLEEP_UNPARK_DEADLINE );
    FD_VOLATILE( sleep->tile[ 0 ].word ) = 1UL;
  }
  long waited_ns = (long)((double)(fd_tickcount()-t0)/tick_per_ns);
  FD_TEST( waited_ns>=10000000L && waited_ns<500000000L );

  /* lapsed deadline returns without sleeping */
  FD_VOLATILE( sleep->tile[ 0 ].word ) = 0UL;
  FD_TEST( fd_sleep_park_wait( sleep, &sleep->tile[ 0 ].word, fd_tickcount()-1L )==FD_SLEEP_UNPARK_DEADLINE );
  FD_VOLATILE( sleep->tile[ 0 ].word ) = 1UL;

  /* word already 1: EAGAIN counts as a ring */
  FD_VOLATILE( sleep->tile[ 0 ].word ) = 1UL;
  FD_TEST( fd_sleep_park_wait( sleep, &sleep->tile[ 0 ].word, fd_tickcount()+(long)(1e9*tick_per_ns) )==FD_SLEEP_UNPARK_RING );

  /* lost-wake hammer: a lost wake trips the 1s backstop deadline and
     fails the cause assertion */
  pthread_t waker;
  FD_TEST( !pthread_create( &waker, NULL, waker_thread, NULL ) );
  long deadline_slack = (long)(1e9*tick_per_ns);
  for( ulong i=0UL; i<HAMMER_ITER; i++ ) {
    FD_VOLATILE( sleep->tile[ 1 ].word ) = 0UL;
    __atomic_fetch_or( &sleep->parked_bits[ 0 ], 2UL, __ATOMIC_SEQ_CST );
    int cause = fd_sleep_park_wait( sleep, &sleep->tile[ 1 ].word, fd_tickcount()+deadline_slack );
    FD_TEST( cause==FD_SLEEP_UNPARK_RING );
    FD_VOLATILE( sleep->tile[ 1 ].word ) = 1UL;
    __atomic_fetch_and( &sleep->doorbell   [ 0 ], ~2UL, __ATOMIC_SEQ_CST );
    __atomic_fetch_and( &sleep->parked_bits[ 0 ], ~2UL, __ATOMIC_SEQ_CST );
  }
  hammer_done = 1;
  FD_TEST( !pthread_join( waker, NULL ) );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
