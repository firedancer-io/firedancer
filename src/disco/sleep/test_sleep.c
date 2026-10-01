#include "fd_sleep.h"

#include "../topo/fd_topo.h"
#include "../../util/fd_util.h"
#include "../../tango/tempo/fd_tempo.h"

#include <pthread.h>
#include <time.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <unistd.h>

static uchar        shmem_mem[ sizeof(fd_sleep_t) ] __attribute__((aligned(FD_SLEEP_ALIGN)));
static fd_sleep_t * sleep_obj;

#define HAMMER_ITER (100000UL)

static volatile int hammer_done;

/* Plays the mwaitx tile: whenever tile 1 is parked, ring and wake it.
   Extra wakes are absorbed, as in production. */

static int hammer_eventfd = -1; /* -1: futex waiter */

/* Wakes the word passed as arg for a deadline after DELAYED_WAKE_NS */

#define DELAYED_WAKE_NS (50000000L)

static void *
delayed_wake_thread( void * arg ) {
  struct timespec ts = { .tv_sec = 0, .tv_nsec = DELAYED_WAKE_NS };
  while( nanosleep( &ts, &ts ) ) {}
  fd_sleep_wake_one( (ulong *)arg, FD_SLEEP_UNPARK_DEADLINE );
  return NULL;
}

static void *
waker_thread( void * arg ) {
  (void)arg;
  while( !hammer_done ) {
    if( ( FD_VOLATILE_CONST( sleep_obj->parked_bits[ 0 ] ) & 2UL ) &&
        !FD_VOLATILE_CONST( sleep_obj->tile[ 1 ].word ) ) {
      fd_sleep_ring( sleep_obj, 1UL );
      if( __atomic_exchange_n( &sleep_obj->doorbell[ 0 ], 0UL, __ATOMIC_ACQUIRE ) & 2UL ) {
        if( hammer_eventfd>=0 ) fd_sleep_wake_eventfd( &sleep_obj->tile[ 1 ].word, hammer_eventfd, FD_SLEEP_UNPARK_RING );
        else                    fd_sleep_wake_one    ( &sleep_obj->tile[ 1 ].word, FD_SLEEP_UNPARK_RING );
      }
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
  sleep_obj = fd_sleep_join( shmem_mem );
  FD_TEST( sleep_obj );
  for( ulong i=0UL; i<FD_SLEEP_TILE_MAX; i++ ) FD_TEST( sleep_obj->tile[ i ].word==1UL );

  /* wake_check rings only parked consumers in the mask */
  fd_sleep_wake_t wake[ 2 ] = { { .w=0UL, .mask=6UL }, { .w=1UL, .mask=1UL } };
  fd_sleep_wake_check( sleep_obj, wake, 2UL );
  FD_TEST( !sleep_obj->doorbell[ 0 ] && !sleep_obj->doorbell[ 1 ] );        /* nobody parked   */
  sleep_obj->parked_bits[ 0 ] = 4UL;
  sleep_obj->parked_bits[ 1 ] = 1UL;
  fd_sleep_wake_check( sleep_obj, wake, 2UL );
  FD_TEST( sleep_obj->doorbell[ 0 ]==4UL && sleep_obj->doorbell[ 1 ]==1UL ); /* parked&mask     */
  sleep_obj->parked_bits[ 0 ] = 0UL; sleep_obj->doorbell[ 0 ] = 0UL;
  sleep_obj->parked_bits[ 1 ] = 0UL; sleep_obj->doorbell[ 1 ] = 0UL;

  /* a consumer parked on backpressure (credit bit) is not rung by a
     publish; the other parked consumers in the same word still are */
  sleep_obj->parked_bits[ 0 ] = 6UL; sleep_obj->credit_bits[ 0 ] = 4UL;
  sleep_obj->parked_bits[ 1 ] = 1UL; sleep_obj->credit_bits[ 1 ] = 1UL;
  fd_sleep_wake_check( sleep_obj, wake, 2UL );
  FD_TEST( sleep_obj->doorbell[ 0 ]==2UL && !sleep_obj->doorbell[ 1 ] );     /* credit masked   */
  sleep_obj->credit_bits[ 0 ] = 0UL; sleep_obj->credit_bits[ 1 ] = 0UL; sleep_obj->doorbell[ 0 ] = 0UL;
  fd_sleep_wake_check( sleep_obj, wake, 2UL );
  FD_TEST( sleep_obj->doorbell[ 0 ]==6UL && sleep_obj->doorbell[ 1 ]==1UL ); /* bit cleared: rung */
  sleep_obj->parked_bits[ 0 ] = 0UL; sleep_obj->doorbell[ 0 ] = 0UL;
  sleep_obj->parked_bits[ 1 ] = 0UL; sleep_obj->doorbell[ 1 ] = 0UL;

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
  FD_TEST( fd_sleep_wake_table( table, topo, 7UL )==0UL ); /* no sleep_obj object: nothing to ring */
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
    FD_VOLATILE( sleep_obj->tile[ 0 ].word ) = 0UL;
    FD_TEST( fd_sleep_park_wait( &sleep_obj->tile[ 0 ].word, fd_tickcount()+(long)(2e6*tick_per_ns), tick_per_ns )==FD_SLEEP_UNPARK_DEADLINE );
    FD_VOLATILE( sleep_obj->tile[ 0 ].word ) = 1UL;
  }
  long waited_ns = (long)((double)(fd_tickcount()-t0)/tick_per_ns);
  FD_TEST( waited_ns>=10000000L && waited_ns<500000000L );

  /* lapsed deadline returns without sleeping */
  FD_VOLATILE( sleep_obj->tile[ 0 ].word ) = 0UL;
  FD_TEST( fd_sleep_park_wait( &sleep_obj->tile[ 0 ].word, fd_tickcount()-1L, tick_per_ns )==FD_SLEEP_UNPARK_DEADLINE );
  FD_VOLATILE( sleep_obj->tile[ 0 ].word ) = 1UL;

  /* word already 1: EAGAIN counts as a ring */
  FD_VOLATILE( sleep_obj->tile[ 0 ].word ) = 1UL;
  FD_TEST( fd_sleep_park_wait( &sleep_obj->tile[ 0 ].word, fd_tickcount()+(long)(1e9*tick_per_ns), tick_per_ns )==FD_SLEEP_UNPARK_RING );

  /* the waker's cause comes back through the word, timed or untimed */
  fd_sleep_wake_one( &sleep_obj->tile[ 0 ].word, FD_SLEEP_UNPARK_DEADLINE );
  FD_TEST( fd_sleep_park_wait( &sleep_obj->tile[ 0 ].word, fd_tickcount()+(long)(1e9*tick_per_ns), tick_per_ns )==FD_SLEEP_UNPARK_DEADLINE );
  fd_sleep_wake_one( &sleep_obj->tile[ 0 ].word, FD_SLEEP_UNPARK_RING );
  FD_TEST( fd_sleep_park_wait( &sleep_obj->tile[ 0 ].word, LONG_MAX, tick_per_ns )==FD_SLEEP_UNPARK_RING );
  fd_sleep_wake_one( &sleep_obj->tile[ 0 ].word, FD_SLEEP_UNPARK_DEADLINE );
  FD_TEST( fd_sleep_park_wait( &sleep_obj->tile[ 0 ].word, LONG_MAX, tick_per_ns )==FD_SLEEP_UNPARK_DEADLINE );

  /* untimed park: a 3s wait is only ended by the wake, at the wake */
  pthread_t untimed;
  FD_VOLATILE( sleep_obj->tile[ 0 ].word ) = 0UL;
  FD_TEST( !pthread_create( &untimed, NULL, delayed_wake_thread, &sleep_obj->tile[ 0 ].word ) );
  t0 = fd_tickcount();
  FD_TEST( fd_sleep_park_wait( &sleep_obj->tile[ 0 ].word, LONG_MAX, tick_per_ns )==FD_SLEEP_UNPARK_DEADLINE );
  waited_ns = (long)((double)(fd_tickcount()-t0)/tick_per_ns);
  FD_TEST( waited_ns>=DELAYED_WAKE_NS && waited_ns<20L*DELAYED_WAKE_NS );
  FD_TEST( !pthread_join( untimed, NULL ) );

  /* lost-wake hammer: a lost wake trips the 1s backstop deadline and
     fails the cause assertion */
  pthread_t waker;
  FD_TEST( !pthread_create( &waker, NULL, waker_thread, NULL ) );
  long deadline_slack = (long)(1e9*tick_per_ns);
  for( ulong i=0UL; i<HAMMER_ITER; i++ ) {
    FD_VOLATILE( sleep_obj->tile[ 1 ].word ) = 0UL;
    __atomic_fetch_or( &sleep_obj->parked_bits[ 0 ], 2UL, __ATOMIC_SEQ_CST );
    int cause = fd_sleep_park_wait( &sleep_obj->tile[ 1 ].word, fd_tickcount()+deadline_slack, tick_per_ns );
    FD_TEST( cause==FD_SLEEP_UNPARK_RING );
    FD_VOLATILE( sleep_obj->tile[ 1 ].word ) = 1UL;
    __atomic_fetch_and( &sleep_obj->doorbell   [ 0 ], ~2UL, __ATOMIC_SEQ_CST );
    __atomic_fetch_and( &sleep_obj->parked_bits[ 0 ], ~2UL, __ATOMIC_SEQ_CST );
  }
  hammer_done = 1;
  FD_TEST( !pthread_join( waker, NULL ) );

  /* epoll park: an eventfd doorbell (EPOLLET, never read) plus a level
     triggered pipe standing in for the tile's own fd */
  int efd = eventfd( 0U, EFD_NONBLOCK );
  int pfd[ 2 ];
  FD_TEST( efd>=0 && !pipe( pfd ) );
  int epfd = epoll_create1( 0 );
  FD_TEST( epfd>=0 );
  struct epoll_event ev = { .events = EPOLLIN|EPOLLET, .data.u64 = FD_SLEEP_EPOLL_DOORBELL };
  FD_TEST( !epoll_ctl( epfd, EPOLL_CTL_ADD, efd, &ev ) );
  ev = (struct epoll_event){ .events = EPOLLIN, .data.u64 = 7UL };
  FD_TEST( !epoll_ctl( epfd, EPOLL_CTL_ADD, pfd[ 0 ], &ev ) );
  struct epoll_event evs[ 2 ];
  int ev_cnt;
  ulong * word = &sleep_obj->tile[ 1 ].word;

  /* deadline, ms timeout rounded up: never early */
  t0 = fd_tickcount();
  FD_VOLATILE( word[0] ) = 0UL;
  FD_TEST( fd_sleep_park_wait_epoll( epfd, word, evs, 2, &ev_cnt, fd_tickcount()+(long)(1.5e6*tick_per_ns), tick_per_ns )==FD_SLEEP_UNPARK_DEADLINE );
  FD_TEST( !ev_cnt );
  FD_TEST( (double)(fd_tickcount()-t0)/tick_per_ns>=1.5e6 );
  FD_TEST( fd_sleep_park_wait_epoll( epfd, word, evs, 2, &ev_cnt, fd_tickcount()-1L, tick_per_ns )==FD_SLEEP_UNPARK_DEADLINE );

  /* a doorbell wakes it, once (edge) */
  fd_sleep_wake_eventfd( word, efd, FD_SLEEP_UNPARK_RING );
  FD_TEST( word[0]==FD_SLEEP_WORD( FD_SLEEP_UNPARK_RING ) );
  FD_TEST( fd_sleep_park_wait_epoll( epfd, word, evs, 2, &ev_cnt, fd_tickcount()+deadline_slack, tick_per_ns )==FD_SLEEP_UNPARK_RING );
  FD_TEST( ev_cnt==1 && evs[ 0 ].data.u64==FD_SLEEP_EPOLL_DOORBELL );
  FD_VOLATILE( word[0] ) = 0UL;
  FD_TEST( fd_sleep_park_wait_epoll( epfd, word, evs, 2, &ev_cnt, fd_tickcount()+(long)(2e6*tick_per_ns), tick_per_ns )==FD_SLEEP_UNPARK_DEADLINE );

  /* a deadline wake through the doorbell reports a deadline, untimed */
  fd_sleep_wake_eventfd( word, efd, FD_SLEEP_UNPARK_DEADLINE );
  FD_TEST( fd_sleep_park_wait_epoll( epfd, word, evs, 2, &ev_cnt, LONG_MAX, tick_per_ns )==FD_SLEEP_UNPARK_DEADLINE );
  FD_TEST( !ev_cnt );
  FD_VOLATILE( word[0] ) = 0UL;

  /* a stale doorbell (word 0 again) is waited through */
  ulong one = 1UL;
  FD_TEST( write( efd, &one, sizeof(one) )==(long)sizeof(one) );
  FD_TEST( fd_sleep_park_wait_epoll( epfd, word, evs, 2, &ev_cnt, fd_tickcount()+(long)(2e6*tick_per_ns), tick_per_ns )==FD_SLEEP_UNPARK_DEADLINE );

  /* the tile's own fd: ready before the park returns at once, and
     stays ready (level) until read */
  FD_TEST( write( pfd[ 1 ], "x", 1UL )==1L );
  FD_TEST( fd_sleep_park_wait_epoll( epfd, word, evs, 2, &ev_cnt, fd_tickcount()+deadline_slack, tick_per_ns )==FD_SLEEP_UNPARK_RING );
  FD_TEST( ev_cnt==1 && evs[ 0 ].data.u64==7UL );
  FD_TEST( fd_sleep_park_wait_epoll( epfd, word, evs, 2, &ev_cnt, fd_tickcount()+deadline_slack, tick_per_ns )==FD_SLEEP_UNPARK_RING );
  char c;
  FD_TEST( read( pfd[ 0 ], &c, 1UL )==1L );
  FD_TEST( fd_sleep_park_wait_epoll( epfd, word, evs, 2, &ev_cnt, fd_tickcount()+(long)(2e6*tick_per_ns), tick_per_ns )==FD_SLEEP_UNPARK_DEADLINE );
  FD_VOLATILE( word[0] ) = 1UL;

  /* lost-wake hammer through the eventfd: the eventfd counter is never
     read, only its edges wake */
  hammer_done    = 0;
  hammer_eventfd = efd;
  FD_TEST( !pthread_create( &waker, NULL, waker_thread, NULL ) );
  for( ulong i=0UL; i<HAMMER_ITER; i++ ) {
    FD_VOLATILE( word[0] ) = 0UL;
    __atomic_fetch_or( &sleep_obj->parked_bits[ 0 ], 2UL, __ATOMIC_SEQ_CST );
    int cause = fd_sleep_park_wait_epoll( epfd, word, evs, 2, &ev_cnt, fd_tickcount()+deadline_slack, tick_per_ns );
    FD_TEST( cause==FD_SLEEP_UNPARK_RING );
    FD_VOLATILE( word[0] ) = 1UL;
    __atomic_fetch_and( &sleep_obj->doorbell   [ 0 ], ~2UL, __ATOMIC_SEQ_CST );
    __atomic_fetch_and( &sleep_obj->parked_bits[ 0 ], ~2UL, __ATOMIC_SEQ_CST );
  }
  hammer_done = 1;
  FD_TEST( !pthread_join( waker, NULL ) );
  FD_TEST( !close( epfd ) && !close( efd ) && !close( pfd[ 0 ] ) && !close( pfd[ 1 ] ) );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
