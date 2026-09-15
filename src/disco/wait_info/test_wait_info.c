#include "fd_wait_info.h"
#include "../../util/fd_util.h"

#include <pthread.h>
#include <limits.h>

/* Shared state for hammer test */
static fd_wait_info_box_t hammer_box __attribute__((aligned(64)));
static volatile int       hammer_done;

#define HAMMER_ITER (1000000UL)

static void
test_new_join_null( void ) {
  FD_LOG_NOTICE(( "testing new join null" ));
  FD_TEST( !fd_wait_info_box_new( NULL ) );
  FD_TEST( !fd_wait_info_box_join( NULL ) );
  FD_LOG_NOTICE(( "... pass" ));
}

static void
test_join_bad_magic( void ) {
  FD_LOG_NOTICE(( "testing join bad magic" ));
  uchar mem[ sizeof(fd_wait_info_box_t) ] __attribute__((aligned(64)));
  fd_memset( mem, 0, sizeof(mem) );
  FD_TEST( !fd_wait_info_box_join( mem ) );
  FD_LOG_NOTICE(( "... pass" ));
}

static void
test_new_join_ok( void ) {
  FD_LOG_NOTICE(( "testing new join ok" ));
  uchar mem[ sizeof(fd_wait_info_box_t) ] __attribute__((aligned(64)));
  FD_TEST( fd_wait_info_box_new( mem )==mem );
  fd_wait_info_box_t * box = fd_wait_info_box_join( mem );
  FD_TEST( box );
  FD_TEST( box->info.caught_up==0 );
  FD_TEST( box->info.reset_slot==0UL );
  FD_TEST( box->info.next_leader_slot==0UL );
  FD_TEST( box->info.leader_slot==0UL );
  FD_TEST( box->info.epoch_end_slot==0UL );
  FD_TEST( box->info.slots_per_epoch==0UL );
  FD_TEST( box->info.ns_per_slot==0UL );
  FD_TEST( box->info.delinquent_stake_lamports==0UL );
  FD_TEST( box->info.cluster_active_stake_lamports==0UL );
  FD_TEST( box->info.snap_active==0 );
  FD_TEST( box->info.snap_finished_full==0UL );
  FD_TEST( box->info.snap_finished_incr==0UL );
  FD_TEST( atomic_load_explicit( &box->seq_lock, memory_order_relaxed )==0U );
  FD_LOG_NOTICE(( "... pass" ));
}

static void
test_write_cycle_seq( void ) {
  FD_LOG_NOTICE(( "testing write cycle seq" ));
  uchar mem[ sizeof(fd_wait_info_box_t) ] __attribute__((aligned(64)));
  fd_wait_info_box_t * box = fd_wait_info_box_join( fd_wait_info_box_new( mem ) );
  FD_TEST( box );
  FD_TEST( atomic_load_explicit( &box->seq_lock, memory_order_relaxed )==0U );

  fd_wait_info_write_begin( box );
  FD_TEST( atomic_load_explicit( &box->seq_lock, memory_order_relaxed )==1U );
  fd_wait_info_write_end( box );
  FD_TEST( atomic_load_explicit( &box->seq_lock, memory_order_relaxed )==2U );

  fd_wait_info_write_begin( box );
  FD_TEST( atomic_load_explicit( &box->seq_lock, memory_order_relaxed )==3U );
  fd_wait_info_write_end( box );
  FD_TEST( atomic_load_explicit( &box->seq_lock, memory_order_relaxed )==4U );
  FD_LOG_NOTICE(( "... pass" ));
}

static void
test_try_read_quiescent( void ) {
  FD_LOG_NOTICE(( "testing try read quiescent" ));
  uchar mem[ sizeof(fd_wait_info_box_t) ] __attribute__((aligned(64)));
  fd_wait_info_box_t * box = fd_wait_info_box_join( fd_wait_info_box_new( mem ) );
  FD_TEST( box );

  box->info.caught_up        = 1;
  box->info.reset_slot       = 42UL;
  box->info.next_leader_slot = 100UL;
  box->info.slots_per_epoch  = 432000UL;
  box->info.snap_active      = 0;

  fd_wait_info_t dst;
  FD_TEST( fd_wait_info_try_read( &dst, box ) );
  FD_TEST( dst.caught_up==1 );
  FD_TEST( dst.reset_slot==42UL );
  FD_TEST( dst.next_leader_slot==100UL );
  FD_TEST( dst.slots_per_epoch==432000UL );
  FD_TEST( dst.snap_active==0 );
  FD_LOG_NOTICE(( "... pass" ));
}

static void
test_try_read_during_write( void ) {
  FD_LOG_NOTICE(( "testing try read during write" ));
  uchar mem[ sizeof(fd_wait_info_box_t) ] __attribute__((aligned(64)));
  fd_wait_info_box_t * box = fd_wait_info_box_join( fd_wait_info_box_new( mem ) );
  FD_TEST( box );

  fd_wait_info_write_begin( box );
  fd_wait_info_t dst;
  FD_TEST( !fd_wait_info_try_read( &dst, box ) );

  fd_wait_info_write_end( box );
  FD_TEST( fd_wait_info_try_read( &dst, box ) );
  FD_LOG_NOTICE(( "... pass" ));
}

static void
test_seq_lock_uint_wrap( void ) {
  FD_LOG_NOTICE(( "testing seq lock uint wrap" ));
  uchar mem[ sizeof(fd_wait_info_box_t) ] __attribute__((aligned(64)));
  fd_wait_info_box_t * box = fd_wait_info_box_join( fd_wait_info_box_new( mem ) );
  FD_TEST( box );

  /* Seed seq_lock to UINT_MAX-1 (even) */
  atomic_store_explicit( &box->seq_lock, UINT_MAX-1U, memory_order_relaxed );
  FD_TEST( atomic_load_explicit( &box->seq_lock, memory_order_relaxed )==UINT_MAX-1U );

  box->info.reset_slot = 99UL;

  /* write_begin: UINT_MAX-1 -> UINT_MAX (odd) */
  fd_wait_info_write_begin( box );
  FD_TEST( atomic_load_explicit( &box->seq_lock, memory_order_relaxed )==UINT_MAX );
  /* write_end: UINT_MAX -> 0 (wraps, even) */
  fd_wait_info_write_end( box );
  FD_TEST( atomic_load_explicit( &box->seq_lock, memory_order_relaxed )==0U );

  fd_wait_info_t dst;
  FD_TEST( fd_wait_info_try_read( &dst, box ) );
  FD_TEST( dst.reset_slot==99UL );
  FD_LOG_NOTICE(( "... pass" ));
}

static void *
writer_thread( void * arg ) {
  fd_wait_info_box_t * box = (fd_wait_info_box_t *)arg;
  ulong gen = 0UL;
  while( !hammer_done ) {
    gen++;
    fd_wait_info_write_begin( box );
    box->info.caught_up                     = (int)gen;
    box->info.reset_slot                    = gen;
    box->info.next_leader_slot              = gen;
    box->info.leader_slot                   = gen;
    box->info.epoch_end_slot                = gen;
    box->info.slots_per_epoch               = gen;
    box->info.ns_per_slot                   = gen;
    box->info.delinquent_stake_lamports     = gen;
    box->info.cluster_active_stake_lamports = gen;
    box->info.snap_active                   = (int)gen;
    box->info.snap_finished_full            = gen;
    box->info.snap_finished_incr            = gen;
    fd_wait_info_write_end( box );
  }
  return NULL;
}

static void
test_hammer_no_torn_reads( void ) {
  FD_LOG_NOTICE(( "testing hammer no torn reads" ));
  hammer_done = 0;
  fd_wait_info_box_t * box = fd_wait_info_box_join( fd_wait_info_box_new( &hammer_box ) );
  FD_TEST( box );

  pthread_t writer;
  FD_TEST( !pthread_create( &writer, NULL, writer_thread, box ) );

  ulong reads = 0UL;
  ulong fails = 0UL;
  while( reads<HAMMER_ITER ) {
    fd_wait_info_t snap;
    if( !fd_wait_info_try_read( &snap, box ) ) { fails++; continue; }
    reads++;

    ulong gen = snap.reset_slot;
    FD_TEST( snap.caught_up                     ==(int)gen );
    FD_TEST( snap.next_leader_slot              ==gen );
    FD_TEST( snap.leader_slot                   ==gen );
    FD_TEST( snap.epoch_end_slot                ==gen );
    FD_TEST( snap.slots_per_epoch               ==gen );
    FD_TEST( snap.ns_per_slot                   ==gen );
    FD_TEST( snap.delinquent_stake_lamports     ==gen );
    FD_TEST( snap.cluster_active_stake_lamports ==gen );
    FD_TEST( snap.snap_active                   ==(int)gen );
    FD_TEST( snap.snap_finished_full            ==gen );
    FD_TEST( snap.snap_finished_incr            ==gen );
  }

  hammer_done = 1;
  FD_TEST( !pthread_join( writer, NULL ) );
  FD_LOG_NOTICE(( "hammer: %lu successful reads, %lu retries", reads, fails ));
  FD_LOG_NOTICE(( "... pass" ));
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  test_new_join_null();
  test_join_bad_magic();
  test_new_join_ok();
  test_write_cycle_seq();
  test_try_read_quiescent();
  test_try_read_during_write();
  test_seq_lock_uint_wrap();
  test_hammer_no_torn_reads();

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
