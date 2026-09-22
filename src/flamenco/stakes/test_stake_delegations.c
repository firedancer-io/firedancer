#define _GNU_SOURCE
#include "test_stake_delegations_util.h"
#include "fd_stakes.h"
#include "../../util/fd_hash32.h"
#include "../runtime/fd_system_ids.h"
#include "../runtime/sysvar/fd_sysvar_stake_history.h"

#if FD_HAS_RACESAN
#include "../../util/racesan/fd_racesan_async.h"
#include "../../util/racesan/fd_racesan_weave.h"
#endif

#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

FD_STATIC_ASSERT( sizeof(((fd_stake_delegations_t *)0)->tree_lock)==sizeof(fd_rwlock_t), tree_lock_is_raw_rwlock );
FD_STATIC_ASSERT( sizeof(((fd_stake_delegations_t *)0)->cache_lock)==sizeof(fd_rwlock_t), cache_lock_is_raw_rwlock );

#define TEST_STAKE_DELEGATION_LAMPORTS (123456789UL)
#define TEST_STAKE_DELEGATION_ACC_DLEN ((uint)sizeof(fd_stake_state_t))

#define TEST_ACCDB_CACHE_FOOTPRINT    (32UL<<20)
#define TEST_ACCDB_CACHE_MIN_RESERVED (2UL)

struct test_accdb {
  fd_accdb_t * accdb;
  void *       shmem_mem;
  int          fd;
};
typedef struct test_accdb test_accdb_t;

static test_accdb_t
test_accdb_new( void ) {
  test_accdb_t test = { .fd = memfd_create( "stake_delegations_accdb", 0 ) };
  FD_TEST( test.fd>=0 );

  ulong shmem_footprint = fd_accdb_shmem_footprint( 64UL, 3UL, 64UL, 64UL, TEST_ACCDB_CACHE_FOOTPRINT, TEST_ACCDB_CACHE_MIN_RESERVED, 1UL, 0UL );
  FD_TEST( shmem_footprint );
  test.shmem_mem = aligned_alloc( fd_accdb_shmem_align(), shmem_footprint );
  FD_TEST( test.shmem_mem );
  fd_accdb_shmem_t * shmem = fd_accdb_shmem_join(
      fd_accdb_shmem_new( test.shmem_mem, 64UL, 3UL, 64UL, 64UL, 1UL<<30, TEST_ACCDB_CACHE_FOOTPRINT, TEST_ACCDB_CACHE_MIN_RESERVED, 0, 42UL, 1UL, 0UL ) );
  FD_TEST( shmem );

  void * accdb_mem = aligned_alloc( fd_accdb_align(), fd_accdb_footprint( 3UL ) );
  FD_TEST( accdb_mem );
  test.accdb = fd_accdb_join( fd_accdb_new( accdb_mem, shmem, test.fd, 0UL, NULL ) );
  FD_TEST( test.accdb );
  return test;
}

static void
test_accdb_delete( test_accdb_t * test ) {
  free( test->shmem_mem );
  free( test->accdb );
  FD_TEST( !close( test->fd ) );
}

static void
test_accdb_write_stake( fd_accdb_t *             accdb,
                        fd_accdb_fork_id_t       fork_id,
                        fd_pubkey_t const *      pubkey,
                        fd_stake_state_t const * stake ) {
  uchar const * keys[ 1 ] = { pubkey->uc };
  int           writable[ 1 ] = { 1 };
  fd_acc_t      acc[ 1 ] = {0};
  fd_accdb_acquire( accdb, fork_id, 1UL, keys, writable, acc );
  acc[ 0 ].lamports = TEST_STAKE_DELEGATION_LAMPORTS;
  acc[ 0 ].data_len = sizeof(fd_stake_state_t);
  memcpy( acc[ 0 ].owner, &fd_solana_stake_program_id, sizeof(fd_pubkey_t) );
  memcpy( acc[ 0 ].data, stake, sizeof(fd_stake_state_t) );
  acc[ 0 ].commit = 1;
  fd_accdb_release( accdb, 1UL, acc );
}


static fd_pubkey_t
key( ulong k ) {
  fd_pubkey_t pubkey = {{0}};
  pubkey.ul[ 0 ] = k;
  return pubkey;
}

static void
update( fd_stake_delegations_t * sd, ushort fork, ulong k, ulong stake ) {
  fd_pubkey_t pubkey = key( k );
  fd_stake_delegations_fork_update( sd, fork, &pubkey, &pubkey, stake, ULONG_MAX, ULONG_MAX, 0UL, stake+1UL, 200U, 0 );
}

static void
root_update( fd_stake_delegations_t * sd, ulong k, ulong stake ) {
  fd_pubkey_t pubkey = key( k );
  fd_stake_delegations_root_update( sd, &pubkey, &pubkey, stake, ULONG_MAX, ULONG_MAX, 0UL, stake+1UL, 200U, 0 );
}

static ulong
expect( fd_stake_delegations_t * sd, ushort fork, ulong k, ulong stake ) {
  fd_pubkey_t pubkey = key( k );
  fd_stake_delegations_view_t view[1];
  fd_stake_delegations_view_begin( view, sd, fork );
  ulong idx = ULONG_MAX;
  int found = 0;
  fd_stake_delegations_iter_t iter[1];
  for( fd_stake_delegations_iter_init( iter, view ); !fd_stake_delegations_iter_done( iter ); fd_stake_delegations_iter_next( iter ) ) {
    fd_stake_delegation_t const * d = fd_stake_delegations_iter_ele( iter );
    if( memcmp( &d->stake_account, &pubkey, sizeof(pubkey) ) ) continue;
    FD_TEST( !found );
    FD_TEST( d->stake==stake );
    FD_TEST( d->state==FD_STAKE_DELEGATION_STATE_UNKNOWN );
    found = 1;
    idx = fd_stake_delegations_iter_idx( iter );
  }
  fd_stake_delegations_view_end( view );
  FD_TEST( found==(stake!=ULONG_MAX) );
  return idx;
}

static void
test_visibility( fd_stake_delegations_t * sd ) {
  fd_stake_delegations_reset( sd );
  ushort root = fd_stake_delegations_root_fork_id( sd );
  root_update( sd, 1UL, 100UL );
  ushort a = fd_stake_delegations_attach_child( sd, root );
  update( sd, a, 1UL, 120UL );
  fd_stake_delegations_finalize_fork( sd, a );
  ushort f = fd_stake_delegations_attach_child( sd, a );
  ushort b = fd_stake_delegations_attach_child( sd, root );
  update( sd, b, 1UL, 90UL );
  fd_stake_delegations_finalize_fork( sd, b );
  ulong idx = expect( sd, f, 1UL, 120UL );
  FD_TEST( expect( sd, b, 1UL, 90UL )==idx );
  FD_TEST( expect( sd, root, 1UL, 100UL )==idx );
  fd_stake_delegations_activate_fork( sd, f );
  update( sd, f, 1UL, 150UL );
  update( sd, f, 1UL, 160UL );
  FD_TEST( test_stake_delegations_record_cnt( sd, PAGE_DELTA )==3UL );
  fd_stake_delegations_finalize_fork( sd, f );
  fd_stake_history_t history = {0};
  fd_stake_delegations_delta_stats_t stats = {0};
  fd_stake_delegations_advance_root( sd, f, 2UL, &history, NULL, 1, 0, NULL, &stats );
  FD_TEST( stats.upserts==2UL && !stats.removes && stats.root_cnt==1UL );
  FD_TEST( test_stake_delegations_record_cnt( sd, PAGE_DELTA )==0UL );
  FD_TEST( sd->effective_stake==160UL );
  FD_TEST( expect( sd, f, 1UL, 160UL )==idx );
  ushort reused = fd_stake_delegations_attach_child( sd, f );
  update( sd, reused, 1UL, 170UL );
  fd_stake_delegations_cancel_fork( sd, reused );
  expect( sd, f, 1UL, 160UL );
}

static void
test_placeholder( fd_stake_delegations_t * sd ) {
  fd_stake_delegations_reset( sd );
  ushort root = fd_stake_delegations_root_fork_id( sd );
  root_update( sd, 2UL, 100UL );
  ulong idx = expect( sd, root, 2UL, 100UL );
  ushort a = fd_stake_delegations_attach_child( sd, root );
  fd_pubkey_t pubkey = key( 2UL );
  fd_stake_delegations_fork_remove( sd, a, &pubkey );
  fd_stake_delegations_finalize_fork( sd, a );
  ushort b = fd_stake_delegations_attach_child( sd, a );
  update( sd, b, 2UL, 150UL );
  fd_stake_history_t history = {0};
  fd_stake_delegations_advance_root( sd, a, 2UL, &history, NULL, 1, 0, NULL, NULL );
  expect( sd, a, 2UL, ULONG_MAX );
  FD_TEST( expect( sd, b, 2UL, 150UL )==idx );
  FD_TEST( sd->root_cnt==0UL && test_stake_delegations_record_cnt( sd, PAGE_ROOT )==sd->root_cnt+1UL );
  fd_stake_delegations_finalize_fork( sd, b );
  fd_stake_delegations_advance_root( sd, b, 3UL, &history, NULL, 1, 0, NULL, NULL );
  FD_TEST( expect( sd, b, 2UL, 150UL )==idx );
  FD_TEST( sd->root_cnt==1UL && test_stake_delegations_record_cnt( sd, PAGE_ROOT )==sd->root_cnt );
}

static void
test_model( fd_stake_delegations_t * sd ) {
  fd_stake_delegations_reset( sd );
  ulong model[ 3 ][ 300 ];
  for( ulong k=0UL; k<300UL; k++ ) { root_update( sd, k, k+10UL ); model[0][k] = k+10UL; }
  ushort root = fd_stake_delegations_root_fork_id( sd );
  ushort fork[2] = { fd_stake_delegations_attach_child( sd, root ), fd_stake_delegations_attach_child( sd, root ) };
  for( ulong f=0UL; f<2UL; f++ ) {
    memcpy( model[f+1UL], model[0], sizeof(model[0]) );
    for( ulong n=0UL; n<700UL; n++ ) {
      ulong k = (n*137UL + f*59UL)%300UL;
      if( n%5UL ) { model[f+1UL][k] = n+30UL; update( sd, fork[f], k, n+30UL ); }
      else { model[f+1UL][k] = ULONG_MAX; fd_pubkey_t p = key(k); fd_stake_delegations_fork_remove( sd, fork[f], &p ); }
    }
    fd_stake_delegations_finalize_fork( sd, fork[f] );
  }
  for( ulong f=0UL; f<3UL; f++ ) {
    fd_stake_delegations_view_t view[1];
    fd_stake_delegations_view_begin( view, sd, f ? fork[f-1UL] : root );
    uchar seen[300] = {0};
    ulong total = 0UL;
    fd_stake_delegations_iter_t iter[1];
    for( fd_stake_delegations_iter_init( iter, view ); !fd_stake_delegations_iter_done( iter ); fd_stake_delegations_iter_next( iter ) ) {
      fd_stake_delegation_t const * d = fd_stake_delegations_iter_ele( iter );
      ulong k = d->stake_account.ul[0];
      FD_TEST( k<300UL && !seen[k] );
      seen[k] = 1;
      FD_TEST( d->stake==model[f][k] );
      total += d->stake;
    }
    for( ulong k=0UL; k<300UL; k++ ) FD_TEST( seen[k]==(model[f][k]!=ULONG_MAX) );
    fd_stake_history_t history = {0};
    fd_stake_history_entry_t totals;
    fd_stake_delegations_view_totals( view, 10UL, &history, NULL, 1, &totals );
    FD_TEST( totals.effective==total && !totals.activating && !totals.deactivating );
    fd_stake_delegations_view_end( view );
  }
}

struct writer_args { fd_stake_delegations_t * sd; ushort fork; ulong start; };

static void *
writer( void * arg ) {
  struct writer_args * a = arg;
  for( ulong k=a->start; k<a->start+192UL; k++ ) {
    update( a->sd, a->fork, k, k+1000UL );
    update( a->sd, a->fork, k, k+2000UL );
  }
  return NULL;
}

static void
test_concurrent( fd_stake_delegations_t * sd ) {
  fd_stake_delegations_reset( sd );
  root_update( sd, 999UL, 77UL );
  ushort root = fd_stake_delegations_root_fork_id( sd );
  ushort f = fd_stake_delegations_attach_child( sd, root );
  fd_stake_delegations_activate_fork( sd, f );
  fd_stake_delegations_view_t view[1];
  fd_stake_delegations_view_begin( view, sd, root );
  struct writer_args args[2] = {{sd,f,0UL},{sd,f,192UL}};
  pthread_t threads[2];
  FD_TEST( !pthread_create( &threads[0], NULL, writer, &args[0] ) );
  FD_TEST( !pthread_create( &threads[1], NULL, writer, &args[1] ) );
  for( ulong pass=0UL; pass<20UL; pass++ ) {
    fd_stake_delegations_iter_t iter[1];
    fd_stake_delegations_iter_init( iter, view );
    FD_TEST( !fd_stake_delegations_iter_done( iter ) );
    FD_TEST( fd_stake_delegations_iter_ele( iter )->stake==77UL );
    fd_stake_delegations_iter_next( iter );
    FD_TEST( fd_stake_delegations_iter_done( iter ) );
  }
  FD_TEST( !pthread_join( threads[0], NULL ) );
  FD_TEST( !pthread_join( threads[1], NULL ) );
  fd_stake_delegations_view_end( view );
  FD_TEST( test_stake_delegations_record_cnt( sd, PAGE_DELTA )==384UL );
  fd_stake_delegations_finalize_fork( sd, f );
  fd_stake_history_t history = {0};
  fd_stake_delegations_advance_root( sd, f, 3UL, &history, NULL, 1, 0, NULL, NULL );
  FD_TEST( sd->root_cnt==385UL && !test_stake_delegations_record_cnt( sd, PAGE_DELTA ) );
  expect( sd, f, 192UL, 2192UL );
}

static void
test_context_and_prune( fd_stake_delegations_t * sd ) {
  fd_stake_delegations_reset( sd );
  fd_pubkey_t p = key( 10UL );
  fd_stake_delegations_root_update( sd, &p, &p, 100UL, 5UL, ULONG_MAX, 0UL, 110UL, 200U, 0 );
  ushort root = fd_stake_delegations_root_fork_id( sd );
  ushort a = fd_stake_delegations_attach_child( sd, root );
  fd_stake_delegations_finalize_fork( sd, a );
  fd_stake_history_t history = {0};
  fd_stake_delegations_advance_root( sd, a, 5UL, &history, NULL, 0, 0, NULL, NULL );
  FD_TEST( !sd->effective_stake && sd->activating_stake==100UL );
  ushort b = fd_stake_delegations_attach_child( sd, a );
  fd_stake_delegations_finalize_fork( sd, b );
  fd_stake_delegations_advance_root( sd, b, 6UL, &history, NULL, 0, 0, NULL, NULL );
  FD_TEST( sd->effective_stake==100UL && !sd->activating_stake && sd->fp_warmed_awarded );
  fd_stake_delegations_view_t view[1];
  fd_stake_delegations_view_begin( view, sd, b );
  view->use_stable_tags = 1;
  fd_stake_delegations_iter_t iter[1];
  fd_stake_delegations_iter_init( iter, view );
  FD_TEST( fd_stake_delegations_iter_ele( iter )->state==FD_STAKE_DELEGATION_STATE_WARMED );
  fd_stake_delegations_view_end( view );
  fd_stake_delegations_invalidate_warmed( sd );
  FD_TEST( !sd->fp_warmed_awarded );
  fd_stake_delegations_view_begin( view, sd, b );
  view->use_stable_tags = 1;
  fd_stake_delegations_iter_init( iter, view );
  FD_TEST( fd_stake_delegations_iter_ele( iter )->state==FD_STAKE_DELEGATION_STATE_UNKNOWN );
  fd_stake_delegations_view_end( view );

  /* A changed history at the same epoch changes the baseline totals. */
  fd_stake_history_entry_t entries[2] = {
    { .epoch=5UL, .effective=100UL, .activating=1000UL },
    { .epoch=3UL, .effective=100UL, .activating=1000UL }
  };
  history = (fd_stake_history_t){ .entries=entries, .len=2UL };
  ushort c = fd_stake_delegations_attach_child( sd, b );
  fd_stake_delegations_finalize_fork( sd, c );
  fd_stake_delegations_advance_root( sd, c, 6UL, &history, NULL, 1, 0, NULL, NULL );
  FD_TEST( sd->effective_stake==2UL && sd->activating_stake==98UL );
  entries[0].effective = 1000000UL; /* Store context must own a copy. */
  ushort d = fd_stake_delegations_attach_child( sd, c );
  fd_pubkey_t q = key( 11UL );
  fd_stake_delegations_fork_update( sd, d, &q, &q, 9UL, 5UL, 5UL, 0UL, 10UL, 200U, 0 );
  fd_stake_delegations_finalize_fork( sd, d );
  ushort e = fd_stake_delegations_attach_child( sd, d );
  update( sd, e, 11UL, 17UL );
  ulong idx = expect( sd, e, 11UL, 17UL );
  fd_stake_delegations_advance_root( sd, d, 7UL, &history, NULL, 1, 1, NULL, NULL );
  expect( sd, d, 11UL, ULONG_MAX );
  FD_TEST( expect( sd, e, 11UL, 17UL )==idx );
  FD_TEST( test_stake_delegations_record_cnt( sd, PAGE_ROOT )==sd->root_cnt+1UL );
  fd_stake_delegations_cancel_fork( sd, e );
  FD_TEST( test_stake_delegations_record_cnt( sd, PAGE_ROOT )==sd->root_cnt );
}

struct admission_args {
  fd_stake_delegations_t * sd;
  ushort fork;
  uint started;
  uint done;
};

static void *
cancel_writer( void * arg ) {
  struct admission_args * a = arg;
  __atomic_store_n( &a->started, 1U, __ATOMIC_RELEASE );
  fd_stake_delegations_cancel_fork( a->sd, a->fork );
  __atomic_store_n( &a->done, 1U, __ATOMIC_RELEASE );
  return NULL;
}

static void
test_writer_blocking( fd_stake_delegations_t * sd ) {
  fd_stake_delegations_reset( sd );
  for( ulong k=0UL; k<300UL; k++ ) root_update( sd, k, k+1UL );
  ushort root = fd_stake_delegations_root_fork_id( sd );
  ushort sibling = fd_stake_delegations_attach_child( sd, root );
  update( sd, sibling, 0UL, 55UL );
  fd_stake_delegations_view_t view[1];
  fd_stake_delegations_view_begin( view, sd, root );
  struct admission_args args = { .sd=sd, .fork=sibling };
  pthread_t thread;
  FD_TEST( !pthread_create( &thread, NULL, cancel_writer, &args ) );
  while( !__atomic_load_n( &args.started, __ATOMIC_ACQUIRE ) ) FD_SPIN_PAUSE();
  FD_TEST( !__atomic_load_n( &args.done, __ATOMIC_ACQUIRE ) );
  /* A tree writer blocked by this view must not hold the cache lock. */
  FD_TEST( test_stake_delegations_view_cnt( view )==300UL );
  fd_stake_delegations_view_end( view );
  FD_TEST( !pthread_join( thread, NULL ) );
  FD_TEST( __atomic_load_n( &args.done, __ATOMIC_ACQUIRE ) );
  FD_TEST( !test_stake_delegations_record_cnt( sd, PAGE_DELTA ) );
}

static void
test_refresh( fd_stake_delegations_t * sd ) {
  fd_stake_delegations_reset( sd );
  fd_pubkey_t preserved = key( 129UL );
  ulong collision;
  for( collision=1000UL;; collision++ ) {
    fd_pubkey_t candidate = key( collision );
    if( !((fd_hash32( candidate.uc, sd->seed ) ^ fd_hash32( preserved.uc, sd->seed )) & (FD_STAKE_DELEGATIONS_BUCKET_CNT-1UL)) ) break;
  }
  /* Both fit in a single accdb batch.  Removing the first must update
     the preserved root's link without later restoring the stale copy. */
  root_update( sd, collision, 1UL );
  root_update( sd, 129UL, 130UL );
  for( ulong k=0UL; k<260UL; k++ ) if( k!=129UL ) root_update( sd, k, k+1UL );
  test_accdb_t db = test_accdb_new();
  fd_accdb_fork_id_t fork = fd_accdb_attach_child( db.accdb, (fd_accdb_fork_id_t){ .val=USHORT_MAX } );
  fd_stake_state_t state = {
    .stake_type = FD_STAKE_STATE_STAKE,
    .stake = { .stake = { .delegation = {
      .stake=101UL, .activation_epoch=ULONG_MAX, .deactivation_epoch=ULONG_MAX,
      .warmup_cooldown_rate=FD_STAKE_DELEGATIONS_WARMUP_COOLDOWN_RATE_025
    } } }
  };
  fd_pubkey_t p = key( 129UL );
  test_accdb_write_stake( db.accdb, fork, &p, &state );
  state.stake.stake.delegation.activation_epoch = 2UL;
  state.stake.stake.delegation.deactivation_epoch = 2UL;
  fd_pubkey_t q = key( 259UL );
  test_accdb_write_stake( db.accdb, fork, &q, &state );
  fd_stake_history_t history = {0};
  fd_stake_delegations_refresh( sd, 4UL, &history, NULL, 1, 1, db.accdb, fork );
  FD_TEST( sd->root_cnt==1UL && sd->effective_stake==101UL );
  expect( sd, fd_stake_delegations_root_fork_id( sd ), 129UL, 101UL );
  expect( sd, fd_stake_delegations_root_fork_id( sd ), 259UL, ULONG_MAX );
  test_accdb_delete( &db );
  ushort child = fd_stake_delegations_attach_child( sd, fd_stake_delegations_root_fork_id( sd ) );
  update( sd, child, collision, 55UL );
  expect( sd, child, collision, 55UL );
  fd_stake_delegations_cancel_fork( sd, child );
  FD_TEST( sd->root_cnt==1UL && test_stake_delegations_record_cnt( sd, PAGE_ROOT )==sd->root_cnt );
}

/* Three hundred siblings exceed the iterator's cache-lock traversal
   chunk.  Check both root fallback and an oldest selected version, then
   repeat after a tombstone and another key which is absent in the root. */
static void
test_long_chain( fd_stake_delegations_t * sd ) {
  fd_stake_delegations_reset( sd );
  root_update( sd, 1UL, 100UL );
  root_update( sd, 2UL, 200UL );
  ushort root = fd_stake_delegations_root_fork_id( sd );
  ushort forks[300];
  for( ulong i=0UL; i<300UL; i++ ) {
    forks[i] = fd_stake_delegations_attach_child( sd, root );
    update( sd, forks[i], 1UL, 1000UL+i );
    update( sd, forks[i], 3UL, 3000UL+i );
    if( !i ) {
      fd_pubkey_t p = key( 2UL );
      fd_stake_delegations_fork_remove( sd, forks[i], &p );
    } else update( sd, forks[i], 2UL, 2000UL+i );
    fd_stake_delegations_finalize_fork( sd, forks[i] );
  }
  FD_TEST( sd->root_cnt==2UL );
  FD_TEST( test_stake_delegations_record_cnt( sd, PAGE_ROOT )==3UL );
  FD_TEST( test_stake_delegations_record_cnt( sd, PAGE_DELTA )==900UL );
  ulong idx = expect( sd, root, 1UL, 100UL );
  expect( sd, root, 2UL, 200UL );
  expect( sd, root, 3UL, ULONG_MAX );
  FD_TEST( expect( sd, forks[0], 1UL, 1000UL )==idx );
  expect( sd, forks[0], 2UL, ULONG_MAX );
  expect( sd, forks[0], 3UL, 3000UL );
  if( sd->frame_max<=4U ) FD_TEST( test_stake_delegations_page_cnt( sd, 0 )>sd->frame_max );
  fd_stake_history_t history = {0};
  fd_stake_delegations_advance_root( sd, forks[0], 4UL, &history, NULL, 1, 0, NULL, NULL );
  FD_TEST( expect( sd, forks[0], 1UL, 1000UL )==idx );
  expect( sd, forks[0], 2UL, ULONG_MAX );
  expect( sd, forks[0], 3UL, 3000UL );
  FD_TEST( sd->root_cnt==2UL && test_stake_delegations_record_cnt( sd, PAGE_ROOT )==sd->root_cnt && !test_stake_delegations_record_cnt( sd, PAGE_DELTA ) && test_stake_delegations_fork_cnt( sd )==1UL );
}

struct sibling_writer_args {
  fd_stake_delegations_t * sd;
  pthread_barrier_t *      barrier;
  ushort                  fork;
  ulong                   stake;
};

static void *
sibling_writer( void * arg ) {
  struct sibling_writer_args * a = arg;
  for( ulong k=0UL; k<192UL; k++ ) {
    int err = pthread_barrier_wait( a->barrier );
    FD_TEST( !err || err==PTHREAD_BARRIER_SERIAL_THREAD );
    update( a->sd, a->fork, k, a->stake+k );
    fd_pubkey_t p = key( k );
    fd_stake_delegations_fork_remove( a->sd, a->fork, &p );
    update( a->sd, a->fork, k, a->stake+k+1UL );
  }
  return NULL;
}

static void
test_same_key_siblings( fd_stake_delegations_t * sd ) {
  fd_stake_delegations_reset( sd );
  root_update( sd, 999UL, 77UL );
  ushort root = fd_stake_delegations_root_fork_id( sd );
  ushort selected = fd_stake_delegations_attach_child( sd, root );
  ushort forks[2] = { fd_stake_delegations_attach_child( sd, root ), fd_stake_delegations_attach_child( sd, root ) };
  fd_stake_delegations_activate_fork( sd, forks[0] );
  fd_stake_delegations_activate_fork( sd, forks[1] );
  pthread_barrier_t barrier;
  FD_TEST( !pthread_barrier_init( &barrier, NULL, 2U ) );
  struct sibling_writer_args args[2] = {
    { .sd=sd, .barrier=&barrier, .fork=forks[0], .stake=1000UL },
    { .sd=sd, .barrier=&barrier, .fork=forks[1], .stake=2000UL }
  };
  fd_stake_delegations_view_t view[1];
  fd_stake_delegations_view_begin( view, sd, selected );
  pthread_t threads[2];
  FD_TEST( !pthread_create( threads,     NULL, sibling_writer, args     ) );
  FD_TEST( !pthread_create( threads+1,   NULL, sibling_writer, args+1   ) );
  for( ulong pass=0UL; pass<20UL; pass++ ) {
    fd_stake_delegations_iter_t iter[1];
    fd_stake_delegations_iter_init( iter, view );
    FD_TEST( !fd_stake_delegations_iter_done( iter ) );
    FD_TEST( fd_stake_delegations_iter_ele( iter )->stake_account.ul[0]==999UL );
    FD_TEST( fd_stake_delegations_iter_ele( iter )->stake==77UL );
    fd_stake_delegations_iter_next( iter );
    FD_TEST( fd_stake_delegations_iter_done( iter ) );
  }
  FD_TEST( !pthread_join( threads[0], NULL ) );
  FD_TEST( !pthread_join( threads[1], NULL ) );
  FD_TEST( !pthread_barrier_destroy( &barrier ) );
  fd_stake_delegations_view_end( view );
  FD_TEST( sd->root_cnt==1UL );
  FD_TEST( test_stake_delegations_record_cnt( sd, PAGE_ROOT )==193UL );
  FD_TEST( test_stake_delegations_record_cnt( sd, PAGE_DELTA )==384UL );
  ulong indices[192];
  for( ulong f=0UL; f<2UL; f++ ) {
    fd_stake_delegations_finalize_fork( sd, forks[f] );
    fd_stake_delegations_view_begin( view, sd, forks[f] );
    uchar seen[192] = {0};
    ulong count = 0UL;
    fd_stake_delegations_iter_t iter[1];
    for( fd_stake_delegations_iter_init( iter, view ); !fd_stake_delegations_iter_done( iter ); fd_stake_delegations_iter_next( iter ) ) {
      fd_stake_delegation_t const * d = fd_stake_delegations_iter_ele( iter );
      ulong k = d->stake_account.ul[0];
      if( k==999UL ) { FD_TEST( d->stake==77UL ); continue; }
      FD_TEST( k<192UL && !seen[k] );
      seen[k] = 1;
      FD_TEST( d->stake==args[f].stake+k+1UL );
      if( !f ) indices[k] = fd_stake_delegations_iter_idx( iter );
      else FD_TEST( indices[k]==fd_stake_delegations_iter_idx( iter ) );
      count++;
    }
    FD_TEST( count==192UL );
    fd_stake_delegations_view_end( view );
  }
  fd_stake_delegations_cancel_fork( sd, forks[0] );
  FD_TEST( expect( sd, forks[1], 0UL, 2001UL )==indices[0] );
  fd_stake_delegations_cancel_fork( sd, forks[1] );
  FD_TEST( sd->root_cnt==1UL && test_stake_delegations_record_cnt( sd, PAGE_ROOT )==sd->root_cnt && !test_stake_delegations_record_cnt( sd, PAGE_DELTA ) );
}

static void
test_fork_reuse( fd_stake_delegations_t * sd ) {
  fd_stake_delegations_reset( sd );
  root_update( sd, 1UL, 100UL );
  ushort root = fd_stake_delegations_root_fork_id( sd );
  ushort a = fd_stake_delegations_attach_child( sd, root );
  update( sd, a, 1UL, 200UL );
  update( sd, a, 2UL, 300UL );
  fd_stake_delegations_finalize_fork( sd, a );
  ushort b = fd_stake_delegations_attach_child( sd, a );
  update( sd, b, 1UL, 400UL );
  update( sd, b, 2UL, 500UL );
  fd_stake_delegations_cancel_fork( sd, a );
  FD_TEST( test_stake_delegations_fork_cnt( sd )==1UL && !test_stake_delegations_record_cnt( sd, PAGE_DELTA ) && test_stake_delegations_record_cnt( sd, PAGE_ROOT )==sd->root_cnt );
  ushort reused_a = fd_stake_delegations_attach_child( sd, root );
  FD_TEST( reused_a==a );
  expect( sd, reused_a, 1UL, 100UL );
  expect( sd, reused_a, 2UL, ULONG_MAX );
  fd_stake_delegations_finalize_fork( sd, reused_a );
  ushort reused_b = fd_stake_delegations_attach_child( sd, reused_a );
  FD_TEST( reused_b==b );
  expect( sd, reused_b, 1UL, 100UL );
  expect( sd, reused_b, 2UL, ULONG_MAX );
  update( sd, reused_b, 2UL, 600UL );
  fd_stake_delegations_finalize_fork( sd, reused_b );
  fd_stake_history_t history = {0};
  fd_stake_delegations_advance_root( sd, reused_b, 7UL, &history, NULL, 1, 0, NULL, NULL );
  expect( sd, reused_b, 1UL, 100UL );
  expect( sd, reused_b, 2UL, 600UL );
  FD_TEST( sd->root_cnt==2UL && sd->effective_stake==700UL );
}

#define FAIL_UPDATE          (0)
#define FAIL_ATTACH          (1)
#define FAIL_VIEW            (2)
#define FAIL_ROOT_CAPACITY   (3)
#define FAIL_TRUNCATED_PAGE  (4)

/* Isolate fatal contracts in a fork, with a bounded wait and diagnostic
   capture so a crash, assertion in setup, or successful return cannot
   masquerade as the expected rejection. */
static void
test_failure( fd_stake_delegations_t * sd, ushort fork_id, int action, char const * reason ) {
  int fds[2];
  FD_TEST( !pipe( fds ) );
  pid_t pid = fork();
  FD_TEST( pid>=0 );
  if( !pid ) {
    FD_TEST( !close( fds[0] ) );
    FD_TEST( dup2( fds[1], STDERR_FILENO )==STDERR_FILENO );
    FD_TEST( !close( fds[1] ) );
    fd_log_level_core_set( 8 );
    alarm( 10U );
    switch( action ) {
      case FAIL_UPDATE: update( sd, fork_id, 1UL, 200UL ); break;
      case FAIL_ATTACH: fd_stake_delegations_attach_child( sd, fork_id ); break;
      case FAIL_VIEW: {
        fd_stake_delegations_view_t view[1];
        fd_stake_delegations_view_begin( view, sd, fork_id );
        fd_stake_delegations_view_end( view );
        break;
      }
      case FAIL_ROOT_CAPACITY: root_update( sd, 10000UL, 1UL ); break;
      case FAIL_TRUNCATED_PAGE: {
        FD_TEST( !ftruncate( sd->disk_fd, 0L ) );
        fd_stake_delegations_view_t view[1];
        fd_stake_delegations_view_begin( view, sd, fork_id );
        fd_stake_delegations_iter_t iter[1];
        fd_stake_delegations_iter_init( iter, view );
        fd_stake_delegations_view_end( view );
        break;
      }
      default: _exit( 2 );
    }
    _exit( 0 );
  }
  FD_TEST( !close( fds[1] ) );
  char diagnostic[4096];
  ulong used = 0UL;
  for(;;) {
    long n = read( fds[0], diagnostic+used, sizeof(diagnostic)-1UL-used );
    if( n<0L && errno==EINTR ) continue;
    FD_TEST( n>=0L );
    if( !n ) break;
    used += (ulong)n;
    FD_TEST( used<sizeof(diagnostic)-1UL );
  }
  diagnostic[used] = '\0';
  FD_TEST( !close( fds[0] ) );
  int status;
  pid_t waited;
  do waited = waitpid( pid, &status, 0 ); while( waited<0 && errno==EINTR );
  FD_TEST( waited==pid && WIFEXITED( status ) && WEXITSTATUS( status )==1 );
  FD_TEST( strstr( diagnostic, reason ) );
}

static void
test_lifecycle_failures( fd_stake_delegations_t * sd ) {
  fd_stake_delegations_reset( sd );
  ushort root = fd_stake_delegations_root_fork_id( sd );
  ushort child = fd_stake_delegations_attach_child( sd, root );
  test_failure( sd, child, FAIL_ATTACH, "parent is not immutable" );
  fd_stake_delegations_view_t view[1];
  fd_stake_delegations_view_begin( view, sd, child );
  test_failure( sd, child, FAIL_UPDATE, "write to viewed fork" );
  fd_stake_delegations_view_end( view );
  fd_stake_delegations_activate_fork( sd, child );
  test_failure( sd, child, FAIL_VIEW, "fork is not viewable" );
  fd_stake_delegations_finalize_fork( sd, child );
  test_failure( sd, child, FAIL_UPDATE, "fork is not mutable" );
  fd_stake_delegations_cancel_fork( sd, child );
  test_failure( sd, child, FAIL_UPDATE, "fork is not mutable" );
}

static void
test_capacity_and_eof( int direct_fd ) {
  ulong footprint = fd_stake_delegations_footprint( 256UL, 4UL, FD_STAKE_DELEGATIONS_PAGE_SZ );
  void * mem = aligned_alloc( fd_stake_delegations_align(), footprint );
  FD_TEST( mem );
  fd_stake_delegations_t * sd = fd_stake_delegations_join(
      fd_stake_delegations_new( mem, direct_fd, 123UL, 128UL, 4UL, FD_STAKE_DELEGATIONS_PAGE_SZ ), direct_fd );
  FD_TEST( sd );
  for( ulong k=0UL; k<128UL; k++ ) root_update( sd, k, k+1UL );
  test_failure( sd, 0, FAIL_ROOT_CAPACITY, "logical page capacity exhausted" );
  FD_TEST( test_stake_delegations_base_cnt( sd )==128UL );
  fd_stake_delegations_reset( sd );
  ushort root = fd_stake_delegations_root_fork_id( sd );
  for( ulong i=0UL; i<3UL; i++ ) fd_stake_delegations_attach_child( sd, root );
  test_failure( sd, root, FAIL_ATTACH, "fork capacity exhausted" );

  sd = fd_stake_delegations_join(
      fd_stake_delegations_new( mem, direct_fd, 123UL, 256UL, 4UL, FD_STAKE_DELEGATIONS_PAGE_SZ ), direct_fd );
  FD_TEST( sd );
  for( ulong k=0UL; k<129UL; k++ ) root_update( sd, k, k+1UL );
  /* Reading both pages leaves the sole frame clean.  Truncation must
     reach EOF on the next fault, without a dirty eviction growing the
     file first and supplying a zero-filled sparse page instead. */
  FD_TEST( test_stake_delegations_base_cnt( sd )==129UL );
  FD_TEST( test_stake_delegations_page_cnt( sd, 1 )==1UL );
  FD_TEST( test_stake_delegations_page_cnt( sd, 0 )==2UL );
  FD_TEST( test_stake_delegations_file_sz( sd )>=2UL*FD_STAKE_DELEGATIONS_PAGE_SZ );
  test_failure( sd, fd_stake_delegations_root_fork_id( sd ), FAIL_TRUNCATED_PAGE, "read made no progress" );
  free( mem );
}

#if FD_HAS_RACESAN

#define RACESAN_STACK_SZ (1UL<<20)
#define RACESAN_SEED_CNT (100UL)
#define RACESAN_STEP_MAX (32768UL)

struct racesan_writer_args {
  fd_stake_delegations_t * sd;
  ushort                  fork;
  ulong                   key;
  ulong                   stake;
};

struct racesan_view_args {
  fd_stake_delegations_t * sd;
  ushort                  fork;
  ushort                  cancel_fork;
  uint                    ready;
  uint                    writer_started;
  uint                    done;
  uint                    canceled;
  int                     coordinate_writer;
  ulong                   count;
  ulong                   total;
};

static void
racesan_writer( void * arg ) {
  struct racesan_writer_args * a = arg;
  update( a->sd, a->fork, a->key, a->stake );
  fd_pubkey_t p = key( a->key );
  fd_stake_delegations_fork_remove( a->sd, a->fork, &p );
  update( a->sd, a->fork, a->key, a->stake+1UL );
}

static void
racesan_view( void * arg ) {
  struct racesan_view_args * a = arg;
  fd_stake_delegations_view_t view[1];
  fd_stake_delegations_view_begin( view, a->sd, a->fork );
  __atomic_store_n( &a->ready, 1U, __ATOMIC_RELEASE );
  if( a->coordinate_writer ) {
    while( !__atomic_load_n( &a->writer_started, __ATOMIC_ACQUIRE ) ) {
      fd_racesan_hook( "stake_delegations_test:wait_writer" );
    }
    FD_TEST( !__atomic_load_n( &a->canceled, __ATOMIC_ACQUIRE ) );
  }
  if( a->coordinate_writer ) FD_TEST( test_stake_delegations_page_cnt( a->sd, 0 )>a->sd->frame_max );
  for( ulong pass=0UL; pass<2UL; pass++ ) {
    ulong count = 0UL;
    ulong total = 0UL;
    fd_stake_delegations_iter_t iter[1];
    for( fd_stake_delegations_iter_init( iter, view ); !fd_stake_delegations_iter_done( iter ); fd_stake_delegations_iter_next( iter ) ) {
      count++;
      total += fd_stake_delegations_iter_ele( iter )->stake;
    }
    FD_TEST( count==a->count && total==a->total );
  }
  fd_stake_delegations_view_end( view );
  __atomic_store_n( &a->done, 1U, __ATOMIC_RELEASE );
}

static void
racesan_cancel( void * arg ) {
  struct racesan_view_args * a = arg;
  while( !__atomic_load_n( &a->ready, __ATOMIC_ACQUIRE ) ) {
    fd_racesan_hook( "stake_delegations_test:wait_view" );
  }
  __atomic_store_n( &a->writer_started, 1U, __ATOMIC_RELEASE );
  fd_stake_delegations_cancel_fork( a->sd, a->cancel_fork );
  FD_TEST( __atomic_load_n( &a->done, __ATOMIC_ACQUIRE ) );
  __atomic_store_n( &a->canceled, 1U, __ATOMIC_RELEASE );
}

static void
test_racesan_writers( fd_stake_delegations_t * sd,
                       void **                   stacks ) {
  fd_racesan_async_t async[3];
  for( ulong mode=0UL; mode<3UL; mode++ ) {
    for( ulong seed=0UL; seed<RACESAN_SEED_CNT; seed++ ) {
      fd_stake_delegations_reset( sd );
      root_update( sd, 999UL, 77UL );
      ushort root     = fd_stake_delegations_root_fork_id( sd );
      ushort selected = fd_stake_delegations_attach_child( sd, root );
      ushort a        = fd_stake_delegations_attach_child( sd, root );
      ushort b        = mode==2UL ? fd_stake_delegations_attach_child( sd, root ) : a;
      fd_stake_delegations_activate_fork( sd, a );
      if( b!=a ) fd_stake_delegations_activate_fork( sd, b );
      /* Initialize resident allocator pages before racing their unused
         slots; the one-frame run exercises the same calls cold. */
      update( sd, a, 998UL, 11UL );
      struct racesan_writer_args writers[2] = {
        { .sd=sd, .fork=a, .key=1UL,                   .stake=100UL },
        { .sd=sd, .fork=b, .key=mode==1UL ? 2UL : 1UL, .stake=200UL }
      };
      struct racesan_view_args reader = { .sd=sd, .fork=selected, .count=1UL, .total=77UL };
      fd_racesan_weave_t weave[1];
      fd_racesan_weave_new( weave );
      fd_racesan_async_new( async,   stacks[0], RACESAN_STACK_SZ, racesan_writer, writers   );
      fd_racesan_async_new( async+1, stacks[1], RACESAN_STACK_SZ, racesan_writer, writers+1 );
      fd_racesan_async_new( async+2, stacks[2], RACESAN_STACK_SZ, racesan_view,   &reader   );
      for( ulong i=0UL; i<3UL; i++ ) fd_racesan_weave_add( weave, async+i );
      fd_racesan_weave_exec_rand( weave, seed, RACESAN_STEP_MAX );
      FD_TEST( !weave->rem_cnt && reader.done );
      FD_TEST( sd->root_cnt==1UL && test_stake_delegations_record_cnt( sd, PAGE_ROOT )==sd->root_cnt+(mode==1UL ? 3UL : 2UL) );
      FD_TEST( test_stake_delegations_record_cnt( sd, PAGE_DELTA )==(mode==0UL ? 2UL : 3UL) );
      fd_stake_delegations_finalize_fork( sd, a );
      if( b!=a ) fd_stake_delegations_finalize_fork( sd, b );
      if( !mode ) {
        fd_stake_delegations_view_t view[1];
        fd_stake_delegations_view_begin( view, sd, a );
        fd_stake_delegation_t d;
        fd_pubkey_t p = key( 1UL );
        FD_TEST( test_stake_delegations_view_find_copy( view, &p, &d ) );
        FD_TEST( d.stake==101UL || d.stake==201UL );
        fd_stake_delegations_view_end( view );
      } else {
        expect( sd, a, 1UL, 101UL );
        expect( sd, b, writers[1].key, 201UL );
      }
      for( ulong i=0UL; i<3UL; i++ ) fd_racesan_async_delete( async+i );
      fd_racesan_weave_delete( weave );
    }
  }
}

static void
test_racesan_admission( fd_stake_delegations_t * sd,
                         void **                   stacks ) {
  fd_racesan_async_t async[2];
  for( ulong seed=0UL; seed<RACESAN_SEED_CNT; seed++ ) {
    fd_stake_delegations_reset( sd );
    for( ulong k=0UL; k<129UL; k++ ) root_update( sd, k, k+1UL );
    ushort root    = fd_stake_delegations_root_fork_id( sd );
    ushort sibling = fd_stake_delegations_attach_child( sd, root );
    update( sd, sibling, 0UL, 200UL );
    struct racesan_view_args reader = {
      .sd                = sd,
      .fork              = root,
      .cancel_fork       = sibling,
      .coordinate_writer = 1,
      .count             = 129UL,
      .total             = 8385UL
    };
    fd_racesan_weave_t weave[1];
    fd_racesan_weave_new( weave );
    fd_racesan_async_new( async,   stacks[0], RACESAN_STACK_SZ, racesan_view,   &reader );
    fd_racesan_async_new( async+1, stacks[1], RACESAN_STACK_SZ, racesan_cancel, &reader );
    fd_racesan_weave_add( weave, async   );
    fd_racesan_weave_add( weave, async+1 );
    fd_racesan_weave_exec_rand( weave, seed, RACESAN_STEP_MAX );
    FD_TEST( !weave->rem_cnt && reader.done && reader.canceled );
    FD_TEST( !test_stake_delegations_record_cnt( sd, PAGE_DELTA ) && sd->root_cnt==129UL && test_stake_delegations_fork_cnt( sd )==1UL );
    fd_racesan_async_delete( async+1 );
    fd_racesan_async_delete( async   );
    fd_racesan_weave_delete( weave );
  }
}

static void
test_racesan( fd_stake_delegations_t * sd ) {
  void * stacks[3];
  for( ulong i=0UL; i<3UL; i++ ) stacks[i] = fd_racesan_stack_create( RACESAN_STACK_SZ );

  /* Prove the instrumented path actually enters an async context and
     suspends at a store-owned admission hook.  Enabling hooks alone
     would allow ordinary pthread tests to pass without any weaving. */
  fd_stake_delegations_reset( sd );
  root_update( sd, 999UL, 77UL );
  struct racesan_view_args reader = { .sd=sd, .fork=fd_stake_delegations_root_fork_id( sd ), .count=1UL, .total=77UL };
  fd_racesan_async_t async[1];
  fd_racesan_async_new( async, stacks[0], RACESAN_STACK_SZ, racesan_view, &reader );
  FD_TEST( fd_racesan_async_step_until( async, "stake_delegations_view:admitted", RACESAN_STEP_MAX )==FD_RACESAN_ASYNC_RET_HOOK );
  ulong step = 0UL;
  while( !async->done && step++<RACESAN_STEP_MAX ) fd_racesan_async_step( async );
  FD_TEST( async->done && reader.done );
  fd_racesan_async_delete( async );

  test_racesan_writers( sd, stacks );
  if( sd->frame_max==1U ) test_racesan_admission( sd, stacks );
  for( ulong i=0UL; i<3UL; i++ ) fd_racesan_stack_destroy( stacks[i], RACESAN_STACK_SZ );
  FD_LOG_NOTICE(( "racesan: 100 seeds per writer schedule, %u frame(s), bounded to %lu steps",
                  sd->frame_max, RACESAN_STEP_MAX ));
}

#endif /* FD_HAS_RACESAN */

int
main( int argc, char ** argv ) {
  fd_boot( &argc, &argv );
  FD_TEST( sizeof(fd_stake_delegation_t)==128UL );
  for( ulong frames=1UL; frames<=16UL; frames*=2UL ) {
    char path[] = "/tmp/stake-delegations-XXXXXX";
    int fd = mkstemp( path );
    FD_TEST( fd>=0 );
    int direct_fd = open( path, O_RDWR|O_DIRECT );
    FD_TEST( direct_fd>=0 );
    FD_TEST( !close( fd ) );
    FD_TEST( !unlink( path ) );
    ulong footprint = fd_stake_delegations_footprint( 8192UL, 512UL, frames*16384UL );
    FD_TEST( footprint );
    void * mem = aligned_alloc( fd_stake_delegations_align(), footprint );
    FD_TEST( mem );
    fd_stake_delegations_t * sd = fd_stake_delegations_join( fd_stake_delegations_new( mem, direct_fd, 123UL, 8192UL, 512UL, frames*16384UL ), direct_fd );
    FD_TEST( sd );
#if FD_HAS_RACESAN
    if( frames==1UL || frames==4UL ) test_racesan( sd );
#endif
    test_visibility( sd );
    test_placeholder( sd );
    test_model( sd );
    if( frames==16UL ) FD_TEST( !test_stake_delegations_file_sz( sd ) );
    else if( frames<=4UL ) FD_TEST( test_stake_delegations_file_sz( sd ) );
    test_concurrent( sd );
    test_context_and_prune( sd );
    test_writer_blocking( sd );
    test_refresh( sd );
    test_long_chain( sd );
    test_same_key_siblings( sd );
    test_fork_reuse( sd );
    if( frames==1UL ) {
      test_lifecycle_failures( sd );
      test_capacity_and_eof( direct_fd );
    }
    fd_stake_delegations_reset( sd );
    FD_TEST( !sd->root_cnt && !test_stake_delegations_record_cnt( sd, PAGE_DELTA ) && !test_stake_delegations_page_cnt( sd, 0 ) );
    free( mem );
    FD_TEST( !close( direct_fd ) );
    FD_LOG_NOTICE(( "passed with %lu frame(s)", frames ));
  }
  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
