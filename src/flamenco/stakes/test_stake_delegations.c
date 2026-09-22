#define _GNU_SOURCE
#include "test_stake_delegations_util.h"
#include "fd_stakes.h"
#include "../../util/fd_hash32.h"
#include "../runtime/fd_system_ids.h"
#include "../runtime/sysvar/fd_sysvar_stake_history.h"

#include <fcntl.h>
#include <pthread.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

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
  FD_TEST( sd->delta_cnt==3UL );
  fd_stake_delegations_finalize_fork( sd, f );
  fd_stake_history_t history = {0};
  fd_stake_delegations_delta_stats_t stats = {0};
  fd_stake_delegations_advance_root( sd, f, 2UL, &history, NULL, 1, 0, NULL, &stats );
  FD_TEST( stats.upserts==2UL && !stats.removes && stats.root_cnt==1UL );
  FD_TEST( sd->delta_cnt==0UL );
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
  FD_TEST( sd->root_cnt==0UL && sd->placeholder_cnt==1UL );
  fd_stake_delegations_finalize_fork( sd, b );
  fd_stake_delegations_advance_root( sd, b, 3UL, &history, NULL, 1, 0, NULL, NULL );
  FD_TEST( expect( sd, b, 2UL, 150UL )==idx );
  FD_TEST( sd->root_cnt==1UL && !sd->placeholder_cnt );
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
  FD_TEST( sd->delta_cnt==384UL );
  fd_stake_delegations_finalize_fork( sd, f );
  fd_stake_history_t history = {0};
  fd_stake_delegations_advance_root( sd, f, 3UL, &history, NULL, 1, 0, NULL, NULL );
  FD_TEST( sd->root_cnt==385UL && !sd->delta_cnt );
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
  FD_TEST( sd->placeholder_cnt==1UL );
  fd_stake_delegations_cancel_fork( sd, e );
  FD_TEST( !sd->placeholder_cnt );
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
test_writer_admission( fd_stake_delegations_t * sd ) {
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
  while( !__atomic_load_n( &sd->tree_lock.waiting, __ATOMIC_SEQ_CST ) ) FD_SPIN_PAUSE();
  FD_TEST( !__atomic_load_n( &args.done, __ATOMIC_ACQUIRE ) );
  /* A waiting tree writer must not gate cache admission by this view. */
  FD_TEST( test_stake_delegations_view_cnt( view )==300UL );
  fd_stake_delegations_view_end( view );
  FD_TEST( !pthread_join( thread, NULL ) );
  FD_TEST( __atomic_load_n( &args.done, __ATOMIC_ACQUIRE ) );
  FD_TEST( !sd->delta_cnt );
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
  FD_TEST( sd->root_cnt==1UL && !sd->placeholder_cnt );
}

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
    ulong footprint = fd_stake_delegations_footprint( 8192UL, 32UL, frames*16384UL );
    FD_TEST( footprint );
    void * mem = aligned_alloc( fd_stake_delegations_align(), footprint );
    FD_TEST( mem );
    fd_stake_delegations_t * sd = fd_stake_delegations_join( fd_stake_delegations_new( mem, direct_fd, 123UL, 8192UL, 32UL, frames*16384UL ), direct_fd );
    FD_TEST( sd );
    test_visibility( sd );
    test_placeholder( sd );
    test_model( sd );
    if( frames==16UL ) FD_TEST( !sd->bytes_read && !sd->bytes_written );
    else if( frames<=4UL ) FD_TEST( sd->bytes_read && sd->bytes_written );
    test_concurrent( sd );
    test_context_and_prune( sd );
    test_writer_admission( sd );
    test_refresh( sd );
    fd_stake_delegations_reset( sd );
    FD_TEST( !sd->root_cnt && !sd->delta_cnt && !sd->occupied_pages );
    free( mem );
    FD_TEST( !close( direct_fd ) );
    FD_LOG_NOTICE(( "passed with %lu frame(s)", frames ));
  }
  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
