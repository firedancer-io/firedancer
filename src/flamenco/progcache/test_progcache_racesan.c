#include "fd_progcache_admin.h"
#include "fd_progcache_user.h"
#include "fd_progcache_reclaim.h"
#include "fd_progcache_clock.h"
#include "test_progcache_common.c"
#include "fd_prog_load.h"
#include "../runtime/fd_system_ids.h"
#include "../features/fd_features.h"
#include "../../util/racesan/fd_racesan_async.h"
#include "../../util/racesan/fd_racesan_weave.h"
#include "../../util/tmpl/fd_unit_test.c"

FD_IMPORT_BINARY( valid_program_data,   "src/ballet/sbpf/fixtures/hello_solana_program.so" );
FD_IMPORT_BINARY( invalid_program_data, "src/ballet/sbpf/fixtures/malformed_bytecode.so"   );


static fd_wksp_t *   wksp;
static fd_features_t g_features[1];

#define FIBER_MAX       (4)
#define FIBER_STACK_MAX (1UL<<21)
#define ITER_DEFAULT    (4096UL)
#define STEP_MAX        (100000UL)

/* Declare fibers */

struct fiber {

  fd_racesan_async_t async[1];

  fd_progcache_t cache[1];

  uchar scratch[ FD_PROGCACHE_SCRATCH_FOOTPRINT ] __attribute__((aligned(FD_PROGCACHE_SCRATCH_ALIGN)));

  uchar stack[ FIBER_STACK_MAX ] __attribute__((aligned(64)));

  union {

    struct {
      fd_progcache_t *       cache;
      fd_progcache_fork_id_t fork_id;
      fd_pubkey_t            prog_addr;
      fd_prog_load_env_t     load_env;
      fd_acc_t const *        prog_ro;
      fd_progcache_rec_t *   res;
      ulong                  res_data_gaddr;
    } pull;

    struct {
      fd_progcache_t *       cache;
      fd_progcache_fork_id_t fork_id;
      fd_pubkey_t            prog_addr;
      ulong                  feature_slot;
      ulong                  deploy_slot;
    } peek;

    struct {
      fd_progcache_t * cache;
      ulong            sz;
    } evict;

    struct {
      fd_progcache_join_t *  cache;
      fd_progcache_fork_id_t fork_id;
    } advance_root;

    struct {
      fd_progcache_join_t *  cache;
      fd_progcache_fork_id_t fork_id;
    } cancel;

    struct {
      fd_progcache_join_t * cache;
      fd_progcache_rec_t * rec;
      long                 result;
    } delete_rec;

  };

};
typedef struct fiber fiber_t;

static fiber_t g_fiber[ FIBER_MAX ];

static void
fiber_delete( fiber_t * fiber ) {
  fd_racesan_async_delete( fiber->async );
  fd_progcache_leave( fiber->cache, NULL );
}

static void
fiber_pull_exec( void * _ctx ) {
  fiber_t * f = _ctx;
  fd_progcache_rec_t * res = fd_progcache_pull(
      f->pull.cache, f->pull.fork_id, &f->pull.prog_addr, &f->pull.load_env, f->pull.prog_ro );
  FD_TEST( res ); /* the program is deployed, so pull must produce it */
  f->pull.res            = res;
  f->pull.res_data_gaddr = res->data_gaddr;
  fd_progcache_rec_close( f->pull.cache, res );
}

static fd_racesan_async_t *
fiber_pull( fiber_t *                  fiber,
            void *                     shmem,
            fd_progcache_fork_id_t     fork_id,
            void const *               prog_addr,
            fd_prog_load_env_t const * load_env,
            fd_acc_t const *            prog_ro ) {
  FD_TEST( fd_progcache_join( fiber->cache, shmem, fiber->scratch, sizeof(fiber->scratch) ) );
  fiber->pull.cache     = fiber->cache;
  fiber->pull.fork_id   = fork_id;
  fiber->pull.prog_addr = FD_LOAD( fd_pubkey_t, prog_addr );
  fiber->pull.load_env  = *load_env;
  fiber->pull.prog_ro   = prog_ro;
  fd_racesan_async_new( fiber->async, fiber->stack+FIBER_STACK_MAX, FIBER_STACK_MAX, fiber_pull_exec, fiber );
  return fiber->async;
}

static void
fiber_peek_exec( void * _ctx ) {
  fiber_t * f = _ctx;
  fd_progcache_rec_t * res = fd_progcache_peek(
      f->peek.cache, f->peek.fork_id, &f->peek.prog_addr,
      f->peek.feature_slot, f->peek.deploy_slot );
  if( res ) fd_progcache_rec_close( f->peek.cache, res );
}

static fd_racesan_async_t *
fiber_peek( fiber_t *              fiber,
            void *                 shmem,
            fd_progcache_fork_id_t fork_id,
            void const *           prog_addr ) {
  FD_TEST( fd_progcache_join( fiber->cache, shmem, fiber->scratch, sizeof(fiber->scratch) ) );
  fiber->peek.cache        = fiber->cache;
  fiber->peek.fork_id      = fork_id;
  fiber->peek.prog_addr    = FD_LOAD( fd_pubkey_t, prog_addr );
  fiber->peek.feature_slot = 0UL;
  fiber->peek.deploy_slot  = 1UL;
  fd_racesan_async_new( fiber->async, fiber->stack+FIBER_STACK_MAX, FIBER_STACK_MAX, fiber_peek_exec, fiber );
  return fiber->async;
}

static void
fiber_evict_exec( void * _ctx ) {
  fiber_t * f = _ctx;
  fd_progcache_rec_t * rec = fd_prog_evict( f->evict.cache, f->evict.sz );
  if( rec ) fd_progcache_rec_abandon( f->evict.cache->join, rec );
}

static fd_racesan_async_t *
fiber_evict( fiber_t * fiber,
             void *    shmem,
             ulong     sz ) {
  FD_TEST( fd_progcache_join( fiber->cache, shmem, fiber->scratch, sizeof(fiber->scratch) ) );
  fiber->evict.cache = fiber->cache;
  fiber->evict.sz    = sz;
  fd_racesan_async_new( fiber->async, fiber->stack+FIBER_STACK_MAX, FIBER_STACK_MAX, fiber_evict_exec, fiber );
  return fiber->async;
}

static void
fiber_advance_root_exec( void * _ctx ) {
  fiber_t * f = _ctx;
  fd_progcache_advance_root( f->advance_root.cache, f->advance_root.fork_id );
}

static fd_racesan_async_t *
fiber_advance_root( fiber_t *              fiber,
                    void *                 shmem,
                    fd_progcache_fork_id_t fork_id ) {
  FD_TEST( fd_progcache_join( fiber->cache, shmem, fiber->scratch, sizeof(fiber->scratch) ) );
  fiber->advance_root.cache   = (fd_progcache_join_t *)fd_type_pun( fiber->cache );
  fiber->advance_root.fork_id = fork_id;
  fd_racesan_async_new( fiber->async, fiber->stack+FIBER_STACK_MAX, FIBER_STACK_MAX, fiber_advance_root_exec, fiber );
  return fiber->async;
}

static void
fiber_cancel_exec( void * _ctx ) {
  fiber_t * f = _ctx;
  fd_progcache_cancel_fork( f->cancel.cache, f->cancel.fork_id );
}

static fd_racesan_async_t *
fiber_cancel( fiber_t *              fiber,
              void *                 shmem,
              fd_progcache_fork_id_t fork_id ) {
  FD_TEST( fd_progcache_join( fiber->cache, shmem, fiber->scratch, sizeof(fiber->scratch) ) );
  fiber->cancel.cache   = (fd_progcache_join_t *)fd_type_pun( fiber->cache );
  fiber->cancel.fork_id = fork_id;
  fd_racesan_async_new( fiber->async, fiber->stack+FIBER_STACK_MAX, FIBER_STACK_MAX, fiber_cancel_exec, fiber );
  return fiber->async;
}

static void
fiber_delete_rec_exec( void * _ctx ) {
  fiber_t * f = _ctx;
  f->delete_rec.result = fd_prog_delete_rec( f->delete_rec.cache, f->delete_rec.rec );
}

static fd_racesan_async_t *
fiber_delete_rec( fiber_t *            fiber,
                  void *               shmem,
                  fd_progcache_rec_t * rec ) {
  FD_TEST( fd_progcache_join( fiber->cache, shmem, fiber->scratch, sizeof(fiber->scratch) ) );
  fiber->delete_rec.cache  = (fd_progcache_join_t *)fd_type_pun( fiber->cache );
  fiber->delete_rec.rec    = rec;
  fiber->delete_rec.result = -2L;
  fd_racesan_async_new( fiber->async, fiber->stack+FIBER_STACK_MAX, FIBER_STACK_MAX, fiber_delete_rec_exec, fiber );
  return fiber->async;
}

/* Utils */

static void
metrics_reset( void ) {
  memset( &fd_progcache_metrics_default, 0, sizeof(fd_progcache_metrics_default) );
  memset( &fd_progcache_admin_metrics_g, 0, sizeof(fd_progcache_admin_metrics_g) );
}

static void
metrics_check_no_oom( void ) {
  FD_TEST( fd_progcache_metrics_default.class_full_cnt==0UL );
}

static fd_progcache_shmem_t *
test_progcache_shmem_new( void ) {
  fd_wksp_reset( wksp, 1UL );
  ulong txn_max  = 16UL;
  ulong wksp_tag =  1UL;

  fd_progcache_shmem_t * shmem = fd_wksp_alloc_laddr( wksp, fd_progcache_shmem_align(), fd_progcache_shmem_footprint( txn_max, 256UL<<20 ), wksp_tag );
  FD_TEST( fd_progcache_shmem_new( shmem, wksp_tag, 1UL, txn_max, 256UL<<20 ) );
  return shmem;
}

static void
test_progcache_shmem_delete( fd_progcache_shmem_t * shmem ) {
  fd_wksp_free_laddr( fd_progcache_shmem_delete( shmem ) );
}

static void
test_progcache_reset( fd_progcache_join_t * join ) {
  fd_progcache_reset( join );
}

static fd_progcache_rec_t const *
query_rec_exact( fd_progcache_join_t *  join,
                 fd_progcache_fork_id_t fork_id,
                 fd_pubkey_t const *    key ) {
  fd_progcache_rec_key_t pair = { .xid = fork_id, .prog = *key };
  fd_prog_recm_query_t query[1];
  int query_err = fd_prog_recm_query_try( join->rec.map, &pair, NULL, query, 0 );
  if( query_err==FD_MAP_ERR_KEY ) return NULL;
  if( FD_UNLIKELY( query_err!=FD_MAP_SUCCESS ) )
    FD_LOG_CRIT(( "fd_prog_recm_query_try failed: %i-%s", query_err, fd_map_strerror( query_err ) ));
  return fd_prog_recm_query_ele_const( query );
}

/* TESTS **************************************************************/

/* test_pull_pull races two pulls of the same program.  Only one of them may run
   fd_sbpf_program_load: the first to publish claims the key under the loading
   sentinel and the other waits for it, rather than loading a second copy and
   throwing it away. */

FD_UNIT_TEST( pull_pull ) {
  fd_progcache_shmem_t * shmem = test_progcache_shmem_new();

  fd_pubkey_t        key = test_key( 42UL );
  fd_prog_load_env_t load_env = { .features = g_features, .feature_slot=0UL };

  test_account_t acc;
  test_account_init( &acc, &key, &fd_solana_bpf_loader_deprecated_program_id, 1, valid_program_data, valid_program_data_sz );

  fd_progcache_join_t admin[1]; FD_TEST( fd_progcache_shmem_join( admin, shmem ) );

  for( ulong i=0UL; i<ITER_DEFAULT; i++ ) {
    fd_progcache_fork_id_t xid = fd_progcache_attach_child( admin, fd_progcache_fork_id_initial() );

    fd_racesan_weave_t w[1];
    fd_racesan_weave_new( w );
    fd_racesan_weave_add( w, fiber_pull( &g_fiber[ 0 ], shmem, xid, &key, &load_env, acc.entry ) );
    fd_racesan_weave_add( w, fiber_pull( &g_fiber[ 1 ], shmem, xid, &key, &load_env, acc.entry ) );

    metrics_reset();
    fd_racesan_weave_exec_rand( w, i, STEP_MAX );
    FD_TEST( !w->rem_cnt );
    FD_TEST( fd_progcache_metrics_default.lookup_cnt==2UL );
    FD_TEST( fd_progcache_metrics_default.fill_cnt  ==1UL );
    FD_TEST( fd_progcache_metrics_default.hit_cnt+fd_progcache_metrics_default.miss_cnt==2UL );
    FD_TEST( fd_progcache_metrics_default.miss_cnt  >=1UL ); /* the fill was a miss */
    /* single flight: one load for one revision, whatever the interleaving.  Both
       fibers get that record, and only the one that does not load can wait. */
    FD_TEST( g_fiber[ 0 ].pull.res==g_fiber[ 1 ].pull.res );
    FD_TEST( fd_progcache_metrics_default.load_cnt  ==1UL );
    FD_TEST( fd_progcache_metrics_default.hit_loading_cnt<=1UL );
    metrics_check_no_oom();

    fd_racesan_weave_delete( w );
    fiber_delete( &g_fiber[ 0 ] );
    fiber_delete( &g_fiber[ 1 ] );
    FD_TEST( !fd_progcache_verify( admin ) );
    test_progcache_reset( admin );
  }

  FD_TEST( fd_progcache_shmem_leave( admin, NULL ) );
  test_progcache_shmem_delete( shmem );
}

/* test_pull_peek races a cache fill against a read-only cache lookup */

FD_UNIT_TEST( pull_peek ) {
  fd_progcache_shmem_t * shmem = test_progcache_shmem_new();

  fd_pubkey_t key = test_key( 42UL );
  fd_prog_load_env_t load_env = { .features = g_features, .feature_slot = 0UL };

  test_account_t acc;
  test_account_init( &acc, &key, &fd_solana_bpf_loader_deprecated_program_id, 1, valid_program_data, valid_program_data_sz );

  fd_progcache_join_t admin[1]; FD_TEST( fd_progcache_shmem_join( admin, shmem ) );

  for( ulong i=0UL; i<ITER_DEFAULT; i++ ) {
    fd_progcache_fork_id_t xid = fd_progcache_attach_child( admin, fd_progcache_fork_id_initial() );

    fd_racesan_weave_t w[1];
    fd_racesan_weave_new( w );
    fd_racesan_weave_add( w, fiber_pull( &g_fiber[ 0 ], shmem, xid, &key, &load_env, acc.entry ) );
    fd_racesan_weave_add( w, fiber_peek( &g_fiber[ 1 ], shmem, xid, &key ) );

    metrics_reset();
    fd_racesan_weave_exec_rand( w, i, STEP_MAX );
    FD_TEST( !w->rem_cnt );
    FD_TEST( fd_progcache_metrics_default.lookup_cnt==1UL );
    FD_TEST( fd_progcache_metrics_default.fill_cnt  ==1UL );
    FD_TEST( fd_progcache_metrics_default.miss_cnt  ==1UL );
    metrics_check_no_oom();

    fd_racesan_weave_delete( w );
    fiber_delete( &g_fiber[ 0 ] );
    fiber_delete( &g_fiber[ 1 ] );
    FD_TEST( !fd_progcache_verify( admin ) );
    test_progcache_reset( admin );
  }

  FD_TEST( fd_progcache_shmem_leave( admin, NULL ) );
  test_progcache_shmem_delete( shmem );
}

/* test_pull_root roots a fork while a pull holds the key under the loading
   sentinel.  Rooting detaches the record but leaves it mapped, so the publisher
   must finish the publish rather than bail: a bail leaves a LOADING entry that no
   lookup can resolve.  Deterministic, not woven -- an interleaving that roots
   before the publish is a caller executing on a rooted fork, which insert
   rejects by design. */

FD_UNIT_TEST( pull_root ) {
  fd_progcache_shmem_t * shmem = test_progcache_shmem_new();

  fd_pubkey_t        key = test_key( 42UL );
  fd_prog_load_env_t load_env = { .features = g_features, .feature_slot = 0UL };

  test_account_t acc;
  test_account_init( &acc, &key, &fd_solana_bpf_loader_deprecated_program_id, 1, valid_program_data, valid_program_data_sz );

  fd_progcache_join_t admin[1]; FD_TEST( fd_progcache_shmem_join( admin, shmem ) );
  fd_progcache_fork_id_t xid = fd_progcache_attach_child( admin, fd_progcache_fork_id_initial() );

  /* Run the pull up to the point where it owns the load and the record is in the
     map under the sentinel. */
  fd_racesan_async_t * a = fiber_pull( &g_fiber[ 0 ], shmem, xid, &key, &load_env, acc.entry );
  FD_TEST( fd_racesan_async_step_until( a, "prog_insert:post_claim", STEP_MAX )==FD_RACESAN_ASYNC_RET_HOOK );

  fd_progcache_advance_root( admin, xid );

  /* Bounded: a publisher that bailed leaves its own retry loop spinning on the
     record it stranded, so an unbounded resume would hang instead of report. */
  int exited = 0;
  for( ulong step=0UL; step<STEP_MAX; step++ ) {
    int ret = fd_racesan_async_step( a );
    if( ret==FD_RACESAN_ASYNC_RET_EXIT ) { exited = 1; break; }
    FD_TEST( ret==FD_RACESAN_ASYNC_RET_HOOK );
  }
  FD_TEST( exited );
  fiber_delete( &g_fiber[ 0 ] );

  /* Catches the strand: a mapped, detached record must be LIVE. */
  FD_TEST( !fd_progcache_verify( admin ) );

  /* And it must be usable.  Pre-fix this pull never returns. */
  {
    fd_progcache_fork_id_t child = fd_progcache_attach_child( admin, xid );
    fd_progcache_t tmp[1];
    FD_TEST( fd_progcache_join( tmp, shmem, g_fiber[ 1 ].scratch, FD_PROGCACHE_SCRATCH_FOOTPRINT ) );
    fd_progcache_rec_t * rec = fd_progcache_pull( tmp, child, &key, &load_env, acc.entry );
    FD_TEST( rec );
    fd_progcache_rec_close( tmp, rec );
    fd_progcache_leave( tmp, NULL );
  }

  FD_TEST( fd_progcache_shmem_leave( admin, NULL ) );
  test_progcache_shmem_delete( shmem );
}

/* test_pull_cancel cancels a fork while a pull holds the key under the loading
   sentinel.  Cancel unmaps the record, so the publisher cannot cache it -- but the
   program is loaded and read-locked, so pull still returns it and the close
   leaves a zombie for the next sweep.  Deterministic for the same reason as
   pull_root. */

FD_UNIT_TEST( pull_cancel ) {
  fd_progcache_shmem_t * shmem = test_progcache_shmem_new();

  fd_pubkey_t        key = test_key( 42UL );
  fd_prog_load_env_t load_env = { .features = g_features, .feature_slot = 0UL };

  test_account_t acc;
  test_account_init( &acc, &key, &fd_solana_bpf_loader_deprecated_program_id, 1, valid_program_data, valid_program_data_sz );

  fd_progcache_join_t admin[1]; FD_TEST( fd_progcache_shmem_join( admin, shmem ) );
  fd_progcache_fork_id_t xid = fd_progcache_attach_child( admin, fd_progcache_fork_id_initial() );

  fd_racesan_async_t * a = fiber_pull( &g_fiber[ 0 ], shmem, xid, &key, &load_env, acc.entry );
  FD_TEST( fd_racesan_async_step_until( a, "prog_insert:post_claim", STEP_MAX )==FD_RACESAN_ASYNC_RET_HOOK );

  fd_progcache_cancel_fork( admin, xid );

  int exited = 0;
  for( ulong step=0UL; step<STEP_MAX; step++ ) {
    int ret = fd_racesan_async_step( a );
    if( ret==FD_RACESAN_ASYNC_RET_EXIT ) { exited = 1; break; }
    FD_TEST( ret==FD_RACESAN_ASYNC_RET_HOOK );
  }
  FD_TEST( exited ); /* fiber_pull asserts the record it got is non-NULL */
  fiber_delete( &g_fiber[ 0 ] );

  FD_TEST( !fd_progcache_verify( admin ) );

  /* Nothing was cached: the fork is gone, so a fresh fork reloads rather than
     inheriting a record from the cancelled one. */
  {
    fd_progcache_fork_id_t xid2 = fd_progcache_attach_child( admin, fd_progcache_fork_id_initial() );
    fd_progcache_t tmp[1];
    FD_TEST( fd_progcache_join( tmp, shmem, g_fiber[ 1 ].scratch, FD_PROGCACHE_SCRATCH_FOOTPRINT ) );
    metrics_reset();
    fd_progcache_rec_t * rec = fd_progcache_pull( tmp, xid2, &key, &load_env, acc.entry );
    FD_TEST( rec );
    FD_TEST( fd_progcache_metrics_default.fill_cnt==1UL ); /* a fill, not a stale hit */
    fd_progcache_rec_close( tmp, rec );
    fd_progcache_leave( tmp, NULL );
  }

  FD_TEST( fd_progcache_shmem_leave( admin, NULL ) );
  test_progcache_shmem_delete( shmem );
}

/* test_lost_race_failed_load: B loses the publish race and parks in insert's wait
   on A's record.  A's load is then rejected, so A unmaps that record -- B must not
   be handed the failed load's slot as if it were a program. */

FD_UNIT_TEST( lost_race_failed_load ) {
  fd_progcache_shmem_t * shmem = test_progcache_shmem_new();

  fd_pubkey_t        key = test_key( 7UL );
  fd_prog_load_env_t load_env = { .features = g_features, .feature_slot = 0UL };

  test_account_t acc;
  test_account_init( &acc, &key, &fd_solana_bpf_loader_deprecated_program_id, 1, invalid_program_data, invalid_program_data_sz );

  fd_progcache_join_t admin[1]; FD_TEST( fd_progcache_shmem_join( admin, shmem ) );
  fd_progcache_fork_id_t xid = fd_progcache_attach_child( admin, fd_progcache_fork_id_initial() );

  /* Both miss in query and hold their own record, neither published yet. */
  fd_racesan_async_t * a = fiber_pull( &g_fiber[ 0 ], shmem, xid, &key, &load_env, acc.entry );
  FD_TEST( fd_racesan_async_step_until( a, "prog_insert:pre_push", STEP_MAX )==FD_RACESAN_ASYNC_RET_HOOK );
  fd_racesan_async_t * b = fiber_pull( &g_fiber[ 1 ], shmem, xid, &key, &load_env, acc.entry );
  FD_TEST( fd_racesan_async_step_until( b, "prog_insert:pre_push", STEP_MAX )==FD_RACESAN_ASYNC_RET_HOOK );

  /* A wins the key and owns the load. */
  FD_TEST( fd_racesan_async_step_until( a, "prog_insert:post_claim", STEP_MAX )==FD_RACESAN_ASYNC_RET_HOOK );

  /* B loses and parks on A's record. */
  FD_TEST( fd_racesan_async_step_until( b, "prog_wait_if_loading:spin", STEP_MAX )==FD_RACESAN_ASYNC_RET_HOOK );

  /* A's load is rejected: it unmaps the record B is waiting on. */
  for(;;) {
    int ret = fd_racesan_async_step( a );
    if( ret==FD_RACESAN_ASYNC_RET_EXIT ) break;
    FD_TEST( ret==FD_RACESAN_ASYNC_RET_HOOK );
  }

  for(;;) {
    int ret = fd_racesan_async_step( b );
    if( ret==FD_RACESAN_ASYNC_RET_EXIT ) break;
    FD_TEST( ret==FD_RACESAN_ASYNC_RET_HOOK );
  }

  /* Neither caller may be handed program data for a program that did not load. */
  FD_TEST( !g_fiber[ 0 ].pull.res_data_gaddr );
  FD_TEST( !g_fiber[ 1 ].pull.res_data_gaddr );

  fiber_delete( &g_fiber[ 0 ] );
  fiber_delete( &g_fiber[ 1 ] );
  FD_TEST( !fd_progcache_verify( admin ) );
  FD_TEST( fd_progcache_shmem_leave( admin, NULL ) );
  test_progcache_shmem_delete( shmem );
}

/* test_peek_failed_load waits on a record whose load then fails verification.
   The record is marked non-executable in place and stays mapped, so the waiter
   wakes on the same record and gets the non-executable answer. */

FD_UNIT_TEST( peek_failed_load ) {
  fd_progcache_shmem_t * shmem = test_progcache_shmem_new();

  fd_pubkey_t        key = test_key( 42UL );
  fd_prog_load_env_t load_env = { .features = g_features, .feature_slot = 0UL };

  test_account_t acc;
  test_account_init( &acc, &key, &fd_solana_bpf_loader_deprecated_program_id, 1, invalid_program_data, invalid_program_data_sz );

  fd_progcache_join_t admin[1]; FD_TEST( fd_progcache_shmem_join( admin, shmem ) );
  fd_progcache_fork_id_t xid = fd_progcache_attach_child( admin, fd_progcache_fork_id_initial() );

  /* A owns the load, with the record published under the sentinel. */
  fd_racesan_async_t * a = fiber_pull( &g_fiber[ 0 ], shmem, xid, &key, &load_env, acc.entry );
  FD_TEST( fd_racesan_async_step_until( a, "prog_insert:post_claim", STEP_MAX )==FD_RACESAN_ASYNC_RET_HOOK );

  /* B finds it and parks in the wait, holding a read lock on A's record.  A pull,
     not a peek: it derives the same revision fields A did. */
  fd_racesan_async_t * b = fiber_pull( &g_fiber[ 1 ], shmem, xid, &key, &load_env, acc.entry );
  FD_TEST( fd_racesan_async_step_until( b, "prog_wait_if_loading:spin", STEP_MAX )==FD_RACESAN_ASYNC_RET_HOOK );

  /* A fails verification: it deletes the record B holds, then publishes nx. */
  int a_done = 0;
  for( ulong step=0UL; step<STEP_MAX; step++ ) {
    int ret = fd_racesan_async_step( a );
    if( ret==FD_RACESAN_ASYNC_RET_EXIT ) { a_done = 1; break; }
    FD_TEST( ret==FD_RACESAN_ASYNC_RET_HOOK );
  }
  FD_TEST( a_done );

  /* B must notice the record never became LIVE and re-find the nx record. */
  int b_done = 0;
  for( ulong step=0UL; step<STEP_MAX; step++ ) {
    int ret = fd_racesan_async_step( b );
    if( ret==FD_RACESAN_ASYNC_RET_EXIT ) { b_done = 1; break; }
    FD_TEST( ret==FD_RACESAN_ASYNC_RET_HOOK );
  }
  FD_TEST( b_done );

  /* Both got the same record, and it reads back non-executable. */
  FD_TEST( g_fiber[ 0 ].pull.res && !g_fiber[ 0 ].pull.res_data_gaddr );
  FD_TEST( g_fiber[ 1 ].pull.res==g_fiber[ 0 ].pull.res );
  FD_TEST( !g_fiber[ 1 ].pull.res_data_gaddr );

  fiber_delete( &g_fiber[ 0 ] );
  fiber_delete( &g_fiber[ 1 ] );
  FD_TEST( !fd_progcache_verify( admin ) );
  FD_TEST( fd_progcache_shmem_leave( admin, NULL ) );
  test_progcache_shmem_delete( shmem );
}

/* test_cancel_peek races a cancel against a peek for a child txn.
   Pre-populates cache under xid0, then races cancel(xid1) vs peek(xid0). */

FD_UNIT_TEST( cancel_peek ) {
  fd_progcache_shmem_t * shmem = test_progcache_shmem_new();

  fd_pubkey_t key  = test_key( 42UL );
  fd_prog_load_env_t load_env = { .features = g_features, .feature_slot = 0UL };

  test_account_t acc;
  test_account_init( &acc, &key, &fd_solana_bpf_loader_deprecated_program_id, 1, valid_program_data, valid_program_data_sz );

  fd_progcache_join_t admin[1]; FD_TEST( fd_progcache_shmem_join( admin, shmem ) );

  for( ulong i=0UL; i<ITER_DEFAULT; i++ ) {
    /* Pre-populate the cache at root through a real txn */
    fd_progcache_fork_id_t xid_pre;
    {
      xid_pre = fd_progcache_attach_child( admin, fd_progcache_fork_id_initial() );
      fd_progcache_t tmp[1];
      FD_TEST( fd_progcache_join( tmp, shmem, g_fiber[ 0 ].scratch, FD_PROGCACHE_SCRATCH_FOOTPRINT ) );
      fd_progcache_rec_t * rec = fd_progcache_pull( tmp, xid_pre, &key, &load_env, acc.entry );
      FD_TEST( rec );
      fd_progcache_rec_close( tmp, rec );
      fd_progcache_leave( tmp, NULL );
      fd_progcache_advance_root( admin, xid_pre );
    }

    fd_progcache_fork_id_t xid1 = fd_progcache_attach_child( admin, xid_pre );

    fd_racesan_weave_t w[1];
    fd_racesan_weave_new( w );
    fd_racesan_weave_add( w, fiber_cancel( &g_fiber[ 0 ], shmem, xid1 ) );
    fd_racesan_weave_add( w, fiber_peek(   &g_fiber[ 1 ], shmem, fd_progcache_fork_id_initial(), &key ) );

    metrics_reset();
    fd_racesan_weave_exec_rand( w, i, STEP_MAX );
    FD_TEST( !w->rem_cnt );
    metrics_check_no_oom();

    fd_racesan_weave_delete( w );
    fiber_delete( &g_fiber[ 0 ] );
    fiber_delete( &g_fiber[ 1 ] );
    FD_TEST( !fd_progcache_verify( admin ) );
    test_progcache_reset( admin );
  }

  FD_TEST( fd_progcache_shmem_leave( admin, NULL ) );
  test_progcache_shmem_delete( shmem );
}

/* test_cancel_evict races fork cancellation against clock eviction competing to
   remove the same record: cancel_one orphans it and unmaps it while the sweep
   is unmapping and claiming it for a caller that needs the slot. */

FD_UNIT_TEST( cancel_evict ) {
  fd_progcache_shmem_t * shmem = test_progcache_shmem_new();

  fd_pubkey_t key = test_key( 42UL );
  fd_prog_load_env_t load_env = { .features = g_features, .feature_slot = 0UL };

  test_account_t acc;
  test_account_init( &acc, &key, &fd_solana_bpf_loader_deprecated_program_id, 1, valid_program_data, valid_program_data_sz );

  fd_progcache_join_t admin[1]; FD_TEST( fd_progcache_shmem_join( admin, shmem ) );

  for( ulong i=0UL; i<ITER_DEFAULT; i++ ) {
    fd_progcache_fork_id_t xid1 = fd_progcache_attach_child( admin, fd_progcache_fork_id_initial() );

    {
      fd_progcache_t tmp[1];
      FD_TEST( fd_progcache_join( tmp, shmem, g_fiber[ 0 ].scratch, FD_PROGCACHE_SCRATCH_FOOTPRINT ) );
      fd_progcache_rec_t * rec = fd_progcache_pull( tmp, xid1, &key, &load_env, acc.entry );
      FD_TEST( rec );
      fd_progcache_rec_close( tmp, rec );
      /* Drop the second chance so the sweep targets this record immediately. */
      ulong rec_idx = (ulong)( rec - tmp->join->rec.ele );
      __atomic_fetch_and( &tmp->join->rec.ele[ rec_idx ].state, (uchar)~FD_PROGCACHE_REC_VISITED, __ATOMIC_RELAXED );
      fd_progcache_leave( tmp, NULL );
    }

    fd_racesan_weave_t w[1];
    fd_racesan_weave_new( w );
    fd_racesan_weave_add( w, fiber_cancel( &g_fiber[ 0 ], shmem, xid1 ) );
    fd_racesan_weave_add( w, fiber_evict ( &g_fiber[ 1 ], shmem, valid_program_data_sz ) );

    metrics_reset();
    fd_racesan_weave_exec_rand( w, i, STEP_MAX );
    FD_TEST( !w->rem_cnt );

    fd_racesan_weave_delete( w );
    fiber_delete( &g_fiber[ 0 ] );
    fiber_delete( &g_fiber[ 1 ] );
    FD_TEST( !fd_progcache_verify( admin ) );
    test_progcache_reset( admin );
  }

  FD_TEST( fd_progcache_shmem_leave( admin, NULL ) );
  test_progcache_shmem_delete( shmem );
}

/* test_publish_evict races advance_root against clock eviction */

FD_UNIT_TEST( publish_evict ) {
  fd_progcache_shmem_t * shmem = test_progcache_shmem_new();

  fd_pubkey_t key  = test_key( 42UL );
  fd_prog_load_env_t load_env = { .features = g_features, .feature_slot = 0UL };

  test_account_t acc;
  test_account_init( &acc, &key, &fd_solana_bpf_loader_deprecated_program_id, 1, valid_program_data, valid_program_data_sz );

  fd_progcache_join_t admin[1]; FD_TEST( fd_progcache_shmem_join( admin, shmem ) );

  for( ulong i=0UL; i<ITER_DEFAULT; i++ ) {
    fd_progcache_fork_id_t xid1 = fd_progcache_attach_child( admin, fd_progcache_fork_id_initial() );

    /* Pre-populate the cache */
    {
      fd_progcache_t tmp[1];
      FD_TEST( fd_progcache_join( tmp, shmem, g_fiber[ 0 ].scratch, FD_PROGCACHE_SCRATCH_FOOTPRINT ) );
      fd_progcache_rec_t * rec = fd_progcache_pull( tmp, xid1, &key, &load_env, acc.entry );
      FD_TEST( rec );
      fd_progcache_rec_close( tmp, rec );
      fd_progcache_leave( tmp, NULL );
    }

    fd_racesan_weave_t w[1];
    fd_racesan_weave_new( w );
    fd_racesan_weave_add( w, fiber_advance_root( &g_fiber[ 0 ], shmem, xid1 ) );
    fd_racesan_weave_add( w, fiber_evict(        &g_fiber[ 1 ], shmem, valid_program_data_sz ) );

    metrics_reset();
    fd_racesan_weave_exec_rand( w, i, STEP_MAX );
    FD_TEST( !w->rem_cnt );

    fd_racesan_weave_delete( w );
    fiber_delete( &g_fiber[ 0 ] );
    fiber_delete( &g_fiber[ 1 ] );
    FD_TEST( !fd_progcache_verify( admin ) );
    test_progcache_reset( admin );
  }

  FD_TEST( fd_progcache_shmem_leave( admin, NULL ) );
  test_progcache_shmem_delete( shmem );
}

/* test_peek_root races a peek against advance_root */

FD_UNIT_TEST( peek_root ) {
  fd_progcache_shmem_t * shmem = test_progcache_shmem_new();

  fd_pubkey_t key  = test_key( 42UL );
  fd_prog_load_env_t load_env = { .features = g_features, .feature_slot = 0UL };

  test_account_t acc;
  test_account_init( &acc, &key, &fd_solana_bpf_loader_deprecated_program_id, 1, valid_program_data, valid_program_data_sz );

  fd_progcache_join_t admin[1]; FD_TEST( fd_progcache_shmem_join( admin, shmem ) );

  for( ulong i=0UL; i<ITER_DEFAULT; i++ ) {
    fd_progcache_fork_id_t xid1 = fd_progcache_attach_child( admin, fd_progcache_fork_id_initial() );

    /* Pre-populate the cache */
    {
      fd_progcache_t tmp[1];
      FD_TEST( fd_progcache_join( tmp, shmem, g_fiber[ 0 ].scratch, FD_PROGCACHE_SCRATCH_FOOTPRINT ) );
      fd_progcache_rec_t * rec = fd_progcache_pull( tmp, xid1, &key, &load_env, acc.entry );
      FD_TEST( rec );
      fd_progcache_rec_close( tmp, rec );
      fd_progcache_leave( tmp, NULL );
    }

    fd_racesan_weave_t w[1];
    fd_racesan_weave_new( w );
    fd_racesan_weave_add( w, fiber_peek(         &g_fiber[ 0 ], shmem, xid1, &key ) );
    fd_racesan_weave_add( w, fiber_advance_root( &g_fiber[ 1 ], shmem, xid1 ) );

    metrics_reset();
    fd_racesan_weave_exec_rand( w, i, STEP_MAX );
    FD_TEST( !w->rem_cnt );
    metrics_check_no_oom();

    fd_racesan_weave_delete( w );
    fiber_delete( &g_fiber[ 0 ] );
    fiber_delete( &g_fiber[ 1 ] );
    FD_TEST( !fd_progcache_verify( admin ) );
    test_progcache_reset( admin );
  }

  FD_TEST( fd_progcache_shmem_leave( admin, NULL ) );
  test_progcache_shmem_delete( shmem );
}

/* test_peek_cancel_new races a peek against cancel */

FD_UNIT_TEST( peek_cancel ) {
  fd_progcache_shmem_t * shmem = test_progcache_shmem_new();

  fd_pubkey_t key  = test_key( 42UL );
  fd_prog_load_env_t load_env = { .features = g_features, .feature_slot = 0UL };

  test_account_t acc;
  test_account_init( &acc, &key, &fd_solana_bpf_loader_deprecated_program_id, 1, valid_program_data, valid_program_data_sz );

  fd_progcache_join_t admin[1]; FD_TEST( fd_progcache_shmem_join( admin, shmem ) );

  for( ulong i=0UL; i<ITER_DEFAULT; i++ ) {
    fd_progcache_fork_id_t xid1 = fd_progcache_attach_child( admin, fd_progcache_fork_id_initial() );

    /* Pre-populate the cache */
    {
      fd_progcache_t tmp[1];
      FD_TEST( fd_progcache_join( tmp, shmem, g_fiber[ 0 ].scratch, FD_PROGCACHE_SCRATCH_FOOTPRINT ) );
      fd_progcache_rec_t * rec = fd_progcache_pull( tmp, xid1, &key, &load_env, acc.entry );
      FD_TEST( rec );
      fd_progcache_rec_close( tmp, rec );
      fd_progcache_leave( tmp, NULL );
    }

    fd_racesan_weave_t w[1];
    fd_racesan_weave_new( w );
    fd_racesan_weave_add( w, fiber_peek(   &g_fiber[ 0 ], shmem, xid1, &key ) );
    fd_racesan_weave_add( w, fiber_cancel( &g_fiber[ 1 ], shmem, xid1 ) );

    metrics_reset();
    fd_racesan_weave_exec_rand( w, i, STEP_MAX );
    FD_TEST( !w->rem_cnt );
    metrics_check_no_oom();

    fd_racesan_weave_delete( w );
    fiber_delete( &g_fiber[ 0 ] );
    fiber_delete( &g_fiber[ 1 ] );
    FD_TEST( !fd_progcache_verify( admin ) );
    test_progcache_reset( admin );
  }

  FD_TEST( fd_progcache_shmem_leave( admin, NULL ) );
  test_progcache_shmem_delete( shmem );
}

/* test_peek_peek races two peeks for the same program */

FD_UNIT_TEST( peek_peek ) {
  fd_progcache_shmem_t * shmem = test_progcache_shmem_new();

  fd_pubkey_t key = test_key( 42UL );
  fd_prog_load_env_t load_env = { .features = g_features, .feature_slot = 0UL };

  test_account_t acc;
  test_account_init( &acc, &key, &fd_solana_bpf_loader_deprecated_program_id, 1, valid_program_data, valid_program_data_sz );

  fd_progcache_join_t admin[1]; FD_TEST( fd_progcache_shmem_join( admin, shmem ) );

  for( ulong i=0UL; i<ITER_DEFAULT; i++ ) {
    /* Pre-populate the cache at root through a real txn */
    fd_progcache_fork_id_t xid_pre;
    {
      xid_pre = fd_progcache_attach_child( admin, fd_progcache_fork_id_initial() );
      fd_progcache_t tmp[1];
      FD_TEST( fd_progcache_join( tmp, shmem, g_fiber[ 0 ].scratch, FD_PROGCACHE_SCRATCH_FOOTPRINT ) );
      fd_progcache_rec_t * rec = fd_progcache_pull( tmp, xid_pre, &key, &load_env, acc.entry );
      FD_TEST( rec );
      fd_progcache_rec_close( tmp, rec );
      fd_progcache_leave( tmp, NULL );
      fd_progcache_advance_root( admin, xid_pre );
    }

    fd_racesan_weave_t w[1];
    fd_racesan_weave_new( w );
    fd_racesan_weave_add( w, fiber_peek( &g_fiber[ 0 ], shmem, fd_progcache_fork_id_initial(), &key ) );
    fd_racesan_weave_add( w, fiber_peek( &g_fiber[ 1 ], shmem, fd_progcache_fork_id_initial(), &key ) );

    metrics_reset();
    fd_racesan_weave_exec_rand( w, i, STEP_MAX );
    FD_TEST( !w->rem_cnt );
    metrics_check_no_oom();

    fd_racesan_weave_delete( w );
    fiber_delete( &g_fiber[ 0 ] );
    fiber_delete( &g_fiber[ 1 ] );
    FD_TEST( !fd_progcache_verify( admin ) );
    test_progcache_reset( admin );
  }

  FD_TEST( fd_progcache_shmem_leave( admin, NULL ) );
  test_progcache_shmem_delete( shmem );
}

/* test_peek_root_sibling races a peek on one sibling against
   advance_root of another sibling */

FD_UNIT_TEST( peek_root_sibling ) {
  fd_progcache_shmem_t * shmem = test_progcache_shmem_new();

  fd_pubkey_t key  = test_key( 42UL );
  fd_prog_load_env_t load_env = { .features = g_features, .feature_slot = 0UL };

  test_account_t acc;
  test_account_init( &acc, &key, &fd_solana_bpf_loader_deprecated_program_id, 1, valid_program_data, valid_program_data_sz );

  fd_progcache_join_t admin[1]; FD_TEST( fd_progcache_shmem_join( admin, shmem ) );

  for( ulong i=0UL; i<ITER_DEFAULT; i++ ) {
    fd_progcache_fork_id_t xid1 = fd_progcache_attach_child( admin, fd_progcache_fork_id_initial() );
    fd_progcache_fork_id_t xid2 = fd_progcache_attach_child( admin, fd_progcache_fork_id_initial() );

    {
      fd_progcache_t tmp[1];
      FD_TEST( fd_progcache_join( tmp, shmem, g_fiber[ 0 ].scratch, FD_PROGCACHE_SCRATCH_FOOTPRINT ) );
      fd_progcache_rec_t * rec;
      rec = fd_progcache_pull( tmp, xid1, &key, &load_env, acc.entry );
      FD_TEST( rec ); fd_progcache_rec_close( tmp, rec );
      rec = fd_progcache_pull( tmp, xid2, &key, &load_env, acc.entry );
      FD_TEST( rec ); fd_progcache_rec_close( tmp, rec );
      fd_progcache_leave( tmp, NULL );
    }

    fd_racesan_weave_t w[1];
    fd_racesan_weave_new( w );
    fd_racesan_weave_add( w, fiber_peek(         &g_fiber[ 0 ], shmem, xid2, &key ) );
    fd_racesan_weave_add( w, fiber_advance_root( &g_fiber[ 1 ], shmem, xid1 ) );

    metrics_reset();
    fd_racesan_weave_exec_rand( w, i, STEP_MAX );
    FD_TEST( !w->rem_cnt );
    metrics_check_no_oom();

    fd_racesan_weave_delete( w );
    fiber_delete( &g_fiber[ 0 ] );
    fiber_delete( &g_fiber[ 1 ] );
    FD_TEST( !fd_progcache_verify( admin ) );
    test_progcache_reset( admin );
  }

  FD_TEST( fd_progcache_shmem_leave( admin, NULL ) );
  test_progcache_shmem_delete( shmem );
}

/* test_peek_peek_root races two peeks against advance_root */

FD_UNIT_TEST( peek_peek_root ) {
  fd_progcache_shmem_t * shmem = test_progcache_shmem_new();

  fd_pubkey_t key  = test_key( 42UL );
  fd_prog_load_env_t load_env = { .features = g_features, .feature_slot = 0UL };

  test_account_t acc;
  test_account_init( &acc, &key, &fd_solana_bpf_loader_deprecated_program_id, 1, valid_program_data, valid_program_data_sz );

  fd_progcache_join_t admin[1]; FD_TEST( fd_progcache_shmem_join( admin, shmem ) );

  for( ulong i=0UL; i<ITER_DEFAULT; i++ ) {
    fd_progcache_fork_id_t xid1 = fd_progcache_attach_child( admin, fd_progcache_fork_id_initial() );
    fd_progcache_fork_id_t xid2 = fd_progcache_attach_child( admin, fd_progcache_fork_id_initial() );

    {
      fd_progcache_t tmp[1];
      FD_TEST( fd_progcache_join( tmp, shmem, g_fiber[ 0 ].scratch, FD_PROGCACHE_SCRATCH_FOOTPRINT ) );
      fd_progcache_rec_t * rec;
      rec = fd_progcache_pull( tmp, xid1, &key, &load_env, acc.entry );
      FD_TEST( rec ); fd_progcache_rec_close( tmp, rec );
      rec = fd_progcache_pull( tmp, xid2, &key, &load_env, acc.entry );
      FD_TEST( rec ); fd_progcache_rec_close( tmp, rec );
      fd_progcache_leave( tmp, NULL );
    }

    fd_racesan_weave_t w[1];
    fd_racesan_weave_new( w );
    fd_racesan_weave_add( w, fiber_peek(         &g_fiber[ 0 ], shmem, xid1, &key ) );
    fd_racesan_weave_add( w, fiber_peek(         &g_fiber[ 1 ], shmem, xid2, &key ) );
    fd_racesan_weave_add( w, fiber_advance_root( &g_fiber[ 2 ], shmem, xid1 ) );

    metrics_reset();
    fd_racesan_weave_exec_rand( w, i, STEP_MAX );
    FD_TEST( !w->rem_cnt );
    metrics_check_no_oom();

    fd_racesan_weave_delete( w );
    fiber_delete( &g_fiber[ 0 ] );
    fiber_delete( &g_fiber[ 1 ] );
    fiber_delete( &g_fiber[ 2 ] );
    FD_TEST( !fd_progcache_verify( admin ) );
    test_progcache_reset( admin );
  }

  FD_TEST( fd_progcache_shmem_leave( admin, NULL ) );
  test_progcache_shmem_delete( shmem );
}

/* test_inject_at_hook verifies that racesan hooks fire correctly
   during advance_root */

FD_UNIT_TEST( inject_at_hook ) {
  fd_progcache_shmem_t * shmem = test_progcache_shmem_new();

  fd_pubkey_t key  = test_key( 42UL );
  fd_prog_load_env_t load_env = { .features = g_features, .feature_slot = 0UL };

  test_account_t acc;
  test_account_init( &acc, &key, &fd_solana_bpf_loader_deprecated_program_id, 1, valid_program_data, valid_program_data_sz );

  fd_progcache_join_t admin[1]; FD_TEST( fd_progcache_shmem_join( admin, shmem ) );

  fd_progcache_fork_id_t xid1 = fd_progcache_attach_child( admin, fd_progcache_fork_id_initial() );

  {
    fd_progcache_t tmp[1];
    FD_TEST( fd_progcache_join( tmp, shmem, g_fiber[ 0 ].scratch, FD_PROGCACHE_SCRATCH_FOOTPRINT ) );
    fd_progcache_rec_t * rec = fd_progcache_pull( tmp, xid1, &key, &load_env, acc.entry );
    FD_TEST( rec );
    fd_progcache_rec_close( tmp, rec );
    fd_progcache_leave( tmp, NULL );
  }

  fd_racesan_async_t * a = fiber_advance_root( &g_fiber[ 0 ], shmem, xid1 );

  for(;;) {
    int ret = fd_racesan_async_step( a );
    if( ret==FD_RACESAN_ASYNC_RET_EXIT ) break;
    FD_TEST( ret==FD_RACESAN_ASYNC_RET_HOOK );
  }

  fiber_delete( &g_fiber[ 0 ] );
  FD_TEST( fd_progcache_shmem_leave( admin, NULL ) );
  test_progcache_shmem_delete( shmem );
}

/* test_publish_reclaim_evicted races advance_root against eviction
   where the evicted record belongs to the txn being published */

FD_UNIT_TEST( publish_reclaim_evicted ) {
  fd_progcache_shmem_t * shmem = test_progcache_shmem_new();

  fd_pubkey_t key  = test_key( 42UL );
  fd_prog_load_env_t load_env = { .features = g_features, .feature_slot = 0UL };

  test_account_t acc;
  test_account_init( &acc, &key, &fd_solana_bpf_loader_deprecated_program_id, 1, valid_program_data, valid_program_data_sz );

  fd_progcache_join_t admin[1]; FD_TEST( fd_progcache_shmem_join( admin, shmem ) );

  for( ulong i=0UL; i<ITER_DEFAULT; i++ ) {
    fd_progcache_fork_id_t xid1 = fd_progcache_attach_child( admin, fd_progcache_fork_id_initial() );

    {
      fd_progcache_t tmp[1];
      FD_TEST( fd_progcache_join( tmp, shmem, g_fiber[ 0 ].scratch, FD_PROGCACHE_SCRATCH_FOOTPRINT ) );
      fd_progcache_rec_t * rec = fd_progcache_pull( tmp, xid1, &key, &load_env, acc.entry );
      FD_TEST( rec );
      fd_progcache_rec_close( tmp, rec );
      fd_progcache_leave( tmp, NULL );
    }

    fd_racesan_weave_t w[1];
    fd_racesan_weave_new( w );
    fd_racesan_weave_add( w, fiber_evict(        &g_fiber[ 0 ], shmem, valid_program_data_sz ) );
    fd_racesan_weave_add( w, fiber_advance_root( &g_fiber[ 1 ], shmem, xid1 ) );

    metrics_reset();
    fd_racesan_weave_exec_rand( w, i, STEP_MAX );
    FD_TEST( !w->rem_cnt );

    fd_racesan_weave_delete( w );
    fiber_delete( &g_fiber[ 0 ] );
    fiber_delete( &g_fiber[ 1 ] );
    FD_TEST( !fd_progcache_verify( admin ) );
    test_progcache_reset( admin );
  }

  FD_TEST( fd_progcache_shmem_leave( admin, NULL ) );
  test_progcache_shmem_delete( shmem );
}

/* test_root_evict_two races advance_root against eviction with
   two different programs populated on two sibling forks */

FD_UNIT_TEST( root_evict_two ) {
  fd_progcache_shmem_t * shmem = test_progcache_shmem_new();

  fd_pubkey_t ka   = test_key( 1UL );
  fd_pubkey_t kb   = test_key( 2UL );
  fd_prog_load_env_t load_env = { .features = g_features, .feature_slot = 0UL };

  test_account_t acc_a;
  test_account_init( &acc_a, &ka, &fd_solana_bpf_loader_deprecated_program_id, 1, valid_program_data, valid_program_data_sz );
  test_account_t acc_b;
  test_account_init( &acc_b, &kb, &fd_solana_bpf_loader_deprecated_program_id, 1, valid_program_data, valid_program_data_sz );

  fd_progcache_join_t admin[1]; FD_TEST( fd_progcache_shmem_join( admin, shmem ) );

  for( ulong i=0UL; i<ITER_DEFAULT; i++ ) {
    fd_progcache_fork_id_t xid1 = fd_progcache_attach_child( admin, fd_progcache_fork_id_initial() );
    fd_progcache_fork_id_t xid2 = fd_progcache_attach_child( admin, fd_progcache_fork_id_initial() );

    {
      fd_progcache_t tmp[1];
      FD_TEST( fd_progcache_join( tmp, shmem, g_fiber[ 0 ].scratch, FD_PROGCACHE_SCRATCH_FOOTPRINT ) );
      fd_progcache_rec_t * rec;
      rec = fd_progcache_pull( tmp, xid1, &ka, &load_env, acc_a.entry );
      FD_TEST( rec ); fd_progcache_rec_close( tmp, rec );
      rec = fd_progcache_pull( tmp, xid2, &kb, &load_env, acc_b.entry );
      FD_TEST( rec ); fd_progcache_rec_close( tmp, rec );
      fd_progcache_leave( tmp, NULL );
    }

    fd_racesan_weave_t w[1];
    fd_racesan_weave_new( w );
    fd_racesan_weave_add( w, fiber_advance_root( &g_fiber[ 0 ], shmem, xid1 ) );
    fd_racesan_weave_add( w, fiber_evict(        &g_fiber[ 1 ], shmem, valid_program_data_sz ) );

    metrics_reset();
    fd_racesan_weave_exec_rand( w, i, STEP_MAX );
    FD_TEST( !w->rem_cnt );
    metrics_check_no_oom();

    fd_racesan_weave_delete( w );
    fiber_delete( &g_fiber[ 0 ] );
    fiber_delete( &g_fiber[ 1 ] );
    FD_TEST( !fd_progcache_verify( admin ) );
    test_progcache_reset( admin );
  }

  FD_TEST( fd_progcache_shmem_leave( admin, NULL ) );
  test_progcache_shmem_delete( shmem );
}

/* test_publish_evict_stale races advance_root against clock eviction
   where the evicted record's CLOCK bits are stale.
   Reproduces the crash from auditor-internal#460 */

FD_UNIT_TEST( publish_evict_stale ) {
  fd_progcache_shmem_t * shmem = test_progcache_shmem_new();

  fd_pubkey_t key  = test_key( 42UL );

  fd_prog_load_env_t load_env_root  = { .features = g_features, .feature_slot = 0UL };
  fd_prog_load_env_t load_env_child = { .features = g_features, .feature_slot = 2UL };

  test_account_t acc;
  test_account_init( &acc, &key, &fd_solana_bpf_loader_deprecated_program_id, 1, valid_program_data, valid_program_data_sz );

  fd_progcache_join_t admin[1]; FD_TEST( fd_progcache_shmem_join( admin, shmem ) );

  for( ulong i=0UL; i<ITER_DEFAULT; i++ ) {

    /* Pre-populate the same program at root through a real txn */
    fd_progcache_fork_id_t xid_pre;
    {
      xid_pre = fd_progcache_attach_child( admin, fd_progcache_fork_id_initial() );
      fd_progcache_t tmp[1];
      FD_TEST( fd_progcache_join( tmp, shmem, g_fiber[ 0 ].scratch, FD_PROGCACHE_SCRATCH_FOOTPRINT ) );
      fd_progcache_rec_t * rec = fd_progcache_pull( tmp, xid_pre, &key, &load_env_root, acc.entry );
      FD_TEST( rec );
      fd_progcache_rec_close( tmp, rec );
      fd_progcache_leave( tmp, NULL );
      fd_progcache_advance_root( admin, xid_pre );
    }

    /* Create child fork and populate the same key under xid1's txn
       Peek won't hit the root record because slot 2 != slot 0. */
    fd_progcache_fork_id_t xid1 = fd_progcache_attach_child( admin, xid_pre );
    {
      fd_progcache_t tmp[1];
      FD_TEST( fd_progcache_join( tmp, shmem, g_fiber[ 0 ].scratch, FD_PROGCACHE_SCRATCH_FOOTPRINT ) );
      fd_progcache_rec_t * rec = fd_progcache_pull( tmp, xid1, &key, &load_env_child, acc.entry );
      FD_TEST( rec );
      fd_progcache_rec_close( tmp, rec );
      fd_progcache_leave( tmp, NULL );
    }

    /* Race advance_root (which gc's old root and retags child to
       root) against clock eviction (which may see stale CLOCK bits
       for the gc'd record).  Request evicting 2 records so that
       clock_evict does a full 2*rec_max scan, wrapping around to
       revisit entries whose visited bits were cleared on pass 1. */
    fd_racesan_weave_t w[1];
    fd_racesan_weave_new( w );
    fd_racesan_weave_add( w, fiber_advance_root( &g_fiber[ 0 ], shmem, xid1 ) );
    fd_racesan_weave_add( w, fiber_evict(        &g_fiber[ 1 ], shmem, valid_program_data_sz ) );

    metrics_reset();
    fd_racesan_weave_exec_rand( w, i, STEP_MAX );
    FD_TEST( !w->rem_cnt );

    fd_racesan_weave_delete( w );
    fiber_delete( &g_fiber[ 0 ] );
    fiber_delete( &g_fiber[ 1 ] );
    FD_TEST( !fd_progcache_verify( admin ) );
    test_progcache_reset( admin );
  }

  FD_TEST( fd_progcache_shmem_leave( admin, NULL ) );
  test_progcache_shmem_delete( shmem );
}

FD_UNIT_TEST( evict_reclaim_reuse ) {
  fd_progcache_shmem_t * shmem = test_progcache_shmem_new();

  fd_pubkey_t key1 = test_key( 1UL );
  fd_pubkey_t key2 = test_key( 2UL );
  fd_prog_load_env_t load_env = { .features = g_features, .feature_slot = 0UL };

  test_account_t acc1, acc2;
  test_account_init( &acc1, &key1, &fd_solana_bpf_loader_deprecated_program_id, 1, valid_program_data, valid_program_data_sz );
  test_account_init( &acc2, &key2, &fd_solana_bpf_loader_deprecated_program_id, 1, valid_program_data, valid_program_data_sz );

  fd_progcache_join_t admin[1]; FD_TEST( fd_progcache_shmem_join( admin, shmem ) );

  fd_progcache_fork_id_t xid1 = fd_progcache_attach_child( admin, fd_progcache_fork_id_initial() );

  /* Populate key1 */
  fd_progcache_rec_t * rec_old;
  {
    fd_progcache_t tmp[1];
    FD_TEST( fd_progcache_join( tmp, shmem, g_fiber[ 1 ].scratch, FD_PROGCACHE_SCRATCH_FOOTPRINT ) );
    rec_old = fd_progcache_pull( tmp, xid1, &key1, &load_env, acc1.entry );
    FD_TEST( rec_old );
    fd_progcache_rec_close( tmp, rec_old );
    fd_progcache_leave( tmp, NULL );
  }
  ulong rec_idx = (ulong)( rec_old - admin->rec.ele );

  /* Only rooted records are evictable, and a rooted record stays visible to the
     fresh child used for the pulls below. */
  fd_progcache_advance_root( admin, xid1 );
  xid1 = fd_progcache_attach_child( admin, xid1 );

  /* Clear the visited flag so the CLOCK hand picks this record */
  __atomic_fetch_and( &admin->rec.ele[ rec_idx ].state, (uchar)~FD_PROGCACHE_REC_VISITED, __ATOMIC_RELAXED );

  /* Aim the next ticket at this record: the scan examines
     rec_base[c] + (ticket % class_max[c]). */
  ulong hand_cls = fd_progcache_rec_class( shmem, rec_idx );
  shmem->cache.clock_hand[ hand_cls ].val = rec_idx - shmem->cache.rec_base[ hand_cls ];

  /* Start an eviction scan; pause it with the victim chosen and its key
     snapshotted, right before the claim. */
  fd_racesan_async_t * e = fiber_evict( &g_fiber[ 0 ], shmem, valid_program_data_sz );
  FD_TEST( fd_racesan_async_step_until( e, "prog_clock_evict:pre_delete", STEP_MAX )==FD_RACESAN_ASYNC_RET_HOOK );

  /* Retire the record behind the paused scan's back and release its slot. */
  FD_TEST( fd_prog_delete_rec( admin, rec_old )>=0L );
  FD_TEST( fd_prog_reclaim_work( admin )==1UL );

  /* Reuse the slot for a different program */
  fd_progcache_rec_t * rec_new;
  {
    fd_progcache_t tmp[1];
    FD_TEST( fd_progcache_join( tmp, shmem, g_fiber[ 1 ].scratch, FD_PROGCACHE_SCRATCH_FOOTPRINT ) );
    rec_new = fd_progcache_pull( tmp, xid1, &key2, &load_env, acc2.entry );
    FD_TEST( rec_new );
    fd_progcache_rec_close( tmp, rec_new );
    fd_progcache_leave( tmp, NULL );
  }
  FD_TEST( rec_new==rec_old ); /* pool slot was reused */

  /* Run the eviction scan to completion.  Its claim was decided under key1,
     which is no longer mapped here, so it must fail rather than take the new
     record. */
  for(;;) {
    int ret = fd_racesan_async_step( e );
    if( ret==FD_RACESAN_ASYNC_RET_EXIT ) break;
    FD_TEST( ret==FD_RACESAN_ASYNC_RET_HOOK );
  }
  fiber_delete( &g_fiber[ 0 ] );

  /* The new record must still be marked existing (evictable) */
  FD_TEST( __atomic_load_n( &admin->rec.ele[ rec_idx ].state, __ATOMIC_RELAXED ) & FD_PROGCACHE_REC_LIVE );
  FD_TEST( !fd_progcache_verify( admin ) );

  fd_progcache_cancel_fork( admin, xid1 );
  FD_TEST( !fd_progcache_verify( admin ) );
  FD_TEST( fd_progcache_shmem_leave( admin, NULL ) );
  test_progcache_shmem_delete( shmem );
}

/* A record is reachable from the map the instant the chain is released, so its
   state must already be LIVE by then -- fd_progcache_verify asserts it. */

FD_UNIT_TEST( publish_verify_live ) {
  fd_progcache_shmem_t * shmem = test_progcache_shmem_new();

  fd_pubkey_t key = test_key( 42UL );
  fd_prog_load_env_t load_env = { .features = g_features, .feature_slot = 0UL };
  test_account_t acc;
  test_account_init( &acc, &key, &fd_solana_bpf_loader_deprecated_program_id, 1, valid_program_data, valid_program_data_sz );

  fd_progcache_join_t admin[1]; FD_TEST( fd_progcache_shmem_join( admin, shmem ) );
  fd_progcache_fork_id_t xid = fd_progcache_attach_child( admin, fd_progcache_fork_id_initial() );

  /* Pause the pull with the record inserted and the chain still held. */
  fd_racesan_async_t * p = fiber_pull( &g_fiber[ 0 ], shmem, xid, &key, &load_env, acc.entry );
  FD_TEST( fd_racesan_async_step_until( p, "prog_push:post_map_insert", STEP_MAX )==FD_RACESAN_ASYNC_RET_HOOK );

  FD_TEST( !fd_progcache_verify( admin ) ); /* mapped => LIVE, mid-publish */

  for(;;) {
    int ret = fd_racesan_async_step( p );
    if( ret==FD_RACESAN_ASYNC_RET_EXIT ) break;
    FD_TEST( ret==FD_RACESAN_ASYNC_RET_HOOK );
  }
  fiber_delete( &g_fiber[ 0 ] );

  FD_TEST( !fd_progcache_verify( admin ) );
  fd_progcache_cancel_fork( admin, xid );
  FD_TEST( !fd_progcache_verify( admin ) );
  FD_TEST( fd_progcache_shmem_leave( admin, NULL ) );
  test_progcache_shmem_delete( shmem );
}

FD_UNIT_TEST( delete_reclaim_reuse_pair ) {
  fd_progcache_shmem_t * shmem = test_progcache_shmem_new();

  fd_pubkey_t key1 = test_key( 1UL );
  fd_pubkey_t key2 = test_key( 2UL );
  fd_prog_load_env_t load_env = { .features = g_features, .feature_slot = 0UL };

  test_account_t acc1, acc2;
  test_account_init( &acc1, &key1, &fd_solana_bpf_loader_deprecated_program_id, 1, valid_program_data, valid_program_data_sz );
  test_account_init( &acc2, &key2, &fd_solana_bpf_loader_deprecated_program_id, 1, valid_program_data, valid_program_data_sz );

  fd_progcache_join_t admin[1]; FD_TEST( fd_progcache_shmem_join( admin, shmem ) );

  fd_progcache_fork_id_t xid1 = fd_progcache_attach_child( admin, fd_progcache_fork_id_initial() );

  fd_progcache_rec_t * rec_old;
  {
    fd_progcache_t tmp[1];
    FD_TEST( fd_progcache_join( tmp, shmem, g_fiber[ 1 ].scratch, FD_PROGCACHE_SCRATCH_FOOTPRINT ) );
    rec_old = fd_progcache_pull( tmp, xid1, &key1, &load_env, acc1.entry );
    FD_TEST( rec_old );
    fd_progcache_rec_close( tmp, rec_old );
    fd_progcache_leave( tmp, NULL );
  }

  /* Only a detached (rooted) zombie is collectable, and a rooted record stays
     visible to the fresh child used for the pulls below. */
  fd_progcache_advance_root( admin, xid1 );
  xid1 = fd_progcache_attach_child( admin, xid1 );

  fd_racesan_async_t * d = fiber_delete_rec( &g_fiber[ 0 ], shmem, rec_old );
  FD_TEST( fd_racesan_async_step_until( d, "prog_delete_rec:post_txn_add", STEP_MAX )==FD_RACESAN_ASYNC_RET_HOOK );

  FD_TEST( fd_prog_delete_rec( admin, rec_old )>=0L );
  FD_TEST( fd_prog_reclaim_work( admin )==1UL );

  fd_progcache_rec_t * rec_new;
  {
    fd_progcache_t tmp[1];
    FD_TEST( fd_progcache_join( tmp, shmem, g_fiber[ 1 ].scratch, FD_PROGCACHE_SCRATCH_FOOTPRINT ) );
    rec_new = fd_progcache_pull( tmp, xid1, &key2, &load_env, acc2.entry );
    FD_TEST( rec_new );
    fd_progcache_rec_close( tmp, rec_new );
    fd_progcache_leave( tmp, NULL );
  }
  FD_TEST( rec_new==rec_old );
  FD_TEST( query_rec_exact( admin, xid1, &key2 )==rec_new );

  int done = 0;
  for( ulong step=0UL; step<STEP_MAX; step++ ) {
    int ret = fd_racesan_async_step( d );
    if( ret==FD_RACESAN_ASYNC_RET_EXIT ) {
      done = 1;
      break;
    }
    FD_TEST( ret==FD_RACESAN_ASYNC_RET_HOOK );
  }
  FD_TEST( done );
  FD_TEST( g_fiber[ 0 ].delete_rec.result==-1L );
  fiber_delete( &g_fiber[ 0 ] );

  FD_TEST( query_rec_exact( admin, xid1, &key2 )==rec_new );
  FD_TEST( !fd_progcache_verify( admin ) );

  fd_progcache_cancel_fork( admin, xid1 );
  FD_TEST( !fd_progcache_verify( admin ) );
  FD_TEST( fd_progcache_shmem_leave( admin, NULL ) );
  test_progcache_shmem_delete( shmem );
}

FD_UNIT_TEST( cancel_reclaim_reuse_next ) {
  fd_progcache_shmem_t * shmem = test_progcache_shmem_new();

  fd_pubkey_t key1 = test_key( 1UL );
  fd_pubkey_t key2 = test_key( 2UL );
  fd_prog_load_env_t load_env = { .features = g_features, .feature_slot = 0UL };

  test_account_t acc1, acc2;
  test_account_init( &acc1, &key1, &fd_solana_bpf_loader_deprecated_program_id, 1, valid_program_data, valid_program_data_sz );
  test_account_init( &acc2, &key2, &fd_solana_bpf_loader_deprecated_program_id, 1, valid_program_data, valid_program_data_sz );

  fd_progcache_join_t admin[1]; FD_TEST( fd_progcache_shmem_join( admin, shmem ) );

  fd_progcache_fork_id_t xid1 = fd_progcache_attach_child( admin, fd_progcache_fork_id_initial() );

  fd_progcache_rec_t * rec1;
  fd_progcache_rec_t * rec2;
  {
    fd_progcache_t tmp[1];
    FD_TEST( fd_progcache_join( tmp, shmem, g_fiber[ 1 ].scratch, FD_PROGCACHE_SCRATCH_FOOTPRINT ) );
    rec1 = fd_progcache_pull( tmp, xid1, &key1, &load_env, acc1.entry );
    FD_TEST( rec1 );
    fd_progcache_rec_close( tmp, rec1 );
    rec2 = fd_progcache_pull( tmp, xid1, &key2, &load_env, acc2.entry );
    FD_TEST( rec2 );
    fd_progcache_rec_close( tmp, rec2 );
    fd_progcache_leave( tmp, NULL );
  }

  uint rec2_idx = (uint)( rec2 - admin->rec.ele );
  FD_TEST( rec2_idx!=0U );
  FD_TEST( rec1->next_idx==rec2_idx );

  FD_TEST( fd_prog_delete_rec( admin, rec1 )>=0L );

  fd_racesan_async_t * c = fiber_cancel( &g_fiber[ 0 ], shmem, xid1 );
  FD_TEST( fd_racesan_async_step_until( c, "prog_cancel_one:post_orphan", STEP_MAX )==FD_RACESAN_ASYNC_RET_HOOK );

  FD_TEST( fd_prog_reclaim_work( admin )==1UL );

  fd_progcache_rec_t * rec_reuse = fd_progcache_rec_acquire( admin, 4096UL ); /* class 0: LIFO free list returns rec1 */
  FD_TEST( rec_reuse==rec1 );
  FD_TEST( rec_reuse->next_idx==0U );

  int done = 0;
  for( ulong step=0UL; step<STEP_MAX; step++ ) {
    int ret = fd_racesan_async_step( c );
    if( ret==FD_RACESAN_ASYNC_RET_EXIT ) {
      done = 1;
      break;
    }
    FD_TEST( ret==FD_RACESAN_ASYNC_RET_HOOK );
  }
  FD_TEST( done );
  fiber_delete( &g_fiber[ 0 ] );

  fd_progcache_rec_abandon( admin, rec_reuse );

  FD_TEST( !query_rec_exact( admin, xid1, &key1 ) );
  FD_TEST( !query_rec_exact( admin, xid1, &key2 ) );
  FD_TEST( !fd_progcache_verify( admin ) );

  FD_TEST( fd_progcache_shmem_leave( admin, NULL ) );
  test_progcache_shmem_delete( shmem );
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  ulong cpu_idx = fd_tile_cpu_id( fd_tile_idx() );
  if( cpu_idx>fd_shmem_cpu_cnt() ) cpu_idx = 0UL;

  char const * _page_sz  = fd_env_strip_cmdline_cstr ( &argc, &argv, "--page-sz",   NULL, "gigantic"                   );
  ulong        page_cnt  = fd_env_strip_cmdline_ulong( &argc, &argv, "--page-cnt",  NULL, 1UL                          );
  ulong        numa_idx  = fd_env_strip_cmdline_ulong( &argc, &argv, "--numa-idx",  NULL, fd_shmem_numa_idx( cpu_idx ) );

  ulong page_sz = fd_cstr_to_shmem_page_sz( _page_sz );
  if( FD_UNLIKELY( !page_sz ) ) FD_LOG_ERR(( "unsupported --page-sz" ));

  FD_LOG_NOTICE(( "Creating workspace (--page-cnt %lu, --page-sz %s, --numa-idx %lu)", page_cnt, _page_sz, numa_idx ));
  wksp = fd_wksp_new_anonymous( page_sz, page_cnt, fd_shmem_cpu_idx( numa_idx ), "wksp", 0UL );
  FD_TEST( wksp );

  fd_unit_tests( argc, argv );

  fd_wksp_delete_anonymous( wksp );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
