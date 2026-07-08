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

FD_IMPORT_BINARY( valid_program_data, "src/ballet/sbpf/fixtures/hello_solana_program.so" );

int const fd_progcache_use_malloc = 1;

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
      ulong            rec_min;
      ulong            heap_min;
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
  if( res ) fd_progcache_rec_close( f->pull.cache, res );
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
  fd_prog_clock_evict( f->evict.cache, f->evict.rec_min, f->evict.heap_min );
}

static fd_racesan_async_t *
fiber_evict( fiber_t * fiber,
             void *    shmem,
             ulong     rec_min,
             ulong     heap_min ) {
  FD_TEST( fd_progcache_join( fiber->cache, shmem, fiber->scratch, sizeof(fiber->scratch) ) );
  fiber->evict.cache    = fiber->cache;
  fiber->evict.rec_min  = rec_min;
  fiber->evict.heap_min = heap_min;
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
  FD_TEST( fd_progcache_metrics_default.oom_heap_cnt==0UL );
  FD_TEST( fd_progcache_metrics_default.oom_desc_cnt==0UL );
}

static fd_progcache_shmem_t *
test_progcache_shmem_new( void ) {
  fd_wksp_reset( wksp, 1UL );
  ulong txn_max           = 16UL;
  ulong progcache_rec_max = 32UL;
  ulong wksp_tag          =  1UL;

  fd_progcache_shmem_t * shmem = fd_wksp_alloc_laddr( wksp, fd_progcache_shmem_align(), fd_progcache_shmem_footprint( txn_max, progcache_rec_max ), wksp_tag );
  FD_TEST( fd_progcache_shmem_new( shmem, wksp_tag, 1UL, txn_max, progcache_rec_max ) );
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

/* test_pull_pull races two loads for the same program */

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
    FD_TEST( fd_progcache_metrics_default.hit_cnt   >=1UL );
    FD_TEST( fd_progcache_metrics_default.miss_cnt  <=1UL );
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
    fd_racesan_weave_add( w, fiber_evict(        &g_fiber[ 1 ], shmem, 1UL, 0UL ) );

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
    fd_racesan_weave_add( w, fiber_evict(        &g_fiber[ 0 ], shmem, 1UL, 0UL ) );
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
    fd_racesan_weave_add( w, fiber_evict(        &g_fiber[ 1 ], shmem, 1UL, 0UL ) );

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
    fd_racesan_weave_add( w, fiber_evict(        &g_fiber[ 1 ], shmem, 2UL, 0UL ) );

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
  ulong rec_idx = (ulong)( rec_old - admin->rec.pool->ele );

  /* Clear the visited bit so the CLOCK hand picks this slot */
  atomic_ulong * slot_p = fd_prog_cbits_slot( admin->clock.bits, rec_idx );
  atomic_fetch_and_explicit( slot_p, ~( 1UL<<fd_prog_visited_bit( rec_idx ) ), memory_order_relaxed );

  /* Remove the record from the map (as fork cancellation would),
     deferring reclamation to admin's local reclaim list */
  FD_TEST( fd_prog_delete_rec( admin, rec_old )>=0L );

  shmem->clock.head = rec_idx;

  /* Start an eviction scan; pause it right after it observed the stale
     "exists" bit and its delete attempt failed, but before it writes
     back to the cbits */
  fd_racesan_async_t * e = fiber_evict( &g_fiber[ 0 ], shmem, 1UL, 0UL );
  FD_TEST( fd_racesan_async_step_until( e, "prog_clock_evict:post_load_bits", STEP_MAX )==FD_RACESAN_ASYNC_RET_HOOK );
  FD_TEST( fd_racesan_async_step_until( e, "prog_clock_evict:post_delete",    STEP_MAX )==FD_RACESAN_ASYNC_RET_HOOK );

  /* Reclaim the old record, releasing its pool slot */
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

  /* Run the eviction scan to completion.  It must leave the new
     record's cbits alone. */
  for(;;) {
    int ret = fd_racesan_async_step( e );
    if( ret==FD_RACESAN_ASYNC_RET_EXIT ) break;
    FD_TEST( ret==FD_RACESAN_ASYNC_RET_HOOK );
  }
  fiber_delete( &g_fiber[ 0 ] );

  /* The new record must still be marked existing (evictable) */
  ulong slot_val = atomic_load_explicit( slot_p, memory_order_relaxed );
  FD_TEST( fd_ulong_extract_bit( slot_val, fd_prog_exists_bit( rec_idx ) ) );
  FD_TEST( !fd_progcache_verify( admin ) );

  fd_progcache_cancel_fork( admin, xid1 );
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

  uint rec2_idx = (uint)( rec2 - admin->rec.pool->ele );
  FD_TEST( rec2_idx!=0U );
  FD_TEST( rec1->next_idx==rec2_idx );

  FD_TEST( fd_prog_delete_rec( admin, rec1 )>=0L );

  fd_racesan_async_t * c = fiber_cancel( &g_fiber[ 0 ], shmem, xid1 );
  FD_TEST( fd_racesan_async_step_until( c, "prog_cancel_one:post_orphan", STEP_MAX )==FD_RACESAN_ASYNC_RET_HOOK );

  FD_TEST( fd_prog_reclaim_work( admin )==1UL );

  fd_progcache_rec_t * rec_reuse = fd_prog_recp_acquire( admin->rec.pool );
  FD_TEST( rec_reuse==rec1 );
  memset( rec_reuse, 0, sizeof(fd_progcache_rec_t) );
  rec_reuse->exists       = 1;
  rec_reuse->txn_idx      = UINT_MAX;
  rec_reuse->reclaim_next = UINT_MAX;
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

  rec_reuse->exists = 0;
  fd_prog_recp_release( admin->rec.pool, rec_reuse );

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
