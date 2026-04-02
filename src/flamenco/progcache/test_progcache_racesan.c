#include "fd_progcache_admin.h"
#include "fd_progcache_user.h"
#include "fd_progcache_reclaim.h"
#include "test_progcache_common.c"
#include "fd_prog_load.h"
#include "../runtime/fd_system_ids.h"
#include "../features/fd_features.h"
#include "../../util/racesan/fd_racesan_async.h"
#include "../../util/racesan/fd_racesan_weave.h"

FD_IMPORT_BINARY( valid_program_data, "src/ballet/sbpf/fixtures/hello_solana_program.so" );

int const fd_progcache_use_malloc = 1;

static fd_features_t g_features[1];

#define FIBER_MAX       (4)
#define FIBER_STACK_MAX (1UL<<21)
#define ITER_DEFAULT    (4096UL)
#define STEP_MAX        (100000UL)

#define ROOT_XID ( (fd_xid_t) { .ul={1UL,0UL} } )

/* Declare fibers */

struct fiber {

  fd_racesan_async_t async[1];

  fd_progcache_t cache[1];

  uchar scratch[ FD_PROGCACHE_SCRATCH_FOOTPRINT ] __attribute__((aligned(FD_PROGCACHE_SCRATCH_ALIGN)));

  uchar stack[ FIBER_STACK_MAX ] __attribute__((aligned(64)));

  union {

    struct {
      fd_progcache_t *   cache;
      fd_xid_t           xid;
      fd_pubkey_t        prog_addr;
      fd_prog_load_env_t load_env;
      fd_accdb_ro_t *    prog_ro;
    } pull;

    struct {
      fd_progcache_t * cache;
      fd_xid_t         xid;
      fd_pubkey_t      prog_addr;
      ulong            revision_slot;
    } peek;

    struct {
      fd_progcache_t * cache;
      ulong            rec_min;
      ulong            heap_min;
    } evict;

    struct {
      fd_progcache_join_t * cache;
      fd_xid_t              xid;
    } advance_root;

    struct {
      fd_progcache_join_t * cache;
      fd_xid_t              xid;
    } cancel;

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
      f->pull.cache, &f->pull.xid, &f->pull.prog_addr, &f->pull.load_env, f->pull.prog_ro, fd_accdb_ref_owner( f->pull.prog_ro ) );
  if( res ) fd_progcache_rec_close( f->pull.cache, res );
}

static fd_racesan_async_t *
fiber_pull( fiber_t *                  fiber,
            void *                     shmem,
            fd_xid_t const *           xid,
            void const *               prog_addr,
            fd_prog_load_env_t const * load_env,
            fd_accdb_ro_t *            prog_ro ) {
  FD_TEST( fd_progcache_join( fiber->cache, shmem, fiber->scratch, sizeof(fiber->scratch) ) );
  fiber->pull.cache     = fiber->cache;
  fiber->pull.xid       = *xid;
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
      f->peek.cache, &f->peek.xid, &f->peek.prog_addr, f->peek.revision_slot );
  if( res ) fd_progcache_rec_close( f->peek.cache, res );
}

static fd_racesan_async_t *
fiber_peek( fiber_t *        fiber,
            void *           shmem,
            fd_xid_t const * xid,
            void const *     prog_addr,
            ulong            revision_slot ) {
  FD_TEST( fd_progcache_join( fiber->cache, shmem, fiber->scratch, sizeof(fiber->scratch) ) );
  fiber->peek.cache     = fiber->cache;
  fiber->peek.xid       = *xid;
  fiber->peek.prog_addr = FD_LOAD( fd_pubkey_t, prog_addr );
  fiber->peek.revision_slot = revision_slot;
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
  fd_progcache_advance_root( f->advance_root.cache, &f->advance_root.xid );
}

static fd_racesan_async_t *
fiber_advance_root( fiber_t *        fiber,
                    void *           shmem,
                    fd_xid_t const * xid ) {
  FD_TEST( fd_progcache_join( fiber->cache, shmem, fiber->scratch, sizeof(fiber->scratch) ) );
  fiber->advance_root.cache = (fd_progcache_join_t *)fiber->cache;
  fiber->advance_root.xid   = *xid;
  fd_racesan_async_new( fiber->async, fiber->stack+FIBER_STACK_MAX, FIBER_STACK_MAX, fiber_advance_root_exec, fiber );
  return fiber->async;
}

static void
fiber_cancel_exec( void * _ctx ) {
  fiber_t * f = _ctx;
  fd_progcache_cancel( f->cancel.cache, &f->cancel.xid );
}

static fd_racesan_async_t *
fiber_cancel( fiber_t *        fiber,
              void *           shmem,
              fd_xid_t const * xid ) {
  FD_TEST( fd_progcache_join( fiber->cache, shmem, fiber->scratch, sizeof(fiber->scratch) ) );
  fiber->cancel.cache = (fd_progcache_join_t *)fiber->cache;
  fiber->cancel.xid   = *xid;
  fd_racesan_async_new( fiber->async, fiber->stack+FIBER_STACK_MAX, FIBER_STACK_MAX, fiber_cancel_exec, fiber );
  return fiber->async;
}

static void
fiber_reclaim_exec( void * _ctx ) {
  fiber_t * f = _ctx;
  fd_prog_reclaim_work( f->cache->join );
}

static fd_racesan_async_t *
fiber_reclaim( fiber_t * fiber ) {
  FD_TEST( fiber->cache->join->shmem ); /* assume cache already joined */
  fd_racesan_async_new( fiber->async, fiber->stack+FIBER_STACK_MAX, FIBER_STACK_MAX, fiber_reclaim_exec, fiber );
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
test_progcache_shmem_new( fd_wksp_t * wksp ) {
  ulong txn_max           = 16UL;
  ulong progcache_rec_max = 32UL;
  ulong wksp_tag          =  1UL;

  fd_progcache_shmem_t * shmem = fd_wksp_alloc_laddr( wksp, fd_progcache_shmem_align(), fd_progcache_shmem_footprint( txn_max, progcache_rec_max ), wksp_tag );
  FD_TEST( fd_progcache_shmem_new( shmem, wksp_tag, 1UL, txn_max, progcache_rec_max ) );
  *shmem->txn.last_publish = ROOT_XID;
  return shmem;
}

static void
test_progcache_shmem_delete( fd_progcache_shmem_t * shmem ) {
  fd_wksp_free_laddr( fd_progcache_shmem_delete( shmem ) );
}

static void
test_progcache_clear( fd_progcache_join_t * join ) {
  fd_progcache_clear( join );
  *join->shmem->txn.last_publish = ROOT_XID;
}

/* TESTS **************************************************************/

/* test_pull_pull races two loads for the same program */

static void
test_pull_pull( fd_wksp_t * wksp ) {
  fd_progcache_shmem_t * shmem = test_progcache_shmem_new( wksp );

  fd_xid_t    xid = { .ul = { 1UL, 1UL } };
  fd_pubkey_t key = test_key( 42UL );
  fd_prog_load_env_t load_env = { .features = g_features, .epoch = 0UL, .epoch_slot0 = 0UL };

  test_account_t acc;
  test_account_init( &acc, &key, &fd_solana_bpf_loader_deprecated_program_id, 1, valid_program_data, valid_program_data_sz );

  fd_progcache_join_t admin[1]; FD_TEST( fd_progcache_shmem_join( admin, shmem ) );

  for( ulong i=0UL; i<ITER_DEFAULT; i++ ) {

    fd_racesan_weave_t w[1];
    fd_racesan_weave_new( w );
    fd_racesan_weave_add( w, fiber_pull( &g_fiber[ 0 ], shmem, &xid, &key, &load_env, acc.ro ) );
    fd_racesan_weave_add( w, fiber_pull( &g_fiber[ 1 ], shmem, &xid, &key, &load_env, acc.ro ) );

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
    test_progcache_clear( admin );
  }

  FD_TEST( fd_progcache_shmem_leave( admin, NULL ) );
  test_progcache_shmem_delete( shmem );
}

/* test_pull_peek races a cache fill against a read-only cache lookup */

static void
test_pull_peek( fd_wksp_t * wksp ) {
  fd_progcache_shmem_t * shmem = test_progcache_shmem_new( wksp );

  fd_xid_t    xid = ROOT_XID;
  fd_pubkey_t key = test_key( 42UL );
  fd_prog_load_env_t load_env = { .features = g_features, .epoch = 0UL, .epoch_slot0 = 0UL };

  test_account_t acc;
  test_account_init( &acc, &key, &fd_solana_bpf_loader_deprecated_program_id, 1, valid_program_data, valid_program_data_sz );

  fd_progcache_join_t admin[1]; FD_TEST( fd_progcache_shmem_join( admin, shmem ) );

  for( ulong i=0UL; i<ITER_DEFAULT; i++ ) {
    fd_racesan_weave_t w[1];
    fd_racesan_weave_new( w );
    fd_racesan_weave_add( w, fiber_pull( &g_fiber[ 0 ], shmem, &xid, &key, &load_env, acc.ro ) );
    fd_racesan_weave_add( w, fiber_peek( &g_fiber[ 1 ], shmem, &xid, &key, 1UL ) );

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
    test_progcache_clear( admin );
  }

  FD_TEST( fd_progcache_shmem_leave( admin, NULL ) );
  test_progcache_shmem_delete( shmem );
}

/* test_pull_root races a cache fill against advance_root */

static void
test_pull_root( fd_wksp_t * wksp ) {
  fd_progcache_shmem_t * shmem = test_progcache_shmem_new( wksp );

  fd_xid_t    xid0 = ROOT_XID;
  fd_xid_t    xid1 = { .ul = { 2UL, 1UL } };
  fd_pubkey_t key  = test_key( 42UL );
  fd_prog_load_env_t load_env = { .features = g_features, .epoch = 0UL, .epoch_slot0 = 0UL };

  test_account_t acc;
  test_account_init( &acc, &key, &fd_solana_bpf_loader_deprecated_program_id, 1, valid_program_data, valid_program_data_sz );
  fd_progcache_join_t admin[1]; FD_TEST( fd_progcache_shmem_join( admin, shmem ) );

  for( ulong i=0UL; i<ITER_DEFAULT; i++ ) {
    fd_progcache_attach_child( admin, &xid0, &xid1 );

    fd_racesan_weave_t w[1];
    fd_racesan_weave_new( w );
    fd_racesan_weave_add( w, fiber_pull( &g_fiber[ 0 ], shmem, &xid1, &key, &load_env, acc.ro ) );
    fd_racesan_weave_add( w, fiber_advance_root( &g_fiber[ 1 ], shmem, &xid1 ) );

    metrics_reset();
    fd_racesan_weave_exec_rand( w, i, STEP_MAX );
    FD_TEST( !w->rem_cnt );
    FD_TEST( fd_progcache_metrics_default.lookup_cnt==1UL );
    FD_TEST( fd_progcache_metrics_default.fill_cnt  ==1UL );
    FD_TEST( fd_progcache_metrics_default.hit_cnt   ==0UL );
    FD_TEST( fd_progcache_metrics_default.miss_cnt  ==1UL );
    if( !fd_progcache_admin_metrics_g.root_cnt ) {
      fd_progcache_rec_t * rec = fd_progcache_peek( g_fiber[ 0 ].cache, &xid1, &key, 0UL );
      FD_TEST( rec->txn_idx==UINT_MAX );
      FD_TEST( rec->next_idx==UINT_MAX );
      FD_TEST( rec->prev_idx==UINT_MAX );
      fd_progcache_rec_close( g_fiber[ 0 ].cache, rec );
    } else {
      FD_TEST( fd_progcache_admin_metrics_g.root_cnt==1UL );
    }
    metrics_check_no_oom();

    fd_racesan_weave_delete( w );
    fiber_delete( &g_fiber[ 0 ] );
    fiber_delete( &g_fiber[ 1 ] );
    FD_TEST( !fd_progcache_verify( admin ) );
    test_progcache_clear( admin );
  }

  FD_TEST( fd_progcache_shmem_leave( admin, NULL ) );
  test_progcache_shmem_delete( shmem );
}

/* test_cancel_peek races a cancel against a peek for a child txn.
   Pre-populates cache under xid0, then races cancel(xid1) vs peek(xid0). */

static void
test_cancel_peek( fd_wksp_t * wksp ) {
  fd_progcache_shmem_t * shmem = test_progcache_shmem_new( wksp );

  fd_xid_t    xid0 = ROOT_XID;
  fd_xid_t    xid1 = { .ul = { 2UL, 1UL } };
  fd_pubkey_t key  = test_key( 42UL );
  fd_prog_load_env_t load_env = { .features = g_features, .epoch = 0UL, .epoch_slot0 = 0UL };

  test_account_t acc;
  test_account_init( &acc, &key, &fd_solana_bpf_loader_deprecated_program_id, 1, valid_program_data, valid_program_data_sz );

  fd_progcache_join_t admin[1]; FD_TEST( fd_progcache_shmem_join( admin, shmem ) );

  for( ulong i=0UL; i<ITER_DEFAULT; i++ ) {
    /* Pre-populate the cache */
    {
      fd_progcache_t tmp[1];
      FD_TEST( fd_progcache_join( tmp, shmem, g_fiber[ 0 ].scratch, FD_PROGCACHE_SCRATCH_FOOTPRINT ) );
      fd_progcache_rec_t * rec = fd_progcache_pull( tmp, &xid0, &key, &load_env, acc.ro, fd_accdb_ref_owner( acc.ro ) );
      FD_TEST( rec );
      fd_progcache_rec_close( tmp, rec );
      fd_progcache_leave( tmp, NULL );
    }

    fd_progcache_attach_child( admin, &xid0, &xid1 );

    fd_racesan_weave_t w[1];
    fd_racesan_weave_new( w );
    fd_racesan_weave_add( w, fiber_cancel( &g_fiber[ 0 ], shmem, &xid1 ) );
    fd_racesan_weave_add( w, fiber_peek(   &g_fiber[ 1 ], shmem, &xid0, &key, 1UL ) );

    metrics_reset();
    fd_racesan_weave_exec_rand( w, i, STEP_MAX );
    FD_TEST( !w->rem_cnt );
    metrics_check_no_oom();

    fd_racesan_weave_delete( w );
    fiber_delete( &g_fiber[ 0 ] );
    fiber_delete( &g_fiber[ 1 ] );
    FD_TEST( !fd_progcache_verify( admin ) );
    test_progcache_clear( admin );
  }

  FD_TEST( fd_progcache_shmem_leave( admin, NULL ) );
  test_progcache_shmem_delete( shmem );
}

/* test_publish_evict races advance_root against clock eviction */

static void
test_publish_evict( fd_wksp_t * wksp ) {
  fd_progcache_shmem_t * shmem = test_progcache_shmem_new( wksp );

  fd_xid_t    xid0 = ROOT_XID;
  fd_xid_t    xid1 = { .ul = { 2UL, 1UL } };
  fd_pubkey_t key  = test_key( 42UL );
  fd_prog_load_env_t load_env = { .features = g_features, .epoch = 0UL, .epoch_slot0 = 0UL };

  test_account_t acc;
  test_account_init( &acc, &key, &fd_solana_bpf_loader_deprecated_program_id, 1, valid_program_data, valid_program_data_sz );

  fd_progcache_join_t admin[1]; FD_TEST( fd_progcache_shmem_join( admin, shmem ) );

  for( ulong i=0UL; i<ITER_DEFAULT; i++ ) {
    fd_progcache_attach_child( admin, &xid0, &xid1 );

    /* Pre-populate the cache */
    {
      fd_progcache_t tmp[1];
      FD_TEST( fd_progcache_join( tmp, shmem, g_fiber[ 0 ].scratch, FD_PROGCACHE_SCRATCH_FOOTPRINT ) );
      fd_progcache_rec_t * rec = fd_progcache_pull( tmp, &xid1, &key, &load_env, acc.ro, fd_accdb_ref_owner( acc.ro ) );
      FD_TEST( rec );
      fd_progcache_rec_close( tmp, rec );
      fd_progcache_leave( tmp, NULL );
    }

    fd_racesan_weave_t w[1];
    fd_racesan_weave_new( w );
    fd_racesan_weave_add( w, fiber_advance_root( &g_fiber[ 0 ], shmem, &xid1 ) );
    fd_racesan_weave_add( w, fiber_evict(        &g_fiber[ 1 ], shmem, 1UL, 0UL ) );

    metrics_reset();
    fd_racesan_weave_exec_rand( w, i, STEP_MAX );
    FD_TEST( !w->rem_cnt );

    fd_racesan_weave_delete( w );
    fiber_delete( &g_fiber[ 0 ] );
    fiber_delete( &g_fiber[ 1 ] );
    FD_TEST( !fd_progcache_verify( admin ) );
    test_progcache_clear( admin );
  }

  FD_TEST( fd_progcache_shmem_leave( admin, NULL ) );
  test_progcache_shmem_delete( shmem );
}

/* test_pull_root_peek races a pull, advance_root, and peek */

static void
test_pull_root_peek( fd_wksp_t * wksp ) {
  fd_progcache_shmem_t * shmem = test_progcache_shmem_new( wksp );

  fd_xid_t    xid0 = ROOT_XID;
  fd_xid_t    xid1 = { .ul = { 2UL, 1UL } };
  fd_pubkey_t key  = test_key( 42UL );
  fd_prog_load_env_t load_env = { .features = g_features, .epoch = 0UL, .epoch_slot0 = 0UL };

  test_account_t acc;
  test_account_init( &acc, &key, &fd_solana_bpf_loader_deprecated_program_id, 1, valid_program_data, valid_program_data_sz );

  fd_progcache_join_t admin[1]; FD_TEST( fd_progcache_shmem_join( admin, shmem ) );

  for( ulong i=0UL; i<ITER_DEFAULT; i++ ) {
    fd_progcache_attach_child( admin, &xid0, &xid1 );

    fd_racesan_weave_t w[1];
    fd_racesan_weave_new( w );
    fd_racesan_weave_add( w, fiber_pull(         &g_fiber[ 0 ], shmem, &xid1, &key, &load_env, acc.ro ) );
    fd_racesan_weave_add( w, fiber_advance_root( &g_fiber[ 1 ], shmem, &xid1 ) );
    fd_racesan_weave_add( w, fiber_peek(         &g_fiber[ 2 ], shmem, &xid1, &key, 1UL ) );

    metrics_reset();
    fd_racesan_weave_exec_rand( w, i, STEP_MAX );
    FD_TEST( !w->rem_cnt );
    FD_TEST( fd_progcache_metrics_default.lookup_cnt==1UL );
    metrics_check_no_oom();

    fd_racesan_weave_delete( w );
    fiber_delete( &g_fiber[ 0 ] );
    fiber_delete( &g_fiber[ 1 ] );
    fiber_delete( &g_fiber[ 2 ] );
    FD_TEST( !fd_progcache_verify( admin ) );
    test_progcache_clear( admin );
  }

  FD_TEST( fd_progcache_shmem_leave( admin, NULL ) );
  test_progcache_shmem_delete( shmem );
}

/* test_peek_root races a peek against advance_root */

static void
test_peek_root( fd_wksp_t * wksp ) {
  fd_progcache_shmem_t * shmem = test_progcache_shmem_new( wksp );

  fd_xid_t    xid0 = ROOT_XID;
  fd_xid_t    xid1 = { .ul = { 2UL, 1UL } };
  fd_pubkey_t key  = test_key( 42UL );
  fd_prog_load_env_t load_env = { .features = g_features, .epoch = 0UL, .epoch_slot0 = 0UL };

  test_account_t acc;
  test_account_init( &acc, &key, &fd_solana_bpf_loader_deprecated_program_id, 1, valid_program_data, valid_program_data_sz );

  fd_progcache_join_t admin[1]; FD_TEST( fd_progcache_shmem_join( admin, shmem ) );

  for( ulong i=0UL; i<ITER_DEFAULT; i++ ) {
    fd_progcache_attach_child( admin, &xid0, &xid1 );

    /* Pre-populate the cache */
    {
      fd_progcache_t tmp[1];
      FD_TEST( fd_progcache_join( tmp, shmem, g_fiber[ 0 ].scratch, FD_PROGCACHE_SCRATCH_FOOTPRINT ) );
      fd_progcache_rec_t * rec = fd_progcache_pull( tmp, &xid1, &key, &load_env, acc.ro, fd_accdb_ref_owner( acc.ro ) );
      FD_TEST( rec );
      fd_progcache_rec_close( tmp, rec );
      fd_progcache_leave( tmp, NULL );
    }

    fd_racesan_weave_t w[1];
    fd_racesan_weave_new( w );
    fd_racesan_weave_add( w, fiber_peek(         &g_fiber[ 0 ], shmem, &xid1, &key, 1UL ) );
    fd_racesan_weave_add( w, fiber_advance_root( &g_fiber[ 1 ], shmem, &xid1 ) );

    metrics_reset();
    fd_racesan_weave_exec_rand( w, i, STEP_MAX );
    FD_TEST( !w->rem_cnt );
    metrics_check_no_oom();

    fd_racesan_weave_delete( w );
    fiber_delete( &g_fiber[ 0 ] );
    fiber_delete( &g_fiber[ 1 ] );
    FD_TEST( !fd_progcache_verify( admin ) );
    test_progcache_clear( admin );
  }

  FD_TEST( fd_progcache_shmem_leave( admin, NULL ) );
  test_progcache_shmem_delete( shmem );
}

/* test_peek_cancel_new races a peek against cancel */

static void
test_peek_cancel( fd_wksp_t * wksp ) {
  fd_progcache_shmem_t * shmem = test_progcache_shmem_new( wksp );

  fd_xid_t    xid0 = ROOT_XID;
  fd_xid_t    xid1 = { .ul = { 2UL, 1UL } };
  fd_pubkey_t key  = test_key( 42UL );
  fd_prog_load_env_t load_env = { .features = g_features, .epoch = 0UL, .epoch_slot0 = 0UL };

  test_account_t acc;
  test_account_init( &acc, &key, &fd_solana_bpf_loader_deprecated_program_id, 1, valid_program_data, valid_program_data_sz );

  fd_progcache_join_t admin[1]; FD_TEST( fd_progcache_shmem_join( admin, shmem ) );

  for( ulong i=0UL; i<ITER_DEFAULT; i++ ) {
    fd_progcache_attach_child( admin, &xid0, &xid1 );

    /* Pre-populate the cache */
    {
      fd_progcache_t tmp[1];
      FD_TEST( fd_progcache_join( tmp, shmem, g_fiber[ 0 ].scratch, FD_PROGCACHE_SCRATCH_FOOTPRINT ) );
      fd_progcache_rec_t * rec = fd_progcache_pull( tmp, &xid1, &key, &load_env, acc.ro, fd_accdb_ref_owner( acc.ro ) );
      FD_TEST( rec );
      fd_progcache_rec_close( tmp, rec );
      fd_progcache_leave( tmp, NULL );
    }

    fd_racesan_weave_t w[1];
    fd_racesan_weave_new( w );
    fd_racesan_weave_add( w, fiber_peek(   &g_fiber[ 0 ], shmem, &xid1, &key, 1UL ) );
    fd_racesan_weave_add( w, fiber_cancel( &g_fiber[ 1 ], shmem, &xid1 ) );

    metrics_reset();
    fd_racesan_weave_exec_rand( w, i, STEP_MAX );
    FD_TEST( !w->rem_cnt );
    metrics_check_no_oom();

    fd_racesan_weave_delete( w );
    fiber_delete( &g_fiber[ 0 ] );
    fiber_delete( &g_fiber[ 1 ] );
    FD_TEST( !fd_progcache_verify( admin ) );
    test_progcache_clear( admin );
  }

  FD_TEST( fd_progcache_shmem_leave( admin, NULL ) );
  test_progcache_shmem_delete( shmem );
}

/* test_peek_peek races two peeks for the same program */

static void
test_peek_peek( fd_wksp_t * wksp ) {
  fd_progcache_shmem_t * shmem = test_progcache_shmem_new( wksp );

  fd_xid_t    xid = ROOT_XID;
  fd_pubkey_t key = test_key( 42UL );
  fd_prog_load_env_t load_env = { .features = g_features, .epoch = 0UL, .epoch_slot0 = 0UL };

  test_account_t acc;
  test_account_init( &acc, &key, &fd_solana_bpf_loader_deprecated_program_id, 1, valid_program_data, valid_program_data_sz );

  fd_progcache_join_t admin[1]; FD_TEST( fd_progcache_shmem_join( admin, shmem ) );

  for( ulong i=0UL; i<ITER_DEFAULT; i++ ) {
    /* Pre-populate the cache */
    {
      fd_progcache_t tmp[1];
      FD_TEST( fd_progcache_join( tmp, shmem, g_fiber[ 0 ].scratch, FD_PROGCACHE_SCRATCH_FOOTPRINT ) );
      fd_progcache_rec_t * rec = fd_progcache_pull( tmp, &xid, &key, &load_env, acc.ro, fd_accdb_ref_owner( acc.ro ) );
      FD_TEST( rec );
      fd_progcache_rec_close( tmp, rec );
      fd_progcache_leave( tmp, NULL );
    }

    fd_racesan_weave_t w[1];
    fd_racesan_weave_new( w );
    fd_racesan_weave_add( w, fiber_peek( &g_fiber[ 0 ], shmem, &xid, &key, 1UL ) );
    fd_racesan_weave_add( w, fiber_peek( &g_fiber[ 1 ], shmem, &xid, &key, 1UL ) );

    metrics_reset();
    fd_racesan_weave_exec_rand( w, i, STEP_MAX );
    FD_TEST( !w->rem_cnt );
    metrics_check_no_oom();

    fd_racesan_weave_delete( w );
    fiber_delete( &g_fiber[ 0 ] );
    fiber_delete( &g_fiber[ 1 ] );
    FD_TEST( !fd_progcache_verify( admin ) );
    test_progcache_clear( admin );
  }

  FD_TEST( fd_progcache_shmem_leave( admin, NULL ) );
  test_progcache_shmem_delete( shmem );
}

/* test_peek_root_sibling races a peek on one sibling against
   advance_root of another sibling */

static void
test_peek_root_sibling( fd_wksp_t * wksp ) {
  fd_progcache_shmem_t * shmem = test_progcache_shmem_new( wksp );

  fd_xid_t    xid0 = ROOT_XID;
  fd_xid_t    xid1 = { .ul = { 2UL, 1UL } };
  fd_xid_t    xid2 = { .ul = { 3UL, 2UL } };
  fd_pubkey_t key  = test_key( 42UL );
  fd_prog_load_env_t load_env = { .features = g_features, .epoch = 0UL, .epoch_slot0 = 0UL };

  test_account_t acc;
  test_account_init( &acc, &key, &fd_solana_bpf_loader_deprecated_program_id, 1, valid_program_data, valid_program_data_sz );

  fd_progcache_join_t admin[1]; FD_TEST( fd_progcache_shmem_join( admin, shmem ) );

  for( ulong i=0UL; i<ITER_DEFAULT; i++ ) {
    fd_progcache_attach_child( admin, &xid0, &xid1 );
    fd_progcache_attach_child( admin, &xid0, &xid2 );

    {
      fd_progcache_t tmp[1];
      FD_TEST( fd_progcache_join( tmp, shmem, g_fiber[ 0 ].scratch, FD_PROGCACHE_SCRATCH_FOOTPRINT ) );
      fd_progcache_rec_t * rec;
      rec = fd_progcache_pull( tmp, &xid1, &key, &load_env, acc.ro, fd_accdb_ref_owner( acc.ro ) );
      FD_TEST( rec ); fd_progcache_rec_close( tmp, rec );
      rec = fd_progcache_pull( tmp, &xid2, &key, &load_env, acc.ro, fd_accdb_ref_owner( acc.ro ) );
      FD_TEST( rec ); fd_progcache_rec_close( tmp, rec );
      fd_progcache_leave( tmp, NULL );
    }

    fd_racesan_weave_t w[1];
    fd_racesan_weave_new( w );
    fd_racesan_weave_add( w, fiber_peek(         &g_fiber[ 0 ], shmem, &xid2, &key, 1UL ) );
    fd_racesan_weave_add( w, fiber_advance_root( &g_fiber[ 1 ], shmem, &xid1 ) );

    metrics_reset();
    fd_racesan_weave_exec_rand( w, i, STEP_MAX );
    FD_TEST( !w->rem_cnt );
    metrics_check_no_oom();

    fd_racesan_weave_delete( w );
    fiber_delete( &g_fiber[ 0 ] );
    fiber_delete( &g_fiber[ 1 ] );
    FD_TEST( !fd_progcache_verify( admin ) );
    test_progcache_clear( admin );
  }

  FD_TEST( fd_progcache_shmem_leave( admin, NULL ) );
  test_progcache_shmem_delete( shmem );
}

/* test_peek_peek_root races two peeks against advance_root */

static void
test_peek_peek_root( fd_wksp_t * wksp ) {
  fd_progcache_shmem_t * shmem = test_progcache_shmem_new( wksp );

  fd_xid_t    xid0 = ROOT_XID;
  fd_xid_t    xid1 = { .ul = { 2UL, 1UL } };
  fd_xid_t    xid2 = { .ul = { 3UL, 2UL } };
  fd_pubkey_t key  = test_key( 42UL );
  fd_prog_load_env_t load_env = { .features = g_features, .epoch = 0UL, .epoch_slot0 = 0UL };

  test_account_t acc;
  test_account_init( &acc, &key, &fd_solana_bpf_loader_deprecated_program_id, 1, valid_program_data, valid_program_data_sz );

  fd_progcache_join_t admin[1]; FD_TEST( fd_progcache_shmem_join( admin, shmem ) );

  for( ulong i=0UL; i<ITER_DEFAULT; i++ ) {
    fd_progcache_attach_child( admin, &xid0, &xid1 );
    fd_progcache_attach_child( admin, &xid0, &xid2 );

    {
      fd_progcache_t tmp[1];
      FD_TEST( fd_progcache_join( tmp, shmem, g_fiber[ 0 ].scratch, FD_PROGCACHE_SCRATCH_FOOTPRINT ) );
      fd_progcache_rec_t * rec;
      rec = fd_progcache_pull( tmp, &xid1, &key, &load_env, acc.ro, fd_accdb_ref_owner( acc.ro ) );
      FD_TEST( rec ); fd_progcache_rec_close( tmp, rec );
      rec = fd_progcache_pull( tmp, &xid2, &key, &load_env, acc.ro, fd_accdb_ref_owner( acc.ro ) );
      FD_TEST( rec ); fd_progcache_rec_close( tmp, rec );
      fd_progcache_leave( tmp, NULL );
    }

    fd_racesan_weave_t w[1];
    fd_racesan_weave_new( w );
    fd_racesan_weave_add( w, fiber_peek(         &g_fiber[ 0 ], shmem, &xid1, &key, 1UL ) );
    fd_racesan_weave_add( w, fiber_peek(         &g_fiber[ 1 ], shmem, &xid2, &key, 1UL ) );
    fd_racesan_weave_add( w, fiber_advance_root( &g_fiber[ 2 ], shmem, &xid1 ) );

    metrics_reset();
    fd_racesan_weave_exec_rand( w, i, STEP_MAX );
    FD_TEST( !w->rem_cnt );
    metrics_check_no_oom();

    fd_racesan_weave_delete( w );
    fiber_delete( &g_fiber[ 0 ] );
    fiber_delete( &g_fiber[ 1 ] );
    fiber_delete( &g_fiber[ 2 ] );
    FD_TEST( !fd_progcache_verify( admin ) );
    test_progcache_clear( admin );
  }

  FD_TEST( fd_progcache_shmem_leave( admin, NULL ) );
  test_progcache_shmem_delete( shmem );
}

/* test_inject_at_hook verifies that racesan hooks fire correctly
   during advance_root */

static void
test_inject_at_hook( fd_wksp_t * wksp ) {
  fd_progcache_shmem_t * shmem = test_progcache_shmem_new( wksp );

  fd_xid_t    xid0 = ROOT_XID;
  fd_xid_t    xid1 = { .ul = { 2UL, 1UL } };
  fd_pubkey_t key  = test_key( 42UL );
  fd_prog_load_env_t load_env = { .features = g_features, .epoch = 0UL, .epoch_slot0 = 0UL };

  test_account_t acc;
  test_account_init( &acc, &key, &fd_solana_bpf_loader_deprecated_program_id, 1, valid_program_data, valid_program_data_sz );

  fd_progcache_join_t admin[1]; FD_TEST( fd_progcache_shmem_join( admin, shmem ) );

  fd_progcache_attach_child( admin, &xid0, &xid1 );

  {
    fd_progcache_t tmp[1];
    FD_TEST( fd_progcache_join( tmp, shmem, g_fiber[ 0 ].scratch, FD_PROGCACHE_SCRATCH_FOOTPRINT ) );
    fd_progcache_rec_t * rec = fd_progcache_pull( tmp, &xid1, &key, &load_env, acc.ro, fd_accdb_ref_owner( acc.ro ) );
    FD_TEST( rec );
    fd_progcache_rec_close( tmp, rec );
    fd_progcache_leave( tmp, NULL );
  }

  fd_racesan_async_t * a = fiber_advance_root( &g_fiber[ 0 ], shmem, &xid1 );

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

static void
test_publish_reclaim_evicted( fd_wksp_t * wksp ) {
  fd_progcache_shmem_t * shmem = test_progcache_shmem_new( wksp );

  fd_xid_t    xid0 = ROOT_XID;
  fd_xid_t    xid1 = { .ul = { 2UL, 1UL } };
  fd_pubkey_t key  = test_key( 42UL );
  fd_prog_load_env_t load_env = { .features = g_features, .epoch = 0UL, .epoch_slot0 = 0UL };

  test_account_t acc;
  test_account_init( &acc, &key, &fd_solana_bpf_loader_deprecated_program_id, 1, valid_program_data, valid_program_data_sz );

  fd_progcache_join_t admin[1]; FD_TEST( fd_progcache_shmem_join( admin, shmem ) );

  for( ulong i=0UL; i<ITER_DEFAULT; i++ ) {
    fd_progcache_attach_child( admin, &xid0, &xid1 );

    {
      fd_progcache_t tmp[1];
      FD_TEST( fd_progcache_join( tmp, shmem, g_fiber[ 0 ].scratch, FD_PROGCACHE_SCRATCH_FOOTPRINT ) );
      fd_progcache_rec_t * rec = fd_progcache_pull( tmp, &xid1, &key, &load_env, acc.ro, fd_accdb_ref_owner( acc.ro ) );
      FD_TEST( rec );
      fd_progcache_rec_close( tmp, rec );
      fd_progcache_leave( tmp, NULL );
    }

    fd_racesan_weave_t w[1];
    fd_racesan_weave_new( w );
    fd_racesan_weave_add( w, fiber_evict(        &g_fiber[ 0 ], shmem, 1UL, 0UL ) );
    fd_racesan_weave_add( w, fiber_advance_root( &g_fiber[ 1 ], shmem, &xid1 ) );

    metrics_reset();
    fd_racesan_weave_exec_rand( w, i, STEP_MAX );
    FD_TEST( !w->rem_cnt );

    fd_racesan_weave_delete( w );
    fiber_delete( &g_fiber[ 0 ] );
    fiber_delete( &g_fiber[ 1 ] );
    FD_TEST( !fd_progcache_verify( admin ) );
    test_progcache_clear( admin );
  }

  FD_TEST( fd_progcache_shmem_leave( admin, NULL ) );
  test_progcache_shmem_delete( shmem );
}

static void
test_publish_reclaim_queued( fd_wksp_t * wksp ) {
  fd_progcache_shmem_t * shmem = test_progcache_shmem_new( wksp );

  fd_xid_t    xid0 = ROOT_XID;
  fd_xid_t    xid1 = { .ul = { 2UL, 1UL } };
  fd_pubkey_t key  = test_key( 42UL );
  fd_prog_load_env_t load_env = { .features = g_features, .epoch = 0UL, .epoch_slot0 = 0UL };

  test_account_t acc;
  test_account_init( &acc, &key, &fd_solana_bpf_loader_deprecated_program_id, 1, valid_program_data, valid_program_data_sz );

  fd_progcache_t * cache = g_fiber[ 2 ].cache;
  for( ulong i=0UL; i<ITER_DEFAULT; i++ ) {
    /* Insert entry and immediately mark it for reclaim */
    FD_TEST( fd_progcache_join( cache, shmem, g_fiber[ 2 ].scratch, FD_PROGCACHE_SCRATCH_FOOTPRINT ) );
    FD_TEST( cache->join->rec.reclaim_head==UINT_MAX );
    fd_progcache_attach_child( cache->join, &xid0, &xid1 );
    fd_progcache_rec_t * rec = fd_progcache_pull( cache, &xid1, &key, &load_env, acc.ro, fd_accdb_ref_owner( acc.ro ) );
    FD_TEST( rec );
    fd_progcache_rec_close( cache, rec );
    fd_prog_delete_rec( cache->join, rec );
    FD_TEST( cache->join->rec.reclaim_head!=UINT_MAX );

    fd_racesan_weave_t w[1];
    fd_racesan_weave_new( w );
    fd_racesan_weave_add( w, fiber_advance_root( &g_fiber[ 0 ], shmem, &xid1 ) );
    fd_racesan_weave_add( w, fiber_pull(         &g_fiber[ 1 ], shmem, &xid1, &key, &load_env, acc.ro ) );
    fd_racesan_weave_add( w, fiber_reclaim(      &g_fiber[ 2 ] ) );

    metrics_reset();
    fd_racesan_weave_exec_rand( w, i, STEP_MAX );
    FD_TEST( !w->rem_cnt );

    fd_racesan_weave_delete( w );
    fiber_delete( &g_fiber[ 0 ] );
    fiber_delete( &g_fiber[ 1 ] );
    FD_TEST( !fd_progcache_verify( cache->join ) );
    test_progcache_clear( cache->join );
    fiber_delete( &g_fiber[ 2 ] );
  }

  test_progcache_shmem_delete( shmem );
}

/* test_root_evict_two races advance_root against eviction with
   two different programs populated on two sibling forks */

static void
test_root_evict_two( fd_wksp_t * wksp ) {
  fd_progcache_shmem_t * shmem = test_progcache_shmem_new( wksp );

  fd_xid_t    xid0 = ROOT_XID;
  fd_xid_t    xid1 = { .ul = { 2UL, 1UL } };
  fd_xid_t    xid2 = { .ul = { 3UL, 2UL } };
  fd_pubkey_t ka   = test_key( 1UL );
  fd_pubkey_t kb   = test_key( 2UL );
  fd_prog_load_env_t load_env = { .features = g_features, .epoch = 0UL, .epoch_slot0 = 0UL };

  test_account_t acc_a;
  test_account_init( &acc_a, &ka, &fd_solana_bpf_loader_deprecated_program_id, 1, valid_program_data, valid_program_data_sz );
  test_account_t acc_b;
  test_account_init( &acc_b, &kb, &fd_solana_bpf_loader_deprecated_program_id, 1, valid_program_data, valid_program_data_sz );

  fd_progcache_join_t admin[1]; FD_TEST( fd_progcache_shmem_join( admin, shmem ) );

  for( ulong i=0UL; i<ITER_DEFAULT; i++ ) {
    fd_progcache_attach_child( admin, &xid0, &xid1 );
    fd_progcache_attach_child( admin, &xid0, &xid2 );

    {
      fd_progcache_t tmp[1];
      FD_TEST( fd_progcache_join( tmp, shmem, g_fiber[ 0 ].scratch, FD_PROGCACHE_SCRATCH_FOOTPRINT ) );
      fd_progcache_rec_t * rec;
      rec = fd_progcache_pull( tmp, &xid1, &ka, &load_env, acc_a.ro, fd_accdb_ref_owner( acc_a.ro ) );
      FD_TEST( rec ); fd_progcache_rec_close( tmp, rec );
      rec = fd_progcache_pull( tmp, &xid2, &kb, &load_env, acc_b.ro, fd_accdb_ref_owner( acc_b.ro ) );
      FD_TEST( rec ); fd_progcache_rec_close( tmp, rec );
      fd_progcache_leave( tmp, NULL );
    }

    fd_racesan_weave_t w[1];
    fd_racesan_weave_new( w );
    fd_racesan_weave_add( w, fiber_advance_root( &g_fiber[ 0 ], shmem, &xid1 ) );
    fd_racesan_weave_add( w, fiber_evict(        &g_fiber[ 1 ], shmem, 1UL, 0UL ) );

    metrics_reset();
    fd_racesan_weave_exec_rand( w, i, STEP_MAX );
    FD_TEST( !w->rem_cnt );
    metrics_check_no_oom();

    fd_racesan_weave_delete( w );
    fiber_delete( &g_fiber[ 0 ] );
    fiber_delete( &g_fiber[ 1 ] );
    FD_TEST( !fd_progcache_verify( admin ) );
    test_progcache_clear( admin );
  }

  FD_TEST( fd_progcache_shmem_leave( admin, NULL ) );
  test_progcache_shmem_delete( shmem );
}

/* test_publish_evict_stale races advance_root against clock eviction
   where the evicted record's CLOCK bits are stale.
   Reproduces the crash from auditor-internal#460 */

static void
test_publish_evict_stale( fd_wksp_t * wksp ) {
  fd_progcache_shmem_t * shmem = test_progcache_shmem_new( wksp );

  fd_xid_t    xid0 = ROOT_XID;
  fd_xid_t    xid1 = { .ul = { 2UL, 1UL } };
  fd_pubkey_t key  = test_key( 42UL );

  /* epoch_slot0=0 for root pull gives revision_slot=0.
     epoch_slot0=2 for child pull gives revision_slot=2, which matches
     xid1.ul[0]=2 so fd_lineage_xid returns xid1 and the record is
     inserted under xid1's txn (not at root). */
  fd_prog_load_env_t load_env_root  = { .features = g_features, .epoch = 0UL, .epoch_slot0 = 0UL };
  fd_prog_load_env_t load_env_child = { .features = g_features, .epoch = 0UL, .epoch_slot0 = 2UL };

  test_account_t acc;
  test_account_init( &acc, &key, &fd_solana_bpf_loader_deprecated_program_id, 1, valid_program_data, valid_program_data_sz );

  fd_progcache_join_t admin[1]; FD_TEST( fd_progcache_shmem_join( admin, shmem ) );

  for( ulong i=0UL; i<ITER_DEFAULT; i++ ) {

    /* Pre-populate the same program at root (revision_slot=0) */
    {
      fd_progcache_t tmp[1];
      FD_TEST( fd_progcache_join( tmp, shmem, g_fiber[ 0 ].scratch, FD_PROGCACHE_SCRATCH_FOOTPRINT ) );
      fd_progcache_rec_t * rec = fd_progcache_pull( tmp, &xid0, &key, &load_env_root, acc.ro, fd_accdb_ref_owner( acc.ro ) );
      FD_TEST( rec );
      fd_progcache_rec_close( tmp, rec );
      fd_progcache_leave( tmp, NULL );
    }

    /* Create child fork and populate the same key under xid1's txn
       (revision_slot=2, matching xid1.ul[0]=2).  Peek won't hit
       the root record because slot 2 != slot 0. */
    fd_progcache_attach_child( admin, &xid0, &xid1 );
    {
      fd_progcache_t tmp[1];
      FD_TEST( fd_progcache_join( tmp, shmem, g_fiber[ 0 ].scratch, FD_PROGCACHE_SCRATCH_FOOTPRINT ) );
      fd_progcache_rec_t * rec = fd_progcache_pull( tmp, &xid1, &key, &load_env_child, acc.ro, fd_accdb_ref_owner( acc.ro ) );
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
    fd_racesan_weave_add( w, fiber_advance_root( &g_fiber[ 0 ], shmem, &xid1 ) );
    fd_racesan_weave_add( w, fiber_evict(        &g_fiber[ 1 ], shmem, 2UL, 0UL ) );

    metrics_reset();
    fd_racesan_weave_exec_rand( w, i, STEP_MAX );
    FD_TEST( !w->rem_cnt );

    fd_racesan_weave_delete( w );
    fiber_delete( &g_fiber[ 0 ] );
    fiber_delete( &g_fiber[ 1 ] );
    FD_TEST( !fd_progcache_verify( admin ) );
    test_progcache_clear( admin );
  }

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
  fd_wksp_t * wksp = fd_wksp_new_anonymous( page_sz, page_cnt, fd_shmem_cpu_idx( numa_idx ), "wksp", 0UL );
  FD_TEST( wksp );

# define TEST( name ) { #name, name }
  struct test_case cases[] = {
    TEST( test_pull_pull ),
    TEST( test_pull_peek ),
    TEST( test_pull_root ),
    TEST( test_cancel_peek ),
    TEST( test_publish_evict ),
    TEST( test_pull_root_peek ),
    TEST( test_peek_root ),
    TEST( test_peek_cancel ),
    TEST( test_peek_peek ),
    TEST( test_peek_root_sibling ),
    TEST( test_peek_peek_root ),
    TEST( test_inject_at_hook ),
    TEST( test_root_evict_two ),
    TEST( test_publish_reclaim_evicted ),
    TEST( test_publish_reclaim_queued ),
    TEST( test_publish_evict_stale ),
    {0}
  };
# undef TEST

  for( struct test_case * tc = cases; tc->name; tc++ ) {
    if( match_test_name( tc->name, argc, argv ) ) {
      FD_LOG_NOTICE(( "Running %s", tc->name ));
      tc->fn( wksp );
      fd_wksp_reset( wksp, 1UL );
    }
  }

  fd_wksp_delete_anonymous( wksp );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
