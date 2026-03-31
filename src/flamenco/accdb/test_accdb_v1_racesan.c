#include "fd_accdb_admin_v1.h"
#include "fd_accdb_sync.h"
#include "fd_accdb_impl_v1.h"
#include "../../util/racesan/fd_racesan_async.h"
#include "../../util/racesan/fd_racesan_weave.h"

#define WKSP_TAG_DEF  1UL
#define WKSP_TAG_FUNK 2UL

#define FIBER_MAX       (4)
#define FIBER_STACK_MAX (1UL<<21)
#define ITER_DEFAULT    (4096UL)
#define STEP_MAX        (100000UL)

/* Fiber infrastructure ************************************************/

struct fiber {
  fd_racesan_async_t async[1];
  uchar stack[ FIBER_STACK_MAX ] __attribute__((aligned(64)));

  union {
    struct {
      fd_accdb_user_t *  accdb;
      fd_funk_txn_xid_t  xid;
      uchar              address[32];
    } open_ro;

    struct {
      fd_accdb_user_t *  accdb;
      fd_funk_txn_xid_t  xid;
      uchar              address[32];
      ulong              data_max;
      int                flags;
      ulong              lamports;
    } open_rw;

    struct {
      fd_accdb_admin_t * admin;
      fd_funk_txn_xid_t  xid;
    } advance_root;

    struct {
      fd_accdb_admin_t * admin;
      fd_funk_txn_xid_t  xid;
    } cancel;
  };
};
typedef struct fiber fiber_t;

static fiber_t g_fiber[ FIBER_MAX ];

/* open_ro fiber: speculatively reads an account */

static void
fiber_open_ro_exec( void * _ctx ) {
  fiber_t * f = _ctx;
  fd_accdb_ro_t ro[1];
  if( fd_accdb_open_ro( f->open_ro.accdb, ro, &f->open_ro.xid, f->open_ro.address ) ) {
    fd_accdb_close_ro( f->open_ro.accdb, ro );
  }
}

static fd_racesan_async_t *
fiber_open_ro( fiber_t *                 fiber,
               fd_accdb_user_t *         accdb,
               fd_funk_txn_xid_t const * xid,
               void const *              address ) {
  fiber->open_ro.accdb = accdb;
  fiber->open_ro.xid   = *xid;
  memcpy( fiber->open_ro.address, address, 32UL );
  fd_racesan_async_new( fiber->async, fiber->stack+FIBER_STACK_MAX, FIBER_STACK_MAX, fiber_open_ro_exec, fiber );
  return fiber->async;
}

/* open_rw fiber: writes an account */

static void
fiber_open_rw_exec( void * _ctx ) {
  fiber_t * f = _ctx;
  fd_accdb_rw_t rw[1];
  fd_accdb_rw_t * res = fd_accdb_open_rw( f->open_rw.accdb, rw, &f->open_rw.xid,
                                           f->open_rw.address, f->open_rw.data_max,
                                           f->open_rw.flags );
  if( res ) {
    fd_accdb_ref_lamports_set( rw, f->open_rw.lamports );
    fd_accdb_close_rw( f->open_rw.accdb, rw );
  }
}

static fd_racesan_async_t *
fiber_open_rw( fiber_t *                 fiber,
               fd_accdb_user_t *         accdb,
               fd_funk_txn_xid_t const * xid,
               void const *              address,
               ulong                     data_max,
               int                       flags,
               ulong                     lamports ) {
  fiber->open_rw.accdb    = accdb;
  fiber->open_rw.xid      = *xid;
  memcpy( fiber->open_rw.address, address, 32UL );
  fiber->open_rw.data_max = data_max;
  fiber->open_rw.flags    = flags;
  fiber->open_rw.lamports = lamports;
  fd_racesan_async_new( fiber->async, fiber->stack+FIBER_STACK_MAX, FIBER_STACK_MAX, fiber_open_rw_exec, fiber );
  return fiber->async;
}

/* advance_root fiber */

static void
fiber_advance_root_exec( void * _ctx ) {
  fiber_t * f = _ctx;
  fd_accdb_advance_root( f->advance_root.admin, &f->advance_root.xid );
}

static fd_racesan_async_t *
fiber_advance_root( fiber_t *                 fiber,
                    fd_accdb_admin_t *        admin,
                    fd_funk_txn_xid_t const * xid ) {
  fiber->advance_root.admin = admin;
  fiber->advance_root.xid   = *xid;
  fd_racesan_async_new( fiber->async, fiber->stack+FIBER_STACK_MAX, FIBER_STACK_MAX, fiber_advance_root_exec, fiber );
  return fiber->async;
}

/* cancel fiber */

static void
fiber_cancel_exec( void * _ctx ) {
  fiber_t * f = _ctx;
  fd_accdb_cancel( f->cancel.admin, &f->cancel.xid );
}

static fd_racesan_async_t *
fiber_cancel( fiber_t *                 fiber,
              fd_accdb_admin_t *        admin,
              fd_funk_txn_xid_t const * xid ) {
  fiber->cancel.admin = admin;
  fiber->cancel.xid   = *xid;
  fd_racesan_async_new( fiber->async, fiber->stack+FIBER_STACK_MAX, FIBER_STACK_MAX, fiber_cancel_exec, fiber );
  return fiber->async;
}

/* Test helpers ********************************************************/

struct test_case {
  char const * name;
  void      (* fn)( fd_wksp_t * wksp );
};

static int
match_test_name( char const * test_name,
                 int          argc,
                 char **      argv ) {
  if( argc<=1 ) return 1;
  for( int i=1; i<argc; i++ ) {
    if( argv[ i ][ strspn( argv[ i ], " \t\n\r" ) ]=='\0' ) continue;
    if( strstr( test_name, argv[ i ] ) ) return 1;
  }
  return 0;
}

struct test_ctx {
  void *             shfunk;
  void *             shlocks;
  fd_accdb_admin_t   admin[1];
  fd_accdb_user_t    accdb[1];
};
typedef struct test_ctx test_ctx_t;

static test_ctx_t *
test_ctx_new( test_ctx_t * ctx,
              fd_wksp_t *  wksp,
              ulong        txn_max,
              ulong        rec_max ) {
  ulong funk_footprint = fd_funk_shmem_footprint( txn_max, rec_max );
  ulong lock_footprint = fd_funk_locks_footprint( txn_max, rec_max );
  ctx->shfunk  = fd_wksp_alloc_laddr( wksp, fd_funk_align(), funk_footprint, WKSP_TAG_DEF );
  ctx->shlocks = fd_wksp_alloc_laddr( wksp, fd_funk_align(), lock_footprint, WKSP_TAG_DEF );
  FD_TEST( ctx->shfunk  );
  FD_TEST( ctx->shlocks );
  FD_TEST( fd_funk_shmem_new( ctx->shfunk, WKSP_TAG_FUNK, 0UL, txn_max, rec_max ) );
  FD_TEST( fd_funk_locks_new( ctx->shlocks, txn_max, rec_max ) );

  FD_TEST( fd_accdb_admin_v1_init( ctx->admin, ctx->shfunk, ctx->shlocks ) );
  FD_TEST( fd_accdb_user_v1_init(  ctx->accdb, ctx->shfunk, ctx->shlocks, txn_max ) );
  return ctx;
}

static void
test_ctx_delete( test_ctx_t * ctx ) {
  fd_accdb_user_fini( ctx->accdb );
  fd_accdb_admin_fini( ctx->admin );
  fd_wksp_free_laddr( ctx->shlocks );
  fd_wksp_free_laddr( fd_funk_delete( ctx->shfunk ) );
}

/* Populate an account into a txn via open_rw/close_rw */
static void
populate_account( fd_accdb_admin_t *        admin,
                  fd_accdb_user_t *         accdb,
                  fd_funk_txn_xid_t const * xid,
                  void const *              address,
                  ulong                     lamports ) {
  (void)admin;
  fd_accdb_rw_t rw[1];
  FD_TEST( fd_accdb_open_rw( accdb, rw, xid, address, 16UL, FD_ACCDB_FLAG_CREATE ) );
  fd_accdb_ref_lamports_set( rw, lamports );
  fd_accdb_close_rw( accdb, rw );
}

/* TESTS **************************************************************/

/* test_read_root races a speculative read (open_ro) against
   advance_root.  This exercises the version counter protocol in
   fd_accdb_search_chain: head_cidx must be loaded AFTER the version
   counter (acquire), and the malformed-chain CRIT must be guarded by
   the final version re-check. */

static void
test_read_root( fd_wksp_t * wksp ) {
  ulong txn_max = 8UL;
  ulong rec_max = 64UL;

  static uchar const key_a[32] = { 1 };

  for( ulong i=0UL; i<ITER_DEFAULT; i++ ) {
    test_ctx_t ctx[1];
    test_ctx_new( ctx, wksp, txn_max, rec_max );

    fd_funk_txn_xid_t root = fd_accdb_root_get( ctx->admin );
    fd_funk_txn_xid_t xid1 = { .ul={ i+1UL, 1UL } };
    fd_accdb_attach_child( ctx->admin, &root, &xid1 );
    populate_account( ctx->admin, ctx->accdb, &xid1, key_a, 1000UL );

    fd_racesan_weave_t w[1];
    fd_racesan_weave_new( w );
    fd_racesan_weave_add( w, fiber_open_ro(      &g_fiber[ 0 ], ctx->accdb, &xid1, key_a ) );
    fd_racesan_weave_add( w, fiber_advance_root( &g_fiber[ 1 ], ctx->admin, &xid1 ) );

    fd_racesan_weave_exec_rand( w, i, STEP_MAX );
    FD_TEST( !w->rem_cnt );

    fd_racesan_weave_delete( w );
    test_ctx_delete( ctx );
    fd_wksp_reset( wksp, WKSP_TAG_DEF );
  }
}

/* test_read_insert races a speculative read against a record insertion
   on the same chain.  The writer inserts a new record (modifying the
   chain head_cidx and version counter) while the reader walks the
   chain speculatively. */

static void
test_read_insert( fd_wksp_t * wksp ) {
  ulong txn_max = 8UL;
  ulong rec_max = 64UL;

  static uchar const key_a[32] = { 1 };
  static uchar const key_b[32] = { 2 };

  for( ulong i=0UL; i<ITER_DEFAULT; i++ ) {
    test_ctx_t ctx[1];
    test_ctx_new( ctx, wksp, txn_max, rec_max );

    fd_funk_txn_xid_t root = fd_accdb_root_get( ctx->admin );
    fd_funk_txn_xid_t xid1 = { .ul={ i+1UL, 1UL } };
    fd_accdb_attach_child( ctx->admin, &root, &xid1 );
    populate_account( ctx->admin, ctx->accdb, &xid1, key_a, 1000UL );

    fd_racesan_weave_t w[1];
    fd_racesan_weave_new( w );
    fd_racesan_weave_add( w, fiber_open_ro( &g_fiber[ 0 ], ctx->accdb, &xid1, key_a ) );
    fd_racesan_weave_add( w, fiber_open_rw( &g_fiber[ 1 ], ctx->accdb, &xid1, key_b, 16UL, FD_ACCDB_FLAG_CREATE, 2000UL ) );

    fd_racesan_weave_exec_rand( w, i, STEP_MAX );
    FD_TEST( !w->rem_cnt );

    fd_racesan_weave_delete( w );
    test_ctx_delete( ctx );
    fd_wksp_reset( wksp, WKSP_TAG_DEF );
  }
}

/* test_read_read races two speculative reads for the same account.
   Both should succeed without interference. */

static void
test_read_read( fd_wksp_t * wksp ) {
  ulong txn_max = 8UL;
  ulong rec_max = 64UL;

  static uchar const key_a[32] = { 1 };

  for( ulong i=0UL; i<ITER_DEFAULT; i++ ) {
    test_ctx_t ctx[1];
    test_ctx_new( ctx, wksp, txn_max, rec_max );

    fd_funk_txn_xid_t root = fd_accdb_root_get( ctx->admin );
    fd_funk_txn_xid_t xid1 = { .ul={ i+1UL, 1UL } };
    fd_accdb_attach_child( ctx->admin, &root, &xid1 );
    populate_account( ctx->admin, ctx->accdb, &xid1, key_a, 1000UL );

    fd_racesan_weave_t w[1];
    fd_racesan_weave_new( w );
    fd_racesan_weave_add( w, fiber_open_ro( &g_fiber[ 0 ], ctx->accdb, &xid1, key_a ) );
    fd_racesan_weave_add( w, fiber_open_ro( &g_fiber[ 1 ], ctx->accdb, &xid1, key_a ) );

    fd_racesan_weave_exec_rand( w, i, STEP_MAX );
    FD_TEST( !w->rem_cnt );

    fd_racesan_weave_delete( w );
    test_ctx_delete( ctx );
    fd_wksp_reset( wksp, WKSP_TAG_DEF );
  }
}

/* test_read_cancel races a speculative read against cancel.  The cancel
   removes the txn and its records from the chain while the reader is
   walking it speculatively. */

static void
test_read_cancel( fd_wksp_t * wksp ) {
  ulong txn_max = 8UL;
  ulong rec_max = 64UL;

  static uchar const key_a[32] = { 1 };

  for( ulong i=0UL; i<ITER_DEFAULT; i++ ) {
    test_ctx_t ctx[1];
    test_ctx_new( ctx, wksp, txn_max, rec_max );

    fd_funk_txn_xid_t root = fd_accdb_root_get( ctx->admin );
    fd_funk_txn_xid_t xid1 = { .ul={ i+1UL, 1UL } };
    fd_accdb_attach_child( ctx->admin, &root, &xid1 );
    populate_account( ctx->admin, ctx->accdb, &xid1, key_a, 1000UL );

    fd_racesan_weave_t w[1];
    fd_racesan_weave_new( w );
    fd_racesan_weave_add( w, fiber_open_ro( &g_fiber[ 0 ], ctx->accdb, &xid1, key_a ) );
    fd_racesan_weave_add( w, fiber_cancel(  &g_fiber[ 1 ], ctx->admin, &xid1 ) );

    fd_racesan_weave_exec_rand( w, i, STEP_MAX );
    FD_TEST( !w->rem_cnt );

    fd_racesan_weave_delete( w );
    test_ctx_delete( ctx );
    fd_wksp_reset( wksp, WKSP_TAG_DEF );
  }
}

/* test_read_root_multikey races reads of multiple accounts against
   advance_root, stressing the chain walk version protocol across
   different chains. */

static void
test_read_root_multikey( fd_wksp_t * wksp ) {
  ulong txn_max = 8UL;
  ulong rec_max = 64UL;

  static uchar const key_a[32] = { 1 };
  static uchar const key_b[32] = { 2 };
  static uchar const key_c[32] = { 3 };

  for( ulong i=0UL; i<ITER_DEFAULT; i++ ) {
    test_ctx_t ctx[1];
    test_ctx_new( ctx, wksp, txn_max, rec_max );

    fd_funk_txn_xid_t root = fd_accdb_root_get( ctx->admin );
    fd_funk_txn_xid_t xid1 = { .ul={ i+1UL, 1UL } };
    fd_accdb_attach_child( ctx->admin, &root, &xid1 );
    populate_account( ctx->admin, ctx->accdb, &xid1, key_a, 1000UL );
    populate_account( ctx->admin, ctx->accdb, &xid1, key_b, 2000UL );
    populate_account( ctx->admin, ctx->accdb, &xid1, key_c, 3000UL );

    fd_racesan_weave_t w[1];
    fd_racesan_weave_new( w );
    fd_racesan_weave_add( w, fiber_open_ro(      &g_fiber[ 0 ], ctx->accdb, &xid1, key_a ) );
    fd_racesan_weave_add( w, fiber_open_ro(      &g_fiber[ 1 ], ctx->accdb, &xid1, key_b ) );
    fd_racesan_weave_add( w, fiber_advance_root( &g_fiber[ 2 ], ctx->admin, &xid1 ) );

    fd_racesan_weave_exec_rand( w, i, STEP_MAX );
    FD_TEST( !w->rem_cnt );

    fd_racesan_weave_delete( w );
    test_ctx_delete( ctx );
    fd_wksp_reset( wksp, WKSP_TAG_DEF );
  }
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  ulong cpu_idx = fd_tile_cpu_id( fd_tile_idx() );
  if( cpu_idx>fd_shmem_cpu_cnt() ) cpu_idx = 0UL;

  char const * _page_sz = fd_env_strip_cmdline_cstr ( &argc, &argv, "--page-sz",  NULL, "gigantic"                   );
  ulong        page_cnt = fd_env_strip_cmdline_ulong( &argc, &argv, "--page-cnt", NULL, 1UL                          );
  ulong        numa_idx = fd_env_strip_cmdline_ulong( &argc, &argv, "--numa-idx", NULL, fd_shmem_numa_idx( cpu_idx ) );

  ulong page_sz = fd_cstr_to_shmem_page_sz( _page_sz );
  if( FD_UNLIKELY( !page_sz ) ) FD_LOG_ERR(( "unsupported --page-sz" ));

  FD_LOG_NOTICE(( "Creating workspace (--page-cnt %lu, --page-sz %s, --numa-idx %lu)", page_cnt, _page_sz, numa_idx ));
  fd_wksp_t * wksp = fd_wksp_new_anonymous( page_sz, page_cnt, fd_shmem_cpu_idx( numa_idx ), "wksp", 0UL );
  FD_TEST( wksp );

# define TEST( name ) { #name, name }
  struct test_case cases[] = {
    TEST( test_read_root ),
    TEST( test_read_insert ),
    TEST( test_read_read ),
    TEST( test_read_cancel ),
    TEST( test_read_root_multikey ),
    {0}
  };
# undef TEST

  for( struct test_case * tc = cases; tc->name; tc++ ) {
    if( match_test_name( tc->name, argc, argv ) ) {
      FD_LOG_NOTICE(( "Running %s", tc->name ));
      tc->fn( wksp );
      fd_wksp_reset( wksp, WKSP_TAG_DEF );
    }
  }

  fd_wksp_delete_anonymous( wksp );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
