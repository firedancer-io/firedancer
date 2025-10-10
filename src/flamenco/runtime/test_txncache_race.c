#include "fd_txncache.h"
#include "fd_txncache_shmem.h"
#include "../../util/racesan/fd_racesan_weave.h"
#include "../../util/fd_util.h"

#if !FD_HAS_RACESAN
#error "test_txncache_race requires FD_HAS_RACESAN"
#endif

struct test_env {
  fd_txncache_shmem_t * shmem;
  fd_txncache_t *       tc;
};
typedef struct test_env test_env_t;

static test_env_t g_env[1];

static fd_wksp_t * g_wksp;

static uchar wksp_mem[ 1UL<<26 ] __attribute__((aligned(FD_SHMEM_NORMAL_PAGE_SZ)));

static test_env_t *
test_env_init( void ) {
  FD_TEST( !g_wksp );
  ulong part_max = fd_wksp_part_max_est( sizeof(wksp_mem), 64UL<<10 );
  ulong data_max = fd_wksp_data_max_est( sizeof(wksp_mem), part_max );
  fd_wksp_t * wksp = fd_wksp_join( fd_wksp_new( wksp_mem, "funk_test", 1U, part_max, data_max ) );
  FD_TEST( wksp );
  fd_shmem_join_anonymous( "funk_test", FD_SHMEM_JOIN_MODE_READ_WRITE, wksp, wksp_mem, FD_SHMEM_NORMAL_PAGE_SZ, sizeof(wksp_mem)>>FD_SHMEM_NORMAL_LG_PAGE_SZ );

  ulong  wksp_tag         =  1UL;
  ulong  max_live_slots   =  1UL;
  ulong  max_bh_distance  =  1UL;
  ulong  max_txn_per_slot = 64UL;
  ulong  shmem_fp = fd_txncache_shmem_footprint_ext( max_live_slots, max_bh_distance, max_txn_per_slot );
  FD_TEST( shmem_fp );
  void * shmem = fd_wksp_alloc_laddr( wksp, fd_txncache_shmem_align(), shmem_fp, wksp_tag );
  FD_TEST( shmem );
  FD_TEST( fd_txncache_shmem_new_ext( shmem, max_live_slots, max_bh_distance, max_txn_per_slot ) );

  memset( g_env, 0, sizeof(test_env_t) );
  g_env->shmem = fd_txncache_shmem_join( shmem );
  FD_TEST( g_env->shmem );
  g_env->tc = fd_txncache_join( fd_txncache_new( fd_wksp_alloc_laddr( wksp, fd_txncache_align(), fd_txncache_footprint_ext( max_live_slots, max_bh_distance ), wksp_tag ), g_env->shmem ) );
  FD_TEST( g_env->tc );
  g_wksp = fd_wksp_join( wksp_mem );

  return g_env;
}

static void
test_env_fini( void ) {
  FD_TEST( g_wksp );

  //FD_TEST( fd_wksp_free_laddr( fd_txncache_delete( fd_txncache_leave( g_env->tc ) ) ) );
  fd_wksp_free_laddr( g_env->tc );
  //FD_TEST( fd_wksp_free_laddr( fd_txncache_shmem_delete( fd_txncache_shmem_leave( g_env->shmem ) ) ) );
  fd_wksp_free_laddr( g_env->shmem );

  /* Check for alloc leaks */
  fd_wksp_usage_t wksp_usage;
  FD_TEST( fd_wksp_usage( g_wksp, NULL, 0UL, &wksp_usage ) );
  FD_TEST( wksp_usage.free_cnt==wksp_usage.total_cnt );

  memset( g_env, 0, sizeof(test_env_t) );
  fd_shmem_leave_anonymous( g_wksp, NULL );
  FD_TEST( fd_wksp_delete( fd_wksp_leave( g_wksp ) ) );
  g_wksp = NULL;
}

struct async_ctx {
  fd_txncache_t *       tc;
  fd_txncache_fork_id_t fork_id;
  uchar                 blockhash[ 32 ];
  uchar                 txnhash[ 32 ];
};
typedef struct async_ctx async_ctx_t;

static void
async_insert( void * _ctx ) {
  async_ctx_t * ctx = _ctx;
  fd_txncache_insert( ctx->tc, ctx->fork_id, ctx->blockhash, ctx->txnhash );
}

static void
async_query( void * _ctx ) {
  async_ctx_t * ctx = _ctx;
  (void)fd_txncache_query( ctx->tc, ctx->fork_id, ctx->blockhash, ctx->txnhash );
}

static void
race_insert_query( void ) {
  test_env_t * env = test_env_init();

  fd_racesan_weave_t weave[1];
  fd_racesan_weave_new( weave );

# define OP_CNT 33
  async_ctx_t op_ctx[ OP_CNT ];
  for( ulong i=0UL; i<OP_CNT; i++ ) {
    op_ctx[ i ].tc = env->tc;
    memset( op_ctx[ i ].blockhash, 0, 32UL );
    memset( op_ctx[ i ].txnhash,   0, 32UL );
    FD_STORE( ulong, op_ctx[ i ].txnhash, i );
  }
  static fd_racesan_async_t insert_async[ OP_CNT ];
  for( ulong i=0UL; i<OP_CNT; i++ ) {
    FD_TEST( fd_racesan_async_new( &insert_async[i], async_insert, &op_ctx[i] ) );
    fd_racesan_weave_add( weave, &insert_async[i] );
  }

  (void)async_query;
  // static fd_racesan_async_t query_async[ OP_CNT ];
  // for( ulong i=0UL; i<OP_CNT; i++ ) {
  //   FD_TEST( fd_racesan_async_new( &query_async[i], async_query, &op_ctx[i] ) );
  //   fd_racesan_weave_add( weave, &query_async[i] );
  // }

  ulong iter     = (ulong)1e5;
  ulong step_max = 1024UL;
  for( ulong rem=iter; rem; rem-- ) {
    fd_txncache_reset( env->tc );
    fd_txncache_fork_id_t null = {USHORT_MAX};
    fd_txncache_fork_id_t root = fd_txncache_attach_child( env->tc, null );
    fd_txncache_finalize_fork( env->tc, root, 0UL, op_ctx[0].blockhash );
    fd_txncache_fork_id_t slot1 = fd_txncache_attach_child( env->tc, root );
    for( ulong i=0UL; i<OP_CNT; i++ ) op_ctx[i].fork_id = slot1;
    fd_racesan_weave_exec_rand( weave, rem, step_max );
    fd_txncache_finalize_fork( env->tc, slot1, 0UL, op_ctx[0].blockhash );
    for( ulong i=0UL; i<OP_CNT; i++ ) {
      FD_TEST( fd_txncache_query( env->tc, slot1, op_ctx[ i ].blockhash, op_ctx[ i ].txnhash ) );
    }
  }

  fd_racesan_weave_delete( weave );
  for( ulong i=0UL; i<OP_CNT; i++ ) fd_racesan_async_delete( &insert_async[i] );

  test_env_fini();
# undef OP_CNT
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  race_insert_query();

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
