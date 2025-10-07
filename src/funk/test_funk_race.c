#include "fd_funk.h"
#include "fd_funk_base.h"
#include "fd_funk_rec.h"
#include "../util/racesan/fd_racesan_weave.h"

#if !FD_HAS_RACESAN
#error "test_funk_race requires FD_HAS_RACESAN"
#endif

struct test_env {
  fd_funk_t funk[1];
};
typedef struct test_env test_env_t;

static test_env_t g_env[1];

static fd_wksp_t * g_wksp;

static uchar wksp_mem[ 1<<20UL ] __attribute__((aligned(FD_SHMEM_NORMAL_PAGE_SZ)));

static test_env_t *
test_env_init( void ) {
  FD_TEST( !g_wksp );
  ulong part_max = fd_wksp_part_max_est( sizeof(wksp_mem), 64UL<<10 );
  ulong data_max = fd_wksp_data_max_est( sizeof(wksp_mem), part_max );
  fd_wksp_t * wksp = fd_wksp_join( fd_wksp_new( wksp_mem, "funk_test", 1U, part_max, data_max ) );
  FD_TEST( wksp );
  fd_shmem_join_anonymous( "funk_test", FD_SHMEM_JOIN_MODE_READ_WRITE, wksp, wksp_mem, FD_SHMEM_NORMAL_PAGE_SZ, sizeof(wksp_mem)>>FD_SHMEM_NORMAL_LG_PAGE_SZ );

  ulong wksp_tag =  1UL;
  ulong txn_max  =  2UL;
  ulong rec_max  = 64UL;
  void * shfunk = fd_funk_new( fd_wksp_alloc_laddr( wksp, fd_funk_align(), fd_funk_footprint( txn_max, rec_max ), wksp_tag ), wksp_tag, 1UL, txn_max, rec_max );

  g_wksp = fd_wksp_join( wksp_mem );
  memset( g_env, 0, sizeof(test_env_t) );
  FD_TEST( fd_funk_join( g_env->funk, shfunk ) );

  return g_env;
}

static void
test_env_fini( void ) {
  FD_TEST( g_wksp );

  /* Check for funk integrity and leaks */
  FD_TEST( fd_funk_verify( g_env->funk )==FD_FUNK_SUCCESS );
  FD_TEST( !fd_funk_last_publish_is_frozen( g_env->funk ) ); /* no in prep txns */
  void * shfunk;
  FD_TEST( fd_funk_leave( g_env->funk, &shfunk ) );
  FD_TEST( fd_funk_delete( shfunk ) );

  /* Check for alloc leaks */
  fd_wksp_usage_t wksp_usage;
  FD_TEST( fd_wksp_usage( g_wksp, NULL, 0UL, &wksp_usage ) );
  FD_TEST( wksp_usage.free_cnt==wksp_usage.total_cnt );

  memset( g_env, 0, sizeof(test_env_t) );
  fd_shmem_leave_anonymous( g_wksp, NULL );
  FD_TEST( fd_wksp_delete( fd_wksp_leave( g_wksp ) ) );
  g_wksp = NULL;
}

/* race_txn_insert checks for data races when adding records to the same
   transaction (with different keys). */

struct async_txn_insert_ctx {
  fd_funk_t *       funk;
  fd_funk_txn_xid_t xid;
  fd_funk_rec_key_t rec;
};
typedef struct async_txn_insert_ctx async_txn_insert_ctx_t;

static void
async_txn_insert( void * _ctx ) {
  async_txn_insert_ctx_t * ctx = _ctx;

  fd_funk_rec_prepare_t prepare[1];
  int prep_err;
  fd_funk_rec_t * rec = fd_funk_rec_prepare( ctx->funk, &ctx->xid, &ctx->rec, prepare, &prep_err );
  if( FD_UNLIKELY( !rec ) ) FD_LOG_ERR(( "fd_funk_rec_prepare failed (%i-%s)", prep_err, fd_funk_strerror( prep_err ) ));
  fd_funk_val_truncate( rec, fd_funk_alloc( ctx->funk ), fd_funk_wksp( ctx->funk ), 8UL, 16UL, NULL );
  fd_funk_rec_publish( ctx->funk, prepare );
}

static void
race_single_txn_insert( void ) {
  /* Race 3 concurrent insert ops against each other */
# define REC_CNT 3

  test_env_t * env = test_env_init();
  fd_funk_txn_xid_t xid = { .ul={1UL} };

  async_txn_insert_ctx_t ctx[ REC_CNT ];
  for( ulong i=0UL; i<REC_CNT; i++ ) {
    ctx[ i ].funk      = env->funk;
    ctx[ i ].xid       = xid;
    ctx[ i ].rec.ul[0] = i;
  }
  fd_funk_rec_t * rec_pool = env->funk->rec_pool->ele;

  /* Run random interleavings */
  fd_racesan_weave_t weave[1];
  fd_racesan_weave_new( weave );
  fd_racesan_async_t async[ REC_CNT ];
  for( ulong i=0UL; i<REC_CNT; i++ ) {
    FD_TEST( fd_racesan_async_new( &async[i], async_txn_insert, &ctx[i] ) );
    fd_racesan_weave_add( weave, &async[i] );
  }
  ulong iter     = (ulong)1e5;
  ulong step_max = 1024UL;
  for( ulong rem=iter; rem; rem-- ) {
    fd_funk_txn_prepare( env->funk, fd_funk_last_publish( env->funk ), &xid );
    fd_racesan_weave_exec_rand( weave, rem, step_max );
    fd_funk_txn_t * txn = fd_funk_txn_query( &xid, fd_funk_txn_map( env->funk ) );
    uint seen[ REC_CNT ] = {0};
    for( uint rec_idx = txn->rec_head_idx;
         !fd_funk_rec_idx_is_null( rec_idx );
         rec_idx = rec_pool[ rec_idx ].next_idx ) {
      fd_funk_rec_t *           rec = &rec_pool[ rec_idx ];
      fd_funk_rec_key_t const * key = rec->pair.key;
      FD_TEST( !key->ul[1] && !key->ul[2] && !key->ul[3] && !key->ul[4] );
      FD_TEST( key->ul[0]<REC_CNT );
      seen[ key->ul[0] ]++;
    }
    for( ulong i=0UL; i<REC_CNT; i++ ) FD_TEST( seen[ i ]==1U );
    fd_funk_txn_cancel( env->funk, &xid );
  }
  fd_racesan_weave_delete( weave );
  for( ulong i=0UL; i<REC_CNT; i++ ) fd_racesan_async_delete( &async[i] );

  test_env_fini();
# undef REC_CNT
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  race_single_txn_insert();

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
