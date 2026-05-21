#include "fd_snapin_tile_private.h"
#include "../../funk/fd_funk.h"
#include <stdlib.h>

#if FD_HAS_HOSTED

#define TEST_WKSP_TAG (1UL)
#define TEST_SLOT     (42UL)

struct test_funk_env {
  fd_wksp_t * wksp;
  void *      shfunk;
  void *      shlocks;
  fd_funk_t   funk_join[1];
};
typedef struct test_funk_env test_funk_env_t;

static void
setup_funk_env( test_funk_env_t * env ) {
  memset( env, 0, sizeof(test_funk_env_t) );

  env->wksp = fd_wksp_new_anonymous( fd_cstr_to_shmem_page_sz( "normal" ), 512UL, fd_log_cpu_id(), "wksp", 64UL );
  FD_TEST( env->wksp );

  ulong const txn_max = 4UL;
  ulong const rec_max = 32UL;

  env->shfunk = fd_wksp_alloc_laddr( env->wksp, fd_funk_align(), fd_funk_shmem_footprint( txn_max, rec_max ), TEST_WKSP_TAG );
  FD_TEST( env->shfunk );
  FD_TEST( fd_funk_shmem_new( env->shfunk, TEST_WKSP_TAG, 1UL, txn_max, rec_max ) );

  env->shlocks = fd_wksp_alloc_laddr( env->wksp, fd_funk_align(), fd_funk_locks_footprint( txn_max, rec_max ), TEST_WKSP_TAG );
  FD_TEST( env->shlocks );
  FD_TEST( fd_funk_locks_new( env->shlocks, txn_max, rec_max ) );

  FD_TEST( fd_funk_join( env->funk_join, env->shfunk, env->shlocks ) );
}

static void
teardown_funk_env( test_funk_env_t * env ) {
  fd_wksp_delete_anonymous( env->wksp );
}

static void
setup_snapin_ctx( fd_snapin_tile_t * ctx,
                  fd_funk_t *        funk ) {
  memset( ctx, 0, sizeof(fd_snapin_tile_t) );
  ctx->full = 1;
  ctx->funk = funk;
  fd_funk_txn_xid_set_root( ctx->xid );
}

static void
build_account_frame( uchar * frame,
                     uchar   pubkey_seed,
                     ulong   lamports,
                     uchar   data0 ) {
  fd_memset( frame, 0, 0x89UL );
  FD_STORE( ulong, frame+0x08UL, 1UL       ); /* data_len */
  FD_STORE( ulong, frame+0x30UL, lamports  );
  FD_STORE( ulong, frame+0x38UL, ULONG_MAX ); /* rent_epoch */

  for( ulong j=0UL; j<32UL; j++ ) {
    frame[ 0x10UL+j ] = (uchar)( pubkey_seed + j );
    frame[ 0x40UL+j ] = (uchar)( 0xA0U + pubkey_seed + j );
  }
  frame[ 0x60UL ] = 0U;
  frame[ 0x88UL ] = data0;
}

static void
build_account_batch( fd_ssparse_advance_result_t * result,
                     uchar                          frames[ FD_SSPARSE_ACC_BATCH_MAX ][ 0x89UL ],
                     int                            duplicate_first_key ) {
  memset( result, 0, sizeof(fd_ssparse_advance_result_t) );
  result->account_batch.batch_cnt = FD_SSPARSE_ACC_BATCH_MAX;
  result->account_batch.slot      = TEST_SLOT;

  for( ulong i=0UL; i<FD_SSPARSE_ACC_BATCH_MAX; i++ ) {
    build_account_frame( frames[ i ], (uchar)( 1UL+i ), 100UL+i, (uchar)( 0xC0UL+i ) );
    result->account_batch.batch[ i ] = frames[ i ];
  }

  if( duplicate_first_key ) {
    fd_memcpy( frames[ 1 ]+0x10UL, frames[ 0 ]+0x10UL, 32UL );
  }
}

static void
test_account_batch_insert_success( void ) {
  test_funk_env_t env[1];
  setup_funk_env( env );

  fd_snapin_tile_t ctx[1];
  setup_snapin_ctx( ctx, env->funk_join );

  fd_ssparse_advance_result_t result[1];
  uchar frames[ FD_SSPARSE_ACC_BATCH_MAX ][ 0x89UL ];
  build_account_batch( result, frames, 0 );

  FD_TEST( fd_snapin_process_account_batch( ctx, result )==0 );
  FD_TEST( ctx->metrics.accounts_loaded==FD_SSPARSE_ACC_BATCH_MAX );
  FD_TEST( ctx->capitalization==828UL );

  for( ulong i=0UL; i<FD_SSPARSE_ACC_BATCH_MAX; i++ ) {
    fd_funk_rec_key_t key = FD_LOAD( fd_funk_rec_key_t, frames[ i ]+0x10UL );
    fd_funk_rec_query_t query[1];
    fd_funk_rec_t * rec = fd_funk_rec_query_try( env->funk_join, ctx->xid, &key, query );
    FD_TEST( rec );

    fd_account_meta_t const * meta = fd_funk_val( rec, env->funk_join->wksp );
    FD_TEST( meta );
    FD_TEST( meta->slot==TEST_SLOT );
    FD_TEST( meta->lamports==100UL+i );
    FD_TEST( meta->dlen==1U );
    FD_TEST( *((uchar const *)( meta+1 ))==(uchar)( 0xC0UL+i ) );
  }

  teardown_funk_env( env );
}

static void
test_account_batch_rejects_duplicate_in_same_batch( void ) {
  test_funk_env_t env[1];
  setup_funk_env( env );

  fd_snapin_tile_t ctx[1];
  setup_snapin_ctx( ctx, env->funk_join );

  fd_ssparse_advance_result_t result[1];
  uchar frames[ FD_SSPARSE_ACC_BATCH_MAX ][ 0x89UL ];
  build_account_batch( result, frames, 1 );

  FD_TEST( fd_snapin_process_account_batch( ctx, result )==-1 );
  FD_TEST( ctx->metrics.accounts_loaded==2UL );

  teardown_funk_env( env );
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  test_account_batch_insert_success();
  test_account_batch_rejects_duplicate_in_same_batch();

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}

#else

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );
  FD_LOG_WARNING(( "skip: unit test requires FD_HAS_HOSTED capabilities" ));
  fd_halt();
  return 0;
}

#endif
