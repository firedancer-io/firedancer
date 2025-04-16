#include "../runtime/context/fd_exec_slot_ctx.h"
#include "../runtime/context/fd_exec_epoch_ctx.h"
#include "fd_snapshot.h"

int main( int     argc,
          char ** argv ) {
  fd_boot( &argc, &argv );

  char const * _page_sz = fd_env_strip_cmdline_cstr  ( &argc, &argv, "--page-sz",  NULL, "gigantic" );
  ulong        page_cnt = fd_env_strip_cmdline_ulong ( &argc, &argv, "--page-cnt", NULL, 150UL );
  ulong        near_cpu = fd_env_strip_cmdline_ulong ( &argc, &argv, "--near-cpu", NULL, fd_log_cpu_id() );
  char const * snapshot = fd_env_strip_cmdline_cstr  ( &argc, &argv, "--snapshot", NULL, NULL );

  /* Setup workspace */

  FD_LOG_NOTICE(( "Creating workspace (--page-cnt %lu, --page-sz %s)", page_cnt, _page_sz ));
  FD_LOG_WARNING(("near cpu: %lu", near_cpu));
  fd_wksp_t * wksp = fd_wksp_new_anonymous( fd_cstr_to_shmem_page_sz( _page_sz ), page_cnt, near_cpu, "wksp", 0UL );
  FD_TEST( wksp );
  ulong const static_tag = 1UL;

  /* Setup slot context */

  ulong const txn_max =  16UL;
  ulong const rec_max =  200000000UL;

  ulong const funk_seed = 0xeffb398d4552afbcUL;
  ulong const funk_tag  = 42UL;
  fd_funk_t * funk = fd_funk_join( fd_funk_new( fd_wksp_alloc_laddr( wksp, fd_funk_align(), fd_funk_footprint( txn_max, rec_max ), funk_tag ), funk_tag, funk_seed, txn_max, rec_max ) );
  FD_TEST( funk );

  fd_spad_t * _spad = fd_spad_new( fd_wksp_alloc_laddr( wksp, FD_SPAD_ALIGN, FD_SPAD_FOOTPRINT( 4*1024*1024 * 1024UL ), static_tag ), 4*1024*1024 * 1024UL );

  FD_LOG_NOTICE(("setting up tpool with 12 workers! "));
  /* tpool setup */
  uchar _tpool[ FD_TPOOL_FOOTPRINT(FD_TILE_MAX) ] __attribute__((aligned(FD_TPOOL_ALIGN)));
  ulong worker_cnt = 12UL;
  fd_tpool_t * tpool = fd_tpool_init( _tpool, worker_cnt );
  if( tpool == NULL ) {
    FD_LOG_ERR(( "failed to create thread pool" ));
  }
  FD_LOG_WARNING(("tile count: %lu", fd_tile_cnt()));
  (void)tpool;
  FD_LOG_WARNING(("tpool worker max: %lu", fd_tpool_worker_max(tpool)));

  for( ulong i=1UL; i<worker_cnt; i++) {
    if( fd_tpool_worker_push( tpool, i, NULL, 0UL ) == NULL ) {
      FD_LOG_ERR(( "failed to launch worker" ));
    }
  }

  FD_TEST( fd_tpool_worker_cnt(tpool) == worker_cnt );

  /* runtime public set up */
  void * runtime_public_mem = fd_wksp_alloc_laddr( wksp,
    fd_runtime_public_align(),
    fd_runtime_public_footprint(), FD_EXEC_EPOCH_CTX_MAGIC );
  if( FD_UNLIKELY( !runtime_public_mem ) ) {
    FD_LOG_ERR(( "Unable to allocate runtime_public mem" ));
  }
  fd_memset( runtime_public_mem, 0, fd_runtime_public_footprint() );
  fd_runtime_public_t * runtime_public = fd_runtime_public_join( fd_runtime_public_new( runtime_public_mem ) );
  fd_spad_t * runtime_spad = fd_spad_join( fd_wksp_laddr( wksp, runtime_public->runtime_spad_gaddr ) );

  FD_LOG_NOTICE(("starting to load snapshot! "));

  /* load snapshot */
  do {
    fd_spad_push( _spad );
    /* set up epoch context */
    uint cluster_version[3];
    cluster_version[0] = 2;
    cluster_version[1] = 1;
    cluster_version[2] = 14;
    ulong vote_acct_max = 2000000UL;
    uchar * epoch_ctx_mem = fd_spad_alloc( _spad, fd_exec_epoch_ctx_align(), fd_exec_epoch_ctx_footprint( vote_acct_max ) );
    fd_memset( epoch_ctx_mem, 0, fd_exec_epoch_ctx_footprint( vote_acct_max ) );
    fd_exec_epoch_ctx_t * epoch_ctx = fd_exec_epoch_ctx_join( fd_exec_epoch_ctx_new( epoch_ctx_mem, vote_acct_max ) );

    epoch_ctx->runtime_public = runtime_public;
    fd_exec_epoch_ctx_bank_mem_clear( epoch_ctx );
    fd_features_enable_cleaned_up( &epoch_ctx->features, cluster_version );
    fd_memcpy( &epoch_ctx->runtime_public->features, &epoch_ctx->features, sizeof(fd_features_t) );

    uchar slot_ctx_mem[FD_EXEC_SLOT_CTX_FOOTPRINT] __attribute__((aligned(FD_EXEC_SLOT_CTX_ALIGN)));
    fd_exec_slot_ctx_t * slot_ctx = fd_exec_slot_ctx_join( fd_exec_slot_ctx_new( slot_ctx_mem, _spad ) );
    slot_ctx->funk      = funk;
    slot_ctx->epoch_ctx = epoch_ctx;

    long start = fd_log_wallclock();
    fd_snapshot_load_all( snapshot,
                          slot_ctx,
                          NULL,
                          tpool,
                          0,
                          0,
                          FD_SNAPSHOT_TYPE_FULL,
                          NULL,
                          0,
                          runtime_spad );
    long end = fd_log_wallclock();
    FD_LOG_NOTICE(( "snapshot loading took %ld nanos %f seconds %f ops/sec", end-start, ((double)(end-start))/(1000000000UL), 16UL*1048576UL*3UL*1000000000UL/((double)(end-start)) ));
    fd_spad_pop( _spad );
  } while(0);

  return 0;
}