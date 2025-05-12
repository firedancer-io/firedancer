#include "../fd_util.h"
/* FIXME: CLEANUP */
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>

static FD_TL fd_rng_t rng_mem[1];

static FD_FOR_ALL_BEGIN( rng_init, 1L ) {
  fd_rng_t ** _rng = (fd_rng_t **)arg[0];
  _rng[ tpool_t0 ] = fd_rng_join( fd_rng_new( rng_mem, (uint)tpool_t0, 0UL ) );
} FD_FOR_ALL_END

static FD_FOR_ALL_BEGIN( rng_fini, 1L ) {
  fd_rng_t ** _rng = (fd_rng_t **)arg[0];
  fd_rng_delete( fd_rng_leave( _rng[ tpool_t0 ] ) );
} FD_FOR_ALL_END

typedef struct {
  ulong gaddr0;
  ulong sz;
} alloc_info_t;

static FD_FOR_ALL_BEGIN( alloc_init, 1L ) {
  fd_wksp_t *          wksp = (fd_wksp_t *)         arg[0];
  alloc_info_t const * info = (alloc_info_t const *)arg[1];

  for( long idx=block_i0; idx<block_i1; idx++ ) {
    ulong gaddr0 = info[ idx ].gaddr0;   /* !=0 */
    ulong sz     = info[ idx ].sz;       /* >0  */
    ulong tag    = (ulong)(idx+1L);      /* >0, unique */
    int   c      = 1+(int)(tag % 255UL); /* in [1,255] */
    memset( fd_wksp_laddr_fast( wksp, gaddr0 ), c, sz ); /* Fill allocation region with test pattern */
  }

} FD_FOR_ALL_END

static FD_FOR_ALL_BEGIN( alloc_zero, 1L ) {
  fd_wksp_t *          wksp = (fd_wksp_t *)         arg[0];
  alloc_info_t const * info = (alloc_info_t const *)arg[1];

  for( long idx=block_i0; idx<block_i1; idx++ ) {
    ulong gaddr0 = info[ idx ].gaddr0; /* !=0 */
    ulong sz     = info[ idx ].sz;     /* >0  */
    memset( fd_wksp_laddr_fast( wksp, gaddr0 ), 0, sz ); /* Zero out allocation region */
  }

} FD_FOR_ALL_END

static FD_FOR_ALL_BEGIN( alloc_test, 1L ) {
  fd_wksp_t *          wksp = (fd_wksp_t *)         arg[0];
  alloc_info_t const * info = (alloc_info_t const *)arg[1];

  fd_rng_t * rng  = ((fd_rng_t **)arg[2])[ tpool_t0 ];

  for( long idx=block_i0; idx<block_i1; idx++ ) {
    ulong gaddr0 = info[ idx ].gaddr0;   /* !=0 */
    ulong sz     = info[ idx ].sz;       /* >0  */
    ulong tag    = (ulong)(idx+1L);      /* >0, unique  */
    int   c      = 1+(int)(tag % 255UL); /* in [1,255] */

    /* Verify that the first, last and randomly chosen byte of the
       allocation region matches the allocation tag */

    FD_TEST( fd_wksp_tag( wksp, gaddr0                                )==tag );
    FD_TEST( fd_wksp_tag( wksp, gaddr0 + fd_rng_ulong_roll( rng, sz ) )==tag );
    FD_TEST( fd_wksp_tag( wksp, gaddr0 + sz - 1UL                     )==tag );

    /* Verify that the test pattern in the allocation region is correct */

    uchar * laddr0 = (uchar *)fd_wksp_laddr_fast( wksp, gaddr0 );
    for( ulong off=0UL; off<sz; off++ ) FD_TEST( ((int)laddr0[off])==c );
  }

} FD_FOR_ALL_END

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  char const * path       = fd_env_strip_cmdline_cstr ( &argc, &argv, "--path",       NULL,            NULL );
  char const * _mode      = fd_env_strip_cmdline_cstr ( &argc, &argv, "--mode",       NULL,          "0600" );
  int          keep       = fd_env_strip_cmdline_int  ( &argc, &argv, "--keep",       NULL,               0 );
  ulong        worker_cnt = fd_env_strip_cmdline_ulong( &argc, &argv, "--worker-cnt", NULL,   fd_tile_cnt() );
  char const * _wksp      = fd_env_strip_cmdline_cstr ( &argc, &argv, "--wksp",       NULL,            NULL );
  char const * _page_sz   = fd_env_strip_cmdline_cstr ( &argc, &argv, "--page-sz",    NULL,      "gigantic" );
  ulong        page_cnt   = fd_env_strip_cmdline_ulong( &argc, &argv, "--page-cnt",   NULL,             1UL );
  ulong        near_cpu   = fd_env_strip_cmdline_ulong( &argc, &argv, "--near-cpu",   NULL, fd_log_cpu_id() );
  ulong        iter_max   = fd_env_strip_cmdline_ulong( &argc, &argv, "--iter-max",   NULL,           100UL );

  char tmp_path[256];
  if( !path ) path = fd_cstr_printf( tmp_path, 256UL, NULL, "/tmp/test_wksp_tpool.%lu.%li", fd_log_group_id(), fd_log_wallclock() );

  ulong mode = fd_cstr_to_ulong_octal( _mode );

  FD_LOG_NOTICE(( "Using --path %s --mode 0%03lo --keep %i", path, mode, keep ));

  FD_LOG_NOTICE(( "Creating thread pool (--worker-cnt %lu)", worker_cnt ));
  static uchar _tpool[ FD_TPOOL_FOOTPRINT(FD_TILE_MAX) ] __attribute__((aligned(FD_TPOOL_ALIGN)));
  fd_tpool_t * tpool = fd_tpool_init( _tpool, worker_cnt, 0UL ); /* logs details */
  if( FD_UNLIKELY( !tpool ) ) FD_LOG_ERR(( "fd_tpool_init failed" ));

  FD_LOG_NOTICE(( "Adding tiles as workers to thread pool" ));

  for( ulong worker_idx=1UL; worker_idx<worker_cnt; worker_idx++ )
    if( FD_UNLIKELY( !fd_tpool_worker_push( tpool, worker_idx ) ) ) FD_LOG_ERR(( "fd_tpool_worker_push failed" ));

  FD_LOG_NOTICE(( "Creating random number generators" ));

  static fd_rng_t * _rng[ FD_TILE_MAX ];
  FD_FOR_ALL( rng_init, tpool, 0UL, worker_cnt, 0L, (long)worker_cnt, _rng );
  fd_rng_t * rng = _rng[0];

  fd_wksp_t * wksp;
  if( _wksp ) {
    FD_LOG_NOTICE(( "Attaching to --wksp %s", _wksp ));
    wksp = fd_wksp_attach( _wksp );
  } else {
    FD_LOG_NOTICE(( "--wksp not specified, using an anonymous local workspace (--page-sz %s --page-cnt %lu --near-cpu %lu)",
                    _page_sz, page_cnt, near_cpu ));
    wksp = fd_wksp_new_anonymous( fd_cstr_to_shmem_page_sz( _page_sz ), page_cnt, near_cpu, "wksp", 0UL );
  }

  FD_LOG_NOTICE(( "Testing (--iter-max %lu)", iter_max ));

  for( ulong iter=0UL; iter<iter_max; iter++ ) {
    FD_LOG_NOTICE(( "iter %lu", iter ));

    /* Reset the wksp and fill it with randomly aligned and sized allocations */

    uint seed0 = fd_rng_uint( rng );
    fd_wksp_reset( wksp, seed0 );

#   define ALLOC_MAX (8192L)
    static alloc_info_t info[ ALLOC_MAX ];

    long alloc_cnt;
    for( alloc_cnt=0L; alloc_cnt<ALLOC_MAX; alloc_cnt++ ) {
      uint  mask   = (1U << fd_rng_uint_roll( rng, 21U )) - 1U; /* Pick a mask that is all ones in the N least significant bits
                                                                   where N is uniform random in [0,20] */
      ulong align  = 1UL << fd_rng_uint_roll( rng, 7U );        /* Pick a random alignment in 1,2,4,...64 */
      ulong sz     = 1UL + (ulong)(fd_rng_uint( rng ) & mask);  /* Pick a random size power law distributed in [1,1MiB] */
      ulong tag    = (ulong)(alloc_cnt+1L);                     /* Pick a unique non-zero tag for this allocation */
      ulong gaddr0 = fd_wksp_alloc( wksp, align, sz, tag );     /* Do the allocation */
      if( FD_UNLIKELY( !gaddr0 ) ) break;                       /* If wksp is full, we are done */
      info[ alloc_cnt ].gaddr0 = gaddr0;                        /* Save alloc details for thread parallel use below */
      info[ alloc_cnt ].sz     = sz;
    }

    /* Fill each allocations with a test pattern */

    FD_FOR_ALL( alloc_init, tpool, 0UL, worker_cnt, 0L, alloc_cnt, wksp, info );

    /* Blow away any existing file at path and then thread parallel
       checkpt the wksp to path with a random style */

    unlink( path );

    ulong t0    = 0UL;
    ulong t1    = 1UL + fd_rng_ulong_roll( rng, worker_cnt );
    int   style = (int)fd_rng_uint_roll( rng, FD_HAS_LZ4 ? 4U : 3U );

    FD_TEST( !fd_wksp_checkpt_tpool( tpool, t0, t1, wksp, path, mode, style, "test_wksp_tpool" ) );

    /* Zero out all the allocations */

    FD_FOR_ALL( alloc_zero, tpool,0UL,worker_cnt, 0L,alloc_cnt, wksp, info );

    /* Restore the wksp from the checkpt using a different range of
       threads and seed. */

    ulong t2    = 0UL;
    ulong t3    = 1UL + fd_rng_ulong_roll( rng, worker_cnt );
    uint  seed1 = fd_rng_uint( rng );
    FD_TEST( !fd_wksp_restore_tpool( tpool, t2, t3, wksp, path, seed1 ) );

    /* Test all the allocations are as expected */

    FD_FOR_ALL( alloc_test, tpool,0UL,worker_cnt, 0L,alloc_cnt, wksp, info, _rng );

    /* TODO: TEST THERE ARE NO OTHER ALLOCATIONS IN THE WKSP TOO! */
  }

  FD_LOG_NOTICE(( "Cleaning up" ));

  if( FD_LIKELY( !keep ) && FD_UNLIKELY( unlink( path ) ) )
    FD_LOG_WARNING(( "unlink(%s) failed (%i-%s); attempting to continue", path, errno, fd_io_strerror( errno ) ));

  if( _wksp ) fd_wksp_detach( wksp );
  else        fd_wksp_delete_anonymous( wksp );

  FD_FOR_ALL( rng_fini, tpool,0UL,worker_cnt, 0L,(long)worker_cnt, _rng );

  /* Note: fini automatically pops all worker threads */

  fd_tpool_fini( tpool ); /* logs details */

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
