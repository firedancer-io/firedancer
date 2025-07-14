#include "fd_groove.h"

FD_STATIC_ASSERT( FD_GROOVE_VOLUME_ALIGN    ==4096UL,               unit_test );
FD_STATIC_ASSERT( FD_GROOVE_VOLUME_FOOTPRINT==1UL<<30,              unit_test );
FD_STATIC_ASSERT( FD_GROOVE_VOLUME_MAGIC    ==0xfd67007e701c3300UL, unit_test );
FD_STATIC_ASSERT( FD_GROOVE_VOLUME_INFO_MAX ==480UL,                unit_test );
FD_STATIC_ASSERT( FD_GROOVE_VOLUME_DATA_MAX ==(1UL<<30)-512UL,      unit_test );

FD_STATIC_ASSERT( FD_GROOVE_VOLUME_ALIGN    ==alignof(fd_groove_volume_t), unit_test );
FD_STATIC_ASSERT( FD_GROOVE_VOLUME_FOOTPRINT==sizeof( fd_groove_volume_t), unit_test );

#define SHMEM_MAX (1UL<<20)

static FD_TL uchar shmem[ SHMEM_MAX ];
static FD_TL ulong shmem_cnt = 0UL;

static void *
shmem_alloc( ulong a,
             ulong s ) {
  uchar * m  = (uchar *)fd_ulong_align_up( (ulong)(shmem + shmem_cnt), a );
  shmem_cnt = (ulong)((m + s) - shmem);
  FD_TEST( shmem_cnt <= SHMEM_MAX );
  return (void *)m;
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  fd_rng_t rng[1]; fd_rng_join( fd_rng_new( rng, 0U, 0UL ) );

  char const * name       = fd_env_strip_cmdline_cstr ( &argc, &argv, "--name",       NULL,            NULL );
  ulong        volume_cnt = fd_env_strip_cmdline_ulong( &argc, &argv, "--volume-cnt", NULL,             2UL );
  char const * _page_sz   = fd_env_strip_cmdline_cstr ( &argc, &argv, "--page-sz",    NULL,      "gigantic" );
  ulong        near_cpu   = fd_env_strip_cmdline_ulong( &argc, &argv, "--near-cpu",   NULL, fd_log_cpu_id() );

  fd_groove_volume_t * volume;
  ulong                page_sz;
  ulong                page_cnt;
  if( name ) {

    FD_LOG_NOTICE(( "Joining to --name %s", name ));

    fd_shmem_join_info_t info[1];
    volume     = (fd_groove_volume_t *)fd_shmem_join( name, FD_SHMEM_JOIN_MODE_READ_WRITE, NULL, NULL, info ); /* logs details */
    if( FD_UNLIKELY( !volume ) ) FD_LOG_ERR(( "fd_shmem_join failed" ));
    page_sz    = info->page_sz;
    page_cnt   = info->page_cnt;
    volume_cnt = (page_sz*page_cnt) / FD_GROOVE_VOLUME_FOOTPRINT;

  } else {

    FD_LOG_NOTICE(( "--name not specified, using anonymous shmem (--volume-cnt %lu --page-sz %s --near-cpu %lu)",
                    volume_cnt, _page_sz, near_cpu ));

    page_sz  = fd_cstr_to_shmem_page_sz( _page_sz );
    if( FD_UNLIKELY( !page_sz ) ) FD_LOG_ERR(( "invalid page_sz" ));
    page_cnt = (volume_cnt*FD_GROOVE_VOLUME_FOOTPRINT + page_sz-1UL) / page_sz;
    volume   = (fd_groove_volume_t *)fd_shmem_acquire_multi( page_sz, 1UL, &page_cnt, &near_cpu ); /* logs details */
    if( FD_UNLIKELY( !volume ) ) FD_LOG_ERR(( "fd_shmem_join failed" ));

  }

  FD_LOG_NOTICE(( "Testing with %lu groove data volumes", volume_cnt ));

  FD_LOG_NOTICE(( "Creating test volume pool" ));

  void * shpool = shmem_alloc( fd_groove_volume_pool_align(), fd_groove_volume_pool_footprint() );
  FD_TEST( fd_groove_volume_pool_new( shpool )==shpool );

  FD_LOG_NOTICE(( "Testing volume pool operations" ));

  fd_groove_volume_pool_t pool[1];
  FD_TEST( fd_groove_volume_pool_join( pool, shpool, volume, volume_cnt ) );

# define BUF_MAX (2UL*FD_GROOVE_VOLUME_INFO_MAX)
  uchar buf[ BUF_MAX ];

  ulong vfp = FD_GROOVE_VOLUME_FOOTPRINT;
  FD_TEST( !fd_groove_volume_pool_add( 0UL,  NULL,                  0UL,  NULL, 0UL ) );
  FD_TEST(  fd_groove_volume_pool_add( NULL, volume,                vfp,  NULL, 0UL )==FD_GROOVE_ERR_INVAL );
  FD_TEST(  fd_groove_volume_pool_add( pool, NULL,                  vfp,  NULL, 0UL )==FD_GROOVE_ERR_INVAL );
  FD_TEST(  fd_groove_volume_pool_add( pool, volume,                -vfp, NULL, 0UL )==FD_GROOVE_ERR_INVAL );
  FD_TEST(  fd_groove_volume_pool_add( pool, (uchar *)volume + 1UL, vfp,  NULL, 0UL )==FD_GROOVE_ERR_INVAL );
  FD_TEST(  fd_groove_volume_pool_add( pool, volume,                1UL,  NULL, 0UL )==FD_GROOVE_ERR_INVAL );

  FD_TEST( !fd_groove_volume_pool_remove( NULL ) );

  for( ulong rem=100000UL; rem; rem-- ) {
    ulong i0 = fd_rng_ulong_roll( rng, volume_cnt );
    ulong i1 = fd_rng_ulong_roll( rng, volume_cnt );
    fd_swap_if( i1<i0, i0, i1 );
    i1++;

    FD_TEST( !fd_groove_volume_pool_remove( pool ) );

    ulong info_sz = fd_rng_ulong_roll( rng, BUF_MAX+1UL ); /* In [0,BUF_MAX] */
    for( ulong i=0UL; i<info_sz; i++ ) buf[i] = fd_rng_uchar( rng );
    uchar * info = (fd_rng_uint( rng ) & 1U) ? buf : NULL;

    FD_TEST( !fd_groove_volume_pool_add( pool, &volume[i0], (i1-i0)*FD_GROOVE_VOLUME_FOOTPRINT, info, info_sz ) );

    if( !info ) info_sz = 0UL;
    if( info_sz>FD_GROOVE_VOLUME_INFO_MAX ) info_sz = FD_GROOVE_VOLUME_INFO_MAX;

    for( ulong i=i0; i<i1; i++ ) {
      FD_TEST( volume[i].magic  ==~FD_GROOVE_VOLUME_MAGIC );
      FD_TEST( volume[i].idx    ==i                       );
      FD_TEST( volume[i].info_sz==info_sz                 );
      if( FD_LIKELY( info_sz ) ) FD_TEST( !memcmp( volume[i].info, info, info_sz ) );
      for( ulong j=info_sz; j<FD_GROOVE_VOLUME_INFO_MAX; j++ ) FD_TEST( !volume[i].info[j] );
      FD_TEST( fd_groove_volume_pool_remove( pool )==&volume[i] );
      FD_TEST( !volume[i].magic );
    }
  }

  FD_TEST( !fd_groove_volume_pool_remove( pool ) );

  FD_LOG_NOTICE(( "Destroying test volume pool" ));

  FD_TEST( fd_groove_volume_pool_leave( pool )==pool );

  FD_TEST( fd_groove_volume_pool_delete( shpool )==shpool );

  FD_LOG_NOTICE(( "Cleaning up" ));

  if( name ) fd_shmem_leave  ( volume, NULL, NULL );        /* logs details */
  else       fd_shmem_release( volume, page_sz, page_cnt ); /* logs details */

  fd_rng_delete( fd_rng_leave( rng ) );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
