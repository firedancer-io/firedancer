#include "../fd_vinyl.h"

FD_STATIC_ASSERT( FD_VINYL_DATA_SZC_CNT==188UL, unit_test );

FD_STATIC_ASSERT( FD_VINYL_DATA_OBJ_TYPE_FREEVOL   ==0xf7eef7eef7eef7eeUL, unit_test );
FD_STATIC_ASSERT( FD_VINYL_DATA_OBJ_TYPE_ALLOC     ==0xa11ca11ca11ca11cUL, unit_test );
FD_STATIC_ASSERT( FD_VINYL_DATA_OBJ_TYPE_SUPERBLOCK==0x59e759e759e759e7UL, unit_test );

FD_STATIC_ASSERT( FD_VINYL_DATA_OBJ_GUARD_SZ==384UL, unit_test );

FD_STATIC_ASSERT( alignof(fd_vinyl_data_obj_t)==FD_VINYL_BSTREAM_BLOCK_SZ, unit_test );
FD_STATIC_ASSERT( sizeof (fd_vinyl_data_obj_t)==FD_VINYL_BSTREAM_BLOCK_SZ, unit_test );

FD_STATIC_ASSERT( FD_VINYL_DATA_VOL_FOOTPRINT==114211328UL, unit_test );

FD_STATIC_ASSERT( FD_VINYL_DATA_ALIGN    == 128UL, unit_test );
FD_STATIC_ASSERT( FD_VINYL_DATA_FOOTPRINT==3072UL, unit_test );

FD_STATIC_ASSERT( alignof(fd_vinyl_data_vol_t)==FD_VINYL_BSTREAM_BLOCK_SZ,   unit_test );
FD_STATIC_ASSERT( sizeof (fd_vinyl_data_vol_t)==FD_VINYL_DATA_VOL_FOOTPRINT, unit_test );

#define ALLOC_MAX (65536UL)

fd_vinyl_data_obj_t * alloc[ ALLOC_MAX ];

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  char const * name     = fd_env_strip_cmdline_cstr ( &argc, &argv, "--name",     NULL,            NULL );
  ulong        page_cnt = fd_env_strip_cmdline_ulong( &argc, &argv, "--page-cnt", NULL,             1UL );
  char const * _page_sz = fd_env_strip_cmdline_cstr ( &argc, &argv, "--page-sz",  NULL,      "gigantic" );
  ulong        near_cpu = fd_env_strip_cmdline_ulong( &argc, &argv, "--near-cpu", NULL, fd_log_cpu_id() );
  ulong        iter_cnt = fd_env_strip_cmdline_ulong( &argc, &argv, "--iter-cnt", NULL,        10000000 );
  int          level    = fd_env_strip_cmdline_int  ( &argc, &argv, "--level",    NULL,               0 );

  fd_rng_t rng[1]; fd_rng_join( fd_rng_new( rng, 0U, 0UL ) );

  fd_tpool_t * tpool = NULL;

  ulong thread_cnt = fd_tile_cnt();

  if( thread_cnt>1UL ) {
    FD_LOG_NOTICE(( "Creating tpool from all %lu tiles", thread_cnt ));

    static uchar _tpool[ FD_TPOOL_FOOTPRINT( FD_TILE_MAX ) ] __attribute__((aligned(FD_TPOOL_ALIGN)));

    tpool = fd_tpool_init( _tpool, thread_cnt, 0UL ); /* logs details */
    if( FD_UNLIKELY( !tpool ) ) FD_LOG_ERR(( "fd_tpool_init failed" ));

    for( ulong thread_idx=1UL; thread_idx<thread_cnt; thread_idx++ )
      if( FD_UNLIKELY( !fd_tpool_worker_push( tpool, thread_idx ) ) ) FD_LOG_ERR(( "fd_tpool_worker_push failed" ));
  }

  FD_LOG_NOTICE(( "Testing fd_vinyl_data size classes" ));

  FD_TEST( fd_vinyl_data_szc_val_max( FD_VINYL_DATA_SZC_CNT-1UL ) >= FD_VINYL_VAL_MAX );
  FD_TEST( fd_vinyl_data_szc( 0UL )==0UL );

  FD_TEST( fd_vinyl_data_szc_val_max( fd_vinyl_data_szc( FD_VINYL_VAL_MAX ) )==FD_VINYL_VAL_MAX );

  ulong val_max = 0UL;
  for( ulong szc=0UL; szc<FD_VINYL_DATA_SZC_CNT; szc++ ) {
    ulong val_max_prev = val_max;

    /* General sizeclass tests */

    /**/  val_max    = (ulong)fd_vinyl_data_szc_cfg[ szc ].val_max;
    ulong obj_cnt    = (ulong)fd_vinyl_data_szc_cfg[ szc ].obj_cnt;
    ulong parent_szc = (ulong)fd_vinyl_data_szc_cfg[ szc ].parent_szc;

    ulong obj_footprint = fd_vinyl_data_szc_obj_footprint( szc );

    FD_TEST( val_max > val_max_prev                                 ); /* Sorted by val_max */
    FD_TEST( (2UL<=obj_cnt) & (obj_cnt<=64UL)                       ); /* Valid obj_cnt */
    FD_TEST( (szc<parent_szc) & (parent_szc<=FD_VINYL_DATA_SZC_CNT) ); /* Parent superblock szc is higher or a volume */

    /* parent sizeclass can hold a superblock of this size */
    ulong superblock_footprint = sizeof(fd_vinyl_data_obj_t) + obj_cnt*obj_footprint;
    if( parent_szc<FD_VINYL_DATA_SZC_CNT ) FD_TEST( superblock_footprint<=fd_vinyl_data_szc_obj_footprint( parent_szc ) );
    else                                   FD_TEST( superblock_footprint<=FD_VINYL_DATA_VOL_FOOTPRINT );

    /* Test szc_val_max( szc )==val_max and szc( val_test )==szc for
       val_test in (val_max_prev,val_max]. */

    FD_TEST( fd_vinyl_data_szc_val_max( szc )==val_max );
    for( ulong val_test=val_max; val_test>val_max_prev; val_test-- ) FD_TEST( fd_vinyl_data_szc( val_test )==szc );

    /* fd_vinyl_data_t specific tests */

    /* object footprint correct for object in memory layout */
    ulong _obj_footprint = sizeof(fd_vinyl_data_obj_t) + sizeof(fd_vinyl_bstream_phdr_t) + val_max + FD_VINYL_BSTREAM_FTR_SZ;
    FD_TEST( obj_footprint==_obj_footprint );
    FD_TEST( fd_ulong_is_aligned( obj_footprint,               FD_VINYL_BSTREAM_BLOCK_SZ ) );
    FD_TEST( fd_ulong_is_aligned( sizeof(fd_vinyl_data_obj_t), FD_VINYL_BSTREAM_BLOCK_SZ ) );
  }

  FD_LOG_NOTICE(( "Testing fd_vinyl_data obj accessors" ));

  for( ulong rem=1000000UL; rem; rem-- ) {

#   define VAL_MAX (FD_VINYL_BSTREAM_BLOCK_SZ - sizeof(fd_vinyl_bstream_phdr_t) - FD_VINYL_BSTREAM_FTR_SZ)
    struct {
      fd_vinyl_data_obj_t     obj;
      fd_vinyl_bstream_phdr_t phdr;
      uchar                   val[ VAL_MAX ];
      ulong                   hash_trail;
      ulong                   hash_blocks;
    } cache;

    ulong r      = fd_rng_ulong( rng );
    ulong szc    = r % FD_VINYL_DATA_SZC_CNT;
    ulong val_sz = (ulong)(uint)r;

    cache.obj.szc          = (ushort)szc;
    cache.phdr.info.val_sz = (uint)val_sz;

    FD_TEST( fd_vinyl_data_obj_phdr   ( &cache.obj ) == &cache.phdr                      );
    FD_TEST( fd_vinyl_data_obj_key    ( &cache.obj ) == &cache.phdr.key                  );
    FD_TEST( fd_vinyl_data_obj_info   ( &cache.obj ) == &cache.phdr.info                 );
    FD_TEST( fd_vinyl_data_obj_val    ( &cache.obj ) == (void *)cache.val                );
    FD_TEST( fd_vinyl_data_obj_val_sz ( &cache.obj ) == val_sz                           );
    FD_TEST( fd_vinyl_data_obj_val_max( &cache.obj ) == fd_vinyl_data_szc_val_max( szc ) );

    FD_TEST( fd_vinyl_data_obj        (  cache.val ) == &cache.obj                       );
    FD_TEST( fd_vinyl_data_phdr       (  cache.val ) == &cache.phdr                      );
    FD_TEST( fd_vinyl_data_key        (  cache.val ) == &cache.phdr.key                  );
    FD_TEST( fd_vinyl_data_info       (  cache.val ) == &cache.phdr.info                 );
    FD_TEST( fd_vinyl_data_val_sz     (  cache.val ) == val_sz                           );
    FD_TEST( fd_vinyl_data_val_max    (  cache.val ) == fd_vinyl_data_szc_val_max( szc ) );

  }

  FD_LOG_NOTICE(( "Acquiring local and shared memory" ));

  fd_vinyl_data_t lmem[1];

  void * shmem;
  ulong  page_sz;
  if( name ) {

    FD_LOG_NOTICE(( "Joining to --name %s", name ));
    fd_shmem_join_info_t info[1];
    shmem    = fd_shmem_join( name, FD_SHMEM_JOIN_MODE_READ_WRITE, NULL, NULL, info, 0 ); /* logs details */
    if( FD_UNLIKELY( !shmem ) ) FD_LOG_ERR(( "fd_shmem_join failed" ));
    page_cnt = info->page_cnt;
    page_sz  = info->page_sz;

  } else {

    FD_LOG_NOTICE(( "--name not specified, using anonymous shmem (--page-cnt %lu --page-sz %s --near-cpu %lu)",
                    page_cnt, _page_sz, near_cpu ));
    page_sz = fd_cstr_to_shmem_page_sz( _page_sz );
    if( FD_UNLIKELY( !page_sz ) ) FD_LOG_ERR(( "invalid page_sz" ));
    shmem   = fd_shmem_acquire_multi( page_sz, 1UL, &page_cnt, &near_cpu ); /* logs details */
    if( FD_UNLIKELY( !shmem ) ) FD_LOG_ERR(( "fd_shmem_acquire_multi failed" ));

  }

  ulong shmem_sz = page_sz*page_cnt;

  FD_LOG_NOTICE(( "Testing with %lu size data cache", shmem_sz ));

  FD_LOG_NOTICE(( "Testing fd_vinyl_data_t construction" ));

  ulong align     = fd_vinyl_data_align    (); FD_TEST( fd_ulong_is_pow2( align ) );
  ulong footprint = fd_vinyl_data_footprint(); FD_TEST( fd_ulong_is_aligned( footprint, align ) );

  ulong sz_too_small = FD_VINYL_DATA_VOL_FOOTPRINT - 1UL;

  FD_TEST( !fd_vinyl_data_init( NULL,        shmem,             shmem_sz,     NULL        ) ); /* NULL lmem */
  FD_TEST( !fd_vinyl_data_init( (void *)1UL, shmem,             shmem_sz,     NULL        ) ); /* misaligned lmem */
  FD_TEST( !fd_vinyl_data_init( lmem,        NULL,              shmem_sz,     NULL        ) ); /* NULL shmem */
  FD_TEST( !fd_vinyl_data_init( lmem,        (void *)ULONG_MAX, shmem_sz,     NULL        ) ); /* shmem wraps */
  FD_TEST( !fd_vinyl_data_init( lmem,        shmem,             sz_too_small, NULL        ) ); /* sz too small */
  FD_TEST( !fd_vinyl_data_init( lmem,        shmem,             shmem_sz,     shmem       ) ); /* shmem at or before laddr0 */
  FD_TEST( !fd_vinyl_data_init( lmem,        shmem,             shmem_sz,     (void *)1UL ) ); /* misaligned laddr0 */

  fd_vinyl_data_t * data = fd_vinyl_data_init( lmem, shmem, shmem_sz, NULL );
  FD_TEST( data );

  FD_LOG_NOTICE(( "Testing fd_vinyl_data_t reset (--level %i)", level ));

  fd_vinyl_data_reset( tpool,0UL,thread_cnt, level, data );

  FD_TEST( !fd_vinyl_data_verify( data ) );

  FD_LOG_NOTICE(( "Testing fd_vinyl data_t accessors" ));

  FD_TEST( fd_vinyl_data_laddr0  ( data )==NULL     );
  FD_TEST( fd_vinyl_data_shmem   ( data )==shmem    );
  FD_TEST( fd_vinyl_data_shmem_sz( data )==shmem_sz );

  FD_LOG_NOTICE(( "Testing alloc/free (--iter-cnt %lu)", iter_cnt ));

  ulong verify_rem = 0UL;
  for( ulong iter_idx=0UL; iter_idx<iter_cnt; iter_idx++ ) {
    if( !verify_rem ) {
      FD_LOG_NOTICE(( "Iter %lu of %lu: verifying", iter_idx, iter_cnt ));
      FD_TEST( !fd_vinyl_data_verify( data ) );
      verify_rem = iter_cnt / 10UL;
    }
    verify_rem--;

    ulong alloc_idx = fd_rng_ulong( rng ) & (ALLOC_MAX-1UL);

    fd_vinyl_data_obj_t * obj = alloc[ alloc_idx ];
    if( !obj ) {
      ulong pat = fd_rng_ulong( rng );
      ulong szc = fd_ulong_min( 16UL*fd_rng_coin_tosses( rng ) + (pat & 15UL), FD_VINYL_DATA_SZC_CNT-1UL );

      obj = fd_vinyl_data_alloc( data, szc );
      if( FD_UNLIKELY( !obj ) ) continue;

      FD_TEST( fd_vinyl_data_is_valid_obj( obj, data->vol, data->vol_cnt ) );

      obj->unused[0] = pat;

      uchar * p = (uchar *)(obj+1);
      for( ulong rem=fd_vinyl_bstream_pair_sz( fd_vinyl_data_szc_val_max( szc ) ) >> 3; rem; p+=8UL, rem-- ) *(ulong *)p = pat;

      alloc[ alloc_idx ] = obj;

    } else {
      uchar const * p   = (uchar const *)(obj+1);
      ulong         pat = obj->unused[0];

      for( ulong rem=fd_vinyl_bstream_pair_sz( fd_vinyl_data_szc_val_max( (ulong)obj->szc ) ) >> 3; rem; p+=8UL, rem-- )
        FD_TEST( *((ulong const *)p)==pat );

      FD_TEST( fd_vinyl_data_is_valid_obj( obj, data->vol, data->vol_cnt ) );

      fd_vinyl_data_free( data, obj );

      FD_TEST( !fd_vinyl_data_is_valid_obj( obj, data->vol, data->vol_cnt ) );

      alloc[ alloc_idx ] = NULL;
    }
  }

  FD_TEST( !fd_vinyl_data_verify( data ) );

  for( ulong alloc_idx=0UL; alloc_idx<ALLOC_MAX; alloc_idx++ ) {
    fd_vinyl_data_obj_t * obj = alloc[ alloc_idx ];
    if( obj ) {
      uchar const * p   = (uchar const *)(obj+1);
      ulong         pat = obj->unused[0];

      for( ulong rem=fd_vinyl_bstream_pair_sz( fd_vinyl_data_szc_val_max( (ulong)obj->szc ) ) >> 3; rem; p+=8UL, rem-- )
        FD_TEST( *((ulong const *)p)==pat );

      fd_vinyl_data_free( data, obj );

      alloc[ alloc_idx ] = NULL;
    }
  }

  FD_TEST( !fd_vinyl_data_verify( data ) );

  FD_LOG_NOTICE(( "Testing fd_vinyl_data_t destruction" ));

  FD_TEST( !fd_vinyl_data_fini( NULL ) );

  FD_TEST( fd_vinyl_data_fini( lmem )==lmem );

  FD_LOG_NOTICE(( "Cleaning up" ));

  if( name ) fd_shmem_leave  ( shmem, NULL, NULL );        /* logs details */
  else       fd_shmem_release( shmem, page_sz, page_cnt ); /* logs details */

  if( tpool ) fd_tpool_fini( tpool ); /* logs details, note: fini automatically pops all worker threads */

  fd_rng_delete( fd_rng_leave( rng ) );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
