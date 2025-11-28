#include "fd_groove.h"

FD_STATIC_ASSERT( FD_GROOVE_DATA_SZC_CNT       ==32UL, unit_test );
FD_STATIC_ASSERT( FD_GROOVE_DATA_SZC_CGROUP_MAX==64UL, unit_test );

FD_STATIC_ASSERT( FD_GROOVE_DATA_HDR_ALIGN    ==16UL, unit_test );
FD_STATIC_ASSERT( FD_GROOVE_DATA_HDR_FOOTPRINT==16UL, unit_test );

FD_STATIC_ASSERT( FD_GROOVE_DATA_HDR_TYPE_ALLOC     ==0xfd67, unit_test );
FD_STATIC_ASSERT( FD_GROOVE_DATA_HDR_TYPE_SUPERBLOCK==0x0298, unit_test );

FD_STATIC_ASSERT( FD_GROOVE_DATA_ALLOC_ALIGN_DEFAULT==16UL,             unit_test );
FD_STATIC_ASSERT( FD_GROOVE_DATA_ALLOC_ALIGN_MAX    ==512UL,            unit_test );
FD_STATIC_ASSERT( FD_GROOVE_DATA_ALLOC_FOOTPRINT_MAX==(10UL<<20)+512UL, unit_test );

FD_STATIC_ASSERT( alignof(fd_groove_data_hdr_t)==FD_GROOVE_DATA_HDR_ALIGN,     unit_test );
FD_STATIC_ASSERT( sizeof (fd_groove_data_hdr_t)==FD_GROOVE_DATA_HDR_FOOTPRINT, unit_test );

FD_STATIC_ASSERT( FD_GROOVE_DATA_MAGIC==0xfd67007eda7a36c0, unit_test );

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

static ulong volume_avail_pmap = 0UL;

static int
grow_data( fd_groove_data_t * data,
           fd_rng_t *         rng ) {

  fd_groove_volume_t * volume0    = (fd_groove_volume_t *)fd_groove_data_volume0( data );
  int                  volume_cnt = (int)fd_groove_data_volume_max( data ); /* Assumes<=64 */

  /* Pick an available volume uniform IID random in a thread safe way */

  int idx = -1;

  FD_TURNSTILE_BEGIN( 1 /* blocking */ ) {

    if( FD_LIKELY( volume_avail_pmap ) ) {
      int sr = fd_rng_int_roll( rng, volume_cnt ); /* In [0,volume_cnt) */
      int sl = (volume_cnt-sr) & 63;               /* In [0,volume_cnt), sl + sr = (volume_cnt % 64) */
      idx  = fd_ulong_find_lsb( (volume_avail_pmap >> sr) | (volume_avail_pmap << sl) ) + sr;
      idx -= fd_int_if( idx>=volume_cnt, volume_cnt, 0 );
      volume_avail_pmap ^= (1UL<<idx);
    }

  } FD_TURNSTILE_BLOCKED {

    /* never get here */

  } FD_TURNSTILE_END;

  if( FD_UNLIKELY( idx<0 ) ) {
    FD_LOG_ERR(( "no volumes available ... increase --volume-cnt" ));
    return FD_GROOVE_ERR_FULL;
  }

  FD_LOG_NOTICE(( "Adding volume %i to groove", idx ));
  return fd_groove_data_volume_add( data, volume0 + idx, FD_GROOVE_VOLUME_FOOTPRINT, NULL, 0 );
}

#define TEST_SLOT_MAX 8192

static struct __attribute__((aligned(128))) {
  ulong   lock;
  uchar * mem;
  ulong   align;
  ulong   sz;
  ulong   tag;
  ulong   pat;
} test_slot[ TEST_SLOT_MAX ];

int    _go         = 0;
void * _shdata     = NULL;
void * _volume     = NULL;
ulong  _volume_cnt = 0UL;
ulong  _alloc_cnt  = 0UL;
ulong  _sz_max     = 0UL;

static int
tile_main( int     argc,
           char ** argv ) {
  (void)argc; (void)argv;

  ulong tile_idx    = fd_tile_idx();
  ulong cgroup_hint = fd_ulong_hash( tile_idx );

  void * shdata      = FD_VOLATILE_CONST( _shdata     );
  void * volume      = FD_VOLATILE_CONST( _volume     );
  ulong  volume_cnt  = FD_VOLATILE_CONST( _volume_cnt );
  ulong  alloc_cnt   = FD_VOLATILE_CONST( _alloc_cnt  );
  ulong  sz_max      = FD_VOLATILE_CONST( _sz_max     );

  int    lg_align_max = fd_ulong_find_msb( FD_GROOVE_DATA_ALLOC_ALIGN_MAX );

  fd_rng_t _rng[1]; fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, (uint)(tile_idx+1UL), 0UL ) );

  fd_groove_data_t data[1];
  FD_TEST( fd_groove_data_join( data, shdata, volume, volume_cnt, cgroup_hint )==data );

//if( tile_idx<volume_cnt ) grow_data( data, rng );

  if( !tile_idx ) FD_VOLATILE( _go ) = 1;
  else            while( !FD_VOLATILE_CONST( _go ) ) FD_SPIN_PAUSE();

//fd_groove_data_free( data, fd_groove_data_alloc( data, 0UL, sz_max, 0UL, NULL ) );

  for( ulong i=0UL; i<(2UL*alloc_cnt); i++ ) {

    /* Pick a random slot and lock it */

    ulong idx;
    for(;;) {
      idx = (ulong)(fd_rng_uint( rng ) & (uint)(TEST_SLOT_MAX-1));
      ulong volatile * lock = &test_slot[ idx ].lock;
#     if FD_HAS_ATOMIC
      if( FD_LIKELY( !lock[0] ) && FD_LIKELY( !FD_ATOMIC_CAS( lock, 0UL, 1UL ) ) ) break;
      FD_SPIN_PAUSE();
#     else
      lock[0] = 1;
      break;
#     endif
    }

    /* If there is no allocation associated with this slot, allocate
       some memory and fill it with a test pattern.  Otherwise, make
       sure the test pattern is fine and free the memory.  Note that
       this memory could have been allocated by another thread. */

    uchar * mem = test_slot[ idx ].mem;
    if( !mem ) {

      /* Pick the size and alignment randomly */

      int   lg_align = fd_rng_int_roll( rng, lg_align_max+2 );
      int   sz_width = fd_int_min( 12 + (int)fd_rng_coin_tosses( rng ), 64 );
      ulong align    = fd_ulong_if( lg_align==lg_align_max+1, 0UL, 1UL<<lg_align );
      ulong sz       = fd_ulong_min( fd_rng_ulong( rng ) >> (64-sz_width), sz_max );
      ulong tag      = fd_rng_ulong( rng );

      /* Allocate it */

      int err;
      mem = (uchar *)fd_groove_data_alloc( data, align, sz, tag, &err );

      if( err==FD_GROOVE_ERR_FULL ) {
        FD_TEST( !mem );
        grow_data( data, rng );
        i--; /* do iteration over */
        FD_VOLATILE( test_slot[ idx ].lock ) = 0UL;
        continue;
      }

      align = fd_ulong_if( !!align, align, FD_GROOVE_DATA_ALLOC_ALIGN_DEFAULT );

      FD_TEST( mem );
      FD_TEST( fd_ulong_is_aligned( (ulong)mem, align ) );
      FD_TEST( !err );

      FD_TEST( fd_groove_data_alloc_align( mem )==align );
      FD_TEST( fd_groove_data_alloc_sz   ( mem )==sz    );
      FD_TEST( fd_groove_data_alloc_tag  ( mem )==tag   );

      uchar * p    = (uchar *)fd_groove_data_alloc_start( mem );
      uchar * stop = (uchar *)fd_groove_data_alloc_stop ( mem );

      FD_TEST( (ulong)p      <= (ulong)mem    );
      FD_TEST( (ulong)mem    <= (ulong)mem+sz );
      FD_TEST( (ulong)mem+sz <= (ulong)stop   );

      /* Fill it with a bit pattern unique to this allocation */

      ulong pat = fd_ulong_hash( (tile_idx<<32) | (uint)tag );
      for( ; (p+7UL)<stop; p+=8UL ) *((ulong *)p) = pat;
      for( ; p<stop; p++ ) *p = ((uchar)pat);

      /* This allocation is now outstanding */

      test_slot[ idx ].mem   = mem;
      test_slot[ idx ].align = align;
      test_slot[ idx ].sz    = sz;
      test_slot[ idx ].tag   = tag;
      test_slot[ idx ].pat   = pat;

    } else {

      /* Validate the bit pattern was preserved */

      ulong align = test_slot[ idx ].align;
      ulong sz    = test_slot[ idx ].sz;
      ulong tag   = test_slot[ idx ].tag;
      ulong pat   = test_slot[ idx ].pat;

      FD_TEST( fd_groove_data_alloc_align( mem )==align );
      FD_TEST( fd_groove_data_alloc_sz   ( mem )==sz    );
      FD_TEST( fd_groove_data_alloc_tag  ( mem )==tag   );

      uchar const * p    = (uchar const *)fd_groove_data_alloc_start_const( mem );
      uchar const * stop = (uchar const *)fd_groove_data_alloc_stop_const ( mem );

      FD_TEST( (ulong)p      <= (ulong)mem    );
      FD_TEST( (ulong)mem    <= (ulong)mem+sz );
      FD_TEST( (ulong)mem+sz <= (ulong)stop   );

      for( ; (p+7UL)<stop; p+=8UL ) FD_TEST( (*((ulong *)p))==pat );
      for( ; p<stop; p++ ) FD_TEST( (*p)==((uchar)pat)  );

      if( fd_rng_uint( rng ) & 1UL ) {

        /* Free the allocation */

        fd_groove_data_free( data, mem );

        /* Remove from outstanding allocations */

        test_slot[ idx ].mem = NULL;
      }

    }

    /* Release the lock */

    FD_VOLATILE( test_slot[ idx ].lock ) = 0UL;
  }

  FD_TEST( fd_groove_data_leave( data )==data );
  fd_rng_delete( fd_rng_leave( rng ) );
  return 0;
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  fd_rng_t rng[1]; fd_rng_join( fd_rng_new( rng, 0U, 0UL ) );

  char const * name       = fd_env_strip_cmdline_cstr ( &argc, &argv, "--name",       NULL,            NULL );
  ulong        volume_cnt = fd_env_strip_cmdline_ulong( &argc, &argv, "--volume-cnt", NULL,             1UL );
  char const * _page_sz   = fd_env_strip_cmdline_cstr ( &argc, &argv, "--page-sz",    NULL,      "gigantic" );
  ulong        near_cpu   = fd_env_strip_cmdline_ulong( &argc, &argv, "--near-cpu",   NULL, fd_log_cpu_id() );
  ulong        alloc_cnt  = fd_env_strip_cmdline_ulong( &argc, &argv, "--alloc-cnt",  NULL,       1048576UL );
  ulong        sz_max     = fd_env_strip_cmdline_ulong( &argc, &argv, "--sz-max",     NULL,      10UL << 20 );
  ulong        tile_cnt   = fd_tile_cnt();

  FD_LOG_NOTICE(( "Creating test volume pool" ));

  fd_groove_volume_t * volume;
  ulong                page_sz;
  ulong                page_cnt;
  if( name ) {

    FD_LOG_NOTICE(( "Joining to --name %s", name ));

    fd_shmem_join_info_t info[1];
    volume     = (fd_groove_volume_t *)fd_shmem_join( name, FD_SHMEM_JOIN_MODE_READ_WRITE, NULL, NULL, info, 0 ); /* logs details */
    if( FD_UNLIKELY( !volume ) ) FD_LOG_ERR(( "fd_shmem_join failed" ));
    page_sz    = info->page_sz;
    page_cnt   = info->page_cnt;
    volume_cnt = (page_sz*page_cnt) / FD_GROOVE_VOLUME_FOOTPRINT;

  } else {

    FD_LOG_NOTICE(( "--name not specified, using anonymous shmem (--volume-cnt %lu --page-sz %s --near-cpu %lu)",
                    volume_cnt, _page_sz, near_cpu ));

    page_sz  = fd_cstr_to_shmem_page_sz( _page_sz );
    if( FD_UNLIKELY( !page_sz ) ) FD_LOG_ERR(( "invalid page_sz" ));
    page_cnt = (volume_cnt*FD_GROOVE_VOLUME_FOOTPRINT+page_sz-1UL) / page_sz;
    volume   = (fd_groove_volume_t *)fd_shmem_acquire_multi( page_sz, 1UL, &page_cnt, &near_cpu ); /* logs details */
    if( FD_UNLIKELY( !volume ) ) FD_LOG_ERR(( "fd_shmem_join failed" ));

  }

  volume_avail_pmap = fd_ulong_mask_lsb( (int)volume_cnt );

  FD_LOG_NOTICE(( "Testing with %lu groove data volumes", volume_cnt ));

  FD_LOG_NOTICE(( "Testing groove data construction" ));

  ulong align     = fd_groove_data_align();     FD_TEST( fd_ulong_is_pow2( align ) );
  ulong footprint = fd_groove_data_footprint(); FD_TEST( fd_ulong_is_aligned( footprint, align ) );

  FD_TEST( !fd_groove_data_new( NULL        ) ); /* NULL shmem */
  FD_TEST( !fd_groove_data_new( (void *)1UL ) ); /* misaligned shmem */

  void * shdata = shmem_alloc( align, footprint );
  FD_TEST( fd_groove_data_new( shdata )==shdata );

  fd_groove_data_t data[1];

  ulong cgroup_hint = fd_rng_ulong( rng );

  FD_TEST( !fd_groove_data_join( NULL,        shdata,      volume,      volume_cnt, cgroup_hint ) ); /* NULL ljoin */
  FD_TEST( !fd_groove_data_join( (void *)1UL, shdata,      volume,      volume_cnt, cgroup_hint ) ); /* misaligned ljoin */
  FD_TEST( !fd_groove_data_join( data,        NULL,        volume,      volume_cnt, cgroup_hint ) ); /* NULL shdata */
  FD_TEST( !fd_groove_data_join( data,        (void *)1UL, volume,      volume_cnt, cgroup_hint ) ); /* misaligned shdata */
  /* bad magic tested below */
  FD_TEST( !fd_groove_data_join( data,        shdata,      NULL,        volume_cnt, cgroup_hint ) ); /* NULL volume */
  FD_TEST( !fd_groove_data_join( data,        shdata,      (void *)1UL, volume_cnt, cgroup_hint ) ); /* misaligned volume */
  FD_TEST( !fd_groove_data_join( data,        shdata,      volume,      ULONG_MAX,  cgroup_hint ) ); /* too large volume_cnt */
  /* cgroup_hint arbitrary */

  FD_TEST( fd_groove_data_join( data, shdata, volume, volume_cnt, cgroup_hint )==data );

  FD_TEST( !fd_groove_data_verify( data ) );
  for( ulong idx=0UL; idx<volume_cnt; idx++ )
    if( !(volume_avail_pmap & (1UL<<idx)) ) FD_TEST( !fd_groove_data_volume_verify( data, volume + idx ) );

  FD_LOG_NOTICE(( "Testing groove data accessors" ));

  FD_TEST( fd_groove_data_shdata     ( data )==shdata      ); FD_TEST( fd_groove_data_shdata_const ( data )==shdata );
  FD_TEST( fd_groove_data_volume0    ( data )==volume      ); FD_TEST( fd_groove_data_volume0_const( data )==volume );
  FD_TEST( fd_groove_data_volume_max ( data )==volume_cnt  );
  FD_TEST( fd_groove_data_cgroup_hint( data )==cgroup_hint );

  FD_TEST( fd_groove_data_volume1( data )==volume+volume_cnt ); FD_TEST( fd_groove_data_volume1_const( data )==volume+volume_cnt );

  FD_LOG_NOTICE(( "Testing groove data internals" ));

  for( ulong rem=10000000UL; rem; rem-- ) {
    uchar block[ FD_GROOVE_BLOCK_FOOTPRINT ] __attribute__((aligned(FD_GROOVE_BLOCK_ALIGN)));
    ulong r0 = fd_rng_ulong( rng );
    ulong r1 = fd_rng_ulong( rng );
    ulong r2 = fd_rng_ulong( rng );

    ((ulong *)block)[0] = r0;
    ((ulong *)block)[1] = r1;

    uchar * mem = block + fd_ulong_max( 1UL+(r2 & (FD_GROOVE_BLOCK_FOOTPRINT-1UL)), FD_GROOVE_DATA_HDR_FOOTPRINT );

    fd_groove_data_hdr_t * _hdr = fd_groove_data_object_hdr( mem );
    FD_TEST( _hdr==fd_groove_data_object_hdr_const( mem ) );
    FD_TEST( _hdr==(fd_groove_data_hdr_t *)block    );

    fd_groove_data_hdr_t h0 = *_hdr;

    ulong type  = fd_groove_data_hdr_type ( h0 ); FD_TEST( type <   65536UL );
    ulong idx   = fd_groove_data_hdr_idx  ( h0 ); FD_TEST( idx  <      64UL );
    ulong szc   = fd_groove_data_hdr_szc  ( h0 ); FD_TEST( szc  <     128UL );
    ulong align = fd_groove_data_hdr_align( h0 ); FD_TEST( align<    1024UL );
    ulong sz    = fd_groove_data_hdr_sz   ( h0 ); FD_TEST( sz   <33554432UL );
    ulong info  = fd_groove_data_hdr_info ( h0 ); /* arb */

    fd_groove_data_hdr_t h1 = fd_groove_data_hdr( type, idx, szc, align, sz, info );
    FD_TEST( fd_groove_data_hdr_type ( h1 )==type  );
    FD_TEST( fd_groove_data_hdr_idx  ( h1 )==idx   );
    FD_TEST( fd_groove_data_hdr_szc  ( h1 )==szc   );
    FD_TEST( fd_groove_data_hdr_align( h1 )==align );
    FD_TEST( fd_groove_data_hdr_sz   ( h1 )==sz    );
    FD_TEST( fd_groove_data_hdr_info ( h1 )==info  );

    szc %= FD_GROOVE_DATA_SZC_CNT;

    ulong obj_footprint = (ulong)fd_groove_data_szc_cfg[ szc ].obj_footprint;
    ulong obj_cnt       = (ulong)fd_groove_data_szc_cfg[ szc ].obj_cnt;
    ulong cgroup_cnt    = (ulong)fd_groove_data_szc_cfg[ szc ].cgroup_mask + 1UL;
    ulong parent_szc    = (ulong)fd_groove_data_szc_cfg[ szc ].parent_szc;

    FD_TEST( fd_ulong_is_aligned( obj_footprint, FD_GROOVE_BLOCK_ALIGN )                  );
    FD_TEST( (FD_GROOVE_BLOCK_FOOTPRINT<=obj_footprint) & (obj_footprint<=(1UL<<25))      );

    FD_TEST( (2UL<=obj_cnt) & (obj_cnt<=64UL)                                             );
    FD_TEST( (FD_GROOVE_BLOCK_FOOTPRINT+obj_cnt*obj_footprint)<=FD_GROOVE_VOLUME_DATA_MAX );

    FD_TEST( fd_ulong_is_pow2( cgroup_cnt ) & (cgroup_cnt<=FD_GROOVE_DATA_SZC_CGROUP_MAX) );

    FD_TEST( parent_szc<=FD_GROOVE_DATA_SZC_CGROUP_MAX                                    );

    ulong footprint_min = szc==0UL ? 0UL : 1UL+(ulong)fd_groove_data_szc_cfg[ szc-1UL ].obj_footprint;
    ulong footprint_max = obj_footprint;
    FD_TEST( footprint_min<footprint_max );
    ulong footprint = footprint_min + (r2 % (footprint_max-footprint_min+1UL));
    FD_TEST( fd_groove_data_szc( footprint )==szc );

    idx %= fd_groove_data_szc_cfg[ szc ].obj_cnt;

    FD_TEST( _hdr==fd_groove_data_superblock_hdr      ( mem+FD_GROOVE_BLOCK_FOOTPRINT+idx*obj_footprint, szc, idx ) );
    FD_TEST( _hdr==fd_groove_data_superblock_hdr_const( mem+FD_GROOVE_BLOCK_FOOTPRINT+idx*obj_footprint, szc, idx ) );
  }

  FD_LOG_NOTICE(( "Testing groove data volume add / remove" ));

  FD_TEST(  fd_groove_data_volume_add( NULL, volume, volume_cnt*FD_GROOVE_VOLUME_FOOTPRINT, NULL, 0UL )==FD_GROOVE_ERR_INVAL );
  FD_TEST( !fd_groove_data_volume_add( data, volume, volume_cnt*FD_GROOVE_VOLUME_FOOTPRINT, NULL, 0UL ) );

  FD_TEST( !fd_groove_data_volume_remove( NULL ) );
  for( ulong i=0UL; i<volume_cnt; i++ ) FD_TEST( fd_groove_data_volume_remove( data )==(void *)(volume+i) );
  FD_TEST( !fd_groove_data_volume_remove( data ) );

  FD_TEST( !fd_groove_data_verify( data ) );
  for( ulong idx=0UL; idx<volume_cnt; idx++ )
    if( !(volume_avail_pmap & (1UL<<idx)) ) FD_TEST( !fd_groove_data_volume_verify( data, volume + idx ) );

  FD_LOG_NOTICE(( "Testing groove data alloc / free (--alloc-cnt %lu --sz-max %lu)", alloc_cnt, sz_max ));

  /* Test alloc error cases */

  ulong bad_align = FD_GROOVE_DATA_ALLOC_ALIGN_MAX * 2UL;
  ulong bad_sz    = FD_GROOVE_DATA_ALLOC_FOOTPRINT_MAX - FD_GROOVE_DATA_HDR_FOOTPRINT + 1UL;

  FD_TEST( !fd_groove_data_alloc( NULL, 0UL,       0UL,    0UL, NULL ) ); /* NULL data */
  FD_TEST( !fd_groove_data_alloc( data, 3UL,       0UL,    0UL, NULL ) ); /* bad align */
  FD_TEST( !fd_groove_data_alloc( data, bad_align, 0UL,    0UL, NULL ) ); /* bad align */
  FD_TEST( !fd_groove_data_alloc( data, 1UL,       bad_sz, 0UL, NULL ) ); /* bad sz */

  int err;

  err = 1; FD_TEST( !fd_groove_data_alloc( NULL, 0UL,       0UL,    0UL, &err ) && err==FD_GROOVE_ERR_INVAL ); /* NULL data */
  err = 1; FD_TEST( !fd_groove_data_alloc( data, 3UL,       0UL,    0UL, &err ) && err==FD_GROOVE_ERR_INVAL ); /* bad align */
  err = 1; FD_TEST( !fd_groove_data_alloc( data, bad_align, 0UL,    0UL, &err ) && err==FD_GROOVE_ERR_INVAL ); /* bad align */
  err = 1; FD_TEST( !fd_groove_data_alloc( data, 1UL,       bad_sz, 0UL, &err ) && err==FD_GROOVE_ERR_INVAL ); /* bad sz */

  /* Test free error cases */

  FD_TEST( fd_groove_data_free( NULL, data )==FD_GROOVE_ERR_INVAL ); /* NULL data (logged) */
  FD_TEST( fd_groove_data_free( data, NULL )==FD_GROOVE_ERR_INVAL ); /* NULL obj  (silent) */

  FD_TEST( !fd_groove_data_verify( data ) );
  for( ulong idx=0UL; idx<volume_cnt; idx++ )
    if( !(volume_avail_pmap & (1UL<<idx)) ) FD_TEST( !fd_groove_data_volume_verify( data, volume + idx ) );

  /* Start up remote tiles */

  FD_COMPILER_MFENCE();
  _go         = 0;
  _shdata     = shdata;
  _volume     = volume;
  _volume_cnt = volume_cnt;
  _alloc_cnt  = alloc_cnt;
  _sz_max     = sz_max;
  FD_COMPILER_MFENCE();

  fd_tile_exec_t * exec[ FD_TILE_MAX ];

  for( ulong tile_idx=1UL; tile_idx<tile_cnt; tile_idx++ ) exec[tile_idx] = fd_tile_exec_new( tile_idx, tile_main, 0, NULL );

  /* Wait ~0.1 seconds */

  fd_log_sleep( (long)1e8 );

  /* Run locally (will start up the waiting tiles) */

  tile_main( 0, NULL );

  /* Wait for remote tiles to finish */

  for( ulong tile_idx=1UL; tile_idx<tile_cnt; tile_idx++ ) fd_tile_exec_delete( exec[tile_idx], NULL );

  FD_TEST( !fd_groove_data_verify( data ) );
  for( ulong idx=0UL; idx<volume_cnt; idx++ )
    if( !(volume_avail_pmap & (1UL<<idx)) ) FD_TEST( !fd_groove_data_volume_verify( data, volume + idx ) );

  /* Free outstanding allocations */

  for( ulong idx=0UL; idx<TEST_SLOT_MAX; idx++ )
    if( test_slot[ idx ].mem ) FD_TEST( !fd_groove_data_free( data, test_slot[ idx ].mem ) );

  FD_TEST( !fd_groove_data_verify( data ) );
  for( ulong idx=0UL; idx<volume_cnt; idx++ )
    if( !(volume_avail_pmap & (1UL<<idx)) ) FD_TEST( !fd_groove_data_volume_verify( data, volume + idx ) );

  FD_LOG_NOTICE(( "Testing groove data destruction" ));

  FD_TEST( !fd_groove_data_leave( NULL ) );

  FD_TEST(  fd_groove_data_leave( data )==data );

  FD_TEST( !fd_groove_data_delete( NULL        ) ); /* NULL shdata */
  FD_TEST( !fd_groove_data_delete( (void *)1UL ) ); /* misaligned shdata */

  FD_TEST( fd_groove_data_delete( shdata )==shdata );

  FD_TEST( !fd_groove_data_join( data, shdata, volume, volume_cnt, cgroup_hint ) ); /* bad magic */
  FD_TEST( !fd_groove_data_delete( shdata ) ); /* bad magic */

  FD_LOG_NOTICE(( "Cleaning up" ));

  if( name ) fd_shmem_leave  ( volume, NULL, NULL );        /* logs details */
  else       fd_shmem_release( volume, page_sz, page_cnt ); /* logs details */

  fd_rng_delete( fd_rng_leave( rng ) );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
