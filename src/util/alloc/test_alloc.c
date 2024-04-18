#define _POSIX_C_SOURCE 200809L  /* open_memstream */
#include "../fd_util.h"
#include <stdio.h>
#include <stdlib.h>

#if FD_HAS_HOSTED

FD_STATIC_ASSERT( FD_ALLOC_ALIGN               == 4096UL, unit_test );
FD_STATIC_ASSERT( FD_ALLOC_FOOTPRINT           ==20480UL, unit_test );
FD_STATIC_ASSERT( FD_ALLOC_MALLOC_ALIGN_DEFAULT==   16UL, unit_test );
FD_STATIC_ASSERT( FD_ALLOC_JOIN_CGROUP_HINT_MAX==   15UL, unit_test );

/* This is a torture test for same thread allocation */
/* FIXME: IDEALLY SHOULD ADD TORTURE TEST FOR MALLOC / FREE PAIRS SPLIT
   BETWEEN THREADS AND ADD ADD INTERPROCESS TESTING MODES. */

static int    _go;
static void * _shalloc;
static ulong  _alloc_cnt;
static ulong  _align_max;
static ulong  _sz_max;

/* TODO consider moving declaration of fd_alloc_fprintf into an
        fd_tile_private.h */

int
fd_alloc_fprintf( fd_alloc_t * join,
                  FILE *       stream );

static int
test_main( int     argc,
           char ** argv ) {
  (void)argc; (void)argv;

  ulong tile_idx = fd_tile_idx();

  void * shalloc   = FD_VOLATILE_CONST( _shalloc   );
  ulong  alloc_cnt = FD_VOLATILE_CONST( _alloc_cnt );
  ulong  align_max = FD_VOLATILE_CONST( _align_max );
  ulong  sz_max    = FD_VOLATILE_CONST( _sz_max    );

  ulong print_interval          = (1UL<<fd_ulong_find_msb_w_default( alloc_cnt>>2, 1 ));
  ulong FD_FN_UNUSED print_mask = (print_interval<<1)-1UL;

  fd_rng_t _rng[1]; fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, (uint)tile_idx, 0UL ) );

  fd_alloc_t * alloc = fd_alloc_join( shalloc, tile_idx );

  FD_TEST( fd_alloc_join_cgroup_hint( alloc )==(tile_idx & FD_ALLOC_JOIN_CGROUP_HINT_MAX) );
  FD_TEST( fd_alloc_join_cgroup_hint( fd_alloc_join_cgroup_hint_set( alloc, 1UL ) )==1UL  );

# define OUTSTANDING_MAX 128UL
  ulong   sz [ OUTSTANDING_MAX ];
  uchar * mem[ OUTSTANDING_MAX ];
  ulong   pat[ OUTSTANDING_MAX ];

  ulong j = 0UL; /* Number of outstanding allocs */

  int lg_align_max = fd_ulong_find_msb( align_max );

  while( !FD_VOLATILE( _go ) ) FD_SPIN_PAUSE();

  for( ulong i=0UL; i<2UL*alloc_cnt; i++ ) {

    #if !FD_HAS_DEEPASAN
    if( (i & print_mask)==print_interval )  {
      char * info    = NULL;
      ulong  info_sz = 0UL;
      FILE * stream = open_memstream( &info, &info_sz );
      FD_TEST( stream );
      int print_sz = fd_alloc_fprintf( alloc, stream );
      FD_TEST( print_sz>0 );
      FD_TEST( 0==fclose( stream ) );
      FD_LOG_INFO(( "fd_alloc_fprintf printed %lu bytes", info_sz ));
      FD_LOG_DEBUG(( "fd_alloc_fprintf said:\n%*s", (int)(info_sz&INT_MAX), info ));
      free( info );
    }
    #endif

    /* Determine if we should alloc or free this iteration.  If j==0,
       there are no outstanding allocs to free so we must alloc.  If
       j==OUTSTANDING_MAX, we have too many outstanding allocs so we
       must free.  If (i+j)==2*alloc_cnt, we should be winding down the
       outstanding allocs.  Otherwise, we toss a coin. */

    int f;
    if(      j==0UL                                     ) f = 0;
    else if( j==OUTSTANDING_MAX || (i+j)==2UL*alloc_cnt ) f = 1;
    else                                                  f = (int)(fd_rng_uint( rng ) & 1UL);

    if( !f ) { /* Malloc */

      /* Pick the size and alignment randomly */

      int   lg_align = fd_rng_int_roll( rng, lg_align_max+2 );
      ulong align    = fd_ulong_if( lg_align==lg_align_max+1, 0UL, 1UL<<lg_align );

      sz[j] = fd_rng_ulong_roll( rng, sz_max+1UL );
      #if FD_HAS_DEEPASAN
      /* Enforce 8 byte alignment requirements */
      align = fd_ulong_if( align < FD_ASAN_ALIGN, FD_ASAN_ALIGN, align );
      sz[j] = fd_ulong_if( sz[j] < FD_ASAN_ALIGN, FD_ASAN_ALIGN, sz[j] ); 
      #endif

      /* Allocate it */

      ulong max;
      mem[j] = (uchar *)fd_alloc_malloc_at_least( alloc, align, sz[j], &max );

      #if FD_HAS_DEEPASAN
      if ( mem[j] && sz[j] )
        FD_TEST( fd_asan_query( mem[j], sz[j] ) == NULL );
      #endif

      /* Check if the value is sane */

      if( !sz[j] && mem[j] )
        FD_LOG_ERR(( "On tile %lu, alloc(%lu,%lu) failed, got %lx, expected NULL", tile_idx, align, sz[j], (ulong)mem[j] ));

      if( sz[j] && !mem[j] )
        FD_LOG_ERR(( "On tile %lu, alloc(%lu,%lu) failed, got %lx, expected non-NULL", tile_idx, align, sz[j], (ulong)mem[j] ));

      if( !align ) align = FD_ALLOC_MALLOC_ALIGN_DEFAULT;
      if( !fd_ulong_is_aligned( (ulong)mem[j], align ) )
        FD_LOG_ERR(( "On tile %lu, alloc(%lu,%lu) failed, got %lx (misaligned)", tile_idx, align, sz[j], (ulong)mem[j] ));

      FD_TEST( mem[j] ? (max>=sz[j]) : (!max) );

      /* Fill it with a bit pattern unique to this allocation */

      pat[j] = (tile_idx<<32) | i;
      ulong b;
      for( b=0UL; (b+7UL)<sz[j]; b+=8UL ) *((ulong *)(mem[j]+b)) = pat[j];
      for( ; b<sz[j]; b++ ) mem[j][b] = ((uchar)tile_idx);

      /* This allocation is now outstanding */

      j++;

    } else { /* Free */

      /* Determine which outstanding allocation to free (note j>0 here) */

      ulong k = fd_rng_ulong_roll( rng, j );

      /* Validate the bit pattern was preserved between alloc and free */

      ulong b;
      for( b=0UL; (b+7UL)<sz[k]; b+=8UL )
        if( (*(ulong *)(mem[k]+b))!=pat[k] ) FD_LOG_ERR(( "On tile %lu, memory corruption detected", tile_idx ));
      for( ; b<sz[k]; b++ ) if( mem[k][b]!=((uchar)tile_idx) ) FD_LOG_ERR(( "On tile %lu, memory corruption detected", tile_idx ));

      /* Free the allocation */

      fd_alloc_free( alloc, mem[k] );

      #if FD_HAS_DEEPASAN
      if ( mem[k] && sz[k] )
        FD_TEST( fd_asan_query( mem[k], sz[k] ) != NULL );
      #endif

      /* Remove from outstanding allocations */

      j--;
      sz [k] = sz [j];
      mem[k] = mem[j];
      pat[k] = pat[j];

    }
  }

  fd_alloc_leave( alloc );
  fd_rng_delete( fd_rng_leave( rng ) );
  return 0;
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  char const * name      = fd_env_strip_cmdline_cstr ( &argc, &argv, "--wksp",      NULL,            NULL );
  char const * _page_sz  = fd_env_strip_cmdline_cstr ( &argc, &argv, "--page-sz",   NULL,      "gigantic" );
  ulong        page_cnt  = fd_env_strip_cmdline_ulong( &argc, &argv, "--page-cnt",  NULL,             1UL );
  ulong        near_cpu  = fd_env_strip_cmdline_ulong( &argc, &argv, "--near-cpu",  NULL, fd_log_cpu_id() );
  ulong        alloc_cnt = fd_env_strip_cmdline_ulong( &argc, &argv, "--alloc-cnt", NULL,       1048576UL );
  ulong        align_max = fd_env_strip_cmdline_ulong( &argc, &argv, "--align-max", NULL,           256UL );
  ulong        sz_max    = fd_env_strip_cmdline_ulong( &argc, &argv, "--sz-max",    NULL,         73728UL );
  ulong        tag       = fd_env_strip_cmdline_ulong( &argc, &argv, "--tag",       NULL,          1234UL );
  ulong        tile_cnt  = fd_tile_cnt();

  fd_rng_t _rng[1]; fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, (uint)tile_cnt, 0UL ) );

  fd_wksp_t * wksp;
  if( name ) {
    FD_LOG_NOTICE(( "Attaching to --wksp %s", name ));
    wksp = fd_wksp_attach( name );
  } else {
    FD_LOG_NOTICE(( "--wksp not specified, using an anonymous local workspace, --page-sz %s, --page-cnt %lu, --near-cpu %lu",
                    _page_sz, page_cnt, near_cpu ));
    wksp = fd_wksp_new_anonymous( fd_cstr_to_shmem_page_sz( _page_sz ), page_cnt, near_cpu, "wksp", 0UL );
  }

  if( FD_UNLIKELY( !wksp ) ) FD_LOG_ERR(( "Unable to attach to wksp" ));

  ulong  align     = fd_alloc_align();     FD_TEST( align    ==FD_ALLOC_ALIGN     );
  ulong  footprint = fd_alloc_footprint(); FD_TEST( footprint==FD_ALLOC_FOOTPRINT );

  void * shmem = fd_wksp_alloc_laddr( wksp, align, footprint, 1UL ); /* FIXME: allow this tag to be configured too? */
  if( FD_UNLIKELY( !shmem ) ) FD_LOG_ERR(( "Unable to allocate wksp memory for fd_alloc" ));

  static uchar dummy_mem[ FD_ALLOC_FOOTPRINT ] __attribute__((aligned(FD_ALLOC_ALIGN))) = {0};
  FD_TEST( !fd_alloc_new( NULL,        tag ) );  /* NULL shmem */
  FD_TEST( !fd_alloc_new( (void *)1UL, tag ) );  /* misaligned shmem */
  FD_TEST( !fd_alloc_new( dummy_mem,   tag ) );  /* shmem must be in a workspace */
  FD_TEST( !fd_alloc_new( shmem,       0UL ) );  /* bad tag */

  void * shalloc = fd_alloc_new( shmem, tag ); FD_TEST( shalloc==shmem );

  FD_TEST( !fd_alloc_join( NULL,        0UL ) );  /* NULL shalloc */
  FD_TEST( !fd_alloc_join( (void *)1UL, 0UL ) );  /* misaligned shalloc */
  FD_TEST( !fd_alloc_join( dummy_mem,   0UL ) );  /* bad magic */

  fd_alloc_t * alloc = fd_alloc_join( shalloc, 0UL ); FD_TEST( alloc );

  FD_TEST( !fd_alloc_leave( NULL ) );  /* NULL join */
  FD_TEST( fd_alloc_leave( alloc )==shalloc );

  FD_TEST( fd_alloc_wksp( NULL  )==NULL ); FD_TEST( fd_alloc_tag( NULL  )==0UL );
  FD_TEST( fd_alloc_wksp( alloc )==wksp ); FD_TEST( fd_alloc_tag( alloc )==tag );

  FD_LOG_NOTICE(( "Testing is_empty" ));

  do {
    FD_TEST( fd_alloc_is_empty( alloc ) );
    void * mem[64];
    for( ulong idx=0UL; idx<64UL; idx++ ) mem[idx] = fd_alloc_malloc( alloc, 1UL, 1UL );
    for( ulong idx=0UL; idx<64UL; idx++ ) {
      FD_TEST( !fd_alloc_is_empty( alloc ) );
      fd_alloc_free( alloc, mem[idx] );
    }
    FD_TEST( fd_alloc_is_empty( alloc ) );
  } while(0);

  FD_LOG_NOTICE(( "Testing compact" ));

  do {
    void * mem[64];
    for( ulong idx=0UL; idx<64UL; idx++ ) mem[idx] = fd_alloc_malloc( alloc, 1UL, 1UL );
    for( ulong idx=0UL; idx<64UL; idx++ ) {
      fd_alloc_free( alloc, mem[idx] );
      fd_alloc_compact( alloc );
    }
    FD_TEST( fd_alloc_is_empty( alloc ) );
  } while(0);

  FD_LOG_NOTICE(( "Testing max_expand" ));
  do {

    /* BIT_PATTERN uses the lower 13 bits of r (uniform random) to
       generate uniform random length string of 0s or 1s bits starting a
       uniform random offset and going for a uniform random length
       cyclic and filling the rest of the bits with a uniform bit
       pattern.  (Stress stuff near 0 and ULONG_MAX and other tricky
       edge cases preferentially.) */

#   define BIT_PATTERN (fd_ulong_rotate_left( fd_rng_ulong( rng ) >> (int)(r&63UL), (int)((r>>6)&63UL) ) ^ (-((r>>12)&1UL)))
    for( ulong iter=0UL; iter<1000000UL;  iter++ ) {
      ulong r      = fd_rng_ulong( rng );
      ulong max    = BIT_PATTERN; r >>= 13;
      ulong delta  = BIT_PATTERN; r >>= 13;     if( delta  ) delta = 1UL;
      ulong needed = BIT_PATTERN; r >>= 13;
      ulong t0     = max + delta;               if( t0<max ) t0 = ULONG_MAX;
      ulong t1     = max + (max>>2) + (max>>4); if( t1<max ) t1 = ULONG_MAX;
      ulong new_max_exp = fd_ulong_max( fd_ulong_max( t0, t1 ), needed );
      FD_TEST( fd_alloc_max_expand( max, delta, needed )==new_max_exp );
    }
#   undef BIT_PATTERN

  } while(0);

  FD_LOG_NOTICE(( "Running torture test with --alloc-cnt %lu, --align-max %lu, --sz-max %lu on %lu tile(s)",
                  alloc_cnt, align_max, sz_max, tile_cnt ));

  FD_COMPILER_MFENCE();
  FD_VOLATILE( _go        ) = 0;
  FD_VOLATILE( _shalloc   ) = shalloc;
  FD_VOLATILE( _alloc_cnt ) = alloc_cnt;
  FD_VOLATILE( _align_max ) = align_max;
  FD_VOLATILE( _sz_max    ) = sz_max;
  FD_COMPILER_MFENCE();

  fd_tile_exec_t * exec[ FD_TILE_MAX ];
  for( ulong tile_idx=1UL; tile_idx<tile_cnt; tile_idx++ ) exec[tile_idx] = fd_tile_exec_new( tile_idx, test_main, 0, NULL );

  /* Wait ~1/10 second to get ready and then go */

  fd_log_sleep( (long)1e8 );

  FD_COMPILER_MFENCE();
  FD_VOLATILE( _go ) = 1;
  FD_COMPILER_MFENCE();

  test_main( 0, NULL );

  FD_LOG_NOTICE(( "Waiting for remote tiles to finish" ));

  for( ulong tile_idx=1UL; tile_idx<tile_cnt; tile_idx++ ) fd_tile_exec_delete( exec[tile_idx], NULL );

  FD_TEST( !fd_alloc_delete( NULL        ) );  /* NULL shalloc */
  FD_TEST( !fd_alloc_delete( (void *)1UL ) );  /* misaligned shalloc */
  FD_TEST( !fd_alloc_delete( dummy_mem   ) );  /* bad magic */

  FD_TEST( fd_alloc_delete( shalloc )==shmem );

  fd_wksp_free_laddr( shmem );
  if( name ) fd_wksp_detach( wksp );
  else       fd_wksp_delete_anonymous( wksp );

  fd_rng_delete( fd_rng_leave( rng ) );

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
