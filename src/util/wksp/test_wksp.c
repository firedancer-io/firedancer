#include "../fd_util.h"

#define OUTSTANDING_MAX (128UL)

static int go = 0;

static fd_wksp_t * _wksp;
static ulong       _alloc_cnt;
static ulong       _align_max;
static ulong       _sz_max;

/* This is a torture test for same thread allocation */

static int
test_main( int     argc,
           char ** argv ) {
  (void)argc; (void)argv;

  ulong tile_idx = fd_tile_idx();

  fd_wksp_t * wksp      = FD_VOLATILE_CONST( _wksp      );
  ulong       alloc_cnt = FD_VOLATILE_CONST( _alloc_cnt );
  ulong       align_max = FD_VOLATILE_CONST( _align_max );
  ulong       sz_max    = FD_VOLATILE_CONST( _sz_max    );

  fd_rng_t _rng[1]; fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, (uint)tile_idx, 0UL ) );

  ulong   sz [ OUTSTANDING_MAX ];
  ulong   tag[ OUTSTANDING_MAX ];
  uchar * mem[ OUTSTANDING_MAX ];
  ulong   pat[ OUTSTANDING_MAX ];

  ulong j = 0UL; /* Number of outstanding allocs */

  int lg_align_max = fd_ulong_find_msb( align_max );

  fd_wksp_usage_t usage    [1];
  ulong           usage_tag[2];

  FD_TEST( fd_wksp_usage( _wksp, NULL, 0UL, usage )==usage );
  FD_TEST( usage->total_max>=usage->total_cnt );
  FD_TEST( usage->total_cnt>=(usage->free_cnt+usage->used_cnt) ); FD_TEST( usage->total_sz>=(usage->free_sz+usage->used_sz) );
  FD_TEST( !usage->used_cnt );                                    FD_TEST( !usage->used_sz );
  ulong total_max = usage->total_max;
  ulong total_sz  = usage->total_sz;

  FD_TEST( fd_wksp_usage( _wksp, usage_tag, 0UL, usage )==usage );
  FD_TEST( usage->total_max>=usage->total_cnt );
  FD_TEST( usage->total_max==total_max );                         FD_TEST( usage->total_sz==total_sz );
  FD_TEST( usage->total_cnt>=(usage->free_cnt+usage->used_cnt) ); FD_TEST( usage->total_sz>=(usage->free_sz+usage->used_sz) );
  FD_TEST( !usage->used_cnt );                                    FD_TEST( !usage->used_sz );

  usage_tag[0] = 0UL;
  FD_TEST( fd_wksp_usage( _wksp, usage_tag, 1UL, usage )==usage );
  FD_TEST( usage->total_max>=usage->total_cnt );
  FD_TEST( usage->total_max==total_max );      FD_TEST( usage->total_sz==total_sz );
  FD_TEST( usage->free_cnt==usage->used_cnt ); FD_TEST( usage->free_sz==usage->used_sz );

  tag[0] = 1234UL; tag[1] = 2345UL;

  while( !FD_VOLATILE( go ) ) FD_SPIN_PAUSE();

  for( ulong i=0UL; i<2UL*alloc_cnt; i++ ) {

    if( FD_UNLIKELY( !(fd_rng_uint( rng ) & 1023U) ) ) {
      FD_TEST( fd_wksp_usage( _wksp, tag, 2UL, usage )==usage );
      FD_TEST( usage->total_max>=usage->total_cnt );
      FD_TEST( usage->total_max==total_max );                         FD_TEST( usage->total_sz==total_sz );
      FD_TEST( usage->total_cnt>=(usage->free_cnt+usage->used_cnt) ); FD_TEST( usage->total_sz>=(usage->free_sz+usage->used_sz) );
    }

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

      int   itmp  = fd_rng_int_roll( rng, lg_align_max+2 );
      ulong align = fd_ulong_if( itmp==lg_align_max+1, 0UL, 1UL<<itmp );

      sz[j]  = fd_rng_ulong_roll( rng, sz_max+1UL );
      tag[j] = fd_rng_ulong( rng ) | 1UL;
      
      /* Allocate it */

      ulong glo;
      ulong ghi;
      ulong gmem = fd_wksp_alloc_at_least( wksp, align, sz[j], tag[j], &glo, &ghi );

      align = fd_ulong_if( !align, FD_WKSP_ALIGN_DEFAULT, align );

      mem[j] = (uchar *)fd_wksp_laddr( wksp, gmem );
      FD_TEST( fd_ulong_is_aligned( (ulong)mem[j], align ) );

      if( sz[j] ) {
        FD_TEST( gmem   );
        FD_TEST( mem[j] );
        FD_TEST( (glo<=gmem) & ((gmem+sz[j])<=ghi) );
        ulong gaddr = glo + fd_rng_ulong_roll( rng, ghi-glo );
        FD_TEST( fd_wksp_tag( wksp, gaddr )==tag[j] );
      } else {
        FD_TEST( !gmem   );
        FD_TEST( !mem[j] );
        FD_TEST( !glo    );
        FD_TEST( !ghi    );
      }

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
      for( b=0UL; (b+7UL)<sz[k]; b+=8UL ) FD_TEST( (*(ulong *)(mem[k]+b))==pat[k] );
      for( ; b<sz[k]; b++ ) FD_TEST( mem[k][b]==((uchar)tile_idx) );

      /* Check the tag */

      ulong gaddr = fd_wksp_gaddr( wksp, mem[k] + fd_rng_ulong_roll( rng, sz[k] + (!sz[k]) ) );
      FD_TEST( sz[k] ? gaddr : !gaddr );

      FD_TEST( fd_wksp_tag( wksp, gaddr )==(sz[k] ? tag[k] : 0UL) );

      /* Free the allocation */

      fd_wksp_free( wksp, gaddr );

      /* Remove from outstanding allocations */

      j--;
      sz [k] = sz [j];
      tag[k] = tag[j];
      mem[k] = mem[j];
      pat[k] = pat[j];

    }
  }

  fd_rng_delete( fd_rng_leave( rng ) );
  return 0;
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  char const * name       = fd_env_strip_cmdline_cstr ( &argc, &argv, "--wksp",      NULL,            NULL );
  char const * _page_sz   = fd_env_strip_cmdline_cstr ( &argc, &argv, "--page-sz",   NULL,      "gigantic" );
  ulong        page_cnt   = fd_env_strip_cmdline_ulong( &argc, &argv, "--page-cnt",  NULL,             1UL );
  ulong        near_cpu   = fd_env_strip_cmdline_ulong( &argc, &argv, "--near-cpu",  NULL, fd_log_cpu_id() );
  uint         seed       = fd_env_strip_cmdline_uint ( &argc, &argv, "--seed",      NULL,              0U );
  ulong        part_max   = fd_env_strip_cmdline_ulong( &argc, &argv, "--part-max",  NULL,             0UL );
  /**/         _alloc_cnt = fd_env_strip_cmdline_ulong( &argc, &argv, "--alloc-cnt", NULL,       1048576UL );
  /**/         _align_max = fd_env_strip_cmdline_ulong( &argc, &argv, "--align-max", NULL,          4096UL );
  /**/         _sz_max    = fd_env_strip_cmdline_ulong( &argc, &argv, "--sz-max",    NULL,        262144UL );

  if( FD_UNLIKELY( !_alloc_cnt                     ) ) FD_LOG_ERR(( "--alloc-cnt should be positive"     ));
  if( FD_UNLIKELY( !fd_ulong_is_pow2( _align_max ) ) ) FD_LOG_ERR(( "--align-max should be a power of 2" ));
  if( FD_UNLIKELY( !_sz_max                        ) ) FD_LOG_ERR(( "--sz-max should be positive"        ));
  if( FD_UNLIKELY( _sz_max>=ULONG_MAX              ) ) FD_LOG_ERR(( "--sz-max be less than ULONG_MAX"    ));

  ulong tile_cnt = fd_tile_cnt();

  if( name ) {
    FD_LOG_NOTICE(( "Attaching to --wksp %s", name ));
    _wksp = fd_wksp_attach( name );
  } else {
    FD_LOG_NOTICE(( "--wksp not specified, using an anonymous --page-sz %s --page-cnt %lu --near-cpu %lu --seed %u --part-max %lu",
                    _page_sz, page_cnt, near_cpu, seed, part_max ));
    _wksp = fd_wksp_new_anon( "wksp", fd_cstr_to_shmem_page_sz( _page_sz ), 1UL, &page_cnt, &near_cpu, seed, part_max );
  }

  FD_LOG_NOTICE(( "Testing with --alloc-cnt %lu, --align-max %lu, --sz-max %lu on %lu tile(s)",
                  _alloc_cnt, _align_max, _sz_max, tile_cnt ));

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)_wksp, _align_max ) ) )
    FD_LOG_ERR(( "--align-max %lu too large for the page size backing wksp %s", _align_max, name ));

  FD_LOG_NOTICE(( "Booting up remote tiles" ));

  fd_tile_exec_t * exec[ FD_TILE_MAX ];
  for( ulong tile_idx=1UL; tile_idx<tile_cnt; tile_idx++ ) exec[tile_idx] = fd_tile_exec_new( tile_idx, test_main, 0, NULL );

  FD_LOG_NOTICE(( "Waiting 1/10 second and then starting tests" ));

  fd_log_sleep( (long)1e8 );

  FD_COMPILER_MFENCE();
  FD_VOLATILE( go ) = 1;
  FD_COMPILER_MFENCE();

  test_main( 0, NULL );

  FD_LOG_NOTICE(( "Waiting for remote tiles to finish" ));

  for( ulong tile_idx=1UL; tile_idx<tile_cnt; tile_idx++ ) fd_tile_exec_delete( exec[tile_idx], NULL );

  if( name ) fd_wksp_detach     ( _wksp );
  else       fd_wksp_delete_anon( _wksp );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}

#undef OUTSTANDING_MAX

