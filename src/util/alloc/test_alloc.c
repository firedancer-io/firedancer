#include "../fd_util.h"

#if FD_HAS_HOSTED

/* FIXME: consider moving declaration of fd_alloc_fprintf into an
   fd_alloc_private.h?  (Or using a void * to get rid of stdio.h).  */

#include <stdio.h>

int
fd_alloc_fprintf( fd_alloc_t * join,
                  FILE *       stream );

/* FIXME: ADD INTERPROCESS TESTING MODES TOO. */

FD_STATIC_ASSERT( FD_ALLOC_ALIGN               ==  128UL, unit_test );
FD_STATIC_ASSERT( FD_ALLOC_FOOTPRINT           ==32768UL, unit-test );
FD_STATIC_ASSERT( FD_ALLOC_MALLOC_ALIGN_DEFAULT==   16UL, unit_test );
FD_STATIC_ASSERT( FD_ALLOC_JOIN_CGROUP_HINT_MAX==   15UL, unit_test );

static int    _go;
static void * _shalloc;
static ulong  _alloc_cnt;
static ulong  _align_max;
static ulong  _sz_max;

/* This is a torture test for concurrent allocation where free is done
   on the same that did the alloc. */

static int
test_main( int     argc,
           char ** argv ) {
  (void)argc; (void)argv;

  ulong tile_idx = fd_tile_idx();
  ulong tile_cnt = fd_tile_cnt(); (void)tile_cnt;

  void * shalloc   = FD_VOLATILE_CONST( _shalloc   );
  ulong  alloc_cnt = FD_VOLATILE_CONST( _alloc_cnt );
  ulong  align_max = FD_VOLATILE_CONST( _align_max );
  ulong  sz_max    = FD_VOLATILE_CONST( _sz_max    );

  fd_rng_t _rng[1]; fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, (uint)tile_idx, 0UL ) );

  fd_alloc_t * alloc = fd_alloc_join( shalloc, tile_idx );
  FD_TEST( fd_alloc_join_cgroup_hint( alloc )==(tile_idx & FD_ALLOC_JOIN_CGROUP_HINT_MAX) );

# define OUTSTANDING_MAX 128UL

  ulong   sz [ OUTSTANDING_MAX ];
  uchar * mem[ OUTSTANDING_MAX ];
  ulong   pat[ OUTSTANDING_MAX ];

  ulong j = 0UL; /* Number of outstanding allocs */

  int lg_align_max = fd_ulong_find_msb( align_max );

  while( !FD_VOLATILE( _go ) ) FD_SPIN_PAUSE();

  ulong diag_rem = 0UL;
  for( ulong i=0UL; i<(2UL*alloc_cnt); i++ ) {
    if( FD_UNLIKELY( !diag_rem ) ) {
      if( FD_UNLIKELY( !tile_idx ) ) {
        FD_LOG_NOTICE(( "Iter %lu of %lu", i, 2UL*alloc_cnt ));
        FD_TEST( fd_alloc_fprintf( alloc, stdout )>0 );
      }
      diag_rem = 500000UL;
    }
    diag_rem--;

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

      /* Allocate it */

      ulong max;
      mem[j] = (uchar *)fd_alloc_malloc_at_least( alloc, align, sz[j], &max );

#     if FD_HAS_DEEPASAN
      if( mem[j] && max ) FD_TEST( !fd_asan_query( mem[j], max ) );
#     endif

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

#     if FD_HAS_DEEPASAN
      if( mem[k] && sz[k] ) FD_TEST( !fd_asan_query( mem[k], sz[k] ) );
#     endif

      fd_alloc_free( alloc, mem[k] );

#     if FD_HAS_DEEPASAN
      /* It is possible another thread might reuse mem between the above
         free and the below query.  So we only do this test if we are
         running non-concurrent. */
      if( tile_cnt==1UL && mem[k] && sz[k] ) FD_TEST( fd_asan_query( mem[k], sz[k] ) );
#     endif

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

/* This is a torture test for concurrent allocation where free can
   be done on a different thread that did the alloc. */

#define TEST2_SLOT_MAX 4096

static struct __attribute__((aligned(128))) {
  ulong   lock;
  uchar * mem;
  ulong   sz;
  ulong   pat;
  ulong   src;
} test2_slot[ TEST2_SLOT_MAX ];

static int
test2_main( int     argc,
            char ** argv ) {
  (void)argc; (void)argv;

  ulong tile_idx = fd_tile_idx();
  ulong tile_cnt = fd_tile_cnt(); (void)tile_cnt;

  void * shalloc   = FD_VOLATILE_CONST( _shalloc   );
  ulong  alloc_cnt = FD_VOLATILE_CONST( _alloc_cnt );
  ulong  align_max = FD_VOLATILE_CONST( _align_max );
  ulong  sz_max    = FD_VOLATILE_CONST( _sz_max    );

  fd_rng_t _rng[1]; fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, (uint)tile_idx, 0UL ) );

  fd_alloc_t * alloc = fd_alloc_join( shalloc, tile_idx );
  FD_TEST( fd_alloc_join_cgroup_hint( alloc )==(tile_idx & FD_ALLOC_JOIN_CGROUP_HINT_MAX) );

  int lg_align_max = fd_ulong_find_msb( align_max );

  while( !FD_VOLATILE( _go ) ) FD_SPIN_PAUSE();

  ulong diag_rem = 0UL;
  for( ulong i=0UL; i<(2UL*alloc_cnt); i++ ) {
    if( FD_UNLIKELY( !diag_rem ) ) {
      if( FD_UNLIKELY( !tile_idx ) ) {
        FD_LOG_NOTICE(( "Iter %lu of %lu", i, 2UL*alloc_cnt ));
        FD_TEST( fd_alloc_fprintf( alloc, stdout )>0 );
      }
      diag_rem = 500000UL;
    }
    diag_rem--;

    /* Pick a random slot and lock it */

    ulong idx;
    for(;;) {
      idx = (ulong)(fd_rng_uint( rng ) & (uint)(TEST2_SLOT_MAX-1));
      ulong volatile * lock = &test2_slot[ idx ].lock;
      if( FD_LIKELY( !lock[0] ) && FD_LIKELY( !FD_ATOMIC_CAS( lock, 0UL, 1UL ) ) ) break;
      FD_SPIN_PAUSE();
    }

    /* If there is no allocation associated with this slot, allocate
       some memory and fill it with a test pattern.  Otherwise, make
       sure the test pattern is fine and free the memory.  Note that
       this memory could have been allocated by another thread. */

    uchar * mem = test2_slot[ idx ].mem;
    if( !mem ) {

      /* Pick the size and alignment randomly */

      int   lg_align = fd_rng_int_roll( rng, lg_align_max+2 );
      ulong align    = fd_ulong_if( lg_align==lg_align_max+1, 0UL, 1UL<<lg_align );
      ulong sz       = fd_rng_ulong_roll( rng, sz_max+1UL );

      /* Allocate it */

      ulong max;
      mem = (uchar *)fd_alloc_malloc_at_least( alloc, align, sz, &max );

#     if FD_HAS_DEEPASAN
      if( mem && max ) FD_TEST( !fd_asan_query( mem, max ) );
#     endif

      /* Check if the value is sane */

      if( !sz && mem )
        FD_LOG_ERR(( "On tile %lu, alloc(%lu,%lu) failed, got %lx, expected NULL", tile_idx, align, sz, (ulong)mem ));

      if( sz && !mem )
        FD_LOG_ERR(( "On tile %lu, alloc(%lu,%lu) failed, got %lx, expected non-NULL", tile_idx, align, sz, (ulong)mem ));

      if( !align ) align = FD_ALLOC_MALLOC_ALIGN_DEFAULT;
      if( !fd_ulong_is_aligned( (ulong)mem, align ) )
        FD_LOG_ERR(( "On tile %lu, alloc(%lu,%lu) failed, got %lx (misaligned)", tile_idx, align, sz, (ulong)mem ));

      FD_TEST( mem ? (max>=sz) : (!max) );

      /* Fill it with a bit pattern unique to this allocation */

      ulong pat = (tile_idx<<32) | i;
      ulong b;
      for( b=0UL; (b+7UL)<sz; b+=8UL ) *((ulong *)(mem+b)) = pat;
      for( ; b<sz; b++ ) mem[b] = ((uchar)tile_idx);

      /* This allocation is now outstanding */

      test2_slot[ idx ].mem = mem;
      test2_slot[ idx ].sz  = sz;
      test2_slot[ idx ].pat = pat;
      test2_slot[ idx ].src = tile_idx;

    } else {

      /* Validate the bit pattern was preserved between alloc and free */

      ulong sz  = test2_slot[ idx ].sz;
      ulong pat = test2_slot[ idx ].pat;
      ulong src = test2_slot[ idx ].src;

      ulong b;
      for( b=0UL; (b+7UL)<sz; b+=8UL )
        if( (*(ulong *)(mem+b))!=pat ) { FD_LOG_ERR(( "On tile %lu, memory corruption detected", tile_idx )); break; }
      for( ; b<sz; b++ ) if( mem[b]!=((uchar)src) ) { FD_LOG_ERR(( "On tile %lu, memory corruption detected", tile_idx )); break; }

      /* Free the allocation */

#     if FD_HAS_DEEPASAN
      if( mem && sz ) FD_TEST( !fd_asan_query( mem, sz ) );
#     endif

      fd_alloc_free( alloc, mem );

#     if FD_HAS_DEEPASAN
      /* It is possible another thread might reuse mem between the above
         free and the below query.  So we only do this test if we are
         running non-concurrent. */
      if( tile_cnt==1UL && mem && sz ) FD_TEST( fd_asan_query( mem, sz ) );
#     endif

      /* Remove from outstanding allocations */

      test2_slot[ idx ].mem = NULL;
    }

    /* Release the lock */

    FD_VOLATILE( test2_slot[ idx ].lock ) = 0UL;
  }

  fd_alloc_leave( alloc );
  fd_rng_delete( fd_rng_leave( rng ) );
  return 0;
}

#include "fd_alloc_cfg.h"

FD_STATIC_ASSERT( (0UL<FD_ALLOC_SIZECLASS_CNT) && (FD_ALLOC_SIZECLASS_CNT<=FD_ALLOC_SIZECLASS_MAX), increase_sizeclass_max );

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  ulong sz_max_default = 37UL << 10;

  char const * name      = fd_env_strip_cmdline_cstr ( &argc, &argv, "--wksp",      NULL,            NULL );
  char const * _page_sz  = fd_env_strip_cmdline_cstr ( &argc, &argv, "--page-sz",   NULL,      "gigantic" );
  ulong        page_cnt  = fd_env_strip_cmdline_ulong( &argc, &argv, "--page-cnt",  NULL,             1UL );
  ulong        near_cpu  = fd_env_strip_cmdline_ulong( &argc, &argv, "--near-cpu",  NULL, fd_log_cpu_id() );
  ulong        alloc_cnt = fd_env_strip_cmdline_ulong( &argc, &argv, "--alloc-cnt", NULL,       1048576UL );
  ulong        align_max = fd_env_strip_cmdline_ulong( &argc, &argv, "--align-max", NULL,           256UL );
  ulong        sz_max    = fd_env_strip_cmdline_ulong( &argc, &argv, "--sz-max",    NULL,  sz_max_default );
  ulong        tag       = fd_env_strip_cmdline_ulong( &argc, &argv, "--tag",       NULL,          1234UL );
  ulong        tile_cnt  = fd_tile_cnt();
  int          paired    = fd_env_strip_cmdline_int  ( &argc, &argv, "--paired",    NULL,               1 );

  fd_rng_t _rng[1]; fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, (uint)tile_cnt, 0UL ) );

  FD_LOG_NOTICE(( "Testing sizeclass configuration" ));

  FD_TEST( fd_ulong_is_pow2( FD_ALLOC_SUPERBLOCK_ALIGN ) );
  FD_TEST( FD_ALLOC_SIZECLASS_ITER_MAX==(ulong)(1UL+(ulong)fd_ulong_find_msb_w_default( FD_ALLOC_SIZECLASS_CNT-1UL, -1 )) );
  FD_TEST( FD_ALLOC_FOOTPRINT_SMALL_THRESH<=(ulong)fd_alloc_sizeclass_cfg[ FD_ALLOC_SIZECLASS_CNT-1UL ].block_footprint );

  ulong block_footprint = 0UL;
  for( ulong sizeclass=0UL; sizeclass<FD_ALLOC_SIZECLASS_CNT; sizeclass++ ) {
    ulong block_footprint_prev = block_footprint;

    /**/  block_footprint  = (ulong)fd_alloc_sizeclass_cfg[ sizeclass ].block_footprint;
    ulong parent_sizeclass = (ulong)fd_alloc_sizeclass_cfg[ sizeclass ].parent_sizeclass;
    ulong block_cnt        = (ulong)fd_alloc_sizeclass_cfg[ sizeclass ].block_cnt;
    ulong cgroup_mask      = (ulong)fd_alloc_sizeclass_cfg[ sizeclass ].cgroup_mask;

    FD_TEST( block_footprint > block_footprint_prev                                             ); /* Sorted by block_footprint */
    FD_TEST( fd_ulong_is_aligned( block_footprint, FD_ALLOC_SUPERBLOCK_ALIGN )                  ); /* Valid block_footprint */
    FD_TEST( (2UL<=block_cnt) & (block_cnt<=64UL)                                               ); /* Valid block_cnt */
    FD_TEST( (cgroup_mask<=FD_ALLOC_JOIN_CGROUP_HINT_MAX) & fd_ulong_is_pow2( cgroup_mask+1UL ) ); /* Valid cgroup_mask */

    /* parent_sizeclass blocks can only a superblock for this sizeclass */
    ulong superblock_footprint = 24UL + block_footprint*block_cnt;
    if( FD_LIKELY( (sizeclass<parent_sizeclass) & (parent_sizeclass<FD_ALLOC_SIZECLASS_CNT) ) ) { /* nested superblock */
      FD_TEST( superblock_footprint<=(ulong)fd_alloc_sizeclass_cfg[ parent_sizeclass ].block_footprint );
    } else { /* root superblock */
      FD_TEST( parent_sizeclass==FD_ALLOC_SIZECLASS_CNT );
      FD_TEST( superblock_footprint<=FD_ALLOC_ROOT_SUPERBLOCK_FOOTPRINT );
    }
  }

  FD_LOG_NOTICE(( "Testing constructors" ));

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

  FD_LOG_NOTICE(( "Testing join" ));

  FD_TEST( !fd_alloc_join( NULL,        0UL ) );  /* NULL shalloc */
  FD_TEST( !fd_alloc_join( (void *)1UL, 0UL ) );  /* misaligned shalloc */
  FD_TEST( !fd_alloc_join( dummy_mem,   0UL ) );  /* bad magic */

  fd_alloc_t * alloc = fd_alloc_join( shalloc, 0UL ); FD_TEST( alloc );

  FD_LOG_NOTICE(( "Testing accessors" ));

  FD_TEST( fd_alloc_wksp( NULL  )==NULL ); FD_TEST( fd_alloc_tag( NULL  )==0UL );
  FD_TEST( fd_alloc_wksp( alloc )==wksp ); FD_TEST( fd_alloc_tag( alloc )==tag );

  FD_TEST( fd_alloc_join_cgroup_hint( alloc )==0UL );
  for( ulong idx=0UL; idx<64UL; idx++ ) {
    ulong cgroup_hint = fd_ulong_hash( idx );
    fd_alloc_t * alloc2 = fd_alloc_join_cgroup_hint_set( alloc, cgroup_hint );
    FD_TEST( fd_alloc_join_cgroup_hint( alloc2 )==(cgroup_hint & FD_ALLOC_JOIN_CGROUP_HINT_MAX) );
  }

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

  FD_TEST( !fd_alloc_leave( NULL ) );  /* NULL join */
  FD_TEST( fd_alloc_leave( alloc )==shalloc );

  FD_LOG_NOTICE(( "Running torture test with --alloc-cnt %lu, --align-max %lu, --sz-max %lu, --paired %i on %lu tile(s)",
                  alloc_cnt, align_max, sz_max, paired, tile_cnt ));

  FD_COMPILER_MFENCE();
  FD_VOLATILE( _go        ) = 0;
  FD_VOLATILE( _shalloc   ) = shalloc;
  FD_VOLATILE( _alloc_cnt ) = alloc_cnt;
  FD_VOLATILE( _align_max ) = align_max;
  FD_VOLATILE( _sz_max    ) = sz_max;
  FD_COMPILER_MFENCE();

  fd_tile_exec_t * exec[ FD_TILE_MAX ];

  if( paired )
    for( ulong tile_idx=1UL; tile_idx<tile_cnt; tile_idx++ ) exec[tile_idx] = fd_tile_exec_new( tile_idx, test_main,  0, NULL );
  else
    for( ulong tile_idx=1UL; tile_idx<tile_cnt; tile_idx++ ) exec[tile_idx] = fd_tile_exec_new( tile_idx, test2_main, 0, NULL );

  /* Wait ~1/10 second to get ready and then go */

  fd_log_sleep( (long)1e8 );

  FD_COMPILER_MFENCE();
  FD_VOLATILE( _go ) = 1;
  FD_COMPILER_MFENCE();

  if( paired ) test_main ( 0, NULL );
  else         test2_main( 0, NULL );

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
