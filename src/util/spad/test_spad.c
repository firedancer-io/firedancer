#include "../fd_util.h"

/* Use the debug variant for extra code coverage and test strictness */

#if 1
#define fd_spad_alloc_max fd_spad_alloc_max_debug
#define fd_spad_frame_lo  fd_spad_frame_lo_debug
#define fd_spad_frame_hi  fd_spad_frame_hi_debug
#define fd_spad_push      fd_spad_push_debug
#define fd_spad_pop       fd_spad_pop_debug
#define fd_spad_alloc     fd_spad_alloc_debug
#define fd_spad_trim      fd_spad_trim_debug
#define fd_spad_prepare   fd_spad_prepare_debug
#define fd_spad_cancel    fd_spad_cancel_debug
#define fd_spad_publish   fd_spad_publish_debug

#undef  FD_SPAD_FRAME_BEGIN
#undef  FD_SPAD_FRAME_END

#define FD_SPAD_FRAME_BEGIN FD_SPAD_FRAME_BEGIN_DEBUG
#define FD_SPAD_FRAME_END   FD_SPAD_FRAME_END_DEBUG
#endif

FD_STATIC_ASSERT( FD_SPAD_LG_ALIGN      ==7,                       unit_test );
FD_STATIC_ASSERT( FD_SPAD_ALIGN         ==(1UL<<FD_SPAD_LG_ALIGN), unit_test );
FD_STATIC_ASSERT( FD_SPAD_FOOTPRINT(0UL)==1152UL,                  unit_test );

FD_STATIC_ASSERT( FD_SPAD_FRAME_MAX          ==128UL, unit_test );
FD_STATIC_ASSERT( FD_SPAD_ALLOC_ALIGN_DEFAULT== 16UL, unit_test );

#define FOOTPRINT_MAX 1048576UL
static uchar mem[ FOOTPRINT_MAX ] __attribute__((aligned(FD_SPAD_ALIGN)));

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  ulong mem_max = fd_env_strip_cmdline_ulong( &argc, &argv, "--mem-max", NULL, 524288UL );

  FD_LOG_NOTICE(( "Testing with --mem-max %lu", mem_max ));

  fd_rng_t _rng[1]; fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, 0U, 0UL ) );

  /* Test mem_max, align, footprint */

  for( ulong iter=0UL; iter<1000000UL; iter++ ) {
    ulong mem_max = fd_rng_ulong( rng ) >> ((int)(fd_rng_uint( rng ) & 63UL));

    ulong align     = fd_spad_align();
    ulong footprint = fd_spad_footprint( mem_max );

    FD_TEST( align==FD_SPAD_ALIGN );

    if( FD_UNLIKELY( mem_max>(1UL<<63) ) ) FD_TEST( !footprint );
    else {
      FD_TEST( footprint==fd_ulong_align_up( sizeof(fd_spad_t) + mem_max, FD_SPAD_ALIGN ) );
      FD_TEST( footprint==FD_SPAD_FOOTPRINT( mem_max ) );
    }

    footprint = mem_max;
    mem_max   = fd_spad_mem_max_max( footprint );

    ulong footprint_dn = fd_ulong_align_dn( footprint, FD_SPAD_ALIGN );
    if( FD_UNLIKELY( (footprint_dn<sizeof(fd_spad_t)) | ((footprint_dn-sizeof(fd_spad_t))>(1UL<<63)) ) )
      FD_TEST( !mem_max );
    else
      FD_TEST( fd_spad_footprint( mem_max )==footprint_dn );
  }

  /* Test constructors */

  ulong footprint = fd_spad_footprint( mem_max );
  if( FD_UNLIKELY( !footprint              ) ) FD_LOG_ERR(( "too large --mem-max" ));
  if( FD_UNLIKELY( footprint>FOOTPRINT_MAX ) ) FD_LOG_ERR(( "increase FOOTPRINT_MAX to test with this large --mem-max" ));

  FD_TEST( !fd_spad_new( NULL,  mem_max       ) ); /* NULL shmem */
  FD_TEST( !fd_spad_new( mem+1, mem_max       ) ); /* misaligned shmem */
  FD_TEST( !fd_spad_new( mem,   (1UL<<63)+1UL ) ); /* too large mem_max */

  FD_TEST( fd_spad_new( mem, mem_max )==(void *)mem );

  FD_TEST( !fd_spad_join( NULL  ) ); /* NULL shmem */
  FD_TEST( !fd_spad_join( mem+1 ) ); /* misaligned shmem */
  /* bad magic tested below */

  fd_spad_t * spad = fd_spad_join( mem ); FD_TEST( spad );

  /* Test accessors */

  FD_TEST( fd_spad_frame_max ( spad )==FD_SPAD_FRAME_MAX );
  FD_TEST( fd_spad_frame_used( spad )==0UL               );
  FD_TEST( fd_spad_frame_free( spad )==FD_SPAD_FRAME_MAX );

  FD_TEST( fd_spad_mem_max ( spad )==mem_max );
  FD_TEST( fd_spad_mem_used( spad )==0UL     );
  FD_TEST( fd_spad_mem_free( spad )==mem_max );

  uchar * alloc;

  FD_TEST( !fd_spad_in_frame( spad ) );

  fd_spad_push( spad );

  FD_TEST( fd_spad_frame_max ( spad )==FD_SPAD_FRAME_MAX     );
  FD_TEST( fd_spad_frame_used( spad )==1UL                   );
  FD_TEST( fd_spad_frame_free( spad )==FD_SPAD_FRAME_MAX-1UL );

  FD_TEST( fd_spad_in_frame ( spad ) );
  FD_TEST( fd_spad_alloc_max( spad, 1UL )==mem_max );

  FD_TEST( (ulong)mem                     < (ulong)fd_spad_frame_lo( spad ) );
  FD_TEST( (ulong)fd_spad_frame_lo( spad )==(ulong)fd_spad_frame_hi( spad ) );

  /* sz==0 behavior */
  for( ulong align=FD_SPAD_ALIGN; align; align>>=1 ) {
    alloc = (uchar *)fd_spad_alloc( spad, align, 0UL );
    FD_TEST( alloc ); FD_TEST( fd_ulong_is_aligned( (ulong)alloc, align ) );
  }

  alloc = (uchar *)fd_spad_alloc( spad, 0UL, 0UL );
  FD_TEST( alloc ); FD_TEST( fd_ulong_is_aligned( (ulong)alloc, FD_SPAD_ALLOC_ALIGN_DEFAULT ) );

  /* non-multiple size behavior */
  for( ulong align=FD_SPAD_ALIGN; align; align>>=1 ) {
    alloc = (uchar *)fd_spad_alloc( spad, align, 1UL );
    FD_TEST( alloc ); FD_TEST( fd_ulong_is_aligned( (ulong)alloc, align ) );
  }

  alloc = (uchar *)fd_spad_alloc( spad, 0UL, 1UL );
  FD_TEST( alloc ); FD_TEST( fd_ulong_is_aligned( (ulong)alloc, FD_SPAD_ALLOC_ALIGN_DEFAULT ) );

  fd_spad_pop( spad );
  FD_TEST( fd_spad_frame_max ( spad )==FD_SPAD_FRAME_MAX );
  FD_TEST( fd_spad_frame_used( spad )==0UL               );
  FD_TEST( fd_spad_frame_free( spad )==FD_SPAD_FRAME_MAX );

  FD_TEST( fd_spad_frame_max ( spad )==FD_SPAD_FRAME_MAX );
  FD_TEST( fd_spad_frame_used( spad )==0UL               );
  FD_TEST( fd_spad_frame_free( spad )==FD_SPAD_FRAME_MAX );

  ulong m0   [ 1024UL ];
  ulong m1   [ 1024UL ];            ulong alloc_cnt = 0UL;
  ulong frame[ FD_SPAD_FRAME_MAX ]; ulong frame_cnt = 0UL;

  for( ulong iter=0UL; iter<1000000UL; iter++ ) {
    ulong bits = fd_rng_ulong(rng);

    int do_verify = (!(bits & 15UL)); bits >>= 4;
    if( do_verify ) FD_TEST( !fd_spad_verify( spad ) );

    int do_reset = (!(bits & 4095UL)); bits >>= 12;
    if( do_reset ) {
      fd_spad_reset( spad );
      FD_TEST( fd_spad_frame_max ( spad )==FD_SPAD_FRAME_MAX );
      FD_TEST( fd_spad_frame_used( spad )==0UL               );
      FD_TEST( fd_spad_frame_free( spad )==FD_SPAD_FRAME_MAX );
      alloc_cnt = 0UL;
      frame_cnt = 0UL;
      continue;
    }

    int do_push = (!(bits & 63UL)) & (fd_spad_frame_free( spad )>0UL); bits >>= 6;
    if( do_push ) {
      frame[ frame_cnt++ ] = alloc_cnt;
      fd_spad_push( spad );
      FD_TEST( fd_spad_frame_max ( spad )==FD_SPAD_FRAME_MAX           );
      FD_TEST( fd_spad_frame_used( spad )==frame_cnt                   );
      FD_TEST( fd_spad_frame_free( spad )==FD_SPAD_FRAME_MAX-frame_cnt );
      continue;
    }

    int do_pop = (!(bits & 63UL)) & (fd_spad_frame_used( spad )>0UL); bits >>= 6;
    if( do_pop ) {
      alloc_cnt = frame[ --frame_cnt ];
      fd_spad_pop( spad );
      FD_TEST( fd_spad_frame_max ( spad )==FD_SPAD_FRAME_MAX           );
      FD_TEST( fd_spad_frame_used( spad )==frame_cnt                   );
      FD_TEST( fd_spad_frame_free( spad )==FD_SPAD_FRAME_MAX-frame_cnt );
      continue;
    }

    /* Do an alloc randomly via the usual mechanism or via prepare /
       cancel / publish */

    if( !fd_spad_frame_used( spad ) ) continue;

    int lg_align = fd_rng_int_roll( rng, FD_SPAD_LG_ALIGN+2UL ); /* in [0,FD_SPAD_LG_ALIGN+1], FD_SPAD_LG_ALIGN+1 means use 0 */

    ulong align = ((ulong)(lg_align<=FD_SPAD_LG_ALIGN)) << lg_align;
    ulong sz    = (ulong)fd_rng_uint( rng ) & 2047U;
    ulong max   = fd_spad_alloc_max( spad, align );
    if( !( (alloc_cnt<1024UL) & (max>=sz) & (fd_spad_frame_used( spad )>0UL) ) ) continue;

    if( fd_rng_uint( rng ) & 1U ) alloc = (uchar *)fd_spad_alloc( spad, align, sz );
    else {
      ulong pmax = sz + fd_rng_ulong_roll( rng, max-sz+1UL ); /* in [sz,max] */
      alloc = (uchar *)fd_spad_prepare( spad, align, pmax );
      if( fd_rng_uint( rng ) & 1U ) {
        fd_spad_cancel( spad );
        alloc = (uchar *)fd_spad_prepare( spad, align, pmax ); /* note: will not bump mem_used as previous aligned */
      }
      fd_spad_publish( spad, sz );
    }

    ulong a = fd_ulong_if( !!align, align, FD_SPAD_ALLOC_ALIGN_DEFAULT );

    /* Validate the allocation */

    FD_TEST( alloc );
    FD_TEST( fd_ulong_is_aligned( (ulong)alloc, a ) );
    if( FD_LIKELY( sz ) ) {
      alloc[ 0UL    ] = (uchar)1;
      alloc[ sz/2UL ] = (uchar)1;
      alloc[ sz-1UL ] = (uchar)1;
    }

    ulong new_m0 = (ulong)alloc;
    ulong new_m1 = new_m0 + sz;
    FD_TEST( (((ulong)mem)<=new_m0) & (new_m0<=new_m1) & (new_m1<=(ulong)(mem+footprint)) );     /* in backing memory */
    for( ulong idx=0UL; idx<alloc_cnt; idx++ ) FD_TEST( (m1[idx]<=new_m0) | (new_m1<=m0[idx]) ); /* with no overlap */

    /* Trim the allocation */

    sz = fd_rng_ulong_roll( rng, sz+1UL );
    fd_spad_trim( spad, alloc + sz );
    new_m1 = new_m0 + sz;

    /* Validate the trimmed allocation */

    FD_TEST( (((ulong)mem)<=new_m0) & (new_m0<=new_m1) & (new_m1<=(ulong)(mem+footprint)) );     /* in backing memory */
    for( ulong idx=0UL; idx<alloc_cnt; idx++ ) FD_TEST( (m1[idx]<=new_m0) | (new_m1<=m0[idx]) ); /* with no overlap */

    m0[ alloc_cnt ] = new_m0;
    m1[ alloc_cnt ] = new_m1;
    alloc_cnt++;
  }

  /* Test FD_SPAD_FRAME_{BEGIN,END} */

  fd_spad_reset( spad );

  for( ulong i=0UL; i<1024UL; i++ ) {

    FD_TEST( fd_spad_frame_used( spad )==0UL );
    FD_SPAD_FRAME_BEGIN( spad ) {
      FD_TEST( fd_spad_frame_used( spad )==1UL );

      ulong inner_cnt = fd_rng_ulong( rng ) & 1023UL;
      for( ulong j=0UL; j<inner_cnt; j++ ) {
        int volatile dummy[1];

        FD_TEST( fd_spad_frame_used( spad )==1UL );
        FD_SPAD_FRAME_BEGIN( spad ) {
          FD_TEST( fd_spad_frame_used( spad )==2UL );

          if( fd_rng_uint( rng ) & 1U ) break;
          dummy[0]++;

          FD_TEST( fd_spad_frame_used( spad )==2UL );
        } FD_SPAD_FRAME_END;
        FD_TEST( fd_spad_frame_used( spad )==1UL );

      }

      FD_TEST( fd_spad_frame_used( spad )==1UL );
    } FD_SPAD_FRAME_END;
    FD_TEST( fd_spad_frame_used( spad )==0UL );

  }

  /* Test destructors */

  FD_TEST( !fd_spad_leave( NULL ) ); /* NULL spad */

  FD_TEST( fd_spad_leave( spad )==spad );

  FD_TEST( !fd_spad_delete( NULL  ) ); /* NULL shmem */
  FD_TEST( !fd_spad_delete( mem+1 ) ); /* misaligned shmem */
  /* bad magic tested below */
  FD_TEST( fd_spad_delete( mem )==(void *)mem );

  FD_TEST( !fd_spad_join  ( mem ) ); /* bad magic */
  FD_TEST( !fd_spad_delete( mem ) ); /* bad magic */

  fd_rng_delete( fd_rng_leave( rng ) );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
