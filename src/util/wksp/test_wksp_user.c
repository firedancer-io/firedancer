#include "../fd_util.h"
#include "fd_wksp_private.h"

FD_STATIC_ASSERT( FD_WKSP_ALIGN_DEFAULT==4096UL, unit_test );

#define SCRATCH_MAX (16384UL)
uchar scratch[ SCRATCH_MAX ] __attribute__((aligned((FD_WKSP_ALIGN))));

#if 0
#include <stdio.h>

void
dump_used_tree( ulong                           i,
                fd_wksp_private_pinfo_t const * pinfo,
                ulong                           indent ) {
  if( i==FD_WKSP_PRIVATE_PINFO_IDX_NULL ) {
    for( ulong rem=indent; rem; rem-- ) fputc( ' ', stdout );
    printf( "  -\n" );
    return;
  }

  dump_used_tree( fd_wksp_private_pinfo_idx( pinfo[i].left_cidx ), pinfo, indent+4UL );

  for( ulong rem=indent; rem; rem-- ) fputc( ' ', stdout );
  printf( "[%5lu,%5lu)", pinfo[i].gaddr_lo, pinfo[i].gaddr_hi );
  ulong j = i;
  do {
    printf( " %3lu ", j );
    j = fd_wksp_private_pinfo_idx( pinfo[j].same_cidx );
  } while( j!=FD_WKSP_PRIVATE_PINFO_IDX_NULL );
  printf( "\n" );

  dump_used_tree( fd_wksp_private_pinfo_idx( pinfo[i].right_cidx ), pinfo, indent+4UL );
}

void
dump_free_tree( ulong                           i,
                fd_wksp_private_pinfo_t const * pinfo,
                ulong                           indent ) {
  if( i==FD_WKSP_PRIVATE_PINFO_IDX_NULL ) {
    for( ulong rem=indent; rem; rem-- ) fputc( ' ', stdout );
    printf( "  -\n" );
    return;
  }

  dump_free_tree( fd_wksp_private_pinfo_idx( pinfo[i].left_cidx ), pinfo, indent+4UL );

  for( ulong rem=indent; rem; rem-- ) fputc( ' ', stdout );
  printf( "%5lu: ", pinfo[i].gaddr_hi - pinfo[i].gaddr_lo );
  ulong j = i;
  do {
    printf( " %3lu ", j );
    j = fd_wksp_private_pinfo_idx( pinfo[j].same_cidx );
  } while( j!=FD_WKSP_PRIVATE_PINFO_IDX_NULL );
  printf( "\n" );

  dump_free_tree( fd_wksp_private_pinfo_idx( pinfo[i].right_cidx ), pinfo, indent+4UL );
}
#endif

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  fd_rng_t _rng[1]; fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, 0U, 0UL ) );

  ulong        scratch_sz = fd_env_strip_cmdline_ulong( &argc, &argv, "--scratch-sz", "", SCRATCH_MAX );
  char const * name       = fd_env_strip_cmdline_cstr ( &argc, &argv, "--name",       "", "test"      );
  uint         seed       = fd_env_strip_cmdline_uint ( &argc, &argv, "--seed",       "", 1234U       );
  ulong        part_max   = fd_env_strip_cmdline_ulong( &argc, &argv, "--part-max",   "", 0UL         );
  ulong        data_max   = fd_env_strip_cmdline_ulong( &argc, &argv, "--data-max",   "", 0UL         );

  if( FD_UNLIKELY( scratch_sz>SCRATCH_MAX ) ) FD_LOG_ERR(( "Increase SCRATCH_MAX for this --scratch-sz" ));

  if( !part_max ) {
    FD_LOG_NOTICE(( "Configuring --part-max" ));
    part_max = fd_wksp_part_max_est( scratch_sz, 64UL );
    if( FD_UNLIKELY( !part_max ) ) FD_LOG_ERR(( "--scratch-sz too small for test" ));
  }

  if( !data_max ) {
    FD_LOG_NOTICE(( "Configuring --data-max" ));
    data_max = fd_wksp_data_max_est( scratch_sz, part_max );
    if( FD_UNLIKELY( !data_max ) ) FD_LOG_ERR(( "--part-max too large for --scratch-sz" ));
  }

  FD_LOG_NOTICE(( "Testing with --scratch-sz %lu --name %s --seed %u --part-max %lu --data-max %lu",
                  scratch_sz, name, seed, part_max, data_max ));

  ulong footprint = fd_wksp_footprint( part_max, data_max );
  if( FD_UNLIKELY( !footprint           ) ) FD_LOG_ERR(( "Bad --part-max and/or --data-max" ));
  if( FD_UNLIKELY( footprint>scratch_sz ) ) FD_LOG_ERR(( "Increase --scratch-sz for this --part-max and --data-max" ));

  fd_wksp_t * wksp = fd_wksp_join( fd_wksp_new( scratch, name, seed, part_max, data_max ) );
  if( FD_UNLIKELY( !wksp ) ) FD_LOG_ERR(( "Unable to create wksp" ));

  ulong gaddr_lo = wksp->gaddr_lo; uchar * laddr_lo = (uchar *)(((ulong)wksp) + gaddr_lo);
  ulong gaddr_hi = wksp->gaddr_hi; uchar * laddr_hi = (uchar *)(((ulong)wksp) + gaddr_hi);

  /* Test fd_wksp_laddr */

  FD_TEST( !fd_wksp_laddr( NULL, 0UL          ) ); FD_TEST( !fd_wksp_laddr( wksp, 0UL          )                   );
  FD_TEST( !fd_wksp_laddr( NULL, gaddr_lo-1UL ) ); FD_TEST( !fd_wksp_laddr( wksp, gaddr_lo-1UL )                   );
  FD_TEST( !fd_wksp_laddr( NULL, gaddr_lo     ) ); FD_TEST(  fd_wksp_laddr( wksp, gaddr_lo     )==(void *)laddr_lo );
  FD_TEST( !fd_wksp_laddr( NULL, gaddr_hi     ) ); FD_TEST(  fd_wksp_laddr( wksp, gaddr_hi     )==(void *)laddr_hi );
  FD_TEST( !fd_wksp_laddr( NULL, gaddr_hi+1UL ) ); FD_TEST( !fd_wksp_laddr( wksp, gaddr_hi+1UL )                   );

  /* Test fd_wksp_gaddr */

  FD_TEST( !fd_wksp_gaddr( NULL, NULL         ) ); FD_TEST( !fd_wksp_gaddr( wksp, NULL         )                   );
  FD_TEST( !fd_wksp_gaddr( NULL, laddr_lo-1UL ) ); FD_TEST( !fd_wksp_gaddr( wksp, laddr_lo-1UL )                   );
  FD_TEST( !fd_wksp_gaddr( NULL, laddr_lo     ) ); FD_TEST(  fd_wksp_gaddr( wksp, laddr_lo     )==gaddr_lo         );
  FD_TEST( !fd_wksp_gaddr( NULL, laddr_hi     ) ); FD_TEST(  fd_wksp_gaddr( wksp, laddr_hi     )==gaddr_hi         );
  FD_TEST( !fd_wksp_gaddr( NULL, laddr_hi+1UL ) ); FD_TEST( !fd_wksp_gaddr( wksp, laddr_hi+1UL )                   );

  /* Test fd_wksp_laddr_fast */

  FD_TEST( fd_wksp_laddr_fast( wksp, gaddr_lo )==(void *)laddr_lo );
  FD_TEST( fd_wksp_laddr_fast( wksp, gaddr_hi )==(void *)laddr_hi );

  /* Test fd_wksp_gaddr_fast */

  FD_TEST( fd_wksp_gaddr_fast( wksp, laddr_lo )==gaddr_lo );
  FD_TEST( fd_wksp_gaddr_fast( wksp, laddr_hi )==gaddr_hi );

  {
    /* Test fd_wksp_alloc edge cases */

    FD_TEST( !fd_wksp_alloc( NULL, 1UL, 1UL,       1UL ) ); /* NULL wksp */
    FD_TEST( !fd_wksp_alloc( wksp, 3UL, 1UL,       1UL ) ); /* non-pow2 align */
    FD_TEST( !fd_wksp_alloc( wksp, 1UL, 0UL,       1UL ) ); /* zero sz */
    FD_TEST( !fd_wksp_alloc( wksp, 2UL, ULONG_MAX, 1UL ) ); /* overflow footprint */
    FD_TEST( !fd_wksp_alloc( wksp, 1UL, 1UL,       0UL ) ); /* zero tag */

    ulong g = fd_wksp_alloc( wksp, 0UL, 1UL, 1UL ); /* default align */
    FD_TEST( g );
    FD_TEST( fd_ulong_is_aligned( g, FD_WKSP_ALIGN_DEFAULT ) );
    FD_TEST( fd_wksp_tag( wksp, g )==1UL );

    /* Test fd_wksp_tag edge cases */

    FD_TEST( !fd_wksp_tag( NULL, g   ) ); /* NULL wksp  */
    FD_TEST( !fd_wksp_tag( wksp, 0UL ) ); /* zero gaddr */

    /* Test fd_wksp_memset edge cases */

    fd_wksp_memset( NULL, g,   255 ); /* NULL wksp */
    fd_wksp_memset( wksp, 0UL, 255 ); /* NULL gaddr */

    /* Test fd_wksp_free edge cases */

    fd_wksp_free( NULL, g   ); /* NULL wksp */
    fd_wksp_free( wksp, 0UL ); /* zero gaddr */

    /* Test fd_wksp_tag_query edge cases */

    ulong                    tag_tmp;
    fd_wksp_tag_query_info_t info[2];

    tag_tmp = 1UL;
    FD_TEST( fd_wksp_tag_query( NULL, &tag_tmp, 1UL, info, 2UL )==0UL ); /* NULL wksp */
    FD_TEST( fd_wksp_tag_query( wksp, NULL,     1UL, info, 2UL )==0UL ); /* NULL tags */
    FD_TEST( fd_wksp_tag_query( wksp, NULL,     0UL, info, 2UL )==0UL ); /* no tags (NULL tag array) */
    FD_TEST( fd_wksp_tag_query( wksp, &tag_tmp, 0UL, info, 2UL )==0UL ); /* no tags */
    FD_TEST( fd_wksp_tag_query( wksp, &tag_tmp, 1UL, NULL, 2UL )==0UL ); /* NULL info */
    FD_TEST( fd_wksp_tag_query( wksp, &tag_tmp, 1UL, NULL, 0UL )==1UL ); /* count only (NULL info array) */
    FD_TEST( fd_wksp_tag_query( wksp, &tag_tmp, 1UL, info, 0UL )==1UL ); /* count only */

    FD_TEST( fd_wksp_tag_query( wksp, &tag_tmp, 1UL, info, 2UL )==1UL );
    FD_TEST( info[0].gaddr_lo<=g && (g+1UL)<=info[0].gaddr_hi && info[0].tag==1UL );

    /* Test fd_wksp_tag_free edge cases */

    tag_tmp = 2UL;
    fd_wksp_tag_free( NULL, &tag_tmp, 1UL ); /* NULL wksp */
    fd_wksp_tag_free( wksp, NULL,     0UL );
    fd_wksp_tag_free( wksp, NULL,     1UL );
    fd_wksp_tag_free( wksp, &tag_tmp, 0UL );
    fd_wksp_tag_free( wksp, &tag_tmp, 1UL );
    FD_TEST( fd_wksp_tag( wksp, g )==1UL );

    /* Test fd_wksp_reset edge cases */

    fd_wksp_reset( NULL, 0UL ); /* NULL wksp */

    /* Test fd_wksp_usage edge cases */

    fd_wksp_usage_t ref[1]; memset( ref, 0, sizeof(fd_wksp_usage_t) );
    fd_wksp_usage_t tst[1];

#   define SET           memset( tst, -1,  sizeof(fd_wksp_usage_t ) )
#   define TST FD_TEST( !memcmp( tst, ref, sizeof(fd_wksp_usage_t ) ) )

    SET; FD_TEST( fd_wksp_usage( NULL, &tag_tmp, 1UL, tst )==tst ); TST; /* NULL wksp */
    SET; FD_TEST( fd_wksp_usage( wksp, NULL,     1UL, tst )==tst ); TST; /* bad tags */
    SET; FD_TEST( fd_wksp_usage( wksp, NULL,     0UL, ref )==ref );      /* no tags (use as ref, TODO: validate the result) */
    SET; FD_TEST( fd_wksp_usage( wksp, &tag_tmp, 0UL, tst )==tst ); TST; /* no tags */
    SET; FD_TEST( fd_wksp_usage( wksp, &tag_tmp, 1UL, tst )==tst ); TST; /* tag for something with no allocs */

#   undef TST
#   undef SET

    FD_TEST( !fd_wksp_usage( wksp, &tag_tmp, 1UL, NULL ) );

    /* Misc edge cases */

    fd_wksp_free( wksp, g );

    FD_TEST( !fd_wksp_tag( wksp, g ) );
    fd_wksp_free  ( wksp, g      ); /* double free */
    fd_wksp_memset( wksp, g, 255 ); /* memset unallocated */
    FD_TEST( !fd_wksp_tag( wksp, g ) );
  }

  struct { ulong g0; ulong g1; ulong tag; } alloc[ 256 ];
  ulong alloc_cnt = 0UL;

  ulong alloc_tag[4];
  alloc_tag[0] = (fd_rng_ulong( rng )<<3) | 4UL; /* non-zero, full width, LSB encodes index */
  alloc_tag[1] = (fd_rng_ulong( rng )<<3) | 5UL; /* " */
  alloc_tag[2] = (fd_rng_ulong( rng )<<3) | 6UL; /* " */
  alloc_tag[3] = (fd_rng_ulong( rng )<<3) | 7UL; /* " */

  for( ulong iter=0UL; iter<100000000UL; iter++ ) {
    if( FD_UNLIKELY( !(iter & 8388607UL) ) ) {
      FD_LOG_NOTICE(( "iter %lu", iter ));

    //printf( "Used tree\n" );
    //dump_used_tree( wksp->part_used_cidx, fd_wksp_private_pinfo( wksp ), 4UL );
    //printf( "Free tree\n" );
    //dump_free_tree( wksp->part_free_cidx, fd_wksp_private_pinfo( wksp ), 4UL );
      FD_TEST( !fd_wksp_verify( wksp ) );

      fd_wksp_usage_t usage[1];
      FD_TEST( fd_wksp_usage( wksp, alloc_tag, 4UL, usage )==usage );
      FD_TEST( usage->total_max==part_max ); FD_TEST( usage->total_sz==data_max );
      FD_TEST( usage->total_cnt==(usage->free_cnt+usage->used_cnt) ); /* only when tag query is comprehensive */
      FD_TEST( usage->total_sz ==(usage->free_sz +usage->used_sz ) ); /* " */
      FD_LOG_NOTICE(( "Usage\n\t"
                      "total_part  %3lu\n\t"
                      "active_part %3lu active_sz %5lu\n\t"
                      "free_part   %3lu free_sz   %5lu\n\t"
                      "used_part   %3lu used_sz   %5lu",
                      usage->total_max,
                      usage->total_cnt, usage->total_sz,
                      usage->free_cnt,  usage->free_sz,
                      usage->used_cnt,  usage->used_sz ));
    }

    uint r = fd_rng_uint( rng );
    int do_tag_free = !(r & 1048575U); r >>= 20;
    if( FD_UNLIKELY( do_tag_free ) ) {
      ulong t0 = (ulong)(r & 3U); r >>= 2;
      ulong t1 = (ulong)(r & 3U); r >>= 2;
      ulong i  = fd_ulong_min( t0, t1 );
      ulong j  = fd_ulong_max( t0, t1 );

      ulong new_alloc_cnt = 0UL;
      ulong free_cnt      = 0UL;
      for( ulong alloc_idx=0UL; alloc_idx<alloc_cnt; alloc_idx++ ) {
        ulong k = alloc[ alloc_idx ].tag & 3UL;
        if( !((i<=k) & (k<j)) ) alloc[ new_alloc_cnt++ ] = alloc[ alloc_idx ];
        else                    free_cnt++;
      }
      alloc_cnt = new_alloc_cnt;

      FD_TEST( fd_wksp_tag_query( wksp, alloc_tag+i, j-i, NULL, 0UL )==free_cnt );
      fd_wksp_tag_free( wksp, alloc_tag+i, j-i );
      FD_TEST( fd_wksp_tag_query( wksp, alloc_tag+i, j-i, NULL, 0UL )==0UL );

      continue;
    }

    r = fd_rng_uint( rng );
    int do_reset = !(r & 1048575U); r >>= 20;
    if( FD_UNLIKELY( do_reset ) ) {
      fd_wksp_reset( wksp, fd_rng_uint( rng ) );
      alloc_cnt = 0UL;
      continue;
    }

    r = fd_rng_uint( rng );
    int do_rebuild = !(r & 1048575U); r >>= 20;
    if( FD_UNLIKELY( do_rebuild ) ) {
      FD_TEST( !fd_wksp_rebuild( wksp, fd_rng_uint( rng ) ) );
      continue;
    }

    r = fd_rng_uint( rng );

    int op = (r & 3U); r >>= 2;
    switch( op ) {
    default:
    case 0: { /* tag */
      ulong g     = fd_rng_ulong_roll( rng, footprint+1UL );
      ulong tag   = fd_wksp_tag( wksp, g );
      ulong found = 0UL;
      for( ulong alloc_idx=0UL; alloc_idx<alloc_cnt; alloc_idx++ )
        if( ((alloc[ alloc_idx ].g0<=g) & (g<alloc[ alloc_idx ].g1)) ) { found = alloc[ alloc_idx ].tag; break; }
      FD_TEST( tag==found );
      break;
    }

    case 1: { /* alloc */
      if( FD_UNLIKELY( alloc_cnt>=256UL ) ) break;
      ulong align = 1UL << (int)(r & 3U);    r >>= 2; /* In {1,2,4,8} */
      ulong sz    = 1UL + (ulong)(r & 127U); r >>= 6; /* In [1,128] */
      ulong tag   = alloc_tag[ r & 3U ];     r >>= 2; /* Full width, Non-zero with lots of collisions */

      ulong g0;
      ulong g1;
      ulong gr0 = fd_wksp_alloc_at_least( wksp, align, sz, tag, &g0, &g1 );
      if( !gr0 ) break;
      ulong gr1 = gr0 + sz;

      FD_TEST( fd_ulong_is_aligned( gr0, align ) );
      FD_TEST( (gaddr_lo<=g0) & (g0<=gr0) & (gr0<gr1) & (gr1<=g1) & (g1<=gaddr_hi) );
      for( ulong i=0UL; i<alloc_cnt; i++ ) FD_TEST( (g1<=alloc[i].g0) | (g0>=alloc[i].g1) ); /* doesn't overlap */

      alloc[ alloc_cnt ].g0  = g0;
      alloc[ alloc_cnt ].g1  = g1;
      alloc[ alloc_cnt ].tag = tag;
      alloc_cnt++;
      break;
    }

    case 2: { /* free */
      if( FD_UNLIKELY( !alloc_cnt ) ) break;
      ulong alloc_idx = fd_rng_ulong_roll( rng, alloc_cnt );
      ulong g0        = alloc[ alloc_idx ].g0;
      ulong g1        = alloc[ alloc_idx ].g1;
      ulong g         = g0 + fd_rng_ulong_roll( rng, g1-g0 );

      fd_wksp_free( wksp, g );

      alloc[ alloc_idx ] = alloc[ --alloc_cnt ];
      break;
    }

    case 3: { /* memset */
      if( FD_UNLIKELY( !alloc_cnt ) ) break;
      ulong alloc_idx = fd_rng_ulong_roll( rng, alloc_cnt );
      ulong g0        = alloc[ alloc_idx ].g0;
      ulong g1        = alloc[ alloc_idx ].g1;
      ulong g         = g0 + fd_rng_ulong_roll( rng, g1-g0 );
      int   c         = (int)(r & 255U); r >>= 8;

      fd_wksp_memset( wksp, g, c );

      FD_TEST( (int)(*(uchar *)fd_wksp_laddr_fast( wksp, g0     ))==c );
      FD_TEST( (int)(*(uchar *)fd_wksp_laddr_fast( wksp, g      ))==c );
      FD_TEST( (int)(*(uchar *)fd_wksp_laddr_fast( wksp, g1-1UL ))==c );
      break;
    }
    }
  }

  FD_TEST( !fd_wksp_verify( wksp ) );

  fd_wksp_delete( fd_wksp_leave( wksp ) );

  fd_rng_delete( fd_rng_leave( rng ) );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
