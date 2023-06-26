#include "../fd_util.h"
#include "../math/fd_sqrt.h"
#include "fd_wksp_private.h"

#define SCRATCH_MAX (16384UL)

static uchar scratch[ SCRATCH_MAX ] __attribute__((aligned((FD_WKSP_ALIGN))));

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  fd_rng_t _rng[1]; fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, 0U, 0UL ) );

  ulong        scratch_sz = fd_env_strip_cmdline_ulong( &argc, &argv, "--scratch-sz", "", SCRATCH_MAX );
  char const * name       = fd_env_strip_cmdline_cstr ( &argc, &argv, "--name",       "", "test"      );
  uint         seed       = fd_env_strip_cmdline_uint ( &argc, &argv, "--seed",       "", 0UL         );
  ulong        part_max   = fd_env_strip_cmdline_ulong( &argc, &argv, "--part-max",   "", 0UL         );
  ulong        data_max   = fd_env_strip_cmdline_ulong( &argc, &argv, "--data-max",   "", 0UL         );

  if( FD_UNLIKELY( scratch_sz>SCRATCH_MAX ) ) FD_LOG_ERR(( "Increase SCRATCH_MAX for this --scratch-sz" ));

  if( !part_max ) part_max = fd_wksp_part_max_est( scratch_sz, 64UL     );
  if( !data_max ) data_max = fd_wksp_data_max_est( scratch_sz, part_max );

  FD_LOG_NOTICE(( "Testing with --scratch-sz %lu --name %s --seed %u --part-max %lu --data-max %lu",
                  scratch_sz, name, seed, part_max, data_max ));

  fd_wksp_t * wksp = fd_wksp_join( fd_wksp_new( scratch, name, seed, part_max, data_max ) );
  if( FD_UNLIKELY( !wksp ) ) FD_LOG_ERR(( "Unable to create wksp" ));

  fd_wksp_private_pinfo_t * pinfo = fd_wksp_private_pinfo( wksp );

  wksp->part_used_cidx = fd_wksp_private_pinfo_cidx( FD_WKSP_PRIVATE_PINFO_IDX_NULL );

  /* Make a bunch of non-conflicting partitions of non-zero size.  We
     will hack in the tag MSB whether or not the partition is currently
     in the treap and do a ton of random operations on the treap. */

  ulong wksp_gaddr_lo = wksp->gaddr_lo;
  ulong wksp_gaddr_hi = wksp->gaddr_hi;

  ulong test_cnt = 0UL;
  ulong g0       = wksp_gaddr_lo;
  for(;;) {
    ulong g1 = g0 + test_cnt + 1UL;
    if( ((test_cnt>=part_max) | (g1>wksp_gaddr_hi)) ) break;
    pinfo[ test_cnt ].gaddr_lo = g0;
    pinfo[ test_cnt ].gaddr_hi = g1;
    pinfo[ test_cnt ].tag      = test_cnt+1UL;
    test_cnt++;
    g0 = g1;
  }
  ulong test_gaddr_hi = g0;

  /* Do a bunch of random treap operations
     TODO: coverage of insert partial overlap? */

  for( ulong iter=0UL; iter<100000000UL; iter++ ) {
    uint r  = fd_rng_uint( rng );
    int  op = (int)(r & 3U); r >>= 2;

    switch( op ) {

    default:
    case 0: { /* Query */
      ulong gaddr = fd_rng_ulong_roll( rng, scratch_sz );
      ulong i     = fd_wksp_private_used_treap_query( gaddr, wksp, pinfo );
      if( !((wksp_gaddr_lo<=gaddr) & (gaddr<test_gaddr_hi) ) ) { /* Outside the mocked up partitions */
        FD_TEST( fd_wksp_private_pinfo_idx_is_null( i ) );
      } else if( fd_wksp_private_pinfo_idx_is_null( i ) ) { /* Query indicated a partition not in treap */
        ulong j = (fd_ulong_sqrt( 8UL*(gaddr - wksp_gaddr_lo) + 1UL ) - 1UL) >> 1; /* Figure out partition */
        FD_TEST( j<test_cnt );                                             /* Make sure valid index */
        FD_TEST( (pinfo[j].gaddr_lo<=gaddr) & (gaddr<pinfo[j].gaddr_hi) ); /* Make sure in partition */
        FD_TEST( pinfo[j].tag==(j+1UL) );                                  /* Make sure tag matches */
      } else { /* Query indicated a partition in the treap */
        FD_TEST( i<test_cnt );                                             /* Make sure valid index */
        FD_TEST( (pinfo[i].gaddr_lo<=gaddr) & (gaddr<pinfo[i].gaddr_hi) ); /* Make sure in partition */
        FD_TEST( pinfo[i].tag==((1UL<<63) | (i+1UL)) );                    /* Make sure tag matches */
      }
      break;
    }

    case 1: { /* Insert */
      ulong i   = fd_rng_ulong_roll( rng, test_cnt );
      ulong tag = pinfo[i].tag;
      FD_TEST( fd_wksp_private_used_treap_insert( i, wksp, pinfo )==((tag>>63) ? FD_WKSP_ERR_CORRUPT : FD_WKSP_SUCCESS) );
      pinfo[i].tag = tag |  (1UL<<63);
      break;
    }

    case 2: { /* Remove */
      ulong i   = fd_rng_ulong_roll( rng, test_cnt );
      ulong tag = pinfo[i].tag;
      FD_TEST( fd_wksp_private_used_treap_remove( i, wksp, pinfo )==((tag>>63) ? FD_WKSP_SUCCESS : FD_WKSP_ERR_CORRUPT) );
      pinfo[i].tag = tag & ~(1UL<<63);
      break;
    }

    }
  }

  fd_wksp_delete( fd_wksp_leave( wksp ) );

  fd_rng_delete( fd_rng_leave( rng ) );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
