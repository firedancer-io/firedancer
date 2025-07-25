#include <stdalign.h>

#include "fd_rdisp.h"

#define TEST_FOOTPRINT (1024UL*1024UL)
uchar footprint[ TEST_FOOTPRINT ] __attribute__((aligned(128)));

/* so that if/when we change RDISP_BLOCK_TAG_T, only one function has to
   change. */
static inline FD_RDISP_BLOCK_TAG_T tag( ulong x ) { return x; }

static ulong
add_txn( fd_rdisp_t *         rdisp,
         fd_rng_t   *         rng,
         FD_RDISP_BLOCK_TAG_T tag,
         char const *         writable,
         char const *         readonly,
         int                  serializing ) {
  char categorized[3][2][128]; /* (signer, nonsigner, alt) x (writeble, readonly) x accts */
  ulong cat_cnts[3][2] = { 0 };

  for( ulong j=0UL; j<2UL; j++ ) {
    char const * str = fd_ptr_if( j==0UL, writable, readonly );
    while( *str ) {
      ulong cat = fd_rng_uint_roll( rng, 3UL );
      categorized[cat][j][ cat_cnts[cat][j]++ ] = *str;
      str++;
    }
  }

  FD_TEST( cat_cnts[0][0]+cat_cnts[0][1]+cat_cnts[1][0]+cat_cnts[1][1]<=38UL );

  uchar _txn[ sizeof(fd_txn_t) ] __attribute__((aligned(alignof(fd_txn_t)))) = { 0 };

  fd_txn_t * txn = (fd_txn_t *)fd_type_pun( _txn );
  txn->transaction_version = FD_TXN_V0;
  txn->signature_cnt = (uchar)(cat_cnts[0][0]+cat_cnts[0][1]);
  txn->readonly_signed_cnt = (uchar)cat_cnts[0][1];
  txn->readonly_unsigned_cnt = (uchar)cat_cnts[1][1];
  txn->acct_addr_cnt = (uchar)(cat_cnts[0][0]+cat_cnts[0][1]+cat_cnts[1][0]+cat_cnts[1][1]);
  txn->acct_addr_off = 0;
  txn->addr_table_lookup_cnt = 1;
  txn->addr_table_adtl_writable_cnt = (uchar)cat_cnts[2][0];
  txn->addr_table_adtl_cnt = (uchar)(cat_cnts[2][0]+cat_cnts[2][1]);

  uchar payload[ 1232 ];
  fd_acct_addr_t * acct = (fd_acct_addr_t *)fd_type_pun( payload );
  for( ulong i=0UL; i<4UL; i++ ) for( ulong j=0UL; j<cat_cnts[i>>1][i&1]; j++ ) memset( acct++, categorized[i>>1][i&1][j], 32UL );
  fd_acct_addr_t alt[ 128 ];
  acct = alt;
  for( ulong i=4UL; i<6UL; i++ ) for( ulong j=0UL; j<cat_cnts[2][i&1]; j++ ) memset( acct++, categorized[2][i&1][j], 32UL );

  return fd_rdisp_add_txn( rdisp, tag, txn, payload, alt, serializing );
}

static inline ulong
pop_option( ulong * indices,
            ulong   cnt,
            ulong   idx ) {
  for( ulong i=0UL; i<cnt; i++ ) {
    if( indices[i]==idx ) { indices[i] |= 0x8000000000UL; return idx; }
  }
  return 0UL;
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  fd_rng_t _rng[1]; fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, 0U, 0UL ) );

  ulong depth       = 100UL;
  ulong block_depth = 10UL;
  FD_TEST( fd_rdisp_footprint( depth, block_depth )<=TEST_FOOTPRINT && fd_rdisp_align()<=128UL ); /* if this fails, update the test */

  fd_rdisp_staging_lane_info_t lane_info[ 4 ];

  fd_rdisp_t * disp = fd_rdisp_join( fd_rdisp_new( footprint, depth, block_depth ) );   FD_TEST( disp );

  /* operations on an unknown block fail */
  FD_TEST( -1==fd_rdisp_remove_block( disp, tag( 1UL ) ) );
  FD_TEST( 0UL==add_txn( disp, rng, tag( 1UL ), "ABC", "DEF", 0 ) );
  FD_TEST( 0UL==fd_rdisp_get_next_ready( disp, tag( 1UL ) ) );

  FD_TEST( 0xFUL==fd_rdisp_staging_lane_info( disp, lane_info ) ); /* all free */

  FD_TEST( 0==fd_rdisp_add_block( disp, tag( 0UL ), 0 ) );
  FD_TEST( 0xEUL==fd_rdisp_staging_lane_info( disp, lane_info ) );
  FD_TEST( -1==fd_rdisp_add_block( disp, tag( 0UL ), 0                 ) ); /* can't add again */
  FD_TEST( -1==fd_rdisp_add_block( disp, tag( 0UL ), FD_RDISP_UNSTAGED ) ); /* can't add again */

  FD_TEST(  0==fd_rdisp_add_block( disp, tag( 1UL ), FD_RDISP_UNSTAGED ) );
  FD_TEST( 0xEUL==fd_rdisp_staging_lane_info( disp, lane_info ) );

  FD_TEST(  0==fd_rdisp_add_block( disp, tag( 2UL ), 2 ) );
  FD_TEST( 0xAUL==fd_rdisp_staging_lane_info( disp, lane_info ) );
  FD_TEST(  0==fd_rdisp_remove_block( disp, tag( 2UL ) ) );
  FD_TEST( 0xEUL==fd_rdisp_staging_lane_info( disp, lane_info ) );
  FD_TEST(  0==fd_rdisp_add_block( disp, tag( 2UL ), 2 ) );
  FD_TEST( 0xAUL==fd_rdisp_staging_lane_info( disp, lane_info ) );

  ulong t0[3];
  ulong t1[3];
  ulong t2[3];
  ulong t3[3];
  /* 3 transactions that have to go in order */
  FD_TEST( 0UL!=(t1[0]=add_txn( disp, rng, tag( 1UL ), "ABC", "DEF", 0 )) );
  FD_TEST( 0UL!=(t1[1]=add_txn( disp, rng, tag( 1UL ), "A",   "DEF", 0 )) );
  FD_TEST( 0UL!=(t1[2]=add_txn( disp, rng, tag( 1UL ), "AF",  "DE",  0 )) );

  FD_TEST( t1[0]==fd_rdisp_get_next_ready( disp, tag( 1UL ) ) );
  FD_TEST( 0UL  ==fd_rdisp_get_next_ready( disp, tag( 1UL ) ) );   fd_rdisp_complete_txn( disp, t1[0] );
  FD_TEST( t1[1]==fd_rdisp_get_next_ready( disp, tag( 1UL ) ) );   fd_rdisp_complete_txn( disp, t1[1] );
  FD_TEST( t1[2]==fd_rdisp_get_next_ready( disp, tag( 1UL ) ) );   fd_rdisp_complete_txn( disp, t1[2] );
  FD_TEST( 0UL  ==fd_rdisp_get_next_ready( disp, tag( 1UL ) ) ); /* empty */

  /* 3 transactions that can go in any order */
  FD_TEST( 0UL!=(t1[0]=add_txn( disp, rng, tag( 1UL ), "A", "DEF", 0 )) );
  FD_TEST( 0UL!=(t1[1]=add_txn( disp, rng, tag( 1UL ), "B", "DEF", 0 )) );
  FD_TEST( 0UL!=(t1[2]=add_txn( disp, rng, tag( 1UL ), "C", "DE",  0 )) );

  ulong last;
  last = fd_rdisp_get_next_ready( disp, tag( 1UL ) ); FD_TEST( pop_option( t1, 3UL, last ) ); fd_rdisp_complete_txn( disp, last );
  last = fd_rdisp_get_next_ready( disp, tag( 1UL ) ); FD_TEST( pop_option( t1, 3UL, last ) ); fd_rdisp_complete_txn( disp, last );
  last = fd_rdisp_get_next_ready( disp, tag( 1UL ) ); FD_TEST( pop_option( t1, 3UL, last ) ); fd_rdisp_complete_txn( disp, last );
  FD_TEST( 0UL  ==fd_rdisp_get_next_ready( disp, tag( 1UL ) ) ); /* empty */

  FD_TEST( 0UL!=(t0[0]=add_txn( disp, rng, tag( 0UL ), "A", "DEF", 0 )) );
  FD_TEST( 0UL!=(t0[1]=add_txn( disp, rng, tag( 0UL ), "B", "DEF", 0 )) );
  FD_TEST( 0UL!=(t0[2]=add_txn( disp, rng, tag( 0UL ), "C", "DE",  0 )) );

  FD_TEST( 0UL!=(t1[0]=add_txn( disp, rng, tag( 1UL ), "A", "DEF", 0 )) );
  FD_TEST( 0UL!=(t1[1]=add_txn( disp, rng, tag( 1UL ), "B", "DEF", 0 )) );
  FD_TEST( 0UL!=(t1[2]=add_txn( disp, rng, tag( 1UL ), "C", "DE",  0 )) );

  FD_TEST( 0==fd_rdisp_promote_block( disp, tag( 1UL ), 0 ) );

  last = fd_rdisp_get_next_ready( disp, tag( 0UL ) ); FD_TEST( pop_option( t0, 3UL, last ) ); fd_rdisp_complete_txn( disp, last );
  last = fd_rdisp_get_next_ready( disp, tag( 0UL ) ); FD_TEST( pop_option( t0, 3UL, last ) ); fd_rdisp_complete_txn( disp, last );
  last = fd_rdisp_get_next_ready( disp, tag( 0UL ) ); FD_TEST( pop_option( t0, 3UL, last ) ); fd_rdisp_complete_txn( disp, last );
  FD_TEST( 0UL  ==fd_rdisp_get_next_ready( disp, tag( 0UL ) ) ); /* empty */

  FD_TEST( 0==fd_rdisp_add_block( disp, tag( 3UL ), 0 ) );
  FD_TEST( 0UL!=(t3[0]=add_txn( disp, rng, tag( 3UL ), "A", "DEF", 0 )) );
  FD_TEST( 0UL!=(t3[1]=add_txn( disp, rng, tag( 3UL ), "B", "DEF", 0 )) );
  FD_TEST( 0UL!=(t3[2]=add_txn( disp, rng, tag( 3UL ), "C", "DE",  0 )) );

  FD_TEST(  0==fd_rdisp_remove_block ( disp, tag( 0UL ) ) );
  FD_TEST( -1==fd_rdisp_abandon_block( disp, tag( 0UL ) ) );
  FD_TEST(  0==fd_rdisp_abandon_block( disp, tag( 1UL ) ) );

  FD_TEST( 0UL  ==fd_rdisp_get_next_ready( disp, tag( 0UL ) ) );
  FD_TEST( 0UL  ==fd_rdisp_get_next_ready( disp, tag( 1UL ) ) );

  last = fd_rdisp_get_next_ready( disp, tag( 3UL ) ); FD_TEST( pop_option( t3, 3UL, last ) ); fd_rdisp_complete_txn( disp, last );
  last = fd_rdisp_get_next_ready( disp, tag( 3UL ) ); FD_TEST( pop_option( t3, 3UL, last ) ); fd_rdisp_complete_txn( disp, last );
  last = fd_rdisp_get_next_ready( disp, tag( 3UL ) ); FD_TEST( pop_option( t3, 3UL, last ) ); fd_rdisp_complete_txn( disp, last );

  (void)t2;

  fd_rng_delete( fd_rng_leave( rng ) );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
