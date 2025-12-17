#include "../../../util/fd_util.h"
#include "fd_crds.h"

#include <stdlib.h>

static void
test_crds_new_basic( void ) {
  ulong ele_max    = 1024UL;
  ulong purged_max =  512UL;

  void * mem = aligned_alloc( fd_crds_align(), fd_crds_footprint( ele_max, purged_max ) );
  FD_TEST( mem );

  fd_rng_t _rng[1];
  fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, 0U, 0UL ) );
  FD_TEST( rng );

  static fd_gossip_out_ctx_t gossip_out = {0};

  void * shcrds = fd_crds_new( mem, rng, ele_max, purged_max, &gossip_out );
  FD_TEST( shcrds );

  fd_crds_t * crds = fd_crds_join( shcrds );
  FD_TEST( crds );

  free( mem );
}

static ulong
generate_mask( ulong prefix,
               uint  mask_bits ) {
  /* agave defines the mask as a ulong with the top mask_bits bits
     set to the desired prefix and all other bits set to 1. */
  FD_TEST( mask_bits<64U );
  if( FD_UNLIKELY( mask_bits==0U ) )  return ~0UL;
  prefix &=  fd_ulong_mask( 0U, (int)(mask_bits-1U) );
  prefix <<= 64U-mask_bits;
  return prefix | fd_ulong_mask( 0U, (int)(63U-mask_bits) );
}

static void
test_generate_mask( void ) {
  FD_TEST( generate_mask(   0UL,  0U )  == 0xFFFFFFFFFFFFFFFF );
  FD_TEST( generate_mask(   1UL,  0U )  == 0xFFFFFFFFFFFFFFFF );
  FD_TEST( generate_mask(  ~0UL,  0U )  == 0xFFFFFFFFFFFFFFFF );

  FD_TEST( generate_mask(   0UL,  1U )  == 0x7FFFFFFFFFFFFFFF );
  FD_TEST( generate_mask(   1UL,  1U )  == 0xFFFFFFFFFFFFFFFF );
  FD_TEST( generate_mask(   2UL,  1U )  == 0x7FFFFFFFFFFFFFFF );
  FD_TEST( generate_mask(   3UL,  1U )  == 0xFFFFFFFFFFFFFFFF );

  FD_TEST( generate_mask(   0UL,  4U )  == 0x0FFFFFFFFFFFFFFF );
  FD_TEST( generate_mask( 255UL,  4U )  == 0xFFFFFFFFFFFFFFFF );

  FD_TEST( generate_mask(   0UL,  8U )  == 0x00FFFFFFFFFFFFFF );
  FD_TEST( generate_mask(  68UL,  8U )  == 0x44FFFFFFFFFFFFFF );
  FD_TEST( generate_mask(  70UL,  8U )  == 0x46FFFFFFFFFFFFFF );
  FD_TEST( generate_mask( 255UL,  8U )  == 0xFFFFFFFFFFFFFFFF );

  FD_TEST( generate_mask(   0UL, 63U )  == 0x0000000000000001 );
  FD_TEST( generate_mask(   1UL, 63U )  == 0x0000000000000003 );
  FD_TEST( generate_mask(  ~0UL, 63U )  == 0xFFFFFFFFFFFFFFFF );
}

static void
do_mask_test( ulong       prefix,
              uint        mask_bits,
              ulong       expected_matches,
              fd_crds_t * crds ) {
  uchar iter_mem[ 16UL ];
  ulong mask = generate_mask( prefix, mask_bits );
  ulong matches = 0UL;
  for( fd_crds_mask_iter_t * it=fd_crds_mask_iter_init( crds, mask, mask_bits, iter_mem );
       !fd_crds_mask_iter_done( it, crds );
       it=fd_crds_mask_iter_next( it, crds ) ) {
    matches++;
    fd_crds_entry_t const * candidate = fd_crds_mask_iter_entry( it, crds );
    uchar const *           hash      = fd_crds_entry_hash( candidate );
    ulong                   prefix    = fd_ulong_bswap( fd_ulong_load_8( hash ) );
    FD_TEST( (prefix & mask)==prefix );
  }
  if( FD_UNLIKELY( matches!=expected_matches ) ) FD_LOG_ERR(( "incorrect match count, expected %lu got %lu", expected_matches, matches ));
}

static void
do_purged_mask_test( ulong       prefix,
                     uint        mask_bits,
                     ulong       expected_matches,
                     fd_crds_t * crds ) {
  uchar iter_mem[ 16UL ];
  ulong mask = generate_mask( prefix, mask_bits );
  ulong matches = 0UL;
  for( fd_crds_mask_iter_t * it=fd_crds_purged_mask_iter_init( crds, mask, mask_bits, iter_mem );
       !fd_crds_purged_mask_iter_done( it, crds );
       it=fd_crds_purged_mask_iter_next( it, crds ) ) {
    matches++;
    uchar const * hash   = fd_crds_purged_mask_iter_hash( it, crds );
    ulong         prefix = fd_ulong_bswap( fd_ulong_load_8( hash ) );
    FD_TEST( (prefix & mask)==prefix );
  }
  if( FD_UNLIKELY( matches!=expected_matches ) ) FD_LOG_ERR(( "incorrect match count, expected %lu got %lu", expected_matches, matches ));
}

static void
test_crds_mask_iter( void ) {
  fd_rng_t _rng[1];
  fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, 0U, 0UL ) );
  FD_TEST( rng );

  ulong ele_max = 1024UL;
  ulong purged_max = 1024UL;
  void * crds_mem = aligned_alloc( fd_crds_align(), fd_crds_footprint( ele_max, purged_max ) );
  FD_TEST( crds_mem );
  static fd_gossip_out_ctx_t test_gossip_out_ctx = {0};
  fd_crds_t * crds = fd_crds_join( fd_crds_new( crds_mem, rng, ele_max, purged_max, &test_gossip_out_ctx ) );
  FD_TEST( crds );

  long now = fd_log_wallclock();

#define ENTRY_CNT 768UL
  uchar payloads[ ENTRY_CNT ][ FD_GOSSIP_CRDS_MAX_SZ ];
  for( ulong i=0UL; i<ENTRY_CNT; i++ ) {
    for( ulong j=0UL; j<FD_GOSSIP_CRDS_MAX_SZ; j++ ) payloads[ i ][ j ] = fd_rng_uchar( rng );
    FD_STORE( uint, payloads[ i ]+64UL, FD_GOSSIP_VALUE_LOWEST_SLOT );
  }

  for( ulong i=0UL; i<ENTRY_CNT; i++ ) {
    fd_gossip_view_crds_value_t view[1];
    view->value_off = 0UL;
    view->pubkey_off = 64UL+4UL;
    view->wallclock_nanos = now;
    view->length = FD_GOSSIP_CRDS_MAX_SZ;
    view->tag = FD_GOSSIP_VALUE_LOWEST_SLOT;
    view->lowest_slot = i;

    int crds_res = fd_crds_checks_fast( crds, view, payloads[ i ], 0 );
    FD_TEST( crds_res==FD_CRDS_UPSERT_CHECK_UPSERTS );
    fd_crds_entry_t const * entry = fd_crds_insert( crds, view, payloads[ i ], 0UL, 0, now, NULL );
    FD_TEST( entry!=NULL );
  }

  /* Zero bits should yeild all crds entries */
  do_mask_test( 0x0UL, 0U, ENTRY_CNT, crds );

  /* 63 bits should yeild one crds entry */
  do_mask_test( (0x356e7c8ca538cdcaUL>>1UL), 63U, 1UL, crds );

  /* All the hashes starting with byte 0x11 */
  do_mask_test( 0x11UL, 8U, 4UL, crds );

  /* Hashes starting with 0b11111 */
  do_mask_test( 0x1fUL, 5U, 28UL, crds );

  /* Invalid prefix */
  do_mask_test( 0xbeef, 12U, 0UL, crds );

  /* No purged yet */
  uchar iter_mem[ 16UL ];
  fd_crds_mask_iter_t * it = fd_crds_purged_mask_iter_init( crds, generate_mask( 0x0UL, 0U ), 0U, iter_mem );
  FD_TEST( fd_crds_purged_mask_iter_done( it, crds ) );

  /* Purge everything */
  now += 60L*60L*1000L*1000L*1000L;
  for( ulong i=0UL; i<ENTRY_CNT; i++ ) {
    for( ulong j=0UL; j<64UL; j++ ) payloads[ i ][ j ] = fd_rng_uchar( rng );

    fd_gossip_view_crds_value_t view[1];
    view->value_off = 0UL;
    view->pubkey_off = 64UL+4UL;
    view->wallclock_nanos = now;
    view->length = FD_GOSSIP_CRDS_MAX_SZ;
    view->tag = FD_GOSSIP_VALUE_LOWEST_SLOT;
    view->lowest_slot = i;

    int crds_res = fd_crds_checks_fast( crds, view, payloads[ i ], 0 );
    FD_TEST( crds_res==FD_CRDS_UPSERT_CHECK_UPSERTS );
    fd_crds_entry_t const * entry = fd_crds_insert( crds, view, payloads[ i ], 0UL, 0, now, NULL );
    FD_TEST( entry!=NULL );
  }

  /* Zero bits should yeild all crds entries */
  do_purged_mask_test( 0x0UL, 0U, ENTRY_CNT, crds );

  /* 63 bits should yeild one crds entry */
  do_purged_mask_test( (0x356e7c8ca538cdcaUL>>1UL), 63U, 1UL, crds );

  /* All the hashes starting with byte 0x11 */
  do_purged_mask_test( 0x11UL, 8U, 4UL, crds );

  /* Hashes starting with 0b11111 */
  do_purged_mask_test( 0x1fUL, 5U, 28UL, crds );

  /* Invalid prefix */
  do_purged_mask_test( 0xbeef, 12U, 0UL, crds );

  free( crds_mem );
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );
  test_crds_new_basic();
  test_generate_mask();
  test_crds_mask_iter();
  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
