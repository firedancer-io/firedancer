#include "../../util/fd_util.h"
#include "fd_bloom.h"
#include "fd_gossip_message.h"

#include <stdlib.h>
#include <string.h>

FD_STATIC_ASSERT( FD_BLOOM_ALIGN    ==64UL,  unit_test );
FD_STATIC_ASSERT( FD_BLOOM_FOOTPRINT==128UL, unit_test );

FD_STATIC_ASSERT( FD_BLOOM_ALIGN    ==alignof(fd_bloom_t), unit_test );
FD_STATIC_ASSERT( FD_BLOOM_FOOTPRINT==sizeof (fd_bloom_t), unit_test );

void
test_filters( void ) {
  void * bytes = aligned_alloc( fd_bloom_align(), fd_bloom_footprint( 0.1, 100 ) );
  FD_TEST( bytes );

  fd_rng_t _rng[1]; fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, 0U, 0UL ) );
  FD_TEST( rng );

  fd_bloom_t * bloom = fd_bloom_join( fd_bloom_new( bytes, rng, 0.1, 100 ) );
  FD_TEST( bloom );

  fd_bloom_initialize( bloom, 0UL );
  FD_TEST( bloom->keys_len==0UL );
  FD_TEST( bloom->bits_len==1UL );

  fd_bloom_initialize( bloom, 10UL );
  FD_TEST( bloom->keys_len==3UL );
  FD_TEST( bloom->bits_len==48UL );

  fd_bloom_initialize( bloom, 100UL );
  FD_TEST( bloom->keys_len==1UL );
  FD_TEST( bloom->bits_len==100UL );

  free( bytes );
}

void
test_add_contains( void ) {
  void * bytes = aligned_alloc( fd_bloom_align(), fd_bloom_footprint( 0.1, 100*8 ) );
  FD_TEST( bytes );

  fd_rng_t _rng[1]; fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, 0U, 0UL ) );
  FD_TEST( rng );

  fd_bloom_t * bloom = fd_bloom_join( fd_bloom_new( bytes, rng, 0.1, 100*8 ) );
  FD_TEST( bloom );

  fd_bloom_initialize( bloom, 100UL );

  FD_TEST( !fd_bloom_contains( bloom, (uchar *)"hello", 5UL ) );
  fd_bloom_insert( bloom, (uchar *)"hello", 5UL );
  FD_TEST( fd_bloom_contains( bloom, (uchar *)"hello", 5UL ) );

  FD_TEST( !fd_bloom_contains( bloom, (uchar *)"world", 5UL ) );
  fd_bloom_insert( bloom, (uchar *)"world", 5UL );
  FD_TEST( fd_bloom_contains( bloom, (uchar *)"world", 5UL ) );

  free( bytes );
}

void
test_empty_contains( void ) {
  ulong keys[1] = { 0UL };
  ulong bits[1] = { 0UL };
  fd_bloom_t bloom[1] = {{
    .keys     = keys,
    .keys_len = 0UL,
    .bits     = bits,
    .bits_len = 64UL
  }};

  FD_TEST( !fd_bloom_contains( bloom, (uchar *)"hello", 5UL ) );

  bloom->keys_len = 1UL;
  bloom->bits_len = 0UL;
  fd_bloom_insert( bloom, (uchar *)"hello", 5UL );
  FD_TEST( !bits[0] );
  FD_TEST( !fd_bloom_contains( bloom, (uchar *)"hello", 5UL ) );
}

void
test_bitvec_deserialize_case( uchar has_bits,
                              ulong bits_cap,
                              ulong encoded_bits_len,
                              ulong expected_bits_len ) {
  uchar payload[ 183UL ] = {0};
  uchar * cur = payload;

  FD_STORE( uint,  cur, FD_GOSSIP_MESSAGE_PULL_REQUEST ); cur += 4UL;
  FD_STORE( ulong, cur, 0UL                            ); cur += 8UL; /* keys */
  FD_STORE( uchar, cur, has_bits                       ); cur += 1UL;
  if( has_bits ) {
    FD_TEST( bits_cap<=1UL );
    FD_STORE( ulong, cur, bits_cap ); cur += 8UL;
    cur += bits_cap*8UL;
  }
  FD_STORE( ulong, cur, encoded_bits_len ); cur += 8UL;
  FD_STORE( ulong, cur, 0UL                            ); cur += 8UL; /* bits set */
  FD_STORE( ulong, cur, 0UL                            ); cur += 8UL; /* mask */
  FD_STORE( uint,  cur, 6U                             ); cur += 4UL; /* mask bits */

  cur += 64UL; /* signature */
  FD_STORE( uint, cur, FD_GOSSIP_VALUE_CONTACT_INFO ); cur += 4UL;
  cur += 32UL; /* origin */
  *cur++ = 0U; /* wallclock */
  cur += 8UL;  /* outset */
  cur += 2UL;  /* shred version */
  *cur++ = 0U; /* major */
  *cur++ = 0U; /* minor */
  *cur++ = 0U; /* patch */
  cur += 4UL;  /* commit */
  cur += 4UL;  /* feature set */
  *cur++ = 0U; /* client */
  *cur++ = 0U; /* addresses */
  *cur++ = 0U; /* sockets */
  *cur++ = 0U; /* extensions */

  fd_gossip_message_t message[1] = {0};
  FD_TEST( fd_gossip_message_deserialize( message, payload, (ulong)(cur-payload) ) );
  FD_TEST( message->pull_request->crds_filter->filter->bits_cap==(has_bits ? bits_cap : 0UL) );
  FD_TEST( message->pull_request->crds_filter->filter->bits_len==expected_bits_len );
}

void
test_bitvec_deserialize( void ) {
  test_bitvec_deserialize_case( 0U, 0UL,  0UL,  0UL );
  test_bitvec_deserialize_case( 0U, 0UL,  1UL,  0UL );
  test_bitvec_deserialize_case( 1U, 0UL,  0UL,  0UL );
  test_bitvec_deserialize_case( 1U, 0UL,  1UL,  0UL );
  test_bitvec_deserialize_case( 1U, 1UL, 64UL, 64UL );
  test_bitvec_deserialize_case( 1U, 1UL, 65UL, 64UL );
}

void
test_epoch_slots_bitvec_deserialize_case( uchar has_bits,
                                          ulong bits_cap,
                                          ulong encoded_bits_len,
                                          int   expected ) {
  uchar payload[ 199UL ] = {0};
  uchar * cur = payload;

  FD_STORE( uint,  cur, FD_GOSSIP_MESSAGE_PUSH ); cur += 4UL;
  cur += 32UL; /* sender */
  FD_STORE( ulong, cur, 1UL ); cur += 8UL; /* values */

  cur += 64UL; /* signature */
  FD_STORE( uint, cur, FD_GOSSIP_VALUE_EPOCH_SLOTS ); cur += 4UL;
  *cur++ = 0U; /* index */
  cur += 32UL; /* origin */
  FD_STORE( ulong, cur, 1UL ); cur += 8UL; /* slots */
  FD_STORE( uint,  cur, 1U  ); cur += 4UL; /* Uncompressed */
  FD_STORE( ulong, cur, 0UL ); cur += 8UL; /* first slot */
  FD_STORE( ulong, cur, 0UL ); cur += 8UL; /* num */

  *cur++ = has_bits;
  if( has_bits ) {
    FD_TEST( bits_cap<=1UL );
    FD_STORE( ulong, cur, bits_cap ); cur += 8UL;
    cur += bits_cap;
  }
  FD_STORE( ulong, cur, encoded_bits_len ); cur += 8UL;
  FD_STORE( ulong, cur, 0UL              ); cur += 8UL; /* wallclock */

  fd_gossip_message_t message[1] = {0};
  FD_TEST( fd_gossip_message_deserialize( message, payload, (ulong)(cur-payload) )==expected );
}

void
test_epoch_slots_bitvec_deserialize( void ) {
  test_epoch_slots_bitvec_deserialize_case( 1U, 0UL, 0UL, 1 );
  test_epoch_slots_bitvec_deserialize_case( 0U, 0UL, 1UL, 1 );
  test_epoch_slots_bitvec_deserialize_case( 1U, 0UL, 1UL, 1 );
  test_epoch_slots_bitvec_deserialize_case( 1U, 1UL, 7UL, 0 );
  test_epoch_slots_bitvec_deserialize_case( 1U, 1UL, 8UL, 1 );
  test_epoch_slots_bitvec_deserialize_case( 1U, 1UL, 9UL, 1 );
}

/* If keys region is incorrectly sized, it would overlap with filter
   bits, which would result in undefined behaviors if any of the
   overlapping bits get set when populating the filter. */
void
test_keys_oob( void ) {
  const ulong max_bits = 8UL;
  const double false_positive_rate = 0.000000001; /* very low rate ensures we use max bits */
  void * bytes = aligned_alloc( fd_bloom_align(), fd_bloom_footprint( false_positive_rate, max_bits ) );
  FD_TEST( bytes );

  fd_rng_t _rng[1]; fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, 0U, 0UL ) );
  FD_TEST( rng );

  fd_bloom_t * bloom = fd_bloom_join( fd_bloom_new( bytes, rng, false_positive_rate, max_bits ) );
  FD_TEST( bloom );

  fd_bloom_initialize( bloom, 1 );

  uchar * bits_copy = (uchar *)aligned_alloc( 8UL, fd_ulong_align_up( (bloom->bits_len+7UL)/8UL, 8UL ) );
  fd_memcpy( bits_copy, bloom->bits, (bloom->bits_len+7UL)/8UL );

  for( ulong i=0UL; i<bloom->keys_len; i++ ) bloom->keys[ i ] = ULONG_MAX;

  FD_TEST( !memcmp( bits_copy, bloom->bits, (bloom->bits_len+7UL)/8UL ) );

  free( bits_copy );
  free( bytes );
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  FD_TEST( fd_bloom_align()==FD_BLOOM_ALIGN );

  test_filters();
  test_add_contains();
  test_empty_contains();
  test_bitvec_deserialize();
  test_epoch_slots_bitvec_deserialize();
  test_keys_oob();

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
