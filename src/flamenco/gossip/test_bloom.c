#include "../../util/fd_util.h"
#include "fd_bloom.h"
#include "fd_gossip_message.h"

#include <stdlib.h>
#include <string.h>

FD_STATIC_ASSERT( FD_BLOOM_ALIGN    ==64UL,  unit_test );
FD_STATIC_ASSERT( FD_BLOOM_FOOTPRINT==128UL, unit_test );

FD_STATIC_ASSERT( FD_BLOOM_ALIGN    ==alignof(fd_bloom_t), unit_test );
FD_STATIC_ASSERT( FD_BLOOM_FOOTPRINT==sizeof (fd_bloom_t), unit_test );

static ulong
ref_fnv( uchar const * ele, ulong ele_sz, ulong key ) {
  for( ulong i=0UL; i<ele_sz; i++ ) { key ^= (ulong)ele[i]; key *= 1099511628211UL; }
  return key;
}

/* The bits set by fd_bloom_insert must match the plain one key at a
   time FNV construction (Agave wire compatibility). */

void
test_fnv_reference( void ) {
  fd_rng_t _rng[1]; fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, 1U, 0UL ) );
  for( ulong keys_len=1UL; keys_len<=9UL; keys_len++ ) {
    for( ulong iter=0UL; iter<200UL; iter++ ) {
      ulong keys[ 9 ];
      ulong bits[ 64 ] = {0};
      ulong ref [ 64 ] = {0};
      ulong bits_len = 1UL + fd_rng_ulong_roll( rng, 64UL*64UL );
      for( ulong k=0UL; k<keys_len; k++ ) keys[ k ] = fd_rng_ulong( rng );
      fd_bloom_t bloom[1] = {{ .keys = keys, .keys_len = keys_len, .bits = bits, .bits_len = bits_len }};
      uchar ele[ 40 ];
      ulong ele_sz = fd_rng_ulong_roll( rng, 41UL );
      for( ulong i=0UL; i<ele_sz; i++ ) ele[ i ] = fd_rng_uchar( rng );
      fd_bloom_insert( bloom, ele, ele_sz );
      for( ulong k=0UL; k<keys_len; k++ ) {
        ulong bit = ref_fnv( ele, ele_sz, keys[ k ] ) % bits_len;
        ref[ bit/64UL ] |= 1UL<<(bit%64UL);
      }
      FD_TEST( !memcmp( bits, ref, sizeof(bits) ) );
      FD_TEST( fd_bloom_contains( bloom, ele, ele_sz ) );
    }
  }
  fd_rng_delete( fd_rng_leave( rng ) );
}

/* insert8 must set the same bits as fd_bloom_insert of each lane. */

void
test_insert8( void ) {
  fd_rng_t _rng[1]; fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, 2U, 0UL ) );
  for( ulong iter=0UL; iter<20000UL; iter++ ) {
    ulong keys_len = 1UL + fd_rng_ulong_roll( rng, 9UL );
    ulong bits_len = 1UL + fd_rng_ulong_roll( rng, 151UL*64UL );
    if( iter<16UL ) bits_len = iter+1UL;
    ulong keys[ 9 ];
    for( ulong k=0UL; k<keys_len; k++ ) keys[ k ] = fd_rng_ulong( rng );
    if( iter&1UL ) for( ulong k=0UL; k<keys_len; k++ ) keys[ k ] = ULONG_MAX-fd_rng_ulong_roll( rng, 4UL );
    ulong bits0[ 151 ] = {0};
    ulong bits1[ 151 ] = {0};
    fd_bloom_t b0[1] = {{ .keys = keys, .keys_len = keys_len, .bits = bits0, .bits_len = bits_len }};
    fd_bloom_t b1[1] = {{ .keys = keys, .keys_len = keys_len, .bits = bits1, .bits_len = bits_len }};
    uchar ele[ 256 ];
    for( ulong i=0UL; i<256UL; i++ ) ele[ i ] = fd_rng_uchar( rng );
    uint lanes = fd_rng_uint( rng ) & 0xffU;
    fd_bloom_insert8( b1, ele, lanes );
    for( ulong i=0UL; i<8UL; i++ ) if( lanes & (1U<<i) ) fd_bloom_insert( b0, ele+32UL*i, 32UL );
    FD_TEST( !memcmp( bits0, bits1, sizeof(bits0) ) );
  }
  fd_rng_delete( fd_rng_leave( rng ) );
}

/* insert16 must set the same bits as insert8 of each block. */

void
test_insert16( void ) {
  fd_rng_t _rng[1]; fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, 4U, 0UL ) );
  for( ulong iter=0UL; iter<20000UL; iter++ ) {
    ulong keys_len = 1UL + fd_rng_ulong_roll( rng, 9UL );
    ulong bits_len = 1UL + fd_rng_ulong_roll( rng, 151UL*64UL );
    if( iter<16UL ) bits_len = iter+1UL;
    ulong keys[ 9 ];
    for( ulong k=0UL; k<keys_len; k++ ) keys[ k ] = fd_rng_ulong( rng );
    if( iter&1UL ) for( ulong k=0UL; k<keys_len; k++ ) keys[ k ] = ULONG_MAX-fd_rng_ulong_roll( rng, 4UL );
    ulong bits0[ 151 ] = {0};
    ulong bits1[ 151 ] = {0};
    fd_bloom_t b0[1] = {{ .keys = keys, .keys_len = keys_len, .bits = bits0, .bits_len = bits_len }};
    fd_bloom_t b1[1] = {{ .keys = keys, .keys_len = keys_len, .bits = bits1, .bits_len = bits_len }};
    uchar ele[ 512 ];
    for( ulong i=0UL; i<512UL; i++ ) ele[ i ] = fd_rng_uchar( rng );
    uint lanes_a = fd_rng_uint( rng ) & 0xffU;
    uint lanes_b = fd_rng_uint( rng ) & 0xffU;
    if( (iter%7UL)==0UL ) lanes_a = 0U;
    if( (iter%11UL)==0UL ) lanes_b = 0U;
    fd_bloom_insert16( b1, ele, lanes_a, ele+256UL, lanes_b );
    fd_bloom_insert8( b0, ele, lanes_a );
    fd_bloom_insert8( b0, ele+256UL, lanes_b );
    FD_TEST( !memcmp( bits0, bits1, sizeof(bits0) ) );
  }
  fd_rng_delete( fd_rng_leave( rng ) );
}

/* contains8 must answer as fd_bloom_contains on each lane, including
   the wire filter's attacker chosen shapes: keys_len 0..152, bits_len
   0..9664, and lanes with a mix of members and non members. */

void
test_contains8( void ) {
  fd_rng_t _rng[1]; fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, 3U, 0UL ) );
  static ulong keys[ 152 ];
  static ulong bits[ 151 ];
  for( ulong iter=0UL; iter<20000UL; iter++ ) {
    ulong keys_len = fd_rng_ulong_roll( rng, 153UL );
    if( iter&1UL ) keys_len = fd_rng_ulong_roll( rng, 9UL );
    ulong bits_len = fd_rng_ulong_roll( rng, 151UL*64UL+1UL );
    if( iter<16UL ) bits_len = iter;
    for( ulong k=0UL; k<keys_len; k++ ) keys[ k ] = fd_rng_ulong( rng );
    memset( bits, 0, sizeof(bits) );
    fd_bloom_t bloom[1] = {{ .keys = keys, .keys_len = keys_len, .bits = bits, .bits_len = bits_len }};
    uchar ele[ 256 ];
    for( ulong i=0UL; i<256UL; i++ ) ele[ i ] = fd_rng_uchar( rng );
    /* insert some lanes, and some random bits so partial matches occur */
    uint lanes = fd_rng_uint( rng ) & 0xffU;
    fd_bloom_insert8( bloom, ele, lanes );
    if( bits_len ) for( ulong n=fd_rng_ulong_roll( rng, 64UL ); n; n-- ) { ulong bit = fd_rng_ulong_roll( rng, bits_len ); bits[ bit/64UL ] |= 1UL<<(bit%64UL); }
    uint got = fd_bloom_contains8( bloom, ele );
    uint ref = 0U;
    for( ulong i=0UL; i<8UL; i++ ) ref |= (uint)fd_bloom_contains( bloom, ele+32UL*i, 32UL )<<i;
    FD_TEST( got==ref );
    if( keys_len && bits_len ) FD_TEST( (got&lanes)==lanes );
    if( !keys_len || !bits_len ) FD_TEST( !got );
  }
  fd_rng_delete( fd_rng_leave( rng ) );
}

/* contains_multi must answer as fd_bloom_contains on each bloom, for
   the active set's 3 key blooms and for shapes that take the scalar
   fallback (a bloom with many keys, more than 40 keys in total). */

void
test_contains_multi( void ) {
  fd_rng_t _rng[1]; fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, 4U, 0UL ) );
  static ulong keys[ 32 ][ 48 ];
  static ulong bits[ 32 ][ 16 ];
  fd_bloom_t   bloom[ 32 ];
  fd_bloom_t * blooms[ 32 ];
  for( ulong iter=0UL; iter<20000UL; iter++ ) {
    ulong cnt = fd_rng_ulong_roll( rng, 33UL );
    if( iter&1UL ) cnt = 1UL+fd_rng_ulong_roll( rng, 12UL );
    for( ulong b=0UL; b<cnt; b++ ) {
      ulong keys_len = (iter&2UL) ? 3UL : fd_rng_ulong_roll( rng, 49UL );
      ulong bits_len = fd_rng_ulong_roll( rng, 16UL*64UL+1UL );
      if( !fd_rng_ulong_roll( rng, 16UL ) ) keys_len = 0UL;
      if( !fd_rng_ulong_roll( rng, 16UL ) ) bits_len = 0UL;
      for( ulong k=0UL; k<keys_len; k++ ) keys[ b ][ k ] = fd_rng_ulong( rng );
      memset( bits[ b ], 0, sizeof(bits[ b ]) );
      bloom[ b ] = (fd_bloom_t){ .keys = keys[ b ], .keys_len = keys_len, .bits = bits[ b ], .bits_len = bits_len };
      blooms[ b ] = &bloom[ b ];
    }
    uchar key[ 40 ];
    ulong key_sz = (iter&4UL) ? 32UL : fd_rng_ulong_roll( rng, 41UL );
    for( ulong i=0UL; i<key_sz; i++ ) key[ i ] = fd_rng_uchar( rng );
    uint ins = fd_rng_uint( rng );
    for( ulong b=0UL; b<cnt; b++ ) {
      if( (ins>>b)&1U ) fd_bloom_insert( &bloom[ b ], key, key_sz );
      if( bloom[ b ].bits_len ) for( ulong n=fd_rng_ulong_roll( rng, 8UL ); n; n-- ) { ulong bit = fd_rng_ulong_roll( rng, bloom[ b ].bits_len ); bits[ b ][ bit/64UL ] |= 1UL<<(bit%64UL); }
    }
    uint got = fd_bloom_contains_multi( blooms, cnt, key, key_sz );
    uint ref = 0U;
    for( ulong b=0UL; b<cnt; b++ ) ref |= (uint)fd_bloom_contains( &bloom[ b ], key, key_sz )<<b;
    FD_TEST( got==ref );
  }
  FD_TEST( !fd_bloom_contains_multi( blooms, 0UL, (uchar const *)"x", 1UL ) );
  fd_rng_delete( fd_rng_leave( rng ) );
}

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

static void
test_pull_request_serialize_alignment( void ) {
  uchar payload[256UL] __attribute__((aligned(8))) = {0};
  uchar contact_info[1UL] = {0};
  uchar * wire_keys;
  uchar * wire_bits;
  uchar * wire_bits_set;

  long payload_sz = fd_gossip_pull_request_init( payload,
                                                  sizeof(payload),
                                                  1UL,
                                                  64UL,
                                                  0UL,
                                                  0U,
                                                  contact_info,
                                                  sizeof(contact_info),
                                                  &wire_keys,
                                                  &wire_bits,
                                                  &wire_bits_set );
  FD_TEST( payload_sz>0L );
  FD_TEST( !fd_ulong_is_aligned( (ulong)wire_keys,     alignof(ulong) ) );
  FD_TEST( !fd_ulong_is_aligned( (ulong)wire_bits,     alignof(ulong) ) );
  FD_TEST( !fd_ulong_is_aligned( (ulong)wire_bits_set, alignof(ulong) ) );

  ulong keys[1UL];
  ulong bits[1UL] = {0};
  fd_rng_t rng_mem[1];
  fd_rng_t * rng = fd_rng_join( fd_rng_new( rng_mem, 0U, 0UL ) );
  FD_TEST( rng );

  fd_bloom_t bloom[1];
  FD_TEST( !fd_bloom_init_inplace( keys, bits, 1UL, 64UL, 0UL, rng, 0.1, bloom ) );
  fd_bloom_insert( bloom, (uchar const *)"x", 1UL );
  ulong bits_set = (ulong)fd_ulong_popcnt( bits[0] );
  FD_TEST( bits_set );

  fd_memcpy( wire_keys, keys, sizeof(keys) );
  fd_memcpy( wire_bits, bits, sizeof(bits) );
  FD_STORE( ulong, wire_bits_set, bits_set );

  FD_TEST( FD_LOAD( ulong, wire_keys     )==keys[0]  );
  FD_TEST( FD_LOAD( ulong, wire_bits     )==bits[0]  );
  FD_TEST( FD_LOAD( ulong, wire_bits_set )==bits_set );

  fd_rng_delete( fd_rng_leave( rng ) );
}

void
test_bitvec_deserialize_case( uchar has_bits,
                              ulong bits_cap,
                              ulong encoded_bits_len,
                              int   expected ) {
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
  FD_TEST( fd_gossip_message_deserialize( message, payload, (ulong)(cur-payload) )==expected );
  if( expected ) {
    FD_TEST( message->pull_request->crds_filter->filter->bits_cap==(has_bits ? bits_cap : 0UL) );
    FD_TEST( message->pull_request->crds_filter->filter->bits_len==encoded_bits_len );
  }
}

void
test_bitvec_deserialize( void ) {
  /*                            has_bits  cap  bits_len  accept */
  test_bitvec_deserialize_case( 0U,       0UL,  0UL,     1 ); /* None, empty            */
  test_bitvec_deserialize_case( 0U,       0UL,  1UL,     0 ); /* None, over capacity 0  */
  test_bitvec_deserialize_case( 1U,       0UL,  0UL,     1 ); /* Some([]), empty        */
  test_bitvec_deserialize_case( 1U,       0UL,  1UL,     0 ); /* Some([]), over cap 0   */
  test_bitvec_deserialize_case( 1U,       1UL, 32UL,     1 ); /* surplus capacity is ok */
  test_bitvec_deserialize_case( 1U,       1UL, 64UL,     1 ); /* exact fit              */
  test_bitvec_deserialize_case( 1U,       1UL, 65UL,     0 ); /* over capacity 64       */
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
  /*                                        has_bits  cap  bits_cnt  accept */
  test_epoch_slots_bitvec_deserialize_case( 0U,       0UL, 0UL,      1 ); /* None, empty          */
  test_epoch_slots_bitvec_deserialize_case( 1U,       0UL, 0UL,      1 ); /* Some([]), empty      */
  test_epoch_slots_bitvec_deserialize_case( 0U,       0UL, 1UL,      0 ); /* None, over cap 0     */
  test_epoch_slots_bitvec_deserialize_case( 1U,       0UL, 1UL,      0 ); /* Some([]), over cap 0 */
  test_epoch_slots_bitvec_deserialize_case( 1U,       1UL, 7UL,      0 ); /* under capacity 8     */
  test_epoch_slots_bitvec_deserialize_case( 1U,       1UL, 8UL,      1 ); /* exact fit            */
  test_epoch_slots_bitvec_deserialize_case( 1U,       1UL, 9UL,      0 ); /* over capacity 8      */
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

static void
bench_insert( void ) {
  fd_rng_t _rng[1]; fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, 2U, 0UL ) );
  ulong keys[ 3 ] = { fd_rng_ulong( rng ), fd_rng_ulong( rng ), fd_rng_ulong( rng ) };
  static ulong bits[ 160 ];
  fd_bloom_t bloom[1] = {{ .keys = keys, .keys_len = 3UL, .bits = bits, .bits_len = 9000UL }};
  static uchar hash[ 4096 ][ 32 ];
  for( ulong i=0UL; i<4096UL; i++ ) for( ulong j=0UL; j<32UL; j++ ) hash[ i ][ j ] = fd_rng_uchar( rng );
  ulong iter = 10000000UL;
  long dt = -fd_log_wallclock();
  for( ulong i=0UL; i<iter; i++ ) fd_bloom_insert( bloom, hash[ i&4095UL ], 32UL );
  dt += fd_log_wallclock();
  FD_LOG_NOTICE(( "fd_bloom_insert(32 B, 3 keys) %.2f ns", (double)dt/(double)iter ));

  dt = -fd_log_wallclock();
  ulong acc = 0UL;
  for( ulong i=0UL; i<iter; i++ ) acc += (ulong)fd_bloom_contains( bloom, hash[ i&4095UL ], 32UL );
  dt += fd_log_wallclock();
  FD_LOG_NOTICE(( "fd_bloom_contains(32 B, 3 keys) %.2f ns (%lu)", (double)dt/(double)iter, acc ));

  dt = -fd_log_wallclock();
  for( ulong i=0UL; i<iter/8UL; i++ ) acc += (ulong)fd_bloom_contains8( bloom, hash[ (8UL*i)&4095UL ] );
  dt += fd_log_wallclock();
  FD_LOG_NOTICE(( "fd_bloom_contains8(32 B, 3 keys) %.2f ns/element (%lu)", (double)dt/(double)iter, acc ));

  ulong keys12[ 12 ][ 3 ];
  static ulong bits12[ 12 ][ 160 ];
  fd_bloom_t   bloom12[ 12 ];
  fd_bloom_t * blooms[ 12 ];
  for( ulong b=0UL; b<12UL; b++ ) {
    for( ulong k=0UL; k<3UL; k++ ) keys12[ b ][ k ] = fd_rng_ulong( rng );
    bloom12[ b ] = (fd_bloom_t){ .keys = keys12[ b ], .keys_len = 3UL, .bits = bits12[ b ], .bits_len = 9000UL };
    blooms[ b ] = &bloom12[ b ];
    for( ulong i=0UL; i<2048UL; i++ ) fd_bloom_insert( &bloom12[ b ], hash[ i ], 32UL );
  }
  dt = -fd_log_wallclock();
  for( ulong i=0UL; i<iter/12UL; i++ ) for( ulong b=0UL; b<12UL; b++ ) acc += (ulong)fd_bloom_contains( &bloom12[ b ], hash[ i&4095UL ], 32UL );
  dt += fd_log_wallclock();
  FD_LOG_NOTICE(( "12 x fd_bloom_contains(32 B, 3 keys) %.2f ns/value (%lu)", 12.0*(double)dt/(double)iter, acc ));
  dt = -fd_log_wallclock();
  for( ulong i=0UL; i<iter/12UL; i++ ) acc += (ulong)fd_bloom_contains_multi( blooms, 12UL, hash[ i&4095UL ], 32UL );
  dt += fd_log_wallclock();
  FD_LOG_NOTICE(( "fd_bloom_contains_multi(12 x 3 keys) %.2f ns/value (%lu)", 12.0*(double)dt/(double)iter, acc ));
  fd_rng_delete( fd_rng_leave( rng ) );
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );
  int bench = fd_env_strip_cmdline_contains( &argc, &argv, "--bench" );

  FD_TEST( fd_bloom_align()==FD_BLOOM_ALIGN );

  test_filters();
  test_fnv_reference();
  test_insert8();
  test_insert16();
  test_contains8();
  test_contains_multi();
  test_add_contains();
  test_empty_contains();
  test_pull_request_serialize_alignment();
  test_bitvec_deserialize();
  test_epoch_slots_bitvec_deserialize();
  test_keys_oob();
  if( bench ) bench_insert();

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
