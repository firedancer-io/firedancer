/* test_dragon_cuckoo checks the cuckoo filter port against reference
   vectors, most importantly the golden wire fixture that the Rust
   implementation's own test suite carries
   (yellowstone-grpc-proto/src/cuckoo/filter.rs).  The vectors in
   test_cuckoo_vectors.h come from gen_cuckoo_vectors.py, a
   transcription of that Rust source rather than a binding to it; the
   golden fixture is what ties the transcription to the real thing. */

#include "fd_dragon_cuckoo.h"
#include "test_cuckoo_vectors.h"
#include "../../util/fd_util.h"

#define BUCKET_MAX (65536UL)

static ushort bucket_mem[ BUCKET_MAX*FD_DRAGON_CUCKOO_ENTRIES_PER_BUCKET ];
static ushort bucket_mem2[ BUCKET_MAX*FD_DRAGON_CUCKOO_ENTRIES_PER_BUCKET ];
static uchar  encode_buf[ BUCKET_MAX*FD_DRAGON_CUCKOO_BUCKET_SZ ];

/* The bucket count for a capacity is the one the reference computes. */

static void
test_bucket_cnt( void ) {
  FD_TEST( fd_dragon_cuckoo_bucket_cnt(     0UL )==   1UL );
  FD_TEST( fd_dragon_cuckoo_bucket_cnt(     1UL )==   1UL );
  FD_TEST( fd_dragon_cuckoo_bucket_cnt(     4UL )==   2UL );
  FD_TEST( fd_dragon_cuckoo_bucket_cnt(     8UL )==   4UL );
  FD_TEST( fd_dragon_cuckoo_bucket_cnt(    32UL )==  16UL );
  FD_TEST( fd_dragon_cuckoo_bucket_cnt(   300UL )== 128UL );
  FD_TEST( fd_dragon_cuckoo_bucket_cnt(  1000UL )== 512UL );
  FD_TEST( fd_dragon_cuckoo_bucket_cnt( 10000UL )==4096UL );
  FD_TEST( fd_dragon_cuckoo_bucket_cnt( ULONG_MAX )==0UL );
  FD_TEST( fd_dragon_cuckoo_bucket_cnt( ULONG_MAX-1UL )==0UL );

  /* Every count is a power of two that holds the capacity */
  for( ulong cap=1UL; cap<=100000UL; cap = cap*3UL/2UL + 1UL ) {
    ulong cnt = fd_dragon_cuckoo_bucket_cnt( cap );
    FD_TEST( cnt && fd_ulong_is_pow2( cnt ) );
    FD_TEST( cnt*FD_DRAGON_CUCKOO_ENTRIES_PER_BUCKET>=cap );
  }
  FD_LOG_NOTICE(( "test_bucket_cnt: ok" ));
}

/* SipHash-2-4 against the vectors of the reference implementation
   (github.com/veorq/SipHash vectors_sip64.h), with the key
   000102...0f as specified there. */

static void
test_siphash24( void ) {
  static ulong const expect[ 8 ] = {
    0x726fdb47dd0e0e31UL, 0x74f839c593dc67fdUL, 0x0d6c8009d9a94f5aUL, 0x85676696d7fb7e2dUL,
    0xcf2794e0277187b7UL, 0x18765564cd99a68dUL, 0xcbc9466e58fee3ceUL, 0xab0200f58b01d137UL
  };
  uchar in[ 8 ];
  ulong k0 = 0x0706050403020100UL;
  ulong k1 = 0x0f0e0d0c0b0a0908UL;
  for( ulong i=0UL; i<8UL; i++ ) {
    in[ i ] = (uchar)i;
    FD_TEST( fd_dragon_cuckoo_siphash24( in, i, k0, k1 )==expect[ i ] );
  }
  FD_LOG_NOTICE(( "test_siphash24: ok" ));
}

/* The golden wire fixture: inserting 47 keys of 32 equal bytes into a
   filter built for capacity 32 with the fixture's seed has to produce
   the exact 128 bytes the Rust test asserts on, and the filter has to
   answer the fixture's membership and removal questions the same way. */

static void
test_golden( void ) {
  ulong bucket_cnt = fd_dragon_cuckoo_bucket_cnt( CUCKOO_GOLDEN_CAPACITY );
  FD_TEST( bucket_cnt==16UL );
  FD_TEST( fd_dragon_cuckoo_data_sz( bucket_cnt )==sizeof(cuckoo_golden_data) );

  fd_dragon_cuckoo_t f[1];
  fd_dragon_cuckoo_init( f, CUCKOO_GOLDEN_SEED, bucket_mem, bucket_cnt );
  for( ulong b=0UL; b<CUCKOO_GOLDEN_KEY_CNT; b++ ) {
    uchar key[ 32 ];
    fd_memset( key, (int)b, 32UL );
    FD_TEST( fd_dragon_cuckoo_insert( f, key, 32UL ) );
  }
  fd_dragon_cuckoo_encode( f, encode_buf );
  FD_TEST( !memcmp( encode_buf, cuckoo_golden_data, sizeof(cuckoo_golden_data) ) );

  /* The same bytes off the wire answer the same questions */
  fd_dragon_cuckoo_t g[1];
  fd_dragon_cuckoo_decode( g, CUCKOO_GOLDEN_SEED, cuckoo_golden_data,
                           sizeof(cuckoo_golden_data), bucket_mem2 );
  FD_TEST( g->bucket_cnt==16UL );
  for( ulong b=0UL; b<CUCKOO_GOLDEN_KEY_CNT; b++ ) {
    uchar key[ 32 ];
    fd_memset( key, (int)b, 32UL );
    FD_TEST( fd_dragon_cuckoo_contains32( g, key ) );
  }
  uchar absent[ 32 ];
  fd_memset( absent, 0xff, 32UL );
  FD_TEST( !fd_dragon_cuckoo_contains32( g, absent ) );

  uchar relocated[ 32 ];
  fd_memset( relocated, 46, 32UL );
  FD_TEST(  fd_dragon_cuckoo_remove( g, relocated, 32UL ) );
  FD_TEST( !fd_dragon_cuckoo_contains32( g, relocated ) );
  for( ulong b=0UL; b<46UL; b++ ) {
    uchar key[ 32 ];
    fd_memset( key, (int)b, 32UL );
    FD_TEST( fd_dragon_cuckoo_contains32( g, key ) );
  }
  FD_LOG_NOTICE(( "test_golden: ok, 128 bytes byte-equal with the Rust fixture" ));
}

/* One generated case: the encoded filter has to be byte-equal, every
   member has to be found, and the probe list's false positives have to
   be exactly the ones the reference computed. */

static void
test_case( char const *  name,
           ulong         seed,
           ulong         bucket_cnt,
           uchar const * data,
           ulong         data_sz,
           uchar const   (* member)[ 32 ],
           ulong         member_cnt,
           uchar const   (* probe)[ 32 ],
           ulong         probe_cnt,
           uchar const * probe_hit ) {
  FD_TEST( bucket_cnt<=BUCKET_MAX );
  FD_TEST( fd_dragon_cuckoo_data_sz( bucket_cnt )==data_sz );

  fd_dragon_cuckoo_t f[1];
  fd_dragon_cuckoo_init( f, seed, bucket_mem, bucket_cnt );
  for( ulong i=0UL; i<member_cnt; i++ ) FD_TEST( fd_dragon_cuckoo_insert( f, member[ i ], 32UL ) );
  fd_dragon_cuckoo_encode( f, encode_buf );
  FD_TEST( !memcmp( encode_buf, data, data_sz ) );

  fd_dragon_cuckoo_t g[1];
  fd_dragon_cuckoo_decode( g, seed, data, data_sz, bucket_mem2 );
  FD_TEST( g->bucket_cnt==bucket_cnt );

  for( ulong i=0UL; i<member_cnt; i++ ) FD_TEST( fd_dragon_cuckoo_contains32( g, member[ i ] ) );

  ulong hit_cnt = 0UL;
  for( ulong i=0UL; i<probe_cnt; i++ ) {
    int want = !!( probe_hit[ i>>3 ] & ( 1<<( i & 7UL ) ) );
    FD_TEST( fd_dragon_cuckoo_contains32( g, probe[ i ] )==want );
    hit_cnt += (ulong)want;
  }
  FD_LOG_NOTICE(( "%s: ok, %lu members, %lu/%lu probes are false positives",
                  name, member_cnt, hit_cnt, probe_cnt ));
}

/* Malformed data fields cannot fault and cannot report a member. */

static void
test_malformed( void ) {
  static ulong const sizes[] = { 0UL, 1UL, 2UL, 3UL, 7UL, 8UL, 9UL, 15UL, 16UL, 23UL, 1023UL };
  uchar data[ 1024 ];
  for( ulong i=0UL; i<sizeof(data); i++ ) data[ i ] = (uchar)( i*7UL+1UL );

  for( ulong i=0UL; i<sizeof(sizes)/sizeof(ulong); i++ ) {
    fd_dragon_cuckoo_t f[1];
    fd_dragon_cuckoo_decode( f, FD_DRAGON_CUCKOO_DEFAULT_SEED, data, sizes[ i ], bucket_mem );
    FD_TEST( f->bucket_cnt>=1UL );
    FD_TEST( f->bucket_cnt==fd_dragon_cuckoo_wire_bucket_cnt( sizes[ i ] ) );
    for( ulong k=0UL; k<64UL; k++ ) {
      uchar key[ 32 ];
      fd_memset( key, (int)k, 32UL );
      (void)fd_dragon_cuckoo_contains32( f, key );
    }
  }

  /* An empty data field is one empty bucket and matches nothing */
  fd_dragon_cuckoo_t e[1];
  fd_dragon_cuckoo_decode( e, FD_DRAGON_CUCKOO_DEFAULT_SEED, NULL, 0UL, bucket_mem );
  FD_TEST( e->bucket_cnt==1UL );
  for( ulong k=0UL; k<256UL; k++ ) {
    uchar key[ 32 ];
    fd_memset( key, (int)k, 32UL );
    FD_TEST( !fd_dragon_cuckoo_contains32( e, key ) );
  }

  /* A bucket count that is not a power of two keeps every index in
     bounds: 3 buckets out of 24 bytes */
  fd_dragon_cuckoo_t o[1];
  fd_dragon_cuckoo_decode( o, FD_DRAGON_CUCKOO_DEFAULT_SEED, data, 24UL, bucket_mem );
  FD_TEST( o->bucket_cnt==3UL );
  for( ulong k=0UL; k<1024UL; k++ ) {
    uchar key[ 32 ];
    for( ulong j=0UL; j<32UL; j++ ) key[ j ] = (uchar)( k*31UL+j );
    (void)fd_dragon_cuckoo_contains32( o, key );
  }
  FD_LOG_NOTICE(( "test_malformed: ok" ));
}

/* A filter that runs out of room reports it rather than looping. */

static void
test_saturation( void ) {
  fd_dragon_cuckoo_t f[1];
  fd_dragon_cuckoo_init( f, FD_DRAGON_CUCKOO_DEFAULT_SEED, bucket_mem, 4UL );
  ulong ok = 0UL;
  int   full_seen = 0;
  for( ulong i=0UL; i<1000UL; i++ ) {
    uchar key[ 32 ];
    for( ulong j=0UL; j<32UL; j++ ) key[ j ] = (uchar)( i*131UL+j );
    if( fd_dragon_cuckoo_insert( f, key, 32UL ) ) ok++;
    else { full_seen = 1; break; }
  }
  FD_TEST( full_seen );
  FD_TEST( ok<=16UL );
  FD_LOG_NOTICE(( "test_saturation: ok, %lu inserts into 16 slots before full", ok ));
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  test_siphash24();
  test_bucket_cnt();
  test_golden();
  test_case( "cuckoo_small", CUCKOO_SMALL_SEED, CUCKOO_SMALL_BUCKET_CNT,
             cuckoo_small_data, sizeof(cuckoo_small_data),
             cuckoo_small_member, CUCKOO_SMALL_MEMBER_CNT,
             cuckoo_small_probe, CUCKOO_SMALL_PROBE_CNT, cuckoo_small_probe_hit );
  test_case( "cuckoo_mid", CUCKOO_MID_SEED, CUCKOO_MID_BUCKET_CNT,
             cuckoo_mid_data, sizeof(cuckoo_mid_data),
             cuckoo_mid_member, CUCKOO_MID_MEMBER_CNT,
             cuckoo_mid_probe, CUCKOO_MID_PROBE_CNT, cuckoo_mid_probe_hit );
  test_case( "cuckoo_seeded", CUCKOO_SEEDED_SEED, CUCKOO_SEEDED_BUCKET_CNT,
             cuckoo_seeded_data, sizeof(cuckoo_seeded_data),
             cuckoo_seeded_member, CUCKOO_SEEDED_MEMBER_CNT,
             cuckoo_seeded_probe, CUCKOO_SEEDED_PROBE_CNT, cuckoo_seeded_probe_hit );
  test_malformed();
  test_saturation();

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
