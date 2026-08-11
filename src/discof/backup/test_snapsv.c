#define FD_TILE_TEST 1
#include "fd_snapsv_tile.c"
#include "../../util/tmpl/fd_unit_test.c"

/* Snapshot map sized small on purpose, so that collisions and probe
   sequence repairs are common. */

#define TEST_ELE_MAX (16UL)
#define TEST_SNAP_MAX (12UL)

static snap_entry_t test_map_ele[ TEST_ELE_MAX ];

static fd_snapsv_t test_ctx[1];

/* ctx_reset rebuilds the tile state with an empty snapshot map. */

static void
ctx_reset( ulong seed ) {
  memset( test_ctx, 0, sizeof(fd_snapsv_t) );
  for( ulong i=0UL; i<TEST_ELE_MAX; i++ ) {
    test_map_ele[ i ].key = (snap_key_t){ ULONG_MAX, ULONG_MAX };
  }
  FD_TEST( snap_map_join( test_ctx->snap_map, test_map_ele, TEST_ELE_MAX, TEST_ELE_MAX, seed ) );
  test_ctx->snap_max = TEST_SNAP_MAX;
}

/* test_hash is a deterministic snapshot hash derived from n. */

static uchar const *
test_hash( ulong n ) {
  static uchar hash[ 32 ];
  memset( hash, 0, sizeof(hash) );
  hash[ 0 ] = (uchar)  n;
  hash[ 1 ] = (uchar)( n>>8 );
  hash[ 2 ] = 0x5a;
  return hash;
}

/* snap_name writes the canonical archive filename of a snapshot into a
   static buffer.  base_slot is ULONG_MAX for full snapshots. */

static char const *
snap_name( ulong slot,
           ulong base_slot,
           ulong hash_n,
           int   is_zstd ) {
  static char name[ FD_SNAP_NAME_MAX ];
  char hash_b58[ FD_BASE58_ENCODED_32_SZ ];
  fd_base58_encode_32( test_hash( hash_n ), NULL, hash_b58 );
  if( base_slot==ULONG_MAX ) {
    FD_TEST( fd_cstr_printf_check( name, sizeof(name), NULL, "snapshot-%lu-%s.%s",
                                   slot, hash_b58, is_zstd ? "tar.zst" : "tar" ) );
  } else {
    FD_TEST( fd_cstr_printf_check( name, sizeof(name), NULL, "incremental-snapshot-%lu-%lu-%s.%s",
                                   base_slot, slot, hash_b58, is_zstd ? "tar.zst" : "tar" ) );
  }
  return name;
}

/* Range header parsing ***********************************************/

/* range_of runs parse_range_header over the NUL terminated header
   value.  The NUL is not passed to the parser, which operates on
   non-terminated header slices. */

static int
range_of( char const * value,
          ulong        object_sz,
          ulong *      range0,
          ulong *      range1 ) {
  *range0 = 0xdeadbeefUL;
  *range1 = 0xdeadbeefUL;
  return parse_range_header( value, strlen( value ), object_sz, range0, range1 );
}

/* RANGE_OK asserts that value over an object_sz sized object yields the
   half open range [r0,r1).  RANGE_ERR asserts a malformed value (400)
   and RANGE_UNSAT an unsatisfiable one (416).  Both must leave the
   outputs alone as far as the caller is concerned. */

#define RANGE_OK(value,object_sz,r0,r1) do {                                \
    ulong _a, _b;                                                           \
    FD_TEST( 0==range_of( (value), (object_sz), &_a, &_b ) );               \
    if( FD_UNLIKELY( _a!=(r0) || _b!=(r1) ) ) {                             \
      FD_LOG_ERR(( "FAIL: '%s'/%lu gave [%lu,%lu), expected [%lu,%lu)",     \
                   (value), (ulong)(object_sz), _a, _b,                     \
                   (ulong)(r0), (ulong)(r1) ));                             \
    }                                                                       \
  } while(0)

#define RANGE_ERR(value,object_sz) do {                                     \
    ulong _a, _b;                                                           \
    int _err = range_of( (value), (object_sz), &_a, &_b );                  \
    if( FD_UNLIKELY( _err!=-1 ) ) {                                         \
      FD_LOG_ERR(( "FAIL: '%s'/%lu gave %i, expected -1",                   \
                   (value), (ulong)(object_sz), _err ));                    \
    }                                                                       \
  } while(0)

#define RANGE_UNSAT(value,object_sz) do {                                   \
    ulong _a, _b;                                                           \
    int _err = range_of( (value), (object_sz), &_a, &_b );                  \
    if( FD_UNLIKELY( _err!=-2 ) ) {                                         \
      FD_LOG_ERR(( "FAIL: '%s'/%lu gave %i, expected -2",                   \
                   (value), (ulong)(object_sz), _err ));                    \
    }                                                                       \
  } while(0)

FD_UNIT_TEST( test_parse_range_header ) {

  /* basic int-int form.  Note the HTTP range is inclusive on both ends
     while the parser returns a half-open range. */

  RANGE_OK( "bytes=0-99",   1000UL, 0UL,  100UL );
  RANGE_OK( "bytes=0-0",    1000UL, 0UL,    1UL );
  RANGE_OK( "bytes=0-0",       1UL, 0UL,    1UL );
  RANGE_OK( "bytes=1-1",    1000UL, 1UL,    2UL );
  RANGE_OK( "bytes=10-20",  1000UL, 10UL,  21UL );
  RANGE_OK( "bytes=999-999",1000UL, 999UL,1000UL );

  /* open ended form */

  RANGE_OK( "bytes=100-",   1000UL, 100UL,1000UL );
  RANGE_OK( "bytes=0-",     1000UL, 0UL,  1000UL );
  RANGE_OK( "bytes=999-",   1000UL, 999UL,1000UL );

  /* suffix form: last N bytes */

  RANGE_OK( "bytes=-500",   1000UL, 500UL,1000UL );
  RANGE_OK( "bytes=-1",     1000UL, 999UL,1000UL );
  RANGE_OK( "bytes=-1000",  1000UL, 0UL,  1000UL );
  RANGE_OK( "bytes=-1001",  1000UL, 0UL,  1000UL ); /* clamped to whole object */

  /* clamping of the last byte position.  last>=object_sz-1 must clamp
     range1 to object_sz rather than run past the end. */

  RANGE_OK( "bytes=0-998",  1000UL, 0UL,  999UL );
  RANGE_OK( "bytes=0-999",  1000UL, 0UL, 1000UL );
  RANGE_OK( "bytes=0-1000", 1000UL, 0UL, 1000UL );
  RANGE_OK( "bytes=0-18446744073709551615", 1000UL, 0UL, 1000UL );

  /* leading and trailing whitespace is stripped */

  RANGE_OK( " bytes=0-99",     1000UL, 0UL, 100UL );
  RANGE_OK( "\tbytes=0-99",    1000UL, 0UL, 100UL );
  RANGE_OK( "bytes=0-99 ",     1000UL, 0UL, 100UL );
  RANGE_OK( "bytes=0-99\t",    1000UL, 0UL, 100UL );
  RANGE_OK( "  \t bytes=0-99 \t ", 1000UL, 0UL, 100UL );

  /* the unit is matched case insensitively */

  RANGE_OK( "BYTES=0-99", 1000UL, 0UL, 100UL );
  RANGE_OK( "ByTeS=0-99", 1000UL, 0UL, 100UL );

  /* malformed values */

  RANGE_ERR( "",                1000UL );
  RANGE_ERR( "   ",             1000UL );
  RANGE_ERR( "bytes=",          1000UL ); /* too short, no range at all */
  RANGE_ERR( "bytes=-",         1000UL ); /* neither first nor last */
  RANGE_ERR( "bytes=0",         1000UL ); /* missing '-' */
  RANGE_ERR( "bytes=0 99",      1000UL );
  RANGE_ERR( "bytes=abc",       1000UL );
  RANGE_ERR( "bytes=0-99x",     1000UL ); /* trailing garbage */
  RANGE_ERR( "bytes=0-99,200-", 1000UL ); /* multi-range unsupported */
  RANGE_ERR( "bytes=x0-99",     1000UL );
  RANGE_ERR( "bytes= 0-99",     1000UL ); /* interior whitespace */
  RANGE_ERR( "bytes=0 -99",     1000UL );
  RANGE_ERR( "bytes=0- 99",     1000UL );
  RANGE_ERR( "items=0-99",      1000UL ); /* wrong unit */
  RANGE_ERR( "byte=0-99",       1000UL );
  RANGE_ERR( "bytes 0-99",      1000UL ); /* missing '=' */
  RANGE_ERR( "0-99",            1000UL );

  /* integer overflow guards.  21 digits overflows a ulong. */

  RANGE_ERR( "bytes=99999999999999999999-",  1000UL );
  RANGE_ERR( "bytes=-99999999999999999999",  1000UL );
  RANGE_ERR( "bytes=0-99999999999999999999", 1000UL );
  RANGE_ERR( "bytes=18446744073709551616-",  1000UL );
  RANGE_ERR( "bytes=0-18446744073709551616", 1000UL );
  /* leading zeros do not trip the guard */
  RANGE_OK( "bytes=00000000000000000000000000001-1", 1000UL, 1UL, 2UL );

  /* ULONG_MAX itself does not overflow */
  RANGE_UNSAT( "bytes=18446744073709551615-", 1000UL );

  /* unsatisfiable ranges */

  RANGE_UNSAT( "bytes=1000-",     1000UL ); /* first==object_sz */
  RANGE_UNSAT( "bytes=1000-2000", 1000UL );
  RANGE_UNSAT( "bytes=1001-",     1000UL ); /* first>object_sz */
  RANGE_UNSAT( "bytes=20-10",     1000UL ); /* last<first */
  RANGE_UNSAT( "bytes=1-0",       1000UL );
  RANGE_UNSAT( "bytes=-0",        1000UL ); /* zero length suffix */
  RANGE_UNSAT( "bytes=0-99",         0UL ); /* empty object */
  RANGE_UNSAT( "bytes=0-",           0UL );
  RANGE_UNSAT( "bytes=-1",           0UL );
  RANGE_UNSAT( "bytes=0-0",          0UL );

  /* a malformed value beats an unsatisfiable one */
  RANGE_ERR( "bytes=junk", 0UL );
}

#undef RANGE_OK
#undef RANGE_ERR
#undef RANGE_UNSAT

/* Request path matching **********************************************/

/* path_matches parses path and checks the resulting key, hash and zstd
   flag.  Returns 1 if the path parsed, 0 if it did not. */

static int
path_matches( char const * path,
              ulong        slot,
              ulong        base_slot,
              uchar const  want_hash[ static 32 ],
              int          is_zstd ) {
  snap_key_t key;
  uchar      hash[ 32 ];
  int        zstd = -1;
  if( !match_snapshot_path( path, strlen( path ), &key, hash, &zstd ) ) return 0;
  FD_TEST( key.slot     ==slot      );
  FD_TEST( key.base_slot==base_slot );
  FD_TEST( 0==memcmp( hash, want_hash, 32UL ) );
  FD_TEST( zstd==is_zstd );
  return 1;
}

/* path_rejected returns 1 if match_snapshot_path refuses path. */

static int
path_rejected( char const * path,
               ulong        path_len ) {
  snap_key_t key;
  uchar      hash[ 32 ];
  int        zstd;
  return !match_snapshot_path( path, path_len, &key, hash, &zstd );
}

FD_UNIT_TEST( test_match_snapshot_path ) {

  uchar zero_hash[ 32 ];
  memset( zero_hash, 0, sizeof(zero_hash) );

  /* full snapshots get base_slot==ULONG_MAX */

  FD_TEST( path_matches( snap_name( 1000UL, ULONG_MAX, 7UL, 1 ), 1000UL, ULONG_MAX, test_hash( 7UL ), 1 ) );
  FD_TEST( path_matches( snap_name( 1000UL, ULONG_MAX, 7UL, 0 ), 1000UL, ULONG_MAX, test_hash( 7UL ), 0 ) );
  FD_TEST( path_matches( snap_name( 0UL,    ULONG_MAX, 0UL, 1 ), 0UL,    ULONG_MAX, test_hash( 0UL ), 1 ) );

  /* incremental snapshots swap the slots: the incremental slot lands in
     .slot and the full slot it is based on in .base_slot */

  FD_TEST( path_matches( snap_name( 2000UL, 1000UL, 9UL, 1 ), 2000UL, 1000UL, test_hash( 9UL ), 1 ) );
  FD_TEST( path_matches( snap_name( 2000UL, 1000UL, 9UL, 0 ), 2000UL, 1000UL, test_hash( 9UL ), 0 ) );

  /* spot check the literal wire form so that a change in the archive
     naming scheme is noticed here.  32 base58 '1's decode to the
     all-zero hash. */

  FD_TEST( path_matches( "snapshot-100-11111111111111111111111111111111.tar.zst",
                         100UL, ULONG_MAX, zero_hash, 1 ) );
  FD_TEST( path_matches( "incremental-snapshot-100-200-11111111111111111111111111111111.tar",
                         200UL, 100UL, zero_hash, 0 ) );

  /* too short: the length floor rejects before anything else */

  FD_TEST( path_rejected( "",          0UL ) );
  FD_TEST( path_rejected( "snapshot",  8UL ) );
  FD_TEST( path_rejected( "snapshot-", 9UL ) ); /* long enough, still invalid */

  /* buffer bound: paths of FD_SNAP_NAME_MAX-1 bytes or longer are
     rejected rather than truncated */

  static char long_path[ 2UL*FD_SNAP_NAME_MAX ];
  memset( long_path, 'a', sizeof(long_path) );
  FD_TEST( !path_rejected( snap_name( 1000UL, ULONG_MAX, 7UL, 1 ), strlen( snap_name( 1000UL, ULONG_MAX, 7UL, 1 ) ) ) );
  FD_TEST(  path_rejected( long_path, FD_SNAP_NAME_MAX-1UL ) );
  FD_TEST(  path_rejected( long_path, FD_SNAP_NAME_MAX     ) );
  FD_TEST(  path_rejected( long_path, sizeof(long_path)    ) );

  /* a valid name padded out to exactly the bound is rejected too */
  {
    char const * ok = snap_name( 1000UL, ULONG_MAX, 7UL, 1 );
    static char padded[ FD_SNAP_NAME_MAX ];
    memset( padded, 'x', sizeof(padded) );
    memcpy( padded, ok, strlen( ok ) );
    FD_TEST( path_rejected( padded, FD_SNAP_NAME_MAX-1UL ) );
  }

  /* garbage and near misses */

  FD_TEST( path_rejected( "not-a-snapshot-at-all",  21UL ) );
  FD_TEST( path_rejected( "snapshot-abc-1111111111111111111111111111111.tar", 48UL ) );
  FD_TEST( path_rejected( "snapshot-100-11111111111111111111111111111111.tar.gz",  52UL ) );
  FD_TEST( path_rejected( "snapshot-100-11111111111111111111111111111111",         45UL ) );
  FD_TEST( path_rejected( "snapshot-100-!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!.tar",      49UL ) );
  FD_TEST( path_rejected( "incremental-snapshot-100-11111111111111111111111111111111.tar", 61UL ) );
  FD_TEST( path_rejected( "/snapshot-100-11111111111111111111111111111111.tar",    50UL ) ); /* leading slash not stripped here */
  FD_TEST( path_rejected( "SNAPSHOT-100-11111111111111111111111111111111.tar",     49UL ) ); /* case sensitive */

  /* an embedded NUL truncates the copy, which must not parse into a
     valid name */
  FD_TEST( path_rejected( "snapshot\0-100-11111111111111111111111111111111.tar", 50UL ) );
}

/* Snapshot map *******************************************************/

/* map_bucket returns the home slot index of key. */

static ulong
map_bucket( snap_key_t const * key ) {
  return snap_key_hash( key, snap_map_seed( test_ctx->snap_map ) ) & (TEST_ELE_MAX-1UL);
}

/* map_put inserts key with the given size marker. */

static snap_entry_t *
map_put( snap_key_t key,
         ulong      sz ) {
  snap_entry_t * ele = snap_map_insert( test_ctx->snap_map, &key );
  FD_TEST( ele );
  ele->sz      = sz;
  ele->fd      = -1;
  ele->locked  = 0;
  ele->is_zstd = 0;
  memset( ele->hash, 0, sizeof(ele->hash) );
  return ele;
}

FD_UNIT_TEST( test_snap_map ) {
  ctx_reset( 0x5eedUL );

  /* a fresh map is entirely free and finds nothing */

  for( ulong i=0UL; i<TEST_ELE_MAX; i++ ) FD_TEST( snap_map_ele_is_free( &test_map_ele[ i ] ) );
  FD_TEST( !snap_map_query( test_ctx->snap_map, &(snap_key_t){ 1UL, ULONG_MAX } ) );
  FD_TEST( 0==snap_map_verify( test_ctx->snap_map ) );

  /* the free sentinel is exactly {ULONG_MAX,ULONG_MAX}; neither half
     alone marks a slot free */

  FD_TEST(  snap_map_ele_is_free( &(snap_entry_t){ .key = { ULONG_MAX, ULONG_MAX } } ) );
  FD_TEST( !snap_map_ele_is_free( &(snap_entry_t){ .key = { 0UL,       ULONG_MAX } } ) );
  FD_TEST( !snap_map_ele_is_free( &(snap_entry_t){ .key = { ULONG_MAX, 0UL       } } ) );
  FD_TEST( !snap_map_ele_is_free( &(snap_entry_t){ .key = { 0UL,       0UL       } } ) );

  /* slot and base_slot are distinct key components */

  FD_TEST(  snap_map_key_eq( &(snap_key_t){ 5UL, 7UL }, &(snap_key_t){ 5UL, 7UL } ) );
  FD_TEST( !snap_map_key_eq( &(snap_key_t){ 5UL, 7UL }, &(snap_key_t){ 7UL, 5UL } ) );
  FD_TEST( !snap_map_key_eq( &(snap_key_t){ 5UL, 7UL }, &(snap_key_t){ 5UL, 8UL } ) );
  FD_TEST( !snap_map_key_eq( &(snap_key_t){ 5UL, 7UL }, &(snap_key_t){ 6UL, 7UL } ) );

  /* ... and the hash mixes both of them */

  ulong seed = snap_map_seed( test_ctx->snap_map );
  FD_TEST( snap_key_hash( &(snap_key_t){ 5UL, 7UL }, seed )!=
           snap_key_hash( &(snap_key_t){ 7UL, 5UL }, seed ) );
  FD_TEST( snap_key_hash( &(snap_key_t){ 5UL, 7UL }, seed )!=
           snap_key_hash( &(snap_key_t){ 5UL, 8UL }, seed ) );
  FD_TEST( snap_key_hash( &(snap_key_t){ 5UL, 7UL }, 0UL  )!=
           snap_key_hash( &(snap_key_t){ 5UL, 7UL }, 1UL  ) ); /* seeded */

  /* a full and an incremental snapshot that share a slot number are
     different keys and coexist */

  snap_key_t full = { 1000UL, ULONG_MAX };
  snap_key_t incr = { 1000UL, 900UL     };
  map_put( full, 111UL );
  map_put( incr, 222UL );
  FD_TEST( snap_map_query( test_ctx->snap_map, &full )->sz==111UL );
  FD_TEST( snap_map_query( test_ctx->snap_map, &incr )->sz==222UL );
  FD_TEST( 0==snap_map_verify( test_ctx->snap_map ) );

  /* duplicate insert fails */
  FD_TEST( !snap_map_insert( test_ctx->snap_map, &full ) );

  /* remove one, the other survives */
  snap_map_remove( test_ctx->snap_map, snap_map_update( test_ctx->snap_map, &full ) );
  FD_TEST( !snap_map_query( test_ctx->snap_map, &full ) );
  FD_TEST(  snap_map_query( test_ctx->snap_map, &incr )->sz==222UL );
  FD_TEST( 0==snap_map_verify( test_ctx->snap_map ) );

  /* Colliding keys.  Find three keys that share a home slot, then
     remove the first one and check that the other two are still
     reachable.  This is the classic backshift-removal bug: without a
     correct MAP_ELE_MOVE the tail of the probe sequence is orphaned. */

  ctx_reset( 0x5eedUL );
  snap_key_t collide[ 3 ];
  ulong      collide_cnt = 0UL;
  ulong      home        = map_bucket( &(snap_key_t){ 1UL, ULONG_MAX } );
  for( ulong slot=1UL; slot<1000000UL && collide_cnt<3UL; slot++ ) {
    snap_key_t key = { slot, ULONG_MAX };
    if( map_bucket( &key )!=home ) continue;
    collide[ collide_cnt++ ] = key;
  }
  FD_TEST( collide_cnt==3UL );

  for( ulong i=0UL; i<3UL; i++ ) map_put( collide[ i ], 1000UL+i );
  FD_TEST( 0==snap_map_verify( test_ctx->snap_map ) );
  /* they really did collide: consecutive slots starting at home */
  FD_TEST( (ulong)( snap_map_query( test_ctx->snap_map, &collide[ 0 ] ) - test_map_ele )==home );

  for( ulong i=0UL; i<3UL; i++ ) FD_TEST( snap_map_query( test_ctx->snap_map, &collide[ i ] )->sz==1000UL+i );
  snap_map_remove( test_ctx->snap_map, snap_map_update( test_ctx->snap_map, &collide[ 0 ] ) );
  FD_TEST( !snap_map_query( test_ctx->snap_map, &collide[ 0 ] ) );
  FD_TEST(  snap_map_query( test_ctx->snap_map, &collide[ 1 ] )->sz==1001UL );
  FD_TEST(  snap_map_query( test_ctx->snap_map, &collide[ 2 ] )->sz==1002UL );
  FD_TEST( 0==snap_map_verify( test_ctx->snap_map ) );
  /* the survivor got backshifted into the hole */
  FD_TEST( (ulong)( snap_map_query( test_ctx->snap_map, &collide[ 1 ] ) - test_map_ele )==home );

  /* remove the middle of what is left */
  snap_map_remove( test_ctx->snap_map, snap_map_update( test_ctx->snap_map, &collide[ 1 ] ) );
  FD_TEST( !snap_map_query( test_ctx->snap_map, &collide[ 1 ] ) );
  FD_TEST(  snap_map_query( test_ctx->snap_map, &collide[ 2 ] )->sz==1002UL );
  snap_map_remove( test_ctx->snap_map, snap_map_update( test_ctx->snap_map, &collide[ 2 ] ) );
  for( ulong i=0UL; i<TEST_ELE_MAX; i++ ) FD_TEST( snap_map_ele_is_free( &test_map_ele[ i ] ) );

  /* Randomized insert/remove churn against a reference model.  Keeps
     the map near capacity so probe sequences stay long. */

  fd_rng_t _rng[1]; fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, 0x51ce, 0UL ) );
  for( ulong trial=0UL; trial<64UL; trial++ ) {
    ctx_reset( fd_rng_ulong( rng ) );

    /* model: which of the 24 candidate keys are live */
    ulong const cand_cnt = 24UL;
    int  live[ 24 ] = {0};
    ulong live_cnt  = 0UL;

    for( ulong step=0UL; step<512UL; step++ ) {
      ulong      i   = fd_rng_ulong_roll( rng, cand_cnt );
      snap_key_t key = { i>>1, (i&1UL) ? ULONG_MAX : 1UL+(i>>1) };

      if( live[ i ] ) {
        snap_entry_t * ele = snap_map_update( test_ctx->snap_map, &key );
        FD_TEST( ele && ele->sz==0xf00UL+i );
        snap_map_remove( test_ctx->snap_map, ele );
        live[ i ] = 0; live_cnt--;
      } else if( live_cnt<TEST_ELE_MAX/2UL ) {
        map_put( key, 0xf00UL+i );
        live[ i ] = 1; live_cnt++;
      }

      /* every live key must still be reachable, every dead key must
         not be found */
      for( ulong j=0UL; j<cand_cnt; j++ ) {
        snap_key_t k = { j>>1, (j&1UL) ? ULONG_MAX : 1UL+(j>>1) };
        snap_entry_t const * ele = snap_map_query( test_ctx->snap_map, &k );
        if( live[ j ] ) FD_TEST( ele && ele->sz==0xf00UL+j );
        else            FD_TEST( !ele );
      }
      FD_TEST( 0==snap_map_verify( test_ctx->snap_map ) );
    }
  }
  fd_rng_delete( fd_rng_leave( rng ) );
}

/* Snapshot open/close bookkeeping and the newest snapshot cache *******/

/* open_snap adds a snapshot through the same entry point the snapmk
   tile uses.  Entries are left unlocked, so snap_close never issues an
   fcntl and no real file descriptor is needed. */

static void
open_snap( ulong slot,
           ulong base_slot,
           ulong pool_idx,
           ulong sz,
           ulong hash_n,
           int   is_zstd ) {
  snap_open( test_ctx, slot, base_slot, pool_idx, sz, snap_name( slot, base_slot, hash_n, is_zstd ) );
}

FD_UNIT_TEST( test_snap_open_close ) {
  ctx_reset( 0xabcdUL );

  FD_TEST( test_ctx->snap_cnt_full==0UL );
  FD_TEST( test_ctx->snap_cnt_incr==0UL );

  open_snap( 100UL, ULONG_MAX, 0UL, 4096UL, 1UL, 1 );
  FD_TEST( test_ctx->snap_cnt_full==1UL );
  FD_TEST( test_ctx->snap_cnt_incr==0UL );

  /* snap_open fills in everything the response path needs */
  snap_entry_t const * e = snap_map_query( test_ctx->snap_map, &(snap_key_t){ 100UL, ULONG_MAX } );
  FD_TEST( e );
  FD_TEST( e->sz     ==4096UL           );
  FD_TEST( e->fd     ==FD_SNAP_RO_FD(0) );
  FD_TEST( e->locked ==0                );
  FD_TEST( e->is_zstd==1                );
  FD_TEST( 0==memcmp( e->hash, test_hash( 1UL ), 32UL ) );

  /* an uncompressed snapshot */
  open_snap( 200UL, ULONG_MAX, 1UL, 8192UL, 2UL, 0 );
  FD_TEST( test_ctx->snap_cnt_full==2UL );
  FD_TEST( snap_map_query( test_ctx->snap_map, &(snap_key_t){ 200UL, ULONG_MAX } )->is_zstd==0 );

  /* incrementals count separately */
  open_snap( 250UL, 200UL, 2UL, 512UL, 3UL, 1 );
  open_snap( 260UL, 200UL, 3UL, 512UL, 4UL, 1 );
  FD_TEST( test_ctx->snap_cnt_full==2UL );
  FD_TEST( test_ctx->snap_cnt_incr==2UL );

  /* closing decrements the matching counter only */
  snap_close( test_ctx, 250UL, 200UL );
  FD_TEST( test_ctx->snap_cnt_full==2UL );
  FD_TEST( test_ctx->snap_cnt_incr==1UL );
  FD_TEST( !snap_map_query( test_ctx->snap_map, &(snap_key_t){ 250UL, 200UL } ) );

  /* closing an unknown snapshot is a no-op, not an underflow */
  snap_close( test_ctx, 250UL, 200UL );
  snap_close( test_ctx, 999UL, ULONG_MAX );
  snap_close( test_ctx, 100UL, 42UL ); /* right slot, wrong base */
  FD_TEST( test_ctx->snap_cnt_full==2UL );
  FD_TEST( test_ctx->snap_cnt_incr==1UL );

  snap_close( test_ctx, 100UL, ULONG_MAX );
  snap_close( test_ctx, 200UL, ULONG_MAX );
  snap_close( test_ctx, 260UL, 200UL );
  FD_TEST( test_ctx->snap_cnt_full==0UL );
  FD_TEST( test_ctx->snap_cnt_incr==0UL );
  for( ulong i=0UL; i<TEST_ELE_MAX; i++ ) FD_TEST( snap_map_ele_is_free( &test_map_ele[ i ] ) );
}

FD_UNIT_TEST( test_newest_snap ) {
  ctx_reset( 0xf00dUL );

  /* nothing available */
  FD_TEST( !newest_snap( test_ctx, 0 ) );
  FD_TEST( !newest_snap( test_ctx, 1 ) );

  /* one full snapshot; incremental still unavailable */
  open_snap( 100UL, ULONG_MAX, 0UL, 1UL, 1UL, 1 );
  FD_TEST( newest_snap( test_ctx, 0 )->key.slot==100UL );
  FD_TEST( !newest_snap( test_ctx, 1 ) );

  /* insertion order must not matter: an older snapshot does not win */
  open_snap( 50UL, ULONG_MAX, 1UL, 1UL, 2UL, 1 );
  FD_TEST( newest_snap( test_ctx, 0 )->key.slot==100UL );

  /* ... and a newer one takes over, invalidating the memoized answer */
  open_snap( 300UL, ULONG_MAX, 2UL, 1UL, 3UL, 1 );
  FD_TEST( newest_snap( test_ctx, 0 )->key.slot==300UL );
  FD_TEST( newest_snap( test_ctx, 0 )->key.slot==300UL ); /* served from cache */

  /* incrementals are tracked independently of fulls */
  open_snap( 310UL, 300UL, 3UL, 1UL, 4UL, 1 );
  open_snap( 320UL, 300UL, 4UL, 1UL, 5UL, 1 );
  open_snap( 305UL, 100UL, 5UL, 1UL, 6UL, 1 );
  FD_TEST( newest_snap( test_ctx, 0 )->key.slot==300UL );
  FD_TEST( newest_snap( test_ctx, 1 )->key.slot==320UL );
  FD_TEST( newest_snap( test_ctx, 1 )->key.base_slot==300UL );

  /* adding a full snapshot must not disturb the incremental answer */
  open_snap( 400UL, ULONG_MAX, 6UL, 1UL, 7UL, 1 );
  FD_TEST( newest_snap( test_ctx, 1 )->key.slot==320UL );
  FD_TEST( newest_snap( test_ctx, 0 )->key.slot==400UL );

  /* removing the newest falls back to the runner up */
  snap_close( test_ctx, 400UL, ULONG_MAX );
  FD_TEST( newest_snap( test_ctx, 0 )->key.slot==300UL );
  FD_TEST( newest_snap( test_ctx, 1 )->key.slot==320UL );
  snap_close( test_ctx, 320UL, 300UL );
  FD_TEST( newest_snap( test_ctx, 1 )->key.slot==310UL );
  FD_TEST( newest_snap( test_ctx, 0 )->key.slot==300UL );

  /* removing a non-newest snapshot keeps the answer stable */
  snap_close( test_ctx, 50UL, ULONG_MAX );
  FD_TEST( newest_snap( test_ctx, 0 )->key.slot==300UL );

  /* drain the incrementals; the full answer must be unaffected */
  snap_close( test_ctx, 310UL, 300UL );
  snap_close( test_ctx, 305UL, 100UL );
  FD_TEST( !newest_snap( test_ctx, 1 ) );
  FD_TEST( newest_snap( test_ctx, 0 )->key.slot==300UL );

  /* drain the fulls */
  snap_close( test_ctx, 300UL, ULONG_MAX );
  FD_TEST( newest_snap( test_ctx, 0 )->key.slot==100UL );
  snap_close( test_ctx, 100UL, ULONG_MAX );
  FD_TEST( !newest_snap( test_ctx, 0 ) );
  FD_TEST( !newest_snap( test_ctx, 1 ) );

  /* the returned entry is the live map slot, not a copy */
  ctx_reset( 0xf00dUL );
  open_snap( 700UL, ULONG_MAX, 0UL, 1234UL, 8UL, 0 );
  snap_entry_t * live = newest_snap( test_ctx, 0 );
  FD_TEST( live==snap_map_query( test_ctx->snap_map, &(snap_key_t){ 700UL, ULONG_MAX } ) );
  FD_TEST( live->sz==1234UL );
}

/* Response header generation *****************************************/

/* HDR_EQ asserts that a header builder produced exactly want. */

#define HDR_EQ(got_len,want) do {                                           \
    ulong _len  = (got_len);                                                \
    char const * _want = (want);                                            \
    if( FD_UNLIKELY( _len!=strlen( _want ) ||                               \
                     memcmp( hdr, _want, _len ) ) ) {                       \
      FD_LOG_ERR(( "FAIL: got (%lu)\n%.*s\nexpected (%lu)\n%s",             \
                   _len, (int)_len, hdr, strlen( _want ), _want ));         \
    }                                                                       \
    FD_TEST( _len<RES_HDR_MAX );                                            \
  } while(0)

FD_UNIT_TEST( test_build_err_hdr ) {
  char hdr[ RES_HDR_MAX ];

  HDR_EQ( build_err_hdr( hdr, 400U, ULONG_MAX, 0 ),
          "HTTP/1.1 400 Bad Request\r\n"
          "Content-Length: 0\r\n"
          "\r\n" );

  HDR_EQ( build_err_hdr( hdr, 404U, ULONG_MAX, 0 ),
          "HTTP/1.1 404 Not Found\r\n"
          "Content-Length: 0\r\n"
          "\r\n" );

  /* unknown status codes fall back to 500 */
  HDR_EQ( build_err_hdr( hdr, 500U, ULONG_MAX, 0 ),
          "HTTP/1.1 500 Internal Server Error\r\n"
          "Content-Length: 0\r\n"
          "\r\n" );
  HDR_EQ( build_err_hdr( hdr, 418U, ULONG_MAX, 0 ),
          "HTTP/1.1 500 Internal Server Error\r\n"
          "Content-Length: 0\r\n"
          "\r\n" );

  /* 'Connection: close' when the conn is sick */
  HDR_EQ( build_err_hdr( hdr, 400U, ULONG_MAX, 1 ),
          "HTTP/1.1 400 Bad Request\r\n"
          "Content-Length: 0\r\n"
          "Connection: close\r\n"
          "\r\n" );

  /* 416 carries the object size, but only when one is known */
  HDR_EQ( build_err_hdr( hdr, 416U, 4096UL, 0 ),
          "HTTP/1.1 416 Range Not Satisfiable\r\n"
          "Content-Range: bytes */4096\r\n"
          "Content-Length: 0\r\n"
          "\r\n" );
  HDR_EQ( build_err_hdr( hdr, 416U, 0UL, 1 ),
          "HTTP/1.1 416 Range Not Satisfiable\r\n"
          "Content-Range: bytes */0\r\n"
          "Content-Length: 0\r\n"
          "Connection: close\r\n"
          "\r\n" );
  HDR_EQ( build_err_hdr( hdr, 416U, ULONG_MAX, 0 ),
          "HTTP/1.1 416 Range Not Satisfiable\r\n"
          "Content-Length: 0\r\n"
          "\r\n" );

  /* non-416 statuses never emit a Content-Range */
  HDR_EQ( build_err_hdr( hdr, 404U, 4096UL, 0 ),
          "HTTP/1.1 404 Not Found\r\n"
          "Content-Length: 0\r\n"
          "\r\n" );

  /* worst case: a huge object size still fits the buffer */
  HDR_EQ( build_err_hdr( hdr, 416U, ULONG_MAX-1UL, 1 ),
          "HTTP/1.1 416 Range Not Satisfiable\r\n"
          "Content-Range: bytes */18446744073709551614\r\n"
          "Content-Length: 0\r\n"
          "Connection: close\r\n"
          "\r\n" );
}

FD_UNIT_TEST( test_build_snap_res_hdr ) {
  char hdr[ RES_HDR_MAX ];

  /* whole object, zstd */
  HDR_EQ( build_snap_res_hdr( hdr, 0, 1, 0UL, 4096UL, 4096UL, 0 ),
          "HTTP/1.1 200 OK\r\n"
          "Content-Type: application/zstd\r\n"
          "Accept-Ranges: bytes\r\n"
          "Content-Length: 4096\r\n"
          "\r\n" );

  /* whole object, uncompressed tar */
  HDR_EQ( build_snap_res_hdr( hdr, 0, 0, 0UL, 4096UL, 4096UL, 0 ),
          "HTTP/1.1 200 OK\r\n"
          "Content-Type: application/x-tar\r\n"
          "Accept-Ranges: bytes\r\n"
          "Content-Length: 4096\r\n"
          "\r\n" );

  /* partial content.  The half open [range0,range1) becomes the
     inclusive 'Content-Range: bytes range0-(range1-1)/object_sz'. */
  HDR_EQ( build_snap_res_hdr( hdr, 1, 1, 0UL, 100UL, 4096UL, 0 ),
          "HTTP/1.1 206 Partial Content\r\n"
          "Content-Type: application/zstd\r\n"
          "Accept-Ranges: bytes\r\n"
          "Content-Range: bytes 0-99/4096\r\n"
          "Content-Length: 100\r\n"
          "\r\n" );

  /* a range that runs to the end of the object */
  HDR_EQ( build_snap_res_hdr( hdr, 1, 0, 4000UL, 4096UL, 4096UL, 0 ),
          "HTTP/1.1 206 Partial Content\r\n"
          "Content-Type: application/x-tar\r\n"
          "Accept-Ranges: bytes\r\n"
          "Content-Range: bytes 4000-4095/4096\r\n"
          "Content-Length: 96\r\n"
          "\r\n" );

  /* single byte range */
  HDR_EQ( build_snap_res_hdr( hdr, 1, 1, 7UL, 8UL, 4096UL, 0 ),
          "HTTP/1.1 206 Partial Content\r\n"
          "Content-Type: application/zstd\r\n"
          "Accept-Ranges: bytes\r\n"
          "Content-Range: bytes 7-7/4096\r\n"
          "Content-Length: 1\r\n"
          "\r\n" );

  /* an empty object still advertises range support */
  HDR_EQ( build_snap_res_hdr( hdr, 0, 1, 0UL, 0UL, 0UL, 0 ),
          "HTTP/1.1 200 OK\r\n"
          "Content-Type: application/zstd\r\n"
          "Accept-Ranges: bytes\r\n"
          "Content-Length: 0\r\n"
          "\r\n" );

  /* 'Connection: close' when conn is sick */
  HDR_EQ( build_snap_res_hdr( hdr, 0, 1, 0UL, 4096UL, 4096UL, 1 ),
          "HTTP/1.1 200 OK\r\n"
          "Content-Type: application/zstd\r\n"
          "Accept-Ranges: bytes\r\n"
          "Content-Length: 4096\r\n"
          "Connection: close\r\n"
          "\r\n" );

  /* the parser feeds through real Range headers; check the two ends of
     the wire round trip agree */
  {
    ulong r0, r1;
    FD_TEST( 0==parse_range_header( "bytes=-500", 10UL, 1000UL, &r0, &r1 ) );
    HDR_EQ( build_snap_res_hdr( hdr, 1, 1, r0, r1, 1000UL, 0 ),
            "HTTP/1.1 206 Partial Content\r\n"
            "Content-Type: application/zstd\r\n"
            "Accept-Ranges: bytes\r\n"
            "Content-Range: bytes 500-999/1000\r\n"
            "Content-Length: 500\r\n"
            "\r\n" );
  }

  /* worst case sizes fit the buffer */
  FD_TEST( build_snap_res_hdr( hdr, 1, 1, 0UL, ULONG_MAX, ULONG_MAX, 1 )<RES_HDR_MAX );
}

FD_UNIT_TEST( test_build_redirect_hdr ) {
  char hdr[ RES_HDR_MAX ];

  uchar hash[ 32 ];
  memset( hash, 0, sizeof(hash) );

  /* the all-zero hash encodes as 32 base58 '1's */
  HDR_EQ( build_redirect_hdr( hdr, 0, 100UL, ULONG_MAX, hash, 1, 0 ),
          "HTTP/1.1 302 Found\r\n"
          "Location: /snapshot-100-11111111111111111111111111111111.tar.zst\r\n"
          "Content-Length: 0\r\n"
          "\r\n" );

  HDR_EQ( build_redirect_hdr( hdr, 0, 100UL, ULONG_MAX, hash, 0, 0 ),
          "HTTP/1.1 302 Found\r\n"
          "Location: /snapshot-100-11111111111111111111111111111111.tar\r\n"
          "Content-Length: 0\r\n"
          "\r\n" );

  /* incremental redirects name the base slot first */
  HDR_EQ( build_redirect_hdr( hdr, 1, 250UL, 100UL, hash, 1, 0 ),
          "HTTP/1.1 302 Found\r\n"
          "Location: /incremental-snapshot-100-250-11111111111111111111111111111111.tar.zst\r\n"
          "Content-Length: 0\r\n"
          "\r\n" );

  /* sick conns get a 'Connection: close' */
  HDR_EQ( build_redirect_hdr( hdr, 0, 100UL, ULONG_MAX, hash, 1, 1 ),
          "HTTP/1.1 302 Found\r\n"
          "Location: /snapshot-100-11111111111111111111111111111111.tar.zst\r\n"
          "Content-Length: 0\r\n"
          "Connection: close\r\n"
          "\r\n" );

  /* the Location of a real snapshot must round trip back through the
     request path matcher */
  {
    memcpy( hash, test_hash( 11UL ), 32UL );
    build_redirect_hdr( hdr, 1, 250UL, 100UL, hash, 1, 0 );
    char const * loc = strstr( hdr, "Location: /" );
    FD_TEST( loc );
    loc += strlen( "Location: /" );
    char const * eol = strstr( loc, "\r\n" );
    FD_TEST( eol );
    FD_TEST( path_matches( snap_name( 250UL, 100UL, 11UL, 1 ), 250UL, 100UL, test_hash( 11UL ), 1 ) );
    FD_TEST( (ulong)(eol-loc)==strlen( snap_name( 250UL, 100UL, 11UL, 1 ) ) );
    FD_TEST( 0==memcmp( loc, snap_name( 250UL, 100UL, 11UL, 1 ), (ulong)(eol-loc) ) );
  }

  /* worst case sizes fit the buffer */
  memset( hash, 0xff, sizeof(hash) );
  FD_TEST( build_redirect_hdr( hdr, 1, ULONG_MAX-1UL, ULONG_MAX-1UL, hash, 1, 1 )<RES_HDR_MAX );
}

#undef HDR_EQ

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  /* tile entry points that need an io_uring instance, a listen socket,
     or a live topology are out of scope here */
  (void)scratch_footprint;
  (void)privileged_init;
  (void)unprivileged_init;
  (void)populate_allowed_fds;
  (void)populate_allowed_seccomp;
  (void)rlimit_file_cnt;

  FD_TEST( snap_map_footprint( TEST_ELE_MAX )<=sizeof(test_map_ele) );

  fd_unit_tests( argc, argv );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
