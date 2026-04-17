/* Unit tests for fd_alut_state_encode / fd_alut_state_decode wire
   format compatibility with Agave's bincode representation of
   `ProgramState` / `LookupTableMeta`.

   Reference:
     https://github.com/anza-xyz/agave/blob/v2.1.4/sdk/program/src/address_lookup_table/state.rs

   Wire layout (little-endian throughout):
     - u32 discriminant (0=Uninitialized, 1=LookupTable)
     - if LookupTable:
       - u64 deactivation_slot
       - u64 last_extended_slot
       - u8  last_extended_slot_start_index
       - u8  authority tag (0=None, 1=Some)  [bincode Option tag]
       - if Some: [u8; 32] authority_pubkey
       - u16 _padding

   Agave test_lookup_table_meta_size asserts:
     - serialized size with authority=Some is exactly 56 bytes
     - serialized size with authority=None is exactly 24 bytes
   The on-disk representation zero-pads the None case up to 56 bytes.

   These tests document CURRENTLY FAILING cases.  Each check is a soft
   FD_TEST_SOFT which records a failure and continues so we can see
   every bug exercised in a single run. */

#include "fd_alut.h"

static ulong g_fail_cnt;
static ulong g_check_cnt;

#define FD_TEST_SOFT(cond) do {                                          \
    g_check_cnt++;                                                       \
    if( !(cond) ) {                                                      \
      g_fail_cnt++;                                                      \
      FD_LOG_WARNING(( "FAIL  %s:%d  %s", __FILE__, __LINE__, #cond ));  \
    }                                                                    \
  } while(0)

/* Helper to build a bincode-compatible "LookupTable(None-authority)"
   byte buffer of the requested size (must be >=24).  Bytes [24, size)
   are zero-filled, matching Agave's `overwrite_meta_data` which
   resizes to LOOKUP_TABLE_META_SIZE. */

static void
build_none_authority_buf( uchar * buf,
                          ulong   size,
                          ulong   deactivation_slot,
                          ulong   last_extended_slot,
                          uchar   last_extended_slot_start_index,
                          ushort  padding ) {
  FD_TEST( size >= 24UL );
  fd_memset( buf, 0, size );
  uchar * p = buf;
  FD_STORE( uint,   p, FD_ALUT_STATE_DISC_LOOKUP_TABLE ); p += 4;
  FD_STORE( ulong,  p, deactivation_slot              ); p += 8;
  FD_STORE( ulong,  p, last_extended_slot             ); p += 8;
  *p = last_extended_slot_start_index;                    p += 1;
  *p = 0;                                                 p += 1; /* authority tag = None */
  FD_STORE( ushort, p, padding                        ); p += 2;
  (void)p;
}

/* Helper to build a bincode-compatible "LookupTable(Some(pubkey))"
   byte buffer of exactly 56 bytes. */

static void
build_some_authority_buf( uchar *             buf,
                          ulong               deactivation_slot,
                          ulong               last_extended_slot,
                          uchar               last_extended_slot_start_index,
                          fd_pubkey_t const * authority,
                          ushort              padding ) {
  fd_memset( buf, 0, FD_LOOKUP_TABLE_META_SIZE );
  uchar * p = buf;
  FD_STORE( uint,   p, FD_ALUT_STATE_DISC_LOOKUP_TABLE ); p += 4;
  FD_STORE( ulong,  p, deactivation_slot              ); p += 8;
  FD_STORE( ulong,  p, last_extended_slot             ); p += 8;
  *p = last_extended_slot_start_index;                    p += 1;
  *p = 1;                                                 p += 1; /* authority tag = Some */
  fd_memcpy( p, authority->key, 32 );                     p += 32;
  FD_STORE( ushort, p, padding                        ); p += 2;
  (void)p;
}

/* -----------------------------------------------------------------------
   Bug 1: has_authority tag not validated.
   Per bincode, the Option tag MUST be exactly 0 or 1.  Any other byte
   is a decode error.  Agave rejects ALUT accounts whose tag byte is
   outside {0,1}; so must we. */

static void
test_decode_rejects_invalid_authority_tag_once( uchar tag ) {
  uchar buf[ FD_LOOKUP_TABLE_META_SIZE ];
  fd_memset( buf, 0, sizeof(buf) );
  uchar * p = buf;
  FD_STORE( uint,  p, FD_ALUT_STATE_DISC_LOOKUP_TABLE ); p += 4;
  FD_STORE( ulong, p, ULONG_MAX                       ); p += 8;
  FD_STORE( ulong, p, 0UL                             ); p += 8;
  *p = 0;                                                p += 1;
  *p = tag;                                              p += 1;
  /* rest stays zero */

  fd_alut_meta_t meta[1];
  int err = fd_alut_state_decode( buf, sizeof(buf), meta );
  if( err == 0 ) {
    FD_LOG_WARNING(( "FAIL: decode accepted authority tag 0x%02x (expected reject)", (uint)tag ));
    g_fail_cnt++;
  }
  g_check_cnt++;
}

static void
test_decode_rejects_invalid_authority_tag( void ) {
  FD_LOG_NOTICE(( "test_decode_rejects_invalid_authority_tag" ));
  test_decode_rejects_invalid_authority_tag_once( 0x02 );
  test_decode_rejects_invalid_authority_tag_once( 0x03 );
  test_decode_rejects_invalid_authority_tag_once( 0x7F );
  test_decode_rejects_invalid_authority_tag_once( 0x80 );
  test_decode_rejects_invalid_authority_tag_once( 0xFE );
  test_decode_rejects_invalid_authority_tag_once( 0xFF );
}

/* -----------------------------------------------------------------------
   Bug 2 (part A): Decoder must NOT consume 32 pubkey bytes when the
   authority tag is 0.  With a 24-byte bincode payload (the minimum
   valid size for None-authority), the decode must succeed and correctly
   land on _padding at offset 22. */

static void
test_decode_24_byte_none_payload( void ) {
  FD_LOG_NOTICE(( "test_decode_24_byte_none_payload" ));

  uchar buf[ 24 ];
  build_none_authority_buf( buf, sizeof(buf),
                            /* deactivation_slot */ ULONG_MAX,
                            /* last_extended_slot */ 42UL,
                            /* last_extended_slot_start_index */ 7,
                            /* padding */ 0x1234 );

  fd_alut_meta_t meta[1];
  int err = fd_alut_state_decode( buf, sizeof(buf), meta );
  FD_TEST_SOFT( err == 0 );
  FD_TEST_SOFT( meta->discriminant                    == FD_ALUT_STATE_DISC_LOOKUP_TABLE );
  FD_TEST_SOFT( meta->deactivation_slot               == ULONG_MAX );
  FD_TEST_SOFT( meta->last_extended_slot              == 42UL      );
  FD_TEST_SOFT( meta->last_extended_slot_start_index  == 7         );
  FD_TEST_SOFT( meta->has_authority                   == 0         );
}

/* -----------------------------------------------------------------------
   Bug 2 (part B): Round-trip equality with Agave's wire format for
   authority=None.  A 24-byte canonical buffer, zero-padded to 56
   (mimicking Agave's overwrite_meta_data), must survive
   decode -> encode and match byte-for-byte. */

static void
test_encode_none_authority_matches_agave_layout( void ) {
  FD_LOG_NOTICE(( "test_encode_none_authority_matches_agave_layout" ));

  uchar expected[ FD_LOOKUP_TABLE_META_SIZE ];
  build_none_authority_buf( expected, sizeof(expected),
                            /* deactivation_slot */ 1234UL,
                            /* last_extended_slot */ 5678UL,
                            /* last_extended_slot_start_index */ 9,
                            /* padding */ 0 );

  fd_alut_meta_t meta = {
    .discriminant                   = FD_ALUT_STATE_DISC_LOOKUP_TABLE,
    .deactivation_slot              = 1234UL,
    .last_extended_slot             = 5678UL,
    .last_extended_slot_start_index = 9,
    .has_authority                  = 0,
  };

  uchar actual[ FD_LOOKUP_TABLE_META_SIZE ];
  FD_TEST_SOFT( fd_alut_state_encode( &meta, actual, sizeof(actual) ) == 0 );

  /* Byte-for-byte equality with the Agave-formatted reference buffer. */
  FD_TEST_SOFT( fd_memeq( actual, expected, sizeof(expected) ) );
}

/* -----------------------------------------------------------------------
   Bug 2 (part C): authority=Some round-trip.  The 56-byte layout for
   Some is unambiguous; this test documents the baseline we already
   support and should keep supporting after the fix. */

static void
test_encode_some_authority_matches_agave_layout( void ) {
  FD_LOG_NOTICE(( "test_encode_some_authority_matches_agave_layout" ));

  fd_pubkey_t auth = {{0}};
  for( ulong i = 0; i < 32; i++ ) auth.key[i] = (uchar)(0xA0 + i);

  uchar expected[ FD_LOOKUP_TABLE_META_SIZE ];
  build_some_authority_buf( expected,
                            /* deactivation_slot */ 111UL,
                            /* last_extended_slot */ 222UL,
                            /* last_extended_slot_start_index */ 33,
                            &auth,
                            /* padding */ 0 );

  fd_alut_meta_t meta = {
    .discriminant                   = FD_ALUT_STATE_DISC_LOOKUP_TABLE,
    .deactivation_slot              = 111UL,
    .last_extended_slot             = 222UL,
    .last_extended_slot_start_index = 33,
    .has_authority                  = 1,
    .authority                      = auth,
  };

  uchar actual[ FD_LOOKUP_TABLE_META_SIZE ];
  FD_TEST_SOFT( fd_alut_state_encode( &meta, actual, sizeof(actual) ) == 0 );
  FD_TEST_SOFT( fd_memeq( actual, expected, sizeof(expected) ) );

  fd_alut_meta_t decoded[1];
  FD_TEST_SOFT( fd_alut_state_decode( actual, sizeof(actual), decoded ) == 0 );
  FD_TEST_SOFT( decoded->discriminant                    == FD_ALUT_STATE_DISC_LOOKUP_TABLE );
  FD_TEST_SOFT( decoded->deactivation_slot               == 111UL );
  FD_TEST_SOFT( decoded->last_extended_slot              == 222UL );
  FD_TEST_SOFT( decoded->last_extended_slot_start_index  == 33    );
  FD_TEST_SOFT( decoded->has_authority                   == 1     );
  FD_TEST_SOFT( fd_memeq( decoded->authority.key, auth.key, 32 )  );
}

/* -----------------------------------------------------------------------
   Bug 3: Decoder must read the 2-byte _padding that follows the
   authority option.  Agave's bincode footprint validator calls
   fd_bincode_uint16_decode_footprint at the end; if the buffer is too
   small to hold _padding, Agave returns FD_BINCODE_ERR_UNDERFLOW.  Our
   decoder silently accepts the truncation.

   Test A: 23-byte buffer (1 of 2 padding bytes present). */

static void
test_decode_rejects_short_none_buffer_23( void ) {
  FD_LOG_NOTICE(( "test_decode_rejects_short_none_buffer_23" ));

  uchar buf[ 23 ];
  fd_memset( buf, 0, sizeof(buf) );
  uchar * p = buf;
  FD_STORE( uint,  p, FD_ALUT_STATE_DISC_LOOKUP_TABLE ); p += 4;
  FD_STORE( ulong, p, ULONG_MAX                       ); p += 8;
  FD_STORE( ulong, p, 0UL                             ); p += 8;
  *p = 0;                                                p += 1;
  *p = 0;                                                p += 1; /* authority tag = None */
  /* 1 byte of padding present, 1 byte missing */

  fd_alut_meta_t meta[1];
  int err = fd_alut_state_decode( buf, sizeof(buf), meta );
  FD_TEST_SOFT( err != 0 );
}

/* Test B: 22-byte buffer (both padding bytes missing). */

static void
test_decode_rejects_short_none_buffer_22( void ) {
  FD_LOG_NOTICE(( "test_decode_rejects_short_none_buffer_22" ));

  uchar buf[ 22 ];
  fd_memset( buf, 0, sizeof(buf) );
  uchar * p = buf;
  FD_STORE( uint,  p, FD_ALUT_STATE_DISC_LOOKUP_TABLE ); p += 4;
  FD_STORE( ulong, p, ULONG_MAX                       ); p += 8;
  FD_STORE( ulong, p, 0UL                             ); p += 8;
  *p = 0;                                                p += 1;
  *p = 0;                                                p += 1; /* authority tag = None */
  /* no padding bytes present */

  fd_alut_meta_t meta[1];
  int err = fd_alut_state_decode( buf, sizeof(buf), meta );
  FD_TEST_SOFT( err != 0 );
}

/* -----------------------------------------------------------------------
   Bug 2 (wire-format sanity): document the expected byte positions of
   each field explicitly.  This catches any silent offset drift in the
   encoder. */

static void
test_encoded_field_offsets( void ) {
  FD_LOG_NOTICE(( "test_encoded_field_offsets" ));

  fd_alut_meta_t meta = {
    .discriminant                   = FD_ALUT_STATE_DISC_LOOKUP_TABLE,
    .deactivation_slot              = 0x1122334455667788UL,
    .last_extended_slot             = 0x99AABBCCDDEEFF00UL,
    .last_extended_slot_start_index = 0x42,
    .has_authority                  = 0,
  };

  uchar buf[ FD_LOOKUP_TABLE_META_SIZE ];
  FD_TEST_SOFT( fd_alut_state_encode( &meta, buf, sizeof(buf) ) == 0 );

  /* discriminant at [0,4) */
  FD_TEST_SOFT( FD_LOAD( uint,  buf +  0 ) == FD_ALUT_STATE_DISC_LOOKUP_TABLE  );
  /* deactivation_slot at [4,12) */
  FD_TEST_SOFT( FD_LOAD( ulong, buf +  4 ) == 0x1122334455667788UL              );
  /* last_extended_slot at [12,20) */
  FD_TEST_SOFT( FD_LOAD( ulong, buf + 12 ) == 0x99AABBCCDDEEFF00UL              );
  /* last_extended_slot_start_index at [20,21) */
  FD_TEST_SOFT( buf[20] == 0x42                                                  );
  /* authority tag at [21,22) */
  FD_TEST_SOFT( buf[21] == 0                                                     );
  /* _padding at [22,24) -- NOT at [54, 56) */
  FD_TEST_SOFT( FD_LOAD( ushort, buf + 22 ) == 0                                 );
  /* Bytes [24, 56) must be zero (zero-padded tail) */
  for( ulong i = 24; i < FD_LOOKUP_TABLE_META_SIZE; i++ ) FD_TEST_SOFT( buf[i] == 0 );
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  test_decode_rejects_invalid_authority_tag();
  test_decode_24_byte_none_payload();
  test_encode_none_authority_matches_agave_layout();
  test_encode_some_authority_matches_agave_layout();
  test_decode_rejects_short_none_buffer_23();
  test_decode_rejects_short_none_buffer_22();
  test_encoded_field_offsets();

  if( g_fail_cnt ) {
    FD_LOG_ERR(( "FAIL: %lu / %lu checks failed", g_fail_cnt, g_check_cnt ));
  }
  FD_LOG_NOTICE(( "pass: %lu checks", g_check_cnt ));
  fd_halt();
  return 0;
}
