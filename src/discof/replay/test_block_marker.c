#include "fd_block_marker.h"

/* Test vectors are hand-encoded per the wincode wire format in Agave
   entry/src/block_component.rs (all integers little endian). */

static uchar g_buf[ 2048UL ];
static ulong g_sz;

static void
emit_reset( void ) {
  g_sz = 0UL;
}

static void
emit( void const * bytes,
      ulong        sz ) {
  FD_TEST( g_sz+sz<=sizeof(g_buf) );
  fd_memcpy( g_buf+g_sz, bytes, sz );
  g_sz += sz;
}

static void
emit_u8( uchar v ) {
  emit( &v, 1UL );
}

static void
emit_u16( ushort v ) {
  emit( &v, 2UL );
}

static void
emit_u64( ulong v ) {
  emit( &v, 8UL );
}

static void
emit_rep( uchar v,
          ulong cnt ) {
  for( ulong i=0UL; i<cnt; i++ ) emit_u8( v );
}

static fd_hash_t
hash_of( uchar fill ) {
  fd_hash_t h;
  fd_memset( h.uc, (int)fill, sizeof(fd_hash_t) );
  return h;
}

/* emit_preamble emits marker_flag | version | variant | length. */

static void
emit_preamble( uchar  variant,
               ushort length ) {
  emit_u64( 0UL );
  emit_u16( (ushort)1 );
  emit_u8 ( variant   );
  emit_u16( length    );
}

/* emit_votes_aggregate emits a VotesAggregate with the given bitmap
   byte count, returning its serialized size. */

static ulong
emit_votes_aggregate( uchar sig_fill,
                      ulong bitmap_sz ) {
  emit_rep( sig_fill, 96UL );
  emit_u16( (ushort)bitmap_sz );
  emit_rep( 0xbb, bitmap_sz );
  return 96UL+2UL+bitmap_sz;
}

static void
test_header( void ) {
  fd_hash_t parent_id = hash_of( 0x11 );

  emit_reset();
  emit_preamble( HEADER, (ushort)41 );
  emit_u8 ( 1 );                              /* VersionedBlockHeader::V1 */
  emit_u64( 1234UL );                         /* parent_slot */
  emit( parent_id.uc, sizeof(fd_hash_t) );    /* parent_block_id */
  ulong trailing = g_sz;
  emit_rep( 0xee, 7UL );                      /* trailing bytes are not the marker's */

  fd_block_marker_t marker[1];
  ulong             consumed = 0UL;
  FD_TEST( fd_block_marker_de( marker, g_buf, g_sz, &consumed )==FD_BLOCK_MARKER_DE_SUCCESS );
  FD_TEST( consumed==trailing );
  FD_TEST( marker->variant==HEADER );
  FD_TEST( marker->header.parent_slot==1234UL );
  FD_TEST( !memcmp( marker->header.parent_block_id.uc, parent_id.uc, sizeof(fd_hash_t) ) );

  /* every strict prefix of the marker is truncated */
  for( ulong sz=0UL; sz<trailing; sz++ ) {
    FD_TEST( fd_block_marker_de( marker, g_buf, sz, NULL )==FD_BLOCK_MARKER_DE_ERR_TRUNCATED );
  }
}

static void
test_update_parent( void ) {
  fd_hash_t new_parent_id = hash_of( 0x22 );

  emit_reset();
  emit_preamble( UPDATE_PARENT, (ushort)41 );
  emit_u8 ( 1 );                                /* VersionedUpdateParent::V1 */
  emit_u64( 5678UL );                           /* new_parent_slot */
  emit( new_parent_id.uc, sizeof(fd_hash_t) );  /* new_parent_block_id */

  fd_block_marker_t marker[1];
  ulong             consumed = 0UL;
  FD_TEST( fd_block_marker_de( marker, g_buf, g_sz, &consumed )==FD_BLOCK_MARKER_DE_SUCCESS );
  FD_TEST( consumed==g_sz );
  FD_TEST( marker->variant==UPDATE_PARENT );
  FD_TEST( marker->update_parent.new_parent_slot==5678UL );
  FD_TEST( !memcmp( marker->update_parent.new_parent_block_id.uc, new_parent_id.uc, sizeof(fd_hash_t) ) );
}

static void
test_footer_no_certs( void ) {
  fd_hash_t bank_hash = hash_of( 0x33 );

  emit_reset();
  emit_preamble( FOOTER, (ushort)(1UL+32UL+8UL+1UL+5UL+3UL) );
  emit_u8 ( 1 );                            /* VersionedBlockFooter::V1 */
  emit( bank_hash.uc, sizeof(fd_hash_t) );  /* bank_hash */
  emit_u64( 987654321UL );                  /* block_producer_time_nanos */
  emit_u8 ( 5 );                            /* user agent len */
  emit( "agave", 5UL );                     /* user agent */
  emit_u8 ( 0 );                            /* block_final_cert: None */
  emit_u8 ( 0 );                            /* skip_reward_cert: None */
  emit_u8 ( 0 );                            /* notar_reward_cert: None */

  fd_block_marker_t marker[1];
  ulong             consumed = 0UL;
  FD_TEST( fd_block_marker_de( marker, g_buf, g_sz, &consumed )==FD_BLOCK_MARKER_DE_SUCCESS );
  FD_TEST( consumed==g_sz );
  FD_TEST( marker->variant==FOOTER );
  FD_TEST( !memcmp( marker->footer.bank_hash.uc, bank_hash.uc, sizeof(fd_hash_t) ) );
  FD_TEST( marker->footer.block_producer_time_nanos==987654321UL );
  FD_TEST( marker->footer.user_agent_len==5UL );
  FD_TEST( !memcmp( marker->footer.user_agent, "agave", 5UL ) );
  FD_TEST( !marker->footer.final_cert        && !marker->footer.final_cert_sz        );
  FD_TEST( !marker->footer.skip_reward_cert  && !marker->footer.skip_reward_cert_sz  );
  FD_TEST( !marker->footer.notar_reward_cert && !marker->footer.notar_reward_cert_sz );
}

static void
test_footer_with_certs( int has_notar_aggregate ) {
  fd_hash_t bank_hash = hash_of( 0x44 );
  fd_hash_t block_id  = hash_of( 0x55 );

  emit_reset();
  emit_preamble( FOOTER, (ushort)0 ); /* length patched below */
  ulong payload_off = g_sz;
  emit_u8 ( 1 );                            /* VersionedBlockFooter::V1 */
  emit( bank_hash.uc, sizeof(fd_hash_t) );  /* bank_hash */
  emit_u64( 42UL );                         /* block_producer_time_nanos */
  emit_u8 ( 0 );                            /* empty user agent */

  emit_u8( 1 );                             /* block_final_cert: Some */
  ulong final_cert_off = g_sz;
  emit_u64( 777UL );                        /* BlockFinalizationCert::slot */
  emit( block_id.uc, sizeof(fd_hash_t) );   /* BlockFinalizationCert::block_id */
  emit_votes_aggregate( 0xf1, 4UL );        /* final_aggregate */
  emit_u8( (uchar)!!has_notar_aggregate );  /* notar_aggregate tag */
  if( has_notar_aggregate ) emit_votes_aggregate( 0xf2, 6UL );
  ulong final_cert_sz = g_sz-final_cert_off;

  emit_u8( 1 );                             /* skip_reward_cert: Some */
  ulong skip_cert_off = g_sz;
  emit_u64( 775UL );                        /* SkipRewardCertificate::slot */
  emit_rep( 0xf3, 96UL );                   /* compressed signature */
  emit_u8 ( 3 );                            /* bitmap len (ShortU16, 1 byte) */
  emit_rep( 0xcc, 3UL );                    /* bitmap */
  ulong skip_cert_sz = g_sz-skip_cert_off;

  emit_u8( 1 );                             /* notar_reward_cert: Some */
  ulong notar_cert_off = g_sz;
  emit_u64( 776UL );                        /* NotarRewardCertificate::slot */
  emit( block_id.uc, sizeof(fd_hash_t) );   /* NotarRewardCertificate::block_id */
  emit_rep( 0xf4, 96UL );                   /* compressed signature */
  emit_u8 ( 200 ); emit_u8( 1 );            /* bitmap len 200 (ShortU16, 2 bytes: 0xc8 0x01) */
  emit_rep( 0xdd, 200UL );                  /* bitmap */
  ulong notar_cert_sz = g_sz-notar_cert_off;

  FD_STORE( ushort, g_buf+FD_BLOCK_MARKER_PREAMBLE_SZ-2UL, (ushort)(g_sz-payload_off) );

  fd_block_marker_t marker[1];
  ulong             consumed = 0UL;
  FD_TEST( fd_block_marker_de( marker, g_buf, g_sz, &consumed )==FD_BLOCK_MARKER_DE_SUCCESS );
  FD_TEST( consumed==g_sz );
  FD_TEST( marker->variant==FOOTER );
  FD_TEST( marker->footer.user_agent_len==0UL );
  FD_TEST( marker->footer.final_cert        ==g_buf+final_cert_off && marker->footer.final_cert_sz        ==final_cert_sz );
  FD_TEST( marker->footer.skip_reward_cert  ==g_buf+skip_cert_off  && marker->footer.skip_reward_cert_sz  ==skip_cert_sz  );
  FD_TEST( marker->footer.notar_reward_cert ==g_buf+notar_cert_off && marker->footer.notar_reward_cert_sz ==notar_cert_sz );

  /* every strict prefix of the marker is truncated */
  for( ulong sz=0UL; sz<g_sz; sz++ ) {
    int err = fd_block_marker_de( marker, g_buf, sz, NULL );
    FD_TEST( err==FD_BLOCK_MARKER_DE_ERR_TRUNCATED || err==FD_BLOCK_MARKER_DE_ERR_MALFORMED );
  }
}

static void
test_errors( void ) {
  fd_block_marker_t marker[1];

  /* nonzero marker flag */
  emit_reset();
  emit_u64( 1UL ); emit_u16( 1 ); emit_u8( HEADER ); emit_u16( 41 ); emit_rep( 0, 41UL );
  FD_TEST( fd_block_marker_de( marker, g_buf, g_sz, NULL )==FD_BLOCK_MARKER_DE_ERR_MALFORMED );

  /* unsupported marker version */
  emit_reset();
  emit_u64( 0UL ); emit_u16( 2 ); emit_u8( HEADER ); emit_u16( 41 ); emit_rep( 0, 41UL );
  FD_TEST( fd_block_marker_de( marker, g_buf, g_sz, NULL )==FD_BLOCK_MARKER_DE_ERR_UNSUPPORTED );

  /* genesis certificate variant is recognized but unsupported */
  emit_reset();
  emit_preamble( GENESIS_CERTIFICATE, (ushort)1 ); emit_u8( 0 );
  FD_TEST( fd_block_marker_de( marker, g_buf, g_sz, NULL )==FD_BLOCK_MARKER_DE_ERR_UNSUPPORTED );

  /* unknown variant tag */
  emit_reset();
  emit_preamble( (uchar)7, (ushort)1 ); emit_u8( 0 );
  FD_TEST( fd_block_marker_de( marker, g_buf, g_sz, NULL )==FD_BLOCK_MARKER_DE_ERR_MALFORMED );

  /* unsupported payload version */
  emit_reset();
  emit_preamble( HEADER, (ushort)41 );
  emit_u8( 2 ); emit_rep( 0, 40UL );
  FD_TEST( fd_block_marker_de( marker, g_buf, g_sz, NULL )==FD_BLOCK_MARKER_DE_ERR_UNSUPPORTED );

  /* announced length exceeds the input */
  emit_reset();
  emit_preamble( HEADER, (ushort)42 );
  emit_u8( 1 ); emit_rep( 0, 40UL );
  FD_TEST( fd_block_marker_de( marker, g_buf, g_sz, NULL )==FD_BLOCK_MARKER_DE_ERR_TRUNCATED );

  /* option tag out of range */
  emit_reset();
  emit_preamble( FOOTER, (ushort)(1UL+32UL+8UL+1UL+1UL) );
  emit_u8( 1 ); emit_rep( 0x66, 32UL ); emit_u64( 0UL ); emit_u8( 0 );
  emit_u8( 2 ); /* block_final_cert tag */
  FD_TEST( fd_block_marker_de( marker, g_buf, g_sz, NULL )==FD_BLOCK_MARKER_DE_ERR_MALFORMED );
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  test_header();
  test_update_parent();
  test_footer_no_certs();
  test_footer_with_certs( 0 );
  test_footer_with_certs( 1 );
  test_errors();

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
