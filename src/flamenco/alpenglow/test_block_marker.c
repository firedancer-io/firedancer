#include "fd_block_marker_serde.h"

#include "../../ballet/bls/fd_bls12_381.h"

/* Test vectors are hand-encoded per the wincode wire format in Agave
   entry/src/block_component.rs (all integers little endian). */

static uchar g_buf[ 4096UL ];
static ulong g_sz;

/* set_is_range tests that set names exactly the ranks [lo,hi) */

static int
set_is_range( ag_bls_set_t const * set,
              ulong                lo,
              ulong                hi ) {
  ag_bls_set_t want[ ag_bls_set_word_cnt ];
  ag_bls_set_range( want, lo, hi );
  return ag_bls_set_eq( set, want );
}

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

/* emit_cu16 emits a ShortU16 (valid for v<0x4000). */

static void
emit_cu16( ushort v ) {
  if( v<0x80 ) {
    emit_u8( (uchar)v );
  } else {
    emit_u8( (uchar)((v&0x7f)|0x80) );
    emit_u8( (uchar)(v>>7) );
  }
}

static fd_hash_t
hash_of( uchar fill ) {
  fd_hash_t h;
  fd_memset( h.uc, (int)fill, sizeof(fd_hash_t) );
  return h;
}

/* emit_preamble emits marker_flag | version | tag | length. */

static void
emit_preamble( uchar  tag,
               ushort length ) {
  emit_u64( 0UL );
  emit_u16( (ushort)1 );
  emit_u8 ( tag       );
  emit_u16( length    );
}

/* emit_base2_bitmap emits a solana_signer_store base2 bitmap over nbits
   ranks, the low 64 of which come from mask and the rest of which are
   zero. */

static void
emit_base2_bitmap( ulong nbits,
                   ulong mask ) {
  ulong payload = (nbits+7UL)/8UL;
  emit_u8 ( 0 );                             /* base2 bitmap */
  emit_u16( (ushort)nbits );                 /* bit count */
  for( ulong b=0UL; b<payload; b++ ) emit_u8( (uchar)( b<8UL ? (mask>>(8UL*b))&0xffUL : 0UL ) );
}

/* emit_votes_aggregate emits a VotesAggregate whose signature is 96
   fixed bytes (the compressed G2 point at infinity, which the serde
   copies verbatim) and whose base2 bitmap, under a u16 byte count,
   names the ranks set in mask.  The serializer emits the bitmap exactly
   nbits wide, so these bytes re-encode as they are. */

static void
emit_votes_aggregate( ulong nbits,
                      ulong mask ) {
  emit_u8 ( 0xc0 ); emit_rep( 0x00, 95UL );  /* compressed signature: infinity */
  emit_u16( (ushort)(3UL+(nbits+7UL)/8UL) ); /* bitmap byte count */
  emit_base2_bitmap( nbits, mask );
}

/* emit_reward_cert emits a SkipRewardCertificate (block_id NULL) or a
   NotarRewardCertificate.  Its bitmap byte count is a ShortU16, not the
   aggregate's u16, and its signature stays compressed. */

static void
emit_reward_cert( ulong             slot,
                  fd_hash_t const * block_id,
                  uchar             sig_fill,
                  ulong             nbits,
                  ulong             mask ) {
  emit_u64( slot );
  if( block_id ) emit( block_id->uc, sizeof(fd_hash_t) );
  emit_rep( sig_fill, 96UL );
  emit_cu16( (ushort)(3UL+(nbits+7UL)/8UL) );
  emit_base2_bitmap( nbits, mask );
}

/* roundtrip re-encodes the marker occupying g_buf[0,marker_sz) and
   asserts the encoding is byte identical. */

static void
roundtrip( ulong marker_sz ) {
  static uchar out[ FD_BLOCK_MARKER_SER_MAX ];

  fd_block_marker_t marker[1];
  FD_TEST( fd_block_marker_de( marker, g_buf, marker_sz )==FD_BLOCK_MARKER_DE_SUCCESS );

  ulong out_sz = fd_block_marker_ser( marker, out );
  FD_TEST( out_sz==marker_sz );
  FD_TEST( !memcmp( out, g_buf, marker_sz ) );
}

static void
test_header( void ) {
  fd_hash_t parent_id = hash_of( 0x11 );

  emit_reset();
  emit_preamble( FD_BLOCK_MARKER_SERDE_TAG_HEADER, (ushort)41 );
  emit_u8 ( 1 );                              /* VersionedBlockHeader::V1 */
  emit_u64( 1234UL );                         /* parent_slot */
  emit( parent_id.uc, sizeof(fd_hash_t) );    /* parent_block_id */
  ulong trailing = g_sz;
  emit_rep( 0xee, 7UL );                      /* trailing bytes are not the marker's */

  fd_block_marker_t marker[1];
  FD_TEST( fd_block_marker_de( marker, g_buf, g_sz )==FD_BLOCK_MARKER_DE_SUCCESS );
  FD_TEST( marker->kind==FD_BLOCK_MARKER_KIND_HEADER );
  FD_TEST( marker->header.parent_slot==1234UL );
  FD_TEST( !memcmp( marker->header.parent_block_id.uc, parent_id.uc, sizeof(fd_hash_t) ) );

  /* the marker ends where the trailing bytes begin */
  FD_TEST( fd_block_marker_de( marker, g_buf, trailing )==FD_BLOCK_MARKER_DE_SUCCESS );

  /* every strict prefix of the marker is truncated */
  for( ulong sz=0UL; sz<trailing; sz++ ) {
    FD_TEST( fd_block_marker_de( marker, g_buf, sz )==FD_BLOCK_MARKER_DE_ERR_SZ );
  }
}

static void
test_update_parent( void ) {
  fd_hash_t new_parent_id = hash_of( 0x22 );

  emit_reset();
  emit_preamble( FD_BLOCK_MARKER_SERDE_TAG_UPDATE_PARENT, (ushort)41 );
  emit_u8 ( 1 );                                /* VersionedUpdateParent::V1 */
  emit_u64( 5678UL );                           /* new_parent_slot */
  emit( new_parent_id.uc, sizeof(fd_hash_t) );  /* new_parent_block_id */

  fd_block_marker_t marker[1];
  FD_TEST( fd_block_marker_de( marker, g_buf, g_sz )==FD_BLOCK_MARKER_DE_SUCCESS );
  FD_TEST( marker->kind==FD_BLOCK_MARKER_KIND_UPDATE_PARENT );
  FD_TEST( marker->update_parent.new_parent_slot==5678UL );
  FD_TEST( !memcmp( marker->update_parent.new_parent_block_id.uc, new_parent_id.uc, sizeof(fd_hash_t) ) );
}

static void
test_footer_no_certs( void ) {
  fd_hash_t bank_hash = hash_of( 0x33 );

  emit_reset();
  emit_preamble( FD_BLOCK_MARKER_SERDE_TAG_FOOTER, (ushort)(1UL+32UL+8UL+1UL+5UL+3UL) );
  emit_u8 ( 1 );                            /* VersionedBlockFooter::V1 */
  emit( bank_hash.uc, sizeof(fd_hash_t) );  /* bank_hash */
  emit_u64( 987654321UL );                  /* block_producer_time_nanos */
  emit_u8 ( 5 );                            /* user agent len */
  emit( "agave", 5UL );                     /* user agent */
  emit_u8 ( 0 );                            /* block_final_cert: None */
  emit_u8 ( 0 );                            /* skip_reward_cert: None */
  emit_u8 ( 0 );                            /* notar_reward_cert: None */

  fd_block_marker_t marker[1];
  FD_TEST( fd_block_marker_de( marker, g_buf, g_sz )==FD_BLOCK_MARKER_DE_SUCCESS );
  FD_TEST( marker->kind==FD_BLOCK_MARKER_KIND_FOOTER );
  FD_TEST( !memcmp( marker->footer.bank_hash.uc, bank_hash.uc, sizeof(fd_hash_t) ) );
  FD_TEST( marker->footer.block_producer_time_nanos==987654321UL );
  FD_TEST( marker->footer.user_agent_len==5UL );
  FD_TEST( !memcmp( marker->footer.user_agent, "agave", 5UL ) );
  FD_TEST( !marker->footer.has_fast_final_cert  );
  FD_TEST( !marker->footer.has_final_cert       );
  FD_TEST( !marker->footer.has_skip_reward_cert  );
  FD_TEST( !marker->footer.has_notar_reward_cert );
}

static void
test_footer_with_certs( int has_notar_aggregate ) {
  fd_hash_t bank_hash = hash_of( 0x44 );
  fd_hash_t block_id  = hash_of( 0x55 );

  emit_reset();
  emit_preamble( FD_BLOCK_MARKER_SERDE_TAG_FOOTER, (ushort)0 ); /* length patched below */
  ulong payload_off = g_sz;
  emit_u8 ( 1 );                            /* VersionedBlockFooter::V1 */
  emit( bank_hash.uc, sizeof(fd_hash_t) );  /* bank_hash */
  emit_u64( 42UL );                         /* block_producer_time_nanos */
  emit_u8 ( 0 );                            /* empty user agent */

  emit_u8( 1 );                             /* block_final_cert: Some */
  emit_u64( 777UL );                        /* BlockFinalizationCert::slot */
  emit( block_id.uc, sizeof(fd_hash_t) );   /* BlockFinalizationCert::block_id */
  emit_votes_aggregate( 13UL, 0x7fUL );     /* final_aggregate, signer ranks 0-6 */
  emit_u8( (uchar)!!has_notar_aggregate );  /* notar_aggregate tag */
  if( has_notar_aggregate ) emit_votes_aggregate( 13UL, 0x1fUL ); /* signer ranks 0-4 */

  emit_u8( 1 );                             /* skip_reward_cert: Some */
  emit_u64( 775UL );                        /* SkipRewardCertificate::slot */
  emit_rep( 0xf3, 96UL );                   /* compressed signature */
  emit_cu16( 5 );                           /* bitmap byte count */
  emit_u8 ( 0 ); emit_u16( 13 );            /* base2 bitmap over 13 signers */
  emit_u8 ( 0xa5 ); emit_u8( 0x14 );        /* signer ranks 0, 2, 5, 7, 10, 12 */

  emit_u8( 1 );                             /* notar_reward_cert: Some */
  emit_u64( 776UL );                        /* NotarRewardCertificate::slot */
  emit( block_id.uc, sizeof(fd_hash_t) );   /* NotarRewardCertificate::block_id */
  emit_rep( 0xf4, 96UL );                   /* compressed signature */
  emit_cu16( 200 );                         /* bitmap byte count (ShortU16, 2 bytes) */
  emit_u8 ( 0 ); emit_u16( 1576 );          /* base2 bitmap over 1576 signers */
  emit_rep( 0xff, 197UL );                  /* every signer rank set */

  FD_STORE( ushort, g_buf+FD_BLOCK_MARKER_PREAMBLE_SZ-2UL, (ushort)(g_sz-payload_off) );

  fd_block_marker_t marker[1];
  FD_TEST( fd_block_marker_de( marker, g_buf, g_sz )==FD_BLOCK_MARKER_DE_SUCCESS );
  FD_TEST( marker->kind==FD_BLOCK_MARKER_KIND_FOOTER );
  FD_TEST( marker->footer.user_agent_len==0UL );

  if( has_notar_aggregate ) {
    /* slow finalization: final + notar certs */
    FD_TEST( !marker->footer.has_fast_final_cert && marker->footer.has_final_cert );
    FD_TEST( marker->footer.final_cert.slot==777UL );
    FD_TEST( set_is_range( marker->footer.final_cert.signer_set, 0UL, 7UL ) );
    FD_TEST( marker->footer.final_cert.nbits==13 );
    FD_TEST( marker->footer.notar_cert.slot==777UL );
    FD_TEST( !memcmp( marker->footer.notar_cert.block_id.uc, block_id.uc, sizeof(fd_hash_t) ) );
    FD_TEST( set_is_range( marker->footer.notar_cert.signer_set, 0UL, 5UL ) );
    FD_TEST( marker->footer.notar_cert.nbits==13 );
    FD_TEST( marker->footer.final_cert.sig[ 0 ]==0xc0 );
    for( ulong i=1UL; i<AG_BLS_SIG_COMPRESSED_SZ; i++ ) FD_TEST( !marker->footer.final_cert.sig[ i ] );
  } else {
    /* fast finalization */
    FD_TEST( marker->footer.has_fast_final_cert && !marker->footer.has_final_cert );
    FD_TEST( marker->footer.fast_final_cert.slot==777UL );
    FD_TEST( !memcmp( marker->footer.fast_final_cert.block_id.uc, block_id.uc, sizeof(fd_hash_t) ) );
    FD_TEST( set_is_range( marker->footer.fast_final_cert.signer_set, 0UL, 7UL ) );
    FD_TEST( marker->footer.fast_final_cert.nbits==13 );
    FD_TEST( marker->footer.fast_final_cert.sig[ 0 ]==0xc0 );
    for( ulong i=1UL; i<AG_BLS_SIG_COMPRESSED_SZ; i++ ) FD_TEST( !marker->footer.fast_final_cert.sig[ i ] );
  }

  fd_hash_t zero_id = hash_of( 0x00 );
  fd_block_footer_cert_t const * skip = &marker->footer.skip_reward_cert;
  FD_TEST( marker->footer.has_skip_reward_cert );
  FD_TEST( skip->slot==775UL );
  FD_TEST( !memcmp( skip->block_id.uc, zero_id.uc, sizeof(fd_hash_t) ) );
  for( ulong i=0UL; i<sizeof(skip->sig); i++ ) FD_TEST( skip->sig[ i ]==0xf3 );
  FD_TEST( skip->nbits==13 );
  ag_bls_set_t skip_want[ ag_bls_set_word_cnt ]; /* 0x14a5 */
  ag_bls_set_null( skip_want );
  ulong skip_ranks[ 6 ] = { 0UL, 2UL, 5UL, 7UL, 10UL, 12UL };
  for( ulong i=0UL; i<6UL; i++ ) ag_bls_set_insert( skip_want, skip_ranks[ i ] );
  FD_TEST( ag_bls_set_eq( skip->signer_set, skip_want ) );

  fd_block_footer_cert_t const * notar = &marker->footer.notar_reward_cert;
  FD_TEST( marker->footer.has_notar_reward_cert );
  FD_TEST( notar->slot==776UL );
  FD_TEST( !memcmp( notar->block_id.uc, block_id.uc, sizeof(fd_hash_t) ) );
  for( ulong i=0UL; i<sizeof(notar->sig); i++ ) FD_TEST( notar->sig[ i ]==0xf4 );
  FD_TEST( notar->nbits==1576 );
  FD_TEST( set_is_range( notar->signer_set, 0UL, 1576UL ) );

  /* and it re-encodes byte for byte: the 13 bit aggregates pack their
     ranks into one byte and zero fill the second */
  roundtrip( g_sz );

  /* every strict prefix of the marker is truncated */
  for( ulong sz=0UL; sz<g_sz; sz++ ) {
    FD_TEST( fd_block_marker_de( marker, g_buf, sz )==FD_BLOCK_MARKER_DE_ERR_SZ );
  }
}

/* footer_skip_cert_de builds a footer whose only cert is a skip reward
   cert carrying the given bitmap and returns the deserializer's error
   code. */

static int
footer_skip_cert_de( uchar const * bitmap,
                     ulong         bitmap_sz ) {
  emit_reset();
  emit_preamble( FD_BLOCK_MARKER_SERDE_TAG_FOOTER, (ushort)0 ); /* length patched below */
  ulong payload_off = g_sz;
  emit_u8 ( 1 );                /* VersionedBlockFooter::V1 */
  emit_rep( 0x66, 32UL );       /* bank_hash */
  emit_u64( 0UL );              /* block_producer_time_nanos */
  emit_u8 ( 0 );                /* empty user agent */
  emit_u8 ( 0 );                /* block_final_cert: None */
  emit_u8 ( 1 );                /* skip_reward_cert: Some */
  emit_u64( 775UL );            /* SkipRewardCertificate::slot */
  emit_rep( 0xf3, 96UL );       /* compressed signature */
  emit_cu16( (ushort)bitmap_sz );
  emit( bitmap, bitmap_sz );
  emit_u8 ( 0 );                /* notar_reward_cert: None */
  FD_STORE( ushort, g_buf+FD_BLOCK_MARKER_PREAMBLE_SZ-2UL, (ushort)(g_sz-payload_off) );

  fd_block_marker_t marker[1];
  return fd_block_marker_de( marker, g_buf, g_sz );
}

static void
test_reward_cert_bitmap_errors( void ) {
  uchar bitmap[ 512 ];

  /* well-formed base2 bitmap */
  bitmap[ 0 ] = 0;
  FD_STORE( ushort, bitmap+1UL, (ushort)13 );
  bitmap[ 3 ] = 0xa5; bitmap[ 4 ] = 0x14;
  FD_TEST( footer_skip_cert_de( bitmap, 5UL )==FD_BLOCK_MARKER_DE_SUCCESS );

  /* base3 bitmap version */
  bitmap[ 0 ] = 1;
  FD_TEST( footer_skip_cert_de( bitmap, 5UL )==FD_BLOCK_MARKER_DE_ERR_INVAL );
  bitmap[ 0 ] = 0;

  /* bitmap too short for its header */
  FD_TEST( footer_skip_cert_de( bitmap, 2UL )==FD_BLOCK_MARKER_DE_ERR_SZ );

  /* payload length inconsistent with the bit count */
  FD_TEST( footer_skip_cert_de( bitmap, 6UL )==FD_BLOCK_MARKER_DE_ERR_INVAL );

  /* bit count over AG_VAT_MAX */
  FD_STORE( ushort, bitmap+1UL, (ushort)(AG_VAT_MAX+1UL) );
  fd_memset( bitmap+3UL, 0, (AG_VAT_MAX+1UL+7UL)/8UL );
  FD_TEST( footer_skip_cert_de( bitmap, 3UL+(AG_VAT_MAX+1UL+7UL)/8UL )==FD_BLOCK_MARKER_DE_ERR_SZ );
}

static void
test_final_cert_bitmap_bound( void ) {
  /* a finalization cert aggregate bitmap over AG_BLS_SET_MAX
     signers is refused */
  emit_reset();
  emit_preamble( FD_BLOCK_MARKER_SERDE_TAG_FOOTER, (ushort)0 ); /* length patched below */
  ulong payload_off = g_sz;
  emit_u8 ( 1 );                /* VersionedBlockFooter::V1 */
  emit_rep( 0x66, 32UL );       /* bank_hash */
  emit_u64( 0UL );              /* block_producer_time_nanos */
  emit_u8 ( 0 );                /* empty user agent */
  emit_u8 ( 1 );                /* block_final_cert: Some */
  emit_u64( 777UL );            /* BlockFinalizationCert::slot */
  emit_rep( 0x55, 32UL );       /* BlockFinalizationCert::block_id */
  emit_votes_aggregate( AG_BLS_SET_MAX+1UL, 0UL );
  emit_u8 ( 0 );                /* notar_aggregate: None */
  emit_u8 ( 0 );                /* skip_reward_cert: None */
  emit_u8 ( 0 );                /* notar_reward_cert: None */
  FD_STORE( ushort, g_buf+FD_BLOCK_MARKER_PREAMBLE_SZ-2UL, (ushort)(g_sz-payload_off) );

  fd_block_marker_t marker[1];
  FD_TEST( fd_block_marker_de( marker, g_buf, g_sz )==FD_BLOCK_MARKER_DE_ERR_SZ );
}

static void
test_errors( void ) {
  fd_block_marker_t marker[1];

  /* nonzero marker flag */
  emit_reset();
  emit_u64( 1UL ); emit_u16( 1 ); emit_u8( FD_BLOCK_MARKER_SERDE_TAG_HEADER ); emit_u16( 41 ); emit_rep( 0, 41UL );
  FD_TEST( fd_block_marker_de( marker, g_buf, g_sz )==FD_BLOCK_MARKER_DE_ERR_INVAL );

  /* marker version other than V1 */
  emit_reset();
  emit_u64( 0UL ); emit_u16( 2 ); emit_u8( FD_BLOCK_MARKER_SERDE_TAG_HEADER ); emit_u16( 41 ); emit_rep( 0, 41UL );
  FD_TEST( fd_block_marker_de( marker, g_buf, g_sz )==FD_BLOCK_MARKER_DE_ERR_INVAL );

  /* genesis certificate tag is recognized but unsupported */
  emit_reset();
  emit_preamble( FD_BLOCK_MARKER_SERDE_TAG_GENESIS_CERT, (ushort)1 ); emit_u8( 0 );
  FD_TEST( fd_block_marker_de( marker, g_buf, g_sz )==FD_BLOCK_MARKER_DE_ERR_UNSUPPORTED );

  /* unknown tag */
  emit_reset();
  emit_preamble( (uchar)7, (ushort)1 ); emit_u8( 0 );
  FD_TEST( fd_block_marker_de( marker, g_buf, g_sz )==FD_BLOCK_MARKER_DE_ERR_INVAL );

  /* payload version other than V1 */
  emit_reset();
  emit_preamble( FD_BLOCK_MARKER_SERDE_TAG_HEADER, (ushort)41 );
  emit_u8( 2 ); emit_rep( 0, 40UL );
  FD_TEST( fd_block_marker_de( marker, g_buf, g_sz )==FD_BLOCK_MARKER_DE_ERR_INVAL );

  /* announced length exceeds the input */
  emit_reset();
  emit_preamble( FD_BLOCK_MARKER_SERDE_TAG_HEADER, (ushort)42 );
  emit_u8( 1 ); emit_rep( 0, 40UL );
  FD_TEST( fd_block_marker_de( marker, g_buf, g_sz )==FD_BLOCK_MARKER_DE_ERR_SZ );

  /* option tag out of range */
  emit_reset();
  emit_preamble( FD_BLOCK_MARKER_SERDE_TAG_FOOTER, (ushort)(1UL+32UL+8UL+1UL+1UL) );
  emit_u8( 1 ); emit_rep( 0x66, 32UL ); emit_u64( 0UL ); emit_u8( 0 );
  emit_u8( 2 ); /* block_final_cert tag */
  FD_TEST( fd_block_marker_de( marker, g_buf, g_sz )==FD_BLOCK_MARKER_DE_ERR_INVAL );

  /* LengthPrefixed is exact: a length prefix larger than the payload's
     serialized size is refused even when the bytes are present */
  emit_reset();
  emit_preamble( FD_BLOCK_MARKER_SERDE_TAG_HEADER, (ushort)42 );
  emit_u8( 1 ); emit_rep( 0, 40UL ); emit_u8( 0xee ); /* one byte of padding */
  FD_TEST( fd_block_marker_de( marker, g_buf, g_sz )==FD_BLOCK_MARKER_DE_ERR_SZ );

  emit_reset();
  emit_preamble( FD_BLOCK_MARKER_SERDE_TAG_UPDATE_PARENT, (ushort)42 );
  emit_u8( 1 ); emit_rep( 0, 40UL ); emit_u8( 0xee );
  FD_TEST( fd_block_marker_de( marker, g_buf, g_sz )==FD_BLOCK_MARKER_DE_ERR_SZ );

  emit_reset();
  emit_preamble( FD_BLOCK_MARKER_SERDE_TAG_FOOTER, (ushort)(1UL+32UL+8UL+1UL+3UL+1UL) );
  emit_u8( 1 ); emit_rep( 0x66, 32UL ); emit_u64( 0UL ); emit_u8( 0 );
  emit_u8( 0 ); emit_u8( 0 ); emit_u8( 0 ); /* all certs None */
  emit_u8( 0xee );                          /* one byte of padding */
  FD_TEST( fd_block_marker_de( marker, g_buf, g_sz )==FD_BLOCK_MARKER_DE_ERR_SZ );

  /* a footer that ends after its fixed fields is short of its option tags */
  emit_reset();
  emit_preamble( FD_BLOCK_MARKER_SERDE_TAG_FOOTER, (ushort)(1UL+32UL+8UL+1UL) );
  emit_u8( 1 ); emit_rep( 0x66, 32UL ); emit_u64( 0UL ); emit_u8( 0 );
  FD_TEST( fd_block_marker_de( marker, g_buf, g_sz )==FD_BLOCK_MARKER_DE_ERR_SZ );

  /* a reward cert that ends after its signature has no byte for its
     ShortU16, which is a short read; a non minimal ShortU16 is malformed */
  emit_reset();
  emit_preamble( FD_BLOCK_MARKER_SERDE_TAG_FOOTER, (ushort)(1UL+32UL+8UL+1UL+1UL+1UL+8UL+96UL) );
  emit_u8( 1 ); emit_rep( 0x66, 32UL ); emit_u64( 0UL ); emit_u8( 0 );
  emit_u8( 0 );                                            /* block_final_cert: None */
  emit_u8( 1 ); emit_u64( 775UL ); emit_rep( 0xf3, 96UL ); /* skip_reward_cert: Some, cut after the signature */
  FD_TEST( fd_block_marker_de( marker, g_buf, g_sz )==FD_BLOCK_MARKER_DE_ERR_SZ );

  emit_u8( 0x80 ); emit_u8( 0x00 );                        /* ShortU16 zero in two bytes */
  FD_STORE( ushort, g_buf+FD_BLOCK_MARKER_PREAMBLE_SZ-2UL, (ushort)(g_sz-FD_BLOCK_MARKER_PREAMBLE_SZ) );
  FD_TEST( fd_block_marker_de( marker, g_buf, g_sz )==FD_BLOCK_MARKER_DE_ERR_INVAL );

  /* notar_aggregate tag out of range, inside a BlockFinalizationCert */
  fd_hash_t block_id = hash_of( 0x42 );
  emit_reset();
  emit_preamble( FD_BLOCK_MARKER_SERDE_TAG_FOOTER, (ushort)0 ); /* length patched below */
  ulong payload_off = g_sz;
  emit_u8( 1 ); emit_rep( 0x66, 32UL ); emit_u64( 0UL ); emit_u8( 0 );
  emit_u8( 1 );                                 /* block_final_cert: Some */
  emit_u64( 7UL );                              /* BlockFinalizationCert::slot */
  emit( block_id.uc, sizeof(fd_hash_t) );       /* BlockFinalizationCert::block_id */
  emit_votes_aggregate( 11UL, 0x7fUL );         /* final_aggregate, signer ranks 0-6 */
  emit_u8( 2 );                                 /* notar_aggregate tag */
  FD_STORE( ushort, g_buf+FD_BLOCK_MARKER_PREAMBLE_SZ-2UL, (ushort)(g_sz-payload_off) );
  FD_TEST( fd_block_marker_de( marker, g_buf, g_sz )==FD_BLOCK_MARKER_DE_ERR_INVAL );

  /* a notar aggregate cut one byte short */
  emit_reset();
  emit_preamble( FD_BLOCK_MARKER_SERDE_TAG_FOOTER, (ushort)0 ); /* length patched below */
  payload_off = g_sz;
  emit_u8( 1 ); emit_rep( 0x66, 32UL ); emit_u64( 0UL ); emit_u8( 0 );
  emit_u8( 1 );                                 /* block_final_cert: Some */
  emit_u64( 7UL );                              /* BlockFinalizationCert::slot */
  emit( block_id.uc, sizeof(fd_hash_t) );       /* BlockFinalizationCert::block_id */
  emit_votes_aggregate( 11UL, 0x7fUL );         /* final_aggregate, signer ranks 0-6 */
  emit_u8( 1 );                                 /* notar_aggregate: Some */
  emit_votes_aggregate( 11UL, 0x7fUL );         /* notar_aggregate, signer ranks 0-6 */
  g_sz--;                                       /* drop the last bitmap byte */
  FD_STORE( ushort, g_buf+FD_BLOCK_MARKER_PREAMBLE_SZ-2UL, (ushort)(g_sz-payload_off) );
  FD_TEST( fd_block_marker_de( marker, g_buf, g_sz )==FD_BLOCK_MARKER_DE_ERR_SZ );
}

static void
test_ser( void ) {
  static uchar out[ FD_BLOCK_MARKER_SER_MAX ];
  fd_hash_t parent_id = hash_of( 0x11 );

  /* header round trips */
  emit_reset();
  emit_preamble( FD_BLOCK_MARKER_SERDE_TAG_HEADER, (ushort)41 );
  emit_u8 ( 1 );
  emit_u64( 1234UL );
  emit( parent_id.uc, sizeof(fd_hash_t) );
  roundtrip( g_sz );

  /* footer with no certs round trips */
  emit_reset();
  emit_preamble( FD_BLOCK_MARKER_SERDE_TAG_FOOTER, (ushort)(1UL+32UL+8UL+1UL+5UL+3UL) );
  emit_u8 ( 1 );
  emit_rep( 0x33, 32UL );
  emit_u64( 987654321UL );
  emit_u8 ( 5 ); emit( "agave", 5UL );
  emit_u8 ( 0 ); emit_u8( 0 ); emit_u8( 0 );
  roundtrip( g_sz );

  /* empty user agent round trips */
  emit_reset();
  emit_preamble( FD_BLOCK_MARKER_SERDE_TAG_FOOTER, (ushort)(1UL+32UL+8UL+1UL+3UL) );
  emit_u8 ( 1 );
  emit_rep( 0x44, 32UL );
  emit_u64( 0UL );
  emit_u8 ( 0 );
  emit_u8 ( 0 ); emit_u8( 0 ); emit_u8( 0 );
  roundtrip( g_sz );

  /* the kinds we never produce are refused */
  fd_block_marker_t marker[1];
  fd_memset( marker, 0, sizeof(fd_block_marker_t) );
  marker->kind = FD_BLOCK_MARKER_KIND_UPDATE_PARENT;
  FD_TEST( !fd_block_marker_ser( marker, out ) );
  marker->kind = FD_BLOCK_MARKER_KIND_GENESIS_CERT;
  FD_TEST( !fd_block_marker_ser( marker, out ) );

  /* nor is an over-long user agent */
  fd_memset( marker, 0, sizeof(fd_block_marker_t) );
  marker->kind                  = FD_BLOCK_MARKER_KIND_FOOTER;
  marker->footer.user_agent_len = FD_BLOCK_FOOTER_USER_AGENT_MAX+1UL;
  FD_TEST( !fd_block_marker_ser( marker, out ) );

  /* nor is a footer that claims both finalization shapes */
  fd_memset( marker, 0, sizeof(fd_block_marker_t) );
  marker->kind                       = FD_BLOCK_MARKER_KIND_FOOTER;
  marker->footer.has_fast_final_cert = 1;
  marker->footer.has_final_cert      = 1;
  FD_TEST( !fd_block_marker_ser( marker, out ) );

  /* nor a slow finalization whose two certs name different slots */
  fd_memset( marker, 0, sizeof(fd_block_marker_t) );
  marker->kind                   = FD_BLOCK_MARKER_KIND_FOOTER;
  marker->footer.has_final_cert  = 1;
  marker->footer.final_cert.slot = 7UL;
  marker->footer.notar_cert.slot = 8UL;
  FD_TEST( !fd_block_marker_ser( marker, out ) );
}

/* emit_cert_footer lays out a footer marker carrying whichever of the
   three certificates is asked for, in the wincode order the Agave
   BlockFooterV1 declares: each Option is a tag immediately followed by
   its own body, not three tags and then three bodies.  Bitmaps go out
   at the width they carry, so a notar reward cert with an empty signer
   set at width 1576 re-encodes to exactly these bytes. */

#define CERT_NONE       (0)
#define CERT_FAST_FINAL (1)
#define CERT_SLOW_FINAL (2)

static void
emit_cert_footer( int final_kind,
                  int skip_reward,
                  int notar_reward ) {
  fd_hash_t bank_hash = hash_of( 0x44 );
  fd_hash_t block_id  = hash_of( 0x55 );

  emit_reset();
  emit_preamble( FD_BLOCK_MARKER_SERDE_TAG_FOOTER, (ushort)0 ); /* length patched below */
  ulong payload_off = g_sz;
  emit_u8 ( 1 );                            /* VersionedBlockFooter::V1  */
  emit( bank_hash.uc, sizeof(fd_hash_t) );  /* bank_hash                 */
  emit_u64( 42UL );                         /* block_producer_time_nanos */
  emit_u8 ( 3 ); emit( "fd/", 3UL );        /* block_user_agent          */

  emit_u8( final_kind!=CERT_NONE );         /* block_final_cert */
  if( final_kind!=CERT_NONE ) {
    emit_u64( 777UL );
    emit( block_id.uc, sizeof(fd_hash_t) );
    emit_votes_aggregate( 13UL, 0x1a05UL ); /* final_aggregate, ranks 0, 2, 10, 11, 12 */
    emit_u8( final_kind==CERT_SLOW_FINAL );
    if( final_kind==CERT_SLOW_FINAL ) emit_votes_aggregate( 9UL, 0x101UL ); /* notar_aggregate, ranks 0, 8 */
  }

  emit_u8( !!skip_reward );                 /* skip_reward_cert */
  if( skip_reward ) emit_reward_cert( 769UL, NULL, 0xf3, 13UL, 0x14a5UL );

  emit_u8( !!notar_reward );                /* notar_reward_cert */
  if( notar_reward ) emit_reward_cert( 769UL, &block_id, 0xf4, 1576UL, 0UL );

  FD_STORE( ushort, g_buf+FD_BLOCK_MARKER_PREAMBLE_SZ-2UL, (ushort)(g_sz-payload_off) );
}

/* test_ser_certs asserts the serializer reproduces a hand encoded
   footer byte for byte, for every combination of the three optional
   certificates.  Round tripping alone would not catch a serializer and
   deserializer that drifted together. */

static void
test_ser_certs( void ) {
  for( int final_kind=CERT_NONE; final_kind<=CERT_SLOW_FINAL; final_kind++ ) {
    for( int skip_reward=0; skip_reward<2; skip_reward++ ) {
      for( int notar_reward=0; notar_reward<2; notar_reward++ ) {
        emit_cert_footer( final_kind, skip_reward, notar_reward );
        roundtrip( g_sz );
      }
    }
  }

  /* the interleaving is load bearing: a footer that carries only the
     notar reward cert must put two zero tags in front of it, and the
     one that carries only the finalization cert must put its two zero
     tags behind the cert body, not in front. */
  emit_cert_footer( CERT_NONE, 0, 1 );
  ulong ua_end = FD_BLOCK_MARKER_PREAMBLE_SZ+1UL+32UL+8UL+1UL+3UL;
  FD_TEST( g_buf[ ua_end     ]==0 ); /* block_final_cert:  None */
  FD_TEST( g_buf[ ua_end+1UL ]==0 ); /* skip_reward_cert:  None */
  FD_TEST( g_buf[ ua_end+2UL ]==1 ); /* notar_reward_cert: Some */

  emit_cert_footer( CERT_FAST_FINAL, 0, 0 );
  FD_TEST( g_buf[ ua_end ]==1 );     /* block_final_cert: Some */
  FD_TEST( g_buf[ g_sz-2UL ]==0 );   /* skip_reward_cert:  None */
  FD_TEST( g_buf[ g_sz-1UL ]==0 );   /* notar_reward_cert: None */
}

/* fill_max_cert_footer builds the widest footer we can emit: a slow
   finalization, both reward certs, every one of AG_VAT_MAX ranks
   signing, and a full length user agent. */

static void
fill_max_cert_footer( fd_block_marker_t * marker ) {
  fd_memset( marker, 0, sizeof(fd_block_marker_t) );
  marker->kind = FD_BLOCK_MARKER_KIND_FOOTER;

  fd_block_footer_t * footer = &marker->footer;
  fd_memset( footer->bank_hash.uc, 0x5a, sizeof(fd_hash_t) );
  footer->block_producer_time_nanos = ULONG_MAX;
  footer->user_agent_len            = FD_BLOCK_FOOTER_USER_AGENT_MAX;
  fd_memset( footer->user_agent, 'u', FD_BLOCK_FOOTER_USER_AGENT_MAX );

  /* a fixed 96 byte signature (the compressed G2 point at infinity);
     nothing on this path decompresses it */
  uchar csig[ AG_BLS_SIG_COMPRESSED_SZ ];
  fd_memset( csig, 0, sizeof(csig) ); csig[ 0 ] = 0xc0;

  footer->has_final_cert   = 1;
  footer->final_cert.slot  = 777UL;
  footer->notar_cert.slot  = 777UL;
  fd_memset( footer->notar_cert.block_id.uc, 0x55, sizeof(fd_hash_t) );
  memcpy( footer->final_cert.sig, csig, sizeof(csig) );
  memcpy( footer->notar_cert.sig, csig, sizeof(csig) );
  footer->final_cert.nbits = (ushort)AG_VAT_MAX;
  footer->notar_cert.nbits = (ushort)AG_VAT_MAX;

  footer->has_skip_reward_cert   = 1;
  footer->skip_reward_cert.slot  = 769UL;
  footer->skip_reward_cert.nbits = (ushort)AG_VAT_MAX;
  fd_memset( footer->skip_reward_cert.sig, 0xf3, AG_BLS_SIG_COMPRESSED_SZ );

  footer->has_notar_reward_cert   = 1;
  footer->notar_reward_cert.slot  = 769UL;
  footer->notar_reward_cert.nbits = (ushort)AG_VAT_MAX;
  fd_memset( footer->notar_reward_cert.block_id.uc, 0x55, sizeof(fd_hash_t) );
  fd_memset( footer->notar_reward_cert.sig,         0xf4, AG_BLS_SIG_COMPRESSED_SZ );

  /* every one of AG_VAT_MAX ranks signs all four certs */
  ag_bls_set_full( footer->final_cert.signer_set        );
  ag_bls_set_full( footer->notar_cert.signer_set        );
  ag_bls_set_full( footer->skip_reward_cert.signer_set  );
  ag_bls_set_full( footer->notar_reward_cert.signer_set );
}

/* test_ser_max asserts FD_BLOCK_MARKER_SER_MAX really bounds the widest
   footer we emit, which is what sizes the leader footer frag. */

static void
test_ser_max( void ) {
  static uchar out[ FD_BLOCK_MARKER_SER_MAX ];

  fd_block_marker_t marker[1];
  fill_max_cert_footer( marker );

  ulong out_sz = fd_block_marker_ser( marker, out );
  FD_LOG_NOTICE(( "widest footer is %lu bytes, bound is %lu", out_sz, FD_BLOCK_MARKER_SER_MAX ));
  FD_TEST( out_sz==1806UL );
  FD_TEST( out_sz<=FD_BLOCK_MARKER_SER_MAX );

  /* the marker length prefix is a u16 */
  FD_TEST( out_sz-FD_BLOCK_MARKER_PREAMBLE_SZ<=(ulong)USHORT_MAX );

  /* and it reads back */
  uchar csig[ AG_BLS_SIG_COMPRESSED_SZ ];
  fd_memset( csig, 0, sizeof(csig) ); csig[ 0 ] = 0xc0;
  FD_TEST( fd_block_marker_de( marker, out, out_sz )==FD_BLOCK_MARKER_DE_SUCCESS );
  FD_TEST( marker->kind==FD_BLOCK_MARKER_KIND_FOOTER );
  FD_TEST( marker->footer.user_agent_len==FD_BLOCK_FOOTER_USER_AGENT_MAX );
  FD_TEST( marker->footer.has_final_cert && !marker->footer.has_fast_final_cert );
  FD_TEST( marker->footer.final_cert.nbits       ==(ushort)AG_VAT_MAX );
  FD_TEST( marker->footer.notar_cert.nbits       ==(ushort)AG_VAT_MAX );
  FD_TEST( marker->footer.skip_reward_cert.nbits ==(ushort)AG_VAT_MAX );
  FD_TEST( marker->footer.notar_reward_cert.nbits==(ushort)AG_VAT_MAX );
  FD_TEST( !memcmp( marker->footer.final_cert.sig, csig, sizeof(csig) ) );
  FD_TEST( !memcmp( marker->footer.notar_cert.sig, csig, sizeof(csig) ) );
  FD_TEST( set_is_range( marker->footer.final_cert.signer_set,        0UL, AG_VAT_MAX ) );
  FD_TEST( set_is_range( marker->footer.notar_cert.signer_set,        0UL, AG_VAT_MAX ) );
  FD_TEST( set_is_range( marker->footer.skip_reward_cert.signer_set,  0UL, AG_VAT_MAX ) );
  FD_TEST( set_is_range( marker->footer.notar_reward_cert.signer_set, 0UL, AG_VAT_MAX ) );

  /* a width past AG_VAT_MAX is refused */
  fill_max_cert_footer( marker );
  marker->footer.skip_reward_cert.nbits = (ushort)(AG_VAT_MAX+1UL);
  FD_TEST( !fd_block_marker_ser( marker, out ) );

  fill_max_cert_footer( marker );
  marker->footer.final_cert.nbits = (ushort)(AG_VAT_MAX+1UL);
  FD_TEST( !fd_block_marker_ser( marker, out ) );
}

/* test_ser_signature exercises the constructors and the signature path
   on a real BLS point rather than the point at infinity: the footer
   cert holds the compressed 96 bytes, the wire carries them verbatim,
   and they decompress back to the aggregate's point. */

static void
test_ser_signature( void ) {
  static uchar out[ FD_BLOCK_MARKER_SER_MAX ];

  ag_bls_sec_t sec;
  ag_bls_sig_t sig;
  ag_bls_sec_derive( &sec, (uchar const *)"fd_block_marker footer serializer seed", 38UL );
  ag_bls_sec_sign( &sec, (uchar const *)"footer", 6UL, &sig );

  ag_bls_agg_t agg[1];
  memset( agg, 0, sizeof(ag_bls_agg_t) );
  ag_bls_set_insert( agg->set, 4UL ); agg->sig = sig;
  fd_hash_t bid = hash_of( 0x77 );

  fd_block_marker_t marker[1];
  fd_memset( marker, 0, sizeof(fd_block_marker_t) );
  marker->kind                       = FD_BLOCK_MARKER_KIND_FOOTER;
  marker->footer.has_fast_final_cert = fd_block_footer_cert_from_agg( &marker->footer.fast_final_cert, 99UL, bid.uc, agg );
  FD_TEST( marker->footer.has_fast_final_cert );
  FD_TEST( marker->footer.fast_final_cert.nbits==5 );

  ulong out_sz = fd_block_marker_ser( marker, out );
  FD_TEST( out_sz );

  /* the emitted signature is the cert's, and decompresses back to the
     aggregate's point */
  ulong sig_off = FD_BLOCK_MARKER_PREAMBLE_SZ+1UL+32UL+8UL+1UL+1UL+8UL+32UL;
  FD_TEST( !memcmp( out+sig_off, marker->footer.fast_final_cert.sig, AG_BLS_SIG_COMPRESSED_SZ ) );
  uchar expected[ 192 ];
  { blst_p2_affine a[1]; blst_p2_to_affine( a, &agg->sig ); blst_p2_affine_serialize( expected, a ); }
  uchar decompressed[ 192 ];
  FD_TEST( !fd_bls12_381_g2_decompress_syscall( decompressed, out+sig_off, 1 ) );
  FD_TEST( !memcmp( decompressed, expected, sizeof(decompressed) ) );

  /* and the whole marker reads back to the same cert */
  fd_block_marker_t rt[1];
  FD_TEST( fd_block_marker_de( rt, out, out_sz )==FD_BLOCK_MARKER_DE_SUCCESS );
  FD_TEST( rt->footer.has_fast_final_cert );
  FD_TEST( rt->footer.fast_final_cert.slot==99UL );
  FD_TEST( !memcmp( rt->footer.fast_final_cert.sig, marker->footer.fast_final_cert.sig, AG_BLS_SIG_COMPRESSED_SZ ) );
  FD_TEST( set_is_range( rt->footer.fast_final_cert.signer_set, 4UL, 5UL ) );
  FD_TEST( rt->footer.fast_final_cert.nbits==5 );
  FD_TEST( !memcmp( rt->footer.fast_final_cert.block_id.uc, bid.uc, sizeof(fd_hash_t) ) );

  /* the constructors refuse an empty aggregate, and a reward cert
     without a block_id keeps it zero */
  fd_block_footer_cert_t c;
  memset( agg, 0, sizeof(ag_bls_agg_t) );
  FD_TEST( !fd_block_footer_cert_from_agg( &c, 1UL, NULL, agg ) );

  memset( agg, 0, sizeof(ag_bls_agg_t) );
  ag_bls_set_insert( agg->set, 4UL ); agg->sig = sig;
  fd_block_footer_cert_t rc;
  FD_TEST( fd_block_footer_cert_from_agg( &rc, 5UL, NULL, agg ) );
  FD_TEST( rc.slot==5UL && rc.nbits==5 && set_is_range( rc.signer_set, 4UL, 5UL ) );
  fd_hash_t zero_id = hash_of( 0x00 );
  FD_TEST( !memcmp( rc.block_id.uc, zero_id.uc, sizeof(fd_hash_t) ) );
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
  test_reward_cert_bitmap_errors();
  test_final_cert_bitmap_bound();
  test_errors();
  test_ser();
  test_ser_certs();
  test_ser_max();
  test_ser_signature();

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
