#include "fd_block_marker.h"

#include "../../ballet/bls/fd_bls12_381.h"

/* Test vectors are hand-encoded per the wincode wire format in Agave
   entry/src/block_component.rs (all integers little endian). */

static uchar g_buf[ 4096UL ];
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

/* emit_preamble emits marker_flag | version | variant | length. */

static void
emit_preamble( uchar  variant,
               ushort length ) {
  emit_u64( 0UL );
  emit_u16( (ushort)1 );
  emit_u8 ( variant   );
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

/* emit_votes_aggregate emits a VotesAggregate whose signature is the
   compressed G2 point at infinity (so it decompresses, and compresses
   back to the same bytes) and whose base2 bitmap, under a u16 byte
   count, names the ranks set in mask.  The serializer always emits a
   bitmap one bit past the highest signing rank, so only an nbits of
   exactly that re-encodes to these bytes. */

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
  emit_preamble( FOOTER, (ushort)0 ); /* length patched below */
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
  ulong             consumed = 0UL;
  FD_TEST( fd_block_marker_de( marker, g_buf, g_sz, &consumed )==FD_BLOCK_MARKER_DE_SUCCESS );
  FD_TEST( consumed==g_sz );
  FD_TEST( marker->variant==FOOTER );
  FD_TEST( marker->footer.user_agent_len==0UL );

  if( has_notar_aggregate ) {
    /* slow finalization: final + notar certs */
    FD_TEST( !marker->footer.has_fast_final_cert && marker->footer.has_final_cert );
    FD_TEST( marker->footer.final_cert.slot==777UL );
    FD_TEST( marker->footer.final_cert.agg.bitmask[ 0 ]==0x7fUL );
    FD_TEST( marker->footer.notar_cert.slot==777UL );
    FD_TEST( !memcmp( marker->footer.notar_cert.block_hash, block_id.uc, sizeof(fd_hash_t) ) );
    FD_TEST( marker->footer.notar_cert.agg.bitmask[ 0 ]==0x1fUL );
  } else {
    /* fast finalization */
    FD_TEST( marker->footer.has_fast_final_cert && !marker->footer.has_final_cert );
    FD_TEST( marker->footer.fast_final_cert.slot==777UL );
    FD_TEST( !memcmp( marker->footer.fast_final_cert.block_hash, block_id.uc, sizeof(fd_hash_t) ) );
    FD_TEST( marker->footer.fast_final_cert.agg.bitmask[ 0 ]==0x7fUL );
  }

  fd_hash_t zero_id = hash_of( 0x00 );
  fd_reward_cert_t const * skip = &marker->footer.skip_reward_cert;
  FD_TEST( marker->footer.has_skip_reward_cert );
  FD_TEST( skip->slot==775UL );
  FD_TEST( !memcmp( skip->block_id.uc, zero_id.uc, sizeof(fd_hash_t) ) );
  for( ulong i=0UL; i<sizeof(skip->sig); i++ ) FD_TEST( skip->sig[ i ]==0xf3 );
  FD_TEST( skip->nbits==13 );
  FD_TEST( skip->signer_set[ 0 ]==0x14a5UL );
  for( ulong w=1UL; w<FD_REWARD_CERT_SET_WORDS; w++ ) FD_TEST( !skip->signer_set[ w ] );

  fd_reward_cert_t const * notar = &marker->footer.notar_reward_cert;
  FD_TEST( marker->footer.has_notar_reward_cert );
  FD_TEST( notar->slot==776UL );
  FD_TEST( !memcmp( notar->block_id.uc, block_id.uc, sizeof(fd_hash_t) ) );
  for( ulong i=0UL; i<sizeof(notar->sig); i++ ) FD_TEST( notar->sig[ i ]==0xf4 );
  FD_TEST( notar->nbits==1576 );
  for( ulong r=0UL; r<AG_VAT_MAX; r++ ) {
    int set = !!( notar->signer_set[ r>>6 ] & (1UL<<(r&63UL)) );
    FD_TEST( set==(r<1576UL) );
  }

  /* every strict prefix of the marker is truncated */
  for( ulong sz=0UL; sz<g_sz; sz++ ) {
    int err = fd_block_marker_de( marker, g_buf, sz, NULL );
    FD_TEST( err==FD_BLOCK_MARKER_DE_ERR_TRUNCATED || err==FD_BLOCK_MARKER_DE_ERR_MALFORMED );
  }
}

/* footer_skip_cert_de builds a footer whose only cert is a skip reward
   cert carrying the given bitmap and returns the deserializer's error
   code. */

static int
footer_skip_cert_de( uchar const * bitmap,
                     ulong         bitmap_sz ) {
  emit_reset();
  emit_preamble( FOOTER, (ushort)0 ); /* length patched below */
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
  return fd_block_marker_de( marker, g_buf, g_sz, NULL );
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
  FD_TEST( footer_skip_cert_de( bitmap, 5UL )==FD_BLOCK_MARKER_DE_ERR_MALFORMED );
  bitmap[ 0 ] = 0;

  /* bitmap too short for its header */
  FD_TEST( footer_skip_cert_de( bitmap, 2UL )==FD_BLOCK_MARKER_DE_ERR_MALFORMED );

  /* payload length inconsistent with the bit count */
  FD_TEST( footer_skip_cert_de( bitmap, 6UL )==FD_BLOCK_MARKER_DE_ERR_MALFORMED );

  /* bit count over AG_VAT_MAX */
  FD_STORE( ushort, bitmap+1UL, (ushort)(AG_VAT_MAX+1UL) );
  fd_memset( bitmap+3UL, 0, (AG_VAT_MAX+1UL+7UL)/8UL );
  FD_TEST( footer_skip_cert_de( bitmap, 3UL+(AG_VAT_MAX+1UL+7UL)/8UL )==FD_BLOCK_MARKER_DE_ERR_MALFORMED );
}

static void
test_final_cert_bitmap_bound( void ) {
  /* a finalization cert aggregate bitmap over AG_BLS_SIGNERS_MAX
     signers is malformed */
  emit_reset();
  emit_preamble( FOOTER, (ushort)0 ); /* length patched below */
  ulong payload_off = g_sz;
  emit_u8 ( 1 );                /* VersionedBlockFooter::V1 */
  emit_rep( 0x66, 32UL );       /* bank_hash */
  emit_u64( 0UL );              /* block_producer_time_nanos */
  emit_u8 ( 0 );                /* empty user agent */
  emit_u8 ( 1 );                /* block_final_cert: Some */
  emit_u64( 777UL );            /* BlockFinalizationCert::slot */
  emit_rep( 0x55, 32UL );       /* BlockFinalizationCert::block_id */
  emit_votes_aggregate( AG_BLS_SIGNERS_MAX+1UL, 0UL );
  emit_u8 ( 0 );                /* notar_aggregate: None */
  emit_u8 ( 0 );                /* skip_reward_cert: None */
  emit_u8 ( 0 );                /* notar_reward_cert: None */
  FD_STORE( ushort, g_buf+FD_BLOCK_MARKER_PREAMBLE_SZ-2UL, (ushort)(g_sz-payload_off) );

  fd_block_marker_t marker[1];
  FD_TEST( fd_block_marker_de( marker, g_buf, g_sz, NULL )==FD_BLOCK_MARKER_DE_ERR_MALFORMED );
}

/* test_final_cert_de exercises fd_block_final_cert_de on its own, on a
   BlockFinalizationCert that is not wrapped in a footer. */

static void
test_final_cert_de( void ) {
  ulong     n        = 11UL;
  fd_hash_t block_id = hash_of( 0x42 );

  emit_reset();
  emit_u64( 7UL );                              /* BlockFinalizationCert::slot */
  emit( block_id.uc, sizeof(fd_hash_t) );       /* BlockFinalizationCert::block_id */
  emit_votes_aggregate( n, 0x7fUL );            /* final_aggregate, signer ranks 0-6 */
  emit_u8 ( 1 );                                /* notar_aggregate: Some */
  emit_votes_aggregate( n, 0x7fUL );            /* notar_aggregate, signer ranks 0-6 */
  ulong off = g_sz;

  ag_cert_fast_final_t fast_final;
  ag_cert_final_t      final;
  ag_cert_notar_t      notar;

  /* slow finalization: final + notar */
  ulong consumed;
  FD_TEST( fd_block_final_cert_de( &fast_final, &final, &notar, g_buf, off, &consumed )==0 );
  FD_TEST( consumed==off );
  FD_TEST( final.slot==7UL );
  FD_TEST( notar.slot==7UL );
  FD_TEST( !memcmp( notar.block_hash, block_id.uc, sizeof(fd_hash_t) ) );
  for( ulong i=0UL; i<7UL; i++ ) FD_TEST( ag_bls_agg_is_signer( &final.agg, i ) );
  FD_TEST( !ag_bls_agg_is_signer( &final.agg, 7UL ) );
  for( ulong i=0UL; i<7UL; i++ ) FD_TEST( ag_bls_agg_is_signer( &notar.agg, i ) );

  /* trailing bytes are not the cert's */
  g_buf[ off ] = 0xaa;
  FD_TEST( fd_block_final_cert_de( &fast_final, &final, &notar, g_buf, off+1UL, &consumed )==0 );
  FD_TEST( consumed==off );

  FD_TEST( fd_block_final_cert_de( &fast_final, &final, &notar, g_buf, off-1UL, NULL )==-1 );

  /* fast finalization: the notar aggregate is absent */
  g_sz = 8UL+sizeof(fd_hash_t);
  emit_votes_aggregate( n, 0x1ffUL );           /* final_aggregate, signer ranks 0-8 */
  emit_u8 ( 0 );                                /* notar_aggregate: None */
  ulong off2 = g_sz;

  FD_TEST( fd_block_final_cert_de( &fast_final, &final, &notar, g_buf, off2, &consumed )==1 );
  FD_TEST( consumed==off2 );
  FD_TEST( fast_final.slot==7UL );
  FD_TEST( !memcmp( fast_final.block_hash, block_id.uc, sizeof(fd_hash_t) ) );
  for( ulong i=0UL; i<9UL; i++ ) FD_TEST( ag_bls_agg_is_signer( &fast_final.agg, i ) );
  FD_TEST( !ag_bls_agg_is_signer( &fast_final.agg, 9UL ) );

  /* notar_aggregate tag out of range */
  g_buf[ off2-1UL ] = 2;
  FD_TEST( fd_block_final_cert_de( &fast_final, &final, &notar, g_buf, off2, NULL )==-1 );
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

/* roundtrip re-encodes the marker occupying g_buf[0,marker_sz) and
   asserts the encoding is byte identical, then that every shorter output
   buffer is refused. */

static void
roundtrip( ulong marker_sz ) {
  static uchar out[ FD_BLOCK_FOOTER_SER_MAX ];

  fd_block_marker_t marker[1];
  FD_TEST( fd_block_marker_de( marker, g_buf, marker_sz, NULL )==FD_BLOCK_MARKER_DE_SUCCESS );

  ulong out_sz = 0UL;
  FD_TEST( fd_block_marker_ser( marker, out, sizeof(out), &out_sz )==FD_BLOCK_MARKER_SER_SUCCESS );
  FD_TEST( out_sz==marker_sz );
  FD_TEST( !memcmp( out, g_buf, marker_sz ) );

  for( ulong sz=0UL; sz<out_sz; sz++ ) {
    FD_TEST( fd_block_marker_ser( marker, out, sz, NULL )==FD_BLOCK_MARKER_SER_ERR_NOSPACE );
  }
}

static void
test_ser( void ) {
  static uchar out[ FD_BLOCK_FOOTER_SER_MAX ];
  fd_hash_t parent_id = hash_of( 0x11 );

  /* header round trips */
  emit_reset();
  emit_preamble( HEADER, (ushort)41 );
  emit_u8 ( 1 );
  emit_u64( 1234UL );
  emit( parent_id.uc, sizeof(fd_hash_t) );
  roundtrip( g_sz );

  /* footer with no certs round trips */
  emit_reset();
  emit_preamble( FOOTER, (ushort)(1UL+32UL+8UL+1UL+5UL+3UL) );
  emit_u8 ( 1 );
  emit_rep( 0x33, 32UL );
  emit_u64( 987654321UL );
  emit_u8 ( 5 ); emit( "agave", 5UL );
  emit_u8 ( 0 ); emit_u8( 0 ); emit_u8( 0 );
  roundtrip( g_sz );

  /* empty user agent round trips */
  emit_reset();
  emit_preamble( FOOTER, (ushort)(1UL+32UL+8UL+1UL+3UL) );
  emit_u8 ( 1 );
  emit_rep( 0x44, 32UL );
  emit_u64( 0UL );
  emit_u8 ( 0 );
  emit_u8 ( 0 ); emit_u8( 0 ); emit_u8( 0 );
  roundtrip( g_sz );

  /* the variants we never produce are refused */
  fd_block_marker_t marker[1];
  fd_memset( marker, 0, sizeof(fd_block_marker_t) );
  marker->variant = UPDATE_PARENT;
  FD_TEST( fd_block_marker_ser( marker, out, sizeof(out), NULL )==FD_BLOCK_MARKER_SER_ERR_UNSUPPORTED );
  marker->variant = GENESIS_CERTIFICATE;
  FD_TEST( fd_block_marker_ser( marker, out, sizeof(out), NULL )==FD_BLOCK_MARKER_SER_ERR_UNSUPPORTED );

  /* nor is an over-long user agent */
  fd_memset( marker, 0, sizeof(fd_block_marker_t) );
  marker->variant               = FOOTER;
  marker->footer.user_agent_len = FD_BLOCK_FOOTER_USER_AGENT_MAX+1UL;
  FD_TEST( fd_block_marker_ser( marker, out, sizeof(out), NULL )==FD_BLOCK_MARKER_SER_ERR_UNSUPPORTED );

  /* nor is a footer that claims both finalization shapes */
  fd_memset( marker, 0, sizeof(fd_block_marker_t) );
  marker->variant                    = FOOTER;
  marker->footer.has_fast_final_cert = 1;
  marker->footer.has_final_cert      = 1;
  FD_TEST( fd_block_marker_ser( marker, out, sizeof(out), NULL )==FD_BLOCK_MARKER_SER_ERR_MALFORMED );

  /* nor a slow finalization whose two certs name different slots */
  fd_memset( marker, 0, sizeof(fd_block_marker_t) );
  marker->variant                = FOOTER;
  marker->footer.has_final_cert  = 1;
  marker->footer.final_cert.slot = 7UL;
  marker->footer.notar_cert.slot = 8UL;
  FD_TEST( fd_block_marker_ser( marker, out, sizeof(out), NULL )==FD_BLOCK_MARKER_SER_ERR_MALFORMED );
}

/* emit_cert_footer lays out a footer marker carrying whichever of the
   three certificates is asked for, in the wincode order the Agave
   BlockFooterV1 declares: each Option is a tag immediately followed by
   its own body, not three tags and then three bodies.  All bitmaps are
   canonical (one bit past the highest signing rank) so that the encoding
   is exactly what the serializer produces. */

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
  emit_preamble( FOOTER, (ushort)0 ); /* length patched below */
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
  marker->variant = FOOTER;

  fd_block_footer_t * footer = &marker->footer;
  fd_memset( footer->bank_hash.uc, 0x5a, sizeof(fd_hash_t) );
  footer->block_producer_time_nanos = ULONG_MAX;
  footer->user_agent_len            = FD_BLOCK_FOOTER_USER_AGENT_MAX;
  fd_memset( footer->user_agent, 'u', FD_BLOCK_FOOTER_USER_AGENT_MAX );

  /* the compressed G2 point at infinity is the only signature this test
     can name without a keypair, and it decompresses */
  uchar csig[ 96 ];
  fd_memset( csig, 0, sizeof(csig) ); csig[ 0 ] = 0xc0;

  footer->has_final_cert  = 1;
  footer->final_cert.slot = 777UL;
  footer->notar_cert.slot = 777UL;
  fd_memset( footer->notar_cert.block_hash, 0x55, sizeof(ag_block_hash_t) );
  FD_TEST( !fd_bls12_381_g2_decompress_syscall( footer->final_cert.agg.sig, csig, 1 ) );
  FD_TEST( !fd_bls12_381_g2_decompress_syscall( footer->notar_cert.agg.sig, csig, 1 ) );
  for( ulong r=0UL; r<AG_VAT_MAX; r++ ) {
    signer_set_insert( footer->final_cert.agg.bitmask, r );
    signer_set_insert( footer->notar_cert.agg.bitmask, r );
  }

  footer->has_skip_reward_cert   = 1;
  footer->skip_reward_cert.slot  = 769UL;
  footer->skip_reward_cert.nbits = (ushort)AG_VAT_MAX;
  fd_memset( footer->skip_reward_cert.sig,        0xf3, AG_BLS_SIG_COMPRESSED_SZ );
  fd_memset( footer->skip_reward_cert.signer_set, 0xff, sizeof(footer->skip_reward_cert.signer_set) );

  footer->has_notar_reward_cert   = 1;
  footer->notar_reward_cert.slot  = 769UL;
  footer->notar_reward_cert.nbits = (ushort)AG_VAT_MAX;
  fd_memset( footer->notar_reward_cert.block_id.uc, 0x55, sizeof(fd_hash_t) );
  fd_memset( footer->notar_reward_cert.sig,         0xf4, AG_BLS_SIG_COMPRESSED_SZ );
  fd_memset( footer->notar_reward_cert.signer_set,  0xff, sizeof(footer->notar_reward_cert.signer_set) );
}

/* test_ser_max asserts FD_BLOCK_FOOTER_SER_MAX really bounds the widest
   footer we emit, which is what sizes the leader footer frag. */

static void
test_ser_max( void ) {
  static uchar out[ FD_BLOCK_FOOTER_SER_MAX ];

  fd_block_marker_t marker[1];
  fill_max_cert_footer( marker );

  ulong out_sz = 0UL;
  FD_TEST( fd_block_marker_ser( marker, out, sizeof(out), &out_sz )==FD_BLOCK_MARKER_SER_SUCCESS );
  FD_LOG_NOTICE(( "widest footer is %lu bytes, bound is %lu", out_sz, FD_BLOCK_FOOTER_SER_MAX ));
  FD_TEST( out_sz<=FD_BLOCK_FOOTER_SER_MAX );

  /* the marker length prefix is a u16 */
  FD_TEST( out_sz-FD_BLOCK_MARKER_PREAMBLE_SZ<=(ulong)USHORT_MAX );

  /* and it reads back */
  ulong consumed = 0UL;
  FD_TEST( fd_block_marker_de( marker, out, out_sz, &consumed )==FD_BLOCK_MARKER_DE_SUCCESS );
  FD_TEST( consumed==out_sz );
  FD_TEST( marker->footer.user_agent_len==FD_BLOCK_FOOTER_USER_AGENT_MAX );
  FD_TEST( marker->footer.has_final_cert && !marker->footer.has_fast_final_cert );
  FD_TEST( marker->footer.skip_reward_cert.nbits ==(ushort)AG_VAT_MAX );
  FD_TEST( marker->footer.notar_reward_cert.nbits==(ushort)AG_VAT_MAX );
  for( ulong r=0UL; r<AG_VAT_MAX; r++ ) {
    FD_TEST( ag_bls_agg_is_signer( &marker->footer.final_cert.agg, r ) );
    FD_TEST( ag_bls_agg_is_signer( &marker->footer.notar_cert.agg, r ) );
    FD_TEST( marker->footer.skip_reward_cert.signer_set [ r>>6 ] & (1UL<<(r&63UL)) );
    FD_TEST( marker->footer.notar_reward_cert.signer_set[ r>>6 ] & (1UL<<(r&63UL)) );
  }

  /* one byte short of the bound is not enough */
  fill_max_cert_footer( marker );
  FD_TEST( fd_block_marker_ser( marker, out, out_sz-1UL, NULL )==FD_BLOCK_MARKER_SER_ERR_NOSPACE );

  /* a rank the footer bound does not cover is refused rather than
     silently overrunning it */
  fill_max_cert_footer( marker );
  signer_set_insert( marker->footer.final_cert.agg.bitmask, AG_VAT_MAX );
  FD_TEST( fd_block_marker_ser( marker, out, sizeof(out), NULL )==FD_BLOCK_MARKER_SER_ERR_UNSUPPORTED );

  fill_max_cert_footer( marker );
  marker->footer.skip_reward_cert.nbits = (ushort)(AG_VAT_MAX+1UL);
  FD_TEST( fd_block_marker_ser( marker, out, sizeof(out), NULL )==FD_BLOCK_MARKER_SER_ERR_UNSUPPORTED );
}

/* test_ser_signature exercises the aggregate signature path on a real
   BLS point rather than the point at infinity: what a cert holds is the
   decompressed signature, and the footer has to compress it back to the
   96 bytes it came from. */

static void
test_ser_signature( void ) {
  static uchar out[ FD_BLOCK_FOOTER_SER_MAX ];

  ag_bls_sec_t sec;
  ag_bls_sig_t sig;
  ag_bls_sec_derive( sec, (uchar const *)"fd_block_marker footer serializer seed", 38UL );
  ag_bls_sec_sign( sec, sig, (uchar const *)"footer", 6UL );

  fd_block_marker_t marker[1];
  fd_memset( marker, 0, sizeof(fd_block_marker_t) );
  marker->variant                        = FOOTER;
  marker->footer.has_fast_final_cert     = 1;
  marker->footer.fast_final_cert.slot    = 99UL;
  ag_bls_agg_zero( &marker->footer.fast_final_cert.agg );
  ag_bls_agg_add( &marker->footer.fast_final_cert.agg, 4UL, sig );

  ulong out_sz = 0UL;
  FD_TEST( fd_block_marker_ser( marker, out, sizeof(out), &out_sz )==FD_BLOCK_MARKER_SER_SUCCESS );

  /* the emitted signature decompresses back to the aggregate's */
  ulong sig_off = FD_BLOCK_MARKER_PREAMBLE_SZ+1UL+32UL+8UL+1UL+1UL+8UL+32UL;
  uchar decompressed[ 192 ];
  FD_TEST( !fd_bls12_381_g2_decompress_syscall( decompressed, out+sig_off, 1 ) );
  FD_TEST( !memcmp( decompressed, marker->footer.fast_final_cert.agg.sig, sizeof(decompressed) ) );

  /* and the whole marker reads back to the same aggregate */
  fd_block_marker_t rt[1];
  FD_TEST( fd_block_marker_de( rt, out, out_sz, NULL )==FD_BLOCK_MARKER_DE_SUCCESS );
  FD_TEST( rt->footer.has_fast_final_cert );
  FD_TEST( rt->footer.fast_final_cert.slot==99UL );
  FD_TEST( ag_bls_agg_is_signer( &rt->footer.fast_final_cert.agg, 4UL ) );
  FD_TEST( ag_bls_agg_signer_cnt( &rt->footer.fast_final_cert.agg )==1UL );
  FD_TEST( !memcmp( rt->footer.fast_final_cert.agg.sig, marker->footer.fast_final_cert.agg.sig, sizeof(ag_bls_sig_t) ) );

  /* a signature that is not a G2 point cannot be emitted */
  fd_memset( marker->footer.fast_final_cert.agg.sig, 0x11, sizeof(ag_bls_sig_t) );
  FD_TEST( fd_block_marker_ser( marker, out, sizeof(out), NULL )==FD_BLOCK_MARKER_SER_ERR_MALFORMED );
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
  test_final_cert_de();
  test_errors();
  test_ser();
  test_ser_certs();
  test_ser_max();
  test_ser_signature();

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
