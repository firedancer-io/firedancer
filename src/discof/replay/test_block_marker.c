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

/* emit_votes_aggregate emits a VotesAggregate whose signature is the
   compressed G2 point at infinity (so it decompresses) and whose base2
   bitmap sets signer ranks [0,signer_cnt) out of nbits. */

static void
emit_votes_aggregate( ulong nbits,
                      ulong signer_cnt ) {
  emit_u8 ( 0xc0 ); emit_rep( 0x00, 95UL );  /* compressed signature: infinity */
  ulong payload = (nbits+7UL)/8UL;
  emit_u16( (ushort)(3UL+payload) );         /* bitmap byte count */
  emit_u8 ( 0 );                             /* base2 bitmap */
  emit_u16( (ushort)nbits );                 /* bit count */
  ulong off = g_sz;
  emit_rep( 0x00, payload );
  for( ulong i=0UL; i<signer_cnt; i++ ) g_buf[ off+(i>>3) ] = (uchar)( g_buf[ off+(i>>3) ] | (1U<<(i&7U)) );
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
  emit_votes_aggregate( 13UL, 7UL );        /* final_aggregate, signer ranks 0-6 */
  emit_u8( (uchar)!!has_notar_aggregate );  /* notar_aggregate tag */
  if( has_notar_aggregate ) emit_votes_aggregate( 13UL, 5UL ); /* signer ranks 0-4 */

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
    FD_TEST( marker->footer.final_cert.agg_sig.bitmask[ 0 ]==0x7fUL );
    FD_TEST( marker->footer.notar_cert.slot==777UL );
    FD_TEST( !memcmp( marker->footer.notar_cert.block_hash, block_id.uc, sizeof(fd_hash_t) ) );
    FD_TEST( marker->footer.notar_cert.agg_sig.bitmask[ 0 ]==0x1fUL );
  } else {
    /* fast finalization */
    FD_TEST( marker->footer.has_fast_final_cert && !marker->footer.has_final_cert );
    FD_TEST( marker->footer.fast_final_cert.slot==777UL );
    FD_TEST( !memcmp( marker->footer.fast_final_cert.block_hash, block_id.uc, sizeof(fd_hash_t) ) );
    FD_TEST( marker->footer.fast_final_cert.agg_sig.bitmask[ 0 ]==0x7fUL );
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
  emit_votes_aggregate( n, 7UL );               /* final_aggregate, signer ranks 0-6 */
  emit_u8 ( 1 );                                /* notar_aggregate: Some */
  emit_votes_aggregate( n, 7UL );               /* notar_aggregate, signer ranks 0-6 */
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
  for( ulong i=0UL; i<7UL; i++ ) FD_TEST( ag_bls_agg_is_signer( &final.agg_sig, i ) );
  FD_TEST( !ag_bls_agg_is_signer( &final.agg_sig, 7UL ) );
  for( ulong i=0UL; i<7UL; i++ ) FD_TEST( ag_bls_agg_is_signer( &notar.agg_sig, i ) );

  /* trailing bytes are not the cert's */
  g_buf[ off ] = 0xaa;
  FD_TEST( fd_block_final_cert_de( &fast_final, &final, &notar, g_buf, off+1UL, &consumed )==0 );
  FD_TEST( consumed==off );

  FD_TEST( fd_block_final_cert_de( &fast_final, &final, &notar, g_buf, off-1UL, NULL )==-1 );

  /* fast finalization: the notar aggregate is absent */
  g_sz = 8UL+sizeof(fd_hash_t);
  emit_votes_aggregate( n, 9UL );               /* final_aggregate, signer ranks 0-8 */
  emit_u8 ( 0 );                                /* notar_aggregate: None */
  ulong off2 = g_sz;

  FD_TEST( fd_block_final_cert_de( &fast_final, &final, &notar, g_buf, off2, &consumed )==1 );
  FD_TEST( consumed==off2 );
  FD_TEST( fast_final.slot==7UL );
  FD_TEST( !memcmp( fast_final.block_hash, block_id.uc, sizeof(fd_hash_t) ) );
  for( ulong i=0UL; i<9UL; i++ ) FD_TEST( ag_bls_agg_is_signer( &fast_final.agg_sig, i ) );
  FD_TEST( !ag_bls_agg_is_signer( &fast_final.agg_sig, 9UL ) );

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
  static uchar out[ 512 ];

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
  static uchar out[ 512 ];
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

  /* a footer carrying a cert is not emitted */
  fd_block_marker_t marker[1];
  fd_memset( marker, 0, sizeof(fd_block_marker_t) );
  marker->variant                    = FOOTER;
  marker->footer.has_fast_final_cert = 1;
  FD_TEST( fd_block_marker_ser( marker, out, sizeof(out), NULL )==FD_BLOCK_MARKER_SER_ERR_UNSUPPORTED );

  /* nor is an over-long user agent */
  fd_memset( marker, 0, sizeof(fd_block_marker_t) );
  marker->variant               = FOOTER;
  marker->footer.user_agent_len = FD_BLOCK_FOOTER_USER_AGENT_MAX+1UL;
  FD_TEST( fd_block_marker_ser( marker, out, sizeof(out), NULL )==FD_BLOCK_MARKER_SER_ERR_UNSUPPORTED );

  /* nor are the variants we never produce */
  fd_memset( marker, 0, sizeof(fd_block_marker_t) );
  marker->variant = UPDATE_PARENT;
  FD_TEST( fd_block_marker_ser( marker, out, sizeof(out), NULL )==FD_BLOCK_MARKER_SER_ERR_UNSUPPORTED );
  marker->variant = GENESIS_CERTIFICATE;
  FD_TEST( fd_block_marker_ser( marker, out, sizeof(out), NULL )==FD_BLOCK_MARKER_SER_ERR_UNSUPPORTED );

  /* the widest footer we emit fits the bound */
  fd_memset( marker, 0, sizeof(fd_block_marker_t) );
  marker->variant               = FOOTER;
  marker->footer.user_agent_len = FD_BLOCK_FOOTER_USER_AGENT_MAX;
  ulong out_sz = 0UL;
  FD_TEST( fd_block_marker_ser( marker, out, sizeof(out), &out_sz )==FD_BLOCK_MARKER_SER_SUCCESS );
  FD_TEST( out_sz<=sizeof(out) );
  FD_TEST( fd_block_marker_de( marker, out, out_sz, NULL )==FD_BLOCK_MARKER_DE_SUCCESS );
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

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
