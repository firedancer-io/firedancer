/* Round trip test for the alpenglow block marker encoders in fd_poh.c.

   These encoders produce bytes that a REMOTE agave validator parses, so
   getting the layout wrong is not a crash, it is a block that silently
   does not land.  There is no compiler-enforced link between
   fd_poh_ag_header_encode and the parser that consumes its output
   (fd_sched.c on our side, wincode SchemaRead on agave's), so this test
   is the link.

   The layout is verified against agave's derives in
   entry/src/block_component.rs, NOT against the doc comment in that
   file: the comment draws each variant WITHOUT the inner Versioned*
   enum tag byte, and the derive emits one.

     u64  entry count      == 0    BlockComponent discriminator
     u16  marker version   == 1    VersionedBlockMarker,  tag_encoding u16
     u8   variant                  BlockMarkerV1
     u16  length                   LengthPrefixed<T>.len, size of the inner
                                     value INCLUDING its version byte
     u8   inner version    == 1    VersionedBlock{Header,Footer},
                                     tag_encoding u8
     ...  payload */

#include "fd_poh.h"
#include "../replay/fd_block_marker.h"

#include <stddef.h> /* offsetof */

FD_STATIC_ASSERT( FD_POH_AG_MARKER_HDR_SZ==offsetof( fd_block_marker_t, data ), marker_hdr_sz );
FD_STATIC_ASSERT( FD_POH_AG_MARKER_HDR_SZ+sizeof(fd_block_header_t)==AG_BLOCK_HEADER_V1_SZ, header_sz );

/* The variant ids must match fd_block_marker_variant, which in turn
   matches the declaration order of agave's BlockMarkerV1. */
FD_STATIC_ASSERT( FD_POH_AG_VARIANT_FOOTER       ==FOOTER,              variant_footer );
FD_STATIC_ASSERT( FD_POH_AG_VARIANT_HEADER       ==HEADER,              variant_header );
FD_STATIC_ASSERT( FD_POH_AG_VARIANT_UPDATE_PARENT==UPDATE_PARENT,       variant_update );
FD_STATIC_ASSERT( FD_POH_AG_VARIANT_GENESIS_CERT ==GENESIS_CERTIFICATE, variant_genesis );

static void
test_header( void ) {
  uchar     buf[ FD_POH_AG_MARKER_MAX ];
  fd_hash_t pbid;
  for( ulong i=0UL; i<32UL; i++ ) pbid.uc[ i ] = (uchar)i;

  ulong sz = fd_poh_ag_header_encode( buf, 123456UL, &pbid );
  FD_TEST( sz==AG_BLOCK_HEADER_V1_SZ );

  /* The entry count must be zero: that is the ONLY thing distinguishing
     a marker from an entry batch on the wire. */
  FD_TEST( FD_LOAD( ulong, buf )==0UL );

  fd_block_marker_t const * m = (fd_block_marker_t const *)fd_type_pun_const( buf );
  FD_TEST( m->marker_flag==0UL                );
  FD_TEST( m->version    ==FD_POH_AG_MARKER_VER );
  FD_TEST( m->variant    ==HEADER             );
  FD_TEST( m->length     ==sizeof(fd_block_header_t) ); /* includes the version byte */

  FD_TEST( m->data.header.header_version    ==1        );
  FD_TEST( m->data.header.v1.parent_slot    ==123456UL );
  FD_TEST( !memcmp( m->data.header.v1.parent_block_id.uc, pbid.uc, 32UL ) );
}

static void
test_footer_no_cert( void ) {
  uchar     buf[ FD_POH_AG_MARKER_MAX ];
  fd_hash_t bank_hash;
  for( ulong i=0UL; i<32UL; i++ ) bank_hash.uc[ i ] = (uchar)(32UL+i);

  ulong sz = fd_poh_ag_footer_encode( buf, &bank_hash, 1786730126000000000L, NULL, 0UL );

  /* version + bank_hash + time + ua_len + three absent options. */
  ulong inner_sz = 1UL+32UL+8UL+1UL+1UL+1UL+1UL;
  FD_TEST( sz==FD_POH_AG_MARKER_HDR_SZ+inner_sz );

  fd_block_marker_t const * m = (fd_block_marker_t const *)fd_type_pun_const( buf );
  FD_TEST( m->marker_flag==0UL       );
  FD_TEST( m->variant    ==FOOTER    );
  FD_TEST( m->length     ==inner_sz  );
  FD_TEST( m->data.footer.footer_version==1 );
  FD_TEST( !memcmp( m->data.footer.v1.bank_hash.uc, bank_hash.uc, 32UL ) );
  FD_TEST( m->data.footer.v1.block_producer_time_nanos==1786730126000000000UL );
  FD_TEST( m->data.footer.v1.block_user_agent_length==0 );

  /* Walk the option bytes the way fd_sched.c's parse_footer_final_cert
     does, and check it finds "no cert" rather than running off the end. */
  uchar const * p   = buf+FD_POH_AG_MARKER_HDR_SZ;
  ulong         off = 1UL+32UL+8UL+1UL;
  FD_TEST( inner_sz>=off );
  off += (ulong)p[ off-1UL ]; /* user agent */
  FD_TEST( inner_sz>=off+1UL );
  FD_TEST( p[ off ]==0 ); /* Option<FinalCertificate>::None */
}

static void
test_footer_with_cert( void ) {
  uchar buf[ FD_POH_AG_MARKER_MAX ];
  fd_hash_t bank_hash; memset( bank_hash.uc, 0xAB, 32UL );

  /* A minimal fast-finalization cert body, as ag_block_final_cert_de
     expects it: slot | block_id | (compressed sig | u16 bitmap len |
     bitmap) | has_notar. */
  uchar cert[ 8UL+32UL+96UL+2UL+3UL+1UL ];
  memset( cert, 0, sizeof(cert) );
  FD_STORE( ulong,  cert,                    77UL );
  FD_STORE( ushort, cert+8UL+32UL+96UL,      (ushort)3 );
  cert[ sizeof(cert)-1UL ] = 0; /* no notar aggregate */

  ulong sz = fd_poh_ag_footer_encode( buf, &bank_hash, 1L, cert, sizeof(cert) );

  ulong inner_sz = 1UL+32UL+8UL+1UL+1UL+sizeof(cert)+1UL+1UL;
  FD_TEST( sz==FD_POH_AG_MARKER_HDR_SZ+inner_sz );

  fd_block_marker_t const * m = (fd_block_marker_t const *)fd_type_pun_const( buf );
  FD_TEST( m->length==inner_sz );

  uchar const * p   = buf+FD_POH_AG_MARKER_HDR_SZ;
  ulong         off = 1UL+32UL+8UL+1UL;
  off += (ulong)p[ off-1UL ];
  FD_TEST( p[ off ]==1 ); /* Option<FinalCertificate>::Some */
  off++;
  FD_TEST( !memcmp( p+off, cert, sizeof(cert) ) );
  FD_TEST( inner_sz==off+sizeof(cert)+2UL ); /* skip + notar reward, both None */
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  test_header();
  test_footer_no_cert();
  test_footer_with_cert();

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
