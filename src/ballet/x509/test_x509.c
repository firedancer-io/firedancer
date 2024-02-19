#include "fd_x509_mock.h"
#include "../../util/fd_util.h"

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  fd_rng_t _rng[1]; fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, 0U, 0UL ) );

  for( ulong j=0UL; j<100000UL; j++ ) {

    /* Params */
    uchar public_key[ 32 ];
    for( ulong j=0UL; j<32UL; j++ ) public_key[ j ] = fd_rng_uchar( rng );
    ulong hash = fd_hash( 0UL, public_key, 32UL );

    /* Generate certificate */
    uchar cert[ FD_X509_MOCK_CERT_SZ ];
    fd_x509_mock_cert( cert, public_key );

    /* Ensure pubkey matches */
    FD_TEST( fd_hash( 0UL, public_key, 32UL )==hash );  /* orig same */
    uchar const * extracted = fd_x509_mock_pubkey( cert, FD_X509_MOCK_CERT_SZ );
    FD_TEST( 0==memcmp( extracted, public_key, 32UL ) );  /* extract same */

    for( ulong k=0UL; k<64UL; k++ ) {

      /* Corrupt some bytes */
      uint off = fd_rng_uint_roll( rng, FD_X509_MOCK_CERT_SZ );
      uint val = fd_rng_uchar( rng );
      cert[ off ] = (uchar)( cert[ off ] ^ val );
      extracted = fd_x509_mock_pubkey( cert, FD_X509_MOCK_CERT_SZ );
      
      /* Extraction must fail if we flipped a bit in the template */
      FD_TEST( (!extracted) == ( ( (off<0x64) | (off>=0x84) ) & (!!val) ) );
      cert[ off ] = (uchar)( cert[ off ] ^ val );

    }

  }

  fd_rng_delete( fd_rng_leave( rng ) );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
