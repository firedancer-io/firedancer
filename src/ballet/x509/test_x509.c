#include "fd_x509_mock.h"
#include "../../util/fd_util.h"

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  fd_rng_t _rng[1]; fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, 0U, 0UL ) );

  /* Params */

  uchar public_key[ 32 ];
  for( ulong j=0UL; j<32UL; j++ ) public_key[ j ] = fd_rng_uchar( rng );

  /* Generate certificate */

  uchar cert[ FD_X509_MOCK_CERT_SZ ];
  fd_x509_mock_cert( cert, public_key );

  FD_LOG_HEXDUMP_DEBUG(( "cert", cert, FD_X509_MOCK_CERT_SZ ));

  /* Clean up */

  fd_rng_delete( fd_rng_leave( rng ) );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
