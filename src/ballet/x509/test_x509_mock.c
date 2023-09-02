#include "fd_x509_common.h"
#include "fd_x509_mock.h"
#include "fd_x509_cert_parser.h"

#include "../ed25519/fd_ed25519.h"

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  fd_rng_t _rng[1]; fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, 0U, 0UL ) );
  fd_sha512_t _sha[1]; fd_sha512_t * sha = fd_sha512_join( fd_sha512_new( _sha ) );

  /* Params */

  uchar private_key[ 32 ];
  for( ulong j=0UL; j<32UL; j++ ) private_key[ j ] = fd_rng_uchar( rng );
  ulong serial = fd_rng_ulong( rng );

  /* Generate certificate */

  uchar cert[ FD_X509_MOCK_CERT_SZ ];
  fd_x509_mock_cert( cert, private_key, serial, sha );

  FD_LOG_HEXDUMP_DEBUG(( "cert", cert, FD_X509_MOCK_CERT_SZ ));

  /* Parse generated certificate */

  cert_parsing_ctx parsed[1] = {{0}};
  FD_TEST( 0==parse_x509_cert( parsed, cert, FD_X509_MOCK_CERT_SZ ) );

  FD_TEST( parsed->tbs_start                       ==0x03U );
  FD_TEST( parsed->tbs_len                         ==0xa7U );
  FD_TEST( parsed->version                         ==0x02U );
  FD_TEST( parsed->serial_start                    ==0x0dU );
  FD_TEST( parsed->serial_len                      ==0x08U );
  FD_TEST( parsed->tbs_sig_alg_start               ==0x15U );
  FD_TEST( parsed->tbs_sig_alg_len                 ==0x07U );
  FD_TEST( parsed->tbs_sig_alg_oid_start           ==0x17U );
  FD_TEST( parsed->tbs_sig_alg_oid_len             ==0x05U );
  FD_TEST( parsed->tbs_sig_alg_oid_params_len      ==0x00U );
  FD_TEST( parsed->issuer_start                    ==0x1cU );
  FD_TEST( parsed->issuer_len                      ==0x13U );
  FD_TEST( parsed->not_before         ==2166042218463232UL );
  FD_TEST( parsed->not_after          ==4503603939115008UL );
  FD_TEST( parsed->subject_start                   ==0x51U );
  FD_TEST( parsed->subject_len                     ==0x02U );
  FD_TEST( parsed->sig_start                       ==0xb1U );
  FD_TEST( parsed->sig_len                         ==0x43U );
  FD_TEST( parsed->sig_alg_params.ed25519.r_raw_off==0xb4U );
  FD_TEST( parsed->sig_alg_params.ed25519.r_raw_len==0x20U );
  FD_TEST( parsed->sig_alg_params.ed25519.s_raw_off==0xd4U );
  FD_TEST( parsed->sig_alg_params.ed25519.s_raw_len==0x20U );
  FD_TEST( !!parsed->empty_subject             );
  FD_TEST(  !parsed->subject_issuer_identical  );
  FD_TEST( parsed->spki_alg ==SPKI_ALG_ED25519 );
  FD_TEST( parsed->sig_alg  ==SIG_ALG_ED25519  );
  FD_TEST( parsed->hash_alg ==HASH_ALG_SHA512  );

  /* Verify signature */

  uchar const *  pubkey = cert + parsed->spki_alg_params.ed25519.ed25519_raw_pub_off;
  uchar expected_pubkey[ 32 ];
  fd_ed25519_public_from_private( expected_pubkey, private_key, sha );
  FD_TEST( 0==memcmp( pubkey, expected_pubkey, 32UL ) );

  uchar const * sig = cert + parsed->sig_alg_params.ed25519.r_raw_off;
  int vfy_ok = fd_ed25519_verify( cert + parsed->tbs_start,
                                  parsed->tbs_len,
                                  sig, pubkey, sha );
  FD_TEST( vfy_ok==FD_ED25519_SUCCESS );

  fd_sha512_delete( fd_sha512_leave( sha ) );
  fd_rng_delete( fd_rng_leave( rng ) );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
