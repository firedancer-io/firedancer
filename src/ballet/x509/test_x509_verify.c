#include "fd_x509.h"
#include "fd_x509_verify.h"
#include "fd_x509_ca_store.h"
#include "../../util/fd_util.h"

#include <string.h>

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  /* Test 1: Parse zero-length input */
  {
    uchar buf[ 1 ];
    fd_x509_cert_info_t info;
    FD_TEST( fd_x509_cert_parse( buf, 0UL, &info )!=0 );
    FD_LOG_INFO(( "OK: parse zero-length returns non-zero" ));
  }

  /* Test 2: Parse 64 bytes of garbage (0xFF) */
  {
    uchar garbage[ 64 ];
    memset( garbage, 0xFF, 64 );
    fd_x509_cert_info_t info;
    FD_TEST( fd_x509_cert_parse( garbage, 64UL, &info )!=0 );
    FD_LOG_INFO(( "OK: parse garbage returns non-zero" ));
  }

  /* Test 3: Parse too-short valid-looking DER */
  {
    uchar short_der[ 5 ] = { 0x30, 0x03, 0x02, 0x01, 0x00 };
    fd_x509_cert_info_t info;
    FD_TEST( fd_x509_cert_parse( short_der, 5UL, &info )!=0 );
    FD_LOG_INFO(( "OK: parse too-short DER returns non-zero" ));
  }

  /* Test 4: Exact match */
  {
    fd_x509_cert_info_t info;
    memset( &info, 0, sizeof(info) );
    info.san_dns_cnt = 1;
    info.san_dns[0].name     = "example.com";
    info.san_dns[0].name_len = 11;
    FD_TEST( fd_x509_san_matches( &info, "example.com", 11UL )==1 );
    FD_LOG_INFO(( "OK: exact SAN match" ));
  }

  /* Test 5: No match */
  {
    fd_x509_cert_info_t info;
    memset( &info, 0, sizeof(info) );
    info.san_dns_cnt = 1;
    info.san_dns[0].name     = "example.com";
    info.san_dns[0].name_len = 11;
    FD_TEST( fd_x509_san_matches( &info, "other.com", 9UL )==0 );
    FD_LOG_INFO(( "OK: SAN no match" ));
  }

  /* Test 6: Wildcard match */
  {
    fd_x509_cert_info_t info;
    memset( &info, 0, sizeof(info) );
    info.san_dns_cnt = 1;
    info.san_dns[0].name     = "*.example.com";
    info.san_dns[0].name_len = 13;
    FD_TEST( fd_x509_san_matches( &info, "foo.example.com", 15UL )==1 );
    FD_LOG_INFO(( "OK: wildcard SAN match" ));
  }

  /* Test 7: Wildcard no deep match */
  {
    fd_x509_cert_info_t info;
    memset( &info, 0, sizeof(info) );
    info.san_dns_cnt = 1;
    info.san_dns[0].name     = "*.example.com";
    info.san_dns[0].name_len = 13;
    FD_TEST( fd_x509_san_matches( &info, "a.b.example.com", 15UL )==0 );
    FD_LOG_INFO(( "OK: wildcard no deep match" ));
  }

  /* Test 8: Wildcard no bare match */
  {
    fd_x509_cert_info_t info;
    memset( &info, 0, sizeof(info) );
    info.san_dns_cnt = 1;
    info.san_dns[0].name     = "*.example.com";
    info.san_dns[0].name_len = 13;
    FD_TEST( fd_x509_san_matches( &info, "example.com", 11UL )==0 );
    FD_LOG_INFO(( "OK: wildcard no bare match" ));
  }

  /* Test 9: Multiple SANs, second matches */
  {
    fd_x509_cert_info_t info;
    memset( &info, 0, sizeof(info) );
    info.san_dns_cnt = 2;
    info.san_dns[0].name     = "other.com";
    info.san_dns[0].name_len = 9;
    info.san_dns[1].name     = "example.com";
    info.san_dns[1].name_len = 11;
    FD_TEST( fd_x509_san_matches( &info, "example.com", 11UL )==1 );
    FD_LOG_INFO(( "OK: multiple SANs, second matches" ));
  }

  /* Test 10: Empty hostname */
  {
    fd_x509_cert_info_t info;
    memset( &info, 0, sizeof(info) );
    info.san_dns_cnt = 1;
    info.san_dns[0].name     = "example.com";
    info.san_dns[0].name_len = 11;
    FD_TEST( fd_x509_san_matches( &info, "", 0UL )==0 );
    FD_LOG_INFO(( "OK: empty hostname returns 0" ));
  }

  /* Test 11: Empty store find returns NULL */
  {
    fd_x509_ca_store_t store;
    memset( &store, 0, sizeof(store) );
    uchar query[ 4 ] = { 0x30, 0x02, 0x01, 0x00 };
    FD_TEST( fd_x509_ca_store_find( &store, query, 4UL )==NULL );
    FD_LOG_INFO(( "OK: empty store find returns NULL" ));
  }

  /* Test 12: Store with one entry, match */
  {
    fd_x509_ca_store_t store;
    memset( &store, 0, sizeof(store) );
    uchar subject_bytes[ 8 ] = { 0x30, 0x06, 0x31, 0x04, 0x0C, 0x02, 0x43, 0x41 };
    ulong subject_len = 8;
    store.cnt = 1;
    memcpy( store.entries[0].subject, subject_bytes, subject_len );
    store.entries[0].subject_len = subject_len;
    FD_TEST( fd_x509_ca_store_find( &store, subject_bytes, subject_len )!=NULL );
    FD_LOG_INFO(( "OK: store find with matching subject" ));
  }

  /* Test 13: Store with one entry, no match */
  {
    fd_x509_ca_store_t store;
    memset( &store, 0, sizeof(store) );
    uchar subject_bytes[ 8 ] = { 0x30, 0x06, 0x31, 0x04, 0x0C, 0x02, 0x43, 0x41 };
    ulong subject_len = 8;
    store.cnt = 1;
    memcpy( store.entries[0].subject, subject_bytes, subject_len );
    store.entries[0].subject_len = subject_len;
    uchar other[ 4 ] = { 0x30, 0x02, 0x01, 0xFF };
    FD_TEST( fd_x509_ca_store_find( &store, other, 4UL )==NULL );
    FD_LOG_INFO(( "OK: store find with non-matching subject returns NULL" ));
  }

  /* Test 14: Empty chain returns non-zero error */
  {
    fd_x509_ca_store_t store;
    memset( &store, 0, sizeof(store) );
    int err = fd_x509_verify_chain( NULL, NULL, 0UL, &store, "example.com", 11UL );
    FD_TEST( err!=FD_X509_VERIFY_OK );
    FD_LOG_INFO(( "OK: empty chain returns error" ));
  }

  /* Test 15: Chain with garbage cert returns FD_X509_VERIFY_ERR_PARSE */
  {
    uchar garbage[ 64 ];
    memset( garbage, 0xFF, 64 );
    uchar const * chain_der[ 1 ]    = { garbage };
    ulong         chain_der_sz[ 1 ] = { 64UL };
    fd_x509_ca_store_t store;
    memset( &store, 0, sizeof(store) );
    int err = fd_x509_verify_chain( chain_der, chain_der_sz, 1UL, &store, "example.com", 11UL );
    FD_TEST( err==FD_X509_VERIFY_ERR_PARSE );
    FD_LOG_INFO(( "OK: garbage cert returns ERR_PARSE" ));
  }

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
