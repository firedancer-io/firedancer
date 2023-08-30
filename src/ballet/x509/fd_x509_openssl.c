#include "fd_x509_openssl.h"
#include <openssl/asn1.h>

#if !FD_HAS_OPENSSL
#error "fd_x509 requires OpenSSL"
#endif

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include "../../util/net/fd_ip4.h"

/* Example cert:

   Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            ee:c3:85:8c:ec:a9:7b:45
        Signature Algorithm: ED25519
        Validity
            Not Before: Jan  1 00:00:00 1975 GMT
            Not After : Jan  1 00:00:00 4096 GMT
        Subject Public Key Info:
            Public Key Algorithm: ED25519
                ED25519 Public-Key:
                pub:
                    e3:41:83:55:1f:3d:92:0b:62:2c:54:10:74:8e:20:
                    ca:b2:1b:b3:fb:b6:5a:fd:7d:62:ee:ee:53:8e:e4:
                    da:7e
        X509v3 extensions:
            X509v3 Subject Alternative Name:
                DNS:localhost
    Signature Algorithm: ED25519
         ee:28:ca:94:37:db:c6:b8:cf:9e:32:ef:c4:ca:f0:5d:5b:2e:
         94:e0:49:6f:4d:da:06:26:d9:87:9b:bd:d5:64:7b:6f:de:ca:
         7c:96:ab:cb:32:26:56:53:cc:46:8d:dc:69:49:ce:7a:6d:10:
         42:3d:14:4f:95:c8:e9:6f:3d:0d */

X509 *
fd_x509_gen_solana_cert( EVP_PKEY * pkey ) {
  X509 * x = X509_new();
  if( FD_UNLIKELY( !x ) ) {
    FD_LOG_WARNING(( "X509_new() failed" ));
    goto cleanup0;
  }

  X509_set_version( x, 2 );

  /* Generate serial number */
  long serial;
  if( FD_UNLIKELY( 1!=RAND_bytes( (uchar *)&serial, sizeof(long) ) ) ) {
    FD_LOG_WARNING(( "RAND_bytes() failed" ));
    goto cleanup1;
  }
  ASN1_INTEGER_set( X509_get_serialNumber(x), serial );

  /* Set public key (the only important part) */
  X509_set_pubkey( x, pkey );

  /* Set very long expiration date */
  long not_before = 0L;            /* Jan  1 00:00:00 1975 GMT */
  X509_time_adj( X509_getm_notBefore( x ), 0, &not_before );
  long not_after  = 67090118400L;  /* Jan  1 00:00:00 4096 GMT */
  X509_time_adj( X509_getm_notAfter ( x ), 0, &not_after  );

  /* Set SAN to localhost */
  X509_EXTENSION * san = X509V3_EXT_conf_nid( NULL, NULL, NID_subject_alt_name, "DNS: localhost" );
  if( FD_UNLIKELY( !san ) ) {
    FD_LOG_WARNING(( "X509V3_EXT_conf_nid(NID_subject_alt_name) failed" ));
    goto cleanup1;
  }
  X509_add_ext( x, san, -1 );
  X509_EXTENSION_free( san );

  /* Set cert usage constraints */
  X509_EXTENSION * constraints = X509V3_EXT_conf_nid( NULL, NULL, NID_basic_constraints, "critical,CA:FALSE" );
  if( FD_UNLIKELY( !constraints ) ) {
    FD_LOG_WARNING(( "X509V3_EXT_conf_nid(NID_basic_constraints) failed" ));
    goto cleanup1;
  }
  X509_add_ext( x, constraints, -1 );
  X509_EXTENSION_free( constraints );

  /* Sign cert */
  if( FD_UNLIKELY( !X509_sign( x, pkey, NULL ) ) ) {
    FD_LOG_WARNING(( "X509_sign() failed" ));
    goto cleanup1;
  }

  return x;

cleanup1:
  X509_free( x );
cleanup0:
  return NULL;
}
