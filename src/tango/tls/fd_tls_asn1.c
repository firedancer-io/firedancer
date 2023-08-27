#include "fd_tls_asn1.h"

/* Example:
   https://lapo.it/asn1js/#MCowBQYDK2VwAyEAGb9ECWmEzf6FQbrBZ9w7lshQhqowtrbLDFw4rXAxZuE */

void const *
fd_ed25519_public_key_from_asn1( uchar const * buf,
                                 ulong         sz ) {

  static const uchar known_prefix[] =
    { /* SEQUENCE (2) */
      0x30, 0x2A,
      /*   SEQUENCE (1) */
      0x30, 0x05,
      /*     OBJECT IDENTIFIER  1.3.101.112 */
      0x06, 0x03, 0x2B, 0x65, 0x70,
      /*   BIT STRING */
      0x03, 0x21, 0x00 };

  if( FD_UNLIKELY( sz!=sizeof(known_prefix)+32UL ) )
    return NULL;

  if( FD_UNLIKELY( 0!=memcmp( buf, known_prefix, sizeof(known_prefix) ) ) )
    return NULL;

  return buf+sizeof(known_prefix);
}
