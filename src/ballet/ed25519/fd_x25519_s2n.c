#include <stdint.h>
#include <s2n-bignum.h>

#ifndef __ADX__
#define curve25519_x25519_byte      curve25519_x25519_byte_alt
#define curve25519_x25519base_byte  curve25519_x25519base_byte_alt
#endif

/* s2n-bignum implementation of X25519.  curve25519_x25519_byte and
   curve25519_x25519base_byte are formally-verified hand-written
   x86-64/AArch64 assembly routines from
   https://github.com/awslabs/s2n-bignum (Apache-2.0 / ISC / MIT-0).
   They implement RFC 7748 §5 including scalar clamping and
   u-coordinate MSB masking internally. */

uchar * FD_FN_SENSITIVE
fd_x25519_public( uchar       self_public_key [ 32 ],
                  uchar const self_private_key[ 32 ] ) {
  curve25519_x25519base_byte( self_public_key, self_private_key );
  return self_public_key;
}

uchar * FD_FN_SENSITIVE
fd_x25519_exchange( uchar       shared_secret   [ 32 ],
                    uchar const self_private_key[ 32 ],
                    uchar const peer_public_key [ 32 ] ) {
  curve25519_x25519_byte( shared_secret, self_private_key, peer_public_key );

  /* Reject low order points */
  if( FD_UNLIKELY( fd_x25519_is_zero_const_time( shared_secret ) ) ) {
    return NULL;
  }

  return shared_secret;
}
