#include "fd_hmac.h"

#include "../sha256/fd_sha256.h"
#include "../sha512/fd_sha512.h"

#define HASH_ALG      sha256
#define HASH_BLOCK_SZ FD_SHA256_BLOCK_SZ
#define HASH_SZ       FD_SHA256_HASH_SZ
#include "fd_hmac_tmpl.c"

#define HASH_ALG      sha384
#define HASH_BLOCK_SZ FD_SHA384_BLOCK_SZ
#define HASH_SZ       FD_SHA384_HASH_SZ
#include "fd_hmac_tmpl.c"

#define HASH_ALG      sha512
#define HASH_BLOCK_SZ FD_SHA512_BLOCK_SZ
#define HASH_SZ       FD_SHA512_HASH_SZ
#include "fd_hmac_tmpl.c"

void *
fd_hkdf_expand_label( uchar *       out,
                      ulong         out_sz,
                      uchar const * secret,
                      ulong         secret_sz,
                      char const *  label,
                      ulong         label_sz,
                      uchar const * context,
                      ulong         context_sz,
                      fd_hmac_fn_t  hmac_fn ) {

# define LABEL_BUFSZ (64UL)
# define HASH_BUFSZ  (64UL)

  if( FD_UNLIKELY(
      (!out_sz)                  |
      (out_sz    > secret_sz)    |
      (secret_sz > HASH_BUFSZ)   |
      (label_sz  > LABEL_BUFSZ)  |
      (context_sz> LABEL_BUFSZ) ) ) {
    return NULL;
  }

  uchar info[ 2+1+6+LABEL_BUFSZ+1+LABEL_BUFSZ+1 ];
  ulong info_sz = 0UL;

  /* Length of output */
  info[0] = 0;
  info[1] = (uchar)out_sz;
  info_sz += 2UL;

  /* Label: length-prefixed "tls13 " + label */
  info[ info_sz ] = (uchar)( 6UL + label_sz );
  info_sz += 1UL;
  memcpy( info+info_sz, "tls13 ", 6UL );
  info_sz += 6UL;
  memcpy( info+info_sz, label, label_sz );
  info_sz += label_sz;

  /* Context: length-prefixed context bytes */
  info[ info_sz ] = (uchar)context_sz;
  info_sz += 1UL;
  fd_memcpy( info+info_sz, context, context_sz );
  info_sz += context_sz;

  /* HKDF-Expand counter=1 */
  info[ info_sz ] = 0x01;
  info_sz += 1UL;

  /* PRF = HMAC(secret, info) */
  uchar hash[ HASH_BUFSZ ];
  hmac_fn( info, info_sz, secret, secret_sz, hash );
  fd_memcpy( out, hash, out_sz );
  return out;

# undef HASH_BUFSZ
# undef LABEL_BUFSZ
}
