#include "fd_hkdf.h"
#include "../hmac/fd_hmac.h"

void
fd_hkdf_extract( uchar        output[ 32 ],
                 void const * salt,
                 ulong        salt_sz,
                 void const * ikm,
                 ulong        ikm_sz ) {
  fd_hmac_sha256( ikm, ikm_sz, salt, salt_sz, output );
}

uchar *
fd_hkdf_expand_label_tls( uchar *       out,
                          ulong         out_sz,
                          uchar const   secret[ 32 ],
                          char const *  label,
                          ulong         label_sz,
                          uchar const * context,
                          ulong         context_sz ) {

# define LABEL_BUFSZ (64UL)
  FD_CHECK_CRIT( label_sz  <=LABEL_BUFSZ, "api" );
  FD_CHECK_CRIT( context_sz<=LABEL_BUFSZ, "api" );
  FD_CHECK_CRIT( out_sz    <=32UL,        "api" );

  /* Create HKDF info */
  uchar info[ 2+1+6+LABEL_BUFSZ+1+LABEL_BUFSZ+1 ];
  ulong info_sz = 0UL;

  /* Length of hash output */
  info[0]=0; info[1]=(uchar)out_sz;
  info_sz += 2UL;

  /* Length prefix of label */
  info[ info_sz ] = (uchar)( 6UL + label_sz );
  info_sz += 1UL;

  /* Label */
  memcpy( info+info_sz, "tls13 ", 6UL );
  info_sz += 6UL;
  memcpy( info+info_sz, label, label_sz );
  info_sz += label_sz;

  /* Length prefix of context */
  info[ info_sz ] = (uchar)( context_sz );
  info_sz += 1UL;

  /* Context */
  fd_memcpy( info+info_sz, context, context_sz );
  info_sz += context_sz;

  /* HKDF-Expand suffix */
  info[ info_sz ] = 0x01;
  info_sz += 1UL;

  /* Compute result of HKDF-Expand-Label */
  uchar hash[ 32 ];
  fd_hmac_sha256( info, info_sz, secret, 32UL, hash );
  fd_memcpy( out, hash, out_sz );
  return out;
# undef LABEL_BUFSZ
}
