#ifndef HEADER_fd_src_ballet_hmac_fd_hkdf_h
#define HEADER_fd_src_ballet_hmac_fd_hkdf_h

/* fd_hkdf.h provides the HMAC-based Extract-and-Expand KDF.
   https://datatracker.ietf.org/doc/html/rfc5869
   (It turns random bytes and labels into encryption key material.) */

#include "../../util/fd_util_base.h"

void
fd_hkdf_extract( uchar        output[ 32 ],
                 void const * salt,
                 ulong        salt_sz,
                 void const * ikm,
                 ulong        ikm_sz );

/* fd_hkdf_expand_label_tls implements the TLS 1.3 HKDF-Expand function
   with SHA-256.  Writes the resulting hash to out.  secret is a 32 byte
   secret value.  label points to the label string.  label_sz is the
   number of chars in label (not including terminating NUL).  context
   points to the context byte array.  context_sz is the number of bytes
   in context. */

uchar *
fd_hkdf_expand_label_tls( uchar *       out,
                          ulong         out_sz,       /* in [1,32] */
                          uchar const   secret[ 32 ],
                          char const *  label,
                          ulong         label_sz,     /* in [0,64] */
                          uchar const * context,
                          ulong         context_sz ); /* in [0,64] */

#endif /* HEADER_fd_src_ballet_hmac_fd_hkdf_h */
