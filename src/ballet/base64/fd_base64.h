#ifndef HEADER_fd_src_ballet_base64_fd_base64_h
#define HEADER_fd_src_ballet_base64_fd_base64_h

/* fd_base64.h provides methods for converting between binary and
   Base64.  Uses the standard Base64 alphabet as specified in RFC 4648
   with padding. */

#include "../fd_ballet_base.h"

/* FD_BASE64_ENC_SZ returns the number of Base64 characters required
   to encode a given byte count.  sz in [0,0xbffffffffffffffe).
   Supports compile-time evaluation, and is thus suitable for use in
   declarations.  Not homomorphic due to padding, i.e.:

     FD_BASE64_ENC_SZ(a)+FD_BASE64_ENC_SZ(b) >= FD_BASE64_ENC_SZ(a+b) */

#define FD_BASE64_ENC_SZ(sz) ((((sz)+2UL)/3UL)*4UL)

/* FD_BASE64_DEC_SZ returns the max number of bytes required to hold a
   the decoding of a given number of Base64 characters.
   sz in [0,0xfffffffffffffffd). */

#define FD_BASE64_DEC_SZ(sz) ((((sz)+3UL)/4UL)*3UL)

FD_PROTOTYPES_BEGIN

/* fd_base64_encode encodes the given bytes [in,in+in_sz) as Base64,
   optionally using trailing padding.  Does not write a NULL terminator
   to out (thus out will not be a valid cstr on return).  Writes result
   to [out,out+FD_BASE64_ENC_SZ(in_sz)) and returns the number of writes
   written. */

ulong
fd_base64_encode( char *       out,
                  void const * in,
                  ulong        in_sz );

/* fd_cstr_append_base64 appends Base64 encoded data to p.  Assumes p
   is valid (non-NULL and room for at least FD_BASE64_ENC_SZ( sz )
   characters and a final terminating '\0').  sz==0UL is treated as a
   no-op. */

static inline char *
fd_cstr_append_base64( char *        p,
                       uchar const * s,
                       ulong         sz ) {
  if( FD_UNLIKELY( !sz ) ) return p;
  ulong n = fd_base64_encode( p, s, sz );
  return p + n;
}

/* fd_base64_decode decodes the Base64 characters in [in+in_sz).  Writes
   up to FD_BASE64_DEC_SZ(in_sz) bytes to out.  Returns number of bytes
   encoded on success, or -1L on failure.  Only supports trailing
   padding. */

long
fd_base64_decode( uchar *      out,
                  char const * in,
                  ulong        in_sz );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_ballet_base64_fd_base64_h */
