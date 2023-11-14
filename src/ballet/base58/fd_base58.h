#ifndef HEADER_fd_src_ballet_base58_fd_base58_h
#define HEADER_fd_src_ballet_base58_fd_base58_h

/* fd_base58.h provides methods for converting between binary and
   base58. */

#include "../fd_ballet_base.h"

/* FD_BASE58_ENCODED_{32,64}_{LEN,SZ} give the maximum string length
   (LEN) and size (SZ, which includes the '\0') of the base58 cstrs that
   result from converting 32 or 64 bytes to base58. */

#define FD_BASE58_ENCODED_32_LEN (44UL)                         /* Computed as ceil(log_58(256^32 - 1)) */
#define FD_BASE58_ENCODED_64_LEN (88UL)                         /* Computed as ceil(log_58(256^64 - 1)) */
#define FD_BASE58_ENCODED_32_SZ  (FD_BASE58_ENCODED_32_LEN+1UL) /* Including the nul terminator */
#define FD_BASE58_ENCODED_64_SZ  (FD_BASE58_ENCODED_64_LEN+1UL) /* Including the nul terminator */

FD_PROTOTYPES_BEGIN

/* fd_base58_encode_{32, 64}: Interprets the supplied 32 or 64 bytes
   (respectively) as a large big-endian integer, and converts it to a
   nul-terminated base58 string of:

     32 to 44 characters, inclusive (not counting nul) for 32 B
     64 to 88 characters, inclusive (not counting nul) for 64 B

   Stores the output in the buffer pointed to by out.  If opt_len is
   non-NULL, *opt_len == strlen( out ) on return.  Returns out.  out is
   guaranteed to be nul terminated on return.

   Out must have enough space for FD_BASE58_ENCODED_{32,64}_SZ
   characters, including the nul terminator.

   The 32 byte conversion is suitable for printing Solana account
   addresses, and the 64 byte conversion is suitable for printing Solana
   transaction signatures.  This is high performance (~100ns for 32B and
   ~200ns for 64B without AVX, and roughly twice as fast with AVX), but
   base58 is an inherently slow format and should not be used in any
   performance critical places except where absolutely necessary. */

char * fd_base58_encode_32( uchar const * bytes, ulong * opt_len, char * out );
char * fd_base58_encode_64( uchar const * bytes, ulong * opt_len, char * out );

/* fd_base58_decode_{32, 64}: Converts the base58 encoded number stored
   in the cstr `encoded` to a 32 or 64 byte number, which is written to
   out in big endian.  out must have room for 32 and 64 bytes respective
   on entry.  Returns out on success and NULL if the input string is
   invalid in some way: illegal base58 character or decodes to something
   other than 32 or 64 bytes (respectively).  The contents of out are
   undefined on failure (i.e. out may be clobbered).

   A similar note to the above applies: these are high performance
   (~120ns for 32 byte and ~300ns for 64 byte), but base58 is an
   inherently slow format and should not be used in any performance
   critical places except where absolutely necessary. */

uchar * fd_base58_decode_32( char const * encoded, uchar * out );
uchar * fd_base58_decode_64( char const * encoded, uchar * out );

FD_PROTOTYPES_BEGIN

#endif /* HEADER_fd_src_ballet_base58_fd_base58_h */
