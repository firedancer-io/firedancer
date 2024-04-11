#ifndef HEADER_fd_src_ballet_utf8_fd_utf8_h
#define HEADER_fd_src_ballet_utf8_fd_utf8_h

#include "../fd_ballet_base.h"

/* fd_utf8_verify checks whether a byte array contains valid UTF-8.

   This function matches the validation rules of Rust's
   std::str::from_utf8.
   https://doc.rust-lang.org/std/str/fn.from_utf8.html

   The validation rules are:

     1. Each code point must be one to four bytes long.
     1.1. 1-byte code points must be in [U+0000,U+0080) (US-ASCII)
          The zero byte is not considered a code point.
     1.2. 2-byte code points must be in [U+0080,U+0800)
     1.3. 3-byte code points must be in [U+0800,U+10000)
           excluding UTF-16 surrogates [U+D800,U+D900)
     1.4. 4-byte code points must be in [U+10000,U+110000)

     2. Zero bytes are treated as a one byte code point (notably, zero
        bytes do not fail validation, nor do they terminate the string)

     3. Each encoded code point starts with a control char and is
        followed by zero or more continuation chars.  The number of
        continuation chars is indicated by the control char;  Out-of-
        place continuation chars are treated as an error.

     4. It is not checked whether code points are valid Unicode
        characters.

   str points to the first byte of the UTF-8 string (not a C string).
   sz is the number of bytes in the string.  Assumes that str+sz does
   not overflow.  str is ignored if sz==0UL. */

FD_FN_PURE int
fd_utf8_verify( char const * str,
                ulong        sz );

#endif /* HEADER_fd_src_ballet_utf8_fd_utf8_h */
