#ifndef HEADER_fd_src_ballet_utf8_fd_utf8_h
#define HEADER_fd_src_ballet_utf8_fd_utf8_h

#include "../fd_ballet_base.h"

/* fd_utf8_check_cstr checks whether the given pointer is a valid UTF-8
   encoded cstr.  That is, checks whether the string complies with UTF-8
   encoding rules.  Does not whether the code points are defined in the
   Unicode character set.

   cstr points to the first byte of the UTF-8 string.  May read
   from memory region [cstr,cstr+sz).  U.B. if cstr+sz overflows.
   A zero byte is interpreted as the null terminator of the string.

   For example, fd_utf8_check_cstr( "😃\x00ABC", 64UL ) returns 5UL.
   Hex view:

     F0 9F 98 83 00 41 42 43 00
     ▲  ▲  ▲  ▲  ▲
     │  │  │  │  └─────────────── Null terminator
     │  └──┴──┴────────────────── Continuation char
     └─────────────────────────── Control char

   Returns the byte size of the cstr on success, such that the null
   terminator is at `cstr[ fd_utf8_check_cstr( cstr, sz )-1UL ]`.

   On failure, returns an undefined negative value.
   TODO: Consider encoding the position at which verification failed
         in the return value.

   The validation rules are:

     1. Each code point must be one to four bytes long.
     1.1. 1-byte code points must be in [U+0001,U+0080) (US-ASCII)
          The zero byte is not considered a code point.
     1.2. 2-byte code points must be in [U+0080,U+0800)
     1.3. 3-byte code points must be in [U+0800,U+10000)
           excluding UTF-16 surrogates [U+D800,U+D900)
     1.4. 4-byte code points must be in [U+10000,U+110000)

     2. cstr is terminated by the first zero byte.
        If there is no zero byte in [cstr,cstr+sz) then fail.
        Note: This means that sz==0UL always fails.

     3. Each encoded code point starts with a control char and is
        followed by zero or more continuation chars.  The number of
        continuation chars is indicated by the control char;  Out-of-
        place continuation chars are treated as an error.

   This matches the validation criteria of Rust's std::str::from_utf8
   https://doc.rust-lang.org/std/str/fn.from_utf8.html */

FD_FN_PURE long
fd_utf8_check_cstr( char const * cstr,
                    ulong        sz );

#endif /* HEADER_fd_src_ballet_utf8_fd_utf8_h */
