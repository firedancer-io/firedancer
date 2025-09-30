#ifndef HEADER_fd_src_flamenco_racesan_fd_racesan_base_h
#define HEADER_fd_src_flamenco_racesan_fd_racesan_base_h

#include "../../util/fd_util_base.h"

#ifndef FD_HAS_RACESAN
#define FD_HAS_RACESAN 0
#endif

/* FIXME Check for FD_HAS_UCONTEXT */

struct fd_racesan;
typedef struct fd_racesan fd_racesan_t;

FD_PROTOTYPES_BEGIN

/* fd_racesan_strhash is a FNV-1a for 64-bit implementation of string
   hashing.  Used to hash racesan hook names to integers.  The compiler
   can typically evaluate the following at compile time:

     ulong x = fd_racesan_strhash( "hello", sizeof("hello")-1 );
     ... x is resolved at compile time ... */

static inline ulong
fd_racesan_strhash( char const * s,
                    ulong        len ) {
  ulong x = 0xCBF29CE484222325UL;
  for( ; len; len--, s++ ) {
    x ^= (ulong)(uchar)( *s );
    x *= 0x100000001B3UL;
  }
  return x;
}

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_racesan_fd_racesan_base_h */
