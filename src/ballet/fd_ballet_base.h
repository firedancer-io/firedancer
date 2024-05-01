#ifndef HEADER_fd_src_ballet_fd_ballet_base_h
#define HEADER_fd_src_ballet_fd_ballet_base_h

#include "../util/fd_util.h"

/* FD_TPU_MTU: The maximum size of a Solana transaction in serialized
   wire-protocol form.  This does not count any network-level (e.g. UDP
   or QUIC) headers. */
#define FD_TPU_MTU (1232UL)

/* FD_ALIGN: Default alignment according to platform:
    - avx512     => 64
    - avx        => 32
    - noarch128  => 16
    - noarch(64) =>  8 */

 #if FD_HAS_AVX512
 #define FD_ALIGN (64UL)
 #elif FD_HAS_AVX
 #define FD_ALIGN (32UL)
 #elif FD_HAS_INT128
 #define FD_ALIGN (16UL)
 #else
 #define FD_ALIGN (8UL)
 #endif

 /* FD_ALIGNED: shortcut to compiler aligned attribute with default alignment */
 #define FD_ALIGNED __attribute__((aligned(FD_ALIGN)))

//FD_PROTOTYPES_BEGIN

/* This is currently just a stub in anticipation of future common
   interoperability functionality */

//FD_PROTOTYPES_END

#endif /* HEADER_fd_src_ballet_fd_ballet_base_h */

