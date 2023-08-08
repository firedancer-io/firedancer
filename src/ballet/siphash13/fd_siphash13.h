#ifndef HEADER_fd_src_ballet_siphash13_fd_siphash13_h
#define HEADER_fd_src_ballet_siphash13_fd_siphash13_h

/* fd_siphash13 provides APIs for SipHash1-3.
   (1 compression round, 3 finalization rounds) */

#include "../fd_ballet_base.h"

FD_PROTOTYPES_BEGIN

ulong
fd_siphash13_hash( void const * data,
                   ulong        sz,
                   ulong        k0,
                   ulong        k1 );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_ballet_siphash13_fd_siphash13_h */
