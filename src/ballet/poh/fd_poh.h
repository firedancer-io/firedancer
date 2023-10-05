#ifndef HEADER_fd_src_ballet_poh_fd_poh_h
#define HEADER_fd_src_ballet_poh_fd_poh_h

/* fd_poh provides a software-based implementation of the Proof-of-History hashchain. */

#include "../sha256/fd_sha256.h"

FD_PROTOTYPES_BEGIN

/* fd_poh_append performs n recursive hash operations. */

void *
fd_poh_append( void * poh,
               ulong  n );

/* fd_poh_mixin mixes in a 32-byte value. */

void *
fd_poh_mixin( void *        FD_RESTRICT poh,
              uchar const * FD_RESTRICT mixin );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_ballet_poh_fd_poh_h */
