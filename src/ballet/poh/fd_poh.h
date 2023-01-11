#ifndef HEADER_fd_src_ballet_poh_fd_poh_h
#define HEADER_fd_src_ballet_poh_fd_poh_h

/* fd_poh provides a software-based implementation of the Proof-of-History hashchain. */

#include "../sha256/fd_sha256.h"

#define FD_POH_STATE_ALIGN (32UL)

struct __attribute__((aligned(32))) fd_poh_state {
  uchar state[FD_SHA256_HASH_SZ];
};

typedef struct fd_poh_state fd_poh_state_t;

FD_PROTOTYPES_BEGIN

/* fd_poh_append performs n recursive hash operations. */

fd_poh_state_t *
fd_poh_append( fd_poh_state_t * poh,
               ulong            n );

/* fd_poh_mixin mixes in a 32-byte value. */

fd_poh_state_t *
fd_poh_mixin( fd_poh_state_t * FD_RESTRICT poh,
              uchar const *    FD_RESTRICT mixin );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_ballet_poh_fd_poh_h */
