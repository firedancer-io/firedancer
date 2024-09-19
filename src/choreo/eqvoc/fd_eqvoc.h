#ifndef HEADER_fd_src_choreo_eqvoc_fd_eqvoc_h
#define HEADER_fd_src_choreo_eqvoc_fd_eqvoc_h

#include "../../flamenco/runtime/fd_blockstore.h"
#include "../fd_choreo_base.h"
#include "../ghost/fd_ghost.h"

/* FD_EQVOC_USE_HANDHOLDING:  Define this to non-zero at compile time
   to turn on additional runtime checks and logging. */

#ifndef FD_EQVOC_USE_HANDHOLDING
#define FD_EQVOC_USE_HANDHOLDING 1
#endif

/* fd_eqvoc_test checks if shred1 and shred2 are equivocating shreds
   (same key but different payloads).  Returns 1 if shred1 and shred2
   are equivocating, 0 otherwise.

   IMPORTANT!  Assumes shred1 and shred2 are both merkle shred variants
   (if handholding is enabled, explicitly checks and errors).  Also
   assumes they have both passed sigverify signed by a valid leader for
   their given slot.  Only the shreds' signatures are compared, so if
   these assumptions aren't true this function return incorrect results.
   Only the signatures are compared (vs. the full payloads) because the
   signature is the merkle root of the FEC set containing that shred,
   which includes the shred payload as a member.

   Handholding also enables additional sanity checks that indicate bugs
   or config issues in caller's code, namely shred key and shred version
   must match (errors otherwise). */

int
fd_eqvoc_test( fd_shred_t const * shred1, fd_shred_t const * shred2 );

#endif /* HEADER_fd_src_choreo_eqvoc_fd_eqvoc_h */
