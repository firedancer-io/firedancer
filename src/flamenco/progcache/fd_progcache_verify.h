#ifndef HEADER_fd_src_flamenco_progcache_fd_progcache_verify_h
#define HEADER_fd_src_flamenco_progcache_fd_progcache_verify_h

#include "fd_progcache_admin.h"
#include "fd_progcache_user.h"

FD_PROTOTYPES_BEGIN

/* fd_progcache_verify_comprehensive performs extensive integrity checks
   on the program cache data structures.

   This function verifies:
   - Underlying funk instance consistency
   - Fork management invariants (fork depth, XIDs, parent-child relationships)
   - Record structure integrity (executable/non-executable, memory layout)
   - No duplicate (xid, prog_addr) pairs exist
   - Visibility and invalidation rules
   - Cross-references between progcache and funk records

   Parameters:
   - admin_cache: Admin interface to the progcache (required)
   - user_cache: User interface to the progcache (optional, can be NULL)
   - epoch_slot0: First slot of the current epoch for visibility checks

   Returns:
   - FD_FUNK_SUCCESS (0) if all checks pass
   - FD_FUNK_ERR_INVAL if any invariant is violated

   The function logs detailed information about any failures encountered.

   This function assumes no concurrent modifications to the progcache. */

int
fd_progcache_verify_comprehensive( fd_progcache_admin_t * admin_cache,
                                   fd_progcache_t *       user_cache,
                                   ulong                  epoch_slot0 );

/* fd_progcache_verify_enhanced is a drop-in replacement for the existing
   fd_progcache_verify that includes comprehensive checks.

   Unlike fd_progcache_verify_comprehensive, this function uses FD_TEST
   assertions that will abort on failure, matching the behavior of the
   original fd_progcache_verify function. */

void
fd_progcache_verify_enhanced( fd_progcache_admin_t * cache );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_progcache_fd_progcache_verify_h */
