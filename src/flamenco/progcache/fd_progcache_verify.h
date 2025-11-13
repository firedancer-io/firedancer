#ifndef HEADER_fd_src_flamenco_progcache_fd_progcache_verify_h
#define HEADER_fd_src_flamenco_progcache_fd_progcache_verify_h

#include "fd_progcache_admin.h"
#include "fd_progcache_user.h"

#define FD_PROGCACHE_VERIFY_SUCCESS (0)
#define FD_PROGCACHE_VERIFY_FAILURE (1)

FD_PROTOTYPES_BEGIN

/* fd_progcache_verify_admin verifies a fd_progcache_admin_t,
   conducting various expensive data structure integrity checks.

   Assumes no concurrent users of admin, or the underlying Funk database.

   Returns FD_PROGCACHE_VERIFY_SUCCESS on success,
   FD_PROGCACHE_VERIFY_FAILURE on failure.
*/
int
fd_progcache_verify_admin( fd_progcache_admin_t * admin );

/* fd_progcache_verify verifies a fd_progcache_t,
   conducting various expensive data structure integrity checks.

   Assumes no concurrent users of progcache, or the underlying Funk database.

   Returns FD_PROGCACHE_VERIFY_SUCCESS on success,
   FD_PROGCACHE_VERIFY_FAILURE on failure.
 */
int
fd_progcache_verify( fd_progcache_t * user_cache );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_progcache_fd_progcache_verify_h */
