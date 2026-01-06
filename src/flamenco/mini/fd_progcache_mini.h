#ifndef HEADER_fd_src_flamenco_mini_fd_progcache_mini_h
#define HEADER_fd_src_flamenco_mini_fd_progcache_mini_h

/* fd_progcache_mini.h provides APIs to quickly create progcache instances for
   testing. */

#include "../progcache/fd_progcache_admin.h"
#include "../progcache/fd_progcache_user.h"

/* A 'mini' progcache instance is fully in-memory, optimized for quick
   creation and destruction, and backed by demand-paged memory.  Has
   significantly worse performance than an progcache created properly via
   fd_topo APIs (due to page faults, TLB misses, etc).  Is less secure
   than fd_topo-provided memory due to weaker ASLR.

   This class is furthermore position-dependent (cannot be shared across
   different address spaces). */

struct fd_progcache_mini {
  fd_wksp_t *       wksp;
  ulong             wksp_footprint;  /* mmap() requested size */
  fd_funk_shmem_t * funk_shmem;
};

typedef struct fd_progcache_mini fd_progcache_mini_t;

FD_PROTOTYPES_BEGIN

/* fd_progcache_mini_create creates a new normal-page backed heap region
   (using mmap MAP_ANONYMOUS), creates a wksp within that region, and
   then constructs a funk database within that wksp.

   rec_max and txn_max control funk record/transaction map limits.

   wksp_name and heap_min are the parameters of the wksp to create.
   wksp_name is the workspace name cstr, which must not yet be
   registered in the current process.  heap_min is the minimum number
   of space to reserve for the heap allocator, excluding the space
   needed for index data structures (aligned up to normal page size).

   seed is used as a PRNG seed (e.g. for test determinism).

   Populates *mini and returns mini on success.  On failure, releases
   any created resources, logs to WARNING, and returns NULL.  Reasons
   for failure include:
   - A parameter was invalid
   - Address space exhausted (mmap failed)
   - fd_shmem region/fd_wksp already registered under wksp_name */

fd_progcache_mini_t *
fd_progcache_mini_create( fd_progcache_mini_t * mini,
                          ulong                 rec_max,
                          ulong                 txn_max,
                          char const *          wksp_name,
                          ulong                 heap_min,
                          ulong                 seed );

/* fd_progcache_mini_destroy releases resources created by an
   fd_progcache_mini_create call.  Wipes any database records in the
   instance.  Returns the ownership of the region backing *mini back to
   the caller. */

void
fd_progcache_mini_destroy( fd_progcache_mini_t * mini );

/* fd_progcache_mini_join_admin creates an progcache_admin handle joined to the
   progcache_mini instance. */

fd_progcache_admin_t *
fd_progcache_mini_join_admin( fd_progcache_mini_t *  mini,
                          fd_progcache_admin_t * join );

/* fd_progcache_mini_join_user creates an progcache handle joined to the
   progcache_mini instance. */

fd_progcache_t *
fd_progcache_mini_join_user( fd_progcache_mini_t * mini,
                             fd_progcache_t *      join );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_mini_fd_progcache_mini_h */