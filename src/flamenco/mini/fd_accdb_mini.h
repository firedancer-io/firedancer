#ifndef HEADER_fd_src_flamenco_mini_fd_accdb_mini_h
#define HEADER_fd_src_flamenco_mini_fd_accdb_mini_h

/* fd_accdb_mini.h provides APIs to quickly create accdb instances for
   testing. */

#include "../accdb/fd_accdb_impl_v1.h"
#include "../accdb/fd_accdb_admin.h"
#include "../accdb/fd_accdb_user.h"

/* A 'mini' accdb instance is fully in-memory, optimized for quick
   creation and destruction, and backed by demand-paged memory.  Has
   significantly worse performance than an accdb created properly via
   fd_topo APIs (due to page faults, TLB misses, etc).  Is less secure
   than fd_topo-provided memory due to weaker ASLR.

   This class is furthermore position-dependent (cannot be shared across
   different address spaces). */

struct fd_accdb_mini {
  fd_wksp_t *       wksp;
  ulong             wksp_footprint;  /* mmap() requested size */
  fd_funk_shmem_t * funk_shmem;
};

typedef struct fd_accdb_mini fd_accdb_mini_t;

FD_PROTOTYPES_BEGIN

/* fd_accdb_mini_create creates a new normal-page backed heap region
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

fd_accdb_mini_t *
fd_accdb_mini_create( fd_accdb_mini_t * mini,
                      ulong             rec_max,
                      ulong             txn_max,
                      char const *      wksp_name,
                      ulong             heap_min,
                      ulong             seed );

/* fd_accdb_mini_destroy releases resources created by an
   fd_accdb_mini_create call.  Wipes any database records in the
   instance.  Returns the ownership of the region backing *mini back to
   the caller. */

void
fd_accdb_mini_destroy( fd_accdb_mini_t * mini );

/* fd_accdb_mini_join_admin creates an accdb_admin handle joined to the
   accdb_mini instance. */

fd_accdb_admin_t *
fd_accdb_mini_join_admin( fd_accdb_mini_t *  mini,
                          fd_accdb_admin_t * join );

/* fd_accdb_mini_join_user creates an accdb_user handle joined to the
   accdb_mini instance. */

fd_accdb_user_t *
fd_accdb_mini_join_user( fd_accdb_mini_t * mini,
                         fd_accdb_user_t * join );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_mini_fd_accdb_mini_h */
