#ifndef HEADER_fd_src_tango_mvcc_fd_mvcc_h
#define HEADER_fd_src_tango_mvcc_fd_mvcc_h

#include "../../util/fd_util.h"

/* fd_mvcc ("Multiversion Concurrency Control") is a simple primitive for lock-free synchronization
   of concurrent readers and writers. It is strictly less general than the MVCC used in various
   DBMS [https://dl.acm.org/doi/pdf/10.1145/356842.356846], but it is conceptually similar in that
   it uses a version number to detect conflicts.

   Usage:
   - Writer increments version number
   - Writer does update
   - Writer increments version number
   - Therefore, if the version number is odd, a write is in progress.

   - Reader reads version number
   - Reader reads data
   - Reader reads version number
   - Therefore, if the version number has changed, the read is invalid.

   fd_mvcc_begin_write()  // release-store
   ... write ...
   fd_mvcc_end_write()    // acquire-load

   ulong begin = fd_mvcc_begin_read()  // acquire-load
   ulong end = fd_mvcc_end_read()      // acquire-load
   if (end != begin) {
     ... read is invalid ...
   }

   Note this is similar to how producers / consumers synchronize across mcache / dcache.

   TODO hardware fencing */

struct fd_mvcc {
  ulong version;
};
typedef struct fd_mvcc fd_mvcc_t;

/* fd_mvcc_version_laddr returns a local pointer to the version number for the current joined
 * process. Caller is responsible for fencing the dereference if necessary. */
ulong *
fd_mvcc_version_laddr( fd_mvcc_t * mvcc );

/* fd_mvcc_begin_write increments then returns the version number, fencing preceding memory
 * accesses. Corresponds to C++ memory_order_release. */
ulong
fd_mvcc_begin_write( fd_mvcc_t * mvcc );

/* fd_mvcc_begin_write increments then returns the version number, fencing subsequent memory
 * accesses. Corresponds to C++ memory_order_acquire. */
ulong
fd_mvcc_end_write( fd_mvcc_t * mvcc );

/* fd_mvcc_{begin,end}_read are convenience exports for code readability assisting with
   remembering to read back the version. */
ulong
fd_mvcc_begin_read( fd_mvcc_t * mvcc );

ulong
fd_mvcc_end_read( fd_mvcc_t * mvcc );

ulong
fd_mvcc_read( fd_mvcc_t * mvcc );

#endif /* HEADER_fd_src_tango_mvcc_fd_mvcc_h */
