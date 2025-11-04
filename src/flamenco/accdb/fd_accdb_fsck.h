#ifndef HEADER_fd_src_flamenco_accdb_fd_accdb_fsck_h
#define HEADER_fd_src_flamenco_accdb_fd_accdb_fsck_h

/* fd_accdb_fsck.h provides APIs to do integrity checking of an account
   database. */

#include "../../vinyl/io/fd_vinyl_io.h"
#include "../../vinyl/meta/fd_vinyl_meta.h"

/* FD_ACCDB_FSCK_* gives high-level fsck status results */

#define FD_ACCDB_FSCK_NO_ERROR  0U /* no error detected */
#define FD_ACCDB_FSCK_UNCLEAN   1U /* unclean shutdown detected (recoverable) */
#define FD_ACCDB_FSCK_INVARIANT 2U /* invariant violation detected */
#define FD_ACCDB_FSCK_CORRUPT   3U /* data corruption detected */
#define FD_ACCDB_FSCK_UNKNOWN   4U /* check stopped early */

FD_PROTOTYPES_BEGIN

/* fd_accdb_fsck_vinyl verifies a bstream and meta index.  Returns the
   high-level result (FD_ACCDB_FSCK_*) and writes NOTICE/WARNING logs
   along the way.  Assumes that no data cache is active (smashes bits
   used by vinyl_data for integrity check scratch space). */

uint
fd_accdb_fsck_vinyl( fd_vinyl_io_t *   io,     /* must be io_mm */
                     fd_vinyl_meta_t * meta ); /* local join to meta index */

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_accdb_fd_accdb_fsck_h */
