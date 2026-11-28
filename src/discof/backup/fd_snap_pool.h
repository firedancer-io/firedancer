#ifndef HEADER_fd_src_discof_backup_fd_snap_pool_h
#define HEADER_fd_src_discof_backup_fd_snap_pool_h

/* Snapshot inode/file descriptor management */

#include "fd_backup.h"

/* fd_snap_pool_layout_t describes how the snapshot pool slots are
   partitioned:

     [0, full_max)            retained full snapshots
     [full_max, max)          retained incremental snapshots */

struct fd_snap_pool_layout {
  ulong full_max;
  ulong incr_max;
  ulong max;      /* full_max+incr_max */
};

typedef struct fd_snap_pool_layout fd_snap_pool_layout_t;

FD_PROTOTYPES_BEGIN

FD_FN_CONST static inline fd_snap_pool_layout_t
fd_snap_pool_layout( ulong full_max,
                     ulong incr_max ) {
  fd_snap_pool_layout_t layout = {
    .full_max = full_max,
    .incr_max = incr_max,
    .max      = full_max + incr_max
  };
  return layout;
}

/* Formats the canonical partial name for a pool slot. */

FD_FN_UNUSED static char *
fd_snap_pool_partial_name( char name[ static FD_SNAP_NAME_MAX ],
                           uint idx ) {
  FD_TEST( fd_cstr_printf_check( name, FD_SNAP_NAME_MAX, NULL, ".snapshot-x%u.partial", idx ) );
  return name;
}

/* Recovers directory-entry metadata for each inherited pool
   descriptor.  The caller must ensure directory ownership is quiescent
   for the duration of the scan. */

void
fd_snap_pool_recover( int                 snapshots_fd,
                      char const *        snapshots_path,
                      fd_backup_inode_t * pool,
                      uint                pool_max );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_discof_backup_fd_snap_pool_h */
