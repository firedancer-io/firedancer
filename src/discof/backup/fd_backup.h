#ifndef HEADER_fd_src_discof_backup_fd_backup_h
#define HEADER_fd_src_discof_backup_fd_backup_h

/* fd_backup.h produces Solana snapshots from Firedancer state. */

#include "../restore/utils/fd_ssarchive.h"

/* FD_SNAP_MAX bounds the number of managed snapshot files
   (max_full_snapshots_to_keep+max_incremental_snapshots_to_keep, plus
   up to two scratch slots for a snapshot class that is downloaded but
   not retained). */

#define FD_SNAP_MAX (2U*(uint)FD_SSARCHIVE_MAX_ENTRIES+2U)

/* Well-known snapshot file descriptors

   Firedancer's strict sandbox bans opening/creating new files via
   open(2).  Instead, Firedancer opens a fixed number of existing
   snapshots and creates placeholder files.  Each file is eventually
   recycled by truncating and renaming it. */

#define FD_SNAP_FD_BASE (200000)
#define FD_SNAP_FD( i ) (FD_SNAP_FD_BASE+(int)(i))

/* fd_backup_inode_t annotates a snapshot file descriptor. */

struct fd_backup_inode {
  char  name[ FD_SNAP_NAME_MAX ];
  ulong full_slot; /* ULONG_MAX if placeholder */
  ulong incr_slot; /* ULONG_MAX if placeholder or full snapshot */
};

typedef struct fd_backup_inode fd_backup_inode_t;

#endif /* HEADER_fd_src_discof_backup_fd_backup_h */
