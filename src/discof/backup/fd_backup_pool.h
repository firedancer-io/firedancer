#ifndef HEADER_fd_src_discof_backup_fd_backup_pool_h
#define HEADER_fd_src_discof_backup_fd_backup_pool_h

/* fd_backup_pool manages the fixed pool of snapshot files in the
   snapshots directory that the snapshot producer (snapmk/snapzp) is
   allowed to write.

   The producer tiles run inside the strict sandbox and cannot open,
   create, or unlink files at runtime.  Instead, the boot process
   reconciles the snapshots directory once, before any tile is spawned,
   into exactly max_full_snapshots_to_keep+max_incremental_snapshots_to_keep
   files (the newest existing snapshots of each kind, padded out with
   empty "snapshot<i>.partial" placeholders), and opens two file
   descriptors to each of them at well known fd numbers which the tiles
   inherit and keep forever.

   At runtime the producer never touches the filesystem namespace
   except through renameat(2) relative to the (also preopened)
   snapshots directory fd:

     "delete" a snapshot: ftruncate the slot fd to zero and renameat
     the file back to its "snapshot<i>.partial" placeholder name.

     "create" a snapshot: write the slot file through the preopened
     fds and, once complete, renameat it from the placeholder name to
     the final snapshot-<slot>-<hash>.tar.zst name. */

#include "../../util/fd_util_base.h"

/* FD_BACKUP_POOL_MAX bounds the number of managed snapshot files
   (max_full_snapshots_to_keep+max_incremental_snapshots_to_keep). */

#define FD_BACKUP_POOL_MAX (16U)

/* Well-known file descriptor numbers for snapshot pool slot i.  Like
   FD_ACCDB_FD_{RW,RO}, the boot process dups the slot files to these
   fds before fork+exec so seccomp filters can pin syscalls to a fixed
   fd range.  fds 123460+ are reserved by accdb and XDP.

   Slot i has two open file descriptions: FD_BACKUP_POOL_FD( i ) is a
   plain O_WRONLY description used by snapmk for sequential writes,
   and FD_BACKUP_POOL_DIO_FD( i ) is an O_WRONLY|O_DIRECT description
   shared by the snapzp tiles for block aligned pwrites. */

#define FD_BACKUP_POOL_FD(     i ) (123400+(int)(i))
#define FD_BACKUP_POOL_DIO_FD( i ) (123400+(int)FD_BACKUP_POOL_MAX+(int)(i))

/* FD_BACKUP_POOL_PARTIAL_NAME_MAX is the max cstr size (null
   included) of a "snapshot<i>.partial" placeholder name. */

#define FD_BACKUP_POOL_PARTIAL_NAME_MAX (32UL)

/* fd_backup_pool_slot_t describes the current directory entry backing
   a snapshot pool slot.  A slot either holds a valid snapshot
   (full_slot!=ULONG_MAX) or a zero length "snapshot<i>.partial"
   placeholder (full_slot==ULONG_MAX). */

struct fd_backup_pool_slot {
  char  name[ 128UL ]; /* FD_BACKUP_NAME_MAX */
  ulong full_slot;     /* ULONG_MAX if placeholder */
  ulong incr_slot;     /* ULONG_MAX if placeholder or full snapshot */
};

typedef struct fd_backup_pool_slot fd_backup_pool_slot_t;

FD_PROTOTYPES_BEGIN

/* fd_backup_pool_partial_name writes the "snapshot<i>.partial"
   placeholder name of pool slot slot_idx into name and returns name. */

char *
fd_backup_pool_partial_name( char name[ static FD_BACKUP_POOL_PARTIAL_NAME_MAX ],
                             uint slot_idx );

/* fd_backup_pool_boot reconciles the snapshots directory into the
   managed pool and opens the pool fds.  Must be called by the boot
   process before any tile is spawned (and therefore before any
   sandboxing), in the process that tiles inherit fds from.

   Slots [0,max_full) are assigned the newest existing full snapshots
   (newest first), slots [max_full,max_full+max_incr) the newest
   existing incremental snapshots.  Excess snapshots and leftover
   producer artifacts (*.partial placeholders, legacy *.wip files) are
   unlinked, and unassigned slots are created as empty
   "snapshot<i>.partial" placeholders.  Unrecognized files are left
   alone.  Created files are chowned to uid/gid when running as root.

   This runs before the snapshot loader tiles (snapct/snapld) call
   fd_ssarchive_latest_pair, so the loader observes the pruned
   directory (previously pruning raced the loader's open). */

void
fd_backup_pool_boot( char const * snapshots_path,
                     uint         max_full_snapshots_to_keep,
                     uint         max_incremental_snapshots_to_keep,
                     uint         uid,
                     uint         gid );

/* fd_backup_pool_recover rebuilds the slot->directory entry table by
   matching the inode of each preopened pool fd against the entries of
   the snapshots directory.  Called from snapmk's privileged init
   (after fd_backup_pool_boot ran in the boot process, before the
   sandbox is entered).  snapshots_path is the snapshots directory,
   pool_cnt the total slot count and slot an array of pool_cnt entries
   filled in on return.  Logs an error and exits the process if a pool
   fd is missing or does not match any directory entry. */

void
fd_backup_pool_recover( char const *            snapshots_path,
                        uint                    pool_cnt,
                        fd_backup_pool_slot_t * slot );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_discof_backup_fd_backup_pool_h */
