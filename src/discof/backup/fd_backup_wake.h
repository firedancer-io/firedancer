#ifndef HEADER_fd_src_discof_backup_fd_backup_wake_h
#define HEADER_fd_src_discof_backup_fd_backup_wake_h

/* fd_backup_wake.h wakes the snapsv tile.  It sleeps in io_uring and
   does not poll, so the snapshot maker and the stream tile both hand
   it their new sequence number with a futex wake.

   This is not in fd_snapmk_tile.h with the messages, because the
   syscall it makes is only declared where _GNU_SOURCE is, and the
   topology builder includes that header too. */

#include "../../tango/mcache/fd_mcache.h"

#include <errno.h>
#include <limits.h>
#include <linux/futex.h>
#include <sys/syscall.h>
#include <unistd.h>

FD_PROTOTYPES_BEGIN

/* fd_backup_out_wake publishes seq as the producer sequence number of
   a link into snapsv and wakes the tile. */

FD_FN_UNUSED static void
fd_backup_out_wake( ulong * seq_prod,
                    ulong   seq ) {
  fd_mcache_seq_update( seq_prod, seq );
  if( FD_UNLIKELY( -1==syscall( SYS_futex, (uint *)seq_prod, FUTEX_WAKE, INT_MAX, NULL, NULL, 0 ) ) ) {
    FD_LOG_ERR(( "FUTEX_WAKE failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  }
}

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_discof_backup_fd_backup_wake_h */
