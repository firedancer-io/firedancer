#ifndef HEADER_fd_src_discof_fd_startup_h
#define HEADER_fd_src_discof_fd_startup_h

#include "../disco/topo/fd_topo.h"

/* fd_sleep_until_replay_started sleeps until the replay tile's status
   metric indicates that it loaded a snapshot.

   Requires read access to the metric_in workspace.
   Dispatches syscall clock_nanosleep( CLOCK_REALTIME, 0, ???, NULL ).

   Typically called in unprivileged_init.  (Sleeping in unprivileged_init
   makes the tile appear as offline in metrics)

   Returns the startup/root slot. */

ulong
fd_sleep_until_replay_started( fd_topo_t const * topo );

#endif /* HEADER_fd_src_discof_fd_startup_h */
