#ifndef HEADER_fd_src_discof_restore_fd_ssping_h
#define HEADER_fd_src_discof_restore_fd_ssping_h

/* The snapshot pinger (ssping) is responsible for maintaining a list of
   peers that are reachable for snapshot download, and returning the
   "best" such peer at any time.

   The "best" peer is defined as the one with the lowest latency for
   now, in response to an ICMP ping request, although this should likely
   be changed to include snapshot age, or actual observed download speed
   for a small sample, or other factors.

   The snapshot pinger works on the assumption that there is a maximum
   size of peers that will ever be added, as we expect from the gossip
   system.  Peers can be added and removed arbitrarily outside of this
   maximum restriction. */

#include "../../../util/fd_util_base.h"
#include "../../../util/net/fd_net_headers.h"
#include "../../../flamenco/types/fd_types_custom.h"

#define FD_SSPING_ALIGN (8UL)

#define FD_SSPING_MAGIC (0xF17EDA2CE55A1A60) /* FIREDANCE SSPING V0 */

struct fd_ssping_private;
typedef struct fd_ssping_private fd_ssping_t;

/* fd_ssinfo stores the resolved snapshot information from a peer. */
struct fd_ssinfo {
   struct {
      ulong slot;                      /* slot of the full snapshot */
      uchar hash[ FD_HASH_FOOTPRINT ]; /* base58 decoded hash of the full snapshot */
      ulong slots_behind;              /* number of slots behind the latest full cluster slot */
    } full;

    struct {
      ulong base_slot;
      ulong slot;
      uchar hash[ FD_HASH_FOOTPRINT ];
      ulong slots_behind;
    } incremental;
};
typedef struct fd_ssinfo fd_ssinfo_t;

struct fd_sspeer {
  fd_ip4_port_t       addr;
  fd_ssinfo_t const * snapshot_info;
};
typedef struct fd_sspeer fd_sspeer_t;

FD_PROTOTYPES_BEGIN

FD_FN_CONST ulong
fd_ssping_align( void );

FD_FN_CONST ulong
fd_ssping_footprint( ulong max_peers );

void *
fd_ssping_new( void * shmem,
               ulong  max_peers,
               ulong  seed );

fd_ssping_t *
fd_ssping_join( void * shping );

/* Add a peer to be tracked by the snapshot pinger, which will from here
   until it is removed, constantly ping the node to maintain its
   status.

   An address can be added multiple times, and the addresses are
   internally reference counted, so it will need a corresponding number
   of releases to be removed from ping tracking.

   The ping tracker cannot be overflowed, and if too many peers are
   being tracked, trying to add a new peer is a no-op. */

void
fd_ssping_add( fd_ssping_t * ssping,
               fd_ip4_port_t addr );

/* Remove a peer from tracking by the snapshot pinger.  Peers are
   reference counted, so this will only remove the peer only if the
   count goes to zero.  If the peer is not tracked, this is a no-op. */

void
fd_ssping_remove( fd_ssping_t * ssping,
                  fd_ip4_port_t addr );

/* Mark the peer as invalid for selection for a period of time, probably
   if they refused a connection or served us a bad snapshot. */

void
fd_ssping_invalidate( fd_ssping_t * ssping,
                      fd_ip4_port_t addr,
                      long          now );

/* Advance the ping tracker forward in time until "now".  This should be
   called periodically to refresh pings and service networking to
   maintain ping states. */

void
fd_ssping_advance( fd_ssping_t * ssping,
                   long          now );

/* Retrieve the best "active" peer right now, by lowest ping.  If no
   peer is active or pingable, this returns 0.0.0.0:0. */

fd_sspeer_t
fd_ssping_best( fd_ssping_t const * ssping );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_discof_restore_fd_ssping_h */
