#ifndef HEADER_fd_src_discof_restore_utils_fd_sspeer_selector_h
#define HEADER_fd_src_discof_restore_utils_fd_sspeer_selector_h

/* The snapshot peer selector (sspeer_selector) continuously selects
   the most optimal snapshot peer to download snapshots from.  The
   most optimal peer is defined as the closest peer that serves the
   most recent snapshot. */

#include "../../../util/fd_util_base.h"
#include "../../../util/net/fd_net_headers.h"

#define FD_SSPEER_SELECTOR_MAGIC (0xF17EDA2CE5593350) /* FIREDANCE SSPING V0 */

/* fd_sscluster_slot stores the highest full and incremental slot pair
   seen in the cluster. */
struct fd_sscluster_slot {
  ulong full;
  ulong incremental;
};

typedef struct fd_sscluster_slot fd_sscluster_slot_t;

 /* fd_sspeer_t represents a selected peer from the snapshot peer
    selector, including the peer's address, resolved snapshot slots,
    and selector score. */
struct fd_sspeer {
  fd_ip4_port_t addr;      /* address of the peer */
  ulong         full_slot;
  ulong         incr_slot;
  ulong         score;    /* selector score of peer */
};

typedef struct fd_sspeer fd_sspeer_t;

struct fd_sspeer_selector_private;
typedef struct fd_sspeer_selector_private fd_sspeer_selector_t;

FD_PROTOTYPES_BEGIN

FD_FN_CONST ulong
fd_sspeer_selector_align( void );

FD_FN_CONST ulong
fd_sspeer_selector_footprint( ulong max_peers );

void *
fd_sspeer_selector_new( void * shmem,
                        ulong  max_peers,
                        int    incremental_snapshot_fetch,
                        ulong  seed );

fd_sspeer_selector_t *
fd_sspeer_selector_join( void * shselector );

void *
fd_sspeer_selector_leave( fd_sspeer_selector_t * selector );

void *
fd_sspeer_selector_delete( void * shselector );

/* Add a peer to the selector.  If the peer already exists,
   fd_sspeer_selector_add updates the existing peer's score using the
   given peer latency and snapshot info.  Returns the updated score. */
ulong
fd_sspeer_selector_add( fd_sspeer_selector_t * selector,
                        fd_ip4_port_t          addr,
                        ulong                  peer_latency,
                        ulong                  full_slot,
                        ulong                  incr_slot );

/* Remove a peer from the selector.  Peers are removed when they are
   not reachable or serving corrupted/malformed snapshots.  This is a
   no-op if the peer does not exist in the selector.  */
void
fd_sspeer_selector_remove( fd_sspeer_selector_t * selector,
                           fd_ip4_port_t          addr );

/* Select the best peer to download a snapshot from.  incremental
   indicates to select a peer to download an incremental snapshot.  If
   incremental is set, base_slot must be a valid full snapshot slot. */
fd_sspeer_t
fd_sspeer_selector_best( fd_sspeer_selector_t * selector,
                         int                    incremental,
                         ulong                  base_slot );

/* Updates the selector's internal cluster slot and re-score all peers
   when the cluster slot updates (moves forward) */
void
fd_sspeer_selector_process_cluster_slot( fd_sspeer_selector_t * selector,
                                         ulong                  full_slot,
                                         ulong                  incr_slot );

/* Obtain the cluster slot from the selector.  It is the highest
   resolved full/incremental slot pair seen from snapshot hashes or
   from resolved http peers. */
fd_sscluster_slot_t
fd_sspeer_selector_cluster_slot( fd_sspeer_selector_t * selector );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_discof_restore_utils_fd_sspeer_selector_h */
