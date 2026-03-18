#ifndef HEADER_fd_src_discof_restore_utils_fd_sspeer_selector_h
#define HEADER_fd_src_discof_restore_utils_fd_sspeer_selector_h

/* The snapshot peer selector (sspeer_selector) continuously selects
   the most optimal snapshot peer to download snapshots from.  The
   most optimal peer is defined as the closest peer that serves the
   most recent snapshot. */

#include "../../../util/fd_util_base.h"
#include "../../../util/net/fd_net_headers.h"
#include "../../../flamenco/types/fd_types_custom.h"
#include "fd_sspeer.h"

#define FD_SSPEER_SELECTOR_MAGIC (0xF17EDA2CE5593350) /* FIREDANCE SSPING V0 */

/* Sentinel score returned by fd_sspeer_selector_best when no peer was
   found and by fd_sspeer_selector_add on failure. */
#define FD_SSPEER_SCORE_INVALID   (ULONG_MAX)

/* Maximum score a valid peer can have.  FD_SSPEER_SCORE_MAX ensures a
   valid peer's score is never confused with FD_SSPEER_SCORE_INVALID. */
#define FD_SSPEER_SCORE_MAX       (ULONG_MAX-1UL)

/* Sentinel value indicating that a snapshot slot (full or incremental)
   is unknown or absent. */
#define FD_SSPEER_SLOT_UNKNOWN    (ULONG_MAX)

/* Sentinel value indicating that peer latency has not been measured. */
#define FD_SSPEER_LATENCY_UNKNOWN (ULONG_MAX)

/* Return codes for fd_sspeer_selector_update_on_resolve. */
#define FD_SSPEER_UPDATE_SUCCESS         ( 0)
#define FD_SSPEER_UPDATE_ERR_NULL_KEY    (-1)
#define FD_SSPEER_UPDATE_ERR_NOT_FOUND   (-2)
#define FD_SSPEER_UPDATE_ERR_INVALID_ARG (-3)

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
  uchar         full_hash[ FD_HASH_FOOTPRINT ];
  uchar         incr_hash[ FD_HASH_FOOTPRINT ];
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

/* Update the selector when an http server is resolved.  The peer is
   identified by key.  The values that can be updated are slot and
   hash, for both full and incremental snapshots.  Returns
   FD_SSPEER_UPDATE_SUCCESS on success, FD_SSPEER_UPDATE_ERR_NULL_KEY
   if key==NULL, FD_SSPEER_UPDATE_ERR_NOT_FOUND if the key was not
   found, and FD_SSPEER_UPDATE_ERR_INVALID_ARG if the update failed
   due to invalid arguments (e.g. incr_slot < full_slot).

   Slot-based incremental clearing: when the caller provides
   incr_slot==FD_SSPEER_SLOT_UNKNOWN and full_slot!=FD_SSPEER_SLOT_UNKNOWN,
   the peer's existing incremental data is cleared if it is stale
   (peer->incr_slot < full_slot).  Otherwise, existing incremental
   data is preserved. */
int
fd_sspeer_selector_update_on_resolve( fd_sspeer_selector_t *  selector,
                                      fd_sspeer_key_t const * key,
                                      ulong                   full_slot,
                                      ulong                   incr_slot,
                                      uchar const             full_hash[ FD_HASH_FOOTPRINT ],
                                      uchar const             incr_hash[ FD_HASH_FOOTPRINT ] );

/* Update the selector when a ping response is received.  The only
   value that can be updated is the latency.  If multiple peers
   advertise the same address, the update is applied to all of them,
   since ssping cannot distinguish between these peers.  It returns
   the number of peers that have been updated. */
ulong
fd_sspeer_selector_update_on_ping( fd_sspeer_selector_t * selector,
                                   fd_ip4_port_t          addr,
                                   ulong                  latency );

/* Add a peer to the selector.  If the peer already exists,
   fd_sspeer_selector_add updates the existing peer's score using the
   given peer latency and snapshot info.  Returns the updated score.

   Slot-based incremental clearing: for an existing peer, when
   incr_slot==FD_SSPEER_SLOT_UNKNOWN and full_slot!=FD_SSPEER_SLOT_UNKNOWN,
   the peer's incremental data is cleared if it is stale
   (peer->incr_slot < full_slot).  For a new peer, full_hash and
   incr_hash are handled independently.

   Returns the updated score, or FD_SSPEER_SCORE_INVALID on failure. */
ulong
fd_sspeer_selector_add( fd_sspeer_selector_t * selector,
                        fd_sspeer_key_t const * key,
                        fd_ip4_port_t          addr,
                        ulong                  peer_latency,
                        ulong                  full_slot,
                        ulong                  incr_slot,
                        uchar const            full_hash[ FD_HASH_FOOTPRINT ],
                        uchar const            incr_hash[ FD_HASH_FOOTPRINT ] );

/* Remove a peer from the selector.  Peers are removed when they are
   not reachable or serving corrupted/malformed snapshots.  This is a
   no-op if the peer does not exist in the selector.  When removing by
   address, all peers advertising that address will be removed. */
void
fd_sspeer_selector_remove( fd_sspeer_selector_t *  selector,
                           fd_sspeer_key_t const * key );

void
fd_sspeer_selector_remove_by_addr( fd_sspeer_selector_t * selector,
                                   fd_ip4_port_t          addr );

/* Select the best peer to download a snapshot from.  incremental
   indicates to select a peer to download an incremental snapshot.  If
   incremental is set, base_slot must be a valid full snapshot slot.
   Peers that do not offer an incremental snapshot
   (incr_slot==FD_SSPEER_SLOT_UNKNOWN) are excluded from incremental
   selection. */
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

/* Helper functions to count how many elements exist in both peer maps
   (by_key and by_addr).  Mainly used in unit tests.  These are not
   optimized for performance. */
ulong
fd_sspeer_selector_peer_map_by_key_ele_cnt( fd_sspeer_selector_t * selector );

ulong
fd_sspeer_selector_peer_map_by_addr_ele_cnt( fd_sspeer_selector_t * selector );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_discof_restore_utils_fd_sspeer_selector_h */
