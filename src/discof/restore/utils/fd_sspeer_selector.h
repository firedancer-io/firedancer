#ifndef HEADER_fd_src_discof_restore_utils_fd_sspeer_selector_h
#define HEADER_fd_src_discof_restore_utils_fd_sspeer_selector_h

/* The snapshot peer selector (sspeer_selector) continuously selects
   the most optimal snapshot peer to download snapshots from.  The
   most optimal peer is defined as the closest peer that serves the
   most recent snapshot. */

#include "../../../util/fd_util_base.h"
#include "../../../util/net/fd_net_headers.h"

#define FD_SSPEER_SELECTOR_MAGIC (0xF17EDA2CE5593350) /* FIREDANCE SSPING V0 */

/* fd_ssinfo stores the resolved snapshot slot information from a peer. */
struct fd_ssinfo {
   struct {
     ulong slot;
   } full;

   struct {
     ulong base_slot;
     ulong slot;
   } incremental;
 };
 typedef struct fd_ssinfo fd_ssinfo_t;

 /* fd_sspeer_t represents a selected peer from the snapshot peer
    selector, including the peer's address, resolved snapshot slots,
    and selector score. */
struct fd_sspeer {
  fd_ip4_port_t addr;   /* address of the peer */
  fd_ssinfo_t   ssinfo; /* resolved snapshot slot info of the peer */
  ulong         score;  /* selector score of peer */
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
                        fd_ssinfo_t const *    ssinfo );

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
                                         fd_ssinfo_t const *    ssinfo );

/* Obtain the cluster slot from the selector.  It is the highest
   resolved full/incremental slot pair seen from snapshot hashes or
   from resolved http peers. */
fd_ssinfo_t
fd_sspeer_selector_cluster_slot( fd_sspeer_selector_t * selector );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_discof_restore_utils_fd_sspeer_selector_h */
