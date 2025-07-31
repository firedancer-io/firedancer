#ifndef HEADER_fd_src_discof_restore_utils_fd_sshashes_h
#define HEADER_fd_src_discof_restore_utils_fd_sshashes_h

#include "../../../util/fd_util_base.h"
#include "../../../flamenco/gossip/fd_gossip_update_msg.h"

/* SnapshotHashes are used verify snapshots served by peers discovered
   from gossip.  A SnapshotHash message contains the slot and hash of
   the latest full and incremental snapshot advertised by a validator.
   A validator verifies a snapshot by matching the
   snapshot's slot and hash against a set of known snapshot hashes
   published by a set of known, trusted validators.  These known
   validators are configured manually at boot time.

   fd_sshashes_t stores the latest SnapshotHashes messages received
   from known validators.  It provides an interface to query and update
   a set of known snapshot hashes as SnapshotHashes messages are
   continuously received from gossip.

   Internally, it keeps a map from known validator pubkey
   to the latest SnapshotHash message by slot received.  It also keeps a
   KnownSnapshotHashes map, represented as
   HashMap<ulong slot, HashMap<ulong slot, hash>>, designed for O(1)
   querying. */
struct fd_sshashes_private;
typedef struct fd_sshashes_private fd_sshashes_t;

/* fd_sshashes_entry_t defines a slot and hash pair structure used
   to query KnownSnapshotHashes in fd_sshashes_t. */
struct fd_sshashes_entry {
  ulong slot;                        /* slot of the snapshot */
  uchar hash[ FD_HASH_FOOTPRINT ]; /* base58 decoded hash of the snapshot */
};

typedef struct fd_sshashes_entry fd_sshashes_entry_t;

struct fd_sshashes_cluster_slot_pair {
  ulong full;
  ulong incremental;
};

typedef struct fd_sshashes_cluster_slot_pair fd_sshashes_cluster_slot_pair_t;

#define FD_SSHASHES_MAGIC (0xF17EDA2CE555710) /* FIREDANCER HTTP RESOLVE V0 */

#define FD_SSHASHES_MAP_KEY_MAX (1UL<<5UL) /* 32 slots, 2*(maximum known vlidators) */

FD_PROTOTYPES_BEGIN

FD_FN_CONST ulong
fd_sshashes_align( void );

FD_FN_CONST ulong
fd_sshashes_footprint( void );

void *
fd_sshashes_new( void * shmem );

fd_sshashes_t *
fd_sshashes_join( void * _sshashes_map );

void *
fd_sshashes_leave( fd_sshashes_t * sshashes );

void *
fd_sshashes_delete( fd_sshashes_t * sshashes );

/* fd_sshashes_query queries the set of known snapshot hashes with a
   full and incremental snapshot hash entry.  The full entry must not
   be null but the incremental entry can be null.  Returns 1 if found
   and otherwise returns 0. */
int
fd_sshashes_query( fd_sshashes_t const *       sshashes,
                   fd_sshashes_entry_t const * full_entry,
                   fd_sshashes_entry_t const * incremental_entry );

#define FD_SSHASHES_ERROR   (-1)
#define FD_SSHASHES_SUCCESS ( 0)

/* fd_sshashes_update updates the set of known snapshot hashes with a
   new SnapshotHash message.  The new SnapshotHash message is assumed to
   come from a known validator.  Returns FD_SSHASHES_SUCCESS_UPDATE if
   the the set of known snapshot hashes was updated.  Returns
   FD_SSHASHES_SUCCESS_PASS if the set of known snapshot hashes remains
   unchanged. Returns FD_SSHASHES_ERROR if the update failed or if the
   new SnapshotHash message is invalid.

   A SnapshotHash message is considered invalid if it contains the
   same slot as an existing known SnapshotHash with a different hash.
   Only the first hash is accepted for a given slot.  Any subsequently
   received SnapshotHashes that contain a different hash for the same
   slot are rejected. */
int
fd_sshashes_update( fd_sshashes_t *                         map,
                    uchar const                             pubkey[ static FD_HASH_FOOTPRINT ],
                    fd_gossip_upd_snapshot_hashes_t const * snapshot_hashes );

/* fd_sshashes_get_highest_slots returns a pair of the highest full
   and highest incremental snapshot slot advertised by known validators
   via SnapshotHashes messages.  The incremental slot is gauranteed to
   build off the full slot.  If no known SnapshotHashes messages have
   been received, the full and incremental slots in the slot pair
   are set to ULONG_MAX. */
fd_sshashes_cluster_slot_pair_t
fd_sshashes_get_highest_slots( fd_sshashes_t const * sshashes );

/* fd_sshashes_reset resets the internal state of sshashes. */
void
fd_sshashes_reset( fd_sshashes_t * sshashes );

void
fd_sshashes_print( fd_sshashes_t const * sshashes );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_discof_restore_utils_fd_sshashes_h */
