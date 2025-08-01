#ifndef HEADER_fd_src_discof_restore_utils_fd_sshashes_h
#define HEADER_fd_src_discof_restore_utils_fd_sshashes_h

#include "../../../util/fd_util_base.h"
#include "../../../flamenco/gossip/fd_gossip_update_msg.h"

/* SnapshotHashes are used verify snapshots served by peers discovered
   from gossip.  A SnapshotHash message contains the slot and hash of
   the latest full and incremental snapshot advertised by a peer.
   A validator verifies a snapshot by matching the
   snapshot's slot and hash against a set of known SnapshotHashes
   published by a set of known, trusted validators.  These known
   validators are configured manually at boot time.

   fd_sshashes_t stores the latest SnapshotHashes messages received
   from known validators.  It provides an interface to query and update
   a set of known SnapshotHashes as SnapshotHashes messages are
   continuously received from gossip.  It also continuously calculates
   the highest full and incremental slot pair from the set of known
   SnapshotHashes.  This highest slot pair is used to select a peer
   that is serving the latest snapshots on the cluster.

   Internally, it keeps a map from known validator pubkey
   to the latest SnapshotHash message by slot received.  It also keeps a
   KnownSnapshotHashes map, represented as
   HashMap<ulong slot, HashMap<ulong slot, hash>>, designed for O(1)
   querying. */
struct fd_sshashes_private;
typedef struct fd_sshashes_private fd_sshashes_t;

/* fd_sshashes_entry_t defines a slot and hash pair structure used
   to query known SnapshotHashes in fd_sshashes_t. */
struct fd_sshashes_entry {
  ulong slot;                      /* slot of the snapshot */
  uchar hash[ FD_HASH_FOOTPRINT ]; /* base58 decoded hash of the snapshot */
};

typedef struct fd_sshashes_entry fd_sshashes_entry_t;

/* fd_sshashes_cluster_slot_pair is */
struct fd_sshashes_cluster_slot_pair {
  ulong full;
  ulong incremental;
};

typedef struct fd_sshashes_cluster_slot_pair fd_sshashes_cluster_slot_pair_t;

#define FD_SSHASHES_MAGIC                (0xF17EDA2CE555710) /* FIREDANCER HTTP RESOLVE V0 */
#define FD_SSHASHES_KNOWN_VALIDATORS_MAX (16UL) /* maximum number of known validators */
#define FD_SSHASHES_MAP_KEY_MAX          (1UL<<5UL) /* 32 slots, 2*(maximum known vlidators) */

FD_PROTOTYPES_BEGIN

FD_FN_CONST ulong
fd_sshashes_align( void );

FD_FN_CONST ulong
fd_sshashes_footprint( void );

/* fd_sshashes_new formats a memory region to be suitable for use as
   an fd_sshashes_t object and initializes the fd_sshashes_t object with
   a set of known validators. */
void *
fd_sshashes_new( void * shmem,
                 char   known_validators[ FD_SSHASHES_KNOWN_VALIDATORS_MAX ][ FD_BASE58_ENCODED_32_SZ ],
                 ulong  known_validators_cnt );

fd_sshashes_t *
fd_sshashes_join( void * _sshashes_map );

/* fd_sshashes_init initializes an fd_sshashes_t object with a set
   of known validators.  Assumes that the fd_sshashes_t is in a clean
   and uninitialized state from fd_sshashes_join/fd_sshashes_new or from
   fd_sshashes_reset. */
void
fd_sshashes_init( fd_sshashes_t * sshashes,
                  char            known_validators[ FD_SSHASHES_KNOWN_VALIDATORS_MAX ][ FD_BASE58_ENCODED_32_SZ ],
                  ulong           known_validators_cnt );

void *
fd_sshashes_leave( fd_sshashes_t * sshashes );

void *
fd_sshashes_delete( fd_sshashes_t * sshashes );

/* fd_sshashes_query queries the set of known snapshot hashes with a
   full and incremental snapshot hash entry.  full_entry points to a
   fd_sshashes_entry_t, which is a slot and hash pair, for the full
   snapshot. inc_entry points to a fd_sshashes_entry_t for the
   incremental snapshot. The full entry must not be null but the
   incremental entry can be null.  Returns 1 if found and otherwise
   returns 0. */
int
fd_sshashes_query( fd_sshashes_t const *       sshashes,
                   fd_sshashes_entry_t const * full_entry,
                   fd_sshashes_entry_t const * incremental_entry );

#define FD_SSHASHES_REJECT  (-1)
#define FD_SSHASHES_SUCCESS ( 0)

/* fd_sshashes_update updates the set of known SnapshotHashes with a new
   SnapshotHash message.  Returns FD_SSHASHES_SUCCESS if the new
   SnapshotHash message was valid and the set of known SnapshotHashes
   was updated.  Returns FD_SSHASHES_REJECT if the SnapshotHash message
   was rejected for the following reasons:
   - The SnapshotHash message did not come from a known validator.
   - The SnapshotHash message was invalid.
   - The SnapshotHash message originated from a known validator but
     the SnapshotHash message was already previously received.  Thus
     the set of known SnapshotHashes is not updated.

   A SnapshotHash message is considered invalid if it contains the
   same slot as an existing known SnapshotHash with a different hash.
   Only the first hash is accepted for a given slot.  Any subsequently
   received SnapshotHashes that contain a different hash for the same
   slot are rejected.
   
   When fd_sshashes_t receives an invalid SnapshotHash message from a
   known validator, it removes the validator from the set of known
   validators, effectively blacklisting it.  Subsequent SnapshotHashes
   messages from that validator will be rejected. */
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

/* fd_sshashes_reset resets the internal state of sshashes.  Upon
   completion, the sshashes object will not contain any queryable
   SnapshotHashes and will not contain any known validators.  This means
   the sshashes object will not be able to accept any SnapshotHashes
   messages.  The caller is responsible for reinitializing the sshashes
   object by calling fd_sshashes_init with a new set of known
   validators for the sshashes object to be usable again. */
void
fd_sshashes_reset( fd_sshashes_t * sshashes );

/* fd_sshashes_print prints the internal set of known SnapshotHashes
   for tracing and debugging purposes. */
void
fd_sshashes_print( fd_sshashes_t const * sshashes );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_discof_restore_utils_fd_sshashes_h */
