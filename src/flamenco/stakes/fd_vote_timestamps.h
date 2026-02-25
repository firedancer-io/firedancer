#ifndef HEADER_fd_src_flamenco_stakes_fd_vote_timestamps_h
#define HEADER_fd_src_flamenco_stakes_fd_vote_timestamps_h

#include "../../util/fd_util_base.h"
#include "../../util/tmpl/fd_map.h"
#include "../types/fd_types_custom.h"

FD_PROTOTYPES_BEGIN

// STATIC: SIZED FOR 2^25 PUBKEYS MAX, 1.25GiB
// PUBKEYS: Array<(Pubkey, ushort: refcnt)>
// PUBKEY_IDX: uint into pubkeys array
// PUBKEY_MAP: Map<Pubkey, PUBKEY_IDX>

// attach_child( fork_id: ushort, parent_fork_id: ushort );
// advance_root( fork_id: ushort ) -> ensure snapshot child
// insert( fork_id: ushort, pubkey: [u8; 32], slot: u64, timestamp: i64 );
// timestamp( fork_id: ushort ) -> i64;
//
// SNAPSHOTS: 8*2^25*8 bytes in gib ~ 2 GiB
// SNAPSHOTS: Pool<Array<PUBKEY_IDX, (slot_age, timestamp)>> // slot_age 19 bits, timestamp 45 bits
//
// DELTAS: List<(PUBKEY_IDX, timestamp)> // 4096 * 40000 * 4 bytes in gib ~ 0.61 GiB

struct fd_vote_timestamps;
typedef struct fd_vote_timestamps fd_vote_timestamps_t;

ulong
fd_vote_timestamps_align( void );

ulong
fd_vote_timestamps_footprint( ulong max_live_slots,
                              uchar max_snaps,
                              ulong max_vote_accs );

void *
fd_vote_timestamps_new( void * shmem,
                        ulong  max_live_slots,
                        ulong  max_snaps,
                        ulong  max_vote_accs,
                        ulong  seed );

fd_vote_timestamps_t *
fd_vote_timestamps_join( void * shmem );

ushort
fd_vote_timestamps_init( fd_vote_timestamps_t * vote_ts,
                         ulong                  slot,
                         ushort                 epoch );

ushort
fd_vote_timestamps_attach_child( fd_vote_timestamps_t * vote_ts,
                                 ushort                 parent_fork_idx,
                                 ulong                  slot,
                                 ushort                 epoch );

void
fd_vote_timestamps_advance_root( fd_vote_timestamps_t * vote_ts,
                                 ushort                 new_root_idx );

void
fd_vote_timestamps_insert( fd_vote_timestamps_t * vote_ts,
                           ushort                 fork_idx,
                           fd_pubkey_t            pubkey,
                           ulong                  timestamp,
                           ulong                  stake );

void
fd_vote_timestamps_insert_root( fd_vote_timestamps_t * vote_ts,
                                fd_pubkey_t            pubkey,
                                ulong                  timestamp,
                                ulong                  stake );

ulong
fd_vote_timestamps_get_timestamp( fd_vote_timestamps_t * vote_ts,
                                  ushort                 fork_idx );

void
fd_vote_timestamps_update_stakes( fd_vote_timestamps_t * vote_ts,
                                  fd_pubkey_t *          pubkey,
                                  ulong                  stake,
                                  ushort                 epoch );

void
fd_vote_timestamps_prune_child( fd_vote_timestamps_t * vote_ts,
                                ushort                 prune_idx );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_stakes_fd_vote_timestamps_h */
