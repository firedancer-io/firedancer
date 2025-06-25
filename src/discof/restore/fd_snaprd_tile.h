#ifndef HEADER_fd_src_discof_restore_fd_snaprd_tile_h
#define HEADER_fd_src_discof_restore_fd_snaprd_tile_h

#include "../../util/fd_util_base.h"

/* The snaprd tile at a high level is a state machine that downloads
   snapshots from the network or reads snapshots from disk and produces
   a byte stream that is parsed by downstream snapshot consumer tiles.
   The snaprd tile gathers the latest SnapshotHashes information from
   gossip to decide whether to download snapshots or read local
   snapshots from disk.  If the snaprd tile needs to download a snapshot,
   it goes through the process of discovering and selecting elegible
   peers from gossip to download from. */

#define FD_SNAPRD_STATE_WAITING_FOR_PEERS         ( 0) /* Waiting for first peer to arrive from gossip to download from */
#define FD_SNAPRD_STATE_COLLECTING_PEERS          ( 1) /* First peer arrived, wait a little longer to see if a better one arrives */
#define FD_SNAPRD_STATE_READING_FULL_FILE         ( 2) /* Full file looks better than peer, reading it from disk */
#define FD_SNAPRD_STATE_FLUSHING_FULL_FILE        ( 3) /* Full file was read ok, confirm it decompressed and inserted ok */
#define FD_SNAPRD_STATE_FLUSHING_FULL_FILE_RESET  ( 4) /* Resetting to load full snapshot from file again, confirm decompress and inserter are reset too */
#define FD_SNAPRD_STATE_READING_FULL_HTTP         ( 5) /* Peer was selected, reading full snapshot from HTTP */
#define FD_SNAPRD_STATE_FLUSHING_FULL_HTTP        ( 6) /* Full snapshot was downloaded ok, confirm it decompressed and inserted ok */
#define FD_SNAPRD_STATE_FLUSHING_FULL_HTTP_RESET  ( 7) /* Resetting to load full snapshot from HTTP again, confirm decompress and inserter are reset too */
#define FD_SNAPRD_STATE_READING_INCREMENTAL_FILE  ( 8) /* Incremental file looks better than peer, reading it from disk */
#define FD_SNAPRD_STATE_FLUSHING_INCREMENTAL_FILE ( 9) /* Incremental file was read ok, confirm it decompressed and inserted ok */
#define FD_SNAPRD_STATE_READING_INCREMENTAL_HTTP  (10) /* Peer was selected, reading incremental snapshot from HTTP */
#define FD_SNAPRD_STATE_FLUSHING_INCREMENTAL_HTTP (11) /* Incremental snapshot was downloaded ok, confirm it decompressed and inserted ok */
#define FD_SNAPRD_STATE_SHUTDOWN                  (12) /* The tile is done, and has likely already exited */

static inline const char *
fd_snaprd_state_str( ulong state ) {
  switch( state ) {
    case FD_SNAPRD_STATE_WAITING_FOR_PEERS:         return "waiting_for_peers";
    case FD_SNAPRD_STATE_COLLECTING_PEERS:          return "collecting_peers";
    case FD_SNAPRD_STATE_READING_FULL_FILE:         return "reading_full_file";
    case FD_SNAPRD_STATE_FLUSHING_FULL_FILE:        return "flushing_full_file";
    case FD_SNAPRD_STATE_FLUSHING_FULL_FILE_RESET:  return "flushing_full_file_reset";
    case FD_SNAPRD_STATE_READING_INCREMENTAL_FILE:  return "reading_incremental_file";
    case FD_SNAPRD_STATE_FLUSHING_INCREMENTAL_FILE: return "flushing_incremental_file";
    case FD_SNAPRD_STATE_READING_FULL_HTTP:         return "reading_full_http";
    case FD_SNAPRD_STATE_FLUSHING_FULL_HTTP:        return "flushing_full_http";
    case FD_SNAPRD_STATE_FLUSHING_FULL_HTTP_RESET:  return "flushing_full_http_reset";
    case FD_SNAPRD_STATE_READING_INCREMENTAL_HTTP:  return "reading_incremental_http";
    case FD_SNAPRD_STATE_FLUSHING_INCREMENTAL_HTTP: return "flushing_incremental_http";
    case FD_SNAPRD_STATE_SHUTDOWN:                  return "shutdown";
    default:                                        return "unknown";
  }
}

#define FD_SNAPRD_SNAPSHOT_TYPE_FULL        (0)
#define FD_SNAPRD_SNAPSHOT_TYPE_INCREMENTAL (1)

typedef struct {
  int type;
  int is_download;
  char read_path[ PATH_MAX ];
} fd_snaprd_update_t;

#endif /* HEADER_fd_src_discof_restore_fd_snaprd_tile_h */
