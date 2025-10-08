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

#define FD_SNAPRD_STATE_WAITING_FOR_PEERS               ( 0) /* Waiting for first peer to arrive from gossip to download from */
#define FD_SNAPRD_STATE_WAITING_FOR_PEERS_INCREMENTAL   ( 1) /* Waiting for peers when attempting to download an incremental snapshot */
#define FD_SNAPRD_STATE_COLLECTING_PEERS                ( 2) /* First peer arrived, wait a little longer to see if a better one arrives */
#define FD_SNAPRD_STATE_COLLECTING_PEERS_INCREMENTAL    ( 3) /* Collecting peers to download an incremental snapshot */
#define FD_SNAPRD_STATE_READING_FULL_FILE               ( 4) /* Full file looks better than peer, reading it from disk */
#define FD_SNAPRD_STATE_FLUSHING_FULL_FILE              ( 5) /* Full file was read ok, confirm it decompressed and inserted ok */
#define FD_SNAPRD_STATE_FLUSHING_FULL_FILE_RESET        ( 6) /* Resetting to load full snapshot from file again, confirm decompress and inserter are reset too */
#define FD_SNAPRD_STATE_READING_INCREMENTAL_FILE        ( 7) /* Incremental file looks better than peer, reading it from disk */
#define FD_SNAPRD_STATE_FLUSHING_INCREMENTAL_FILE       ( 8) /* Incremental file was read ok, confirm it decompressed and inserted ok */
#define FD_SNAPRD_STATE_FLUSHING_INCREMENTAL_FILE_RESET ( 9) /* Resetting to load incremental snapshot from file again, confirm decompress and inserter are reset too */
#define FD_SNAPRD_STATE_READING_FULL_HTTP               (10) /* Peer was selected, reading full snapshot from HTTP */
#define FD_SNAPRD_STATE_FLUSHING_FULL_HTTP              (11) /* Full snapshot was downloaded ok, confirm it decompressed and inserted ok */
#define FD_SNAPRD_STATE_FLUSHING_FULL_HTTP_RESET        (12) /* Resetting to load full snapshot from HTTP again, confirm decompress and inserter are reset too */
#define FD_SNAPRD_STATE_READING_INCREMENTAL_HTTP        (13) /* Peer was selected, reading incremental snapshot from HTTP */
#define FD_SNAPRD_STATE_FLUSHING_INCREMENTAL_HTTP       (14) /* Incremental snapshot was downloaded ok, confirm it decompressed and inserted ok */
#define FD_SNAPRD_STATE_FLUSHING_INCREMENTAL_HTTP_RESET (15) /* Resetting to load incremental snapshot from HTTP again, confirm decompress and inserter are reset too */
#define FD_SNAPRD_STATE_SHUTDOWN                        (16) /* The tile is done, and has likely already exited */

static inline const char *
fd_snaprd_state_str( ulong state ) {
  switch( state ) {
    case FD_SNAPRD_STATE_WAITING_FOR_PEERS:               return "waiting_for_peers";
    case FD_SNAPRD_STATE_WAITING_FOR_PEERS_INCREMENTAL:   return "waiting_for_peers_incremental";
    case FD_SNAPRD_STATE_COLLECTING_PEERS:                return "collecting_peers";
    case FD_SNAPRD_STATE_COLLECTING_PEERS_INCREMENTAL:    return "collecting_peers_incremental";
    case FD_SNAPRD_STATE_READING_FULL_FILE:               return "reading_full_file";
    case FD_SNAPRD_STATE_FLUSHING_FULL_FILE:              return "flushing_full_file";
    case FD_SNAPRD_STATE_FLUSHING_FULL_FILE_RESET:        return "flushing_full_file_reset";
    case FD_SNAPRD_STATE_READING_INCREMENTAL_FILE:        return "reading_incremental_file";
    case FD_SNAPRD_STATE_FLUSHING_INCREMENTAL_FILE:       return "flushing_incremental_file";
    case FD_SNAPRD_STATE_FLUSHING_INCREMENTAL_FILE_RESET: return "flushing_incremental_file_reset";
    case FD_SNAPRD_STATE_READING_FULL_HTTP:               return "reading_full_http";
    case FD_SNAPRD_STATE_FLUSHING_FULL_HTTP:              return "flushing_full_http";
    case FD_SNAPRD_STATE_FLUSHING_FULL_HTTP_RESET:        return "flushing_full_http_reset";
    case FD_SNAPRD_STATE_READING_INCREMENTAL_HTTP:        return "reading_incremental_http";
    case FD_SNAPRD_STATE_FLUSHING_INCREMENTAL_HTTP:       return "flushing_incremental_http";
    case FD_SNAPRD_STATE_FLUSHING_INCREMENTAL_HTTP_RESET: return "flushing_incremental_http_reset";
    case FD_SNAPRD_STATE_SHUTDOWN:                        return "shutdown";
    default:                                              return "unknown";
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
