#ifndef HEADER_fd_src_discof_restore_fd_snapct_tile_h
#define HEADER_fd_src_discof_restore_fd_snapct_tile_h

#include "../../util/fd_util_base.h"

/* The snapct tile at a high level is a state machine that downloads
   snapshots from the network or reads snapshots from disk and produces
   a byte stream that is parsed by downstream snapshot consumer tiles.
   The snapct tile gathers the latest SnapshotHashes information from
   gossip to decide whether to download snapshots or read local
   snapshots from disk.  If the snapct tile needs to download a snapshot,
   it goes through the process of discovering and selecting elegible
   peers from gossip to download from. */

#define FD_SNAPCT_STATE_INIT                            ( 0) /* Initialization step, it determines whether to start loading from file or to download */

#define FD_SNAPCT_STATE_WAITING_FOR_PEERS               ( 1) /* Waiting for first peer to arrive from gossip to download from */
#define FD_SNAPCT_STATE_WAITING_FOR_PEERS_INCREMENTAL   ( 2) /* Waiting for peers when attempting to download an incremental snapshot */
#define FD_SNAPCT_STATE_COLLECTING_PEERS                ( 3) /* First peer arrived, wait a little longer to see if a better one arrives */
#define FD_SNAPCT_STATE_COLLECTING_PEERS_INCREMENTAL    ( 4) /* Collecting peers to download an incremental snapshot */

#define FD_SNAPCT_STATE_READING_FULL_FILE               ( 5) /* Full file looks better than peer, reading it from disk */
#define FD_SNAPCT_STATE_FLUSHING_FULL_FILE_FINI         ( 6) /* Full file was read ok, signal downstream to finish all pending operations */
#define FD_SNAPCT_STATE_FLUSHING_FULL_FILE_DONE         ( 7) /* Full file was read ok, and all other tiles have finished processing it */
#define FD_SNAPCT_STATE_FLUSHING_FULL_FILE_RESET        ( 8) /* Resetting to load full snapshot from file again, confirm decompress and inserter are reset too */

#define FD_SNAPCT_STATE_READING_INCREMENTAL_FILE        ( 9) /* Incremental file looks better than peer, reading it from disk */
#define FD_SNAPCT_STATE_FLUSHING_INCREMENTAL_FILE_FINI  (10) /* Incremental file was read ok, and all other tiles have finished processing it */
#define FD_SNAPCT_STATE_FLUSHING_INCREMENTAL_FILE_DONE  (11) /* Incremental file was read ok, signal downstream to finish all pending operations */
#define FD_SNAPCT_STATE_FLUSHING_INCREMENTAL_FILE_RESET (12) /* Resetting to load incremental snapshot from file again, confirm decompress and inserter are reset too */

#define FD_SNAPCT_STATE_READING_FULL_HTTP               (13) /* Peer was selected, reading full snapshot from HTTP */
#define FD_SNAPCT_STATE_FLUSHING_FULL_HTTP_FINI         (14) /* Full snapshot was downloaded ok, and all other tiles have finished processing it */
#define FD_SNAPCT_STATE_FLUSHING_FULL_HTTP_DONE         (15) /* Full snapshot was downloaded ok, signal downstream to finish all pending operations */
#define FD_SNAPCT_STATE_FLUSHING_FULL_HTTP_RESET        (16) /* Resetting to load full snapshot from HTTP again, confirm decompress and inserter are reset too */

#define FD_SNAPCT_STATE_READING_INCREMENTAL_HTTP        (17) /* Peer was selected, reading incremental snapshot from HTTP */
#define FD_SNAPCT_STATE_FLUSHING_INCREMENTAL_HTTP_FINI  (18) /* Incremental snapshot was downloaded ok, and all other tiles have finished processing it */
#define FD_SNAPCT_STATE_FLUSHING_INCREMENTAL_HTTP_DONE  (19) /* Incremental snapshot was downloaded ok, signal downstream to finish all pending operations */
#define FD_SNAPCT_STATE_FLUSHING_INCREMENTAL_HTTP_RESET (20) /* Resetting to load incremental snapshot from HTTP again, confirm decompress and inserter are reset too */

#define FD_SNAPCT_STATE_SHUTDOWN                        (21) /* The tile is done, and has likely already exited */




static inline const char *
fd_snapct_state_str( ulong state ) {
  switch( state ) {
    case FD_SNAPCT_STATE_INIT:                            return "init";
    case FD_SNAPCT_STATE_WAITING_FOR_PEERS:               return "waiting_for_peers";
    case FD_SNAPCT_STATE_WAITING_FOR_PEERS_INCREMENTAL:   return "waiting_for_peers_incremental";
    case FD_SNAPCT_STATE_COLLECTING_PEERS:                return "collecting_peers";
    case FD_SNAPCT_STATE_COLLECTING_PEERS_INCREMENTAL:    return "collecting_peers_incremental";
    case FD_SNAPCT_STATE_READING_FULL_FILE:               return "reading_full_file";
    case FD_SNAPCT_STATE_FLUSHING_FULL_FILE_FINI:         return "flushing_full_file_fini";
    case FD_SNAPCT_STATE_FLUSHING_FULL_FILE_DONE:         return "flushing_full_file_done";
    case FD_SNAPCT_STATE_FLUSHING_FULL_FILE_RESET:        return "flushing_full_file_reset";
    case FD_SNAPCT_STATE_READING_INCREMENTAL_FILE:        return "reading_incremental_file";
    case FD_SNAPCT_STATE_FLUSHING_INCREMENTAL_FILE_FINI:  return "flushing_incremental_file_fini";
    case FD_SNAPCT_STATE_FLUSHING_INCREMENTAL_FILE_DONE:  return "flushing_incremental_file_done";
    case FD_SNAPCT_STATE_FLUSHING_INCREMENTAL_FILE_RESET: return "flushing_incremental_file_reset";
    case FD_SNAPCT_STATE_READING_FULL_HTTP:               return "reading_full_http";
    case FD_SNAPCT_STATE_FLUSHING_FULL_HTTP_FINI:         return "flushing_full_http_fini";
    case FD_SNAPCT_STATE_FLUSHING_FULL_HTTP_DONE:         return "flushing_full_http_done";
    case FD_SNAPCT_STATE_FLUSHING_FULL_HTTP_RESET:        return "flushing_full_http_reset";
    case FD_SNAPCT_STATE_READING_INCREMENTAL_HTTP:        return "reading_incremental_http";
    case FD_SNAPCT_STATE_FLUSHING_INCREMENTAL_HTTP_FINI:  return "flushing_incremental_http_fini";
    case FD_SNAPCT_STATE_FLUSHING_INCREMENTAL_HTTP_DONE:  return "flushing_incremental_http_done";
    case FD_SNAPCT_STATE_FLUSHING_INCREMENTAL_HTTP_RESET: return "flushing_incremental_http_reset";
    case FD_SNAPCT_STATE_SHUTDOWN:                        return "shutdown";
    default:                                              return "unknown";
  }
}

#define FD_SNAPCT_SNAPSHOT_TYPE_FULL        (0)
#define FD_SNAPCT_SNAPSHOT_TYPE_INCREMENTAL (1)

typedef struct {
  int type;
  int is_download;
  char read_path[ PATH_MAX ];
} fd_snapct_update_t;

#endif /* HEADER_fd_src_discof_restore_fd_snapct_tile_h */
