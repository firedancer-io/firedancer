#include "../../disco/topo/fd_topo.h"
#include "../../disco/metrics/fd_metrics.h"
#include "utils/fd_snapshot_messages_internal.h"
#include "utils/fd_snapshot_archive.h"
#include "utils/fd_snapshot_reader.h"
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>

#define NAME "snaprd"
#define SNAP_READ_MAX ( 16384UL )
#define SNAPSHOT_OUT_LINK_IDX 0UL

/* The SnapRd tile at a high level is a state machine that downloads
   snapshots from the network or reads snapshots from disk and produces
   a byte stream that is parsed by downstream snapshot consumer tiles.
   The snaprd tile gathers the latest SnapshotHashes information from
   gossip to decide whether to download snapshots or read local
   snapshots from disk.  If the snaprd tile needs to download a snapshot,
   it goes through the process of discovering and selecting elegible
   peers from gossip to download from. */

/* The initial state is waiting for peer ContactInfo and SnapshotHashes
   to arrive from the gossip tile.  These gossip messages arrive over
   time in a non-deterministic order, so there is not a clear indicator
   when we have all such messages.

   If SnapRd receives at least one valid gossip peer, it will transition
   to COLLECTING_PEERS, where it will wait a fixed duration to wait for
   additional gossip peers to arrive.  */
#define FD_SNAPRD_STATE_WAITING_FOR_PEERS                    ( 0)

/* SnapRd waits until it sees a single valid gossip peer which we could
   download a snapshot from, and then waits a further fixed duration
   before transitioning to peer selection.  If no single peer has been
   received, or all received peers are invalid, SnapRd will stay in the
   waiting state indefinitely.

   If there are elegible peers and at least one known validator peer and
   there exists a local snapshot whose slot is recent enough compared to
   the collected SnapshotHashes slot numbers, SnapRd transitions to
   loading a snapshot from disk.

   If there are elegible peers and at least one known validator peer
   and no local snapshot is recent enough, SnapRd transitions to
   PINGING_PEERS. */
#define FD_SNAPRD_STATE_COLLECTING_PEERS                     ( 1)

/* Once peers are collected, SnapRd select peers by pinging
   ones that are reporting as having a recent snapshot, to see if they
   are online and what the latency is.  SnapRd pings all of them  and
   waits for responses for up to a second.  */
#define FD_SNAPRD_STATE_PINGING_PEERS                        ( 2)

/* Collect responses from pings. If we get no response, or the latency
   is too high the peer is marked as ignored for the next 3 minutes, but
   may be retried again later.  If there are no eligible peers, we
   transition back to WAITING_FOR_PEERS.

   Once we have waited a second for pings to come back, we can select a
   peer to try and download the snapshot from.  We select the peer based
   on a combination of latency and snapshot age, preferring peers
   that are both fast and have a recent snapshot. */
   /* TODO: Check how long to wait ... borrow from that python file */
#define FD_SNAPRD_STATE_COLLECTING_RESPONSES                 ( 3)

/* If SnapRd has decided to load the full snapshot from a local file, it
   can now begin reading it.  This choice is not reversible, and so any
   error encountered while reading the file will abort the boot process,
   rather than retrying from gossip.  Once the full snapshot is loaded,
   SnapRd may optionally load an incremental snapshot or due to
   configuration simply transition to the WAITING_FOR_LOAD stage. */
#define FD_SNAPRD_STATE_READING_FULL_FILE                    ( 4)

/* Optionally, after loading the full snapshot SnapRd loads the
   incremental snapshot from a local file.  This is also not reversible,
   and any error encountered while reading the file will abort the boot
   process, rather than retrying from gossip.  Once the incremental
   snapshot is loaded, the tile will transition to the WAITING_FOR_LOAD
   state. */
#define FD_SNAPRD_STATE_READING_INCREMENTAL_FILE             ( 5)

/* Once SnapRd has decided to download from a peer, it can begin to
   download the full snapshot from them.  This choice is still
   reversible if the peer turns out to be downloading to slow, or goes
   offline, or serves something corrupt, or we hit some other transient
   networking issue.  Once the full snapshot is downloaded, we may
   optionally download an incremental snapshot, or otherwise proceed to
   the WAITING_FOR_LOAD state. */
#define FD_SNAPRD_STATE_FULL_DOWNLOAD                        ( 6)

/* Optionally, after downloading the full snapshot we can now download
   the incremental snapshot from the same peer.  The choice to continue
   from the same peer is arbitrary, but we may later switch if the peer
   goes down or encounters an issue with the incremental snapshot.  This
   download is therefore reversible, and any error encountered while
   downloading the file will mark the peer as invalid, and transition to
   the PINGING_PEERS_INCREMENTAL state.  Once the incremental download
   successfully completes, the tile will transition to the
   WAITING_FOR_LOAD state. */
#define FD_SNAPRD_STATE_INCREMENTAL_DOWNLOAD                 ( 7)

/* If we have failed to download an incremntal snapshot, either because
   it was not available, the peer went offline, or it was corrupt, we
   may retry just the incremental snapshot download from a different
   peer.  We start this process by again, pinging all the peers that are
   reporting as having a recent incremental snapshot, built on top of
   the full snapshot we already have, and reporting a valid snapshot
   port.  If there is no valid peer, we abandon all progress and
   transition back to the WAITING_FOR_PEER state, as likely the cluster
   has moved forward and our full snapshot is now too old. */
#define FD_SNAPRD_STATE_PINGING_PEERS_INCREMENTAL            ( 8)

/* Once we have waited a second for pings to come back, we can select a
   peer to try and download the incremental snapshot from.  We select
   the peer based on a combination of latency and snapshot age,
   preferring peers that are both fast and have a recent snapshot.  If
   we get no response, or the latency is too high the peer is marked as
   ignored for the next 3 minutes, but may be retried again later.  If
   there are no eligible peers, we transition back to WAITING_FOR_PEER. */
#define FD_SNAPRD_STATE_COLLECTING_RESPONSES_INCREMENTAL     ( 9)

/* Once we have fully downloaded the full snapshot, and there is no
   following incremental snapshot, we are almost done, except that the
   load may fail later in the pipeline due to a decompression
   corruption, corrupt file, or some invalid account state.  If such a
   failure happens, we may wish to retry the process, by going back to
   the PINGING_PEERS state.  Once the full snapshot is successfully
   fully loaded, the tile will transition to the DONE state and
   shutdown. */
#define FD_SNAPRD_STATE_WAITING_FOR_FULL_LOAD                (10)

/* Once we have fully downloaded an incremental snapshot, we are almost
   done except that the load may fail later in the pipeline due to a
   decompression corruption, corrupt file, or some invalid account
   state.  If such a failure happens, we may wish to retry the process,
   by going back to the PINGING_PEERS_INCREMENTAL state.  Once the
   incremental snapshot is successfully fully loaded, the tile will
   transition to the DONE state and shutdown. */
#define FD_SNAPRD_STATE_WAITING_FOR_INCREMENTAL_LOAD         (11)

/* The terminal state of the tile, snapshot load is completed and
   the tile has exited. */
#define FD_SNAPRD_STATE_DONE                                 (12)

/* TODO: these should be received from gossip */
#define CLUSTER_SNAPSHOT_SLOT 0
#define INITIAL_PEERS_COUNT 2UL

fd_snapshot_peer_t initial_peers[ 2UL ] = {
  { .dest = {
    /* Solana testnet peer */
    .addr = FD_IP4_ADDR( 145, 40, 95, 69 ),
    .port = 8899
     },
  },
  { .dest = {
    /* A fast testnet peer from snapshot-finder script */
    .addr = FD_IP4_ADDR( 177, 54, 155, 187 ),
    .port = 8899
     },
  }
};

// fd_snapshot_peer_t initial_peers[ 2UL ] = {
//   { .dest = {
//     /* Solana testnet peer */
//     .addr = FD_IP4_ADDR( 170, 39, 214, 146 ),
//     .port = 8899
//      },
//   },
//   { .dest = {
//     /* A fast testnet peer from snapshot-finder script */
//     .addr = FD_IP4_ADDR( 177, 54, 155, 187 ),
//     .port = 8899
//      },
//   }
// };

/* fd_snaprd_download_pair indicates whether
   the full and incremental snapshots need to be downloaded or not. */
struct fd_snaprd_download_pair {
  int full;
  int incremental;
};

typedef struct fd_snaprd_download_pair fd_snaprd_download_pair_t;

struct fd_snaprd_tile {
  /* Snapshot bytestream producer */
  struct {
    fd_wksp_t *      wksp;
    ulong            chunk0;
    ulong            wmark;
    ulong            chunk;
  } out;

  fd_snaprd_download_pair_t               download_pair;
  fd_snapshot_archive_entry_t             full_snapshot_entry;
  fd_incremental_snapshot_archive_entry_t incremental_snapshot_entry;

  fd_snapshot_reader_t *        snapshot_reader;
  fd_snapshot_peers_manager_t * peers_manager;

  /* State machine */
  int                       state;
  long                      wait_deadline_nanos;
  long                      wait_duration_nanos;
  int                       should_download;

  struct {
    char path[ PATH_MAX ];
    int  do_download;
    int  incremental_snapshot_fetch;
    uint maximum_local_snapshot_age;
    uint minimum_download_speed_mib;
    uint maximum_download_retry_abort;
  } config;

  struct {

    struct {
      ulong bytes_read;
      ulong bytes_total;
      uint  num_retries;
    } full;

    struct {
      ulong bytes_read;
      ulong bytes_total;
      uint  num_retries;
    } incremental;

  } metrics;
};

typedef struct fd_snaprd_tile fd_snaprd_tile_t;

/* SnapRd tile Helper functions ***************************************/

__attribute__((noreturn)) FD_FN_UNUSED static void
fd_snaprd_shutdown( void ) {
  FD_COMPILER_MFENCE();
  FD_MGAUGE_SET( TILE, STATUS, 2UL );
  FD_COMPILER_MFENCE();

  FD_LOG_INFO(( "snaprd: shutting down" ));

  for(;;) pause();
}

static void
fd_snaprd_accumulate_metrics( fd_snaprd_tile_t *             ctx,
                              fd_snapshot_reader_metrics_t * metrics ) {
  switch ( ctx->state ) {
    case FD_SNAPRD_STATE_FULL_DOWNLOAD:
    case FD_SNAPRD_STATE_READING_FULL_FILE: {
      ctx->metrics.full.bytes_read  = metrics->bytes_read;
      ctx->metrics.full.bytes_total = metrics->bytes_total;
      break;
    }
    case FD_SNAPRD_STATE_INCREMENTAL_DOWNLOAD:
    case FD_SNAPRD_STATE_READING_INCREMENTAL_FILE: {
      ctx->metrics.incremental.bytes_read  = metrics->bytes_read;
      ctx->metrics.incremental.bytes_total = metrics->bytes_total;
      break;
    }
  }
}

static void
fd_snaprd_init_config( fd_snaprd_tile_t * ctx,
                       fd_topo_tile_t *   tile ) {
  fd_memcpy( ctx->config.path, tile->snaprd.snapshots_path, PATH_MAX );
  ctx->config.incremental_snapshot_fetch   = tile->snaprd.incremental_snapshot_fetch;
  ctx->config.do_download                  = tile->snaprd.do_download;
  ctx->config.maximum_local_snapshot_age   = tile->snaprd.maximum_local_snapshot_age;
  ctx->config.minimum_download_speed_mib   = tile->snaprd.minimum_download_speed_mib;

  if( tile->snaprd.maximum_download_retry_abort==0 ) {
    /* If the maximum download retry abort field is 0, allow infinite
       retries. */
    ctx->config.maximum_download_retry_abort = UINT_MAX;
  } else {
    ctx->config.maximum_download_retry_abort = tile->snaprd.maximum_download_retry_abort;
  }
}

static fd_snaprd_download_pair_t
fd_snaprd_should_download( fd_snaprd_tile_t * ctx ) {
  /* first, check if there are any full local snapshots and get the highest slot */
  int res = fd_snapshot_archive_get_latest_full_snapshot( ctx->config.path,
                                                          &ctx->full_snapshot_entry );

  /* If we don't have any full snapshots in the snapshots archive path, we need to download  */
  if( FD_UNLIKELY( res ) ) {
    FD_LOG_NOTICE(( "Unable to find any local full snapshots in the "
                    "snapshots path: %s. Downloading from peers.", ctx->config.path ));
    return ( fd_snaprd_download_pair_t ){ .full = 1,
                                            .incremental = ctx->config.incremental_snapshot_fetch };
  }

  ulong highest_slot = ctx->full_snapshot_entry.slot;
  if( ctx->config.incremental_snapshot_fetch ) {
    /* Next, get the incremental snapshot entry */
    res = fd_snapshot_archive_get_latest_incremental_snapshot( ctx->config.path,
                                                             &ctx->incremental_snapshot_entry );
    if( FD_UNLIKELY( res ) ) {
      /* there is no incremental snapshot entry */
      FD_LOG_NOTICE(( "Unable to find any local incremental snapshots "
                      "in the snapshots path %s. Downloading from peers.", ctx->config.path ));
      return ( fd_snaprd_download_pair_t ){ .full = 0,
                                              .incremental = 1 };
    }

    /* Validate the incremental snapshot builds off the full snapshot */
    if( ctx->incremental_snapshot_entry.base_slot != ctx->full_snapshot_entry.slot ) {
      FD_LOG_NOTICE(( "Local incremental snapshot at slot %lu does not build off the full snapshot at slot %lu. "
                      "Downloading from peers.",
                    ctx->incremental_snapshot_entry.inner.slot,
                    ctx->full_snapshot_entry.slot ));
      fd_memset( &ctx->incremental_snapshot_entry, 0, sizeof(fd_incremental_snapshot_archive_entry_t) );
      return ( fd_snaprd_download_pair_t ){ .full = 0,
                                              .incremental = 1 };
    }

    highest_slot = ctx->incremental_snapshot_entry.inner.slot;
  }

  /* Check that the snapshot age is within the maximum local snapshot age */
  if( highest_slot >= fd_ulong_sat_sub( CLUSTER_SNAPSHOT_SLOT, ctx->config.maximum_local_snapshot_age ) ) {
    FD_LOG_NOTICE(( "Re-using local full snapshot at slot %lu", ctx->full_snapshot_entry.slot ));
    if( ctx->config.incremental_snapshot_fetch ) {
      FD_LOG_NOTICE(( "Re-using local incremental snapshot at slot %lu", ctx->incremental_snapshot_entry.inner.slot ));
    }
    return ( fd_snaprd_download_pair_t ){ .full = 0,
                                            .incremental = 0 };
  } else {
    FD_LOG_NOTICE(( "Local snapshot at slot %lu is too old. ", ctx->full_snapshot_entry.slot ));
    fd_memset( &ctx->full_snapshot_entry, 0, sizeof(fd_snapshot_archive_entry_t) );
    return ( fd_snaprd_download_pair_t ){ .full = 1,
                                            .incremental = 1 };
  }
}

static void
fd_snaprd_init_reader( fd_snaprd_tile_t * ctx ) {
  ctx->download_pair = fd_snaprd_should_download( ctx );
  ctx->should_download = ctx->download_pair.full || ctx->download_pair.incremental;

  if( ctx->should_download && !ctx->config.do_download ) {
    FD_LOG_ERR(( "There are no valid local snapshots and the validator was configured to not download snapshots. "
                      "Please reconfigure the validator to enable snapshot downloading by setting [snapshots.do_download] to true." ));
  }

  ctx->snapshot_reader = fd_snapshot_reader_new( ctx->snapshot_reader,
                                                 ctx->download_pair.full,
                                                 ctx->download_pair.incremental,
                                                 ctx->config.path,
                                                 ctx->peers_manager,
                                                 &ctx->full_snapshot_entry,
                                                 &ctx->incremental_snapshot_entry,
                                                 ctx->config.incremental_snapshot_fetch,
                                                 ctx->config.minimum_download_speed_mib );

  if( ctx->download_pair.full ) {
    ctx->state = FD_SNAPRD_STATE_PINGING_PEERS;
  } else {
    ctx->state = FD_SNAPRD_STATE_READING_FULL_FILE;
  }
}

/* SnapRd State Machine Functions *************************************/

static void
handle_incremental( fd_snaprd_tile_t *  ctx,
                          fd_stem_context_t * stem ) {
  /* SnapRd is configured to load the incremental snapshot. */

  /* Prepare snapshot reader to read from incremental snapshot
    source. */
  fd_snapshot_reader_set_source_incremental( ctx->snapshot_reader );
  /* Determine next state from incremental source */
  int source_type = fd_snapshot_reader_get_source_type( ctx->snapshot_reader );
  if( source_type == SRC_FILE ) {
    ctx->state = FD_SNAPRD_STATE_READING_INCREMENTAL_FILE;
  } else {
    ctx->state = FD_SNAPRD_STATE_INCREMENTAL_DOWNLOAD;
  }

  /* Notify downstream consumers of incoming incremental snapshot
      byte stream. */
  fd_stem_publish( stem,
                    0UL,
                    FD_SNAPSHOT_MSG_CTRL_FULL_DONE,
                    ctx->out.chunk,
                    0UL,
                    0UL,
                    0UL,
                    0UL );
}

static void
handle_fini( fd_snaprd_tile_t * ctx,
             fd_stem_context_t * stem ) {
  /* snaprd is done with reading / downloading snapshots */
  ctx->state = FD_SNAPRD_STATE_DONE;
  fd_snapshot_reader_delete( ctx->snapshot_reader );

  /* SnapRd is shutting down, notify downstream consumers of the
     shutdown. */
  fd_stem_publish( stem,
                   0UL,
                   FD_SNAPSHOT_MSG_CTRL_FINI,
                   ctx->out.chunk,
                   0UL,
                   0UL,
                   0UL,
                   0UL );

  fd_snaprd_shutdown( );
}

static void
handle_file_complete( fd_snaprd_tile_t * ctx,
                            fd_stem_context_t * stem ) {
  switch( ctx->state ) {
    case FD_SNAPRD_STATE_FULL_DOWNLOAD:
    case FD_SNAPRD_STATE_READING_FULL_FILE: {
      if( ctx->config.incremental_snapshot_fetch ) {
        FD_LOG_INFO(("snaprd: done reading full snapshot, now reading incremental snapshot" ));
       handle_incremental( ctx, stem );
      } else {
        FD_LOG_INFO(( "snaprd: done reading full snapshot with size %lu",
                      ctx->metrics.full.bytes_total ));
        handle_fini( ctx, stem );
      }
      break;
    }
    case FD_SNAPRD_STATE_INCREMENTAL_DOWNLOAD:
    case FD_SNAPRD_STATE_READING_INCREMENTAL_FILE: {
      FD_LOG_INFO(( "snaprd: done reading incremental snapshot with size %lu",
                    ctx->metrics.incremental.bytes_total ));
      handle_fini( ctx, stem );
      break;
    }
  }
}

static void
handle_retry( fd_snaprd_tile_t * ctx,
              fd_stem_context_t * stem ) {
  uint * num_retries = NULL;

  /* Determine which num_retries metric to use from
     the state */
  if( ctx->state == FD_SNAPRD_STATE_FULL_DOWNLOAD ) {
    num_retries = &ctx->metrics.full.num_retries;
  } else if( ctx->state == FD_SNAPRD_STATE_INCREMENTAL_DOWNLOAD ) {
    num_retries = &ctx->metrics.incremental.num_retries;
  } else {
    FD_LOG_ERR(( "snaprd: unexpected state %d for retry", ctx->state ));
    return;
  }

  (*num_retries)++;

  /* Notify downstream consumers of retry (soft reset) */
  fd_stem_publish( stem,
                   0UL,
                   FD_SNAPSHOT_MSG_CTRL_RETRY,
                   ctx->out.chunk,
                   0UL,
                   0UL,
                   0UL,
                   0UL );

  if( FD_UNLIKELY( *num_retries > ctx->config.maximum_download_retry_abort ) ) {
    FD_LOG_ERR(( "Hit the maximum number of download retries, aborting." ));
  }

  if( ctx->state == FD_SNAPRD_STATE_INCREMENTAL_DOWNLOAD &&
      *num_retries == 1 ) {
    /* Upon trying the incremental download for the second time,
       we execute the peer selection process in case some peers have
       gone offline or changed during the time we downloaded or read
       the full snapshot. */
    ctx->state = FD_SNAPRD_STATE_PINGING_PEERS_INCREMENTAL;
  }
}

static void
handle_reset( fd_snaprd_tile_t *  ctx,
              fd_stem_context_t * stem ) {
  /* A fatal, recoverable snapshot loading error has occurred.
     Reset the snaprd tile to re-load both the full and incremental snapshots. */

  /* Notify downstream consumers of hard reset with start of message
     bit. */
  fd_stem_publish( stem,
                   0UL,
                   FD_SNAPSHOT_MSG_CTRL_ABANDON,
                   ctx->out.chunk,
                   0UL,
                   0UL,
                   0UL,
                   0UL );

  ctx->state = FD_SNAPRD_STATE_WAITING_FOR_PEERS;
}

static void
fd_snaprd_read_snapshot( fd_snaprd_tile_t * ctx,
                         fd_stem_context_t * stem ) {
  FD_TEST( ctx->state==FD_SNAPRD_STATE_READING_FULL_FILE ||
           ctx->state==FD_SNAPRD_STATE_READING_INCREMENTAL_FILE ||
           ctx->state==FD_SNAPRD_STATE_FULL_DOWNLOAD ||
           ctx->state==FD_SNAPRD_STATE_INCREMENTAL_DOWNLOAD );

  if( FD_UNLIKELY( !*stem->cr_avail ) ) return;

  uchar * out     = fd_chunk_to_laddr( ctx->out.wksp, ctx->out.chunk );
  ulong   out_max = SNAP_READ_MAX;
  ulong   sz      = 0UL;

  fd_snapshot_reader_metrics_t metrics =
    fd_snapshot_reader_read( ctx->snapshot_reader, out, out_max, &sz );

  if( FD_LIKELY( sz ) ) {
    fd_stem_publish( stem,
                     0UL,
                     FD_SNAPSHOT_MSG_DATA,
                     ctx->out.chunk,
                     sz,
                     0UL,
                     0UL,
                     0UL );
    ctx->out.chunk = fd_dcache_compact_next( ctx->out.chunk,
                                                sz,
                                                ctx->out.chunk0,
                                                ctx->out.wmark );
  }

  fd_snaprd_accumulate_metrics( ctx, &metrics );

  if( metrics.status == FD_SNAPSHOT_READER_DONE ) {
    handle_file_complete( ctx, stem );
  } else if( metrics.status == FD_SNAPSHOT_READER_RETRY ) {
    handle_retry( ctx, stem);
  } else if( metrics.status == FD_SNAPSHOT_READER_RESET ) {
    handle_reset( ctx, stem );
  } else if( metrics.status == FD_SNAPSHOT_READER_FAIL ) {
    /* aborts app */
    FD_LOG_ERR(( "Failed to read snapshot: %d", metrics.err ));
  }
}

static int
fd_snaprd_shared_state_transition( fd_snaprd_tile_t * ctx ) {
  switch( ctx->state ) {
    case FD_SNAPRD_STATE_PINGING_PEERS:
      return FD_SNAPRD_STATE_COLLECTING_RESPONSES;
    case FD_SNAPRD_STATE_PINGING_PEERS_INCREMENTAL:
      return FD_SNAPRD_STATE_COLLECTING_RESPONSES_INCREMENTAL;
    case FD_SNAPRD_STATE_COLLECTING_RESPONSES:
      return FD_SNAPRD_STATE_FULL_DOWNLOAD;
    case FD_SNAPRD_STATE_COLLECTING_RESPONSES_INCREMENTAL:
      return FD_SNAPRD_STATE_INCREMENTAL_DOWNLOAD;
    default: {
      FD_LOG_ERR(( "snaprd: unexpected state %d for shared state transition", ctx->state ));
      return -1; /* error */
    }
  }
}

/* snaprd callbacks ***************************************************/

static void
during_frag( fd_snaprd_tile_t * ctx,
             ulong              in_idx,
             ulong              seq,
             ulong              sig,
             ulong              chunk,
             ulong              sz,
             ulong              ctl ) {
  (void)ctx;
  (void)in_idx;
  (void)seq;
  (void)sig;
  (void)chunk;
  (void)sz;
  (void)ctl;
}

static void
after_credit( fd_snaprd_tile_t *  ctx,
              fd_stem_context_t * stem,
              int *               opt_poll_in,
              int *               charge_busy ) {
  (void)stem;
  (void)opt_poll_in;
  (void)charge_busy;
  // TODO: ... maybe query RPC for the nodes instead?

  /* Background tasks that always get run */
  fd_snapshot_peers_manager_update_peer_state( ctx->peers_manager );

  switch ( ctx->state ) {
    case FD_SNAPRD_STATE_WAITING_FOR_PEERS: {
      /* Stay in this state until we have received at least one peer
         from gossip. */

      /* Because we are not receiving from gossip right now, just
         set peers to be initial peers */
      fd_snapshot_peers_manager_set_peers_testing( ctx->peers_manager,
                                                   initial_peers,
                                                   INITIAL_PEERS_COUNT );
      if( ctx->peers_manager->peers_cnt > 0 ) {
        ctx->wait_deadline_nanos = fd_log_wallclock() + ctx->wait_duration_nanos;
        ctx->state = FD_SNAPRD_STATE_COLLECTING_PEERS;
      }
      break;
    }
    case FD_SNAPRD_STATE_COLLECTING_PEERS: {
      long now = fd_log_wallclock();
      if( now > ctx->wait_deadline_nanos ) {
        /* We have at least one peer after waiting a fixed duration to
           collect more peers.  Now, we can initialize our snapshot
           reader and decide whether to download snapshots from the
           network or read snapshots from disk. */
        fd_snaprd_init_reader( ctx );
      }
      break;
    }
    case FD_SNAPRD_STATE_PINGING_PEERS:
    case FD_SNAPRD_STATE_PINGING_PEERS_INCREMENTAL: {
      int complete = fd_snapshot_peers_manager_send_pings( ctx->peers_manager );
      if( complete ) {
        ctx->state = fd_snaprd_shared_state_transition( ctx );
      }
      break;
    }
    case FD_SNAPRD_STATE_COLLECTING_RESPONSES:
    case FD_SNAPRD_STATE_COLLECTING_RESPONSES_INCREMENTAL: {
      int complete = fd_snapshot_peers_maanger_collect_responses( ctx->peers_manager );
      if( complete ) {
        fd_snapshot_peers_manager_sort_peers( ctx->peers_manager );

        fd_snapshot_peers_manager_reset_pings( ctx->peers_manager );

        ctx->state = fd_snaprd_shared_state_transition( ctx );
      }
      break;
    }
    case FD_SNAPRD_STATE_READING_FULL_FILE:
    case FD_SNAPRD_STATE_READING_INCREMENTAL_FILE:
    case FD_SNAPRD_STATE_FULL_DOWNLOAD:
    case FD_SNAPRD_STATE_INCREMENTAL_DOWNLOAD:{
      fd_snaprd_read_snapshot( ctx, stem );
      break;
    }
    default: {
      FD_LOG_ERR(( "snaprd: unexpected state %d", ctx->state ));
      break;
    }
  }
}

/* SnapRd Tile Functions **********************************************/

static ulong
scratch_align( void ) {
  return alignof(fd_snaprd_tile_t);
}

static ulong
scratch_footprint( fd_topo_tile_t const * tile ) {
  (void)tile;
  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, alignof(fd_snaprd_tile_t),         sizeof(fd_snaprd_tile_t)              );
  l = FD_LAYOUT_APPEND( l, fd_snapshot_reader_align(),        fd_snapshot_reader_footprint()        );
  l = FD_LAYOUT_APPEND( l, fd_snapshot_peers_manager_align(), fd_snapshot_peers_manager_footprint() );
  return FD_LAYOUT_FINI( l, alignof(fd_snaprd_tile_t) );
}

static void
metrics_write( fd_snaprd_tile_t * ctx ) {
  FD_MGAUGE_SET( SNAPRD, FULL_BYTES_READ,               ctx->metrics.full.bytes_read );
  FD_MGAUGE_SET( SNAPRD, FULL_BYTES_TOTAL,              ctx->metrics.full.bytes_total );
  FD_MGAUGE_SET( SNAPRD, INCREMENTAL_BYTES_READ,        ctx->metrics.incremental.bytes_read );
  FD_MGAUGE_SET( SNAPRD, INCREMENTAL_BYTES_TOTAL,       ctx->metrics.incremental.bytes_total );
  FD_MGAUGE_SET( SNAPRD, FULL_DOWNLOAD_RETRIES,         ctx->metrics.full.num_retries );
  FD_MGAUGE_SET( SNAPRD, INCREMENTAL_DOWNLOAD_RETRIES,  ctx->metrics.incremental.num_retries );

  FD_MGAUGE_SET( SNAPRD, STATE, (ulong)ctx->state );
}

static void
privileged_init( fd_topo_t *      topo,
                 fd_topo_tile_t * tile ) {
  FD_SCRATCH_ALLOC_INIT( l, fd_topo_obj_laddr( topo, tile->tile_obj_id ) );
  fd_snaprd_tile_t * ctx     = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_snaprd_tile_t), sizeof(fd_snaprd_tile_t) );
  void * snapshot_reader_mem = FD_SCRATCH_ALLOC_APPEND( l, fd_snapshot_reader_align(), fd_snapshot_reader_footprint() );
  void * peers_manager_mem = FD_SCRATCH_ALLOC_APPEND( l, fd_snapshot_peers_manager_align(), fd_snapshot_peers_manager_footprint() );

  fd_memset( ctx, 0, sizeof(fd_snaprd_tile_t) );

  fd_snaprd_init_config( ctx, tile );

  /* initialized later when deciding whether to read or download snapshots */
  ctx->snapshot_reader = (fd_snapshot_reader_t *)snapshot_reader_mem;
  ctx->peers_manager   = fd_snapshot_peers_manager_new( peers_manager_mem );
}

static void
unprivileged_init( fd_topo_t *      topo,
                   fd_topo_tile_t * tile ) {
  (void)topo;
  if( FD_UNLIKELY( tile->in_cnt !=0UL ) ) {
    FD_LOG_ERR(( "tile `" NAME "` has %lu ins, expected 0",  tile->in_cnt  ));
  }
  if( FD_UNLIKELY( tile->out_cnt!=1UL ) ) {
    FD_LOG_ERR(( "tile `" NAME "` has %lu outs, expected 1", tile->out_cnt ));
  }

  FD_SCRATCH_ALLOC_INIT( l, fd_topo_obj_laddr( topo, tile->tile_obj_id ) );
  fd_snaprd_tile_t * ctx               = FD_SCRATCH_ALLOC_APPEND( l,
                                                                  alignof(fd_snaprd_tile_t),
                                                                  sizeof(fd_snaprd_tile_t) );

  ctx->metrics.full.bytes_read         = 0UL;
  ctx->metrics.incremental.bytes_read  = 0UL;

  /* set up the snapshot byte stream producer */
  fd_topo_link_t * writer_link = &topo->links[ tile->out_link_id[ SNAPSHOT_OUT_LINK_IDX ] ];
  ctx->out.wksp             = topo->workspaces[ topo->objs[ writer_link->dcache_obj_id ].wksp_id ].wksp;
  ctx->out.chunk0           = fd_dcache_compact_chunk0( fd_wksp_containing( writer_link->dcache ), writer_link->dcache );
  ctx->out.wmark            = fd_dcache_compact_wmark ( ctx->out.wksp, writer_link->dcache, writer_link->mtu );
  ctx->out.chunk            = ctx->out.chunk0;

  /* TODO: this might come from config later */
  ctx->wait_duration_nanos = 3UL * 1000000000UL; /* 3 seconds */
  ctx->state               = FD_SNAPRD_STATE_WAITING_FOR_PEERS;
}

#define STEM_BURST                  4UL
#define STEM_LAZY                   1e3L

#define STEM_CALLBACK_CONTEXT_TYPE  fd_snaprd_tile_t
#define STEM_CALLBACK_CONTEXT_ALIGN alignof(fd_snaprd_tile_t)

#define STEM_CALLBACK_METRICS_WRITE metrics_write
#define STEM_CALLBACK_DURING_FRAG   during_frag
#define STEM_CALLBACK_AFTER_CREDIT  after_credit

#include "../../disco/stem/fd_stem.c"

fd_topo_run_tile_t fd_tile_snaprd = {
  .name                 = NAME,
  .scratch_align        = scratch_align,
  .scratch_footprint    = scratch_footprint,
  .privileged_init      = privileged_init,
  .unprivileged_init    = unprivileged_init,
  .run                  = stem_run,
  .keep_host_networking = 1,
  .allow_connect        = 1
};

#undef NAME
