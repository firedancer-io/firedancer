/* The dragon tile serves the Yellowstone Dragon's Mouth gRPC API.  It
   owns an fd_grpc_server, routes the geyser.Geyser service through
   fd_dragon_rpc, and feeds the geyser core with replay's
   notifications, which is what the fork graph, the commitment
   statuses and the unary calls are built from.  It is a waker client:
   the sockets it owns live in the waker's inner epoll set, so the tile
   only touches them when the waker says one is ready.

   The tile feeds the validator nothing and may exit on its own
   (allow_shutdown).  It is a reliable consumer of replay's slot
   statuses, so that a finalized subscriber never loses one, and an
   unreliable consumer of every record and event link.  A reliable
   consumer of a hot link holds replay if it stops consuming, so
   nothing in this tile's frag path may block: the accounts database is
   read past its cache only for a sealed bank, nothing touches disk,
   and every pass does a bounded amount of work; the lag gate and the
   duty bound keep the send side from starving the input side.
   contrib/dragon/frag_path_check.sh holds the file to that.  Its one
   output is the bank references it gives back to replay, published as
   soon as it can: replay's storage reclamation waits on them. */

#include "fd_dragon_rpc.h"
#include "fd_dragon_tile.h"
#include "../../disco/events/fd_event_report.h"
#include "fd_dragon_index.h"
#include "fd_dragon_ingest.h"
#include "fd_geyser_core.h"

#include "../replay/fd_replay_tile.h"
#include "../../disco/fd_clock_tile.h"
#include "../../disco/metrics/fd_metrics.h"
#include "../../disco/topo/fd_topo.h"
#include "../../disco/waker/fd_waker.h"
#include "../../flamenco/accdb/fd_accdb.h"
#include "../../flamenco/accdb/fd_accdb_shmem.h"
#include "../../flamenco/runtime/fd_runtime_const.h"
#include "../../waltz/grpc/fd_grpc_server.h"

#include <errno.h>
#include <sys/epoll.h>
#include <sys/resource.h>
#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>

#include "generated/fd_dragon_tile_seccomp.h"

/* FD_DRAGON_SERVICE_INTERVAL_NANOS is how often the tile runs the
   server's timers when nothing woke it.  Keepalive, deadline and
   subscription ping deadlines are therefore accurate to this. */

#define FD_DRAGON_SERVICE_INTERVAL_NANOS (1000000L) /* 1ms */

/* FD_DRAGON_SEND_HOLDOFF_SHIFT bounds the share of the core the send
   passes may take: after a pass of cost c the next one waits c>>SHIFT,
   so sends get at most 2^SHIFT/(2^SHIFT+1) of the time and reading the
   input links gets the rest.  A pass that finds little to send costs
   little and holds nothing off; one that drains a backlog of sends
   delays the next sends, and so coalesces more messages into each,
   instead of starving the record links. */

#define FD_DRAGON_SEND_HOLDOFF_SHIFT (1) /* sends <= 2/3 of the core */

/* FD_DRAGON_REPLAY_LAG_SHIFT bounds how far the tile may fall behind on
   its replay link, a reliable link whose depth replay stops at, before
   send passes stop until it has caught up: a quarter of the depth.
   Replay never waits on this tile; clients do. */

#define FD_DRAGON_REPLAY_LAG_SHIFT (2)

/* FD_DRAGON_SHUTDOWN_GRACE_NANOS bounds how long a shutting down tile
   waits for connections to take their GOAWAY. */

#define FD_DRAGON_SHUTDOWN_GRACE_NANOS (1000000000L) /* 1s */

/* Transport sizing that is not exposed as config: requests are small
   and the number of concurrent calls is bounded, so these are fixed. */

#define FD_DRAGON_MAX_FRAME_SZ   (16384UL)
#define FD_DRAGON_CONN_RX_WND_SZ (1048576UL)
#define FD_DRAGON_STREAM_RX_WND_SZ (262144UL)

#define IN_KIND_REPLAY (0)
#define IN_KIND_RECORD (1)
#define IN_KIND_EVENT  (2)

/* FD_DRAGON_IN_MAX bounds the tile's input links: replay's
   notifications plus one record link per producer tile. */

#define FD_DRAGON_IN_MAX (64UL)

struct fd_dragon_tile {
  fd_grpc_server_t * server;
  fd_dragon_rpc_t *  rpc;
  fd_geyser_core_t * core;

  /* The read-only join to the accounts database, which is what
     fd_geyser_read_account reads an account at a bank's fork through.
     NULL when finalized is off: the tile then joins nothing.
     acct_data is where one account's data lands, which the API
     demands be as large as an account can be. */
  fd_accdb_t * accdb;
  uchar *      acct_data;
  uchar        acct_owner[ 32 ];

  ulong   waker_client_idx;
  ulong * waker_fseq;
  int     epoll_fd;
  int     listen_fd;      /* the listening socket, -1 before it is bound */

  ulong   conn_cnt;       /* client sockets the transport currently holds */
  ulong   conn_max;       /* max_clients */
  ulong   call_max;       /* max_clients*max_streams_per_client */

  int          serving;
  long         service_nanos;
  long         send_interval_nanos;
  long         service_holdoff_nanos; /* wallclock before which no pass runs */
  ulong const * replay_in_seq;      /* producer sequence of the replay link, NULL without one */
  ulong         replay_in_idx;
  ulong         replay_lag_max;     /* frags behind the producer at which send passes yield */
  ulong         replay_lag_gate_cnt;
  ulong        tx_msg_seen;  /* server tx_msg_cnt as of the last service pass */
  long         shutdown_nanos;  /* 0 while the tile is not shutting down */
  int          shutdown_pending;/* the shutdown was asked for and the transport has not been stopped yet */
  char const * shutdown_reason; /* what made the tile shut down, NULL while it is not */
  int          detach_pending;  /* the tile is shutting down and replay has not been told yet */

  fd_clock_tile_t clock[1];

  ulong in_cnt;
  uchar in_kind[ FD_DRAGON_IN_MAX ];
  struct {
    void * mem;
    ulong  chunk0;
    ulong  wmark;
    ulong  mtu;
    ulong  asm_idx;  /* index into the ingest module's links, ULONG_MAX for a link that carries no records */
    ulong  next_seq; /* sequence number the next frag of this link must have, ULONG_MAX before the first */
    ulong const * seq_laddr; /* where the producer publishes how far it has got */
  } in[ FD_DRAGON_IN_MAX ];

  /* The most fragments a record link was ever seen to be ahead of the
     tile, sampled once per housekeeping.  The link depth is the bound;
     a link that reaches it loses records. */
  ulong record_lag_hi;

  fd_dragon_ingest_t * ingest;
  ulong                record_link_cnt;

  /* The ingest link whose record the frag just completed, ULONG_MAX if
     none. */
  ulong asm_ready;

  ulong record_malformed_cnt;  /* records the core could not read */
  fd_histf_t record_sz[1];     /* size of the commit records, which is what the memory model is built on */
  fd_histf_t ref_hi[1];      /* pending segment high water of the calls that ended */
  fd_histf_t acct_read[1];     /* nanoseconds a read at a bank's fork takes */
  ulong record_bad_chunk_cnt;  /* frags naming a chunk outside the link's dcache */


  ulong  replay_out_idx;
  void * replay_out_mem;
  ulong  replay_out_chunk0;
  ulong  replay_out_wmark;
  ulong  replay_out_chunk;

  /* Bank references waiting to be published back to replay.  The core
     can ask for a whole fork graph's worth at once (a root advance
     that prunes everything, or an input gap), which is more than one
     stem iteration may publish, so they queue here.  The queue holds
     one entry per bank index replay can have live plus two per record
     in the core's graph, which is the most the core can ever owe. */
  ulong                 release_max;
  ulong                 release_cnt;
  ulong                 release_head;
  ulong                 release_drop_cnt;
  fd_dragon_release_t * release;

  /* Test-only: the slot whose completion makes the tile shut down, 0
     when the tile runs until the validator does. */
  ulong exit_at_slot;

  ulong replay_frag_cnt;
  ulong slot_completed_cnt;
  ulong overrun_cnt;

  /* Set when the tile lost frags; the next frag it handles carries the
     sequence number the recovery needs. */
  int gap_pending;

  fd_replay_message_t frag[1];
  int                 frag_valid;
  /* One runtime_txn event, copied out of its frag. */
  fd_event_runtime_txn_t event[1];
};

typedef struct fd_dragon_tile fd_dragon_tile_t;

/* dragon_release_max bounds the release queue.  Five references per
   live bank covers the whole fork graph (two records per bank index,
   one reference each from the bank being published and one from it
   becoming the root) and a full sweep of every bank index after an
   input gap. */

static inline ulong
dragon_release_max( fd_topo_tile_t const * tile ) {
  return 5UL*tile->dragon.max_live_banks;
}

/* dragon_release queues one bank reference for release.  Losing one
   would keep replay from reclaiming storage, so the queue is sized to
   never fill; a full queue is counted and logged, and the reference is
   recovered the next time an input gap sweeps every bank index. */

static void
dragon_release( void * _ctx,
                ulong  bank_idx,
                ulong  seq_bound ) {
  fd_dragon_tile_t * ctx = _ctx;
  if( FD_UNLIKELY( ctx->release_cnt>=ctx->release_max ) ) {
    ctx->release_drop_cnt++;
    FD_DRAGON_WARN_POW2( ctx->release_drop_cnt,
                         "dragon release queue full, bank idx %lu not released", bank_idx );
    return;
  }
  ulong i = (ctx->release_head+ctx->release_cnt) % ctx->release_max;
  ctx->release[ i ].bank_idx  = bank_idx;
  ctx->release[ i ].seq_bound = seq_bound;
  ctx->release_cnt++;
}

/* dragon_release_flush publishes up to FD_DRAGON_RELEASE_BURST queued
   releases, which is the tile's stem burst. */

static void
dragon_release_flush( fd_dragon_tile_t *  ctx,
                      fd_stem_context_t * stem ) {
  ulong cnt = fd_ulong_min( ctx->release_cnt, FD_DRAGON_RELEASE_BURST );
  /* before_credit runs ahead of the stem's credit gate, so the flush
     bounds itself by the credits that are actually available. */
  cnt = fd_ulong_min( cnt, stem->cr_avail[ ctx->replay_out_idx ] );
  for( ulong i=0UL; i<cnt; i++ ) {
    fd_dragon_release_t const * rel = ctx->release + ctx->release_head;
    ctx->release_head = (ctx->release_head+1UL) % ctx->release_max;
    ctx->release_cnt--;

    fd_dragon_release_t * msg = fd_chunk_to_laddr( ctx->replay_out_mem, ctx->replay_out_chunk );
    *msg = *rel;
    fd_stem_publish( stem, ctx->replay_out_idx, rel->bank_idx, ctx->replay_out_chunk,
                     sizeof(fd_dragon_release_t), 0UL, 0UL, 0UL );
    ctx->replay_out_chunk = fd_dcache_compact_next( ctx->replay_out_chunk, sizeof(fd_dragon_release_t),
                                                    ctx->replay_out_chunk0, ctx->replay_out_wmark );
  }
}

ulong
fd_dragon_index_html_sz( void ) {
  return sizeof(fd_dragon_index_html)-1UL;
}

static fd_grpc_server_params_t
derive_server_params( fd_topo_tile_t const * tile ) {
  fd_grpc_server_params_t params[1];
  fd_grpc_server_params_default( params );
  params->max_conn_cnt             = tile->dragon.max_clients;
  params->max_conn_per_addr        = tile->dragon.max_clients_per_address;
  params->max_stream_cnt           = tile->dragon.max_streams_per_client;
  params->max_request_msg_sz       = tile->dragon.max_request_bytes;
  params->request_buf_cnt          = tile->dragon.request_buffers;
  params->tx_ring_sz               = tile->dragon.send_buffer_size_mb<<20;
  params->stream_tx_ref_max        = tile->dragon.channel_capacity;
  params->tx_ref_pool              = tile->dragon.channel_pool_capacity;
  params->max_msg_sz               = tile->dragon.max_message_bytes;
  params->conn_rx_buf_sz           = tile->dragon.conn_recv_bytes;
  params->conn_tx_buf_sz           = tile->dragon.conn_send_bytes;
  params->tx_burst_cnt             = tile->dragon.burst_buffers;
  params->tx_burst_sz              = tile->dragon.burst_send_bytes;
  params->send_interval_nanos      = tile->dragon.send_interval_nanos;
  params->max_frame_sz             = FD_DRAGON_MAX_FRAME_SZ;
  params->conn_rx_wnd_sz           = FD_DRAGON_CONN_RX_WND_SZ;
  params->stream_rx_wnd_sz         = FD_DRAGON_STREAM_RX_WND_SZ;
  params->idle_timeout_nanos       = tile->dragon.idle_timeout_nanos;
  params->compression              = tile->dragon.compression;
  params->compression_min_sz       = tile->dragon.compression_min_bytes;
  params->compression_level        = tile->dragon.compression_level;
  params->web                      = tile->dragon.grpc_web;
  params->web_index                = fd_dragon_index_html;
  params->web_index_sz             = sizeof(fd_dragon_index_html)-1UL;
  return *params;
}

static fd_dragon_rpc_params_t
derive_rpc_params( fd_topo_tile_t const * tile ) {
  fd_dragon_rpc_params_t params = {
    .stream_max            = tile->dragon.max_clients*tile->dragon.max_streams_per_client,
    .request_max           = tile->dragon.max_request_bytes,
    .ping_interval_nanos   = tile->dragon.ping_interval_nanos,
    .x_token               = tile->dragon.x_token,
    .finalized             = tile->dragon.finalized,
    .filter_at             = tile->dragon.filter_at,
    .buf_depth             = FD_DRAGON_BUF_DEPTH,
    .filter_limits         = &tile->dragon.filter_limits,
    .cuckoo_bytes          = tile->dragon.cuckoo_bytes_per_client,
    /* An account update or a block is assembled whole before it is
       sent; the transport delivers one larger than a client's send
       queue from a large send slot, so the bound is the largest
       message the transport takes. */
    .msg_max_bytes         = tile->dragon.max_message_bytes,
    /* The buffer holds a bank from the moment something of it is
       buffered until the bank is rooted or dropped, which is the same
       span the fork graph covers. */
    .bank_max              = 2UL*tile->dragon.max_live_banks
  };
  return params;
}

/* dragon_read_account reads one account at a bank's accdb fork, which
   is what fd_geyser_read_account is built on.  An account that is not
   at the fork is one the block closed, which the caller is told by the
   lamports it gets.  The core only calls this for a sealed bank, whose
   fork is frozen, so the read never waits on a write in progress. */

static int
dragon_read_account( void *                _ctx,
                     fd_accdb_fork_id_t    fork_id,
                     uchar const *         pubkey,
                     fd_geyser_account_t * out ) {
  fd_dragon_tile_t * ctx = _ctx;
  if( FD_UNLIKELY( !ctx->accdb ) ) return -1;

  ulong lamports   = 0UL;
  int   executable = 0;
  ulong data_sz    = 0UL;

  fd_memset( ctx->acct_owner, 0, sizeof(ctx->acct_owner) );
  long t0  = fd_tickcount();
  int  res = fd_accdb_read_one_nocache_max( ctx->accdb, fork_id, pubkey, &lamports, &executable,
                                            ctx->acct_owner, ctx->acct_data, FD_RUNTIME_ACC_SZ_MAX,
                                            0, &data_sz );
  fd_histf_sample( ctx->acct_read, fd_metrics_convert_ticks_to_nanoseconds( (ulong)fd_long_max( fd_tickcount()-t0, 0L ) ) );

  out->owner = ctx->acct_owner;
  if( FD_UNLIKELY( res==FD_ACCDB_READ_ONE_NOCACHE_MISS ) ) return 0;

  out->lamports   = lamports;
  out->executable = executable;
  out->data       = data_sz ? ctx->acct_data : NULL;
  out->data_sz    = data_sz;
  return 0;
}

static fd_geyser_core_params_t
derive_core_params( fd_topo_tile_t const * tile ) {
  fd_geyser_core_params_t params = {
    .max_live_banks = tile->dragon.max_live_banks,
    /* A bank is sealed only once every transaction record it produced
       and the four sysvar writes of its slot have arrived. */
    .records_gate   = 1,
    .release_fn     = dragon_release,
    .read_fn        = tile->dragon.finalized ? dragon_read_account : NULL
  };
  return params;
}

FD_FN_CONST static inline ulong
scratch_align( void ) {
  ulong a = alignof(fd_dragon_tile_t);
  a = fd_ulong_max( a, fd_grpc_server_align() );
  a = fd_ulong_max( a, fd_dragon_rpc_align()  );
  a = fd_ulong_max( a, fd_geyser_core_align() );
  a = fd_ulong_max( a, fd_accdb_align()       );
  return a;
}

static inline ulong
scratch_footprint( fd_topo_tile_t const * tile ) {
  fd_grpc_server_params_t server_params = derive_server_params( tile );
  fd_dragon_rpc_params_t  rpc_params    = derive_rpc_params( tile );
  fd_geyser_core_params_t core_params   = derive_core_params( tile );

  ulong server_fp = fd_grpc_server_footprint( &server_params );
  if( FD_UNLIKELY( !server_fp ) ) FD_LOG_ERR(( "invalid [tiles.dragon] config parameters" ));
  ulong rpc_fp = fd_dragon_rpc_footprint( &rpc_params );
  if( FD_UNLIKELY( !rpc_fp ) ) FD_LOG_ERR(( "invalid [tiles.dragon] config parameters" ));
  ulong core_fp = fd_geyser_core_footprint( &core_params );
  if( FD_UNLIKELY( !core_fp ) ) FD_LOG_ERR(( "invalid [tiles.dragon] config parameters" ));

  /* What the tile costs, itemized the way [tiles.dragon]'s memory
     model in default.toml is, so that an operator can check the
     configuration against the machine without doing the arithmetic. */
  FD_LOG_NOTICE(( "dragon memory: transport %lu MiB, service %lu MiB, buffer %lu MiB, core %lu MiB, "
                  "records %lu MiB, account read %lu MiB",
                  server_fp>>20, rpc_fp>>20, tile->dragon.finalized ? tile->dragon.buffer_size_mib : 0UL, core_fp>>20,
                  ( tile->dragon.record_link_cnt ? fd_dragon_ingest_footprint( tile->dragon.record_link_cnt ) : 0UL )>>20,
                  ( tile->dragon.finalized ? (ulong)FD_RUNTIME_ACC_SZ_MAX : 0UL )>>20 ));

  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, alignof(fd_dragon_tile_t), sizeof(fd_dragon_tile_t)                 );
  l = FD_LAYOUT_APPEND( l, fd_dragon_rpc_align(),     rpc_fp                                   );
  l = FD_LAYOUT_APPEND( l, fd_grpc_server_align(),    server_fp                                );
  l = FD_LAYOUT_APPEND( l, fd_geyser_core_align(),    core_fp                                  );
  l = FD_LAYOUT_APPEND( l, alignof(fd_dragon_release_t), dragon_release_max( tile )*sizeof(fd_dragon_release_t) );
  if( FD_LIKELY( tile->dragon.record_link_cnt ) )
    l = FD_LAYOUT_APPEND( l, fd_dragon_ingest_align(), fd_dragon_ingest_footprint( tile->dragon.record_link_cnt ) );
  if( FD_LIKELY( tile->dragon.finalized ) ) {
    l = FD_LAYOUT_APPEND( l, fd_accdb_align(), fd_accdb_footprint( tile->dragon.max_live_banks, 0 ) );
    l = FD_LAYOUT_APPEND( l, 128UL,            FD_RUNTIME_ACC_SZ_MAX                            );
  }
  return FD_LAYOUT_FINI( l, scratch_align() );
}

static void
dragon_shutdown_begin( fd_dragon_tile_t * ctx,
                       char const *       reason ) {
  if( FD_UNLIKELY( ctx->shutdown_nanos || ctx->shutdown_pending ) ) return;
  FD_LOG_WARNING(( "dragon tile is shutting down: %s", reason ));

  /* The health watchers are told first, and the GOAWAY waits for the
     next service tick: fd_grpc_server_shutdown throws away whatever is
     still queued, and this one message is the point of watching.  The
     wait is also what makes this safe to call from a transport
     callback, which must not re-enter the transport to flush. */
  fd_dragon_rpc_set_serving( ctx->rpc, 0 );
  ctx->shutdown_reason  = reason;
  ctx->shutdown_pending = 1;
}

/* dragon_shutdown_flush sends what the shutdown owes its clients and
   then stops the transport.  Runs on the service tick, outside any
   transport callback. */

static void
dragon_shutdown_flush( fd_dragon_tile_t * ctx,
                       long               now ) {
  ctx->shutdown_pending = 0;
  fd_grpc_server_shutdown( ctx->server );
  ctx->shutdown_nanos = now;
  ctx->detach_pending = 1;
}

/* dragon_detach_flush publishes the tile's last message to replay: it
   is leaving, and every reference replay granted it has to come back,
   or the banks holding them can never be pruned.  The detach covers
   every grant replay has, including the ones the tile never saw, so
   the releases already queued are subsumed by it and the queue is
   dropped.  Notifications the tile keeps handling during its
   shutdown grace period still queue releases behind it; replay holds
   no grants by then, so they change nothing. */

static void
dragon_detach_flush( fd_dragon_tile_t *  ctx,
                     fd_stem_context_t * stem ) {
  fd_dragon_release_t * msg = fd_chunk_to_laddr( ctx->replay_out_mem, ctx->replay_out_chunk );
  msg->bank_idx  = FD_DRAGON_RELEASE_DETACH;
  msg->seq_bound = ULONG_MAX;
  fd_stem_publish( stem, ctx->replay_out_idx, FD_DRAGON_RELEASE_DETACH, ctx->replay_out_chunk,
                   sizeof(fd_dragon_release_t), 0UL, 0UL, 0UL );
  ctx->replay_out_chunk = fd_dcache_compact_next( ctx->replay_out_chunk, sizeof(fd_dragon_release_t),
                                                  ctx->replay_out_chunk0, ctx->replay_out_wmark );
  ctx->release_cnt    = 0UL;
  ctx->detach_pending = 0;

  FD_LOG_WARNING(( "dragon told replay to take back every bank reference it granted, and to grant no more" ));
}

/* dragon_conn_open and dragon_conn_close count the client sockets the
   transport holds; the server itself keeps them in the waker's inner
   epoll set. */

static void
dragon_conn_open( void * _ctx,
                  int    sock ) {
  fd_dragon_tile_t * ctx = _ctx;
  if( FD_UNLIKELY( sock<0 ) ) return;
  ctx->conn_cnt++;
}



static void
dragon_conn_close( void * _ctx,
                   int    sock ) {
  (void)sock;
    fd_dragon_tile_t * ctx = _ctx;
  if( FD_LIKELY( ctx->conn_cnt ) ) ctx->conn_cnt--;
}

static void
privileged_init( fd_topo_t const *      topo,
                 fd_topo_tile_t const * tile ) {
  void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );

  fd_grpc_server_params_t server_params = derive_server_params( tile );
  fd_dragon_rpc_params_t  rpc_params    = derive_rpc_params( tile );

  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_dragon_tile_t * ctx     = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_dragon_tile_t), sizeof(fd_dragon_tile_t)                      );
  void *             _rpc    = FD_SCRATCH_ALLOC_APPEND( l, fd_dragon_rpc_align(),     fd_dragon_rpc_footprint( &rpc_params )        );
  void *             _server = FD_SCRATCH_ALLOC_APPEND( l, fd_grpc_server_align(),    fd_grpc_server_footprint( &server_params )    );
  FD_SCRATCH_ALLOC_FINI( l, scratch_align() );

  fd_memset( ctx, 0, sizeof(fd_dragon_tile_t) );

  ctx->waker_client_idx = tile->waker_client_idx;
  FD_TEST( ctx->waker_client_idx!=ULONG_MAX );
    ctx->epoll_fd = FD_WAKER_INNER_FD( ctx->waker_client_idx );
  server_params.epoll_fd = ctx->epoll_fd;

  /* One descriptor per client plus the tile's own. */
  struct rlimit nofile;
  if( FD_UNLIKELY( getrlimit( RLIMIT_NOFILE, &nofile ) ) ) FD_LOG_ERR(( "getrlimit(RLIMIT_NOFILE) failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  ulong nofile_want = tile->dragon.max_clients + 64UL;
  if( nofile.rlim_cur<nofile_want ) {
    nofile.rlim_cur = nofile_want;
    if( nofile.rlim_max<nofile_want ) nofile.rlim_max = nofile_want;
    if( FD_UNLIKELY( setrlimit( RLIMIT_NOFILE, &nofile ) ) )
      FD_LOG_ERR(( "setrlimit(RLIMIT_NOFILE,%lu) failed (%i-%s): [tiles.dragon.max_clients] needs that many descriptors, raise fs.nr_open",
                   nofile_want, errno, fd_io_strerror( errno ) ));
  }

  /* The ring the buffered levels are served from: an mcache and a
     dcache of the topology, the dcache in a workspace of its own so
     that [tiles.dragon.buffer_size_mib] is what it costs. */
  if( FD_LIKELY( tile->dragon.finalized ) ) {
    rpc_params.buf_mcache = fd_mcache_join( fd_topo_obj_laddr( topo, tile->dragon.buf_mcache_obj_id ) );
    rpc_params.buf_dcache = fd_dcache_join( fd_topo_obj_laddr( topo, tile->dragon.buf_dcache_obj_id ) );
    FD_TEST( rpc_params.buf_mcache && rpc_params.buf_dcache );
    rpc_params.buf_base   = fd_wksp_containing( rpc_params.buf_dcache );
    FD_TEST( rpc_params.buf_base );
  }

  /* The GetVersion document needs the host name, which the sandbox
     hides, so the RPC layer is built here. */
  rpc_params.conn_ctx   = ctx;
  rpc_params.conn_open  = dragon_conn_open;
  rpc_params.conn_close = dragon_conn_close;
    ctx->listen_fd        = -1;
  ctx->conn_cnt         = 0UL;
  ctx->conn_max         = tile->dragon.max_clients;
  ctx->call_max         = tile->dragon.max_clients*tile->dragon.max_streams_per_client;
  ctx->rpc = fd_dragon_rpc_join( fd_dragon_rpc_new( _rpc, &rpc_params ) );
  FD_TEST( ctx->rpc );

  ctx->server = fd_grpc_server_join( fd_grpc_server_new( _server, &server_params, fd_dragon_rpc_callbacks(), ctx->rpc ) );
  FD_TEST( ctx->server );

  /* Binding a port below 1024 needs a capability the tile drops before
     unprivileged_init runs, so the listen socket is created here. */
  if( FD_UNLIKELY( fd_grpc_server_listen( ctx->server, tile->dragon.listen_addr, tile->dragon.listen_port )<0 ) )
    FD_LOG_ERR(( "failed to listen on " FD_IP4_ADDR_FMT ":%hu",
                 FD_IP4_ADDR_FMT_ARGS( tile->dragon.listen_addr ), tile->dragon.listen_port ));

  FD_LOG_NOTICE(( "dragon server listening at %shttp://" FD_IP4_ADDR_FMT ":%hu%s",
                  fd_log_style_bold(), FD_IP4_ADDR_FMT_ARGS( tile->dragon.listen_addr ),
                  tile->dragon.listen_port, fd_log_style_normal() ));
}

static void
unprivileged_init( fd_topo_t const *      topo,
                   fd_topo_tile_t const * tile ) {
  void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );

  fd_grpc_server_params_t server_params = derive_server_params( tile );
  fd_dragon_rpc_params_t  rpc_params    = derive_rpc_params( tile );
  fd_geyser_core_params_t core_params   = derive_core_params( tile );

  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_dragon_tile_t * ctx      = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_dragon_tile_t), sizeof(fd_dragon_tile_t)                      );
  /**/                         FD_SCRATCH_ALLOC_APPEND( l, fd_dragon_rpc_align(),     fd_dragon_rpc_footprint( &rpc_params )        );
  /**/                         FD_SCRATCH_ALLOC_APPEND( l, fd_grpc_server_align(),    fd_grpc_server_footprint( &server_params )    );
  void *             _core    = FD_SCRATCH_ALLOC_APPEND( l, fd_geyser_core_align(),    fd_geyser_core_footprint( &core_params )      );
  void *             _release = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_dragon_release_t), dragon_release_max( tile )*sizeof(fd_dragon_release_t) );
  void *             _ingest  = tile->dragon.record_link_cnt ?
                                  FD_SCRATCH_ALLOC_APPEND( l, fd_dragon_ingest_align(), fd_dragon_ingest_footprint( tile->dragon.record_link_cnt ) ) : NULL;
  void *             _accdb   = tile->dragon.finalized ?
                                  FD_SCRATCH_ALLOC_APPEND( l, fd_accdb_align(), fd_accdb_footprint( tile->dragon.max_live_banks, 0 ) ) : NULL;
  void *             _acct    = tile->dragon.finalized ?
                                  FD_SCRATCH_ALLOC_APPEND( l, 128UL, FD_RUNTIME_ACC_SZ_MAX ) : NULL;

  ctx->serving      = !tile->dragon.delay_startup;
  ctx->exit_at_slot = tile->dragon.exit_at_slot;
  fd_dragon_rpc_set_serving( ctx->rpc, ctx->serving );

  /* Read-only join to the accounts database, through which an account
     can be read at a bank's fork.  The accdb workspace is mapped
     PROT_READ in this tile (see topology); the
     only writable external mapping is the tile's private epoch fseq,
     which the accdb tile watches so that it defers reclaiming a
     partition this tile is reading.  FD_ACCDB_FD_RO is the O_RDONLY
     dup of the accdb data file. */
  if( FD_LIKELY( _accdb ) ) {
    fd_accdb_shmem_t * accdb_shmem_ro = fd_accdb_shmem_join( fd_topo_obj_laddr( topo, tile->dragon.accdb_obj_id ) );
    FD_TEST( accdb_shmem_ro );
    ulong * epoch_fseq = fd_fseq_join( fd_topo_obj_laddr( topo, tile->dragon.accdb_epoch_fseq_obj_id ) );
    FD_TEST( epoch_fseq );
    ctx->accdb = fd_accdb_join_readonly( _accdb, accdb_shmem_ro, epoch_fseq, FD_ACCDB_FD_RO );
    FD_TEST( ctx->accdb );
    ctx->acct_data = _acct;
  }

  ctx->release_max  = dragon_release_max( tile );
  ctx->release      = _release;
  ctx->release_cnt  = 0UL;
  ctx->release_head = 0UL;

  core_params.release_ctx = ctx;
  core_params.read_ctx    = ctx;
  ctx->core = fd_geyser_core_join( fd_geyser_core_new( _core, &core_params ) );
  FD_TEST( ctx->core );

  fd_geyser_consumer_t consumer[1];
  FD_TEST( !fd_geyser_core_register( ctx->core, fd_dragon_rpc_consumer( ctx->rpc, ctx->core, consumer ) ) );

  fd_clock_tile_init( ctx->clock );
  ctx->service_nanos       = fd_clock_tile_now( ctx->clock );
  ctx->send_interval_nanos = tile->dragon.send_interval_nanos;

  ctx->waker_fseq = fd_fseq_join( fd_topo_obj_laddr( topo, tile->waker_fseq_obj_id ) );
  FD_TEST( ctx->waker_fseq );

    /* The server put the listen socket and puts every accepted socket
     in the waker's inner epoll set. */
  int listen_fd = fd_grpc_server_fd( ctx->server, 0UL );
  FD_TEST( listen_fd>=0 );
  ctx->listen_fd = listen_fd;

  fd_histf_join( fd_histf_new( ctx->record_sz,
                               FD_MHIST_MIN( DRAGON, RECORD_SIZE_BYTES ),
                               FD_MHIST_MAX( DRAGON, RECORD_SIZE_BYTES ) ) );
  fd_histf_join( fd_histf_new( ctx->ref_hi,
                               FD_MHIST_MIN( DRAGON, PENDING_REF_PEAK_PER_CALL ),
                               FD_MHIST_MAX( DRAGON, PENDING_REF_PEAK_PER_CALL ) ) );
  fd_histf_join( fd_histf_new( ctx->acct_read,
                               FD_MHIST_MIN( DRAGON, ACCOUNT_READ_DURATION_NANOS ),
                               FD_MHIST_MAX( DRAGON, ACCOUNT_READ_DURATION_NANOS ) ) );

  ctx->record_link_cnt = tile->dragon.record_link_cnt;
  ctx->asm_ready       = ULONG_MAX;
  if( FD_LIKELY( ctx->record_link_cnt ) ) {
    ctx->ingest = fd_dragon_ingest_join( fd_dragon_ingest_new( _ingest, ctx->record_link_cnt ) );
    FD_TEST( ctx->ingest );
  }

  if( FD_UNLIKELY( tile->in_cnt>FD_DRAGON_IN_MAX ) )
    FD_LOG_ERR(( "dragon tile has %lu input links, above FD_DRAGON_IN_MAX (%lu): the topology has more "
                 "executing tiles than the dragon tile can take records from", tile->in_cnt, FD_DRAGON_IN_MAX ));
  ctx->in_cnt   = tile->in_cnt;
  ulong asm_idx = 0UL;
  for( ulong i=0UL; i<tile->in_cnt; i++ ) {
    fd_topo_link_t const * link      = &topo->links[ tile->in_link_id[ i ] ];
    fd_topo_wksp_t const * link_wksp = &topo->workspaces[ topo->objs[ link->dcache_obj_id ].wksp_id ];

    ctx->in[ i ].mem     = link_wksp->wksp;
    ctx->in[ i ].chunk0  = fd_dcache_compact_chunk0( ctx->in[ i ].mem, link->dcache );
    ctx->in[ i ].wmark   = fd_dcache_compact_wmark ( ctx->in[ i ].mem, link->dcache, link->mtu );
    ctx->in[ i ].mtu     = link->mtu;
    ctx->in[ i ].asm_idx   = ULONG_MAX;
    ctx->in[ i ].next_seq  = ULONG_MAX;
    ctx->in[ i ].seq_laddr = fd_mcache_seq_laddr_const( link->mcache );

    char const * evint = strstr( link->name, "_evint" );
    char const * event = strstr( link->name, "_event" );
    if( FD_LIKELY( !strcmp( link->name, "replay_slot" ) ) ) {
      ctx->in_kind[ i ] = IN_KIND_REPLAY;
      ctx->replay_in_seq  = fd_mcache_seq_laddr_const( link->mcache );
      ctx->replay_in_idx  = i;
      ctx->replay_lag_max = link->depth>>FD_DRAGON_REPLAY_LAG_SHIFT;
    } else if( FD_LIKELY( evint && !strcmp( evint, "_evint" ) ) ) {
      ctx->in_kind[ i ]    = IN_KIND_RECORD;
      FD_TEST( asm_idx<ctx->record_link_cnt );
      ctx->in[ i ].asm_idx = asm_idx++;
    } else if( FD_LIKELY( event && !strcmp( event, "_event" ) ) ) {
      ctx->in_kind[ i ] = IN_KIND_EVENT;
    } else {
      FD_LOG_ERR(( "unexpected link name %s", link->name ));
    }
  }
  FD_TEST( asm_idx==ctx->record_link_cnt );

  ctx->replay_out_idx = fd_topo_find_tile_out_link( topo, tile, "dragon_replay", tile->kind_id );
  FD_TEST( ctx->replay_out_idx!=ULONG_MAX );

  fd_topo_link_t const * out_link = &topo->links[ tile->out_link_id[ ctx->replay_out_idx ] ];
  FD_TEST( out_link->mtu>=sizeof(fd_dragon_release_t) );
  ctx->replay_out_mem    = topo->workspaces[ topo->objs[ out_link->dcache_obj_id ].wksp_id ].wksp;
  ctx->replay_out_chunk0 = fd_dcache_compact_chunk0( ctx->replay_out_mem, out_link->dcache );
  ctx->replay_out_wmark  = fd_dcache_compact_wmark ( ctx->replay_out_mem, out_link->dcache, out_link->mtu );
  ctx->replay_out_chunk  = ctx->replay_out_chunk0;

  /* The tile boots into a validator that is already running, and
     replay may hold bank references granted to whatever ran in this
     topology slot before.  Booting is therefore the same situation as
     an input gap: the first replay notification the tile handles
     bounds a sweep that gives back every reference granted below it.
     On a validator that just started replay has granted none, and a
     release for a reference replay does not hold does nothing. */
  ctx->gap_pending = 1;

  /* Whatever ran in this slot before may have died between clearing
     its readiness word and rearming its entry in the waker's outer
     set, which is one shot.  The rearm re-polls, so it costs one
     epoll_ctl and is the difference between being woken and never
     hearing from a socket again. */
  fd_waker_client_rearm( ctx->waker_client_idx );

  ulong scratch_top = FD_SCRATCH_ALLOC_FINI( l, scratch_align() );
  if( FD_UNLIKELY( scratch_top > (ulong)scratch + scratch_footprint( tile ) ) )
    FD_LOG_ERR(( "scratch overflow %lu %lu %lu", scratch_top - (ulong)scratch - scratch_footprint( tile ), scratch_top, (ulong)scratch + scratch_footprint( tile ) ));
}

static void
during_housekeeping( fd_dragon_tile_t * ctx ) {
  if( FD_UNLIKELY( fd_clock_tile_recal_due( ctx->clock ) ) ) fd_clock_tile_recal( ctx->clock );

  /* How far behind the producers the tile is running. */
  for( ulong i=0UL; i<ctx->in_cnt; i++ ) {
    if( ctx->in[ i ].asm_idx==ULONG_MAX ) continue;
    ulong next = fd_dragon_ingest_next_seq( ctx->ingest, ctx->in[ i ].asm_idx );
    if( FD_UNLIKELY( next==ULONG_MAX ) ) continue;
    long lag = fd_seq_diff( fd_mcache_seq_query( ctx->in[ i ].seq_laddr ), next );
    if( FD_UNLIKELY( lag>0L && (ulong)lag>ctx->record_lag_hi ) ) ctx->record_lag_hi = (ulong)lag;
  }

  /* A record link that went quiet after losing frags would otherwise
     keep the banks in flight waiting for records that will never
     arrive. */
  if( FD_UNLIKELY( ctx->ingest && fd_dragon_ingest_gap_clear( ctx->ingest ) ) ) fd_geyser_core_record_gap( ctx->core );

  fd_geyser_core_housekeeping( ctx->core );
}

static void
metrics_write( fd_dragon_tile_t * ctx ) {
  fd_dragon_rpc_metrics_t const *  rpc = fd_dragon_rpc_metrics( ctx->rpc );
  fd_grpc_server_metrics_t const * srv = fd_grpc_server_metrics( ctx->server );

  FD_MCNT_ENUM_COPY( DRAGON, CALL_HANDLED, rpc->request_cnt );

  FD_MGAUGE_SET( DRAGON, CONN_OPEN,                   rpc->conn_cnt         );
  FD_MGAUGE_SET( DRAGON, CONN_CAPACITY,               ctx->conn_max         );
  FD_MGAUGE_SET( DRAGON, CALL_OPEN,                   rpc->stream_cnt       );
  FD_MGAUGE_SET( DRAGON, CALL_CAPACITY,               ctx->call_max         );
  FD_MGAUGE_SET( DRAGON, SUBSCRIPTION_OPEN,           rpc->subscription_cnt );
  FD_MGAUGE_SET( DRAGON, SUBSCRIPTION_CLASS_USED,     rpc->sub_cnt          );
  FD_MGAUGE_SET( DRAGON, SUBSCRIPTION_CLASS_CAPACITY, FD_DRAGON_SUB_MAX     );
  FD_MGAUGE_SET( DRAGON, LAST_PROCESSED_SLOT, fd_dragon_rpc_level_slot( ctx->rpc, FD_DRAGON_COMMITMENT_PROCESSED ) );
  FD_MGAUGE_SET( DRAGON, LAST_CONFIRMED_SLOT, fd_dragon_rpc_level_slot( ctx->rpc, FD_DRAGON_COMMITMENT_CONFIRMED ) );
  FD_MGAUGE_SET( DRAGON, LAST_FINALIZED_SLOT, fd_dragon_rpc_level_slot( ctx->rpc, FD_DRAGON_COMMITMENT_FINALIZED ) );

  FD_MCNT_SET( DRAGON, CONN_ACCEPTED,              srv->conn_open_cnt           );
  FD_MCNT_SET( DRAGON, CONN_CLOSED,                srv->conn_close_cnt          );
  FD_MCNT_SET( DRAGON, CONN_EVICTED_IDLE,          srv->idle_timeout_cnt        );
  FD_MCNT_SET( DRAGON, CONN_EVICTED_HANDSHAKE,     srv->handshake_timeout_cnt   );
  FD_MCNT_SET( DRAGON, CONN_EVICTED_BURST_STALL,   srv->tx_burst_stall_cnt      );
  FD_MCNT_SET( DRAGON, CONN_EVICTED_RESET_FLOOD,   srv->reset_flood_cnt         );
  FD_MCNT_SET( DRAGON, CONN_EVICTED_SLOW_CLIENT,   rpc->lagged_reap_cnt         );
  FD_MCNT_SET( DRAGON, CONN_FULL_REJECTED,         srv->accept_refused_cnt      );
  FD_MCNT_SET( DRAGON, CONN_ADDRESS_FULL_REJECTED, srv->accept_refused_addr_cnt );
  FD_MCNT_SET( DRAGON, ACCEPT_FAILED,              srv->accept_error_cnt        );
  FD_MCNT_SET( DRAGON, POLL_FAILED,                srv->poll_error_cnt          );

  FD_MCNT_SET( DRAGON, REQUEST_RX,                       srv->rx_msg_cnt           );
  FD_MCNT_SET( DRAGON, REQUEST_RX_BYTES,                 srv->rx_byte_cnt          );
  FD_MCNT_SET( DRAGON, REQUEST_REJECTED_AUTH,            rpc->auth_fail_cnt        );
  FD_MCNT_SET( DRAGON, REQUEST_REJECTED_UNIMPLEMENTED,   rpc->unimplemented_cnt    );
  FD_MCNT_SET( DRAGON, REQUEST_REJECTED_DECODE,          rpc->decode_fail_cnt      );
  FD_MCNT_SET( DRAGON, REQUEST_REJECTED_FILTER,          rpc->filter_reject_cnt    );
  FD_MCNT_SET( DRAGON, REQUEST_REJECTED_FROM_SLOT,       rpc->from_slot_reject_cnt );
  FD_MCNT_SET( DRAGON, REQUEST_REJECTED_COMMITMENT,      rpc->deferred_reject_cnt  );
  FD_MCNT_SET( DRAGON, REQUEST_REJECTED_CALL_FULL,       rpc->stream_full_cnt      );
  FD_MCNT_SET( DRAGON, REQUEST_REJECTED_CLASS_FULL,      rpc->sub_full_cnt         );
  FD_MCNT_SET( DRAGON, REQUEST_REJECTED_MALFORMED,       srv->request_error_cnt    );
  FD_MCNT_SET( DRAGON, REQUEST_REJECTED_BUFFER_EVICTED,  srv->rx_buf_evict_cnt     );
  FD_MCNT_SET( DRAGON, REQUEST_REJECTED_BUFFER_TIMEOUT,  srv->rx_buf_timeout_cnt   );
  FD_MCNT_SET( DRAGON, REQUEST_REJECTED_BUFFER_ADDRESS,  srv->rx_buf_addr_cnt      );

  ulong chunk_free, req_free, burst_free;
  ulong chunk_cap,  req_cap,  burst_cap;
  fd_grpc_server_pool_free    ( ctx->server, &chunk_free, &req_free, &burst_free );
  fd_grpc_server_pool_capacity( ctx->server, &chunk_cap,  &req_cap,  &burst_cap  );
  FD_MGAUGE_SET( DRAGON, REQUEST_BUFFER_FREE,         req_free   );
  FD_MGAUGE_SET( DRAGON, REQUEST_BUFFER_CAPACITY,     req_cap    );
  FD_MGAUGE_SET( DRAGON, UPDATE_QUEUE_CHUNK_FREE,     chunk_free );
  FD_MGAUGE_SET( DRAGON, UPDATE_QUEUE_CHUNK_CAPACITY, chunk_cap  );
  FD_MGAUGE_SET( DRAGON, BURST_BUFFER_FREE,           burst_free );
  FD_MGAUGE_SET( DRAGON, BURST_BUFFER_CAPACITY,       burst_cap  );
  FD_MCNT_SET( DRAGON, BURST_BUFFER_ACQUIRED, srv->tx_burst_acquire_cnt );
  FD_MCNT_SET( DRAGON, BURST_BUFFER_DENIED,   srv->tx_burst_miss_cnt    );

  FD_MCNT_SET( DRAGON, UPDATE_TX_SLOT,             rpc->slot_sent_cnt       );
  FD_MCNT_SET( DRAGON, UPDATE_TX_TXN,              rpc->txn_update_cnt      );
  FD_MCNT_SET( DRAGON, UPDATE_TX_TXN_STATUS,       rpc->txn_status_cnt      );
  FD_MCNT_SET( DRAGON, UPDATE_TX_BLOCK_META,       rpc->block_meta_sent_cnt );
  FD_MCNT_SET( DRAGON, UPDATE_TX_ACCOUNT,          rpc->acct_update_cnt     );
  FD_MCNT_SET( DRAGON, UPDATE_TX_BLOCK,            rpc->block_sent_cnt      );
  FD_MCNT_SET( DRAGON, UPDATE_TX_BYTES_SLOT,       rpc->slot_byte_cnt       );
  FD_MCNT_SET( DRAGON, UPDATE_TX_BYTES_TXN,        rpc->txn_byte_cnt        );
  FD_MCNT_SET( DRAGON, UPDATE_TX_BYTES_TXN_STATUS, rpc->status_byte_cnt     );
  FD_MCNT_SET( DRAGON, UPDATE_TX_BYTES_BLOCK_META, rpc->block_meta_byte_cnt );
  FD_MCNT_SET( DRAGON, UPDATE_TX_BYTES_ACCOUNT,    rpc->acct_byte_cnt       );
  FD_MCNT_SET( DRAGON, UPDATE_TX_BYTES_BLOCK,      rpc->block_byte_cnt      );
  FD_MCNT_SET( DRAGON, PING_TX,                    rpc->server_ping_cnt     );
  FD_MCNT_SET( DRAGON, PONG_TX,                    rpc->pong_cnt            );
  FD_MCNT_SET( DRAGON, MSG_TX,                     srv->tx_msg_cnt            );
  FD_MCNT_SET( DRAGON, MSG_TX_BYTES,               srv->tx_byte_cnt           );
  FD_MCNT_SET( DRAGON, MSG_WIRE_TX_BYTES,          srv->tx_byte_cnt_wire      );
  FD_MCNT_SET( DRAGON, MSG_COMPRESSED_TX,          srv->tx_msg_compressed_cnt );
  FD_MCNT_SET( DRAGON, MSG_SHARED_TX,              srv->tx_msg_shared_cnt     );
  FD_MCNT_SET( DRAGON, MSG_OVERSIZE_REJECTED,      srv->tx_toobig_cnt         );
  FD_MCNT_SET( DRAGON, ENCODE_FAILED,              rpc->encode_fail_cnt       );
  FD_MCNT_SET( DRAGON, TXN_META_BUILD_FAILED,      rpc->meta_fail_cnt         );
  FD_MCNT_SET( DRAGON, CUCKOO_FILTER_INSTALLED,    rpc->cuckoo_filter_cnt     );

  FD_MCNT_SET( DRAGON, CALL_EVICTED_SEND_RING,  srv->tx_too_slow_ring_cnt  );
  FD_MCNT_SET( DRAGON, CALL_EVICTED_REF_QUEUE,  srv->tx_too_slow_refs_cnt  );
  FD_MCNT_SET( DRAGON, CALL_EVICTED_REF_POOL,   srv->tx_too_slow_pool_cnt  );
  FD_MCNT_SET( DRAGON, CALL_EVICTED_DEADLINE,   srv->deadline_exceeded_cnt );
  FD_MCNT_SET( DRAGON, SUBSCRIPTION_LAGGED_CLOSED,       rpc->lagged_close_cnt       );
  FD_MCNT_SET( DRAGON, SUBSCRIPTION_CONTENT_LOST_CLOSED, rpc->content_lost_close_cnt );

  FD_MCNT_SET( DRAGON, REPLAY_FRAG_RX,   ctx->replay_frag_cnt    );
  FD_MCNT_SET( DRAGON, SLOT_COMPLETE_RX, ctx->slot_completed_cnt );
  FD_MCNT_SET( DRAGON, REPLAY_OVERRUN,   ctx->overrun_cnt        );

  FD_MGAUGE_SET( DRAGON, BLOCKHASH_COUNT,  rpc->blockhash_cnt      );
  FD_MGAUGE_SET( DRAGON, BLOCK_META_COUNT, rpc->block_meta_tracked );

  fd_geyser_core_metrics_t const * geyser = fd_geyser_core_metrics( ctx->core );

  FD_MGAUGE_SET( DRAGON, BANK_COUNT,               fd_geyser_core_bank_cnt    ( ctx->core ) );
  FD_MGAUGE_SET( DRAGON, BANK_CAPACITY,            fd_geyser_core_bank_max    ( ctx->core ) );
  FD_MGAUGE_SET( DRAGON, BANK_REF_COUNT,           fd_geyser_core_ref_held_cnt( ctx->core ) );
  FD_MGAUGE_SET( DRAGON, BANK_REF_RELEASE_PENDING, ctx->release_cnt                         );
  FD_MGAUGE_SET( DRAGON, BANK_PENDING,             fd_geyser_core_pending_cnt ( ctx->core ) );

  FD_MCNT_SET( DRAGON, BANK_CREATED,            geyser->bank_created_cnt      );
  FD_MCNT_SET( DRAGON, BANK_EVICTED,            geyser->pool_full_cnt         );
  FD_MCNT_SET( DRAGON, BANK_SEALED,             geyser->bank_sealed_cnt       );
  FD_MCNT_SET( DRAGON, FORK_GRAPH_FLUSHED,      geyser->flush_cnt             );
  FD_MCNT_SET( DRAGON, BANK_REF_ACQUIRED,       geyser->ref_acquired_cnt      );
  FD_MCNT_SET( DRAGON, BANK_REF_RELEASED,       geyser->ref_released_cnt      );
  FD_MCNT_SET( DRAGON, BANK_REF_QUEUE_FULL_LOST, ctx->release_drop_cnt        );
  FD_MCNT_SET( DRAGON, BANK_REF_UNNAMED_LOST,   geyser->ref_unnamed_cnt       );
  FD_MCNT_SET( DRAGON, BANK_UNKNOWN_DROPPED,    geyser->unknown_bank_cnt      );
  FD_MCNT_SET( DRAGON, ROOT_CHAIN_GAP_SEEN,     geyser->root_chain_broken_cnt );
  FD_MCNT_SET( DRAGON, BANK_PENDING_ENTERED,    geyser->bank_pending_cnt      );
  FD_MCNT_SET( DRAGON, BANK_PENDING_TIMED_OUT,  geyser->pending_timeout_cnt   );
  FD_MCNT_SET( DRAGON, BANK_PENDING_DROPPED,    geyser->pending_dropped_cnt   );
  FD_MCNT_SET( DRAGON, BANK_DEGRADED,           rpc->degrade_cnt              );
  FD_MCNT_SET( DRAGON, CONTENT_LOST,            rpc->content_lost_cnt         );

  fd_dragon_ingest_metrics_t const ing_zero = {0};
  fd_dragon_ingest_metrics_t const * ing = ctx->ingest ? fd_dragon_ingest_metrics( ctx->ingest ) : &ing_zero;

  FD_MCNT_SET( DRAGON, RECORD_RX,                    ing->record_cnt            );
  FD_MCNT_SET( DRAGON, TXN_EVENT_RX,                 geyser->txn_event_cnt      );
  FD_MCNT_SET( DRAGON, RECORD_MULTI_FRAG_RX,         ing->multi_frag_cnt        );
  FD_MCNT_SET( DRAGON, RECORD_MALFORMED_DROPPED,     ing->malformed_cnt+ctx->record_malformed_cnt );
  FD_MCNT_SET( DRAGON, RECORD_GAP_DROPPED,           ing->gap_drop_cnt          );
  FD_MCNT_SET( DRAGON, RECORD_BAD_CHUNK_DROPPED,     ctx->record_bad_chunk_cnt  );
  FD_MCNT_SET( DRAGON, RECORD_BANK_GONE_DROPPED,     geyser->record_dropped_cnt );
  FD_MCNT_SET( DRAGON, RECORD_OVERRUN,               ing->overrun_cnt           );
  FD_MCNT_SET( DRAGON, RECORD_GAP_FLUSHED,           geyser->record_gap_cnt     );
  FD_MCNT_SET( DRAGON, TXN_RECORD_PROCESSED,         geyser->txn_record_cnt     );
  FD_MCNT_SET( DRAGON, WRITE_RECORD_PROCESSED,       geyser->write_record_cnt   );
  FD_MCNT_SET( DRAGON, ACCOUNT_WRITE_PROCESSED,      geyser->account_cnt        );
  FD_MCNT_SET( DRAGON, ACCOUNT_WRITE_PROCESSED_BYTES, geyser->account_byte_cnt  );
  FD_MGAUGE_SET( DRAGON, RECORD_LINK_LAG_PEAK, ctx->record_lag_hi );
  FD_MHIST_COPY( DRAGON, RECORD_SIZE_BYTES, ctx->record_sz );

  fd_dragon_buf_t * buf = fd_dragon_rpc_buf( ctx->rpc );
  if( FD_LIKELY( buf ) ) {
    fd_dragon_buf_metrics_t const * bm = fd_dragon_buf_metrics( buf );

    FD_MGAUGE_SET( DRAGON, BUFFER_BANK_COUNT,     fd_dragon_buf_bank_cnt ( buf ) );
    FD_MGAUGE_SET( DRAGON, BUFFER_BANK_CAPACITY,  fd_dragon_buf_bank_max ( buf ) );
    FD_MGAUGE_SET( DRAGON, BUFFER_ENTRY_COUNT,    fd_dragon_buf_entry_cnt( buf ) );
    FD_MGAUGE_SET( DRAGON, BUFFER_ENTRY_CAPACITY, fd_dragon_buf_depth    ( buf ) );
    FD_MGAUGE_SET( DRAGON, BUFFER_ENTRY_PEAK,     bm->entry_hi                   );
    FD_MGAUGE_SET( DRAGON, BUFFER_USED_BYTES,     fd_dragon_buf_byte_cnt ( buf ) );
    FD_MGAUGE_SET( DRAGON, BUFFER_CAPACITY_BYTES, fd_dragon_buf_byte_max ( buf ) );
    FD_MGAUGE_SET( DRAGON, BUFFER_PEAK_BYTES,     bm->byte_hi                    );

    FD_MCNT_SET( DRAGON, BUFFER_ENTRY_STORED_TXN,       bm->push_cnt[ FD_DRAGON_BUF_TXN     ] );
    FD_MCNT_SET( DRAGON, BUFFER_ENTRY_STORED_ACCOUNT,   bm->push_cnt[ FD_DRAGON_BUF_ACCT    ] );
    FD_MCNT_SET( DRAGON, BUFFER_ENTRY_STORED_REWARD,    bm->push_cnt[ FD_DRAGON_BUF_REWARDS ] );
    FD_MCNT_SET( DRAGON, BUFFER_STORED_BYTES,           bm->push_byte_cnt );
    FD_MCNT_SET( DRAGON, BUFFER_ENTRY_OVERSIZE_DROPPED, bm->push_fail_cnt );
    FD_MCNT_SET( DRAGON, BUFFER_BANK_FULL_DROPPED,      bm->bank_full_cnt );
    FD_MCNT_SET( DRAGON, BUFFER_OVERRUN,                bm->overrun_cnt   );
  }

  FD_MCNT_SET( DRAGON, ACCOUNT_READ,                 geyser->acct_read_cnt        );
  FD_MCNT_SET( DRAGON, ACCOUNT_CLOSED_READ,          geyser->acct_read_closed_cnt );
  FD_MCNT_SET( DRAGON, ACCOUNT_DATA_MISSING_SKIPPED, rpc->acct_skipped_cnt        );
  FD_MCNT_SET( DRAGON, ACCOUNT_PARTIAL_SKIPPED,      rpc->acct_partial_cnt        );
  FD_MCNT_SET( DRAGON, ACCOUNT_OVERSIZE_DROPPED,     rpc->acct_oversize_cnt       );
  FD_MCNT_SET( DRAGON, BLOCK_OVERSIZE_DROPPED,       rpc->block_oversize_cnt      );
  FD_MHIST_COPY( DRAGON, ACCOUNT_READ_DURATION_NANOS, ctx->acct_read );

  /* The calls that ended since the last write, whose queue high water
     is what says how much of a subscriber's queue was ever needed. */
  ulong ref_hi[ FD_DRAGON_SUB_MAX ];
  ulong ref_hi_cnt = fd_dragon_rpc_ref_hi_drain( ctx->rpc, ref_hi, FD_DRAGON_SUB_MAX );
  for( ulong i=0UL; i<ref_hi_cnt; i++ ) fd_histf_sample( ctx->ref_hi, ref_hi[ i ] );
  FD_MHIST_COPY( DRAGON, PENDING_REF_PEAK_PER_CALL, ctx->ref_hi );

  FD_MCNT_ENUM_COPY( DRAGON, BANK_DISCARDED,       geyser->bank_discarded_cnt  );
  FD_MCNT_ENUM_COPY( DRAGON, BANK_INCOMPLETE_SEEN, geyser->bank_incomplete_cnt );
  FD_MCNT_ENUM_COPY( DRAGON, SLOT_STATUS_REPORTED, geyser->status_cnt          );
}

static void
before_credit( fd_dragon_tile_t *  ctx,
               fd_stem_context_t * stem,
               int *               charge_busy ) {
  if( FD_UNLIKELY( ctx->release_cnt ) ) {
    dragon_release_flush( ctx, stem );
    *charge_busy = 1;
  }

  /* A shutdown that was asked for owes its clients one pass before the
     transport stops, so it runs the tick even on a tile that never
     started serving. */
  int pending = ctx->shutdown_pending;
  if( FD_UNLIKELY( !ctx->serving && !pending ) ) return;

  /* Messages staged since the last pass go out at once rather than on
     the next tick.  With a send interval they wait for their tick in
     any case, and the pass then runs on the clock alone: the sends it
     makes cost milliseconds, and the frags the stem reads between
     passes are what keeps the input links from overrunning. */
  long  now        = fd_clock_tile_now( ctx->clock );
  int   woken      = fd_fseq_query( ctx->waker_fseq )==1UL;
  int   due        = ( now - ctx->service_nanos )>=FD_DRAGON_SERVICE_INTERVAL_NANOS;
  ulong tx_msg_cnt = fd_grpc_server_metrics( ctx->server )->tx_msg_cnt;
  int   sent       = ( !ctx->send_interval_nanos ) & ( tx_msg_cnt!=ctx->tx_msg_seen );
  if( FD_LIKELY( !woken && !due && !pending && !sent ) ) return;
  if( FD_LIKELY( now<ctx->service_holdoff_nanos && !pending ) ) return;

  /* Replay first: a pass waits while the tile is far behind on the
     link replay would otherwise stop at. */
  if( FD_LIKELY( ctx->replay_in_seq && !pending ) ) {
    ulong next = ctx->in[ ctx->replay_in_idx ].next_seq;
    if( FD_LIKELY( next!=ULONG_MAX ) ) {
      long lag = fd_seq_diff( fd_mcache_seq_query( ctx->replay_in_seq ), next );
      if( FD_UNLIKELY( lag>(long)ctx->replay_lag_max ) ) {
        ctx->replay_lag_gate_cnt++;
        FD_DRAGON_WARN_POW2( ctx->replay_lag_gate_cnt, "dragon %ld frags behind replay, holding sends", lag );
        return;
      }
    }
  }

  *charge_busy = 1;
  ctx->service_nanos = now;
  ctx->tx_msg_seen   = tx_msg_cnt;

  /* Timers run whether or not a socket is ready: subscription pings,
     gRPC deadlines and the idle timeout. */
  fd_dragon_rpc_service( ctx->rpc, now );
  fd_grpc_server_service( ctx->server, now );

  if( FD_UNLIKELY( woken ) ) {
    fd_fseq_update( ctx->waker_fseq, 0UL );
    fd_grpc_server_poll( ctx->server, 0, now );
    fd_waker_client_rearm( ctx->waker_client_idx );
  } else if( FD_UNLIKELY( fd_grpc_server_tx_pending( ctx->server ) ) ) {
    /* A send the kernel refused is retried on the service tick as well
       as when the waker reports the socket writable. */
    fd_grpc_server_poll( ctx->server, 0, now );
  }

  if( FD_UNLIKELY( pending ) ) dragon_shutdown_flush( ctx, now );

  long end = fd_clock_tile_now( ctx->clock );
  ctx->service_holdoff_nanos = end + ( ( end-now )>>FD_DRAGON_SEND_HOLDOFF_SHIFT );
}

/* after_credit publishes the detach, which is the one message the tile
   owes replay and the one the stem's credits are needed for.  The run
   loop calls this whether or not a notification arrived, so a quiet
   replay does not hold the shutdown up. */

static void
after_credit( fd_dragon_tile_t *  ctx,
              fd_stem_context_t * stem,
              int *               opt_poll_in,
              int *               charge_busy ) {
  if( FD_LIKELY( !ctx->detach_pending ) ) return;
  dragon_detach_flush( ctx, stem );
  /* The iteration's credits cover one burst of releases, which this
     spends one of, so the frags that would queue more wait. */
  *opt_poll_in = 0;
  *charge_busy = 1;
}

/* should_shutdown ends the run loop, which exits the tile process with
   code 0.  Nothing starts the tile again, so the exit says what took
   the server away, whether any client was still connected, and
   whether replay got the detach.  The grace period bounds the wait:
   a dragon_replay link that never drains means replay is not reading,
   and staying alive for it would help nobody. */

static int
should_shutdown( fd_dragon_tile_t * ctx ) {
  if( FD_LIKELY( !ctx->shutdown_nanos ) ) return 0;
  /* Replay cannot advance its root while it still holds references the
     detach gives back, so the grace period bounds the wait for clients
     and never the wait for replay. */
  if( FD_UNLIKELY( ctx->detach_pending ) ) return 0;
  int idle    = fd_grpc_server_is_idle( ctx->server );
  int expired = fd_clock_tile_now( ctx->clock ) > ctx->shutdown_nanos+FD_DRAGON_SHUTDOWN_GRACE_NANOS;
  if( FD_LIKELY( !expired && !idle ) ) return 0;
  FD_LOG_WARNING(( "dragon tile exiting with code 0: %s (%s, every bank reference given back)", ctx->shutdown_reason,
                   idle ? "all clients disconnected" : "clients cut off at the end of the shutdown grace period" ));
  return 1;
}

/* dragon_gap runs when the tile lost notifications.  The stem hands
   frags to a tile in sequence, so a frag that does not follow the last
   one the tile saw is the only evidence of an overrun it needs,
   whichever of the stem's three overrun paths produced it.  Everything
   the core knows may be stale and it may hold references it no longer
   knows about, so the recovery waits for after_frag, where the sequence
   number bounding the references is known.

   The record links track their own sequence numbers in the ingest
   module, which needs to know where a record was cut short. */

static void
dragon_gap( fd_dragon_tile_t * ctx ) {
  ctx->overrun_cnt++;
  ctx->gap_pending = 1;
  FD_DRAGON_WARN_POW2( ctx->overrun_cnt, "dragon was overrun on replay_slot, resynchronizing" );
}

static int
before_frag( fd_dragon_tile_t * ctx,
             ulong              in_idx,
             ulong              seq,
             ulong              sig ) {
  if( FD_UNLIKELY( ctx->in_kind[ in_idx ]==IN_KIND_REPLAY ) ) {
    ulong next_seq = ctx->in[ in_idx ].next_seq;
    if( FD_UNLIKELY( next_seq==ULONG_MAX ) ) {
      /* The first frag.  Every grant replay published below it was
         made before this tile started reading, which after a restart
         is every grant the previous instance held, so they are given
         back the way the grants lost to a gap are. */
      if( FD_UNLIKELY( seq ) ) {
        ctx->gap_pending = 1;
        FD_LOG_NOTICE(( "dragon starting at replay_slot seq %lu, giving back every bank reference granted before it", seq ));
      }
    } else if( FD_UNLIKELY( seq!=next_seq ) ) dragon_gap( ctx );
    ctx->in[ in_idx ].next_seq = fd_seq_inc( seq, 1UL );

    return sig!=REPLAY_SIG_SLOT_COMPLETED && sig!=REPLAY_SIG_SLOT_DEAD &&
           sig!=REPLAY_SIG_ROOT_ADVANCED  && sig!=REPLAY_SIG_DROP_BANK_REF;
  }
  /* Of the event links, only the transaction events are read. */
  if( FD_UNLIKELY( ctx->in_kind[ in_idx ]==IN_KIND_EVENT ) ) return FD_EVENT_SIG_TYPE( sig )!=FD_EVENT_RUNTIME_TXN_ID;
  return 0; /* every frag of a record link is part of a record */
}

/* dragon_frag_sz is how much of a replay notification the tile reads,
   by signal.  A frag that is shorter than its message is not the
   message the signal claims, so it is dropped. */

static ulong
dragon_frag_sz( ulong sig ) {
  switch( sig ) {
  case REPLAY_SIG_SLOT_COMPLETED: return sizeof(fd_replay_slot_completed_t);
  case REPLAY_SIG_SLOT_DEAD:      return sizeof(fd_replay_slot_dead_t);
  case REPLAY_SIG_ROOT_ADVANCED:  return sizeof(fd_replay_root_advanced_t);
  case REPLAY_SIG_DROP_BANK_REF:  return sizeof(fd_replay_drop_bank_ref_t);
  default:                        return ULONG_MAX;
  }
}

/* during_frag_record accumulates one frag of a record.  A frag that
   cannot be part of a record is dropped by the ingest module, which
   never fails on what a link gives it. */

static void
during_frag_record( fd_dragon_tile_t * ctx,
                    ulong              in_idx,
                    ulong              seq,
                    ulong              sig,
                    ulong              chunk,
                    ulong              sz,
                    ulong              ctl ) {
  if( FD_UNLIKELY( chunk<ctx->in[ in_idx ].chunk0 || chunk>ctx->in[ in_idx ].wmark ||
                   sz>ctx->in[ in_idx ].mtu ) ) {
    /* A chunk outside the link's dcache names no payload to copy, so
       the frag is skipped.  The ingest module then sees the next frag
       out of sequence and gives up on the record, which is what a lost
       frag means. */
    ctx->record_bad_chunk_cnt++;
    return;
  }

  ulong link_idx = ctx->in[ in_idx ].asm_idx;
  if( FD_UNLIKELY( fd_dragon_ingest_frag( ctx->ingest, link_idx, seq, sig, ctl,
                                          fd_chunk_to_laddr_const( ctx->in[ in_idx ].mem, chunk ), sz ) ) )
    ctx->asm_ready = link_idx;
}

static void
during_frag( fd_dragon_tile_t * ctx,
             ulong              in_idx,
             ulong              seq,
             ulong              sig,
             ulong              chunk,
             ulong              sz,
             ulong              ctl ) {
  ctx->frag_valid = 0;
  ctx->asm_ready  = ULONG_MAX;

  if( FD_LIKELY( ctx->in_kind[ in_idx ]==IN_KIND_RECORD ) ) {
    during_frag_record( ctx, in_idx, seq, sig, chunk, sz, ctl );
    return;
  }

  if( FD_UNLIKELY( chunk<ctx->in[ in_idx ].chunk0 || chunk>ctx->in[ in_idx ].wmark ||
                   sz>ctx->in[ in_idx ].mtu ) ) {
    FD_LOG_ERR(( "chunk %lu %lu corrupt, not in range [%lu,%lu]", chunk, sz, ctx->in[ in_idx ].chunk0, ctx->in[ in_idx ].wmark ));
  }

  if( FD_UNLIKELY( ctx->in_kind[ in_idx ]==IN_KIND_EVENT ) ) {
    /* An event of the wrong size is not the struct the type claims. */
    /* An event's size travels in its signature; the frag's own size
       field is zero.  One of the wrong size is not the struct its type
       claims. */
    if( FD_UNLIKELY( FD_EVENT_SIG_SZ( sig )!=sizeof(fd_event_runtime_txn_t) ) ) return;
    fd_memcpy( ctx->event, fd_chunk_to_laddr_const( ctx->in[ in_idx ].mem, chunk ), sizeof(fd_event_runtime_txn_t) );
    ctx->frag_valid = 1;
    return;
  }

  ulong msg_sz = dragon_frag_sz( sig );
  if( FD_UNLIKELY( sz<msg_sz ) ) return;

  fd_memcpy( ctx->frag, fd_chunk_to_laddr_const( ctx->in[ in_idx ].mem, chunk ), msg_sz );
  ctx->frag_valid = 1;
}

/* after_frag_record hands a completed record to the core.  A record the
   core cannot read is counted and dropped. */

static void
after_frag_record( fd_dragon_tile_t * ctx,
                   ulong              in_idx ) {
  /* The banks in flight are told about a gap before the record that
     revealed it is accounted for, so that the bank it belongs to is
     marked incomplete either way. */
  if( FD_UNLIKELY( fd_dragon_ingest_gap_clear( ctx->ingest ) ) ) fd_geyser_core_record_gap( ctx->core );

  if( FD_LIKELY( ctx->asm_ready==ULONG_MAX ) ) return;
  ctx->asm_ready = ULONG_MAX;

  ulong        type;
  void const * rec;
  ulong        rec_sz;
  fd_dragon_ingest_record( ctx->ingest, ctx->in[ in_idx ].asm_idx, &type, &rec, &rec_sz );

  switch( type ) {
  case FD_EVENT_INTERNAL_COMMIT_ID: {
    fd_histf_sample( ctx->record_sz, rec_sz );
    fd_event_internal_commit_parts_t parts[1];
    if( FD_UNLIKELY( fd_event_internal_commit_unpack( rec, rec_sz, parts ) ) ) {
      ctx->record_malformed_cnt++;
      return;
    }
    fd_geyser_core_commit_record( ctx->core, parts );
    break;
  }
  case FD_EVENT_INTERNAL_RUNTIME_WRITE_ID: {
    fd_event_internal_runtime_write_parts_t parts[1];
    if( FD_UNLIKELY( fd_event_internal_runtime_write_unpack( rec, rec_sz, parts ) ) ) {
      ctx->record_malformed_cnt++;
      return;
    }
    fd_geyser_core_runtime_write_record( ctx->core, parts );
    break;
  }
  case FD_EVENT_INTERNAL_REWARD_ID: {
    fd_event_internal_reward_parts_t parts[1];
    if( FD_UNLIKELY( fd_event_internal_reward_unpack( rec, rec_sz, parts ) ) ) {
      ctx->record_malformed_cnt++;
      return;
    }
    fd_geyser_core_reward_record( ctx->core, parts );
    break;
  }
  default:
    ctx->record_malformed_cnt++;
    break;
  }
}

static void
after_frag( fd_dragon_tile_t *  ctx,
            ulong               in_idx,
            ulong               seq,
            ulong               sig,
            ulong               sz     FD_PARAM_UNUSED,
            ulong               tsorig FD_PARAM_UNUSED,
            ulong               tspub  FD_PARAM_UNUSED,
            fd_stem_context_t * stem ) {
  if( FD_LIKELY( ctx->in_kind[ in_idx ]==IN_KIND_RECORD ) ) {
    after_frag_record( ctx, in_idx );
    return;
  }

  if( FD_UNLIKELY( ctx->in_kind[ in_idx ]==IN_KIND_EVENT ) ) {
    if( FD_LIKELY( ctx->frag_valid ) ) fd_geyser_core_txn_event( ctx->core, ctx->event );
    return;
  }

  ctx->replay_frag_cnt++;

  /* The recovery from a gap runs here, where the sequence number of
     the first frag after it is known: every grant below it is either
     lost or already given back, and every grant at or above it is
     still to come. */
  if( FD_UNLIKELY( ctx->gap_pending ) ) {
    ctx->gap_pending = 0;
    fd_geyser_core_link_gap( ctx->core, seq );
  }

  if( FD_UNLIKELY( !ctx->frag_valid ) ) {
    dragon_release_flush( ctx, stem );
    return;
  }

  switch( sig ) {
  case REPLAY_SIG_SLOT_COMPLETED:
    ctx->slot_completed_cnt++;
    fd_geyser_core_slot_completed( ctx->core, &ctx->frag->slot_completed, seq );
    if( FD_UNLIKELY( ctx->exit_at_slot && ctx->frag->slot_completed.slot>=ctx->exit_at_slot ) )
      dragon_shutdown_begin( ctx, "[development.dragon.exit_at_slot] reached" );
    break;
  case REPLAY_SIG_SLOT_DEAD:
    fd_geyser_core_slot_dead( ctx->core, &ctx->frag->slot_dead, seq );
    break;
  case REPLAY_SIG_ROOT_ADVANCED:
    fd_geyser_core_root_advanced( ctx->core, &ctx->frag->root_advanced, seq );
    break;
  case REPLAY_SIG_DROP_BANK_REF:
    fd_geyser_core_drop_bank_ref( ctx->core, ctx->frag->drop_bank_ref.bank_idx, seq );
    break;
  default:
    break;
  }

  /* Replay waits on the references this publishes, and a drop request
     waits on them to make progress, so they go out in the same frag
     that asked for them. */
  dragon_release_flush( ctx, stem );

  /* Clients may connect once a bank is known at every commitment
     level, so that nobody sees a partial chain state. */
  if( FD_UNLIKELY( !ctx->serving ) ) {
    ctx->serving = fd_dragon_rpc_is_ready( ctx->rpc );
    if( FD_UNLIKELY( ctx->serving ) ) fd_dragon_rpc_set_serving( ctx->rpc, 1 );
  }
}

static ulong
populate_allowed_seccomp( fd_topo_t const *      topo,
                          fd_topo_tile_t const * tile,
                          ulong                  out_cnt,
                          struct sock_filter *   out ) {
  void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );
  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_dragon_tile_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_dragon_tile_t), sizeof(fd_dragon_tile_t) );

  populate_sock_filter_policy_fd_dragon_tile( out_cnt, out,
                                              (uint)fd_log_private_logfile_fd(),
                                              (uint)fd_grpc_server_fd( ctx->server, 0UL ),
                                              (uint)FD_WAKER_INNER_FD( tile->waker_client_idx ),
                                              (uint)FD_WAKER_OUTER_FD,
                                              (uint)FD_ACCDB_FD_RO );
  return sock_filter_policy_fd_dragon_tile_instr_cnt;
}

static ulong
populate_allowed_fds( fd_topo_t const *      topo,
                      fd_topo_tile_t const * tile,
                      ulong                  out_fds_cnt,
                      int *                  out_fds ) {
  void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );
  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_dragon_tile_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_dragon_tile_t), sizeof(fd_dragon_tile_t) );

  if( FD_UNLIKELY( out_fds_cnt<6UL ) ) FD_LOG_ERR(( "out_fds_cnt %lu", out_fds_cnt ));

  ulong out_cnt = 0UL;
  out_fds[ out_cnt++ ] = 2; /* stderr */
  if( FD_LIKELY( -1!=fd_log_private_logfile_fd() ) )
    out_fds[ out_cnt++ ] = fd_log_private_logfile_fd(); /* logfile */
  out_fds[ out_cnt++ ] = fd_grpc_server_fd( ctx->server, 0UL ); /* dragon listen socket */
  out_fds[ out_cnt++ ] = FD_WAKER_OUTER_FD;
  out_fds[ out_cnt++ ] = FD_WAKER_INNER_FD( tile->waker_client_idx );
  /* The accounts database file, which the read-only accdb join reads. */
  if( FD_LIKELY( tile->dragon.finalized ) ) out_fds[ out_cnt++ ] = FD_ACCDB_FD_RO;

  return out_cnt;
}

static ulong
rlimit_file_cnt( fd_topo_t const *      topo FD_PARAM_UNUSED,
                 fd_topo_tile_t const * tile ) {
  /* pipefd, listen socket, stderr, logfile, the two epoll fds, and one
     spare for a connection that accept() is about to refuse */
  return 7UL + tile->dragon.max_clients;
}

/* before_credit, after_frag and after_credit each publish in one
   iteration: two release flushes and the detach. */
#define STEM_BURST (2UL*FD_DRAGON_RELEASE_BURST+1UL)

/* The tile's only output carries bank reference releases, which are
   published as soon as they exist rather than in bulk, so the default
   STEM_LAZY formula does not apply.  384us is the credit interval
   other non-critical tiles use. */
#define STEM_LAZY (128L*3000L)

/* The waker tile sleeps on the sockets; this tile spins so a client is
   served the moment the waker reports one ready. */
#define STEM_NEVER_PARK             1
#define STEM_CALLBACK_CONTEXT_TYPE  fd_dragon_tile_t
#define STEM_CALLBACK_CONTEXT_ALIGN alignof(fd_dragon_tile_t)

#define STEM_CALLBACK_METRICS_WRITE       metrics_write
#define STEM_CALLBACK_DURING_HOUSEKEEPING during_housekeeping
#define STEM_CALLBACK_BEFORE_CREDIT       before_credit
#define STEM_CALLBACK_AFTER_CREDIT        after_credit
#define STEM_CALLBACK_SHOULD_SHUTDOWN     should_shutdown
#define STEM_CALLBACK_BEFORE_FRAG         before_frag
#define STEM_CALLBACK_DURING_FRAG         during_frag
#define STEM_CALLBACK_AFTER_FRAG          after_frag

#include "../../disco/stem/fd_stem.c"

#ifndef FD_TILE_TEST
fd_topo_run_tile_t fd_tile_dragon = {
  .name                     = "dragon",
  .keep_host_networking     = 1,
  .rlimit_file_cnt_fn       = rlimit_file_cnt,
  .populate_allowed_seccomp = populate_allowed_seccomp,
  .populate_allowed_fds     = populate_allowed_fds,
  .scratch_align            = scratch_align,
  .scratch_footprint        = scratch_footprint,
  .privileged_init          = privileged_init,
  .unprivileged_init        = unprivileged_init,
  .run                      = stem_run,
};
#endif
