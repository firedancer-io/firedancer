#ifndef HEADER_fd_src_discof_backup_fd_snapsv_tile_h
#define HEADER_fd_src_discof_backup_fd_snapsv_tile_h

/* fd_snapsv_tile.h specifies the snapsv tile ABI.

   The snapsv tile is a HTTP/1.1 file server that serves local snapshots
   to remote peers. */

#include "../../util/net/fd_ip6.h"

/* The snapsv_out link replicates out snapshot server state to external
   consumers.  Currently, events for the following tables exist:

   - snapshot downloads: active snapshot download HTTP connections with
     periodic progress updates (SYNC_PERIOD)

   Notes on the sync protocol:

   - each frag fully describes a row revision
   - every SYNC_PERIOD, each row generates an update (all rows are
     published in one burst)
   - if SYNC_EXPIRY time passes without an update, consumers remove that
     row (to recover from dropped deletions)

   Generic frag_meta fields:
   - sig: FD_SNAPSV_MSG_*
   - tspub: unix nanosecond timestamp of event (**not tickcount**) */

#define FD_SNAPSV_WAKE_PERIOD ((long)50e6) /*   50 ms */
#define FD_SNAPSV_SYNC_PERIOD ((long)50e6) /*   50 ms */
#define FD_SNAPSV_SYNC_EXPIRY ((long) 1e9) /* 1000 ms */

/* FD_SNAPSV_MSG_* give message types */

#define FD_SNAPSV_MSG_SNAP 1 /* fd_snapsv_msg_snap_t */

/* FD_SNAPSV_CLOSE_* give reasons an upload ended */

#define FD_SNAPSV_CLOSE_DONE  0 /* the whole requested range was sent */
#define FD_SNAPSV_CLOSE_NET   1 /* failed for arbitrary network reason */
#define FD_SNAPSV_CLOSE_ABORT 2 /* failed because we locally aborted */

/* fd_snapsv_conn_key_t identifies a snapshot server HTTP request.

   (kind_id,req_seq) is an app-wide unique request identifier across all
   live and historical requests.
   (kind_id,slot_idx) is app-wide unique among live/ongoing requests only. */

struct fd_snapsv_conn_key {
  uint  kind_id;  /* which snapsv tile? */
  ulong req_seq;  /* tile-unique HTTP request sequence number */
  uint  slot_idx; /* primary key (index of row in fixed size table) */
};

typedef struct fd_snapsv_conn_key fd_snapsv_conn_key_t;

/* fd_snapsv_msg_snap_t is an event for a snapshot GET request.

   frag_meta::
   - ctl::som: first frag of this request
   - ctl::eom: last frag of this request (request ended)

   For every snapshot GET request, there is at least one {som,eom} frag
   generated (might be the same frag), but they might get dropped due to
   mcache overruns. */

struct fd_snapsv_msg_snap {
  fd_snapsv_conn_key_t key;

  ulong slot;         /* snapshot slot */
  ulong base_slot;    /* ULONG_MAX if full snapshot */
  ulong snap_sz;      /* total snapshot file size */

  ulong req_off; /* file offset of HTTP Range request */
  ulong req_sz;  /* size of HTTP Range request */
  ulong req_cur; /* number of bytes sent or in send window */

  fd_ip6_addr_t req_ip;
  ushort        req_port;
  uchar         close_kind; /* FD_SNAPSV_CLOSE_* (valid if ctl.eom==1) */
  long          resp_ts;    /* timestamp of HTTP response start (unix nanoseconds) */
};

typedef struct fd_snapsv_msg_snap fd_snapsv_msg_snap_t;

/* fd_snapsv_msg_t is the data payload behind the fd_frag_meta_t::chunk
   compressed offset.  This type only exists to derive the link MTU. */

union fd_snapsv_msg {
  fd_snapsv_msg_snap_t snap;
};

typedef union fd_snapsv_msg fd_snapsv_msg_t;

#endif /* HEADER_fd_src_discof_backup_fd_snapsv_tile_h */
