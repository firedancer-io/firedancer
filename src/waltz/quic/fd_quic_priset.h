#ifndef HEADER_fd_src_waltz_quic_fd_quic_priset_h
#define HEADER_fd_src_waltz_quic_fd_quic_priset_h


/* Limits on INITIAL and HANDSHAKE packets */
#define ALLOWED_INITIAL           100UL
#define ALLOWED_HANDSHAKE         100UL
#define ALLOWED_INITIAL_PERIOD_NS ((ulong)1e6)

/* frequency of key update for connections */
#define CONN_KEY_UPDATE_PERIOD_NS ((ulong)10e9)

/* used to maintain active connections in priority sequence */
struct fd_quic_priset_key {
  uchar has_at_least_one_stream;   /* bool : at least one completed stream */
  ulong last_stream_activity_time; /* defined by stream completion */
  float ema_completed_streams;     /* recent rate of stream completion */

  ulong conn_idx;                  /* need to be able to uniquely identify */

  fd_qos_priority_t qos_prio;      /* QoS priority - from QoS IP map */

  /* don't want to update the priority set every packet */
  /* this data is approximate and delayed anyway */
  /* so we use a policy of updating the connection key of: */
  /*   - update certain changes immediately */
  /*       e.g. has_at_least_one_stream, and last_stream_activity_time */
  /*   - update periodically */
  /* implement the first policy by setting last_updated_time to a low value */
  /*   so only one check is needed in the critical path */
  ulong last_updated_time;
};
typedef struct fd_quic_priset_key fd_quic_priset_key_t;

/* connection related statistics for generating priority key */
struct fd_quic_conn_stats {
  /* connection is lower priority if:
   *    it has never sent streams
   *    it has sent fewer streams recently
   *    it has never sent streams, and it's been alive longer */
  ulong                last_completed_stream; /* time of last completed stream */
  ulong                tot_completed_streams; /* count completed streams */
  float                ema_completed_streams; /* run EMA over completed streams */
};
typedef struct fd_quic_conn_stats fd_quic_conn_stats_t;


/* define a priority set and a pool */

struct fd_quic_priset_node {
  fd_quic_priset_key_t key;

  fd_quic_conn_t * conn;

  /* required for treap impl */
  ulong parent;
  ulong left;
  ulong right;
  ulong prio;

  /* required for pool */
  ulong next;
};
typedef struct fd_quic_priset_node fd_quic_priset_node_t;

#endif /* HEADER_fd_src_waltz_quic_fd_quic_priset_h */
