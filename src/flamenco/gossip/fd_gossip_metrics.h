#ifndef HEADER_fd_src_flamenco_gossip_fd_gossip_metrics_h
#define HEADER_fd_src_flamenco_gossip_fd_gossip_metrics_h

#define GOSSIP_MESSAGE_TYPES_COUNT 6UL
#define GOSSIP_CRDS_TYPES_COUNT    14UL

struct fd_gossip_metrics_message {
  ulong msg[ GOSSIP_MESSAGE_TYPES_COUNT ];
};

typedef struct fd_gossip_metrics_message fd_gossip_metrics_message_t;

struct fd_gossip_metrics_message_traffic {
  fd_gossip_metrics_message_t count;
  fd_gossip_metrics_message_t bytes;
};
typedef struct fd_gossip_metrics_message_traffic fd_gossip_metrics_message_traffic_t;

struct fd_gossip_metrics_crds {
  ulong crd[ GOSSIP_CRDS_TYPES_COUNT ];
};
typedef struct fd_gossip_metrics_crds fd_gossip_metrics_crds_t;

struct fd_gossip_metrics_crds_traffic {
  fd_gossip_metrics_crds_t count;
  fd_gossip_metrics_crds_t bytes;
};
typedef struct fd_gossip_metrics_crds_traffic fd_gossip_metrics_crds_traffic_t;

struct fd_gossip_metrics_crds_insert {
  fd_gossip_metrics_crds_traffic_t rx;
  fd_gossip_metrics_crds_t         upserted;
  fd_gossip_metrics_crds_t         duplicates;
  fd_gossip_metrics_crds_t         too_old;
};

typedef struct fd_gossip_metrics_crds_insert fd_gossip_metrics_crds_insert_t;

struct fd_crds_table_metrics {
  ulong                    total_ele_cnt;
  fd_gossip_metrics_crds_t ele_cnt;
  fd_gossip_metrics_crds_t undetermined;
  ulong                    table_purged_cnt;

  ulong                    visible_stake;
  ulong                    unstaked_peer_cnt;
  ulong                    staked_peer_cnt;
};

typedef struct fd_crds_table_metrics fd_crds_table_metrics_t;

struct fd_gossip_metrics {
  fd_crds_table_metrics_t             crds_table[ 1 ];

  fd_gossip_metrics_message_traffic_t rx[1];
  fd_gossip_metrics_message_traffic_t tx[1];

  fd_gossip_metrics_crds_insert_t     push_rx[1];
  fd_gossip_metrics_crds_insert_t     pull_rx[1];

  fd_gossip_metrics_crds_traffic_t    push_tx[1];
  fd_gossip_metrics_crds_traffic_t    pull_tx[1];
};

typedef struct fd_gossip_metrics fd_gossip_metrics_t;

#endif
