#ifndef HEADER_fd_src_flamenco_gossip_fd_gossip_metrics_h
#define HEADER_fd_src_flamenco_gossip_fd_gossip_metrics_h

#include "fd_gossip_private.h"
#include "../../disco/metrics/generated/fd_metrics_gossip.h"

FD_STATIC_ASSERT( FD_METRICS_ENUM_GOSSIP_MESSAGE_CNT== FD_GOSSIP_MESSAGE_LAST+1,
                  "FD_METRICS_ENUM_GOSSIP_MESSAGE_CNT must match FD_GOSSIP_MESSAGE_LAST+1" );

FD_STATIC_ASSERT( FD_METRICS_ENUM_CRDS_VALUE_CNT== FD_GOSSIP_VALUE_LAST+1,
                  "FD_METRICS_ENUM_CRDS_VALUE_CNT must match FD_GOSSIP_VALUE_LAST+1" );

struct fd_crds_table_metrics {
  ulong total_ele_cnt;
  ulong ele_cnt[ FD_METRICS_ENUM_CRDS_VALUE_CNT ];
  ulong tiebroken[ FD_METRICS_ENUM_CRDS_VALUE_CNT ];
  ulong table_purged_cnt;

  ulong visible_stake;
  ulong unstaked_peer_cnt;
  ulong staked_peer_cnt;
};

typedef struct fd_crds_table_metrics fd_crds_table_metrics_t;

struct fd_gossip_metrics {
  fd_crds_table_metrics_t crds_table[ 1 ];

  ulong                   rx_msg_count[ FD_METRICS_ENUM_GOSSIP_MESSAGE_CNT ];
  ulong                   rx_msg_bytes[ FD_METRICS_ENUM_GOSSIP_MESSAGE_CNT ];

  ulong                   tx_msg_count[ FD_METRICS_ENUM_GOSSIP_MESSAGE_CNT ];
  ulong                   tx_msg_bytes[ FD_METRICS_ENUM_GOSSIP_MESSAGE_CNT ];

  ulong                   rx_push_crd_count[ FD_METRICS_ENUM_CRDS_VALUE_CNT ];
  ulong                   rx_push_crd_bytes[ FD_METRICS_ENUM_CRDS_VALUE_CNT ];
  ulong                   rx_push_crd_upserted[ FD_METRICS_ENUM_CRDS_VALUE_CNT ];
  ulong                   rx_push_crd_duplicate[ FD_METRICS_ENUM_CRDS_VALUE_CNT ];
  ulong                   rx_push_crd_fail[ FD_METRICS_ENUM_CRDS_VALUE_CNT ];

  ulong                   rx_pull_crd_count[ FD_METRICS_ENUM_CRDS_VALUE_CNT ];
  ulong                   rx_pull_crd_bytes[ FD_METRICS_ENUM_CRDS_VALUE_CNT ];
  ulong                   rx_pull_crd_upserted[ FD_METRICS_ENUM_CRDS_VALUE_CNT ];
  ulong                   rx_pull_crd_duplicate[ FD_METRICS_ENUM_CRDS_VALUE_CNT ];
  ulong                   rx_pull_crd_fail[ FD_METRICS_ENUM_CRDS_VALUE_CNT ];

  ulong                   tx_push_crd_count[ FD_METRICS_ENUM_CRDS_VALUE_CNT ];
  ulong                   tx_push_crd_bytes[ FD_METRICS_ENUM_CRDS_VALUE_CNT ];

  ulong                   tx_pull_crd_count[ FD_METRICS_ENUM_CRDS_VALUE_CNT ];
  ulong                   tx_pull_crd_bytes[ FD_METRICS_ENUM_CRDS_VALUE_CNT ];
};

typedef struct fd_gossip_metrics fd_gossip_metrics_t;

#endif
