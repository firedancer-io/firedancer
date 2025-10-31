#ifndef HEADER_fd_src_disco_gui_fd_gui_peers_h
#define HEADER_fd_src_disco_gui_fd_gui_peers_h

/* fd_gui_peers defines methods that maintain metrics and metadata about
   Solana cluster peers that are active on the Gossip network.

   Peer identifiers are added and removed by incoming update messages
   from the gossip tile. Additional information about the peer is
   obtained from other places and merged into the a large peers table
   with live updates.

   fd_gui_peers also defines methods for handling messages from a
   WebSocket client. These messages contain peer related information,
   including a live view of the peer table with the option to order the
   table a custom sort key. */

#include "../../util/net/fd_net_headers.h"
#include "../../disco/metrics/fd_metrics.h"
#include "../../flamenco/gossip/fd_gossip_types.h"
#include "../../discof/replay/fd_replay_tile.h"
#include "../../flamenco/runtime/fd_runtime_const.h"

#include "../../waltz/http/fd_http_server.h"
#include "../topo/fd_topo.h"

#define FD_GUI_PEERS_VALIDATOR_INFO_NAME_SZ     ( 64UL)
#define FD_GUI_PEERS_VALIDATOR_INFO_WEBSITE_SZ  (128UL)
#define FD_GUI_PEERS_VALIDATOR_INFO_DETAILS_SZ  (256UL)
#define FD_GUI_PEERS_VALIDATOR_INFO_ICON_URI_SZ (128UL)

#define FD_GUI_PEERS_NODE_NOP    (0)
#define FD_GUI_PEERS_NODE_ADD    (1)
#define FD_GUI_PEERS_NODE_UPDATE (2)
#define FD_GUI_PEERS_NODE_DELETE (3)

#define FD_GUI_PEERS_CI_TABLE_SORT_KEY_CNT                 (256UL) /* maximum number of maintained active sort keys */
#define FD_GUI_PEERS_WS_VIEWPORT_MAX_SZ                    (200UL) /* the maximum number of rows a client can request for a table viewport */
#define FD_GUI_PEERS_WS_VIEWPORT_UPDATE_INTERVAL_MILLIS    ( 100L)
#define FD_GUI_PEERS_METRIC_RATE_UPDATE_INTERVAL_MILLIS    ( 100L)
#define FD_GUI_PEERS_GOSSIP_STATS_UPDATE_INTERVAL_MILLIS   ( 100L)

#define FD_GUI_PEERS_GOSSIP_TOP_PEERS_CNT (64UL)

/* Some table columns are rates of change, which require keeping a
   historical value / timestamp. */
struct fd_gui_peers_metric_rate {
  ulong cur;
  ulong ref;
  long rate; /* units per sec. live_table treaps use this field to sort table entries */
};
typedef struct fd_gui_peers_metric_rate fd_gui_peers_metric_rate_t;

struct fd_gui_peers_vote {
  fd_pubkey_t node_account;
  fd_pubkey_t vote_account;
  ulong       stake;
  ulong       last_vote_slot;
  long        last_vote_timestamp;
  uchar       commission;
  ulong       epoch;
  ulong       epoch_credits;
};

typedef struct fd_gui_peers_vote fd_gui_peers_vote_t;

struct fd_gui_peers_node {
  int valid;
  long update_time_nanos;
  fd_contact_info_t contact_info;

  fd_gui_peers_metric_rate_t gossvf_rx[ FD_METRICS_ENUM_GOSSIP_MESSAGE_CNT ];
  fd_gui_peers_metric_rate_t gossip_tx[ FD_METRICS_ENUM_GOSSIP_MESSAGE_CNT ];
  fd_gui_peers_metric_rate_t gossvf_rx_sum; /* sum of gossvf_rx */
  fd_gui_peers_metric_rate_t gossip_tx_sum; /* sum of gossip_tx */

  int  has_val_info;
  char name    [ FD_GUI_PEERS_VALIDATOR_INFO_NAME_SZ     ];
  char website [ FD_GUI_PEERS_VALIDATOR_INFO_WEBSITE_SZ  ];
  char details [ FD_GUI_PEERS_VALIDATOR_INFO_DETAILS_SZ  ];
  char icon_uri[ FD_GUI_PEERS_VALIDATOR_INFO_ICON_URI_SZ ];

  int         has_vote_info;
  fd_pubkey_t vote_account;
  ulong       stake; /* if has_vote_info==0 then stake==ULONG_MAX */
  ulong       last_vote_slot;
  long        last_vote_timestamp;
  uchar       commission;
  ulong       epoch;
  ulong       epoch_credits;
  int         delinquent;

  struct {
    ulong next;
    ulong prev;
  } pubkey_map;

  struct {
    ulong next;
    ulong prev;
  } sock_map;

  struct {
    ulong parent;
    ulong left;
    ulong right;
    ulong prio;
    ulong next;
    ulong prev;
  } treaps_live_table[ FD_GUI_PEERS_CI_TABLE_SORT_KEY_CNT ];
  struct {
    ulong next;
    ulong prev;
  } dlist_live_table;
  ulong sort_keys_live_table;

  struct {
    ulong parent;
    ulong left;
    ulong right;
    ulong prio;
    ulong next;
    ulong prev;
  } treaps_bandwidth_tracking[ 2UL ];
    struct {
    ulong next;
    ulong prev;
  } dlist_bandwidth_tracking;
  ulong sort_keys_bandwidth_tracking;
};
typedef struct fd_gui_peers_node fd_gui_peers_node_t;

struct fd_gui_peers_gossip_stats {
  long  sample_time;
  ulong network_health_pull_response_msg_rx_success;
  ulong network_health_pull_response_msg_rx_failure;
  ulong network_health_push_msg_rx_success;
  ulong network_health_push_msg_rx_failure;
  ulong network_health_push_crds_rx_duplicate;
  ulong network_health_pull_response_crds_rx_duplicate;
  ulong network_health_push_crds_rx_success;
  ulong network_health_push_crds_rx_failure;
  ulong network_health_pull_response_crds_rx_success;
  ulong network_health_pull_response_crds_rx_failure;
  ulong network_health_push_msg_tx;
  ulong network_health_pull_response_msg_tx;
  ulong network_health_total_stake; /* lamports */
  ulong network_health_total_peers;
  ulong network_health_connected_stake; /* lamports */
  ulong network_health_connected_staked_peers;
  ulong network_health_connected_unstaked_peers;
  ulong network_ingress_total_bytes;
  ulong network_ingress_peer_sz;
  long  network_ingress_peer_bytes_per_sec   [ FD_GUI_PEERS_GOSSIP_TOP_PEERS_CNT ];
  char  network_ingress_peer_names           [ FD_GUI_PEERS_GOSSIP_TOP_PEERS_CNT ][ FD_GUI_PEERS_VALIDATOR_INFO_NAME_SZ ];
  fd_pubkey_t network_ingress_peer_identities[ FD_GUI_PEERS_GOSSIP_TOP_PEERS_CNT ];
  long  network_ingress_total_bytes_per_sec;
  ulong network_egress_total_bytes;
  ulong network_egress_peer_sz;
  long  network_egress_peer_bytes_per_sec   [ FD_GUI_PEERS_GOSSIP_TOP_PEERS_CNT ];
  char  network_egress_peer_names           [ FD_GUI_PEERS_GOSSIP_TOP_PEERS_CNT ][ FD_GUI_PEERS_VALIDATOR_INFO_NAME_SZ ];
  fd_pubkey_t network_egress_peer_identities[ FD_GUI_PEERS_GOSSIP_TOP_PEERS_CNT ];
  long  network_egress_total_bytes_per_sec;
  ulong storage_capacity;
  ulong storage_expired_cnt;
  ulong storage_evicted_cnt;
  ulong storage_active_cnt[ FD_METRICS_ENUM_CRDS_VALUE_CNT ];
  ulong storage_cnt_tx    [ FD_METRICS_ENUM_CRDS_VALUE_CNT ];
  ulong storage_bytes_tx  [ FD_METRICS_ENUM_CRDS_VALUE_CNT ];
  ulong messages_push_rx_cnt;
  ulong messages_push_tx_cnt;
  ulong messages_pull_response_rx_cnt;
  ulong messages_pull_response_tx_cnt;
  ulong messages_bytes_rx[ FD_METRICS_ENUM_GOSSIP_MESSAGE_CNT ];
  ulong messages_count_rx[ FD_METRICS_ENUM_GOSSIP_MESSAGE_CNT ];
  ulong messages_bytes_tx[ FD_METRICS_ENUM_GOSSIP_MESSAGE_CNT ];
  ulong messages_count_tx[ FD_METRICS_ENUM_GOSSIP_MESSAGE_CNT ];
};
typedef struct fd_gui_peers_gossip_stats fd_gui_peers_gossip_stats_t;

#define MAP_NAME  fd_gui_peers_node_pubkey_map
#define MAP_ELE_T fd_gui_peers_node_t
#define MAP_KEY_T fd_pubkey_t
#define MAP_KEY   contact_info.pubkey
#define MAP_IDX_T ulong
#define MAP_NEXT  pubkey_map.next
#define MAP_PREV  pubkey_map.prev
#define MAP_KEY_HASH(k,s) ((s) ^ fd_ulong_hash( (k)->ul[ 0 ] ))
#define MAP_KEY_EQ(k0,k1) (!memcmp((k0)->uc, (k1)->uc, 32UL))
#define MAP_OPTIMIZE_RANDOM_ACCESS_REMOVAL 1
#include "../../util/tmpl/fd_map_chain.c"

#define MAP_NAME  fd_gui_peers_node_sock_map
#define MAP_ELE_T fd_gui_peers_node_t
#define MAP_KEY_T fd_ip4_port_t
#define MAP_KEY   contact_info.sockets[ FD_CONTACT_INFO_SOCKET_GOSSIP ]
#define MAP_IDX_T ulong
#define MAP_NEXT  sock_map.next
#define MAP_PREV  sock_map.prev
#define MAP_KEY_HASH(k,s) ( fd_hash( (s), (k), sizeof(uint) + sizeof(ushort) ) )
#define MAP_KEY_EQ(k0,k1) ((k0)->l==(k1)->l )
#define MAP_OPTIMIZE_RANDOM_ACCESS_REMOVAL 1
#define MAP_MULTI 1
#include "../../util/tmpl/fd_map_chain.c"

static int live_table_col_pubkey_lt( void const * a, void const * b ) { return memcmp( ((fd_pubkey_t *)a)->uc, ((fd_pubkey_t *)b)->uc, 32UL ) < 0; }
static int live_table_col_long_lt  ( void const * a, void const * b ) { return *(long *)a < *(long *)b;                                            }
static int live_table_col_ipv4_lt  ( void const * a, void const * b ) { return fd_uint_bswap(*(uint *)a) < fd_uint_bswap(*(uint *)b);              }
static int live_table_col_stake_lt ( void const * a, void const * b ) { return fd_long_if( *(ulong *)a>LONG_MAX, -1L, (long)*(ulong *)a ) < fd_long_if( *(ulong *)b>LONG_MAX, -1L, (long)*(ulong *)b ); }

#define LIVE_TABLE_NAME fd_gui_peers_live_table
#define LIVE_TABLE_TREAP treaps_live_table
#define LIVE_TABLE_SORT_KEYS sort_keys_live_table
#define LIVE_TABLE_DLIST dlist_live_table
#define LIVE_TABLE_COLUMN_CNT (7UL)
#define LIVE_TABLE_MAX_SORT_KEY_CNT FD_GUI_PEERS_CI_TABLE_SORT_KEY_CNT
#define LIVE_TABLE_ROW_T fd_gui_peers_node_t
#define LIVE_TABLE_COLUMNS LIVE_TABLE_COL_ARRAY( \
  LIVE_TABLE_COL_ENTRY( "Ingress Push", gossvf_rx[ FD_METRICS_ENUM_GOSSIP_MESSAGE_V_PUSH_IDX ].rate,          live_table_col_long_lt   ), \
  LIVE_TABLE_COL_ENTRY( "Ingress Pull", gossvf_rx[ FD_METRICS_ENUM_GOSSIP_MESSAGE_V_PULL_RESPONSE_IDX ].rate, live_table_col_long_lt   ), \
  LIVE_TABLE_COL_ENTRY( "Egress Push",  gossip_tx[ FD_METRICS_ENUM_GOSSIP_MESSAGE_V_PUSH_IDX ].rate,          live_table_col_long_lt   ), \
  LIVE_TABLE_COL_ENTRY( "Egress Pull",  gossip_tx[ FD_METRICS_ENUM_GOSSIP_MESSAGE_V_PULL_RESPONSE_IDX ].rate, live_table_col_long_lt   ), \
  LIVE_TABLE_COL_ENTRY( "Stake",        stake,                                                                live_table_col_stake_lt  ), \
  LIVE_TABLE_COL_ENTRY( "Pubkey",       contact_info.pubkey,                                                  live_table_col_pubkey_lt ), \
  LIVE_TABLE_COL_ENTRY( "IP Addr",      contact_info.sockets[ FD_CONTACT_INFO_SOCKET_GOSSIP ].addr,           live_table_col_ipv4_lt   )  )
#include "fd_gui_live_table_tmpl.c"

#define FD_GUI_PEERS_LIVE_TABLE_DEFAULT_SORT_KEY ((fd_gui_peers_live_table_sort_key_t){ .col = { 0, 1, 2, 3, 4, 5, 6 }, .dir = { -1, -1, -1, -1, -1, -1, -1 } })

#define LIVE_TABLE_NAME fd_gui_peers_bandwidth_tracking
#define LIVE_TABLE_TREAP treaps_bandwidth_tracking
#define LIVE_TABLE_SORT_KEYS sort_keys_bandwidth_tracking
#define LIVE_TABLE_DLIST dlist_bandwidth_tracking
#define LIVE_TABLE_COLUMN_CNT (2UL)
#define LIVE_TABLE_MAX_SORT_KEY_CNT (2UL)
#define LIVE_TABLE_ROW_T fd_gui_peers_node_t
#define LIVE_TABLE_COLUMNS LIVE_TABLE_COL_ARRAY( \
  LIVE_TABLE_COL_ENTRY( "Ingress Total", gossvf_rx_sum.rate, live_table_col_long_lt ), \
  LIVE_TABLE_COL_ENTRY( "Egress Total",  gossip_tx_sum.rate, live_table_col_long_lt )  )
#include "fd_gui_live_table_tmpl.c"

#define FD_GUI_PEERS_BW_TRACKING_INGRESS_SORT_KEY ((fd_gui_peers_bandwidth_tracking_sort_key_t){ .col = { 0, 1 }, .dir = { -1, 0 } })
#define FD_GUI_PEERS_BW_TRACKING_EGRESS_SORT_KEY  ((fd_gui_peers_bandwidth_tracking_sort_key_t){ .col = { 0, 1 }, .dir = { 0, -1 } })

struct fd_gui_peers_ws_conn {
  int connected;
  long connected_time;

  ulong start_row;
  ulong row_cnt;
  fd_gui_peers_node_t viewport[ FD_GUI_PEERS_WS_VIEWPORT_MAX_SZ ];
  fd_gui_peers_live_table_sort_key_t sort_key;
};
typedef struct fd_gui_peers_ws_conn fd_gui_peers_ws_conn_t;
struct fd_gui_peers_ctx {
  long next_client_nanos; /* ns timestamp when we'll service the next ws client */
  long next_metric_rate_update_nanos; /* ns timestamp when we'll next update rate-of-change metrics */
  long next_gossip_stats_update_nanos; /* ns timestamp when we'll next broadcast out gossip stats message */

  fd_gui_peers_node_pubkey_map_t * node_pubkey_map;
  fd_gui_peers_node_sock_map_t  * node_sock_map;
  fd_gui_peers_live_table_t * live_table;
  fd_gui_peers_bandwidth_tracking_t * bw_tracking;

  fd_http_server_t * http;
  fd_topo_t * topo;

  ulong max_ws_conn_cnt;
  ulong open_ws_conn_cnt;
  ulong active_ws_conn_id;
  fd_gui_peers_ws_conn_t * client_viewports; /* points to 2D array with max_ws_conn_cnt rows and FD_GUI_PEERS_WS_VIEWPORT_MAX_SZ columns */

  fd_gui_peers_gossip_stats_t gossip_stats  [ 1 ];
  fd_gui_peers_node_t contact_info_table[ FD_CONTACT_INFO_TABLE_SIZE ];

  fd_gui_peers_vote_t votes        [ FD_RUNTIME_MAX_VOTE_ACCOUNTS ];
  fd_gui_peers_vote_t votes_scratch[ FD_RUNTIME_MAX_VOTE_ACCOUNTS ]; /* for fast stable sort */
};
typedef struct fd_gui_peers_ctx fd_gui_peers_ctx_t;

FD_PROTOTYPES_BEGIN

FD_FN_CONST ulong
fd_gui_peers_align( void );

FD_FN_CONST ulong
fd_gui_peers_footprint( ulong max_ws_conn_cnt );

void *
fd_gui_peers_new( void *             shmem,
                  fd_http_server_t * http,
                  fd_topo_t *        topo,
                  ulong              max_ws_conn_cnt,
                  long               now );

fd_gui_peers_ctx_t *
fd_gui_peers_join( void * shmem );

/* fd_gui_peers_handle_gossip_message_rx parses gossip messages from the
   net_gossvf link for ingress messages and the gossip_net link for
   egress messages and tracks per-peer, per-message bytes.  payload and
   payload_sz corresponds to the frag data after the network headers
   have been stripped. is_rx is true if the frag is an incoming message
   from the net_gossvf link. Otherwise, the frag is assumed to be an
   outgoing message from the gossip_net link. peer_sock is the ipv4
   address and port from the stripped net headers, which identifies the
   peers that sent or will receive the message.

   Note that gossip_net frags are unverified gossip messages from the
   network.  Messages that cannot be parsed are ignored. */
void
fd_gui_peers_handle_gossip_message( fd_gui_peers_ctx_t *  peers,
                                    uchar const *         payload,
                                    ulong                 payload_sz,
                                    fd_ip4_port_t const * peer_sock,
                                    int                   is_rx );

/* fd_gui_peers_handle_gossip_message_tx parses frags on the gossip_out
   link and uses the contact info update to build up the peer table.
   */
void
fd_gui_peers_handle_gossip_update( fd_gui_peers_ctx_t *               peers,
                                   fd_gossip_update_message_t const * update,
                                   long                               now );

void
fd_gui_peers_handle_vote_update( fd_gui_peers_ctx_t *  peers,
                                 fd_gui_peers_vote_t * votes,
                                 ulong                 vote_cnt,
                                 long                  now );

/* fd_gui_peers_ws_message handles incoming websocket request payloads
   requesting peer-related responses.  ws_conn_id is the connection id
   of the requester.  data is a pointer to the start of the
   json-formatted request payload.  data_len is the length of the
   request payload. */
int
fd_gui_peers_ws_message( fd_gui_peers_ctx_t * peers,
                         ulong                ws_conn_id,
                         uchar const *        data,
                         ulong                data_len );

/* fd_gui_peers_ws_open is a callback which should be triggered when a
   new client opens a WebSocket connection.  ws_conn_id is the
   connection id of the new client.  now is a UNIX nanosecond timestamp
   for the current time. */
void
fd_gui_peers_ws_open( fd_gui_peers_ctx_t * peers, ulong ws_conn_id, long now );

/* fd_gui_peers_ws_close is a callback which should be triggered when an
   existing client closes their WebSocket connection.  ws_conn_id is the
   connection id of the client.*/
void
fd_gui_peers_ws_close( fd_gui_peers_ctx_t * peers, ulong ws_conn_id );

/* fd_gui_peers_poll should be called in a the tile's main spin loop to
   periodically update peers internal state as well as publish new
   Websocket messages to clients. now is a UNIX nanosecond timestamp for
   the current time. */
int
fd_gui_peers_poll( fd_gui_peers_ctx_t * peers, long now  );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_disco_gui_fd_gui_peers_h */
