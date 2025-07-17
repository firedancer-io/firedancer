#ifndef HEADER_fd_src_disco_gui_fd_gui_peers_h
#define HEADER_fd_src_disco_gui_fd_gui_peers_h

#include "../fd_disco_base.h"

#include "../../util/net/fd_net_headers.h"
#include "../../disco/metrics/fd_metrics.h"
#include "../../flamenco/gossip/fd_gossip_private.h"
#include "../../waltz/http/fd_http_server.h"

#define FD_GUI_PEERS_VALIDATOR_INFO_NAME_SZ     ( 64UL)
#define FD_GUI_PEERS_VALIDATOR_INFO_WEBSITE_SZ  (128UL)
#define FD_GUI_PEERS_VALIDATOR_INFO_DETAILS_SZ  (256UL)
#define FD_GUI_PEERS_VALIDATOR_INFO_ICON_URI_SZ (128UL)

#define FD_GUI_PEERS_NODE_NOP    (0)
#define FD_GUI_PEERS_NODE_ADD    (1)
#define FD_GUI_PEERS_NODE_UPDATE (2)
#define FD_GUI_PEERS_NODE_DELETE (3)

#define FD_GUI_PEERS_CI_TABLE_SORT_KEY_CNT (256UL) /* maximum number of maintained active sort keys */
#define FD_GUI_PEERS_WS_VIEWPORT_MAX_SZ (200UL) /* the maximum number of rows a client can request for a table viewport */
#define FD_GUI_PEERS_WS_VIEWPORT_UPDATE_INTERVAL_MILLIS (1000L)

struct fd_gui_peers_node {
  int valid;

  /* Consumers are interested in rate of change for these fields. Since
     we only send updates when a field has changed, we need to also keep
     a diff so that we can estimate the second derivate and only send an
     update if it's non-zero. */

  struct {
    struct {
      ulong bytes_rx[ FD_METRICS_ENUM_GOSSIP_MESSAGE_CNT ];
    } gossvf;

    struct {
      ulong bytes_tx[ FD_METRICS_ENUM_GOSSIP_MESSAGE_CNT ];
    } gossip;
  } cur, diff;

  fd_contact_info_t contact_info;

  fd_pubkey_t vote_account;
  ulong       activated_stake;
  uchar       commission;
  ulong       last_vote;
  ulong       root_slot;
  ulong       epoch_credits;
  int         delinquent;

  char name    [ FD_GUI_PEERS_VALIDATOR_INFO_NAME_SZ     ];
  char website [ FD_GUI_PEERS_VALIDATOR_INFO_WEBSITE_SZ  ];
  char details [ FD_GUI_PEERS_VALIDATOR_INFO_DETAILS_SZ  ];
  char icon_uri[ FD_GUI_PEERS_VALIDATOR_INFO_ICON_URI_SZ ];

  struct {
    ulong next;
    ulong prev;
  } pubkey_map;

  struct {
    ulong next;
    ulong prev;
  } sock_map;

  struct {
    ulong parent  [ FD_GUI_PEERS_CI_TABLE_SORT_KEY_CNT ];
    ulong left    [ FD_GUI_PEERS_CI_TABLE_SORT_KEY_CNT ];
    ulong right   [ FD_GUI_PEERS_CI_TABLE_SORT_KEY_CNT ];
    ulong prio    [ FD_GUI_PEERS_CI_TABLE_SORT_KEY_CNT ];
    ulong next    [ FD_GUI_PEERS_CI_TABLE_SORT_KEY_CNT ];
    ulong prev    [ FD_GUI_PEERS_CI_TABLE_SORT_KEY_CNT ];
  } live_table_treap;
};
typedef struct fd_gui_peers_node fd_gui_peers_node_t;

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
#define MAP_KEY_HASH(k,s) ((s) ^ fd_ulong_hash( (ulong)((k)->addr) ) ^ fd_ulong_hash( (ulong)((k)->port) ))
#define MAP_KEY_EQ(k0,k1) ((k0)->addr==(k1)->addr && (k0)->port==(k1)->port )
#define MAP_OPTIMIZE_RANDOM_ACCESS_REMOVAL 1
#include "../../util/tmpl/fd_map_chain.c"

static int live_table_col_pubkey_lt( void const * a, void const * b ) { return memcmp( (fd_pubkey_t *)a, (fd_pubkey_t *)b, 32UL ) < 0; }
static int live_table_col_uint_lt  ( void const * a, void const * b ) { return *(uint *)a < *(uint *)b;                                }
static int live_table_col_ulong_lt ( void const * a, void const * b ) { return fd_uint_bswap(*(uint *)a) < fd_uint_bswap(*(uint *)b);  }

#define LIVE_TABLE_NAME fd_gui_peers_live_table
#define LIVE_TABLE_COLUMN_CNT (6UL)
#define LIVE_TABLE_MAX_SORT_KEY_CNT FD_GUI_PEERS_CI_TABLE_SORT_KEY_CNT
#define LIVE_TABLE_COLUMNS LIVE_TABLE_COL_ARRAY( \
  LIVE_TABLE_COL_ENTRY( "Pubkey",       contact_info.pubkey,                                         live_table_col_pubkey_lt), \
  LIVE_TABLE_COL_ENTRY( "IP Addr",      contact_info.sockets[ FD_CONTACT_INFO_SOCKET_GOSSIP ].addr,  live_table_col_uint_lt  ), \
  LIVE_TABLE_COL_ENTRY( "Ingress Pull", diff.gossvf.bytes_rx[ FD_CRDS_OUTCOME_ROUTE_PULL_RESPONSE ], live_table_col_ulong_lt ), \
  LIVE_TABLE_COL_ENTRY( "Ingress Push", diff.gossvf.bytes_rx[ FD_CRDS_OUTCOME_ROUTE_PUSH ],          live_table_col_ulong_lt ), \
  LIVE_TABLE_COL_ENTRY( "Egress Pull",  diff.gossip.bytes_tx[ FD_CRDS_OUTCOME_ROUTE_PULL_RESPONSE ], live_table_col_ulong_lt ), \
  LIVE_TABLE_COL_ENTRY( "Egress Push",  diff.gossip.bytes_tx[ FD_CRDS_OUTCOME_ROUTE_PUSH ],          live_table_col_ulong_lt )  )
#define LIVE_TABLE_ROW_T fd_gui_peers_node_t
#include "fd_gui_live_table_tmpl.c"

struct fd_gui_peers_ws_conn_viewport {
  int connected;

  fd_gui_peers_live_table_sort_key_t sort_key;
  ulong start_row;
  ulong row_cnt;
  fd_gui_peers_node_t viewport[ FD_GUI_PEERS_WS_VIEWPORT_MAX_SZ ];
};
typedef struct fd_gui_peers_ws_conn_viewport fd_gui_peers_ws_conn_viewport_t;
struct fd_gui_peers_ctx {
  long last_sample_1000millis; /* ns timestamp */

  ulong contact_info_table_sz;
  fd_gui_peers_node_t contact_info_table[ FD_CONTACT_INFO_TABLE_SIZE ];
  fd_gui_peers_node_pubkey_map_t * node_pubkey_map;
  fd_gui_peers_node_sock_map_t  * node_sock_map;
  fd_gui_peers_live_table_t * live_table;

  fd_http_server_t * http;

  ulong max_ws_connection_cnt;
  fd_gui_peers_ws_conn_viewport_t * client_viewports; /* points to 2D array with max_ws_connection_cnt rows and FD_GUI_PEERS_WS_VIEWPORT_MAX_SZ columns */
};
typedef struct fd_gui_peers_ctx fd_gui_peers_ctx_t;

FD_PROTOTYPES_BEGIN

FD_FN_CONST ulong
fd_gui_peers_align( void );

FD_FN_CONST ulong
fd_gui_peers_footprint( ulong max_ws_connection_cnt );

void *
fd_gui_peers_new( void * shmem, fd_http_server_t * http, ulong max_ws_connection_cnt );

fd_gui_peers_ctx_t *
fd_gui_peers_join( void * shmem );

/* fd_gui_peers_handle_gossip_message_rx parses frags from the
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
   link and uses the contact info to build up the peer map. */
int
fd_gui_peers_handle_gossip_update( fd_gui_peers_ctx_t *               peers,
                                   fd_gossip_update_message_t const * update );

int
fd_gui_peers_ws_message( fd_gui_peers_ctx_t * peers,
                         ulong                ws_conn_id,
                         uchar const *        data,
                         ulong                data_len );

void
fd_gui_peers_ws_open( fd_gui_peers_ctx_t * peers, ulong ws_conn_id );

void
fd_gui_peers_ws_close( fd_gui_peers_ctx_t * peers, ulong ws_conn_id );

int
fd_gui_peers_poll( fd_gui_peers_ctx_t * peers  );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_disco_gui_fd_gui_peers_h */
