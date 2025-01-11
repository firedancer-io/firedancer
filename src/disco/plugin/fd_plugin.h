#ifndef HEADER_fd_src_disco_plugin_fd_plugin_h
#define HEADER_fd_src_disco_plugin_fd_plugin_h

#define FD_PLUGIN_MSG_SLOT_ROOTED                   ( 0UL)
#define FD_PLUGIN_MSG_SLOT_OPTIMISTICALLY_CONFIRMED ( 1UL)
#define FD_PLUGIN_MSG_SLOT_COMPLETED                ( 2UL)
#define FD_PLUGIN_MSG_SLOT_ESTIMATED                ( 3UL)
#define FD_PLUGIN_MSG_GOSSIP_UPDATE                 ( 4UL)
#define FD_PLUGIN_MSG_VOTE_ACCOUNT_UPDATE           ( 5UL)
#define FD_PLUGIN_MSG_LEADER_SCHEDULE               ( 6UL)
#define FD_PLUGIN_MSG_VALIDATOR_INFO                ( 7UL)
#define FD_PLUGIN_MSG_SLOT_START                    ( 8UL)

typedef struct {
  ulong slot;
  ulong parent_slot;
} fd_plugin_msg_slot_start_t;

#define FD_PLUGIN_MSG_SLOT_END                      ( 9UL)

typedef struct {
  ulong slot;
  ulong cus_used;
} fd_plugin_msg_slot_end_t;

#define FD_PLUGIN_MSG_SLOT_RESET                    (10UL)
#define FD_PLUGIN_MSG_BALANCE                       (11UL)
#define FD_PLUGIN_MSG_START_PROGRESS                (12UL)

struct __attribute__((packed, aligned(8))) fd_replay_complete_msg {
  ulong slot;
  ulong total_txn_count;
  ulong nonvote_txn_count;
  ulong failed_txn_count;
  ulong nonvote_failed_txn_count;
  ulong compute_units;
  ulong transaction_fee;
  ulong priority_fee;
  ulong parent_slot;
};
typedef struct fd_replay_complete_msg fd_replay_complete_msg_t;

#define FD_CLUSTER_NODE_CNT     (200U*201U - 1U)
#define FD_GOSSIP_LINK_MSG_SIZE (58U + 12U * 6U)

struct __attribute__((packed)) fd_gossip_update_msg {
  uchar  pubkey[32];			// 0..31
  ulong  wallclock; 			// 32..39
  ushort shred_version;			// 40..41
  uchar  version_type;			// 42
  ushort version_major;			// 43..44
  ushort version_minor;			// 45..46
  ushort version_patch;			// 47..48
  uchar  version_commit_type;		// 49
  uint   version_commit;		// 50..53
  uint   version_feature_set;		// 54..57
    /* gossip_socket,
       rpc_socket,
       rpc_pubsub_socket,
       serve_repair_socket_udp,
       serve_repair_socket_quic,
       tpu_socket_udp,
       tpu_socket_quic,
       tvu_socket_udp,
       tvu_socket_quic,
       tpu_forwards_socket_udp,
       tpu_forwards_socket_quic,
       tpu_vote_socket, */
  struct __attribute__((packed)) {
    uint ip;				// 0..3
    ushort port;			// 4..5
  } addrs[12];
};
typedef struct fd_gossip_update_msg fd_gossip_update_msg_t;

FD_STATIC_ASSERT( sizeof(fd_gossip_update_msg_t) == FD_GOSSIP_LINK_MSG_SIZE, fd_gossip_update_msg );

struct __attribute__((packed)) fd_vote_update_msg {
  uchar vote_pubkey[32];	// 0..31
  uchar node_pubkey[32];	// 32..63
  ulong activated_stake;	// 64..71
  ulong last_vote;		// 72..79
  ulong root_slot;		// 80..87
  ulong epoch_credits;		// 88..95
  uchar commission;		// 96
  uchar is_delinquent;		// 97
};
typedef struct fd_vote_update_msg fd_vote_update_msg_t;

FD_STATIC_ASSERT( sizeof(fd_vote_update_msg_t) <= FD_GOSSIP_LINK_MSG_SIZE, fd_vote_update_msg );

#define FD_PLUGIN_MSG_BLOCK_ENGINE_UPDATE           (13UL)

#define FD_PLUGIN_MSG_BLOCK_ENGINE_UPDATE_STATUS_DISCONNECTED (0)
#define FD_PLUGIN_MSG_BLOCK_ENGINE_UPDATE_STATUS_CONNECTING   (1)
#define FD_PLUGIN_MSG_BLOCK_ENGINE_UPDATE_STATUS_CONNECTED    (2)

typedef struct {
  char name[ 16 ];
  char url[ 256 ];
  int status;
} fd_plugin_msg_block_engine_update_t;

#endif /* HEADER_fd_src_disco_plugin_fd_plugin_h */
