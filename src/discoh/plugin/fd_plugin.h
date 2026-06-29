#ifndef HEADER_fd_src_discoh_plugin_fd_plugin_h
#define HEADER_fd_src_discoh_plugin_fd_plugin_h

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
#define FD_PLUGIN_MSG_GENESIS_HASH_KNOWN            (13UL)

/* TODO: this needs to be bumped to 13, but that would break
   fd_gui_handle_gossip_update */
#define FD_GOSSIP_UPDATE_MSG_NUM_SOCKETS      (12U)
#define FD_GOSSIP_LINK_MSG_SIZE    (58U + FD_GOSSIP_UPDATE_MSG_NUM_SOCKETS * 6U)
#define FD_VALIDATOR_INFO_MSG_SIZE (          608U)

#endif /* HEADER_fd_src_discoh_plugin_fd_plugin_h */
