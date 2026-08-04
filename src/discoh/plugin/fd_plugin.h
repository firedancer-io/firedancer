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

/* One consensus summary, replacing SLOT_ROOTED, SLOT_RESET and
   SLOT_OPTIMISTICALLY_CONFIRMED once alpenglow is running.  Those three
   are produced only by TowerBFT code paths -- the voting path, the
   reset-bank path and the gossip vote listener -- none of which execute
   under alpenglow, so without this the gui's slot progress stops at
   COMPLETED.

   Deliberately shaped as the gui-relevant subset of Firedancer's
   fd_tower_slot_done_t (src/discof/tower/fd_tower_tile.h), which is
   what its tower tile already sends its own gui, rather than as an
   extension of the plugin messages above.  That struct is already
   consensus-mechanism-neutral and already carries block ids, which
   alpenglow needs and the older messages have nowhere to put.  When
   Firedancer's consensus side learns alpenglow it can fill the same
   fields and reuse its existing handler; the Frankendancer half here is
   then the part that gets thrown away.

   finalized_* has no counterpart in fd_tower_slot_done_t because
   TowerBFT has no finalization: it is the one genuinely new thing
   alpenglow provides.

   ULONG_MAX means "not known" for any slot field.  Laid out so the
   Rust side can write it as a flat byte image with no padding. */

#define FD_PLUGIN_MSG_CONSENSUS_UPDATE              (14UL)

typedef struct {
  /* The consensus fork to build on, and the slot we most recently voted
     for.  From alpenglow's highest ParentReady and vote history. */
  ulong reset_slot;
  ulong vote_slot;

  /* The new root, when one was just set, else ULONG_MAX. */
  ulong root_slot;

  /* The highest block covered by a finalization certificate, and
     whether that certificate was the fast (one round, 80%) kind. */
  ulong finalized_slot;
  ulong finalized_fast;

  ulong active_fork_cnt;
  ulong is_voting;

  uchar reset_block_id    [ 32 ];
  uchar root_block_id     [ 32 ];
  uchar finalized_block_id[ 32 ];

  /* Ancestors of reset_slot, and how many.  A slot is marked skipped
     exactly when it is not the next entry walking back from the head,
     so without this the skip rate can only ever read zero.

     parents[0] is reset_slot itself and the ancestors follow, highest
     first, which is the shape the walk expects -- the same one the
     legacy reset message uses, where the head sits at the base of the
     array.

     parent_cnt counts EVERY entry, the head included, because the walk
     treats it as a budget: it stops after matching that many entries.
     The legacy producer counts only the ancestors, so its walk always
     stops one short -- harmless there because TowerBFT's chain is long,
     but fatal under alpenglow where this array is often just
     [head, root] and stopping one short means never getting past the
     head to see a skipped window at all. */
  ulong parent_cnt;
  ulong parents[];
} fd_plugin_msg_consensus_update_t;

/* 152: everything up to and including finalized_block_id.  Spelled out
   because the flexible array member makes sizeof() unhelpful. */
#define FD_PLUGIN_CONSENSUS_UPDATE_HDR_SZ (152UL)

/* Bounded so the message cannot exceed the replay_plugi mtu (4098*8).
   The producer truncates rather than failing: a short chain degrades the
   skip display, a dropped message loses everything. */
#define FD_PLUGIN_CONSENSUS_UPDATE_PARENTS_MAX (4000UL)

/* TODO: this needs to be bumped to 13, but that would break
   fd_gui_handle_gossip_update */
#define FD_GOSSIP_UPDATE_MSG_NUM_SOCKETS      (12U)
#define FD_GOSSIP_LINK_MSG_SIZE    (60U + FD_GOSSIP_UPDATE_MSG_NUM_SOCKETS * 6U)
#define FD_VALIDATOR_INFO_MSG_SIZE (          608U)

#endif /* HEADER_fd_src_discoh_plugin_fd_plugin_h */
