#ifndef HEADER_fd_src_discof_geyser_fd_replay_notif_h
#define HEADER_fd_src_discof_geyser_fd_replay_notif_h

#include "../../funk/fd_funk.h"
#include "../../flamenco/types/fd_types.h"

/* Data structure which is passed through replay_notif link */

#define FD_REPLAY_SLOT_TYPE  0xD1239ACAU

struct __attribute__((aligned(64UL))) fd_replay_notif_msg {
  union {
    struct {
      ulong parent;
      ulong root;
      ulong slot;
      ulong height;
      fd_hash_t bank_hash;
      fd_hash_t block_hash;
      ulong transaction_count;
      ulong shred_cnt;
      ulong ts;
    } slot_exec;
  };
  uint type;
};
typedef struct fd_replay_notif_msg fd_replay_notif_msg_t;

#define FD_REPLAY_NOTIF_MTU sizeof(fd_replay_notif_msg_t)
#define FD_REPLAY_NOTIF_DEPTH 1024

#endif /* HEADER_fd_src_discof_geyser_fd_replay_notif_h */
