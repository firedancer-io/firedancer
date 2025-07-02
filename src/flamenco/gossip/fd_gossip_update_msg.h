#ifndef HEADER_fd_src_flamenco_gossip_fd_crds_value_h
#define HEADER_fd_src_flamenco_gossip_fd_crds_value_h

#include "../../util/fd_util.h"
#include "fd_contact_info.h"

#define FD_GOSSIP_UPDATE_TAG_CONTACT_INFO  (0)
#define FD_GOSSIP_UPDATE_TAG_VOTE          (1)
#define FD_GOSSIP_UPDATE_TAG_LOWEST_SLOT   (2)

/* Gossip messages encode wallclock in millis, while we
   parse them into nanoseconds for internal use. */
#define FD_NANOSEC_TO_MILLI(_ts_) ((long)(_ts_/1000000))
#define FD_MILLI_TO_NANOSEC(_ts_) ((long)(_ts_*1000000))

typedef fd_contact_info_t fd_gossip_upd_contact_info_t;

struct fd_gossip_upd_vote {
  ulong slot;
  uchar vote_tower_index;
  uchar txn[ 1232UL ];
};

typedef struct fd_gossip_upd_vote fd_gossip_upd_vote_t;

struct fd_gossip_upd_lowest_slot {
  ulong lowest_slot;
};

typedef struct fd_gossip_upd_lowest_slot fd_gossip_upd_lowest_slot_t;

struct fd_gossip_update_message {

  uchar tag;
  uchar origin_pubkey[ 32UL ];

  long  wallclock_nanos;

  union {
    fd_gossip_upd_contact_info_t  contact_info;
    fd_gossip_upd_vote_t          vote;
    fd_gossip_upd_lowest_slot_t   lowest_slot;
  };
};
typedef struct fd_gossip_update_message fd_gossip_update_message_t;
#endif /* HEADER_fd_src_flamenco_gossip_fd_crds_value_h */
