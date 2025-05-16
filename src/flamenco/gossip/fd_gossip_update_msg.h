#ifndef HEADER_fd_src_flamenco_gossip_fd_crds_value_h
#define HEADER_fd_src_flamenco_gossip_fd_crds_value_h

#include "../../util/fd_util.h"
#include "fd_contact_info.h"
#include "crds/fd_crds.h"

#define FD_GOSSIP_UPDATE_TAG_CONTACT_INFO        (0)
#define FD_GOSSIP_UPDATE_TAG_CONTACT_INFO_REMOVE (1)
#define FD_GOSSIP_UPDATE_TAG_LOWEST_SLOT         (2)
#define FD_GOSSIP_UPDATE_TAG_VOTE (3)

/* TODO: API for maintaining a contact info table based on
   fd_gossip_update_msg_t */
#define FD_CONTACT_INFO_TABLE_SIZE (CRDS_MAX_CONTACT_INFO)

typedef fd_contact_info_t fd_gossip_upd_contact_info_t;

struct fd_gossip_upd_vote {
  uchar vote_tower_index;
  ulong txn_sz;
  uchar txn[ 1232UL ];
};

typedef struct fd_gossip_upd_vote fd_gossip_upd_vote_t;

struct fd_gossip_update_message {

  uchar tag;
  uchar origin_pubkey[ 32UL ];
  ulong origin_stake;
  long  wallclock_nanos;

  union {
    fd_contact_info_t    contact_info;
    fd_gossip_upd_vote_t vote;
    ulong                lowest_slot;
  };
};
typedef struct fd_gossip_update_message fd_gossip_update_message_t;

#define FD_GOSSIP_UPDATE_SZ_CONTACT_INFO        (offsetof(fd_gossip_update_message_t, contact_info) + sizeof(fd_gossip_upd_contact_info_t))
#define FD_GOSSIP_UPDATE_SZ_CONTACT_INFO_REMOVE (offsetof(fd_gossip_update_message_t, contact_info))
#define FD_GOSSIP_UPDATE_SZ_VOTE                (offsetof(fd_gossip_update_message_t, vote)         + sizeof(fd_gossip_upd_vote_t))
#define FD_GOSSIP_UPDATE_SZ_LOWEST_SLOT         (offsetof(fd_gossip_update_message_t, lowest_slot)  + sizeof(ulong))


FD_PROTOTYPES_BEGIN

FD_FN_CONST static inline ulong
fd_gossip_update_message_sig( uchar tag ){
  return (ulong)(tag & 0x3U);
}

FD_FN_CONST static inline uchar
fd_gossip_update_message_sig_tag( ulong sig ){
  return (sig & 0x3U);
}

FD_PROTOTYPES_END
#endif /* HEADER_fd_src_flamenco_gossip_fd_crds_value_h */
