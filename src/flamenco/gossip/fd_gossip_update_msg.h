#ifndef HEADER_fd_src_flamenco_gossip_fd_crds_value_h
#define HEADER_fd_src_flamenco_gossip_fd_crds_value_h

#include "../../util/fd_util.h"
#include "fd_contact_info.h"
#include "crds/fd_crds.h"
#include "../../choreo/eqvoc/fd_eqvoc.h"

#define FD_GOSSIP_UPDATE_TAG_CONTACT_INFO        (0)
#define FD_GOSSIP_UPDATE_TAG_CONTACT_INFO_REMOVE (1)
#define FD_GOSSIP_UPDATE_TAG_LOWEST_SLOT         (2)
#define FD_GOSSIP_UPDATE_TAG_VOTE                (3)
#define FD_GOSSIP_UPDATE_TAG_DUPLICATE_SHRED     (4)
#define FD_GOSSIP_UPDATE_TAG_SNAPSHOT_HASHES     (5)

#define FD_CONTACT_INFO_TABLE_SIZE (CRDS_MAX_CONTACT_INFO)

struct fd_gossip_upd_vote {
  uchar vote_tower_index;
  ulong txn_sz;
  uchar txn[ 1232UL ];
};

typedef struct fd_gossip_upd_vote fd_gossip_upd_vote_t;

struct fd_gossip_upd_duplicate_shred {
  ushort index;
  ulong  slot;
  uchar  num_chunks;
  uchar  chunk_index;
  ulong  chunk_len;
  uchar  chunk[ FD_EQVOC_PROOF_CHUNK_SZ ];
};

typedef struct fd_gossip_upd_duplicate_shred fd_gossip_upd_duplicate_shred_t;

struct fd_gossip_snapshot_hash_pair {
  ulong slot;
  uchar hash[ 32UL ];
};
typedef struct fd_gossip_snapshot_hash_pair fd_gossip_snapshot_hash_pair_t;

struct fd_gossip_upd_snapshot_hashes {
  fd_gossip_snapshot_hash_pair_t full[1];
  ulong                          inc_len;
  /* Bound max inc entries by
      1188b (max CRDS encoded buffer size )
    - 64b (signature)
    - 4b  (tag)
    - 32b (pubkey)
    - 40b (full pair)
    - 8b  (inc len)
    - 8b  (wallclock)
    = 1032b

    1032b/40 ~= 25 */
  fd_gossip_snapshot_hash_pair_t inc[ 25UL ]; /* Incremental snapshot hashes */
};
typedef struct fd_gossip_upd_snapshot_hashes fd_gossip_upd_snapshot_hashes_t;

struct fd_gossip_update_message {
  uchar tag;
  uchar origin_pubkey[ 32UL ];
  ulong origin_stake;
  long  wallclock_nanos;

  union {
    struct {
      /* Holds CRDS contact info pool idx for quick indexing into
         downstream tables. */
      ulong             pool_idx;
      fd_contact_info_t contact_info[1];
    } contact_info;
    ulong                           rm_contact_info_pool_idx;
    ulong                           lowest_slot;
    fd_gossip_upd_vote_t            vote;
    fd_gossip_upd_duplicate_shred_t duplicate_shred;
    fd_gossip_upd_snapshot_hashes_t snapshot_hashes;
  };
};
typedef struct fd_gossip_update_message fd_gossip_update_message_t;

#define FD_GOSSIP_UPDATE_SZ_CONTACT_INFO        (offsetof(fd_gossip_update_message_t, contact_info) + sizeof(fd_contact_info_t) + sizeof(ulong))
#define FD_GOSSIP_UPDATE_SZ_CONTACT_INFO_REMOVE (offsetof(fd_gossip_update_message_t, contact_info) + sizeof(ulong))
#define FD_GOSSIP_UPDATE_SZ_LOWEST_SLOT         (offsetof(fd_gossip_update_message_t, lowest_slot)  + sizeof(ulong))
#define FD_GOSSIP_UPDATE_SZ_VOTE                (offsetof(fd_gossip_update_message_t, vote)         + sizeof(fd_gossip_upd_vote_t))
#define FD_GOSSIP_UPDATE_SZ_DUPLICATE_SHRED     (offsetof(fd_gossip_update_message_t, duplicate_shred) + sizeof(fd_gossip_upd_duplicate_shred_t))
#define FD_GOSSIP_UPDATE_SZ_SNAPSHOT_HASHES     (offsetof(fd_gossip_update_message_t, snapshot_hashes) + sizeof(fd_gossip_upd_snapshot_hashes_t))


FD_PROTOTYPES_BEGIN

FD_FN_CONST static inline ulong
fd_gossip_update_message_sig( uchar tag ){
  return (ulong)(tag & 0x7U);
}

FD_FN_CONST static inline uchar
fd_gossip_update_message_sig_tag( ulong sig ){
  return (sig & 0x7U);
}

FD_PROTOTYPES_END
#endif /* HEADER_fd_src_flamenco_gossip_fd_crds_value_h */
