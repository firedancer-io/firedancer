#ifndef HEADER_fd_src_choreo_tower_fd_tower_serde_h
#define HEADER_fd_src_choreo_tower_fd_tower_serde_h

#include "../fd_choreo_base.h"
#include "../voter/fd_voter.h"

#define FD_TOWER_SYNC_SERDE_KIND        (14)
#define FD_TOWER_SYNC_SWITCH_SERDE_KIND (15)
#define FD_TOWER_SYNC_SERDE_MAX         (148UL) /* max bincode-serialized sz of fd_tower_sync_serde_t */

/* fd_tower_sync_serde describes the serialization / deserialization
   schema for a tower when it is encoded inside a vote instruction.
   There are various legacy encodings for vote transactions, but this
   corresponds with the bincode layout of `TowerSync` in Agave. */

struct fd_tower_sync_serde /* CompactTowerSync */ {
  ulong root;
  struct /* ShortVec */ {
    ushort lockouts_cnt; /* ShortU16 */
    struct /* Lockout */ {
      ulong offset; /* VarInt */
      uchar confirmation_count;
    } lockouts[31];
  };
  fd_hash_t hash; /* bank hash */
  struct /* Option<UnixTimestamp> */ {
    uchar timestamp_option;
    long  timestamp; /* UnixTimestamp */
  };
  fd_hash_t block_id;
};
typedef struct fd_tower_sync_serde fd_tower_sync_serde_t;

/* fd_tower_acc_v2_serde defines a serialization / deserialization
   schema for a tower when it is encoded inside a vote account.  This is
   the v3 version of the format and corresponds with the bincode layout
   of `VoteState1_14_11` in Agave. */

struct fd_tower_acc_v2_serde {
  fd_pubkey_t node_pubkey;
  fd_pubkey_t authorized_withdrawer;
  uchar       commission;

  struct /* VecDeque<Lockout> */ {
    ulong votes_cnt;
    struct {
      ulong slot;
      uint  confirmation_count;
    } votes[31]; /* idx >= votes_cnt are invalid */
  };

  struct /* Option<Slot> */ {
    uchar root_slot_option;
    ulong root_slot;
  };

  struct /* AuthorizedVoters */ {
    ulong const authorized_voters_cnt;
    struct {
      ulong       epoch;
      fd_pubkey_t pubkey;
    } authorized_voters[32]; /* idx >= authorized_voters_cnt are invalid */
  };

  struct /* CircBuf<Pubkey, Epoch, Epoch> */ {
    struct {
      fd_pubkey_t pubkey;
      ulong       start_epoch;
      ulong       end_epoch;
    } buf[32];
    ulong idx;
    uchar is_empty;
  } prior_voters;

  struct /* Vec<Epoch, u64, u64> */ {
    ulong epoch_credits_cnt;
    struct {
      ulong epoch;
      ulong credits;
      ulong prev_credits;
    } epoch_credits[32]; /* idx >= epoch_credits_cnt are invalid */
  };

  struct /* BlockTimestamp */ {
    ulong slot;
    long  timestamp;
  } last_timestamp;
};
typedef struct fd_tower_acc_v2_serde fd_tower_acc_v2_serde_t;

/* fd_tower_acc_v3_serde defines a serialization / deserialization
   schema for a tower when it is encoded inside a vote account.  This is
   the v3 version of the format and corresponds with the bincode layout
   of `VoteState` in Agave. */

struct fd_tower_acc_v3_serde {
  fd_pubkey_t node_pubkey;
  fd_pubkey_t authorized_withdrawer;
  uchar       commission;

  struct /* VecDeque<LandedVote> */ {
    ulong votes_cnt;
    struct {
      uchar latency;
      ulong slot;
      uint  confirmation_count;
    } votes[31]; /* idx >= votes_cnt are invalid */
  };

  struct /* Option<Slot> */ {
    uchar root_slot_option;
    ulong root_slot;
  };

  struct /* AuthorizedVoters */ {
    ulong const authorized_voters_cnt;
    struct {
      ulong       epoch;
      fd_pubkey_t pubkey;
    } authorized_voters[32]; /* idx >= authorized_voters_cnt are invalid */
  };

  struct /* CircBuf<Pubkey, Epoch, Epoch> */ {
    struct {
      fd_pubkey_t pubkey;
      ulong       start_epoch;
      ulong       end_epoch;
    } buf[32];
    ulong idx;
    uchar is_empty;
  } prior_voters;

  struct /* Vec<Epoch, u64, u64> */ {
    ulong epoch_credits_cnt;
    struct {
      ulong epoch;
      ulong credits;
      ulong prev_credits;
    } epoch_credits[32]; /* idx >= epoch_credits_cnt are invalid */
  };

  struct /* BlockTimestamp */ {
    ulong slot;
    long  timestamp;
  } last_timestamp;
};
typedef struct fd_tower_acc_v3_serde fd_tower_acc_v3_serde_t;

/* fd_tower_file_serde describes a serialization / deserialization
   schema for a tower when it is used for checkpointing / restoring from
   a file.  The tower file is used during boot, set-identity and voting,
   and corresponds with the bincode layout of `SavedTower` in Agave. */

struct fd_tower_file_serde /* SavedTowerVersions::Current */ {
  uint const *             kind;
  fd_ed25519_sig_t const * signature;
  ulong const *            data_sz; /* serialized sz of data field below */
  struct /* Tower1_14_11 */ {
    fd_pubkey_t const * node_pubkey;
    ulong const *       threshold_depth;
    double const *      threshold_size;
    fd_voter_v2_serde_t vote_state;
    struct {
      uint const *          last_vote_kind;
      fd_tower_sync_serde_t last_vote;
    };
    struct /* BlockTimestamp */ {
      ulong const * slot;
      long const *  timestamp;
    } last_timestamp;
  } /* data */;
};
typedef struct fd_tower_file_serde fd_tower_file_serde_t;

int
fd_tower_sync_serialize( fd_tower_sync_serde_t * serde,
                         uchar *                 buf,
                         ulong                   buf_max,
                         ulong *                 buf_sz );

int
fd_tower_sync_deserialize( fd_tower_sync_serde_t * serde,
                           uchar const *           buf,
                           ulong                   buf_sz );

#endif /* HEADER_fd_src_choreo_tower_fd_tower_serde_h */
