#ifndef HEADER_fd_src_choreo_tower_fd_tower_serdes_h
#define HEADER_fd_src_choreo_tower_fd_tower_serdes_h

#include "../fd_choreo_base.h"
#include "../../ballet/txn/fd_txn.h"

#define FD_VOTE_IX_KIND_TOWER_SYNC        (14)
#define FD_VOTE_IX_KIND_TOWER_SYNC_SWITCH (15)

/* fd_compact_tower_sync_serde describes the serialization /
   deserialization schema of a CompactTowerSync vote instruction.  There
   are various legacy instructions for vote transactions, but current
   mainnet votes are almost exclusively this instruction. */

struct fd_compact_tower_sync_serde { /* CompactTowerSync */
  ulong root;                        /* u64              */
  struct {
    ushort lockouts_cnt;             /* ShortU16         */
    struct {
      ulong offset;                  /* VarInt           */
      uchar confirmation_count;      /* u8               */
    } lockouts[31];
  };
  fd_hash_t hash;                    /* [u8; 32]         */
  struct {
    uchar timestamp_option;          /* Option           */
    long  timestamp;                 /* UnixTimestamp    */
  };
  fd_hash_t block_id;                /* [u8; 32]         */
};
typedef struct fd_compact_tower_sync_serde fd_compact_tower_sync_serde_t;

/* fd_compact_tower_sync_ser serializes fd_compact_tower_sync_serde_t
   into a buffer.  Returns 0 on success, -1 if the lockouts_cnt is
   greater than FD_TOWER_VOTE_MAX or buf_max is too small to fit the
   serialized data.  On success, sets *buf_sz to the number of bytes
   written if buf_sz is non-NULL. */

int
fd_compact_tower_sync_ser( fd_compact_tower_sync_serde_t const * serde,
                           uchar *                               buf,
                           ulong                                 buf_max,
                           ulong *                               buf_sz );

/* fd_compact_tower_sync_de deserializes at most buf_sz of buf into
   fd_compact_tower_sync_serde_t.  Designed to deserialize untrusted
   inputs (gossip / TPU vote txns).  Assumes buf is at least of size
   buf_sz.  Returns 0 on success, -1 on deserialization failure.  Note:
   the return value only indicates whether the wire format was valid,
   not whether the resulting tower is semantically valid (e.g. slots
   and confirmations are monotonically increasing).  Callers must
   validate the deserialized tower contents separately. */

int
fd_compact_tower_sync_de( fd_compact_tower_sync_serde_t * serde,
                          uchar const *                   buf,
                          ulong                           buf_sz );

#define FD_VOTE_STATE_DATA_MAX 3762UL

#define FD_VOTE_ACC_V2 (1)
#define FD_VOTE_ACC_V3 (2)
#define FD_VOTE_ACC_V4 (3)
FD_STATIC_ASSERT( FD_VOTE_ACC_V2==fd_vote_state_versioned_enum_v1_14_11, FD_VOTE_ACC_V2 );
FD_STATIC_ASSERT( FD_VOTE_ACC_V3==fd_vote_state_versioned_enum_v3,       FD_VOTE_ACC_V3 );
FD_STATIC_ASSERT( FD_VOTE_ACC_V4==fd_vote_state_versioned_enum_v4,       FD_VOTE_ACC_V4 );

/* fd_vote_acc describes the layout of a vote state stored in a vote
   account.  These structs are used to support zero-copy access (direct
   casts) of byte arrays containing the vote account data.

   fd_vote_acc is versioned, and the serialized formats differ depending
   on this.  They correspond to Agave's VoteState1_14_11, VoteStateV3,
   and VoteStateV4 structs.

   VoteState1_14_11 corresponds to FD_VOTE_ACC_V2, VoteStateV3
   corresponds to FD_VOTE_ACC_V3, and VoteStateV4 corresponds to
   FD_VOTE_ACC_V4.  V2 and V3 differ only in that V3 votes contain an
   additional uchar field `latency`.  V4 has a different header layout
   with additional fields (inflation_rewards_collector,
   block_revenue_collector, commission in bps, pending_delegator_rewards,
   and bls_pubkey_compressed).

   The binary layout begins with metadata in the vote account, followed
   by the voter's votes (tower), root, and authorized voters. */

struct __attribute__((packed)) fd_vote_acc_vote {
  uchar latency;
  ulong slot;
  uint  conf;
};
typedef struct fd_vote_acc_vote fd_vote_acc_vote_t;

struct __attribute__((packed)) fd_vote_acc_auth_voter {
  ulong       epoch;
  fd_pubkey_t pubkey;
};
typedef struct fd_vote_acc_auth_voter fd_vote_acc_auth_voter_t;

#define FD_VOTE_ACC_AUTH_VOTERS_MAX (4UL)

struct __attribute__((packed)) fd_vote_acc {
  uint kind;
  union __attribute__((packed)) {
    struct __attribute__((packed)) {
      fd_pubkey_t node_pubkey;
      fd_pubkey_t authorized_withdrawer;
      uchar       commission;
      ulong       votes_cnt;
      struct __attribute__((packed)) {
        ulong slot;
        uint  conf;
      } votes[31]; /* variable-length */
      // no longer directly accessible after this point
      uchar root_option;
      ulong root;
      ulong authorized_voters_cnt;
      fd_vote_acc_auth_voter_t authorized_voters[FD_VOTE_ACC_AUTH_VOTERS_MAX]; /* BTreeMap<Epoch, Pubkey> */
      /* prior_voters */
      /* epoch_credits */
      /* last_timestamp */
    } v2; /* VoteState1_14_11 */

    struct __attribute__((packed)) {
      fd_pubkey_t        node_pubkey;
      fd_pubkey_t        authorized_withdrawer;
      uchar              commission;
      ulong              votes_cnt;
      fd_vote_acc_vote_t votes[31]; /* variable-length */
      // no longer directly accessible after this point
      uchar root_option;
      ulong root;
      ulong authorized_voters_cnt;
      fd_vote_acc_auth_voter_t authorized_voters[FD_VOTE_ACC_AUTH_VOTERS_MAX]; /* BTreeMap<Epoch, Pubkey> */
      /* prior_voters */
      /* epoch_credits */
      /* last_timestamp */
    } v3;

    struct __attribute__((packed)) {
      fd_pubkey_t     node_pubkey;                      /* Pubkey */
      fd_pubkey_t     authorized_withdrawer;            /* Pubkey */
      fd_pubkey_t     inflation_rewards_collector;      /* Pubkey */
      fd_pubkey_t     block_revenue_collector;          /* Pubkey */
      ushort          inflation_rewards_commission_bps; /* u16 */
      ushort          block_revenue_commission_bps;     /* u16 */
      ulong           pending_delegator_rewards;        /* u64 */
      uchar           has_bls_pubkey_compressed;        /* u8 */
      uchar           bls_pubkey_compressed[48];        /* [u8; 48] */
      ulong           votes_cnt;
      fd_vote_acc_vote_t votes[31];                     /* VecDeque<LandedVote> */
      uchar root_option;
      ulong root;
      ulong authorized_voters_cnt;
      fd_vote_acc_auth_voter_t authorized_voters[FD_VOTE_ACC_AUTH_VOTERS_MAX]; /* BTreeMap<Epoch, Pubkey> */
      /* epoch_credits */
      /* last_timestamp */
    } v4;
  };
};
typedef struct fd_vote_acc fd_vote_acc_t;

/* fd_vote_acc_ser serializes fd_vote_acc_serde_t into buf.  Returns 0
   on success, -1 on error (e.g. buf_max too small). */

int
fd_vote_acc_ser( fd_vote_acc_t const * serde,
                 uchar *               buf,
                 ulong                 buf_max,
                 ulong *               buf_sz );

/* fd_vote_acc_de deserializes at most buf_sz bytes of buf into
   fd_vote_acc_serde_t.  Returns 0 on success, -1 on error. */

int
fd_vote_acc_de( fd_vote_acc_t * serde,
                uchar const *   buf,
                ulong           buf_sz );

FD_FN_PURE ulong
fd_vote_acc_vote_cnt( uchar const * buf );

/* fd_vote_acc_vote_slot takes a voter's vote account data and returns
   the voter's most recent vote slot in the tower.  Returns ULONG_MAX if
   they have an empty tower. */

FD_FN_PURE ulong
fd_vote_acc_vote_slot( uchar const * buf );

/* fd_vote_acc_root_slot takes a voter's vote account data and returns
   the voter's root slot.  Returns ULONG_MAX if they don't have one. */

FD_FN_PURE ulong
fd_vote_acc_root_slot( uchar const * buf );

/* fd_txn_parse_simple_vote optionally extracts the vote account pubkey,
   identity pubkey, and largest voted-for slot from a vote transaction. */

int
fd_txn_parse_simple_vote( fd_txn_t const * txn,
                          uchar    const * payload,
                          fd_pubkey_t *    opt_identity,
                          fd_pubkey_t *    opt_vote_acct,
                          ulong *          opt_vote_slot );

FD_FN_PURE ulong
fd_vote_acc_authorized_voters_cnt( fd_vote_acc_t const * vote_acc );

FD_FN_PURE fd_vote_acc_auth_voter_t const *
fd_vote_acc_authorized_voters( fd_vote_acc_t const * vote_acc );



#endif /* HEADER_fd_src_choreo_tower_fd_tower_serdes_h */
