#ifndef HEADER_fd_src_choreo_tower_fd_tower_serde_h
#define HEADER_fd_src_choreo_tower_fd_tower_serde_h

#include "../fd_choreo_base.h"
#include "../../ballet/txn/fd_txn.h"
#include "../../flamenco/runtime/program/vote/fd_vote_codec.h"
#include "fd_tower.h"

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

#define FD_VOTE_ACC_V2 (1)
#define FD_VOTE_ACC_V3 (2)
#define FD_VOTE_ACC_V4 (3)
FD_STATIC_ASSERT( FD_VOTE_ACC_V2==fd_vote_state_versioned_enum_v1_14_11, FD_VOTE_ACC_V2 );
FD_STATIC_ASSERT( FD_VOTE_ACC_V3==fd_vote_state_versioned_enum_v3,       FD_VOTE_ACC_V3 );
FD_STATIC_ASSERT( FD_VOTE_ACC_V4==fd_vote_state_versioned_enum_v4,       FD_VOTE_ACC_V4 );

/* fd_vote_acc describes the layout of a vote state stored in a vote
   account.  The vote_acc_{...} deserializers assume trusted input
   (account data written to by the vote program).  These structs are
   used to support zero-copy access (direct casts) of byte arrays
   containing the vote account data.

   fd_vote_acc is versioned, and the serialized formats differ depending
   on this.  They correspond to Agave's VoteState0_23_5,
   VoteState1_14_11 and VoteState structs.

   VoteStatev0_23_5 is deprecated and there are no longer vote accounts
   of that version on testnet / mainnet.  VoteState1_14_11 corresponds
   to FD_VOTE_ACC_V2 and VoteState corresponds to FD_VOTE_ACC_V3.  The
   only difference between the two is the votes in V3 contain an
   additional uchar field `latency`.

   The binary layout begins with metadata in the vote account, followed
   by the voter's votes (tower), and terminates with the root. */

struct __attribute__((packed)) fd_lat_vote {
  uchar latency;
  ulong slot;
  uint  conf;
};
typedef struct fd_lat_vote fd_lat_vote_t;

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
      /* uchar root_option */
      /* ulong root */
    } v2;

    struct __attribute__((packed)) {
      fd_pubkey_t        node_pubkey;
      fd_pubkey_t        authorized_withdrawer;
      uchar              commission;
      ulong              votes_cnt;
      fd_lat_vote_t    votes[31]; /* variable-length */
      /* uchar root_option */
      /* ulong root */
    } v3;

    struct __attribute__((packed)) {
      fd_pubkey_t     node_pubkey;
      fd_pubkey_t     authorized_withdrawer;
      fd_pubkey_t     inflation_rewards_collector;
      fd_pubkey_t     block_revenue_collector;
      ushort          inflation_rewards_commission_bps;
      ushort          block_revenue_commission_bps;
      ulong           pending_delegator_rewards;
      uchar           has_bls_pubkey_compressed;
      uchar           bls_pubkey_compressed[48];
      /* ulong              votes_cnt; */
      /* fd_lat_vote_t votes[31]; */
      /* uchar root_option */
      /* ulong root */
    } v4;
  };
};
typedef struct fd_vote_acc fd_vote_acc_t;

ulong
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

/* fd_tower_from_vote_acc deserializes the vote account into a votes
   deque and extracts the root.  Assumes votes is a valid joined deque
   and currently empty.  On return *root is the tower root slot, or
   ULONG_MAX if the vote account has no root. */

void
fd_tower_from_vote_acc( fd_tower_vote_t * votes,
                        ulong           * root,
                        uchar const     * vote_acc );

/* fd_tower_with_lat_from_vote_acc deserializes the vote account into
   tower, including slot latency (when available) for tower votes.
   Assumes tower points to a static array of length FD_TOWER_VOTE_MAX.

   Returns the number of copied elements. */

ulong
fd_tower_with_lat_from_vote_acc( fd_lat_vote_t tower[ static FD_TOWER_VOTE_MAX ],
                                 uchar const * vote_acc );

/* fd_tower_to_vote_txn writes tower into a fd_tower_sync_t vote
   instruction and serializes it into a Solana transaction.  Assumes
   tower is a valid local join. */

void
fd_tower_to_vote_txn( fd_tower_t    const * tower,
                      fd_hash_t     const * bank_hash,
                      fd_hash_t     const * block_id,
                      fd_hash_t     const * recent_blockhash,
                      fd_pubkey_t   const * validator_identity,
                      fd_pubkey_t   const * vote_authority,
                      fd_pubkey_t   const * vote_account,
                      fd_txn_p_t          * vote_txn );

/* fd_tower_to_cstr pretty-prints tower as a formatted table to the
   buffer cstr.  Assumes cstr is a buffer of at least FD_TOWER_CSTR_MIN
   capacity.

   Sample output:

        slot | confirmation count
   --------- | ------------------
   279803931 | 1
   279803930 | 2
   ...
   279803901 | 31
   279803900 | root
*/

#define FD_TOWER_CSTR_MIN (917UL)

char *
fd_tower_to_cstr( fd_tower_vote_t * votes,
                  ulong             root,
                  char *            cstr );

#endif /* HEADER_fd_src_choreo_tower_fd_tower_serde_h */
