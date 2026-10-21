#ifndef HEADER_fd_src_choreo_tower_fd_tower_serdes_h
#define HEADER_fd_src_choreo_tower_fd_tower_serdes_h

/* fd_tower_serdes.h provides APIs for serializing and deserializing
   vote accounts and instructions. */

#include "../fd_choreo_base.h"
#include "../../ballet/txn/fd_txn.h"
#include "../../flamenco/runtime/program/vote/fd_vote_codec.h"

/* FD_VOTE_IX_KIND_* give vote program instruction discriminants (first
   four bytes of instruction data).  Older instruction types are ignored
   by tower. */

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

/* A buffer with capacity FD_VOTE_STATE_DATA_MAX can fit any valid vote
   account supported by tower (v2, v3, and v4). */

#define FD_VOTE_STATE_DATA_MAX (3762UL)

/* FD_VOTE_ACC_V* give vote account/state versions. */

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

struct __attribute__((packed)) fd_vote_acc_vote {
  uchar latency;
  ulong slot;
  uint  conf;
};
typedef struct fd_vote_acc_vote fd_vote_acc_vote_t;

struct __attribute__((packed)) fd_vote_acc_vote_v2 {
  ulong slot;
  uint  conf;
};
typedef struct fd_vote_acc_vote_v2 fd_vote_acc_vote_v2_t;

struct __attribute__((packed)) fd_vote_acc {
  uint kind;
  union __attribute__((packed)) {
    struct __attribute__((packed)) {
      fd_pubkey_t node_pubkey;
      fd_pubkey_t authorized_withdrawer;
      uchar       commission;
      ulong       votes_cnt;
      fd_vote_acc_vote_v2_t votes[31]; /* variable-length */
      /* uchar root_option */
      /* ulong root */
    } v2;

    struct __attribute__((packed)) {
      fd_pubkey_t        node_pubkey;
      fd_pubkey_t        authorized_withdrawer;
      uchar              commission;
      ulong              votes_cnt;
      fd_vote_acc_vote_t votes[31]; /* variable-length */
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
      /* fd_vote_acc_vote_t votes[31]; */
      /* uchar root_option */
      /* ulong root */
    } v4;
  };
};
typedef struct fd_vote_acc fd_vote_acc_t;

/* fd_vote_acc_desc is a lightweight vote account descriptor for zero-
   copy inspection of a vote account. */

struct fd_vote_acc_desc {
  int    kind;        /* FD_VOTE_ACC_* */
  ushort votes_off;   /* offset to vote array */
  uchar  vote_cnt;    /* number of votes (max FD_TOWER_VOTE_MAX) */
  uchar  vote_stride; /* byte stride between votes */
  ulong  root_slot;   /* ULONG_MAX if not set */
};
typedef struct fd_vote_acc_desc fd_vote_acc_desc_t;

FD_PROTOTYPES_BEGIN

/* fd_vote_acc_desc recovers offsets to vote account bits given
   serialized data.  Does minimal input validation.  Initializes *desc
   and returns desc on success, or NULL on failure (invalid or
   unsupported vote account data). */

fd_vote_acc_desc_t *
fd_vote_acc_desc( fd_vote_acc_desc_t * desc,
                  uchar const *        data,
                  ulong                data_sz );

/* fd_vote_acc_desc_vote returns a pointer to a vote in a serialized
   vote account.  The return type depends on desc->kind:
   - FD_VOTE_ACC_V2 -> fd_vote_acc_vote_v2_t
   - FD_VOTE_ACC_V3 -> fd_vote_acc_vote_t
   - FD_VOTE_ACC_V4 -> fd_vote_acc_vote_t */

FD_FN_PURE static inline void const *
fd_vote_acc_desc_vote( fd_vote_acc_desc_t const * desc,
                       uchar const *              data,
                       ulong                      idx ) {
  return data + desc->votes_off + idx*desc->vote_stride;
}

/* fd_txn_parse_simple_vote optionally extracts the decoded tower sync
   from a vote transaction. */

int
fd_txn_parse_simple_vote( fd_txn_t const *                txn,
                          uchar    const *                payload,
                          fd_compact_tower_sync_serde_t * opt_tower_sync );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_choreo_tower_fd_tower_serdes_h */
