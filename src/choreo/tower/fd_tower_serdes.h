#ifndef HEADER_fd_src_choreo_tower_fd_tower_serdes_h
#define HEADER_fd_src_choreo_tower_fd_tower_serdes_h

/* fd_tower_serdes.h provides APIs for serializing and deserializing
   vote accounts and instructions. */

#include "../fd_choreo_base.h"
#include "../../ballet/txn/fd_txn.h"

#define FD_TOWER_LOCKOS_MAX 31UL
#define FD_TOWER_VOTE_MAX (FD_TOWER_LOCKOS_MAX)

struct fd_tower_vote;
typedef struct fd_tower_vote fd_tower_vote_t;

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

FD_PROTOTYPES_BEGIN

/* fd_txn_parse_simple_vote optionally extracts the decoded tower sync
   from a vote transaction. */

int
fd_txn_parse_simple_vote( fd_txn_t const *                txn,
                          uchar    const *                payload,
                          fd_compact_tower_sync_serde_t * opt_tower_sync );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_choreo_tower_fd_tower_serdes_h */
