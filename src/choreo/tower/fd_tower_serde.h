#ifndef HEADER_fd_src_choreo_tower_fd_tower_serde_h
#define HEADER_fd_src_choreo_tower_fd_tower_serde_h

#include "../fd_choreo_base.h"
#include "../voter/fd_voter_serde.h"

#define FD_VOTE_IX_KIND_TOWER_SYNC        (14)
#define FD_VOTE_IX_KIND_TOWER_SYNC_SWITCH (15)

/* fd_compact_tower_sync_serde describes the serialization /
   deserialization schema of a CompactTowerSync vote instruction.  There
   are various legacy instructions for vote transactions, but current
   mainnet votes are almost exclusively this instruction. */

struct fd_compact_tower_sync_serde /* CompactTowerSync */ {
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
typedef struct fd_compact_tower_sync_serde fd_compact_tower_sync_serde_t;

int
fd_compact_tower_sync_deserialize( fd_compact_tower_sync_serde_t * serde,
                                   uchar const *                   buf,
                                   ulong                           buf_sz );

#endif /* HEADER_fd_src_choreo_tower_fd_tower_serde_h */
