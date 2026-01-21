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

/* fd_compact_tower_sync_serialize serializes a
   fd_compact_tower_sync_serde_t into a buffer. Returns 0 on success, -1
   on failure.  The only failure case is if the lockouts_cnt is greater
   than FD_TOWER_VOTE_MAX, or if the buffer is too small to fit the
   serialized data. */
int
fd_compact_tower_sync_serialize( fd_compact_tower_sync_serde_t const * serde,
                                 uchar *                               buf,
                                 ulong                                 buf_sz,
                                 ulong *                               out_sz );

#endif /* HEADER_fd_src_choreo_tower_fd_tower_serde_h */
