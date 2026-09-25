#ifndef HEADER_fd_src_choreo_tower_fd_tower_file_h
#define HEADER_fd_src_choreo_tower_fd_tower_file_h

/* Reads Agave's tower file, tower-1_9-<pubkey>.bin, bincode of
   SavedTowerVersions::Current, a 64 byte Ed25519 signature by the node
   identity over a Tower1_14_11 body.  Read only, the writer follows. */

#include "fd_tower.h"
#include "fd_tower_serdes.h"

/* FD_TOWER_FILE_MAX is the largest file we read. */
#define FD_TOWER_FILE_MAX (8192UL)

/* Return codes of fd_tower_file_de. */
#define FD_TOWER_FILE_SUCCESS      ( 0)
#define FD_TOWER_FILE_ERR_SIZE     (-1) /* truncated, too large, or the lengths disagree */
#define FD_TOWER_FILE_ERR_VERSION  (-2) /* not SavedTowerVersions::Current, or the last vote is not a TowerSync */
#define FD_TOWER_FILE_ERR_SIG      (-3) /* the signature does not verify under identity */
#define FD_TOWER_FILE_ERR_IDENTITY (-4) /* the node pubkey in the file is not identity (Agave's WrongTower) */
#define FD_TOWER_FILE_ERR_TOWER    (-5) /* thresholds, votes, root or lockouts are not a tower Agave writes */

/* A decoded and verified tower file.  bank_hash and block_id belong
   to the last vote, votes[votes_cnt-1].  timestamp_slot and timestamp
   are Agave's last_timestamp pair, stamped with the vote before the
   newest one. */
struct fd_tower_file {
  fd_tower_vote_t votes[ FD_TOWER_VOTE_MAX ];
  ulong           votes_cnt;
  ulong           root;
  fd_hash_t       bank_hash;
  fd_hash_t       block_id;
  ulong           timestamp_slot;
  long            timestamp;
};
typedef struct fd_tower_file fd_tower_file_t;

FD_PROTOTYPES_BEGIN

/* fd_tower_file_de verifies the signature under identity, checks that
   the file is for identity, the two checks Agave makes, and decodes
   into out, root is ULONG_MAX if absent.  Returns FD_TOWER_FILE_SUCCESS,
   or an FD_TOWER_FILE_ERR_* code with out left untouched. */
int
fd_tower_file_de( uchar const *       buf,
                  ulong               buf_sz,
                  fd_pubkey_t const * identity,
                  fd_tower_file_t *   out );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_choreo_tower_fd_tower_file_h */
