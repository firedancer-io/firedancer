#ifndef HEADER_fd_src_choreo_tower_fd_tower_recover_h
#define HEADER_fd_src_choreo_tower_fd_tower_recover_h

#include "fd_tower_file.h"
#include "../../flamenco/runtime/sysvar/fd_sysvar_slot_history.h"
#include "../../flamenco/runtime/sysvar/fd_sysvar_slot_hashes.h"

#define FD_TOWER_RECOVER_READY       ( 0)
#define FD_TOWER_RECOVER_WAIT        ( 1)
#define FD_TOWER_RECOVER_ERR_HISTORY (-1)
#define FD_TOWER_RECOVER_ERR_HASH    (-2)
#define FD_TOWER_RECOVER_ERR_FORK    (-3)
#define FD_TOWER_RECOVER_ERR_STALE   (-4)

/* Recovery keeps the authenticated checkpoint separate from the live
   tower until its outstanding votes have been resolved.  The caller
   must not vote, reconcile over this checkpoint, or advance its root
   while recovery is pending.  Replay itself must remain enabled. */
struct fd_tower_recover {
  fd_tower_file_t saved;
  ulong           snapshot_slot;
  ulong           rooted_cnt;
};
typedef struct fd_tower_recover fd_tower_recover_t;

FD_PROTOTYPES_BEGIN

/* fd_tower_recover_init checks a verified checkpoint against the
   startup snapshot's rooted history.  `saved` must come from a successful
   fd_tower_file_de.  `history` and `hashes` must be the snapshot's sysvars,
   not those of an arbitrary unrooted replay bank.

   Saved votes at or below snapshot_slot may be retired only if they
   occur in SlotHistory.  If the entire tower is rooted, its last bank
   hash must also match the snapshot or its SlotHashes.  SlotHistory
   alone cannot distinguish duplicate blocks.  When the last vote is
   newer than the snapshot, try below checks its exact block identity
   and ancestry after replay reaches it.

   Returns READY if all saved votes are rooted, WAIT if replay is
   needed, or a negative error.  An unavailable history/hash anchor is
   an error, not permission to discard the file.  `out` is unchanged on
   error.  A successful check does not prove the file is the newest
   checkpoint or that another machine has stopped signing. */
int
fd_tower_recover_init( fd_tower_recover_t *          out,
                       fd_tower_file_t const *       saved,
                       ulong                         snapshot_slot,
                       fd_hash_t const *             snapshot_bank_hash,
                       fd_hash_t const *             snapshot_block_id,
                       fd_slot_history_view_t const * history,
                       fd_slot_hashes_t const *       hashes );

/* fd_tower_recover_check_onchain rejects a checkpoint known to be
   stale because the vote account contains a later vote or root.
   `onchain_votes` is a deque.  Success only means this check found no
   newer vote. It cannot detect unlanded votes missing from the file. */
int
fd_tower_recover_check_onchain( fd_tower_recover_t const * recovery,
                                fd_tower_vote_t const *    onchain_votes,
                                ulong                      onchain_root );

/* fd_tower_recover_try installs all unrooted saved votes together,
   using only the exact tip and ancestors verified by replay.  `tower`
   must have an empty vote deque and tower/ghost must still be rooted
   at `snapshot_slot`.  Returns WAIT if necessary replay metadata is
   absent, READY on success, or a negative error.  WAIT and error leave
   the tower and outputs unchanged.

   On READY, `root_slot` and `root_block_id` describe the recovered root.
   The caller must publish that root through its normal root-advance
   path before allowing a vote.  This function does not prune ghost,
   change tower->root, or sign anything.  It will never truncate an
   unreplayed tail or substitute a same-slot sibling's block ID. */
int
fd_tower_recover_try( fd_tower_recover_t const * recovery,
                      fd_tower_t *                tower,
                      fd_ghost_t *                ghost,
                      ulong *                     root_slot,
                      fd_hash_t *                 root_block_id );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_choreo_tower_fd_tower_recover_h */
