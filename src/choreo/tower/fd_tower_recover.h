#ifndef HEADER_fd_src_choreo_tower_fd_tower_recover_h
#define HEADER_fd_src_choreo_tower_fd_tower_recover_h

#include "fd_tower_file.h"
#include "../../flamenco/runtime/sysvar/fd_sysvar_slot_history.h"

#define FD_TOWER_RECOVER_READY       ( 0)
#define FD_TOWER_RECOVER_ERR_HISTORY (-1) /* history unusable, tower older than it, or no common slot */
#define FD_TOWER_RECOVER_ERR_FORK    (-3) /* a rooted vote is missing from the history below a found one */
#define FD_TOWER_RECOVER_ERR_STALE   (-4) /* the vote account already shows a later vote or root */

/* Startup recovery follows Agave's tower adjustment.  Saved votes at or
   below the newest slot found in the snapshot's rooted SlotHistory are
   dropped.  Every newer vote is kept as a lockout by slot whether or not
   its block is ever replayed, so a last vote on a block the cluster
   skipped, or a restart hours later from a fresh snapshot, both work.  A
   kept vote whose slot was never replayed is a stray in
   fd_tower_vote_and_reset, it gets no same-fork shortcut, needs a switch
   proof, and expires by slot like any other vote.  A saved root above the
   snapshot becomes the consensus root, see fd_tower_consensus_root, so
   vote transactions and the switch floor never fall below the root
   already on chain while the prune root catches up through replay. */
struct fd_tower_recover {
  fd_tower_file_t saved;
  ulong           snapshot_slot;
  ulong           retained_cnt; /* newest saved votes kept as lockouts */
};
typedef struct fd_tower_recover fd_tower_recover_t;

FD_PROTOTYPES_BEGIN

/* Decides which saved votes survive.  saved comes from fd_tower_file_de
   and history is the snapshot bank's SlotHistory.  Walking from the
   newest vote, votes are kept until the first one found in the history,
   and everything older has to be found too unless the history no longer
   covers it.  Refused: a tip older than the history window, a rooted
   vote missing below a found one, and a tower with no slot in common
   with the history.  A tower entirely newer than the snapshot is kept
   whole.  Returns READY or a negative error, and leaves out unchanged on
   error.  Success does not prove the file is the newest checkpoint. */
int
fd_tower_recover_init( fd_tower_recover_t *           out,
                       fd_tower_file_t const *        saved,
                       ulong                          snapshot_slot,
                       fd_slot_history_view_t const * history );

/* Rejects a checkpoint the vote account already shows to be stale, a
   later vote or root.  onchain_votes is a deque.  Passing only means no
   newer vote was found, it cannot see unlanded votes missing from the
   file. */
int
fd_tower_recover_check_onchain( fd_tower_recover_t const * recovery,
                                fd_tower_vote_t const *    onchain_votes,
                                ulong                      onchain_root );

/* fd_tower_recover_install pushes the retained votes into tower, which
   must have an empty vote deque and be rooted at snapshot_slot, and
   records a saved root above the snapshot as tower->saved_root and the
   newest retained slot as tower->restored_tip.  Block metadata is left
   alone, fd_tower_recover_replayed attaches it as replay produces the
   blocks. */
void
fd_tower_recover_install( fd_tower_recover_t const * recovery,
                          fd_tower_t *               tower );

/* Marks a retained vote's block as voted the first time replay produces
   its slot, so the same-fork logic applies again.  The vote follows the
   slot, as fd_tower_reconcile assumes and as Agave keys ancestors, so a
   duplicate block at a voted slot does not strand the tower.  Returns 1
   if slot is a retained vote. */
int
fd_tower_recover_replayed( fd_tower_recover_t const * recovery,
                           fd_tower_t *               tower,
                           ulong                      slot,
                           fd_hash_t const *          block_id );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_choreo_tower_fd_tower_recover_h */
