#ifndef HEADER_fd_src_discof_votor_fd_votor_rooted_h
#define HEADER_fd_src_discof_votor_fd_votor_rooted_h

#include "../../disco/fd_disco_base.h"

/* This belongs most cleanly in fd_votor_tile.h, but the shred tile
   needs this type, and the shred tile is in disco, not discof.  Nothing
   in this header requires discof, so we factor it out so that the shred
   tile can just include this one.  See fd_tower_slot_rooted.h, which
   exists for the same reason. */

#define FD_VOTOR_SIG_ROOTED (0) /* see fd_votor_tile.h for the full set */

/* fd_votor_rooted describes a Votor frag that notifies a new root.
   It is the Alpenglow counterpart of fd_tower_slot_rooted: under
   Alpenglow there is no tower, and votor replaces it as the tile that
   tells the rest of the validator which block can never be rolled back.

   A block is rooted once it, or one of its descendants, is finalized.
   Finalization in Alpenglow is absolute rather than probabilistic: a
   finalization certificate for a block implies no conflicting block for
   that slot can ever be finalized, so every ancestor of a finalized
   block is implicitly finalized too.  That makes finalized the correct
   analogue of a tower root, and the same consumers rely on it the same
   way, "publishing" the new root to prune forks that do not descend
   from it.

   Votor only roots blocks for which it has observed replay completed,
   so the rooted blk never runs ahead of replay.  Roots are
   monotonically increasing, and consecutive in slot number for all
   slots that are not skipped or implicitly finalized. */

struct fd_votor_rooted {
  ulong     slot;
  fd_hash_t block_id;
};
typedef struct fd_votor_rooted fd_votor_rooted_t;

#endif /* HEADER_fd_src_discof_votor_fd_votor_rooted_h */
