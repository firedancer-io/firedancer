#ifndef HEADER_fd_src_choreo_votor_fd_vote_history_serde_h
#define HEADER_fd_src_choreo_votor_fd_vote_history_serde_h

/* Reads and writes Agave's Alpenglow vote history file,
   vote_history-<pubkey>.bin, wincode (bincode layout) of
   SavedVoteHistoryVersions::Current which has the identity's Ed25519
   signature with VoteHistory body. */

#include "fd_votor_base.h"

#define FD_VOTE_HISTORY_SERDE_KIND     (0U)           /* SavedVoteHistoryVersions::Current */
#define FD_VOTE_HISTORY_SERDE_SIG_OFF  (4UL)
#define FD_VOTE_HISTORY_SERDE_DATA_OFF (4UL+64UL+8UL) /* kind, signature, data_sz */

#define FD_VOTE_HISTORY_SER_SZ  (FD_VOTE_HISTORY_SERDE_DATA_OFF+32UL+9UL*8UL+8UL) /* the file we write: identity, 9 empty collections, root */
#define FD_VOTE_HISTORY_DE_MAX  (FD_VOTE_HISTORY_SERDE_DATA_OFF+(18UL<<30))        /* the largest file Agave restores, but for trailing bytes: VOTE_HISTORY_PREALLOCATION_SIZE_LIMIT on the history it signs */

/* VotePayloadToSign wire tags. */
#define FD_VOTE_HISTORY_SERDE_TAG_NOTAR          (1U)
#define FD_VOTE_HISTORY_SERDE_TAG_FINAL          (2U)
#define FD_VOTE_HISTORY_SERDE_TAG_SKIP           (3U)
#define FD_VOTE_HISTORY_SERDE_TAG_NOTAR_FALLBACK (4U)
#define FD_VOTE_HISTORY_SERDE_TAG_SKIP_FALLBACK  (5U)
#define FD_VOTE_HISTORY_SERDE_TAG_GENESIS        (6U)

/* Return codes of fd_vote_history_de. */
#define FD_VOTE_HISTORY_DE_SUCCESS      ( 0)
#define FD_VOTE_HISTORY_DE_ERR_SIZE     (-1) /* truncated, or too large */
#define FD_VOTE_HISTORY_DE_ERR_VERSION  (-2) /* not SavedVoteHistoryVersions::Current */
#define FD_VOTE_HISTORY_DE_ERR_SIG      (-3) /* the signature does not verify under identity */
#define FD_VOTE_HISTORY_DE_ERR_IDENTITY (-4) /* the node pubkey in the file is not identity (Agave's WrongVoteHistory) */
#define FD_VOTE_HISTORY_DE_ERR_HISTORY  (-5) /* a bad vote tag */

FD_PROTOTYPES_BEGIN

/* fd_vote_history_ser serializes an Agave-compatible vote history
   file, with the end of the window of our highest notar or skip slot as
   the root.  There are two edge cases, both of which only matter when
   either Agave or Firedancer is in a bad state:

   1. Equivocation (safety): if the Agave failover node's blockstore
      root is not on the same fork as our highest notar or skip slot, it
      fails to boot.
   2. Standstill (liveness): Agave's set-identity ends a standstill
      detected below the root, delaying its re-broadcast.

   The FD->Agave failover is best effort, as Agave has inherently
   different data structures than Firedancer.  Operators should not
   expect a 1-to-1 correspondence between Firedancer's state and Agave's
   state.  The vote history file is simply to protect against
   double-voting (equivocation). */

void
fd_vote_history_ser( uchar const identity[ static 32 ],
                     ulong       root,
                     uchar       buf[ static FD_VOTE_HISTORY_SER_SZ ] );

/* fd_vote_history_de deserializes an Agave-compatible vote history
   file.  The vote history file determines the minimum slot we can vote
   for (wait_to_vote_slot).  The vote history file must be well-formed
   and signed by the provided identity key. Returns
   FD_VOTE_HISTORY_DE_SUCCESS or an FD_VOTE_HISTORY_DE_ERR_* code.

   The Agave->FD failover is best effort, as Agave has inherently
   different data structures than Firedancer.  Operators should not
   expect a 1-to-1 correspondence between Agave's state and Firedancer's
   state.  The vote history file is simply to protect against
   double-voting (equivocation). */

int
fd_vote_history_de( uchar const * buf,
                    ulong         buf_sz,
                    uchar const   identity[ static 32 ],
                    ulong *       wait_to_vote_slot );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_choreo_votor_fd_vote_history_serde_h */
