#ifndef HEADER_fd_src_choreo_votor_ag_vote_history_file_h
#define HEADER_fd_src_choreo_votor_ag_vote_history_file_h

/* Reads Agave's Alpenglow vote history file, vote_history-<pubkey>.bin,
   wincode (bincode layout) of SavedVoteHistoryVersions::Current, a 64
   byte Ed25519 signature by the node identity over a bare VoteHistory
   body (no VoteHistoryVersions tag).  Read only, the writer follows. */

#include "ag_votor_base.h"

/* Capacities of the decoded history.  Agave prunes everything below
   root, so these bound the unrooted window we can restore. */
#define AG_VOTE_HISTORY_SLOT_MAX  (4096UL)
#define AG_VOTE_HISTORY_BLOCK_MAX (4UL*AG_VOTE_HISTORY_SLOT_MAX)
#define AG_VOTE_HISTORY_VOTE_MAX  (8UL*AG_VOTE_HISTORY_SLOT_MAX)

/* AG_VOTE_HISTORY_FILE_MAX is the largest file we read, about 180
   slots of history without finalization.  It fills the 32 KiB
   set-identity adminctl payload. */
#define AG_VOTE_HISTORY_FILE_MAX  (32688UL)

/* Parent ready sets grow quadratically with fallback certificates, so
   they are bounded by the file instead: each (slot, parent) pair
   encodes to at least a 40 byte Block. */
#define AG_VOTE_HISTORY_PARENT_READY_MAX (AG_VOTE_HISTORY_FILE_MAX/40UL)

/* VotePayloadToSign wire tags. */
#define AG_VOTE_HISTORY_KIND_NOTAR          (1U)
#define AG_VOTE_HISTORY_KIND_FINAL          (2U)
#define AG_VOTE_HISTORY_KIND_SKIP           (3U)
#define AG_VOTE_HISTORY_KIND_NOTAR_FALLBACK (4U)
#define AG_VOTE_HISTORY_KIND_SKIP_FALLBACK  (5U)
#define AG_VOTE_HISTORY_KIND_GENESIS        (6U)

/* Return codes of ag_vote_history_file_{de,scan}. */
#define AG_VOTE_HISTORY_FILE_SUCCESS      ( 0)
#define AG_VOTE_HISTORY_FILE_ERR_SIZE     (-1) /* truncated, too large, or the lengths disagree */
#define AG_VOTE_HISTORY_FILE_ERR_VERSION  (-2) /* not SavedVoteHistoryVersions::Current */
#define AG_VOTE_HISTORY_FILE_ERR_SIG      (-3) /* the signature does not verify under identity */
#define AG_VOTE_HISTORY_FILE_ERR_IDENTITY (-4) /* the node pubkey in the file is not identity (Agave's WrongVoteHistory) */
#define AG_VOTE_HISTORY_FILE_ERR_HISTORY  (-5) /* a bad vote tag, or an entry below root */
#define AG_VOTE_HISTORY_FILE_ERR_FULL     (-6) /* exceeds an AG_VOTE_HISTORY_*_MAX capacity */

/* A vote Agave signed, VotePayloadToSign.  block is valid for NOTAR,
   NOTAR_FALLBACK and GENESIS, otherwise only block.slot is set. */
struct ag_vote_history_vote {
  uint          kind;
  ushort        shred_version;
  ag_block_id_t block;
};
typedef struct ag_vote_history_vote ag_vote_history_vote_t;

/* A parent ready pair: block is a ready parent for slot. */
struct ag_vote_history_parent_ready {
  ulong         slot;
  ag_block_id_t block;
};
typedef struct ag_vote_history_parent_ready ag_vote_history_parent_ready_t;

/* A decoded and verified vote history.  Agave's maps are flattened
   into (slot, value) arrays in file order: voted_notar and
   voted_notar_fallback as blocks, votes_cast as votes whose
   block.slot is the map key, parent_ready as (slot, block) pairs. */
struct ag_vote_history_file {
  ulong root;

  ulong voted              [ AG_VOTE_HISTORY_SLOT_MAX ]; ulong voted_cnt;
  ulong voted_skip_fallback[ AG_VOTE_HISTORY_SLOT_MAX ]; ulong voted_skip_fallback_cnt;
  ulong skipped            [ AG_VOTE_HISTORY_SLOT_MAX ]; ulong skipped_cnt;
  ulong its_over           [ AG_VOTE_HISTORY_SLOT_MAX ]; ulong its_over_cnt;

  ag_block_id_t voted_notar         [ AG_VOTE_HISTORY_SLOT_MAX  ]; ulong voted_notar_cnt;
  ag_block_id_t voted_notar_fallback[ AG_VOTE_HISTORY_BLOCK_MAX ]; ulong voted_notar_fallback_cnt;
  ag_block_id_t notarized_blocks    [ AG_VOTE_HISTORY_BLOCK_MAX ]; ulong notarized_blocks_cnt;

  ag_vote_history_parent_ready_t parent_ready[ AG_VOTE_HISTORY_PARENT_READY_MAX ];
  ulong                          parent_ready_cnt;

  ag_vote_history_vote_t votes_cast[ AG_VOTE_HISTORY_VOTE_MAX ];
  ulong                  votes_cast_cnt;
};
typedef struct ag_vote_history_file ag_vote_history_file_t;

FD_PROTOTYPES_BEGIN

/* ag_vote_history_file_de verifies the signature under identity,
   checks that the file is for identity, the two checks Agave makes,
   and decodes into out.  Returns AG_VOTE_HISTORY_FILE_SUCCESS, or an
   AG_VOTE_HISTORY_FILE_ERR_* code with out clobbered. */
int
ag_vote_history_file_de( uchar const *            buf,
                         ulong                    buf_sz,
                         uchar const              identity[ static 32 ],
                         ag_vote_history_file_t * out );

/* ag_vote_history_file_scan does validation on a vote history file and
   returns in *wait_to_vote_slot the first slot of the leader window
   after the highest slot the file voted in, or after its root if that
   is higher.  Returns AG_VOTE_HISTORY_FILE_SUCCESS, or an
   AG_VOTE_HISTORY_FILE_ERR_* code with *wait_to_vote_slot unchanged. */
int
ag_vote_history_file_scan( uchar const * buf,
                           ulong         buf_sz,
                           uchar const   identity[ static 32 ],
                           ulong *       wait_to_vote_slot );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_choreo_votor_ag_vote_history_file_h */
