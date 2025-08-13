#ifndef HEADER_fd_src_choreo_voter_fd_voter_h
#define HEADER_fd_src_choreo_voter_fd_voter_h

#include "../fd_choreo_base.h"
#include "../../funk/fd_funk_rec.h"

/* FD_VOTER_USE_HANDHOLDING:  Define this to non-zero at compile time
   to turn on additional runtime checks and logging. */

#ifndef FD_VOTER_USE_HANDHOLDING
#define FD_VOTER_USE_HANDHOLDING 1
#endif

#define FD_VOTER_STATE_V0_23_5  (0)
#define FD_VOTER_STATE_V1_14_11 (1)
#define FD_VOTER_STATE_CURRENT  (2)
FD_STATIC_ASSERT(FD_VOTER_STATE_V0_23_5 ==fd_vote_state_versioned_enum_v0_23_5,  FD_VOTER_STATE_V0_23_5 );
FD_STATIC_ASSERT(FD_VOTER_STATE_V1_14_11==fd_vote_state_versioned_enum_v1_14_11, FD_VOTER_STATE_V1_14_11);
FD_STATIC_ASSERT(FD_VOTER_STATE_CURRENT ==fd_vote_state_versioned_enum_current,  FD_VOTER_STATE_CURRENT );

/* Useful to keep both the block_id and slot in the vote record,
   for handling equivocation cases. Potentially re-evaluate removing the
   slot altogether.*/
struct fd_vote_record {
  ulong     slot;
  fd_hash_t hash;
};
typedef struct fd_vote_record fd_vote_record_t;

/* A fd_voter_t describes a voter.  The voter is generic to the context
   in which it is used, eg. it might be a voter in a slot-level context
   in which its stake value may be different from the same voter in an
   epoch-level context which in turn is different from the same voter in
   the prior epoch's context.

   The voter is used by various choreo APIs including fd_epoch which
   tracks all the voters in a given epoch, fd_forks which performs
   choreo-related fork updates after replaying a slot, and ghost and
   tower which both require bookkeeping the epoch voters. */

struct fd_voter {

  fd_pubkey_t key;  /* vote account address */
  uint        hash; /* reserved for fd_map_dynamic.c */

  /* IMPORTANT! The values below should only be modified by fd_epoch and
     fd_ghost. */

  ulong            stake;       /* voter's stake */
  fd_vote_record_t replay_vote; /* cached read of last tower vote via replay */
  fd_vote_record_t gossip_vote; /* cached read of last tower vote via gossip */
  fd_vote_record_t rooted_vote; /* cached read of last tower root via replay */
};
typedef struct fd_voter fd_voter_t;

/* fd_voter_{vote_old, vote, meta, meta_old, state} are struct
   representations of the bincode-serialized layout of a voter's state
   stored in a vote account. These structs are used to support zero-copy
   reads of the vote account.

   The voter's state is versioned, and the serialized formats differ
   depending on this.  Currently, the only version that differs from the
   others that is relevant here is v0.23.5.  Thus v0.23.5 has its own
   dedicated struct definition with a different set of fields that
   precede the votes than the other versions.  Furthermore, v0.23.5
   contains votes of type `fd_vote_lockout_t` vs. the other versions
   which are of type `fd_landed_vote_t`.  The only difference between
   `fd_vote_lockout_t` and `fd_landed_vote_t` is there is an additional
   uchar field `latency`, so that is we include an offset of 0 or 1
   depending on which vote state type it is.

   The layout begins with a set of fields providing important metadata
   about the voter.  Immediately following these fields is the tower
   itself. The tower layout begins with the number of votes currently in
   the tower ie. `cnt`.  Then the votes themselves follow. The format of
   the votes varies depending on the version.  Finally the layout
   concludes with the tower's root slot.

   --------
   metadata <- sizeof(fd_voter_meta_t) or sizeof(fd_voter_meta_old_t)
   --------
   votes    <- {sizeof(vote) or sizeof(vote_old)} * cnt
   --------
   root     <- 5 or 1 byte(s). bincode-serialized Option<u64>
   --------
*/

struct __attribute__((packed)) fd_voter_vote_old {
  ulong slot;
  uint  conf;
};
typedef struct fd_voter_vote_old fd_voter_vote_old_t;

struct __attribute__((packed)) fd_voter_vote {
  uchar latency;
  ulong slot;
  uint  conf;
};
typedef struct fd_voter_vote fd_voter_vote_t;

struct __attribute__((packed)) fd_voter_meta_old {
  fd_pubkey_t node_pubkey;
  fd_pubkey_t authorized_voter;
  ulong       authorized_voter_epoch;
  uchar       prior_voters[ (32*56+sizeof(ulong)) /* serialized bincode sz */ ];
  fd_pubkey_t authorized_withdrawer;
  uchar       commission;
  ulong       cnt;
};
typedef struct fd_voter_meta_old fd_voter_meta_old_t;

struct __attribute__((packed)) fd_voter_meta {
  fd_pubkey_t node_pubkey;
  fd_pubkey_t authorized_withdrawer;
  uchar       commission;
  ulong       cnt;
};
typedef struct fd_voter_meta fd_voter_meta_t;

struct __attribute__((packed)) fd_voter_state {
  uint discriminant;
  union {
    struct __attribute__((packed)) {
      fd_voter_meta_old_t meta;
      fd_voter_vote_old_t votes[31];
    } v0_23_5;

    struct __attribute__((packed)) {
      fd_voter_meta_t     meta;
      fd_voter_vote_old_t votes[31];
    } v1_14_11;

    struct __attribute__((packed)) {
      fd_voter_meta_t meta;
      fd_voter_vote_t votes[31];
    };

    /* The voter's root (a bincode-serialized Option<u64>) follows
       votes. Because the preceding votes are variable-length in
       serialized form, we cannot encode the root directly inside the
       struct. */
  };
};
typedef struct fd_voter_state fd_voter_state_t;


/* fd_voter_state queries funk for the record in the provided `txn` and
   `key`.  Returns a pointer to the start of the voter's state.  Assumes
   `key` is a vote account address and the record is a voter's state
   (fd_voter_state_t).  U.B. if `key` does not point to a valid vote
   account.

   It will update the given Funk query with the version at the point of
   querying. fd_funk_rec_query_test must be called after usage to check
   that the record has not been modified. */

fd_voter_state_t const *
fd_voter_state( fd_funk_t * funk, fd_funk_rec_t const * rec );

/* fd_voter_state_cnt returns the number of votes in the voter's tower.
   Assumes `state` is a valid fd_voter_state_t. */

FD_FN_PURE static inline ulong
fd_voter_state_cnt( fd_voter_state_t const * state ) {
  if( FD_UNLIKELY( state->discriminant == FD_VOTER_STATE_V0_23_5 ) )  return state->v0_23_5.meta.cnt;
  if( FD_UNLIKELY( state->discriminant == FD_VOTER_STATE_V1_14_11 ) ) return state->v1_14_11.meta.cnt;
  return state->meta.cnt;
}

/* fd_voter_state_vote returns the voter's most recent vote (ie. the
   last vote of the tower in the voter's state).  Assumes `state` is a
   valid fd_voter_state_t. */

FD_FN_PURE static inline ulong
fd_voter_state_vote( fd_voter_state_t const * state ) {
  ulong cnt = fd_voter_state_cnt( state );
  if( FD_UNLIKELY( !cnt ) ) return FD_SLOT_NULL;

  if( FD_UNLIKELY( state->discriminant == FD_VOTER_STATE_V0_23_5 ) )  return state->v0_23_5.votes[cnt - 1].slot;
  if( FD_UNLIKELY( state->discriminant == FD_VOTER_STATE_V1_14_11 ) ) return state->v1_14_11.votes[cnt - 1].slot;
  return state->votes[cnt - 1].slot;
}

/* fd_voter_state_root returns the voter's tower root.  Assumes `state`
   is a valid fd_voter_state_t. */

static inline ulong
fd_voter_state_root( fd_voter_state_t const * state ) {
  ulong cnt = fd_voter_state_cnt( state );
  if( FD_UNLIKELY( !cnt ) ) return FD_SLOT_NULL;

  uchar * root = NULL;
  if( FD_UNLIKELY( state->discriminant == FD_VOTER_STATE_V0_23_5 ) )       root = (uchar *)&state->v0_23_5.votes[cnt];
  else if( FD_UNLIKELY( state->discriminant == FD_VOTER_STATE_V1_14_11 ) ) root = (uchar *)&state->v1_14_11.votes[cnt];
  else                                                                     root = (uchar *)&state->votes[cnt];

  #if FD_VOTER_USE_HANDHOLDING
  FD_TEST( root );
  #endif

  return *(uchar *)root ? *(ulong *)(root+sizeof(uchar)) /* Some(root) */ : FD_SLOT_NULL /* None */;
}

#endif /* HEADER_fd_src_choreo_voter_fd_voter_h */
