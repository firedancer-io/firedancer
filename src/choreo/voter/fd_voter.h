#ifndef HEADER_fd_src_choreo_voter_fd_voter_h
#define HEADER_fd_src_choreo_voter_fd_voter_h

#include "../fd_choreo_base.h"
#include "../../funk/fd_funk_rec.h"

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
  union {
    fd_pubkey_t       key; /* vote account address */
    fd_funk_rec_key_t rec; /* funk record key to query above */
  };
  uint hash; /* reserved for fd_map_dynamic.c */

  /* IMPORTANT! The values below should only be modified by fd_epoch and
     fd_ghost. */

  ulong prev_stake;  /* voter's stake as of the previous vote slot */
  ulong stake;       /* voter's current stake (usually == prev stake) */
  ulong replay_vote; /* cached read of last tower vote via replay */
  ulong gossip_vote; /* cached read of last tower vote via gossip */
  ulong rooted_vote; /* cached read of last tower root via replay */
};
typedef struct fd_voter fd_voter_t;

/* fd_voter_state is a struct representation of the bincode-serialized
   layout of a voter's state (known in Agave parlance as "VoteState").
   This struct is then used to support zero-copy access of members.

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
   metadata <- variable. depends on vote state version
   --------
   cnt      <- 8 bytes. bincode-serialized u64
   --------
   votes    <- variable. depends on vote state version and cnt
   --------
   root     <- 5 or 1 byte(s). bincode-serialized Option<u64>
   --------
*/

struct __attribute__((packed)) fd_voter_state {
  uint discriminant; 
  union {
    struct __attribute__((packed)) {
      fd_pubkey_t node_pubkey;
      fd_pubkey_t authorized_voter;
      ulong authorized_voter_epoch;
      uchar prior_voters[ (32*56+sizeof(ulong)) /* serialized bincode sz */ ];
      fd_pubkey_t authorized_withdrawer;
      uchar commission;
      struct __attribute__((packed)) fd_voter_state_tower_v0_23_5 {
      ulong cnt;
        struct __attribute__((packed)) fd_voter_state_tower_vote_v0_23_5 {
          ulong slot;
          uint  conf;
        } votes[32]; /* only first `cnt` elements are valid */
      } tower;
    } v0_23_5;
    
    struct __attribute__((packed)) {
      fd_pubkey_t node_pubkey;
      fd_pubkey_t authorized_withdrawer;
      uchar commission;
      struct __attribute__((packed)) fd_voter_state_tower {
        ulong cnt;
        struct __attribute__((packed)) fd_voter_state_tower_vote {
          uchar latency;
          ulong slot;
          uint  conf;
        } votes[32]; /* only first `cnt` elements are valid */
      } tower;
    };

    /* The tower's root (a bincode-serialized Option<u64>) follows
      votes. Because the preceding votes are variable-length in
      serialized form, we cannot encode the root directly inside the
      struct. */
  };
};
typedef struct fd_voter_state_tower_vote_v0_23_5 fd_voter_state_tower_vote_v0_23_5_t;
typedef struct fd_voter_state_tower_vote fd_voter_state_tower_vote_t;
typedef struct fd_voter_state_tower_v0_23_5 fd_voter_state_tower_v0_23_5_t;
typedef struct fd_voter_state_tower fd_voter_state_tower_t;
typedef struct fd_voter_state fd_voter_state_t;

/* fd_voter_state queries funk for the record in the provided `txn` and
   `key`.  Returns a pointer to the start of the voter's state.  Assumes
   `key` is a vote account address and the record is a voter's state
   (fd_voter_state_t).  U.B. if `key` does not point to a valid vote
   account. */

fd_voter_state_t const *
fd_voter_state( fd_funk_t * funk, fd_funk_txn_t const * txn, fd_funk_rec_key_t const * key );

/* fd_voter_state_cnt returns the number of votes in the voter's tower.
   Assumes `state` is a valid fd_voter_state_t. */

FD_FN_PURE static inline ulong
fd_voter_state_cnt( fd_voter_state_t const * state ) {
  if( FD_UNLIKELY( state->discriminant == fd_vote_state_versioned_enum_v0_23_5 ) ) {
    return state->v0_23_5.tower.cnt;
  }
  return state->tower.cnt;
}

/* fd_voter_state_vote returns the voter's most recent vote (ie. the
   last vote of the tower in the voter's state).  Assumes `state` is a
   valid fd_voter_state_t. */

FD_FN_PURE static inline ulong
fd_voter_state_vote( fd_voter_state_t const * state ) {
  if( FD_UNLIKELY( !fd_voter_state_cnt( state ) ) ) return FD_SLOT_NULL;
  if( FD_UNLIKELY( state->discriminant == fd_vote_state_versioned_enum_v0_23_5 ) ) {
    return state->v0_23_5.tower.votes[state->tower.cnt - 1].slot;
  }
  return state->tower.votes[state->tower.cnt - 1].slot;
}

/* fd_voter_state_root returns the voter's tower root.  Assumes `state`
   is a valid fd_voter_state_t. */

FD_FN_PURE static inline ulong
fd_voter_state_root( fd_voter_state_t const * state ) {
  uchar * root = fd_ptr_if(
    state->discriminant == fd_vote_state_versioned_enum_v0_23_5,
    (uchar *)&state->v0_23_5.tower.votes + sizeof(fd_voter_state_tower_vote_v0_23_5_t) * state->v0_23_5.tower.cnt,
    (uchar *)&state->tower.votes         + sizeof(fd_voter_state_tower_vote_t)         * state->tower.cnt
  );
  uchar is_some = *(uchar *)root;         /* whether the Option is a Some type */
  if( FD_UNLIKELY( !is_some ) ) return 0; /* the implicit root is the genesis slot */
  return *(ulong *)(root+sizeof(uchar));
}

#endif /* HEADER_fd_src_choreo_voter_fd_voter_h */
