#ifndef HEADER_fd_src_choreo_vote_fd_voter_h
#define HEADER_fd_src_choreo_vote_fd_voter_h

#include "../../flamenco/runtime/fd_system_ids.h"
#include "../../flamenco/runtime/program/fd_vote_program.h"
#include "../../flamenco/txn/fd_txn_generate.h"
#include "../fd_choreo_base.h"
#include "../forks/fd_forks.h"
#include "../tower/fd_tower.h"

struct fd_voter {
  ulong key;  /* map key */
  ulong next; /* reserved for use by fd_pool_para.c */
  ulong hash; /* reserved for use by fd_map_para.c */

  union {
    fd_pubkey_t       addr;    /* vote account address */
    fd_funk_rec_key_t rec_key; /* funk record key to query above */
  };

  ulong       stake;
  fd_pubkey_t validator_identity;
  fd_pubkey_t vote_authority;
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

struct fd_voter_state {
  uint discriminant; 
  union {
    struct __attribute__((packed)) {
      fd_pubkey_t node_pubkey;
      fd_pubkey_t authorized_voter;
      ulong authorized_voter_epoch;
      uchar prior_voters[ (32 * 56 + sizeof(ulong)) /* serialized bincode sz */ ];
      fd_pubkey_t authorized_withdrawer;
      uchar commission;
      struct __attribute__((packed)) {
      ulong cnt;
        struct __attribute__((packed)) fd_voter_state_vote_v0_23_5 {
          ulong slot;
          uint  conf;
        } votes[32]; /* only first `cnt` elements are valid */
      } tower;
    } v0_23_5;
    
    struct __attribute__((packed)) {
      fd_pubkey_t node_pubkey;
      fd_pubkey_t authorized_withdrawer;
      uchar commission;
      struct __attribute__((packed)) {
        ulong cnt;
        struct __attribute__((packed)) fd_voter_state_vote {
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
typedef struct fd_voter_state_vote_v0_23_5 fd_voter_state_vote_v0_23_5_t;
typedef struct fd_voter_state_vote fd_voter_state_vote_t;
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
    (uchar *)&state->v0_23_5.tower.votes + sizeof(fd_voter_state_vote_v0_23_5_t) * state->v0_23_5.tower.cnt,
    (uchar *)&state->tower.votes         + sizeof(fd_voter_state_vote_t)         * state->tower.cnt
  );
  uchar is_some = *(uchar *)root; /* whether the Option is a Some type */
  if( FD_UNLIKELY( !is_some ) ) return FD_SLOT_NULL;
  return *(ulong *)(root+sizeof(uchar));
}

/* fd_voter_txn_generate generates a vote txn using the TowerSync ix. */

ulong
fd_voter_txn_generate( fd_voter_t const *                     voter,
                       fd_compact_vote_state_update_t const * vote_update,
                       fd_hash_t const *                      recent_blockhash,
                       uchar                                  txn_meta_out[static FD_TXN_MAX_SZ],
                       uchar                                  txn_out[static FD_TXN_MTU] );

/* fd_voter_txn_parse parses a txn and returns a pointer to an
   fd_vote_instruction_t.  Assumes caller is currently in a scratch
   scope and allocates memory using fd_scratch_virtual().  Lifetime of
   the returned pointer is lifetime of the caller's scratch scope when
   calling this function. */

// fd_vote_instruction_t *
// fd_voter_txn_parse( uchar txn[static FD_TXN_MTU], ulong txn_sz,  );

#endif
