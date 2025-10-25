#include "fd_voter.h"

/* fd_voter_v2_serde defines a serialization / deserialization schema
   for a bincode-encoded vote account v2.  This corresponds exactly with
   the binary layout of a an Agave VoteState1_14_11.

   The serde is structured for zero-copy access ie. x-raying individual
   fields

   Agave schema: https://github.com/anza-xyz/agave/blob/v2.3.7/vote/src/vote_state_view.rs#L182 */

struct fd_voter_v2_serde {
  fd_pubkey_t const * node_pubkey;
  fd_pubkey_t const * authorized_withdrawer;
  uchar       const * commission;

  struct /* VecDeque<Lockout> */ {
    ulong const * votes_cnt;
    struct {
      ulong const * slot;
      uint  const * confirmation_count;
    } votes[31]; /* idx >= votes_cnt are invalid */
  };

  struct /* Option<Slot> */ {
    uchar const * root_slot_option;
    ulong const * root_slot;
  };

  struct /* AuthorizedVoters */ {
    ulong const * authorized_voters_cnt;
    struct {
      ulong       const * epoch;
      fd_pubkey_t const * pubkey;
    } authorized_voters[32]; /* idx >= authorized_voters_cnt are invalid */
  };

  struct /* CircBuf<Pubkey, Epoch, Epoch> */ {
    struct {
      fd_pubkey_t const * pubkey;
      ulong       const * start_epoch;
      ulong       const * end_epoch;
    } buf[32];
    ulong const * idx;
    uchar const * is_empty;
  } prior_voters;

  struct /* Vec<Epoch, u64, u64> */ {
    ulong const * epoch_credits_cnt;
    struct {
      ulong const * epoch;
      ulong const * credits;
      ulong const * prev_credits;
    } epoch_credits[32]; /* idx >= epoch_credits_cnt are invalid */
  };

  struct /* BlockTimestamp */ {
    ulong const * slot;
    long  const * timestamp;
  } last_timestamp;
};
typedef struct fd_voter_v2_serde fd_voter_v2_serde_t;

/* fd_voter_v3_serde defines a serialization / deserialization schema
   for a bincode-encoded vote account v3.  This corresponds exactly with
   the binary layout of a an Agave VoteState (also known as
   VoteStateVersioned::Current).

   The serde is structured for zero-copy access ie. x-raying individual
   fields. */

struct fd_voter_v3_serde {
  fd_pubkey_t const * node_pubkey;
  fd_pubkey_t const * authorized_withdrawer;
  uchar       const * commission;

  struct /* VecDeque<LandedVote> */ {
    ulong const * votes_cnt;
    struct {
      uchar const * latency;
      ulong const * slot;
      uint  const * confirmation_count;
    } votes[31]; /* idx >= votes_cnt are invalid */
  };

  struct /* Option<Slot> */ {
    uchar const * root_slot_option;
    ulong const * root_slot;
  };

  struct /* AuthorizedVoters */ {
    ulong const * authorized_voters_cnt;
    struct {
      ulong       const * epoch;
      fd_pubkey_t const * pubkey;
    } authorized_voters[32]; /* idx >= authorized_voters_cnt are invalid */
  };

  struct /* CircBuf<Pubkey, Epoch, Epoch> */ {
    struct {
      fd_pubkey_t const * pubkey;
      ulong       const * start_epoch;
      ulong       const * end_epoch;
    } buf[32];
    ulong const * idx;
    uchar const * is_empty;
  } prior_voters;

  struct /* Vec<Epoch, u64, u64> */ {
    ulong const * epoch_credits_cnt;
    struct {
      ulong const * epoch;
      ulong const * credits;
      ulong const * prev_credits;
    } epoch_credits[32]; /* idx >= epoch_credits_cnt are invalid */
  };

  struct /* BlockTimestamp */ {
    ulong const * slot;
    long  const * timestamp;
  } last_timestamp;
};
typedef struct fd_voter_v3_serde fd_voter_v3_serde_t;
