#ifndef HEADER_fd_src_choreo_voter_fd_voter_h
#define HEADER_fd_src_choreo_voter_fd_voter_h

/* fd_voter provides APIs for zero-copy serializing and deserializing
   on-chain vote accounts.  Vote accounts contain "vote states" which
   store a voter's metadata and tower. */

#include "../fd_choreo_base.h"

/* FD_VOTER_USE_HANDHOLDING:  Define this to non-zero at compile time
   to turn on additional runtime checks and logging. */

#ifndef FD_VOTER_USE_HANDHOLDING
#define FD_VOTER_USE_HANDHOLDING 1
#endif

#define FD_VOTER_V2 (1)
#define FD_VOTER_V3 (2)
#define FD_VOTER_V4 (3)
FD_STATIC_ASSERT( FD_VOTER_V2==fd_vote_state_versioned_enum_v1_14_11, FD_VOTER_V2 );
FD_STATIC_ASSERT( FD_VOTER_V3==fd_vote_state_versioned_enum_v3,       FD_VOTER_V3 );
FD_STATIC_ASSERT( FD_VOTER_V4==fd_vote_state_versioned_enum_v4,       FD_VOTER_V4 );

/* TODO: Update for vote state v4

   fd_voter describes the layout of a vote state stored in a vote
   account.  These structs are used to support zero-copy access (direct
   casts) of byte arrays containing the vote account data.

   fd_voter is versioned, and the serialized formats differ depending on
   this.  They correspond to Agave's VoteState0_23_5, VoteState1_14_11
   and VoteState structs.

   VoteStatev0_23_5 is deprecated and there are no longer vote accounts
   of that version on testnet / mainnet.  VoteState1_14_11 corresponds
   to FD_VOTER_V2 and VoteState corresponds to FD_VOTER_V3.  The only
   difference between the two is the votes in V3 contain an additional
   uchar field `latency`.

   The binary layout begins with metadata in the vote account, followed by the voter's votes (tower), and terminates with the root. */
struct __attribute__((packed)) fd_voter {
  uint        kind;
  fd_pubkey_t node_pubkey;
  fd_pubkey_t authorized_withdrawer;
  uchar       commission;
  ulong       votes_cnt;
  union {
    struct __attribute__((packed)) {
      ulong slot;
      uint  conf;
    } votes_v2[31]; /* variable-length */
    struct __attribute__((packed)) {
      uchar latency;
      ulong slot;
      uint  conf;
    } votes_v3[31]; /* variable-length */
    /* uchar root_option */
    /* ulong root */
  };
};
typedef struct fd_voter fd_voter_t;

/* fd_voter_vote_slot takes a voter's vote account data and returns the
   voter's most recent vote slot in the tower.  Returns ULONG_MAX if
   they have an empty tower. */

static inline ulong
fd_voter_vote_slot( uchar const * vote_account_data ) {
  fd_voter_t const * voter = (fd_voter_t const *)fd_type_pun_const( vote_account_data );
  ulong              cnt   = voter->votes_cnt;
  switch( voter->kind ) {
  case FD_VOTER_V3: return cnt ? voter->votes_v3[cnt-1].slot : ULONG_MAX;
  case FD_VOTER_V2: return cnt ? voter->votes_v2[cnt-1].slot : ULONG_MAX;
  default: FD_LOG_HEXDUMP_CRIT(( "bad voter", vote_account_data, 3762 ));
  }
}

/* fd_voter_root_slot takes a voter's vote account data and returns the
   voter's root slot.  Returns ULONG_MAX if they don't have a root. */

static inline ulong
fd_voter_root_slot( uchar const * vote_account_data ) {
  fd_voter_t const * voter = (fd_voter_t const *)fd_type_pun_const( vote_account_data );
  ulong              cnt   = voter->votes_cnt;
  switch( voter->kind ) {
  case FD_VOTER_V3: { uchar root_option = fd_uchar_load_1_fast( (uchar *)&voter->votes_v3[cnt] ); return root_option ? fd_ulong_load_8_fast( (uchar *)&voter->votes_v3[cnt] + 1UL ) : ULONG_MAX; }
  case FD_VOTER_V2: { uchar root_option = fd_uchar_load_1_fast( (uchar *)&voter->votes_v2[cnt] ); return root_option ? fd_ulong_load_8_fast( (uchar *)&voter->votes_v2[cnt] + 1UL ) : ULONG_MAX; }
  default: FD_LOG_CRIT(( "unhandled kind %u", voter->kind ));
  }
}

#endif /* HEADER_fd_src_choreo_voter_fd_voter_h */
