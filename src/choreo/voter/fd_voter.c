#include "fd_voter.h"

ulong
fd_voter_votes_cnt( uchar const * vote_account_data ) {
  fd_voter_t const * voter = (fd_voter_t const *)fd_type_pun_const( vote_account_data );
  switch( voter->kind ) {
  case FD_VOTER_V4: return fd_ulong_load_8( voter->v4.bls_pubkey_compressed + voter->v4.has_bls_pubkey_compressed * sizeof(voter->v4.bls_pubkey_compressed) );
  case FD_VOTER_V3: return voter->v3.votes_cnt;
  case FD_VOTER_V2: return voter->v2.votes_cnt;
  default:          FD_LOG_HEXDUMP_CRIT(( "bad voter", vote_account_data, 3762 ));
  }
}

fd_voter_vote_t const *
v4_off( fd_voter_t const * voter ) {
  return (fd_voter_vote_t const *)( voter->v4.bls_pubkey_compressed + voter->v4.has_bls_pubkey_compressed * sizeof(voter->v4.bls_pubkey_compressed) + sizeof(ulong) );
}

/* fd_voter_vote_slot takes a voter's vote account data and returns the
   voter's most recent vote slot in the tower.  Returns ULONG_MAX if
   they have an empty tower. */

ulong
fd_voter_vote_slot( uchar const * vote_account_data ) {
  fd_voter_t const * voter = (fd_voter_t const *)fd_type_pun_const( vote_account_data );
  ulong              cnt   = fd_voter_votes_cnt( vote_account_data );
  switch( voter->kind ) {
  case FD_VOTER_V4: return cnt ? v4_off( voter )[cnt-1].slot : ULONG_MAX;
  case FD_VOTER_V3: return cnt ? voter->v3.votes[cnt-1].slot : ULONG_MAX;
  case FD_VOTER_V2: return cnt ? voter->v2.votes[cnt-1].slot : ULONG_MAX;
  default:          FD_LOG_HEXDUMP_CRIT(( "bad voter", vote_account_data, 3762 ));
  }
}

/* fd_voter_root_slot takes a voter's vote account data and returns the
   voter's root slot.  Returns ULONG_MAX if they don't have a root. */

ulong
fd_voter_root_slot( uchar const * vote_account_data ) {
  fd_voter_t const * voter = (fd_voter_t const *)fd_type_pun_const( vote_account_data );
  ulong              cnt   = fd_voter_votes_cnt( vote_account_data );
  switch( voter->kind ) {
  case FD_VOTER_V4: { uchar root_option = fd_uchar_load_1_fast( (uchar *)&v4_off( voter )[cnt] ); return root_option ? fd_ulong_load_8_fast( (uchar *)&v4_off( voter )[cnt] + 1UL ) : ULONG_MAX; }
  case FD_VOTER_V3: { uchar root_option = fd_uchar_load_1_fast( (uchar *)&voter->v3.votes[cnt] ); return root_option ? fd_ulong_load_8_fast( (uchar *)&voter->v3.votes[cnt] + 1UL ) : ULONG_MAX; }
  case FD_VOTER_V2: { uchar root_option = fd_uchar_load_1_fast( (uchar *)&voter->v2.votes[cnt] ); return root_option ? fd_ulong_load_8_fast( (uchar *)&voter->v2.votes[cnt] + 1UL ) : ULONG_MAX; }
  default:          FD_LOG_CRIT(( "unhandled kind %u", voter->kind ));
  }
}
