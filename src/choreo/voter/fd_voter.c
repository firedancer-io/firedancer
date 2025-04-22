#include "fd_voter.h"

#include "../../funk/fd_funk.h"
#include "../../funk/fd_funk_val.h"

fd_voter_state_t const *
fd_voter_state( fd_funk_t * funk,
                fd_funk_rec_query_t * query,
                fd_funk_txn_t const * txn,
                fd_funk_rec_key_t const * key ) {
  for( ; ; ) {
    fd_funk_rec_t const * rec = fd_funk_rec_query_try_global( funk, txn, key, NULL, query );
    if( FD_UNLIKELY( !rec ) ) {
      return NULL;
    }
    fd_account_meta_t const * meta = fd_funk_val_const( rec, fd_funk_wksp(funk) );
    if( FD_UNLIKELY( meta == NULL || meta->magic != FD_ACCOUNT_META_MAGIC ) ) {
      FD_LOG_WARNING(( "bad account meta" ));
      continue;
    }

    fd_voter_state_t const * state = fd_type_pun_const( (uchar const *)meta + meta->hlen );
    if( FD_UNLIKELY( state == NULL || state->discriminant > fd_vote_state_versioned_enum_current ) ) {
      FD_LOG_WARNING(( "bad account state" ));
      continue;
    }

    if( FD_LIKELY( fd_funk_rec_query_test( query ) == FD_FUNK_SUCCESS ) ) {
      return state;
    }
  }
  /* unreachable */
  return NULL;
}
