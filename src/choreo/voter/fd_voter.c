#include "fd_voter.h"

#include "../../funkier/fd_funkier.h"
#include "../../funkier/fd_funkier_val.h"

fd_voter_state_t const *
fd_voter_state( fd_funkier_t * funk, fd_funkier_txn_t const * txn, fd_funkier_rec_key_t const * key ) {
  /* Doing a query without a test isn't safe, but we are returning a pointer to funk memory. TODO: fix this */
  fd_funkier_rec_query_t query[1];
  fd_funkier_rec_t const * rec = fd_funkier_rec_query_try_global( funk, txn, key, NULL, query );
  if( FD_UNLIKELY( !rec || !!( rec->flags & FD_FUNKIER_REC_FLAG_ERASE ) ) ) {
    return NULL;
  }
  fd_account_meta_t const * meta = fd_funkier_val_const( rec, fd_funkier_wksp(funk) );
  FD_TEST( meta->magic == FD_ACCOUNT_META_MAGIC );
  fd_voter_state_t const * state = fd_type_pun_const( (uchar const *)meta + meta->hlen );
  #if FD_VOTER_USE_HANDHOLDING
  FD_TEST( state->discriminant <= fd_vote_state_versioned_enum_current );
  #endif
  return state;
}
