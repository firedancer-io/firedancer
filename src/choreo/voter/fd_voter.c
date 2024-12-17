#include "fd_voter.h"

#include "../../funk/fd_funk.h"
#include "../../funk/fd_funk_val.h"

fd_voter_state_t const *
fd_voter_state( fd_funk_t * funk, fd_funk_txn_t const * txn, fd_funk_rec_key_t const * key ) {
  fd_funk_rec_t const * rec = fd_funk_rec_query_global( funk, txn, key, NULL );
  if( FD_UNLIKELY( !rec || !!( rec->flags & FD_FUNK_REC_FLAG_ERASE ) ) ) {
    return NULL;
  }
  fd_account_meta_t const * meta = fd_funk_val_const( rec, fd_funk_wksp(funk) );
  FD_TEST( meta->magic == FD_ACCOUNT_META_MAGIC );
  fd_voter_state_t const * state = fd_type_pun_const( (uchar const *)meta + meta->hlen );
  #if FD_TOWER_USE_HANDHOLDING
  FD_TEST( state->discriminant <= fd_vote_state_versioned_enum_current );
  #endif
  return state;
}
