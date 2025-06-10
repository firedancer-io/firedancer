#include "fd_voter.h"

#include "../../funk/fd_funk.h"
#include "../../funk/fd_funk_val.h"

fd_voter_state_t const *
fd_voter_state( fd_funk_t * funk, fd_funk_rec_t const * rec ) {
  if( FD_UNLIKELY( !rec || !!( rec->flags & FD_FUNK_REC_FLAG_ERASE ) ) ) {
    FD_LOG_WARNING(( "account erased. address: %s", FD_BASE58_ENC_32_ALLOCA( rec->pair.key->uc ) ));
    return NULL;
  }

  fd_account_meta_t const * meta = fd_funk_val_const( rec, fd_funk_wksp(funk) );
  if( FD_UNLIKELY( meta == NULL || meta->magic != FD_ACCOUNT_META_MAGIC ) ) {
    FD_LOG_WARNING(( "bad account meta. address: %s", FD_BASE58_ENC_32_ALLOCA( rec->pair.key->uc ) ));
    return NULL;
  }

  fd_voter_state_t const * state = fd_type_pun_const( (uchar const *)meta + meta->hlen );
  if( FD_UNLIKELY( state == NULL || state->discriminant > fd_vote_state_versioned_enum_current ) ) {
    FD_LOG_WARNING(( "bad account state. address: %s", FD_BASE58_ENC_32_ALLOCA( rec->pair.key->uc ) ));
    return NULL;
  }

  return state;
}
