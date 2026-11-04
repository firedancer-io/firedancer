#include "fd_vote_state_v5.h"
#include "fd_vote_utils.h"
#include "../fd_vote_program.h"
#include "../../fd_runtime.h"

static ulong
authorized_voter_idx( fd_vote_state_v5_t const * self,
                      ulong                      epoch ) {
  for( ulong i=0UL; i<self->authorized_voters_len; i++ ) {
    if( self->authorized_voters[ i ].epoch==epoch ) return i;
  }
  return ULONG_MAX;
}

static int
insert_authorized_voter( fd_vote_state_v5_t * self,
                         ulong                epoch,
                         fd_pubkey_t const *  pubkey ) {
  ulong cnt = self->authorized_voters_len;
  if( FD_UNLIKELY( cnt>=MAX_AUTHORIZED_VOTERS ) ) return FD_EXECUTOR_INSTR_ERR_INVALID_INSTR_DATA;

  ulong i = cnt;
  for( ; i && self->authorized_voters[ i-1UL ].epoch>epoch; i-- ) {
    self->authorized_voters[ i ] = self->authorized_voters[ i-1UL ];
  }
  self->authorized_voters[ i ] = (fd_vote_state_v5_authorized_voter_t){ .epoch=epoch, .pubkey=*pubkey };
  self->authorized_voters_len  = (uint)( cnt+1UL );
  return FD_EXECUTOR_INSTR_SUCCESS;
}

static void
purge_authorized_voters( fd_vote_state_v5_t * self,
                         ulong                epoch ) {
  ulong cnt  = self->authorized_voters_len;
  ulong skip = 0UL;
  while( skip<cnt && self->authorized_voters[ skip ].epoch<epoch ) skip++;
  memmove( self->authorized_voters, self->authorized_voters+skip, (cnt-skip)*sizeof(fd_vote_state_v5_authorized_voter_t) );
  fd_memset( self->authorized_voters+cnt-skip, 0, skip*sizeof(fd_vote_state_v5_authorized_voter_t) );
  self->authorized_voters_len = (uint)( cnt-skip );
}

int
fd_vote_state_v5_get_and_update_authorized_voter( fd_vote_state_v5_t * self,
                                                  ulong                current_epoch,
                                                  fd_pubkey_t **       pubkey ) {
  ulong idx = ULONG_MAX;
  for( ulong i=0UL; i<self->authorized_voters_len; i++ ) {
    if( self->authorized_voters[ i ].epoch<=current_epoch ) idx = i;
  }
  if( FD_UNLIKELY( idx==ULONG_MAX ) ) return FD_EXECUTOR_INSTR_ERR_INVALID_ACC_DATA;

  fd_pubkey_t voter   = self->authorized_voters[ idx ].pubkey;
  int         existed = self->authorized_voters[ idx ].epoch==current_epoch;
  purge_authorized_voters( self, fd_ulong_sat_sub( current_epoch, 1UL ) );
  if( !existed ) {
    int rc = insert_authorized_voter( self, current_epoch, &voter );
    if( FD_UNLIKELY( rc ) ) return rc;
  }

  *pubkey = &self->authorized_voters[ authorized_voter_idx( self, current_epoch ) ].pubkey;
  return FD_EXECUTOR_INSTR_SUCCESS;
}

int
fd_vote_state_v5_set_new_authorized_voter( fd_exec_instr_ctx_t * ctx,
                                           fd_vote_state_v5_t *  self,
                                           fd_pubkey_t const *   authorized_pubkey,
                                           ulong                 current_epoch,
                                           ulong                 target_epoch,
                                           uchar const *         bls_pubkey,
                                           int                   authorized_withdrawer_signer,
                                           fd_pubkey_t const *   signers[ FD_INSTR_SIGNERS_MAX ],
                                           ulong                 signers_cnt ) {
  fd_pubkey_t * epoch_authorized_voter = NULL;
  int rc = fd_vote_state_v5_get_and_update_authorized_voter( self, current_epoch, &epoch_authorized_voter );
  if( FD_UNLIKELY( rc ) ) return rc;

  rc = fd_vote_signature_verify( epoch_authorized_voter, authorized_withdrawer_signer, signers, signers_cnt );
  if( FD_UNLIKELY( rc ) ) return rc;

  if( FD_UNLIKELY( authorized_voter_idx( self, target_epoch )!=ULONG_MAX ) ) {
    ctx->txn_out->err.custom_err = FD_VOTE_ERR_TOO_SOON_TO_REAUTHORIZE;
    return FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;
  }

  rc = insert_authorized_voter( self, target_epoch, authorized_pubkey );
  if( FD_UNLIKELY( rc ) ) return rc;

  if( FD_LIKELY( bls_pubkey ) ) memcpy( self->bls_pubkey_compressed, bls_pubkey, FD_BLS_PUBKEY_COMPRESSED_SZ );
  return FD_EXECUTOR_INSTR_SUCCESS;
}
