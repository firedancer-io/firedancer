#include "fd_txn_account.h"
#include "fd_txn_account_vtable.h"

FD_PROTOTYPES_BEGIN

fd_account_meta_t const *
fd_txn_account_get_acc_meta( fd_txn_account_t const * acct ) {
  return acct->const_meta;
}

uchar const *
fd_txn_account_get_acc_data( fd_txn_account_t const * acct ) {
  return acct->const_data;
}

fd_funk_rec_t const *
fd_txn_account_get_acc_rec( fd_txn_account_t const * acct ) {
  return acct->const_rec;
}

uchar *
fd_txn_account_get_acc_data_mut_writable( fd_txn_account_t const * acct ) {
  return acct->data;
}

void
fd_txn_account_set_meta_readonly( fd_txn_account_t *        acct,
                                  fd_account_meta_t const * meta ) {
  acct->const_meta = meta;
}

void
fd_txn_account_set_meta_mutable_writable( fd_txn_account_t *  acct,
                                 fd_account_meta_t * meta ) {
  acct->const_meta = acct->meta = meta;
}

ulong
fd_txn_account_get_data_len( fd_txn_account_t const * acct ) {
  return acct->const_meta->dlen;
}

int
fd_txn_account_is_executable( fd_txn_account_t const * acct ) {
  return !!acct->const_meta->info.executable;
}

fd_pubkey_t const *
fd_txn_account_get_owner( fd_txn_account_t const * acct ) {
  return (fd_pubkey_t const *)acct->const_meta->info.owner;
}

ulong
fd_txn_account_get_lamports( fd_txn_account_t const * acct ) {
  /* (!const_meta) considered an internal error */
  if( FD_UNLIKELY( !acct->const_meta ) ) return 0UL;
  return acct->const_meta->info.lamports;
}

ulong
fd_txn_account_get_rent_epoch( fd_txn_account_t const * acct ) {
  if( FD_UNLIKELY( !acct->const_meta ) ) FD_LOG_ERR(("account is not setup" ));
  return acct->const_meta->info.rent_epoch;
}

void
fd_txn_account_set_executable_writable( fd_txn_account_t * acct, int is_executable ) {
  if( FD_UNLIKELY( !acct->meta ) ) FD_LOG_ERR(("account is not mutable" ));
  acct->meta->info.executable = !!is_executable;
}

void
fd_txn_account_set_owner_writable( fd_txn_account_t * acct, fd_pubkey_t const * owner ) {
  if( FD_UNLIKELY( !acct->meta ) ) FD_LOG_ERR(("account is not mutable" ));
  fd_memcpy( acct->meta->info.owner, owner, sizeof(fd_pubkey_t) );
}

void
fd_txn_account_set_lamports_writable( fd_txn_account_t * acct, ulong lamports ) {
  if( FD_UNLIKELY( !acct->meta ) ) FD_LOG_ERR(("account is not mutable" ));
  acct->meta->info.lamports = lamports;
}

int
fd_txn_account_checked_add_lamports_writable( fd_txn_account_t * acct, ulong lamports ) {
  ulong balance_post = 0UL;
  int err = fd_ulong_checked_add( acct->vt->get_lamports( acct ), lamports, &balance_post );
  if( FD_UNLIKELY( err ) ) {
    return FD_EXECUTOR_INSTR_ERR_ARITHMETIC_OVERFLOW;
  }

  acct->vt->set_lamports( acct, balance_post );
  return FD_EXECUTOR_INSTR_SUCCESS;
}

int
fd_txn_account_checked_sub_lamports_writable( fd_txn_account_t * acct, ulong lamports ) {
  ulong balance_post = 0UL;
  int err = fd_ulong_checked_sub( acct->vt->get_lamports( acct ),
                                  lamports,
                                  &balance_post );
  if( FD_UNLIKELY( err ) ) {
    return FD_EXECUTOR_INSTR_ERR_ARITHMETIC_OVERFLOW;
  }

  acct->vt->set_lamports( acct, balance_post );
  return FD_EXECUTOR_INSTR_SUCCESS;
}

void
fd_txn_account_set_rent_epoch_writable( fd_txn_account_t * acct, ulong rent_epoch ) {
  if( FD_UNLIKELY( !acct->meta ) ) FD_LOG_ERR(("account is not mutable" ));
  acct->meta->info.rent_epoch = rent_epoch;
}

void
fd_txn_account_set_data_writable( fd_txn_account_t * acct,
                                  uchar const * data,
                                  ulong data_sz) {
  if( FD_UNLIKELY( !acct->meta ) ) FD_LOG_ERR(("account is not mutable" ));
  acct->meta->dlen = data_sz;
  fd_memcpy( acct->data, data, data_sz );
}

void
fd_txn_account_set_data_len_writable( fd_txn_account_t * acct,
                                      ulong              data_len ) {
  if( FD_UNLIKELY( !acct->meta ) ) FD_LOG_ERR(("account is not mutable" ));
  acct->meta->dlen = data_len;
}

void
fd_txn_account_resize_writable( fd_txn_account_t * acct,
                                ulong              dlen ) {
  if( FD_UNLIKELY( !acct->meta ) ) FD_LOG_ERR(("account is not mutable" ));
  /* Because the memory for an account is preallocated for the transaction
     up to the max account size, we only need to zero out bytes (for the case
     where the account grew) and update the account dlen. */
  ulong old_sz    = acct->meta->dlen;
  ulong new_sz    = dlen;
  ulong memset_sz = fd_ulong_sat_sub( new_sz, old_sz );
  fd_memset( acct->data+old_sz, 0, memset_sz );

  acct->meta->dlen = dlen;
}

uchar *
fd_txn_account_get_acc_data_mut_readonly( fd_txn_account_t const * acct FD_PARAM_UNUSED ) {
  FD_LOG_ERR(( "account is not mutable" ));
  return NULL;
}

void
fd_txn_account_set_meta_mutable_readonly( fd_txn_account_t *  acct FD_PARAM_UNUSED,
                                          fd_account_meta_t * meta FD_PARAM_UNUSED ) {
  FD_LOG_ERR(( "cannot set meta as mutable in a readonly account!" ));
}

void
fd_txn_account_set_executable_readonly( fd_txn_account_t * acct FD_PARAM_UNUSED,
                                        int                is_executable FD_PARAM_UNUSED ) {
    FD_LOG_ERR(( "cannot set executable in a readonly account!" ));
}

void
fd_txn_account_set_owner_readonly( fd_txn_account_t * acct FD_PARAM_UNUSED,
                                   fd_pubkey_t const * owner FD_PARAM_UNUSED ) {
    FD_LOG_ERR(( "cannot set owner in a readonly account!" ));
}

void
fd_txn_account_set_lamports_readonly( fd_txn_account_t * acct FD_PARAM_UNUSED,
                                      ulong lamports FD_PARAM_UNUSED ) {
  FD_LOG_ERR(( "cannot set lamports in a readonly account!" ));
}

int
fd_txn_account_checked_add_lamports_readonly( fd_txn_account_t * acct FD_PARAM_UNUSED,
                                              ulong              lamports FD_PARAM_UNUSED ) {
  FD_LOG_ERR(( "cannot do a checked add to lamports in a readonly account!" ));
  return FD_EXECUTOR_INSTR_SUCCESS;
}

int
fd_txn_account_checked_sub_lamports_readonly( fd_txn_account_t * acct FD_PARAM_UNUSED,
                                              ulong              lamports FD_PARAM_UNUSED ) {
  FD_LOG_ERR(( "cannot do a checked sub to lamports in a readonly account!" ));
  return FD_EXECUTOR_INSTR_SUCCESS;
}

void
fd_txn_account_set_rent_epoch_readonly( fd_txn_account_t * acct FD_PARAM_UNUSED,
                                        ulong              rent_epoch FD_PARAM_UNUSED ) {
  FD_LOG_ERR(( "cannot set rent epoch in a readonly account!" ));
}

void
fd_txn_account_set_data_readonly( fd_txn_account_t * acct FD_PARAM_UNUSED,
                                  uchar const * data FD_PARAM_UNUSED,
                                  ulong data_sz FD_PARAM_UNUSED ) {
  FD_LOG_ERR(( "cannot set data in a readonly account!" ));
}

void
fd_txn_account_set_data_len_readonly( fd_txn_account_t * acct FD_PARAM_UNUSED,
                                      ulong              data_len FD_PARAM_UNUSED ) {
  FD_LOG_ERR(( "cannot set data_len in a readonly account!" ));
}

void
fd_txn_account_resize_readonly( fd_txn_account_t * acct FD_PARAM_UNUSED,
                                ulong              dlen FD_PARAM_UNUSED ) {
  FD_LOG_ERR(( "cannot resize a readonly account!" ));
}

ushort
fd_txn_account_is_borrowed( fd_txn_account_t const * acct ) {
  return !!acct->refcnt_excl;
}

int
fd_txn_account_is_mutable( fd_txn_account_t const * acct ) {
  /* A txn account is mutable if meta is non NULL */
  return acct->meta != NULL;
}

int
fd_txn_account_is_readonly( fd_txn_account_t const * acct ) {
  /* A txn account is readonly if only the const_meta field is non NULL */
  return acct->const_meta!=NULL && acct->meta==NULL;
}

int
fd_txn_account_try_borrow_mut( fd_txn_account_t * acct ) {
  return fd_txn_account_acquire_write( acct );
}

void
fd_txn_account_drop( fd_txn_account_t * acct ) {
  fd_txn_account_release_write( acct );
}

FD_PROTOTYPES_END

const fd_txn_account_vtable_t
fd_txn_account_readonly_vtable = {
  .get_meta             = fd_txn_account_get_acc_meta,
  .get_data             = fd_txn_account_get_acc_data,
  .get_rec              = fd_txn_account_get_acc_rec,

  .get_data_mut         = fd_txn_account_get_acc_data_mut_readonly,

  .set_meta_readonly    = fd_txn_account_set_meta_readonly,
  .set_meta_mutable     = fd_txn_account_set_meta_mutable_readonly,

  .get_data_len         = fd_txn_account_get_data_len,
  .is_executable        = fd_txn_account_is_executable,
  .get_owner            = fd_txn_account_get_owner,
  .get_lamports         = fd_txn_account_get_lamports,
  .get_rent_epoch       = fd_txn_account_get_rent_epoch,

  .set_executable       = fd_txn_account_set_executable_readonly,
  .set_owner            = fd_txn_account_set_owner_readonly,
  .set_lamports         = fd_txn_account_set_lamports_readonly,
  .checked_add_lamports = fd_txn_account_checked_add_lamports_readonly,
  .checked_sub_lamports = fd_txn_account_checked_sub_lamports_readonly,
  .set_rent_epoch       = fd_txn_account_set_rent_epoch_readonly,
  .set_data             = fd_txn_account_set_data_readonly,
  .set_data_len         = fd_txn_account_set_data_len_readonly,
  .resize               = fd_txn_account_resize_readonly,

  .is_borrowed          = fd_txn_account_is_borrowed,
  .is_mutable           = fd_txn_account_is_mutable,

  .try_borrow_mut       = fd_txn_account_try_borrow_mut,
  .drop                 = fd_txn_account_drop
};

const fd_txn_account_vtable_t
fd_txn_account_writable_vtable = {
  .get_meta             = fd_txn_account_get_acc_meta,
  .get_data             = fd_txn_account_get_acc_data,
  .get_rec              = fd_txn_account_get_acc_rec,

  .get_data_mut         = fd_txn_account_get_acc_data_mut_writable,

  .set_meta_readonly    = fd_txn_account_set_meta_readonly,
  .set_meta_mutable     = fd_txn_account_set_meta_mutable_writable,

  .get_data_len         = fd_txn_account_get_data_len,
  .is_executable        = fd_txn_account_is_executable,
  .get_owner            = fd_txn_account_get_owner,
  .get_lamports         = fd_txn_account_get_lamports,
  .get_rent_epoch       = fd_txn_account_get_rent_epoch,

  .set_executable       = fd_txn_account_set_executable_writable,
  .set_owner            = fd_txn_account_set_owner_writable,
  .set_lamports         = fd_txn_account_set_lamports_writable,
  .checked_add_lamports = fd_txn_account_checked_add_lamports_writable,
  .checked_sub_lamports = fd_txn_account_checked_sub_lamports_writable,
  .set_rent_epoch       = fd_txn_account_set_rent_epoch_writable,
  .set_data             = fd_txn_account_set_data_writable,
  .set_data_len         = fd_txn_account_set_data_len_writable,
  .resize               = fd_txn_account_resize_writable,

  .is_borrowed          = fd_txn_account_is_borrowed,
  .is_mutable           = fd_txn_account_is_mutable,
  .is_readonly          = fd_txn_account_is_readonly,

  .try_borrow_mut       = fd_txn_account_try_borrow_mut,
  .drop                 = fd_txn_account_drop
};
