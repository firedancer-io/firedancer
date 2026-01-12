#include "fd_txn_account.h"
#include "fd_runtime.h"
#include "program/fd_program_util.h"

void *
fd_txn_account_new( void *              mem,
                    fd_pubkey_t const * pubkey,
                    fd_account_meta_t * meta,
                    int                 is_mutable ) {
  if( FD_UNLIKELY( !mem ) ) {
    FD_LOG_WARNING(( "NULL mem" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)mem, alignof(fd_txn_account_t) ) ) ) {
    FD_LOG_WARNING(( "misaligned mem" ));
    return NULL;
  }

  if( FD_UNLIKELY( !pubkey ) ) {
    FD_LOG_WARNING(( "NULL pubkey" ));
    return NULL;
  }

  if( FD_UNLIKELY( !meta ) ) {
    FD_LOG_WARNING(( "NULL meta" ));
    return NULL;
  }

  fd_txn_account_t * txn_account = (fd_txn_account_t *)mem;

  fd_memcpy( txn_account->pubkey, pubkey, sizeof(fd_pubkey_t) );

  txn_account->magic = FD_TXN_ACCOUNT_MAGIC;

  uchar * data = (uchar *)meta + sizeof(fd_account_meta_t);

  txn_account->meta_soff = (long)( (ulong)meta - (ulong)mem );

  txn_account->meta       = meta;
  txn_account->data       = data;
  txn_account->is_mutable = is_mutable;

  return mem;
}

fd_txn_account_t *
fd_txn_account_join( void * mem ) {
  if( FD_UNLIKELY( !mem ) ) {
    FD_LOG_WARNING(( "NULL mem" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)mem, alignof(fd_txn_account_t) ) ) ) {
    FD_LOG_WARNING(( "misaligned mem" ));
    return NULL;
  }

  fd_txn_account_t * txn_account = (fd_txn_account_t *)mem;

  if( FD_UNLIKELY( txn_account->magic != FD_TXN_ACCOUNT_MAGIC ) ) {
    FD_LOG_WARNING(( "wrong magic" ));
    return NULL;
  }

  if( FD_UNLIKELY( txn_account->meta_soff==0UL ) ) {
    FD_LOG_CRIT(( "invalid meta_soff" ));
  }

  return txn_account;
}

void *
fd_txn_account_leave( fd_txn_account_t * acct ) {

  if( FD_UNLIKELY( !acct ) ) {
    FD_LOG_WARNING(( "NULL acct" ));
    return NULL;
  }

  if( FD_UNLIKELY( acct->magic != FD_TXN_ACCOUNT_MAGIC ) ) {
    FD_LOG_WARNING(( "wrong magic" ));
    return NULL;
  }

  acct->meta = NULL;
  acct->data = NULL;

  return acct;
}

void *
fd_txn_account_delete( void * mem ) {
  if( FD_UNLIKELY( !mem ) ) {
    FD_LOG_WARNING(( "NULL mem" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)mem, alignof(fd_txn_account_t) ) ) ) {
    FD_LOG_WARNING(( "misaligned mem" ));
    return NULL;
  }

  fd_txn_account_t * txn_account = (fd_txn_account_t *)mem;

  if( FD_UNLIKELY( txn_account->magic != FD_TXN_ACCOUNT_MAGIC ) ) {
    FD_LOG_WARNING(( "wrong magic" ));
    return NULL;
  }

  txn_account->magic = 0UL;

  return mem;
}

fd_pubkey_t const *
fd_txn_account_get_owner( fd_txn_account_t const * acct ) {
  if( FD_UNLIKELY( !acct->meta ) ) {
    FD_LOG_CRIT(( "account is not setup" ));
  }
  return (fd_pubkey_t const *)acct->meta->owner;
}

fd_account_meta_t const *
fd_txn_account_get_meta( fd_txn_account_t const * acct ) {
  return acct->meta;
}

uchar const *
fd_txn_account_get_data( fd_txn_account_t const * acct ) {
  return acct->data;
}

uchar *
fd_txn_account_get_data_mut( fd_txn_account_t const * acct ) {
  return acct->data;
}

ulong
fd_txn_account_get_data_len( fd_txn_account_t const * acct ) {
  if( FD_UNLIKELY( !acct->meta ) ) {
    FD_LOG_CRIT(( "account is not setup" ));
  }
  return acct->meta->dlen;
}

int
fd_txn_account_is_executable( fd_txn_account_t const * acct ) {
  if( FD_UNLIKELY( !acct->meta ) ) {
    FD_LOG_CRIT(( "account is not setup" ));
  }
  return !!acct->meta->executable;
}

ulong
fd_txn_account_get_lamports( fd_txn_account_t const * acct ) {
  if( FD_UNLIKELY( !acct->meta ) ) {
    FD_LOG_CRIT(( "account is not setup" ));
  }
  return acct->meta->lamports;
}

void
fd_txn_account_set_meta( fd_txn_account_t * acct, fd_account_meta_t * meta ) {
  if( FD_UNLIKELY( !acct->is_mutable ) ) {
    FD_LOG_CRIT(( "account is not mutable" ));
  }
  if( FD_UNLIKELY( !meta ) ) {
    FD_LOG_CRIT(( "account is not setup" ));
  }
  acct->meta = meta;
}

void
fd_txn_account_set_executable( fd_txn_account_t * acct, int is_executable ) {
  if( FD_UNLIKELY( !acct->is_mutable ) ) {
    FD_LOG_CRIT(( "account is not mutable" ));
  }
  if( FD_UNLIKELY( !acct->meta ) ) {
    FD_LOG_CRIT(( "account is not setup" ));
  }
  acct->meta->executable = !!is_executable;
}

void
fd_txn_account_set_owner( fd_txn_account_t * acct, fd_pubkey_t const * owner ) {
  if( FD_UNLIKELY( !acct->is_mutable ) ) {
    FD_LOG_CRIT(( "account is not mutable" ));
  }
  if( FD_UNLIKELY( !acct->meta ) ) {
    FD_LOG_CRIT(( "account is not setup" ));
  }
  fd_memcpy( acct->meta->owner, owner, sizeof(fd_pubkey_t) );
}

void
fd_txn_account_set_lamports( fd_txn_account_t * acct, ulong lamports ) {
  if( FD_UNLIKELY( !acct->is_mutable ) ) {
    FD_LOG_CRIT(( "account is not mutable" ));
  }
  if( FD_UNLIKELY( !acct->meta ) ) {
    FD_LOG_CRIT(( "account is not setup" ));
  }
  acct->meta->lamports = lamports;
}

int
fd_txn_account_checked_add_lamports( fd_txn_account_t * acct, ulong lamports ) {
  ulong balance_post = 0UL;
  int err = fd_ulong_checked_add( fd_txn_account_get_lamports( acct ), lamports, &balance_post );
  if( FD_UNLIKELY( err ) ) {
    return FD_EXECUTOR_INSTR_ERR_ARITHMETIC_OVERFLOW;
  }

  fd_txn_account_set_lamports( acct, balance_post );
  return FD_EXECUTOR_INSTR_SUCCESS;
}

int
fd_txn_account_checked_sub_lamports( fd_txn_account_t * acct, ulong lamports ) {
  ulong balance_post = 0UL;
  int err = fd_ulong_checked_sub( fd_txn_account_get_lamports( acct ),
                                  lamports,
                                  &balance_post );
  if( FD_UNLIKELY( err ) ) {
    return FD_EXECUTOR_INSTR_ERR_ARITHMETIC_OVERFLOW;
  }

  fd_txn_account_set_lamports( acct, balance_post );
  return FD_EXECUTOR_INSTR_SUCCESS;
}

void
fd_txn_account_set_data( fd_txn_account_t * acct,
                         void const *       data,
                         ulong              data_sz ) {
  if( FD_UNLIKELY( !acct->is_mutable ) ) {
    FD_LOG_CRIT(( "account is not mutable" ));
  }
  if( FD_UNLIKELY( !acct->meta ) ) {
    FD_LOG_CRIT(( "account is not setup" ));
  }
  acct->meta->dlen = (uint)data_sz;
  fd_memcpy( acct->data, data, data_sz );
}

void
fd_txn_account_set_data_len( fd_txn_account_t * acct, ulong data_len ) {
  if( FD_UNLIKELY( !acct->is_mutable ) ) {
    FD_LOG_CRIT(( "account is not mutable" ));
  }
  if( FD_UNLIKELY( !acct->meta ) ) {
    FD_LOG_CRIT(( "account is not setup" ));
  }
  acct->meta->dlen = (uint)data_len;
}

void
fd_txn_account_set_slot( fd_txn_account_t * acct, ulong slot ) {
  if( FD_UNLIKELY( !acct->is_mutable ) ) {
    FD_LOG_CRIT(( "account is not mutable" ));
  }
  if( FD_UNLIKELY( !acct->meta ) ) {
    FD_LOG_CRIT(( "account is not setup" ));
  }
  acct->meta->slot = slot;
}

void
fd_txn_account_clear_owner( fd_txn_account_t * acct ) {
  if( FD_UNLIKELY( !acct->is_mutable ) ) {
    FD_LOG_CRIT(( "account is not mutable" ));
  }
  if( FD_UNLIKELY( !acct->meta ) ) {
    FD_LOG_CRIT(( "account is not setup" ));
  }
  fd_memset( acct->meta->owner, 0, sizeof(fd_pubkey_t) );
}

void
fd_txn_account_resize( fd_txn_account_t * acct,
                       ulong              dlen ) {
  if( FD_UNLIKELY( !acct->is_mutable ) ) {
    FD_LOG_CRIT(( "account is not mutable" ));
  }
  if( FD_UNLIKELY( !acct->meta ) ) {
    FD_LOG_CRIT(( "account is not setup" ));
  }
  /* Because the memory for an account is preallocated for the transaction
     up to the max account size, we only need to zero out bytes (for the case
     where the account grew) and update the account dlen. */
  ulong old_sz    = acct->meta->dlen;
  ulong new_sz    = dlen;
  ulong memset_sz = fd_ulong_sat_sub( new_sz, old_sz );
  fd_memset( acct->data+old_sz, 0, memset_sz );

  acct->meta->dlen = (uint)dlen;
}

int
fd_txn_account_is_mutable( fd_txn_account_t const * acct ) {
  /* A txn account is mutable if meta is non NULL */
  return acct->is_mutable;
}

int
fd_txn_account_is_readonly( fd_txn_account_t const * acct ) {
  /* A txn account is readonly if only the meta_ field is non NULL */
  return !acct->is_mutable;
}

void
fd_txn_account_set_readonly( fd_txn_account_t * acct ) {
  acct->is_mutable = 0;
}

void
fd_txn_account_set_mutable( fd_txn_account_t * acct ) {
  acct->is_mutable = 1;
}
