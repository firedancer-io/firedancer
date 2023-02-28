#include "fd_acc_mgr.h"

void* fd_acc_mgr_new( void* mem,
                      fd_funk_t* funk,
                      const fd_funk_xactionid_t* funk_xroot,
                      ulong footprint ) {
  if( FD_UNLIKELY( !mem ) ) {
    FD_LOG_WARNING(( "NULL mem" ));
    return NULL;
  }

  fd_memset( mem, 0, footprint );

  fd_acc_mgr_t* acc_mgr = (fd_acc_mgr_t*)mem;
  acc_mgr->funk         = funk;
  acc_mgr->funk_xroot   = funk_xroot;
  
  return mem;
}

fd_acc_mgr_t* fd_acc_mgr_join( void* mem ) {
  return (fd_acc_mgr_t*)mem;
}

void* fd_acc_mgr_leave( fd_acc_mgr_t* acc_mgr ) {
  return (void*)acc_mgr;
}

void* fd_acc_mgr_delete( void* mem ) {
  return mem;
}

fd_funk_recordid_t funk_id( fd_pubkey_t* pubkey ) {
  fd_funk_recordid_t id;
  fd_memset( &id, 0, sizeof(id) );
  fd_memcpy( id.id, pubkey, sizeof(fd_pubkey_t) );

  return id;
}

int fd_acc_mgr_get_metadata( fd_acc_mgr_t* acc_mgr, fd_pubkey_t* pubkey, fd_account_meta_t *result ) {
  fd_funk_recordid_t id = funk_id(pubkey);
  void* buffer = (void*)result;
  long read = fd_funk_read( acc_mgr->funk, acc_mgr->funk_xroot, &id, (const void**)&buffer, 0, sizeof(fd_account_meta_t) );
  if ( FD_UNLIKELY( read == -1 )) {
    FD_LOG_WARNING(( "attempt to read account metadata for unknown account" ));
    return FD_ACC_MGR_ERR_UNKNOWN_ACCOUNT;
  }
  else if ( FD_UNLIKELY( read != sizeof(fd_account_meta_t) ) ) {
    FD_LOG_WARNING(( "read account metadata failed" ));
    return FD_ACC_MGR_ERR_READ_FAILED;
  }
  
  return FD_ACC_MGR_SUCCESS;
} 

int fd_acc_mgr_write_account( fd_acc_mgr_t* acc_mgr, fd_pubkey_t* pubkey, uchar* data, ulong data_len ) {
  fd_funk_recordid_t id = funk_id( pubkey );
  if ( FD_UNLIKELY( fd_funk_write( acc_mgr->funk, acc_mgr->funk_xroot, &id, data, 0, data_len ) != (long)data_len ) ) {
    FD_LOG_WARNING(( "failed to write account data" ));
    return FD_ACC_MGR_ERR_WRITE_FAILED;
  }

  return FD_ACC_MGR_SUCCESS;
}

int fd_acc_mgr_get_lamports( fd_acc_mgr_t* acc_mgr, fd_pubkey_t * pubkey, fd_acc_lamports_t* result ) {
  fd_account_meta_t metadata;
  int read_result = fd_acc_mgr_get_metadata( acc_mgr, pubkey, &metadata );
  if ( FD_UNLIKELY( read_result != FD_ACC_MGR_SUCCESS ) ) {
    FD_LOG_WARNING(( "failed to read account metadata" ));
    return read_result;
  }

  *result = metadata.info.lamports;
  return FD_ACC_MGR_SUCCESS;
}

int fd_acc_mgr_set_lamports( fd_acc_mgr_t* acc_mgr, fd_pubkey_t * pubkey, fd_acc_lamports_t lamports ) {
  /* Read the current metadata from Funk */
  fd_account_meta_t metadata;
  int read_result = fd_acc_mgr_get_metadata( acc_mgr, pubkey, &metadata );
  if ( FD_UNLIKELY( read_result != FD_ACC_MGR_SUCCESS ) ) {
    FD_LOG_WARNING(( "failed to read account metadata" ));
    return read_result;
  }

  /* Overwrite the lamports value and write back */
  metadata.info.lamports = lamports;
  /* Bet we have to update the hash of the account.. and track the dirty pubkeys.. */
  int write_result = fd_acc_mgr_write_account( acc_mgr, pubkey, (uchar*)&metadata, sizeof(metadata) );
  if ( FD_UNLIKELY( write_result != FD_ACC_MGR_SUCCESS ) ) {
    FD_LOG_WARNING(( "failed to write account metadata" ));
    return write_result;
  }

  return FD_ACC_MGR_SUCCESS;
}

int fd_acc_mgr_write_structured_account( fd_acc_mgr_t* acc_mgr, fd_pubkey_t* pubkey, fd_solana_account_t * account) {
  ulong dlen =  sizeof(fd_account_meta_t) + account->data_len;
  uchar *data = fd_alloca(8UL, dlen);
  fd_account_meta_t *m = (fd_account_meta_t *) data;

  m->magic = FD_ACCOUNT_META_MAGIC;
  m->hlen = sizeof(fd_account_meta_t);

  m->info.lamports = account->lamports;
  m->info.rent_epoch = account->rent_epoch;
  memcpy(m->info.owner, account->owner.key, sizeof(account->owner.key));
  m->info.executable = (char) account->executable;
  fd_memset(m->info.padding, 0, sizeof(m->info.padding));

  // What is the correct hash function we should be using?
  fd_memset(m->hash.value, 0, sizeof(m->hash.value));

  fd_memcpy(&data[sizeof(fd_account_meta_t)], account->data, account->data_len);

  return fd_acc_mgr_write_account(acc_mgr, pubkey, (uchar *) data, dlen);
}

int fd_acc_mgr_write_append_vec_account( fd_acc_mgr_t* acc_mgr, fd_solana_account_hdr_t * hdr) {
  ulong dlen =  sizeof(fd_account_meta_t) + hdr->meta.data_len;
  uchar *data = fd_alloca(8UL, dlen);
  fd_account_meta_t *m = (fd_account_meta_t *) data;

  m->magic = FD_ACCOUNT_META_MAGIC;
  m->hlen = sizeof(fd_account_meta_t);

  fd_memcpy(&m->info, &hdr->info, sizeof(m->info));

  fd_memset(m->hash.value, 0, sizeof(m->hash.value));

  fd_memcpy(&data[sizeof(fd_account_meta_t)], &hdr[1], hdr->meta.data_len);

  return fd_acc_mgr_write_account(acc_mgr, (fd_pubkey_t *) &hdr->meta.pubkey, (uchar *) data, dlen);
}
