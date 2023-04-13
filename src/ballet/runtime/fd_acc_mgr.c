#include "fd_acc_mgr.h"
#include "../base58/fd_base58.h"
#include "fd_hashes.h"
#include <stdio.h>

#ifdef _DISABLE_OPTIMIZATION
#pragma GCC optimize ("O0")
#endif

void* fd_acc_mgr_new( void*      mem,
                      fd_funk_t* funk,
                      ulong      footprint ) {
  if( FD_UNLIKELY( !mem ) ) {
    FD_LOG_WARNING(( "NULL mem" ));
    return NULL;
  }

  fd_memset( mem, 0, footprint );

  fd_acc_mgr_t* acc_mgr = (fd_acc_mgr_t*)mem;
  acc_mgr->funk         = funk;

  acc_mgr->shmap = fd_dirty_dup_new ( acc_mgr->data, LG_SLOT_CNT );

  fd_pubkey_hash_vector_new(&acc_mgr->keys);

  return mem;
}

fd_acc_mgr_t* fd_acc_mgr_join( void* mem ) {
  fd_acc_mgr_t* acc_mgr = (fd_acc_mgr_t*)mem;

  acc_mgr->dup = fd_dirty_dup_join( acc_mgr->shmap );

  return acc_mgr;
}

void* fd_acc_mgr_leave( fd_acc_mgr_t* acc_mgr ) {
  fd_dirty_dup_leave( acc_mgr->shmap );
  acc_mgr->dup   = NULL;

  return (void*)acc_mgr;
}

void* fd_acc_mgr_delete( void* mem ) {
  fd_acc_mgr_t* acc_mgr = (fd_acc_mgr_t*)mem;

  fd_dirty_dup_delete ( acc_mgr->shmap );
  acc_mgr->shmap = NULL;

  return mem;
}

fd_funk_recordid_t funk_id( fd_pubkey_t* pubkey ) {
  fd_funk_recordid_t id;
  fd_memset( &id, 0, sizeof(id) );
  fd_memcpy( id.id, pubkey, sizeof(fd_pubkey_t) );

  return id;
}

int fd_acc_mgr_get_account_data( fd_acc_mgr_t* acc_mgr, struct fd_funk_xactionid const* txn, fd_pubkey_t* pubkey, uchar* result, ulong offset, ulong bytes ) {
  fd_funk_recordid_t id = funk_id(pubkey);
  void*              buffer = NULL;
  long               read = fd_funk_read( acc_mgr->funk, txn, &id, (const void**)&buffer, offset, bytes );
  if ( FD_UNLIKELY( read == -1 )) {
//    FD_LOG_WARNING(( "attempt to read data for unknown account" ));
    return FD_ACC_MGR_ERR_UNKNOWN_ACCOUNT;
  } else if ( FD_UNLIKELY( (ulong)read != bytes ) ) {
    FD_LOG_WARNING(( "read account data failed" ));
    return FD_ACC_MGR_ERR_READ_FAILED;
  }

  fd_memcpy(result, buffer, (ulong) read);

  return FD_ACC_MGR_SUCCESS;
}

int fd_acc_mgr_get_metadata( fd_acc_mgr_t* acc_mgr, struct fd_funk_xactionid const* txn, fd_pubkey_t* pubkey, fd_account_meta_t *result ) {
  int read_result = fd_acc_mgr_get_account_data( acc_mgr, txn, pubkey, (uchar*)result, 0, sizeof(fd_account_meta_t) );
  if ( read_result != FD_ACC_MGR_SUCCESS ) {
    //FD_LOG_WARNING(( "failed to read account data" ));
    return read_result;
  }

  if ( FD_UNLIKELY( result->magic != FD_ACCOUNT_META_MAGIC ) ) {
    char buf[50];
    fd_base58_encode_32((uchar *) pubkey, NULL, buf);

    FD_LOG_WARNING(( "read account metadata: wrong metadata magic in %s: %d", buf, result->magic ));
    return FD_ACC_MGR_ERR_WRONG_MAGIC;
  }

  return FD_ACC_MGR_SUCCESS;
}

int fd_acc_mgr_write_account_data( fd_acc_mgr_t* acc_mgr, struct fd_funk_xactionid const* txn, fd_pubkey_t* pubkey, ulong offset, uchar* data, ulong data_len ) {
#ifdef _VWRITE
  char buf[50];
  fd_base58_encode_32((uchar *) pubkey, NULL, buf);
  FD_LOG_WARNING(( "fd_acc_mgr_write_account to %s", buf ));
#endif

  /* Write the account data */
  fd_funk_recordid_t id = funk_id( pubkey );
  if ( FD_UNLIKELY( fd_funk_write( acc_mgr->funk, txn, &id, data, offset, data_len ) != (long)data_len ) ) {
    FD_LOG_WARNING(( "failed to write account data" ));
    return FD_ACC_MGR_ERR_WRITE_FAILED;
  }

  return FD_ACC_MGR_SUCCESS;
}

int fd_acc_mgr_get_lamports( fd_acc_mgr_t* acc_mgr, struct fd_funk_xactionid const* txn, fd_pubkey_t * pubkey, fd_acc_lamports_t* result ) {
  fd_account_meta_t metadata;
  int               read_result = fd_acc_mgr_get_metadata( acc_mgr, txn, pubkey, &metadata );
  if ( FD_UNLIKELY( read_result != FD_ACC_MGR_SUCCESS ) ) {
    char buf[50];
    fd_base58_encode_32((uchar *) pubkey, NULL, buf);

    FD_LOG_WARNING(( "failed to read account metadata: %s", buf ));
    return read_result;
  }

  *result = metadata.info.lamports;
  return FD_ACC_MGR_SUCCESS;
}

int fd_acc_mgr_set_lamports( fd_acc_mgr_t* acc_mgr, struct fd_funk_xactionid const* txn, ulong slot, fd_pubkey_t * pubkey, fd_acc_lamports_t lamports ) {
  /* Read the current metadata from Funk */
  fd_account_meta_t metadata;
  int               read_result = fd_acc_mgr_get_metadata( acc_mgr, txn, pubkey, &metadata );
  if ( FD_UNLIKELY( read_result != FD_ACC_MGR_SUCCESS ) ) {
    FD_LOG_WARNING(( "failed to read account metadata" ));
    return read_result;
  }

  /* Overwrite the lamports value and write back */
  metadata.info.lamports = lamports;

  /* Bet we have to update the hash of the account.. and track the dirty pubkeys.. */
  int write_result = fd_acc_mgr_write_account_data( acc_mgr, txn, pubkey, 0, (uchar*)&metadata, sizeof(metadata) );
  if ( FD_UNLIKELY( write_result != FD_ACC_MGR_SUCCESS ) ) {
    FD_LOG_WARNING(( "failed to write account metadata" ));
    return write_result;
  }

  fd_acc_mgr_update_hash( acc_mgr, &metadata, txn,  slot, pubkey, NULL, 0);
  return FD_ACC_MGR_SUCCESS;
}

int fd_acc_mgr_write_structured_account( fd_acc_mgr_t* acc_mgr, struct fd_funk_xactionid const* txn, ulong slot, fd_pubkey_t* pubkey, fd_solana_account_t * account) {
  ulong              dlen =  sizeof(fd_account_meta_t) + account->data_len;
  uchar *            data = fd_alloca(8UL, dlen);
  fd_account_meta_t *m = (fd_account_meta_t *) data;

  fd_account_meta_init(m);
  m->dlen = account->data_len;

  m->info.lamports = account->lamports;
  m->info.rent_epoch = account->rent_epoch;
  memcpy(m->info.owner, account->owner.key, sizeof(account->owner.key));
  m->info.executable = (char) account->executable;
  fd_memset(m->info.padding, 0, sizeof(m->info.padding));

  m->slot = slot;

  fd_hash_meta( m, slot, (fd_pubkey_t const *)  pubkey, account->data, (fd_hash_t *) m->hash);

  fd_acc_mgr_dirty_pubkey ( acc_mgr, (fd_pubkey_t *) pubkey, (fd_hash_t *) m->hash );

  char encoded_hash[50];
  fd_base58_encode_32((uchar *) m->hash, 0, encoded_hash);
  char encoded_pubkey[50];
  fd_base58_encode_32((uchar *) pubkey, 0, encoded_pubkey);

  FD_LOG_WARNING(( "fd_acc_mgr_write_structured_account: slot=%ld, pubkey=%s  hash=%s   dlen=%ld", slot, encoded_pubkey, encoded_hash, m->dlen ));

  fd_memcpy(&data[sizeof(fd_account_meta_t)], account->data, account->data_len);

  return fd_acc_mgr_write_account_data(acc_mgr, txn, pubkey, 0, (uchar *) data, dlen);
}

int fd_acc_mgr_write_append_vec_account( fd_acc_mgr_t* acc_mgr, struct fd_funk_xactionid const* txn, ulong slot, fd_solana_account_hdr_t * hdr) {
  ulong dlen =  sizeof(fd_account_meta_t) + hdr->meta.data_len;

  // TODO: Switch this all over to using alexs new writev interface and get rid of malloc
  //
  // fd_alloca was failing in odd way

  uchar *            data = aligned_alloc(8UL, dlen);
  fd_account_meta_t *m = (fd_account_meta_t *) data;

  fd_account_meta_init(m);
  m->dlen = hdr->meta.data_len;

  fd_memcpy(&m->info, &hdr->info, sizeof(m->info));

  m->slot = slot;

  fd_hash_meta(m, slot, (fd_pubkey_t *) &hdr->meta.pubkey, (uchar *) &hdr[1], (fd_hash_t *) m->hash);

  fd_acc_mgr_dirty_pubkey ( acc_mgr, (fd_pubkey_t *) &hdr->meta.pubkey, (fd_hash_t *) m->hash );

  fd_memcpy(&data[sizeof(fd_account_meta_t)], (uchar *) &hdr[1], hdr->meta.data_len);

  int ret = fd_acc_mgr_write_account_data(acc_mgr, txn, (fd_pubkey_t *) &hdr->meta.pubkey, 0, (uchar *) data, dlen);
  free(data);
  return ret;
}

void fd_acc_mgr_dirty_pubkey ( fd_acc_mgr_t* acc_mgr, fd_pubkey_t* pubkey, fd_hash_t *hash) {
  fd_dirty_map_entry_t * me = fd_dirty_dup_query(acc_mgr->dup, *((fd_pubkey_t *) pubkey), NULL);

  if (me == NULL) {
    fd_pubkey_hash_pair_t e;
    fd_memcpy(e.pubkey.key, pubkey, sizeof(e.pubkey.key));
    fd_memcpy(e.hash.hash, hash, sizeof(e.hash.hash));

    ulong idx = acc_mgr->keys.cnt;
    fd_pubkey_hash_vector_push(&acc_mgr->keys, e);

    me = fd_dirty_dup_insert (acc_mgr->dup, *((fd_pubkey_t *) pubkey));
    me->index = idx;
  } else 
    fd_memcpy(acc_mgr->keys.elems[me->index].hash.hash, hash, sizeof(*hash));
}

int fd_acc_mgr_update_hash ( fd_acc_mgr_t* acc_mgr, fd_account_meta_t * m, struct fd_funk_xactionid const* txn, ulong slot, fd_pubkey_t * pubkey, uchar *data, ulong dlen ) {
  fd_account_meta_t metadata;

  if (NULL == m) {
    int               read_result = fd_acc_mgr_get_metadata( acc_mgr, txn, pubkey, &metadata );
    if ( FD_UNLIKELY( read_result != FD_ACC_MGR_SUCCESS ) ) 
      return read_result;
    m = &metadata;
  }

  if (dlen != 0)
    m->dlen = dlen;

  m->slot = slot;

  if (NULL == data) {
    uchar *           account_data = (uchar *) fd_alloca(8UL,  m->dlen);
    int               read_result = fd_acc_mgr_get_account_data( acc_mgr, txn, pubkey, account_data, sizeof(fd_account_meta_t), m->dlen);
    if ( FD_UNLIKELY( read_result != FD_ACC_MGR_SUCCESS ) ) 
      return read_result;
    data = account_data;
  }

  fd_hash_t hash;

  fd_hash_meta(m, slot, pubkey, data, (fd_hash_t *) &hash);

  char buf[50];
  fd_base58_encode_32((uchar *) &hash, NULL, buf);

  if (memcmp(&hash, m->hash, sizeof(hash))) {
    int write_result = fd_acc_mgr_write_account_data( acc_mgr, txn, pubkey, 0, (uchar*)m, sizeof(metadata) );
    if ( FD_UNLIKELY( write_result != FD_ACC_MGR_SUCCESS ) ) 
      return write_result;

    fd_acc_mgr_dirty_pubkey( acc_mgr, pubkey, &hash);
  }

  return 0;
}
