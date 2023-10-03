#include "fd_rocksdb.h"
#include <malloc.h>
#include <stdbool.h>
#include <stdlib.h>
#include "../../util/bits/fd_bits.h"
#include "../../ballet/shred/fd_deshredder.h"

char *
fd_rocksdb_init( fd_rocksdb_t * db,
                 char const *   db_name ) {
  fd_memset(db, 0, sizeof(fd_rocksdb_t));

  db->opts = rocksdb_options_create();
  db->cfgs[ FD_ROCKSDB_CFIDX_DEFAULT     ] = "default";
  db->cfgs[ FD_ROCKSDB_CFIDX_META        ] = "meta";
  db->cfgs[ FD_ROCKSDB_CFIDX_ROOT        ] = "root";
  db->cfgs[ FD_ROCKSDB_CFIDX_DATA_SHRED  ] = "data_shred";
  db->cfgs[ FD_ROCKSDB_CFIDX_BANK_HASHES ] = "bank_hashes";
  db->cfgs[ FD_ROCKSDB_CFIDX_TXN_STATUS  ] = "transaction_status";

  rocksdb_options_t const * cf_options[ FD_ROCKSDB_CF_CNT ];
  for( ulong i=0UL; i<FD_ROCKSDB_CF_CNT; i++ )
    cf_options[ i ] = db->opts;

  char *err = NULL;

  db->db = rocksdb_open_for_read_only_column_families(
      db->opts,
      db_name,
      FD_ROCKSDB_CF_CNT,
      (char              const * const *)db->cfgs,
      (rocksdb_options_t const * const *)cf_options,
      db->cf_handles,
      false,
      &err );

  if( FD_UNLIKELY( err ) ) return err;

  db->ro = rocksdb_readoptions_create();

  return NULL;
}

void fd_rocksdb_destroy(fd_rocksdb_t *db) {

  for( ulong i=0UL; i<FD_ROCKSDB_CF_CNT; i++ ) {
    if( db->cf_handles[i] ) {
      rocksdb_column_family_handle_destroy( db->cf_handles[i] );
      db->cf_handles[i] = NULL;
    }
  }

  if( db->ro ) {
    rocksdb_readoptions_destroy( db->ro );
    db->ro = NULL;
  }

  if( db->opts ) {
    rocksdb_options_destroy( db->opts );
    db->opts = NULL;
  }

  if( db->db ) {
    rocksdb_close( db->db );
    db->db = NULL;
  }
}

ulong fd_rocksdb_last_slot(fd_rocksdb_t *db, char **err) {
  rocksdb_iterator_t* iter = rocksdb_create_iterator_cf(db->db, db->ro, db->cf_handles[2]);
  rocksdb_iter_seek_to_last(iter);
  if (!rocksdb_iter_valid(iter)) {
    rocksdb_iter_destroy(iter);
    *err = "db column for root is empty";
    return 0;
  }

  size_t klen = 0;
  const char *key = rocksdb_iter_key(iter, &klen); // There is no need to free key
  unsigned long slot = fd_ulong_bswap(*((unsigned long *) key));
  rocksdb_iter_destroy(iter);
  return slot;
}

ulong
fd_rocksdb_first_slot( fd_rocksdb_t * db,
                       char **        err ) {

  rocksdb_iterator_t* iter = rocksdb_create_iterator_cf(db->db, db->ro, db->cf_handles[2]);
  rocksdb_iter_seek_to_first(iter);
  if( FD_UNLIKELY( !rocksdb_iter_valid(iter) ) ) {
    rocksdb_iter_destroy(iter);
    *err = "db column for root is empty";
    return 0;
  }

  ulong klen = 0;
  char const * key = rocksdb_iter_key( iter, &klen ); // There is no need to free key
  ulong slot = fd_ulong_bswap( *((ulong *)key));
  rocksdb_iter_destroy(iter);
  return slot;
}

int
fd_rocksdb_get_meta( fd_rocksdb_t *   db,
                     ulong            slot,
                     fd_slot_meta_t * m,
                     fd_valloc_t      valloc ) {
  ulong ks = fd_ulong_bswap(slot);
  size_t vallen = 0;

  char *err = NULL;
  char *meta = rocksdb_get_cf(
    db->db, db->ro, db->cf_handles[1], (const char *) &ks, sizeof(ks), &vallen, &err);

  if (NULL != err) {
    FD_LOG_WARNING(( "%s", err ));
    free (err);
    return -2;
  }

  if (0 == vallen)
    return -1;

  fd_bincode_decode_ctx_t ctx;
  ctx.data = meta;
  ctx.dataend = &meta[vallen];
  ctx.valloc  = valloc;
  if ( fd_slot_meta_decode(m, &ctx) )
    FD_LOG_ERR(("fd_slot_meta_decode failed"));

  free(meta);

  return 0;
}

void *
fd_rocksdb_get_block( fd_rocksdb_t *   db,
                      fd_slot_meta_t * m,
                      fd_valloc_t      valloc,
                      ulong *          result_sz ) {
  ulong slot = m->slot;
  ulong start_idx = 0;
  ulong end_idx = m->received;

  rocksdb_iterator_t* iter = rocksdb_create_iterator_cf(db->db, db->ro, db->cf_handles[3]);

  char k[16];
  *((ulong *) &k[0]) = fd_ulong_bswap(slot);
  *((ulong *) &k[8]) = fd_ulong_bswap(start_idx);

  rocksdb_iter_seek(iter, (const char *) k, sizeof(k));

  ulong bufsize = m->consumed * 1500;
  void* buf = fd_valloc_malloc( valloc, 1UL, bufsize );

  fd_deshredder_t deshred;
  fd_deshredder_init(&deshred, buf, bufsize, NULL, 0);

  for (ulong i = start_idx; i < end_idx; i++) {
    ulong cur_slot, index;
    uchar valid = rocksdb_iter_valid(iter);

    if (valid) {
      size_t klen = 0;
      const char* key = rocksdb_iter_key(iter, &klen); // There is no need to free key
      if (klen != 16)  // invalid key
        continue;
      cur_slot = fd_ulong_bswap(*((ulong *) &key[0]));
      index = fd_ulong_bswap(*((ulong *) &key[8]));
    }

    if (!valid || cur_slot != slot) {
      FD_LOG_WARNING(("missing shreds for slot %ld", slot));
      rocksdb_iter_destroy(iter);
      return NULL;
    }

    if (index != i) {
      FD_LOG_WARNING(("missing shred %ld at index %ld for slot %ld", i, index, slot));
      rocksdb_iter_destroy(iter);
      return NULL;
    }

    size_t dlen = 0;
    // Data was first copied from disk into memory to make it available to this API
    const unsigned char *data = (const unsigned char *) rocksdb_iter_value(iter, &dlen);
    if (data == NULL) {
      FD_LOG_WARNING(("failed to read shred %ld/%ld", slot, i));
      rocksdb_iter_destroy(iter);
      return NULL;
    }

    // This just correctly selects from inside the data pointer to the
    // actual data without a memory copy
    fd_shred_t const * shred = fd_shred_parse( data, (ulong) dlen );

    fd_shred_t const * const shred_list[1] = { shred };
    deshred.shreds    = shred_list;
    deshred.shred_cnt = 1U;

    /* Copy o the buffer */
    long written = fd_deshredder_next( &deshred );

    if ( FD_UNLIKELY ( (written < 0) & (written != -FD_SHRED_EPIPE ) )  ) {
      FD_LOG_ERR(("fd_deshredder_next returned %ld", written));
    }

    rocksdb_iter_next(iter);
  }

  rocksdb_iter_destroy(iter);

  *result_sz = (ulong)((uchar*)deshred.buf - (uchar*)buf);
  return buf;
}

void *
fd_rocksdb_root_iter_new     ( void * ptr ) {
  fd_memset(ptr, 0, sizeof(fd_rocksdb_root_iter_t));
  return ptr;
}

fd_rocksdb_root_iter_t *
fd_rocksdb_root_iter_join    ( void * ptr ) {
  return (fd_rocksdb_root_iter_t *) ptr;
}

void *
fd_rocksdb_root_iter_leave   ( fd_rocksdb_root_iter_t * ptr ) {
  return ptr;
}

int
fd_rocksdb_root_iter_seek( fd_rocksdb_root_iter_t * self,
                           fd_rocksdb_t *           db,
                           ulong                    slot,
                           fd_slot_meta_t *         m,
                           fd_valloc_t              valloc ) {
  self->db = db;

  if( FD_UNLIKELY( !self->iter ) )
    self->iter = rocksdb_create_iterator_cf(self->db->db, self->db->ro, self->db->cf_handles[2]);

  ulong ks = fd_ulong_bswap( slot );

  rocksdb_iter_seek( self->iter, (char const *)&ks, sizeof(ulong) );
  if( FD_UNLIKELY( !rocksdb_iter_valid(self->iter) ) )
    return -1;

  size_t klen = 0;
  char const * key = rocksdb_iter_key( self->iter, &klen ); // There is no need to free key
  ulong kslot = fd_ulong_bswap( *((ulong *)key) );

  if( FD_UNLIKELY( kslot != slot ) ) {
    FD_LOG_WARNING(( "fd_rocksdb_root_iter_seek: wanted slot %lu, found %lu",
                     slot, kslot ));
    return -2;
  }

  return fd_rocksdb_get_meta( self->db, slot, m, valloc );
}

int
fd_rocksdb_root_iter_slot  ( fd_rocksdb_root_iter_t * self, ulong *slot ) {
  if ((NULL == self->db) || (NULL == self->iter))
    return -1;

  if (!rocksdb_iter_valid(self->iter))
    return -2;

  size_t klen = 0;
  const char *key = rocksdb_iter_key(self->iter, &klen); // There is no need to free key
  *slot = fd_ulong_bswap(*((unsigned long *) key));
  return 0;
}

int
fd_rocksdb_root_iter_next( fd_rocksdb_root_iter_t * self,
                           fd_slot_meta_t *         m,
                           fd_valloc_t              valloc ) {
  if ((NULL == self->db) || (NULL == self->iter))
    return -1;

  if (!rocksdb_iter_valid(self->iter))
    return -2;

  rocksdb_iter_next(self->iter);

  if (!rocksdb_iter_valid(self->iter))
    return -3;

  size_t klen = 0;
  const char *key = rocksdb_iter_key(self->iter, &klen); // There is no need to free key

  return fd_rocksdb_get_meta( self->db, fd_ulong_bswap(*((unsigned long *) key)), m, valloc );
}

void
fd_rocksdb_root_iter_destroy ( fd_rocksdb_root_iter_t * self ) {
  if (NULL != self->iter) {
    rocksdb_iter_destroy(self->iter);
    self->iter = 0;
  }
  self->db = NULL;
}

void *
fd_rocksdb_get_bank_hash( fd_rocksdb_t * self,
                          ulong          slot,
                          void *         out ) {

  ulong slot_be = fd_ulong_bswap( slot );

  ulong  vallen;
  char * err = NULL;
  char * res = rocksdb_get_cf(
      self->db,
      self->ro,
      self->cf_handles[ 4 ],
      (char const *)&slot_be, sizeof(ulong),
      &vallen,
      &err );

  if( FD_UNLIKELY( err ) ) {
    FD_LOG_WARNING(( "rocksdb: %s", err ));
    free( err );
    return NULL;
  }

  fd_scratch_push();

  void * retval = NULL;

  fd_bincode_decode_ctx_t decode = {
    .data    = res,
    .dataend = res + vallen,
    .valloc  = fd_scratch_virtual(),
  };
  fd_frozen_hash_versioned_t versioned;
  int decode_err = fd_frozen_hash_versioned_decode( &versioned, &decode );
  if( FD_UNLIKELY( decode_err!=FD_BINCODE_SUCCESS ) ) goto cleanup;
  if( FD_UNLIKELY( decode.data!=decode.dataend    ) ) goto cleanup;
  if( FD_UNLIKELY( versioned.discriminant
      !=fd_frozen_hash_versioned_enum_current     ) ) goto cleanup;

  /* Success */
  memcpy( out, versioned.inner.current.frozen_hash.hash, 32UL );
  retval = out;

cleanup:
  free( res );
  fd_scratch_pop();
  return retval;
}

void *
fd_rocksdb_get_txn_status_raw( fd_rocksdb_t * self,
                               ulong          slot,
                               void const *   sig,
                               ulong *        psz ) {

  ulong slot_be = fd_ulong_bswap( slot );

  /* Construct RocksDB query key */
  char key[ 80 ];
  memset( key,      0,        8UL );
  memcpy( key+ 8UL, sig,     64UL );
  memcpy( key+72UL, &slot_be, 8UL );

  /* Query record */
  char * err = NULL;
  char * res = rocksdb_get_cf(
      self->db, self->ro,
      self->cf_handles[ FD_ROCKSDB_CFIDX_TXN_STATUS ],
      key, 80UL,
      psz,
      &err );

  if( FD_UNLIKELY( err ) ) {
    free( err );
    return NULL;
  }
  return res;
}
