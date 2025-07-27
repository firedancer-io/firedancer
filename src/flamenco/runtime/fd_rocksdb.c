#include "fd_rocksdb.h"
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include "../../util/bits/fd_bits.h"

char *
fd_rocksdb_init( fd_rocksdb_t * db,
                 char const *   db_name ) {
  fd_memset(db, 0, sizeof(fd_rocksdb_t));

  db->opts = rocksdb_options_create();
  db->cfgs[ FD_ROCKSDB_CFIDX_DEFAULT                  ] = "default";
  db->cfgs[ FD_ROCKSDB_CFIDX_META                     ] = "meta";
  db->cfgs[ FD_ROCKSDB_CFIDX_DEAD_SLOTS               ] = "dead_slots";
  db->cfgs[ FD_ROCKSDB_CFIDX_DUPLICATE_SLOTS          ] = "duplicate_slots";
  db->cfgs[ FD_ROCKSDB_CFIDX_ERASURE_META             ] = "erasure_meta";
  db->cfgs[ FD_ROCKSDB_CFIDX_ORPHANS                  ] = "orphans";
  db->cfgs[ FD_ROCKSDB_CFIDX_BANK_HASHES              ] = "bank_hashes";
  db->cfgs[ FD_ROCKSDB_CFIDX_ROOT                     ] = "root";
  db->cfgs[ FD_ROCKSDB_CFIDX_INDEX                    ] = "index";
  db->cfgs[ FD_ROCKSDB_CFIDX_DATA_SHRED               ] = "data_shred";
  db->cfgs[ FD_ROCKSDB_CFIDX_CODE_SHRED               ] = "code_shred";
  db->cfgs[ FD_ROCKSDB_CFIDX_TRANSACTION_STATUS       ] = "transaction_status";
  db->cfgs[ FD_ROCKSDB_CFIDX_ADDRESS_SIGNATURES       ] = "address_signatures";
  db->cfgs[ FD_ROCKSDB_CFIDX_TRANSACTION_MEMOS        ] = "transaction_memos";
  db->cfgs[ FD_ROCKSDB_CFIDX_TRANSACTION_STATUS_INDEX ] = "transaction_status_index";
  db->cfgs[ FD_ROCKSDB_CFIDX_REWARDS                  ] = "rewards";
  db->cfgs[ FD_ROCKSDB_CFIDX_BLOCKTIME                ] = "blocktime";
  db->cfgs[ FD_ROCKSDB_CFIDX_PERF_SAMPLES             ] = "perf_samples";
  db->cfgs[ FD_ROCKSDB_CFIDX_BLOCK_HEIGHT             ] = "block_height";
  db->cfgs[ FD_ROCKSDB_CFIDX_OPTIMISTIC_SLOTS         ] = "optimistic_slots";
  db->cfgs[ FD_ROCKSDB_CFIDX_MERKLE_ROOT_META         ] = "merkle_root_meta";

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

void
fd_rocksdb_new( fd_rocksdb_t * db,
                char const *   db_name ) {
  fd_memset(db, 0, sizeof(fd_rocksdb_t));

  db->opts = rocksdb_options_create();
  /* Create the db*/
  rocksdb_options_set_create_if_missing(db->opts, 1);

  db->cfgs[ FD_ROCKSDB_CFIDX_DEFAULT                  ] = "default";
  db->cfgs[ FD_ROCKSDB_CFIDX_META                     ] = "meta";
  db->cfgs[ FD_ROCKSDB_CFIDX_DEAD_SLOTS               ] = "dead_slots";
  db->cfgs[ FD_ROCKSDB_CFIDX_DUPLICATE_SLOTS          ] = "duplicate_slots";
  db->cfgs[ FD_ROCKSDB_CFIDX_ERASURE_META             ] = "erasure_meta";
  db->cfgs[ FD_ROCKSDB_CFIDX_ORPHANS                  ] = "orphans";
  db->cfgs[ FD_ROCKSDB_CFIDX_BANK_HASHES              ] = "bank_hashes";
  db->cfgs[ FD_ROCKSDB_CFIDX_ROOT                     ] = "root";
  db->cfgs[ FD_ROCKSDB_CFIDX_INDEX                    ] = "index";
  db->cfgs[ FD_ROCKSDB_CFIDX_DATA_SHRED               ] = "data_shred";
  db->cfgs[ FD_ROCKSDB_CFIDX_CODE_SHRED               ] = "code_shred";
  db->cfgs[ FD_ROCKSDB_CFIDX_TRANSACTION_STATUS       ] = "transaction_status";
  db->cfgs[ FD_ROCKSDB_CFIDX_ADDRESS_SIGNATURES       ] = "address_signatures";
  db->cfgs[ FD_ROCKSDB_CFIDX_TRANSACTION_MEMOS        ] = "transaction_memos";
  db->cfgs[ FD_ROCKSDB_CFIDX_TRANSACTION_STATUS_INDEX ] = "transaction_status_index";
  db->cfgs[ FD_ROCKSDB_CFIDX_REWARDS                  ] = "rewards";
  db->cfgs[ FD_ROCKSDB_CFIDX_BLOCKTIME                ] = "blocktime";
  db->cfgs[ FD_ROCKSDB_CFIDX_PERF_SAMPLES             ] = "perf_samples";
  db->cfgs[ FD_ROCKSDB_CFIDX_BLOCK_HEIGHT             ] = "block_height";
  db->cfgs[ FD_ROCKSDB_CFIDX_OPTIMISTIC_SLOTS         ] = "optimistic_slots";
  db->cfgs[ FD_ROCKSDB_CFIDX_MERKLE_ROOT_META         ] = "merkle_root_meta";

  /* Create the rocksdb */
  char * err = NULL;
  db->db = rocksdb_open(db->opts, db_name, &err);
  if ( err != NULL ) {
    FD_LOG_ERR(("rocksdb creation failed: %s", err));
  }

  db->wo = rocksdb_writeoptions_create();

  /* Create column families, default already exists at index 0 */
  for ( ulong i = 1; i < FD_ROCKSDB_CF_CNT; ++i ) {
    db->cf_handles[i] = rocksdb_create_column_family(db->db, db->opts, db->cfgs[i], &err);
  }
  rocksdb_options_set_compression( db->opts, rocksdb_lz4_compression );
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

  if( db->wo ) {
    rocksdb_writeoptions_destroy( db->wo );
  }
}

ulong fd_rocksdb_last_slot(fd_rocksdb_t *db, char **err) {
  rocksdb_iterator_t* iter = rocksdb_create_iterator_cf(db->db, db->ro, db->cf_handles[FD_ROCKSDB_CFIDX_ROOT]);
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

ulong fd_rocksdb_find_last_slot(fd_rocksdb_t *db, char **err) {
  ulong max_slot = 0;
  rocksdb_iterator_t* iter = rocksdb_create_iterator_cf(db->db, db->ro, db->cf_handles[FD_ROCKSDB_CFIDX_ROOT]);
  rocksdb_iter_seek_to_first(iter);
  if (!rocksdb_iter_valid(iter)) {
    rocksdb_iter_destroy(iter);
    *err = "db column for root is empty";
    return 0;
  }

  for( ; rocksdb_iter_valid(iter); rocksdb_iter_next(iter) ) {
    size_t klen = 0;
    const char *key = rocksdb_iter_key(iter, &klen); // There is no need to free key
    unsigned long slot = fd_ulong_bswap(*((unsigned long *) key));

    if( slot > max_slot ) {
      max_slot = slot;
      FD_LOG_WARNING(("new max_slot: %lu", max_slot));
    }
  }

  rocksdb_iter_destroy(iter);
  return max_slot;
}

ulong
fd_rocksdb_first_slot( fd_rocksdb_t * db,
                       char **        err ) {

  rocksdb_iterator_t* iter = rocksdb_create_iterator_cf(db->db, db->ro, db->cf_handles[FD_ROCKSDB_CFIDX_ROOT]);
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

  char * err  = NULL;
  char * meta = rocksdb_get_cf( db->db,
                                db->ro,
                                db->cf_handles[FD_ROCKSDB_CFIDX_META],
                                (const char *) &ks,
                                sizeof(ks),
                                &vallen,
                                &err );

  if( NULL != err ) {
    FD_LOG_WARNING(( "%s", err ));
    free( err );
    return -2;
  }

  if (0 == vallen)
    return -1;

  fd_bincode_decode_ctx_t ctx;
  ctx.data = meta;
  ctx.dataend = &meta[vallen];

  ulong total_sz = 0UL;
  if( fd_slot_meta_decode_footprint( &ctx, &total_sz ) ) {
    FD_LOG_ERR(( "fd_slot_meta_decode failed" ));
  }

  uchar * mem = fd_valloc_malloc( valloc, fd_slot_meta_align(), total_sz );
  if( NULL == mem ) {
    FD_LOG_ERR(( "fd_valloc_malloc failed" ));
  }

  fd_slot_meta_decode( mem, &ctx );

  fd_memcpy( m, mem, sizeof(fd_slot_meta_t) );

  free(meta);

  return 0;
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
    self->iter = rocksdb_create_iterator_cf(self->db->db, self->db->ro, self->db->cf_handles[FD_ROCKSDB_CFIDX_ROOT]);

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
fd_rocksdb_get_txn_status_raw( fd_rocksdb_t * self,
                               ulong          slot,
                               void const *   sig,
                               ulong *        psz ) {

  ulong slot_be = fd_ulong_bswap( slot );

  /* Construct RocksDB query key */
  char key[72];
  memcpy( key,      sig,      64UL );
  memcpy( key+64UL, &slot_be, 8UL  );

  /* Query record */
  char * err = NULL;
  char * res = rocksdb_get_cf(
      self->db, self->ro,
      self->cf_handles[ FD_ROCKSDB_CFIDX_TRANSACTION_STATUS ],
      key, 72UL,
      psz,
      &err );

  if( FD_UNLIKELY( err ) ) {
    FD_LOG_WARNING(("err=%s", err));
    free( err );
    return NULL;
  }
  return res;
}

ulong
fd_rocksdb_get_slot( ulong cf_idx, char const * key ) {
  switch (cf_idx) {
    case FD_ROCKSDB_CFIDX_TRANSACTION_STATUS:
      return fd_ulong_bswap(*((ulong *) &key[72])); /* (signature,slot)*/
    case FD_ROCKSDB_CFIDX_ADDRESS_SIGNATURES:
      return fd_ulong_bswap(*((ulong *) &key[40])); /* (pubkey,slot,u32,signature) */
    default: /* all other cfs have the slot at the start */
      return fd_ulong_bswap( *((ulong *)&key[0]) ); /* The key is just the slot number */
  }

  return fd_ulong_bswap( *((ulong *)key) );
}

void
fd_rocksdb_iter_seek_to_slot_if_possible( rocksdb_iterator_t * iter, const ulong cf_idx, const ulong slot ) {
  ulong k = fd_ulong_bswap(slot);
  switch (cf_idx) {
    /* These cfs do not have the slot at the start, we can't seek based on slot prefix */
    case FD_ROCKSDB_CFIDX_TRANSACTION_STATUS:
    case FD_ROCKSDB_CFIDX_ADDRESS_SIGNATURES:
      rocksdb_iter_seek_to_first( iter );
      break;
    default: /* all other cfs have the slot at the start, seek based on slot prefix */
      rocksdb_iter_seek( iter, (const char *)&k, 8);
      break;
  }
}

int
fd_rocksdb_copy_over_slot_indexed_range( fd_rocksdb_t * src,
                                         fd_rocksdb_t * dst,
                                         ulong          cf_idx,
                                         ulong          start_slot,
                                         ulong          end_slot ) {
  FD_LOG_NOTICE(( "fd_rocksdb_copy_over_slot_indexed_range: %lu", cf_idx ));

  if ( cf_idx == FD_ROCKSDB_CFIDX_TRANSACTION_MEMOS  ||
       cf_idx == FD_ROCKSDB_CFIDX_TRANSACTION_STATUS ||
       cf_idx == FD_ROCKSDB_CFIDX_ADDRESS_SIGNATURES ) {
    FD_LOG_NOTICE(( "fd_rocksdb_copy_over_range: skipping cf_idx=%lu because not slot indexed", cf_idx ));
    return 0;
  }

  rocksdb_iterator_t * iter = rocksdb_create_iterator_cf( src->db, src->ro, src->cf_handles[cf_idx] );
  if ( FD_UNLIKELY( iter == NULL ) ) {
    FD_LOG_ERR(( "rocksdb_create_iterator_cf failed for cf_idx=%lu", cf_idx ));
  }

  for ( fd_rocksdb_iter_seek_to_slot_if_possible( iter, cf_idx, start_slot ); rocksdb_iter_valid( iter ); rocksdb_iter_next( iter ) ) {
    ulong klen = 0;
    char const * key = rocksdb_iter_key( iter, &klen ); // There is no need to free key

    ulong slot = fd_rocksdb_get_slot( cf_idx, key );
    if ( slot < start_slot ) {
      continue;
    }
    else if ( slot > end_slot ) {
      break;
    }

    ulong vlen = 0;
    char const * value = rocksdb_iter_value( iter, &vlen );

    fd_rocksdb_insert_entry( dst, cf_idx, key, klen, value, vlen );
  }
  rocksdb_iter_destroy( iter );
  return 0;
}

int
fd_rocksdb_insert_entry( fd_rocksdb_t * db,
                         ulong          cf_idx,
                         const char *   key,
                         ulong          klen,
                         const char *   value,
                         ulong          vlen )
{
  char * err = NULL;
  rocksdb_put_cf( db->db, db->wo, db->cf_handles[cf_idx],
                  key, klen, value, vlen, &err );
  if( FD_UNLIKELY( err != NULL ) ) {
    FD_LOG_WARNING(( "rocksdb_put_cf failed with error %s", err ));
    return -1;
  }
  return 0;
}
