#include "fd_rocksdb.h"
#include "fd_blockstore.h"
#include "../shredcap/fd_shredcap.h"
#include <malloc.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include "../../util/bits/fd_bits.h"

#pragma GCC diagnostic ignored "-Wformat"
#pragma GCC diagnostic ignored "-Wformat-extra-args"

char *
fd_rocksdb_init( fd_rocksdb_t * db,
                 char const *   db_name ) {
  fd_memset( db, 0, sizeof(fd_rocksdb_t) );

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
  db->cfgs[ FD_ROCKSDB_CFIDX_PROGRAM_COSTS            ] = "program_costs";
  db->cfgs[ FD_ROCKSDB_CFIDX_OPTIMISTIC_SLOTS         ] = "optimistic_slots";
  db->cfgs[ FD_ROCKSDB_CFIDX_MERKLE_ROOT_META         ] = "merkle_root_meta";


  rocksdb_options_t const * cf_options[ FD_ROCKSDB_CF_CNT ];
  for( ulong i=0UL; i<FD_ROCKSDB_CF_CNT; i++ ) {
    cf_options[ i ] = db->opts;
  }

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

  if( FD_UNLIKELY( err ) ) {
    return err;
  }

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
  db->cfgs[ FD_ROCKSDB_CFIDX_PROGRAM_COSTS            ] = "program_costs";
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

void 
fd_rocksdb_destroy( fd_rocksdb_t *db ) {

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

  char *err = NULL;
  char *meta = rocksdb_get_cf(
    db->db, db->ro, db->cf_handles[FD_ROCKSDB_CFIDX_META], (const char *) &ks, sizeof(ks), &vallen, &err);

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

// void
// fd_rocksdb_root_iter_destroy( fd_rocksdb_root_iter_t * iter ) {
//   if( !iter ) {
//     return;
//   }
//   rocksdb_destroy_iterator_cf( iter );
// }

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
  char key[ 80 ];
  memset( key,      0,        8UL );
  memcpy( key+ 8UL, sig,     64UL );
  memcpy( key+72UL, &slot_be, 8UL );

  /* Query record */
  char * err = NULL;
  char * res = rocksdb_get_cf(
      self->db, self->ro,
      self->cf_handles[ FD_ROCKSDB_CFIDX_TRANSACTION_STATUS ],
      key, 80UL,
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
  FD_LOG_NOTICE(("fd_rocksdb_copy_over_slot_indexed_range: %d", cf_idx));

  if ( cf_idx == FD_ROCKSDB_CFIDX_TRANSACTION_MEMOS  ||
       cf_idx == FD_ROCKSDB_CFIDX_PROGRAM_COSTS      ||
       cf_idx == FD_ROCKSDB_CFIDX_TRANSACTION_STATUS ||
       cf_idx == FD_ROCKSDB_CFIDX_ADDRESS_SIGNATURES ) {
    FD_LOG_NOTICE(("fd_rocksdb_copy_over_range: skipping cf_idx=%lu because not slot indexed", cf_idx));
    return 0;
  }

  rocksdb_iterator_t * iter = rocksdb_create_iterator_cf( src->db, src->ro, src->cf_handles[cf_idx] );
  if ( FD_UNLIKELY( iter == NULL ) ) {
    FD_LOG_ERR(("rocksdb_create_iterator_cf failed for cf_idx=%lu", cf_idx));
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
fd_rocksdb_copy_over_txn_status_range( fd_rocksdb_t *    src,
                                       fd_rocksdb_t *    dst,
                                       fd_blockstore_t * blockstore,
                                       ulong             start_slot,
                                       ulong             end_slot ) {
  /* Look up the blocks data and iterate through its transactions */
  fd_blockstore_slot_map_t * block_map = fd_blockstore_slot_map( blockstore );
  fd_wksp_t * wksp = fd_blockstore_wksp( blockstore );

  for ( ulong slot = start_slot; slot <= end_slot; ++slot ) {
    FD_LOG_NOTICE(("fd_rocksdb_copy_over_txn_status_range: %d", slot));
    fd_blockstore_slot_map_t * block_entry = fd_blockstore_slot_map_query( block_map, slot, NULL );
    if( FD_LIKELY( block_entry ) ) {
      uchar * data = fd_wksp_laddr_fast( wksp, block_entry->block.data_gaddr );
      fd_block_txn_ref_t * txns = fd_wksp_laddr_fast( wksp, block_entry->block.txns_gaddr );
      ulong last_txn_off = ULONG_MAX;
      for ( ulong j = 0; j < block_entry->block.txns_cnt; ++j ) {
        fd_blockstore_txn_key_t sig;
        fd_memcpy( &sig, data + txns[j].id_off, sizeof(sig) );
        if( txns[j].txn_off != last_txn_off ) {
          last_txn_off = txns[j].txn_off;
          fd_rocksdb_copy_over_txn_status( src, dst, slot, &sig );
        }
      }
    }
  }
  return 0;
}

void
fd_rocksdb_copy_over_txn_status( fd_rocksdb_t * src,
                                 fd_rocksdb_t * dst,
                                 ulong          slot,
                                 void const *   sig ) {
  ulong slot_be = fd_ulong_bswap( slot );

  /* Construct RocksDB query key */
  /* TODO: Replace with constants */
  char key[ 80 ];
  memset( key,      0,        8UL );
  memcpy( key+ 8UL, sig,     64UL );
  memcpy( key+72UL, &slot_be, 8UL );

  /* Query record */
  ulong sz;
  char * err = NULL;
  char * res = rocksdb_get_cf(
      src->db, src->ro, src->cf_handles[ FD_ROCKSDB_CFIDX_TRANSACTION_STATUS ],
      key, 80UL, &sz, &err );

  if( FD_UNLIKELY( err ) ) {
    FD_LOG_WARNING(("err=%s", err));
    free( err );
    return;
  }

  fd_rocksdb_insert_entry( dst, FD_ROCKSDB_CFIDX_TRANSACTION_STATUS, key, 80UL, res, sz );
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
  if ( FD_UNLIKELY( err != NULL ) ) {
    FD_LOG_WARNING(("rocksdb_put_cf failed with error=%d", err));
    return -1;
  }
  return 0;
}

int
fd_rocksdb_import_block_blockstore( fd_rocksdb_t *    db,
                                    fd_slot_meta_t *  m,
                                    fd_blockstore_t * blockstore,
                                    int txnstatus,
                                    const uchar *hash_override ) // How much effort should we go to here to confirm the size of the hash override?
{
  fd_blockstore_start_write( blockstore );

  ulong slot = m->slot;
  ulong start_idx = 0;
  ulong end_idx = m->received;

  rocksdb_iterator_t* iter = rocksdb_create_iterator_cf(db->db, db->ro, db->cf_handles[FD_ROCKSDB_CFIDX_DATA_SHRED]);

  char k[16];
  ulong slot_be = *((ulong *) &k[0]) = fd_ulong_bswap(slot);
  *((ulong *) &k[8]) = fd_ulong_bswap(start_idx);

  rocksdb_iter_seek(iter, (const char *) k, sizeof(k));

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
      fd_blockstore_end_write(blockstore);
      return -1;
    }

    if (index != i) {
      FD_LOG_WARNING(("missing shred %ld at index %ld for slot %ld", i, index, slot));
      rocksdb_iter_destroy(iter);
      fd_blockstore_end_write(blockstore);
      return -1;
    }

    size_t dlen = 0;
    // Data was first copied from disk into memory to make it available to this API
    const unsigned char *data = (const unsigned char *) rocksdb_iter_value(iter, &dlen);
    if (data == NULL) {
      FD_LOG_WARNING(("failed to read shred %ld/%ld", slot, i));
      rocksdb_iter_destroy(iter);
      fd_blockstore_end_write(blockstore);
      return -1;
    }

    // This just correctly selects from inside the data pointer to the
    // actual data without a memory copy
    fd_shred_t const * shred = fd_shred_parse( data, (ulong) dlen );
    if (shred == NULL) {
      FD_LOG_WARNING(("failed to parse shred %ld/%ld", slot, i));
      rocksdb_iter_destroy(iter);
      fd_blockstore_end_write(blockstore);
      return -1;
    }
    int rc = fd_blockstore_shred_insert( blockstore, shred );
    if (rc != FD_BLOCKSTORE_OK_SLOT_COMPLETE && rc != FD_BLOCKSTORE_OK) {
      FD_LOG_WARNING(("failed to store shred %ld/%ld", slot, i));
      rocksdb_iter_destroy(iter);
      fd_blockstore_end_write(blockstore);
      return -1;
    }

    rocksdb_iter_next(iter);
  }

  rocksdb_iter_destroy(iter);

  fd_wksp_t * wksp = fd_wksp_containing( blockstore );
  fd_blockstore_slot_map_t * block_map = fd_blockstore_slot_map( blockstore );
  fd_blockstore_slot_map_t * block_entry = fd_blockstore_slot_map_query( block_map, slot, NULL );
  if( FD_LIKELY( block_entry ) ) {
    size_t vallen = 0;
    char * err = NULL;
    char * res = rocksdb_get_cf(
      db->db,
      db->ro,
      db->cf_handles[ FD_ROCKSDB_CFIDX_BLOCKTIME ],
      (char const *)&slot_be, sizeof(ulong),
      &vallen,
      &err );
    if( FD_UNLIKELY( err ) ) {
      FD_LOG_WARNING(( "rocksdb: %s", err ));
      free( err );
    } else if(vallen == sizeof(ulong)) {
      block_entry->block.ts = (*(long*)res)*((long)1e9); /* Convert to nanos */
      free(res);
    }

    vallen = 0;
    err = NULL;
    res = rocksdb_get_cf(
      db->db,
      db->ro,
      db->cf_handles[ FD_ROCKSDB_CFIDX_BLOCK_HEIGHT ],
      (char const *)&slot_be, sizeof(ulong),
      &vallen,
      &err );
    block_entry->block.height = 0;
    if( FD_UNLIKELY( err ) ) {
      FD_LOG_WARNING(( "rocksdb: %s", err ));
      free( err );
    } else if(vallen == sizeof(ulong)) {
      block_entry->block.height = *(ulong*)res;
      free(res);
    }

    vallen = 0;
    err = NULL;
    if (NULL != hash_override)
      fd_memcpy( block_entry->block.bank_hash.hash, hash_override, 32UL );
    else {
      res = rocksdb_get_cf(
        db->db,
          db->ro,
          db->cf_handles[ FD_ROCKSDB_CFIDX_BANK_HASHES ],
          (char const *)&slot_be, sizeof(ulong),
          &vallen,
          &err );
      if( FD_UNLIKELY( err ) ) {
        FD_LOG_WARNING(( "rocksdb: %s", err ));
        free( err );
      } else {
        fd_scratch_push();
        fd_bincode_decode_ctx_t decode = {
          .data    = res,
          .dataend = res + vallen,
          .valloc  = fd_scratch_virtual(),
        };
        fd_frozen_hash_versioned_t versioned;
        int decode_err = fd_frozen_hash_versioned_decode( &versioned, &decode );
        if( FD_UNLIKELY( decode_err!=FD_BINCODE_SUCCESS ) ) goto cleanup;
        if( FD_UNLIKELY( decode.data!=decode.dataend    ) ) goto cleanup;
        if( FD_UNLIKELY( versioned.discriminant !=fd_frozen_hash_versioned_enum_current ) ) goto cleanup;
        /* Success */
        fd_memcpy( block_entry->block.bank_hash.hash, versioned.inner.current.frozen_hash.hash, 32UL );
      cleanup:
        free( res );
        fd_scratch_pop();
      }
    }
  }

  if( txnstatus ) {
    fd_alloc_t * alloc = fd_wksp_laddr_fast( wksp, blockstore->alloc_gaddr );
    fd_blockstore_txn_map_t *   txn_map   = fd_wksp_laddr_fast( wksp, blockstore->txn_map_gaddr );
    if( FD_LIKELY( block_entry ) ) {
      uchar * data = fd_wksp_laddr_fast( wksp, block_entry->block.data_gaddr );
      fd_block_txn_ref_t * txns = fd_wksp_laddr_fast( wksp, block_entry->block.txns_gaddr );
      ulong meta_gaddr = 0;
      ulong meta_sz = 0;
      int meta_owned = 0;
      ulong last_txn_off = ULONG_MAX;
      for ( ulong j = 0; j < block_entry->block.txns_cnt; ++j ) {
        fd_blockstore_txn_key_t sig;
        fd_memcpy( &sig, data + txns[j].id_off, sizeof( sig ) );
        fd_blockstore_txn_map_t * txn_map_entry = fd_blockstore_txn_map_query( txn_map, sig, NULL );
        if( FD_UNLIKELY( !txn_map_entry ) ) {
          FD_LOG_WARNING(("missing transaction %64J", &sig));
          continue;
        }

        if( txns[j].txn_off != last_txn_off ) {
          last_txn_off = txns[j].txn_off;
          ulong sz;
          void * raw = fd_rocksdb_get_txn_status_raw( db, slot, &sig, &sz );
          if( raw == NULL ) {
            meta_gaddr = 0;
            meta_sz = 0;
            meta_owned = 0;
          } else {
            void * laddr = fd_alloc_malloc( alloc, 1, sz );
            fd_memcpy(laddr, raw, sz);
            free(raw);
            meta_gaddr = fd_wksp_gaddr_fast( wksp, laddr );
            meta_sz = sz;
            meta_owned = 1;
          }
        }

        txn_map_entry->meta_gaddr = meta_gaddr;
        txn_map_entry->meta_sz = meta_sz;
        txn_map_entry->meta_owned = meta_owned;
        meta_owned = 0;
      }
    }
  }

  fd_blockstore_end_write(blockstore);
  return 0;
}

int
fd_rocksdb_import_block_shredcap( fd_rocksdb_t *             db,
                                    fd_slot_meta_t *           metadata,
                                    fd_io_buffered_ostream_t * ostream,
                                    fd_io_buffered_ostream_t * bank_hash_ostream ) {
  ulong slot = metadata->slot;

  /* pre_slot_hdr_file_offset is the current offset within the file, but
     pre_slot_hdr_file_offset_real accounts for the size of the buffer that has
     been filled but not flushed. This value is used to jump back into the file to
     populate the payload_sz for the slot header */
  long pre_slot_hdr_file_offset      = lseek( ostream->fd, 0, SEEK_CUR );
  long pre_slot_hdr_file_offset_real = pre_slot_hdr_file_offset + (long)ostream->wbuf_used;
  if ( FD_UNLIKELY( pre_slot_hdr_file_offset == -1 ) ) {
    FD_LOG_ERR(( "lseek error while seeking to current location" ));
  }

  /* Write slot specific header */
  fd_shredcap_slot_hdr_t slot_hdr;
  slot_hdr.magic                 = FD_SHREDCAP_SLOT_HDR_MAGIC;
  slot_hdr.version               = FD_SHREDCAP_SLOT_HDR_VERSION;
  slot_hdr.payload_sz            = ULONG_MAX; /* This value is populated after slot is processed */
  slot_hdr.slot                  = metadata->slot;
  slot_hdr.consumed              = metadata->consumed;
  slot_hdr.received              = metadata->received;
  slot_hdr.first_shred_timestamp = metadata->first_shred_timestamp;
  slot_hdr.last_index            = metadata->last_index;
  slot_hdr.parent_slot           = metadata->parent_slot;
  fd_io_buffered_ostream_write( ostream, &slot_hdr, FD_SHREDCAP_SLOT_HDR_FOOTPRINT );

  /* We need to track the payload size */
  ulong payload_sz = 0;

  rocksdb_iterator_t* iter = rocksdb_create_iterator_cf( db->db, db->ro, db->cf_handles[FD_ROCKSDB_CFIDX_DATA_SHRED] );

  char k[16];
  ulong slot_be = *((ulong *) &k[0]) = fd_ulong_bswap( slot );
  *((ulong *) &k[8]) = fd_ulong_bswap( 0 );

  rocksdb_iter_seek( iter, (const char *) k, sizeof(k) );

  ulong start_idx = 0;
  ulong end_idx   = metadata->received;
  for ( ulong i = start_idx; i < end_idx; i++ ) {
    ulong cur_slot, index;
    uchar valid = rocksdb_iter_valid( iter );

    if ( valid ) {
      size_t klen = 0;
      const char* key = rocksdb_iter_key( iter, &klen ); // There is no need to free key
      if ( klen != 16 ) {  // invalid key
        continue;
      }
      cur_slot = fd_ulong_bswap(*((ulong *) &key[0]));
      index    = fd_ulong_bswap(*((ulong *) &key[8]));
    }

    if ( !valid || cur_slot != slot ) {
      FD_LOG_WARNING(( "missing shreds for slot %ld", slot ));
      rocksdb_iter_destroy( iter );
      return -1;
    }

    if ( index != i ) {
      FD_LOG_WARNING(( "missing shred %ld at index %ld for slot %ld", i, index, slot ));
      rocksdb_iter_destroy( iter );
      return -1;
    }

    size_t dlen = 0;
    // Data was first copied from disk into memory to make it available to this API
    const unsigned char *data = (const unsigned char *) rocksdb_iter_value( iter, &dlen );
    if ( data == NULL ) {
      FD_LOG_WARNING(( "failed to read shred %ld/%ld", slot, i ));
      rocksdb_iter_destroy( iter );
      return -1;
    }

    fd_shred_t const * shred = fd_shred_parse( data, (ulong) dlen );
    if ( shred == NULL ) {
      FD_LOG_WARNING(( "failed to parse shred %ld/%ld", slot, i ));
      rocksdb_iter_destroy( iter );
      return -1;
    }

    /* Write a shred header and shred. Each shred and it's header will be aligned */
    char shred_buf[ FD_SHREDCAP_SHRED_MAX ];
    char * shred_buf_ptr = shred_buf;
    ushort shred_sz = (ushort)fd_shred_sz( shred );
    uint shred_boundary_sz = (uint)fd_uint_align_up( shred_sz + FD_SHREDCAP_SHRED_HDR_FOOTPRINT,
                                                     FD_SHREDCAP_ALIGN ) - FD_SHREDCAP_SHRED_HDR_FOOTPRINT;

    fd_memset( shred_buf_ptr, 0, shred_boundary_sz );
    /* Populate start of buffer with header */
    fd_shredcap_shred_hdr_t * shred_hdr = (fd_shredcap_shred_hdr_t*)shred_buf_ptr;
    shred_hdr->hdr_sz            = FD_SHREDCAP_SHRED_HDR_FOOTPRINT;
    shred_hdr->shred_sz          = shred_sz;
    shred_hdr->shred_boundary_sz = shred_boundary_sz;

    /* Skip ahead and populate rest of buffer with shred and write out */
    fd_memcpy( shred_buf_ptr + FD_SHREDCAP_SHRED_HDR_FOOTPRINT, shred, shred_boundary_sz );
    fd_io_buffered_ostream_write( ostream, shred_buf_ptr,
                                  shred_boundary_sz + FD_SHREDCAP_SHRED_HDR_FOOTPRINT );

    payload_sz += shred_boundary_sz + FD_SHREDCAP_SHRED_HDR_FOOTPRINT;
    rocksdb_iter_next( iter );
  }

  /* Update file size */
  long pre_slot_processed_file_offset = lseek( ostream->fd, 0, SEEK_CUR );
  if ( FD_UNLIKELY( pre_slot_processed_file_offset == -1 ) ) {
    FD_LOG_ERR(( "lseek error when seeking to current position" ));
  }

  if ( FD_UNLIKELY( pre_slot_processed_file_offset == pre_slot_hdr_file_offset ) ) {
    /* This case is when the payload from the shreds is smaller than the free
       space from the write buffer. This means that the buffer was not flushed
       at any point. This case is highly unlikely */
    fd_io_buffered_ostream_flush( ostream );
  }

  /* Safely assume that the buffer was flushed to the file at least once. Store
     original seek position, skip to position with payload_sz in header, write
     updated payload sz, and then reset seek position. */
  long original_offset = lseek( ostream->fd, 0, SEEK_CUR );
  if ( FD_UNLIKELY( original_offset == -1 ) ) {
    FD_LOG_ERR(( "lseek error when seeking to current position" ));
  }
  long payload_sz_file_offset = pre_slot_hdr_file_offset_real +
                                (long)FD_SHREDCAP_SLOT_HDR_PAYLOAD_SZ_OFFSET;

  long offset;
  offset = lseek( ostream->fd, payload_sz_file_offset, SEEK_SET );
  if ( FD_UNLIKELY( offset == -1 ) ) {
    FD_LOG_ERR(( "lseek error when seeking to offset=%ld", payload_sz_file_offset ));
  }
  ulong to_write;
  fd_io_write( ostream->fd, &payload_sz, sizeof(ulong), sizeof(ulong), &to_write );

  offset = lseek( ostream->fd, original_offset, SEEK_SET );
  if ( FD_UNLIKELY( offset == -1 ) ) {
    FD_LOG_ERR(( "lseek error when seeking to offset=%ld", original_offset ));
  }

  /* Write slot footer */
  fd_shredcap_slot_ftr_t slot_ftr;
  slot_ftr.magic      = FD_SHREDCAP_SLOT_FTR_MAGIC;
  slot_ftr.payload_sz = payload_sz;
  fd_io_buffered_ostream_write( ostream, &slot_ftr, FD_SHREDCAP_SLOT_FTR_FOOTPRINT );
  rocksdb_iter_destroy( iter );

  /* Get and write bank hash information to respective file */
  size_t vallen = 0;
  char * err = NULL;
  char * res = rocksdb_get_cf( db->db, db->ro, db->cf_handles[ FD_ROCKSDB_CFIDX_BANK_HASHES ],
               (char const *)&slot_be, sizeof(ulong), &vallen, &err );
  if( FD_UNLIKELY( err ) ) {
    FD_LOG_WARNING((" Could not get bank hash data due to err=%s",err ));
    free( err );
  } else {
    fd_scratch_push();
    fd_bincode_decode_ctx_t decode = {
      .data    = res,
      .dataend = res + vallen,
      .valloc  = fd_scratch_virtual(),
    };
    fd_frozen_hash_versioned_t versioned;
    int decode_err = fd_frozen_hash_versioned_decode( &versioned, &decode );
    if( FD_UNLIKELY( decode_err != FD_BINCODE_SUCCESS ) ) goto cleanup;
    if( FD_UNLIKELY( decode.data!=decode.dataend    ) ) goto cleanup;
    if( FD_UNLIKELY( versioned.discriminant != fd_frozen_hash_versioned_enum_current ) ) goto cleanup;

    fd_shredcap_bank_hash_entry_t bank_hash_entry;
    bank_hash_entry.slot = slot;
    fd_memcpy( &bank_hash_entry.bank_hash, versioned.inner.current.frozen_hash.hash, 32UL );
    fd_io_buffered_ostream_write( bank_hash_ostream, &bank_hash_entry, FD_SHREDCAP_BANK_HASH_ENTRY_FOOTPRINT );
  cleanup:
    free( res );
    fd_scratch_pop();
  }
  return 0;
}
