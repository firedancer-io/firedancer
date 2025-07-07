#include "fd_rocksdb.h"
#include "fd_blockstore.h"
#include "../shredcap/fd_shredcap.h"
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

static void
fd_blockstore_scan_block( fd_blockstore_t * blockstore, ulong slot, fd_block_t * block ) {

  fd_block_micro_t * micros = fd_alloc_malloc( fd_blockstore_alloc( blockstore ),
                                               alignof( fd_block_micro_t ),
                                               sizeof( *micros ) * FD_MICROBLOCK_MAX_PER_SLOT );

  /*
   * Agave decodes precisely one array of microblocks from each batch.
   * As of bincode version 1.3.3, the default deserializer used when
   * decoding a batch in the blockstore allows for trailing bytes to be
   * ignored.
   * https://github.com/anza-xyz/agave/blob/v2.1.0/ledger/src/blockstore.rs#L3764
   */
  uchar allow_trailing = 1UL;

  uchar const * data = fd_blockstore_block_data_laddr( blockstore, block );
  FD_LOG_DEBUG(( "scanning slot %lu, ptr %p, sz %lu", slot, (void *)data, block->data_sz ));

  fd_block_entry_batch_t const * batch_laddr = fd_blockstore_block_batch_laddr( blockstore, block );
  ulong const                    batch_cnt   = block->batch_cnt;

  ulong micros_cnt = 0UL;
  ulong blockoff   = 0UL;
  for( ulong batch_i = 0UL; batch_i < batch_cnt; batch_i++ ) {
    ulong const batch_end_off = batch_laddr[ batch_i ].end_off;
    if( blockoff + sizeof( ulong ) > batch_end_off ) FD_LOG_ERR(( "premature end of batch" ));
    ulong mcount = FD_LOAD( ulong, data + blockoff );
    blockoff += sizeof( ulong );

    /* Loop across microblocks */
    for( ulong mblk = 0; mblk < mcount; ++mblk ) {
      if( blockoff + sizeof( fd_microblock_hdr_t ) > batch_end_off )
        FD_LOG_ERR(( "premature end of batch" ));
      if( micros_cnt < FD_MICROBLOCK_MAX_PER_SLOT ) {
        fd_block_micro_t * m = micros + ( micros_cnt++ );
        m->off               = blockoff;
      }
      fd_microblock_hdr_t * hdr = (fd_microblock_hdr_t *)( data + blockoff );
      blockoff += sizeof( fd_microblock_hdr_t );

      /* Loop across transactions */
      for( ulong txn_idx = 0; txn_idx < hdr->txn_cnt; txn_idx++ ) {
        uchar         txn_out[FD_TXN_MAX_SZ];
        uchar const * raw    = data + blockoff;
        ulong         pay_sz = 0;
        ulong         txn_sz = fd_txn_parse_core( (uchar const *)raw,
                                          fd_ulong_min( batch_end_off - blockoff, FD_TXN_MTU ),
                                          txn_out,
                                          NULL,
                                          &pay_sz );
        if( txn_sz == 0 || txn_sz > FD_TXN_MTU ) {
          FD_LOG_ERR(( "failed to parse transaction %lu in microblock %lu in slot %lu. txn size: %lu",
                        txn_idx,
                        mblk,
                        slot,
                        txn_sz ));
        }

        if( pay_sz == 0UL )
          FD_LOG_ERR(( "failed to parse transaction %lu in microblock %lu in slot %lu",
                        txn_idx,
                        mblk,
                        slot ));

        blockoff += pay_sz;
      }
    }
    if( FD_UNLIKELY( blockoff > batch_end_off ) ) {
      FD_LOG_ERR(( "parser error: shouldn't have been allowed to read past batch boundary" ));
    }
    if( FD_UNLIKELY( blockoff < batch_end_off ) ) {
      if( FD_LIKELY( allow_trailing ) ) {
        FD_LOG_DEBUG(( "ignoring %lu trailing bytes in slot %lu batch %lu", batch_end_off-blockoff, slot, batch_i ));
      }
      if( FD_UNLIKELY( !allow_trailing ) ) {
        FD_LOG_ERR(( "%lu trailing bytes in slot %lu batch %lu", batch_end_off-blockoff, slot, batch_i ));
      }
    }
    blockoff = batch_end_off;
  }

  fd_block_micro_t * micros_laddr =
      fd_alloc_malloc( fd_blockstore_alloc( blockstore ),
                       alignof( fd_block_micro_t ),
                       sizeof( fd_block_micro_t ) * micros_cnt );
  fd_memcpy( micros_laddr, micros, sizeof( fd_block_micro_t ) * micros_cnt );
  block->micros_gaddr = fd_wksp_gaddr_fast( fd_blockstore_wksp( blockstore ), micros_laddr );
  block->micros_cnt   = micros_cnt;

  fd_alloc_free( fd_blockstore_alloc( blockstore ), micros );
}

static int
deshred( fd_blockstore_t * blockstore, ulong slot ) {
  FD_LOG_NOTICE(( "[%s] slot %lu", __func__, slot ));

  // TODO make this update non blocking
  fd_block_map_query_t query[1];
  int err = fd_block_map_prepare( blockstore->block_map, &slot, NULL, query, FD_MAP_FLAG_BLOCKING );
  fd_block_info_t * block_info = fd_block_map_query_ele( query );
  FD_TEST( err == FD_MAP_SUCCESS && block_info->slot == slot && block_info->block_gaddr == 0 );
  /* FIXME duplicate blocks are not supported */

  block_info->ts = fd_log_wallclock();
  ulong shred_cnt = block_info->slot_complete_idx + 1;
  fd_block_map_publish( query );

  ulong block_sz  = 0UL;
  ulong batch_cnt = 0UL;
  fd_shred_t shred_hdr;
  for( uint idx = 0; idx < shred_cnt; idx++ ) {
    fd_shred_key_t key = { slot, idx };
    int err = FD_MAP_ERR_AGAIN;
    while( err == FD_MAP_ERR_AGAIN ) {
      fd_buf_shred_map_query_t query[1] = { 0 };
      err = fd_buf_shred_map_query_try( blockstore->shred_map, &key, NULL, query, 0 );
      if( FD_UNLIKELY( err == FD_MAP_ERR_KEY ) ) FD_LOG_ERR(( "[%s] map missing shred %lu %u while deshredding", __func__, slot, idx ));
      if( FD_UNLIKELY( err == FD_MAP_ERR_CORRUPT ) ) FD_LOG_ERR(( "[%s] map corrupt. shred %lu %u", __func__, slot, idx ));
      if( FD_UNLIKELY( err == FD_MAP_ERR_AGAIN ) ) continue;
      fd_buf_shred_t const * shred = fd_buf_shred_map_query_ele_const( query );
      shred_hdr = shred->hdr;
      err = fd_buf_shred_map_query_test( query );
    }
    FD_TEST( !err );
    block_sz += fd_shred_payload_sz( &shred_hdr );
    if( FD_LIKELY( ( shred_hdr.data.flags & FD_SHRED_DATA_FLAG_SLOT_COMPLETE ) ||
                     shred_hdr.data.flags & FD_SHRED_DATA_FLAG_DATA_COMPLETE ) ) {
      batch_cnt++;
    }
  }

  // alloc mem for the block
  ulong data_off  = fd_ulong_align_up( sizeof(fd_block_t), 128UL );
  ulong shred_off = fd_ulong_align_up( data_off + block_sz, alignof(fd_block_shred_t) );
  ulong batch_off = fd_ulong_align_up( shred_off + (sizeof(fd_block_shred_t) * shred_cnt), alignof(fd_block_entry_batch_t) );
  ulong tot_sz    = batch_off + (sizeof(fd_block_entry_batch_t) * batch_cnt);

  fd_alloc_t * alloc = fd_blockstore_alloc( blockstore );
  fd_wksp_t *  wksp  = fd_blockstore_wksp( blockstore );
  fd_block_t * block = fd_alloc_malloc( alloc, 128UL, tot_sz );
  if( FD_UNLIKELY( !block ) ) {
    FD_LOG_ERR(( "[%s] OOM: failed to alloc block. blockstore needs to hold in memory all blocks for slots >= SMR, so either increase memory or check for issues with publishing new SMRs.", __func__ ));
  }

  fd_memset( block, 0, sizeof(fd_block_t) );

  uchar * data_laddr  = (uchar *)((ulong)block + data_off);
  block->data_gaddr   = fd_wksp_gaddr_fast( wksp, data_laddr );
  block->data_sz      = block_sz;
  fd_block_shred_t * shreds_laddr = (fd_block_shred_t *)((ulong)block + shred_off);
  block->shreds_gaddr = fd_wksp_gaddr_fast( wksp, shreds_laddr );
  block->shreds_cnt   = shred_cnt;
  fd_block_entry_batch_t * batch_laddr = (fd_block_entry_batch_t *)((ulong)block + batch_off);
  block->batch_gaddr = fd_wksp_gaddr_fast( wksp, batch_laddr );
  block->batch_cnt    = batch_cnt;

  ulong off     = 0UL;
  ulong batch_i = 0UL;
  for( uint idx = 0; idx < shred_cnt; idx++ ) {
    // TODO can do this in one iteration with block sz loop... massage with deshredder API
    fd_shred_key_t key        = { slot, idx };
    ulong          payload_sz = 0UL;
    uchar          flags      = 0;
    int err = FD_MAP_ERR_AGAIN;
    while( err == FD_MAP_ERR_AGAIN ) {
      fd_buf_shred_map_query_t query[1] = { 0 };;
      err = fd_buf_shred_map_query_try( blockstore->shred_map, &key, NULL, query, 0 );
      if( FD_UNLIKELY( err == FD_MAP_ERR_AGAIN ) ) continue;
      if( FD_UNLIKELY( err == FD_MAP_ERR_KEY ) ) FD_LOG_ERR(( "[%s] map missing shred %lu %u while deshredding", __func__, slot, idx ));
      if( FD_UNLIKELY( err == FD_MAP_ERR_CORRUPT ) ) FD_LOG_ERR(( "[%s] map corrupt. shred %lu %u", __func__, slot, idx ));
      fd_shred_t const * shred = &fd_buf_shred_map_query_ele_const( query )->hdr;
      memcpy( data_laddr + off, fd_shred_data_payload( shred ), fd_shred_payload_sz( shred ) );

      shreds_laddr[idx].hdr = *shred;
      shreds_laddr[idx].off = off;
      FD_TEST( 0 == memcmp( &shreds_laddr[idx].hdr, shred, sizeof( fd_shred_t ) ) );
      FD_TEST( 0 == memcmp( data_laddr + shreds_laddr[idx].off, fd_shred_data_payload( shred ), fd_shred_payload_sz( shred ) ) );

      payload_sz = fd_shred_payload_sz( shred );
      flags      = shred->data.flags;

      err = fd_buf_shred_map_query_test( query );
    }
    FD_TEST( !err );
    off += payload_sz;
    if( FD_LIKELY( (flags & FD_SHRED_DATA_FLAG_SLOT_COMPLETE) || flags & FD_SHRED_DATA_FLAG_DATA_COMPLETE ) ) {
      batch_laddr[ batch_i++ ].end_off = off;
    }
    // fd_blockstore_shred_remove( blockstore, slot, idx );
  }
  if( FD_UNLIKELY( batch_cnt != batch_i ) ) {
    FD_LOG_ERR(( "batch_cnt(%lu)!=batch_i(%lu) potential memory corruption", batch_cnt, batch_i ));
  }

  fd_blockstore_scan_block( blockstore, slot, block );

  /* Do this last when it's safe */
  FD_COMPILER_MFENCE();

  // TODO make this non blocking
  err = fd_block_map_prepare( blockstore->block_map, &slot, NULL, query, FD_MAP_FLAG_BLOCKING );
  block_info = fd_block_map_query_ele( query );
  FD_TEST( err == FD_MAP_SUCCESS && block_info->slot == slot );

  block_info->block_gaddr          = fd_wksp_gaddr_fast( wksp, block );
  fd_block_micro_t *    micros     = fd_wksp_laddr_fast( wksp, block->micros_gaddr );
  uchar *               data       = fd_wksp_laddr_fast( wksp, block->data_gaddr );
  fd_microblock_hdr_t * last_micro = (fd_microblock_hdr_t *)( data + micros[block->micros_cnt - 1].off );
  memcpy( &block_info->block_hash, last_micro->hash, sizeof( fd_hash_t ) );

  block_info->flags = fd_uchar_clear_bit( block_info->flags, FD_BLOCK_FLAG_RECEIVING );
  block_info->flags = fd_uchar_set_bit( block_info->flags, FD_BLOCK_FLAG_COMPLETED );
  fd_block_map_publish( query );

  return FD_BLOCKSTORE_SUCCESS;
}

void
fd_blockstore_block_allocs_remove( fd_blockstore_t * blockstore,
                                   ulong slot ){
  fd_block_map_query_t query[1] = { 0 };
  ulong block_gaddr             = 0;
  int    err  = FD_MAP_ERR_AGAIN;
  while( err == FD_MAP_ERR_AGAIN ) {
    err = fd_block_map_query_try( blockstore->block_map, &slot, NULL, query, 0 );
    if( FD_UNLIKELY( err == FD_MAP_ERR_AGAIN ) ) continue;
    if( FD_UNLIKELY( err == FD_MAP_ERR_KEY ) ) return; /* slot not found */
    fd_block_info_t * block_info = fd_block_map_query_ele( query );
    if( FD_UNLIKELY( fd_uchar_extract_bit( block_info->flags, FD_BLOCK_FLAG_REPLAYING ) ) ) {
      FD_LOG_WARNING(( "[%s] slot %lu has replay in progress. not removing.", __func__, slot ));
      return;
    }
    block_gaddr  = block_info->block_gaddr;
    err = fd_block_map_query_test( query );
  }

  /* Remove all the allocations relating to a block. */

  fd_wksp_t *  wksp  = fd_blockstore_wksp( blockstore );
  fd_alloc_t * alloc = fd_blockstore_alloc( blockstore );

  fd_block_t *   block   = fd_wksp_laddr_fast( wksp, block_gaddr );

  /* DO THIS FIRST FOR THREAD SAFETY */
  FD_COMPILER_MFENCE();
  //block_info->block_gaddr = 0;

  if( block->micros_gaddr ) fd_alloc_free( alloc, fd_wksp_laddr_fast( wksp, block->micros_gaddr ) );

  fd_alloc_free( alloc, block );
}

int
fd_rocksdb_import_block_blockstore( fd_rocksdb_t *    db,
                                    fd_slot_meta_t *  m,
                                    fd_blockstore_t * blockstore,
                                    const uchar *     hash_override,
                                    fd_valloc_t       valloc ) {
  ulong slot = m->slot;
  ulong start_idx = 0;
  ulong end_idx = m->received;

  rocksdb_iterator_t * iter = rocksdb_create_iterator_cf(db->db, db->ro, db->cf_handles[FD_ROCKSDB_CFIDX_DATA_SHRED]);

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
      FD_LOG_WARNING(("missing shreds for slot %lu", slot));
      rocksdb_iter_destroy(iter);
      return -1;
    }

    if (index != i) {
      FD_LOG_WARNING(("missing shred %lu at index %lu for slot %lu", i, index, slot));
      rocksdb_iter_destroy(iter);
      return -1;
    }

    size_t dlen = 0;
    // Data was first copied from disk into memory to make it available to this API
    const unsigned char *data = (const unsigned char *) rocksdb_iter_value(iter, &dlen);
    if (data == NULL) {
      FD_LOG_WARNING(("failed to read shred %lu/%lu", slot, i));
      rocksdb_iter_destroy(iter);
      return -1;
    }

    // This just correctly selects from inside the data pointer to the
    // actual data without a memory copy
    fd_shred_t const * shred = fd_shred_parse( data, (ulong) dlen );
    if (shred == NULL) {
      FD_LOG_WARNING(("failed to parse shred %lu/%lu", slot, i));
      rocksdb_iter_destroy(iter);
      return -1;
    }
    fd_blockstore_shred_insert( blockstore, shred );
    // if (rc != FD_BLOCKSTORE_SUCCESS_SLOT_COMPLETE && rc != FD_BLOCKSTORE_SUCCESS) {
    //   FD_LOG_WARNING(("failed to store shred %lu/%lu", slot, i));
    //   rocksdb_iter_destroy(iter);
    //   return -1;
    // }

    rocksdb_iter_next(iter);
  }

  rocksdb_iter_destroy(iter);

  fd_block_info_t * block_info = fd_blockstore_block_map_query( blockstore, slot );
  if( FD_LIKELY( block_info && fd_blockstore_shreds_complete( blockstore, slot ) ) ) {
    deshred( blockstore, slot );

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
      block_info->ts = (*(long*)res)*((long)1e9); /* Convert to nanos */
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
    block_info->block_height = 0;
    if( FD_UNLIKELY( err ) ) {
      FD_LOG_WARNING(( "rocksdb: %s", err ));
      free( err );
    } else if(vallen == sizeof(ulong)) {
      block_info->block_height = *(ulong*)res;
      free(res);
    }

    vallen = 0;
    err = NULL;
    if (NULL != hash_override)
      fd_memcpy( block_info->bank_hash.hash, hash_override, 32UL );
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
        fd_bincode_decode_ctx_t decode = {
          .data    = res,
          .dataend = res + vallen
        };
        ulong total_sz = 0UL;
        int decode_err = fd_frozen_hash_versioned_decode_footprint( &decode, &total_sz );

        uchar * mem = fd_valloc_malloc( valloc, fd_frozen_hash_versioned_align(), total_sz );
        if( NULL == mem ) {
          FD_LOG_ERR(( "fd_valloc_malloc failed" ));
        }

        fd_frozen_hash_versioned_t * versioned = fd_frozen_hash_versioned_decode( mem, &decode );
        if( FD_UNLIKELY( decode_err!=FD_BINCODE_SUCCESS ) ) goto cleanup;
        if( FD_UNLIKELY( decode.data!=decode.dataend    ) ) goto cleanup;
        if( FD_UNLIKELY( versioned->discriminant !=fd_frozen_hash_versioned_enum_current ) ) goto cleanup;
        /* Success */
        fd_memcpy( block_info->bank_hash.hash, versioned->inner.current.frozen_hash.hash, 32UL );
      cleanup:
        free( res );
      }
    }
  }

  blockstore->shmem->lps = slot;
  blockstore->shmem->hcs = slot;
  blockstore->shmem->wmk = slot;

  if( FD_LIKELY( block_info ) ) {
    block_info->flags =
      fd_uchar_set_bit(
      fd_uchar_set_bit(
      fd_uchar_set_bit(
      fd_uchar_set_bit(
      fd_uchar_set_bit(
        block_info->flags,
        FD_BLOCK_FLAG_COMPLETED ),
        FD_BLOCK_FLAG_PROCESSED ),
        FD_BLOCK_FLAG_EQVOCSAFE ),
        FD_BLOCK_FLAG_CONFIRMED ),
        FD_BLOCK_FLAG_FINALIZED );
  }

  return 0;
}

int
fd_rocksdb_import_block_shredcap( fd_rocksdb_t *               db,
                                  fd_slot_meta_t *             metadata,
                                  fd_io_buffered_ostream_t *   ostream,
                                  fd_io_buffered_ostream_t *   bank_hash_ostream,
                                  fd_valloc_t                  valloc ) {
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
      FD_LOG_WARNING(( "missing shreds for slot %lu", slot ));
      rocksdb_iter_destroy( iter );
      return -1;
    }

    if ( index != i ) {
      FD_LOG_WARNING(( "missing shred %lu at index %lu for slot %lu", i, index, slot ));
      rocksdb_iter_destroy( iter );
      return -1;
    }

    size_t dlen = 0;
    // Data was first copied from disk into memory to make it available to this API
    const unsigned char *data = (const unsigned char *) rocksdb_iter_value( iter, &dlen );
    if ( data == NULL ) {
      FD_LOG_WARNING(( "failed to read shred %lu/%lu", slot, i ));
      rocksdb_iter_destroy( iter );
      return -1;
    }

    fd_shred_t const * shred = fd_shred_parse( data, (ulong) dlen );
    if ( shred == NULL ) {
      FD_LOG_WARNING(( "failed to parse shred %lu/%lu", slot, i ));
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
    fd_bincode_decode_ctx_t decode = {
      .data    = res,
      .dataend = res + vallen,
    };
    ulong total_sz = 0UL;
    int decode_err = fd_frozen_hash_versioned_decode_footprint( &decode, &total_sz );

    uchar * mem = fd_valloc_malloc( valloc, fd_frozen_hash_versioned_align(), total_sz );

    fd_frozen_hash_versioned_t * versioned = fd_frozen_hash_versioned_decode( mem, &decode );

    if( FD_UNLIKELY( decode_err != FD_BINCODE_SUCCESS ) ) goto cleanup;
    if( FD_UNLIKELY( decode.data!=decode.dataend    ) ) goto cleanup;
    if( FD_UNLIKELY( versioned->discriminant != fd_frozen_hash_versioned_enum_current ) ) goto cleanup;
    fd_shredcap_bank_hash_entry_t bank_hash_entry;
    bank_hash_entry.slot = slot;
    fd_memcpy( &bank_hash_entry.bank_hash, versioned->inner.current.frozen_hash.hash, 32UL );
    fd_io_buffered_ostream_write( bank_hash_ostream, &bank_hash_entry, FD_SHREDCAP_BANK_HASH_ENTRY_FOOTPRINT );
  cleanup:
    free( res );
  }
  return 0;
}
