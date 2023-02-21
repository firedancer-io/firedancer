#include "fd_rocksdb.h"
#include <malloc.h>
#include <stdbool.h>
#include <stdlib.h>

#ifdef FD_HAS_ROCKSDB

void fd_slot_meta_decode(fd_slot_meta_t* self, void const** data, void const* dataend, fd_alloc_fun_t allocf, FD_FN_UNUSED void* allocf_arg) {
  fd_bincode_uint64_decode(&self->slot, data, dataend);
  fd_bincode_uint64_decode(&self->consumed, data, dataend);
  fd_bincode_uint64_decode(&self->received, data, dataend);
  fd_bincode_uint64_decode(&self->first_shred_timestamp, data, dataend);
  fd_bincode_uint64_decode(&self->last_index, data, dataend);
  fd_bincode_uint64_decode(&self->parent_slot, data, dataend);
  fd_bincode_uint64_decode(&self->num_next_slots, data, dataend);
  if (self->num_next_slots > 0) {
    self->next_slots = (ulong*)(*allocf)(sizeof(ulong)*self->num_next_slots, (8UL), allocf_arg);
    for (ulong i = 0; i < self->num_next_slots; ++i)
      fd_bincode_uint64_decode(self->next_slots + i, data, dataend);
  } else
    self->next_slots = NULL;
  fd_bincode_uint8_decode(&self->is_connected, data, dataend);
  fd_bincode_uint64_decode(&self->num_entry_end_indexes, data, dataend);
  for (ulong i = 0; i < self->num_entry_end_indexes; ++i)
    fd_bincode_uint32_decode(self->entry_end_indexes + i, data, dataend);
}

char * fd_rocksdb_init(fd_rocksdb_t *db, const char *db_name) {
  fd_memset(db, 0, sizeof(fd_rocksdb_t));

  db->opts = rocksdb_options_create();
  db->cfgs[0] = "default";
  db->cfgs[1] = "meta";
  db->cfgs[2] = "root";
  db->cfgs[3] = "data_shred";
  db->cf_options[0] = db->cf_options[1] = db->cf_options[2] = db->cf_options[3] = db->opts;

  char *err = NULL;

  db->db = rocksdb_open_for_read_only_column_families(
    db->opts, db_name, sizeof(db->cfgs) / sizeof(db->cfgs[0]),
      (const char * const *) db->cfgs,
      (const rocksdb_options_t * const*) db->cf_options,
      db->column_family_handles,
      false, &err);

  if (err != NULL) {
    return err;
  }

  db->ro = rocksdb_readoptions_create();

  return NULL;
}

void fd_rocksdb_destroy(fd_rocksdb_t *db) {
  if (db->db != NULL) {
    rocksdb_close(db->db);
    db->db = NULL;
  }

  if (db->ro != NULL) {
    rocksdb_readoptions_destroy(db->ro);
    db->ro = NULL;
  }

  if (db->opts != NULL) {
    rocksdb_options_destroy(db->opts);
    db->opts = NULL;
  }
}

ulong fd_rocksdb_last_slot(fd_rocksdb_t *db, char **err) {
  rocksdb_iterator_t* iter = rocksdb_create_iterator_cf(db->db, db->ro, db->column_family_handles[2]);
  rocksdb_iter_seek_to_last(iter);
  if (!rocksdb_iter_valid(iter)) {
    *err = "db column for root is empty";
    return 0;
  }

  size_t klen = 0;
  const char *key = rocksdb_iter_key(iter, &klen); // There is no need to free key
  unsigned long slot = fd_ulong_bswap(*((unsigned long *) key));
  rocksdb_iter_destroy(iter);
  return slot;
}

void fd_rocksdb_get_meta(fd_rocksdb_t *db, ulong slot, fd_slot_meta_t *m, fd_alloc_fun_t allocf, char **err) {
  ulong ks = fd_ulong_bswap(slot);
  size_t vallen = 0;

  char *meta = rocksdb_get_cf(
    db->db, db->ro, db->column_family_handles[1], (const char *) &ks, sizeof(ks), &vallen, err);

  unsigned char *outend = (unsigned char *) &meta[vallen];
  const void * o = meta;

  fd_slot_meta_decode(m, &o, outend, allocf, NULL);

  free(meta);
}


fd_slot_blocks_t * fd_rocksdb_get_microblocks(fd_rocksdb_t *db, fd_slot_meta_t *m) {
  ulong slot = m->slot;
  ulong start_idx = 0;
  ulong end_idx = m->received;

  rocksdb_iterator_t* iter = rocksdb_create_iterator_cf(db->db, db->ro, db->column_family_handles[3]);

  char k[16];
  *((ulong *) &k[0]) = fd_ulong_bswap(slot);
  *((ulong *) &k[8]) = fd_ulong_bswap(start_idx);

  rocksdb_iter_seek(iter, (const char *) k, sizeof(k));
  // Put valid check for iter up here... to short circut unused memory alloc
  ulong bufsize = m->consumed * 1500;
  fd_slot_blocks_t *batch = aligned_alloc(FD_SLOT_BLOCKS_ALIGN, FD_SLOT_BLOCKS_FOOTPRINT(bufsize));

  // Should we make this "debug only"??
  memset(batch, 0, FD_SLOT_BLOCKS_FOOTPRINT(bufsize));

  fd_slot_blocks_init(batch);

  fd_deshredder_t deshred;
  fd_deshredder_init(&deshred, batch->buffer, bufsize, NULL, 0);

  uchar *next_batch = deshred.buf;

  uchar * empty = NULL;

  for (ulong i = start_idx; i < end_idx; i++) {
    ulong cur_slot, index;
    bool valid = rocksdb_iter_valid(iter);

    if (valid) {
      size_t klen = 0;
      const char *key = rocksdb_iter_key(iter, &klen); // There is no need to free key
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
      FD_LOG_WARNING(("missing shred %ld for slot %ld", i, index));
      rocksdb_iter_destroy(iter);
      return NULL;
    }

    size_t dlen = 0;
    // Data was first copied from disk into memory to make it available to this API
    const unsigned char *data = (const unsigned char *) rocksdb_iter_value(iter, &dlen);
    if (data == NULL) {
      FD_LOG_WARNING(("failed to deserialize shred %ld/%ld", slot, i));
      rocksdb_iter_destroy(iter);
      return NULL;
    }

    // This just correctly selects from inside the data pointer to the
    // actual data without a memory copy
    fd_shred_t const * shred = fd_shred_parse( data, (ulong) dlen );

    FD_LOG_INFO(("shred info: raw_flag: %x, ref: %d, slot_complete: %d, data_complete: %d",
        shred->data.flags,
        shred->data.flags & FD_SHRED_DATA_REF_TICK_MASK,
        (shred->data.flags & FD_SHRED_DATA_FLAG_SLOT_COMPLETE) != 0,
        (shred->data.flags & FD_SHRED_DATA_FLAG_DATA_COMPLETE) != 0
        ));

    /* Refill deshredder with shred.

       We could have created a single shred list with all the shreds
       but that would have involved another memory copy of all the
       data.  Possibly we can investigate the memory guarentees of
       the rocksdb_iter to see what our options are.

       calling fd_deshredder_next adds a few lines of code to be
       executed (which should be in the code cache) in exchange for
       not copying the data an extra time
     */
    fd_shred_t const * const shred_list[1] = { shred };
    deshred.shreds    = shred_list;
    deshred.shred_cnt = 1U;

    /*
      This performs another memory copy, copying the data into the
      batch->buffer
      */
    fd_deshredder_next( &deshred );

    if ((deshred.result == FD_SHRED_ESLOT) | (deshred.result == FD_SHRED_EBATCH)) {
      ulong mblocks = *((ulong *) next_batch);

      FD_LOG_INFO(("found %ld microblocks", mblocks));

      next_batch += sizeof(ulong);

      for (ulong idx = 0; idx < mblocks; idx++) {
        fd_microblock_hdr_t * hdr = (fd_microblock_hdr_t *)next_batch;

        ulong txn_max_cnt = hdr->txn_cnt;

        ulong footprint = fd_microblock_footprint( txn_max_cnt );

        // What allocator should we do here considering we are going to
        // pass these microblocks to executors on different tiles
        // potentally?
        uchar * raw;
        if (0 == txn_max_cnt) {
          if (NULL == empty)
            empty = aligned_alloc(FD_MICROBLOCK_ALIGN, footprint);
          raw = empty;
        } else
          raw = aligned_alloc(FD_MICROBLOCK_ALIGN, footprint);

        void * shblock = fd_microblock_new( raw, txn_max_cnt );
        fd_microblock_t * block = fd_microblock_join( shblock );

        // Does memory copy of header, not of data
        ulong microblock_sz = fd_microblock_deserialize( block, next_batch, (ulong) (deshred.buf - next_batch), NULL );
        if (microblock_sz == 0) {
          // Should we return what we have found or should we just fall over?
          FD_LOG_ERR(("deserialization error"));
        }

        fd_microblock_leave(shblock);

        if (0 != txn_max_cnt) {
          if (batch->block_cnt >= 64) {
            FD_LOG_ERR(("microblock overflow"));
          }
          batch->micro_blocks[batch->block_cnt++] = shblock;
        }
        next_batch += microblock_sz;
      }
      FD_LOG_INFO(("total blocks found so far: %d", batch->block_cnt));
      // We want to assert this?
      // next_batch == deshred.buf;
    }

    rocksdb_iter_next(iter);
  }

  if (NULL != empty)
    free(empty);
  rocksdb_iter_destroy(iter);

  return batch;
}

void fd_slot_blocks_init(fd_slot_blocks_t *b) {
  b->block_cnt = 0;
}

void fd_slot_blocks_destroy(fd_slot_blocks_t *b) {
  for (uint i = 0; i < b->block_cnt; i++) {
    free(b->micro_blocks[i]);
    b->micro_blocks[i] = 0;
  }
  b->block_cnt = 0;
}

#endif
