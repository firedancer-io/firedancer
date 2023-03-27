#include "fd_rocksdb.h"
#include <malloc.h>
#include <stdbool.h>
#include <stdlib.h>
#include "../../util/bits/fd_bits.h"

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

  // This C wrapper is destroying too deeply..   We will accept the leak for now

  //  for (int i = 0; i < 4; i++) {
  //    if (NULL != db->column_family_handles[i]) {
  //      rocksdb_column_family_handle_destroy(db->column_family_handles[i]);
  //      db->column_family_handles[i] = NULL;
  //    }
  //  }
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

ulong fd_rocksdb_first_slot(fd_rocksdb_t *db, char **err) {
  rocksdb_iterator_t* iter = rocksdb_create_iterator_cf(db->db, db->ro, db->column_family_handles[2]);
  rocksdb_iter_seek_to_first(iter);
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

int fd_rocksdb_get_meta(fd_rocksdb_t *db, ulong slot, fd_slot_meta_t *m, fd_alloc_fun_t allocf, void* allocf_arg) {
  ulong ks = fd_ulong_bswap(slot);
  size_t vallen = 0;

  char *err = NULL;
  char *meta = rocksdb_get_cf(
    db->db, db->ro, db->column_family_handles[1], (const char *) &ks, sizeof(ks), &vallen, &err);

  if (NULL != err) {
    FD_LOG_WARNING(( "%s", err ));
    free (err);
    return -2;
  }

  if (0 == vallen) 
    return -1;

  unsigned char *outend = (unsigned char *) &meta[vallen];
  const void * o = meta;

  fd_slot_meta_decode(m, &o, outend, allocf, allocf_arg);

  free(meta);

  return 0;
}

fd_slot_blocks_t * fd_rocksdb_get_microblocks(fd_rocksdb_t *db, fd_slot_meta_t *m, fd_alloc_fun_t allocf,  void* allocf_arg) {
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
  fd_slot_blocks_t *batch = (fd_slot_blocks_t *) allocf(allocf_arg, FD_SLOT_BLOCKS_ALIGN, FD_SLOT_BLOCKS_FOOTPRINT(bufsize));

  fd_slot_blocks_new(batch);

  fd_deshredder_t deshred;
  fd_deshredder_init(&deshred, batch->buffer, bufsize, NULL, 0);

  uchar *next_batch = deshred.buf;

  for (ulong i = start_idx; i < end_idx; i++) {
    ulong cur_slot, index;
    uchar valid = rocksdb_iter_valid(iter);

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
      FD_LOG_WARNING(("missing shred %ld at index %ld for slot %ld", i, index, slot));
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
    long written = fd_deshredder_next( &deshred );

    if ( FD_UNLIKELY ( (written < 0) & (written != -FD_SHRED_EPIPE ) )  ) {
      FD_LOG_ERR(("fd_deshredder_next returned %ld", written));
    }

    if ((written > 0) & ((deshred.result == FD_SHRED_ESLOT) | (deshred.result == FD_SHRED_EBATCH))) {
      ulong mblocks = *((ulong *) next_batch);

      next_batch += sizeof(ulong);

      // We quickly walk through the data structure and figure out how
      // many and how big all the microblocks were.  Then, we can use
      // this to allocate a single giant buffer which holds every
      // microblock in this batch.  Finally, we will link all the
      // batches together as a linked list.  

      // This results in a single call on the allocator per batch
      // instead of a call per microblock.

      // The first 8 bytes of the buffer is either 0 (end of the list)
      // or a pointer to the next entry in the linked list.  The next
      // 4 bytes is the count of microblocks that can be found in this
      // batch blob
      ulong blob_start = FD_BLOB_DATA_START;
      ulong bsz = blob_start;

      // This should be fast since everything should be in the
      // cache.. we DID just read it
      uint mcnt = 0;
      uchar *tptr = next_batch;
      for (ulong idx = 0; idx < mblocks; idx++) {
        fd_microblock_hdr_t * hdr = (fd_microblock_hdr_t *)tptr;
        ulong fp = fd_microblock_footprint( hdr->txn_cnt );
        bsz = fd_ulong_align_up( bsz + blob_start + fp, FD_MICROBLOCK_ALIGN );
        mcnt ++;
        ulong psize = (ulong) (deshred.buf - next_batch);
        ulong sz = fd_microblock_skip( tptr, (ulong) psize);
        if (0UL == sz) {
          FD_LOG_ERR(("deserialization error"));
        }
        tptr += sz;
      }

      if (mcnt > 0) {
        uchar * blob = (uchar *) allocf(allocf_arg, FD_MICROBLOCK_ALIGN, bsz);
        // Yes, a simple linked list...
        if (NULL != batch->last_blob) 
          *((uchar **) batch->last_blob) = blob;
        *((ulong *) blob) = 0;
        batch->last_blob = blob;
        if (NULL == batch->first_blob) 
          batch->first_blob = blob;

        *((uint *) (blob + 8)) = mcnt;
        uchar * blob_ptr = blob + blob_start;

        // Now, we can walk through and lay out all the microblocks and transactions...
        for (ulong idx = 0; idx < mblocks; idx++) {
          fd_microblock_hdr_t * hdr = (fd_microblock_hdr_t *)next_batch;

          void * shblock = fd_microblock_new( blob_ptr, hdr->txn_cnt );
          fd_microblock_t * block = fd_microblock_join( shblock );

          ulong psize = (ulong) (deshred.buf - next_batch);
          // Does memory copy of header, not of data
          ulong microblock_sz = fd_microblock_deserialize( block, next_batch, psize, NULL );
          if (microblock_sz == 0) {
            // Should we return what we have found or should we just fall over?
            FD_LOG_ERR(("deserialization error"));
          }

          // All done
          fd_microblock_leave(shblock);

          // TODO: did we use this field?
          batch->block_cnt++;

          blob_ptr = (uchar *) fd_ulong_align_up((ulong)blob_ptr + fd_microblock_footprint( hdr->txn_cnt ), FD_MICROBLOCK_ALIGN);

          next_batch += microblock_sz;
        } // for (ulong idx = 0; idx < mblocks; idx++)
      } // if (mcnt > 0)
      else {
        // Just update this to the next spot that will be decoded into
        next_batch = deshred.buf;
      }
    } // if ((deshred.result == FD_SHRED_ESLOT) | (deshred.result == FD_SHRED_EBATCH)) 

    rocksdb_iter_next(iter);
  }

  rocksdb_iter_destroy(iter);

  return batch;
}

void fd_slot_blocks_new(fd_slot_blocks_t *b) {
  fd_memset(b, 0, sizeof(*b));
}

void fd_slot_blocks_destroy(fd_slot_blocks_t *b, fd_free_fun_t freef,  void* freef_arg) {
  uchar *blob = b->first_blob;
  while (NULL != blob) {
    uchar *n = *((uchar **) blob);
    freef(freef_arg, blob);
    blob = n;
  }
  fd_memset(b, 0, sizeof(*b));
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
fd_rocksdb_root_iter_seek    ( fd_rocksdb_root_iter_t * self, fd_rocksdb_t * db, ulong slot, fd_slot_meta_t *m, fd_alloc_fun_t allocf, void* allocf_arg ) {
  self->db = db;

  if (NULL == self->iter) 
    self->iter = rocksdb_create_iterator_cf(self->db->db, self->db->ro, self->db->column_family_handles[2]);

  ulong ks = fd_ulong_bswap(slot);

  rocksdb_iter_seek(self->iter, (char *) &ks, sizeof(ks));
  if (!rocksdb_iter_valid(self->iter)) 
    return -1;

  size_t klen = 0;
  const char *key = rocksdb_iter_key(self->iter, &klen); // There is no need to free key
  unsigned long kslot = fd_ulong_bswap(*((unsigned long *) key));

  if (kslot != slot) 
    return -2;

  return fd_rocksdb_get_meta(self->db, slot, m, allocf, allocf_arg);
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
fd_rocksdb_root_iter_next    ( fd_rocksdb_root_iter_t * self, fd_slot_meta_t *m, fd_alloc_fun_t allocf, void* allocf_arg ) {
  if ((NULL == self->db) || (NULL == self->iter))
    return -1;

  if (!rocksdb_iter_valid(self->iter)) 
    return -2;

  rocksdb_iter_next(self->iter);

  if (!rocksdb_iter_valid(self->iter)) 
    return -3;

  size_t klen = 0;
  const char *key = rocksdb_iter_key(self->iter, &klen); // There is no need to free key

  return fd_rocksdb_get_meta(self->db, fd_ulong_bswap(*((unsigned long *) key)), m, allocf, allocf_arg);
}

void 
fd_rocksdb_root_iter_destroy ( fd_rocksdb_root_iter_t * self ) {
  if (NULL != self->iter) {
    rocksdb_iter_destroy(self->iter);
    self->iter = 0;
  }
  self->db = NULL;
}
