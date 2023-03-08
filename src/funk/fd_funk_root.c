// Control block size
#define FD_FUNK_CONTROL_SIZE (2UL<<20) /* 2 MB */

// An entry in an on-disk control block, describing the state of a disk allocation
struct fd_funk_control_entry {
    union {
        // Entry is unused
        struct {
            int dummy;
        } empty;
        // Entry points to record data
        struct {
            // Record identifier
            struct fd_funk_recordid id;
            // Offset into file for content.
            ulong start;
            // Length of content. Must be <= FD_FUNK_MAX_ENTRY_SIZE.
            uint size;
            // Length of disk allocation. Must be <= FD_FUNK_MAX_ENTRY_SIZE.
            uint alloc;
            // Version of this record. Used to disambiguate multiple
            // versions of the same record caused by an ill-timed
            // crash.
            uint version;
        } normal;
        // A dead record that can be reused.
        struct {
            // Offset into file for content.
            ulong start;
            // Length of disk allocation
            uint alloc;
        } dead;
        // A write-ahead log for a transaction
        struct {
            // Transaction identifier
            struct fd_funk_xactionid id;
            // Parent transaction identifier
            struct fd_funk_xactionid parent;
            // Offset into file for content.
            ulong start;
            // Length of content
            uint size;
            // Length of disk allocation
            uint alloc;
        } xaction;
    } u;
    uint type;
#define FD_FUNK_CONTROL_EMPTY 0   // Unused control entry ("empty")
#define FD_FUNK_CONTROL_NORMAL 1  // Control entry for a normal record ("normal")
#define FD_FUNK_CONTROL_DEAD 2    // Control entry for a dead record ("dead")
#define FD_FUNK_CONTROL_XACTION 3 // Control entry for transaction write-ahead log ("xaction")
};

// Control blocks are allocated as a unit with a bunch of entries at once
#define FD_FUNK_ENTRIES_IN_CONTROL (FD_FUNK_CONTROL_SIZE/128)
struct fd_funk_control {
    // Make sure control entries don't cross block boundaries
    struct {
        struct fd_funk_control_entry entry;
        union {
            char pad[128 - sizeof(struct fd_funk_control_entry)];
            ulong next_control;
        } u;
    } entries[FD_FUNK_ENTRIES_IN_CONTROL];
};
// Disk offset of next control block in chain
#define FD_FUNK_CONTROL_NEXT(_ctrl_) (_ctrl_.entries[0].u.next_control)

// Round up a size to a valid disk allocation size. Returns zero on
// failure.
uint fd_funk_disk_size(ulong rawsize, ulong* index) {
  // These are all the allowed disk allocation sizes. These include
  // sizes much larger than the max record size because write-ahead
  // logs can include several giant records at once and exceed the
  // max size of a single record. Also, disk allocations are aligned
  // at 128 bytes to make sure that control records never cross
  // physical disk block boundaries.
  // This list was generated with this python code:
  //   l = []
  //   for i in range(1,10):
  //     l.append(i*128)
  //   while l[-1] < 100000000:
  //     l.append((int(l[-1]*1.3)+127)&~127)

  static const uint ALLSIZES[FD_FUNK_NUM_DISK_SIZES] = {
    128, 256, 384, 512, 640, 768, 896, 1024, 1152, 1536, 2048,
    2688, 3584, 4736, 6272, 8192, 10752, 14080, 18304, 23808, 30976,
    40320, 52480, 68224, 88704, 115328, 150016, 195072, 253696, 329856,
    428928, 557696, 725120, 942720, 1225600, 1593344, 2071424, 2692864,
    3500800, 4551040, 5916416, 7691392, 9998848, 12998528, 16898176,
    21967744, 28558080, 37125504, 48263168, 62742144, 81564800, 106034304
  };
  ulong i = 0;
  // Quickly skip ahead to speed up the search, but the vast majority
  // of allocations are small in practice.
  while (i+4 < FD_FUNK_NUM_DISK_SIZES && rawsize >= ALLSIZES[i+4])
    i += 4;
  // More meticulous search
  for (;;) {
    if (rawsize <= ALLSIZES[i]) {
      *index = i;
      return ALLSIZES[i];
    }
    if (++i == FD_FUNK_NUM_DISK_SIZES)
      return 0U;
  }
}

// Force a control entry to be dead and add the allocation to the free list
void fd_funk_make_dead(struct fd_funk* store, ulong control, ulong start, uint alloc) {
  // Get the index for the allocation size
  ulong k = 0;
  ulong rsize = fd_funk_disk_size(alloc, &k);
  if (rsize != alloc) {
    FD_LOG_WARNING(("invalid record allocation in store"));
    return;
  }
  // Update deads lists. Every allocation size has its own list.
  struct fd_funk_dead_entry de;
  de.control = control;
  de.start = start;
  fd_funk_vec_dead_entry_push(&store->deads[k], de);
  // Update control on disk. This is atomic because it is aligned on block boundaries
  struct fd_funk_control_entry de2;
  fd_memset(&de2, 0, sizeof(de2));
  de2.type = FD_FUNK_CONTROL_DEAD;
  de2.u.dead.alloc = alloc;
  de2.u.dead.start = start;
  if (pwrite(store->backing_fd, &de2, sizeof(de2), (long)control) < (long)sizeof(de2)) {
    FD_LOG_WARNING(("failed to write backing file: %s", strerror(errno)));
  }
}

// Replay the control blocks on disk. Build the in-memory index and
// other data structures.
void fd_funk_replay_root(struct fd_funk* store) {
  FD_STATIC_ASSERT(sizeof(struct fd_funk_control_entry) <= 120,fd_funk);
  FD_STATIC_ASSERT(sizeof(struct fd_funk_control) == FD_FUNK_CONTROL_SIZE,fd_funk);

  // See if it's a new file
  struct fd_funk_control ctrl;
  FD_STATIC_ASSERT(sizeof(ctrl.entries[0]) == 128,fd_funk);
  if (store->backing_sz < sizeof(ctrl)) {
    // Initialize with an all-empty control block
    fd_memset(&ctrl, 0, sizeof(ctrl));
    if (pwrite(store->backing_fd, &ctrl, sizeof(ctrl), 0) < (long)sizeof(ctrl)) {
      FD_LOG_ERR(("failed to initialize store: %s", strerror(errno)));
    }
  }

  // First control block is always at position zero
  store->lastcontrol = 0;
  for (;;) {
    // Read the control block
    if (pread(store->backing_fd, &ctrl, sizeof(ctrl), (long)store->lastcontrol) < (long)sizeof(ctrl)) {
      FD_LOG_ERR(("failed to read backing file: %s", strerror(errno)));
      break;
    }
    // Make sure backing_sz is correct
    if (store->lastcontrol + sizeof(ctrl) > store->backing_sz)
      store->backing_sz = store->lastcontrol + sizeof(ctrl);

    // Loop through the control entries
    for (ulong i = 0; i < FD_FUNK_ENTRIES_IN_CONTROL; ++i) {
      struct fd_funk_control_entry* ent = &ctrl.entries[i].entry;
      // Compute file position of control entry so we can update it later
      ulong entpos = store->lastcontrol + (ulong)((char*)ent - (char*)&ctrl);
        
      if (ent->type == FD_FUNK_CONTROL_NORMAL) {
        // Account for gaps at the end
        if (ent->u.normal.start + ent->u.normal.alloc > store->backing_sz)
          store->backing_sz = ent->u.normal.start + ent->u.normal.alloc;
        // Insert the entry in the master index
        int exists;
        struct fd_funk_index_entry* ent2 = fd_funk_index_insert(store->index, &ent->u.normal.id, &exists);
        if (NULL == ent2) 
          FD_LOG_ERR(("index insert failed during recovery. make the index larger and try again."));
        if (exists) {
          // Resolve duplicate records caused by a crash at the wrong time
          FD_LOG_WARNING(("duplicate record id in store"));
          // Keep the later version. Delete the older one.
          if (ent2->version > ent->u.normal.version) {
            fd_funk_make_dead(store, entpos, ent->u.normal.start, ent->u.normal.alloc);
            // Leave ent2 alone
            continue;
          } else {
            fd_funk_make_dead(store, ent2->control, ent2->start, ent2->alloc);
            // Update ent2 below
          }
        }

        // Initialize the index entry
        ent2->start = ent->u.normal.start;
        ent2->size = ent->u.normal.size;
        ent2->alloc = ent->u.normal.alloc;
        ent2->version = ent->u.normal.version;
        ent2->control = entpos;
        ent2->cachehandle = FD_CACHE_INVALID_HANDLE;

      } else if (ent->type == FD_FUNK_CONTROL_DEAD) {
        // Account for gaps at the end
        if (ent->u.dead.start + ent->u.dead.alloc > store->backing_sz)
          store->backing_sz = ent->u.dead.start + ent->u.dead.alloc;
        // Get the index for the allocation size
        ulong k = 0;
        ulong rsize = fd_funk_disk_size(ent->u.dead.alloc, &k);
        if (rsize != ent->u.dead.alloc) {
          FD_LOG_WARNING(("invalid record allocation in store"));
          continue;
        }
        // Remember the dead entry so we can reuse it later
        struct fd_funk_dead_entry de;
        de.control = entpos;
        de.start = ent->u.dead.start;
        fd_funk_vec_dead_entry_push(&store->deads[k], de);

      } else if (ent->type == FD_FUNK_CONTROL_EMPTY) {
        // Unused control entry
        fd_vec_ulong_push(&store->free_ctrl, entpos);

      } else if (ent->type == FD_FUNK_CONTROL_XACTION) {
        // Account for gaps at the end
        if (ent->u.xaction.start + ent->u.xaction.alloc > store->backing_sz)
          store->backing_sz = ent->u.xaction.start + ent->u.xaction.alloc;
        // Write-ahead log entry
        char* script = fd_alloc_malloc(store->alloc, 1, ent->u.xaction.size);
        if (pread(store->backing_fd, script, ent->u.xaction.size, (long)ent->u.xaction.start) < (long)ent->u.xaction.size) {
          FD_LOG_ERR(("failed to read backing file: %s", strerror(errno)));
          break;
        }
        // Store the entry in the transaction table
        fd_funk_writeahead_load(store,
                                &ent->u.xaction.id,
                                &ent->u.xaction.parent,
                                ent->u.xaction.start,
                                ent->u.xaction.size,
                                ent->u.xaction.alloc,
                                entpos,
                                script);
      }
    }

    // Advance to next control block
    ulong next = FD_FUNK_CONTROL_NEXT(ctrl);
    if (!next)
      break;
    store->lastcontrol = next;
  }

  // Commit all transactions that had a write-ahead log entry
  fd_funk_writeahead_recommits(store);
}

// Allocate disk space for a new entry
int fd_funk_allocate_disk(struct fd_funk* store, ulong data_sz, ulong* control, ulong* start, uint* alloc) {
  // Round up to the nearest allocation size
  ulong k = 0;
  *alloc = fd_funk_disk_size(data_sz, &k);
  if (*alloc == 0U) {
    FD_LOG_WARNING(("attempted to allocate too large a disk entry, requested %lu bytes", data_sz));
    return 0;
  }
  
  // Look for a dead control which owns a chunk of disk of the right
  // size. Once a chunk of disk space is carved out, it is permanent.
  struct fd_funk_vec_dead_entry* vec = &store->deads[k];
  if (!fd_funk_vec_dead_entry_empty(vec)) {
    struct fd_funk_dead_entry de = fd_funk_vec_dead_entry_pop_unsafe(vec);
    *control = de.control;
    *start = de.start;
    return 1;
  }

  // We need an empty control entry
  if (fd_vec_ulong_empty(&store->free_ctrl)) {
    // Make a batch of empty controls at the end of the file
    const ulong ctrlpos = store->backing_sz;
    struct fd_funk_control ctrl;
    fd_memset(&ctrl, 0, sizeof(ctrl));
    if (pwrite(store->backing_fd, &ctrl, sizeof(ctrl), (long)ctrlpos) < (long)sizeof(ctrl)) {
      FD_LOG_WARNING(("failed to write store: %s", strerror(errno)));
      return 0;
    }
    store->backing_sz = ctrlpos + sizeof(ctrl);
    for (ulong i = 0; i < FD_FUNK_ENTRIES_IN_CONTROL; ++i) {
      struct fd_funk_control_entry* ent = &ctrl.entries[i].entry;
      // Compute file position of control entry
      ulong entpos = ctrlpos + (ulong)((char*)ent - (char*)&ctrl);
      fd_vec_ulong_push(&store->free_ctrl, entpos);
    }
    // Chain together control blocks
    long offset = (char*)(&FD_FUNK_CONTROL_NEXT(ctrl)) - (char*)&ctrl;
    if (pwrite(store->backing_fd, &ctrlpos, sizeof(ctrlpos), (long)store->lastcontrol + offset) < (long)sizeof(ctrlpos)) {
      FD_LOG_WARNING(("failed to write store: %s", strerror(errno)));
      return 0;
    }
    store->lastcontrol = ctrlpos;
  }

  // Grow the file to create new space
  *control = fd_vec_ulong_pop_unsafe(&store->free_ctrl);
  *start = store->backing_sz;
  store->backing_sz += *alloc;
  return 1;
}

// Update an on-disk control to correspond to the index
void fd_funk_update_control_from_index(struct fd_funk* store,
                                       struct fd_funk_index_entry* ent) {
  // Write out the control atomically
  struct fd_funk_control_entry ctrl;
  fd_memset(&ctrl, 0, sizeof(ctrl));
  ctrl.type = FD_FUNK_CONTROL_NORMAL;
  fd_funk_recordid_t_copy(&ctrl.u.normal.id, &ent->key);
  ctrl.u.normal.start = ent->start;
  ctrl.u.normal.size = ent->size;
  ctrl.u.normal.alloc = ent->alloc;
  ctrl.u.normal.version = ent->version;
  if (pwrite(store->backing_fd, &ctrl, sizeof(ctrl), (long)ent->control) < (long)sizeof(ctrl)) {
    FD_LOG_WARNING(("failed to write backing file: %s", strerror(errno)));
  }
}

// write operation for the root transaction
long fd_funk_writev_root(struct fd_funk* store,
                         struct fd_funk_recordid const* recordid,
                         struct iovec const * const iov,
                         ulong iovcnt,
                         ulong offset) {
  // Compute sizes
  ulong data_sz = 0;
  for (ulong i = 0; i < iovcnt; ++i)
    data_sz += iov[i].iov_len;
  const ulong new_record_sz = offset + data_sz;
  
  // See if this is a new record. We insert/create the index entry.
  int exists;
  struct fd_funk_index_entry* ent = fd_funk_index_insert(store->index, recordid, &exists);
  if (ent == NULL) {
    FD_LOG_WARNING(("index is full, cannot create a new record"));
    return -1;
  }

  // See if an entry already existed for the record
  if (exists) {
    // Patch the cached data
    uint cache_sz;
    void* cache = fd_cache_lookup(store->cache, ent->cachehandle, &cache_sz);
    if (cache) {
      // Copy one piece at a time
      ulong toffset = offset;
      for (ulong i = 0; i < iovcnt; ++i) {
        if (toffset >= cache_sz)
          break;
        ulong sz = fd_ulong_min(iov[i].iov_len, cache_sz - toffset);
        fd_memcpy((char*)cache + toffset, iov[i].iov_base, sz);
        toffset += sz;
      }
    }
    
    if (new_record_sz <= ent->alloc) {
      // Can update in place without reallocating. Just patch the disk storage
      if (offset > ent->size) {
        // Zero fill gap in disk space
        ulong zeroslen = offset - ent->size;
        char* zeros = fd_alloca(1, zeroslen);
        fd_memset(zeros, 0, zeroslen);
        if (pwrite(store->backing_fd, zeros, zeroslen, (long)(ent->start + ent->size)) < (long)zeroslen) {
          FD_LOG_WARNING(("failed to write backing file: %s", strerror(errno)));
          return -1;
        }
      }
      if (pwritev(store->backing_fd, iov, (int)iovcnt, (long)(ent->start + offset)) < (long)data_sz) {
        FD_LOG_WARNING(("failed to write backing file: %s", strerror(errno)));
        return -1;
      }
      if (ent->size < new_record_sz) {
        // Update the control with the new length as a final, atomic operations.
        ent->size = (uint)new_record_sz;
        fd_funk_update_control_from_index(store, ent);
      }
      return (long)data_sz;
      
    } else {
      // Hard case where we must move and grow the entry at the same
      // time. Create a new record with a new version number
      // first. Ordering is important in case we crash in the
      // middle. It's safe to start by writing out new data into a
      // dead segment.
      uint oldlen = ent->size;
      ulong oldcontrol = ent->control;
      ulong oldstart = ent->start;
      uint oldalloc = ent->alloc;
      if (!fd_funk_allocate_disk(store, new_record_sz, &ent->control, &ent->start, &ent->alloc))
        // Allocation failure
        return -1;
      // Fix the index
      ulong newstart = ent->start;
      ent->size = (uint)new_record_sz;
      ent->version ++;
      // Track how much we have written so far as we cobble together
      // the new record.
      uint done = 0;
      if (cache) {
        // Start by writing out what we cached because this is easy
        // and quick.
        if (pwrite(store->backing_fd, cache, cache_sz, (long)newstart) < (long)cache_sz) {
          FD_LOG_WARNING(("failed to write backing file: %s", strerror(errno)));
          return -1;
        }
        done = cache_sz;
      }
      char* tmpbuf = NULL;
      int tmpbuflen = 0;
      // Copy old data that came before the update
      int beforelen = (int)((offset < oldlen ? offset : oldlen) - done);
      if (beforelen > 0) {
        if (tmpbuf == NULL || beforelen > tmpbuflen) {
          tmpbuf = fd_alloca(1, (uint)beforelen);
          tmpbuflen = beforelen;
        }
        if (pread(store->backing_fd, tmpbuf, (ulong)beforelen, (long)(oldstart + done)) < (long)beforelen) {
          FD_LOG_WARNING(("failed to read backing file: %s", strerror(errno)));
          return -1;
        }
        if (pwrite(store->backing_fd, tmpbuf, (ulong)beforelen, (long)(newstart + done)) < (long)beforelen) {
          FD_LOG_WARNING(("failed to write backing file: %s", strerror(errno)));
          return -1;
        }
        done += (uint)beforelen;
      }
      // Fill gap with zeros if the offset is past the end of the
      // existing record.
      int zeroslen = (int)(offset - done);
      if (zeroslen > 0) {
        if (tmpbuf == NULL || zeroslen > tmpbuflen) {
          tmpbuf = fd_alloca(1, (uint)zeroslen);
          tmpbuflen = zeroslen;
        }
        fd_memset(tmpbuf, 0, (ulong)zeroslen);
        if (pwrite(store->backing_fd, tmpbuf, (ulong)zeroslen, (long)(newstart + done)) < (long)zeroslen) {
          FD_LOG_WARNING(("failed to write backing file: %s", strerror(errno)));
          return -1;
        }
        done += (uint)zeroslen;
      }
      // Write out whatever is left of the original update
      int updatelen = (int)(new_record_sz - done);
      if (updatelen > 0) {
        if (pwritev(store->backing_fd, iov, (int)iovcnt, (long)(newstart + offset)) < (long)data_sz) {
          FD_LOG_WARNING(("failed to write backing file: %s", strerror(errno)));
          return -1;
        }
      }
      // Data is ready. Finally update the new control.
      // Write out the new version first in case we crash in the
      // middle. If duplicate keys are found during recovery, the newer
      // version wins. This update is atomic on disk.
      fd_funk_update_control_from_index(store, ent);
      // Garbage collect old control and disk space
      fd_funk_make_dead(store, oldcontrol, oldstart, oldalloc);
      return (long)data_sz;
    }
    
  } else {
    // Create a new record from scratch.
    if (!fd_funk_allocate_disk(store, new_record_sz, &ent->control, &ent->start, &ent->alloc))
      // Allocation failure
      return -1;
    // Finish initializing the index entry
    ent->size = (uint)new_record_sz;
    ent->version = 1;
    ent->cachehandle = FD_CACHE_INVALID_HANDLE;
    if (offset > 0) {
      // Zero fill gap in disk space in case the initial offset isn't zero
      char* zeros = fd_alloca(1, offset);
      fd_memset(zeros, 0, offset);
      if (pwrite(store->backing_fd, zeros, offset, (long)ent->start) < (long)offset) {
        FD_LOG_WARNING(("failed to write backing file: %s", strerror(errno)));
        return -1;
      }
    }
    if (pwritev(store->backing_fd, iov, (int)iovcnt, (long)(ent->start + offset)) < (long)data_sz) {
      FD_LOG_WARNING(("failed to write backing file: %s", strerror(errno)));
      return -1;
    }
    // Data is in place. Update the control atomically.
    fd_funk_update_control_from_index(store, ent);
    return (long)data_sz;
  }
}

// Get/construct the cache entry for a record. This is part of a read
// operation. "needed_sz" is the desired size of the cache.
fd_cache_handle fd_funk_get_cache_root(struct fd_funk* store,
                                       struct fd_funk_recordid const* recordid,
                                       uint needed_sz,
                                       void** cache_data,
                                       uint* cache_sz,
                                       uint* record_sz) {
  // Find the record in the index
  struct fd_funk_index_entry* ent = fd_funk_index_query(store->index, recordid);
  // See if we got a hit
  if (ent == NULL)
    return FD_CACHE_INVALID_HANDLE;
  // Return the actual record length
  *record_sz = ent->size;
  // Trim needed_sz to reflect the record length
  if (needed_sz > ent->size)
    needed_sz = ent->size;
  // See if the data is already cached and we have what is needed
  *cache_data = fd_cache_lookup(store->cache, ent->cachehandle, cache_sz);
  if (*cache_data == NULL || needed_sz > *cache_sz) {
    // Load the cache. We can cache a prefix rather than the entire
    // record. This is useful if metadata is in front of the real data.
    if (*cache_data != NULL)
      fd_cache_release(store->cache, ent->cachehandle, store->alloc);
    // Allocate fresh cache space
    ent->cachehandle = fd_cache_allocate(store->cache, cache_data, needed_sz, store->alloc);
    *cache_sz = needed_sz;
    // Read from the file
    if (pread(store->backing_fd, *cache_data, needed_sz, (long)ent->start) < (long)needed_sz) {
      FD_LOG_WARNING(("failed to read backing file: %s", strerror(errno)));
      fd_cache_release(store->cache, ent->cachehandle, store->alloc);
      return FD_CACHE_INVALID_HANDLE;
    }
  }
  // Return the cache entry handle
  return ent->cachehandle;
}

int fd_funk_delete_record_root(struct fd_funk* store,
                               struct fd_funk_recordid const* recordid) {

  // Remove the entry from the index
  struct fd_funk_index_entry* ent = fd_funk_index_remove(store->index, recordid);
  if (ent == NULL) {
    // Doesn't exist
    return 0;
  }
  // Release the cached data
  fd_cache_release(store->cache, ent->cachehandle, store->alloc);
  // Force the control to be dead. Allow the disk space to be reused.
  fd_funk_make_dead(store, ent->control, ent->start, ent->alloc);
  return 1;
}

// Get the current number of records
ulong fd_funk_num_records(struct fd_funk* store) {
  return store->index->used;
}

// Write a write-ahead log entry to disk
int fd_funk_writeahead(struct fd_funk* store,
                       struct fd_funk_xactionid const* id,
                       struct fd_funk_xactionid const* parent,
                       char const* script,
                       uint scriptlen,
                       ulong* control,
                       ulong* start,
                       uint* alloc) {
  // Find space for the log
  // !!! A write-ahead log can be much larger than MAX_SIZE. Need to
  // deal with this as a special case.
  if (!fd_funk_allocate_disk(store, scriptlen, control, start, alloc))
    return 0;
  // Write the data
  if (pwrite(store->backing_fd, script, scriptlen, (long)(*start)) < (long)scriptlen) {
    FD_LOG_WARNING(("failed to write backing file: %s", strerror(errno)));
    return 0;
  }
  // Update the control. This has to be atomic.
  struct fd_funk_control_entry ctrl;
  fd_memset(&ctrl, 0, sizeof(ctrl));
  ctrl.type = FD_FUNK_CONTROL_XACTION;
  fd_funk_xactionid_t_copy(&ctrl.u.xaction.id, id);
  fd_funk_xactionid_t_copy(&ctrl.u.xaction.parent, parent);
  ctrl.u.xaction.start = *start;
  ctrl.u.xaction.size = scriptlen;
  ctrl.u.xaction.alloc = *alloc;
  if (pwrite(store->backing_fd, &ctrl, sizeof(ctrl), (long)(*control)) < (long)sizeof(ctrl)) {
    FD_LOG_WARNING(("failed to write backing file: %s", strerror(errno)));
    return 0;
  }
  return 1;
}

// Delete a write-ahead log record
void fd_funk_writeahead_delete(struct fd_funk* store,
                               ulong control,
                               ulong start,
                               uint alloc) {
  fd_funk_make_dead(store, control, start, alloc);
}

void fd_funk_iter_init(struct fd_funk* store,
                       struct fd_funk_index_iter* iter) {
  fd_funk_index_iter_init(store->index, iter);
}

struct fd_funk_recordid const* fd_funk_iter_next(struct fd_funk* store,
                                                 struct fd_funk_index_iter* iter) {
  struct fd_funk_index_entry* entry = fd_funk_index_iter_next(store->index, iter);
  return (entry != NULL ? &entry->key : NULL);
}

// Verify the integrity of the on-disk data structure as well as the
// master index.
void fd_funk_validate_root(struct fd_funk* store) {
  if (!fd_funk_index_validate(store->index))
    FD_LOG_ERR(("index is corrupt"));

  char* scratch = malloc(FD_FUNK_MAX_ENTRY_SIZE);

  ulong normalcnt = 0;
  ulong emptycnt = 0;
  ulong deadcnt[FD_FUNK_NUM_DISK_SIZES];
  fd_memset(deadcnt, 0, sizeof(deadcnt));
  
  struct fd_funk_control ctrl;
  ulong ctrlpos = 0;
  ulong allocpos = 0;
  for (;;) {
    if (pread(store->backing_fd, &ctrl, sizeof(ctrl), (long)ctrlpos) < (long)sizeof(ctrl))
      FD_LOG_ERR(("failed to read backing file: %s", strerror(errno)));
    if (ctrlpos + sizeof(ctrl) > store->backing_sz)
      FD_LOG_ERR(("backing_sz is wrong"));
    if (ctrlpos < allocpos)
      FD_LOG_ERR(("overlapping allocations"));
    allocpos = ctrlpos + sizeof(ctrl);

    // It is an artifact of the way disk is allocated that reversed
    // control order gets all allocations in ascending positional order
    for (int i=FD_FUNK_ENTRIES_IN_CONTROL-1; i >= 0; --i) {
      struct fd_funk_control_entry* ent = &ctrl.entries[i].entry;
      // Compute file position of control entry
      ulong entpos = ctrlpos + (ulong)((char*)ent - (char*)&ctrl);
        
      if (ent->type == FD_FUNK_CONTROL_NORMAL) {
        if (ent->u.normal.start + ent->u.normal.alloc > store->backing_sz)
          FD_LOG_ERR(("backing_sz is wrong"));
        struct fd_funk_index_entry* ent2 = fd_funk_index_query(store->index, &ent->u.normal.id);
        if (ent2 == NULL)
          FD_LOG_ERR(("index missing entry"));
        if (!(ent2->start == ent->u.normal.start ||
              ent2->size == ent->u.normal.size ||
              ent2->alloc == ent->u.normal.alloc ||
              ent2->version == ent->u.normal.version ||
              ent2->control == entpos))
          FD_LOG_ERR(("index is wrong"));
        if (ent->u.normal.size > FD_FUNK_MAX_ENTRY_SIZE ||
            ent->u.normal.size > ent->u.normal.alloc)
          FD_LOG_ERR(("lengths make no sense"));
        ulong k = 0;
        ulong rsize = fd_funk_disk_size(ent->u.normal.alloc, &k);
        if (rsize != ent->u.normal.alloc || k >= FD_FUNK_NUM_DISK_SIZES)
          FD_LOG_ERR(("invalid record allocation in store"));
        uint cache_sz;
        void* cache = fd_cache_lookup(store->cache, ent2->cachehandle, &cache_sz);
        if (cache != NULL) {
          if (cache_sz > ent->u.normal.size)
            FD_LOG_ERR(("cache too large"));
          if (pread(store->backing_fd, scratch, cache_sz, (long)ent->u.normal.start) < (long)cache_sz)
            FD_LOG_ERR(("failed to read backing file: %s", strerror(errno)));
          if (memcmp(scratch, cache, cache_sz) != 0)
            FD_LOG_ERR(("cache is wrong"));
        }
        if (ent->u.normal.start < allocpos)
          FD_LOG_ERR(("overlapping allocations"));
        allocpos = ent->u.normal.start + ent->u.normal.alloc;
        normalcnt++;

      } else if (ent->type == FD_FUNK_CONTROL_DEAD) {
        if (ent->u.dead.start + ent->u.dead.alloc > store->backing_sz)
          FD_LOG_ERR(("backing_sz is wrong"));
        ulong k = 0;
        ulong rsize = fd_funk_disk_size(ent->u.dead.alloc, &k);
        if (rsize != ent->u.dead.alloc || k >= FD_FUNK_NUM_DISK_SIZES)
          FD_LOG_ERR(("invalid record allocation in store"));
        if (ent->u.dead.start < allocpos)
          FD_LOG_ERR(("overlapping allocations"));
        allocpos = ent->u.dead.start + ent->u.dead.alloc;
        deadcnt[k]++;

      } else if (ent->type == FD_FUNK_CONTROL_XACTION) {
        if (ent->u.xaction.start + ent->u.xaction.alloc > store->backing_sz)
          FD_LOG_ERR(("backing_sz is wrong"));
        ulong k = 0;
        ulong rsize = fd_funk_disk_size(ent->u.xaction.alloc, &k);
        if (rsize != ent->u.xaction.alloc || k >= FD_FUNK_NUM_DISK_SIZES)
          FD_LOG_ERR(("invalid record allocation in store"));
        if (ent->u.xaction.start < allocpos)
          FD_LOG_ERR(("overlapping allocations"));
        allocpos = ent->u.xaction.start + ent->u.xaction.alloc;

      } else if (ent->type == FD_FUNK_CONTROL_EMPTY) {
        emptycnt++;

      } else {
        FD_LOG_ERR(("unknown control entry type"));
      }
    }

    ulong next = FD_FUNK_CONTROL_NEXT(ctrl);
    if (!next)
      break;
    ctrlpos = next;
  }

  if (normalcnt != store->index->used)
    FD_LOG_ERR(("wrong count for normal entries"));
  for (uint i = 0; i < FD_FUNK_NUM_DISK_SIZES; ++i) {
    if (deadcnt[i] != store->deads[i].cnt)
      FD_LOG_ERR(("wrong count for dead entries"));
  }
  if (emptycnt != store->free_ctrl.cnt)
    FD_LOG_ERR(("wrong count for free entries"));

  free(scratch);
}
