// Control block size
#define FD_FUNK_CONTROL_SIZE (64UL<<10)

struct fd_funk_control_entry {
    union {
        struct {
            int dummy;
        } empty;
        struct {
            // Record identifier
            struct fd_funk_recordid id;
            // Offset into file for content.
            ulong start;
            // Length of content
            uint len;
            // Length of disk allocation
            uint alloc;
            // Version of this record
            uint version;
        } normal;
        struct {
            // Offset into file for content.
            ulong start;
            // Length of disk allocation
            uint alloc;
        } dead;
    } u;
    uint type;
#define FD_FUNK_CONTROL_EMPTY 0 // Unused control entry
#define FD_FUNK_CONTROL_NORMAL 1 // Control entry for a normal record
#define FD_FUNK_CONTROL_DEAD 2 // Control entry for a dead record
};

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
#define FD_FUNK_CONTROL_NEXT(_ctrl_) (_ctrl_.entries[0].u.next_control)

// Round up a size to a valid disk allocation size
uint fd_funk_disk_size(ulong rawsize, uint* index) {
  static const uint ALLSIZES[FD_FUNK_NUM_DISK_SIZES] = {
    128, 256, 384, 512, 640, 768, 896, 1024, 1152, 1280, 1664, 2176, 2944, 3840,
    4992, 6528, 8576, 11264, 14720, 19200, 24960, 32512, 42368, 55168, 71808, 93440,
    121472, 157952, 205440, 267136, 347392, 451712, 587264, 763520, 992640, 1290496,
    1677696, 2181120, 2835456, 3686144, 4792064, 6229760, 8098688, FD_FUNK_MAX_ENTRY_SIZE
  };
  uint i = 0;
  while (i+4 < FD_FUNK_NUM_DISK_SIZES && rawsize >= ALLSIZES[i+4])
    i += 4;
  while (i+1 < FD_FUNK_NUM_DISK_SIZES && rawsize > ALLSIZES[i])
    i += 1;
  *index = i;
  return ALLSIZES[i];
}

void fd_funk_make_dead(struct fd_funk* store, ulong control, ulong start, uint alloc) {
  uint k;
  ulong rsize = fd_funk_disk_size(alloc, &k);
  if (rsize != alloc) {
    FD_LOG_WARNING(("invalid record allocation in store"));
    return;
  }
  // Update deads lists
  struct fd_funk_dead_entry de;
  de.control = control;
  de.start = start;
  fd_funk_vec_dead_entry_push(&store->deads[k], de);
  // Update control on disk
  struct fd_funk_control_entry de2;
  fd_memset(&de2, 0, sizeof(de2));
  de2.type = FD_FUNK_CONTROL_DEAD;
  de2.u.dead.alloc = alloc;
  de2.u.dead.start = start;
  if (pwrite(store->backingfd, &de2, sizeof(de2), (long)control) < (long)sizeof(de2)) {
    FD_LOG_WARNING(("failed to write backing file: %s", strerror(errno)));
  }
}

void fd_funk_replay_root(struct fd_funk* store) {
  FD_STATIC_ASSERT(sizeof(struct fd_funk_control_entry) <= 120,fd_funk);
  FD_STATIC_ASSERT(sizeof(struct fd_funk_control) == FD_FUNK_CONTROL_SIZE,fd_funk);

  struct fd_funk_control ctrl;
  FD_STATIC_ASSERT(sizeof(ctrl.entries[0]) == 128,fd_funk);
  if (store->backinglen < sizeof(ctrl)) {
    // Initialize with an empty control block
    fd_memset(&ctrl, 0, sizeof(ctrl));
    if (pwrite(store->backingfd, &ctrl, sizeof(ctrl), 0) < (long)sizeof(ctrl)) {
      FD_LOG_ERR(("failed to initialize store: %s", strerror(errno)));
    }
  }

  // First control block is always at zero
  store->lastcontrol = 0;
  for (;;) {
    if (pread(store->backingfd, &ctrl, sizeof(ctrl), (long)store->lastcontrol) < (long)sizeof(ctrl)) {
      FD_LOG_WARNING(("failed to read backing file: %s", strerror(errno)));
      break;
    }
    if (store->lastcontrol + sizeof(ctrl) > store->backinglen)
      store->backinglen = store->lastcontrol + sizeof(ctrl);

    for (ulong i = 0; i < FD_FUNK_ENTRIES_IN_CONTROL; ++i) {
      struct fd_funk_control_entry* ent = &ctrl.entries[i].entry;
      // Compute file position of control entry
      ulong entpos = store->lastcontrol + (ulong)((char*)ent - (char*)&ctrl);
        
      if (ent->type == FD_FUNK_CONTROL_NORMAL) {
        // Account for gaps at the end
        if (ent->u.normal.start + ent->u.normal.alloc > store->backinglen)
          store->backinglen = ent->u.normal.start + ent->u.normal.alloc;
        int exists;
        struct fd_funk_index_entry* ent2 = fd_funk_index_insert(store->index, &ent->u.normal.id, &exists);
        if (exists) {
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
          
        ent2->start = ent->u.normal.start;
        ent2->len = ent->u.normal.len;
        ent2->alloc = ent->u.normal.alloc;
        ent2->version = ent->u.normal.version;
        ent2->control = entpos;
        ent2->cachehandle = FD_CACHE_INVALID_HANDLE;

      } else if (ent->type == FD_FUNK_CONTROL_DEAD) {
        // Account for gaps at the end
        if (ent->u.dead.start + ent->u.dead.alloc > store->backinglen)
          store->backinglen = ent->u.dead.start + ent->u.dead.alloc;
        uint k;
        ulong rsize = fd_funk_disk_size(ent->u.dead.alloc, &k);
        if (rsize != ent->u.dead.alloc) {
          FD_LOG_WARNING(("invalid record allocation in store"));
          continue;
        }
        struct fd_funk_dead_entry de;
        de.control = entpos;
        de.start = ent->u.dead.start;
        fd_funk_vec_dead_entry_push(&store->deads[k], de);

      } else if (ent->type == FD_FUNK_CONTROL_EMPTY) {
        fd_vec_ulong_push(&store->free_ctrl, entpos);
      }
    }

    ulong next = FD_FUNK_CONTROL_NEXT(ctrl);
    if (!next)
      break;
    store->lastcontrol = next;
  }
}

int fd_funk_allocate_disk(struct fd_funk* store, ulong datalen, ulong* control, ulong* start, uint* alloc) {
  uint k;
  *alloc = fd_funk_disk_size(datalen, &k);
  if (datalen > *alloc) {
    FD_LOG_WARNING(("entry too large"));
    return 0;
  }
  
  // Look for a dead control which owns a chunk of disk of the right size
  struct fd_funk_vec_dead_entry* vec = &store->deads[k];
  if (!fd_funk_vec_dead_entry_empty(vec)) {
    struct fd_funk_dead_entry de = fd_funk_vec_dead_entry_pop_unsafe(vec);
    *control = de.control;
    *start = de.start;
    return 1;
  }
  
  if (fd_vec_ulong_empty(&store->free_ctrl)) {
    // Make a batch of empty controls
    const ulong ctrlpos = store->backinglen;
    struct fd_funk_control ctrl;
    fd_memset(&ctrl, 0, sizeof(ctrl));
    if (pwrite(store->backingfd, &ctrl, sizeof(ctrl), (long)ctrlpos) < (long)sizeof(ctrl)) {
      FD_LOG_WARNING(("failed to write store: %s", strerror(errno)));
      return 0;
    }
    store->backinglen = ctrlpos + sizeof(ctrl);
    for (ulong i = 0; i < FD_FUNK_ENTRIES_IN_CONTROL; ++i) {
      struct fd_funk_control_entry* ent = &ctrl.entries[i].entry;
      // Compute file position of control entry
      ulong entpos = ctrlpos + (ulong)((char*)ent - (char*)&ctrl);
      fd_vec_ulong_push(&store->free_ctrl, entpos);
    }
    // Chain together control blocks
    long offset = (char*)(&FD_FUNK_CONTROL_NEXT(ctrl)) - (char*)&ctrl;
    if (pwrite(store->backingfd, &ctrlpos, sizeof(ctrlpos), (long)store->lastcontrol + offset) < (long)sizeof(ctrlpos)) {
      FD_LOG_WARNING(("failed to write store: %s", strerror(errno)));
      return 0;
    }
    store->lastcontrol = ctrlpos;
  }

  // Grow the file
  *control = fd_vec_ulong_pop_unsafe(&store->free_ctrl);
  *start = store->backinglen;
  store->backinglen += *alloc;
  return 1;
}

void fd_funk_update_control_from_index(struct fd_funk* store,
                                       struct fd_funk_index_entry* ent) {
  struct fd_funk_control_entry ctrl;
  fd_memset(&ctrl, 0, sizeof(ctrl));
  ctrl.type = FD_FUNK_CONTROL_NORMAL;
  fd_funk_recordid_t_copy(&ctrl.u.normal.id, &ent->key);
  ctrl.u.normal.start = ent->start;
  ctrl.u.normal.len = ent->len;
  ctrl.u.normal.alloc = ent->alloc;
  ctrl.u.normal.version = ent->version;
  if (pwrite(store->backingfd, &ctrl, sizeof(ctrl), (long)ent->control) < (long)sizeof(ctrl)) {
    FD_LOG_WARNING(("failed to write backing file: %s", strerror(errno)));
  }
}

long fd_funk_write_root(struct fd_funk* store,
                        struct fd_funk_recordid const* recordid,
                        const void* data,
                        ulong offset,
                        ulong datalen) {
  const ulong newlen = offset + datalen;
  // See if this is a new record
  int exists;
  struct fd_funk_index_entry* ent = fd_funk_index_insert(store->index, recordid, &exists);
  if (ent == NULL) {
    FD_LOG_WARNING(("index is full, cannot create a new record"));
    return -1;
  }
  
  if (exists) {
    // Patch the cache
    uint cachelen;
    void* cache = fd_cache_lookup(store->cache, ent->cachehandle, &cachelen);
    if (cache && offset < cachelen)
      fd_memcpy((char*)cache + offset, data,
                (datalen <= cachelen - offset ? datalen : cachelen - offset));
    
    if (newlen <= ent->alloc) {
      // Can update in place. Just patch the disk storage
      if (offset > ent->len) {
        // Zero fill gap in disk space
        ulong zeroslen = offset - ent->len;
        char* zeros = fd_alloca(1, zeroslen);
        fd_memset(zeros, 0, zeroslen);
        if (pwrite(store->backingfd, zeros, zeroslen, (long)(ent->start + ent->len)) < (long)zeroslen) {
          FD_LOG_WARNING(("failed to write backing file: %s", strerror(errno)));
          return -1;
        }
      }
      if (pwrite(store->backingfd, data, datalen, (long)(ent->start + offset)) < (long)datalen) {
        FD_LOG_WARNING(("failed to write backing file: %s", strerror(errno)));
        return -1;
      }
      if (ent->len < newlen) {
        // Update the control with the new length
        ent->len = (uint)newlen;
        fd_funk_update_control_from_index(store, ent);
      }
      return (long)datalen;
      
    } else {
      // Hard case where we must move and grow the entry at the same
      // time. Create a new record with a new version number first
      uint oldlen = ent->len;
      ulong oldcontrol = ent->control;
      ulong oldstart = ent->start;
      uint oldalloc = ent->alloc;
      if (!fd_funk_allocate_disk(store, newlen, &ent->control, &ent->start, &ent->alloc))
        // Allocation failure
        return -1;
      ulong newstart = ent->start;
      ent->len = (uint)newlen;
      ent->version ++;
      // Track how much we have written so far
      uint done = 0;
      if (cache) {
        // Start by writing out what we cached because this is easy
        if (pwrite(store->backingfd, cache, cachelen, (long)newstart) < (long)cachelen) {
          FD_LOG_WARNING(("failed to write backing file: %s", strerror(errno)));
          return -1;
        }
        done = cachelen;
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
        if (pread(store->backingfd, tmpbuf, (ulong)beforelen, (long)(oldstart + done)) < (long)beforelen) {
          FD_LOG_WARNING(("failed to read backing file: %s", strerror(errno)));
          return -1;
        }
        if (pwrite(store->backingfd, tmpbuf, (ulong)beforelen, (long)(newstart + done)) < (long)beforelen) {
          FD_LOG_WARNING(("failed to write backing file: %s", strerror(errno)));
          return -1;
        }
        done += (uint)beforelen;
      }
      // Fill gap with zeros
      int zeroslen = (int)(offset - done);
      if (zeroslen > 0) {
        if (tmpbuf == NULL || zeroslen > tmpbuflen) {
          tmpbuf = fd_alloca(1, (uint)zeroslen);
          tmpbuflen = zeroslen;
        }
        fd_memset(tmpbuf, 0, (ulong)zeroslen);
        if (pwrite(store->backingfd, tmpbuf, (ulong)zeroslen, (long)(newstart + done)) < (long)zeroslen) {
          FD_LOG_WARNING(("failed to write backing file: %s", strerror(errno)));
          return -1;
        }
        done += (uint)zeroslen;
      }
      // Write out whatever is left of the original update
      int updatelen = (int)(newlen - done);
      if (updatelen > 0) {
        if (pwrite(store->backingfd, (const char*)data + (datalen - (uint)updatelen),
                   (ulong)updatelen, (long)(newstart + done)) < (long)updatelen) {
          FD_LOG_WARNING(("failed to write backing file: %s", strerror(errno)));
          return -1;
        }
      }
      // Data is ready. Finally update the control.
      // Write out the new version first in case we crash in the
      // middle. If duplicate keys are found during recovery, the newer
      // version wins.
      fd_funk_update_control_from_index(store, ent);
      // Collect old control and disk space
      fd_funk_make_dead(store, oldcontrol, oldstart, oldalloc);
      return (long)datalen;
    }
    
  } else {
    // Create a new record
    if (!fd_funk_allocate_disk(store, newlen, &ent->control, &ent->start, &ent->alloc))
      // Allocation failure
      return -1;
    ent->len = (uint)newlen;
    ent->version = 1;
    ent->cachehandle = FD_CACHE_INVALID_HANDLE;
    if (offset > 0) {
      // Zero fill gap in disk space
      char* zeros = fd_alloca(1, offset);
      fd_memset(zeros, 0, offset);
      if (pwrite(store->backingfd, zeros, offset, (long)ent->start) < (long)offset) {
        FD_LOG_WARNING(("failed to write backing file: %s", strerror(errno)));
        return -1;
      }
    }
    if (pwrite(store->backingfd, data, datalen, (long)(ent->start + offset)) < (long)datalen) {
      FD_LOG_WARNING(("failed to write backing file: %s", strerror(errno)));
      return -1;
    }
    // Data is in place. Update the control.
    fd_funk_update_control_from_index(store, ent);
    return (long)datalen;
  }
}

// Get/construct the cache entry for a record
fd_cache_handle fd_funk_get_cache_root(struct fd_funk* store,
                                       struct fd_funk_recordid const* recordid,
                                       uint neededlen,
                                       void** cachedata,
                                       uint* cachelen,
                                       uint* recordlen) {
  struct fd_funk_index_entry* ent = fd_funk_index_query(store->index, recordid);
  // See if we got a hit
  if (ent == NULL)
    return FD_CACHE_INVALID_HANDLE;
  *recordlen = ent->len;
  if (neededlen > ent->len)
    neededlen = ent->len;
  *cachedata = fd_cache_lookup(store->cache, ent->cachehandle, cachelen);
  if (*cachedata == NULL || neededlen > *cachelen) {
    // Load the cache. We can cache a prefix rather than the entire
    // record. This is useful if metadata is in front of the real data.
    if (*cachedata != NULL)
      fd_cache_release(store->cache, ent->cachehandle);
    ent->cachehandle = fd_cache_allocate(store->cache, cachedata, neededlen);
    *cachelen = neededlen;
    if (pread(store->backingfd, *cachedata, neededlen, (long)ent->start) < (long)neededlen) {
      FD_LOG_WARNING(("failed to read backing file: %s", strerror(errno)));
      fd_cache_release(store->cache, ent->cachehandle);
      return FD_CACHE_INVALID_HANDLE;
    }
  }
  return ent->cachehandle;
}

void fd_funk_delete_record_root(struct fd_funk* store,
                                struct fd_funk_recordid const* recordid) {
  
  struct fd_funk_index_entry* ent = fd_funk_index_remove(store->index, recordid);
  if (ent == NULL) {
    // Doesn't exist
    return;
  }
  fd_cache_release(store->cache, ent->cachehandle);
  fd_funk_make_dead(store, ent->control, ent->start, ent->alloc);
}

uint fd_funk_num_records(struct fd_funk* store) {
  return store->index->used;
}

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
    if (pread(store->backingfd, &ctrl, sizeof(ctrl), (long)ctrlpos) < (long)sizeof(ctrl))
      FD_LOG_ERR(("failed to read backing file: %s", strerror(errno)));
    if (ctrlpos + sizeof(ctrl) > store->backinglen)
      FD_LOG_ERR(("backinglen is wrong"));
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
        if (ent->u.normal.start + ent->u.normal.alloc > store->backinglen)
          FD_LOG_ERR(("backinglen is wrong"));
        struct fd_funk_index_entry* ent2 = fd_funk_index_query(store->index, &ent->u.normal.id);
        if (ent2 == NULL)
          FD_LOG_ERR(("index missing entry"));
        if (!(ent2->start == ent->u.normal.start ||
              ent2->len == ent->u.normal.len ||
              ent2->alloc == ent->u.normal.alloc ||
              ent2->version == ent->u.normal.version ||
              ent2->control == entpos))
          FD_LOG_ERR(("index is wrong"));
        if (ent->u.normal.len > FD_FUNK_MAX_ENTRY_SIZE ||
            ent->u.normal.len > ent->u.normal.alloc)
          FD_LOG_ERR(("lengths make no sense"));
        uint k;
        ulong rsize = fd_funk_disk_size(ent->u.normal.alloc, &k);
        if (rsize != ent->u.normal.alloc || k >= FD_FUNK_NUM_DISK_SIZES)
          FD_LOG_ERR(("invalid record allocation in store"));
        uint cachelen;
        void* cache = fd_cache_lookup(store->cache, ent2->cachehandle, &cachelen);
        if (cache != NULL) {
          if (cachelen > ent->u.normal.len)
            FD_LOG_ERR(("cache too large"));
          if (pread(store->backingfd, scratch, cachelen, (long)ent->u.normal.start) < (long)cachelen)
            FD_LOG_ERR(("failed to read backing file: %s", strerror(errno)));
          if (memcmp(scratch, cache, cachelen) != 0)
            FD_LOG_ERR(("cache is wrong"));
        }
        if (ent->u.normal.start < allocpos)
          FD_LOG_ERR(("overlapping allocations"));
        allocpos = ent->u.normal.start + ent->u.normal.alloc;
        normalcnt++;

      } else if (ent->type == FD_FUNK_CONTROL_DEAD) {
        if (ent->u.dead.start + ent->u.dead.alloc > store->backinglen)
          FD_LOG_ERR(("backinglen is wrong"));
        uint k;
        ulong rsize = fd_funk_disk_size(ent->u.dead.alloc, &k);
        if (rsize != ent->u.dead.alloc || k >= FD_FUNK_NUM_DISK_SIZES)
          FD_LOG_ERR(("invalid record allocation in store"));
        if (ent->u.dead.start < allocpos)
          FD_LOG_ERR(("overlapping allocations"));
        allocpos = ent->u.dead.start + ent->u.dead.alloc;
        deadcnt[k]++;

      } else if (ent->type == FD_FUNK_CONTROL_EMPTY) {
        emptycnt++;
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
