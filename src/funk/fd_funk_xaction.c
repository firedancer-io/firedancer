// First thing in a transaction transcript
struct __attribute__((packed)) fd_funk_xaction_prefix {
  // The state of the transaction
  char state;
};
// Cases for state. Frozen means the transaction was forked but no
// committed yet.
#define FD_FUNK_XACTION_LIVE 'l'
#define FD_FUNK_XACTION_FROZEN 'f'
#define FD_FUNK_XACTION_COMMITTED 'c'

// Get the location of the prefix in the transaction transcript
#define FD_FUNK_XACTION_PREFIX(_ent_) ((struct fd_funk_xaction_prefix*)((_ent_)->script))

// Transcript header indicating a "write" update
struct __attribute__((packed)) fd_funk_xaction_write_header {
  // Header type. This type must be the first byte in the header
  char type;
  uchar recordid[FD_FUNK_RECORDID_FOOTPRINT];
  // Offset and length of write. Both must be <=
  // FD_FUNK_MAX_ENTRY_SIZE. The sum also.
  uint offset;
  uint size;
  // Data being written follows the header
};
#define FD_FUNK_XACTION_WRITE_TYPE 'w'

// Transcript header indicating a "delete" update
struct __attribute__((packed)) fd_funk_xaction_delete_header {
  // Header type. This type must be the first byte in the header
  char type;
  uchar recordid[FD_FUNK_RECORDID_FOOTPRINT];
  // Offset and length of delete
};
#define FD_FUNK_XACTION_DELETE_TYPE 'd'

// Tests whether a transaction id is for the "root"
int fd_funk_is_root(struct fd_funk_xactionid const* xid) {
  // A xactionid is 4 ulongs long
  FD_STATIC_ASSERT(sizeof(struct fd_funk_xactionid)/sizeof(ulong) == 4,fd_funk);

  const ulong* const idhack = (const ulong* const)xid;
  return (idhack[0] | idhack[1] | idhack[2] | idhack[3]) == 0;
}

void fd_funk_fork(struct fd_funk* store,
                  struct fd_funk_xactionid const* parent,
                  struct fd_funk_xactionid const* child) {
  // Find the entry for the parent transaction
  struct fd_funk_xaction_entry* parentry = NULL;
  if (!fd_funk_is_root(parent)) {
    parentry = fd_funk_xactions_query(store->xactions, parent);
    if (parentry == NULL) {
      FD_LOG_WARNING(("parent transaction does not exist"));
      return;
    }
  }
  // Create the child transaction
  int exists;
  struct fd_funk_xaction_entry* entry = fd_funk_xactions_insert(store->xactions, child, &exists);
  if (entry == NULL) {
    FD_LOG_WARNING(("too many inflight transactions"));
    return;
  }
  if (exists) {
    FD_LOG_WARNING(("transaction id already used"));
    return;
  }
  // Initialize the entry
  fd_funk_xactionid_t_copy(&entry->parent, parent);
  entry->scriptmax = 1<<12; // 4KB
  entry->script = (char*)malloc(entry->scriptmax);
  // The prefix always comes first in the transcript
  entry->scriptlen = sizeof(struct fd_funk_xaction_prefix);
  FD_FUNK_XACTION_PREFIX(entry)->state = FD_FUNK_XACTION_LIVE;
  if (parentry != NULL && FD_FUNK_XACTION_PREFIX(parentry)->state == FD_FUNK_XACTION_LIVE) {
    // Freeze the parent transaction. Updates to a forked transaction
    // are not allowed.
    FD_FUNK_XACTION_PREFIX(parentry)->state = FD_FUNK_XACTION_FROZEN;
  }
  fd_funk_xaction_cache_new(&entry->cache);
}

void fd_funk_xaction_entry_cleanup(struct fd_funk* store,
                                   struct fd_funk_xaction_entry* entry) {
  free(entry->script);
  const ulong cnt = entry->cache.cnt;
  struct fd_funk_xaction_cache_entry* const elems = entry->cache.elems;
  for (ulong i = 0; i < cnt; ++i) {
    struct fd_funk_xaction_cache_entry* const elem = elems + i;
    fd_cache_release(store->cache, elem->cachehandle, store->alloc);
  }
  fd_funk_xaction_cache_destroy(&entry->cache);
}

void fd_funk_xactions_cleanup(struct fd_funk* store) {
  struct fd_funk_xactions_iter iter;
  fd_funk_xactions_iter_init(store->xactions, &iter);
  struct fd_funk_xaction_entry* entry;
  while ((entry = fd_funk_xactions_iter_next(store->xactions, &iter)) != NULL)
    fd_funk_xaction_entry_cleanup(store, entry);
}

void fd_funk_cancel_orphans(struct fd_funk* store) {
  // TBD!!!
  (void)store;
}

void fd_funk_execute_script(struct fd_funk* store,
                            const char* script,
                            uint scriptlen) {
  const char* p = script + sizeof(struct fd_funk_xaction_prefix);
  const char* const pend = script + scriptlen;
  while (p < pend) {
    // The type is the first byte in the header
    switch (*p) {
    case FD_FUNK_XACTION_WRITE_TYPE: {
      struct fd_funk_xaction_write_header const* head = (struct fd_funk_xaction_write_header const*)p;
      // Copy record id to fix alignment
      struct fd_funk_recordid recordid;
      fd_memcpy(&recordid, &head->recordid, sizeof(recordid));
      fd_funk_write_root(store, &recordid, p + sizeof(*head), head->offset, head->size);
      p += sizeof(*head) + head->size;
      if (p > pend)
        FD_LOG_ERR(("corrupt transaction transcript"));
      break;
    }
    case FD_FUNK_XACTION_DELETE_TYPE: {
      struct fd_funk_xaction_delete_header const* head = (struct fd_funk_xaction_delete_header const*)p;
      // Copy record id to fix alignment
      struct fd_funk_recordid recordid;
      fd_memcpy(&recordid, &head->recordid, sizeof(recordid));
      fd_funk_delete_record_root(store, &recordid);
      p += sizeof(*head);
      if (p > pend)
        FD_LOG_ERR(("corrupt transaction transcript"));
      break;
    }
    default:
      FD_LOG_ERR(("corrupt transaction transcript"));
      break;
    }
  }
}

void fd_funk_commit(struct fd_funk* store,
                    struct fd_funk_xactionid const* id) {
  struct fd_funk_xaction_entry* entry = fd_funk_xactions_query(store->xactions, id);
  if (entry == NULL || FD_FUNK_XACTION_PREFIX(entry)->state == FD_FUNK_XACTION_COMMITTED) {
    // Fail silently in case the transaction was already committed and cleaned up
    return;
  }

  // Commit the parent transaction first
  fd_funk_commit(store, &entry->parent);
  
  // Set the state to committed
  FD_FUNK_XACTION_PREFIX(entry)->state = FD_FUNK_XACTION_COMMITTED;
  // Write a write-ahead log entry
  ulong wa_control;
  ulong wa_start;
  uint wa_alloc;
  if (!fd_funk_writeahead(store, id, &entry->parent, entry->script, entry->scriptlen,
                          &wa_control, &wa_start, &wa_alloc)) {
    FD_LOG_WARNING(("failed to write write-ahead log, commit failed"));
    FD_FUNK_XACTION_PREFIX(entry)->state = FD_FUNK_XACTION_FROZEN;
    fd_funk_cancel(store, id);
    return;
  }
  // We are now in a happy place regarding this transaction. Even if
  // we crash, we can re-execute the transaction out of the
  // write-ahead log
  fd_funk_execute_script(store, entry->script, entry->scriptlen);
  // We can delete the write-ahead log now
  fd_funk_writeahead_delete(store, wa_control, wa_start, wa_alloc);
  // We can't cleanup the transaction because we may still fork of it
  // or have live children, but we can cleanup the parent.
  struct fd_funk_xaction_entry* parentry = fd_funk_xactions_remove(store->xactions, &entry->parent);
  if (parentry != NULL)
    fd_funk_xaction_entry_cleanup(store, parentry);

  // Cancel all uncommitted transactions who are now orphans. These
  // are typically competitors to the transaction that was just
  // committed.
  fd_funk_cancel_orphans(store);
}

void fd_funk_cancel(struct fd_funk* store,
                    struct fd_funk_xactionid const* id) {
  struct fd_funk_xaction_entry* entry = fd_funk_xactions_remove(store->xactions, id);
  if (entry == NULL) {
    FD_LOG_WARNING(("transaction does not exist"));
    return;
  }
  fd_funk_xaction_entry_cleanup(store, entry);

  // Cancel all uncommitted transactions who are now orphans
  fd_funk_cancel_orphans(store);
}

void fd_funk_merge(struct fd_funk* store,
                   struct fd_funk_xactionid const* destid,
                   ulong source_cnt,
                   struct fd_funk_xactionid const* const* source_ids) {
  // Lookup the source entries
  struct fd_funk_xaction_entry** source_ents = (struct fd_funk_xaction_entry**)
    fd_alloca(8U, source_cnt*sizeof(struct fd_funk_xaction_entry*));
  ulong newscriptlen = sizeof(struct fd_funk_xaction_prefix);
  for (ulong i = 0; i < source_cnt; ++i) {
    // Find the entry for the transaction
    struct fd_funk_xaction_entry* entry = fd_funk_xactions_query(store->xactions, source_ids[i]);
    if (entry == NULL) {
      FD_LOG_WARNING(("invalid transaction id"));
      return;
    }
    if (FD_FUNK_XACTION_PREFIX(entry)->state != FD_FUNK_XACTION_LIVE) {
      FD_LOG_WARNING(("transaction frozen due to being forked or committed"));
      return;
    }
    if (i > 0 && !fd_funk_xactionid_t_equal(&entry->parent, &source_ents[0]->parent)) {
      FD_LOG_WARNING(("all merged transactions must share a common parent"));
      return;
    }
    source_ents[i] = entry;
    newscriptlen += entry->scriptlen - sizeof(struct fd_funk_xaction_prefix);
  }

  // Create the child transaction
  int exists;
  struct fd_funk_xaction_entry* entry = fd_funk_xactions_insert(store->xactions, destid, &exists);
  if (entry == NULL) {
    FD_LOG_WARNING(("too many inflight transactions"));
    return;
  }
  if (exists) {
    FD_LOG_WARNING(("transaction id already used"));
    return;
  }
  // Initialize the entry
  fd_funk_xactionid_t_copy(&entry->parent, &source_ents[0]->parent);
  entry->scriptmax = (uint)newscriptlen;
  entry->script = (char*)malloc(newscriptlen);
  entry->scriptlen = (uint)newscriptlen;
  FD_FUNK_XACTION_PREFIX(entry)->state = FD_FUNK_XACTION_LIVE;
  fd_funk_xaction_cache_new(&entry->cache);
  // Concatenate all the transcripts
  char* p = entry->script + sizeof(struct fd_funk_xaction_prefix);
  for (ulong i = 0; i < source_cnt; ++i) {
    ulong copylen = source_ents[i]->scriptlen - sizeof(struct fd_funk_xaction_prefix);
    fd_memcpy(p, source_ents[i]->script + sizeof(struct fd_funk_xaction_prefix), copylen);
    p += copylen;
  }

  // Cleanup the original transactions
  for (ulong i = 0; i < source_cnt; ++i) {
    struct fd_funk_xaction_entry* entry = fd_funk_xactions_remove(store->xactions, source_ids[i]);
    fd_funk_xaction_entry_cleanup(store, entry);
  }  
}

int fd_funk_isopen(struct fd_funk* store,
                   struct fd_funk_xactionid const* id) {
  // See if the transaction id is in the table
  struct fd_funk_xaction_entry* entry = fd_funk_xactions_query(store->xactions, id);
  return (entry != NULL && FD_FUNK_XACTION_PREFIX(entry)->state != FD_FUNK_XACTION_COMMITTED);
}

long fd_funk_write(struct fd_funk* store,
                   struct fd_funk_xactionid const* xid,
                   struct fd_funk_recordid const* recordid,
                   const void* data,
                   ulong offset,
                   ulong data_sz) {
  if (offset + data_sz > FD_FUNK_MAX_ENTRY_SIZE) {
    FD_LOG_WARNING(("record too large"));
    return -1;
  }
  
  // Check for special root case
  if (fd_funk_is_root(xid)) {
    // See if the root is currently forked
    if (store->xactions->used > 0) {
      FD_LOG_WARNING(("cannot update root while transactions are in flight"));
      return -1;
    }
    return fd_funk_write_root(store, recordid, data, offset, data_sz);
  }

  // Find the entry for the transaction
  struct fd_funk_xaction_entry* entry = fd_funk_xactions_query(store->xactions, xid);
  if (entry == NULL) {
    FD_LOG_WARNING(("invalid transaction id"));
    return -1;
  }
  if (FD_FUNK_XACTION_PREFIX(entry)->state != FD_FUNK_XACTION_LIVE) {
    FD_LOG_WARNING(("transaction frozen due to being forked or committed"));
    return -1;
  }
  
  // Add the write update to the transcript. This consists of a header
  // followed by the data.
  ulong newlen = entry->scriptlen + sizeof(struct fd_funk_xaction_write_header) + data_sz;
  if (newlen > entry->scriptmax) {
    entry->scriptmax = (uint)(newlen + (64U<<10)); // 64KB of slop
    entry->script = (char*)realloc(entry->script, entry->scriptmax);
  }
  struct fd_funk_xaction_write_header* head = (struct fd_funk_xaction_write_header*)(entry->script + entry->scriptlen);
  head->type = FD_FUNK_XACTION_WRITE_TYPE;
  // Need to use memcpy because of alignment issues
  fd_memcpy(head->recordid, recordid, FD_FUNK_RECORDID_FOOTPRINT);
  head->offset = (uint)offset;
  head->size = (uint)data_sz;
  fd_memcpy(entry->script + entry->scriptlen + sizeof(*head), data, data_sz);
  entry->scriptlen = (uint)newlen;

  // Update the cache for this transaction. Keep in mind that the
  // cache might just be a prefix of the record.
  struct fd_funk_xaction_cache* cache = &entry->cache;
  for (ulong i = 0; i < cache->cnt; ++i) {
    struct fd_funk_xaction_cache_entry* j = cache->elems + i;
    if (fd_funk_recordid_t_equal(&j->record, recordid)) {
      uint cache_sz;
      void* cachemem = fd_cache_lookup(store->cache, j->cachehandle, &cache_sz);
      if (cachemem == NULL) {
        // Cache entry was released while I was awawy
        fd_funk_xaction_cache_remove_at(cache, i);
        break;
      }
      if (offset < cache_sz) {
        // Update the cache
        fd_memcpy((char*)cachemem + offset, data,
                  (data_sz <= cache_sz - offset ? data_sz : cache_sz - offset));
      }
      if (offset + data_sz > j->record_sz) {
        // Update the total record length
        j->record_sz = (uint)(offset + data_sz);
      }
    }
  }
  
  return (long)data_sz;
}

void fd_funk_delete_record(struct fd_funk* store,
                           struct fd_funk_xactionid const* xid,
                           struct fd_funk_recordid const* recordid) {
  // Check for special root case
  if (fd_funk_is_root(xid)) {
    // See if the root is currently forked
    if (store->xactions->used > 0) {
      FD_LOG_WARNING(("cannot update root while transactions are in flight"));
      return;
    }
    fd_funk_delete_record_root(store, recordid);
    return;
  }

  // Find the entry for the transaction
  struct fd_funk_xaction_entry* entry = fd_funk_xactions_query(store->xactions, xid);
  if (entry == NULL) {
    FD_LOG_WARNING(("invalid transaction id"));
    return;
  }
  if (FD_FUNK_XACTION_PREFIX(entry)->state != FD_FUNK_XACTION_LIVE) {
    FD_LOG_WARNING(("transaction frozen due to being forked or committed"));
    return;
  }
  
  // Add the delete update to the transcript.
  ulong newlen = entry->scriptlen + sizeof(struct fd_funk_xaction_delete_header);
  if (newlen > entry->scriptmax) {
    entry->scriptmax = (uint)(newlen + (64U<<10)); // 64KB of slop
    entry->script = (char*)realloc(entry->script, entry->scriptmax);
  }
  struct fd_funk_xaction_delete_header* head = (struct fd_funk_xaction_delete_header*)(entry->script + entry->scriptlen);
  head->type = FD_FUNK_XACTION_DELETE_TYPE;
  // Need to use memcpy because of alignment issues
  fd_memcpy(head->recordid, recordid, FD_FUNK_RECORDID_FOOTPRINT);
  entry->scriptlen = (uint)newlen;

  // Update the cache for this transaction.
  struct fd_funk_xaction_cache* cache = &entry->cache;
  for (uint i = 0; i < cache->cnt; ++i) {
    struct fd_funk_xaction_cache_entry* j = cache->elems + i;
    if (fd_funk_recordid_t_equal(&j->record, recordid)) {
      fd_cache_release(store->cache, j->cachehandle, store->alloc);
      fd_funk_xaction_cache_remove_at(cache, i);
      break;
    }
  }
}

// Get/construct the cache entry for a record
fd_cache_handle fd_funk_get_cache(struct fd_funk* store,
                                  struct fd_funk_xactionid const* xid,
                                  struct fd_funk_recordid const* recordid,
                                  uint needed_sz,
                                  void** cache_data,
                                  uint* cache_sz,
                                  uint* record_sz) {
  // Root is a special case
  if (fd_funk_is_root(xid))
    return fd_funk_get_cache_root(store, recordid, needed_sz, cache_data, cache_sz, record_sz);

  // Find the transaction entry
  struct fd_funk_xaction_entry* entry = fd_funk_xactions_query(store->xactions, xid);
  if (entry == NULL) {
    FD_LOG_WARNING(("invalid transaction id"));
    return FD_CACHE_INVALID_HANDLE;
  }
  // See if we already have cached data
  struct fd_funk_xaction_cache* cache = &entry->cache;
  for (ulong i = 0; i < cache->cnt; ++i) {
    struct fd_funk_xaction_cache_entry* j = cache->elems + i;
    if (fd_funk_recordid_t_equal(&j->record, recordid)) {
      *record_sz = j->record_sz;
      // Get the underlying data
      *cache_data = fd_cache_lookup(store->cache, j->cachehandle, cache_sz);
      if (*cache_data == NULL) {
        // Cache entry was released while I was away. Just discard it.
        fd_funk_xaction_cache_remove_at(cache, i);
        break;
      }
      // See if we have enough data
      if (*cache_sz >= fd_uint_min(needed_sz, *record_sz))
        return j->cachehandle;
      // Existing cache is too small (a short prefix). Throw away the
      // old one and rebuild it from scratch.
      fd_cache_release(store->cache, j->cachehandle, store->alloc);
      fd_funk_xaction_cache_remove_at(cache, i);
      break;
    }
  }

  // Start by reading from the parent transaction
  fd_cache_handle hand = fd_funk_get_cache(store, &entry->parent, recordid, needed_sz,
                                           cache_data, cache_sz, record_sz);

  // See if this transaction includes an update to this record. We walk
  // through the transcript and compute the updated record length.
  int newrecord_sz = (hand == FD_CACHE_INVALID_HANDLE ? -1 : (int)(*record_sz));
  int updated = 0;
  const char* p = (const char*)entry->script + sizeof(struct fd_funk_xaction_prefix);
  const char* const pend = (const char*)entry->script + entry->scriptlen;
  while (p < pend) {
    // The type is the first byte in the header
    switch (*p) {
    case FD_FUNK_XACTION_WRITE_TYPE: {
      struct fd_funk_xaction_write_header const* head = (struct fd_funk_xaction_write_header const*)p;
      // Use memcmp due to alignment issues
      if (memcmp(head->recordid, recordid, FD_FUNK_RECORDID_FOOTPRINT) == 0) {
        int len = (int)(head->offset + head->size);
        if (len > newrecord_sz)
          newrecord_sz = len;
        updated = 1;
      }
      p += sizeof(*head) + head->size;
      if (p > pend)
        FD_LOG_ERR(("corrupt transaction transcript"));
      break;
    }
    case FD_FUNK_XACTION_DELETE_TYPE: {
      struct fd_funk_xaction_delete_header const* head = (struct fd_funk_xaction_delete_header const*)p;
      // Use memcmp due to alignment issues
      if (memcmp(head->recordid, recordid, FD_FUNK_RECORDID_FOOTPRINT) == 0) {
        newrecord_sz = -1; // Indicate a delete
        updated = 1;
      }
      p += sizeof(*head);
      if (p > pend)
        FD_LOG_ERR(("corrupt transaction transcript"));
      break;
    }
    default:
      FD_LOG_ERR(("corrupt transaction transcript"));
      break;
    }
  }
  if (!updated) {
    // No update found. Just use the result from the parent.
    return hand;
  }

  if (newrecord_sz < 0) {
    // Record was deleted in this transaction
    *cache_data = NULL;
    *cache_sz = 0;
    *record_sz = 0;
    return FD_CACHE_INVALID_HANDLE;
  }

  // Create a new cache entry for this transaction
  if (needed_sz > (uint)newrecord_sz)
    needed_sz = (uint)newrecord_sz; // Trim to the actual record size
  void* newdata;
  fd_cache_handle newhandle = fd_cache_allocate(store->cache, &newdata, needed_sz, store->alloc);
  
  // Copy existing cache data from parent transaction
  if (hand == FD_CACHE_INVALID_HANDLE)
    // Zero fill in case of gaps
    fd_memset(newdata, 0, needed_sz);
  else {
    fd_memcpy(newdata, *cache_data, (needed_sz <= *cache_sz ? needed_sz : *cache_sz));
    if (needed_sz > *cache_sz)
      fd_memset((char*)newdata + *cache_sz, 0, needed_sz - *cache_sz);
  }

  // Apply updates in the transaction to the new cache entry
  p = (const char*)entry->script + sizeof(struct fd_funk_xaction_prefix);
  while (p < pend) {
    // Type is first byte in header
    switch (*p) {
    case FD_FUNK_XACTION_WRITE_TYPE: {
      struct fd_funk_xaction_write_header const* head = (struct fd_funk_xaction_write_header const*)p;
      if (memcmp(head->recordid, recordid, FD_FUNK_RECORDID_FOOTPRINT) == 0) {
        if (head->offset < needed_sz)
          fd_memcpy((char*)newdata + head->offset,
                    p + sizeof(*head), // Data follows header
                    fd_uint_min(head->size, needed_sz - head->offset));
      }
      p += sizeof(*head) + head->size;
      if (p > pend)
        FD_LOG_ERR(("corrupt transaction transcript"));
      break;
    }
    case FD_FUNK_XACTION_DELETE_TYPE: {
      struct fd_funk_xaction_delete_header const* head = (struct fd_funk_xaction_delete_header const*)p;
      // Use memcmp due to alignment issues
      if (memcmp(head->recordid, recordid, FD_FUNK_RECORDID_FOOTPRINT) == 0) {
        // Zero fill for future updates
        fd_memset(newdata, 0, needed_sz);
      }
      p += sizeof(*head);
      if (p > pend)
        FD_LOG_ERR(("corrupt transaction transcript"));
      break;
    }
    default:
      FD_LOG_ERR(("corrupt transaction transcript"));
      break;
    }
  }

  // Remember the new cache entry
  struct fd_funk_xaction_cache_entry newent;
  fd_funk_recordid_t_copy(&newent.record, recordid);
  newent.record_sz = (uint)newrecord_sz;
  newent.cachehandle = newhandle;
  fd_funk_xaction_cache_push(cache, newent);

  *cache_data = newdata;
  *cache_sz = needed_sz;
  *record_sz = (uint)newrecord_sz;
  return newhandle;
}

long fd_funk_read(struct fd_funk* store,
                  struct fd_funk_xactionid const* xid,
                  struct fd_funk_recordid const* recordid,
                  const void** data,
                  ulong offset,
                  ulong data_sz) {
  *data = NULL; // defensive
  // Get the cache entry for the record
  void* cache_data;
  uint cache_sz, record_sz;
  fd_cache_handle hand = fd_funk_get_cache(store, xid, recordid, (uint)(offset + data_sz),
                                           &cache_data, &cache_sz, &record_sz);
  if (hand == FD_CACHE_INVALID_HANDLE)
    return -1;
  // Return a pointer into the cache
  if (offset >= cache_sz)
    return 0;
  *data = (char*)cache_data + offset;
  return (long)fd_ulong_min(data_sz, cache_sz - offset);
}

