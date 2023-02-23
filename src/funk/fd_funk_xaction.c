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
  // Offset and length of write
  uint offset;
  uint length;
  // Data being written follows the header
};
#define FD_FUNK_XACTION_WRITE_TYPE 'w'

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
  const uint cnt = entry->cache.cnt;
  struct fd_funk_xaction_cache_entry* const elems = entry->cache.elems;
  for (uint i = 0; i < cnt; ++i) {
    struct fd_funk_xaction_cache_entry* const elem = elems + i;
    fd_cache_release(store->cache, elem->cachehandle);
  }
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
      fd_funk_write_root(store, &recordid, p + sizeof(*head), head->offset, head->length);
      p += sizeof(*head) + head->length;
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
  // We can't cleanup the transaction because we may still fork of it,
  // but we can cleanup the parent.
  struct fd_funk_xaction_entry* parentry = fd_funk_xactions_remove(store->xactions, &entry->parent);
  if (parentry != NULL)
    fd_funk_xaction_entry_cleanup(store, parentry);

  // Cancel all uncommitted transactions who are now orphans
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
                   struct fd_funk_xactionid const* const* source_ids);

int fd_funk_isopen(struct fd_funk* store,
                   struct fd_funk_xactionid const* id) {
  // See if the transaction id is in the table
  return fd_funk_xactions_query(store->xactions, id) != NULL;
}

long fd_funk_write(struct fd_funk* store,
                   struct fd_funk_xactionid const* xid,
                   struct fd_funk_recordid const* recordid,
                   const void* data,
                   ulong offset,
                   ulong datalen) {
  // Check for special root case
  if (fd_funk_is_root(xid)) {
    // See if the root is currently forked
    if (store->xactions->used > 0) {
      FD_LOG_WARNING(("cannot update root while transactions are in flight"));
      return -1;
    }
    return fd_funk_write_root(store, recordid, data, offset, datalen);
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
  ulong newlen = entry->scriptlen + sizeof(struct fd_funk_xaction_write_header) + datalen;
  if (newlen > entry->scriptmax) {
    entry->scriptmax = (uint)(newlen + (64U<<10)); // 64KB of slop
    entry->script = (char*)realloc(entry->script, entry->scriptmax);
  }
  struct fd_funk_xaction_write_header* head = (struct fd_funk_xaction_write_header*)(entry->script + entry->scriptlen);
  head->type = FD_FUNK_XACTION_WRITE_TYPE;
  // Need to use memcpy because of alignment issues
  fd_memcpy(head->recordid, recordid, FD_FUNK_RECORDID_FOOTPRINT);
  head->offset = (uint)offset;
  head->length = (uint)datalen;
  fd_memcpy(entry->script + entry->scriptlen + sizeof(*head), data, datalen);
  entry->scriptlen = (uint)newlen;

  // Update the cache for this transaction. Keep in mind that the
  // cache might just be a prefix of the record.
  struct fd_funk_xaction_cache* cache = &entry->cache;
  for (unsigned i = 0; i < cache->cnt; ++i) {
    struct fd_funk_xaction_cache_entry* j = cache->elems + i;
    if (fd_funk_recordid_t_equal(&j->record, recordid)) {
      uint cachelen;
      void* cachemem = fd_cache_lookup(store->cache, j->cachehandle, &cachelen);
      if (cachemem == NULL) {
        // Cache entry was released while I was awawy
        fd_funk_xaction_cache_remove_at(cache, i);
        break;
      }
      if (offset < cachelen) {
        // Update the cache
        fd_memcpy((char*)cachemem + offset, data,
                  (datalen <= cachelen - offset ? datalen : cachelen - offset));
      }
      if (offset + datalen > j->recordlen) {
        // Update the total record length
        j->recordlen = (uint)(offset + datalen);
      }
    }
  }
  
  return (long)datalen;
}

// Get/construct the cache entry for a record
fd_cache_handle fd_funk_get_cache(struct fd_funk* store,
                                  struct fd_funk_xactionid const* xid,
                                  struct fd_funk_recordid const* recordid,
                                  uint neededlen,
                                  void** cachedata,
                                  uint* cachelen,
                                  uint* recordlen) {
  // Root is a special case
  if (fd_funk_is_root(xid))
    return fd_funk_get_cache_root(store, recordid, neededlen, cachedata, cachelen, recordlen);

  // Find the transaction entry
  struct fd_funk_xaction_entry* entry = fd_funk_xactions_query(store->xactions, xid);
  if (entry == NULL) {
    FD_LOG_WARNING(("invalid transaction id"));
    return FD_CACHE_INVALID_HANDLE;
  }
  // See if we already have cached data
  struct fd_funk_xaction_cache* cache = &entry->cache;
  for (unsigned i = 0; i < cache->cnt; ++i) {
    struct fd_funk_xaction_cache_entry* j = cache->elems + i;
    if (fd_funk_recordid_t_equal(&j->record, recordid)) {
      *recordlen = j->recordlen;
      // Get the underlying data
      *cachedata = fd_cache_lookup(store->cache, j->cachehandle, cachelen);
      if (*cachedata == NULL) {
        // Cache entry was released while I was away. Just discard it.
        fd_funk_xaction_cache_remove_at(cache, i);
        break;
      }
      // See if we have enough data
      if (*cachelen >= (neededlen <= *recordlen ? neededlen : *recordlen))
        return j->cachehandle;
      // Existing cache is too small (a short prefix). Throw away the
      // old one and rebuild it from scratch.
      fd_cache_release(store->cache, j->cachehandle);
      fd_funk_xaction_cache_remove_at(cache, i);
      break;
    }
  }

  // Start by reading from the parent transaction
  fd_cache_handle hand = fd_funk_get_cache(store, &entry->parent, recordid, neededlen,
                                           cachedata, cachelen, recordlen);

  // See if this transaction includes an update to this record. We walk
  // through the transcript.
  uint maxlen = 0;
  const char* p = (const char*)entry->script + sizeof(struct fd_funk_xaction_prefix);
  const char* const pend = (const char*)entry->script + entry->scriptlen;
  while (p < pend) {
    // The type is the first byte in the header
    switch (*p) {
    case FD_FUNK_XACTION_WRITE_TYPE: {
      struct fd_funk_xaction_write_header const* head = (struct fd_funk_xaction_write_header const*)p;
      // Use memcmp due to alignment issues
      if (memcmp(head->recordid, recordid, FD_FUNK_RECORDID_FOOTPRINT) == 0) {
        // maxlen is the extent of the updates
        uint len = head->offset + head->length;
        if (len > maxlen)
          maxlen = len;
      }
      p += sizeof(*head) + head->length;
      if (p > pend)
        FD_LOG_ERR(("corrupt transaction transcript"));
      break;
    }
    default:
      FD_LOG_ERR(("corrupt transaction transcript"));
      break;
    }
  }
  if (maxlen == 0) {
    // No update found. Just use the result from the parent.
    return hand;
  }

  // Compute the new record size
  if (hand == FD_CACHE_INVALID_HANDLE || *recordlen < maxlen)
    *recordlen = maxlen;
  if (neededlen > *recordlen)
    neededlen = *recordlen; // Trim to the actual record size
  // Create a new cache entry for this transaction
  void* newdata;
  fd_cache_handle newhandle = fd_cache_allocate(store->cache, &newdata, neededlen);
  
  // Copy existing cache data from parent transaction
  if (hand == FD_CACHE_INVALID_HANDLE)
    // Zero fill in case of gaps
    fd_memset(newdata, 0, neededlen);
  else {
    fd_memcpy(newdata, *cachedata, (neededlen <= *cachelen ? neededlen : *cachelen));
    if (neededlen > *cachelen)
      fd_memset((char*)newdata + *cachelen, 0, neededlen - *cachelen);
  }

  // Apply updates in the transaction to the new cache entry
  p = (const char*)entry->script + sizeof(struct fd_funk_xaction_prefix);
  while (p < pend) {
    // Type is first byte in header
    switch (*p) {
    case FD_FUNK_XACTION_WRITE_TYPE: {
      struct fd_funk_xaction_write_header const* head = (struct fd_funk_xaction_write_header const*)p;
      if (memcmp(head->recordid, recordid, FD_FUNK_RECORDID_FOOTPRINT) == 0) {
        if (head->offset < neededlen)
          fd_memcpy((char*)newdata + head->offset,
                    p + sizeof(*head), // Data follows header
                    (head->length <= neededlen - head->offset ? head->length : neededlen - head->offset));
      }
      p += sizeof(*head) + head->length;
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
  newent.recordlen = *recordlen;
  newent.cachehandle = newhandle;
  fd_funk_xaction_cache_push(cache, newent);

  *cachedata = newdata;
  *cachelen = neededlen;
  return newhandle;
}

long fd_funk_read(struct fd_funk* store,
                  struct fd_funk_xactionid const* xid,
                  struct fd_funk_recordid const* recordid,
                  const void** data,
                  ulong offset,
                  ulong datalen) {
  *data = NULL; // defensive
  // Get the cache entry for the record
  void* cachedata;
  uint cachelen, recordlen;
  fd_cache_handle hand = fd_funk_get_cache(store, xid, recordid, (uint)(offset + datalen),
                                           &cachedata, &cachelen, &recordlen);
  if (hand == FD_CACHE_INVALID_HANDLE)
    return -1;
  // Return a pointer into the cache
  if (offset >= cachelen)
    return 0;
  *data = (char*)cachedata + offset;
  return (long)(offset + datalen <= cachelen ? datalen : cachelen - offset);
}

