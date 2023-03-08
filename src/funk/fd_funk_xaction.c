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

ulong fd_funk_num_xactions(struct fd_funk* store) {
  return store->xactions->used;
}

void fd_funk_xaction_entry_cleanup(struct fd_funk* store,
                                   struct fd_funk_xaction_entry* entry) {
  fd_alloc_free(store->alloc, entry->script);
  const ulong cnt = entry->cache.cnt;
  struct fd_funk_xaction_cache_entry* const elems = entry->cache.elems;
  for (ulong i = 0; i < cnt; ++i) {
    struct fd_funk_xaction_cache_entry* const elem = elems + i;
    fd_cache_release(store->cache, elem->cachehandle, store->alloc);
  }
  fd_funk_xaction_cache_destroy(&entry->cache);
}

int fd_funk_xactions_gc_state(struct fd_funk* store,
                              struct fd_funk_xaction_entry* entry) {
  // See if we already computed the state
  if (entry->gc_state != FD_FUNK_GC_UNKNOWN)
    return entry->gc_state;
  // Direct children of the root are good
  if (fd_funk_xactionid_t_equal(&entry->parent, &store->last_commit))
    return (entry->gc_state = FD_FUNK_GC_GOOD);
  // Lookup the parent transaction
  struct fd_funk_xaction_entry* parentry = fd_funk_xactions_query(store->xactions, &entry->parent);
  if (parentry == NULL) {
    // Parent is gone. This transaction should be deleted
    return (entry->gc_state = FD_FUNK_GC_ORPHAN);
  }
  // Inherit the state from the parent
  return (entry->gc_state = fd_funk_xactions_gc_state(store, parentry));
}

// Garbage collect any orphan transactions (those that are detached
// from the root). The complexity of this operation is O(n) where n is
// the size of the transaction table. It should be used sparingly.
ulong fd_funk_xactions_kill_orphans(struct fd_funk* store) {
  // Initialize all the entries in the transaction table to unknown
  // garbage collection state
  struct fd_funk_xactions_iter iter;
  fd_funk_xactions_iter_init(store->xactions, &iter);
  struct fd_funk_xaction_entry* entry;
  while ((entry = fd_funk_xactions_iter_next(store->xactions, &iter)) != NULL)
    entry->gc_state = FD_FUNK_GC_UNKNOWN;
  // Compute the state of all transactions. Count the orphans.
  ulong numkill = 0;
  fd_funk_xactions_iter_init(store->xactions, &iter);
  while ((entry = fd_funk_xactions_iter_next(store->xactions, &iter)) != NULL) {
    if (fd_funk_xactions_gc_state(store, entry) == FD_FUNK_GC_ORPHAN)
      numkill++;
  }
  if (numkill == 0)
    return 0;
  // Create a list of orphan entries. The iterator doesn't support deletes.
  struct fd_funk_xactionid** deadpool = (struct fd_funk_xactionid**)
    fd_alloca(8U, numkill*sizeof(struct fd_funk_xactionid*));
  numkill = 0;
  fd_funk_xactions_iter_init(store->xactions, &iter);
  while ((entry = fd_funk_xactions_iter_next(store->xactions, &iter)) != NULL) {
    if (entry->gc_state == FD_FUNK_GC_ORPHAN)
      deadpool[numkill++] = &entry->key;
  }
  // Murder the orphans
  for (ulong i = 0; i < numkill; ++i) {
    entry = fd_funk_xactions_remove(store->xactions, deadpool[i]);
    fd_funk_xaction_entry_cleanup(store, entry);
  }
  FD_LOG_WARNING(("canceled %lu orphan transactions due to garbage collection", numkill));
  return numkill;
}

int fd_funk_fork(struct fd_funk* store,
                 struct fd_funk_xactionid const* parent,
                 struct fd_funk_xactionid const* child) {
  // Root is really a synonym for the last committed transaction, and
  // the latter is less ambiguous, safer.
  if (fd_funk_is_root(parent))
    parent = &store->last_commit;
  // Find the entry for the parent transaction. We are allowed to fork
  // off the last committed transaction as well as any uncomitted transaction
  struct fd_funk_xaction_entry* parentry = fd_funk_xactions_query(store->xactions, parent);
  if (parentry == NULL && !fd_funk_xactionid_t_equal(parent, &store->last_commit)) {
    FD_LOG_WARNING(("parent transaction does not exist"));
    return 0;
  }
  // Create the child transaction
  int exists;
  struct fd_funk_xaction_entry* entry = fd_funk_xactions_insert(store->xactions, child, &exists);
  if (entry == NULL) {
    // Garbage collect orphans are try again
    fd_funk_xactions_kill_orphans(store);
    entry = fd_funk_xactions_insert(store->xactions, child, &exists);
    if (entry == NULL) {
      // The transaction table is full
      FD_LOG_WARNING(("too many inflight transactions"));
      return 0;
    }
  }
  if (exists) {
    FD_LOG_WARNING(("transaction id already used"));
    return 0;
  }
  // Initialize the entry
  fd_funk_xactionid_t_copy(&entry->parent, parent);
  entry->scriptmax = 1<<12; // 4KB
  entry->script = (char*)fd_cache_safe_malloc(store->cache, store->alloc, 1, entry->scriptmax);
  // The prefix always comes first in the transcript
  entry->scriptlen = sizeof(struct fd_funk_xaction_prefix);
  FD_FUNK_XACTION_PREFIX(entry)->state = FD_FUNK_XACTION_LIVE;
  if (parentry != NULL && FD_FUNK_XACTION_PREFIX(parentry)->state == FD_FUNK_XACTION_LIVE) {
    // Freeze the parent transaction. Updates to a forked transaction
    // are not allowed.
    FD_FUNK_XACTION_PREFIX(parentry)->state = FD_FUNK_XACTION_FROZEN;
  }
  fd_funk_xaction_cache_new(&entry->cache);
  entry->wa_control = 0;
  entry->wa_start = 0;
  entry->wa_alloc = 0;
  return 1;
}

void fd_funk_xactions_cleanup(struct fd_funk* store) {
  struct fd_funk_xactions_iter iter;
  fd_funk_xactions_iter_init(store->xactions, &iter);
  struct fd_funk_xaction_entry* entry;
  while ((entry = fd_funk_xactions_iter_next(store->xactions, &iter)) != NULL)
    fd_funk_xaction_entry_cleanup(store, entry);
}

int fd_funk_execute_script(struct fd_funk* store,
                           const char* script,
                           uint scriptlen,
                           int recovery) {
  int result = 1;
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
      struct iovec iov;
      iov.iov_base = (void*)(p + sizeof(*head));
      iov.iov_len = head->size;
      if (fd_funk_writev_root(store, &recordid, &iov, 1, head->offset) != (long)head->size) {
        FD_LOG_WARNING(("write failed during commit"));
        result = 0;
      }
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
      if (!fd_funk_delete_record_root(store, &recordid)) {
        // Redundant deletes are OK on recovery
        if (!recovery) {
          FD_LOG_WARNING(("delete failed during commit"));
          result = 0;
        }
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
  return result;
}

int fd_funk_commit(struct fd_funk* store,
                   struct fd_funk_xactionid const* id) {
  // Recommitting the last committed transaction is always
  // allowed. This also stops the recursive walk up the chain.
  if (fd_funk_xactionid_t_equal(id, &store->last_commit))
    return 1;
  // Find the transaction entry
  struct fd_funk_xaction_entry* entry = fd_funk_xactions_query(store->xactions, id);
  if (entry == NULL) {
    // Not a live transaction
    return 0;
  }

  // Commit the parent transaction first
  if (!fd_funk_commit(store, &entry->parent)) {
    FD_LOG_WARNING(("attempt to commit a detached transaction, canceling instead"));
    entry = fd_funk_xactions_remove(store->xactions, id);
    fd_funk_xaction_entry_cleanup(store, entry);
    return 0;
  }
  
  // Set the state to committed
  FD_FUNK_XACTION_PREFIX(entry)->state = FD_FUNK_XACTION_COMMITTED;
  // Write a write-ahead log entry
  if (!fd_funk_writeahead(store, id, &entry->parent, entry->script, entry->scriptlen,
                          &entry->wa_control, &entry->wa_start, &entry->wa_alloc)) {
    FD_LOG_WARNING(("failed to write write-ahead log, transaction left in uncommitted state"));
    FD_FUNK_XACTION_PREFIX(entry)->state = FD_FUNK_XACTION_FROZEN;
    return 0;
  }
  // We are now in a happy place regarding this transaction. Even if
  // we crash, we can re-execute the transaction out of the
  // write-ahead log
  if (!fd_funk_execute_script(store, entry->script, entry->scriptlen, 0)) {
    FD_LOG_ERR(("failed to execute transaction, exiting to allow normal recovery"));
    return 0;
  }
  // We can delete the write-ahead log now
  fd_funk_writeahead_delete(store, entry->wa_control, entry->wa_start, entry->wa_alloc);
  // Final cleanup
  entry = fd_funk_xactions_remove(store->xactions, id);
  fd_funk_xaction_entry_cleanup(store, entry);

  // Remember the last committed transaction
  fd_funk_xactionid_t_copy(&store->last_commit, id);

  return 1;
}

void fd_funk_writeahead_load(struct fd_funk* store,
                             struct fd_funk_xactionid* id,
                             struct fd_funk_xactionid* parent,
                             ulong start,
                             uint size,
                             uint alloc,
                             ulong ctrlpos,
                             char* script) {
  // Create a table entry with all the arguments
  int exists;
  struct fd_funk_xaction_entry* entry = fd_funk_xactions_insert(store->xactions, id, &exists);
    // Initialize the entry
  fd_funk_xactionid_t_copy(&entry->parent, parent);
  entry->script = script; // Assumes caller allocated with fd_alloc_malloc
  entry->scriptlen = size;
  entry->scriptmax = size;
  fd_funk_xaction_cache_new(&entry->cache);
  entry->wa_control = ctrlpos;
  entry->wa_start = start;
  entry->wa_alloc = alloc;
}

void fd_funk_writeahead_recommit_entry(struct fd_funk* store,
                                       struct fd_funk_xaction_entry* entry) {
  // Do the parent first in case a chain of transactions as written
  // ahead all at once.
  struct fd_funk_xaction_entry* parentry = fd_funk_xactions_query(store->xactions, &entry->parent);
  if (parentry != NULL)
    fd_funk_writeahead_recommit_entry(store, parentry);

  // Try the transaction again
  FD_LOG_WARNING(("recovering transaction which was partially executed in prior incarnation"));
  if (!fd_funk_execute_script(store, entry->script, entry->scriptlen, 1)) {
    FD_LOG_ERR(("failed to execute recovered transaction, exiting"));
    return;
  }
  // Remember the last committed transaction id
  fd_funk_xactionid_t_copy(&store->last_commit, &entry->key);
  // We can delete the write-ahead log now
  fd_funk_writeahead_delete(store, entry->wa_control, entry->wa_start, entry->wa_alloc);
  // Final cleanup
  entry = fd_funk_xactions_remove(store->xactions, &entry->key);
  fd_funk_xaction_entry_cleanup(store, entry);
}

// Recommit transactions that were partially committed in a previous incarnation
void fd_funk_writeahead_recommits(struct fd_funk* store) {
  // Search for committed transactions
  struct fd_funk_xactions_iter iter;
  fd_funk_xactions_iter_init(store->xactions, &iter);
  struct fd_funk_xaction_entry* entry;
  while ((entry = fd_funk_xactions_iter_next(store->xactions, &iter)) != NULL) {
    if (FD_FUNK_XACTION_PREFIX(entry)->state == FD_FUNK_XACTION_COMMITTED) {
      fd_funk_writeahead_recommit_entry(store, entry);
      // The iterator doesn't work right with deletes so start over
      fd_funk_xactions_iter_init(store->xactions, &iter);
    }
  }
}

void fd_funk_cancel(struct fd_funk* store,
                    struct fd_funk_xactionid const* id) {
  struct fd_funk_xaction_entry* entry = fd_funk_xactions_remove(store->xactions, id);
  if (entry == NULL || FD_FUNK_XACTION_PREFIX(entry)->state == FD_FUNK_XACTION_COMMITTED) {
    FD_LOG_WARNING(("transaction is not alive"));
    return;
  }
  fd_funk_xaction_entry_cleanup(store, entry);
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
  entry->script = (char*)fd_cache_safe_malloc(store->cache, store->alloc, 1, entry->scriptmax);
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
  entry->wa_control = 0;
  entry->wa_start = 0;
  entry->wa_alloc = 0;

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

long fd_funk_writev(struct fd_funk* store,
                    struct fd_funk_xactionid const* xid,
                    struct fd_funk_recordid const* recordid,
                    struct iovec const * const iov,
                    ulong iovcnt,
                    ulong offset) {
  // Compute sizes
  ulong data_sz = 0;
  for (ulong i = 0; i < iovcnt; ++i)
    data_sz += iov[i].iov_len;
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
    return fd_funk_writev_root(store, recordid, iov, iovcnt, offset);
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
    // Grow the unused space in the transcript to accommodate the new update
    entry->scriptmax = (uint)(newlen + (64U<<10)); // 64KB of slop
    char* newscript = (char*)fd_cache_safe_malloc(store->cache, store->alloc, 1, entry->scriptmax);
    // Copy old data into new space
    fd_memcpy(newscript, entry->script, entry->scriptlen);
    fd_alloc_free(store->alloc, entry->script);
    entry->script = newscript;
  }
  struct fd_funk_xaction_write_header* head = (struct fd_funk_xaction_write_header*)(entry->script + entry->scriptlen);
  head->type = FD_FUNK_XACTION_WRITE_TYPE;
  // Need to use memcpy because of alignment issues
  fd_memcpy(head->recordid, recordid, FD_FUNK_RECORDID_FOOTPRINT);
  head->offset = (uint)offset;
  head->size = (uint)data_sz;
  char* p = (char*)(head + 1);
  for (ulong i = 0; i < iovcnt; ++i) {
    fd_memcpy(p, iov[i].iov_base, iov[i].iov_len);
    p += iov[i].iov_len;
  }
  entry->scriptlen = (uint)newlen;

  // Update the cache for this transaction. Keep in mind that the
  // cache might just be a prefix of the record.
  struct fd_funk_xaction_cache* cache = &entry->cache;
  for (ulong i = 0; i < cache->cnt; ++i) {
    struct fd_funk_xaction_cache_entry* j = cache->elems + i;
    if (fd_funk_recordid_t_equal(&j->record, recordid)) {
      // Update the cache
      uint cache_sz;
      void* cachemem = fd_cache_lookup(store->cache, j->cachehandle, &cache_sz);
      if (cachemem == NULL) {
        // Cache entry was released while I was awawy
        fd_funk_xaction_cache_remove_at(cache, i);
        break;
      }
      // Copy one piece at a time
      ulong toffset = offset;
      for (ulong i = 0; i < iovcnt; ++i) {
        if (toffset >= cache_sz)
          break;
        ulong sz = fd_ulong_min(iov[i].iov_len, cache_sz - toffset);
        fd_memcpy((char*)cachemem + toffset, iov[i].iov_base, sz);
        toffset += sz;
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
    // Grow the unused space in the transcript to accommodate the new update
    entry->scriptmax = (uint)(newlen + (64U<<10)); // 64KB of slop
    char* newscript = (char*)fd_cache_safe_malloc(store->cache, store->alloc, 1, entry->scriptmax);
    // Copy old data into new space
    fd_memcpy(newscript, entry->script, entry->scriptlen);
    fd_alloc_free(store->alloc, entry->script);
    entry->script = newscript;
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
  if (fd_funk_is_root(xid) || fd_funk_xactionid_t_equal(xid, &store->last_commit))
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

void fd_funk_validate_xaction(struct fd_funk* store) {
  if (!fd_funk_xactions_validate(store->xactions))
    FD_LOG_ERR(("transaction table is corrupt"));
}
