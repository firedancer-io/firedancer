// First thing in a transaction transcript
struct __attribute__((packed)) fd_funk_xaction_prefix {
  char state;
};
#define FD_FUNK_XACTION_LIVE 'l'
#define FD_FUNK_XACTION_FROZEN 'f'
#define FD_FUNK_XACTION_COMMITTED 'c'

#define FD_FUNK_XACTION_PREFIX(_ent_) ((struct fd_funk_xaction_prefix*)((_ent_)->script))

struct __attribute__((packed)) fd_funk_xaction_write_header {
  char type;
  uint offset;
  uint length;
};
#define FD_FUNK_XACTION_WRITE_TYPE 'w'

int fd_funk_is_root(struct fd_funk_xactionid const* xid) {
  // A xactionid is 4 ulongs long
  FD_STATIC_ASSERT(sizeof(struct fd_funk_xactionid)/sizeof(ulong) == 4,fd_funk);

  const ulong* const idhack = (const ulong* const)xid;
  return (idhack[0] | idhack[1] | idhack[2] | idhack[3]) == 0;
}

void fd_funk_fork(struct fd_funk* store,
                  struct fd_funk_xactionid const* parent,
                  struct fd_funk_xactionid const* child) {
  struct fd_funk_xaction_entry* parentry = NULL;
  if (!fd_funk_is_root(parent)) {
    parentry = fd_funk_xactions_query(store->xactions, parent);
    if (parentry == NULL) {
      FD_LOG_WARNING(("parent transaction does not exist"));
      return;
    }
  }
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
  fd_funk_xactionid_t_copy(&entry->parent, parent);
  fd_funk_xactionid_t_copy(&entry->grandparent, (parentry != NULL ? &parentry->parent : fd_funk_root(store)));
  entry->scriptmax = 1<<12; // 4KB
  entry->script = (char*)malloc(entry->scriptmax);
  entry->scriptlen = sizeof(struct fd_funk_xaction_prefix);
  FD_FUNK_XACTION_PREFIX(entry)->state = FD_FUNK_XACTION_LIVE;
  if (parentry != NULL && FD_FUNK_XACTION_PREFIX(parentry)->state == FD_FUNK_XACTION_LIVE) {
    // Freeze the parent transaction
    FD_FUNK_XACTION_PREFIX(parentry)->state = FD_FUNK_XACTION_FROZEN;
  }
  fd_funk_xaction_cache_new(&entry->cache);
}

void fd_funk_commit(struct fd_funk* store,
                    struct fd_funk_xactionid const* id);

void fd_funk_cancel(struct fd_funk* store,
                    struct fd_funk_xactionid const* id);

void fd_funk_merge(struct fd_funk* store,
                   struct fd_funk_xactionid const* destid,
                   ulong source_cnt,
                   struct fd_funk_xactionid const* const* source_ids);

int fd_funk_isopen(struct fd_funk* store,
                   struct fd_funk_xactionid const* id) {
  return fd_funk_xactions_query(store->xactions, id) != NULL;
}

long fd_funk_write(struct fd_funk* store,
                   struct fd_funk_xactionid const* xid,
                   struct fd_funk_recordid const* recordid,
                   const void* data,
                   ulong offset,
                   ulong datalen) {
  if (fd_funk_is_root(xid)) {
    if (store->xactions->used > 0) {
      FD_LOG_WARNING(("cannot update root while transactions are in flight"));
      return -1;
    }
    return fd_funk_write_root(store, recordid, data, offset, datalen);
  }

  struct fd_funk_xaction_entry* entry = fd_funk_xactions_query(store->xactions, xid);
  if (entry == NULL) {
    FD_LOG_WARNING(("invalid transaction id"));
    return -1;
  }
  if (FD_FUNK_XACTION_PREFIX(entry)->state != FD_FUNK_XACTION_LIVE) {
    FD_LOG_WARNING(("transaction frozen due to being forked or committed"));
    return -1;
  }
  
  // Add the update to the transcript
  if (entry->scriptlen + sizeof(struct fd_funk_xaction_write_header) + datalen > entry->scriptmax) {
    entry->scriptmax = (uint)(entry->scriptlen + sizeof(struct fd_funk_xaction_write_header) + datalen + (64U<<10)); // 64KB
    entry->script = (char*)realloc(entry->script, entry->scriptmax);
  }
  struct fd_funk_xaction_write_header* head = (struct fd_funk_xaction_write_header*)(entry->script + entry->scriptlen);
  head->type = FD_FUNK_XACTION_WRITE_TYPE;
  head->offset = (uint)offset;
  head->length = (uint)datalen;
  fd_memcpy(entry->script + entry->scriptlen + sizeof(*head), data, datalen);
  entry->scriptlen += (uint)(sizeof(*head) + datalen);

  // Update the cache for this transaction
  struct fd_funk_xaction_cache* cache = &entry->cache;
  for (unsigned i = 0; i < cache->cnt; ++i) {
    struct fd_funk_xaction_cache_entry* j = cache->elems + i;
    if (fd_funk_recordid_t_equal(&j->record, recordid)) {
      uint cachelen;
      void* cachemem = fd_cache_lookup(store->cache, j->cachehandle, &cachelen);
      if (cachemem && offset < cachelen)
        fd_memcpy((char*)cachemem + offset, data,
                  (datalen <= cachelen - offset ? datalen : cachelen - offset));
    }
  }
  
  return (long)datalen;
}
