#define FD_CACHE_INVALID_HANDLE (~0UL)

typedef ulong fd_cache_handle;

struct fd_cache_entry {
    // Pointer to actual data or next entry in free list. Unused
    // entries have data_sz==-1.
    void* data;
    int data_sz;
    // Generation number. Incremented every time an entry is reused.
    uint gen;
    // Used to determine most recently used.
    ulong clock;
};
        
struct fd_cache {
    // Number of entries
    ulong entry_cnt;
    // Used to determine most recently used.
    ulong clock;
    ulong lastgc;
    // Newest member of free list
    struct fd_cache_entry* newest_free;
    // Oldest member of free list
    struct fd_cache_entry* oldest_free;
    ulong hits;
    ulong misses;
};

ulong fd_cache_align() { return 8U; }

ulong fd_cache_footprint(ulong entry_cnt) {
  return sizeof(struct fd_cache) + sizeof(struct fd_cache_entry)*entry_cnt;
}

struct fd_cache* fd_cache_new(void* mem, ulong entry_cnt) {
  struct fd_cache* self = (struct fd_cache*)mem;
  self->entry_cnt = entry_cnt;
  self->clock = self->lastgc = 0;
  self->hits = self->misses = 0;
  
  struct fd_cache_entry* entries = (struct fd_cache_entry*)(self + 1);
  self->oldest_free = entries;
  struct fd_cache_entry* ent = NULL;
  for (ulong i = 0; i < entry_cnt; ++i) {
    ent = entries + i;
    // Create a free entry
    ent->data = ent+1;
    ent->data_sz = -1;
    ent->gen = 0;
    ent->clock = 0;
  }
  // Terminate the free list
  ent->data = NULL;
  self->newest_free = ent;

  return self;
}

void fd_cache_destroy(struct fd_cache* self) {
  struct fd_cache_entry* const entries = (struct fd_cache_entry*)(self + 1);
  const ulong cnt = self->entry_cnt;
  for (ulong i = 0; i < cnt; ++i) {
    struct fd_cache_entry* ent = entries + i;
    if (ent->data_sz >= 0) {
      free(ent->data);
      ent->data = NULL;
      ent->data_sz = -1;
      ent->gen ++; // Invalidate existing handles
    }
  }
}

void fd_cache_release_entry(struct fd_cache* self, struct fd_cache_entry* ent) {
  free(ent->data);
  if (FD_UNLIKELY(self->newest_free == NULL))
    self->oldest_free = ent;
  else
    self->newest_free->data = ent;
  self->newest_free = ent;
  ent->data = NULL;
  ent->data_sz = -1;
  ent->gen ++; // Invalidate existing handles
}

// Release a bunch of old entries
void fd_cache_garbage_collect(struct fd_cache* self) {
  // Release about 1/4 of the entries
  ulong mark = self->lastgc + (self->clock - self->lastgc)/4;
  struct fd_cache_entry* const entries = (struct fd_cache_entry*)(self + 1);
  const ulong cnt = self->entry_cnt;
  for (ulong i = 0; i < cnt; ++i) {
    struct fd_cache_entry* ent = entries + i;
    if (ent->data_sz >= 0 && ent->clock < mark)
      fd_cache_release_entry(self, ent);
  }
  self->lastgc = mark;
}

// Allocate cache space of size data_sz. The handle is returned. *data
// is updated to refer to the resulting data pointer. The
// FD_CACHE_MALLOC macro performs the raw allocation.
fd_cache_handle fd_cache_allocate(struct fd_cache* self, void** data, uint data_sz) {
  // Reuse the oldest free entry. This minimizes the rate at which gen
  // is incremented.
  while (FD_UNLIKELY(self->oldest_free == NULL))
    fd_cache_garbage_collect(self);
  struct fd_cache_entry* ent = self->oldest_free;
  struct fd_cache_entry* next = (struct fd_cache_entry*)ent->data;
  self->oldest_free = next;
  if (FD_UNLIKELY(next == NULL))
    self->newest_free = NULL;
  ent->data = *data = malloc(data_sz);
  ent->data_sz = (int)data_sz;
  ent->clock = ++(self->clock);
  struct fd_cache_entry* entries = (struct fd_cache_entry*)(self + 1);
  // Encode the generation in the high bits of the handle, and the
  // entry number in the low bits
  return (((ulong)ent->gen)<<32U) | (ulong)(ent - entries);
}

// Lookup an entry by its handle. NULL is returned if the handle is
// invalid.
void* fd_cache_lookup(struct fd_cache* self, fd_cache_handle handle, uint* data_sz) {
  uint pos = (uint)handle; // Get the low 32 bits
  if (FD_UNLIKELY(pos >= self->entry_cnt)) {
    *data_sz = 0;
    return NULL;
  }
  struct fd_cache_entry* ent = (struct fd_cache_entry*)(self + 1) + pos;
  if (FD_UNLIKELY(ent->data_sz < 0 || ent->gen != handle>>32U)) {
    // Obsolete handle
    *data_sz = 0;
    self->misses ++;
    return NULL;
  }
  self->hits ++;
  *data_sz = (uint)ent->data_sz;
  ent->clock = ++(self->clock); // Don't release for a while
  return ent->data;
}

// Free the storage for the cache entry
void fd_cache_release(struct fd_cache* self, fd_cache_handle handle) {
  uint pos = (uint)handle; // Get the low 32 bits
  if (FD_UNLIKELY(pos >= self->entry_cnt)) {
    return;
  }
  struct fd_cache_entry* ent = (struct fd_cache_entry*)(self + 1) + pos;
  if (FD_UNLIKELY(ent->data_sz < 0 || ent->gen != handle>>32U)) {
    // Obsolete handle
    self->misses ++;
    return;
  }
  self->hits ++;
  fd_cache_release_entry(self, ent);
}
