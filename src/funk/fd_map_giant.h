/***
    A hash table implementation suitable for gigantic tables. Memory
    efficiency and flexible footprint is prioritized. Elements that
    are recently used are moved to the front of the chains.

    Assumes map elements look like this:
    MAP_ELEMENT {
      MAP_KEY key;
      uint next;
      ...
    };
***/

#ifndef MAP_NAME
#error "Define MAP_NAME"
#endif

#ifndef MAP_ELEMENT
#error "Define MAP_ELEMENT"
#endif

#ifndef MAP_KEY
#error "Define MAP_KEY"
#endif

#define MAP_(n)       FD_EXPAND_THEN_CONCAT3(MAP_NAME,_,n)
#define MAP_KEY_(n)   FD_EXPAND_THEN_CONCAT3(MAP_KEY,_,n)
#define MAP_LIST_TERM ((uint)-1)

struct MAP_NAME {
    uint header_cnt;
    uint free_list;
    ulong elembase;
    ulong capacity;
    ulong used;
    ulong hashseed;
} __attribute__ ((aligned(64)));

ulong MAP_(align)(void) { return 64U; }

ulong MAP_(footprint)(ulong max) {
  // Round up the header count to powers of 2 such that the average
  // chain length is between 1 and 2
  ulong header_cnt = 1;
  while (header_cnt*2 < max)
    header_cnt <<= 1;
  // Elements must start on a cache line
  return fd_ulong_align_up(sizeof(struct MAP_NAME) + header_cnt*sizeof(uint), 64) + max*sizeof(MAP_ELEMENT);
}

// Construct a map
struct MAP_NAME* MAP_(new)(void* mem, ulong max, ulong hashseed) {
  struct MAP_NAME* self = (struct MAP_NAME*)mem;
  self->hashseed = hashseed;
  
  // Round up the header count to powers of 2 such that the average
  // chain length is between 1 and 2
  ulong header_cnt = 1;
  while (header_cnt*2 < max)
    header_cnt <<= 1;
  self->header_cnt = (uint)header_cnt;

  // Set all the chain headers to null. We use -1 because zero is a
  // valid entry number.
  uint* headers = (uint*)(self+1);
  fd_memset(headers, -1, sizeof(uint)*header_cnt);

  // Build the free list
  uint* last = &self->free_list;
  // Elements must start on a cache line
  self->elembase = fd_ulong_align_up(sizeof(struct MAP_NAME) + header_cnt*sizeof(uint), 64);
  MAP_ELEMENT* const elembase = (MAP_ELEMENT*)((char*)self + self->elembase);
  for (uint i = 0; i < max; ++i) {
    MAP_ELEMENT* elem = elembase + i;
    *last = i;
    last = &elem->next;
  }
  *last = MAP_LIST_TERM;
  self->capacity = max;
  self->used = 0;
  return self;
}

void MAP_(destroy)(struct MAP_NAME* self) {
  (void)self;
}

// Insert a key into the map and return the resulting
// element. *exists is set to true if the element already existed in
// the map. Otherwise, the element is returned uninitialized (only key
// and next are set). If out of space, a NULL is returned.
MAP_ELEMENT* MAP_(insert)(struct MAP_NAME* self, MAP_KEY const* key, int* exists) {
  const ulong cnt = self->header_cnt;
  uint* const headers = (uint*)(self+1);
  MAP_ELEMENT* const elembase = (MAP_ELEMENT*)((char*)self + self->elembase);

  // See if the key exists
  uint* first = headers + (MAP_KEY_(hash)(key, self->hashseed) & (cnt-1));
  uint* cur = first;
  for (;;) {
    const uint i = *cur;
    if (i == MAP_LIST_TERM)
      break;
    MAP_ELEMENT* elem = elembase + i;
    if (MAP_KEY_(equal)(key, &elem->key)) {
      // Found the key. Move it to the front of the chain.
      if (cur != first) {
        *cur = elem->next;
        elem->next = *first;
        *first = i;
      }
      *exists = 1;
      return elem;
    }
    // Retain the pointer to next so we can rewrite it later.
    cur = &elem->next;
  }
  // Allocate an entry of the first list
  const uint i = self->free_list;
  if (FD_UNLIKELY(i == MAP_LIST_TERM)) {
    // Out of space
    *exists = 0;
    return NULL;
  }
  MAP_ELEMENT* elem = elembase + i;
  self->free_list = elem->next;
  MAP_KEY_(copy)(&elem->key, key);
  elem->next = *first;
  *first = i;
  *exists = 0;
  self->used ++;
  return elem;
}
  
// Lookup a key in the map and return the resulting element. A NULL is
// returned if not found.
MAP_ELEMENT* MAP_(query)(struct MAP_NAME* self, MAP_KEY const* key) {
  const ulong cnt = self->header_cnt;
  uint* const headers = (uint*)(self+1);
  MAP_ELEMENT* const elembase = (MAP_ELEMENT*)((char*)self + self->elembase);

  // See if the key exists
  uint* first = headers + (MAP_KEY_(hash)(key, self->hashseed) & (cnt-1));
  uint* cur = first;
  for (;;) {
    const uint i = *cur;
    if (i == MAP_LIST_TERM)
      break;
    MAP_ELEMENT* elem = elembase + i;
    if (MAP_KEY_(equal)(key, &elem->key)) {
      // Found the key. Move it to the front of the chain.
      if (cur != first) {
        *cur = elem->next;
        elem->next = *first;
        *first = i;
      }
      return elem;
    }
    // Retain the pointer to next so we can rewrite it later.
    cur = &elem->next;
  }
  return NULL;
}
  
// Remove a key from the map. A pointer to the former entry is
// returned to allow additional cleanup.
MAP_ELEMENT* MAP_(remove)(struct MAP_NAME* self, MAP_KEY const* key) {
  const ulong cnt = self->header_cnt;
  uint* const headers = (uint*)(self+1);
  MAP_ELEMENT* const elembase = (MAP_ELEMENT*)((char*)self + self->elembase);

  // See if the key exists
  uint* first = headers + (MAP_KEY_(hash)(key, self->hashseed) & (cnt-1));
  uint* cur = first;
  for (;;) {
    const uint i = *cur;
    if (i == MAP_LIST_TERM)
      break;
    MAP_ELEMENT* elem = elembase + i;
    if (MAP_KEY_(equal)(key, &elem->key)) {
      // Move the element to the free list
      *cur = elem->next;
      elem->next = self->free_list;
      self->free_list = i;
      self->used --; 
      return elem;
    }
    // Retain the pointer to next so we can rewrite it later.
    cur = &elem->next;
  }
  // Key not found
  return NULL;
}

struct MAP_(iter) {
  int header;
  uint cur;
};

// Initialize a map iterator
void MAP_(iter_init)(struct MAP_NAME* self, struct MAP_(iter)* iter) {
  (void)self;
  iter->header = -1;
  iter->cur = MAP_LIST_TERM;
}

// Get the next element, or NULL if done
MAP_ELEMENT* MAP_(iter_next)(struct MAP_NAME* self, struct MAP_(iter)* iter) {
  const ulong cnt = self->header_cnt;
  uint* const headers = (uint*)(self+1);
  MAP_ELEMENT* const elembase = (MAP_ELEMENT*)((char*)self + self->elembase);

  if (iter->cur != MAP_LIST_TERM) {
    MAP_ELEMENT* elem = elembase + iter->cur;
    iter->cur = elem->next;
    return elem;
  }
  if (iter->header == (int)cnt)
    return NULL;
  while (++(iter->header) < (int)cnt) {
    iter->cur = headers[iter->header];
    if (iter->cur != MAP_LIST_TERM) {
      MAP_ELEMENT* elem = elembase + iter->cur;
      iter->cur = elem->next;
      return elem;
    }
  }
  return NULL;
}

// Return true if the data structure is internally consistent
int MAP_(validate)(struct MAP_NAME* self) {
  const ulong cnt = self->header_cnt;
  uint* const headers = (uint*)(self+1);
  MAP_ELEMENT* const elembase = (MAP_ELEMENT*)((char*)self + self->elembase);

  ulong used = 0;
  for (ulong i = 0; i < cnt; ++i) {
    uint j = headers[i];
    while (j != MAP_LIST_TERM) {
      MAP_ELEMENT* elem = elembase + j;
      if ((MAP_KEY_(hash)(&elem->key, self->hashseed) & (cnt-1)) != i)
        return 0;
      used++;
      j = elem->next;
    }
  }
  if (used != self->used)
    return 0;

  used = 0;
  uint j = self->free_list;
  while (j != MAP_LIST_TERM) {
    MAP_ELEMENT* elem = elembase + j;
    used++;
    j = elem->next;
  }
  if (used != self->capacity - self->used)
    return 0;

  return 1;
}

#undef MAP_
#undef MAP_KEY_
#undef MAP_LIST_TERM
