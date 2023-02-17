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
    uint capacity;
    uint used;
    ulong hashseed;
} __attribute__ ((aligned(64)));

// Construct a map, using as much of the footprint as possible. The
// actual footprint used is returned.
ulong MAP_(new)(struct MAP_NAME* self, ulong footprint, ulong hashseed) {
  self->hashseed = hashseed;
  
  // Compute a number of headers that fills the footprint with the
  // average chain length between 1 and 2 at max capacity.
  uint cnt = 1;
  while (sizeof(struct MAP_NAME) + ((ulong)cnt)*(sizeof(uint) + sizeof(MAP_ELEMENT)) < footprint)
    cnt <<= 1;
  self->header_cnt = cnt;

  // Set all the chain headers to null. We use -1 because zero is a
  // valid entry number.
  uint* headers = (uint*)(self+1);
  fd_memset(headers, -1, sizeof(uint)*cnt);

  // Build the free list up to the footprint size
  uint* last = &self->free_list;
  MAP_ELEMENT* elembase = (MAP_ELEMENT*)(headers + cnt);
  uint i;
  for (i = 0; ; ++i) {
    MAP_ELEMENT* elem = elembase + i;
    if ((char*)(elem + 1) > (char*)self + footprint)
      break;
    *last = i;
    last = &elem->next;
  }
  *last = MAP_LIST_TERM;
  self->capacity = i;
  self->used = 0;
  return sizeof(struct MAP_NAME) + cnt*sizeof(uint) + i*sizeof(MAP_ELEMENT);
}

void MAP_(destroy)(struct MAP_NAME* self) {
  (void)self;
}

// Insert a key into the map and return the resulting
// element. *exists is set to true if the element already existed in
// the map. Otherwise, the element is returned uninitialized (only key
// and next are set). If out of space, a NULL is returned.
MAP_ELEMENT* MAP_(insert)(struct MAP_NAME* self, MAP_KEY const* key, int* exists) {
  const uint cnt = self->header_cnt;
  uint* const headers = (uint*)(self+1);
  MAP_ELEMENT* const elembase = (MAP_ELEMENT*)(headers + cnt);

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
  const uint cnt = self->header_cnt;
  uint* const headers = (uint*)(self+1);
  MAP_ELEMENT* const elembase = (MAP_ELEMENT*)(headers + cnt);

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
  const uint cnt = self->header_cnt;
  uint* const headers = (uint*)(self+1);
  MAP_ELEMENT* const elembase = (MAP_ELEMENT*)(headers + cnt);

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

// Return true if the data structure is internally consistent
int MAP_(validate)(struct MAP_NAME* self) {
  const uint cnt = self->header_cnt;
  uint* const headers = (uint*)(self+1);
  MAP_ELEMENT* const elembase = (MAP_ELEMENT*)(headers + cnt);

  uint used = 0;
  for (uint i = 0; i < cnt; ++i) {
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
