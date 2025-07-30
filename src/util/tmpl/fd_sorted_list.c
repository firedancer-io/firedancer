/* SORTLIST_NAME gives the name of the function to declare (and the base
   name of auxiliary and/or variant functions). */

#ifndef SORTLIST_NAME
#error "SORTLIST_NAME must be defined"
#endif

/* SORTLIST_T gives the POD datatype to sort. */

#ifndef SORTLIST_T
#error "SORTLIST_T must be defined"
#endif

/* SORTLIST_KEY_T gives the type of the key. */

#ifndef SORTLIST_KEY_T
#error "SORTLIST_KEY_T must be defined"
#endif

/* SORTLIST_KEY_NAME gives the name of the key in the datatype. */

#ifndef SORTLIST_KEY_NAME
#define SORTLIST_KEY_NAME key
#endif

/* SORTLIST_BEFORE(a,b) evaluates to 1 if a<b is strictly true.  SAFETY TIP:
   This is not a 3-way comparison function! */

#ifndef SORTLIST_BEFORE
#define SORTLIST_BEFORE(a,b) (a)<(b)
#endif

#ifndef SORTLIST_IMPL_STYLE
#define SORTLIST_IMPL_STYLE 0
#endif

/* Implementation *****************************************************/

#if SORTLIST_IMPL_STYLE==0 /* local use only */
#define SORTLIST_STATIC FD_FN_UNUSED static
#else /* library header and/or implementation */
#define SORTLIST_STATIC
#endif

#define SORTLIST_(x)FD_EXPAND_THEN_CONCAT3(SORTLIST_NAME,_,x)

union SORTLIST_(element) {
  SORTLIST_T data;
  uint next_free;
};

typedef union SORTLIST_(element) SORTLIST_(element_t);

struct SORTLIST_(private) {
  uint sorted_cnt;       /* How many elements are already sorted */
  uint total_cnt;        /* How many elements are in the list */
  uint max;              /* Max number of elements */
  uint first_free;
  // uint offsets[total_cnt];
  // element pool[total_cnt];
};

typedef struct SORTLIST_(private) SORTLIST_(private_t);

struct SORTLIST_(joined) {
  SORTLIST_(private_t) * hdr;
  uint * offsets;
  SORTLIST_(element) * pool;
};
typedef struct SORTLIST_(joined) SORTLIST_(joined_t);

struct SORTLIST_(iter) {
  uint * current_offset;
  uint * end_offset;
  SORTLIST_(element) * pool;
};
typedef struct SORTLIST_(iter) SORTLIST_(iter_t);

#if SORTLIST_IMPL_STYLE!=2 /* need header */

FD_PROTOTYPES_BEGIN

SORTLIST_STATIC ulong SORTLIST_(align)( void );

SORTLIST_STATIC ulong SORTLIST_(footprint)( ulong max );

SORTLIST_STATIC ulong SORTLIST_(max_for_footprint)( ulong footprint );

SORTLIST_STATIC void * SORTLIST_(new)( void * shmem, ulong max );

SORTLIST_STATIC SORTLIST_(joined_t) SORTLIST_(join)( void * shsortlist, ulong max );

SORTLIST_STATIC ulong SORTLIST_(max)( SORTLIST_(joined_t) join );

SORTLIST_STATIC int SORTLIST_(is_full)( SORTLIST_(joined_t) join );

SORTLIST_STATIC inline void * SORTLIST_(leave)( SORTLIST_(joined_t) join ) { return join.hdr; }

SORTLIST_STATIC inline void * SORTLIST_(delete)( void * shmem ) { return shmem; }

SORTLIST_STATIC void SORTLIST_(resort)( SORTLIST_(joined_t) join );

SORTLIST_STATIC SORTLIST_T * SORTLIST_(query)( SORTLIST_(joined_t) join, SORTLIST_KEY_T const * key );

SORTLIST_STATIC int SORTLIST_(erase)( SORTLIST_(joined_t) join, SORTLIST_KEY_T const * key );

SORTLIST_STATIC SORTLIST_T * SORTLIST_(add)( SORTLIST_(joined_t) join, SORTLIST_KEY_T const * key );

SORTLIST_STATIC SORTLIST_(iter_t) SORTLIST_(iter_begin)( SORTLIST_(joined_t) join, int sorted_only );

SORTLIST_STATIC SORTLIST_(iter_t) SORTLIST_(iter_next)( SORTLIST_(iter_t) iter );

SORTLIST_STATIC SORTLIST_T * SORTLIST_(iter_data)( SORTLIST_(iter_t) iter );

SORTLIST_STATIC int SORTLIST_(iter_done)( SORTLIST_(iter_t) iter );

SORTLIST_STATIC void SORTLIST_(verify)( SORTLIST_(joined_t) join );

/* This function is provided by the caller. */
int SORTLIST_(compare)( SORTLIST_KEY_T const * a, SORTLIST_KEY_T const * b );

FD_PROTOTYPES_END

#endif

#if SORTLIST_IMPL_STYLE!=1 /* need implementations (assumes header already included) */

ulong
SORTLIST_(align)( void ) {
  return ( alignof(uint) > alignof(SORTLIST_(element)) ? alignof(uint) : alignof(SORTLIST_(element)) );
}

ulong
SORTLIST_(footprint)( ulong max ) {
  ulong off = sizeof( SORTLIST_(private_t) );
  off = fd_ulong_align_up( off, alignof(uint) );               off += max*sizeof(uint);
  off = fd_ulong_align_up( off, alignof(SORTLIST_(element)) ); off += max*sizeof( SORTLIST_(element) );
  return off;
}

ulong
SORTLIST_(max_for_footprint)( ulong footprint ) {
  return (footprint - sizeof( SORTLIST_(private_t) ))/(sizeof(uint) + sizeof( SORTLIST_(element) ));
}

SORTLIST_(joined_t)
SORTLIST_(join)( void * shsortlist, ulong max ) {
  SORTLIST_(joined_t) joined;
  SORTLIST_(private_t) * hdr = (SORTLIST_(private_t) *)shsortlist;
  joined.hdr = hdr;
  ulong off = sizeof( SORTLIST_(private_t) );
  off = fd_ulong_align_up( off, alignof(uint) );
  joined.offsets = (uint*) ( (ulong)hdr + off );
  off += max*sizeof(uint);
  off = fd_ulong_align_up( off, alignof(SORTLIST_(element)) );
  joined.pool = (SORTLIST_(element)*)( (ulong)hdr + off );
  return joined;
}

void *
SORTLIST_(new)( void * shmem, ulong max ) {
  SORTLIST_(joined_t) joined = SORTLIST_(join)( shmem, max );

  joined.hdr->sorted_cnt = 0;
  joined.hdr->total_cnt = 0;
  joined.hdr->max = (uint)max;
  SORTLIST_(element) * pool = joined.pool;
  uint last_free = UINT_MAX;
  for( uint i = 0; i < max; ++i ) {
    pool[i].next_free = last_free;
    last_free = i*sizeof(SORTLIST_(element));
  }
  joined.hdr->first_free = last_free;

  return shmem;
}

ulong
SORTLIST_(max)( SORTLIST_(joined_t) join ) {
  return join.hdr->max;
}

int
SORTLIST_(is_full)( SORTLIST_(joined_t) join ) {
  return join.hdr->first_free == UINT_MAX;
}

static int
SORTLIST_(private_compare)( const void * a, const void * b, void * arg ) {
  SORTLIST_(joined_t) * join = (SORTLIST_(joined_t) *)arg;
  /* Offsets are simple byte offsets into the pool to avoid a multiply */
  uint a_offset = *(uint const *)a;
  uint b_offset = *(uint const *)b;
  /* Push deletions to the end */
  if( FD_UNLIKELY( a_offset == b_offset ) ) return 0;
  if( FD_UNLIKELY( a_offset == UINT_MAX ) ) return 1;
  if( FD_UNLIKELY( b_offset == UINT_MAX ) ) return -1;
  SORTLIST_(element) const * a_elem = (SORTLIST_(element) const *)((ulong)join->pool + a_offset);
  SORTLIST_(element) const * b_elem = (SORTLIST_(element) const *)((ulong)join->pool + b_offset);
  return SORTLIST_(compare)( &a_elem->data.SORTLIST_KEY_NAME, &b_elem->data.SORTLIST_KEY_NAME );
}

void
SORTLIST_(resort)( SORTLIST_(joined_t) join ) {
  qsort_r( join.offsets, join.hdr->total_cnt, sizeof(uint), SORTLIST_(private_compare), &join );
  /* Clean up deletions */
  while( join.hdr->total_cnt > 0 && join.offsets[join.hdr->total_cnt - 1] == UINT_MAX ) {
    join.hdr->total_cnt--;
  }
  join.hdr->sorted_cnt = join.hdr->total_cnt;
}

/* Returns the position of the offset for the element with the given key, or
   UINT_MAX if not found.
*/
static uint
SORTLIST_(private_query)( SORTLIST_(joined_t) join, SORTLIST_KEY_T const * key ) {
  SORTLIST_(element) * pool = join.pool;
  /* Binary search for the key on the sorted offsets. If key is present,
     it is at position >= low and < high. */
  uint low = 0;
  uint high = join.hdr->sorted_cnt;
  while( low < high ) {
    uint mid = (low + high)>>1U;
    uint off = join.offsets[mid];

    if( FD_LIKELY( off != UINT_MAX ) ) { /* Not a deletion */
      SORTLIST_(element) const * elem = (SORTLIST_(element) const *)((ulong)pool + off);
      int r = SORTLIST_(compare)( &elem->data.SORTLIST_KEY_NAME, key );
      if( r == 0 ) return mid;
      if( r > 0 ) high = mid;
      else        low = mid+1;
      continue;
    }

    /* Find the element before the deletion */
    uint mid2 = mid;
    while( mid2 > low ) {
      off = join.offsets[--mid2];
      if( FD_LIKELY( off != UINT_MAX ) ) {
        SORTLIST_(element) const * elem = (SORTLIST_(element) const *)((ulong)pool + off);
        int r = SORTLIST_(compare)( &elem->data.SORTLIST_KEY_NAME, key );
        if( r == 0 ) return mid2;
        if( r > 0 ) { high = mid2; goto outer_loop; }
      }
    }

    /* Move low past the deletions */
    low = mid+1;
    while( low < high && join.offsets[low] == UINT_MAX ) low++;

    outer_loop: continue;
  }
  return UINT_MAX;
}

SORTLIST_T *
SORTLIST_(query)( SORTLIST_(joined_t) join, SORTLIST_KEY_T const * key ) {
  uint idx = SORTLIST_(private_query)( join, key );
  if( idx == UINT_MAX ) return NULL;
  uint off = join.offsets[idx];
  SORTLIST_(element) * elem = (SORTLIST_(element) *)((ulong)join.pool + off);
  return &elem->data;
}

/* Returns 0 if the element was found and erased, 1 if the element was not
   found. */
int
SORTLIST_(erase)( SORTLIST_(joined_t) join, SORTLIST_KEY_T const * key ) {
  uint idx = SORTLIST_(private_query)( join, key );
  if( idx == UINT_MAX ) return 1;
  uint off = join.offsets[idx];
  SORTLIST_(element) * elem = (SORTLIST_(element) *)((ulong)join.pool + off);
  elem->next_free = join.hdr->first_free;
  join.hdr->first_free = off;
  join.offsets[idx] = UINT_MAX;
  return 0;
}

/* Just add the element to the end of the list for now. resort must be called
   after all adds. */
SORTLIST_T *
SORTLIST_(add)( SORTLIST_(joined_t) join, SORTLIST_KEY_T const * key ) {
  uint off = join.hdr->first_free;
  if( off == UINT_MAX ) {
    /* No free elements */
    FD_LOG_ERR(( "No free elements in SORTLIST_(add)" ));
    return NULL;
  }
  /* Add the element */
  SORTLIST_(element) * elem = (SORTLIST_(element) *)((ulong)join.pool + off);
  join.hdr->first_free = elem->next_free;
  elem->data.SORTLIST_KEY_NAME = *key;
  join.offsets[join.hdr->total_cnt++] = off;
  FD_TEST( join.hdr->total_cnt <= join.hdr->max );
  return &elem->data;
}

SORTLIST_(iter_t)
SORTLIST_(iter_begin)( SORTLIST_(joined_t) join, int sorted_only ) {
  SORTLIST_(iter_t) iter;
  iter.current_offset = join.offsets;
  iter.end_offset = join.offsets + (sorted_only ? join.hdr->sorted_cnt : join.hdr->total_cnt);
  iter.pool = join.pool;
  while( iter.current_offset < iter.end_offset ) {
    if( *iter.current_offset != UINT_MAX ) break;
    iter.current_offset ++;
  }
  return iter;
}

SORTLIST_(iter_t)
SORTLIST_(iter_next)( SORTLIST_(iter_t) iter ) {
  while( ++( iter.current_offset ) < iter.end_offset ) {
    if( *iter.current_offset != UINT_MAX ) break;
  }
  return iter;
}

SORTLIST_T *
SORTLIST_(iter_data)( SORTLIST_(iter_t) iter ) {
  return &((SORTLIST_(element) *)((ulong)iter.pool + *iter.current_offset))->data;
}

int
SORTLIST_(iter_done)( SORTLIST_(iter_t) iter ) {
  return iter.current_offset == iter.end_offset;
}

void
SORTLIST_(verify)( SORTLIST_(joined_t) join ) {
  FD_TEST( join.hdr->sorted_cnt <= join.hdr->total_cnt );
  FD_TEST( join.hdr->total_cnt <= join.hdr->max );

  char * tags = (char*)alloca(join.hdr->max);
  memset( tags, 0, join.hdr->max );

  uint cnt = 0;
  for( uint i = 0; i < join.hdr->total_cnt; ++i ) {
    uint off = join.offsets[i];
    if( off == UINT_MAX ) continue;
    FD_TEST( off % sizeof(SORTLIST_(element)) == 0 && off/sizeof(SORTLIST_(element)) < join.hdr->max );
    FD_TEST( tags[off/sizeof(SORTLIST_(element))] == 0 );
    tags[off/sizeof(SORTLIST_(element))] = 1;
    cnt++;
  }

  uint off = join.hdr->first_free;
  while( off != UINT_MAX ) {
    FD_TEST( off % sizeof(SORTLIST_(element)) == 0 && off/sizeof(SORTLIST_(element)) < join.hdr->max );
    FD_TEST( tags[off/sizeof(SORTLIST_(element))] == 0 );
    tags[off/sizeof(SORTLIST_(element))] = 2;
    off = ((SORTLIST_(element) *)((ulong)join.pool + off))->next_free;
    cnt++;
  }
  FD_TEST( cnt == join.hdr->max );

  SORTLIST_KEY_T const * last_key = NULL;
  for( uint i = 0; i < join.hdr->sorted_cnt; ++i ) {
    uint off = join.offsets[i];
    if( off == UINT_MAX ) continue;
    SORTLIST_(element) const * elem = (SORTLIST_(element) const *)((ulong)join.pool + off);
    SORTLIST_KEY_T const * next_key = &elem->data.SORTLIST_KEY_NAME;
    if( last_key ) {
      FD_TEST( SORTLIST_(compare)( next_key, last_key ) > 0 );
    }
    last_key = next_key;
  }
}

#endif /* SORTLIST_IMPL_STYLE!=1 */

#undef SORTLIST_
#undef SORTLIST_STATIC

#undef SORTLIST_IMPL_STYLE
#undef SORTLIST_BEFORE
#undef SORTLIST_KEY_T
#undef SORTLIST_KEY_NAME
#undef SORTLIST_T
#undef SORTLIST_NAME
