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
  // uint index[total_cnt];
  // element pool[total_cnt];
};

typedef struct SORTLIST_(private) SORTLIST_(private_t);

struct SORTLIST_(joined) {
  SORTLIST_(private_t) * hdr;
  uint * index;
  SORTLIST_(element) * pool;
};

typedef struct SORTLIST_(joined) SORTLIST_(joined_t);

#if SORTLIST_IMPL_STYLE!=2 /* need header */

FD_PROTOTYPES_BEGIN

SORTLIST_STATIC ulong SORTLIST_(align)( void );

SORTLIST_STATIC ulong SORTLIST_(footprint)( ulong max );

SORTLIST_STATIC ulong SORTLIST_(max_for_footprint)( ulong footprint );

SORTLIST_STATIC void * SORTLIST_(new)( void * shmem, ulong max );

SORTLIST_STATIC SORTLIST_(joined_t) SORTLIST_(join)( void * shsortlist, ulong max );

SORTLIST_STATIC ulong SORTLIST_(max)( SORTLIST_(joined_t) join );

SORTLIST_STATIC inline void * SORTLIST_(leave)( SORTLIST_(joined_t) join ) { return join.hdr; }

SORTLIST_STATIC inline void * SORTLIST_(delete)( void * shmem ) { return shmem; }

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
  joined.index = (uint*) ( (ulong)hdr + off );
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
    last_free = i;
  }
  joined.hdr->first_free = last_free;

  return shmem;
}

ulong
SORTLIST_(max)( SORTLIST_(joined_t) join ) {
  return join.hdr->max;
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
