/* MAP_NAME gives the API prefix to use for map */

#ifndef MAP_NAME
#error "Define MAP_NAME"
#endif

/* MAP_ELE_T is the map element type. */

#ifndef MAP_ELE_T
#error "Define MAP_ELE_T"
#endif

/* MAP_KEY_T is the map key type */

#ifndef MAP_KEY_T
#define MAP_KEY_T ulong
#endif

/* MAP_KEY is the MAP_ELE_T key field */

#ifndef MAP_KEY
#define MAP_KEY key
#endif

/* MAP_IDX_T is the type used for the next field in the MAP_ELE_T.
   Should be a primitive unsigned integer type.  Defaults to ulong.  A
   map can't use element stores with more elements than the maximum
   value that can be represented by a MAP_IDX_T.  (E.g. if ushort, the
   maximum size element store usable by the map is 65535 elements.) */

#ifndef MAP_IDX_T
#define MAP_IDX_T ulong
#endif

/* MAP_NEXT is the MAP_ELE_T next field */

#ifndef MAP_NEXT
#define MAP_NEXT next
#endif

#ifndef MAP_PREV
#define MAP_PREV prev
#endif

/* MAP_KEY_EQ returns 0/1 if *k0 is the same/different as *k1 */

#ifndef MAP_KEY_EQ
#define MAP_KEY_EQ(k0,k1) ((*(k0))==(*(k1)))
#endif

/* MAP_KEY_HASH maps *key into ulong uniform pseudo randomly. */

#ifndef MAP_KEY_HASH
#define MAP_KEY_HASH(key,seed) fd_ulong_hash( (*(key)) ^ (seed) )
#endif

/* MAP_MAGIC is the magic number to use for the structure to aid in
   persistent and or IPC usage. */

#ifndef MAP_MAGIC
#define MAP_MAGIC (0xf17eda2c37c3a900UL) /* firedancer cmap version 0 */
#endif

/* 0 - local use only
   1 - library header declaration
   2 - library implementation */

#ifndef MAP_IMPL_STYLE
#define MAP_IMPL_STYLE 0
#endif

/* Implementation *****************************************************/

/* Constructors and verification log details on failure (rest only needs
   fd_bits.h, consider making logging a compile time option). */

#include "../../util/log/fd_log.h"

#define MAP_(n) FD_EXPAND_THEN_CONCAT3(MAP_NAME,_,n)

#if MAP_IMPL_STYLE==0 || MAP_IMPL_STYLE==1 /* need structures and inlines */

struct MAP_(private) {

  /* join points here */

  ulong magic;     /* == MAP_MAGIC */
  ulong seed;      /* Hash seed, arbitrary */
  ulong chain_cnt; /* Number of chains, positive integer power-of-two */

  /* MAP_IDX_T chain[ chain_cnt ] here */

};

typedef struct MAP_(private) MAP_(private_t);

typedef MAP_(private_t) MAP_(t);

struct MAP_(iter) {
  ulong chain_rem;
  ulong ele_idx;
};

typedef struct MAP_(iter) MAP_(iter_t);

FD_PROTOTYPES_BEGIN

/* map_private returns the location of the map private for a current
   local join.  Assumes join is a current local join.  map_private_const
   is a const correct version. */

FD_FN_CONST static inline MAP_(private_t) *       MAP_(private)      ( MAP_(t) *       join ) { return join; }
FD_FN_CONST static inline MAP_(private_t) const * MAP_(private_const)( MAP_(t) const * join ) { return join; }

/* map_private_chain returns the location in the caller's address space
   of the map chains.  Assumes map is valid.  map_private_chain_const is
   a const correct version. */

FD_FN_CONST static inline MAP_IDX_T *
MAP_(private_chain)( MAP_(private_t) * map ) {
  return (MAP_IDX_T *)(map+1);
}

FD_FN_CONST static inline MAP_IDX_T const *
MAP_(private_chain_const)( MAP_(private_t) const * map ) {
  return (MAP_IDX_T const *)(map+1);
}

/* map_private_chain_idx returns the index of the chain (in
   [0,chain_cnt) that will contain the element corresponding to key (if
   present at all) for a map with chain_cnt elements and seed.  Assumes
   chain_cnt is an integer power-of-two.  Assumes key points to a key is
   in the caller's address space that will not be changed concurrently.
   Retains no interest in key on return. */

FD_FN_PURE static inline ulong
MAP_(private_chain_idx)( MAP_KEY_T const * key,
                         ulong             seed,
                         ulong             chain_cnt ) {
  return (MAP_KEY_HASH( (key), (seed) )) & (chain_cnt-1UL);
}

/* map_private_{box,unbox} compress / decompress 64-bit in-register
   indices to/from their in-memory representations. */

FD_FN_CONST static inline MAP_IDX_T MAP_(private_box)  ( ulong     idx  ) { return (MAP_IDX_T)idx;  }
FD_FN_CONST static inline ulong     MAP_(private_unbox)( MAP_IDX_T cidx ) { return (ulong)    cidx; }

/* map_private_idx_null returns the element storage index that
   represents NULL. */

FD_FN_CONST static inline ulong MAP_(private_idx_null)( void ) { return (ulong)(MAP_IDX_T)(~0UL); }

/* map_private_idx_is_null returns 1 if idx is the NULL map index
   and 0 otherwise. */

FD_FN_CONST static inline int MAP_(private_idx_is_null)( ulong idx ) { return idx==(ulong)(MAP_IDX_T)(~0UL); }

FD_FN_CONST static inline ulong MAP_(ele_max)( void ) { return (ulong)(MAP_IDX_T)(~0UL); }

FD_FN_CONST static inline ulong
MAP_(chain_max)( void ) {
  return fd_ulong_pow2_dn( (ULONG_MAX + 1UL - alignof(MAP_(t)) - sizeof(MAP_(t))) / sizeof(MAP_IDX_T) );
}

FD_FN_CONST static inline ulong
MAP_(chain_cnt_est)( ulong ele_max_est ) {

  /* Clamp to be in [1,ele_max] (as ele_max_est 0 is degenerate and as
     the map is guaranteed to hold at most ele_max keys). */

  ele_max_est = fd_ulong_min( fd_ulong_max( ele_max_est, 1UL ), MAP_(ele_max)() );

  /* Compute the number of chains as the power of 2 that makes the
     average chain length between ~1 and ~2 when ele_max_est are stored
     in the map and then clamp to the chain max. */

  ulong chain_min = (ele_max_est>>1) + (ele_max_est&1UL); /* chain_min = ceil(ele_max_est/2), in [1,2^63], computed w/o overflow */
  ulong chain_cnt = fd_ulong_pow2_up( chain_min );        /* Power of 2 in [1,2^63] */

  return fd_ulong_min( chain_cnt, MAP_(chain_max)() );
}

FD_FN_PURE static inline ulong MAP_(chain_cnt)( MAP_(t) const * join ) { return MAP_(private_const)( join )->chain_cnt; }
FD_FN_PURE static inline ulong MAP_(seed)     ( MAP_(t) const * join ) { return MAP_(private_const)( join )->seed;      }

FD_FN_PURE static inline int
MAP_(key_eq)( MAP_KEY_T const * k0,
              MAP_KEY_T const * k1 ) {
  return !!(MAP_KEY_EQ( (k0), (k1) ));
}

FD_FN_PURE static inline ulong
MAP_(key_hash)( MAP_KEY_T const * key,
                ulong             seed ) {
  return (MAP_KEY_HASH( (key), (seed) ));
}

FD_PROTOTYPES_END

#endif

#if MAP_IMPL_STYLE==1 /* need prototypes */

FD_PROTOTYPES_BEGIN

FD_FN_CONST ulong MAP_(align)    ( void );
FD_FN_CONST ulong MAP_(footprint)( ulong chain_cnt );
void *            MAP_(new)      ( void * shmem, ulong chain_cnt, ulong seed );
MAP_(t) *         MAP_(join)     ( void * shmap );
void *            MAP_(leave)    ( MAP_(t) * join );
void *            MAP_(delete)   ( void * shmap );

MAP_(t) *
MAP_(idx_insert)( MAP_(t) *   join,
                  ulong       ele_idx,
                  MAP_ELE_T * pool );

FD_FN_PURE ulong
MAP_(idx_query)( MAP_(t) *         join,
                 MAP_KEY_T const * key,
                 ulong             sentinel,
                 MAP_ELE_T *       pool );

FD_FN_PURE ulong
MAP_(idx_query_const)( MAP_(t) const *   join,
                       MAP_KEY_T const * key,
                       ulong             sentinel,
                       MAP_ELE_T const * pool );

FD_PROTOTYPES_END

#else /* need implementations */

#if MAP_IMPL_STYLE==0 /* local only */
#define MAP_IMPL_STATIC FD_FN_UNUSED static
#else
#define MAP_IMPL_STATIC
#endif

FD_FN_CONST MAP_IMPL_STATIC ulong MAP_(align)( void ) { return alignof(MAP_(t)); }

FD_FN_CONST MAP_IMPL_STATIC ulong
MAP_(footprint)( ulong chain_cnt ) {
  if( !(fd_ulong_is_pow2( chain_cnt ) & (chain_cnt<=MAP_(chain_max)())) ) return 0UL;
  return fd_ulong_align_up( sizeof(MAP_(t)) + chain_cnt*sizeof(MAP_IDX_T), alignof(MAP_(t)) ); /* no overflow */
}

MAP_IMPL_STATIC void *
MAP_(new)( void * shmap,
           ulong  chain_cnt,
           ulong  seed ) {

  if( FD_UNLIKELY( !shmap ) ) {
    FD_LOG_WARNING(( "NULL shmap" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shmap, MAP_(align)() ) ) ) {
    FD_LOG_WARNING(( "misaligned shmap" ));
    return NULL;
  }

  ulong footprint = MAP_(footprint)( chain_cnt );
  if( FD_UNLIKELY( !footprint ) ) {
    FD_LOG_WARNING(( "bad footprint" ));
    return NULL;
  }

  /* seed is arbitrary */

  /* Init the metadata */

  MAP_(private_t) * map = (MAP_(private_t) *)shmap;

  map->seed      = seed;
  map->chain_cnt = chain_cnt;

  /* Set all the chains to NULL */

  MAP_IDX_T * chain = MAP_(private_chain)( map );
  for( ulong chain_idx=0UL; chain_idx<chain_cnt; chain_idx++ ) chain[ chain_idx ] = MAP_(private_box)( MAP_(private_idx_null)() );

  FD_COMPILER_MFENCE();
  FD_VOLATILE( map->magic ) = MAP_MAGIC;
  FD_COMPILER_MFENCE();

  return shmap;
}

MAP_IMPL_STATIC MAP_(t) *
MAP_(join)( void * shmap ) {
  MAP_(private_t) * map = (MAP_(private_t) *)shmap;

  if( FD_UNLIKELY( !map ) ) {
    FD_LOG_WARNING(( "NULL shmap" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)map, MAP_(align)() ) ) ) {
    FD_LOG_WARNING(( "misaligned shmap" ));
    return NULL;
  }

  if( FD_UNLIKELY( map->magic!=MAP_MAGIC ) ) {
    FD_LOG_WARNING(( "bad magic" ));
    return NULL;
  }

  return (MAP_(t) *)map;
}

MAP_IMPL_STATIC void *
MAP_(leave)( MAP_(t) * join ) {

  if( FD_UNLIKELY( !join ) ) {
    FD_LOG_WARNING(( "NULL join" ));
    return NULL;
  }

  return (void *)join;
}

MAP_IMPL_STATIC void *
MAP_(delete)( void * shmap ) {
  MAP_(private_t) * map = (MAP_(private_t) *)shmap;

  if( FD_UNLIKELY( !map ) ) {
    FD_LOG_WARNING(( "NULL shmap" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)map, MAP_(align)() ) ) ) {
    FD_LOG_WARNING(( "misaligned shmap" ));
    return NULL;
  }

  if( FD_UNLIKELY( map->magic!=MAP_MAGIC ) ) {
    FD_LOG_WARNING(( "bad magic" ));
    return NULL;
  }

  FD_COMPILER_MFENCE();
  FD_VOLATILE( map->magic ) = 0UL;
  FD_COMPILER_MFENCE();

  return shmap;
}

MAP_IMPL_STATIC MAP_(t) *
MAP_(idx_insert)( MAP_(t) *   join,
                  ulong       ele_idx,
                  MAP_ELE_T * pool ) {
  MAP_(private_t) * map = MAP_(private)( join );

  MAP_IDX_T * head = MAP_(private_chain)( map ) + MAP_(private_chain_idx)( &pool[ ele_idx ].MAP_KEY, map->seed, map->chain_cnt );

  ulong prev_head = MAP_(private_unbox)( *head );
  MAP_IDX_T _dummy[1];
  *fd_ptr_if( !MAP_(private_idx_is_null)( prev_head ), &pool[ prev_head ].MAP_PREV, _dummy ) = MAP_(private_box)( ele_idx );

  pool[ ele_idx ].MAP_PREV = MAP_(private_box)( MAP_(private_idx_null)() );
  pool[ ele_idx ].MAP_NEXT = MAP_(private_box)( prev_head );
  *head = MAP_(private_box)( ele_idx );

  return join;
}

FD_FN_PURE MAP_IMPL_STATIC ulong
MAP_(idx_query_const)( MAP_(t) const *   join,
                       MAP_KEY_T const * key,
                       ulong             sentinel,
                       MAP_ELE_T const * pool ) {
  MAP_(private_t) const * map = MAP_(private_const)( join );

  /* Find the key */

  MAP_IDX_T const * cur = MAP_(private_chain_const)( map ) + MAP_(private_chain_idx)( key, map->seed, map->chain_cnt );
  for(;;) {
    ulong ele_idx = MAP_(private_unbox)( *cur );
    if( FD_UNLIKELY( MAP_(private_idx_is_null)( ele_idx ) ) ) break; /* optimize for found */
    if( FD_LIKELY( MAP_(key_eq)( key, &pool[ ele_idx ].MAP_KEY ) ) ) return ele_idx; /* optimize for found */
    cur = &pool[ ele_idx ].MAP_NEXT;
  }

  /* Not found */

  return sentinel;
}

#undef MAP_IMPL_STATIC

#endif

#if MAP_IMPL_STYLE==0 || MAP_IMPL_STYLE==1 /* need inlines */

FD_PROTOTYPES_BEGIN

static inline MAP_(t) *
MAP_(ele_insert)( MAP_(t) *   join,
                  MAP_ELE_T * ele,
                  MAP_ELE_T * pool ) {
  return MAP_(idx_insert)( join, (ulong)(ele-pool), pool );
}

FD_FN_PURE static inline MAP_ELE_T *
MAP_(ele_query)( MAP_(t) *         join,
                 MAP_KEY_T const * key,
                 MAP_ELE_T *       sentinel,
                 MAP_ELE_T *       pool ) {
  ulong ele_idx = MAP_(idx_query_const)( join, key, MAP_(private_idx_null)(), pool );
  return fd_ptr_if( !MAP_(private_idx_is_null)( ele_idx ), (MAP_ELE_T       *)( (ulong)pool + (ele_idx * sizeof(MAP_ELE_T)) ), sentinel );
}

FD_FN_PURE static inline MAP_ELE_T const *
MAP_(ele_query_const)( MAP_(t) const *   join,
                       MAP_KEY_T const * key,
                       MAP_ELE_T const * sentinel,
                       MAP_ELE_T const * pool ) {
  ulong ele_idx = MAP_(idx_query_const)( join, key, MAP_(private_idx_null)(), pool );
  return fd_ptr_if( !MAP_(private_idx_is_null)( ele_idx ), (MAP_ELE_T const *)( (ulong)pool + (ele_idx * sizeof(MAP_ELE_T)) ), sentinel );
}

FD_PROTOTYPES_END

#endif

#undef MAP_

#undef MAP_IMPL_STYLE
#undef MAP_MAGIC
#undef MAP_KEY_HASH
#undef MAP_KEY_EQ
#undef MAP_NEXT
#undef MAP_IDX_T
#undef MAP_KEY
#undef MAP_KEY_T
#undef MAP_ELE_T
#undef MAP_NAME
