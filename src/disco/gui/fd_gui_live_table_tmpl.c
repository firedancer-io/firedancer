/*
Generate prototypes, inlines and implementations for tabular viewports
with a bounded compile-time number of columns and a bounded run-time
fixed row capacity.

A tabular viewport stores a collections of views into some underlying
table.  Each view has an associated sort key which determines the order
of the rows in the view.

This API is designed for ultra tight coupling with pools, treaps,
heaps, maps, other tables, etc.  Likewise, a live table can be persisted
beyond the lifetime of the creating process, used concurrently in
many common operations, used inter-process, relocated in memory,
naively serialized/deserialized, moved between hosts, supports index
compression for cache and memory bandwidth efficiency, etc.

Typical usage:

todo ... fix docs

    struct myrow {
      ulong col1;
      uint col2;
      ...
    };
    typedef struct myrow myrow_t;

    static int col1_cmp( void const * a, void const * b ) { return (*(ulong *)a > *(ulong *)b) - (*(ulong *)a < *(ulong *)b); }
    static int col2_cmp( void const * a, void const * b ) { return (*( uint *)a > *( uint *)b) - (*( uint *)a < *( uint *)b); }

    static ulong col1_hash( void const * key ) { return fd_ulong_hash( *(ulong *)key ); }
    static ulong col2_hash( void const * key ) { return fd_ulong_hash( (ulong)*(uint *)key; }

    mytable_sort_key_t my_sort_key = { .col = { 0, 1 }, .dir =  { 0, 1 } };

    #define LIVE_TABLE_NAME mytable
    #define LIVE_TABLE_COLUMN_CNT 2UL
    #define LIVE_TABLE_MAX_SORT_KEY_CNT 1024UL

    #define LIVE_TABLE_COLUMNS LIVE_TABLE_COL_ARRAY( \
        LIVE_TABLE_COL_ENTRY( col1, col1_cmp, col1_hash, 1), \  // is_primary=1
        LIVE_TABLE_COL_ENTRY( col2, col2_cmp, col2_hash, 0) \   // is_primary=0
    )
    #define LIVE_TABLE_ROW_T myrow_t
    #include "fd_gui_live_table_tmpl.c"

  will declare the following APIs as a header-only style library in the
  compilation unit:

     // mytable_{align,footprint} returns the alignment and footprint
     // needed for a memory region to hold the state of a mytable of
     // elements containing at most rows_max rows.  align will be an
     // integer power-of-two and footprint will be a multiple of align.
     // mytable_t is stack declaration, data segment declaration, heap
     // allocation and stack allocation friendly.
     //
     // mytable_new formats a memory region with the appropriate
     // alignment and footprint whose first byte in the caller's address
     // space is pointed to by shmem as a mytable.  Returns shmem on
     // success and NULL on failure.  Caller is not joined on return.
     // The mytable will be empty.
     //
     // mytable_join joins a mytable.  Assumes shtable points at a
     // memory region formatted as a mytable in the caller's address
     // space.  Returns a handle to the caller's local join on success
     // and NULL on failure (logs details).
     //
     // mytable_leave leaves a mytable.  Assumes join points to a
     // current local join.  Returns shtable used on join and NULL on
     // failure (logs details).
     //
     // mytable_delete unformats a memory region used as a mytable.
     // Assumes shtable points to a memory region in the caller's local
     // address space formatted as a mytable, that there are no joins to
     // the mytable and that any application side cleanups have been
     // done.  Returns shtable on success and NULL on failure (logs
     // details).

     ulong       mytable_align    ( void                                     );
     ulong       mytable_footprint( ulong rows_max                           );
     void      * mytable_new      ( void * shmem, ulong rows_max, ulong seed );
     mytable_t * mytable_join     ( void * shtable                           );
     void      * mytable_leave    ( mytable_t * join                         );
     void      * mytable_delete   ( void * shtable                           );

     // mytable_max_rows returns the maximum number of rows supported by the table
     ulong mytable_max_rows( mytable_t * join );

     // Operations

     // A "sort key" is a structure used to define multi-column sorting
     // behavior. It consists of:
     //    - An array of LIVE_TABLE_COLUMN_CNT column indices,
     //      specifying which columns are sorted.
     //    - An array of corresponding sort directions (null, asc, or
     //      desc), defining the sorting order.
     //
     // Rows are sorted by prioritizing earlier columns in the sort key,
     // with each column sorted according to its specified direction.
     // These directions are:
     //    - null ( 0): No sorting applied to the column.
     //    - asc  ( 1): Sort the column in ascending order.
     //    - desc (-1): Sort the column in descending order.

     void      mytable_remove_sort_key( mytable_t * join, mytable_sort_key_t const * sort_key ); // removes a sorted view from mytable
     void      mytable_remove         ( mytable_t * join, myrow_t * key                       ); // removes a row from mytable
     myrow_t * mytable_upsert         ( mytable_t * join, myrow_t const * row                 ); // updates (or inserts) a row in mytable

     // Iteration

     int                 mytable_fwd_iter_done     ( mytable_fwd_iter_t iter                                                        );
     ulong               mytable_fwd_iter_idx      ( mytable_fwd_iter_t iter                                                        );
     mytable_fwd_iter_t  mytable_fwd_iter_init     ( mytable_t * join, mytable_sort_key_t const * sort_key                          );
     mytable_fwd_iter_t  mytable_fwd_iter_next     ( mytable_t * join, mytable_sort_key_t const * sort_key, mytable_fwd_iter_t iter );
     myrow_t *           mytable_fwd_iter_row      ( mytable_t * join, mytable_sort_key_t const * sort_key, mytable_fwd_iter_t iter );
     myrow_t const *     mytable_fwd_iter_row_const( mytable_t * join, mytable_sort_key_t const * sort_key, mytable_fwd_iter_t iter );
*/

#ifndef LIVE_TABLE_NAME
#error "need to define LIVE_TABLE_NAME"
#endif

#ifndef LIVE_TABLE_COLUMN_CNT
#error "need to define LIVE_TABLE_COLUMN_CNT"
#endif

#ifndef LIVE_TABLE_MAX_SORT_KEY_CNT
#define LIVE_TABLE_MAX_SORT_KEY_CNT (1024UL)
#endif

#ifndef LIVE_TABLE_ROW_T
#error "need to define LIVE_TABLE_ROW_T"
#endif

#ifndef LIVE_TABLE_COLUMNS
#error "need to define LIVE_TABLE_COLUMNS"
#endif

#ifndef LIVE_TABLE_TREAP
#define LIVE_TABLE_TREAP live_table_treap
#endif

#define LIVE_TABLE_(n) FD_EXPAND_THEN_CONCAT3(LIVE_TABLE_NAME,_,n)

#define LIVE_TABLE_COL_ENTRY(col_id, field, lt_func) \
    { .col_name = col_id, .off = offsetof(LIVE_TABLE_ROW_T, field), .lt = lt_func }

#define LIVE_TABLE_COL_ARRAY(...) \
    static const struct  LIVE_TABLE_(private_column)  LIVE_TABLE_(private_columns)[] = { __VA_ARGS__ };

#define LIVE_TABLE_DEFAULT_TREAP_IDX (0UL)

#ifndef LIVE_TABLE_IMPL_STYLE
#define LIVE_TABLE_IMPL_STYLE 0
#endif

#if LIVE_TABLE_IMPL_STYLE==0
#define LIVE_TABLE_STATIC static FD_FN_UNUSED
#else
#define LIVE_TABLE_STATIC
#endif

#include "../../util/log/fd_log.h" /* failure logs */
#include "../../util/bits/fd_bits.h"

#if TREAP_IMPL_STYLE!=2 /* need structures, prototypes and inlines */
struct LIVE_TABLE_(private_column) {
  char * col_name; /* cstr */
  ulong off;
  int (* const lt)(void const * a, void const * b);
};

struct LIVE_TABLE_(sort_key) {
  ulong col[ LIVE_TABLE_COLUMN_CNT ];
  int dir[ LIVE_TABLE_COLUMN_CNT ];
};
typedef struct LIVE_TABLE_(sort_key) LIVE_TABLE_(sort_key_t);

#if TREAP_IMPL_STYLE!=1 /* need implementations */

/* global state is ugly. We only have one type of treap and they all
   share the same static comparison function, but we need that function
   to change dynamically.  The simplest way to do this is to have the
   function reference changing global state.  Not ideal but the
   alternative is to change the implementation of the treap template */
static LIVE_TABLE_(sort_key_t) LIVE_TABLE_(private_sort_keys)[ LIVE_TABLE_MAX_SORT_KEY_CNT ] = { 0UL };
static ulong LIVE_TABLE_(private_active_sort_key_idx) = ULONG_MAX;

/* global constant array of column metadata */
LIVE_TABLE_COLUMNS

FD_STATIC_ASSERT( LIVE_TABLE_COLUMN_CNT==sizeof(LIVE_TABLE_(private_columns))/sizeof(LIVE_TABLE_(private_columns)[0]), "column count mismatch" );

#endif /* TREAP_IMPL_STYLE!=1 */

static int
LIVE_TABLE_(private_row_lt)(LIVE_TABLE_ROW_T const * a, LIVE_TABLE_ROW_T const * b) {
  FD_TEST( LIVE_TABLE_(private_active_sort_key_idx) < LIVE_TABLE_MAX_SORT_KEY_CNT );

  LIVE_TABLE_(sort_key_t) const * active_sort_key = &LIVE_TABLE_(private_sort_keys)[ LIVE_TABLE_(private_active_sort_key_idx) ];

  ulong a_idx_idx = 0UL; /* idx into array of indices */
  ulong b_idx_idx = 0UL;
  while( a_idx_idx<LIVE_TABLE_COLUMN_CNT && b_idx_idx<LIVE_TABLE_COLUMN_CNT ) {
    /* advance pointers until neither column sort diraction is 0 (null) */
    if( FD_UNLIKELY( a_idx_idx<LIVE_TABLE_COLUMN_CNT && active_sort_key->dir[ a_idx_idx ]==0 ) ) {
      a_idx_idx++;
      continue;
    }
    if( FD_UNLIKELY( b_idx_idx<LIVE_TABLE_COLUMN_CNT && active_sort_key->dir[ b_idx_idx ]==0 ) ) {
      b_idx_idx++;
      continue;
    }
    void * col_a = ((uchar *)a) + LIVE_TABLE_(private_columns)[ active_sort_key->col[ a_idx_idx ] ].off;
    void * col_b = ((uchar *)b) + LIVE_TABLE_(private_columns)[ active_sort_key->col[ b_idx_idx ] ].off;
    int a_lt_b = LIVE_TABLE_(private_columns)[ active_sort_key->col[ a_idx_idx ] ].lt(col_a, col_b);
    int b_lt_a = LIVE_TABLE_(private_columns)[ active_sort_key->col[ b_idx_idx ] ].lt(col_b, col_a);
    
    if( FD_UNLIKELY( !(a_lt_b || b_lt_a) ) ) {
      if( FD_LIKELY( a_idx_idx<LIVE_TABLE_COLUMN_CNT ) ) a_idx_idx++;
      if( FD_LIKELY( b_idx_idx<LIVE_TABLE_COLUMN_CNT ) ) b_idx_idx++;
      continue; /* equal */
    }

    return fd_int_if( active_sort_key->dir[ a_idx_idx ]==1, a_lt_b, !a_lt_b );
  }

  return 0; /* all columns equal */
}

#define TREAP_NAME      LIVE_TABLE_(private_treap)
#define TREAP_T         LIVE_TABLE_ROW_T
#define TREAP_QUERY_T   void *                                         /* query isn't used */
#define TREAP_CMP(q,e)  (__extension__({ (void)(q); (void)(e); -1; })) /* which means we don't need to give a real
                                                                          implementation to cmp either */
#define TREAP_LT(e0,e1) (LIVE_TABLE_(private_row_lt)( (e0), (e1) ))
#define TREAP_OPTIMIZE_ITERATION 1
#define TREAP_PARENT LIVE_TABLE_TREAP.parent[ LIVE_TABLE_(private_active_sort_key_idx) ]
#define TREAP_LEFT   LIVE_TABLE_TREAP.left  [ LIVE_TABLE_(private_active_sort_key_idx) ]
#define TREAP_RIGHT  LIVE_TABLE_TREAP.right [ LIVE_TABLE_(private_active_sort_key_idx) ]
#define TREAP_NEXT   LIVE_TABLE_TREAP.next  [ LIVE_TABLE_(private_active_sort_key_idx) ]
#define TREAP_PREV   LIVE_TABLE_TREAP.prev  [ LIVE_TABLE_(private_active_sort_key_idx) ]
#define TREAP_PRIO   LIVE_TABLE_TREAP.prio  [ LIVE_TABLE_(private_active_sort_key_idx) ]
#define TREAP_IMPL_STYLE LIVE_TABLE_IMPL_STYLE
#include "../../util/tmpl/fd_treap.c"

struct LIVE_TABLE_() {
  LIVE_TABLE_(private_treap_t) * treaps[ LIVE_TABLE_MAX_SORT_KEY_CNT ];
  void * treaps_shmem[ LIVE_TABLE_MAX_SORT_KEY_CNT ]; /* keep pointers to the allocated memory region since treaps are dynamically created / destroyed */
  ulong activity_timers[ LIVE_TABLE_MAX_SORT_KEY_CNT ]; /* ULONG_MAX if treap is inactive, nanos UNIX timestamp of last iter.  First entry is special gets initalized to a default sort key and is not removable */
  ulong max_rows;
};
typedef struct LIVE_TABLE_() LIVE_TABLE_(t);

typedef LIVE_TABLE_(private_treap_fwd_iter_t) LIVE_TABLE_(fwd_iter_t);

FD_PROTOTYPES_BEGIN

LIVE_TABLE_STATIC void LIVE_TABLE_(seed)( LIVE_TABLE_ROW_T * pool, ulong rows_max, ulong seed );

LIVE_TABLE_STATIC FD_FN_CONST ulong LIVE_TABLE_(align)    ( void                         );
LIVE_TABLE_STATIC FD_FN_CONST ulong LIVE_TABLE_(footprint)( ulong rows_max               );
LIVE_TABLE_STATIC void      *       LIVE_TABLE_(new)      ( void * shmem, ulong rows_max );
LIVE_TABLE_STATIC LIVE_TABLE_(t) *  LIVE_TABLE_(join)     ( void * shtable               );
LIVE_TABLE_STATIC void      *       LIVE_TABLE_(leave)    ( LIVE_TABLE_(t) * join        );
LIVE_TABLE_STATIC void      *       LIVE_TABLE_(delete)   ( void * shtable               );

LIVE_TABLE_STATIC LIVE_TABLE_ROW_T * LIVE_TABLE_(idx_insert)( LIVE_TABLE_(t) * join, ulong pool_idx, LIVE_TABLE_ROW_T * pool );
LIVE_TABLE_STATIC void               LIVE_TABLE_(idx_remove)( LIVE_TABLE_(t) * join, ulong pool_idx, LIVE_TABLE_ROW_T * pool );

LIVE_TABLE_STATIC FD_FN_PURE LIVE_TABLE_(fwd_iter_t)LIVE_TABLE_(fwd_iter_next)( LIVE_TABLE_(fwd_iter_t) iter, LIVE_TABLE_ROW_T const * pool );
LIVE_TABLE_STATIC FD_FN_PURE LIVE_TABLE_(fwd_iter_t)LIVE_TABLE_(fwd_iter_init)( LIVE_TABLE_(t) * join, LIVE_TABLE_(sort_key_t) const * sort_key, LIVE_TABLE_ROW_T * pool );

FD_FN_CONST static inline LIVE_TABLE_(fwd_iter_t)
LIVE_TABLE_(fwd_iter_next)( LIVE_TABLE_(fwd_iter_t) iter, LIVE_TABLE_ROW_T const * pool ) {
  return LIVE_TABLE_(private_treap_fwd_iter_next)( iter, pool );
}

FD_FN_CONST static inline LIVE_TABLE_ROW_T *
LIVE_TABLE_(fwd_iter_ele)( LIVE_TABLE_(fwd_iter_t) iter, LIVE_TABLE_ROW_T * pool ) {
  return LIVE_TABLE_(private_treap_fwd_iter_ele)( iter, pool );
}

FD_FN_CONST static inline LIVE_TABLE_ROW_T const *
LIVE_TABLE_(fwd_iter_ele_const)( LIVE_TABLE_(fwd_iter_t) iter, LIVE_TABLE_ROW_T const * pool ) {
  return LIVE_TABLE_(private_treap_fwd_iter_ele_const)( iter, pool );
}

FD_FN_CONST static inline int
LIVE_TABLE_(fwd_iter_done)( LIVE_TABLE_(fwd_iter_t) iter ) {
  return LIVE_TABLE_(private_treap_fwd_iter_done)( iter );
}

FD_FN_CONST static inline ulong
LIVE_TABLE_(fwd_iter_idx)( LIVE_TABLE_(fwd_iter_t) iter ) {
  return LIVE_TABLE_(private_treap_fwd_iter_idx)( iter );
}

static inline LIVE_TABLE_ROW_T *
LIVE_TABLE_(ele_insert)( LIVE_TABLE_(t) * join, LIVE_TABLE_ROW_T * row, LIVE_TABLE_ROW_T * pool ) {
  return LIVE_TABLE_(idx_insert)( join, (ulong)(row - pool), pool );
}

static inline void
LIVE_TABLE_(ele_remove)( LIVE_TABLE_(t) * join, LIVE_TABLE_ROW_T * row, LIVE_TABLE_ROW_T * pool ) {
  LIVE_TABLE_(idx_remove)( join, (ulong)(row - pool), pool );
}

FD_FN_CONST static inline ulong
LIVE_TABLE_(max_rows)( LIVE_TABLE_(t) * join ) {
  return join->max_rows;
}

FD_FN_PURE static inline ulong
LIVE_TABLE_(active_sort_key_cnt)( LIVE_TABLE_(t) * join ) {
  ulong count = 0UL;
  for( ulong i = 0; i<LIVE_TABLE_MAX_SORT_KEY_CNT; i++ ) {
    FD_TEST( join->activity_timers[ LIVE_TABLE_DEFAULT_TREAP_IDX ]!=ULONG_MAX );
    if( FD_LIKELY( join->activity_timers[ i ]!=ULONG_MAX ) ) count++;
  }
  return count;
}

FD_FN_CONST static inline ulong
LIVE_TABLE_(col_name_to_idx)( LIVE_TABLE_(t) * join, char const * col_name ) {
  (void)join;
  for( ulong i = 0; i < LIVE_TABLE_COLUMN_CNT; i++ ) {
    if( FD_UNLIKELY( strcmp( LIVE_TABLE_( private_columns)[ i ].col_name, col_name ) ) ) continue;
    return i;
  }
  return ULONG_MAX;
}

FD_FN_CONST static inline char const *
LIVE_TABLE_(col_idx_to_name)( LIVE_TABLE_(t) * join, ulong col_idx ) {
  (void)join;
  if( FD_UNLIKELY( col_idx>=LIVE_TABLE_COLUMN_CNT ) ) return NULL;
  return LIVE_TABLE_( private_columns)[ col_idx ].col_name;
}

FD_FN_CONST static inline LIVE_TABLE_(sort_key_t) const *
LIVE_TABLE_(default_sort_key)( LIVE_TABLE_(t) * join ) {
  (void)join;
  return &LIVE_TABLE_(private_sort_keys)[ LIVE_TABLE_DEFAULT_TREAP_IDX ];
}

FD_PROTOTYPES_END

#endif /* TREAP_IMPL_STYLE!=2 */

#if TREAP_IMPL_STYLE!=1 /* need implementations */

static inline void
LIVE_TABLE_(private_sort_key_delete)( LIVE_TABLE_(t) * join, ulong sort_key_idx ) {
  FD_TEST( sort_key_idx!=LIVE_TABLE_DEFAULT_TREAP_IDX );
  FD_TEST( sort_key_idx<LIVE_TABLE_MAX_SORT_KEY_CNT );
  LIVE_TABLE_(private_active_sort_key_idx) = sort_key_idx;
  LIVE_TABLE_(private_treap_leave)( join->treaps[ sort_key_idx ] );
  LIVE_TABLE_(private_treap_delete)( join->treaps_shmem[ sort_key_idx ] );
  join->treaps[ sort_key_idx ] = NULL;
  join->activity_timers[ sort_key_idx ] = ULONG_MAX;
}

static inline void
LIVE_TABLE_(private_sort_key_create)( LIVE_TABLE_(t) * join, ulong sort_key_idx, LIVE_TABLE_(sort_key_t) const * sort_key, LIVE_TABLE_ROW_T * pool ) {
  FD_TEST( sort_key_idx<LIVE_TABLE_MAX_SORT_KEY_CNT );
  LIVE_TABLE_(private_active_sort_key_idx) = sort_key_idx;
  fd_memcpy( &LIVE_TABLE_(private_sort_keys)[ sort_key_idx ], sort_key, sizeof(LIVE_TABLE_(sort_key_t)) );

  join->treaps[ sort_key_idx ] = LIVE_TABLE_(private_treap_join)( LIVE_TABLE_(private_treap_new)( join->treaps_shmem[ sort_key_idx ], join->max_rows ) );
  join->activity_timers[ sort_key_idx ] = (ulong)fd_tickcount();
  FD_TEST( join->treaps[ sort_key_idx ] );

  /* loop through treaps[ LIVE_TABLE_DEFAULT_TREAP_IDX ], insert
     all entries into the new treap */
  LIVE_TABLE_(private_active_sort_key_idx) = LIVE_TABLE_DEFAULT_TREAP_IDX;
  LIVE_TABLE_(private_treap_fwd_iter_t) iter = LIVE_TABLE_(private_treap_fwd_iter_init)( join->treaps[ LIVE_TABLE_DEFAULT_TREAP_IDX ], pool );
  while( 1 ) {
    ulong pool_idx = LIVE_TABLE_(private_treap_fwd_iter_idx)( iter );

    LIVE_TABLE_(private_active_sort_key_idx) = sort_key_idx;
    LIVE_TABLE_(private_treap_idx_insert)( join->treaps[ sort_key_idx ], pool_idx, pool );
    // FD_LOG_NOTICE(( "INSERT pool_idx=%lu sort_key=%lu", pool_idx, (ulong)sort_key ));
    
    LIVE_TABLE_(private_active_sort_key_idx) = LIVE_TABLE_DEFAULT_TREAP_IDX;
    iter = LIVE_TABLE_(private_treap_fwd_iter_next)( iter, pool );
    if( FD_UNLIKELY( LIVE_TABLE_(private_treap_fwd_iter_done)( iter ) ) ) break;
  }
}

static inline ulong
LIVE_TABLE_(private_query_sort_key)( LIVE_TABLE_(t) * join, LIVE_TABLE_(sort_key_t) const * sort_key ) {
  for( ulong i = 0; i<LIVE_TABLE_MAX_SORT_KEY_CNT; i++ ) {
    if( FD_UNLIKELY( join->activity_timers[ i ]==ULONG_MAX ) ) continue;
    int equal = 1;
    ulong j = 0;
    ulong k = 0;
    while( j<LIVE_TABLE_COLUMN_CNT && k<LIVE_TABLE_COLUMN_CNT ) {
      /* columns with dir=0 don't actually count, they're ignored */
      if( FD_UNLIKELY( j<LIVE_TABLE_COLUMN_CNT && LIVE_TABLE_(private_sort_keys)[ i ].dir[ j ]==0 ) ) {
        j++;
        continue;
      }
      if( FD_UNLIKELY( k<LIVE_TABLE_COLUMN_CNT && sort_key->dir[ k ]==0 ) ) {
        k++;
        continue;
      }
      if( FD_LIKELY( LIVE_TABLE_(private_sort_keys)[ i ].col[ j ] != sort_key->col[ k ] || LIVE_TABLE_(private_sort_keys)[ i ].dir[ j ] != sort_key->dir[ k ] ) ) {
        equal = 0;
        break;
      }
      if( FD_LIKELY( j<LIVE_TABLE_COLUMN_CNT ) ) j++;
      if( FD_LIKELY( k<LIVE_TABLE_COLUMN_CNT ) ) k++;
    }
    if( FD_LIKELY( !equal ) ) continue;
    join->activity_timers[ i ] = (ulong)fd_tickcount(); /* todo ... use new clock api */
    // FD_LOG_NOTICE(("sort_key=%lu i=%lu", (ulong)sort_key, i ));
    return i;
  }

  // FD_LOG_NOTICE(("sort_key=%lu NOT FOUND", (ulong)sort_key ));
  return ULONG_MAX;
}

static inline ulong
LIVE_TABLE_(private_query_or_add_sort_key)( LIVE_TABLE_(t) * join, LIVE_TABLE_(sort_key_t) const * sort_key, LIVE_TABLE_ROW_T * pool ) {
  /* todo ... add garbage collection */
  ulong sort_key_idx = LIVE_TABLE_(private_query_sort_key)( join, sort_key );
  if( FD_LIKELY( sort_key_idx!=ULONG_MAX ) ) return sort_key_idx;

  /* look for an inactive sort key */
  for( ulong i=0UL; i<LIVE_TABLE_MAX_SORT_KEY_CNT; i++ ) {
    if( FD_UNLIKELY( i==LIVE_TABLE_DEFAULT_TREAP_IDX ) ) continue;
    if( FD_LIKELY( join->activity_timers[ i ]==ULONG_MAX ) ) {
      LIVE_TABLE_(private_sort_key_create)( join, i, sort_key, pool );
      // FD_LOG_NOTICE(("ADD sort_key=%lu i=%lu", (ulong)sort_key, i ));
      return i;
    }
  }

  /* evict the oldest sort key */
  ulong oldest_timer_val = join->activity_timers[ 0UL ];
  ulong oldest_timer_idx = 0UL;
  for( ulong i=0UL; i<LIVE_TABLE_MAX_SORT_KEY_CNT; i++ ) {
    if( FD_UNLIKELY( i==LIVE_TABLE_DEFAULT_TREAP_IDX ) ) continue;
    if( FD_UNLIKELY( oldest_timer_val < join->activity_timers[ i ] ) ) {
      oldest_timer_val = join->activity_timers[ i ];
      oldest_timer_idx = i;
    }
  }

  if( FD_UNLIKELY( oldest_timer_idx==ULONG_MAX ) ) FD_LOG_ERR(("should not happend"));

  LIVE_TABLE_(private_active_sort_key_idx) = oldest_timer_idx;
  LIVE_TABLE_(private_sort_key_delete)( join, oldest_timer_idx );
  LIVE_TABLE_(private_sort_key_create)( join, oldest_timer_idx, sort_key, pool );

  return oldest_timer_idx;
}

LIVE_TABLE_STATIC ulong
LIVE_TABLE_(align)(void) {
  ulong a = alignof(LIVE_TABLE_(t));
  ulong b = LIVE_TABLE_(private_treap_align)();
  ulong c = 128UL;
  return fd_ulong_max( a, fd_ulong_max( b, c ) );
}

LIVE_TABLE_STATIC ulong
LIVE_TABLE_(footprint)( ulong max_rows ) {
  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, alignof(LIVE_TABLE_(t)), sizeof(LIVE_TABLE_(t)) );
  for( ulong i = 0; i<LIVE_TABLE_MAX_SORT_KEY_CNT; i++ ) l = FD_LAYOUT_APPEND( l, LIVE_TABLE_(private_treap_align)(), LIVE_TABLE_(private_treap_footprint)( max_rows ) );
  return FD_LAYOUT_FINI( l, LIVE_TABLE_(align)() );
}

LIVE_TABLE_STATIC void *
LIVE_TABLE_(new)( void * shmem, ulong max_rows ) {
  if( !shmem ) {
    FD_LOG_WARNING(( "NULL shmem" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shmem, LIVE_TABLE_(align)() ) ) ) {
    FD_LOG_WARNING(( "misaligned shmem" ));
    return NULL;
  }

  FD_SCRATCH_ALLOC_INIT( l, shmem );
  LIVE_TABLE_(t) * _table = FD_SCRATCH_ALLOC_APPEND( l, alignof(LIVE_TABLE_(t)), sizeof(LIVE_TABLE_(t)) );
  for( ulong i = 0; i<LIVE_TABLE_MAX_SORT_KEY_CNT; i++ ) _table->treaps_shmem[ i ] = FD_SCRATCH_ALLOC_APPEND( l, LIVE_TABLE_(private_treap_align)(), LIVE_TABLE_(private_treap_footprint)( max_rows ) );
  FD_SCRATCH_ALLOC_FINI( l, LIVE_TABLE_(align)() );
  
  for( ulong i = 0; i<LIVE_TABLE_MAX_SORT_KEY_CNT; i++ ) _table->activity_timers[ i ] = ULONG_MAX;

  /* Note that treaps[ LIVE_TABLE_DEFAULT_TREAP_IDX ] is special,
     it will never be garbage collected or evicted and is treated as
     always active, even if its activity timer is ULONG_MAX. Its sort
     key is the columns in the order in which they are defined in the
     template all set to dir=-1 (descending) */
  LIVE_TABLE_(private_active_sort_key_idx) = LIVE_TABLE_DEFAULT_TREAP_IDX;
  _table->treaps[ LIVE_TABLE_DEFAULT_TREAP_IDX ] = LIVE_TABLE_(private_treap_join)( LIVE_TABLE_(private_treap_new)( _table->treaps_shmem[ LIVE_TABLE_DEFAULT_TREAP_IDX ], max_rows ) );
  _table->activity_timers[ LIVE_TABLE_DEFAULT_TREAP_IDX ] = (ulong)fd_tickcount();

  for( ulong i = 0; i < LIVE_TABLE_COLUMN_CNT; i++ ) {
    LIVE_TABLE_(private_sort_keys)[ LIVE_TABLE_DEFAULT_TREAP_IDX ].col[ i ] = i;
    LIVE_TABLE_(private_sort_keys)[ LIVE_TABLE_DEFAULT_TREAP_IDX ].dir[ i ] = -1;
  }

  _table->max_rows = max_rows;

  /* live_table_treap_new( ... ) not called since all treaps start as inactive */

  return _table;
}

LIVE_TABLE_STATIC void
LIVE_TABLE_(seed)( LIVE_TABLE_ROW_T * pool, ulong rows_max, ulong seed ) {
  for( ulong i = 0; i<LIVE_TABLE_MAX_SORT_KEY_CNT; i++ ) {
    LIVE_TABLE_(private_active_sort_key_idx) = i;
    LIVE_TABLE_(private_treap_seed)( pool, rows_max, seed ); /* set random priorities */
  }
}

LIVE_TABLE_STATIC LIVE_TABLE_(t) *
LIVE_TABLE_(join)( void * shtable ) {
  if( !shtable ) {
    FD_LOG_WARNING(( "NULL shtable" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shtable, LIVE_TABLE_(align)() ) ) ) {
    FD_LOG_WARNING(( "misaligned shtable" ));
    return NULL;
  }

  return (LIVE_TABLE_(t) *)shtable;
}

LIVE_TABLE_STATIC void *
LIVE_TABLE_(leave)( LIVE_TABLE_(t) * join ) {
  if( FD_UNLIKELY( !join ) ) {
    FD_LOG_WARNING(( "NULL join" ));
    return NULL;
  }

  for( ulong i = 0; i<LIVE_TABLE_MAX_SORT_KEY_CNT; i++ ) {
    if( FD_LIKELY( join->activity_timers[ i ] == ULONG_MAX ) ) continue;
    LIVE_TABLE_(private_active_sort_key_idx) = i;
    FD_TEST( LIVE_TABLE_(private_treap_leave)( join->treaps[ i ] )==join->treaps_shmem[ i ] );
  }

  return (void *)join;
}

LIVE_TABLE_STATIC void *
LIVE_TABLE_(delete)( void * shtable ) {
  LIVE_TABLE_(t) * table = (LIVE_TABLE_(t) *)shtable;

  if( FD_UNLIKELY( !table ) ) {
    FD_LOG_WARNING(( "NULL shtable" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)table, alignof(LIVE_TABLE_(t)) ) ) ) {
    FD_LOG_WARNING(( "misaligned shtable" ));
    return NULL;
  }

  for( ulong i = 0; i<LIVE_TABLE_MAX_SORT_KEY_CNT; i++ ) {
    if( FD_LIKELY( table->activity_timers[ i ] == ULONG_MAX ) ) continue;
    LIVE_TABLE_(private_active_sort_key_idx) = i;
    LIVE_TABLE_(private_treap_delete)( table->treaps_shmem[ i ] );
  }

  return (void *)table;
}

LIVE_TABLE_STATIC void
LIVE_TABLE_(idx_remove)( LIVE_TABLE_(t) * join, ulong pool_idx, LIVE_TABLE_ROW_T * pool ) {
  for( ulong i = 0; i<LIVE_TABLE_MAX_SORT_KEY_CNT; i++ ) {
    if( FD_LIKELY( join->activity_timers[ i ] == ULONG_MAX ) ) continue;
    LIVE_TABLE_(private_active_sort_key_idx) = i;
    LIVE_TABLE_(private_treap_idx_remove)( join->treaps[ i ], pool_idx, pool );
  }
}

LIVE_TABLE_STATIC LIVE_TABLE_ROW_T *
LIVE_TABLE_(idx_insert)( LIVE_TABLE_(t) * join, ulong pool_idx, LIVE_TABLE_ROW_T * pool ) {
  /* insert into all active treaps */
  for( ulong i = 0; i<LIVE_TABLE_MAX_SORT_KEY_CNT; i++ ) {
    if( FD_LIKELY( join->activity_timers[ i ] == ULONG_MAX ) ) continue;
    LIVE_TABLE_(private_active_sort_key_idx) = i;
    LIVE_TABLE_(private_treap_idx_insert)(join->treaps[i], pool_idx, pool);
    join->activity_timers[ i ] = (ulong)fd_tickcount();
  }

  return pool + pool_idx;
}

LIVE_TABLE_STATIC FD_FN_PURE LIVE_TABLE_(fwd_iter_t)
LIVE_TABLE_(fwd_iter_init)( LIVE_TABLE_(t) * join, LIVE_TABLE_(sort_key_t) const * sort_key, LIVE_TABLE_ROW_T * pool ) {
  ulong sort_key_idx = LIVE_TABLE_(private_query_or_add_sort_key)( join, sort_key, pool );
  // FD_LOG_INFO(("live_table_fwd_iter_init sort_key_idx=%lu", sort_key_idx));
  LIVE_TABLE_(private_active_sort_key_idx) = sort_key_idx;
  return LIVE_TABLE_(private_treap_fwd_iter_init)( join->treaps[ sort_key_idx ], pool );
}

#endif /* TREAP_IMPL_STYLE!=1 */

#undef LIVE_TABLE_STATIC
#undef LIVE_TABLE_IMPL_STYLE
#undef LIVE_TABLE_NAME
#undef LIVE_TABLE_COLUMN_CNT
#undef LIVE_TABLE_MAX_SORT_KEY_CNT
#undef LIVE_TABLE_ROW_T
#undef LIVE_TABLE_COLUMNS
#undef LIVE_TABLE_COL_ENTRY
#undef LIVE_TABLE_COL_ARRAY
#undef LIVE_TABLE_TREAP
#undef LIVE_TABLE_COL_ENTRY
#undef LIVE_TABLE_COL_ARRAY
#undef LIVE_TABLE_DEFAULT_TREAP_IDX
#undef LIVE_TABLE_
