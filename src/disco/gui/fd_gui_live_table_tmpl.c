/*
Generate prototypes, inlines and implementations for tabular viewports
with a bounded compile-time number of columns and a bounded run-time
fixed row capacity.

A tabular viewport stores a collections of views into some underlying
table.  Each view has an associated sort key which determines the order
of the rows in the view.

This API is an extension of the fd_treap API. As such methods included
in fd_treap.c also included in the template will have the same
specification, unless noted otherwise.

This API is designed for ultra tight coupling with pools, treaps,
heaps, maps, other tables, etc.  Likewise, a live table can be persisted
beyond the lifetime of the creating process, used concurrently in
many common operations, used inter-process, relocated in memory,
naively serialized/deserialized, moved between hosts, supports index
compression for cache and memory bandwidth efficiency, etc.

Typical usage:

    struct myrow {
      ulong col1;
      uint col2;

      struct {
        ulong parent  [ MY_TABLE_MAX_SORT_KEY_CNT ];
        ulong left    [ MY_TABLE_MAX_SORT_KEY_CNT ];
        ulong right   [ MY_TABLE_MAX_SORT_KEY_CNT ];
        ulong prio    [ MY_TABLE_MAX_SORT_KEY_CNT ];
        ulong next    [ MY_TABLE_MAX_SORT_KEY_CNT ];
        ulong prev    [ MY_TABLE_MAX_SORT_KEY_CNT ];

        ... these fields back one of up to MY_TABLE_MAX_SORT_KEY_CNT
        ... active treaps.  See fd_treap.c for restrictions, lifetimes, etc.

      } treaps; // technically LIVE_TABLE_TREAP
      ulong sort_keys; // technically LIVE_TABLE_SORT_KEYS
    };
    typedef struct myrow myrow_t;

    static int col1_lt( void const * a, void const * b ) { return *(ulong *)a < *(ulong *)b; }
    static int col2_lt( void const * a, void const * b ) { return *(uint  *)a < *(uint  *)b; }

    ... by setting LIVE_TABLE_GC_INTERVAL_NANOS to a non-zero value,
    ... mytable will garbage collect any treaps that haven't been
    ... iterated over in LIVE_TABLE_GC_INTERVAL_NANOS nanoseconds

    #define LIVE_TABLE_GC_INTERVAL_NANOS (60000000000)
    #define LIVE_TABLE_NAME my_table
    #define LIVE_TABLE_COLUMN_CNT (MY_TABLE_MAX_COLUMN_CNT)
    #define LIVE_TABLE_MAX_SORT_KEY_CNT (MY_TABLE_MAX_SORT_KEY_CNT)
    #define LIVE_TABLE_COLUMNS LIVE_TABLE_COL_ARRAY( \
      LIVE_TABLE_COL_ENTRY("Column One", col1, col1_lt), \
      LIVE_TABLE_COL_ENTRY("Column Two", col2, col2_lt)  )
    #define LIVE_TABLE_ROW_T myrow_t
    #include "fd_gui_live_table_tmpl.c"

    ... LIVE_TABLE_COL_ENTRY accepts 3 arguments.  The name of the table
    ... column as a const cstr, the member of myrow_t which corresponds
    ... to the column being added, and a pure function that accepts two
    ... columns (as void* to members of myrow_t) and returns true if the
    ... first compares less than the second.

  will declare the following APIs as a header-only style library in the
  compilation unit:

     // These methods have the same behavior as their counterparts in
     // fd_treap.c. The main difference is that there are up to
     // LIVE_TABLE_MAX_SORT_KEY_CNT treaps actively maintained by
     // mytable, and callers should not make any assumptions about a
     // given treap being used or unused.

     ulong       mytable_align    ( void                                     );
     ulong       mytable_footprint( ulong rows_max                           );
     void      * mytable_new      ( void * shmem, ulong rows_max, ulong seed );
     mytable_t * mytable_join     ( void * shtable                           );
     void      * mytable_leave    ( mytable_t * join                         );
     void      * mytable_delete   ( void * shtable                           );

     ulong           mytable_idx_null      ( void );
     myrow_t *       mytable_ele_null      ( void );
     myrow_t const * mytable_ele_null_const( void );

     int mytable_idx_is_null( ulong           i );
     int mytable_ele_is_null( myrow_t const * e );

     ulong mytable_idx     ( myrow_t const * e, myrow_t const * pool );
     ulong mytable_idx_fast( myrow_t const * e, myrow_t const * pool );

     myrow_t * mytable_ele     ( ulong i, myrow_t * pool );
     myrow_t * mytable_ele_fast( ulong i, myrow_t * pool );

     myrow_t const * mytable_ele_const     ( ulong i, myrow_t const * pool );
     myrow_t const * mytable_ele_fast_const( ulong i, myrow_t const * pool );

     ulong mytable_ele_max( mytable_t const * table );
     ulong mytable_ele_cnt( mytable_t const * table );

     mytable_t * mytable_idx_insert( mytable_t * table, ulong     n, myrow_t * pool );
     mytable_t * mytable_idx_remove( mytable_t * table, ulong     d, myrow_t * pool );

     mytable_t * mytable_ele_insert( mytable_t * table, myrow_t * n, myrow_t * pool );
     mytable_t * mytable_ele_remove( mytable_t * table, myrow_t * d, myrow_t * pool );

     void mytable_seed( myrow_t * pool, ulong ele_max, ulong seed );

     int mytable_verify( mytable_t const * table, myrow_t const * pool );

     // A sort key is a structure used to define multi-column sorting
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
     //
     // e.g.
     //
     // mytable_sort_key_t my_sort_key = { .col = { 0, 1, 2 }, .dir =  { 0, 1, 0 } };
     //
     // The position of a column in col determined the precedence of the
     // column. Earlier columns are considered first when sorting, which
     // increases the visual impact of their sort.
     //
     // Also note that two sort keys may have different column orderings
     // but still be isomorphic (i.e. always result in the same sort).
     // For example, the following sort key is isomorphic with the key
     // above.
     //
     // mytable_sort_key_t my_sort_key = { .col = { 1, 0, 2 }, .dir =  { 1, 0, 0 } };
     //
     // mytable_lt compares two myrow_t according to the specified sort key.

     int mytable_lt( mytable_sort_key_t const * sort_key, myrow_t const * e0, myrow_t const * e1 );

     // mytable_default_sort_key returns a sort key where where columns
     // are ordered in the same order they appear in
     // LIVE_TABLE_COL_ARRAY and their sort direction is "descending".

     mytable_sort_key_t const * mytable_default_sort_key( mytable_t * join  );

     // mytable_fwd_iter_{init,done,next,idx,ele,ele_const} provide an
     // in-order iterator from smallest to largest value.  Typical
     // usage:
     //
     //  for( mytable_fwd_iter_t iter = mytable_fwd_iter_init( table, pool );
     //       !mytable_fwd_iter_done( iter );
     //       iter = mytable_fwd_iter_next( iter, pool ) ) {
     //     ulong i = mytable_fwd_iter_idx( iter );
     //     ... or myrow_t *       e = mytable_fwd_iter_ele      ( iter, pool );
     //     ... or myrow_t const * e = mytable_fwd_iter_ele_const( iter, pool );
     //
     //     ... process i (or e) here
     //
     //     ... Do not remove the element the iterator is currently
     //     ... pointing to, and do not change the element's parent,
     //     ... left, right, or prio here.  It is fine to run other
     //     ... iterations concurrently.  Other fields are free to
     //     ... modify (from the table's POV, the application manages
     //     ... concurrency for other fields).
     //  }
     //
     // pool is a pointer in the caller's address space to the ele_max
     // linearly addressable storage region backing the table.

     int                 mytable_fwd_iter_done     ( mytable_fwd_iter_t iter                                                        );
     ulong               mytable_fwd_iter_idx      ( mytable_fwd_iter_t iter                                                        );
     mytable_fwd_iter_t  mytable_fwd_iter_init     ( mytable_t * join, mytable_sort_key_t const * sort_key                          );
     mytable_fwd_iter_t  mytable_fwd_iter_next     ( mytable_t * join, mytable_sort_key_t const * sort_key, mytable_fwd_iter_t iter );
     myrow_t *           mytable_fwd_iter_ele      ( mytable_t * join, mytable_sort_key_t const * sort_key, mytable_fwd_iter_t iter );
     myrow_t const *     mytable_fwd_iter_ele_const( mytable_t * join, mytable_sort_key_t const * sort_key, mytable_fwd_iter_t iter );
*/

#ifndef LIVE_TABLE_NAME
#error "need to define LIVE_TABLE_NAME"
#endif

#ifndef LIVE_TABLE_COLUMN_CNT
#error "need to define LIVE_TABLE_COLUMN_CNT"
#endif
FD_STATIC_ASSERT( LIVE_TABLE_COLUMN_CNT >= 1UL, "Expected 1+ live table columns" );

#ifndef LIVE_TABLE_MAX_SORT_KEY_CNT
#define LIVE_TABLE_MAX_SORT_KEY_CNT (1024UL)
#endif
FD_STATIC_ASSERT( LIVE_TABLE_MAX_SORT_KEY_CNT >= 2UL, "Requires at least 2 sort keys" );

#ifndef LIVE_TABLE_ROW_T
#error "need to define LIVE_TABLE_ROW_T"
#endif

#ifndef LIVE_TABLE_COLUMNS
#error "need to define LIVE_TABLE_COLUMNS"
#endif

#ifndef LIVE_TABLE_SORT_KEYS
#define LIVE_TABLE_SORT_KEYS sort_keys
#endif
#ifndef LIVE_TABLE_TREAP
#define LIVE_TABLE_TREAP treaps
#endif

#ifndef LIVE_TABLE_GC_INTERVAL_NANOS
#define LIVE_TABLE_GC_INTERVAL_NANOS 0
#endif

#define LIVE_TABLE_(n) FD_EXPAND_THEN_CONCAT3(LIVE_TABLE_NAME,_,n)

#define LIVE_TABLE_COL_ENTRY(col_id, field, lt_func) \
    (LIVE_TABLE_(private_column_t)){ .col_name = col_id, .off = __builtin_offsetof(LIVE_TABLE_ROW_T, field), .lt = lt_func }

#define LIVE_TABLE_COL_ARRAY(...) (LIVE_TABLE_(private_column_t)[]){ __VA_ARGS__ }

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
#include "../../util/math/fd_stat.h"

#if LIVE_TABLE_IMPL_STYLE!=2 /* need structures, prototypes and inlines */
struct LIVE_TABLE_(private_column) {
  char * col_name; /* cstr */
  ulong off;
  int (* const lt)(void const * a, void const * b);
};
typedef struct LIVE_TABLE_(private_column) LIVE_TABLE_(private_column_t);

struct LIVE_TABLE_(sort_key) {
  ulong col[ LIVE_TABLE_COLUMN_CNT ];
  int dir[ LIVE_TABLE_COLUMN_CNT ];
};
typedef struct LIVE_TABLE_(sort_key) LIVE_TABLE_(sort_key_t);

/* global state is ugly. We only have one type of treap and they all
   share the same static comparison function, but we need that function
   to change dynamically.  The simplest way to do this is to have the
   function reference changing global state.  Not ideal but the
   alternative is to change the implementation of the treap template.
   
   It's okay to make this variable static because this state never needs
   to be shared across compile units.  All of the functions in this
   template do not retain interest in this variable after each call.  */
static ulong LIVE_TABLE_(private_active_sort_key_idx) = ULONG_MAX;

static int
LIVE_TABLE_(private_row_lt)(LIVE_TABLE_ROW_T const * a, LIVE_TABLE_ROW_T const * b) {
  FD_TEST( LIVE_TABLE_(private_active_sort_key_idx) < LIVE_TABLE_MAX_SORT_KEY_CNT+1UL );

  LIVE_TABLE_(sort_key_t) const * active_sort_key = &((LIVE_TABLE_(sort_key_t) *)(a->LIVE_TABLE_SORT_KEYS))[ LIVE_TABLE_(private_active_sort_key_idx) ];

  ulong a_idx_idx = 0UL; /* idx into array of indices */
  ulong b_idx_idx = 0UL;
  do {
    /* advance pointers until neither column sort diraction is 0 (null) */
    if( FD_UNLIKELY( a_idx_idx<LIVE_TABLE_COLUMN_CNT-1UL && active_sort_key->dir[ a_idx_idx ]==0 ) ) {
      a_idx_idx++;
      continue;
    }
    if( FD_UNLIKELY( b_idx_idx<LIVE_TABLE_COLUMN_CNT-1UL && active_sort_key->dir[ b_idx_idx ]==0 ) ) {
      b_idx_idx++;
      continue;
    }

    LIVE_TABLE_(private_column_t) const * cols = LIVE_TABLE_COLUMNS;

    void * col_a = ((uchar *)a) + cols[ active_sort_key->col[ a_idx_idx ] ].off;
    void * col_b = ((uchar *)b) + cols[ active_sort_key->col[ b_idx_idx ] ].off;
    int a_lt_b = cols[ active_sort_key->col[ a_idx_idx ] ].lt(col_a, col_b);
    int b_lt_a = cols[ active_sort_key->col[ b_idx_idx ] ].lt(col_b, col_a);

    if( FD_UNLIKELY( !(a_lt_b || b_lt_a) ) ) {
      if( FD_LIKELY( a_idx_idx<LIVE_TABLE_COLUMN_CNT-1UL ) ) a_idx_idx++;
      if( FD_LIKELY( b_idx_idx<LIVE_TABLE_COLUMN_CNT-1UL ) ) b_idx_idx++;
      continue; /* equal */
    }

    return fd_int_if( active_sort_key->dir[ a_idx_idx ]==1, a_lt_b, !a_lt_b );
  } while( !(a_idx_idx==LIVE_TABLE_COLUMN_CNT-1UL && b_idx_idx==LIVE_TABLE_COLUMN_CNT-1UL) );

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
  void * treaps_shmem[ LIVE_TABLE_MAX_SORT_KEY_CNT ];

  /* LONG_MAX if treap is inactive, nanos UNIX timestamp of last iter.
     The first entry gets initalized to a default sort key and is not
     removable. */
  long activity_timers_nanos[ LIVE_TABLE_MAX_SORT_KEY_CNT ];
  ulong max_rows;
  /* We keep an extra space for a sort key at the end for use by
     LIVE_TABLE_(lt) */
  LIVE_TABLE_(sort_key_t) sort_keys[ LIVE_TABLE_MAX_SORT_KEY_CNT+1UL ];
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

LIVE_TABLE_STATIC FD_FN_PURE LIVE_TABLE_(fwd_iter_t) LIVE_TABLE_(fwd_iter_next)( LIVE_TABLE_(fwd_iter_t) iter, LIVE_TABLE_ROW_T const * pool );
LIVE_TABLE_STATIC FD_FN_PURE LIVE_TABLE_(fwd_iter_t) LIVE_TABLE_(fwd_iter_init)( LIVE_TABLE_(t) * join, LIVE_TABLE_(sort_key_t) const * sort_key, LIVE_TABLE_ROW_T * pool );

LIVE_TABLE_STATIC int LIVE_TABLE_(verify)( LIVE_TABLE_(t) const * table, LIVE_TABLE_ROW_T const * pool );

/* inlines */

FD_FN_CONST static inline ulong                    LIVE_TABLE_(idx_null)      ( void ) { return LIVE_TABLE_(private_treap_idx_null)();      }
FD_FN_CONST static inline LIVE_TABLE_ROW_T *       LIVE_TABLE_(ele_null)      ( void ) { return LIVE_TABLE_(private_treap_ele_null)();      }
FD_FN_CONST static inline LIVE_TABLE_ROW_T const * LIVE_TABLE_(ele_null_const)( void ) { return LIVE_TABLE_(private_treap_ele_null_const)(); }

FD_FN_CONST static inline int LIVE_TABLE_(idx_is_null)( ulong                    i ) { return LIVE_TABLE_(private_treap_idx_is_null)( i ); }
FD_FN_CONST static inline int LIVE_TABLE_(ele_is_null)( LIVE_TABLE_ROW_T const * e ) { return LIVE_TABLE_(private_treap_ele_is_null)( e ); }

FD_FN_CONST static inline ulong
LIVE_TABLE_(idx)( LIVE_TABLE_ROW_T const * e, LIVE_TABLE_ROW_T const * pool ) { return LIVE_TABLE_(private_treap_idx)( e, pool ); }

FD_FN_CONST static inline LIVE_TABLE_ROW_T *
LIVE_TABLE_(ele)( ulong i, LIVE_TABLE_ROW_T * pool ) { return LIVE_TABLE_(private_treap_ele)( i, pool ); }

FD_FN_CONST static inline LIVE_TABLE_ROW_T const *
LIVE_TABLE_(ele_const)( ulong i, LIVE_TABLE_ROW_T const * pool ) { return LIVE_TABLE_(private_treap_ele_const)( i, pool ); }

FD_FN_CONST static inline ulong
LIVE_TABLE_(idx_fast)( LIVE_TABLE_ROW_T const * e, LIVE_TABLE_ROW_T const * pool ) { return LIVE_TABLE_(private_treap_idx_fast)( e, pool ); }

FD_FN_CONST static inline LIVE_TABLE_ROW_T *       LIVE_TABLE_(ele_fast)      ( ulong i, LIVE_TABLE_ROW_T *       pool ) { return LIVE_TABLE_(private_treap_ele_fast)( i, pool ); }
FD_FN_CONST static inline LIVE_TABLE_ROW_T const * LIVE_TABLE_(ele_fast_const)( ulong i, LIVE_TABLE_ROW_T const * pool ) { return LIVE_TABLE_(private_treap_ele_fast_const)( i, pool ); }

FD_FN_CONST static inline LIVE_TABLE_(fwd_iter_t)
LIVE_TABLE_(fwd_iter_next)( LIVE_TABLE_(fwd_iter_t) iter, LIVE_TABLE_ROW_T const * pool ) { return LIVE_TABLE_(private_treap_fwd_iter_next)( iter, pool ); }

FD_FN_CONST static inline LIVE_TABLE_ROW_T *
LIVE_TABLE_(fwd_iter_ele)( LIVE_TABLE_(fwd_iter_t) iter, LIVE_TABLE_ROW_T * pool ) { return LIVE_TABLE_(private_treap_fwd_iter_ele)( iter, pool ); }

FD_FN_CONST static inline LIVE_TABLE_ROW_T const *
LIVE_TABLE_(fwd_iter_ele_const)( LIVE_TABLE_(fwd_iter_t) iter, LIVE_TABLE_ROW_T const * pool ) { return LIVE_TABLE_(private_treap_fwd_iter_ele_const)( iter, pool ); }

FD_FN_CONST static inline int
LIVE_TABLE_(fwd_iter_done)( LIVE_TABLE_(fwd_iter_t) iter ) { return LIVE_TABLE_(private_treap_fwd_iter_done)( iter ); }

FD_FN_CONST static inline ulong
LIVE_TABLE_(fwd_iter_idx)( LIVE_TABLE_(fwd_iter_t) iter ) { return LIVE_TABLE_(private_treap_fwd_iter_idx)( iter ); }

static inline LIVE_TABLE_ROW_T *
LIVE_TABLE_(ele_insert)( LIVE_TABLE_(t) * join, LIVE_TABLE_ROW_T * row, LIVE_TABLE_ROW_T * pool ) { return LIVE_TABLE_(idx_insert)( join, (ulong)(row - pool), pool ); }

static inline void
LIVE_TABLE_(ele_remove)( LIVE_TABLE_(t) * join, LIVE_TABLE_ROW_T * row, LIVE_TABLE_ROW_T * pool ) { LIVE_TABLE_(idx_remove)( join, (ulong)(row - pool), pool ); }

FD_FN_PURE static inline ulong LIVE_TABLE_(ele_cnt)( LIVE_TABLE_(t) * join ) { return LIVE_TABLE_(private_treap_ele_cnt)( join->treaps[ LIVE_TABLE_DEFAULT_TREAP_IDX ] ); }
FD_FN_PURE static inline ulong LIVE_TABLE_(ele_max)( LIVE_TABLE_(t) * join ) { return LIVE_TABLE_(private_treap_ele_max)( join->treaps[ LIVE_TABLE_DEFAULT_TREAP_IDX ] ); }

FD_FN_PURE static inline ulong
LIVE_TABLE_(active_sort_key_cnt)( LIVE_TABLE_(t) * join ) {
  ulong count = 0UL;
  for( ulong i=0; i<LIVE_TABLE_MAX_SORT_KEY_CNT; i++ ) {
#if FD_TMPL_USE_HANDHOLDING
    FD_TEST( join->activity_timers_nanos[ LIVE_TABLE_DEFAULT_TREAP_IDX ]!=LONG_MAX );
#endif
    if( FD_LIKELY( join->activity_timers_nanos[ i ]!=LONG_MAX ) ) count++;
  }
  return count;
}

FD_FN_CONST static inline ulong
LIVE_TABLE_(col_name_to_idx)( LIVE_TABLE_(t) * join, char const * col_name ) {
  (void)join;
  LIVE_TABLE_(private_column_t) const * cols = LIVE_TABLE_COLUMNS;
  for( ulong i=0; i < LIVE_TABLE_COLUMN_CNT; i++ ) {
    if( FD_UNLIKELY( strcmp( cols[ i ].col_name, col_name ) ) ) continue;
    return i;
  }
  return ULONG_MAX;
}

FD_FN_CONST static inline char const *
LIVE_TABLE_(col_idx_to_name)( LIVE_TABLE_(t) * join, ulong col_idx ) {
  (void)join;
  if( FD_UNLIKELY( col_idx>=LIVE_TABLE_COLUMN_CNT ) ) return NULL;
  LIVE_TABLE_(private_column_t) const * cols = LIVE_TABLE_COLUMNS;
  return cols[ col_idx ].col_name;
}

FD_FN_CONST static inline LIVE_TABLE_(sort_key_t) const *
LIVE_TABLE_(default_sort_key)( LIVE_TABLE_(t) * join ) {
  (void)join;
  return &join->sort_keys[ LIVE_TABLE_DEFAULT_TREAP_IDX ];
}

static inline void
LIVE_TABLE_(private_sort_key_print)( LIVE_TABLE_(sort_key_t) const * sort_key ) {
  char out[ 4096 ];
  char * p = fd_cstr_init( out );

  p = fd_cstr_append_printf( p, "cols: %lu", sort_key->col[ 0 ] );
  for( ulong i=1UL; i<LIVE_TABLE_COLUMN_CNT; i++ ) {
    p = fd_cstr_append_printf( p, ",%lu", sort_key->col[ i ] );
  }
  p = fd_cstr_append_printf( p, "\ndir: %d", sort_key->dir[ 0 ] );
  for( ulong i=1UL; i<LIVE_TABLE_COLUMN_CNT; i++ ) {
    p = fd_cstr_append_printf( p, ",%d", sort_key->dir[ i ] );
  }
  fd_cstr_fini( p );
  FD_LOG_WARNING(( "%s", out ));
}

static inline void
LIVE_TABLE_(private_sort_key_delete)( LIVE_TABLE_(t) * join, ulong sort_key_idx ) {
#if FD_TMPL_USE_HANDHOLDING
  FD_TEST( sort_key_idx!=LIVE_TABLE_DEFAULT_TREAP_IDX );
  FD_TEST( sort_key_idx<LIVE_TABLE_MAX_SORT_KEY_CNT );
#endif
join->activity_timers_nanos[ sort_key_idx ] = LONG_MAX;
LIVE_TABLE_(private_active_sort_key_idx) = sort_key_idx;
  LIVE_TABLE_(private_treap_delete)( LIVE_TABLE_(private_treap_leave)( join->treaps[ sort_key_idx ] ) );
  join->treaps[ sort_key_idx ] = NULL;
}

static inline void
LIVE_TABLE_(private_sort_key_create)( LIVE_TABLE_(t) * join, ulong sort_key_idx, LIVE_TABLE_(sort_key_t) const * sort_key, LIVE_TABLE_ROW_T * pool ) {
  fd_memcpy( &join->sort_keys[ sort_key_idx ], sort_key, sizeof(LIVE_TABLE_(sort_key_t)) );

  LIVE_TABLE_(private_active_sort_key_idx) = sort_key_idx;
  join->treaps[ sort_key_idx ] = LIVE_TABLE_(private_treap_join)( LIVE_TABLE_(private_treap_new)( join->treaps_shmem[ sort_key_idx ], join->max_rows ) );
#if FD_TMPL_USE_HANDHOLDING
  FD_TEST( sort_key_idx != LIVE_TABLE_DEFAULT_TREAP_IDX );
  FD_TEST( sort_key_idx<LIVE_TABLE_MAX_SORT_KEY_CNT );
  FD_TEST( join->treaps[ sort_key_idx ] );
  FD_TEST( !LIVE_TABLE_(private_treap_verify)( join->treaps[ sort_key_idx ], pool ) );
#endif

  /* loop through treaps[ LIVE_TABLE_DEFAULT_TREAP_IDX ], insert
     all entries into the new treap */
  LIVE_TABLE_(private_active_sort_key_idx) = LIVE_TABLE_DEFAULT_TREAP_IDX;
  LIVE_TABLE_(private_treap_fwd_iter_t) iter = LIVE_TABLE_(private_treap_fwd_iter_init)( join->treaps[ LIVE_TABLE_DEFAULT_TREAP_IDX ], pool );
  while( !LIVE_TABLE_(private_treap_fwd_iter_done)( iter ) ) {
    ulong pool_idx = LIVE_TABLE_(private_treap_fwd_iter_idx)( iter );
#if FD_TMPL_USE_HANDHOLDING
    FD_TEST( !LIVE_TABLE_(private_treap_idx_is_null)( pool_idx ) );
#endif

    LIVE_TABLE_(private_active_sort_key_idx) = sort_key_idx;
    LIVE_TABLE_(private_treap_idx_insert)( join->treaps[ sort_key_idx ], pool_idx, pool );

#if FD_TMPL_USE_HANDHOLDING
    FD_TEST( !LIVE_TABLE_(private_treap_verify)( join->treaps[ sort_key_idx ], pool ) );
#endif


    LIVE_TABLE_(private_active_sort_key_idx) = LIVE_TABLE_DEFAULT_TREAP_IDX;
    iter = LIVE_TABLE_(private_treap_fwd_iter_next)( iter, pool );
  }
  join->activity_timers_nanos[ sort_key_idx ] = fd_log_wallclock();
}

static inline ulong
LIVE_TABLE_(private_query_sort_key)( LIVE_TABLE_(t) * join, LIVE_TABLE_(sort_key_t) const * sort_key ) {
  for( ulong i=0; i<LIVE_TABLE_MAX_SORT_KEY_CNT; i++ ) {
    if( FD_UNLIKELY( join->activity_timers_nanos[ i ]==LONG_MAX ) ) continue;
    int equal = 1;
    ulong j = 0;
    ulong k = 0;
    do {
      /* columns with dir=0 don't actually count, they're ignored */
      if( FD_UNLIKELY( j<LIVE_TABLE_COLUMN_CNT-1UL && join->sort_keys[ i ].dir[ j ]==0 ) ) {
        j++;
        continue;
      }
      if( FD_UNLIKELY( k<LIVE_TABLE_COLUMN_CNT-1UL && sort_key->dir[ k ]==0 ) ) {
        k++;
        continue;
      }
      if( FD_LIKELY( join->sort_keys[ i ].col[ j ] != sort_key->col[ k ] || join->sort_keys[ i ].dir[ j ] != sort_key->dir[ k ] ) ) {
        equal = 0;
        break;
      }
      if( FD_LIKELY( j<LIVE_TABLE_COLUMN_CNT-1UL ) ) j++;
      if( FD_LIKELY( k<LIVE_TABLE_COLUMN_CNT-1UL ) ) k++; /* todo ... test edge case */
    } while( !(j==LIVE_TABLE_COLUMN_CNT-1UL && k==LIVE_TABLE_COLUMN_CNT-1UL) );
    if( FD_LIKELY( !equal ) ) continue;

    /* todo ... use fd_clock.c */
    join->activity_timers_nanos[ i ] = fd_log_wallclock();
    return i;
  }

  return ULONG_MAX;
}

static inline ulong
LIVE_TABLE_(private_query_or_add_sort_key)( LIVE_TABLE_(t) * join, LIVE_TABLE_(sort_key_t) const * sort_key, LIVE_TABLE_ROW_T * pool ) {
  /* garbage collect unused sort keys */
  for( ulong i=0UL; i<LIVE_TABLE_MAX_SORT_KEY_CNT; i++ ) {
    if( FD_LIKELY( LIVE_TABLE_GC_INTERVAL_NANOS==0 ) ) break;
    if( FD_UNLIKELY( i==LIVE_TABLE_DEFAULT_TREAP_IDX ) ) continue;
    if( FD_LIKELY( join->activity_timers_nanos[ i ]==LONG_MAX ) ) continue;

    /* LIVE_TABLE_GC_INTERVAL_NANOS==1 ensures unit tests pass */
    if( FD_UNLIKELY( fd_log_wallclock() - LIVE_TABLE_GC_INTERVAL_NANOS > join->activity_timers_nanos[ i ] || LIVE_TABLE_GC_INTERVAL_NANOS==1 ) ) {
      LIVE_TABLE_(private_active_sort_key_idx) = i;
      LIVE_TABLE_(private_sort_key_delete)( join, i );
    }
  }

  ulong sort_key_idx = LIVE_TABLE_(private_query_sort_key)( join, sort_key );
  if( FD_LIKELY( sort_key_idx!=ULONG_MAX ) ) {
#if FD_TMPL_USE_HANDHOLDING
    FD_TEST( join->activity_timers_nanos[ sort_key_idx ]!=LONG_MAX );
      LIVE_TABLE_(private_active_sort_key_idx) = sort_key_idx;
    if( LIVE_TABLE_(private_treap_verify)( join->treaps[ sort_key_idx ], pool ) ) {
      FD_LOG_WARNING(("default sort key:"));
      LIVE_TABLE_(private_sort_key_print)( LIVE_TABLE_(default_sort_key)( join ) );
      FD_LOG_WARNING(("active sort key:"));
      LIVE_TABLE_(private_sort_key_print)( sort_key );
      FD_LOG_CRIT(( "verify treap failed sort_key_idx=%lu activity_timer=%ld default_activity_timer=%ld", sort_key_idx, join->activity_timers_nanos[ sort_key_idx ], join->activity_timers_nanos[ LIVE_TABLE_DEFAULT_TREAP_IDX ] ));
    }
#endif
    return sort_key_idx;
  }

  /* look for an inactive sort key */
  for( ulong i=0UL; i<LIVE_TABLE_MAX_SORT_KEY_CNT; i++ ) {
    if( FD_LIKELY( join->activity_timers_nanos[ i ]==LONG_MAX ) ) {
      FD_TEST( i!=LIVE_TABLE_DEFAULT_TREAP_IDX );
      LIVE_TABLE_(private_sort_key_create)( join, i, sort_key, pool );
      return i;
    }
  }

  /* evict the oldest sort key */
  long oldest_timer_val = LONG_MAX;
  ulong oldest_timer_idx = ULONG_MAX;
  for( ulong i=0UL; i<LIVE_TABLE_MAX_SORT_KEY_CNT; i++ ) {
    if( FD_UNLIKELY( i==LIVE_TABLE_DEFAULT_TREAP_IDX ) ) continue;
    if( FD_UNLIKELY( oldest_timer_val==LONG_MAX || oldest_timer_val < join->activity_timers_nanos[ i ] ) ) {
      oldest_timer_val = join->activity_timers_nanos[ i ];
      oldest_timer_idx = i;
    }
  }

  if( FD_UNLIKELY( oldest_timer_idx==ULONG_MAX ) ) FD_LOG_CRIT(("unreachable"));

  FD_TEST( oldest_timer_idx!=LIVE_TABLE_DEFAULT_TREAP_IDX );
  LIVE_TABLE_(private_active_sort_key_idx) = oldest_timer_idx;
  LIVE_TABLE_(private_sort_key_delete)( join, oldest_timer_idx );
  LIVE_TABLE_(private_sort_key_create)( join, oldest_timer_idx, sort_key, pool );

  return oldest_timer_idx;
}

static inline int LIVE_TABLE_(lt) ( LIVE_TABLE_(sort_key_t) const * sort_key, LIVE_TABLE_ROW_T const * e0, LIVE_TABLE_ROW_T const * e1 ) {
  fd_memcpy( &((LIVE_TABLE_(sort_key_t) *)(e0->LIVE_TABLE_SORT_KEYS))[ LIVE_TABLE_MAX_SORT_KEY_CNT ], sort_key, sizeof(LIVE_TABLE_(sort_key_t)) );
  LIVE_TABLE_(private_active_sort_key_idx) = LIVE_TABLE_MAX_SORT_KEY_CNT;
  return LIVE_TABLE_(private_row_lt)(e0, e1);
}

#endif /* LIVE_TABLE_IMPL_STYLE!=2 */

#if LIVE_TABLE_IMPL_STYLE!=1 /* need implementations */

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
  for( ulong i=0UL; i<LIVE_TABLE_MAX_SORT_KEY_CNT; i++ ) l = FD_LAYOUT_APPEND( l, LIVE_TABLE_(private_treap_align)(), LIVE_TABLE_(private_treap_footprint)( max_rows ) );
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
  for( ulong i=0; i<LIVE_TABLE_MAX_SORT_KEY_CNT; i++ ) _table->treaps_shmem[ i ] = FD_SCRATCH_ALLOC_APPEND( l, LIVE_TABLE_(private_treap_align)(), LIVE_TABLE_(private_treap_footprint)( max_rows ) );
  FD_SCRATCH_ALLOC_FINI( l, LIVE_TABLE_(align)() );

  _table->max_rows = max_rows;
  for( ulong i=0; i<LIVE_TABLE_MAX_SORT_KEY_CNT; i++ ) _table->activity_timers_nanos[ i ] = LONG_MAX;

  /* treaps[ LIVE_TABLE_DEFAULT_TREAP_IDX ] is special,
     it will never be garbage collected or evicted and is treated as
     always active, even if its activity timer is ULONG_MAX. Its sort
     key is the columns in the order in which they are defined in the
     template all set to dir=-1 (descending) */
  LIVE_TABLE_(private_active_sort_key_idx) = LIVE_TABLE_DEFAULT_TREAP_IDX;
  _table->treaps[ LIVE_TABLE_DEFAULT_TREAP_IDX ] = LIVE_TABLE_(private_treap_join)( LIVE_TABLE_(private_treap_new)( _table->treaps_shmem[ LIVE_TABLE_DEFAULT_TREAP_IDX ], max_rows ) );
  _table->activity_timers_nanos[ LIVE_TABLE_DEFAULT_TREAP_IDX ] = fd_log_wallclock();

  FD_TEST( LIVE_TABLE_(ele_cnt)( _table ) == 0UL );
  FD_TEST( LIVE_TABLE_(active_sort_key_cnt)( _table ) == 1UL );

  for( ulong i=0; i < LIVE_TABLE_COLUMN_CNT; i++ ) {
    _table->sort_keys[ LIVE_TABLE_DEFAULT_TREAP_IDX ].col[ i ] = i;
    _table->sort_keys[ LIVE_TABLE_DEFAULT_TREAP_IDX ].dir[ i ] = -1;
  }

  FD_TEST( LIVE_TABLE_COLUMN_CNT == sizeof((LIVE_TABLE_COLUMNS))/sizeof(LIVE_TABLE_(private_column_t)) );

  /* live_table_treap_new( ... ) not called since all treaps start as inactive */

  return _table;
}

FD_PROTOTYPES_END

LIVE_TABLE_STATIC void
LIVE_TABLE_(seed)( LIVE_TABLE_ROW_T * pool, ulong rows_max, ulong seed ) {
  for( ulong i=0; i<LIVE_TABLE_MAX_SORT_KEY_CNT; i++ ) {
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

  for( ulong i=0; i<LIVE_TABLE_MAX_SORT_KEY_CNT; i++ ) {
    if( FD_LIKELY( join->activity_timers_nanos[ i ] == LONG_MAX ) ) continue;
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

  for( ulong i=0; i<LIVE_TABLE_MAX_SORT_KEY_CNT; i++ ) {
    if( FD_LIKELY( table->activity_timers_nanos[ i ] == LONG_MAX ) ) continue;
    LIVE_TABLE_(private_active_sort_key_idx) = i;
    LIVE_TABLE_(private_treap_delete)( table->treaps_shmem[ i ] );
  }

  return (void *)table;
}

LIVE_TABLE_STATIC void
LIVE_TABLE_(idx_remove)( LIVE_TABLE_(t) * join, ulong pool_idx, LIVE_TABLE_ROW_T * pool ) {
#if FD_TMPL_USE_HANDHOLDING
  FD_TEST( !LIVE_TABLE_(private_treap_idx_is_null)( pool_idx ) );
  ulong cnt = LIVE_TABLE_(ele_cnt)( join );
  FD_TEST( LIVE_TABLE_(active_sort_key_cnt)( join ) >= 1UL );
#endif
  /* remove from all active treaps */
  for( ulong i=0; i<LIVE_TABLE_MAX_SORT_KEY_CNT; i++ ) {
    if( FD_LIKELY( join->activity_timers_nanos[ i ] == LONG_MAX ) ) continue;
    LIVE_TABLE_(private_active_sort_key_idx) = i;
    LIVE_TABLE_(private_treap_idx_remove)( join->treaps[ i ], pool_idx, pool );
    join->activity_timers_nanos[ i ] = fd_log_wallclock();
  }
#if FD_TMPL_USE_HANDHOLDING
  FD_TEST( LIVE_TABLE_(ele_cnt)( join ) == cnt-1UL );
#endif
}

LIVE_TABLE_STATIC LIVE_TABLE_ROW_T *
LIVE_TABLE_(idx_insert)( LIVE_TABLE_(t) * join, ulong pool_idx, LIVE_TABLE_ROW_T * pool ) {
  pool[ pool_idx ].LIVE_TABLE_SORT_KEYS = (ulong)(&join->sort_keys);
#if FD_TMPL_USE_HANDHOLDING
  FD_TEST( !LIVE_TABLE_(private_treap_idx_is_null)( pool_idx ) );
  ulong cnt = LIVE_TABLE_(ele_cnt)( join );
  FD_TEST( LIVE_TABLE_(active_sort_key_cnt)( join ) >= 1UL );
#endif
  /* insert into all active treaps */
  for( ulong i=0; i<LIVE_TABLE_MAX_SORT_KEY_CNT; i++ ) {
    if( FD_LIKELY( join->activity_timers_nanos[ i ] == LONG_MAX ) ) continue;
    LIVE_TABLE_(private_active_sort_key_idx) = i;
    LIVE_TABLE_(private_treap_idx_insert)( join->treaps[ i ], pool_idx, pool );
    join->activity_timers_nanos[ i ] = fd_log_wallclock();
  }
#if FD_TMPL_USE_HANDHOLDING
  FD_TEST( LIVE_TABLE_(ele_cnt)( join ) == cnt+1UL );
#endif

  return pool + pool_idx;
}

LIVE_TABLE_STATIC FD_FN_PURE LIVE_TABLE_(fwd_iter_t)
LIVE_TABLE_(fwd_iter_init)( LIVE_TABLE_(t) * join, LIVE_TABLE_(sort_key_t) const * sort_key, LIVE_TABLE_ROW_T * pool ) {
  ulong sort_key_idx = LIVE_TABLE_(private_query_or_add_sort_key)( join, sort_key, pool );
  LIVE_TABLE_(private_active_sort_key_idx) = sort_key_idx;
#if FD_TMPL_USE_HANDHOLDING
  FD_TEST( join->activity_timers_nanos[ sort_key_idx ]!=LONG_MAX );
  FD_TEST( LIVE_TABLE_(active_sort_key_cnt)( join ) >= 1UL );
#endif
  return LIVE_TABLE_(private_treap_fwd_iter_init)( join->treaps[ sort_key_idx ], pool );
}

LIVE_TABLE_STATIC int
LIVE_TABLE_(verify)( LIVE_TABLE_(t) const * table, LIVE_TABLE_ROW_T const * pool ) {
  ulong prev_sk_idx = LIVE_TABLE_(private_active_sort_key_idx);
  (void)pool;
  for( ulong i=0UL; i<LIVE_TABLE_MAX_SORT_KEY_CNT; i++ ) {
    if( table->activity_timers_nanos[ i ]==LONG_MAX ) continue;

    LIVE_TABLE_(private_active_sort_key_idx) = i;
    if( LIVE_TABLE_(private_treap_verify)( table->treaps[ i ], pool ) ) {
      FD_LOG_CRIT(("failed verify"));
    }

    LIVE_TABLE_(sort_key_t) tmp_key[ 1 ];
    fd_memcpy( tmp_key, &table->sort_keys[ i ], sizeof(LIVE_TABLE_(sort_key_t)) );
    fd_sort_up_ulong_insert( tmp_key->col, LIVE_TABLE_COLUMN_CNT );

    for( ulong j=0UL; j<LIVE_TABLE_COLUMN_CNT; j++ ) {
      if( tmp_key->col[ j ]!=j || tmp_key->dir[ j ] > 1 || tmp_key->dir[ j ] < -1 ) {
        LIVE_TABLE_(private_sort_key_print)( &table->sort_keys[ i ] );
        FD_LOG_CRIT(( "bad sort key %lu", i ));
      }
    }
  }
  LIVE_TABLE_(private_active_sort_key_idx) = prev_sk_idx;
  return 0;
}

#endif /* LIVE_TABLE_IMPL_STYLE!=1 */

#undef LIVE_TABLE_NAME
#undef LIVE_TABLE_COLUMN_CNT
#undef LIVE_TABLE_MAX_SORT_KEY_CNT
#undef LIVE_TABLE_ROW_T
#undef LIVE_TABLE_COLUMNS
#undef LIVE_TABLE_SORT_KEYS
#undef LIVE_TABLE_TREAP
#undef LIVE_TABLE_GC_INTERVAL_NANOS
#undef LIVE_TABLE_
#undef LIVE_TABLE_COL_ENTRY
#undef LIVE_TABLE_COL_ARRAY
#undef LIVE_TABLE_DEFAULT_TREAP_IDX
#undef LIVE_TABLE_IMPL_STYLE
#undef LIVE_TABLE_STATIC
