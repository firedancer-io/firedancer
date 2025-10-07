/*
Generate prototypes, inlines and implementations for multi-sorted views
with a bounded compile-time number of columns and a bounded run-time
fixed row capacity.

A multi-sorted view is an iterator into an underlying table that
traverses the table in a particular multi-sorted ordering.  A multi-sort
is characterized by sorting multiple columns simultaneously, creating a
hierarchical order of data.

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
        ulong parent;
        ulong left;
        ulong right;
        ulong prio;
        ulong next;
        ulong prev;

        ... these fields back one of up to MY_TABLE_MAX_SORT_KEY_CNT
        ... active treaps.  See fd_treap.c for restrictions, lifetimes, etc.

      } treaps[ MY_TABLE_MAX_SORT_KEY_CNT ]; // technically LIVE_TABLE_TREAP[ MY_TABLE_MAX_SORT_KEY_CNT ]

      struct {
        ulong prev;
        ulong next;
      } dlist; // technically LIVE_TABLE_DLIST

      ulong sort_keys; // technically LIVE_TABLE_SORT_KEYS
    };
    typedef struct myrow myrow_t;

    static int col1_lt( void const * a, void const * b ) { return *(ulong *)a < *(ulong *)b; }
    static int col2_lt( void const * a, void const * b ) { return *(uint  *)a < *(uint  *)b; }

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
    ... first compares less than the second. The provided member may be
    ... a nested member but may not use a field that is accessed through
    ... a pointer dereference (due to an incompatibility with clang's
    ... __builtin_offsetof)

    ... OK:     LIVE_TABLE_COL_ENTRY("Column One", col1.a.b.c, col1_lt)
    ... NOT OK: LIVE_TABLE_COL_ENTRY("Column One", col1->a.c,  col1_lt)

    ... LIVE_TABLE_MAX_SORT_KEY_CNT must be greater than or equal to 2.

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

     // mytable_sort_key_remove removes sort_key from the collection of
     // sort_keys maintained by mytable.

     void mytable_sort_key_remove( mytable_t * join, mytable_sort_key_t const * sort_key  );

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

#ifndef LIVE_TABLE_DLIST
#define LIVE_TABLE_DLIST dlist
#endif

#define LIVE_TABLE_(n) FD_EXPAND_THEN_CONCAT3(LIVE_TABLE_NAME,_,n)

#include <stddef.h> // offsetof

#define LIVE_TABLE_COL_ENTRY(col_id, field, lt_func) \
  (LIVE_TABLE_(private_column_t)){ .col_name = col_id, .off = offsetof( LIVE_TABLE_ROW_T , field ), .lt = lt_func }

#define LIVE_TABLE_COL_ARRAY(...) { __VA_ARGS__ }

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

/* Global state is ugly. We only have one type of treap and they all
   share the same static comparison function, but we need that function
   to change dynamically.  The simplest way to do this is to have the
   function reference changing global state.  Not ideal but the
   alternative is to change the implementation of the treap template.

   This variable never needs to be shared across compile units.  All of
   the functions in this template do not retain interest in this
   variable after each call.  */
static ulong LIVE_TABLE_(private_active_sort_key_idx) = ULONG_MAX;

static int
LIVE_TABLE_(private_row_lt)(LIVE_TABLE_ROW_T const * a, LIVE_TABLE_ROW_T const * b) {
  FD_TEST( LIVE_TABLE_(private_active_sort_key_idx) < LIVE_TABLE_MAX_SORT_KEY_CNT+1UL );

  LIVE_TABLE_(sort_key_t) const * active_sort_key = &((LIVE_TABLE_(sort_key_t) *)(a->LIVE_TABLE_SORT_KEYS))[ LIVE_TABLE_(private_active_sort_key_idx) ];

  for( ulong i=0UL; i<LIVE_TABLE_COLUMN_CNT; i++ ) {
    if( FD_LIKELY( active_sort_key->dir[ i ]==0 ) ) continue;

    LIVE_TABLE_(private_column_t) cols[ LIVE_TABLE_COLUMN_CNT ] = LIVE_TABLE_COLUMNS;

    void * col_a = ((uchar *)a) + cols[ active_sort_key->col[ i ] ].off;
    void * col_b = ((uchar *)b) + cols[ active_sort_key->col[ i ] ].off;
    int a_lt_b = cols[ active_sort_key->col[ i ] ].lt(col_a, col_b);
    int b_lt_a = cols[ active_sort_key->col[ i ] ].lt(col_b, col_a);

    if( FD_UNLIKELY( !(a_lt_b || b_lt_a) ) ) continue; /* equal */
    return fd_int_if( active_sort_key->dir[ i ]==1, a_lt_b, !a_lt_b );
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
#define TREAP_PARENT LIVE_TABLE_TREAP[ LIVE_TABLE_(private_active_sort_key_idx) ].parent
#define TREAP_LEFT   LIVE_TABLE_TREAP[ LIVE_TABLE_(private_active_sort_key_idx) ].left
#define TREAP_RIGHT  LIVE_TABLE_TREAP[ LIVE_TABLE_(private_active_sort_key_idx) ].right
#define TREAP_NEXT   LIVE_TABLE_TREAP[ LIVE_TABLE_(private_active_sort_key_idx) ].next
#define TREAP_PREV   LIVE_TABLE_TREAP[ LIVE_TABLE_(private_active_sort_key_idx) ].prev
#define TREAP_PRIO   LIVE_TABLE_TREAP[ LIVE_TABLE_(private_active_sort_key_idx) ].prio
#define TREAP_IMPL_STYLE LIVE_TABLE_IMPL_STYLE
#include "../../util/tmpl/fd_treap.c"

#define DLIST_NAME  LIVE_TABLE_(private_dlist)
#define DLIST_ELE_T LIVE_TABLE_ROW_T
#define DLIST_PREV LIVE_TABLE_DLIST.prev
#define DLIST_NEXT LIVE_TABLE_DLIST.next
#include "../../util/tmpl/fd_dlist.c"

struct LIVE_TABLE_() {
  LIVE_TABLE_(private_dlist_t) * dlist;

  LIVE_TABLE_(private_treap_t) * treaps          [ LIVE_TABLE_MAX_SORT_KEY_CNT ];
  void *                         treaps_shmem    [ LIVE_TABLE_MAX_SORT_KEY_CNT ];
  int                            treaps_is_active[ LIVE_TABLE_MAX_SORT_KEY_CNT ];

  ulong count;
  ulong max_rows;
  LIVE_TABLE_(sort_key_t) sort_keys[ LIVE_TABLE_MAX_SORT_KEY_CNT ];
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

LIVE_TABLE_STATIC void
LIVE_TABLE_(sort_key_remove)( LIVE_TABLE_(t) * join, LIVE_TABLE_(sort_key_t) const * sort_key );

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

FD_FN_PURE static inline ulong LIVE_TABLE_(ele_cnt)( LIVE_TABLE_(t) * join ) { return join->count; }
FD_FN_PURE static inline ulong LIVE_TABLE_(ele_max)( LIVE_TABLE_(t) * join ) { return join->max_rows; }

FD_FN_PURE static inline ulong
LIVE_TABLE_(active_sort_key_cnt)( LIVE_TABLE_(t) * join ) {
  ulong count = 0UL;
  for( ulong i=0; i<LIVE_TABLE_MAX_SORT_KEY_CNT; i++ ) {
    if( FD_LIKELY( join->treaps_is_active[ i ] ) ) count++;
  }
  return count;
}

FD_FN_CONST static inline ulong
LIVE_TABLE_(col_name_to_idx)( LIVE_TABLE_(t) * join, char const * col_name ) {
  (void)join;
  LIVE_TABLE_(private_column_t) cols[ LIVE_TABLE_COLUMN_CNT ] = LIVE_TABLE_COLUMNS;
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
  LIVE_TABLE_(private_column_t) cols[ LIVE_TABLE_COLUMN_CNT ] = LIVE_TABLE_COLUMNS;
  return cols[ col_idx ].col_name;
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
LIVE_TABLE_(private_sort_key_create)( LIVE_TABLE_(t) * join, ulong sort_key_idx, LIVE_TABLE_(sort_key_t) const * sort_key, LIVE_TABLE_ROW_T * pool ) {
  fd_memcpy( &join->sort_keys[ sort_key_idx ], sort_key, sizeof(LIVE_TABLE_(sort_key_t)) );

  LIVE_TABLE_(private_active_sort_key_idx) = sort_key_idx;
  join->treaps[ sort_key_idx ] = LIVE_TABLE_(private_treap_join)( LIVE_TABLE_(private_treap_new)( join->treaps_shmem[ sort_key_idx ], join->max_rows ) );
  join->treaps_is_active[ sort_key_idx ] = 1;
#if FD_TMPL_USE_HANDHOLDING
  FD_TEST( sort_key_idx<LIVE_TABLE_MAX_SORT_KEY_CNT );
  FD_TEST( join->treaps[ sort_key_idx ] );
  FD_TEST( !LIVE_TABLE_(private_treap_verify)( join->treaps[ sort_key_idx ], pool ) );
#endif

  for( LIVE_TABLE_(private_dlist_iter_t) iter = LIVE_TABLE_(private_dlist_iter_fwd_init)( join->dlist, pool );
        !LIVE_TABLE_(private_dlist_iter_done)( iter, join->dlist, pool );
        iter = LIVE_TABLE_(private_dlist_iter_fwd_next)( iter, join->dlist, pool ) ) {
    ulong pool_idx = LIVE_TABLE_(private_dlist_iter_idx)( iter, join->dlist, pool );
    LIVE_TABLE_(private_treap_idx_insert)( join->treaps[ sort_key_idx ], pool_idx, pool );
  }

#if FD_TMPL_USE_HANDHOLDING
  FD_TEST( !LIVE_TABLE_(private_treap_verify)( join->treaps[ sort_key_idx ], pool ) );
#endif
}

static inline ulong
LIVE_TABLE_(private_query_sort_key)( LIVE_TABLE_(t) * join, LIVE_TABLE_(sort_key_t) const * sort_key ) {
  for( ulong i=0; i<LIVE_TABLE_MAX_SORT_KEY_CNT; i++ ) {
    if( FD_UNLIKELY( !join->treaps_is_active[ i ] ) ) continue;
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
      if( FD_LIKELY( !(join->sort_keys[ i ].dir[ j ]==0 && sort_key->dir[ k ]==0) && (join->sort_keys[ i ].col[ j ] != sort_key->col[ k ] || join->sort_keys[ i ].dir[ j ] != sort_key->dir[ k ]) ) ) {
        equal = 0;
        break;
      }
      if( FD_LIKELY( j<LIVE_TABLE_COLUMN_CNT-1UL ) ) j++;
      if( FD_LIKELY( k<LIVE_TABLE_COLUMN_CNT-1UL ) ) k++; /* todo ... test edge case */
    } while( !(j==LIVE_TABLE_COLUMN_CNT-1UL && k==LIVE_TABLE_COLUMN_CNT-1UL) );
    if( FD_LIKELY( !equal ) ) continue;
    return i;
  }

  return ULONG_MAX;
}

static inline int LIVE_TABLE_(lt) ( LIVE_TABLE_(sort_key_t) const * sort_key, LIVE_TABLE_ROW_T const * e0, LIVE_TABLE_ROW_T const * e1 ) {
  ulong old_val = e0->LIVE_TABLE_SORT_KEYS;
  ((LIVE_TABLE_ROW_T *)e0)->LIVE_TABLE_SORT_KEYS = (ulong)sort_key;
  LIVE_TABLE_(private_active_sort_key_idx) = 0;
  int lt = LIVE_TABLE_(private_row_lt)(e0, e1);
  ((LIVE_TABLE_ROW_T *)e0)->LIVE_TABLE_SORT_KEYS = old_val;
  return lt;
}

#endif /* LIVE_TABLE_IMPL_STYLE!=2 */

#if LIVE_TABLE_IMPL_STYLE!=1 /* need implementations */

LIVE_TABLE_STATIC ulong
LIVE_TABLE_(align)(void) {
  ulong a = 1UL;
  a = fd_ulong_max( a, alignof(LIVE_TABLE_(t)) );
  a = fd_ulong_max( a, LIVE_TABLE_(private_treap_align)() );
  a = fd_ulong_max( a, LIVE_TABLE_(private_dlist_align)() );
  a = fd_ulong_max( a, 128UL );
  FD_TEST( fd_ulong_pow2_up( a )==a );
  return a;
}

LIVE_TABLE_STATIC ulong
LIVE_TABLE_(footprint)( ulong max_rows ) {
  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, alignof(LIVE_TABLE_(t)), sizeof(LIVE_TABLE_(t)) );
  l = FD_LAYOUT_APPEND( l, LIVE_TABLE_(private_dlist_align)(), LIVE_TABLE_(private_dlist_footprint)() );
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
  void * _dlist = FD_SCRATCH_ALLOC_APPEND( l, LIVE_TABLE_(private_dlist_align)(), LIVE_TABLE_(private_dlist_footprint)() );
  for( ulong i=0; i<LIVE_TABLE_MAX_SORT_KEY_CNT; i++ ) _table->treaps_shmem[ i ] = FD_SCRATCH_ALLOC_APPEND( l, LIVE_TABLE_(private_treap_align)(), LIVE_TABLE_(private_treap_footprint)( max_rows ) );
  FD_SCRATCH_ALLOC_FINI( l, LIVE_TABLE_(align)() );

  _table->dlist = LIVE_TABLE_(private_dlist_join)( LIVE_TABLE_(private_dlist_new)( _dlist ) );
  _table->max_rows = max_rows;
  _table->count    = 0UL;
  for( ulong i=0; i<LIVE_TABLE_MAX_SORT_KEY_CNT; i++ ) _table->treaps_is_active[ i ] = 0;

  LIVE_TABLE_(private_column_t) cols[ LIVE_TABLE_COLUMN_CNT ] = LIVE_TABLE_COLUMNS;
  FD_TEST( LIVE_TABLE_COLUMN_CNT == sizeof(cols)/sizeof(LIVE_TABLE_(private_column_t)) );

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

  LIVE_TABLE_(private_dlist_delete)( LIVE_TABLE_(private_dlist_leave)( join->dlist ) );
  for( ulong i=0; i<LIVE_TABLE_MAX_SORT_KEY_CNT; i++ ) {
    if( FD_LIKELY( join->treaps_is_active[ i ] ) ) continue;
    LIVE_TABLE_(private_active_sort_key_idx) = i;
    FD_TEST( LIVE_TABLE_(private_treap_delete)( LIVE_TABLE_(private_treap_leave)( join->treaps[ i ] ) ) );
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

  return (void *)table;
}

LIVE_TABLE_STATIC void
LIVE_TABLE_(idx_remove)( LIVE_TABLE_(t) * join, ulong pool_idx, LIVE_TABLE_ROW_T * pool ) {
#if FD_TMPL_USE_HANDHOLDING
  FD_TEST( !LIVE_TABLE_(private_treap_idx_is_null)( pool_idx ) );
  FD_TEST( join->count >= 1UL );
#endif
  /* remove from all active treaps */
  for( ulong i=0; i<LIVE_TABLE_MAX_SORT_KEY_CNT; i++ ) {
    if( FD_LIKELY( !join->treaps_is_active[ i ] ) ) continue;
    LIVE_TABLE_(private_active_sort_key_idx) = i;
    LIVE_TABLE_(private_treap_idx_remove)( join->treaps[ i ], pool_idx, pool );
  }
  LIVE_TABLE_(private_dlist_idx_remove)( join->dlist, pool_idx, pool );
  join->count--;
}

LIVE_TABLE_STATIC LIVE_TABLE_ROW_T *
LIVE_TABLE_(idx_insert)( LIVE_TABLE_(t) * join, ulong pool_idx, LIVE_TABLE_ROW_T * pool ) {
  pool[ pool_idx ].LIVE_TABLE_SORT_KEYS = (ulong)(&join->sort_keys);
#if FD_TMPL_USE_HANDHOLDING
  FD_TEST( !LIVE_TABLE_(private_treap_idx_is_null)( pool_idx ) );
#endif
  /* insert into all active treaps */
  for( ulong i=0; i<LIVE_TABLE_MAX_SORT_KEY_CNT; i++ ) {
    if( FD_LIKELY( !join->treaps_is_active[ i ] ) ) continue;
    LIVE_TABLE_(private_active_sort_key_idx) = i;
    LIVE_TABLE_(private_treap_idx_insert)( join->treaps[ i ], pool_idx, pool );
  }
  LIVE_TABLE_(private_dlist_idx_push_tail)( join->dlist, pool_idx, pool );
  join->count++;

  return pool + pool_idx;
}

LIVE_TABLE_STATIC void
LIVE_TABLE_(sort_key_remove)( LIVE_TABLE_(t) * join, LIVE_TABLE_(sort_key_t) const * sort_key ) {
  ulong sort_key_idx = LIVE_TABLE_(private_query_sort_key)( join, sort_key );
  if( FD_UNLIKELY( sort_key_idx==ULONG_MAX  ) ) return;

  LIVE_TABLE_(private_active_sort_key_idx) = sort_key_idx;
#if FD_TMPL_USE_HANDHOLDING
  FD_TEST( sort_key_idx<LIVE_TABLE_MAX_SORT_KEY_CNT );
  FD_TEST( join->treaps[ sort_key_idx ] );
#endif
  join->treaps_is_active[ sort_key_idx ] = 0;
  LIVE_TABLE_(private_treap_delete)( LIVE_TABLE_(private_treap_leave)( join->treaps[ sort_key_idx ] ) );
  join->treaps[ sort_key_idx ] = NULL;
}

LIVE_TABLE_STATIC FD_FN_PURE LIVE_TABLE_(fwd_iter_t)
LIVE_TABLE_(fwd_iter_init)( LIVE_TABLE_(t) * join, LIVE_TABLE_(sort_key_t) const * sort_key, LIVE_TABLE_ROW_T * pool ) {
  ulong sort_key_idx = LIVE_TABLE_(private_query_sort_key)( join, sort_key );
  if( FD_UNLIKELY( sort_key_idx==ULONG_MAX ) ) {
    for( ulong i=0UL; i<LIVE_TABLE_COLUMN_CNT; i++ ) {
      if( FD_UNLIKELY( join->treaps_is_active[ i ] ) ) continue;
      sort_key_idx = i;
      LIVE_TABLE_(private_sort_key_create)( join, i, sort_key, pool );
      break;
    }
  }
  LIVE_TABLE_(private_active_sort_key_idx) = sort_key_idx;
#if FD_TMPL_USE_HANDHOLDING
  FD_TEST( sort_key_idx!=ULONG_MAX );
  FD_TEST( join->treaps_is_active[ sort_key_idx ] );
#endif
  return LIVE_TABLE_(private_treap_fwd_iter_init)( join->treaps[ sort_key_idx ], pool );
}

LIVE_TABLE_STATIC int
LIVE_TABLE_(verify)( LIVE_TABLE_(t) const * join, LIVE_TABLE_ROW_T const * pool ) {
  ulong prev_sk_idx = LIVE_TABLE_(private_active_sort_key_idx);
  for( ulong i=0UL; i<LIVE_TABLE_MAX_SORT_KEY_CNT; i++ ) {
    if( FD_LIKELY( !join->treaps_is_active[ i ] ) ) continue;

    LIVE_TABLE_(private_active_sort_key_idx) = i;
    if( FD_UNLIKELY( LIVE_TABLE_(private_treap_verify)( join->treaps[ i ], pool ) ) ) {
      FD_LOG_CRIT(("failed verify"));
    }

    LIVE_TABLE_(sort_key_t) tmp_key[ 1 ];
    fd_memcpy( tmp_key, &join->sort_keys[ i ], sizeof(LIVE_TABLE_(sort_key_t)) );
    fd_sort_up_ulong_insert( tmp_key->col, LIVE_TABLE_COLUMN_CNT );

    for( ulong j=0UL; j<LIVE_TABLE_COLUMN_CNT; j++ ) {
      if( FD_UNLIKELY( tmp_key->col[ j ]!=j || tmp_key->dir[ j ] > 1 || tmp_key->dir[ j ] < -1 ) ) {
        LIVE_TABLE_(private_sort_key_print)( &join->sort_keys[ i ] );
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
#undef LIVE_TABLE_DLIST
#undef LIVE_TABLE_
#undef LIVE_TABLE_COL_ENTRY
#undef LIVE_TABLE_COL_ARRAY
#undef LIVE_TABLE_IMPL_STYLE
#undef LIVE_TABLE_STATIC
