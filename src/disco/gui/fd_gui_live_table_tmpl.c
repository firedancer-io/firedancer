/*
Generate prototypes, inlines and implementations for tabular viewports
with a bounded compile-time number of columns and a bounded run-time
fixed row capacity.

A tabular viewport stores a collections of views into some underlying
table.  Each view has an associated sort key which determines the order
of the rows in the view.

Typical usage:

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

    mytable_sort_key_t my_sort_key = { .col = { 0, 1 }, .dir =  { mytable_sort_dir_null(), mytable_sort_dir_asc() } };

    #define LIVE_TABLE_NAME mytable
    #define LIVE_TABLE_ROW_CNT 10000UL
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

     // The mytable_sort_dir_{null|asc|desc} functions return
     // enumeration constants representing the sorting direction for a
     // table column.  These directions are:
     //    - null: No sorting applied to the column.
     //    - asc: Sort the column in ascending order.
     //    - desc: Sort the column in descending order.
     //
     // A "sort key" is a structure used to define multi-column sorting
     // behavior. It consists of:
     //    - An array of LIVE_TABLE_COLUMN_CNT column indices,
     //      specifying which columns are sorted.
     //    - An array of corresponding sort directions (null, asc, or
     //      desc), defining the sorting order.
     //
     // Rows are sorted by prioritizing earlier columns in the sort key,
     // with each column sorted according to its specified direction
     // (ascending, descending, or not sorted).

     int mytable_sort_dir_null(void);
     int mytable_sort_dir_asc (void);
     int mytable_sort_dir_desc(void);


     // Operations

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

#include "../../util/log/fd_log.h"
#include "../../util/rng/fd_rng.h"
#include "../../util/bits/fd_bits.h"


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

#define LIVE_TABLE_(n) FD_EXPAND_THEN_CONCAT3(LIVE_TABLE_NAME,_,n)

#define LIVE_TABLE_COL_ENTRY(field, cmp_func, hash_func, primary) \
    { .row_offset = offsetof(LIVE_TABLE_ROW_T, field), .cmp = cmp_func, .hash = hash_func, .is_primary = primary }

#define LIVE_TABLE_COL_ARRAY(...) \
    static const struct  LIVE_TABLE_(private_column)  LIVE_TABLE_(private_columns)[] = { __VA_ARGS__ };

#define PRIVATE_LIVE_TABLE_SORT_DIR_NULL (0UL)
#define PRIVATE_LIVE_TABLE_SORT_DIR_ASC  (1UL)
#define PRIVATE_LIVE_TABLE_SORT_DIR_DESC (2UL)

struct LIVE_TABLE_(private_pool_ele) {
  ulong pool_next;
  ulong map_next;
  ulong map_prev;
  ulong treap_parent  [ LIVE_TABLE_MAX_SORT_KEY_CNT ];
  ulong treap_left    [ LIVE_TABLE_MAX_SORT_KEY_CNT ];
  ulong treap_right   [ LIVE_TABLE_MAX_SORT_KEY_CNT ];
  ulong treap_prio    [ LIVE_TABLE_MAX_SORT_KEY_CNT ];
  ulong treap_next    [ LIVE_TABLE_MAX_SORT_KEY_CNT ];
  ulong treap_prev    [ LIVE_TABLE_MAX_SORT_KEY_CNT ];
  ulong treap_sort_key[ LIVE_TABLE_MAX_SORT_KEY_CNT ];

  LIVE_TABLE_ROW_T row;
};
typedef struct LIVE_TABLE_(private_pool_ele) LIVE_TABLE_(private_pool_ele_t);

struct LIVE_TABLE_(private_column) {
  ulong row_offset;
  int is_primary;
  int (* const cmp)(void const * a, void const * b);
  ulong (* const hash)(void const * key);
};

/* global constant array of column metadata */
LIVE_TABLE_COLUMNS

struct LIVE_TABLE_(sort_key) {
  ulong pool_next;

  ulong col[ LIVE_TABLE_COLUMN_CNT ];
  int dir[ LIVE_TABLE_COLUMN_CNT ];
};
typedef struct LIVE_TABLE_(sort_key) LIVE_TABLE_(sort_key_t);

#define POOL_NAME LIVE_TABLE_(private_pool)
#define POOL_T    LIVE_TABLE_(private_pool_ele_t)
#define POOL_NEXT pool_next
#include "../../util/tmpl/fd_pool.c"

static int
LIVE_TABLE_(private_key_eq)(LIVE_TABLE_ROW_T const * a, LIVE_TABLE_ROW_T const * b) {
  for( ulong i = 0; i < LIVE_TABLE_COLUMN_CNT; i++ ) {
    if( FD_UNLIKELY( !LIVE_TABLE_(private_columns)[ i ].is_primary ) ) continue;
    int cmp = LIVE_TABLE_(private_columns)[ i ].cmp( (uchar *)a + LIVE_TABLE_(private_columns)[ i ].row_offset, (uchar *)b + LIVE_TABLE_(private_columns)[ i ].row_offset );
    if( FD_UNLIKELY( cmp != 0 ) ) return 0;
  }
  return 1;
}

static ulong
LIVE_TABLE_(private_key_hash)(LIVE_TABLE_ROW_T const * row) {
  ulong hash = 0UL;
  for( ulong i = 0; i < LIVE_TABLE_COLUMN_CNT; i++ ) {
    if( FD_UNLIKELY( !LIVE_TABLE_(private_columns)[ i ].is_primary ) ) continue;
    hash = hash ^ LIVE_TABLE_(private_columns)[ i ].hash( (uchar *)row + LIVE_TABLE_(private_columns)[ i ].row_offset );
  }
  return hash;
}

#define MAP_NAME   LIVE_TABLE_(private_map)
#define MAP_ELE_T  LIVE_TABLE_(private_pool_ele_t)
#define MAP_KEY_T  LIVE_TABLE_ROW_T
#define MAP_KEY_EQ(a, b) ( LIVE_TABLE_(private_key_eq)( (a), (b) ) )
#define MAP_KEY_HASH(key,seed) ( fd_ulong_hash( LIVE_TABLE_(private_key_hash)( key ) ^ (seed) ) )
#define MAP_OPTIMIZE_RANDOM_ACCESS_REMOVAL 1
#define MAP_KEY   row
#define MAP_NEXT  map_next
#define MAP_PREV  map_prev
#include "../../util/tmpl/fd_map_chain.c"

/* global state is ugly. We only have one type of treap and they all
   share the same static comparison function, but we need that function to
   change dynamically.  The simplest way to do this is to have the function
   reference changing global state.  Not ideal but the alternative is to change
   the implementation of the treap template */
static LIVE_TABLE_(sort_key_t) LIVE_TABLE_(private_sort_keys)[ LIVE_TABLE_MAX_SORT_KEY_CNT ] = { 0UL };
static ulong LIVE_TABLE_(private_active_sort_key_idx) = ULONG_MAX;

static int
LIVE_TABLE_(private_row_cmp)(LIVE_TABLE_ROW_T const * a, LIVE_TABLE_ROW_T const * b) {
  FD_TEST( LIVE_TABLE_(private_active_sort_key_idx) < LIVE_TABLE_MAX_SORT_KEY_CNT );

  for( ulong col = 0UL; col < LIVE_TABLE_COLUMN_CNT; col++ ) {
    ulong sort_col = LIVE_TABLE_(private_sort_keys)[ LIVE_TABLE_(private_active_sort_key_idx) ].col[ col ];
    if( FD_LIKELY( LIVE_TABLE_(private_sort_keys)[ LIVE_TABLE_(private_active_sort_key_idx) ].dir[ sort_col ]==PRIVATE_LIVE_TABLE_SORT_DIR_NULL ) ) continue;
    void * col_a = ((uchar *)a) + LIVE_TABLE_(private_columns)[ sort_col ].row_offset;
    void * col_b = ((uchar *)b) + LIVE_TABLE_(private_columns)[ sort_col ].row_offset;
    int res = LIVE_TABLE_(private_columns)[ sort_col ].cmp(col_a, col_b);
    if( FD_UNLIKELY( !res ) ) continue;

    if( FD_LIKELY( LIVE_TABLE_(private_sort_keys)[ LIVE_TABLE_(private_active_sort_key_idx) ].dir[ sort_col ]==PRIVATE_LIVE_TABLE_SORT_DIR_DESC ) ) {
      return -res;
    } else if( FD_LIKELY( LIVE_TABLE_(private_sort_keys)[ LIVE_TABLE_(private_active_sort_key_idx) ].dir[ sort_col ]==PRIVATE_LIVE_TABLE_SORT_DIR_ASC ) ) {
      return res;
    } else {
      FD_LOG_ERR(( "unexpected sort dir %d", LIVE_TABLE_(private_sort_keys)[ LIVE_TABLE_(private_active_sort_key_idx) ].dir[ sort_col ] ));
    }
  }
  return 0;
}

#define TREAP_NAME      LIVE_TABLE_(private_treap)
#define TREAP_T         LIVE_TABLE_(private_pool_ele_t)
#define TREAP_QUERY_T   LIVE_TABLE_ROW_T
#define TREAP_CMP(q,e)  (LIVE_TABLE_(private_row_cmp)( (&q), (&e->row) ))
#define TREAP_LT(e0,e1) (LIVE_TABLE_(private_row_cmp)( (&e0->row), (&e1->row) ) < 0)
#define TREAP_OPTIMIZE_ITERATION 1
#define TREAP_PARENT treap_parent[ LIVE_TABLE_(private_active_sort_key_idx) ]
#define TREAP_LEFT treap_left[ LIVE_TABLE_(private_active_sort_key_idx) ]
#define TREAP_RIGHT treap_right[ LIVE_TABLE_(private_active_sort_key_idx) ]
#define TREAP_NEXT treap_next[ LIVE_TABLE_(private_active_sort_key_idx) ]
#define TREAP_PREV treap_prev[ LIVE_TABLE_(private_active_sort_key_idx) ]
#define TREAP_PRIO treap_prio[ LIVE_TABLE_(private_active_sort_key_idx) ]
#include "../../util/tmpl/fd_treap.c"

struct LIVE_TABLE_() {
  LIVE_TABLE_(private_pool_ele_t) * pool;
  LIVE_TABLE_(private_map_t) * map;
  LIVE_TABLE_(private_treap_t) * treaps[ LIVE_TABLE_MAX_SORT_KEY_CNT ];
  void * treaps_shmem[ LIVE_TABLE_MAX_SORT_KEY_CNT ];
  ulong activity_timers[ LIVE_TABLE_MAX_SORT_KEY_CNT ]; /* ULONG_MAX if treap is inactive, nanos UNIX timestamp of last iter */
  ulong max_rows;
  fd_rng_t * rng;
};
typedef struct LIVE_TABLE_() LIVE_TABLE_(t);

typedef LIVE_TABLE_(private_treap_fwd_iter_t) LIVE_TABLE_(fwd_iter_t);

ulong             LIVE_TABLE_(_align)    ( void                                     );
ulong             LIVE_TABLE_(_footprint)( ulong rows_max                           );
void      *       LIVE_TABLE_(_new)      ( void * shmem, ulong rows_max, ulong seed );
LIVE_TABLE_(t) * LIVE_TABLE_(_join)     ( void * shtable                           );
void      *       LIVE_TABLE_(_leave)    ( LIVE_TABLE_(t) * join                   );
void      *       LIVE_TABLE_(_delete)   ( void * shtable                           );


ulong LIVE_TABLE_(_max_rows)( LIVE_TABLE_(t) * join );

int LIVE_TABLE_(sort_dir_null)(void);
int LIVE_TABLE_(sort_dir_asc) (void);
int LIVE_TABLE_(sort_dir_desc)(void);

void               LIVE_TABLE_(remove_sort_key)( LIVE_TABLE_(t) * join, LIVE_TABLE_(sort_key_t) const * sort_key );
void               LIVE_TABLE_(remove)         ( LIVE_TABLE_(t) * join, LIVE_TABLE_ROW_T * key       );
LIVE_TABLE_ROW_T * LIVE_TABLE_(upsert)         ( LIVE_TABLE_(t) * join, LIVE_TABLE_ROW_T const * row );

int                      LIVE_TABLE_(fwd_iter_done)     ( LIVE_TABLE_(fwd_iter_t) iter );
ulong                    LIVE_TABLE_(fwd_iter_idx)      ( LIVE_TABLE_(fwd_iter_t) iter );
LIVE_TABLE_(fwd_iter_t)  LIVE_TABLE_(fwd_iter_init)     ( LIVE_TABLE_(t) * join, LIVE_TABLE_(sort_key_t) const * sort_key );
LIVE_TABLE_(fwd_iter_t)  LIVE_TABLE_(fwd_iter_next)     ( LIVE_TABLE_(t) * join, LIVE_TABLE_(sort_key_t) const * sort_key, LIVE_TABLE_(fwd_iter_t) iter );
LIVE_TABLE_ROW_T *       LIVE_TABLE_(fwd_iter_row)      ( LIVE_TABLE_(t) * join, LIVE_TABLE_(sort_key_t) const * sort_key, LIVE_TABLE_(fwd_iter_t) iter );
LIVE_TABLE_ROW_T const * LIVE_TABLE_(fwd_iter_row_const)( LIVE_TABLE_(t) * join, LIVE_TABLE_(sort_key_t) const * sort_key, LIVE_TABLE_(fwd_iter_t) iter );

ulong
LIVE_TABLE_(align)(void) {
  ulong a = alignof(LIVE_TABLE_(t));
  ulong b = LIVE_TABLE_(private_map_align)();
  ulong c = LIVE_TABLE_(private_pool_align)();
  ulong d = LIVE_TABLE_(private_treap_align)();
  ulong e = fd_rng_align();
  ulong f = 128UL;
  return fd_ulong_max( a, fd_ulong_max( b, fd_ulong_max( c, fd_ulong_max( d, fd_ulong_max( e, f ) ) ) ) );
}

ulong LIVE_TABLE_(footprint)( ulong max_rows ) {
  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, alignof(LIVE_TABLE_(t)), sizeof(LIVE_TABLE_(t)) );
  l = FD_LAYOUT_APPEND( l, fd_rng_align(), fd_rng_footprint() );
  l = FD_LAYOUT_APPEND( l, LIVE_TABLE_(private_map_align)(), LIVE_TABLE_(private_map_footprint)( LIVE_TABLE_(private_map_chain_cnt_est)( max_rows ) ) );
  l = FD_LAYOUT_APPEND( l, LIVE_TABLE_(private_pool_align)(), LIVE_TABLE_(private_pool_footprint)( max_rows ) );
  for( ulong i = 0; i<LIVE_TABLE_MAX_SORT_KEY_CNT; i++ ) l = FD_LAYOUT_APPEND( l, LIVE_TABLE_(private_treap_align)(), LIVE_TABLE_(private_treap_footprint)( max_rows ) );
  return FD_LAYOUT_FINI( l, LIVE_TABLE_(align)() );
}

void *
LIVE_TABLE_(new)( void * shmem, ulong max_rows, ulong seed ) {
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
  void * _rng = FD_SCRATCH_ALLOC_APPEND( l, fd_rng_align(), fd_rng_footprint() );
  void * _map = FD_SCRATCH_ALLOC_APPEND( l, LIVE_TABLE_(private_map_align)(), LIVE_TABLE_(private_map_footprint)( LIVE_TABLE_(private_map_chain_cnt_est)( max_rows ) ) );
  void * _pool = FD_SCRATCH_ALLOC_APPEND( l, LIVE_TABLE_(private_pool_align)(), LIVE_TABLE_(private_pool_footprint)( max_rows ) );
  for( ulong i = 0; i<LIVE_TABLE_MAX_SORT_KEY_CNT; i++ ) _table->treaps_shmem[ i ] = FD_SCRATCH_ALLOC_APPEND( l, LIVE_TABLE_(private_treap_align)(), LIVE_TABLE_(private_treap_footprint)( max_rows ) );
  FD_SCRATCH_ALLOC_FINI( l, LIVE_TABLE_(align)() );

  for( ulong i = 0; i<LIVE_TABLE_MAX_SORT_KEY_CNT; i++ ) _table->activity_timers[ i ] = ULONG_MAX;
  _table->max_rows = max_rows;

  _table->map  = LIVE_TABLE_(private_map_new)( _map, LIVE_TABLE_(private_map_chain_cnt_est)( max_rows ), seed );
  _table->pool = LIVE_TABLE_(private_pool_new)( _pool, max_rows );
  _table->rng  = fd_rng_new( _rng, (uint)seed, 0UL );
  /* live_table_treap_new( ... ) not called since all treaps start as inactive */

  return _table;
}

LIVE_TABLE_(t) *
LIVE_TABLE_(join)( void * shtable ) {
  LIVE_TABLE_(t) * _table = (LIVE_TABLE_(t) *)shtable;

  _table->map = LIVE_TABLE_(private_map_join)( _table->map );
  _table->pool = LIVE_TABLE_(private_pool_join)( _table->pool );
  _table->rng  = fd_rng_join( _table->rng );

  return _table;
}

void *
LIVE_TABLE_(leave)( LIVE_TABLE_(t) * join ) {
  if( FD_UNLIKELY( !join ) ) {
  FD_LOG_WARNING(( "NULL join" ));
  return NULL;
  }

  LIVE_TABLE_(private_map_leave)( join->map );
  LIVE_TABLE_(private_pool_leave)( join->pool );
  for( ulong i = 0; i<LIVE_TABLE_MAX_SORT_KEY_CNT; i++ ) {
    if( FD_LIKELY( join->activity_timers[ i ] == ULONG_MAX ) ) continue;
    LIVE_TABLE_(private_active_sort_key_idx) = i;
    LIVE_TABLE_(private_treap_leave)( join->treaps[ i ] );
  }

  return (void *)join;
}

void *
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

  LIVE_TABLE_(private_map_delete)( table->map );
  LIVE_TABLE_(private_pool_delete)( table->pool );
  for( ulong i = 0; i<LIVE_TABLE_MAX_SORT_KEY_CNT; i++ ) {
    if( FD_LIKELY( table->activity_timers[ i ] == ULONG_MAX ) ) continue;
    LIVE_TABLE_(private_active_sort_key_idx) = i;
    LIVE_TABLE_(private_treap_delete)( table->treaps[ i ] );
  }

  return (void *)table;
}

ulong
LIVE_TABLE_(_max_rows)( LIVE_TABLE_(t) * join ) {
  return join->max_rows;
}

void
LIVE_TABLE_(remove)( LIVE_TABLE_(t) * join, LIVE_TABLE_ROW_T * row ) {
  ulong pool_idx = LIVE_TABLE_(private_map_idx_query_const)( join->map, row, ULONG_MAX, join->pool);
  if( FD_UNLIKELY( ULONG_MAX==pool_idx ) ) return;

  for( ulong i = 0; i<LIVE_TABLE_MAX_SORT_KEY_CNT; i++ ) {
    if( FD_LIKELY( join->activity_timers[ i ] == ULONG_MAX ) ) continue;
    LIVE_TABLE_(private_active_sort_key_idx) = i;
    LIVE_TABLE_(private_treap_idx_remove)( join->treaps[ i ], pool_idx, join->pool );
  }
  LIVE_TABLE_(private_map_idx_remove)(join->map, row, ULONG_MAX, join->pool);
  LIVE_TABLE_(private_pool_idx_release)(join->pool, pool_idx);
}

LIVE_TABLE_ROW_T *
LIVE_TABLE_(upsert)( LIVE_TABLE_(t) * join, LIVE_TABLE_ROW_T const * row ) {
  /* get idx into join->pool for this row */
  ulong pool_idx = LIVE_TABLE_(private_map_idx_query_const)( join->map, row, ULONG_MAX, join->pool);
  LIVE_TABLE_(private_pool_ele_t) * ele;
  if( FD_LIKELY( pool_idx == ULONG_MAX ) ) {
    /* acquire new pool element */
    pool_idx = LIVE_TABLE_(private_pool_idx_acquire)( join->pool );

    ele = LIVE_TABLE_(private_pool_ele)(join->pool, pool_idx);

    /* algorithmic costs for a treap assume priorities are random */
    for( ulong i=0UL; i<LIVE_TABLE_MAX_SORT_KEY_CNT; i++ ) ele->treap_prio[ i ] = fd_rng_ulong( join->rng );

    /* update the row */
    memcpy( &ele->row, row, sizeof(LIVE_TABLE_ROW_T) );

    LIVE_TABLE_(private_map_idx_insert)(join->map, pool_idx, join->pool);
  } else {
    /* first remove row from all treaps */
    for( ulong i = 0; i<LIVE_TABLE_MAX_SORT_KEY_CNT; i++ ) {
      if( FD_LIKELY( join->activity_timers[ i ] == ULONG_MAX ) ) continue;
      LIVE_TABLE_(private_active_sort_key_idx) = i;
      LIVE_TABLE_(private_treap_idx_remove)( join->treaps[ i ], pool_idx, join->pool );
    }

    /* update the row */
    ele = LIVE_TABLE_(private_pool_ele)(join->pool, pool_idx);
    memcpy( &ele->row, row, sizeof(LIVE_TABLE_ROW_T) );
  }

  /* insert into all active treaps */
  for( ulong i = 0; i<LIVE_TABLE_MAX_SORT_KEY_CNT; i++ ) {
    if( FD_LIKELY( join->activity_timers[ i ] == ULONG_MAX ) ) continue;
    LIVE_TABLE_(private_active_sort_key_idx) = i;
    LIVE_TABLE_(private_treap_idx_insert)(join->treaps[i], pool_idx, join->pool);
    join->activity_timers[ i ] = (ulong)fd_tickcount();
  }

  return &ele->row;
}

static void
LIVE_TABLE_(private_sort_key_delete)( LIVE_TABLE_(t) * join, ulong sort_key_idx ) {
  FD_TEST( sort_key_idx<LIVE_TABLE_MAX_SORT_KEY_CNT );
  LIVE_TABLE_(private_active_sort_key_idx) = sort_key_idx;
  LIVE_TABLE_(private_treap_leave)( join->treaps[ sort_key_idx ] );
  LIVE_TABLE_(private_treap_delete)( join->treaps[ sort_key_idx ] );
  join->treaps[ sort_key_idx ] = NULL;
  join->activity_timers[ sort_key_idx ] = ULONG_MAX;
}

static void
LIVE_TABLE_(private_sort_key_create)( LIVE_TABLE_(t) * join, ulong sort_key_idx, LIVE_TABLE_(sort_key_t) const * sort_key ) {
  // FD_LOG_WARNING(("private_sort_key_create sort_key_idx %lu", sort_key_idx));
  FD_TEST( sort_key_idx<LIVE_TABLE_MAX_SORT_KEY_CNT );
  LIVE_TABLE_(private_sort_keys)[ sort_key_idx ] = *sort_key;
  LIVE_TABLE_(private_active_sort_key_idx) = sort_key_idx;
  join->treaps[ sort_key_idx ] = LIVE_TABLE_(private_treap_join)( LIVE_TABLE_(private_treap_new)( join->treaps_shmem[ sort_key_idx ], join->max_rows ) );
  FD_TEST( join->treaps[ sort_key_idx ] );

  /* loop through the rows and insert them all into the treap */
  for( LIVE_TABLE_(private_map_iter_t) iter = LIVE_TABLE_(private_map_iter_init)( join->map, join->pool );
        !LIVE_TABLE_(private_map_iter_done)( iter, join->map, join->pool );
        iter = LIVE_TABLE_(private_map_iter_next)( iter, join->map, join->pool ) ) {
    ulong pool_idx = LIVE_TABLE_(private_map_iter_idx)( iter, join->map, join->pool );
    LIVE_TABLE_(private_treap_idx_insert)( join->treaps[ sort_key_idx ], pool_idx, join->pool );
  }
  join->activity_timers[ sort_key_idx ] = (ulong)fd_tickcount();
}

static ulong
LIVE_TABLE_(private_query_sort_key)( LIVE_TABLE_(t) * join, LIVE_TABLE_(sort_key_t) const * sort_key ) {
  /* look for a matching sort key. todo ... look for exact match ignoring null cols */
  for( ulong i = 0; i<LIVE_TABLE_MAX_SORT_KEY_CNT; i++ ) {
    if( FD_UNLIKELY( join->activity_timers[ i ] == ULONG_MAX ) ) continue;
    int equal = 1;
    for( ulong j=0UL; j<LIVE_TABLE_COLUMN_CNT; j++ ) {
      FD_TEST( sort_key->col[ j ] <= LIVE_TABLE_COLUMN_CNT );
      if( FD_LIKELY( LIVE_TABLE_(private_sort_keys)[ i ].col[ j ] != sort_key->col[ j ] || LIVE_TABLE_(private_sort_keys)[ i ].dir[ j ] != sort_key->dir[ j ] ) ) {
        equal = 0;
        break;
      }
    }
    if( FD_LIKELY( !equal ) ) continue;
    join->activity_timers[ i ] = (ulong)fd_tickcount();
    return i;
  }

  return ULONG_MAX;
}

static ulong
LIVE_TABLE_(private_query_or_add_sort_key)( LIVE_TABLE_(t) * join, LIVE_TABLE_(sort_key_t) const * sort_key ) {
  ulong sort_key_idx = LIVE_TABLE_(private_query_sort_key)( join, sort_key );
  if( FD_LIKELY( sort_key_idx!=ULONG_MAX ) ) return sort_key_idx;

  /* look for an inactive sort key */
  for( ulong i=0UL; i<LIVE_TABLE_MAX_SORT_KEY_CNT; i++ ) {
    if( FD_LIKELY( join->activity_timers[ i ]==ULONG_MAX ) ) {
      LIVE_TABLE_(private_sort_key_create)( join, i, sort_key );
      return i;
    }
  }

  /* evict the oldest sort key */
  ulong oldest_timer_val = join->activity_timers[ 0UL ];
  ulong oldest_timer_idx = 0UL;
  for( ulong i=0UL; i<LIVE_TABLE_MAX_SORT_KEY_CNT; i++ ) {
    if( FD_UNLIKELY( oldest_timer_val < join->activity_timers[ i ] ) ) {
      oldest_timer_val = join->activity_timers[ i ];
      oldest_timer_idx = i;
    }
  }

  if( FD_UNLIKELY( oldest_timer_idx==ULONG_MAX ) ) FD_LOG_ERR(("should not happend"));

  LIVE_TABLE_(private_active_sort_key_idx) = oldest_timer_idx;
  LIVE_TABLE_(private_sort_key_delete)( join, oldest_timer_idx );
  LIVE_TABLE_(private_sort_key_create)( join, oldest_timer_idx, sort_key );

  return oldest_timer_idx;
}

void
LIVE_TABLE_(remove_sort_key)( LIVE_TABLE_(t) * join, LIVE_TABLE_(sort_key_t) const * sort_key ) {
  ulong sort_key_idx = LIVE_TABLE_(private_query_sort_key)( join, sort_key );
  if( FD_LIKELY( sort_key_idx==ULONG_MAX ) ) return;
  LIVE_TABLE_(private_sort_key_delete)( join, sort_key_idx );
}


int
LIVE_TABLE_(fwd_iter_done)( LIVE_TABLE_(fwd_iter_t) iter ) {
  return LIVE_TABLE_(private_treap_fwd_iter_done)( iter );
}

ulong
LIVE_TABLE_(fwd_iter_idx)( LIVE_TABLE_(fwd_iter_t) iter ) {
  return LIVE_TABLE_(private_treap_fwd_iter_idx)( iter );
}

LIVE_TABLE_(fwd_iter_t)
LIVE_TABLE_(fwd_iter_init)( LIVE_TABLE_(t) * join, LIVE_TABLE_(sort_key_t) const * sort_key ) {
  ulong sort_key_idx = LIVE_TABLE_(private_query_or_add_sort_key)( join, sort_key );
  // FD_LOG_INFO(("live_table_fwd_iter_init sort_key_idx=%lu", sort_key_idx));
  LIVE_TABLE_(private_active_sort_key_idx) = sort_key_idx;
  return LIVE_TABLE_(private_treap_fwd_iter_init)( join->treaps[ sort_key_idx ], join->pool );
}

LIVE_TABLE_(fwd_iter_t)
LIVE_TABLE_(fwd_iter_next)( LIVE_TABLE_(t) * join, LIVE_TABLE_(sort_key_t) const * sort_key, LIVE_TABLE_(fwd_iter_t) iter ) {
  ulong sort_key_idx = LIVE_TABLE_(private_query_sort_key)( join, sort_key );
  // FD_LOG_INFO(("live_table_fwd_iter_next sort_key_idx=%lu", sort_key_idx));
  LIVE_TABLE_(private_active_sort_key_idx) = sort_key_idx;
  return LIVE_TABLE_(private_treap_fwd_iter_next)( iter, join->pool );
}

LIVE_TABLE_ROW_T *
LIVE_TABLE_(fwd_iter_row)( LIVE_TABLE_(t) * join, LIVE_TABLE_(sort_key_t) const * sort_key, LIVE_TABLE_(fwd_iter_t) iter ) {
  ulong sort_key_idx = LIVE_TABLE_(private_query_sort_key)( join, sort_key );
  // FD_LOG_INFO(("live_table_fwd_iter_row sort_key_idx=%lu", sort_key_idx));
  LIVE_TABLE_(private_active_sort_key_idx) = sort_key_idx;
  return &LIVE_TABLE_(private_treap_fwd_iter_ele)( iter, join->pool )->row;
}

LIVE_TABLE_ROW_T const *
LIVE_TABLE_(fwd_iter_row_const)( LIVE_TABLE_(t) * join, LIVE_TABLE_(sort_key_t) const * sort_key, LIVE_TABLE_(fwd_iter_t) iter ) {
  ulong sort_key_idx = LIVE_TABLE_(private_query_sort_key)( join, sort_key );
  // FD_LOG_INFO(("live_table_fwd_iter_init sort_key_idx=%lu", sort_key_idx));
  LIVE_TABLE_(private_active_sort_key_idx) = sort_key_idx;
  return &LIVE_TABLE_(private_treap_fwd_iter_ele)( iter, join->pool )->row;
}

int
LIVE_TABLE_(sort_dir_null)(void) {
  return PRIVATE_LIVE_TABLE_SORT_DIR_NULL;
}

int
LIVE_TABLE_(sort_dir_asc)(void) {
  return PRIVATE_LIVE_TABLE_SORT_DIR_ASC;
}

int
LIVE_TABLE_(sort_dir_desc)(void) {
  return PRIVATE_LIVE_TABLE_SORT_DIR_DESC;
}

#undef LIVE_TABLE_NAME
#undef PRIVATE_LIVE_TABLE_SORT_DIR_NULL
#undef PRIVATE_LIVE_TABLE_SORT_DIR_ASC
#undef PRIVATE_LIVE_TABLE_SORT_DIR_DESC
#undef LIVE_TABLE_COLUMN_CNT
#undef LIVE_TABLE_MAX_SORT_KEY_CNT
#undef LIVE_TABLE_ROW_T
#undef LIVE_TABLE_COLUMNS
#undef LIVE_TABLE_COL_ENTRY
#undef LIVE_TABLE_COL_ARRAY
