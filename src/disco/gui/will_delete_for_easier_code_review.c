/*
NON_TEMPLATE VERSION FOR THE CODE REVIEW. WILL DELETE.
*/

#include "../fd_disco.h"
#include "../../util/log/fd_log.h"
#include "../../util/bits/fd_bits.h"



#define LIVE_TABLE_COLUMN_CNT (2UL)
#define LIVE_TABLE_ROW_CNT (10000UL)
#define LIVE_TABLE_MAX_SORT_KEY_CNT (1024UL)

#define PRIVATE_LIVE_TABLE_SORT_DIR_NULL (0UL)
#define PRIVATE_LIVE_TABLE_SORT_DIR_ASC  (1UL)
#define PRIVATE_LIVE_TABLE_SORT_DIR_DESC (2UL)

struct myrow {
  fd_pubkey_t key;
  uint ipv4;
};
typedef struct myrow myrow_t;

static int live_table_col_pubkey_cmp( void const * a, void const * b ) { return memcmp( (fd_pubkey_t *)a, (fd_pubkey_t *)b, 32UL ); }
static int live_table_col_ipv4_cmp( void const * a, void const * b ) { return (int)((*(uint *)a) - (*(uint *)b)); }
static ulong live_table_col_pubkey_hash( void const * key ) { return fd_ulong_hash( *(ulong *)key ); }
static ulong live_table_col_ipv4_hash( void const * key ) { return fd_ulong_hash( ((fd_pubkey_t *)key)->ul[ 0UL ] ); }

struct mytable_private_pool_ele {
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

  myrow_t row;
};
typedef struct mytable_private_pool_ele mytable_private_pool_ele_t;

struct mytable_private_column {
  ulong row_offset;
  int is_primary;
  int (* const cmp)(void const * a, void const * b);
  ulong (* const hash)(void const * key);
};

/* global constant array of column metadata */
static const struct  mytable_private_column  mytable_private_columns[] = {
  { .row_offset = offsetof(myrow_t, key), .cmp = live_table_col_pubkey_cmp, .hash = live_table_col_pubkey_hash, .is_primary = 1 },
  { .row_offset = offsetof(myrow_t, ipv4), .cmp = live_table_col_ipv4_cmp, .hash = live_table_col_ipv4_hash, .is_primary = 0 }
};

struct mytable_sort_key {
  ulong pool_next;

  ulong col[ LIVE_TABLE_COLUMN_CNT ];
  int dir[ LIVE_TABLE_COLUMN_CNT ];
};
typedef struct mytable_sort_key mytable_sort_key_t;

#define POOL_NAME mytable_private_pool
#define POOL_T    mytable_private_pool_ele_t
#define POOL_NEXT pool_next
#include "../../util/tmpl/fd_pool.c"

static int
mytable_private_key_eq(myrow_t const * a, myrow_t const * b) {
  for( ulong i = 0; i < LIVE_TABLE_COLUMN_CNT; i++ ) {
    if( FD_UNLIKELY( !mytable_private_columns[ i ].is_primary ) ) continue;
    int cmp = mytable_private_columns[ i ].cmp( (uchar *)a + mytable_private_columns[ i ].row_offset, (uchar *)b + mytable_private_columns[ i ].row_offset );
    if( FD_UNLIKELY( cmp != 0 ) ) return 0;
  }
  return 1;
}

static ulong
mytable_private_key_hash(myrow_t const * row) {
  ulong hash = 0UL;
  for( ulong i = 0; i < LIVE_TABLE_COLUMN_CNT; i++ ) {
    if( FD_UNLIKELY( !mytable_private_columns[ i ].is_primary ) ) continue;
    hash = hash ^ mytable_private_columns[ i ].hash( (uchar *)row + mytable_private_columns[ i ].row_offset );
  }
  return hash;
}

#define MAP_NAME   mytable_private_map
#define MAP_ELE_T  mytable_private_pool_ele_t
#define MAP_KEY_T  myrow_t
#define MAP_KEY_EQ(a, b) ( mytable_private_key_eq( (a), (b) ) )
#define MAP_KEY_HASH(key,seed) ( fd_ulong_hash( mytable_private_key_hash( key ) ^ (seed) ) )
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
static mytable_sort_key_t mytable_private_sort_keys[ LIVE_TABLE_MAX_SORT_KEY_CNT ] = { 0UL };
static ulong mytable_private_active_sort_key_idx = ULONG_MAX;

static int
mytable_private_row_cmp(myrow_t const * a, myrow_t const * b) {
  FD_TEST( mytable_private_active_sort_key_idx < LIVE_TABLE_MAX_SORT_KEY_CNT );

  for( ulong col = 0UL; col < LIVE_TABLE_COLUMN_CNT; col++ ) {
    ulong sort_col = mytable_private_sort_keys[ mytable_private_active_sort_key_idx ].col[ col ];
    if( FD_LIKELY( mytable_private_sort_keys[ mytable_private_active_sort_key_idx ].dir[ sort_col ]==PRIVATE_LIVE_TABLE_SORT_DIR_NULL ) ) continue;
    void * col_a = ((uchar *)a) + mytable_private_columns[ sort_col ].row_offset;
    void * col_b = ((uchar *)b) + mytable_private_columns[ sort_col ].row_offset;
    int res = mytable_private_columns[ sort_col ].cmp(col_a, col_b);
    if( FD_UNLIKELY( !res ) ) continue;

    if( FD_LIKELY( mytable_private_sort_keys[ mytable_private_active_sort_key_idx ].dir[ sort_col ]==PRIVATE_LIVE_TABLE_SORT_DIR_DESC ) ) {
      return -res;
    } else if( FD_LIKELY( mytable_private_sort_keys[ mytable_private_active_sort_key_idx ].dir[ sort_col ]==PRIVATE_LIVE_TABLE_SORT_DIR_ASC ) ) {
      return res;
    } else {
      FD_LOG_ERR(( "unexpected sort dir %d", mytable_private_sort_keys[ mytable_private_active_sort_key_idx ].dir[ sort_col ] ));
    }
  }
  return 0;
}

#define TREAP_NAME      mytable_private_treap
#define TREAP_T         mytable_private_pool_ele_t
#define TREAP_QUERY_T   myrow_t
#define TREAP_CMP(q,e)  (mytable_private_row_cmp( (&q), (&e->row) ))
#define TREAP_LT(e0,e1) (mytable_private_row_cmp( (&e0->row), (&e1->row) ) < 0)
#define TREAP_OPTIMIZE_ITERATION 1
#define TREAP_PARENT treap_parent[ mytable_private_active_sort_key_idx ]
#define TREAP_LEFT treap_left[ mytable_private_active_sort_key_idx ]
#define TREAP_RIGHT treap_right[ mytable_private_active_sort_key_idx ]
#define TREAP_NEXT treap_next[ mytable_private_active_sort_key_idx ]
#define TREAP_PREV treap_prev[ mytable_private_active_sort_key_idx ]
#define TREAP_PRIO treap_prio[ mytable_private_active_sort_key_idx ]
#include "../../util/tmpl/fd_treap.c"

struct mytable {
  mytable_private_pool_ele_t * pool;
  mytable_private_map_t * map;
  mytable_private_treap_t * treaps[ LIVE_TABLE_MAX_SORT_KEY_CNT ];
  void * treaps_shmem[ LIVE_TABLE_MAX_SORT_KEY_CNT ];
  ulong activity_timers[ LIVE_TABLE_MAX_SORT_KEY_CNT ]; /* ULONG_MAX if treap is inactive, nanos UNIX timestamp of last iter */
  ulong max_rows;
  fd_rng_t * rng;
};
typedef struct mytable mytable_t;

typedef mytable_private_treap_fwd_iter_t mytable_fwd_iter_t;

ulong             mytable__align    ( void                                     );
ulong             mytable__footprint( ulong rows_max                           );
void      *       mytable__new      ( void * shmem, ulong rows_max, ulong seed );
mytable_t * mytable__join     ( void * shtable                           );
void      *       mytable__leave    ( mytable_t * join                   );
void      *       mytable__delete   ( void * shtable                           );


ulong mytable__max_rows( mytable_t * join );

int mytable_sort_dir_null(void);
int mytable_sort_dir_asc (void);
int mytable_sort_dir_desc(void);

void               mytable_remove_sort_key( mytable_t * join, mytable_sort_key_t const * sort_key );
void               mytable_remove         ( mytable_t * join, myrow_t * key       );
myrow_t * mytable_upsert         ( mytable_t * join, myrow_t const * row );

int                      mytable_fwd_iter_done     ( mytable_fwd_iter_t iter );
ulong                    mytable_fwd_iter_idx      ( mytable_fwd_iter_t iter );
mytable_fwd_iter_t  mytable_fwd_iter_init     ( mytable_t * join, mytable_sort_key_t const * sort_key );
mytable_fwd_iter_t  mytable_fwd_iter_next     ( mytable_t * join, mytable_sort_key_t const * sort_key, mytable_fwd_iter_t iter );
myrow_t *       mytable_fwd_iter_row      ( mytable_t * join, mytable_sort_key_t const * sort_key, mytable_fwd_iter_t iter );
myrow_t const * mytable_fwd_iter_row_const( mytable_t * join, mytable_sort_key_t const * sort_key, mytable_fwd_iter_t iter );

ulong
mytable_align(void) {
  ulong a = alignof(mytable_t);
  ulong b = mytable_private_map_align();
  ulong c = mytable_private_pool_align();
  ulong d = mytable_private_treap_align();
  ulong e = fd_rng_align();
  ulong f = 128UL;
  return fd_ulong_max( a, fd_ulong_max( b, fd_ulong_max( c, fd_ulong_max( d, fd_ulong_max( e, f ) ) ) ) );
}

ulong mytable_footprint( ulong max_rows ) {
  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, alignof(mytable_t), sizeof(mytable_t) );
  l = FD_LAYOUT_APPEND( l, fd_rng_align(), fd_rng_footprint() );
  l = FD_LAYOUT_APPEND( l, mytable_private_map_align(), mytable_private_map_footprint( mytable_private_map_chain_cnt_est( max_rows ) ) );
  l = FD_LAYOUT_APPEND( l, mytable_private_pool_align(), mytable_private_pool_footprint( max_rows ) );
  for( ulong i = 0; i<LIVE_TABLE_MAX_SORT_KEY_CNT; i++ ) l = FD_LAYOUT_APPEND( l, mytable_private_treap_align(), mytable_private_treap_footprint( max_rows ) );
  return FD_LAYOUT_FINI( l, mytable_align() );
}

void *
mytable_new( void * shmem, ulong max_rows, ulong seed ) {
    if( !shmem ) {
    FD_LOG_WARNING(( "NULL shmem" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shmem, mytable_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned shmem" ));
    return NULL;
  }

  FD_SCRATCH_ALLOC_INIT( l, shmem );
  mytable_t * _table = FD_SCRATCH_ALLOC_APPEND( l, alignof(mytable_t), sizeof(mytable_t) );
  void * _rng = FD_SCRATCH_ALLOC_APPEND( l, fd_rng_align(), fd_rng_footprint() );
  void * _map = FD_SCRATCH_ALLOC_APPEND( l, mytable_private_map_align(), mytable_private_map_footprint( mytable_private_map_chain_cnt_est( max_rows ) ) );
  void * _pool = FD_SCRATCH_ALLOC_APPEND( l, mytable_private_pool_align(), mytable_private_pool_footprint( max_rows ) );
  for( ulong i = 0; i<LIVE_TABLE_MAX_SORT_KEY_CNT; i++ ) _table->treaps_shmem[ i ] = FD_SCRATCH_ALLOC_APPEND( l, mytable_private_treap_align(), mytable_private_treap_footprint( max_rows ) );
  FD_SCRATCH_ALLOC_FINI( l, mytable_align() );

  for( ulong i = 0; i<LIVE_TABLE_MAX_SORT_KEY_CNT; i++ ) _table->activity_timers[ i ] = ULONG_MAX;
  _table->max_rows = max_rows;

  _table->map  = mytable_private_map_new( _map, mytable_private_map_chain_cnt_est( max_rows ), seed );
  _table->pool = mytable_private_pool_new( _pool, max_rows );
  _table->rng  = fd_rng_new( _rng, (uint)seed, 0UL );
  /* live_table_treap_new( ... ) not called since all treaps start as inactive */

  return _table;
}

mytable_t *
mytable_join( void * shtable ) {
  mytable_t * _table = (mytable_t *)shtable;

  _table->map = mytable_private_map_join( _table->map );
  _table->pool = mytable_private_pool_join( _table->pool );
  _table->rng  = fd_rng_join( _table->rng );

  return _table;
}

void *
mytable_leave( mytable_t * join ) {
  if( FD_UNLIKELY( !join ) ) {
  FD_LOG_WARNING(( "NULL join" ));
  return NULL;
  }

  mytable_private_map_leave( join->map );
  mytable_private_pool_leave( join->pool );
  for( ulong i = 0; i<LIVE_TABLE_MAX_SORT_KEY_CNT; i++ ) {
    if( FD_LIKELY( join->activity_timers[ i ] == ULONG_MAX ) ) continue;
    mytable_private_active_sort_key_idx = i;
    mytable_private_treap_leave( join->treaps[ i ] );
  }

  return (void *)join;
}

void *
mytable_delete( void * shtable ) {
  mytable_t * table = (mytable_t *)shtable;

  if( FD_UNLIKELY( !table ) ) {
  FD_LOG_WARNING(( "NULL shtable" ));
  return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)table, alignof(mytable_t) ) ) ) {
  FD_LOG_WARNING(( "misaligned shtable" ));
  return NULL;
  }

  mytable_private_map_delete( table->map );
  mytable_private_pool_delete( table->pool );
  for( ulong i = 0; i<LIVE_TABLE_MAX_SORT_KEY_CNT; i++ ) {
    if( FD_LIKELY( table->activity_timers[ i ] == ULONG_MAX ) ) continue;
    mytable_private_active_sort_key_idx = i;
    mytable_private_treap_delete( table->treaps[ i ] );
  }

  return (void *)table;
}

ulong
mytable__max_rows( mytable_t * join ) {
  return join->max_rows;
}

void
mytable_remove( mytable_t * join, myrow_t * row ) {
  ulong pool_idx = mytable_private_map_idx_query_const( join->map, row, ULONG_MAX, join->pool);
  if( FD_UNLIKELY( ULONG_MAX==pool_idx ) ) return;

  for( ulong i = 0; i<LIVE_TABLE_MAX_SORT_KEY_CNT; i++ ) {
    if( FD_LIKELY( join->activity_timers[ i ] == ULONG_MAX ) ) continue;
    mytable_private_active_sort_key_idx = i;
    mytable_private_treap_idx_remove( join->treaps[ i ], pool_idx, join->pool );
  }
  mytable_private_map_idx_remove(join->map, row, ULONG_MAX, join->pool);
  mytable_private_pool_idx_release(join->pool, pool_idx);
}

myrow_t *
mytable_upsert( mytable_t * join, myrow_t const * row ) {
  /* get idx into join->pool for this row */
  ulong pool_idx = mytable_private_map_idx_query_const( join->map, row, ULONG_MAX, join->pool);
  mytable_private_pool_ele_t * ele;
  if( FD_LIKELY( pool_idx == ULONG_MAX ) ) {
    /* acquire new pool element */
    pool_idx = mytable_private_pool_idx_acquire( join->pool );

    ele = mytable_private_pool_ele(join->pool, pool_idx);

    /* algorithmic costs for a treap assume priorities are random */
    for( ulong i=0UL; i<LIVE_TABLE_MAX_SORT_KEY_CNT; i++ ) ele->treap_prio[ i ] = fd_rng_ulong( join->rng );

    /* update the row */
    memcpy( &ele->row, row, sizeof(myrow_t) );

    mytable_private_map_idx_insert(join->map, pool_idx, join->pool);
  } else {
    /* first remove row from all treaps */
    for( ulong i = 0; i<LIVE_TABLE_MAX_SORT_KEY_CNT; i++ ) {
      if( FD_LIKELY( join->activity_timers[ i ] == ULONG_MAX ) ) continue;
      mytable_private_active_sort_key_idx = i;
      mytable_private_treap_idx_remove( join->treaps[ i ], pool_idx, join->pool );
    }

    /* update the row */
    ele = mytable_private_pool_ele(join->pool, pool_idx);
    memcpy( &ele->row, row, sizeof(myrow_t) );
  }

  /* insert into all active treaps */
  for( ulong i = 0; i<LIVE_TABLE_MAX_SORT_KEY_CNT; i++ ) {
    if( FD_LIKELY( join->activity_timers[ i ] == ULONG_MAX ) ) continue;
    mytable_private_active_sort_key_idx = i;
    mytable_private_treap_idx_insert(join->treaps[i], pool_idx, join->pool);
    join->activity_timers[ i ] = (ulong)fd_tickcount();
  }

  return &ele->row;
}

static void
mytable_private_sort_key_delete( mytable_t * join, ulong sort_key_idx ) {
  FD_TEST( sort_key_idx<LIVE_TABLE_MAX_SORT_KEY_CNT );
  mytable_private_active_sort_key_idx = sort_key_idx;
  mytable_private_treap_leave( join->treaps[ sort_key_idx ] );
  mytable_private_treap_delete( join->treaps[ sort_key_idx ] );
  join->treaps[ sort_key_idx ] = NULL;
  join->activity_timers[ sort_key_idx ] = ULONG_MAX;
}

static void
mytable_private_sort_key_create( mytable_t * join, ulong sort_key_idx, mytable_sort_key_t const * sort_key ) {
  // FD_LOG_WARNING(("private_sort_key_create sort_key_idx %lu", sort_key_idx));
  FD_TEST( sort_key_idx<LIVE_TABLE_MAX_SORT_KEY_CNT );
  mytable_private_sort_keys[ sort_key_idx ] = *sort_key;
  mytable_private_active_sort_key_idx = sort_key_idx;
  join->treaps[ sort_key_idx ] = mytable_private_treap_join( mytable_private_treap_new( join->treaps_shmem[ sort_key_idx ], join->max_rows ) );
  FD_TEST( join->treaps[ sort_key_idx ] );

  /* loop through the rows and insert them all into the treap */
  for( mytable_private_map_iter_t iter = mytable_private_map_iter_init( join->map, join->pool );
        !mytable_private_map_iter_done( iter, join->map, join->pool );
        iter = mytable_private_map_iter_next( iter, join->map, join->pool ) ) {
    ulong pool_idx = mytable_private_map_iter_idx( iter, join->map, join->pool );
    mytable_private_treap_idx_insert( join->treaps[ sort_key_idx ], pool_idx, join->pool );
  }
  join->activity_timers[ sort_key_idx ] = (ulong)fd_tickcount();
}

static ulong
mytable_private_query_sort_key( mytable_t * join, mytable_sort_key_t const * sort_key ) {
  /* look for a matching sort key. todo ... look for exact match ignoring null cols */
  for( ulong i = 0; i<LIVE_TABLE_MAX_SORT_KEY_CNT; i++ ) {
    if( FD_UNLIKELY( join->activity_timers[ i ] == ULONG_MAX ) ) continue;
    int equal = 1;
    for( ulong j=0UL; j<LIVE_TABLE_COLUMN_CNT; j++ ) {
      FD_TEST( sort_key->col[ j ] <= LIVE_TABLE_COLUMN_CNT );
      if( FD_LIKELY( mytable_private_sort_keys[ i ].col[ j ] != sort_key->col[ j ] || mytable_private_sort_keys[ i ].dir[ j ] != sort_key->dir[ j ] ) ) {
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
mytable_private_query_or_add_sort_key( mytable_t * join, mytable_sort_key_t const * sort_key ) {
  ulong sort_key_idx = mytable_private_query_sort_key( join, sort_key );
  if( FD_LIKELY( sort_key_idx!=ULONG_MAX ) ) return sort_key_idx;

  /* look for an inactive sort key */
  for( ulong i=0UL; i<LIVE_TABLE_MAX_SORT_KEY_CNT; i++ ) {
    if( FD_LIKELY( join->activity_timers[ i ]==ULONG_MAX ) ) {
      mytable_private_sort_key_create( join, i, sort_key );
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

  mytable_private_active_sort_key_idx = oldest_timer_idx;
  mytable_private_sort_key_delete( join, oldest_timer_idx );
  mytable_private_sort_key_create( join, oldest_timer_idx, sort_key );

  return oldest_timer_idx;
}

void
mytable_remove_sort_key( mytable_t * join, mytable_sort_key_t const * sort_key ) {
  ulong sort_key_idx = mytable_private_query_sort_key( join, sort_key );
  if( FD_LIKELY( sort_key_idx==ULONG_MAX ) ) return;
  mytable_private_sort_key_delete( join, sort_key_idx );
}


int
mytable_fwd_iter_done( mytable_fwd_iter_t iter ) {
  return mytable_private_treap_fwd_iter_done( iter );
}

ulong
mytable_fwd_iter_idx( mytable_fwd_iter_t iter ) {
  return mytable_private_treap_fwd_iter_idx( iter );
}

mytable_fwd_iter_t
mytable_fwd_iter_init( mytable_t * join, mytable_sort_key_t const * sort_key ) {
  ulong sort_key_idx = mytable_private_query_or_add_sort_key( join, sort_key );
  // FD_LOG_INFO(("live_table_fwd_iter_init sort_key_idx=%lu", sort_key_idx));
  mytable_private_active_sort_key_idx = sort_key_idx;
  return mytable_private_treap_fwd_iter_init( join->treaps[ sort_key_idx ], join->pool );
}

mytable_fwd_iter_t
mytable_fwd_iter_next( mytable_t * join, mytable_sort_key_t const * sort_key, mytable_fwd_iter_t iter ) {
  ulong sort_key_idx = mytable_private_query_sort_key( join, sort_key );
  // FD_LOG_INFO(("live_table_fwd_iter_next sort_key_idx=%lu", sort_key_idx));
  mytable_private_active_sort_key_idx = sort_key_idx;
  return mytable_private_treap_fwd_iter_next( iter, join->pool );
}

myrow_t *
mytable_fwd_iter_row( mytable_t * join, mytable_sort_key_t const * sort_key, mytable_fwd_iter_t iter ) {
  ulong sort_key_idx = mytable_private_query_sort_key( join, sort_key );
  // FD_LOG_INFO(("live_table_fwd_iter_row sort_key_idx=%lu", sort_key_idx));
  mytable_private_active_sort_key_idx = sort_key_idx;
  return &mytable_private_treap_fwd_iter_ele( iter, join->pool )->row;
}

myrow_t const *
mytable_fwd_iter_row_const( mytable_t * join, mytable_sort_key_t const * sort_key, mytable_fwd_iter_t iter ) {
  ulong sort_key_idx = mytable_private_query_sort_key( join, sort_key );
  // FD_LOG_INFO(("live_table_fwd_iter_init sort_key_idx=%lu", sort_key_idx));
  mytable_private_active_sort_key_idx = sort_key_idx;
  return &mytable_private_treap_fwd_iter_ele( iter, join->pool )->row;
}

int
mytable_sort_dir_null() {
  return PRIVATE_LIVE_TABLE_SORT_DIR_NULL;
}

int
mytable_sort_dir_asc() {
  return PRIVATE_LIVE_TABLE_SORT_DIR_ASC;
}

int
mytable_sort_dir_desc() {
  return PRIVATE_LIVE_TABLE_SORT_DIR_DESC;
}

#undef LIVE_TABLE_NAME
#undef PRIVATE_LIVE_TABLE_SORT_DIR_NULL
#undef PRIVATE_LIVE_TABLE_SORT_DIR_ASC
#undef PRIVATE_LIVE_TABLE_SORT_DIR_DESC
#undef LIVE_TABLE_COLUMN_CNT
#undef LIVE_TABLE_MAX_SORT_KEY_CNT
#undef myrow_t
#undef LIVE_TABLE_COLUMNS
#undef LIVE_TABLE_COL_ENTRY
#undef LIVE_TABLE_COL_ARRAY
