
#ifndef HEADER_fd_src_disco_gui_fd_gui_live_table_h
#define HEADER_fd_src_disco_gui_fd_gui_live_table_h

#include "../fd_disco.h"
#include "../../util/log/fd_log.h"
#include "../../util/bits/fd_bits.h"


#define FD_LIVE_TABLE_SORT_DIR_NULL (0UL)
#define FD_LIVE_TABLE_SORT_DIR_ASC  (1UL)
#define FD_LIVE_TABLE_SORT_DIR_DESC (2UL)

#define FD_LIVE_TABLE_COLUMN_CNT (2UL)
#define FD_LIVE_TABLE_MAX_SORT_KEY_CNT (1024UL)

static int live_table_col_pubkey_cmp( void * a, void * b ) { return memcmp( (fd_pubkey_t *)a, (fd_pubkey_t *)b, 32UL ); }
static int live_table_col_ipv4_cmp( void * a, void * b ) { return (int)((*(uint *)a) - (*(uint *)b)); }
static ulong live_table_col_pubkey_hash( void * key ) { return fd_ulong_hash( *(ulong *)key ); }
static ulong live_table_col_ipv4_hash( void * key ) { return fd_ulong_hash( ((fd_pubkey_t *)key)->ul[ 0UL ] ); }

struct live_table_col {
  ulong col_idx;
  ulong row_offset;
  ulong key_offset;
  int is_primary;
  int (*cmp)(void * a, void * b);
  ulong (*hash)(void * key);
};
typedef struct live_table_col live_table_col_t;

struct live_table_sort_key {
  ulong col[ FD_LIVE_TABLE_COLUMN_CNT ];
  int dir[ FD_LIVE_TABLE_COLUMN_CNT ];
};
typedef struct live_table_sort_key live_table_sort_key_t;

struct live_table_row_primary_key{
  fd_pubkey_t pubkey;
};
typedef struct live_table_row_primary_key live_table_row_primary_key_t;

struct live_table_row {
  ulong pool_next;
  ulong map_next;
  ulong map_prev;

  live_table_row_primary_key_t key;
  uint ipv4;
};
typedef struct live_table_row live_table_row_t; 

#define POOL_NAME live_table_pool
#define POOL_T    live_table_row_t
#define POOL_NEXT pool_next
#include "../../util/tmpl/fd_pool.c"


static live_table_col_t const live_table_cols[] = {
  { .row_offset = offsetof(live_table_row_t, key.pubkey), .cmp = live_table_col_pubkey_cmp, .hash = live_table_col_pubkey_hash, .is_primary = 1, .key_offset = offsetof(live_table_row_primary_key_t, pubkey) },
  { .row_offset = offsetof(live_table_row_t, ipv4), .cmp = live_table_col_ipv4_cmp, .hash = live_table_col_ipv4_hash, .is_primary = 0, .key_offset = 0UL },
};

static int
_live_table_key_eq(live_table_row_primary_key_t const * a, live_table_row_primary_key_t const * b) {
  for( ulong i = 0; i < FD_LIVE_TABLE_COLUMN_CNT; i++ ) {
    if( FD_UNLIKELY( !live_table_cols[ i ].is_primary ) ) continue;
    int cmp = live_table_cols[ i ].cmp( (uchar *)(&a) + live_table_cols[ i ].key_offset, (uchar *)(&b) + live_table_cols[ i ].key_offset );
    if( FD_UNLIKELY( cmp != 0 ) ) return 0;
  }
  return 1;
}

static ulong
_live_table_key_hash(live_table_row_primary_key_t const * key) {
  ulong hash = 0UL;
  for( ulong i = 0; i < FD_LIVE_TABLE_COLUMN_CNT; i++ ) {
    hash = hash ^ live_table_cols[ i ].hash( (uchar *)(&key) + live_table_cols[ i ].key_offset );
  }
  return hash;
}

#define MAP_NAME   live_table_map
#define MAP_ELE_T  live_table_row_t
#define MAP_KEY_T  live_table_row_primary_key_t
#define MAP_KEY_EQ(a, b) _live_table_key_eq( (a), (b) )
#define MAP_KEY_HASH(key,seed) fd_ulong_hash( _live_table_key_hash( (key) ) ^ (seed) )
#define MAP_OPTIMIZE_RANDOM_ACCESS_REMOVAL 1
#define MAP_NEXT  map_next
#define MAP_PREV  map_prev
#include "../../util/tmpl/fd_map_chain.c"

/* global state is ugly. We only have one type of treap and they all
   share the same static comparison function, but we need that function to
   change dynamically.  The simplest way to do this is to have the function
   reference changing global state.  Not ideal but the alternative is to change
   the implementation of the treap template */
static live_table_sort_key_t live_table_sort_keys[ FD_LIVE_TABLE_MAX_SORT_KEY_CNT ] = { 0UL };
static ulong live_table_active_sort_key_idx = ULONG_MAX;
static live_table_row_t * live_table_map_pool = NULL;

static int
_live_table_row_cmp(ulong const a, ulong const b) {
  FD_TEST( live_table_map_pool );
  FD_TEST( live_table_active_sort_key_idx < FD_LIVE_TABLE_MAX_SORT_KEY_CNT );
  for( ulong col = 0UL; col < FD_LIVE_TABLE_COLUMN_CNT; col++ ) {
    ulong sort_col = live_table_sort_keys[ live_table_active_sort_key_idx ].col[ col ];
    if( FD_LIKELY( live_table_sort_keys[ live_table_active_sort_key_idx ].dir[ sort_col ]==FD_LIVE_TABLE_SORT_DIR_NULL ) ) continue;
    void * col_a = ((uchar *)live_table_pool_ele( live_table_map_pool, a )) + live_table_cols[ sort_col ].row_offset;
    void * col_b = ((uchar *)live_table_pool_ele( live_table_map_pool, b )) + live_table_cols[ sort_col ].row_offset;
    int res = live_table_cols[ sort_col ].cmp(col_a, col_b);
    if( FD_UNLIKELY( !res ) ) continue;

    if( FD_LIKELY( live_table_sort_keys[ live_table_active_sort_key_idx ].dir[ sort_col ]==FD_LIVE_TABLE_SORT_DIR_DESC ) ) {
      return -res;
    } else if( FD_LIKELY( live_table_sort_keys[ live_table_active_sort_key_idx ].dir[ sort_col ]==FD_LIVE_TABLE_SORT_DIR_ASC ) ) {
      return res;
    } else {
      FD_LOG_ERR(( "unexpected sort dir %d", live_table_sort_keys[ live_table_active_sort_key_idx ].dir[ sort_col ] ));
    }
  }
  return 0;
}

struct live_table_treap_ele {
  ulong treap_parent;
  ulong treap_left;
  ulong treap_right;
  ulong treap_prio;
  ulong treap_next;
  ulong treap_prev;
  ulong pool_next;

  ulong key;
};
typedef struct live_table_treap_ele live_table_treap_ele_t;

#define POOL_NAME live_table_treap_pool
#define POOL_T    live_table_treap_ele_t
#define POOL_NEXT pool_next
#include "../../util/tmpl/fd_pool.c"

#define TREAP_NAME      live_table_treap
#define TREAP_T         live_table_treap_ele_t
#define TREAP_QUERY_T   ulong
#define TREAP_CMP(q,e)  (_live_table_row_cmp( (q), (e->key) ))
#define TREAP_LT(e0,e1) (_live_table_row_cmp( (e0->key), (e1->key) ) < 0)
#define TREAP_OPTIMIZE_ITERATION 1
#define TREAP_PARENT treap_parent
#define TREAP_LEFT treap_left
#define TREAP_RIGHT treap_right
#define TREAP_NEXT treap_next
#define TREAP_PREV treap_prev
#define TREAP_PRIO treap_prio
#include "../../util/tmpl/fd_treap.c"

struct live_table {
  live_table_row_t * map_pool;
  live_table_treap_ele_t * sort_pool;
  live_table_map_t * map;
  live_table_treap_t * treaps[ FD_LIVE_TABLE_MAX_SORT_KEY_CNT ];
  void * treaps_shmem[ FD_LIVE_TABLE_MAX_SORT_KEY_CNT ];
  ulong activity_timers[ FD_LIVE_TABLE_MAX_SORT_KEY_CNT ]; /* ULONG_MAX if treap is inactive, nanos UNIX timestamp of last iter */

  ulong max_rows;
};
typedef struct live_table live_table_t;

typedef live_table_treap_fwd_iter_t live_table_fwd_iter_t;

ulong          live_table_align    ( void                                     );
ulong          live_table_footprint( ulong rows_max                           );
void      *    live_table_new      ( void * shmem, ulong rows_max, ulong seed );
live_table_t * live_table_join     ( void * shtable                           );
void      *    live_table_leave    ( live_table_t * join                      );
void      *    live_table_delete   ( void * shtable                           );

void live_table_remove( live_table_t * join, live_table_row_primary_key_t * key );
live_table_row_t * live_table_upsert( live_table_t * join, live_table_row_t const * row );

int                      live_table_fwd_iter_done     ( live_table_fwd_iter_t iter );
ulong                    live_table_fwd_iter_idx      ( live_table_fwd_iter_t iter );
live_table_fwd_iter_t    live_table_fwd_iter_init     ( live_table_t * join, live_table_sort_key_t const * sort_key );
live_table_fwd_iter_t    live_table_fwd_iter_next     ( live_table_t const * join, live_table_sort_key_t const * sort_key, live_table_fwd_iter_t iter );
live_table_row_t *       live_table_fwd_iter_row      ( live_table_t const * join, live_table_sort_key_t const * sort_key, live_table_fwd_iter_t iter );
live_table_row_t const * live_table_fwd_iter_row_const( live_table_t const * join, live_table_sort_key_t const * sort_key, live_table_fwd_iter_t iter );

#endif /* HEADER_fd_src_disco_gui_fd_gui_live_table_h */
