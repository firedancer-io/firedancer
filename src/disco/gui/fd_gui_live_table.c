
#include "fd_gui_live_table.h"

ulong live_table_align(void) {
  ulong a = alignof(live_table_t);
  ulong b = live_table_pool_align();
  ulong c = live_table_pool_align();
  ulong d = live_table_treap_align();
  ulong e = 128UL;
  return fd_ulong_max(a, fd_ulong_max(b, fd_ulong_max(c, fd_ulong_max(d, e))));
}

ulong live_table_footprint( ulong max_rows ) {
  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND(l, alignof(live_table_t), sizeof(alignof(live_table_t)));
  l = FD_LAYOUT_APPEND(l, live_table_map_align(), live_table_map_footprint( live_table_map_chain_cnt_est( max_rows ) ));
  l = FD_LAYOUT_APPEND( l, live_table_pool_align(), live_table_pool_footprint( max_rows ) );
  l = FD_LAYOUT_APPEND( l, live_table_treap_pool_align(), live_table_treap_pool_footprint( max_rows * FD_LIVE_TABLE_MAX_SORT_KEY_CNT ) );
  for( ulong i = 0; i<FD_LIVE_TABLE_MAX_SORT_KEY_CNT; i++ ) l = FD_LAYOUT_APPEND( l, live_table_treap_align(), live_table_treap_footprint( max_rows ) );
  return FD_LAYOUT_FINI( l, live_table_align() );
}

void *
live_table_new( void * shmem, ulong max_rows, ulong seed ) {
  FD_SCRATCH_ALLOC_INIT( l, shmem );
  live_table_t * _table = FD_SCRATCH_ALLOC_APPEND(l, alignof(live_table_t), sizeof(live_table_t));
  void * _map = FD_SCRATCH_ALLOC_APPEND(l, live_table_map_align(), live_table_map_footprint( live_table_map_chain_cnt_est( max_rows ) ));
  void * _map_pool = FD_SCRATCH_ALLOC_APPEND( l, live_table_pool_align(), live_table_pool_footprint( max_rows ) );
  void * _sort_pool = FD_SCRATCH_ALLOC_APPEND( l, live_table_treap_pool_align(), live_table_treap_pool_footprint( max_rows * FD_LIVE_TABLE_MAX_SORT_KEY_CNT ) );
  for( ulong i = 0; i<FD_LIVE_TABLE_MAX_SORT_KEY_CNT; i++ ) _table->treaps_shmem[ i ] = FD_SCRATCH_ALLOC_APPEND( l, live_table_treap_align(), live_table_treap_footprint( max_rows ) );
  FD_SCRATCH_ALLOC_FINI( l, live_table_align() );

  _table->map = _map;
  _table->map_pool = _map_pool;
  _table->sort_pool = _sort_pool;
  _table->max_rows = max_rows;

  for( ulong i = 0; i<FD_LIVE_TABLE_MAX_SORT_KEY_CNT; i++ ) _table->activity_timers[ i ] = ULONG_MAX;

  live_table_map_new( _table->map, live_table_map_chain_cnt_est( max_rows ), seed );
  live_table_pool_new( _table->map_pool, max_rows );
  live_table_treap_pool_new( _table->sort_pool, max_rows );
  /* live_table_treap_new( ... ) not called since all treaps start as inactive */

  return _table;
}

live_table_t *
live_table_join( void * shtable ) {
  live_table_t * _table = (live_table_t *)shtable;

  _table->map = live_table_map_join( _table->map );
  _table->map_pool = live_table_pool_join( _table->map_pool );
  _table->sort_pool = live_table_treap_pool_join( _table->sort_pool );

  live_table_map_pool = _table->map_pool;
  return _table;
}

void *
live_table_leave( live_table_t * join ) {
  if( FD_UNLIKELY( !join ) ) {
  FD_LOG_WARNING(( "NULL join" ));
  return NULL;
  }

  live_table_map_leave( join->map );
  live_table_pool_leave( join->map_pool );
  for( ulong i = 0; i<FD_LIVE_TABLE_MAX_SORT_KEY_CNT; i++ ) {
    if( FD_LIKELY( join->activity_timers[ i ] == ULONG_MAX ) ) continue;
    live_table_active_sort_key_idx = i;
    live_table_treap_leave( join->treaps[i] );
  }
  live_table_treap_pool_leave( join->sort_pool );

  return (void *)join;
}

void *
live_table_delete( void * shtable ) {
  live_table_t * table = (live_table_t *)shtable;

  if( FD_UNLIKELY( !table ) ) {
  FD_LOG_WARNING(( "NULL shtable" ));
  return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)table, alignof(live_table_t) ) ) ) {
  FD_LOG_WARNING(( "misaligned shtable" ));
  return NULL;
  }

  live_table_map_delete( table->map );
  live_table_pool_delete( table->map_pool );
  for( ulong i = 0; i<FD_LIVE_TABLE_MAX_SORT_KEY_CNT; i++ ) {
    if( FD_LIKELY( table->activity_timers[ i ] == ULONG_MAX ) ) continue;
    live_table_active_sort_key_idx = i;
    live_table_treap_delete( table->treaps[ i ] );
  }
  live_table_pool_delete( table->sort_pool );

  return (void *)table;
}

void
live_table_remove( live_table_t * join, live_table_row_primary_key_t * key ) {
  ulong pool_idx = live_table_map_idx_query_const( join->map, key, ULONG_MAX, join->map_pool);
  if( FD_UNLIKELY( ULONG_MAX==pool_idx ) ) return;

  for( ulong i = 0; i<FD_LIVE_TABLE_MAX_SORT_KEY_CNT; i++ ) {
    if( FD_LIKELY( join->activity_timers[ i ] == ULONG_MAX ) ) continue;
    live_table_active_sort_key_idx = i;
    ulong sort_pool_idx = live_table_treap_idx_query( join->treaps[ i ], pool_idx, join->sort_pool );
    live_table_treap_idx_remove( join->treaps[ i ], sort_pool_idx, join->sort_pool );
    live_table_treap_pool_idx_release(join->sort_pool, sort_pool_idx);
  }
  live_table_map_idx_remove(join->map, key, ULONG_MAX, join->map_pool);
  live_table_pool_idx_release(join->map_pool, pool_idx);
}

live_table_row_t *
live_table_upsert( live_table_t * join, live_table_row_t const * row ) {
  /* get idx into join->pool for this row */
  ulong map_pool_idx = live_table_map_idx_query_const( join->map, &row->key, ULONG_MAX, join->map_pool);
  if( FD_LIKELY( map_pool_idx == ULONG_MAX ) ) {
    map_pool_idx = live_table_pool_idx_acquire( join->map_pool );
    live_table_map_idx_insert(join->map, map_pool_idx, join->map_pool);
  } else {
    /* first remove row from all treaps */
    for( ulong i = 0; i<FD_LIVE_TABLE_MAX_SORT_KEY_CNT; i++ ) {
      if( FD_LIKELY( join->activity_timers[ i ] == ULONG_MAX ) ) continue;
      live_table_active_sort_key_idx = i;
      ulong sort_pool_idx = live_table_treap_idx_query( join->treaps[ i ], map_pool_idx, join->sort_pool );
      live_table_treap_idx_remove( join->treaps[ i ], sort_pool_idx, join->sort_pool );
    }
  }

  /* update row without clobbering map metadata */
  live_table_row_t * ele = live_table_pool_ele(join->map_pool, map_pool_idx);
  ulong pool_next = ele->pool_next; ulong map_next = ele->map_next;
  fd_memcpy(ele, row, sizeof(live_table_row_t));
  ele->map_next = map_next;
  ele->pool_next = pool_next;

  /* insert into all active treaps */
  for( ulong i = 0; i<FD_LIVE_TABLE_MAX_SORT_KEY_CNT; i++ ) {
    if( FD_LIKELY( join->activity_timers[ i ] == ULONG_MAX ) ) continue;
    live_table_active_sort_key_idx = i;
    ulong sort_pool_idx = live_table_treap_idx_query( join->treaps[ i ], map_pool_idx, join->sort_pool );
    live_table_treap_idx_insert(join->treaps[i], sort_pool_idx, join->sort_pool);
  }

  return ele;
}

static ulong
live_table_query_sort_key( live_table_t const * join, live_table_sort_key_t const * sort_key ) {
  /* look for a matching sort key */
  for( ulong i = 0; i<FD_LIVE_TABLE_MAX_SORT_KEY_CNT; i++ ) {
    if( FD_UNLIKELY( join->activity_timers[ i ] == ULONG_MAX ) ) continue;
    int equal = 1;
    for( ulong j=0UL; j<FD_LIVE_TABLE_COLUMN_CNT; j++ ) {
      FD_TEST( sort_key->col[ j ] <= FD_LIVE_TABLE_COLUMN_CNT );
      if( FD_LIKELY( live_table_sort_keys[ i ].col[ j ] != sort_key->col[ j ] || live_table_sort_keys[ i ].dir[ j ] != sort_key->dir[ j ] ) ) {
        equal = 0;
        break;
      }
    }
    if( FD_LIKELY( !equal ) ) continue;
    return i;
  }

  return ULONG_MAX;
}

static void
live_table_sort_key_delete( live_table_t * join, ulong sort_key_idx ) {
  live_table_active_sort_key_idx = sort_key_idx;
  /* release pool elements */
  for( live_table_treap_fwd_iter_t iter = live_table_treap_fwd_iter_init( join->treaps[ sort_key_idx ], join->sort_pool );
      !live_table_treap_fwd_iter_done( iter );
      iter = live_table_treap_fwd_iter_next( iter, join->sort_pool ) ) {
    ulong sort_pool_idx = live_table_treap_fwd_iter_idx( iter );

    /* fix me. while functional, this is wrong, because we're releasing the underlying pool memory before removing the element from the treap */
    live_table_treap_pool_idx_release( join->sort_pool, sort_pool_idx );
  }

  live_table_treap_leave( join->treaps[ sort_key_idx ] );
  live_table_treap_delete( join->treaps[ sort_key_idx ] );
  join->treaps[ sort_key_idx ] = NULL;
}

static void
live_table_sort_key_create( live_table_t * join, ulong sort_key_idx, live_table_sort_key_t const * sort_key ) {
  live_table_active_sort_key_idx = sort_key_idx;
  live_table_sort_keys[ live_table_active_sort_key_idx ] = *sort_key;

  join->treaps[ sort_key_idx ] = live_table_treap_join( live_table_treap_new( join->treaps_shmem[ sort_key_idx ], join->max_rows ) );

  /* loop through the rows and insert them all into the treap */
  for( live_table_map_iter_t iter = live_table_map_iter_init( join->map, join->map_pool );
        !live_table_map_iter_done( iter, join->map, join->map_pool );
        iter = live_table_map_iter_next( iter, join->map, join->map_pool ) ) {
    ulong ele_idx = live_table_map_iter_idx( iter, join->map, join->map_pool );

    /* Add to treap pool */
    ulong sort_pool_idx = live_table_treap_pool_idx_acquire( join->sort_pool );
    live_table_treap_ele_t * ele = live_table_treap_pool_ele( join->sort_pool, sort_pool_idx );
    ele->treap_prio = ele_idx; /* todo ... use rng */
    ele->key = ele_idx;

    /* Add to treap */
    live_table_treap_idx_insert( join->treaps[ sort_key_idx ], sort_pool_idx, join->sort_pool );
  }
}

static ulong
live_table_query_or_add_sort_key( live_table_t * join, live_table_sort_key_t const * sort_key ) {
  ulong sort_key_idx = live_table_query_sort_key( join, sort_key );
  if( FD_LIKELY( sort_key_idx!=ULONG_MAX ) ) return sort_key_idx;

  /* look for an inactive sort key */
  for( ulong i=0UL; i<FD_LIVE_TABLE_MAX_SORT_KEY_CNT; i++ ) {
    if( FD_LIKELY( join->activity_timers[ i ]==ULONG_MAX ) ) {
      live_table_active_sort_key_idx = i;
      live_table_sort_key_create( join, i, sort_key );
      FD_LOG_WARNING(("inactive_idx=%lu max_rows=%lu", i, join->max_rows));
      return i;
    }
  }

  /* evict the oldest sort key */
  ulong oldest_timer_val = ULONG_MAX;
  ulong oldest_timer_idx = ULONG_MAX;
  for( ulong i=0UL; i<FD_LIVE_TABLE_MAX_SORT_KEY_CNT; i++ ) {
    if( FD_UNLIKELY( oldest_timer_val < join->activity_timers[ i ] ) ) {
      oldest_timer_val = join->activity_timers[ i ];
      oldest_timer_idx = i;
    }
  }

  if( FD_UNLIKELY( oldest_timer_idx==ULONG_MAX ) ) return ULONG_MAX;

  live_table_active_sort_key_idx = oldest_timer_idx;
  live_table_sort_key_delete( join, oldest_timer_idx );
  live_table_sort_key_create( join, oldest_timer_idx, sort_key );

  return oldest_timer_idx;
}


int live_table_fwd_iter_done( live_table_fwd_iter_t iter ) {
  return live_table_treap_fwd_iter_done( iter );
}

ulong
live_table_fwd_iter_idx( live_table_fwd_iter_t iter ) {
  return live_table_treap_fwd_iter_idx( iter );
}

live_table_fwd_iter_t
live_table_fwd_iter_init( live_table_t * join, live_table_sort_key_t const * sort_key ) {
  ulong sort_key_idx = live_table_query_or_add_sort_key( join, sort_key );
  FD_LOG_WARNING(("sort_key_idx=%lu null_idx=%lu", sort_key_idx, live_table_treap_pool_idx_null( join->sort_pool )));
  if( FD_UNLIKELY( sort_key_idx==live_table_treap_pool_idx_null( join->sort_pool ) ) ) return live_table_treap_idx_null();
  live_table_active_sort_key_idx = sort_key_idx;
  return live_table_treap_fwd_iter_init( join->treaps[ sort_key_idx ], join->sort_pool );
}

live_table_fwd_iter_t
live_table_fwd_iter_next( live_table_t const * join, live_table_sort_key_t const * sort_key, live_table_fwd_iter_t iter ) {
  ulong sort_key_idx = live_table_query_sort_key( join, sort_key );
  live_table_active_sort_key_idx = sort_key_idx;
  return live_table_treap_fwd_iter_next( iter, join->sort_pool );
}

live_table_row_t *
live_table_fwd_iter_row( live_table_t const * join, live_table_sort_key_t const * sort_key, live_table_fwd_iter_t iter ) {
  ulong sort_key_idx = live_table_query_sort_key( join, sort_key );
  live_table_active_sort_key_idx = sort_key_idx;
  ulong row_idx = live_table_treap_fwd_iter_ele( iter, join->sort_pool )->key;
  return live_table_pool_ele( join->map_pool, row_idx );
}

live_table_row_t const *
live_table_fwd_iter_row_const( live_table_t const * join, live_table_sort_key_t const * sort_key, live_table_fwd_iter_t iter ) {
  ulong sort_key_idx = live_table_query_sort_key( join, sort_key );
  live_table_active_sort_key_idx = sort_key_idx;
  ulong row_idx = live_table_treap_fwd_iter_ele( iter, join->sort_pool )->key;
  return live_table_pool_ele_const( join->map_pool, row_idx );
}