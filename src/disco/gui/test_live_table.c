#include "fd_gui_live_table.h"

#define TEST_LIVE_TABLE_ROW_CNT (10000UL)

uchar scratch[ 656106880 ];

int
main( int argc, char ** argv ) {
  (void)argc; (void)argv;
  FD_LOG_NOTICE(("BEGIN TEST"));

  FD_TEST( sizeof(scratch)==live_table_footprint( TEST_LIVE_TABLE_ROW_CNT ) );

  live_table_t * table = live_table_join( live_table_new( scratch, TEST_LIVE_TABLE_ROW_CNT, 42UL ) );

  live_table_row_t r0 = { .key = { .pubkey = { .uc = { 1UL } } }, .ipv4 = 1 };
  live_table_row_t r1 = { .key = { .pubkey = { .uc = { 0UL } } }, .ipv4 = 0 };
  live_table_row_t r2 = { .key = { .pubkey = { .uc = { 2UL } } }, .ipv4 = 2 };
  live_table_row_t r3 = { .key = { .pubkey = { .uc = { 3UL } } }, .ipv4 = 3 };
  live_table_upsert( table, &r0 );
  live_table_upsert( table, &r1 );
  live_table_upsert( table, &r2 );

  live_table_sort_key_t const key0 = { .col = { 0, 1 }, .dir =  { FD_LIVE_TABLE_SORT_DIR_NULL, FD_LIVE_TABLE_SORT_DIR_ASC } };

  // /* loop through the contents of the map */
  // FD_LOG_WARNING(("LOOP THROUGH MAP"));
  // for( live_table_map_iter_t iter = live_table_map_iter_init( table->map, table->map_pool );
  //       !live_table_map_iter_done( iter, table->map, table->map_pool );
  //       iter = live_table_map_iter_next( iter, table->map, table->map_pool ) ) {
  //   ulong ele_idx = live_table_map_iter_idx( iter, table->map, table->map_pool );
  //   live_table_row_t * row = live_table_pool_ele( table->map_pool, ele_idx );
  //   FD_LOG_WARNING(("ele_idx=%lu pubkey=%lu ip=%u", ele_idx, row->key.pubkey.ul[ 0UL ], row->ipv4));
  // }

  // /* loop through the contents of the treap */
  // live_table_fwd_iter_init( table, &key0 );

  // FD_LOG_WARNING(("LOOP THROUGH TREAP"));
  // for( live_table_treap_fwd_iter_t iter = live_table_treap_fwd_iter_init( table->treaps[ 0 ], table->sort_pool );
  //     !live_table_treap_fwd_iter_done( iter );
  //     iter = live_table_treap_fwd_iter_next( iter, table->sort_pool ) ) {
  //   ulong sort_pool_idx = live_table_treap_fwd_iter_idx( iter );
  //   live_table_treap_ele_t * ele = live_table_treap_pool_ele( table->sort_pool, sort_pool_idx );
  //   live_table_row_t * row = live_table_pool_ele( table->map_pool, ele->key );
  //   FD_LOG_WARNING(("sort_pool_idx=%lu ele_idx=%lu pubkey=%lu ip=%u", sort_pool_idx, ele->key, row->key.pubkey.ul[ 0UL ], row->ipv4));
  // }

  // uint ips[ 4UL ];
  for( live_table_fwd_iter_t iter = live_table_fwd_iter_init( table, &key0 ); !live_table_fwd_iter_done( iter ); iter = live_table_fwd_iter_next( table, &key0, iter ) ) {
    live_table_row_t * row = live_table_fwd_iter_row( table, &key0, iter );
    FD_LOG_WARNING(("iter=%lu pubkey=%lu ip=%u", (ulong)iter, row->key.pubkey.ul[ 0UL ], row->ipv4));
  }

  live_table_sort_key_t const key1 = { .col = { 0, 1 }, .dir =  { FD_LIVE_TABLE_SORT_DIR_NULL, FD_LIVE_TABLE_SORT_DIR_DESC } };
  for( live_table_fwd_iter_t iter = live_table_fwd_iter_init( table, &key1 ); !live_table_fwd_iter_done( iter ); iter = live_table_fwd_iter_next( table, &key1, iter ) ) {
    live_table_row_t * row = live_table_fwd_iter_row( table, &key1, iter );
    FD_LOG_WARNING(("iter=%lu pubkey=%lu ip=%u",  (ulong)iter, row->key.pubkey.ul[ 0UL ], row->ipv4));
  }

  live_table_upsert( table, &r3 );

  for( live_table_fwd_iter_t iter = live_table_fwd_iter_init( table, &key0 ); !live_table_fwd_iter_done( iter ); iter = live_table_fwd_iter_next( table, &key0, iter ) ) {
    live_table_row_t * row = live_table_fwd_iter_row( table, &key0, iter );
    FD_LOG_WARNING(("iter=%lu pubkey=%lu ip=%u", (ulong)iter, row->key.pubkey.ul[ 0UL ], row->ipv4));
  }

  for( live_table_fwd_iter_t iter = live_table_fwd_iter_init( table, &key1 ); !live_table_fwd_iter_done( iter ); iter = live_table_fwd_iter_next( table, &key1, iter ) ) {
    live_table_row_t * row = live_table_fwd_iter_row( table, &key1, iter );
    FD_LOG_WARNING(("iter=%lu pubkey=%lu ip=%u",  (ulong)iter, row->key.pubkey.ul[ 0UL ], row->ipv4));
  }

  return 0;
}
