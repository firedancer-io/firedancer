#include "../fd_disco.h"

uchar scratch[ 256 ] __attribute__((aligned(256UL)));

#define TEST_LIVE_TABLE_ROW_CNT          (10000UL)
#define TEST_LIVE_TABLE_MAX_SORT_KEY_CNT (    2UL)
struct test_live_table_row {
  struct {
    ulong parent;
    ulong left;
    ulong right;
    ulong prio;
    ulong next;
    ulong prev;
  } treaps[ TEST_LIVE_TABLE_MAX_SORT_KEY_CNT ];
  ulong sort_keys;
  struct {
    ulong prev;
    ulong next;
  } dlist;

  fd_pubkey_t key;
  uint ipv4;
  ulong counter;
};
typedef struct test_live_table_row test_live_table_row_t;

static int live_table_col_pubkey_lt ( void const * a, void const * b ) { return memcmp( (fd_pubkey_t *)a, (fd_pubkey_t *)b, 32UL ) < 0; }
static int live_table_col_ipv4_lt   ( void const * a, void const * b ) { return *(uint *)a < *(uint *)b;                                }
static int live_table_col_counter_lt( void const * a, void const * b ) { return *(ulong *)a < *(ulong *)b;                              }

#define LIVE_TABLE_NAME test_live_table
#define LIVE_TABLE_COLUMN_CNT (3UL)
#define LIVE_TABLE_SORT_KEYS sort_keys
#define LIVE_TABLE_DLIST dlist
#define LIVE_TABLE_MAX_SORT_KEY_CNT TEST_LIVE_TABLE_MAX_SORT_KEY_CNT
#define LIVE_TABLE_COLUMNS LIVE_TABLE_COL_ARRAY( LIVE_TABLE_COL_ENTRY("Pubkey", key, live_table_col_pubkey_lt), LIVE_TABLE_COL_ENTRY("IP Address", ipv4, live_table_col_ipv4_lt), LIVE_TABLE_COL_ENTRY("Some Metric", counter, live_table_col_counter_lt) )
#define LIVE_TABLE_ROW_T test_live_table_row_t
#include "fd_gui_live_table_tmpl.c"

static inline int
test_live_table_key( test_live_table_t * table, test_live_table_sort_key_t const * key,  test_live_table_row_t * pool, ulong const * expected, ulong const expected_sz ) {
  for( test_live_table_fwd_iter_t iter = test_live_table_fwd_iter_init( table, key, pool ), i = 0; !test_live_table_fwd_iter_done( iter ); iter = test_live_table_fwd_iter_next( iter, pool ), i++ ) {
    if( i>=expected_sz ) {
      FD_LOG_WARNING(( "i=%lu < expected_sz=%lu", i, expected_sz ));
      return 0;
    }
    if( test_live_table_fwd_iter_idx( iter )!=expected[ i ] ) {
      FD_LOG_WARNING(( "expected=%lu actual=%lu", expected[ i ], test_live_table_fwd_iter_idx( iter ) ));
      return 0;
    }
  }
  return 1;
}

int
main( int argc, char ** argv ) {
  (void)argc; (void)argv;

  if( sizeof(scratch)!=test_live_table_footprint( TEST_LIVE_TABLE_ROW_CNT ) ) {
    FD_LOG_ERR(("scratch_sz=%lu != test_live_table_footprint( %lu )=%lu", sizeof(scratch), TEST_LIVE_TABLE_ROW_CNT, test_live_table_footprint( TEST_LIVE_TABLE_ROW_CNT ) ));
  }

  test_live_table_t * table = test_live_table_join( test_live_table_new( scratch, TEST_LIVE_TABLE_ROW_CNT ) );

  FD_TEST( !strcmp( test_live_table_col_idx_to_name( table, 2 ), "Some Metric" ) );
  FD_TEST( !strcmp( test_live_table_col_idx_to_name( table, 0 ), "Pubkey" )      );
  FD_TEST( !strcmp( test_live_table_col_idx_to_name( table, 1 ), "IP Address" )  );
  FD_TEST( test_live_table_col_idx_to_name( table, ULONG_MAX )==NULL             );

  FD_TEST( test_live_table_col_name_to_idx( table, "Some Metric" )==2 );
  FD_TEST( test_live_table_col_name_to_idx( table, "Pubkey" )==0 );
  FD_TEST( test_live_table_col_name_to_idx( table, "IP Address" )==1 );
  FD_TEST( test_live_table_col_name_to_idx( table, "NOT PRESENT" )==ULONG_MAX);

  test_live_table_row_t pool[] = {
    { .key = { .uc = { 0UL } }, .ipv4 = 1, .counter = 8 },
    { .key = { .uc = { 1UL } }, .ipv4 = 0, .counter = 7 },
    { .key = { .uc = { 2UL } }, .ipv4 = 2, .counter = 6 },
    { .key = { .uc = { 3UL } }, .ipv4 = 4, .counter = 5 },
  };

  test_live_table_sort_key_t keys[] = {
    { .col = { 0, 1, 2 }, .dir =  {  0,  1,  0 } },
    { .col = { 0, 1, 2 }, .dir =  {  0, -1,  0 } },
    { .col = { 0, 1, 2 }, .dir =  { -1, -1,  0 } },
    { .col = { 0, 1, 2 }, .dir =  {  0,  1,  0 } }, /* identical to keys[ 0 ]  */
    { .col = { 0, 2, 1 }, .dir =  {  0,  0,  1 } }  /* isomorphic to keys[ 0 ] */
  };

  test_live_table_seed( pool, 4UL, 42UL );
  FD_TEST( test_live_table_ele_cnt( table )==0UL );
  test_live_table_idx_insert( table, 0UL, pool );
  test_live_table_idx_insert( table, 1UL, pool );
  test_live_table_idx_insert( table, 2UL, pool );
  FD_TEST( test_live_table_ele_max( table )==TEST_LIVE_TABLE_ROW_CNT );
  FD_TEST( test_live_table_ele_cnt( table )==3UL );

  FD_TEST( test_live_table_key( table, &keys[ 0 ], pool, (ulong[]){ 1, 0, 2 }, 3UL ) );
  FD_TEST( test_live_table_active_sort_key_cnt( table )==1UL ); /* key0 */
  FD_TEST( test_live_table_key( table, &keys[ 3 ], pool, (ulong[]){ 1, 0, 2 }, 3UL ) );

  /* test insert equivalent keys. key0==key3==key4 */
  FD_TEST( test_live_table_active_sort_key_cnt( table )==1UL ); /* key0 */
  FD_TEST( test_live_table_key( table, &keys[ 4 ], pool, (ulong[]){ 1, 0, 2 }, 3UL ) );
  FD_TEST( test_live_table_active_sort_key_cnt( table )==1UL ); /* key0 */
  test_live_table_sort_key_remove( table, &keys[ 2 ] ); /* removing nonexisting key is NOP */
  FD_TEST( test_live_table_active_sort_key_cnt( table )==1UL );
  test_live_table_sort_key_remove( table, &keys[ 4 ] );
  FD_TEST( test_live_table_active_sort_key_cnt( table )==0UL );

  FD_TEST( test_live_table_key( table, &keys[ 0 ], pool, (ulong[]){ 1, 0, 2 }, 3UL ) );
  FD_TEST( test_live_table_key( table, &keys[ 1 ], pool, (ulong[]){ 2, 0, 1 }, 3UL ) );
  FD_TEST( test_live_table_active_sort_key_cnt( table )==2UL ); /* key0 + key1 */

  /* insert new row */
  test_live_table_idx_insert( table, 3UL, pool );
  FD_TEST( test_live_table_ele_cnt( table )==4UL );

  FD_TEST( test_live_table_key( table, &keys[ 0 ], pool, (ulong[]){ 1, 0, 2, 3 }, 4UL ) );
  FD_TEST( test_live_table_key( table, &keys[ 1 ], pool, (ulong[]){ 3, 2, 0, 1 }, 4UL ) );
  FD_TEST( test_live_table_active_sort_key_cnt( table )==2UL ); /* key0 + key1 */

  /* update existing row */
  test_live_table_idx_remove( table, 0UL, pool );
  pool[ 0 ] = (test_live_table_row_t){ .key = { .uc = { 0UL } }, .ipv4 = 3 };
  test_live_table_idx_insert( table, 0UL, pool );

  FD_TEST( test_live_table_key( table, &keys[ 1 ], pool, (ulong[]){ 3, 0, 2, 1 }, 4UL ) );
  FD_TEST( test_live_table_key( table, &keys[ 0 ], pool, (ulong[]){ 1, 2, 0, 3 }, 4UL ) );
  FD_TEST( test_live_table_active_sort_key_cnt( table )==2UL ); /* key0 + key1 */

  /* evict keys[ 0 ] */
  test_live_table_sort_key_remove( table, &keys[ 0 ] );
  FD_TEST( test_live_table_active_sort_key_cnt( table )==1UL ); /* key1 */
  FD_TEST( test_live_table_key( table, &keys[ 2 ], pool, (ulong[]){ 3, 2, 1, 0 }, 4UL ) );
  FD_TEST( test_live_table_active_sort_key_cnt( table )==2UL ); /* key1 + key2 */

  /* evict keys[ 1 ] */
  test_live_table_sort_key_remove( table, &keys[ 1 ] );
  FD_TEST( test_live_table_active_sort_key_cnt( table )==1UL ); /* key2 */
  FD_TEST( test_live_table_key( table, &keys[ 0 ], pool, (ulong[]){ 1, 2, 0, 3 }, 4UL ) );
  FD_TEST( test_live_table_active_sort_key_cnt( table )==2UL ); /* key2 + key0 */

  /* evict keys[ 2 ] */
  test_live_table_sort_key_remove( table, &keys[ 2 ] );
  FD_TEST( test_live_table_active_sort_key_cnt( table )==1UL ); /* key0 */
  FD_TEST( test_live_table_key( table, &keys[ 1 ], pool, (ulong[]){ 3, 0, 2, 1 }, 4UL ) );
  FD_TEST( test_live_table_active_sort_key_cnt( table )==2UL ); /* key0 + key1 */

  FD_TEST( !test_live_table_verify( table, pool ) );

  /* test lt */
  FD_TEST( 0==test_live_table_lt( &(test_live_table_sort_key_t){ .col = { 0, 1, 2 }, .dir =  {  0, 0, 0 } }, &(test_live_table_row_t){ .key = { .uc = { 0UL } }, .ipv4 = 0, .counter = 0 }, &(test_live_table_row_t){ .key = { .uc = { 1UL } }, .ipv4 = 1, .counter = 1 } ) );
  FD_TEST( 0==test_live_table_lt( &(test_live_table_sort_key_t){ .col = { 0, 1, 2 }, .dir =  {  0, 0, 0 } }, &(test_live_table_row_t){ .key = { .uc = { 1UL } }, .ipv4 = 1, .counter = 1 }, &(test_live_table_row_t){ .key = { .uc = { 0UL } }, .ipv4 = 0, .counter = 0 } ) );
  FD_TEST( 1==test_live_table_lt( &(test_live_table_sort_key_t){ .col = { 0, 1, 2 }, .dir =  {  0, 1, 0 } }, &(test_live_table_row_t){ .key = { .uc = { 1UL } }, .ipv4 = 0, .counter = 1 }, &(test_live_table_row_t){ .key = { .uc = { 0UL } }, .ipv4 = 1, .counter = 0 } ) );
  FD_TEST( 0==test_live_table_lt( &(test_live_table_sort_key_t){ .col = { 0, 1, 2 }, .dir =  {  0, 1, 0 } }, &(test_live_table_row_t){ .key = { .uc = { 0UL } }, .ipv4 = 1, .counter = 0 }, &(test_live_table_row_t){ .key = { .uc = { 1UL } }, .ipv4 = 0, .counter = 1 } ) );

  FD_LOG_INFO(( "PASSED" ));
  return 0;
}
