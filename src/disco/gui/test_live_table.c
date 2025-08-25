#include "../fd_disco.h"

uchar scratch[ 1825920 ] __attribute__((aligned(256UL)));

struct test_live_table_row {
  fd_pubkey_t key;
  uint ipv4;
};
typedef struct test_live_table_row test_live_table_row_t;

static int live_table_col_pubkey_cmp( void const * a, void const * b ) { return memcmp( (fd_pubkey_t *)a, (fd_pubkey_t *)b, 32UL ); }
static int live_table_col_ipv4_cmp( void const * a, void const * b ) { return (int)((*(uint *)a) - (*(uint *)b)); }
static ulong live_table_col_pubkey_hash( void const * key ) { return fd_ulong_hash( *(ulong *)key ); }
static ulong live_table_col_ipv4_hash( void const * key ) { return fd_ulong_hash( ((fd_pubkey_t *)key)->ul[ 0UL ] ); }

#define TEST_LIVE_TABLE_ROW_CNT (10000UL)

#define LIVE_TABLE_NAME test_live_table
#define LIVE_TABLE_ROW_CNT TEST_LIVE_TABLE_ROW_CNT
#define LIVE_TABLE_COLUMN_CNT (2UL)
#define LIVE_TABLE_MAX_SORT_KEY_CNT (2UL)

/* our table is keyed by pubkey */
#define LIVE_TABLE_COLUMNS LIVE_TABLE_COL_ARRAY( \
    LIVE_TABLE_COL_ENTRY(key, live_table_col_pubkey_cmp, live_table_col_pubkey_hash, 1), \
    LIVE_TABLE_COL_ENTRY(ipv4, live_table_col_ipv4_cmp, live_table_col_ipv4_hash, 0) \
)
#define LIVE_TABLE_ROW_T test_live_table_row_t
#include "fd_gui_live_table_tmpl.c"

void
test_live_table_cmp_rows( test_live_table_row_t const * expected, test_live_table_row_t const * actual, ulong cnt ) {
  for ( ulong i = 0UL; i < cnt; i++ ) {
    if( memcmp( expected + i, actual + i, sizeof(test_live_table_row_t) ) ) {
      FD_LOG_ERR(("EXPECTED %lu %u GOT %lu %u ON ITER %lu", expected[ i ].key.ul[ 0UL ], expected[ i ].ipv4, actual[ i ].key.ul[ 0UL ], actual[ i ].ipv4, i ));
    }
  }
}

int
main( int argc, char ** argv ) {
  (void)argc; (void)argv;
  FD_LOG_NOTICE(("BEGIN TEST"));

  FD_LOG_INFO(( "footprint: %lu", test_live_table_footprint( TEST_LIVE_TABLE_ROW_CNT ) ));
  FD_TEST( sizeof(scratch)==test_live_table_footprint( TEST_LIVE_TABLE_ROW_CNT ) );

  test_live_table_t * table = test_live_table_join( test_live_table_new( scratch, TEST_LIVE_TABLE_ROW_CNT, 42UL ) );

  test_live_table_row_t r0 = { .key = { .uc = { 0UL } }, .ipv4 = 1 };
  test_live_table_row_t r1 = { .key = { .uc = { 1UL } }, .ipv4 = 0 };
  test_live_table_row_t r2 = { .key = { .uc = { 2UL } }, .ipv4 = 2 };
  test_live_table_upsert( table, &r0 );
  test_live_table_upsert( table, &r1 );
  test_live_table_upsert( table, &r2 );

  test_live_table_sort_key_t const key0 = { .col = { 0, 1 }, .dir =  { test_live_table_sort_dir_null(), test_live_table_sort_dir_asc() } };
  test_live_table_sort_key_t const key1 = { .col = { 0, 1 }, .dir =  { test_live_table_sort_dir_null(), test_live_table_sort_dir_desc() } };
  test_live_table_sort_key_t const key2 = { .col = { 0, 1 }, .dir =  { test_live_table_sort_dir_desc(), test_live_table_sort_dir_desc() } };

  test_live_table_row_t expected[ 4UL ];
  test_live_table_row_t actual  [ 4UL ];
  ulong idx;

  memcpy( expected, (test_live_table_row_t[ 3UL ]){ r1, r0, r2 }, 3UL*sizeof(test_live_table_row_t) );
  idx = 0UL;
  for( test_live_table_fwd_iter_t iter = test_live_table_fwd_iter_init( table, &key0 ); !test_live_table_fwd_iter_done( iter ); iter = test_live_table_fwd_iter_next( table, &key0, iter ) ) {
    test_live_table_row_t * row = test_live_table_fwd_iter_row( table, &key0, iter );
    actual[ idx++ ] = *row;
  }
  test_live_table_cmp_rows( expected, actual, idx );

  memcpy( expected, (test_live_table_row_t [ 3UL ]){ r2, r0, r1 }, 3UL*sizeof(test_live_table_row_t) );
  idx = 0UL;
  for( test_live_table_fwd_iter_t iter = test_live_table_fwd_iter_init( table, &key1 ); !test_live_table_fwd_iter_done( iter ); iter = test_live_table_fwd_iter_next( table, &key1, iter ) ) {
    test_live_table_row_t * row = test_live_table_fwd_iter_row( table, &key1, iter );
    actual[ idx ] = *row; idx++;
  }
  test_live_table_cmp_rows( expected, actual, idx );

  /* insert new row */
  test_live_table_row_t r3 = { .key = { .uc = { 3UL } }, .ipv4 = 4 };
  test_live_table_upsert( table, &r3 );

  memcpy( expected, (test_live_table_row_t [ 4UL ]){ r1, r0, r2, r3 }, 4UL*sizeof(test_live_table_row_t) );
  idx = 0UL;
  for( test_live_table_fwd_iter_t iter = test_live_table_fwd_iter_init( table, &key0 ); !test_live_table_fwd_iter_done( iter ); iter = test_live_table_fwd_iter_next( table, &key0, iter ) ) {
    test_live_table_row_t * row = test_live_table_fwd_iter_row( table, &key0, iter );
    actual[ idx ] = *row; idx++;
  }
  test_live_table_cmp_rows( expected, actual, idx );

  memcpy( expected, (test_live_table_row_t [ 4UL ]){ r3, r2, r0, r1 }, 4UL*sizeof(test_live_table_row_t) );
  idx = 0UL;
  for( test_live_table_fwd_iter_t iter = test_live_table_fwd_iter_init( table, &key1 ); !test_live_table_fwd_iter_done( iter ); iter = test_live_table_fwd_iter_next( table, &key1, iter ) ) {
    test_live_table_row_t * row = test_live_table_fwd_iter_row( table, &key1, iter );
    actual[ idx ] = *row; idx++;
  }
  test_live_table_cmp_rows( expected, actual, idx );

  /* update existing row */
  r0 = (test_live_table_row_t){ .key = { .uc = { 0UL } }, .ipv4 = 3 };
  test_live_table_upsert( table, &r0 );

  memcpy( expected, (test_live_table_row_t [ 4UL ]){ r1, r2, r0, r3 }, 4UL*sizeof(test_live_table_row_t) );
  idx = 0UL;
  for( test_live_table_fwd_iter_t iter = test_live_table_fwd_iter_init( table, &key0 ); !test_live_table_fwd_iter_done( iter ); iter = test_live_table_fwd_iter_next( table, &key0, iter ) ) {
    test_live_table_row_t * row = test_live_table_fwd_iter_row( table, &key0, iter );
    actual[ idx ] = *row; idx++;
  }
  test_live_table_cmp_rows( expected, actual, idx );

  memcpy( expected, (test_live_table_row_t [ 4UL ]){ r3, r0, r2, r1 }, 4UL*sizeof(test_live_table_row_t) );
  idx = 0UL;
  for( test_live_table_fwd_iter_t iter = test_live_table_fwd_iter_init( table, &key1 ); !test_live_table_fwd_iter_done( iter ); iter = test_live_table_fwd_iter_next( table, &key1, iter ) ) {
    test_live_table_row_t * row = test_live_table_fwd_iter_row( table, &key1, iter );
    actual[ idx ] = *row; idx++;
  }
  test_live_table_cmp_rows( expected, actual, idx );

  /* new key should evict key0 */
  memcpy( expected, (test_live_table_row_t [ 4UL ]){ r3, r2, r1, r0 }, 4UL*sizeof(test_live_table_row_t) );
  idx = 0UL;
  for( test_live_table_fwd_iter_t iter = test_live_table_fwd_iter_init( table, &key2 ); !test_live_table_fwd_iter_done( iter ); iter = test_live_table_fwd_iter_next( table, &key2, iter ) ) {
    test_live_table_row_t * row = test_live_table_fwd_iter_row( table, &key2, iter );
    actual[ idx ] = *row; idx++;
  }
  test_live_table_cmp_rows( expected, actual, idx );

  /* should evict key1 */
  memcpy( expected, (test_live_table_row_t [ 4UL ]){ r1, r2, r0, r3 }, 4UL*sizeof(test_live_table_row_t) );
  idx = 0UL;
  for( test_live_table_fwd_iter_t iter = test_live_table_fwd_iter_init( table, &key0 ); !test_live_table_fwd_iter_done( iter ); iter = test_live_table_fwd_iter_next( table, &key0, iter ) ) {
    test_live_table_row_t * row = test_live_table_fwd_iter_row( table, &key0, iter );
    actual[ idx ] = *row; idx++;
  }
  test_live_table_cmp_rows( expected, actual, idx );

  FD_LOG_INFO(( "PASSED" ));
  return 0;
}
