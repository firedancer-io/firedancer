#include "fd_compute_budget_program.h"

FD_IMPORT_BINARY( txn1, "src/ballet/pack/fixtures/txn1.bin" ); /* 0.2 lamports per CU, doesn't set number of CUs */
FD_IMPORT_BINARY( txn2, "src/ballet/pack/fixtures/txn2.bin" ); /* 500k CU, 15001 ulamports per CU; total fee: 12501 lamports */
FD_IMPORT_BINARY( txn3, "src/ballet/pack/fixtures/txn3.bin" ); /* Just 1M CU, no extra fee */
FD_IMPORT_BINARY( txn4, "src/ballet/pack/fixtures/txn4.bin" ); /* 75k CU, 20001 ulamports per CU, the CU request has trailing data */
FD_IMPORT_BINARY( txn5, "src/ballet/pack/fixtures/txn5.bin" ); /* Requests 6M CUs, so only allotted 1.4M CUs, total fee of 33,000 lamports */
FD_IMPORT_BINARY( txn6, "src/ballet/pack/fixtures/txn6.bin" ); /* Includes a requested_loaded_accounts_data_size_limit instruction */
FD_IMPORT_BINARY( txn7, "src/ballet/pack/fixtures/txn7.bin" ); /* Requests additional heap */


uchar parsed[FD_TXN_MAX_SZ];

void
test_txn( uchar const * payload,
          ulong         payload_sz,
          ulong         expected_max_cu,
          ulong         expected_fee_lamports ) { /* Excludes per-signature fee */
  FD_TEST( fd_txn_parse( payload, payload_sz, parsed, NULL ) );
  fd_txn_t * txn = (fd_txn_t*)parsed;
  fd_compute_budget_program_state_t state;
  fd_compute_budget_program_init( &state );
  uchar const * addresses = payload + txn->acct_addr_off;
  for( ulong i=0UL; i<txn->instr_cnt; i++ ) {
    if( !memcmp( addresses+FD_TXN_ACCT_ADDR_SZ*txn->instr[ i ].program_id, FD_COMPUTE_BUDGET_PROGRAM_ID, FD_TXN_ACCT_ADDR_SZ ) ) {
      FD_TEST( fd_compute_budget_program_parse( payload+txn->instr[ i ].data_off, txn->instr[ i ].data_sz, &state ) );
    }
  }
  ulong rewards = 0UL;
  uint  compute = 0U;
  fd_compute_budget_program_finalize( &state, txn->instr_cnt, &rewards, &compute );
  FD_TEST( rewards==expected_fee_lamports );
  FD_TEST( (ulong)compute==expected_max_cu );
}

FD_FN_CONST int
test_duplicate( ulong request_units_deprecated_cnt,
                ulong request_heap_frame_cnt,
                ulong set_compute_unit_limit_cnt,
                ulong set_compute_unit_price_cnt,
                ulong set_max_loaded_data_cnt ) {
  uchar const request_units_deprecated[ 9UL ] = { 0, 4,3,2,0, 8,7,6,5 };
  uchar const request_heap_frame      [ 5UL ] = { 1, 0,0,1,0          };
  uchar const set_compute_unit_limit  [ 5UL ] = { 2, 4,3,2,0          };
  uchar const set_compute_unit_price  [ 9UL ] = { 3, 8,7,6,5,4,3,2,1  };
  uchar const set_max_loaded_data     [ 5UL ] = { 4, 4,3,2,0          };
  fd_compute_budget_program_state_t state;
  fd_compute_budget_program_init( &state );

  int all_valid = 1;
  for( ulong i=0UL; i<request_units_deprecated_cnt; i++ )
    all_valid &= fd_compute_budget_program_parse( request_units_deprecated, 9UL, &state );
  for( ulong i=0UL; i<request_heap_frame_cnt;       i++ )
    all_valid &= fd_compute_budget_program_parse( request_heap_frame,       5UL, &state );
  for( ulong i=0UL; i<set_compute_unit_limit_cnt;   i++ )
    all_valid &= fd_compute_budget_program_parse( set_compute_unit_limit,   5UL, &state );
  for( ulong i=0UL; i<set_compute_unit_price_cnt;   i++ )
    all_valid &= fd_compute_budget_program_parse( set_compute_unit_price,   9UL, &state );
  for( ulong i=0UL; i<set_max_loaded_data_cnt;      i++ )
    all_valid &= fd_compute_budget_program_parse( set_max_loaded_data,      5UL, &state );
  return all_valid;
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  fd_rng_t _rng[1]; fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, 0U, 0UL ) );

  test_txn( txn1, txn1_sz, 1400000UL, 280000UL );
  test_txn( txn2, txn2_sz,  500000UL,   7501UL );
  test_txn( txn3, txn3_sz, 1000000UL,      0UL );
  test_txn( txn4, txn4_sz,   75000UL,   1501UL );
  test_txn( txn5, txn5_sz, 1400000UL,  28000UL );
  test_txn( txn6, txn6_sz,   60000UL,   5400UL );
  test_txn( txn7, txn7_sz, 1400000UL,      0UL );

  uchar _txn2[ txn2_sz ];
  fd_memcpy( _txn2, txn2, txn2_sz );

  uint  * cu_limit  = (uint  *) &_txn2[ 260 ];
  ulong * ulamports = (ulong *) &_txn2[ 268 ];
  *cu_limit = 1000000U; *ulamports = 1000000UL;    test_txn( _txn2, txn2_sz, 1000000UL, 1000000UL        ); /* No overflow  */
  *cu_limit = 1000000U; *ulamports = ULONG_MAX>>1; test_txn( _txn2, txn2_sz, 1000000UL, ULONG_MAX>>1     ); /* Product>2^64 */
  *cu_limit = 1400000U; *ulamports = ULONG_MAX;    test_txn( _txn2, txn2_sz, 1400000UL, ULONG_MAX        ); /* Result>2^64  */
  *cu_limit = 1400000U; *ulamports = 1UL<<44;      test_txn( _txn2, txn2_sz, 1400000UL, 24629060462183UL ); /* Product<2^64 */
  *cu_limit =       1U; *ulamports = 1UL;          test_txn( _txn2, txn2_sz,       1UL, 1UL              ); /* Test ceil    */

  FD_TEST( test_duplicate( 1, 1, 0, 0, 0 ) == 0 );
  FD_TEST( test_duplicate( 2, 0, 0, 0, 0 ) == 0 );
  FD_TEST( test_duplicate( 0, 1, 1, 1, 1 ) == 1 );
  FD_TEST( test_duplicate( 1, 1, 1, 1, 0 ) == 0 );
  FD_TEST( test_duplicate( 0, 0, 2, 1, 0 ) == 0 );
  FD_TEST( test_duplicate( 0, 0, 1, 2, 0 ) == 0 );
  FD_TEST( test_duplicate( 1, 0, 1, 0, 0 ) == 0 );
  FD_TEST( test_duplicate( 1, 0, 0, 1, 0 ) == 0 );
  FD_TEST( test_duplicate( 0, 1, 1, 1, 2 ) == 0 );
  FD_TEST( test_duplicate( 0, 1, 1, 0, 1 ) == 1 );
  FD_TEST( test_duplicate( 0, 1, 0, 1, 1 ) == 1 );
  FD_TEST( test_duplicate( 0, 0, 1, 1, 1 ) == 1 );

  fd_rng_delete( fd_rng_leave( rng ) );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}

