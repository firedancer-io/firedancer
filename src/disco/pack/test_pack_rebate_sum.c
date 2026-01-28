#include "fd_pack_rebate_sum.h"
#include "fd_pack.h"

#define VOTE     FD_TXN_P_FLAGS_IS_SIMPLE_VOTE
#define BUNDLE   FD_TXN_P_FLAGS_BUNDLE
#define IB       FD_TXN_P_FLAGS_INITIALIZER_BUNDLE
#define SANITIZE FD_TXN_P_FLAGS_SANITIZE_SUCCESS
#define EXECUTE  FD_TXN_P_FLAGS_EXECUTE_SUCCESS

static inline void
fake_transaction( fd_txn_p_t     * txnp,
                  fd_acct_addr_t * alt,
                  ulong            rebate_cus,
                  uint             flags,
                  char const *     writable,
                  char const *     alt_writable ) {
  fd_txn_t * txn = TXN(txnp);
  txn->acct_addr_cnt = (uchar)strlen( writable );
  txn->signature_cnt         = 0;
  txn->readonly_signed_cnt   = 0;
  txn->readonly_unsigned_cnt = 0;
  txn->acct_addr_off         = 0;
  txn->addr_table_adtl_cnt   = (uchar)strlen( alt_writable );
  txn->addr_table_adtl_writable_cnt = (uchar)strlen( alt_writable );
  txn->addr_table_lookup_cnt = (uchar)strlen( alt_writable )>0UL;

  uchar * payload = txnp->payload;
  while( *writable ) {
    memset( payload, *writable, 32UL );
    payload += 32;
    writable++;
  }
  while( *alt_writable ) {
    memset( alt, *alt_writable, 32UL );
    alt_writable++;
    alt++;
  }
  txnp->payload_sz = 111UL;
  txnp->flags = flags;
  txnp->execle_cu.rebated_cus = (uint)rebate_cus;
}

static inline void
check_writer( fd_pack_rebate_t const * r,
              char const * accts,
              ulong cus ) {
  while( *accts ) {
    int found = 0;
    for( ulong i=0UL; i<(ulong)r->writer_cnt; i++ ) {
      if( FD_UNLIKELY( r->writer_rebates[i].key.b[0]==*accts ) ) {
        FD_TEST( !found );
        found = 1;
        FD_TEST( r->writer_rebates[i].rebate_cus==cus );
      }
    }
    FD_TEST( found );
    accts++;
  }
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  /* Normal, votes, microblock cnt with/without bundle, IB result,
     limits */
  fd_pack_rebate_sum_t _sum[1];
  fd_pack_rebate_sum_t * sum = fd_pack_rebate_sum_join( fd_pack_rebate_sum_new( _sum ) );

  union{ fd_pack_rebate_t rebate[1]; uchar footprint[USHORT_MAX]; } report;

  fd_txn_p_t microblock[31];
  fd_acct_addr_t alt[31][128];
  fd_acct_addr_t const * _alt[ 31 ];
  for( ulong i=0UL; i<31UL; i++ ) _alt[i] = alt[i];

  fake_transaction( microblock+0, alt[0],   10000UL, SANITIZE | EXECUTE, "ABCD", "EF" );
  fake_transaction( microblock+1, alt[1], 1400000UL, SANITIZE,           "GH",   ""   );
  fake_transaction( microblock+2, alt[2], 1400000UL, 0,                  "JKL",  "MN" );

  /* only 11 accounts (M,N excluded because sanitize failed), so not a
     problem */
  FD_TEST(       0UL==fd_pack_rebate_sum_add_txn( sum, microblock, _alt, 3UL ) );
  FD_TEST( 40UL*12UL==fd_pack_rebate_sum_report ( sum, report.rebate ) );
  FD_TEST( report.rebate->total_cost_rebate    ==2810000UL );
  FD_TEST( report.rebate->vote_cost_rebate     ==0UL       );
  FD_TEST( report.rebate->data_bytes_rebate    ==222UL     );
  FD_TEST( report.rebate->microblock_cnt_rebate==0UL       );
  FD_TEST( report.rebate->ib_result            ==0         );
  FD_TEST( report.rebate->writer_cnt           ==11U       );
  check_writer( report.rebate, "ABCDEF",   10000UL );
  check_writer( report.rebate, "GH",     1400000UL );
  check_writer( report.rebate, "JKL",    1400000UL );

  FD_TEST( 0UL==fd_pack_rebate_sum_report ( sum, report.rebate ) );

  FD_TEST(       0UL==fd_pack_rebate_sum_add_txn( sum, microblock, _alt, 3UL ) );
  FD_TEST(       0UL==fd_pack_rebate_sum_add_txn( sum, microblock, _alt, 3UL ) );
  FD_TEST( 40UL*12UL==fd_pack_rebate_sum_report ( sum, report.rebate ) );
  FD_TEST( report.rebate->total_cost_rebate    ==5620000UL );
  FD_TEST( report.rebate->vote_cost_rebate     ==0UL       );
  FD_TEST( report.rebate->data_bytes_rebate    ==444UL     );
  FD_TEST( report.rebate->microblock_cnt_rebate==0UL       );
  FD_TEST( report.rebate->ib_result            ==0         );
  FD_TEST( report.rebate->writer_cnt           ==11U       );
  check_writer( report.rebate, "ABCDEF",   20000UL );
  check_writer( report.rebate, "GH",     2800000UL );
  check_writer( report.rebate, "JKL",    2800000UL );



  fake_transaction( microblock+0, alt[0],  100UL, SANITIZE | EXECUTE | VOTE, "", "" );
  fake_transaction( microblock+1, alt[1], 3000UL, SANITIZE           | VOTE, "", "" );
  fake_transaction( microblock+2, alt[2], 4000UL, 0,                         "", "" );
  FD_TEST(  0UL==fd_pack_rebate_sum_add_txn( sum, microblock, _alt, 3UL ) );

  FD_TEST( 40UL==fd_pack_rebate_sum_report ( sum, report.rebate ) );
  FD_TEST( report.rebate->total_cost_rebate    ==7100UL );
  FD_TEST( report.rebate->vote_cost_rebate     ==3100UL );
  FD_TEST( report.rebate->data_bytes_rebate    ==222UL  );
  FD_TEST( report.rebate->microblock_cnt_rebate==0UL    );
  FD_TEST( report.rebate->ib_result            ==0      );
  FD_TEST( report.rebate->writer_cnt           ==0U     );




  fake_transaction( microblock+0, alt[0],   10000UL, SANITIZE, "", "" );
  fake_transaction( microblock+1, alt[1], 1400000UL, SANITIZE, "", "" );
  fake_transaction( microblock+2, alt[2], 1400000UL, 0,        "", "" );
  fake_transaction( microblock+3, alt[3], 1000000UL, 0,        "", "" );
  FD_TEST(  0UL==fd_pack_rebate_sum_add_txn( sum, microblock, _alt, 4UL ) );
  FD_TEST( 40UL==fd_pack_rebate_sum_report ( sum, report.rebate ) );
  FD_TEST( report.rebate->microblock_cnt_rebate==1UL    );
  FD_TEST( report.rebate->data_bytes_rebate    ==492UL  );
  FD_TEST(  0UL==fd_pack_rebate_sum_report ( sum, report.rebate ) );


  fake_transaction( microblock+0, alt[0],   10000UL, SANITIZE | BUNDLE, "", "" );
  fake_transaction( microblock+1, alt[1], 1400000UL, SANITIZE | BUNDLE, "", "" );
  fake_transaction( microblock+2, alt[2], 1400000UL, BUNDLE,            "", "" );
  fake_transaction( microblock+3, alt[3], 1000000UL, BUNDLE,            "", "" );
  FD_TEST(  0UL==fd_pack_rebate_sum_add_txn( sum, microblock, _alt, 4UL ) );
  FD_TEST( 40UL==fd_pack_rebate_sum_report ( sum, report.rebate ) );
  FD_TEST( report.rebate->microblock_cnt_rebate==4UL   );
  FD_TEST( report.rebate->data_bytes_rebate    ==636UL );


  fake_transaction( microblock+0, alt[0],   10000UL, SANITIZE | EXECUTE | BUNDLE | IB, "", "" );
  FD_TEST(  0UL==fd_pack_rebate_sum_add_txn( sum, microblock, _alt, 1UL ) );
  FD_TEST( 40UL==fd_pack_rebate_sum_report ( sum, report.rebate ) );
  FD_TEST( report.rebate->microblock_cnt_rebate==0UL );
  FD_TEST( report.rebate->ib_result            ==1   );
  FD_TEST(  0UL==fd_pack_rebate_sum_report ( sum, report.rebate ) );


  fake_transaction( microblock+1, alt[1],   10000UL, SANITIZE           | BUNDLE | IB, "", "" );
  fake_transaction( microblock+2, alt[2],   10000UL, SANITIZE | EXECUTE | BUNDLE | IB, "", "" );
  FD_TEST(  0UL==fd_pack_rebate_sum_add_txn( sum, microblock, _alt, 3UL ) );
  FD_TEST( 40UL==fd_pack_rebate_sum_report ( sum, report.rebate ) );
  FD_TEST( report.rebate->ib_result            ==-1  );

  for( ulong i=0UL; i<31UL*128UL*32UL; i++ ) alt[i>>12][(i>>5)&0x7F].b[i&0x1F] = (uchar)fd_ulong_hash( i );
  for( ulong i=0UL; i<31UL; i++ ) {
    fd_txn_t * txn = TXN(microblock+i);
    txn->acct_addr_cnt         = 0;
    txn->signature_cnt         = 0;
    txn->readonly_signed_cnt   = 0;
    txn->readonly_unsigned_cnt = 0;
    txn->acct_addr_off         = 0;
    txn->addr_table_adtl_cnt   = 128;
    txn->addr_table_adtl_writable_cnt = 128;
    txn->addr_table_lookup_cnt = 1;
    microblock[i].payload_sz   = 111UL;
    microblock[i].flags        = SANITIZE | EXECUTE;
    microblock[i].execle_cu.rebated_cus = 100U;
  }
  FD_TEST(         2UL==fd_pack_rebate_sum_add_txn( sum, microblock, _alt, 31UL ) );
  FD_TEST( 40UL*1638UL==fd_pack_rebate_sum_report ( sum, report.rebate          ) );
  FD_TEST(         1UL==fd_pack_rebate_sum_add_txn( sum, microblock, _alt, 0UL  ) );
  FD_TEST( 40UL*1638UL==fd_pack_rebate_sum_report ( sum, report.rebate          ) );
  FD_TEST(         0UL==fd_pack_rebate_sum_add_txn( sum, microblock, _alt, 0UL  ) );
  FD_TEST( 40UL* 695UL==fd_pack_rebate_sum_report ( sum, report.rebate          ) );
  FD_TEST(         0UL==fd_pack_rebate_sum_add_txn( sum, microblock, _alt, 0UL  ) );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
