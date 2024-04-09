#include "fd_txn.h"


FD_STATIC_ASSERT( FD_TXN_PUBKEY_SZ==FD_TXN_ACCT_ADDR_SZ, solana_size_disagreement );
FD_STATIC_ASSERT( alignof(fd_txn_acct_addr_lut_t)==alignof(fd_txn_instr_t), fd_txn );
FD_STATIC_ASSERT( FD_TXN_MTU<=USHORT_MAX, fd_txn_mtu );

/* Calculate the max size for an fd_txn_t */

/* A worst-case instruction takes 3B of the payload and is stored as 10 B.  A
   worst-case address lookup table takes 35B of the payload and is stored as 8B.
   This gives the optimization problem:
    Maximize sizeof(fd_txn_t) + x * sizeof(fd_txn_instr_t) + y * sizeof(fd_txn_acct_addr_lut_t)
    subject to:
          MIN_FIXED_SIZE_SECTION
            + (x>0 ? 32 : 0) + len_compact_u16(x) + 3*x
            + (y>0 ?  1 : 0) + len_compact_u16(y) + 35*y          <=  1232
          0 <= x <= FD_TXN_INSTR_MAX
          0 <= y <= FD_TXN_ADDR_TABLE_LOOKUP_MAX
          x, y integers

   which has solution (not hard to see by hand):
     x == FD_TXN_INSTR_MAX
     y == floor((1232 - ... )/35)==24,
   giving an objective of 852.
*/
#define MIN_PAYLOAD_SZ( instr_cnt, alt_cnt )                              \
                        ( 1 + FD_TXN_SIGNATURE_SZ                         \
                          + ((alt_cnt) ? 1 : 0) + 3                       \
                          + 1 + ((instr_cnt) ? 2 : 1)*FD_TXN_ACCT_ADDR_SZ \
                          + FD_TXN_BLOCKHASH_SZ                           \
                          + 1 + 3*(instr_cnt)                             \
                          + 1 + 35*(alt_cnt) )

#define PARSED_SZ( instr_cnt, alt_cnt )                        \
                  sizeof(fd_txn_t)                             \
                  + (instr_cnt)*sizeof(fd_txn_instr_t        ) \
                  + (alt_cnt  )*sizeof(fd_txn_acct_addr_lut_t)

#define MIN_FIXED_SIZE_SECTION ( 1 + FD_TXN_SIGNATURE_SZ     \
                                 + 4                         \
                                 + 1 + FD_TXN_ACCT_ADDR_SZ /* fee payer */ \
                                 + FD_TXN_BLOCKHASH_SZ       )
#define WORST_CASE_INSTR_CNT     FD_TXN_INSTR_MAX
#define WORST_CASE_INSTR_PAYLOAD (1 + WORST_CASE_INSTR_CNT*3 )
#define WORST_CASE_ALT_CNT       ((1232 - MIN_FIXED_SIZE_SECTION - FD_TXN_ACCT_ADDR_SZ - WORST_CASE_INSTR_PAYLOAD - 1)/(35))
FD_STATIC_ASSERT( FD_TXN_MAX_SZ==sizeof(fd_txn_t) +
    WORST_CASE_INSTR_CNT*sizeof(fd_txn_instr_t) +
    WORST_CASE_ALT_CNT*sizeof(fd_txn_acct_addr_lut_t), fd_txn );

static void
iterate_all_acct_categories( void( *fn )( fd_txn_t*, ulong, ulong, ulong, ulong, ulong, ulong ) ) {
  for( ulong x=0UL; x<128UL; x++ ) {
    ulong ws = (x&1UL) + 1UL; /* always at least 1 writable signer for the fee payer */
    ulong rs = x&4UL;
    ulong wi = x&8UL;
    ulong ri = x&16UL;
    ulong wa = x&32UL;
    ulong ra = x&64UL;
    /* Max of 64+32+16+8+4+2=126 accounts */
    fd_txn_t txn;
    txn.transaction_version          = FD_TXN_V0;
    txn.signature_cnt                = (uchar)(ws+rs);
    txn.readonly_signed_cnt          = (uchar)rs;
    txn.readonly_unsigned_cnt        = (uchar)ri;
    txn.acct_addr_cnt                = (ushort)(ws+rs+wi+ri);
    txn.addr_table_lookup_cnt        = (uchar)1;
    txn.addr_table_adtl_writable_cnt = (uchar)wa;
    txn.addr_table_adtl_cnt          = (uchar)(wa+ra);

    fn( &txn, ws, rs, wi, ri, wa, ra );
  }
}

static void
test_cnt( fd_txn_t * txn,
          ulong      ws,
          ulong      rs,
          ulong      wi,
          ulong      ri,
          ulong      wa,
          ulong      ra ) {

  FD_TEST( fd_txn_account_cnt( txn, FD_TXN_ACCT_CAT_WRITABLE_SIGNER        )==ws                );
  FD_TEST( fd_txn_account_cnt( txn, FD_TXN_ACCT_CAT_READONLY_SIGNER        )==rs                );
  FD_TEST( fd_txn_account_cnt( txn, FD_TXN_ACCT_CAT_WRITABLE_NONSIGNER_IMM )==wi                );
  FD_TEST( fd_txn_account_cnt( txn, FD_TXN_ACCT_CAT_READONLY_NONSIGNER_IMM )==ri                );
  FD_TEST( fd_txn_account_cnt( txn, FD_TXN_ACCT_CAT_WRITABLE_ALT           )==wa                );
  FD_TEST( fd_txn_account_cnt( txn, FD_TXN_ACCT_CAT_READONLY_ALT           )==ra                );
  FD_TEST( fd_txn_account_cnt( txn, FD_TXN_ACCT_CAT_WRITABLE               )==ws+wi+wa          );
  FD_TEST( fd_txn_account_cnt( txn, FD_TXN_ACCT_CAT_READONLY               )==rs+ri+ra          );
  FD_TEST( fd_txn_account_cnt( txn, FD_TXN_ACCT_CAT_SIGNER                 )==ws+rs             );
  FD_TEST( fd_txn_account_cnt( txn, FD_TXN_ACCT_CAT_NONSIGNER              )==wi+ri+wa+ra       );
  FD_TEST( fd_txn_account_cnt( txn, FD_TXN_ACCT_CAT_IMM                    )==ws+rs+wi+ri       );
  FD_TEST( fd_txn_account_cnt( txn, FD_TXN_ACCT_CAT_ALT                    )==wa+ra             );
  FD_TEST( fd_txn_account_cnt( txn, FD_TXN_ACCT_CAT_ALL                    )==ws+rs+wi+ri+wa+ra );
  FD_TEST( fd_txn_account_cnt( txn, FD_TXN_ACCT_CAT_NONE                   )==0UL               );
}

static void
test_iter( fd_txn_t * txn,
           ulong      ws,
           ulong      rs,
           ulong      wi,
           ulong      ri,
           ulong      wa,
           ulong      ra ) {

  ulong expected[128] = { 0 };
  ulong expected_cnt = 0UL;

  fd_txn_acct_iter_t i;

  ulong j=0UL, _j=0UL;
#define RESET() j=0UL; _j=0UL; expected_cnt=0UL
#define INCLUDE(cnt) for( ulong i=0UL; i<(cnt); i++ ) { expected[ expected_cnt++ ]=_j+i; } _j += (cnt)
#define SKIP(cnt)    _j+=(cnt)

  i=fd_txn_acct_iter_init( txn, 0 );
  RESET(); SKIP(ws); SKIP(rs); SKIP(wi); SKIP(ri); SKIP(wa); SKIP(ra);
  for( ; i!=fd_txn_acct_iter_end(); i=fd_txn_acct_iter_next( i ) ) { FD_TEST( expected[ j++ ]==fd_txn_acct_iter_idx( i ) ); }
  FD_TEST( j==expected_cnt );

  i=fd_txn_acct_iter_init( txn, FD_TXN_ACCT_CAT_WRITABLE_SIGNER );
  RESET(); INCLUDE(ws); SKIP(rs); SKIP(wi); SKIP(ri); SKIP(wa); SKIP(ra);
  for( ; i!=fd_txn_acct_iter_end(); i=fd_txn_acct_iter_next( i ) ) { FD_TEST( expected[ j++ ]==fd_txn_acct_iter_idx( i ) ); }
  FD_TEST( j==expected_cnt );

  i=fd_txn_acct_iter_init( txn, FD_TXN_ACCT_CAT_READONLY_SIGNER );
  RESET(); SKIP(ws); INCLUDE(rs); SKIP(wi); SKIP(ri); SKIP(wa); SKIP(ra);
  for( ; i!=fd_txn_acct_iter_end(); i=fd_txn_acct_iter_next( i ) ) { FD_TEST( expected[ j++ ]==fd_txn_acct_iter_idx( i ) ); }
  FD_TEST( j==expected_cnt );

  i=fd_txn_acct_iter_init( txn, FD_TXN_ACCT_CAT_WRITABLE_NONSIGNER_IMM );
  RESET(); SKIP(ws); SKIP(rs); INCLUDE(wi); SKIP(ri); SKIP(wa); SKIP(ra);
  for( ; i!=fd_txn_acct_iter_end(); i=fd_txn_acct_iter_next( i ) ) { FD_TEST( expected[ j++ ]==fd_txn_acct_iter_idx( i ) ); }
  FD_TEST( j==expected_cnt );

  i=fd_txn_acct_iter_init( txn, FD_TXN_ACCT_CAT_READONLY_NONSIGNER_IMM );
  RESET(); SKIP(ws); SKIP(rs); SKIP(wi); INCLUDE(ri); SKIP(wa); SKIP(ra);
  for( ; i!=fd_txn_acct_iter_end(); i=fd_txn_acct_iter_next( i ) ) { FD_TEST( expected[ j++ ]==fd_txn_acct_iter_idx( i ) ); }
  FD_TEST( j==expected_cnt );

  i=fd_txn_acct_iter_init( txn, FD_TXN_ACCT_CAT_WRITABLE_ALT );
  RESET(); SKIP(ws); SKIP(rs); SKIP(wi); SKIP(ri); INCLUDE(wa); SKIP(ra);
  for( ; i!=fd_txn_acct_iter_end(); i=fd_txn_acct_iter_next( i ) ) { FD_TEST( expected[ j++ ]==fd_txn_acct_iter_idx( i ) ); }
  FD_TEST( j==expected_cnt );

  i=fd_txn_acct_iter_init( txn, FD_TXN_ACCT_CAT_READONLY_ALT );
  RESET(); SKIP(ws); SKIP(rs); SKIP(wi); SKIP(ri); SKIP(wa); INCLUDE(ra);
  for( ; i!=fd_txn_acct_iter_end(); i=fd_txn_acct_iter_next( i ) ) { FD_TEST( expected[ j++ ]==fd_txn_acct_iter_idx( i ) ); }
  FD_TEST( j==expected_cnt );

  i=fd_txn_acct_iter_init( txn, FD_TXN_ACCT_CAT_IMM );
  RESET(); INCLUDE(ws); INCLUDE(rs); INCLUDE(wi); INCLUDE(ri); SKIP(wa); SKIP(ra);
  for( ; i!=fd_txn_acct_iter_end(); i=fd_txn_acct_iter_next( i ) ) { FD_TEST( expected[ j++ ]==fd_txn_acct_iter_idx( i ) ); }
  FD_TEST( j==expected_cnt );

  i=fd_txn_acct_iter_init( txn, FD_TXN_ACCT_CAT_SIGNER );
  RESET(); INCLUDE(ws); INCLUDE(rs); SKIP(wi); SKIP(ri); SKIP(wa); SKIP(ra);
  for( ; i!=fd_txn_acct_iter_end(); i=fd_txn_acct_iter_next( i ) ) { FD_TEST( expected[ j++ ]==fd_txn_acct_iter_idx( i ) ); }
  FD_TEST( j==expected_cnt );

  i=fd_txn_acct_iter_init( txn, FD_TXN_ACCT_CAT_NONSIGNER );
  RESET(); SKIP(ws); SKIP(rs); INCLUDE(wi); INCLUDE(ri); INCLUDE(wa); INCLUDE(ra);
  for( ; i!=fd_txn_acct_iter_end(); i=fd_txn_acct_iter_next( i ) ) { FD_TEST( expected[ j++ ]==fd_txn_acct_iter_idx( i ) ); }
  FD_TEST( j==expected_cnt );

  i=fd_txn_acct_iter_init( txn, FD_TXN_ACCT_CAT_WRITABLE & FD_TXN_ACCT_CAT_IMM );
  RESET(); INCLUDE(ws); SKIP(rs); INCLUDE(wi); SKIP(ri); SKIP(wa); SKIP(ra);
  for( ; i!=fd_txn_acct_iter_end(); i=fd_txn_acct_iter_next( i ) ) { FD_TEST( expected[ j++ ]==fd_txn_acct_iter_idx( i ) ); }
  FD_TEST( j==expected_cnt );

  i=fd_txn_acct_iter_init( txn, FD_TXN_ACCT_CAT_READONLY & FD_TXN_ACCT_CAT_IMM );
  RESET(); SKIP(ws); INCLUDE(rs); SKIP(wi); INCLUDE(ri); SKIP(wa); SKIP(ra);
  for( ; i!=fd_txn_acct_iter_end(); i=fd_txn_acct_iter_next( i ) ) { FD_TEST( expected[ j++ ]==fd_txn_acct_iter_idx( i ) ); }
  FD_TEST( j==expected_cnt );

  i=fd_txn_acct_iter_init( txn, FD_TXN_ACCT_CAT_WRITABLE );
  RESET(); INCLUDE(ws); SKIP(rs); INCLUDE(wi); SKIP(ri); INCLUDE(wa); SKIP(ra);
  for( ; i!=fd_txn_acct_iter_end(); i=fd_txn_acct_iter_next( i ) ) { FD_TEST( expected[ j++ ]==fd_txn_acct_iter_idx( i ) ); }
  FD_TEST( j==expected_cnt );

  i=fd_txn_acct_iter_init( txn, FD_TXN_ACCT_CAT_READONLY );
  RESET(); SKIP(ws); INCLUDE(rs); SKIP(wi); INCLUDE(ri); SKIP(wa); INCLUDE(ra);
  for( ; i!=fd_txn_acct_iter_end(); i=fd_txn_acct_iter_next( i ) ) { FD_TEST( expected[ j++ ]==fd_txn_acct_iter_idx( i ) ); }
  FD_TEST( j==expected_cnt );

  i=fd_txn_acct_iter_init( txn, FD_TXN_ACCT_CAT_ALT );
  RESET(); SKIP(ws); SKIP(rs); SKIP(wi); SKIP(ri); INCLUDE(wa); INCLUDE(ra);
  for( ; i!=fd_txn_acct_iter_end(); i=fd_txn_acct_iter_next( i ) ) { FD_TEST( expected[ j++ ]==fd_txn_acct_iter_idx( i ) ); }
  FD_TEST( j==expected_cnt );

  i=fd_txn_acct_iter_init( txn, FD_TXN_ACCT_CAT_NONE );
  RESET(); SKIP(ws); SKIP(rs); SKIP(wi); SKIP(ri); SKIP(wa); SKIP(ra);
  for( ; i!=fd_txn_acct_iter_end(); i=fd_txn_acct_iter_next( i ) ) { FD_TEST( expected[ j++ ]==fd_txn_acct_iter_idx( i ) ); }
  FD_TEST( j==expected_cnt );

  i=fd_txn_acct_iter_init( txn, FD_TXN_ACCT_CAT_ALL );
  RESET(); INCLUDE(ws); INCLUDE(rs); INCLUDE(wi); INCLUDE(ri); INCLUDE(wa); INCLUDE(ra);
  for( ; i!=fd_txn_acct_iter_end(); i=fd_txn_acct_iter_next( i ) ) { FD_TEST( expected[ j++ ]==fd_txn_acct_iter_idx( i ) ); }
  FD_TEST( j==expected_cnt );

}


int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );
  /* TODO? Add tests for the offsets of fields? */

  fd_txn_t txn1 = {0};
  FD_TEST( (char *)fd_txn_get_address_tables      ( &txn1 ) == (char *)&txn1 + sizeof(fd_txn_t)                          );
  FD_TEST( (char *)fd_txn_get_address_tables_const( &txn1 ) == (char *)&txn1 + sizeof(fd_txn_t)                          );
  FD_TEST(         fd_txn_footprint(             0UL, 0UL ) ==                 sizeof(fd_txn_t)                          );


  fd_txn_t txn2 = {0};
  txn2.instr_cnt              = 4;
  txn2.addr_table_lookup_cnt  = 3;
  const ulong instr_sz    = 4UL*sizeof(fd_txn_instr_t);
  const ulong addr_lut_sz = 3UL*sizeof(fd_txn_acct_addr_lut_t);
  FD_TEST( (char *)fd_txn_get_address_tables      ( &txn2 ) == (char *)&txn2 + sizeof(fd_txn_t) + instr_sz               );
  FD_TEST( (char *)fd_txn_get_address_tables_const( &txn2 ) == (char *)&txn2 + sizeof(fd_txn_t) + instr_sz               );
  FD_TEST(         fd_txn_footprint(             4UL, 3UL ) ==                 sizeof(fd_txn_t) + instr_sz + addr_lut_sz );

  for( ulong instr_cnt=0UL; instr_cnt<=FD_TXN_INSTR_MAX; instr_cnt++ )
    for( ulong alt_cnt=0UL; alt_cnt<=FD_TXN_ADDR_TABLE_LOOKUP_MAX; alt_cnt++ )
      if( MIN_PAYLOAD_SZ( instr_cnt, alt_cnt ) <= FD_TXN_MTU )
        FD_TEST( PARSED_SZ( instr_cnt, alt_cnt ) <= FD_TXN_MAX_SZ );


  iterate_all_acct_categories( test_cnt  );
  iterate_all_acct_categories( test_iter );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}

