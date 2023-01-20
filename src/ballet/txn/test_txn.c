#include "fd_txn.h"


FD_STATIC_ASSERT( FD_TXN_PUBKEY_SZ==FD_TXN_ACCT_ADDR_SZ, solana_size_disagreement );
FD_STATIC_ASSERT( alignof(fd_txn_acct_addr_lut_t)==alignof(fd_txn_instr_t), fd_txn );

/* Calculate the max size for an fd_txn_t */

/* A worst-case instruction takes 3B of the payload and is stored as 10 B.  A
   worst-case address lookup table takes 34B of the payload and is stored as 8B.
   This gives the optimiztion problem:
    Maximize sizeof(fd_txn_t) + x * sizeof(fd_txn_instr_t) + y * sizeof(fd_txn_acct_addr_lut_t)
    subject to:
          (MIN_FIXED_SIZE_SECTION) + len_compact_u16(x) + 3*x
            + (y>0 ? 1 : 0) + len_compact_u16(y) + 34*y           <=  1232
          0 <= x <= FD_TXN_INSTR_MAX
          0 <= y <= FD_TXN_ADDR_TABLE_LOOKUP_MAX
          x, y integers

   which has solution (not hard to see by hand):
     x == FD_TXN_INSTR_MAX
     y == floor((1232 - ... )/34)==25,
   giving an objective of 860.
*/
#define MIN_FIXED_SIZE_SECTION ( 1 + FD_TXN_SIGNATURE_SZ     \
                                 + 4                         \
                                 + 1 + 2*FD_TXN_ACCT_ADDR_SZ \
                                 + FD_TXN_BLOCKHASH_SZ       )
#define WORST_CASE_INSTR_CNT     FD_TXN_INSTR_MAX
#define WORST_CASE_INSTR_PAYLOAD (1 + WORST_CASE_INSTR_CNT*3 )
#define WORST_CASE_ALT_CNT       ((1232 - 2 - MIN_FIXED_SIZE_SECTION - WORST_CASE_INSTR_PAYLOAD)/(34))
FD_STATIC_ASSERT( FD_TXN_MAX_SZ==sizeof(fd_txn_t) +
    WORST_CASE_INSTR_CNT*sizeof(fd_txn_instr_t) +
    WORST_CASE_ALT_CNT*sizeof(fd_txn_acct_addr_lut_t), fd_txn );


int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );
  /* TODO? Add tests for the offsets of fields? */

  fd_txn_t txn1 = {0};
  FD_TEST( (char *)fd_txn_get_address_tables( &txn1 ) == (char *)&txn1 + sizeof(fd_txn_t)                          );
  FD_TEST(         fd_txn_footprint(       0UL, 0UL ) ==                 sizeof(fd_txn_t)                          );


  fd_txn_t txn2 = {0};
  txn2.instr_cnt              = 4;
  txn2.addr_table_lookup_cnt  = 3;
  const ulong instr_sz    = 4UL*sizeof(fd_txn_instr_t);
  const ulong addr_lut_sz = 3UL*sizeof(fd_txn_acct_addr_lut_t);
  FD_TEST( (char *)fd_txn_get_address_tables( &txn2 ) == (char *)&txn2 + sizeof(fd_txn_t) + instr_sz               );
  FD_TEST(         fd_txn_footprint(       4UL, 3UL ) ==                 sizeof(fd_txn_t) + instr_sz + addr_lut_sz );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}

