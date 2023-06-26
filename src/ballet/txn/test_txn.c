#include "fd_txn.h"


FD_STATIC_ASSERT( FD_TXN_PUBKEY_SZ==FD_TXN_ACCT_ADDR_SZ, solana_size_disagreement );
FD_STATIC_ASSERT( alignof(fd_txn_acct_addr_lut_t)==alignof(fd_txn_instr_t), fd_txn );

/* Calculate the max size for an fd_txn */
#define SERIALIZED_SIZE_OF_INSTRUCTION_AREA (1232                          \
                                              - 1 - FD_TXN_SIGNATURE_SZ   \
                                              - 3                         \
                                              - 1 - 2*FD_TXN_ACCT_ADDR_SZ \
                                              - FD_TXN_BLOCKHASH_SZ       \
                                              - 2) /* 2B for the instr cnt since >128 */
FD_STATIC_ASSERT( FD_TXN_MAX_SZ==sizeof(fd_txn_t)+sizeof(fd_txn_instr_t)*(SERIALIZED_SIZE_OF_INSTRUCTION_AREA/3), fd_txn );


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

