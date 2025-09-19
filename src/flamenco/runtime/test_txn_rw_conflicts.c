#include "fd_acc_mgr.h"
#include "fd_runtime.h"
#include "fd_runtime_err.h"
#include "fd_system_ids.h"
#include "program/fd_address_lookup_table_program.h"

fd_features_t features;

const ulong slot         = 100;
uchar transfer_txn_A_B[] = { 0x01, 0x43, 0xbd, 0x5f, 0x69, 0x99, 0x81, 0x40, 0x3d, 0x30, 0x9e, 0x75, 0x7a, 0x07, 0xcb, 0xfc, 0x06, 0x7b, 0x2e, 0x79, 0xe9, 0x25, 0x12, 0xc5, 0x05, 0xc3, 0x08, 0x37, 0xe6, 0x8d, 0x02, 0x75, 0xa2, 0x94, 0xbd, 0xb7, 0xdf, 0x0d, 0x0b, 0xdb, 0xf4, 0x9a, 0x78, 0x02, 0x01, 0x22, 0x46, 0xff, 0xe3, 0x6f, 0x7c, 0x79, 0x10, 0x0f, 0x0a, 0xd8, 0x72, 0xd4, 0x6f, 0x60, 0x69, 0x8c, 0xa7, 0x97, 0x04, 0x01, 0x00, 0x01, 0x03, 0x44, 0xdf, 0x3e, 0x7e, 0xcf, 0x6f, 0x12, 0xce, 0xeb, 0x6c, 0xe3, 0x1f, 0x6a, 0x93, 0x0f, 0x74, 0x28, 0xb1, 0x27, 0x00, 0x04, 0x99, 0x8b, 0xc3, 0x24, 0xbf, 0xa7, 0x54, 0x57, 0x81, 0xa1, 0xfc, 0x48, 0x84, 0xd7, 0x6a, 0x5d, 0x48, 0x2a, 0xb6, 0xc2, 0x2b, 0x9b, 0xe0, 0x87, 0xd4, 0x7d, 0x4a, 0x72, 0xae, 0xc5, 0x45, 0x06, 0x02, 0xdb, 0xb5, 0xc1, 0xa6, 0x15, 0x0e, 0x60, 0xb6, 0x39, 0x1e, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xd0, 0x16, 0xca, 0x1b, 0xec, 0x8c, 0xfc, 0xd0, 0x43, 0xb4, 0x5a, 0x2a, 0xdd, 0x15, 0x4f, 0x93, 0xae, 0xdb, 0x0d, 0x67, 0x4c, 0x6d, 0xdb, 0x27, 0x59, 0x68, 0x37, 0xbe, 0x60, 0x9e, 0x68, 0x6f, 0x01, 0x02, 0x02, 0x00, 0x01, 0x0c, 0x02, 0x00, 0x00, 0x00, 0x40, 0x42, 0x0f, 0x00, 0x00, 0x00, 0x00, 0x00 };
uchar transfer_txn_A_C[] = { 0x01, 0xe3, 0x33, 0x58, 0xff, 0xd4, 0x96, 0x12, 0xb2, 0x05, 0xd0, 0x43, 0xe1, 0x2f, 0xab, 0x9f, 0xd8, 0x16, 0x43, 0x30, 0x05, 0x74, 0x9d, 0x8a, 0xd4, 0x7a, 0x29, 0x21, 0x66, 0xab, 0x61, 0x02, 0x2a, 0x83, 0x79, 0x97, 0x7c, 0x9f, 0x01, 0x62, 0x0c, 0x67, 0x2e, 0xaf, 0x24, 0x72, 0x7d, 0x80, 0x41, 0xed, 0xb7, 0x0c, 0x4a, 0x86, 0x24, 0xd2, 0xbd, 0xd3, 0x8a, 0xe5, 0x7b, 0x69, 0x9e, 0x11, 0x0c, 0x01, 0x00, 0x01, 0x03, 0x44, 0xdf, 0x3e, 0x7e, 0xcf, 0x6f, 0x12, 0xce, 0xeb, 0x6c, 0xe3, 0x1f, 0x6a, 0x93, 0x0f, 0x74, 0x28, 0xb1, 0x27, 0x00, 0x04, 0x99, 0x8b, 0xc3, 0x24, 0xbf, 0xa7, 0x54, 0x57, 0x81, 0xa1, 0xfc, 0x3b, 0x63, 0x41, 0x60, 0x14, 0xfe, 0x84, 0xd2, 0xb9, 0x23, 0xc7, 0xa4, 0x23, 0x96, 0x80, 0x00, 0xe1, 0x88, 0x41, 0xa7, 0x41, 0x72, 0xef, 0xb9, 0x83, 0x3b, 0x3e, 0x48, 0x8c, 0xc4, 0xcc, 0x25, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xd0, 0x16, 0xca, 0x1b, 0xec, 0x8c, 0xfc, 0xd0, 0x43, 0xb4, 0x5a, 0x2a, 0xdd, 0x15, 0x4f, 0x93, 0xae, 0xdb, 0x0d, 0x67, 0x4c, 0x6d, 0xdb, 0x27, 0x59, 0x68, 0x37, 0xbe, 0x60, 0x9e, 0x68, 0x6f, 0x01, 0x02, 0x02, 0x00, 0x01, 0x0c, 0x02, 0x00, 0x00, 0x00, 0x40, 0x42, 0x0f, 0x00, 0x00, 0x00, 0x00, 0x00 };
uchar transfer_txn_D_E[] = { 0x01, 0x5c, 0x4f, 0x9a, 0x58, 0x2f, 0xf0, 0x43, 0x63, 0x46, 0x7d, 0x65, 0xc4, 0x46, 0x2a, 0x5f, 0x39, 0xf2, 0xbb, 0xb5, 0xa8, 0xda, 0xc9, 0x77, 0x16, 0x84, 0xe9, 0x1d, 0x7a, 0xdb, 0x9c, 0x50, 0xdf, 0x14, 0x9f, 0x30, 0x91, 0x97, 0x27, 0xe5, 0xbc, 0xbe, 0xc5, 0x02, 0x56, 0x35, 0x71, 0xbf, 0xe7, 0xf9, 0x0d, 0x31, 0x98, 0xbc, 0xb0, 0x02, 0xb0, 0xa9, 0xf6, 0x7e, 0xd8, 0xb5, 0x09, 0xd1, 0x08, 0x01, 0x00, 0x01, 0x03, 0xc1, 0xb7, 0x76, 0x33, 0xc6, 0x60, 0x09, 0x44, 0x5b, 0xe5, 0x65, 0xac, 0x18, 0x04, 0x16, 0x58, 0x77, 0x8d, 0x1b, 0x9c, 0xdc, 0x55, 0xca, 0x23, 0xfc, 0xab, 0xfa, 0xca, 0xfb, 0x1a, 0x32, 0x29, 0xf2, 0x13, 0xa1, 0x1d, 0x1e, 0x1e, 0xab, 0x4c, 0x0b, 0x45, 0x41, 0xee, 0x68, 0x18, 0xbe, 0x29, 0xe9, 0x61, 0xed, 0xd6, 0x1e, 0xaa, 0xea, 0x51, 0x08, 0x73, 0x65, 0x94, 0xe3, 0x6e, 0xfc, 0x8e, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xd0, 0x16, 0xca, 0x1b, 0xec, 0x8c, 0xfc, 0xd0, 0x43, 0xb4, 0x5a, 0x2a, 0xdd, 0x15, 0x4f, 0x93, 0xae, 0xdb, 0x0d, 0x67, 0x4c, 0x6d, 0xdb, 0x27, 0x59, 0x68, 0x37, 0xbe, 0x60, 0x9e, 0x68, 0x6f, 0x01, 0x02, 0x02, 0x00, 0x01, 0x0c, 0x02, 0x00, 0x00, 0x00, 0x40, 0x42, 0x0f, 0x00, 0x00, 0x00, 0x00, 0x00 };
uchar write_transfer_program[] = { 0x01, 0xbf, 0xbf, 0x82, 0x6b, 0x2a, 0xb1, 0xbf, 0xe1, 0x69, 0x22, 0x33, 0x33, 0x1a, 0xde, 0xb3, 0xf4, 0x21, 0x63, 0x86, 0x6e, 0xbe, 0x93, 0xd3, 0x84, 0x9b, 0x6e, 0x41, 0xc3, 0x3f, 0xae, 0x78, 0xc3, 0x25, 0x0e, 0x0e, 0x40, 0x4e, 0x4a, 0xd9, 0x6c, 0xaa, 0xfc, 0x85, 0xdc, 0xab, 0x8c, 0xa1, 0xfe, 0x41, 0xa9, 0xa4, 0xaa, 0x66, 0xb9, 0x7e, 0x3a, 0x40, 0x47, 0x98, 0x60, 0x40, 0xcb, 0xbe, 0x0a, 0x01, 0x00, 0x00, 0x02, 0x8a, 0x85, 0xc7, 0x45, 0x4e, 0xb4, 0x36, 0xfd, 0x29, 0x1d, 0x2a, 0x68, 0xe3, 0xf2, 0x10, 0xed, 0x96, 0x58, 0xdb, 0x33, 0x32, 0xc7, 0x11, 0x4b, 0xcf, 0x91, 0xb0, 0xc6, 0x64, 0xce, 0xfa, 0xb6, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xd0, 0x16, 0xca, 0x1b, 0xec, 0x8c, 0xfc, 0xd0, 0x43, 0xb4, 0x5a, 0x2a, 0xdd, 0x15, 0x4f, 0x93, 0xae, 0xdb, 0x0d, 0x67, 0x4c, 0x6d, 0xdb, 0x27, 0x59, 0x68, 0x37, 0xbe, 0x60, 0x9e, 0x68, 0x6f, 0x01, 0x01, 0x02, 0x00, 0x01, 0x0c, 0x02, 0x00, 0x00, 0x00, 0x40, 0x42, 0x0f, 0x00, 0x00, 0x00, 0x00, 0x00 };
/* S stands for sentinel (fd_acct_addr_null) */
uchar transfer_txn_F_S[] = { 0x01, 0x9c, 0x7b, 0xe1, 0x80, 0xb3, 0x76, 0x31, 0xf1, 0x94, 0x57, 0x4a, 0xf5, 0xa2, 0x9a, 0x88, 0x7a, 0xcf, 0xd6, 0xd4, 0x26, 0xdd, 0xe0, 0x86, 0x4c, 0xa5, 0x20, 0xce, 0xc9, 0xf9, 0x21, 0x11, 0x8c, 0x1c, 0x75, 0xf7, 0x36, 0xb2, 0xf4, 0x4e, 0x30, 0xce, 0x8a, 0x2d, 0xf1, 0x1b, 0xf9, 0x61, 0xe4, 0xd0, 0xaa, 0xb1, 0xf7, 0x18, 0x8f, 0xbc, 0x04, 0x03, 0xc6, 0x26, 0x06, 0x2f, 0x6c, 0x78, 0x06, 0x01, 0x00, 0x01, 0x03, 0x3d, 0x0e, 0x1e, 0xae, 0xa3, 0x7b, 0xf1, 0xfd, 0xcb, 0xe7, 0xfd, 0x85, 0xe7, 0xca, 0xc5, 0xc4, 0xf3, 0x3c, 0xe2, 0x30, 0x0e, 0x39, 0x4b, 0x2b, 0x4e, 0xcc, 0xd2, 0x37, 0x6f, 0x68, 0x71, 0xf6, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xd0, 0x16, 0xca, 0x1b, 0xec, 0x8c, 0xfc, 0xd0, 0x43, 0xb4, 0x5a, 0x2a, 0xdd, 0x15, 0x4f, 0x93, 0xae, 0xdb, 0x0d, 0x67, 0x4c, 0x6d, 0xdb, 0x27, 0x59, 0x68, 0x37, 0xbe, 0x60, 0x9e, 0x68, 0x6f, 0x01, 0x02, 0x02, 0x00, 0x01, 0x0c, 0x02, 0x00, 0x00, 0x00, 0x40, 0x42, 0x0f, 0x00, 0x00, 0x00, 0x00, 0x00 };
uchar transfer_txn_G_S[] = { 0x01, 0x76, 0x0a, 0x45, 0x8b, 0xbf, 0x2d, 0x9f, 0x99, 0x04, 0xbc, 0xe9, 0x5f, 0x06, 0xc7, 0xd0, 0x96, 0x06, 0x0c, 0x1e, 0x8a, 0x1d, 0x08, 0x58, 0x90, 0x23, 0xe9, 0xfc, 0x00, 0x97, 0x93, 0x73, 0xd1, 0x1c, 0x01, 0x31, 0x3c, 0x5d, 0xb6, 0xc8, 0xee, 0xfb, 0x20, 0x64, 0x95, 0x50, 0xf9, 0x13, 0x5d, 0xff, 0xd8, 0xb0, 0xd9, 0xf2, 0x6f, 0xaf, 0xd6, 0x94, 0xa9, 0x8d, 0x7b, 0x24, 0xee, 0x48, 0x08, 0x01, 0x00, 0x01, 0x03, 0xd7, 0x78, 0xea, 0x4f, 0x19, 0x0b, 0xff, 0x4c, 0x80, 0x5d, 0x53, 0x11, 0xb6, 0x16, 0x24, 0x1e, 0x6d, 0x4e, 0x0d, 0x31, 0xfb, 0xc9, 0xee, 0x39, 0xec, 0x9f, 0xee, 0x42, 0x27, 0xe1, 0x17, 0x0b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xd0, 0x16, 0xca, 0x1b, 0xec, 0x8c, 0xfc, 0xd0, 0x43, 0xb4, 0x5a, 0x2a, 0xdd, 0x15, 0x4f, 0x93, 0xae, 0xdb, 0x0d, 0x67, 0x4c, 0x6d, 0xdb, 0x27, 0x59, 0x68, 0x37, 0xbe, 0x60, 0x9e, 0x68, 0x6f, 0x01, 0x02, 0x02, 0x00, 0x01, 0x0c, 0x02, 0x00, 0x00, 0x00, 0x40, 0x42, 0x0f, 0x00, 0x00, 0x00, 0x00, 0x00 };

#define MAX_TXNS_CNT 3
fd_txn_p_t txns[MAX_TXNS_CNT];
ulong txn_sz[MAX_TXNS_CNT], pay_sz[MAX_TXNS_CNT];

void parse_txns( const ulong txns_cnt,
                 uchar *     raw_txns[],
                 ulong *     raw_txns_len ) {
   for( ulong i=0; i<txns_cnt; i++ ) {
      txns[i].payload_sz = raw_txns_len[i];
      fd_memcpy( txns[i].payload, raw_txns[i], txns[i].payload_sz );
      txn_sz[i] = fd_txn_parse_core( txns[i].payload, txns[i].payload_sz, TXN( &txns[i] ), NULL, &pay_sz[i] );
      FD_LOG_INFO(( "Txn#%lu has payload size %lu, %u+%u read-only accts, total=%u", i, txns[i].payload_sz,
TXN( &txns[i] )->readonly_unsigned_cnt, TXN( &txns[i] )->readonly_signed_cnt, TXN( &txns[i] )->acct_addr_cnt ));

      if( FD_UNLIKELY( !pay_sz[i] || !txn_sz[i] || txn_sz[i] > FD_TXN_MTU ) )
        FD_LOG_ERR(( "failed to parse transaction #%lu", i ));
  }
}

void test_no_conflict( fd_conflict_detect_ele_t * acct_map,
                       fd_acct_addr_t *  acct_arr ) {
  const ulong txns_cnt = 2UL;
  uchar * raw_txns[]       = { transfer_txn_A_B, transfer_txn_D_E };
  ulong raw_txns_len[]     = { sizeof(transfer_txn_A_B), sizeof(transfer_txn_D_E) };

  parse_txns( txns_cnt, raw_txns, raw_txns_len );

  fd_acct_addr_t conflict_acct;
  int detected;
  int err = fd_runtime_microblock_verify_read_write_conflicts( txns, txns_cnt, acct_map, acct_arr, NULL, NULL, slot, NULL, &features, &detected, &conflict_acct );
  FD_TEST( err==FD_RUNTIME_EXECUTE_SUCCESS );
  FD_TEST( detected==FD_RUNTIME_NO_CONFLICT_DETECTED );
  FD_TEST( 0==fd_conflict_detect_map_key_cnt( acct_map ) );
  FD_LOG_NOTICE(( "Pass test_no_conflict" ));
}

void test_no_conflict_demote( fd_conflict_detect_ele_t * acct_map,
                               fd_acct_addr_t *  acct_arr ) {
  const ulong txns_cnt = 2UL;
  uchar * raw_txns[]       = { transfer_txn_A_B, write_transfer_program };
  ulong raw_txns_len[]     = { sizeof(transfer_txn_A_B), sizeof(write_transfer_program) };

  parse_txns( txns_cnt, raw_txns, raw_txns_len );

  fd_acct_addr_t conflict_acct;
  int detected;
  int err = fd_runtime_microblock_verify_read_write_conflicts(txns, txns_cnt, acct_map, acct_arr, NULL, NULL, slot, NULL, &features, &detected, &conflict_acct );
  FD_TEST( err==FD_RUNTIME_EXECUTE_SUCCESS );
  FD_TEST( detected==FD_RUNTIME_NO_CONFLICT_DETECTED );
  FD_TEST( 0==fd_conflict_detect_map_key_cnt( acct_map ) );
  FD_LOG_NOTICE(( "Pass test_no_conflict_demote" ));
}

void test_write_write_conflict( fd_conflict_detect_ele_t * acct_map,
                                fd_acct_addr_t *  acct_arr ) {
  const ulong txns_cnt = 3UL;
  uchar * raw_txns[]       = { transfer_txn_A_B, transfer_txn_D_E, transfer_txn_A_C };
  ulong raw_txns_len[]     = { sizeof(transfer_txn_A_B), sizeof(transfer_txn_D_E), sizeof(transfer_txn_A_C) };

  parse_txns( txns_cnt, raw_txns, raw_txns_len );

  fd_acct_addr_t conflict_acct;
  int detected;
  int err = fd_runtime_microblock_verify_read_write_conflicts(txns, txns_cnt, acct_map, acct_arr, NULL, NULL, slot, NULL, &features, &detected, &conflict_acct );
  FD_TEST( err==FD_RUNTIME_TXN_ERR_ACCOUNT_IN_USE );
  FD_TEST( detected==FD_RUNTIME_WRITE_WRITE_CONFLICT_DETECTED );
  FD_TEST( 0==fd_conflict_detect_map_key_cnt( acct_map ) );
  FD_LOG_NOTICE(( "Pass test_write_write_conflict" ));
}

void test_write_write_conflict_sentinel( fd_conflict_detect_ele_t * acct_map,
                                         fd_acct_addr_t *  acct_arr ) {
  const ulong txns_cnt = 2UL;
  uchar * raw_txns[]   = { transfer_txn_F_S, transfer_txn_G_S };
  ulong raw_txns_len[] = { sizeof(transfer_txn_F_S), sizeof(transfer_txn_G_S) };

  parse_txns( txns_cnt, raw_txns, raw_txns_len );

  fd_acct_addr_t conflict_acct;
  int detected;
  int err = fd_runtime_microblock_verify_read_write_conflicts(txns, txns_cnt, acct_map, acct_arr, NULL, NULL, slot, NULL, &features, &detected, &conflict_acct );
  FD_TEST( err==FD_RUNTIME_TXN_ERR_ACCOUNT_IN_USE );
  FD_TEST( detected==FD_RUNTIME_WRITE_WRITE_CONFLICT_DETECTED );
  FD_TEST( 0==fd_conflict_detect_map_key_cnt( acct_map ) );
  FD_LOG_NOTICE(( "Pass test_write_write_conflict_sentinel" ));
}

void add_address_lookup_table( fd_funk_t *     funk,
                               fd_funk_txn_t * funk_txn,
                               fd_pubkey_t *   alt_acct_addr,
                               uchar *         alt_acct_data,
                               ulong           alt_acct_data_sz,
                               uchar *         in_payload,
                               ushort          in_payload_sz,
                               fd_txn_p_t *    out_txn,
                               ulong *         out_txn_sz,
                               ulong *         out_pay_sz ) {

  FD_TXN_ACCOUNT_DECL( rec );
  fd_funk_rec_prepare_t prepare = {0};
  const ulong rec_sz = FD_LOOKUP_TABLE_META_SIZE+alt_acct_data_sz;
  int result = fd_txn_account_init_from_funk_mutable( rec, alt_acct_addr, funk, funk_txn, /* do_create */ 1, rec_sz, &prepare );
  FD_TEST( result==FD_ACC_MGR_SUCCESS );

  fd_address_lookup_table_state_t table;
  table.discriminant = fd_address_lookup_table_state_enum_lookup_table;
  table.inner.lookup_table.meta.deactivation_slot  = ULONG_MAX;
  table.inner.lookup_table.meta.last_extended_slot = 0; /* this makes fd_get_active_addresses_len return 2 */

  fd_bincode_encode_ctx_t encode_ctx = {
    .data    = fd_txn_account_get_data_mut( rec ),
    .dataend = fd_txn_account_get_data_mut( rec ) + FD_LOOKUP_TABLE_META_SIZE
  };
  int err = fd_address_lookup_table_state_encode( &table, &encode_ctx );
  FD_TEST( err==0 );

  fd_txn_account_set_data_len( rec, rec_sz );
  fd_txn_account_set_owner( rec, &fd_solana_address_lookup_table_program_id );
  fd_memcpy( fd_txn_account_get_data_mut( rec )+FD_LOOKUP_TABLE_META_SIZE, alt_acct_data, alt_acct_data_sz );
  fd_txn_account_mutable_fini( rec, funk, funk_txn, &prepare );
  /* other metadata fields (e.g., slot, hash, ...) are ommited */

  /* Append an address lookup table after txn_payload */
  fd_txn_acct_addr_lut_t alt = {
    .addr_off    =(ushort)(in_payload_sz+sizeof(fd_txn_acct_addr_lut_t)),
    .writable_cnt=(ushort)1,
    .readonly_cnt=(ushort)1,
    .writable_off=(ushort)(in_payload_sz+sizeof(fd_txn_acct_addr_lut_t)+sizeof(fd_acct_addr_t)),
    .readonly_off=(ushort)(in_payload_sz+sizeof(fd_txn_acct_addr_lut_t)+sizeof(fd_acct_addr_t)+sizeof(uchar))
  };
  /*                    original txn binary   lookup table struct            lookup table address   address indexes */
  //uchar txn_with_alt[ in_payload           +sizeof(fd_txn_acct_addr_lut_t)+sizeof(fd_acct_addr_t)+sizeof(uchar)*2 ];
  uchar * out_payload = out_txn->payload;
  fd_memcpy( out_payload, in_payload, in_payload_sz );
  fd_memcpy( out_payload+in_payload_sz, &alt, sizeof(fd_txn_acct_addr_lut_t) );
  fd_memcpy( out_payload+in_payload_sz+sizeof(fd_txn_acct_addr_lut_t),
             alt_acct_addr->uc, sizeof(fd_pubkey_t) );
  ulong idx_offset = in_payload_sz+sizeof(fd_txn_acct_addr_lut_t)+sizeof(fd_pubkey_t);
  out_payload[ idx_offset ] = 0;
  out_payload[ idx_offset+1 ] = 1;

  out_txn->payload_sz = idx_offset+2*sizeof(uchar);
  *out_txn_sz         = fd_txn_parse_core( out_payload, out_txn->payload_sz, TXN( out_txn ), NULL, out_pay_sz );
  if( FD_UNLIKELY( *out_pay_sz==0 || *out_txn_sz==0 || *out_txn_sz > FD_TXN_MTU ) )
    FD_LOG_ERR(( "failed to parse transaction #%lu", 1UL ));

  /* Add the address lookup table into the parsed txn */
  TXN( out_txn )->transaction_version          = FD_TXN_V0;
  TXN( out_txn )->addr_table_lookup_cnt        = 1;
  TXN( out_txn )->addr_table_adtl_writable_cnt = 1;
  TXN( out_txn )->addr_table_adtl_cnt          = 2;
  fd_txn_acct_addr_lut_t * addr_luts = fd_txn_get_address_tables( TXN( out_txn ) );
  fd_memcpy( addr_luts, &alt, sizeof(fd_txn_acct_addr_lut_t) );
}

void test_no_conflict_alt( fd_funk_t *                funk,
                           fd_funk_txn_t *            funk_txn,
                           fd_conflict_detect_ele_t * acct_map,
                           fd_acct_addr_t *           acct_arr ) {
  const ulong txns_cnt     = 2UL;
  uchar * raw_txns[]       = { transfer_txn_A_B, transfer_txn_D_E };
  ulong raw_txns_len[]     = { sizeof(transfer_txn_A_B), sizeof(transfer_txn_D_E) };
  parse_txns( txns_cnt, raw_txns, raw_txns_len );

  fd_pubkey_t    alt_acct_addr;
  fd_acct_addr_t alt_acct_content[2];
  fd_base58_decode_32( "oQPnhXAbLbMuKHESaGrbXT17CyvWCpLyERSJA9HCYd7",  alt_acct_addr.uc );
  fd_base58_decode_32( "6KUbAnWkuAmAoQX7iAAh7r8n2EjERbqao2t1hfPChwpH", alt_acct_content[0].b );
  fd_base58_decode_32( "AEK3Z5CGNgmRQHxK9sRHbbn6MJ5oCg5M96qsXjQJE123", alt_acct_content[1].b );

  add_address_lookup_table( funk,
                            funk_txn,
                            &alt_acct_addr,
                            (void*)&alt_acct_content,
                            sizeof(fd_acct_addr_t)*2,
                            transfer_txn_D_E,
                            sizeof(transfer_txn_D_E),
                            &txns[1],
                            &txn_sz[1],
                            &pay_sz[1] );

  fd_acct_addr_t conflict_acct;
  int detected;
  int err = fd_runtime_microblock_verify_read_write_conflicts(txns, txns_cnt, acct_map, acct_arr, funk, funk_txn, slot, NULL, &features, &detected, &conflict_acct );
  FD_TEST( err==FD_RUNTIME_NO_CONFLICT_DETECTED );
  FD_TEST( 0==fd_conflict_detect_map_key_cnt( acct_map ) );
  FD_LOG_NOTICE(( "Pass test_no_conflict_alt" ));
}

void test_read_write_conflict_alt( fd_funk_t *                funk,
                                   fd_funk_txn_t *            funk_txn,
                                   fd_conflict_detect_ele_t * acct_map,
                                   fd_acct_addr_t *           acct_arr ) {
  const ulong txns_cnt     = 2UL;
  uchar * raw_txns[]       = { transfer_txn_A_B, transfer_txn_D_E };
  ulong raw_txns_len[]     = { sizeof(transfer_txn_A_B), sizeof(transfer_txn_D_E) };
  parse_txns( txns_cnt, raw_txns, raw_txns_len );

  fd_pubkey_t    alt_acct_addr;
  fd_acct_addr_t alt_acct_content[2];
  fd_base58_decode_32( "oQPnhXAbLbMuKHESaGrbXT17CyvWCpLyERSJA9HCYd7", alt_acct_addr.uc );
  fd_base58_decode_32( "6KUbAnWkuAmAoQX7iAAh7r8n2EjERbqao2t1hfPChwpH", alt_acct_content[0].b );
  fd_base58_decode_32( "5drANtynCaE2fbXFMaWxSeB8BvHmdBNfb32PnGdpFr6P", alt_acct_content[1].b );

  add_address_lookup_table( funk,
                            funk_txn,
                            &alt_acct_addr,
                            (void*)&alt_acct_content,
                            sizeof(fd_acct_addr_t)*2,
                            transfer_txn_D_E,
                            sizeof(transfer_txn_D_E),
                            &txns[1],
                            &txn_sz[1],
                            &pay_sz[1] );

  fd_acct_addr_t conflict_acct;
  int detected;
  int err = fd_runtime_microblock_verify_read_write_conflicts(txns, txns_cnt, acct_map, acct_arr, funk, funk_txn, slot, NULL, &features, &detected, &conflict_acct );
  FD_TEST( err==FD_RUNTIME_TXN_ERR_ACCOUNT_IN_USE );
  FD_TEST( detected==FD_RUNTIME_READ_WRITE_CONFLICT_DETECTED );
  FD_TEST( 0==fd_conflict_detect_map_key_cnt( acct_map ) );
  FD_LOG_NOTICE(( "Pass test_read_write_conflict_alt" ));
}

void test_write_write_conflict_alt( fd_funk_t *                 funk,
                                     fd_funk_txn_t *            funk_txn,
                                     fd_conflict_detect_ele_t * acct_map,
                                     fd_acct_addr_t *           acct_arr ) {
  const ulong txns_cnt     = 2UL;
  uchar * raw_txns[]       = { transfer_txn_A_B, transfer_txn_D_E };
  ulong raw_txns_len[]     = { sizeof(transfer_txn_A_B), sizeof(transfer_txn_D_E) };
  parse_txns( txns_cnt, raw_txns, raw_txns_len );

  fd_pubkey_t    alt_acct_addr;
  fd_acct_addr_t alt_acct_content[2];
  fd_base58_decode_32( "oQPnhXAbLbMuKHESaGrbXT17CyvWCpLyERSJA9HCYd7", alt_acct_addr.uc );
  fd_base58_decode_32( "5drANtynCaE2fbXFMaWxSeB8BvHmdBNfb32PnGdpFr6P", alt_acct_content[0].b );
  fd_base58_decode_32( "6KUbAnWkuAmAoQX7iAAh7r8n2EjERbqao2t1hfPChwpH", alt_acct_content[1].b );

  add_address_lookup_table( funk,
                            funk_txn,
                            &alt_acct_addr,
                            (void*)&alt_acct_content,
                            sizeof(fd_acct_addr_t)*2,
                            transfer_txn_D_E,
                            sizeof(transfer_txn_D_E),
                            &txns[1],
                            &txn_sz[1],
                            &pay_sz[1] );

  fd_acct_addr_t conflict_acct;
  int detected;
  int err = fd_runtime_microblock_verify_read_write_conflicts(txns, txns_cnt, acct_map, acct_arr, funk, funk_txn, slot, NULL, &features, &detected, &conflict_acct );
  FD_TEST( err==FD_RUNTIME_TXN_ERR_ACCOUNT_IN_USE );
  FD_TEST( detected==FD_RUNTIME_WRITE_WRITE_CONFLICT_DETECTED );
  FD_TEST( 0==fd_conflict_detect_map_key_cnt( acct_map ) );
  FD_LOG_NOTICE(( "Pass test_write_write_conflict_alt" ));
}

void test_read_write_conflict_alt_sentinel( fd_funk_t *                funk,
                                            fd_funk_txn_t *            funk_txn,
                                            fd_conflict_detect_ele_t * acct_map,
                                            fd_acct_addr_t *           acct_arr ) {
  const ulong txns_cnt     = 2UL;
  uchar * raw_txns[]       = { transfer_txn_A_B, transfer_txn_F_S };
  ulong raw_txns_len[]     = { sizeof(transfer_txn_A_B), sizeof(transfer_txn_F_S) };
  parse_txns( txns_cnt, raw_txns, raw_txns_len );

  fd_pubkey_t    alt_acct_addr;
  fd_acct_addr_t alt_acct_content[2];
  fd_base58_decode_32( "oQPnhXAbLbMuKHESaGrbXT17CyvWCpLyERSJA9HCYd7", alt_acct_addr.uc );
  fd_base58_decode_32( "6KUbAnWkuAmAoQX7iAAh7r8n2EjERbqao2t1hfPChwpH", alt_acct_content[0].b );
  /* Add sentinel (fd_acct_addr_null) to the address lookup table as an read-only account */
  fd_base58_decode_32( "JEKNVnkbo3jma5nREBBJCDoXFVeKkD56V3xKrvRmWxFG", alt_acct_content[1].b );

  add_address_lookup_table( funk,
                            funk_txn,
                            &alt_acct_addr,
                            (void*)&alt_acct_content,
                            sizeof(fd_acct_addr_t)*2,
                            transfer_txn_F_S,
                            sizeof(transfer_txn_F_S),
                            &txns[1],
                            &txn_sz[1],
                            &pay_sz[1] );

  fd_acct_addr_t conflict_acct;
  int detected;
  int err = fd_runtime_microblock_verify_read_write_conflicts(txns, txns_cnt, acct_map, acct_arr, funk, funk_txn, slot, NULL, &features, &detected, &conflict_acct );
  FD_TEST( err==FD_RUNTIME_TXN_ERR_ACCOUNT_IN_USE );
  FD_TEST( detected==FD_RUNTIME_READ_WRITE_CONFLICT_DETECTED );
  FD_TEST( 0==fd_conflict_detect_map_key_cnt( acct_map ) );
  FD_LOG_NOTICE(( "Pass test_read_write_conflict_alt_sentinel" ));
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  ulong cpu_idx = fd_tile_cpu_id( fd_tile_idx() );
  if( cpu_idx>fd_shmem_cpu_cnt() ) cpu_idx = 0UL;

  char const * _page_sz = fd_env_strip_cmdline_cstr ( &argc, &argv, "--page-sz",  NULL, "gigantic"                   );
  ulong        page_cnt = fd_env_strip_cmdline_ulong( &argc, &argv, "--page-cnt", NULL, 1UL                          );
  ulong        numa_idx = fd_env_strip_cmdline_ulong( &argc, &argv, "--numa-idx", NULL, fd_shmem_numa_idx( cpu_idx ) );

  ulong page_sz = fd_cstr_to_shmem_page_sz( _page_sz );
  if( FD_UNLIKELY( !page_sz ) ) FD_LOG_ERR(( "unsupported --page-sz" ));

  fd_wksp_t * wksp = fd_wksp_new_anonymous( page_sz, page_cnt, fd_shmem_cpu_idx( numa_idx ), "wksp", 0UL );
  FD_TEST( wksp );

  /**********************************************************************/
  /* Initialization                                                     */
  /**********************************************************************/

  int   lg_max_naccts = 20;
  ulong max_naccts    = 1UL<<lg_max_naccts;
  FD_LOG_NOTICE(( "fd_conflict_detect_map_footprint = %.1f MiB",
                  (double)fd_conflict_detect_map_footprint( lg_max_naccts )/1048576. ));

  void * acct_map_mem = fd_wksp_alloc_laddr( wksp, fd_conflict_detect_map_align(), fd_conflict_detect_map_footprint( lg_max_naccts ), 1234UL );
  void * acct_arr_mem = fd_wksp_alloc_laddr( wksp, 32UL, sizeof(fd_acct_addr_t)*max_naccts, 1235UL );
  ulong tag=2345UL, seed=5678UL, txn_max=1024;
  uint rec_max=1024;
  void * funk_mem     = fd_wksp_alloc_laddr( wksp, fd_funk_align(), fd_funk_footprint( txn_max, rec_max ), 1236UL );
  FD_TEST( funk_mem );
  FD_TEST( acct_arr_mem );
  FD_TEST( acct_map_mem );

  fd_conflict_detect_ele_t * acct_map = fd_conflict_detect_map_join( fd_conflict_detect_map_new( acct_map_mem, lg_max_naccts ) );
  fd_acct_addr_t *  acct_arr = acct_arr_mem;
  FD_TEST( fd_funk_new( funk_mem, tag, seed, txn_max, rec_max ) );
  fd_funk_t funk[1];
  FD_TEST( fd_funk_join( funk, funk_mem ) );

  fd_funk_txn_xid_t xid = {.ul={ slot+1, slot+1 }};
  fd_funk_txn_xid_t const * last_publish_xid = fd_funk_last_publish( funk );
  fd_funk_txn_map_t * txn_map = fd_funk_txn_map( funk );
  fd_funk_txn_t * last_publish = fd_funk_txn_query( last_publish_xid, txn_map );
  fd_funk_txn_t * funk_txn = fd_funk_txn_prepare( funk, last_publish, &xid, 1 );
  FD_TEST( funk_txn );

  /**********************************************************************/
  /* Unit test without address lookup tables                            */
  /**********************************************************************/
  test_no_conflict( acct_map, acct_arr );
  test_no_conflict_demote( acct_map, acct_arr );
  test_write_write_conflict( acct_map, acct_arr );
  test_write_write_conflict_sentinel( acct_map, acct_arr );

  /**********************************************************************/
  /* Unit test with address lookup tables                               */
  /**********************************************************************/

  test_no_conflict_alt( funk, funk_txn, acct_map, acct_arr );
  test_read_write_conflict_alt( funk, funk_txn, acct_map, acct_arr );
  test_write_write_conflict_alt( funk, funk_txn, acct_map, acct_arr );
  test_read_write_conflict_alt_sentinel( funk, funk_txn, acct_map, acct_arr );

  fd_funk_leave( funk, NULL );
  fd_wksp_free_laddr( acct_arr_mem );
  fd_wksp_free_laddr( acct_map_mem );
  fd_wksp_free_laddr( fd_funk_delete( funk_mem ) );
  fd_wksp_delete_anonymous( wksp );
  return 0;
}
