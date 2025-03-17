#include "../../util/fd_util_base.h"
#include "../fd_flamenco_base.h"
#include "fd_acc_mgr.h"
#include "fd_runtime.h"
#include "fd_runtime_err.h"
#include "fd_system_ids.h"
#include "program/fd_address_lookup_table_program.h"

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  /**********************************************************************/
  /* Specify conflict type in this unit test                            */
  /**********************************************************************/

#define TEST_NO_CONFLICT
//#define TEST_READ_WRITE
//#define TEST_WRITE_WRITE

#define ALT_TEST_NO_CONFLICT
//#define ALT_TEST_READ_WRITE
//#define ALT_TEST_WRITE_WRITE

  /**********************************************************************/
  /* Initialize and parse some raw transactions                         */
  /**********************************************************************/

  /* Raw transactions */
  uchar transfer_txn_A_B[] = { 0x01, 0x43, 0xbd, 0x5f, 0x69, 0x99, 0x81, 0x40, 0x3d, 0x30, 0x9e, 0x75, 0x7a, 0x07, 0xcb, 0xfc, 0x06, 0x7b, 0x2e, 0x79, 0xe9, 0x25, 0x12, 0xc5, 0x05, 0xc3, 0x08, 0x37, 0xe6, 0x8d, 0x02, 0x75, 0xa2, 0x94, 0xbd, 0xb7, 0xdf, 0x0d, 0x0b, 0xdb, 0xf4, 0x9a, 0x78, 0x02, 0x01, 0x22, 0x46, 0xff, 0xe3, 0x6f, 0x7c, 0x79, 0x10, 0x0f, 0x0a, 0xd8, 0x72, 0xd4, 0x6f, 0x60, 0x69, 0x8c, 0xa7, 0x97, 0x04, 0x01, 0x00, 0x01, 0x03, 0x44, 0xdf, 0x3e, 0x7e, 0xcf, 0x6f, 0x12, 0xce, 0xeb, 0x6c, 0xe3, 0x1f, 0x6a, 0x93, 0x0f, 0x74, 0x28, 0xb1, 0x27, 0x00, 0x04, 0x99, 0x8b, 0xc3, 0x24, 0xbf, 0xa7, 0x54, 0x57, 0x81, 0xa1, 0xfc, 0x48, 0x84, 0xd7, 0x6a, 0x5d, 0x48, 0x2a, 0xb6, 0xc2, 0x2b, 0x9b, 0xe0, 0x87, 0xd4, 0x7d, 0x4a, 0x72, 0xae, 0xc5, 0x45, 0x06, 0x02, 0xdb, 0xb5, 0xc1, 0xa6, 0x15, 0x0e, 0x60, 0xb6, 0x39, 0x1e, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xd0, 0x16, 0xca, 0x1b, 0xec, 0x8c, 0xfc, 0xd0, 0x43, 0xb4, 0x5a, 0x2a, 0xdd, 0x15, 0x4f, 0x93, 0xae, 0xdb, 0x0d, 0x67, 0x4c, 0x6d, 0xdb, 0x27, 0x59, 0x68, 0x37, 0xbe, 0x60, 0x9e, 0x68, 0x6f, 0x01, 0x02, 0x02, 0x00, 0x01, 0x0c, 0x02, 0x00, 0x00, 0x00, 0x40, 0x42, 0x0f, 0x00, 0x00, 0x00, 0x00, 0x00 };
  uchar transfer_txn_A_C[] = { 0x01, 0xe3, 0x33, 0x58, 0xff, 0xd4, 0x96, 0x12, 0xb2, 0x05, 0xd0, 0x43, 0xe1, 0x2f, 0xab, 0x9f, 0xd8, 0x16, 0x43, 0x30, 0x05, 0x74, 0x9d, 0x8a, 0xd4, 0x7a, 0x29, 0x21, 0x66, 0xab, 0x61, 0x02, 0x2a, 0x83, 0x79, 0x97, 0x7c, 0x9f, 0x01, 0x62, 0x0c, 0x67, 0x2e, 0xaf, 0x24, 0x72, 0x7d, 0x80, 0x41, 0xed, 0xb7, 0x0c, 0x4a, 0x86, 0x24, 0xd2, 0xbd, 0xd3, 0x8a, 0xe5, 0x7b, 0x69, 0x9e, 0x11, 0x0c, 0x01, 0x00, 0x01, 0x03, 0x44, 0xdf, 0x3e, 0x7e, 0xcf, 0x6f, 0x12, 0xce, 0xeb, 0x6c, 0xe3, 0x1f, 0x6a, 0x93, 0x0f, 0x74, 0x28, 0xb1, 0x27, 0x00, 0x04, 0x99, 0x8b, 0xc3, 0x24, 0xbf, 0xa7, 0x54, 0x57, 0x81, 0xa1, 0xfc, 0x3b, 0x63, 0x41, 0x60, 0x14, 0xfe, 0x84, 0xd2, 0xb9, 0x23, 0xc7, 0xa4, 0x23, 0x96, 0x80, 0x00, 0xe1, 0x88, 0x41, 0xa7, 0x41, 0x72, 0xef, 0xb9, 0x83, 0x3b, 0x3e, 0x48, 0x8c, 0xc4, 0xcc, 0x25, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xd0, 0x16, 0xca, 0x1b, 0xec, 0x8c, 0xfc, 0xd0, 0x43, 0xb4, 0x5a, 0x2a, 0xdd, 0x15, 0x4f, 0x93, 0xae, 0xdb, 0x0d, 0x67, 0x4c, 0x6d, 0xdb, 0x27, 0x59, 0x68, 0x37, 0xbe, 0x60, 0x9e, 0x68, 0x6f, 0x01, 0x02, 0x02, 0x00, 0x01, 0x0c, 0x02, 0x00, 0x00, 0x00, 0x40, 0x42, 0x0f, 0x00, 0x00, 0x00, 0x00, 0x00 };
  uchar transfer_txn_D_E[] = { 0x01, 0x5c, 0x4f, 0x9a, 0x58, 0x2f, 0xf0, 0x43, 0x63, 0x46, 0x7d, 0x65, 0xc4, 0x46, 0x2a, 0x5f, 0x39, 0xf2, 0xbb, 0xb5, 0xa8, 0xda, 0xc9, 0x77, 0x16, 0x84, 0xe9, 0x1d, 0x7a, 0xdb, 0x9c, 0x50, 0xdf, 0x14, 0x9f, 0x30, 0x91, 0x97, 0x27, 0xe5, 0xbc, 0xbe, 0xc5, 0x02, 0x56, 0x35, 0x71, 0xbf, 0xe7, 0xf9, 0x0d, 0x31, 0x98, 0xbc, 0xb0, 0x02, 0xb0, 0xa9, 0xf6, 0x7e, 0xd8, 0xb5, 0x09, 0xd1, 0x08, 0x01, 0x00, 0x01, 0x03, 0xc1, 0xb7, 0x76, 0x33, 0xc6, 0x60, 0x09, 0x44, 0x5b, 0xe5, 0x65, 0xac, 0x18, 0x04, 0x16, 0x58, 0x77, 0x8d, 0x1b, 0x9c, 0xdc, 0x55, 0xca, 0x23, 0xfc, 0xab, 0xfa, 0xca, 0xfb, 0x1a, 0x32, 0x29, 0xf2, 0x13, 0xa1, 0x1d, 0x1e, 0x1e, 0xab, 0x4c, 0x0b, 0x45, 0x41, 0xee, 0x68, 0x18, 0xbe, 0x29, 0xe9, 0x61, 0xed, 0xd6, 0x1e, 0xaa, 0xea, 0x51, 0x08, 0x73, 0x65, 0x94, 0xe3, 0x6e, 0xfc, 0x8e, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xd0, 0x16, 0xca, 0x1b, 0xec, 0x8c, 0xfc, 0xd0, 0x43, 0xb4, 0x5a, 0x2a, 0xdd, 0x15, 0x4f, 0x93, 0xae, 0xdb, 0x0d, 0x67, 0x4c, 0x6d, 0xdb, 0x27, 0x59, 0x68, 0x37, 0xbe, 0x60, 0x9e, 0x68, 0x6f, 0x01, 0x02, 0x02, 0x00, 0x01, 0x0c, 0x02, 0x00, 0x00, 0x00, 0x40, 0x42, 0x0f, 0x00, 0x00, 0x00, 0x00, 0x00 };
  uchar write_transfer_program[] = { 0x01, 0xbf, 0xbf, 0x82, 0x6b, 0x2a, 0xb1, 0xbf, 0xe1, 0x69, 0x22, 0x33, 0x33, 0x1a, 0xde, 0xb3, 0xf4, 0x21, 0x63, 0x86, 0x6e, 0xbe, 0x93, 0xd3, 0x84, 0x9b, 0x6e, 0x41, 0xc3, 0x3f, 0xae, 0x78, 0xc3, 0x25, 0x0e, 0x0e, 0x40, 0x4e, 0x4a, 0xd9, 0x6c, 0xaa, 0xfc, 0x85, 0xdc, 0xab, 0x8c, 0xa1, 0xfe, 0x41, 0xa9, 0xa4, 0xaa, 0x66, 0xb9, 0x7e, 0x3a, 0x40, 0x47, 0x98, 0x60, 0x40, 0xcb, 0xbe, 0x0a, 0x01, 0x00, 0x00, 0x02, 0x8a, 0x85, 0xc7, 0x45, 0x4e, 0xb4, 0x36, 0xfd, 0x29, 0x1d, 0x2a, 0x68, 0xe3, 0xf2, 0x10, 0xed, 0x96, 0x58, 0xdb, 0x33, 0x32, 0xc7, 0x11, 0x4b, 0xcf, 0x91, 0xb0, 0xc6, 0x64, 0xce, 0xfa, 0xb6, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xd0, 0x16, 0xca, 0x1b, 0xec, 0x8c, 0xfc, 0xd0, 0x43, 0xb4, 0x5a, 0x2a, 0xdd, 0x15, 0x4f, 0x93, 0xae, 0xdb, 0x0d, 0x67, 0x4c, 0x6d, 0xdb, 0x27, 0x59, 0x68, 0x37, 0xbe, 0x60, 0x9e, 0x68, 0x6f, 0x01, 0x01, 0x02, 0x00, 0x01, 0x0c, 0x02, 0x00, 0x00, 0x00, 0x40, 0x42, 0x0f, 0x00, 0x00, 0x00, 0x00, 0x00 };
  (void) transfer_txn_A_B;
  (void) transfer_txn_A_C;
  (void) transfer_txn_D_E;
  (void) write_transfer_program;

#ifdef TEST_NO_CONFLICT
  /* independent transfers should not trigger any conflicts */
  const ulong txns_cnt = 2UL;
  uchar * raw_txns[]       = { transfer_txn_A_B, transfer_txn_D_E };
  ulong raw_txns_len[]     = { sizeof(transfer_txn_A_B), sizeof(transfer_txn_D_E) };
#endif

#ifdef TEST_READ_WRITE
  /* transfer_txn_A_B and write_transfer_program will trigger read-write conflict
   * because the transfer system program is read only in transfer_txn_A_B */
  const ulong txns_cnt = 2UL;
  uchar * raw_txns[]       = { transfer_txn_A_B, write_transfer_program };
  ulong raw_txns_len[]     = { sizeof(transfer_txn_A_B), sizeof(write_transfer_program) };
#endif

#ifdef TEST_WRITE_WRITE
  /* transfer_txn_A_B and transfer_txn_A_C will trigger write-write conflict
   * because the two transfers have the same sender account */
  const ulong txns_cnt = 3UL;
  uchar * raw_txns[]       = { transfer_txn_A_B, transfer_txn_D_E, transfer_txn_A_C };
  ulong raw_txns_len[]     = { sizeof(transfer_txn_A_B), sizeof(transfer_txn_D_E), sizeof(transfer_txn_A_C) };
#endif

  /* TODO: use slot meaningfully for address lookup tables */
  ulong slot = 100;

  /* Parse the transactions into fd_txn_p_t */
  fd_txn_p_t txns[txns_cnt];
  ulong txn_sz[txns_cnt], pay_sz[txns_cnt];

  for( ulong i=0; i<txns_cnt; i++ ) {
      txns[i].payload_sz = raw_txns_len[i];
      fd_memcpy( txns[i].payload, raw_txns[i], txns[i].payload_sz );
      txn_sz[i] = fd_txn_parse_core( txns[i].payload, txns[i].payload_sz, TXN( &txns[i] ), NULL, &pay_sz[i] );
      FD_LOG_NOTICE(( "Txn#%lu has payload size %lu, %u+%u read-only accts, total=%u", i, txns[i].payload_sz,
TXN( &txns[i] )->readonly_unsigned_cnt, TXN( &txns[i] )->readonly_signed_cnt, TXN( &txns[i] )->acct_addr_cnt ));

      if( FD_UNLIKELY( !pay_sz[i] || !txn_sz[i] || txn_sz[i] > FD_TXN_MTU ) )
        FD_LOG_ERR(( "failed to parse transaction #%lu", i ));
  }

  /**********************************************************************/
  /* Unit test without address lookup tables                            */
  /**********************************************************************/

  /* Create a map for inserting all accounts written by txns */
  fd_wksp_t * wksp    = fd_wksp_new_anonymous( fd_cstr_to_shmem_page_sz( "gigantic" ), 5UL, fd_log_cpu_id(), "wksp", 0UL );
  int lg_max_naccts   = fd_ulong_find_msb( fd_ulong_pow2_up( FD_TXN_CONFLICT_MAP_MAX_NACCT ) );
  void * acct_map_mem = fd_wksp_alloc_laddr( wksp, fd_txn_writes_align(), fd_txn_writes_footprint( lg_max_naccts ), 1234UL );
  void * bitvec_mem   = fd_wksp_alloc_laddr( wksp, fd_txn_writes_bitvec_align(), fd_txn_writes_bitvec_footprint(), 1235UL );
  ulong tag=2345UL, seed=5678UL, txn_max=1024, rec_max=1024;
  void * funk_mem     = fd_wksp_alloc_laddr( wksp, fd_funk_align(), fd_funk_footprint(), tag );
  void * acc_mgr_mem  = fd_wksp_alloc_laddr( wksp,  FD_ACC_MGR_ALIGN, FD_ACC_MGR_FOOTPRINT, 3456UL );
  FD_TEST( funk_mem );
  FD_TEST( bitvec_mem );
  FD_TEST( acct_map_mem );

  fd_txn_writes_t *      acct_map = fd_txn_writes_join( fd_txn_writes_new( acct_map_mem, lg_max_naccts ) );
  fd_funk_t *                funk = fd_funk_new( funk_mem, tag, seed, txn_max, rec_max );
  fd_txn_writes_bitvec_t * bitvec = fd_txn_writes_bitvec_join( fd_txn_writes_bitvec_new( bitvec_mem ) );
  fd_acc_mgr_t *          acc_mgr = fd_acc_mgr_new( acc_mgr_mem, funk );
  FD_TEST( funk==funk_mem );
  FD_TEST( bitvec==bitvec_mem );

  FD_LOG_NOTICE(( "Allocating %lu MB for the account map", fd_txn_writes_footprint( lg_max_naccts )/1024/1024 ));

  /* Detect conflicts among the txn_cnt transactions in txns */
  FD_LOG_NOTICE(( "Detecting conflicts among %lu transactions", txns_cnt ));
  fd_acct_addr_t conflict_acct;
  int err = fd_runtime_microblock_verify_read_write_conflicts(txns, txns_cnt, acct_map, bitvec, NULL, NULL, slot, NULL, &conflict_acct );
  if( err==FD_RUNTIME_EXECUTE_SUCCESS ) FD_LOG_WARNING(( "No conflicts detected among %lu txns", txns_cnt ));
  if( err==FD_RUNTIME_TXN_ERR_OUT_OF_MEMORY_WHEN_DETECTING_CONFLICTS ) FD_LOG_ERR(( "The acct_map provided is too small" ));
  if( err==FD_RUNTIME_TXN_ERR_READ_WRITE_CONFLICT ) FD_LOG_ERR(( "Read-write conflicts detected among %lu txns for acct=%s",
                                                                 txns_cnt,
                                                                 FD_BASE58_ENC_32_ALLOCA( &conflict_acct ) ));
  if( err==FD_RUNTIME_TXN_ERR_WRITE_WRITE_CONFLICT ) FD_LOG_ERR(( "Write-write conflicts detected among %lu txns for acct=%s",
                                                                  txns_cnt,
                                                                  FD_BASE58_ENC_32_ALLOCA( &conflict_acct ) ));

  /**********************************************************************/
  /* Unit test with address lookup tables                               */
  /**********************************************************************/

  /* Add an account with 2 addresses as content into funk */
  /* Note: 5drANtynCaE2fbXFMaWxSeB8BvHmdBNfb32PnGdpFr6P is the A in transfer_txn_A_B */
  #define ALT_PUBKEY_NUM 2
  fd_pubkey_t    alt_acct_addr;
  fd_acct_addr_t alt_acct_content[ALT_PUBKEY_NUM];

#ifdef ALT_TEST_NO_CONFLICT
  /* The conflicting account is not in the address lookup table */
  fd_base58_decode_32( "oQPnhXAbLbMuKHESaGrbXT17CyvWCpLyERSJA9HCYd7", alt_acct_addr.uc );
  fd_base58_decode_32( "6KUbAnWkuAmAoQX7iAAh7r8n2EjERbqao2t1hfPChwpH", alt_acct_content[0].b );
  fd_base58_decode_32( "AEK3Z5CGNgmRQHxK9sRHbbn6MJ5oCg5M96qsXjQJE123", alt_acct_content[1].b );
#endif

#ifdef ALT_TEST_READ_WRITE
  /* The conflicting account is read-only in the address lookup table */
  fd_base58_decode_32( "oQPnhXAbLbMuKHESaGrbXT17CyvWCpLyERSJA9HCYd7", alt_acct_addr.uc );
  fd_base58_decode_32( "6KUbAnWkuAmAoQX7iAAh7r8n2EjERbqao2t1hfPChwpH", alt_acct_content[0].b );
  fd_base58_decode_32( "5drANtynCaE2fbXFMaWxSeB8BvHmdBNfb32PnGdpFr6P", alt_acct_content[1].b );
#endif

#ifdef ALT_TEST_WRITE_WRITE
  /* The conflicting account is writable in the address lookup table */
  fd_base58_decode_32( "oQPnhXAbLbMuKHESaGrbXT17CyvWCpLyERSJA9HCYd7", alt_acct_addr.uc );
  fd_base58_decode_32( "5drANtynCaE2fbXFMaWxSeB8BvHmdBNfb32PnGdpFr6P", alt_acct_content[0].b );
  fd_base58_decode_32( "6KUbAnWkuAmAoQX7iAAh7r8n2EjERbqao2t1hfPChwpH", alt_acct_content[1].b );
#endif

  /* Initialize a funk for the unit test */

  fd_funk_txn_t * txn_map = fd_funk_txn_map( funk, wksp ); FD_TEST( txn_map );
  FD_TEST( fd_funk_txn_max( funk )==txn_max );

  fd_funk_start_write( funk );

  /* Suppose the current funk txn is at slot #302 */
  fd_funk_txn_xid_t xid = {.ul={ 302UL, 302UL }};
  fd_funk_txn_xid_t const * last_publish_xid = fd_funk_last_publish( funk );
  fd_funk_txn_t * last_publish = fd_funk_txn_query( last_publish_xid, txn_map );
  fd_funk_txn_t * funk_txn = fd_funk_txn_prepare( funk, last_publish, &xid, 1 );
  FD_TEST( funk_txn );

  FD_TXN_ACCOUNT_DECL( rec );
  const ulong rec_sz = FD_LOOKUP_TABLE_META_SIZE+sizeof(alt_acct_content);
  int result = fd_acc_mgr_modify( acc_mgr, funk_txn, &alt_acct_addr, /* do_create */ 1, rec_sz, rec );
  FD_TEST( result==FD_ACC_MGR_SUCCESS );

  fd_address_lookup_table_state_t table;
  table.discriminant = fd_address_lookup_table_state_enum_lookup_table;
  table.inner.lookup_table.meta.deactivation_slot  = ULONG_MAX;
  table.inner.lookup_table.meta.last_extended_slot = 0; /* this makes fd_get_active_addresses_len return 2 */

  fd_bincode_encode_ctx_t encode_ctx = {
    .data    = rec->data,
    .dataend = rec->data + FD_LOOKUP_TABLE_META_SIZE
  };
  err = fd_address_lookup_table_state_encode( &table, &encode_ctx );
  FD_TEST( err==0 );

  rec->meta->dlen = rec_sz;
  fd_memcpy( rec->meta->info.owner, fd_solana_address_lookup_table_program_id.key, sizeof(fd_pubkey_t) );
  fd_memcpy( rec->data+FD_LOOKUP_TABLE_META_SIZE, &alt_acct_content, sizeof(alt_acct_content) );
  /* other metadata fields (e.g., slot, hash, ...) are ommited */

  fd_funk_end_write( funk );

  /* Add an address lookup table at the end of raw txn transfer_txn_D_E */
  fd_txn_acct_addr_lut_t alt = {
    .addr_off=sizeof(transfer_txn_D_E)+sizeof(fd_txn_acct_addr_lut_t),
    .writable_cnt=1,
    .readonly_cnt=1,
    .writable_off=sizeof(transfer_txn_D_E)+sizeof(fd_txn_acct_addr_lut_t)+sizeof(fd_acct_addr_t),
    .readonly_off=sizeof(transfer_txn_D_E)+sizeof(fd_txn_acct_addr_lut_t)+sizeof(fd_acct_addr_t)+sizeof(uchar)
  };
  /*                               original txn binary      lookup table struct            lookup table address   address indexes */
  uchar transfer_txn_D_E_with_alt[ sizeof(transfer_txn_D_E)+sizeof(fd_txn_acct_addr_lut_t)+sizeof(fd_acct_addr_t)+sizeof(uchar)*2 ];
  fd_memcpy( transfer_txn_D_E_with_alt, transfer_txn_D_E, sizeof(transfer_txn_D_E) );
  fd_memcpy( transfer_txn_D_E_with_alt+sizeof(transfer_txn_D_E), &alt, sizeof(fd_txn_acct_addr_lut_t) );
  fd_memcpy( transfer_txn_D_E_with_alt+sizeof(transfer_txn_D_E)+sizeof(fd_txn_acct_addr_lut_t),
             alt_acct_addr.uc, sizeof(fd_acct_addr_t) );
  transfer_txn_D_E_with_alt[ sizeof(transfer_txn_D_E_with_alt)-2 ] = 0;
  transfer_txn_D_E_with_alt[ sizeof(transfer_txn_D_E_with_alt)-1 ] = 1;

  /* Parse transaction transfer_txn_D_E_with_alt into txns[1] */
  txns[1].payload_sz = sizeof(transfer_txn_D_E_with_alt);
  fd_memcpy( txns[1].payload, transfer_txn_D_E_with_alt, txns[1].payload_sz );
  txn_sz[1] = fd_txn_parse_core( txns[1].payload, txns[1].payload_sz, TXN( &txns[1] ), NULL, &pay_sz[1] );
  FD_LOG_NOTICE(( "Txn#%lu has payload size %lu, %u+%u read-only accts, total=%u", 1UL, txns[1].payload_sz,
                  TXN( &txns[1] )->readonly_unsigned_cnt, TXN( &txns[1] )->readonly_signed_cnt, TXN( &txns[1] )->acct_addr_cnt ));

  if( FD_UNLIKELY( !pay_sz[1] || !txn_sz[1] || txn_sz[1] > FD_TXN_MTU ) )
    FD_LOG_ERR(( "failed to parse transaction #%lu", 1UL ));

  /* Add the address lookup table into the parsed txn */
  TXN( &txns[1] )->transaction_version          = FD_TXN_V0;
  TXN( &txns[1] )->addr_table_lookup_cnt        = 1;
  TXN( &txns[1] )->addr_table_adtl_writable_cnt = 1;
  TXN( &txns[1] )->addr_table_adtl_cnt          = 2;
  fd_txn_acct_addr_lut_t * addr_luts = fd_txn_get_address_tables( TXN( &txns[1] ) );
  fd_memcpy( addr_luts, &alt, sizeof(fd_txn_acct_addr_lut_t) );

  /* Detect txn conflict again */
  err = fd_runtime_microblock_verify_read_write_conflicts(txns, txns_cnt, acct_map, bitvec, acc_mgr, funk_txn, slot, NULL, &conflict_acct );
  if( err==FD_RUNTIME_EXECUTE_SUCCESS ) FD_LOG_WARNING(( "No conflicts detected among %lu txns w/ ALT", txns_cnt ));
  if( err==FD_RUNTIME_TXN_ERR_OUT_OF_MEMORY_WHEN_DETECTING_CONFLICTS ) FD_LOG_ERR(( "The acct_map provided is too small w/ ALT" ));
  if( err==FD_RUNTIME_TXN_ERR_READ_WRITE_CONFLICT ) FD_LOG_ERR(( "Read-write conflicts detected among %lu txns w/ ALT for acct=%s",
                                                                 txns_cnt,
                                                                 FD_BASE58_ENC_32_ALLOCA( &conflict_acct ) ));
  if( err==FD_RUNTIME_TXN_ERR_WRITE_WRITE_CONFLICT ) FD_LOG_ERR(( "Write-write conflicts detected among %lu txns w/ ALT for acct=%s",
                                                                  txns_cnt,
                                                                  FD_BASE58_ENC_32_ALLOCA( &conflict_acct ) ));

  err = fd_runtime_microblock_verify_read_write_conflicts(NULL, 0, acct_map, bitvec, acc_mgr, funk_txn, slot, NULL, NULL);
  FD_TEST( err==FD_RUNTIME_EXECUTE_SUCCESS );
  FD_TEST( fd_txn_writes_key_cnt( acct_map )==0 );

  return 0;
}
