#include "fd_txn_account.h"
#include "fd_acc_mgr.h"

int
main( int argc, char ** argv ) {
  fd_boot( &argc, &argv );

  char *      _page_sz = "gigantic";
  ulong       numa_idx = fd_shmem_numa_idx( 0 );
  fd_wksp_t * wksp     = fd_wksp_new_anonymous( fd_cstr_to_shmem_page_sz( _page_sz ),
                                                1UL,
                                                fd_shmem_cpu_idx( numa_idx ),
                                                "wksp",
                                                0UL );
  void * tx_acc_mem = fd_wksp_alloc_laddr( wksp, FD_TXN_ACCOUNT_ALIGN, FD_TXN_ACCOUNT_FOOTPRINT, 1UL );
  FD_TEST( tx_acc_mem );

  fd_pubkey_t pubkey = { .ul = { 9, 10 } };

  uchar * data  = fd_wksp_alloc_laddr( wksp, 1UL, 1000UL, 1UL );
  uchar * data2 = fd_wksp_alloc_laddr( wksp, 1UL, 1000UL, 1UL );
  fd_account_meta_t * meta = (fd_account_meta_t *)data;
  fd_account_meta_init( meta );
  meta->dlen = 100UL;
  uchar * acc_data = fd_account_meta_get_data( meta );

  FD_TEST( !fd_txn_account_new( NULL, &pubkey, meta, 0 ) );
  FD_TEST( !fd_txn_account_new( tx_acc_mem, NULL, meta, 0 ) );
  FD_TEST( !fd_txn_account_new( tx_acc_mem, &pubkey, NULL, 0 ) );

  uchar * new_tx_account = fd_txn_account_new( tx_acc_mem, &pubkey, meta, 0 );
  FD_TEST( new_tx_account );

  FD_TEST( !fd_txn_account_join( NULL, wksp ) );
  FD_TEST( !fd_txn_account_join( data2, wksp ) );
  FD_TEST( !fd_txn_account_join( tx_acc_mem, NULL ) );
  fd_txn_account_t * txn_account = fd_txn_account_join( tx_acc_mem, wksp );
  FD_TEST( txn_account );

  /* TODO: These tests do not enforce that the account is read-only
     because the current impl calls FD_LOG_CRIT when the account is
     not mutable but the caller calls a mutator. */

  uchar null_hash[32] = { 0 };

  FD_TEST( !fd_txn_account_is_mutable( txn_account ) );
  FD_TEST( fd_txn_account_is_readonly( txn_account ) );
  FD_TEST( fd_txn_account_get_data_len( txn_account ) == 100UL );
  FD_TEST( fd_txn_account_get_lamports( txn_account ) == 0UL );
  FD_TEST( fd_txn_account_get_rent_epoch( txn_account ) == ULONG_MAX );
  FD_TEST( !memcmp( fd_txn_account_get_hash( txn_account ), null_hash, sizeof(null_hash) ) );
  FD_TEST( !memcmp( fd_txn_account_get_owner( txn_account ), null_hash, sizeof(null_hash) ) );
  FD_TEST( fd_txn_account_get_meta( txn_account ) == meta );
  FD_TEST( fd_txn_account_get_data( txn_account ) == acc_data );

  FD_TEST( fd_txn_account_leave( txn_account ) );

  FD_TEST( fd_txn_account_join( fd_txn_account_leave( txn_account ), wksp ) );
  FD_TEST( !fd_txn_account_leave( NULL ) );

  uchar * deleted_tx_account = fd_txn_account_delete( fd_txn_account_leave( txn_account ) );
  FD_TEST( deleted_tx_account );
  FD_TEST( !fd_txn_account_join( deleted_tx_account, wksp ) );
  FD_TEST( !fd_txn_account_delete( NULL ) );

  /* Repeat similar tests with a mutable account */

  meta->dlen = 101UL;
  txn_account = fd_txn_account_join( fd_txn_account_new( tx_acc_mem, &pubkey, meta, 1 ), wksp );
  FD_TEST( txn_account );

  FD_TEST( fd_txn_account_is_mutable( txn_account ) );
  FD_TEST( !fd_txn_account_is_readonly( txn_account ) );
  FD_TEST( fd_txn_account_get_data_len( txn_account ) == 101UL );
  FD_TEST( fd_txn_account_get_lamports( txn_account ) == 0UL );

  fd_txn_account_set_lamports( txn_account, 1000UL );
  FD_TEST( fd_txn_account_get_lamports( txn_account ) == 1000UL );

  fd_txn_account_set_rent_epoch( txn_account, 100UL );
  FD_TEST( fd_txn_account_get_rent_epoch( txn_account ) == 100UL );

  fd_txn_account_set_data_len( txn_account, 102UL );
  FD_TEST( fd_txn_account_get_data_len( txn_account ) == 102UL );
  FD_TEST( fd_txn_account_delete( fd_txn_account_leave( txn_account ) ) );

  FD_LOG_NOTICE(( "pass" ));

  fd_halt();
  return 0;
}
