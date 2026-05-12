#include "fd_svm_mini.h"
#include "../fd_bank.h"
#include "../fd_blockhashes.h"
#include "../fd_runtime_err.h"
#include "../fd_txncache.h"
#include "../fd_txncache_shmem.h"
#include "../../../ballet/txn/fd_compact_u16.h"
#include "../../../disco/fd_txn_p.h"
#include <stdlib.h>

#define FD_CHECKED_ADD_TO_TXN_DATA( _begin, _cur_data, _to_add, _sz ) __extension__({ \
  if( FD_UNLIKELY( (*_cur_data)+(_sz)>_begin+FD_TXN_MTU ) ) return;                  \
  fd_memcpy( *_cur_data, _to_add, _sz );                                             \
  *_cur_data += (_sz);                                                               \
})

#define FD_CHECKED_ADD_CU16_TO_TXN_DATA( _begin, _cur_data, _to_add ) __extension__({ \
  do {                                                                               \
    uchar _buf[3];                                                                   \
    ulong _sz = (ulong)fd_cu16_enc( (ushort)(_to_add), _buf );                       \
    FD_CHECKED_ADD_TO_TXN_DATA( _begin, _cur_data, _buf, _sz );                      \
  } while(0);                                                                        \
})

static void
test_txn_serialize( fd_txn_p_t *        out,
                    fd_pubkey_t const * fee_payer,
                    fd_hash_t const *   recent_blockhash ) {
  uchar * txn_raw_begin   = out->payload;
  uchar * txn_raw_cur_ptr = txn_raw_begin;

  uchar signature_cnt = 1U;
  FD_CHECKED_ADD_TO_TXN_DATA( txn_raw_begin, &txn_raw_cur_ptr, &signature_cnt, sizeof(uchar) );

  fd_signature_t sig = {0};
  FD_CHECKED_ADD_TO_TXN_DATA( txn_raw_begin, &txn_raw_cur_ptr, &sig, FD_TXN_SIGNATURE_SZ );

  uchar header_b0 = (uchar)0x80UL;
  FD_CHECKED_ADD_TO_TXN_DATA( txn_raw_begin, &txn_raw_cur_ptr, &header_b0, sizeof(uchar) );

  uchar num_req_sigs    = 1U;
  uchar num_ro_signed   = 0U;
  uchar num_ro_unsigned = 0U;
  FD_CHECKED_ADD_TO_TXN_DATA( txn_raw_begin, &txn_raw_cur_ptr, &num_req_sigs,    1UL );
  FD_CHECKED_ADD_TO_TXN_DATA( txn_raw_begin, &txn_raw_cur_ptr, &num_ro_signed,   1UL );
  FD_CHECKED_ADD_TO_TXN_DATA( txn_raw_begin, &txn_raw_cur_ptr, &num_ro_unsigned, 1UL );

  ushort account_keys_cnt = 1U;
  FD_CHECKED_ADD_CU16_TO_TXN_DATA( txn_raw_begin, &txn_raw_cur_ptr, account_keys_cnt );
  FD_CHECKED_ADD_TO_TXN_DATA( txn_raw_begin, &txn_raw_cur_ptr, fee_payer, sizeof(fd_pubkey_t) );

  FD_CHECKED_ADD_TO_TXN_DATA( txn_raw_begin, &txn_raw_cur_ptr, recent_blockhash, sizeof(fd_hash_t) );

  ushort instr_cnt = 0U;
  FD_CHECKED_ADD_CU16_TO_TXN_DATA( txn_raw_begin, &txn_raw_cur_ptr, instr_cnt );

  ushort addr_table_cnt = 0U;
  FD_CHECKED_ADD_CU16_TO_TXN_DATA( txn_raw_begin, &txn_raw_cur_ptr, addr_table_cnt );

  out->payload_sz = (ushort)(txn_raw_cur_ptr - txn_raw_begin);
}

static fd_txncache_t *
test_txncache_new( void ) {
  ulong shmem_align = fd_txncache_shmem_align();
  ulong shmem_sz    = fd_ulong_align_up( fd_txncache_shmem_footprint( 4UL, 16UL ), shmem_align );
  void * shmem = aligned_alloc( shmem_align, shmem_sz );
  FD_TEST( shmem );
  fd_txncache_shmem_t * shcache = fd_txncache_shmem_join( fd_txncache_shmem_new( shmem, 4UL, 16UL ) );
  FD_TEST( shcache );

  ulong ljoin_align = fd_txncache_align();
  ulong ljoin_sz    = fd_ulong_align_up( fd_txncache_footprint( 4UL ), ljoin_align );
  void * ljoin = aligned_alloc( ljoin_align, ljoin_sz );
  FD_TEST( ljoin );
  return fd_txncache_join( fd_txncache_new( ljoin, shcache ) );
}

static void
test_duplicate_txn_in_block_rejected( fd_svm_mini_t * mini ) {
  fd_svm_mini_params_t params[1];
  fd_svm_mini_params_default( params );
  params->root_slot = 10UL;

  ulong root_idx = fd_svm_mini_reset( mini, params );
  fd_bank_t * root_bank = fd_svm_mini_bank( mini, root_idx );
  FD_TEST( root_bank );

  fd_txncache_t * txncache = test_txncache_new();
  FD_TEST( txncache );
  mini->runtime->status_cache = txncache;

  fd_txncache_fork_id_t null_fork = { .val = USHORT_MAX };
  root_bank->txncache_fork_id = fd_txncache_attach_child( txncache, null_fork );
  fd_txncache_finalize_fork( txncache, root_bank->txncache_fork_id, 0UL, root_bank->f.poh.uc );

  ulong block_idx = fd_svm_mini_attach_child( mini, root_idx, 11UL );
  fd_bank_t * block_bank = fd_svm_mini_bank( mini, block_idx );
  FD_TEST( block_bank );
  block_bank->txncache_fork_id = fd_txncache_attach_child( txncache, root_bank->txncache_fork_id );

  fd_pubkey_t fee_payer = { .ul = { 0xFEEDUL, 0UL, 0UL, 0UL } };
  fd_xid_t block_xid = fd_bank_xid( block_bank );
  fd_svm_mini_add_lamports( mini, &block_xid, &fee_payer, 1000000000UL );

  fd_hash_t const * recent_blockhash = fd_blockhashes_peek_last_hash( &block_bank->f.block_hash_queue );
  FD_TEST( recent_blockhash );

  fd_txn_p_t txn = {0};
  test_txn_serialize( &txn, &fee_payer, recent_blockhash );
  FD_TEST( txn.payload_sz );
  FD_TEST( fd_txn_parse( txn.payload, txn.payload_sz, TXN( &txn ), NULL ) );

  fd_txn_in_t txn_in = {0};
  txn_in.txn = &txn;

  fd_txn_out_t first = {0};
  fd_runtime_prepare_and_execute_txn( mini->runtime, block_bank, &txn_in, &first );
  FD_TEST( first.err.is_committable );
  FD_TEST( first.err.txn_err==FD_RUNTIME_EXECUTE_SUCCESS );
  fd_runtime_commit_txn( mini->runtime, block_bank, &first );

  fd_txn_out_t second = {0};
  fd_runtime_prepare_and_execute_txn( mini->runtime, block_bank, &txn_in, &second );
  FD_TEST( !second.err.is_committable );
  FD_TEST( second.err.txn_err==FD_RUNTIME_TXN_ERR_ALREADY_PROCESSED );
  fd_runtime_cancel_txn( mini->runtime, &second );

  fd_svm_mini_cancel_fork( mini, block_idx );
}

int
main( int     argc,
      char ** argv ) {
  fd_svm_mini_limits_t limits[1];
  fd_svm_mini_limits_default( limits );
  limits->max_accounts        = 256UL;
  limits->max_txn_write_locks = 8UL;

  fd_svm_mini_t * mini = fd_svm_test_boot( &argc, &argv, limits );

  test_duplicate_txn_in_block_rejected( mini );

  FD_LOG_NOTICE(( "pass" ));
  fd_svm_test_halt( mini );
  return 0;
}
