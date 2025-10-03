#include "fd_sysvar_recent_hashes.h"
#include "../fd_acc_mgr.h"
#include "fd_sysvar.h"
#include "../fd_system_ids.h"

/* Skips fd_types encoding preflight checks and directly serializes the
   blockhash queue into a buffer representing account data for the
   recent blockhashes sysvar. */

static void
encode_rbh_from_blockhash_queue( fd_bank_t * bank,
                                 uchar       out_mem[ FD_SYSVAR_RECENT_HASHES_BINCODE_SZ ] ) {
  fd_blockhashes_t const * bhq = fd_bank_block_hash_queue_query( bank );

  ulong queue_sz = fd_blockhash_deq_cnt( bhq->d.deque );
  ulong out_max  = fd_ulong_min( queue_sz, FD_SYSVAR_RECENT_HASHES_CAP );

  uchar * enc = out_mem;
  fd_memcpy( enc, &out_max, sizeof(ulong) );

  enc += sizeof(ulong);

  /* Iterate over blockhash queue and encode the recent blockhashes.
     We can do direct memcpying and avoid redundant checks from fd_types
     encoders since the enc buffer is already sized out to the
     worst-case bound. */
  ulong out_idx = 0UL;
  for( fd_blockhash_deq_iter_t iter = fd_blockhash_deq_iter_init_rev( bhq->d.deque );
       out_idx<FD_SYSVAR_RECENT_HASHES_CAP &&
          !fd_blockhash_deq_iter_done_rev( bhq->d.deque, iter );
       out_idx++,   iter = fd_blockhash_deq_iter_prev( bhq->d.deque, iter ) ) {
    fd_blockhash_info_t const * n = fd_blockhash_deq_iter_ele_const( bhq->d.deque, iter );
    fd_memcpy( enc, n->hash.uc, 32 );
    FD_STORE( ulong, enc+32, n->fee_calculator.lamports_per_signature );
    enc += 40;
  }
}

void
fd_sysvar_recent_hashes_init( fd_bank_t *               bank,
                              fd_funk_t *               funk,
                              fd_funk_txn_xid_t const * xid,
                              fd_capture_ctx_t *        capture_ctx ) {
  uchar enc[ FD_SYSVAR_RECENT_HASHES_BINCODE_SZ ] = {0};
  encode_rbh_from_blockhash_queue( bank, enc );
  fd_sysvar_account_update( bank, funk, xid, capture_ctx, &fd_sysvar_recent_block_hashes_id, enc, FD_SYSVAR_RECENT_HASHES_BINCODE_SZ );
}

// https://github.com/anza-xyz/agave/blob/e8750ba574d9ac7b72e944bc1227dc7372e3a490/accounts-db/src/blockhash_queue.rs#L113
static void
register_blockhash( fd_bank_t *       bank,
                    fd_hash_t const * hash ) {
  fd_blockhashes_t * bhq = fd_bank_block_hash_queue_modify( bank );
  fd_blockhash_info_t * bh = fd_blockhashes_push_new( bhq, hash );
  bh->fee_calculator = (fd_fee_calculator_t){
    .lamports_per_signature = fd_bank_lamports_per_signature_get( bank )
  };
}

/* This implementation is more consistent with Agave's bank implementation for updating the block hashes sysvar:
   1. Update the block hash queue with the latest poh
   2. Take the first 150 blockhashes from the queue (or fewer if there are)
   3. Manually serialize the recent blockhashes
   4. Set the sysvar account with the new data */
void
fd_sysvar_recent_hashes_update( fd_bank_t *               bank,
                                fd_funk_t *               funk,
                                fd_funk_txn_xid_t const * xid,
                                fd_capture_ctx_t *        capture_ctx ) {
  register_blockhash( bank, fd_bank_poh_query( bank ) );

  uchar enc[ FD_SYSVAR_RECENT_HASHES_BINCODE_SZ ] = {0};
  encode_rbh_from_blockhash_queue( bank, enc );
  fd_sysvar_account_update( bank, funk, xid, capture_ctx, &fd_sysvar_recent_block_hashes_id, enc, sizeof(enc) );
}

fd_recent_block_hashes_t *
fd_sysvar_recent_hashes_read( fd_funk_t * funk, fd_funk_txn_xid_t const * xid, fd_spad_t * spad ) {
  FD_TXN_ACCOUNT_DECL( acc );
  int err = fd_txn_account_init_from_funk_readonly( acc, &fd_sysvar_recent_block_hashes_id, funk, xid );
  if( FD_UNLIKELY( err != FD_ACC_MGR_SUCCESS ) )
    return NULL;

  fd_bincode_decode_ctx_t ctx = {
    .data    = fd_txn_account_get_data( acc ),
    .dataend = fd_txn_account_get_data( acc ) + fd_txn_account_get_data_len( acc ),
  };

  /* This check is needed as a quirk of the fuzzer. If a sysvar account
     exists in the accounts database, but doesn't have any lamports,
     this means that the account does not exist. This wouldn't happen
     in a real execution environment. */
  if( FD_UNLIKELY( fd_txn_account_get_lamports( acc )==0UL ) ) {
    return NULL;
  }

  ulong total_sz = 0;
  err = fd_recent_block_hashes_decode_footprint( &ctx, &total_sz );
  if( FD_UNLIKELY( err ) ) {
    return NULL;
  }

  uchar * mem = fd_spad_alloc( spad, fd_recent_block_hashes_align(), total_sz );
  if( FD_UNLIKELY( !mem ) ) {
    FD_LOG_CRIT(( "fd_spad_alloc failed" ));
  }

  /* This would never happen in a real cluster, this is a workaround
     for fuzz-generated cases where sysvar accounts are not funded. */
  if( FD_UNLIKELY( fd_txn_account_get_lamports( acc ) == 0 ) ) {
    return NULL;
  }

  return fd_recent_block_hashes_decode( mem, &ctx );
}
