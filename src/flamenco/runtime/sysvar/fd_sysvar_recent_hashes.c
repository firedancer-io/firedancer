#include "fd_sysvar_recent_hashes.h"
#include "fd_sysvar.h"
#include "../fd_system_ids.h"
#include "../../accdb/fd_accdb_sync.h"

/* Skips fd_types encoding preflight checks and directly serializes the
   blockhash queue into a buffer representing account data for the
   recent blockhashes sysvar. */

static void
encode_rbh_from_blockhash_queue( fd_bank_t * bank,
                                 uchar       out_mem[ static FD_SYSVAR_RECENT_HASHES_BINCODE_SZ ] ) {
  fd_blockhashes_t const * bhq = &bank->f.block_hash_queue;

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
    FD_STORE( ulong, enc+32, n->lamports_per_signature );
    enc += 40;
  }
}

void
fd_sysvar_recent_hashes_init( fd_bank_t *               bank,
                              fd_accdb_user_t *         accdb,
                              fd_funk_txn_xid_t const * xid,
                              fd_capture_ctx_t *        capture_ctx ) {
  uchar enc[ FD_SYSVAR_RECENT_HASHES_BINCODE_SZ ] = {0};
  encode_rbh_from_blockhash_queue( bank, enc );
  fd_sysvar_account_update( bank, accdb, xid, capture_ctx, &fd_sysvar_recent_block_hashes_id, enc, FD_SYSVAR_RECENT_HASHES_BINCODE_SZ );
}

// https://github.com/anza-xyz/agave/blob/e8750ba574d9ac7b72e944bc1227dc7372e3a490/accounts-db/src/blockhash_queue.rs#L113
static void
register_blockhash( fd_bank_t *       bank,
                    fd_hash_t const * hash ) {
  fd_blockhashes_t * bhq = &bank->f.block_hash_queue;
  fd_blockhash_info_t * bh = fd_blockhashes_push_new( bhq, hash );
  bh->lamports_per_signature = bank->f.rbh_lamports_per_sig;
}

/* This implementation is more consistent with Agave's bank implementation for updating the block hashes sysvar:
   1. Update the block hash queue with the latest poh
   2. Take the first 150 blockhashes from the queue (or fewer if there are)
   3. Manually serialize the recent blockhashes
   4. Set the sysvar account with the new data */
void
fd_sysvar_recent_hashes_update( fd_bank_t *               bank,
                                fd_accdb_user_t *         accdb,
                                fd_funk_txn_xid_t const * xid,
                                fd_capture_ctx_t *        capture_ctx ) {
  register_blockhash( bank, &bank->f.poh );

  uchar enc[ FD_SYSVAR_RECENT_HASHES_BINCODE_SZ ] = {0};
  encode_rbh_from_blockhash_queue( bank, enc );
  fd_sysvar_account_update( bank, accdb, xid, capture_ctx, &fd_sysvar_recent_block_hashes_id, enc, sizeof(enc) );
}

int
fd_sysvar_recent_hashes_validate( uchar const * data,
                                  ulong         sz ) {
  if( FD_UNLIKELY( sz < sizeof(ulong)) ) return 0;
  ulong len = FD_LOAD( ulong, data );
  data += sizeof(ulong); sz -= sizeof(ulong);
  ulong min_sz;
  if( FD_UNLIKELY( __builtin_umull_overflow( len, 40UL, &min_sz ) ) ) return 0;
  if( FD_UNLIKELY( sz < min_sz ) ) return 0;
  return 1;
}
