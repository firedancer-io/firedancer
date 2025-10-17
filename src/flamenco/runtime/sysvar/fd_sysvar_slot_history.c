#include "fd_sysvar_slot_history.h"
#include "fd_sysvar.h"
#include "fd_sysvar_rent.h"
#include "../fd_system_ids.h"
#include "../fd_txn_account.h"
#include "../../../funk/fd_funk_txn.h"

/* FIXME These constants should be header defines */

#define FD_SLOT_HISTORY_MIN_ACCOUNT_SIZE (131097UL)

/* https://github.com/solana-labs/solana/blob/8f2c8b8388a495d2728909e30460aa40dcc5d733/sdk/program/src/slot_history.rs#L37 */
#define FD_SLOT_HISTORY_MAX_ENTRIES (1024UL * 1024UL)

/* TODO: move into separate bitvec library */
#define FD_SLOT_HISTORY_BITS_PER_BLOCK (8UL * sizeof(ulong))

#define FD_SLOT_HISTORY_BLOCKS_LEN (FD_SLOT_HISTORY_MAX_ENTRIES / FD_SLOT_HISTORY_BITS_PER_BLOCK)

void
fd_sysvar_slot_history_set( fd_slot_history_global_t * history,
                            ulong                      i ) {
  if( FD_UNLIKELY( i > history->next_slot && i - history->next_slot >= FD_SLOT_HISTORY_MAX_ENTRIES ) ) {
    FD_LOG_WARNING(( "Ignoring out of bounds (i=%lu next_slot=%lu)", i, history->next_slot ));
    return;
  }

  ulong * blocks     = (ulong *)((uchar*)history + history->bits_bitvec_offset);
  ulong   blocks_len = history->bits_bitvec_len;

  // Skipped slots, delete them from history
  if( FD_UNLIKELY( blocks_len == 0 ) ) return;
  for( ulong j = history->next_slot; j < i; j++ ) {
    ulong block_idx = (j / FD_SLOT_HISTORY_BITS_PER_BLOCK) % (blocks_len);
    blocks[ block_idx ] &= ~( 1UL << ( j % FD_SLOT_HISTORY_BITS_PER_BLOCK ) );
  }
  ulong block_idx = (i / FD_SLOT_HISTORY_BITS_PER_BLOCK) % (blocks_len);
  blocks[ block_idx ] |= ( 1UL << ( i % FD_SLOT_HISTORY_BITS_PER_BLOCK ) );
}


void
fd_sysvar_slot_history_write_history( fd_bank_t *                bank,
                                      fd_funk_t *                funk,
                                      fd_funk_txn_xid_t const *  xid,
                                      fd_capture_ctx_t *         capture_ctx,
                                      fd_slot_history_global_t * history ) {
  static FD_TL uchar __attribute__((aligned(alignof(fd_slot_history_global_t)))) slot_history_mem[ FD_SLOT_HISTORY_MIN_ACCOUNT_SIZE ] = {0};
  fd_bincode_encode_ctx_t ctx = {
    .data    = slot_history_mem,
    .dataend = slot_history_mem + FD_SLOT_HISTORY_MIN_ACCOUNT_SIZE
  };
  int err = fd_slot_history_encode_global( history, &ctx );
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) FD_LOG_ERR(( "fd_slot_history_encode_global failed" ));
  fd_sysvar_account_update( bank, funk, xid, capture_ctx, &fd_sysvar_slot_history_id, slot_history_mem, FD_SLOT_HISTORY_MIN_ACCOUNT_SIZE );
}

/* https://github.com/solana-labs/solana/blob/8f2c8b8388a495d2728909e30460aa40dcc5d733/sdk/program/src/slot_history.rs#L16 */

void
fd_sysvar_slot_history_init( fd_bank_t *               bank,
                             fd_funk_t *               funk,
                             fd_funk_txn_xid_t const * xid,
                             fd_capture_ctx_t *        capture_ctx ) {
  static FD_TL uchar __attribute__((aligned(alignof(fd_slot_history_global_t)))) slot_history_mem[ FD_SLOT_HISTORY_MIN_ACCOUNT_SIZE ] = {0};

  /* Create a new slot history instance */

  fd_slot_history_global_t * history = (fd_slot_history_global_t *)slot_history_mem;
  ulong *                    blocks  = (ulong *)fd_ulong_align_up( (ulong)((uchar*)history + sizeof(fd_slot_history_global_t)), alignof(ulong) );

  history->next_slot          = fd_bank_slot_get( bank ) + 1UL;
  history->bits_bitvec_offset = (ulong)((uchar*)blocks - (uchar*)history);
  history->bits_len           = FD_SLOT_HISTORY_MAX_ENTRIES;
  history->bits_bitvec_len    = FD_SLOT_HISTORY_BLOCKS_LEN;
  history->has_bits           = 1;

  fd_sysvar_slot_history_set( history, fd_bank_slot_get( bank ) );
  fd_sysvar_slot_history_write_history( bank, funk, xid, capture_ctx, history );
}

/* https://github.com/solana-labs/solana/blob/8f2c8b8388a495d2728909e30460aa40dcc5d733/runtime/src/bank.rs#L2345 */
int
fd_sysvar_slot_history_update( fd_bank_t *               bank,
                               fd_funk_t *               funk,
                               fd_funk_txn_xid_t const * xid,
                               fd_capture_ctx_t *        capture_ctx ) {
  /* Set current_slot, and update next_slot */
  fd_pubkey_t const * key = &fd_sysvar_slot_history_id;

  fd_txn_account_t rec[1];
  int err = fd_txn_account_init_from_funk_readonly( rec, key, funk, xid );
  if( FD_UNLIKELY( err ) ) FD_LOG_CRIT(( "fd_txn_account_init_from_funk_readonly(slot_history) failed: %d", err ));

  fd_bincode_decode_ctx_t ctx = {
    .data    = fd_txn_account_get_data( rec ),
    .dataend = fd_txn_account_get_data( rec ) + fd_txn_account_get_data_len( rec )
  };

  static FD_TL uchar __attribute__((aligned(alignof(fd_slot_history_global_t)))) slot_history_mem[ FD_SLOT_HISTORY_MIN_ACCOUNT_SIZE ] = {0};
  fd_slot_history_global_t * history = fd_slot_history_decode_global( slot_history_mem, &ctx );

  /* https://github.com/solana-labs/solana/blob/8f2c8b8388a495d2728909e30460aa40dcc5d733/sdk/program/src/slot_history.rs#L48 */
  fd_sysvar_slot_history_set( history, fd_bank_slot_get( bank ) );
  history->next_slot = fd_bank_slot_get( bank ) + 1;

  fd_sysvar_slot_history_write_history( bank, funk, xid, capture_ctx, history );

  return 0;
}

fd_slot_history_global_t *
fd_sysvar_slot_history_read( fd_funk_t *               funk,
                             fd_funk_txn_xid_t const * xid,
                             uchar                     out_mem[ static FD_SYSVAR_SLOT_HISTORY_FOOTPRINT ] ) {
  /* Set current_slot, and update next_slot */

  fd_pubkey_t const * key = &fd_sysvar_slot_history_id;

  fd_txn_account_t rec[1];
  int err = fd_txn_account_init_from_funk_readonly( rec, key, funk, xid );
  if( err ) {
    FD_LOG_CRIT(( "fd_txn_account_init_from_funk_readonly(slot_history) failed: %d", err ));
  }

  /* This check is needed as a quirk of the fuzzer. If a sysvar account
     exists in the accounts database, but doesn't have any lamports,
     this means that the account does not exist. This wouldn't happen
     in a real execution environment. */
  if( FD_UNLIKELY( fd_txn_account_get_lamports( rec )==0UL ) ) {
    return NULL;
  }

  ulong data_len = fd_txn_account_get_data_len( rec );
  if( FD_UNLIKELY( data_len>FD_SYSVAR_SLOT_HISTORY_BINCODE_SZ ) ) {
    FD_LOG_ERR(( "corrupt slot history sysvar: sysvar data is too large (%lu bytes)", data_len ));
  }

  fd_bincode_decode_ctx_t ctx = {
    .data    = fd_txn_account_get_data( rec ),
    .dataend = fd_txn_account_get_data( rec ) + data_len
  };

  return fd_slot_history_decode_global( out_mem, &ctx );
}

int
fd_sysvar_slot_history_find_slot( fd_slot_history_global_t const * history,
                                  ulong                            slot ) {

  ulong * blocks = (ulong *)((uchar*)history + history->bits_bitvec_offset);
  if( FD_UNLIKELY( !blocks ) ) {
    FD_LOG_ERR(( "Unable to find slot history blocks" ));
  }
  ulong blocks_len = history->bits_bitvec_len;


  if( slot > history->next_slot - 1UL ) {
    return FD_SLOT_HISTORY_SLOT_FUTURE;
  } else if ( slot < fd_ulong_sat_sub( history->next_slot, FD_SLOT_HISTORY_MAX_ENTRIES ) ) {
    return FD_SLOT_HISTORY_SLOT_TOO_OLD;
  } else {
    ulong block_idx = (slot / FD_SLOT_HISTORY_BITS_PER_BLOCK) % blocks_len;
    if( blocks[ block_idx ] & ( 1UL << ( slot % FD_SLOT_HISTORY_BITS_PER_BLOCK ) ) ) {
      return FD_SLOT_HISTORY_SLOT_FOUND;
    } else {
      return FD_SLOT_HISTORY_SLOT_NOT_FOUND;
    }
  }
}
