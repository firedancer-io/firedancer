#ifndef HEADER_fd_src_flamenco_events_fd_event_internal_h
#define HEADER_fd_src_flamenco_events_fd_event_internal_h

/* fd_event_internal.h builds the internal records of §4 of the dragon
   design out of the runtime's own state and publishes them on the
   tile's internal link (see src/disco/events/fd_event_report.h).

   Two records exist.  A commit record carries one committed
   transaction: its metadata and the post state of every account it
   wrote.  A runtime-write record carries one account the runtime wrote
   outside of any transaction.

   Both are produced only when the banks-wide dragon flags are set
   (fd_bank_dragon_enabled), and account data is included only when
   fd_bank_dragon_accounts is set as well.  A tile without an internal
   link reports nothing, whatever the flags say. */

#include "../runtime/fd_runtime.h"
#include "../runtime/fd_executor.h"
#include "../../disco/events/fd_event_report.h"

FD_PROTOTYPES_BEGIN

/* fd_event_internal_post_lamports is the balance account idx ends the
   transaction with, as a geyser consumer must see it.  A transaction
   that failed writes back only its rollback accounts -- the fee payer,
   and the nonce account when there is one -- so every other account
   keeps the balance it started with.  Agave collects its post balances
   after that write-back (svm/src/transaction_processor.rs:612-626); the
   account objects here still carry what execution left behind, because
   only the two rollback accounts are restored in place
   (fd_runtime.c:1237-1275). */

FD_FN_PURE static inline ulong
fd_event_internal_post_lamports( fd_txn_out_t const * txn_out,
                                 ulong                idx ) {
  fd_acc_t const * acc         = txn_out->accounts.account[ idx ];
  ulong            live        = acc ? acc->lamports : 0UL;
  int              rolled_back = txn_out->err.txn_err && !txn_out->err.is_noop;
  int              is_rollback = ( idx==FD_FEE_PAYER_TXN_IDX ) |
                                 ( idx==txn_out->accounts.nonce_idx_in_txn );
  return ( rolled_back && !is_rollback ) ? txn_out->accounts.starting_lamports[ idx ] : live;
}

/* fd_event_internal_commit_emit reports one committed transaction.
   Called from the commit path once the transaction's account writes are
   final, and never for a transaction that did not commit.  with_accounts
   asks for the post state of the accounts the transaction wrote. */

void
fd_event_internal_commit_emit( fd_runtime_t const * runtime,
                               fd_bank_t const *    bank,
                               fd_txn_in_t const *  txn_in,
                               fd_txn_out_t const * txn_out,
                               int                  with_accounts );

/* fd_event_internal_write_phase declares which side of the block's
   transactions the runtime writes that follow belong to: 0 before them,
   2 after them (transaction writes are phase 1).  A consumer orders
   writes to the same account by (phase, index), so a write reported
   under the wrong phase would order wrongly against the transactions of
   its own slot.  The phase is per thread and starts at 0. */

void
fd_event_internal_write_phase( int phase );

/* fd_event_internal_write_emit reports one account the runtime wrote
   outside of a transaction, in the phase declared above.  with_accounts
   asks for the account's data. */

void
fd_event_internal_write_emit( fd_bank_t const * bank,
                              uchar const *     pubkey,
                              uchar const *     owner,
                              ulong             lamports,
                              int               executable,
                              uchar const *     data,
                              ulong             data_sz,
                              int               with_accounts );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_events_fd_event_internal_h */
