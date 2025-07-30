#ifndef HEADER_fd_src_flamenco_runtime_context_fd_txn_exec_h
#define HEADER_fd_src_flamenco_runtime_context_fd_txn_exec_h

#include "fd_exec_instr_ctx.h"
#include "../../log_collector/fd_log_collector_base.h"
#include "../../../ballet/txn/fd_txn.h"
#include "../../features/fd_features.h"
#include "../fd_txncache.h"
#include "../fd_bank.h"
#include "../../../funk/fd_funk.h"
#include "../fd_compute_budget_details.h"
#include "../../../disco/pack/fd_microblock.h"

FD_PROTOTYPES_BEGIN

/* A parsed transaction along with an identifier (slot number/block id)
   is sent from the replay tile to the exec tile. At this point, the
   exec tile derives the right database handle and bank to execute the
   transaction on. The transaction along with the bank and database
   handle is represented by a fd_txn_ready_t. fd_txn_exec_ready_init
   will be responsible for initializing the ready state.

   At this point, the transaction is ready to be prepared. Transaction
   preparation consists of loading all of the accounts (including
   address lookup table resolution) and doing basic validation on the
   transaction (e.g. signature verification, duplicate account checks,
   fee payer balance minimums etc). This state is represented by a
   fd_txn_prepare_t. This struct now gains ownership of the transaction
   and the staging area for the account changes. This data will live in
   a dcache which is shared between the exec and replay tiles.
   fd_txn_exec_prepare() will ingest a fd_txn_ready_t and populate
   a fd_txn_prepare_t.

   Once the transaction is prepared we know that we have a valid
   fd_txn_prepare_t and we can execute the transaction. The results of
   the transaction are returned in a fd_txn_done_t. The fd_txn_done_t
   stores return data for the transaction and other metadata (including
   fees collected, CUs consumed, etc.). At this point, the account data
   that lives on the dcache will be owned by the fd_txn_done_t. The
   fd_txn_done_t will be sent to the writer tile. The exec tile will
   notify the writer tile with an mcache frag (fd_stem_publish).

   When the writer tile receives the frag containing fd_txn_done_t,
   the writer tile will now be own the staged account data changes. It
   will make required changes to the bank, apply account changes to the
   accounts database, and once the transactions are committed, the
   writer tile will notify the replay tile that the transaction is
   done executing (so that conflicting transactions can be dispatched).
   fd_txn_writer_commit() will also responisble for updating the
   lt-hash.

*/

/* fd_txn_ready is the initial state of the transaction execution.
   It represents everything we need to prepare and execute a
   transaction. */

struct fd_txn_ready {
  fd_txn_p_t      txn;
  ulong           slot;
  fd_bank_t *     bank;
  fd_funk_t *     funk;
  fd_funk_txn_t * funk_txn;
  /* Some notion of precomputed ALUTs */
};
typedef struct fd_txn_ready fd_txn_ready_t;

/* The prepare state is all of the state of a transaction after said
   transaction has been sanitized and prepared. At this point, we have
   a valid transaction where all accounts have been loaded. */

struct fd_txn_prepare {
  /* The bank that the transaction is being executed on. */
  fd_bank_t const * bank;

  /* fd_spad_t is used as a scratch-space for transaction execution. */
  fd_spad_t * spad;

  /* The account keys that are used in the transaction. */
  ulong            accounts_cnt;
  fd_txn_account_t accounts[FD_TXN_ACCT_ADDR_MAX];
};
typedef struct fd_txn_prepare fd_txn_prepare_t;

struct fd_txn_done {
  /* Execution error code and details. If the exec_err ==0, then the
     transaction executed successfully. */
  int exec_err;
  int exec_err_kind;

  /* Metadata about the transaction. */
  ulong execution_fee;
  ulong priority_fee;
  ulong collected_rent; /* TODO: This can likely be deprecated. */
  ulong total_compute_units_used;
  ulong signature_count;
  uchar is_vote_account;

  /* If these flags are set, then the transaction modified a vote or
     stake account and the account(s)' state needs to be cached. */
  uchar dirty_vote_acc  : 1; /* 1 if this transaction maybe modified a vote account */
  uchar dirty_stake_acc : 1; /* 1 if this transaction maybe modified a stake account */

  ulong            accounts_cnt;
  fd_txn_account_t accounts[FD_TXN_ACCT_ADDR_MAX];

  /* These are accounts that are used in the case a nonce account or
     fee payer account are modified by the transaction but the
     transaction fails. In this case, the nonce account will be
     advanced and the fee payer will be debited the transaction fee
     and their states will be hashed. However, their data needs to be
     restored to their original state. */

  fd_txn_account_t rollback_nonce_account[ 1 ];
  /* If the transaction has a nonce account that must be advanced,
     this would be !=ULONG_MAX. */
  ulong            nonce_account_idx_in_txn;
  fd_txn_account_t rollback_fee_payer_account[ 1 ];
};
typedef struct fd_txn_done fd_txn_done_t;

/* fd_txn_exec_ready_init is responsible for initializing the ready
   state to execute a transaction. */

int
fd_txn_exec_ready_init( fd_txn_ready_t * ready_out,
                        fd_txn_p_t *     txn,
                        ulong            slot,
                        fd_banks_t *     banks,
                        fd_funk_t *      funk );

int
fd_txn_exec_prepare( fd_txn_ready_t const * ready,
                     fd_txn_prepare_t *     prepare );

int
fd_txn_exec( fd_txn_prepare_t const * prepare,
             fd_txn_done_t *          done );

int
fd_txn_writer_commit( fd_txn_done_t const * done,
                      fd_banks_t *          banks,
                      fd_bank_t *           bank,
                      fd_funk_t *           funk,
                      fd_funk_txn_t *       funk_txn );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_runtime_context_fd_exec_txn_ctx_h */
