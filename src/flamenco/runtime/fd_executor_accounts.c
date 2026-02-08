#include "fd_executor_accounts.h"
#include "fd_runtime.h"
#include "fd_bank.h"
#include "fd_system_ids.h"
#include "../accdb/fd_accdb_sync.h"
#include "../accdb/fd_accdb_impl_v1.h"
#include "program/fd_bpf_loader_program.h"
#include "../../ballet/lthash/fd_lthash_adder.h"

/* accdb references 101 ************************************************

   This backend implements non-trivial zero-copy optimizations for
   managing transaction accounts across bundles, etc.  To bring some
   structure into transaction account management, we identify account
   references by what database they are backed by (accdb_type) and
   access type (ref_type).

   The following combinations are valid.  (Any other combinations do not
   occur during txn execution.)

   | accdb_type | ref_type | meaning                                  |
   |------------|----------|------------------------------------------|
   | NONE       | INVAL    | read-lock to non-existent account        |
   | NONE       | RO       | read-lock to externally-managed account  |
   | NONE       | RW       | write-lock to externally-managed account |
   | V1         | RO       | read-lock to funk (non-rooted) account   |
   | V1         | RW       | write-lock to unpublished funk account   |
   | V2         | RO       | read-lock to vinyl (rooted) account      |

   Next, there are different types of account accesses according to the
   Solana protocol:
   - Transaction accounts are accounts specified by the user in the
     transaction payload or account lookup tables.
   - Executable data accounts are accounts implicitly loaded when the
     transaction account list includes deployed upgradable programs.
   - Rollback accounts are backups of original account states of the
     fee payer and nonce accounts.

   Account references have a conceptual owner who is tasked with
   managing the lifetime of references and freeing them:
   - Any transaction owns (V1,RO) and (V2,RO) references for executable
     data accounts.  Freed when the txn finishes executing.
   - Normal transactions own (V1,RW), (V1,RO), and (V2,RO) references
     for transaction accounts.  Freed when the txn finishes executing.
   - Bundle transactions do not own transaction account references.
     Those references are owned by the accdb_overlay instead.  Freed
     when the bundle finishes executing. */

/* DB batch acquire/release API ***************************************/

/* A db_batch maps a database batch request to a transaction account
   list (txn_out). */

#define DB_BATCH_MAX (2*MAX_TX_ACCOUNT_LOCKS)

struct db_batch {

  fd_pubkey_t addr[ DB_BATCH_MAX ];

  fd_accdb_ro_t ro[ DB_BATCH_MAX ];

  uint cnt; /* in [0,DB_BATCH_MAX) */

  /* Maps account batch index -> txn_out array index
     If bit 15 is set, specifies an executable account. */
  ushort index[ DB_BATCH_MAX ];

};

typedef struct db_batch db_batch_t;

FD_STATIC_ASSERT( MAX_TX_ACCOUNT_LOCKS<=SHORT_MAX, bit_width );

static db_batch_t *
db_batch_init( db_batch_t * batch ) {
  batch->cnt = 0;
  return batch;
}

/* db_batch_{push,push_exec} adds a {normal,executable} account to a
   load request batch. */

static void
db_batch_push_private( db_batch_t *        batch,
                       uint                acct_idx,
                       fd_pubkey_t const * addr ) {
  uint idx = batch->cnt;
  if( FD_UNLIKELY( idx>=DB_BATCH_MAX ) ) {
    FD_LOG_CRIT(( "attempted to load more than %lu accounts (batch limit)", DB_BATCH_MAX ));
  }
  batch->addr [ idx ] = *addr;
  batch->index[ idx ] = (ushort)acct_idx;
  batch->cnt          = idx+1;
}

static void
db_batch_push( db_batch_t *        batch,
               uint                acct_idx,
               fd_pubkey_t const * addr ) {
  db_batch_push_private( batch, acct_idx, addr );
}

static void
db_batch_push_exec( db_batch_t *        batch,
                    uint                acct_idx,
                    fd_pubkey_t const * addr ) {
  db_batch_push_private( batch, acct_idx | 0x8000U, addr );
}

/* db_batch_push_ref adds an account to a close request batch. */

static void
db_batch_push_ref( db_batch_t *          batch,
                   fd_accdb_ro_t const * ro ) {
  uint idx = batch->cnt;
  if( FD_UNLIKELY( idx>=DB_BATCH_MAX ) ) {
    FD_LOG_CRIT(( "attempted to close more than %lu accounts (batch limit)", DB_BATCH_MAX ));
  }
  batch->ro[ idx ] = *ro;
  batch->cnt       = idx+1;
}

/* db_batch_open does a batch open request (acquires read-only handles
   in account database) */

static void
db_batch_open( db_batch_t *              batch,
               fd_accdb_user_t *         accdb,
               fd_funk_txn_xid_t const * xid ) {
  if( FD_UNLIKELY( !batch->cnt ) ) return;
  fd_accdb_open_ro_multi( accdb, batch->ro, xid, batch->addr, batch->cnt );
}

/* db_batch_close does a batch close request (releases read-only handles
   in account database) */

static void
db_batch_close( db_batch_t *      batch,
                fd_accdb_user_t * accdb ) {
  if( FD_UNLIKELY( !batch->cnt ) ) return;
  accdb->base.vt->close_ref_multi( accdb, fd_type_pun( batch->ro ), batch->cnt );
}

/* Accounts setup *****************************************************/

/* request_account adds an account to a request batch.

   If the account already exists in the overlay, immediately fills in an
   account reference. */

static void
request_account( fd_runtime_t *      runtime,
                 fd_bank_t *         bank,
                 fd_txn_in_t const * txn_in,
                 fd_txn_out_t *      txn_out,
                 db_batch_t *        batch,
                 uint                acc_idx ) {

  fd_accdb_overlay_t * overlay = runtime->acc_overlay;
  fd_pubkey_t const *  addr    = &txn_out->accounts.keys[ acc_idx ];

  /* Does account already exist in overlay?  (Inherit from previous
     transaction) */

  if( txn_in->bundle.is_bundle ) {
    fd_accdb_overlay_rec_t const * rec = fd_accdb_overlay_query( overlay, addr );
    if( rec ) {
      txn_out->accounts.account[ acc_idx ] = *rec->ref;
      return;
    }
  }

  /* Is a special account? */

  if( fd_pubkey_eq( addr, &fd_sysvar_instructions_id ) ) {
    FD_CRIT( !fd_runtime_account_is_writable_idx( txn_in, txn_out, bank, (ushort)acc_idx ), "attempted to write lock sysvar instructions" );
    fd_account_meta_t * meta = fd_account_meta_init( (void *)runtime->accounts.sysvar_instructions_mem );
    fd_accdb_ro_init_nodb( txn_out->accounts.account[ acc_idx ].ro, addr, meta );
  }

  /* Account not found anywhere else, add to request batch */

  db_batch_push( batch, acc_idx, addr );
}

/* request_executable_data adds an executable data account to the
   request batch.

   FIXME: This returns stale account data in various edge cases, such as
          bundle transactions.  Unclear if this causes issues, to be
          investigated.
   FIXME: Unclear if it is possible to load the same executable account
          twice.  Should either gracefully handle this edge case or add
          an assert to prevent it. */

static void
request_executable_data( fd_runtime_t *        runtime,
                         db_batch_t *          batch,
                         fd_accdb_ro_t const * prog ) {

  fd_bpf_upgradeable_loader_state_t state[1];
  if( fd_bpf_loader_program_get_state( prog->meta, state )!=FD_EXECUTOR_INSTR_SUCCESS ) return;
  if( !fd_bpf_upgradeable_loader_state_is_program( state ) ) return;

  ulong idx = runtime->accounts.executable_cnt;
  if( FD_UNLIKELY( idx>=MAX_TX_ACCOUNT_LOCKS ) ) {
    FD_LOG_CRIT(( "more than %lu executable accounts requested", MAX_TX_ACCOUNT_LOCKS ));
  }
  db_batch_push_exec( batch, (uint)idx, &state->inner.program.programdata_address );
  runtime->accounts.executable_cnt = idx+1UL;
}

/* account_promote_rw copies out account data to writable buffers for
   all write-locked accounts. */

static void
promote_accounts_rw( fd_runtime_t *      runtime,
                     fd_bank_t *         bank, /* FIXME this should not require a bank ref */
                     fd_txn_in_t const * txn_in,
                     fd_txn_out_t *      txn_out,
                     db_batch_t *        batch ) {

  fd_funk_t *          funk      = fd_accdb_user_v1_funk( runtime->accdb );
  fd_funk_rec_pool_t * rec_pool  = fd_funk_rec_pool( funk );
  fd_wksp_t *          val_wksp  = fd_funk_wksp( funk );
  fd_alloc_t *         val_alloc = fd_funk_alloc( funk );

  /* Request account records for writable accounts */

  for( ushort i=0; i<(txn_out->accounts.cnt); i++ ) {
    if( !fd_runtime_account_is_writable_idx( txn_in, txn_out, bank, i ) ) continue;

    /* If account is already writable, there's no need for another slot */
    fd_accdb_rw_t * ref = &txn_out->accounts.account[ i ];
    if( ref->ref->ref_type==FD_ACCDB_REF_RW ) {
      continue;
    }

    /* If account is currently read-only, enqueue this reference for
       freeing, since we'll replace it with the writable record */
    if( ref->ref->accdb_type!=FD_ACCDB_TYPE_NONE ) {
      db_batch_push_ref( batch, ref->ro );
    }

    /* Allocate account buffer */

    /* FIXME use batch acquire here */
    fd_funk_rec_t * rec = fd_funk_rec_pool_acquire( rec_pool, NULL, 1, NULL );
    if( FD_UNLIKELY( !rec ) ) {
      FD_LOG_CRIT(( "no free account database slots (increase [funk.max_account_records])" ));
    }
    rec->map_next = UINT_MAX;
    memset( rec->user, 0, sizeof(rec->user) );
    rec->ver_lock = fd_funk_rec_ver_lock( fd_funk_rec_ver_inc( fd_funk_rec_ver_bits( rec->ver_lock ) ), FD_FUNK_REC_LOCK_MASK );
    rec->next_idx = FD_FUNK_REC_IDX_NULL;
    rec->prev_idx = FD_FUNK_REC_IDX_NULL;
    fd_funk_val_init( rec );
    rec->tag       = 0;
    rec->val_gaddr = 0UL;

    ulong  data_sz = fd_accdb_ref_data_sz( ref->ro );
    ulong  val_sz  = sizeof(fd_account_meta_t) + data_sz;
    void * val     = fd_funk_val_truncate( rec, val_alloc, val_wksp, alignof(fd_account_meta_t), val_sz, NULL );
    if( FD_UNLIKELY( !val ) ) {
      /* FIXME block until memory becomes available? */
      FD_LOG_CRIT(( "failed to allocate account, out of memory (increase [funk.heap_size_gib])" ));
    }

    /* Copy account data */

    fd_memcpy( fd_funk_val( rec, val_wksp ), ref->ro->meta, sizeof(fd_account_meta_t) );
  }
}

/* update_overlay updates account references held by the overlay with
   those created by this txn (e.g. newly accessed accounts, or newfound
   write locks).  New write locks may evict existing read references,
   which are returned to the batch. */

static void
update_overlay( fd_runtime_t *       runtime,
                fd_txn_in_t const *  txn_in,
                fd_txn_out_t *       txn_out,
                db_batch_t *         batch ) {
  (void)runtime; (void)txn_in; (void)txn_out; (void)batch;
  FD_LOG_CRIT(( "update_overlay not implemented yet" ));
}

/* fd_exec_accounts_setup is broadly tasked with acquiring references
   to any account that will be used during execution of the given txn.

   This includes:
   - Fee-payer
   - User-specified transaction accounts
   - Program data accounts

   Readonly account handles typically reference DB cache directly to
   avoid copies.  Writable account handles use an unpublished funk_rec. */

void
fd_exec_accounts_setup( fd_runtime_t *      runtime,
                        fd_bank_t *         bank,
                        fd_txn_in_t const * txn_in,
                        fd_txn_out_t *      txn_out ) {

  if( !txn_in->bundle.is_bundle ) {
    if( FD_UNLIKELY( runtime->acc_overlay->cnt!=0 ) ) {
      FD_LOG_CRIT(( "invariant violation: requested to execute a normal transaction but found a bundle account overlay" ));
    }
  }

  /* Acquire missing accounts from the database */

  fd_funk_txn_xid_t xid = { .ul = { fd_bank_slot_get( bank ), bank->data->idx } };
  db_batch_t batch[1];
  db_batch_init( batch );
  for( ushort i=0; i<(txn_out->accounts.cnt); i++ ) {
    request_account( runtime, bank, txn_in, txn_out, batch, i );
  }

  /* Send request to DB and wait */

  db_batch_open( batch, runtime->accdb, &xid );

  /* Do another batch acquire for any executable accounts */

  db_batch_init( batch );
  for( ushort i=0; i<(txn_out->accounts.cnt); i++ ) {
    fd_accdb_ro_t const * prog = txn_out->accounts.account[ i ].ro;
    if( fd_pubkey_eq( fd_accdb_ref_owner( prog ), &fd_solana_bpf_loader_upgradeable_program_id ) ) {
      request_executable_data( runtime, batch, prog );
    }
  }

  /* Send request to DB and wait */

  db_batch_open( batch, runtime->accdb, &xid );

  /* If the user requested writable accounts that are currently backed
     by read-only buffers, copy them out to writable buffers */

  promote_accounts_rw( runtime, bank, txn_in, txn_out, batch );

  /* Move ownership of all references to the overlay

     If the user requested read-only accounts that are currently backed
     by writable buffers, demote them. */

  if( txn_in->bundle.is_bundle ) {
    db_batch_init( batch );
    update_overlay( runtime, txn_in, txn_out, batch );
    db_batch_close( batch, runtime->accdb );
  }
}

/* FIXME a considerable critical-path speedup is possible by pipelining
         hashing work (hashing lags behind execution) */

void
fd_exec_accounts_lthash( fd_txn_out_t const * txn,
                         fd_lthash_value_t *  lthash_out ) {
  fd_lthash_adder_t adder[1];
  fd_lthash_adder_new( adder );
  fd_lthash_zero( lthash_out );

  ulong const acct_cnt = txn->accounts.cnt;
  for( ulong i=0UL; i<acct_cnt; i++ ) {
    fd_accdb_ro_t const * ref = txn->accounts.account[ i ].ro;
    if( ref->ref->ref_type!=FD_ACCDB_REF_RW ) continue;
    fd_lthash_adder_push_solana_account(
        adder,
        lthash_out,
        fd_accdb_ref_address   ( ref ),
        fd_accdb_ref_data_const( ref ),
        fd_accdb_ref_data_sz   ( ref ),
        fd_accdb_ref_lamports  ( ref ),
        !!fd_accdb_ref_exec_bit( ref ),
        fd_accdb_ref_owner     ( ref )
    );
  }
  fd_lthash_adder_flush( adder, lthash_out );

  fd_lthash_adder_delete( adder );
}

void
fd_exec_accounts_commit( fd_runtime_t * runtime,
                         fd_txn_out_t * txn_out ) {
  fd_accdb_user_v1_t * accdb = (fd_accdb_user_v1_t *)runtime->accdb;
  fd_funk_txn_t * txn = fd_accdb_lineage_write_check( accdb->lineage, accdb->funk );

  for( ulong i=0UL; i<txn_out->accounts.cnt; i++ ) {
    /* Expect transaction account handles to  */

    fd_accdb_rw_t * rw = &txn_out->accounts.account[ i ];
    if( rw->ref->ref_type!=FD_ACCDB_REF_RW ) continue;
    if( FD_UNLIKELY( rw->ref->accdb_type!=FD_ACCDB_TYPE_V1 ) ) {
      FD_LOG_CRIT(( "transaction account write lock has unexpected accdb_type %u", (uint)rw->ref->accdb_type ));
    }



    fd_funk_rec_prepare_t prepare = {
      .rec          = (fd_funk_rec_t *)txn_out->accounts.account[ i ].ref->user_data,
      .rec_head_idx = &txn->rec_head_idx,
      .rec_tail_idx = &txn->rec_tail_idx
    };
    fd_funk_rec_publish(  )
  }
}

void
fd_exec_accounts_lthash_fail( fd_txn_out_t const * txn_out,
                              fd_lthash_value_t *  lthash_out ) {
  fd_hashes_account_lthash(
      &txn_out->accounts.keys[ FD_FEE_PAYER_TXN_IDX ],
      txn_out->accounts.rollback_fee_payer,
      fd_account_data( txn_out->accounts.rollback_fee_payer ),
      lthash_out
  );
  if( txn_out->accounts.nonce_idx_in_txn!=ULONG_MAX &&
      txn_out->accounts.nonce_idx_in_txn!=FD_FEE_PAYER_TXN_IDX ) {
    fd_lthash_value_t addend[1];
    fd_hashes_account_lthash(
        &txn_out->accounts.keys[ txn_out->accounts.nonce_idx_in_txn ],
        txn_out->accounts.rollback_nonce,
        fd_account_data( txn_out->accounts.rollback_nonce ),
        addend
    );
    fd_lthash_add( lthash_out, addend );
  }
}

void
fd_exec_accounts_commit_fail( fd_runtime_t * runtime,
                              fd_txn_out_t * txn_out ) {
  funk_rec_copy(
      &txn_out->accounts.keys[ FD_FEE_PAYER_TXN_IDX ],
      txn_out->accounts.rollback_fee_payer,
      fd_account_data( txn_out->accounts.rollback_fee_payer )s
  );
  if( txn_out->accounts.nonce_idx_in_txn!=ULONG_MAX &&
      txn_out->accounts.nonce_idx_in_txn!=FD_FEE_PAYER_TXN_IDX ) {
    funk_rec_copy(
        &txn_out->accounts.keys[ txn_out->accounts.nonce_idx_in_txn ],
        txn_out->accounts.rollback_nonce,
        fd_account_data( txn_out->accounts.rollback_nonce )
    );
  }
}

void
fd_exec_accounts_cancel( fd_runtime_t * runtime,
                         fd_txn_out_t * txn_out ) {

}
