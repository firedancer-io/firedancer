#include "fd_txntrace.h"

#include "fd_trace.pb.h"
#include "../fd_flamenco_base.h"
#include "../runtime/fd_runtime.h"
#include "../runtime/fd_executor.h"
#include "../nanopb/pb_encode.h"

#include <stdbool.h>

/* Capture ************************************************************/

fd_soltrace_TxnInput *
fd_txntrace_capture_pre( fd_soltrace_TxnInput * input,
                         fd_global_ctx_t *      global,
                         fd_txn_t const *       txn,
                         uchar const *          txn_data ) {

  /* Get transaction signature */
  if( FD_UNLIKELY( txn->signature_cnt == 0UL ) ) {
    FD_LOG_WARNING(( "txn without signatures (runtime bug)" ));
    return NULL;
  }

  fd_memset( input, 0, sizeof(fd_soltrace_TxnInput) );

  /* Allocate variable-length transaction structures */
  {
    if( FD_UNLIKELY( !fd_scratch_prepare_is_safe( 1UL ) ) ) return NULL;
    FD_SCRATCH_ALLOC_INIT( txn_layout, fd_scratch_prepare( 1UL ) );

    input->transaction.account_keys = FD_SCRATCH_ALLOC_APPEND( txn_layout,
        1UL, 32UL * txn->acct_addr_cnt );
    input->transaction.account_keys_count = txn->acct_addr_cnt;

    input->transaction.instructions = FD_SCRATCH_ALLOC_APPEND( txn_layout,
        alignof(fd_solblock_Instruction),
        sizeof (fd_solblock_Instruction) * txn->instr_cnt );
    input->transaction.instructions_count = txn->instr_cnt;

    input->transaction.address_table_lookups = NULL;
    input->transaction.address_table_lookups_count = 0UL;

    input->accounts = FD_SCRATCH_ALLOC_APPEND( txn_layout,
        alignof(fd_soltrace_Account),
        sizeof (fd_soltrace_Account) * txn->acct_addr_cnt );
    input->accounts_count = txn->acct_addr_cnt;

    if( FD_UNLIKELY( !FD_SCRATCH_ALLOC_PUBLISH( txn_layout ) ) ) return NULL;
    }

  /* Allocate variable-length implicit state */
  ulong blockhash_cnt = deq_fd_block_block_hash_entry_t_cnt( global->bank.recent_block_hashes.hashes );
  {
    if( FD_UNLIKELY( !fd_scratch_prepare_is_safe( 1UL ) ) ) return NULL;
    FD_SCRATCH_ALLOC_INIT( state_layout, fd_scratch_prepare( 1UL ) );

    input->state.blockhash_count = (uint)blockhash_cnt;
    input->state.blockhash = FD_SCRATCH_ALLOC_APPEND( state_layout,
        alignof(fd_soltrace_RecentBlockhash),
        sizeof (fd_soltrace_RecentBlockhash) * blockhash_cnt );

    if( FD_UNLIKELY( !FD_SCRATCH_ALLOC_PUBLISH( state_layout ) ) ) return NULL;
  }

  /* Allocate variable-length instruction structures */
  for( ulong i=0UL; i < txn->instr_cnt; i++ ) {
    fd_solblock_Instruction * instr_out = &input->transaction.instructions[i];
    fd_txn_instr_t const *    instr_in  = &txn->instr[i];

    fd_memset( instr_out, 0, sizeof(fd_solblock_Instruction) );

    if( FD_UNLIKELY( !fd_scratch_prepare_is_safe( 1UL ) ) ) return NULL;
    FD_SCRATCH_ALLOC_INIT( instr_layout, fd_scratch_prepare( 1UL ) );

    instr_out->accounts = FD_SCRATCH_ALLOC_APPEND( instr_layout,
        alignof(pb_bytes_array_t), PB_BYTES_ARRAY_T_ALLOCSIZE( instr_in->acct_cnt ) );
    instr_out->data     = FD_SCRATCH_ALLOC_APPEND( instr_layout,
        alignof(pb_bytes_array_t), PB_BYTES_ARRAY_T_ALLOCSIZE( instr_in->data_sz  ) );

    if( FD_UNLIKELY( !FD_SCRATCH_ALLOC_PUBLISH( instr_layout ) ) ) return NULL;
  }

  fd_acc_mgr_t *  acc_mgr  = global->acc_mgr;
  fd_funk_txn_t * funk_txn = global->funk_txn;

  /* Allocate and capture accounts */
  for( ulong i=0UL; i < txn->acct_addr_cnt; i++ ) {
    fd_soltrace_Account *  acc_out   = &input->accounts[i];
    fd_acct_addr_t const * acc_addr  = &fd_txn_get_acct_addrs( txn, txn_data )[i];
    fd_pubkey_t    const * acc_addr2 = fd_type_pun_const( acc_addr );  /* silly */

    /* Lookup account */
    fd_borrowed_account_t acc_in[1];
    if( FD_UNLIKELY( fd_acc_mgr_view( acc_mgr, funk_txn, acc_addr2, acc_in )
                     !=FD_ACC_MGR_SUCCESS ) )
      return NULL;

    fd_memset( acc_out, 0, sizeof(fd_soltrace_Account) );

    /* Allocate account data */
    ulong data_sz = acc_in->const_meta->dlen;
    if( FD_UNLIKELY( !fd_scratch_alloc_is_safe( alignof(pb_bytes_array_t), PB_BYTES_ARRAY_T_ALLOCSIZE( data_sz ) ) ) ) return NULL;
    acc_out->data = fd_scratch_alloc( alignof(pb_bytes_array_t), PB_BYTES_ARRAY_T_ALLOCSIZE( data_sz ) );

    /* Capture account */
    acc_out->meta = (fd_soltrace_AccountMeta) {
      .lamports   = acc_in->const_meta->info.lamports,
      .slot       = acc_in->const_meta->slot,
      .rent_epoch = acc_in->const_meta->info.rent_epoch,
      .executable = acc_in->const_meta->info.executable
    };
    memcpy( acc_out->meta.owner, acc_in->const_meta->info.owner, 32UL );

    acc_out->data->size = (uint)data_sz;
    fd_memcpy( acc_out->data->bytes, acc_in->const_data, data_sz );
  }

  /* Capture transaction */
  input->transaction.header = (fd_solblock_MessageHeader) {
    .num_required_signatures        = txn->signature_cnt,
    .num_readonly_signed_accounts   = txn->readonly_signed_cnt,
    .num_readonly_unsigned_accounts = txn->readonly_unsigned_cnt
  };
  fd_memcpy( *input->transaction.account_keys,
             fd_txn_get_acct_addrs( txn, txn_data ),
             32UL * txn->acct_addr_cnt );
  fd_memcpy( input->transaction.recent_blockhash,
             fd_txn_get_recent_blockhash( txn, txn_data ),
             32UL );
  input->transaction.versioned = false;  /* TODO */

  /* Capture instructions */
  for( ulong i=0UL; i < txn->instr_cnt; i++ ) {
    fd_solblock_Instruction * instr_out = &input->transaction.instructions[i];
    fd_txn_instr_t const *    instr_in  = &txn->instr[i];

    instr_out->program_id_index = instr_in->program_id;

    instr_out->accounts->size = instr_in->acct_cnt;
    fd_memcpy( instr_out->accounts->bytes,
               txn_data + instr_in->acct_off,
                          instr_in->acct_cnt );
    instr_out->data->size = instr_in->data_sz;
    fd_memcpy( instr_out->data->bytes,
               txn_data + instr_in->data_off,
                          instr_in->data_sz );
  }

  /* Capture implicit state */
  fd_soltrace_ImplicitState * state = &input->state;
  state->prev_slot = global->bank.prev_slot;
  for( ulong i=0UL; i<blockhash_cnt; i++ ) {
    state->blockhash[ i ].lamports_per_signature =
        global->bank.recent_block_hashes.hashes[i].fee_calculator.lamports_per_signature;
    fd_memcpy( state->blockhash[ i ].hash,
               global->bank.recent_block_hashes.hashes[i].blockhash.uc,
               32UL );
  }

  return input;
}

fd_soltrace_TxnDiff *
fd_txntrace_capture_post( fd_soltrace_TxnDiff *        out,
                          fd_global_ctx_t *            global,
                          fd_soltrace_TxnInput const * pre ) {
  (void)global; (void)pre;
  fd_memset( out, 0, sizeof(fd_soltrace_TxnDiff) );
  return out;
}

/* Replay *************************************************************/

static fd_rent_t const default_rent = {
  .lamports_per_uint8_year = 3480,
  .exemption_threshold     = 2.0,
  .burn_percent            = 50
};

/* TODO: fd_txntrace_load_sysvars logic is duplicated.  There should be
   some common place to restore sysvars. */

static void
fd_txntrace_load_sysvars( fd_global_ctx_t *                global,
                          fd_soltrace_KeyedAccount const * sysvar,
                          ulong                            sysvar_cnt ) {

  for( ulong i=0UL; i<sysvar_cnt; i++ ) {

    uchar const *                   key  = sysvar[i].pubkey;
    fd_soltrace_Account     const * acc  = &sysvar[i].account;
    fd_soltrace_AccountMeta const * meta = &acc->meta;

    fd_sysvar_set( global, meta->owner, (fd_pubkey_t const *)key,
                   acc->data->bytes, acc->data->size,
                   meta->slot, &meta->lamports );

    /* Update sysvar cache (ugly!) */

    if( 0==memcmp( key, global->sysvar_rent, sizeof(fd_pubkey_t) ) ) {
      FD_TEST( 0==fd_sysvar_rent_read( global, &global->bank.rent ) );
    }

  }

}

static void
fd_txntrace_load_defaults( fd_global_ctx_t * global ) {

  fd_memcpy( &global->bank.rent, &default_rent, sizeof(fd_rent_t) );
  fd_sysvar_rent_init( global );

}

static void
fd_txntrace_load_state( fd_global_ctx_t *                 global,
                        fd_soltrace_ImplicitState const * state ) {

  fd_txntrace_load_defaults( global );
  fd_txntrace_load_sysvars( global, state->sysvars, state->sysvars_count );

  fd_firedancer_banks_t * bank = &global->bank;
  bank->prev_slot = state->prev_slot;
  memcpy( bank->banks_hash.uc, state->bank_hash, 32UL );
  bank->capitalization = state->capitalization;
  bank->block_height = state->block_height;

  void * mem = fd_scratch_alloc( deq_fd_block_block_hash_entry_t_align(), deq_fd_block_block_hash_entry_t_footprint() );
  bank->recent_block_hashes.hashes = deq_fd_block_block_hash_entry_t_join( deq_fd_block_block_hash_entry_t_new( mem ) );

}

static void
fd_txntrace_load_account( fd_global_ctx_t *     global,
                          uchar const           addr[ static 32 ],
                          fd_soltrace_Account * acc ) {

  fd_pubkey_t const * pubkey = (fd_pubkey_t const *)addr;
  fd_borrowed_account_t handle[1] = {{0}};
  int err = fd_acc_mgr_modify( global->acc_mgr, global->funk_txn, pubkey, 1, acc->data->size, handle );
  FD_TEST( err==FD_ACC_MGR_SUCCESS );

  handle->meta->dlen            = acc->data->size;
  handle->meta->slot            = acc->meta.slot;
  handle->meta->info.lamports   = acc->meta.lamports;
  handle->meta->info.rent_epoch = acc->meta.rent_epoch;
  handle->meta->info.executable = acc->meta.executable;
  memcpy( handle->meta->info.owner, acc->meta.owner, 32UL );

  fd_memcpy( handle->data, acc->data->bytes, acc->data->size );

  fd_acc_mgr_commit( global->acc_mgr, handle, acc->meta.slot, 0 );
}

/* fd_txn_o_t is a handle to a txn created by fd_txntrace_create.
   txn points to the transaction descriptor.  heap points to the first
   byte of the memory region that txn offsets point to.  heap is not a
   valid txn message. */

struct fd_txn_o {
  fd_txn_t *    txn;
  fd_rawtxn_b_t heap;
};

typedef struct fd_txn_o fd_txn_o_t;

/* fd_txntrace_create_tx creates a new fd_txn_t descriptor from the
   given message.  Does not create a valid serialized transaction.
   Returns a pointer to the transaction descriptor and heap memory,
   which is created in the current fd_scratch frame. */

static fd_txn_o_t
fd_txntrace_create( fd_solblock_Message const * msg ) {

  ulong sig_cnt  = msg->header.num_required_signatures;
  ulong addr_cnt = msg->account_keys_count;

  ulong const heap_base = (ulong)fd_scratch_prepare( 16UL );
  uchar *     heap      = (uchar *)heap_base;

  /* Input validation */

  if( ( msg->account_keys_count             > FD_TXN_ACCT_ADDR_MAX )
    | ( msg->header.num_required_signatures > FD_TXN_SIG_MAX       )
    | ( msg->header.num_readonly_signed_accounts > msg->header.num_required_signatures )
    | ( msg->header.num_readonly_signed_accounts + msg->header.num_readonly_unsigned_accounts > msg->account_keys_count ) ) {
    fd_scratch_cancel();
    return (fd_txn_o_t){0};
  }

  /* Allocate constant-size transaction parts */

  fd_signature_t * sigs = (fd_signature_t *)heap;
  heap += sig_cnt * sizeof(fd_signature_t);

  fd_pubkey_t * addrs = (fd_pubkey_t *)heap;
  heap += addr_cnt * sizeof(fd_pubkey_t);

  fd_hash_t * recent_blockhash = (fd_hash_t *)heap;
  heap += sizeof(fd_hash_t);

  fd_txn_t * txn = (fd_txn_t *)heap;
  heap += fd_txn_footprint( msg->instructions_count, msg->address_table_lookups_count );

  FD_TEST( (ulong)heap - heap_base <= USHORT_MAX );

  /* Assemble message body */

  *txn = (fd_txn_t) {
    .transaction_version   = FD_TXN_VLEGACY,
    .signature_cnt         = (uchar)sig_cnt,
    .signature_off         = (ushort)( (ulong)sigs - heap_base ),
    .message_off           = 0U,
    .readonly_signed_cnt   = (uchar)msg->header.num_readonly_signed_accounts,
    .readonly_unsigned_cnt = (uchar)msg->header.num_readonly_unsigned_accounts,
    .acct_addr_cnt         = (ushort)msg->account_keys_count,
    .acct_addr_off         = (ushort)( (ulong)addrs - heap_base ),
    .recent_blockhash_off  = (ushort)( (ulong)recent_blockhash - heap_base ),

    .addr_table_lookup_cnt        = (uchar)0U,
    .addr_table_adtl_writable_cnt = (uchar)0U,
    .addr_table_adtl_cnt          = (uchar)0U,

    .instr_cnt = (ushort)msg->instructions_count
  };

  fd_memset( sigs,  0,                  sig_cnt  * sizeof(fd_signature_t) );
  fd_memcpy( addrs, *msg->account_keys, addr_cnt * sizeof(fd_pubkey_t   ) );
  fd_memcpy( recent_blockhash, msg->recent_blockhash, sizeof(fd_hash_t) );

  /* Convert instructions */

  for( ulong i=0UL; i<(txn->instr_cnt); i++ ) {

    fd_solblock_Instruction const * src      = &msg->instructions[i];
    pb_bytes_array_t const *        src_data = src->data;
    pb_bytes_array_t const *        src_accs = src->accounts;

    /* Input validation */

    if( src->program_id_index > msg->account_keys_count ) {
      fd_scratch_cancel();
      return (fd_txn_o_t){0};
    }
    for( ulong i=0UL; i<(src_accs->size); i++ ) {
      if( src_accs->bytes[i] > msg->account_keys_count ) {
        fd_scratch_cancel();
        return (fd_txn_o_t){0};
      }
    }

    /* Allocate instruction parts */

    uchar * instr_accts = heap;
    heap += src->accounts->size;

    uchar * data = heap;
    heap += src->data->size;

    FD_TEST( (ulong)heap - heap_base <= USHORT_MAX );

    /* Assemble instruction */

    txn->instr[i] = (fd_txn_instr_t) {
      .program_id = (uchar)src->program_id_index,
      .acct_cnt   = (ushort)src_accs->size,
      .data_sz    = (ushort)src_data->size,
      .acct_off   = (ushort)( (ulong)instr_accts - heap_base ),
      .data_off   = (ushort)( (ulong)data        - heap_base )
    };

  }

  fd_scratch_publish( heap );

  return (fd_txn_o_t) {
    .heap = (fd_rawtxn_b_t) {
      .raw    = (void *)heap_base,
      .txn_sz = (ushort)( (ulong)heap - heap_base )
    },
    .txn  = txn
  };
}

static bool
fd_txntrace_replay2( fd_global_ctx_t * global,
                     fd_txn_o_t        to ) {

  fd_execute_txn( global, to.txn, &to.heap );

  return true;
}

fd_soltrace_TxnDiff *
fd_txntrace_replay( fd_soltrace_TxnInput const * in,
                    fd_wksp_t *                  wksp ) {

  /* Create funk database */

  ulong       const funk_seed = 123UL;
  ulong       const txn_max   = 16UL;
  ulong       const rec_max   = 1024UL;
  void *      const funk_mem  = fd_wksp_alloc_laddr( wksp, fd_funk_align(), fd_funk_footprint(), 1UL );
  fd_funk_t *       funk      = fd_funk_join( fd_funk_new( funk_mem, 1UL, funk_seed, txn_max, rec_max ) );
  FD_TEST( funk );

  fd_funk_txn_xid_t funk_xid = { .ul = { 1UL, 2UL, 3UL, 4UL } };
  fd_funk_txn_t * funk_txn = fd_funk_txn_prepare( funk, NULL, &funk_xid, 1 );
  FD_TEST( funk_txn );

  /* Create a global context */

  fd_global_ctx_t * global = fd_global_ctx_join( fd_global_ctx_new(
      fd_scratch_alloc( FD_GLOBAL_CTX_ALIGN, FD_GLOBAL_CTX_FOOTPRINT ) ) );
  FD_TEST( global );

  fd_acc_mgr_t _acc_mgr[1];
  global->acc_mgr = fd_acc_mgr_new( _acc_mgr, global );

  global->valloc   = fd_scratch_virtual();
  global->funk     = funk;
  global->funk_txn = funk_txn;

  fd_txntrace_load_state( global, &in->state );
  for( ulong i=0UL; i < in->accounts_count; i++ )
    fd_txntrace_load_account( global, in->transaction.account_keys[i], &in->accounts[i] );

  /* Create and replay transaction */

  fd_scratch_push();
  fd_txn_o_t to = fd_txntrace_create( &in->transaction );
  if( to.txn )
    fd_txntrace_replay2( global, to );
  fd_scratch_pop();

  /* Clean up */

  fd_funk_txn_cancel( funk, funk_txn, 1 );
  fd_global_ctx_delete( fd_global_ctx_leave( global ) );
  fd_wksp_free_laddr( fd_funk_delete( fd_funk_leave( funk ) ) );

  /* out may be NULL */
  return NULL;
}
