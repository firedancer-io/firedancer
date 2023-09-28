#include "fd_txntrace.h"

#include "fd_trace.pb.h"
#include "../fd_flamenco_base.h"
#include "../runtime/fd_runtime.h"
#include "../runtime/fd_executor.h"
#include "../nanopb/pb_encode.h"

#include <stdbool.h>

/* Capture ************************************************************/

#define FD_TXNTRACE_SYSVAR_ITER( x )  \
  x( sysvar_recent_block_hashes ) \
  x( sysvar_clock               ) \
  x( sysvar_slot_history        ) \
  x( sysvar_slot_hashes         ) \
  x( sysvar_epoch_schedule      ) \
  x( sysvar_epoch_rewards       ) \
  x( sysvar_fees                ) \
  x( sysvar_rent                ) \
  x( sysvar_stake_history       ) \
  x( sysvar_last_restart_slot   )

#define FD_TXNTRACE_SYSVAR_CNT_HELPER(x) +1UL
#define FD_TXNTRACE_SYSVAR_CNT (0UL FD_TXNTRACE_SYSVAR_ITER( FD_TXNTRACE_SYSVAR_CNT_HELPER ))

static fd_soltrace_Account *
fd_txntrace_capture_acct( fd_soltrace_Account *       acc_out,
                          fd_global_ctx_t const *     global,
                          uchar const                 acc_addr[ static 32 ],
                          fd_soltrace_Account const * acc_pre ) {
  fd_acc_mgr_t *  acc_mgr  = global->acc_mgr;
  fd_funk_txn_t * funk_txn = global->funk_txn;

  /* Lookup account */
  FD_BORROWED_ACCOUNT_DECL(acc);
  int err = fd_acc_mgr_view( acc_mgr, funk_txn, fd_type_pun_const( acc_addr ), acc );
  if( FD_UNLIKELY( err!=FD_ACC_MGR_SUCCESS ) ) {
    FD_LOG_DEBUG(( "fd_acc_mgr_view(%32J) failed (%d-%s)",
                   acc_addr, err, fd_acc_mgr_strerror( err ) ));
    return NULL;
  }
  ulong data_sz = acc->const_meta->dlen;

  fd_memset( acc_out, 0, sizeof(fd_soltrace_Account) );

  /* Capture account */
  acc_out->meta = (fd_soltrace_AccountMeta) {
    .lamports   = acc->const_meta->info.lamports,
    .slot       = acc->const_meta->slot,
    .rent_epoch = acc->const_meta->info.rent_epoch,
    .executable = acc->const_meta->info.executable
  };
  memcpy( acc_out->meta.owner, acc->const_meta->info.owner, 32UL );

  /* Omit data if it didn't change */
  if(    acc_pre
      && acc_pre->data->size == data_sz
      && 0==memcmp( acc_pre->data->bytes, acc->const_data, data_sz ) ) {
    acc_out->data = NULL;
  } else {
    /* Allocate account data */
    if( FD_LIKELY( fd_scratch_alloc_is_safe( alignof(pb_bytes_array_t), PB_BYTES_ARRAY_T_ALLOCSIZE( data_sz ) ) ) ) {
      acc_out->data = fd_scratch_alloc( alignof(pb_bytes_array_t), PB_BYTES_ARRAY_T_ALLOCSIZE( data_sz ) );

      acc_out->data->size = (pb_size_t)data_sz;
      fd_memcpy( acc_out->data->bytes, acc->const_data, data_sz );
    } else {
      acc_out = NULL;
    }
  }

  fd_funk_val_uncache( global->funk, acc->rec );

  return acc_out;
}

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

    input->account = FD_SCRATCH_ALLOC_APPEND( txn_layout,
        alignof(fd_soltrace_Account),
        sizeof (fd_soltrace_Account) * txn->acct_addr_cnt );
    input->account_count = txn->acct_addr_cnt;

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

    input->state.feature_count = FD_FEATURE_ID_CNT;
    input->state.feature = FD_SCRATCH_ALLOC_APPEND( state_layout,
        alignof(fd_soltrace_KeyedAccount),
        sizeof (fd_soltrace_KeyedAccount) * FD_FEATURE_ID_CNT );

    input->state.sysvar_count = FD_TXNTRACE_SYSVAR_CNT;
    input->state.sysvar = FD_SCRATCH_ALLOC_APPEND( state_layout,
        alignof(fd_soltrace_KeyedAccount),
        sizeof (fd_soltrace_KeyedAccount) * input->state.sysvar_count );

    if( FD_UNLIKELY( !FD_SCRATCH_ALLOC_PUBLISH( state_layout ) ) ) return NULL;
  }

  /* Capture blockhash queue */
  {
    ulong i=0;
    for( deq_fd_block_block_hash_entry_t_iter_t iter =
         deq_fd_block_block_hash_entry_t_iter_init( global->bank.recent_block_hashes.hashes );
         deq_fd_block_block_hash_entry_t_iter_done( global->bank.recent_block_hashes.hashes, iter );
         iter = deq_fd_block_block_hash_entry_t_iter_next( global->bank.recent_block_hashes.hashes, iter ),
         i++ ) {
      fd_block_block_hash_entry_t const * elem = deq_fd_block_block_hash_entry_t_iter_ele( global->bank.recent_block_hashes.hashes, iter );
      fd_soltrace_RecentBlockhash * bh = &input->state.blockhash[i];
      bh->lamports_per_signature = elem->fee_calculator.lamports_per_signature;
      fd_memcpy( bh->hash, elem->blockhash.uc, 32UL );
    }
  }

  /* Capture sysvar accounts */
  {
    fd_soltrace_KeyedAccount * sysvar = input->state.sysvar;

#   define CAPTURE_SYSVAR( NAME )                                                          \
    do {                                                                                   \
      fd_memcpy( sysvar->pubkey, global->NAME, 32UL );                                     \
      int ok = !!fd_txntrace_capture_acct( &sysvar->account, global, global->NAME, NULL ); \
      if( FD_UNLIKELY( !ok ) ) break;  /* skip */                                          \
      sysvar++;                                                                            \
    } while(0);

    FD_TXNTRACE_SYSVAR_ITER( CAPTURE_SYSVAR )

#   undef CAPTURE_SYSVAR

    input->state.sysvar_count = (pb_size_t)( sysvar - input->state.sysvar );
  }

  /* Capture feature accounts */
  {
    ulong i=0;
    for( fd_feature_id_t const * id = fd_feature_iter_init();
         !fd_feature_iter_done( id );
         id = fd_feature_iter_next( id ) ) {

      /* Lookup account
         (Allocates funk memory that will be released once funk_txn
         expires) */

      FD_BORROWED_ACCOUNT_DECL(acc_rec);
      int err = fd_acc_mgr_view( global->acc_mgr, global->funk_txn, &id->id, acc_rec );
      if( err==FD_ACC_MGR_ERR_UNKNOWN_ACCOUNT ) {
        if( FD_UNLIKELY( *fd_features_ptr_const( &global->features, id ) <= global->bank.slot ) ) {
          FD_LOG_ERR(( "Feature %32J activated at slot %lu according to cache, "
                       "but corresponding feature account does not exist",
                       id->id.uc ));
        }
      } else if( FD_UNLIKELY( err!=FD_ACC_MGR_SUCCESS ) ) {
        FD_LOG_ERR(( "fd_acc_mgr_view(%32J) failed (%d-%s)",
                     id->id.uc, err, fd_acc_mgr_strerror( err ) ));
      }

      fd_soltrace_KeyedAccount * acc = &input->state.feature[ i ];
      fd_memcpy( acc->pubkey, id->id.uc, 32UL );
      if( FD_UNLIKELY( !fd_txntrace_capture_acct( &acc->account, global, id->id.uc, NULL ) ) )
        return NULL;

      i++;
    }
    input->state.feature_count = (pb_size_t)i;
    FD_LOG_DEBUG(( "Captured %lu feature accounts", i ));
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

  /* Allocate and capture accounts */
  for( ulong i=0UL; i < txn->acct_addr_cnt; i++ ) {
    fd_soltrace_Account *  acc_out   = &input->account[i];
    fd_acct_addr_t const * acc_addr  = &fd_txn_get_acct_addrs( txn, txn_data )[i];

    if( FD_UNLIKELY( !fd_txntrace_capture_acct( acc_out, global, acc_addr->b, NULL ) ) )
      return NULL;
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
  state->fee_rate_governor = (fd_soltrace_FeeRateGovernor) {
    .target_lamports_per_signature = global->bank.fee_rate_governor.target_lamports_per_signature,
    .target_signatures_per_slot    = global->bank.fee_rate_governor.target_signatures_per_slot,
    .min_lamports_per_signature    = global->bank.fee_rate_governor.min_lamports_per_signature,
    .max_lamports_per_signature    = global->bank.fee_rate_governor.max_lamports_per_signature,
    .burn_percent                  = global->bank.fee_rate_governor.burn_percent,
  };
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
  fd_memset( out, 0, sizeof(fd_soltrace_TxnDiff) );

  {
    if( FD_UNLIKELY( !fd_scratch_prepare_is_safe( 1UL ) ) ) return NULL;
    FD_SCRATCH_ALLOC_INIT( layout, fd_scratch_prepare( 1UL ) );

    out->account_count = pre->account_count;
    out->account = FD_SCRATCH_ALLOC_APPEND( layout,
          alignof(fd_soltrace_Account),
          sizeof (fd_soltrace_Account) * pre->account_count );

    if( FD_UNLIKELY( !FD_SCRATCH_ALLOC_PUBLISH( layout ) ) ) return NULL;
    fd_memset( out->account, 0, sizeof(fd_soltrace_Account) * out->account_count );
  }

  /* Allocate and capture accounts */
  for( ulong i=0UL; i < pre->account_count; i++ ) {
    fd_soltrace_Account * acc_out   = &out->account[i];
    fd_soltrace_Account * acc_in    = &pre->account[i];
    uchar const *         acc_addr  = pre->transaction.account_keys[i];

    if( FD_UNLIKELY( !fd_txntrace_capture_acct( acc_out, global, acc_addr, acc_in ) ) )
      return NULL;
  }

  return out;
}

/* Replay *************************************************************/

static fd_rent_t const default_rent = {
  .lamports_per_uint8_year = 3480,
  .exemption_threshold     = 2.0,
  .burn_percent            = 50
};

static void
fd_txntrace_load_defaults( fd_global_ctx_t * global ) {

  fd_memcpy( &global->bank.rent, &default_rent, sizeof(fd_rent_t) );
  fd_sysvar_rent_init( global );

}

static void
fd_txntrace_load_acct( fd_global_ctx_t *           global,
                       uchar const                 pubkey_[ static 32 ],
                       fd_soltrace_Account const * acc ) {

  /* Create account and acquire write handle */

  FD_BORROWED_ACCOUNT_DECL(rec);

  fd_acc_mgr_t *      acc_mgr  = global->acc_mgr;
  fd_funk_txn_t *     funk_txn = global->funk_txn;
  fd_pubkey_t const * pubkey   = (fd_pubkey_t const *)pubkey_;

  int err = fd_acc_mgr_modify( acc_mgr, funk_txn, pubkey, 1, acc->data->size, rec );
  if( FD_UNLIKELY( err!=FD_ACC_MGR_SUCCESS ) )
    FD_LOG_ERR(( "fd_acc_mgr_modify failed (%d-%s)", err, fd_acc_mgr_strerror( err ) ));

  /* Copy content */

  rec->meta->dlen            = acc->data->size;
  rec->meta->slot            = acc->meta.slot;
  rec->meta->info.lamports   = acc->meta.lamports;
  rec->meta->info.rent_epoch = acc->meta.rent_epoch;
  memcpy( rec->meta->info.owner, acc->meta.owner, 32UL );
  rec->meta->info.executable = acc->meta.executable;

  fd_memcpy( rec->data, acc->data->bytes, acc->data->size );

  /* Update account hash */

  err = fd_acc_mgr_commit( global->acc_mgr, rec, acc->meta.slot, 0 );
  if( FD_UNLIKELY( err!=FD_ACC_MGR_SUCCESS ) )
    FD_LOG_ERR(( "fd_acc_mgr_commit failed (%d-%s)", err, fd_acc_mgr_strerror( err ) ));
}

/* TODO: fd_txntrace_load_sysvars logic is duplicated.  There should be
   some common place to restore sysvars. */

static void
fd_txntrace_load_sysvars( fd_global_ctx_t *                global,
                          fd_soltrace_KeyedAccount const * sysvar,
                          ulong                            sysvar_cnt ) {

  for( ulong i=0UL; i<sysvar_cnt; i++ ) {

    fd_txntrace_load_acct( global, sysvar[i].pubkey, &sysvar[i].account );

    /* Update sysvar cache (ugly!) */

    uchar const * pubkey = sysvar->pubkey;
    if( 0==memcmp( pubkey, global->sysvar_rent, sizeof(fd_pubkey_t) ) ) {
      FD_TEST( 0==fd_sysvar_rent_read( global, &global->bank.rent ) );
    }

  }

}

static void
fd_txntrace_load_state( fd_global_ctx_t *                 global,
                        fd_soltrace_ImplicitState const * state ) {

  fd_txntrace_load_defaults( global );
  fd_txntrace_load_sysvars ( global, state->sysvar,  state->sysvar_count  );

  for( ulong i=0UL; i < state->feature_count; i++ ) {
    fd_soltrace_KeyedAccount const * acc = &state->feature[i];
    fd_txntrace_load_acct( global, acc->pubkey, &acc->account );
  }
  fd_features_restore( global );  /* populate feature cache */

  fd_firedancer_banks_t * bank = &global->bank;
  bank->prev_slot = state->prev_slot;
  memcpy( bank->banks_hash.uc, state->bank_hash, 32UL );
  bank->capitalization = state->capitalization;
  bank->block_height = state->block_height;

  bank->fee_rate_governor = (fd_fee_rate_governor_t) {
    .target_lamports_per_signature = state->fee_rate_governor.target_lamports_per_signature,
    .target_signatures_per_slot    = state->fee_rate_governor.target_signatures_per_slot,
    .min_lamports_per_signature    = state->fee_rate_governor.min_lamports_per_signature,
    .max_lamports_per_signature    = state->fee_rate_governor.max_lamports_per_signature,
    .burn_percent                  = (uchar)state->fee_rate_governor.burn_percent
  };

  void * mem = fd_scratch_alloc( deq_fd_block_block_hash_entry_t_align(), deq_fd_block_block_hash_entry_t_footprint() );
  bank->recent_block_hashes.hashes = deq_fd_block_block_hash_entry_t_join( deq_fd_block_block_hash_entry_t_new( mem ) );
  FD_TEST( !!bank->recent_block_hashes.hashes );
  for( ulong i=0UL; i < state->blockhash_count; i++ ) {
    fd_block_block_hash_entry_t * entry =
      deq_fd_block_block_hash_entry_t_push_tail_nocopy( bank->recent_block_hashes.hashes );
    entry->fee_calculator.lamports_per_signature = state->blockhash[i].lamports_per_signature;
    memcpy( entry->blockhash.uc, state->blockhash[i].hash, 32UL );
  }

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
    heap += src_accs->size;

    uchar * data = heap;
    heap += src_data->size;

    FD_TEST( (ulong)heap - heap_base <= USHORT_MAX );

    fd_memcpy( instr_accts, src_accs->bytes, src_accs->size );
    fd_memcpy( data,        src_data->bytes, src_data->size );

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

fd_soltrace_TxnDiff *
fd_txntrace_replay( fd_soltrace_TxnDiff *        out,
                    fd_soltrace_TxnInput const * in,
                    fd_wksp_t *                  wksp ) {

  FD_LOG_DEBUG(( "fd_txntrace_replay start" ));

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
  for( ulong i=0UL; i < in->account_count; i++ )
    fd_txntrace_load_acct( global, in->transaction.account_keys[i], &in->account[i] );

  /* Prevent recursion */
  global->trace_mode = 0;

  /* Create and replay transaction */

  fd_scratch_push();
  fd_txn_o_t to = fd_txntrace_create( &in->transaction );
  if( FD_UNLIKELY( !to.txn ) )
    FD_LOG_ERR(( "fd_txntrace_create failed (out of scratch memory?)" ));
  fd_execute_txn( global, to.txn, &to.heap );
  fd_scratch_pop();

  /* Export diff */

  out = fd_txntrace_capture_post( out, global, in );

  /* Clean up */

  fd_funk_txn_cancel( funk, funk_txn, 1 );
  fd_global_ctx_delete( fd_global_ctx_leave( global ) );
  fd_wksp_free_laddr( fd_funk_delete( fd_funk_leave( funk ) ) );

  FD_LOG_DEBUG(( "fd_txntrace_replay success" ));

  /* out may be NULL */
  return out;
}

/* Diff ***************************************************************/

static FD_TLS char diff_cstr[ 2048UL ];

char const *
fd_txntrace_diff_cstr( void ) {
  return diff_cstr;
}

int
fd_txntrace_diff( fd_soltrace_TxnDiff const * left,
                  fd_soltrace_TxnDiff const * right ) {
  if( FD_UNLIKELY( left->account_count != right->account_count ) ) {
    fd_cstr_printf( diff_cstr, sizeof(diff_cstr), NULL,
                    "account_count %u != %u",
                    left->account_count, right->account_count );
    return 0;
  }

  /* TODO use fd_capture diff API */

  for( ulong i=0UL; i<left->account_count; i++ ) {
    fd_soltrace_Account const * left_acc  = &left->account[i];
    fd_soltrace_Account const * right_acc = &right->account[i];

    if( FD_UNLIKELY( left_acc->meta.lamports != right_acc->meta.lamports ) ) {
      fd_cstr_printf( diff_cstr, sizeof(diff_cstr), NULL,
                      "account[%lu].meta.lamports %lu != %lu",
                      i, left_acc->meta.lamports, right_acc->meta.lamports );
      return 0;
    }
    if( FD_UNLIKELY( left_acc->meta.slot != right_acc->meta.slot ) ) {
      fd_cstr_printf( diff_cstr, sizeof(diff_cstr), NULL,
                      "account[%lu].meta.slot %lu != %lu",
                      i, left_acc->meta.slot, right_acc->meta.slot );
      return 0;
    }
    if( FD_UNLIKELY( left_acc->meta.rent_epoch != right_acc->meta.rent_epoch ) ) {
      fd_cstr_printf( diff_cstr, sizeof(diff_cstr), NULL,
                      "account[%lu].meta.rent_epoch %lu != %lu",
                      i, left_acc->meta.rent_epoch, right_acc->meta.rent_epoch );
      return 0;
    }
    if( FD_UNLIKELY( left_acc->meta.executable != right_acc->meta.executable ) ) {
      fd_cstr_printf( diff_cstr, sizeof(diff_cstr), NULL,
                      "account[%lu].meta.executable %u != %u",
                      i, left_acc->meta.executable, right_acc->meta.executable );
      return 0;
    }
    if( FD_UNLIKELY( 0!=memcmp( left_acc->meta.owner, right_acc->meta.owner, 32UL ) ) ) {
      fd_cstr_printf( diff_cstr, sizeof(diff_cstr), NULL,
                      "account[%lu].meta.owner != account[%lu].meta.owner",
                      i, i );
      return 0;
    }
    /* TODO properly detect case where account didn't change */
    if( (!!left_acc->data) & (!!right_acc->data) ) {
      if( FD_UNLIKELY( left_acc->data->size != right_acc->data->size ) ) {
        fd_cstr_printf( diff_cstr, sizeof(diff_cstr), NULL,
                        "account[%lu].data->size %u != %u",
                        i, left_acc->data->size, right_acc->data->size );
        return 0;
      }
      if( FD_UNLIKELY( 0!=memcmp( left_acc->data->bytes, right_acc->data->bytes, left_acc->data->size ) ) ) {
        fd_cstr_printf( diff_cstr, sizeof(diff_cstr), NULL,
                        "account[%lu].data->bytes != account[%lu].data->bytes",
                        i, i );
        return 0;
      }
    }
  }

  return 1;
}
