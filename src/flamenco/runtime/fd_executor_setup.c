#include "fd_executor_setup.h"

static void
fd_executor_setup_instr_infos_from_txn_instrs( fd_exec_txn_ctx_t * txn_ctx ) {
  ushort instr_cnt = txn_ctx->txn_descriptor->instr_cnt;

  /* Set up the instr infos for the transaction */
  for( ushort i=0; i<instr_cnt; i++ ) {
    fd_txn_instr_t const * instr = &txn_ctx->txn_descriptor->instr[i];
    fd_instr_info_init_from_txn_instr( &txn_ctx->instr_infos[i], txn_ctx, instr );
  }

  txn_ctx->instr_info_cnt = instr_cnt;
}

static void
fd_executor_setup_executable_account( fd_exec_txn_ctx_t * txn_ctx,
                                      fd_txn_account_t *  txn_account,
                                      ushort *            executable_idx ) {
  int err = 0;
  fd_bpf_upgradeable_loader_state_t * program_loader_state = fd_bpf_loader_program_get_state( txn_account, txn_ctx->spad, &err );
  if( FD_UNLIKELY( !program_loader_state ) ) {
    return;
  }

  if( !fd_bpf_upgradeable_loader_state_is_program( program_loader_state ) ) {
    return;
  }

  /* Attempt to load the program data account from funk. This prevents any unknown program
      data accounts from getting loaded into the executable accounts list. If such a program is
      invoked, the call will fail at the instruction execution level since the programdata
      account will not exist within the executable accounts list. */
  fd_pubkey_t * programdata_acc = &program_loader_state->inner.program.programdata_address;
  if( FD_LIKELY( fd_txn_account_init_from_funk_readonly( &txn_ctx->executable_accounts[ *executable_idx ],
                                                            programdata_acc,
                                                            txn_ctx->funk,
                                                            txn_ctx->funk_txn )==0 ) ) {
    (*executable_idx)++;
  }
}

fd_txn_account_t *
fd_executor_setup_txn_account( fd_exec_txn_ctx_t * txn_ctx,
                               ushort              idx ) {
  fd_pubkey_t *      acc         = &txn_ctx->account_keys[ idx ];
  int                err         = fd_txn_account_init_from_funk_readonly( &txn_ctx->accounts[ idx ],
                                                                           acc,
                                                                           txn_ctx->funk,
                                                                           txn_ctx->funk_txn );
  fd_txn_account_t * txn_account = &txn_ctx->accounts[ idx ];

  if( FD_UNLIKELY( err!=FD_ACC_MGR_SUCCESS && err!=FD_ACC_MGR_ERR_UNKNOWN_ACCOUNT ) ) {
    FD_LOG_ERR(( "fd_txn_account_init_from_funk_readonly err=%d", err ));
  }

  uchar is_unknown_account = err==FD_ACC_MGR_ERR_UNKNOWN_ACCOUNT;
  memcpy( txn_account->pubkey->key, acc, sizeof(fd_pubkey_t) );

  if( fd_exec_txn_ctx_account_is_writable_idx( txn_ctx, idx ) || idx==FD_FEE_PAYER_TXN_IDX ) {
    void * txn_account_data = fd_spad_alloc( txn_ctx->spad, FD_ACCOUNT_REC_ALIGN, FD_ACC_TOT_SZ_MAX );

    /* promote the account to mutable, which requires a memcpy*/
    fd_txn_account_make_mutable( txn_account, txn_account_data, txn_ctx->spad_wksp );

    /* All new accounts should have their rent epoch set to ULONG_MAX.
       https://github.com/anza-xyz/agave/blob/89050f3cb7e76d9e273f10bea5e8207f2452f79f/svm/src/account_loader.rs#L485-L497 */
    if( FD_UNLIKELY( is_unknown_account ) ) {
      txn_account->vt->set_rent_epoch( txn_account, ULONG_MAX );
    }
  }

  fd_account_meta_t const * meta = txn_account->vt->get_meta( txn_account );

  if( meta==NULL ) {
    fd_txn_account_setup_sentinel_meta_readonly( txn_account, txn_ctx->spad, txn_ctx->spad_wksp );
    return NULL;
  }

  return txn_account;
}

void
fd_executor_setup_accounts_for_txn( fd_exec_txn_ctx_t * txn_ctx ) {
  ushort j = 0UL;
  fd_memset( txn_ctx->accounts, 0, sizeof(fd_txn_account_t) * txn_ctx->accounts_cnt );

  for( ushort i=0; i<txn_ctx->accounts_cnt; i++ ) {

    fd_txn_account_t * txn_account = fd_executor_setup_txn_account( txn_ctx, i );

    if( FD_UNLIKELY( txn_account &&
                     memcmp( txn_account->vt->get_owner( txn_account ), fd_solana_bpf_loader_upgradeable_program_id.key, sizeof(fd_pubkey_t) ) == 0 ) ) {
      fd_executor_setup_executable_account( txn_ctx, txn_account, &j );
    }
  }

  /* Dumping ELF files to protobuf, if applicable */
  int dump_elf_to_pb = txn_ctx->capture_ctx &&
                       txn_ctx->slot >= txn_ctx->capture_ctx->dump_proto_start_slot &&
                       txn_ctx->capture_ctx->dump_elf_to_pb;
  if( FD_UNLIKELY( dump_elf_to_pb ) ) {
    for( ushort i=0; i<txn_ctx->accounts_cnt; i++ ) {
      fd_dump_elf_to_protobuf( txn_ctx, &txn_ctx->accounts[i] );
    }
  }

  txn_ctx->nonce_account_idx_in_txn = ULONG_MAX;
  txn_ctx->executable_cnt           = j;

  /* Set up instr infos from the txn descriptor. No Agave equivalent to this function. */
  fd_executor_setup_instr_infos_from_txn_instrs( txn_ctx );
}

void
fd_executor_setup_txn_ctx_from_slot_ctx( fd_exec_slot_ctx_t const * slot_ctx,
                                         fd_exec_txn_ctx_t *        ctx,
                                         fd_wksp_t const *          funk_wksp,
                                         fd_wksp_t const *          runtime_pub_wksp,
                                         ulong                      funk_txn_gaddr,
                                         ulong                      funk_gaddr,
                                         fd_bank_hash_cmp_t *       bank_hash_cmp ) {

  ctx->runtime_pub_wksp = (fd_wksp_t *)runtime_pub_wksp;

  ctx->funk_txn = fd_wksp_laddr( funk_wksp, funk_txn_gaddr );
  if( FD_UNLIKELY( !ctx->funk_txn ) ) {
    FD_LOG_ERR(( "Could not find valid funk transaction" ));
  }

  if( FD_UNLIKELY( !fd_funk_join( ctx->funk, fd_wksp_laddr( funk_wksp, funk_gaddr ) ) ) ) {
    FD_LOG_ERR(( "Could not find valid funk %lu", funk_gaddr ));
  }

  ctx->status_cache = slot_ctx->status_cache;

  ctx->bank_hash_cmp = bank_hash_cmp;

  ctx->enable_exec_recording = fd_bank_enable_exec_recording_get( slot_ctx->bank );

  ctx->bank = slot_ctx->bank;

  ctx->slot = fd_bank_slot_get( slot_ctx->bank );

  ctx->features = fd_bank_features_get( ctx->bank );
}
