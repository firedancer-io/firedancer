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
                     fd_txn_out_t *      txn_out ) {

  fd_accdb_overlay_t * overlay  = runtime->acc_overlay;
  fd_acc_pool_t *      acc_pool = runtime->acc_pool;
  fd_funk_t *          funk     = fd_accdb_user_v1_funk( runtime->accdb );

  /* First, count up how many writable buffers to acquire
     FIXME this is a bit silly because writable accounts appear in
           contiguous ranges */

  ushort copy_idx[ MAX_TX_ACCOUNT_LOCKS ];
  uint   copy_cnt  = 0U;
  uint   write_cnt = 2U;  /* reserve two extra for nonce/fee-payer rollback */
  for( ushort i=0; i<(txn_out->accounts.cnt); i++ ) {
    if( !fd_runtime_account_is_writable_idx( txn_in, txn_out, bank, i ) ) continue;
    fd_accdb_overlay_rec_t const * rec = fd_accdb_overlay_query( overlay, &txn_out->accounts.keys[i] );
    fd_accdb_ref_t const * ref = rec->ref->ref;
    if( ref->accdb_type==FD_ACCDB_TYPE_NONE && ref->ref_type==FD_ACCDB_REF_RW ) {
      continue; /* already writable, no need for another slot */
    }
    write_cnt++;
    copy_idx[ copy_cnt++ ] = i;
  }

  /* Request account buffers */

  uchar * slots[ 2+MAX_TX_ACCOUNT_LOCKS ];
  if( FD_UNLIKELY( write_cnt>2+MAX_TX_ACCOUNT_LOCKS ) ) {
    FD_LOG_CRIT(( "too many account locks (%u > %lu)", write_cnt, 2+MAX_TX_ACCOUNT_LOCKS ));
  }
  fd_acc_pool_acquire( acc_pool, write_cnt, slots );
  uchar ** next_slot = slots;

  txn_out->accounts.rollback_fee_payer_mem = *( next_slot++ );
  txn_out->accounts.rollback_nonce_mem     = *( next_slot++ );

  /* Copy accounts */

  for( uint i=0; i<copy_cnt; i++ ) {
    uint idx = copy_idx[i];
    fd_accdb_ro_t * ro = txn_out->accounts.account[ idx ].ro;

    uchar * rw_mem  = *( next_slot++ );
    ulong   data_sz = fd_accdb_ref_data_sz( txn_out->accounts.account[ idx ].ro );
    fd_memcpy( rw_mem, fd_accdb_ref_data_const( ro ), sizeof(fd_account_meta_t)+data_sz );
  }
  FD_CRIT( slots+write_cnt==next_slot, "memory corruption detected" );
}