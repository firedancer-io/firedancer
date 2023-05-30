#include "fd_stake_program.h"
#include "fd_vote_program.h"
#include "../sysvar/fd_sysvar.h"

/* https://github.com/solana-labs/solana/blob/8f2c8b8388a495d2728909e30460aa40dcc5d733/programs/stake/src/stake_state.rs#L441 */
#define STAKE_ACCOUNT_SIZE ( 200 )

/* https://github.com/solana-labs/solana/blob/8f2c8b8388a495d2728909e30460aa40dcc5d733/sdk/program/src/stake/mod.rs#L12 */
#define MINIMUM_STAKE_DELEGATION ( 1 )

void write_stake_config( fd_global_ctx_t* global, fd_stake_config_t* stake_config) {
  ulong          sz = fd_stake_config_size( stake_config );
  unsigned char *enc = fd_alloca_check( 1, sz );
  memset( enc, 0, sz );
  void const *ptr = (void const *) enc;
  fd_stake_config_encode( stake_config, &ptr );

  fd_solana_account_t account = {
    .lamports = 960480,
    .rent_epoch = 0,
    .data_len = (ulong) ((uchar *) ptr- (uchar *) enc),
    .data = enc,
    .executable = (uchar) 0
  };
  fd_memcpy( account.owner.key, global->solana_config_program, sizeof(fd_pubkey_t) );
  fd_acc_mgr_write_structured_account( global->acc_mgr, global->funk_txn, global->bank.solana_bank.slot, (fd_pubkey_t *) global->solana_stake_program_config, &account );
}

void read_stake_config( fd_global_ctx_t* global, fd_stake_config_t* result ) {
  fd_account_meta_t metadata;
  int               read_result = fd_acc_mgr_get_metadata( global->acc_mgr, global->funk_txn, (fd_pubkey_t *) global->solana_stake_program_config, &metadata );
  if ( read_result != FD_ACC_MGR_SUCCESS ) {
    FD_LOG_NOTICE(( "failed to read account metadata: %d", read_result ));
    return;
  }

  unsigned char *raw_acc_data = fd_alloca_check( 1, metadata.dlen );
  read_result = fd_acc_mgr_get_account_data( global->acc_mgr, global->funk_txn, (fd_pubkey_t *) global->solana_stake_program_config, raw_acc_data, metadata.hlen, metadata.dlen );
  if ( read_result != FD_ACC_MGR_SUCCESS ) {
    FD_LOG_NOTICE(( "failed to read account data: %d", read_result ));
    return;
  }

  void* input = (void *)raw_acc_data;
  fd_stake_config_decode( result, (const void **)&input, raw_acc_data + metadata.dlen, global->allocf, global->allocf_arg );
}

void fd_stake_program_config_init( fd_global_ctx_t* global ) {
  /* Defaults taken from
     https://github.com/solana-labs/solana/blob/8f2c8b8388a495d2728909e30460aa40dcc5d733/sdk/program/src/stake/config.rs#L8-L11 */
  fd_stake_config_t stake_config = {
    .warmup_cooldown_rate = 0.25,
    .slash_penalty = 12,
  };
  write_stake_config( global, &stake_config );
}

void read_stake_state( fd_global_ctx_t* global, fd_pubkey_t* stake_acc, fd_stake_state_t* result ) {
  fd_account_meta_t metadata;
  int               read_result = fd_acc_mgr_get_metadata( global->acc_mgr, global->funk_txn, stake_acc, &metadata );
  if ( read_result != FD_ACC_MGR_SUCCESS ) {
    FD_LOG_NOTICE(( "failed to read account metadata: %d", read_result ));
    return;
  }

  unsigned char *raw_acc_data = fd_alloca_check( 1, metadata.dlen );
  read_result = fd_acc_mgr_get_account_data( global->acc_mgr, global->funk_txn, stake_acc, raw_acc_data, metadata.hlen, metadata.dlen );
  if ( read_result != FD_ACC_MGR_SUCCESS ) {
    FD_LOG_NOTICE(( "failed to read account data: %d", read_result ));
    return;
  }

  void* input = (void *)raw_acc_data;
  fd_stake_state_decode( result, (const void **)&input, raw_acc_data + metadata.dlen, global->allocf, global->allocf_arg );
}

int write_stake_state(
    fd_global_ctx_t* global,
    fd_pubkey_t* stake_acc,
    fd_stake_state_t* stake_state
) {
    fd_account_meta_t metadata;
    int read_result = fd_acc_mgr_get_metadata( global->acc_mgr, global->funk_txn, stake_acc, &metadata );
    if ( FD_UNLIKELY( read_result != FD_ACC_MGR_SUCCESS ) ) {
      FD_LOG_WARNING(( "failed to read account metadata" ));
      return read_result;
    }

    ulong encoded_stake_state_size = fd_stake_state_size( stake_state );
    uchar* encoded_stake_state = (uchar *)(global->allocf)( global->allocf_arg, 8UL, encoded_stake_state_size );
    fd_memset( encoded_stake_state, 0, encoded_stake_state_size );

    void* encoded_stake_state_vp = (void*)encoded_stake_state;
    const void ** encode_stake_state_dest = (const void **)(&encoded_stake_state_vp);
    fd_stake_state_encode( stake_state, encode_stake_state_dest );

    fd_solana_account_t structured_account;
    structured_account.data = encoded_stake_state;
    structured_account.data_len = encoded_stake_state_size;
    structured_account.executable = 0;
    structured_account.rent_epoch = 0;
    memcpy( &structured_account.owner, global->solana_stake_program, sizeof(fd_pubkey_t) );

    int write_result = fd_acc_mgr_write_structured_account( global->acc_mgr, global->funk_txn, global->bank.solana_bank.slot, stake_acc, &structured_account );
    if ( write_result != FD_ACC_MGR_SUCCESS ) {
      FD_LOG_WARNING(( "failed to write account data" ));
      return write_result;
    }
    fd_acc_mgr_update_hash ( global->acc_mgr, &metadata, global->funk_txn, global->bank.solana_bank.slot, stake_acc, (uchar*)encoded_stake_state, encoded_stake_state_size);

    return FD_EXECUTOR_INSTR_SUCCESS;
}

int fd_executor_stake_program_execute_instruction(
  FD_FN_UNUSED instruction_ctx_t ctx
) {
  /* Deserialize the Stake instruction */
  uchar *data            = (uchar *)ctx.txn_raw->raw + ctx.instr->data_off; 
  void* input            = (void *)data;
  const void** input_ptr = (const void **)&input;
  void* dataend          = (void*)&data[ctx.instr->data_sz];

  fd_stake_instruction_t instruction;
  fd_stake_instruction_decode( &instruction, input_ptr, dataend, ctx.global->allocf, ctx.global->allocf_arg );

  /* TODO: check that the instruction account 0 owner is the stake program ID
     https://github.com/solana-labs/solana/blob/8f2c8b8388a495d2728909e30460aa40dcc5d733/programs/stake/src/stake_instruction.rs#L37 */

  if ( fd_stake_instruction_is_initialize( &instruction ) ) {
    /* https://github.com/solana-labs/solana/blob/8f2c8b8388a495d2728909e30460aa40dcc5d733/programs/stake/src/stake_instruction.rs#L43 */

    FD_LOG_INFO(( "executing StakeInstruction::Initialize instruction" ));
    fd_stake_instruction_initialize_t* initialize_instruction = &instruction.inner.initialize;

    /* Check that Instruction Account 1 is the Rent account
       https://github.com/solana-labs/solana/blob/8f2c8b8388a495d2728909e30460aa40dcc5d733/programs/stake/src/stake_instruction.rs#L44-L47 */
    uchar * instr_acc_idxs = ((uchar *)ctx.txn_raw->raw + ctx.instr->acct_off);
    fd_pubkey_t * txn_accs = (fd_pubkey_t *)((uchar *)ctx.txn_raw->raw + ctx.txn_descriptor->acct_addr_off);
    if ( memcmp( &txn_accs[instr_acc_idxs[1]], ctx.global->sysvar_rent, sizeof(fd_pubkey_t) ) != 0 ) {
      return FD_EXECUTOR_INSTR_ERR_INVALID_ARG;
    }

    /* Check that the stake account is the correct size
       https://github.com/solana-labs/solana/blob/8f2c8b8388a495d2728909e30460aa40dcc5d733/programs/stake/src/stake_state.rs#L441-L443 */
    fd_pubkey_t * stake_acc = &txn_accs[instr_acc_idxs[0]];
    fd_account_meta_t metadata;
    int read_result = fd_acc_mgr_get_metadata( ctx.global->acc_mgr, ctx.global->funk_txn, stake_acc, &metadata );
    if ( FD_UNLIKELY( read_result != FD_ACC_MGR_SUCCESS ) ) {
      FD_LOG_WARNING(( "failed to read account metadata" ));
      return read_result;
    }
    if ( metadata.dlen != STAKE_ACCOUNT_SIZE ) {
      FD_LOG_WARNING(( "Stake account size incorrect. expected %d got %lu", STAKE_ACCOUNT_SIZE, metadata.dlen ));
      return FD_EXECUTOR_INSTR_ERR_INVALID_ACC_DATA;
    }

    /* Read the current data in the Stake account */
    uchar *stake_acc_data = (uchar *)(ctx.global->allocf)(ctx.global->allocf_arg, 8UL, metadata.dlen);
    read_result = fd_acc_mgr_get_account_data( ctx.global->acc_mgr, ctx.global->funk_txn, stake_acc, (uchar*)stake_acc_data, sizeof(fd_account_meta_t), metadata.dlen );
    if ( read_result != FD_ACC_MGR_SUCCESS ) {
      FD_LOG_WARNING(( "failed to read account data" ));
      return read_result;
    }

    void* input            = (void *)stake_acc_data;
    const void** input_ptr = (const void **)&input;
    void* dataend          = (void*)&stake_acc_data[metadata.dlen];

    fd_stake_state_t stake_state;
    fd_stake_state_decode( &stake_state, input_ptr, dataend, ctx.global->allocf, ctx.global->allocf_arg );

    /* Check that the Stake account is Uninitialized */
    if ( !fd_stake_state_is_uninitialized( &stake_state ) ) {
      FD_LOG_NOTICE(( "Stake account already initialized" ));
      return FD_EXECUTOR_INSTR_ERR_INVALID_ACC_DATA;
    }

    /* Check that the stake account has enough balance
       https://github.com/solana-labs/solana/blob/8f2c8b8388a495d2728909e30460aa40dcc5d733/programs/stake/src/stake_state.rs#L445-L456 */
    fd_acc_lamports_t lamports;
    read_result = fd_acc_mgr_get_lamports( ctx.global->acc_mgr, ctx.global->funk_txn, stake_acc, &lamports );
    if ( read_result != FD_ACC_MGR_SUCCESS ) {
      FD_LOG_WARNING(( "failed to read account data" ));
      return read_result;
    }
    ulong minimum_rent_exempt_balance = fd_rent_exempt_minimum_balance( ctx.global, metadata.dlen );
    ulong minimum_balance = MINIMUM_STAKE_DELEGATION + minimum_rent_exempt_balance;
    if ( lamports < minimum_balance ) {
      return FD_EXECUTOR_INSTR_ERR_INSUFFICIENT_FUNDS;
    }

    /* Initialize the Stake Account
       https://github.com/solana-labs/solana/blob/8f2c8b8388a495d2728909e30460aa40dcc5d733/programs/stake/src/stake_state.rs#L449-L453 */
    stake_state.discriminant = 1;
    fd_stake_state_meta_t* stake_state_meta = &stake_state.inner.initialized;
    stake_state_meta->rent_exempt_reserve = minimum_rent_exempt_balance;
    fd_memcpy( &stake_state_meta->authorized, &initialize_instruction->authorized, FD_STAKE_AUTHORIZED_FOOTPRINT );
    fd_memcpy( &stake_state_meta->lockup, &initialize_instruction->lockup, sizeof(fd_pubkey_t) );

    /* Write the initialized Stake account to the database */
    int result = write_stake_state( ctx.global, stake_acc, &stake_state );
    if ( result != FD_EXECUTOR_INSTR_SUCCESS ) {
      FD_LOG_WARNING(( "failed to write stake account state: %d", result ));
      return result;
    }

  } else if ( fd_stake_instruction_is_delegate_stake( &instruction ) ) {
    /* https://github.com/solana-labs/solana/blob/8f2c8b8388a495d2728909e30460aa40dcc5d733/programs/stake/src/stake_instruction.rs#L126 */

    /* Check that the instruction accounts are correct
      https://github.com/solana-labs/solana/blob/8f2c8b8388a495d2728909e30460aa40dcc5d733/programs/stake/src/stake_instruction.rs#L127-L142 */
    uchar* instr_acc_idxs = ((uchar *)ctx.txn_raw->raw + ctx.instr->acct_off);
    fd_pubkey_t* txn_accs = (fd_pubkey_t *)((uchar *)ctx.txn_raw->raw + ctx.txn_descriptor->acct_addr_off);
    fd_pubkey_t* stake_acc         = &txn_accs[instr_acc_idxs[0]];

    /* Check that the Instruction Account 2 is the Clock Sysvar account */
    if ( memcmp( &txn_accs[instr_acc_idxs[2]], ctx.global->sysvar_clock, sizeof(fd_pubkey_t) ) != 0 ) {
      return FD_EXECUTOR_INSTR_ERR_INVALID_ARG;
    }
    fd_sol_sysvar_clock_t clock;
    fd_sysvar_clock_read( ctx.global, &clock );

    /* Check that the Instruction Account 3 is the Stake History Sysvar account */
    if ( memcmp( &txn_accs[instr_acc_idxs[3]], ctx.global->sysvar_stake_history, sizeof(fd_pubkey_t) ) != 0 ) {
      return FD_EXECUTOR_INSTR_ERR_INVALID_ARG;
    }

    /* Check that Instruction Account 4 is the Stake Config Program account */
    if ( memcmp( &txn_accs[instr_acc_idxs[4]], ctx.global->solana_stake_program_config, sizeof(fd_pubkey_t) ) != 0 ) {
      return FD_EXECUTOR_INSTR_ERR_INVALID_ARG;
    }
    fd_stake_config_t stake_config;
    read_stake_config( ctx.global, &stake_config );

    /* Check that Instruction Account 1 is owned by the vote program
       https://github.com/solana-labs/solana/blob/8f2c8b8388a495d2728909e30460aa40dcc5d733/programs/stake/src/stake_state.rs#L540 */
    fd_pubkey_t* vote_acc = &txn_accs[instr_acc_idxs[1]];
    fd_pubkey_t vote_acc_owner;
    fd_acc_mgr_get_owner( ctx.global->acc_mgr, ctx.global->funk_txn, vote_acc, &vote_acc_owner ); 
    if ( memcmp( &vote_acc_owner, ctx.global->solana_vote_program, sizeof(fd_pubkey_t) ) != 0 ) {
      return FD_EXECUTOR_INSTR_ERR_INCORRECT_PROGRAM_ID;
    }

    /* Read the current State State from the Stake account */
    fd_stake_state_t stake_state;
    read_stake_state( ctx.global, stake_acc, &stake_state );

    /* Require the Stake State to be either Initialized or Stake
       https://github.com/solana-labs/solana/blob/8f2c8b8388a495d2728909e30460aa40dcc5d733/programs/stake/src/stake_state.rs#L573 */
    if ( !( fd_stake_state_is_initialized( &stake_state ) || fd_stake_state_is_stake( &stake_state ) ) ) {
      return FD_EXECUTOR_INSTR_ERR_INVALID_ACC_DATA;
    }

    fd_stake_state_meta_t* meta = NULL;
    if ( fd_stake_state_is_initialized( &stake_state ) ) {
      meta = &stake_state.inner.initialized;
    } else if ( fd_stake_state_is_stake( &stake_state ) ) {
      meta = &stake_state.inner.stake.meta;
    }

    /* Check that the authorized staker for this Stake account has signed the transaction
       https://github.com/solana-labs/solana/blob/8f2c8b8388a495d2728909e30460aa40dcc5d733/programs/stake/src/stake_state.rs#L546 */
    uchar authorized_staker_signed = 0;
    for ( ulong i = 0; i < ctx.instr->acct_cnt; i++ ) {
      if ( instr_acc_idxs[i] < ctx.txn_descriptor->signature_cnt ) {
        fd_pubkey_t * signer = &txn_accs[instr_acc_idxs[i]];
        if ( !memcmp( signer, &meta->authorized.staker, sizeof(fd_pubkey_t) ) ) {
          authorized_staker_signed = 1;
          break;
        }
      }
    }
    if ( !authorized_staker_signed ) {
      return FD_EXECUTOR_INSTR_ERR_MISSING_REQUIRED_SIGNATURE;
    }

    /* Ensire that we leave enough balance in the account such that the Stake account is rent exempt
       https://github.com/solana-labs/solana/blob/8f2c8b8388a495d2728909e30460aa40dcc5d733/programs/stake/src/stake_state.rs#L837 */
    ulong stake_amount = 0;
    fd_acc_lamports_t lamports;
    int read_result = fd_acc_mgr_get_lamports( ctx.global->acc_mgr, ctx.global->funk_txn, stake_acc, &lamports );
    if ( read_result != FD_ACC_MGR_SUCCESS ) {
      FD_LOG_WARNING(( "failed to read stake account data" ));
      return read_result;
    }
    if ( lamports > meta->rent_exempt_reserve ) {
      stake_amount = lamports - meta->rent_exempt_reserve;
    }

    if ( fd_stake_state_is_initialized( &stake_state ) ) {
      /* Create the new stake state
         https://github.com/solana-labs/solana/blob/8f2c8b8388a495d2728909e30460aa40dcc5d733/programs/stake/src/stake_state.rs#L549 */
      stake_state.discriminant = 2;
      fd_stake_state_stake_t* stake_state_stake = &stake_state.inner.stake;
      fd_memcpy( &stake_state_stake->meta, meta, FD_STAKE_STATE_META_FOOTPRINT );
      stake_state_stake->stake.delegation.activation_epoch = clock.epoch;
      stake_state_stake->stake.delegation.activation_epoch = ULONG_MAX;
      stake_state_stake->stake.delegation.stake = stake_amount;
      fd_memcpy( &stake_state_stake->stake.delegation.voter_pubkey, vote_acc, sizeof(fd_pubkey_t) );
      stake_state_stake->stake.delegation.warmup_cooldown_rate = stake_config.warmup_cooldown_rate;
      
      ulong credits = 0;
      fd_vote_acc_credits( ctx.global, vote_acc, &credits );
      stake_state_stake->stake.credits_observed = credits;
    }

    /* Write the stake state back to the database */
    int result = write_stake_state( ctx.global, stake_acc, &stake_state );
    if ( result != FD_EXECUTOR_INSTR_SUCCESS ) {
      FD_LOG_WARNING(( "failed to write stake account state: %d", result ));
      return result;
    }
  } else {
    FD_LOG_NOTICE(( "unsupported StakeInstruction instruction: discriminant %d", instruction.discriminant ));
    return FD_EXECUTOR_INSTR_ERR_INVALID_ARG;
  }

  fd_stake_instruction_destroy( &instruction, ctx.global->freef, ctx.global->allocf_arg );

  return FD_EXECUTOR_INSTR_SUCCESS;
}
