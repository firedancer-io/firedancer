#include "fd_stake_program.h"
#include "fd_vote_program.h"
#include "../sysvar/fd_sysvar.h"

/* https://github.com/solana-labs/solana/blob/8f2c8b8388a495d2728909e30460aa40dcc5d733/programs/stake/src/stake_state.rs#L441 */
#define STAKE_ACCOUNT_SIZE ( 200 )

/* https://github.com/solana-labs/solana/blob/8f2c8b8388a495d2728909e30460aa40dcc5d733/sdk/program/src/stake/mod.rs#L12 */
#define ACCOUNT_STORAGE_OVERHEAD ( 128 )
#define MINIMUM_STAKE_DELEGATION ( 1 )
#define MINIMUM_DELEGATION_SOL ( 1 )
#define LAMPORTS_PER_SOL (1000000000)
#define FEATURE_ACTIVE_STAKE_SPLIT_USES_RENT_SYSVAR ( 1 )
#define FEATURE_STAKE_ALLOW_ZERO_UNDELEGATED_AMOUNT ( 1 )
#define FEATURE_CLEAN_UP_DELEGATION_ERRORS ( 1 )
#define FEATURE_STAKE_RAISE_MINIMUM_DELEGATION_TO_1_SOL ( 0 ) // old behavior

void write_stake_config( fd_global_ctx_t* global, fd_stake_config_t* stake_config) {
  ulong          sz = fd_stake_config_size( stake_config );
  unsigned char *enc = fd_alloca_check( 1, sz );
  memset( enc, 0, sz );
  fd_bincode_encode_ctx_t ctx3;
  ctx3.data = enc;
  ctx3.dataend = enc + sz;
  if ( fd_stake_config_encode( stake_config, &ctx3 ) )
    FD_LOG_ERR(("fd_stake_config_encode failed"));

  fd_solana_account_t account = {
    .lamports = 960480,
    .rent_epoch = 0,
    .data_len = (ulong) ((uchar *) ctx3.data - (uchar *) enc),
    .data = enc,
    .executable = (uchar) 0
  };
  fd_memcpy( account.owner.key, global->solana_config_program, sizeof(fd_pubkey_t) );
  fd_acc_mgr_write_structured_account( global->acc_mgr, global->funk_txn, global->bank.solana_bank.slot, (fd_pubkey_t *) global->solana_stake_program_config, &account );
}

int read_stake_config( fd_global_ctx_t* global, fd_stake_config_t* result ) {
  fd_account_meta_t metadata;
  int               read_result = fd_acc_mgr_get_metadata( global->acc_mgr, global->funk_txn, (fd_pubkey_t *) global->solana_stake_program_config, &metadata );
  if ( read_result != FD_ACC_MGR_SUCCESS ) {
    FD_LOG_NOTICE(( "failed to read account metadata: %d", read_result ));
    return read_result;
  }

  unsigned char *raw_acc_data = fd_alloca_check( 1, metadata.dlen );
  read_result = fd_acc_mgr_get_account_data( global->acc_mgr, global->funk_txn, (fd_pubkey_t *) global->solana_stake_program_config, raw_acc_data, metadata.hlen, metadata.dlen );
  if ( read_result != FD_ACC_MGR_SUCCESS ) {
    FD_LOG_NOTICE(( "failed to read account data: %d", read_result ));
    return read_result;
  }

  fd_bincode_decode_ctx_t ctx;
  ctx.data = raw_acc_data;
  ctx.dataend = raw_acc_data + metadata.dlen;
  ctx.allocf = global->allocf;
  ctx.allocf_arg = global->allocf_arg;
  if ( fd_stake_config_decode( result, &ctx ) ) {
    FD_LOG_WARNING(("fd_stake_config_decode failed"));
    return FD_EXECUTOR_INSTR_ERR_INVALID_ACC_DATA;
  }
  return FD_ACC_MGR_SUCCESS;
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

int read_stake_state( fd_global_ctx_t* global, fd_pubkey_t* stake_acc, fd_stake_state_t* result ) {
  fd_memset( result, 0, STAKE_ACCOUNT_SIZE );
  fd_account_meta_t metadata;
  int               read_result = fd_acc_mgr_get_metadata( global->acc_mgr, global->funk_txn, stake_acc, &metadata );
  if ( read_result != FD_ACC_MGR_SUCCESS ) {
    FD_LOG_NOTICE(( "failed to read account metadata: %d", read_result ));
    return read_result;
  }

  unsigned char *raw_acc_data = fd_alloca_check( 1, metadata.dlen );
  read_result = fd_acc_mgr_get_account_data( global->acc_mgr, global->funk_txn, stake_acc, raw_acc_data, metadata.hlen, metadata.dlen );
  if ( read_result != FD_ACC_MGR_SUCCESS ) {
    FD_LOG_NOTICE(( "failed to read account data: %d", read_result ));
    return read_result;
  }

  fd_bincode_decode_ctx_t ctx;
  ctx.data = raw_acc_data;
  ctx.dataend = raw_acc_data + metadata.dlen;
  ctx.allocf = global->allocf;
  ctx.allocf_arg = global->allocf_arg;
  if ( fd_stake_state_decode( result, &ctx ) ) {
    FD_LOG_WARNING(("fd_stake_state_decode failed"));
    return FD_EXECUTOR_INSTR_ERR_INVALID_ACC_DATA;
  }
  return FD_ACC_MGR_SUCCESS;
}

int write_stake_state(
    fd_global_ctx_t* global,
    fd_pubkey_t* stake_acc,
    fd_stake_state_t* stake_state,
    ushort is_new_account
) {
    fd_account_meta_t metadata;
    int read_result = fd_acc_mgr_get_metadata( global->acc_mgr, global->funk_txn, stake_acc, &metadata );
    if ( FD_UNLIKELY( read_result != FD_ACC_MGR_SUCCESS ) ) {
      FD_LOG_WARNING(( "failed to read account metadata" ));
      return read_result;
    }

    ulong encoded_stake_state_size = (is_new_account) ? STAKE_ACCOUNT_SIZE : fd_stake_state_size(stake_state);
    uchar* encoded_stake_state = (uchar *)(global->allocf)( global->allocf_arg, 8UL, encoded_stake_state_size );
    if (is_new_account) {
      fd_memset( encoded_stake_state, 0, encoded_stake_state_size );
    }    

    fd_bincode_encode_ctx_t ctx3;
    ctx3.data = encoded_stake_state;
    ctx3.dataend = encoded_stake_state + encoded_stake_state_size;
    if ( fd_stake_state_encode( stake_state, &ctx3 ) )
      FD_LOG_ERR(("fd_stake_state_encode failed"));

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
    ulong dlen = (is_new_account) ? STAKE_ACCOUNT_SIZE : metadata.dlen;
    fd_acc_mgr_update_hash ( global->acc_mgr, &metadata, global->funk_txn, global->bank.solana_bank.slot, stake_acc, (uchar*)encoded_stake_state, dlen);

    return FD_EXECUTOR_INSTR_SUCCESS;
}

int validate_split_amount(
    instruction_ctx_t ctx,
    ushort source_account_index,
    ushort destination_account_index,
    ushort source_stake_is_some,
    fd_acc_lamports_t lamports,
    fd_acc_lamports_t additional_lamports,
    fd_acc_lamports_t * source_remaining_balance,
    fd_acc_lamports_t * destination_rent_exempt_reserve) {
    /// Ensure the split amount is valid.  This checks the source and destination accounts meet the
    /// minimum balance requirements, which is the rent exempt reserve plus the minimum stake
    /// delegation, and that the source account has enough lamports for the request split amount.  If
    /// not, return an error.
    // Split amount has to be something
    if (lamports == 0) {
      FD_LOG_WARNING(( "Split amount has to be something"));
      return FD_EXECUTOR_INSTR_ERR_INSUFFICIENT_FUNDS;
    }

    uchar * instr_acc_idxs = ((uchar *)ctx.txn_ctx->txn_raw->raw + ctx.instr->acct_off);
    fd_pubkey_t * txn_accs = (fd_pubkey_t *)((uchar *)ctx.txn_ctx->txn_raw->raw + ctx.txn_ctx->txn_descriptor->acct_addr_off);

    // getting all source data
    fd_pubkey_t* source_acc         = &txn_accs[instr_acc_idxs[source_account_index]];
    fd_account_meta_t metadata_source;
    fd_acc_mgr_get_metadata( ctx.global->acc_mgr, ctx.global->funk_txn, source_acc, &metadata_source );
    fd_acc_lamports_t source_lamports = metadata_source.info.lamports;

    // Obviously cannot split more than what the source account has
    if (lamports > source_lamports) {
      FD_LOG_WARNING(( "Obviously cannot split more than what the source account has"));
      return FD_EXECUTOR_INSTR_ERR_INSUFFICIENT_FUNDS;
    }

    ulong source_data_len = metadata_source.dlen;

    // getting all dest data
    fd_pubkey_t* dest_acc = &txn_accs[instr_acc_idxs[destination_account_index]];
    fd_account_meta_t metadata_dest;
    fd_acc_mgr_get_metadata( ctx.global->acc_mgr, ctx.global->funk_txn, dest_acc, &metadata_dest );

    fd_acc_lamports_t destination_lamports = metadata_dest.info.lamports;
    ulong destination_data_len = metadata_dest.dlen;

    // Verify that the source account still has enough lamports left after splitting:
    // EITHER at least the minimum balance, OR zero (in this case the source
    // account is transferring all lamports to new destination account, and the source
    // account will be closed)
    
    fd_stake_state_t source_state;
    read_stake_state( ctx.global, source_acc, &source_state ); 

    fd_acc_lamports_t source_minimum_balance = source_state.inner.initialized.rent_exempt_reserve + additional_lamports;
    *source_remaining_balance = source_lamports - lamports;
    if (*source_remaining_balance == 0) {
      // full amount is a withdrawal
      // nothing to do here
    } else if (*source_remaining_balance < source_minimum_balance) {
      FD_LOG_WARNING(( "remaining balance is too low to do the split" ));
      return FD_EXECUTOR_INSTR_ERR_INSUFFICIENT_FUNDS;
    } else {
      // all clear! nothing to do here
    }

    // Verify the destination account meets the minimum balance requirements
    // This must handle:
    // 1. The destination account having a different rent exempt reserve due to data size changes
    // 2. The destination account being prefunded, which would lower the minimum split amount
    // https://github.com/firedancer-io/solana/blob/56bd357f0dfdb841b27c4a346a58134428173f42/programs/stake/src/stake_state.rs#L1277-L1289
    // Note stake_split_uses_rent_sysvar is inactive this time
    if (FEATURE_ACTIVE_STAKE_SPLIT_USES_RENT_SYSVAR) {
      *destination_rent_exempt_reserve = fd_rent_exempt_minimum_balance(ctx.global, destination_data_len);
    } else {
      *destination_rent_exempt_reserve = source_state.inner.initialized.rent_exempt_reserve / (source_data_len + ACCOUNT_STORAGE_OVERHEAD) * (destination_data_len + ACCOUNT_STORAGE_OVERHEAD); 
    }
    fd_acc_lamports_t dest_minimum_balance = fd_ulong_sat_add(*destination_rent_exempt_reserve, additional_lamports);

    if (fd_ulong_sat_add(lamports, destination_lamports) < dest_minimum_balance) {
      // FD_LOG_WARNING(( "lamports are less than dest_balance_deficit\n lamports=%lu,\n dest_balance_deficit=%lu destination_rent_exempt_reserve=%lu, \n additional_lamports=%lu \n destination_lamports=%lu", lamports, dest_balance_deficit, *destination_rent_exempt_reserve, additional_lamports, destination_lamports ));
      return FD_EXECUTOR_INSTR_ERR_INSUFFICIENT_FUNDS;
    }

    if (
      !FEATURE_CLEAN_UP_DELEGATION_ERRORS &&
      source_stake_is_some &&
      lamports < additional_lamports) {
      return FD_EXECUTOR_INSTR_ERR_INSUFFICIENT_FUNDS;
    }

    // source_remaining_balance
    // destination_rent_exempt_reserve

    return FD_EXECUTOR_INSTR_SUCCESS;
}


int fd_executor_stake_program_execute_instruction(
  FD_FN_UNUSED instruction_ctx_t ctx
) {
  /* Deserialize the Stake instruction */
  uchar *data            = (uchar *)ctx.txn_ctx->txn_raw->raw + ctx.instr->data_off; 

  fd_stake_instruction_t instruction;
  fd_stake_instruction_new( &instruction );
  fd_bincode_decode_ctx_t ctx2;
  ctx2.data = data;
  ctx2.dataend = &data[ctx.instr->data_sz];
  ctx2.allocf = ctx.global->allocf;
  ctx2.allocf_arg = ctx.global->allocf_arg;
  if ( fd_stake_instruction_decode( &instruction, &ctx2 ) ) {
    FD_LOG_WARNING(("fd_stake_instruction_decode failed"));
    return FD_EXECUTOR_INSTR_ERR_INVALID_ACC_DATA;
  }

  /* TODO: check that the instruction account 0 owner is the stake program ID
     https://github.com/solana-labs/solana/blob/8f2c8b8388a495d2728909e30460aa40dcc5d733/programs/stake/src/stake_instruction.rs#L37 */

  if ( fd_stake_instruction_is_initialize( &instruction ) ) {
    /* https://github.com/solana-labs/solana/blob/8f2c8b8388a495d2728909e30460aa40dcc5d733/programs/stake/src/stake_instruction.rs#L43 */

    FD_LOG_INFO(( "executing StakeInstruction::Initialize instruction" ));
    fd_stake_instruction_initialize_t* initialize_instruction = &instruction.inner.initialize;

    /* Check that Instruction Account 1 is the Rent account
       https://github.com/solana-labs/solana/blob/8f2c8b8388a495d2728909e30460aa40dcc5d733/programs/stake/src/stake_instruction.rs#L44-L47 */
    uchar * instr_acc_idxs = ((uchar *)ctx.txn_ctx->txn_raw->raw + ctx.instr->acct_off);
    fd_pubkey_t * txn_accs = (fd_pubkey_t *)((uchar *)ctx.txn_ctx->txn_raw->raw + ctx.txn_ctx->txn_descriptor->acct_addr_off);
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

    fd_stake_state_t stake_state;
    fd_stake_state_new( &stake_state );
    fd_bincode_decode_ctx_t ctx3;
    ctx3.data = stake_acc_data;
    ctx3.dataend = &stake_acc_data[metadata.dlen];
    ctx3.allocf = ctx.global->allocf;
    ctx3.allocf_arg = ctx.global->allocf_arg;
    if ( fd_stake_state_decode( &stake_state, &ctx3 ) ) {
      FD_LOG_WARNING(("fd_stake_state_decode failed"));
      return FD_EXECUTOR_INSTR_ERR_INVALID_ACC_DATA;
    }

    /* Check that the Stake account is Uninitialized */
    if ( !fd_stake_state_is_uninitialized( &stake_state ) ) {
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
    int result = write_stake_state( ctx.global, stake_acc, &stake_state, 1 );
    if ( result != FD_EXECUTOR_INSTR_SUCCESS ) {
      FD_LOG_WARNING(( "failed to write stake account state: %d", result ));
      return result;
    }
  } // end of fd_stake_instruction_is_initialize 
  else if ( fd_stake_instruction_is_delegate_stake( &instruction ) ) {
    /* https://github.com/solana-labs/solana/blob/8f2c8b8388a495d2728909e30460aa40dcc5d733/programs/stake/src/stake_instruction.rs#L126 */

    /* Check that the instruction accounts are correct
      https://github.com/solana-labs/solana/blob/8f2c8b8388a495d2728909e30460aa40dcc5d733/programs/stake/src/stake_instruction.rs#L127-L142 */
    uchar* instr_acc_idxs = ((uchar *)ctx.txn_ctx->txn_raw->raw + ctx.instr->acct_off);
    fd_pubkey_t* txn_accs = (fd_pubkey_t *)((uchar *)ctx.txn_ctx->txn_raw->raw + ctx.txn_ctx->txn_descriptor->acct_addr_off);
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
      if ( instr_acc_idxs[i] < ctx.txn_ctx->txn_descriptor->signature_cnt ) {
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
    int result = write_stake_state( ctx.global, stake_acc, &stake_state, 0 );
    if ( result != FD_EXECUTOR_INSTR_SUCCESS ) {
      FD_LOG_WARNING(( "failed to write stake account state: %d", result ));
      return result;
    }
  } // end of fd_stake_instruction_is_delegate_stake 
  else if ( fd_stake_instruction_is_authorize( &instruction )) { // discriminant 1
    // https://github.com/solana-labs/solana/blob/8f2c8b8388a495d2728909e30460aa40dcc5d733/programs/stake/src/stake_instruction.rs#L50

  } else if ( fd_stake_instruction_is_split( &instruction )) { // discriminant 3
  // https://github.com/firedancer-io/solana/blob/56bd357f0dfdb841b27c4a346a58134428173f42/programs/stake/src/stake_instruction.rs#L192
    if (ctx.txn_ctx->txn_descriptor->acct_addr_cnt < 2) {
      return FD_EXECUTOR_INSTR_ERR_NOT_ENOUGH_ACC_KEYS;
    }
    uchar * instr_acc_idxs = ((uchar *)ctx.txn_ctx->txn_raw->raw + ctx.instr->acct_off);
    fd_pubkey_t * txn_accs = (fd_pubkey_t *)((uchar *)ctx.txn_ctx->txn_raw->raw + ctx.txn_ctx->txn_descriptor->acct_addr_off);
    fd_pubkey_t* stake_acc = &txn_accs[instr_acc_idxs[0]];
    fd_pubkey_t* split_acc = &txn_accs[instr_acc_idxs[1]];


    // https://github.com/firedancer-io/solana/blob/56bd357f0dfdb841b27c4a346a58134428173f42/programs/stake/src/stake_state.rs#L666
    
    fd_pubkey_t split_acc_owner;
    fd_acc_mgr_get_owner( ctx.global->acc_mgr, ctx.global->funk_txn, split_acc, &split_acc_owner ); 
    if ( memcmp( &split_acc_owner, ctx.global->solana_stake_program, sizeof(fd_pubkey_t) ) != 0 ) {
      return FD_EXECUTOR_INSTR_ERR_INCORRECT_PROGRAM_ID;
    }

    fd_account_meta_t split_metadata;
    int read_result = fd_acc_mgr_get_metadata( ctx.global->acc_mgr, ctx.global->funk_txn, split_acc, &split_metadata );
    if ( FD_UNLIKELY( read_result != FD_ACC_MGR_SUCCESS ) ) {
      FD_LOG_WARNING(( "failed to read split account metadata" ));
      return read_result;
    }

    if ( split_metadata.dlen != STAKE_ACCOUNT_SIZE ) {
      FD_LOG_WARNING(( "Split account size incorrect. expected %d got %lu", STAKE_ACCOUNT_SIZE, split_metadata.dlen ));
      return FD_EXECUTOR_INSTR_ERR_INVALID_ACC_DATA;
    }

    fd_stake_state_t split_state;
    read_stake_state( ctx.global, split_acc, &split_state ); 
    if ( !fd_stake_state_is_uninitialized( &split_state ) ) {
      return FD_EXECUTOR_INSTR_ERR_INVALID_ACC_DATA;
    }

    fd_account_meta_t stake_metadata;
    read_result = fd_acc_mgr_get_metadata( ctx.global->acc_mgr, ctx.global->funk_txn, stake_acc, &stake_metadata );
    if ( FD_UNLIKELY( read_result != FD_ACC_MGR_SUCCESS ) ) {
      FD_LOG_WARNING(( "failed to read stake account metadata" ));
      return read_result;
    }

    fd_acc_lamports_t split_lamports_balance = split_metadata.info.lamports;
    fd_acc_lamports_t lamports = instruction.inner.split; // split amount

    if ( lamports > stake_metadata.info.lamports ) {
      return FD_EXECUTOR_INSTR_ERR_INSUFFICIENT_FUNDS;
    }
    
    /* Read the current State State from the Stake account */
    fd_stake_state_t stake_state;
    read_stake_state( ctx.global, stake_acc, &stake_state );

    if ( fd_stake_state_is_stake( &stake_state ) ) {
      // validate split amount, etc
      // https://github.com/firedancer-io/solana/blob/56bd357f0dfdb841b27c4a346a58134428173f42/programs/stake/src/stake_state.rs#L698-L771

      uchar authorized_staker_signed = 0;

      for ( ulong i = 0; i < ctx.instr->acct_cnt; i++ ) {
        if ( instr_acc_idxs[i] < ctx.txn_ctx->txn_descriptor->signature_cnt ) {
          fd_pubkey_t * signer = &txn_accs[instr_acc_idxs[i]];
          if ( !memcmp( signer, stake_acc, sizeof(fd_pubkey_t) ) ) {
            authorized_staker_signed = 1;
            break;
          }
        }
      }
      
      if ( !authorized_staker_signed ) {
          return FD_EXECUTOR_INSTR_ERR_MISSING_REQUIRED_SIGNATURE;
      }


      fd_acc_lamports_t minimum_delegation = (FEATURE_STAKE_RAISE_MINIMUM_DELEGATION_TO_1_SOL) ? MINIMUM_DELEGATION_SOL * LAMPORTS_PER_SOL: MINIMUM_STAKE_DELEGATION;
      fd_acc_lamports_t source_remaining_balance, destination_rent_exempt_reserve;
      // todo: implement source_stake = Some(&stake)
      int validate_result = validate_split_amount(ctx, 0, 1, 1, lamports, minimum_delegation, &source_remaining_balance, &destination_rent_exempt_reserve);
      if (validate_result != FD_EXECUTOR_INSTR_SUCCESS) {
        return validate_result;
      }
      fd_acc_lamports_t remaining_stake_delta, split_stake_amount;
      if (source_remaining_balance == 0) {
        remaining_stake_delta = fd_ulong_sat_sub(lamports, stake_state.inner.initialized.rent_exempt_reserve);
        split_stake_amount = remaining_stake_delta;
      } else {
        if (FEATURE_CLEAN_UP_DELEGATION_ERRORS && stake_state.inner.stake.stake.delegation.stake < fd_ulong_sat_add(minimum_delegation, lamports)) {
          ctx.txn_ctx->custom_err = 12;
          return FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR; // (StakeError::InsufficientDelegation.into());
        }
        remaining_stake_delta = lamports;
        split_stake_amount = fd_ulong_sat_sub(lamports, fd_ulong_sat_sub(destination_rent_exempt_reserve, split_lamports_balance));
      }
      if (FEATURE_CLEAN_UP_DELEGATION_ERRORS && split_stake_amount < minimum_delegation) {
        ctx.txn_ctx->custom_err = 12; 
        return FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR; // (StakeError::InsufficientDelegation.into());
      }

      if (remaining_stake_delta > stake_state.inner.stake.stake.delegation.stake) {
        ctx.txn_ctx->custom_err = 12;
        return FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR; // (StakeError::InsufficientDelegation.into()); 
      }

      stake_state.inner.stake.stake.delegation.stake -= remaining_stake_delta;

      memcpy(&split_state, &stake_state, STAKE_ACCOUNT_SIZE);
      split_state.discriminant = 2;
      split_state.inner.stake.stake.delegation.stake = split_stake_amount; 
      split_state.inner.stake.meta.rent_exempt_reserve = destination_rent_exempt_reserve;

      /* Write the split and stake account to the database */
      write_stake_state( ctx.global, split_acc, &split_state, 1 );
      write_stake_state( ctx.global, stake_acc, &stake_state, 0 );

    } else if ( fd_stake_state_is_initialized( &stake_state ) ) {

      // meta.authorized.check(signers, StakeAuthorize::Staker)?;
      uchar authorized_staker_signed = 0;
      for ( ulong i = 0; i < ctx.instr->acct_cnt; i++ ) {
        if ( instr_acc_idxs[i] < ctx.txn_ctx->txn_descriptor->signature_cnt ) {
          fd_pubkey_t * signer = &txn_accs[instr_acc_idxs[i]];
          if ( !memcmp( signer, stake_acc, sizeof(fd_pubkey_t) ) ) {
            authorized_staker_signed = 1;
            break;
          }
        }
      }

      if ( !authorized_staker_signed ) {
          return FD_EXECUTOR_INSTR_ERR_MISSING_REQUIRED_SIGNATURE;
      }

      // ./target/debug/solana feature status sTKz343FM8mqtyGvYWvbLpTThw3ixRM4Xk8QvZ985mw
      fd_acc_lamports_t additional_required_lamports = FEATURE_STAKE_ALLOW_ZERO_UNDELEGATED_AMOUNT ? 0 : (FEATURE_STAKE_RAISE_MINIMUM_DELEGATION_TO_1_SOL ? MINIMUM_DELEGATION_SOL * LAMPORTS_PER_SOL : MINIMUM_STAKE_DELEGATION);
      
      fd_acc_lamports_t source_remaining_balance, destination_rent_exempt_reserve;
      int validate_result = validate_split_amount(ctx, 0, 1, 0, lamports, additional_required_lamports, &source_remaining_balance, &destination_rent_exempt_reserve);
      if (validate_result != FD_EXECUTOR_INSTR_SUCCESS) {
        return validate_result;
      }

      memcpy(&split_state, &stake_state, STAKE_ACCOUNT_SIZE);
      split_state.discriminant = 1; // initialized
      split_state.inner.initialized.rent_exempt_reserve = destination_rent_exempt_reserve;

      /* Write the initialized split account to the database */
      int result = write_stake_state( ctx.global, split_acc, &split_state, 1 );
      if ( result != FD_EXECUTOR_INSTR_SUCCESS ) {
        FD_LOG_WARNING(( "failed to write split account state: %d", result ));
        return result;
      }

    } else if ( fd_stake_state_is_uninitialized( &stake_state ) ) {
      uchar authorized_staker_signed = 0;
      for ( ulong i = 0; i < ctx.instr->acct_cnt; i++ ) {
        if ( instr_acc_idxs[i] < ctx.txn_ctx->txn_descriptor->signature_cnt ) {
          fd_pubkey_t * signer = &txn_accs[instr_acc_idxs[i]];
          if ( !memcmp( signer, stake_acc, sizeof(fd_pubkey_t) ) ) {
            authorized_staker_signed = 1;
            break;
          }
        }
      }
      
      if ( !authorized_staker_signed ) {
          return FD_EXECUTOR_INSTR_ERR_MISSING_REQUIRED_SIGNATURE;
      }

    } else {
      return FD_EXECUTOR_INSTR_ERR_INVALID_ACC_DATA;
    }

    // ulong sz = 0;
    // int err = 0;
    // char * raw_acc_data = (char*) fd_acc_mgr_view_data(ctx.global->acc_mgr, ctx.global->funk_txn, (fd_pubkey_t *) stake_acc, &sz, &err);   
    // void* d = (void *)(raw_acc_data + stake_metadata.hlen);
    // for (int idx = 0; idx < 200; ++idx) {
    //   FD_LOG_NOTICE(( "idx %d char %d", idx, ((uchar*)d)[idx] ));
    // }

    // Deinitialize state of stake acc (only if it has been initialized) upon zero balance
    if (lamports == stake_metadata.info.lamports && !fd_stake_state_is_uninitialized( &stake_state ) ) {
      stake_state.discriminant = 0; // de-initialize
      int result = write_stake_state( ctx.global, stake_acc, &stake_state, 0 );
      if ( result != FD_EXECUTOR_INSTR_SUCCESS ) {
        FD_LOG_WARNING(( "failed to write stake account state: %d", result ));
        return result;
      }
    }

    if (instr_acc_idxs[0] != instr_acc_idxs[1]) {
      // add to destination
      fd_acc_mgr_set_lamports( ctx.global->acc_mgr, ctx.global->funk_txn, ctx.global->bank.solana_bank.slot, split_acc, split_metadata.info.lamports + lamports);
      // sub from source
      fd_acc_mgr_set_lamports( ctx.global->acc_mgr, ctx.global->funk_txn, ctx.global->bank.solana_bank.slot, stake_acc, stake_metadata.info.lamports - lamports);
    }
  } // end of split, discriminant 3
  else if ( fd_stake_instruction_is_deactivate( &instruction )) { // discriminant 5

    //   if let StakeState::Stake(meta, mut stake) = stake_account.get_state()? {
    //     meta.authorized.check(signers, StakeAuthorize::Staker)?;
    //     stake.deactivate(clock.epoch)?;

    //     stake_account.set_state(&StakeState::Stake(meta, stake))
    // } else {
    //     Err(InstructionError::InvalidAccountData)
    // }

    /* Read the current State State from the Stake account */
    uchar * instr_acc_idxs = ((uchar *)ctx.txn_ctx->txn_raw->raw + ctx.instr->acct_off);
    fd_pubkey_t * txn_accs = (fd_pubkey_t *)((uchar *)ctx.txn_ctx->txn_raw->raw + ctx.txn_ctx->txn_descriptor->acct_addr_off);
    fd_pubkey_t* stake_acc         = &txn_accs[instr_acc_idxs[0]]; 
    fd_stake_state_t stake_state;
    read_stake_state( ctx.global, stake_acc, &stake_state ); 

    if ( !fd_stake_state_is_stake ( &stake_state) ) {
      return FD_EXECUTOR_INSTR_ERR_INVALID_ACC_DATA;
    }
    //meta.authorized.check(signers, StakeAuthorize::Staker)?;
    //stake.deactivate(clock.epoch)?;

    //stake_account.set_state(&StakeState::Stake(meta, stake))    
    
  } // end of deactivate, discriminant 5

  else if ( fd_stake_instruction_is_merge( &instruction )) { // merge, discriminant 7
    // https://github.com/firedancer-io/solana/blob/56bd357f0dfdb841b27c4a346a58134428173f42/programs/stake/src/stake_state.rs#L830
    if (ctx.txn_ctx->txn_descriptor->acct_addr_cnt < 2) {
      return FD_EXECUTOR_INSTR_ERR_NOT_ENOUGH_ACC_KEYS;
    }
    uchar * instr_acc_idxs = ((uchar *)ctx.txn_ctx->txn_raw->raw + ctx.instr->acct_off);
    fd_pubkey_t * txn_accs = (fd_pubkey_t *)((uchar *)ctx.txn_ctx->txn_raw->raw + ctx.txn_ctx->txn_descriptor->acct_addr_off);

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

    // Get source account and check its owner
    fd_pubkey_t* source_acc = &txn_accs[instr_acc_idxs[1]];
    fd_pubkey_t source_acc_owner;
    fd_acc_mgr_get_owner( ctx.global->acc_mgr, ctx.global->funk_txn, source_acc, &source_acc_owner ); 
    if ( memcmp( &source_acc_owner, ctx.global->solana_stake_program, sizeof(fd_pubkey_t) ) != 0 ) {
      return FD_EXECUTOR_INSTR_ERR_INCORRECT_PROGRAM_ID;
    }

    // Close the stake account-reference loophole
    if (instr_acc_idxs[0] == instr_acc_idxs[1]) {
      return FD_EXECUTOR_INSTR_ERR_INVALID_ARG;
    }

    // Get stake account
    fd_pubkey_t* stake_acc = &txn_accs[instr_acc_idxs[0]];

    // Check if the destination stake acount is mergeable
    // get_if_mergeable

    // Check if the source stake account is mergeable
    /* Read the current State State from the Stake account */
    fd_stake_state_t stake_state;
    read_stake_state( ctx.global, stake_acc, &stake_state );
    fd_acc_lamports_t stake_lamports;
    fd_acc_mgr_get_lamports( ctx.global->acc_mgr, ctx.global->funk_txn, stake_acc, &stake_lamports ); 
    
    // Merging stake accounts
    
    // deinitialize the source stake account


    // Drain the source stake account


  } // end of merge, discriminant 7
  else {
    FD_LOG_NOTICE(( "unsupported StakeInstruction instruction: discriminant %d", instruction.discriminant ));
    return FD_EXECUTOR_INSTR_ERR_INVALID_ARG;
  }

  fd_bincode_destroy_ctx_t ctx3;
  ctx3.freef = ctx.global->freef;
  ctx3.freef_arg = ctx.global->allocf_arg;
  fd_stake_instruction_destroy( &instruction, &ctx3 );

  return FD_EXECUTOR_INSTR_SUCCESS;
}
