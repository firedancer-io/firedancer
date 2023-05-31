#include "fd_vote_program.h"
#include "../fd_executor.h"
#include "../../../ballet/txn/fd_compact_u16.h"
#include "../fd_runtime.h"
#include "../../base58/fd_base58.h"
#include "../sysvar/fd_sysvar.h"

#include <math.h>

/* https://github.com/solana-labs/solana/blob/8f2c8b8388a495d2728909e30460aa40dcc5d733/programs/vote/src/vote_state/mod.rs#L36 */
#define INITIAL_LOCKOUT     ( 2 )

/* https://github.com/solana-labs/solana/blob/8f2c8b8388a495d2728909e30460aa40dcc5d733/programs/vote/src/vote_state/mod.rs#L35 */
#define MAX_LOCKOUT_HISTORY ( 31 )

/* https://github.com/solana-labs/solana/blob/8f2c8b8388a495d2728909e30460aa40dcc5d733/programs/vote/src/vote_state/mod.rs#L369
   TODO: support different values of MAX_LOCKOUT_HISTORY */
#define VOTE_ACCOUNT_SIZE ( 3731 )

void record_timestamp_vote(
  fd_global_ctx_t* global,
  fd_pubkey_t* vote_acc,
  ulong timestamp
) {
    uchar found = 0;
    for ( ulong i = 0; i < global->bank.timestamp_votes.votes.cnt; i++ ) {
      if ( memcmp( &global->bank.timestamp_votes.votes.elems[i].pubkey, vote_acc, sizeof(fd_pubkey_t) ) == 0 ) {
        global->bank.timestamp_votes.votes.elems[i].slot      = global->bank.solana_bank.slot;
        global->bank.timestamp_votes.votes.elems[i].timestamp = (long)timestamp;
        found = 1;
      }
    } 
    if ( !found ) {
      fd_clock_timestamp_vote_t timestamp_vote = {
        .pubkey    = *vote_acc,
        .timestamp = (long)timestamp,
        .slot      = global->bank.solana_bank.slot,
      };
      fd_vec_fd_clock_timestamp_vote_t_push( &global->bank.timestamp_votes.votes, timestamp_vote );
    }
}

int read_vote_state(
  fd_global_ctx_t* global,
  fd_pubkey_t * vote_acc,
  fd_vote_state_versioned_t* result
) {
    /* Read the data from the vote account */
    fd_account_meta_t metadata;
    int read_result = fd_acc_mgr_get_metadata( global->acc_mgr, global->funk_txn, vote_acc, &metadata );
    if ( FD_UNLIKELY( read_result != FD_ACC_MGR_SUCCESS ) ) {
      FD_LOG_WARNING(( "failed to read account metadata" ));
      return read_result;
    }

    uchar *vota_acc_data = (uchar *)(global->allocf)(global->allocf_arg, 8UL, metadata.dlen);
    read_result = fd_acc_mgr_get_account_data( global->acc_mgr, global->funk_txn, vote_acc, (uchar*)vota_acc_data, sizeof(fd_account_meta_t), metadata.dlen );
    if ( read_result != FD_ACC_MGR_SUCCESS ) {
      FD_LOG_WARNING(( "failed to read account data" ));
      return read_result;
    }

    /* The vote account data structure is versioned, so we decode the VoteStateVersions enum
        https://github.com/solana-labs/solana/blob/8f2c8b8388a495d2728909e30460aa40dcc5d733/programs/vote/src/vote_state/vote_state_versions.rs#L4
    */
    void* input            = (void *)vota_acc_data;
    const void** input_ptr = (const void **)&input;
    void* dataend          = (void*)&vota_acc_data[metadata.dlen];
    fd_vote_state_versioned_decode( result, input_ptr, dataend, global->allocf, global->allocf_arg );

    return FD_ACC_MGR_SUCCESS;
}

int get_and_verify_versioned_vote_state(
    instruction_ctx_t ctx,
    uchar* instr_acc_idxs,
    fd_pubkey_t* txn_accs,
    fd_pubkey_t * vote_acc,
    fd_vote_state_versioned_t* result
) {
    int read_result = read_vote_state( ctx.global, vote_acc, result );
    if ( FD_UNLIKELY( read_result != FD_ACC_MGR_SUCCESS ) ) {
      FD_LOG_WARNING(( "failed to read account data" ));
      return read_result;
    }

    /* Read the data from the vote account */
    fd_account_meta_t metadata;
    read_result = fd_acc_mgr_get_metadata( ctx.global->acc_mgr, ctx.global->funk_txn, vote_acc, &metadata );
    if ( FD_UNLIKELY( read_result != FD_ACC_MGR_SUCCESS ) ) {
      FD_LOG_WARNING(( "failed to read account metadata" ));
      return read_result;
    }

    uchar *vota_acc_data = (uchar *)(ctx.global->allocf)(ctx.global->allocf_arg, 8UL, metadata.dlen);
    read_result = fd_acc_mgr_get_account_data( ctx.global->acc_mgr, ctx.global->funk_txn, vote_acc, (uchar*)vota_acc_data, sizeof(fd_account_meta_t), metadata.dlen );
    if ( read_result != FD_ACC_MGR_SUCCESS ) {
      FD_LOG_WARNING(( "failed to read account data" ));
      return read_result;
    }

    /* The vote account data structure is versioned, so we decode the VoteStateVersions enum
        https://github.com/solana-labs/solana/blob/8f2c8b8388a495d2728909e30460aa40dcc5d733/programs/vote/src/vote_state/vote_state_versions.rs#L4
    */
    void* input            = (void *)vota_acc_data;
    const void** input_ptr = (const void **)&input;
    void* dataend          = (void*)&vota_acc_data[metadata.dlen];
    fd_vote_state_versioned_decode( result, input_ptr, dataend, ctx.global->allocf, ctx.global->allocf_arg );

    if ( fd_vote_state_versioned_is_v0_23_5( result ) ) {
      /* TODO: support legacy V0_23_5 vote state layout */
      FD_LOG_ERR(( "unsupported vote account state version V0_23_5" ));
      return FD_EXECUTOR_INSTR_ERR_INVALID_ARG;
    }
    fd_vote_state_t* vote_state = &result->inner.current;

    /* Check that the vote state account is initialized */
    if ( vote_state->authorized_voters.cnt == 0 ) {
      return FD_EXECUTOR_INSTR_ERR_UNINITIALIZED_ACCOUNT;
    }

    /* Get the current authorized voter for the current epoch */
    /* TODO: handle epoch rollover */
    fd_pubkey_t authorized_voter = vote_state->authorized_voters.elems[0].pubkey;

    /* Check that the authorized voter for this epoch has signed the vote transaction
        https://github.com/solana-labs/solana/blob/8f2c8b8388a495d2728909e30460aa40dcc5d733/programs/vote/src/vote_state/mod.rs#L1265
    */
    uchar authorized_voter_signed = 0;
    for ( ulong i = 0; i < ctx.instr->acct_cnt; i++ ) {
      if ( instr_acc_idxs[i] < ctx.txn_ctx->txn_descriptor->signature_cnt ) {
        fd_pubkey_t * signer = &txn_accs[instr_acc_idxs[i]];
        if ( !memcmp( signer, &authorized_voter, sizeof(fd_pubkey_t) ) ) {
          authorized_voter_signed = 1;
          break;
        }
      }
    }
    if ( !authorized_voter_signed ) {
      return FD_EXECUTOR_INSTR_ERR_MISSING_REQUIRED_SIGNATURE;
    }

    return FD_EXECUTOR_INSTR_SUCCESS;
}

int write_vote_state(
    instruction_ctx_t ctx,
    fd_pubkey_t* vote_acc,
    fd_vote_state_versioned_t* vote_state_versioned
) {
    ulong encoded_vote_state_versioned_size = fd_vote_state_versioned_size( vote_state_versioned );

    if (encoded_vote_state_versioned_size < VOTE_ACCOUNT_SIZE)
      encoded_vote_state_versioned_size = VOTE_ACCOUNT_SIZE;

    /* Encode and write the new account data. */
    fd_account_meta_t metadata;
    int read_result = fd_acc_mgr_get_metadata( ctx.global->acc_mgr, ctx.global->funk_txn, vote_acc, &metadata );
    if ( FD_UNLIKELY( read_result != FD_ACC_MGR_SUCCESS ) ) {
      FD_LOG_WARNING(( "failed to read account metadata" ));
      return read_result;
    }

    uchar* encoded_vote_state_versioned = (uchar *)(ctx.global->allocf)( ctx.global->allocf_arg, 8UL, encoded_vote_state_versioned_size );
    fd_memset(encoded_vote_state_versioned, 0, encoded_vote_state_versioned_size);

    void* encoded_vote_state_versioned_vp = (void*)encoded_vote_state_versioned;
    const void ** encode_vote_state_versioned_dest = (const void **)(&encoded_vote_state_versioned_vp);
    fd_vote_state_versioned_encode( vote_state_versioned, encode_vote_state_versioned_dest );

    fd_solana_account_t structured_account;
    structured_account.data = encoded_vote_state_versioned;
    structured_account.data_len = encoded_vote_state_versioned_size;
    structured_account.executable = 0;
    structured_account.rent_epoch = 0;
    memcpy( &structured_account.owner, ctx.global->solana_vote_program, sizeof(fd_pubkey_t) );

    int write_result = fd_acc_mgr_write_structured_account( ctx.global->acc_mgr, ctx.global->funk_txn, ctx.global->bank.solana_bank.slot, vote_acc, &structured_account );
    if ( write_result != FD_ACC_MGR_SUCCESS ) {
      FD_LOG_WARNING(( "failed to write account data" ));
      return write_result;
    }
    fd_acc_mgr_update_hash ( ctx.global->acc_mgr, &metadata, ctx.global->funk_txn, ctx.global->bank.solana_bank.slot, vote_acc, (uchar*)encoded_vote_state_versioned, encoded_vote_state_versioned_size);

    return FD_EXECUTOR_INSTR_SUCCESS;
}

int fd_executor_vote_program_execute_instruction(
    instruction_ctx_t ctx
) {
    /* Deserialize the Vote instruction */
    uchar *data            = (uchar *)ctx.txn_ctx->txn_raw->raw + ctx.instr->data_off;
    void* input            = (void *)data;
    const void** input_ptr = (const void **)&input;
    void* dataend          = (void*)&data[ctx.instr->data_sz];

    fd_vote_instruction_t instruction;
    fd_vote_instruction_decode( &instruction, input_ptr, dataend, ctx.global->allocf, ctx.global->allocf_arg );

    if ( fd_vote_instruction_is_initialize_account( &instruction ) ) {
      /* VoteInstruction::InitializeAccount instruction
         https://github.com/solana-labs/solana/blob/8f2c8b8388a495d2728909e30460aa40dcc5d733/programs/vote/src/vote_instruction.rs#L22-L29
       */

      FD_LOG_INFO(( "executing VoteInstruction::InitializeAccount instruction" ));
      fd_vote_init_t* init_account_params = &instruction.inner.initialize_account;

      /* Check that the accounts are correct
         https://github.com/solana-labs/solana/blob/8f2c8b8388a495d2728909e30460aa40dcc5d733/programs/vote/src/vote_processor.rs#L72-L81 */
      uchar * instr_acc_idxs = ((uchar *)ctx.txn_ctx->txn_raw->raw + ctx.instr->acct_off);
      fd_pubkey_t * txn_accs = (fd_pubkey_t *)((uchar *)ctx.txn_ctx->txn_raw->raw + ctx.txn_ctx->txn_descriptor->acct_addr_off);
      fd_pubkey_t * vote_acc = &txn_accs[instr_acc_idxs[0]];

      /* Check that account at index 1 is the rent sysvar */
      if ( memcmp( &txn_accs[instr_acc_idxs[1]], ctx.global->sysvar_rent, sizeof(fd_pubkey_t) ) != 0 ) {
        return FD_EXECUTOR_INSTR_ERR_INVALID_ARG;
      }

      /* TODO: verify account at index 0 is rent exempt */

      /* Check that account at index 2 is the clock sysvar */
      if ( memcmp( &txn_accs[instr_acc_idxs[2]], ctx.global->sysvar_clock, sizeof(fd_pubkey_t) ) != 0 ) {
        return FD_EXECUTOR_INSTR_ERR_INVALID_ARG;
      }
      fd_sol_sysvar_clock_t clock;
      fd_sysvar_clock_read( ctx.global, &clock ); 

      /* Initialize the account
         https://github.com/solana-labs/solana/blob/8f2c8b8388a495d2728909e30460aa40dcc5d733/programs/vote/src/vote_state/mod.rs#L1334 */
      
      /* Check that the vote account is the correct size
         https://github.com/solana-labs/solana/blob/8f2c8b8388a495d2728909e30460aa40dcc5d733/programs/vote/src/vote_state/mod.rs#L1340-L1342 */
      fd_account_meta_t metadata;
      int read_result = fd_acc_mgr_get_metadata( ctx.global->acc_mgr, ctx.global->funk_txn, vote_acc, &metadata );
      if ( FD_UNLIKELY( read_result != FD_ACC_MGR_SUCCESS ) ) {
        FD_LOG_WARNING(( "failed to read account metadata" ));
        return read_result;
      }
      if ( metadata.dlen != VOTE_ACCOUNT_SIZE ) {
        FD_LOG_WARNING(( "vote account size incorrect. expected %d got %lu", VOTE_ACCOUNT_SIZE, metadata.dlen ));
        return FD_EXECUTOR_INSTR_ERR_INVALID_ACC_DATA;
      }

      /* Check, for both the current and V0_23_5 versions of the vote account state, that the vote account is uninitialized. */
      uchar *vota_acc_data = (uchar *)(ctx.global->allocf)(ctx.global->allocf_arg, 8UL, metadata.dlen);
      read_result = fd_acc_mgr_get_account_data( ctx.global->acc_mgr, ctx.global->funk_txn, vote_acc, (uchar*)vota_acc_data, sizeof(fd_account_meta_t), metadata.dlen );
      if ( read_result != FD_ACC_MGR_SUCCESS ) {
        FD_LOG_WARNING(( "failed to read account data" ));
        return read_result;
      }

      /* Check that the account does not already contain an initialized vote state
         https://github.com/solana-labs/solana/blob/8f2c8b8388a495d2728909e30460aa40dcc5d733/programs/vote/src/vote_state/mod.rs#L1345-L1347
         https://github.com/solana-labs/solana/blob/8f2c8b8388a495d2728909e30460aa40dcc5d733/programs/vote/src/vote_state/vote_state_versions.rs#L54 */
      void* input            = (void *)vota_acc_data;
      const void** input_ptr = (const void **)&input;
      void* dataend          = (void*)&vota_acc_data[metadata.dlen];
      fd_vote_state_versioned_t stored_vote_state_versioned;
      fd_vote_state_versioned_decode( &stored_vote_state_versioned, input_ptr, dataend, ctx.global->allocf, ctx.global->allocf_arg );
      uchar uninitialized_vote_state = 0;
      if ( fd_vote_state_versioned_is_v0_23_5( &stored_vote_state_versioned ) ) {
        fd_vote_state_0_23_5_t* vote_state_0_25_5 = &stored_vote_state_versioned.inner.v0_23_5;

        fd_pubkey_t empty_pubkey;
        memset( &empty_pubkey, 0, sizeof(empty_pubkey) );

        if ( memcmp( &vote_state_0_25_5->authorized_voter, &empty_pubkey, sizeof(fd_pubkey_t) ) == 0 ) {
          uninitialized_vote_state = 1;
        }
      } else if ( fd_vote_state_versioned_is_current( &stored_vote_state_versioned ) ) {
        fd_vote_state_t* vote_state = &stored_vote_state_versioned.inner.current;

        if ( vote_state->authorized_voters.cnt == 0 ) {
          uninitialized_vote_state = 1;
        }
      }
      if ( !uninitialized_vote_state ) {
        return FD_EXECUTOR_INSTR_ERR_ACC_ALREADY_INITIALIZED;
      }
      fd_vote_state_versioned_destroy( &stored_vote_state_versioned, ctx.global->freef, ctx.global->allocf_arg );

      /* Check that the init_account_params.node_pubkey has signed the transaction
         https://github.com/solana-labs/solana/blob/8f2c8b8388a495d2728909e30460aa40dcc5d733/programs/vote/src/vote_state/mod.rs#L1349-L1350 */
      /* TODO: factor signature check out */
      uchar node_pubkey_signed = 0;
      for ( ulong i = 0; i < ctx.instr->acct_cnt; i++ ) {
        if ( instr_acc_idxs[i] < ctx.txn_ctx->txn_descriptor->signature_cnt ) {
          fd_pubkey_t * signer = &txn_accs[instr_acc_idxs[i]];
          if ( !memcmp( signer, &init_account_params->node_pubkey, sizeof(fd_pubkey_t) ) ) {
            node_pubkey_signed = 1;
            break;
          }
        }
      }
      if ( !node_pubkey_signed ) {
        return FD_EXECUTOR_INSTR_ERR_MISSING_REQUIRED_SIGNATURE;
      }

      /* Create a new vote account state structure */
      /* TODO: create constructors in fd_types */
      fd_vote_state_versioned_t* vote_state_versioned = (fd_vote_state_versioned_t*) fd_alloca( 1UL, sizeof(fd_vote_state_versioned_t) );
      memset( vote_state_versioned, 0, sizeof(fd_vote_state_versioned_t) );
      vote_state_versioned->discriminant = 1;
      fd_vote_state_t* vote_state = &vote_state_versioned->inner.current;
      fd_vote_prior_voter_t* prior_voters_buf = (fd_vote_prior_voter_t*)(*ctx.global->allocf)(ctx.global->allocf_arg, FD_VOTE_PRIOR_VOTER_ALIGN, FD_VOTE_PRIOR_VOTER_FOOTPRINT*32);
      fd_vote_prior_voters_t prior_voters = {
        .buf = prior_voters_buf,
        .buf_len = 0,
        .idx = 31,
        .is_empty = 1,
      };
      vote_state->prior_voters = prior_voters;

      /* Initialize the vote account fields:
         https://github.com/solana-labs/solana/blob/8f2c8b8388a495d2728909e30460aa40dcc5d733/programs/vote/src/vote_state/mod.rs#L343 */
      vote_state->voting_node = init_account_params->node_pubkey;
      fd_vote_historical_authorized_voter_t authorized_voter = {
        .epoch  = clock.epoch,
        .pubkey = init_account_params->authorized_voter,
      };
      fd_vec_fd_vote_historical_authorized_voter_t_new( &vote_state->authorized_voters );
      fd_vec_fd_vote_historical_authorized_voter_t_push( &vote_state->authorized_voters, authorized_voter );
      vote_state->authorized_withdrawer = init_account_params->authorized_withdrawer;
      vote_state->commission = init_account_params->commission;

      /* Write the new vote account back to the database */
      int result = write_vote_state( ctx, vote_acc, vote_state_versioned );
      if ( result != FD_EXECUTOR_INSTR_SUCCESS ) {
        FD_LOG_WARNING(( "failed to write versioned vote state: %d", result ));
        return result;
      }

      fd_vote_state_versioned_destroy( vote_state_versioned, ctx.global->freef, ctx.global->allocf_arg );
    } else if ( fd_vote_instruction_is_vote( &instruction ) ) {
      /* VoteInstruction::Vote instruction
         https://github.com/solana-labs/solana/blob/8f2c8b8388a495d2728909e30460aa40dcc5d733/programs/vote/src/vote_instruction.rs#L39-L46
       */
      FD_LOG_INFO(( "executing VoteInstruction::Vote instruction" ));
      fd_vote_t * vote = &instruction.inner.vote;

      /* Check that the accounts are correct */
      uchar * instr_acc_idxs = ((uchar *)ctx.txn_ctx->txn_raw->raw + ctx.instr->acct_off);
      fd_pubkey_t * txn_accs = (fd_pubkey_t *)((uchar *)ctx.txn_ctx->txn_raw->raw + ctx.txn_ctx->txn_descriptor->acct_addr_off);
      fd_pubkey_t * vote_acc = &txn_accs[instr_acc_idxs[0]];

      /* Ensure that keyed account 1 is the slot hashes sysvar */
      if ( memcmp( &txn_accs[instr_acc_idxs[1]], ctx.global->sysvar_slot_hashes, sizeof(fd_pubkey_t) ) != 0 ) {
        return FD_EXECUTOR_INSTR_ERR_INVALID_ARG;
      }

      /* Ensure that keyed account 2 is the clock sysvar */
      if ( memcmp( &txn_accs[instr_acc_idxs[2]], ctx.global->sysvar_clock, sizeof(fd_pubkey_t) ) != 0 ) {
        return FD_EXECUTOR_INSTR_ERR_INVALID_ARG;
      }

      /* Read the vote account state from the database */
      fd_vote_state_versioned_t vote_state_versioned;
      int result = get_and_verify_versioned_vote_state( ctx, instr_acc_idxs, txn_accs, vote_acc, &vote_state_versioned );
      if ( result != FD_EXECUTOR_INSTR_SUCCESS ) {
        FD_LOG_WARNING(( "failed to get and verify versioned vote state: %d", result ));
        return result;
      }
      fd_vote_state_t* vote_state = &vote_state_versioned.inner.current;

      /* Process the vote
         https://github.com/solana-labs/solana/blob/8f2c8b8388a495d2728909e30460aa40dcc5d733/programs/vote/src/vote_state/mod.rs#L902
       */
      
      /* Check that the vote slots aren't empty */
      if ( vote->slots.cnt == 0 ) {        
        /* TODO: propagate custom error code FD_VOTE_EMPTY_SLOTS */
        return FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;
      }

      /* Filter out vote slots older than the earliest slot present in the slot hashes history.
         https://github.com/solana-labs/solana/blob/8f2c8b8388a495d2728909e30460aa40dcc5d733/programs/vote/src/vote_state/mod.rs#L912-L926
       */
      fd_slot_hashes_t slot_hashes;
      fd_sysvar_slot_hashes_read( ctx.global, &slot_hashes );

      ulong earliest_slot_in_history = 0;
      if ( slot_hashes.hashes.cnt > 0 ) {
        earliest_slot_in_history = slot_hashes.hashes.elems[ slot_hashes.hashes.cnt - 1 ].slot;
      }

      fd_vec_ulong_t vote_slots;
      fd_vec_ulong_new( &vote_slots );
      for ( ulong i = 0; i < vote->slots.cnt; i++ ) {
        if ( vote->slots.elems[i] >= earliest_slot_in_history ) {
          fd_vec_ulong_push( &vote_slots, vote->slots.elems[i] );
        }
      } 

      if ( vote_slots.cnt == 0 ) {
        /* TODO: propagate custom error code FD_VOTE_VOTES_TOO_OLD_ALL_FILTERED */
        return FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;
      }

      /* Check that all the slots in the vote tower are present in the slot hashes,
         in the same order they are present in the vote tower.

         https://github.com/solana-labs/solana/blob/8f2c8b8388a495d2728909e30460aa40dcc5d733/programs/vote/src/vote_state/mod.rs#L658
       */
      ulong vote_idx = 0;
      ulong slot_hash_idx = slot_hashes.hashes.cnt;
      while ( vote_idx < vote_slots.cnt && slot_hash_idx > 0 ) {

        /* Skip to the smallest vote slot that is newer than the last slot we previously voted on.  */
        if ( ( vote_state->votes.cnt > 0 ) && ( vote_slots.elems[ vote_idx ] <= vote_state->votes.elems[ vote_state->votes.cnt - 1 ].slot ) ) {
          vote_idx += 1;
          continue;
        }

        /* Find the corresponding slot hash entry for that slot. */
        if ( vote_slots.elems[ vote_idx ] != slot_hashes.hashes.elems[ slot_hash_idx - 1 ].slot ) {
          slot_hash_idx -= 1;
          continue;
        }

        /* When we have found a hash for that slot, move on to the next proposed slot. */
        vote_idx      += 1;
        slot_hash_idx -= 1;

      }

      /* Check that there does exist a proposed vote slot newer than the last slot we previously voted on:
         if so, we would have made some progress through the slot hashes. */
      if ( slot_hash_idx == slot_hashes.hashes.cnt ) {
        ulong previously_voted_on = vote_state->votes.elems[ vote_state->votes.cnt - 1 ].slot;
        ulong most_recent_proposed_vote_slot = vote->slots.elems[ vote->slots.cnt - 1 ];
        FD_LOG_INFO(( "vote instruction too old (%lu <= %lu): discarding", most_recent_proposed_vote_slot, previously_voted_on ));
        
        /* TODO: propagate custom error code FD_VOTE_VOTE_TOO_OLD */
        /* TODO: return FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR and properly handle failed transactions */
        return FD_EXECUTOR_INSTR_SUCCESS;
      }

      /* Check that for each slot in the vote tower, we found a slot in the slot hashes:
         if so, we would have got to the end of the vote tower. */
      if ( vote_idx != vote_slots.cnt ) {
        /* TODO: propagate custom error code FD_VOTE_SLOTS_MISMATCH */
        return FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;
      }

      /* Check that the vote hash, which is the hash for the slot at the top of the vote tower,
         matches the slot hashes hash for that slot. */
      if ( memcmp( &slot_hashes.hashes.elems[ slot_hash_idx ].hash, &vote->hash, sizeof(fd_hash_t) ) != 0 ) {
        char slot_hash_hash[50];
        fd_base58_encode_32((uchar *) &slot_hashes.hashes.elems[ slot_hash_idx ].hash, 0, slot_hash_hash);

        char vote_hash_hash[50];
        fd_base58_encode_32((uchar *) &vote->hash, 0, vote_hash_hash);

        FD_LOG_INFO(( "hash mismatch: slot_hash: %s vote_hash: %s", slot_hash_hash, vote_hash_hash ));
        /* TODO: propagate custom error code FD_VOTE_SLOT_HASH_MISMATCH */
        /* FIXME: re-visit when bank hashes are confirmed to be good */
        // return FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;
      }

      /* Process each vote slot, pushing any new slots in the vote onto our lockout tower.
         https://github.com/solana-labs/solana/blob/8f2c8b8388a495d2728909e30460aa40dcc5d733/programs/vote/src/vote_state/mod.rs#L941
       */
      for ( ulong i = 0; i < vote_slots.cnt; i++ ) {
        ulong vote_slot = vote_slots.elems[i];

        /* Skip the slot if it is older than the the last slot we previously voted on. */
        if ( ( vote_state->votes.cnt > 0 ) && ( vote_slot <= vote_state->votes.elems[ vote_state->votes.cnt - 1 ].slot ) ) {
          continue;
        }

        /* Pop all recent votes that are not locked out at the next vote slot. This has two effects:
           - Allows validators to switch forks after their lockout period has expired.
           - Allows validators to continue voting on recent blocks in the same fork without increasing their lockouts.

           https://github.com/solana-labs/solana/blob/8f2c8b8388a495d2728909e30460aa40dcc5d733/programs/vote/src/vote_state/mod.rs#L1135
        */
        while ( vote_state->votes.cnt > 0 ) {
          fd_vote_lockout_t lockout = vote_state->votes.elems[ vote_state->votes.cnt - 1 ];
          if ( ( ( lockout.slot + (ulong)pow( INITIAL_LOCKOUT, lockout.confirmation_count ) ) < vote_slot ) ) {
            fd_vec_fd_vote_lockout_t_pop_unsafe( &vote_state->votes );
          } else {
            break;
          }
        }

        /* Check if the lockout stack is full: we have committed to a fork. */
        if ( vote_state->votes.cnt == MAX_LOCKOUT_HISTORY ) {

          /* Update the root slot to be the oldest lockout. */
          vote_state->saved_root_slot = fd_alloca( 1UL, sizeof(ulong) );
          *vote_state->saved_root_slot = vote_state->votes.elems[0].slot;

          /* Give this validator a credit for committing to a slot. */
          if ( vote_state->epoch_credits.cnt == 0 ) {
            fd_vote_epoch_credits_t epoch_credits = {
              .epoch = 0,
              .credits = 0,
              .prev_credits = 0,
            };
            fd_vec_fd_vote_epoch_credits_t_push( &vote_state->epoch_credits, epoch_credits );
          }
          vote_state->epoch_credits.elems[0].credits += 1;

          /* Pop the oldest slot from the lockout tower. */
          fd_vec_fd_vote_lockout_t_remove_at( &vote_state->votes, 0 );

        }

        /* Push the current vote onto the lockouts stack. */
        fd_vote_lockout_t vote_lockout = {
          .slot = vote_slot,
          .confirmation_count = 1,
        };
        fd_vec_fd_vote_lockout_t_push( &vote_state->votes, vote_lockout );

        /* Because we add a new vote to the tower, double the lockouts of existing votes in the tower.
           https://github.com/solana-labs/solana/blob/8f2c8b8388a495d2728909e30460aa40dcc5d733/programs/vote/src/vote_state/mod.rs#L1145
        */
        for ( ulong j = 0; j < vote_state->votes.cnt; j++ ) {
          /* Double the lockout for this vote slot if our lockout stack is now deeper than the largest number of confirmations this vote slot has seen. */
          ulong confirmations = j + vote_state->votes.elems[ j ].confirmation_count;
          if ( vote_state->votes.cnt > confirmations ) {
            /* Increment the confirmation count, implicitly doubling the lockout. */
            vote_state->votes.elems[ j ].confirmation_count += 1;
          } 
        }
      }

      /* Check that the vote tower is now non-empty. */
      if ( vote_state->votes.cnt == 0 ) {
        /* TODO: propagate custom error code FD_VOTE_EMPTY_SLOTS */
        return FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;
      }

      /* Check that the vote is new enough, and if so update the timestamp.
         https://github.com/solana-labs/solana/blob/8f2c8b8388a495d2728909e30460aa40dcc5d733/programs/vote/src/vote_state/mod.rs#L1386-L1392
      */
      if ( vote->timestamp != NULL ) {
        ulong highest_vote_slot = 0;
        for ( ulong i = 0; i < vote->slots.cnt; i++ ) {
          /* TODO: can maybe just use vote at top of tower? Seems safer to use same logic as Solana though. */
          highest_vote_slot = fd_ulong_max( highest_vote_slot, vote->slots.elems[i] );
        }

        if ( highest_vote_slot < vote_state->latest_timestamp.slot || *vote->timestamp < vote_state->latest_timestamp.timestamp ) {
          /* TODO: propagate custom error code FD_VOTE_TIMESTAMP_TOO_OLD */
          return FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;
        }

        /* If we have previously received a vote with this slot and a different
           timestamp, reject it. */
        if ( highest_vote_slot == vote_state->latest_timestamp.slot &&
             *vote->timestamp != vote_state->latest_timestamp.timestamp &&
             vote_state->latest_timestamp.timestamp != 0 ) {
          /* TODO: propagate custom error code FD_VOTE_TIMESTAMP_TOO_OLD */
          return FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;
        }
      }

      /* Write the new state back to the database */
      result = write_vote_state( ctx, vote_acc, &vote_state_versioned );
      if ( result != FD_EXECUTOR_INSTR_SUCCESS ) {
        FD_LOG_WARNING(( "failed to write versioned vote state: %d", result ));
        return result;
      }

      /* Record the timestamp vote */
      if ( vote->timestamp != NULL ) {
        record_timestamp_vote( ctx.global, vote_acc, *vote->timestamp );
      }

      fd_vote_state_versioned_destroy( &vote_state_versioned, ctx.global->freef, ctx.global->allocf_arg );
    } else if ( fd_vote_instruction_is_update_vote_state( &instruction ) ) {
      /* VoteInstruction::UpdateVoteState instruction
         https://github.com/solana-labs/solana/blob/8f2c8b8388a495d2728909e30460aa40dcc5d733/programs/vote/src/vote_processor.rs#L174
       */
      FD_LOG_INFO(( "executing VoteInstruction::UpdateVoteState instruction" ));
      fd_vote_state_update_t * vote_state_update = &instruction.inner.update_vote_state;

      /* Read vote account state stored in the vote account data */
      uchar * instr_acc_idxs = ((uchar *)ctx.txn_ctx->txn_raw->raw + ctx.instr->acct_off);
      fd_pubkey_t * txn_accs = (fd_pubkey_t *)((uchar *)ctx.txn_ctx->txn_raw->raw + ctx.txn_ctx->txn_descriptor->acct_addr_off);
      fd_pubkey_t * vote_acc = &txn_accs[instr_acc_idxs[0]];

      /* Read the vote state */
      fd_vote_state_versioned_t vote_state_versioned;
      int result = get_and_verify_versioned_vote_state( ctx, instr_acc_idxs, txn_accs, vote_acc, &vote_state_versioned );
      if ( result != FD_EXECUTOR_INSTR_SUCCESS ) {
        FD_LOG_WARNING(( "failed to get and verify versioned vote state: %d", result ));
        return result;
      }
      fd_vote_state_t* vote_state = &vote_state_versioned.inner.current;

      /* Execute the extremely thin minimal slice of the vote state update logic necessary to validate our test ledger, lifted from
         https://github.com/solana-labs/solana/blob/8f2c8b8388a495d2728909e30460aa40dcc5d733/programs/vote/src/vote_state/mod.rs#L886-L898
         This skips all the safety checks, and assumes many things including that:
         - The vote state update is valid and for the current epoch
         - The vote is for the current fork
         - ...
      */

      /* If the root has changed, give this validator a credit for doing work */
      /* In mininal slice proposed_root will always be present */
      if ( vote_state->saved_root_slot == NULL || ( *vote_state_update->proposed_root != *vote_state->saved_root_slot ) ) {
        if ( vote_state->epoch_credits.cnt == 0 ) {
          fd_vote_epoch_credits_t epoch_credits = {
            .epoch = 0,
            .credits = 0,
            .prev_credits = 0,
          };
          fd_vec_fd_vote_epoch_credits_t_push( &vote_state->epoch_credits, epoch_credits );
        }
        vote_state->epoch_credits.elems[0].credits += 1;
      }

      /* Update the new root slot, timestamp and votes */
      if ( vote_state_update->timestamp != NULL ) {
        vote_state->latest_timestamp.slot = vote_state_update->lockouts[ vote_state_update->lockouts_len - 1 ].slot;
        vote_state->latest_timestamp.timestamp = *vote_state_update->timestamp;
      }
      /* TODO: add constructors to fd_types */
      if ( vote_state->saved_root_slot == NULL ) {
        vote_state->saved_root_slot = (ulong *)(ctx.global->allocf)( ctx.global->allocf_arg, 8UL, sizeof(ulong) );
      }
      *vote_state->saved_root_slot = *vote_state_update->proposed_root;
      fd_vec_fd_vote_lockout_t_clear( &vote_state->votes );
      for ( ulong i = 0; i < vote_state_update->lockouts_len; i++ ) {
        fd_vec_fd_vote_lockout_t_push( &vote_state->votes, vote_state_update->lockouts[i] );
      }

      /* Write the new state back to the database */
      result = write_vote_state( ctx, vote_acc, &vote_state_versioned );
      if ( result != FD_EXECUTOR_INSTR_SUCCESS ) {
        FD_LOG_WARNING(( "failed to write versioned vote state: %d", result ));
        return result;
      }

      if ( vote_state_update->timestamp != NULL ) {
        record_timestamp_vote( ctx.global, vote_acc, *vote_state_update->timestamp );
      }

      fd_vote_state_versioned_destroy( &vote_state_versioned, ctx.global->freef, ctx.global->allocf_arg );
    } else {
      /* TODO: support other vote program instructions */
      FD_LOG_ERR(( "unsupported vote program instruction: discriminant: %d", instruction.discriminant ));
      return FD_EXECUTOR_INSTR_ERR_INVALID_ARG;
    }

    fd_vote_instruction_destroy( &instruction, ctx.global->freef, ctx.global->allocf_arg );

    return FD_EXECUTOR_INSTR_SUCCESS;
}

/* https://github.com/solana-labs/solana/blob/8f2c8b8388a495d2728909e30460aa40dcc5d733/programs/vote/src/vote_state/mod.rs#L1041 */
void fd_vote_acc_credits( fd_global_ctx_t* global, fd_pubkey_t* vote_acc, ulong* result ) {

  fd_vote_state_versioned_t versioned;
  read_vote_state( global, vote_acc, &versioned );

  if ( fd_vote_state_versioned_is_current( &versioned ) ) {
    fd_vote_state_t* state = &versioned.inner.current;
    if ( state->epoch_credits.cnt == 0 ) {
      *result = 0;
    } else {
      *result = state->epoch_credits.elems[ state->epoch_credits.cnt - 1 ].credits;
    }
  } else {
    /* TODO: conversion function from old vote state to current */
    FD_LOG_ERR(( "legacy v0_23_5 vote state not supported yet" ));
  }

  fd_vote_state_versioned_destroy( &versioned, global->freef, global->allocf_arg );
}
