#include "fd_vote_program.h"
#include "../fd_executor.h"
#include "../../../ballet/txn/fd_compact_u16.h"
#include "../fd_runtime.h"
#include "../../base58/fd_base58.h"
#include "../sysvar/fd_sysvar.h"

int fd_executor_vote_program_execute_instruction(
    instruction_ctx_t ctx
) {
    /* TODO: template out bincode decoding of enums */

    /* Deserialize the VoteInstruction enum */
    /* solana/sdk/program/src/vote/instruction.rs::VoteInstruction */
    uchar *data            = (uchar *)ctx.txn_raw->raw + ctx.instr->data_off;
    void* input            = (void *)data;
    const void** input_ptr = (const void **)&input;
    void* dataend          = (void*)&data[ctx.instr->data_sz];

    uint discrimant  = 0;
    fd_bincode_uint32_decode( &discrimant, input_ptr, dataend );

    FD_LOG_INFO(( "decoded vote program discriminant: %d", discrimant ));

    if ( discrimant == 2 ) {
      /* VoteInstruction::Vote instruction
         https://github.com/solana-labs/solana/blob/8f2c8b8388a495d2728909e30460aa40dcc5d733/programs/vote/src/vote_instruction.rs#L39-L46
       */
      FD_LOG_INFO(( "executing VoteInstruction::Vote instruction" ));

      /* Check that the accounts are correct */
      uchar * instr_acc_idxs = ((uchar *)ctx.txn_raw->raw + ctx.instr->acct_off);
      fd_pubkey_t * txn_accs = (fd_pubkey_t *)((uchar *)ctx.txn_raw->raw + ctx.txn_descriptor->acct_addr_off);
      fd_pubkey_t * vote_acc = &txn_accs[instr_acc_idxs[0]];

      /* Ensure that keyed account 1 is the slot hashes sysvar */
      if ( memcmp( &txn_accs[instr_acc_idxs[1]], ctx.global->sysvar_slot_hashes, sizeof(fd_pubkey_t) ) != 0 ) {
        return FD_EXECUTOR_INSTR_ERR_INVALID_ARG;
      }

      /* Ensure that keyed account 2 is the clock sysvar */
      if ( memcmp( &txn_accs[instr_acc_idxs[2]], ctx.global->sysvar_clock, sizeof(fd_pubkey_t) ) != 0 ) {
        return FD_EXECUTOR_INSTR_ERR_INVALID_ARG;
      }

      /* Decode the vote instruction */
      fd_vote_t vote;
      fd_vote_decode(&vote, input_ptr, dataend, ctx.global->allocf, ctx.global->allocf_arg);

      /* Read vote account state stored in the vote account data */
      fd_account_meta_t metadata;
      int read_result = fd_acc_mgr_get_metadata( ctx.global->acc_mgr, ctx.global->funk_txn, vote_acc, &metadata );
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
      input     = (void *)vota_acc_data;
      input_ptr = (const void **)&input;
      dataend   = (void*)&vota_acc_data[metadata.dlen];

      /* Decode the disciminant */
      discrimant  = 0;
      fd_bincode_uint32_decode( &discrimant, input_ptr, dataend );
      if ( discrimant != 1 ) {
          /* TODO: support legacy V0_23_5 vote state layout */
          FD_LOG_ERR(( "unsupported vote account state version: discrimant: %d", discrimant ));
          return FD_EXECUTOR_INSTR_ERR_INVALID_ARG;
      }

      /* Decode the current vote state */
      fd_vote_state_t vote_state;
      fd_vote_state_decode(&vote_state, input_ptr, dataend, ctx.global->allocf, ctx.global->allocf_arg);

      /* Check that the vote state account is initialized */
      if ( vote_state.authorized_voters_len == 0 ) {
        return FD_EXECUTOR_INSTR_ERR_UNINITIALIZED_ACCOUNT;
      }

      /* Get the current authorized voter for the current epoch */
      /* TODO: handle epoch rollover */
      fd_pubkey_t authorized_voter = vote_state.authorized_voters->pubkey;

      /* Check that the authorized voter for this epoch has signed the vote transaction
         https://github.com/solana-labs/solana/blob/8f2c8b8388a495d2728909e30460aa40dcc5d733/programs/vote/src/vote_state/mod.rs#L1265
       */
      uchar authorized_voter_signed = 0;
      for ( ulong i = 0; i < ctx.instr->acct_cnt; i++ ) {
        if ( instr_acc_idxs[i] < ctx.txn_descriptor->signature_cnt ) {
          fd_pubkey_t * signer = &txn_accs[instr_acc_idxs[0]];
          if ( !memcmp( signer, &authorized_voter, sizeof(fd_pubkey_t) ) ) {
            authorized_voter_signed = 1;
            break;
          }
        }
      }
      if ( !authorized_voter_signed ) {
        return FD_EXECUTOR_INSTR_ERR_MISSING_REQUIRED_SIGNATURE;
      }

      /* Process the vote
         https://github.com/solana-labs/solana/blob/8f2c8b8388a495d2728909e30460aa40dcc5d733/programs/vote/src/vote_state/mod.rs#L902
       */
      
      /* Check that the vote slots aren't empty */
      if ( vote.slots.cnt == 0 ) {        
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
      for ( ulong i = 0; i < vote.slots.cnt; i++ ) {
        if ( vote.slots.elems[i] >= earliest_slot_in_history ) {
          fd_vec_ulong_push( &vote_slots, vote.slots.elems[i] );
        }
      } 

      if ( vote_slots.cnt == 0 ) {
        /* TODO: propagate custom error code FD_VOTE_VOTES_TOO_OLD_ALL_FILTERED */
        return FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;
      }


    } else if ( discrimant == 8 ) {
      /* VoteInstruction::UpdateVoteState instruction
         https://github.com/solana-labs/solana/blob/8f2c8b8388a495d2728909e30460aa40dcc5d733/programs/vote/src/vote_processor.rs#L174
       */
      FD_LOG_INFO(( "executing VoteInstruction::UpdateVoteState instruction" ));

      /* Decode the vote state update instruction */
      fd_vote_state_update_t vote_state_update;
      fd_vote_state_update_decode(&vote_state_update, input_ptr, dataend, ctx.global->allocf, ctx.global->allocf_arg);

      /* Read vote account state stored in the vote account data */
      uchar * instr_acc_idxs = ((uchar *)ctx.txn_raw->raw + ctx.instr->acct_off);
      fd_pubkey_t * txn_accs = (fd_pubkey_t *)((uchar *)ctx.txn_raw->raw + ctx.txn_descriptor->acct_addr_off);
      fd_pubkey_t * vote_acc = &txn_accs[instr_acc_idxs[0]];

      fd_account_meta_t metadata;
      int read_result = fd_acc_mgr_get_metadata( ctx.global->acc_mgr, ctx.global->funk_txn, vote_acc, &metadata );
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
      input     = (void *)vota_acc_data;
      input_ptr = (const void **)&input;
      dataend   = (void*)&vota_acc_data[metadata.dlen];

      /* Decode the disciminant */
      discrimant  = 0;
      fd_bincode_uint32_decode( &discrimant, input_ptr, dataend );
      if ( discrimant != 1 ) {
          /* TODO: support legacy V0_23_5 vote state layout */
          FD_LOG_ERR(( "unsupported vote account state version: discrimant: %d", discrimant ));
          return FD_EXECUTOR_INSTR_ERR_INVALID_ARG;
      }

      /* Decode the current vote state */
      fd_vote_state_t vote_state;
      fd_vote_state_decode(&vote_state, input_ptr, dataend, ctx.global->allocf, ctx.global->allocf_arg);

      /* Execute the extremely thin minimal slice of the vote state update logic necessary to validate our test ledger, lifted from
         https://github.com/solana-labs/solana/blob/8f2c8b8388a495d2728909e30460aa40dcc5d733/programs/vote/src/vote_state/mod.rs#L886-L898
         This skips all the safety checks, and assumes many things including that:
         - The vote state update is valid and for the current epoch
         - The vote is for the current fork
         - ...
      */

      /* If the root has changed, give this validator a credit for doing work */
      /* In mininal slice proposed_root will always be present */
      if ( vote_state.saved_root_slot == NULL || ( *vote_state_update.proposed_root != *vote_state.saved_root_slot ) ) {
        if ( vote_state.epoch_credits.cnt == 0 ) {
          fd_vote_epoch_credits_t epoch_credits = {
            .epoch = 0,
            .credits = 0,
            .prev_credits = 0,
          };
          fd_vec_fd_vote_epoch_credits_t_push( &vote_state.epoch_credits, epoch_credits );
        }
        vote_state.epoch_credits.elems[0].credits += 1;
      }

      /* Update the new root slot, timestamp and votes */
      if ( vote_state_update.timestamp != NULL ) {
        vote_state.latest_timestamp.slot = vote_state_update.lockouts[ vote_state_update.lockouts_len - 1 ].slot;
        vote_state.latest_timestamp.timestamp = *vote_state_update.timestamp;
      }
      /* TODO: add constructors to fd_types */
      if ( vote_state.saved_root_slot == NULL ) {
        vote_state.saved_root_slot = (ulong *)(ctx.global->allocf)( ctx.global->allocf_arg, 8UL, sizeof(ulong) );
      }
      *vote_state.saved_root_slot = *vote_state_update.proposed_root;
      fd_vec_fd_vote_lockout_t_clear( &vote_state.votes );
      for ( ulong i = 0; i < vote_state_update.lockouts_len; i++ ) {
        fd_vec_fd_vote_lockout_t_push( &vote_state.votes, vote_state_update.lockouts[i] );
      }

      /* Write the new state back to the database */
      /* Add 4 to the size, for discriminant */
      ulong encoded_vote_state_size = fd_vote_state_size( &vote_state ) + 4;

      if (encoded_vote_state_size < 3731)
        encoded_vote_state_size = 3731;

      /* Encode and write the new account data. */
      uchar* encoded_vote_state = (uchar *)(ctx.global->allocf)( ctx.global->allocf_arg, 8UL, encoded_vote_state_size );
      fd_memset(encoded_vote_state, 0, encoded_vote_state_size);


      void* encoded_vote_state_vp = (void*)encoded_vote_state;
      const void ** encode_vote_state_dest = (const void **)(&encoded_vote_state_vp);
      fd_bincode_uint32_encode( &discrimant, encode_vote_state_dest );
      fd_vote_state_encode( &vote_state, encode_vote_state_dest );

      /* TEST: decode the result again, and check that it is correct (encoding-decoding flow works end-to-end) */
      // fd_vote_state_t check_vote_state;
      // void* check_vote_state_input = encoded_vote_state;
      // void *check_vote_state_dataend = ((uchar *)check_vote_state_input) + encoded_vote_state_size;
      // fd_vote_state_decode(&check_vote_state, (const void**)&check_vote_state_input, check_vote_state_dataend, ctx.global->allocf, ctx.global->allocf_arg);

      fd_solana_account_t structured_account;
      structured_account.data = encoded_vote_state;
      structured_account.data_len = encoded_vote_state_size;
      structured_account.executable = 0;
      structured_account.rent_epoch = 0;
      memcpy( &structured_account.owner, ctx.global->solana_vote_program, sizeof(fd_pubkey_t) );

      int write_result = fd_acc_mgr_write_structured_account( ctx.global->acc_mgr, ctx.global->funk_txn, ctx.global->bank.solana_bank.slot, vote_acc, &structured_account );
      if ( write_result != FD_ACC_MGR_SUCCESS ) {
        FD_LOG_WARNING(( "failed to write account data" ));
        return write_result;
      }

      fd_acc_mgr_update_hash ( ctx.global->acc_mgr, &metadata, ctx.global->funk_txn, ctx.global->bank.solana_bank.slot, vote_acc, (uchar*)encoded_vote_state, encoded_vote_state_size);

      /* Record this timestamp vote */
      if ( vote_state_update.timestamp != NULL ) {
        uchar found = 0;
        for ( ulong i = 0; i < ctx.global->timestamp_votes.votes.cnt; i++ ) {
          if ( memcmp( &ctx.global->timestamp_votes.votes.elems[i].pubkey, vote_acc, sizeof(fd_pubkey_t) ) == 0 ) {
            ctx.global->timestamp_votes.votes.elems[i].slot      = ctx.global->bank.solana_bank.slot;
            ctx.global->timestamp_votes.votes.elems[i].timestamp = (long)*vote_state_update.timestamp;
            found = 1;
          }
        } 
        if ( !found ) {
          fd_clock_timestamp_vote_t timestamp_vote = {
            .pubkey    = *vote_acc,
            .timestamp = (long)*vote_state_update.timestamp,
            .slot      = ctx.global->bank.solana_bank.slot,
          };
          fd_vec_fd_clock_timestamp_vote_t_push( &ctx.global->timestamp_votes.votes, timestamp_vote );
        }
      }

      fd_vote_state_destroy( &vote_state, ctx.global->freef, ctx.global->allocf_arg );
      fd_vote_state_update_destroy( &vote_state_update, ctx.global->freef, ctx.global->allocf_arg );
    } else {
      /* TODO: support other vote program instructions */
      FD_LOG_ERR(( "unsupported vote program instruction: discrimant: %d", discrimant ));
      return FD_EXECUTOR_INSTR_ERR_INVALID_ARG;
    }
    

    return FD_EXECUTOR_INSTR_SUCCESS;
}
