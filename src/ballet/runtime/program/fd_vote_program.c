#include "fd_vote_program.h"
#include "../fd_executor.h"
#include "../../../ballet/txn/fd_compact_u16.h"

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

    if ( discrimant == 8 ) {
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
      int read_result = fd_acc_mgr_get_metadata( ctx.global->acc_mgr, vote_acc, &metadata );
      if ( FD_UNLIKELY( read_result != FD_ACC_MGR_SUCCESS ) ) {
        FD_LOG_WARNING(( "failed to read account metadata" ));
        return read_result;
      }
      uchar *vota_acc_data = (uchar *)(ctx.global->allocf)(ctx.global->allocf_arg, 8UL, metadata.dlen);
      read_result = fd_acc_mgr_get_account_data( ctx.global->acc_mgr, vote_acc, (uchar*)vota_acc_data, sizeof(fd_account_meta_t), metadata.dlen );
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
      ulong encoded_vote_state_size = fd_vote_state_size( &vote_state );

      /* Write the new account data. Write at offset (dlen + 4) to preserve VoteStateVersions enum discriminant */
      uchar* encoded_vote_state = (uchar *)(ctx.global->allocf)( ctx.global->allocf_arg, 8UL, encoded_vote_state_size );
      void* encode_vote_state_dest = encoded_vote_state;
      fd_vote_state_encode( &vote_state, (const void **)(&encode_vote_state_dest) );

      /* TEST: decode the result again, and check that it is correct (encoding-decoding flow works end-to-end) */
      // fd_vote_state_t check_vote_state;
      // void* check_vote_state_input = encoded_vote_state;
      // void *check_vote_state_dataend = ((uchar *)check_vote_state_input) + encoded_vote_state_size;
      // fd_vote_state_decode(&check_vote_state, (const void**)&check_vote_state_input, check_vote_state_dataend, ctx.global->allocf, ctx.global->allocf_arg);

      /* TODO: write back max(previous size, new size). Maybe move this abstraction into the accounts manager. */
      int write_result = fd_acc_mgr_write_account_data( ctx.global->acc_mgr, &ctx.global->funk_txn, vote_acc, (ulong)(metadata.hlen + 4), (uchar*)encoded_vote_state, encoded_vote_state_size );
      if ( write_result != FD_ACC_MGR_SUCCESS ) {
        FD_LOG_WARNING(( "failed to write account data" ));
        return write_result;
      }

      /* Record this timestamp vote */
      if ( vote_state_update.timestamp != NULL ) {
        uchar found = 0;
        for ( ulong i = 0; i < ctx.global->timestamp_votes.votes.cnt; i++ ) {
          if ( memcmp( &ctx.global->timestamp_votes.votes.elems[i].pubkey, vote_acc, sizeof(fd_pubkey_t) ) == 0 ) {
            ctx.global->timestamp_votes.votes.elems[i].slot      = ctx.global->current_slot;
            ctx.global->timestamp_votes.votes.elems[i].timestamp = (long)*vote_state_update.timestamp;
            found = 1;
          }
        } 
        if ( !found ) {
          fd_clock_timestamp_vote_t timestamp_vote = {
            .pubkey    = *vote_acc,
            .timestamp = (long)*vote_state_update.timestamp,
            .slot      = ctx.global->current_slot,
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
