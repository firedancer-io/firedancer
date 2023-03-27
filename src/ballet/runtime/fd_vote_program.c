#include "fd_vote_program.h"
#include "fd_sysvars.h"
#include "fd_executor.h"
#include "../../ballet/txn/fd_compact_u16.h"

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

    if ( discrimant == 8 ) { /* VoteInstruction::UpdateVoteState */
      FD_LOG_INFO(( "executing VoteInstruction::UpdateVoteState instruction" ));

      /* Decode the VoteInstruction::UpdateVoteState instruction
         https://github.com/solana-labs/solana/blob/8f2c8b8388a495d2728909e30460aa40dcc5d733/programs/vote/src/vote_instruction.rs#L92-L97
       */

    }
    else if ( discrimant == 12 ) { /* VoteInstruction::CompactVoteStateUpdate (not present in v1.13.6) */
      FD_LOG_INFO(( "executing VoteInstruction::CompactVoteStateUpdate instruction" ));

      /* Decode the VoteInstruction::CompactVoteStateUpdate instruction from the encoding detailed in
        solana/sdk/program/src/vote/state/mod.rs::serde_compact_vote_state_update.
        See solana/sdk/program/src/vote/instruction.rs::VoteInstruction
        
        The encoding is as follows:
        - The proposed root, encoded as a u64.
        - The lockout, encoded as a vector in the "Short Vec" format:
          see https://github.com/solana-labs/solana/blob/master/sdk/program/src/short_vec.rs
          
          This is a normal bincode vector, but the length is encoded as a variable-length "Short U16".
          - The elements of the lockout vector are tuples of slot offsets and confirmation counts.
            - The slot offsets are cumulative offsets, starting at the proposed root. These are encoded
              in the variable-length serde_varint format.
            - Confirmation counts are uchars.
        - The vote's bank hash, encoded as a 32-byte array.
        - The processing timestamp of the last slot, encoded as a ulong. */

      /* Decode the vote tower */
      fd_compact_vote_state_update_t compact_vote;
      fd_compact_vote_state_update_decode(&compact_vote, input_ptr, dataend, ctx.global->allocf, ctx.global->allocf_arg);

      fd_compact_vote_state_update_destroy(&compact_vote, ctx.global->freef, ctx.global->freef_arg);

  //    ulong proposed_root = 0;
  //    fd_bincode_uint64_decode( &proposed_root, input_ptr, dataend );
  //
  //    /* Decode the proposed tower of votes (for slot/lockout pairs) */
  //    ushort lockouts_len = 0;
  //    fd_decode_short_u16( &lockouts_len, input_ptr, dataend );
  //
  //    fd_vote_lockout_t lockouts[lockouts_len];
  //    ulong current_lockout_slot = proposed_root;
  //    for ( ushort i = 0; i < lockouts_len; i++ ) {
  //      ulong offset = 0;
  //      fd_decode_varint( &offset, input_ptr, dataend );
  //      current_lockout_slot += offset;
  //      lockouts[i].slot = current_lockout_slot;
  //      FD_LOG_INFO(( "slot: %lu", lockouts[i].slot ));
  //      fd_bincode_uint8_decode( &lockouts[i].confirmation_count, input_ptr, dataend );
  //      FD_LOG_INFO(( "confirmation_count: %d", lockouts[i].confirmation_count ));
  //    }
  //
  //    /* Decode the hash */
  //    fd_hash_t hash;
  //    fd_bincode_bytes_decode( (uchar *)&hash.hash, sizeof(hash), input_ptr, dataend );
  //    FD_LOG_HEXDUMP_INFO(( "hash", &hash, sizeof(hash) ));
  //
  //    /* Decode the processing timestamp of last slot */
  //    fd_unix_timestamp_t timestamp = 0;
  //    uchar timestamp_present = 0;
  //    fd_bincode_uint8_decode( &timestamp_present, input_ptr, dataend );
  //    if ( timestamp_present ) {
  //      fd_bincode_uint64_decode( &timestamp, input_ptr, dataend );
  //      FD_LOG_INFO(( "timestamp: %lu", timestamp ));
  //    }

      /* Skip reading in sysvars, as we are skipping safety checks for minimal slice */

      /* Read vote account data */
      uchar * instr_acc_idxs = ((uchar *)ctx.txn_raw->raw + ctx.instr->acct_off);
      fd_pubkey_t * txn_accs = (fd_pubkey_t *)((uchar *)ctx.txn_raw->raw + ctx.txn_descriptor->acct_addr_off);
      fd_pubkey_t * vote_acc = &txn_accs[instr_acc_idxs[0]];

      fd_account_meta_t metadata;
      int read_result = fd_acc_mgr_get_metadata( ctx.acc_mgr, vote_acc, &metadata );
      if ( FD_UNLIKELY( read_result != FD_ACC_MGR_SUCCESS ) ) {
        FD_LOG_WARNING(( "failed to read account metadata" ));
        return read_result;
      }
      uchar *vota_acc_data = fd_alloca(8UL, metadata.dlen);
      read_result = fd_acc_mgr_get_account_data( ctx.acc_mgr, vote_acc, (uchar*)vota_acc_data, sizeof(fd_account_meta_t), metadata.dlen );
      if ( read_result != FD_ACC_MGR_SUCCESS ) {
        FD_LOG_WARNING(( "failed to read account data" ));
        return read_result;
      }
      
      /* Decoding the VoteStateVersions enum: solana/programs/vote/src/vote_processor.rs::VoteStateVersions */
      input     = (void *)vota_acc_data;
      input_ptr = (const void **)&input;
      dataend   = (void*)&vota_acc_data[metadata.dlen];

      /* Decode the disciminant */
      discrimant  = 0;
      fd_bincode_uint32_decode( &discrimant, input_ptr, dataend );
      if ( discrimant != 1 ) {
          /* TODO: support legacy V0_23_5 vote state layout */
          FD_LOG_ERR(( "unsupported vote state version: discrimant: %d", discrimant ));
          return FD_EXECUTOR_INSTR_ERR_INVALID_ARG;
      }

      /* Decode the VoteState data structure: solana/sdk/program/src/vote/state/mod.rs::VoteState */
      fd_vote_state_t vote_state;
      fd_vote_state_decode(&vote_state, input_ptr, dataend, ctx.global->allocf, ctx.global->allocf_arg);

      fd_vote_state_destroy(&vote_state, ctx.global->freef, ctx.global->freef_arg);
    } else {
      /* TODO: support other vote program instructions */
      FD_LOG_ERR(( "unsupported vote program instruction: discrimant: %d", discrimant ));
      return FD_EXECUTOR_INSTR_ERR_INVALID_ARG;
    }
    

    return FD_EXECUTOR_INSTR_SUCCESS;
}
