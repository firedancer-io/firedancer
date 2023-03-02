#include "fd_vote_program.h"
#include "fd_sysvars.h"
#include "fd_executor.h"
#include "../../ballet/txn/fd_compact_u16.h"

struct fd_vote_lockout {
  fd_slot_t slot;
  uchar     confirmation_count;
};
typedef struct fd_vote_lockout fd_vote_lockout_t;

struct fd_vote_authorized_voter {
  fd_epoch_t  epoch;
  fd_pubkey_t pubkey;
};
typedef struct fd_vote_authorized_voter fd_vote_authorized_voter_t;

/* A prior authorized voter and the epochs for which they were authorized */
struct fd_vote_prior_voter {
  fd_pubkey_t pubkey;
  fd_epoch_t  epoch_start; /* Inclusive */
  fd_epoch_t  epoch_end; /* Exclusive */
};
typedef struct fd_vote_prior_voter fd_vote_prior_voter_t;

/* How many credits earned by the end of an epoch */
struct fd_vote_epoch_credits {
  fd_epoch_t  epoch;
  ulong       credits;
  ulong       prev_credits;
};
typedef struct fd_vote_epoch_credits fd_vote_epoch_credits_t;

/* State of a Vote Account */
struct fd_vote_state {
  /* The node that votes in this account */
  fd_pubkey_t voting_node;
  /* The signer for withdrawals */
  fd_pubkey_t authorized_withdrawer;
  /* Percentage which represents what part of a rewards payout should be given to this vote account */
  uchar commission;
  /* The vote lockouts */
  fd_vote_lockout_t* votes;
  ulong votes_len;
  /* Saved root slot.
     This usually the last lockout which was popped from the votes, but it can be an arbitrary slot
     when being used inside the tower.
   */
  ulong *saved_root_slot;
  /* History of prior authorized voters and the epochs for which they were authorized. */
  fd_vote_prior_voter_t* prior_voters;
  ulong prior_voters_len;
  /* History of how many credits were earned by the end of each epoch. */
  fd_vote_epoch_credits_t* epoch_credits;
  ulong epoch_credits_len;
  /* Most recent timestamp submitted with a vote */
  fd_slot_t latest_slot;
  ulong latest_timestamp;
};
typedef struct fd_vote_state fd_vote_state_t;

/* Wrapper around fd_cu16_dec, to make the function signature more consistent with the
   other fd_bincode_decode functions.  */
ulong fd_decode_short_u16( ushort* self, void const** data, FD_FN_UNUSED void const* dataend ) {
  const uchar *ptr = (const uchar*) *data;

  ulong size = fd_cu16_dec( (uchar const *)*data, 3, self );
  if ( size == 0 ) {
    FD_LOG_ERR(( "failed to decode short u16" ));
  }
  *data = ptr + size;

  return size;

}

/* Decodes an integer encoded using the serde_varint algorithm:
   https://github.com/solana-labs/solana/blob/master/sdk/program/src/serde_varint.rs 
   
   A variable number of bytes could have been used to encode the integer.
   The most significant bit of each byte indicates if more bytes have been used, so we keep consuming until
   we reach a byte where the most significant bit is 0.
*/
void fd_decode_varint( ulong* self, void const** data, void const* dataend ) {
  const uchar *ptr = (const uchar *) *data;

  /* Determine how many bytes were used to encode the varint.
     The MSB of each byte indicates if more bytes have been used to encode the varint, so we consume
     until the MSB is 0 or we reach the maximum allowed number of bytes (to avoid an infinite loop).   
   */
  ulong bytes = 1;
  const ulong max_bytes = 8;
  while ( ( ( ptr[bytes - 1] & 0x80 ) != 0 ) && bytes < max_bytes ) {
    bytes = bytes + 1;
  }

  /* Use the lowest 7 bits of each byte */
  *self = 0;
  ulong shift = 0;
  for ( ulong i = 0; i < bytes; i++ ) {
    if (FD_UNLIKELY((void const *) (ptr + i) > dataend )) {
      FD_LOG_ERR(( "buffer underflow"));
    }

    *self |= (ulong)(( ptr[i] & 0x7F ) << shift);
    shift += 7;
  }

  *data = ptr + bytes;
}

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

    if ( discrimant != 12 ) {
        /* TODO: support other vote program instructions */
        FD_LOG_ERR(( "unsupported vote program instruction: discrimant: %d", discrimant ));
        return FD_EXECUTOR_INSTR_ERR_INVALID_ARG;
    }
    FD_LOG_INFO(( "executing compact update vote state" ));

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
    ulong proposed_root = 0;
    fd_bincode_uint64_decode( &proposed_root, input_ptr, dataend );

    /* Decode the proposed tower of votes (for slot/lockout pairs) */
    ushort lockouts_len = 0;
    fd_decode_short_u16( &lockouts_len, input_ptr, dataend );

    fd_vote_lockout_t lockouts[lockouts_len];
    ulong current_lockout_slot = proposed_root;
    for ( ushort i = 0; i < lockouts_len; i++ ) {
      ulong offset = 0;
      fd_decode_varint( &offset, input_ptr, dataend );
      current_lockout_slot += offset;
      lockouts[i].slot = current_lockout_slot;
      FD_LOG_INFO(( "slot: %lu", lockouts[i].slot ));
      fd_bincode_uint8_decode( &lockouts[i].confirmation_count, input_ptr, dataend );
      FD_LOG_INFO(( "confirmation_count: %d", lockouts[i].confirmation_count ));
    }

    /* Decode the hash */
    fd_hash_t hash;
    fd_bincode_bytes_decode( (uchar *)&hash.hash, sizeof(hash), input_ptr, dataend );
    FD_LOG_HEXDUMP_INFO(( "hash", &hash, sizeof(hash) ));

    /* Decode the processing timestamp of last slot */
    fd_unix_timestamp_t timestamp = 0;
    uchar timestamp_present = 0;
    fd_bincode_uint8_decode( &timestamp_present, input_ptr, dataend );
    if ( timestamp_present ) {
      fd_bincode_uint64_decode( &timestamp, input_ptr, dataend );
      FD_LOG_INFO(( "timestamp: %lu", timestamp ));
    }

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

    /* The node that votes in this account */
    fd_pubkey_t voting_node;
    fd_bincode_bytes_decode( (uchar *)&voting_node, sizeof(fd_pubkey_t), input_ptr, dataend );
    FD_LOG_HEXDUMP_INFO(( "voting_node", &voting_node, sizeof(fd_pubkey_t) ));

    /* The signer for withdrawals */
    fd_pubkey_t authorized_withdrawer;
    fd_bincode_bytes_decode( (uchar *)&authorized_withdrawer, sizeof(fd_pubkey_t), input_ptr, dataend );
    FD_LOG_HEXDUMP_INFO(( "authorized_withdrawer", &authorized_withdrawer, sizeof(fd_pubkey_t) ));

    /* Percentage which represents what part of a rewards payout should be given to this VoteAccount */
    uchar commission = 0;
    fd_bincode_uint8_decode( &commission, input_ptr, dataend );
    FD_LOG_INFO(( "commission: %d", commission ));

    /* Decoding the actual votes */
    ulong votes_len = 0;
    fd_bincode_uint64_decode( &votes_len, input_ptr, dataend );
    FD_LOG_INFO(( "votes_len: %lu", votes_len ));
    fd_vote_lockout_t votes[votes_len];
    for ( ulong i = 0; i < votes_len; i++ ) {
      fd_bincode_uint64_decode( &votes[i].slot, input_ptr, dataend );
      FD_LOG_INFO(( "slot: %lu", votes[i].slot ));
      fd_bincode_uint8_decode( &votes[i].confirmation_count, input_ptr, dataend );
      FD_LOG_INFO(( "confirmation_count: %d", votes[i].confirmation_count ));
    }

    /* Saved root slot */
    uchar has_saved_root_slot = fd_bincode_option_decode( input_ptr, dataend );
    ulong saved_root_slot = 0;
    if ( has_saved_root_slot ) {
      fd_bincode_uint64_decode( &saved_root_slot, input_ptr, dataend );
      FD_LOG_INFO(( "saved_root_slot: %lu", saved_root_slot ));
    }

    /* Authorized voters */
    ulong authorized_voters_len = 0;
    fd_bincode_uint64_decode( &authorized_voters_len, input_ptr, dataend );
    FD_LOG_INFO(( "authorized_voters_len: %lu", authorized_voters_len ));
    fd_vote_authorized_voter_t authorized_voters[authorized_voters_len];
    for ( ulong i = 0; i < authorized_voters_len; i++ ) {
      fd_bincode_uint64_decode( &authorized_voters[i].epoch, input_ptr, dataend );
      FD_LOG_INFO(( "authorized_voter epoch: %lu", authorized_voters[i].epoch ));
      fd_bincode_bytes_decode( (uchar *)&authorized_voters[i].pubkey, sizeof(fd_pubkey_t), input_ptr, dataend );
      FD_LOG_HEXDUMP_INFO(( "authorized_voter pubkey", &authorized_voters[i].pubkey, sizeof(fd_pubkey_t) ));
    }

    /* Prior voters */
    const ulong prior_voters_len = 32;
    fd_vote_prior_voter_t prior_voters[prior_voters_len];
    FD_LOG_INFO(( "prior_voters_len: %lu", prior_voters_len ));
    for ( ulong i = 0; i < prior_voters_len; i++ ) {
      fd_bincode_bytes_decode( (uchar *)&prior_voters[i].pubkey, sizeof(fd_pubkey_t), input_ptr, dataend );
      FD_LOG_HEXDUMP_INFO(( "prior voter pubkey", &prior_voters[i].pubkey, sizeof(fd_pubkey_t) ));
      fd_bincode_uint64_decode( &prior_voters[i].epoch_start, input_ptr, dataend );
      FD_LOG_INFO(( "prior voter epoch_start: %lu", prior_voters[i].epoch_start ));
      fd_bincode_uint64_decode( &prior_voters[i].epoch_end, input_ptr, dataend );
      FD_LOG_INFO(( "prior voter epoch_end: %lu", prior_voters[i].epoch_end ));
    }
    ulong prior_voters_idx = 0;
    fd_bincode_uint64_decode( &prior_voters_idx, input_ptr, dataend );
    FD_LOG_INFO(( "prior_voters_idx: %lu", prior_voters_idx ));
    uchar prior_voters_empty = 0;
    fd_bincode_uint8_decode( &prior_voters_empty, input_ptr, dataend );
    FD_LOG_INFO(( "prior_voters_empty: %d", prior_voters_empty ));

    /* Epoch credits */
    ulong epoch_credits_len = 0;
    fd_bincode_uint64_decode( &epoch_credits_len, input_ptr, dataend );
    FD_LOG_INFO(( "epoch_credits_len: %lu", epoch_credits_len ));
    fd_vote_epoch_credits_t epoch_credits[epoch_credits_len];
    for ( ulong i = 0; i < epoch_credits_len; i++ ) {
      fd_bincode_uint64_decode( &epoch_credits[i].epoch, input_ptr, dataend );
      FD_LOG_INFO(( "epoch credit epoch: %lu", epoch_credits[i].epoch ));
      fd_bincode_uint64_decode( &epoch_credits[i].credits, input_ptr, dataend );
      FD_LOG_INFO(( "epoch credit credits: %lu", epoch_credits[i].credits ));
      fd_bincode_uint64_decode( &epoch_credits[i].prev_credits, input_ptr, dataend );
      FD_LOG_INFO(( "epoch credit prev_credits: %lu", epoch_credits[i].prev_credits ));
    }

    /* Most recent timestamp submitted with a vote */
    fd_slot_t block_timestamp_slot = 0;
    fd_bincode_uint64_decode( &block_timestamp_slot, input_ptr, dataend );
    FD_LOG_INFO(( "block_timestamp_slot: %lu", block_timestamp_slot ));
    fd_slot_t block_timestamp_timestamp = 0;
    fd_bincode_uint64_decode( &block_timestamp_timestamp, input_ptr, dataend );
    FD_LOG_INFO(( "block_timestamp_timestamp: %lu", block_timestamp_timestamp ));

    return FD_EXECUTOR_INSTR_SUCCESS;
}
