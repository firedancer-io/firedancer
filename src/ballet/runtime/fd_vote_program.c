#include "fd_vote_program.h"
#include "fd_sysvars.h"
#include "fd_executor.h"
#include "../../ballet/txn/fd_compact_u16.h"

struct fd_vote_lockout {
  fd_slot_t slot;
  uchar     confirmation_count;
};
typedef struct fd_vote_lockout fd_vote_lockout_t;

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
void fd_decode_varint( ulong* self, void const** data, FD_FN_UNUSED void const* dataend ) {
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
    
    return FD_EXECUTOR_INSTR_SUCCESS;
}
