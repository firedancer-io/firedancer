#include "fd_vote_program.h"
#include "fd_sysvars.h"
#include "fd_executor.h"
#include "../../ballet/txn/fd_compact_u16.h"

struct fd_vote_lockout {
  fd_slot_t slot;
  uchar     confirmation_count;
};
typedef struct fd_vote_lockout fd_vote_lockout_t;

ulong fd_decode_short_u16( ushort* self, void const** data, FD_FN_UNUSED void const* dataend ) {

  ulong size = fd_cu16_dec( (uchar const *)*data, 3, self );
  for ( ulong i = 0; i < size; i++ ) {
    data += 1;
  }

  return size;

}

void fd_decode_varint( ulong* self, void const** data, void const* dataend ) {
  const uchar *ptr = (const uchar *) *data;

  /* Determine how many bytes were used to encode the varint.
     The MSB of each byte indicates if more bytes have been used to encode the varint, so we consume
     until the MSB is 0 or we reach the maximum allowed number of bytes (to avoid an infinite loop).   
   */
  ulong bytes = 0;
  const ulong max_bytes = 8;
  while ( ( ptr[bytes] & 0x80 ) && bytes < max_bytes ) {
    bytes += 1;
  }

  /* Use the lowest 7 bits of each byte */
  *self = 0;
  ulong shift = 0;
  for ( ulong i = 0; i < bytes; i++ ) {
    *self |= ( ptr[i] & 0x7FUL ) << shift;
    shift += 8;
  }
  ptr += bytes;

  if (FD_UNLIKELY((void const *) (ptr + 1) > dataend )) {
    FD_LOG_ERR(( "buffer underflow"));
  }
  *self = *ptr;
  *data = ptr + 1;

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
    FD_LOG_NOTICE(( "executing compact update vote state" ));

    /* Deserialize VoteInstruction::CompactVoteStateUpdate from the encoding described in
       solana/sdk/program/src/vote/state/mod.rs::serde_compact_vote_state_update */

    /*
    short_vec decoding:
    - length as ShortU16
      - Uses between 1 and 3 bytes
      - Remaining value stored in the next bytes
      - For each portion: if the value is above 0x7f, the top bit is set and the remaining value
        is stored in the next bytes.
      - The third byte, if needed, uses all 8 bits to store the last byte of the original value.
    - Remaining elements are serialized as usual
    - How to deserialize 

    LockoutOffset {
      Offset: Slot, // u64 serialized with varint 
      confirmation_count: u8,
    }

    CompactVoteStateUpdate {
      root: u64,
      lockout_offsets: vec<LockoutOffset> // vector serialized with short_vec,
      hash: 32-byte array,
      timestamp: Option<long> // first byte says if option is present or not
    }
    */

    /* Decode the vote tower */
    ulong proposed_root = 0;
    fd_bincode_uint64_decode( &proposed_root, input_ptr, dataend );
    FD_LOG_INFO(( "proposed_root: %lu", proposed_root )); /* Correct */

    FD_LOG_HEXDUMP_INFO(( "lockouts bytes", input_ptr, 20 ));

    /* Decode the proposed tower of votes (for slot/lockout pairs) */
    ushort lockouts_len = 0;
    fd_decode_short_u16( &lockouts_len, input_ptr, dataend );

    FD_LOG_INFO(( "lockouts len: %d", lockouts_len ));
    fd_vote_lockout_t lockouts[lockouts_len];
    for ( ushort i = 0; i < lockouts_len; i++ ) {
      fd_decode_varint( &lockouts[i].slot, input_ptr, dataend );
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
      /* TODO: decoding of signed integers */
      fd_bincode_uint64_decode( (ulong *) &timestamp, input_ptr, dataend );
      FD_LOG_NOTICE(( "timestamp: %lu", timestamp ));
    }

    /* Skip reading in sysvars, as we are skipping safety checks for minimal slice */

    /* Deserialize account metadata */
    fd_account_meta_t vote_account_meta;
    int read_result = fd_acc_mgr_get_metadata( ctx.acc_mgr, &vote_program_pubkey, &vote_account_meta );
    if ( FD_UNLIKELY( read_result != FD_ACC_MGR_SUCCESS ) ) {
      FD_LOG_ERR(( "failed to read vote program account metadata" ));
      return FD_EXECUTOR_INSTR_ERR_GENERIC_ERR;
    }
    


    return FD_EXECUTOR_INSTR_SUCCESS;
}
