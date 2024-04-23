// https://docs.solana.com/developing/runtime-facilities/programs#secp256k1-program
// https://github.com/solana-labs/solana/blob/master/sdk/src/secp256k1_instruction.rs#L932

#include "fd_secp256k1_program.h"
#include "../../features/fd_features.h"
#include "../context/fd_exec_epoch_ctx.h"
#include "../context/fd_exec_slot_ctx.h"

#if !FD_HAS_SECP256K1
int
fd_executor_secp256k1_program_execute_instruction( FD_PARAM_UNUSED fd_exec_instr_ctx_t ctx ) {
  return FD_EXECUTOR_INSTR_ERR_FATAL;
}
#else

#include "../fd_executor.h"
#include "../fd_runtime.h"
#include "../context/fd_exec_txn_ctx.h"
#include "../../../ballet/keccak256/fd_keccak256.h"
#include "../../../ballet/secp256k1/fd_secp256k1.h"

struct __attribute__((packed)) fd_secp256k1_signature_offsets {
  // Offset to 64-byte signature plus 1-byte recovery ID.
  ushort signature_offset;
  // Within the transaction, the index of the instruction whose instruction data contains the signature.
  uchar signature_instruction_index;
  // Offset to 20-byte Ethereum address.
  ushort eth_address_offset;
  // Within the transaction, the index of the instruction whose instruction data contains the address.
  uchar eth_address_instruction_index;
  // Offset to start of message data.
  ushort message_data_offset;
  // Size of message data in bytes.
  ushort message_data_size;
  // Within the transaction, the index of the instruction whose instruction data contains the message.
  uchar message_instruction_index;
};
typedef struct fd_secp256k1_signature_offsets fd_secp256k1_signature_offsets_t;

static const ulong HASHED_PUBKEY_SERIALIZED_SIZE = 20;
static const ulong SIGNATURE_SERIALIZED_SIZE = 64;
static const ulong SIGNATURE_OFFSETS_SERIALIZED_SIZE = 11;

FD_STATIC_ASSERT( alignof( fd_secp256k1_signature_offsets_t )==1, fd_ballet );
FD_STATIC_ASSERT( sizeof( fd_secp256k1_signature_offsets_t )==11, fd_ballet );

static int fd_executor_secp256k1_program_get_data( fd_exec_instr_ctx_t ctx, ulong index, ulong offset, ulong sz, void const ** res ) {
  uchar const * data;
  ulong data_sz;
  if ( index == USHORT_MAX) {
    data = ctx.instr->data;
    data_sz = ctx.instr->data_sz;
  } else {
    fd_txn_t const * txn_descriptor = ctx.txn_ctx->txn_descriptor;
    if ( index >= txn_descriptor->instr_cnt )
      return FD_EXECUTOR_SIGN_ERR_DATA_OFFSETS;
    fd_txn_instr_t const * instr = &txn_descriptor->instr[index];
    data = (uchar const *)ctx.txn_ctx->_txn_raw->raw + instr->data_off;
    data_sz = instr->data_sz;
  }
  if ( offset + sz > data_sz )
    return FD_EXECUTOR_SIGN_ERR_SIGNATURE;
  *res = data + offset;
  return 0;
}

int fd_executor_secp256k1_program_execute_instruction( fd_exec_instr_ctx_t ctx ) {
  uchar const * data = ctx.instr->data;
  ulong data_sz = ctx.instr->data_sz;

  if ( data_sz < 1 )
    return FD_EXECUTOR_SIGN_ERR_INSTRUCTION_DATA_SIZE;
  ulong numsigs = data[0];
  if( (    FD_FEATURE_ACTIVE( ctx.slot_ctx, libsecp256k1_fail_on_bad_count  )
        || FD_FEATURE_ACTIVE( ctx.slot_ctx, libsecp256k1_fail_on_bad_count2 ) )
      && numsigs == 0
      && data_sz > 1 )
    return FD_EXECUTOR_SIGN_ERR_INSTRUCTION_DATA_SIZE;
  if ( 1 + numsigs*SIGNATURE_OFFSETS_SERIALIZED_SIZE > data_sz )
    return FD_EXECUTOR_SIGN_ERR_INSTRUCTION_DATA_SIZE;

  for( ulong i = 0; i < numsigs; ++i ) {
    const fd_secp256k1_signature_offsets_t * sigoffs = (const fd_secp256k1_signature_offsets_t *)
      (data + 1 + i*SIGNATURE_OFFSETS_SERIALIZED_SIZE);

    void const * sig = NULL;
    int err = fd_executor_secp256k1_program_get_data( ctx,
                                                      sigoffs->signature_instruction_index,
                                                      sigoffs->signature_offset,
                                                      SIGNATURE_SERIALIZED_SIZE,
                                                      &sig );
    if ( err ) return ( err == FD_EXECUTOR_SIGN_ERR_DATA_OFFSETS ?
                        FD_EXECUTOR_SIGN_ERR_INSTRUCTION_DATA_SIZE : err );

    void const * recovery_id = NULL;
    err = fd_executor_secp256k1_program_get_data( ctx,
                                                  sigoffs->signature_instruction_index,
                                                  sigoffs->signature_offset + SIGNATURE_SERIALIZED_SIZE,
                                                  1,
                                                  &recovery_id );
    if ( err ) return err;

    void const * eth_address = NULL;
    err = fd_executor_secp256k1_program_get_data( ctx,
                                                  sigoffs->eth_address_instruction_index,
                                                  sigoffs->eth_address_offset,
                                                  HASHED_PUBKEY_SERIALIZED_SIZE,
                                                  &eth_address );
    if ( err ) return err;

    void const * msg = NULL;
    ushort msg_sz = sigoffs->message_data_size;
    err = fd_executor_secp256k1_program_get_data( ctx,
                                                  sigoffs->message_instruction_index,
                                                  sigoffs->message_data_offset,
                                                  msg_sz,
                                                  &msg );
    if ( err ) return err;

    uchar msg_hash[ FD_KECCAK256_HASH_SZ ];
    fd_keccak256_hash( msg, msg_sz, msg_hash );

    uchar pubkey[64];
    if ( fd_secp256k1_recover( pubkey, msg_hash, sig, *(const uchar*)recovery_id ) == NULL )
      return FD_EXECUTOR_SIGN_ERR_SIGNATURE;

    uchar pubkey_hash[ FD_KECCAK256_HASH_SZ ];
    fd_keccak256_hash( pubkey, 64, pubkey_hash );

    if ( memcmp( eth_address, &pubkey_hash[ FD_KECCAK256_HASH_SZ - HASHED_PUBKEY_SERIALIZED_SIZE ], HASHED_PUBKEY_SERIALIZED_SIZE ) )
      return FD_EXECUTOR_SIGN_ERR_SIGNATURE;
  }

  return FD_EXECUTOR_INSTR_SUCCESS;
}

#endif
