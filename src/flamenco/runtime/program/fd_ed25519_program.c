// https://docs.solana.com/developing/runtime-facilities/programs#ed25519-program
// https://github.com/solana-labs/solana/blob/master/sdk/src/ed25519_instruction.rs#L85

#include "../fd_executor.h"
#include "fd_ed25519_program.h"
#include "../fd_acc_mgr.h"

struct fd_ed25519_signature_offsets {
  ushort signature_offset;
  ushort signature_instruction_index;
  ushort public_key_offset;
  ushort public_key_instruction_index;
  ushort message_data_offset;
  ushort message_data_size;
  ushort message_instruction_index;
};
typedef struct fd_ed25519_signature_offsets fd_ed25519_signature_offsets_t;

static const ulong PUBKEY_SERIALIZED_SIZE = 32;
static const ulong SIGNATURE_SERIALIZED_SIZE = 64;
static const ulong SIGNATURE_OFFSETS_SERIALIZED_SIZE = 14;
static const ulong SIGNATURE_OFFSETS_START = 2;

FD_STATIC_ASSERT( alignof( fd_ed25519_signature_offsets_t )==sizeof( ushort ), fd_ballet );
FD_STATIC_ASSERT( sizeof( fd_ed25519_signature_offsets_t )==14, fd_ballet );

static int fd_executor_ed25519_program_get_data( fd_exec_instr_ctx_t ctx, ulong index, ulong offset, ulong sz, void const ** res ) {
  uchar const * data;
  ulong data_sz;
  if ( index == USHORT_MAX) {
    data = ctx.instr->data;
    data_sz = ctx.instr->data_sz;
  } else {
    fd_txn_t * txn_descriptor = ctx.txn_ctx->txn_descriptor;
    if ( index >= txn_descriptor->instr_cnt )
      return FD_EXECUTOR_SIGN_ERR_DATA_OFFSETS;
    fd_txn_instr_t * instr = &txn_descriptor->instr[index];
    data = (uchar const *)ctx.txn_ctx->_txn_raw->raw + instr->data_off;
    data_sz = instr->data_sz;
  }
  if ( offset + sz > data_sz )
    return FD_EXECUTOR_SIGN_ERR_DATA_OFFSETS;
  *res = data + offset;
  return 0;
}

int fd_executor_ed25519_program_execute_instruction( fd_exec_instr_ctx_t ctx ) {
  uchar const * data = ctx.instr->data;
  ulong data_sz = ctx.instr->data_sz;

  if ( data_sz < 2 )
    return FD_EXECUTOR_SIGN_ERR_INSTRUCTION_DATA_SIZE;
  ulong numsigs = data[0];
  ulong off = SIGNATURE_OFFSETS_START;
  
  for( ulong i = 0; i < numsigs; ++i ) {
    if ( off + SIGNATURE_OFFSETS_SERIALIZED_SIZE > data_sz )
      return FD_EXECUTOR_SIGN_ERR_INSTRUCTION_DATA_SIZE;
    const fd_ed25519_signature_offsets_t * sigoffs = (const fd_ed25519_signature_offsets_t *) (data + off);
    off += SIGNATURE_OFFSETS_SERIALIZED_SIZE;

    void const * sig = NULL;
    int err = fd_executor_ed25519_program_get_data( ctx,
                                                    sigoffs->signature_instruction_index,
                                                    sigoffs->signature_offset,
                                                    SIGNATURE_SERIALIZED_SIZE,
                                                    &sig );
    if ( err ) return err;
    
    void const * pubkey = NULL;
    err = fd_executor_ed25519_program_get_data( ctx,
                                                sigoffs->public_key_instruction_index,
                                                sigoffs->public_key_offset,
                                                PUBKEY_SERIALIZED_SIZE,
                                                &pubkey );
    if ( err ) return err;
    
    void const * msg = NULL;
    ushort msg_sz = sigoffs->message_data_size;
    err = fd_executor_ed25519_program_get_data( ctx,
                                                sigoffs->message_instruction_index,
                                                sigoffs->message_data_offset,
                                                msg_sz,
                                                &msg );
    if ( err ) return err;

    fd_sha512_t sha;
    fd_sha512_init( &sha );

    if( fd_ed25519_verify( msg, msg_sz, sig, pubkey, &sha )!=FD_ED25519_SUCCESS ) {
      return FD_EXECUTOR_SIGN_ERR_SIGNATURE;
    }    
  }

  return FD_EXECUTOR_INSTR_SUCCESS;
}
