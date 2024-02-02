#include "../fd_executor.h"
#include "fd_ed25519_program.h"
#include "../fd_acc_mgr.h"
#include "../context/fd_exec_txn_ctx.h"
#include <assert.h>

/* Useful links:

   https://docs.solana.com/developing/runtime-facilities/programs#ed25519-program
   https://github.com/solana-labs/solana/blob/master/sdk/src/ed25519_instruction.rs */

struct __attribute__((packed)) fd_ed25519_sig_offsets {
  ushort sig_offset;
  ushort sig_instr_idx;
  ushort pubkey_offset;
  ushort pubkey_instr_idx;
  ushort msg_offset;
  ushort msg_data_sz;
  ushort msg_instr_idx;
};

typedef struct fd_ed25519_sig_offsets fd_ed25519_signature_offsets_t;

#define PUBKEY_SERIALIZED_SIZE            (32)
#define SIGNATURE_SERIALIZED_SIZE         (64)
#define SIGNATURE_OFFSETS_SERIALIZED_SIZE (14)
#define SIGNATURE_OFFSETS_START            (2)

FD_STATIC_ASSERT( sizeof( fd_ed25519_signature_offsets_t )==14, fd_ballet );

static int
_get_instr_data( fd_exec_instr_ctx_t ctx,
                 ulong               index,
                 ulong               offset,
                 ulong               sz,
                 void const **       res ) {

  assert( (offset<=USHORT_MAX) & (sz<=USHORT_MAX) );

  uchar const * data;
  ulong         data_sz;
  if( index == USHORT_MAX ) {

    /* Use current instruction data */

    data    = ctx.instr->data;
    data_sz = ctx.instr->data_sz;

  } else {

    /* Use data of a transaction-level (0) instruction.
       TODO How does this behave in nested CPI?  Does it use
            sibling-level data or transaction-level data? */

    fd_txn_t const * txn_descriptor = ctx.txn_ctx->txn_descriptor;
    if( FD_UNLIKELY( index >= txn_descriptor->instr_cnt ) )
      return FD_EXECUTOR_SIGN_ERR_DATA_OFFSETS;

    fd_txn_instr_t const * instr = &txn_descriptor->instr[index];
    data    = (uchar const *)ctx.txn_ctx->_txn_raw->raw + instr->data_off;
    data_sz = instr->data_sz;

  }

  if( FD_UNLIKELY( offset+sz > data_sz ) )  /* (offset+sz) in [0,2^17) */
    return FD_EXECUTOR_SIGN_ERR_DATA_OFFSETS;

  *res = data + offset;
  return 0;
}

int
fd_ed25519_program_execute( fd_exec_instr_ctx_t ctx ) {

  uchar const * data    = ctx.instr->data;
  ulong         data_sz = ctx.instr->data_sz;

  /* TODO: shouldn't this be an executor error? */
  if( FD_UNLIKELY( data_sz < 2UL ) )
    return FD_EXECUTOR_SIGN_ERR_INSTRUCTION_DATA_SIZE;

  ulong sig_cnt = data[0];
  ulong off     = SIGNATURE_OFFSETS_START;

  for( ulong i = 0; i < sig_cnt; ++i ) {
    if( FD_UNLIKELY( off + SIGNATURE_OFFSETS_SERIALIZED_SIZE > data_sz ) )
      return FD_EXECUTOR_SIGN_ERR_INSTRUCTION_DATA_SIZE;
    fd_ed25519_signature_offsets_t const * sigoffs = (const fd_ed25519_signature_offsets_t *) (data + off);
    off += SIGNATURE_OFFSETS_SERIALIZED_SIZE;

    void const * sig = NULL;
    int err = _get_instr_data( ctx,
                               sigoffs->sig_instr_idx,
                               sigoffs->sig_offset,
                               SIGNATURE_SERIALIZED_SIZE,
                               &sig );
    if( FD_UNLIKELY( err ) ) return err;

    void const * pubkey = NULL;
    err = _get_instr_data( ctx,
                           sigoffs->pubkey_instr_idx,
                           sigoffs->pubkey_offset,
                           PUBKEY_SERIALIZED_SIZE,
                           &pubkey );
    if( FD_UNLIKELY( err ) ) return err;

    void const * msg = NULL;
    ushort msg_sz = sigoffs->msg_data_sz;
    err = _get_instr_data( ctx,
                           sigoffs->msg_instr_idx,
                           sigoffs->msg_offset,
                           msg_sz,
                           &msg );
    if( FD_UNLIKELY( err ) ) return err;

    fd_sha512_t sha[1];
    if( fd_ed25519_verify( msg, msg_sz, sig, pubkey, sha )!=FD_ED25519_SUCCESS )
      return FD_EXECUTOR_SIGN_ERR_SIGNATURE;
  }

  return FD_EXECUTOR_INSTR_SUCCESS;
}
