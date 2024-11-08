#include <stdio.h>
#include <unistd.h>
#define ZSTD_STATIC_LINKING_ONLY
#include <zstd.h>
#include <errno.h>
#include "../../util/fd_util.h"
#include "../nanopb/pb_decode.h"
#include "fd_webserver.h"
#include "../../ballet/txn/fd_txn.h"
#include "../../ballet/block/fd_microblock.h"
#include "../../ballet/base58/fd_base58.h"
#include "../../ballet/zstd/fd_zstd.h"
#include "../types/fd_types.h"
#include "../types/fd_solana_block.pb.h"
#include "../runtime/fd_blockstore.h"
#include "../runtime/fd_executor_err.h"
#include "../runtime/fd_system_ids.h"
#include "fd_block_to_json.h"
#include "fd_stub_to_json.h"

#define EMIT_SIMPLE(_str_) fd_web_reply_append(ws, _str_, sizeof(_str_)-1)

void fd_tokenbalance_to_json( fd_webserver_t * ws, struct _fd_solblock_TokenBalance * b ) {
  fd_web_reply_sprintf(ws, "{\"accountIndex\":%u,\"mint\":\"%s\",\"owner\":\"%s\",\"programId\":\"%s\",\"uiTokenAmount\":{",
                       b->account_index, b->mint, b->owner, b->program_id);
  fd_web_reply_sprintf(ws, "\"amount\":\"%s\",", b->ui_token_amount.amount);
  int dec;
  if (b->ui_token_amount.has_decimals) {
    fd_web_reply_sprintf(ws, "\"decimals\":%u,", b->ui_token_amount.decimals);
    dec = (int)b->ui_token_amount.decimals;
  } else
    dec = 0;
  if (b->ui_token_amount.has_ui_amount)
    fd_web_reply_sprintf(ws, "\"uiAmount\":%.*f,", dec, b->ui_token_amount.ui_amount);
  fd_web_reply_sprintf(ws, "\"uiAmountString\":\"%s\"}}", b->ui_token_amount.ui_amount_string);
}

static char const *
instr_strerror( int err ) {
  switch( err ) {
  case FD_EXECUTOR_INSTR_SUCCESS                                : return ""; // not used
  case FD_EXECUTOR_INSTR_ERR_FATAL                              : return ""; // not used
  case FD_EXECUTOR_INSTR_ERR_GENERIC_ERR                        : return "GenericError";
  case FD_EXECUTOR_INSTR_ERR_INVALID_ARG                        : return "InvalidArgument";
  case FD_EXECUTOR_INSTR_ERR_INVALID_INSTR_DATA                 : return "InvalidInstructionData";
  case FD_EXECUTOR_INSTR_ERR_INVALID_ACC_DATA                   : return "InvalidAccountData";
  case FD_EXECUTOR_INSTR_ERR_ACC_DATA_TOO_SMALL                 : return "AccountDataTooSmall";
  case FD_EXECUTOR_INSTR_ERR_INSUFFICIENT_FUNDS                 : return "InsufficientFunds";
  case FD_EXECUTOR_INSTR_ERR_INCORRECT_PROGRAM_ID               : return "IncorrectProgramId";
  case FD_EXECUTOR_INSTR_ERR_MISSING_REQUIRED_SIGNATURE         : return "MissingRequiredSignature";
  case FD_EXECUTOR_INSTR_ERR_ACC_ALREADY_INITIALIZED            : return "AccountAlreadyInitialized";
  case FD_EXECUTOR_INSTR_ERR_UNINITIALIZED_ACCOUNT              : return "UninitializedAccount";
  case FD_EXECUTOR_INSTR_ERR_UNBALANCED_INSTR                   : return "UnbalancedInstruction";
  case FD_EXECUTOR_INSTR_ERR_MODIFIED_PROGRAM_ID                : return "ModifiedProgramId";
  case FD_EXECUTOR_INSTR_ERR_EXTERNAL_ACCOUNT_LAMPORT_SPEND     : return "ExternalAccountLamportSpend";
  case FD_EXECUTOR_INSTR_ERR_EXTERNAL_DATA_MODIFIED             : return "ExternalAccountDataModified";
  case FD_EXECUTOR_INSTR_ERR_READONLY_LAMPORT_CHANGE            : return "ReadonlyLamportChange";
  case FD_EXECUTOR_INSTR_ERR_READONLY_DATA_MODIFIED             : return "ReadonlyDataModified";
  case FD_EXECUTOR_INSTR_ERR_DUPLICATE_ACCOUNT_IDX              : return "DuplicateAccountIndex";
  case FD_EXECUTOR_INSTR_ERR_EXECUTABLE_MODIFIED                : return "ExecutableModified";
  case FD_EXECUTOR_INSTR_ERR_RENT_EPOCH_MODIFIED                : return "RentEpochModified";
  case FD_EXECUTOR_INSTR_ERR_NOT_ENOUGH_ACC_KEYS                : return "NotEnoughAccountKeys";
  case FD_EXECUTOR_INSTR_ERR_ACC_DATA_SIZE_CHANGED              : return "AccountDataSizeChanged";
  case FD_EXECUTOR_INSTR_ERR_ACC_NOT_EXECUTABLE                 : return "AccountNotExecutable";
  case FD_EXECUTOR_INSTR_ERR_ACC_BORROW_FAILED                  : return "AccountBorrowFailed";
  case FD_EXECUTOR_INSTR_ERR_ACC_BORROW_OUTSTANDING             : return "AccountBorrowOutstanding";
  case FD_EXECUTOR_INSTR_ERR_DUPLICATE_ACCOUNT_OUT_OF_SYNC      : return "DuplicateAccountOutOfSync";
  case FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR                         : return "Custom(u32)";
  case FD_EXECUTOR_INSTR_ERR_INVALID_ERR                        : return "InvalidError";
  case FD_EXECUTOR_INSTR_ERR_EXECUTABLE_DATA_MODIFIED           : return "ExecutableDataModified";
  case FD_EXECUTOR_INSTR_ERR_EXECUTABLE_LAMPORT_CHANGE          : return "ExecutableLamportChange";
  case FD_EXECUTOR_INSTR_ERR_EXECUTABLE_ACCOUNT_NOT_RENT_EXEMPT : return "ExecutableAccountNotRentExempt";
  case FD_EXECUTOR_INSTR_ERR_UNSUPPORTED_PROGRAM_ID             : return "UnsupportedProgramId";
  case FD_EXECUTOR_INSTR_ERR_CALL_DEPTH                         : return "CallDepth";
  case FD_EXECUTOR_INSTR_ERR_MISSING_ACC                        : return "MissingAccount";
  case FD_EXECUTOR_INSTR_ERR_REENTRANCY_NOT_ALLOWED             : return "ReentrancyNotAllowed";
  case FD_EXECUTOR_INSTR_ERR_MAX_SEED_LENGTH_EXCEEDED           : return "MaxSeedLengthExceeded";
  case FD_EXECUTOR_INSTR_ERR_INVALID_SEEDS                      : return "InvalidSeeds";
  case FD_EXECUTOR_INSTR_ERR_INVALID_REALLOC                    : return "InvalidRealloc";
  case FD_EXECUTOR_INSTR_ERR_COMPUTE_BUDGET_EXCEEDED            : return "ComputationalBudgetExceeded";
  case FD_EXECUTOR_INSTR_ERR_PRIVILEGE_ESCALATION               : return "PrivilegeEscalation";
  case FD_EXECUTOR_INSTR_ERR_PROGRAM_ENVIRONMENT_SETUP_FAILURE  : return "ProgramEnvironmentSetupFailure";
  case FD_EXECUTOR_INSTR_ERR_PROGRAM_FAILED_TO_COMPLETE         : return "ProgramFailedToComplete";
  case FD_EXECUTOR_INSTR_ERR_PROGRAM_FAILED_TO_COMPILE          : return "ProgramFailedToCompile";
  case FD_EXECUTOR_INSTR_ERR_ACC_IMMUTABLE                      : return "Immutable";
  case FD_EXECUTOR_INSTR_ERR_INCORRECT_AUTHORITY                : return "IncorrectAuthority";
  case FD_EXECUTOR_INSTR_ERR_BORSH_IO_ERROR                     : return "BorshIoError(String)";
  case FD_EXECUTOR_INSTR_ERR_ACC_NOT_RENT_EXEMPT                : return "AccountNotRentExempt";
  case FD_EXECUTOR_INSTR_ERR_INVALID_ACC_OWNER                  : return "InvalidAccountOwner";
  case FD_EXECUTOR_INSTR_ERR_ARITHMETIC_OVERFLOW                : return "ArithmeticOverflow";
  case FD_EXECUTOR_INSTR_ERR_UNSUPPORTED_SYSVAR                 : return "UnsupportedSysvar";
  case FD_EXECUTOR_INSTR_ERR_ILLEGAL_OWNER                      : return "IllegalOwner";
  case FD_EXECUTOR_INSTR_ERR_MAX_ACCS_DATA_ALLOCS_EXCEEDED      : return "MaxAccountsDataAllocationsExceeded";
  case FD_EXECUTOR_INSTR_ERR_MAX_ACCS_EXCEEDED                  : return "MaxAccountsExceeded";
  case FD_EXECUTOR_INSTR_ERR_MAX_INSN_TRACE_LENS_EXCEEDED       : return "MaxInstructionTraceLengthExceeded";
  case FD_EXECUTOR_INSTR_ERR_BUILTINS_MUST_CONSUME_CUS          : return "BuiltinProgramsMustConsumeComputeUnits";
  default: break;
  }

  return "";
}

void
fd_error_to_json( fd_webserver_t * ws,
                  const uchar* bytes,
                  ulong size ) {
  const uchar* orig_bytes = bytes;
  ulong orig_size = size;

  if (size < sizeof(uint) )
    goto dump_as_hex;
  uint kind = *(const uint*)bytes;
  bytes += sizeof(uint);
  size -= sizeof(uint);

  if( kind == 8 /* Instruction error */ ) {
    if( size < 1 )
      goto dump_as_hex;
    uint index = *(bytes++); /* Instruction index */
    size--;

    if (size < sizeof(uint))
      goto dump_as_hex;
    int cnum =  *(const int*)bytes;
    bytes += sizeof(uint);
    size -= sizeof(uint);

    if( cnum == FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR ) {
      if (size < sizeof(uint))
        goto dump_as_hex;
      uint code = *(const uint*)bytes; /* Custom code? */
      fd_web_reply_sprintf(ws, "{\"InstructionError\":[%u,{\"Custom\":%u}]}", index, code);
      return;
    } else {
      fd_web_reply_sprintf(ws, "{\"InstructionError\":[%u,\"%s\"]}", index, instr_strerror( cnum ));
      return;
    }
  }

 dump_as_hex:
  EMIT_SIMPLE("\"");
  fd_web_reply_encode_hex(ws, orig_bytes, orig_size);
  EMIT_SIMPLE("\"");
}

void fd_inner_instructions_to_json( fd_webserver_t * ws,
                                    struct _fd_solblock_InnerInstructions * insts ) {
  fd_web_reply_sprintf(ws, "{\"index\":%u,\"instructions\":[", insts->index);
  for ( pb_size_t i = 0; i < insts->instructions_count; ++i ) {
    struct _fd_solblock_InnerInstruction * inst = insts->instructions + i;
    fd_web_reply_sprintf(ws, "%s{\"data\":\"", (i == 0 ? "" : ","));
    fd_web_reply_encode_base58(ws, inst->data->bytes, inst->data->size);
    fd_web_reply_sprintf(ws, "\",\"programIdIndex:\":%u}", inst->program_id_index);
  }
  EMIT_SIMPLE("]}");
}

struct decode_return_data_buf {
  uchar data[256];
  ulong sz;
};

static bool
decode_return_data(pb_istream_t *stream, const pb_field_t *field, void **arg) {
  (void)field;
  struct decode_return_data_buf * buf = (struct decode_return_data_buf *)(*arg);
  buf->sz = fd_ulong_min( sizeof(buf->data), stream->bytes_left );
  pb_read( stream, buf->data, buf->sz );
  return 1;
}

const char*
fd_txn_meta_to_json( fd_webserver_t * ws,
                     const void * meta_raw,
                     ulong meta_raw_sz ) {
  if( meta_raw==NULL || meta_raw_sz==0 ) {
    EMIT_SIMPLE("\"meta\":null,");
    return NULL;
  }

  fd_solblock_TransactionStatusMeta txn_status = {0};
  struct decode_return_data_buf return_data_buf;
  pb_callback_t return_data_cb = { .funcs.decode = decode_return_data, .arg = &return_data_buf };
  txn_status.return_data.data = return_data_cb;

  pb_istream_t stream = pb_istream_from_buffer( meta_raw, meta_raw_sz );
  if( FD_UNLIKELY( !pb_decode( &stream, fd_solblock_TransactionStatusMeta_fields, &txn_status ) ) ) {
    FD_LOG_ERR(( "failed to decode txn status: %s", PB_GET_ERROR( &stream ) ));
  }

  EMIT_SIMPLE("\"meta\":{");
  if (txn_status.has_compute_units_consumed)
    fd_web_reply_sprintf(ws, "\"computeUnitsConsumed\":%lu,", txn_status.compute_units_consumed);
  EMIT_SIMPLE("\"err\":");
  if (txn_status.has_err)
    fd_error_to_json(ws, txn_status.err.err->bytes, txn_status.err.err->size);
  else
    EMIT_SIMPLE("null");
  fd_web_reply_sprintf(ws, ",\"fee\":%lu,\"innerInstructions\":[", txn_status.fee);
  if (!txn_status.inner_instructions_none) {
    for (pb_size_t i = 0; i < txn_status.inner_instructions_count; ++i) {
      if ( i > 0 ) EMIT_SIMPLE(",");
      fd_inner_instructions_to_json(ws, txn_status.inner_instructions + i);
    }
  }
  EMIT_SIMPLE("],\"loadedAddresses\":{\"readonly\":[");
  for (pb_size_t i = 0; i < txn_status.loaded_readonly_addresses_count; ++i) {
    pb_bytes_array_t * ba = txn_status.loaded_readonly_addresses[i];
    if (ba->size == 32) {
      char buf32[FD_BASE58_ENCODED_32_SZ];
      fd_base58_encode_32(ba->bytes, NULL, buf32);
      fd_web_reply_sprintf(ws, "%s\"%s\"", (i == 0 ? "" : ","), buf32);
    } else
      fd_web_reply_sprintf(ws, "%s\"\"", (i == 0 ? "" : ","));
  }
  EMIT_SIMPLE("],\"writable\":[");
  for (pb_size_t i = 0; i < txn_status.loaded_writable_addresses_count; ++i) {
    pb_bytes_array_t * ba = txn_status.loaded_writable_addresses[i];
    if (ba->size == 32) {
      char buf32[FD_BASE58_ENCODED_32_SZ];
      fd_base58_encode_32(ba->bytes, NULL, buf32);
      fd_web_reply_sprintf(ws, "%s\"%s\"", (i == 0 ? "" : ","), buf32);
    } else
      fd_web_reply_sprintf(ws, "%s\"\"", (i == 0 ? "" : ","));
  }
  EMIT_SIMPLE("]},\"logMessages\":[");
  for (pb_size_t i = 0; i < txn_status.log_messages_count; ++i) {
    if( i ) EMIT_SIMPLE(",");
    fd_web_reply_encode_json_string(ws, txn_status.log_messages[i]);
  }
  EMIT_SIMPLE("],\"postBalances\":[");
  for (pb_size_t i = 0; i < txn_status.post_balances_count; ++i)
    fd_web_reply_sprintf(ws, "%s%lu", (i == 0 ? "" : ","), txn_status.post_balances[i]);
  EMIT_SIMPLE("],\"postTokenBalances\":[");
  for (pb_size_t i = 0; i < txn_status.post_token_balances_count; ++i) {
    if (i > 0) EMIT_SIMPLE(",");
    fd_tokenbalance_to_json(ws, txn_status.post_token_balances + i);
  }
  EMIT_SIMPLE("],\"preBalances\":[");
  for (pb_size_t i = 0; i < txn_status.pre_balances_count; ++i)
    fd_web_reply_sprintf(ws, "%s%lu", (i == 0 ? "" : ","), txn_status.pre_balances[i]);
  EMIT_SIMPLE("],\"preTokenBalances\":[");
  for (pb_size_t i = 0; i < txn_status.pre_token_balances_count; ++i) {
    if (i > 0) EMIT_SIMPLE(",");
    fd_tokenbalance_to_json(ws, txn_status.pre_token_balances + i);
  }
  EMIT_SIMPLE("]");
  if( txn_status.has_return_data ) {
    EMIT_SIMPLE(",\"returnData\":{\"data\":[\"");
    fd_web_reply_encode_base64( ws, return_data_buf.data, return_data_buf.sz );
    EMIT_SIMPLE("\",\"base64\"]");
    if( txn_status.return_data.has_program_id ) {
      char buf32[FD_BASE58_ENCODED_32_SZ];
      fd_base58_encode_32(txn_status.return_data.program_id, NULL, buf32);
      fd_web_reply_sprintf(ws, ",\"programId\":\"%s\"", buf32);
    }
    EMIT_SIMPLE("}");
  }
  EMIT_SIMPLE(",\"rewards\":[],\"status\":{\"Ok\":null}");
  EMIT_SIMPLE("},");

  pb_release( fd_solblock_TransactionStatusMeta_fields, &txn_status );

  return NULL;
}

const char*
generic_program_to_json( fd_webserver_t * ws,
                         fd_txn_t * txn,
                         fd_txn_instr_t * instr,
                         const uchar * raw,
                         int * need_comma ) {
  FD_SCRATCH_SCOPE_BEGIN { /* read_epoch consumes a ton of scratch space! */
    if( *need_comma ) EMIT_SIMPLE(",");
    EMIT_SIMPLE("{\"accounts\":[");
    const uchar * instr_acc_idxs = raw + instr->acct_off;
    const fd_pubkey_t * accts = (const fd_pubkey_t *)(raw + txn->acct_addr_off);
    for (ushort j = 0; j < instr->acct_cnt; j++) {
      char buf32[FD_BASE58_ENCODED_32_SZ];
      fd_base58_encode_32((const uchar*)(accts + instr_acc_idxs[j]), NULL, buf32);
      fd_web_reply_sprintf(ws, "%s\"%s\"", (j == 0 ? "" : ","), buf32);
    }
    EMIT_SIMPLE("],\"data\":\"");
    fd_web_reply_encode_base58(ws, raw + instr->data_off, instr->data_sz);
    char buf32[FD_BASE58_ENCODED_32_SZ];
    fd_base58_encode_32((const uchar*)(accts + instr->program_id), NULL, buf32);
    fd_web_reply_sprintf(ws, "\",\"program\":\"unknown\",\"programId\":\"%s\",\"stackHeight\":null}", buf32);
    *need_comma = 1;
  } FD_SCRATCH_SCOPE_END;
  return NULL;
}

const char*
vote_program_to_json( fd_webserver_t * ws,
                      fd_txn_t * txn,
                      fd_txn_instr_t * instr,
                      const uchar * raw,
                      int * need_comma ) {
  (void)txn;
  FD_SCRATCH_SCOPE_BEGIN { /* read_epoch consumes a ton of scratch space! */
    if( *need_comma ) EMIT_SIMPLE(",");
    fd_vote_instruction_t   instruction;
    fd_bincode_decode_ctx_t decode = {
      .data    = raw + instr->data_off,
      .dataend = raw + instr->data_off + instr->data_sz,
      .valloc  = fd_scratch_virtual()
    };
    int decode_result = fd_vote_instruction_decode( &instruction, &decode );
    if( decode_result != FD_BINCODE_SUCCESS ) {
      EMIT_SIMPLE("null");
      return NULL;
    }

    EMIT_SIMPLE("{\"parsed\":");

    fd_rpc_json_t * json = fd_rpc_json_init( fd_rpc_json_new( fd_scratch_alloc( fd_rpc_json_align(), fd_rpc_json_footprint() ) ), ws );
    fd_vote_instruction_walk( json, &instruction, fd_rpc_json_walk, NULL, 0 );

    EMIT_SIMPLE(",\"program\":\"vote\",\"programId\":\"Vote111111111111111111111111111111111111111\",\"stackHeight\":null}");
    *need_comma = 1;
  } FD_SCRATCH_SCOPE_END;
  return NULL;
}

const char *
system_program_to_json( fd_webserver_t * ws,
                        fd_txn_t * txn,
                        fd_txn_instr_t * instr,
                        const uchar * raw,
                        int * need_comma ) {
  (void)txn;
  FD_SCRATCH_SCOPE_BEGIN { /* read_epoch consumes a ton of scratch space! */
    if( *need_comma ) EMIT_SIMPLE(",");
    fd_system_program_instruction_t instruction;
    fd_bincode_decode_ctx_t decode = {
      .data    = raw + instr->data_off,
      .dataend = raw + instr->data_off + instr->data_sz,
      .valloc  = fd_scratch_virtual()
    };
    int decode_result = fd_system_program_instruction_decode( &instruction, &decode );
    if( decode_result != FD_BINCODE_SUCCESS ) {
      EMIT_SIMPLE("null");
      return NULL;
    }

    EMIT_SIMPLE("{\"parsed\":");

    fd_rpc_json_t * json = fd_rpc_json_init( fd_rpc_json_new( fd_scratch_alloc( fd_rpc_json_align(), fd_rpc_json_footprint() ) ), ws );
    fd_system_program_instruction_walk( json, &instruction, fd_rpc_json_walk, NULL, 0 );

    EMIT_SIMPLE(",\"program\":\"system\",\"programId\":\"11111111111111111111111111111111\",\"stackHeight\":null}");
    *need_comma = 1;
  } FD_SCRATCH_SCOPE_END;
  return NULL;
}

const char*
config_program_to_json( fd_webserver_t * ws,
                        fd_txn_t * txn,
                        fd_txn_instr_t * instr,
                        const uchar * raw,
                        int * need_comma ) {
  FD_LOG_WARNING(( "config_program_to_json not implemented" ));
  generic_program_to_json( ws, txn, instr, raw, need_comma );
  return NULL;
}

const char*
stake_program_to_json( fd_webserver_t * ws,
                       fd_txn_t * txn,
                       fd_txn_instr_t * instr,
                       const uchar * raw,
                       int * need_comma ) {
  FD_LOG_WARNING(( "stake_program_to_json not implemented" ));
  generic_program_to_json( ws, txn, instr, raw, need_comma );
  return NULL;
}

const char*
compute_budget_program_to_json( fd_webserver_t * ws,
                                fd_txn_t * txn,
                                fd_txn_instr_t * instr,
                                const uchar * raw,
                                int * need_comma ) {
  (void)txn;
  FD_SCRATCH_SCOPE_BEGIN { /* read_epoch consumes a ton of scratch space! */
    if( *need_comma ) EMIT_SIMPLE(",");
    fd_compute_budget_program_instruction_t instruction;
    fd_bincode_decode_ctx_t decode = {
      .data    = raw + instr->data_off,
      .dataend = raw + instr->data_off + instr->data_sz,
      .valloc  = fd_scratch_virtual()
    };
    int decode_result = fd_compute_budget_program_instruction_decode( &instruction, &decode );
    if( decode_result != FD_BINCODE_SUCCESS ) {
      EMIT_SIMPLE("null");
      return NULL;
    }

    EMIT_SIMPLE("{\"parsed\":");

    fd_rpc_json_t * json = fd_rpc_json_init( fd_rpc_json_new( fd_scratch_alloc( fd_rpc_json_align(), fd_rpc_json_footprint() ) ), ws );
    fd_compute_budget_program_instruction_walk( json, &instruction, fd_rpc_json_walk, NULL, 0 );

    EMIT_SIMPLE(",\"program\":\"compute_budget\",\"programId\":\"ComputeBudget111111111111111111111111111111\",\"stackHeight\":null}");
    *need_comma = 1;
  } FD_SCRATCH_SCOPE_END;
  return NULL;
}

const char*
address_lookup_table_program_to_json( fd_webserver_t * ws,
                                      fd_txn_t * txn,
                                      fd_txn_instr_t * instr,
                                      const uchar * raw,
                                      int * need_comma ) {
  FD_LOG_WARNING(( "address_lookup_table_program_to_json not implemented" ));
  generic_program_to_json( ws, txn, instr, raw, need_comma );
  return NULL;
}

const char*
executor_zk_elgamal_proof_program_to_json( fd_webserver_t * ws,
                                           fd_txn_t * txn,
                                           fd_txn_instr_t * instr,
                                           const uchar * raw,
                                           int * need_comma ) {
  FD_LOG_WARNING(( "executor_zk_elgamal_proof_program_to_json not implemented" ));
  generic_program_to_json( ws, txn, instr, raw, need_comma );
  return NULL;
}

const char*
bpf_loader_program_to_json( fd_webserver_t * ws,
                            fd_txn_t * txn,
                            fd_txn_instr_t * instr,
                            const uchar * raw,
                            int * need_comma ) {
  FD_LOG_WARNING(( "bpf_loader_program_to_json not implemented" ));
  generic_program_to_json( ws, txn, instr, raw, need_comma );
  return NULL;
}

const char*
fd_instr_to_json( fd_webserver_t * ws,
                  fd_txn_t * txn,
                  fd_txn_instr_t * instr,
                  const uchar * raw,
                  fd_rpc_encoding_t encoding,
                  int * need_comma ) {
  if( encoding == FD_ENC_JSON ) {
    if( *need_comma ) EMIT_SIMPLE(",");
    EMIT_SIMPLE("{\"accounts\":[");
    const uchar * instr_acc_idxs = raw + instr->acct_off;
    for (ushort j = 0; j < instr->acct_cnt; j++) {
      fd_web_reply_sprintf(ws, "%s%u", (j == 0 ? "" : ","), (uint)instr_acc_idxs[j]);
    }
    EMIT_SIMPLE("],\"data\":\"");
    fd_web_reply_encode_base58(ws, raw + instr->data_off, instr->data_sz);
    fd_web_reply_sprintf(ws, "\",\"programIdIndex\":%u,\"stackHeight\":null}", (uint)instr->program_id);
    *need_comma = 1;

  } else if( encoding == FD_ENC_JSON_PARSED ) {
    ushort acct_cnt = txn->acct_addr_cnt;
    const fd_pubkey_t * accts = (const fd_pubkey_t *)(raw + txn->acct_addr_off);
    if( instr->program_id >= acct_cnt ) {
      return NULL;
    }
    const fd_pubkey_t * prog = accts + instr->program_id;
    if ( !memcmp( prog, fd_solana_vote_program_id.key, sizeof( fd_pubkey_t ) ) ) {
      return vote_program_to_json( ws, txn, instr, raw, need_comma );
    } else if ( !memcmp( prog, fd_solana_system_program_id.key, sizeof( fd_pubkey_t ) ) ) {
      return system_program_to_json( ws, txn, instr, raw, need_comma );
    } else if ( !memcmp( prog, fd_solana_config_program_id.key, sizeof( fd_pubkey_t ) ) ) {
      return config_program_to_json( ws, txn, instr, raw, need_comma );
    } else if ( !memcmp( prog, fd_solana_stake_program_id.key, sizeof( fd_pubkey_t ) ) ) {
      return stake_program_to_json( ws, txn, instr, raw, need_comma );
    } else if ( !memcmp( prog, fd_solana_compute_budget_program_id.key, sizeof( fd_pubkey_t ) ) ) {
      return compute_budget_program_to_json( ws, txn, instr, raw, need_comma );
    } else if( !memcmp( prog, fd_solana_address_lookup_table_program_id.key, sizeof( fd_pubkey_t ) ) ) {
      return address_lookup_table_program_to_json( ws, txn, instr, raw, need_comma );
    } else if( !memcmp( prog, fd_solana_zk_elgamal_proof_program_id.key, sizeof( fd_pubkey_t ) ) ) {
      return executor_zk_elgamal_proof_program_to_json( ws, txn, instr, raw, need_comma );
    } else if( !memcmp( prog, fd_solana_bpf_loader_deprecated_program_id.key, sizeof( fd_pubkey_t ))) {
      return bpf_loader_program_to_json( ws, txn, instr, raw, need_comma );
    } else if( !memcmp( prog, fd_solana_bpf_loader_program_id.key, sizeof(fd_pubkey_t) ) ) {
      return bpf_loader_program_to_json( ws, txn, instr, raw, need_comma );
    } else if( !memcmp( prog, fd_solana_bpf_loader_upgradeable_program_id.key, sizeof(fd_pubkey_t) ) ) {
      return bpf_loader_program_to_json( ws, txn, instr, raw, need_comma );
    } else {
      generic_program_to_json( ws, txn, instr, raw, need_comma );
    }
  }
  return NULL;
}

const char*
fd_txn_to_json_full( fd_webserver_t * ws,
                     fd_txn_t* txn,
                     const uchar* raw,
                     ulong raw_sz,
                     fd_rpc_encoding_t encoding,
                     long maxvers ) {
  (void)maxvers;

  if( encoding == FD_ENC_BASE64 ) {
    EMIT_SIMPLE("\"transaction\":[\"");
    if (fd_web_reply_encode_base64(ws, raw, raw_sz)) {
      return "failed to encode data in base64";
    }
    EMIT_SIMPLE("\",\"base64\"]");
    return NULL;
  }

  if( encoding == FD_ENC_BASE58 ) {
    EMIT_SIMPLE("\"transaction\":[\"");
    if (fd_web_reply_encode_base58(ws, raw, raw_sz)) {
      return "failed to encode data in base58";
    }
    EMIT_SIMPLE("\",\"base58\"]");
    return NULL;
  }

  EMIT_SIMPLE("\"transaction\":{\"message\":{\"accountKeys\":[");

  ushort acct_cnt = txn->acct_addr_cnt;
  const fd_pubkey_t * accts = (const fd_pubkey_t *)(raw + txn->acct_addr_off);
  char buf32[FD_BASE58_ENCODED_32_SZ];

  if( encoding == FD_ENC_JSON ) {
    for (ushort idx = 0; idx < acct_cnt; idx++) {
      fd_base58_encode_32(accts[idx].uc, NULL, buf32);
      fd_web_reply_sprintf(ws, "%s\"%s\"", (idx == 0 ? "" : ","), buf32);
    }
  } else if( encoding == FD_ENC_JSON_PARSED ) {
    for (ushort idx = 0; idx < acct_cnt; idx++) {
      fd_base58_encode_32(accts[idx].uc, NULL, buf32);
      bool signer = (idx < txn->signature_cnt);
      bool writable = ((idx < txn->signature_cnt - txn->readonly_signed_cnt) ||
                       ((idx >= txn->signature_cnt) && (idx < acct_cnt - txn->readonly_unsigned_cnt)));
      fd_web_reply_sprintf(ws, "%s{\"pubkey\":\"%s\",\"signer\":%s,\"source\":\"transaction\",\"writable\":%s}",
                           (idx == 0 ? "" : ","), buf32, (signer ? "true" : "false"), (writable ? "true" : "false"));
    }
  }

  EMIT_SIMPLE("],");

  if( txn->transaction_version == FD_TXN_V0 ) {
    EMIT_SIMPLE("\"addressTableLookups\":[");
    fd_txn_acct_addr_lut_t const * addr_luts = fd_txn_get_address_tables_const( txn );
    for( ulong i = 0; i < txn->addr_table_lookup_cnt; i++ ) {
      if( i ) EMIT_SIMPLE(",");
      fd_txn_acct_addr_lut_t const * addr_lut = &addr_luts[i];
      fd_pubkey_t const * addr_lut_acc = (fd_pubkey_t *)(raw + addr_lut->addr_off);
      fd_base58_encode_32(addr_lut_acc->uc, NULL, buf32);
      fd_web_reply_sprintf(ws, "{\"accountKey\":\"%s\",\"readonlyIndexes\":[", buf32);
      uchar const * idxs = raw + addr_lut->readonly_off;
      for( uchar j = 0; j < addr_lut->readonly_cnt; j++ ) {
        if( j ) EMIT_SIMPLE(",");
        fd_web_reply_sprintf(ws, "%u", (uint)idxs[j]);
      }
      EMIT_SIMPLE("],\"writableIndexes\":[");
      idxs = raw + addr_lut->writable_off;
      for( uchar j = 0; j < addr_lut->writable_cnt; j++ ) {
        if( j ) EMIT_SIMPLE(",");
        fd_web_reply_sprintf(ws, "%u", (uint)idxs[j]);
      }
      EMIT_SIMPLE("]}");
    }
    EMIT_SIMPLE("],");
  }

  fd_web_reply_sprintf(ws, "\"header\":{\"numReadonlySignedAccounts\":%u,\"numReadonlyUnsignedAccounts\":%u,\"numRequiredSignatures\":%u},\"instructions\":[",
                       (uint)txn->readonly_signed_cnt, (uint)txn->readonly_unsigned_cnt, (uint)txn->signature_cnt);

  ushort instr_cnt = txn->instr_cnt;
  int need_comma = 0;
  for (ushort idx = 0; idx < instr_cnt; idx++) {
    const char * res = fd_instr_to_json( ws, txn, &txn->instr[idx], raw, encoding, &need_comma );
    if( res ) return res;
  }

  const fd_hash_t * recent = (const fd_hash_t *)(raw + txn->recent_blockhash_off);
  fd_base58_encode_32(recent->uc, NULL, buf32);
  fd_web_reply_sprintf(ws, "],\"recentBlockhash\":\"%s\"},\"signatures\":[", buf32);

  fd_ed25519_sig_t const * sigs = (fd_ed25519_sig_t const *)(raw + txn->signature_off);
  for ( uchar j = 0; j < txn->signature_cnt; j++ ) {
    char buf64[FD_BASE58_ENCODED_64_SZ];
    fd_base58_encode_64((const uchar*)&sigs[j], NULL, buf64);
    fd_web_reply_sprintf(ws, "%s\"%s\"", (j == 0 ? "" : ","), buf64);
  }

  const char* vers;
  switch (txn->transaction_version) {
  case FD_TXN_VLEGACY: vers = "\"legacy\""; break;
  case FD_TXN_V0:      vers = "0";          break;
  default:             vers = "\"?\"";      break;
  }
  fd_web_reply_sprintf(ws, "]},\"version\":%s", vers);


  return NULL;
}

const char*
fd_txn_to_json_accts( fd_webserver_t * ws,
                      fd_txn_t* txn,
                      const uchar* raw,
                      fd_rpc_encoding_t encoding,
                      long maxvers ) {
  (void)encoding;
  (void)maxvers;

  EMIT_SIMPLE("\"transaction\":{\"accountKeys\":[");

  ushort acct_cnt = txn->acct_addr_cnt;
  const fd_pubkey_t * accts = (const fd_pubkey_t *)(raw + txn->acct_addr_off);
  char buf32[FD_BASE58_ENCODED_32_SZ];
  for (ushort idx = 0; idx < acct_cnt; idx++) {
    fd_base58_encode_32(accts[idx].uc, NULL, buf32);
    bool signer = (idx < txn->signature_cnt);
    bool writable = ((idx < txn->signature_cnt - txn->readonly_signed_cnt) ||
                     ((idx >= txn->signature_cnt) && (idx < acct_cnt - txn->readonly_unsigned_cnt)));
    fd_web_reply_sprintf(ws, "%s{\"pubkey\":\"%s\",\"signer\":%s,\"source\":\"transaction\",\"writable\":%s}",
                         (idx == 0 ? "" : ","), buf32, (signer ? "true" : "false"), (writable ? "true" : "false"));
  }

  fd_web_reply_sprintf(ws, "],\"signatures\":[");
  fd_ed25519_sig_t const * sigs = (fd_ed25519_sig_t const *)(raw + txn->signature_off);
  for ( uchar j = 0; j < txn->signature_cnt; j++ ) {
    char buf64[FD_BASE58_ENCODED_64_SZ];
    fd_base58_encode_64((const uchar*)&sigs[j], NULL, buf64);
    fd_web_reply_sprintf(ws, "%s\"%s\"", (j == 0 ? "" : ","), buf64);
  }
  EMIT_SIMPLE("]}");

  return NULL;
}

const char *
fd_txn_to_json( fd_webserver_t * ws,
                fd_txn_t* txn,
                const uchar* raw,
                ulong raw_sz,
                fd_rpc_encoding_t encoding,
                long maxvers,
                enum fd_block_detail detail ) {
  if( detail == FD_BLOCK_DETAIL_FULL )
    return fd_txn_to_json_full( ws, txn, raw, raw_sz, encoding, maxvers );
  else if( detail == FD_BLOCK_DETAIL_ACCTS )
    return fd_txn_to_json_accts( ws, txn, raw, encoding, maxvers );
  return "unsupported detail parameter";
}

const char*
fd_block_to_json( fd_webserver_t * ws,
                  fd_blockstore_t * blockstore,
                  const char * call_id,
                  const uchar * blk_data,
                  ulong blk_sz,
                  fd_block_map_t * meta,
                  fd_hash_t * parent_hash,
                  fd_rpc_encoding_t encoding,
                  long maxvers,
                  enum fd_block_detail detail,
                  fd_block_rewards_t * rewards ) {
  EMIT_SIMPLE("{\"jsonrpc\":\"2.0\",\"result\":{");

  char hash[50];
  fd_base58_encode_32(meta->block_hash.uc, 0, hash);
  char phash[50];
  fd_base58_encode_32(parent_hash->uc, 0, phash);
  fd_web_reply_sprintf(ws, "\"blockHeight\":%lu,\"blockTime\":%ld,\"parentSlot\":%lu,\"blockhash\":\"%s\",\"previousBlockhash\":\"%s\"",
                       meta->height, meta->ts/(long)1e9, meta->parent_slot, hash, phash);

  if( rewards ) {
    fd_base58_encode_32(rewards->leader.uc, 0, hash);
    fd_web_reply_sprintf(ws, ",\"rewards\":[{\"commission\":null,\"lamports\":%lu,\"postBalance\":%lu,\"pubkey\":\"%s\",\"rewardType\":\"Fee\"}]",
                         rewards->collected_fees,
                         rewards->post_balance,
                         hash);
  }

  if( detail == FD_BLOCK_DETAIL_NONE ) {
    fd_web_reply_sprintf(ws, "},\"id\":%s}", call_id);
    return 0;
  }

  EMIT_SIMPLE(",");

  if( detail == FD_BLOCK_DETAIL_SIGS ) {
    EMIT_SIMPLE("\"signatures\":[");

    int first_sig = 1;
    ulong blockoff = 0;
    while (blockoff < blk_sz) {
      if ( blockoff + sizeof(ulong) > blk_sz )
        FD_LOG_ERR(("premature end of block"));
      ulong mcount = *(const ulong *)(blk_data + blockoff);
      blockoff += sizeof(ulong);

      /* Loop across microblocks */
      for (ulong mblk = 0; mblk < mcount; ++mblk) {
        if ( blockoff + sizeof(fd_microblock_hdr_t) > blk_sz )
          FD_LOG_ERR(("premature end of block"));
        fd_microblock_hdr_t * hdr = (fd_microblock_hdr_t *)((const uchar *)blk_data + blockoff);
        blockoff += sizeof(fd_microblock_hdr_t);

        /* Loop across transactions */
        for ( ulong txn_idx = 0; txn_idx < hdr->txn_cnt; txn_idx++ ) {
          uchar txn_out[FD_TXN_MAX_SZ];
          ulong pay_sz = 0;
          const uchar* raw = (const uchar *)blk_data + blockoff;
          ulong txn_sz = fd_txn_parse_core(raw, fd_ulong_min(blk_sz - blockoff, FD_TXN_MTU), txn_out, NULL, &pay_sz);
          if ( txn_sz == 0 || txn_sz > FD_TXN_MAX_SZ ) {
            FD_LOG_WARNING( ( "failed to parse transaction %lu in microblock %lu",
                              txn_idx,
                              mblk ) );
            return "failed to parse transaction";
          }
          fd_txn_t * txn = (fd_txn_t *)txn_out;

          /* Loop across signatures */
          fd_ed25519_sig_t const * sigs = (fd_ed25519_sig_t const *)(raw + txn->signature_off);
          for ( uchar j = 0; j < txn->signature_cnt; j++ ) {
            char buf64[FD_BASE58_ENCODED_64_SZ];
            fd_base58_encode_64((const uchar*)&sigs[j], NULL, buf64);
            fd_web_reply_sprintf(ws, "%s\"%s\"", (first_sig ? "" : ","), buf64);
            first_sig = 0;
          }

          blockoff += pay_sz;
        }
      }
    }
    if ( blockoff != blk_sz )
      FD_LOG_ERR(("garbage at end of block"));

    fd_web_reply_sprintf(ws, "]},\"id\":%s}", call_id);
    return NULL;
  }

  EMIT_SIMPLE("\"transactions\":[");

  fd_wksp_t * blockstore_wksp = fd_blockstore_wksp( blockstore );

  int first_txn = 1;
  ulong blockoff = 0;
  while (blockoff < blk_sz) {
    if ( blockoff + sizeof(ulong) > blk_sz )
      FD_LOG_ERR(("premature end of block"));
    ulong mcount = *(const ulong *)(blk_data + blockoff);
    blockoff += sizeof(ulong);

    /* Loop across microblocks */
    for (ulong mblk = 0; mblk < mcount; ++mblk) {
      if ( blockoff + sizeof(fd_microblock_hdr_t) > blk_sz )
        FD_LOG_ERR(("premature end of block"));
      fd_microblock_hdr_t * hdr = (fd_microblock_hdr_t *)((const uchar *)blk_data + blockoff);
      blockoff += sizeof(fd_microblock_hdr_t);

      /* Loop across transactions */
      for ( ulong txn_idx = 0; txn_idx < hdr->txn_cnt; txn_idx++ ) {
        uchar txn_out[FD_TXN_MAX_SZ];
        ulong pay_sz = 0;
        const uchar* raw = (const uchar *)blk_data + blockoff;
        ulong txn_sz = fd_txn_parse_core(raw, fd_ulong_min(blk_sz - blockoff, FD_TXN_MTU), txn_out, NULL, &pay_sz);
        if ( txn_sz == 0 || txn_sz > FD_TXN_MAX_SZ ) {
          FD_LOG_WARNING( ( "failed to parse transaction %lu in microblock %lu",
                            txn_idx,
                            mblk ) );
          return "failed to parse transaction";
        }
        if (first_txn) {
          first_txn = 0;
          EMIT_SIMPLE("{");
        } else
          EMIT_SIMPLE(",{");

        uchar const * sig_p = raw + ((fd_txn_t *)txn_out)->signature_off;
        fd_blockstore_txn_map_t elem;
        uchar flags;
        if( !fd_blockstore_txn_query_volatile( blockstore, sig_p, &elem, NULL, &flags, NULL ) ) {
          const void * meta = fd_wksp_laddr_fast( blockstore_wksp, elem.meta_gaddr );
          const char * err = fd_txn_meta_to_json( ws, meta, elem.meta_sz );
          if ( err ) return err;
        }

        const char * err = fd_txn_to_json( ws, (fd_txn_t *)txn_out, raw, pay_sz, encoding, maxvers, detail );
        if ( err ) return err;

        EMIT_SIMPLE("}");

        blockoff += pay_sz;
      }
    }
  }
  if ( blockoff != blk_sz )
    FD_LOG_ERR(("garbage at end of block"));

  fd_web_reply_sprintf(ws, "]},\"id\":%s}", call_id);

  return NULL;
}

const char*
fd_account_to_json( fd_webserver_t * ws,
                    fd_pubkey_t acct,
                    fd_rpc_encoding_t enc,
                    uchar const * val,
                    ulong val_sz,
                    long off,
                    long len ) {
  fd_web_reply_sprintf(ws, "{\"data\":[\"");

  fd_account_meta_t * metadata = (fd_account_meta_t *)val;
  if (val_sz < sizeof(fd_account_meta_t) && val_sz < metadata->hlen) {
    return "failed to load account data";
  }
  val = (uchar*)val + metadata->hlen;
  val_sz = val_sz - metadata->hlen;
  if (val_sz > metadata->dlen)
    val_sz = metadata->dlen;

  if (len != FD_LONG_UNSET && off != FD_LONG_UNSET) {
    if (enc == FD_ENC_JSON) {
      return "cannot use jsonParsed encoding with slice";
    }
    if (off < 0 || (ulong)off >= val_sz) {
      val = NULL;
      val_sz = 0;
    } else {
      val = (uchar*)val + (ulong)off;
      val_sz = val_sz - (ulong)off;
    }
    if (len < 0) {
      val = NULL;
      val_sz = 0;
    } else if ((ulong)len < val_sz)
      val_sz = (ulong)len;
  }

  const char* encstr;
  switch (enc) {
  case FD_ENC_BASE58:
    if (fd_web_reply_encode_base58(ws, val, val_sz)) {
      return "failed to encode data in base58";
    }
    encstr = "base58";
    break;
  case FD_ENC_BASE64:
  case FD_ENC_JSON:
    if (fd_web_reply_encode_base64(ws, val, val_sz)) {
      return "failed to encode data in base64";
    }
    encstr = "base64";
    break;
# if FD_HAS_ZSTD
  case FD_ENC_BASE64_ZSTD: {
    size_t const cBuffSize = ZSTD_compressBound( val_sz );
    void * cBuff = fd_scratch_alloc( 1, cBuffSize );
    size_t const cSize = ZSTD_compress( cBuff, cBuffSize, val, val_sz, 1 );
    if (fd_web_reply_encode_base64(ws, cBuff, cSize)) {
      return "failed to encode data in base64";
    }
    encstr = "base64+zstd";
    break;
  }
# endif /* FD_HAS_ZSTD */
  default:
    return "unsupported encoding";
  }

  char owner[50];
  fd_base58_encode_32((uchar*)metadata->info.owner, 0, owner);
  char addr[50];
  fd_base58_encode_32(acct.uc, 0, addr);
  fd_web_reply_sprintf(ws, "\",\"%s\"],\"executable\":%s,\"lamports\":%lu,\"owner\":\"%s\",\"address\":\"%s\",\"rentEpoch\":%lu,\"space\":%lu}",
                       encstr,
                       (metadata->info.executable ? "true" : "false"),
                       metadata->info.lamports,
                       owner,
                       addr,
                       metadata->info.rent_epoch,
                       val_sz);

  return NULL;
}
