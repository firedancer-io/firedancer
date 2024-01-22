#include <stdio.h>
#include <unistd.h>
#include "../../util/fd_util.h"
#include "../nanopb/pb_decode.h"
#include "../../tango/webserver/fd_webserver.h"
#include "../../ballet/txn/fd_txn.h"
#include "../../ballet/block/fd_microblock.h"
#include "../../ballet/base58/fd_base58.h"
#include "../types/fd_types.h"
#include "../types/fd_solana_block.pb.h"
#include "../runtime/fd_blockstore.h"
#include "fd_block_to_json.h"

#define EMIT_SIMPLE(_str_) fd_textstream_append(ts, _str_, sizeof(_str_)-1)

void fd_tokenbalance_to_json( fd_textstream_t * ts, struct _fd_solblock_TokenBalance * b ) {
  fd_textstream_sprintf(ts, "{\"accountIndex\":%u,\"mint\":\"%s\",\"owner\":\"%s\",\"programId\":\"%s\",\"uiTokenAmount\":{",
                        b->account_index, b->mint, b->owner, b->program_id);
  fd_textstream_sprintf(ts, "\"amount\":\"%s\",", b->ui_token_amount.amount);
  int dec;
  if (b->ui_token_amount.has_decimals) {
    fd_textstream_sprintf(ts, "\"decimals\":%u,", b->ui_token_amount.decimals);
    dec = (int)b->ui_token_amount.decimals;
  } else
    dec = 0;
  if (b->ui_token_amount.has_ui_amount)
    fd_textstream_sprintf(ts, "\"uiAmount\":%.*f,", dec, b->ui_token_amount.ui_amount);
  fd_textstream_sprintf(ts, "\"uiAmountString\":\"%s\"}}", b->ui_token_amount.ui_amount_string);
}

void fd_error_to_json( fd_textstream_t * ts,
                       const uchar* bytes,
                       ulong size ) {
  /* I worked this out by brute force examination of actual cases */

  const uchar* orig_bytes = bytes;
  ulong orig_size = size;

#define INSTRUCTION_ERROR 8
  if (size < sizeof(uint) || *(const uint*)bytes != INSTRUCTION_ERROR) /* Always the same? */
    goto dump_as_hex;
  bytes += sizeof(uint);
  size -= sizeof(uint);

  if (size < 1)
    goto dump_as_hex;
  uint index = *(bytes++); /* Instruction index */
  size--;

  if (size < sizeof(uint))
    goto dump_as_hex;
  uint cnum =  *(const uint*)bytes;
  bytes += sizeof(uint);
  size -= sizeof(uint);

  switch (cnum) {
  case 25: { /* "Custom" */
    if (size < sizeof(uint))
      goto dump_as_hex;
    uint code =  *(const uint*)bytes; /* Custom code? */
    fd_textstream_sprintf(ts, "{\"InstructionError\":[%u,{\"Custom\":%u}]}", index, code);
    return;
  }

  case 0: fd_textstream_sprintf(ts, "{\"InstructionError\":[%u,\"GenericError\"]}", index); return;
  case 1: fd_textstream_sprintf(ts, "{\"InstructionError\":[%u,\"InvalidArgument\"]}", index); return;
  case 2: fd_textstream_sprintf(ts, "{\"InstructionError\":[%u,\"InvalidInstructionData\"]}", index); return;
  case 3: fd_textstream_sprintf(ts, "{\"InstructionError\":[%u,\"InvalidAccountData\"]}", index); return;
  case 4: fd_textstream_sprintf(ts, "{\"InstructionError\":[%u,\"AccountDataTooSmall\"]}", index); return;
  case 5: fd_textstream_sprintf(ts, "{\"InstructionError\":[%u,\"InsufficientFunds\"]}", index); return;
  case 6: fd_textstream_sprintf(ts, "{\"InstructionError\":[%u,\"IncorrectProgramId\"]}", index); return;
  case 7: fd_textstream_sprintf(ts, "{\"InstructionError\":[%u,\"MissingRequiredSignature\"]}", index); return;
  case 8: fd_textstream_sprintf(ts, "{\"InstructionError\":[%u,\"AccountAlreadyInitialized\"]}", index); return;
  case 9: fd_textstream_sprintf(ts, "{\"InstructionError\":[%u,\"UninitializedAccount\"]}", index); return;
  case 10: fd_textstream_sprintf(ts, "{\"InstructionError\":[%u,\"UnbalancedInstruction\"]}", index); return;
  case 11: fd_textstream_sprintf(ts, "{\"InstructionError\":[%u,\"ModifiedProgramId\"]}", index); return;
  case 12: fd_textstream_sprintf(ts, "{\"InstructionError\":[%u,\"ExternalAccountLamportSpend\"]}", index); return;
  case 13: fd_textstream_sprintf(ts, "{\"InstructionError\":[%u,\"ExternalAccountDataModified\"]}", index); return;
  case 14: fd_textstream_sprintf(ts, "{\"InstructionError\":[%u,\"ReadonlyLamportChange\"]}", index); return;
  case 15: fd_textstream_sprintf(ts, "{\"InstructionError\":[%u,\"ReadonlyDataModified\"]}", index); return;
  case 16: fd_textstream_sprintf(ts, "{\"InstructionError\":[%u,\"DuplicateAccountIndex\"]}", index); return;
  case 17: fd_textstream_sprintf(ts, "{\"InstructionError\":[%u,\"ExecutableModified\"]}", index); return;
  case 18: fd_textstream_sprintf(ts, "{\"InstructionError\":[%u,\"RentEpochModified\"]}", index); return;
  case 19: fd_textstream_sprintf(ts, "{\"InstructionError\":[%u,\"NotEnoughAccountKeys\"]}", index); return;
  case 20: fd_textstream_sprintf(ts, "{\"InstructionError\":[%u,\"AccountDataSizeChanged\"]}", index); return;
  case 21: fd_textstream_sprintf(ts, "{\"InstructionError\":[%u,\"AccountNotExecutable\"]}", index); return;
  case 22: fd_textstream_sprintf(ts, "{\"InstructionError\":[%u,\"AccountBorrowFailed\"]}", index); return;
  case 23: fd_textstream_sprintf(ts, "{\"InstructionError\":[%u,\"AccountBorrowOutstanding\"]}", index); return;
  case 24: fd_textstream_sprintf(ts, "{\"InstructionError\":[%u,\"DuplicateAccountOutOfSync\"]}", index); return;
  case 26: fd_textstream_sprintf(ts, "{\"InstructionError\":[%u,\"InvalidError\"]}", index); return;
  case 27: fd_textstream_sprintf(ts, "{\"InstructionError\":[%u,\"ExecutableDataModified\"]}", index); return;
  case 28: fd_textstream_sprintf(ts, "{\"InstructionError\":[%u,\"ExecutableLamportChange\"]}", index); return;
  case 29: fd_textstream_sprintf(ts, "{\"InstructionError\":[%u,\"ExecutableAccountNotRentExempt\"]}", index); return;
  case 30: fd_textstream_sprintf(ts, "{\"InstructionError\":[%u,\"UnsupportedProgramId\"]}", index); return;
  case 31: fd_textstream_sprintf(ts, "{\"InstructionError\":[%u,\"CallDepth\"]}", index); return;
  case 32: fd_textstream_sprintf(ts, "{\"InstructionError\":[%u,\"MissingAccount\"]}", index); return;
  case 33: fd_textstream_sprintf(ts, "{\"InstructionError\":[%u,\"ReentrancyNotAllowed\"]}", index); return;
  case 34: fd_textstream_sprintf(ts, "{\"InstructionError\":[%u,\"MaxSeedLengthExceeded\"]}", index); return;
  case 35: fd_textstream_sprintf(ts, "{\"InstructionError\":[%u,\"InvalidSeeds\"]}", index); return;
  case 36: fd_textstream_sprintf(ts, "{\"InstructionError\":[%u,\"InvalidRealloc\"]}", index); return;
  case 37: fd_textstream_sprintf(ts, "{\"InstructionError\":[%u,\"ComputationalBudgetExceeded\"]}", index); return;
  case 38: fd_textstream_sprintf(ts, "{\"InstructionError\":[%u,\"PrivilegeEscalation\"]}", index); return;
  case 39: fd_textstream_sprintf(ts, "{\"InstructionError\":[%u,\"ProgramEnvironmentSetupFailure\"]}", index); return;
  case 40: fd_textstream_sprintf(ts, "{\"InstructionError\":[%u,\"ProgramFailedToComplete\"]}", index); return;
  case 41: fd_textstream_sprintf(ts, "{\"InstructionError\":[%u,\"ProgramFailedToCompile\"]}", index); return;
  case 42: fd_textstream_sprintf(ts, "{\"InstructionError\":[%u,\"Immutable\"]}", index); return;
  case 43: fd_textstream_sprintf(ts, "{\"InstructionError\":[%u,\"IncorrectAuthority\"]}", index); return;
  case 44: fd_textstream_sprintf(ts, "{\"InstructionError\":[%u,\"BorshIoError(String::new())\"]}", index); return;
  case 45: fd_textstream_sprintf(ts, "{\"InstructionError\":[%u,\"AccountNotRentExempt\"]}", index); return;
  case 46: fd_textstream_sprintf(ts, "{\"InstructionError\":[%u,\"InvalidAccountOwner\"]}", index); return;
  case 47: fd_textstream_sprintf(ts, "{\"InstructionError\":[%u,\"ArithmeticOverflow\"]}", index); return;
  case 48: fd_textstream_sprintf(ts, "{\"InstructionError\":[%u,\"UnsupportedSysvar\"]}", index); return;
  case 49: fd_textstream_sprintf(ts, "{\"InstructionError\":[%u,\"IllegalOwner\"]}", index); return;
  case 50: fd_textstream_sprintf(ts, "{\"InstructionError\":[%u,\"MaxAccountsDataSizeExceeded\"]}", index); return;
  case 51: fd_textstream_sprintf(ts, "{\"InstructionError\":[%u,\"MaxAccountsExceeded\"]}", index); return;
  }

 dump_as_hex:
  EMIT_SIMPLE("\"");
  fd_textstream_encode_hex(ts, orig_bytes, orig_size);
  EMIT_SIMPLE("\"");
}

void fd_inner_instructions_to_json( fd_textstream_t * ts,
                                    struct _fd_solblock_InnerInstructions * insts ) {
  fd_textstream_sprintf(ts, "{\"index\":%u,\"instructions\":[", insts->index);
  for ( pb_size_t i = 0; i < insts->instructions_count; ++i ) {
    struct _fd_solblock_InnerInstruction * inst = insts->instructions + i;
    fd_textstream_sprintf(ts, "%s{\"data\":\"", (i == 0 ? "" : ","));
    fd_textstream_encode_base58(ts, inst->data->bytes, inst->data->size);
    fd_textstream_sprintf(ts, "\",\"programIdIndex:\":%u}", inst->program_id_index);
  }
  EMIT_SIMPLE("]}");
}

int fd_txn_to_json( fd_textstream_t * ts,
                    fd_txn_t* txn,
                    const uchar* raw,
                    const void * meta_raw,
                    ulong meta_raw_sz,
                    enum fd_block_encoding encoding,
                    long maxvers,
                    enum fd_block_detail detail,
                    int rewards ) {
  (void)encoding;
  (void)maxvers;
  (void)detail;
  (void)rewards;

  if (meta_raw) {
    fd_solblock_TransactionStatusMeta txn_status = {0};
    pb_istream_t stream = pb_istream_from_buffer( meta_raw, meta_raw_sz );
    if( FD_UNLIKELY( !pb_decode( &stream, fd_solblock_TransactionStatusMeta_fields, &txn_status ) ) ) {
      FD_LOG_ERR(( "failed to decode txn status: %s", PB_GET_ERROR( &stream ) ));
    }

    EMIT_SIMPLE("\"meta\":{");
    if (txn_status.has_compute_units_consumed)
      fd_textstream_sprintf(ts, "\"computeUnitsConsumed\":%lu,", txn_status.compute_units_consumed);
    EMIT_SIMPLE("\"err\":");
    if (txn_status.has_err)
      fd_error_to_json(ts, txn_status.err.err->bytes, txn_status.err.err->size);
    else
      EMIT_SIMPLE("null");
    fd_textstream_sprintf(ts, ",\"fee\":%lu,\"innerInstructions\":[", txn_status.fee);
    if (!txn_status.inner_instructions_none) {
      for (pb_size_t i = 0; i < txn_status.inner_instructions_count; ++i) {
        if ( i > 0 ) EMIT_SIMPLE(",");
        fd_inner_instructions_to_json(ts, txn_status.inner_instructions + i);
      }
    }
    EMIT_SIMPLE("],\"loadedAddresses\":{\"readonly\":[");
    for (pb_size_t i = 0; i < txn_status.loaded_readonly_addresses_count; ++i) {
      pb_bytes_array_t * ba = txn_status.loaded_readonly_addresses[i];
      if (ba->size == 32) {
        char buf32[FD_BASE58_ENCODED_32_SZ];
        fd_base58_encode_32(ba->bytes, NULL, buf32);
        fd_textstream_sprintf(ts, "%s\"%s\"", (i == 0 ? "" : ","), buf32);
      } else
        fd_textstream_sprintf(ts, "%s\"\"", (i == 0 ? "" : ","));
    }
    EMIT_SIMPLE("],\"writable\":[");
    for (pb_size_t i = 0; i < txn_status.loaded_writable_addresses_count; ++i) {
      pb_bytes_array_t * ba = txn_status.loaded_writable_addresses[i];
      if (ba->size == 32) {
        char buf32[FD_BASE58_ENCODED_32_SZ];
        fd_base58_encode_32(ba->bytes, NULL, buf32);
        fd_textstream_sprintf(ts, "%s\"%s\"", (i == 0 ? "" : ","), buf32);
      } else
        fd_textstream_sprintf(ts, "%s\"\"", (i == 0 ? "" : ","));
    }
    EMIT_SIMPLE("]},\"logMessages\":[");
    for (pb_size_t i = 0; i < txn_status.log_messages_count; ++i)
      fd_textstream_sprintf(ts, "%s\"%s\"", (i == 0 ? "" : ","), txn_status.log_messages[i]);
    EMIT_SIMPLE("],\"postBalances\":[");
    for (pb_size_t i = 0; i < txn_status.post_balances_count; ++i)
      fd_textstream_sprintf(ts, "%s%lu", (i == 0 ? "" : ","), txn_status.post_balances[i]);
    EMIT_SIMPLE("],\"postTokenBalances\":[");
    for (pb_size_t i = 0; i < txn_status.post_token_balances_count; ++i) {
      if (i > 0) EMIT_SIMPLE(",");
      fd_tokenbalance_to_json(ts, txn_status.post_token_balances + i);
    }
    EMIT_SIMPLE("],\"preBalances\":[");
    for (pb_size_t i = 0; i < txn_status.pre_balances_count; ++i)
      fd_textstream_sprintf(ts, "%s%lu", (i == 0 ? "" : ","), txn_status.pre_balances[i]);
    EMIT_SIMPLE("],\"preTokenBalances\":[");
    for (pb_size_t i = 0; i < txn_status.pre_token_balances_count; ++i) {
      if (i > 0) EMIT_SIMPLE(",");
      fd_tokenbalance_to_json(ts, txn_status.pre_token_balances + i);
    }
    EMIT_SIMPLE("],\"rewards\":[");
    EMIT_SIMPLE("],\"status\":{\"Ok\":null}},");

    pb_release( fd_solblock_TransactionStatusMeta_fields, &txn_status );
  }

  EMIT_SIMPLE("\"transaction\":{\"message\":{\"accountKeys\":[");

  ushort acct_cnt = txn->acct_addr_cnt;
  const fd_pubkey_t * accts = (const fd_pubkey_t *)(raw + txn->acct_addr_off);
  char buf32[FD_BASE58_ENCODED_32_SZ];
  for (ushort idx = 0; idx < acct_cnt; idx++) {
    fd_base58_encode_32(accts[idx].uc, NULL, buf32);
    fd_textstream_sprintf(ts, "%s\"%s\"", (idx == 0 ? "" : ","), buf32);
  }

  fd_textstream_sprintf(ts, "],\"header\":{\"numReadonlySignedAccounts\":%u,\"numReadonlyUnsignedAccounts\":%u,\"numRequiredSignatures\":%u},\"instructions\":[",
                        (uint)txn->readonly_signed_cnt, (uint)txn->readonly_unsigned_cnt, (uint)txn->signature_cnt);

  ushort instr_cnt = txn->instr_cnt;
  for (ushort idx = 0; idx < instr_cnt; idx++) {
    fd_textstream_sprintf(ts, "%s{\"accounts\":[", (idx == 0 ? "" : ","));

    fd_txn_instr_t * instr = &txn->instr[idx];
    const uchar * instr_acc_idxs = raw + instr->acct_off;
    for (ushort j = 0; j < instr->acct_cnt; j++)
      fd_textstream_sprintf(ts, "%s%u", (j == 0 ? "" : ","), (uint)instr_acc_idxs[j]);

    EMIT_SIMPLE("],\"data\":\"");
    fd_textstream_encode_base58(ts, raw + instr->data_off, instr->data_sz);

    fd_textstream_sprintf(ts, "\",\"programIdIndex\":%u,\"stackHeight\":null}", (uint)instr->program_id);
  }

  const fd_hash_t * recent = (const fd_hash_t *)(raw + txn->recent_blockhash_off);
  fd_base58_encode_32(recent->uc, NULL, buf32);
  fd_textstream_sprintf(ts, "],\"recentBlockhash\":\"%s\"},\"signatures\":[", buf32);

  fd_ed25519_sig_t const * sigs = (fd_ed25519_sig_t const *)(raw + txn->signature_off);
  for ( uchar j = 0; j < txn->signature_cnt; j++ ) {
    char buf64[FD_BASE58_ENCODED_64_SZ];
    fd_base58_encode_64((const uchar*)&sigs[j], NULL, buf64);
    fd_textstream_sprintf(ts, "%s\"%s\"", (j == 0 ? "" : ","), buf64);
  }

  const char* vers;
  switch (txn->transaction_version) {
  case FD_TXN_VLEGACY: vers = "\"legacy\""; break;
  case FD_TXN_V0:      vers = "0";          break;
  default:             vers = "\"?\"";      break;
  }
  fd_textstream_sprintf(ts, "]},\"version\":%s", vers);

  return 0;
}

int fd_block_to_json( fd_textstream_t * ts,
                      long call_id,
                      fd_blockstore_t * blks,
                      ulong slot,
                      enum fd_block_encoding encoding,
                      long maxvers,
                      enum fd_block_detail detail,
                      int rewards) {
  fd_blockstore_start_read( blks );
  
  fd_blockstore_block_t * blk = fd_blockstore_block_query(blks, slot);
  if (blk == NULL) {
    fd_blockstore_end_read( blks );
    return -1;
  }

  fd_slot_meta_t * meta = fd_blockstore_slot_meta_query(blks, slot);

  uchar const * block = fd_blockstore_block_data_laddr(blks, blk);
  ulong block_sz = blk->sz;

  FD_LOG_DEBUG(("converting ptr %p, sz %lu", (void *)block, block_sz));

  EMIT_SIMPLE("{\"jsonrpc\":\"2.0\",\"result\":{");

  if ( meta ) {
    fd_textstream_sprintf(ts, "\"blockHeight\":%lu,\"blockTime\":%ld,\"blockhash\":\"",
                          blk->height, blk->ts/(long)1e9);
    uchar const * hash = fd_blockstore_block_query_hash( blks, slot );
    if (hash)
      fd_textstream_encode_base58(ts, hash, FD_SHA256_HASH_SZ);
    fd_textstream_sprintf(ts, "\",\"parentSlot\":%lu,\"previousBlockhash\":\"",
                          meta->parent_slot);
    hash = fd_blockstore_block_query_hash( blks, meta->parent_slot );
    if (hash)
      fd_textstream_encode_base58(ts, hash, FD_SHA256_HASH_SZ);
    fd_textstream_sprintf(ts, "\",");
  }

  EMIT_SIMPLE("\"transactions\":[");

  int first_txn = 1;
  ulong blockoff = 0;
  while (blockoff < block_sz) {
    if ( blockoff + sizeof(ulong) > block_sz )
      FD_LOG_ERR(("premature end of block"));
    ulong mcount = *(const ulong *)((const uchar *)block + blockoff);
    blockoff += sizeof(ulong);

    /* Loop across microblocks */
    for (ulong mblk = 0; mblk < mcount; ++mblk) {
      if ( blockoff + sizeof(fd_microblock_hdr_t) > block_sz )
        FD_LOG_ERR(("premature end of block"));
      fd_microblock_hdr_t * hdr = (fd_microblock_hdr_t *)((const uchar *)block + blockoff);
      blockoff += sizeof(fd_microblock_hdr_t);

      /* Loop across transactions */
      for ( ulong txn_idx = 0; txn_idx < hdr->txn_cnt; txn_idx++ ) {
        uchar txn_out[FD_TXN_MAX_SZ];
        ulong pay_sz = 0;
        const uchar* raw = (const uchar *)block + blockoff;
        ulong txn_sz = fd_txn_parse_core(raw, fd_ulong_min(block_sz - blockoff, FD_TXN_MTU), txn_out, NULL, &pay_sz, 0);
        if ( txn_sz == 0 || txn_sz > FD_TXN_MAX_SZ )
          FD_LOG_ERR( ( "failed to parse transaction %lu in microblock %lu",
                        txn_idx,
                        mblk ) );

        if (first_txn) {
          first_txn = 0;
          EMIT_SIMPLE("{");
        } else
          EMIT_SIMPLE(",{");

        const void * val2 = NULL;
        ulong val2_sz = 0;
#if 0
        if ( stat_block ) {
          fd_ed25519_sig_t const * sigs = (fd_ed25519_sig_t const *)(raw + ((fd_txn_t *)txn_out)->signature_off);
          txn_map_elem_t * elem = txn_map_elem_query( txn_map, (const struct txn_map_key*)sigs, NULL );
          if (elem && elem->txn_stat_off != ULONG_MAX) {
            if (elem->txn_stat_off + elem->txn_stat_sz > stat_block_sz)
              FD_LOG_ERR(("correct transaction index"));
            val2 = (const uchar*)stat_block + elem->txn_stat_off;
            val2_sz = elem->txn_stat_sz;
          }
        }
#endif

        int r = fd_txn_to_json( ts, (fd_txn_t *)txn_out, raw, val2, val2_sz, encoding, maxvers, detail, rewards );
        if ( r ) {
          fd_blockstore_end_read( blks );
          return r;
        }

        EMIT_SIMPLE("}");

        blockoff += pay_sz;
      }
    }
  }
  if ( blockoff != block_sz )
    FD_LOG_ERR(("garbage at end of block"));

  EMIT_SIMPLE("]"); // transactions

  fd_textstream_sprintf(ts, "},\"id\":%lu}", call_id);

  fd_blockstore_end_read( blks );
  
  return 0;
}
