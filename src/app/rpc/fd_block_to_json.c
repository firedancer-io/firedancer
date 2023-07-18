#include "../../util/fd_util.h"
#include "pb.h"
#include "../../flamenco/nanopb/pb_decode.h"
#include "../../tango/webserver/fd_webserver.h"
#include "../../ballet/txn/fd_txn.h"
#include "../../ballet/block/fd_microblock.h"
#include "../../ballet/base58/fd_base58.h"
#include "../../flamenco/types/fd_types.h"
#include "../../flamenco/types/fd_solana_block.pb.h"
#include "fd_block_to_json.h"

#define EMIT_SIMPLE(_str_) fd_textstream_append(ts, _str_, sizeof(_str_)-1)

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
  (void)meta_raw;
  (void)meta_raw_sz;

  if (meta_raw) {
    fd_solblock_TransactionStatusMeta txn_status = {0};
    pb_istream_t stream = pb_istream_from_buffer( meta_raw, meta_raw_sz );
    if( FD_UNLIKELY( !pb_decode( &stream, fd_solblock_TransactionStatusMeta_fields, &txn_status ) ) ) {
      FD_LOG_ERR(( "failed to decode txn status: %s", PB_GET_ERROR( &stream ) ));
    }

    EMIT_SIMPLE("\"meta\":{\"err\":");
    if (txn_status.has_err)
      fd_textstream_sprintf(ts, "\"%s\"", txn_status.err.err);
    else
      EMIT_SIMPLE("null");
    fd_textstream_sprintf(ts, ",\"fee\":%lu,\"innerInstructions\":[", txn_status.fee);
    EMIT_SIMPLE("],\"loadedAddresses\":{\"readonly\":[");
    EMIT_SIMPLE("],\"writable\":[");
    EMIT_SIMPLE("]},\"logMessages\":[");
    for (pb_size_t i = 0; i < txn_status.log_messages_count; ++i)
      fd_textstream_sprintf(ts, "%s\"%s\"", (i == 0 ? "" : ","), txn_status.log_messages[i]);
    EMIT_SIMPLE("],\"postBalances\":[");
    for (pb_size_t i = 0; i < txn_status.post_balances_count; ++i)
      fd_textstream_sprintf(ts, "%s%lu", (i == 0 ? "" : ","), txn_status.post_balances[i]);
    EMIT_SIMPLE("],\"preTokenBalances\":[");
    for (pb_size_t i = 0; i < txn_status.pre_balances_count; ++i)
      fd_textstream_sprintf(ts, "%s%lu", (i == 0 ? "" : ","), txn_status.pre_balances[i]);
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

    fd_textstream_sprintf(ts, "\",\"programIdIndex\": %u}", (uint)instr->program_id);
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
  case FD_TXN_VLEGACY: vers = "legacy"; break;
  case FD_TXN_V0:      vers = "0";      break;
  default:             vers = "?";      break;
  }
  fd_textstream_sprintf(ts, "]},\"version\":\"%s\"", vers);

  return 0;
}

int fd_block_to_json( fd_textstream_t * ts,
                      long call_id,
                      const void* block,
                      ulong block_sz,
                      const void* stat_block,
                      ulong stat_block_sz,
                      enum fd_block_encoding encoding,
                      long maxvers,
                      enum fd_block_detail detail,
                      int rewards ) {
  EMIT_SIMPLE("{\"jsonrpc\":\"2.0\",\"result\":{");

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
        ulong txn_sz = fd_txn_parse_core(raw, fd_ulong_min(block_sz - blockoff, USHORT_MAX), txn_out, NULL, &pay_sz, 0);
        if ( txn_sz == 0 || txn_sz > FD_TXN_MAX_SZ )
          FD_LOG_ERR(("failed to parse transaction"));

        if (first_txn) {
          first_txn = 0;
          EMIT_SIMPLE("{");
        } else
          EMIT_SIMPLE(",{");

        const void * val2 = NULL;
        ulong val2_sz = 0;
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
        
        int r = fd_txn_to_json( ts, (fd_txn_t *)txn_out, raw, val2, val2_sz, encoding, maxvers, detail, rewards );
        if ( r ) return r;

        EMIT_SIMPLE("}");
        
        blockoff += pay_sz;
      }
    }
  }
  if ( blockoff != block_sz )
    FD_LOG_ERR(("garbage at end of block"));

  EMIT_SIMPLE("]"); // transactions

  fd_textstream_sprintf(ts, "},\"id\":%lu}", call_id);

  return 0;
}
