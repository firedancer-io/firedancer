/**

   export RUST_LOG=solana_repair=TRACE
   cargo run --bin solana-test-validator

   wget --trust-server-names http://localhost:8899/snapshot.tar.bz2
   wget --trust-server-names http://localhost:8899/incremental-snapshot.tar.bz2
   ./build/native/gcc/unit-test/test_tvu --repair-peer-pubkey F7SW17yGN7UUPQ519nxaDt26UMtvwJPSFVu9kBMBQpW --rpc-port 8123 --snapshotfile snapshot-240023734-3upPYDhyaoJ6DJZoeHnRPQKuba7B2xB93gFkHbGri5sK.tar.zst --incremental incremental-snapshot-240023734-240033566-7pHtH4n592Cgn3wWz459PGkbBgZUSJ3HtLxFYzEq8BXN.tar.zst

   curl http://localhost:8123 -X POST -H 'content-type: application/json' --data '{"jsonrpc":"2.0", "id":1234, "method":"getAccountInfo", "params":["CsE3MdkQXYwEFuNsEkLajgqSEiLqN6aH7eBzhCdJecar",{"encoding":"base58"}]}'
   curl http://localhost:8123 -H 'content-type: application/json' --data '{"jsonrpc":"2.0", "id":1234, "method":"getBalance", "params":["CsE3MdkQXYwEFuNsEkLajgqSEiLqN6aH7eBzhCdJecar"]}'
 **/

#include "fd_rpc_service.h"
#include <microhttpd.h>
#include "../../tango/webserver/fd_methods.h"
#include "../../tango/webserver/fd_webserver.h"
#include "../types/fd_types.h"
#include "../types/fd_solana_block.pb.h"
#include "../runtime/fd_runtime.h"
#include "../runtime/fd_acc_mgr.h"
#include "../../ballet/base58/fd_base58.h"
#include "keywords.h"
#include "fd_block_to_json.h"

#define API_VERSION "1.14.19"

#define CRLF "\r\n"
#define MATCH_STRING(_text_,_text_sz_,_str_) (_text_sz_ == sizeof(_str_)-1 && memcmp(_text_, _str_, sizeof(_str_)-1) == 0)

struct fd_rpc_ctx {
  fd_webserver_t ws;
  fd_funk_t * funk;
  fd_blockstore_t * blks;
  long call_id;
  ulong slot;
};

// Implementation of the "getAccountInfo" method
static int
method_getAccountInfo(struct fd_web_replier* replier, struct json_values* values, fd_rpc_ctx_t * ctx) {
  // Path to argument
  static const uint PATH[3] = {
    (JSON_TOKEN_LBRACE<<16) | KEYW_JSON_PARAMS,
    (JSON_TOKEN_LBRACKET<<16) | 0,
    (JSON_TOKEN_STRING<<16)
  };
  ulong arg_sz = 0;
  const void* arg = json_get_value(values, PATH, 3, &arg_sz);
  if (arg == NULL) {
    fd_web_replier_error(replier, "getAccountInfo requires a string as first parameter");
    return 0;
  }
  fd_pubkey_t acct;
  fd_base58_decode_32((const char *)arg, acct.uc);
  fd_funk_rec_key_t recid = fd_acc_mgr_key(&acct);
  fd_funk_rec_t const * rec = fd_funk_rec_query_global(ctx->funk, NULL, &recid);

  fd_textstream_t * ts = fd_web_replier_textstream(replier);
  if (rec == NULL) {
    fd_textstream_sprintf(ts, "{\"jsonrpc\":\"2.0\",\"result\":{\"context\":{\"apiVersion\":\"" API_VERSION "\",\"slot\":%lu},\"value\":null},\"id\":%lu}" CRLF,
                          ctx->slot, ctx->call_id);
    fd_web_replier_done(replier);
    return 0;
  }

  fd_wksp_t * wksp = fd_funk_wksp(ctx->funk);
  void * val = fd_funk_val(rec, wksp);
  ulong val_sz = fd_funk_val_sz(rec);
  fd_account_meta_t * metadata = (fd_account_meta_t *)val;
  if (val_sz < metadata->hlen) {
    fd_web_replier_error(replier, "failed to load account data for %s", (const char*)arg);
    return 0;
  }
  val = (char*)val + metadata->hlen;
  val_sz = val_sz - metadata->hlen;
  if (val_sz > metadata->dlen)
    val_sz = metadata->dlen;
  
  static const uint PATH2[4] = {
    (JSON_TOKEN_LBRACE<<16) | KEYW_JSON_PARAMS,
    (JSON_TOKEN_LBRACKET<<16) | 1,
    (JSON_TOKEN_LBRACE<<16) | KEYW_JSON_ENCODING,
    (JSON_TOKEN_STRING<<16)
  };
  ulong enc_str_sz = 0;
  const void* enc_str = json_get_value(values, PATH2, 4, &enc_str_sz);
  enum { ENC_BASE58, ENC_BASE64, ENC_BASE64_ZSTD, ENC_JSON } enc;
  if (enc_str == NULL || MATCH_STRING(enc_str, enc_str_sz, "base58"))
    enc = ENC_BASE58;
  else if (MATCH_STRING(enc_str, enc_str_sz, "base64"))
    enc = ENC_BASE64;
  else if (MATCH_STRING(enc_str, enc_str_sz, "base64+zstd"))
    enc = ENC_BASE64_ZSTD;
  else if (MATCH_STRING(enc_str, enc_str_sz, "jsonParsed"))
    enc = ENC_JSON;
  else {
    fd_web_replier_error(replier, "invalid data encoding %s", (const char*)enc_str);
    return 0;
  }

  static const uint PATH3[4] = {
    (JSON_TOKEN_LBRACE<<16) | KEYW_JSON_PARAMS,
    (JSON_TOKEN_LBRACKET<<16) | 2,
    (JSON_TOKEN_LBRACE<<16) | KEYW_JSON_LENGTH,
    (JSON_TOKEN_INTEGER<<16)
  };
  static const uint PATH4[4] = {
    (JSON_TOKEN_LBRACE<<16) | KEYW_JSON_PARAMS,
    (JSON_TOKEN_LBRACKET<<16) | 2,
    (JSON_TOKEN_LBRACE<<16) | KEYW_JSON_OFFSET,
    (JSON_TOKEN_INTEGER<<16)
  };
  ulong len_sz = 0;
  const void* len_ptr = json_get_value(values, PATH3, 4, &len_sz);
  ulong off_sz = 0;
  const void* off_ptr = json_get_value(values, PATH4, 4, &off_sz);
  if (len_ptr && off_ptr) {
    if (enc == ENC_JSON) {
      fd_web_replier_error(replier, "cannot use jsonParsed encoding with slice");
      return 0;
    }
    long len = *(long*)len_ptr;
    long off = *(long*)off_ptr;
    if (off < 0 || (ulong)off >= val_sz) {
      val = NULL;
      val_sz = 0;
    } else {
      val = (char*)val + (ulong)off;
      val_sz = val_sz - (ulong)off;
    }
    if (len < 0) {
      val = NULL;
      val_sz = 0;
    } else if ((ulong)len < val_sz)
      val_sz = (ulong)len;
  }

  fd_textstream_sprintf(ts, "{\"jsonrpc\":\"2.0\",\"result\":{\"context\":{\"apiVersion\":\"" API_VERSION "\",\"slot\":%lu},\"value\":{\"data\":\"",
                        ctx->slot);

  if (val_sz) {
    switch (enc) {
    case ENC_BASE58:
      if (fd_textstream_encode_base58(ts, val, val_sz)) {
        fd_web_replier_error(replier, "failed to encode data in base58");
        return 0;
      }
      break;
    case ENC_BASE64:
      if (fd_textstream_encode_base64(ts, val, val_sz)) {
        fd_web_replier_error(replier, "failed to encode data in base64");
        return 0;
      }
      break;
    case ENC_BASE64_ZSTD:
      break;
    case ENC_JSON:
      break;
    }
  }
  
  char owner[50];
  fd_base58_encode_32((uchar*)metadata->info.owner, 0, owner);
  fd_textstream_sprintf(ts, "\",\"executable\":%s,\"lamports\":%lu,\"owner\":\"%s\",\"rentEpoch\":%lu}},\"id\":%lu}" CRLF,
                        (metadata->info.executable ? "true" : "false"),
                        metadata->info.lamports,
                        owner,
                        metadata->info.rent_epoch,
                        ctx->call_id);
  fd_web_replier_done(replier);
  return 0;
}

// Implementation of the "getBalance" method
static int
method_getBalance(struct fd_web_replier* replier, struct json_values* values, fd_rpc_ctx_t * ctx) {
  // Path to argument
  static const uint PATH[3] = {
    (JSON_TOKEN_LBRACE<<16) | KEYW_JSON_PARAMS,
    (JSON_TOKEN_LBRACKET<<16) | 0,
    (JSON_TOKEN_STRING<<16)
  };
  ulong arg_sz = 0;
  const void* arg = json_get_value(values, PATH, 3, &arg_sz);
  if (arg == NULL) {
    fd_web_replier_error(replier, "getBalance requires a string as first parameter");
    return 0;
  }
  fd_pubkey_t acct;
  fd_base58_decode_32((const char *)arg, acct.uc);
  fd_funk_rec_key_t recid = fd_acc_mgr_key(&acct);
  fd_funk_rec_t const * rec = fd_funk_rec_query_global(ctx->funk, NULL, &recid);
  if (rec == NULL) {
    fd_web_replier_error(replier, "failed to load account data for %s", (const char*)arg);
    return 0;
  }
  void * val = fd_funk_val(rec, fd_funk_wksp(ctx->funk));
  fd_account_meta_t * metadata = (fd_account_meta_t *)val;
  fd_textstream_t * ts = fd_web_replier_textstream(replier);
  fd_textstream_sprintf(ts, "{\"jsonrpc\":\"2.0\",\"result\":{\"context\":{\"apiVersion\":\"" API_VERSION "\",\"slot\":%lu},\"value\":%lu},\"id\":%lu}" CRLF,
                        ctx->slot, metadata->info.lamports, ctx->call_id);
  fd_web_replier_done(replier);
  return 0;
}

// Implementation of the "getBlock" method
static int
method_getBlock(struct fd_web_replier* replier, struct json_values* values, fd_rpc_ctx_t * ctx) {
  static const uint PATH_SLOT[3] = {
    (JSON_TOKEN_LBRACE<<16) | KEYW_JSON_PARAMS,
    (JSON_TOKEN_LBRACKET<<16) | 0,
    (JSON_TOKEN_INTEGER<<16)
  };
  static const uint PATH_ENCODING[4] = {
    (JSON_TOKEN_LBRACE<<16) | KEYW_JSON_PARAMS,
    (JSON_TOKEN_LBRACKET<<16) | 1,
    (JSON_TOKEN_LBRACE<<16) | KEYW_JSON_ENCODING,
    (JSON_TOKEN_STRING<<16)
  };
  static const uint PATH_MAXVERS[4] = {
    (JSON_TOKEN_LBRACE<<16) | KEYW_JSON_PARAMS,
    (JSON_TOKEN_LBRACKET<<16) | 1,
    (JSON_TOKEN_LBRACE<<16) | KEYW_JSON_MAXSUPPORTEDTRANSACTIONVERSION,
    (JSON_TOKEN_INTEGER<<16)
  };
  static const uint PATH_DETAIL[4] = {
    (JSON_TOKEN_LBRACE<<16) | KEYW_JSON_PARAMS,
    (JSON_TOKEN_LBRACKET<<16) | 1,
    (JSON_TOKEN_LBRACE<<16) | KEYW_JSON_TRANSACTIONDETAILS,
    (JSON_TOKEN_STRING<<16)
  };
  static const uint PATH_REWARDS[4] = {
    (JSON_TOKEN_LBRACE<<16) | KEYW_JSON_PARAMS,
    (JSON_TOKEN_LBRACKET<<16) | 1,
    (JSON_TOKEN_LBRACE<<16) | KEYW_JSON_REWARDS,
    (JSON_TOKEN_BOOL<<16)
  };
  
  ulong slot_sz = 0;
  const void* slot = json_get_value(values, PATH_SLOT, 3, &slot_sz);
  if (slot == NULL) {
    fd_web_replier_error(replier, "getBlock requires a slot number as first parameter");
    return 0;
  }
  ulong slotn = (ulong)(*(long*)slot);

  ulong enc_str_sz = 0;
  const void* enc_str = json_get_value(values, PATH_ENCODING, 4, &enc_str_sz);
  enum fd_block_encoding enc;
  if (enc_str == NULL || MATCH_STRING(enc_str, enc_str_sz, "json"))
    enc = FD_BLOCK_ENC_JSON;
  else if (MATCH_STRING(enc_str, enc_str_sz, "base58"))
    enc = FD_BLOCK_ENC_BASE58;
  else if (MATCH_STRING(enc_str, enc_str_sz, "base64"))
    enc = FD_BLOCK_ENC_BASE64;
  else if (MATCH_STRING(enc_str, enc_str_sz, "jsonParsed"))
    enc = FD_BLOCK_ENC_JSON_PARSED;
  else {
    fd_web_replier_error(replier, "invalid data encoding %s", (const char*)enc_str);
    return 0;
  }

  ulong maxvers_sz = 0;
  const void* maxvers = json_get_value(values, PATH_MAXVERS, 4, &maxvers_sz);
  
  ulong det_str_sz = 0;
  const void* det_str = json_get_value(values, PATH_DETAIL, 4, &det_str_sz);
  enum fd_block_detail det;
  if (det_str == NULL || MATCH_STRING(det_str, det_str_sz, "full"))
    det = FD_BLOCK_DETAIL_FULL;
  else if (MATCH_STRING(det_str, det_str_sz, "accounts"))
    det = FD_BLOCK_DETAIL_ACCTS;
  else if (MATCH_STRING(det_str, det_str_sz, "signatures"))
    det = FD_BLOCK_DETAIL_SIGS;
  else if (MATCH_STRING(det_str, det_str_sz, "none"))
    det = FD_BLOCK_DETAIL_NONE;
  else {
    fd_web_replier_error(replier, "invalid block detail %s", (const char*)det_str);
    return 0;
  }
  
  ulong rewards_sz = 0;
  const void* rewards = json_get_value(values, PATH_REWARDS, 4, &rewards_sz);

  fd_blockstore_block_t * blk = fd_blockstore_block_query(ctx->blks, slotn);
  if (blk == NULL) {
    fd_web_replier_error(replier, "failed to load block for slot %lu", slotn);
    return 0;
  }
  
  fd_textstream_t * ts = fd_web_replier_textstream(replier);
  if (fd_block_to_json(ts, ctx->call_id, blk->data, blk->sz, NULL, 0, enc,
                       (maxvers == NULL ? 0 : *(const long*)maxvers),
                       det,
                       (rewards == NULL ? 1 : *(const int*)rewards))) {
    fd_web_replier_error(replier, "failed to display block for slot %lu", slotn);
    return 0;
  }
  fd_web_replier_done(replier);
  return 0;
}

// Implementation of the "getTransaction" method
static int
method_getTransaction(struct fd_web_replier* replier, struct json_values* values, fd_rpc_ctx_t * ctx) {
  (void)ctx;
  static const uint PATH_SIG[3] = {
    (JSON_TOKEN_LBRACE<<16) | KEYW_JSON_PARAMS,
    (JSON_TOKEN_LBRACKET<<16) | 0,
    (JSON_TOKEN_STRING<<16)
  };
  static const uint PATH_ENCODING[3] = {
    (JSON_TOKEN_LBRACE<<16) | KEYW_JSON_PARAMS,
    (JSON_TOKEN_LBRACKET<<16) | 1,
    (JSON_TOKEN_STRING<<16)
  };
  
  ulong sig_sz = 0;
  const void* sig = json_get_value(values, PATH_SIG, 3, &sig_sz);
  if (sig == NULL) {
    fd_web_replier_error(replier, "getTransaction requires a signature as first parameter");
    return 0;
  }

  ulong enc_str_sz = 0;
  const void* enc_str = json_get_value(values, PATH_ENCODING, 3, &enc_str_sz);
  enum fd_block_encoding enc;
  if (enc_str == NULL || MATCH_STRING(enc_str, enc_str_sz, "json"))
    enc = FD_BLOCK_ENC_JSON;
  else if (MATCH_STRING(enc_str, enc_str_sz, "base58"))
    enc = FD_BLOCK_ENC_BASE58;
  else if (MATCH_STRING(enc_str, enc_str_sz, "base64"))
    enc = FD_BLOCK_ENC_BASE64;
  else if (MATCH_STRING(enc_str, enc_str_sz, "jsonParsed"))
    enc = FD_BLOCK_ENC_JSON_PARSED;
  else {
    fd_web_replier_error(replier, "invalid data encoding %s", (const char*)enc_str);
    return 0;
  }
  (void)enc;

  fd_textstream_t * ts = fd_web_replier_textstream(replier);
  (void)ts;

#if 0
  struct txn_map_key key;
  if ( fd_base58_decode_64( sig, (uchar*)&key) == NULL ) {
    fd_textstream_sprintf(ts, "{\"jsonrpc\":\"2.0\",\"result\":null,\"id\":%lu}" CRLF, call_id);
    fd_web_replier_done(replier);
    return 0;
  }
  txn_map_elem_t * elem = txn_map_elem_query( txn_map, &key, NULL );
  if ( FD_UNLIKELY( NULL == elem ) ) {
    fd_textstream_sprintf(ts, "{\"jsonrpc\":\"2.0\",\"result\":null,\"id\":%lu}" CRLF, call_id);
    fd_web_replier_done(replier);
    return 0;
  }

  fd_funk_rec_key_t recid = fd_runtime_block_key(elem->slot);
  fd_funk_rec_t const * rec = fd_funk_rec_query_global(funk, NULL, &recid);
  if (rec == NULL) {
    fd_web_replier_error(replier, "failed to load block for slot %lu", elem->slot);
    return 0;
  }
  void * val = fd_funk_val(rec, fd_funk_wksp(funk));
  void * val2 = NULL;
  ulong val2_sz = 0;
  if (elem->txn_stat_off != ULONG_MAX) {
    fd_funk_rec_key_t recid2 = fd_runtime_block_txnstatus_key(elem->slot);
    fd_funk_rec_t const * rec2 = fd_funk_rec_query_global(funk, NULL, &recid2);
    if (rec2) {
      val2 = fd_funk_val(rec2, fd_funk_wksp(funk));
      val2 = (uchar*)val2 + elem->txn_stat_off;
      val2_sz = elem->txn_stat_sz;
    }
  }

  uchar txn_out[FD_TXN_MAX_SZ];
  ulong pay_sz = 0;
  const uchar* raw = (const uchar *)val + elem->txn_off;
  ulong txn_sz = fd_txn_parse_core(raw, elem->txn_sz, txn_out, NULL, &pay_sz, 0);
  if ( txn_sz == 0 || txn_sz > FD_TXN_MAX_SZ )
    FD_LOG_ERR(("failed to parse transaction"));

  fd_textstream_sprintf(ts, "{\"jsonrpc\":\"2.0\",\"result\":{\"context\":{\"apiVersion\":\"" API_VERSION "\",\"slot\":%lu},\"slot\":%lu,", slot_bank.slot, elem->slot);
  fd_txn_to_json( ts, (fd_txn_t *)txn_out, raw, val2, val2_sz, enc, 0, FD_BLOCK_DETAIL_FULL, 0 );
  fd_textstream_sprintf(ts, "},\"id\":%lu}" CRLF, call_id);
#endif
  fd_web_replier_done(replier);
  return 0;
}

// Top level method dispatch function
void
fd_webserver_method_generic(struct fd_web_replier* replier, struct json_values* values, void * cb_arg) {
  fd_rpc_ctx_t ctx = *( fd_rpc_ctx_t *)cb_arg;
  
  static const uint PATH[2] = {
    (JSON_TOKEN_LBRACE<<16) | KEYW_JSON_JSONRPC,
    (JSON_TOKEN_STRING<<16)
  };
  ulong arg_sz = 0;
  const void* arg = json_get_value(values, PATH, 2, &arg_sz);
  if (arg == NULL) {
    fd_web_replier_error(replier, "missing jsonrpc member");
    return;
  }
  if (!MATCH_STRING(arg, arg_sz, "2.0")) {
    fd_web_replier_error(replier, "jsonrpc value must be 2.0");
    return;
  }

  static const uint PATH3[2] = {
    (JSON_TOKEN_LBRACE<<16) | KEYW_JSON_ID,
    (JSON_TOKEN_INTEGER<<16)
  };
  arg_sz = 0;
  arg = json_get_value(values, PATH3, 2, &arg_sz);
  if (arg == NULL) {
    fd_web_replier_error(replier, "missing id member");
    return;
  }
  ctx.call_id = *(long*)arg;

  static const uint PATH2[2] = {
    (JSON_TOKEN_LBRACE<<16) | KEYW_JSON_METHOD,
    (JSON_TOKEN_STRING<<16)
  };
  arg_sz = 0;
  arg = json_get_value(values, PATH2, 2, &arg_sz);
  if (arg == NULL) {
    fd_web_replier_error(replier, "missing method member");
    return;
  }
  long meth_id = fd_webserver_json_keyword((const char*)arg, arg_sz);

  switch (meth_id) {
  case KEYW_RPCMETHOD_GETACCOUNTINFO:
    if (!method_getAccountInfo(replier, values, &ctx))
      return;
    break;
  case KEYW_RPCMETHOD_GETBALANCE:
    if (!method_getBalance(replier, values, &ctx))
      return;
    break;
  case KEYW_RPCMETHOD_GETBLOCK:
    if (!method_getBlock(replier, values, &ctx))
      return;
    break;
  case KEYW_RPCMETHOD_GETTRANSACTION:
    if (!method_getTransaction(replier, values, &ctx))
      return;
    break;
  default:
    fd_web_replier_error(replier, "unknown or unimplemented method %s", (const char*)arg);
    return;
  }

  /* Probably should make an error here */
  static const char* DOC=
"<html>" CRLF
"<head>" CRLF
"<title>OK</title>" CRLF
"</head>" CRLF
"<body>" CRLF
"</body>" CRLF
"</html>";
  fd_textstream_t * ts = fd_web_replier_textstream(replier);
  fd_textstream_append(ts, DOC, strlen(DOC));
  fd_web_replier_done(replier);
}

fd_rpc_ctx_t *
fd_rpc_alloc_ctx(fd_funk_t * funk, fd_blockstore_t * blks, fd_valloc_t valloc) {
  fd_rpc_ctx_t * ctx = (fd_rpc_ctx_t *)fd_valloc_malloc( valloc, alignof(fd_rpc_ctx_t), sizeof(fd_rpc_ctx_t));
  fd_memset(ctx, 0, sizeof(fd_rpc_ctx_t));
  ctx->funk = funk;
  ctx->blks = blks;
  return ctx;
}

void
fd_rpc_set_slot(fd_rpc_ctx_t * ctx, ulong slot) {
  ctx->slot = slot;
}

void
fd_rpc_start_service(ushort portno, fd_rpc_ctx_t * ctx) {
  if (fd_webserver_start(portno, &ctx->ws, ctx))
    FD_LOG_ERR(("fd_webserver_start failed"));
}
  
void
fd_rpc_stop_service(fd_rpc_ctx_t * ctx) {
  if (fd_webserver_stop(&ctx->ws))
    FD_LOG_ERR(("fd_webserver_stop failed"));
}
