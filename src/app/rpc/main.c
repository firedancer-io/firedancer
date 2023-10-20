/****

build/native/gcc/bin/fd_frank_ledger --wksp giant_wksp --reset true --cmd ingest --snapshotfile /data/jsiegel/mainnet-ledger/snapshot-179244882-2DyMb1qN8JuTijCjsW8w4G2tg1hWuAw2AopH7Bj9Qstu.tar.zst --incremental /data/jsiegel/mainnet-ledger/incremental-snapshot-179244882-179248368-6TprbHABozQQLjjc1HBeQ2p4AigMC7rhHJS2Q5WLcbyw.tar.zst --rocksdb /data/jsiegel/mainnet-ledger/rocksdb --endslot 179249378 --txnstatus true
     
build/native/gcc/bin/fd_rpc --wksp giant_wksp --gaddr 0x000000000e7ce580

curl http://localhost:8899 -X POST -H 'content-type: application/json' --data '{"jsonrpc":"2.0", "id":1234, "method":"getAccountInfo", "params":["2cMzyuUE7VgDDVspERn8zo6dyrVsFgWi7G46QewbMEyc",{"encoding":"base58"}]}'

curl http://localhost:8899 -H 'content-type: application/json' --data '{"jsonrpc":"2.0", "id":1234, "method":"getBalance", "params":["7cVfgArCheMR6Cs4t6vz5rfnqd56vZq4ndaBrY5xkxXy"]}'

curl http://localhost:8899 -H 'content-type: application/json' --data '{"jsonrpc": "2.0","id":1,"method":"getBlock","params": [189587883,{"encoding": "json", "maxSupportedTransactionVersion":0, "transactionDetails":"full", "rewards":false}]}'

curl https://try-rpc.mainnet.solana.blockdaemon.tech -X POST -H 'content-type: application/json' --data '{"jsonrpc":"2.0", "id":1, "method":"getBlock", "params":[189587883,{"maxSupportedTransactionVersion":0}]}'

curl http://localhost:8899 -X POST -H "Content-Type: application/json" -d '{"jsonrpc": "2.0","id": 1,"method": "getTransaction","params": ["5uCzmkd9ymBN5vha4BPARWWNN9ebHC959XRAx7tdygomdjCzUY3J7u1zQ3XFmy1Z1DgE3KV1vx6mL8BpWwv8fzRU","json"]}'

curl http://localhost:8899 -X POST -H "Content-Type: application/json" -d '{"jsonrpc": "2.0","id": 1,"method": "getTransaction","params": ["4BQ4bxhrjuSCiaTFxWY9bozBK8wYtoZdQ8Lvshavh4dELq4246kAiuTxyTgzRT6HssztsStAFvHxAiT19aiNdvkC","json"]}'

curl https://try-rpc.mainnet.solana.blockdaemon.tech -X POST -H 'content-type: application/json' --data '{"jsonrpc": "2.0","id": 1,"method": "getTransaction","params": ["4BQ4bxhrjuSCiaTFxWY9bozBK8wYtoZdQ8Lvshavh4dELq4246kAiuTxyTgzRT6HssztsStAFvHxAiT19aiNdvkC",{"maxSupportedTransactionVersion":0,"encoding":"json"}]}'

build/native/gcc/bin/fd_frank_ledger --wksp giant_wksp --reset true --cmd ingest --snapshotfile /data/asiegel/ledger/snapshot-189585884-BsRKa7RbjrzR2d2VXeDvMnZdUbTxPir5sFceJyvSZJbZ.tar.zst --rocksdb /data/asiegel/ledger/rocksdb --txnstatus true --endslot 189587884

****/

#include "../../util/fd_util.h"
#include <signal.h>
#include <stdio.h>
#include <microhttpd.h>
#include "../../tango/webserver/fd_methods.h"
#include "../../tango/webserver/fd_webserver.h"
#include "../../funk/fd_funk.h"
#include "../../flamenco/types/fd_types.h"
#include "../../flamenco/types/fd_solana_block.pb.h"
#include "../../flamenco/runtime/fd_runtime.h"
#include "../../flamenco/runtime/fd_acc_mgr.h"
#include "../../ballet/base58/fd_base58.h"
#include "keywords.h"
#include "fd_block_to_json.h"

txn_map_elem_t * txn_map = NULL;

#define API_VERSION "1.14.19"

#define CRLF "\r\n"
#define MATCH_STRING(_text_,_text_sz_,_str_) (_text_sz_ == sizeof(_str_)-1 && memcmp(_text_, _str_, sizeof(_str_)-1) == 0)

static fd_funk_t* funk = NULL;
static fd_firedancer_banks_t bank;

// Implementation of the "getAccountInfo" method
int method_getAccountInfo(struct fd_web_replier* replier, struct json_values* values, long call_id) {
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
  fd_funk_rec_t const * rec = fd_funk_rec_query_global(funk, NULL, &recid);

  fd_textstream_t * ts = fd_web_replier_textstream(replier);
  if (rec == NULL) {
    fd_textstream_sprintf(ts, "{\"jsonrpc\":\"2.0\",\"result\":{\"context\":{\"apiVersion\":\"" API_VERSION "\",\"slot\":%lu},\"value\":null},\"id\":%lu}" CRLF,
                          bank.slot, call_id);
    fd_web_replier_done(replier);
    return 0;
  }

  fd_wksp_t * wksp = fd_funk_wksp(funk);
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
                        bank.slot);

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
                        call_id);
  fd_web_replier_done(replier);
  return 0;
}

// Implementation of the "getBalance" method
int method_getBalance(struct fd_web_replier* replier, struct json_values* values, long call_id) {
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
  fd_funk_rec_t const * rec = fd_funk_rec_query_global(funk, NULL, &recid);
  if (rec == NULL) {
    fd_web_replier_error(replier, "failed to load account data for %s", (const char*)arg);
    return 0;
  }
  void * val = fd_funk_val(rec, fd_funk_wksp(funk));
  fd_account_meta_t * metadata = (fd_account_meta_t *)val;
  fd_textstream_t * ts = fd_web_replier_textstream(replier);
  fd_textstream_sprintf(ts, "{\"jsonrpc\":\"2.0\",\"result\":{\"context\":{\"apiVersion\":\"" API_VERSION "\",\"slot\":%lu},\"value\":%lu},\"id\":%lu}" CRLF,
                        bank.slot, metadata->info.lamports, call_id);
  fd_web_replier_done(replier);
  return 0;
}

// Implementation of the "getBlock" method
int method_getBlock(struct fd_web_replier* replier, struct json_values* values, long call_id) {
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

  fd_funk_rec_key_t recid = fd_runtime_block_key(slotn);
  fd_funk_rec_t const * rec = fd_funk_rec_query_global(funk, NULL, &recid);
  if (rec == NULL) {
    fd_web_replier_error(replier, "failed to load block for slot %lu", slotn);
    return 0;
  }
  void * val = fd_funk_val(rec, fd_funk_wksp(funk));
  fd_funk_rec_key_t recid2 = fd_runtime_block_txnstatus_key(slotn);
  fd_funk_rec_t const * rec2 = fd_funk_rec_query_global(funk, NULL, &recid2);
  void * val2 = NULL;
  ulong val2_sz = 0;
  if (rec2) {
    val2 = fd_funk_val(rec2, fd_funk_wksp(funk));
    val2_sz = fd_funk_val_sz(rec2);
  }
  
  fd_textstream_t * ts = fd_web_replier_textstream(replier);
  if (fd_block_to_json(ts, call_id, val, fd_funk_val_sz(rec), val2, val2_sz, enc,
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
int method_getTransaction(struct fd_web_replier* replier, struct json_values* values, long call_id) {
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

  fd_textstream_t * ts = fd_web_replier_textstream(replier);

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

  fd_textstream_sprintf(ts, "{\"jsonrpc\":\"2.0\",\"result\":{\"context\":{\"apiVersion\":\"" API_VERSION "\",\"slot\":%lu},\"slot\":%lu,", bank.slot, elem->slot);
  fd_txn_to_json( ts, (fd_txn_t *)txn_out, raw, val2, val2_sz, enc, 0, FD_BLOCK_DETAIL_FULL, 0 );
  fd_textstream_sprintf(ts, "},\"id\":%lu}" CRLF, call_id);
  fd_web_replier_done(replier);
  return 0;
}

// Top level method dispatch function
void fd_webserver_method_generic(struct fd_web_replier* replier, struct json_values* values) {
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
  long call_id = *(long*)arg;

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
    if (!method_getAccountInfo(replier, values, call_id))
      return;
    break;
  case KEYW_RPCMETHOD_GETBALANCE:
    if (!method_getBalance(replier, values, call_id))
      return;
    break;
  case KEYW_RPCMETHOD_GETBLOCK:
    if (!method_getBlock(replier, values, call_id))
      return;
    break;
  case KEYW_RPCMETHOD_GETTRANSACTION:
    if (!method_getTransaction(replier, values, call_id))
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

void prescan(void)  {
  fd_funk_rec_key_t key = fd_runtime_block_meta_key(ULONG_MAX);
  fd_funk_rec_t const * rec = fd_funk_rec_query( funk, NULL, &key );
  if (rec == NULL)
    FD_LOG_ERR(("missing meta record"));
  fd_slot_meta_meta_t mm;
  const void * val = fd_funk_val( rec, fd_funk_wksp(funk) );
  fd_bincode_decode_ctx_t ctx2;
  ctx2.data    = val;
  ctx2.dataend = (uchar*)val + fd_funk_val_sz(rec);
  ctx2.valloc  = fd_libc_alloc_virtual();
  if ( fd_slot_meta_meta_decode( &mm, &ctx2 ) )
    FD_LOG_ERR(("fd_slot_meta_meta_decode failed"));
  FD_LOG_NOTICE(("scanning block %lu to %lu", mm.start_slot, mm.end_slot));

  /* Estimate an upper bound for the number of transactions based on the number of blocks */
  ulong key_max = 4000*(1 + mm.end_slot - mm.start_slot);
  void* mem = fd_valloc_malloc(fd_libc_alloc_virtual(), txn_map_elem_align(), txn_map_elem_footprint(key_max));
  txn_map = txn_map_elem_join(txn_map_elem_new(mem, key_max, 0));
  
  for (ulong slot = mm.start_slot; slot <= mm.end_slot; ++slot) {
    fd_funk_rec_key_t recid = fd_runtime_block_key(slot);
    rec = fd_funk_rec_query_global(funk, NULL, &recid);
    if (rec == NULL)
      continue;
    const void * block = fd_funk_val(rec, fd_funk_wksp(funk));
    ulong blocklen = fd_funk_val_sz( rec );

    // TODO: move to the block_info api!
    /* Loop across batches */
    ulong blockoff = 0;
    while (blockoff < blocklen) {
      if ( blockoff + sizeof(ulong) > blocklen )
        FD_LOG_ERR(("premature end of block"));
      ulong mcount = *(const ulong *)((const uchar *)block + blockoff);
      blockoff += sizeof(ulong);

      /* Loop across microblocks */
      for (ulong mblk = 0; mblk < mcount; ++mblk) {
        if ( blockoff + sizeof(fd_microblock_hdr_t) > blocklen )
          FD_LOG_ERR(("premature end of block"));
        fd_microblock_hdr_t * hdr = (fd_microblock_hdr_t *)((const uchar *)block + blockoff);
        blockoff += sizeof(fd_microblock_hdr_t);

        /* Loop across transactions */
        for ( ulong txn_idx = 0; txn_idx < hdr->txn_cnt; txn_idx++ ) {
          uchar txn_out[FD_TXN_MAX_SZ];
          uchar const * raw = (uchar const *)block + blockoff;
          ulong pay_sz = 0;
          ulong txn_sz = fd_txn_parse_core( (uchar const *)raw, fd_ulong_min(blocklen - blockoff, FD_TXN_MTU), txn_out, NULL, &pay_sz, 0 );
          if ( txn_sz == 0 || txn_sz > FD_TXN_MTU ) {
              FD_LOG_ERR(("failed to parse transaction %lu in microblock %lu in slot %lu", txn_idx, mblk, slot));
          }
          fd_txn_t const * txn = (fd_txn_t const *)txn_out;
        
          if ( pay_sz == 0UL )
            FD_LOG_ERR(("failed to parse transaction %lu in microblock %lu in slot %lu", txn_idx, mblk, slot));
          
          struct txn_map_key const * sigs = (struct txn_map_key const *)((ulong)raw + (ulong)txn->signature_off);
          for ( ulong j = 0; j < txn->signature_cnt; j++ ) {
            txn_map_elem_t * elem = txn_map_elem_insert( txn_map, sigs+j );
            if ( FD_UNLIKELY( NULL == elem ) ) {
              FD_LOG_NOTICE(("scanned %lu transactions (reached max estimate)", txn_map_elem_key_cnt( txn_map )));
              return;
            }
            elem->slot = slot;
            elem->txn_off = blockoff;
            elem->txn_sz = pay_sz;
            elem->txn_stat_off = ULONG_MAX;
            elem->txn_stat_sz = ULONG_MAX;
          }
          
          blockoff += pay_sz;
        }
      }
    }

    if (blockoff != blocklen)
      FD_LOG_ERR(("garbage at end of block"));

    key = fd_runtime_block_txnstatus_key(slot);
    rec = fd_funk_rec_query( funk, NULL, &key );
    if (rec == NULL)
      continue;
    val = fd_funk_val( rec, fd_funk_wksp(funk) );
    ulong val_sz = fd_funk_val_sz( rec );
    if (val_sz < sizeof(ulong))
      FD_LOG_ERR(("garbage txn status block at slot %lu", slot));
    ulong idx_cnt = *(ulong*)val;
    ulong hdr_sz = sizeof(ulong) + idx_cnt*sizeof(fd_txnstatusidx_t);
    if (val_sz < hdr_sz)
      FD_LOG_ERR(("garbage txn status block at slot %lu", slot));
    const fd_txnstatusidx_t * j = (const fd_txnstatusidx_t *)((const uchar*)val + sizeof(ulong));
    for ( ulong i = 0; i < idx_cnt; ++i, ++j ) {
      txn_map_elem_t * elem = txn_map_elem_query( txn_map, (const struct txn_map_key*)j->sig, NULL );
      if ( FD_UNLIKELY( NULL == elem ) )
        FD_LOG_ERR(("garbage txn status block at slot %lu", slot));
      elem->txn_stat_off = hdr_sz + j->offset;
      elem->txn_stat_sz = j->status_sz;
      if (val_sz < elem->txn_stat_off + elem->txn_stat_sz)
        FD_LOG_ERR(("garbage txn status block at slot %lu", slot));
    }
  }
  FD_LOG_NOTICE(("scanned %lu transactions", txn_map_elem_key_cnt( txn_map )));
}

// SIGINT signal handler
volatile int stopflag = 0;
void stop(int sig) { (void)sig; stopflag = 1; }

int main(int argc, char** argv)
{
  fd_boot(&argc, &argv);

  const char* wkspname = fd_env_strip_cmdline_cstr(&argc, &argv, "--wksp", NULL, NULL);
  if (wkspname == NULL)
    FD_LOG_ERR(( "--wksp not specified" ));
  fd_wksp_t* wksp = fd_wksp_attach(wkspname);
  if (wksp == NULL)
    FD_LOG_ERR(( "failed to attach to workspace %s", wkspname ));
  
  void* shmem;
  fd_wksp_tag_query_info_t info;
  ulong tag = FD_FUNK_MAGIC;
  if (fd_wksp_tag_query(wksp, &tag, 1, &info, 1) > 0) {
    shmem = fd_wksp_laddr_fast( wksp, info.gaddr_lo );
    funk = fd_funk_join(shmem);
    if (funk == NULL)
      FD_LOG_ERR(( "failed to join a funky" ));
  } else {
    FD_LOG_ERR(( "failed to join a funky" ));
  }

  {
    fd_funk_rec_key_t id = fd_runtime_banks_key();
    fd_funk_rec_t const * rec = fd_funk_rec_query_global(funk, NULL, &id);
    if ( rec == NULL )
      FD_LOG_ERR(("failed to read banks record"));
    void * val = fd_funk_val( rec, fd_funk_wksp(funk) );
    fd_bincode_decode_ctx_t ctx;
    ctx.data = val;
    ctx.dataend = (uchar*)val + fd_funk_val_sz( rec );
    ctx.valloc = fd_libc_alloc_virtual();
    if ( fd_firedancer_banks_decode(&bank, &ctx ) )
      FD_LOG_ERR(("failed to read banks record"));
  }

  prescan();
  
  signal(SIGINT, stop);
  signal(SIGPIPE, SIG_IGN);

  // Get the gateway service port number 
  uint portno = fd_env_strip_cmdline_uint(&argc, &argv, "--port", "FD_FCGI_PORT", 8899U);
  fd_webserver_t ws;
  if (fd_webserver_start(portno, &ws))
    FD_LOG_ERR(("fd_webserver_start failed"));
  
  while (!stopflag) {
    sleep(1);
  }

  if (fd_webserver_stop(&ws))
    FD_LOG_ERR(("fd_webserver_stop failed"));

  fd_valloc_free(fd_libc_alloc_virtual(), txn_map_elem_delete(txn_map_elem_leave(txn_map)));
  txn_map = NULL;
  
  {
    fd_bincode_destroy_ctx_t ctx;
    ctx.valloc = fd_libc_alloc_virtual();
    fd_firedancer_banks_destroy(&bank, &ctx);
  }

  fd_funk_leave( funk );

  fd_log_flush();
  fd_halt();
  return 0;
}
