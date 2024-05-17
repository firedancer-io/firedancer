#include "fd_rpc_service.h"
#include <microhttpd.h>
#include "fd_methods.h"
#include "fd_webserver.h"
#include "../../flamenco/types/fd_types.h"
#include "../../flamenco/types/fd_solana_block.pb.h"
#include "../../flamenco/runtime/fd_runtime.h"
#include "../../flamenco/runtime/fd_acc_mgr.h"
#include "../../flamenco/runtime/sysvar/fd_sysvar_rent.h"
#include "../../ballet/base58/fd_base58.h"
#include "keywords.h"
#include "fd_block_to_json.h"

#define API_VERSION "1.17.6"

#define CRLF "\r\n"
#define MATCH_STRING(_text_,_text_sz_,_str_) (_text_sz_ == sizeof(_str_)-1 && memcmp(_text_, _str_, sizeof(_str_)-1) == 0)

struct fd_rpc_ctx {
    fd_webserver_t ws;
    fd_funk_t * funk;
    fd_blockstore_t * blockstore;
    long call_id;
};

static void *
read_account( fd_rpc_ctx_t * ctx, fd_pubkey_t * acct, fd_valloc_t valloc, ulong * result_len ) {
  fd_funk_rec_key_t recid = fd_acc_funk_key(acct);
  return fd_funk_rec_query_safe(ctx->funk, &recid, valloc, result_len);
}

fd_epoch_bank_t *
read_epoch_bank( fd_rpc_ctx_t * ctx, fd_valloc_t valloc ) {
  fd_funk_rec_key_t recid = fd_runtime_epoch_bank_key();
  ulong vallen;
  void * val = fd_funk_rec_query_safe(ctx->funk, &recid, valloc, &vallen);
  if( val == NULL ) {
    FD_LOG_WARNING(( "failed to decode epoch_bank" ));
    return NULL;
  }
  fd_epoch_bank_t * epoch_bank = fd_valloc_malloc( valloc, fd_epoch_bank_align(), fd_epoch_bank_footprint() );
  fd_epoch_bank_new( epoch_bank );
  fd_bincode_decode_ctx_t binctx;
  binctx.data = val;
  binctx.dataend = (uchar*)val + vallen;
  binctx.valloc  = valloc;
  if( fd_epoch_bank_decode( epoch_bank, &binctx )!=FD_BINCODE_SUCCESS ) {
    FD_LOG_WARNING(( "failed to decode epoch_bank" ));
    fd_valloc_free( valloc, val );
    return NULL;
  }
  fd_valloc_free( valloc, val );
  return epoch_bank;
}

fd_slot_bank_t *
read_slot_bank( fd_rpc_ctx_t * ctx, fd_valloc_t valloc ) {
  fd_funk_rec_key_t recid = fd_runtime_slot_bank_key();
  ulong vallen;
  void * val = fd_funk_rec_query_safe(ctx->funk, &recid, valloc, &vallen);
  if( val == NULL ) {
    FD_LOG_WARNING(( "failed to decode slot_bank" ));
    return NULL;
  }
  fd_slot_bank_t * slot_bank = fd_valloc_malloc( valloc, fd_slot_bank_align(), fd_slot_bank_footprint() );
  fd_slot_bank_new( slot_bank );
  fd_bincode_decode_ctx_t binctx;
  binctx.data = val;
  binctx.dataend = (uchar*)val + vallen;
  binctx.valloc  = valloc;
  if( fd_slot_bank_decode( slot_bank, &binctx )!=FD_BINCODE_SUCCESS ) {
    FD_LOG_WARNING(( "failed to decode slot_bank" ));
    fd_valloc_free( valloc, val );
    return NULL;
  }
  fd_valloc_free( valloc, val );
  return slot_bank;
}

static void fd_method_cleanup( uchar ** smem ) {
  fd_scratch_detach( NULL );
  free( *smem );
}

/* Setup scratch space */
#define FD_METHOD_SCRATCH_BEGIN( SMAX ) do {                              \
  uchar * smem = aligned_alloc( FD_SCRATCH_SMEM_ALIGN,                  \
    fd_ulong_align_up( fd_scratch_smem_footprint( SMAX  ), FD_SCRATCH_SMEM_ALIGN ) ); \
  ulong fmem[4U];                                                       \
  fd_scratch_attach( smem, fmem, SMAX, 4U );                            \
  fd_scratch_push();                                                    \
  uchar * __fd_scratch_guard_ ## __LINE__                               \
    __attribute__((cleanup(fd_method_cleanup))) = smem;                 \
  do

#define FD_METHOD_SCRATCH_END while(0); } while(0)

// Implementation of the "getAccountInfo" method
// curl http://localhost:8123 -X POST -H "Content-Type: application/json" -d '{ "jsonrpc": "2.0", "id": 1, "method": "getAccountInfo", "params": [ "21bVZhkqPJRVYDG3YpYtzHLMvkc7sa4KB7fMwGekTquG", { "encoding": "base64" } ] }'

static int
method_getAccountInfo(struct fd_web_replier* replier, struct json_values* values, fd_rpc_ctx_t * ctx) {
  FD_METHOD_SCRATCH_BEGIN( 11<<20 ) {
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

    fd_textstream_t * ts = fd_web_replier_textstream(replier);

    fd_pubkey_t acct;
    fd_base58_decode_32((const char *)arg, acct.uc);
    ulong val_sz;
    void * val = read_account(ctx, &acct, fd_scratch_virtual(), &val_sz);
    if (val == NULL) {
      fd_textstream_sprintf(ts, "{\"jsonrpc\":\"2.0\",\"result\":{\"context\":{\"apiVersion\":\"" API_VERSION "\",\"slot\":%lu},\"value\":null},\"id\":%lu}" CRLF,
                            ctx->blockstore->smr, ctx->call_id);
      fd_web_replier_done(replier);
      return 0;
    }

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

    fd_textstream_sprintf(ts, "{\"jsonrpc\":\"2.0\",\"result\":{\"context\":{\"apiVersion\":\"" API_VERSION "\",\"slot\":%lu},\"value\":{\"data\":[\"",
                          ctx->blockstore->smr);

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
    fd_textstream_sprintf(ts, "\",\"%s\"],\"executable\":%s,\"lamports\":%lu,\"owner\":\"%s\",\"rentEpoch\":%lu,\"space\":%lu}},\"id\":%lu}" CRLF,
                          (const char*)enc_str,
                          (metadata->info.executable ? "true" : "false"),
                          metadata->info.lamports,
                          owner,
                          metadata->info.rent_epoch,
                          val_sz,
                          ctx->call_id);
    fd_web_replier_done(replier);

  } FD_METHOD_SCRATCH_END;

  return 0;
}

// Implementation of the "getBalance" method
// curl http://localhost:8123 -X POST -H "Content-Type: application/json" -d '{ "jsonrpc": "2.0", "id": 1, "method": "getBalance", "params": [ "6s5gDyLyfNXP6WHUEn4YSMQJVcGETpKze7FCPeg9wxYT" ] }'

static int
method_getBalance(struct fd_web_replier* replier, struct json_values* values, fd_rpc_ctx_t * ctx) {
  FD_METHOD_SCRATCH_BEGIN( 11<<20 ) {
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
    ulong val_sz;
    void * val = read_account(ctx, &acct, fd_scratch_virtual(), &val_sz);
    if (val == NULL) {
      fd_web_replier_error(replier, "failed to load account data for %s", (const char*)arg);
      return 0;
    }
    fd_account_meta_t * metadata = (fd_account_meta_t *)val;
    fd_textstream_t * ts = fd_web_replier_textstream(replier);
    fd_textstream_sprintf(ts, "{\"jsonrpc\":\"2.0\",\"result\":{\"context\":{\"apiVersion\":\"" API_VERSION "\",\"slot\":%lu},\"value\":%lu},\"id\":%lu}" CRLF,
                          ctx->blockstore->smr, metadata->info.lamports, ctx->call_id);
    fd_web_replier_done(replier);
  } FD_METHOD_SCRATCH_END;
  return 0;
}

// Implementation of the "getBlock" method
// curl http://localhost:8123 -X POST -H "Content-Type: application/json" -d ' {"jsonrpc": "2.0","id":1, "method":"getBlock", "params": [270562740, {"encoding": "json", "maxSupportedTransactionVersion":0, "transactionDetails":"full", "rewards":false}]} '

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

  fd_textstream_t * ts = fd_web_replier_textstream(replier);
  if (fd_block_to_json(ts,
                       ctx->call_id,
                       ctx->blockstore,
                       slotn,
                       enc,
                       (maxvers == NULL ? 0 : *(const long*)maxvers),
                       det,
                       (rewards == NULL ? 1 : *(const int*)rewards))) {
    fd_web_replier_error(replier, "failed to display block for slot %lu", slotn);
    return 0;
  }
  fd_web_replier_done(replier);
  return 0;
}

// Implementation of the "getBlockCommitment" methods
static int
method_getBlockCommitment(struct fd_web_replier* replier, struct json_values* values, fd_rpc_ctx_t * ctx) {
  (void)values;
  (void)ctx;
  fd_web_replier_error(replier, "getBlockCommitment is not implemented");
  return 0;
}

// Implementation of the "getBlockHeight" method
static int
method_getBlockHeight(struct fd_web_replier* replier, struct json_values* values, fd_rpc_ctx_t * ctx) {
  (void) values;
  fd_textstream_t * ts = fd_web_replier_textstream(replier);
  fd_textstream_sprintf(ts, "{\"jsonrpc\":\"2.0\",\"result\":%lu,\"id\":%lu}" CRLF,
                        /*block_height*/ 0UL,
                        ctx->call_id);
  fd_web_replier_done(replier);
  return 0;
}

// Implementation of the "getBlockProduction" methods
static int
method_getBlockProduction(struct fd_web_replier* replier, struct json_values* values, fd_rpc_ctx_t * ctx) {
  (void)values;
  (void)ctx;
  fd_web_replier_error(replier, "getBlockProduction is not implemented");
  return 0;
}

// Implementation of the "getBlocks" method
// curl http://localhost:8123 -X POST -H "Content-Type: application/json" -d ' {"jsonrpc": "2.0", "id": 1, "method": "getBlocks", "params": [270562730, 270562740]} '

static int
method_getBlocks(struct fd_web_replier* replier, struct json_values* values, fd_rpc_ctx_t * ctx) {
  static const uint PATH_STARTSLOT[3] = {
    (JSON_TOKEN_LBRACE<<16) | KEYW_JSON_PARAMS,
    (JSON_TOKEN_LBRACKET<<16) | 0,
    (JSON_TOKEN_INTEGER<<16)
  };
  ulong startslot_sz = 0;
  const void* startslot = json_get_value(values, PATH_STARTSLOT, 3, &startslot_sz);
  if (startslot == NULL) {
    fd_web_replier_error(replier, "getBlocks requires a start slot number as first parameter");
    return 0;
  }
  ulong startslotn = (ulong)(*(long*)startslot);
  static const uint PATH_ENDSLOT[3] = {
    (JSON_TOKEN_LBRACE<<16) | KEYW_JSON_PARAMS,
    (JSON_TOKEN_LBRACKET<<16) | 1,
    (JSON_TOKEN_INTEGER<<16)
  };
  ulong endslot_sz = 0;
  const void* endslot = json_get_value(values, PATH_ENDSLOT, 3, &endslot_sz);
  ulong endslotn = (endslot == NULL ? ULONG_MAX : (ulong)(*(long*)endslot));

  if (startslotn < ctx->blockstore->min)
    startslotn = ctx->blockstore->min;
  if (endslotn > ctx->blockstore->max)
    endslotn = ctx->blockstore->max;

  fd_blockstore_start_read( ctx->blockstore );
  fd_textstream_t * ts = fd_web_replier_textstream(replier);
  fd_textstream_sprintf(ts, "{\"jsonrpc\":\"2.0\",\"result\":[");
  uint cnt = 0;
  for ( ulong i = startslotn; i <= endslotn && cnt < 500000U; ++i ) {
    fd_block_t * blk = fd_blockstore_block_query(ctx->blockstore, i);
    if (blk != NULL) {
      fd_textstream_sprintf(ts, "%s%lu", (cnt==0 ? "" : ","), i);
      ++cnt;
    }
  }
  fd_textstream_sprintf(ts, "],\"id\":%lu}" CRLF, ctx->call_id);
  fd_blockstore_end_read( ctx->blockstore );

  fd_web_replier_done(replier);
  return 0;
}

// Implementation of the "getBlocksWithLimit" method
// curl http://localhost:8123 -X POST -H "Content-Type: application/json" -d ' {"jsonrpc": "2.0", "id":1, "method":"getBlocksWithLimit", "params":[270562730, 3]} '

static int
method_getBlocksWithLimit(struct fd_web_replier* replier, struct json_values* values, fd_rpc_ctx_t * ctx) {
  static const uint PATH_SLOT[3] = {
    (JSON_TOKEN_LBRACE<<16) | KEYW_JSON_PARAMS,
    (JSON_TOKEN_LBRACKET<<16) | 0,
    (JSON_TOKEN_INTEGER<<16)
  };
  ulong startslot_sz = 0;
  const void* startslot = json_get_value(values, PATH_SLOT, 3, &startslot_sz);
  if (startslot == NULL) {
    fd_web_replier_error(replier, "getBlocksWithLimit requires a start slot number as first parameter");
    return 0;
  }
  ulong startslotn = (ulong)(*(long*)startslot);
  static const uint PATH_LIMIT[3] = {
    (JSON_TOKEN_LBRACE<<16) | KEYW_JSON_PARAMS,
    (JSON_TOKEN_LBRACKET<<16) | 1,
    (JSON_TOKEN_INTEGER<<16)
  };
  ulong limit_sz = 0;
  const void* limit = json_get_value(values, PATH_LIMIT, 3, &limit_sz);
  if (limit == NULL) {
    fd_web_replier_error(replier, "getBlocksWithLimit requires a limit as second parameter");
    return 0;
  }
  ulong limitn = (ulong)(*(long*)limit);

  if (startslotn < ctx->blockstore->min)
    startslotn = ctx->blockstore->min;
  if (limitn > 500000)
    limitn = 500000;

  fd_blockstore_start_read( ctx->blockstore );
  fd_textstream_t * ts = fd_web_replier_textstream(replier);
  fd_textstream_sprintf(ts, "{\"jsonrpc\":\"2.0\",\"result\":[");
  uint cnt = 0;
  for ( ulong i = startslotn; i <= ctx->blockstore->max && cnt < limitn; ++i ) {
    fd_block_t * blk = fd_blockstore_block_query(ctx->blockstore, i);
    if (blk != NULL) {
      fd_textstream_sprintf(ts, "%s%lu", (cnt==0 ? "" : ","), i);
      ++cnt;
    }
  }
  fd_textstream_sprintf(ts, "],\"id\":%lu}" CRLF, ctx->call_id);
  fd_blockstore_end_read( ctx->blockstore );

  fd_web_replier_done(replier);
  return 0;
}

// Implementation of the "getBlockTime" methods
static int
method_getBlockTime(struct fd_web_replier* replier, struct json_values* values, fd_rpc_ctx_t * ctx) {
  (void)values;
  (void)ctx;
  fd_web_replier_error(replier, "getBlockTime is not implemented");
  return 0;
}

// Implementation of the "getClusterNodes" methods
static int
method_getClusterNodes(struct fd_web_replier* replier, struct json_values* values, fd_rpc_ctx_t * ctx) {
  (void)values;
  (void)ctx;
  fd_web_replier_error(replier, "getClusterNodes is not implemented");
  return 0;
}

// Implementation of the "getConfirmedBlock" methods
static int
method_getConfirmedBlock(struct fd_web_replier* replier, struct json_values* values, fd_rpc_ctx_t * ctx) {
  (void)values;
  (void)ctx;
  fd_web_replier_error(replier, "getConfirmedBlock is not implemented");
  return 0;
}

// Implementation of the "getConfirmedBlocks" methods
static int
method_getConfirmedBlocks(struct fd_web_replier* replier, struct json_values* values, fd_rpc_ctx_t * ctx) {
  (void)values;
  (void)ctx;
  fd_web_replier_error(replier, "getConfirmedBlocks is not implemented");
  return 0;
}

// Implementation of the "getConfirmedBlocksWithLimit" methods
static int
method_getConfirmedBlocksWithLimit(struct fd_web_replier* replier, struct json_values* values, fd_rpc_ctx_t * ctx) {
  (void)values;
  (void)ctx;
  fd_web_replier_error(replier, "getConfirmedBlocksWithLimit is not implemented");
  return 0;
}

// Implementation of the "getConfirmedSignaturesForAddress2" methods
static int
method_getConfirmedSignaturesForAddress2(struct fd_web_replier* replier, struct json_values* values, fd_rpc_ctx_t * ctx) {
  (void)values;
  (void)ctx;
  fd_web_replier_error(replier, "getConfirmedSignaturesForAddress2 is not implemented");
  return 0;
}

// Implementation of the "getConfirmedTransaction" methods
static int
method_getConfirmedTransaction(struct fd_web_replier* replier, struct json_values* values, fd_rpc_ctx_t * ctx) {
  (void)values;
  (void)ctx;
  fd_web_replier_error(replier, "getConfirmedTransaction is not implemented");
  return 0;
}

// Implementation of the "getEpochInfo" methods
// curl http://localhost:8123 -X POST -H "Content-Type: application/json" -d ' {"jsonrpc":"2.0","id":1, "method":"getEpochInfo"} '

static int
method_getEpochInfo(struct fd_web_replier* replier, struct json_values* values, fd_rpc_ctx_t * ctx) {
  (void)values;
  (void)ctx;
  fd_web_replier_error(replier, "getEpochInfo is not implemented");
  return 0;
  /*
    fd_textstream_t * ts = fd_web_replier_textstream(replier);
    fd_exec_slot_ctx_t * slot_ctx = get_slot_ctx(ctx);
    ulong slot_idx = 0;
    fd_epoch_bank_t * epoch_bank = fd_exec_epoch_ctx_epoch_bank( ctx->replay->epoch_ctx );
    ulong epoch = fd_slot_to_epoch( &epoch_bank->epoch_schedule, slot_ctx->slot_bank.slot, &slot_idx );
    ulong slots_per_epoch = fd_epoch_slot_cnt( &epoch_bank->epoch_schedule, epoch );
    fd_textstream_sprintf(ts, "{\"jsonrpc\":\"2.0\",\"result\":{\"absoluteSlot\":%lu,\"blockHeight\":%lu,\"epoch\":%lu,\"slotIndex\":%lu,\"slotsInEpoch\":%lu,\"transactionCount\":%lu},\"id\":%lu}" CRLF,
    slot_ctx->slot_bank.slot,
    slot_ctx->slot_bank.block_height,
    epoch,
    slot_idx,
    slots_per_epoch,
    slot_ctx->slot_bank.transaction_count,
    ctx->call_id);
    fd_web_replier_done(replier);
    return 0;
  */
}

// Implementation of the "getEpochSchedule" methods
// curl http://localhost:8123 -X POST -H "Content-Type: application/json" -d ' {"jsonrpc":"2.0","id":1, "method":"getEpochSchedule"} '

static int
method_getEpochSchedule(struct fd_web_replier* replier, struct json_values* values, fd_rpc_ctx_t * ctx) {
  (void)values;
  (void)ctx;
  fd_web_replier_error(replier, "getEpochSchedule is not implemented");
  return 0;
  /*
    fd_textstream_t * ts = fd_web_replier_textstream(replier);
    fd_epoch_bank_t * epoch_bank = fd_exec_epoch_ctx_epoch_bank( ctx->replay->epoch_ctx );
    fd_textstream_sprintf(ts, "{\"jsonrpc\":\"2.0\",\"result\":{\"firstNormalEpoch\":%lu,\"firstNormalSlot\":%lu,\"leaderScheduleSlotOffset\":%lu,\"slotsPerEpoch\":%lu,\"warmup\":%s},\"id\":%lu}" CRLF,
    epoch_bank->epoch_schedule.first_normal_epoch,
    epoch_bank->epoch_schedule.first_normal_slot,
    epoch_bank->epoch_schedule.leader_schedule_slot_offset,
    epoch_bank->epoch_schedule.slots_per_epoch,
    (epoch_bank->epoch_schedule.warmup ? "true" : "false"),
    ctx->call_id);
    fd_web_replier_done(replier);
    return 0;
  */
}

// Implementation of the "getFeeCalculatorForBlockhash" methods
static int
method_getFeeCalculatorForBlockhash(struct fd_web_replier* replier, struct json_values* values, fd_rpc_ctx_t * ctx) {
  (void)values;
  (void)ctx;
  fd_web_replier_error(replier, "getFeeCalculatorForBlockhash is not implemented");
  return 0;
}

// Implementation of the "getFeeForMessage" methods
static int
method_getFeeForMessage(struct fd_web_replier* replier, struct json_values* values, fd_rpc_ctx_t * ctx) {
  (void)values;
  (void)ctx;
  fd_web_replier_error(replier, "getFeeForMessage is not implemented");
  return 0;
}

// Implementation of the "getFeeRateGovernor" methods
static int
method_getFeeRateGovernor(struct fd_web_replier* replier, struct json_values* values, fd_rpc_ctx_t * ctx) {
  (void)values;
  (void)ctx;
  fd_web_replier_error(replier, "getFeeRateGovernor is not implemented");
  return 0;
}

// Implementation of the "getFees" methods
static int
method_getFees(struct fd_web_replier* replier, struct json_values* values, fd_rpc_ctx_t * ctx) {
  (void)values;
  (void)ctx;
  fd_web_replier_error(replier, "getFees is not implemented");
  return 0;
}

// Implementation of the "getFirstAvailableBlock" methods
static int
method_getFirstAvailableBlock(struct fd_web_replier* replier, struct json_values* values, fd_rpc_ctx_t * ctx) {
  (void)values;
  (void)ctx;
  fd_web_replier_error(replier, "getFirstAvailableBlock is not implemented");
  return 0;
}

// Implementation of the "getGenesisHash" methods
// curl http://localhost:8123 -X POST -H "Content-Type: application/json" -d ' {"jsonrpc":"2.0","id":1, "method":"getGenesisHash"} '

static int
method_getGenesisHash(struct fd_web_replier* replier, struct json_values* values, fd_rpc_ctx_t * ctx) {
  (void) values;
  (void)ctx;
  fd_web_replier_error(replier, "getGenesisHash is not implemented");
  return 0;
  /*
    fd_textstream_t * ts = fd_web_replier_textstream(replier);
    fd_textstream_sprintf(ts, "{\"jsonrpc\":\"2.0\",\"result\":\"");
    fd_epoch_bank_t * epoch_bank = fd_exec_epoch_ctx_epoch_bank( ctx->replay->epoch_ctx );
    fd_textstream_encode_base58(ts, epoch_bank->genesis_hash.uc, sizeof(fd_pubkey_t));
    fd_textstream_sprintf(ts, "\",\"id\":%lu}" CRLF, ctx->call_id);
    fd_web_replier_done(replier);
    return 0;
  */
}

// Implementation of the "getHealth" methods
static int
method_getHealth(struct fd_web_replier* replier, struct json_values* values, fd_rpc_ctx_t * ctx) {
  (void)values;
  fd_textstream_t * ts = fd_web_replier_textstream(replier);
  fd_textstream_sprintf(ts, "{\"jsonrpc\":\"2.0\",\"result\":\"ok\",\"id\":%lu}" CRLF, ctx->call_id);
  fd_web_replier_done(replier);
  return 0;
}

// Implementation of the "getHighestSnapshotSlot" methods
static int
method_getHighestSnapshotSlot(struct fd_web_replier* replier, struct json_values* values, fd_rpc_ctx_t * ctx) {
  (void)values;
  (void)ctx;
  fd_web_replier_error(replier, "getHighestSnapshotSlot is not implemented");
  return 0;
}

// Implementation of the "getIdentity" method
// curl http://localhost:8123 -X POST -H "Content-Type: application/json" -d ' {"jsonrpc":"2.0","id":1, "method":"getIdentity"} '

static int
method_getIdentity(struct fd_web_replier* replier, struct json_values* values, fd_rpc_ctx_t * ctx) {
  (void) values;
  (void)ctx;
  fd_web_replier_error(replier, "getIdentity is not implemented");
  return 0;
  /*
    fd_textstream_t * ts = fd_web_replier_textstream(replier);
    fd_textstream_sprintf(ts, "{\"jsonrpc\":\"2.0\",\"result\":{\"identity\":\"");
    fd_textstream_encode_base58(ts, ctx->identity->uc, sizeof(fd_pubkey_t));
    fd_textstream_sprintf(ts, "\"},\"id\":%lu}" CRLF, ctx->call_id);
    fd_web_replier_done(replier);
    return 0;
  */
}
// Implementation of the "getInflationGovernor" methods
static int
method_getInflationGovernor(struct fd_web_replier* replier, struct json_values* values, fd_rpc_ctx_t * ctx) {
  (void)values;
  (void)ctx;
  fd_web_replier_error(replier, "getInflationGovernor is not implemented");
  return 0;
}

// Implementation of the "getInflationRate" methods
// curl http://localhost:8123 -X POST -H "Content-Type: application/json" -d ' {"jsonrpc":"2.0","id":1, "method":"getInflationRate"} '

static int
method_getInflationRate(struct fd_web_replier* replier, struct json_values* values, fd_rpc_ctx_t * ctx) {
  (void) values;
  (void)ctx;
  fd_web_replier_error(replier, "getInflationRate is not implemented");
  return 0;
  /*
    fd_textstream_t * ts = fd_web_replier_textstream(replier);
    fd_inflation_rates_t rates;
    calculate_inflation_rates( get_slot_ctx(ctx), &rates );
    fd_textstream_sprintf(ts, "{\"jsonrpc\":\"2.0\",\"result\":{\"epoch\":%lu,\"foundation\":%.18f,\"total\":%.18f,\"validator\":%.18f},\"id\":%lu}" CRLF,
    rates.epoch,
    rates.foundation,
    rates.total,
    rates.validator,
    ctx->call_id);
    fd_web_replier_done(replier);
    return 0;
  */
}

// Implementation of the "getInflationReward" methods
static int
method_getInflationReward(struct fd_web_replier* replier, struct json_values* values, fd_rpc_ctx_t * ctx) {
  (void)values;
  (void)ctx;
  fd_web_replier_error(replier, "getInflationReward is not implemented");
  return 0;
}

// Implementation of the "getLargestAccounts" methods
static int
method_getLargestAccounts(struct fd_web_replier* replier, struct json_values* values, fd_rpc_ctx_t * ctx) {
  (void)values;
  (void)ctx;
  fd_web_replier_error(replier, "getLargestAccounts is not implemented");
  return 0;
}

// Implementation of the "getLatestBlockhash" methods
// curl http://localhost:8123 -X POST -H "Content-Type: application/json" -d ' {"jsonrpc":"2.0","id":1, "method":"getLatestBlockhash"} '

static int
method_getLatestBlockhash(struct fd_web_replier* replier, struct json_values* values, fd_rpc_ctx_t * ctx) {
  (void) values;
  (void)ctx;
  fd_web_replier_error(replier, "getLatestBlockhash is not implemented");
  return 0;
  /*
    fd_textstream_t * ts = fd_web_replier_textstream(replier);
    fd_exec_slot_ctx_t * slot_ctx = get_slot_ctx(ctx);
    fd_textstream_sprintf(ts, "{\"jsonrpc\":\"2.0\",\"result\":{\"context\":{\"apiVersion\":\"" API_VERSION "\",\"slot\":%lu},\"value\":{\"blockhash\":\"",
    slot_ctx->slot_bank.slot);
    fd_textstream_encode_base58(ts, slot_ctx->slot_bank.poh.uc, sizeof(fd_pubkey_t));
    fd_textstream_sprintf(ts, "\",\"lastValidBlockHeight\":%lu}},\"id\":%lu}" CRLF,
    slot_ctx->slot_bank.block_height,
    ctx->call_id);
    fd_web_replier_done(replier);
    return 0;
  */
}

// Implementation of the "getLeaderSchedule" methods
// TODO
static int
method_getLeaderSchedule(struct fd_web_replier* replier, struct json_values* values, fd_rpc_ctx_t * ctx) {
  (void)values;
  (void)ctx;
  fd_web_replier_error(replier, "getLeaderSchedule is not implemented");
  return 0;
}

// Implementation of the "getMaxRetransmitSlot" methods
static int
method_getMaxRetransmitSlot(struct fd_web_replier* replier, struct json_values* values, fd_rpc_ctx_t * ctx) {
  (void)values;
  (void)ctx;
  fd_web_replier_error(replier, "getMaxRetransmitSlot is not implemented");
  return 0;
}

// Implementation of the "getMaxShredInsertSlot" methods
static int
method_getMaxShredInsertSlot(struct fd_web_replier* replier, struct json_values* values, fd_rpc_ctx_t * ctx) {
  (void)values;
  (void)ctx;
  fd_web_replier_error(replier, "getMaxShredInsertSlot is not implemented");
  return 0;
}

// Implementation of the "getMinimumBalanceForRentExemption" methods
// curl http://localhost:8123 -X POST -H "Content-Type: application/json" -d ' {"jsonrpc": "2.0", "id": 1, "method": "getMinimumBalanceForRentExemption", "params": [50]} '

static int
method_getMinimumBalanceForRentExemption(struct fd_web_replier* replier, struct json_values* values, fd_rpc_ctx_t * ctx) {
  FD_METHOD_SCRATCH_BEGIN( 1<<29 ) {
    static const uint PATH_SIZE[3] = {
      (JSON_TOKEN_LBRACE<<16) | KEYW_JSON_PARAMS,
      (JSON_TOKEN_LBRACKET<<16) | 0,
      (JSON_TOKEN_INTEGER<<16)
    };
    ulong size_sz = 0;
    const void* size = json_get_value(values, PATH_SIZE, 3, &size_sz);
    ulong sizen = (size == NULL ? 0UL : (ulong)(*(long*)size));
    fd_epoch_bank_t * epoch_bank = read_epoch_bank(ctx, fd_scratch_virtual());
    ulong min_balance = fd_rent_exempt_minimum_balance2(&epoch_bank->rent, sizen);

    fd_textstream_t * ts = fd_web_replier_textstream(replier);
    fd_textstream_sprintf(ts, "{\"jsonrpc\":\"2.0\",\"result\":%lu,\"id\":%lu}" CRLF,
                          min_balance, ctx->call_id);
    fd_web_replier_done(replier);
  } FD_METHOD_SCRATCH_END;
  return 0;
}

// Implementation of the "getMultipleAccounts" method
// curl http://localhost:8123 -X POST -H "Content-Type: application/json" -d ' {"jsonrpc": "2.0", "id": 1, "method": "getMultipleAccounts", "params": [["Cwg1f6m4m3DGwMEbmsbAfDtUToUf5jRdKrJSGD7GfZCB", "Cwg1f6m4m3DGwMEbmsbAfDtUToUf5jRdKrJSGD7GfZCB", "7935owQYeYk1H6HjzKRYnT1aZpf1uXcpZNYjgTZ8q7VR"], {"encoding": "base64"}]} '

static int
method_getMultipleAccounts(struct fd_web_replier* replier, struct json_values* values, fd_rpc_ctx_t * ctx) {
  FD_METHOD_SCRATCH_BEGIN( 11<<20 ) {
    static const uint ENC_PATH[4] = {
      (JSON_TOKEN_LBRACE<<16) | KEYW_JSON_PARAMS,
      (JSON_TOKEN_LBRACKET<<16) | 1,
      (JSON_TOKEN_LBRACE<<16) | KEYW_JSON_ENCODING,
      (JSON_TOKEN_STRING<<16)
    };
    ulong enc_str_sz = 0;
    const void* enc_str = json_get_value(values, ENC_PATH, 4, &enc_str_sz);
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

    fd_textstream_t * ts = fd_web_replier_textstream(replier);
    fd_textstream_sprintf(ts, "{\"jsonrpc\":\"2.0\",\"result\":{\"context\":{\"apiVersion\":\"" API_VERSION "\",\"slot\":%lu},\"value\":[",
                          ctx->blockstore->smr);

    // Iterate through account ids
    for ( ulong i = 0; ; ++i ) {
      // Path to argument
      uint path[4];
      path[0] = (JSON_TOKEN_LBRACE<<16) | KEYW_JSON_PARAMS;
      path[1] = (JSON_TOKEN_LBRACKET<<16) | 0;
      path[2] = (uint) ((JSON_TOKEN_LBRACKET<<16) | i);
      path[3] = (JSON_TOKEN_STRING<<16);
      ulong arg_sz = 0;
      const void* arg = json_get_value(values, path, 4, &arg_sz);
      if (arg == NULL)
        // End of list
        break;

      if (i > 0)
        fd_textstream_append(ts, ",", 1);

      fd_pubkey_t acct;
      fd_base58_decode_32((const char *)arg, acct.uc);
      fd_scratch_push();
      ulong val_sz;
      void * val = read_account(ctx, &acct, fd_scratch_virtual(), &val_sz);
      if (val == NULL) {
        fd_textstream_sprintf(ts, "null");
        continue;
      }

      fd_textstream_sprintf(ts, "{\"data\":[\"");

      fd_account_meta_t * metadata = (fd_account_meta_t *)val;
      if (val_sz < metadata->hlen) {
        fd_web_replier_error(replier, "failed to load account data for %s", (const char*)arg);
        return 0;
      }
      val = (char*)val + metadata->hlen;
      val_sz = val_sz - metadata->hlen;
      if (val_sz > metadata->dlen)
        val_sz = metadata->dlen;

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
      fd_textstream_sprintf(ts, "\",\"%s\"],\"executable\":%s,\"lamports\":%lu,\"owner\":\"%s\",\"rentEpoch\":%lu,\"space\":%lu}",
                            (const char*)enc_str,
                            (metadata->info.executable ? "true" : "false"),
                            metadata->info.lamports,
                            owner,
                            metadata->info.rent_epoch,
                            val_sz);

      fd_scratch_pop();
    }

    fd_textstream_sprintf(ts, "]},\"id\":%lu}" CRLF, ctx->call_id);
    fd_web_replier_done(replier);
  } FD_METHOD_SCRATCH_END;
  return 0;
}

// Implementation of the "getProgramAccounts" methods
static int
method_getProgramAccounts(struct fd_web_replier* replier, struct json_values* values, fd_rpc_ctx_t * ctx) {
  (void)values;
  (void)ctx;
  fd_web_replier_error(replier, "getProgramAccounts is not implemented");
  return 0;
}

// Implementation of the "getRecentBlockhash" methods
static int
method_getRecentBlockhash(struct fd_web_replier* replier, struct json_values* values, fd_rpc_ctx_t * ctx) {
  (void)values;
  (void)ctx;
  fd_web_replier_error(replier, "getRecentBlockhash is not implemented");
  return 0;
}

// Implementation of the "getRecentPerformanceSamples" methods
static int
method_getRecentPerformanceSamples(struct fd_web_replier* replier, struct json_values* values, fd_rpc_ctx_t * ctx) {
  (void)values;
  (void)ctx;
  fd_web_replier_error(replier, "getRecentPerformanceSamples is not implemented");
  return 0;
}

// Implementation of the "getRecentPrioritizationFees" methods
static int
method_getRecentPrioritizationFees(struct fd_web_replier* replier, struct json_values* values, fd_rpc_ctx_t * ctx) {
  (void)values;
  (void)ctx;
  fd_web_replier_error(replier, "getRecentPrioritizationFees is not implemented");
  return 0;
}

// Implementation of the "getSignaturesForAddress" methods
static int
method_getSignaturesForAddress(struct fd_web_replier* replier, struct json_values* values, fd_rpc_ctx_t * ctx) {
  (void)values;
  (void)ctx;
  fd_web_replier_error(replier, "getSignaturesForAddress is not implemented");
  return 0;
}

// Implementation of the "getSignatureStatuses" methods
// curl http://localhost:8123 -X POST -H "Content-Type: application/json" -d ' {"jsonrpc": "2.0", "id": 1, "method": "getSignatureStatuses", "params": [["4qj8WecUytFE96SFhdiTkc3v2AYLY7795sbSQTnYG7cPL9s6xKNHNyi3wraQc83PsNSgV8yedWbfGa4vRXfzBDzB"], {"searchTransactionHistory": true}]} '

static int
method_getSignatureStatuses(struct fd_web_replier* replier, struct json_values* values, fd_rpc_ctx_t * ctx) {
  fd_textstream_t * ts = fd_web_replier_textstream(replier);
  fd_textstream_sprintf(ts, "{\"jsonrpc\":\"2.0\",\"result\":{\"context\":{\"apiVersion\":\"" API_VERSION "\",\"slot\":%lu},\"value\":[",
                        ctx->blockstore->smr);

  // Iterate through account ids
  fd_blockstore_start_read( ctx->blockstore );
  for ( ulong i = 0; ; ++i ) {
    // Path to argument
    uint path[4];
    path[0] = (JSON_TOKEN_LBRACE<<16) | KEYW_JSON_PARAMS;
    path[1] = (JSON_TOKEN_LBRACKET<<16) | 0;
    path[2] = (uint) ((JSON_TOKEN_LBRACKET<<16) | i);
    path[3] = (JSON_TOKEN_STRING<<16);
    ulong sig_sz = 0;
    const void* sig = json_get_value(values, path, 4, &sig_sz);
    if (sig == NULL)
      // End of list
      break;

    if (i > 0)
      fd_textstream_append(ts, ",", 1);

    uchar key[FD_ED25519_SIG_SZ];
    if ( fd_base58_decode_64( sig, key ) == NULL ) {
      fd_textstream_sprintf(ts, "null");
      continue;
    }
    fd_blockstore_txn_map_t * elem = fd_blockstore_txn_query( ctx->blockstore, key );
    if ( FD_UNLIKELY( NULL == elem ) ) {
      fd_textstream_sprintf(ts, "null");
      continue;
    }

    // TODO other fields
    fd_textstream_sprintf(ts, "{\"slot\":%lu,\"confirmations\":null,\"err\":null,\"confirmationStatus\":\"finalized\"}",
                          elem->slot);
  }
  fd_blockstore_end_read( ctx->blockstore );

  fd_textstream_sprintf(ts, "]},\"id\":%lu}" CRLF, ctx->call_id);
  fd_web_replier_done(replier);
  return 0;
}

// Implementation of the "getSlot" method
// curl http://localhost:8123 -X POST -H "Content-Type: application/json" -d ' {"jsonrpc":"2.0","id":1, "method":"getSlot"} '

static int
method_getSlot(struct fd_web_replier* replier, struct json_values* values, fd_rpc_ctx_t * ctx) {
  (void) values;
  fd_textstream_t * ts = fd_web_replier_textstream(replier);
  fd_textstream_sprintf(ts, "{\"jsonrpc\":\"2.0\",\"result\":%lu,\"id\":%lu}" CRLF,
                        ctx->blockstore->smr, ctx->call_id);
  fd_web_replier_done(replier);
  return 0;
}

// Implementation of the "getSlotLeader" methods
// curl http://localhost:8123 -X POST -H "Content-Type: application/json" -d ' {"jsonrpc":"2.0","id":1, "method":"getSlotLeader"} '

static int
method_getSlotLeader(struct fd_web_replier* replier, struct json_values* values, fd_rpc_ctx_t * ctx) {
  (void)values;
  (void)ctx;
  fd_web_replier_error(replier, "getSlotLeader is not implemented");
  /*
    fd_textstream_t * ts = fd_web_replier_textstream(replier);
    fd_textstream_sprintf(ts, "{\"jsonrpc\":\"2.0\",\"result\":\"");
    fd_pubkey_t const * leader = fd_epoch_leaders_get(fd_exec_epoch_ctx_leaders( ctx->replay->epoch_ctx ), get_slot_ctx(ctx)->slot_bank.slot);
    fd_textstream_encode_base58(ts, leader->uc, sizeof(fd_pubkey_t));
    fd_textstream_sprintf(ts, "\",\"id\":%lu}" CRLF, ctx->call_id);
    fd_web_replier_done(replier);
  */
  return 0;
}

// Implementation of the "getSlotLeaders" methods
static int
method_getSlotLeaders(struct fd_web_replier* replier, struct json_values* values, fd_rpc_ctx_t * ctx) {
  (void)values;
  (void)ctx;
  fd_web_replier_error(replier, "getSlotLeaders is not implemented");
  return 0;
}

// Implementation of the "getSnapshotSlot" methods
static int
method_getSnapshotSlot(struct fd_web_replier* replier, struct json_values* values, fd_rpc_ctx_t * ctx) {
  (void)values;
  (void)ctx;
  fd_web_replier_error(replier, "getSnapshotSlot is not implemented");
  return 0;
}

// Implementation of the "getStakeActivation" methods
static int
method_getStakeActivation(struct fd_web_replier* replier, struct json_values* values, fd_rpc_ctx_t * ctx) {
  (void)values;
  (void)ctx;
  fd_web_replier_error(replier, "getStakeActivation is not implemented");
  return 0;
}

// Implementation of the "getStakeMinimumDelegation" methods
static int
method_getStakeMinimumDelegation(struct fd_web_replier* replier, struct json_values* values, fd_rpc_ctx_t * ctx) {
  (void)values;
  (void)ctx;
  fd_web_replier_error(replier, "getStakeMinimumDelegation is not implemented");
  return 0;
}

// Implementation of the "getSupply" methods
// TODO
static int
method_getSupply(struct fd_web_replier* replier, struct json_values* values, fd_rpc_ctx_t * ctx) {
  (void)values;
  (void)ctx;
  fd_web_replier_error(replier, "getSupply is not implemented");
  return 0;
}

// Implementation of the "getTokenAccountBalance" methods
static int
method_getTokenAccountBalance(struct fd_web_replier* replier, struct json_values* values, fd_rpc_ctx_t * ctx) {
  (void)values;
  (void)ctx;
  fd_web_replier_error(replier, "getTokenAccountBalance is not implemented");
  return 0;
}

// Implementation of the "getTokenAccountsByDelegate" methods
static int
method_getTokenAccountsByDelegate(struct fd_web_replier* replier, struct json_values* values, fd_rpc_ctx_t * ctx) {
  (void)values;
  (void)ctx;
  fd_web_replier_error(replier, "getTokenAccountsByDelegate is not implemented");
  return 0;
}

// Implementation of the "getTokenAccountsByOwner" methods
static int
method_getTokenAccountsByOwner(struct fd_web_replier* replier, struct json_values* values, fd_rpc_ctx_t * ctx) {
  (void)values;
  (void)ctx;
  fd_web_replier_error(replier, "getTokenAccountsByOwner is not implemented");
  return 0;
}

// Implementation of the "getTokenLargestAccounts" methods
static int
method_getTokenLargestAccounts(struct fd_web_replier* replier, struct json_values* values, fd_rpc_ctx_t * ctx) {
  (void)values;
  (void)ctx;
  fd_web_replier_error(replier, "getTokenLargestAccounts is not implemented");
  return 0;
}

// Implementation of the "getTokenSupply" methods
static int
method_getTokenSupply(struct fd_web_replier* replier, struct json_values* values, fd_rpc_ctx_t * ctx) {
  (void)values;
  (void)ctx;
  fd_web_replier_error(replier, "getTokenSupply is not implemented");
  return 0;
}

// Implementation of the "getTransaction" method
// curl http://localhost:8123 -X POST -H "Content-Type: application/json" -d ' {"jsonrpc": "2.0", "id": 1, "method": "getTransaction", "params": ["4qj8WecUytFE96SFhdiTkc3v2AYLY7795sbSQTnYG7cPL9s6xKNHNyi3wraQc83PsNSgV8yedWbfGa4vRXfzBDzB", "json"]} '

static int
method_getTransaction(struct fd_web_replier* replier, struct json_values* values, fd_rpc_ctx_t * ctx) {
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

  uchar key[FD_ED25519_SIG_SZ];
  if ( fd_base58_decode_64( sig, key) == NULL ) {
    fd_textstream_sprintf(ts, "{\"jsonrpc\":\"2.0\",\"result\":null,\"id\":%lu}" CRLF, ctx->call_id);
    fd_web_replier_done(replier);
    return 0;
  }
  fd_blockstore_start_read( ctx->blockstore );
  fd_blockstore_txn_map_t * elem = fd_blockstore_txn_query( ctx->blockstore, key );
  if ( FD_UNLIKELY( NULL == elem ) ) {
    fd_textstream_sprintf(ts, "{\"jsonrpc\":\"2.0\",\"result\":null,\"id\":%lu}" CRLF, ctx->call_id);
    fd_web_replier_done(replier);
    fd_blockstore_end_read( ctx->blockstore );
    return 0;
  }

  fd_block_t * blk = fd_blockstore_block_query( ctx->blockstore, elem->slot );
  if (blk == NULL) {
    fd_web_replier_error(replier, "failed to load block for slot %lu", elem->slot);
    fd_blockstore_end_read( ctx->blockstore );
    return 0;
  }

  uchar txn_out[FD_TXN_MAX_SZ];
  ulong pay_sz = 0;
  const uchar* raw = (const uchar *)fd_blockstore_block_data_laddr(ctx->blockstore, blk) + elem->offset;
  ulong txn_sz = fd_txn_parse_core(raw, elem->sz, txn_out, NULL, &pay_sz, 0);
  if ( txn_sz == 0 || txn_sz > FD_TXN_MAX_SZ )
    FD_LOG_ERR(("failed to parse transaction"));

  ulong meta_gaddr = elem->meta_gaddr;
  ulong meta_sz = elem->meta_sz;
  void * meta = (meta_gaddr ? fd_wksp_laddr_fast( fd_blockstore_wksp( ctx->blockstore ), meta_gaddr ) : NULL);

  fd_textstream_sprintf(ts, "{\"jsonrpc\":\"2.0\",\"result\":{\"context\":{\"apiVersion\":\"" API_VERSION "\",\"slot\":%lu},\"blockTime\":%ld,\"slot\":%lu,",
                        ctx->blockstore->smr, blk->ts/(long)1e9, elem->slot);
  fd_txn_to_json( ts, (fd_txn_t *)txn_out, raw, meta, meta_sz, enc, 0, FD_BLOCK_DETAIL_FULL, 0 );
  fd_textstream_sprintf(ts, "},\"id\":%lu}" CRLF, ctx->call_id);

  fd_web_replier_done(replier);
  fd_blockstore_end_read( ctx->blockstore );
  return 0;
}

// Implementation of the "getTransactionCount" methods
static int
method_getTransactionCount(struct fd_web_replier* replier, struct json_values* values, fd_rpc_ctx_t * ctx) {
  (void)values;
  (void)ctx;
  fd_web_replier_error(replier, "getTransactionCount is not implemented");
  return 0;
}

// Implementation of the "getVersion" method
// curl http://localhost:8123 -X POST -H "Content-Type: application/json" -d ' {"jsonrpc":"2.0","id":1, "method":"getVersion"} '

static int
method_getVersion(struct fd_web_replier* replier, struct json_values* values, fd_rpc_ctx_t * ctx) {
  (void) values;
  fd_textstream_t * ts = fd_web_replier_textstream(replier);
  /* TODO Where does feature-set come from? */
  fd_textstream_sprintf(ts, "{\"jsonrpc\":\"2.0\",\"result\":{\"feature-set\":666,\"solana-core\":\"" API_VERSION "\"},\"id\":%lu}" CRLF,
                        ctx->call_id);
  fd_web_replier_done(replier);
  return 0;
}

// Implementation of the "getVoteAccounts" methods
static int
method_getVoteAccounts(struct fd_web_replier* replier, struct json_values* values, fd_rpc_ctx_t * ctx) {
  (void)values;
  (void)ctx;
  fd_web_replier_error(replier, "getVoteAccounts is not implemented");
  return 0;
}

// Implementation of the "isBlockhashValid" methods
static int
method_isBlockhashValid(struct fd_web_replier* replier, struct json_values* values, fd_rpc_ctx_t * ctx) {
  (void)values;
  (void)ctx;
  fd_web_replier_error(replier, "isBlockhashValid is not implemented");
  return 0;
}

// Implementation of the "minimumLedgerSlot" methods
static int
method_minimumLedgerSlot(struct fd_web_replier* replier, struct json_values* values, fd_rpc_ctx_t * ctx) {
  (void)values;
  (void)ctx;
  fd_web_replier_error(replier, "minimumLedgerSlot is not implemented");
  return 0;
}

// Implementation of the "requestAirdrop" methods
static int
method_requestAirdrop(struct fd_web_replier* replier, struct json_values* values, fd_rpc_ctx_t * ctx) {
  (void)values;
  (void)ctx;
  fd_web_replier_error(replier, "requestAirdrop is not implemented");
  return 0;
}

// Implementation of the "sendTransaction" methods
static int
method_sendTransaction(struct fd_web_replier* replier, struct json_values* values, fd_rpc_ctx_t * ctx) {
  (void)values;
  (void)ctx;
  fd_web_replier_error(replier, "sendTransaction is not implemented");
  return 0;
}

// Implementation of the "simulateTransaction" methods
static int
method_simulateTransaction(struct fd_web_replier* replier, struct json_values* values, fd_rpc_ctx_t * ctx) {
  (void)values;
  (void)ctx;
  fd_web_replier_error(replier, "simulateTransaction is not implemented");
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
  case KEYW_RPCMETHOD_GETBLOCKCOMMITMENT:
    if (!method_getBlockCommitment(replier, values, &ctx))
      return;
    break;
  case KEYW_RPCMETHOD_GETBLOCKHEIGHT:
    if (!method_getBlockHeight(replier, values, &ctx))
      return;
    break;
  case KEYW_RPCMETHOD_GETBLOCKPRODUCTION:
    if (!method_getBlockProduction(replier, values, &ctx))
      return;
    break;
  case KEYW_RPCMETHOD_GETBLOCKS:
    if (!method_getBlocks(replier, values, &ctx))
      return;
    break;
  case KEYW_RPCMETHOD_GETBLOCKSWITHLIMIT:
    if (!method_getBlocksWithLimit(replier, values, &ctx))
      return;
    break;
  case KEYW_RPCMETHOD_GETBLOCKTIME:
    if (!method_getBlockTime(replier, values, &ctx))
      return;
    break;
  case KEYW_RPCMETHOD_GETCLUSTERNODES:
    if (!method_getClusterNodes(replier, values, &ctx))
      return;
    break;
  case KEYW_RPCMETHOD_GETCONFIRMEDBLOCK:
    if (!method_getConfirmedBlock(replier, values, &ctx))
      return;
    break;
  case KEYW_RPCMETHOD_GETCONFIRMEDBLOCKS:
    if (!method_getConfirmedBlocks(replier, values, &ctx))
      return;
    break;
  case KEYW_RPCMETHOD_GETCONFIRMEDBLOCKSWITHLIMIT:
    if (!method_getConfirmedBlocksWithLimit(replier, values, &ctx))
      return;
    break;
  case KEYW_RPCMETHOD_GETCONFIRMEDSIGNATURESFORADDRESS2:
    if (!method_getConfirmedSignaturesForAddress2(replier, values, &ctx))
      return;
    break;
  case KEYW_RPCMETHOD_GETCONFIRMEDTRANSACTION:
    if (!method_getConfirmedTransaction(replier, values, &ctx))
      return;
    break;
  case KEYW_RPCMETHOD_GETEPOCHINFO:
    if (!method_getEpochInfo(replier, values, &ctx))
      return;
    break;
  case KEYW_RPCMETHOD_GETEPOCHSCHEDULE:
    if (!method_getEpochSchedule(replier, values, &ctx))
      return;
    break;
  case KEYW_RPCMETHOD_GETFEECALCULATORFORBLOCKHASH:
    if (!method_getFeeCalculatorForBlockhash(replier, values, &ctx))
      return;
    break;
  case KEYW_RPCMETHOD_GETFEEFORMESSAGE:
    if (!method_getFeeForMessage(replier, values, &ctx))
      return;
    break;
  case KEYW_RPCMETHOD_GETFEERATEGOVERNOR:
    if (!method_getFeeRateGovernor(replier, values, &ctx))
      return;
    break;
  case KEYW_RPCMETHOD_GETFEES:
    if (!method_getFees(replier, values, &ctx))
      return;
    break;
  case KEYW_RPCMETHOD_GETFIRSTAVAILABLEBLOCK:
    if (!method_getFirstAvailableBlock(replier, values, &ctx))
      return;
    break;
  case KEYW_RPCMETHOD_GETGENESISHASH:
    if (!method_getGenesisHash(replier, values, &ctx))
      return;
    break;
  case KEYW_RPCMETHOD_GETHEALTH:
    if (!method_getHealth(replier, values, &ctx))
      return;
    break;
  case KEYW_RPCMETHOD_GETHIGHESTSNAPSHOTSLOT:
    if (!method_getHighestSnapshotSlot(replier, values, &ctx))
      return;
    break;
  case KEYW_RPCMETHOD_GETIDENTITY:
    if (!method_getIdentity(replier, values, &ctx))
      return;
    break;
  case KEYW_RPCMETHOD_GETINFLATIONGOVERNOR:
    if (!method_getInflationGovernor(replier, values, &ctx))
      return;
    break;
  case KEYW_RPCMETHOD_GETINFLATIONRATE:
    if (!method_getInflationRate(replier, values, &ctx))
      return;
    break;
  case KEYW_RPCMETHOD_GETINFLATIONREWARD:
    if (!method_getInflationReward(replier, values, &ctx))
      return;
    break;
  case KEYW_RPCMETHOD_GETLARGESTACCOUNTS:
    if (!method_getLargestAccounts(replier, values, &ctx))
      return;
    break;
  case KEYW_RPCMETHOD_GETLATESTBLOCKHASH:
    if (!method_getLatestBlockhash(replier, values, &ctx))
      return;
    break;
  case KEYW_RPCMETHOD_GETLEADERSCHEDULE:
    if (!method_getLeaderSchedule(replier, values, &ctx))
      return;
    break;
  case KEYW_RPCMETHOD_GETMAXRETRANSMITSLOT:
    if (!method_getMaxRetransmitSlot(replier, values, &ctx))
      return;
    break;
  case KEYW_RPCMETHOD_GETMAXSHREDINSERTSLOT:
    if (!method_getMaxShredInsertSlot(replier, values, &ctx))
      return;
    break;
  case KEYW_RPCMETHOD_GETMINIMUMBALANCEFORRENTEXEMPTION:
    if (!method_getMinimumBalanceForRentExemption(replier, values, &ctx))
      return;
    break;
  case KEYW_RPCMETHOD_GETMULTIPLEACCOUNTS:
    if (!method_getMultipleAccounts(replier, values, &ctx))
      return;
    break;
  case KEYW_RPCMETHOD_GETPROGRAMACCOUNTS:
    if (!method_getProgramAccounts(replier, values, &ctx))
      return;
    break;
  case KEYW_RPCMETHOD_GETRECENTBLOCKHASH:
    if (!method_getRecentBlockhash(replier, values, &ctx))
      return;
    break;
  case KEYW_RPCMETHOD_GETRECENTPERFORMANCESAMPLES:
    if (!method_getRecentPerformanceSamples(replier, values, &ctx))
      return;
    break;
  case KEYW_RPCMETHOD_GETRECENTPRIORITIZATIONFEES:
    if (!method_getRecentPrioritizationFees(replier, values, &ctx))
      return;
    break;
  case KEYW_RPCMETHOD_GETSIGNATURESFORADDRESS:
    if (!method_getSignaturesForAddress(replier, values, &ctx))
      return;
    break;
  case KEYW_RPCMETHOD_GETSIGNATURESTATUSES:
    if (!method_getSignatureStatuses(replier, values, &ctx))
      return;
    break;
  case KEYW_RPCMETHOD_GETSLOT:
    if (!method_getSlot(replier, values, &ctx))
      return;
    break;
  case KEYW_RPCMETHOD_GETSLOTLEADER:
    if (!method_getSlotLeader(replier, values, &ctx))
      return;
    break;
  case KEYW_RPCMETHOD_GETSLOTLEADERS:
    if (!method_getSlotLeaders(replier, values, &ctx))
      return;
    break;
  case KEYW_RPCMETHOD_GETSNAPSHOTSLOT:
    if (!method_getSnapshotSlot(replier, values, &ctx))
      return;
    break;
  case KEYW_RPCMETHOD_GETSTAKEACTIVATION:
    if (!method_getStakeActivation(replier, values, &ctx))
      return;
    break;
  case KEYW_RPCMETHOD_GETSTAKEMINIMUMDELEGATION:
    if (!method_getStakeMinimumDelegation(replier, values, &ctx))
      return;
    break;
  case KEYW_RPCMETHOD_GETSUPPLY:
    if (!method_getSupply(replier, values, &ctx))
      return;
    break;
  case KEYW_RPCMETHOD_GETTOKENACCOUNTBALANCE:
    if (!method_getTokenAccountBalance(replier, values, &ctx))
      return;
    break;
  case KEYW_RPCMETHOD_GETTOKENACCOUNTSBYDELEGATE:
    if (!method_getTokenAccountsByDelegate(replier, values, &ctx))
      return;
    break;
  case KEYW_RPCMETHOD_GETTOKENACCOUNTSBYOWNER:
    if (!method_getTokenAccountsByOwner(replier, values, &ctx))
      return;
    break;
  case KEYW_RPCMETHOD_GETTOKENLARGESTACCOUNTS:
    if (!method_getTokenLargestAccounts(replier, values, &ctx))
      return;
    break;
  case KEYW_RPCMETHOD_GETTOKENSUPPLY:
    if (!method_getTokenSupply(replier, values, &ctx))
      return;
    break;
  case KEYW_RPCMETHOD_GETTRANSACTION:
    if (!method_getTransaction(replier, values, &ctx))
      return;
    break;
  case KEYW_RPCMETHOD_GETTRANSACTIONCOUNT:
    if (!method_getTransactionCount(replier, values, &ctx))
      return;
    break;
  case KEYW_RPCMETHOD_GETVERSION:
    if (!method_getVersion(replier, values, &ctx))
      return;
    break;
  case KEYW_RPCMETHOD_GETVOTEACCOUNTS:
    if (!method_getVoteAccounts(replier, values, &ctx))
      return;
    break;
  case KEYW_RPCMETHOD_ISBLOCKHASHVALID:
    if (!method_isBlockhashValid(replier, values, &ctx))
      return;
    break;
  case KEYW_RPCMETHOD_MINIMUMLEDGERSLOT:
    if (!method_minimumLedgerSlot(replier, values, &ctx))
      return;
    break;
  case KEYW_RPCMETHOD_REQUESTAIRDROP:
    if (!method_requestAirdrop(replier, values, &ctx))
      return;
    break;
  case KEYW_RPCMETHOD_SENDTRANSACTION:
    if (!method_sendTransaction(replier, values, &ctx))
      return;
    break;
  case KEYW_RPCMETHOD_SIMULATETRANSACTION:
    if (!method_simulateTransaction(replier, values, &ctx))
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

void
fd_rpc_start_service(fd_rpcserver_args_t * args, fd_rpc_ctx_t ** ctx_p) {
  fd_rpc_ctx_t * ctx = (fd_rpc_ctx_t *)malloc(sizeof(fd_rpc_ctx_t));
  *ctx_p = ctx;
  ctx->funk = args->funk;
  ctx->blockstore = args->blockstore;
  FD_LOG_NOTICE(( "starting web server with %lu threads on port %u", args->num_threads, (uint)args->port ));
  if (fd_webserver_start(args->num_threads, args->port, &ctx->ws, ctx))
    FD_LOG_ERR(("fd_webserver_start failed"));
}

void
fd_rpc_stop_service(fd_rpc_ctx_t * ctx) {
  FD_LOG_NOTICE(( "stopping web server" ));
  if (fd_webserver_stop(&ctx->ws))
    FD_LOG_ERR(("fd_webserver_stop failed"));
  free(ctx);
}
