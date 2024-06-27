#include "fd_rpc_service.h"
#include <microhttpd.h>
#include "fd_methods.h"
#include "fd_webserver.h"
#include "../../flamenco/types/fd_types.h"
#include "../../flamenco/types/fd_solana_block.pb.h"
#include "../../flamenco/runtime/fd_runtime.h"
#include "../../flamenco/runtime/fd_acc_mgr.h"
#include "../../flamenco/runtime/sysvar/fd_sysvar_rent.h"
#include "../../flamenco/runtime/sysvar/fd_sysvar_epoch_schedule.h"
#include "../../ballet/base58/fd_base58.h"
#include "keywords.h"

#define API_VERSION "1.17.6"

#define CRLF "\r\n"
#define MATCH_STRING(_text_,_text_sz_,_str_) (_text_sz_ == sizeof(_str_)-1 && memcmp(_text_, _str_, sizeof(_str_)-1) == 0)

struct fd_ws_subscription {
  fd_websocket_ctx_t * socket;
  long meth_id;
  long call_id;
  ulong subsc_id;
  union {
    struct {
      fd_pubkey_t acct;
      fd_rpc_encoding_t enc;
      long off;
      long len;
    } acct_subscribe;
  };
};

#define FD_WS_MAX_SUBS 1024

struct fd_rpc_global_ctx {
  fd_readwrite_lock_t lock;
  fd_webserver_t ws;
  fd_funk_t * funk;
  fd_blockstore_t * blockstore;
  struct fd_ws_subscription sub_list[FD_WS_MAX_SUBS];
  ulong sub_cnt;
  ulong last_subsc_id;
  fd_epoch_bank_t * epoch_bank;
  ulong epoch_bank_epoch;
};
typedef struct fd_rpc_global_ctx fd_rpc_global_ctx_t;

struct fd_rpc_ctx {
  long call_id;
  fd_rpc_global_ctx_t * global;
};

static void *
read_account( fd_rpc_ctx_t * ctx, fd_pubkey_t * acct, fd_valloc_t valloc, ulong * result_len ) {
  fd_funk_rec_key_t recid = fd_acc_funk_key(acct);
  fd_funk_t * funk = ctx->global->funk;
  return fd_funk_rec_query_safe(funk, &recid, valloc, result_len);
}

static void *
read_account_with_xid( fd_rpc_ctx_t * ctx, fd_pubkey_t * acct, fd_funk_txn_xid_t * xid, fd_valloc_t valloc, ulong * result_len ) {
  fd_funk_rec_key_t recid = fd_acc_funk_key(acct);
  fd_funk_t * funk = ctx->global->funk;
  return fd_funk_rec_query_xid_safe(funk, &recid, xid, valloc, result_len);
}

/* LEAVES THE LOCK IN READ MODE */
fd_epoch_bank_t *
read_epoch_bank( fd_rpc_ctx_t * ctx, fd_valloc_t valloc, ulong * smr ) {
  fd_rpc_global_ctx_t * glob = ctx->global;

  for(;;) {
    fd_readwrite_start_read( &glob->lock );
    *smr = glob->blockstore->smr;

    if( glob->epoch_bank != NULL &&
        glob->epoch_bank_epoch == fd_slot_to_epoch(&glob->epoch_bank->epoch_schedule, *smr, NULL) ) {
      /* Leave lock held */
      return glob->epoch_bank;
    }

    fd_readwrite_end_read( &glob->lock );
    fd_readwrite_start_write( &glob->lock );

    if( glob->epoch_bank != NULL ) {
      fd_bincode_destroy_ctx_t binctx;
      binctx.valloc = fd_libc_alloc_virtual();
      fd_epoch_bank_destroy( glob->epoch_bank, &binctx );
      free( glob->epoch_bank );
      glob->epoch_bank = NULL;
    }

    fd_funk_rec_key_t recid = fd_runtime_epoch_bank_key();
    ulong vallen;
    fd_funk_t * funk = ctx->global->funk;
    void * val = fd_funk_rec_query_safe(funk, &recid, valloc, &vallen);
    if( val == NULL ) {
      FD_LOG_WARNING(( "failed to decode epoch_bank" ));
      fd_readwrite_end_write( &glob->lock );
      return NULL;
    }
    fd_epoch_bank_t * epoch_bank = malloc( fd_epoch_bank_footprint() );
    fd_epoch_bank_new( epoch_bank );
    fd_bincode_decode_ctx_t binctx;
    binctx.data = val;
    binctx.dataend = (uchar*)val + vallen;
    binctx.valloc  = fd_libc_alloc_virtual();
    if( fd_epoch_bank_decode( epoch_bank, &binctx )!=FD_BINCODE_SUCCESS ) {
      FD_LOG_WARNING(( "failed to decode epoch_bank" ));
      fd_valloc_free( valloc, val );
      free( epoch_bank );
      fd_readwrite_end_write( &glob->lock );
      return NULL;
    }
    fd_valloc_free( valloc, val );

    glob->epoch_bank = epoch_bank;
    glob->epoch_bank_epoch = fd_slot_to_epoch(&epoch_bank->epoch_schedule, *smr, NULL);
    fd_readwrite_end_write( &glob->lock );
  }
}

fd_slot_bank_t *
read_slot_bank( fd_rpc_ctx_t * ctx, fd_valloc_t valloc ) {
  fd_funk_rec_key_t recid = fd_runtime_slot_bank_key();
  ulong vallen;
  fd_funk_t * funk = ctx->global->funk;
  void * val = fd_funk_rec_query_safe(funk, &recid, valloc, &vallen);
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
    fd_blockstore_t * blockstore = ctx->global->blockstore;
    if (val == NULL) {
      fd_textstream_sprintf(ts, "{\"jsonrpc\":\"2.0\",\"result\":{\"context\":{\"apiVersion\":\"" API_VERSION "\",\"slot\":%lu},\"value\":null},\"id\":%lu}" CRLF,
                            blockstore->smr, ctx->call_id);
      fd_web_replier_done(replier);
      return 0;
    }

    static const uint PATH2[4] = {
      (JSON_TOKEN_LBRACE<<16) | KEYW_JSON_PARAMS,
      (JSON_TOKEN_LBRACKET<<16) | 1,
      (JSON_TOKEN_LBRACE<<16) | KEYW_JSON_ENCODING,
      (JSON_TOKEN_STRING<<16)
    };
    ulong enc_str_sz = 0;
    const void* enc_str = json_get_value(values, PATH2, 4, &enc_str_sz);
    fd_rpc_encoding_t enc;
    if (enc_str == NULL || MATCH_STRING(enc_str, enc_str_sz, "base58"))
      enc = FD_ENC_BASE58;
    else if (MATCH_STRING(enc_str, enc_str_sz, "base64"))
      enc = FD_ENC_BASE64;
    else if (MATCH_STRING(enc_str, enc_str_sz, "base64+zstd"))
      enc = FD_ENC_BASE64_ZSTD;
    else if (MATCH_STRING(enc_str, enc_str_sz, "jsonParsed"))
      enc = FD_ENC_JSON;
    else {
      fd_web_replier_error(replier, "invalid data encoding %s", (const char*)enc_str);
      return 0;
    }

    static const uint PATH3[5] = {
      (JSON_TOKEN_LBRACE<<16) | KEYW_JSON_PARAMS,
      (JSON_TOKEN_LBRACKET<<16) | 1,
      (JSON_TOKEN_LBRACE<<16) | KEYW_JSON_DATASLICE,
      (JSON_TOKEN_LBRACE<<16) | KEYW_JSON_LENGTH,
      (JSON_TOKEN_INTEGER<<16)
    };
    static const uint PATH4[5] = {
      (JSON_TOKEN_LBRACE<<16) | KEYW_JSON_PARAMS,
      (JSON_TOKEN_LBRACKET<<16) | 1,
      (JSON_TOKEN_LBRACE<<16) | KEYW_JSON_DATASLICE,
      (JSON_TOKEN_LBRACE<<16) | KEYW_JSON_OFFSET,
      (JSON_TOKEN_INTEGER<<16)
    };
    ulong len_sz = 0;
    const void* len_ptr = json_get_value(values, PATH3, 5, &len_sz);
    ulong off_sz = 0;
    const void* off_ptr = json_get_value(values, PATH4, 5, &off_sz);
    long off = (off_ptr ? *(long *)off_ptr : FD_LONG_UNSET);
    long len = (len_ptr ? *(long *)len_ptr : FD_LONG_UNSET);

    fd_textstream_sprintf(ts, "{\"jsonrpc\":\"2.0\",\"result\":{\"context\":{\"apiVersion\":\"" API_VERSION "\",\"slot\":%lu},\"value\":",
                          blockstore->smr);
    const char * err = fd_account_to_json( ts, acct, enc, val, val_sz, off, len );
    if( err ) {
      fd_web_replier_error(replier, "%s", err);
      return 0;
    }
    fd_textstream_sprintf(ts, "},\"id\":%lu}" CRLF, ctx->call_id);

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
    fd_blockstore_t * blockstore = ctx->global->blockstore;
    fd_textstream_sprintf(ts, "{\"jsonrpc\":\"2.0\",\"result\":{\"context\":{\"apiVersion\":\"" API_VERSION "\",\"slot\":%lu},\"value\":%lu},\"id\":%lu}" CRLF,
                          blockstore->smr, metadata->info.lamports, ctx->call_id);
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
  fd_rpc_encoding_t enc;
  if (enc_str == NULL || MATCH_STRING(enc_str, enc_str_sz, "json"))
    enc = FD_ENC_JSON;
  else if (MATCH_STRING(enc_str, enc_str_sz, "base58"))
    enc = FD_ENC_BASE58;
  else if (MATCH_STRING(enc_str, enc_str_sz, "base64"))
    enc = FD_ENC_BASE64;
  else if (MATCH_STRING(enc_str, enc_str_sz, "jsonParsed"))
    enc = FD_ENC_JSON_PARSED;
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

  fd_block_t blk[1];
  fd_slot_meta_t slot_meta[1];
  ulong blk_sz;
  fd_blockstore_t * blockstore = ctx->global->blockstore;
  uchar * blk_data = fd_blockstore_block_query_volatile( blockstore, slotn, fd_libc_alloc_virtual(), blk, slot_meta, &blk_sz );
  if( blk_data == NULL ) {
    fd_web_replier_error(replier, "failed to display block for slot %lu", slotn);
    return 0;
  }

  fd_textstream_t * ts = fd_web_replier_textstream(replier);
  if (fd_block_to_json(ts,
                       ctx->call_id,
                       blk,
                       blk_data,
                       blk_sz,
                       slot_meta,
                       enc,
                       (maxvers == NULL ? 0 : *(const long*)maxvers),
                       det,
                       (rewards == NULL ? 1 : *(const int*)rewards))) {
    free( blk_data );
    fd_web_replier_error(replier, "failed to display block for slot %lu", slotn);
    return 0;
  }
  free( blk_data );
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
// curl http://localhost:8123 -X POST -H "Content-Type: application/json" -d '{ "jsonrpc":"2.0","id":1, "method":"getBlockHeight" }'
static int
method_getBlockHeight(struct fd_web_replier* replier, struct json_values* values, fd_rpc_ctx_t * ctx) {
  (void) values;
  fd_textstream_t * ts = fd_web_replier_textstream(replier);
  fd_block_t blk[1];
  fd_slot_meta_t slot_meta[1];
  fd_blockstore_t * blockstore = ctx->global->blockstore;
  int ret = fd_blockstore_slot_meta_query_volatile(blockstore, blockstore->smr, blk, slot_meta);
  fd_textstream_sprintf(ts, "{\"jsonrpc\":\"2.0\",\"result\":%lu,\"id\":%lu}" CRLF,
                        (!ret ? blk->height : 0UL), ctx->call_id);
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

  fd_blockstore_t * blockstore = ctx->global->blockstore;
  if (startslotn < blockstore->min)
    startslotn = blockstore->min;
  if (endslotn > blockstore->max)
    endslotn = blockstore->max;

  fd_textstream_t * ts = fd_web_replier_textstream(replier);
  fd_textstream_sprintf(ts, "{\"jsonrpc\":\"2.0\",\"result\":[");
  uint cnt = 0;
  for ( ulong i = startslotn; i <= endslotn && cnt < 500000U; ++i ) {
    fd_block_t blk[1];
    fd_slot_meta_t slot_meta[1];
    int ret = fd_blockstore_slot_meta_query_volatile(blockstore, i, blk, slot_meta);
    if (!ret) {
      fd_textstream_sprintf(ts, "%s%lu", (cnt==0 ? "" : ","), i);
      ++cnt;
    }
  }
  fd_textstream_sprintf(ts, "],\"id\":%lu}" CRLF, ctx->call_id);

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

  fd_blockstore_t * blockstore = ctx->global->blockstore;
  if (startslotn < blockstore->min)
    startslotn = blockstore->min;
  if (limitn > 500000)
    limitn = 500000;

  fd_textstream_t * ts = fd_web_replier_textstream(replier);
  fd_textstream_sprintf(ts, "{\"jsonrpc\":\"2.0\",\"result\":[");
  uint cnt = 0;
  for ( ulong i = startslotn; i <= blockstore->max && cnt < limitn; ++i ) {
    fd_block_t blk[1];
    fd_slot_meta_t slot_meta[1];
    int ret = fd_blockstore_slot_meta_query_volatile(blockstore, i, blk, slot_meta);
    if (!ret) {
      fd_textstream_sprintf(ts, "%s%lu", (cnt==0 ? "" : ","), i);
      ++cnt;
    }
  }
  fd_textstream_sprintf(ts, "],\"id\":%lu}" CRLF, ctx->call_id);

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
  FD_METHOD_SCRATCH_BEGIN( 1<<28 ) { /* read_epoch consumes a ton of scratch space! */
    fd_textstream_t * ts = fd_web_replier_textstream(replier);
    fd_blockstore_t * blockstore = ctx->global->blockstore;
    ulong smr;
    fd_epoch_bank_t * epoch_bank = read_epoch_bank(ctx, fd_scratch_virtual(), &smr);
    fd_slot_bank_t * slot_bank = read_slot_bank(ctx, fd_scratch_virtual());
    ulong slot_idx = 0;
    ulong epoch = fd_slot_to_epoch( &epoch_bank->epoch_schedule, smr, &slot_idx );
    ulong slots_per_epoch = fd_epoch_slot_cnt( &epoch_bank->epoch_schedule, epoch );
    fd_block_t blk[1];
    fd_slot_meta_t slot_meta[1];
    int ret = fd_blockstore_slot_meta_query_volatile(blockstore, smr, blk, slot_meta);
    fd_textstream_sprintf(ts, "{\"jsonrpc\":\"2.0\",\"result\":{\"absoluteSlot\":%lu,\"blockHeight\":%lu,\"epoch\":%lu,\"slotIndex\":%lu,\"slotsInEpoch\":%lu,\"transactionCount\":%lu},\"id\":%lu}" CRLF,
                          smr,
                          (!ret ? blk->height : 0UL),
                          epoch,
                          slot_idx,
                          slots_per_epoch,
                          slot_bank->transaction_count,
                          ctx->call_id);
    fd_web_replier_done(replier);
    fd_readwrite_end_read( &ctx->global->lock );
  } FD_METHOD_SCRATCH_END;
  return 0;
}

// Implementation of the "getEpochSchedule" methods
// curl http://localhost:8123 -X POST -H "Content-Type: application/json" -d ' {"jsonrpc":"2.0","id":1, "method":"getEpochSchedule"} '

static int
method_getEpochSchedule(struct fd_web_replier* replier, struct json_values* values, fd_rpc_ctx_t * ctx) {
  (void)values;
  FD_METHOD_SCRATCH_BEGIN( 1<<28 ) { /* read_epoch consumes a ton of scratch space! */
    fd_textstream_t * ts = fd_web_replier_textstream(replier);
    ulong smr;
    fd_epoch_bank_t * epoch_bank = read_epoch_bank(ctx, fd_scratch_virtual(), &smr);
    fd_textstream_sprintf(ts, "{\"jsonrpc\":\"2.0\",\"result\":{\"firstNormalEpoch\":%lu,\"firstNormalSlot\":%lu,\"leaderScheduleSlotOffset\":%lu,\"slotsPerEpoch\":%lu,\"warmup\":%s},\"id\":%lu}" CRLF,
    epoch_bank->epoch_schedule.first_normal_epoch,
    epoch_bank->epoch_schedule.first_normal_slot,
    epoch_bank->epoch_schedule.leader_schedule_slot_offset,
    epoch_bank->epoch_schedule.slots_per_epoch,
    (epoch_bank->epoch_schedule.warmup ? "true" : "false"),
    ctx->call_id);
    fd_web_replier_done(replier);
    fd_readwrite_end_read( &ctx->global->lock );
  } FD_METHOD_SCRATCH_END;
  return 0;
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
  (void)values;
  FD_METHOD_SCRATCH_BEGIN( 1<<28 ) { /* read_epoch consumes a ton of scratch space! */
    ulong smr;
    fd_epoch_bank_t * epoch_bank = read_epoch_bank(ctx, fd_scratch_virtual(), &smr);
    fd_textstream_t * ts = fd_web_replier_textstream(replier);
    fd_textstream_sprintf(ts, "{\"jsonrpc\":\"2.0\",\"result\":\"");
    fd_textstream_encode_base58(ts, epoch_bank->genesis_hash.uc, sizeof(fd_pubkey_t));
    fd_textstream_sprintf(ts, "\",\"id\":%lu}" CRLF, ctx->call_id);
    fd_web_replier_done(replier);
    fd_readwrite_end_read( &ctx->global->lock );
  } FD_METHOD_SCRATCH_END;
  return 0;
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
  /* FIXME!
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
  /* FIXME!
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
  (void)values;
  FD_METHOD_SCRATCH_BEGIN( 1UL<<26 ) {
    fd_textstream_t * ts = fd_web_replier_textstream(replier);
    fd_slot_bank_t * slot_bank = read_slot_bank(ctx, fd_scratch_virtual());
    fd_textstream_sprintf(ts, "{\"jsonrpc\":\"2.0\",\"result\":{\"context\":{\"apiVersion\":\"" API_VERSION "\",\"slot\":%lu},\"value\":{\"blockhash\":\"",
                          slot_bank->slot);
    fd_textstream_encode_base58(ts, slot_bank->poh.uc, sizeof(fd_pubkey_t));
    fd_textstream_sprintf(ts, "\",\"lastValidBlockHeight\":%lu}},\"id\":%lu}" CRLF,
                          slot_bank->block_height, ctx->call_id);
    fd_web_replier_done(replier);
  } FD_METHOD_SCRATCH_END;
  return 0;
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
  FD_METHOD_SCRATCH_BEGIN( 1<<28 ) { /* read_epoch consumes a ton of scratch space! */
    static const uint PATH_SIZE[3] = {
      (JSON_TOKEN_LBRACE<<16) | KEYW_JSON_PARAMS,
      (JSON_TOKEN_LBRACKET<<16) | 0,
      (JSON_TOKEN_INTEGER<<16)
    };
    ulong size_sz = 0;
    const void* size = json_get_value(values, PATH_SIZE, 3, &size_sz);
    ulong sizen = (size == NULL ? 0UL : (ulong)(*(long*)size));
    ulong smr;
    fd_epoch_bank_t * epoch_bank = read_epoch_bank(ctx, fd_scratch_virtual(), &smr);
    ulong min_balance = fd_rent_exempt_minimum_balance2(&epoch_bank->rent, sizen);

    fd_textstream_t * ts = fd_web_replier_textstream(replier);
    fd_textstream_sprintf(ts, "{\"jsonrpc\":\"2.0\",\"result\":%lu,\"id\":%lu}" CRLF,
                          min_balance, ctx->call_id);
    fd_web_replier_done(replier);
    fd_readwrite_end_read( &ctx->global->lock );
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
    fd_rpc_encoding_t enc;
    if (enc_str == NULL || MATCH_STRING(enc_str, enc_str_sz, "base58"))
      enc = FD_ENC_BASE58;
    else if (MATCH_STRING(enc_str, enc_str_sz, "base64"))
      enc = FD_ENC_BASE64;
    else if (MATCH_STRING(enc_str, enc_str_sz, "base64+zstd"))
      enc = FD_ENC_BASE64_ZSTD;
    else if (MATCH_STRING(enc_str, enc_str_sz, "jsonParsed"))
      enc = FD_ENC_JSON;
    else {
      fd_web_replier_error(replier, "invalid data encoding %s", (const char*)enc_str);
      return 0;
    }

    fd_blockstore_t * blockstore = ctx->global->blockstore;
    fd_textstream_t * ts = fd_web_replier_textstream(replier);
    fd_textstream_sprintf(ts, "{\"jsonrpc\":\"2.0\",\"result\":{\"context\":{\"apiVersion\":\"" API_VERSION "\",\"slot\":%lu},\"value\":[",
                          blockstore->smr);

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
        case FD_ENC_BASE58:
          if (fd_textstream_encode_base58(ts, val, val_sz)) {
            fd_web_replier_error(replier, "failed to encode data in base58");
            return 0;
          }
          break;
        case FD_ENC_BASE64:
          if (fd_textstream_encode_base64(ts, val, val_sz)) {
            fd_web_replier_error(replier, "failed to encode data in base64");
            return 0;
          }
          break;
        default:
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
  fd_blockstore_t * blockstore = ctx->global->blockstore;
  fd_textstream_sprintf(ts, "{\"jsonrpc\":\"2.0\",\"result\":{\"context\":{\"apiVersion\":\"" API_VERSION "\",\"slot\":%lu},\"value\":[",
                        blockstore->smr);

  // Iterate through account ids
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
    fd_blockstore_txn_map_t elem;
    if( fd_blockstore_txn_query_volatile( blockstore, key, &elem, NULL, NULL ) ) {
      fd_textstream_sprintf(ts, "null");
      continue;
    }

    // TODO other fields
    fd_textstream_sprintf(ts, "{\"slot\":%lu,\"confirmations\":null,\"err\":null,\"confirmationStatus\":\"finalized\"}",
                          elem.slot);
  }

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
  fd_blockstore_t * blockstore = ctx->global->blockstore;
  fd_textstream_sprintf(ts, "{\"jsonrpc\":\"2.0\",\"result\":%lu,\"id\":%lu}" CRLF,
                        blockstore->smr, ctx->call_id);
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
  /* FIXME!
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
  fd_rpc_encoding_t enc;
  if (enc_str == NULL || MATCH_STRING(enc_str, enc_str_sz, "json"))
    enc = FD_ENC_JSON;
  else if (MATCH_STRING(enc_str, enc_str_sz, "base58"))
    enc = FD_ENC_BASE58;
  else if (MATCH_STRING(enc_str, enc_str_sz, "base64"))
    enc = FD_ENC_BASE64;
  else if (MATCH_STRING(enc_str, enc_str_sz, "jsonParsed"))
    enc = FD_ENC_JSON_PARSED;
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
  fd_blockstore_txn_map_t elem;
  long blk_ts;
  uchar txn_data_raw[FD_TXN_MTU];
  fd_blockstore_t * blockstore = ctx->global->blockstore;
  if( fd_blockstore_txn_query_volatile( blockstore, key, &elem, &blk_ts, txn_data_raw ) ) {
    fd_textstream_sprintf(ts, "{\"jsonrpc\":\"2.0\",\"result\":null,\"id\":%lu}" CRLF, ctx->call_id);
    fd_web_replier_done(replier);
    return 0;
  }

  uchar txn_out[FD_TXN_MAX_SZ];
  ulong pay_sz = 0;
  ulong txn_sz = fd_txn_parse_core(txn_data_raw, elem.sz, txn_out, NULL, &pay_sz, 0);
  if ( txn_sz == 0 || txn_sz > FD_TXN_MAX_SZ )
    FD_LOG_ERR(("failed to parse transaction"));

  fd_textstream_sprintf(ts, "{\"jsonrpc\":\"2.0\",\"result\":{\"context\":{\"apiVersion\":\"" API_VERSION "\",\"slot\":%lu},\"blockTime\":%ld,\"slot\":%lu,",
                        blockstore->smr, blk_ts/(long)1e9, elem.slot);
  fd_txn_to_json( ts, (fd_txn_t *)txn_out, txn_data_raw, enc, 0, FD_BLOCK_DETAIL_FULL, 0 );
  fd_textstream_sprintf(ts, "},\"id\":%lu}" CRLF, ctx->call_id);

  fd_web_replier_done(replier);
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

static void
vote_account_to_json(fd_textstream_t * ts, fd_vote_accounts_pair_t_mapnode_t * vote_node) {
  fd_textstream_sprintf(ts, "{\"commission\":0,\"epochVoteAccount\":true,\"epochCredits\":[[1,64,0],[2,192,64]],\"nodePubkey\":\")");
  fd_textstream_encode_base58(ts, vote_node->elem.value.owner.uc, sizeof(fd_pubkey_t));
  fd_textstream_sprintf(ts, "\",\"lastVote\":147,\"activatedStake\":%lu,\"votePubkey\":\"",
                        vote_node->elem.value.lamports);
  fd_textstream_encode_base58(ts, vote_node->elem.key.uc, sizeof(fd_pubkey_t));
  fd_textstream_sprintf(ts, "\"}");
}

// Implementation of the "getVoteAccounts" methods
// curl http://localhost:8123 -X POST -H "Content-Type: application/json" -d '{"jsonrpc": "2.0", "id": 1, "method": "getVoteAccounts", "params": [ { "votePubkey": "6j9YPqDdYWc9NWrmV6tSLygog9CrkG9BfYHb5zu9eidH" } ] }'

static int
method_getVoteAccounts(struct fd_web_replier* replier, struct json_values* values, fd_rpc_ctx_t * ctx) {
  FD_METHOD_SCRATCH_BEGIN( 1<<28 ) { /* read_epoch consumes a ton of scratch space! */
    ulong smr;
    fd_epoch_bank_t * epoch_bank = read_epoch_bank(ctx, fd_scratch_virtual(), &smr);
    fd_vote_accounts_t * accts = &epoch_bank->stakes.vote_accounts;
    fd_vote_accounts_pair_t_mapnode_t * root = accts->vote_accounts_root;
    fd_vote_accounts_pair_t_mapnode_t * pool = accts->vote_accounts_pool;

    fd_textstream_t * ts = fd_web_replier_textstream(replier);
    fd_textstream_sprintf(ts, "{\"jsonrpc\":\"2.0\",\"result\":{\"current\":[");

    int needcomma = 0;
    for ( ulong i = 0; ; ++i ) {
      // Path to argument
      uint path[4];
      path[0] = (JSON_TOKEN_LBRACE<<16) | KEYW_JSON_PARAMS;
      path[1] = (uint) ((JSON_TOKEN_LBRACKET<<16) | i);
      path[2] = (JSON_TOKEN_LBRACE<<16) | KEYW_JSON_VOTEPUBKEY;
      path[3] = (JSON_TOKEN_STRING<<16);
      ulong arg_sz = 0;
      const void* arg = json_get_value(values, path, 4, &arg_sz);
      if (arg == NULL)
        // End of list
        break;

      fd_vote_accounts_pair_t_mapnode_t key  = { 0 };
      fd_base58_decode_32((const char *)arg, key.elem.key.uc);
      fd_vote_accounts_pair_t_mapnode_t * vote_node = fd_vote_accounts_pair_t_map_find( pool, root, &key );
      if( vote_node == NULL ) continue;

      if( needcomma ) fd_textstream_sprintf(ts, ",");
      vote_account_to_json(ts, vote_node);
      needcomma = 1;
    }

    fd_textstream_sprintf(ts, "],\"delinquent\":[]},\"id\":%lu}" CRLF, ctx->call_id);
    fd_web_replier_done(replier);
    fd_readwrite_end_read( &ctx->global->lock );
  } FD_METHOD_SCRATCH_END;
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

static int
ws_method_accountSubscribe(fd_websocket_ctx_t * wsctx, struct json_values * values, fd_rpc_ctx_t * ctx, fd_textstream_t * ts) {
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
      fd_web_ws_error(wsctx, "getAccountInfo requires a string as first parameter");
      return 0;
    }
    fd_pubkey_t acct;
    fd_base58_decode_32((const char *)arg, acct.uc);

    static const uint PATH2[4] = {
      (JSON_TOKEN_LBRACE<<16) | KEYW_JSON_PARAMS,
      (JSON_TOKEN_LBRACKET<<16) | 1,
      (JSON_TOKEN_LBRACE<<16) | KEYW_JSON_ENCODING,
      (JSON_TOKEN_STRING<<16)
    };
    ulong enc_str_sz = 0;
    const void* enc_str = json_get_value(values, PATH2, 4, &enc_str_sz);
    fd_rpc_encoding_t enc;
    if (enc_str == NULL || MATCH_STRING(enc_str, enc_str_sz, "base58"))
      enc = FD_ENC_BASE58;
    else if (MATCH_STRING(enc_str, enc_str_sz, "base64"))
      enc = FD_ENC_BASE64;
    else if (MATCH_STRING(enc_str, enc_str_sz, "base64+zstd"))
      enc = FD_ENC_BASE64_ZSTD;
    else if (MATCH_STRING(enc_str, enc_str_sz, "jsonParsed"))
      enc = FD_ENC_JSON;
    else {
      fd_web_ws_error(wsctx, "invalid data encoding %s", (const char*)enc_str);
      return 0;
    }

    static const uint PATH3[5] = {
      (JSON_TOKEN_LBRACE<<16) | KEYW_JSON_PARAMS,
      (JSON_TOKEN_LBRACKET<<16) | 1,
      (JSON_TOKEN_LBRACE<<16) | KEYW_JSON_DATASLICE,
      (JSON_TOKEN_LBRACE<<16) | KEYW_JSON_LENGTH,
      (JSON_TOKEN_INTEGER<<16)
    };
    static const uint PATH4[5] = {
      (JSON_TOKEN_LBRACE<<16) | KEYW_JSON_PARAMS,
      (JSON_TOKEN_LBRACKET<<16) | 1,
      (JSON_TOKEN_LBRACE<<16) | KEYW_JSON_DATASLICE,
      (JSON_TOKEN_LBRACE<<16) | KEYW_JSON_OFFSET,
      (JSON_TOKEN_INTEGER<<16)
    };
    ulong len_sz = 0;
    const void* len_ptr = json_get_value(values, PATH3, 5, &len_sz);
    ulong off_sz = 0;
    const void* off_ptr = json_get_value(values, PATH4, 5, &off_sz);
    if (len_ptr && off_ptr) {
      if (enc == FD_ENC_JSON) {
        fd_web_ws_error(wsctx, "cannot use jsonParsed encoding with slice");
        return 0;
      }
    }

    fd_rpc_global_ctx_t * subs = ctx->global;
    fd_readwrite_start_write( &subs->lock );
    if( subs->sub_cnt >= FD_WS_MAX_SUBS ) {
      fd_readwrite_end_write( &subs->lock );
      fd_web_ws_error(wsctx, "too many subscriptions");
      return 0;
    }
    struct fd_ws_subscription * sub = &subs->sub_list[ subs->sub_cnt++ ];
    sub->socket = wsctx;
    sub->meth_id = KEYW_WS_METHOD_ACCOUNTSUBSCRIBE;
    sub->call_id = ctx->call_id;
    ulong subid = sub->subsc_id = ++(subs->last_subsc_id);
    sub->acct_subscribe.acct = acct;
    sub->acct_subscribe.enc = enc;
    sub->acct_subscribe.off = (off_ptr ? *(long*)off_ptr : FD_LONG_UNSET);
    sub->acct_subscribe.len = (len_ptr ? *(long*)len_ptr : FD_LONG_UNSET);
    fd_readwrite_end_write( &subs->lock );

    fd_textstream_sprintf(ts, "{\"jsonrpc\":\"2.0\",\"result\":%lu,\"id\":%lu}" CRLF,
                          subid, sub->call_id);

  } FD_METHOD_SCRATCH_END;

  return 1;
}

static int
ws_method_accountSubscribe_update(fd_rpc_ctx_t * ctx, fd_replay_notif_msg_t * msg, struct fd_ws_subscription * sub, fd_textstream_t * ts) {
  FD_METHOD_SCRATCH_BEGIN( 11<<20 ) {
    fd_websocket_ctx_t * wsctx = sub->socket;

    ulong val_sz;
    void * val = read_account_with_xid(ctx, &sub->acct_subscribe.acct, &msg->acct_saved.funk_xid, fd_scratch_virtual(), &val_sz);
    if (val == NULL) {
      fd_textstream_sprintf(ts, "{\"jsonrpc\":\"2.0\",\"result\":{\"context\":{\"apiVersion\":\"" API_VERSION "\",\"slot\":%lu},\"value\":null},\"subscription\":%lu}" CRLF,
                            msg->acct_saved.funk_xid.ul[0], sub->subsc_id);
      return 1;
    }

    fd_textstream_sprintf(ts, "{\"jsonrpc\":\"2.0\",\"method\":\"accountNotification\",\"params\":{\"result\":{\"context\":{\"apiVersion\":\"" API_VERSION "\",\"slot\":%lu},\"value\":",
                          msg->acct_saved.funk_xid.ul[0]);
    const char * err = fd_account_to_json( ts, sub->acct_subscribe.acct, sub->acct_subscribe.enc, val, val_sz, sub->acct_subscribe.off, sub->acct_subscribe.len );
    if( err ) {
      fd_web_ws_error(wsctx, "%s", err);
      return 0;
    }
    fd_textstream_sprintf(ts, "},\"subscription\":%lu}}" CRLF, sub->subsc_id);
  } FD_METHOD_SCRATCH_END;

  return 1;
}

static int
ws_method_slotSubscribe(fd_websocket_ctx_t * wsctx, struct json_values * values, fd_rpc_ctx_t * ctx, fd_textstream_t * ts) {
  (void)values;
  fd_rpc_global_ctx_t * subs = ctx->global;
  fd_readwrite_start_write( &subs->lock );
  if( subs->sub_cnt >= FD_WS_MAX_SUBS ) {
    fd_readwrite_end_write( &subs->lock );
    fd_web_ws_error(wsctx, "too many subscriptions");
    return 0;
  }
  struct fd_ws_subscription * sub = &subs->sub_list[ subs->sub_cnt++ ];
  sub->socket = wsctx;
  sub->meth_id = KEYW_WS_METHOD_SLOTSUBSCRIBE;
  sub->call_id = ctx->call_id;
  ulong subid = sub->subsc_id = ++(subs->last_subsc_id);
  fd_readwrite_end_write( &subs->lock );

  fd_textstream_sprintf(ts, "{\"jsonrpc\":\"2.0\",\"result\":%lu,\"id\":%lu}" CRLF,
                        subid, sub->call_id);

  return 1;
}

static int
ws_method_slotSubscribe_update(fd_rpc_ctx_t * ctx, fd_replay_notif_msg_t * msg, struct fd_ws_subscription * sub, fd_textstream_t * ts) {
  (void)ctx;
  char bank_hash[50];
  fd_base58_encode_32(msg->slot_exec.bank_hash.uc, 0, bank_hash);
  fd_textstream_sprintf(ts, "{\"jsonrpc\":\"2.0\",\"method\":\"slotNotification\",\"params\":{\"result\":{\"parent\":%lu,\"root\":%lu,\"slot\":%lu,\"bank_hash\":\"%s\"},\"subscription\":%lu}}" CRLF,
                        msg->slot_exec.parent, msg->slot_exec.root, msg->slot_exec.slot,
                        bank_hash, sub->subsc_id);
  return 1;
}

int
fd_webserver_ws_subscribe(struct json_values* values, fd_websocket_ctx_t * wsctx, void * cb_arg) {
  fd_rpc_ctx_t ctx = *( fd_rpc_ctx_t *)cb_arg;

  static const uint PATH[2] = {
    (JSON_TOKEN_LBRACE<<16) | KEYW_JSON_JSONRPC,
    (JSON_TOKEN_STRING<<16)
  };
  ulong arg_sz = 0;
  const void* arg = json_get_value(values, PATH, 2, &arg_sz);
  if (arg == NULL) {
    fd_web_ws_error( wsctx, "missing jsonrpc member" );
    return 0;
  }
  if (!MATCH_STRING(arg, arg_sz, "2.0")) {
    fd_web_ws_error( wsctx, "jsonrpc value must be 2.0" );
    return 0;
  }

  static const uint PATH3[2] = {
    (JSON_TOKEN_LBRACE<<16) | KEYW_JSON_ID,
    (JSON_TOKEN_INTEGER<<16)
  };
  arg_sz = 0;
  arg = json_get_value(values, PATH3, 2, &arg_sz);
  if (arg == NULL) {
    fd_web_ws_error( wsctx, "missing id member" );
    return 0;
  }
  ctx.call_id = *(long*)arg;

  static const uint PATH2[2] = {
    (JSON_TOKEN_LBRACE<<16) | KEYW_JSON_METHOD,
    (JSON_TOKEN_STRING<<16)
  };
  arg_sz = 0;
  arg = json_get_value(values, PATH2, 2, &arg_sz);
  if (arg == NULL) {
    fd_web_ws_error( wsctx, "missing method member" );
    return 0;
  }
  long meth_id = fd_webserver_json_keyword((const char*)arg, arg_sz);

  fd_textstream_t ts;
  fd_textstream_new(&ts, fd_libc_alloc_virtual(), 1UL<<15UL);

  switch (meth_id) {
  case KEYW_WS_METHOD_ACCOUNTSUBSCRIBE:
    if (ws_method_accountSubscribe(wsctx, values, &ctx, &ts)) {
      fd_web_ws_reply( wsctx, &ts );
      fd_textstream_destroy(&ts);
      return 1;
    }
    return 0;
  case KEYW_WS_METHOD_SLOTSUBSCRIBE:
    if (ws_method_slotSubscribe(wsctx, values, &ctx, &ts)) {
      fd_web_ws_reply( wsctx, &ts );
      fd_textstream_destroy(&ts);
      return 1;
    }
    return 0;
  }

  fd_textstream_destroy(&ts);
  fd_web_ws_error( wsctx, "unknown websocket method: %s", (const char*)arg );
  return 0;
}

void
fd_rpc_start_service(fd_rpcserver_args_t * args, fd_rpc_ctx_t ** ctx_p) {
  fd_rpc_ctx_t * ctx         = (fd_rpc_ctx_t *)malloc(sizeof(fd_rpc_ctx_t));
  fd_rpc_global_ctx_t * gctx = (fd_rpc_global_ctx_t *)malloc(sizeof(fd_rpc_global_ctx_t));
  fd_memset(ctx, 0, sizeof(fd_rpc_ctx_t));
  fd_memset(gctx, 0, sizeof(fd_rpc_global_ctx_t));

  fd_readwrite_new( &gctx->lock );
  ctx->global = gctx;
  gctx->funk = args->funk;
  gctx->blockstore = args->blockstore;

  FD_LOG_NOTICE(( "starting web server with %lu threads on port %u", args->num_threads, (uint)args->port ));
  if (fd_webserver_start(args->num_threads, args->port, args->ws_port, &gctx->ws, ctx))
    FD_LOG_ERR(("fd_webserver_start failed"));

  *ctx_p = ctx;
}

void
fd_rpc_stop_service(fd_rpc_ctx_t * ctx) {
  FD_LOG_NOTICE(( "stopping web server" ));
  if (fd_webserver_stop(&ctx->global->ws))
    FD_LOG_ERR(("fd_webserver_stop failed"));
  free(ctx->global);
  free(ctx);
}

void
fd_rpc_ws_poll(fd_rpc_ctx_t * ctx) {
  fd_webserver_ws_poll(&ctx->global->ws);
}

void
fd_webserver_ws_closed(fd_websocket_ctx_t * wsctx, void * cb_arg) {
  fd_rpc_ctx_t * ctx = ( fd_rpc_ctx_t *)cb_arg;
  fd_rpc_global_ctx_t * subs = ctx->global;
  fd_readwrite_start_write( &subs->lock );
  for( ulong i = 0; i < subs->sub_cnt; ++i ) {
    if( subs->sub_list[i].socket == wsctx ) {
      fd_memcpy( &subs->sub_list[i], &subs->sub_list[--(subs->sub_cnt)], sizeof(struct fd_ws_subscription) );
      --i;
    }
  }
  fd_readwrite_end_write( &subs->lock );
}

void
fd_rpc_replay_notify(fd_rpc_ctx_t * ctx, fd_replay_notif_msg_t * msg) {
  fd_rpc_global_ctx_t * subs = ctx->global;
  fd_readwrite_start_read( &subs->lock );

  if( subs->sub_cnt == 0 ) {
    /* do nothing */

  } else if( msg->type == FD_REPLAY_SAVED_TYPE ) {
    fd_textstream_t ts;
    fd_textstream_new(&ts, fd_libc_alloc_virtual(), 11UL<<21);

    /* TODO: replace with a hash table lookup? */
    for( uint i = 0; i < msg->acct_saved.acct_id_cnt; ++i ) {
      fd_pubkey_t * id = &msg->acct_saved.acct_id[i];
      for( ulong j = 0; j < subs->sub_cnt; ++j ) {
        struct fd_ws_subscription * sub = &subs->sub_list[ j ];
        if( sub->meth_id == KEYW_WS_METHOD_ACCOUNTSUBSCRIBE &&
            fd_pubkey_eq( id, &sub->acct_subscribe.acct ) ) {
          fd_textstream_clear( &ts );
          if( ws_method_accountSubscribe_update( ctx, msg, sub, &ts ) )
            fd_web_ws_reply( sub->socket, &ts );
        }
      }
    }

    fd_textstream_destroy(&ts);

  } else if( msg->type == FD_REPLAY_SLOT_TYPE ) {
    fd_textstream_t ts;
    fd_textstream_new(&ts, fd_libc_alloc_virtual(), 1UL<<16);

    for( ulong j = 0; j < subs->sub_cnt; ++j ) {
      struct fd_ws_subscription * sub = &subs->sub_list[ j ];
      if( sub->meth_id == KEYW_WS_METHOD_SLOTSUBSCRIBE ) {
        fd_textstream_clear( &ts );
        if( ws_method_slotSubscribe_update( ctx, msg, sub, &ts ) )
          fd_web_ws_reply( sub->socket, &ts );
      }
    }

    fd_textstream_destroy(&ts);
  }

  fd_readwrite_end_read( &subs->lock );
}
