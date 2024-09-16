#include "fd_rpc_service.h"
#include "fd_methods.h"
#include "fd_webserver.h"
#include "base_enc.h"
#include "../../flamenco/types/fd_types.h"
#include "../../flamenco/types/fd_solana_block.pb.h"
#include "../../flamenco/runtime/fd_runtime.h"
#include "../../flamenco/runtime/fd_acc_mgr.h"
#include "../../flamenco/runtime/sysvar/fd_sysvar_rent.h"
#include "../../flamenco/runtime/sysvar/fd_sysvar_epoch_schedule.h"
#include "../../ballet/base58/fd_base58.h"
#include "../../ballet/base64/fd_base64.h"
#include "keywords.h"
#include <errno.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <stdarg.h>

#define CRLF "\r\n"
#define MATCH_STRING(_text_,_text_sz_,_str_) (_text_sz_ == sizeof(_str_)-1 && memcmp(_text_, _str_, sizeof(_str_)-1) == 0)

#define MAX_RECENT_BLOCKHASHES 300

static const uint PATH_COMMITMENT[4] = { ( JSON_TOKEN_LBRACE << 16 ) | KEYW_JSON_PARAMS,
                                         ( JSON_TOKEN_LBRACKET << 16 ) | 1,
                                         ( JSON_TOKEN_LBRACE << 16 ) | KEYW_JSON_COMMITMENT,
                                         ( JSON_TOKEN_STRING << 16 ) };

struct fd_ws_subscription {
  ulong conn_id;
  long meth_id;
  char call_id[64];
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


typedef struct fd_stats_snapshot fd_stats_snapshot_t;

struct fd_perf_sample {
  ulong num_slots;
  ulong num_transactions;
  ulong num_non_vote_transactions;
  ulong highest_slot;
};
typedef struct fd_perf_sample fd_perf_sample_t;

#define DEQUE_NAME fd_perf_sample_deque
#define DEQUE_T    fd_perf_sample_t
#define DEQUE_MAX  720UL /* MAX RPC PERF SAMPLES */
#include "../../util/tmpl/fd_deque.c"

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
  fd_replay_notif_msg_t last_slot_notify;
  int tpu_socket;
  struct sockaddr_in tpu_addr;
  fd_hash_t recent_blockhash[MAX_RECENT_BLOCKHASHES];
  fd_perf_sample_t * perf_samples;
  fd_perf_sample_t perf_sample_snapshot;
  long perf_sample_ts;
};
typedef struct fd_rpc_global_ctx fd_rpc_global_ctx_t;

struct fd_rpc_ctx {
  char call_id[64];
  fd_rpc_global_ctx_t * global;
};

static int fd_hash_eq( const fd_hash_t * key1, const fd_hash_t * key2 ) {
  for (ulong i = 0; i < 32U/sizeof(ulong); ++i)
    if (key1->ul[i] != key2->ul[i])
      return 0;
  return 1;
}

static void fd_hash_copy( fd_hash_t * keyd, const fd_hash_t * keys ) {
  for (ulong i = 0; i < 32U/sizeof(ulong); ++i)
    keyd->ul[i] = keys->ul[i];
}

static void *
read_account( fd_rpc_ctx_t * ctx, fd_pubkey_t * acct, fd_valloc_t valloc, ulong * result_len ) {
  fd_funk_rec_key_t recid = fd_acc_funk_key(acct);
  fd_funk_t * funk = ctx->global->funk;
  return fd_funk_rec_query_safe(funk, &recid, valloc, result_len);
}

static void
fd_method_simple_error( fd_rpc_ctx_t * ctx, int errcode, const char* text ) {
  fd_webserver_t * ws = &ctx->global->ws;
  fd_hcache_reset(ws->hcache);
  ws->quick_size = 0;
  fd_web_reply_sprintf(ws, "{\"jsonrpc\":\"2.0\",\"error\":{\"code\":%d,\"message\":\"%s\"},\"id\":%s}",
                       errcode, text, ctx->call_id );
}

static void
fd_method_error( fd_rpc_ctx_t * ctx, int errcode, const char* format, ... )
  __attribute__ ((format (printf, 3, 4)));

static void
fd_method_error( fd_rpc_ctx_t * ctx, int errcode, const char* format, ... ) {
  char text[4096];
  va_list ap;
  va_start(ap, format);
  vsnprintf(text, sizeof(text), format, ap);
  va_end(ap);
  fd_method_simple_error(ctx, errcode, text);
}


static void *
read_account_with_xid( fd_rpc_ctx_t * ctx, fd_pubkey_t * acct, fd_funk_txn_xid_t * xid, fd_valloc_t valloc, ulong * result_len ) {
  fd_funk_rec_key_t recid = fd_acc_funk_key(acct);
  fd_funk_t * funk = ctx->global->funk;
  return fd_funk_rec_query_xid_safe(funk, &recid, xid, valloc, result_len);
}


static ulong
get_slot_from_commitment_level( struct json_values * values, fd_rpc_ctx_t * ctx ) {
  ulong        commit_str_sz = 0;
  const void * commit_str    = json_get_value( values, PATH_COMMITMENT, 4, &commit_str_sz );
  if( commit_str == NULL || MATCH_STRING( commit_str, commit_str_sz, "confirmed" ) ) {
    return ctx->global->blockstore->hcs;
  } else if( MATCH_STRING( commit_str, commit_str_sz, "processed" ) ) {
    return ctx->global->blockstore->lps;
  } else if( MATCH_STRING( commit_str, commit_str_sz, "finalized" ) ) {
    return ctx->global->blockstore->smr;
  } else {
    fd_method_error( ctx, -1, "invalid commitment %s", (const char *)commit_str );
    return FD_SLOT_NULL;
  }
}

fd_slot_bank_t *
read_root_bank( fd_rpc_ctx_t * ctx, fd_valloc_t valloc ) {
  fd_funk_rec_key_t recid = fd_runtime_slot_bank_key();
  ulong vallen;

  fd_funk_t * funk = ctx->global->funk;

  void * val = fd_funk_rec_query_safe(funk, &recid, valloc, &vallen);
  if( FD_UNLIKELY( !val ) ) {
    FD_LOG_WARNING(( "failed to decode slot_bank" ));
    return NULL;
  }
  uint magic = *(uint*)val;
  fd_slot_bank_t * slot_bank = fd_valloc_malloc( valloc, fd_slot_bank_align(), fd_slot_bank_footprint() );
  fd_slot_bank_new( slot_bank );
  fd_bincode_decode_ctx_t binctx;
  binctx.data = (uchar*)val + sizeof(uint);
  binctx.dataend = (uchar*)val + vallen;
  binctx.valloc  = valloc;
  if( magic == FD_RUNTIME_ENC_BINCODE ) {
    if( fd_slot_bank_decode( slot_bank, &binctx )!=FD_BINCODE_SUCCESS ) {
      FD_LOG_WARNING(( "failed to decode slot_bank" ));
      fd_valloc_free( valloc, val );
      return NULL;
    }
  } else if( magic == FD_RUNTIME_ENC_ARCHIVE ) {
    if( fd_slot_bank_decode_archival( slot_bank, &binctx )!=FD_BINCODE_SUCCESS ) {
      FD_LOG_WARNING(( "failed to decode slot_bank" ));
      fd_valloc_free( valloc, val );
      return NULL;
    }
  } else {
    FD_LOG_ERR(( "failed to read banks record: invalid magic number" ));
  }
  fd_valloc_free( valloc, val );
  return slot_bank;
}

/* LEAVES THE LOCK IN READ MODE */
fd_epoch_bank_t *
read_epoch_bank( fd_rpc_ctx_t * ctx, ulong slot, fd_valloc_t valloc ) {
  fd_rpc_global_ctx_t * glob = ctx->global;
  // fd_slot_bank_t *      root_bank = read_root_bank( ctx, valloc );
  // FD_LOG_NOTICE( ( "funk root is %lu", root_bank->slot ) );

  for(;;) FD_SCRATCH_SCOPE_BEGIN {
    fd_readwrite_start_read( &glob->lock );

    if( glob->epoch_bank != NULL &&
        glob->epoch_bank_epoch == fd_slot_to_epoch(&glob->epoch_bank->epoch_schedule, slot, NULL) ) {
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

    /* FIXME always uses the root's epoch bank because we don't serialize it */

    void * val = fd_funk_rec_query_safe(funk, &recid, valloc, &vallen);
    if( val == NULL ) {
      FD_LOG_WARNING(( "failed to decode epoch_bank" ));
      fd_readwrite_end_write( &glob->lock );
      return NULL;
    }
    uint magic = *(uint*)val;
    fd_epoch_bank_t * epoch_bank = malloc( fd_epoch_bank_footprint() );
    fd_epoch_bank_new( epoch_bank );
    fd_bincode_decode_ctx_t binctx;
    binctx.data = (uchar*)val + sizeof(uint);
    binctx.dataend = (uchar*)val + vallen;
    binctx.valloc  = fd_libc_alloc_virtual();
    if( magic == FD_RUNTIME_ENC_BINCODE ) {
      if( fd_epoch_bank_decode( epoch_bank, &binctx )!=FD_BINCODE_SUCCESS ) {
        FD_LOG_WARNING(( "failed to decode epoch_bank" ));
        fd_valloc_free( valloc, val );
        free( epoch_bank );
        fd_readwrite_end_write( &glob->lock );
        return NULL;
      }
    } else if( magic == FD_RUNTIME_ENC_ARCHIVE ) {
      if( fd_epoch_bank_decode_archival( epoch_bank, &binctx )!=FD_BINCODE_SUCCESS ) {
        FD_LOG_WARNING(( "failed to decode epoch_bank" ));
        fd_valloc_free( valloc, val );
        free( epoch_bank );
        fd_readwrite_end_write( &glob->lock );
        return NULL;
      }
    } else {
      FD_LOG_ERR(("failed to read banks record: invalid magic number"));
    }
    fd_valloc_free( valloc, val );

    glob->epoch_bank = epoch_bank;
    glob->epoch_bank_epoch = fd_slot_to_epoch(&epoch_bank->epoch_schedule, slot, NULL);
    fd_readwrite_end_write( &glob->lock );
  } FD_SCRATCH_SCOPE_END;
}


fd_slot_bank_t *
read_slot_bank( fd_rpc_ctx_t * ctx, ulong slot, fd_valloc_t valloc ) {
  fd_funk_rec_key_t recid = fd_runtime_slot_bank_key();
  ulong vallen;

  fd_rpc_global_ctx_t * glob = ctx->global;
  fd_funk_t * funk = ctx->global->funk;

  fd_block_map_t block_map_entry = { 0 };
  fd_blockstore_block_map_query_volatile( glob->blockstore, slot, &block_map_entry );
  if( FD_UNLIKELY( block_map_entry.slot != slot ) ) {
    FD_LOG_WARNING( ( "query_volatile failed" ) );
    return NULL;
  }
  fd_funk_txn_xid_t xid;
  memcpy( xid.uc, &block_map_entry.block_hash, sizeof( fd_funk_txn_xid_t ) );
  xid.ul[0] = slot;

  void * val = fd_funk_rec_query_xid_safe(funk, &recid, &xid, valloc, &vallen);
  if( FD_UNLIKELY( !val ) ) {
    FD_LOG_WARNING(( "failed to decode slot_bank" ));
    return NULL;
  }
  uint magic = *(uint*)val;
  fd_slot_bank_t * slot_bank = fd_valloc_malloc( valloc, fd_slot_bank_align(), fd_slot_bank_footprint() );
  fd_slot_bank_new( slot_bank );
  fd_bincode_decode_ctx_t binctx;
  binctx.data = (uchar*)val + sizeof(uint);
  binctx.dataend = (uchar*)val + vallen;
  binctx.valloc  = valloc;
  if( magic == FD_RUNTIME_ENC_BINCODE ) {
    if( fd_slot_bank_decode( slot_bank, &binctx )!=FD_BINCODE_SUCCESS ) {
      FD_LOG_WARNING(( "failed to decode slot_bank" ));
      fd_valloc_free( valloc, val );
      return NULL;
    }
  } else if( magic == FD_RUNTIME_ENC_ARCHIVE ) {
    if( fd_slot_bank_decode_archival( slot_bank, &binctx )!=FD_BINCODE_SUCCESS ) {
      FD_LOG_WARNING(( "failed to decode slot_bank" ));
      fd_valloc_free( valloc, val );
      return NULL;
    }
  } else {
    FD_LOG_ERR(( "failed to read banks record: invalid magic number" ));
  }
  fd_valloc_free( valloc, val );
  return slot_bank;
}

static const char *
block_flags_to_confirmation_status( uchar flags ) {
  if( flags & (1U << FD_BLOCK_FLAG_FINALIZED) ) return "\"finalized\"";
  if( flags & (1U << FD_BLOCK_FLAG_CONFIRMED) ) return "\"confirmed\"";
  if( flags & (1U << FD_BLOCK_FLAG_PROCESSED) ) return "\"processed\"";
  return "null";
}

// Implementation of the "getAccountInfo" method
// curl http://localhost:8123 -X POST -H "Content-Type: application/json" -d '{ "jsonrpc": "2.0", "id": 1, "method": "getAccountInfo", "params": [ "21bVZhkqPJRVYDG3YpYtzHLMvkc7sa4KB7fMwGekTquG", { "encoding": "base64" } ] }'

static int
method_getAccountInfo(struct json_values* values, fd_rpc_ctx_t * ctx) {
  fd_webserver_t * ws = &ctx->global->ws;

  FD_SCRATCH_SCOPE_BEGIN {
    // Path to argument
    static const uint PATH[3] = {
      (JSON_TOKEN_LBRACE<<16) | KEYW_JSON_PARAMS,
      (JSON_TOKEN_LBRACKET<<16) | 0,
      (JSON_TOKEN_STRING<<16)
    };
    ulong arg_sz = 0;
    const void* arg = json_get_value(values, PATH, 3, &arg_sz);
    if (arg == NULL) {
      fd_method_error(ctx, -1, "getAccountInfo requires a string as first parameter");
      return 0;
    }

    fd_pubkey_t acct;
    if( fd_base58_decode_32((const char *)arg, acct.uc) == NULL ) {
      fd_method_error(ctx, -1, "invalid base58 encoding");
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
      fd_method_error(ctx, -1, "invalid data encoding %s", (const char*)enc_str);
      return 0;
    }

    ulong val_sz;
    void * val = read_account(ctx, &acct, fd_scratch_virtual(), &val_sz);
    if (val == NULL) {
      fd_web_reply_sprintf(ws, "{\"jsonrpc\":\"2.0\",\"result\":{\"context\":{\"apiVersion\":\"" FIREDANCER_VERSION "\",\"slot\":%lu},\"value\":null},\"id\":%s}" CRLF,
                           ctx->global->last_slot_notify.slot_exec.slot, ctx->call_id);
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

    fd_web_reply_sprintf(ws, "{\"jsonrpc\":\"2.0\",\"result\":{\"context\":{\"apiVersion\":\"" FIREDANCER_VERSION "\",\"slot\":%lu},\"value\":",
                         ctx->global->last_slot_notify.slot_exec.slot);
    const char * err = fd_account_to_json( ws, acct, enc, val, val_sz, off, len );
    if( err ) {
      fd_method_error(ctx, -1, "%s", err);
      return 0;
    }
    fd_web_reply_sprintf(ws, "},\"id\":%s}" CRLF, ctx->call_id);

  } FD_SCRATCH_SCOPE_END;

  return 0;
}

// Implementation of the "getBalance" method
// curl http://localhost:8123 -X POST -H "Content-Type: application/json" -d '{ "jsonrpc": "2.0", "id": 1, "method": "getBalance", "params": [ "6s5gDyLyfNXP6WHUEn4YSMQJVcGETpKze7FCPeg9wxYT" ] }'

static int
method_getBalance(struct json_values* values, fd_rpc_ctx_t * ctx) {
  FD_SCRATCH_SCOPE_BEGIN {
    // Path to argument
    static const uint PATH[3] = {
      (JSON_TOKEN_LBRACE<<16) | KEYW_JSON_PARAMS,
      (JSON_TOKEN_LBRACKET<<16) | 0,
      (JSON_TOKEN_STRING<<16)
    };
    fd_webserver_t * ws = &ctx->global->ws;
    ulong arg_sz = 0;
    const void* arg = json_get_value(values, PATH, 3, &arg_sz);
    if (arg == NULL) {
      fd_method_error(ctx, -1, "getBalance requires a string as first parameter");
      return 0;
    }
    fd_pubkey_t acct;
    if( fd_base58_decode_32((const char *)arg, acct.uc) == NULL ) {
      fd_method_error(ctx, -1, "invalid base58 encoding");
      return 0;
    }
    ulong val_sz;
    void * val = read_account(ctx, &acct, fd_scratch_virtual(), &val_sz);
    if (val == NULL) {
      fd_web_reply_sprintf(ws, "{\"jsonrpc\":\"2.0\",\"result\":{\"context\":{\"apiVersion\":\"" FIREDANCER_VERSION "\",\"slot\":%lu},\"value\":0},\"id\":%s}" CRLF,
                         ctx->global->last_slot_notify.slot_exec.slot, ctx->call_id);
      return 0;
    }
    fd_account_meta_t * metadata = (fd_account_meta_t *)val;
    fd_web_reply_sprintf(ws, "{\"jsonrpc\":\"2.0\",\"result\":{\"context\":{\"apiVersion\":\"" FIREDANCER_VERSION "\",\"slot\":%lu},\"value\":%lu},\"id\":%s}" CRLF,
                         ctx->global->last_slot_notify.slot_exec.slot, metadata->info.lamports, ctx->call_id);
  } FD_SCRATCH_SCOPE_END;
  return 0;
}

// Implementation of the "getBlock" method
// curl http://localhost:8123 -X POST -H "Content-Type: application/json" -d ' {"jsonrpc": "2.0","id":1, "method":"getBlock", "params": [270562740, {"encoding": "json", "maxSupportedTransactionVersion":0, "transactionDetails":"full", "rewards":false}]} '

static int
method_getBlock(struct json_values* values, fd_rpc_ctx_t * ctx) {
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

  fd_webserver_t * ws = &ctx->global->ws;
  ulong slot_sz = 0;
  const void* slot = json_get_value(values, PATH_SLOT, 3, &slot_sz);
  if (slot == NULL) {
    fd_method_error(ctx, -1, "getBlock requires a slot number as first parameter");
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
    fd_method_error(ctx, -1, "invalid data encoding %s", (const char*)enc_str);
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
    fd_method_error(ctx, -1, "invalid block detail %s", (const char*)det_str);
    return 0;
  }

  ulong rewards_sz = 0;
  const void* rewards = json_get_value(values, PATH_REWARDS, 4, &rewards_sz);

  ulong blk_sz;
  fd_blockstore_t * blockstore = ctx->global->blockstore;
  fd_block_map_t meta[1];
  fd_hash_t parent_hash;
  uchar * blk_data;
  if( fd_blockstore_block_data_query_volatile( blockstore, slotn, meta, &parent_hash, fd_libc_alloc_virtual(), &blk_data, &blk_sz ) ) {
    fd_method_error(ctx, -1, "failed to display block for slot %lu", slotn);
    return 0;
  }

  const char * err = fd_block_to_json(ws,
                                      blockstore,
                                      ctx->call_id,
                                      blk_data,
                                      blk_sz,
                                      meta,
                                      &parent_hash,
                                      enc,
                                      (maxvers == NULL ? 0 : *(const long*)maxvers),
                                      det,
                                      (rewards == NULL ? 1 : *(const int*)rewards));
  if( err ) {
    free( blk_data );
    fd_method_error(ctx, -1, "%s", err);
    return 0;
  }
  free( blk_data );
  return 0;
}

// Implementation of the "getBlockCommitment" methods
static int
method_getBlockCommitment(struct json_values* values, fd_rpc_ctx_t * ctx) {
  (void)values;
  (void)ctx;
  FD_LOG_WARNING(( "getBlockCommitment is not implemented" ));
  fd_method_error(ctx, -1, "getBlockCommitment is not implemented");
  return 0;
}

// Implementation of the "getBlockHeight" method
// curl http://localhost:8123 -X POST -H "Content-Type: application/json" -d '{ "jsonrpc":"2.0","id":1, "method":"getBlockHeight" }'
static int
method_getBlockHeight(struct json_values* values, fd_rpc_ctx_t * ctx) {
  (void) values;
  fd_rpc_global_ctx_t * glob = ctx->global;
  fd_readwrite_start_read( &glob->lock );
  fd_webserver_t * ws = &ctx->global->ws;
  fd_web_reply_sprintf(ws, "{\"jsonrpc\":\"2.0\",\"result\":%lu,\"id\":%s}" CRLF,
                       glob->last_slot_notify.slot_exec.height, ctx->call_id);
  fd_readwrite_end_read( &glob->lock );
  return 0;
}

// Implementation of the "getBlockProduction" methods
static int
method_getBlockProduction(struct json_values* values, fd_rpc_ctx_t * ctx) {
  (void)values;
  (void)ctx;
  FD_LOG_WARNING(( "getBlockProduction is not implemented" ));
  fd_method_error(ctx, -1, "getBlockProduction is not implemented");
  return 0;
}

// Implementation of the "getBlocks" method
// curl http://localhost:8123 -X POST -H "Content-Type: application/json" -d ' {"jsonrpc": "2.0", "id": 1, "method": "getBlocks", "params": [270562730, 270562740]} '

static int
method_getBlocks(struct json_values* values, fd_rpc_ctx_t * ctx) {
  static const uint PATH_STARTSLOT[3] = {
    (JSON_TOKEN_LBRACE<<16) | KEYW_JSON_PARAMS,
    (JSON_TOKEN_LBRACKET<<16) | 0,
    (JSON_TOKEN_INTEGER<<16)
  };
  fd_webserver_t * ws = &ctx->global->ws;
  ulong startslot_sz = 0;
  const void* startslot = json_get_value(values, PATH_STARTSLOT, 3, &startslot_sz);
  if (startslot == NULL) {
    fd_method_error(ctx, -1, "getBlocks requires a start slot number as first parameter");
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

  fd_web_reply_sprintf(ws, "{\"jsonrpc\":\"2.0\",\"result\":[");
  uint cnt = 0;
  for ( ulong i = startslotn; i <= endslotn && cnt < 500000U; ++i ) {
    fd_block_map_t meta[1];
    int ret = fd_blockstore_block_map_query_volatile(blockstore, i, meta);
    if (!ret) {
      fd_web_reply_sprintf(ws, "%s%lu", (cnt==0 ? "" : ","), i);
      ++cnt;
    }
  }
  fd_web_reply_sprintf(ws, "],\"id\":%s}" CRLF, ctx->call_id);

  return 0;
}

// Implementation of the "getBlocksWithLimit" method
// curl http://localhost:8123 -X POST -H "Content-Type: application/json" -d ' {"jsonrpc": "2.0", "id":1, "method":"getBlocksWithLimit", "params":[270562730, 3]} '

static int
method_getBlocksWithLimit(struct json_values* values, fd_rpc_ctx_t * ctx) {
  static const uint PATH_SLOT[3] = {
    (JSON_TOKEN_LBRACE<<16) | KEYW_JSON_PARAMS,
    (JSON_TOKEN_LBRACKET<<16) | 0,
    (JSON_TOKEN_INTEGER<<16)
  };
  fd_webserver_t * ws = &ctx->global->ws;
  ulong startslot_sz = 0;
  const void* startslot = json_get_value(values, PATH_SLOT, 3, &startslot_sz);
  if (startslot == NULL) {
    fd_method_error(ctx, -1, "getBlocksWithLimit requires a start slot number as first parameter");
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
    fd_method_error(ctx, -1, "getBlocksWithLimit requires a limit as second parameter");
    return 0;
  }
  ulong limitn = (ulong)(*(long*)limit);

  fd_blockstore_t * blockstore = ctx->global->blockstore;
  if (startslotn < blockstore->min)
    startslotn = blockstore->min;
  if (limitn > 500000)
    limitn = 500000;

  fd_web_reply_sprintf(ws, "{\"jsonrpc\":\"2.0\",\"result\":[");
  uint cnt = 0;
  uint skips = 0;
  for ( ulong i = startslotn; i <= blockstore->max && cnt < limitn && skips < 100U; ++i ) {
    fd_block_map_t meta[1];
    int ret = fd_blockstore_block_map_query_volatile(blockstore, i, meta);
    if (!ret) {
      fd_web_reply_sprintf(ws, "%s%lu", (cnt==0 ? "" : ","), i);
      ++cnt;
      skips = 0;
    } else {
      ++skips;
    }
  }
  fd_web_reply_sprintf(ws, "],\"id\":%s}" CRLF, ctx->call_id);

  return 0;
}

// Implementation of the "getBlockTime" methods
// curl http://localhost:8123 -X POST -H "Content-Type: application/json" -d '{"jsonrpc":"2.0","id":1,"method":"getBlockTime","params":[280687015]}'

static int
method_getBlockTime(struct json_values* values, fd_rpc_ctx_t * ctx) {
  static const uint PATH_SLOT[3] = {
    (JSON_TOKEN_LBRACE<<16) | KEYW_JSON_PARAMS,
    (JSON_TOKEN_LBRACKET<<16) | 0,
    (JSON_TOKEN_INTEGER<<16)
  };
  fd_webserver_t * ws = &ctx->global->ws;
  ulong slot_sz = 0;
  const void* slot = json_get_value(values, PATH_SLOT, 3, &slot_sz);
  if (slot == NULL) {
    fd_method_error(ctx, -1, "getBlockTime requires a slot number as first parameter");
    return 0;
  }
  ulong slotn = (ulong)(*(long*)slot);

  fd_blockstore_t * blockstore = ctx->global->blockstore;
  fd_block_map_t meta[1];
  int ret = fd_blockstore_block_map_query_volatile(blockstore, slotn, meta);
  if (ret) {
    fd_method_error(ctx, -1, "invalid slot: %lu", slotn);
    return 0;
  }

  fd_web_reply_sprintf(ws, "{\"jsonrpc\":\"2.0\",\"result\":%ld,\"id\":%s}" CRLF,
                       meta->ts/(long)1e9,
                       ctx->call_id);
  return 0;
}

// Implementation of the "getClusterNodes" methods
static int
method_getClusterNodes(struct json_values* values, fd_rpc_ctx_t * ctx) {
  (void)values;
  (void)ctx;
  FD_LOG_WARNING(( "getClusterNodes is not implemented" ));
  fd_method_error(ctx, -1, "getClusterNodes is not implemented");
  return 0;
}

// Implementation of the "getEpochInfo" methods
// curl http://localhost:8123 -X POST -H "Content-Type: application/json" -d ' {"jsonrpc":"2.0","id":1, "method":"getEpochInfo"} '

static int
method_getEpochInfo(struct json_values* values, fd_rpc_ctx_t * ctx) {

  FD_SCRATCH_SCOPE_BEGIN { /* read_epoch consumes a ton of scratch space! */

    fd_webserver_t * ws   = &ctx->global->ws;
    ulong            slot = get_slot_from_commitment_level( values, ctx );

    fd_epoch_bank_t * epoch_bank = read_epoch_bank(ctx, slot, fd_scratch_virtual() );
    if( epoch_bank == NULL ) {
      fd_method_error(ctx, -1, "unable to read epoch_bank");
      return 0;
    }
    fd_slot_bank_t * slot_bank = read_slot_bank(ctx, slot, fd_scratch_virtual());
    if( slot_bank == NULL ) {
      fd_method_error(ctx, -1, "unable to read slot_bank");
      fd_readwrite_end_read( &ctx->global->lock );
      return 0;
    }
    ulong slot_index;
    ulong epoch = fd_slot_to_epoch( &epoch_bank->epoch_schedule, slot, &slot_index );
    fd_block_map_t meta[1];
    int ret = fd_blockstore_block_map_query_volatile(ctx->global->blockstore, slot, meta);
    fd_web_reply_sprintf(ws, "{\"jsonrpc\":\"2.0\",\"result\":{\"absoluteSlot\":%lu,\"blockHeight\":%lu,\"epoch\":%lu,\"slotIndex\":%lu,\"slotsInEpoch\":%lu,\"transactionCount\":%lu},\"id\":%s}" CRLF,
                         slot,
                         (!ret ? meta->height : 0UL),
                         epoch,
                         slot_index,
                         fd_epoch_slot_cnt( &epoch_bank->epoch_schedule, epoch ),
                         ctx->global->last_slot_notify.slot_exec.transaction_count,
                         ctx->call_id);
    fd_readwrite_end_read( &ctx->global->lock );
  } FD_SCRATCH_SCOPE_END;
  return 0;
}

// Implementation of the "getEpochSchedule" methods
// curl http://localhost:8123 -X POST -H "Content-Type: application/json" -d ' {"jsonrpc":"2.0","id":1, "method":"getEpochSchedule"} '

static int
method_getEpochSchedule(struct json_values* values, fd_rpc_ctx_t * ctx) {
  (void)values;
  FD_SCRATCH_SCOPE_BEGIN { /* read_epoch consumes a ton of scratch space! */
    fd_webserver_t * ws = &ctx->global->ws;
    ulong            slot = get_slot_from_commitment_level( values, ctx );
    fd_epoch_bank_t * epoch_bank = read_epoch_bank(ctx, slot, fd_scratch_virtual() );
    if( FD_UNLIKELY( !epoch_bank ) ) {
      fd_web_error( ws, "unable to read epoch_bank" );
      return 0;
    }
    fd_web_reply_sprintf(ws, "{\"jsonrpc\":\"2.0\",\"result\":{\"firstNormalEpoch\":%lu,\"firstNormalSlot\":%lu,\"leaderScheduleSlotOffset\":%lu,\"slotsPerEpoch\":%lu,\"warmup\":%s},\"id\":%s}" CRLF,
                         epoch_bank->epoch_schedule.first_normal_epoch,
                         epoch_bank->epoch_schedule.first_normal_slot,
                         epoch_bank->epoch_schedule.leader_schedule_slot_offset,
                         epoch_bank->epoch_schedule.slots_per_epoch,
                         (epoch_bank->epoch_schedule.warmup ? "true" : "false"),
                         ctx->call_id);
    fd_readwrite_end_read( &ctx->global->lock );
  } FD_SCRATCH_SCOPE_END;
  return 0;
}

// Implementation of the "getFeeForMessage" methods
static int
method_getFeeForMessage(struct json_values* values, fd_rpc_ctx_t * ctx) {
  fd_webserver_t * ws = &ctx->global->ws;
  static const uint PATH[3] = {
    (JSON_TOKEN_LBRACE<<16) | KEYW_JSON_PARAMS,
    (JSON_TOKEN_LBRACKET<<16) | 0,
    (JSON_TOKEN_STRING<<16)
  };
  ulong arg_sz = 0;
  const void* arg = json_get_value(values, PATH, 3, &arg_sz);
  if (arg == NULL) {
    fd_method_error(ctx, -1, "getFeeForMessage requires a string as first parameter");
    return 0;
  }
  if( FD_BASE64_DEC_SZ(arg_sz) > FD_TXN_MTU ) {
    fd_method_error(ctx, -1, "message too large");
    return 0;
  }
  uchar data[FD_TXN_MTU];
  long res = fd_base64_decode( data, (const char*)arg, arg_sz );
  if( res < 0 ) {
    fd_method_error(ctx, -1, "failed to decode base64 data");
    return 0;
  }
  ulong data_sz = (ulong)res;
  // TODO: implement this
  (void)data;
  (void)data_sz;
  fd_web_reply_sprintf(ws, "{\"jsonrpc\":\"2.0\",\"result\":{\"context\":{\"apiVersion\":\"" FIREDANCER_VERSION "\",\"slot\":%lu},\"value\":5000},\"id\":%s}" CRLF,
                       ctx->global->last_slot_notify.slot_exec.slot, ctx->call_id);
  return 0;
}

// Implementation of the "getFirstAvailableBlock" methods
// curl http://localhost:8123 -X POST -H "Content-Type: application/json" -d '{"jsonrpc":"2.0","id":1,"method":"getFirstAvailableBlock"}'

static int
method_getFirstAvailableBlock(struct json_values* values, fd_rpc_ctx_t * ctx) {
  (void) values;
  fd_blockstore_t * blockstore = ctx->global->blockstore;
  fd_webserver_t * ws = &ctx->global->ws;
  fd_web_reply_sprintf(ws, "{\"jsonrpc\":\"2.0\",\"result\":%lu,\"id\":%s}" CRLF,
                       blockstore->min, ctx->call_id);
  return 0;
}

// Implementation of the "getGenesisHash" methods
// curl http://localhost:8123 -X POST -H "Content-Type: application/json" -d ' {"jsonrpc":"2.0","id":1, "method":"getGenesisHash"} '

static int
method_getGenesisHash(struct json_values* values, fd_rpc_ctx_t * ctx) {
  (void)values;
  FD_SCRATCH_SCOPE_BEGIN { /* read_epoch consumes a ton of scratch space! */
    ulong slot = get_slot_from_commitment_level( values, ctx );
    fd_epoch_bank_t * epoch_bank = read_epoch_bank(ctx, slot, fd_scratch_virtual());
    if( epoch_bank == NULL ) {
      fd_method_error(ctx, -1, "unable to read epoch_bank");
      return 0;
    }
    fd_webserver_t * ws = &ctx->global->ws;
    fd_web_reply_sprintf(ws, "{\"jsonrpc\":\"2.0\",\"result\":\"");
    fd_web_reply_encode_base58(ws, epoch_bank->genesis_hash.uc, sizeof(fd_pubkey_t));
    fd_web_reply_sprintf(ws, "\",\"id\":%s}" CRLF, ctx->call_id);
    fd_readwrite_end_read( &ctx->global->lock );
  } FD_SCRATCH_SCOPE_END;
  return 0;
}

// Implementation of the "getHealth" methods
static int
method_getHealth(struct json_values* values, fd_rpc_ctx_t * ctx) {
  (void)values;
  fd_webserver_t * ws = &ctx->global->ws;
  fd_web_reply_sprintf(ws, "{\"jsonrpc\":\"2.0\",\"result\":\"ok\",\"id\":%s}" CRLF, ctx->call_id);
  return 0;
}

// Implementation of the "getHighestSnapshotSlot" methods
static int
method_getHighestSnapshotSlot(struct json_values* values, fd_rpc_ctx_t * ctx) {
  (void)values;
  (void)ctx;
  FD_LOG_WARNING(( "getHighestSnapshotSlot is not implemented" ));
  fd_method_error(ctx, -1, "getHighestSnapshotSlot is not implemented");
  return 0;
}

// Implementation of the "getIdentity" method
// curl http://localhost:8123 -X POST -H "Content-Type: application/json" -d ' {"jsonrpc":"2.0","id":1, "method":"getIdentity"} '

static int
method_getIdentity(struct json_values* values, fd_rpc_ctx_t * ctx) {
  (void)values;
  fd_rpc_global_ctx_t * glob = ctx->global;
  fd_readwrite_start_read( &glob->lock );
  fd_webserver_t * ws = &ctx->global->ws;
  fd_web_reply_sprintf(ws, "{\"jsonrpc\":\"2.0\",\"result\":{\"identity\":\"");
  fd_web_reply_encode_base58(ws, &glob->last_slot_notify.slot_exec.identity, sizeof(fd_pubkey_t));
  fd_web_reply_sprintf(ws, "\"},\"id\":%s}" CRLF, ctx->call_id);
  fd_readwrite_end_read( &glob->lock );
  return 0;
}
// Implementation of the "getInflationGovernor" methods
static int
method_getInflationGovernor(struct json_values* values, fd_rpc_ctx_t * ctx) {
  (void)values;
  (void)ctx;
  FD_LOG_WARNING(( "getInflationGovernor is not implemented" ));
  fd_method_error(ctx, -1, "getInflationGovernor is not implemented");
  return 0;
}

// Implementation of the "getInflationRate" methods
// curl http://localhost:8123 -X POST -H "Content-Type: application/json" -d ' {"jsonrpc":"2.0","id":1, "method":"getInflationRate"} '

static int
method_getInflationRate(struct json_values* values, fd_rpc_ctx_t * ctx) {
  (void) values;
  (void)ctx;
  FD_LOG_WARNING(( "getInflationRate is not implemented" ));
  fd_method_error(ctx, -1, "getInflationRate is not implemented");
  return 0;
  /* FIXME!
     fd_webserver_t * ws = &ctx->global->ws;
     fd_inflation_rates_t rates;
     calculate_inflation_rates( get_slot_ctx(ctx), &rates );
     fd_web_reply_sprintf(ws, "{\"jsonrpc\":\"2.0\",\"result\":{\"epoch\":%lu,\"foundation\":%.18f,\"total\":%.18f,\"validator\":%.18f},\"id\":%s}" CRLF,
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
method_getInflationReward(struct json_values* values, fd_rpc_ctx_t * ctx) {
  (void)values;
  (void)ctx;
  FD_LOG_WARNING(( "getInflationReward is not implemented" ));
  fd_method_error(ctx, -1, "getInflationReward is not implemented");
  return 0;
}

// Implementation of the "getLargestAccounts" methods
static int
method_getLargestAccounts(struct json_values* values, fd_rpc_ctx_t * ctx) {
  (void)values;
  (void)ctx;
  FD_LOG_WARNING(( "getLargestAccounts is not implemented" ));
  fd_method_error(ctx, -1, "getLargestAccounts is not implemented");
  return 0;
}

// Implementation of the "getLatestBlockhash" methods
// curl http://localhost:8123 -X POST -H "Content-Type: application/json" -d ' {"jsonrpc":"2.0","id":1, "method":"getLatestBlockhash"} '

static int
method_getLatestBlockhash(struct json_values* values, fd_rpc_ctx_t * ctx) {
  (void) values;
  fd_rpc_global_ctx_t * glob = ctx->global;
  fd_readwrite_start_read( &glob->lock );
  fd_webserver_t * ws = &ctx->global->ws;
  fd_web_reply_sprintf(ws, "{\"jsonrpc\":\"2.0\",\"result\":{\"context\":{\"apiVersion\":\"" FIREDANCER_VERSION "\",\"slot\":%lu},\"value\":{\"blockhash\":\"",
                       glob->last_slot_notify.slot_exec.slot);
  fd_web_reply_encode_base58(ws, &glob->last_slot_notify.slot_exec.block_hash, sizeof(fd_hash_t));
  fd_web_reply_sprintf(ws, "\",\"lastValidBlockHeight\":%lu}},\"id\":%s}" CRLF,
                       glob->last_slot_notify.slot_exec.height, ctx->call_id);
  fd_readwrite_end_read( &glob->lock );
  return 0;
}

// Implementation of the "getLeaderSchedule" methods
// TODO
static int
method_getLeaderSchedule(struct json_values* values, fd_rpc_ctx_t * ctx) {
  (void)values;
  (void)ctx;
  FD_LOG_WARNING(( "getLeaderSchedule is not implemented" ));
  fd_method_error(ctx, -1, "getLeaderSchedule is not implemented");
  return 0;
}

// Implementation of the "getMaxRetransmitSlot" methods
static int
method_getMaxRetransmitSlot(struct json_values* values, fd_rpc_ctx_t * ctx) {
  (void)values;
  (void)ctx;
  FD_LOG_WARNING(( "getMaxRetransmitSlot is not implemented" ));
  fd_method_error(ctx, -1, "getMaxRetransmitSlot is not implemented");
  return 0;
}

// Implementation of the "getMaxShredInsertSlot" methods
// curl http://localhost:8123 -X POST -H "Content-Type: application/json" -d ' {"jsonrpc":"2.0","id":1, "method":"getMaxShredInsertSlot"} '

static int
method_getMaxShredInsertSlot(struct json_values* values, fd_rpc_ctx_t * ctx) {
  (void) values;
  fd_blockstore_t * blockstore = ctx->global->blockstore;
  fd_webserver_t * ws = &ctx->global->ws;
  fd_web_reply_sprintf(ws, "{\"jsonrpc\":\"2.0\",\"result\":%lu,\"id\":%s}" CRLF,
                       blockstore->max, ctx->call_id);
  return 0;
}

// Implementation of the "getMinimumBalanceForRentExemption" methods
// curl http://localhost:8123 -X POST -H "Content-Type: application/json" -d ' {"jsonrpc": "2.0", "id": 1, "method": "getMinimumBalanceForRentExemption", "params": [50]} '

static int
method_getMinimumBalanceForRentExemption(struct json_values* values, fd_rpc_ctx_t * ctx) {
  FD_SCRATCH_SCOPE_BEGIN { /* read_epoch consumes a ton of scratch space! */
    static const uint PATH_SIZE[3] = {
      (JSON_TOKEN_LBRACE<<16) | KEYW_JSON_PARAMS,
      (JSON_TOKEN_LBRACKET<<16) | 0,
      (JSON_TOKEN_INTEGER<<16)
    };
    ulong size_sz = 0;
    const void* size = json_get_value(values, PATH_SIZE, 3, &size_sz);
    ulong sizen = (size == NULL ? 0UL : (ulong)(*(long*)size));
    ulong slot = get_slot_from_commitment_level( values, ctx );
    fd_epoch_bank_t * epoch_bank  = read_epoch_bank( ctx, slot, fd_scratch_virtual() );
    if( epoch_bank == NULL ) {
      fd_method_error(ctx, -1, "unable to read epoch_bank");
      return 0;
    }
    ulong min_balance = fd_rent_exempt_minimum_balance2(&epoch_bank->rent, sizen);

    fd_webserver_t * ws = &ctx->global->ws;
    fd_web_reply_sprintf(ws, "{\"jsonrpc\":\"2.0\",\"result\":%lu,\"id\":%s}" CRLF,
                         min_balance, ctx->call_id);
    fd_readwrite_end_read( &ctx->global->lock );
  } FD_SCRATCH_SCOPE_END;
  return 0;
}

// Implementation of the "getMultipleAccounts" method
// curl http://localhost:8123 -X POST -H "Content-Type: application/json" -d ' {"jsonrpc": "2.0", "id": 1, "method": "getMultipleAccounts", "params": [["Cwg1f6m4m3DGwMEbmsbAfDtUToUf5jRdKrJSGD7GfZCB", "Cwg1f6m4m3DGwMEbmsbAfDtUToUf5jRdKrJSGD7GfZCB", "7935owQYeYk1H6HjzKRYnT1aZpf1uXcpZNYjgTZ8q7VR"], {"encoding": "base64"}]} '

static int
method_getMultipleAccounts(struct json_values* values, fd_rpc_ctx_t * ctx) {
  FD_SCRATCH_SCOPE_BEGIN {
    static const uint ENC_PATH[4] = {
      (JSON_TOKEN_LBRACE<<16) | KEYW_JSON_PARAMS,
      (JSON_TOKEN_LBRACKET<<16) | 1,
      (JSON_TOKEN_LBRACE<<16) | KEYW_JSON_ENCODING,
      (JSON_TOKEN_STRING<<16)
    };
    fd_webserver_t * ws = &ctx->global->ws;
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
      fd_method_error(ctx, -1, "invalid data encoding %s", (const char*)enc_str);
      return 0;
    }

    fd_web_reply_sprintf(ws, "{\"jsonrpc\":\"2.0\",\"result\":{\"context\":{\"apiVersion\":\"" FIREDANCER_VERSION "\",\"slot\":%lu},\"value\":[",
                         ctx->global->last_slot_notify.slot_exec.slot);

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
        fd_web_reply_append(ws, ",", 1);

      fd_pubkey_t acct;
      if( fd_base58_decode_32((const char *)arg, acct.uc) == NULL ) {
        fd_method_error(ctx, -1, "invalid base58 encoding");
        return 0;
      }
      FD_SCRATCH_SCOPE_BEGIN {
        ulong val_sz;
        void * val = read_account(ctx, &acct, fd_scratch_virtual(), &val_sz);
        if (val == NULL) {
          fd_web_reply_sprintf(ws, "null");
          continue;
        }

        const char * err = fd_account_to_json( ws, acct, enc, val, val_sz, FD_LONG_UNSET, FD_LONG_UNSET );
        if( err ) {
          fd_method_error(ctx, -1, "%s", err);
          return 0;
        }
      } FD_SCRATCH_SCOPE_END;
    }

    fd_web_reply_sprintf(ws, "]},\"id\":%s}" CRLF, ctx->call_id);
  } FD_SCRATCH_SCOPE_END;
  return 0;
}

// Implementation of the "getProgramAccounts" methods
static int
method_getProgramAccounts(struct json_values* values, fd_rpc_ctx_t * ctx) {
  (void)values;
  (void)ctx;
  FD_LOG_WARNING(( "getProgramAccounts is not implemented" ));
  fd_method_error(ctx, -1, "getProgramAccounts is not implemented");
  return 0;
}

// Implementation of the "getRecentPerformanceSamples" methods
static int
method_getRecentPerformanceSamples(struct json_values* values, fd_rpc_ctx_t * ctx) {
  (void)values;
  (void)ctx;

  fd_webserver_t * ws = &ctx->global->ws;

  static const uint PATH_LIMIT[3] = {
    (JSON_TOKEN_LBRACE<<16) | KEYW_JSON_PARAMS,
    (JSON_TOKEN_LBRACKET<<16) | 0,
    (JSON_TOKEN_INTEGER<<16)
  };

  ulong limit_sz = 0;
  const void* limit = json_get_value(values, PATH_LIMIT, 3, &limit_sz);
  if( FD_UNLIKELY( !limit ) ) {
    fd_method_error( ctx, -1, "getRecentPerformanceSamples requires a number as first parameter" );
    return 0;
  }
  ulong limitn = (ulong)(*(long*)limit);

  ulong cnt = fd_ulong_min( fd_perf_sample_deque_cnt( ctx->global->perf_samples ), limitn );
  fd_web_reply_sprintf(ws, "{\"jsonrpc\":\"2.0\",\"result\":[");

  for (ulong i = 0; i < cnt; i++) {
    fd_perf_sample_t const * perf_sample = fd_perf_sample_deque_peek_index_const( ctx->global->perf_samples, i );
    FD_TEST( perf_sample );
    fd_web_reply_sprintf(ws, "{\"numSlots\":%lu,\"numTransactions\":%lu,\"numNonVoteTransactions\":%lu,\"samplePeriodSecs\":60,\"slot\":%lu}", perf_sample->num_slots, perf_sample->num_transactions, perf_sample->num_non_vote_transactions, perf_sample->highest_slot );
    if ( FD_LIKELY( i < cnt - 1 ) ) {
      fd_web_reply_sprintf(ws, ",");
    }
  }
  fd_web_reply_sprintf(ws, "]}");

  return 0;
}

// Implementation of the "getRecentPrioritizationFees" methods
static int
method_getRecentPrioritizationFees(struct json_values* values, fd_rpc_ctx_t * ctx) {
  (void)values;
  (void)ctx;
  FD_LOG_WARNING(( "getRecentPrioritizationFees is not implemented" ));
  fd_method_error(ctx, -1, "getRecentPrioritizationFees is not implemented");
  return 0;
}

// Implementation of the "getSignaturesForAddress" methods
static int
method_getSignaturesForAddress(struct json_values* values, fd_rpc_ctx_t * ctx) {
  (void)values;
  (void)ctx;
  FD_LOG_WARNING(( "getSignaturesForAddress is not implemented" ));
  fd_method_error(ctx, -1, "getSignaturesForAddress is not implemented");
  return 0;
}

// Implementation of the "getSignatureStatuses" methods
// curl http://localhost:8123 -X POST -H "Content-Type: application/json" -d ' {"jsonrpc": "2.0", "id": 1, "method": "getSignatureStatuses", "params": [["4qj8WecUytFE96SFhdiTkc3v2AYLY7795sbSQTnYG7cPL9s6xKNHNyi3wraQc83PsNSgV8yedWbfGa4vRXfzBDzB"], {"searchTransactionHistory": true}]} '

static int
method_getSignatureStatuses(struct json_values* values, fd_rpc_ctx_t * ctx) {
  fd_webserver_t * ws = &ctx->global->ws;
  fd_blockstore_t * blockstore = ctx->global->blockstore;
  fd_web_reply_sprintf(ws, "{\"jsonrpc\":\"2.0\",\"result\":{\"context\":{\"apiVersion\":\"" FIREDANCER_VERSION "\",\"slot\":%lu},\"value\":[",
                       ctx->global->last_slot_notify.slot_exec.slot);

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
      fd_web_reply_append(ws, ",", 1);

    uchar key[FD_ED25519_SIG_SZ];
    if ( fd_base58_decode_64( sig, key ) == NULL ) {
      fd_web_reply_sprintf(ws, "null");
      continue;
    }
    fd_blockstore_txn_map_t elem;
    uchar flags;
    if( fd_blockstore_txn_query_volatile( blockstore, key, &elem, NULL, &flags, NULL ) ) {
      fd_web_reply_sprintf(ws, "null");
      continue;
    }

    // TODO other fields
    fd_web_reply_sprintf(ws, "{\"slot\":%lu,\"confirmations\":null,\"err\":null,\"confirmationStatus\":%s}",
                         elem.slot, block_flags_to_confirmation_status(flags));
  }

  fd_web_reply_sprintf(ws, "]},\"id\":%s}" CRLF, ctx->call_id);
  return 0;
}

// Implementation of the "getSlot" method
// curl http://localhost:8123 -X POST -H "Content-Type: application/json" -d ' {"jsonrpc":"2.0","id":1, "method":"getSlot"} '

static int
method_getSlot(struct json_values* values, fd_rpc_ctx_t * ctx) {
  (void) values;
  fd_rpc_global_ctx_t * glob = ctx->global;
  fd_readwrite_start_read( &glob->lock );
  fd_webserver_t * ws = &ctx->global->ws;
  fd_web_reply_sprintf(ws, "{\"jsonrpc\":\"2.0\",\"result\":%lu,\"id\":%s}" CRLF,
                       glob->last_slot_notify.slot_exec.slot, ctx->call_id);
  fd_readwrite_end_read( &glob->lock );
  return 0;
}

// Implementation of the "getSlotLeader" methods
// curl http://localhost:8123 -X POST -H "Content-Type: application/json" -d ' {"jsonrpc":"2.0","id":1, "method":"getSlotLeader"} '

static int
method_getSlotLeader(struct json_values* values, fd_rpc_ctx_t * ctx) {
  (void)values;
  (void)ctx;
  FD_LOG_WARNING(( "getSlotLeader is not implemented" ));
  fd_method_error(ctx, -1, "getSlotLeader is not implemented");
  /* FIXME!
     fd_webserver_t * ws = &ctx->global->ws;
     fd_web_reply_sprintf(ws, "{\"jsonrpc\":\"2.0\",\"result\":\"");
     fd_pubkey_t const * leader = fd_epoch_leaders_get(fd_exec_epoch_ctx_leaders( ctx->replay->epoch_ctx ), get_slot_ctx(ctx)->slot_bank.slot);
     fd_textstream_encode_base58(ts, leader->uc, sizeof(fd_pubkey_t));
     fd_web_reply_sprintf(ws, "\",\"id\":%s}" CRLF, ctx->call_id);
     fd_web_replier_done(replier);
  */
  return 0;
}

// Implementation of the "getSlotLeaders" methods
static int
method_getSlotLeaders(struct json_values* values, fd_rpc_ctx_t * ctx) {
  (void)values;
  (void)ctx;
  FD_LOG_WARNING(( "getSlotLeaders is not implemented" ));
  fd_method_error(ctx, -1, "getSlotLeaders is not implemented");
  return 0;
}

// Implementation of the "getStakeActivation" methods
static int
method_getStakeActivation(struct json_values* values, fd_rpc_ctx_t * ctx) {
  (void)values;
  (void)ctx;
  FD_LOG_WARNING(( "getStakeActivation is not implemented" ));
  fd_method_error(ctx, -1, "getStakeActivation is not implemented");
  return 0;
}

// Implementation of the "getStakeMinimumDelegation" methods
static int
method_getStakeMinimumDelegation(struct json_values* values, fd_rpc_ctx_t * ctx) {
  (void)values;
  (void)ctx;
  FD_LOG_WARNING(( "getStakeMinimumDelegation is not implemented" ));
  fd_method_error(ctx, -1, "getStakeMinimumDelegation is not implemented");
  return 0;
}

// Implementation of the "getSupply" methods
// TODO
static int
method_getSupply(struct json_values* values, fd_rpc_ctx_t * ctx) {
  (void)values;
  (void)ctx;
  FD_LOG_WARNING(( "getSupply is not implemented" ));
  fd_method_error(ctx, -1, "getSupply is not implemented");
  return 0;
}

// Implementation of the "getTokenAccountBalance" methods
static int
method_getTokenAccountBalance(struct json_values* values, fd_rpc_ctx_t * ctx) {
  (void)values;
  (void)ctx;
  FD_LOG_WARNING(( "getTokenAccountBalance is not implemented" ));
  fd_method_error(ctx, -1, "getTokenAccountBalance is not implemented");
  return 0;
}

// Implementation of the "getTokenAccountsByDelegate" methods
static int
method_getTokenAccountsByDelegate(struct json_values* values, fd_rpc_ctx_t * ctx) {
  (void)values;
  (void)ctx;
  FD_LOG_WARNING(( "getTokenAccountsByDelegate is not implemented" ));
  fd_method_error(ctx, -1, "getTokenAccountsByDelegate is not implemented");
  return 0;
}

// Implementation of the "getTokenAccountsByOwner" methods
static int
method_getTokenAccountsByOwner(struct json_values* values, fd_rpc_ctx_t * ctx) {
  (void)values;
  (void)ctx;
  FD_LOG_WARNING(( "getTokenAccountsByOwner is not implemented" ));
  fd_method_error(ctx, -1, "getTokenAccountsByOwner is not implemented");
  return 0;
}

// Implementation of the "getTokenLargestAccounts" methods
static int
method_getTokenLargestAccounts(struct json_values* values, fd_rpc_ctx_t * ctx) {
  (void)values;
  (void)ctx;
  FD_LOG_WARNING(( "getTokenLargestAccounts is not implemented" ));
  fd_method_error(ctx, -1, "getTokenLargestAccounts is not implemented");
  return 0;
}

// Implementation of the "getTokenSupply" methods
static int
method_getTokenSupply(struct json_values* values, fd_rpc_ctx_t * ctx) {
  (void)values;
  (void)ctx;
  FD_LOG_WARNING(( "getTokenSupply is not implemented" ));
  fd_method_error(ctx, -1, "getTokenSupply is not implemented");
  return 0;
}

// Implementation of the "getTransaction" method
// curl http://localhost:8123 -X POST -H "Content-Type: application/json" -d ' {"jsonrpc": "2.0", "id": 1, "method": "getTransaction", "params": ["4qj8WecUytFE96SFhdiTkc3v2AYLY7795sbSQTnYG7cPL9s6xKNHNyi3wraQc83PsNSgV8yedWbfGa4vRXfzBDzB", "json"]} '

static int
method_getTransaction(struct json_values* values, fd_rpc_ctx_t * ctx) {
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
  static const uint PATH_ENCODING2[4] = {
    (JSON_TOKEN_LBRACE<<16) | KEYW_JSON_PARAMS,
    (JSON_TOKEN_LBRACKET<<16) | 1,
    (JSON_TOKEN_LBRACE<<16) | KEYW_JSON_ENCODING,
    (JSON_TOKEN_STRING<<16)
  };

  fd_webserver_t * ws = &ctx->global->ws;
  ulong sig_sz = 0;
  const void* sig = json_get_value(values, PATH_SIG, 3, &sig_sz);
  if (sig == NULL) {
    fd_method_error(ctx, -1, "getTransaction requires a signature as first parameter");
    return 0;
  }

  ulong enc_str_sz = 0;
  const void* enc_str = json_get_value(values, PATH_ENCODING, 3, &enc_str_sz);
  if (enc_str == NULL) enc_str = json_get_value(values, PATH_ENCODING2, 4, &enc_str_sz);
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
    fd_method_error(ctx, -1, "invalid data encoding %s", (const char*)enc_str);
    return 0;
  }

  ulong commit_str_sz = 0;
  const void* commit_str = json_get_value(values, PATH_COMMITMENT, 4, &commit_str_sz);
  uchar need_blk_flags;
  if (commit_str == NULL || MATCH_STRING(commit_str, commit_str_sz, "processed"))
    need_blk_flags = (uchar)(1U << FD_BLOCK_FLAG_PROCESSED);
  else if (MATCH_STRING(commit_str, commit_str_sz, "confirmed"))
    need_blk_flags = (uchar)(1U << FD_BLOCK_FLAG_CONFIRMED);
  else if (MATCH_STRING(commit_str, commit_str_sz, "finalized"))
    need_blk_flags = (uchar)(1U << FD_BLOCK_FLAG_FINALIZED);
  else {
    fd_method_error(ctx, -1, "invalid commitment %s", (const char*)commit_str);
    return 0;
  }

  uchar key[FD_ED25519_SIG_SZ];
  if ( fd_base58_decode_64( sig, key) == NULL ) {
    fd_web_reply_sprintf(ws, "{\"jsonrpc\":\"2.0\",\"result\":null,\"id\":%s}" CRLF, ctx->call_id);
    return 0;
  }
  fd_blockstore_txn_map_t elem;
  long blk_ts;
  uchar blk_flags;
  uchar txn_data_raw[FD_TXN_MTU];
  fd_blockstore_t * blockstore = ctx->global->blockstore;
  if( fd_blockstore_txn_query_volatile( blockstore, key, &elem, &blk_ts, &blk_flags, txn_data_raw ) ||
      ( blk_flags & need_blk_flags ) == (uchar)0 ) {
    fd_web_reply_sprintf(ws, "{\"jsonrpc\":\"2.0\",\"result\":null,\"id\":%s}" CRLF, ctx->call_id);
    return 0;
  }

  uchar txn_out[FD_TXN_MAX_SZ];
  ulong pay_sz = 0;
  ulong txn_sz = fd_txn_parse_core(txn_data_raw, elem.sz, txn_out, NULL, &pay_sz);
  if ( txn_sz == 0 || txn_sz > FD_TXN_MAX_SZ )
    FD_LOG_ERR(("failed to parse transaction"));

  void const * meta = fd_wksp_laddr_fast( fd_blockstore_wksp( blockstore ), elem.meta_gaddr );

  fd_web_reply_sprintf(ws, "{\"jsonrpc\":\"2.0\",\"result\":{\"context\":{\"apiVersion\":\"" FIREDANCER_VERSION "\",\"slot\":%lu},\"blockTime\":%ld,\"slot\":%lu,",
                       ctx->global->last_slot_notify.slot_exec.slot, blk_ts/(long)1e9, elem.slot);

  /* Emit meta, including the case for `meta:null` */
  const char * err = fd_txn_meta_to_json( ws, meta, elem.meta_sz );
  if( err ) {
    fd_method_error(ctx, -1, "%s", err);
    return 0;
  }

  err = fd_txn_to_json( ws, (fd_txn_t *)txn_out, txn_data_raw, pay_sz, enc, 0, FD_BLOCK_DETAIL_FULL, 0 );
  if( err ) {
    fd_method_error(ctx, -1, "%s", err);
    return 0;
  }
  fd_web_reply_sprintf(ws, "},\"id\":%s}" CRLF, ctx->call_id);

  return 0;
}

// Implementation of the "getTransactionCount" methods
static int
method_getTransactionCount(struct json_values* values, fd_rpc_ctx_t * ctx) {
  FD_SCRATCH_SCOPE_BEGIN { /* read_epoch consumes a ton of scratch space! */
    (void)values;
    fd_webserver_t * ws = &ctx->global->ws;
    fd_rpc_global_ctx_t * glob      = ctx->global;

    fd_readwrite_start_read( &glob->lock );
    ulong                 slot      = get_slot_from_commitment_level( values, ctx );
    fd_slot_bank_t *      slot_bank = read_slot_bank( ctx, slot, fd_scratch_virtual() );
    if( FD_UNLIKELY( !slot_bank ) ) {
      fd_method_error( ctx, -1, "slot bank %lu not found", slot );
      return 0;
    }
    fd_web_reply_sprintf( ws,
                          "{\"jsonrpc\":\"2.0\",\"result\":%lu,\"id\":%s}" CRLF,
                          slot_bank->transaction_count,
                          ctx->call_id );
    fd_readwrite_end_read( &glob->lock );
  } FD_SCRATCH_SCOPE_END;
  return 0;
}

// Implementation of the "getVersion" method
// curl http://localhost:8123 -X POST -H "Content-Type: application/json" -d ' {"jsonrpc":"2.0","id":1, "method":"getVersion"} '

static int
method_getVersion(struct json_values* values, fd_rpc_ctx_t * ctx) {
  (void) values;
  fd_webserver_t * ws = &ctx->global->ws;
  /* TODO Where does feature-set come from? */
  fd_web_reply_sprintf(ws, "{\"jsonrpc\":\"2.0\",\"result\":{\"feature-set\":666,\"solana-core\":\"" FIREDANCER_VERSION "\"},\"id\":%s}" CRLF,
                       ctx->call_id);
  return 0;
}

static void
vote_account_to_json(fd_webserver_t * ws, fd_vote_accounts_pair_t_mapnode_t const * vote_node) {
  fd_web_reply_sprintf(ws, "{\"commission\":0,\"epochVoteAccount\":true,\"epochCredits\":[[1,64,0],[2,192,64]],\"nodePubkey\":\")");
  fd_web_reply_encode_base58(ws, vote_node->elem.value.owner.uc, sizeof(fd_pubkey_t));
  fd_web_reply_sprintf(ws, "\",\"lastVote\":147,\"activatedStake\":%lu,\"votePubkey\":\"",
                       vote_node->elem.value.lamports);
  fd_web_reply_encode_base58(ws, vote_node->elem.key.uc, sizeof(fd_pubkey_t));
  fd_web_reply_sprintf(ws, "\"}");
}

// Implementation of the "getVoteAccounts" methods
// curl http://localhost:8123 -X POST -H "Content-Type: application/json" -d '{"jsonrpc": "2.0", "id": 1, "method": "getVoteAccounts", "params": [ { "votePubkey": "6j9YPqDdYWc9NWrmV6tSLygog9CrkG9BfYHb5zu9eidH" } ] }'

static int
method_getVoteAccounts(struct json_values* values, fd_rpc_ctx_t * ctx) {
  FD_SCRATCH_SCOPE_BEGIN { /* read_epoch consumes a ton of scratch space! */
    ulong slot = get_slot_from_commitment_level( values, ctx );
    fd_epoch_bank_t * epoch_bank = read_epoch_bank(ctx, slot, fd_scratch_virtual());
    if( epoch_bank == NULL ) {
      fd_method_error(ctx, -1, "unable to read epoch_bank");
      return 0;
    }

    fd_vote_accounts_t * accts = &epoch_bank->stakes.vote_accounts;
    fd_vote_accounts_pair_t_mapnode_t * root = accts->vote_accounts_root;
    fd_vote_accounts_pair_t_mapnode_t * pool = accts->vote_accounts_pool;

    fd_webserver_t * ws = &ctx->global->ws;
    fd_web_reply_sprintf(ws, "{\"jsonrpc\":\"2.0\",\"result\":{\"current\":[");

    uint path[4] = {
      (JSON_TOKEN_LBRACE<<16) | KEYW_JSON_PARAMS,
      (uint) ((JSON_TOKEN_LBRACKET<<16) | 0),
      (JSON_TOKEN_LBRACE<<16) | KEYW_JSON_VOTEPUBKEY,
      (JSON_TOKEN_STRING<<16)
    };
    ulong arg_sz = 0;
    const void* arg = json_get_value(values, path, 4, &arg_sz);
    if (arg == NULL) {
      // No vote pub key specified
      int needcomma = 0;
      for( fd_vote_accounts_pair_t_mapnode_t const * n = fd_vote_accounts_pair_t_map_minimum_const( pool, root );
           n;
           n = fd_vote_accounts_pair_t_map_successor_const( pool, n ) ) {
        if( needcomma ) fd_web_reply_sprintf(ws, ",");
        vote_account_to_json(ws, n);
        needcomma = 1;
      }

    } else {
      int needcomma = 0;
      for ( ulong i = 0; ; ++i ) {
        // Path to argument
        path[1] = (uint) ((JSON_TOKEN_LBRACKET<<16) | i);
        arg = json_get_value(values, path, 4, &arg_sz);
        if (arg == NULL)
          // End of list
          break;

        fd_vote_accounts_pair_t_mapnode_t key  = { 0 };
        if( fd_base58_decode_32((const char *)arg, key.elem.key.uc) == NULL ) {
          fd_method_error(ctx, -1, "invalid base58 encoding");
          fd_readwrite_end_read( &ctx->global->lock );
          return 0;
        }
        fd_vote_accounts_pair_t_mapnode_t * vote_node = fd_vote_accounts_pair_t_map_find( pool, root, &key );
        if( vote_node == NULL ) continue;

        if( needcomma ) fd_web_reply_sprintf(ws, ",");
        vote_account_to_json(ws, vote_node);
        needcomma = 1;
      }
    }

    fd_web_reply_sprintf(ws, "],\"delinquent\":[]},\"id\":%s}" CRLF, ctx->call_id);
    fd_readwrite_end_read( &ctx->global->lock );
  } FD_SCRATCH_SCOPE_END;
  return 0;
}

// Implementation of the "isBlockhashValid" methods
static int
method_isBlockhashValid(struct json_values* values, fd_rpc_ctx_t * ctx) {
  fd_rpc_global_ctx_t * glob = ctx->global;
  fd_webserver_t * ws = &glob->ws;

  // Path to argument
  static const uint PATH[3] = {
    (JSON_TOKEN_LBRACE<<16) | KEYW_JSON_PARAMS,
    (JSON_TOKEN_LBRACKET<<16) | 0,
    (JSON_TOKEN_STRING<<16)
  };
  ulong arg_sz = 0;
  const void* arg = json_get_value(values, PATH, 3, &arg_sz);
  if (arg == NULL) {
    fd_method_error(ctx, -1, "isBlockhashValid requires a string as first parameter");
    return 0;
  }

  fd_hash_t h;
  if( fd_base58_decode_32((const char *)arg, h.uc) == NULL ) {
    fd_method_error(ctx, -1, "invalid base58 encoding");
    return 0;
  }

  int res = 0;
  for( ulong i = 0; i < MAX_RECENT_BLOCKHASHES; ++i ) {
    if( fd_hash_eq( &glob->recent_blockhash[i], &h ) ) {
      res = 1;
      break;
    }
  }
  fd_web_reply_sprintf(ws, "{\"jsonrpc\":\"2.0\",\"result\":{\"context\":{\"slot\":%lu},\"value\":%s},\"id\":%s}" CRLF,
                       ctx->global->last_slot_notify.slot_exec.slot, (res ? "true" : "false"), ctx->call_id);

  return 0;
}

// Implementation of the "minimumLedgerSlot" methods
static int
method_minimumLedgerSlot(struct json_values* values, fd_rpc_ctx_t * ctx) {
  (void)values;
  (void)ctx;
  FD_LOG_WARNING(( "minimumLedgerSlot is not implemented" ));
  fd_method_error(ctx, -1, "minimumLedgerSlot is not implemented");
  return 0;
}

// Implementation of the "requestAirdrop" methods
static int
method_requestAirdrop(struct json_values* values, fd_rpc_ctx_t * ctx) {
  (void)values;
  (void)ctx;
  FD_LOG_WARNING(( "requestAirdrop is not implemented" ));
  fd_method_error(ctx, -1, "requestAirdrop is not implemented");
  return 0;
}

// Implementation of the "sendTransaction" methods
static int
method_sendTransaction(struct json_values* values, fd_rpc_ctx_t * ctx) {
  fd_webserver_t * ws = &ctx->global->ws;
  static const uint ENCPATH[4] = {
    (JSON_TOKEN_LBRACE<<16) | KEYW_JSON_PARAMS,
    (JSON_TOKEN_LBRACKET<<16) | 1,
    (JSON_TOKEN_LBRACE<<16) | KEYW_JSON_ENCODING,
    (JSON_TOKEN_STRING<<16)
  };
  ulong enc_str_sz = 0;
  const void* enc_str = json_get_value(values, ENCPATH, 4, &enc_str_sz);
  fd_rpc_encoding_t enc;
  if (enc_str == NULL || MATCH_STRING(enc_str, enc_str_sz, "base58"))
    enc = FD_ENC_BASE58;
  else if (MATCH_STRING(enc_str, enc_str_sz, "base64"))
    enc = FD_ENC_BASE64;
  else {
    fd_method_error(ctx, -1, "invalid data encoding %s", (const char*)enc_str);
    return 0;
  }

  static const uint DATAPATH[3] = {
    (JSON_TOKEN_LBRACE<<16) | KEYW_JSON_PARAMS,
    (JSON_TOKEN_LBRACKET<<16) | 0,
    (JSON_TOKEN_STRING<<16)
  };
  ulong arg_sz = 0;
  const void* arg = json_get_value(values, DATAPATH, 3, &arg_sz);
  if (arg == NULL) {
    fd_method_error(ctx, -1, "sendTransaction requires a string as first parameter");
    return 0;
  }

  uchar data[FD_TXN_MTU];
  ulong data_sz = FD_TXN_MTU;
  if( enc == FD_ENC_BASE58 ) {
    if( b58tobin( data, &data_sz, (const char*)arg, arg_sz ) ) {
      fd_method_error(ctx, -1, "failed to decode base58 data");
      return 0;
    }
  } else {
    FD_TEST( enc == FD_ENC_BASE64 );
    if( FD_BASE64_DEC_SZ( arg_sz ) > FD_TXN_MTU ) {
      fd_method_error(ctx, -1, "failed to decode base64 data");
      return 0;
    }
    long res = fd_base64_decode( data, (const char*)arg, arg_sz );
    if( res < 0 ) {
      fd_method_error(ctx, -1, "failed to decode base64 data");
      return 0;
    }
    data_sz = (ulong)res;
  }

  FD_LOG_NOTICE(( "received transaction of size %lu", data_sz ));

  uchar txn_out[FD_TXN_MAX_SZ];
  ulong pay_sz = 0;
  ulong txn_sz = fd_txn_parse_core(data, data_sz, txn_out, NULL, &pay_sz);
  if ( txn_sz == 0 || txn_sz > FD_TXN_MAX_SZ ) {
    fd_method_error(ctx, -1, "failed to parse transaction");
    return 0;
  }

  if( sendto( ctx->global->tpu_socket, data, data_sz, 0,
              (const struct sockaddr*)fd_type_pun_const(&ctx->global->tpu_addr), sizeof(ctx->global->tpu_addr) ) < 0 ) {
    fd_method_error(ctx, -1, "failed to send transaction data");
    return 0;
  }

  fd_txn_t * txn = (fd_txn_t *)txn_out;
  fd_ed25519_sig_t const * sigs = (fd_ed25519_sig_t const *)(data + txn->signature_off);
  char buf64[FD_BASE58_ENCODED_64_SZ];
  fd_base58_encode_64((const uchar*)sigs, NULL, buf64);
  fd_web_reply_sprintf(ws, "{\"jsonrpc\":\"2.0\",\"result\":\"%s\",\"id\":%s}" CRLF, buf64, ctx->call_id);

  return 0;
}

// Implementation of the "simulateTransaction" methods
static int
method_simulateTransaction(struct json_values* values, fd_rpc_ctx_t * ctx) {
  (void)values;
  (void)ctx;
  FD_LOG_WARNING(( "simulateTransaction is not implemented" ));
  fd_method_error(ctx, -1, "simulateTransaction is not implemented");
  return 0;
}

// Top level method dispatch function
void
fd_webserver_method_generic(struct json_values* values, void * cb_arg) {
  fd_rpc_ctx_t ctx = *( fd_rpc_ctx_t *)cb_arg;
  fd_webserver_t * ws = &ctx.global->ws;

  snprintf(ctx.call_id, sizeof(ctx.call_id)-1, "null");

  static const uint PATH[2] = {
    (JSON_TOKEN_LBRACE<<16) | KEYW_JSON_JSONRPC,
    (JSON_TOKEN_STRING<<16)
  };
  ulong arg_sz = 0;
  const void* arg = json_get_value(values, PATH, 2, &arg_sz);
  if (arg == NULL) {
    fd_method_error(&ctx, -1, "missing jsonrpc member");
    return;
  }
  if (!MATCH_STRING(arg, arg_sz, "2.0")) {
    fd_method_error(&ctx, -1, "jsonrpc value must be 2.0");
    return;
  }

  static const uint PATH3[2] = {
    (JSON_TOKEN_LBRACE<<16) | KEYW_JSON_ID,
    (JSON_TOKEN_INTEGER<<16)
  };
  arg_sz = 0;
  arg = json_get_value(values, PATH3, 2, &arg_sz);
  if (arg != NULL) {
    snprintf(ctx.call_id, sizeof(ctx.call_id)-1, "%lu", *(long*)arg);
  } else {
    static const uint PATH4[2] = {
      (JSON_TOKEN_LBRACE<<16) | KEYW_JSON_ID,
      (JSON_TOKEN_STRING<<16)
    };
    arg_sz = 0;
    arg = json_get_value(values, PATH4, 2, &arg_sz);
    if (arg != NULL) {
      snprintf(ctx.call_id, sizeof(ctx.call_id)-1, "\"%s\"", (const char *)arg);
    } else {
      fd_method_error(&ctx, -1, "missing id member");
      return;
    }
  }

  static const uint PATH2[2] = {
    (JSON_TOKEN_LBRACE<<16) | KEYW_JSON_METHOD,
    (JSON_TOKEN_STRING<<16)
  };
  arg_sz = 0;
  arg = json_get_value(values, PATH2, 2, &arg_sz);
  if (arg == NULL) {
    fd_method_error(&ctx, -1, "missing method member");
    return;
  }
  long meth_id = fd_webserver_json_keyword((const char*)arg, arg_sz);

  switch (meth_id) {
  case KEYW_RPCMETHOD_GETACCOUNTINFO:
    if (!method_getAccountInfo(values, &ctx))
      return;
    break;
  case KEYW_RPCMETHOD_GETBALANCE:
    if (!method_getBalance(values, &ctx))
      return;
    break;
  case KEYW_RPCMETHOD_GETBLOCK:
    if (!method_getBlock(values, &ctx))
      return;
    break;
  case KEYW_RPCMETHOD_GETBLOCKCOMMITMENT:
    if (!method_getBlockCommitment(values, &ctx))
      return;
    break;
  case KEYW_RPCMETHOD_GETBLOCKHEIGHT:
    if (!method_getBlockHeight(values, &ctx))
      return;
    break;
  case KEYW_RPCMETHOD_GETBLOCKPRODUCTION:
    if (!method_getBlockProduction(values, &ctx))
      return;
    break;
  case KEYW_RPCMETHOD_GETBLOCKS:
    if (!method_getBlocks(values, &ctx))
      return;
    break;
  case KEYW_RPCMETHOD_GETBLOCKSWITHLIMIT:
    if (!method_getBlocksWithLimit(values, &ctx))
      return;
    break;
  case KEYW_RPCMETHOD_GETBLOCKTIME:
    if (!method_getBlockTime(values, &ctx))
      return;
    break;
  case KEYW_RPCMETHOD_GETCLUSTERNODES:
    if (!method_getClusterNodes(values, &ctx))
      return;
    break;
  case KEYW_RPCMETHOD_GETEPOCHINFO:
    if (!method_getEpochInfo(values, &ctx))
      return;
    break;
  case KEYW_RPCMETHOD_GETEPOCHSCHEDULE:
    if (!method_getEpochSchedule(values, &ctx))
      return;
    break;
  case KEYW_RPCMETHOD_GETFEEFORMESSAGE:
    if (!method_getFeeForMessage(values, &ctx))
      return;
    break;
  case KEYW_RPCMETHOD_GETFIRSTAVAILABLEBLOCK:
    if (!method_getFirstAvailableBlock(values, &ctx))
      return;
    break;
  case KEYW_RPCMETHOD_GETGENESISHASH:
    if (!method_getGenesisHash(values, &ctx))
      return;
    break;
  case KEYW_RPCMETHOD_GETHEALTH:
    if (!method_getHealth(values, &ctx))
      return;
    break;
  case KEYW_RPCMETHOD_GETHIGHESTSNAPSHOTSLOT:
    if (!method_getHighestSnapshotSlot(values, &ctx))
      return;
    break;
  case KEYW_RPCMETHOD_GETIDENTITY:
    if (!method_getIdentity(values, &ctx))
      return;
    break;
  case KEYW_RPCMETHOD_GETINFLATIONGOVERNOR:
    if (!method_getInflationGovernor(values, &ctx))
      return;
    break;
  case KEYW_RPCMETHOD_GETINFLATIONRATE:
    if (!method_getInflationRate(values, &ctx))
      return;
    break;
  case KEYW_RPCMETHOD_GETINFLATIONREWARD:
    if (!method_getInflationReward(values, &ctx))
      return;
    break;
  case KEYW_RPCMETHOD_GETLARGESTACCOUNTS:
    if (!method_getLargestAccounts(values, &ctx))
      return;
    break;
  case KEYW_RPCMETHOD_GETLATESTBLOCKHASH:
    if (!method_getLatestBlockhash(values, &ctx))
      return;
    break;
  case KEYW_RPCMETHOD_GETLEADERSCHEDULE:
    if (!method_getLeaderSchedule(values, &ctx))
      return;
    break;
  case KEYW_RPCMETHOD_GETMAXRETRANSMITSLOT:
    if (!method_getMaxRetransmitSlot(values, &ctx))
      return;
    break;
  case KEYW_RPCMETHOD_GETMAXSHREDINSERTSLOT:
    if (!method_getMaxShredInsertSlot(values, &ctx))
      return;
    break;
  case KEYW_RPCMETHOD_GETMINIMUMBALANCEFORRENTEXEMPTION:
    if (!method_getMinimumBalanceForRentExemption(values, &ctx))
      return;
    break;
  case KEYW_RPCMETHOD_GETMULTIPLEACCOUNTS:
    if (!method_getMultipleAccounts(values, &ctx))
      return;
    break;
  case KEYW_RPCMETHOD_GETPROGRAMACCOUNTS:
    if (!method_getProgramAccounts(values, &ctx))
      return;
    break;
  case KEYW_RPCMETHOD_GETRECENTPERFORMANCESAMPLES:
    if (!method_getRecentPerformanceSamples(values, &ctx))
      return;
    break;
  case KEYW_RPCMETHOD_GETRECENTPRIORITIZATIONFEES:
    if (!method_getRecentPrioritizationFees(values, &ctx))
      return;
    break;
  case KEYW_RPCMETHOD_GETSIGNATURESFORADDRESS:
    if (!method_getSignaturesForAddress(values, &ctx))
      return;
    break;
  case KEYW_RPCMETHOD_GETSIGNATURESTATUSES:
    if (!method_getSignatureStatuses(values, &ctx))
      return;
    break;
  case KEYW_RPCMETHOD_GETSLOT:
    if (!method_getSlot(values, &ctx))
      return;
    break;
  case KEYW_RPCMETHOD_GETSLOTLEADER:
    if (!method_getSlotLeader(values, &ctx))
      return;
    break;
  case KEYW_RPCMETHOD_GETSLOTLEADERS:
    if (!method_getSlotLeaders(values, &ctx))
      return;
    break;
  case KEYW_RPCMETHOD_GETSTAKEACTIVATION:
    if (!method_getStakeActivation(values, &ctx))
      return;
    break;
  case KEYW_RPCMETHOD_GETSTAKEMINIMUMDELEGATION:
    if (!method_getStakeMinimumDelegation(values, &ctx))
      return;
    break;
  case KEYW_RPCMETHOD_GETSUPPLY:
    if (!method_getSupply(values, &ctx))
      return;
    break;
  case KEYW_RPCMETHOD_GETTOKENACCOUNTBALANCE:
    if (!method_getTokenAccountBalance(values, &ctx))
      return;
    break;
  case KEYW_RPCMETHOD_GETTOKENACCOUNTSBYDELEGATE:
    if (!method_getTokenAccountsByDelegate(values, &ctx))
      return;
    break;
  case KEYW_RPCMETHOD_GETTOKENACCOUNTSBYOWNER:
    if (!method_getTokenAccountsByOwner(values, &ctx))
      return;
    break;
  case KEYW_RPCMETHOD_GETTOKENLARGESTACCOUNTS:
    if (!method_getTokenLargestAccounts(values, &ctx))
      return;
    break;
  case KEYW_RPCMETHOD_GETTOKENSUPPLY:
    if (!method_getTokenSupply(values, &ctx))
      return;
    break;
  case KEYW_RPCMETHOD_GETTRANSACTION:
    if (!method_getTransaction(values, &ctx))
      return;
    break;
  case KEYW_RPCMETHOD_GETTRANSACTIONCOUNT:
    if (!method_getTransactionCount(values, &ctx))
      return;
    break;
  case KEYW_RPCMETHOD_GETVERSION:
    if (!method_getVersion(values, &ctx))
      return;
    break;
  case KEYW_RPCMETHOD_GETVOTEACCOUNTS:
    if (!method_getVoteAccounts(values, &ctx))
      return;
    break;
  case KEYW_RPCMETHOD_ISBLOCKHASHVALID:
    if (!method_isBlockhashValid(values, &ctx))
      return;
    break;
  case KEYW_RPCMETHOD_MINIMUMLEDGERSLOT:
    if (!method_minimumLedgerSlot(values, &ctx))
      return;
    break;
  case KEYW_RPCMETHOD_REQUESTAIRDROP:
    if (!method_requestAirdrop(values, &ctx))
      return;
    break;
  case KEYW_RPCMETHOD_SENDTRANSACTION:
    if (!method_sendTransaction(values, &ctx))
      return;
    break;
  case KEYW_RPCMETHOD_SIMULATETRANSACTION:
    if (!method_simulateTransaction(values, &ctx))
      return;
    break;
  default:
    fd_method_error(&ctx, -1, "unknown or unimplemented method %s", (const char*)arg);
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
  fd_web_reply_append(ws, DOC, strlen(DOC));
}

static int
ws_method_accountSubscribe(ulong conn_id, struct json_values * values, fd_rpc_ctx_t * ctx) {
  fd_webserver_t * ws = &ctx->global->ws;

  FD_SCRATCH_SCOPE_BEGIN {
    // Path to argument
    static const uint PATH[3] = {
      (JSON_TOKEN_LBRACE<<16) | KEYW_JSON_PARAMS,
      (JSON_TOKEN_LBRACKET<<16) | 0,
      (JSON_TOKEN_STRING<<16)
    };
    ulong arg_sz = 0;
    const void* arg = json_get_value(values, PATH, 3, &arg_sz);
    if (arg == NULL) {
      fd_web_ws_error(ws, conn_id, "getAccountInfo requires a string as first parameter");
      return 0;
    }
    fd_pubkey_t acct;
    if( fd_base58_decode_32((const char *)arg, acct.uc) == NULL ) {
      fd_method_error(ctx, -1, "invalid base58 encoding");
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
      fd_web_ws_error(ws, conn_id, "invalid data encoding %s", (const char*)enc_str);
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
        fd_web_ws_error(ws, conn_id, "cannot use jsonParsed encoding with slice");
        return 0;
      }
    }

    fd_rpc_global_ctx_t * subs = ctx->global;
    fd_readwrite_start_write( &subs->lock );
    if( subs->sub_cnt >= FD_WS_MAX_SUBS ) {
      fd_readwrite_end_write( &subs->lock );
      fd_web_ws_error(ws, conn_id, "too many subscriptions");
      return 0;
    }
    struct fd_ws_subscription * sub = &subs->sub_list[ subs->sub_cnt++ ];
    sub->conn_id = conn_id;
    sub->meth_id = KEYW_WS_METHOD_ACCOUNTSUBSCRIBE;
    strncpy(sub->call_id, ctx->call_id, sizeof(sub->call_id));
    ulong subid = sub->subsc_id = ++(subs->last_subsc_id);
    sub->acct_subscribe.acct = acct;
    sub->acct_subscribe.enc = enc;
    sub->acct_subscribe.off = (off_ptr ? *(long*)off_ptr : FD_LONG_UNSET);
    sub->acct_subscribe.len = (len_ptr ? *(long*)len_ptr : FD_LONG_UNSET);
    fd_readwrite_end_write( &subs->lock );

    fd_web_reply_sprintf(ws, "{\"jsonrpc\":\"2.0\",\"result\":%lu,\"id\":%s}" CRLF,
                         subid, sub->call_id);

  } FD_SCRATCH_SCOPE_END;

  return 1;
}

static int
ws_method_accountSubscribe_update(fd_rpc_ctx_t * ctx, fd_replay_notif_msg_t * msg, struct fd_ws_subscription * sub) {
  fd_webserver_t * ws = &ctx->global->ws;

  FD_SCRATCH_SCOPE_BEGIN {
    ulong conn_id = sub->conn_id;

    ulong val_sz;
    void * val = read_account_with_xid(ctx, &sub->acct_subscribe.acct, &msg->acct_saved.funk_xid, fd_scratch_virtual(), &val_sz);
    if (val == NULL) {
      fd_web_reply_sprintf(ws, "{\"jsonrpc\":\"2.0\",\"result\":{\"context\":{\"apiVersion\":\"" FIREDANCER_VERSION "\",\"slot\":%lu},\"value\":null},\"subscription\":%lu}" CRLF,
                           msg->acct_saved.funk_xid.ul[0], sub->subsc_id);
      return 1;
    }

    fd_web_reply_sprintf(ws, "{\"jsonrpc\":\"2.0\",\"method\":\"accountNotification\",\"params\":{\"result\":{\"context\":{\"apiVersion\":\"" FIREDANCER_VERSION "\",\"slot\":%lu},\"value\":",
                         msg->acct_saved.funk_xid.ul[0]);
    const char * err = fd_account_to_json( ws, sub->acct_subscribe.acct, sub->acct_subscribe.enc, val, val_sz, sub->acct_subscribe.off, sub->acct_subscribe.len );
    if( err ) {
      fd_web_ws_error(ws, conn_id, "%s", err);
      return 0;
    }
    fd_web_reply_sprintf(ws, "},\"subscription\":%lu}}" CRLF, sub->subsc_id);
  } FD_SCRATCH_SCOPE_END;

  return 1;
}

static int
ws_method_slotSubscribe(ulong conn_id, struct json_values * values, fd_rpc_ctx_t * ctx) {
  (void)values;
  fd_webserver_t * ws = &ctx->global->ws;

  fd_rpc_global_ctx_t * subs = ctx->global;
  fd_readwrite_start_write( &subs->lock );
  if( subs->sub_cnt >= FD_WS_MAX_SUBS ) {
    fd_readwrite_end_write( &subs->lock );
    fd_web_ws_error(ws, conn_id, "too many subscriptions");
    return 0;
  }
  struct fd_ws_subscription * sub = &subs->sub_list[ subs->sub_cnt++ ];
  sub->conn_id = conn_id;
  sub->meth_id = KEYW_WS_METHOD_SLOTSUBSCRIBE;
  strncpy(sub->call_id, ctx->call_id, sizeof(sub->call_id));
  ulong subid = sub->subsc_id = ++(subs->last_subsc_id);
  fd_readwrite_end_write( &subs->lock );

  fd_web_reply_sprintf(ws, "{\"jsonrpc\":\"2.0\",\"result\":%lu,\"id\":%s}" CRLF,
                       subid, sub->call_id);

  return 1;
}

static int
ws_method_slotSubscribe_update(fd_rpc_ctx_t * ctx, fd_replay_notif_msg_t * msg, struct fd_ws_subscription * sub) {
  (void)ctx;
  char bank_hash[50];
  fd_base58_encode_32(msg->slot_exec.bank_hash.uc, 0, bank_hash);
  fd_webserver_t * ws = &ctx->global->ws;
  fd_web_reply_sprintf(ws, "{\"jsonrpc\":\"2.0\",\"method\":\"slotNotification\",\"params\":{\"result\":{\"parent\":%lu,\"root\":%lu,\"slot\":%lu,\"bank_hash\":\"%s\"},\"subscription\":%lu}}" CRLF,
                       msg->slot_exec.parent, msg->slot_exec.root, msg->slot_exec.slot,
                       bank_hash, sub->subsc_id);
  return 1;
}

int
fd_webserver_ws_subscribe(struct json_values* values, ulong conn_id, void * cb_arg) {
  fd_rpc_ctx_t ctx = *( fd_rpc_ctx_t *)cb_arg;
  fd_webserver_t * ws = &ctx.global->ws;

  static const uint PATH[2] = {
    (JSON_TOKEN_LBRACE<<16) | KEYW_JSON_JSONRPC,
    (JSON_TOKEN_STRING<<16)
  };
  ulong arg_sz = 0;
  const void* arg = json_get_value(values, PATH, 2, &arg_sz);
  if (arg == NULL) {
    fd_web_ws_error( ws, conn_id, "missing jsonrpc member" );
    return 0;
  }
  if (!MATCH_STRING(arg, arg_sz, "2.0")) {
    fd_web_ws_error( ws, conn_id, "jsonrpc value must be 2.0" );
    return 0;
  }

  static const uint PATH3[2] = {
    (JSON_TOKEN_LBRACE<<16) | KEYW_JSON_ID,
    (JSON_TOKEN_INTEGER<<16)
  };
  arg_sz = 0;
  arg = json_get_value(values, PATH3, 2, &arg_sz);
  if (arg != NULL) {
    snprintf(ctx.call_id, sizeof(ctx.call_id)-1, "%lu", *(long*)arg);
  } else {
    static const uint PATH4[2] = {
      (JSON_TOKEN_LBRACE<<16) | KEYW_JSON_ID,
      (JSON_TOKEN_STRING<<16)
    };
    arg_sz = 0;
    arg = json_get_value(values, PATH4, 2, &arg_sz);
    if (arg != NULL) {
      snprintf(ctx.call_id, sizeof(ctx.call_id)-1, "\"%s\"", (const char *)arg);
    } else {
      fd_web_ws_error( ws, conn_id, "missing id member" );
      return 0;
    }
  }

  static const uint PATH2[2] = {
    (JSON_TOKEN_LBRACE<<16) | KEYW_JSON_METHOD,
    (JSON_TOKEN_STRING<<16)
  };
  arg_sz = 0;
  arg = json_get_value(values, PATH2, 2, &arg_sz);
  if (arg == NULL) {
    fd_web_ws_error( ws, conn_id, "missing method member" );
    return 0;
  }
  long meth_id = fd_webserver_json_keyword((const char*)arg, arg_sz);

  switch (meth_id) {
  case KEYW_WS_METHOD_ACCOUNTSUBSCRIBE:
    if (ws_method_accountSubscribe(conn_id, values, &ctx)) {
      fd_web_ws_send( ws, conn_id );
      return 1;
    }
    return 0;
  case KEYW_WS_METHOD_SLOTSUBSCRIBE:
    if (ws_method_slotSubscribe(conn_id, values, &ctx)) {
      fd_web_ws_send( ws, conn_id );
      return 1;
    }
    return 0;
  }

  fd_web_ws_error( ws, conn_id, "unknown websocket method: %s", (const char*)arg );
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

  if( !args->offline ) {
    gctx->tpu_socket = socket(AF_INET, SOCK_DGRAM, 0);
    if( gctx->tpu_socket == -1 ) {
      FD_LOG_ERR(( "socket failed (%i-%s)", errno, strerror( errno ) ));
    }
    struct sockaddr_in addrLocal;
    memset( &addrLocal, 0, sizeof(addrLocal) );
    addrLocal.sin_family = AF_INET;
    if( bind(gctx->tpu_socket, (const struct sockaddr*)fd_type_pun_const(&addrLocal), sizeof(addrLocal)) == -1 ) {
      FD_LOG_ERR(( "bind failed (%i-%s)", errno, strerror( errno ) ));
    }
    memcpy( &gctx->tpu_addr, &args->tpu_addr, sizeof(struct sockaddr_in) );
  } else {
    gctx->tpu_socket = -1;
  }

  fd_valloc_t valloc = fd_libc_alloc_virtual();
  void * mem = fd_valloc_malloc( valloc, fd_perf_sample_deque_align(), fd_perf_sample_deque_footprint() );
  gctx->perf_samples = fd_perf_sample_deque_join( fd_perf_sample_deque_new( mem ) );
  FD_TEST( gctx->perf_samples );

  fd_replay_notif_msg_t * msg = &gctx->last_slot_notify;
  msg->type = FD_REPLAY_SLOT_TYPE;
  msg->slot_exec.slot = args->blockstore->smr;
  msg->slot_exec.root = args->blockstore->smr;

  FD_LOG_NOTICE(( "starting web server on port %u", (uint)args->port ));
  if (fd_webserver_start(args->port, args->params, args->hcache_size, &gctx->ws, ctx))
    FD_LOG_ERR(("fd_webserver_start failed"));

  *ctx_p = ctx;
}

void
fd_rpc_stop_service(fd_rpc_ctx_t * ctx) {
  FD_LOG_NOTICE(( "stopping web server" ));
  if (fd_webserver_stop(&ctx->global->ws))
    FD_LOG_ERR(("fd_webserver_stop failed"));
  if( ctx->global->epoch_bank != NULL ) {
    fd_bincode_destroy_ctx_t binctx;
    binctx.valloc = fd_libc_alloc_virtual();
    fd_epoch_bank_destroy( ctx->global->epoch_bank, &binctx );
    free( ctx->global->epoch_bank );
    ctx->global->epoch_bank = NULL;
  }
  fd_valloc_t valloc = fd_libc_alloc_virtual();
  if ( FD_LIKELY( ctx->global->perf_samples ) ) {
    fd_valloc_free( valloc, fd_perf_sample_deque_delete( fd_perf_sample_deque_leave( ctx->global->perf_samples ) ) );
  }
  free(ctx->global);
  free(ctx);
}

void
fd_rpc_ws_poll(fd_rpc_ctx_t * ctx) {
  fd_webserver_poll(&ctx->global->ws);
}

void
fd_webserver_ws_closed(ulong conn_id, void * cb_arg) {
  fd_rpc_ctx_t * ctx = ( fd_rpc_ctx_t *)cb_arg;
  fd_rpc_global_ctx_t * subs = ctx->global;
  fd_readwrite_start_write( &subs->lock );
  for( ulong i = 0; i < subs->sub_cnt; ++i ) {
    if( subs->sub_list[i].conn_id == conn_id ) {
      fd_memcpy( &subs->sub_list[i], &subs->sub_list[--(subs->sub_cnt)], sizeof(struct fd_ws_subscription) );
      --i;
    }
  }
  fd_readwrite_end_write( &subs->lock );
}

void
fd_rpc_replay_notify(fd_rpc_ctx_t * ctx, fd_replay_notif_msg_t * msg) {
  fd_rpc_global_ctx_t * subs = ctx->global;

  if( msg->type == FD_REPLAY_SLOT_TYPE ) {
    fd_readwrite_start_write( &subs->lock );

    long ts = fd_log_wallclock() / (long)1e9;
    if( FD_UNLIKELY( ts - subs->perf_sample_ts >= 60 ) ) {

      if( FD_UNLIKELY( fd_perf_sample_deque_full( subs->perf_samples ) ) ) {
        fd_perf_sample_deque_pop_head( subs->perf_samples );
      }

      /* Record a new perf sample */

      if( FD_LIKELY( subs->perf_sample_snapshot.highest_slot ) ) {
        fd_perf_sample_t perf_sample = { .num_slots = msg->slot_exec.slot - subs->perf_sample_snapshot.highest_slot,
                                         .num_transactions = msg->slot_exec.transaction_count -
                                                             subs->perf_sample_snapshot.num_transactions,
                                         .num_non_vote_transactions = 0,
                                         .highest_slot              = msg->slot_exec.slot };
        fd_perf_sample_deque_push_tail( subs->perf_samples, perf_sample );
      }

      /* Update the snapshot of perf sample to record a diff on next interval. */

      subs->perf_sample_snapshot = ( fd_perf_sample_t ){
          .num_slots                 = 0,
          .num_transactions          = msg->slot_exec.transaction_count,
          .num_non_vote_transactions = 0,
          .highest_slot              = msg->slot_exec.slot };

      /* Update the timestamp for checking interval. */

      subs->perf_sample_ts = ts;
    }

    fd_memcpy( &subs->last_slot_notify, msg, sizeof(fd_replay_notif_msg_t) );
    fd_hash_t * h = &subs->recent_blockhash[msg->slot_exec.slot % MAX_RECENT_BLOCKHASHES];
    fd_hash_copy( h, &msg->slot_exec.block_hash );
    fd_readwrite_end_write( &subs->lock );
  }

  fd_readwrite_start_read( &subs->lock );

  if( subs->sub_cnt == 0 ) {
    /* do nothing */

  } else if( msg->type == FD_REPLAY_SAVED_TYPE ) {
    /* TODO: replace with a hash table lookup? */
    for( uint i = 0; i < msg->acct_saved.acct_id_cnt; ++i ) {
      fd_pubkey_t * id = &msg->acct_saved.acct_id[i];
      for( ulong j = 0; j < subs->sub_cnt; ++j ) {
        struct fd_ws_subscription * sub = &subs->sub_list[ j ];
        if( sub->meth_id == KEYW_WS_METHOD_ACCOUNTSUBSCRIBE &&
            fd_pubkey_eq( id, &sub->acct_subscribe.acct ) ) {
          if( ws_method_accountSubscribe_update( ctx, msg, sub ) )
            fd_web_ws_send( &subs->ws, sub->conn_id );
        }
      }
    }

  } else if( msg->type == FD_REPLAY_SLOT_TYPE ) {
    for( ulong j = 0; j < subs->sub_cnt; ++j ) {
      struct fd_ws_subscription * sub = &subs->sub_list[ j ];
      if( sub->meth_id == KEYW_WS_METHOD_SLOTSUBSCRIBE ) {
        if( ws_method_slotSubscribe_update( ctx, msg, sub ) )
          fd_web_ws_send( &subs->ws, sub->conn_id );
      }
    }
  }

  fd_readwrite_end_read( &subs->lock );
}
