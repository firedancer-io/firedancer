#include "fd_rpc_service.h"
#include "fd_methods.h"
#include "fd_webserver.h"
#include "base_enc.h"
#include "../../flamenco/types/fd_types.h"
#include "../../flamenco/runtime/fd_acc_mgr.h"
#include "../../flamenco/runtime/sysvar/fd_sysvar_epoch_schedule.h"
#include "../../disco/fd_disco_base.h"
#include "../../ballet/base58/fd_base58.h"
#include "../../ballet/base64/fd_base64.h"
#include "../../ballet/shred/fd_shred.h"
#include "../../choreo/tower/fd_tower.h"
#include "../reasm/fd_reasm.h"
#include "fd_rpc_history.h"
#include "fd_block_to_json.h"
#include "keywords.h"
#include <errno.h>
#include <stdlib.h>
#include <stdio.h> /* snprintf */
#include <sys/socket.h>
#include <netinet/in.h>
#include <stdarg.h>

#ifdef __has_include
#if __has_include("../../app/firedancer/version.h")
#include "../../app/firedancer/version.h"
#endif
#endif

#ifndef FDCTL_MAJOR_VERSION
#define FDCTL_MAJOR_VERSION 0
#endif
#ifndef FDCTL_MINOR_VERSION
#define FDCTL_MINOR_VERSION 0
#endif
#ifndef FDCTL_PATCH_VERSION
#define FDCTL_PATCH_VERSION 0
#endif

#define CRLF "\r\n"
#define MATCH_STRING(_text_,_text_sz_,_str_) (_text_sz_ == sizeof(_str_)-1 && memcmp(_text_, _str_, sizeof(_str_)-1) == 0)
#define EMIT_SIMPLE(_str_) fd_web_reply_append(ws, _str_, sizeof(_str_)-1)

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
  fd_spad_t * spad;
  fd_webserver_t ws;
  fd_funk_t * funk;
  fd_store_t * store;
  struct fd_ws_subscription sub_list[FD_WS_MAX_SUBS];
  ulong sub_cnt;
  ulong last_subsc_id;
  int tpu_socket;
  struct sockaddr_in tpu_addr;
  fd_perf_sample_t * perf_samples;
  fd_perf_sample_t perf_sample_snapshot;
  long perf_sample_ts;
  fd_multi_epoch_leaders_t * leaders;
  uchar buffer[sizeof(fd_reasm_fec_t) > sizeof(fd_replay_notif_msg_t) ? sizeof(fd_reasm_fec_t) : sizeof(fd_replay_notif_msg_t)];
  int buffer_sz;
  ulong acct_age;
  fd_rpc_history_t * history;
  fd_pubkey_t const * identity_key; /* nullable */
  ulong replay_towers_cnt;
  fd_replay_tower_t replay_towers[FD_REPLAY_TOWER_VOTE_ACC_MAX];
  int replay_towers_eom;
  ulong confirmed_slot;
  ulong root_slot;
};
typedef struct fd_rpc_global_ctx fd_rpc_global_ctx_t;

struct fd_rpc_ctx {
  char call_id[64];
  fd_rpc_global_ctx_t * global;
};

static void
fd_method_simple_error( fd_rpc_ctx_t * ctx, int errcode, const char* text ) {
  fd_web_reply_error( &ctx->global->ws, errcode, text, ctx->call_id );
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

static const void *
read_account_with_xid( fd_rpc_ctx_t * ctx, fd_funk_rec_key_t * recid, fd_funk_txn_xid_t * xid, ulong * result_len ) {
  fd_funk_txn_map_t * txn_map = fd_funk_txn_map( ctx->global->funk );
  fd_funk_txn_t *     txn     = fd_funk_txn_query( xid, txn_map );
  return fd_funk_rec_query_copy( ctx->global->funk, txn, recid, fd_spad_virtual(ctx->global->spad), result_len );
}

static const void *
read_account( fd_rpc_ctx_t * ctx, fd_funk_rec_key_t * recid, ulong * result_len ) {
  return fd_funk_rec_query_copy( ctx->global->funk, NULL, recid, fd_spad_virtual(ctx->global->spad), result_len );
}

static ulong
get_slot_from_commitment_level( struct json_values * values, fd_rpc_ctx_t * ctx ) {
  static const uint PATH_COMMITMENT[4] = { ( JSON_TOKEN_LBRACE << 16 ) | KEYW_JSON_PARAMS,
                                           ( JSON_TOKEN_LBRACKET << 16 ) | 1,
                                           ( JSON_TOKEN_LBRACE << 16 ) | KEYW_JSON_COMMITMENT,
                                           ( JSON_TOKEN_STRING << 16 ) };

  ulong        commit_str_sz = 0;
  const void * commit_str    = json_get_value( values, PATH_COMMITMENT, 4, &commit_str_sz );
  if( commit_str == NULL ) {
    return ctx->global->root_slot;
  } else if( MATCH_STRING( commit_str, commit_str_sz, "confirmed" ) ) {
    return ctx->global->confirmed_slot;
  } else if( MATCH_STRING( commit_str, commit_str_sz, "processed" ) ) {
    return fd_rpc_history_latest_slot( ctx->global->history );
  } else if( MATCH_STRING( commit_str, commit_str_sz, "finalized" ) ) {
    return ctx->global->root_slot;
  } else {
    fd_method_error( ctx, -1, "invalid commitment %s", (const char *)commit_str );
    return FD_SLOT_NULL;
  }
}

static const char *
get_commitment_level_from_slot( ulong slot, fd_rpc_ctx_t * ctx ) {
  if( slot <= ctx->global->root_slot ) return "finalized";
  if( slot <= ctx->global->confirmed_slot ) return "confirmed";
  if( slot <= fd_rpc_history_latest_slot( ctx->global->history ) ) return "processed";
  return "unknown";
}

// Implementation of the "getAccountInfo" method
// curl http://localhost:8123 -X POST -H "Content-Type: application/json" -d '{ "jsonrpc": "2.0", "id": 1, "method": "getAccountInfo", "params": [ "21bVZhkqPJRVYDG3YpYtzHLMvkc7sa4KB7fMwGekTquG", { "encoding": "base64" } ] }'

static int
method_getAccountInfo(struct json_values* values, fd_rpc_ctx_t * ctx) {
  fd_webserver_t * ws = &ctx->global->ws;

  FD_SPAD_FRAME_BEGIN( ctx->global->spad ) {
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
    fd_funk_rec_key_t recid = fd_funk_acc_key(&acct);
    const void * val        = read_account(ctx, &recid, &val_sz);
    if (val == NULL) {
      fd_web_reply_sprintf(ws, "{\"jsonrpc\":\"2.0\",\"result\":{\"context\":{\"apiVersion\":\"" FIREDANCER_VERSION "\",\"slot\":%lu},\"value\":null},\"id\":%s}" CRLF,
                           fd_rpc_history_latest_slot( ctx->global->history ), ctx->call_id);
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
                         fd_rpc_history_latest_slot( ctx->global->history ) );
    const char * err = fd_account_to_json( ws, acct, enc, val, val_sz, off, len, ctx->global->spad );
    if( err ) {
      fd_method_error(ctx, -1, "%s", err);
      return 0;
    }
    fd_web_reply_sprintf(ws, "},\"id\":%s}" CRLF, ctx->call_id);

  } FD_SPAD_FRAME_END;

  return 0;
}

// Implementation of the "getBalance" method
// curl http://localhost:8123 -X POST -H "Content-Type: application/json" -d '{ "jsonrpc": "2.0", "id": 1, "method": "getBalance", "params": [ "6s5gDyLyfNXP6WHUEn4YSMQJVcGETpKze7FCPeg9wxYT" ] }'

static int
method_getBalance(struct json_values* values, fd_rpc_ctx_t * ctx) {
  FD_SPAD_FRAME_BEGIN( ctx->global->spad ) {
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
    fd_funk_rec_key_t recid = fd_funk_acc_key(&acct);
    const void * val        = read_account(ctx, &recid, &val_sz);
    if (val == NULL) {
      fd_web_reply_sprintf(ws, "{\"jsonrpc\":\"2.0\",\"result\":{\"context\":{\"apiVersion\":\"" FIREDANCER_VERSION "\",\"slot\":%lu},\"value\":0},\"id\":%s}" CRLF,
                           fd_rpc_history_latest_slot( ctx->global->history ), ctx->call_id);
      return 0;
    }
    fd_account_meta_t * metadata = (fd_account_meta_t *)val;
    fd_web_reply_sprintf(ws, "{\"jsonrpc\":\"2.0\",\"result\":{\"context\":{\"apiVersion\":\"" FIREDANCER_VERSION "\",\"slot\":%lu},\"value\":%lu},\"id\":%s}" CRLF,
                         fd_rpc_history_latest_slot( ctx->global->history ), metadata->lamports, ctx->call_id);
  } FD_SPAD_FRAME_END;
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
  /*
  static const uint PATH_REWARDS[4] = {
    (JSON_TOKEN_LBRACE<<16) | KEYW_JSON_PARAMS,
    (JSON_TOKEN_LBRACKET<<16) | 1,
    (JSON_TOKEN_LBRACE<<16) | KEYW_JSON_REWARDS,
    (JSON_TOKEN_BOOL<<16)
  };
  */

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

  fd_replay_notif_msg_t * info = fd_rpc_history_get_block_info( ctx->global->history, slotn );
  if( info == NULL ) {
    fd_method_error(ctx, -1, "unable to find slot info");
    return 0;
  }
  fd_replay_notif_msg_t * parent_info = fd_rpc_history_get_block_info( ctx->global->history, info->slot_exec.parent );

  ulong blk_sz;
  uchar * blk_data = fd_rpc_history_get_block( ctx->global->history, slotn, &blk_sz );
  if( blk_data == NULL ) {
    fd_method_error(ctx, -1, "failed to display block for slot %lu", slotn);
    return 0;
  }

  const char * err = fd_block_to_json(ws,
                                      ctx->call_id,
                                      blk_data,
                                      blk_sz,
                                      info,
                                      parent_info,
                                      enc,
                                      (maxvers == NULL ? 0 : *(const long*)maxvers),
                                      det,
                                      NULL,
                                      ctx->global->spad );
  if( err ) {
    fd_method_error(ctx, -1, "%s", err);
    return 0;
  }
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
  fd_webserver_t * ws = &ctx->global->ws;
  ulong slot = get_slot_from_commitment_level( values, ctx );
  fd_replay_notif_msg_t * info = fd_rpc_history_get_block_info(ctx->global->history, slot);
  if( info == NULL ) {
    fd_method_error(ctx, -1, "block info not available");
    return 0;
  }
  fd_web_reply_sprintf(ws, "{\"jsonrpc\":\"2.0\",\"result\":%lu,\"id\":%s}" CRLF,
                       info->slot_exec.height, ctx->call_id);
  return 0;
}

// Implementation of the "getBlockProduction" methods

struct product_rb_node {
    fd_pubkey_t key;
    uint nleader, nproduced;
    ulong redblack_parent;
    ulong redblack_left;
    ulong redblack_right;
    int redblack_color;
};
typedef struct product_rb_node product_rb_node_t;
#define REDBLK_T product_rb_node_t
#define REDBLK_NAME product_rb
FD_FN_PURE static long product_rb_compare(product_rb_node_t* left, product_rb_node_t* right) {
  for( uint i = 0; i < sizeof(fd_pubkey_t)/sizeof(ulong); ++i ) {
    ulong a = left->key.ul[i];
    ulong b = right->key.ul[i];
    if( a != b ) return (fd_ulong_bswap( a ) < fd_ulong_bswap( b ) ? -1 : 1);
  }
  return 0;
}
#include "../../util/tmpl/fd_redblack.c"

static int
method_getBlockProduction(struct json_values* values, fd_rpc_ctx_t * ctx) {
  (void)values;
  fd_rpc_global_ctx_t * glob = ctx->global;
  fd_webserver_t * ws = &glob->ws;
  FD_SPAD_FRAME_BEGIN( ctx->global->spad ) {
    ulong startslot = 0;
    ulong endslot = 0;

    fd_multi_epoch_leaders_lsched_sorted_t lscheds = fd_multi_epoch_leaders_get_sorted_lscheds( glob->leaders );

    ulong slots_in_leaders = (lscheds.lscheds[0] ? lscheds.lscheds[0]->slot_cnt : 0UL) +
                             (lscheds.lscheds[1] ? lscheds.lscheds[1]->slot_cnt : 0UL);
    ulong worst_case_n = fd_ulong_min( slots_in_leaders, (endslot - startslot) / 4UL + 1UL );

    void * shmem = fd_spad_alloc( glob->spad, product_rb_align(), product_rb_footprint( worst_case_n ) );
    product_rb_node_t * pool = product_rb_join( product_rb_new( shmem, worst_case_n ) );
    product_rb_node_t * root = NULL;

    for( ulong i=0UL; i<2UL; i++ ) {
      const fd_epoch_leaders_t * lsched = lscheds.lscheds[i];
      if( !lsched ) continue;

      ulong const start_slot_in_epoch = fd_ulong_max( startslot, lsched->slot0 );
      ulong const end_slot_in_epoch   = fd_ulong_min( endslot+1, lsched->slot0 + lsched->slot_cnt );
      /* we're guaranteed start_slot_in_epoch <= end_slot_in_epoch */

      for( ulong j=start_slot_in_epoch; j<end_slot_in_epoch; j++ ) {
        fd_pubkey_t const * slot_leader = fd_epoch_leaders_get( lsched, j );
        if( slot_leader ) {
          product_rb_node_t key;
          fd_memcpy( key.key.uc, slot_leader->uc, sizeof(fd_pubkey_t) );
          product_rb_node_t * nd = product_rb_find( pool, root, &key );
          if( !nd ) {
            nd = product_rb_acquire( pool );
            fd_memcpy( nd->key.uc, slot_leader->uc, sizeof(fd_pubkey_t) );
            nd->nproduced = nd->nleader = 0;
            product_rb_insert( pool, &root, nd );
          }
          nd->nleader++;
          if( fd_rpc_history_get_block_info(ctx->global->history, j) ) {
            nd->nproduced++;
          }
        }
      }
    }

    fd_web_reply_sprintf(ws, "{\"jsonrpc\":\"2.0\",\"result\":{\"context\":{\"apiVersion\":\"" FIREDANCER_VERSION "\",\"slot\":%lu},\"value\":{\"byIdentity\":{",
                         fd_rpc_history_latest_slot( glob->history ) );
    int first=1;
    for ( product_rb_node_t* nd = product_rb_minimum(pool, root); nd; nd = product_rb_successor(pool, nd) ) {
      char str[50];
      fd_base58_encode_32(nd->key.uc, 0, str);
      fd_web_reply_sprintf(ws, "%s\"%s\":[%u,%u]", (first ? "" : ","), str, nd->nleader, nd->nproduced);
      first=0;
    }
    fd_web_reply_sprintf(ws, "},\"range\":{\"firstSlot\":%lu,\"lastSlot\":%lu}}},\"id\":%s}" CRLF,
                         startslot, endslot, ctx->call_id);
  } FD_SPAD_FRAME_END;
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

  if (startslotn < fd_rpc_history_first_slot( ctx->global->history ))
    startslotn = fd_rpc_history_first_slot( ctx->global->history );
  if (endslotn > fd_rpc_history_latest_slot( ctx->global->history ))
    endslotn = fd_rpc_history_latest_slot( ctx->global->history );

  fd_web_reply_sprintf(ws, "{\"jsonrpc\":\"2.0\",\"result\":[");
  uint cnt = 0;
  for ( ulong i = startslotn; i <= endslotn && cnt < 500000U; ++i ) {
    fd_replay_notif_msg_t * info = fd_rpc_history_get_block_info( ctx->global->history, i );
    if( info == NULL ) continue;
    fd_web_reply_sprintf(ws, "%s%lu", (cnt==0 ? "" : ","), i);
    ++cnt;
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

  if (startslotn < fd_rpc_history_first_slot( ctx->global->history ))
    startslotn = fd_rpc_history_first_slot( ctx->global->history );
  if (limitn > 500000)
    limitn = 500000;

  fd_web_reply_sprintf(ws, "{\"jsonrpc\":\"2.0\",\"result\":[");
  uint cnt = 0;
  for ( ulong i = startslotn; i <= fd_rpc_history_latest_slot( ctx->global->history ) && cnt < limitn; ++i ) {
    fd_replay_notif_msg_t * info = fd_rpc_history_get_block_info( ctx->global->history, i );
    if( info == NULL ) continue;
    fd_web_reply_sprintf(ws, "%s%lu", (cnt==0 ? "" : ","), i);
    ++cnt;
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

  fd_replay_notif_msg_t * info = fd_rpc_history_get_block_info( ctx->global->history, slotn );
  if( info == NULL ) {
    fd_method_error(ctx, -1, "invalid slot: %lu", slotn);
    return 0;
  }

  fd_web_reply_sprintf(ws, "{\"jsonrpc\":\"2.0\",\"result\":%ld,\"id\":%s}" CRLF,
                       (long)info->slot_exec.ts/(long)1e9,
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
  FD_SPAD_FRAME_BEGIN( ctx->global->spad ) {
    fd_webserver_t * ws   = &ctx->global->ws;
    ulong            slot = get_slot_from_commitment_level( values, ctx );
    fd_replay_notif_msg_t * info = fd_rpc_history_get_block_info( ctx->global->history, slot );
    if( info == NULL ) {
      fd_method_error(ctx, -1, "unable to find slot info");
      return 0;
    }
    fd_funk_txn_map_t * map = fd_funk_txn_map( ctx->global->funk );
    fd_funk_txn_xid_t xid;
    xid.ul[0] = xid.ul[1] = slot;
    fd_funk_txn_t * txn = fd_funk_txn_query( &xid, map );
    fd_epoch_schedule_t epoch_schedule_out[1];
    fd_epoch_schedule_t * epoch_schedule = fd_sysvar_epoch_schedule_read( ctx->global->funk, txn, epoch_schedule_out );
    if( epoch_schedule == NULL ) {
      fd_method_error(ctx, -1, "unable to find epoch schedule");
      return 0;
    }
    fd_web_reply_sprintf(ws, "{\"jsonrpc\":\"2.0\",\"result\":{\"absoluteSlot\":%lu,\"blockHeight\":%lu,\"epoch\":%lu,\"slotIndex\":%lu,\"slotsInEpoch\":%lu,\"transactionCount\":%lu},\"id\":%s}" CRLF,
                         slot,
                         info->slot_exec.height,
                         info->slot_exec.epoch,
                         info->slot_exec.slot_in_epoch,
                         epoch_schedule->slots_per_epoch,
                         info->slot_exec.transaction_count,
                         ctx->call_id);
  } FD_SPAD_FRAME_END;
  return 0;
}

// Implementation of the "getEpochSchedule" methods
// curl http://localhost:8123 -X POST -H "Content-Type: application/json" -d ' {"jsonrpc":"2.0","id":1, "method":"getEpochSchedule"} '

static int
method_getEpochSchedule(struct json_values* values, fd_rpc_ctx_t * ctx) {
  FD_SPAD_FRAME_BEGIN( ctx->global->spad ) {
    fd_webserver_t * ws = &ctx->global->ws;
    fd_funk_txn_map_t * map = fd_funk_txn_map( ctx->global->funk );
    ulong slot = get_slot_from_commitment_level( values, ctx );
    fd_funk_txn_xid_t xid;
    xid.ul[0] = xid.ul[1] = slot;
    fd_funk_txn_t * txn = fd_funk_txn_query( &xid, map );
    fd_epoch_schedule_t epoch_schedule_out[1];
    fd_epoch_schedule_t * epoch_schedule = fd_sysvar_epoch_schedule_read( ctx->global->funk, txn, epoch_schedule_out );
    if( epoch_schedule == NULL ) {
      fd_method_error(ctx, -1, "unable to find epoch schedule");
      return 0;
    }
    fd_web_reply_sprintf(ws, "{\"jsonrpc\":\"2.0\",\"result\":{\"firstNormalEpoch\":%lu,\"firstNormalSlot\":%lu,\"leaderScheduleSlotOffset\":%lu,\"slotsPerEpoch\":%lu,\"warmup\":%s},\"id\":%s}" CRLF,
                         epoch_schedule->first_normal_epoch,
                         epoch_schedule->first_normal_slot,
                         epoch_schedule->leader_schedule_slot_offset,
                         epoch_schedule->slots_per_epoch,
                         (epoch_schedule->warmup ? "true" : "false"),
                         ctx->call_id);
  } FD_SPAD_FRAME_END;
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
                       fd_rpc_history_latest_slot( ctx->global->history ), ctx->call_id);
  return 0;
}

// Implementation of the "getFirstAvailableBlock" methods
// curl http://localhost:8123 -X POST -H "Content-Type: application/json" -d '{"jsonrpc":"2.0","id":1,"method":"getFirstAvailableBlock"}'

static int
method_getFirstAvailableBlock(struct json_values* values, fd_rpc_ctx_t * ctx) {
  (void) values;
  fd_webserver_t * ws = &ctx->global->ws;
  fd_web_reply_sprintf(ws, "{\"jsonrpc\":\"2.0\",\"result\":%lu,\"id\":%s}" CRLF,
                       fd_rpc_history_first_slot( ctx->global->history ), ctx->call_id); /* FIXME archival file */
  return 0;
}

// Implementation of the "getGenesisHash" methods
// curl http://localhost:8123 -X POST -H "Content-Type: application/json" -d ' {"jsonrpc":"2.0","id":1, "method":"getGenesisHash"} '

static int
method_getGenesisHash(struct json_values* values, fd_rpc_ctx_t * ctx) {
  (void)values;
  FD_SPAD_FRAME_BEGIN( ctx->global->spad ) {
    fd_webserver_t * ws = &ctx->global->ws;
    fd_web_reply_sprintf(ws, "{\"jsonrpc\":\"2.0\",\"result\":\"11111111111111111111111111111111\",\"id\":%s}" CRLF, ctx->call_id);
  } FD_SPAD_FRAME_END;
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
  fd_webserver_t * ws = &ctx->global->ws;
  if( !ctx->global->identity_key ) return 1; /* not supported */
  fd_web_reply_sprintf(ws, "{\"jsonrpc\":\"2.0\",\"result\":{\"identity\":\"");
  fd_web_reply_encode_base58(ws, ctx->global->identity_key, sizeof(fd_pubkey_t));
  fd_web_reply_sprintf(ws, "\"},\"id\":%s}" CRLF, ctx->call_id);
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
  fd_webserver_t * ws = &ctx->global->ws;
  ulong slot = get_slot_from_commitment_level( values, ctx );
  fd_replay_notif_msg_t * info = fd_rpc_history_get_block_info(ctx->global->history, slot);
  fd_web_reply_sprintf(ws, "{\"jsonrpc\":\"2.0\",\"result\":{\"context\":{\"apiVersion\":\"" FIREDANCER_VERSION "\",\"slot\":%lu},\"value\":{\"blockhash\":\"",
                       info->slot_exec.slot);
  fd_web_reply_encode_base58(ws, &info->slot_exec.block_hash, sizeof(fd_hash_t));
  fd_web_reply_sprintf(ws, "\",\"lastValidBlockHeight\":%lu}},\"id\":%s}" CRLF,
                       info->slot_exec.height, ctx->call_id);
  return 0;
}

// Implementation of the "getLeaderSchedule" methods

struct leader_rb_node {
    fd_pubkey_t key;
    uint first, last;
    ulong redblack_parent;
    ulong redblack_left;
    ulong redblack_right;
    int redblack_color;
};
typedef struct leader_rb_node leader_rb_node_t;
#define REDBLK_T leader_rb_node_t
#define REDBLK_NAME leader_rb
FD_FN_PURE static long leader_rb_compare(leader_rb_node_t* left, leader_rb_node_t* right) {
  for( uint i = 0; i < sizeof(fd_pubkey_t)/sizeof(ulong); ++i ) {
    ulong a = left->key.ul[i];
    ulong b = right->key.ul[i];
    if( a != b ) return (fd_ulong_bswap( a ) < fd_ulong_bswap( b ) ? -1 : 1);
  }
  return 0;
}
#include "../../util/tmpl/fd_redblack.c"

static int
method_getLeaderSchedule(struct json_values* values, fd_rpc_ctx_t * ctx) {
  (void)values;

  FD_SPAD_FRAME_BEGIN( ctx->global->spad ) {
    fd_webserver_t * ws = &ctx->global->ws;

    ulong slot = get_slot_from_commitment_level( values, ctx );
    fd_epoch_leaders_t const * leaders = fd_multi_epoch_leaders_get_lsched_for_slot( ctx->global->leaders, slot );
    if( FD_UNLIKELY( !leaders ) ) {
      fd_method_error(ctx, -1, "unable to get leaders for slot %lu", slot);
      return 0;
    }

    /* Reorganize the map to index on sorted leader key */
    void * shmem = fd_spad_alloc( ctx->global->spad, leader_rb_align(), leader_rb_footprint( leaders->pub_cnt ) );
    leader_rb_node_t * pool = leader_rb_join( leader_rb_new( shmem, leaders->pub_cnt ) );
    leader_rb_node_t * root = NULL;
    uint * nexts = (uint*)fd_spad_alloc( ctx->global->spad, alignof(uint), sizeof(uint) * leaders->sched_cnt );
    for( uint i = 0; i < leaders->sched_cnt; ++i ) {
      fd_pubkey_t * pk = leaders->pub + leaders->sched[i];
      leader_rb_node_t key;
      fd_memcpy( key.key.uc, pk->uc, sizeof(fd_pubkey_t) );
      leader_rb_node_t * nd = leader_rb_find( pool, root, &key );
      if( nd ) {
        nexts[nd->last] = i;
        nd->last = i;
        nexts[i] = UINT_MAX;
      } else {
        nd = leader_rb_acquire( pool );
        fd_memcpy( nd->key.uc, pk->uc, sizeof(fd_pubkey_t) );
        nd->first = nd->last = i;
        nexts[i] = UINT_MAX;
        leader_rb_insert( pool, &root, nd );
      }
    }

    fd_web_reply_sprintf(ws, "{\"jsonrpc\":\"2.0\",\"result\":{");

    int first=1;
    for ( leader_rb_node_t* nd = leader_rb_minimum(pool, root); nd; nd = leader_rb_successor(pool, nd) ) {
      char str[50];
      fd_base58_encode_32(nd->key.uc, 0, str);
      fd_web_reply_sprintf(ws, "%s\"%s\":[", (first ? "" : ","), str);
      first=0;
      int first2=1;
      for( uint i = nd->first; i != UINT_MAX; i = nexts[i] ) {
        fd_web_reply_sprintf(ws, "%s%u,%u,%u,%u", (first2 ? "" : ","), i*4, i*4+1, i*4+2, i*4+3);
        first2=0;
      }
      fd_web_reply_sprintf(ws, "]");
    }

    fd_web_reply_sprintf(ws, "},\"id\":%s}" CRLF, ctx->call_id);
  } FD_SPAD_FRAME_END;
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
  ulong slot = 0;
  fd_webserver_t * ws = &ctx->global->ws;
  fd_web_reply_sprintf(ws, "{\"jsonrpc\":\"2.0\",\"result\":%lu,\"id\":%s}" CRLF,
                       slot, ctx->call_id); /* FIXME archival file */
  return 0;
}

// Implementation of the "getMinimumBalanceForRentExemption" methods
// curl http://localhost:8123 -X POST -H "Content-Type: application/json" -d ' {"jsonrpc": "2.0", "id": 1, "method": "getMinimumBalanceForRentExemption", "params": [50]} '

static int
method_getMinimumBalanceForRentExemption(struct json_values* values, fd_rpc_ctx_t * ctx) {
  FD_SPAD_FRAME_BEGIN( ctx->global->spad ) {
    static const uint PATH_SIZE[3] = {
      (JSON_TOKEN_LBRACE<<16) | KEYW_JSON_PARAMS,
      (JSON_TOKEN_LBRACKET<<16) | 0,
      (JSON_TOKEN_INTEGER<<16)
    };
    ulong size_sz = 0;
    const void* size = json_get_value(values, PATH_SIZE, 3, &size_sz);
    ulong sizen = (size == NULL ? 0UL : (ulong)(*(long*)size));
    (void)sizen;
    // ulong min_balance = fd_rent_exempt_minimum_balance( &epoch_bank->rent, sizen );
    ulong min_balance = 0UL;

    fd_webserver_t * ws = &ctx->global->ws;
    fd_web_reply_sprintf(ws, "{\"jsonrpc\":\"2.0\",\"result\":%lu,\"id\":%s}" CRLF,
                         min_balance, ctx->call_id);
  } FD_SPAD_FRAME_END;
  return 0;
}

// Implementation of the "getMultipleAccounts" method
// curl http://localhost:8123 -X POST -H "Content-Type: application/json" -d ' {"jsonrpc": "2.0", "id": 1, "method": "getMultipleAccounts", "params": [["Cwg1f6m4m3DGwMEbmsbAfDtUToUf5jRdKrJSGD7GfZCB", "Cwg1f6m4m3DGwMEbmsbAfDtUToUf5jRdKrJSGD7GfZCB", "7935owQYeYk1H6HjzKRYnT1aZpf1uXcpZNYjgTZ8q7VR"], {"encoding": "base64"}]} '

static int
method_getMultipleAccounts(struct json_values* values, fd_rpc_ctx_t * ctx) {
  FD_SPAD_FRAME_BEGIN( ctx->global->spad ) {
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
                         fd_rpc_history_latest_slot( ctx->global->history ));

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
      FD_SPAD_FRAME_BEGIN( ctx->global->spad ) {
        ulong val_sz;
        fd_funk_rec_key_t recid = fd_funk_acc_key(&acct);
        const void * val        = read_account(ctx, &recid, &val_sz);
        if (val == NULL) {
          fd_web_reply_sprintf(ws, "null");
          continue;
        }

        const char * err = fd_account_to_json( ws, acct, enc, val, val_sz, FD_LONG_UNSET, FD_LONG_UNSET, ctx->global->spad );
        if( err ) {
          fd_method_error(ctx, -1, "%s", err);
          return 0;
        }
      } FD_SPAD_FRAME_END;
    }

    fd_web_reply_sprintf(ws, "]},\"id\":%s}" CRLF, ctx->call_id);
  } FD_SPAD_FRAME_END;
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
  fd_webserver_t * ws = &ctx->global->ws;

  FD_SPAD_FRAME_BEGIN( ctx->global->spad ) {
    // Path to argument
    static const uint PATH[3] = {
      (JSON_TOKEN_LBRACE<<16) | KEYW_JSON_PARAMS,
      (JSON_TOKEN_LBRACKET<<16) | 0,
      (JSON_TOKEN_STRING<<16)
    };
    ulong arg_sz = 0;
    const void* arg = json_get_value(values, PATH, 3, &arg_sz);
    if (arg == NULL) {
      fd_method_error(ctx, -1, "getSignaturesForAddress requires a string as first parameter");
      return 0;
    }
    fd_pubkey_t acct;
    if( fd_base58_decode_32((const char *)arg, acct.uc) == NULL ) {
      fd_method_error(ctx, -1, "invalid base58 encoding");
      return 0;
    }

    ulong slot_max = get_slot_from_commitment_level( values, ctx );
    if( slot_max == ULONG_MAX ) return 0;

    static const uint PATH2[4] = {
      (JSON_TOKEN_LBRACE<<16) | KEYW_JSON_PARAMS,
      (JSON_TOKEN_LBRACKET<<16) | 1,
      (JSON_TOKEN_LBRACE<<16) | KEYW_JSON_LIMIT,
      (JSON_TOKEN_INTEGER<<16)
    };
    ulong limit_sz = 0;
    const void* limit_ptr = json_get_value(values, PATH2, 4, &limit_sz);
    ulong limit = ( limit_ptr ? fd_ulong_min( *(const ulong*)limit_ptr, 1000U ) : 1000U );

    fd_web_reply_sprintf(ws, "{\"jsonrpc\":\"2.0\",\"result\":[");
    fd_rpc_global_ctx_t * gctx = ctx->global;
    fd_rpc_txn_key_t sig;
    ulong slot;
    const void * iter = fd_rpc_history_first_txn_for_acct( gctx->history, &acct, &sig, &slot );
    ulong cnt = 0;
    while( iter != NULL && cnt < limit ) {
      if( slot > slot_max ) {
        iter = fd_rpc_history_next_txn_for_acct( gctx->history, &sig, &slot, iter );
        continue;
      }

      if( cnt ) EMIT_SIMPLE(",");

      fd_replay_notif_msg_t * info = fd_rpc_history_get_block_info( ctx->global->history, slot );
      char buf64[FD_BASE58_ENCODED_64_SZ];
      fd_base58_encode_64((uchar const*)&sig, NULL, buf64);
      fd_web_reply_sprintf(ws, "{\"blockTime\":%ld,\"confirmationStatus\":\"%s\",\"err\":null,\"memo\":null,\"signature\":\"%s\",\"slot\":%lu}",
                           (long)info->slot_exec.ts/(long)1e9, get_commitment_level_from_slot(slot, ctx), buf64, slot);

      cnt++;

      iter = fd_rpc_history_next_txn_for_acct( gctx->history, &sig, &slot, iter );
    }
    fd_web_reply_sprintf(ws, "],\"id\":%s}" CRLF, ctx->call_id);

  } FD_SPAD_FRAME_END;

  return 0;
}

// Implementation of the "getSignatureStatuses" methods
// curl http://localhost:8123 -X POST -H "Content-Type: application/json" -d ' {"jsonrpc": "2.0", "id": 1, "method": "getSignatureStatuses", "params": [["4qj8WecUytFE96SFhdiTkc3v2AYLY7795sbSQTnYG7cPL9s6xKNHNyi3wraQc83PsNSgV8yedWbfGa4vRXfzBDzB"], {"searchTransactionHistory": true}]} '

static int
method_getSignatureStatuses(struct json_values* values, fd_rpc_ctx_t * ctx) {
  fd_webserver_t * ws = &ctx->global->ws;
  fd_web_reply_sprintf(ws, "{\"jsonrpc\":\"2.0\",\"result\":{\"context\":{\"apiVersion\":\"" FIREDANCER_VERSION "\",\"slot\":%lu},\"value\":[",
                       fd_rpc_history_latest_slot( ctx->global->history ));

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

    fd_rpc_txn_key_t key;
    if ( fd_base58_decode_64( sig, (uchar*)&key) == NULL ) {
      fd_web_reply_sprintf(ws, "null");
      continue;
    }

    ulong txn_sz;
    ulong slot;
    uchar * txn_data_raw = fd_rpc_history_get_txn( ctx->global->history, &key, &txn_sz, &slot );
    if( txn_data_raw == NULL ) {
      fd_web_reply_sprintf(ws, "null");
      continue;
    }

    // TODO other fields
    fd_web_reply_sprintf(ws, "{\"slot\":%lu,\"confirmations\":null,\"err\":null,\"status\":{\"Ok\":null},\"confirmationStatus\":\"%s\"}",
                         slot, get_commitment_level_from_slot(slot, ctx));
  }

  fd_web_reply_sprintf(ws, "]},\"id\":%s}" CRLF, ctx->call_id);
  return 0;
}

// Implementation of the "getSlot" method
// curl http://localhost:8123 -X POST -H "Content-Type: application/json" -d ' {"jsonrpc":"2.0","id":1, "method":"getSlot"} '

static int
method_getSlot(struct json_values* values, fd_rpc_ctx_t * ctx) {
  fd_webserver_t * ws = &ctx->global->ws;
  ulong slot = get_slot_from_commitment_level( values, ctx );
  fd_web_reply_sprintf(ws, "{\"jsonrpc\":\"2.0\",\"result\":%lu,\"id\":%s}" CRLF,
                       slot, ctx->call_id);
  return 0;
}

// Implementation of the "getSlotLeader" methods
// curl http://localhost:8123 -X POST -H "Content-Type: application/json" -d ' {"jsonrpc":"2.0","id":1, "method":"getSlotLeader"} '

static int
method_getSlotLeader(struct json_values* values, fd_rpc_ctx_t * ctx) {
  fd_webserver_t * ws = &ctx->global->ws;
  fd_web_reply_sprintf(ws, "{\"jsonrpc\":\"2.0\",\"result\":");
  ulong slot = get_slot_from_commitment_level( values, ctx );
  fd_pubkey_t const * slot_leader = fd_multi_epoch_leaders_get_leader_for_slot( ctx->global->leaders, slot );
  if( slot_leader ) {
    char str[50];
    fd_base58_encode_32(slot_leader->uc, 0, str);
    fd_web_reply_sprintf(ws, "\"%s\"", str);
  } else {
    EMIT_SIMPLE("null");
  }
  fd_web_reply_sprintf(ws, ",\"id\":%s}" CRLF, ctx->call_id);
  return 0;
}

// Implementation of the "getSlotLeaders" methods
static int
method_getSlotLeaders(struct json_values* values, fd_rpc_ctx_t * ctx) {
  static const uint PATH_SLOT[3] = {
    (JSON_TOKEN_LBRACE<<16) | KEYW_JSON_PARAMS,
    (JSON_TOKEN_LBRACKET<<16) | 0,
    (JSON_TOKEN_INTEGER<<16)
  };
  fd_webserver_t * ws = &ctx->global->ws;
  ulong startslot_sz = 0;
  const void* startslot = json_get_value(values, PATH_SLOT, 3, &startslot_sz);
  if (startslot == NULL) {
    fd_method_error(ctx, -1, "getSlotLeaders requires a start slot number as first parameter");
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
    fd_method_error(ctx, -1, "getSlotLeaders requires a limit as second parameter");
    return 0;
  }
  ulong limitn = (ulong)(*(long*)limit);
  if (limitn > 5000)
    limitn = 5000;

  fd_web_reply_sprintf(ws, "{\"jsonrpc\":\"2.0\",\"result\":[");
  fd_epoch_leaders_t const * lsched = fd_multi_epoch_leaders_get_lsched_for_slot( ctx->global->leaders, startslotn );
  if( lsched ) {
    for ( ulong i = startslotn; i < startslotn + limitn; ++i ) {
      if( i > startslotn ) EMIT_SIMPLE(",");
      fd_pubkey_t const * slot_leader = fd_epoch_leaders_get( lsched, i );
      if( slot_leader ) {
        char str[50];
        fd_base58_encode_32(slot_leader->uc, 0, str);
        fd_web_reply_sprintf(ws, "\"%s\"", str);
      } else {
        EMIT_SIMPLE("null");
      }
    }
  }
  fd_web_reply_sprintf(ws, "],\"id\":%s}" CRLF, ctx->call_id);

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
  fd_webserver_t * ws = &ctx->global->ws;
  fd_web_reply_sprintf(ws, "{\"jsonrpc\":\"2.0\",\"result\":{\"context\":{\"apiVersion\":\"" FIREDANCER_VERSION "\",\"slot\":%lu},\"value\":{\"circulating\":%lu,\"nonCirculating\":%lu,\"total\":%lu,\"nonCirculatingAccounts\":[]}},\"id\":%s}" CRLF,
                       fd_rpc_history_latest_slot( ctx->global->history ),
                       0UL, // ctx->global->supply.circulating,
                       0UL, // ctx->global->supply.non_circulating,
                       0UL, // ctx->global->supply.total,
                       ctx->call_id);
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

  ulong slot_max = get_slot_from_commitment_level( values, ctx );
  if( slot_max == ULONG_MAX ) return 0;

  fd_rpc_txn_key_t key;
  if ( fd_base58_decode_64( sig, (uchar*)&key) == NULL ) {
    fd_web_reply_sprintf(ws, "{\"jsonrpc\":\"2.0\",\"result\":null,\"id\":%s}" CRLF, ctx->call_id);
    return 0;
  }
  ulong txn_sz;
  ulong slot;
  uchar * txn_data_raw = fd_rpc_history_get_txn( ctx->global->history, &key, &txn_sz, &slot );
  if( txn_data_raw == NULL || slot > slot_max ) {
    fd_web_reply_sprintf(ws, "{\"jsonrpc\":\"2.0\",\"result\":null,\"id\":%s}" CRLF, ctx->call_id);
    return 0;
  }
  uchar txn_out[FD_TXN_MAX_SZ];
  ulong pay_sz = 0;
  ulong txn_sz2 = fd_txn_parse_core(txn_data_raw, txn_sz, txn_out, NULL, &pay_sz);
  if ( txn_sz2 == 0 || txn_sz2 > FD_TXN_MAX_SZ || txn_sz != pay_sz ) {
    FD_LOG_ERR(("failed to parse transaction"));
  }

  fd_replay_notif_msg_t * info = fd_rpc_history_get_block_info( ctx->global->history, slot );

  fd_web_reply_sprintf(ws, "{\"jsonrpc\":\"2.0\",\"result\":{\"context\":{\"apiVersion\":\"" FIREDANCER_VERSION "\",\"slot\":%lu},\"blockTime\":%ld,\"slot\":%lu,",
                       fd_rpc_history_latest_slot( ctx->global->history ), (long)info->slot_exec.ts/(long)1e9, slot);

  const char * err = fd_txn_to_json( ws, (fd_txn_t *)txn_out, txn_data_raw, pay_sz, enc, 0, FD_BLOCK_DETAIL_FULL, ctx->global->spad );
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
  FD_SPAD_FRAME_BEGIN( ctx->global->spad ) {
    (void)values;
    fd_webserver_t * ws = &ctx->global->ws;

    ulong                   slot = get_slot_from_commitment_level( values, ctx );
    fd_replay_notif_msg_t * info = fd_rpc_history_get_block_info( ctx->global->history, slot );
    if( FD_UNLIKELY( !info ) ) {
      fd_method_error( ctx, -1, "slot bank %lu not found", slot );
      return 0;
    }
    fd_web_reply_sprintf( ws,
                          "{\"jsonrpc\":\"2.0\",\"result\":%lu,\"id\":%s}" CRLF,
                          info->slot_exec.transaction_count,
                          ctx->call_id );
  } FD_SPAD_FRAME_END;
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

static int
method_getVoteAccounts(struct json_values* values, fd_rpc_ctx_t * ctx) {
  fd_rpc_global_ctx_t * glob = ctx->global;
  FD_SPAD_FRAME_BEGIN( glob->spad ) {
    fd_webserver_t * ws = &glob->ws;
    fd_web_reply_sprintf(ws, "{\"jsonrpc\":\"2.0\",\"result\":{\"current\":[");

    uint path[4] = {
      (JSON_TOKEN_LBRACE<<16) | KEYW_JSON_PARAMS,
      (uint) ((JSON_TOKEN_LBRACKET<<16) | 0),
      (JSON_TOKEN_LBRACE<<16) | KEYW_JSON_VOTEPUBKEY,
      (JSON_TOKEN_STRING<<16)
    };
    ulong arg_sz = 0;
    const void* filter_arg = json_get_value(values, path, 4, &arg_sz);
    fd_hash_t filter_key = {0};
    if( filter_arg != NULL ) {
      if( fd_base58_decode_32((const char *)filter_arg, filter_key.uc) == NULL ) {
        fd_method_error(ctx, -1, "invalid base58 encoding");
        return 0;
      }
    }

    if( !glob->replay_towers_eom ) {
      fd_method_error( ctx, -1, "vote accounts are not ready" );
      return 0;
    }

    int needcomma = 0;
    for( ulong i=0UL; i<glob->replay_towers_cnt; i++ ) {
      fd_replay_tower_t const * w = &glob->replay_towers[i];
      if( filter_arg != NULL ) {
        if( !fd_hash_eq( &w->key, &filter_key ) ) continue;
      }
      if( needcomma ) fd_web_reply_sprintf(ws, ",");

      fd_bincode_decode_ctx_t ctx = {
        .data    = w->acc,
        .dataend = w->acc + w->acc_sz,
      };
      ulong total_sz = 0UL;
      int err = fd_vote_state_versioned_decode_footprint( &ctx, &total_sz );
      if( FD_UNLIKELY( err ) ) {
        FD_LOG_CRIT(( "unable to decode vote state versioned" ));
        continue;
      }
      uchar mem[total_sz];
      fd_vote_state_versioned_t * vsv = fd_vote_state_versioned_decode( mem, &ctx );

      fd_pubkey_t node_account;
      uchar       commission;
      ulong       root_slot;
      ulong       last_vote_slot;
      ulong       credits_cnt = 0UL;
      ushort      epoch[EPOCH_CREDITS_MAX];
      ulong       credits[EPOCH_CREDITS_MAX];
      ulong       prev_credits[EPOCH_CREDITS_MAX];

      fd_vote_epoch_credits_t * epoch_credits = NULL;

      switch( vsv->discriminant ) {
      case fd_vote_state_versioned_enum_v0_23_5:
        node_account        = vsv->inner.v0_23_5.node_pubkey;
        commission          = vsv->inner.v0_23_5.commission;
        root_slot           = vsv->inner.v0_23_5.root_slot;
        last_vote_slot      = vsv->inner.v0_23_5.last_timestamp.slot;
        epoch_credits       = vsv->inner.v0_23_5.epoch_credits;
        for( deq_fd_vote_epoch_credits_t_iter_t iter = deq_fd_vote_epoch_credits_t_iter_init( epoch_credits );
             !deq_fd_vote_epoch_credits_t_iter_done( epoch_credits, iter );
             iter = deq_fd_vote_epoch_credits_t_iter_next( epoch_credits, iter ) ) {
          fd_vote_epoch_credits_t * ele = deq_fd_vote_epoch_credits_t_iter_ele( epoch_credits, iter );
          epoch[credits_cnt]        = (ushort)ele->epoch;
          credits[credits_cnt]      = ele->credits;
          prev_credits[credits_cnt] = ele->prev_credits;
          credits_cnt++;
        }
        break;

      case fd_vote_state_versioned_enum_v1_14_11:
        node_account        = vsv->inner.v1_14_11.node_pubkey;
        commission          = vsv->inner.v1_14_11.commission;
        root_slot           = vsv->inner.v1_14_11.root_slot;
        last_vote_slot      = vsv->inner.v1_14_11.last_timestamp.slot;
        epoch_credits       = vsv->inner.v1_14_11.epoch_credits;
        for( deq_fd_vote_epoch_credits_t_iter_t iter = deq_fd_vote_epoch_credits_t_iter_init( epoch_credits );
             !deq_fd_vote_epoch_credits_t_iter_done( epoch_credits, iter );
             iter = deq_fd_vote_epoch_credits_t_iter_next( epoch_credits, iter ) ) {
          fd_vote_epoch_credits_t * ele = deq_fd_vote_epoch_credits_t_iter_ele( epoch_credits, iter );
          epoch[credits_cnt]        = (ushort)ele->epoch;
          credits[credits_cnt]      = ele->credits;
          prev_credits[credits_cnt] = ele->prev_credits;
          credits_cnt++;
        }
        break;

      case fd_vote_state_versioned_enum_current:
        node_account        = vsv->inner.current.node_pubkey;
        commission          = vsv->inner.current.commission;
        root_slot           = vsv->inner.current.root_slot;
        last_vote_slot      = vsv->inner.current.last_timestamp.slot;
        epoch_credits       = vsv->inner.current.epoch_credits;
        for( deq_fd_vote_epoch_credits_t_iter_t iter = deq_fd_vote_epoch_credits_t_iter_init( epoch_credits );
             !deq_fd_vote_epoch_credits_t_iter_done( epoch_credits, iter );
             iter = deq_fd_vote_epoch_credits_t_iter_next( epoch_credits, iter ) ) {
          fd_vote_epoch_credits_t * ele = deq_fd_vote_epoch_credits_t_iter_ele( epoch_credits, iter );
          epoch[credits_cnt]        = (ushort)ele->epoch;
          credits[credits_cnt]      = ele->credits;
          prev_credits[credits_cnt] = ele->prev_credits;
          credits_cnt++;
        }
        break;

      default:
        FD_LOG_CRIT(( "[%s] unknown vote state version. discriminant %u", __func__, vsv->discriminant ));
        __builtin_unreachable();
      }

      char vote_account_s[50];
      fd_base58_encode_32(w->key.uc, 0, vote_account_s);
      char node_account_s[50];
      fd_base58_encode_32(node_account.uc, 0, node_account_s);
      fd_web_reply_sprintf(ws, "{\"activatedStake\":%lu,\"commission\":%u,\"epochVoteAccount\":true,\"epochCredits\":[",
                           w->stake, (uint)commission);
      for( ulong j=(credits_cnt >= 5U ? credits_cnt - 5U : 0UL); j<credits_cnt; j++ ) {
        fd_web_reply_sprintf(ws, "[%u,%lu,%lu]", epoch[j], credits[j], prev_credits[j]);
        if( j < credits_cnt - 1 ) fd_web_reply_sprintf(ws, ",");
      }
      fd_web_reply_sprintf(ws, "],\"nodePubkey\":\"%s\",\"lastVote\":%lu,\"votePubkey\":\"%s\",\"rootSlot\":%lu}",
                           node_account_s, last_vote_slot, vote_account_s, root_slot);

      needcomma = 1;
    }

    fd_web_reply_sprintf(ws, "]},\"id\":%s}" CRLF, ctx->call_id);
  } FD_SPAD_FRAME_END;
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

  fd_replay_notif_msg_t * info = fd_rpc_history_get_block_info_by_hash( ctx->global->history, &h );

  fd_web_reply_sprintf(ws, "{\"jsonrpc\":\"2.0\",\"result\":{\"context\":{\"slot\":%lu},\"value\":%s},\"id\":%s}" CRLF,
                       fd_rpc_history_latest_slot( ctx->global->history ), (info ? "true" : "false"), ctx->call_id);

  return 0;
}

// Implementation of the "minimumLedgerSlot" methods
static int
method_minimumLedgerSlot(struct json_values* values, fd_rpc_ctx_t * ctx) {
  (void) values;
  fd_webserver_t * ws = &ctx->global->ws;
  ulong slot = 0;
  fd_web_reply_sprintf(ws, "{\"jsonrpc\":\"2.0\",\"result\":%lu,\"id\":%s}" CRLF,
                       slot, ctx->call_id); /* FIXME archival file */
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
    snprintf(ctx.call_id, sizeof(ctx.call_id)-1, "%lu", *(ulong*)arg); /* TODO check signedness of arg */
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
}

static int
ws_method_accountSubscribe(ulong conn_id, struct json_values * values, fd_rpc_ctx_t * ctx) {
  fd_webserver_t * ws = &ctx->global->ws;

  FD_SPAD_FRAME_BEGIN( ctx->global->spad ) {
    // Path to argument
    static const uint PATH[3] = {
      (JSON_TOKEN_LBRACE<<16) | KEYW_JSON_PARAMS,
      (JSON_TOKEN_LBRACKET<<16) | 0,
      (JSON_TOKEN_STRING<<16)
    };
    ulong arg_sz = 0;
    const void* arg = json_get_value(values, PATH, 3, &arg_sz);
    if (arg == NULL) {
      fd_method_simple_error( ctx, -1, "getAccountInfo requires a string as first parameter" );
      return 0;
    }
    fd_pubkey_t acct;
    if( fd_base58_decode_32((const char *)arg, acct.uc) == NULL ) {
      fd_method_simple_error(ctx, -1, "invalid base58 encoding");
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
        fd_method_simple_error(ctx, -1, "cannot use jsonParsed encoding with slice");
        return 0;
      }
    }

    fd_rpc_global_ctx_t * subs = ctx->global;
    if( subs->sub_cnt >= FD_WS_MAX_SUBS ) {
      fd_method_simple_error(ctx, -1, "too many subscriptions");
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

    fd_web_reply_sprintf(ws, "{\"jsonrpc\":\"2.0\",\"result\":%lu,\"id\":%s}" CRLF,
                         subid, sub->call_id);

  } FD_SPAD_FRAME_END;

  return 1;
}

static int
ws_method_accountSubscribe_update(fd_rpc_ctx_t * ctx, fd_replay_notif_msg_t * msg, struct fd_ws_subscription * sub) {
  fd_webserver_t * ws = &ctx->global->ws;
  fd_web_reply_new( ws );

  FD_SPAD_FRAME_BEGIN( ctx->global->spad ) {
    ulong val_sz;
    fd_funk_rec_key_t recid = fd_funk_acc_key(&sub->acct_subscribe.acct);
    fd_funk_txn_xid_t xid;
    xid.ul[0] = xid.ul[1] = msg->slot_exec.slot;
    const void * val = read_account_with_xid(ctx, &recid, &xid, &val_sz);
    if (val == NULL) {
      /* Account not in tranaction */
      return 0;
    }

    fd_web_reply_sprintf(ws, "{\"jsonrpc\":\"2.0\",\"method\":\"accountNotification\",\"params\":{\"result\":{\"context\":{\"apiVersion\":\"" FIREDANCER_VERSION "\",\"slot\":%lu},\"value\":",
                         msg->slot_exec.slot);
    const char * err = fd_account_to_json( ws, sub->acct_subscribe.acct, sub->acct_subscribe.enc, val, val_sz, sub->acct_subscribe.off, sub->acct_subscribe.len, ctx->global->spad );
    if( err ) {
      FD_LOG_WARNING(( "error converting account to json: %s", err ));
      return 0;
    }
    fd_web_reply_sprintf(ws, "},\"subscription\":%lu}}" CRLF, sub->subsc_id);
  } FD_SPAD_FRAME_END;

  return 1;
}

static int
ws_method_slotSubscribe(ulong conn_id, struct json_values * values, fd_rpc_ctx_t * ctx) {
  (void)values;
  fd_webserver_t * ws = &ctx->global->ws;

  fd_rpc_global_ctx_t * subs = ctx->global;
  if( subs->sub_cnt >= FD_WS_MAX_SUBS ) {
    fd_method_simple_error(ctx, -1, "too many subscriptions");
    return 0;
  }
  struct fd_ws_subscription * sub = &subs->sub_list[ subs->sub_cnt++ ];
  sub->conn_id = conn_id;
  sub->meth_id = KEYW_WS_METHOD_SLOTSUBSCRIBE;
  strncpy(sub->call_id, ctx->call_id, sizeof(sub->call_id));
  ulong subid = sub->subsc_id = ++(subs->last_subsc_id);

  fd_web_reply_sprintf(ws, "{\"jsonrpc\":\"2.0\",\"result\":%lu,\"id\":%s}" CRLF,
                       subid, sub->call_id);

  return 1;
}

static int
ws_method_slotSubscribe_update(fd_rpc_ctx_t * ctx, fd_replay_notif_msg_t * msg, struct fd_ws_subscription * sub) {
  fd_webserver_t * ws = &ctx->global->ws;
  fd_web_reply_new( ws );

  char bank_hash[50];
  fd_base58_encode_32(msg->slot_exec.bank_hash.uc, 0, bank_hash);
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
    fd_web_reply_error( ws, -1, "missing jsonrpc member", "null" );
    return 0;
  }
  if (!MATCH_STRING(arg, arg_sz, "2.0")) {
    fd_web_reply_error( ws, -1, "jsonrpc value must be 2.0", "null" );
    return 0;
  }

  static const uint PATH3[2] = {
    (JSON_TOKEN_LBRACE<<16) | KEYW_JSON_ID,
    (JSON_TOKEN_INTEGER<<16)
  };
  arg_sz = 0;
  arg = json_get_value(values, PATH3, 2, &arg_sz);
  if (arg != NULL) {
    snprintf(ctx.call_id, sizeof(ctx.call_id)-1, "%lu", *(ulong*)arg); /* TODO: check signedness of arg */
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
      fd_web_reply_error( ws, -1, "missing id member", "null" );
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
    fd_web_reply_error( ws, -1, "missing method member", ctx.call_id );
    return 0;
  }
  long meth_id = fd_webserver_json_keyword((const char*)arg, arg_sz);

  switch (meth_id) {
  case KEYW_WS_METHOD_ACCOUNTSUBSCRIBE:
    if (ws_method_accountSubscribe(conn_id, values, &ctx)) {
      return 1;
    }
    return 0;
  case KEYW_WS_METHOD_SLOTSUBSCRIBE:
    if (ws_method_slotSubscribe(conn_id, values, &ctx)) {
      return 1;
    }
    return 0;
  }

  char text[4096];
  snprintf( text, sizeof(text), "unknown websocket method: %s", (const char*)arg );
  fd_web_reply_error( ws, -1, text, ctx.call_id );
  return 0;
}

void
fd_rpc_create_ctx(fd_rpcserver_args_t * args, fd_rpc_ctx_t ** ctx_p) {
  fd_rpc_ctx_t * ctx         = (fd_rpc_ctx_t *)fd_spad_alloc( args->spad, alignof(fd_rpc_ctx_t), sizeof(fd_rpc_ctx_t) );
  fd_rpc_global_ctx_t * gctx = (fd_rpc_global_ctx_t *)fd_spad_alloc( args->spad, alignof(fd_rpc_global_ctx_t), sizeof(fd_rpc_global_ctx_t) );
  fd_memset(ctx, 0, sizeof(fd_rpc_ctx_t));
  fd_memset(gctx, 0, sizeof(fd_rpc_global_ctx_t));

  ctx->global   = gctx;
  gctx->spad    = args->spad;

  uchar * mleaders_mem = (uchar *)fd_spad_alloc( args->spad, FD_MULTI_EPOCH_LEADERS_ALIGN, FD_MULTI_EPOCH_LEADERS_FOOTPRINT );
  gctx->leaders = fd_multi_epoch_leaders_join( fd_multi_epoch_leaders_new( mleaders_mem) );

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
    gctx->tpu_addr = args->tpu_addr;

  } else {
    gctx->tpu_socket = -1;
  }

  void * mem = fd_spad_alloc( args->spad, fd_perf_sample_deque_align(), fd_perf_sample_deque_footprint() );
  gctx->perf_samples = fd_perf_sample_deque_join( fd_perf_sample_deque_new( mem ) );
  FD_TEST( gctx->perf_samples );

  gctx->history = fd_rpc_history_create(args);
  gctx->identity_key = &args->identity_key;

  FD_LOG_NOTICE(( "starting web server on port %u", (uint)args->port ));
  if (fd_webserver_start(args->port, args->params, gctx->spad, &gctx->ws, ctx))
    FD_LOG_ERR(("fd_webserver_start failed"));

  *ctx_p = ctx;
}

void
fd_rpc_start_service(fd_rpcserver_args_t * args, fd_rpc_ctx_t * ctx) {
  fd_rpc_global_ctx_t * gctx = ctx->global;
  gctx->funk = args->funk;
  gctx->store = args->store;
}

int
fd_rpc_ws_poll(fd_rpc_ctx_t * ctx) {
  return fd_webserver_poll(&ctx->global->ws);
}

int
fd_rpc_ws_fd(fd_rpc_ctx_t * ctx) {
  return fd_webserver_fd(&ctx->global->ws);
}

void
fd_webserver_ws_closed(ulong conn_id, void * cb_arg) {
  fd_rpc_ctx_t * ctx = ( fd_rpc_ctx_t *)cb_arg;
  fd_rpc_global_ctx_t * subs = ctx->global;
  for( ulong i = 0; i < subs->sub_cnt; ++i ) {
    if( subs->sub_list[i].conn_id == conn_id ) {
      subs->sub_list[i] = subs->sub_list[--(subs->sub_cnt)];
      --i;
    }
  }
}

void
fd_rpc_replay_during_frag( fd_rpc_ctx_t * ctx, void const * msg, int sz ) {
  FD_TEST( sz <= (int)sizeof(ctx->global->buffer) );
  memcpy(ctx->global->buffer, msg, (ulong)sz);
  ctx->global->buffer_sz = sz;
}

void
fd_rpc_replay_after_frag(fd_rpc_ctx_t * ctx) {
  fd_rpc_global_ctx_t * subs = ctx->global;
  if( subs->buffer_sz != (int)sizeof(fd_replay_notif_msg_t) ) return;
  fd_replay_notif_msg_t * msg = (fd_replay_notif_msg_t *)subs->buffer;

  if( msg->type == FD_REPLAY_SLOT_TYPE ) {
    long ts = fd_log_wallclock() / (long)1e9;
    if( FD_UNLIKELY( ts - subs->perf_sample_ts >= 60 ) ) {

      if( FD_UNLIKELY( fd_perf_sample_deque_full( subs->perf_samples ) ) ) {
        fd_perf_sample_deque_pop_head( subs->perf_samples );
      }

      /* Record a new perf sample */

      if( FD_LIKELY( subs->perf_sample_snapshot.highest_slot ) ) {
        ulong diff = msg->slot_exec.transaction_count - subs->perf_sample_snapshot.num_transactions;
        if( diff > 100000000 ) diff = 0; // ignore huge diffs, they are caused by integer overflows
        fd_perf_sample_t perf_sample = { .num_slots = msg->slot_exec.slot - subs->perf_sample_snapshot.highest_slot,
                                         .num_transactions = diff,
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

    fd_rpc_history_save_info( subs->history, msg );

    for( ulong j = 0; j < subs->sub_cnt; ++j ) {
      struct fd_ws_subscription * sub = &subs->sub_list[ j ];
      if( sub->meth_id == KEYW_WS_METHOD_SLOTSUBSCRIBE ) {
        if( ws_method_slotSubscribe_update( ctx, msg, sub ) )
          fd_web_ws_send( &subs->ws, sub->conn_id );
      }
      if( sub->meth_id == KEYW_WS_METHOD_ACCOUNTSUBSCRIBE ) {
        if( ws_method_accountSubscribe_update( ctx, msg, sub ) )
          fd_web_ws_send( &subs->ws, sub->conn_id );
      }
    }
  }
}

void
fd_rpc_stake_during_frag( fd_rpc_ctx_t * ctx, void const * msg, int sz ) {
  (void)sz;
  fd_multi_epoch_leaders_stake_msg_init( ctx->global->leaders, msg );
}

void
fd_rpc_stake_after_frag(fd_rpc_ctx_t * ctx) {
  fd_multi_epoch_leaders_stake_msg_fini( ctx->global->leaders );
}

void
fd_rpc_repair_during_frag(fd_rpc_ctx_t * ctx, void const * msg, int sz) {
  FD_TEST( sz <= (int)sizeof(ctx->global->buffer) );
  memcpy(ctx->global->buffer, msg, (ulong)sz);
  ctx->global->buffer_sz = sz;
}

void
fd_rpc_repair_after_frag(fd_rpc_ctx_t * ctx) {
  fd_rpc_global_ctx_t * subs = ctx->global;
  if( subs->buffer_sz != (int)sizeof(fd_reasm_fec_t) ) return;
  fd_reasm_fec_t * fec_p = (fd_reasm_fec_t *)subs->buffer;
  fd_rpc_history_save_fec( subs->history, subs->store, fec_p );
}

#define MAX_LOCKOUT_HISTORY 31UL

static fd_landed_vote_t *
landed_votes_from_lockouts( fd_vote_lockout_t * lockouts,
                            fd_spad_t *         spad ) {
  if( !lockouts ) return NULL;

  /* Allocate MAX_LOCKOUT_HISTORY (sane case) by default.  In case the
     vote account is corrupt, allocate as many entries are needed. */

  ulong cnt = deq_fd_vote_lockout_t_cnt( lockouts );
        cnt = fd_ulong_max( cnt, MAX_LOCKOUT_HISTORY );
  uchar * deque_mem = fd_spad_alloc( spad,
                                     deq_fd_landed_vote_t_align(),
                                     deq_fd_landed_vote_t_footprint( cnt ) );
  fd_landed_vote_t * landed_votes = deq_fd_landed_vote_t_join( deq_fd_landed_vote_t_new( deque_mem, cnt ) );

  for( deq_fd_vote_lockout_t_iter_t iter = deq_fd_vote_lockout_t_iter_init( lockouts );
       !deq_fd_vote_lockout_t_iter_done( lockouts, iter );
       iter = deq_fd_vote_lockout_t_iter_next( lockouts, iter ) ) {
    fd_vote_lockout_t const * ele = deq_fd_vote_lockout_t_iter_ele_const( lockouts, iter );
    fd_landed_vote_t * elem = deq_fd_landed_vote_t_push_tail_nocopy( landed_votes );
    fd_landed_vote_new( elem );
    elem->latency                    = 0;
    elem->lockout.slot               = ele->slot;
    elem->lockout.confirmation_count = ele->confirmation_count;
  }

  return landed_votes;
}

struct weight_by_slot {
  #define WEIGHT_BY_SLOT_MAX 256UL
  ulong weight[WEIGHT_BY_SLOT_MAX];
  uint cnt;
  ulong first;
};
typedef struct weight_by_slot weight_by_slot_t;

static void
weight_by_slot_init( weight_by_slot_t * wbs ) {
  memset( wbs, 0, sizeof(weight_by_slot_t) );
}

static void
weight_by_slot_add( weight_by_slot_t * wbs, ulong slot, ulong weight ) {
  if( wbs->cnt == 0U ) {
    wbs->first = slot;
    wbs->cnt = 1U;
    wbs->weight[slot & (WEIGHT_BY_SLOT_MAX - 1)] = 0UL;
  } else if( slot < wbs->first ) {
    do {
      if( wbs->cnt == WEIGHT_BY_SLOT_MAX ) {
        return; // Too far back, ignore
      }
      // Extend the queue backwards
      wbs->first--;
      wbs->cnt++;
      wbs->weight[wbs->first & (WEIGHT_BY_SLOT_MAX - 1)] = 0UL;
    } while( slot < wbs->first );
  } else if ( slot >= wbs->first + wbs->cnt ) {
    do {
      if( wbs->cnt < WEIGHT_BY_SLOT_MAX ) {
        wbs->cnt++; // Extend the queue forwards
      } else {
        wbs->first++; // Roll the queue forward
      }
      wbs->weight[(wbs->first + wbs->cnt - 1U) & (WEIGHT_BY_SLOT_MAX - 1)] = 0UL;
    } while( slot >= wbs->first + wbs->cnt );
  }
  FD_TEST( slot >= wbs->first && slot < wbs->first + wbs->cnt && wbs->cnt <= WEIGHT_BY_SLOT_MAX );
  wbs->weight[slot & (WEIGHT_BY_SLOT_MAX - 1)] += weight;
}

static void
fd_rpc_recompute_confirmed( fd_rpc_global_ctx_t * glob ) {
  FD_SPAD_FRAME_BEGIN( glob->spad ) {
    ulong total_stake = 0UL;
    weight_by_slot_t wbs_votes;
    weight_by_slot_init( &wbs_votes );
    weight_by_slot_t wbs_root;
    weight_by_slot_init( &wbs_root );

    for( ulong i=0UL; i<glob->replay_towers_cnt; i++ ) {
      fd_replay_tower_t const * w = &glob->replay_towers[i];

      fd_bincode_decode_ctx_t ctx = {
        .data    = w->acc,
        .dataend = w->acc + w->acc_sz,
      };
      ulong total_sz = 0UL;
      int err = fd_vote_state_versioned_decode_footprint( &ctx, &total_sz );
      if( FD_UNLIKELY( err ) ) {
        FD_LOG_CRIT(( "unable to decode vote state versioned" ));
        continue;
      }
      uchar mem[total_sz];
      fd_vote_state_versioned_t * vsv = fd_vote_state_versioned_decode( mem, &ctx );

      ulong root_slot;
      fd_landed_vote_t * votes; /* fd_deque_dynamic (min cnt 32) */

      switch( vsv->discriminant ) {
      case fd_vote_state_versioned_enum_v0_23_5:
        root_slot = vsv->inner.v0_23_5.root_slot;
        votes     = landed_votes_from_lockouts( vsv->inner.v0_23_5.votes, glob->spad );
        break;

      case fd_vote_state_versioned_enum_v1_14_11:
        root_slot = vsv->inner.v1_14_11.root_slot;
        votes     = landed_votes_from_lockouts( vsv->inner.v1_14_11.votes, glob->spad );
        break;

      case fd_vote_state_versioned_enum_current:
        root_slot = vsv->inner.current.root_slot;
        votes     = vsv->inner.current.votes;
        break;

      default:
        FD_LOG_CRIT(( "[%s] unknown vote state version. discriminant %u", __func__, vsv->discriminant ));
        __builtin_unreachable();
      }

      for( deq_fd_landed_vote_t_iter_t iter = deq_fd_landed_vote_t_iter_init( votes );
           !deq_fd_landed_vote_t_iter_done( votes, iter );
           iter = deq_fd_landed_vote_t_iter_next( votes, iter ) ) {
        fd_landed_vote_t const * ele = deq_fd_landed_vote_t_iter_ele_const( votes, iter );
        weight_by_slot_add( &wbs_votes, ele->lockout.slot, w->stake );
      }
      weight_by_slot_add( &wbs_root, root_slot, w->stake );

      total_stake += w->stake;
    }

    /* Find the latest slot that has 2/3 of the total stake. */
    ulong threshold = total_stake * 2UL / 3UL;
    for( uint i=wbs_votes.cnt; i>0; i-- ) {
      ulong slot = wbs_votes.first + i - 1U;
      ulong stake = wbs_votes.weight[slot & (WEIGHT_BY_SLOT_MAX - 1)];
      if( stake >= threshold ) {
        glob->confirmed_slot = slot;
        break;
      }
    }

    /* Find a slot for 2/3 of the total stake is rooted. */
    ulong sum = 0UL;
    for( uint i=wbs_root.cnt; i>0; i-- ) {
      ulong slot = wbs_root.first + i - 1U;
      sum += wbs_root.weight[slot & (WEIGHT_BY_SLOT_MAX - 1)];
      if( sum >= threshold ) {
        glob->root_slot = slot;
        break;
      }
    }
  } FD_SPAD_FRAME_END;
}

void
fd_rpc_tower_during_frag(fd_rpc_ctx_t * ctx, ulong sig, ulong ctl, void const * msg, int sz) {
  fd_rpc_global_ctx_t * glob = ctx->global;
  if( FD_LIKELY( sig==FD_REPLAY_SIG_VOTE_STATE ) ) {
    if( FD_UNLIKELY( fd_frag_meta_ctl_som( ctl ) ) ) {
      glob->replay_towers_cnt = 0;
      glob->replay_towers_eom = 0;
    }
    if( FD_UNLIKELY( glob->replay_towers_cnt >= FD_REPLAY_TOWER_VOTE_ACC_MAX ) ) FD_LOG_ERR(( "tower received more vote states than expected" ));
    FD_TEST( sz == (int)sizeof(fd_replay_tower_t) );
    memcpy( &glob->replay_towers[glob->replay_towers_cnt++], msg, sizeof(fd_replay_tower_t) );
    glob->replay_towers_eom = fd_frag_meta_ctl_eom( ctl );
    if( glob->replay_towers_eom ) {
      fd_rpc_recompute_confirmed( glob );
    }
  }
}

void
fd_rpc_tower_after_frag(fd_rpc_ctx_t * ctx) {
  (void)ctx;
}
