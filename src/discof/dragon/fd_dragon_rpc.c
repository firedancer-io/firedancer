#include "fd_dragon_rpc.h"
#include "proto/geyser.pb.h"
#include "proto/health.pb.h"
#include "../../ballet/base58/fd_base58.h"
#include "../../flamenco/txnmeta/fd_txn_meta.h"
#include "../../third_party/nanopb/pb_encode.h"
#include "../../third_party/nanopb/pb_decode.h"
#include "../../util/fd_version.h"

/* FD_DRAGON_RPC_MSG_MAX bounds a response message.  The largest one
   this server encodes is the GetVersion document; subscription updates
   are a ping, a pong, or a slot status, plus the filter names the
   subscription used. */

#define FD_DRAGON_RPC_MSG_MAX (16384UL)

/* The store the unary calls answer from, mirroring yellowstone's
   BlockMetaStorage (grpc.rs:118-311).

   DRAGON_KEEP_SLOTS is how far below the finalized slot a block meta
   is kept, DRAGON_MAX_RECENT_BLOCKHASHES is solana's
   MAX_RECENT_BLOCKHASHES, and DRAGON_BLOCKHASH_WINDOW is how far below
   the finalized slot a blockhash status is kept, which is also how
   many of them have to be known before IsBlockhashValid answers.

   DRAGON_META_MAX and DRAGON_HASH_MAX are the table sizes.  Metas are
   kept for the slots above the finalized one too, which under tower is
   the ~32 slots of the rooting delay, and blockhash statuses for a
   window of DRAGON_BLOCKHASH_WINDOW slots; both tables have room for
   two banks per slot in the window, so the eviction of the lowest slot
   is a backstop for a fork history deeper than that. */

#define DRAGON_KEEP_SLOTS             (   3UL)
#define DRAGON_MAX_RECENT_BLOCKHASHES ( 300UL)
#define DRAGON_BLOCKHASH_WINDOW       ( 332UL) /* MAX_RECENT_BLOCKHASHES + 32 */
#define DRAGON_META_MAX               ( 128UL)
#define DRAGON_HASH_MAX               ( 768UL)

struct dragon_meta {
  ulong     slot;         /* ULONG_MAX when the entry is free */
  ulong     parent_slot;
  ulong     block_height;
  fd_hash_t block_hash;
};

typedef struct dragon_meta dragon_meta_t;

struct dragon_blockhash {
  fd_hash_t hash;
  ulong     slot;         /* ULONG_MAX when the entry is free */
  int       processed;
  int       confirmed;
  int       finalized;
};

typedef struct dragon_blockhash dragon_blockhash_t;

/* FD_DRAGON_REAP_NANOS is how long a finished subscription may hold a
   connection while its trailers wait behind data the client is not
   taking. */

#define FD_DRAGON_REAP_NANOS (10000000000L) /* 10s */

/* FD_DRAGON_REQUEST_NANOS is how long a call may hold its slot without
   sending the request that gives it a purpose. */

#define FD_DRAGON_REQUEST_NANOS (30000000000L) /* 30s */

/* FD_DRAGON_UPDATE_SZ_MAX bounds one SubscribeUpdate carrying a
   transaction: the largest message body plus the filter names of one
   client and the timestamp. */

#define FD_DRAGON_UPDATE_SZ_MAX                                        \
  ( FD_TXN_META_UPDATE_SZ_MAX + 16UL                                   \
    + FD_DRAGON_FILTER_MAX*( FD_DRAGON_FILTER_NAME_MAX + 8UL )         \
    + 32UL )

/* The field numbers of geyser.SubscribeUpdate that this layer writes
   by hand, because the body they carry is encoded once and shared by
   every client that receives it. */

#define DRAGON_UPDATE_FILTERS_FIELD    ( 1U)
#define DRAGON_UPDATE_ACCOUNT_FIELD    ( 2U)
#define DRAGON_UPDATE_TXN_FIELD        ( 4U)
#define DRAGON_UPDATE_BLOCK_FIELD      ( 5U)
#define DRAGON_UPDATE_TXN_STATUS_FIELD (10U)
#define DRAGON_UPDATE_BLOCK_META_FIELD ( 7U)
#define DRAGON_UPDATE_CREATED_AT_FIELD (11U)

/* The field numbers of geyser.SubscribeUpdateAccount and of the
   account state it carries. */

#define DRAGON_ACCT_INFO_FIELD       (1U)
#define DRAGON_ACCT_SLOT_FIELD       (2U)
#define DRAGON_ACCT_IS_STARTUP_FIELD (3U)
#define DRAGON_ACCT_BANK_ID_FIELD    (4U)

#define DRAGON_AI_PUBKEY_FIELD        (1U)
#define DRAGON_AI_LAMPORTS_FIELD      (2U)
#define DRAGON_AI_OWNER_FIELD         (3U)
#define DRAGON_AI_EXECUTABLE_FIELD    (4U)
#define DRAGON_AI_RENT_EPOCH_FIELD    (5U)
#define DRAGON_AI_DATA_FIELD          (6U)
#define DRAGON_AI_WRITE_VERSION_FIELD (7U)
#define DRAGON_AI_TXN_SIGNATURE_FIELD (8U)

/* The field numbers of geyser.SubscribeUpdateBlock. */

#define DRAGON_BLK_SLOT_FIELD             ( 1U)
#define DRAGON_BLK_BLOCKHASH_FIELD        ( 2U)
#define DRAGON_BLK_REWARDS_FIELD          ( 3U)
#define DRAGON_BLK_BLOCK_HEIGHT_FIELD     ( 5U)
#define DRAGON_BLK_TRANSACTIONS_FIELD     ( 6U)
#define DRAGON_BLK_PARENT_SLOT_FIELD      ( 7U)
#define DRAGON_BLK_PARENT_BLOCKHASH_FIELD ( 8U)
#define DRAGON_BLK_EXECUTED_TXN_CNT_FIELD ( 9U)
#define DRAGON_BLK_UPDATED_ACCT_CNT_FIELD (10U)
#define DRAGON_BLK_ACCOUNTS_FIELD         (11U)
#define DRAGON_BLK_ENTRIES_CNT_FIELD      (12U)
#define DRAGON_BLK_BANK_ID_FIELD          (14U)

/* DRAGON_ACCT_RENT_EPOCH is the rent epoch every account update
   reports.  The accounts database keeps none, and the rpc tile answers
   the same value (fd_rpc_tile.c:1491).  Agave normalizes the rent
   epoch of every account it loads to RENT_EXEMPT_RENT_EPOCH, which is
   u64::MAX (svm/src/rent_calculator.rs:16), as long as the account is
   rent exempt (svm/src/account_loader.rs:355-366,641,
   svm/src/transaction_processor.rs:803), and rent exempt is what every
   account that can be created is.  An account left over from when rent
   was collected keeps a smaller rent epoch in agave and is reported
   with this one here. */

#define DRAGON_ACCT_RENT_EPOCH (ULONG_MAX)

/* The field numbers of geyser.SubscribeUpdateBlockMeta, whose body
   this layer writes by hand. */

#define DRAGON_BM_SLOT_FIELD             ( 1U)
#define DRAGON_BM_BLOCKHASH_FIELD        ( 2U)
#define DRAGON_BM_REWARDS_FIELD          ( 3U)
#define DRAGON_BM_BLOCK_HEIGHT_FIELD     ( 5U)
#define DRAGON_BM_PARENT_SLOT_FIELD      ( 6U)
#define DRAGON_BM_PARENT_BLOCKHASH_FIELD ( 7U)
#define DRAGON_BM_EXECUTED_TXN_CNT_FIELD ( 8U)
#define DRAGON_BM_BANK_ID_FIELD          (10U)

/* Every field number written by hand, against the protobuf
   definitions: a regenerated proto that renumbers one breaks the
   build. */

FD_STATIC_ASSERT( DRAGON_UPDATE_FILTERS_FIELD   ==geyser_SubscribeUpdate_filters_tag,            dragon_field );
FD_STATIC_ASSERT( DRAGON_UPDATE_ACCOUNT_FIELD   ==geyser_SubscribeUpdate_account_tag,            dragon_field );
FD_STATIC_ASSERT( DRAGON_UPDATE_BLOCK_FIELD     ==geyser_SubscribeUpdate_block_tag,              dragon_field );
FD_STATIC_ASSERT( DRAGON_UPDATE_TXN_FIELD       ==geyser_SubscribeUpdate_transaction_tag,        dragon_field );
FD_STATIC_ASSERT( DRAGON_UPDATE_TXN_STATUS_FIELD==geyser_SubscribeUpdate_transaction_status_tag, dragon_field );
FD_STATIC_ASSERT( DRAGON_UPDATE_BLOCK_META_FIELD==geyser_SubscribeUpdate_block_meta_tag,         dragon_field );
FD_STATIC_ASSERT( DRAGON_UPDATE_CREATED_AT_FIELD==geyser_SubscribeUpdate_created_at_tag,         dragon_field );

FD_STATIC_ASSERT( DRAGON_BM_SLOT_FIELD            ==geyser_SubscribeUpdateBlockMeta_slot_tag,             dragon_field );
FD_STATIC_ASSERT( DRAGON_BM_BLOCKHASH_FIELD       ==geyser_SubscribeUpdateBlockMeta_blockhash_tag,        dragon_field );
FD_STATIC_ASSERT( DRAGON_BM_REWARDS_FIELD         ==geyser_SubscribeUpdateBlockMeta_rewards_tag,          dragon_field );
FD_STATIC_ASSERT( DRAGON_BM_BLOCK_HEIGHT_FIELD    ==geyser_SubscribeUpdateBlockMeta_block_height_tag,     dragon_field );
FD_STATIC_ASSERT( DRAGON_BM_PARENT_SLOT_FIELD     ==geyser_SubscribeUpdateBlockMeta_parent_slot_tag,      dragon_field );
FD_STATIC_ASSERT( DRAGON_BM_PARENT_BLOCKHASH_FIELD==geyser_SubscribeUpdateBlockMeta_parent_blockhash_tag, dragon_field );
FD_STATIC_ASSERT( DRAGON_BM_EXECUTED_TXN_CNT_FIELD==geyser_SubscribeUpdateBlockMeta_executed_transaction_count_tag, dragon_field );
FD_STATIC_ASSERT( DRAGON_BM_BANK_ID_FIELD         ==geyser_SubscribeUpdateBlockMeta_bank_id_tag,          dragon_field );

/* The block summary leaves the block time and the entry count out, and
   they are fields of their own. */
FD_STATIC_ASSERT( geyser_SubscribeUpdateBlockMeta_block_time_tag   == 4U, dragon_field );
FD_STATIC_ASSERT( geyser_SubscribeUpdateBlockMeta_entries_count_tag== 9U, dragon_field );

FD_STATIC_ASSERT( DRAGON_ACCT_INFO_FIELD      ==geyser_SubscribeUpdateAccount_account_tag,    dragon_field );
FD_STATIC_ASSERT( DRAGON_ACCT_SLOT_FIELD      ==geyser_SubscribeUpdateAccount_slot_tag,       dragon_field );
FD_STATIC_ASSERT( DRAGON_ACCT_IS_STARTUP_FIELD==geyser_SubscribeUpdateAccount_is_startup_tag, dragon_field );
FD_STATIC_ASSERT( DRAGON_ACCT_BANK_ID_FIELD   ==geyser_SubscribeUpdateAccount_bank_id_tag,    dragon_field );

FD_STATIC_ASSERT( DRAGON_AI_PUBKEY_FIELD       ==geyser_SubscribeUpdateAccountInfo_pubkey_tag,        dragon_field );
FD_STATIC_ASSERT( DRAGON_AI_LAMPORTS_FIELD     ==geyser_SubscribeUpdateAccountInfo_lamports_tag,      dragon_field );
FD_STATIC_ASSERT( DRAGON_AI_OWNER_FIELD        ==geyser_SubscribeUpdateAccountInfo_owner_tag,         dragon_field );
FD_STATIC_ASSERT( DRAGON_AI_EXECUTABLE_FIELD   ==geyser_SubscribeUpdateAccountInfo_executable_tag,    dragon_field );
FD_STATIC_ASSERT( DRAGON_AI_RENT_EPOCH_FIELD   ==geyser_SubscribeUpdateAccountInfo_rent_epoch_tag,    dragon_field );
FD_STATIC_ASSERT( DRAGON_AI_DATA_FIELD         ==geyser_SubscribeUpdateAccountInfo_data_tag,          dragon_field );
FD_STATIC_ASSERT( DRAGON_AI_WRITE_VERSION_FIELD==geyser_SubscribeUpdateAccountInfo_write_version_tag, dragon_field );
FD_STATIC_ASSERT( DRAGON_AI_TXN_SIGNATURE_FIELD==geyser_SubscribeUpdateAccountInfo_txn_signature_tag, dragon_field );

FD_STATIC_ASSERT( DRAGON_BLK_SLOT_FIELD            ==geyser_SubscribeUpdateBlock_slot_tag,             dragon_field );
FD_STATIC_ASSERT( DRAGON_BLK_BLOCKHASH_FIELD       ==geyser_SubscribeUpdateBlock_blockhash_tag,        dragon_field );
FD_STATIC_ASSERT( DRAGON_BLK_REWARDS_FIELD         ==geyser_SubscribeUpdateBlock_rewards_tag,          dragon_field );
FD_STATIC_ASSERT( DRAGON_BLK_BLOCK_HEIGHT_FIELD    ==geyser_SubscribeUpdateBlock_block_height_tag,     dragon_field );
FD_STATIC_ASSERT( DRAGON_BLK_TRANSACTIONS_FIELD    ==geyser_SubscribeUpdateBlock_transactions_tag,     dragon_field );
FD_STATIC_ASSERT( DRAGON_BLK_PARENT_SLOT_FIELD     ==geyser_SubscribeUpdateBlock_parent_slot_tag,      dragon_field );
FD_STATIC_ASSERT( DRAGON_BLK_PARENT_BLOCKHASH_FIELD==geyser_SubscribeUpdateBlock_parent_blockhash_tag, dragon_field );
FD_STATIC_ASSERT( DRAGON_BLK_EXECUTED_TXN_CNT_FIELD==geyser_SubscribeUpdateBlock_executed_transaction_count_tag, dragon_field );
FD_STATIC_ASSERT( DRAGON_BLK_UPDATED_ACCT_CNT_FIELD==geyser_SubscribeUpdateBlock_updated_account_count_tag,      dragon_field );
FD_STATIC_ASSERT( DRAGON_BLK_ACCOUNTS_FIELD        ==geyser_SubscribeUpdateBlock_accounts_tag,         dragon_field );
FD_STATIC_ASSERT( DRAGON_BLK_ENTRIES_CNT_FIELD     ==geyser_SubscribeUpdateBlock_entries_count_tag,    dragon_field );
FD_STATIC_ASSERT( DRAGON_BLK_BANK_ID_FIELD         ==geyser_SubscribeUpdateBlock_bank_id_tag,          dragon_field );

/* A block leaves its block time out and reconstructs no entries, and
   both are fields of their own. */
FD_STATIC_ASSERT( geyser_SubscribeUpdateBlock_block_time_tag==4U, dragon_field );
FD_STATIC_ASSERT( geyser_SubscribeUpdateBlock_entries_tag  ==13U, dragon_field );

/* google.protobuf.Timestamp, which every update carries. */
#define DRAGON_TS_SECONDS_FIELD (1U)
#define DRAGON_TS_NANOS_FIELD   (2U)
FD_STATIC_ASSERT( DRAGON_TS_SECONDS_FIELD==google_protobuf_Timestamp_seconds_tag, dragon_field );
FD_STATIC_ASSERT( DRAGON_TS_NANOS_FIELD  ==google_protobuf_Timestamp_nanos_tag,   dragon_field );

/* FD_DRAGON_DEGRADE_MAX is how many banks the layer remembers giving
   up on without being able to note it on the bank itself, which is the
   case when the buffer's bank table had no room for the bank. */

#define FD_DRAGON_DEGRADE_MAX (64UL)
/* FD_DRAGON_BLOCK_OPEN_MAX is how many blocks one delivery pass
   assembles at once, each in a buffer of its own, so that the accounts
   of a bank are read once for all of them.  A level with more blocks
   filters than this takes another pass and reads the accounts again;
   two covers a client watching whole blocks alongside one watching a
   program's blocks, and the buffers cost
   FD_DRAGON_BLOCK_OPEN_MAX times what one message may be. */

#define FD_DRAGON_BLOCK_OPEN_MAX (2UL)

/* FD_DRAGON_BLOCK_SUB_MAX is how many blocks filters the server holds
   across all its subscriptions, which bounds the passes over a bank,
   and so its account reads, to four per commitment level. */

#define FD_DRAGON_BLOCK_SUB_MAX (4UL*FD_DRAGON_BLOCK_OPEN_MAX)


/* A buffered entry's mask has one bit per client slot. */
FD_STATIC_ASSERT( FD_DRAGON_CLIENT_MAX==FD_DRAGON_BUF_CLIENT_MAX, dragon_client_max );

#define FD_DRAGON_RPC_MAGIC (0xf17eda2547d2a600UL) /* firedancer dragon */

struct fd_dragon_rpc {
  ulong magic;

  ulong stream_max;
  long  ping_interval;

  char  x_token[ FD_DRAGON_RPC_TOKEN_MAX ];
  ulong x_token_len;

  char  version_json[ FD_DRAGON_RPC_VERSION_MAX ];
  ulong version_json_len;

  void * conn_ctx;
  void (* conn_open_fn )( void * ctx, int sock );
  void (* conn_close_fn)( void * ctx, int sock );

  long now; /* wallclock stamped on created_at */

  /* The latest slot seen at each FD_DRAGON_COMMITMENT_* level, and
     whether one was seen at all. */
  int   have_level[ 3 ];
  ulong level_slot[ 3 ];

  /* What the health service reports: the owner sets it when it starts
     serving and clears it when it starts shutting down. */
  int health_serving;

  dragon_meta_t      meta[ DRAGON_META_MAX ];
  dragon_blockhash_t hash[ DRAGON_HASH_MAX ];
  ulong              hash_cnt;

  fd_dragon_session_t *  session; /* stream_max entries */
  fd_dragon_filter_set_t scratch[1];

  /* The configured filter limits, and the cuckoo bucket arena: one
     slice of cuckoo_entry_max entries per session, plus the one the
     scratch set decodes into. */
  fd_dragon_filter_limits_t limits[1];
  ushort *                  cuckoo;
  ulong                     cuckoo_entry_max;

  uchar msg_buf[ FD_DRAGON_RPC_MSG_MAX ];

  /* The geyser core, which builds a transaction's meta object, and the
     buffer the layer serves the commitment levels above processed
     from, NULL when it serves none. */
  fd_geyser_core_t * core;
  fd_dragon_buf_t *  buf;
  int                finalized;
  int                filter_at; /* FD_DRAGON_FILTER_AT_* */

  /* The highest bank id any callback has named, which is what a new or
     updated deferred subscription becomes eligible above. */
  ulong bank_seq_hi;
  ulong serve_from_bank_seq; /* nothing below it is served; set when serving starts */

  /* How many sessions ask for each of the things the layer has to do
     work for, so that a record costs nothing when nobody is
     subscribed. */
  ulong txn_sub_cnt;
  ulong block_meta_sub_cnt;
  ulong deferred_sub_cnt;
  ulong acct_sub_cnt;
  ulong blocks_sub_cnt;

  /* The banks the layer gave up on at the buffered levels without
     being able to record it on the bank. */
  ulong degrade_bank[ FD_DRAGON_DEGRADE_MAX ];
  ulong degrade_next;

  /* The working memory of one record: the message bodies encoded once
     for every client, and the message assembled for one client. */
  ulong                 txn_names   [ FD_DRAGON_CLIENT_MAX ];
  ulong                 status_names[ FD_DRAGON_CLIENT_MAX ];
  ulong                 block_names [ FD_DRAGON_CLIENT_MAX ];
  ulong                 acct_names  [ FD_DRAGON_CLIENT_MAX ];
  ulong                 meta_names  [ FD_DRAGON_CLIENT_MAX ];
  uchar                 body_buf  [ FD_TXN_META_UPDATE_SZ_MAX ];
  uchar                 status_buf[ FD_TXN_META_STATUS_SZ_MAX ];
  uchar                 update_buf[ FD_DRAGON_UPDATE_SZ_MAX ];

  /* The working memory of one account write: the union of the data
     slices the subscribers it is buffered for asked for. */
  fd_dragon_buf_seg_t   seg[ FD_DRAGON_CLIENT_MAX*FD_DRAGON_DATA_SLICE_MAX ];

  /* Where an account update or a block is assembled.  Both carry
     account data, whose size the schema of a record does not bound, so
     they get a buffer of their own rather than a bound of their own.
     The blocks of one delivery pass are assembled side by side, so
     that the accounts they share are read once. */
  ulong   msg_max;
  uchar * msg_big;
  uchar * blk_big;  /* FD_DRAGON_BLOCK_OPEN_MAX buffers of msg_max */

  /* The send queue high water of the calls that ended, which the
     owner drains into a histogram.  A slot that is not drained before
     FD_DRAGON_CLIENT_MAX more calls end is overwritten, which cannot
     happen at the rate an owner reads its metrics. */
  ulong ref_hi[ FD_DRAGON_CLIENT_MAX ];
  ulong ref_hi_next;
  ulong ref_hi_taken;

  fd_dragon_rpc_metrics_t metrics;
};

/* Status texts.  Every one of these is what a yellowstone server
   answers in the same situation (grpc.rs, plugin/filter). */

#define DRAGON_MSG_NO_TOKEN      "No valid auth token"
#define DRAGON_MSG_DISABLED      "method disabled"
#define DRAGON_MSG_NO_BLOCK      "block is not available yet"
#define DRAGON_MSG_STARTUP       "startup"
#define DRAGON_MSG_BUILD_FAILED  "failed to build response"
#define DRAGON_MSG_LAGGED_SEND   "lagged to send an update"
#define DRAGON_MSG_MAX_SUBS      "max subscription limit exceeded"
#define DRAGON_MSG_MAX_BLOCKS    "max blocks subscription limit exceeded"
#define DRAGON_MSG_NO_ENTRY      "entry subscriptions are not supported"
#define DRAGON_MSG_NO_REQUEST    "no request received"

#define DRAGON_FINISH(stream,status,lit) \
  fd_grpc_server_finish( (stream), (status), (lit), sizeof(lit)-1UL )

/* Routing ***********************************************************/

struct dragon_route {
  char const * path;
  ulong        path_len;
  int          method;
};

#define DRAGON_ROUTE(name,method) { "/geyser.Geyser/" name, sizeof("/geyser.Geyser/" name)-1UL, (method) }
#define DRAGON_PATH(path,method)  { (path), sizeof(path)-1UL, (method) }

static struct dragon_route const dragon_routes[] = {
  DRAGON_ROUTE( "Subscribe",           FD_DRAGON_METHOD_SUBSCRIBE             ),
  DRAGON_ROUTE( "SubscribeDeshred",    FD_DRAGON_METHOD_SUBSCRIBE_DESHRED     ),
  DRAGON_ROUTE( "SubscribeGossip",     FD_DRAGON_METHOD_SUBSCRIBE_GOSSIP      ),
  DRAGON_ROUTE( "SubscribeReplayInfo", FD_DRAGON_METHOD_SUBSCRIBE_REPLAY_INFO ),
  DRAGON_ROUTE( "Ping",                FD_DRAGON_METHOD_PING                  ),
  DRAGON_ROUTE( "GetLatestBlockhash",  FD_DRAGON_METHOD_GET_LATEST_BLOCKHASH  ),
  DRAGON_ROUTE( "GetBlockHeight",      FD_DRAGON_METHOD_GET_BLOCK_HEIGHT      ),
  DRAGON_ROUTE( "GetSlot",             FD_DRAGON_METHOD_GET_SLOT              ),
  DRAGON_ROUTE( "IsBlockhashValid",    FD_DRAGON_METHOD_IS_BLOCKHASH_VALID    ),
  DRAGON_ROUTE( "GetVersion",          FD_DRAGON_METHOD_GET_VERSION           ),
  DRAGON_PATH ( "/grpc.health.v1.Health/Check", FD_DRAGON_METHOD_HEALTH_CHECK  ),
  DRAGON_PATH ( "/grpc.health.v1.Health/Watch", FD_DRAGON_METHOD_HEALTH_WATCH  )
};

#undef DRAGON_ROUTE
#undef DRAGON_PATH

static int
dragon_route( char const * path,
              ulong        path_len ) {
  for( ulong i=0UL; i<sizeof(dragon_routes)/sizeof(dragon_routes[0]); i++ ) {
    if( dragon_routes[ i ].path_len==path_len &&
        fd_memeq( dragon_routes[ i ].path, path, path_len ) ) return dragon_routes[ i ].method;
  }
  return FD_DRAGON_METHOD_UNKNOWN;
}

/* Construction ******************************************************/

FD_FN_CONST ulong
fd_dragon_rpc_align( void ) {
  return FD_DRAGON_RPC_ALIGN;
}

/* dragon_buf_params is the buffer the parameters ask for. */

static fd_dragon_buf_params_t
dragon_buf_params( fd_dragon_rpc_params_t const * params ) {
  fd_dragon_buf_params_t out = {
    .bank_max = params->bank_max,
    .depth    = params->buf_depth,
    .mcache   = params->buf_mcache,
    .dcache   = params->buf_dcache,
    .base     = params->buf_base
  };
  return out;
}

/* dragon_msg_max is the assembly buffer the parameters ask for, which
   is never smaller than the largest update the schema of a record
   bounds. */

static ulong
dragon_msg_max( fd_dragon_rpc_params_t const * params ) {
  return fd_ulong_max( params->msg_max_bytes, FD_DRAGON_UPDATE_SZ_MAX );
}

/* dragon_cuckoo_bytes is the cuckoo bucket arena of one subscription,
   rounded down to whole buckets. */

static ulong
dragon_cuckoo_bytes( fd_dragon_rpc_params_t const * params ) {
  return fd_ulong_align_dn( params->cuckoo_bytes, FD_DRAGON_CUCKOO_BUCKET_SZ );
}

/* dragon_cuckoo_arena is the cuckoo bucket arena of session idx, or of
   the scratch filter set at idx stream_max. */

FD_FN_PURE static ushort *
dragon_cuckoo_arena( fd_dragon_rpc_t const * rpc,
                     ulong                   idx ) {
  if( FD_LIKELY( !rpc->cuckoo ) ) return NULL;
  return rpc->cuckoo + idx*rpc->cuckoo_entry_max;
}

ulong
fd_dragon_rpc_footprint( fd_dragon_rpc_params_t const * params ) {
  if( FD_UNLIKELY( !params->stream_max || params->stream_max>FD_DRAGON_CLIENT_MAX ) ) return 0UL;

  if( FD_UNLIKELY( params->filter_at!=FD_DRAGON_FILTER_AT_INGEST &&
                   params->filter_at!=FD_DRAGON_FILTER_AT_SEND ) ) return 0UL;

  fd_dragon_buf_params_t buf_params = dragon_buf_params( params );
  ulong buf_fp = 0UL;
  if( params->finalized ) {
    buf_fp = fd_dragon_buf_footprint( &buf_params );
    if( FD_UNLIKELY( !buf_fp ) ) return 0UL;
  }

  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, FD_DRAGON_RPC_ALIGN,            sizeof(fd_dragon_rpc_t)                        );
  l = FD_LAYOUT_APPEND( l, alignof(fd_dragon_session_t),   params->stream_max*sizeof(fd_dragon_session_t) );
  l = FD_LAYOUT_APPEND( l, 8UL,      ( params->stream_max+1UL )*dragon_cuckoo_bytes( params )             );
  l = FD_LAYOUT_APPEND( l, 128UL,                          dragon_msg_max( params )                       );
  if( params->finalized )
    l = FD_LAYOUT_APPEND( l, 128UL, FD_DRAGON_BLOCK_OPEN_MAX*dragon_msg_max( params ) );
  if( buf_fp ) l = FD_LAYOUT_APPEND( l, fd_dragon_buf_align(), buf_fp );
  return FD_LAYOUT_FINI( l, FD_DRAGON_RPC_ALIGN );
}

/* dragon_json_append_escaped appends a JSON string body, escaping what
   RFC 8259 requires.  Returns the number of bytes written. */

static ulong
dragon_json_append_escaped( char *       out,
                            ulong        out_sz,
                            char const * in ) {
  ulong o = 0UL;
  for( char const * p=in; *p; p++ ) {
    uchar c = (uchar)*p;
    char  esc[ 8 ];
    ulong esc_sz;
    if     ( c=='"'  ) { esc[0]='\\'; esc[1]='"';  esc_sz = 2UL; }
    else if( c=='\\' ) { esc[0]='\\'; esc[1]='\\'; esc_sz = 2UL; }
    else if( c<0x20U ) {
      static char const hex[] = "0123456789abcdef";
      esc[0]='\\'; esc[1]='u'; esc[2]='0'; esc[3]='0';
      esc[4]=hex[ (c>>4)&0xF ]; esc[5]=hex[ c&0xF ];
      esc_sz = 6UL;
    } else { esc[0]=(char)c; esc_sz = 1UL; }
    if( FD_UNLIKELY( o+esc_sz>out_sz ) ) break;
    fd_memcpy( out+o, esc, esc_sz );
    o += esc_sz;
  }
  return o;
}

/* dragon_version_json writes the GetVersion document.  The shape is
   yellowstone's (version.rs): a "version" object of package, version,
   proto, solana, git, rustc and buildts, plus an "extra" object with
   the host name.  Firedancer is the implementation of the Solana
   protocol here, so "solana" carries its version too; "rustc" carries
   the C compiler that built this binary and "buildts" is empty
   because the build does not stamp one. */

static void
dragon_version_json( fd_dragon_rpc_t * rpc ) {
  char host[ 256 ];
  char git [ 128 ];
  char ver [ 128 ];
  char cc  [ 256 ];

  host[ dragon_json_append_escaped( host, sizeof(host)-1UL, fd_log_host()         ) ] = '\0';
  git [ dragon_json_append_escaped( git,  sizeof(git )-1UL, fd_commit_ref_cstr    ) ] = '\0';
  ver [ dragon_json_append_escaped( ver,  sizeof(ver )-1UL, fd_version_cstr       ) ] = '\0';
  cc  [ dragon_json_append_escaped( cc,   sizeof(cc  )-1UL, __VERSION__           ) ] = '\0';

  ulong len = 0UL;
  fd_cstr_printf( rpc->version_json, sizeof(rpc->version_json), &len,
                  "{\"version\":{"
                    "\"package\":\"firedancer-dragon\","
                    "\"version\":\"%s\","
                    "\"proto\":\"%s\","
                    "\"solana\":\"%s\","
                    "\"git\":\"%s\","
                    "\"rustc\":\"%s\","
                    "\"buildts\":\"\""
                  "},\"extra\":{\"hostname\":\"%s\"}}",
                  ver, FD_DRAGON_PROTO_VERSION, ver, git, cc, host );
  rpc->version_json_len = len;
}

void *
fd_dragon_rpc_new( void *                         mem,
                   fd_dragon_rpc_params_t const * params ) {
  if( FD_UNLIKELY( !mem ) ) {
    FD_LOG_WARNING(( "NULL mem" ));
    return NULL;
  }
  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)mem, FD_DRAGON_RPC_ALIGN ) ) ) {
    FD_LOG_WARNING(( "misaligned mem" ));
    return NULL;
  }
  if( FD_UNLIKELY( !fd_dragon_rpc_footprint( params ) ) ) {
    FD_LOG_WARNING(( "invalid fd_dragon_rpc params" ));
    return NULL;
  }
  ulong x_token_len = params->x_token ? strlen( params->x_token ) : 0UL;
  if( FD_UNLIKELY( x_token_len>=FD_DRAGON_RPC_TOKEN_MAX ) ) {
    FD_LOG_WARNING(( "x_token is longer than %lu bytes", FD_DRAGON_RPC_TOKEN_MAX-1UL ));
    return NULL;
  }

  fd_dragon_buf_params_t buf_params = dragon_buf_params( params );
  ulong                  buf_fp     = params->finalized ? fd_dragon_buf_footprint( &buf_params ) : 0UL;

  FD_SCRATCH_ALLOC_INIT( l, mem );
  fd_dragon_rpc_t * rpc   = FD_SCRATCH_ALLOC_APPEND( l, FD_DRAGON_RPC_ALIGN,          sizeof(fd_dragon_rpc_t)                        );
  void *            ses   = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_dragon_session_t), params->stream_max*sizeof(fd_dragon_session_t) );
  void *            cuck  = FD_SCRATCH_ALLOC_APPEND( l, 8UL,    ( params->stream_max+1UL )*dragon_cuckoo_bytes( params )             );
  void *            big   = FD_SCRATCH_ALLOC_APPEND( l, 128UL,                        dragon_msg_max( params )                       );
  void *            blk   = params->finalized ?
                              FD_SCRATCH_ALLOC_APPEND( l, 128UL, FD_DRAGON_BLOCK_OPEN_MAX*dragon_msg_max( params ) ) : NULL;
  void *            buf   = buf_fp ? FD_SCRATCH_ALLOC_APPEND( l, fd_dragon_buf_align(), buf_fp ) : NULL;
  FD_SCRATCH_ALLOC_FINI( l, FD_DRAGON_RPC_ALIGN );

  fd_memset( rpc, 0, sizeof(fd_dragon_rpc_t) );
  fd_memset( ses, 0, params->stream_max*sizeof(fd_dragon_session_t) );

  for( ulong i=0UL; i<DRAGON_META_MAX; i++ ) rpc->meta[ i ].slot = ULONG_MAX;
  for( ulong i=0UL; i<DRAGON_HASH_MAX; i++ ) rpc->hash[ i ].slot = ULONG_MAX;

  rpc->stream_max        = params->stream_max;
  rpc->ping_interval     = params->ping_interval_nanos;
  rpc->session           = ses;
  rpc->conn_ctx          = params->conn_ctx;
  rpc->conn_open_fn      = params->conn_open;
  rpc->conn_close_fn     = params->conn_close;
  rpc->x_token_len       = x_token_len;
  rpc->finalized         = !!params->finalized;
  rpc->filter_at         = params->filter_at;
  rpc->msg_max           = dragon_msg_max( params );
  rpc->msg_big           = big;
  rpc->blk_big           = blk;
  if( x_token_len ) fd_memcpy( rpc->x_token, params->x_token, x_token_len );

  for( ulong i=0UL; i<FD_DRAGON_DEGRADE_MAX; i++ ) rpc->degrade_bank[ i ] = ULONG_MAX;

  if( buf ) {
    rpc->buf = fd_dragon_buf_join( fd_dragon_buf_new( buf, &buf_params ) );
    if( FD_UNLIKELY( !rpc->buf ) ) return NULL;
  }

  rpc->cuckoo           = dragon_cuckoo_bytes( params ) ? cuck : NULL;
  rpc->cuckoo_entry_max = dragon_cuckoo_bytes( params )/sizeof(ushort);
  if( params->filter_limits ) *rpc->limits = *params->filter_limits;
  else                        fd_dragon_filter_limits_default( rpc->limits );

  dragon_version_json( rpc );
  fd_dragon_filter_set_init( rpc->scratch, dragon_cuckoo_arena( rpc, rpc->stream_max ),
                             rpc->cuckoo_entry_max );
  for( ulong i=0UL; i<rpc->stream_max; i++ ) {
    fd_dragon_filter_set_init( rpc->session[ i ].filter, dragon_cuckoo_arena( rpc, i ),
                               rpc->cuckoo_entry_max );
  }

  FD_COMPILER_MFENCE();
  rpc->magic = FD_DRAGON_RPC_MAGIC;
  FD_COMPILER_MFENCE();
  return mem;
}

fd_dragon_rpc_t *
fd_dragon_rpc_join( void * mem ) {
  fd_dragon_rpc_t * rpc = mem;
  if( FD_UNLIKELY( !rpc ) ) {
    FD_LOG_WARNING(( "NULL mem" ));
    return NULL;
  }
  if( FD_UNLIKELY( rpc->magic!=FD_DRAGON_RPC_MAGIC ) ) {
    FD_LOG_WARNING(( "bad magic" ));
    return NULL;
  }
  return rpc;
}

FD_FN_PURE char const *
fd_dragon_rpc_version_json( fd_dragon_rpc_t const * rpc ) {
  return rpc->version_json;
}

FD_FN_PURE fd_dragon_rpc_metrics_t const *
fd_dragon_rpc_metrics( fd_dragon_rpc_t const * rpc ) {
  return &rpc->metrics;
}

ulong
fd_dragon_rpc_ref_hi_drain( fd_dragon_rpc_t * rpc,
                              ulong *           out,
                              ulong             out_max ) {
  ulong avail = rpc->ref_hi_next - rpc->ref_hi_taken;
  if( FD_UNLIKELY( avail>FD_DRAGON_CLIENT_MAX ) ) {
    rpc->ref_hi_taken = rpc->ref_hi_next - FD_DRAGON_CLIENT_MAX;
    avail               = FD_DRAGON_CLIENT_MAX;
  }
  ulong cnt = fd_ulong_min( avail, out_max );
  for( ulong i=0UL; i<cnt; i++ ) out[ i ] = rpc->ref_hi[ ( rpc->ref_hi_taken+i ) % FD_DRAGON_CLIENT_MAX ];
  rpc->ref_hi_taken += cnt;
  return cnt;
}

FD_FN_PURE int
fd_dragon_rpc_is_ready( fd_dragon_rpc_t const * rpc ) {
  /* A rooted bank has been confirmed as well, so a root is what tells
     the server that every level has an answer.  Waiting for a
     confirmed status of its own would never finish where no optimistic
     confirmation notification exists, which is the case under
     alpenglow and when replaying a ledger. */
  return rpc->have_level[ FD_DRAGON_COMMITMENT_PROCESSED ] &&
         rpc->have_level[ FD_DRAGON_COMMITMENT_FINALIZED ];
}

/* Block meta store ***************************************************/

static dragon_meta_t *
dragon_meta_query( fd_dragon_rpc_t * rpc,
                   ulong             slot ) {
  if( FD_UNLIKELY( slot==ULONG_MAX ) ) return NULL;
  for( ulong i=0UL; i<DRAGON_META_MAX; i++ ) {
    if( rpc->meta[ i ].slot==slot ) return rpc->meta + i;
  }
  return NULL;
}

/* dragon_meta_store keeps one block meta per slot, the newest bank of
   the slot winning, as a map insert does. */

static void
dragon_meta_store( fd_dragon_rpc_t *              rpc,
                   fd_geyser_block_meta_t const * meta ) {
  dragon_meta_t * out   = dragon_meta_query( rpc, meta->slot );
  dragon_meta_t * spare = NULL;
  if( !out ) {
    for( ulong i=0UL; i<DRAGON_META_MAX; i++ ) {
      dragon_meta_t * m = rpc->meta + i;
      if( m->slot==ULONG_MAX ) { out = m; break; }
      if( !spare || m->slot<spare->slot ) spare = m;
    }
    if( !out ) out = spare;
  }

  out->slot         = meta->slot;
  out->parent_slot  = meta->parent_slot;
  out->block_height = meta->block_height;
  out->block_hash   = meta->block_hash;
  rpc->metrics.block_meta_cnt++;

  ulong cnt = 0UL;
  for( ulong i=0UL; i<DRAGON_META_MAX; i++ ) cnt += rpc->meta[ i ].slot!=ULONG_MAX;
  rpc->metrics.block_meta_tracked = cnt;
}

static dragon_blockhash_t *
dragon_blockhash_query( fd_dragon_rpc_t * rpc,
                        uchar const *     hash ) {
  for( ulong i=0UL; i<DRAGON_HASH_MAX; i++ ) {
    dragon_blockhash_t * h = rpc->hash + i;
    if( h->slot==ULONG_MAX ) continue;
    if( fd_memeq( h->hash.uc, hash, 32UL ) ) return h;
  }
  return NULL;
}

static dragon_blockhash_t *
dragon_blockhash_insert( fd_dragon_rpc_t * rpc,
                         uchar const *     hash,
                         ulong             slot ) {
  dragon_blockhash_t * out = dragon_blockhash_query( rpc, hash );
  if( FD_LIKELY( out ) ) return out;

  dragon_blockhash_t * spare = NULL;
  for( ulong i=0UL; i<DRAGON_HASH_MAX; i++ ) {
    dragon_blockhash_t * h = rpc->hash + i;
    if( h->slot==ULONG_MAX ) { out = h; break; }
    if( !spare || h->slot<spare->slot ) spare = h;
  }
  if( !out ) {
    out = spare;
    rpc->hash_cnt--;
  }

  fd_memset( out, 0, sizeof(dragon_blockhash_t) );
  fd_memcpy( out->hash.uc, hash, 32UL );
  out->slot = slot;
  rpc->hash_cnt++;
  return out;
}

/* dragon_store_status is what yellowstone's BlockMetaStorage does with
   a slot status: remember the level's latest slot, mark the slot's
   blockhash as having reached the level, and on a finalized status
   forget the slots that fell out of either window. */

static void
dragon_store_status( fd_dragon_rpc_t * rpc,
                     ulong             slot,
                     int               status ) {
  int level = status==FD_GEYSER_SLOT_PROCESSED ? FD_DRAGON_COMMITMENT_PROCESSED :
              status==FD_GEYSER_SLOT_CONFIRMED ? FD_DRAGON_COMMITMENT_CONFIRMED :
              status==FD_GEYSER_SLOT_FINALIZED ? FD_DRAGON_COMMITMENT_FINALIZED : -1;
  if( level<0 ) return;

  rpc->have_level[ level ] = 1;
  rpc->level_slot[ level ] = slot;

  dragon_meta_t const * meta = dragon_meta_query( rpc, slot );
  if( FD_LIKELY( meta ) ) {
    dragon_blockhash_t * h = dragon_blockhash_insert( rpc, meta->block_hash.uc, slot );
    if( level==FD_DRAGON_COMMITMENT_PROCESSED ) h->processed = 1;
    if( level==FD_DRAGON_COMMITMENT_CONFIRMED ) h->confirmed = 1;
    if( level==FD_DRAGON_COMMITMENT_FINALIZED ) h->finalized = 1;
  }

  if( status!=FD_GEYSER_SLOT_FINALIZED ) return;

  if( FD_LIKELY( slot>=DRAGON_KEEP_SLOTS ) ) {
    ulong keep_from = slot - DRAGON_KEEP_SLOTS;
    for( ulong i=0UL; i<DRAGON_META_MAX; i++ ) {
      if( rpc->meta[ i ].slot!=ULONG_MAX && rpc->meta[ i ].slot<keep_from ) rpc->meta[ i ].slot = ULONG_MAX;
    }
  }

  if( FD_LIKELY( slot>=DRAGON_BLOCKHASH_WINDOW ) ) {
    ulong keep_from = slot - DRAGON_BLOCKHASH_WINDOW;
    for( ulong i=0UL; i<DRAGON_HASH_MAX; i++ ) {
      if( rpc->hash[ i ].slot!=ULONG_MAX && rpc->hash[ i ].slot<keep_from ) {
        rpc->hash[ i ].slot = ULONG_MAX;
        rpc->hash_cnt--;
      }
    }
  }

  rpc->metrics.blockhash_cnt = rpc->hash_cnt;

  ulong cnt = 0UL;
  for( ulong i=0UL; i<DRAGON_META_MAX; i++ ) cnt += rpc->meta[ i ].slot!=ULONG_MAX;
  rpc->metrics.block_meta_tracked = cnt;
}

/* dragon_level_meta returns the block meta of the latest slot at the
   level, or NULL if there is none: either nothing reached the level
   yet, or the meta of the slot that did has already been forgotten,
   which is the case yellowstone answers "block is not available yet"
   for. */

static dragon_meta_t *
dragon_level_meta( fd_dragon_rpc_t * rpc,
                   int               commitment ) {
  if( FD_UNLIKELY( !rpc->have_level[ commitment ] ) ) return NULL;
  return dragon_meta_query( rpc, rpc->level_slot[ commitment ] );
}

/* Sessions **********************************************************/

static fd_dragon_session_t *
dragon_session_acquire( fd_dragon_rpc_t *         rpc,
                        fd_grpc_server_stream_t * stream,
                        int                       method ) {
  for( ulong i=0UL; i<rpc->stream_max; i++ ) {
    fd_dragon_session_t * s = rpc->session + i;
    if( s->stream ) continue;
    fd_memset( s, 0, sizeof(fd_dragon_session_t) );
    s->stream        = stream;
    s->method        = method;
    s->request_nanos = rpc->now + FD_DRAGON_REQUEST_NANOS;
    s->kind   = method==FD_DRAGON_METHOD_SUBSCRIBE    ? FD_DRAGON_SESSION_SUBSCRIBE
              : method==FD_DRAGON_METHOD_HEALTH_WATCH ? FD_DRAGON_SESSION_HEALTH_WATCH
                                                      : FD_DRAGON_SESSION_NONE;
    fd_dragon_filter_set_init( s->filter, dragon_cuckoo_arena( rpc, i ), rpc->cuckoo_entry_max );
    rpc->metrics.stream_cnt++;
    return s;
  }
  return NULL;
}

/* Encoding **********************************************************/

/* dragon_encode encodes one message into the shared response buffer.
   Returns the encoded size, or ULONG_MAX on failure. */

static ulong
dragon_encode( fd_dragon_rpc_t *     rpc,
               pb_msgdesc_t const *  fields,
               void const *          msg ) {
  pb_ostream_t os = pb_ostream_from_buffer( rpc->msg_buf, sizeof(rpc->msg_buf) );
  if( FD_UNLIKELY( !pb_encode( &os, fields, msg ) ) ) return ULONG_MAX;
  return (ulong)os.bytes_written;
}

/* dragon_respond sends one response message and ends the call.  A
   response that does not fit or a queue that cannot take it ends the
   call with internal("failed to build response") instead. */

static void
dragon_respond( fd_dragon_rpc_t *         rpc,
                fd_grpc_server_stream_t * stream,
                pb_msgdesc_t const *      fields,
                void const *              msg ) {
  ulong sz = dragon_encode( rpc, fields, msg );
  if( FD_UNLIKELY( sz==ULONG_MAX ) ) {
    DRAGON_FINISH( stream, FD_GRPC_STATUS_INTERNAL, DRAGON_MSG_BUILD_FAILED );
    return;
  }
  int err = fd_grpc_server_send( stream, rpc->msg_buf, sz, 0U );
  if( FD_UNLIKELY( err!=FD_GRPC_SERVER_SUCCESS ) ) {
    DRAGON_FINISH( stream, FD_GRPC_STATUS_INTERNAL, DRAGON_MSG_BUILD_FAILED );
    return;
  }
  fd_grpc_server_finish( stream, FD_GRPC_STATUS_OK, NULL, 0UL );
}

/* dragon_session_finish ends a call and remembers that the session no
   longer has anything to say.  The transport reports stream_close only
   once it has delivered the trailers, and HTTP/2 keeps trailers behind
   the DATA already queued, so a client that stops reading holds the
   call open: fd_dragon_rpc_service gives up its connection
   FD_DRAGON_REAP_NANOS later. */

static void
dragon_session_finish( fd_dragon_rpc_t *     rpc,
                       fd_dragon_session_t * s,
                       uint                  grpc_status,
                       char const *          grpc_msg,
                       ulong                 msg_len ) {
  s->finished   = 1;
  s->reap_nanos = rpc->now + FD_DRAGON_REAP_NANOS;
  fd_grpc_server_finish( s->stream, grpc_status, grpc_msg, msg_len );
}

#define DRAGON_SESSION_FINISH(rpc,s,status,lit) \
  dragon_session_finish( (rpc), (s), (status), (lit), sizeof(lit)-1UL )

/* Health service (grpc.health.v1, health.proto) **********************/

/* The names the tile answers for: the empty one is the whole server,
   as the health checking protocol defines it, and the other is the one
   service it serves.  tonic-health, which yellowstone loads, registers
   exactly this pair -- the empty name in HealthReporter::new
   (tonic-health-0.14.6/src/server.rs:40-43) and the service name in
   set_serving::<GeyserServer<_>>, which is what the yellowstone client
   asks for (yellowstone-grpc-client/src/lib.rs:494-496). */

#define DRAGON_HEALTH_SERVICE "geyser.Geyser"

/* Anything else is NOT_FOUND with tonic-health's own text, for Watch
   as much as for Check: tonic answers a Watch of an unknown service
   with not_found rather than the SERVICE_UNKNOWN message health.proto
   suggests (tonic-health-0.14.6/src/server.rs:137,152). */

#define DRAGON_MSG_NO_SERVICE "service not registered"

struct dragon_health_req {
  char  name[ 64 ];
  ulong name_len;
  int   too_long;  /* a service name longer than any this tile serves */
};

typedef struct dragon_health_req dragon_health_req_t;

static bool
dragon_health_name_cb( pb_istream_t *     stream,
                       pb_field_t const * field,
                       void **            arg ) {
  (void)field;
  dragon_health_req_t * req = *arg;
  ulong len = (ulong)stream->bytes_left;
  if( FD_UNLIKELY( len>=sizeof(req->name) ) ) {
    req->too_long = 1;
    req->name_len = 0UL;
    return pb_read( stream, NULL, stream->bytes_left );
  }
  if( FD_UNLIKELY( !pb_read( stream, (pb_byte_t *)req->name, (size_t)len ) ) ) return false;
  req->name[ len ] = '\0';
  req->name_len    = len;
  req->too_long    = 0;
  return true;
}

/* dragon_health_known reports whether the request names a service this
   tile answers for.  Returns -1 when the request does not decode. */

static int
dragon_health_known( fd_dragon_rpc_t * rpc,
                     uchar const *     msg,
                     ulong             msg_sz ) {
  dragon_health_req_t got = { .name = { '\0' }, .name_len = 0UL, .too_long = 0 };

  grpc_health_v1_HealthCheckRequest req = grpc_health_v1_HealthCheckRequest_init_zero;
  req.service.funcs.decode = dragon_health_name_cb;
  req.service.arg          = &got;

  pb_istream_t is = pb_istream_from_buffer( (pb_byte_t const *)msg, (size_t)msg_sz );
  if( FD_UNLIKELY( !pb_decode( &is, grpc_health_v1_HealthCheckRequest_fields, &req ) ) ) {
    rpc->metrics.decode_fail_cnt++;
    return -1;
  }
  if( FD_UNLIKELY( got.too_long ) ) return 0;
  return ( got.name_len==0UL ) ||
         ( got.name_len==sizeof(DRAGON_HEALTH_SERVICE)-1UL &&
           fd_memeq( got.name, DRAGON_HEALTH_SERVICE, got.name_len ) );
}

static int
dragon_health_status( fd_dragon_rpc_t const * rpc ) {
  return rpc->health_serving ? grpc_health_v1_HealthCheckResponse_ServingStatus_SERVING
                             : grpc_health_v1_HealthCheckResponse_ServingStatus_NOT_SERVING;
}

/* dragon_health_send queues one HealthCheckResponse on an open Watch
   stream.  A client that has stopped reading ends its own call. */

static void
dragon_health_send( fd_dragon_rpc_t *     rpc,
                    fd_dragon_session_t * s,
                    int                   status ) {
  grpc_health_v1_HealthCheckResponse res = grpc_health_v1_HealthCheckResponse_init_zero;
  res.status = (grpc_health_v1_HealthCheckResponse_ServingStatus)status;

  ulong sz = dragon_encode( rpc, grpc_health_v1_HealthCheckResponse_fields, &res );
  if( FD_UNLIKELY( sz==ULONG_MAX ) ) {
    DRAGON_SESSION_FINISH( rpc, s, FD_GRPC_STATUS_INTERNAL, DRAGON_MSG_BUILD_FAILED );
    return;
  }
  if( FD_UNLIKELY( fd_grpc_server_send( s->stream, rpc->msg_buf, sz, 0U )!=FD_GRPC_SERVER_SUCCESS ) ) {
    DRAGON_SESSION_FINISH( rpc, s, FD_GRPC_STATUS_INTERNAL, DRAGON_MSG_LAGGED_SEND );
    return;
  }
  s->health_status = status;
}

/* dragon_health_watch_request answers the one request of a Watch call
   with the status as it stands.  The stream then stays open and
   fd_dragon_rpc_set_serving sends the changes. */

static void
dragon_health_watch_request( fd_dragon_rpc_t *     rpc,
                             fd_dragon_session_t * s,
                             uchar const *         msg,
                             ulong                 msg_sz ) {
  if( FD_UNLIKELY( s->answered || s->finished ) ) return; /* a watch takes one request message */

  int known = dragon_health_known( rpc, msg, msg_sz );
  if( FD_UNLIKELY( known<0 ) ) {
    DRAGON_SESSION_FINISH( rpc, s, FD_GRPC_STATUS_INVALID_ARGUMENT, "failed to decode request" );
    return;
  }
  if( FD_UNLIKELY( !known ) ) {
    DRAGON_SESSION_FINISH( rpc, s, FD_GRPC_STATUS_NOT_FOUND, DRAGON_MSG_NO_SERVICE );
    return;
  }

  s->answered = 1;
  dragon_health_send( rpc, s, dragon_health_status( rpc ) );
}

void
fd_dragon_rpc_set_serving( fd_dragon_rpc_t * rpc,
                           int               serving ) {
  serving = !!serving;
  if( FD_LIKELY( rpc->health_serving==serving ) ) return;
  rpc->health_serving = serving;

  /* Clients queued while the server was not serving are accepted from
     here on, and what they see begins at the first bank created from
     here on: no stream opens in the middle of a block. */
  if( serving ) rpc->serve_from_bank_seq = rpc->bank_seq_hi+1UL;

  int status = dragon_health_status( rpc );
  for( ulong i=0UL; i<rpc->stream_max; i++ ) {
    fd_dragon_session_t * s = rpc->session + i;
    if( s->kind!=FD_DRAGON_SESSION_HEALTH_WATCH ) continue;
    if( !s->answered || s->finished )              continue;
    if( s->health_status==status )                 continue;
    dragon_health_send( rpc, s, status );
  }
}

/* dragon_filter_list is the filter names of one client that a message
   matched, which the update echoes back in its filters field. */

struct dragon_filter_list {
  ulong                           cnt;
  fd_dragon_filter_name_t const * name[ FD_DRAGON_FILTER_MAX ];
};

typedef struct dragon_filter_list dragon_filter_list_t;

static bool
dragon_encode_filters( pb_ostream_t *     stream,
                       pb_field_t const * field,
                       void * const *     arg ) {
  dragon_filter_list_t const * list = *arg;
  for( ulong i=0UL; i<list->cnt; i++ ) {
    if( FD_UNLIKELY( !pb_encode_tag_for_field( stream, field ) ) ) return false;
    if( FD_UNLIKELY( !pb_encode_string( stream, (pb_byte_t const *)list->name[ i ]->cstr,
                                        (size_t)list->name[ i ]->len ) ) ) return false;
  }
  return true;
}

/* dragon_update_send sends one SubscribeUpdate on a subscription
   stream.  A client whose queue cannot take the update is dropped
   with internal("lagged to send an update"). */

static void
dragon_update_send( fd_dragon_rpc_t *            rpc,
                    fd_dragon_session_t *        s,
                    geyser_SubscribeUpdate *     update,
                    dragon_filter_list_t const * list ) {
  if( FD_LIKELY( list && list->cnt ) ) {
    update->filters.funcs.encode = dragon_encode_filters;
    update->filters.arg          = (void *)list;
  }

  update->has_created_at     = true;
  update->created_at.seconds = rpc->now / 1000000000L;
  update->created_at.nanos   = (int32_t)( rpc->now % 1000000000L );

  ulong sz = dragon_encode( rpc, geyser_SubscribeUpdate_fields, update );
  if( FD_UNLIKELY( sz==ULONG_MAX ) ) {
    DRAGON_SESSION_FINISH( rpc, s, FD_GRPC_STATUS_INTERNAL, DRAGON_MSG_BUILD_FAILED );
    return;
  }

  int err = fd_grpc_server_send( s->stream, rpc->msg_buf, sz, 0U );
  if( FD_UNLIKELY( err==FD_GRPC_SERVER_ERR_CLOSED ) ) {
    s->finished = 1;
    return;
  }
  if( FD_UNLIKELY( err!=FD_GRPC_SERVER_SUCCESS ) ) {
    rpc->metrics.lagged_close_cnt++;
    DRAGON_SESSION_FINISH( rpc, s, FD_GRPC_STATUS_INTERNAL, DRAGON_MSG_LAGGED_SEND );
    return;
  }

  s->update_cnt++;
  rpc->metrics.update_sent_cnt++;
  if( update->which_update_oneof==geyser_SubscribeUpdate_slot_tag ) rpc->metrics.slot_byte_cnt += sz;
}

/* Content delivery ***************************************************/

/* The messages that carry content are assembled by hand out of a body
   that was encoded once: a client's own filter names, the shared body,
   and the server's wall clock.  Protobuf lets the fields of a message
   go out in any order, so every client gets byte identical body bytes
   with its own names in front, which is what a yellowstone server does
   (plugin/filter/message.rs:84-92). */

static ulong
dragon_varint( uchar * out,
               ulong   v ) {
  ulong o = 0UL;
  while( v>=0x80UL ) { out[ o++ ] = (uchar)( ( v & 0x7FUL ) | 0x80UL ); v >>= 7; }
  out[ o++ ] = (uchar)v;
  return o;
}

static ulong
dragon_varint_sz( ulong v ) {
  ulong n = 1UL;
  while( v>=0x80UL ) { v >>= 7; n++; }
  return n;
}

/* dragon_field_hdr writes the tag and length prefix of a length
   delimited field. */

static ulong
dragon_field_hdr( uchar * out,
                  uint    field,
                  ulong   body_sz ) {
  ulong o = dragon_varint( out, ( ((ulong)field)<<3 ) | 2UL );
  return o + dragon_varint( out+o, body_sz );
}

/* dragon_created_at writes the created_at field of a SubscribeUpdate:
   a google.protobuf.Timestamp of the server's wall clock, whose
   seconds and nanoseconds are each omitted when zero. */

static ulong
dragon_created_at( fd_dragon_rpc_t const * rpc,
                   uchar *                 out ) {
  long  now     = rpc->now;
  ulong seconds = (ulong)( now/1000000000L );
  ulong nanos   = (ulong)( now%1000000000L );
  ulong ts_sz   = ( seconds ? 1UL+dragon_varint_sz( seconds ) : 0UL ) +
                  ( nanos   ? 1UL+dragon_varint_sz( nanos   ) : 0UL );

  ulong o = 0UL;
  out[ o++ ] = (uchar)( ( DRAGON_UPDATE_CREATED_AT_FIELD<<3 ) | 2U );
  o += dragon_varint( out+o, ts_sz );
  if( seconds ) { out[ o++ ] = (uchar)( (DRAGON_TS_SECONDS_FIELD<<3) | 0U ); o += dragon_varint( out+o, seconds ); }
  if( nanos   ) { out[ o++ ] = (uchar)( (DRAGON_TS_NANOS_FIELD  <<3) | 0U ); o += dragon_varint( out+o, nanos   ); }
  return o;
}

/* dragon_names_sz is the room the filter names of one client take in
   an update. */

FD_FN_PURE static ulong
dragon_names_sz( fd_dragon_session_t const * s,
                 ulong                       name_mask ) {
  ulong sz = 0UL;
  for( ulong j=0UL; j<s->filter->name_cnt; j++ ) {
    if( !( name_mask & (1UL<<j) ) ) continue;
    sz += s->filter->name[ j ].len + 8UL;
  }
  return sz;
}

/* dragon_names_write writes the filter names of one client that a
   message matched, as the repeated filters field of the update. */

static ulong
dragon_names_write( fd_dragon_session_t const * s,
                    ulong                       name_mask,
                    uchar *                     out ) {
  ulong o = 0UL;
  for( ulong j=0UL; j<s->filter->name_cnt; j++ ) {
    if( !( name_mask & (1UL<<j) ) ) continue;
    fd_dragon_filter_name_t const * name = s->filter->name + j;
    out[ o++ ] = (uchar)( ( DRAGON_UPDATE_FILTERS_FIELD<<3 ) | 2U );
    o += dragon_varint( out+o, name->len );
    fd_memcpy( out+o, name->cstr, name->len );
    o += name->len;
  }
  return o;
}

static void
dragon_oversize( fd_dragon_session_t * s,
                 char const *          what,
                 ulong                 sz );

/* dragon_names_eq returns 1 if the filter names of two clients that a
   message matched go out as the same bytes: the same names in the
   same order, whatever positions they hold in each client's filter
   set. */

static int
dragon_names_eq( fd_dragon_session_t const * a,
                 ulong                       mask_a,
                 fd_dragon_session_t const * b,
                 ulong                       mask_b ) {
  ulong ia = 0UL;
  ulong ib = 0UL;
  for(;;) {
    while( ia<a->filter->name_cnt && !( ( mask_a>>ia ) & 1UL ) ) ia++;
    while( ib<b->filter->name_cnt && !( ( mask_b>>ib ) & 1UL ) ) ib++;
    int end_a = ia>=a->filter->name_cnt;
    int end_b = ib>=b->filter->name_cnt;
    if( end_a || end_b ) return end_a && end_b;
    fd_dragon_filter_name_t const * na = a->filter->name + ia;
    fd_dragon_filter_name_t const * nb = b->filter->name + ib;
    if( na->len!=nb->len || !fd_memeq( na->cstr, nb->cstr, na->len ) ) return 0;
    ia++;
    ib++;
  }
}

/* dragon_names_group takes out of *mask its lowest client and every
   other client whose names for the message, names[ i ], are the same
   bytes as that client's, and returns them: the clients one message,
   staged once, serves. */

static ulong
dragon_names_group( fd_dragon_rpc_t const * rpc,
                    ulong *                 mask,
                    ulong const *           names ) {
  ulong i     = (ulong)fd_ulong_find_lsb( *mask );
  ulong group = 1UL<<i;
  for( ulong j=i+1UL; j<rpc->stream_max; j++ ) {
    if( !( ( *mask>>j ) & 1UL ) ) continue;
    if( dragon_names_eq( rpc->session + i, names[ i ], rpc->session + j, names[ j ] ) ) group |= 1UL<<j;
  }
  *mask &= ~group;
  return group;
}

/* dragon_send_group hands one assembled message to the transport for
   every client of group, which stages it once for all of them, and
   settles each client's result: a client whose call is gone is marked
   finished, one the transport cannot queue the message for is closed
   as lagging, and an account update or a block larger than one
   message may be is dropped for the client and counted, since nothing
   about it says the client is slow.  field is the update's oneof
   member, which the counters are kept by, and body_sz the shared body
   bytes the transaction counters count. */

static void
dragon_send_group( fd_dragon_rpc_t * rpc,
                   ulong             group,
                   uchar const *     msg,
                   ulong             msg_sz,
                   uint              field,
                   ulong             body_sz ) {
  fd_grpc_server_stream_t * streams[ FD_DRAGON_CLIENT_MAX ];
  ulong                     idx    [ FD_DRAGON_CLIENT_MAX ];
  int                       err    [ FD_DRAGON_CLIENT_MAX ];
  ulong                     cnt = 0UL;
  for( ulong i=0UL; i<rpc->stream_max; i++ ) {
    if( !( ( group>>i ) & 1UL ) ) continue;
    streams[ cnt ] = rpc->session[ i ].stream;
    idx    [ cnt ] = i;
    cnt++;
  }
  fd_grpc_server_send_multi( streams, cnt, msg, msg_sz, 0U, err );

  for( ulong k=0UL; k<cnt; k++ ) {
    fd_dragon_session_t * s = rpc->session + idx[ k ];
    if( FD_UNLIKELY( err[ k ]==FD_GRPC_SERVER_ERR_CLOSED ) ) {
      s->finished = 1;
      continue;
    }
    if( FD_UNLIKELY( err[ k ]==FD_GRPC_SERVER_ERR_TOOBIG &&
                     ( field==DRAGON_UPDATE_ACCOUNT_FIELD || field==DRAGON_UPDATE_BLOCK_FIELD ) ) ) {
      if( field==DRAGON_UPDATE_ACCOUNT_FIELD ) rpc->metrics.acct_oversize_cnt++;
      else                                     rpc->metrics.block_oversize_cnt++;
      dragon_oversize( s, field==DRAGON_UPDATE_ACCOUNT_FIELD ? "an account update" : "a block", msg_sz );
      continue;
    }
    if( FD_UNLIKELY( err[ k ]!=FD_GRPC_SERVER_SUCCESS ) ) {
      rpc->metrics.lagged_close_cnt++;
      DRAGON_SESSION_FINISH( rpc, s, FD_GRPC_STATUS_INTERNAL, DRAGON_MSG_LAGGED_SEND );
      continue;
    }

    s->update_cnt++;
    rpc->metrics.update_sent_cnt++;
    switch( field ) {
    case DRAGON_UPDATE_TXN_FIELD:        rpc->metrics.txn_update_cnt++;      rpc->metrics.txn_byte_cnt        += body_sz; break;
    case DRAGON_UPDATE_TXN_STATUS_FIELD: rpc->metrics.txn_status_cnt++;      rpc->metrics.status_byte_cnt     += body_sz; break;
    case DRAGON_UPDATE_BLOCK_META_FIELD: rpc->metrics.block_meta_sent_cnt++; rpc->metrics.block_meta_byte_cnt += body_sz; break;
    case DRAGON_UPDATE_ACCOUNT_FIELD:    rpc->metrics.acct_update_cnt++;     rpc->metrics.acct_byte_cnt       += msg_sz;  break;
    case DRAGON_UPDATE_BLOCK_FIELD:      rpc->metrics.block_sent_cnt++;      rpc->metrics.block_byte_cnt      += msg_sz;  break;
    default: break;
    }
  }
}

/* dragon_update_raw3_group assembles one SubscribeUpdate whose oneof
   member is field, carrying pre, body and post one after the other,
   under the filter names of the group's lowest client named by
   name_mask, which every client of the group shares byte for byte,
   and sends it to all of them.  The three parts let a message be sent
   from bytes that were encoded once and shared, wrapped in the fields
   that belong to this update. */

static void
dragon_update_raw3_group( fd_dragon_rpc_t * rpc,
                          ulong             group,
                          ulong             name_mask,
                          uint              field,
                          uchar const *     pre,
                          ulong             pre_sz,
                          uchar const *     body,
                          ulong             body_sz,
                          uchar const *     post,
                          ulong             post_sz ) {
  fd_dragon_session_t const * s   = rpc->session + fd_ulong_find_lsb( group );
  uchar *                     out = rpc->update_buf;
  ulong                       o   = dragon_names_write( s, name_mask, out );

  o += dragon_field_hdr( out+o, field, pre_sz+body_sz+post_sz );
  if( FD_UNLIKELY( pre_sz  ) ) { fd_memcpy( out+o, pre,  pre_sz  ); o += pre_sz;  }
  if( FD_LIKELY  ( body_sz ) ) { fd_memcpy( out+o, body, body_sz ); o += body_sz; }
  if( FD_UNLIKELY( post_sz ) ) { fd_memcpy( out+o, post, post_sz ); o += post_sz; }

  o += dragon_created_at( rpc, out+o );

  dragon_send_group( rpc, group, out, o, field, body_sz );
}

/* dragon_update_fits is the room one client's message needs, which
   bounds the body a client can be sent.  A body that does not fit is
   never assembled; this is the encoder's own bound, not the client's
   queue, which is handled by the lagged close above. */

static int
dragon_update_fits( fd_dragon_session_t const * s,
                    ulong                       body_sz ) {
  ulong names = 0UL;
  for( ulong j=0UL; j<s->filter->name_cnt; j++ ) names += s->filter->name[ j ].len + 8UL;
  return body_sz + names + 32UL <= FD_DRAGON_UPDATE_SZ_MAX;
}

/* dragon_update_body_send sends one SubscribeUpdate whose oneof member
   is field with the given body to the clients of mask, under the
   filter names of client i in names[ i ], one staged message per set
   of clients whose names are the same bytes.  A client the body does
   not fit with its names is skipped and counted. */

static void
dragon_update_body_send( fd_dragon_rpc_t * rpc,
                         ulong             mask,
                         ulong const *     names,
                         uint              field,
                         uchar const *     body,
                         ulong             body_sz ) {
  while( mask ) {
    ulong group = dragon_names_group( rpc, &mask, names );
    for( ulong i=0UL; i<rpc->stream_max; i++ ) {
      if( ( ( group>>i ) & 1UL ) && !dragon_update_fits( rpc->session + i, body_sz ) ) {
        rpc->metrics.encode_fail_cnt++;
        group &= ~( 1UL<<i );
      }
    }
    if( FD_LIKELY( group ) )
      dragon_update_raw3_group( rpc, group, names[ fd_ulong_find_lsb( group ) ], field, NULL, 0UL, body, body_sz, NULL, 0UL );
  }
}

/* dragon_session_active returns 1 if a session can be sent an update
   right now. */

static int
dragon_session_active( fd_dragon_session_t const * s ) {
  return s->kind==FD_DRAGON_SESSION_SUBSCRIBE && !s->finished;
}

/* dragon_recount refreshes the counts that let a record cost nothing
   when nobody is subscribed to it. */

static void
dragon_recount( fd_dragon_rpc_t * rpc ) {
  ulong txn = 0UL;
  ulong bm  = 0UL;
  ulong def = 0UL;
  ulong acc = 0UL;
  ulong blk = 0UL;
  for( ulong i=0UL; i<rpc->stream_max; i++ ) {
    fd_dragon_session_t const * s = rpc->session + i;
    if( !dragon_session_active( s ) ) continue;
    txn += !!( s->filter->type_cnt[ FD_DRAGON_FILTER_TRANSACTIONS        ] ||
               s->filter->type_cnt[ FD_DRAGON_FILTER_TRANSACTIONS_STATUS ] );
    bm  += !!  s->filter->type_cnt[ FD_DRAGON_FILTER_BLOCKS_META         ];
    acc += !!  s->filter->type_cnt[ FD_DRAGON_FILTER_ACCOUNTS            ];
    blk += !!  s->filter->type_cnt[ FD_DRAGON_FILTER_BLOCKS              ];
    def += !!  s->deferred;
  }
  rpc->txn_sub_cnt        = txn;
  rpc->block_meta_sub_cnt = bm;
  rpc->acct_sub_cnt       = acc;
  rpc->blocks_sub_cnt     = blk;
  rpc->deferred_sub_cnt   = def;
}

/* dragon_blocks_clients returns the client slots a block of the bank
   is owed to: a subscription with a blocks filter that is eligible for
   the bank.  A block is served from the buffer, so with the filters at
   ingest a subscription is eligible for the banks created after its
   filters were installed, whatever its commitment: a bank already in
   flight would otherwise produce a block missing everything that
   arrived before the client did. */

FD_FN_PURE static ulong
dragon_blocks_clients( fd_dragon_rpc_t const * rpc,
                       ulong                   bank_id ) {
  if( FD_LIKELY( !rpc->blocks_sub_cnt ) ) return 0UL;

  ulong mask = 0UL;
  for( ulong i=0UL; i<rpc->stream_max; i++ ) {
    fd_dragon_session_t const * s = rpc->session + i;
    if( !dragon_session_active( s ) ) continue;
    if( !s->filter->type_cnt[ FD_DRAGON_FILTER_BLOCKS ] ) continue;
    if( bank_id<s->eligible_from_bank_seq ) continue;
    mask |= 1UL<<i;
  }
  return mask;
}

/* Degraded banks *****************************************************/

/* dragon_degrade records that nothing will be delivered for a bank at
   the buffered levels.  The reason is that the buffer could not hold
   the bank: an entry of it could not be built or was larger than the
   ring, in which case the bank is noted incomplete, or the bank table
   was full, in which case the bank is remembered here. */

static void
dragon_degrade( fd_dragon_rpc_t *      rpc,
                fd_dragon_buf_bank_t * bank,
                ulong                  bank_seq ) {
  if( FD_LIKELY( bank ) ) {
    if( FD_UNLIKELY( bank->incomplete ) ) return;
    bank->incomplete = 1;
    rpc->metrics.degrade_cnt++;
    return;
  }

  for( ulong i=0UL; i<FD_DRAGON_DEGRADE_MAX; i++ ) {
    if( rpc->degrade_bank[ i ]==bank_seq ) return;
  }
  rpc->degrade_bank[ rpc->degrade_next ] = bank_seq;
  rpc->degrade_next = ( rpc->degrade_next+1UL ) % FD_DRAGON_DEGRADE_MAX;
  rpc->metrics.degrade_cnt++;
}

static int
dragon_degraded( fd_dragon_rpc_t const * rpc,
                 ulong                   bank_seq ) {
  for( ulong i=0UL; i<FD_DRAGON_DEGRADE_MAX; i++ ) {
    if( rpc->degrade_bank[ i ]==bank_seq ) return 1;
  }
  return 0;
}

/* dragon_buf_bank_open returns the buffer's entry for a bank, creating
   it if it is new.  Returns NULL if the table has no room, and notes
   the bank as degraded. */

static fd_dragon_buf_bank_t *
dragon_buf_bank_open( fd_dragon_rpc_t * rpc,
                      ulong             bank_seq,
                      ulong             slot ) {
  fd_dragon_buf_bank_t * bank = fd_dragon_buf_bank( rpc->buf, bank_seq );
  if( FD_LIKELY( bank ) ) return bank;

  bank = fd_dragon_buf_bank_open( rpc->buf, bank_seq, slot );
  if( FD_UNLIKELY( !bank ) ) {
    /* A table with no room stays that way for as long as the banks it
       holds do, which is every bank until then. */
    FD_DRAGON_WARN_POW2( rpc->metrics.degrade_cnt+1UL,
                         "dragon has no room to buffer bank_id %lu (slot %lu)", bank_seq, slot );
    dragon_degrade( rpc, NULL, bank_seq );
    return NULL;
  }
  return bank;
}

/* dragon_buf_bank_overrun returns 1 if the ring has come round and
   overwritten part of the bank before it was served, which is a
   buffer too small for the lag between a bank's records and its
   finalization.  Reported once per power of two, since every one of
   these is a bank the subscribers at the buffered levels miss. */

static int
dragon_buf_bank_overrun( fd_dragon_rpc_t *      rpc,
                         fd_dragon_buf_bank_t * bank ) {
  if( FD_LIKELY( fd_dragon_buf_bank_live( rpc->buf, bank ) ) ) return 0;
  FD_DRAGON_WARN_POW2( fd_dragon_buf_metrics( rpc->buf )->overrun_cnt,
                       "dragon buffer overwrote bank_id %lu (slot %lu) before it was served: "
                       "[tiles.dragon.buffer_size_mib] does not cover the finalization lag",
                       bank->bank_seq, bank->slot );
  return 1;
}

/* dragon_buf_names writes the per client name masks of a buffered
   entry: for every client of push_mask, in slot order, the names of
   its own subscriptions that matched, of its status subscriptions,
   and of its blocks filters the entry belongs to.  A NULL name mask
   array stores zeros, which is what an account write keeps for its
   blocks: which blocks carry an account is decided by pubkey when the
   block is built. */

static void
dragon_buf_names( fd_dragon_buf_hdr_t * hdr,
                  ulong                 mask,
                  ulong const *         name_mask,
                  ulong                 status_mask,
                  ulong const *         status_name_mask,
                  ulong                 block_mask,
                  ulong const *         block_name_mask ) {
  ulong   push_mask = mask | status_mask | block_mask;
  ulong * names     = fd_dragon_buf_hdr_names( hdr );
  ulong   n         = 0UL;

  hdr->mask        = mask;
  hdr->status_mask = status_mask;
  hdr->block_mask  = block_mask;
  hdr->push_mask   = push_mask;
  hdr->name_cnt    = (uint)fd_ulong_popcnt( push_mask );

  for( ulong i=0UL; i<FD_DRAGON_CLIENT_MAX; i++ ) {
    ulong bit = 1UL<<i;
    if( !( push_mask & bit ) ) continue;
    names[ n*FD_DRAGON_BUF_NAME_CNT + FD_DRAGON_BUF_NAME_TXN    ] = ( ( mask        & bit ) && name_mask        ) ? name_mask       [ i ] : 0UL;
    names[ n*FD_DRAGON_BUF_NAME_CNT + FD_DRAGON_BUF_NAME_STATUS ] = ( ( status_mask & bit ) && status_name_mask ) ? status_name_mask[ i ] : 0UL;
    names[ n*FD_DRAGON_BUF_NAME_CNT + FD_DRAGON_BUF_NAME_BLOCK  ] = ( ( block_mask  & bit ) && block_name_mask  ) ? block_name_mask [ i ] : 0UL;
    n++;
  }
}

/* Accounts ***********************************************************/

/* DRAGON_ACCT_INFO_OVERHEAD is what an account update takes besides
   the account's data: the pubkey, the owner, the signature and eight
   scalar fields with their tags. */

#define DRAGON_ACCT_INFO_OVERHEAD (256UL)

/* DRAGON_WRAP_RESERVE is the room left in front of a message that is
   assembled body first, for the tag and length prefixes of the fields
   it ends up nested in. */

#define DRAGON_WRAP_RESERVE (32UL)


/* dragon_wrap writes the tag and length prefix of a length delimited
   field so that they end at buf+end, which is where the field's body
   starts, and returns the offset the field itself starts at. */

static ulong
dragon_wrap( uchar * buf,
             ulong   end,
             uint    field,
             ulong   body_sz ) {
  uchar hdr[ 16 ];
  ulong hdr_sz = dragon_field_hdr( hdr, field, body_sz );
  fd_memcpy( buf+end-hdr_sz, hdr, hdr_sz );
  return end-hdr_sz;
}

/* dragon_acct_data_t is where an account's data is: NULL for the
   whole of it behind the write's data pointer, or the segments a
   buffered entry holds of it. */

struct dragon_acct_data {
  fd_dragon_buf_seg_t const * seg;
  ulong                       seg_cnt;
  uchar const *               bytes;
};

typedef struct dragon_acct_data dragon_acct_data_t;

/* dragon_slice_fits returns 1 if a slice lies wholly inside data_sz.
   offset and length are unbounded client values, so the span is
   compared against what remains rather than summed. */

FD_FN_PURE static inline int
dragon_slice_fits( fd_dragon_data_slice_t const * slice,
                   ulong                          data_sz ) {
  return ( slice->offset<=data_sz ) & ( slice->length<=data_sz-slice->offset );
}

/* dragon_slice_ptr returns where len bytes of the account's data from
   off are, or NULL if the slice does not fit the account or the entry
   does not hold it. */

static uchar const *
dragon_slice_ptr( fd_geyser_account_t const * acct,
                  dragon_acct_data_t const *  view,
                  ulong                       off,
                  ulong                       len ) {
  if( FD_UNLIKELY( off>acct->data_sz || len>acct->data_sz-off ) ) return NULL;
  if( FD_UNLIKELY( !len ) ) return (uchar const *)"";
  if( FD_LIKELY( !view ) ) return acct->data + off;

  ulong o = 0UL;
  for( ulong i=0UL; i<view->seg_cnt; i++ ) {
    fd_dragon_buf_seg_t const * seg = view->seg + i;
    if( off>=seg->off && off-seg->off<=seg->len && len<=seg->len-( off-seg->off ) ) return view->bytes + o + ( off-seg->off );
    o += seg->len;
  }
  return NULL;
}

/* dragon_slice_len is how much of an account's data a data slice
   configuration keeps, and dragon_slice_copy copies it.  A slice the
   account is too short for is left out whole, and an empty
   configuration keeps everything, which is what yellowstone's
   FilterAccountsDataSlice does (plugin/filter/filter.rs:2349-2383).
   ULONG_MAX is a configuration the entry does not hold the data for,
   which only a subscriber the entry was not buffered for can have. */

static ulong
dragon_slice_len( fd_geyser_account_t const *    acct,
                  dragon_acct_data_t const *     view,
                  fd_dragon_data_slice_t const * slice,
                  ulong                          slice_cnt ) {
  if( FD_LIKELY( !slice_cnt ) ) return dragon_slice_ptr( acct, view, 0UL, acct->data_sz ) ? acct->data_sz : ULONG_MAX;

  ulong len = 0UL;
  for( ulong i=0UL; i<slice_cnt; i++ ) {
    if( !dragon_slice_fits( slice+i, acct->data_sz ) ) continue;
    if( FD_UNLIKELY( !dragon_slice_ptr( acct, view, slice[ i ].offset, slice[ i ].length ) ) ) return ULONG_MAX;
    len += slice[ i ].length;
  }
  return len;
}

static ulong
dragon_slice_copy( uchar *                        out,
                   fd_geyser_account_t const *    acct,
                   dragon_acct_data_t const *     view,
                   fd_dragon_data_slice_t const * slice,
                   ulong                          slice_cnt ) {
  if( FD_LIKELY( !slice_cnt ) ) {
    if( FD_LIKELY( acct->data_sz ) ) fd_memcpy( out, dragon_slice_ptr( acct, view, 0UL, acct->data_sz ), acct->data_sz );
    return acct->data_sz;
  }

  ulong o = 0UL;
  for( ulong i=0UL; i<slice_cnt; i++ ) {
    if( !dragon_slice_fits( slice+i, acct->data_sz ) ) continue;
    fd_memcpy( out+o, dragon_slice_ptr( acct, view, slice[ i ].offset, slice[ i ].length ), slice[ i ].length );
    o += slice[ i ].length;
  }
  return o;
}

/* dragon_slice_union writes to seg the segments of an account's data
   that the subscribers of mask need, merged and in offset order, and
   returns how many.  The whole of it when full is set or one of them
   slices nothing; a slice the account is too short for is left out,
   as it is when the account goes out. */

static ulong
dragon_slice_union( fd_dragon_rpc_t const *     rpc,
                    fd_geyser_account_t const * acct,
                    ulong                       mask,
                    int                         full,
                    fd_dragon_buf_seg_t *       seg ) {
  for( ulong i=0UL; !full && i<rpc->stream_max; i++ ) {
    if( ( ( mask>>i ) & 1UL ) && !rpc->session[ i ].filter->slice_cnt ) full = 1;
  }
  if( FD_LIKELY( full ) ) {
    if( FD_UNLIKELY( !acct->data_sz ) ) return 0UL;
    seg[ 0 ].off = 0UL;
    seg[ 0 ].len = acct->data_sz;
    return 1UL;
  }

  ulong cnt = 0UL;
  for( ulong i=0UL; i<rpc->stream_max; i++ ) {
    if( !( ( mask>>i ) & 1UL ) ) continue;
    fd_dragon_filter_set_t const * f = rpc->session[ i ].filter;
    for( ulong j=0UL; j<f->slice_cnt; j++ ) {
      if( !dragon_slice_fits( f->slice+j, acct->data_sz ) || !f->slice[ j ].length ) continue;
      /* Insert in offset order */
      ulong k = cnt;
      while( k && seg[ k-1UL ].off>f->slice[ j ].offset ) { seg[ k ] = seg[ k-1UL ]; k--; }
      seg[ k ].off = f->slice[ j ].offset;
      seg[ k ].len = f->slice[ j ].length;
      cnt++;
    }
  }

  /* Merge what overlaps or touches */
  ulong out = 0UL;
  for( ulong k=0UL; k<cnt; k++ ) {
    if( out && seg[ out-1UL ].off+seg[ out-1UL ].len>=seg[ k ].off ) {
      ulong end = fd_ulong_max( seg[ out-1UL ].off+seg[ out-1UL ].len, seg[ k ].off+seg[ k ].len );
      seg[ out-1UL ].len = end-seg[ out-1UL ].off;
      continue;
    }
    seg[ out++ ] = seg[ k ];
  }
  return out;
}

/* dragon_slice_eq returns 1 if two subscriptions apply the same data
   slices, which is when they can be sent the same encoded account. */

FD_FN_PURE static int
dragon_slice_eq( fd_dragon_filter_set_t const * a,
                 fd_dragon_filter_set_t const * b ) {
  if( a->slice_cnt!=b->slice_cnt ) return 0;
  for( ulong i=0UL; i<a->slice_cnt; i++ ) {
    if( a->slice[ i ].offset!=b->slice[ i ].offset ||
        a->slice[ i ].length!=b->slice[ i ].length ) return 0;
  }
  return 1;
}

/* DRAGON_ENCODE_TOOBIG and DRAGON_ENCODE_PARTIAL are what an account
   encoder returns for an account that does not fit its buffer, and for
   one the entry holds less of the data of than the subscription
   asked for. */

#define DRAGON_ENCODE_TOOBIG  (ULONG_MAX)
#define DRAGON_ENCODE_PARTIAL (ULONG_MAX-1UL)

/* dragon_acct_info_encode writes the body of a
   geyser.SubscribeUpdateAccountInfo, sliced as the subscription asked.
   Returns the number of bytes written, or one of DRAGON_ENCODE_*. */

static ulong
dragon_acct_info_encode( uchar *                        out,
                         ulong                          out_sz,
                         fd_geyser_account_t const *    acct,
                         dragon_acct_data_t const *     view,
                         fd_dragon_data_slice_t const * slice,
                         ulong                          slice_cnt ) {
  ulong data_len = dragon_slice_len( acct, view, slice, slice_cnt );
  if( FD_UNLIKELY( data_len==ULONG_MAX ) ) return DRAGON_ENCODE_PARTIAL;
  if( FD_UNLIKELY( out_sz<DRAGON_ACCT_INFO_OVERHEAD ||
                   data_len>out_sz-DRAGON_ACCT_INFO_OVERHEAD ) ) return DRAGON_ENCODE_TOOBIG;

  ulong o = 0UL;

  o += dragon_field_hdr( out+o, DRAGON_AI_PUBKEY_FIELD, 32UL );
  fd_memcpy( out+o, acct->pubkey, 32UL ); o += 32UL;

  if( acct->lamports ) {
    out[ o++ ] = (uchar)( (DRAGON_AI_LAMPORTS_FIELD<<3)|0U );
    o += dragon_varint( out+o, acct->lamports );
  }

  o += dragon_field_hdr( out+o, DRAGON_AI_OWNER_FIELD, 32UL );
  fd_memcpy( out+o, acct->owner, 32UL ); o += 32UL;

  if( acct->executable ) {
    out[ o++ ] = (uchar)( (DRAGON_AI_EXECUTABLE_FIELD<<3)|0U );
    out[ o++ ] = 1;
  }

  out[ o++ ] = (uchar)( (DRAGON_AI_RENT_EPOCH_FIELD<<3)|0U );
  o += dragon_varint( out+o, DRAGON_ACCT_RENT_EPOCH );

  if( data_len ) {
    o += dragon_field_hdr( out+o, DRAGON_AI_DATA_FIELD, data_len );
    o += dragon_slice_copy( out+o, acct, view, slice, slice_cnt );
  }

  if( acct->write_version ) {
    out[ o++ ] = (uchar)( (DRAGON_AI_WRITE_VERSION_FIELD<<3)|0U );
    o += dragon_varint( out+o, acct->write_version );
  }

  if( acct->txn_signature ) {
    o += dragon_field_hdr( out+o, DRAGON_AI_TXN_SIGNATURE_FIELD, 64UL );
    fd_memcpy( out+o, acct->txn_signature, 64UL ); o += 64UL;
  }

  return o;
}

/* dragon_acct_assemble builds the shared part of one SubscribeUpdate
   carrying an account into the layer's assembly buffer: the account
   state, the fields of the update around it, and the timestamp.  What
   is left per client is its filter names.

   Returns the offset the message starts at and writes the end of the
   shared part to end_out, or one of DRAGON_ENCODE_*. */

static ulong
dragon_acct_assemble( fd_dragon_rpc_t *              rpc,
                      fd_geyser_account_t const *    acct,
                      dragon_acct_data_t const *     view,
                      fd_dragon_data_slice_t const * slice,
                      ulong                          slice_cnt,
                      ulong *                        end_out ) {
  uchar * buf  = rpc->msg_big;
  ulong   head = DRAGON_WRAP_RESERVE;

  ulong info_sz = dragon_acct_info_encode( buf+head, rpc->msg_max-head-64UL, acct, view, slice, slice_cnt );
  if( FD_UNLIKELY( info_sz>=DRAGON_ENCODE_PARTIAL ) ) return info_sz;

  /* The fields of the update that follow the account state: which slot
     it was written in and which bank.  is_startup is always false, so
     it is left out. */
  ulong o = head + info_sz;
  if( acct->slot ) {
    buf[ o++ ] = (uchar)( (DRAGON_ACCT_SLOT_FIELD<<3)|0U );
    o += dragon_varint( buf+o, acct->slot );
  }
  if( acct->bank_id ) {
    buf[ o++ ] = (uchar)( (DRAGON_ACCT_BANK_ID_FIELD<<3)|0U );
    o += dragon_varint( buf+o, acct->bank_id );
  }

  ulong info_start = dragon_wrap( buf, head, DRAGON_ACCT_INFO_FIELD, info_sz );
  ulong update_sz  = o - info_start;
  ulong start      = dragon_wrap( buf, info_start, DRAGON_UPDATE_ACCOUNT_FIELD, update_sz );

  o += dragon_created_at( rpc, buf+o );
  *end_out = o;
  return start;
}

/* dragon_oversize reports one update that cannot be delivered to a
   subscriber because it is larger than a message may be, which is the
   largest message the tile assembles and the transport delivers: a
   block carrying the accounts of a busy slot reaches that bound.  An
   update larger than the client's send queue is not oversized, it
   goes out through the transport's large send path.  Counted always,
   and logged once per subscription, so that an operator sees which
   knob is too small without a line per update. */

static void
dragon_oversize( fd_dragon_session_t * s,
                 char const *          what,
                 ulong                 sz ) {
  if( FD_LIKELY( !s->warned_oversize ) ) {
    s->warned_oversize = 1;
    FD_LOG_WARNING(( "dragon is dropping %s of %lu bytes for a subscriber: one message goes out "
                     "whole, and this one is above [tiles.dragon.max_message_bytes]",
                     what, sz ));
  }
}

/* dragon_msg_send_group sends the message assembled in [start,end) of
   buf to the clients of group, with the filter names of its lowest
   client, name_mask, appended once: protobuf lets the fields of a
   message go out in any order, so the names go behind a body that
   every client of the group shares byte for byte. */

static void
dragon_msg_send_group( fd_dragon_rpc_t * rpc,
                       ulong             group,
                       ulong             name_mask,
                       uchar *           buf,
                       ulong             start,
                       ulong             end,
                       uint              field ) {
  fd_dragon_session_t * s          = rpc->session + fd_ulong_find_lsb( group );
  int                   is_account = field==DRAGON_UPDATE_ACCOUNT_FIELD;

  if( FD_UNLIKELY( end+dragon_names_sz( s, name_mask )>rpc->msg_max ) ) {
    for( ulong i=0UL; i<rpc->stream_max; i++ ) {
      if( !( ( group>>i ) & 1UL ) ) continue;
      if( is_account ) rpc->metrics.acct_oversize_cnt++;
      else             rpc->metrics.block_oversize_cnt++;
      dragon_oversize( rpc->session + i, is_account ? "an account update" : "a block", end-start );
    }
    return;
  }
  ulong o = end + dragon_names_write( s, name_mask, buf+end );
  dragon_send_group( rpc, group, buf+start, o-start, field, 0UL );
}

/* dragon_acct_fanout sends one account write to the clients of mask,
   with the filter names of client i in names[ i ].  The payload is
   encoded once per distinct data slice configuration among them, which
   is what makes the common case of clients that slice alike one
   encoding (§2.3 of the design). */

static void
dragon_acct_fanout( fd_dragon_rpc_t *           rpc,
                    fd_geyser_account_t const * acct,
                    dragon_acct_data_t const *  view,
                    ulong                       mask,
                    ulong const *               names ) {
  while( mask ) {
    ulong i = (ulong)fd_ulong_find_lsb( mask );
    fd_dragon_session_t * s = rpc->session + i;

    /* The clients that slice the account the same way, which is the
       group this one encoding serves. */
    ulong group = 0UL;
    for( ulong j=i; j<rpc->stream_max; j++ ) {
      if( !( ( mask>>j ) & 1UL ) ) continue;
      if( j!=i && !dragon_slice_eq( s->filter, rpc->session[ j ].filter ) ) continue;
      group |= 1UL<<j;
    }
    mask &= ~group;

    ulong end;
    ulong start = dragon_acct_assemble( rpc, acct, view, s->filter->slice, s->filter->slice_cnt, &end );
    if( FD_UNLIKELY( start==DRAGON_ENCODE_PARTIAL ) ) {
      rpc->metrics.acct_partial_cnt += (ulong)fd_ulong_popcnt( group );
      continue;
    }
    if( FD_UNLIKELY( start==DRAGON_ENCODE_TOOBIG ) ) {
      /* The account does not fit what this group asked for, which a
         client whose slices are smaller may still be sent. */
      for( ulong j=i; j<rpc->stream_max; j++ ) {
        if( !( ( group>>j ) & 1UL ) ) continue;
        rpc->metrics.acct_oversize_cnt++;
        dragon_oversize( rpc->session + j, "an account update", acct->data_sz );
      }
      continue;
    }

    /* Within the slice group, the clients whose names are the same
       bytes share one staged message. */
    while( group ) {
      ulong same = dragon_names_group( rpc, &group, names );
      dragon_msg_send_group( rpc, same, names[ fd_ulong_find_lsb( same ) ], rpc->msg_big, start, end, DRAGON_UPDATE_ACCOUNT_FIELD );
    }
  }
}

/* dragon_on_account is the processed firehose of account writes: every
   write of every bank, as it happened.  The clients at processed have
   their account filters evaluated here and are served now.  The ones
   at a buffered level are served when their bank reaches their level,
   from an entry buffered here: with the filters at ingest, one that
   some subscriber matched, with the masks of who did and the union of
   the data slices they asked for; with the filters at send, every
   write, whole.

   A write whose data the producer did not carry cannot be served: what
   the account holds is only readable at the bank's fork.  Such a write
   is counted and skipped. */

static void
dragon_on_account( void *                      ctx,
                   fd_geyser_account_t const * acct,
                   ulong                       slot,
                   ulong                       bank_id ) {
  fd_dragon_rpc_t * rpc = ctx;

  rpc->bank_seq_hi = fd_ulong_max( rpc->bank_seq_hi, bank_id );
  if( FD_UNLIKELY( bank_id<rpc->serve_from_bank_seq ) ) return;

  int   buffer_all = rpc->buf && rpc->filter_at==FD_DRAGON_FILTER_AT_SEND;
  ulong block_mask = ( rpc->buf && !buffer_all ) ? dragon_blocks_clients( rpc, bank_id ) : 0UL;
  if( FD_LIKELY( !rpc->acct_sub_cnt && !block_mask && !buffer_all ) ) return;

  ulong proc = 0UL;
  ulong def  = 0UL;

  for( ulong i=0UL; i<rpc->stream_max; i++ ) {
    fd_dragon_session_t const * s = rpc->session + i;
    rpc->acct_names[ i ] = 0UL;
    if( !dragon_session_active( s ) ) continue;
    if( !s->filter->type_cnt[ FD_DRAGON_FILTER_ACCOUNTS ] ) continue;
    if( s->deferred && ( buffer_all || bank_id<s->eligible_from_bank_seq ) ) continue;

    for( ulong j=0UL; j<s->filter->name_cnt; j++ ) {
      fd_dragon_filter_name_t const * name = s->filter->name + j;
      if( name->type!=FD_DRAGON_FILTER_ACCOUNTS ) continue;
      if( !fd_dragon_acct_match( s->filter, name, acct->pubkey, acct->owner, acct->lamports,
                                 acct->data, acct->data_sz, !!acct->txn_signature ) ) continue;
      rpc->acct_names[ i ] |= 1UL<<j;
    }

    if( rpc->acct_names[ i ] ) *( s->deferred ? &def : &proc ) |= 1UL<<i;
  }

  if( FD_UNLIKELY( proc ) ) {
    if( FD_UNLIKELY( acct->data_missing ) ) rpc->metrics.acct_skipped_cnt++;
    else                                    dragon_acct_fanout( rpc, acct, NULL, proc, rpc->acct_names );
  }

  if( FD_LIKELY( !def && !block_mask && !buffer_all ) ) return;
  if( FD_UNLIKELY( acct->data_missing ) ) {
    rpc->metrics.acct_skipped_cnt++;
    return;
  }

  fd_dragon_buf_bank_t * bank = dragon_buf_bank_open( rpc, bank_id, slot );
  if( FD_UNLIKELY( !bank || bank->incomplete ) ) return;
  bank->block_mask |= block_mask;

  /* A block carries the whole account, and so does a subscriber whose
     filters run at send. */
  ulong seg_cnt  = dragon_slice_union( rpc, acct, def, ( block_mask!=0UL ) | buffer_all, rpc->seg );
  ulong byte_cnt = 0UL;
  for( ulong i=0UL; i<seg_cnt; i++ ) byte_cnt += rpc->seg[ i ].len;

  ulong name_cnt = (ulong)fd_ulong_popcnt( def | block_mask );
  fd_dragon_buf_hdr_t * hdr = fd_dragon_buf_push( rpc->buf, bank, FD_DRAGON_BUF_ACCT,
                                                  fd_dragon_buf_acct_sz( name_cnt, seg_cnt, byte_cnt ) );
  if( FD_UNLIKELY( !hdr ) ) {
    dragon_degrade( rpc, bank, bank_id );
    return;
  }
  dragon_buf_names( hdr, def, rpc->acct_names, 0UL, NULL, block_mask, NULL );

  fd_dragon_buf_acct_t * ent = fd_dragon_buf_hdr_body( hdr );
  ent->write_version = acct->write_version;
  ent->lamports      = acct->lamports;
  ent->data_sz       = acct->data_sz;
  ent->seg_cnt       = seg_cnt;
  ent->executable    = (uint)!!acct->executable;
  ent->has_signature = (uint)!!acct->txn_signature;
  fd_memcpy( ent->pubkey, acct->pubkey, 32UL );
  fd_memcpy( ent->owner,  acct->owner,  32UL );
  if( acct->txn_signature ) fd_memcpy( ent->signature, acct->txn_signature, 64UL );
  else                      fd_memset( ent->signature, 0, 64UL );

  fd_dragon_buf_seg_t * seg   = fd_dragon_buf_acct_seg  ( ent );
  uchar *               bytes = fd_dragon_buf_acct_bytes( ent );
  for( ulong i=0UL; i<seg_cnt; i++ ) {
    seg[ i ] = rpc->seg[ i ];
    fd_memcpy( bytes, acct->data+seg[ i ].off, seg[ i ].len );
    bytes += seg[ i ].len;
  }
  rpc->metrics.acct_entry_cnt++;
}

/* Blocks *************************************************************/

/* dragon_block_open_t is one block being assembled: which
   subscription and blocks filter it is for, and how far its buffer has
   got.  A block's buffer holds the message body from
   DRAGON_WRAP_RESERVE on, so that the tag and length of the field the
   body ends up in can be written in front of it.

   broken is a block that outgrew the buffer, which is dropped: it
   could not have been sent either. */

struct dragon_block_open {
  fd_dragon_session_t * s;
  ulong                 name_idx;
  ulong                 client_idx;
  uchar *               buf;
  ulong                 off;
  int                   broken;
};

typedef struct dragon_block_open dragon_block_open_t;

/* dragon_block_room returns 1 if a block has room for need more bytes,
   and marks it broken if it does not. */

static int
dragon_block_room( fd_dragon_rpc_t *     rpc,
                   dragon_block_open_t * open,
                   ulong                 need ) {
  if( FD_UNLIKELY( open->broken ) ) return 0;
  if( FD_UNLIKELY( open->off+need+64UL>rpc->msg_max ) ) {
    open->broken = 1;
    return 0;
  }
  return 1;
}

/* dragon_block_begin writes the summary of a block: everything but
   its transactions and accounts, which the walks over the bank's
   entries append behind it.  acct_cnt is how many accounts the block
   updated, which is the accounts it wrote deduplicated, whether or
   not the block carries them (plugin/filter/filter.rs:2157-2219
   builds the same message). */

static void
dragon_block_begin( fd_dragon_rpc_t *            rpc,
                    fd_dragon_buf_bank_t const * bank,
                    dragon_block_open_t *        open,
                    ulong                        acct_cnt ) {
  fd_geyser_block_meta_t const * meta = &bank->meta;

  uchar * buf = open->buf;
  open->off    = DRAGON_WRAP_RESERVE;
  open->broken = 0;

  char blockhash[ FD_BASE58_ENCODED_32_SZ ];
  char parent   [ FD_BASE58_ENCODED_32_SZ ];
  fd_base58_encode_32( meta->block_hash.uc, NULL, blockhash );

  dragon_meta_t const * parent_meta = meta->has_parent ? dragon_meta_query( rpc, meta->parent_slot ) : NULL;
  if( FD_LIKELY( parent_meta ) ) fd_base58_encode_32( parent_meta->block_hash.uc, NULL, parent );
  else                           parent[ 0 ] = '\0';

  ulong blockhash_len = strlen( blockhash );
  ulong parent_len    = strlen( parent    );

  if( FD_UNLIKELY( !dragon_block_room( rpc, open, 256UL+blockhash_len+parent_len ) ) ) return;

  ulong o = open->off;
  if( meta->slot ) { buf[ o++ ] = (uchar)( (DRAGON_BLK_SLOT_FIELD<<3)|0U ); o += dragon_varint( buf+o, meta->slot ); }
  if( blockhash_len ) {
    o += dragon_field_hdr( buf+o, DRAGON_BLK_BLOCKHASH_FIELD, blockhash_len );
    fd_memcpy( buf+o, blockhash, blockhash_len ); o += blockhash_len;
  }
  /* An empty Rewards message, which is what a yellowstone server sends
     for a block whose rewards it has none of. */
  o += dragon_field_hdr( buf+o, DRAGON_BLK_REWARDS_FIELD, 0UL );
  if( meta->block_height!=ULONG_MAX ) {
    ulong bh_sz = meta->block_height ? 1UL+dragon_varint_sz( meta->block_height ) : 0UL;
    o += dragon_field_hdr( buf+o, DRAGON_BLK_BLOCK_HEIGHT_FIELD, bh_sz );
    if( bh_sz ) { buf[ o++ ] = (uchar)( (1U<<3)|0U ); o += dragon_varint( buf+o, meta->block_height ); }
  }
  if( meta->has_parent && meta->parent_slot ) {
    buf[ o++ ] = (uchar)( (DRAGON_BLK_PARENT_SLOT_FIELD<<3)|0U ); o += dragon_varint( buf+o, meta->parent_slot );
  }
  if( parent_len ) {
    o += dragon_field_hdr( buf+o, DRAGON_BLK_PARENT_BLOCKHASH_FIELD, parent_len );
    fd_memcpy( buf+o, parent, parent_len ); o += parent_len;
  }
  if( meta->executed_txn_cnt && meta->executed_txn_cnt!=ULONG_MAX ) {
    buf[ o++ ] = (uchar)( (DRAGON_BLK_EXECUTED_TXN_CNT_FIELD<<3)|0U );
    o += dragon_varint( buf+o, meta->executed_txn_cnt );
  }
  if( acct_cnt ) {
    buf[ o++ ] = (uchar)( (DRAGON_BLK_UPDATED_ACCT_CNT_FIELD<<3)|0U );
    o += dragon_varint( buf+o, acct_cnt );
  }
  open->off = o;
}

/* dragon_block_txn appends one transaction to a block, as the info
   bytes the buffer holds, so a block costs no re-encoding of them. */

static void
dragon_block_txn( fd_dragon_rpc_t *     rpc,
                  dragon_block_open_t * open,
                  uchar const *         info,
                  ulong                 info_sz ) {
  if( FD_UNLIKELY( !dragon_block_room( rpc, open, info_sz+16UL ) ) ) return;
  uchar * buf = open->buf;
  ulong   o   = open->off;
  o += dragon_field_hdr( buf+o, DRAGON_BLK_TRANSACTIONS_FIELD, info_sz );
  fd_memcpy( buf+o, info, info_sz );
  open->off = o + info_sz;
}

/* dragon_block_wants returns 1 if a block carries the account, which
   is what its filter's account set says. */

static int
dragon_block_wants( dragon_block_open_t const * open,
                    uchar const *               pubkey ) {
  fd_dragon_filter_name_t const * name = open->s->filter->name + open->name_idx;
  if( FD_UNLIKELY( open->broken || !name->include_accts ) ) return 0;
  return fd_dragon_blocks_acct_match( open->s->filter, name, pubkey );
}

/* dragon_block_account appends one account to a block, sliced as its
   subscription asked. */

static void
dragon_block_account( fd_dragon_rpc_t *           rpc,
                      dragon_block_open_t *       open,
                      fd_geyser_account_t const * acct,
                      dragon_acct_data_t const *  view ) {
  if( FD_UNLIKELY( !dragon_block_room( rpc, open, 16UL ) ) ) return;

  /* The account state goes in as one element of the repeated accounts
     field, so it is encoded where it lands, behind room for its tag
     and length. */
  uchar * buf     = open->buf;
  ulong   o       = open->off;
  ulong   info_sz = dragon_acct_info_encode( buf+o+16UL, rpc->msg_max-o-80UL, acct, view,
                                             open->s->filter->slice, open->s->filter->slice_cnt );
  if( FD_UNLIKELY( info_sz>=DRAGON_ENCODE_PARTIAL ) ) {
    open->broken = 1;
    return;
  }
  ulong hdr_sz = dragon_field_hdr( buf+o, DRAGON_BLK_ACCOUNTS_FIELD, info_sz );
  memmove( buf+o+hdr_sz, buf+o+16UL, info_sz );
  open->off = o + hdr_sz + info_sz;
}

/* dragon_block_finish closes a block and sends it.  No component
   reconstructs entries, so the count is zero and the list is
   empty. */

static void
dragon_block_finish( fd_dragon_rpc_t *            rpc,
                     fd_dragon_buf_bank_t const * bank,
                     dragon_block_open_t *        open ) {
  if( FD_UNLIKELY( !dragon_block_room( rpc, open, 32UL ) ) ) {
    rpc->metrics.block_oversize_cnt++;
    dragon_oversize( open->s, "a block", open->off );
    return;
  }

  uchar * buf = open->buf;
  ulong   o   = open->off;
  if( bank->bank_seq ) {
    buf[ o++ ] = (uchar)( (DRAGON_BLK_BANK_ID_FIELD<<3)|0U );
    o += dragon_varint( buf+o, bank->bank_seq );
  }

  ulong start = dragon_wrap( buf, DRAGON_WRAP_RESERVE, DRAGON_UPDATE_BLOCK_FIELD, o-DRAGON_WRAP_RESERVE );
  o += dragon_created_at( rpc, buf+o );

  dragon_msg_send_group( rpc, 1UL<<open->client_idx, 1UL<<open->name_idx, buf, start, o, DRAGON_UPDATE_BLOCK_FIELD );
}

/* dragon_blocks_open collects the next batch of blocks a bank owes at
   one commitment, starting from the cursor and advancing it past what
   it returns.  One message goes out per blocks filter, because what a
   block carries depends on that filter's account set and include
   flags, which is what a yellowstone server does with its own one
   update per filter (plugin/filter/filter.rs:2204-2218).  With the
   filters at send every bank is buffered whole, so a block is owed to
   every blocks subscription of the level. */

static ulong
dragon_blocks_open( fd_dragon_rpc_t *            rpc,
                    fd_dragon_buf_bank_t const * bank,
                    int                          commitment,
                    ulong *                      cursor_i,
                    ulong *                      cursor_j,
                    dragon_block_open_t *        open ) {
  ulong cnt  = 0UL;
  ulong owed = rpc->filter_at==FD_DRAGON_FILTER_AT_SEND ? ~0UL : bank->block_mask;
  if( FD_LIKELY( !owed || !bank->has_meta ) ) return 0UL;

  for( ulong i=*cursor_i; i<rpc->stream_max; i++ ) {
    ulong j0 = i==*cursor_i ? *cursor_j : 0UL;
    *cursor_j = 0UL;

    if( !( ( owed>>i ) & 1UL ) ) continue;
    fd_dragon_session_t * s = rpc->session + i;
    if( !dragon_session_active( s ) ) continue;
    if( s->filter->commitment!=commitment ) continue;
    if( bank->bank_seq<s->eligible_from_bank_seq ) continue;

    for( ulong j=j0; j<s->filter->name_cnt; j++ ) {
      if( s->filter->name[ j ].type!=FD_DRAGON_FILTER_BLOCKS ) continue;

      open[ cnt ].s          = s;
      open[ cnt ].name_idx   = j;
      open[ cnt ].client_idx = i;
      open[ cnt ].buf        = rpc->blk_big + cnt*rpc->msg_max;
      open[ cnt ].off        = DRAGON_WRAP_RESERVE;
      open[ cnt ].broken     = 0;
      cnt++;

      if( FD_UNLIKELY( cnt>=FD_DRAGON_BLOCK_OPEN_MAX ) ) {
        *cursor_i = i;
        *cursor_j = j+1UL;
        return cnt;
      }
    }
  }

  *cursor_i = rpc->stream_max;
  *cursor_j = 0UL;
  return cnt;
}

/* Transactions *******************************************************/

/* dragon_txn_update_send sends one transaction as a
   geyser.SubscribeUpdateTransaction to the clients of mask, under the
   filter names of client i in names[ i ].  The body the layer holds is
   the transaction info, which the update carries as its first field
   followed by the slot and the bank id, so one encoding serves both a
   transaction subscription and a block. */

static void
dragon_txn_update_send( fd_dragon_rpc_t * rpc,
                        ulong             mask,
                        ulong const *     names,
                        uchar const *     info,
                        ulong             info_sz,
                        ulong             slot,
                        ulong             bank_id ) {
  uchar pre[ 16 ];
  ulong pre_sz = dragon_field_hdr( pre, FD_TXN_META_F_UPDATE_TRANSACTION, info_sz );

  uchar post[ 32 ];
  ulong post_sz = 0UL;
  if( slot ) {
    post[ post_sz++ ] = (uchar)( (FD_TXN_META_F_UPDATE_SLOT<<3)|0U );
    post_sz += dragon_varint( post+post_sz, slot );
  }
  if( bank_id ) {
    post[ post_sz++ ] = (uchar)( (FD_TXN_META_F_UPDATE_BANK_ID<<3)|0U );
    post_sz += dragon_varint( post+post_sz, bank_id );
  }

  while( mask ) {
    ulong group = dragon_names_group( rpc, &mask, names );
    for( ulong i=0UL; i<rpc->stream_max; i++ ) {
      if( ( ( group>>i ) & 1UL ) && !dragon_update_fits( rpc->session + i, pre_sz+info_sz+post_sz ) ) {
        rpc->metrics.encode_fail_cnt++;
        group &= ~( 1UL<<i );
      }
    }
    if( FD_LIKELY( group ) )
      dragon_update_raw3_group( rpc, group, names[ fd_ulong_find_lsb( group ) ], DRAGON_UPDATE_TXN_FIELD,
                                pre, pre_sz, info, info_sz, post, post_sz );
  }
}

/* dragon_on_transaction is the processed firehose: one committed
   transaction, on one bank, as it happened.  The clients at processed
   have their filters evaluated here and are served now.  The ones at a
   buffered level are served when their bank reaches their level, from
   an entry buffered here: with the filters at ingest, one that some
   subscriber matched, with the masks of who did, under the names of
   its transactions filters and of its blocks filters the transaction
   belongs to; with the filters at send, every transaction, with what
   the filters look at. */

static void
dragon_on_transaction( void *                  ctx,
                       fd_geyser_txn_t const * txn,
                       ulong                   slot,
                       ulong                   bank_id ) {
  fd_dragon_rpc_t * rpc = ctx;

  rpc->bank_seq_hi = fd_ulong_max( rpc->bank_seq_hi, bank_id );
  if( FD_UNLIKELY( bank_id<rpc->serve_from_bank_seq ) ) return;

  int   buffer_all    = rpc->buf && rpc->filter_at==FD_DRAGON_FILTER_AT_SEND;
  ulong block_clients = ( rpc->buf && !buffer_all ) ? dragon_blocks_clients( rpc, bank_id ) : 0UL;
  if( FD_LIKELY( !rpc->txn_sub_cnt && !block_clients && !buffer_all ) ) return;

  /* The core builds the meta object once, however many consumers ask
     for it. */
  fd_txn_meta_t const * meta = fd_geyser_txn_meta( rpc->core, txn );
  if( FD_UNLIKELY( !meta ) ) {
    rpc->metrics.meta_fail_cnt++;
    return;
  }

  int failed = meta->err.kind!=FD_TXN_META_ERR_NONE;

  ulong proc_txn    = 0UL;
  ulong proc_status = 0UL;
  ulong def_txn     = 0UL;
  ulong def_status  = 0UL;
  ulong block_mask  = 0UL;

  for( ulong i=0UL; i<rpc->stream_max; i++ ) {
    fd_dragon_session_t const * s = rpc->session + i;
    rpc->txn_names   [ i ] = 0UL;
    rpc->status_names[ i ] = 0UL;
    rpc->block_names [ i ] = 0UL;
    if( !dragon_session_active( s ) ) continue;

    if( ( block_clients>>i ) & 1UL ) {
      for( ulong j=0UL; j<s->filter->name_cnt; j++ ) {
        fd_dragon_filter_name_t const * name = s->filter->name + j;
        if( name->type!=FD_DRAGON_FILTER_BLOCKS || !name->include_txns ) continue;
        if( !fd_dragon_blocks_txn_match( s->filter, name, meta->keys, meta->key_cnt ) ) continue;
        rpc->block_names[ i ] |= 1UL<<j;
      }
      if( rpc->block_names[ i ] ) block_mask |= 1UL<<i;
    }

    if( !( s->filter->type_cnt[ FD_DRAGON_FILTER_TRANSACTIONS        ] ||
           s->filter->type_cnt[ FD_DRAGON_FILTER_TRANSACTIONS_STATUS ] ) ) continue;

    /* With the filters at ingest, a buffered subscription is eligible
       from the first bank created after its filters were installed, so
       a bank already in flight is never delivered to it under a mix of
       filter sets.  With them at send, it is matched when the bank is
       served. */
    if( s->deferred && ( buffer_all || bank_id<s->eligible_from_bank_seq ) ) continue;

    for( ulong j=0UL; j<s->filter->name_cnt; j++ ) {
      fd_dragon_filter_name_t const * name = s->filter->name + j;
      if( name->type!=FD_DRAGON_FILTER_TRANSACTIONS &&
          name->type!=FD_DRAGON_FILTER_TRANSACTIONS_STATUS ) continue;
      if( !fd_dragon_txn_match( s->filter, name, meta->signature, meta->is_vote, failed,
                                meta->keys, meta->key_cnt ) ) continue;
      if( name->type==FD_DRAGON_FILTER_TRANSACTIONS ) rpc->txn_names   [ i ] |= 1UL<<j;
      else                                            rpc->status_names[ i ] |= 1UL<<j;
    }

    if( rpc->txn_names   [ i ] ) *( s->deferred ? &def_txn    : &proc_txn    ) |= 1UL<<i;
    if( rpc->status_names[ i ] ) *( s->deferred ? &def_status : &proc_status ) |= 1UL<<i;
  }

  int keep_info   = ( ( def_txn | block_mask )!=0UL ) | buffer_all;
  int keep_status = ( def_status!=0UL )               | buffer_all;
  if( FD_LIKELY( !( proc_txn | proc_status ) && !keep_info && !keep_status ) ) return;

  ulong info_sz   = 0UL;
  ulong status_sz = 0UL;

  if( proc_txn || keep_info ) {
    info_sz = fd_txn_meta_encode_txn_info( meta, rpc->body_buf, sizeof(rpc->body_buf) );
    if( FD_UNLIKELY( info_sz==ULONG_MAX ) ) {
      rpc->metrics.encode_fail_cnt++;
      if( keep_info ) dragon_degrade( rpc, dragon_buf_bank_open( rpc, bank_id, slot ), bank_id );
      return;
    }
  }
  if( proc_status || keep_status ) {
    status_sz = fd_txn_meta_encode_txn_status( meta, rpc->status_buf, sizeof(rpc->status_buf) );
    if( FD_UNLIKELY( status_sz==ULONG_MAX ) ) {
      rpc->metrics.encode_fail_cnt++;
      if( keep_status ) dragon_degrade( rpc, dragon_buf_bank_open( rpc, bank_id, slot ), bank_id );
      return;
    }
  }

  if( proc_txn    ) dragon_txn_update_send( rpc, proc_txn, rpc->txn_names, rpc->body_buf, info_sz, meta->slot, meta->bank_id );
  if( proc_status ) dragon_update_body_send( rpc, proc_status, rpc->status_names, DRAGON_UPDATE_TXN_STATUS_FIELD,
                                             rpc->status_buf, status_sz );

  if( FD_LIKELY( !keep_info && !keep_status ) ) return;

  fd_dragon_buf_bank_t * bank = dragon_buf_bank_open( rpc, bank_id, slot );
  if( FD_UNLIKELY( !bank || bank->incomplete ) ) return;

  ulong keep_info_sz   = keep_info   ? info_sz   : 0UL;
  ulong keep_status_sz = keep_status ? status_sz : 0UL;
  ulong key_cnt        = buffer_all  ? meta->key_cnt : 0UL;
  ulong name_cnt       = (ulong)fd_ulong_popcnt( def_txn | def_status | block_mask );

  fd_dragon_buf_hdr_t * hdr = fd_dragon_buf_push( rpc->buf, bank, FD_DRAGON_BUF_TXN,
                                                  fd_dragon_buf_txn_sz( name_cnt, keep_info_sz, keep_status_sz, key_cnt ) );
  if( FD_UNLIKELY( !hdr ) ) {
    dragon_degrade( rpc, bank, bank_id );
    return;
  }
  dragon_buf_names( hdr, def_txn, rpc->txn_names, def_status, rpc->status_names, block_mask, rpc->block_names );

  fd_dragon_buf_txn_t * ent = fd_dragon_buf_hdr_body( hdr );
  ent->info_sz   = keep_info_sz;
  ent->status_sz = keep_status_sz;
  ent->key_cnt   = key_cnt;
  ent->is_vote   = (uint)!!meta->is_vote;
  ent->failed    = (uint)failed;
  fd_memcpy( ent->signature, meta->signature, 64UL );
  if( keep_info_sz   ) fd_memcpy( fd_dragon_buf_txn_info  ( ent ), rpc->body_buf,   keep_info_sz   );
  if( keep_status_sz ) fd_memcpy( fd_dragon_buf_txn_status( ent ), rpc->status_buf, keep_status_sz );
  if( key_cnt        ) fd_memcpy( fd_dragon_buf_txn_keys  ( ent ), meta->keys,      key_cnt*32UL   );
}

/* Block metas ********************************************************/

/* dragon_block_meta_encode writes the body of a
   geyser.SubscribeUpdateBlockMeta.  The rewards are an empty list, the
   block time is absent, and the entry count is zero, because no
   component reconstructs entries (§5.3 of the design). */

static ulong
dragon_block_meta_encode( fd_dragon_rpc_t *              rpc,
                          fd_geyser_block_meta_t const * meta,
                          ulong                          bank_id ) {
  uchar * out = rpc->body_buf;
  ulong   o   = 0UL;

  char blockhash[ FD_BASE58_ENCODED_32_SZ ];
  char parent   [ FD_BASE58_ENCODED_32_SZ ];
  fd_base58_encode_32( meta->block_hash.uc, NULL, blockhash );

  dragon_meta_t const * parent_meta = meta->has_parent ? dragon_meta_query( rpc, meta->parent_slot ) : NULL;
  if( FD_LIKELY( parent_meta ) ) fd_base58_encode_32( parent_meta->block_hash.uc, NULL, parent );
  else                           parent[ 0 ] = '\0';

  ulong blockhash_len = strlen( blockhash );
  ulong parent_len    = strlen( parent    );

  if( meta->slot ) { out[ o++ ] = (uchar)( (DRAGON_BM_SLOT_FIELD<<3)|0U ); o += dragon_varint( out+o, meta->slot ); }
  if( blockhash_len ) {
    out[ o++ ] = (uchar)( (DRAGON_BM_BLOCKHASH_FIELD<<3)|2U );
    o += dragon_varint( out+o, blockhash_len );
    fd_memcpy( out+o, blockhash, blockhash_len ); o += blockhash_len;
  }
  /* An empty Rewards message, which is what a yellowstone server sends
     for a block whose rewards it has none of. */
  out[ o++ ] = (uchar)( (DRAGON_BM_REWARDS_FIELD<<3)|2U );
  out[ o++ ] = 0;
  if( meta->block_height!=ULONG_MAX ) {
    ulong bh_sz = meta->block_height ? 1UL+dragon_varint_sz( meta->block_height ) : 0UL;
    out[ o++ ] = (uchar)( (DRAGON_BM_BLOCK_HEIGHT_FIELD<<3)|2U );
    o += dragon_varint( out+o, bh_sz );
    if( bh_sz ) { out[ o++ ] = (uchar)( (1U<<3)|0U ); o += dragon_varint( out+o, meta->block_height ); }
  }
  if( meta->has_parent && meta->parent_slot ) {
    out[ o++ ] = (uchar)( (DRAGON_BM_PARENT_SLOT_FIELD<<3)|0U ); o += dragon_varint( out+o, meta->parent_slot );
  }
  if( parent_len ) {
    out[ o++ ] = (uchar)( (DRAGON_BM_PARENT_BLOCKHASH_FIELD<<3)|2U );
    o += dragon_varint( out+o, parent_len );
    fd_memcpy( out+o, parent, parent_len ); o += parent_len;
  }
  if( meta->executed_txn_cnt && meta->executed_txn_cnt!=ULONG_MAX ) {
    out[ o++ ] = (uchar)( (DRAGON_BM_EXECUTED_TXN_CNT_FIELD<<3)|0U ); o += dragon_varint( out+o, meta->executed_txn_cnt );
  }
  if( bank_id ) { out[ o++ ] = (uchar)( (DRAGON_BM_BANK_ID_FIELD<<3)|0U ); o += dragon_varint( out+o, bank_id ); }

  return o;
}

/* dragon_block_meta_fanout sends one block summary to every
   subscription at the given commitment that asked for block metas.  A
   deferred subscription only sees the banks it is eligible for. */

static void
dragon_block_meta_fanout( fd_dragon_rpc_t *              rpc,
                          fd_geyser_block_meta_t const * meta,
                          ulong                          bank_id,
                          int                            commitment ) {
  if( FD_LIKELY( !rpc->block_meta_sub_cnt ) ) return;

  ulong mask = 0UL;
  for( ulong i=0UL; i<rpc->stream_max; i++ ) {
    fd_dragon_session_t * s = rpc->session + i;
    rpc->meta_names[ i ] = 0UL;
    if( !dragon_session_active( s ) ) continue;
    if( s->filter->commitment!=commitment ) continue;
    if( !s->filter->type_cnt[ FD_DRAGON_FILTER_BLOCKS_META ] ) continue;
    if( s->deferred && bank_id<s->eligible_from_bank_seq ) continue;

    for( ulong j=0UL; j<s->filter->name_cnt; j++ ) {
      if( s->filter->name[ j ].type==FD_DRAGON_FILTER_BLOCKS_META ) rpc->meta_names[ i ] |= 1UL<<j;
    }
    if( rpc->meta_names[ i ] ) mask |= 1UL<<i;
  }
  if( FD_LIKELY( !mask ) ) return;

  ulong body_sz = dragon_block_meta_encode( rpc, meta, bank_id );
  dragon_update_body_send( rpc, mask, rpc->meta_names, DRAGON_UPDATE_BLOCK_META_FIELD, rpc->body_buf, body_sz );
}

/* Buffered delivery **************************************************/

/* dragon_txn_serve serves one buffered transaction: to the clients of
   the level whose transactions or status filters it is for, when
   content is set, and to every open block whose blocks filter it
   belongs to.  Which clients those are was recorded on the entry when
   the filters ran at ingest, and is what the filters say now when they
   run at send. */

static void
dragon_txn_serve( fd_dragon_rpc_t *            rpc,
                  fd_dragon_buf_bank_t const * bank,
                  fd_dragon_buf_hdr_t *        hdr,
                  int                          commitment,
                  int                          content,
                  dragon_block_open_t *        open,
                  ulong                        open_cnt ) {
  fd_dragon_buf_txn_t * txn    = fd_dragon_buf_hdr_body( hdr );
  uchar const *         info   = fd_dragon_buf_txn_info  ( txn );
  uchar const *         status = fd_dragon_buf_txn_status( txn );
  uchar const (* keys)[ 32UL ] = (uchar const (*)[ 32UL ])fd_dragon_buf_txn_keys( txn );
  int   at_send     = rpc->filter_at==FD_DRAGON_FILTER_AT_SEND;
  ulong txn_mask    = 0UL;
  ulong status_mask = 0UL;

  for( ulong i=0UL; i<rpc->stream_max; i++ ) {
    fd_dragon_session_t * s = rpc->session + i;
    rpc->txn_names   [ i ] = 0UL;
    rpc->status_names[ i ] = 0UL;
    if( !dragon_session_active( s ) ) continue;
    if( s->filter->commitment!=commitment ) continue;
    if( bank->bank_seq<s->eligible_from_bank_seq ) continue;

    ulong txn_names    = 0UL;
    ulong status_names = 0UL;
    ulong block_names  = 0UL;
    if( at_send ) {
      for( ulong j=0UL; j<s->filter->name_cnt; j++ ) {
        fd_dragon_filter_name_t const * name = s->filter->name + j;
        if( name->type==FD_DRAGON_FILTER_BLOCKS ) {
          if( open_cnt && name->include_txns &&
              fd_dragon_blocks_txn_match( s->filter, name, keys, txn->key_cnt ) ) block_names |= 1UL<<j;
          continue;
        }
        if( name->type!=FD_DRAGON_FILTER_TRANSACTIONS &&
            name->type!=FD_DRAGON_FILTER_TRANSACTIONS_STATUS ) continue;
        if( !content ) continue;
        if( !fd_dragon_txn_match( s->filter, name, txn->signature, (int)txn->is_vote, (int)txn->failed,
                                  keys, txn->key_cnt ) ) continue;
        if( name->type==FD_DRAGON_FILTER_TRANSACTIONS ) txn_names    |= 1UL<<j;
        else                                            status_names |= 1UL<<j;
      }
    } else {
      if( ( hdr->mask       >>i ) & 1UL ) txn_names    = fd_dragon_buf_names( hdr, i, FD_DRAGON_BUF_NAME_TXN    );
      if( ( hdr->status_mask>>i ) & 1UL ) status_names = fd_dragon_buf_names( hdr, i, FD_DRAGON_BUF_NAME_STATUS );
      if( ( hdr->block_mask >>i ) & 1UL ) block_names  = fd_dragon_buf_names( hdr, i, FD_DRAGON_BUF_NAME_BLOCK  );
    }

    if( content ) {
      rpc->txn_names   [ i ] = txn_names;
      rpc->status_names[ i ] = status_names;
      if( txn_names    && txn->info_sz   ) txn_mask    |= 1UL<<i;
      if( status_names && txn->status_sz ) status_mask |= 1UL<<i;
    }

    if( !block_names || !txn->info_sz ) continue;
    for( ulong k=0UL; k<open_cnt; k++ ) {
      if( open[ k ].s==s && ( ( block_names>>open[ k ].name_idx ) & 1UL ) ) dragon_block_txn( rpc, open+k, info, txn->info_sz );
    }
  }

  if( txn_mask    ) dragon_txn_update_send( rpc, txn_mask, rpc->txn_names, info, txn->info_sz, bank->slot, bank->bank_seq );
  if( status_mask ) dragon_update_body_send( rpc, status_mask, rpc->status_names, DRAGON_UPDATE_TXN_STATUS_FIELD, status, txn->status_sz );
}

/* dragon_acct_serve serves one buffered account write, which is the
   state the block left the account in: to the clients of the level
   whose accounts filters it is for, when content is set, and to every
   open block whose blocks filter carries the account. */

static void
dragon_acct_serve( fd_dragon_rpc_t *            rpc,
                   fd_dragon_buf_bank_t const * bank,
                   fd_dragon_buf_hdr_t *        hdr,
                   int                          commitment,
                   int                          content,
                   dragon_block_open_t *        open,
                   ulong                        open_cnt ) {
  fd_dragon_buf_acct_t * ent = fd_dragon_buf_hdr_body( hdr );
  dragon_acct_data_t     view = {
    .seg     = fd_dragon_buf_acct_seg  ( ent ),
    .seg_cnt = ent->seg_cnt,
    .bytes   = fd_dragon_buf_acct_bytes( ent )
  };
  /* The data is addressable whole only when the entry holds all of
     it, which is what a filter that reads it needs. */
  int whole = !ent->data_sz || ( ent->seg_cnt==1UL && !view.seg[ 0 ].off && view.seg[ 0 ].len==ent->data_sz );
  fd_geyser_account_t acct = {
    .slot          = bank->slot,
    .bank_id       = bank->bank_seq,
    .pubkey        = ent->pubkey,
    .owner         = ent->owner,
    .lamports      = ent->lamports,
    .executable    = (int)ent->executable,
    .data          = ( whole && ent->data_sz ) ? view.bytes : NULL,
    .data_sz       = ent->data_sz,
    .write_version = ent->write_version,
    .txn_signature = ent->has_signature ? ent->signature : NULL
  };
  int at_send = rpc->filter_at==FD_DRAGON_FILTER_AT_SEND;

  if( content ) {
    ulong mask = 0UL;
    for( ulong i=0UL; i<rpc->stream_max; i++ ) {
      fd_dragon_session_t const * s = rpc->session + i;
      if( !dragon_session_active( s ) ) continue;
      if( s->filter->commitment!=commitment ) continue;
      if( bank->bank_seq<s->eligible_from_bank_seq ) continue;

      ulong names = 0UL;
      if( at_send ) {
        if( !s->filter->type_cnt[ FD_DRAGON_FILTER_ACCOUNTS ] || !whole ) continue;
        for( ulong j=0UL; j<s->filter->name_cnt; j++ ) {
          fd_dragon_filter_name_t const * name = s->filter->name + j;
          if( name->type!=FD_DRAGON_FILTER_ACCOUNTS ) continue;
          if( !fd_dragon_acct_match( s->filter, name, acct.pubkey, acct.owner, acct.lamports,
                                     acct.data, acct.data_sz, !!acct.txn_signature ) ) continue;
          names |= 1UL<<j;
        }
      } else if( ( hdr->mask>>i ) & 1UL ) {
        names = fd_dragon_buf_names( hdr, i, FD_DRAGON_BUF_NAME_ACCT );
      }
      if( !names ) continue;
      rpc->acct_names[ i ] = names;
      mask |= 1UL<<i;
    }
    if( FD_UNLIKELY( mask ) ) dragon_acct_fanout( rpc, &acct, &view, mask, rpc->acct_names );
  }

  for( ulong k=0UL; k<open_cnt; k++ ) {
    if( dragon_block_wants( open+k, acct.pubkey ) ) dragon_block_account( rpc, open+k, &acct, &view );
  }
}

/* dragon_deliver_content serves what is buffered for a bank at one
   commitment.  content selects whether the bank's own messages are
   served as well as its blocks: at confirmed and finalized they are,
   at processed they went out as they arrived and only the block is
   left.

   The order is the one a yellowstone client sees (grpc.rs:1233-1242):
   the transactions and accounts of the bank in the order they
   arrived, the accounts deduplicated to the state the block left them
   in, then its blocks, then its summary, then the slot status, which
   the caller sends after this returns.  A block carries its
   transactions and then its accounts, so the entries are walked once
   for the content and the blocks' transactions, and once more for the
   blocks' accounts.  A level with more blocks filters than one pass
   assembles takes another pass over the entries. */

static void
dragon_deliver_content( fd_dragon_rpc_t *      rpc,
                        fd_dragon_buf_bank_t * bank,
                        int                    commitment,
                        int                    content ) {
  ulong acct_cnt = fd_dragon_buf_dedup( rpc->buf, bank );
  ulong cursor_i = 0UL;
  ulong cursor_j = 0UL;

  for( ulong pass=0UL;; pass++ ) {
    dragon_block_open_t open[ FD_DRAGON_BLOCK_OPEN_MAX ];
    ulong               open_cnt = dragon_blocks_open( rpc, bank, commitment, &cursor_i, &cursor_j, open );
    int                 serve    = content && !pass;

    for( ulong k=0UL; k<open_cnt; k++ ) dragon_block_begin( rpc, bank, open+k, acct_cnt );

    if( ( serve || open_cnt ) && bank->first_seq!=ULONG_MAX ) {
      for( ulong seq=bank->first_seq; seq<=bank->last_seq; seq++ ) {
        fd_dragon_buf_hdr_t * hdr = fd_dragon_buf_entry( rpc->buf, bank, seq );
        if( !hdr ) continue;
        if( hdr->kind==FD_DRAGON_BUF_TXN ) dragon_txn_serve( rpc, bank, hdr, commitment, serve, open, open_cnt );
        else if( serve && !hdr->superseded ) dragon_acct_serve( rpc, bank, hdr, commitment, 1, NULL, 0UL );
      }
      for( ulong seq=bank->first_seq; open_cnt && seq<=bank->last_seq; seq++ ) {
        fd_dragon_buf_hdr_t * hdr = fd_dragon_buf_entry( rpc->buf, bank, seq );
        if( !hdr || hdr->kind!=FD_DRAGON_BUF_ACCT || hdr->superseded ) continue;
        dragon_acct_serve( rpc, bank, hdr, commitment, 0, open, open_cnt );
      }
    }

    for( ulong k=0UL; k<open_cnt; k++ ) dragon_block_finish( rpc, bank, open+k );

    if( FD_LIKELY( open_cnt<FD_DRAGON_BLOCK_OPEN_MAX ) ) break;
  }
}

/* dragon_deliver serves a bank at one of the buffered levels, once. */

static void
dragon_deliver( fd_dragon_rpc_t * rpc,
                ulong             bank_id,
                int               commitment ) {
  fd_dragon_buf_bank_t * bank = fd_dragon_buf_bank( rpc->buf, bank_id );
  if( FD_UNLIKELY( !bank || bank->incomplete ) ) return;

  if( commitment==FD_DRAGON_COMMITMENT_CONFIRMED ) {
    if( FD_UNLIKELY( bank->sent_confirmed ) ) return;
    bank->sent_confirmed = 1;
  } else {
    if( FD_UNLIKELY( bank->sent_finalized ) ) return;
    bank->sent_finalized = 1;
  }

  dragon_deliver_content( rpc, bank, commitment, 1 );

  if( FD_LIKELY( bank->has_meta ) ) dragon_block_meta_fanout( rpc, &bank->meta, bank_id, commitment );
}

/* dragon_on_bank_sealed serves the block of a bank to the
   subscriptions at processed.  Everything else at processed goes out
   as it arrives; a block is the one message that needs the whole bank,
   so it goes out when the bank seals, which is what a yellowstone
   server does for its processed block subscribers
   (grpc.rs:1404-1412). */

static void
dragon_on_bank_sealed( void * ctx,
                       ulong  bank_id ) {
  fd_dragon_rpc_t * rpc = ctx;
  if( FD_LIKELY( !rpc->buf || !rpc->blocks_sub_cnt ) ) return;

  fd_dragon_buf_bank_t * bank = fd_dragon_buf_bank( rpc->buf, bank_id );
  if( FD_LIKELY( !bank || bank->incomplete || bank->sent_processed ) ) return;
  if( FD_UNLIKELY( dragon_buf_bank_overrun( rpc, bank ) ) ) return;
  bank->sent_processed = 1;

  dragon_deliver_content( rpc, bank, FD_DRAGON_COMMITMENT_PROCESSED, 0 );
}

/* Unary calls *******************************************************/

/* dragon_commitment reads the optional commitment of a unary request.
   Returns 0 on success, or -1 after ending the call with
   unknown("failed to create CommitmentLevel from {v}"). */

static int
dragon_commitment( fd_grpc_server_stream_t * stream,
                   int                       has_commitment,
                   int                       commitment,
                   int *                     out ) {
  if( !has_commitment ) {
    *out = FD_DRAGON_COMMITMENT_PROCESSED;
    return 0;
  }
  if( FD_UNLIKELY( commitment!=FD_DRAGON_COMMITMENT_PROCESSED &&
                   commitment!=FD_DRAGON_COMMITMENT_CONFIRMED &&
                   commitment!=FD_DRAGON_COMMITMENT_FINALIZED ) ) {
    char msg[ FD_DRAGON_ERR_MAX ];
    ulong msg_len = 0UL;
    fd_cstr_printf( msg, sizeof(msg), &msg_len, "failed to create CommitmentLevel from %d", commitment );
    fd_grpc_server_finish( stream, FD_GRPC_STATUS_UNKNOWN, msg, msg_len );
    return -1;
  }
  *out = commitment;
  return 0;
}

static void
dragon_unary( fd_dragon_rpc_t *         rpc,
              fd_dragon_session_t *     s,
              int                       method,
              uchar const *             msg,
              ulong                     msg_sz ) {
  fd_grpc_server_stream_t * stream = s->stream;
  pb_istream_t is = pb_istream_from_buffer( (pb_byte_t const *)msg, (size_t)msg_sz );

  switch( method ) {

  case FD_DRAGON_METHOD_PING: {
    geyser_PingRequest req = geyser_PingRequest_init_zero;
    if( FD_UNLIKELY( !pb_decode( &is, geyser_PingRequest_fields, &req ) ) ) {
      rpc->metrics.decode_fail_cnt++;
      DRAGON_FINISH( stream, FD_GRPC_STATUS_INVALID_ARGUMENT, "failed to decode request" );
      return;
    }
    geyser_PongResponse res = geyser_PongResponse_init_zero;
    res.count = req.count;
    dragon_respond( rpc, stream, geyser_PongResponse_fields, &res );
    return;
  }

  case FD_DRAGON_METHOD_GET_VERSION: {
    geyser_GetVersionResponse res = geyser_GetVersionResponse_init_zero;
    fd_memcpy( res.version, rpc->version_json, rpc->version_json_len+1UL );
    dragon_respond( rpc, stream, geyser_GetVersionResponse_fields, &res );
    return;
  }

  case FD_DRAGON_METHOD_HEALTH_CHECK: {
    int known = dragon_health_known( rpc, msg, msg_sz );
    if( FD_UNLIKELY( known<0 ) ) {
      DRAGON_FINISH( stream, FD_GRPC_STATUS_INVALID_ARGUMENT, "failed to decode request" );
      return;
    }
    if( FD_UNLIKELY( !known ) ) {
      DRAGON_FINISH( stream, FD_GRPC_STATUS_NOT_FOUND, DRAGON_MSG_NO_SERVICE );
      return;
    }
    grpc_health_v1_HealthCheckResponse res = grpc_health_v1_HealthCheckResponse_init_zero;
    res.status = (grpc_health_v1_HealthCheckResponse_ServingStatus)dragon_health_status( rpc );
    dragon_respond( rpc, stream, grpc_health_v1_HealthCheckResponse_fields, &res );
    return;
  }

  case FD_DRAGON_METHOD_SUBSCRIBE_REPLAY_INFO: {
    /* No replay buffer, so first_available stays unset. */
    geyser_SubscribeReplayInfoResponse res = geyser_SubscribeReplayInfoResponse_init_zero;
    dragon_respond( rpc, stream, geyser_SubscribeReplayInfoResponse_fields, &res );
    return;
  }

  case FD_DRAGON_METHOD_GET_SLOT: {
    geyser_GetSlotRequest req = geyser_GetSlotRequest_init_zero;
    if( FD_UNLIKELY( !pb_decode( &is, geyser_GetSlotRequest_fields, &req ) ) ) {
      rpc->metrics.decode_fail_cnt++;
      DRAGON_FINISH( stream, FD_GRPC_STATUS_INVALID_ARGUMENT, "failed to decode request" );
      return;
    }
    int commitment;
    if( FD_UNLIKELY( dragon_commitment( stream, req.has_commitment, (int)req.commitment, &commitment ) ) ) return;
    dragon_meta_t const * meta = dragon_level_meta( rpc, commitment );
    if( FD_UNLIKELY( !meta ) ) {
      DRAGON_FINISH( stream, FD_GRPC_STATUS_INTERNAL, DRAGON_MSG_NO_BLOCK );
      return;
    }
    geyser_GetSlotResponse res = geyser_GetSlotResponse_init_zero;
    res.slot = meta->slot;
    dragon_respond( rpc, stream, geyser_GetSlotResponse_fields, &res );
    return;
  }

  case FD_DRAGON_METHOD_GET_BLOCK_HEIGHT: {
    geyser_GetBlockHeightRequest req = geyser_GetBlockHeightRequest_init_zero;
    if( FD_UNLIKELY( !pb_decode( &is, geyser_GetBlockHeightRequest_fields, &req ) ) ) {
      rpc->metrics.decode_fail_cnt++;
      DRAGON_FINISH( stream, FD_GRPC_STATUS_INVALID_ARGUMENT, "failed to decode request" );
      return;
    }
    int commitment;
    if( FD_UNLIKELY( dragon_commitment( stream, req.has_commitment, (int)req.commitment, &commitment ) ) ) return;
    dragon_meta_t const * meta = dragon_level_meta( rpc, commitment );
    if( FD_UNLIKELY( !meta ) ) {
      DRAGON_FINISH( stream, FD_GRPC_STATUS_INTERNAL, DRAGON_MSG_NO_BLOCK );
      return;
    }
    geyser_GetBlockHeightResponse res = geyser_GetBlockHeightResponse_init_zero;
    res.block_height = meta->block_height;
    dragon_respond( rpc, stream, geyser_GetBlockHeightResponse_fields, &res );
    return;
  }

  case FD_DRAGON_METHOD_GET_LATEST_BLOCKHASH: {
    geyser_GetLatestBlockhashRequest req = geyser_GetLatestBlockhashRequest_init_zero;
    if( FD_UNLIKELY( !pb_decode( &is, geyser_GetLatestBlockhashRequest_fields, &req ) ) ) {
      rpc->metrics.decode_fail_cnt++;
      DRAGON_FINISH( stream, FD_GRPC_STATUS_INVALID_ARGUMENT, "failed to decode request" );
      return;
    }
    int commitment;
    if( FD_UNLIKELY( dragon_commitment( stream, req.has_commitment, (int)req.commitment, &commitment ) ) ) return;
    dragon_meta_t const * meta = dragon_level_meta( rpc, commitment );
    if( FD_UNLIKELY( !meta ) ) {
      DRAGON_FINISH( stream, FD_GRPC_STATUS_INTERNAL, DRAGON_MSG_NO_BLOCK );
      return;
    }
    geyser_GetLatestBlockhashResponse res = geyser_GetLatestBlockhashResponse_init_zero;
    res.slot = meta->slot;
    fd_base58_encode_32( meta->block_hash.uc, NULL, res.blockhash );
    /* A blockhash stops being usable MAX_RECENT_BLOCKHASHES blocks
       after the block it came from. */
    res.last_valid_block_height = meta->block_height + DRAGON_MAX_RECENT_BLOCKHASHES;
    dragon_respond( rpc, stream, geyser_GetLatestBlockhashResponse_fields, &res );
    return;
  }

  case FD_DRAGON_METHOD_IS_BLOCKHASH_VALID: {
    geyser_IsBlockhashValidRequest req = geyser_IsBlockhashValidRequest_init_zero;
    if( FD_UNLIKELY( !pb_decode( &is, geyser_IsBlockhashValidRequest_fields, &req ) ) ) {
      rpc->metrics.decode_fail_cnt++;
      DRAGON_FINISH( stream, FD_GRPC_STATUS_INVALID_ARGUMENT, "failed to decode request" );
      return;
    }
    int commitment;
    if( FD_UNLIKELY( dragon_commitment( stream, req.has_commitment, (int)req.commitment, &commitment ) ) ) return;

    /* A server that has not yet seen a whole blockhash window cannot
       tell an expired blockhash from one it never had. */
    if( FD_UNLIKELY( rpc->hash_cnt<DRAGON_BLOCKHASH_WINDOW || !rpc->have_level[ commitment ] ) ) {
      DRAGON_FINISH( stream, FD_GRPC_STATUS_INTERNAL, DRAGON_MSG_STARTUP );
      return;
    }

    uchar hash[ 32 ];
    int   valid = 0;
    if( FD_LIKELY( fd_base58_decode_32( req.blockhash, hash ) ) ) {
      dragon_blockhash_t const * h = dragon_blockhash_query( rpc, hash );
      if( FD_LIKELY( h ) ) {
        valid = commitment==FD_DRAGON_COMMITMENT_PROCESSED ? h->processed :
                commitment==FD_DRAGON_COMMITMENT_CONFIRMED ? h->confirmed : h->finalized;
      }
    }

    geyser_IsBlockhashValidResponse res = geyser_IsBlockhashValidResponse_init_zero;
    res.slot  = rpc->level_slot[ commitment ];
    res.valid = !!valid;
    dragon_respond( rpc, stream, geyser_IsBlockhashValidResponse_fields, &res );
    return;
  }

  default:
    DRAGON_FINISH( stream, FD_GRPC_STATUS_UNIMPLEMENTED, DRAGON_MSG_DISABLED );
    return;
  }
}

/* Subscribe *********************************************************/

static void
dragon_subscribe_pong( fd_dragon_rpc_t *     rpc,
                       fd_dragon_session_t * s,
                       int                   id ) {
  geyser_SubscribeUpdate update = geyser_SubscribeUpdate_init_zero;
  update.which_update_oneof     = geyser_SubscribeUpdate_pong_tag;
  update.update_oneof.pong.id   = id;
  rpc->metrics.pong_cnt++;
  dragon_update_send( rpc, s, &update, NULL );
}

static void
dragon_subscribe_ping( fd_dragon_rpc_t *     rpc,
                       fd_dragon_session_t * s ) {
  geyser_SubscribeUpdate update = geyser_SubscribeUpdate_init_zero;
  update.which_update_oneof     = geyser_SubscribeUpdate_ping_tag;
  rpc->metrics.server_ping_cnt++;
  dragon_update_send( rpc, s, &update, NULL );
}

static void
dragon_subscribe_request( fd_dragon_rpc_t *     rpc,
                          fd_dragon_session_t * s,
                          uchar const *         msg,
                          ulong                 msg_sz ) {
  char  err[ FD_DRAGON_ERR_MAX ];
  ulong names_seen = s->names_seen;
  if( FD_UNLIKELY( fd_dragon_filter_decode( rpc->scratch, rpc->limits,
                                            dragon_cuckoo_arena( rpc, rpc->stream_max ),
                                            rpc->cuckoo_entry_max,
                                            &names_seen, msg, msg_sz, err, sizeof(err) ) ) ) {
    char  txt[ FD_GRPC_SERVER_MSG_MAX ];
    ulong txt_len = 0UL;
    fd_cstr_printf( txt, sizeof(txt), &txt_len, "failed to create filter: %s", err );
    rpc->metrics.filter_reject_cnt++;
    dragon_session_finish( rpc, s, FD_GRPC_STATUS_INVALID_ARGUMENT, txt, txt_len );
    return;
  }
  s->names_seen = names_seen;

  /* The entry filter parses, but no entry update is ever produced, so
     a subscriber that asked for one would wait forever. */
  if( FD_UNLIKELY( rpc->scratch->type_cnt[ FD_DRAGON_FILTER_ENTRY ] ) ) {
    rpc->metrics.filter_reject_cnt++;
    DRAGON_SESSION_FINISH( rpc, s, FD_GRPC_STATUS_UNIMPLEMENTED, DRAGON_MSG_NO_ENTRY );
    return;
  }

  /* A request that carries a ping is answered with a pong and leaves
     the filter set in place (grpc.rs: the filter receiver continues
     before it forwards the new filter). */
  if( rpc->scratch->has_ping ) {
    dragon_subscribe_pong( rpc, s, rpc->scratch->ping_id );
    return;
  }

  /* A commitment above processed is served from the buffer, which the
     operator can turn off. */
  int deferred = rpc->scratch->commitment!=FD_DRAGON_COMMITMENT_PROCESSED;
  if( FD_UNLIKELY( deferred && !rpc->finalized ) ) {
    char const * level = rpc->scratch->commitment==FD_DRAGON_COMMITMENT_CONFIRMED ? "confirmed" : "finalized";
    char  txt[ FD_GRPC_SERVER_MSG_MAX ];
    ulong txt_len = 0UL;
    fd_cstr_printf( txt, sizeof(txt), &txt_len, "commitment %s not supported by this server", level );
    rpc->metrics.deferred_reject_cnt++;
    dragon_session_finish( rpc, s, FD_GRPC_STATUS_INVALID_ARGUMENT, txt, txt_len );
    return;
  }

  /* A block is assembled from what the buffer kept of its bank, at
     every commitment, so a blocks subscription needs the buffer too. */
  if( FD_UNLIKELY( rpc->scratch->type_cnt[ FD_DRAGON_FILTER_BLOCKS ] && !rpc->finalized ) ) {
    rpc->metrics.deferred_reject_cnt++;
    DRAGON_SESSION_FINISH( rpc, s, FD_GRPC_STATUS_INVALID_ARGUMENT,
                           "blocks are not supported by this server" );
    return;
  }

  ulong idx = (ulong)( s - rpc->session );

  /* Every blocks filter costs a share of a pass over each bank's
     accounts, so the server as a whole holds a bounded number. */
  if( FD_UNLIKELY( rpc->scratch->type_cnt[ FD_DRAGON_FILTER_BLOCKS ] ) ) {
    ulong blocks = rpc->scratch->type_cnt[ FD_DRAGON_FILTER_BLOCKS ];
    for( ulong i=0UL; i<rpc->stream_max; i++ ) {
      if( i!=idx && dragon_session_active( rpc->session+i ) ) blocks += rpc->session[ i ].filter->type_cnt[ FD_DRAGON_FILTER_BLOCKS ];
    }
    if( FD_UNLIKELY( blocks>FD_DRAGON_BLOCK_SUB_MAX ) ) {
      /* A request past the cap on its own can never be served */
      uint status = rpc->scratch->type_cnt[ FD_DRAGON_FILTER_BLOCKS ]>FD_DRAGON_BLOCK_SUB_MAX
                    ? FD_GRPC_STATUS_INVALID_ARGUMENT : FD_GRPC_STATUS_RESOURCE_EXHAUSTED;
      rpc->metrics.filter_reject_cnt++;
      DRAGON_SESSION_FINISH( rpc, s, status, DRAGON_MSG_MAX_BLOCKS );
      return;
    }
  }

  fd_dragon_filter_set_adopt( s->filter, rpc->scratch,
                              dragon_cuckoo_arena( rpc, idx ), rpc->cuckoo_entry_max );
  for( ulong i=0UL; i<s->filter->name_cnt; i++ ) {
    if( s->filter->name[ i ].cuckoo_bucket_cnt ) rpc->metrics.cuckoo_filter_cnt++;
  }

  /* With the filters at ingest, the buffer holds for this slot only
     what was matched under the filter set of the moment, so the set
     installed here is served from the next new bank on: a bank in
     flight was matched under someone else's set, or under this
     client's old one.  With the filters at send, every bank the buffer
     holds is served under the set of the moment it is served. */
  s->deferred               = deferred;
  s->eligible_from_bank_seq = rpc->filter_at==FD_DRAGON_FILTER_AT_INGEST ? rpc->bank_seq_hi+1UL : 0UL;
  dragon_recount( rpc );

  /* Replay from a past slot needs the history buffer, which this
     server does not keep.  out_of_range is what makes the yellowstone
     client drop its checkpoint and resume live; internal would make it
     retry the same from_slot. */
  if( FD_UNLIKELY( s->filter->has_from_slot ) ) {
    char  txt[ FD_GRPC_SERVER_MSG_MAX ];
    ulong txt_len = 0UL;
    fd_cstr_printf( txt, sizeof(txt), &txt_len,
                    "broadcast from %lu is not available, last available: %lu",
                    s->filter->from_slot,
                    rpc->have_level[ FD_DRAGON_COMMITMENT_PROCESSED ] ? rpc->level_slot[ FD_DRAGON_COMMITMENT_PROCESSED ] : 0UL );
    rpc->metrics.from_slot_reject_cnt++;
    dragon_session_finish( rpc, s, FD_GRPC_STATUS_OUT_OF_RANGE, txt, txt_len );
    return;
  }
}

/* Geyser consumer ****************************************************/

/* dragon_content_lost handles a bank that reached a buffered level
   without the buffer being able to serve it: the buffer gave up on it
   or the ring overwrote it, or the core never sealed it.  The status
   goes out to everyone regardless, so every subscriber sees the same
   slots reach the level; a subscriber that wanted the bank's content
   at that level cannot be given a complete view any more, so its call
   is ended with an error, the way a yellowstone server ends a call it
   fell behind on, and it backfills from wherever it reconnects.  The
   subscriptions at processed that owe a block of the bank are ended
   too: the block never went out. */

static void
dragon_content_lost( fd_dragon_rpc_t * rpc,
                     ulong             bank_id,
                     ulong             slot,
                     int               commitment ) {
  rpc->metrics.content_lost_cnt++;
  FD_DRAGON_WARN_POW2( rpc->metrics.content_lost_cnt,
                       "dragon cannot serve slot %lu (bank_id %lu) at %s: ending the subscriptions that wanted it",
                       slot, bank_id, commitment==FD_DRAGON_COMMITMENT_CONFIRMED ? "confirmed" : "finalized" );

  char  txt[ FD_GRPC_SERVER_MSG_MAX ];
  ulong txt_len = 0UL;
  fd_cstr_printf( txt, sizeof(txt), &txt_len, "content of slot %lu at %s was lost", slot,
                  commitment==FD_DRAGON_COMMITMENT_CONFIRMED ? "confirmed" : "finalized" );

  for( ulong i=0UL; i<rpc->stream_max; i++ ) {
    fd_dragon_session_t * s = rpc->session + i;
    if( !dragon_session_active( s ) ) continue;
    if( bank_id<s->eligible_from_bank_seq ) continue;

    int wanted = 0;
    for( ulong j=0UL; j<s->filter->name_cnt; j++ ) {
      int type = s->filter->name[ j ].type;
      if( type==FD_DRAGON_FILTER_SLOTS ) continue;
      if( s->filter->commitment==commitment || type==FD_DRAGON_FILTER_BLOCKS ) wanted = 1;
    }
    if( !wanted ) continue;

    rpc->metrics.content_lost_close_cnt++;
    dragon_session_finish( rpc, s, FD_GRPC_STATUS_INTERNAL, txt, txt_len );
  }
}

/* dragon_on_slot_status feeds the store the unary calls answer from,
   then fans the status out to the subscriptions whose slots filters
   pass it. */

static void
dragon_on_slot_status( void *       ctx,
                       ulong        slot,
                       ulong        parent_slot,
                       int          has_parent,
                       int          status,
                       ulong        bank_id,
                       int          has_bank_id,
                       char const * dead_error ) {
  fd_dragon_rpc_t * rpc = ctx;

  if( has_bank_id ) rpc->bank_seq_hi = fd_ulong_max( rpc->bank_seq_hi, bank_id );
  if( FD_UNLIKELY( has_bank_id && bank_id<rpc->serve_from_bank_seq ) ) return;

  dragon_store_status( rpc, slot, status );

  /* The commitment this status is, if it is one of the two the buffer
     serves. */
  int deferred_level = -1;
  if( has_bank_id && rpc->buf ) {
    if     ( status==FD_GEYSER_SLOT_CONFIRMED ) deferred_level = FD_DRAGON_COMMITMENT_CONFIRMED;
    else if( status==FD_GEYSER_SLOT_FINALIZED ) deferred_level = FD_DRAGON_COMMITMENT_FINALIZED;
  }

  /* Nothing is delivered at a buffered level for a bank the buffer
     gave up on or the ring overwrote, or one the core does not call
     sealed; the status still goes out. */
  if( deferred_level>=0 ) {
    fd_dragon_buf_bank_t * bank = fd_dragon_buf_bank( rpc->buf, bank_id );
    int lost = ( bank && ( bank->incomplete || dragon_buf_bank_overrun( rpc, bank ) ) ) ||
               dragon_degraded( rpc, bank_id )                                          ||
               !fd_geyser_bank_is_complete( rpc->core, bank_id );
    if( FD_LIKELY( !lost ) ) dragon_deliver( rpc, bank_id, deferred_level );
    else                     dragon_content_lost( rpc, bank_id, slot, deferred_level );
  }

  for( ulong i=0UL; i<rpc->stream_max; i++ ) {
    fd_dragon_session_t * s = rpc->session + i;
    if( s->kind!=FD_DRAGON_SESSION_SUBSCRIBE ) continue;
    if( FD_UNLIKELY( s->finished ) ) continue;

    /* A deferred subscription's own level is reported from the first
       bank it is eligible for, so its stream starts cleanly. */
    if( deferred_level>=0 && s->deferred && s->filter->commitment==deferred_level &&
        bank_id<s->eligible_from_bank_seq ) continue;

    dragon_filter_list_t list = { .cnt = 0UL };
    for( ulong j=0UL; j<s->filter->name_cnt; j++ ) {
      fd_dragon_filter_name_t const * name = s->filter->name + j;
      if( name->type!=FD_DRAGON_FILTER_SLOTS ) continue;
      if( !fd_dragon_slots_match( name, s->filter->commitment, status ) ) continue;
      list.name[ list.cnt++ ] = name;
    }
    if( !list.cnt ) continue;

    geyser_SubscribeUpdate update = geyser_SubscribeUpdate_init_zero;
    update.which_update_oneof = geyser_SubscribeUpdate_slot_tag;

    geyser_SubscribeUpdateSlot * u = &update.update_oneof.slot;
    u->slot        = slot;
    u->has_parent  = !!has_parent;
    u->parent      = parent_slot;
    u->status      = (geyser_SlotStatus)status;
    u->has_bank_id = !!has_bank_id;
    u->bank_id     = bank_id;
    if( FD_UNLIKELY( dead_error ) ) {
      u->has_dead_error = true;
      fd_cstr_printf( u->dead_error, sizeof(u->dead_error), NULL, "%s", dead_error );
    }

    rpc->metrics.slot_update_cnt++;
    dragon_update_send( rpc, s, &update, &list );
  }

  /* A finalized bank is served once, so whatever the buffer held for
     it is done with. */
  if( deferred_level==FD_DRAGON_COMMITMENT_FINALIZED ) {
    fd_dragon_buf_bank_t * bank = fd_dragon_buf_bank( rpc->buf, bank_id );
    if( FD_LIKELY( bank ) ) fd_dragon_buf_bank_drop( rpc->buf, bank );
  }
}

/* dragon_on_block_meta keeps the block summary the unary calls answer
   from, sends it to the subscriptions at processed, and keeps it for
   the buffered levels, where it goes out behind the bank's content. */

static void
dragon_on_block_meta( void *                         ctx,
                      fd_geyser_block_meta_t const * meta,
                      ulong                          bank_id ) {
  fd_dragon_rpc_t * rpc = ctx;

  rpc->bank_seq_hi = fd_ulong_max( rpc->bank_seq_hi, bank_id );
  if( FD_UNLIKELY( bank_id<rpc->serve_from_bank_seq ) ) return;

  dragon_meta_store( rpc, meta );
  dragon_block_meta_fanout( rpc, meta, bank_id, FD_DRAGON_COMMITMENT_PROCESSED );

  /* The summary is what a block is built around, so it is kept for a
     bank a block is owed for as well as for the buffered levels; with
     the filters at send, for every bank, since the subscribers it is
     served to are the ones of the moment it is served. */
  if( FD_LIKELY( !rpc->buf ) ) return;
  if( FD_LIKELY( rpc->filter_at==FD_DRAGON_FILTER_AT_INGEST && !rpc->deferred_sub_cnt && !rpc->blocks_sub_cnt ) ) return;

  fd_dragon_buf_bank_t * bank = dragon_buf_bank_open( rpc, bank_id, meta->slot );
  if( FD_UNLIKELY( !bank ) ) return;
  bank->meta     = *meta;
  bank->has_meta = 1;
}

/* dragon_on_bank_discarded reports a bank that is gone for good:
   whatever the buffer held for it will never be delivered. */

static void
dragon_on_bank_discarded( void * ctx,
                          ulong  bank_id,
                          int    reason ) {
  (void)reason;
  fd_dragon_rpc_t * rpc = ctx;
  if( FD_LIKELY( !rpc->buf ) ) return;

  /* Nothing names the bank any more, so the note that it was given up
     on has nothing left to suppress. */
  for( ulong i=0UL; i<FD_DRAGON_DEGRADE_MAX; i++ ) {
    if( rpc->degrade_bank[ i ]==bank_id ) rpc->degrade_bank[ i ] = ULONG_MAX;
  }

  fd_dragon_buf_bank_t * bank = fd_dragon_buf_bank( rpc->buf, bank_id );
  if( FD_LIKELY( !bank ) ) return;
  fd_dragon_buf_bank_drop( rpc->buf, bank );
}

fd_geyser_consumer_t *
fd_dragon_rpc_consumer( fd_dragon_rpc_t *      rpc,
                        fd_geyser_core_t *     core,
                        fd_geyser_consumer_t * out ) {
  rpc->core = core;

  fd_memset( out, 0, sizeof(fd_geyser_consumer_t) );
  out->ctx                = rpc;
  out->wants_transactions = 1;
  out->wants_accounts     = 1;
  out->on_slot_status     = dragon_on_slot_status;
  out->on_block_meta      = dragon_on_block_meta;
  out->on_transaction     = dragon_on_transaction;
  out->on_account         = dragon_on_account;
  out->on_bank_sealed     = dragon_on_bank_sealed;
  out->on_bank_discarded  = dragon_on_bank_discarded;
  return out;
}

FD_FN_PURE fd_dragon_buf_t *
fd_dragon_rpc_buf( fd_dragon_rpc_t * rpc ) {
  return rpc->buf;
}

/* Handler callbacks *************************************************/

static int
dragon_cb_conn_open( void *                  ctx,
                     fd_grpc_server_conn_t * conn ) {
  fd_dragon_rpc_t * rpc = ctx;
  rpc->metrics.conn_cnt++;
  if( rpc->conn_open_fn ) rpc->conn_open_fn( rpc->conn_ctx, fd_grpc_server_conn_fd( conn ) );
  return 0;
}

static void
dragon_cb_conn_close( void *                  ctx,
                      fd_grpc_server_conn_t * conn ) {
  fd_dragon_rpc_t * rpc = ctx;
  rpc->metrics.conn_cnt--;
  if( rpc->conn_close_fn ) rpc->conn_close_fn( rpc->conn_ctx, fd_grpc_server_conn_fd( conn ) );
}

/* DRAGON_AUTH_OK marks a stream whose field block carried the token.
   It lives in the stream context, which the transport clears whenever
   it hands out a stream slot, so it cannot outlive one request. */

#define DRAGON_AUTH_OK ((void *)1UL)

static void
dragon_cb_stream_hdr( void *                    ctx,
                      fd_grpc_server_stream_t * stream,
                      char const *              name,
                      ulong                     name_len,
                      char const *              value,
                      ulong                     value_len ) {
  fd_dragon_rpc_t * rpc = ctx;

  if( name_len!=7UL || !fd_memeq( name, "x-token", 7UL ) ) return;
  if( value_len!=rpc->x_token_len ) return;

  /* Compare without an early exit, so that the response time does not
     depend on how much of the token the client guessed. */
  uint diff = 0U;
  for( ulong i=0UL; i<value_len; i++ ) diff |= (uint)( (uchar)value[ i ] ^ (uchar)rpc->x_token[ i ] );
  fd_grpc_server_stream_set_ctx( stream, diff ? NULL : DRAGON_AUTH_OK );
}

static int
dragon_cb_stream_open( void *                    ctx,
                       fd_grpc_server_stream_t * stream,
                       char const *              path,
                       ulong                     path_len ) {
  fd_dragon_rpc_t * rpc = ctx;

  int authed = fd_grpc_server_stream_ctx( stream )==DRAGON_AUTH_OK;
  fd_grpc_server_stream_set_ctx( stream, NULL );

  int method = dragon_route( path, path_len );
  rpc->metrics.request_cnt[ method ]++;

  if( FD_UNLIKELY( rpc->x_token_len && !authed ) ) {
    rpc->metrics.auth_fail_cnt++;
    DRAGON_FINISH( stream, FD_GRPC_STATUS_UNAUTHENTICATED, DRAGON_MSG_NO_TOKEN );
    return FD_GRPC_SERVER_REJECT;
  }

  switch( method ) {
  case FD_DRAGON_METHOD_UNKNOWN:
    /* The transport answers unimplemented for a path nobody serves. */
    rpc->metrics.unimplemented_cnt++;
    return FD_GRPC_SERVER_REJECT;
  case FD_DRAGON_METHOD_SUBSCRIBE_DESHRED:
  case FD_DRAGON_METHOD_SUBSCRIBE_GOSSIP:
    rpc->metrics.unimplemented_cnt++;
    DRAGON_FINISH( stream, FD_GRPC_STATUS_UNIMPLEMENTED, DRAGON_MSG_DISABLED );
    return FD_GRPC_SERVER_REJECT;
  default:
    break;
  }

  fd_dragon_session_t * s = dragon_session_acquire( rpc, stream, method );
  if( FD_UNLIKELY( !s ) ) {
    rpc->metrics.stream_full_cnt++;
    DRAGON_FINISH( stream, FD_GRPC_STATUS_RESOURCE_EXHAUSTED, DRAGON_MSG_MAX_SUBS );
    return FD_GRPC_SERVER_REJECT;
  }
  fd_grpc_server_stream_set_ctx( stream, s );

  if( method==FD_DRAGON_METHOD_SUBSCRIBE ) {
    rpc->metrics.subscription_cnt++;
    /* The first server ping goes out as soon as the stream is up, as
       a tokio interval fires its first tick immediately. */
    s->next_ping_nanos = rpc->now;
    return FD_GRPC_SERVER_ACCEPT_STREAM;
  }

  /* Watch answers its one request with the current status and then
     stays open for the changes. */
  if( method==FD_DRAGON_METHOD_HEALTH_WATCH ) return FD_GRPC_SERVER_ACCEPT_STREAM;

  return FD_GRPC_SERVER_ACCEPT_UNARY;
}

static void
dragon_cb_stream_msg( void *                    ctx,
                      fd_grpc_server_stream_t * stream,
                      uchar const *             msg,
                      ulong                     msg_sz ) {
  fd_dragon_rpc_t *     rpc = ctx;
  fd_dragon_session_t * s   = fd_grpc_server_stream_ctx( stream );
  if( FD_UNLIKELY( !s ) ) return;
  s->request_nanos = 0L;

  if( s->kind==FD_DRAGON_SESSION_SUBSCRIBE ) {
    dragon_subscribe_request( rpc, s, msg, msg_sz );
    return;
  }

  if( s->kind==FD_DRAGON_SESSION_HEALTH_WATCH ) {
    dragon_health_watch_request( rpc, s, msg, msg_sz );
    return;
  }

  if( FD_UNLIKELY( s->answered ) ) return; /* a unary call takes one request message */
  s->answered = 1;
  dragon_unary( rpc, s, s->method, msg, msg_sz );
}

static void
dragon_cb_stream_half_close( void *                    ctx,
                             fd_grpc_server_stream_t * stream ) {
  fd_dragon_rpc_t *     rpc = ctx;
  fd_dragon_session_t * s   = fd_grpc_server_stream_ctx( stream );
  if( FD_UNLIKELY( !s ) ) return;
  if( s->kind==FD_DRAGON_SESSION_SUBSCRIBE ) return; /* the response stream stays open */
  if( s->answered ) return;

  if( s->kind==FD_DRAGON_SESSION_HEALTH_WATCH ) {
    /* A Watch that closed its request side without naming a service
       is watching the whole server. */
    dragon_health_watch_request( rpc, s, NULL, 0UL );
    return;
  }

  /* A unary call that ended without a request message is answered
     from an empty request, which is what every field of the request
     defaulting to zero means. */
  s->answered = 1;
  dragon_unary( rpc, s, s->method, NULL, 0UL );
}

static void
dragon_cb_stream_close( void *                    ctx,
                        fd_grpc_server_stream_t * stream,
                        int                       reason ) {
  fd_dragon_rpc_t *     rpc = ctx;
  fd_dragon_session_t * s   = fd_grpc_server_stream_ctx( stream );
  if( FD_UNLIKELY( !s ) ) return;

  /* The transport decides who has fallen behind, so the count of
     subscribers it dropped comes back with the close. */
  if( reason==FD_GRPC_SERVER_CLOSE_TOO_SLOW ) rpc->metrics.lagged_close_cnt++;

  if( s->kind==FD_DRAGON_SESSION_SUBSCRIBE ) rpc->metrics.subscription_cnt--;
  rpc->metrics.stream_cnt--;

  /* How close the call came to being closed for falling behind, which
     the owner turns into a histogram. */
  rpc->ref_hi[ rpc->ref_hi_next % FD_DRAGON_CLIENT_MAX ] = fd_grpc_server_stream_tx_ref_hi( stream );
  rpc->ref_hi_next++;

  /* The buffer may still hold entries whose masks name this client
     slot.  They are harmless: the next client of the slot is eligible
     from the next new bank only, and nothing is delivered to a slot
     nobody occupies. */
  fd_memset( s, 0, sizeof(fd_dragon_session_t) );
  fd_grpc_server_stream_set_ctx( stream, NULL );
  dragon_recount( rpc );
}

static fd_grpc_server_callbacks_t const dragon_callbacks = {
  .conn_open         = dragon_cb_conn_open,
  .conn_close        = dragon_cb_conn_close,
  .stream_hdr        = dragon_cb_stream_hdr,
  .stream_open       = dragon_cb_stream_open,
  .stream_msg        = dragon_cb_stream_msg,
  .stream_half_close = dragon_cb_stream_half_close,
  .stream_close      = dragon_cb_stream_close
};

FD_FN_CONST fd_grpc_server_callbacks_t const *
fd_dragon_rpc_callbacks( void ) {
  return &dragon_callbacks;
}

void
fd_dragon_rpc_service( fd_dragon_rpc_t * rpc,
                       long              now_nanos ) {
  rpc->now = now_nanos;

  for( ulong i=0UL; i<rpc->stream_max; i++ ) {
    fd_dragon_session_t * s = rpc->session + i;
    if( !s->stream ) continue;

    if( FD_UNLIKELY( s->finished ) ) {
      /* The status cannot reach a client that is not reading.  Closing
         the connection releases the call slot and its queue; the
         session is gone once this returns. */
      if( s->reap_nanos && now_nanos>=s->reap_nanos ) {
        rpc->metrics.lagged_reap_cnt++;
        fd_grpc_server_conn_close( fd_grpc_server_stream_conn( s->stream ) );
      }
      continue;
    }

    if( FD_UNLIKELY( s->request_nanos && now_nanos>=s->request_nanos ) ) {
      DRAGON_SESSION_FINISH( rpc, s, FD_GRPC_STATUS_DEADLINE_EXCEEDED, DRAGON_MSG_NO_REQUEST );
      continue;
    }

    if( s->kind!=FD_DRAGON_SESSION_SUBSCRIBE ) continue;
    if( !rpc->ping_interval ) continue;
    if( now_nanos<s->next_ping_nanos ) continue;
    s->next_ping_nanos = now_nanos + rpc->ping_interval;
    dragon_subscribe_ping( rpc, s );
  }
}
