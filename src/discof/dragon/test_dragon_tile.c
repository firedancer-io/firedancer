/* test_dragon_tile runs the dragon tile's server on a real socket,
   wired exactly as the tile wires it: an fd_grpc_server whose sockets
   live in an epoll set, the Dragon's Mouth service on top, the service
   tick that runs the timers, and optionally the tile's own seccomp
   policy.  It exists so that a real HTTP/2 client can be pointed at
   the server without booting a validator.

   Usage:

     test_dragon_tile [--listen-port 10000] [--x-token ""]
                      [--compression zstd|none] [--compression-min-bytes 1024]
                      [--slot 0] [--block-height 0] [--slot-millis 400]
                      [--duration-seconds 10] [--seccomp 0]

   With --slot set, the harness also feeds the geyser core a chain of
   slots, one every --slot-millis, rooting the one 32 slots behind, so
   that a client sees the same statuses and unary answers a validator
   would give it. */

#include "fd_dragon_rpc.h"
#include "fd_dragon_index.h"
#include "fd_geyser_core.h"
#include "../../ballet/base58/fd_base58.h"
#include "../../flamenco/accdb/fd_accdb.h"
#include "../../flamenco/runtime/fd_system_ids.h"
#include "../../util/sandbox/fd_sandbox_private.h"
#include "../../waltz/grpc/fd_grpc_server.h"

#include <errno.h>
#include <sys/epoll.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>

#include "generated/fd_dragon_tile_seccomp.h"

/* The tile defaults need about 70 MiB, most of it the per call send
   queues; the pages of this array that are never touched cost
   nothing. */
static uchar server_mem[ 256UL<<20 ] __attribute__((aligned(FD_GRPC_SERVER_ALIGN)));
static uchar rpc_mem   [ 512UL<<20 ] __attribute__((aligned(FD_DRAGON_RPC_ALIGN)));
static uchar core_mem  [   4UL<<20 ] __attribute__((aligned(FD_GEYSER_CORE_ALIGN)));

/* The ring the buffered levels are served from, sized by
   --buffer-bytes up to what this region holds. */

#define TEST_BUF_DEPTH (1UL<<16)

static uchar buf_mcache_mem[   4UL<<20 ] __attribute__((aligned(FD_MCACHE_ALIGN)));
static uchar buf_dcache_mem[ 257UL<<20 ] __attribute__((aligned(FD_DCACHE_ALIGN)));

#define TEST_BANK_IDX_MAX (64UL)

/* The harness stands in for replay: it grants a reference with every
   notification and takes them all back on a release. */

static ulong test_refcnt[ TEST_BANK_IDX_MAX ];
static ulong test_seq;

static void
test_release( void * ctx,
              ulong  bank_idx,
              ulong  seq_bound ) {
  (void)ctx; (void)seq_bound;
  FD_TEST( bank_idx<TEST_BANK_IDX_MAX );
  test_refcnt[ bank_idx ] = 0UL;
}

/* test_read_account stands in for the accounts database: an account
   is whatever its address says it is, so that a subscriber at a
   deferred level is served something deterministic. */

static uchar test_acct_data[ 4096 ];
static uchar test_acct_owner[ 32 ];

static int
test_read_account( void *                ctx,
                   fd_accdb_fork_id_t    fork_id,
                   uchar const *         pubkey,
                   fd_geyser_account_t * out ) {
  (void)ctx; (void)fork_id;
  ulong sz = 64UL + ( (ulong)pubkey[ 0 ] * 13UL );
  if( sz>sizeof(test_acct_data) ) sz = sizeof(test_acct_data);
  for( ulong i=0UL; i<sz; i++ ) test_acct_data[ i ] = (uchar)( pubkey[ 0 ]+i );
  fd_memset( test_acct_owner, 0x60, 32UL );
  out->lamports   = 1000UL + (ulong)pubkey[ 0 ];
  out->executable = 0;
  out->owner      = test_acct_owner;
  out->data       = test_acct_data;
  out->data_sz    = sz;
  return 0;
}

/* test_records feeds one slot's worth of records: txn_cnt committed
   transactions that each wrote an account, and the four sysvar writes
   that seal a bank.  Each transaction is a parseable legacy message
   whose program is one of the demo page's preset accounts, so its
   default filter matches. */

static char const * test_demo_program[ 3 ] = {
  "2DNbzPochEcyCcWMbL4d9S3u9QqQEj5bbe6cSZFvKsbh",
  "JanusXpm3gsW3c9ErNoUgHppL8dGLvZKB7uekkJEYFP",
  "Tri3NG4HkZ6DddYPKoX2ehgkqFtDuej9Aspw5BmvSo4"
};

static void
test_records( fd_geyser_core_t * core,
              ulong              slot,
              ulong              txn_cnt,
              ulong              acct_data_sz,
              int                with_accounts ) {
  static uchar payload[ 256 ];
  static uchar keys[ 3 ][ 32 ];
  static ulong pre [ 3 ];
  static ulong post[ 3 ];
  static uchar writable[ 3 ] = { 1, 1, 1 };
  static uchar data[ 65536 ];
  static fd_event_internal_commit_touched_t touched[ 1 ];

  if( acct_data_sz>sizeof(data) ) acct_data_sz = sizeof(data);
  for( ulong i=0UL; i<sizeof(data); i++ ) data[ i ] = (uchar)i;

  for( ulong t=0UL; t<txn_cnt; t++ ) {
    for( ulong i=0UL; i<3UL; i++ ) {
      fd_memset( keys[ i ], (int)( 0x20+i+t ), 32UL );
      pre [ i ] = 100UL+i;
      post[ i ] = 200UL+i;
    }
    FD_TEST( fd_base58_decode_32( test_demo_program[ t%3UL ], keys[ 2 ] ) );

    uchar sig[ 64 ];
    fd_memset( sig, (int)( 0xA0+t ), 64UL );
    FD_STORE( ulong, sig, slot );

    ulong o = 0UL;
    payload[ o++ ] = 1U;                               /* one signature */
    fd_memcpy( payload+o, sig, 64UL ); o += 64UL;
    payload[ o++ ] = 1U;                               /* signers */
    payload[ o++ ] = 0U;                               /* readonly signers */
    payload[ o++ ] = 1U;                               /* readonly non signers */
    payload[ o++ ] = 3U;
    for( ulong i=0UL; i<3UL; i++ ) { fd_memcpy( payload+o, keys[ i ], 32UL ); o += 32UL; }
    fd_memset( payload+o, 0x30, 32UL ); o += 32UL;     /* recent blockhash */
    payload[ o++ ] = 1U;                               /* one instruction */
    payload[ o++ ] = 2U;                               /* program */
    payload[ o++ ] = 1U;                               /* one account */
    payload[ o++ ] = 0U;
    payload[ o++ ] = 1U;                               /* one data byte */
    payload[ o++ ] = 0x77;
    touched[ 0 ].key_idx    = 2U;
    touched[ 0 ].executable = 0U;
    touched[ 0 ].lamports   = 500UL+t;
    touched[ 0 ].data_sz    = acct_data_sz;
    fd_memset( touched[ 0 ].owner, 0x60, 32UL );

    fd_event_internal_commit_t ev[1];
    fd_memset( ev, 0, sizeof(fd_event_internal_commit_t) );
    ev->bank_seq             = slot;
    ev->slot                 = slot;
    ev->index_in_slot        = t;
    ev->commit_index_in_slot = t;
    ev->accounts_included    = !!with_accounts;
    ev->exec_err_idx         = UINT_MAX;
    ev->custom_err           = UINT_MAX;
    ev->rent_err_account_idx = UINT_MAX;
    ev->execution_fee        = 5000UL;
    ev->payload_cnt          = o;
    ev->acct_addr_cnt        = 3U;
    ev->keys_cnt             = 3UL;
    ev->pre_lamports_cnt     = 3UL;
    ev->post_lamports_cnt    = 3UL;
    ev->is_writable_cnt      = 3UL;
    ev->touched_cnt          = with_accounts ? 1UL : 0UL;
    fd_memcpy( ev->signature, sig, 64UL );

    fd_event_internal_commit_parts_t parts = {
      .prefix        = ev,
      .payload       = payload,
      .keys          = (uchar const (*)[ 32UL ])keys,
      .pre_lamports  = pre,
      .post_lamports = post,
      .is_writable   = writable,
      .touched       = touched
    };
    fd_geyser_core_commit_record( core, &parts );

    /* The account record of the one account it wrote. */
    if( with_accounts ) {
      static fd_event_internal_runtime_write_touched_t atouched[ 1 ];
      atouched[ 0 ].key_idx    = 0U;
      atouched[ 0 ].executable = 0U;
      atouched[ 0 ].lamports   = 500UL+t;
      atouched[ 0 ].data_off   = 0UL;
      atouched[ 0 ].data_sz    = acct_data_sz;
      fd_memset( atouched[ 0 ].owner, 0x60, 32UL );

      fd_event_internal_runtime_write_t aev[1];
      fd_memset( aev, 0, sizeof(fd_event_internal_runtime_write_t) );
      aev->bank_seq             = slot;
      aev->slot                 = slot;
      aev->phase                = 1U;
      fd_memcpy( aev->signature, sig, 64UL );
      aev->commit_index_in_slot = t;
      aev->touched_idx          = 0U;
      aev->accounts_included    = 1;
      aev->keys_cnt             = 1UL;
      aev->touched_cnt          = 1UL;
      aev->account_data_cnt     = acct_data_sz;

      fd_event_internal_runtime_write_parts_t aparts = {
        .prefix       = aev,
        .keys         = (uchar const (*)[ 32UL ])(keys+2),
        .touched      = atouched,
        .account_data = data
      };
      fd_geyser_core_runtime_write_record( core, &aparts );
    }
  }

  /* The sysvar writes, without which a bank never seals */
  fd_pubkey_t const * sysvar[ 4 ] = { &fd_sysvar_clock_id, &fd_sysvar_slot_hashes_id,
                                      &fd_sysvar_slot_history_id, &fd_sysvar_recent_block_hashes_id };
  for( ulong i=0UL; i<4UL; i++ ) {
    static uchar wkeys[ 1 ][ 32 ];
    static fd_event_internal_runtime_write_touched_t wtouched[ 1 ];
    fd_memcpy( wkeys[ 0 ], sysvar[ i ]->uc, 32UL );
    wtouched[ 0 ].key_idx    = 0U;
    wtouched[ 0 ].executable = 0U;
    wtouched[ 0 ].lamports   = 1UL;
    wtouched[ 0 ].data_off   = 0UL;
    wtouched[ 0 ].data_sz    = with_accounts ? 64UL : 0UL;
    fd_memset( wtouched[ 0 ].owner, 0x61, 32UL );

    fd_event_internal_runtime_write_t ev[1];
    fd_memset( ev, 0, sizeof(fd_event_internal_runtime_write_t) );
    ev->bank_seq          = slot;
    ev->slot              = slot;
    ev->phase             = 2U;
    ev->accounts_included = !!with_accounts;
    ev->write_seq         = i;
    ev->keys_cnt          = 1UL;
    ev->touched_cnt       = 1UL;
    ev->account_data_cnt  = wtouched[ 0 ].data_sz;

    fd_event_internal_runtime_write_parts_t parts = {
      .prefix       = ev,
      .keys         = (uchar const (*)[ 32UL ])wkeys,
      .touched      = wtouched,
      .account_data = data
    };
    fd_geyser_core_runtime_write_record( core, &parts );
  }
}

static void
test_slot_completed( fd_geyser_core_t * core,
                     ulong              slot,
                     ulong              block_height,
                     ulong              txn_per_slot ) {
  fd_replay_slot_completed_t msg = {
    .slot              = slot,
    .parent_slot       = slot-1UL,
    .bank_seq          = slot,
    .parent_bank_seq   = slot>1UL ? slot-1UL : ULONG_MAX,
    .bank_idx          = slot % TEST_BANK_IDX_MAX,
    .block_height      = block_height,
    .transaction_count = txn_per_slot*slot, /* cumulative, so each block has txn_per_slot */
    /* Replay's per slot counts, which are what the core gates a
       bank's seal on */
    .vote_success      = 0UL,
    .vote_failed       = 0UL,
    .nonvote_success   = txn_per_slot,
    .nonvote_failed    = 0UL
  };
  msg.block_hash.ul[ 0 ] = 0x100UL + slot;
  test_refcnt[ msg.bank_idx ]++;
  fd_geyser_core_slot_completed( core, &msg, test_seq++ );
}

static void
test_root_advanced( fd_geyser_core_t * core,
                    ulong              slot ) {
  fd_replay_oc_advanced_t   oc   = { .slot = slot, .bank_seq = slot, .bank_idx = slot % TEST_BANK_IDX_MAX };
  fd_replay_root_advanced_t root = { .slot = slot, .bank_seq = slot, .bank_idx = slot % TEST_BANK_IDX_MAX };
  fd_geyser_core_oc_advanced( core, &oc, test_seq++ );
  test_refcnt[ root.bank_idx ]++;
  fd_geyser_core_root_advanced( core, &root, test_seq++ );
}

struct test_ctx {
  int epoll_inner;
  int epoll_outer;
};

typedef struct test_ctx test_ctx_t;

static void
test_conn_open( void * _ctx,
                int    sock ) {
  test_ctx_t * ctx = _ctx;
  if( FD_UNLIKELY( sock<0 ) ) return;
  struct epoll_event ev = { .events = EPOLLIN, .data = { .fd = sock } };
  if( FD_UNLIKELY( 0!=epoll_ctl( ctx->epoll_inner, EPOLL_CTL_ADD, sock, &ev ) && errno!=EEXIST ) )
    FD_LOG_ERR(( "epoll_ctl(EPOLL_CTL_ADD,%d) failed (%i-%s)", sock, errno, fd_io_strerror( errno ) ));
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  ulong        listen_port      = fd_env_strip_cmdline_ulong( &argc, &argv, "--listen-port",          NULL,    10000UL );
  char const * x_token          = fd_env_strip_cmdline_cstr ( &argc, &argv, "--x-token",              NULL,         "" );
  char const * compression      = fd_env_strip_cmdline_cstr ( &argc, &argv, "--compression",          NULL,     "zstd" );
  ulong        compression_min  = fd_env_strip_cmdline_ulong( &argc, &argv, "--compression-min-bytes",NULL,     1024UL );
  ulong        slot             = fd_env_strip_cmdline_ulong( &argc, &argv, "--slot",                 NULL,         0UL );
  ulong        block_height     = fd_env_strip_cmdline_ulong( &argc, &argv, "--block-height",         NULL,         0UL );
  long         slot_millis      = fd_env_strip_cmdline_long ( &argc, &argv, "--slot-millis",          NULL,        400L );
  long         duration_seconds = fd_env_strip_cmdline_long ( &argc, &argv, "--duration-seconds",     NULL,         10L );
  long         max_streams      = fd_env_strip_cmdline_long ( &argc, &argv, "--max-streams",          NULL,          4L );
  long         max_conns        = fd_env_strip_cmdline_long ( &argc, &argv, "--max-conns",            NULL,         16L );
  long         session_max      = fd_env_strip_cmdline_long ( &argc, &argv, "--session-max",          NULL,         64L );
  int          seccomp          = fd_env_strip_cmdline_int  ( &argc, &argv, "--seccomp",              NULL,          0 );
  ulong        records          = fd_env_strip_cmdline_ulong( &argc, &argv, "--records",              NULL,         0UL );
  ulong        record_bytes     = fd_env_strip_cmdline_ulong( &argc, &argv, "--record-bytes",         NULL,       512UL );
  int          deferred         = fd_env_strip_cmdline_int  ( &argc, &argv, "--deferred",             NULL,          1 );
  ulong        buf_bytes        = fd_env_strip_cmdline_ulong( &argc, &argv, "--buffer-bytes",         NULL, 64UL<<20 );
  char const * filter_at_str    = fd_env_strip_cmdline_cstr ( &argc, &argv, "--filter-at",            NULL, "ingest" );
  ulong        max_message      = fd_env_strip_cmdline_ulong( &argc, &argv, "--max-message-bytes",    NULL, 16UL<<20 );
  ulong        ring_bytes       = fd_env_strip_cmdline_ulong( &argc, &argv, "--send-buffer-bytes",    NULL, 64UL<<20 );
  ulong        ref_max          = fd_env_strip_cmdline_ulong( &argc, &argv, "--channel-capacity",     NULL,     4096UL );
  ulong        cuckoo_bytes     = fd_env_strip_cmdline_ulong( &argc, &argv, "--cuckoo-bytes",         NULL,  1UL<<20 );

  ulong txn_per_slot = records ? records : 10UL;

  test_ctx_t ctx[1] = {{ .epoll_inner = -1, .epoll_outer = -1 }};

  ctx->epoll_inner = epoll_create1( 0 );
  FD_TEST( ctx->epoll_inner>=0 );
  ctx->epoll_outer = epoll_create1( 0 );
  FD_TEST( ctx->epoll_outer>=0 );
  struct epoll_event inner_ev = { .events = EPOLLIN|EPOLLONESHOT, .data = { .fd = ctx->epoll_inner } };
  FD_TEST( 0==epoll_ctl( ctx->epoll_outer, EPOLL_CTL_ADD, ctx->epoll_inner, &inner_ev ) );

  int filter_at = !strcmp( filter_at_str, "send" ) ? FD_DRAGON_FILTER_AT_SEND : FD_DRAGON_FILTER_AT_INGEST;
  FD_TEST( fd_mcache_footprint( TEST_BUF_DEPTH, 0UL )<=sizeof(buf_mcache_mem) );
  FD_TEST( fd_dcache_footprint( buf_bytes, 0UL )<=sizeof(buf_dcache_mem) );
  fd_dragon_rpc_params_t rpc_params = {
    .stream_max            = (ulong)session_max,
    .ping_interval_nanos   = 10000000000L,
    .x_token               = x_token,
    .conn_ctx              = ctx,
    .conn_open             = test_conn_open,
    .finalized             = deferred,
    .filter_at             = filter_at,
    .buf_mcache            = fd_mcache_join( fd_mcache_new( buf_mcache_mem, TEST_BUF_DEPTH, 0UL, 0UL ) ),
    .buf_dcache            = fd_dcache_join( fd_dcache_new( buf_dcache_mem, buf_bytes, 0UL ) ),
    .buf_base              = buf_dcache_mem,
    .buf_depth             = TEST_BUF_DEPTH,
    .bank_max              = 2UL*TEST_BANK_IDX_MAX,
    .msg_max_bytes         = max_message,
    .cuckoo_bytes          = cuckoo_bytes
  };
  FD_TEST( rpc_params.buf_mcache && rpc_params.buf_dcache );
  FD_TEST( fd_dragon_rpc_footprint( &rpc_params )<=sizeof(rpc_mem) );
  FD_LOG_NOTICE(( "DBG rpc stream_max=%lu", rpc_params.stream_max ));
  fd_dragon_rpc_t * rpc = fd_dragon_rpc_join( fd_dragon_rpc_new( rpc_mem, &rpc_params ) );
  FD_TEST( rpc );

  fd_geyser_core_params_t core_params = {
    .max_live_banks = TEST_BANK_IDX_MAX,
    .records_gate   = !!records,
    .release_fn     = test_release,
    .read_fn        = deferred ? test_read_account : NULL
  };
  FD_TEST( fd_geyser_core_footprint( &core_params )<=sizeof(core_mem) );
  fd_geyser_core_t * core = fd_geyser_core_join( fd_geyser_core_new( core_mem, &core_params ) );
  FD_TEST( core );
  fd_geyser_consumer_t consumer[1];
  FD_TEST( !fd_geyser_core_register( core, fd_dragon_rpc_consumer( rpc, core, consumer ) ) );

  /* A history deep enough that every commitment level has a bank. */
  if( slot ) {
    FD_TEST( slot>64UL );
    for( ulong s=slot-40UL; s<=slot; s++ ) {
      if( records ) test_records( core, s, records, record_bytes, 1 );
      test_slot_completed( core, s, block_height ? block_height-(slot-s) : s, txn_per_slot );
      if( s>=slot-40UL+33UL ) test_root_advanced( core, s-32UL );
    }
  }

  fd_grpc_server_params_t params[1];
  fd_grpc_server_params_default( params );
  params->max_conn_cnt       = (ulong)max_conns;
  params->max_stream_cnt     = (ulong)max_streams;
  params->max_request_msg_sz = 65536UL;
  params->max_msg_sz         = max_message;
  params->tx_ring_sz         = fd_ulong_max( ring_bytes, 3UL*( params->max_msg_sz+5UL ) );
  params->stream_tx_ref_max  = ref_max;
  params->conn_rx_buf_sz     = 65536UL;
  params->conn_tx_buf_sz     = 262144UL;
  params->conn_rx_wnd_sz     = 1UL<<20;
  params->stream_rx_wnd_sz   = 262144UL;
  params->idle_timeout_nanos = 300L*1000000000L;
  params->compression        = !strcmp( compression, "zstd" ) ? FD_GRPC_SERVER_COMPRESSION_ZSTD
                                                              : FD_GRPC_SERVER_COMPRESSION_NONE;
  params->compression_min_sz = compression_min;
  params->compression_level  = 1;
  params->web                = 1;
  params->web_index          = fd_dragon_index_html;
  params->web_index_sz       = sizeof(fd_dragon_index_html)-1UL;
  FD_TEST( fd_grpc_server_footprint( params )<=sizeof(server_mem) );

  fd_grpc_server_t * server = fd_grpc_server_join( fd_grpc_server_new( server_mem, params, fd_dragon_rpc_callbacks(), rpc ) );
  FD_TEST( server );

  int listen_fd = fd_grpc_server_listen( server, 0U /* 0.0.0.0 */, (ushort)listen_port );
  FD_TEST( listen_fd>=0 );
  struct epoll_event listen_ev = { .events = EPOLLIN, .data = { .fd = listen_fd } };
  FD_TEST( 0==epoll_ctl( ctx->epoll_inner, EPOLL_CTL_ADD, listen_fd, &listen_ev ) );

  FD_LOG_NOTICE(( "listening on port %lu", listen_port ));

  if( seccomp ) {
    FD_TEST( 0==prctl( PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0 ) );
    struct sock_filter filter[ 256 ];
    FD_TEST( sock_filter_policy_fd_dragon_tile_instr_cnt<=256U );
    populate_sock_filter_policy_fd_dragon_tile( 256UL, filter,
                                               (uint)fd_log_private_logfile_fd(),
                                               (uint)listen_fd,
                                               (uint)ctx->epoll_inner,
                                               (uint)ctx->epoll_outer,
                                               (uint)FD_ACCDB_FD_RO );
    fd_sandbox_private_set_seccomp_filter( (ushort)sock_filter_policy_fd_dragon_tile_instr_cnt, filter );
    FD_LOG_NOTICE(( "seccomp policy installed" ));
  }

  long deadline  = fd_log_wallclock() + duration_seconds*1000000000L;
  long next_slot = fd_log_wallclock() + slot_millis*1000000L;
  ulong next     = slot+1UL;

  /* Stream lifecycle sampler: one CSV line whenever anything moves,
     plus a heartbeat, so a client's stream usage can be read off. */
  long  t0          = fd_log_wallclock();
  long  next_sample = t0;
  long  next_beat   = t0;
  ulong prev[ 8 ] = {0};
  FD_LOG_NOTICE(( "SAMPLE t_ms,conns,calls,subs,s_open,s_reject,c_open,c_close,upd,"
                  "m_subscribe,m_ping,m_hcheck,m_hwatch,m_getver,m_getslot,m_unknown" ));

  for(;;) {
    long now = fd_log_wallclock();
    if( FD_UNLIKELY( now>deadline ) ) break;

    if( now>=next_sample ) {
      next_sample = now + 20000000L; /* 20ms */
      fd_grpc_server_metrics_t const * sm = fd_grpc_server_metrics( server );
      fd_dragon_rpc_metrics_t  const * dm = fd_dragon_rpc_metrics( rpc );
      ulong cur[ 8 ] = { dm->conn_cnt, dm->stream_cnt, dm->subscription_cnt,
                         sm->stream_open_cnt, sm->stream_reject_cnt,
                         sm->conn_open_cnt, sm->conn_close_cnt, dm->update_sent_cnt };
      int changed = 0;
      for( ulong i=0UL; i<8UL; i++ ) if( cur[i]!=prev[i] ) changed = 1;
      if( changed || now>=next_beat ) {
        if( now>=next_beat ) next_beat = now + 2000000000L;
        FD_LOG_NOTICE(( "SAMPLE %ld,%lu,%lu,%lu,%lu,%lu,%lu,%lu,%lu,%lu,%lu,%lu,%lu,%lu,%lu,%lu",
                        (now-t0)/1000000L, cur[0], cur[1], cur[2], cur[3], cur[4], cur[5], cur[6], cur[7],
                        dm->request_cnt[ FD_DRAGON_METHOD_SUBSCRIBE ],
                        dm->request_cnt[ FD_DRAGON_METHOD_PING ],
                        dm->request_cnt[ FD_DRAGON_METHOD_HEALTH_CHECK ],
                        dm->request_cnt[ FD_DRAGON_METHOD_HEALTH_WATCH ],
                        dm->request_cnt[ FD_DRAGON_METHOD_GET_VERSION ],
                        dm->request_cnt[ FD_DRAGON_METHOD_GET_SLOT ],
                        dm->request_cnt[ FD_DRAGON_METHOD_UNKNOWN ] ));
        for( ulong i=0UL; i<8UL; i++ ) prev[i] = cur[i];
      }
    }

    if( slot && now>=next_slot ) {
      next_slot = now + slot_millis*1000000L;
      if( records ) test_records( core, next, records, record_bytes, 1 );
      test_slot_completed( core, next, block_height ? block_height+(next-slot) : next, txn_per_slot );
      test_root_advanced( core, next-32UL );
      fd_geyser_core_housekeeping( core );
      next++;
    }

    fd_dragon_rpc_service( rpc, now );
    fd_grpc_server_service( server, now );
    fd_grpc_server_poll( server, 0 );

    /* The waker rearms its entry after every drain, so the same
       epoll_ctl the tile makes is exercised here. */
    struct epoll_event ev = { .events = EPOLLIN|EPOLLONESHOT, .data = { .fd = ctx->epoll_inner } };
    if( FD_UNLIKELY( 0!=epoll_ctl( ctx->epoll_outer, EPOLL_CTL_MOD, ctx->epoll_inner, &ev ) ) )
      FD_LOG_ERR(( "epoll_ctl(EPOLL_CTL_MOD) failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  }

  fd_grpc_server_shutdown( server );
  for( ulong i=0UL; i<1000UL && !fd_grpc_server_is_idle( server ); i++ ) {
    fd_grpc_server_poll( server, 1 );
  }

  /* Every client is gone.  A few more slots let the banks that were in
     flight reach the root, which is what frees what the store held for
     the subscribers that left, and a gap sweep takes back every bank
     reference replay granted. */
  for( ulong i=0UL; i<64UL; i++ ) {
    if( slot ) {
      if( records ) test_records( core, next, records, record_bytes, 1 );
      test_slot_completed( core, next, block_height ? block_height+(next-slot) : next, txn_per_slot );
      test_root_advanced( core, next-32UL );
      next++;
    }
    fd_geyser_core_housekeeping( core );
    fd_dragon_rpc_service( rpc, fd_log_wallclock() );
    fd_grpc_server_service( server, fd_log_wallclock() );
  }
  fd_geyser_core_link_gap( core, test_seq++ );
  fd_dragon_rpc_service( rpc, fd_log_wallclock() );

  fd_grpc_server_metrics_t  const * srv = fd_grpc_server_metrics( server );
  fd_dragon_rpc_metrics_t   const * met = fd_dragon_rpc_metrics( rpc );
  fd_geyser_core_metrics_t  const * geyser = fd_geyser_core_metrics( core );
  fd_dragon_buf_t *                 buf    = fd_dragon_rpc_buf( rpc );

  FD_LOG_NOTICE(( "conns %lu calls %lu msgs %lu large %lu bytes %lu wire %lu compressed %lu "
                  "auth_fail %lu unimplemented %lu filter_reject %lu lagged %lu lagged_reap %lu "
                  "queue_full %lu large_busy %lu req_err %lu",
                  srv->conn_open_cnt, srv->stream_open_cnt, srv->tx_msg_cnt, srv->tx_too_slow_ring_cnt,
                  srv->tx_byte_cnt, srv->tx_byte_cnt_wire, srv->tx_msg_compressed_cnt,
                  met->auth_fail_cnt, met->unimplemented_cnt, met->filter_reject_cnt,
                  met->lagged_close_cnt, met->lagged_reap_cnt, srv->tx_toobig_cnt,
                  srv->tx_too_slow_refs_cnt, srv->request_error_cnt ));
  FD_LOG_NOTICE(( "updates %lu slots %lu txns %lu statuses %lu blockmeta %lu accounts %lu blocks %lu "
                  "acct_oversize %lu block_oversize %lu degraded %lu cuckoo %lu",
                  met->update_sent_cnt, met->slot_update_cnt, met->txn_update_cnt, met->txn_status_cnt,
                  met->block_meta_sent_cnt, met->acct_update_cnt, met->block_sent_cnt,
                  met->acct_oversize_cnt, met->block_oversize_cnt, met->degrade_cnt,
                  met->cuckoo_filter_cnt ));
  FD_LOG_NOTICE(( "at rest: conns %lu calls %lu subs %lu banks %lu refs_held %lu "
                  "pending %lu buffer banks %lu entries %lu bytes %lu overrun %lu",
                  met->conn_cnt, met->stream_cnt, met->subscription_cnt,
                  fd_geyser_core_bank_cnt( core ), fd_geyser_core_ref_held_cnt( core ),
                  fd_geyser_core_pending_cnt( core ),
                  buf ? fd_dragon_buf_bank_cnt ( buf ) : 0UL,
                  buf ? fd_dragon_buf_entry_cnt( buf ) : 0UL,
                  buf ? fd_dragon_buf_byte_cnt ( buf ) : 0UL,
                  buf ? fd_dragon_buf_metrics( buf )->overrun_cnt : 0UL ));
  FD_LOG_NOTICE(( "refs acquired %lu released %lu unnamed %lu", geyser->ref_acquired_cnt,
                  geyser->ref_released_cnt, geyser->ref_unnamed_cnt ));
  FD_LOG_NOTICE(( "core incomplete by reason: none %lu pending %lu dropped %lu records %lu sysvars %lu gap %lu",
                  geyser->bank_incomplete_cnt[ 0 ], geyser->bank_incomplete_cnt[ 1 ],
                  geyser->bank_incomplete_cnt[ 2 ], geyser->bank_incomplete_cnt[ 3 ],
                  geyser->bank_incomplete_cnt[ 4 ], geyser->bank_incomplete_cnt[ 5 ] ));
  FD_LOG_NOTICE(( "core: banks %lu sealed %lu txn_records %lu write_records %lu dropped %lu "
                  "pending %lu timeout %lu dropped_pending %lu accounts %lu",
                  geyser->bank_created_cnt, geyser->bank_sealed_cnt, geyser->txn_record_cnt,
                  geyser->write_record_cnt, geyser->record_dropped_cnt, geyser->bank_pending_cnt,
                  geyser->pending_timeout_cnt, geyser->pending_dropped_cnt, geyser->account_cnt ));

  /* The invariants a soak is run to check */
  FD_TEST( !met->conn_cnt );
  FD_TEST( !met->stream_cnt );
  FD_TEST( !met->subscription_cnt );
  FD_TEST( !fd_geyser_core_ref_held_cnt( core ) );
  FD_TEST( geyser->ref_acquired_cnt==geyser->ref_released_cnt );
  for( ulong i=0UL; i<TEST_BANK_IDX_MAX; i++ ) FD_TEST( !test_refcnt[ i ] );
  if( buf ) {
    FD_TEST( !fd_dragon_buf_entry_cnt( buf ) );
    FD_TEST( !fd_dragon_buf_byte_cnt ( buf ) );
  }

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
