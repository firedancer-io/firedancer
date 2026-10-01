/* fuzz_dragon_rpc.c drives the whole serving path with arbitrary
   client bytes: HTTP/2 framing, gRPC message framing, the
   SubscribeRequest decoder, and the account and transaction fan-out
   that an installed subscription runs.  The other fuzzers stop short
   of this composition: fuzz_grpc_server drives a toy application, and
   fuzz_dragon_filter stops at the decoder and never delivers a
   record through the filters it decodes.

   The connection preface and a Subscribe field block are supplied, so
   the input is spent on request messages and frames rather than on
   rediscovering HPACK. */

#if !FD_HAS_HOSTED
#error "This target requires FD_HAS_HOSTED"
#endif

#include <assert.h>
#include <stdlib.h>

#include "fd_dragon_rpc.h"
#include "fd_geyser_core.h"
#include "../../waltz/grpc/fd_grpc_server_private.h"
#include "../../util/fd_util.h"

#define FUZZ_BANK_IDX_MAX (8UL)

static FD_TL fd_rng_t g_rng[1];

static uchar g_server_mem[ 8UL<<20 ] __attribute__((aligned(FD_GRPC_SERVER_ALIGN)));
static uchar g_rpc_mem   [ 8UL<<20 ] __attribute__((aligned(FD_DRAGON_RPC_ALIGN)));
static uchar g_core_mem  [ 4UL<<20 ] __attribute__((aligned(FD_GEYSER_CORE_ALIGN)));

#define FUZZ_BUF_DEPTH (1024UL)
#define FUZZ_BUF_BYTES (1UL<<20)

static uchar g_buf_mcache_mem[ 64UL<<10 ] __attribute__((aligned(FD_MCACHE_ALIGN)));
static uchar g_buf_dcache_mem[  2UL<<20 ] __attribute__((aligned(FD_DCACHE_ALIGN)));

static fd_dragon_rpc_t *  g_rpc;
static fd_geyser_core_t * g_core;
static uchar              g_read_owner[ 32 ];
static uchar              g_read_data [ 512 ];

static void
fuzz_release( void * ctx,
              ulong  bank_idx,
              ulong  seq_bound ) {
  (void)ctx; (void)seq_bound;
  assert( bank_idx<FUZZ_BANK_IDX_MAX );
}

/* Every account reads back the same way, so a divergence is the
   server's and not the store's. */

static int
fuzz_read_account( void *                ctx,
                   fd_accdb_fork_id_t    fork_id,
                   uchar const *         pubkey,
                   fd_geyser_account_t * out ) {
  (void)ctx; (void)fork_id;
  fd_memset( g_read_owner, 0x60, 32UL );
  fd_memset( g_read_data,  pubkey[ 0 ], sizeof(g_read_data) );
  out->owner      = g_read_owner;
  out->lamports   = 500UL;
  out->executable = 0;
  out->data       = g_read_data;
  out->data_sz    = sizeof(g_read_data);
  return 0;
}

/* fuzz_txn_write commits one transaction that writes one account, so
   that whatever filters the input installed are run against a record
   and the fan-out assembles a message. */

static void
fuzz_txn_write( ulong bank_seq,
                ulong slot,
                ulong index,
                uint  key_byte ) {
  static uchar payload [ 1232 ];
  static uchar keys    [ 3 ][ 32 ];
  static ulong pre     [ 3 ];
  static ulong post    [ 3 ];
  static uchar writable[ 3 ] = { 1, 1, 1 };
  static uchar data    [ 96 ];

  uchar key_bytes[ 3 ] = { 0x20, 0x21, (uchar)key_byte };

  ulong o = 0UL;
  payload[ o++ ] = 1U;
  fd_memset( payload+o, 0xA1, 64UL ); o += 64UL;
  payload[ o++ ] = 1U;
  payload[ o++ ] = 0U;
  payload[ o++ ] = 1U;
  payload[ o++ ] = 3U;
  for( ulong i=0UL; i<3UL; i++ ) { fd_memset( payload+o, key_bytes[ i ], 32UL ); o += 32UL; }
  fd_memset( payload+o, 0x30, 32UL ); o += 32UL;
  payload[ o++ ] = 1U;
  payload[ o++ ] = 2U;
  payload[ o++ ] = 1U;
  payload[ o++ ] = 0U;
  payload[ o++ ] = 1U;
  payload[ o++ ] = 0x77;

  for( ulong i=0UL; i<3UL; i++ ) {
    fd_memset( keys[ i ], key_bytes[ i ], 32UL );
    pre [ i ] = 100UL+i;
    post[ i ] = 100UL+i;
  }
  for( ulong i=0UL; i<sizeof(data); i++ ) data[ i ] = (uchar)i;

  fd_event_internal_commit_touched_t touched[1] = {{
    .key_idx    = 2U,
    .executable = 0U,
    .lamports   = 500UL,
    .data_sz    = sizeof(data)
  }};
  fd_memset( touched[ 0 ].owner, 0x60, 32UL );

  fd_event_internal_commit_t ev[1];
  fd_memset( ev, 0, sizeof(fd_event_internal_commit_t) );
  ev->bank_seq               = bank_seq;
  ev->slot                   = slot;
  ev->index_in_slot          = index;
  ev->commit_index_in_slot   = index;
  ev->accounts_included      = 1;
  ev->exec_err_idx           = UINT_MAX;
  ev->custom_err             = UINT_MAX;
  ev->rent_err_account_idx   = UINT_MAX;
  ev->execution_fee          = 5000UL;
  ev->compute_units_consumed = 1000UL;
  ev->cost_units             = 720UL;
  ev->payload_cnt            = o;
  ev->acct_addr_cnt          = 3U;
  ev->keys_cnt               = 3UL;
  ev->pre_lamports_cnt       = 3UL;
  ev->post_lamports_cnt      = 3UL;
  ev->is_writable_cnt        = 3UL;
  ev->touched_cnt            = 1UL;
  fd_memset( ev->signature, 0xA1, 64UL );

  fd_event_internal_commit_parts_t parts = {
    .prefix        = ev,
    .payload       = payload,
    .keys          = (uchar const (*)[ 32UL ])keys,
    .pre_lamports  = pre,
    .post_lamports = post,
    .is_writable   = writable,
    .logs          = NULL,
    .trace         = NULL,
    .trace_accts   = NULL,
    .trace_data    = NULL,
    .return_data   = NULL,
    .touched       = touched
  };
  fd_geyser_core_commit_record( g_core, &parts );
}


/* Structured request building.  A SubscribeRequest whose numeric
   fields are protobuf varints is out of reach of byte mutation when a
   bug needs an exact relation between two of them, so one mode takes
   those fields straight from the input and encodes a well formed
   request around them. */

static ulong
fuzz_varint( uchar * out,
             ulong   v ) {
  ulong o = 0UL;
  for(;;) {
    uchar b = (uchar)( v & 0x7fUL );
    v >>= 7;
    out[ o++ ] = (uchar)( b | ( v ? 0x80U : 0U ) );
    if( !v ) break;
  }
  return o;
}

static ulong
fuzz_tag( uchar * out,
          uint    field,
          uint    wire ) {
  return fuzz_varint( out, ( (ulong)field<<3 ) | (ulong)wire );
}

static ulong
fuzz_varfld( uchar * out,
             uint    field,
             ulong   v ) {
  ulong o = fuzz_tag( out, field, 0U );
  return o + fuzz_varint( out+o, v );
}

static ulong
fuzz_lenfld( uchar *       out,
             uint          field,
             uchar const * body,
             ulong         body_sz ) {
  ulong o = fuzz_tag( out, field, 2U );
  o += fuzz_varint( out+o, body_sz );
  fd_memcpy( out+o, body, body_sz );
  return o + body_sz;
}

/* fuzz_request encodes one SubscribeRequest driven by the input, and
   returns its size.  Bytes the input does not supply stay zero. */

static ulong
fuzz_request( uchar *       out,
              ulong         out_max,
              uchar const * p,
              ulong         p_sz ) {
  uchar params[ 64 ] = {0};
  fd_memcpy( params, p, fd_ulong_min( p_sz, sizeof(params) ) );

  uchar  kind        = params[ 0 ];
  ulong  slice_off   = FD_LOAD( ulong, params+ 1 );
  ulong  slice_len   = FD_LOAD( ulong, params+ 9 );
  ulong  memcmp_off  = FD_LOAD( ulong, params+17 );
  ulong  memcmp_sz   = (ulong)params[ 25 ] & 0x1fUL;
  ulong  datasize    = FD_LOAD( ulong, params+26 );
  ulong  from_slot   = FD_LOAD( ulong, params+34 );

  uchar  inner[ 256 ]; ulong in_sz = 0UL;
  if( kind & 0x01U ) {
    uchar mc[ 128 ]; ulong mc_sz = 0UL;
    mc_sz += fuzz_varfld( mc+mc_sz, 1U, memcmp_off );
    uchar bytes[ 32 ];
    fd_memset( bytes, 0xab, memcmp_sz );
    mc_sz += fuzz_lenfld( mc+mc_sz, 2U, bytes, memcmp_sz );
    uchar one[ 160 ]; ulong one_sz = fuzz_lenfld( one, 1U, mc, mc_sz );
    in_sz += fuzz_lenfld( inner+in_sz, 4U, one, one_sz );
  }
  if( kind & 0x02U ) {
    uchar one[ 32 ]; ulong one_sz = fuzz_varfld( one, 2U, datasize );
    in_sz += fuzz_lenfld( inner+in_sz, 4U, one, one_sz );
  }

  uchar entry[ 320 ]; ulong e_sz = 0UL;
  uchar name[ 1 ] = { 'a' };
  e_sz += fuzz_lenfld( entry+e_sz, 1U, name, 1UL );
  e_sz += fuzz_lenfld( entry+e_sz, 2U, inner, in_sz );

  ulong o = 0UL;
  uint  map_field = ( kind & 0x04U ) ? 3U : 1U; /* transactions or accounts */
  o += fuzz_lenfld( out+o, map_field, entry, e_sz );

  if( kind & 0x08U ) {
    uchar sl[ 32 ]; ulong sl_sz = 0UL;
    sl_sz += fuzz_varfld( sl+sl_sz, 1U, slice_off );
    sl_sz += fuzz_varfld( sl+sl_sz, 2U, slice_len );
    o += fuzz_lenfld( out+o, 7U, sl, sl_sz );
  }
  if( kind & 0x10U ) o += fuzz_varfld( out+o, 11U, from_slot );
  if( kind & 0x20U ) o += fuzz_varfld( out+o, 5U, (ulong)( params[ 35 ] & 0x07U ) ); /* commitment */

  assert( o<=out_max );
  return o;
}

int
LLVMFuzzerInitialize( int  *   argc,
                      char *** argv ) {
  putenv( "FD_LOG_BACKTRACE=0" );
  setenv( "FD_LOG_PATH", "", 0 );
  fd_boot( argc, argv );
  (void)atexit( fd_halt );
  fd_log_level_core_set(1); /* crash on info log */
  return 0;
}

/* The request the input continues: a Subscribe call whose field block
   is complete but whose stream stays open for request messages. */

#define FUZZ_PATH "/geyser.Geyser/Subscribe"

static uchar const fuzz_hello[] =
  "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
  "\x00\x00\x00\x04\x00\x00\x00\x00\x00"   /* SETTINGS */
  "\x00\x00\x00\x04\x01\x00\x00\x00\x00"   /* SETTINGS ACK */
  "\x00\x00\x68\x01\x04\x00\x00\x00\x01"   /* HEADERS, END_HEADERS, stream 1 */
  "\x00\x07" ":method" "\x04" "POST"
  "\x00\x07" ":scheme" "\x04" "http"
  "\x00\x05" ":path"   "\x18" FUZZ_PATH
  "\x00\x0c" "content-type" "\x10" "application/grpc"
  "\x00\x02" "te" "\x08" "trailers";

FD_STATIC_ASSERT( sizeof(FUZZ_PATH)-1UL==0x18UL, path_len );
FD_STATIC_ASSERT( sizeof(fuzz_hello)-1UL==24UL+9UL+9UL+9UL+0x68UL, hello_len );

int
LLVMFuzzerTestOneInput( uchar const * data,
                        ulong         size ) {
  if( size<4UL ) return -1;
  uint seed = FD_LOAD( uint, data );
  data += 4UL; size -= 4UL;

  fd_rng_t * rng = fd_rng_join( fd_rng_new( g_rng, seed, 0UL ) );
  long now = 1700000000L*1000000000L;

  assert( fd_mcache_footprint( FUZZ_BUF_DEPTH, 0UL )<=sizeof(g_buf_mcache_mem) );
  assert( fd_dcache_footprint( FUZZ_BUF_BYTES, 0UL )<=sizeof(g_buf_dcache_mem) );
  fd_dragon_rpc_params_t rpc_params = {
    .stream_max            = 4UL,
    .ping_interval_nanos   = 10000000000L,
    .x_token               = NULL,
    .finalized             = 1,
    /* Either place the filters run, chosen by the seed */
    .filter_at             = ( seed>>31 ) ? FD_DRAGON_FILTER_AT_SEND : FD_DRAGON_FILTER_AT_INGEST,
    .buf_mcache            = fd_mcache_join( fd_mcache_new( g_buf_mcache_mem, FUZZ_BUF_DEPTH, 0UL, 0UL ) ),
    .buf_dcache            = fd_dcache_join( fd_dcache_new( g_buf_dcache_mem, FUZZ_BUF_BYTES, 0UL ) ),
    .buf_base              = g_buf_dcache_mem,
    .buf_depth             = FUZZ_BUF_DEPTH,
    .bank_max              = 2UL*FUZZ_BANK_IDX_MAX,
    .msg_max_bytes         = 64UL<<10,
    .cuckoo_bytes          = 8UL<<10
  };
  assert( fd_dragon_rpc_footprint( &rpc_params )<=sizeof(g_rpc_mem) );
  g_rpc = fd_dragon_rpc_join( fd_dragon_rpc_new( g_rpc_mem, &rpc_params ) );
  assert( g_rpc );

  fd_grpc_server_params_t params[1];
  fd_grpc_server_params_default( params );
  params->max_conn_cnt       = 1UL;
  params->max_stream_cnt     = 4UL;
  params->max_request_msg_sz = 8192UL;
  params->max_msg_sz         = 64UL<<10;
  /* A ring that holds only a few messages, and a short segment queue,
     so that both ways of falling behind are reachable */
  params->tx_ring_sz         = 3UL*( ( 64UL<<10 )+5UL );
  params->stream_tx_ref_max  = 8UL;
  params->conn_rx_buf_sz     = 32768UL;
  params->conn_tx_buf_sz     = 32768UL;
  params->conn_rx_wnd_sz     = 1UL<<20;
  params->stream_rx_wnd_sz   = 1UL<<20;
  params->idle_timeout_nanos = 0L;
  params->compression        = FD_GRPC_SERVER_COMPRESSION_ZSTD;
  params->compression_min_sz = 1024UL;
  params->compression_level  = 1;
  assert( fd_grpc_server_footprint( params )<=sizeof(g_server_mem) );
  fd_grpc_server_t * server = fd_grpc_server_join(
      fd_grpc_server_new( g_server_mem, params, fd_dragon_rpc_callbacks(), g_rpc ) );
  assert( server );

  fd_geyser_core_params_t core_params = {
    .max_live_banks = FUZZ_BANK_IDX_MAX,
    .records_gate   = 0,
    .release_fn     = fuzz_release,
    .read_fn        = fuzz_read_account
  };
  assert( fd_geyser_core_footprint( &core_params )<=sizeof(g_core_mem) );
  g_core = fd_geyser_core_join( fd_geyser_core_new( g_core_mem, &core_params ) );
  assert( g_core );
  fd_geyser_consumer_t consumer[1];
  assert( !fd_geyser_core_register( g_core, fd_dragon_rpc_consumer( g_rpc, g_core, consumer ) ) );

  fd_dragon_rpc_service( g_rpc, now );
  fd_dragon_rpc_set_serving( g_rpc, 1 );

  fd_grpc_server_conn_t * conn = fd_grpc_server_conn_open_direct( server, now );
  assert( conn );
  assert( fd_grpc_server_conn_push_rx( conn, fuzz_hello, sizeof(fuzz_hello)-1UL, now )==sizeof(fuzz_hello)-1UL );

  /* One in two inputs builds a request out of its leading bytes, so
     that relations between two numeric fields are reachable. */
  if( seed & 1u ) {
    uchar req[ 512 ];
    ulong param_sz = fd_ulong_min( size, 40UL );
    ulong req_sz   = fuzz_request( req, sizeof(req), data, param_sz );
    data += param_sz; size -= param_sz;

    uchar msg[ 640 ];
    ulong o = 0UL;
    msg[ o++ ] = 0x00;
    uint be = fd_uint_bswap( (uint)req_sz );
    fd_memcpy( msg+o, &be, 4UL ); o += 4UL;
    fd_memcpy( msg+o, req, req_sz ); o += req_sz;

    uchar frame[ 640+9 ];
    frame[ 0 ] = (uchar)( ( o>>16 ) & 0xffUL );
    frame[ 1 ] = (uchar)( ( o>> 8 ) & 0xffUL );
    frame[ 2 ] = (uchar)(   o       & 0xffUL );
    frame[ 3 ] = 0x00; /* DATA */
    frame[ 4 ] = 0x00;
    frame[ 5 ] = 0x00; frame[ 6 ] = 0x00; frame[ 7 ] = 0x00; frame[ 8 ] = 0x01;
    fd_memcpy( frame+9, msg, o );
    fd_grpc_server_conn_push_rx( conn, frame, o+9UL, now );

    fd_dragon_rpc_service( g_rpc, now );
    fd_grpc_server_service( server, now );
    static uchar drain0[ 4096 ];
    while( fd_grpc_server_conn_pop_tx( conn, drain0, sizeof(drain0) ) ) {}
  }

  static uchar drain[ 4096 ];
  ulong        record = 0UL;
  while( size && fd_grpc_server_conn_is_open( conn ) ) {
    ulong chunk = fd_ulong_min( size, ( (ulong)fd_rng_uint( rng ) & 255UL )+1UL );
    ulong n     = fd_grpc_server_conn_push_rx( conn, data, chunk, now );
    data += n; size -= n;
    while( fd_grpc_server_conn_pop_tx( conn, drain, sizeof(drain) ) ) {}

    /* Deliver a record, so a subscription the input installed has to
       match it and assemble an update. */
    record++;
    fuzz_txn_write( record, 10UL+record, 0UL, (uint)( fd_rng_uint( rng ) & 0xffU ) );

    now += (long)( fd_rng_uint( rng ) & 0xffffff );
    fd_dragon_rpc_service( g_rpc, now );
    fd_grpc_server_service( server, now );
    while( fd_grpc_server_conn_pop_tx( conn, drain, sizeof(drain) ) ) {}

    if( !n ) break; /* no progress */
  }

  /* Deliver at least one record, so a subscription installed by the
     structured path is exercised even with no input left. */
  record++;
  fuzz_txn_write( record, 10UL+record, 0UL, 0x40U );
  now += 1000000L;
  fd_dragon_rpc_service( g_rpc, now );
  fd_grpc_server_service( server, now );
  while( fd_grpc_server_conn_pop_tx( conn, drain, sizeof(drain) ) ) {}

  if( fd_grpc_server_conn_is_open( conn ) ) fd_grpc_server_conn_close( conn );
  assert( fd_grpc_server_is_idle( server ) );
  assert( !fd_dragon_rpc_metrics( g_rpc )->stream_cnt );

  fd_grpc_server_delete( fd_grpc_server_leave( server ) );
  fd_rng_delete( fd_rng_leave( rng ) );
  return 0;
}
