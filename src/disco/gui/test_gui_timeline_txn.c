#include "fd_gui.h"
#include "fd_gui_printf.h"
#include "../../ballet/json/fd_jtok.h"
#include "../../waltz/http/fd_http_server_private.h"
#include <stdlib.h>
#include <unistd.h>

/* Exercise the public producer and query paths against a real history
   store and HTTP staging buffer, without starting validator tiles. */

typedef struct {
  char const * ptr;
  ulong        sz;
} json_t;

static json_t
field( json_t       json,
       char const * name ) {
  fd_jtok_t j[1]; fd_jtok_init( j, json.ptr, json.sz );
  fd_jtok_str_t key;
  json_t result = {0};
  fd_jtok_obj_enter( j );
  while( fd_jtok_obj_next( j, &key ) ) {
    if( fd_jtok_str_eq( &key, name ) ) fd_jtok_raw( j, &result.ptr, &result.sz );
  }
  FD_TEST( !fd_jtok_fini( j ) );
  return result;
}

static json_t
element( json_t json,
         ulong  index ) {
  fd_jtok_t j[1]; fd_jtok_init( j, json.ptr, json.sz );
  json_t result = {0};
  ulong i = 0UL;
  fd_jtok_arr_enter( j );
  while( fd_jtok_arr_next( j ) ) {
    if( i++==index ) { fd_jtok_raw( j, &result.ptr, &result.sz ); return result; }
  }
  FD_TEST( 0 );
  return result;
}

static ulong
count( json_t json ) {
  fd_jtok_t j[1]; fd_jtok_init( j, json.ptr, json.sz );
  ulong n = 0UL;
  fd_jtok_arr_enter( j );
  while( fd_jtok_arr_next( j ) ) n++;
  FD_TEST( !fd_jtok_fini( j ) );
  return n;
}

static int
is_null( json_t json ) {
  fd_jtok_t j[1]; fd_jtok_init( j, json.ptr, json.sz );
  return fd_jtok_peek( j )==FD_JTOK_NULL;
}

static ulong
number( json_t json ) {
  fd_jtok_t j[1]; fd_jtok_init( j, json.ptr, json.sz );
  ulong value = 0UL;
  fd_jtok_ulong( j, &value );
  FD_TEST( !fd_jtok_fini( j ) );
  return value;
}

static int
string_eq( json_t       json,
           char const * expected ) {
  fd_jtok_t j[1]; fd_jtok_init( j, json.ptr, json.sz );
  fd_jtok_str_t value;
  fd_jtok_str( j, &value );
  FD_TEST( !fd_jtok_fini( j ) );
  return fd_jtok_str_eq( &value, expected );
}

/* Response slices remain valid until the next HTTP staging write. */
static json_t
query( fd_gui_t *   gui,
       char const * key,
       long         start,
       long         end ) {
  int states = !strcmp( key, "query_tile_states" );
  FD_TEST( !(states ? fd_gui_printf_timeline_query_tile_states( gui, start, end, 0, 7UL )
                    : fd_gui_printf_timeline_query_txn_meta( gui, start, end, 7UL )) );
  FD_TEST( !gui->http->stage_err );
  ulong len = fd_http_server_stage_len( gui->http );
  FD_TEST( len && len<(32UL<<20) && gui->http->stage_off%gui->http->oring_sz+len<=gui->http->oring_sz );
  json_t json = { (char const *)gui->http->oring+gui->http->stage_off%gui->http->oring_sz, len };
  FD_TEST( string_eq( field( json, "topic" ), "timeline" ) );
  FD_TEST( string_eq( field( json, "key" ), key ) );
  FD_TEST( number( field( json, "id" ) )==7UL );
  fd_http_server_stage_trunc( gui->http, 0UL );
  return json;
}

static void
test_requests( fd_gui_t * gui ) {
  char const * invalid[] = {
    "{}",
    "{\"start_ns\":\"0\",\"end_ns\":\"1\"}",
    "{\"start_ns\":\"01\",\"end_ns\":\"2\",\"granularity\":\"txn\"}",
    "{\"start_ns\":\"-1\",\"end_ns\":\"2\",\"granularity\":\"txn\"}",
    "{\"start_ns\":0,\"end_ns\":\"2\",\"granularity\":\"txn\"}",
    "{\"start_ns\":\"0\",\"end_ns\":\"9223372036854775807\",\"granularity\":\"txn\"}",
    "{\"start_ns\":\"0\",\"end_ns\":\"9223372036854775808\",\"granularity\":\"txn\"}",
    "{\"start_ns\":\"2\",\"end_ns\":\"2\",\"granularity\":\"txn\"}",
    "{\"start_ns\":\"3\",\"end_ns\":\"2\",\"granularity\":\"txn\"}",
    "{\"start_ns\":\"0\",\"end_ns\":\"1\",\"granularity\":\"shred\"}",
    "{\"start_ns\":\"0\",\"end_ns\":\"1\",\"granularity\":1}"
  };
  for( ulong i=0UL; i<sizeof(invalid)/sizeof(invalid[0]); i++ ) {
    char request[512];
    fd_cstr_printf_check( request, sizeof(request), NULL,
      "{\"id\":7,\"topic\":\"timeline\",\"key\":\"query_tile_states\",\"params\":%s}", invalid[i] );
    FD_TEST( fd_gui_ws_message( gui, 0UL, (uchar const *)request, strlen(request) )==FD_HTTP_SERVER_CONNECTION_CLOSE_BAD_REQUEST );
    FD_TEST( !fd_http_server_stage_len( gui->http ) );
  }
  char const * valid[] = {
    "{\"id\":7,\"topic\":\"timeline\",\"key\":\"query_tile_states\",\"params\":{\"start_ns\":\"0\",\"end_ns\":\"1\",\"granularity\":\"txn\"}}",
    "{\"id\":7,\"topic\":\"timeline\",\"key\":\"query_tile_states\",\"params\":{\"start_ns\":\"0\",\"end_ns\":\"1\",\"granularity\":\"txn_batch\"}}",
    "{\"id\":7,\"topic\":\"timeline\",\"key\":\"query_txn_meta\",\"params\":{\"start_ns\":\"0\",\"end_ns\":\"1\"}}",
    "{\"id\":7,\"topic\":\"timeline\",\"key\":\"query_slots\",\"params\":{\"start_ns\":\"0\",\"end_ns\":\"1\"}}"
  };
  for( ulong i=0UL; i<sizeof(valid)/sizeof(valid[0]); i++ ) {
    FD_TEST( !fd_gui_ws_message( gui, 0UL, (uchar const *)valid[i], strlen(valid[i]) ) );
  }
  /* query_txn_meta and query_slots validate their window like the rest. */
  char const * bad[] = {
    "{\"id\":7,\"topic\":\"timeline\",\"key\":\"query_txn_meta\",\"params\":{\"start_ns\":\"2\",\"end_ns\":\"2\"}}",
    "{\"id\":7,\"topic\":\"timeline\",\"key\":\"query_slots\",\"params\":{\"start_ns\":\"0\",\"end_ns\":\"9223372036854775807\"}}"
  };
  for( ulong i=0UL; i<sizeof(bad)/sizeof(bad[0]); i++ ) {
    FD_TEST( fd_gui_ws_message( gui, 0UL, (uchar const *)bad[i], strlen(bad[i]) )==FD_HTTP_SERVER_CONNECTION_CLOSE_BAD_REQUEST );
  }
  /* query_txn_timestamps was renamed to query_tile_states. */
  char const * old = "{\"id\":7,\"topic\":\"timeline\",\"key\":\"query_txn_timestamps\",\"params\":{\"start_ns\":\"0\",\"end_ns\":\"1\",\"granularity\":\"txn\"}}";
  FD_TEST( fd_gui_ws_message( gui, 0UL, (uchar const *)old, strlen(old) )==FD_HTTP_SERVER_CONNECTION_CLOSE_UNKNOWN_METHOD );
}

static void
test_timestamps( fd_gui_t * gui ) {
  json_t value = field( query( gui, "query_txn_meta", 0L, 1L ), "value" );
  FD_TEST( !count( field( value, "txn_idx" ) ) );
  FD_TEST( is_null( field( value, "reference_slot" ) ) && is_null( field( value, "reference_ts" ) ) );
  FD_TEST( is_null( field( value, "available_start_ns" ) ) && is_null( field( value, "available_end_ns" ) ) );

  /* A later sigverify completion selects the row, even when commit has
     already finished.  The insertion index needs its one-second margin. */
  long const ts = 10000000000L;
  fd_gui_store_replay_txn_t rec = {
    .insert_time_ns=ts+500000000L, .completion_time_ns=ts+20L, .slot=100UL, .txn_idx=3UL,
    .txn_exec_idx=1UL, .txn_sigverify_exec_idx=2UL,
    .sigverify_start_ns=ts, .sigverify_end_ns=ts+20L, .load_start_ns=ts+1L,
    .check_start_ns=LONG_MAX, .exec_start_ns=LONG_MAX, .commit_start_ns=LONG_MAX, .commit_end_ns=ts+10L,
    .error_code=9U
  };
  FD_TEST( !fd_gui_hist_ts_append( gui, FD_GUI_HIST_REPLAY_TXN, &rec ) );
  value = field( query( gui, "query_txn_meta", ts+19L, ts+20L ), "value" );
  FD_TEST( !count( field( value, "txn_idx" ) ) );
  value = field( query( gui, "query_txn_meta", ts+20L, ts+21L ), "value" );
  FD_TEST( count( field( value, "txn_idx" ) )==1UL );
  FD_TEST( string_eq( field( value, "reference_ts" ), "10000000000" ) );
  FD_TEST( string_eq( field( value, "available_start_ns" ), "9500000000" ) );
  FD_TEST( string_eq( field( value, "available_end_ns" ), "11500000001" ) );
  FD_TEST( string_eq( element( field( value, "txn_load_start_ts_delta" ), 0UL ), "1" ) );
  FD_TEST( string_eq( element( field( value, "txn_commit_end_ts_delta" ), 0UL ), "10" ) );
  FD_TEST( number( element( field( value, "txn_error_code" ), 0UL ) )==9UL );

  /* The same row as states: tile 1 loads over [1,10), tile 2
     sigverifies over [0,20), within a [0,21) window. */
  gui->tile_state.exec_cnt = 3UL;
  gui->tile_state.pos_cnt  = 3UL;
  value = field( query( gui, "query_tile_states", ts, ts+21L ), "value" );
  FD_TEST( string_eq( field( value, "granularity" ), "txn" ) );
  FD_TEST( string_eq( field( value, "start_ts" ), "10000000000" ) );
  ulong const states[] = { FD_GUI_TILE_STATE_IDLE, FD_GUI_TILE_STATE_IDLE, FD_GUI_TILE_STATE_LOADING, FD_GUI_TILE_STATE_IDLE,
                           FD_GUI_TILE_STATE_SIGVERIFY, FD_GUI_TILE_STATE_IDLE };
  ulong const durs[]   = { 21UL, 1UL, 9UL, 11UL, 20UL, 1UL };
  FD_TEST( count( field( value, "state" ) )==6UL );
  for( ulong i=0UL; i<6UL; i++ ) {
    FD_TEST( number( element( field( value, "state" ), i ) )==states[ i ] );
    FD_TEST( number( element( field( value, "dur" ), i ) )==durs[ i ] );
  }
  FD_TEST( number( element( field( value, "txn_error_code" ), 0UL ) )==9UL );
  FD_TEST( is_null( element( field( value, "txn_error_code" ), 1UL ) ) );
  gui->tile_state.exec_cnt = 0UL;
  gui->tile_state.pos_cnt  = 0UL;

  rec.slot = 99UL; rec.txn_idx = 8UL;
  FD_TEST( !fd_gui_hist_ts_append( gui, FD_GUI_HIST_REPLAY_TXN, &rec ) );
  rec.slot = 100UL; rec.txn_idx = 1UL;
  FD_TEST( !fd_gui_hist_ts_append( gui, FD_GUI_HIST_REPLAY_TXN, &rec ) );
  value = field( query( gui, "query_txn_meta", ts+20L, ts+21L ), "value" );
  FD_TEST( number( field( value, "reference_slot" ) )==99UL );
  ulong expected[] = {8UL, 1UL, 3UL};
  for( ulong i=0UL; i<3UL; i++ ) {
    FD_TEST( number( element( field( value, "txn_idx" ), i ) )==expected[i] );
    FD_TEST( number( element( field( value, "slot_delta" ), i ) )==!!i );
  }

  /* Replay producer: stages that were never reached remain null. */
  long const now  = 20000000000L;
  long const tick = fd_tickcount();
  gui->tick_per_ns = 1e30; /* deterministic sub-nanosecond tick offsets */
  fd_replay_txn_executed_t executed = {
    .slot=101UL, .exec_tile_idx=3UL, .sigverify_exec_tile_idx=4UL, .index_in_slot=5UL,
    .tick_sigverify_disp=tick, .tick_sigverify_done=tick, .tick_load_start=tick,
    .tick_check_start=LONG_MAX, .tick_exec_start=LONG_MAX, .tick_commit_start=LONG_MAX, .tick_commit_end=tick,
    .txn_err=-9
  };
  /* Minimal parsed legacy transaction: one signature, one account. */
  executed.txn->payload[0] = 1U; executed.txn->payload[65] = 1U; executed.txn->payload[68] = 1U;
  executed.txn->payload_sz = 134U;
  FD_TEST( fd_txn_parse( executed.txn->payload, executed.txn->payload_sz, TXN( executed.txn ), NULL ) );
  fd_gui_handle_replay_txn( gui, &executed, now );
  executed.tick_commit_end = LONG_MAX;
  fd_gui_handle_replay_txn( gui, &executed, now );
  value = field( query( gui, "query_txn_meta", now, now+1L ), "value" );
  FD_TEST( count( field( value, "txn_idx" ) )==1UL );
  FD_TEST( number( element( field( value, "txn_exec_idx" ), 0UL ) )==3UL );
  FD_TEST( number( element( field( value, "txn_sigverify_exec_idx" ), 0UL ) )==4UL );
  FD_TEST( number( element( field( value, "txn_error_code" ), 0UL ) )==9UL );

  /* Leader rows come from execle, use pack indices and have no sigverify. */
  fd_txn_p_t txn = *executed.txn;
  txn.flags = FD_TXN_P_FLAGS_EXECUTE_SUCCESS | (200U<<24);
  fd_txn_ns_dt_t dt = { .load_start=10.4f, .check_start=20.6f, .exec_start=30.4f, .commit_start=60.6f, .commit_end=100.4f };
  long const leader_now = 30000000000L;
  fd_gui_microblock_execution_end( gui, leader_now, 3UL, 500UL, 1UL, &txn, 17UL, dt, tick, 0UL, 7UL, leader_now );
  txn.flags = 0U;
  fd_gui_microblock_execution_end( gui, leader_now, 3UL, 500UL, 1UL, &txn, 18UL, dt, tick, 0UL, 7UL, leader_now );
  txn.flags = FD_TXN_P_FLAGS_EXECUTE_SUCCESS;
  fd_gui_microblock_execution_end( gui, leader_now, 3UL, 500UL, 1UL, &txn, 19UL, dt, LONG_MAX, 0UL, 7UL, leader_now );
  value = field( query( gui, "query_txn_meta", leader_now, leader_now+1L ), "value" );
  FD_TEST( count( field( value, "txn_idx" ) )==1UL );
  FD_TEST( number( element( field( value, "txn_idx" ), 0UL ) )==17UL );
  FD_TEST( number( element( field( value, "txn_error_code" ), 0UL ) )==200UL );
  FD_TEST( is_null( element( field( value, "txn_sigverify_exec_idx" ), 0UL ) ) );
  FD_TEST( string_eq( field( value, "reference_ts" ), "29999999910" ) );
  FD_TEST( string_eq( element( field( value, "txn_commit_end_ts_delta" ), 0UL ), "90" ) );
  /* query_tile_states skips leader rows. */
  value = field( query( gui, "query_tile_states", leader_now-100L, leader_now+1L ), "value" );
  FD_TEST( !count( field( value, "txn_idx" ) ) && is_null( field( value, "reference_slot" ) ) );
}

static void
test_limit( fd_gui_t * gui ) {
  long const ts = 40000000000L;
  fd_gui_store_replay_txn_t txn = { .insert_time_ns=ts, .completion_time_ns=ts, .slot=100UL, .load_start_ns=ts, .commit_end_ns=ts };
  for( ulong i=0UL; i<FD_GUI_TIMELINE_QUERY_TXN_MAX; i++ ) {
    txn.txn_idx = i;
    FD_TEST( !fd_gui_hist_ts_append( gui, FD_GUI_HIST_REPLAY_TXN, &txn ) );
  }
  json_t json = query( gui, "query_txn_meta", ts, ts+1L );
  FD_TEST( count( field( field( json, "value" ), "txn_idx" ) )==FD_GUI_TIMELINE_QUERY_TXN_MAX );
  FD_TEST( !fd_gui_hist_ts_append( gui, FD_GUI_HIST_REPLAY_TXN, &txn ) );
  for( int states=0; states<2; states++ ) {
    json = query( gui, states ? "query_tile_states" : "query_txn_meta", ts, ts+1L );
    FD_TEST( !field( json, "value" ).ptr );
    FD_TEST( string_eq( field( field( json, "error" ), "code" ), "result_limit_exceeded" ) );
  }
}

int
main( int argc, char ** argv ) {
  fd_boot( &argc, &argv );
  fd_gui_t * gui = aligned_alloc( fd_gui_align(), fd_gui_footprint( 1UL, 1UL, 1UL ) );
  FD_TEST( gui );
  memset( gui, 0, fd_gui_footprint( 1UL, 1UL, 1UL ) );
  char path[128];
  fd_cstr_printf_check( path, sizeof(path), NULL, "/tmp/fd_gui_timeline_txn.%i", (int)getpid() );
  ulong bytes = 5UL<<30;
  fd_gui_store_desc_t const * descs = fd_gui_hist_db_descs( bytes, 1UL );
  void * db_mem = aligned_alloc( fd_gui_store_align(), fd_ulong_align_up( fd_gui_store_footprint( bytes, FD_GUI_HIST_CNT, descs ), fd_gui_store_align() ) );
  FD_TEST( db_mem );
  gui->db = fd_gui_store_join( fd_gui_store_new( db_mem, path, bytes, FD_GUI_HIST_CNT, 0UL, descs ) );
  FD_TEST( gui->db );
  void * hist_mem = aligned_alloc( fd_gui_hist_align(), fd_ulong_align_up( fd_gui_hist_footprint(), fd_gui_hist_align() ) );
  FD_TEST( hist_mem );
  gui->hist = fd_gui_hist_join( fd_gui_hist_new( hist_mem, gui->db ) );
  FD_TEST( gui->hist );
  fd_http_server_params_t params = {
    .max_connection_cnt=1UL, .max_ws_connection_cnt=1UL, .max_request_len=1024UL,
    .max_ws_recv_frame_len=1024UL, .max_ws_send_frame_cnt=4UL, .outgoing_buffer_sz=FD_GUI_HTTP_MIN_SEND_BUFFER_SZ
  };
  void * http_mem = aligned_alloc( fd_http_server_align(), fd_http_server_footprint( params ) );
  FD_TEST( http_mem );
  gui->http = fd_http_server_join( fd_http_server_new( http_mem, params, (fd_http_server_callbacks_t){0}, NULL ) );
  FD_TEST( gui->http );
  test_requests( gui );
  test_timestamps( gui );
  test_limit( gui );
  fd_http_server_delete( fd_http_server_leave( gui->http ) );
  fd_gui_hist_delete( fd_gui_hist_leave( gui->hist ) );
  fd_gui_store_delete( fd_gui_store_leave( gui->db ) );
  FD_TEST( !unlink( path ) );
  free( http_mem ); free( hist_mem ); free( db_mem ); free( gui );
  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
