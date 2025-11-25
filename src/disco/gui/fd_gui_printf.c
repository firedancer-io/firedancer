#include <ctype.h>
#include <stdio.h>

#include "fd_gui_printf.h"

#include "../../waltz/http/fd_http_server_private.h"
#include "../../ballet/utf8/fd_utf8.h"
#include "../../disco/fd_txn_m_t.h"

#ifdef __has_include
#if __has_include("../../app/fdctl/version.h")
#include "../../app/fdctl/version.h"
#endif
#endif

#ifndef FDCTL_COMMIT_REF_CSTR
#define FDCTL_COMMIT_REF_CSTR "0000000000000000000000000000000000000000"
#endif

static void
jsonp_strip_trailing_comma( fd_gui_t * gui ) {
  if( FD_LIKELY( !gui->http->stage_err &&
                 gui->http->stage_len>=1UL &&
                 gui->http->oring[ (gui->http->stage_off%gui->http->oring_sz)+gui->http->stage_len-1UL ]==(uchar)',' ) ) {
    gui->http->stage_len--;
  }
}

static void
jsonp_open_object( fd_gui_t *   gui,
                   char const * key ) {
  if( FD_LIKELY( key ) ) fd_http_server_printf( gui->http, "\"%s\":{", key );
  else                   fd_http_server_printf( gui->http, "{" );
}

static void
jsonp_close_object( fd_gui_t * gui ) {
  jsonp_strip_trailing_comma( gui );
  fd_http_server_printf( gui->http, "}," );
}

static void
jsonp_open_array( fd_gui_t *   gui,
                  char const * key ) {
  if( FD_LIKELY( key ) ) fd_http_server_printf( gui->http, "\"%s\":[", key );
  else                   fd_http_server_printf( gui->http, "[" );
}

static void
jsonp_close_array( fd_gui_t * gui ) {
  jsonp_strip_trailing_comma( gui );
  fd_http_server_printf( gui->http, "]," );
}

static void
jsonp_ulong( fd_gui_t *   gui,
             char const * key,
             ulong        value ) {
  if( FD_LIKELY( key ) ) fd_http_server_printf( gui->http, "\"%s\":%lu,", key, value );
  else                   fd_http_server_printf( gui->http, "%lu,", value );
}

static void
jsonp_long( fd_gui_t *   gui,
            char const * key,
            long         value ) {
  if( FD_LIKELY( key ) ) fd_http_server_printf( gui->http, "\"%s\":%ld,", key, value );
  else                   fd_http_server_printf( gui->http, "%ld,", value );
}

static void
jsonp_double( fd_gui_t *   gui,
              char const * key,
              double       value ) {
  if( FD_LIKELY( key ) ) fd_http_server_printf( gui->http, "\"%s\":%.2f,", key, value );
  else                   fd_http_server_printf( gui->http, "%.2f,", value );
}

static void
jsonp_ulong_as_str( fd_gui_t *   gui,
                    char const * key,
                    ulong        value ) {
  if( FD_LIKELY( key ) ) fd_http_server_printf( gui->http, "\"%s\":\"%lu\",", key, value );
  else                   fd_http_server_printf( gui->http, "\"%lu\",", value );
}

static void
jsonp_long_as_str( fd_gui_t *   gui,
                   char const * key,
                   long         value ) {
  if( FD_LIKELY( key ) ) fd_http_server_printf( gui->http, "\"%s\":\"%ld\",", key, value );
  else                   fd_http_server_printf( gui->http, "\"%ld\",", value );
}

static void
jsonp_sanitize_str( fd_http_server_t * http,
                    ulong              start_len ) {
  /* escape quotemark, reverse solidus, and control chars U+0000 through U+001F
     just replace with a space */
  uchar * data = http->oring;
  for( ulong i=start_len; i<http->stage_len; i++ ) {
    if( FD_UNLIKELY( data[ (http->stage_off%http->oring_sz)+i ] < 0x20 ||
                     data[ (http->stage_off%http->oring_sz)+i ] == '"' ||
                     data[ (http->stage_off%http->oring_sz)+i ] == '\\' ) ) {
      data[ (http->stage_off%http->oring_sz)+i ] = ' ';
    }
  }
}

static void
jsonp_string( fd_gui_t *   gui,
              char const * key,
              char const * value ) {
  char * val = (void *)value;
  if( FD_LIKELY( value ) ) {
    if( FD_UNLIKELY( !fd_utf8_verify( value, strlen( value ) ) )) {
      val = NULL;
    }
  }
  if( FD_LIKELY( key ) ) fd_http_server_printf( gui->http, "\"%s\":", key );
  if( FD_LIKELY( val ) ) {
    fd_http_server_printf( gui->http, "\"" );
    ulong start_len = gui->http->stage_len;
    fd_http_server_printf( gui->http, "%s", val );
    jsonp_sanitize_str( gui->http, start_len );
    fd_http_server_printf( gui->http, "\"," );
  } else {
    fd_http_server_printf( gui->http, "null," );
  }
}

static void
jsonp_bool( fd_gui_t *   gui,
            char const * key,
            int          value ) {
  if( FD_LIKELY( key ) ) fd_http_server_printf( gui->http, "\"%s\":%s,", key, value ? "true" : "false" );
  else                   fd_http_server_printf( gui->http, "%s,", value ? "true" : "false" );
}

static void
jsonp_null( fd_gui_t *   gui,
            char const * key ) {
  if( FD_LIKELY( key ) ) fd_http_server_printf( gui->http, "\"%s\": null,", key );
  else                   fd_http_server_printf( gui->http, "null," );
}

static void
jsonp_open_envelope( fd_gui_t *   gui,
                     char const * topic,
                     char const * key ) {
  jsonp_open_object( gui, NULL );
  jsonp_string( gui, "topic", topic );
  jsonp_string( gui, "key",   key );
}

static void
jsonp_close_envelope( fd_gui_t * gui ) {
  jsonp_close_object( gui );
  jsonp_strip_trailing_comma( gui );
}

void
fd_gui_printf_open_query_response_envelope( fd_gui_t *   gui,
                                            char const * topic,
                                            char const * key,
                                            ulong        id ) {
  jsonp_open_object( gui, NULL );
  jsonp_string( gui, "topic", topic );
  jsonp_string( gui, "key", key );
  jsonp_ulong( gui, "id", id );
}

void
fd_gui_printf_close_query_response_envelope( fd_gui_t * gui ) {
  jsonp_close_object( gui );
  jsonp_strip_trailing_comma( gui );
}

void
fd_gui_printf_null_query_response( fd_gui_t *   gui,
                                   char const * topic,
                                   char const * key,
                                   ulong        id ) {
  fd_gui_printf_open_query_response_envelope( gui, topic, key, id );
    jsonp_null( gui, "value" );
  fd_gui_printf_close_query_response_envelope( gui );
}

void
fd_gui_printf_version( fd_gui_t * gui ) {
  jsonp_open_envelope( gui, "summary", "version" );
    jsonp_string( gui, "value", gui->summary.version );
  jsonp_close_envelope( gui );
}

void
fd_gui_printf_cluster( fd_gui_t * gui ) {
  jsonp_open_envelope( gui, "summary", "cluster" );
    jsonp_string( gui, "value", gui->summary.cluster );
  jsonp_close_envelope( gui );
}

void
fd_gui_printf_commit_hash( fd_gui_t * gui ) {
  jsonp_open_envelope( gui, "summary", "commit_hash" );
    jsonp_string( gui, "value", FDCTL_COMMIT_REF_CSTR );
  jsonp_close_envelope( gui );
}

void
fd_gui_printf_identity_key( fd_gui_t * gui ) {
  jsonp_open_envelope( gui, "summary", "identity_key" );
    jsonp_string( gui, "value", gui->summary.identity_key_base58 );
  jsonp_close_envelope( gui );
}

void
fd_gui_printf_vote_key( fd_gui_t * gui ) {
  jsonp_open_envelope( gui, "summary", "vote_key" );
    if( FD_LIKELY( gui->summary.has_vote_key ) ) jsonp_string( gui, "value", gui->summary.vote_key_base58 );
    else                                         jsonp_null( gui, "value" );
  jsonp_close_envelope( gui );
}

void
fd_gui_printf_startup_time_nanos( fd_gui_t * gui ) {
  jsonp_open_envelope( gui, "summary", "startup_time_nanos" );
    jsonp_long_as_str( gui, "value", gui->summary.startup_time_nanos );
  jsonp_close_envelope( gui );
}

void
fd_gui_printf_vote_distance( fd_gui_t * gui ) {
  jsonp_open_envelope( gui, "summary", "vote_distance" );
    jsonp_ulong( gui, "value", gui->summary.vote_distance );
  jsonp_close_envelope( gui );
}


void
fd_gui_printf_vote_state( fd_gui_t * gui ) {
  jsonp_open_envelope( gui, "summary", "vote_state" );
    switch( gui->summary.vote_state ) {
      case FD_GUI_VOTE_STATE_NON_VOTING:
        jsonp_string( gui, "value", "non-voting" );
        break;
      case FD_GUI_VOTE_STATE_VOTING:
        jsonp_string( gui, "value", "voting" );
        break;
      case FD_GUI_VOTE_STATE_DELINQUENT:
        jsonp_string( gui, "value", "delinquent" );
        break;
      default:
        FD_LOG_ERR(( "unknown vote state %d", gui->summary.vote_state ));
    }
  jsonp_close_envelope( gui );
}

void
fd_gui_printf_skipped_history( fd_gui_t * gui ) {
  jsonp_open_envelope( gui, "slot", "skipped_history" );
    jsonp_open_array( gui, "value" );
      for( ulong i=0UL; i<fd_ulong_min( gui->summary.slot_completed+1, FD_GUI_SLOTS_CNT ); i++ ) {
        ulong _slot = gui->summary.slot_completed-i;
        fd_gui_slot_t * slot = gui->slots[ _slot % FD_GUI_SLOTS_CNT ];

        if( FD_UNLIKELY( slot->slot!=_slot ) ) break;
        if( FD_UNLIKELY( slot->mine && slot->skipped ) ) jsonp_ulong( gui, NULL, slot->slot );
      }
    jsonp_close_array( gui );
  jsonp_close_envelope( gui );
}

void
fd_gui_printf_tps_history( fd_gui_t * gui ) {
  jsonp_open_envelope( gui, "summary", "tps_history" );
    jsonp_open_array( gui, "value" );

    for( ulong i=0UL; i<FD_GUI_TPS_HISTORY_SAMPLE_CNT; i++ ) {
      ulong idx = (gui->summary.estimated_tps_history_idx+i) % FD_GUI_TPS_HISTORY_SAMPLE_CNT;
      jsonp_open_array( gui, NULL );
        jsonp_double( gui, NULL, (double)gui->summary.estimated_tps_history[ idx ][ 0 ]/(double)FD_GUI_TPS_HISTORY_WINDOW_DURATION_SECONDS );
        jsonp_double( gui, NULL, (double)gui->summary.estimated_tps_history[ idx ][ 1 ]/(double)FD_GUI_TPS_HISTORY_WINDOW_DURATION_SECONDS );
        jsonp_double( gui, NULL, (double)(gui->summary.estimated_tps_history[ idx ][ 0 ] - gui->summary.estimated_tps_history[ idx ][ 1 ] - gui->summary.estimated_tps_history[ idx ][ 2 ])/(double)FD_GUI_TPS_HISTORY_WINDOW_DURATION_SECONDS );
        jsonp_double( gui, NULL, (double)gui->summary.estimated_tps_history[ idx ][ 2 ]/(double)FD_GUI_TPS_HISTORY_WINDOW_DURATION_SECONDS );
      jsonp_close_array( gui );
    }

    jsonp_close_array( gui );
  jsonp_close_envelope( gui );
}

void
fd_gui_printf_startup_progress( fd_gui_t * gui ) {
  char const * phase;

  switch( gui->summary.startup_progress ) {
    case FD_GUI_START_PROGRESS_TYPE_INITIALIZING:
      phase = "initializing";
      break;
    case FD_GUI_START_PROGRESS_TYPE_SEARCHING_FOR_FULL_SNAPSHOT:
      phase = "searching_for_full_snapshot";
      break;
    case FD_GUI_START_PROGRESS_TYPE_DOWNLOADING_FULL_SNAPSHOT:
      phase = "downloading_full_snapshot";
      break;
    case FD_GUI_START_PROGRESS_TYPE_SEARCHING_FOR_INCREMENTAL_SNAPSHOT:
      phase = "searching_for_incremental_snapshot";
      break;
    case FD_GUI_START_PROGRESS_TYPE_DOWNLOADING_INCREMENTAL_SNAPSHOT:
      phase = "downloading_incremental_snapshot";
      break;
    case FD_GUI_START_PROGRESS_TYPE_CLEANING_BLOCK_STORE:
      phase = "cleaning_blockstore";
      break;
    case FD_GUI_START_PROGRESS_TYPE_CLEANING_ACCOUNTS:
      phase = "cleaning_accounts";
      break;
    case FD_GUI_START_PROGRESS_TYPE_LOADING_LEDGER:
      phase = "loading_ledger";
      break;
    case FD_GUI_START_PROGRESS_TYPE_PROCESSING_LEDGER:
      phase = "processing_ledger";
      break;
    case FD_GUI_START_PROGRESS_TYPE_STARTING_SERVICES:
      phase = "starting_services";
      break;
    case FD_GUI_START_PROGRESS_TYPE_HALTED:
      phase = "halted";
      break;
    case FD_GUI_START_PROGRESS_TYPE_WAITING_FOR_SUPERMAJORITY:
      phase = "waiting_for_supermajority";
      break;
    case FD_GUI_START_PROGRESS_TYPE_RUNNING:
      phase = "running";
      break;
    default:
      FD_LOG_ERR(( "unknown phase %d", gui->summary.startup_progress ));
  }

  jsonp_open_envelope( gui, "summary", "startup_progress" );
    jsonp_open_object( gui, "value" );
      jsonp_string( gui, "phase", phase );
      if( FD_LIKELY( gui->summary.startup_progress>=FD_GUI_START_PROGRESS_TYPE_DOWNLOADING_FULL_SNAPSHOT) ) {
        char peer_addr[ 64 ];
        FD_TEST( fd_cstr_printf_check( peer_addr, sizeof(peer_addr), NULL, FD_IP4_ADDR_FMT ":%u", FD_IP4_ADDR_FMT_ARGS(gui->summary.startup_full_snapshot_peer_ip_addr), gui->summary.startup_full_snapshot_peer_port ) );

        jsonp_string( gui, "downloading_full_snapshot_peer", peer_addr );
        jsonp_ulong( gui, "downloading_full_snapshot_slot", gui->summary.startup_full_snapshot_slot );
        jsonp_double( gui, "downloading_full_snapshot_elapsed_secs", gui->summary.startup_full_snapshot_elapsed_secs );
        jsonp_double( gui, "downloading_full_snapshot_remaining_secs", gui->summary.startup_full_snapshot_remaining_secs );
        jsonp_double( gui, "downloading_full_snapshot_throughput", gui->summary.startup_full_snapshot_throughput );
        jsonp_ulong( gui, "downloading_full_snapshot_total_bytes", gui->summary.startup_full_snapshot_total_bytes );
        jsonp_ulong( gui, "downloading_full_snapshot_current_bytes", gui->summary.startup_full_snapshot_current_bytes );
      } else {
        jsonp_null( gui, "downloading_full_snapshot_peer" );
        jsonp_null( gui, "downloading_full_snapshot_slot" );
        jsonp_null( gui, "downloading_full_snapshot_elapsed_secs" );
        jsonp_null( gui, "downloading_full_snapshot_remaining_secs" );
        jsonp_null( gui, "downloading_full_snapshot_throughput" );
        jsonp_null( gui, "downloading_full_snapshot_total_bytes" );
        jsonp_null( gui, "downloading_full_snapshot_current_bytes" );
      }

      if( FD_LIKELY( gui->summary.startup_progress>=FD_GUI_START_PROGRESS_TYPE_DOWNLOADING_INCREMENTAL_SNAPSHOT) ) {
        char peer_addr[ 64 ];
        FD_TEST( fd_cstr_printf_check( peer_addr, sizeof(peer_addr), NULL, FD_IP4_ADDR_FMT ":%u", FD_IP4_ADDR_FMT_ARGS(gui->summary.startup_incremental_snapshot_peer_ip_addr), gui->summary.startup_incremental_snapshot_peer_port ) );

        jsonp_string( gui, "downloading_incremental_snapshot_peer", peer_addr );
        jsonp_ulong( gui, "downloading_incremental_snapshot_slot", gui->summary.startup_incremental_snapshot_slot );
        jsonp_double( gui, "downloading_incremental_snapshot_elapsed_secs", gui->summary.startup_incremental_snapshot_elapsed_secs );
        jsonp_double( gui, "downloading_incremental_snapshot_remaining_secs", gui->summary.startup_incremental_snapshot_remaining_secs );
        jsonp_double( gui, "downloading_incremental_snapshot_throughput", gui->summary.startup_incremental_snapshot_throughput );
        jsonp_ulong( gui, "downloading_incremental_snapshot_total_bytes", gui->summary.startup_incremental_snapshot_total_bytes );
        jsonp_ulong( gui, "downloading_incremental_snapshot_current_bytes", gui->summary.startup_incremental_snapshot_current_bytes );
      } else {
        jsonp_null( gui, "downloading_incremental_snapshot_peer" );
        jsonp_null( gui, "downloading_incremental_snapshot_slot" );
        jsonp_null( gui, "downloading_incremental_snapshot_elapsed_secs" );
        jsonp_null( gui, "downloading_incremental_snapshot_remaining_secs" );
        jsonp_null( gui, "downloading_incremental_snapshot_throughput" );
        jsonp_null( gui, "downloading_incremental_snapshot_total_bytes" );
        jsonp_null( gui, "downloading_incremental_snapshot_current_bytes" );
      }

      if( FD_LIKELY( gui->summary.startup_progress>=FD_GUI_START_PROGRESS_TYPE_PROCESSING_LEDGER) ) {
        jsonp_ulong( gui, "ledger_slot",     gui->summary.startup_ledger_slot );
        jsonp_ulong( gui, "ledger_max_slot", gui->summary.startup_ledger_max_slot );
      } else {
        jsonp_null( gui, "ledger_slot" );
        jsonp_null( gui, "ledger_max_slot" );
      }

      if( FD_LIKELY( gui->summary.startup_progress>=FD_GUI_START_PROGRESS_TYPE_WAITING_FOR_SUPERMAJORITY ) && gui->summary.startup_waiting_for_supermajority_slot!=ULONG_MAX ) {
        jsonp_ulong( gui, "waiting_for_supermajority_slot",      gui->summary.startup_waiting_for_supermajority_slot );
        jsonp_ulong( gui, "waiting_for_supermajority_stake_percent", gui->summary.startup_waiting_for_supermajority_stake_pct );
      } else {
        jsonp_null( gui, "waiting_for_supermajority_slot" );
        jsonp_null( gui, "waiting_for_supermajority_stake_percent" );
      }
    jsonp_close_object( gui );
  jsonp_close_envelope( gui );
}

void
fd_gui_printf_block_engine( fd_gui_t * gui ) {
  jsonp_open_envelope( gui, "block_engine", "update" );
    jsonp_open_object( gui, "value" );
      jsonp_string( gui, "name",   gui->block_engine.name );
      jsonp_string( gui, "url",    gui->block_engine.url );
      jsonp_string( gui, "ip",     gui->block_engine.ip_cstr );
      if( FD_LIKELY( gui->block_engine.status==1 ) )      jsonp_string( gui, "status", "connecting" );
      else if( FD_LIKELY( gui->block_engine.status==2 ) ) jsonp_string( gui, "status", "connected" );
      else                                                jsonp_string( gui, "status", "disconnected" );
    jsonp_close_object( gui );
  jsonp_close_envelope( gui );
}

void
fd_gui_printf_tiles( fd_gui_t * gui ) {
  jsonp_open_envelope( gui, "summary", "tiles" );
    jsonp_open_array( gui, "value" );
      for( ulong i=0UL; i<gui->topo->tile_cnt; i++ ) {
        fd_topo_tile_t const * tile = &gui->topo->tiles[ i ];

        if( FD_UNLIKELY( !strncmp( tile->name, "bench", 5UL ) ) ) {
          /* bench tiles not reported */
          continue;
        }

        jsonp_open_object( gui, NULL );
          jsonp_string( gui, "kind", tile->name );
          jsonp_ulong( gui, "kind_id", tile->kind_id );
        jsonp_close_object( gui );
      }
    jsonp_close_array( gui );
  jsonp_close_envelope( gui );
}

void
fd_gui_printf_schedule_strategy( fd_gui_t * gui ) {
  jsonp_open_envelope( gui, "summary", "schedule_strategy" );
    char mode[10];
    switch (gui->summary.schedule_strategy) {
      case 0: strncpy( mode, "perf", sizeof(mode) ); break;
      case 1: strncpy( mode, "balanced", sizeof(mode) ); break;
      case 2: strncpy( mode, "revenue", sizeof(mode) ); break;
      default: FD_LOG_ERR(("unexpected schedule_strategy %d", gui->summary.schedule_strategy));
    }
    mode[ sizeof(mode) - 1] = '\0';
    jsonp_string( gui, "value", mode );
  jsonp_close_envelope( gui );
}

void
fd_gui_printf_identity_balance( fd_gui_t * gui ) {
  jsonp_open_envelope( gui, "summary", "identity_balance" );
    jsonp_ulong_as_str( gui, "value", gui->summary.identity_account_balance );
  jsonp_close_envelope( gui );
}

void
fd_gui_printf_vote_balance( fd_gui_t * gui ) {
  jsonp_open_envelope( gui, "summary", "vote_balance" );
    jsonp_ulong_as_str( gui, "value", gui->summary.vote_account_balance );
  jsonp_close_envelope( gui );
}

void
fd_gui_printf_estimated_slot_duration_nanos( fd_gui_t * gui ) {
  jsonp_open_envelope( gui, "summary", "estimated_slot_duration_nanos" );
    jsonp_ulong( gui, "value", gui->summary.estimated_slot_duration_nanos );
  jsonp_close_envelope( gui );
}


void
fd_gui_printf_root_slot( fd_gui_t * gui ) {
  jsonp_open_envelope( gui, "summary", "root_slot" );
    jsonp_ulong( gui, "value", gui->summary.slot_rooted );
  jsonp_close_envelope( gui );
}

void
fd_gui_printf_optimistically_confirmed_slot( fd_gui_t * gui ) {
  jsonp_open_envelope( gui, "summary", "optimistically_confirmed_slot" );
    jsonp_ulong( gui, "value", gui->summary.slot_optimistically_confirmed );
  jsonp_close_envelope( gui );
}

void
fd_gui_printf_completed_slot( fd_gui_t * gui ) {
  jsonp_open_envelope( gui, "summary", "completed_slot" );
    jsonp_ulong( gui, "value", gui->summary.slot_completed );
  jsonp_close_envelope( gui );
}

void
fd_gui_printf_estimated_slot( fd_gui_t * gui ) {
  jsonp_open_envelope( gui, "summary", "estimated_slot" );
    jsonp_ulong( gui, "value", gui->summary.slot_estimated );
  jsonp_close_envelope( gui );
}

void
fd_gui_printf_skip_rate( fd_gui_t * gui,
                         ulong      epoch_idx ) {
  jsonp_open_envelope( gui, "summary", "skip_rate" );
    jsonp_open_object( gui, "value" );
      jsonp_ulong( gui, "epoch", gui->epoch.epochs[ epoch_idx ].epoch );
      if( FD_UNLIKELY( !gui->epoch.epochs[ epoch_idx ].my_total_slots ) ) jsonp_double( gui, "skip_rate", 0.0 );
      else                                                                jsonp_double( gui, "skip_rate", (double)gui->epoch.epochs[ epoch_idx ].my_skipped_slots/(double)gui->epoch.epochs[ epoch_idx ].my_total_slots );
    jsonp_close_object( gui );
  jsonp_close_envelope( gui );
}

void
fd_gui_printf_epoch( fd_gui_t * gui,
                     ulong      epoch_idx ) {
  jsonp_open_envelope( gui, "epoch", "new" );
    jsonp_open_object( gui, "value" );
      jsonp_ulong( gui, "epoch",                   gui->epoch.epochs[ epoch_idx ].epoch );
      if( FD_LIKELY( gui->epoch.epochs[ epoch_idx ].start_time!=LONG_MAX ) ) jsonp_ulong_as_str( gui, "start_time_nanos", (ulong)gui->epoch.epochs[ epoch_idx ].start_time );
      else                                                                    jsonp_null( gui, "start_time_nanos" );
      if( FD_LIKELY( gui->epoch.epochs[ epoch_idx ].end_time!=LONG_MAX ) ) jsonp_ulong_as_str( gui, "end_time_nanos", (ulong)gui->epoch.epochs[ epoch_idx ].end_time );
      else                                                                  jsonp_null( gui, "end_time_nanos" );
      jsonp_ulong( gui, "start_slot",              gui->epoch.epochs[ epoch_idx ].start_slot );
      jsonp_ulong( gui, "end_slot",                gui->epoch.epochs[ epoch_idx ].end_slot );
      jsonp_ulong_as_str( gui, "excluded_stake_lamports", gui->epoch.epochs[ epoch_idx ].excluded_stake );
      jsonp_open_array( gui, "staked_pubkeys" );
        fd_epoch_leaders_t * lsched = gui->epoch.epochs[epoch_idx].lsched;
        for( ulong i=0UL; i<lsched->pub_cnt; i++ ) {
          char identity_base58[ FD_BASE58_ENCODED_32_SZ ];
          fd_base58_encode_32( lsched->pub[ i ].uc, NULL, identity_base58 );
          jsonp_string( gui, NULL, identity_base58 );
        }
      jsonp_close_array( gui );

      jsonp_open_array( gui, "staked_lamports" );
        fd_vote_stake_weight_t * stakes = gui->epoch.epochs[epoch_idx].stakes;
        for( ulong i=0UL; i<lsched->pub_cnt; i++ ) jsonp_ulong_as_str( gui, NULL, stakes[ i ].stake );
      jsonp_close_array( gui );

      jsonp_open_array( gui, "leader_slots" );
        for( ulong i = 0; i < lsched->sched_cnt; i++ ) jsonp_ulong( gui, NULL, lsched->sched[ i ] );
      jsonp_close_array( gui );
    jsonp_close_object( gui );
  jsonp_close_envelope( gui );
}

static void
fd_gui_printf_waterfall( fd_gui_t *               gui,
                         fd_gui_txn_waterfall_t const * prev,
                         fd_gui_txn_waterfall_t const * cur ) {
  jsonp_open_object( gui, "waterfall" );
    jsonp_open_object( gui, "in" );
      jsonp_ulong( gui, "pack_cranked",    cur->in.pack_cranked - prev->in.pack_cranked );
      jsonp_ulong( gui, "pack_retained",   prev->out.pack_retained );
      jsonp_ulong( gui, "resolv_retained", prev->out.resolv_retained );
      jsonp_ulong( gui, "quic",            cur->in.quic   - prev->in.quic );
      jsonp_ulong( gui, "udp",             cur->in.udp    - prev->in.udp );
      jsonp_ulong( gui, "gossip",          cur->in.gossip - prev->in.gossip );
      jsonp_ulong( gui, "block_engine",    cur->in.block_engine - prev->in.block_engine );
    jsonp_close_object( gui );

    jsonp_open_object( gui, "out" );
      jsonp_ulong( gui, "net_overrun",         cur->out.net_overrun         - prev->out.net_overrun );
      jsonp_ulong( gui, "quic_overrun",        cur->out.quic_overrun        - prev->out.quic_overrun );
      jsonp_ulong( gui, "quic_frag_drop",      cur->out.quic_frag_drop      - prev->out.quic_frag_drop );
      jsonp_ulong( gui, "quic_abandoned",      cur->out.quic_abandoned      - prev->out.quic_abandoned );
      jsonp_ulong( gui, "tpu_quic_invalid",    cur->out.tpu_quic_invalid    - prev->out.tpu_quic_invalid );
      jsonp_ulong( gui, "tpu_udp_invalid",     cur->out.tpu_udp_invalid     - prev->out.tpu_udp_invalid );
      jsonp_ulong( gui, "verify_overrun",      cur->out.verify_overrun      - prev->out.verify_overrun );
      jsonp_ulong( gui, "verify_parse",        cur->out.verify_parse        - prev->out.verify_parse );
      jsonp_ulong( gui, "verify_failed",       cur->out.verify_failed       - prev->out.verify_failed );
      jsonp_ulong( gui, "verify_duplicate",    cur->out.verify_duplicate    - prev->out.verify_duplicate );
      jsonp_ulong( gui, "dedup_duplicate",     cur->out.dedup_duplicate     - prev->out.dedup_duplicate );
      jsonp_ulong( gui, "resolv_lut_failed",   cur->out.resolv_lut_failed   - prev->out.resolv_lut_failed );
      jsonp_ulong( gui, "resolv_expired",      cur->out.resolv_expired      - prev->out.resolv_expired );
      jsonp_ulong( gui, "resolv_ancient",      cur->out.resolv_ancient      - prev->out.resolv_ancient );
      jsonp_ulong( gui, "resolv_no_ledger",    cur->out.resolv_no_ledger    - prev->out.resolv_no_ledger );
      jsonp_ulong( gui, "resolv_retained",     cur->out.resolv_retained );
      jsonp_ulong( gui, "pack_invalid",        cur->out.pack_invalid        - prev->out.pack_invalid );
      jsonp_ulong( gui, "pack_invalid_bundle", cur->out.pack_invalid_bundle - prev->out.pack_invalid_bundle );
      jsonp_ulong( gui, "pack_expired",        cur->out.pack_expired        - prev->out.pack_expired );
      jsonp_ulong( gui, "pack_retained",       cur->out.pack_retained );
      jsonp_ulong( gui, "pack_wait_full",      cur->out.pack_wait_full      - prev->out.pack_wait_full );
      jsonp_ulong( gui, "pack_leader_slow",    cur->out.pack_leader_slow    - prev->out.pack_leader_slow );
      jsonp_ulong( gui, "bank_invalid",        cur->out.bank_invalid        - prev->out.bank_invalid );
      jsonp_ulong( gui, "block_success",       cur->out.block_success       - prev->out.block_success );
      jsonp_ulong( gui, "block_fail",          cur->out.block_fail          - prev->out.block_fail );
    jsonp_close_object( gui );
  jsonp_close_object( gui );
}

void
fd_gui_printf_live_txn_waterfall( fd_gui_t *                     gui,
                                  fd_gui_txn_waterfall_t const * prev,
                                  fd_gui_txn_waterfall_t const * cur,
                                  ulong                          next_leader_slot ) {
  jsonp_open_envelope( gui, "summary", "live_txn_waterfall" );
    jsonp_open_object( gui, "value" );
      jsonp_ulong( gui, "next_leader_slot", next_leader_slot );
      fd_gui_printf_waterfall( gui, prev, cur );
    jsonp_close_object( gui );
  jsonp_close_envelope( gui );
}

static void
fd_gui_printf_tile_stats( fd_gui_t *                  gui,
                          fd_gui_tile_stats_t const * prev,
                          fd_gui_tile_stats_t const * cur ) {
  jsonp_open_object( gui, "tile_primary_metric" );
    jsonp_ulong(  gui, "quic",    cur->quic_conn_cnt );
    jsonp_double( gui, "bundle_rtt_smoothed_millis", (double)(cur->bundle_rtt_smoothed_nanos) / 1000000.0 );

    fd_histf_t bundle_rx_delay_hist_delta[ 1 ];
    fd_histf_subtract( &cur->bundle_rx_delay_hist, &prev->bundle_rx_delay_hist, bundle_rx_delay_hist_delta );
    ulong bundle_rx_delay_nanos_p90 = fd_histf_percentile( bundle_rx_delay_hist_delta, 90U, ULONG_MAX );
    jsonp_double( gui, "bundle_rx_delay_millis_p90", fd_double_if(bundle_rx_delay_nanos_p90==ULONG_MAX, 0.0, (double)(bundle_rx_delay_nanos_p90) / 1000000.0 ));

    if( FD_LIKELY( cur->sample_time_nanos>prev->sample_time_nanos ) ) {
      jsonp_ulong( gui, "net_in",  (ulong)((double)(cur->net_in_rx_bytes - prev->net_in_rx_bytes) * 1000000000.0 / (double)(cur->sample_time_nanos - prev->sample_time_nanos) ));
      jsonp_ulong( gui, "net_out", (ulong)((double)(cur->net_out_tx_bytes - prev->net_out_tx_bytes) * 1000000000.0 / (double)(cur->sample_time_nanos - prev->sample_time_nanos) ));
    } else {
      jsonp_ulong( gui, "net_in",  0 );
      jsonp_ulong( gui, "net_out", 0 );
    }
    if( FD_LIKELY( cur->verify_total_cnt>prev->verify_total_cnt ) ) {
      jsonp_double( gui, "verify", (double)(cur->verify_drop_cnt-prev->verify_drop_cnt) / (double)(cur->verify_total_cnt-prev->verify_total_cnt) );
    } else {
      jsonp_double( gui, "verify", 0.0 );
    }
    if( FD_LIKELY( cur->dedup_total_cnt>prev->dedup_total_cnt ) ) {
      jsonp_double( gui, "dedup", (double)(cur->dedup_drop_cnt-prev->dedup_drop_cnt) / (double)(cur->dedup_total_cnt-prev->dedup_total_cnt) );
    } else {
      jsonp_double( gui, "dedup", 0.0 );
    }
    jsonp_ulong(  gui, "bank", cur->bank_txn_exec_cnt - prev->bank_txn_exec_cnt );
    jsonp_double( gui, "pack", !cur->pack_buffer_capacity ? 1.0 : (double)cur->pack_buffer_cnt/(double)cur->pack_buffer_capacity );
    jsonp_double( gui, "poh", 0.0 );
    jsonp_double( gui, "shred", 0.0 );
    jsonp_double( gui, "store", 0.0 );
  jsonp_close_object( gui );
}

void
fd_gui_printf_live_tile_stats( fd_gui_t *                  gui,
                               fd_gui_tile_stats_t const * prev,
                               fd_gui_tile_stats_t const * cur ) {
  jsonp_open_envelope( gui, "summary", "live_tile_primary_metric" );
    jsonp_open_object( gui, "value" );
      jsonp_ulong( gui, "next_leader_slot", 0UL );
      fd_gui_printf_tile_stats( gui, prev, cur );
    jsonp_close_object( gui );
  jsonp_close_envelope( gui );
}

static void
fd_gui_printf_tile_timers( fd_gui_t *                   gui,
                           fd_gui_tile_timers_t const * prev,
                           fd_gui_tile_timers_t const * cur ) {
  for( ulong i=0UL; i<gui->topo->tile_cnt; i++ ) {
    fd_topo_tile_t const * tile = &gui->topo->tiles[ i ];

    if( FD_UNLIKELY( !strncmp( tile->name, "bench", 5UL ) ) ) {
      /* bench tiles not reported */
      continue;
    }

    double cur_total = (double)(cur[ i ].caughtup_housekeeping_ticks
                                + cur[ i ].processing_housekeeping_ticks
                                + cur[ i ].backpressure_housekeeping_ticks
                                + cur[ i ].caughtup_prefrag_ticks
                                + cur[ i ].processing_prefrag_ticks
                                + cur[ i ].backpressure_prefrag_ticks
                                + cur[ i ].caughtup_postfrag_ticks
                                + cur[ i ].processing_postfrag_ticks
                                + cur[ i ].sleeping_ticks);

    double prev_total = (double)(prev[ i ].caughtup_housekeeping_ticks
                                  + prev[ i ].processing_housekeeping_ticks
                                  + prev[ i ].backpressure_housekeeping_ticks
                                  + prev[ i ].caughtup_prefrag_ticks
                                  + prev[ i ].processing_prefrag_ticks
                                  + prev[ i ].backpressure_prefrag_ticks
                                  + prev[ i ].caughtup_postfrag_ticks
                                  + prev[ i ].processing_postfrag_ticks
                                  + prev[ i ].sleeping_ticks);

    double idle;
    if( FD_UNLIKELY( cur_total==prev_total ) ) {
      /* The tile didn't sample timers since the last sample, unclear what
         idleness should be so send -1. NaN would be better but no NaN in
         JSON. */
      idle = -1;
    } else {
      idle = (double)(cur[ i ].caughtup_postfrag_ticks - prev[ i ].caughtup_postfrag_ticks) / (cur_total - prev_total);
    }

    jsonp_double( gui, NULL, idle );
  }
}

void
fd_gui_printf_live_tile_timers( fd_gui_t * gui ) {
  jsonp_open_envelope( gui, "summary", "live_tile_timers" );
    jsonp_open_array( gui, "value" );
      fd_gui_tile_timers_t * cur  = gui->summary.tile_timers_snap[ (gui->summary.tile_timers_snap_idx+(FD_GUI_TILE_TIMER_SNAP_CNT-1UL))%FD_GUI_TILE_TIMER_SNAP_CNT ];
      fd_gui_tile_timers_t * prev = gui->summary.tile_timers_snap[ (gui->summary.tile_timers_snap_idx+(FD_GUI_TILE_TIMER_SNAP_CNT-2UL))%FD_GUI_TILE_TIMER_SNAP_CNT ];
      fd_gui_printf_tile_timers( gui, prev, cur );
    jsonp_close_array( gui );
  jsonp_close_envelope( gui );
}

void
fd_gui_printf_estimated_tps( fd_gui_t * gui ) {
  ulong idx = (gui->summary.estimated_tps_history_idx+FD_GUI_TPS_HISTORY_SAMPLE_CNT-1UL) % FD_GUI_TPS_HISTORY_SAMPLE_CNT;

  jsonp_open_envelope( gui, "summary", "estimated_tps" );
    jsonp_open_object( gui, "value" );
      jsonp_double( gui, "total",           (double)gui->summary.estimated_tps_history[ idx ][ 0 ]/(double)FD_GUI_TPS_HISTORY_WINDOW_DURATION_SECONDS );
      jsonp_double( gui, "vote",            (double)gui->summary.estimated_tps_history[ idx ][ 1 ]/(double)FD_GUI_TPS_HISTORY_WINDOW_DURATION_SECONDS );
      jsonp_double( gui, "nonvote_success", (double)(gui->summary.estimated_tps_history[ idx ][ 0 ] - gui->summary.estimated_tps_history[ idx ][ 1 ] - gui->summary.estimated_tps_history[ idx ][ 2 ])/(double)FD_GUI_TPS_HISTORY_WINDOW_DURATION_SECONDS );
      jsonp_double( gui, "nonvote_failed",  (double)gui->summary.estimated_tps_history[ idx ][ 2 ]/(double)FD_GUI_TPS_HISTORY_WINDOW_DURATION_SECONDS );
    jsonp_close_object( gui );
  jsonp_close_envelope( gui );
}

static int
fd_gui_gossip_contains( fd_gui_t const * gui,
                        uchar const *    pubkey ) {
  for( ulong i=0UL; i<gui->gossip.peer_cnt; i++ ) {
    if( FD_UNLIKELY( !memcmp( gui->gossip.peers[ i ].pubkey->uc, pubkey, 32 ) ) ) return 1;
  }
  return 0;
}

static int
fd_gui_vote_acct_contains( fd_gui_t const * gui,
                           uchar const *    pubkey ) {
  for( ulong i=0UL; i<gui->vote_account.vote_account_cnt; i++ ) {
    if( FD_UNLIKELY( !memcmp( gui->vote_account.vote_accounts[ i ].pubkey, pubkey, 32 ) ) ) return 1;
  }
  return 0;
}

static int
fd_gui_validator_info_contains( fd_gui_t const * gui,
                                uchar const *    pubkey ) {
  for( ulong i=0UL; i<gui->validator_info.info_cnt; i++ ) {
    if( FD_UNLIKELY( !memcmp( gui->validator_info.info[ i ].pubkey, pubkey, 32 ) ) ) return 1;
  }
  return 0;
}

static void
fd_gui_printf_peer( fd_gui_t *    gui,
                    uchar const * identity_pubkey ) {
  ulong gossip_idx = ULONG_MAX;
  ulong info_idx = ULONG_MAX;
  ulong vote_idxs[ FD_GUI_MAX_PEER_CNT ] = {0};
  ulong vote_idx_cnt = 0UL;

  for( ulong i=0UL; i<gui->gossip.peer_cnt; i++ ) {
    if( FD_UNLIKELY( !memcmp( gui->gossip.peers[ i ].pubkey->uc, identity_pubkey, 32 ) ) ) {
      gossip_idx = i;
      break;
    }
  }

  for( ulong i=0UL; i<gui->validator_info.info_cnt; i++ ) {
    if( FD_UNLIKELY( !memcmp( gui->validator_info.info[ i ].pubkey, identity_pubkey, 32 ) ) ) {
      info_idx = i;
      break;
    }
  }

  for( ulong i=0UL; i<gui->vote_account.vote_account_cnt; i++ ) {
    if( FD_UNLIKELY( !memcmp( gui->vote_account.vote_accounts[ i ].pubkey, identity_pubkey, 32 ) ) ) {
      vote_idxs[ vote_idx_cnt++ ] = i;
    }
  }

  jsonp_open_object( gui, NULL );

    char identity_base58[ FD_BASE58_ENCODED_32_SZ ];
    fd_base58_encode_32( identity_pubkey, NULL, identity_base58 );
    jsonp_string( gui, "identity_pubkey", identity_base58 );

    if( FD_UNLIKELY( gossip_idx==ULONG_MAX ) ) {
      jsonp_string( gui, "gossip", NULL );
    } else {
      jsonp_open_object( gui, "gossip" );

        char version[ 32 ];
        FD_TEST( fd_cstr_printf( version, sizeof( version ), NULL, "%u.%u.%u", gui->gossip.peers[ gossip_idx ].version.major, gui->gossip.peers[ gossip_idx ].version.minor, gui->gossip.peers[ gossip_idx ].version.patch ) );
        jsonp_string( gui, "version", version );
        jsonp_ulong( gui, "feature_set", gui->gossip.peers[ gossip_idx ].version.feature_set );
        jsonp_ulong( gui, "wallclock", gui->gossip.peers[ gossip_idx ].wallclock );
        jsonp_ulong( gui, "shred_version", gui->gossip.peers[ gossip_idx ].shred_version );
        jsonp_open_object( gui, "sockets" );
          for( ulong j=0UL; j<12UL; j++ ) {
            if( FD_LIKELY( !gui->gossip.peers[ gossip_idx ].sockets[ j ].ipv4 && !gui->gossip.peers[ gossip_idx ].sockets[ j ].port ) ) continue;
            char const * tag;
            switch( j ) {
              case  0: tag = "gossip";            break;
              case  1: tag = "rpc";               break;
              case  2: tag = "rpb_pubsub";        break;
              case  3: tag = "serve_repair";      break;
              case  4: tag = "serve_repair_quic"; break;
              case  5: tag = "tpu";               break;
              case  6: tag = "tpu_quic";          break;
              case  7: tag = "tvu";               break;
              case  8: tag = "tvu_quic";          break;
              case  9: tag = "tpu_forwards";      break;
              case 10: tag = "tpu_forwards_quic"; break;
              case 11: tag = "tpu_vote";          break;
            }
            char line[ 64 ];
            FD_TEST( fd_cstr_printf( line, sizeof( line ), NULL, FD_IP4_ADDR_FMT ":%u", FD_IP4_ADDR_FMT_ARGS(gui->gossip.peers[ gossip_idx ].sockets[ j ].ipv4 ), gui->gossip.peers[ gossip_idx ].sockets[ j ].port ) );
            jsonp_string( gui, tag, line );
          }
        jsonp_close_object( gui );

      jsonp_close_object( gui );
    }

    jsonp_open_array( gui, "vote" );
      for( ulong i=0UL; i<vote_idx_cnt; i++ ) {
        jsonp_open_object( gui, NULL );
          char vote_account_base58[ FD_BASE58_ENCODED_32_SZ ];
          fd_base58_encode_32( gui->vote_account.vote_accounts[ vote_idxs[ i ] ].vote_account->uc, NULL, vote_account_base58 );
          jsonp_string( gui, "vote_account", vote_account_base58 );
          jsonp_ulong_as_str( gui, "activated_stake", gui->vote_account.vote_accounts[ vote_idxs[ i ] ].activated_stake );
          jsonp_ulong( gui, "last_vote", gui->vote_account.vote_accounts[ vote_idxs[ i ] ].last_vote );
          jsonp_ulong( gui, "root_slot", gui->vote_account.vote_accounts[ vote_idxs[ i ] ].root_slot );
          jsonp_ulong( gui, "epoch_credits", gui->vote_account.vote_accounts[ vote_idxs[ i ] ].epoch_credits );
          jsonp_ulong( gui, "commission", gui->vote_account.vote_accounts[ vote_idxs[ i ] ].commission );
          jsonp_bool( gui, "delinquent", gui->vote_account.vote_accounts[ vote_idxs[ i ] ].delinquent );
        jsonp_close_object( gui );
      }
    jsonp_close_array( gui );

    if( FD_UNLIKELY( info_idx==ULONG_MAX ) ) {
      jsonp_string( gui, "info", NULL );
    } else {
      jsonp_open_object( gui, "info" );
        jsonp_string( gui, "name", gui->validator_info.info[ info_idx ].name );
        jsonp_string( gui, "details", gui->validator_info.info[ info_idx ].details );
        jsonp_string( gui, "website", gui->validator_info.info[ info_idx ].website );
        jsonp_string( gui, "icon_url", gui->validator_info.info[ info_idx ].icon_uri );
      jsonp_close_object( gui );
    }

  jsonp_close_object( gui );
}

void
fd_gui_printf_peers_gossip_update( fd_gui_t *          gui,
                                   ulong const *       updated,
                                   ulong               updated_cnt,
                                   fd_pubkey_t const * removed,
                                   ulong               removed_cnt,
                                   ulong const *       added,
                                   ulong               added_cnt ) {
  jsonp_open_envelope( gui, "peers", "update" );
    jsonp_open_object( gui, "value" );
      jsonp_open_array( gui, "add" );
        for( ulong i=0UL; i<added_cnt; i++ ) {
          int actually_added = !fd_gui_vote_acct_contains( gui, gui->gossip.peers[ added[ i ] ].pubkey->uc ) &&
                               !fd_gui_validator_info_contains( gui, gui->gossip.peers[ added[ i ] ].pubkey->uc );
          if( FD_LIKELY( !actually_added ) ) continue;

          fd_gui_printf_peer( gui, gui->gossip.peers[ added[ i ] ].pubkey->uc );
        }
      jsonp_close_array( gui );

      jsonp_open_array( gui, "update" );
        for( ulong i=0UL; i<added_cnt; i++ ) {
          int actually_added = !fd_gui_vote_acct_contains( gui, gui->gossip.peers[ added[ i ] ].pubkey->uc ) &&
                              !fd_gui_validator_info_contains( gui, gui->gossip.peers[ added[ i ] ].pubkey->uc );
          if( FD_LIKELY( actually_added ) ) continue;

          fd_gui_printf_peer( gui, gui->gossip.peers[ added[ i ] ].pubkey->uc );
        }
        for( ulong i=0UL; i<updated_cnt; i++ ) {
          fd_gui_printf_peer( gui, gui->gossip.peers[ updated[ i ] ].pubkey->uc );
        }
      jsonp_close_array( gui );

      jsonp_open_array( gui, "remove" );
        for( ulong i=0UL; i<removed_cnt; i++ ) {
          int actually_removed = !fd_gui_vote_acct_contains( gui, removed[ i ].uc ) &&
                                 !fd_gui_validator_info_contains( gui, removed[ i ].uc );
          if( FD_UNLIKELY( !actually_removed ) ) continue;

          jsonp_open_object( gui, NULL );
            char identity_base58[ FD_BASE58_ENCODED_32_SZ ];
            fd_base58_encode_32( removed[ i ].uc, NULL, identity_base58 );
            jsonp_string( gui, "identity_pubkey", identity_base58 );
          jsonp_close_object( gui );
        }
      jsonp_close_array( gui );
    jsonp_close_object( gui );
  jsonp_close_envelope( gui );
}

void
fd_gui_printf_peers_vote_account_update( fd_gui_t *          gui,
                                         ulong const *       updated,
                                         ulong               updated_cnt,
                                         fd_pubkey_t const * removed,
                                         ulong               removed_cnt,
                                         ulong const *       added,
                                         ulong               added_cnt ) {
  jsonp_open_envelope( gui, "peers", "update" );
    jsonp_open_object( gui, "value" );
      jsonp_open_array( gui, "add" );
      for( ulong i=0UL; i<added_cnt; i++ ) {
        int actually_added = !fd_gui_gossip_contains( gui, gui->vote_account.vote_accounts[ added[ i ] ].pubkey->uc ) &&
                             !fd_gui_validator_info_contains( gui, gui->vote_account.vote_accounts[ added[ i ] ].pubkey->uc );
        if( FD_LIKELY( !actually_added ) ) continue;

        fd_gui_printf_peer( gui, gui->vote_account.vote_accounts[ added[ i ] ].pubkey->uc );
      }
      jsonp_close_array( gui );

      jsonp_open_array( gui, "update" );
      for( ulong i=0UL; i<added_cnt; i++ ) {
        int actually_added = !fd_gui_gossip_contains( gui, gui->vote_account.vote_accounts[ added[ i ] ].pubkey->uc ) &&
                             !fd_gui_validator_info_contains( gui, gui->vote_account.vote_accounts[ added[ i ] ].pubkey->uc );
        if( FD_LIKELY( actually_added ) ) continue;

        fd_gui_printf_peer( gui, gui->vote_account.vote_accounts[ added[ i ] ].pubkey->uc );
      }
      for( ulong i=0UL; i<updated_cnt; i++ ) {
        fd_gui_printf_peer( gui, gui->vote_account.vote_accounts[ updated[ i ] ].pubkey->uc );
      }
      jsonp_close_array( gui );

      jsonp_open_array( gui, "remove" );
      for( ulong i=0UL; i<removed_cnt; i++ ) {
        int actually_removed = !fd_gui_gossip_contains( gui, gui->vote_account.vote_accounts[ added[ i ] ].pubkey->uc ) &&
                               !fd_gui_validator_info_contains( gui, gui->vote_account.vote_accounts[ added[ i ] ].pubkey->uc );
        if( FD_UNLIKELY( !actually_removed ) ) continue;

        jsonp_open_object( gui, NULL );
          char identity_base58[ FD_BASE58_ENCODED_32_SZ ];
          fd_base58_encode_32( removed[ i ].uc, NULL, identity_base58 );
          jsonp_string( gui, "identity_pubkey", identity_base58 );
        jsonp_close_object( gui );
      }
      jsonp_close_array( gui );
    jsonp_close_object( gui );
  jsonp_close_envelope( gui );
}

void
fd_gui_printf_peers_validator_info_update( fd_gui_t *          gui,
                                           ulong const *       updated,
                                           ulong               updated_cnt,
                                           fd_pubkey_t const * removed,
                                           ulong               removed_cnt,
                                           ulong const *       added,
                                           ulong               added_cnt ) {
  jsonp_open_envelope( gui, "peers", "update" );
    jsonp_open_object( gui, "value" );
      jsonp_open_array( gui, "add" );
      for( ulong i=0UL; i<added_cnt; i++ ) {
        int actually_added = !fd_gui_gossip_contains( gui, gui->validator_info.info[ added[ i ] ].pubkey->uc ) &&
                             !fd_gui_vote_acct_contains( gui, gui->validator_info.info[ added[ i ] ].pubkey->uc );
        if( FD_LIKELY( !actually_added ) ) continue;

        fd_gui_printf_peer( gui, gui->validator_info.info[ added[ i ] ].pubkey->uc );
      }
      jsonp_close_array( gui );

      jsonp_open_array( gui, "update" );
      for( ulong i=0UL; i<added_cnt; i++ ) {
        int actually_added = !fd_gui_gossip_contains( gui, gui->validator_info.info[ added[ i ] ].pubkey->uc ) &&
                             !fd_gui_vote_acct_contains( gui, gui->validator_info.info[ added[ i ] ].pubkey->uc );
        if( FD_LIKELY( actually_added ) ) continue;

        fd_gui_printf_peer( gui, gui->validator_info.info[ added[ i ] ].pubkey->uc );
      }
      for( ulong i=0UL; i<updated_cnt; i++ ) {
        fd_gui_printf_peer( gui, gui->validator_info.info[ updated[ i ] ].pubkey->uc );
      }
      jsonp_close_array( gui );

      jsonp_open_array( gui, "remove" );
      for( ulong i=0UL; i<removed_cnt; i++ ) {
        int actually_removed = !fd_gui_gossip_contains( gui, gui->validator_info.info[ added[ i ] ].pubkey->uc ) &&
                               !fd_gui_vote_acct_contains( gui, gui->validator_info.info[ added[ i ] ].pubkey->uc );
        if( FD_UNLIKELY( !actually_removed ) ) continue;

        jsonp_open_object( gui, NULL );
          char identity_base58[ FD_BASE58_ENCODED_32_SZ ];
          fd_base58_encode_32( removed[ i ].uc, NULL, identity_base58 );
          jsonp_string( gui, "identity_pubkey", identity_base58 );
        jsonp_close_object( gui );
      }
      jsonp_close_array( gui );
    jsonp_close_object( gui );
  jsonp_close_envelope( gui );
}

void
fd_gui_printf_peers_all( fd_gui_t * gui ) {
  jsonp_open_envelope( gui, "peers", "update" );
    jsonp_open_object( gui, "value" );
      jsonp_open_array( gui, "add" );
      for( ulong i=0UL; i<gui->gossip.peer_cnt; i++ ) {
        fd_gui_printf_peer( gui, gui->gossip.peers[ i ].pubkey->uc );
      }
      for( ulong i=0UL; i<gui->vote_account.vote_account_cnt; i++ ) {
        int actually_added = !fd_gui_gossip_contains( gui, gui->vote_account.vote_accounts[ i ].pubkey->uc );
        if( FD_UNLIKELY( actually_added ) ) {
          fd_gui_printf_peer( gui, gui->vote_account.vote_accounts[ i ].pubkey->uc );
        }
      }
      for( ulong i=0UL; i<gui->validator_info.info_cnt; i++ ) {
        int actually_added = !fd_gui_gossip_contains( gui, gui->validator_info.info[ i ].pubkey->uc ) &&
                             !fd_gui_vote_acct_contains( gui, gui->validator_info.info[ i ].pubkey->uc );
        if( FD_UNLIKELY( actually_added ) ) {
          fd_gui_printf_peer( gui, gui->validator_info.info[ i ].pubkey->uc );
        }
      }
      jsonp_close_array( gui );
    jsonp_close_object( gui );
  jsonp_close_envelope( gui );
}

static void
fd_gui_printf_ts_tile_timers( fd_gui_t *                   gui,
                              fd_gui_tile_timers_t const * prev,
                              fd_gui_tile_timers_t const * cur ) {
  jsonp_open_object( gui, NULL );
    jsonp_ulong_as_str( gui, "timestamp_nanos", 0 );
    jsonp_open_array( gui, "tile_timers" );
      fd_gui_printf_tile_timers( gui, prev, cur );
    jsonp_close_array( gui );
  jsonp_close_object( gui );
}

void
fd_gui_printf_slot( fd_gui_t * gui,
                    ulong      _slot ) {
  fd_gui_slot_t * slot = gui->slots[ _slot % FD_GUI_SLOTS_CNT ];

  char const * level;
  switch( slot->level ) {
    case FD_GUI_SLOT_LEVEL_INCOMPLETE:               level = "incomplete"; break;
    case FD_GUI_SLOT_LEVEL_COMPLETED:                level = "completed";  break;
    case FD_GUI_SLOT_LEVEL_OPTIMISTICALLY_CONFIRMED: level = "optimistically_confirmed"; break;
    case FD_GUI_SLOT_LEVEL_ROOTED:                   level = "rooted"; break;
    case FD_GUI_SLOT_LEVEL_FINALIZED:                level = "finalized"; break;
    default:                                         level = "unknown"; break;
  }

  fd_gui_slot_t * parent_slot = gui->slots[ slot->parent_slot % FD_GUI_SLOTS_CNT ];
  if( FD_UNLIKELY( parent_slot->slot!=slot->parent_slot ) ) parent_slot = NULL;

  long duration_nanos = LONG_MAX;
  if( FD_LIKELY( slot->completed_time!=LONG_MAX && parent_slot && parent_slot->completed_time!=LONG_MAX ) ) {
    duration_nanos = slot->completed_time - parent_slot->completed_time;
  }

  jsonp_open_envelope( gui, "slot", "update" );
    jsonp_open_object( gui, "value" );
      jsonp_open_object( gui, "publish" );
        jsonp_ulong( gui, "slot", _slot );
        jsonp_bool( gui, "mine", slot->mine );
        jsonp_bool( gui, "skipped", slot->skipped );
        if( FD_UNLIKELY( duration_nanos==LONG_MAX ) ) jsonp_null( gui, "duration_nanos" );
        else                                          jsonp_long( gui, "duration_nanos", duration_nanos );
        if( FD_UNLIKELY( slot->completed_time==LONG_MAX ) ) jsonp_null( gui, "completed_time_nanos" );
        else                                                jsonp_long_as_str( gui, "completed_time_nanos", slot->completed_time );
        jsonp_string( gui, "level", level );
        if( FD_UNLIKELY( slot->total_txn_cnt==UINT_MAX
                         || slot->vote_txn_cnt==UINT_MAX
                         || slot->nonvote_failed_txn_cnt==UINT_MAX ) ) jsonp_null( gui, "success_nonvote_transaction_cnt" );
        else                                                           jsonp_ulong( gui, "success_nonvote_transaction_cnt", slot->total_txn_cnt - slot->vote_txn_cnt - slot->nonvote_failed_txn_cnt );
        if( FD_UNLIKELY( slot->nonvote_failed_txn_cnt==UINT_MAX ) ) jsonp_null( gui, "failed_nonvote_transaction_cnt" );
        else                                                        jsonp_ulong( gui, "failed_nonvote_transaction_cnt", slot->nonvote_failed_txn_cnt );
        if( FD_UNLIKELY( slot->vote_txn_cnt==UINT_MAX
                         || slot->failed_txn_cnt==UINT_MAX
                         || slot->nonvote_failed_txn_cnt==UINT_MAX ) ) jsonp_null( gui, "success_vote_transaction_cnt" );
        else                                                           jsonp_ulong( gui, "success_vote_transaction_cnt", slot->vote_txn_cnt - (slot->failed_txn_cnt - slot->nonvote_failed_txn_cnt) );
        if( FD_UNLIKELY( slot->failed_txn_cnt==UINT_MAX
                         || slot->nonvote_failed_txn_cnt==UINT_MAX ) ) jsonp_null( gui, "failed_vote_transaction_cnt" );
        else                                                           jsonp_ulong( gui, "failed_vote_transaction_cnt", slot->failed_txn_cnt - slot->nonvote_failed_txn_cnt );
        if( FD_UNLIKELY( slot->max_compute_units==UINT_MAX ) ) jsonp_null( gui, "max_compute_units" );
        else                                                       jsonp_ulong( gui, "max_compute_units", slot->max_compute_units );
        if( FD_UNLIKELY( slot->compute_units==UINT_MAX ) ) jsonp_null( gui, "compute_units" );
        else                                               jsonp_ulong( gui, "compute_units", slot->compute_units );
        if( FD_UNLIKELY( slot->transaction_fee==ULONG_MAX ) ) jsonp_null( gui, "transaction_fee" );
        else                                                  jsonp_ulong_as_str( gui, "transaction_fee", slot->transaction_fee );
        if( FD_UNLIKELY( slot->priority_fee==ULONG_MAX ) ) jsonp_null( gui, "priority_fee" );
        else                                               jsonp_ulong_as_str( gui, "priority_fee", slot->priority_fee );
        if( FD_UNLIKELY( slot->tips==ULONG_MAX ) ) jsonp_null( gui, "tips" );
        else                                       jsonp_ulong_as_str( gui, "tips", slot->tips );
      jsonp_close_object( gui );
    jsonp_close_object( gui );
  jsonp_close_envelope( gui );
}

void
fd_gui_printf_summary_ping( fd_gui_t * gui,
                            ulong      id ) {
  jsonp_open_envelope( gui, "summary", "ping" );
    jsonp_ulong( gui, "id", id );
    jsonp_null( gui, "value" );
  jsonp_close_envelope( gui );
}

void
fd_gui_printf_slot_request( fd_gui_t * gui,
                            ulong      _slot,
                            ulong      id ) {
  fd_gui_slot_t * slot = gui->slots[ _slot % FD_GUI_SLOTS_CNT ];

  char const * level;
  switch( slot->level ) {
    case FD_GUI_SLOT_LEVEL_INCOMPLETE:               level = "incomplete"; break;
    case FD_GUI_SLOT_LEVEL_COMPLETED:                level = "completed";  break;
    case FD_GUI_SLOT_LEVEL_OPTIMISTICALLY_CONFIRMED: level = "optimistically_confirmed"; break;
    case FD_GUI_SLOT_LEVEL_ROOTED:                   level = "rooted"; break;
    case FD_GUI_SLOT_LEVEL_FINALIZED:                level = "finalized"; break;
    default:                                         level = "unknown"; break;
  }

  fd_gui_slot_t * parent_slot = gui->slots[ slot->parent_slot % FD_GUI_SLOTS_CNT ];
  if( FD_UNLIKELY( parent_slot->slot!=slot->parent_slot ) ) parent_slot = NULL;

  long duration_nanos = LONG_MAX;
  if( FD_LIKELY( slot->completed_time!=LONG_MAX && parent_slot && parent_slot->completed_time!=LONG_MAX ) ) {
    duration_nanos = slot->completed_time - parent_slot->completed_time;
  }

  jsonp_open_envelope( gui, "slot", "query" );
    jsonp_ulong( gui, "id", id );
    jsonp_open_object( gui, "value" );

      jsonp_open_object( gui, "publish" );
        jsonp_ulong( gui, "slot", _slot );
        jsonp_bool( gui, "mine", slot->mine );
        jsonp_bool( gui, "skipped", slot->skipped );
        jsonp_string( gui, "level", level );
        if( FD_UNLIKELY( duration_nanos==LONG_MAX ) ) jsonp_null( gui, "duration_nanos" );
        else                                          jsonp_long( gui, "duration_nanos", duration_nanos );
        if( FD_UNLIKELY( slot->completed_time==LONG_MAX ) ) jsonp_null( gui, "completed_time_nanos" );
        else                                                jsonp_long( gui, "completed_time_nanos", slot->completed_time );
        if( FD_UNLIKELY( slot->total_txn_cnt==UINT_MAX
                         || slot->vote_txn_cnt==UINT_MAX
                         || slot->nonvote_failed_txn_cnt==UINT_MAX ) ) jsonp_null( gui, "success_nonvote_transaction_cnt" );
        else                                                           jsonp_ulong( gui, "success_nonvote_transaction_cnt", slot->total_txn_cnt - slot->vote_txn_cnt - slot->nonvote_failed_txn_cnt );
        if( FD_UNLIKELY( slot->nonvote_failed_txn_cnt==UINT_MAX ) ) jsonp_null( gui, "failed_nonvote_transaction_cnt" );
        else                                                        jsonp_ulong( gui, "failed_nonvote_transaction_cnt", slot->nonvote_failed_txn_cnt );
        if( FD_UNLIKELY( slot->vote_txn_cnt==UINT_MAX
                         || slot->failed_txn_cnt==UINT_MAX
                         || slot->nonvote_failed_txn_cnt==UINT_MAX ) ) jsonp_null( gui, "success_vote_transaction_cnt" );
        else                                                           jsonp_ulong( gui, "success_vote_transaction_cnt", slot->vote_txn_cnt - (slot->failed_txn_cnt - slot->nonvote_failed_txn_cnt) );
        if( FD_UNLIKELY( slot->failed_txn_cnt==UINT_MAX
                         || slot->nonvote_failed_txn_cnt==UINT_MAX ) ) jsonp_null( gui, "failed_vote_transaction_cnt" );
        else                                                           jsonp_ulong( gui, "failed_vote_transaction_cnt", slot->failed_txn_cnt - slot->nonvote_failed_txn_cnt );
        if( FD_UNLIKELY( slot->max_compute_units==UINT_MAX ) ) jsonp_null( gui, "max_compute_units" );
        else                                                       jsonp_ulong( gui, "max_compute_units", slot->max_compute_units );
        if( FD_UNLIKELY( slot->compute_units==UINT_MAX ) ) jsonp_null( gui, "compute_units" );
        else                                               jsonp_ulong( gui, "compute_units", slot->compute_units );
        if( FD_UNLIKELY( slot->transaction_fee==ULONG_MAX ) ) jsonp_null( gui, "transaction_fee" );
        else                                                  jsonp_ulong( gui, "transaction_fee", slot->transaction_fee );
        if( FD_UNLIKELY( slot->priority_fee==ULONG_MAX ) ) jsonp_null( gui, "priority_fee" );
        else                                               jsonp_ulong( gui, "priority_fee", slot->priority_fee );
        if( FD_UNLIKELY( slot->tips==ULONG_MAX ) ) jsonp_null( gui, "tips" );
        else                                       jsonp_ulong( gui, "tips", slot->tips );
      jsonp_close_object( gui );

    jsonp_close_object( gui );
  jsonp_close_envelope( gui );
}

void
fd_gui_printf_slot_transactions_request( fd_gui_t * gui,
                                         ulong      _slot,
                                         ulong      id ) {
  fd_gui_slot_t * slot = gui->slots[ _slot % FD_GUI_SLOTS_CNT ];

  char const * level;
  switch( slot->level ) {
    case FD_GUI_SLOT_LEVEL_INCOMPLETE:               level = "incomplete"; break;
    case FD_GUI_SLOT_LEVEL_COMPLETED:                level = "completed";  break;
    case FD_GUI_SLOT_LEVEL_OPTIMISTICALLY_CONFIRMED: level = "optimistically_confirmed"; break;
    case FD_GUI_SLOT_LEVEL_ROOTED:                   level = "rooted"; break;
    case FD_GUI_SLOT_LEVEL_FINALIZED:                level = "finalized"; break;
    default:                                         level = "unknown"; break;
  }

  fd_gui_slot_t * parent_slot = gui->slots[ slot->parent_slot % FD_GUI_SLOTS_CNT ];
  if( FD_UNLIKELY( parent_slot->slot!=slot->parent_slot ) ) parent_slot = NULL;

  long duration_nanos = LONG_MAX;
  if( FD_LIKELY( slot->completed_time!=LONG_MAX && parent_slot && parent_slot->completed_time!=LONG_MAX ) ) {
    duration_nanos = slot->completed_time - parent_slot->completed_time;
  }

  jsonp_open_envelope( gui, "slot", "query" );
    jsonp_ulong( gui, "id", id );
    jsonp_open_object( gui, "value" );

      jsonp_open_object( gui, "publish" );
        jsonp_ulong( gui, "slot", _slot );
        jsonp_bool( gui, "mine", slot->mine );
        jsonp_bool( gui, "skipped", slot->skipped );
        jsonp_string( gui, "level", level );
        if( FD_UNLIKELY( duration_nanos==LONG_MAX ) ) jsonp_null( gui, "duration_nanos" );
        else                                          jsonp_long( gui, "duration_nanos", duration_nanos );
        if( FD_UNLIKELY( slot->completed_time==LONG_MAX ) ) jsonp_null( gui, "completed_time_nanos" );
        else                                                jsonp_long( gui, "completed_time_nanos", slot->completed_time );
        if( FD_UNLIKELY( slot->total_txn_cnt==UINT_MAX
                         || slot->vote_txn_cnt==UINT_MAX
                         || slot->nonvote_failed_txn_cnt==UINT_MAX ) ) jsonp_null( gui, "success_nonvote_transaction_cnt" );
        else                                                           jsonp_ulong( gui, "success_nonvote_transaction_cnt", slot->total_txn_cnt - slot->vote_txn_cnt - slot->nonvote_failed_txn_cnt );
        if( FD_UNLIKELY( slot->nonvote_failed_txn_cnt==UINT_MAX ) ) jsonp_null( gui, "failed_nonvote_transaction_cnt" );
        else                                                        jsonp_ulong( gui, "failed_nonvote_transaction_cnt", slot->nonvote_failed_txn_cnt );
        if( FD_UNLIKELY( slot->vote_txn_cnt==UINT_MAX
                         || slot->failed_txn_cnt==UINT_MAX
                         || slot->nonvote_failed_txn_cnt==UINT_MAX ) ) jsonp_null( gui, "success_vote_transaction_cnt" );
        else                                                           jsonp_ulong( gui, "success_vote_transaction_cnt", slot->vote_txn_cnt - (slot->failed_txn_cnt - slot->nonvote_failed_txn_cnt) );
        if( FD_UNLIKELY( slot->failed_txn_cnt==UINT_MAX
                         || slot->nonvote_failed_txn_cnt==UINT_MAX ) ) jsonp_null( gui, "failed_vote_transaction_cnt" );
        else                                                           jsonp_ulong( gui, "failed_vote_transaction_cnt", slot->failed_txn_cnt - slot->nonvote_failed_txn_cnt );
        if( FD_UNLIKELY( slot->max_compute_units==UINT_MAX ) ) jsonp_null( gui, "max_compute_units" );
        else                                                       jsonp_ulong( gui, "max_compute_units", slot->max_compute_units );
        if( FD_UNLIKELY( slot->compute_units==UINT_MAX ) ) jsonp_null( gui, "compute_units" );
        else                                               jsonp_ulong( gui, "compute_units", slot->compute_units );
        if( FD_UNLIKELY( slot->transaction_fee==ULONG_MAX ) ) jsonp_null( gui, "transaction_fee" );
        else                                                  jsonp_ulong( gui, "transaction_fee", slot->transaction_fee );
        if( FD_UNLIKELY( slot->priority_fee==ULONG_MAX ) ) jsonp_null( gui, "priority_fee" );
        else                                               jsonp_ulong( gui, "priority_fee", slot->priority_fee );
        if( FD_UNLIKELY( slot->tips==ULONG_MAX ) ) jsonp_null( gui, "tips" );
        else                                       jsonp_ulong( gui, "tips", slot->tips );
      jsonp_close_object( gui );

      int overwritten               = (gui->pack_txn_idx - slot->txs.start_offset)>FD_GUI_TXN_HISTORY_SZ;
      int processed_all_microblocks = slot->slot!=ULONG_MAX &&
                                      slot->txs.microblocks_upper_bound!=USHORT_MAX &&
                                      slot->txs.begin_microblocks==slot->txs.end_microblocks &&
                                      slot->txs.begin_microblocks==slot->txs.microblocks_upper_bound;

      if( FD_LIKELY( !overwritten && processed_all_microblocks ) ) {
        ulong txn_cnt = slot->txs.end_offset-slot->txs.start_offset;

        jsonp_open_object( gui, "transactions" );
          jsonp_long_as_str( gui, "start_timestamp_nanos", slot->txs.leader_start_time );
          jsonp_long_as_str( gui, "target_end_timestamp_nanos", slot->txs.leader_end_time );
          jsonp_open_array( gui, "txn_mb_start_timestamps_nanos" );
            for( ulong i=0UL; i<txn_cnt; i++) jsonp_long_as_str( gui, NULL, slot->txs.reference_nanos + (long)gui->txs[ (slot->txs.start_offset + i)%FD_GUI_TXN_HISTORY_SZ ]->timestamp_delta_start_nanos );
          jsonp_close_array( gui );
          jsonp_open_array( gui, "txn_mb_end_timestamps_nanos" );
            /* clamp end_ts to start_ts + 1 */
            for( ulong i=0UL; i<txn_cnt; i++) {
              jsonp_long_as_str( gui, NULL, slot->txs.reference_nanos + fd_long_max( (long)gui->txs[ (slot->txs.start_offset + i)%FD_GUI_TXN_HISTORY_SZ ]->timestamp_delta_end_nanos,
                                                                                     (long)gui->txs[ (slot->txs.start_offset + i)%FD_GUI_TXN_HISTORY_SZ ]->timestamp_delta_start_nanos + 1L ) );
            }
          jsonp_close_array( gui );
          jsonp_open_array( gui, "txn_compute_units_requested" );
            for( ulong i=0UL; i<txn_cnt; i++) jsonp_ulong( gui, NULL, gui->txs[ (slot->txs.start_offset + i)%FD_GUI_TXN_HISTORY_SZ ]->compute_units_requested );
          jsonp_close_array( gui );
          jsonp_open_array( gui, "txn_compute_units_consumed" );
            for( ulong i=0UL; i<txn_cnt; i++) jsonp_ulong( gui, NULL, gui->txs[ (slot->txs.start_offset + i)%FD_GUI_TXN_HISTORY_SZ ]->compute_units_consumed );
          jsonp_close_array( gui );
          jsonp_open_array( gui, "txn_priority_fee" );
            for( ulong i=0UL; i<txn_cnt; i++) jsonp_ulong_as_str( gui, NULL, gui->txs[ (slot->txs.start_offset + i)%FD_GUI_TXN_HISTORY_SZ ]->priority_fee );
          jsonp_close_array( gui );
          jsonp_open_array( gui, "txn_transaction_fee" );
            for( ulong i=0UL; i<txn_cnt; i++) jsonp_ulong_as_str( gui, NULL, gui->txs[ (slot->txs.start_offset + i)%FD_GUI_TXN_HISTORY_SZ ]->transaction_fee );
          jsonp_close_array( gui );
          jsonp_open_array( gui, "txn_error_code" );
            for( ulong i=0UL; i<txn_cnt; i++) jsonp_ulong( gui, NULL, gui->txs[ (slot->txs.start_offset + i)%FD_GUI_TXN_HISTORY_SZ ]->error_code );
          jsonp_close_array( gui );
          jsonp_open_array( gui, "txn_from_bundle" );
            for( ulong i=0UL; i<txn_cnt; i++) jsonp_bool( gui, NULL, gui->txs[ (slot->txs.start_offset + i)%FD_GUI_TXN_HISTORY_SZ ]->flags & FD_GUI_TXN_FLAGS_FROM_BUNDLE );
          jsonp_close_array( gui );
          jsonp_open_array( gui, "txn_is_simple_vote" );
            for( ulong i=0UL; i<txn_cnt; i++) jsonp_bool( gui, NULL, gui->txs[ (slot->txs.start_offset + i)%FD_GUI_TXN_HISTORY_SZ ]->flags & FD_GUI_TXN_FLAGS_IS_SIMPLE_VOTE );
          jsonp_close_array( gui );
          jsonp_open_array( gui, "txn_bank_idx" );
            for( ulong i=0UL; i<txn_cnt; i++) jsonp_ulong( gui, NULL, gui->txs[ (slot->txs.start_offset + i)%FD_GUI_TXN_HISTORY_SZ ]->bank_idx );
          jsonp_close_array( gui );
          jsonp_open_array( gui, "txn_preload_end_timestamps_nanos" );
            for( ulong i=0UL; i<txn_cnt; i++) {
              fd_gui_txn_t * txn = gui->txs[ (slot->txs.start_offset + i)%FD_GUI_TXN_HISTORY_SZ ];
              long microblock_duration = (long)txn->timestamp_delta_end_nanos - (long)txn->timestamp_delta_start_nanos;
              long timestamp_delta_preload_end = (long)txn->timestamp_delta_start_nanos + (long)((double)txn->txn_preload_end_pct * (double)microblock_duration / (double)UCHAR_MAX);
              jsonp_long_as_str( gui, NULL, slot->txs.reference_nanos + timestamp_delta_preload_end );
            }
          jsonp_close_array( gui );
          jsonp_open_array( gui, "txn_start_timestamps_nanos" );
            for( ulong i=0UL; i<txn_cnt; i++) {
              fd_gui_txn_t * txn = gui->txs[ (slot->txs.start_offset + i)%FD_GUI_TXN_HISTORY_SZ ];
              long microblock_duration = (long)txn->timestamp_delta_end_nanos - (long)txn->timestamp_delta_start_nanos;
              long timestamp_delta_validate_end = (long)txn->timestamp_delta_start_nanos + (long)((double)txn->txn_start_pct * (double)microblock_duration / (double)UCHAR_MAX);
              jsonp_long_as_str( gui, NULL, slot->txs.reference_nanos + timestamp_delta_validate_end );
            }
          jsonp_close_array( gui );
          jsonp_open_array( gui, "txn_load_end_timestamps_nanos" );
            for( ulong i=0UL; i<txn_cnt; i++) {
              fd_gui_txn_t * txn = gui->txs[ (slot->txs.start_offset + i)%FD_GUI_TXN_HISTORY_SZ ];
              long microblock_duration = (long)txn->timestamp_delta_end_nanos - (long)txn->timestamp_delta_start_nanos;
              long timestamp_delta_load_end = (long)txn->timestamp_delta_start_nanos + (long)((double)txn->txn_load_end_pct * (double)microblock_duration / (double)UCHAR_MAX);
              jsonp_long_as_str( gui, NULL, slot->txs.reference_nanos + timestamp_delta_load_end );
            }
          jsonp_close_array( gui );
          jsonp_open_array( gui, "txn_end_timestamps_nanos" );
            for( ulong i=0UL; i<txn_cnt; i++) {
              fd_gui_txn_t * txn = gui->txs[ (slot->txs.start_offset + i)%FD_GUI_TXN_HISTORY_SZ ];
              long microblock_duration = (long)txn->timestamp_delta_end_nanos - (long)txn->timestamp_delta_start_nanos;
              long timestamp_delta_exec_end = (long)txn->timestamp_delta_start_nanos + (long)((double)txn->txn_end_pct * (double)microblock_duration / (double)UCHAR_MAX);
              jsonp_long_as_str( gui, NULL, slot->txs.reference_nanos + timestamp_delta_exec_end );
            }
          jsonp_close_array( gui );
          jsonp_open_array( gui, "txn_arrival_timestamps_nanos" );
            for( ulong i=0UL; i<txn_cnt; i++) jsonp_long_as_str( gui, NULL, gui->txs[ (slot->txs.start_offset + i)%FD_GUI_TXN_HISTORY_SZ ]->timestamp_arrival_nanos );
          jsonp_close_array( gui );
          jsonp_open_array( gui, "txn_tips" );
            for( ulong i=0UL; i<txn_cnt; i++) jsonp_ulong_as_str( gui, NULL, gui->txs[ (slot->txs.start_offset + i)%FD_GUI_TXN_HISTORY_SZ ]->tips );
          jsonp_close_array( gui );
          jsonp_open_array( gui, "txn_source_ipv4" );
            for( ulong i=0UL; i<txn_cnt; i++) {
              char addr[ 64 ];
              fd_cstr_printf_check( addr, sizeof(addr), NULL, FD_IP4_ADDR_FMT, FD_IP4_ADDR_FMT_ARGS( gui->txs[ (slot->txs.start_offset + i)%FD_GUI_TXN_HISTORY_SZ ]->source_ipv4 ) );
              jsonp_string( gui, NULL, addr );
            }
          jsonp_close_array( gui );
          jsonp_open_array( gui, "txn_source_tpu" );
            for( ulong i=0UL; i<txn_cnt; i++) {
              switch ( gui->txs[ (slot->txs.start_offset + i)%FD_GUI_TXN_HISTORY_SZ ]->source_tpu ) {
                case FD_TXN_M_TPU_SOURCE_QUIC: {
                  jsonp_string( gui, NULL, "quic");
                  break;
                }
                case FD_TXN_M_TPU_SOURCE_UDP   : {
                  jsonp_string( gui, NULL, "udp");
                  break;
                }
                case FD_TXN_M_TPU_SOURCE_GOSSIP: {
                  jsonp_string( gui, NULL, "gossip");
                  break;
                }
                case FD_TXN_M_TPU_SOURCE_BUNDLE: {
                  jsonp_string( gui, NULL, "bundle");
                  break;
                }
                case FD_TXN_M_TPU_SOURCE_SEND  : {
                  jsonp_string( gui, NULL, "send");
                  break;
                }
                default: FD_LOG_ERR(("unknown tpu"));
              }
            }
          jsonp_close_array( gui );
          jsonp_open_array( gui, "txn_microblock_id" );
            for( ulong i=0UL; i<txn_cnt; i++) jsonp_ulong( gui, NULL, gui->txs[ (slot->txs.start_offset + i)%FD_GUI_TXN_HISTORY_SZ ]->microblock_idx );
          jsonp_close_array( gui );
          jsonp_open_array( gui, "txn_landed" );
            for( ulong i=0UL; i<txn_cnt; i++) jsonp_bool( gui, NULL, gui->txs[ (slot->txs.start_offset + i)%FD_GUI_TXN_HISTORY_SZ ]->flags & FD_GUI_TXN_FLAGS_LANDED_IN_BLOCK );
          jsonp_close_array( gui );
          jsonp_open_array( gui, "txn_signature" );
            for( ulong i=0UL; i<txn_cnt; i++) {
              FD_BASE58_ENCODE_64_BYTES( gui->txs[ (slot->txs.start_offset + i)%FD_GUI_TXN_HISTORY_SZ ]->signature, encoded_signature );
              jsonp_string( gui, NULL, encoded_signature );
            }
          jsonp_close_array( gui );
        jsonp_close_object( gui );
      } else {
        jsonp_null( gui, "compute_units" );
      }

    jsonp_close_object( gui );
  jsonp_close_envelope( gui );
}

void
fd_gui_printf_slot_request_detailed( fd_gui_t * gui,
                                     ulong      _slot,
                                     ulong      id ) {
  fd_gui_slot_t * slot = gui->slots[ _slot % FD_GUI_SLOTS_CNT ];

  char const * level;
  switch( slot->level ) {
    case FD_GUI_SLOT_LEVEL_INCOMPLETE:               level = "incomplete"; break;
    case FD_GUI_SLOT_LEVEL_COMPLETED:                level = "completed";  break;
    case FD_GUI_SLOT_LEVEL_OPTIMISTICALLY_CONFIRMED: level = "optimistically_confirmed"; break;
    case FD_GUI_SLOT_LEVEL_ROOTED:                   level = "rooted"; break;
    case FD_GUI_SLOT_LEVEL_FINALIZED:                level = "finalized"; break;
    default:                                         level = "unknown"; break;
  }

  fd_gui_slot_t * parent_slot = gui->slots[ slot->parent_slot % FD_GUI_SLOTS_CNT ];
  if( FD_UNLIKELY( parent_slot->slot!=slot->parent_slot ) ) parent_slot = NULL;

  long duration_nanos = LONG_MAX;
  if( FD_LIKELY( slot->completed_time!=LONG_MAX && parent_slot && parent_slot->completed_time!=LONG_MAX ) ) {
    duration_nanos = slot->completed_time - parent_slot->completed_time;
  }

  jsonp_open_envelope( gui, "slot", "query" );
    jsonp_ulong( gui, "id", id );
    jsonp_open_object( gui, "value" );

      jsonp_open_object( gui, "publish" );
        jsonp_ulong( gui, "slot", _slot );
        jsonp_bool( gui, "mine", slot->mine );
        jsonp_bool( gui, "skipped", slot->skipped );
        jsonp_string( gui, "level", level );
        if( FD_UNLIKELY( duration_nanos==LONG_MAX ) ) jsonp_null( gui, "duration_nanos" );
        else                                          jsonp_long( gui, "duration_nanos", duration_nanos );
        if( FD_UNLIKELY( slot->completed_time==LONG_MAX ) ) jsonp_null( gui, "completed_time_nanos" );
        else                                                jsonp_long( gui, "completed_time_nanos", slot->completed_time );
        if( FD_UNLIKELY( slot->total_txn_cnt==UINT_MAX
                         || slot->vote_txn_cnt==UINT_MAX
                         || slot->nonvote_failed_txn_cnt==UINT_MAX ) ) jsonp_null( gui, "success_nonvote_transaction_cnt" );
        else                                                           jsonp_ulong( gui, "success_nonvote_transaction_cnt", slot->total_txn_cnt - slot->vote_txn_cnt - slot->nonvote_failed_txn_cnt );
        if( FD_UNLIKELY( slot->nonvote_failed_txn_cnt==UINT_MAX ) ) jsonp_null( gui, "failed_nonvote_transaction_cnt" );
        else                                                        jsonp_ulong( gui, "failed_nonvote_transaction_cnt", slot->nonvote_failed_txn_cnt );
        if( FD_UNLIKELY( slot->vote_txn_cnt==UINT_MAX
                         || slot->failed_txn_cnt==UINT_MAX
                         || slot->nonvote_failed_txn_cnt==UINT_MAX ) ) jsonp_null( gui, "success_vote_transaction_cnt" );
        else                                                           jsonp_ulong( gui, "success_vote_transaction_cnt", slot->vote_txn_cnt - (slot->failed_txn_cnt - slot->nonvote_failed_txn_cnt) );
        if( FD_UNLIKELY( slot->failed_txn_cnt==UINT_MAX
                         || slot->nonvote_failed_txn_cnt==UINT_MAX ) ) jsonp_null( gui, "failed_vote_transaction_cnt" );
        else                                                           jsonp_ulong( gui, "failed_vote_transaction_cnt", slot->failed_txn_cnt - slot->nonvote_failed_txn_cnt );
        if( FD_UNLIKELY( slot->max_compute_units==UINT_MAX ) ) jsonp_null( gui, "max_compute_units" );
        else                                                   jsonp_ulong( gui, "max_compute_units", slot->max_compute_units );
        if( FD_UNLIKELY( slot->compute_units==UINT_MAX ) ) jsonp_null( gui, "compute_units" );
        else                                               jsonp_ulong( gui, "compute_units", slot->compute_units );
        if( FD_UNLIKELY( slot->transaction_fee==ULONG_MAX ) ) jsonp_null( gui, "transaction_fee" );
        else                                                  jsonp_ulong( gui, "transaction_fee", slot->transaction_fee );
        if( FD_UNLIKELY( slot->priority_fee==ULONG_MAX ) ) jsonp_null( gui, "priority_fee" );
        else                                               jsonp_ulong( gui, "priority_fee", slot->priority_fee );
        if( FD_UNLIKELY( slot->tips==ULONG_MAX ) ) jsonp_null( gui, "tips" );
        else                                       jsonp_ulong( gui, "tips", slot->tips );
      jsonp_close_object( gui );

      if( FD_LIKELY( slot->leader_state==FD_GUI_SLOT_LEADER_ENDED ) ) {
        fd_gui_printf_waterfall( gui, slot->waterfall_begin, slot->waterfall_end );

        if( FD_LIKELY( gui->summary.tile_timers_leader_history_slot[ slot->tile_timers_history_idx ]==_slot ) ) {
          jsonp_open_array( gui, "tile_timers" );
            fd_gui_tile_timers_t const * prev_timer = gui->summary.tile_timers_leader_history[ slot->tile_timers_history_idx ][ 0 ];
            for( ulong i=1UL; i<gui->summary.tile_timers_leader_history_slot_sample_cnt[ slot->tile_timers_history_idx ]; i++ ) {
              fd_gui_tile_timers_t const * cur_timer = gui->summary.tile_timers_leader_history[ slot->tile_timers_history_idx ][ i ];
              fd_gui_printf_ts_tile_timers( gui, prev_timer, cur_timer );
              prev_timer = cur_timer;
            }
          jsonp_close_array( gui );
        } else {
          /* Our tile timers were overwritten. */
          jsonp_null( gui, "tile_timers" );
        }

        fd_gui_printf_tile_stats( gui, slot->tile_stats_begin, slot->tile_stats_end );
      } else {
        jsonp_null( gui, "waterfall" );
        jsonp_null( gui, "tile_timers" );
        jsonp_null( gui, "tile_primary_metric" );
      }

    jsonp_close_object( gui );
  jsonp_close_envelope( gui );
}
