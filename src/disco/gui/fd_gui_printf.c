#include "fd_gui_printf.h"
#include "fd_gui_config_parse.h"
#include "fd_gui_hist.h"

#include "../bundle/fd_bundle_tile.h"
#include "../diag/fd_diag_tile.h"
#include "../../waltz/http/fd_http_server_private.h"
#include "../../ballet/utf8/fd_utf8.h"
#include "../../disco/fd_txn_m.h"
#include "../../disco/metrics/fd_metrics.h"
#include "../../disco/topo/fd_topob.h"

static void
jsonp_strip_trailing_comma( fd_http_server_t * http ) {
  if( FD_LIKELY( !http->stage_err &&
                 http->stage_len>=1UL &&
                 http->oring[ (http->stage_off%http->oring_sz)+http->stage_len-1UL ]==(uchar)',' ) ) {
    http->stage_len--;
  }
}

static void
jsonp_open_object( fd_http_server_t * http,
                   char const *       key ) {
  if( FD_LIKELY( key ) ) fd_http_server_printf( http, "\"%s\":{", key );
  else                   fd_http_server_printf( http, "{" );
}

static void
jsonp_close_object( fd_http_server_t * http ) {
  jsonp_strip_trailing_comma( http );
  fd_http_server_printf( http, "}," );
}

static void
jsonp_open_array( fd_http_server_t * http,
                  char const *       key ) {
  if( FD_LIKELY( key ) ) fd_http_server_printf( http, "\"%s\":[", key );
  else                   fd_http_server_printf( http, "[" );
}

static void
jsonp_close_array( fd_http_server_t * http ) {
  jsonp_strip_trailing_comma( http );
  fd_http_server_printf( http, "]," );
}

static void
jsonp_ulong( fd_http_server_t * http,
             char const *       key,
             ulong              value ) {
  if( FD_LIKELY( key ) ) fd_http_server_printf( http, "\"%s\":%lu,", key, value );
  else                   fd_http_server_printf( http, "%lu,", value );
}

static void
jsonp_long( fd_http_server_t * http,
            char const *       key,
            long               value ) {
  if( FD_LIKELY( key ) ) fd_http_server_printf( http, "\"%s\":%ld,", key, value );
  else                   fd_http_server_printf( http, "%ld,", value );
}

static void
jsonp_double( fd_http_server_t * http,
              char const *       key,
              double             value ) {
  if( FD_LIKELY( key ) ) fd_http_server_printf( http, "\"%s\":%.2f,", key, value );
  else                   fd_http_server_printf( http, "%.2f,", value );
}

static void
jsonp_ulong_as_str( fd_http_server_t * http,
                    char const *       key,
                    ulong              value ) {
  if( FD_LIKELY( key ) ) fd_http_server_printf( http, "\"%s\":\"%lu\",", key, value );
  else                   fd_http_server_printf( http, "\"%lu\",", value );
}

static void
jsonp_long_as_str( fd_http_server_t * http,
                   char const *       key,
                   long               value ) {
  if( FD_LIKELY( key ) ) fd_http_server_printf( http, "\"%s\":\"%ld\",", key, value );
  else                   fd_http_server_printf( http, "\"%ld\",", value );
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
jsonp_string( fd_http_server_t * http,
              char const *       key,
              char const *       value ) {
  char * val = (void *)value;
  if( FD_LIKELY( value ) ) {
    if( FD_UNLIKELY( !fd_utf8_verify( value, strlen( value ) ) )) {
      val = NULL;
    }
  }
  if( FD_LIKELY( key ) ) fd_http_server_printf( http, "\"%s\":", key );
  if( FD_LIKELY( val ) ) {
    fd_http_server_printf( http, "\"" );
    ulong start_len = http->stage_len;
    fd_http_server_printf( http, "%s", val );
    jsonp_sanitize_str( http, start_len );
    fd_http_server_printf( http, "\"," );
  } else {
    fd_http_server_printf( http, "null," );
  }
}

static void
jsonp_bool( fd_http_server_t * http,
            char const *       key,
            int                value ) {
  if( FD_LIKELY( key ) ) fd_http_server_printf( http, "\"%s\":%s,", key, value ? "true" : "false" );
  else                   fd_http_server_printf( http, "%s,", value ? "true" : "false" );
}

static void
jsonp_null( fd_http_server_t * http,
            char const *       key ) {
  if( FD_LIKELY( key ) ) fd_http_server_printf( http, "\"%s\": null,", key );
  else                   fd_http_server_printf( http, "null," );
}

static void
jsonp_open_envelope( fd_http_server_t * http,
                     char const *       topic,
                     char const *       key ) {
  jsonp_open_object( http, NULL );
  jsonp_string( http, "topic", topic );
  jsonp_string( http, "key",   key );
}

static void
jsonp_close_envelope( fd_http_server_t * http ) {
  jsonp_close_object( http );
  jsonp_strip_trailing_comma( http );
}

void
fd_gui_printf_open_query_response_envelope( fd_http_server_t * http,
                                            char const *       topic,
                                            char const *       key,
                                            ulong              id ) {
  jsonp_open_object( http, NULL );
  jsonp_string( http, "topic", topic );
  jsonp_string( http, "key", key );
  jsonp_ulong( http, "id", id );
}

void
fd_gui_printf_close_query_response_envelope( fd_http_server_t * http ) {
  jsonp_close_object( http );
  jsonp_strip_trailing_comma( http );
}

void
fd_gui_printf_null_query_response( fd_http_server_t * http,
                                   char const *       topic,
                                   char const *       key,
                                   ulong              id ) {
  fd_gui_printf_open_query_response_envelope( http, topic, key, id );
    jsonp_null( http, "value" );
  fd_gui_printf_close_query_response_envelope( http );
}

void
fd_gui_printf_version( fd_gui_t * gui ) {
  jsonp_open_envelope( gui->http, "summary", "version" );
    jsonp_string( gui->http, "value", gui->summary.version );
  jsonp_close_envelope( gui->http );
}

void
fd_gui_printf_cluster( fd_gui_t * gui ) {
  jsonp_open_envelope( gui->http, "summary", "cluster" );
    jsonp_string( gui->http, "value", gui->summary.cluster );
  jsonp_close_envelope( gui->http );
}

void
fd_gui_printf_commit_hash( fd_gui_t * gui ) {
  jsonp_open_envelope( gui->http, "summary", "commit_hash" );
    jsonp_string( gui->http, "value", fd_commit_ref_cstr );
  jsonp_close_envelope( gui->http );
}

void
fd_gui_printf_identity_key( fd_gui_t * gui ) {
  jsonp_open_envelope( gui->http, "summary", "identity_key" );
    jsonp_string( gui->http, "value", gui->summary.identity_key_base58 );
  jsonp_close_envelope( gui->http );
}

void
fd_gui_printf_vote_key( fd_gui_t * gui ) {
  jsonp_open_envelope( gui->http, "summary", "vote_key" );
    if( FD_LIKELY( gui->summary.has_vote_key ) ) jsonp_string( gui->http, "value", gui->summary.vote_key_base58 );
    else                                         jsonp_null( gui->http, "value" );
  jsonp_close_envelope( gui->http );
}

void
fd_gui_printf_startup_time_nanos( fd_gui_t * gui ) {
  jsonp_open_envelope( gui->http, "summary", "startup_time_nanos" );
    jsonp_long_as_str( gui->http, "value", gui->summary.startup_time_nanos );
  jsonp_close_envelope( gui->http );
}

void
fd_gui_printf_server_time_nanos( fd_gui_t * gui, long now ) {
  jsonp_open_envelope( gui->http, "summary", "server_time_nanos" );
    jsonp_long_as_str( gui->http, "value", now );
  jsonp_close_envelope( gui->http );
}

void
fd_gui_printf_vote_distance( fd_gui_t * gui ) {
  jsonp_open_envelope( gui->http, "summary", "vote_distance" );
    jsonp_ulong( gui->http, "value", gui->summary.vote_distance );
  jsonp_close_envelope( gui->http );
}

void
fd_gui_printf_repair_slot( fd_gui_t * gui ) {
  jsonp_open_envelope( gui->http, "summary", "repair_slot" );
    if( FD_LIKELY( gui->summary.slot_repair!=ULONG_MAX  ) ) jsonp_ulong( gui->http, "value", gui->summary.slot_repair );
    else                                                    jsonp_null ( gui->http, "value" );
  jsonp_close_envelope( gui->http );
}

void
fd_gui_peers_printf_vote_slot( fd_gui_peers_ctx_t * peers ) {
  jsonp_open_envelope( peers->http, "summary", "vote_slot" );
    if( FD_LIKELY( peers->slot_voted!=ULONG_MAX  ) ) jsonp_ulong( peers->http, "value", peers->slot_voted );
    else                                             jsonp_null ( peers->http, "value" );
  jsonp_close_envelope( peers->http );
}

void
fd_gui_printf_turbine_slot( fd_gui_t * gui ) {
  jsonp_open_envelope( gui->http, "summary", "turbine_slot" );
    if( FD_LIKELY( gui->summary.slot_turbine!=ULONG_MAX  ) ) jsonp_ulong( gui->http, "value", gui->summary.slot_turbine );
    else                                                     jsonp_null ( gui->http, "value" );
  jsonp_close_envelope( gui->http );
}

void
fd_gui_printf_reset_slot( fd_gui_t * gui ) {
  jsonp_open_envelope( gui->http, "summary", "reset_slot" );
    if( FD_LIKELY( gui->summary.slot_reset!=ULONG_MAX  ) ) jsonp_ulong( gui->http, "value", gui->summary.slot_reset );
    else                                                   jsonp_null ( gui->http, "value" );
  jsonp_close_envelope( gui->http );
}

void
fd_gui_printf_storage_slot( fd_gui_t * gui ) {
  jsonp_open_envelope( gui->http, "summary", "storage_slot" );
    if( FD_LIKELY( gui->summary.slot_storage!=ULONG_MAX  ) ) jsonp_ulong( gui->http, "value", gui->summary.slot_storage );
    else                                                     jsonp_null ( gui->http, "value" );
  jsonp_close_envelope( gui->http );
}

void
fd_gui_printf_active_fork_cnt( fd_gui_t * gui ) {
  jsonp_open_envelope( gui->http, "summary", "active_fork_count" );
    if( FD_LIKELY( gui->summary.active_fork_cnt!=ULONG_MAX  ) ) jsonp_ulong( gui->http, "value", gui->summary.active_fork_cnt );
    else                                                        jsonp_null ( gui->http, "value" );
  jsonp_close_envelope( gui->http );
}

void
fd_gui_printf_slot_caught_up( fd_gui_t * gui ) {
  jsonp_open_envelope( gui->http, "summary", "slot_caught_up" );
    if( FD_LIKELY( gui->summary.slot_caught_up!=ULONG_MAX  ) ) jsonp_ulong( gui->http, "value", gui->summary.slot_caught_up );
    else                                                       jsonp_null ( gui->http, "value" );
  jsonp_close_envelope( gui->http );
}

void
fd_gui_printf_catch_up_history( fd_gui_t * gui ) {
  jsonp_open_envelope( gui->http, "summary", "catch_up_history" );
    jsonp_open_object( gui->http, "value" );
      jsonp_open_array( gui->http, "turbine" );
        for( ulong i=0UL; i<gui->summary.catch_up_turbine_sz; i+=2 ) {
          for( ulong j=gui->summary.catch_up_turbine[ i ]; j<=gui->summary.catch_up_turbine[ i+1UL ]; j++ ) {
            jsonp_ulong( gui->http, NULL, j );
          }
        }
      jsonp_close_array( gui->http );
      jsonp_open_array( gui->http, "repair" );
        for( ulong i=0UL; i<gui->summary.catch_up_repair_sz; i+=2 ) {
          for( ulong j=gui->summary.catch_up_repair[ i ]; j<=gui->summary.catch_up_repair[ i+1UL ]; j++ ) {
            jsonp_ulong( gui->http, NULL, j );
          }
        }
      jsonp_close_array( gui->http );

      if( FD_LIKELY( gui->summary.boot_progress.phase==FD_GUI_BOOT_PROGRESS_TYPE_CATCHING_UP ) ) {
        ulong min_slot = ULONG_MAX;
        long min_ts = LONG_MAX;

#define SHREDS_REV_ITER( age_ns, code_archive ) \
        do { \
          if( FD_UNLIKELY( gui->summary.boot_progress.catching_up_time_nanos==0L ) ) break; \
          void * _db = gui->db; \
          if( FD_LIKELY( _db ) ) { \
            long _hi_ns = gui->summary.boot_progress.catching_up_time_nanos; \
            long _lo_ns = _hi_ns - (long)(age_ns); \
            fd_gui_hist_iter_t _it; \
            if( FD_LIKELY( !fd_gui_hist_range_begin( gui, &_it, FD_GUI_HIST_SHRED_EVENTS, _lo_ns, _hi_ns, NULL, NULL ) ) ) { \
              while( fd_gui_hist_range_next( &_it ) ) { \
                fd_gui_slot_history_shred_event_t const * event = (fd_gui_slot_history_shred_event_t const *)_it.rec; (void)event; \
                ulong db_event_slot = event->slot; (void)db_event_slot; \
                if( FD_UNLIKELY( event->timestamp < _lo_ns ) ) continue; \
                do { code_archive } while (0); \
              } \
              fd_gui_hist_range_end( &_it ); \
            } \
          } \
        } while(0);

        SHREDS_REV_ITER(
          15000000000,
          {
            min_slot = fd_ulong_min( min_slot, db_event_slot );
            min_ts = fd_long_min( min_ts, event->timestamp );
          }
        )

        jsonp_open_object( gui->http, "shreds" );
          jsonp_ulong      ( gui->http, "reference_slot", min_slot );
          jsonp_long_as_str( gui->http, "reference_ts",   min_ts   );

          jsonp_open_array( gui->http, "slot_delta" );
            SHREDS_REV_ITER(
              15000000000L,
              { jsonp_ulong( gui->http, NULL, db_event_slot-min_slot ); }
            )
          jsonp_close_array( gui->http );
          jsonp_open_array( gui->http, "shred_idx" );
            SHREDS_REV_ITER(
              15000000000L,
              {
                if( FD_LIKELY( event->shred_idx!=USHORT_MAX ) ) jsonp_ulong( gui->http, NULL, event->shred_idx );
                else                                            jsonp_null ( gui->http, NULL );
              }
            )
          jsonp_close_array( gui->http );
          jsonp_open_array( gui->http, "event" );
            SHREDS_REV_ITER(
              15000000000L,
              { jsonp_ulong( gui->http, NULL, event->event ); }
            )
          jsonp_close_array( gui->http );
          jsonp_open_array( gui->http, "event_ts_delta" );
            SHREDS_REV_ITER(
              15000000000L,
              { jsonp_long_as_str( gui->http, NULL, event->timestamp-min_ts ); }
            )
          jsonp_close_array( gui->http );
        jsonp_close_object( gui->http );
#undef SHREDS_REV_ITER
      } else {
        jsonp_null( gui->http, "shreds" );
      }

    jsonp_close_object( gui->http );
  jsonp_close_envelope( gui->http );
}

void
fd_gui_printf_vote_state( fd_gui_t * gui ) {
  jsonp_open_envelope( gui->http, "summary", "vote_state" );
    switch( gui->summary.vote_state ) {
      case FD_GUI_VOTE_STATE_NON_VOTING:
        jsonp_string( gui->http, "value", "non-voting" );
        break;
      case FD_GUI_VOTE_STATE_VOTING:
        jsonp_string( gui->http, "value", "voting" );
        break;
      case FD_GUI_VOTE_STATE_DELINQUENT:
        jsonp_string( gui->http, "value", "delinquent" );
        break;
      default:
        FD_LOG_ERR(( "unknown vote state %d", gui->summary.vote_state ));
    }
  jsonp_close_envelope( gui->http );
}

void
fd_gui_printf_skipped_history( fd_gui_t * gui, ulong epoch ) {
  jsonp_open_envelope( gui->http, "slot", "skipped_history" );
    jsonp_open_array( gui->http, "value" );
      ulong first_replay_slot = fd_ulong_if( gui->summary.slot_caught_up!=ULONG_MAX, fd_gui_first_replay_slot( gui ), ULONG_MAX );
      fd_gui_epoch_t const * rec = fd_gui_epoch( gui, epoch );
      ulong epoch_start = FD_LIKELY( rec ) ? rec->start_slot : 0UL;
      ulong start_slot  = fd_ulong_max( epoch_start, first_replay_slot );
      ulong end_slot    = FD_LIKELY( rec ) ? rec->start_slot+rec->slot_cnt-1UL : 0UL; /* inclusive */
      for( ulong s=start_slot; s<=end_slot; s++ ) {
        if( FD_LIKELY( gui->summary.slot_tower==ULONG_MAX ) ) break;
        if( FD_UNLIKELY( s>gui->summary.slot_tower ) ) break;

        fd_gui_slot_t * slot = fd_gui_slot_get_canon_safe( gui, s );
        if( FD_UNLIKELY( !slot->mine ) ) continue;
        if( FD_UNLIKELY( slot->skip==FD_GUI_SKIP_STATUS_SKIPPED ) ) jsonp_ulong( gui->http, NULL, s );
      }
    jsonp_close_array( gui->http );
  jsonp_close_envelope( gui->http );
}

void
fd_gui_printf_skipped_history_cluster( fd_gui_t * gui, ulong epoch ) {
  jsonp_open_envelope( gui->http, "slot", "skipped_history_cluster" );
    jsonp_open_array( gui->http, "value" );
      ulong first_replay_slot = fd_ulong_if( gui->summary.slot_caught_up!=ULONG_MAX, fd_gui_first_replay_slot( gui ), ULONG_MAX );
      fd_gui_epoch_t const * rec = fd_gui_epoch( gui, epoch );
      ulong epoch_start = FD_LIKELY( rec ) ? rec->start_slot : 0UL;
      ulong start_slot  = fd_ulong_max( epoch_start, first_replay_slot );
      ulong end_slot    = FD_LIKELY( rec ) ? rec->start_slot+rec->slot_cnt-1UL : 0UL; /* inclusive */
      for( ulong s=start_slot; s<=end_slot; s++ ) {
        if( FD_LIKELY( gui->summary.slot_tower==ULONG_MAX ) ) break;
        if( FD_UNLIKELY( s>gui->summary.slot_tower ) ) break;
        if( FD_UNLIKELY( fd_gui_slot_get_canon_safe( gui, s )->skip==FD_GUI_SKIP_STATUS_SKIPPED ) ) jsonp_ulong( gui->http, NULL, s );
      }
    jsonp_close_array( gui->http );
  jsonp_close_envelope( gui->http );
}

/* TODO: deprecated */
void
fd_gui_printf_vote_latency_history( fd_gui_t * gui ) {
  fd_gui_epoch_t * rec = fd_gui_current_epoch( gui );
  ulong   lv_sz = FD_LIKELY( rec ) ? rec->late_votes_sz : 0UL;
  ulong * lv    = FD_LIKELY( rec ) ? rec->late_votes    : NULL;
  jsonp_open_envelope( gui->http, "slot", "vote_latency_history" );
      jsonp_open_array( gui->http, "value" );
        FD_TEST( lv_sz % 2UL == 0UL );
        for( ulong i=0UL; i<lv_sz; i++ ) jsonp_ulong( gui->http, NULL, lv[ i ] );
      jsonp_close_array( gui->http );
  jsonp_close_envelope( gui->http );
}

void
fd_gui_printf_late_votes_history( fd_gui_t * gui ) {
  fd_gui_epoch_t * rec = fd_gui_current_epoch( gui );
  ulong   lv_sz = FD_LIKELY( rec ) ? rec->late_votes_sz : 0UL;
  ulong * lv    = FD_LIKELY( rec ) ? rec->late_votes    : NULL;
  jsonp_open_envelope( gui->http, "slot", "late_votes_history" );
      jsonp_open_object( gui->http, "value" );
        jsonp_open_array( gui->http, "slot" );
          for( ulong i=0UL; i<lv_sz; i++ ) jsonp_ulong( gui->http, NULL, lv[ i ] );
        jsonp_close_array( gui->http );
        jsonp_open_array( gui->http, "latency" );
          for( long i=0UL; i<(long)lv_sz-1L; i+=2L ) {
            FD_TEST( (ulong)i+1<lv_sz );
            ulong s = lv[ i ];
            ulong s2 = lv[ i + 1 ];
            for( ulong j=s; j<=fd_ulong_min( s2, s+MAX_SLOTS_PER_EPOCH ); j++ ) {
              fd_gui_slot_t const * slot = fd_gui_slot_get_canon_safe( gui, j );
              if( FD_UNLIKELY( slot && slot->vote_latency!=UCHAR_MAX ) ) jsonp_ulong( gui->http, NULL, slot->vote_latency );
              else                                                       jsonp_null( gui->http, NULL );
            }
          }
        jsonp_close_array( gui->http );
      jsonp_close_object( gui->http );
  jsonp_close_envelope( gui->http );
}

void
fd_gui_printf_tps_history( fd_gui_t * gui ) {
  jsonp_open_envelope( gui->http, "summary", "tps_history" );
    jsonp_open_array( gui->http, "value" );

    for( ulong i=0UL; i<FD_GUI_TPS_HISTORY_SAMPLE_CNT; i++ ) {
      ulong idx = (gui->summary.estimated_tps_history_idx+i) % FD_GUI_TPS_HISTORY_SAMPLE_CNT;
      ulong vote_cnt = gui->summary.estimated_tps_history[ idx ].vote_failed
                     + gui->summary.estimated_tps_history[ idx ].vote_success;
      ulong total_cnt = vote_cnt
                      + gui->summary.estimated_tps_history[ idx ].nonvote_success
                      + gui->summary.estimated_tps_history[ idx ].nonvote_failed;
      jsonp_open_array( gui->http, NULL );
        jsonp_double( gui->http, NULL, (double)total_cnt/(double)FD_GUI_TPS_HISTORY_WINDOW_DURATION_SECONDS );
        jsonp_double( gui->http, NULL, (double)vote_cnt/(double)FD_GUI_TPS_HISTORY_WINDOW_DURATION_SECONDS );
        jsonp_double( gui->http, NULL, (double)gui->summary.estimated_tps_history[ idx ].nonvote_success/(double)FD_GUI_TPS_HISTORY_WINDOW_DURATION_SECONDS );
        jsonp_double( gui->http, NULL, (double)gui->summary.estimated_tps_history[ idx ].nonvote_failed/(double)FD_GUI_TPS_HISTORY_WINDOW_DURATION_SECONDS );
      jsonp_close_array( gui->http );
    }

    jsonp_close_array( gui->http );
  jsonp_close_envelope( gui->http );
}

void
fd_gui_printf_block_engine( fd_gui_t * gui ) {
  jsonp_open_envelope( gui->http, "block_engine", "update" );
    jsonp_open_object( gui->http, "value" );
      jsonp_string( gui->http, "name",   gui->block_engine.name );
      jsonp_string( gui->http, "url",    gui->block_engine.url );
      jsonp_string( gui->http, "ip",     gui->block_engine.ip_cstr );
      if( FD_LIKELY( gui->block_engine.status==FD_BUNDLE_STATE_CONNECTING ) )     jsonp_string( gui->http, "status", "connecting" );
      else if( FD_LIKELY( gui->block_engine.status==FD_BUNDLE_STATE_CONNECTED ) ) jsonp_string( gui->http, "status", "connected" );
      else if( FD_LIKELY( gui->block_engine.status==FD_BUNDLE_STATE_SLEEPING ) )  jsonp_string( gui->http, "status", "sleeping" );
      else                                                                        jsonp_string( gui->http, "status", "disconnected" );
    jsonp_close_object( gui->http );
  jsonp_close_envelope( gui->http );
}

void
fd_gui_printf_tiles( fd_gui_t * gui ) {
  jsonp_open_envelope( gui->http, "summary", "tiles" );
    jsonp_open_array( gui->http, "value" );
      for( ulong i=0UL; i<gui->summary.tile_cnt; i++ ) {
        fd_topo_tile_t const * tile = &gui->topo->tiles[ gui->summary.tile[ i ] ];

        if( FD_UNLIKELY( !strncmp( tile->name, "bench", 5UL ) ) ) {
          /* bench tiles not reported */
          continue;
        }

        jsonp_open_object( gui->http, NULL );
          jsonp_string( gui->http, "kind", tile->name );
          jsonp_ulong( gui->http, "kind_id", tile->kind_id );
          jsonp_ulong( gui->http, "pid", fd_metrics_tile( tile->metrics )[ MIDX( GAUGE, TILE, PID ) ] );
        jsonp_close_object( gui->http );
      }
    jsonp_close_array( gui->http );
  jsonp_close_envelope( gui->http );
}

void
fd_gui_printf_schedule_strategy( fd_gui_t * gui ) {
  jsonp_open_envelope( gui->http, "summary", "schedule_strategy" );
    char mode[10];
    switch (gui->summary.schedule_strategy) {
      case 0: fd_cstr_ncpy( mode, "perf",     sizeof(mode) ); break;
      case 1: fd_cstr_ncpy( mode, "balanced", sizeof(mode) ); break;
      case 2: fd_cstr_ncpy( mode, "revenue",  sizeof(mode) ); break;
      default: FD_LOG_ERR(("unexpected schedule_strategy %d", gui->summary.schedule_strategy));
    }
    jsonp_string( gui->http, "value", mode );
  jsonp_close_envelope( gui->http );
}

void
fd_gui_printf_identity_balance( fd_gui_t * gui ) {
  jsonp_open_envelope( gui->http, "summary", "identity_balance" );
    jsonp_ulong_as_str( gui->http, "value", gui->summary.identity_account_balance );
  jsonp_close_envelope( gui->http );
}

void
fd_gui_printf_vote_balance( fd_gui_t * gui ) {
  jsonp_open_envelope( gui->http, "summary", "vote_balance" );
    jsonp_ulong_as_str( gui->http, "value", gui->summary.vote_account_balance );
  jsonp_close_envelope( gui->http );
}

void
fd_gui_printf_estimated_slot_duration_nanos( fd_gui_t * gui ) {
  jsonp_open_envelope( gui->http, "summary", "estimated_slot_duration_nanos" );
    jsonp_ulong( gui->http, "value", gui->summary.estimated_slot_duration_nanos );
  jsonp_close_envelope( gui->http );
}


void
fd_gui_printf_root_slot( fd_gui_t * gui ) {
  jsonp_open_envelope( gui->http, "summary", "root_slot" );
    jsonp_ulong( gui->http, "value", fd_ulong_if( gui->summary.slot_rooted!=ULONG_MAX, gui->summary.slot_rooted, 0UL ) );
  jsonp_close_envelope( gui->http );
}

void
fd_gui_printf_optimistically_confirmed_slot( fd_gui_t * gui ) {
  jsonp_open_envelope( gui->http, "summary", "optimistically_confirmed_slot" );
    jsonp_ulong( gui->http, "value", fd_ulong_if( gui->summary.slot_optimistically_confirmed!=ULONG_MAX, gui->summary.slot_optimistically_confirmed, 0UL ) );
  jsonp_close_envelope( gui->http );
}

void
fd_gui_printf_completed_slot( fd_gui_t * gui ) {
  jsonp_open_envelope( gui->http, "summary", "completed_slot" );
    jsonp_ulong( gui->http, "value", fd_ulong_if( gui->summary.slot_tower!=ULONG_MAX, gui->summary.slot_tower, 0UL ) );
  jsonp_close_envelope( gui->http );
}

void
fd_gui_printf_estimated_slot( fd_gui_t * gui ) {
  jsonp_open_envelope( gui->http, "summary", "estimated_slot" );
    jsonp_ulong( gui->http, "value", fd_ulong_if( gui->summary.slot_estimated!=ULONG_MAX, gui->summary.slot_estimated, 0UL ) );
  jsonp_close_envelope( gui->http );
}

void
fd_gui_printf_skip_rate( fd_gui_t * gui,
                         ulong      epoch ) {
  fd_gui_epoch_t const * rec = fd_gui_epoch( gui, epoch );
  jsonp_open_envelope( gui->http, "summary", "skip_rate" );
    jsonp_open_object( gui->http, "value" );
      jsonp_ulong( gui->http, "epoch", FD_LIKELY( rec ) ? rec->epoch : 0UL );
      double skip_rate = ( FD_LIKELY( rec ) && rec->my_total_slots ) ? (double)rec->my_skipped_slots/(double)rec->my_total_slots : 0.0;
      fd_http_server_printf( gui->http, "\"skip_rate\":%.7f,", skip_rate );
    jsonp_close_object( gui->http );
  jsonp_close_envelope( gui->http );
}

void
fd_gui_printf_epoch( fd_gui_t * gui,
                     ulong      epoch ) {
  fd_gui_epoch_t const * meta = fd_gui_epoch( gui, epoch );
  jsonp_open_envelope( gui->http, "epoch", "new" );
    jsonp_open_object( gui->http, "value" );
      jsonp_ulong( gui->http, "epoch",                   FD_LIKELY( meta ) ? meta->epoch : 0UL );
      if( FD_LIKELY( meta && meta->start_time!=LONG_MAX ) ) jsonp_ulong_as_str( gui->http, "start_time_nanos", (ulong)meta->start_time );
      else                                                  jsonp_null( gui->http, "start_time_nanos" );
      if( FD_LIKELY( meta && meta->end_time!=LONG_MAX ) ) jsonp_ulong_as_str( gui->http, "end_time_nanos", (ulong)meta->end_time );
      else                                                jsonp_null( gui->http, "end_time_nanos" );
      jsonp_ulong( gui->http, "start_slot",              FD_LIKELY( meta ) ? meta->start_slot : 0UL );
      jsonp_ulong( gui->http, "end_slot",                FD_LIKELY( meta ) ? meta->start_slot+meta->slot_cnt-1UL : 0UL );
      jsonp_ulong( gui->http, "target_slot_duration_nanos", FD_LIKELY( meta ) ? (ulong)meta->target_slot_duration_ns : LONG_MAX );
      jsonp_ulong_as_str( gui->http, "excluded_stake_lamports", 0UL );
      ulong pub_cnt    = FD_LIKELY( meta ) ? meta->pub_cnt : 0UL;
      ulong stakes_cnt = FD_LIKELY( meta ) ? meta->stakes_cnt : 0UL;
      ulong sched_cnt  = FD_LIKELY( meta ) ? (meta->slot_cnt+FD_EPOCH_SLOTS_PER_ROTATION-1UL)/FD_EPOCH_SLOTS_PER_ROTATION : 0UL;
      jsonp_open_array( gui->http, "staked_pubkeys" );
        for( ulong i=0UL; i<pub_cnt; i++ ) {
          char identity_base58[ FD_BASE58_ENCODED_32_SZ ];
          fd_base58_encode_32( meta->pub[ i ].uc, NULL, identity_base58 );
          jsonp_string( gui->http, NULL, identity_base58 );
        }
      jsonp_close_array( gui->http );

      jsonp_open_array( gui->http, "staked_lamports" );
        for( ulong i=0UL; i<stakes_cnt; i++ ) jsonp_ulong_as_str( gui->http, NULL, meta->stakes[ i ].stake );
      jsonp_close_array( gui->http );

      jsonp_open_array( gui->http, "leader_slots" );
        for( ulong i=0UL; i<sched_cnt; i++ ) jsonp_ulong( gui->http, NULL, meta->sched[ i ] );
      jsonp_close_array( gui->http );
    jsonp_close_object( gui->http );
  jsonp_close_envelope( gui->http );
}

static void
fd_gui_printf_waterfall( fd_gui_t *               gui,
                         fd_gui_txn_waterfall_t const * prev,
                         fd_gui_txn_waterfall_t const * cur ) {
  jsonp_open_object( gui->http, "waterfall" );
    jsonp_open_object( gui->http, "in" );
      jsonp_ulong( gui->http, "pack_cranked",    cur->in.pack_cranked - prev->in.pack_cranked );
      jsonp_ulong( gui->http, "pack_retained",   prev->out.pack_retained );
      jsonp_ulong( gui->http, "resolv_retained", prev->out.resolv_retained );
      jsonp_ulong( gui->http, "quic",            cur->in.quic   - prev->in.quic );
      jsonp_ulong( gui->http, "udp",             cur->in.udp    - prev->in.udp );
      jsonp_ulong( gui->http, "gossip",          cur->in.gossip - prev->in.gossip );
      jsonp_ulong( gui->http, "block_engine",    cur->in.block_engine - prev->in.block_engine );
    jsonp_close_object( gui->http );

    jsonp_open_object( gui->http, "out" );
      jsonp_ulong( gui->http, "net_overrun",         cur->out.net_overrun         - prev->out.net_overrun );
      jsonp_ulong( gui->http, "quic_overrun",        cur->out.quic_overrun        - prev->out.quic_overrun );
      jsonp_ulong( gui->http, "quic_frag_drop",      cur->out.quic_frag_drop      - prev->out.quic_frag_drop );
      jsonp_ulong( gui->http, "quic_abandoned",      cur->out.quic_abandoned      - prev->out.quic_abandoned );
      jsonp_ulong( gui->http, "tpu_quic_invalid",    cur->out.tpu_quic_invalid    - prev->out.tpu_quic_invalid );
      jsonp_ulong( gui->http, "tpu_udp_invalid",     cur->out.tpu_udp_invalid     - prev->out.tpu_udp_invalid );
      jsonp_ulong( gui->http, "verify_overrun",      cur->out.verify_overrun      - prev->out.verify_overrun );
      jsonp_ulong( gui->http, "verify_parse",        cur->out.verify_parse        - prev->out.verify_parse );
      jsonp_ulong( gui->http, "verify_failed",       cur->out.verify_failed       - prev->out.verify_failed );
      jsonp_ulong( gui->http, "verify_duplicate",    cur->out.verify_duplicate    - prev->out.verify_duplicate );
      jsonp_ulong( gui->http, "dedup_duplicate",     cur->out.dedup_duplicate     - prev->out.dedup_duplicate );
      jsonp_ulong( gui->http, "resolv_lut_failed",   cur->out.resolv_lut_failed   - prev->out.resolv_lut_failed );
      jsonp_ulong( gui->http, "resolv_expired",      cur->out.resolv_expired      - prev->out.resolv_expired );
      jsonp_ulong( gui->http, "resolv_ancient",      cur->out.resolv_ancient      - prev->out.resolv_ancient );
      jsonp_ulong( gui->http, "resolv_no_ledger",    cur->out.resolv_no_ledger    - prev->out.resolv_no_ledger );
      jsonp_ulong( gui->http, "resolv_retained",     cur->out.resolv_retained );
      jsonp_ulong( gui->http, "pack_invalid",        cur->out.pack_invalid        - prev->out.pack_invalid );
      jsonp_ulong( gui->http, "pack_invalid_bundle", cur->out.pack_invalid_bundle - prev->out.pack_invalid_bundle );
      jsonp_ulong( gui->http, "pack_expired",        cur->out.pack_expired        - prev->out.pack_expired );
      jsonp_ulong( gui->http, "pack_already_executed", cur->out.pack_already_executed - prev->out.pack_already_executed );
      jsonp_ulong( gui->http, "pack_retained",       cur->out.pack_retained );
      jsonp_ulong( gui->http, "pack_wait_full",      cur->out.pack_wait_full      - prev->out.pack_wait_full );
      jsonp_ulong( gui->http, "pack_leader_slow",    cur->out.pack_leader_slow    - prev->out.pack_leader_slow );
      jsonp_ulong( gui->http, "bank_invalid",        cur->out.bank_invalid        - prev->out.bank_invalid );
      jsonp_ulong( gui->http, "bank_nonce_already_advanced", cur->out.bank_nonce_already_advanced - prev->out.bank_nonce_already_advanced );
      jsonp_ulong( gui->http, "bank_nonce_advance_failed",   cur->out.bank_nonce_advance_failed   - prev->out.bank_nonce_advance_failed   );
      jsonp_ulong( gui->http, "bank_nonce_wrong_blockhash",  cur->out.bank_nonce_wrong_blockhash  - prev->out.bank_nonce_wrong_blockhash  );
      jsonp_ulong( gui->http, "block_success",       cur->out.block_success       - prev->out.block_success );
      jsonp_ulong( gui->http, "block_fail",          cur->out.block_fail          - prev->out.block_fail );
    jsonp_close_object( gui->http );
  jsonp_close_object( gui->http );
}

void
fd_gui_printf_live_txn_waterfall( fd_gui_t *                     gui,
                                  fd_gui_txn_waterfall_t const * prev,
                                  fd_gui_txn_waterfall_t const * cur,
                                  ulong                          next_leader_slot ) {
  jsonp_open_envelope( gui->http, "summary", "live_txn_waterfall" );
    jsonp_open_object( gui->http, "value" );
      jsonp_ulong( gui->http, "next_leader_slot", next_leader_slot );
      fd_gui_printf_waterfall( gui, prev, cur );
    jsonp_close_object( gui->http );
  jsonp_close_envelope( gui->http );
}

static void
fd_gui_printf_network_metrics( fd_gui_t *                     gui,
                               fd_gui_network_stats_t const * cur ) {
  jsonp_open_array( gui->http, "ingress" );
    jsonp_ulong( gui->http, NULL, cur->in.turbine );
    jsonp_ulong( gui->http, NULL, cur->in.gossip  );
    jsonp_ulong( gui->http, NULL, cur->in.tpu     );
    jsonp_ulong( gui->http, NULL, cur->in.repair  );
    jsonp_ulong( gui->http, NULL, cur->in.rserve  );
    jsonp_ulong( gui->http, NULL, cur->in.metric  );
  jsonp_close_array( gui->http );
  jsonp_open_array( gui->http, "egress" );
    jsonp_ulong( gui->http, NULL, cur->out.turbine );
    jsonp_ulong( gui->http, NULL, cur->out.gossip  );
    jsonp_ulong( gui->http, NULL, cur->out.tpu     );
    jsonp_ulong( gui->http, NULL, cur->out.repair  );
    jsonp_ulong( gui->http, NULL, cur->out.rserve  );
    jsonp_ulong( gui->http, NULL, cur->out.metric  );
  jsonp_close_array( gui->http );
  jsonp_open_array( gui->http, "ingress_ema" );
    for( ulong i=0UL; i<FD_GUI_NET_PROTO_CNT; i++ ) jsonp_double( gui->http, NULL, fd_double_if( gui->summary.net_rate_ema_ready, gui->summary.ingress_ema[ i ], 0.0 ) );
  jsonp_close_array( gui->http );
  jsonp_open_array( gui->http, "egress_ema" );
    for( ulong i=0UL; i<FD_GUI_NET_PROTO_CNT; i++ ) jsonp_double( gui->http, NULL, fd_double_if( gui->summary.net_rate_ema_ready, gui->summary.egress_ema[ i ], 0.0 ) );
  jsonp_close_array( gui->http );
  fd_gui_rate_entry_t const * ingress_max_head = fd_gui_rate_deque_empty( gui->summary.ingress_maxq ) ? NULL : fd_gui_rate_deque_peek_head_const( gui->summary.ingress_maxq );
  fd_gui_rate_entry_t const * egress_max_head  = fd_gui_rate_deque_empty( gui->summary.egress_maxq )  ? NULL : fd_gui_rate_deque_peek_head_const( gui->summary.egress_maxq );
  jsonp_ulong( gui->http, "ingress_max_5m", ingress_max_head ? (ulong)ingress_max_head->value : 0UL );
  jsonp_ulong( gui->http, "egress_max_5m",  egress_max_head  ? (ulong)egress_max_head->value  : 0UL );
}

void
fd_gui_printf_live_network_metrics( fd_gui_t *                     gui,
                                    fd_gui_network_stats_t const * cur ) {
  jsonp_open_envelope( gui->http, "summary", "live_network_metrics" );
    jsonp_open_object( gui->http, "value" );
      fd_gui_printf_network_metrics( gui, cur );
    jsonp_close_object( gui->http );
  jsonp_close_envelope( gui->http );
}

static void
fd_gui_printf_tile_stats( fd_gui_t *                  gui,
                          fd_gui_tile_stats_t const * prev,
                          fd_gui_tile_stats_t const * cur ) {
  jsonp_open_object( gui->http, "tile_primary_metric" );
    jsonp_ulong(  gui->http, "quic",    cur->quic_conn_cnt );
    jsonp_double( gui->http, "bundle_rtt_smoothed_millis", (double)(cur->bundle_rtt_smoothed_nanos) / 1000000.0 );

    fd_histf_t bundle_rx_delay_hist_delta[ 1 ];
    fd_histf_subtract( &cur->bundle_rx_delay_hist, &prev->bundle_rx_delay_hist, bundle_rx_delay_hist_delta );
    ulong bundle_rx_delay_nanos_p90 = fd_histf_percentile( bundle_rx_delay_hist_delta, 90U, ULONG_MAX );
    jsonp_double( gui->http, "bundle_rx_delay_millis_p90", fd_double_if(bundle_rx_delay_nanos_p90==ULONG_MAX, 0.0, (double)(bundle_rx_delay_nanos_p90) / 1000000.0 ));

    if( FD_LIKELY( cur->sample_time_nanos>prev->sample_time_nanos ) ) {
      jsonp_ulong( gui->http, "net_in",  (ulong)((double)(cur->net_in_rx_bytes - prev->net_in_rx_bytes) * 1000000000.0 / (double)(cur->sample_time_nanos - prev->sample_time_nanos) ));
      jsonp_ulong( gui->http, "net_out", (ulong)((double)(cur->net_out_tx_bytes - prev->net_out_tx_bytes) * 1000000000.0 / (double)(cur->sample_time_nanos - prev->sample_time_nanos) ));
    } else {
      jsonp_ulong( gui->http, "net_in",  0 );
      jsonp_ulong( gui->http, "net_out", 0 );
    }
    if( FD_LIKELY( cur->verify_total_cnt>prev->verify_total_cnt ) ) {
      jsonp_double( gui->http, "verify", (double)(cur->verify_drop_cnt-prev->verify_drop_cnt) / (double)(cur->verify_total_cnt-prev->verify_total_cnt) );
    } else {
      jsonp_double( gui->http, "verify", 0.0 );
    }
    if( FD_LIKELY( cur->dedup_total_cnt>prev->dedup_total_cnt ) ) {
      jsonp_double( gui->http, "dedup", (double)(cur->dedup_drop_cnt-prev->dedup_drop_cnt) / (double)(cur->dedup_total_cnt-prev->dedup_total_cnt) );
    } else {
      jsonp_double( gui->http, "dedup", 0.0 );
    }
    jsonp_ulong(  gui->http, "bank", cur->bank_txn_exec_cnt - prev->bank_txn_exec_cnt );
    jsonp_double( gui->http, "pack", !cur->pack_buffer_capacity ? 1.0 : (double)cur->pack_buffer_cnt/(double)cur->pack_buffer_capacity );
    jsonp_double( gui->http, "poh", 0.0 );
    jsonp_double( gui->http, "shred", 0.0 );
    jsonp_double( gui->http, "store", 0.0 );
  jsonp_close_object( gui->http );
}

void
fd_gui_printf_live_tile_stats( fd_gui_t *                  gui,
                               fd_gui_tile_stats_t const * prev,
                               fd_gui_tile_stats_t const * cur ) {
  jsonp_open_envelope( gui->http, "summary", "live_tile_primary_metric" );
    jsonp_open_object( gui->http, "value" );
      jsonp_ulong( gui->http, "next_leader_slot", 0UL );
      fd_gui_printf_tile_stats( gui, prev, cur );
    jsonp_close_object( gui->http );
  jsonp_close_envelope( gui->http );
}

static void
fd_gui_printf_tile_timers( fd_gui_t *                        gui,
                           fd_gui_tile_timers_hist_t const * packed ) {
  for( ulong i=0UL; i<gui->summary.tile_cnt; i++ ) {
    ulong t = gui->summary.tile[ i ];
    fd_topo_tile_t const * tile = &gui->topo->tiles[ t ];

    if( FD_UNLIKELY( !strncmp( tile->name, "bench", 5UL ) ) ) {
      /* bench tiles not reported */
      continue;
    }

    ushort ir = packed[ t ].idle_ratio;
    /* -1 signals "no sample this window" (NaN has no JSON representation). */
    double idle_ratio = ( ir==USHORT_MAX ) ? -1.0 : ( (double)ir / 10000.0 );
    jsonp_double( gui->http, NULL, idle_ratio );
  }
}

static void
fd_gui_printf_tile_metrics( fd_gui_t *                        gui,
                            fd_gui_tile_timers_hist_t const * packed ) {
  jsonp_open_array( gui->http, "timers" );
  for( ulong i=0UL; i<gui->summary.tile_cnt; i++ ) {
    ulong t = gui->summary.tile[ i ];
    fd_topo_tile_t const * tile = &gui->topo->tiles[ t ];

    if( FD_UNLIKELY( !strncmp( tile->name, "bench", 5UL ) ) ) {
      /* bench tiles not reported */
      jsonp_null( gui->http, NULL );
      continue;
    }

    if( FD_UNLIKELY( packed[ t ].timers[ 0 ]==USHORT_MAX ) ) {
      jsonp_null( gui->http, NULL );
    } else {
      jsonp_open_array( gui->http, NULL );
        for( ulong j=0UL; j<FD_METRICS_ENUM_TILE_REGIME_CNT; j++ ) {
          jsonp_double( gui->http, NULL, (double)packed[ t ].timers[ j ] / 100.0 );
        }
      jsonp_close_array( gui->http );
    }
  }
  jsonp_close_array( gui->http );

  jsonp_open_array( gui->http, "sched_timers" );
  for( ulong i=0UL; i<gui->summary.tile_cnt; i++ ) {
    ulong t = gui->summary.tile[ i ];
    fd_topo_tile_t const * tile = &gui->topo->tiles[ t ];

    if( FD_UNLIKELY( !strncmp( tile->name, "bench", 5UL ) ) ) {
      /* bench tiles not reported */
      jsonp_null( gui->http, NULL );
      continue;
    }

    if( FD_UNLIKELY( packed[ t ].sched_timers[ 0 ]==USHORT_MAX ) ) {
      jsonp_null( gui->http, NULL );
    } else {
      jsonp_open_array( gui->http, NULL );
        for( ulong j=0UL; j<FD_METRICS_ENUM_CPU_REGIME_CNT; j++ ) {
          jsonp_double( gui->http, NULL, (double)packed[ t ].sched_timers[ j ] / 100.0 );
        }
      jsonp_close_array( gui->http );
    }
  }
  jsonp_close_array( gui->http );

  jsonp_open_array( gui->http, "in_backp" );
    for( ulong i=0UL; i<gui->summary.tile_cnt; i++ ) {
      jsonp_bool( gui->http, NULL, packed[ gui->summary.tile[ i ] ].in_backp );
    }
  jsonp_close_array( gui->http );
  jsonp_open_array( gui->http, "backp_msgs" );
    for( ulong i=0UL; i<gui->summary.tile_cnt; i++ ) {
      jsonp_ulong( gui->http, NULL, packed[ gui->summary.tile[ i ] ].backp_msgs );
    }
  jsonp_close_array( gui->http );
  jsonp_open_array( gui->http, "alive" );
    for( ulong i=0UL; i<gui->summary.tile_cnt; i++ ) {
      jsonp_ulong( gui->http, NULL, packed[ gui->summary.tile[ i ] ].alive );
    }
  jsonp_close_array( gui->http );
  jsonp_open_array( gui->http, "nvcsw" );
    for( ulong i=0UL; i<gui->summary.tile_cnt; i++ ) {
      jsonp_ulong( gui->http, NULL, packed[ gui->summary.tile[ i ] ].nvcsw );
    }
  jsonp_close_array( gui->http );
  jsonp_open_array( gui->http, "nivcsw" );
    for( ulong i=0UL; i<gui->summary.tile_cnt; i++ ) {
      jsonp_ulong( gui->http, NULL, packed[ gui->summary.tile[ i ] ].nivcsw );
    }
  jsonp_close_array( gui->http );
  jsonp_open_array( gui->http, "minflt" );
    for( ulong i=0UL; i<gui->summary.tile_cnt; i++ ) {
      jsonp_ulong( gui->http, NULL, packed[ gui->summary.tile[ i ] ].minflt );
    }
  jsonp_close_array( gui->http );
  jsonp_open_array( gui->http, "majflt" );
    for( ulong i=0UL; i<gui->summary.tile_cnt; i++ ) {
      jsonp_ulong( gui->http, NULL, packed[ gui->summary.tile[ i ] ].majflt );
    }
  jsonp_close_array( gui->http );
  jsonp_open_array( gui->http, "last_cpu" );
    for( ulong i=0UL; i<gui->summary.tile_cnt; i++ ) {
      jsonp_ulong( gui->http, NULL, packed[ gui->summary.tile[ i ] ].last_cpu );
    }
  jsonp_close_array( gui->http );
  jsonp_open_array( gui->http, "interrupts" );
    for( ulong i=0UL; i<gui->summary.tile_cnt; i++ ) {
      jsonp_ulong( gui->http, NULL, packed[ gui->summary.tile[ i ] ].interrupts );
    }
  jsonp_close_array( gui->http );
  jsonp_open_array( gui->http, "tlb_shootdowns" );
    for( ulong i=0UL; i<gui->summary.tile_cnt; i++ ) {
      jsonp_ulong( gui->http, NULL, packed[ gui->summary.tile[ i ] ].tlb_shootdowns );
    }
  jsonp_close_array( gui->http );
  jsonp_open_array( gui->http, "timer_ticks" );
    for( ulong i=0UL; i<gui->summary.tile_cnt; i++ ) {
      jsonp_ulong( gui->http, NULL, packed[ gui->summary.tile[ i ] ].timer_ticks );
    }
  jsonp_close_array( gui->http );
  jsonp_open_array( gui->http, "priority" );
    for( ulong i=0UL; i<gui->summary.tile_cnt; i++ ) {
      int priority = fd_topob_tile_priority_type( gui->topo->tiles[ gui->summary.tile[ i ] ].name );

      char const * priority_type_str = "unknown";
      switch( priority ) {
        case FD_TOPOB_PRIORITY_FLOATING: priority_type_str = "floating"; break;
        case FD_TOPOB_PRIORITY_STARTUP:  priority_type_str = "startup";  break;
        case FD_TOPOB_PRIORITY_NORMAL:   priority_type_str = "normal";   break;
        case FD_TOPOB_PRIORITY_CRITICAL: priority_type_str = "critical"; break;
      }

      jsonp_string( gui->http, NULL, priority_type_str );
    }
  jsonp_close_array( gui->http );
}

void
fd_gui_printf_live_tile_timers( fd_gui_t * gui ) {
  jsonp_open_envelope( gui->http, "summary", "live_tile_timers" );
    jsonp_open_array( gui->http, "value" );
      fd_gui_printf_tile_timers( gui, gui->summary.tile_timers_packed );
    jsonp_close_array( gui->http );
  jsonp_close_envelope( gui->http );
}

void
fd_gui_printf_live_tile_metrics( fd_gui_t * gui ) {
  jsonp_open_envelope( gui->http, "summary", "live_tile_metrics" );
      jsonp_open_object( gui->http, "value" );
        fd_gui_printf_tile_metrics( gui, gui->summary.tile_timers_packed );
      jsonp_close_object( gui->http );
  jsonp_close_envelope( gui->http );
}

void
fd_gui_printf_estimated_tps( fd_gui_t * gui ) {
  ulong idx = (gui->summary.estimated_tps_history_idx+FD_GUI_TPS_HISTORY_SAMPLE_CNT-1UL) % FD_GUI_TPS_HISTORY_SAMPLE_CNT;

  jsonp_open_envelope( gui->http, "summary", "estimated_tps" );
    jsonp_open_object( gui->http, "value" );
      ulong vote_cnt = gui->summary.estimated_tps_history[ idx ].vote_failed
                    + gui->summary.estimated_tps_history[ idx ].vote_success;
      ulong total_cnt = vote_cnt
                      + gui->summary.estimated_tps_history[ idx ].nonvote_success
                      + gui->summary.estimated_tps_history[ idx ].nonvote_failed;
      jsonp_double( gui->http, "total",           (double)total_cnt/(double)FD_GUI_TPS_HISTORY_WINDOW_DURATION_SECONDS );
      jsonp_double( gui->http, "vote",            (double)vote_cnt/(double)FD_GUI_TPS_HISTORY_WINDOW_DURATION_SECONDS );
      jsonp_double( gui->http, "nonvote_success", (double)gui->summary.estimated_tps_history[ idx ].nonvote_success/(double)FD_GUI_TPS_HISTORY_WINDOW_DURATION_SECONDS );
      jsonp_double( gui->http, "nonvote_failed",  (double)gui->summary.estimated_tps_history[ idx ].nonvote_failed/(double)FD_GUI_TPS_HISTORY_WINDOW_DURATION_SECONDS );
    jsonp_close_object( gui->http );
  jsonp_close_envelope( gui->http );
}

void
fd_gui_printf_live_program_cache( fd_gui_t * gui ) {
  fd_topo_t const * topo = gui->topo;

  ulong insertions      = 0UL;
  ulong insertion_bytes = 0UL;
  ulong evictions       = 0UL;
  ulong eviction_bytes  = 0UL;
  ulong spills          = 0UL;
  ulong spill_bytes     = 0UL;

  for( ulong i=0UL; i<gui->summary.execrp_tile_cnt; i++ ) {
    fd_topo_tile_t const * execrp = &topo->tiles[ fd_topo_find_tile( topo, "execrp", i ) ];
    volatile ulong const * metrics = fd_metrics_tile( execrp->metrics );

    insertions      += metrics[ MIDX( COUNTER, EXECRP, PROGCACHE_FILL          ) ];
    insertion_bytes += metrics[ MIDX( COUNTER, EXECRP, PROGCACHE_FILL_BYTES     ) ];
    evictions       += metrics[ MIDX( COUNTER, EXECRP, PROGCACHE_EVICTION      ) ];
    eviction_bytes  += metrics[ MIDX( COUNTER, EXECRP, PROGCACHE_EVICTION_BYTES ) ];
    spills          += metrics[ MIDX( COUNTER, EXECRP, PROGCACHE_SPILL         ) ];
    spill_bytes     += metrics[ MIDX( COUNTER, EXECRP, PROGCACHE_SPILL_BYTES    ) ];
  }

  ulong free_bytes = 0UL;
  ulong size_bytes = 0UL;

  fd_topo_tile_t const * replay = &topo->tiles[ fd_topo_find_tile( topo, "replay", 0UL ) ];
  volatile ulong const * replay_metrics = fd_metrics_tile( replay->metrics );

  free_bytes = replay_metrics[ MIDX( GAUGE, REPLAY, PROGCACHE_FREE_BYTES ) ];
  size_bytes = replay_metrics[ MIDX( GAUGE, REPLAY, PROGCACHE_SIZE_BYTES ) ];

  jsonp_open_envelope( gui->http, "summary", "live_program_cache" );
    jsonp_open_object( gui->http, "value" );
      jsonp_ulong( gui->http, "hits",            gui->summary.progcache_hits_1min    );
      jsonp_ulong( gui->http, "lookups",         gui->summary.progcache_lookups_1min );
      jsonp_ulong( gui->http, "insertions",      insertions      );
      jsonp_ulong( gui->http, "insertion_bytes", insertion_bytes );
      jsonp_ulong( gui->http, "evictions",       evictions       );
      jsonp_ulong( gui->http, "eviction_bytes",  eviction_bytes  );
      jsonp_ulong( gui->http, "spills",          spills          );
      jsonp_ulong( gui->http, "spill_bytes",     spill_bytes     );
      jsonp_ulong( gui->http, "free_bytes",      free_bytes      );
      jsonp_ulong( gui->http, "size_bytes",      size_bytes      );
    jsonp_close_object( gui->http );
  jsonp_close_envelope( gui->http );
}

void
fd_gui_printf_health( fd_gui_t * gui ) {
  fd_topo_t const * topo = gui->topo;

  ulong diag_tile_idx = fd_topo_find_tile( topo, "diag", 0UL );

  /* Default to disabled if no diag tile */
  ulong bundle_status  = FD_DIAG_BUNDLE_STATUS_DISABLED;
  ulong vote_status    = FD_DIAG_VOTE_STATUS_DISABLED;
  ulong replay_status  = FD_DIAG_REPLAY_STATUS_DISABLED;
  ulong turbine_status = FD_DIAG_TURBINE_STATUS_DISABLED;

  if( FD_LIKELY( diag_tile_idx!=ULONG_MAX ) ) {
    volatile ulong const * metrics = fd_metrics_tile( topo->tiles[ diag_tile_idx ].metrics );
    bundle_status  = metrics[ MIDX( GAUGE, DIAG, BUNDLE_STATUS  ) ];
    vote_status    = metrics[ MIDX( GAUGE, DIAG, VOTE_STATUS    ) ];
    replay_status  = metrics[ MIDX( GAUGE, DIAG, REPLAY_STATUS  ) ];
    turbine_status = metrics[ MIDX( GAUGE, DIAG, TURBINE_STATUS ) ];
  }

  if( FD_UNLIKELY( !gui->summary.is_full_client ) ) {
    switch( gui->summary.vote_state ) {
      case FD_GUI_VOTE_STATE_VOTING:     vote_status = FD_DIAG_VOTE_STATUS_VOTING;     break;
      case FD_GUI_VOTE_STATE_DELINQUENT: vote_status = FD_DIAG_VOTE_STATUS_DELINQUENT; break;
      default:                           vote_status = FD_DIAG_VOTE_STATUS_DISABLED;   break;
    }
    replay_status  = FD_DIAG_REPLAY_STATUS_DISABLED;
    turbine_status = FD_DIAG_TURBINE_STATUS_DISABLED;
  }

  /* Map bundle status to string */
  char const * bundle_str;
  switch( bundle_status ) {
    case FD_DIAG_BUNDLE_STATUS_DISCONNECTED: bundle_str = "disconnected"; break;
    case FD_DIAG_BUNDLE_STATUS_CONNECTING:   bundle_str = "connecting";   break;
    case FD_DIAG_BUNDLE_STATUS_CONNECTED:    bundle_str = "connected";    break;
    case FD_DIAG_BUNDLE_STATUS_SLEEPING:     bundle_str = "sleeping";     break;
    default:                                 bundle_str = "disabled";     break;
  }

  /* Map vote status to string */
  char const * vote_str;
  switch( vote_status ) {
    case FD_DIAG_VOTE_STATUS_NOT_STARTED: vote_str = "not_started"; break;
    case FD_DIAG_VOTE_STATUS_DELINQUENT:  vote_str = "delinquent";  break;
    case FD_DIAG_VOTE_STATUS_VOTING:      vote_str = "voting";      break;
    default:                              vote_str = "disabled";    break;
  }

  /* Map replay status to string */
  char const * replay_str;
  switch( replay_status ) {
    case FD_DIAG_REPLAY_STATUS_NOT_STARTED: replay_str = "not_started"; break;
    case FD_DIAG_REPLAY_STATUS_BEHIND:      replay_str = "behind";      break;
    case FD_DIAG_REPLAY_STATUS_RUNNING:     replay_str = "running";     break;
    default:                                replay_str = "disabled";    break;
  }

  /* Map turbine status to string */
  char const * turbine_str;
  switch( turbine_status ) {
    case FD_DIAG_TURBINE_STATUS_NOT_STARTED:      turbine_str = "not_started";      break;
    case FD_DIAG_TURBINE_STATUS_STALLED:          turbine_str = "stalled";          break;
    case FD_DIAG_TURBINE_STATUS_REPAIR_OUTPACING: turbine_str = "repair_outpacing"; break;
    case FD_DIAG_TURBINE_STATUS_RUNNING:          turbine_str = "running";          break;
    default:                                      turbine_str = "disabled";         break;
  }

  jsonp_open_envelope( gui->http, "summary", "health" );
    jsonp_open_object( gui->http, "value" );
      jsonp_string( gui->http, "vote",    vote_str    );
      jsonp_string( gui->http, "bundle",  bundle_str  );
      jsonp_string( gui->http, "replay",  replay_str  );
      jsonp_string( gui->http, "turbine", turbine_str );
    jsonp_close_object( gui->http );
  jsonp_close_envelope( gui->http );
}

/* Triangular-weighted average of a delta ring.  Newest sample has
   weight n, oldest has weight 1.  Returns sum(w*delta) / weighted_dt
   where weighted_dt is precomputed (sum of w * dt_sec for the same
   samples). */
static double
fd_gui_accdb_weighted_rate( ulong const * ring,
                            ulong         next_write_idx,
                            ulong         n,
                            double        weighted_dt ) {
  if( !n || weighted_dt<=0.0 ) return 0.0;
  double num = 0.0;
  for( ulong k=0UL; k<n; k++ ) {
    double w  = (double)(n - k);
    ulong  ri = (next_write_idx + FD_GUI_ACCDB_WIN_SAMPLES - 1UL - k) % FD_GUI_ACCDB_WIN_SAMPLES;
    num += w * (double)ring[ ri ];
  }
  return num / weighted_dt;
}

void
fd_gui_printf_accounts_stats( fd_gui_t * gui ) {
  fd_gui_accounts_stats_t const * cur  = gui->summary.accounts_stats_current;
  fd_gui_accounts_stats_t const * prev = gui->summary.accounts_stats_reference;
  int have_ref = gui->summary.accounts_stats_have_reference;

  long  dt_nanos = have_ref ? (cur->sample_time_nanos - prev->sample_time_nanos) : 0L;

  /* Append this snap's deltas to the triangular-window rings.  The
     emit code below applies triangular weights to compute the smoothed
     rate.  Buffer is a simple ring; idx points to the next write slot. */
  if( have_ref && dt_nanos>0L ) {
    ulong i = gui->summary.accdb->accdb_win_idx;

    gui->summary.accdb->accdb_win_dt_nanos          [ i ] = dt_nanos;
    gui->summary.accdb->agg_acquired_win            [ i ] = cur->acquired                 - prev->acquired                ;
    gui->summary.accdb->agg_acquired_writable_win   [ i ] = cur->acquired_writable        - prev->acquired_writable       ;
    gui->summary.accdb->agg_bytes_read_win          [ i ] = cur->bytes_read               - prev->bytes_read              ;
    gui->summary.accdb->agg_bytes_copied_win        [ i ] = cur->bytes_copied             - prev->bytes_copied            ;
    gui->summary.accdb->agg_bytes_written_win       [ i ] = cur->bytes_written            - prev->bytes_written           ;
    gui->summary.accdb->agg_bytes_written_accdb_win [ i ] = cur->bytes_written_accdb      - prev->bytes_written_accdb     ;
    gui->summary.accdb->agg_read_ops_win            [ i ] = cur->read_ops                 - prev->read_ops                ;
    gui->summary.accdb->agg_write_ops_win           [ i ] = cur->write_ops                - prev->write_ops               ;
    gui->summary.accdb->agg_relocated_bytes_win     [ i ] = cur->accounts_relocated_bytes - prev->accounts_relocated_bytes;

    ulong agg_misses_delta = 0UL;
    for( ulong c=0UL; c<FD_ACCDB_CACHE_CLASS_CNT; c++ ) {
      ulong d = cur->not_found_per_class[ c ] - prev->not_found_per_class[ c ];
      agg_misses_delta += d;
      gui->summary.accdb->class_acq_win        [ c ][ i ] = cur->acquired_per_class            [ c ] - prev->acquired_per_class            [ c ];
      gui->summary.accdb->class_acq_wr_win     [ c ][ i ] = cur->acquired_writable_per_class   [ c ] - prev->acquired_writable_per_class   [ c ];
      gui->summary.accdb->class_not_found_win  [ c ][ i ] = d;
      gui->summary.accdb->class_evicted_win    [ c ][ i ] = cur->evicted_per_class             [ c ] - prev->evicted_per_class             [ c ];
      gui->summary.accdb->class_preevicted_win [ c ][ i ] = cur->preevicted_per_class          [ c ] - prev->preevicted_per_class          [ c ];
      gui->summary.accdb->class_commit_new_win [ c ][ i ] = cur->committed_new_per_class       [ c ] - prev->committed_new_per_class       [ c ];
      gui->summary.accdb->class_commit_over_win[ c ][ i ] = cur->committed_overwrite_per_class [ c ] - prev->committed_overwrite_per_class [ c ];
    }
    gui->summary.accdb->agg_misses_win[ i ] = agg_misses_delta;

    /* Per-partition deltas.  Snap each partition's current cumulative
       counters from accdb_shmem, diff against prev, push into ring.
       Also keep the most-recent snapshot for non-rate fields. */
    if( FD_LIKELY( gui->accdb_shmem ) ) {
      ulong pcnt = fd_accdb_shmem_partition_max( gui->accdb_shmem );
      if( pcnt>FD_GUI_MAX_PARTITIONS ) pcnt = FD_GUI_MAX_PARTITIONS;
      gui->summary.accdb->partition_cnt = pcnt;
      for( ulong p=0UL; p<pcnt; p++ ) {
        fd_accdb_shmem_partition_info_t info;
        fd_accdb_shmem_partition_info( gui->accdb_shmem, p, &info );
        gui->summary.accdb->partitions[ p ] = info;

        /* Pool slots get reused: when a partition is released and
           re-acquired, change_partition zeroes its counters.  Detect
           the reset (any counter dropped below its previous value) and
           treat this sample as the start of a new lifecycle — emit a
           zero delta rather than letting the unsigned subtract wrap
           into a giant rate. */
        int reset = info.read_ops      < gui->summary.accdb->partition_prev_read_ops     [ p ] ||
                    info.bytes_read    < gui->summary.accdb->partition_prev_bytes_read   [ p ] ||
                    info.write_ops     < gui->summary.accdb->partition_prev_write_ops    [ p ] ||
                    info.bytes_written < gui->summary.accdb->partition_prev_bytes_written[ p ];
        if( FD_UNLIKELY( reset ) ) {
          gui->summary.accdb->partition_prev_read_ops     [ p ] = info.read_ops;
          gui->summary.accdb->partition_prev_bytes_read   [ p ] = info.bytes_read;
          gui->summary.accdb->partition_prev_write_ops    [ p ] = info.write_ops;
          gui->summary.accdb->partition_prev_bytes_written[ p ] = info.bytes_written;
          /* Also wipe the historical window so an old lifecycle's
             samples don't keep contributing to this slot's rate. */
          for( ulong k=0UL; k<FD_GUI_ACCDB_WIN_SAMPLES; k++ ) {
            gui->summary.accdb->partition_read_ops_win    [ p ][ k ] = 0UL;
            gui->summary.accdb->partition_bytes_read_win  [ p ][ k ] = 0UL;
            gui->summary.accdb->partition_write_ops_win   [ p ][ k ] = 0UL;
            gui->summary.accdb->partition_bytes_written_win[p ][ k ] = 0UL;
          }
        }
        ulong d_read_ops      = info.read_ops      - gui->summary.accdb->partition_prev_read_ops     [ p ];
        ulong d_bytes_read    = info.bytes_read    - gui->summary.accdb->partition_prev_bytes_read   [ p ];
        ulong d_write_ops     = info.write_ops     - gui->summary.accdb->partition_prev_write_ops    [ p ];
        ulong d_bytes_written = info.bytes_written - gui->summary.accdb->partition_prev_bytes_written[ p ];

        gui->summary.accdb->partition_read_ops_win    [ p ][ i ] = d_read_ops;
        gui->summary.accdb->partition_bytes_read_win  [ p ][ i ] = d_bytes_read;
        gui->summary.accdb->partition_write_ops_win   [ p ][ i ] = d_write_ops;
        gui->summary.accdb->partition_bytes_written_win[p ][ i ] = d_bytes_written;

        gui->summary.accdb->partition_prev_read_ops     [ p ] = info.read_ops;
        gui->summary.accdb->partition_prev_bytes_read   [ p ] = info.bytes_read;
        gui->summary.accdb->partition_prev_write_ops    [ p ] = info.write_ops;
        gui->summary.accdb->partition_prev_bytes_written[ p ] = info.bytes_written;
      }
    }

    /* Per-tile deltas.  Cumulative values were snapped from each tile's
       metric page in fd_gui_accounts_stats_snap; diff against prev and
       push into the ring. */
    for( ulong s=0UL; s<gui->summary.accdb->accdb_tile_cnt; s++ ) {
      gui->summary.accdb->tile_acquired_win         [ s ][ i ] = gui->summary.accdb->tile_cur_acquired         [ s ] - gui->summary.accdb->tile_prev_acquired         [ s ];
      gui->summary.accdb->tile_acquired_writable_win[ s ][ i ] = gui->summary.accdb->tile_cur_acquired_writable[ s ] - gui->summary.accdb->tile_prev_acquired_writable[ s ];
      gui->summary.accdb->tile_bytes_read_win       [ s ][ i ] = gui->summary.accdb->tile_cur_bytes_read       [ s ] - gui->summary.accdb->tile_prev_bytes_read       [ s ];
      gui->summary.accdb->tile_bytes_copied_win     [ s ][ i ] = gui->summary.accdb->tile_cur_bytes_copied     [ s ] - gui->summary.accdb->tile_prev_bytes_copied     [ s ];
      gui->summary.accdb->tile_bytes_written_win    [ s ][ i ] = gui->summary.accdb->tile_cur_bytes_written    [ s ] - gui->summary.accdb->tile_prev_bytes_written    [ s ];
      gui->summary.accdb->tile_read_ops_win         [ s ][ i ] = gui->summary.accdb->tile_cur_read_ops         [ s ] - gui->summary.accdb->tile_prev_read_ops         [ s ];
      gui->summary.accdb->tile_write_ops_win        [ s ][ i ] = gui->summary.accdb->tile_cur_write_ops        [ s ] - gui->summary.accdb->tile_prev_write_ops        [ s ];
      gui->summary.accdb->tile_misses_win           [ s ][ i ] = gui->summary.accdb->tile_cur_misses           [ s ] - gui->summary.accdb->tile_prev_misses           [ s ];
      gui->summary.accdb->tile_evicted_win          [ s ][ i ] = gui->summary.accdb->tile_cur_evicted          [ s ] - gui->summary.accdb->tile_prev_evicted          [ s ];
      gui->summary.accdb->tile_committed_win        [ s ][ i ] = gui->summary.accdb->tile_cur_committed        [ s ] - gui->summary.accdb->tile_prev_committed        [ s ];
      gui->summary.accdb->tile_acquire_calls_win    [ s ][ i ] = gui->summary.accdb->tile_cur_acquire_calls    [ s ] - gui->summary.accdb->tile_prev_acquire_calls    [ s ];

      gui->summary.accdb->tile_prev_acquired         [ s ] = gui->summary.accdb->tile_cur_acquired         [ s ];
      gui->summary.accdb->tile_prev_acquired_writable[ s ] = gui->summary.accdb->tile_cur_acquired_writable[ s ];
      gui->summary.accdb->tile_prev_bytes_read       [ s ] = gui->summary.accdb->tile_cur_bytes_read       [ s ];
      gui->summary.accdb->tile_prev_bytes_copied     [ s ] = gui->summary.accdb->tile_cur_bytes_copied     [ s ];
      gui->summary.accdb->tile_prev_bytes_written    [ s ] = gui->summary.accdb->tile_cur_bytes_written    [ s ];
      gui->summary.accdb->tile_prev_read_ops         [ s ] = gui->summary.accdb->tile_cur_read_ops         [ s ];
      gui->summary.accdb->tile_prev_write_ops        [ s ] = gui->summary.accdb->tile_cur_write_ops        [ s ];
      gui->summary.accdb->tile_prev_misses           [ s ] = gui->summary.accdb->tile_cur_misses           [ s ];
      gui->summary.accdb->tile_prev_evicted          [ s ] = gui->summary.accdb->tile_cur_evicted          [ s ];
      gui->summary.accdb->tile_prev_committed        [ s ] = gui->summary.accdb->tile_cur_committed        [ s ];
      gui->summary.accdb->tile_prev_acquire_calls    [ s ] = gui->summary.accdb->tile_cur_acquire_calls    [ s ];

      /* 60s sparkline accumulator.  Sum this snap's delta into the
         in-flight 1-second bucket; when the bucket closes (>=1s since
         it opened), shift the history rings right (newest at index 0)
         and start a new bucket with the leftover delta. */
      ulong d_acq    = gui->summary.accdb->tile_acquired_win         [ s ][ i ];
      ulong d_acq_wr = gui->summary.accdb->tile_acquired_writable_win[ s ][ i ];
      gui->summary.accdb->tile_sparkline_acq_bucket   [ s ] += d_acq;
      gui->summary.accdb->tile_sparkline_acq_wr_bucket[ s ] += d_acq_wr;

      long bucket_age = cur->sample_time_nanos - gui->summary.accdb->tile_sparkline_bucket_start_nanos[ s ];
      if( gui->summary.accdb->tile_sparkline_bucket_start_nanos[ s ]==0L ) {
        /* First snap for this slot — just open a bucket. */
        gui->summary.accdb->tile_sparkline_bucket_start_nanos[ s ] = cur->sample_time_nanos;
      } else if( bucket_age>=FD_GUI_ACCDB_SPARKLINE_BUCKET_NS ) {
        /* Close the bucket: normalize to per-second, shift right, push. */
        double secs = (double)bucket_age / 1e9;
        double acq_rate    = (double)gui->summary.accdb->tile_sparkline_acq_bucket   [ s ] / secs;
        double acq_wr_rate = (double)gui->summary.accdb->tile_sparkline_acq_wr_bucket[ s ] / secs;
        memmove( &gui->summary.accdb->tile_sparkline_acq_history   [ s ][ 1 ],
                 &gui->summary.accdb->tile_sparkline_acq_history   [ s ][ 0 ],
                 (FD_GUI_ACCDB_SPARKLINE_SAMPLES-1UL)*sizeof(double) );
        memmove( &gui->summary.accdb->tile_sparkline_acq_wr_history[ s ][ 1 ],
                 &gui->summary.accdb->tile_sparkline_acq_wr_history[ s ][ 0 ],
                 (FD_GUI_ACCDB_SPARKLINE_SAMPLES-1UL)*sizeof(double) );
        gui->summary.accdb->tile_sparkline_acq_history   [ s ][ 0 ] = acq_rate;
        gui->summary.accdb->tile_sparkline_acq_wr_history[ s ][ 0 ] = acq_wr_rate;
        if( gui->summary.accdb->tile_sparkline_count[ s ]<FD_GUI_ACCDB_SPARKLINE_SAMPLES )
          gui->summary.accdb->tile_sparkline_count[ s ]++;
        gui->summary.accdb->tile_sparkline_acq_bucket        [ s ] = 0UL;
        gui->summary.accdb->tile_sparkline_acq_wr_bucket     [ s ] = 0UL;
        gui->summary.accdb->tile_sparkline_bucket_start_nanos[ s ] = cur->sample_time_nanos;
      }
    }

    gui->summary.accdb->accdb_win_idx = (i+1UL) % FD_GUI_ACCDB_WIN_SAMPLES;
    if( gui->summary.accdb->accdb_win_count<FD_GUI_ACCDB_WIN_SAMPLES )
      gui->summary.accdb->accdb_win_count++;
  }

  /* Compute weighted denominator once: sum(weight * dt_sec).  Newest
     sample has weight n, oldest has weight 1.  If unfilled, only the
     count samples are used (so first-snap rate is meaningful). */
  ulong  n           = gui->summary.accdb->accdb_win_count;
  double weighted_dt = 0.0;
  for( ulong k=0UL; k<n; k++ ) {
    /* k=0 is newest, k=n-1 is oldest; weight = n - k */
    double w  = (double)(n - k);
    /* idx-1-k in ring */
    ulong  ri = (gui->summary.accdb->accdb_win_idx + FD_GUI_ACCDB_WIN_SAMPLES - 1UL - k) % FD_GUI_ACCDB_WIN_SAMPLES;
    weighted_dt += w * (double)gui->summary.accdb->accdb_win_dt_nanos[ ri ] / 1e9;
  }

  /* Helper: weighted rate of a delta ring. */
# define WRATE( ring ) ( fd_gui_accdb_weighted_rate( (ring), gui->summary.accdb->accdb_win_idx, n, weighted_dt ) )

  double agg_acquired_rate          = WRATE( gui->summary.accdb->agg_acquired_win            );
  double agg_acquired_writable_rate = WRATE( gui->summary.accdb->agg_acquired_writable_win   );
  double agg_bytes_read_rate        = WRATE( gui->summary.accdb->agg_bytes_read_win          );
  double agg_bytes_copied_rate      = WRATE( gui->summary.accdb->agg_bytes_copied_win        );
  double agg_bytes_written_rate     = WRATE( gui->summary.accdb->agg_bytes_written_win       );
  double agg_bytes_written_accdb_rate = WRATE( gui->summary.accdb->agg_bytes_written_accdb_win );
  double agg_read_ops_rate          = WRATE( gui->summary.accdb->agg_read_ops_win            );
  double agg_write_ops_rate         = WRATE( gui->summary.accdb->agg_write_ops_win           );
  double agg_relocated_bytes_rate   = WRATE( gui->summary.accdb->agg_relocated_bytes_win     );
  double agg_misses_rate            = WRATE( gui->summary.accdb->agg_misses_win              );

  double agg_hit_rate = agg_acquired_rate>0.0
    ? fmax( 0.0, 1.0 - agg_misses_rate / agg_acquired_rate )
    : 0.0;


  jsonp_open_envelope( gui->http, "accounts", "stats" );
    jsonp_open_object( gui->http, "value" );
      jsonp_long( gui->http, "sample_time_nanos", cur->sample_time_nanos );

      jsonp_open_object( gui->http, "disk" );
        jsonp_ulong(  gui->http, "accounts_total",       cur->accounts_total       );
        jsonp_ulong(  gui->http, "accounts_capacity",    cur->accounts_capacity    );
        jsonp_ulong(  gui->http, "allocated_bytes",      cur->disk_allocated_bytes );
        jsonp_ulong(  gui->http, "current_bytes",        cur->disk_current_bytes   );
        jsonp_ulong(  gui->http, "used_bytes",           cur->disk_used_bytes      );
      jsonp_close_object( gui->http );

      jsonp_open_object( gui->http, "compaction" );
        jsonp_ulong(  gui->http, "in_compaction",            cur->in_compaction            );
        jsonp_ulong(  gui->http, "compactions_requested",    cur->compactions_requested    );
        jsonp_ulong(  gui->http, "compactions_completed",    cur->compactions_completed    );
        jsonp_ulong(  gui->http, "accounts_relocated_bytes", cur->accounts_relocated_bytes );
        jsonp_double( gui->http, "relocated_bytes_per_sec",  agg_relocated_bytes_rate );
      jsonp_close_object( gui->http );

      ulong cache_size_bytes = 0UL;
      ulong gui_tile_idx = fd_topo_find_tile( gui->topo, "gui", 0UL );
      if( FD_LIKELY( gui_tile_idx!=ULONG_MAX ) ) {
        cache_size_bytes = gui->topo->tiles[ gui_tile_idx ].gui.cache_size_gib * (1UL<<30);
      }

      jsonp_open_object( gui->http, "cache" );
        jsonp_double( gui->http, "hit_rate_ema", agg_hit_rate );
        jsonp_ulong(  gui->http, "size_bytes",   cache_size_bytes );

        jsonp_open_array( gui->http, "classes" );
          for( ulong c=0UL; c<FD_ACCDB_CACHE_CLASS_CNT; c++ ) {
            jsonp_open_object( gui->http, NULL );
              jsonp_ulong(  gui->http, "class",                 c );
              jsonp_ulong(  gui->http, "used_slots",            cur->cache_class_used           [ c ] );
              jsonp_ulong(  gui->http, "max_slots",             cur->cache_class_max            [ c ] );
              jsonp_ulong(  gui->http, "reserved_slots",        cur->cache_class_reserved       [ c ] );
              jsonp_ulong(  gui->http, "target_used_slots",     cur->cache_class_target_used    [ c ] );
              jsonp_ulong(  gui->http, "low_water_used_slots",  cur->cache_class_low_water_used [ c ] );
              jsonp_ulong(  gui->http, "not_found",             cur->not_found_per_class           [ c ] );
              jsonp_ulong(  gui->http, "evicted",               cur->evicted_per_class             [ c ] );
              jsonp_ulong(  gui->http, "preevicted",            cur->preevicted_per_class          [ c ] );
              jsonp_ulong(  gui->http, "committed_new",         cur->committed_new_per_class       [ c ] );
              jsonp_ulong(  gui->http, "committed_overwrite",   cur->committed_overwrite_per_class [ c ] );
              double acq_rate    = WRATE( gui->summary.accdb->class_acq_win        [ c ] );
              double acq_wr_rate = WRATE( gui->summary.accdb->class_acq_wr_win     [ c ] );
              double nf_rate     = WRATE( gui->summary.accdb->class_not_found_win  [ c ] );
              jsonp_double( gui->http, "not_found_per_sec",          nf_rate                                                          );
              jsonp_double( gui->http, "evicted_per_sec",             WRATE( gui->summary.accdb->class_evicted_win    [ c ] )                );
              jsonp_double( gui->http, "preevicted_per_sec",          WRATE( gui->summary.accdb->class_preevicted_win [ c ] )                );
              jsonp_double( gui->http, "committed_new_per_sec",       WRATE( gui->summary.accdb->class_commit_new_win [ c ] )                );
              jsonp_double( gui->http, "committed_overwrite_per_sec", WRATE( gui->summary.accdb->class_commit_over_win[ c ] )                );
              /* reads_per_sec = acquired - acquired_writable (per class);
                 writes_per_sec = acquired_writable (per class). */
              jsonp_double( gui->http, "reads_per_sec",  fmax( 0.0, acq_rate - acq_wr_rate ) );
              jsonp_double( gui->http, "writes_per_sec", acq_wr_rate );
              jsonp_double( gui->http, "hit_rate_ema",
                            acq_rate>0.0 ? fmax( 0.0, 1.0 - nf_rate / acq_rate ) : 0.0 );
            jsonp_close_object( gui->http );
          }
        jsonp_close_array( gui->http );
      jsonp_close_object( gui->http );

      /* Per-tile breakdown.  Iterate the slot table built at init.
         snapwr's row disappears when it has reached the shutdown
         status (matching how snapwr drops out of the overview tiles
         table). */
      jsonp_open_array( gui->http, "tiles" );
        for( ulong s=0UL; s<gui->summary.accdb->accdb_tile_cnt; s++ ) {
          ulong t_idx = (ulong)gui->summary.accdb->accdb_tile_topo_idx[ s ];
          fd_topo_tile_t const * tile = &gui->topo->tiles[ t_idx ];
          uchar kind = gui->summary.accdb->accdb_tile_kind[ s ];

          if( kind==FD_GUI_ACCDB_TILE_KIND_SNAPWR && gui->summary.accdb->tile_cur_status[ s ]==2U ) continue;

          double t_acq_rate    = WRATE( gui->summary.accdb->tile_acquired_win         [ s ] );
          double t_acq_wr_rate = WRATE( gui->summary.accdb->tile_acquired_writable_win[ s ] );
          double t_br_rate     = WRATE( gui->summary.accdb->tile_bytes_read_win       [ s ] );
          double t_bc_rate     = WRATE( gui->summary.accdb->tile_bytes_copied_win     [ s ] );
          double t_bw_rate     = WRATE( gui->summary.accdb->tile_bytes_written_win    [ s ] );
          double t_ro_rate     = WRATE( gui->summary.accdb->tile_read_ops_win         [ s ] );
          double t_wo_rate     = WRATE( gui->summary.accdb->tile_write_ops_win        [ s ] );
          double t_nf_rate     = WRATE( gui->summary.accdb->tile_misses_win           [ s ] );
          double t_ev_rate     = WRATE( gui->summary.accdb->tile_evicted_win          [ s ] );
          double t_cm_rate     = WRATE( gui->summary.accdb->tile_committed_win        [ s ] );
          double t_ac_rate     = WRATE( gui->summary.accdb->tile_acquire_calls_win    [ s ] );

          char const * joiner;
          switch( kind ) {
            case FD_GUI_ACCDB_TILE_KIND_RW:     joiner = "RW"; break;
            case FD_GUI_ACCDB_TILE_KIND_SNAPWR: joiner = "RW"; break;
            case FD_GUI_ACCDB_TILE_KIND_ACCDB:  joiner = "RW"; break;
            default:                            joiner = "RO"; break;
          }

          jsonp_open_object( gui->http, NULL );
            jsonp_string( gui->http, "name",         tile->name );
            jsonp_ulong(  gui->http, "kind_id",      tile->kind_id );
            jsonp_string( gui->http, "joiner_type",  joiner );
            jsonp_ulong(  gui->http, "status",       (ulong)gui->summary.accdb->tile_cur_status[ s ] );

            /* Lifetime totals. */
            jsonp_ulong(  gui->http, "acquired",      gui->summary.accdb->tile_cur_acquired      [ s ] );
            jsonp_ulong(  gui->http, "bytes_read",    gui->summary.accdb->tile_cur_bytes_read    [ s ] );
            jsonp_ulong(  gui->http, "bytes_written", gui->summary.accdb->tile_cur_bytes_written [ s ] );

            /* Rates. */
            jsonp_double( gui->http, "acquired_per_sec",          t_acq_rate    );
            jsonp_double( gui->http, "acquired_writable_per_sec", t_acq_wr_rate );
            jsonp_double( gui->http, "bytes_read_per_sec",        t_br_rate     );
            jsonp_double( gui->http, "bytes_copied_per_sec",      t_bc_rate     );
            jsonp_double( gui->http, "bytes_written_per_sec",     t_bw_rate     );
            jsonp_double( gui->http, "read_ops_per_sec",          t_ro_rate     );
            jsonp_double( gui->http, "write_ops_per_sec",         t_wo_rate     );
            jsonp_double( gui->http, "not_found_per_sec",         t_nf_rate     );
            jsonp_double( gui->http, "evicted_per_sec",           t_ev_rate     );
            jsonp_double( gui->http, "committed_per_sec",         t_cm_rate     );
            jsonp_double( gui->http, "acquire_calls_per_sec",     t_ac_rate     );

            jsonp_double( gui->http, "hit_rate_ema",
                          t_acq_rate>0.0 ? fmax( 0.0, 1.0 - t_nf_rate / t_acq_rate ) : 0.0 );

            /* 60-second sparkline history.  Emit oldest-first so the
               frontend treats index 0 as the leftmost (oldest) sample. */
            ulong sp_cnt = gui->summary.accdb->tile_sparkline_count[ s ];
            jsonp_open_array( gui->http, "acquired_history" );
              for( ulong k=0UL; k<sp_cnt; k++ ) {
                ulong idx = sp_cnt - 1UL - k;
                jsonp_double( gui->http, NULL, gui->summary.accdb->tile_sparkline_acq_history[ s ][ idx ] );
              }
            jsonp_close_array( gui->http );
            jsonp_open_array( gui->http, "acquired_writable_history" );
              for( ulong k=0UL; k<sp_cnt; k++ ) {
                ulong idx = sp_cnt - 1UL - k;
                jsonp_double( gui->http, NULL, gui->summary.accdb->tile_sparkline_acq_wr_history[ s ][ idx ] );
              }
            jsonp_close_array( gui->http );
          jsonp_close_object( gui->http );
        }
      jsonp_close_array( gui->http );

      jsonp_open_object( gui->http, "io" );
        jsonp_ulong(  gui->http, "acquired",            cur->acquired            );
        jsonp_ulong(  gui->http, "acquired_writable",   cur->acquired_writable   );
        jsonp_ulong(  gui->http, "bytes_read",          cur->bytes_read          );
        jsonp_ulong(  gui->http, "bytes_copied",        cur->bytes_copied        );
        jsonp_ulong(  gui->http, "bytes_written",       cur->bytes_written       );
        jsonp_ulong(  gui->http, "bytes_written_accdb", cur->bytes_written_accdb );
        jsonp_ulong(  gui->http, "read_ops",            cur->read_ops            );
        jsonp_ulong(  gui->http, "write_ops",           cur->write_ops           );
        jsonp_double( gui->http, "acquired_per_sec",          agg_acquired_rate          );
        jsonp_double( gui->http, "acquired_writable_per_sec", agg_acquired_writable_rate );
        jsonp_double( gui->http, "bytes_read_per_sec",        agg_bytes_read_rate        );
        jsonp_double( gui->http, "bytes_copied_per_sec",      agg_bytes_copied_rate      );
        jsonp_double( gui->http, "bytes_written_per_sec",     agg_bytes_written_rate     );
        jsonp_double( gui->http, "read_ops_per_sec",          agg_read_ops_rate          );
        jsonp_double( gui->http, "write_ops_per_sec",         agg_write_ops_rate         );
        /* Prewrite ratio: fraction of bytes written that came from the
           accdb tile's background work (preevict + compaction).
           cur->bytes_written already includes accdb tile's writes, so
           the ratio is just accdb_rate / bytes_written_rate. */
        jsonp_double( gui->http, "prewrite_ratio",
                      agg_bytes_written_rate>0.0
                        ? fmin( 1.0, agg_bytes_written_accdb_rate / agg_bytes_written_rate )
                        : 0.0 );
      jsonp_close_object( gui->http );

      /* Per-partition table.  Only emit partitions that have been
         written to (skip the cold tail of the pool that has never been
         allocated).  Ticks are converted to wallclock nanoseconds using
         the GUI tile's locally-measured tick rate, since the accdb hot
         path stamps fd_tickcount() rather than fd_log_wallclock() (no
         syscall on the IO path). */
      jsonp_open_array( gui->http, "partitions" );
      if( FD_LIKELY( gui->accdb_shmem ) ) {
        ulong  partition_sz = fd_accdb_shmem_partition_sz( gui->accdb_shmem );
        long   now_ticks    = (long)fd_tickcount();
        double tick_per_ns  = gui->tick_per_ns;
        for( ulong p=0UL; p<gui->summary.accdb->partition_cnt; p++ ) {
          fd_accdb_shmem_partition_info_t const * info = &gui->summary.accdb->partitions[ p ];
          /* Skip partitions that have never been written and are not
             currently in any compaction state. */
          if( !info->bytes_written && !info->compaction_state ) continue;

          double read_ops_rate     = WRATE( gui->summary.accdb->partition_read_ops_win    [ p ] );
          double bytes_read_rate   = WRATE( gui->summary.accdb->partition_bytes_read_win  [ p ] );
          double write_ops_rate    = WRATE( gui->summary.accdb->partition_write_ops_win   [ p ] );
          double bytes_written_rate= WRATE( gui->summary.accdb->partition_bytes_written_win[p ] );

          double age_seconds    = 0.0;
          double filled_seconds = 0.0;
          if( info->created_ticks && tick_per_ns>0.0 ) {
            age_seconds    = ((double)(now_ticks - info->created_ticks)) / tick_per_ns / 1e9;
            if( age_seconds<0.0 ) age_seconds = 0.0;
          }
          if( info->filled_ticks && tick_per_ns>0.0 ) {
            filled_seconds = ((double)(now_ticks - info->filled_ticks )) / tick_per_ns / 1e9;
            if( filled_seconds<0.0 ) filled_seconds = 0.0;
          }

          /* Fully compacted, awaiting reclaim: present as an "Off" tier
             with zeroed utilization so the row visually clears once its
             data has been moved out. */
          int    is_compacted   = info->compaction_state==0 &&
                                  info->write_offset>0UL &&
                                  info->compaction_offset>=info->write_offset;
          ulong  tier           = is_compacted ? 255UL : (ulong)info->layer;
          double utilization    = (!is_compacted && partition_sz)
            ? (double)info->write_offset / (double)partition_sz : 0.0;
          double fragmentation  = (!is_compacted && info->write_offset)
            ? (double)info->bytes_freed / (double)info->write_offset : 0.0;
          ulong  used_bytes     = (!is_compacted && info->write_offset > info->bytes_freed)
            ? info->write_offset - info->bytes_freed : 0UL;
          double used_frac      = partition_sz ? (double)used_bytes        / (double)partition_sz : 0.0;
          double fragmented_frac= (!is_compacted && partition_sz) ? (double)info->bytes_freed / (double)partition_sz : 0.0;
          double compaction_frac= (!is_compacted && partition_sz) ? (double)info->compaction_offset / (double)partition_sz : 0.0;

          jsonp_open_object( gui->http, NULL );
            jsonp_ulong(  gui->http, "partition_idx",     p );
            jsonp_ulong(  gui->http, "file_offset",       info->file_offset );
            jsonp_ulong(  gui->http, "tier",              tier );
            jsonp_ulong(  gui->http, "write_offset",      info->write_offset );
            jsonp_ulong(  gui->http, "bytes_freed",       info->bytes_freed );
            jsonp_ulong(  gui->http, "read_ops",          info->read_ops );
            jsonp_ulong(  gui->http, "bytes_read",        info->bytes_read );
            jsonp_ulong(  gui->http, "write_ops",         info->write_ops );
            jsonp_ulong(  gui->http, "bytes_written",     info->bytes_written );
            jsonp_double( gui->http, "read_ops_per_sec",     read_ops_rate );
            jsonp_double( gui->http, "bytes_read_per_sec",   bytes_read_rate );
            jsonp_double( gui->http, "write_ops_per_sec",    write_ops_rate );
            jsonp_double( gui->http, "bytes_written_per_sec",bytes_written_rate );
            jsonp_double( gui->http, "utilization",       utilization );
            jsonp_double( gui->http, "fragmentation",     fragmentation );
            jsonp_double( gui->http, "used_frac",         used_frac );
            jsonp_double( gui->http, "fragmented_frac",   fragmented_frac );
            jsonp_double( gui->http, "compaction_trigger_frac", 0.30 );
            jsonp_double( gui->http, "age_seconds",       age_seconds );
            jsonp_double( gui->http, "filled_seconds",    filled_seconds );
            jsonp_ulong(  gui->http, "compaction_state",  (ulong)info->compaction_state );
            jsonp_double( gui->http, "compaction_frac",   compaction_frac );
            jsonp_bool(   gui->http, "is_write_head",    (int)info->is_write_head );
          jsonp_close_object( gui->http );
        }
      }
      jsonp_close_array( gui->http );

    jsonp_close_object( gui->http );
  jsonp_close_envelope( gui->http );

# undef WRATE
}

static void
peers_printf_node( fd_gui_peers_ctx_t *  peers,
                   ulong                 contact_info_table_idx ) {
  fd_gui_peers_node_t * peer = &peers->contact_info_table[ contact_info_table_idx ];

  jsonp_open_object( peers->http, NULL );

    char identity_base58[ FD_BASE58_ENCODED_32_SZ ];
    fd_base58_encode_32( peer->row.pubkey.uc, NULL, identity_base58 );
    jsonp_string( peers->http, "identity_pubkey", identity_base58 );

    jsonp_open_object( peers->http, "gossip" );

      char version[ 64UL ];
      FD_TEST( fd_gossip_version_cstr( peer->row.contact_info.version.major, peer->row.contact_info.version.minor, peer->row.contact_info.version.patch, version, sizeof( version ) ) );
      jsonp_string( peers->http, "version", version );
      jsonp_ulong( peers->http, "client_id", peer->row.contact_info.version.client );
      jsonp_ulong( peers->http, "feature_set", peer->row.contact_info.version.feature_set );
      jsonp_long( peers->http, "wallclock", peer->row.wallclock_nanos );
      jsonp_ulong( peers->http, "shred_version", peer->row.contact_info.shred_version );
      jsonp_open_object( peers->http, "sockets" );
        for( ulong j=0UL; j<FD_GOSSIP_CONTACT_INFO_SOCKET_CNT; j++ ) {
          char const * tag;
          switch( j ) {
            case FD_GOSSIP_CONTACT_INFO_SOCKET_GOSSIP:            tag = "gossip";            break;
            case FD_GOSSIP_CONTACT_INFO_SOCKET_SERVE_REPAIR_QUIC: tag = "serve_repair_quic"; break;
            case FD_GOSSIP_CONTACT_INFO_SOCKET_RPC:               tag = "rpc";               break;
            case FD_GOSSIP_CONTACT_INFO_SOCKET_RPC_PUBSUB:        tag = "rpc_pubsub";        break;
            case FD_GOSSIP_CONTACT_INFO_SOCKET_SERVE_REPAIR:      tag = "serve_repair";      break;
            case FD_GOSSIP_CONTACT_INFO_SOCKET_TPU:               tag = "tpu";               break;
            case FD_GOSSIP_CONTACT_INFO_SOCKET_TPU_FORWARDS:      tag = "tpu_forwards";      break;
            case FD_GOSSIP_CONTACT_INFO_SOCKET_TPU_FORWARDS_QUIC: tag = "tpu_forwards_quic"; break;
            case FD_GOSSIP_CONTACT_INFO_SOCKET_TPU_QUIC:          tag = "tpu_quic";          break;
            case FD_GOSSIP_CONTACT_INFO_SOCKET_TPU_VOTE:          tag = "tpu_vote";          break;
            case FD_GOSSIP_CONTACT_INFO_SOCKET_TVU:               tag = "tvu";               break;
            case FD_GOSSIP_CONTACT_INFO_SOCKET_TVU_QUIC:          tag = "tvu_quic";          break;
            case FD_GOSSIP_CONTACT_INFO_SOCKET_TPU_VOTE_QUIC:     tag = "tpu_vote_quic";     break;
            case FD_GOSSIP_CONTACT_INFO_SOCKET_ALPENGLOW:         tag = "alpenglow";         break;
            default:                                       tag = "unknown";           break;
          }
          uint ip4 = peer->row.contact_info.sockets[ j ].is_ipv6 ? 0U : peer->row.contact_info.sockets[ j ].ip4;
          char line[ 64 ];
          FD_TEST( fd_cstr_printf( line, sizeof( line ), NULL, FD_IP4_ADDR_FMT ":%hu", FD_IP4_ADDR_FMT_ARGS( ip4 ), fd_ushort_bswap( peer->row.contact_info.sockets[ j ].port ) ) );
          jsonp_string( peers->http, tag, line );
        }
      jsonp_close_object( peers->http );

      if( FD_LIKELY( peer->row.country_code_idx!=UCHAR_MAX ) ) {
        jsonp_string( peers->http, "country_code", peers->dbip.country_code[ peer->row.country_code_idx ] );
      } else {
        jsonp_null( peers->http, "country_code" );
      }

      if( FD_LIKELY( peer->row.city_name_idx!=UINT_MAX ) ) {
        jsonp_string( peers->http, "city_name", peers->dbip.city_name[ peer->row.city_name_idx ] );
      } else {
        jsonp_null( peers->http, "city_name" );
      }

    jsonp_close_object( peers->http );

    if( FD_LIKELY( !peer->row.has_vote_info ) ) {
      jsonp_open_array( peers->http, "vote" );
      jsonp_close_array( peers->http );
    } else {
      jsonp_open_array( peers->http, "vote" );
        jsonp_open_object( peers->http, NULL );
          char vote_account_base58[ FD_BASE58_ENCODED_32_SZ ];
          fd_base58_encode_32( peer->row.vote_account.uc, NULL, vote_account_base58 );
          jsonp_string( peers->http, "vote_account", vote_account_base58 );
          jsonp_ulong_as_str( peers->http, "activated_stake", fd_ulong_if( peer->row.stake==ULONG_MAX, 0UL, peer->row.stake ) );
          jsonp_ulong( peers->http, "last_vote", 0UL ); /* todo: deprecate */
          jsonp_ulong( peers->http, "epoch_credits", 0UL ); /* todo: deprecate */
          jsonp_ulong( peers->http, "commission", 0UL ); /* todo: deprecate */
          jsonp_ulong( peers->http, "root_slot", 0UL ); /* todo: deprecate */
          jsonp_bool( peers->http,  "delinquent", peer->row.delinquent );
        jsonp_close_object( peers->http );
      jsonp_close_array( peers->http );
    }

    fd_gui_config_parse_info_t * node_info = fd_gui_peers_node_info_map_ele_query( peers->node_info_map, &peer->row.pubkey, NULL, peers->node_info_pool );
    if( FD_UNLIKELY( !node_info ) ) {
      jsonp_string( peers->http, "info", NULL );
    } else {
      jsonp_open_object( peers->http, "info" );
        jsonp_string( peers->http, "name", node_info->name );
        jsonp_string( peers->http, "details", node_info->details );
        jsonp_string( peers->http, "website", node_info->website );
        jsonp_string( peers->http, "icon_url", node_info->icon_uri );
        jsonp_string( peers->http, "keybase_username", node_info->keybase_username );
      jsonp_close_object( peers->http );
    }

  jsonp_close_object( peers->http );
}

void
fd_gui_peers_printf_nodes( fd_gui_peers_ctx_t * peers,
                           int *                actions,
                           ulong *              idxs,
                           ulong                count ) {
  jsonp_open_envelope( peers->http, "peers", "update" );
    jsonp_open_object( peers->http, "value" );
      jsonp_open_array( peers->http, "add" );
        for( ulong i=0UL; i<count; i++ ) if( FD_UNLIKELY( actions[ i ]==FD_GUI_PEERS_NODE_ADD ) ) peers_printf_node( peers, idxs[ i ] );
      jsonp_close_array( peers->http );

      jsonp_open_array( peers->http, "update" );
        for( ulong i=0UL; i<count; i++ ) if( FD_UNLIKELY( actions[ i ]==FD_GUI_PEERS_NODE_UPDATE ) ) peers_printf_node( peers, idxs[ i ] );
      jsonp_close_array( peers->http );

      jsonp_open_array( peers->http, "remove" );
        for( ulong i=0UL; i<count; i++ ) {
          if( FD_UNLIKELY( actions[ i ]==FD_GUI_PEERS_NODE_DELETE ) ) {
            jsonp_open_object( peers->http, NULL );
              char identity_base58[ FD_BASE58_ENCODED_32_SZ ];
              fd_base58_encode_32( peers->contact_info_table[ idxs[ i ] ].row.pubkey.uc, NULL, identity_base58 );
              jsonp_string( peers->http, "identity_pubkey", identity_base58 );
            jsonp_close_object( peers->http );
          }
        }
      jsonp_close_array( peers->http );
    jsonp_close_object( peers->http );
  jsonp_close_envelope( peers->http );
}

void
fd_gui_peers_printf_node_all( fd_gui_peers_ctx_t *  peers ) {
  jsonp_open_envelope( peers->http, "peers", "update" );
    jsonp_open_object( peers->http, "value" );
      jsonp_open_array( peers->http, "add" );
        /* We can iter through the bandwidth tracking table since it will always be populated */
        for( fd_gui_peers_bandwidth_tracking_fwd_iter_t iter = fd_gui_peers_bandwidth_tracking_fwd_iter_init( peers->bw_tracking, &FD_GUI_PEERS_BW_TRACKING_INGRESS_SORT_KEY, peers->contact_info_table );
             !fd_gui_peers_bandwidth_tracking_fwd_iter_done( iter );
             iter = fd_gui_peers_bandwidth_tracking_fwd_iter_next( iter, peers->contact_info_table ) ) {
          ulong contact_info_table_idx = fd_gui_peers_bandwidth_tracking_fwd_iter_idx( iter );
          peers_printf_node( peers, contact_info_table_idx );
        }
      jsonp_close_array( peers->http );
      jsonp_open_array( peers->http, "update" );
      jsonp_close_array( peers->http );
      jsonp_open_array( peers->http, "remove" );
      jsonp_close_array( peers->http );
    jsonp_close_object( peers->http );
  jsonp_close_envelope( peers->http );
}

static void
fd_gui_printf_ts_tile_timers( fd_gui_t *                        gui,
                              long                              sample_time_nanos,
                              fd_gui_tile_timers_hist_t const * packed ) {
  jsonp_open_object( gui->http, NULL );
    jsonp_long_as_str( gui->http, "timestamp_nanos", sample_time_nanos );
    jsonp_open_array( gui->http, "tile_timers" );
      fd_gui_printf_tile_timers( gui, packed );
    jsonp_close_array( gui->http );
  jsonp_close_object( gui->http );
}

static int
fd_gui_load_leader_meta( fd_gui_t *                      gui,
                         ulong                          _slot,
                         fd_gui_leader_slot_t * out ) {
  memset( out, 0, sizeof(*out) );
  if( FD_UNLIKELY( !gui->db ) ) return 0;
  fd_gui_leader_slot_t const * rec = fd_gui_hist_kv_get_slot_any( gui, FD_GUI_HIST_LEADER_SLOT, _slot );
  if( FD_UNLIKELY( !rec ) ) return 0;
  *out = *rec;
  return 1;
}

static int
fd_gui_load_block_hash( fd_gui_t *  gui,
                        ulong       _slot,
                        fd_hash_t * out ) {
  if( FD_UNLIKELY( !gui->db ) ) return 0;

  fd_gui_slot_t const * replay = fd_gui_hist_kv_get_slot_any( gui, FD_GUI_HIST_SLOT, _slot );
  if( FD_LIKELY( replay ) ) {
    *out = replay->block_hash;
    return 1;
  }

  fd_gui_leader_slot_t const * leader = fd_gui_hist_kv_get_slot_any( gui, FD_GUI_HIST_LEADER_SLOT, _slot );
  if( FD_LIKELY( leader ) ) {
    *out = leader->block_hash;
    return 1;
  }

  return 0;
}

static long
fd_gui_load_slot_duration( fd_gui_t *            gui,
                           ulong                 _slot,
                           fd_gui_slot_t const * slot ) {
  if( FD_UNLIKELY( slot->completed_time==LONG_MAX ) ) return LONG_MAX;

  long parent_completed_time = LONG_MAX;
  fd_gui_slot_t * parent_slot = fd_gui_slot_get_canon( gui, slot->parent_slot );
  if( FD_LIKELY( parent_slot ) ) {
    parent_completed_time = parent_slot->completed_time;
  } else if( FD_LIKELY( gui->db ) ) {
    fd_gui_slot_t const * replay = fd_gui_hist_kv_get_slot_any( gui, FD_GUI_HIST_SLOT, _slot );
    if( FD_LIKELY( replay ) ) parent_completed_time = replay->parent_completed_time;
  }

  if( FD_UNLIKELY( parent_completed_time==LONG_MAX ) ) return LONG_MAX;
  return slot->completed_time - parent_completed_time;
}

void
fd_gui_printf_slot( fd_gui_t *            gui,
                    ulong                _slot,
                    fd_gui_slot_t const * slot ) {
  char const * level;
  switch( slot->level ) {
    case FD_GUI_SLOT_LEVEL_INCOMPLETE:               level = "incomplete"; break;
    case FD_GUI_SLOT_LEVEL_COMPLETED:                level = "completed";  break;
    case FD_GUI_SLOT_LEVEL_OPTIMISTICALLY_CONFIRMED: level = "optimistically_confirmed"; break;
    case FD_GUI_SLOT_LEVEL_ROOTED:                   level = "rooted"; break;
    case FD_GUI_SLOT_LEVEL_FINALIZED:                level = "finalized"; break;
    default:                                         level = "unknown"; break;
  }

  long duration_nanos = fd_gui_load_slot_duration( gui, _slot, slot );

  jsonp_open_envelope( gui->http, "slot", "update" );
    jsonp_open_object( gui->http, "value" );
      fd_gui_leader_slot_t lmeta[ 1 ];
      int have_lmeta = fd_gui_load_leader_meta( gui, _slot, lmeta );
      jsonp_open_object( gui->http, "publish" );
        jsonp_ulong( gui->http, "slot", _slot );
        jsonp_bool( gui->http, "mine", slot->mine );
        if( FD_UNLIKELY( slot->vote_slot!=ULONG_MAX ) ) jsonp_ulong( gui->http, "vote_slot", slot->vote_slot );
        else                                            jsonp_null( gui->http, "vote_slot" );
        if( FD_UNLIKELY( slot->vote_latency!=UCHAR_MAX ) ) jsonp_ulong( gui->http, "vote_latency", slot->vote_latency );
        else                                               jsonp_null( gui->http, "vote_latency" );

        if( FD_UNLIKELY( have_lmeta && lmeta->leader_start_time!=LONG_MAX ) ) jsonp_long_as_str( gui->http, "start_timestamp_nanos", lmeta->leader_start_time  );
        else                                                                  jsonp_null       ( gui->http, "start_timestamp_nanos" );
        if( FD_UNLIKELY( have_lmeta && lmeta->leader_end_time!=LONG_MAX ) ) jsonp_long_as_str( gui->http, "target_end_timestamp_nanos", lmeta->leader_end_time  );
        else                                                                jsonp_null       ( gui->http, "target_end_timestamp_nanos" );

        jsonp_bool( gui->http, "skipped", slot->skip==FD_GUI_SKIP_STATUS_SKIPPED );
        if( FD_UNLIKELY( duration_nanos==LONG_MAX ) ) jsonp_null( gui->http, "duration_nanos" );
        else                                          jsonp_long( gui->http, "duration_nanos", duration_nanos );
        if( FD_UNLIKELY( slot->completed_time==LONG_MAX ) ) jsonp_null( gui->http, "completed_time_nanos" );
        else                                                jsonp_long_as_str( gui->http, "completed_time_nanos", slot->completed_time );
        jsonp_string( gui->http, "level", level );
        if( FD_UNLIKELY( slot->nonvote_success==UINT_MAX ) ) jsonp_null( gui->http, "success_nonvote_transaction_cnt" );
        else                                                           jsonp_ulong( gui->http, "success_nonvote_transaction_cnt", slot->nonvote_success );
        if( FD_UNLIKELY( slot->nonvote_failed==UINT_MAX ) ) jsonp_null( gui->http, "failed_nonvote_transaction_cnt" );
        else                                                jsonp_ulong( gui->http, "failed_nonvote_transaction_cnt", slot->nonvote_failed );
        if( FD_UNLIKELY( slot->vote_success==UINT_MAX ) ) jsonp_null( gui->http, "success_vote_transaction_cnt" );
        else                                              jsonp_ulong( gui->http, "success_vote_transaction_cnt", slot->vote_success );
        if( FD_UNLIKELY( slot->vote_failed==UINT_MAX ) ) jsonp_null( gui->http, "failed_vote_transaction_cnt" );
        else                                             jsonp_ulong( gui->http, "failed_vote_transaction_cnt", slot->vote_failed );
        if( FD_UNLIKELY( slot->max_compute_units==UINT_MAX ) ) jsonp_null( gui->http, "max_compute_units" );
        else                                                   jsonp_ulong( gui->http, "max_compute_units", slot->max_compute_units );
        if( FD_UNLIKELY( slot->compute_units==UINT_MAX ) ) jsonp_null( gui->http, "compute_units" );
        else                                               jsonp_ulong( gui->http, "compute_units", slot->compute_units );
        if( FD_UNLIKELY( slot->shred_cnt==UINT_MAX ) ) jsonp_null( gui->http, "shreds" );
        else                                           jsonp_ulong( gui->http, "shreds", slot->shred_cnt );
        if( FD_UNLIKELY( slot->transaction_fee==ULONG_MAX ) ) jsonp_null( gui->http, "transaction_fee" );
        else                                                  jsonp_ulong_as_str( gui->http, "transaction_fee", slot->transaction_fee );
        if( FD_UNLIKELY( slot->priority_fee==ULONG_MAX ) ) jsonp_null( gui->http, "priority_fee" );
        else                                               jsonp_ulong_as_str( gui->http, "priority_fee", slot->priority_fee );
        if( FD_UNLIKELY( slot->tips==ULONG_MAX ) ) jsonp_null( gui->http, "tips" );
        else                                       jsonp_ulong_as_str( gui->http, "tips", slot->tips );
      jsonp_close_object( gui->http );
    jsonp_close_object( gui->http );
  jsonp_close_envelope( gui->http );
}

void
fd_gui_printf_summary_ping( fd_gui_t * gui,
                            ulong      id ) {
  jsonp_open_envelope( gui->http, "summary", "ping" );
    jsonp_ulong( gui->http, "id", id );
    jsonp_null( gui->http, "value" );
  jsonp_close_envelope( gui->http );
}

void
fd_gui_printf_slot_rankings_request( fd_gui_t * gui,
                                     ulong      id,
                                     int        mine ) {
  fd_gui_epoch_t * rec = fd_gui_current_epoch( gui );

  fd_gui_slot_rankings_t * rankings = FD_LIKELY( rec )
    ? fd_ptr_if( mine, (fd_gui_slot_rankings_t *)rec->my_rankings, (fd_gui_slot_rankings_t *)rec->rankings )
    : NULL;

  jsonp_open_envelope( gui->http, "slot", "query_rankings" );
    jsonp_ulong( gui->http, "id", id );
    jsonp_open_object( gui->http, "value" );

#define OUTPUT_RANKING_ARRAY(field) \
      jsonp_open_array( gui->http, "slots_" FD_STRINGIFY(field) ); \
      for( ulong i = 0UL; i<fd_ulong_if( rankings==NULL, 0UL, FD_GUI_SLOT_RANKINGS_SZ ); i++ ) { \
        if( FD_UNLIKELY( rankings->field[ i ].slot==ULONG_MAX ) ) break; \
        jsonp_ulong( gui->http, NULL, rankings->field[ i ].slot ); \
      } \
      jsonp_close_array( gui->http ); \
      jsonp_open_array( gui->http, "vals_" FD_STRINGIFY(field) ); \
      for( ulong i = 0UL; i<fd_ulong_if( rankings==NULL, 0UL, FD_GUI_SLOT_RANKINGS_SZ ); i++ ) { \
        if( FD_UNLIKELY( rankings->field[ i ].slot==ULONG_MAX ) ) break; \
        jsonp_ulong( gui->http, NULL, rankings->field[ i ].value ); \
      } \
      jsonp_close_array( gui->http )

      OUTPUT_RANKING_ARRAY( largest_tips );
      OUTPUT_RANKING_ARRAY( largest_fees );
      OUTPUT_RANKING_ARRAY( largest_rewards );
      OUTPUT_RANKING_ARRAY( largest_rewards_per_cu );
      OUTPUT_RANKING_ARRAY( largest_duration );
      OUTPUT_RANKING_ARRAY( largest_compute_units );
      OUTPUT_RANKING_ARRAY( largest_skipped );
      OUTPUT_RANKING_ARRAY( smallest_tips );
      OUTPUT_RANKING_ARRAY( smallest_fees );
      OUTPUT_RANKING_ARRAY( smallest_rewards );
      OUTPUT_RANKING_ARRAY( smallest_rewards_per_cu );
      OUTPUT_RANKING_ARRAY( smallest_duration );
      OUTPUT_RANKING_ARRAY( smallest_compute_units );
      OUTPUT_RANKING_ARRAY( smallest_skipped );

#undef OUTPUT_RANKING_ARRAY

    jsonp_close_object( gui->http );
  jsonp_close_envelope( gui->http );
}

void
fd_gui_printf_slot_request( fd_gui_t *            gui,
                            ulong                _slot,
                            ulong                id,
                            fd_gui_slot_t const * slot ) {
  char const * level;
  switch( slot->level ) {
    case FD_GUI_SLOT_LEVEL_INCOMPLETE:               level = "incomplete"; break;
    case FD_GUI_SLOT_LEVEL_COMPLETED:                level = "completed";  break;
    case FD_GUI_SLOT_LEVEL_OPTIMISTICALLY_CONFIRMED: level = "optimistically_confirmed"; break;
    case FD_GUI_SLOT_LEVEL_ROOTED:                   level = "rooted"; break;
    case FD_GUI_SLOT_LEVEL_FINALIZED:                level = "finalized"; break;
    default:                                         level = "unknown"; break;
  }

  long duration_nanos = fd_gui_load_slot_duration( gui, _slot, slot );

  jsonp_open_envelope( gui->http, "slot", "query" );
    jsonp_ulong( gui->http, "id", id );
    jsonp_open_object( gui->http, "value" );
      fd_gui_leader_slot_t lmeta[ 1 ];
      int have_lmeta = fd_gui_load_leader_meta( gui, _slot, lmeta );

      jsonp_open_object( gui->http, "publish" );
        jsonp_ulong( gui->http, "slot", _slot );
        jsonp_bool( gui->http, "mine", slot->mine );
        if( FD_UNLIKELY( slot->vote_slot!=ULONG_MAX ) ) jsonp_ulong( gui->http, "vote_slot", slot->vote_slot );
        else                                            jsonp_null( gui->http, "vote_slot" );
        if( FD_UNLIKELY( slot->vote_latency!=UCHAR_MAX ) ) jsonp_ulong( gui->http, "vote_latency", slot->vote_latency );
        else                                               jsonp_null( gui->http, "vote_latency" );

        if( FD_UNLIKELY( have_lmeta && lmeta->leader_start_time!=LONG_MAX ) ) jsonp_long_as_str( gui->http, "start_timestamp_nanos", lmeta->leader_start_time  );
        else                                                                  jsonp_null       ( gui->http, "start_timestamp_nanos" );
        if( FD_UNLIKELY( have_lmeta && lmeta->leader_end_time!=LONG_MAX ) ) jsonp_long_as_str( gui->http, "target_end_timestamp_nanos", lmeta->leader_end_time  );
        else                                                                jsonp_null       ( gui->http, "target_end_timestamp_nanos" );

        jsonp_bool( gui->http, "skipped", slot->skip==FD_GUI_SKIP_STATUS_SKIPPED );
        jsonp_string( gui->http, "level", level );
        if( FD_UNLIKELY( duration_nanos==LONG_MAX ) ) jsonp_null( gui->http, "duration_nanos" );
        else                                          jsonp_long( gui->http, "duration_nanos", duration_nanos );
        if( FD_UNLIKELY( slot->completed_time==LONG_MAX ) ) jsonp_null( gui->http, "completed_time_nanos" );
        else                                                jsonp_long_as_str( gui->http, "completed_time_nanos", slot->completed_time );
        if( FD_UNLIKELY( slot->nonvote_success==UINT_MAX ) ) jsonp_null( gui->http, "success_nonvote_transaction_cnt" );
        else                                                 jsonp_ulong( gui->http, "success_nonvote_transaction_cnt", slot->nonvote_success );
        if( FD_UNLIKELY( slot->nonvote_failed==UINT_MAX ) ) jsonp_null( gui->http, "failed_nonvote_transaction_cnt" );
        else                                                        jsonp_ulong( gui->http, "failed_nonvote_transaction_cnt", slot->nonvote_failed );
        if( FD_UNLIKELY( slot->vote_success==UINT_MAX ) ) jsonp_null( gui->http, "success_vote_transaction_cnt" );
        else                                              jsonp_ulong( gui->http, "success_vote_transaction_cnt", slot->vote_success );
        if( FD_UNLIKELY( slot->vote_failed==UINT_MAX ) ) jsonp_null( gui->http, "failed_vote_transaction_cnt" );
        else                                             jsonp_ulong( gui->http, "failed_vote_transaction_cnt", slot->vote_failed );
        if( FD_UNLIKELY( slot->max_compute_units==UINT_MAX ) ) jsonp_null( gui->http, "max_compute_units" );
        else                                                   jsonp_ulong( gui->http, "max_compute_units", slot->max_compute_units );
        if( FD_UNLIKELY( slot->compute_units==UINT_MAX ) ) jsonp_null( gui->http, "compute_units" );
        else                                               jsonp_ulong( gui->http, "compute_units", slot->compute_units );
        if( FD_UNLIKELY( slot->shred_cnt==UINT_MAX ) ) jsonp_null( gui->http, "shreds" );
        else                                           jsonp_ulong( gui->http, "shreds", slot->shred_cnt );
        if( FD_UNLIKELY( slot->transaction_fee==ULONG_MAX ) ) jsonp_null( gui->http, "transaction_fee" );
        else                                                  jsonp_ulong( gui->http, "transaction_fee", slot->transaction_fee );
        if( FD_UNLIKELY( slot->priority_fee==ULONG_MAX ) ) jsonp_null( gui->http, "priority_fee" );
        else                                               jsonp_ulong( gui->http, "priority_fee", slot->priority_fee );
        if( FD_UNLIKELY( slot->tips==ULONG_MAX ) ) jsonp_null( gui->http, "tips" );
        else                                       jsonp_ulong( gui->http, "tips", slot->tips );
      jsonp_close_object( gui->http );

    jsonp_close_object( gui->http );
  jsonp_close_envelope( gui->http );
}

#define SORT_NAME fd_gui_slot_txn_start_sort
#define SORT_KEY_T fd_gui_store_txn_start_t
#define SORT_BEFORE(a,b) ( (a).txn_idx<(b).txn_idx )
#include "../../util/tmpl/fd_sort.c"

#define SORT_NAME fd_gui_slot_txn_end_sort
#define SORT_KEY_T fd_gui_store_txn_end_t
#define SORT_BEFORE(a,b) ( (a).txn_idx<(b).txn_idx )
#include "../../util/tmpl/fd_sort.c"

void
fd_gui_printf_slot_transactions_request( fd_gui_t *            gui,
                                         ulong                _slot,
                                         ulong                id,
                                         fd_gui_slot_t const * slot ) {
  char const * level;
  switch( slot->level ) {
    case FD_GUI_SLOT_LEVEL_INCOMPLETE:               level = "incomplete"; break;
    case FD_GUI_SLOT_LEVEL_COMPLETED:                level = "completed";  break;
    case FD_GUI_SLOT_LEVEL_OPTIMISTICALLY_CONFIRMED: level = "optimistically_confirmed"; break;
    case FD_GUI_SLOT_LEVEL_ROOTED:                   level = "rooted"; break;
    case FD_GUI_SLOT_LEVEL_FINALIZED:                level = "finalized"; break;
    default:                                         level = "unknown"; break;
  }

  long duration_nanos = fd_gui_load_slot_duration( gui, _slot, slot );

  jsonp_open_envelope( gui->http, "slot", "query_transactions" );
    jsonp_ulong( gui->http, "id", id );
    jsonp_open_object( gui->http, "value" );
      fd_gui_leader_slot_t lmeta[ 1 ];
      int have_lmeta = fd_gui_load_leader_meta( gui, _slot, lmeta );

      jsonp_open_object( gui->http, "publish" );
        jsonp_ulong( gui->http, "slot", _slot );
        jsonp_bool( gui->http, "mine", slot->mine );
        if( FD_UNLIKELY( slot->vote_slot!=ULONG_MAX ) ) jsonp_ulong( gui->http, "vote_slot", slot->vote_slot );
        else                                            jsonp_null( gui->http, "vote_slot" );
        if( FD_UNLIKELY( slot->vote_latency!=UCHAR_MAX ) ) jsonp_ulong( gui->http, "vote_latency", slot->vote_latency );
        else                                               jsonp_null( gui->http, "vote_latency" );

        if( FD_UNLIKELY( have_lmeta && lmeta->leader_start_time!=LONG_MAX ) ) jsonp_long_as_str( gui->http, "start_timestamp_nanos", lmeta->leader_start_time  );
        else                                                                  jsonp_null       ( gui->http, "start_timestamp_nanos" );
        if( FD_UNLIKELY( have_lmeta && lmeta->leader_end_time!=LONG_MAX ) ) jsonp_long_as_str( gui->http, "target_end_timestamp_nanos", lmeta->leader_end_time  );
        else                                                                jsonp_null       ( gui->http, "target_end_timestamp_nanos" );

        jsonp_bool( gui->http, "skipped", slot->skip==FD_GUI_SKIP_STATUS_SKIPPED );
        jsonp_string( gui->http, "level", level );
        if( FD_UNLIKELY( duration_nanos==LONG_MAX ) ) jsonp_null( gui->http, "duration_nanos" );
        else                                          jsonp_long( gui->http, "duration_nanos", duration_nanos );
        if( FD_UNLIKELY( slot->completed_time==LONG_MAX ) ) jsonp_null( gui->http, "completed_time_nanos" );
        else                                                jsonp_long_as_str( gui->http, "completed_time_nanos", slot->completed_time );
        if( FD_UNLIKELY( slot->nonvote_success==UINT_MAX ) ) jsonp_null( gui->http, "success_nonvote_transaction_cnt" );
        else                                                 jsonp_ulong( gui->http, "success_nonvote_transaction_cnt", slot->nonvote_success );
        if( FD_UNLIKELY( slot->nonvote_failed==UINT_MAX ) ) jsonp_null( gui->http, "failed_nonvote_transaction_cnt" );
        else                                                        jsonp_ulong( gui->http, "failed_nonvote_transaction_cnt", slot->nonvote_failed );
        if( FD_UNLIKELY( slot->vote_success==UINT_MAX ) ) jsonp_null( gui->http, "success_vote_transaction_cnt" );
        else                                              jsonp_ulong( gui->http, "success_vote_transaction_cnt", slot->vote_success );
        if( FD_UNLIKELY( slot->vote_failed==UINT_MAX ) ) jsonp_null( gui->http, "failed_vote_transaction_cnt" );
        else                                             jsonp_ulong( gui->http, "failed_vote_transaction_cnt", slot->vote_failed );
        if( FD_UNLIKELY( slot->max_compute_units==UINT_MAX ) ) jsonp_null( gui->http, "max_compute_units" );
        else                                                   jsonp_ulong( gui->http, "max_compute_units", slot->max_compute_units );
        if( FD_UNLIKELY( slot->compute_units==UINT_MAX ) ) jsonp_null( gui->http, "compute_units" );
        else                                               jsonp_ulong( gui->http, "compute_units", slot->compute_units );
        if( FD_UNLIKELY( slot->shred_cnt==UINT_MAX ) ) jsonp_null( gui->http, "shreds" );
        else                                           jsonp_ulong( gui->http, "shreds", slot->shred_cnt );
        if( FD_UNLIKELY( slot->transaction_fee==ULONG_MAX ) ) jsonp_null( gui->http, "transaction_fee" );
        else                                                  jsonp_ulong( gui->http, "transaction_fee", slot->transaction_fee );
        if( FD_UNLIKELY( slot->priority_fee==ULONG_MAX ) ) jsonp_null( gui->http, "priority_fee" );
        else                                               jsonp_ulong( gui->http, "priority_fee", slot->priority_fee );
        if( FD_UNLIKELY( slot->tips==ULONG_MAX ) ) jsonp_null( gui->http, "tips" );
        else                                       jsonp_ulong( gui->http, "tips", slot->tips );
      jsonp_close_object( gui->http );

      if( FD_UNLIKELY( have_lmeta && lmeta->unbecame_leader ) ) {
        jsonp_open_object( gui->http, "limits" );
          jsonp_ulong( gui->http, "used_total_block_cost",        lmeta->scheduler_stats->limits_usage->block_cost          );
          jsonp_ulong( gui->http, "used_total_vote_cost",         lmeta->scheduler_stats->limits_usage->vote_cost           );
          jsonp_ulong( gui->http, "used_total_bytes",             lmeta->scheduler_stats->limits_usage->block_data_bytes    );
          jsonp_ulong( gui->http, "used_total_microblocks",       lmeta->scheduler_stats->limits_usage->microblocks         );
          jsonp_open_array( gui->http, "used_account_write_costs" );
            for( ulong i = 0; i<FD_PACK_TOP_WRITERS_CNT; i++ ) {
              if( FD_UNLIKELY( !memcmp( lmeta->scheduler_stats->limits_usage->top_writers[ i ].key.b, ((fd_pubkey_t){ 0 }).uc, sizeof(fd_pubkey_t) ) ) ) break;

              jsonp_open_object( gui->http, NULL );
                char account_base58[ FD_BASE58_ENCODED_32_SZ ];
                fd_base58_encode_32( lmeta->scheduler_stats->limits_usage->top_writers[ i ].key.b, NULL, account_base58 );
                jsonp_string( gui->http, "account", account_base58 );
                jsonp_ulong( gui->http, "cost", lmeta->scheduler_stats->limits_usage->top_writers[ i ].total_cost );
              jsonp_close_object( gui->http );
            }
          jsonp_close_array( gui->http );

          jsonp_ulong( gui->http, "max_total_block_cost",        lmeta->scheduler_stats->limits->max_cost_per_block        );
          jsonp_ulong( gui->http, "max_total_vote_cost",         lmeta->scheduler_stats->limits->max_vote_cost_per_block   );
          jsonp_ulong( gui->http, "max_account_write_cost",      lmeta->scheduler_stats->limits->max_write_cost_per_acct   );
          jsonp_ulong( gui->http, "max_total_bytes",             lmeta->scheduler_stats->limits->max_data_bytes_per_block  );
          jsonp_ulong( gui->http, "max_total_microblocks",       lmeta->max_microblocks                                    );
        jsonp_close_object( gui->http );

        jsonp_open_object( gui->http, "scheduler_stats" );
          /* block_hash is replay-sourced; prefer FD_GUI_HIST_SLOT
             and fall back to the leader meta's own block_hash. */
          fd_hash_t block_hash = lmeta->block_hash;
          fd_gui_load_block_hash( gui, _slot, &block_hash );
          char block_hash_base58[ FD_BASE58_ENCODED_32_SZ ];
          fd_base58_encode_32( block_hash.uc, NULL, block_hash_base58 );
          jsonp_string( gui->http, "block_hash", block_hash_base58 );

          switch( lmeta->scheduler_stats->end_slot_reason ) {
            case FD_PACK_END_SLOT_REASON_TIME: {
              jsonp_string( gui->http, "end_slot_reason", "timeout" );
              break;
            }
            case FD_PACK_END_SLOT_REASON_MICROBLOCK: {
              jsonp_string( gui->http, "end_slot_reason", "microblock_limit" );
              break;
            }
            case FD_PACK_END_SLOT_REASON_LEADER_SWITCH: {
              jsonp_string( gui->http, "end_slot_reason", "leader_switch" );
              break;
            }
            default: FD_LOG_ERR(( "unreachable" ));
          }
          jsonp_open_array( gui->http, "slot_schedule_counts" );
            for( ulong i = 0; i<FD_METRICS_COUNTER_PACK_TXN_SCHEDULED_CNT; i++ ) jsonp_ulong( gui->http, NULL, lmeta->scheduler_stats->block_results[ i ] );
          jsonp_close_array( gui->http );
          jsonp_open_array( gui->http, "end_slot_schedule_counts" );
            for( ulong i = 0; i<FD_METRICS_COUNTER_PACK_TXN_SCHEDULED_CNT; i++ ) jsonp_ulong( gui->http, NULL, lmeta->scheduler_stats->end_block_results[ i ] );
          jsonp_close_array( gui->http );

          if( FD_LIKELY( lmeta->scheduler_stats->pending_smallest->cus!=ULONG_MAX ) ) jsonp_ulong( gui->http, "pending_smallest_cost", lmeta->scheduler_stats->pending_smallest->cus );
          else                                                                        jsonp_null( gui->http, "pending_smallest_cost" );
          if( FD_LIKELY( lmeta->scheduler_stats->pending_smallest->bytes!=ULONG_MAX ) ) jsonp_ulong( gui->http, "pending_smallest_bytes", lmeta->scheduler_stats->pending_smallest->bytes );
          else                                                                          jsonp_null( gui->http, "pending_smallest_bytes" );
          if( FD_LIKELY( lmeta->scheduler_stats->pending_votes_smallest->cus!=ULONG_MAX ) ) jsonp_ulong( gui->http, "pending_vote_smallest_cost", lmeta->scheduler_stats->pending_votes_smallest->cus );
          else                                                                              jsonp_null( gui->http, "pending_vote_smallest_cost" );
          if( FD_LIKELY( lmeta->scheduler_stats->pending_votes_smallest->bytes!=ULONG_MAX ) ) jsonp_ulong( gui->http, "pending_vote_smallest_bytes", lmeta->scheduler_stats->pending_votes_smallest->bytes );
          else                                                                                jsonp_null( gui->http, "pending_vote_smallest_bytes" );
        jsonp_close_object( gui->http );

      } else {
        jsonp_null( gui->http, "limits" );
        jsonp_null( gui->http, "scheduler_stats" );
      }

      int processed_all_microblocks = have_lmeta && lmeta->unbecame_leader &&
                                      lmeta->microblocks_upper_bound!=UINT_MAX &&
                                      lmeta->begin_microblocks==lmeta->end_microblocks &&
                                      lmeta->begin_microblocks==lmeta->microblocks_upper_bound;

      int have_leader_window = have_lmeta &&
                               lmeta->leader_start_time!=LONG_MAX &&
                               lmeta->leader_end_time  !=LONG_MAX &&
                               lmeta->leader_start_time<=lmeta->leader_end_time;

      fd_gui_store_txn_start_t *  starts = gui->slot_txn_scratch.starts;
      fd_gui_store_txn_end_t *    ends   = gui->slot_txn_scratch.ends;
      fd_gui_slot_txn_join_t * joined = gui->slot_txn_scratch.joined;
      ulong                    start_cnt = 0UL;
      ulong                    end_cnt   = 0UL;
      ulong                    txn_cnt   = 0UL;
      int                      have_txns = gui->db && processed_all_microblocks && have_leader_window;

      if( FD_LIKELY( have_txns ) ) {
        /* Bound both scans to this slot's leader window, widened by a
           slack to prevent losing txn's that come in right before or
           right after the recorded leader window. */
        long const txn_window_slack_ns = 2L*1000L*1000L*1000L; /* 2 s */
        long txn_lo_ns = lmeta->leader_start_time - txn_window_slack_ns;
        long txn_hi_ns = lmeta->leader_end_time   + txn_window_slack_ns;

        /* Scan the start half, keeping only this slot's records. */
        fd_gui_hist_iter_t it;
        if( FD_LIKELY( !fd_gui_hist_range_begin( gui, &it, FD_GUI_HIST_TXN_START, txn_lo_ns, txn_hi_ns, NULL, NULL ) ) ) {
          while( fd_gui_hist_range_next( &it ) ) {
            fd_gui_store_txn_start_t const * r = (fd_gui_store_txn_start_t const *)it.rec;
            if( FD_UNLIKELY( r->slot!=_slot || r->bank_seq!=slot->bank_seq ) ) continue;
            if( FD_UNLIKELY( start_cnt>=FD_MAX_TXN_PER_SLOT ) ) break;
            starts[ start_cnt++ ] = *r;
          }
          fd_gui_hist_range_end( &it );
        }

        /* Scan the end half, keeping only this slot's records. */
        if( FD_LIKELY( !fd_gui_hist_range_begin( gui, &it, FD_GUI_HIST_TXN_END, txn_lo_ns, txn_hi_ns, NULL, NULL ) ) ) {
          while( fd_gui_hist_range_next( &it ) ) {
            fd_gui_store_txn_end_t const * r = (fd_gui_store_txn_end_t const *)it.rec;
            if( FD_UNLIKELY( r->slot!=_slot || r->bank_seq!=slot->bank_seq ) ) continue;
            if( FD_UNLIKELY( end_cnt>=FD_MAX_TXN_PER_SLOT ) ) break;
            ends[ end_cnt++ ] = *r;
          }
          fd_gui_hist_range_end( &it );
        }

        /* Sort both halves by txn_idx, then merge-walk to join. */
        fd_gui_slot_txn_start_sort_inplace( starts, start_cnt );
        fd_gui_slot_txn_end_sort_inplace  ( ends,   end_cnt   );

        ulong si = 0UL;
        ulong ei = 0UL;
        while( si<start_cnt && ei<end_cnt ) {
          ulong s_idx = starts[ si ].txn_idx;
          ulong e_idx = ends  [ ei ].txn_idx;
          if(      s_idx<e_idx ) si++;
          else if( e_idx<s_idx ) ei++;
          else {
            joined[ txn_cnt ].start = &starts[ si ];
            joined[ txn_cnt ].end   = &ends  [ ei ];
            txn_cnt++;
            si++;
            ei++;
          }
        }
      }

      if( FD_LIKELY( have_txns ) ) {
        jsonp_open_object( gui->http, "transactions" );
          jsonp_long_as_str( gui->http, "start_timestamp_nanos", lmeta->leader_start_time );
          jsonp_long_as_str( gui->http, "target_end_timestamp_nanos", lmeta->leader_end_time );
          jsonp_open_array( gui->http, "txn_mb_start_timestamps_nanos" );
            for( ulong i=0UL; i<txn_cnt; i++) jsonp_long_as_str( gui->http, NULL, joined[ i ].start->microblock_start_ns );
          jsonp_close_array( gui->http );
          jsonp_open_array( gui->http, "txn_mb_end_timestamps_nanos" );
            for( ulong i=0UL; i<txn_cnt; i++) {
              long const mb_start = joined[ i ].start->microblock_start_ns;
              long const mb_end   = fd_long_max( joined[ i ].end->microblock_end_ns, mb_start + 1L );
              jsonp_long_as_str( gui->http, NULL, mb_end );
            }
          jsonp_close_array( gui->http );
          jsonp_open_array( gui->http, "txn_compute_units_requested" );
            for( ulong i=0UL; i<txn_cnt; i++) jsonp_ulong( gui->http, NULL, joined[ i ].start->compute_units_requested );
          jsonp_close_array( gui->http );
          jsonp_open_array( gui->http, "txn_compute_units_consumed" );
            for( ulong i=0UL; i<txn_cnt; i++) jsonp_ulong( gui->http, NULL, joined[ i ].end->compute_units_consumed );
          jsonp_close_array( gui->http );
          jsonp_open_array( gui->http, "txn_priority_fee" );
            for( ulong i=0UL; i<txn_cnt; i++) jsonp_ulong_as_str( gui->http, NULL, joined[ i ].start->priority_fee );
          jsonp_close_array( gui->http );
          jsonp_open_array( gui->http, "txn_transaction_fee" );
            for( ulong i=0UL; i<txn_cnt; i++) jsonp_ulong_as_str( gui->http, NULL, joined[ i ].start->transaction_fee );
          jsonp_close_array( gui->http );
          jsonp_open_array( gui->http, "txn_error_code" );
            for( ulong i=0UL; i<txn_cnt; i++) jsonp_ulong( gui->http, NULL, joined[ i ].end->error_code );
          jsonp_close_array( gui->http );
          jsonp_open_array( gui->http, "txn_from_bundle" );
            for( ulong i=0UL; i<txn_cnt; i++) jsonp_bool( gui->http, NULL, joined[ i ].start->flags & FD_GUI_TXN_FLAGS_FROM_BUNDLE );
          jsonp_close_array( gui->http );
          jsonp_open_array( gui->http, "txn_is_simple_vote" );
            for( ulong i=0UL; i<txn_cnt; i++) jsonp_bool( gui->http, NULL, joined[ i ].start->flags & FD_GUI_TXN_FLAGS_IS_SIMPLE_VOTE );
          jsonp_close_array( gui->http );
          jsonp_open_array( gui->http, "txn_bank_idx" );
            for( ulong i=0UL; i<txn_cnt; i++) jsonp_ulong( gui->http, NULL, joined[ i ].end->bank_idx );
          jsonp_close_array( gui->http );
          jsonp_open_array( gui->http, "txn_check_start_timestamps_nanos" );
            for( ulong i=0UL; i<txn_cnt; i++) {
              jsonp_long_as_str( gui->http, NULL, joined[ i ].start->microblock_start_ns + (long)joined[ i ].end->txn_ns_dt.check_start );
            }
          jsonp_close_array( gui->http );
          jsonp_open_array( gui->http, "txn_load_start_timestamps_nanos" );
            for( ulong i=0UL; i<txn_cnt; i++) {
              jsonp_long_as_str( gui->http, NULL, joined[ i ].start->microblock_start_ns + (long)joined[ i ].end->txn_ns_dt.load_start );
            }
          jsonp_close_array( gui->http );
          jsonp_open_array( gui->http, "txn_execute_start_timestamps_nanos" );
            for( ulong i=0UL; i<txn_cnt; i++) {
              jsonp_long_as_str( gui->http, NULL, joined[ i ].start->microblock_start_ns + (long)joined[ i ].end->txn_ns_dt.exec_start );
            }
          jsonp_close_array( gui->http );
          jsonp_open_array( gui->http, "txn_commit_start_timestamps_nanos" );
            for( ulong i=0UL; i<txn_cnt; i++) {
              jsonp_long_as_str( gui->http, NULL, joined[ i ].start->microblock_start_ns + (long)joined[ i ].end->txn_ns_dt.commit_start );
            }
          jsonp_close_array( gui->http );
          jsonp_open_array( gui->http, "txn_commit_end_timestamps_nanos" );
            for( ulong i=0UL; i<txn_cnt; i++) {
              jsonp_long_as_str( gui->http, NULL, joined[ i ].start->microblock_start_ns + (long)joined[ i ].end->txn_ns_dt.commit_end );
            }
          jsonp_close_array( gui->http );
          jsonp_open_array( gui->http, "txn_arrival_timestamps_nanos" );
            for( ulong i=0UL; i<txn_cnt; i++) jsonp_long_as_str( gui->http, NULL, joined[ i ].start->timestamp_arrival_nanos );
          jsonp_close_array( gui->http );
          jsonp_open_array( gui->http, "txn_tips" );
            for( ulong i=0UL; i<txn_cnt; i++) jsonp_ulong_as_str( gui->http, NULL, joined[ i ].end->tips );
          jsonp_close_array( gui->http );
          jsonp_open_array( gui->http, "txn_source_ipv4" );
            for( ulong i=0UL; i<txn_cnt; i++) {
              char addr[ 64 ];
              fd_cstr_printf_check( addr, sizeof(addr), NULL, FD_IP4_ADDR_FMT, FD_IP4_ADDR_FMT_ARGS( joined[ i ].start->source_ipv4 ) );
              jsonp_string( gui->http, NULL, addr );
            }
          jsonp_close_array( gui->http );
          jsonp_open_array( gui->http, "txn_source_tpu" );
            for( ulong i=0UL; i<txn_cnt; i++) {
              switch ( joined[ i ].start->source_tpu ) {
                case FD_TXN_M_TPU_SOURCE_QUIC: {
                  jsonp_string( gui->http, NULL, "quic");
                  break;
                }
                case FD_TXN_M_TPU_SOURCE_UDP   : {
                  jsonp_string( gui->http, NULL, "udp");
                  break;
                }
                case FD_TXN_M_TPU_SOURCE_GOSSIP: {
                  jsonp_string( gui->http, NULL, "gossip");
                  break;
                }
                case FD_TXN_M_TPU_SOURCE_BUNDLE: {
                  jsonp_string( gui->http, NULL, "bundle");
                  break;
                }
                case FD_TXN_M_TPU_SOURCE_TXSEND: {
                  jsonp_string( gui->http, NULL, "send");
                  break;
                }
                default: FD_LOG_ERR(("unknown tpu"));
              }
            }
          jsonp_close_array( gui->http );
          jsonp_open_array( gui->http, "txn_microblock_id" );
            for( ulong i=0UL; i<txn_cnt; i++) jsonp_ulong( gui->http, NULL, joined[ i ].start->microblock_idx );
          jsonp_close_array( gui->http );
          jsonp_open_array( gui->http, "txn_landed" );
            for( ulong i=0UL; i<txn_cnt; i++) jsonp_bool( gui->http, NULL, joined[ i ].end->flags & FD_GUI_TXN_FLAGS_LANDED_IN_BLOCK );
          jsonp_close_array( gui->http );
          jsonp_open_array( gui->http, "txn_signature" );
            for( ulong i=0UL; i<txn_cnt; i++) {
              FD_BASE58_ENCODE_64_BYTES( joined[ i ].start->signature, encoded_signature );
              jsonp_string( gui->http, NULL, encoded_signature );
            }
          jsonp_close_array( gui->http );
        jsonp_close_object( gui->http );
      } else {
        jsonp_null( gui->http, "transactions" );
      }

    jsonp_close_object( gui->http );
  jsonp_close_envelope( gui->http );
}

void
fd_gui_printf_slot_request_detailed( fd_gui_t *            gui,
                                     ulong                _slot,
                                     ulong                id,
                                     fd_gui_slot_t const * slot ) {
  char const * level;
  switch( slot->level ) {
    case FD_GUI_SLOT_LEVEL_INCOMPLETE:               level = "incomplete"; break;
    case FD_GUI_SLOT_LEVEL_COMPLETED:                level = "completed";  break;
    case FD_GUI_SLOT_LEVEL_OPTIMISTICALLY_CONFIRMED: level = "optimistically_confirmed"; break;
    case FD_GUI_SLOT_LEVEL_ROOTED:                   level = "rooted"; break;
    case FD_GUI_SLOT_LEVEL_FINALIZED:                level = "finalized"; break;
    default:                                         level = "unknown"; break;
  }

  long duration_nanos = fd_gui_load_slot_duration( gui, _slot, slot );

  jsonp_open_envelope( gui->http, "slot", "query_detailed" );
    jsonp_ulong( gui->http, "id", id );
    jsonp_open_object( gui->http, "value" );
      fd_gui_leader_slot_t lmeta[ 1 ];
      int have_lmeta = fd_gui_load_leader_meta( gui, _slot, lmeta );

      jsonp_open_object( gui->http, "publish" );
        jsonp_ulong( gui->http, "slot", _slot );
        jsonp_bool( gui->http, "mine", slot->mine );
        if( FD_UNLIKELY( slot->vote_slot!=ULONG_MAX ) ) jsonp_ulong( gui->http, "vote_slot", slot->vote_slot );
        else                                            jsonp_null( gui->http, "vote_slot" );
        if( FD_UNLIKELY( slot->vote_latency!=UCHAR_MAX ) ) jsonp_ulong( gui->http, "vote_latency", slot->vote_latency );
        else                                               jsonp_null( gui->http, "vote_latency" );

        if( FD_UNLIKELY( have_lmeta && lmeta->leader_start_time!=LONG_MAX ) ) jsonp_long_as_str( gui->http, "start_timestamp_nanos", lmeta->leader_start_time  );
        else                                                                  jsonp_null       ( gui->http, "start_timestamp_nanos" );
        if( FD_UNLIKELY( have_lmeta && lmeta->leader_end_time!=LONG_MAX ) ) jsonp_long_as_str( gui->http, "target_end_timestamp_nanos", lmeta->leader_end_time  );
        else                                                                jsonp_null       ( gui->http, "target_end_timestamp_nanos" );

        jsonp_bool( gui->http, "skipped", slot->skip==FD_GUI_SKIP_STATUS_SKIPPED );
        jsonp_string( gui->http, "level", level );
        if( FD_UNLIKELY( duration_nanos==LONG_MAX ) ) jsonp_null( gui->http, "duration_nanos" );
        else                                          jsonp_long( gui->http, "duration_nanos", duration_nanos );
        if( FD_UNLIKELY( slot->completed_time==LONG_MAX ) ) jsonp_null( gui->http, "completed_time_nanos" );
        else                                                jsonp_long_as_str( gui->http, "completed_time_nanos", slot->completed_time );
        if( FD_UNLIKELY( slot->nonvote_success==UINT_MAX ) ) jsonp_null( gui->http, "success_nonvote_transaction_cnt" );
        else                                                 jsonp_ulong( gui->http, "success_nonvote_transaction_cnt", slot->nonvote_success );
        if( FD_UNLIKELY( slot->nonvote_failed==UINT_MAX ) ) jsonp_null( gui->http, "failed_nonvote_transaction_cnt" );
        else                                                        jsonp_ulong( gui->http, "failed_nonvote_transaction_cnt", slot->nonvote_failed );
        if( FD_UNLIKELY( slot->vote_success==UINT_MAX ) ) jsonp_null( gui->http, "success_vote_transaction_cnt" );
        else                                              jsonp_ulong( gui->http, "success_vote_transaction_cnt", slot->vote_success );
        if( FD_UNLIKELY( slot->vote_failed==UINT_MAX ) ) jsonp_null( gui->http, "failed_vote_transaction_cnt" );
        else                                             jsonp_ulong( gui->http, "failed_vote_transaction_cnt", slot->vote_failed );
        if( FD_UNLIKELY( slot->max_compute_units==UINT_MAX ) ) jsonp_null( gui->http, "max_compute_units" );
        else                                                   jsonp_ulong( gui->http, "max_compute_units", slot->max_compute_units );
        if( FD_UNLIKELY( slot->compute_units==UINT_MAX ) ) jsonp_null( gui->http, "compute_units" );
        else                                               jsonp_ulong( gui->http, "compute_units", slot->compute_units );
        if( FD_UNLIKELY( slot->shred_cnt==UINT_MAX ) ) jsonp_null( gui->http, "shreds" );
        else                                           jsonp_ulong( gui->http, "shreds", slot->shred_cnt );
        if( FD_UNLIKELY( slot->transaction_fee==ULONG_MAX ) ) jsonp_null( gui->http, "transaction_fee" );
        else                                                  jsonp_ulong( gui->http, "transaction_fee", slot->transaction_fee );
        if( FD_UNLIKELY( slot->priority_fee==ULONG_MAX ) ) jsonp_null( gui->http, "priority_fee" );
        else                                               jsonp_ulong( gui->http, "priority_fee", slot->priority_fee );
        if( FD_UNLIKELY( slot->tips==ULONG_MAX ) ) jsonp_null( gui->http, "tips" );
        else                                       jsonp_ulong( gui->http, "tips", slot->tips );
      jsonp_close_object( gui->http );

      if( FD_LIKELY( gui->summary.slot_tower!=ULONG_MAX && gui->summary.slot_tower>_slot ) ) {
        long leader_start_time = have_lmeta ? lmeta->leader_start_time : LONG_MAX;
        long leader_end_time   = have_lmeta ? lmeta->leader_end_time   : LONG_MAX;
        int  have_window       = have_lmeta && gui->db && leader_start_time!=LONG_MAX && leader_end_time!=LONG_MAX;

        int have_wf = 0;
        fd_gui_txn_waterfall_t wf_begin[ 1 ];
        fd_gui_txn_waterfall_t wf_end  [ 1 ];
        if( FD_LIKELY( have_window ) ) {
          fd_gui_hist_iter_t it;
          if( FD_LIKELY( !fd_gui_hist_range_begin( gui, &it, FD_GUI_HIST_TXN_WATERFALL, leader_start_time, leader_end_time, NULL, NULL ) ) ) {
            while( fd_gui_hist_range_next( &it ) ) {
              fd_gui_txn_waterfall_t const * r = (fd_gui_txn_waterfall_t const *)it.rec;
              if( FD_UNLIKELY( r->sample_time_nanos<leader_start_time || r->sample_time_nanos>leader_end_time ) ) continue;
              if( FD_UNLIKELY( !have_wf ) ) *wf_begin = *r;
              *wf_end = *r;
              have_wf = 1;
            }
            fd_gui_hist_range_end( &it );
          }
        }
        if( FD_LIKELY( have_wf ) ) fd_gui_printf_waterfall( gui, wf_begin, wf_end );
        else                       jsonp_null( gui->http, "waterfall" );

        if( FD_LIKELY( have_window ) ) {
          jsonp_open_array( gui->http, "tile_timers" );
            fd_gui_hist_iter_t it;
            if( FD_LIKELY( !fd_gui_hist_range_begin( gui, &it, FD_GUI_HIST_TILE_TIMERS, leader_start_time, leader_end_time, NULL, NULL ) ) ) {
              fd_gui_tile_timers_hist_t sample[ FD_TOPO_MAX_TILES ];
              int  have_sample   = 0;
              long cur_sample_ts = LONG_MAX;
              while( fd_gui_hist_range_next( &it ) ) {
                fd_gui_tile_timers_hist_t const * row = (fd_gui_tile_timers_hist_t const *)it.rec;
                if( FD_UNLIKELY( row->sample_time_nanos<leader_start_time || row->sample_time_nanos>leader_end_time ) ) continue;
                if( FD_UNLIKELY( row->tile_idx>=FD_TOPO_MAX_TILES ) ) continue;

                /* Records are stored already-diffed and self-contained, so
                   each distinct sample_time_nanos is emitted directly (no
                   diff against the previous sample). */
                if( have_sample && row->sample_time_nanos!=cur_sample_ts ) {
                  fd_gui_printf_ts_tile_timers( gui, cur_sample_ts, sample );
                  have_sample = 0;
                }
                cur_sample_ts = row->sample_time_nanos;
                sample[ row->tile_idx ] = *row;
                have_sample = 1;
              }

              if( have_sample ) fd_gui_printf_ts_tile_timers( gui, cur_sample_ts, sample );
              fd_gui_hist_range_end( &it );
            }
          jsonp_close_array( gui->http );
        } else {
          jsonp_null( gui->http, "tile_timers" );
        }

        if( FD_LIKELY( have_window ) ) {
          /* Unlike tile timers (which are counters), scheduler counts are a
             gauge and we don't take a diff. */
          jsonp_open_array( gui->http, "scheduler_counts" );
            fd_gui_hist_iter_t it;
            if( FD_LIKELY( !fd_gui_hist_range_begin( gui, &it, FD_GUI_HIST_SCHEDULER_COUNTS, leader_start_time, leader_end_time, NULL, NULL ) ) ) {
              while( fd_gui_hist_range_next( &it ) ) {
                fd_gui_scheduler_counts_t const * cur = (fd_gui_scheduler_counts_t const *)it.rec;
                if( FD_UNLIKELY( cur->sample_time_ns<leader_start_time ||
                                 cur->sample_time_ns>leader_end_time ) ) continue;
                jsonp_open_object( gui->http, NULL );
                  jsonp_long_as_str( gui->http, "timestamp_nanos", cur->sample_time_ns );
                  jsonp_ulong      ( gui->http, "regular",         cur->regular        );
                  jsonp_ulong      ( gui->http, "votes",           cur->votes          );
                  jsonp_ulong      ( gui->http, "conflicting",     cur->conflicting    );
                  jsonp_ulong      ( gui->http, "bundles",         cur->bundles        );
                jsonp_close_object( gui->http );
              }
              fd_gui_hist_range_end( &it );
            }
          jsonp_close_array( gui->http );
        } else {
          jsonp_null( gui->http, "scheduler_counts" );
        }

        int have_tile_stats = 0;
        fd_gui_tile_stats_t tile_stats_begin[ 1 ];
        fd_gui_tile_stats_t tile_stats_end  [ 1 ];
        if( FD_LIKELY( have_window ) ) {
          fd_gui_hist_iter_t it;
          if( FD_LIKELY( !fd_gui_hist_range_begin( gui, &it, FD_GUI_HIST_TILE_STATS, leader_start_time, leader_end_time, NULL, NULL ) ) ) {
            while( fd_gui_hist_range_next( &it ) ) {
              fd_gui_tile_stats_t cur[ 1 ];
              fd_memcpy( cur, it.rec, sizeof(fd_gui_tile_stats_t) );
              if( FD_UNLIKELY( cur->sample_time_nanos<leader_start_time || cur->sample_time_nanos>leader_end_time ) ) continue;
              if( FD_UNLIKELY( !have_tile_stats ) ) *tile_stats_begin = *cur;
              *tile_stats_end = *cur;
              have_tile_stats = 1;
            }
            fd_gui_hist_range_end( &it );
          }
        }
        if( FD_LIKELY( have_tile_stats ) ) fd_gui_printf_tile_stats( gui, tile_stats_begin, tile_stats_end );
        else                               jsonp_null( gui->http, "tile_primary_metric" );
      } else {
        jsonp_null( gui->http, "waterfall" );
        jsonp_null( gui->http, "tile_timers" );
        jsonp_null( gui->http, "tile_primary_metric" );
      }

    jsonp_close_object( gui->http );
  jsonp_close_envelope( gui->http );
}

void
fd_gui_printf_boot_progress( fd_gui_t * gui ) {
  jsonp_open_envelope( gui->http, "summary", "boot_progress" );
    jsonp_open_object( gui->http, "value" );
      switch( gui->summary.boot_progress.phase ) {
        case FD_GUI_BOOT_PROGRESS_TYPE_JOINING_GOSSIP:               jsonp_string( gui->http, "phase", "joining_gossip" );               break;
        case FD_GUI_BOOT_PROGRESS_TYPE_LOADING_FULL_SNAPSHOT:        jsonp_string( gui->http, "phase", "loading_full_snapshot" );        break;
        case FD_GUI_BOOT_PROGRESS_TYPE_LOADING_INCREMENTAL_SNAPSHOT: jsonp_string( gui->http, "phase", "loading_incremental_snapshot" ); break;
        case FD_GUI_BOOT_PROGRESS_TYPE_WAITING_FOR_SUPERMAJORITY:    jsonp_string( gui->http, "phase", "waiting_for_supermajority" );    break;
        case FD_GUI_BOOT_PROGRESS_TYPE_CATCHING_UP:                  jsonp_string( gui->http, "phase", "catching_up" );                  break;
        case FD_GUI_BOOT_PROGRESS_TYPE_RUNNING:                      jsonp_string( gui->http, "phase", "running" );                      break;
        default: FD_LOG_ERR(( "unknown phase %d", gui->summary.boot_progress.phase ));
      }

      jsonp_string( gui->http, "accounts_database_path", gui->summary.accounts_database_path );
      jsonp_string( gui->http, "gui_database_path", gui->summary.gui_database_path );

      jsonp_double( gui->http, "joining_gossip_elapsed_seconds", (double)(gui->summary.boot_progress.joining_gossip_time_nanos - gui->summary.startup_time_nanos) / 1e9 );

#define HANDLE_SNAPSHOT_STATE(snapshot_type, snapshot_type_upper) { \
      ulong snapshot_idx = FD_GUI_BOOT_PROGRESS_##snapshot_type_upper##_SNAPSHOT_IDX; \
      if( FD_LIKELY( gui->summary.boot_progress.phase>=FD_GUI_BOOT_PROGRESS_TYPE_LOADING_##snapshot_type_upper##_SNAPSHOT && gui->summary.boot_progress.loading_snapshot[ snapshot_idx ].slot!=ULONG_MAX )) { \
        jsonp_double      ( gui->http, "loading_" FD_STRINGIFY(snapshot_type) "_snapshot_elapsed_seconds",                  (double)(gui->summary.boot_progress.loading_snapshot[ snapshot_idx ].sample_time_nanos - gui->summary.boot_progress.loading_snapshot[ snapshot_idx ].reset_time_nanos) / 1e9 ); \
        jsonp_ulong       ( gui->http, "loading_" FD_STRINGIFY(snapshot_type) "_snapshot_reset_count",                      gui->summary.boot_progress.loading_snapshot[ snapshot_idx ].reset_cnt                                            ); \
        jsonp_ulong       ( gui->http, "loading_" FD_STRINGIFY(snapshot_type) "_snapshot_slot",                             gui->summary.boot_progress.loading_snapshot[ snapshot_idx ].slot                                                 ); \
        jsonp_ulong_as_str( gui->http, "loading_" FD_STRINGIFY(snapshot_type) "_snapshot_total_bytes_compressed",           gui->summary.boot_progress.loading_snapshot[ snapshot_idx ].total_bytes_compressed                               ); \
        jsonp_ulong_as_str( gui->http, "loading_" FD_STRINGIFY(snapshot_type) "_snapshot_read_bytes_compressed",            gui->summary.boot_progress.loading_snapshot[ snapshot_idx ].read_bytes_compressed                                ); \
        jsonp_string      ( gui->http, "loading_" FD_STRINGIFY(snapshot_type) "_snapshot_read_path",                        gui->summary.boot_progress.loading_snapshot[ snapshot_idx ].read_path                                            ); \
        jsonp_ulong_as_str( gui->http, "loading_" FD_STRINGIFY(snapshot_type) "_snapshot_decompress_bytes_decompressed",    gui->summary.boot_progress.loading_snapshot[ snapshot_idx ].decompress_bytes_decompressed                        ); \
        jsonp_ulong_as_str( gui->http, "loading_" FD_STRINGIFY(snapshot_type) "_snapshot_decompress_bytes_compressed",      gui->summary.boot_progress.loading_snapshot[ snapshot_idx ].decompress_bytes_compressed                          ); \
        jsonp_ulong_as_str( gui->http, "loading_" FD_STRINGIFY(snapshot_type) "_snapshot_insert_bytes_decompressed",        gui->summary.boot_progress.loading_snapshot[ snapshot_idx ].insert_bytes_decompressed                            ); \
        jsonp_ulong       ( gui->http, "loading_" FD_STRINGIFY(snapshot_type) "_snapshot_insert_accounts",                  gui->summary.boot_progress.loading_snapshot[ snapshot_idx ].insert_accounts_current                              ); \
        jsonp_ulong_as_str( gui->http, "loading_" FD_STRINGIFY(snapshot_type) "_snapshot_snapwr_in_bytes_decompressed",     gui->summary.boot_progress.loading_snapshot[ snapshot_idx ].snapwr_in_bytes_decompressed                         ); \
        jsonp_ulong_as_str( gui->http, "loading_" FD_STRINGIFY(snapshot_type) "_snapshot_snapwr_out_bytes_decompressed",    gui->summary.boot_progress.loading_snapshot[ snapshot_idx ].snapwr_out_bytes_decompressed                        ); \
        jsonp_ulong       ( gui->http, "loading_" FD_STRINGIFY(snapshot_type) "_snapshot_snapwr_accounts",                  gui->summary.boot_progress.loading_snapshot[ snapshot_idx ].snapwr_accounts_current                              ); \
      } else { \
        jsonp_null( gui->http, "loading_" FD_STRINGIFY(snapshot_type) "_snapshot_elapsed_seconds"                  ); \
        jsonp_null( gui->http, "loading_" FD_STRINGIFY(snapshot_type) "_snapshot_reset_count"                      ); \
        jsonp_null( gui->http, "loading_" FD_STRINGIFY(snapshot_type) "_snapshot_slot"                             ); \
        jsonp_null( gui->http, "loading_" FD_STRINGIFY(snapshot_type) "_snapshot_total_bytes_compressed"           ); \
        jsonp_null( gui->http, "loading_" FD_STRINGIFY(snapshot_type) "_snapshot_read_bytes_compressed"            ); \
        jsonp_null( gui->http, "loading_" FD_STRINGIFY(snapshot_type) "_snapshot_read_path"                        ); \
        jsonp_null( gui->http, "loading_" FD_STRINGIFY(snapshot_type) "_snapshot_decompress_bytes_decompressed"    ); \
        jsonp_null( gui->http, "loading_" FD_STRINGIFY(snapshot_type) "_snapshot_decompress_bytes_compressed"      ); \
        jsonp_null( gui->http, "loading_" FD_STRINGIFY(snapshot_type) "_snapshot_insert_bytes_decompressed"        ); \
        jsonp_null( gui->http, "loading_" FD_STRINGIFY(snapshot_type) "_snapshot_insert_accounts"                  ); \
        jsonp_null( gui->http, "loading_" FD_STRINGIFY(snapshot_type) "_snapshot_snapwr_in_bytes_decompressed"     ); \
        jsonp_null( gui->http, "loading_" FD_STRINGIFY(snapshot_type) "_snapshot_snapwr_out_bytes_decompressed"    ); \
        jsonp_null( gui->http, "loading_" FD_STRINGIFY(snapshot_type) "_snapshot_snapwr_accounts"                  ); \
      } \
    }

    HANDLE_SNAPSHOT_STATE(full, FULL)
    HANDLE_SNAPSHOT_STATE(incremental, INCREMENTAL)
#undef HANDLE_SNAPSHOT_STATE

    if( FD_LIKELY( gui->summary.wfs_enabled ) ) {
      jsonp_string      ( gui->http, "wait_for_supermajority_bank_hash",        gui->summary.wfs_bank_hash );
      char shred_version_str[ 8 ];
      FD_TEST( fd_cstr_printf_check( shred_version_str, sizeof(shred_version_str), NULL, "%hu", gui->summary.expected_shred_version ) );
      jsonp_string      ( gui->http, "wait_for_supermajority_shred_version",    shred_version_str );
      if( FD_LIKELY( gui->summary.boot_progress.phase>=FD_GUI_BOOT_PROGRESS_TYPE_WAITING_FOR_SUPERMAJORITY ) ) {
        jsonp_ulong       ( gui->http, "wait_for_supermajority_attempt",          gui->summary.boot_progress.wfs_attempt );
        jsonp_ulong_as_str( gui->http, "wait_for_supermajority_total_stake",      gui->summary.boot_progress.wfs_total_stake );
        jsonp_ulong_as_str( gui->http, "wait_for_supermajority_connected_stake",  gui->summary.boot_progress.wfs_connected_stake );
        jsonp_ulong       ( gui->http, "wait_for_supermajority_total_peers",      gui->summary.boot_progress.wfs_total_peers );
        jsonp_ulong       ( gui->http, "wait_for_supermajority_connected_peers",  gui->summary.boot_progress.wfs_connected_peers );
      } else {
        jsonp_null( gui->http, "wait_for_supermajority_attempt" );
        jsonp_null( gui->http, "wait_for_supermajority_total_stake" );
        jsonp_null( gui->http, "wait_for_supermajority_connected_stake" );
        jsonp_null( gui->http, "wait_for_supermajority_total_peers" );
        jsonp_null( gui->http, "wait_for_supermajority_connected_peers" );
      }
    } else {
      jsonp_null( gui->http, "wait_for_supermajority_bank_hash" );
      jsonp_null( gui->http, "wait_for_supermajority_shred_version" );
      jsonp_null( gui->http, "wait_for_supermajority_attempt" );
      jsonp_null( gui->http, "wait_for_supermajority_total_stake" );
      jsonp_null( gui->http, "wait_for_supermajority_connected_stake" );
      jsonp_null( gui->http, "wait_for_supermajority_total_peers" );
      jsonp_null( gui->http, "wait_for_supermajority_connected_peers" );
    }

    if( FD_LIKELY( gui->summary.boot_progress.phase>=FD_GUI_BOOT_PROGRESS_TYPE_CATCHING_UP ) ) jsonp_double( gui->http, "catching_up_elapsed_seconds",     (double)(gui->summary.boot_progress.catching_up_time_nanos - gui->summary.boot_progress.loading_snapshot[ FD_GUI_BOOT_PROGRESS_INCREMENTAL_SNAPSHOT_IDX ].sample_time_nanos) / 1e9 );
    else                                                                                       jsonp_null  ( gui->http, "catching_up_elapsed_seconds" );

    if( FD_LIKELY( gui->summary.boot_progress.phase>=FD_GUI_BOOT_PROGRESS_TYPE_CATCHING_UP
                && gui->summary.boot_progress.catching_up_first_replay_slot!=ULONG_MAX ) ) {
      jsonp_ulong( gui->http, "catching_up_first_replay_slot", gui->summary.boot_progress.catching_up_first_replay_slot );
    } else {
      jsonp_null( gui->http, "catching_up_first_replay_slot" );
    }

    jsonp_close_object( gui->http );
  jsonp_close_envelope( gui->http );
}

void
fd_gui_printf_peers_viewport_update( fd_gui_peers_ctx_t *  peers,
                                     ulong                 ws_conn_id ) {
  jsonp_open_envelope( peers->http, "gossip", "view_update" );
    jsonp_open_object( peers->http, "value" );
      jsonp_open_array( peers->http, "changes" );
        FD_TEST( peers->scratch.viewport_cnt<=FD_GUI_PEERS_WS_VIEWPORT_MAX_SZ );

        ulong start_row = peers->client_viewports[ ws_conn_id ].start_row;
        for( ulong i=0UL; i<peers->scratch.viewport_cnt; i++ ) {
          ulong j = start_row + i;
          fd_gui_peers_row_t const * cur = &peers->scratch.viewport[ i ];
          fd_gui_peers_row_t const * ref = &peers->scratch.viewport_ref[ i ];

          /* This code should be kept in sync with updates to
             fd_gui_peers_live_table */
          if( FD_UNLIKELY( cur->stake!=ref->stake ) ) {
            jsonp_open_object( peers->http, NULL );
              jsonp_ulong ( peers->http, "row_index", j );
              jsonp_string( peers->http, "column_name", "Stake" );

              if( FD_UNLIKELY( cur->stake==ULONG_MAX ) ) jsonp_long ( peers->http, "new_value", -1 );
              else                                       jsonp_ulong( peers->http, "new_value", cur->stake );
            jsonp_close_object( peers->http );
          }

          if( FD_UNLIKELY( strncmp( cur->name, ref->name, sizeof(ref->name) ) ) ) {
            jsonp_open_object( peers->http, NULL );
              jsonp_ulong ( peers->http, "row_index", j );
              jsonp_string( peers->http, "column_name", "Name" );
              jsonp_string( peers->http, "new_value", cur->name );
            jsonp_close_object( peers->http );
          }

          if( FD_UNLIKELY( cur->country_code_idx!=ref->country_code_idx ) ) {
            jsonp_open_object( peers->http, NULL );
              jsonp_ulong ( peers->http, "row_index", j );
              jsonp_string( peers->http, "column_name", "Country" );
              if( FD_LIKELY( cur->country_code_idx!=UCHAR_MAX ) ) {
                jsonp_string( peers->http, "new_value", peers->dbip.country_code[ cur->country_code_idx ] );
              } else {
                jsonp_null( peers->http, "new_value" );
              }
            jsonp_close_object( peers->http );
          }

          if( FD_UNLIKELY( memcmp( cur->pubkey.uc, ref->pubkey.uc, 32UL ) ) ) {
            jsonp_open_object( peers->http, NULL );
              jsonp_ulong ( peers->http, "row_index", j );
              jsonp_string( peers->http, "column_name", "Pubkey" );

              char pubkey_base58[ FD_BASE58_ENCODED_32_SZ ];
              fd_base58_encode_32( cur->pubkey.uc, NULL, pubkey_base58 );
              jsonp_string( peers->http, "new_value", pubkey_base58 );
            jsonp_close_object( peers->http );
          }

          uint ip4_after  = cur->contact_info.sockets[ FD_GOSSIP_CONTACT_INFO_SOCKET_GOSSIP ].is_ipv6 ? 0U : cur->contact_info.sockets[ FD_GOSSIP_CONTACT_INFO_SOCKET_GOSSIP ].ip4;
          uint ip4_before = ref->contact_info.sockets[ FD_GOSSIP_CONTACT_INFO_SOCKET_GOSSIP ].is_ipv6 ? 0U : ref->contact_info.sockets[ FD_GOSSIP_CONTACT_INFO_SOCKET_GOSSIP ].ip4;
          if( FD_UNLIKELY( ip4_after!=ip4_before ) ) {
            jsonp_open_object( peers->http, NULL );
              jsonp_ulong ( peers->http, "row_index", j );
              jsonp_string( peers->http, "column_name", "IP Addr" );

              char peer_addr[ 16 ]; /* 255.255.255.255 + '\0' */
              FD_TEST( fd_cstr_printf_check( peer_addr, sizeof(peer_addr), NULL, FD_IP4_ADDR_FMT, FD_IP4_ADDR_FMT_ARGS( ip4_after ) ) );
              jsonp_string( peers->http, "new_value", peer_addr );
            jsonp_close_object( peers->http );
          }

          long cur_egress_push_bps           = cur->gossip_tx[ FD_METRICS_ENUM_GOSSIP_MESSAGE_V_PUSH_IDX ].rate_ema;
          long ref_egress_push_bps           = ref->gossip_tx[ FD_METRICS_ENUM_GOSSIP_MESSAGE_V_PUSH_IDX ].rate_ema;
          long cur_ingress_push_bps          = cur->gossvf_rx[ FD_METRICS_ENUM_GOSSIP_MESSAGE_V_PUSH_IDX ].rate_ema;
          long ref_ingress_push_bps          = ref->gossvf_rx[ FD_METRICS_ENUM_GOSSIP_MESSAGE_V_PUSH_IDX ].rate_ema;
          long cur_egress_pull_response_bps  = cur->gossip_tx[ FD_METRICS_ENUM_GOSSIP_MESSAGE_V_PULL_RESPONSE_IDX ].rate_ema;
          long ref_egress_pull_response_bps  = ref->gossip_tx[ FD_METRICS_ENUM_GOSSIP_MESSAGE_V_PULL_RESPONSE_IDX ].rate_ema;
          long cur_ingress_pull_response_bps = cur->gossvf_rx[ FD_METRICS_ENUM_GOSSIP_MESSAGE_V_PULL_RESPONSE_IDX ].rate_ema;
          long ref_ingress_pull_response_bps = ref->gossvf_rx[ FD_METRICS_ENUM_GOSSIP_MESSAGE_V_PULL_RESPONSE_IDX ].rate_ema;

          if( FD_UNLIKELY( ref->valid && cur_ingress_pull_response_bps!=ref_ingress_pull_response_bps ) ) {
            jsonp_open_object( peers->http, NULL );
              jsonp_ulong ( peers->http, "row_index", j );
              jsonp_string( peers->http, "column_name", "Ingress Pull" );
              jsonp_long  ( peers->http, "new_value", cur_ingress_pull_response_bps );
            jsonp_close_object( peers->http );
          }

          if( FD_UNLIKELY( ref->valid && cur_ingress_push_bps!=ref_ingress_push_bps ) ) {
            jsonp_open_object( peers->http, NULL );
              jsonp_ulong ( peers->http, "row_index", j );
              jsonp_string( peers->http, "column_name", "Ingress Push" );
              jsonp_long  ( peers->http, "new_value", cur_ingress_push_bps );
            jsonp_close_object( peers->http );
          }

          if( FD_UNLIKELY( ref->valid && cur_egress_pull_response_bps!=ref_egress_pull_response_bps ) ) {
            jsonp_open_object( peers->http, NULL );
              jsonp_ulong ( peers->http, "row_index", j );
              jsonp_string( peers->http, "column_name", "Egress Pull" );
              jsonp_long  ( peers->http, "new_value", cur_egress_pull_response_bps );
            jsonp_close_object( peers->http );
          }

          if( FD_UNLIKELY( ref->valid && cur_egress_push_bps!=ref_egress_push_bps ) ) {
            jsonp_open_object( peers->http, NULL );
              jsonp_ulong ( peers->http, "row_index", j );
              jsonp_string( peers->http, "column_name", "Egress Push" );
              jsonp_long  ( peers->http, "new_value", cur_egress_push_bps );
            jsonp_close_object( peers->http );
          }

        }
      jsonp_close_array( peers->http );
    jsonp_close_object( peers->http );
  jsonp_close_envelope( peers->http );
}

void
fd_gui_printf_peers_viewport_request( fd_gui_peers_ctx_t *  peers,
                                      char const *          key,
                                      ulong                 ws_conn_id,
                                      ulong                 request_id ) {
  jsonp_open_envelope( peers->http, "gossip", key );
    jsonp_ulong( peers->http, "id", request_id );
    jsonp_open_object( peers->http, "value" );
      FD_TEST( peers->scratch.viewport_cnt<=FD_GUI_PEERS_WS_VIEWPORT_MAX_SZ );
      ulong start_row = peers->client_viewports[ ws_conn_id ].start_row;
      for( ulong i=0UL; i<peers->scratch.viewport_cnt; i++ ) {
        ulong j = start_row + i;
        fd_gui_peers_row_t const * cur = &peers->scratch.viewport[ i ];

        char row_index_cstr[ 32 ];
        FD_TEST( fd_cstr_printf_check( row_index_cstr, sizeof(row_index_cstr), NULL, "%lu", + j ) );
        jsonp_open_object( peers->http, row_index_cstr );
          /* This code should be kept in sync with updates to
            fd_gui_peers_live_table */
          if( FD_UNLIKELY( cur->stake==ULONG_MAX ) ) jsonp_long ( peers->http, "Stake", -1 );
          else                                       jsonp_ulong( peers->http, "Stake", cur->stake );

          char pubkey_base58[ FD_BASE58_ENCODED_32_SZ ];
          fd_base58_encode_32( cur->pubkey.uc, NULL, pubkey_base58 );
          jsonp_string( peers->http, "Pubkey", pubkey_base58 );
          jsonp_string( peers->http, "Name", cur->name );
          if( FD_LIKELY( cur->country_code_idx!=UCHAR_MAX ) ) {
            jsonp_string( peers->http, "Country", peers->dbip.country_code[ cur->country_code_idx ] );
          } else {
            jsonp_null( peers->http, "Country" );
          }

          uint ip4 = cur->contact_info.sockets[ FD_GOSSIP_CONTACT_INFO_SOCKET_GOSSIP ].is_ipv6 ? 0U : cur->contact_info.sockets[ FD_GOSSIP_CONTACT_INFO_SOCKET_GOSSIP ].ip4;
          char peer_addr[ 16 ]; /* 255.255.255.255 + '\0' */
          FD_TEST( fd_cstr_printf_check( peer_addr, sizeof(peer_addr), NULL, FD_IP4_ADDR_FMT, FD_IP4_ADDR_FMT_ARGS( ip4 ) ) );
          jsonp_string( peers->http, "IP Addr", peer_addr );

          long cur_egress_push_bps           = cur->gossip_tx[ FD_METRICS_ENUM_GOSSIP_MESSAGE_V_PUSH_IDX ].rate_ema;
          long cur_ingress_push_bps          = cur->gossvf_rx[ FD_METRICS_ENUM_GOSSIP_MESSAGE_V_PUSH_IDX ].rate_ema;
          long cur_egress_pull_response_bps  = cur->gossip_tx[ FD_METRICS_ENUM_GOSSIP_MESSAGE_V_PULL_RESPONSE_IDX ].rate_ema;
          long cur_ingress_pull_response_bps = cur->gossvf_rx[ FD_METRICS_ENUM_GOSSIP_MESSAGE_V_PULL_RESPONSE_IDX ].rate_ema;

          jsonp_long  ( peers->http, "Ingress Pull", cur_ingress_pull_response_bps );
          jsonp_long  ( peers->http, "Ingress Push", cur_ingress_push_bps );
          jsonp_long  ( peers->http, "Egress Pull", cur_egress_pull_response_bps );
          jsonp_long  ( peers->http, "Egress Push", cur_egress_push_bps );

        jsonp_close_object( peers->http );
      }

    jsonp_close_object( peers->http );
  jsonp_close_envelope( peers->http );
}

void
fd_gui_printf_peers_view_resize( fd_gui_peers_ctx_t *  peers, ulong sz ) {
  jsonp_open_envelope( peers->http, "gossip", "peers_size_update" );
    jsonp_ulong( peers->http, "value", sz );
  jsonp_close_envelope( peers->http );
}

void
fd_gui_peers_printf_gossip_stats( fd_gui_peers_ctx_t *  peers ) {
  fd_gui_peers_gossip_stats_t * cur = peers->gossip_stats;

  jsonp_open_envelope( peers->http, "gossip", "network_stats" );
    jsonp_open_object( peers->http, "value" );

      jsonp_open_object( peers->http, "health" );
        jsonp_ulong       ( peers->http, "num_push_messages_rx_success",            cur->network_health_push_msg_rx_success             );
        jsonp_ulong       ( peers->http, "num_push_messages_rx_failure",            cur->network_health_push_msg_rx_failure             );
        jsonp_ulong       ( peers->http, "num_push_entries_rx_success",             cur->network_health_push_crds_rx_success            );
        jsonp_ulong       ( peers->http, "num_push_entries_rx_failure",             cur->network_health_push_crds_rx_failure            );
        jsonp_ulong       ( peers->http, "num_push_entries_rx_duplicate",           cur->network_health_push_crds_rx_duplicate          );
        jsonp_ulong       ( peers->http, "num_pull_response_messages_rx_success",   cur->network_health_pull_response_msg_rx_success    );
        jsonp_ulong       ( peers->http, "num_pull_response_messages_rx_failure",   cur->network_health_pull_response_msg_rx_failure    );
        jsonp_ulong       ( peers->http, "num_pull_response_entries_rx_success",    cur->network_health_pull_response_crds_rx_success   );
        jsonp_ulong       ( peers->http, "num_pull_response_entries_rx_failure",    cur->network_health_pull_response_crds_rx_failure   );
        jsonp_ulong       ( peers->http, "num_pull_response_entries_rx_duplicate",  cur->network_health_pull_response_crds_rx_duplicate );
        jsonp_ulong_as_str( peers->http, "total_stake",                             cur->network_health_total_stake                     );
        jsonp_ulong       ( peers->http, "total_peers",                             cur->network_health_total_peers                     );
        jsonp_ulong_as_str( peers->http, "connected_stake",                         cur->network_health_connected_stake                 );
        jsonp_ulong       ( peers->http, "connected_staked_peers",                  cur->network_health_connected_staked_peers          );
        jsonp_ulong       ( peers->http, "connected_unstaked_peers",                cur->network_health_connected_unstaked_peers        );
      jsonp_close_object( peers->http );

      jsonp_open_object( peers->http, "ingress" );

        jsonp_open_array( peers->http, "peer_names" );
          for( ulong i=0UL; i<cur->network_ingress_peer_sz; i++ ) jsonp_string( peers->http, NULL, cur->network_ingress_peer_names[ i ] );
        jsonp_close_array( peers->http );

        jsonp_open_array( peers->http, "peer_identities" );
          for( ulong i=0UL; i<cur->network_ingress_peer_sz; i++ ) {
            char identity_base58[ FD_BASE58_ENCODED_32_SZ ];
            fd_base58_encode_32( cur->network_ingress_peer_identities[ i ].uc, NULL, identity_base58 );
            jsonp_string( peers->http, NULL, identity_base58 );
          }
        jsonp_close_array( peers->http );

        jsonp_open_array( peers->http, "peer_throughput" );
          for( ulong i=0UL; i<cur->network_ingress_peer_sz; i++ ) jsonp_long( peers->http, NULL, cur->network_ingress_peer_bytes_per_sec[ i ] );
        jsonp_close_array( peers->http );
        jsonp_long( peers->http, "total_throughput", cur->network_ingress_total_bytes_per_sec );
      jsonp_close_object( peers->http );

      jsonp_open_object( peers->http, "egress" );
        jsonp_open_array( peers->http, "peer_names" );
          for( ulong i=0UL; i<cur->network_egress_peer_sz; i++ ) jsonp_string( peers->http, NULL, cur->network_egress_peer_names[ i ] );
        jsonp_close_array( peers->http );

                jsonp_open_array( peers->http, "peer_identities" );
          for( ulong i=0UL; i<cur->network_egress_peer_sz; i++ ) {
            char identity_base58[ FD_BASE58_ENCODED_32_SZ ];
            fd_base58_encode_32( cur->network_egress_peer_identities[ i ].uc, NULL, identity_base58 );
            jsonp_string( peers->http, NULL, identity_base58 );
          }
        jsonp_close_array( peers->http );

        jsonp_open_array( peers->http, "peer_throughput" );
          for( ulong i=0UL; i<cur->network_egress_peer_sz; i++ ) jsonp_long( peers->http, NULL, cur->network_egress_peer_bytes_per_sec[ i ] );
        jsonp_close_array( peers->http );
        jsonp_long( peers->http, "total_throughput", cur->network_egress_total_bytes_per_sec );
      jsonp_close_object( peers->http );

      jsonp_open_object( peers->http, "storage" );
        /* since these are gauges, we don't take a diff */
        jsonp_ulong( peers->http, "capacity", cur->storage_capacity );
        jsonp_ulong( peers->http, "expired_count", cur->storage_expired_cnt );
        jsonp_ulong( peers->http, "evicted_count", cur->storage_evicted_cnt );
        jsonp_open_array( peers->http, "count" );
          for( ulong i = 0UL; i<FD_METRICS_ENUM_CRDS_VALUE_CNT; i++ ) jsonp_ulong( peers->http, NULL, cur->storage_active_cnt[ i ] );
        jsonp_close_array( peers->http );
        jsonp_open_array( peers->http, "count_tx" );
          for( ulong i = 0UL; i<FD_METRICS_ENUM_CRDS_VALUE_CNT; i++ ) jsonp_ulong( peers->http, NULL, cur->storage_cnt_tx[ i ] );
        jsonp_close_array( peers->http );
        jsonp_open_array( peers->http, "bytes_tx" );
          for( ulong i = 0UL; i<FD_METRICS_ENUM_CRDS_VALUE_CNT; i++ ) jsonp_ulong( peers->http, NULL, cur->storage_bytes_tx[ i ] );
        jsonp_close_array( peers->http );
      jsonp_close_object( peers->http );
      jsonp_open_object( peers->http, "messages" );
        jsonp_open_array( peers->http, "num_bytes_rx" );
          for( ulong i = 0UL; i<FD_METRICS_ENUM_GOSSIP_MESSAGE_CNT; i++ ) jsonp_ulong( peers->http, NULL, cur->messages_bytes_rx[ i ] );
        jsonp_close_array( peers->http );
        jsonp_open_array( peers->http, "num_bytes_tx" );
          for( ulong i = 0UL; i<FD_METRICS_ENUM_GOSSIP_MESSAGE_CNT; i++ ) jsonp_ulong( peers->http, NULL, cur->messages_bytes_tx[ i ] );
        jsonp_close_array( peers->http );
        jsonp_open_array( peers->http, "num_messages_rx" );
          for( ulong i = 0UL; i<FD_METRICS_ENUM_GOSSIP_MESSAGE_CNT; i++ ) jsonp_ulong( peers->http, NULL, cur->messages_count_rx[ i ] );
        jsonp_close_array( peers->http );
        jsonp_open_array( peers->http, "num_messages_tx" );
          for( ulong i = 0UL; i<FD_METRICS_ENUM_GOSSIP_MESSAGE_CNT; i++ ) jsonp_ulong( peers->http, NULL, cur->messages_count_tx[ i ] );
        jsonp_close_array( peers->http );
      jsonp_close_object( peers->http );
    jsonp_close_object( peers->http );
  jsonp_close_envelope( peers->http );
}

static void
fd_gui_printf_shreds_window( fd_gui_t * gui, long after_ns, long before_ns ) {
  /* find the min slot / min ts across the window (for delta encoding). */
  ulong min_slot = ULONG_MAX;
  long  min_ts   = LONG_MAX;
  if( FD_LIKELY( gui->db ) ) {
    fd_gui_hist_iter_t it;
    if( FD_LIKELY( !fd_gui_hist_range_begin( gui, &it, FD_GUI_HIST_SHRED_EVENTS, after_ns, before_ns, NULL, NULL ) ) ) {
      while( fd_gui_hist_range_next( &it ) ) {
        fd_gui_slot_history_shred_event_t const * e = (fd_gui_slot_history_shred_event_t const *)it.rec;
        if( FD_UNLIKELY( e->timestamp<after_ns || e->timestamp>before_ns ) ) continue;
        min_slot = fd_ulong_min( min_slot, e->slot );
        min_ts   = fd_long_min ( min_ts,   e->timestamp );
      }
      fd_gui_hist_range_end( &it );
    }
  }

  jsonp_ulong      ( gui->http, "reference_slot", min_slot );
  jsonp_long_as_str( gui->http, "reference_ts",   min_ts   );

#define SHREDS_WINDOW_ITER( code ) \
  do { \
    if( FD_LIKELY( gui->db ) ) { \
      fd_gui_hist_iter_t it; \
      if( FD_LIKELY( !fd_gui_hist_range_begin( gui, &it, FD_GUI_HIST_SHRED_EVENTS, after_ns, before_ns, NULL, NULL ) ) ) { \
        while( fd_gui_hist_range_next( &it ) ) { \
          fd_gui_slot_history_shred_event_t const * e = (fd_gui_slot_history_shred_event_t const *)it.rec; (void)e; \
          ulong db_event_slot = e->slot; (void)db_event_slot; \
          if( FD_UNLIKELY( e->timestamp<after_ns || e->timestamp>before_ns ) ) continue; \
          do { code } while(0); \
        } \
        fd_gui_hist_range_end( &it ); \
      } \
    } \
  } while(0)

  jsonp_open_array( gui->http, "slot_delta" );
    SHREDS_WINDOW_ITER( { jsonp_ulong( gui->http, NULL, db_event_slot-min_slot ); } );
  jsonp_close_array( gui->http );
  jsonp_open_array( gui->http, "shred_idx" );
    SHREDS_WINDOW_ITER({
      if( FD_LIKELY( e->shred_idx!=USHORT_MAX ) ) jsonp_ulong( gui->http, NULL, e->shred_idx );
      else                                        jsonp_null ( gui->http, NULL );
    });
  jsonp_close_array( gui->http );
  jsonp_open_array( gui->http, "event" );
    SHREDS_WINDOW_ITER( { jsonp_ulong( gui->http, NULL, e->event ); } );
  jsonp_close_array( gui->http );
  jsonp_open_array( gui->http, "event_ts_delta" );
    SHREDS_WINDOW_ITER( { jsonp_long_as_str( gui->http, NULL, e->timestamp-min_ts ); } );
  jsonp_close_array( gui->http );

#undef SHREDS_WINDOW_ITER
}

void
fd_gui_printf_shred_updates( fd_gui_t * gui, long after_ns, long before_ns ) {
  jsonp_open_envelope( gui->http, "slot", "live_shreds" );
    jsonp_open_object( gui->http, "value" );
      fd_gui_printf_shreds_window( gui, after_ns, before_ns );
    jsonp_close_object( gui->http );
  jsonp_close_envelope( gui->http );
}

void
fd_gui_printf_shred_rebroadcast( fd_gui_t * gui, long after, long before ) {
  jsonp_open_envelope( gui->http, "slot", "live_shreds" );
    jsonp_open_object( gui->http, "value" );
      fd_gui_printf_shreds_window( gui, after, before );
    jsonp_close_object( gui->http );
  jsonp_close_envelope( gui->http );
}

void
fd_gui_printf_timeline_query_shreds( fd_gui_t *   gui,
                                     char const * topic,
                                     long         start_ns,
                                     long         end_ns,
                                     ulong        id ) {
  jsonp_open_envelope( gui->http, topic, "query_shreds" );
    jsonp_ulong( gui->http, "id", id );
    jsonp_open_object( gui->http, "value" );
      fd_gui_printf_shreds_window( gui, start_ns, end_ns );
    jsonp_close_object( gui->http );
  jsonp_close_envelope( gui->http );
}

void
fd_gui_peers_printf_wfs_add( fd_gui_peers_ctx_t * peers,
                             ulong const *        idxs,
                             ulong                cnt ) {
  jsonp_open_envelope( peers->http, "wait_for_supermajority", "peer_add" );
    jsonp_open_array( peers->http, "value" );
      for( ulong i=0UL; i<cnt; i++ ) {
        fd_gui_wfs_peer_t * wp = &peers->wfs_peers[ idxs[ i ] ];
        char identity_base58[ FD_BASE58_ENCODED_32_SZ ];
        fd_base58_encode_32( wp->identity_key.uc, NULL, identity_base58 );
        jsonp_string( peers->http, NULL, identity_base58 );
      }
    jsonp_close_array( peers->http );
  jsonp_close_envelope( peers->http );
}

void
fd_gui_peers_printf_wfs_remove( fd_gui_peers_ctx_t * peers,
                                ulong const *        idxs,
                                ulong                cnt ) {
  jsonp_open_envelope( peers->http, "wait_for_supermajority", "peer_remove" );
    jsonp_open_array( peers->http, "value" );
      for( ulong i=0UL; i<cnt; i++ ) {
        fd_gui_wfs_peer_t * wp = &peers->wfs_peers[ idxs[ i ] ];
        char identity_base58[ FD_BASE58_ENCODED_32_SZ ];
        fd_base58_encode_32( wp->identity_key.uc, NULL, identity_base58 );
        jsonp_string( peers->http, NULL, identity_base58 );
      }
    jsonp_close_array( peers->http );
  jsonp_close_envelope( peers->http );
}

void
fd_gui_peers_printf_wfs_stakes( fd_gui_peers_ctx_t * peers ) {
  jsonp_open_envelope( peers->http, "wait_for_supermajority", "stakes" );
    jsonp_open_object( peers->http, "value" );

      jsonp_open_array( peers->http, "staked_pubkeys" );
        for( ulong i=0UL; i<peers->wfs_peers_cnt; i++ ) {
          char identity_base58[ FD_BASE58_ENCODED_32_SZ ];
          fd_base58_encode_32( peers->wfs_peers[ i ].identity_key.uc, NULL, identity_base58 );
          jsonp_string( peers->http, NULL, identity_base58 );
        }
      jsonp_close_array( peers->http );

      jsonp_open_array( peers->http, "staked_lamports" );
        for( ulong i=0UL; i<peers->wfs_peers_cnt; i++ ) {
          jsonp_ulong_as_str( peers->http, NULL, peers->wfs_peers[ i ].stake );
        }
      jsonp_close_array( peers->http );

      jsonp_open_array( peers->http, "infos" );
        for( ulong i=0UL; i<peers->wfs_peers_cnt; i++ ) {
          fd_gui_config_parse_info_t * info =
              fd_gui_peers_node_info_map_ele_query(
                  peers->node_info_map, &peers->wfs_peers[ i ].identity_key, NULL, peers->node_info_pool );
          if( info ) {
            jsonp_open_object( peers->http, NULL );
              jsonp_string( peers->http, "name",             info->name );
              jsonp_string( peers->http, "details",          info->details );
              jsonp_string( peers->http, "website",          info->website );
              jsonp_string( peers->http, "icon_url",         info->icon_uri );
              jsonp_string( peers->http, "keybase_username", info->keybase_username );
            jsonp_close_object( peers->http );
          } else {
            jsonp_null( peers->http, NULL );
          }
        }
      jsonp_close_array( peers->http );

    jsonp_close_object( peers->http );
  jsonp_close_envelope( peers->http );
}
