#ifndef HEADER_fd_src_disco_gui_fd_gui_printf_h
#define HEADER_fd_src_disco_gui_fd_gui_printf_h

#include <ctype.h>
#include <stdio.h>

#include "fd_gui_printf.h"

#include "../../ballet/http/fd_hcache_private.h"
#include "../../ballet/utf8/fd_utf8.h"

#define FD_GUI_PRINTF_DEBUG 0

static void
jsonp_strip_trailing_comma( fd_gui_t * gui ) {
  if( FD_LIKELY( !gui->hcache->snap_err &&
                 gui->hcache->snap_len>=1UL &&
                 fd_hcache_private_data( gui->hcache )[ gui->hcache->snap_off+gui->hcache->snap_len-1UL]==(uchar)',' ) ) {
    gui->hcache->snap_len--;
  }
}

static void
jsonp_open_object( fd_gui_t *   gui,
                   char const * key ) {
  if( FD_LIKELY( key ) ) fd_hcache_printf( gui->hcache, "\"%s\":{", key );
  else                   fd_hcache_printf( gui->hcache, "{" );
}

static void
jsonp_close_object( fd_gui_t * gui ) {
  jsonp_strip_trailing_comma( gui );
  fd_hcache_printf( gui->hcache, "}," );
}

static void
jsonp_open_array( fd_gui_t *   gui,
                  char const * key ) {
  if( FD_LIKELY( key ) ) fd_hcache_printf( gui->hcache, "\"%s\":[", key );
  else                   fd_hcache_printf( gui->hcache, "[" );
}

static void
jsonp_close_array( fd_gui_t * gui ) {
  jsonp_strip_trailing_comma( gui );
  fd_hcache_printf( gui->hcache, "]," );
}

static void
jsonp_ulong( fd_gui_t *   gui,
             char const * key,
             ulong        value ) {
  if( FD_LIKELY( key ) ) fd_hcache_printf( gui->hcache, "\"%s\":%lu,", key, value );
  else                   fd_hcache_printf( gui->hcache, "%lu,", value );
}

static void 
jsonp_double( fd_gui_t *   gui,
              char const * key,
              double       value ) {
  if( FD_LIKELY( key ) ) fd_hcache_printf( gui->hcache, "\"%s\":%.2f,", key, value );
  else                   fd_hcache_printf( gui->hcache, "%.2f,", value );
}

static void
jsonp_sanitize_str( fd_hcache_t * hcache,
                    ulong         start_len ) {
  /* escape quotemark, reverse solidus, and control chars U+0000 through U+001F
     just replace with a space */
  uchar * data = fd_hcache_private_data( hcache );
  for( ulong i=start_len; i<hcache->snap_len; i++ ) {
    if( FD_UNLIKELY( data[ hcache->snap_off+i ] < 0x20 ||
                     data[ hcache->snap_off+i ] == '"' ||
                     data[ hcache->snap_off+i ] == '\\' ) ) {
      data[ hcache->snap_off+i ] = ' ';
    }
  }
}

FD_FN_UNUSED static void
print_char_buf_to_buf_escape_hex(const char *buf, ulong buf_sz, char *out_buf, ulong out_buf_sz) {
  /* Prints invisible chars as escaped hex codes */
  ulong idx = 0;
  for( ulong i = 0; i < buf_sz; ++i ) {
    uchar c = (uchar)buf[i];
    if( isprint( c ) ) {
      if( idx < out_buf_sz - 1 ) {
        out_buf[idx++] = (char)c;
      }
    } else {
      if( idx < out_buf_sz - 4UL ) { // \xXX takes 4 characters
        snprintf(out_buf + idx, out_buf_sz - idx, "\\x%02x", c);
        idx += 4UL;
      }
    }
  }
  // Null-terminate the temporary buffer
  if( idx < out_buf_sz ) {
    out_buf[idx] = '\0';
  } else {
    out_buf[out_buf_sz - 1] = '\0';
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
#if FD_GUI_PRINTF_DEBUG
      print_char_buf_to_buf_escape_hex( value, strlen( value ), gui->tmp_buf, sizeof(gui->tmp_buf) );
      FD_LOG_NOTICE(( "invalid utf8 for key=%s value=%s", key ? key : "", gui->tmp_buf ));
#endif
    }
  }
  if( FD_LIKELY( key ) ) {
    if( FD_LIKELY( val ) ) {
      fd_hcache_printf( gui->hcache, "\"%s\":\"", key );
      ulong start_len = gui->hcache->snap_len;
      fd_hcache_printf( gui->hcache, "%s", val );
      jsonp_sanitize_str( gui->hcache, start_len );
      fd_hcache_printf( gui->hcache, "\"," );
    } else {
      fd_hcache_printf( gui->hcache, "\"%s\":null,", key );
    }
  } else {
    if( FD_LIKELY( val ) ) {
      fd_hcache_printf( gui->hcache, "\"" );
      ulong start_len = gui->hcache->snap_len;
      fd_hcache_printf( gui->hcache, "%s", val );
      jsonp_sanitize_str( gui->hcache, start_len );
      fd_hcache_printf( gui->hcache, "\"," );
    } else {
      fd_hcache_printf( gui->hcache, "null," );
    }
  }
}

static void
jsonp_bool( fd_gui_t *   gui,
            char const * key,
            int          value ) {
  if( FD_LIKELY( key ) ) fd_hcache_printf( gui->hcache, "\"%s\":%s,", key, value ? "true" : "false" );
  else                   fd_hcache_printf( gui->hcache, "%s,", value ? "true" : "false" );
}

static void
jsonp_null( fd_gui_t *   gui,
            char const * key ) {
  if( FD_LIKELY( key ) ) fd_hcache_printf( gui->hcache, "\"%s\": null,", key );
  else                   fd_hcache_printf( gui->hcache, "null," );
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
  jsonp_open_object( gui, NULL );
    jsonp_string( gui, "topic", topic );
    jsonp_string( gui, "key", key );
    jsonp_ulong( gui, "id", id );
    jsonp_null( gui, "value" );
  jsonp_close_object( gui );
  jsonp_strip_trailing_comma( gui );
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
fd_gui_printf_identity_key( fd_gui_t * gui ) {
  jsonp_open_envelope( gui, "summary", "identity_key" );
    jsonp_string( gui, "value", gui->summary.identity_key_base58 );
  jsonp_close_envelope( gui );
}

void
fd_gui_printf_uptime_nanos( fd_gui_t * gui ) {
  jsonp_open_envelope( gui, "summary", "uptime_nanos" );
    jsonp_ulong( gui, "value", (ulong)(fd_log_wallclock() - gui->summary.startup_time_nanos ) );
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

    for( ulong i=0UL; i<150UL; i++ ) {
      ulong total_txn_cnt  = 0UL;
      ulong vote_txn_cnt   = 0UL;
      ulong failed_txn_cnt = 0UL;

      ulong last_total_txn_cnt  = 0UL;
      ulong last_vote_txn_cnt   = 0UL;
      ulong last_failed_txn_cnt = 0UL;
      long  last_time_nanos     = 0L;

      ;

      ulong start_slot = fd_ulong_if( gui->summary.slot_completed+i<=149, 0UL, gui->summary.slot_completed+i-149 );

      for( ulong i=0UL; i<fd_ulong_min( start_slot+1, FD_GUI_TPS_HISTORY_WINDOW_SZ ); i++ ) {
        ulong parent_idx = (start_slot-i) % FD_GUI_SLOTS_CNT;

        fd_gui_slot_t * slot = gui->slots[ parent_idx ];
        if( FD_UNLIKELY( slot->slot==ULONG_MAX) ) break;

        if( FD_UNLIKELY( slot->slot!=(start_slot-i) ) ) {
          FD_LOG_ERR(( "_slot %lu i %lu we expect _slot-i %lu got slot->slot %lu", start_slot, i, start_slot-i, slot->slot ));
        }

        if( FD_LIKELY( !slot->skipped ) ) {
          total_txn_cnt  += slot->total_txn_cnt;
          vote_txn_cnt   += slot->vote_txn_cnt;
          failed_txn_cnt += slot->failed_txn_cnt;

          last_total_txn_cnt  = slot->total_txn_cnt;
          last_vote_txn_cnt   = slot->vote_txn_cnt;
          last_failed_txn_cnt = slot->failed_txn_cnt;
          last_time_nanos     = slot->completed_time;
        }
      }

      total_txn_cnt  -= last_total_txn_cnt;
      vote_txn_cnt   -= last_vote_txn_cnt;
      failed_txn_cnt -= last_failed_txn_cnt;

      long now = fd_log_wallclock();
      gui->summary.estimated_tps        = (total_txn_cnt *1000000000UL)/(ulong)(now-last_time_nanos);
      gui->summary.estimated_vote_tps   = (vote_txn_cnt  *1000000000UL)/(ulong)(now-last_time_nanos);
      gui->summary.estimated_failed_tps = (failed_txn_cnt*1000000000UL)/(ulong)(now-last_time_nanos);

      jsonp_open_array( gui, NULL );
        jsonp_ulong( gui, NULL, gui->summary.estimated_tps );
        jsonp_ulong( gui, NULL, gui->summary.estimated_vote_tps );
        jsonp_ulong( gui, NULL, gui->summary.estimated_failed_tps );
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
fd_gui_printf_balance( fd_gui_t * gui ) {
  jsonp_open_envelope( gui, "summary", "balance" );
    jsonp_ulong( gui, "value", gui->summary.balance );
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
fd_gui_printf_epoch( fd_gui_t * gui,
                     ulong      epoch_idx ) {
  jsonp_open_envelope( gui, "epoch", "new" );
    jsonp_open_object( gui, "value" );
      jsonp_ulong( gui, "epoch",                   gui->epoch.epochs[ epoch_idx ].epoch );
      if( FD_LIKELY( gui->epoch.epochs[ epoch_idx ].start_time!=LONG_MAX ) ) jsonp_ulong( gui, "start_time", (ulong)gui->epoch.epochs[ epoch_idx ].start_time );
      else                                                                    jsonp_null( gui, "start_time" );
      if( FD_LIKELY( gui->epoch.epochs[ epoch_idx ].end_time!=LONG_MAX ) ) jsonp_ulong( gui, "end_time", (ulong)gui->epoch.epochs[ epoch_idx ].end_time );
      else                                                                  jsonp_null( gui, "end_time" );
      jsonp_ulong( gui, "start_slot",              gui->epoch.epochs[ epoch_idx ].start_slot );
      jsonp_ulong( gui, "end_slot",                gui->epoch.epochs[ epoch_idx ].end_slot );
      jsonp_ulong( gui, "excluded_stake_lamports", gui->epoch.epochs[ epoch_idx ].excluded_stake );
      jsonp_open_array( gui, "staked_pubkeys" );
        fd_epoch_leaders_t * lsched = gui->epoch.epochs[epoch_idx].lsched;
        for( ulong i=0UL; i<lsched->pub_cnt; i++ ) {
          char identity_base58[ FD_BASE58_ENCODED_32_SZ ];
          fd_base58_encode_32( lsched->pub[ i ].uc, NULL, identity_base58 );
          jsonp_string( gui, NULL, identity_base58 );
        }
      jsonp_close_array( gui );

      jsonp_open_array( gui, "staked_lamports" );
        fd_stake_weight_t * stakes = gui->epoch.epochs[epoch_idx].stakes;
        for( ulong i=0UL; i<lsched->pub_cnt; i++ ) jsonp_ulong( gui, NULL, stakes[ i ].stake );
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
      jsonp_ulong( gui, "retained", prev->out.pack_retained );
      jsonp_ulong( gui, "quic",     cur->in.quic   - prev->in.quic );
      jsonp_ulong( gui, "udp",      cur->in.udp    - prev->in.udp );
      jsonp_ulong( gui, "gossip",   cur->in.gossip - prev->in.gossip );
    jsonp_close_object( gui );

    jsonp_open_object( gui, "out" );
      jsonp_ulong( gui, "quic_overrun",      cur->out.quic_overrun      - prev->out.quic_overrun );
      jsonp_ulong( gui, "quic_quic_invalid", cur->out.quic_quic_invalid - prev->out.quic_quic_invalid );
      jsonp_ulong( gui, "quic_udp_invalid",  cur->out.quic_udp_invalid  - prev->out.quic_udp_invalid );
      jsonp_ulong( gui, "verify_overrun",    cur->out.verify_overrun    - prev->out.verify_overrun );
      jsonp_ulong( gui, "verify_parse",      cur->out.verify_parse      - prev->out.verify_parse );
      jsonp_ulong( gui, "verify_failed",     cur->out.verify_failed     - prev->out.verify_failed );
      jsonp_ulong( gui, "verify_duplicate",  cur->out.verify_duplicate  - prev->out.verify_duplicate );
      jsonp_ulong( gui, "dedup_duplicate",   cur->out.dedup_duplicate   - prev->out.dedup_duplicate );
      jsonp_ulong( gui, "pack_invalid",      cur->out.pack_invalid      - prev->out.pack_invalid );
      jsonp_ulong( gui, "pack_retained",     cur->out.pack_retained );
      jsonp_ulong( gui, "pack_wait_full",    cur->out.pack_wait_full    - prev->out.pack_wait_full );
      jsonp_ulong( gui, "pack_leader_slow",  cur->out.pack_leader_slow  - prev->out.pack_leader_slow );
      jsonp_ulong( gui, "bank_invalid",      cur->out.bank_invalid      - prev->out.bank_invalid );
      jsonp_ulong( gui, "block_success",     cur->out.block_success     - prev->out.block_success );
      jsonp_ulong( gui, "block_fail",        cur->out.block_fail        - prev->out.block_fail );
    jsonp_close_object( gui );
  jsonp_close_object( gui );
}

void
fd_gui_printf_live_txn_waterfall( fd_gui_t *               gui,
                                  fd_gui_txn_waterfall_t * prev,
                                  fd_gui_txn_waterfall_t * cur,
                                  ulong                    next_leader_slot ) {
  jsonp_open_envelope( gui, "summary", "live_txn_waterfall" );
    jsonp_open_object( gui, "value" );
      jsonp_ulong( gui, "next_leader_slot", next_leader_slot );
      fd_gui_printf_waterfall( gui, prev, cur );
    jsonp_close_object( gui );
  jsonp_close_envelope( gui );
}

static void
fd_gui_printf_tile_prime_metric( fd_gui_t *                   gui,
                                 fd_gui_tile_prime_metric_t * prev,
                                 fd_gui_tile_prime_metric_t * cur ) {
  jsonp_open_object( gui, "tile_primary_metric" );
    /* Connection count is a point-in-time value not a cumulative value. */
    jsonp_ulong( gui, "quic",    cur->quic_conns );
    jsonp_ulong( gui, "net_in",  (cur->net_in_bytes-prev->net_in_bytes)*1000000000UL/(ulong)(cur->ts_nanos-prev->ts_nanos) );
    jsonp_ulong( gui, "net_out", (cur->net_out_bytes - prev->net_out_bytes)*1000000000UL/(ulong)(cur->ts_nanos-prev->ts_nanos) );
    if( FD_LIKELY( cur->verify_drop_denominator>prev->verify_drop_denominator ) ) {
      jsonp_double( gui, "verify", (double)(cur->verify_drop_numerator-prev->verify_drop_numerator)/(double)(cur->verify_drop_denominator-prev->verify_drop_denominator) );
    } else {
      jsonp_double( gui, "verify", -1 );
    }
    if( FD_LIKELY( cur->dedup_drop_denominator>prev->dedup_drop_denominator ) ) {
      jsonp_double( gui, "dedup", (double)(cur->dedup_drop_numerator-prev->dedup_drop_numerator)/(double)(cur->dedup_drop_denominator-prev->dedup_drop_denominator) );
    } else {
      jsonp_double( gui, "dedup", -1 );
    }
    jsonp_ulong( gui, "bank", (cur->bank_txn-prev->bank_txn)*1000000000UL/(ulong)(cur->ts_nanos-prev->ts_nanos) );
    /* pack fill rate is a point-in-time value not a cumulative value. */
    jsonp_double( gui, "pack", (double)(cur->pack_fill_numerator)/(double)(cur->pack_fill_denominator) );
    jsonp_double( gui, "poh", 0.0 );  //TODO
    jsonp_double( gui, "shred", 0.0 );//TODO
    jsonp_double( gui, "store", 0.0 );//TODO
  jsonp_close_object( gui );
}

void
fd_gui_printf_live_tile_prime_metric( fd_gui_t *                   gui,
                                      fd_gui_tile_prime_metric_t * prev,
                                      fd_gui_tile_prime_metric_t * cur,
                                      ulong                        next_leader_slot ) {
  jsonp_open_envelope( gui, "summary", "live_tile_primary_metric" );
    jsonp_open_object( gui, "value" );
      jsonp_ulong( gui, "next_leader_slot", next_leader_slot );
      fd_gui_printf_tile_prime_metric( gui, prev, cur );
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

    double cur_total = (double)(cur[ i ].housekeeping_ticks
                                + cur[ i ].backpressure_ticks
                                + cur[ i ].caught_up_ticks
                                + cur[ i ].overrun_polling_ticks
                                + cur[ i ].overrun_reading_ticks
                                + cur[ i ].filter_before_frag_ticks
                                + cur[ i ].filter_after_frag_ticks
                                + cur[ i ].finish_ticks);

    double prev_total = (double)(prev[ i ].housekeeping_ticks
                                  + prev[ i ].backpressure_ticks
                                  + prev[ i ].caught_up_ticks
                                  + prev[ i ].overrun_polling_ticks
                                  + prev[ i ].overrun_reading_ticks
                                  + prev[ i ].filter_before_frag_ticks
                                  + prev[ i ].filter_after_frag_ticks
                                  + prev[ i ].finish_ticks);

    double idle;
    if( FD_UNLIKELY( cur_total==prev_total ) ) {
      /* The tile didn't sample timers since the last sample, unclear what
         idleness should be so send -1. NaN would be better but no NaN in
         JSON. */
      idle = -1;
    } else {
      idle = (double)(cur[ i ].caught_up_ticks - prev[ i ].caught_up_ticks) / (cur_total - prev_total);
    }

    jsonp_double( gui, NULL, idle );
  }
}

void
fd_gui_printf_live_tile_timers( fd_gui_t * gui ) {
  ulong timers_cnt = sizeof(gui->summary.tile_timers_snap) / sizeof(gui->summary.tile_timers_snap[ 0 ]);

  jsonp_open_envelope( gui, "summary", "live_tile_timers" );
    jsonp_open_array( gui, "value" );
      fd_gui_tile_timers_t * cur  = gui->summary.tile_timers_snap[ (gui->summary.tile_timers_snap_idx+(timers_cnt-1UL))%timers_cnt ];
      fd_gui_tile_timers_t * prev = gui->summary.tile_timers_snap[ (gui->summary.tile_timers_snap_idx+(timers_cnt-2UL))%timers_cnt ];
      fd_gui_printf_tile_timers( gui, prev, cur );
    jsonp_close_array( gui );
  jsonp_close_envelope( gui );
}

void
fd_gui_printf_estimated_tps( fd_gui_t * gui ) {
  jsonp_open_envelope( gui, "summary", "estimated_tps" );
    jsonp_ulong( gui, "value", gui->summary.estimated_tps );
  jsonp_close_envelope( gui );
}

void
fd_gui_printf_estimated_vote_tps( fd_gui_t * gui ) {
  jsonp_open_envelope( gui, "summary", "estimated_vote_tps" );
    jsonp_ulong( gui, "value", gui->summary.estimated_vote_tps );
  jsonp_close_envelope( gui );
}

void
fd_gui_printf_estimated_nonvote_tps( fd_gui_t * gui ) {
  jsonp_open_envelope( gui, "summary", "estimated_nonvote_tps" );
    jsonp_ulong( gui, "value", gui->summary.estimated_tps - gui->summary.estimated_vote_tps );
  jsonp_close_envelope( gui );
}

void
fd_gui_printf_estimated_failed_tps( fd_gui_t * gui ) {
  jsonp_open_envelope( gui, "summary", "estimated_failed_tps" );
    jsonp_ulong( gui, "value", gui->summary.estimated_failed_tps );
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
  ulong vote_idxs[ 40200 ] = {0};
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
          jsonp_ulong( gui, "activated_stake", gui->vote_account.vote_accounts[ vote_idxs[ i ] ].activated_stake );
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

static fd_gui_txn_waterfall_t const *
reference_waterfall( fd_gui_t const *      gui,
                     fd_gui_slot_t const * slot ) {
  if( FD_UNLIKELY( slot->prior_leader_slot==ULONG_MAX ) ) return NULL;

  fd_gui_slot_t const * reference_slot = gui->slots[ slot->prior_leader_slot % FD_GUI_SLOTS_CNT ];
  if( FD_LIKELY( reference_slot->slot==slot->prior_leader_slot ) ) return reference_slot->waterfall_end;
  else                                                             return NULL;
}

static void
fd_gui_printf_ts_tile_timers( fd_gui_t *                   gui,
                              fd_gui_tile_timers_t const * prev,
                              fd_gui_tile_timers_t const * cur ) {
  jsonp_open_object( gui, NULL );
    jsonp_ulong( gui, "timestamp_nanos", 0 );
    jsonp_open_array( gui, "tile_timers" );
      fd_gui_printf_tile_timers( gui, prev, cur );
    jsonp_close_array( gui );
  jsonp_close_object( gui );
}

void
fd_gui_printf_slot( fd_gui_t * gui,
                    ulong      _slot ) {
  ulong slots_sz = sizeof(gui->slots) / sizeof(gui->slots[ 0 ]);
  fd_gui_slot_t * slot = gui->slots[ _slot % slots_sz ];

  char const * level;
  switch( slot->level ) {
    case FD_GUI_SLOT_LEVEL_INCOMPLETE:               level = "incomplete"; break;
    case FD_GUI_SLOT_LEVEL_COMPLETED:                level = "completed";  break;
    case FD_GUI_SLOT_LEVEL_OPTIMISTICALLY_CONFIRMED: level = "optimistically_confirmed"; break;
    case FD_GUI_SLOT_LEVEL_ROOTED:                   level = "rooted"; break;
    case FD_GUI_SLOT_LEVEL_FINALIZED:                level = "finalized"; break;
    default:                                         level = "unknown"; break;
  }

  jsonp_open_envelope( gui, "slot", "update" );
    jsonp_open_object( gui, "value" );
      jsonp_open_object( gui, "publish" );
        jsonp_ulong( gui, "slot", _slot );
        jsonp_bool( gui, "mine", slot->mine );
        jsonp_bool( gui, "skipped", slot->skipped );
        jsonp_string( gui, "level", level );
        if( FD_UNLIKELY( slot->total_txn_cnt==ULONG_MAX ) ) jsonp_null( gui, "transactions" );
        else                                                jsonp_ulong( gui, "transactions", slot->total_txn_cnt );
        if( FD_UNLIKELY( slot->vote_txn_cnt==ULONG_MAX ) ) jsonp_null( gui, "vote_transactions" );
        else                                               jsonp_ulong( gui, "vote_transactions", slot->vote_txn_cnt );
        if( FD_UNLIKELY( slot->failed_txn_cnt==ULONG_MAX ) ) jsonp_null( gui, "failed_transactions" );
        else                                                 jsonp_ulong( gui, "failed_transactions", slot->failed_txn_cnt );
        if( FD_UNLIKELY( slot->compute_units==ULONG_MAX ) ) jsonp_null( gui, "compute_units" );
        else                                                jsonp_ulong( gui, "compute_units", slot->compute_units );
      jsonp_close_object( gui );

      if( FD_LIKELY( slot->leader_state==FD_GUI_SLOT_LEADER_ENDED ) ) {
        fd_gui_txn_waterfall_t const * ref = reference_waterfall( gui, slot );
        if( FD_LIKELY( ref ) ) fd_gui_printf_waterfall( gui, ref, slot->waterfall_end );
        else                   jsonp_null( gui, "waterfall" );

        /*jsonp_open_array( gui, "tile_timers" );
          fd_gui_tile_timers_t const * prev_timer = slot->tile_timers_begin;

          ulong end = fd_ulong_if( slot->tile_timers_end_snap_idx<slot->tile_timers_begin_snap_idx, slot->tile_timers_end_snap_idx+sizeof(gui->summary.tile_timers_snap)/sizeof(gui->summary.tile_timers_snap[0]), slot->tile_timers_end_snap_idx );
          ulong stride = fd_ulong_max( 1UL, (end-slot->tile_timers_begin_snap_idx) / 40UL );

          for( ulong sample_snap_idx=slot->tile_timers_begin_snap_idx; sample_snap_idx<end; sample_snap_idx+=stride ) {
            fd_gui_printf_ts_tile_timers( gui, prev_timer, gui->summary.tile_timers_snap[ sample_snap_idx % (sizeof(gui->summary.tile_timers_snap)/sizeof(gui->summary.tile_timers_snap[0])) ] );
            prev_timer = gui->summary.tile_timers_snap[ sample_snap_idx % (sizeof(gui->summary.tile_timers_snap)/sizeof(gui->summary.tile_timers_snap[0])) ];
          }
          fd_gui_printf_ts_tile_timers( gui, prev_timer, slot->tile_timers_end );
        jsonp_close_array( gui );*/

        fd_gui_printf_tile_prime_metric( gui, slot->tile_prime_metric_begin, slot->tile_prime_metric_end );
      } else {
        jsonp_null( gui, "waterfall" );
        // jsonp_null( gui, "tile_timers" );
        jsonp_null( gui, "tile_primary_metric" );
      }
    jsonp_close_object( gui );
  jsonp_close_envelope( gui );
}

void
fd_gui_printf_slot_request( fd_gui_t * gui,
                            ulong      _slot,
                            ulong      id ) {
  ulong slots_sz = sizeof(gui->slots) / sizeof(gui->slots[ 0 ]);
  fd_gui_slot_t * slot = gui->slots[ _slot % slots_sz ];

  char const * level;
  switch( slot->level ) {
    case FD_GUI_SLOT_LEVEL_INCOMPLETE:               level = "incomplete"; break;
    case FD_GUI_SLOT_LEVEL_COMPLETED:                level = "completed";  break;
    case FD_GUI_SLOT_LEVEL_OPTIMISTICALLY_CONFIRMED: level = "optimistically_confirmed"; break;
    case FD_GUI_SLOT_LEVEL_ROOTED:                   level = "rooted"; break;
    case FD_GUI_SLOT_LEVEL_FINALIZED:                level = "finalized"; break;
    default:                                         level = "unknown"; break;
  }


  jsonp_open_envelope( gui, "slot", "query" );
    jsonp_ulong( gui, "id", id );
    jsonp_open_object( gui, "value" );

      jsonp_open_object( gui, "publish" );
        jsonp_ulong( gui, "slot", _slot );
        jsonp_bool( gui, "mine", slot->mine );
        jsonp_bool( gui, "skipped", slot->skipped );
        jsonp_string( gui, "level", level );
        if( FD_UNLIKELY( slot->total_txn_cnt==ULONG_MAX ) ) jsonp_null( gui, "transactions" );
        else                                                jsonp_ulong( gui, "transactions", slot->total_txn_cnt );
        if( FD_UNLIKELY( slot->vote_txn_cnt==ULONG_MAX ) ) jsonp_null( gui, "vote_transactions" );
        else                                               jsonp_ulong( gui, "vote_transactions", slot->vote_txn_cnt );
        if( FD_UNLIKELY( slot->failed_txn_cnt==ULONG_MAX ) ) jsonp_null( gui, "failed_transactions" );
        else                                                 jsonp_ulong( gui, "failed_transactions", slot->failed_txn_cnt );
        if( FD_UNLIKELY( slot->compute_units==ULONG_MAX ) ) jsonp_null( gui, "compute_units" );
        else                                                jsonp_ulong( gui, "compute_units", slot->compute_units );
      jsonp_close_object( gui );

      if( FD_LIKELY( slot->leader_state==FD_GUI_SLOT_LEADER_ENDED ) ) {
        fd_gui_txn_waterfall_t const * ref = reference_waterfall( gui, slot );
        if( FD_LIKELY( ref ) ) fd_gui_printf_waterfall( gui, ref, slot->waterfall_end );
        else                   jsonp_null( gui, "waterfall" );

        jsonp_open_array( gui, "tile_timers" );
          fd_gui_tile_timers_t const * prev_timer = slot->tile_timers_begin;

          ulong end = fd_ulong_if( slot->tile_timers_end_snap_idx<slot->tile_timers_begin_snap_idx, slot->tile_timers_end_snap_idx+sizeof(gui->summary.tile_timers_snap)/sizeof(gui->summary.tile_timers_snap[0]), slot->tile_timers_end_snap_idx );
          ulong stride = fd_ulong_max( 1UL, (end-slot->tile_timers_begin_snap_idx) / 40UL );

          for( ulong sample_snap_idx=slot->tile_timers_begin_snap_idx; sample_snap_idx<end; sample_snap_idx+=stride ) {
            fd_gui_printf_ts_tile_timers( gui, prev_timer, gui->summary.tile_timers_snap[ sample_snap_idx % (sizeof(gui->summary.tile_timers_snap)/sizeof(gui->summary.tile_timers_snap[0])) ] );
            prev_timer = gui->summary.tile_timers_snap[ sample_snap_idx % (sizeof(gui->summary.tile_timers_snap)/sizeof(gui->summary.tile_timers_snap[0])) ];
          }
          fd_gui_printf_ts_tile_timers( gui, prev_timer, slot->tile_timers_end );
        jsonp_close_array( gui );

        fd_gui_printf_tile_prime_metric( gui, slot->tile_prime_metric_begin, slot->tile_prime_metric_end );
      } else {
        jsonp_null( gui, "waterfall" );
        jsonp_null( gui, "tile_timers" );
        jsonp_null( gui, "tile_primary_metric" );
      }

    jsonp_close_object( gui );
  jsonp_close_envelope( gui );
}

#endif /* HEADER_fd_src_disco_gui_fd_gui_printf_h */
