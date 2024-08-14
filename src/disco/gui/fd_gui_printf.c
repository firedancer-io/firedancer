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
jsonp_pct( fd_gui_t * gui,
           ulong     num_now,
           ulong     num_then,
           double    lhopital_num,
           ulong     den_now,
           ulong     den_then,
           double    lhopital_den ) {
  if( FD_UNLIKELY( (num_now<num_then)                              |
                   (den_now<den_then)                              |
                   !((0.<=lhopital_num) && (lhopital_num<=DBL_MAX)) |
                   !((0.< lhopital_den) && (lhopital_den<=DBL_MAX)) ) ) {
    FD_LOG_ERR(( "invalid pct" ));
  }

  double pct = 100.*(((double)(num_now - num_then) + lhopital_num) / ((double)(den_now - den_then) + lhopital_den));

  if( FD_UNLIKELY( !((0.<=pct) && (pct<=DBL_MAX)) ) ) {
    FD_LOG_ERR(( "overflow pct" ));
  }

  jsonp_double( gui, NULL, pct );
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

static void
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
#ifdef FD_GUI_PRINTF_DEBUG
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
fd_gui_printf_open_query_response_envelope( fd_gui_t * gui,
                                            ulong      seq ) {
  jsonp_open_object( gui, NULL );
  jsonp_ulong( gui, "seq", seq );
  jsonp_open_array( gui, "response" );
}

void
fd_gui_printf_close_query_response_envelope( fd_gui_t * gui ) {
  jsonp_close_array( gui );
  jsonp_close_object( gui );
  jsonp_strip_trailing_comma( gui );
}

void
fd_gui_printf_null_query_response( fd_gui_t * gui,
                                   ulong      seq ) {
  jsonp_open_object( gui, NULL );
  jsonp_ulong( gui, "seq", seq );
  jsonp_null( gui, "response" );
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
fd_gui_printf_topology( fd_gui_t * gui ) {
  jsonp_open_envelope( gui, "summary", "topology" );
    jsonp_open_object( gui, "value" );
      jsonp_open_object( gui, "tile_counts" );
        jsonp_ulong( gui, "net",    gui->summary.net_tile_count );
        jsonp_ulong( gui, "quic",   gui->summary.quic_tile_count );
        jsonp_ulong( gui, "verify", gui->summary.verify_tile_count );
        jsonp_ulong( gui, "dedup",  1UL );
        jsonp_ulong( gui, "pack",   1UL );
        jsonp_ulong( gui, "bank",   gui->summary.bank_tile_count );
        jsonp_ulong( gui, "poh",    1UL );
        jsonp_ulong( gui, "shred",  gui->summary.shred_tile_count );
      jsonp_close_object( gui );
    jsonp_close_object( gui );
  jsonp_close_envelope( gui );
}

void
fd_gui_printf_epoch( fd_gui_t * gui,
                     ulong      epoch_idx ) {
  jsonp_open_envelope( gui, "epoch", "new" );
    jsonp_open_object( gui, "value" );
      jsonp_ulong( gui, "epoch",                   gui->epoch.epochs[epoch_idx].epoch );
      jsonp_ulong( gui, "start_slot",              gui->epoch.epochs[epoch_idx].start_slot );
      jsonp_ulong( gui, "end_slot",                gui->epoch.epochs[epoch_idx].end_slot );
      jsonp_ulong( gui, "excluded_stake_lamports", gui->epoch.epochs[epoch_idx].excluded_stake );
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

void
fd_gui_printf_epoch1( fd_gui_t * gui ) {
  fd_gui_printf_epoch( gui, 0UL );
}

void
fd_gui_printf_epoch2( fd_gui_t * gui ) {
  fd_gui_printf_epoch( gui, 1UL );
}

void
fd_gui_printf_txn_info_summary_this( fd_gui_t *          gui,
                                     fd_gui_txn_info_t * txn_info ) {
  jsonp_open_envelope( gui, "summary", "upcoming_slot_txn_info" );
    jsonp_open_object( gui, "value" );
      jsonp_ulong( gui, "acquired_txns",          txn_info->acquired_txns );
      jsonp_ulong( gui, "acquired_txns_leftover", txn_info->acquired_txns_leftover );
      jsonp_ulong( gui, "acquired_txns_quic",     txn_info->acquired_txns_quic );
      jsonp_ulong( gui, "acquired_txns_nonquic",  txn_info->acquired_txns_nonquic );
      jsonp_ulong( gui, "acquired_txns_gossip",   txn_info->acquired_txns_gossip );
      jsonp_ulong( gui, "dropped_txns",           txn_info->dropped_txns );

      jsonp_open_object( gui, "dropped_txns_net" );
        jsonp_ulong( gui, "count", txn_info->dropped_txns_net_overrun + txn_info->dropped_txns_net_invalid );
        jsonp_open_object( gui, "breakdown" );
          jsonp_ulong( gui, "net_overrun", txn_info->dropped_txns_net_overrun );
          jsonp_ulong( gui, "net_invalid", txn_info->dropped_txns_net_invalid );
        jsonp_close_object( gui );
      jsonp_close_object( gui );

      jsonp_open_object( gui, "dropped_txns_quic" );
        jsonp_ulong( gui, "count", txn_info->dropped_txns_quic_overrun + txn_info->dropped_txns_quic_reasm );
        jsonp_open_object( gui, "breakdown" );
          jsonp_ulong( gui, "quic_overrun", txn_info->dropped_txns_quic_overrun );
          jsonp_ulong( gui, "quic_reasm",   txn_info->dropped_txns_quic_reasm );
        jsonp_close_object( gui );
      jsonp_close_object( gui );

      jsonp_open_object( gui, "dropped_txns_verify" );
        jsonp_ulong( gui, "count", txn_info->dropped_txns_verify_overrun + txn_info->dropped_txns_verify_drop );
        jsonp_open_object( gui, "breakdown" );
          jsonp_ulong( gui, "verify_overrun", txn_info->dropped_txns_verify_overrun );
          jsonp_ulong( gui, "verify_drop", txn_info->dropped_txns_verify_drop );
        jsonp_close_object( gui );
      jsonp_close_object( gui );

      jsonp_open_object( gui, "dropped_txns_dedup" );
        jsonp_ulong( gui, "count", txn_info->dropped_txns_dedup_drop );
        jsonp_open_object( gui, "breakdown" );
          jsonp_ulong( gui, "dedup_drop", txn_info->dropped_txns_dedup_drop );
        jsonp_close_object( gui );
      jsonp_close_object( gui );

      jsonp_open_object( gui, "dropped_txns_pack" );
        jsonp_ulong( gui, "count", txn_info->dropped_txns_pack_nonleader + txn_info->dropped_txns_pack_invalid + txn_info->dropped_txns_pack_priority );
        jsonp_open_object( gui, "breakdown" );
          jsonp_ulong( gui, "pack_nonleader", txn_info->dropped_txns_pack_nonleader );
          jsonp_ulong( gui, "pack_invalid", txn_info->dropped_txns_pack_invalid );
          jsonp_ulong( gui, "pack_priority", txn_info->dropped_txns_pack_priority );
        jsonp_close_object( gui );
      jsonp_close_object( gui );

      jsonp_open_object( gui, "dropped_txns_bank" );
        jsonp_ulong( gui, "count", txn_info->dropped_txns_bank_invalid );
        jsonp_open_object( gui, "breakdown" );
          jsonp_ulong( gui, "bank_invalid", txn_info->dropped_txns_bank_invalid );
        jsonp_close_object( gui );
      jsonp_close_object( gui );

      jsonp_ulong( gui, "executed_txns_failure", txn_info->executed_txns_failure );
      jsonp_ulong( gui, "executed_txns_success", txn_info->executed_txns_success );

      jsonp_ulong( gui, "buffered_txns", txn_info->buffered_txns );
    jsonp_close_object( gui );
  jsonp_close_envelope( gui );
}

void
fd_gui_printf_txn_info_summary( fd_gui_t * gui ) {
  fd_gui_printf_txn_info_summary_this( gui, gui->summary.txn_info_json );
}

static ulong
tile_total_ticks( fd_gui_tile_info_t * tile_info ) {
  return tile_info->housekeeping_ticks +
         tile_info->backpressure_ticks +
         tile_info->caught_up_ticks +
         tile_info->overrun_polling_ticks +
         tile_info->overrun_reading_ticks +
         tile_info->filter_before_frag_ticks +
         tile_info->filter_after_frag_ticks +
         tile_info->finish_ticks;
}

static void
fd_gui_printf_tile_info1( fd_gui_t * gui,
                          char *     tile_name ) {
  fd_topo_t * topo      = gui->topo;

  jsonp_open_array( gui, "idle" );
    for( ulong i=0UL; i<topo->tile_cnt; i++) {
      if ( !strcmp( topo->tiles[ i ].name, tile_name ) ) {
        fd_gui_tile_info_t * prv = gui->summary.tile_info + ( 2 * i + ( gui->summary.tile_info_sample_cnt % 2 ));
        fd_gui_tile_info_t * cur = gui->summary.tile_info + ( 2 * i + ( ( gui->summary.tile_info_sample_cnt + 1 ) % 2 ));
        // jsonb_pct( jsonb, cur->housekeeping_ticks,       prv->housekeeping_ticks,       0., tile_total_ticks( cur ), tile_total_ticks( prv ), DBL_MIN );
        // jsonb_pct( jsonb, cur->backpressure_ticks,       prv->backpressure_ticks,       0., tile_total_ticks( cur ), tile_total_ticks( prv ), DBL_MIN );
        jsonp_pct( gui, cur->caught_up_ticks,          prv->caught_up_ticks,          0., tile_total_ticks( cur ), tile_total_ticks( prv ), DBL_MIN );
        // jsonb_pct( jsonb, cur->overrun_polling_ticks,    prv->overrun_polling_ticks,    0., tile_total_ticks( cur ), tile_total_ticks( prv ), DBL_MIN );
        // jsonb_pct( jsonb, cur->overrun_reading_ticks,    prv->overrun_reading_ticks,    0., tile_total_ticks( cur ), tile_total_ticks( prv ), DBL_MIN );
        // jsonb_pct( jsonb, cur->filter_before_frag_ticks, prv->filter_before_frag_ticks, 0., tile_total_ticks( cur ), tile_total_ticks( prv ), DBL_MIN );
        // jsonb_pct( jsonb, cur->filter_after_frag_ticks , prv->filter_after_frag_ticks,  0., tile_total_ticks( cur ), tile_total_ticks( prv ), DBL_MIN );
        // jsonb_pct( jsonb, cur->finish_ticks,             prv->finish_ticks,             0., tile_total_ticks( cur ), tile_total_ticks( prv ), DBL_MIN );
      }
    }
  jsonp_close_array( gui );
}

void
fd_gui_printf_tile_info( fd_gui_t * gui ) {
  jsonp_open_envelope( gui, "summary", "tile_info" );
    jsonp_open_object( gui, "value" );
      jsonp_open_object( gui, "net" );
      fd_gui_printf_tile_info1( gui, "net" );
      jsonp_close_object( gui );

      jsonp_open_object( gui, "quic" );
      fd_gui_printf_tile_info1( gui, "quic" );
      jsonp_close_object( gui );

      jsonp_open_object( gui, "verify" );
      fd_gui_printf_tile_info1( gui, "verify" );
      jsonp_close_object( gui );

      jsonp_open_object( gui, "dedup" );
      fd_gui_printf_tile_info1( gui, "dedup" );
      jsonp_close_object( gui );

      jsonp_open_object( gui, "pack" );
      fd_gui_printf_tile_info1( gui, "pack" );
      jsonp_close_object( gui );

      jsonp_open_object( gui, "bank" );
      fd_gui_printf_tile_info1( gui, "bank" );
      jsonp_close_object( gui );

      jsonp_open_object( gui, "poh" );
      fd_gui_printf_tile_info1( gui, "poh" );
      jsonp_close_object( gui );

      jsonp_open_object( gui, "shred" );
      fd_gui_printf_tile_info1( gui, "shred" );
      jsonp_close_object( gui );
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

#endif /* HEADER_fd_src_disco_gui_fd_gui_printf_h */