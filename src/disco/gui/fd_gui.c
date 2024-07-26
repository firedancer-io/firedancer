#include "fd_gui.h"

#include "../fd_disco.h"
#include "../plugin/fd_plugin.h"

#include "../../ballet/base58/fd_base58.h"

#include "../../app/fdctl/config.h"

FD_FN_CONST ulong
fd_gui_align( void ) {
  return 128UL;
}

FD_FN_CONST ulong
fd_gui_footprint( void ) {
  return sizeof(fd_gui_t);
}

void *
fd_gui_new( void *             shmem,
            fd_http_server_t * server,
            fd_alloc_t *       alloc,
            char const *       version,
            char const *       cluster,
            char const *       identity_key_base58 ) {
  fd_gui_t * gui = (fd_gui_t *)shmem;

  gui->server              = server;
  gui->alloc               = alloc;

  gui->summary.version             = version;
  gui->summary.cluster             = cluster;
  gui->summary.identity_key_base58 = identity_key_base58;

  gui->summary.slot_rooted                   = 0UL;
  gui->summary.slot_optimistically_confirmed = 0UL;
  gui->summary.slot_completed                = 0UL;
  gui->summary.slot_estimated                = 0UL;

  fd_memset( &gui->summary.txn_info, 0, sizeof(gui->summary.txn_info) );
  gui->summary.last_txn_ts = fd_log_wallclock();

  gui->epoch.max_known_epoch = 1UL;
  fd_stake_weight_t dummy_stakes[1] = {{ .key = {{0}}, .stake = 1UL }};
  for( ulong i = 0UL; i < FD_GUI_NUM_EPOCHS; i++ ) {
    gui->epoch.epochs[i].epoch          = i;
    gui->epoch.epochs[i].start_slot     = 0UL;
    gui->epoch.epochs[i].end_slot       = 0UL; // end_slot is inclusive.
    gui->epoch.epochs[i].excluded_stake = 0UL;
    gui->epoch.epochs[i].lsched = fd_epoch_leaders_join( fd_epoch_leaders_new( gui->epoch.epochs[i]._lsched, 0UL, 0UL, 1UL, 1UL, dummy_stakes, 0UL ) );
    fd_memcpy(gui->epoch.epochs[i].stakes, dummy_stakes, sizeof(dummy_stakes[0]));
  }

  gui->gossip.peer_cnt = 0UL;

  jsonb_new(gui->jsonb, gui->json_buf, sizeof(gui->json_buf));

  return gui;
}

fd_gui_t *
fd_gui_join( void * shmem ) {
  return (fd_gui_t *)shmem;
}


static void
fd_gui_topic_key_to_json_init( jsonb_t    * jsonb,
                               char const * topic,
                               char const * key) {
  jsonb_init( jsonb );
  jsonb_open_obj( jsonb, NULL );
  jsonb_str( jsonb, "topic", topic );
  jsonb_str( jsonb, "key",   key );
}

static void
fd_gui_topic_key_to_json_fini( jsonb_t * jsonb) {
  jsonb_close_obj( jsonb );
  jsonb_fini( jsonb );
}

static void
fd_gui_epoch_to_json( fd_gui_t * gui,
                      jsonb_t  * jsonb,
                      ulong      epoch_idx) {
  fd_gui_topic_key_to_json_init( jsonb, "epoch", "new" );
  jsonb_open_obj( jsonb, "value" );
  jsonb_ulong( jsonb, "epoch",                   gui->epoch.epochs[epoch_idx].epoch );
  jsonb_ulong( jsonb, "start_slot",              gui->epoch.epochs[epoch_idx].start_slot );
  jsonb_ulong( jsonb, "end_slot",                gui->epoch.epochs[epoch_idx].end_slot );
  jsonb_ulong( jsonb, "excluded_stake_lamports", gui->epoch.epochs[epoch_idx].excluded_stake );
  jsonb_open_arr( jsonb, "staked_pubkeys" );
  fd_epoch_leaders_t * lsched = gui->epoch.epochs[epoch_idx].lsched;
  for( ulong i = 0; i < lsched->pub_cnt; i++ ) {
    char identity_base58[ FD_BASE58_ENCODED_32_SZ ];
    fd_base58_encode_32( lsched->pub[ i ].uc, NULL, identity_base58 );
    jsonb_str(jsonb, NULL, identity_base58);
  }
  jsonb_close_arr( jsonb );
  jsonb_open_arr( jsonb, "staked_lamports" );
  fd_stake_weight_t * stakes = gui->epoch.epochs[epoch_idx].stakes;
  for( ulong i = 0; i < lsched->pub_cnt; i++ ) {
    jsonb_ulong(jsonb, NULL, stakes[ i ].stake);
  }
  jsonb_close_arr( jsonb );
  jsonb_open_arr( jsonb, "leader_slots" );
  for( ulong i = 0; i < lsched->sched_cnt; i++ ) {
    jsonb_ulong(jsonb, NULL, lsched->sched[ i ]);
  }
  jsonb_close_arr( jsonb );
  jsonb_close_obj( jsonb );
  fd_gui_topic_key_to_json_fini( jsonb );
}

static void
fd_gui_txn_info_to_json_no_init( fd_gui_t * gui,
                                 jsonb_t  * jsonb) {
  jsonb_open_obj( jsonb, "value" );
  jsonb_ulong( jsonb, "acquired_txns_quic",          gui->summary.txn_info.acquired_txns_quic );
  jsonb_ulong( jsonb, "dropped_txns_quic_failed",    gui->summary.txn_info.dropped_txns_quic_failed );
  jsonb_ulong( jsonb, "dropped_txns_verify_failed",  gui->summary.txn_info.dropped_txns_verify_failed );
  jsonb_ulong( jsonb, "dropped_txns_verify_overrun", gui->summary.txn_info.dropped_txns_verify_overrun );
  jsonb_ulong( jsonb, "dropped_txns_dedup_failed",   gui->summary.txn_info.dropped_txns_dedup_failed );
  jsonb_ulong( jsonb, "dropped_txns_pack_invalid",   gui->summary.txn_info.dropped_txns_pack_invalid );
  jsonb_ulong( jsonb, "dropped_txns_pack_overrun",   gui->summary.txn_info.dropped_txns_pack_overrun );
  jsonb_close_obj( jsonb );
}

static void
fd_gui_txn_info_summary_to_json( fd_gui_t * gui,
                                 jsonb_t  * jsonb) {
  fd_gui_topic_key_to_json_init( jsonb, "summary", "upcoming_slot_txn_info" );
  fd_gui_txn_info_to_json_no_init( gui, jsonb );
  fd_gui_topic_key_to_json_fini( jsonb );
}

static void
fd_gui_version_to_json( fd_gui_t * gui,
                        jsonb_t  * jsonb) {
  fd_gui_topic_key_to_json_init( jsonb, "summary", "version" );
  jsonb_str( jsonb, "value", gui->summary.version );
  fd_gui_topic_key_to_json_fini( jsonb );
}

static void
fd_gui_cluster_to_json( fd_gui_t * gui,
                        jsonb_t  * jsonb) {
  fd_gui_topic_key_to_json_init( jsonb, "summary", "cluster" );
  jsonb_str( jsonb, "value", gui->summary.cluster );
  fd_gui_topic_key_to_json_fini( jsonb );
}

static void
fd_gui_identity_key_to_json( fd_gui_t * gui,
                             jsonb_t  * jsonb) {
  fd_gui_topic_key_to_json_init( jsonb, "summary", "identity_key" );
  jsonb_str( jsonb, "value", gui->summary.identity_key_base58 );
  fd_gui_topic_key_to_json_fini( jsonb );
}

static void
fd_gui_root_slot_to_json( fd_gui_t * gui,
                          jsonb_t  * jsonb) {
  fd_gui_topic_key_to_json_init( jsonb, "summary", "root_slot" );
  jsonb_ulong( jsonb, "value", gui->summary.slot_rooted );
  fd_gui_topic_key_to_json_fini( jsonb );
}

static void
fd_gui_optimistically_confirmed_slot_to_json( fd_gui_t * gui,
                                              jsonb_t  * jsonb) {
  fd_gui_topic_key_to_json_init( jsonb, "summary", "optimistically_confirmed_slot" );
  jsonb_ulong( jsonb, "value", gui->summary.slot_optimistically_confirmed );
  fd_gui_topic_key_to_json_fini( jsonb );
}

static void
fd_gui_completed_slot_to_json( fd_gui_t * gui,
                               jsonb_t  * jsonb) {
  fd_gui_topic_key_to_json_init( jsonb, "summary", "completed_slot" );
  jsonb_ulong( jsonb, "value", gui->summary.slot_completed );
  fd_gui_topic_key_to_json_fini( jsonb );
}

static void
fd_gui_estimated_slot_to_json( fd_gui_t * gui,
                               jsonb_t  * jsonb) {
  fd_gui_topic_key_to_json_init( jsonb, "summary", "estimated_slot" );
  jsonb_ulong( jsonb, "value", gui->summary.slot_estimated );
  fd_gui_topic_key_to_json_fini( jsonb );
}

static void
fd_gui_jsonb_send( fd_gui_t * gui,
                   jsonb_t  * jsonb,
                   ulong conn_id) {
  void * buffer = fd_alloc_malloc( gui->alloc, 1UL, jsonb->cur_sz );
  FD_TEST( buffer );
  fd_memcpy( buffer, jsonb->buf, jsonb->cur_sz );
  fd_http_server_ws_send( gui->server, conn_id, buffer, jsonb->cur_sz );
}

static void
fd_gui_jsonb_broadcast( fd_gui_t * gui,
                        jsonb_t  * jsonb) {
  void * buffer = fd_alloc_malloc( gui->alloc, 1UL, jsonb->cur_sz );
  FD_TEST( buffer );
  fd_memcpy( buffer, jsonb->buf, jsonb->cur_sz );
  fd_http_server_ws_broadcast( gui->server, buffer, jsonb->cur_sz );
}

void
fd_gui_ws_open( fd_gui_t *         gui,
                ulong              conn_id ) {

  jsonb_t * jsonb = gui->jsonb;

  fd_gui_version_to_json( gui, jsonb );
  fd_gui_jsonb_send( gui, jsonb, conn_id );

  fd_gui_cluster_to_json( gui, jsonb );
  fd_gui_jsonb_send( gui, jsonb, conn_id );

  fd_gui_identity_key_to_json( gui, jsonb );
  fd_gui_jsonb_send( gui, jsonb, conn_id );

  fd_gui_root_slot_to_json( gui, jsonb );
  fd_gui_jsonb_send( gui, jsonb, conn_id );

  fd_gui_optimistically_confirmed_slot_to_json( gui, jsonb );
  fd_gui_jsonb_send( gui, jsonb, conn_id );

  fd_gui_completed_slot_to_json( gui, jsonb );
  fd_gui_jsonb_send( gui, jsonb, conn_id );

  fd_gui_estimated_slot_to_json( gui, jsonb );
  fd_gui_jsonb_send( gui, jsonb, conn_id );

  ulong idx                 = (gui->epoch.max_known_epoch + 1) % FD_GUI_NUM_EPOCHS;
  for ( ulong i=0UL; i < FD_GUI_NUM_EPOCHS; i++ ) {
    fd_gui_epoch_to_json( gui, jsonb, idx );
    fd_gui_jsonb_send( gui, jsonb, conn_id );
    idx = (idx + 1) % FD_GUI_NUM_EPOCHS;
  }

  fd_gui_txn_info_summary_to_json( gui, jsonb );
  fd_gui_jsonb_send( gui, jsonb, conn_id );

  ulong message_len;
  const ulong buffer_size = 1024UL * 1024UL;
  char * buffer1 = fd_alloc_malloc( gui->alloc, 1UL, buffer_size );
  FD_TEST( buffer1 );
  FD_TEST( fd_cstr_printf_check( buffer1, buffer_size, &message_len, "{\n    \"topic\": \"gossip\",\n    \"key\": \"update\",\n    \"value\": {\n        \"add\": [\n" ) );

  for( ulong i=0UL; i<gui->gossip.peer_cnt; i++ ) {
    char identity_base58[ FD_BASE58_ENCODED_32_SZ ];
    fd_base58_encode_32( gui->gossip.peers[ i ].pubkey->uc, NULL, identity_base58 );
    ulong line_len;
    FD_TEST( fd_cstr_printf_check( buffer1+message_len, buffer_size-message_len, &line_len,
      "            {\n"
      "                \"identity\": \"%s\",\n"
      "                \"version\": \"%u.%u.%u\",\n"
      "                \"feature_set\": \"%u\",\n"
      "                \"wallclock\": \"%lu\",\n"
      "                \"shred_version\": \"%u\",\n"
      "                \"sockets\": {\n",
      identity_base58,
      gui->gossip.peers[ i ].version.major,
      gui->gossip.peers[ i ].version.minor,
      gui->gossip.peers[ i ].version.patch,
      gui->gossip.peers[ i ].version.feature_set,
      gui->gossip.peers[ i ].wallclock,
      gui->gossip.peers[ i ].shred_version ) );
    message_len += line_len;
    for( ulong j=0UL; j<12UL; j++ ) {
      if( FD_LIKELY( !gui->gossip.peers[ i ].sockets[ j ].ipv4 && !gui->gossip.peers[ i ].sockets[ j ].port ) ) continue;
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
      if( FD_UNLIKELY( j==11 ) )
        FD_TEST( fd_cstr_printf_check( buffer1+message_len, buffer_size-message_len, &line_len, "                    \"%s\": \"" FD_IP4_ADDR_FMT ":%u\"\n", tag, FD_IP4_ADDR_FMT_ARGS(gui->gossip.peers[ i ].sockets[ j ].ipv4 ), gui->gossip.peers[ i ].sockets[ j ].port ) );
      else
        FD_TEST( fd_cstr_printf_check( buffer1+message_len, buffer_size-message_len, &line_len, "                    \"%s\": \"" FD_IP4_ADDR_FMT ":%u\",\n", tag, FD_IP4_ADDR_FMT_ARGS(gui->gossip.peers[ i ].sockets[ j ].ipv4 ), gui->gossip.peers[ i ].sockets[ j ].port ) );
      message_len += line_len;
    }
    if( FD_UNLIKELY( i==gui->gossip.peer_cnt-1UL ) )
      FD_TEST( fd_cstr_printf_check( buffer1+message_len, buffer_size-message_len, &line_len, "                }\n            }\n" ) );
    else
      FD_TEST( fd_cstr_printf_check( buffer1+message_len, buffer_size-message_len, &line_len, "                }\n            },\n" ) );
    message_len += line_len;
  }

  ulong x_len;
  FD_TEST( fd_cstr_printf_check( buffer1+message_len, buffer_size, &x_len, "        ]\n    }\n}\n" ) );
  message_len += x_len;

  fd_http_server_ws_broadcast( gui->server, (uchar const *)buffer1, message_len );
}

void
fd_gui_poll( fd_gui_t *  gui,
             fd_topo_t * topo ) {
  long current = fd_log_wallclock();
  /* Has 100 millis passed since we last collected info? */
  if( current - gui->summary.last_txn_ts <= 100000000 ) return;

  /* Recalculate and publish. */
  gui->summary.last_txn_ts = current;
  config_t * config     = topo->config;
  // ulong net_tile_cnt    = config->layout.net_tile_count;
  ulong quic_tile_cnt   = config->layout.quic_tile_count;
  ulong verify_tile_cnt = config->layout.verify_tile_count;
  // ulong bank_tile_cnt   = config->layout.bank_tile_count;

#define FOR(cnt) for( ulong i=0UL; i<cnt; i++ )

  ulong quic_recv = 0UL;
  ulong quic_sent = 0UL;
  FOR( quic_tile_cnt ) {
    fd_topo_tile_t const * quic = &topo->tiles[ fd_topo_find_tile( topo, "quic", i ) ];
    ulong * quic_metrics = fd_metrics_tile( quic->metrics );
    quic_sent += quic_metrics[ MIDX( COUNTER, QUIC_TILE, REASSEMBLY_NOTIFY_OKAY ) ];
    quic_recv += quic_metrics[ MIDX( COUNTER, QUIC_TILE, REASSEMBLY_NOTIFY_ATTEMPTED ) ];
  }

  ulong verify_failed  = 0UL;
  ulong verify_sent    = 0UL;
  ulong verify_overrun = 0UL;
  FOR( verify_tile_cnt ) {
    fd_topo_tile_t const * verify = &topo->tiles[ fd_topo_find_tile( topo, "verify", i ) ];
    verify_overrun += fd_metrics_link_in( verify->metrics, 0UL )[ FD_METRICS_COUNTER_LINK_OVERRUN_POLLING_FRAG_COUNT_OFF ] / verify_tile_cnt;
    verify_overrun += fd_metrics_link_in( verify->metrics, 0UL )[ FD_METRICS_COUNTER_LINK_OVERRUN_READING_FRAG_COUNT_OFF ] / verify_tile_cnt;
    verify_failed += fd_metrics_link_in( verify->metrics, 0UL )[ FD_METRICS_COUNTER_LINK_FILTERED_COUNT_OFF ];
    verify_sent += fd_metrics_link_in( verify->metrics, 0UL )[ FD_METRICS_COUNTER_LINK_PUBLISHED_COUNT_OFF ];
  }

  fd_topo_tile_t const * dedup = &topo->tiles[ fd_topo_find_tile( topo, "dedup", 0UL ) ];
  ulong dedup_failed  = 0UL;
  FOR( verify_tile_cnt ) {
    dedup_failed += fd_metrics_link_in( dedup->metrics, i )[ FD_METRICS_COUNTER_LINK_FILTERED_COUNT_OFF ];
  }
  // ulong dedup_sent = fd_mcache_seq_query( fd_mcache_seq_laddr( topo->links[ dedup->out_link_id_primary ].mcache ) );

  fd_topo_tile_t const * pack = &topo->tiles[ fd_topo_find_tile( topo, "pack", 0UL ) ];
  ulong * pack_metrics = fd_metrics_tile( pack->metrics );
  // TODO this list is not comprehensive
  ulong pack_invalid = pack_metrics[ FD_METRICS_COUNTER_PACK_TRANSACTION_INSERTED_WRITE_SYSVAR_OFF ] +
                        pack_metrics[ FD_METRICS_COUNTER_PACK_TRANSACTION_INSERTED_ESTIMATION_FAIL_OFF ] +
                        pack_metrics[ FD_METRICS_COUNTER_PACK_TRANSACTION_INSERTED_TOO_LARGE_OFF ] +
                        pack_metrics[ FD_METRICS_COUNTER_PACK_TRANSACTION_INSERTED_EXPIRED_OFF ] +
                        pack_metrics[ FD_METRICS_COUNTER_PACK_TRANSACTION_INSERTED_ADDR_LUT_OFF ] +
                        pack_metrics[ FD_METRICS_COUNTER_PACK_TRANSACTION_INSERTED_UNAFFORDABLE_OFF ] +
                        pack_metrics[ FD_METRICS_COUNTER_PACK_TRANSACTION_INSERTED_DUPLICATE_OFF ] +
                        pack_metrics[ FD_METRICS_COUNTER_PACK_TRANSACTION_INSERTED_PRIORITY_OFF ] +
                        pack_metrics[ FD_METRICS_COUNTER_PACK_TRANSACTION_INSERTED_NONVOTE_REPLACE_OFF ] +
                        pack_metrics[ FD_METRICS_COUNTER_PACK_TRANSACTION_INSERTED_VOTE_REPLACE_OFF ];
  ulong pack_overrun = pack_metrics[ FD_METRICS_COUNTER_PACK_TRANSACTION_DROPPED_FROM_EXTRA_OFF ];
  // ulong pack_sent = pack_metrics[ FD_METRICS_HISTOGRAM_PACK_TOTAL_TRANSACTIONS_PER_MICROBLOCK_COUNT_OFF + FD_HISTF_BUCKET_CNT ];

  fd_gui_txn_info_t * txn_info = &gui->summary.txn_info;
  txn_info->acquired_txns_quic = quic_recv;
  txn_info->dropped_txns_verify_failed = verify_failed;
  txn_info->dropped_txns_verify_overrun = verify_overrun;
  txn_info->dropped_txns_dedup_failed = dedup_failed;
  txn_info->dropped_txns_pack_invalid = pack_invalid;
  txn_info->dropped_txns_pack_overrun = pack_overrun;

  fd_gui_txn_info_summary_to_json( gui, gui->jsonb );
  fd_gui_jsonb_broadcast( gui, gui->jsonb );
}

void
fd_gui_plugin_message( fd_gui_t *    gui,
                       ulong         plugin_msg,
                       uchar const * msg,
                       ulong         msg_len ) {
  (void)msg_len;
  jsonb_t * jsonb = gui->jsonb;

  switch( plugin_msg ) {
    case FD_PLUGIN_MSG_SLOT_ROOTED:
      gui->summary.slot_rooted = *(ulong const *)msg;
      fd_gui_root_slot_to_json( gui, jsonb );
      fd_gui_jsonb_broadcast( gui, jsonb );
      break;
    case FD_PLUGIN_MSG_SLOT_OPTIMISTICALLY_CONFIRMED:
      gui->summary.slot_optimistically_confirmed = *(ulong const *)msg;
      fd_gui_optimistically_confirmed_slot_to_json( gui, jsonb );
      fd_gui_jsonb_broadcast( gui, jsonb );
      break;
    case FD_PLUGIN_MSG_SLOT_COMPLETED:
      gui->summary.slot_completed = *(ulong const *)msg;
      fd_gui_completed_slot_to_json( gui, jsonb );
      fd_gui_jsonb_broadcast( gui, jsonb );
      break;
    case FD_PLUGIN_MSG_SLOT_ESTIMATED:
      gui->summary.slot_estimated = *(ulong const *)msg;
      fd_gui_estimated_slot_to_json( gui, jsonb );
      fd_gui_jsonb_broadcast( gui, jsonb );
      break;
    case FD_PLUGIN_MSG_LEADER_SCHEDULE: {
      ulong const * hdr         = fd_type_pun_const( msg );
      ulong epoch               = hdr[ 0 ];
      ulong staked_cnt          = hdr[ 1 ];
      ulong start_slot          = hdr[ 2 ];
      ulong slot_cnt            = hdr[ 3 ];
      ulong excluded_stake      = hdr[ 4 ];
      ulong idx                 = epoch % FD_GUI_NUM_EPOCHS;
      if( staked_cnt > MAX_PUB_CNT ) {
        FD_LOG_ERR(( "Unexpectedly large staked_cnt = %lu", staked_cnt ));
      }
      FD_LOG_NOTICE(( "got leader schedule epoch %lu staked_cnt %lu start_slot %lu slot_cnt %lu", epoch, staked_cnt, start_slot, slot_cnt ));
      if ( epoch > gui->epoch.max_known_epoch ) {
        gui->epoch.max_known_epoch = epoch;
      }
      gui->epoch.epochs[idx].epoch          = epoch;
      gui->epoch.epochs[idx].start_slot     = start_slot;
      gui->epoch.epochs[idx].end_slot       = start_slot + slot_cnt - 1; // end_slot is inclusive.
      gui->epoch.epochs[idx].excluded_stake = excluded_stake;
      fd_epoch_leaders_delete( fd_epoch_leaders_leave( gui->epoch.epochs[idx].lsched ) );
      gui->epoch.epochs[idx].lsched = fd_epoch_leaders_join( fd_epoch_leaders_new( gui->epoch.epochs[idx]._lsched,
                                                                                   epoch,
                                                                                   gui->epoch.epochs[idx].start_slot,
                                                                                   slot_cnt,
                                                                                   staked_cnt,
                                                                                   fd_type_pun_const( hdr + 5UL ),
                                                                                   excluded_stake ) );
      fd_memcpy(gui->epoch.epochs[idx].stakes, fd_type_pun_const( hdr + 5UL ), staked_cnt * sizeof(gui->epoch.epochs[idx].stakes[0]));

      /* Serialize to JSON */
      jsonb_t * jsonb = gui->jsonb;
      fd_gui_epoch_to_json( gui, jsonb, idx );
      fd_gui_jsonb_broadcast( gui, jsonb );
      break;
    }
    case FD_PLUGIN_MSG_GOSSIP_UPDATE: {
      ulong const * header = (ulong const *)fd_type_pun_const( msg );
      ulong peer_cnt = header[ 0 ];

      ulong update_cnt = 0UL;
      ulong updated[ 40200 ] = {0};

      ulong removed_cnt = 0UL;
      fd_pubkey_t removed[ 40200 ] = {0};

      uchar const * data = (uchar const *)(header+1UL);
      for( ulong i=0UL; i<gui->gossip.peer_cnt; i++ ) {
        int found = 0;
        for( ulong j=0UL; j<peer_cnt; j++ ) {
          if( FD_UNLIKELY( !memcmp( gui->gossip.peers[ i ].pubkey, data+j*(58UL+12UL*6UL), 32UL ) ) ) {
            found = 1;
            break;
          }
        }

        if( FD_UNLIKELY( !found ) ) {
          fd_memcpy( removed[ removed_cnt++ ].uc, gui->gossip.peers[ i ].pubkey->uc, 32UL );
          if( FD_LIKELY( i+1UL!=gui->gossip.peer_cnt ) ) {
            fd_memcpy( &gui->gossip.peers[ i ], &gui->gossip.peers[ gui->gossip.peer_cnt-1UL ], sizeof(struct fd_gui_gossip_peer) );
            gui->gossip.peer_cnt--;
            i--;
          }
        }
      }

      ulong before_peer_cnt = gui->gossip.peer_cnt;
      for( ulong i=0UL; i<peer_cnt; i++ ) {
        int found = 0;
        ulong found_idx;
        for( ulong j=0UL; j<gui->gossip.peer_cnt; j++ ) {
          if( FD_UNLIKELY( !memcmp( gui->gossip.peers[ j ].pubkey, data+i*(58UL+12UL*6UL), 32UL ) ) ) {
            found_idx = j;
            found = 1;
            break;
          }
        }

        if( FD_UNLIKELY( !found ) ) {
          fd_memcpy( gui->gossip.peers[ gui->gossip.peer_cnt ].pubkey->uc, data+i*(58UL+12UL*6UL), 32UL );
          gui->gossip.peers[ gui->gossip.peer_cnt ].wallclock = *(ulong const *)(data+i*(58UL+12UL*6UL)+32UL);
          gui->gossip.peers[ gui->gossip.peer_cnt ].shred_version = *(ushort const *)(data+i*(58UL+12UL*6UL)+40UL);
          gui->gossip.peers[ gui->gossip.peer_cnt ].has_version = *(data+i*(58UL+12UL*6UL)+42UL);
          if( FD_LIKELY( gui->gossip.peers[ gui->gossip.peer_cnt ].has_version ) ) {
            gui->gossip.peers[ gui->gossip.peer_cnt ].version.major = *(ushort const *)(data+i*(58UL+12UL*6UL)+43UL);
            gui->gossip.peers[ gui->gossip.peer_cnt ].version.minor = *(ushort const *)(data+i*(58UL+12UL*6UL)+45UL);
            gui->gossip.peers[ gui->gossip.peer_cnt ].version.patch = *(ushort const *)(data+i*(58UL+12UL*6UL)+47UL);
            gui->gossip.peers[ gui->gossip.peer_cnt ].version.has_commit = *(data+i*(58UL+12UL*6UL)+49UL);
            if( FD_LIKELY( gui->gossip.peers[ gui->gossip.peer_cnt ].version.has_commit ) ) {
              gui->gossip.peers[ gui->gossip.peer_cnt ].version.commit = *(uint const *)(data+i*(58UL+12UL*6UL)+50UL);
            }
            gui->gossip.peers[ gui->gossip.peer_cnt ].version.has_feature_set = *(data+i*(58UL+12UL*6UL)+54UL);
          }

          for( ulong j=0UL; j<12UL; j++ ) {
            gui->gossip.peers[ gui->gossip.peer_cnt ].sockets[ j ].ipv4 = *(uint const *)(data+i*(58UL+12UL*6UL)+58UL+j*6UL);
            gui->gossip.peers[ gui->gossip.peer_cnt ].sockets[ j ].port = *(ushort const *)(data+i*(58UL+12UL*6UL)+58UL+j*6UL+4UL);
          }

          gui->gossip.peer_cnt++;
        } else {
          int peer_updated = gui->gossip.peers[ gui->gossip.peer_cnt ].shred_version!=*(ushort const *)(data+i*(58UL+12UL*6UL)+40UL) ||
                             gui->gossip.peers[ gui->gossip.peer_cnt ].wallclock!=*(ulong const *)(data+i*(58UL+12UL*6UL)+32UL) ||
                             gui->gossip.peers[ gui->gossip.peer_cnt ].has_version!=*(data+i*(58UL+12UL*6UL)+42UL);
          if( FD_LIKELY( !peer_updated && gui->gossip.peers[ gui->gossip.peer_cnt ].has_version ) ) {
            peer_updated = gui->gossip.peers[ gui->gossip.peer_cnt ].version.major!=*(ushort const *)(data+i*(58UL+12UL*6UL)+43UL) ||
                           gui->gossip.peers[ gui->gossip.peer_cnt ].version.minor!=*(ushort const *)(data+i*(58UL+12UL*6UL)+45UL) ||
                           gui->gossip.peers[ gui->gossip.peer_cnt ].version.patch!=*(ushort const *)(data+i*(58UL+12UL*6UL)+47UL) ||
                           gui->gossip.peers[ gui->gossip.peer_cnt ].version.has_commit!=*(data+i*(58UL+12UL*6UL)+49UL) ||
                           (gui->gossip.peers[ gui->gossip.peer_cnt ].version.has_commit && gui->gossip.peers[ gui->gossip.peer_cnt ].version.commit!=*(uint const *)(data+i*(58UL+12UL*6UL)+50UL)) ||
                           gui->gossip.peers[ gui->gossip.peer_cnt ].version.has_feature_set!=*(data+i*(58UL+12UL*6UL)+54UL);

            if( FD_LIKELY( !peer_updated ) ) {
              for( ulong j=0UL; j<12UL; j++ ) {
                peer_updated = gui->gossip.peers[ gui->gossip.peer_cnt ].sockets[ j ].ipv4!=*(uint const *)(data+i*(58UL+12UL*6UL)+58UL+j*6UL) ||
                               gui->gossip.peers[ gui->gossip.peer_cnt ].sockets[ j ].port!=*(ushort const *)(data+i*(58UL+12UL*6UL)+58UL+j*6UL+4UL);
                if( FD_LIKELY( peer_updated ) ) break;
              }
            }
          }

          if( FD_UNLIKELY( peer_updated ) ) {
            updated[ update_cnt++ ] = found_idx;
            gui->gossip.peers[ found_idx ].shred_version = *(ushort const *)(data+i*(58UL+12UL*6UL)+40UL);
            gui->gossip.peers[ found_idx ].wallclock = *(ulong const *)(data+i*(58UL+12UL*6UL)+32UL);
            gui->gossip.peers[ found_idx ].has_version = *(data+i*(58UL+12UL*6UL)+42UL);
            if( FD_LIKELY( gui->gossip.peers[ found_idx ].has_version ) ) {
              gui->gossip.peers[ found_idx ].version.major = *(ushort const *)(data+i*(58UL+12UL*6UL)+43UL);
              gui->gossip.peers[ found_idx ].version.minor = *(ushort const *)(data+i*(58UL+12UL*6UL)+45UL);
              gui->gossip.peers[ found_idx ].version.patch = *(ushort const *)(data+i*(58UL+12UL*6UL)+47UL);
              gui->gossip.peers[ found_idx ].version.has_commit = *(data+i*(58UL+12UL*6UL)+49UL);
              if( FD_LIKELY( gui->gossip.peers[ found_idx ].version.has_commit ) ) {
                gui->gossip.peers[ found_idx ].version.commit = *(uint const *)(data+i*(58UL+12UL*6UL)+50UL);
              }
              gui->gossip.peers[ found_idx ].version.has_feature_set = *(data+i*(58UL+12UL*6UL)+54UL);
            }

            for( ulong j=0UL; j<12UL; j++ ) {
              gui->gossip.peers[ found_idx ].sockets[ j ].ipv4 = *(uint const *)(data+i*(58UL+12UL*6UL)+68UL+j*6UL);
              gui->gossip.peers[ found_idx ].sockets[ j ].port = *(ushort const *)(data+i*(58UL+12UL*6UL)+72UL+j*6UL+2UL);
            }
          }
        }
      }

      ulong message_len;
      const ulong buffer_size = 8192UL;
      char * buffer = fd_alloc_malloc( gui->alloc, 1UL, buffer_size );
      FD_TEST( buffer );
      FD_TEST( fd_cstr_printf_check( buffer, buffer_size, &message_len, "{\n    \"topic\": \"gossip\",\n    \"key\": \"update\",\n    \"value\": {\n        \"add\": [\n" ) );

      for( ulong i=before_peer_cnt; i<gui->gossip.peer_cnt; i++ ) {
        char identity_base58[ FD_BASE58_ENCODED_32_SZ ];
        fd_base58_encode_32( gui->gossip.peers[ i ].pubkey->uc, NULL, identity_base58 );
        ulong line_len;
        FD_TEST( fd_cstr_printf_check( buffer+message_len, buffer_size-message_len, &line_len,
          "            {\n"
          "                \"identity\": \"%s\",\n"
          "                \"version\": \"%u.%u.%u\",\n"
          "                \"feature_set\": \"%u\",\n"
          "                \"wallclock\": \"%lu\",\n"
          "                \"shred_version\": \"%u\",\n"
          "                \"sockets\": {\n",
          identity_base58,
          gui->gossip.peers[ i ].version.major,
          gui->gossip.peers[ i ].version.minor,
          gui->gossip.peers[ i ].version.patch,
          gui->gossip.peers[ i ].version.feature_set,
          gui->gossip.peers[ i ].wallclock,
          gui->gossip.peers[ i ].shred_version ) );
        message_len += line_len;
        for( ulong j=0UL; j<12UL; j++ ) {
          if( FD_LIKELY( !gui->gossip.peers[ i ].sockets[ j ].ipv4 && !gui->gossip.peers[ i ].sockets[ j ].port ) ) continue;
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
          if( FD_UNLIKELY( j==11 ) )
            FD_TEST( fd_cstr_printf_check( buffer+message_len, buffer_size-message_len, &line_len, "                    \"%s\": \"" FD_IP4_ADDR_FMT ":%u\"\n", tag, FD_IP4_ADDR_FMT_ARGS(gui->gossip.peers[ i ].sockets[ j ].ipv4 ), gui->gossip.peers[ i ].sockets[ j ].port ) );
          else
            FD_TEST( fd_cstr_printf_check( buffer+message_len, buffer_size-message_len, &line_len, "                    \"%s\": \"" FD_IP4_ADDR_FMT ":%u\",\n", tag, FD_IP4_ADDR_FMT_ARGS(gui->gossip.peers[ i ].sockets[ j ].ipv4 ), gui->gossip.peers[ i ].sockets[ j ].port ) );
          message_len += line_len;
        }
        if( FD_UNLIKELY( i==gui->gossip.peer_cnt-1UL ) )
          FD_TEST( fd_cstr_printf_check( buffer+message_len, buffer_size-message_len, &line_len, "                }\n            }\n" ) );
        else
          FD_TEST( fd_cstr_printf_check( buffer+message_len, buffer_size-message_len, &line_len, "                }\n            },\n" ) );
        message_len += line_len;
      }

      ulong x_len;
      FD_TEST( fd_cstr_printf_check( buffer+message_len, buffer_size, &x_len, "        ]\n    }\n}\n" ) );
      message_len += x_len;

      fd_http_server_ws_broadcast( gui->server, (uchar const *)buffer, message_len );
      break;

      (void)updated;
    }
    default:
      break;
  }
}
