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
            char const *       identity_key_base58,
            fd_topo_t *        topo ) {
  fd_gui_t * gui = (fd_gui_t *)shmem;
  FD_LOG_NOTICE(( "%s", __func__ ));

  gui->server              = server;
  gui->alloc               = alloc;
  gui->topo                = topo;

  gui->summary.version             = version;
  gui->summary.cluster             = cluster;
  gui->summary.identity_key_base58 = identity_key_base58;

  gui->summary.slot_rooted                   = 0UL;
  gui->summary.slot_optimistically_confirmed = 0UL;
  gui->summary.slot_completed                = 0UL;
  gui->summary.slot_estimated                = 0UL;

  fd_memset( gui->summary.txn_info_prev, 0, sizeof(gui->summary.txn_info_prev[ 0 ]) );
  fd_memset( gui->summary.txn_info_this, 0, sizeof(gui->summary.txn_info_this[ 0 ]) );
  fd_memset( gui->summary.txn_info_json, 0, sizeof(gui->summary.txn_info_json[ 0 ]) );
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
  gui->vote_account.vote_account_cnt = 0UL;
  gui->validator_info.info_cnt = 0UL;

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
  fd_gui_txn_info_t * txn_info = gui->summary.txn_info_json;
  jsonb_open_obj( jsonb, "value" );

  jsonb_ulong( jsonb, "acquired_txns",               txn_info->acquired_txns );

  jsonb_ulong( jsonb, "acquired_txns_leftover",      txn_info->acquired_txns_leftover );
  jsonb_ulong( jsonb, "acquired_txns_quic",          txn_info->acquired_txns_quic );
  jsonb_ulong( jsonb, "acquired_txns_nonquic",       txn_info->acquired_txns_nonquic );
  jsonb_ulong( jsonb, "acquired_txns_gossip",        txn_info->acquired_txns_gossip );

  jsonb_ulong( jsonb, "dropped_txns",                txn_info->dropped_txns );

  jsonb_open_obj( jsonb, "dropped_txns_net" );
  jsonb_ulong( jsonb, "count", txn_info->dropped_txns_net_overrun + txn_info->dropped_txns_net_invalid );
  jsonb_open_obj( jsonb, "breakdown" );
  jsonb_ulong( jsonb, "net_overrun", txn_info->dropped_txns_net_overrun );
  jsonb_ulong( jsonb, "net_invalid", txn_info->dropped_txns_net_invalid );
  jsonb_close_obj( jsonb );
  jsonb_close_obj( jsonb );

  jsonb_open_obj( jsonb, "dropped_txns_quic" );
  jsonb_ulong( jsonb, "count", txn_info->dropped_txns_quic_overrun + txn_info->dropped_txns_quic_reasm );
  jsonb_open_obj( jsonb, "breakdown" );
  jsonb_ulong( jsonb, "quic_overrun", txn_info->dropped_txns_quic_overrun );
  jsonb_ulong( jsonb, "quic_reasm", txn_info->dropped_txns_quic_reasm );
  jsonb_close_obj( jsonb );
  jsonb_close_obj( jsonb );

  jsonb_open_obj( jsonb, "dropped_txns_verify" );
  jsonb_ulong( jsonb, "count", txn_info->dropped_txns_verify_overrun + txn_info->dropped_txns_verify_drop );
  jsonb_open_obj( jsonb, "breakdown" );
  jsonb_ulong( jsonb, "verify_overrun", txn_info->dropped_txns_verify_overrun );
  jsonb_ulong( jsonb, "verify_drop", txn_info->dropped_txns_verify_drop );
  jsonb_close_obj( jsonb );
  jsonb_close_obj( jsonb );

  jsonb_open_obj( jsonb, "dropped_txns_dedup" );
  jsonb_ulong( jsonb, "count", txn_info->dropped_txns_dedup_drop );
  jsonb_open_obj( jsonb, "breakdown" );
  jsonb_ulong( jsonb, "dedup_drop", txn_info->dropped_txns_dedup_drop );
  jsonb_close_obj( jsonb );
  jsonb_close_obj( jsonb );

  jsonb_open_obj( jsonb, "dropped_txns_pack" );
  jsonb_ulong( jsonb, "count", txn_info->dropped_txns_pack_nonleader + txn_info->dropped_txns_pack_invalid + txn_info->dropped_txns_pack_priority );
  jsonb_open_obj( jsonb, "breakdown" );
  jsonb_ulong( jsonb, "pack_nonleader", txn_info->dropped_txns_pack_nonleader );
  jsonb_ulong( jsonb, "pack_invalid", txn_info->dropped_txns_pack_invalid );
  jsonb_ulong( jsonb, "pack_priority", txn_info->dropped_txns_pack_priority );
  jsonb_close_obj( jsonb );
  jsonb_close_obj( jsonb );

  jsonb_open_obj( jsonb, "dropped_txns_bank" );
  jsonb_ulong( jsonb, "count", txn_info->dropped_txns_bank_invalid );
  jsonb_open_obj( jsonb, "breakdown" );
  jsonb_ulong( jsonb, "bank_invalid", txn_info->dropped_txns_bank_invalid );
  jsonb_close_obj( jsonb );
  jsonb_close_obj( jsonb );

  jsonb_ulong( jsonb, "executed_txns_failure", txn_info->executed_txns_failure );
  jsonb_ulong( jsonb, "executed_txns_success", txn_info->executed_txns_success );

  jsonb_ulong( jsonb, "buffered_txns", txn_info->buffered_txns );

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
fd_gui_topology_to_json( fd_gui_t * gui,
                         jsonb_t  * jsonb) {
  fd_gui_topic_key_to_json_init( jsonb, "summary", "topology" );
  jsonb_open_obj( jsonb, "value" );
  jsonb_open_obj( jsonb, "tile_counts" );
  config_t * config = gui->topo->config;
  jsonb_ulong( jsonb, "Networking", config->layout.net_tile_count );
  jsonb_ulong( jsonb, "QUIC", config->layout.quic_tile_count );
  jsonb_ulong( jsonb, "Verify", config->layout.verify_tile_count );
  jsonb_ulong( jsonb, "Dedup", 1UL );
  jsonb_ulong( jsonb, "Pack", 1UL );
  jsonb_ulong( jsonb, "Bank", config->layout.bank_tile_count );
  jsonb_ulong( jsonb, "PoH", 1UL );
  jsonb_ulong( jsonb, "Shred", config->layout.shred_tile_count );
  jsonb_close_obj( jsonb );
  jsonb_close_obj( jsonb );
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
fd_gui_ws_open( fd_gui_t *  gui,
                ulong       conn_id ) {

  jsonb_t * jsonb = gui->jsonb;
  FD_LOG_NOTICE(( "%s", __func__ ));

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

  fd_gui_topology_to_json( gui, jsonb );
  fd_gui_jsonb_send( gui, jsonb, conn_id );

  ulong idx                 = (gui->epoch.max_known_epoch + 1) % FD_GUI_NUM_EPOCHS;
  for ( ulong i=0UL; i < FD_GUI_NUM_EPOCHS; i++ ) {
    fd_gui_epoch_to_json( gui, jsonb, idx );
    fd_gui_jsonb_send( gui, jsonb, conn_id );
    idx = (idx + 1) % FD_GUI_NUM_EPOCHS;
  }

  fd_gui_txn_info_summary_to_json( gui, jsonb );
  fd_gui_jsonb_send( gui, jsonb, conn_id );
}

static void
fd_gui_sample_counters( fd_gui_t * gui, long ts ) {
  // FD_LOG_NOTICE(( "%lu nanos since we last sampled", ts - gui->summary.last_txn_ts ));
  gui->summary.last_txn_ts = ts;

  fd_topo_t * topo      = gui->topo;
  config_t * config     = gui->topo->config;
  fd_gui_txn_info_t * txn_info = gui->summary.txn_info_this;
  ulong net_tile_cnt    = config->layout.net_tile_count;
  ulong quic_tile_cnt   = config->layout.quic_tile_count;
  ulong verify_tile_cnt = config->layout.verify_tile_count;
  ulong bank_tile_cnt   = config->layout.bank_tile_count;

#define FOR(cnt)  for( ulong i=0UL; i<cnt; i++ )
#define FORj(cnt) for( ulong j=0UL; j<cnt; j++ )

  ulong bank_exec = 0UL;
  ulong bank_exec_success = 0UL;
  FOR( bank_tile_cnt ) {
    fd_topo_tile_t const * bank = &topo->tiles[ fd_topo_find_tile( topo, "bank", i ) ];
    ulong * bank_metrics = fd_metrics_tile( bank->metrics );
    bank_exec_success += bank_metrics[ MIDX( COUNTER, BANK_TILE, TRANSACTION_EXECUTED_SUCCESS ) ];
    bank_exec += bank_metrics[ MIDX( COUNTER, BANK_TILE, TRANSACTION_EXECUTING_SUCCESS ) ];
  }
  ulong bank_exec_failure = bank_exec - bank_exec_success;

  fd_topo_tile_t const * pack = &topo->tiles[ fd_topo_find_tile( topo, "pack", 0UL ) ];
  ulong * pack_metrics = fd_metrics_tile( pack->metrics );
  ulong pack_invalid = pack_metrics[ MIDX( COUNTER, PACK, TRANSACTION_INSERTED_WRITE_SYSVAR ) ] +
                        pack_metrics[ MIDX( COUNTER, PACK, TRANSACTION_INSERTED_ESTIMATION_FAIL ) ] +
                        pack_metrics[ MIDX( COUNTER, PACK, TRANSACTION_INSERTED_DUPLICATE_ACCOUNT ) ] +
                        pack_metrics[ MIDX( COUNTER, PACK, TRANSACTION_INSERTED_TOO_MANY_ACCOUNTS ) ] +
                        pack_metrics[ MIDX( COUNTER, PACK, TRANSACTION_INSERTED_TOO_LARGE ) ] +
                        pack_metrics[ MIDX( COUNTER, PACK, TRANSACTION_INSERTED_EXPIRED ) ] +
                        pack_metrics[ MIDX( COUNTER, PACK, TRANSACTION_INSERTED_ADDR_LUT ) ] +
                        pack_metrics[ MIDX( COUNTER, PACK, TRANSACTION_INSERTED_UNAFFORDABLE ) ] +
                        pack_metrics[ MIDX( COUNTER, PACK, TRANSACTION_INSERTED_DUPLICATE ) ] +
                        pack_metrics[ MIDX( COUNTER, PACK, TRANSACTION_EXPIRED ) ];
  ulong pack_nonleader = pack_metrics[ MIDX( COUNTER, PACK, TRANSACTION_DROPPED_FROM_EXTRA ) ];
  ulong pack_priority = pack_metrics[ MIDX( COUNTER, PACK, TRANSACTION_INSERTED_PRIORITY ) ] +
                        pack_metrics[ MIDX( COUNTER, PACK, TRANSACTION_INSERTED_NONVOTE_REPLACE ) ] +
                        pack_metrics[ MIDX( COUNTER, PACK, TRANSACTION_INSERTED_VOTE_REPLACE ) ];
  ulong pack_sent = pack_metrics[ MIDX( COUNTER, PACK, TRANSACTION_SCHEDULE_TAKEN ) ];
  ulong pack_buffered = pack_metrics[ MIDX( GAUGE, PACK, AVAILABLE_TRANSACTIONS ) ] +
                        pack_metrics[ MIDX( COUNTER, PACK, TRANSACTION_INSERTED_TO_EXTRA ) ]-
                        pack_metrics[ MIDX( COUNTER, PACK, TRANSACTION_INSERTED_FROM_EXTRA ) ];

  /* We read bank_exec first, and then pack_sent.  Otherwise, bank_exec
     might be larger than pack_sent by the time we read it, leading to
     an underflow for the subtraction.
     In general, we read values downstream before we read values
     further upstream the TPU pipeline, so subtractions don't
     underflow. */
  ulong bank_invalid = pack_sent - bank_exec;

  fd_topo_tile_t const * dedup = &topo->tiles[ fd_topo_find_tile( topo, "dedup", 0UL ) ];
  ulong * dedup_metrics = fd_metrics_tile( dedup->metrics );
  ulong gossip_recv = dedup_metrics[ MIDX( COUNTER, DEDUP, GOSSIPED_VOTES_RECEIVED ) ];
  ulong dedup_drop = 0UL;
  FOR( verify_tile_cnt ) {
    dedup_drop += fd_metrics_link_in( dedup->metrics, i )[ FD_METRICS_COUNTER_LINK_FILTERED_COUNT_OFF ];
  }

  ulong verify_drop    = 0UL;
  ulong verify_sent    = 0UL;
  ulong verify_overrun = 0UL;
  FOR( verify_tile_cnt ) {
    fd_topo_tile_t const * verify = &topo->tiles[ fd_topo_find_tile( topo, "verify", i ) ];
    FORj( quic_tile_cnt ) {
      verify_overrun += fd_metrics_link_in( verify->metrics, j )[ FD_METRICS_COUNTER_LINK_OVERRUN_POLLING_FRAG_COUNT_OFF ] / verify_tile_cnt;
      verify_overrun += fd_metrics_link_in( verify->metrics, j )[ FD_METRICS_COUNTER_LINK_OVERRUN_READING_FRAG_COUNT_OFF ] / verify_tile_cnt;
      verify_drop += fd_metrics_link_in( verify->metrics, j )[ FD_METRICS_COUNTER_LINK_FILTERED_COUNT_OFF ];
      verify_sent += fd_metrics_link_in( verify->metrics, j )[ FD_METRICS_COUNTER_LINK_PUBLISHED_COUNT_OFF ];
    }
  }

  ulong quic_recv = 0UL;
  ulong quic_sent = 0UL;
  ulong quic_overrun = 0UL;
  FOR( quic_tile_cnt ) {
    fd_topo_tile_t const * quic = &topo->tiles[ fd_topo_find_tile( topo, "quic", i ) ];
    ulong * quic_metrics = fd_metrics_tile( quic->metrics );
    quic_sent += quic_metrics[ MIDX( COUNTER, QUIC_TILE, REASSEMBLY_NOTIFY_OKAY ) ];
    quic_recv += quic_metrics[ MIDX( COUNTER, QUIC_TILE, REASSEMBLY_NOTIFY_ATTEMPTED ) ];
    FORj( net_tile_cnt ) {
      quic_overrun += fd_metrics_link_in( quic->metrics, j )[ FD_METRICS_COUNTER_LINK_OVERRUN_POLLING_FRAG_COUNT_OFF ] / quic_tile_cnt;
      quic_overrun += fd_metrics_link_in( quic->metrics, j )[ FD_METRICS_COUNTER_LINK_OVERRUN_READING_FRAG_COUNT_OFF ] / quic_tile_cnt;
    }
  }
  ulong quic_reasm = quic_recv - quic_sent;

  ulong nonquic_recv = 0UL;
  ulong nonquic_sent = 0UL;
  ulong net_overrun = 0UL; // TODO
  ulong net_invalid = 0UL;
  FOR( quic_tile_cnt ) {
    fd_topo_tile_t const * quic = &topo->tiles[ fd_topo_find_tile( topo, "quic", i ) ];
    ulong * quic_metrics = fd_metrics_tile( quic->metrics );
    net_invalid += quic_metrics[ MIDX( COUNTER, QUIC_TILE, NON_QUIC_PACKET_TOO_SMALL ) ];
    net_invalid += quic_metrics[ MIDX( COUNTER, QUIC_TILE, NON_QUIC_PACKET_TOO_LARGE ) ];
    nonquic_sent += quic_metrics[ MIDX( COUNTER, QUIC_TILE, LEGACY_NOTIFY_OKAY ) ];
    nonquic_recv += quic_metrics[ MIDX( COUNTER, QUIC_TILE, LEGACY_NOTIFY_ATTEMPTED ) ];
    net_invalid += nonquic_recv - nonquic_sent;
  }

  txn_info->acquired_txns_quic = quic_recv + quic_overrun;
  txn_info->acquired_txns_nonquic = nonquic_sent + net_overrun + net_invalid;
  txn_info->acquired_txns_gossip = gossip_recv;
  txn_info->dropped_txns_net_overrun = net_overrun;
  txn_info->dropped_txns_net_invalid = net_invalid;
  txn_info->dropped_txns_quic_overrun = quic_overrun;
  txn_info->dropped_txns_quic_reasm = quic_reasm;
  txn_info->dropped_txns_verify_overrun = verify_overrun;
  txn_info->dropped_txns_verify_drop = verify_drop;
  txn_info->dropped_txns_dedup_drop = dedup_drop;
  txn_info->dropped_txns_pack_nonleader = pack_nonleader;
  txn_info->dropped_txns_pack_invalid = pack_invalid;
  txn_info->dropped_txns_pack_priority = pack_priority;
  txn_info->dropped_txns_bank_invalid = bank_invalid;
  txn_info->executed_txns_failure = bank_exec_failure;
  txn_info->executed_txns_success = bank_exec_success;
  txn_info->dropped_txns = txn_info->dropped_txns_net_overrun +
                          txn_info->dropped_txns_net_invalid +
                          txn_info->dropped_txns_quic_overrun +
                          txn_info->dropped_txns_quic_reasm +
                          txn_info->dropped_txns_verify_overrun +
                          txn_info->dropped_txns_verify_drop +
                          txn_info->dropped_txns_dedup_drop +
                          txn_info->dropped_txns_pack_nonleader +
                          txn_info->dropped_txns_pack_invalid +
                          txn_info->dropped_txns_pack_priority +
                          txn_info->dropped_txns_bank_invalid;
  txn_info->buffered_txns = pack_buffered;

  fd_gui_txn_info_t * txn_info_prev = gui->summary.txn_info_prev;
  fd_gui_txn_info_t * txn_info_json = gui->summary.txn_info_json;
  txn_info_json->acquired_txns_quic = txn_info->acquired_txns_quic - txn_info_prev->acquired_txns_quic;
  txn_info_json->acquired_txns_nonquic = txn_info->acquired_txns_nonquic - txn_info_prev->acquired_txns_nonquic;
  txn_info_json->acquired_txns_gossip = txn_info->acquired_txns_gossip - txn_info_prev->acquired_txns_gossip;
  txn_info_json->dropped_txns = txn_info->dropped_txns - txn_info_prev->dropped_txns;
  txn_info_json->dropped_txns_net_overrun = txn_info->dropped_txns_net_overrun - txn_info_prev->dropped_txns_net_overrun;
  txn_info_json->dropped_txns_net_invalid = txn_info->dropped_txns_net_invalid - txn_info_prev->dropped_txns_net_invalid;
  txn_info_json->dropped_txns_quic_overrun = txn_info->dropped_txns_quic_overrun - txn_info_prev->dropped_txns_quic_overrun;
  txn_info_json->dropped_txns_quic_reasm = txn_info->dropped_txns_quic_reasm - txn_info_prev->dropped_txns_quic_reasm;
  txn_info_json->dropped_txns_verify_overrun = txn_info->dropped_txns_verify_overrun - txn_info_prev->dropped_txns_verify_overrun;
  txn_info_json->dropped_txns_verify_drop = txn_info->dropped_txns_verify_drop - txn_info_prev->dropped_txns_verify_drop;
  txn_info_json->dropped_txns_dedup_drop = txn_info->dropped_txns_dedup_drop - txn_info_prev->dropped_txns_dedup_drop;
  txn_info_json->dropped_txns_pack_nonleader = txn_info->dropped_txns_pack_nonleader - txn_info_prev->dropped_txns_pack_nonleader;
  txn_info_json->dropped_txns_pack_invalid = txn_info->dropped_txns_pack_invalid - txn_info_prev->dropped_txns_pack_invalid;
  txn_info_json->dropped_txns_pack_priority = txn_info->dropped_txns_pack_priority - txn_info_prev->dropped_txns_pack_priority;
  txn_info_json->dropped_txns_bank_invalid = txn_info->dropped_txns_bank_invalid - txn_info_prev->dropped_txns_bank_invalid;
  txn_info_json->executed_txns_failure = txn_info->executed_txns_failure - txn_info_prev->executed_txns_failure;
  txn_info_json->executed_txns_success = txn_info->executed_txns_success - txn_info_prev->executed_txns_success;
  txn_info_json->buffered_txns = txn_info->buffered_txns;
  txn_info_json->acquired_txns = txn_info->acquired_txns_leftover +
                                txn_info->acquired_txns_quic +
                                txn_info->acquired_txns_nonquic +
                                txn_info->acquired_txns_gossip -
                                txn_info_prev->acquired_txns_quic -
                                txn_info_prev->acquired_txns_nonquic -
                                txn_info_prev->acquired_txns_gossip;
  /* Clear numbers that are just underflows due to jitter. */
  ulong * val = fd_type_pun( txn_info_json );
  for( ulong i = 0; i < sizeof(*txn_info_json) / sizeof(*val); i++ ) {
    if( val[i] > ULONG_MAX / 2 ) {
      val[i] = 0;
    }
  }
}

void
fd_gui_poll( fd_gui_t * gui ) {
  // static long last = 0;
  long current = fd_log_wallclock();
  // FD_LOG_NOTICE(( "%lu nanos since we last polled", current - last ));
  // last = current;
  /* Has 100 millis passed since we last collected info? */
  if( current - gui->summary.last_txn_ts <= 100000000 ) return;

  /* Recalculate and publish. */
  fd_gui_sample_counters( gui, current );
  fd_gui_txn_info_summary_to_json( gui, gui->jsonb );
  fd_gui_jsonb_broadcast( gui, gui->jsonb );
  // long done = fd_log_wallclock();
  // FD_LOG_NOTICE(( "fd_gui_poll took %ld nanos", done - current ));
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
fd_gui_publish_peer( fd_gui_t *    gui,
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

  jsonb_open_obj( gui->jsonb, NULL );
  do {
    char identity_base58[ FD_BASE58_ENCODED_32_SZ ];
    fd_base58_encode_32( identity_pubkey, NULL, identity_base58 );
    jsonb_str( gui->jsonb, "identity_pubkey", identity_base58 );

    if( FD_UNLIKELY( gossip_idx==ULONG_MAX ) ) {
      jsonb_str( gui->jsonb, "gossip", NULL );
    } else {
      jsonb_open_obj( gui->jsonb, "gossip" );
      char version[ 32 ];
      FD_TEST( fd_cstr_printf( version, sizeof( version ), NULL, "%u.%u.%u", gui->gossip.peers[ gossip_idx ].version.major, gui->gossip.peers[ gossip_idx ].version.minor, gui->gossip.peers[ gossip_idx ].version.patch ) );
      jsonb_str( gui->jsonb, "version", version );
      jsonb_ulong( gui->jsonb, "feature_set", gui->gossip.peers[ gossip_idx ].version.feature_set );
      jsonb_ulong( gui->jsonb, "wallclock", gui->gossip.peers[ gossip_idx ].wallclock );
      jsonb_ulong( gui->jsonb, "shred_version", gui->gossip.peers[ gossip_idx ].shred_version );
      jsonb_open_obj( gui->jsonb, "sockets" );
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
        jsonb_str( gui->jsonb, tag, line );
      }
      jsonb_close_obj( gui->jsonb );
      jsonb_close_obj( gui->jsonb );
    }
    
    jsonb_open_arr( gui->jsonb, "vote" );
    for( ulong i=0UL; i<vote_idx_cnt; i++ ) {
      jsonb_open_obj( gui->jsonb, NULL );
      char vote_account_base58[ FD_BASE58_ENCODED_32_SZ ];
      fd_base58_encode_32( gui->vote_account.vote_accounts[ vote_idxs[ i ] ].vote_account->uc, NULL, vote_account_base58 );
      jsonb_str( gui->jsonb, "vote_account", vote_account_base58 );
      jsonb_ulong( gui->jsonb, "activated_stake", gui->vote_account.vote_accounts[ vote_idxs[ i ] ].activated_stake );
      jsonb_ulong( gui->jsonb, "last_vote", gui->vote_account.vote_accounts[ vote_idxs[ i ] ].last_vote );
      jsonb_ulong( gui->jsonb, "root_slot", gui->vote_account.vote_accounts[ vote_idxs[ i ] ].root_slot );
      jsonb_ulong( gui->jsonb, "epoch_credits", gui->vote_account.vote_accounts[ vote_idxs[ i ] ].epoch_credits );
      jsonb_ulong( gui->jsonb, "commission", gui->vote_account.vote_accounts[ vote_idxs[ i ] ].commission );
      jsonb_bool( gui->jsonb, "delinquent", gui->vote_account.vote_accounts[ vote_idxs[ i ] ].delinquent );
      jsonb_close_obj( gui->jsonb );
    }
    jsonb_close_arr( gui->jsonb );

    if( FD_UNLIKELY( info_idx==ULONG_MAX ) ) {
      jsonb_str( gui->jsonb, "info", NULL );
    } else {
      jsonb_open_obj( gui->jsonb, "info" );
      jsonb_str( gui->jsonb, "name", gui->validator_info.info[ info_idx ].name );
      jsonb_str( gui->jsonb, "details", gui->validator_info.info[ info_idx ].details );
      jsonb_str( gui->jsonb, "website", gui->validator_info.info[ info_idx ].website );
      jsonb_str( gui->jsonb, "icon_url", gui->validator_info.info[ info_idx ].icon_uri );
      jsonb_close_obj( gui->jsonb );
    }
  } while(0);

  jsonb_close_obj( gui->jsonb );
}

static void
fd_gui_publish_peer_gossip_update( fd_gui_t *          gui,
                                   ulong const *       updated,
                                   ulong               updated_cnt,
                                   fd_pubkey_t const * removed,
                                   ulong               removed_cnt,
                                   ulong const *       added,
                                   ulong               added_cnt ) {
  fd_gui_topic_key_to_json_init( gui->jsonb, "peers", "update" );
  jsonb_open_obj( gui->jsonb, "value" );

  jsonb_open_arr( gui->jsonb, "add" );
  for( ulong i=0UL; i<added_cnt; i++ ) {
    int actually_added = !fd_gui_vote_acct_contains( gui, gui->gossip.peers[ added[ i ] ].pubkey->uc ) &&
                         !fd_gui_validator_info_contains( gui, gui->gossip.peers[ added[ i ] ].pubkey->uc );
    if( FD_LIKELY( !actually_added ) ) continue;

    fd_gui_publish_peer( gui, gui->gossip.peers[ added[ i ] ].pubkey->uc );
  }
  jsonb_close_arr( gui->jsonb );

  jsonb_open_arr( gui->jsonb, "update" );
  for( ulong i=0UL; i<added_cnt; i++ ) {
    int actually_added = !fd_gui_vote_acct_contains( gui, gui->gossip.peers[ added[ i ] ].pubkey->uc ) &&
                         !fd_gui_validator_info_contains( gui, gui->gossip.peers[ added[ i ] ].pubkey->uc );
    if( FD_LIKELY( actually_added ) ) continue;

    fd_gui_publish_peer( gui, gui->gossip.peers[ added[ i ] ].pubkey->uc );
  }
  for( ulong i=0UL; i<updated_cnt; i++ ) {
    fd_gui_publish_peer( gui, gui->gossip.peers[ updated[ i ] ].pubkey->uc );
  }
  jsonb_close_arr( gui->jsonb );

  jsonb_open_arr( gui->jsonb, "remove" );
  for( ulong i=0UL; i<removed_cnt; i++ ) {
    int actually_removed = !fd_gui_vote_acct_contains( gui, removed[ i ].uc ) &&
                           !fd_gui_validator_info_contains( gui, removed[ i ].uc );
    if( FD_UNLIKELY( !actually_removed ) ) continue;

    jsonb_open_obj( gui->jsonb, NULL );
    char identity_base58[ FD_BASE58_ENCODED_32_SZ ];
    fd_base58_encode_32( removed[ i ].uc, NULL, identity_base58 );
    jsonb_str( gui->jsonb, "identity_pubkey", identity_base58 );
    jsonb_close_obj( gui->jsonb );
  }
  jsonb_close_arr( gui->jsonb );

  jsonb_close_obj( gui->jsonb );

  fd_gui_topic_key_to_json_fini( gui->jsonb );

  fd_gui_jsonb_broadcast( gui, gui->jsonb );
}

static void
fd_gui_publish_peer_vote_account_update( fd_gui_t *          gui,
                                         ulong const *       updated,
                                         ulong               updated_cnt,
                                         fd_pubkey_t const * removed,
                                         ulong               removed_cnt,
                                         ulong const *       added,
                                         ulong               added_cnt ) {
  fd_gui_topic_key_to_json_init( gui->jsonb, "peers", "update" );
  jsonb_open_obj( gui->jsonb, "value" );

  jsonb_open_arr( gui->jsonb, "add" );
  for( ulong i=0UL; i<added_cnt; i++ ) {
    int actually_added = !fd_gui_gossip_contains( gui, gui->vote_account.vote_accounts[ added[ i ] ].pubkey->uc ) &&
                         !fd_gui_validator_info_contains( gui, gui->vote_account.vote_accounts[ added[ i ] ].pubkey->uc );
    if( FD_LIKELY( !actually_added ) ) continue;

    fd_gui_publish_peer( gui, gui->vote_account.vote_accounts[ added[ i ] ].pubkey->uc );
  }
  jsonb_close_arr( gui->jsonb );

  jsonb_open_arr( gui->jsonb, "update" );
  for( ulong i=0UL; i<added_cnt; i++ ) {
    int actually_added = !fd_gui_gossip_contains( gui, gui->vote_account.vote_accounts[ added[ i ] ].pubkey->uc ) &&
                         !fd_gui_validator_info_contains( gui, gui->vote_account.vote_accounts[ added[ i ] ].pubkey->uc );
    if( FD_LIKELY( actually_added ) ) continue;

    fd_gui_publish_peer( gui, gui->vote_account.vote_accounts[ added[ i ] ].pubkey->uc );
  }
  for( ulong i=0UL; i<updated_cnt; i++ ) {
    fd_gui_publish_peer( gui, gui->vote_account.vote_accounts[ updated[ i ] ].pubkey->uc );
  }
  jsonb_close_arr( gui->jsonb );

  jsonb_open_arr( gui->jsonb, "remove" );
  for( ulong i=0UL; i<removed_cnt; i++ ) {
    int actually_removed = !fd_gui_gossip_contains( gui, gui->vote_account.vote_accounts[ added[ i ] ].pubkey->uc ) &&
                           !fd_gui_validator_info_contains( gui, gui->vote_account.vote_accounts[ added[ i ] ].pubkey->uc );
    if( FD_UNLIKELY( !actually_removed ) ) continue;

    jsonb_open_obj( gui->jsonb, NULL );
    char identity_base58[ FD_BASE58_ENCODED_32_SZ ];
    fd_base58_encode_32( removed[ i ].uc, NULL, identity_base58 );
    jsonb_str( gui->jsonb, "identity_pubkey", identity_base58 );
    jsonb_close_obj( gui->jsonb );
  }
  jsonb_close_arr( gui->jsonb );

  jsonb_close_obj( gui->jsonb );

  fd_gui_topic_key_to_json_fini( gui->jsonb );

  fd_gui_jsonb_broadcast( gui, gui->jsonb );
}

static void
fd_gui_publish_peer_validator_info_update( fd_gui_t *          gui,
                                           ulong const *       updated,
                                           ulong               updated_cnt,
                                           fd_pubkey_t const * removed,
                                           ulong               removed_cnt,
                                           ulong const *       added,
                                           ulong               added_cnt ) {
  fd_gui_topic_key_to_json_init( gui->jsonb, "peers", "update" );
  jsonb_open_obj( gui->jsonb, "value" );

  jsonb_open_arr( gui->jsonb, "add" );
  for( ulong i=0UL; i<added_cnt; i++ ) {
    int actually_added = !fd_gui_gossip_contains( gui, gui->validator_info.info[ added[ i ] ].pubkey->uc ) &&
                         !fd_gui_vote_acct_contains( gui, gui->validator_info.info[ added[ i ] ].pubkey->uc );
    if( FD_LIKELY( !actually_added ) ) continue;

    fd_gui_publish_peer( gui, gui->validator_info.info[ added[ i ] ].pubkey->uc );
  }
  jsonb_close_arr( gui->jsonb );

  jsonb_open_arr( gui->jsonb, "update" );
  for( ulong i=0UL; i<added_cnt; i++ ) {
    int actually_added = !fd_gui_gossip_contains( gui, gui->validator_info.info[ added[ i ] ].pubkey->uc ) &&
                         !fd_gui_vote_acct_contains( gui, gui->validator_info.info[ added[ i ] ].pubkey->uc );
    if( FD_LIKELY( actually_added ) ) continue;

    fd_gui_publish_peer( gui, gui->validator_info.info[ added[ i ] ].pubkey->uc );
  }
  for( ulong i=0UL; i<updated_cnt; i++ ) {
    fd_gui_publish_peer( gui, gui->validator_info.info[ updated[ i ] ].pubkey->uc );
  }
  jsonb_close_arr( gui->jsonb );

  jsonb_open_arr( gui->jsonb, "remove" );
  for( ulong i=0UL; i<removed_cnt; i++ ) {
    int actually_removed = !fd_gui_gossip_contains( gui, gui->validator_info.info[ added[ i ] ].pubkey->uc ) &&
                           !fd_gui_vote_acct_contains( gui, gui->validator_info.info[ added[ i ] ].pubkey->uc );
    if( FD_UNLIKELY( !actually_removed ) ) continue;

    jsonb_open_obj( gui->jsonb, NULL );
    char identity_base58[ FD_BASE58_ENCODED_32_SZ ];
    fd_base58_encode_32( removed[ i ].uc, NULL, identity_base58 );
    jsonb_str( gui->jsonb, "identity_pubkey", identity_base58 );
    jsonb_close_obj( gui->jsonb );
  }
  jsonb_close_arr( gui->jsonb );

  jsonb_close_obj( gui->jsonb );

  fd_gui_topic_key_to_json_fini( gui->jsonb );

  fd_gui_jsonb_broadcast( gui, gui->jsonb );
}

static void
fd_gui_handle_gossip_update( fd_gui_t *    gui,
                             uchar const * msg ) {
  ulong const * header = (ulong const *)fd_type_pun_const( msg );
  ulong peer_cnt = header[ 0 ];

  ulong added_cnt = 0UL;
  ulong added[ 40200 ] = {0};

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
        gui->gossip.peers[ gui->gossip.peer_cnt ].version.feature_set = *(uint const *)(data+i*(58UL+12UL*6UL)+54UL);
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
                        gui->gossip.peers[ gui->gossip.peer_cnt ].version.feature_set!=*(uint const *)(data+i*(58UL+12UL*6UL)+54UL);

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
          gui->gossip.peers[ gui->gossip.peer_cnt ].version.feature_set = *(uint const *)(data+i*(58UL+12UL*6UL)+54UL);
        }

        for( ulong j=0UL; j<12UL; j++ ) {
          gui->gossip.peers[ found_idx ].sockets[ j ].ipv4 = *(uint const *)(data+i*(58UL+12UL*6UL)+58UL+j*6UL);
          gui->gossip.peers[ found_idx ].sockets[ j ].port = *(ushort const *)(data+i*(58UL+12UL*6UL)+58UL+j*6UL+4UL);
        }
      }
    }
  }

  added_cnt = gui->gossip.peer_cnt - before_peer_cnt;
  for( ulong i=before_peer_cnt; i<gui->gossip.peer_cnt; i++ ) added[ i-before_peer_cnt ] = i;

  fd_gui_publish_peer_gossip_update( gui, updated, update_cnt, removed, removed_cnt, added, added_cnt );
}

static void
fd_gui_handle_vote_account_update( fd_gui_t *    gui,
                                   uchar const * msg ) {
  ulong const * header = (ulong const *)fd_type_pun_const( msg );
  ulong peer_cnt = header[ 0 ];

  ulong added_cnt = 0UL;
  ulong added[ 40200 ] = {0};

  ulong update_cnt = 0UL;
  ulong updated[ 40200 ] = {0};

  ulong removed_cnt = 0UL;
  fd_pubkey_t removed[ 40200 ] = {0};

  uchar const * data = (uchar const *)(header+1UL);
  for( ulong i=0UL; i<gui->vote_account.vote_account_cnt; i++ ) {
    int found = 0;
    for( ulong j=0UL; j<peer_cnt; j++ ) {
      if( FD_UNLIKELY( !memcmp( gui->vote_account.vote_accounts[ i ].vote_account, data+j*112UL, 32UL ) ) ) {
        found = 1;
        break;
      }
    }

    if( FD_UNLIKELY( !found ) ) {
      fd_memcpy( removed[ removed_cnt++ ].uc, gui->vote_account.vote_accounts[ i ].vote_account->uc, 32UL );
      if( FD_LIKELY( i+1UL!=gui->vote_account.vote_account_cnt ) ) {
        fd_memcpy( &gui->vote_account.vote_accounts[ i ], &gui->vote_account.vote_accounts[ gui->vote_account.vote_account_cnt-1UL ], sizeof(struct fd_gui_vote_account) );
        gui->vote_account.vote_account_cnt--;
        i--;
      }
    }
  }

  ulong before_peer_cnt = gui->vote_account.vote_account_cnt;
  for( ulong i=0UL; i<peer_cnt; i++ ) {
    int found = 0;
    ulong found_idx;
    for( ulong j=0UL; j<gui->vote_account.vote_account_cnt; j++ ) {
      if( FD_UNLIKELY( !memcmp( gui->vote_account.vote_accounts[ j ].vote_account, data+i*112UL, 32UL ) ) ) {
        found_idx = j;
        found = 1;
        break;
      }
    }

    if( FD_UNLIKELY( !found ) ) {
      fd_memcpy( gui->vote_account.vote_accounts[ gui->vote_account.vote_account_cnt ].vote_account->uc, data+i*112UL, 32UL );
      fd_memcpy( gui->vote_account.vote_accounts[ gui->vote_account.vote_account_cnt ].pubkey->uc, data+i*112UL+32UL, 32UL );

      gui->vote_account.vote_accounts[ gui->vote_account.vote_account_cnt ].activated_stake = *(ulong const *)(data+i*112UL+64UL);
      gui->vote_account.vote_accounts[ gui->vote_account.vote_account_cnt ].last_vote = *(ulong const *)(data+i*112UL+72UL);
      gui->vote_account.vote_accounts[ gui->vote_account.vote_account_cnt ].root_slot = *(ulong const *)(data+i*112UL+80UL);
      gui->vote_account.vote_accounts[ gui->vote_account.vote_account_cnt ].epoch_credits = *(ulong const *)(data+i*112UL+88UL);
      gui->vote_account.vote_accounts[ gui->vote_account.vote_account_cnt ].commission = *(data+i*112UL+96UL);
      gui->vote_account.vote_accounts[ gui->vote_account.vote_account_cnt ].delinquent = *(data+i*112UL+97UL);

      gui->vote_account.vote_account_cnt++;
    } else {
      int peer_updated =
        memcmp( gui->vote_account.vote_accounts[ gui->vote_account.vote_account_cnt ].pubkey->uc, data+i*112UL+32UL, 32UL ) ||
        gui->vote_account.vote_accounts[ gui->vote_account.vote_account_cnt ].activated_stake != *(ulong const *)(data+i*112UL+64UL) ||
        gui->vote_account.vote_accounts[ gui->vote_account.vote_account_cnt ].last_vote       != *(ulong const *)(data+i*112UL+72UL) ||
        gui->vote_account.vote_accounts[ gui->vote_account.vote_account_cnt ].root_slot       != *(ulong const *)(data+i*112UL+80UL) ||
        gui->vote_account.vote_accounts[ gui->vote_account.vote_account_cnt ].epoch_credits   != *(ulong const *)(data+i*112UL+88UL) ||
        gui->vote_account.vote_accounts[ gui->vote_account.vote_account_cnt ].commission      != *(data+i*112UL+96UL) ||
        gui->vote_account.vote_accounts[ gui->vote_account.vote_account_cnt ].delinquent      != *(data+i*112UL+97UL);

      if( FD_UNLIKELY( peer_updated ) ) {
        updated[ update_cnt++ ] = found_idx;

        fd_memcpy( gui->vote_account.vote_accounts[ found_idx ].pubkey->uc, data+i*112UL+32UL, 32UL );
        gui->vote_account.vote_accounts[ found_idx ].activated_stake = *(ulong const *)(data+i*112UL+64UL);
        gui->vote_account.vote_accounts[ found_idx ].last_vote = *(ulong const *)(data+i*112UL+72UL);
        gui->vote_account.vote_accounts[ found_idx ].root_slot = *(ulong const *)(data+i*112UL+80UL);
        gui->vote_account.vote_accounts[ found_idx ].epoch_credits = *(ulong const *)(data+i*112UL+88UL);
        gui->vote_account.vote_accounts[ found_idx ].commission = *(data+i*112UL+96UL);
        gui->vote_account.vote_accounts[ found_idx ].delinquent = *(data+i*112UL+97UL);
      }
    }
  }

  added_cnt = gui->vote_account.vote_account_cnt - before_peer_cnt;
  for( ulong i=before_peer_cnt; i<gui->vote_account.vote_account_cnt; i++ ) added[ i-before_peer_cnt ] = i;

  fd_gui_publish_peer_vote_account_update( gui, updated, update_cnt, removed, removed_cnt, added, added_cnt );
}

static void
fd_gui_handle_validator_info_update( fd_gui_t *    gui,
                                     uchar const * msg ) {
  ulong const * header = (ulong const *)fd_type_pun_const( msg );
  ulong peer_cnt = header[ 0 ];

  ulong added_cnt = 0UL;
  ulong added[ 40200 ] = {0};

  ulong update_cnt = 0UL;
  ulong updated[ 40200 ] = {0};

  ulong removed_cnt = 0UL;
  fd_pubkey_t removed[ 40200 ] = {0};

  uchar const * data = (uchar const *)(header+1UL);
  for( ulong i=0UL; i<gui->validator_info.info_cnt; i++ ) {
    int found = 0;
    for( ulong j=0UL; j<peer_cnt; j++ ) {
      if( FD_UNLIKELY( !memcmp( gui->validator_info.info[ i ].pubkey, data+j*608UL, 32UL ) ) ) {
        found = 1;
        break;
      }
    }

    if( FD_UNLIKELY( !found ) ) {
      fd_memcpy( removed[ removed_cnt++ ].uc, gui->validator_info.info[ i ].pubkey->uc, 32UL );
      if( FD_LIKELY( i+1UL!=gui->validator_info.info_cnt ) ) {
        fd_memcpy( &gui->validator_info.info[ i ], &gui->validator_info.info[ gui->validator_info.info_cnt-1UL ], sizeof(struct fd_gui_validator_info) );
        gui->validator_info.info_cnt--;
        i--;
      }
    }
  }

  ulong before_peer_cnt = gui->validator_info.info_cnt;
  for( ulong i=0UL; i<peer_cnt; i++ ) {
    int found = 0;
    ulong found_idx;
    for( ulong j=0UL; j<gui->validator_info.info_cnt; j++ ) {
      if( FD_UNLIKELY( !memcmp( gui->validator_info.info[ j ].pubkey, data+i*608UL, 32UL ) ) ) {
        found_idx = j;
        found = 1;
        break;
      }
    }

    if( FD_UNLIKELY( !found ) ) {
      fd_memcpy( gui->validator_info.info[ gui->validator_info.info_cnt ].pubkey->uc, data+i*608UL, 32UL );

      strncpy( gui->validator_info.info[ gui->validator_info.info_cnt ].name, (char const *)(data+i*608UL+32UL), 64 );
      gui->validator_info.info[ gui->validator_info.info_cnt ].name[ 63 ] = '\0';

      strncpy( gui->validator_info.info[ gui->validator_info.info_cnt ].website, (char const *)(data+i*608UL+96UL), 128 );
      gui->validator_info.info[ gui->validator_info.info_cnt ].website[ 127 ] = '\0';

      strncpy( gui->validator_info.info[ gui->validator_info.info_cnt ].details, (char const *)(data+i*608UL+224UL), 256 );
      gui->validator_info.info[ gui->validator_info.info_cnt ].details[ 255 ] = '\0';

      strncpy( gui->validator_info.info[ gui->validator_info.info_cnt ].icon_uri, (char const *)(data+i*608UL+480UL), 128 );
      gui->validator_info.info[ gui->validator_info.info_cnt ].icon_uri[ 127 ] = '\0';

      gui->validator_info.info_cnt++;
    } else {
      int peer_updated =
        memcmp( gui->validator_info.info[ gui->validator_info.info_cnt ].pubkey->uc, data+i*608UL, 32UL ) ||
        strncmp( gui->validator_info.info[ gui->validator_info.info_cnt ].name, (char const *)(data+i*608UL+32UL), 64 ) ||
        strncmp( gui->validator_info.info[ gui->validator_info.info_cnt ].website, (char const *)(data+i*608UL+96UL), 128 ) ||
        strncmp( gui->validator_info.info[ gui->validator_info.info_cnt ].details, (char const *)(data+i*608UL+224UL), 256 ) ||
        strncmp( gui->validator_info.info[ gui->validator_info.info_cnt ].icon_uri, (char const *)(data+i*608UL+480UL), 128 );

      if( FD_UNLIKELY( peer_updated ) ) {
        updated[ update_cnt++ ] = found_idx;

        fd_memcpy( gui->validator_info.info[ gui->validator_info.info_cnt ].pubkey->uc, data+i*608UL, 32UL );

        strncpy( gui->validator_info.info[ gui->validator_info.info_cnt ].name, (char const *)(data+i*608UL+32UL), 64 );
        gui->validator_info.info[ gui->validator_info.info_cnt ].name[ 63 ] = '\0';

        strncpy( gui->validator_info.info[ gui->validator_info.info_cnt ].website, (char const *)(data+i*608UL+96UL), 128 );
        gui->validator_info.info[ gui->validator_info.info_cnt ].website[ 127 ] = '\0';

        strncpy( gui->validator_info.info[ gui->validator_info.info_cnt ].details, (char const *)(data+i*608UL+224UL), 256 );
        gui->validator_info.info[ gui->validator_info.info_cnt ].details[ 255 ] = '\0';

        strncpy( gui->validator_info.info[ gui->validator_info.info_cnt ].icon_uri, (char const *)(data+i*608UL+480UL), 128 );
        gui->validator_info.info[ gui->validator_info.info_cnt ].icon_uri[ 127 ] = '\0';
      }
    }
  }

  added_cnt = gui->validator_info.info_cnt - before_peer_cnt;
  for( ulong i=before_peer_cnt; i<gui->validator_info.info_cnt; i++ ) added[ i-before_peer_cnt ] = i;

  fd_gui_publish_peer_validator_info_update( gui, updated, update_cnt, removed, removed_cnt, added, added_cnt );
}

void
fd_gui_plugin_message( fd_gui_t *    gui,
                       ulong         plugin_msg,
                       uchar const * msg,
                       ulong         msg_len ) {
  (void)msg_len;
  jsonb_t * jsonb = gui->jsonb;
  FD_LOG_NOTICE(( "%s", __func__ ));

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
      fd_stake_weight_t const * stakes = fd_type_pun_const( hdr+5UL );
      for( ulong i=0UL; i<staked_cnt; i++ ) {
        if( stakes[ i ].stake==0UL ) FD_LOG_ERR(( "BAD STAKE: %lu", i ));
      }
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
    case FD_PLUGIN_MSG_BECAME_LEADER: {
      // static long last_became = 0;
      // long current_became = fd_log_wallclock();
      // FD_LOG_NOTICE(( "%lu nanos since we last became leader txn_info_json->acquired_txns %lu", current_became - last_became, gui->summary.txn_info_json->acquired_txns ));
      // last_became = current_became;
      fd_gui_txn_info_t * txn_info = gui->summary.txn_info_this;
      fd_gui_sample_counters( gui, fd_log_wallclock() );
      fd_memcpy( gui->summary.txn_info_prev, txn_info, sizeof(gui->summary.txn_info_prev[ 0 ]) );
      fd_memset( txn_info, 0, sizeof(*txn_info) );
      txn_info->acquired_txns_leftover = gui->summary.txn_info_prev->buffered_txns;
      break;
    }
    case FD_PLUGIN_MSG_GOSSIP_UPDATE: {
      fd_gui_handle_gossip_update( gui, msg );
      break;
    }
    case FD_PLUGIN_MSG_VOTE_ACCOUNT_UPDATE: {
      fd_gui_handle_vote_account_update( gui, msg );
      break;
    }
    case FD_PLUGIN_MSG_VALIDATOR_INFO: {
      fd_gui_handle_validator_info_update( gui, msg );
      break;
    }
    default:
      FD_LOG_ERR(( "Unhandled plugin msg: %lu", plugin_msg ));
      break;
  }
}
