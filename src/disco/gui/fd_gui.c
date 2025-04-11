#include "fd_gui.h"
#include "fd_gui_printf.h"

#include "../metrics/fd_metrics.h"
#include "../plugin/fd_plugin.h"

#include "../../ballet/base58/fd_base58.h"
#include "../../ballet/json/cJSON.h"
#include "../../flamenco/genesis/fd_genesis_cluster.h"

#define SORT_NAME        fd_sort_gui_gossip_peer
#define SORT_KEY_T       fd_gui_gossip_peer_t
#define SORT_BEFORE(a,b) memcmp( a.pubkey, b.pubkey, 32UL )<0
#include "../../util/tmpl/fd_sort.c"

#define SORT_NAME        fd_sort_gui_vote_account
#define SORT_KEY_T       fd_gui_vote_account_t
#define SORT_BEFORE(a,b) memcmp( a.vote_account, b.vote_account, 32UL )<0
#include "../../util/tmpl/fd_sort.c"

#define SORT_NAME        fd_sort_gui_validator_info
#define SORT_KEY_T       fd_gui_validator_info_t
#define SORT_BEFORE(a,b) memcmp( a.pubkey, b.pubkey, 32UL )<0
#include "../../util/tmpl/fd_sort.c"

#define SORT_NAME        fd_sort_gui_pubkey
#define SORT_KEY_T       fd_pubkey_t
#define SORT_BEFORE(a,b) memcmp( &(a), &(b), 32UL )<0
#include "../../util/tmpl/fd_sort.c"

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
            fd_http_server_t * http,
            char const *       version,
            char const *       cluster,
            uchar const *      identity_key,
            int                is_voting,
            fd_topo_t *        topo ) {

  if( FD_UNLIKELY( !shmem ) ) {
    FD_LOG_WARNING(( "NULL shmem" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shmem, fd_gui_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned shmem" ));
    return NULL;
  }

  if( FD_UNLIKELY( topo->tile_cnt>FD_GUI_TILE_TIMER_TILE_CNT ) ) {
    FD_LOG_WARNING(( "too many tiles" ));
    return NULL;
  }

  fd_gui_t * gui = (fd_gui_t *)shmem;

  gui->http = http;
  gui->topo = topo;

  gui->debug_in_leader_slot = ULONG_MAX;


  gui->next_sample_400millis = fd_log_wallclock();
  gui->next_sample_100millis = gui->next_sample_400millis;
  gui->next_sample_10millis  = gui->next_sample_400millis;

  fd_memcpy( gui->summary.identity_key->uc, identity_key, 32UL );
  fd_base58_encode_32( identity_key, NULL, gui->summary.identity_key_base58 );
  gui->summary.identity_key_base58[ FD_BASE58_ENCODED_32_SZ-1UL ] = '\0';

  gui->summary.version            = version;
  gui->summary.cluster            = cluster;
  gui->summary.startup_time_nanos = gui->next_sample_400millis;

  gui->summary.startup_progress                       = FD_GUI_START_PROGRESS_TYPE_INITIALIZING;
  gui->summary.startup_got_full_snapshot              = 0;
  gui->summary.startup_full_snapshot_slot             = 0;
  gui->summary.startup_incremental_snapshot_slot      = 0;
  gui->summary.startup_waiting_for_supermajority_slot = ULONG_MAX;

  gui->summary.identity_account_balance      = 0UL;
  gui->summary.vote_account_balance          = 0UL;
  gui->summary.estimated_slot_duration_nanos = 0UL;

  gui->summary.vote_distance = 0UL;
  gui->summary.vote_state = is_voting ? FD_GUI_VOTE_STATE_VOTING : FD_GUI_VOTE_STATE_NON_VOTING;

  gui->summary.sock_tile_cnt   = fd_topo_tile_name_cnt( gui->topo, "sock"   );
  gui->summary.net_tile_cnt    = fd_topo_tile_name_cnt( gui->topo, "net"    );
  gui->summary.quic_tile_cnt   = fd_topo_tile_name_cnt( gui->topo, "quic"   );
  gui->summary.verify_tile_cnt = fd_topo_tile_name_cnt( gui->topo, "verify" );
  gui->summary.resolv_tile_cnt = fd_topo_tile_name_cnt( gui->topo, "resolv" );
  gui->summary.bank_tile_cnt   = fd_topo_tile_name_cnt( gui->topo, "bank"   );
  gui->summary.shred_tile_cnt  = fd_topo_tile_name_cnt( gui->topo, "shred"  );

  gui->summary.slot_rooted                   = 0UL;
  gui->summary.slot_optimistically_confirmed = 0UL;
  gui->summary.slot_completed                = 0UL;
  gui->summary.slot_estimated                = 0UL;

  gui->summary.estimated_tps_history_idx = 0UL;
  memset( gui->summary.estimated_tps_history, 0, sizeof(gui->summary.estimated_tps_history) );

  memset( gui->summary.txn_waterfall_reference, 0, sizeof(gui->summary.txn_waterfall_reference) );
  memset( gui->summary.txn_waterfall_current,   0, sizeof(gui->summary.txn_waterfall_current) );

  memset( gui->summary.tile_stats_reference, 0, sizeof(gui->summary.tile_stats_reference) );
  memset( gui->summary.tile_stats_current, 0, sizeof(gui->summary.tile_stats_current) );

  memset( gui->summary.tile_timers_snap[ 0 ], 0, sizeof(gui->summary.tile_timers_snap[ 0 ]) );
  memset( gui->summary.tile_timers_snap[ 1 ], 0, sizeof(gui->summary.tile_timers_snap[ 1 ]) );
  gui->summary.tile_timers_snap_idx    = 2UL;
  gui->summary.tile_timers_history_idx = 0UL;
  for( ulong i=0UL; i<FD_GUI_TILE_TIMER_LEADER_CNT; i++ ) gui->summary.tile_timers_leader_history_slot[ i ] = ULONG_MAX;

  gui->cus.offset = 0UL;

  gui->block_engine.has_block_engine = 0;

  gui->epoch.has_epoch[ 0 ] = 0;
  gui->epoch.has_epoch[ 1 ] = 0;
  gui->epoch.has_epoch[ 2 ] = 0;

  gui->peers_cnt                     = 0UL;
  gui->gossip.peer_cnt               = 0UL;
  gui->vote_account.vote_account_cnt = 0UL;
  gui->validator_info.info_cnt       = 0UL;

  for( ulong i=0UL; i<FD_GUI_SLOTS_CNT; i++ ) gui->slots[ i ]->slot = ULONG_MAX;

  /* add self to frontend peers array */
  fd_memcpy( gui->peers, gui->summary.identity_key->uc, 32UL );
  gui->peers_cnt++;

  return gui;
}

fd_gui_t *
fd_gui_join( void * shmem ) {
  return (fd_gui_t *)shmem;
}

/* fd_gui_*_contains functions check if the provided pubkey is in the
   set of peers designated by the function name.  They return the index
   into a corresponding buffer of peer objects or ULONG_MAX if a match
   is not found.

   Peer arrays must be sorted any time they are updated, otherwise these
   functions may return incorrect results. */

static ulong
fd_gui_gossip_contains( fd_gui_t const * gui,
                        uchar const *    pubkey ) {
  fd_gui_gossip_peer_t query;
  fd_memcpy( query.pubkey, pubkey, 32UL );
  ulong pubkey_idx = fd_sort_gui_gossip_peer_search_geq( gui->gossip.peers, gui->gossip.peer_cnt, query );

  if( FD_UNLIKELY( !memcmp( gui->gossip.peers[ pubkey_idx ].pubkey->uc, pubkey, 32UL ) ) ) return pubkey_idx;
  else                                                                                     return ULONG_MAX;
}

static ulong
fd_gui_vote_acct_contains( fd_gui_t const * gui,
                           uchar const *    pubkey ) {
  fd_gui_vote_account_t query;
  fd_memcpy( query.vote_account, pubkey, 32UL );
  ulong pubkey_idx = fd_sort_gui_vote_account_search_geq( gui->vote_account.vote_accounts, gui->vote_account.vote_account_cnt, query );

  if( FD_UNLIKELY( !memcmp( gui->vote_account.vote_accounts[ pubkey_idx ].vote_account->uc, pubkey, 32UL ) ) ) return pubkey_idx;
  else                                                                                                         return ULONG_MAX;
}

static ulong
fd_gui_validator_info_contains( fd_gui_t const * gui,
                                uchar const *    pubkey ) {
  fd_gui_validator_info_t query;
  fd_memcpy( query.pubkey, pubkey, 32UL );
  ulong pubkey_idx = fd_sort_gui_validator_info_search_geq( gui->validator_info.info, gui->validator_info.info_cnt, query );

  if( FD_UNLIKELY( !memcmp( gui->validator_info.info[ pubkey_idx ].pubkey->uc, pubkey, 32UL ) ) ) return pubkey_idx;
  else                                                                                            return ULONG_MAX;
}

static ulong
fd_gui_frontend_peers_contains( fd_gui_t const * gui,
                                uchar const *    pubkey ) {
  ulong pubkey_idx = fd_sort_gui_pubkey_search_geq( gui->peers, gui->peers_cnt, *(fd_pubkey_t const *)fd_type_pun_const( pubkey ) );

  if( FD_UNLIKELY( !memcmp( gui->peers[ pubkey_idx ].uc, pubkey, 32UL ) ) ) return pubkey_idx;
  else                                                                      return ULONG_MAX;
}

/* fd_gui_staked_nodes_contains_current_epoch returns true if pubkey is
   a staked validator for the current epoch. */

int
fd_gui_staked_nodes_contains_current_epoch( fd_gui_t const * gui,
                                            uchar const *    pubkey ) {
  /* The "current" epoch should be the second largest one stored in our
     history. */
  ulong largest_idx = ULONG_MAX, second_largest_idx = ULONG_MAX;
  ulong largest_epoch = 0, second_largest_epoch = 0;

  for( ulong i=0UL; i < 3UL; i++ ) {
      if (!gui->epoch.has_epoch[ i ]) continue;
      ulong epoch = gui->epoch.epochs[i].epoch;
      if (epoch > largest_epoch) {
          second_largest_idx = largest_idx;
          second_largest_epoch = largest_epoch;
          largest_idx = i;
          largest_epoch = epoch;
      } else if (epoch > second_largest_epoch) {
          second_largest_idx = i;
          second_largest_epoch = epoch;
      }
  }

  if( FD_UNLIKELY( ULONG_MAX==largest_idx && ULONG_MAX==second_largest_idx ) ) return 0;
  ulong cur_epoch_idx = fd_ulong_if( ULONG_MAX!=second_largest_idx, second_largest_idx, largest_idx );
  ulong pubkey_idx = fd_sort_gui_pubkey_search_geq( gui->epoch.epochs[ cur_epoch_idx ].stakes_sorted, gui->epoch.epochs[ cur_epoch_idx ].lsched->pub_cnt, *(fd_pubkey_t const *)fd_type_pun_const( pubkey ) );
  return fd_memeq( gui->epoch.epochs[ cur_epoch_idx ].stakes_sorted[ pubkey_idx ].uc, pubkey, 32UL );
}

/* fd_gui_staked_nodes_contains returns true if pubkey is is a staked
   validator for the current, previous, or next epoch. */

static int
fd_gui_staked_nodes_contains( fd_gui_t const * gui,
                              uchar const *    pubkey ) {
  for (ulong i=0UL; i<3UL; i++) {
    if( FD_UNLIKELY( !gui->epoch.has_epoch[ i ] ) ) continue;
    ulong pubkey_idx = fd_sort_gui_pubkey_search_geq( gui->epoch.epochs[ i ].stakes_sorted, gui->epoch.epochs[ i ].lsched->pub_cnt, *(fd_pubkey_t const *)fd_type_pun_const( pubkey ) );
    if( FD_UNLIKELY( !memcmp( gui->epoch.epochs[ i ].stakes_sorted[ pubkey_idx ].uc, pubkey, 32UL ) ) ) return 1;
  }

  return 0;
}

/* A peer is sendable to the frontend only if it falls into any of these
  categories:
  - has active stake in the current epoch
  - had active stake in the previous epoch
  - will have active stake in the next epoch
  - is this validator

  We determine that a node is an rpc node if it has at least one vote
  account and its also has zero vote accounts with active stake this
  epoch. */

static int
fd_gui_send_to_frontend( fd_gui_t const * gui,
                         uchar const *    pubkey ) {
  if( FD_UNLIKELY( fd_gui_staked_nodes_contains( gui, pubkey ) ) )            return 1;
  if( FD_UNLIKELY( !memcmp( gui->summary.identity_key->uc, pubkey, 32UL ) ) ) return 1;

  return 0;
}

/* fd_gui_modify_frontend_peers is a helper that updates the `peers`
   array which tracks peers that have been added to the frontend but
   not removed. It leaves the array sorted so that it can be correcly
   searched. */

static void
fd_gui_modify_frontend_peers( fd_gui_t *          gui,
                              ulong const         peer_cnt,
                              fd_pubkey_t const * peers,
                              ulong const *       action ) {
  for( ulong i=0UL; i<peer_cnt; i++) {
    switch (action[ i ]) {
      case FD_GUI_PEERS_ACTION_ADD:
        fd_memcpy( gui->peers[ gui->peers_cnt++ ].uc, peers[ i ].uc, 32UL );
        break;
      case FD_GUI_PEERS_ACTION_UPDATE:
        break;
      case FD_GUI_PEERS_ACTION_REMOVE:
        for( ulong j=0UL; j<gui->peers_cnt; j++) {
          if( FD_UNLIKELY( fd_memeq( gui->peers[ j ].uc, peers[ i ].uc, 32UL ) ) ) {
            fd_memcpy( gui->peers[ j ].uc, gui->peers[ gui->peers_cnt-1UL ].uc, 32UL );
            gui->peers_cnt--;
            break;
          }
        }
        break;
      default:
        FD_LOG_ERR(( "Unexpected action %lu", action[ i ] ));
    }
  }

  fd_sort_gui_pubkey_insert( gui->peers, gui->peers_cnt );
}

void
fd_gui_set_identity( fd_gui_t *    gui,
                     uchar const * identity_pubkey ) {
  if( FD_UNLIKELY( fd_memeq( gui->summary.identity_key->uc, identity_pubkey, 32UL ) ) ) return;

  ulong action[ 2 ] = { FD_GUI_PEERS_ACTION_ADD, FD_GUI_PEERS_ACTION_REMOVE };
  fd_pubkey_t modified[ 2 ];
  fd_memcpy( modified, identity_pubkey, 32UL );
  fd_memcpy( modified+1, gui->summary.identity_key->uc, 32UL );

  fd_memcpy( gui->summary.identity_key->uc, identity_pubkey, 32UL );
  fd_base58_encode_32( identity_pubkey, NULL, gui->summary.identity_key_base58 );
  gui->summary.identity_key_base58[ FD_BASE58_ENCODED_32_SZ-1UL ] = '\0';

  fd_gui_printf_identity_key( gui );
  fd_http_server_ws_broadcast( gui->http );

  fd_gui_modify_frontend_peers( gui, 2UL, modified, action );
  fd_gui_printf_peers         ( gui, 2UL, modified, action );
  fd_http_server_ws_broadcast( gui->http );

}

void
fd_gui_ws_open( fd_gui_t * gui,
                ulong      ws_conn_id ) {
  void (* printers[] )( fd_gui_t * gui ) = {
    fd_gui_printf_startup_progress,
    fd_gui_printf_version,
    fd_gui_printf_cluster,
    fd_gui_printf_commit_hash,
    fd_gui_printf_identity_key,
    fd_gui_printf_uptime_nanos,
    fd_gui_printf_vote_state,
    fd_gui_printf_vote_distance,
    fd_gui_printf_skipped_history,
    fd_gui_printf_tps_history,
    fd_gui_printf_tiles,
    fd_gui_printf_identity_balance,
    fd_gui_printf_vote_balance,
    fd_gui_printf_estimated_slot_duration_nanos,
    fd_gui_printf_root_slot,
    fd_gui_printf_optimistically_confirmed_slot,
    fd_gui_printf_completed_slot,
    fd_gui_printf_estimated_slot,
    fd_gui_printf_live_tile_timers,
    fd_gui_printf_rpc_count,
  };

  ulong printers_len = sizeof(printers) / sizeof(printers[0]);
  for( ulong i=0UL; i<printers_len; i++ ) {
    printers[ i ]( gui );
    FD_TEST( !fd_http_server_ws_send( gui->http, ws_conn_id ) );
  }

  if( FD_LIKELY( gui->block_engine.has_block_engine ) ) {
    fd_gui_printf_block_engine( gui );
    FD_TEST( !fd_http_server_ws_send( gui->http, ws_conn_id ) );
  }

  ulong epoch_prev = fd_ulong_min( fd_ulong_min( gui->epoch.epochs[ 0 ].epoch, gui->epoch.epochs[ 1 ].epoch ), gui->epoch.epochs[ 2 ].epoch );
  ulong epoch_count = (ulong)(gui->epoch.has_epoch[ 0 ] + gui->epoch.has_epoch[ 1 ] + gui->epoch.has_epoch[ 2 ]);

  for( ulong i=0UL; i<3UL; i++ ) {
    /* we don't send the previous epoch */
    if( FD_UNLIKELY( epoch_count==3UL && epoch_prev==gui->epoch.epochs[ i ].epoch ) ) continue;
    if( FD_LIKELY( gui->epoch.has_epoch[ i ] ) ) {
      fd_gui_printf_skip_rate( gui, i );
      FD_TEST( !fd_http_server_ws_send( gui->http, ws_conn_id ) );
      fd_gui_printf_epoch( gui, i );
      FD_TEST( !fd_http_server_ws_send( gui->http, ws_conn_id ) );
    }
  }

  ulong action[ FD_GUI_MAX_GOSSIP_PEERS ];
  for( ulong i = 0UL; i<gui->peers_cnt; i++ ) action[ i ] = FD_GUI_PEERS_ACTION_ADD;
  fd_gui_printf_peers( gui, gui->peers_cnt, gui->peers, action );
  FD_TEST( !fd_http_server_ws_send( gui->http, ws_conn_id ) );
}

static void
fd_gui_tile_timers_snap( fd_gui_t * gui ) {
  fd_gui_tile_timers_t * cur = gui->summary.tile_timers_snap[ gui->summary.tile_timers_snap_idx ];
  gui->summary.tile_timers_snap_idx = (gui->summary.tile_timers_snap_idx+1UL)%FD_GUI_TILE_TIMER_SNAP_CNT;
  for( ulong i=0UL; i<gui->topo->tile_cnt; i++ ) {
    fd_topo_tile_t * tile = &gui->topo->tiles[ i ];
    if ( FD_UNLIKELY( !tile->metrics ) ) {
      /* bench tiles might not have been booted initially.
         This check shouldn't be necessary if all tiles barrier after boot. */
      // TODO(FIXME) this probably isn't the right fix but it makes fddev bench work for now
      return;
    }
    volatile ulong const * tile_metrics = fd_metrics_tile( tile->metrics );

    cur[ i ].caughtup_housekeeping_ticks     = tile_metrics[ MIDX( COUNTER, TILE, REGIME_DURATION_NANOS_CAUGHT_UP_HOUSEKEEPING ) ];
    cur[ i ].processing_housekeeping_ticks   = tile_metrics[ MIDX( COUNTER, TILE, REGIME_DURATION_NANOS_PROCESSING_HOUSEKEEPING ) ];
    cur[ i ].backpressure_housekeeping_ticks = tile_metrics[ MIDX( COUNTER, TILE, REGIME_DURATION_NANOS_BACKPRESSURE_HOUSEKEEPING ) ];
    cur[ i ].caughtup_prefrag_ticks          = tile_metrics[ MIDX( COUNTER, TILE, REGIME_DURATION_NANOS_CAUGHT_UP_PREFRAG ) ];
    cur[ i ].processing_prefrag_ticks        = tile_metrics[ MIDX( COUNTER, TILE, REGIME_DURATION_NANOS_PROCESSING_PREFRAG ) ];
    cur[ i ].backpressure_prefrag_ticks      = tile_metrics[ MIDX( COUNTER, TILE, REGIME_DURATION_NANOS_BACKPRESSURE_PREFRAG ) ];
    cur[ i ].caughtup_postfrag_ticks         = tile_metrics[ MIDX( COUNTER, TILE, REGIME_DURATION_NANOS_CAUGHT_UP_POSTFRAG ) ];
    cur[ i ].processing_postfrag_ticks       = tile_metrics[ MIDX( COUNTER, TILE, REGIME_DURATION_NANOS_PROCESSING_POSTFRAG ) ];
  }
}

static void
fd_gui_estimated_tps_snap( fd_gui_t * gui ) {
  ulong total_txn_cnt          = 0UL;
  ulong vote_txn_cnt           = 0UL;
  ulong nonvote_failed_txn_cnt = 0UL;

  for( ulong i=0UL; i<fd_ulong_min( gui->summary.slot_completed+1UL, FD_GUI_SLOTS_CNT ); i++ ) {
    ulong _slot = gui->summary.slot_completed-i;
    fd_gui_slot_t * slot = gui->slots[ _slot % FD_GUI_SLOTS_CNT ];
    if( FD_UNLIKELY( slot->slot==ULONG_MAX || slot->slot!=_slot ) ) break; /* Slot no longer exists, no TPS. */
    if( FD_UNLIKELY( slot->completed_time==LONG_MAX ) ) continue; /* Slot is on this fork but was never completed, must have been in root path on boot. */
    if( FD_UNLIKELY( slot->completed_time+FD_GUI_TPS_HISTORY_WINDOW_DURATION_SECONDS*1000L*1000L*1000L<gui->next_sample_400millis ) ) break; /* Slot too old. */
    if( FD_UNLIKELY( slot->skipped ) ) continue; /* Skipped slots don't count to TPS. */

    total_txn_cnt          += slot->total_txn_cnt;
    vote_txn_cnt           += slot->vote_txn_cnt;
    nonvote_failed_txn_cnt += slot->nonvote_failed_txn_cnt;
  }

  gui->summary.estimated_tps_history[ gui->summary.estimated_tps_history_idx ][ 0 ] = total_txn_cnt;
  gui->summary.estimated_tps_history[ gui->summary.estimated_tps_history_idx ][ 1 ] = vote_txn_cnt;
  gui->summary.estimated_tps_history[ gui->summary.estimated_tps_history_idx ][ 2 ] = nonvote_failed_txn_cnt;
  gui->summary.estimated_tps_history_idx = (gui->summary.estimated_tps_history_idx+1UL) % FD_GUI_TPS_HISTORY_SAMPLE_CNT;
}

/* Snapshot all of the data from metrics to construct a view of the
   transaction waterfall.

   Tiles are sampled in reverse pipeline order: this helps prevent data
   discrepancies where a later tile has "seen" more transactions than an
   earlier tile, which shouldn't typically happen. */

static void
fd_gui_txn_waterfall_snap( fd_gui_t *               gui,
                           fd_gui_txn_waterfall_t * cur ) {
  fd_topo_t * topo = gui->topo;

  cur->out.block_success = 0UL;
  cur->out.block_fail    = 0UL;

  cur->out.bank_invalid = 0UL;
  for( ulong i=0UL; i<gui->summary.bank_tile_cnt; i++ ) {
    fd_topo_tile_t const * bank = &topo->tiles[ fd_topo_find_tile( topo, "bank", i ) ];

    volatile ulong const * bank_metrics = fd_metrics_tile( bank->metrics );

    cur->out.block_success += bank_metrics[ MIDX( COUNTER, BANK, SUCCESSFUL_TRANSACTIONS ) ];

    cur->out.block_fail +=
        bank_metrics[ MIDX( COUNTER, BANK, EXECUTED_FAILED_TRANSACTIONS ) ]
      + bank_metrics[ MIDX( COUNTER, BANK, FEE_ONLY_TRANSACTIONS        ) ];

    cur->out.bank_invalid +=
        bank_metrics[ MIDX( COUNTER, BANK, TRANSACTION_LOAD_ADDRESS_TABLES_SLOT_HASHES_SYSVAR_NOT_FOUND ) ]
      + bank_metrics[ MIDX( COUNTER, BANK, TRANSACTION_LOAD_ADDRESS_TABLES_ACCOUNT_NOT_FOUND ) ]
      + bank_metrics[ MIDX( COUNTER, BANK, TRANSACTION_LOAD_ADDRESS_TABLES_INVALID_ACCOUNT_OWNER ) ]
      + bank_metrics[ MIDX( COUNTER, BANK, TRANSACTION_LOAD_ADDRESS_TABLES_INVALID_ACCOUNT_DATA ) ]
      + bank_metrics[ MIDX( COUNTER, BANK, TRANSACTION_LOAD_ADDRESS_TABLES_INVALID_INDEX ) ];

    cur->out.bank_invalid +=
        bank_metrics[ MIDX( COUNTER, BANK, PROCESSING_FAILED ) ]
      + bank_metrics[ MIDX( COUNTER, BANK, PRECOMPILE_VERIFY_FAILURE ) ];
  }


  fd_topo_tile_t const * pack = &topo->tiles[ fd_topo_find_tile( topo, "pack", 0UL ) ];
  volatile ulong const * pack_metrics = fd_metrics_tile( pack->metrics );

  cur->out.pack_invalid =
      pack_metrics[ MIDX( COUNTER, PACK, TRANSACTION_DROPPED_PARTIAL_BUNDLE ) ]
    + pack_metrics[ MIDX( COUNTER, PACK, TRANSACTION_INSERTED_BUNDLE_BLACKLIST ) ]
    + pack_metrics[ MIDX( COUNTER, PACK, TRANSACTION_INSERTED_WRITE_SYSVAR ) ]
    + pack_metrics[ MIDX( COUNTER, PACK, TRANSACTION_INSERTED_ESTIMATION_FAIL ) ]
    + pack_metrics[ MIDX( COUNTER, PACK, TRANSACTION_INSERTED_DUPLICATE_ACCOUNT ) ]
    + pack_metrics[ MIDX( COUNTER, PACK, TRANSACTION_INSERTED_TOO_MANY_ACCOUNTS ) ]
    + pack_metrics[ MIDX( COUNTER, PACK, TRANSACTION_INSERTED_TOO_LARGE ) ]
    + pack_metrics[ MIDX( COUNTER, PACK, TRANSACTION_INSERTED_ADDR_LUT ) ]
    + pack_metrics[ MIDX( COUNTER, PACK, TRANSACTION_INSERTED_UNAFFORDABLE ) ]
    + pack_metrics[ MIDX( COUNTER, PACK, TRANSACTION_INSERTED_DUPLICATE ) ];

  cur->out.pack_expired = pack_metrics[ MIDX( COUNTER, PACK, TRANSACTION_INSERTED_EXPIRED ) ] +
                          pack_metrics[ MIDX( COUNTER, PACK, TRANSACTION_EXPIRED ) ];

  cur->out.pack_leader_slow =
      pack_metrics[ MIDX( COUNTER, PACK, TRANSACTION_INSERTED_PRIORITY ) ]
    + pack_metrics[ MIDX( COUNTER, PACK, TRANSACTION_INSERTED_NONVOTE_REPLACE ) ]
    + pack_metrics[ MIDX( COUNTER, PACK, TRANSACTION_INSERTED_VOTE_REPLACE ) ];

  cur->out.pack_wait_full =
      pack_metrics[ MIDX( COUNTER, PACK, TRANSACTION_DROPPED_FROM_EXTRA ) ];

  cur->out.pack_retained = pack_metrics[ MIDX( GAUGE, PACK, AVAILABLE_TRANSACTIONS ) ];

  ulong inserted_to_extra = pack_metrics[ MIDX( COUNTER, PACK, TRANSACTION_INSERTED_TO_EXTRA ) ];
  ulong inserted_from_extra = pack_metrics[ MIDX( COUNTER, PACK, TRANSACTION_INSERTED_FROM_EXTRA ) ]
                              + pack_metrics[ MIDX( COUNTER, PACK, TRANSACTION_DROPPED_FROM_EXTRA ) ];
  cur->out.pack_retained += fd_ulong_if( inserted_to_extra>=inserted_from_extra, inserted_to_extra-inserted_from_extra, 0UL );

  cur->out.resolv_lut_failed = 0UL;
  cur->out.resolv_expired    = 0UL;
  cur->out.resolv_ancient    = 0UL;
  cur->out.resolv_no_ledger  = 0UL;
  cur->out.resolv_retained   = 0UL;
  for( ulong i=0UL; i<gui->summary.resolv_tile_cnt; i++ ) {
    fd_topo_tile_t const * resolv = &topo->tiles[ fd_topo_find_tile( topo, "resolv", i ) ];
    volatile ulong const * resolv_metrics = fd_metrics_tile( resolv->metrics );

    cur->out.resolv_no_ledger += resolv_metrics[ MIDX( COUNTER, RESOLV, NO_BANK_DROP ) ];
    cur->out.resolv_expired += resolv_metrics[ MIDX( COUNTER, RESOLV, BLOCKHASH_EXPIRED ) ]
                                + resolv_metrics[ MIDX( COUNTER, RESOLV, TRANSACTION_BUNDLE_PEER_FAILURE  ) ];
    cur->out.resolv_lut_failed += resolv_metrics[ MIDX( COUNTER, RESOLV, LUT_RESOLVED_ACCOUNT_NOT_FOUND ) ]
                                + resolv_metrics[ MIDX( COUNTER, RESOLV, LUT_RESOLVED_INVALID_ACCOUNT_OWNER ) ]
                                + resolv_metrics[ MIDX( COUNTER, RESOLV, LUT_RESOLVED_INVALID_ACCOUNT_DATA ) ]
                                + resolv_metrics[ MIDX( COUNTER, RESOLV, LUT_RESOLVED_ACCOUNT_UNINITIALIZED ) ]
                                + resolv_metrics[ MIDX( COUNTER, RESOLV, LUT_RESOLVED_INVALID_LOOKUP_INDEX ) ];
    cur->out.resolv_ancient += resolv_metrics[ MIDX( COUNTER, RESOLV, STASH_OPERATION_OVERRUN ) ];

    ulong inserted_to_resolv = resolv_metrics[ MIDX( COUNTER, RESOLV, STASH_OPERATION_INSERTED ) ];
    ulong removed_from_resolv = resolv_metrics[ MIDX( COUNTER, RESOLV, STASH_OPERATION_OVERRUN ) ]
                              + resolv_metrics[ MIDX( COUNTER, RESOLV, STASH_OPERATION_PUBLISHED ) ]
                              + resolv_metrics[ MIDX( COUNTER, RESOLV, STASH_OPERATION_REMOVED ) ];
    cur->out.resolv_retained += fd_ulong_if( inserted_to_resolv>=removed_from_resolv, inserted_to_resolv-removed_from_resolv, 0UL );
  }


  fd_topo_tile_t const * dedup = &topo->tiles[ fd_topo_find_tile( topo, "dedup", 0UL ) ];
  volatile ulong const * dedup_metrics = fd_metrics_tile( dedup->metrics );

  cur->out.dedup_duplicate = dedup_metrics[ MIDX( COUNTER, DEDUP, TRANSACTION_DEDUP_FAILURE ) ]
                           + dedup_metrics[ MIDX( COUNTER, DEDUP, TRANSACTION_BUNDLE_PEER_FAILURE ) ];


  cur->out.verify_overrun   = 0UL;
  cur->out.verify_duplicate = 0UL;
  cur->out.verify_parse     = 0UL;
  cur->out.verify_failed    = 0UL;

  for( ulong i=0UL; i<gui->summary.verify_tile_cnt; i++ ) {
    fd_topo_tile_t const * verify = &topo->tiles[ fd_topo_find_tile( topo, "verify", i ) ];
    volatile ulong const * verify_metrics = fd_metrics_tile( verify->metrics );

    for( ulong j=0UL; j<gui->summary.quic_tile_cnt; j++ ) {
      /* TODO: Not precise... even if 1 frag gets skipped, it could have been for this verify tile. */
      cur->out.verify_overrun += fd_metrics_link_in( verify->metrics, j )[ FD_METRICS_COUNTER_LINK_OVERRUN_POLLING_FRAG_COUNT_OFF ] / gui->summary.verify_tile_cnt;
      cur->out.verify_overrun += fd_metrics_link_in( verify->metrics, j )[ FD_METRICS_COUNTER_LINK_OVERRUN_READING_FRAG_COUNT_OFF ];
    }

    cur->out.verify_failed    += verify_metrics[ MIDX( COUNTER, VERIFY, TRANSACTION_VERIFY_FAILURE ) ] +
                                 verify_metrics[ MIDX( COUNTER, VERIFY, TRANSACTION_BUNDLE_PEER_FAILURE ) ];
    cur->out.verify_parse     += verify_metrics[ MIDX( COUNTER, VERIFY, TRANSACTION_PARSE_FAILURE ) ];
    cur->out.verify_duplicate += verify_metrics[ MIDX( COUNTER, VERIFY, TRANSACTION_DEDUP_FAILURE ) ];
  }


  cur->out.quic_overrun      = 0UL;
  cur->out.quic_frag_drop    = 0UL;
  cur->out.quic_abandoned    = 0UL;
  cur->out.tpu_quic_invalid  = 0UL;
  cur->out.tpu_udp_invalid   = 0UL;
  for( ulong i=0UL; i<gui->summary.quic_tile_cnt; i++ ) {
    fd_topo_tile_t const * quic = &topo->tiles[ fd_topo_find_tile( topo, "quic", i ) ];
    volatile ulong * quic_metrics = fd_metrics_tile( quic->metrics );

    cur->out.tpu_udp_invalid  += quic_metrics[ MIDX( COUNTER, QUIC, LEGACY_TXN_UNDERSZ      ) ];
    cur->out.tpu_udp_invalid  += quic_metrics[ MIDX( COUNTER, QUIC, LEGACY_TXN_OVERSZ       ) ];
    cur->out.tpu_quic_invalid += quic_metrics[ MIDX( COUNTER, QUIC, PKT_UNDERSZ             ) ];
    cur->out.tpu_quic_invalid += quic_metrics[ MIDX( COUNTER, QUIC, PKT_OVERSZ              ) ];
    cur->out.tpu_quic_invalid += quic_metrics[ MIDX( COUNTER, QUIC, TXN_OVERSZ              ) ];
    cur->out.tpu_quic_invalid += quic_metrics[ MIDX( COUNTER, QUIC, PKT_CRYPTO_FAILED       ) ];
    cur->out.tpu_quic_invalid += quic_metrics[ MIDX( COUNTER, QUIC, PKT_NO_CONN             ) ];
    cur->out.tpu_quic_invalid += quic_metrics[ MIDX( COUNTER, QUIC, PKT_NET_HEADER_INVALID  ) ];
    cur->out.tpu_quic_invalid += quic_metrics[ MIDX( COUNTER, QUIC, PKT_QUIC_HEADER_INVALID ) ];
    cur->out.quic_abandoned   += quic_metrics[ MIDX( COUNTER, QUIC, TXNS_ABANDONED          ) ];
    cur->out.quic_frag_drop   += quic_metrics[ MIDX( COUNTER, QUIC, TXNS_OVERRUN            ) ];

    for( ulong j=0UL; j<gui->summary.net_tile_cnt; j++ ) {
      /* TODO: Not precise... net frags that were skipped might not have been destined for QUIC tile */
      /* TODO: Not precise... even if 1 frag gets skipped, it could have been for this QUIC tile */
      cur->out.quic_overrun += fd_metrics_link_in( quic->metrics, j )[ FD_METRICS_COUNTER_LINK_OVERRUN_POLLING_FRAG_COUNT_OFF ] / gui->summary.quic_tile_cnt;
      cur->out.quic_overrun += fd_metrics_link_in( quic->metrics, j )[ FD_METRICS_COUNTER_LINK_OVERRUN_READING_FRAG_COUNT_OFF ];
    }
  }

  cur->out.net_overrun = 0UL;
  for( ulong i=0UL; i<gui->summary.net_tile_cnt; i++ ) {
    fd_topo_tile_t const * net = &topo->tiles[ fd_topo_find_tile( topo, "net", i ) ];
    volatile ulong * net_metrics = fd_metrics_tile( net->metrics );

    cur->out.net_overrun += net_metrics[ MIDX( COUNTER, NET, XDP_RX_RING_FULL ) ];
    cur->out.net_overrun += net_metrics[ MIDX( COUNTER, NET, XDP_RX_DROPPED_OTHER ) ];
    cur->out.net_overrun += net_metrics[ MIDX( COUNTER, NET, XDP_RX_FILL_RING_EMPTY_DESCS ) ];
  }

  ulong bundle_txns_received = 0UL;
  ulong bundle_tile_idx = fd_topo_find_tile( topo, "bundle", 0UL );
  if( FD_LIKELY( bundle_tile_idx!=ULONG_MAX ) ) {
    fd_topo_tile_t const * bundle = &topo->tiles[ bundle_tile_idx ];
    volatile ulong const * bundle_metrics = fd_metrics_tile( bundle->metrics );

    bundle_txns_received = bundle_metrics[ MIDX( COUNTER, BUNDLE, TRANSACTION_RECEIVED ) ];
  }

  cur->in.pack_cranked = pack_metrics[ MIDX( COUNTER, PACK, BUNDLE_CRANK_STATUS_INSERTED ) ];
  cur->in.gossip   = dedup_metrics[ MIDX( COUNTER, DEDUP, GOSSIPED_VOTES_RECEIVED ) ];
  cur->in.quic     = cur->out.tpu_quic_invalid +
                     cur->out.quic_overrun +
                     cur->out.quic_frag_drop +
                     cur->out.quic_abandoned +
                     cur->out.net_overrun;
  cur->in.udp      = cur->out.tpu_udp_invalid;
  cur->in.block_engine = bundle_txns_received;
  for( ulong i=0UL; i<gui->summary.quic_tile_cnt; i++ ) {
    fd_topo_tile_t const * quic = &topo->tiles[ fd_topo_find_tile( topo, "quic", i ) ];
    volatile ulong * quic_metrics = fd_metrics_tile( quic->metrics );

    cur->in.quic += quic_metrics[ MIDX( COUNTER, QUIC, TXNS_RECEIVED_QUIC_FAST ) ];
    cur->in.quic += quic_metrics[ MIDX( COUNTER, QUIC, TXNS_RECEIVED_QUIC_FRAG ) ];
    cur->in.udp  += quic_metrics[ MIDX( COUNTER, QUIC, TXNS_RECEIVED_UDP       ) ];
  }
}

static void
fd_gui_tile_stats_snap( fd_gui_t *                     gui,
                        fd_gui_txn_waterfall_t const * waterfall,
                        fd_gui_tile_stats_t *          stats ) {
  fd_topo_t const * topo = gui->topo;

  stats->sample_time_nanos = fd_log_wallclock();

  stats->net_in_rx_bytes  = 0UL;
  stats->net_out_tx_bytes = 0UL;
  for( ulong i=0UL; i<gui->summary.net_tile_cnt; i++ ) {
    fd_topo_tile_t const * net = &topo->tiles[ fd_topo_find_tile( topo, "net", i ) ];
    volatile ulong * net_metrics = fd_metrics_tile( net->metrics );

    stats->net_in_rx_bytes  += net_metrics[ MIDX( COUNTER, NET, RX_BYTES_TOTAL ) ];
    stats->net_out_tx_bytes += net_metrics[ MIDX( COUNTER, NET, TX_BYTES_TOTAL ) ];
  }

  for( ulong i=0UL; i<gui->summary.sock_tile_cnt; i++ ) {
    fd_topo_tile_t const * sock = &topo->tiles[ fd_topo_find_tile( topo, "sock", i ) ];
    volatile ulong * sock_metrics = fd_metrics_tile( sock->metrics );

    stats->net_in_rx_bytes  += sock_metrics[ MIDX( COUNTER, SOCK, RX_BYTES_TOTAL ) ];
    stats->net_out_tx_bytes += sock_metrics[ MIDX( COUNTER, SOCK, TX_BYTES_TOTAL ) ];
  }

  stats->quic_conn_cnt = 0UL;
  for( ulong i=0UL; i<gui->summary.quic_tile_cnt; i++ ) {
    fd_topo_tile_t const * quic = &topo->tiles[ fd_topo_find_tile( topo, "quic", i ) ];
    volatile ulong * quic_metrics = fd_metrics_tile( quic->metrics );

    stats->quic_conn_cnt += quic_metrics[ MIDX( GAUGE, QUIC, CONNECTIONS_ACTIVE ) ];
  }

  stats->verify_drop_cnt = waterfall->out.verify_duplicate +
                           waterfall->out.verify_parse +
                           waterfall->out.verify_failed;
  stats->verify_total_cnt = waterfall->in.gossip +
                            waterfall->in.quic +
                            waterfall->in.udp -
                            waterfall->out.net_overrun -
                            waterfall->out.tpu_quic_invalid -
                            waterfall->out.tpu_udp_invalid -
                            waterfall->out.quic_abandoned -
                            waterfall->out.quic_frag_drop -
                            waterfall->out.quic_overrun -
                            waterfall->out.verify_overrun;
  stats->dedup_drop_cnt = waterfall->out.dedup_duplicate;
  stats->dedup_total_cnt = stats->verify_total_cnt -
                           waterfall->out.verify_duplicate -
                            waterfall->out.verify_parse -
                            waterfall->out.verify_failed;

  fd_topo_tile_t const * pack  = &topo->tiles[ fd_topo_find_tile( topo, "pack", 0UL ) ];
  volatile ulong const * pack_metrics = fd_metrics_tile( pack->metrics );
  stats->pack_buffer_cnt      = pack_metrics[ MIDX( GAUGE, PACK, AVAILABLE_TRANSACTIONS ) ];
  stats->pack_buffer_capacity = pack->pack.max_pending_transactions;

  stats->bank_txn_exec_cnt = waterfall->out.block_fail + waterfall->out.block_success;
}

int
fd_gui_poll( fd_gui_t * gui ) {
  long now = fd_log_wallclock();

  int did_work = 0;

  if( FD_LIKELY( now>gui->next_sample_400millis ) ) {
    fd_gui_estimated_tps_snap( gui );
    fd_gui_printf_estimated_tps( gui );
    fd_http_server_ws_broadcast( gui->http );

    gui->next_sample_400millis += 400L*1000L*1000L;
    did_work = 1;
  }

  if( FD_LIKELY( now>gui->next_sample_100millis ) ) {
    fd_gui_txn_waterfall_snap( gui, gui->summary.txn_waterfall_current );
    fd_gui_printf_live_txn_waterfall( gui, gui->summary.txn_waterfall_reference, gui->summary.txn_waterfall_current, 0UL /* TODO: REAL NEXT LEADER SLOT */ );
    fd_http_server_ws_broadcast( gui->http );

    fd_memcpy( gui->summary.tile_stats_reference, gui->summary.tile_stats_current, sizeof(struct fd_gui_tile_stats) );
    fd_gui_tile_stats_snap( gui, gui->summary.txn_waterfall_current, gui->summary.tile_stats_current );
    fd_gui_printf_live_tile_stats( gui, gui->summary.tile_stats_reference, gui->summary.tile_stats_current );
    fd_http_server_ws_broadcast( gui->http );

    gui->next_sample_100millis += 100L*1000L*1000L;
    did_work = 1;
  }

  if( FD_LIKELY( now>gui->next_sample_10millis ) ) {
    fd_gui_tile_timers_snap( gui );

    fd_gui_printf_live_tile_timers( gui );
    fd_http_server_ws_broadcast( gui->http );

    gui->next_sample_10millis += 10L*1000L*1000L;
    did_work = 1;
  }

  return did_work;
}

static void
fd_gui_parse_gossip_peer_msg( fd_gui_gossip_peer_t * peer, uchar const * data ) {
  fd_memcpy( peer->pubkey->uc, data, 32UL );
  peer->wallclock = *(ulong const *)(data+32UL);
  peer->shred_version = *(ushort const *)(data+40UL);
  peer->has_version = *(data+42UL);
  if( FD_LIKELY( peer->has_version ) ) {
    peer->version.major = *(ushort const *)(data+43UL);
    peer->version.minor = *(ushort const *)(data+45UL);
    peer->version.patch = *(ushort const *)(data+47UL);
    peer->version.has_commit = *(data+49UL);
    if( FD_LIKELY( peer->version.has_commit ) ) {
      peer->version.commit = *(uint const *)(data+50UL);
    }
    peer->version.feature_set = *(uint const *)(data+54UL);
  }

  for( ulong j=0UL; j<12UL; j++ ) {
    peer->sockets[ j ].ipv4 = *(uint const *)(data+58UL+j*6UL);
    peer->sockets[ j ].port = *(ushort const *)(data+58UL+j*6UL+4UL);
  }
}

static int
fd_gui_gossip_peer_eq( fd_gui_gossip_peer_t const * a, fd_gui_gossip_peer_t const * b ) {
  int equal = a->shred_version==b->shred_version &&
              // a->wallclock==b->wallclock &&
              a->has_version==b->has_version;

  if( FD_LIKELY( !equal ) ) return 0;

  if( FD_LIKELY( a->has_version ) ) {
    equal = a->version.major==b->version.major &&
            a->version.minor==b->version.minor &&
            a->version.patch==b->version.patch &&
            a->version.has_commit==b->version.has_commit &&
            a->version.feature_set==b->version.feature_set;

    if( FD_LIKELY( equal && a->version.has_commit ) ) equal = a->version.commit==b->version.commit;
  }

  if( FD_LIKELY( !equal ) ) return 0;

  for( ulong j=0UL; j<12UL; j++ ) {
    equal = a->sockets[ j ].ipv4==b->sockets[ j ].ipv4 && a->sockets[ j ].port==b->sockets[ j ].port;
    if( FD_LIKELY( !equal ) ) return 0;
  }

  return 1;
}

static void
fd_gui_add_or_update_modified_peers( fd_gui_t const * gui,
                                     uchar const *    pubkey,
                                     ulong *          modified_cnt,
                                     fd_pubkey_t *    modified_pubkeys,
                                     ulong *          action ) {
  if( FD_UNLIKELY( fd_gui_send_to_frontend( gui, pubkey ) ) ) {
    action[ *modified_cnt ] = fd_ulong_if( ULONG_MAX!=fd_gui_frontend_peers_contains( gui, pubkey ), FD_GUI_PEERS_ACTION_UPDATE, FD_GUI_PEERS_ACTION_ADD );
    fd_memcpy( modified_pubkeys[ *modified_cnt ].uc, pubkey, 32UL );
    (*modified_cnt)++;
  }
}

static void
fd_gui_handle_gossip_update( fd_gui_t *    gui,
                             uchar const * msg ) {
  ulong const * header = (ulong const *)fd_type_pun_const( msg );
  ulong peer_cnt = header[ 0 ];

  FD_TEST( peer_cnt<=FD_GUI_MAX_GOSSIP_PEERS );

  fd_pubkey_t modified_pubkeys[ FD_GUI_MAX_GOSSIP_PEERS ] = {0};
  ulong modified_cnt = 0UL;
  ulong action[ FD_GUI_MAX_GOSSIP_PEERS ] = {0};

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
      if( FD_UNLIKELY( ULONG_MAX!=fd_gui_frontend_peers_contains( gui, gui->gossip.peers[ i ].pubkey->uc ) ) ) {
          action[ modified_cnt ] = FD_GUI_PEERS_ACTION_REMOVE;
          fd_memcpy( modified_pubkeys[ modified_cnt++ ].uc, gui->gossip.peers[ i ].pubkey->uc, 32UL );
      }

      if( FD_LIKELY( i+1UL!=gui->gossip.peer_cnt ) ) {
        fd_memcpy( &gui->gossip.peers[ i ], &gui->gossip.peers[ gui->gossip.peer_cnt-1UL ], sizeof(fd_gui_gossip_peer_t) );
        gui->gossip.peer_cnt--;
        i--;
      }
    }
  }

  for( ulong i=0UL; i<peer_cnt; i++ ) {
    uchar const * pubkey = data+i*(58UL+12UL*6UL);
    fd_gui_parse_gossip_peer_msg( &gui->gossip.peers[ gui->gossip.peer_cnt ], data+i*(58UL+12UL*6UL) );

    int found = 0;
    ulong found_idx = 0;
    for( ulong j=0UL; j<gui->gossip.peer_cnt; j++ ) {
      if( FD_UNLIKELY( !memcmp( gui->gossip.peers[ j ].pubkey, pubkey, 32UL ) ) ) {
        found_idx = j;
        found = 1;
        break;
      }
    }

    if( FD_UNLIKELY( !found ) ) {
      gui->gossip.peer_cnt++;
      fd_gui_add_or_update_modified_peers( gui, pubkey, &modified_cnt, modified_pubkeys, action );
    } else {
      if( FD_UNLIKELY( !fd_gui_gossip_peer_eq( &gui->gossip.peers[ gui->gossip.peer_cnt ], &gui->gossip.peers[ found_idx ] ) ) ) {
        fd_gui_add_or_update_modified_peers( gui, pubkey, &modified_cnt, modified_pubkeys, action );
        fd_memcpy( &gui->gossip.peers[ found_idx ], &gui->gossip.peers[ gui->gossip.peer_cnt ], sizeof(fd_gui_gossip_peer_t) );
      }
    }
  }

  fd_sort_gui_gossip_peer_insert( gui->gossip.peers, gui->gossip.peer_cnt );

  if( FD_LIKELY( modified_cnt>0 )) {
    fd_gui_modify_frontend_peers( gui, modified_cnt, modified_pubkeys, action );
    fd_gui_printf_peers         ( gui, modified_cnt, modified_pubkeys, action );
    fd_http_server_ws_broadcast( gui->http );
  }

  fd_gui_printf_rpc_count( gui );
  fd_http_server_ws_broadcast( gui->http );
}

static void
fd_gui_parse_vote_acct_msg( fd_gui_vote_account_t * vote_acct, uchar const * data ) {
  fd_memcpy( vote_acct->vote_account->uc, data, 32UL );
  fd_memcpy( vote_acct->pubkey->uc, data+32UL, 32UL );

  vote_acct->activated_stake = *(ulong const *)(data+64UL);
  vote_acct->last_vote = *(ulong const *)(data+72UL);
  vote_acct->root_slot = *(ulong const *)(data+80UL);
  vote_acct->epoch_credits = *(ulong const *)(data+88UL);
  vote_acct->commission = *(data+96UL);
  vote_acct->delinquent = *(data+97UL);
}

static int
fd_gui_vote_acct_eq( fd_gui_vote_account_t const * a, fd_gui_vote_account_t const * b ) {
  return fd_memeq( a->pubkey->uc, b->pubkey->uc, 32UL ) &&
                   a->activated_stake == b->activated_stake &&
                  //  a->last_vote       == b->last_vote
                  //  a->root_slot       == b->root_slot
                  //  a->epoch_credits   == b->epoch_credits
                   a->commission      == b->commission &&
                   a->delinquent      == b->delinquent;
}

static void
fd_gui_handle_vote_account_update( fd_gui_t *    gui,
                                   uchar const * msg ) {
  ulong const * header = (ulong const *)fd_type_pun_const( msg );
  ulong peer_cnt = header[ 0 ];

  FD_TEST( peer_cnt<=FD_GUI_MAX_GOSSIP_PEERS );

  fd_pubkey_t modified_pubkeys[ FD_GUI_MAX_GOSSIP_PEERS ] = {0};
  ulong modified_cnt = 0UL;
  ulong action[ FD_GUI_MAX_GOSSIP_PEERS ] = {0};

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
      if( FD_UNLIKELY( ULONG_MAX!=fd_gui_frontend_peers_contains( gui, gui->vote_account.vote_accounts[ i ].pubkey->uc ) ) ) {
        action[ modified_cnt ] = FD_GUI_PEERS_ACTION_REMOVE;
        fd_memcpy( modified_pubkeys[ modified_cnt++ ].uc, gui->vote_account.vote_accounts[ i ].pubkey->uc, 32UL );
      }

      if( FD_LIKELY( i+1UL!=gui->vote_account.vote_account_cnt ) ) {
        fd_memcpy( &gui->vote_account.vote_accounts[ i ], &gui->vote_account.vote_accounts[ gui->vote_account.vote_account_cnt-1UL ], sizeof(fd_gui_vote_account_t) );
        gui->vote_account.vote_account_cnt--;
        i--;
      }
    }
  }

  for( ulong i=0UL; i<peer_cnt; i++ ) {
    uchar const * vote_acct_pubkey = data+i*112UL;
    uchar const * identity_pubkey = data+i*112UL+32UL;
    fd_gui_parse_vote_acct_msg( &gui->vote_account.vote_accounts[ gui->vote_account.vote_account_cnt ], data+i*112UL );

    int found = 0;
    ulong found_idx;
    for( ulong j=0UL; j<gui->vote_account.vote_account_cnt; j++ ) {
      if( FD_UNLIKELY( !memcmp( gui->vote_account.vote_accounts[ j ].vote_account, vote_acct_pubkey, 32UL ) ) ) {
        found_idx = j;
        found = 1;
        break;
      }
    }

    if( FD_UNLIKELY( !found ) ) {
      gui->vote_account.vote_account_cnt++;

        fd_gui_add_or_update_modified_peers( gui, identity_pubkey, &modified_cnt, modified_pubkeys, action );
    } else {
      if( FD_UNLIKELY( !fd_gui_vote_acct_eq( &gui->vote_account.vote_accounts[ gui->vote_account.vote_account_cnt ], &gui->vote_account.vote_accounts[ found_idx ] ) ) ) {
        fd_gui_add_or_update_modified_peers( gui, identity_pubkey, &modified_cnt, modified_pubkeys, action );
        fd_memcpy( &gui->vote_account.vote_accounts[ found_idx ], &gui->vote_account.vote_accounts[ gui->vote_account.vote_account_cnt ], sizeof(fd_gui_vote_account_t) );
      }
    }
  }

  fd_sort_gui_vote_account_insert( gui->vote_account.vote_accounts, gui->vote_account.vote_account_cnt );
  if( FD_LIKELY( modified_cnt>0 )) {
    fd_gui_modify_frontend_peers( gui, modified_cnt, modified_pubkeys, action );
    fd_gui_printf_peers         ( gui, modified_cnt, modified_pubkeys, action );
    fd_http_server_ws_broadcast( gui->http );
  }
}


static void 
fd_gui_parse_validator_info_msg( fd_gui_validator_info_t * peer, uchar const * data ) {
  fd_memcpy( peer->pubkey->uc, data, 32UL );

  strncpy( peer->name,     (char const *)(data+32UL),   64 ); peer->name    [  63 ] = '\0';
  strncpy( peer->website,  (char const *)(data+96UL),  128 ); peer->website [ 127 ] = '\0';
  strncpy( peer->details,  (char const *)(data+224UL), 256 ); peer->details [ 255 ] = '\0';
  strncpy( peer->icon_uri, (char const *)(data+480UL), 128 ); peer->icon_uri[ 127 ] = '\0';
}

static int
fd_gui_validator_info_eq( fd_gui_validator_info_t * a, fd_gui_validator_info_t * b ) {
  return fd_memeq( a->pubkey->uc, b->pubkey->uc, 32UL  ) &&
         strncmp(  a->name,       b->name,       64UL  ) &&
         strncmp(  a->website,    b->website,    128UL ) &&
         strncmp(  a->details,    b->details,    256UL ) &&
         strncmp(  a->icon_uri,   b->icon_uri,   128UL );
}

static void
fd_gui_handle_validator_info_update( fd_gui_t *    gui,
                                     uchar const * msg ) {
  uchar const * data = (uchar const *)fd_type_pun_const( msg );

  /* Unlike gossip or vote account updates, validator info messages come
     in as info is disovered, and will contain only 1 validator
     per message.  Therefore it doesn't make sense to use the remove
     mechanism.  */
  fd_pubkey_t modified_pubkeys[ 1 ] = {0};
  ulong modified_cnt = 0UL;
  ulong action[ 1 ] = {0};

  uchar const * pubkey = data;
  fd_gui_parse_validator_info_msg( &gui->validator_info.info[ gui->validator_info.info_cnt ], data );
  ulong found_idx = fd_gui_validator_info_contains( gui, pubkey );

  if( FD_UNLIKELY( ULONG_MAX==found_idx ) ) {
    gui->validator_info.info_cnt++;
    fd_gui_add_or_update_modified_peers( gui, pubkey, &modified_cnt, modified_pubkeys, action );
  } else {
    if( FD_UNLIKELY( !fd_gui_validator_info_eq( &gui->validator_info.info[ gui->validator_info.info_cnt ], &gui->validator_info.info[ found_idx ] ) ) ) {
      fd_gui_add_or_update_modified_peers( gui, pubkey, &modified_cnt, modified_pubkeys, action );
      fd_memcpy( &gui->validator_info.info[ found_idx ], &gui->validator_info.info[ gui->validator_info.info_cnt ], sizeof(fd_gui_validator_info_t) );
    }
  }

  fd_sort_gui_validator_info_insert( gui->validator_info.info, gui->validator_info.info_cnt );
  if( FD_LIKELY( modified_cnt>0 )) {
    fd_gui_modify_frontend_peers( gui, modified_cnt, modified_pubkeys, action );
    fd_gui_printf_peers         ( gui, modified_cnt, modified_pubkeys, action );
    fd_http_server_ws_broadcast( gui->http );
  }
}

int
fd_gui_request_slot( fd_gui_t *    gui,
                     ulong         ws_conn_id,
                     ulong         request_id,
                     cJSON const * params ) {
  const cJSON * slot_param = cJSON_GetObjectItemCaseSensitive( params, "slot" );
  if( FD_UNLIKELY( !cJSON_IsNumber( slot_param ) ) ) return FD_HTTP_SERVER_CONNECTION_CLOSE_BAD_REQUEST;

  ulong _slot = slot_param->valueulong;
  fd_gui_slot_t const * slot = gui->slots[ _slot % FD_GUI_SLOTS_CNT ];
  if( FD_UNLIKELY( slot->slot!=_slot || slot->slot==ULONG_MAX ) ) {
    fd_gui_printf_null_query_response( gui, "slot", "query", request_id );
    FD_TEST( !fd_http_server_ws_send( gui->http, ws_conn_id ) );
    return 0;
  }

  fd_gui_printf_slot_request( gui, _slot, request_id );
  FD_TEST( !fd_http_server_ws_send( gui->http, ws_conn_id ) );
  return 0;
}

int
fd_gui_request_slot_detailed( fd_gui_t *    gui,
                              ulong         ws_conn_id,
                              ulong         request_id,
                              cJSON const * params ) {
  const cJSON * slot_param = cJSON_GetObjectItemCaseSensitive( params, "slot" );
  if( FD_UNLIKELY( !cJSON_IsNumber( slot_param ) ) ) return FD_HTTP_SERVER_CONNECTION_CLOSE_BAD_REQUEST;

  ulong _slot = slot_param->valueulong;
  fd_gui_slot_t const * slot = gui->slots[ _slot % FD_GUI_SLOTS_CNT ];
  if( FD_UNLIKELY( slot->slot!=_slot || slot->slot==ULONG_MAX ) ) {
    fd_gui_printf_null_query_response( gui, "slot", "query", request_id );
    FD_TEST( !fd_http_server_ws_send( gui->http, ws_conn_id ) );
    return 0;
  }

  fd_gui_printf_slot_request_detailed( gui, _slot, request_id );
  FD_TEST( !fd_http_server_ws_send( gui->http, ws_conn_id ) );
  return 0;
}

int
fd_gui_ws_message( fd_gui_t *    gui,
                   ulong         ws_conn_id,
                   uchar const * data,
                   ulong         data_len ) {
  /* TODO: cJSON allocates, might fail SIGSYS due to brk(2)...
     switch off this (or use wksp allocator) */
  const char * parse_end;
  cJSON * json = cJSON_ParseWithLengthOpts( (char *)data, data_len, &parse_end, 0 );
  if( FD_UNLIKELY( !json ) ) {
    return FD_HTTP_SERVER_CONNECTION_CLOSE_BAD_REQUEST;
  }

  const cJSON * node = cJSON_GetObjectItemCaseSensitive( json, "id" );
  if( FD_UNLIKELY( !cJSON_IsNumber( node ) ) ) {
    cJSON_Delete( json );
    return FD_HTTP_SERVER_CONNECTION_CLOSE_BAD_REQUEST;
  }
  ulong id = node->valueulong;

  const cJSON * topic = cJSON_GetObjectItemCaseSensitive( json, "topic" );
  if( FD_UNLIKELY( !cJSON_IsString( topic ) || topic->valuestring==NULL ) ) {
    cJSON_Delete( json );
    return FD_HTTP_SERVER_CONNECTION_CLOSE_BAD_REQUEST;
  }

  const cJSON * key = cJSON_GetObjectItemCaseSensitive( json, "key" );
  if( FD_UNLIKELY( !cJSON_IsString( key ) || key->valuestring==NULL ) ) {
    cJSON_Delete( json );
    return FD_HTTP_SERVER_CONNECTION_CLOSE_BAD_REQUEST;
  }

  if( FD_LIKELY( !strcmp( topic->valuestring, "slot" ) && !strcmp( key->valuestring, "query" ) ) ) {
    const cJSON * params = cJSON_GetObjectItemCaseSensitive( json, "params" );
    if( FD_UNLIKELY( !cJSON_IsObject( params ) ) ) {
      cJSON_Delete( json );
      return FD_HTTP_SERVER_CONNECTION_CLOSE_BAD_REQUEST;
    }

    int result = fd_gui_request_slot( gui, ws_conn_id, id, params );
    cJSON_Delete( json );
    return result;
  } else if( FD_LIKELY( !strcmp( topic->valuestring, "slot" ) && !strcmp( key->valuestring, "query_detailed" ) ) ) {
    const cJSON * params = cJSON_GetObjectItemCaseSensitive( json, "params" );
    if( FD_UNLIKELY( !cJSON_IsObject( params ) ) ) {
      cJSON_Delete( json );
      return FD_HTTP_SERVER_CONNECTION_CLOSE_BAD_REQUEST;
    }

    int result = fd_gui_request_slot_detailed( gui, ws_conn_id, id, params );
    cJSON_Delete( json );
    return result;
  } else if( FD_LIKELY( !strcmp( topic->valuestring, "summary" ) && !strcmp( key->valuestring, "ping" ) ) ) {
    fd_gui_printf_summary_ping( gui, id );
    FD_TEST( !fd_http_server_ws_send( gui->http, ws_conn_id ) );

    cJSON_Delete( json );
    return 0;
  }

  cJSON_Delete( json );
  return FD_HTTP_SERVER_CONNECTION_CLOSE_UNKNOWN_METHOD;
}

static void
fd_gui_clear_slot( fd_gui_t * gui,
                   ulong      _slot,
                   ulong      _parent_slot ) {
  fd_gui_slot_t * slot = gui->slots[ _slot % FD_GUI_SLOTS_CNT ];

  int mine = 0;
  ulong epoch_idx = 0UL;
  for( ulong i=0UL; i<3UL; i++) {
    if( FD_LIKELY( !gui->epoch.has_epoch[ i ] ) ) continue;
    if( FD_LIKELY( _slot>=gui->epoch.epochs[ i ].start_slot && _slot<=gui->epoch.epochs[ i ].end_slot ) ) {
      fd_pubkey_t const * slot_leader = fd_epoch_leaders_get( gui->epoch.epochs[ i ].lsched, _slot );
      mine = !memcmp( slot_leader->uc, gui->summary.identity_key->uc, 32UL );
      epoch_idx = i;
      break;
    }
  }

  slot->slot                   = _slot;
  slot->parent_slot            = _parent_slot;
  slot->mine                   = mine;
  slot->skipped                = 0;
  slot->must_republish         = 1;
  slot->level                  = FD_GUI_SLOT_LEVEL_INCOMPLETE;
  slot->total_txn_cnt          = UINT_MAX;
  slot->vote_txn_cnt           = UINT_MAX;
  slot->failed_txn_cnt         = UINT_MAX;
  slot->nonvote_failed_txn_cnt = UINT_MAX;
  slot->compute_units          = UINT_MAX;
  slot->transaction_fee        = ULONG_MAX;
  slot->priority_fee           = ULONG_MAX;
  slot->tips                   = ULONG_MAX;
  slot->leader_state           = FD_GUI_SLOT_LEADER_UNSTARTED;
  slot->completed_time         = LONG_MAX;

  slot->cus.leader_start_time  = LONG_MAX;
  slot->cus.leader_end_time    = LONG_MAX;
  slot->cus.max_compute_units  = UINT_MAX;
  slot->cus.microblocks_upper_bound = USHORT_MAX;
  slot->cus.begin_microblocks  = 0U;
  slot->cus.end_microblocks    = 0U;
  slot->cus.reference_ticks    = LONG_MAX;
  slot->cus.reference_nanos    = LONG_MAX;
  for( ulong i=0UL; i<65UL; i++ ) slot->cus.has_offset[ i ]   = 0;

  if( FD_LIKELY( slot->mine && gui->epoch.has_epoch[ epoch_idx ] ) ) {
    /* All slots start off not skipped, until we see it get off the reset
       chain. */
    gui->epoch.epochs[ epoch_idx ].my_total_slots++;
  }

  if( FD_UNLIKELY( !_slot ) ) {
    /* Slot 0 is always rooted */
    slot->level   = FD_GUI_SLOT_LEVEL_ROOTED;
  }
}

static void
fd_gui_handle_leader_schedule( fd_gui_t *    gui,
                               ulong const * msg ) {
  ulong epoch               = msg[ 0 ];
  ulong staked_cnt          = msg[ 1 ];
  ulong start_slot          = msg[ 2 ];
  ulong slot_cnt            = msg[ 3 ];
  ulong excluded_stake      = msg[ 4 ];

  fd_stake_weight_t const * stakes = (fd_stake_weight_t const *)fd_type_pun_const( msg+5UL );

  /* idx is the index of the previous previous epoch, which will
     be replaced by the incoming epoch. */
  ulong idx = epoch % 3UL;

  fd_pubkey_t modified_pubkeys[ FD_GUI_MAX_GOSSIP_PEERS ] = {0};
  ulong modified_cnt = 0UL;
  ulong action[ FD_GUI_MAX_GOSSIP_PEERS ] = {0};

  /* The incoming message contains validators that have activate stake
     used to compute the leader schedule for the next next epoch.  Any
     new validators are added here.

     Note that it is possible for a validator to be in the leader
     schedule for the upcoming epoch even if they have zero active stake
     in this epoch.  This is because the leader schedule for this epoch
     is generated from the active stake amounts of the previous epoch.
     This means, however, that an 0-stake leaders this epoch must have
     been staked last epoch.  We send the fronted staked peers from the
     previous epoch, so the frontend should still receive updates for
     this epoch's 0-stake leaders. */
  for ( ulong i=0UL; i<staked_cnt; i++ ) {
    int available = ULONG_MAX!=fd_gui_vote_acct_contains( gui, stakes[ i ].key.uc ) ||
                    ULONG_MAX!=fd_gui_validator_info_contains( gui, stakes[ i ].key.uc ) ||
                    ULONG_MAX!=fd_gui_gossip_contains( gui, stakes[ i ].key.uc );
    if( FD_UNLIKELY( !available ) ) continue;

    if( FD_UNLIKELY( !fd_gui_send_to_frontend( gui, stakes[ i ].key.uc ) ) ) {
      action[ modified_cnt ] = FD_GUI_PEERS_ACTION_ADD;
      fd_memcpy( modified_pubkeys[ modified_cnt++ ].uc, stakes[ i ].key.uc, 32UL );
      break;
    }
  }

  /* We also want to remove any validators we included that had active
     stake two epochs ago but have zero stake in the incoming epoch. */
  if( FD_UNLIKELY( gui->epoch.has_epoch[ idx ] ) ) {
    for ( ulong i=0UL; i<gui->epoch.epochs[ idx ].lsched->pub_cnt; i++ ) {
      /* This peer is already not in the frontend */
      if( FD_UNLIKELY( ULONG_MAX==fd_gui_frontend_peers_contains( gui, gui->epoch.epochs[ idx ].stakes_sorted[ i ].uc ) ) ) continue;

      int in_incoming_epoch = 0;
      for ( ulong j=0UL; j<staked_cnt; j++ ) {
        in_incoming_epoch |= fd_memeq( gui->epoch.epochs[ idx ].stakes_sorted[ i ].uc, stakes[ j ].key.uc, 32UL );
        if( FD_UNLIKELY( in_incoming_epoch ) ) break;
      }

      if( FD_UNLIKELY( !in_incoming_epoch ) ) {
        action[ modified_cnt ] = FD_GUI_PEERS_ACTION_REMOVE;
        fd_memcpy( modified_pubkeys[ modified_cnt++ ].uc, stakes[ i ].key.uc, 32UL );
        break;
      }
    }
  }


  fd_gui_modify_frontend_peers( gui, modified_cnt, modified_pubkeys, action );
  fd_gui_printf_peers         ( gui, modified_cnt, modified_pubkeys, action );
  fd_http_server_ws_broadcast( gui->http );

  FD_TEST( staked_cnt<=FD_GUI_MAX_STAKED_PEERS );
  FD_TEST( slot_cnt<=432000UL );

  gui->epoch.has_epoch[ idx ] = 1;

  gui->epoch.epochs[ idx ].epoch            = epoch;
  gui->epoch.epochs[ idx ].start_slot       = start_slot;
  gui->epoch.epochs[ idx ].end_slot         = start_slot + slot_cnt - 1; // end_slot is inclusive.
  gui->epoch.epochs[ idx ].excluded_stake   = excluded_stake;
  gui->epoch.epochs[ idx ].my_total_slots   = 0UL;
  gui->epoch.epochs[ idx ].my_skipped_slots = 0UL;
  fd_epoch_leaders_delete( fd_epoch_leaders_leave( gui->epoch.epochs[ idx ].lsched ) );
  gui->epoch.epochs[ idx ].lsched = fd_epoch_leaders_join( fd_epoch_leaders_new( gui->epoch.epochs[ idx ]._lsched,
                                                                                 epoch,
                                                                                 gui->epoch.epochs[ idx ].start_slot,
                                                                                 slot_cnt,
                                                                                 staked_cnt,
                                                                                 stakes,
                                                                                 excluded_stake ) );
  fd_memcpy( gui->epoch.epochs[ idx ].stakes, stakes, staked_cnt*sizeof(fd_stake_weight_t) );
  for( ulong i=0UL; i<gui->epoch.epochs[ idx ].lsched->pub_cnt; i++ ) {
    fd_memcpy( gui->epoch.epochs[ idx ].stakes_sorted[ i ].uc, gui->epoch.epochs[ idx ].stakes[ i ].key.uc, 32UL );
  }
  fd_sort_gui_pubkey_insert( gui->epoch.epochs[ idx ].stakes_sorted, gui->epoch.epochs[ idx ].lsched->pub_cnt );

  if( FD_UNLIKELY( start_slot==0UL ) ) {
    gui->epoch.epochs[ 0 ].start_time = fd_log_wallclock();
  } else {
    gui->epoch.epochs[ idx ].start_time = LONG_MAX;

    for( ulong i=0UL; i<fd_ulong_min( start_slot-1UL, FD_GUI_SLOTS_CNT ); i++ ) {
      fd_gui_slot_t * slot = gui->slots[ (start_slot-i) % FD_GUI_SLOTS_CNT ];
      if( FD_UNLIKELY( slot->slot!=(start_slot-i) ) ) break;
      else if( FD_UNLIKELY( slot->skipped ) )         continue;

      gui->epoch.epochs[ idx ].start_time = slot->completed_time;
      break;
    }
  }

  fd_gui_printf_epoch( gui, idx );
  fd_http_server_ws_broadcast( gui->http );
}

static void
fd_gui_handle_slot_start( fd_gui_t * gui,
                          ulong *    msg ) {
  ulong _slot = msg[ 0 ];
  ulong _parent_slot = msg[ 1 ];
  // FD_LOG_WARNING(( "Got start slot %lu parent_slot %lu", _slot, _parent_slot ));
  FD_TEST( gui->debug_in_leader_slot==ULONG_MAX );
  gui->debug_in_leader_slot = _slot;

  fd_gui_slot_t * slot = gui->slots[ _slot % FD_GUI_SLOTS_CNT ];

  if( FD_UNLIKELY( slot->slot!=_slot ) ) fd_gui_clear_slot( gui, _slot, _parent_slot );
  slot->leader_state = FD_GUI_SLOT_LEADER_STARTED;

  fd_gui_tile_timers_snap( gui );
  gui->summary.tile_timers_snap_idx_slot_start = (gui->summary.tile_timers_snap_idx+(FD_GUI_TILE_TIMER_SNAP_CNT-1UL))%FD_GUI_TILE_TIMER_SNAP_CNT;

  fd_gui_txn_waterfall_t waterfall[ 1 ];
  fd_gui_txn_waterfall_snap( gui, waterfall );
  fd_gui_tile_stats_snap( gui, waterfall, slot->tile_stats_begin );
}

static void
fd_gui_handle_slot_end( fd_gui_t * gui,
                        ulong *    msg ) {
  ulong _slot     = msg[ 0 ];
  ulong _cus_used = msg[ 1 ];
  if( FD_UNLIKELY( gui->debug_in_leader_slot!=_slot ) ) {
    FD_LOG_ERR(( "gui->debug_in_leader_slot %lu _slot %lu", gui->debug_in_leader_slot, _slot ));
  }
  gui->debug_in_leader_slot = ULONG_MAX;

  fd_gui_slot_t * slot = gui->slots[ _slot % FD_GUI_SLOTS_CNT ];
  FD_TEST( slot->slot==_slot );

  slot->leader_state  = FD_GUI_SLOT_LEADER_ENDED;
  slot->compute_units = (uint)_cus_used;

  fd_gui_tile_timers_snap( gui );
  /* Record slot number so we can detect overwrite. */
  gui->summary.tile_timers_leader_history_slot[ gui->summary.tile_timers_history_idx ] = _slot;
  /* Point into per-leader-slot storage. */
  slot->tile_timers_history_idx = gui->summary.tile_timers_history_idx;
  /* Downsample tile timers into per-leader-slot storage. */
  ulong end = gui->summary.tile_timers_snap_idx;
  end = fd_ulong_if( end<gui->summary.tile_timers_snap_idx_slot_start, end+FD_GUI_TILE_TIMER_SNAP_CNT, end );
  gui->summary.tile_timers_leader_history_slot_sample_cnt[ gui->summary.tile_timers_history_idx ] = end-gui->summary.tile_timers_snap_idx_slot_start;
  ulong stride = fd_ulong_max( 1UL, (end-gui->summary.tile_timers_snap_idx_slot_start) / FD_GUI_TILE_TIMER_LEADER_DOWNSAMPLE_CNT );
  for( ulong sample_snap_idx=gui->summary.tile_timers_snap_idx_slot_start, i=0UL; sample_snap_idx<end; sample_snap_idx+=stride, i++ ) {
    fd_memcpy( gui->summary.tile_timers_leader_history[ gui->summary.tile_timers_history_idx ][ i ], gui->summary.tile_timers_snap[ sample_snap_idx%FD_GUI_TILE_TIMER_SNAP_CNT ], sizeof(gui->summary.tile_timers_leader_history[ gui->summary.tile_timers_history_idx ][ i ]) );
  }
  gui->summary.tile_timers_history_idx = (gui->summary.tile_timers_history_idx+1UL)%FD_GUI_TILE_TIMER_LEADER_CNT;

  /* When a slot ends, snap the state of the waterfall and save it into
     that slot, and also reset the reference counters to the end of the
     slot. */

  fd_gui_txn_waterfall_snap( gui, slot->waterfall_end );
  fd_memcpy( slot->waterfall_begin, gui->summary.txn_waterfall_reference, sizeof(slot->waterfall_begin) );
  fd_memcpy( gui->summary.txn_waterfall_reference, slot->waterfall_end, sizeof(gui->summary.txn_waterfall_reference) );

  fd_gui_tile_stats_snap( gui, slot->waterfall_end, slot->tile_stats_end );
}

static void
fd_gui_handle_reset_slot( fd_gui_t * gui,
                          ulong *    msg ) {
  ulong last_landed_vote = msg[ 0 ];

  ulong parent_cnt = msg[ 1 ];
  FD_TEST( parent_cnt<4096UL );

  ulong _slot = msg[ 2 ];

  for( ulong i=0UL; i<parent_cnt; i++ ) {
    ulong parent_slot = msg[2UL+i];
    fd_gui_slot_t * slot = gui->slots[ parent_slot % FD_GUI_SLOTS_CNT ];
    if( FD_UNLIKELY( slot->slot!=parent_slot ) ) {
      ulong parent_parent_slot = ULONG_MAX;
      if( FD_UNLIKELY( i!=parent_cnt-1UL) ) parent_parent_slot = msg[ 3UL+i ];
      fd_gui_clear_slot( gui, parent_slot, parent_parent_slot );
    }
  }

  if( FD_UNLIKELY( gui->summary.vote_distance!=_slot-last_landed_vote ) ) {
    gui->summary.vote_distance = _slot-last_landed_vote;
    fd_gui_printf_vote_distance( gui );
    fd_http_server_ws_broadcast( gui->http );
  }

  if( FD_LIKELY( gui->summary.vote_state!=FD_GUI_VOTE_STATE_NON_VOTING ) ) {
    if( FD_UNLIKELY( last_landed_vote==ULONG_MAX || (last_landed_vote+150UL)<_slot ) ) {
      if( FD_UNLIKELY( gui->summary.vote_state!=FD_GUI_VOTE_STATE_DELINQUENT ) ) {
        gui->summary.vote_state = FD_GUI_VOTE_STATE_DELINQUENT;
        fd_gui_printf_vote_state( gui );
        fd_http_server_ws_broadcast( gui->http );
      }
    } else {
      if( FD_UNLIKELY( gui->summary.vote_state!=FD_GUI_VOTE_STATE_VOTING ) ) {
        gui->summary.vote_state = FD_GUI_VOTE_STATE_VOTING;
        fd_gui_printf_vote_state( gui );
        fd_http_server_ws_broadcast( gui->http );
      }
    }
  }

  ulong parent_slot_idx = 0UL;

  int republish_skip_rate[ 2 ] = {0};

  for( ulong i=0UL; i<fd_ulong_min( _slot+1, FD_GUI_SLOTS_CNT ); i++ ) {
    ulong parent_slot = _slot - i;
    ulong parent_idx = parent_slot % FD_GUI_SLOTS_CNT;

    fd_gui_slot_t * slot = gui->slots[ parent_idx ];
    if( FD_UNLIKELY( slot->slot==ULONG_MAX || slot->slot!=parent_slot ) ) fd_gui_clear_slot( gui, parent_slot, ULONG_MAX );

    /* The chain of parents may stretch into already rooted slots if
       they haven't been squashed yet, if we reach one of them we can
       just exit, all the information prior to the root is already
       correct. */

    if( FD_LIKELY( slot->level>=FD_GUI_SLOT_LEVEL_ROOTED ) ) break;

    int should_republish = slot->must_republish;
    slot->must_republish = 0;

    if( FD_UNLIKELY( parent_slot!=msg[2UL+parent_slot_idx] ) ) {
      /* We are between two parents in the rooted chain, which means
         we were skipped. */
      if( FD_UNLIKELY( !slot->skipped ) ) {
        slot->skipped = 1;
        should_republish = 1;
        if( FD_LIKELY( slot->mine ) ) {
          for( ulong i=0UL; i<3UL; i++ ) {
            if( FD_LIKELY( gui->epoch.has_epoch[ i ] && parent_slot>=gui->epoch.epochs[ i ].start_slot && parent_slot<=gui->epoch.epochs[ i ].end_slot ) ) {
              gui->epoch.epochs[ i ].my_skipped_slots++;
              republish_skip_rate[ i ] = 1;
              break;
            }
          }
        }
      }
    } else {
      /* Reached the next parent... */
      if( FD_UNLIKELY( slot->skipped ) ) {
        slot->skipped = 0;
        should_republish = 1;
        if( FD_LIKELY( slot->mine ) ) {
          for( ulong i=0UL; i<3UL; i++ ) {
            if( FD_LIKELY( gui->epoch.has_epoch[ i ] && parent_slot>=gui->epoch.epochs[ i ].start_slot && parent_slot<=gui->epoch.epochs[ i ].end_slot ) ) {
              gui->epoch.epochs[ i ].my_skipped_slots--;
              republish_skip_rate[ i ] = 1;
              break;
            }
          }
        }
      }
      parent_slot_idx++;
    }

    if( FD_LIKELY( should_republish ) ) {
      fd_gui_printf_slot( gui, parent_slot );
      fd_http_server_ws_broadcast( gui->http );
    }

    /* We reached the last parent in the chain, everything above this
       must have already been rooted, so we can exit. */

    if( FD_UNLIKELY( parent_slot_idx>=parent_cnt ) ) break;
  }

  ulong last_slot = _slot;
  long last_published = gui->slots[ _slot % FD_GUI_SLOTS_CNT ]->completed_time;

  for( ulong i=0UL; i<fd_ulong_min( _slot+1, 750UL ); i++ ) {
    ulong parent_slot = _slot - i;
    ulong parent_idx  = parent_slot % FD_GUI_SLOTS_CNT;

    fd_gui_slot_t * slot = gui->slots[ parent_idx ];
    if( FD_UNLIKELY( slot->slot==ULONG_MAX) ) break;
    if( FD_UNLIKELY( slot->slot!=parent_slot ) ) {
      FD_LOG_ERR(( "_slot %lu i %lu we expect _slot-i %lu got slot->slot %lu", _slot, i, _slot-i, slot->slot ));
    }

    if( FD_LIKELY( !slot->skipped ) ) {
      last_slot = parent_slot;
      last_published = slot->completed_time;
    }
  }

  if( FD_LIKELY( _slot!=last_slot )) {
    gui->summary.estimated_slot_duration_nanos = (ulong)(fd_log_wallclock()-last_published)/(_slot-last_slot);
    fd_gui_printf_estimated_slot_duration_nanos( gui );
    fd_http_server_ws_broadcast( gui->http );
  }

  if( FD_LIKELY( _slot!=gui->summary.slot_completed ) ) {
    gui->summary.slot_completed = _slot;
    fd_gui_printf_completed_slot( gui );
    fd_http_server_ws_broadcast( gui->http );
  }

  for( ulong i=0UL; i<2UL; i++ ) {
    if( FD_LIKELY( republish_skip_rate[ i ] ) ) {
      fd_gui_printf_skip_rate( gui, i );
      fd_http_server_ws_broadcast( gui->http );
    }
  }
}

static void
fd_gui_handle_completed_slot( fd_gui_t * gui,
                              ulong *    msg ) {
  ulong _slot                    = msg[ 0 ];
  uint  total_txn_count          = (uint)msg[ 1 ];
  uint  nonvote_txn_count        = (uint)msg[ 2 ];
  uint  failed_txn_count         = (uint)msg[ 3 ];
  uint  nonvote_failed_txn_count = (uint)msg[ 4 ];
  uint  compute_units            = (uint)msg[ 5 ];
  ulong transaction_fee          = msg[ 6 ];
  ulong priority_fee             = msg[ 7 ];
  ulong tips                     = msg[ 8 ];
  ulong _parent_slot             = msg[ 9 ];

  fd_gui_slot_t * slot = gui->slots[ _slot % FD_GUI_SLOTS_CNT ];
  if( FD_UNLIKELY( slot->slot!=_slot ) ) fd_gui_clear_slot( gui, _slot, _parent_slot );

  slot->completed_time = fd_log_wallclock();
  slot->parent_slot = _parent_slot;
  if( FD_LIKELY( slot->level<FD_GUI_SLOT_LEVEL_COMPLETED ) ) {
    /* Typically a slot goes from INCOMPLETE to COMPLETED but it can
       happen that it starts higher.  One such case is when we
       optimistically confirm a higher slot that skips this one, but
       then later we replay this one anyway to track the bank fork. */

    if( FD_LIKELY( _slot<gui->summary.slot_optimistically_confirmed ) ) {
      /* Cluster might have already optimistically confirmed by the time
         we finish replaying it. */
      slot->level = FD_GUI_SLOT_LEVEL_OPTIMISTICALLY_CONFIRMED;
    } else {
      slot->level = FD_GUI_SLOT_LEVEL_COMPLETED;
    }
  }
  slot->total_txn_cnt          = total_txn_count;
  slot->vote_txn_cnt           = total_txn_count - nonvote_txn_count;
  slot->failed_txn_cnt         = failed_txn_count;
  slot->nonvote_failed_txn_cnt = nonvote_failed_txn_count;
  slot->transaction_fee        = transaction_fee;
  slot->priority_fee           = priority_fee;
  slot->tips                   = tips;
  if( FD_LIKELY( slot->leader_state==FD_GUI_SLOT_LEADER_UNSTARTED ) ) {
    /* If we were already leader for this slot, then the poh component
       calculated the CUs used and sent them there, rather than the
       replay component which is sending this completed slot. */
    slot->compute_units   = compute_units;
  }

  for( ulong i=0UL; i<3UL; i++ ) {
    if( FD_LIKELY( gui->epoch.has_epoch[ i ] && _slot==gui->epoch.epochs[ i ].end_slot ) ) {
      gui->epoch.epochs[ i ].end_time = slot->completed_time;
      break;
    }
  }

  /* Broadcast new skip rate if one of our slots got completed. */
  if( FD_LIKELY( slot->mine ) ) {
    for( ulong i=0UL; i<3UL; i++ ) {
      if( FD_LIKELY( gui->epoch.has_epoch[ i ] && _slot>=gui->epoch.epochs[ i ].start_slot && _slot<=gui->epoch.epochs[ i ].end_slot ) ) {
        fd_gui_printf_skip_rate( gui, i );
        fd_http_server_ws_broadcast( gui->http );
        break;
      }
    }
  }
}

static void
fd_gui_handle_rooted_slot( fd_gui_t * gui,
                           ulong *    msg ) {
  ulong _slot = msg[ 0 ];

  // FD_LOG_WARNING(( "Got rooted slot %lu", _slot ));

  /* Slot 0 is always rooted.  No need to iterate all the way back to
     i==_slot */
  for( ulong i=0UL; i<fd_ulong_min( _slot, FD_GUI_SLOTS_CNT ); i++ ) {
    ulong parent_slot = _slot - i;
    ulong parent_idx = parent_slot % FD_GUI_SLOTS_CNT;

    fd_gui_slot_t * slot = gui->slots[ parent_idx ];
    if( FD_UNLIKELY( slot->slot==ULONG_MAX) ) break;

    if( FD_UNLIKELY( slot->slot!=parent_slot ) ) {
      FD_LOG_ERR(( "_slot %lu i %lu we expect parent_slot %lu got slot->slot %lu", _slot, i, parent_slot, slot->slot ));
    }
    if( FD_UNLIKELY( slot->level>=FD_GUI_SLOT_LEVEL_ROOTED ) ) break;

    slot->level = FD_GUI_SLOT_LEVEL_ROOTED;
    fd_gui_printf_slot( gui, parent_slot );
    fd_http_server_ws_broadcast( gui->http );
  }

  gui->summary.slot_rooted = _slot;
  fd_gui_printf_root_slot( gui );
  fd_http_server_ws_broadcast( gui->http );
}

static void
fd_gui_handle_optimistically_confirmed_slot( fd_gui_t * gui,
                                             ulong *    msg ) {
  ulong _slot = msg[ 0 ];

  /* Slot 0 is always rooted.  No need to iterate all the way back to
     i==_slot */
  for( ulong i=0UL; i<fd_ulong_min( _slot, FD_GUI_SLOTS_CNT ); i++ ) {
    ulong parent_slot = _slot - i;
    ulong parent_idx = parent_slot % FD_GUI_SLOTS_CNT;

    fd_gui_slot_t * slot = gui->slots[ parent_idx ];
    if( FD_UNLIKELY( slot->slot==ULONG_MAX) ) break;

    if( FD_UNLIKELY( slot->slot>parent_slot ) ) {
      FD_LOG_ERR(( "_slot %lu i %lu we expect parent_slot %lu got slot->slot %lu", _slot, i, parent_slot, slot->slot ));
    } else if( FD_UNLIKELY( slot->slot<parent_slot ) ) {
      /* Slot not even replayed yet ... will come out as optmistically confirmed */
      continue;
    }
    if( FD_UNLIKELY( slot->level>=FD_GUI_SLOT_LEVEL_ROOTED ) ) break;

    if( FD_LIKELY( slot->level<FD_GUI_SLOT_LEVEL_OPTIMISTICALLY_CONFIRMED ) ) {
      slot->level = FD_GUI_SLOT_LEVEL_OPTIMISTICALLY_CONFIRMED;
      fd_gui_printf_slot( gui, parent_slot );
      fd_http_server_ws_broadcast( gui->http );
    }
  }

  if( FD_UNLIKELY( _slot<gui->summary.slot_optimistically_confirmed ) ) {
    /* Optimistically confirmed slot went backwards ... mark some slots as no
       longer optimistically confirmed. */
    for( ulong i=gui->summary.slot_optimistically_confirmed; i>=_slot; i-- ) {
      fd_gui_slot_t * slot = gui->slots[ i % FD_GUI_SLOTS_CNT ];
      if( FD_UNLIKELY( slot->slot==ULONG_MAX ) ) break;
      if( FD_LIKELY( slot->slot==i ) ) {
        /* It's possible for the optimistically confirmed slot to skip
           backwards between two slots that we haven't yet replayed.  In
           that case we don't need to change anything, since they will
           get marked properly when they get completed. */
        slot->level = FD_GUI_SLOT_LEVEL_COMPLETED;
        fd_gui_printf_slot( gui, i );
        fd_http_server_ws_broadcast( gui->http );
      }
    }
  }

  gui->summary.slot_optimistically_confirmed = _slot;
  fd_gui_printf_optimistically_confirmed_slot( gui );
  fd_http_server_ws_broadcast( gui->http );
}

static void
fd_gui_handle_balance_update( fd_gui_t *    gui,
                              ulong const * msg ) {
  switch( msg[ 0 ] ) {
    case 0UL:
      gui->summary.identity_account_balance = msg[ 1 ];
      fd_gui_printf_identity_balance( gui );
      fd_http_server_ws_broadcast( gui->http );
      break;
    case 1UL:
      gui->summary.vote_account_balance = msg[ 1 ];
      fd_gui_printf_vote_balance( gui );
      fd_http_server_ws_broadcast( gui->http );
      break;
    default:
      FD_LOG_ERR(( "balance: unknown account type: %lu", msg[ 0 ] ));
}
}

static void
fd_gui_handle_start_progress( fd_gui_t *    gui,
                              uchar const * msg ) {
  uchar type = msg[ 0 ];

  switch (type) {
    case 0:
      gui->summary.startup_progress = FD_GUI_START_PROGRESS_TYPE_INITIALIZING;
      FD_LOG_INFO(( "progress: initializing" ));
      break;
    case 1: {
      char const * snapshot_type;
      if( FD_UNLIKELY( gui->summary.startup_got_full_snapshot ) ) {
        gui->summary.startup_progress = FD_GUI_START_PROGRESS_TYPE_SEARCHING_FOR_INCREMENTAL_SNAPSHOT;
        snapshot_type = "incremental";
      } else {
        gui->summary.startup_progress = FD_GUI_START_PROGRESS_TYPE_SEARCHING_FOR_FULL_SNAPSHOT;
        snapshot_type = "full";
      }
      FD_LOG_INFO(( "progress: searching for %s snapshot", snapshot_type ));
      break;
    }
    case 2: {
      uchar is_full_snapshot = msg[ 1 ];
      if( FD_LIKELY( is_full_snapshot ) ) {
          gui->summary.startup_progress = FD_GUI_START_PROGRESS_TYPE_DOWNLOADING_FULL_SNAPSHOT;
          gui->summary.startup_full_snapshot_slot = *((ulong *)(msg + 2));
          gui->summary.startup_full_snapshot_peer_ip_addr = *((uint *)(msg + 10));
          gui->summary.startup_full_snapshot_peer_port = *((ushort *)(msg + 14));
          gui->summary.startup_full_snapshot_total_bytes = *((ulong *)(msg + 16));
          gui->summary.startup_full_snapshot_current_bytes = *((ulong *)(msg + 24));
          gui->summary.startup_full_snapshot_elapsed_secs = *((double *)(msg + 32));
          gui->summary.startup_full_snapshot_remaining_secs = *((double *)(msg + 40));
          gui->summary.startup_full_snapshot_throughput = *((double *)(msg + 48));
          FD_LOG_INFO(( "progress: downloading full snapshot: slot=%lu", gui->summary.startup_full_snapshot_slot ));
      } else {
          gui->summary.startup_progress = FD_GUI_START_PROGRESS_TYPE_DOWNLOADING_INCREMENTAL_SNAPSHOT;
          gui->summary.startup_incremental_snapshot_slot = *((ulong *)(msg + 2));
          gui->summary.startup_incremental_snapshot_peer_ip_addr = *((uint *)(msg + 10));
          gui->summary.startup_incremental_snapshot_peer_port = *((ushort *)(msg + 14));
          gui->summary.startup_incremental_snapshot_total_bytes = *((ulong *)(msg + 16));
          gui->summary.startup_incremental_snapshot_current_bytes = *((ulong *)(msg + 24));
          gui->summary.startup_incremental_snapshot_elapsed_secs = *((double *)(msg + 32));
          gui->summary.startup_incremental_snapshot_remaining_secs = *((double *)(msg + 40));
          gui->summary.startup_incremental_snapshot_throughput = *((double *)(msg + 48));
          FD_LOG_INFO(( "progress: downloading incremental snapshot: slot=%lu", gui->summary.startup_incremental_snapshot_slot ));
      }
      break;
    }
    case 3: {
      gui->summary.startup_got_full_snapshot = 1;
      break;
    }
    case 4:
      gui->summary.startup_progress = FD_GUI_START_PROGRESS_TYPE_CLEANING_BLOCK_STORE;
      FD_LOG_INFO(( "progress: cleaning block store" ));
      break;
    case 5:
      gui->summary.startup_progress = FD_GUI_START_PROGRESS_TYPE_CLEANING_ACCOUNTS;
      FD_LOG_INFO(( "progress: cleaning accounts" ));
      break;
    case 6:
      gui->summary.startup_progress = FD_GUI_START_PROGRESS_TYPE_LOADING_LEDGER;
      FD_LOG_INFO(( "progress: loading ledger" ));
      break;
    case 7: {
      gui->summary.startup_progress = FD_GUI_START_PROGRESS_TYPE_PROCESSING_LEDGER;
      gui->summary.startup_ledger_slot = fd_ulong_load_8( msg + 1 );
      gui->summary.startup_ledger_max_slot = fd_ulong_load_8( msg + 9 );
      FD_LOG_INFO(( "progress: processing ledger: slot=%lu, max_slot=%lu", gui->summary.startup_ledger_slot, gui->summary.startup_ledger_max_slot ));
      break;
    }
    case 8:
      gui->summary.startup_progress = FD_GUI_START_PROGRESS_TYPE_STARTING_SERVICES;
      FD_LOG_INFO(( "progress: starting services" ));
      break;
    case 9:
      gui->summary.startup_progress = FD_GUI_START_PROGRESS_TYPE_HALTED;
      FD_LOG_INFO(( "progress: halted" ));
      break;
    case 10: {
      gui->summary.startup_progress = FD_GUI_START_PROGRESS_TYPE_WAITING_FOR_SUPERMAJORITY;
      gui->summary.startup_waiting_for_supermajority_slot = fd_ulong_load_8( msg + 1 );
      gui->summary.startup_waiting_for_supermajority_stake_pct = fd_ulong_load_8( msg + 9 );
      FD_LOG_INFO(( "progress: waiting for supermajority: slot=%lu, gossip_stake_percent=%lu", gui->summary.startup_waiting_for_supermajority_slot, gui->summary.startup_waiting_for_supermajority_stake_pct ));
      break;
    }
    case 11:
      gui->summary.startup_progress = FD_GUI_START_PROGRESS_TYPE_RUNNING;
      FD_LOG_INFO(( "progress: running" ));
      break;
    default:
      FD_LOG_ERR(( "progress: unknown type: %u", type ));
  }

  fd_gui_printf_startup_progress( gui );
  fd_http_server_ws_broadcast( gui->http );
}

static void
fd_gui_handle_genesis_hash( fd_gui_t *    gui,
                            uchar const * msg ) {
  FD_BASE58_ENCODE_32_BYTES(msg, hash_cstr);
  ulong cluster = fd_genesis_cluster_identify(hash_cstr);
  char const * cluster_name = fd_genesis_cluster_name(cluster);

  if( FD_LIKELY( strcmp( gui->summary.cluster, cluster_name ) ) ) {
    gui->summary.cluster = fd_genesis_cluster_name(cluster);
    fd_gui_printf_cluster( gui );
    fd_http_server_ws_broadcast( gui->http );
  }
}

static void
fd_gui_handle_block_engine_update( fd_gui_t *    gui,
                                   uchar const * msg ) {
  fd_plugin_msg_block_engine_update_t const * update = (fd_plugin_msg_block_engine_update_t const *)msg;

  gui->block_engine.has_block_engine = 1;
  strncpy( gui->block_engine.name, update->name, sizeof(gui->block_engine.name) );
  strncpy( gui->block_engine.url, update->url, sizeof(gui->block_engine.url) );
  gui->block_engine.status = update->status;

  fd_gui_printf_block_engine( gui );
  fd_http_server_ws_broadcast( gui->http );
}

void
fd_gui_plugin_message( fd_gui_t *    gui,
                       ulong         plugin_msg,
                       uchar const * msg ) {

  switch( plugin_msg ) {
    case FD_PLUGIN_MSG_SLOT_ROOTED:
      fd_gui_handle_rooted_slot( gui, (ulong *)msg );
      break;
    case FD_PLUGIN_MSG_SLOT_OPTIMISTICALLY_CONFIRMED:
      fd_gui_handle_optimistically_confirmed_slot( gui, (ulong *)msg );
      break;
    case FD_PLUGIN_MSG_SLOT_COMPLETED:
      fd_gui_handle_completed_slot( gui, (ulong *)msg );
      break;
    case FD_PLUGIN_MSG_SLOT_ESTIMATED:
      gui->summary.slot_estimated = *(ulong const *)msg;
      fd_gui_printf_estimated_slot( gui );
      fd_http_server_ws_broadcast( gui->http );
      break;
    case FD_PLUGIN_MSG_LEADER_SCHEDULE: {
      fd_gui_handle_leader_schedule( gui, (ulong const *)msg );
      break;
    }
    case FD_PLUGIN_MSG_SLOT_START: {
      fd_gui_handle_slot_start( gui, (ulong *)msg );
      break;
    }
    case FD_PLUGIN_MSG_SLOT_END: {
      fd_gui_handle_slot_end( gui, (ulong *)msg );
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
    case FD_PLUGIN_MSG_SLOT_RESET: {
      fd_gui_handle_reset_slot( gui, (ulong *)msg );
      break;
    }
    case FD_PLUGIN_MSG_BALANCE: {
      fd_gui_handle_balance_update( gui, (ulong *)msg );
      break;
    }
    case FD_PLUGIN_MSG_START_PROGRESS: {
      fd_gui_handle_start_progress( gui, msg );
      break;
    }
    case FD_PLUGIN_MSG_GENESIS_HASH_KNOWN: {
      fd_gui_handle_genesis_hash( gui, msg );
      break;
    }
    case FD_PLUGIN_MSG_BLOCK_ENGINE_UPDATE: {
      fd_gui_handle_block_engine_update( gui, msg );
      break;
    }
    default:
      FD_LOG_ERR(( "Unhandled plugin msg: 0x%lx", plugin_msg ));
      break;
  }
}

void
fd_gui_became_leader( fd_gui_t * gui,
                      ulong      _slot,
                      long       start_time_nanos,
                      long       end_time_nanos,
                      ulong      max_compute_units,
                      ulong      max_microblocks ) {
  fd_gui_slot_t * slot = gui->slots[ _slot % FD_GUI_SLOTS_CNT ];
  if( FD_UNLIKELY( slot->slot!=_slot ) ) fd_gui_clear_slot( gui, _slot, ULONG_MAX );

  slot->cus.leader_start_time  = start_time_nanos;

  long tickcount = fd_tickcount();
  if( FD_LIKELY( slot->cus.reference_ticks==LONG_MAX ) ) slot->cus.reference_ticks = tickcount;
  slot->cus.reference_nanos = fd_log_wallclock() - (long)((double)(tickcount - slot->cus.reference_ticks) / fd_tempo_tick_per_ns( NULL ));

  slot->cus.leader_end_time   = end_time_nanos;
  slot->cus.max_compute_units = (uint)max_compute_units;
  if( FD_LIKELY( slot->cus.microblocks_upper_bound==USHORT_MAX ) ) slot->cus.microblocks_upper_bound = (ushort)max_microblocks;
}

void
fd_gui_unbecame_leader( fd_gui_t * gui,
                        ulong      _slot,
                        ulong      microblocks_in_slot ) {
  fd_gui_slot_t * slot = gui->slots[ _slot % FD_GUI_SLOTS_CNT ];
  if( FD_UNLIKELY( slot->slot!=_slot ) ) fd_gui_clear_slot( gui, _slot, ULONG_MAX );

  slot->cus.microblocks_upper_bound = (ushort)microblocks_in_slot;
}

void
fd_gui_execution_begin( fd_gui_t *   gui,
                        long         tickcount,
                        ulong        _slot,
                        ulong        bank_idx,
                        ulong        txn_cnt,
                        fd_txn_p_t * txns ) {
  fd_gui_slot_t * slot = gui->slots[ _slot % FD_GUI_SLOTS_CNT ];
  if( FD_UNLIKELY( slot->slot!=_slot ) ) fd_gui_clear_slot( gui, _slot, ULONG_MAX );

  if( FD_UNLIKELY( !slot->cus.has_offset[ 64UL ] ) ) slot->cus.start_offset[ 64UL ] = gui->cus.offset;
  slot->cus.has_offset[ 64UL ] = 1;
  if( FD_UNLIKELY( slot->cus.reference_ticks==LONG_MAX ) ) slot->cus.reference_ticks = tickcount;

  for( ulong i=0UL; i<txn_cnt; i++ ) {
    fd_txn_p_t * txn = &txns[ i ];

    ulong comp = fd_gui_cu_history_compress( FD_GUI_EXECUTION_TYPE_BEGIN,
                                             bank_idx,
                                             txn->pack_cu.non_execution_cus + txn->pack_cu.requested_exec_plus_acct_data_cus,
                                             i==0UL,
                                             slot->cus.reference_ticks,
                                             tickcount );
    gui->cus.history[ gui->cus.offset%FD_GUI_COMPUTE_UNITS_HISTORY_SZ ] = comp;
    gui->cus.offset++;
  }

  slot->cus.end_offset[ 64UL ] = gui->cus.offset;
  slot->cus.begin_microblocks = (ushort)(slot->cus.begin_microblocks + txn_cnt);
}

void
fd_gui_execution_end( fd_gui_t *   gui,
                      long         tickcount,
                      ulong        bank_idx,
                      int          is_last_in_bundle,
                      ulong        _slot,
                      ulong        txn_cnt,
                      fd_txn_p_t * txns ) {
  fd_gui_slot_t * slot = gui->slots[ _slot % FD_GUI_SLOTS_CNT ];
  if( FD_UNLIKELY( slot->slot!=_slot ) ) fd_gui_clear_slot( gui, _slot, ULONG_MAX );

  if( FD_UNLIKELY( !slot->cus.has_offset[ bank_idx ] ) ) slot->cus.start_offset[ bank_idx ] = gui->cus.offset;
  slot->cus.has_offset[ bank_idx ] = 1;
  if( FD_UNLIKELY( slot->cus.reference_ticks==LONG_MAX ) ) slot->cus.reference_ticks = tickcount;

  for( ulong i=0UL; i<txn_cnt; i++ ) {
    fd_txn_p_t * txn = &txns[ i ];

    ulong comp = fd_gui_cu_history_compress( FD_GUI_EXECUTION_TYPE_END,
                                             bank_idx,
                                             txn->bank_cu.rebated_cus,
                                             is_last_in_bundle,
                                             slot->cus.reference_ticks,
                                             tickcount );
    gui->cus.history[ gui->cus.offset%FD_GUI_COMPUTE_UNITS_HISTORY_SZ ] = comp;
    gui->cus.offset++;
  }

  slot->cus.end_offset[ bank_idx ] = gui->cus.offset;
  slot->cus.end_microblocks = (ushort)(slot->cus.end_microblocks + txn_cnt);
}
