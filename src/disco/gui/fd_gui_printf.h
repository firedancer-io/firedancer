#ifndef HEADER_fd_src_disco_gui_fd_gui_printf_h
#define HEADER_fd_src_disco_gui_fd_gui_printf_h

#include "fd_gui.h"

/* These functions format the current state of the GUI as various JSON
   messages into the GUI outgoing message buffer, where they can be sent
   to a specific WebSocket client, or broadcast out to all clients. */

void fd_gui_printf_version( fd_gui_t * gui );
void fd_gui_printf_cluster( fd_gui_t * gui );
void fd_gui_printf_commit_hash( fd_gui_t * gui );
void fd_gui_printf_identity_key( fd_gui_t * gui );
void fd_gui_printf_vote_key( fd_gui_t * gui );
void fd_gui_printf_startup_time_nanos( fd_gui_t * gui );
void fd_gui_printf_vote_state( fd_gui_t * gui );
void fd_gui_printf_vote_distance( fd_gui_t * gui );
void fd_gui_printf_turbine_slot( fd_gui_t * gui );
void fd_gui_printf_repair_slot( fd_gui_t * gui );
void fd_gui_printf_slot_caught_up( fd_gui_t * gui );
void fd_gui_printf_skipped_history( fd_gui_t * gui );
void fd_gui_printf_skipped_history_cluster( fd_gui_t * gui );
void fd_gui_printf_tps_history( fd_gui_t * gui );
void fd_gui_printf_startup_progress( fd_gui_t * gui );
void fd_gui_printf_boot_progress( fd_gui_t * gui );
void fd_gui_printf_block_engine( fd_gui_t * gui );
void fd_gui_printf_tiles( fd_gui_t * gui );
void fd_gui_printf_schedule_strategy( fd_gui_t * gui );
void fd_gui_printf_identity_balance( fd_gui_t * gui );
void fd_gui_printf_vote_balance( fd_gui_t * gui );
void fd_gui_printf_estimated_slot_duration_nanos( fd_gui_t * gui );
void fd_gui_printf_root_slot( fd_gui_t * gui );
void fd_gui_printf_optimistically_confirmed_slot( fd_gui_t * gui );
void fd_gui_printf_completed_slot( fd_gui_t * gui );
void fd_gui_printf_estimated_slot( fd_gui_t * gui );
void fd_gui_printf_estimated_tps( fd_gui_t * gui );
void fd_gui_printf_shred_updates( fd_gui_t * gui );
void fd_gui_printf_catch_up_history( fd_gui_t * gui );
void fd_gui_peers_printf_vote_slot( fd_gui_peers_ctx_t * peers );

void
fd_gui_printf_null_query_response( fd_http_server_t * http,
                                   char const *       topic,
                                   char const *       key,
                                   ulong              id );

void
fd_gui_printf_skip_rate( fd_gui_t * gui,
                         ulong      epoch_idx );

void
fd_gui_printf_epoch( fd_gui_t * gui,
                     ulong      epoch_idx );

void
fd_gui_peers_printf_nodes( fd_gui_peers_ctx_t *  peers,
                           int *                 actions,
                           ulong *               idxs,
                           ulong                 count );

void
fd_gui_peers_printf_node_all( fd_gui_peers_ctx_t *  peers );

void
fd_gui_printf_peers_gossip_update( fd_gui_t *          gui,
                                   ulong const *       updated,
                                   ulong               updated_cnt,
                                   fd_pubkey_t const * removed,
                                   ulong               removed_cnt,
                                   ulong const *       added,
                                   ulong               added_cnt );

void
fd_gui_printf_peers_vote_account_update( fd_gui_t *          gui,
                                         ulong const *       updated,
                                         ulong               updated_cnt,
                                         fd_pubkey_t const * removed,
                                         ulong               removed_cnt,
                                         ulong const *       added,
                                         ulong               added_cnt );

void
fd_gui_printf_peers_validator_info_update( fd_gui_t *          gui,
                                           ulong const *       updated,
                                           ulong               updated_cnt,
                                           fd_pubkey_t const * removed,
                                           ulong               removed_cnt,
                                           ulong const *       added,
                                           ulong               added_cnt );

void
fd_gui_printf_peers_all( fd_gui_t * gui );

void
fd_gui_printf_slot( fd_gui_t * gui,
                    ulong      slot );

void
fd_gui_printf_summary_ping( fd_gui_t * gui,
                            ulong      id );

void
fd_gui_printf_slot_request( fd_gui_t * gui,
                            ulong      slot,
                            ulong      id );

void
fd_gui_printf_slot_rankings_request( fd_gui_t * gui,
                                     ulong      id,
                                     int        mine );


void
fd_gui_printf_slot_request_detailed( fd_gui_t * gui,
                                     ulong      slot,
                                     ulong      id );

void
fd_gui_printf_slot_transactions_request( fd_gui_t * gui,
                                         ulong      _slot,
                                         ulong      id );

void
fd_gui_printf_slot_shred_updates( fd_gui_t * gui,
                                  ulong      _slot,
                                  ulong      id );

void
fd_gui_printf_live_tile_timers( fd_gui_t * gui );

void
fd_gui_printf_live_network_metrics( fd_gui_t *                     gui,
                                    fd_gui_network_stats_t const * cur );

void
fd_gui_printf_live_tile_metrics( fd_gui_t * gui );

void
fd_gui_printf_live_txn_waterfall( fd_gui_t *                     gui,
                                  fd_gui_txn_waterfall_t const * prev,
                                  fd_gui_txn_waterfall_t const * cur,
                                  ulong                          next_leader_slot );

void
fd_gui_printf_live_tile_stats( fd_gui_t *                  gui,
                               fd_gui_tile_stats_t const * prev,
                               fd_gui_tile_stats_t const * cur );

void
fd_gui_printf_peers_viewport_update( fd_gui_peers_ctx_t *  peers,
                                     ulong                 ws_conn_id );

void
fd_gui_printf_peers_viewport_request( fd_gui_peers_ctx_t *  peers,
                                      char const *          key,
                                      ulong                 ws_conn_id,
                                      ulong                 request_id );

void
fd_gui_printf_peers_view_resize( fd_gui_peers_ctx_t *  peers, ulong sz );

void
fd_gui_peers_printf_gossip_stats( fd_gui_peers_ctx_t *  peers );

#endif /* HEADER_fd_src_disco_gui_fd_gui_printf_h */
