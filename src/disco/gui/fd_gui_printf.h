#include "fd_gui.h"

/* These functions format the current state of the GUI as various JSON
   messages into the GUI outgoing message buffer, where they can be sent
   to a specific WebSocket client, or broadcast out to all clients. */

void fd_gui_printf_version( fd_gui_t * gui );
void fd_gui_printf_cluster( fd_gui_t * gui );
void fd_gui_printf_identity_key( fd_gui_t * gui );
void fd_gui_printf_uptime_nanos( fd_gui_t * gui );
void fd_gui_printf_vote_state( fd_gui_t * gui );
void fd_gui_printf_vote_distance( fd_gui_t * gui );
void fd_gui_printf_skipped_history( fd_gui_t * gui );
void fd_gui_printf_tps_history( fd_gui_t * gui );
void fd_gui_printf_startup_progress( fd_gui_t * gui );
void fd_gui_printf_block_engine( fd_gui_t * gui );
void fd_gui_printf_tiles( fd_gui_t * gui );
void fd_gui_printf_balance( fd_gui_t * gui );
void fd_gui_printf_estimated_slot_duration_nanos( fd_gui_t * gui );
void fd_gui_printf_root_slot( fd_gui_t * gui );
void fd_gui_printf_optimistically_confirmed_slot( fd_gui_t * gui );
void fd_gui_printf_completed_slot( fd_gui_t * gui );
void fd_gui_printf_estimated_slot( fd_gui_t * gui );
void fd_gui_printf_estimated_tps( fd_gui_t * gui );

void
fd_gui_printf_null_query_response( fd_gui_t *   gui,
                                   char const * topic,
                                   char const * key,
                                   ulong        id );

void
fd_gui_printf_skip_rate( fd_gui_t * gui,
                         ulong      epoch_idx );

void
fd_gui_printf_epoch( fd_gui_t * gui,
                     ulong      epoch_idx );

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
fd_gui_printf_live_tile_timers( fd_gui_t * gui );

void
fd_gui_printf_live_txn_waterfall( fd_gui_t *                     gui,
                                  fd_gui_txn_waterfall_t const * prev,
                                  fd_gui_txn_waterfall_t const * cur,
                                  ulong                          next_leader_slot );

void
fd_gui_printf_live_tile_stats( fd_gui_t *                  gui,
                               fd_gui_tile_stats_t const * prev,
                               fd_gui_tile_stats_t const * cur );
