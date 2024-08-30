#include "fd_gui.h"

void fd_gui_printf_version( fd_gui_t * gui );
void fd_gui_printf_cluster( fd_gui_t * gui );
void fd_gui_printf_identity_key( fd_gui_t * gui );
void fd_gui_printf_uptime_nanos( fd_gui_t * gui );
void fd_gui_printf_skipped_history( fd_gui_t * gui );
void fd_gui_printf_tps_history( fd_gui_t * gui );
void fd_gui_printf_startup_progress( fd_gui_t * gui );
void fd_gui_printf_tiles( fd_gui_t * gui );
void fd_gui_printf_balance( fd_gui_t * gui );
void fd_gui_printf_estimated_slot_duration_nanos( fd_gui_t * gui );
void fd_gui_printf_root_slot( fd_gui_t * gui );
void fd_gui_printf_optimistically_confirmed_slot( fd_gui_t * gui );
void fd_gui_printf_completed_slot( fd_gui_t * gui );
void fd_gui_printf_estimated_slot( fd_gui_t * gui );
void fd_gui_printf_estimated_tps( fd_gui_t * gui );
void fd_gui_printf_estimated_vote_tps( fd_gui_t * gui );
void fd_gui_printf_estimated_nonvote_tps( fd_gui_t * gui );
void fd_gui_printf_estimated_failed_tps( fd_gui_t * gui );

void
fd_gui_printf_null_query_response( fd_gui_t *   gui,
                                   char const * topic,
                                   char const * key,
                                   ulong        id );

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
fd_gui_printf_slot_request( fd_gui_t * gui,
                            ulong      slot,
                            ulong      id );

void
fd_gui_printf_live_tile_timers( fd_gui_t * gui );

void
fd_gui_printf_live_txn_waterfall( fd_gui_t *               gui,
                                  fd_gui_txn_waterfall_t * prev,
                                  fd_gui_txn_waterfall_t * cur,
                                  ulong                    next_leader_slot );

void
fd_gui_printf_live_tile_prime_metric( fd_gui_t *                   gui,
                                      fd_gui_tile_prime_metric_t * prev,
                                      fd_gui_tile_prime_metric_t * cur,
                                      ulong                        next_leader_slot );