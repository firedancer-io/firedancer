#include "fd_gui.h"

void fd_gui_printf_version( fd_gui_t * gui );
void fd_gui_printf_cluster( fd_gui_t * gui );
void fd_gui_printf_identity_key( fd_gui_t * gui );
void fd_gui_printf_root_slot( fd_gui_t * gui );
void fd_gui_printf_optimistically_confirmed_slot( fd_gui_t * gui );
void fd_gui_printf_completed_slot( fd_gui_t * gui );
void fd_gui_printf_estimated_slot( fd_gui_t * gui );
void fd_gui_printf_topology( fd_gui_t * gui );
void fd_gui_printf_epoch1( fd_gui_t * gui );
void fd_gui_printf_epoch2( fd_gui_t * gui );
void fd_gui_printf_txn_info_summary( fd_gui_t * gui );
void fd_gui_printf_tile_info( fd_gui_t * gui );

void fd_gui_printf_epoch( fd_gui_t * gui, ulong epoch_idx );

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
