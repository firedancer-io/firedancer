#include "../../util/fd_util.h"


extern void fd_ext_validator_main( const char ** args FD_PARAM_UNUSED ) {}
extern void fd_ext_genesis_main( const char ** args FD_PARAM_UNUSED ) {}

extern void * fd_ext_bank_pre_balance_info( void const * bank FD_PARAM_UNUSED, void * txns FD_PARAM_UNUSED, ulong txn_cnt FD_PARAM_UNUSED ) { return NULL; }
extern void * fd_ext_bank_load_and_execute_txns( void const * bank FD_PARAM_UNUSED, void * txns FD_PARAM_UNUSED, ulong txn_cnt FD_PARAM_UNUSED, int * out_load_results FD_PARAM_UNUSED, int * out_executing_results FD_PARAM_UNUSED, int * out_executed_results FD_PARAM_UNUSED ) { return NULL; }
extern void fd_ext_bank_acquire( void const * bank FD_PARAM_UNUSED ) {}
extern void fd_ext_bank_release( void const * bank FD_PARAM_UNUSED ) {}
extern void fd_ext_bank_release_thunks( void * load_and_execute_output FD_PARAM_UNUSED ) {}
extern void fd_ext_bank_release_pre_balance_info( void * pre_balance_info FD_PARAM_UNUSED ) {}

extern void fd_ext_bank_commit_txns( void const * bank FD_PARAM_UNUSED, void const * txns FD_PARAM_UNUSED, ulong txn_cnt FD_PARAM_UNUSED, void * load_and_execute_output FD_PARAM_UNUSED, void * pre_balance_info FD_PARAM_UNUSED ) {}
extern void fd_ext_poh_signal_leader_change( void * sender FD_PARAM_UNUSED ) {}
extern void fd_ext_poh_register_tick( void const * bank FD_PARAM_UNUSED, uchar const * hash FD_PARAM_UNUSED ) {}

extern int
fd_ext_blockstore_insert_shreds( void const *  blockstore FD_PARAM_UNUSED,
                                 ulong         shred_cnt FD_PARAM_UNUSED,
                                 uchar const * shred_bytes FD_PARAM_UNUSED,
                                 ulong         shred_sz FD_PARAM_UNUSED,
                                 ulong         stride FD_PARAM_UNUSED ) { return 0; }

extern int
fd_ext_bank_sanitized_txn_load_addresess( void const * bank FD_PARAM_UNUSED,
                                          void *       address_table_lookups FD_PARAM_UNUSED,
                                          ulong        address_table_lookups_cnt FD_PARAM_UNUSED,
                                          void *       out_sidecar FD_PARAM_UNUSED ) { return 0; }

extern void
fd_ext_blockstore_create_block0( char const *  ledger_path FD_PARAM_UNUSED,
                                 ulong         shred_cnt FD_PARAM_UNUSED,
                                 uchar const * shred_bytes FD_PARAM_UNUSED,
                                 ulong         shred_sz FD_PARAM_UNUSED,
                                 ulong         stride FD_PARAM_UNUSED ) {}
