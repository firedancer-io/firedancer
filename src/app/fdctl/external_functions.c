#include "../../util/fd_util.h"


extern void fd_ext_validator_main( const char ** args FD_PARAM_UNUSED ) {}
extern void fd_ext_genesis_main( const char ** args FD_PARAM_UNUSED ) {}

extern void * fd_ext_bank_pre_balance_info( void const * bank FD_PARAM_UNUSED, void * txns FD_PARAM_UNUSED, ulong txn_cnt FD_PARAM_UNUSED ) { return NULL; }
extern int  fd_ext_bank_execute_and_commit_bundle( void const * bank FD_PARAM_UNUSED, void * txns FD_PARAM_UNUSED, ulong txn_cnt FD_PARAM_UNUSED, int * out_transaction_err FD_PARAM_UNUSED, uint * actual_execution_cus FD_PARAM_UNUSED, uint * actual_acct_data_cus FD_PARAM_UNUSED ) { return 0; }
extern void * fd_ext_bank_load_and_execute_txns( void const * bank FD_PARAM_UNUSED, void * txns FD_PARAM_UNUSED, ulong txn_cnt FD_PARAM_UNUSED, int * out_load_results FD_PARAM_UNUSED, int * out_executing_results FD_PARAM_UNUSED, int * out_executed_results FD_PARAM_UNUSED, uint * out_consumed_exec_cus FD_PARAM_UNUSED, uint * out_consumed_acct_data_cus FD_PARAM_UNUSED ) { return NULL; }
extern void fd_ext_bank_acquire( void const * bank FD_PARAM_UNUSED ) {}
extern void fd_ext_bank_release( void const * bank FD_PARAM_UNUSED ) {}
extern void fd_ext_bank_release_thunks( void * load_and_execute_output FD_PARAM_UNUSED ) {}
extern void fd_ext_bank_release_pre_balance_info( void * pre_balance_info FD_PARAM_UNUSED ) {}
extern int  fd_ext_bank_verify_precompiles( void const * bank FD_PARAM_UNUSED, void const * txn FD_PARAM_UNUSED) { return 0; }

extern int fd_ext_admin_rpc_set_identity( uchar const * identity_keypair FD_PARAM_UNUSED, int require_tower FD_PARAM_UNUSED ) { return 0; }

extern int
fd_ext_bank_load_account( void const *  bank FD_PARAM_UNUSED,
                          uchar const * addr FD_PARAM_UNUSED,
                          uchar *       owner FD_PARAM_UNUSED,
                          uchar *       data FD_PARAM_UNUSED,
                          ulong *       data_sz FD_PARAM_UNUSED ) { return 0; }

extern void fd_ext_bank_commit_txns( void const * bank FD_PARAM_UNUSED, void const * txns FD_PARAM_UNUSED, ulong txn_cnt FD_PARAM_UNUSED, void * load_and_execute_output FD_PARAM_UNUSED, void * pre_balance_info FD_PARAM_UNUSED ) {}
extern void fd_ext_poh_signal_leader_change( void * sender FD_PARAM_UNUSED ) {}
extern void fd_ext_poh_register_tick( void const * bank FD_PARAM_UNUSED, uchar const * hash FD_PARAM_UNUSED ) {}

extern int
fd_ext_blockstore_insert_shreds( void const *  blockstore FD_PARAM_UNUSED,
                                 ulong         shred_cnt FD_PARAM_UNUSED,
                                 uchar const * shred_bytes FD_PARAM_UNUSED,
                                 ulong         shred_sz FD_PARAM_UNUSED,
                                 ulong         stride FD_PARAM_UNUSED,
                                 int           is_trusted FD_PARAM_UNUSED ) { return 0; }

extern void
fd_ext_blockstore_create_block0( char const *  ledger_path FD_PARAM_UNUSED,
                                 ulong         shred_cnt FD_PARAM_UNUSED,
                                 uchar const * shred_bytes FD_PARAM_UNUSED,
                                 ulong         shred_sz FD_PARAM_UNUSED,
                                 ulong         stride FD_PARAM_UNUSED ) {}


extern void
plugin_bundle_poll( void *  plugin FD_PARAM_UNUSED,
                    int     reload_identity FD_PARAM_UNUSED,
                    uchar * identity_pubkey FD_PARAM_UNUSED,
                    int *   out_type FD_PARAM_UNUSED,
                    uchar * out_block_builder_pubkey FD_PARAM_UNUSED,
                    ulong * out_block_builder_commission FD_PARAM_UNUSED,
                    ulong * out_bundle_len FD_PARAM_UNUSED,
                    uchar * out_data FD_PARAM_UNUSED ) {}

extern void *
plugin_bundle_init( char const * url FD_PARAM_UNUSED,
                    char const * domain_name FD_PARAM_UNUSED,
                    uchar *      identity_pubkey FD_PARAM_UNUSED ) { return NULL; }
