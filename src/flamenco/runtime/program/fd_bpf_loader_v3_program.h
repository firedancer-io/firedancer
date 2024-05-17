#ifndef HEADER_fd_src_flamenco_runtime_program_fd_bpf_loader_v3_program_h
#define HEADER_fd_src_flamenco_runtime_program_fd_bpf_loader_v3_program_h

/* fd_bpf_loader_v3_program.h is the third version of the BPF loader
   program.

   Address: BPFLoaderUpgradeab1e11111111111111111111111 */

#include "../fd_account.h"

#define DEFAULT_LOADER_COMPUTE_UNITS     (570UL )
#define DEPRECATED_LOADER_COMPUTE_UNITS  (1140UL)
#define UPGRADEABLE_LOADER_COMPUTE_UNITS (2370UL)
#define SIZE_OF_PROGRAM                  (36UL  ) /* UpgradeableLoaderState::size_of_program() */
#define BUFFER_METADATA_SIZE             (37UL  ) /* UpgradeableLoaderState::size_of_buffer_metadata() */
#define PROGRAMDATA_METADATA_SIZE        (45UL  ) /* UpgradeableLoaderState::size_of_programdata_metadata() */
#define SIZE_OF_UNINITIALIZED            (4UL   ) /* UpgradeableLoaderState::size_of_uninitialized() */

FD_PROTOTYPES_BEGIN

/* fd_bpf_loader_v3_is_executable returns 0 if the account with the
   given pubkey is an executable BPF Loader v3 user program.  Otherwise,
   returns an FD_EXECUTOR_INSTR_ERR_{...} code. */

int
fd_bpf_loader_v3_is_executable( fd_exec_slot_ctx_t * slot_ctx,
                                fd_pubkey_t const *  pubkey );

/* fd_bpf_loader_v3_program_execute is the shared entry point for bpf 
   user-defined programs as well as executions of the program itself. */

int
fd_bpf_loader_v3_program_execute( fd_exec_instr_ctx_t instr_ctx );

/* TODO: add comment here */

fd_account_meta_t const *
read_bpf_upgradeable_loader_state_for_program( fd_exec_txn_ctx_t * txn_ctx,
                                               uchar program_id,
                                               fd_bpf_upgradeable_loader_state_t * result,
                                               int * opt_err );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_runtime_program_fd_bpf_loader_v3_program_h */
