#ifndef HEADER_fd_src_flamenco_runtime_program_fd_bpf_loader_v3_program_h
#define HEADER_fd_src_flamenco_runtime_program_fd_bpf_loader_v3_program_h

/* fd_bpf_loader_v3_program.h is the third version of the BPF loader
   program.

   Address: BPFLoaderUpgradeab1e11111111111111111111111 */


#include "../../fd_flamenco_base.h"
#include "../fd_executor.h"
#include "../fd_runtime.h"
#include "fd_bpf_loader_serialization.h"

#define BUFFER_METADATA_SIZE  (37)
#define PROGRAMDATA_METADATA_SIZE (45UL)
#define SIZE_OF_PROGRAM (36)
#define SIZE_OF_UNINITIALIZED (4)

FD_PROTOTYPES_BEGIN

int
fd_executor_bpf_upgradeable_loader_program_is_executable_program_account( fd_exec_slot_ctx_t * slot_ctx,
                                                                          fd_pubkey_t const * pubkey );

/* fd_bpf_loader_v3_program_execute processes an execution of the
   BPF Loader v3 itself. */

int
fd_bpf_loader_v3_program_execute( fd_exec_instr_ctx_t ctx );

/* fd_bpf_loader_v3_user_execute processes an execution of a program
   owner by the BPF Loader v3. */

int
fd_bpf_loader_v3_user_execute( fd_exec_instr_ctx_t ctx );

fd_account_meta_t const *
read_bpf_upgradeable_loader_state_for_program( fd_exec_txn_ctx_t * txn_ctx,
                                               uchar program_id,
                                               fd_bpf_upgradeable_loader_state_t * result,
                                               int * opt_err );
FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_runtime_program_fd_bpf_loader_v3_program_h */
