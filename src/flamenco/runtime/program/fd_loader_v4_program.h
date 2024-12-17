#ifndef HEADER_fd_src_flamenco_runtime_program_fd_loader_v4_program_h
#define HEADER_fd_src_flamenco_runtime_program_fd_loader_v4_program_h

#include "../../fd_flamenco_base.h"
#include "../context/fd_exec_instr_ctx.h"
#include "../fd_system_ids.h"
#include "../fd_executor.h"
#include "../sysvar/fd_sysvar_rent.h"
#include "../fd_account.h"
#include "fd_bpf_loader_program.h"

/* 
  Notes about loader v4 since it differs slightly from the previous BPF v3 loader...
    - There are three possible states for a loader v4 program:
      - Retracted
        - This name is a little bit misleading since it applies to programs that are either in the process of deployment,
          or already deployed and in maintenance (and thus cannot be invoked).
      - Deployed
        - This is the normal state for a program that is ready to be invoked.
        - Programs cannot be retracted within `LOADER_V4_DEPLOYMENT_COOLDOWN_IN_SLOTS` (750) slots of deployment.
      - Finalized
        - The program is immutable.
        - Users must specify a "next version" which, from my inspection, serves no functional purpose besides showing up
          as extra information on a block explorer.
    - There is no longer a concept of a program account vs. a program data account. The program account is the program data account.
      - "Look at me... I'm the programdata account now..."
    - Buffer accounts are no longer necessary. Instead, the `write` instruction writes directly into the program account.
      - Optionally, when calling `deploy`, the user can provide a source buffer account to overwrite the program data
        instead of calling retract -> write -> deploy.
      - There is no direct `upgrade` instruction anymore. The user must either retract the program, truncate / write new bytes, and redeploy,
        or write new bytes to a source buffer account and call `deploy`.
    - There is no `close` instruction anymore. Instead, the user must call `truncate` with a new size of 0 bytes, which automatically closes the program account
      and resets it into an uninitialized state.
*/

/* https://github.com/anza-xyz/agave/blob/v2.1.4/builtins-default-costs/src/lib.rs#L33 */
#define LOADER_V4_DEFAULT_COMPUTE_UNITS (2000UL)

/* https://github.com/anza-xyz/agave/blob/v2.1.4/sdk/program/src/loader_v4.rs#L15 */
#define LOADER_V4_DEPLOYMENT_COOLDOWN_IN_SLOTS (750UL)

/* https://github.com/anza-xyz/agave/blob/v2.1.4/sdk/program/src/loader_v4.rs#L46-L49 */
#define LOADER_V4_PROGRAM_DATA_OFFSET (48UL)

/* Serization / deserialization done for the loader v4 state is done using a `std::mem::transmute()` instead of using
   the standard bincode deserialization. The key difference of doing this is that state deserialization does not fail
   if the `status` enum within the state is invalid (Retracted, Deployed, Finalized). To stay conformant with their semantics,
   we represent `status` as a ulong (intentionally instead of a uint because Agave uses `repr(u64)`) and use direct pointer
   reinterpretation to decode and encode data between the program account and the state object. It also keeps the type size
   consistent with Agave's for safe transmute operations.

   https://github.com/anza-xyz/agave/blob/09ef71223b24e30e59eaeaf5eb95e85f222c7de1/sdk/program/src/loader_v4.rs#L16-L26 */
#define FD_LOADER_V4_STATUS_ENUM_RETRACTED (0UL)
#define FD_LOADER_V4_STATUS_ENUM_DELOYED   (1UL)
#define FD_LOADER_V4_STATUS_ENUM_FINALIZED (2UL)

/* This MUST hold true for safety and conformance. */
FD_STATIC_ASSERT( sizeof(fd_loader_v4_state_t)==LOADER_V4_PROGRAM_DATA_OFFSET, loader_v4 );

FD_PROTOTYPES_BEGIN

FD_FN_PURE uchar
fd_loader_v4_status_is_deployed( fd_loader_v4_state_t const * state );

FD_FN_PURE uchar
fd_loader_v4_status_is_retracted( fd_loader_v4_state_t const * state );

FD_FN_PURE uchar
fd_loader_v4_status_is_finalized( fd_loader_v4_state_t const * state );

int
fd_loader_v4_get_state( fd_borrowed_account_t const * program,
                        fd_loader_v4_state_t *        state );

int
fd_loader_v4_program_execute( fd_exec_instr_ctx_t * instr_ctx );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_runtime_program_fd_loader_v4_program_h */
