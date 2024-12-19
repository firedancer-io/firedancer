#ifndef HEADER_fd_src_flamenco_runtime_program_fd_bpf_loader_program_h
#define HEADER_fd_src_flamenco_runtime_program_fd_bpf_loader_program_h

/* fd_bpf_loader_v3_program.h is the third version of the BPF loader
   program.

   Address: BPFLoaderUpgradeab1e11111111111111111111111 */

#include "../fd_account.h"
#include "fd_bpf_program_util.h"

#define DEFAULT_LOADER_COMPUTE_UNITS     (570UL )
#define DEPRECATED_LOADER_COMPUTE_UNITS  (1140UL)
#define UPGRADEABLE_LOADER_COMPUTE_UNITS (2370UL)
#define SIZE_OF_PROGRAM                  (36UL  ) /* UpgradeableLoaderState::size_of_program() */
#define BUFFER_METADATA_SIZE             (37UL  ) /* UpgradeableLoaderState::size_of_buffer_metadata() */
#define PROGRAMDATA_METADATA_SIZE        (45UL  ) /* UpgradeableLoaderState::size_of_programdata_metadata() */
#define SIZE_OF_UNINITIALIZED            (4UL   ) /* UpgradeableLoaderState::size_of_uninitialized() */

/* InstructionError conversions 
   https://github.com/anza-xyz/agave/blob/ced98f1ebe73f7e9691308afa757323003ff744f/sdk/program/src/program_error.rs#L127-L160 */
#define BUILTIN_BIT_SHIFT                           (32UL)

#define CUSTOM_ZERO                                 ((1UL)  << BUILTIN_BIT_SHIFT)
#define INVALID_ARGUMENT                            ((2UL)  << BUILTIN_BIT_SHIFT)
#define INVALID_INSTRUCTION_DATA                    ((3UL)  << BUILTIN_BIT_SHIFT)
#define INVALID_ACCOUNT_DATA                        ((4UL)  << BUILTIN_BIT_SHIFT)
#define ACCOUNT_DATA_TOO_SMALL                      ((5UL)  << BUILTIN_BIT_SHIFT)
#define INSUFFICIENT_FUNDS                          ((6UL)  << BUILTIN_BIT_SHIFT)
#define INCORRECT_PROGRAM_ID                        ((7UL)  << BUILTIN_BIT_SHIFT)
#define MISSING_REQUIRED_SIGNATURES                 ((8UL)  << BUILTIN_BIT_SHIFT)
#define ACCOUNT_ALREADY_INITIALIZED                 ((9UL)  << BUILTIN_BIT_SHIFT)
#define UNINITIALIZED_ACCOUNT                       ((10UL) << BUILTIN_BIT_SHIFT)
#define NOT_ENOUGH_ACCOUNT_KEYS                     ((11UL) << BUILTIN_BIT_SHIFT)
#define ACCOUNT_BORROW_FAILED                       ((12UL) << BUILTIN_BIT_SHIFT)
#define MAX_SEED_LENGTH_EXCEEDED                    ((13UL) << BUILTIN_BIT_SHIFT)
#define INVALID_SEEDS                               ((14UL) << BUILTIN_BIT_SHIFT)
#define BORSH_IO_ERROR                              ((15UL) << BUILTIN_BIT_SHIFT)
#define ACCOUNT_NOT_RENT_EXEMPT                     ((16UL) << BUILTIN_BIT_SHIFT)
#define UNSUPPORTED_SYSVAR                          ((17UL) << BUILTIN_BIT_SHIFT)
#define ILLEGAL_OWNER                               ((18UL) << BUILTIN_BIT_SHIFT)
#define MAX_ACCOUNTS_DATA_ALLOCATIONS_EXCEEDED      ((19UL) << BUILTIN_BIT_SHIFT)
#define INVALID_ACCOUNT_DATA_REALLOC                ((20UL) << BUILTIN_BIT_SHIFT)
#define MAX_INSTRUCTION_TRACE_LENGTH_EXCEEDED       ((21UL) << BUILTIN_BIT_SHIFT)
#define BUILTIN_PROGRAMS_MUST_CONSUME_COMPUTE_UNITS ((22UL) << BUILTIN_BIT_SHIFT)
#define INVALID_ACCOUNT_OWNER                       ((23UL) << BUILTIN_BIT_SHIFT)
#define ARITHMETIC_OVERFLOW                         ((24UL) << BUILTIN_BIT_SHIFT)
#define IMMUTABLE                                   ((25UL) << BUILTIN_BIT_SHIFT)
#define INCORRECT_AUTHORITY                         ((26UL) << BUILTIN_BIT_SHIFT)

FD_PROTOTYPES_BEGIN

int
fd_bpf_loader_v3_program_get_state( fd_exec_instr_ctx_t const *         instr_ctx,
                                    fd_borrowed_account_t const *       borrowed_acc,
                                    fd_bpf_upgradeable_loader_state_t * state );

int
fd_deploy_program( fd_exec_instr_ctx_t * instr_ctx,
                   uchar const *         programdata,
                   ulong                 programdata_size,
                   fd_valloc_t           valloc );

int
fd_bpf_execute( fd_exec_instr_ctx_t * instr_ctx, fd_sbpf_validated_program_t * prog, uchar is_deprecated );

int
fd_bpf_loader_program_execute( fd_exec_instr_ctx_t * instr_ctx );

/* TODO: add comment here */

fd_account_meta_t const *
read_bpf_upgradeable_loader_state_for_program( fd_exec_txn_ctx_t * txn_ctx,
                                               uchar program_id,
                                               fd_bpf_upgradeable_loader_state_t * result,
                                               int * opt_err );

/* Public APIs */

/* This function is called from `fd_runtime.c` and only performs the ELF and VM validation checks necessary
   to deploy a program, specifically for the core native program BPF migration. Since this call is done at 
   the epoch boundary every time a new BPF core migration feature is activated, we need to mock up a transaction 
   and instruction context for execution. We do not do any funk operations here - instead, the BPF cache entry
   will be created at the end of the block. Because of this, our logic is slightly different than Agave's.
   See the documentation for our `fd_deploy_program` for more information.

   https://github.com/anza-xyz/agave/blob/v2.1.0/runtime/src/bank/builtins/core_bpf_migration/mod.rs#L155-L233 */
int
fd_directly_invoke_loader_v3_deploy( fd_exec_slot_ctx_t * slot_ctx,
                                     uchar const *          elf,
                                     ulong                elf_sz );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_runtime_program_fd_bpf_loader_program_h */
