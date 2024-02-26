#ifndef HEADER_fd_src_flamenco_runtime_program_fd_system_program_h
#define HEADER_fd_src_flamenco_runtime_program_fd_system_program_h

#include "../../fd_flamenco_base.h"
#include "../fd_executor.h"

/* Custom error types */

#define FD_SYSTEM_PROGRAM_ERR_ACCT_ALREADY_IN_USE              (0)  /* SystemError::AccountAlreadyInUse */
#define FD_SYSTEM_PROGRAM_ERR_RESULT_WITH_NEGATIVE_LAMPORTS    (1)  /* SystemError::ResultWithNegativeLamports */
#define FD_SYSTEM_PROGRAM_ERR_INVALID_PROGRAM_ID               (2)  /* SystemError::InvalidProgramId */
#define FD_SYSTEM_PROGRAM_ERR_INVALID_ACCT_DATA_LEN            (3)  /* SystemError::InvalidAccountDataLength */
#define FD_SYSTEM_PROGRAM_ERR_MAX_SEED_LEN_EXCEEDED            (4)  /* SystemError::MaxSeedLengthExceeded */
#define FD_SYSTEM_PROGRAM_ERR_ADDR_WITH_SEED_MISMATCH          (5)  /* SystemError::AddressWithSeedMismatch */
#define FD_SYSTEM_PROGRAM_ERR_NONCE_NO_RECENT_BLOCKHASHES      (6)  /* SystemError::NonceNoRecentBlockhashes */
#define FD_SYSTEM_PROGRAM_ERR_NONCE_BLOCKHASH_NOT_EXPIRED      (7)  /* SystemError::NonceBlockhashNotExpired */
#define FD_SYSTEM_PROGRAM_ERR_NONCE_UNEXPECTED_BLOCKHASH_VALUE (8)  /* SystemError::NonceUnexpectedBlockhashValue */

FD_PROTOTYPES_BEGIN

/* fd_system_program_execute is the entrypoint for the system program */

int fd_system_program_execute( fd_exec_instr_ctx_t ctx ) ;

/* System program instruction handlers */

int fd_system_program_exec_create_account          ( fd_exec_instr_ctx_t * ctx, fd_system_program_instruction_create_account_t const *           data     );
int fd_system_program_exec_assign                  ( fd_exec_instr_ctx_t * ctx, fd_pubkey_t const *                                              owner    );
int fd_system_program_exec_transfer                ( fd_exec_instr_ctx_t * ctx, ulong                                                            lamports );
int fd_system_program_exec_create_account_with_seed( fd_exec_instr_ctx_t * ctx, fd_system_program_instruction_create_account_with_seed_t const * data     );
int fd_system_program_exec_advance_nonce_account   ( fd_exec_instr_ctx_t * ctx                                                                            );
int fd_system_program_exec_withdraw_nonce_account  ( fd_exec_instr_ctx_t * ctx, ulong                                                            lamports );
int fd_system_program_exec_initialize_nonce_account( fd_exec_instr_ctx_t * ctx, fd_pubkey_t const *                                              pubkey   );
int fd_system_program_exec_authorize_nonce_account ( fd_exec_instr_ctx_t * ctx, fd_pubkey_t const *                                              pubkey   );
int fd_system_program_exec_allocate                ( fd_exec_instr_ctx_t * ctx, ulong                                                            space    );
int fd_system_program_exec_allocate_with_seed      ( fd_exec_instr_ctx_t * ctx, fd_system_program_instruction_allocate_with_seed_t const *       data     );
int fd_system_program_exec_assign_with_seed        ( fd_exec_instr_ctx_t * ctx, fd_system_program_instruction_assign_with_seed_t const *         data     );
int fd_system_program_exec_transfer_with_seed      ( fd_exec_instr_ctx_t * ctx, fd_system_program_instruction_transfer_with_seed_t const *       data     );
int fd_system_program_exec_upgrade_nonce_account   ( fd_exec_instr_ctx_t * ctx                                                                            );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_runtime_program_fd_system_program_h */
