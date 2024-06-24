#ifndef HEADER_fd_src_flamenco_vm_syscall_fd_vm_syscall_h
#define HEADER_fd_src_flamenco_vm_syscall_fd_vm_syscall_h

#include "../fd_vm_context.h"

/* FIXME: CONSIDER NOT PREFIXING SYSCALLS WITH SOL_? (OR MAYBE THIS
   IS NECESSARY TO DISAMBIGUATE SOLANA SYSCALLS FROM NON-SOLANA?
   SYSCALLS? */

/* TODO These syscall errors do not map exactly to Labs SyscallError */

#define FD_VM_SYSCALL_SUCCESS           (0UL)
#define FD_VM_SYSCALL_ERR_ABORT         (1UL)
#define FD_VM_SYSCALL_ERR_PANIC         (2UL)
#define FD_VM_SYSCALL_ERR_MEM_OVERLAP   (3UL)
#define FD_VM_SYSCALL_ERR_INVAL         (4UL)
#define FD_VM_SYSCALL_ERR_INSTR_ERR     (5UL)
#define FD_VM_SYSCALL_ERR_INVOKE_CONTEXT_BORROW_FAILED (6UL)
#define FD_VM_SYSCALL_ERR_RETURN_DATA_TOO_LARGE        (7UL)
#define FD_VM_SYSCALL_ERR_TOO_MANY_SIGNERS             (8UL)
#define FD_VM_SYSCALL_ERR_UNIMPLEMENTED (0xFFFFUL) /* TODO: remove when unused */

/* FIXME: NAME */

#define MAX_RETURN_DATA                 (1024UL)

#define FD_VM_SYSCALL_DECL(name)     \
int                                  \
fd_vm_syscall_##name ( void *  _ctx, \
                       ulong   arg0, \
                       ulong   arg1, \
                       ulong   arg2, \
                       ulong   arg3, \
                       ulong   arg4, \
                       ulong * _ret )

FD_PROTOTYPES_BEGIN

/* Registers a syscall by name to an execution context. */

void
fd_vm_register_syscall( fd_sbpf_syscalls_t *   syscalls,
                        char const *           name,
                        fd_sbpf_syscall_func_t func );

/* fd_vm_syscall_register all reigsters all syscalls implemented.
   May change between Firedancer versions without warning. */

void
fd_vm_syscall_register_all( fd_sbpf_syscalls_t * syscalls );

/* fd_vm_syscall_register_ctx registers all syscalls appropriate for
   slot context. */

void
fd_vm_syscall_register_ctx( fd_sbpf_syscalls_t *       syscalls,
                            fd_exec_slot_ctx_t const * slot_ctx );

/* Syscall function declarations **************************************/

/*** Exceptional syscalls ***/

/* syscall(b6fc1a11) "abort"
   Abort program execution and fail transaction. */

FD_VM_SYSCALL_DECL(abort);

/* syscall(686093bb) "sol_panic_"
   Log panic message, abort program execution, and fail transaction. */

FD_VM_SYSCALL_DECL(sol_panic);

/* Logging syscalls ***************************************************/

/* syscall(207559bd) "sol_log_"
   Write message to log. */

FD_VM_SYSCALL_DECL( sol_log );

/* syscall(5c2a3178) "sol_log_64_"
   Write register file (r1, r2, r3, r4, r5) to log. */

FD_VM_SYSCALL_DECL( sol_log_64 );

/* syscall(52ba5096) "sol_log_compute_units_"
   Write remaining compute unit count to log. */

FD_VM_SYSCALL_DECL( sol_log_compute_units );

/* syscall(7ef088ca) "sol_log_pubkey"
   Write Base58 encoding of 32 byte array to log. */

FD_VM_SYSCALL_DECL( sol_log_pubkey );

/* syscall(???) "sol_log_data"
   Write Base64 encoded bytes to log. */

FD_VM_SYSCALL_DECL( sol_log_data );

/*** PDA (program derived address) syscalls ***/

/* syscall(9377323c) "sol_create_program_address"
   Compute SHA-256 hash of `<program ID> .. &[&[u8]] .. <PDA Marker>`,
   and check whether result is an Ed25519 curve point. */

FD_VM_SYSCALL_DECL( sol_create_program_address );

/* syscall(48504a38) "sol_try_find_program_address"
   Repeatedly derive program address while incrementing nonce in seed
   list  until a point is found that is not a valid Ed25519 curve point. */

FD_VM_SYSCALL_DECL( sol_try_find_program_address );

/* Memory syscalls ****************************************************/

FD_VM_SYSCALL_DECL(sol_memcpy);
FD_VM_SYSCALL_DECL(sol_memcmp);
FD_VM_SYSCALL_DECL(sol_memset);
FD_VM_SYSCALL_DECL(sol_memmove);

/* Program syscalls ***************************************************/

FD_VM_SYSCALL_DECL(sol_get_processed_sibling_instruction);

/* CPI syscalls *******************************************************/

/* Represents an account for a CPI*/

struct fd_instruction_account {
  ushort index_in_transaction;
  ushort index_in_caller;
  ushort index_in_callee;
  uint is_signer;
  uint is_writable;
};
typedef struct fd_instruction_account fd_instruction_account_t;

// Prepare instruction method

int
fd_vm_prepare_instruction( fd_instr_info_t const *  caller_instr,
                           fd_instr_info_t *        callee_instr,
                           fd_exec_instr_ctx_t *    instr_ctx,
                           fd_instruction_account_t instruction_accounts[256],
                           ulong *                  instruction_accounts_cnt,
                           fd_pubkey_t const *      signers,
                           ulong                    signers_cnt );


/* syscall(a22b9c85) "sol_invoke_signed_c"
   Dispatch a cross program invocation.  Inputs are in C ABI. */

FD_VM_SYSCALL_DECL(cpi_c);

/* syscall(d7449092) "sol_invoke_signed_rust"
   Dispatch a cross program invocation.  Inputs are in Rust ABI. */

FD_VM_SYSCALL_DECL(cpi_rust);

FD_VM_SYSCALL_DECL(sol_alloc_free);

/* Get syscalls *********************************************************/

FD_VM_SYSCALL_DECL(sol_set_return_data);
FD_VM_SYSCALL_DECL(sol_get_return_data);
FD_VM_SYSCALL_DECL(sol_get_stack_height);
FD_VM_SYSCALL_DECL(sol_get_processed_sibling_instruction);

/* Sysvar syscalls */

FD_VM_SYSCALL_DECL(sol_get_clock_sysvar);
FD_VM_SYSCALL_DECL(sol_get_epoch_schedule_sysvar);
FD_VM_SYSCALL_DECL(sol_get_fees_sysvar);
FD_VM_SYSCALL_DECL(sol_get_rent_sysvar);

/* Crypto syscalls ****************************************************/

/* FD_VM_SYSCALL_SOL_CURVE_ECC_{...} specifies the curve IDs and
   FD_VM_SYSCALL_SOL_CURVE_ECC_G_{...} declares IDs of operations on
   elliptic curve groups for the sol_curve syscalls. */

#define FD_VM_SYSCALL_SOL_CURVE_ECC_ED25519      (0UL)
#define FD_VM_SYSCALL_SOL_CURVE_ECC_RISTRETTO255 (1UL)

#define FD_VM_SYSCALL_SOL_CURVE_ECC_G_ADD        (0UL)  /* add */
#define FD_VM_SYSCALL_SOL_CURVE_ECC_G_SUB        (1UL)  /* add inverse */
#define FD_VM_SYSCALL_SOL_CURVE_ECC_G_MUL        (2UL)  /* scalar mult */

FD_VM_SYSCALL_DECL( sol_alt_bn128_group_op    );
FD_VM_SYSCALL_DECL( sol_alt_bn128_compression );
FD_VM_SYSCALL_DECL( sol_blake3                );
FD_VM_SYSCALL_DECL( sol_curve_validate_point  );
FD_VM_SYSCALL_DECL( sol_curve_group_op        );
FD_VM_SYSCALL_DECL( sol_curve_multiscalar_mul );
FD_VM_SYSCALL_DECL( sol_keccak256             );
FD_VM_SYSCALL_DECL( sol_poseidon              ); /* Light protocol flavor */
FD_VM_SYSCALL_DECL( sol_secp256k1_recover     );
FD_VM_SYSCALL_DECL( sol_sha256                );

FD_PROTOTYPES_END

#endif /*HEADER_src_flamenco_vm_syscall_fd_vm_syscall_h */
