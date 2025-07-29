#ifndef HEADER_fd_src_flamenco_runtime_program_fd_program_cache_h
#define HEADER_fd_src_flamenco_runtime_program_fd_program_cache_h

#include "../../fd_flamenco_base.h"
#include "../fd_acc_mgr.h"
#include "../context/fd_exec_slot_ctx.h"
#include "../../vm/syscall/fd_vm_syscall.h"
#include "../fd_system_ids.h"

/* fd_program_cache contains the core logic for the program cache's
   behavior, including accesses, insertions, updates, and verifies.
   Specifically, the program cache operates in a lazy manner where
   programs are only inserted / reverified when they are referenced
   in a transaction.

   On bootup, the program cache starts out empty. As programs (defined
   as accounts owned by one of the BPF loaders that can be invoked
   by the user) are referenced as account keys within transactions
   (either statically or through address lookup tables),
   `fd_program_cache_update_program()` accepts a pubkey as input and
   will attempt to either insert the program into the cache (performing
   sBPF + ELF validations) if missing, or reverify the program if
   needed.

   After a transaction is executed successfully, we iterate through
   the writable account keys and queue any programs for reverification
   since their account data may have changed (e.g. the program was
   upgraded, closed, etc). To mark a program for reverification, we
   simply update the `last_modified_slot` field to the current slot.
   When the program is next referenced in a transaction,
   `fd_program_cache_update_program()` will check if the program was
   modified since the last time it was reverified, and reverify
   the program accordingly to update the cache entry's sBPF info,
   calldests, etc. Once the program has been reverified, the entry's
   `last_slot_verification_ran` field will be updated to the current
   slot.

   A program cache entry may also be reverified after crossing an
   epoch boundary, even if it was not modified recently. This is because
   the network's active feature set may have changed, and any previously
   {valid,invalid} programs may now be {valid,invalid}. Therefore,
   if a program is referenced in a transaction that has not been
   reverified since the last epoch (regardless of it having been
   modified or not), it will be reverified and updated.

   If a program fails verification due to invalid ELF headers / sBPF
   loading failures, then we update the `failed_verification` tag
   and set `last_modified_slot` to the current slot. A future
   program upgrade / network feature set change could make this
   program valid again.

   A key invariant with the program cache design is that it does not
   evict any entries - it only grows through the lifetime of the
   client's execution. This is meant to prevent any DOS vectors where
   an attacker can invoke programs that repeatedly reverify and
   evict programs. Because of this invariant, we do not touch cache
   entries for programs which are closed, and instead let account
   loading checks catch cases where a user tries to invoke a closed
   program.

   EDGE CASES (and how we handle them):
   - Deploying programs
     - Deploying a program
         - `fd_program_cache_queue_program_for_reverification()` will
           not do anything because the program does not exist in the
           cache yet, and so there is nothing to update. The next time
           the program is referenced in a transaction,
           `fd_program_cache_update_program()` will see that the program
           is missing in the cache and will perform ELF / sBPF
           verifications and insert the entry into the cache.
     - Deploying and invoking in the same slot
         - BPF loader checks will fail because the program account's
           slot value will be equal to the current slot, which
           gets caught by the `DelayedVisibility` checks.
   - Upgrading programs
      - Upgrading a program
         - The program account will have been referenced as writable
           in the transaction, and thus
           `fd_program_cache_queue_program_for_reverification()` will
           update the `last_modified_slot` to queue the program
           for reverification the next time it is referenced in a
           transaction.
      - Upgrading and invoking in the same transaction
        - Same as "deploy" case
   - Closing programs
      - Closing a program
        - We do not touch the program cache here. We let account
          loading / BPF loader checks handle cases where a user may try
          to invoke a closed program.
      - Closing + invoking a program in the same transaction
         - The program account's state will be set to uninitialized /
           retracted, so any future instructions that invoke the program
           will fail when the BPF loader checks the account state.
      - Closing + invoking a program in separate transactions
         - The program account's owner will be set to the system program
           and thus fail account loading checks. */

/* `fd_sbpf_validated_program` defines the structure for a single
   program cache entry. */
struct fd_sbpf_validated_program {
  ulong magic;

   /* For any programs that fail verification, we retain this flag for
      to prevent any reverification attempts for the remainder of the
      epoch / until the program is modified again (instead of removing
      them from the cache). When `failed_verification` is set,
      the values of all other fields except for
      `last_slot_verification_ran` are undefined. Any invocations of a
      program that fails verification will continue to fail until the
      program is queued for reverification by an eligible BPF loader
      instruction (e.g. the program is upgraded). */
   uchar failed_verification;

   /* Stores the last slot the program was modified. This field is
      updated at the end of a transaction for a program account that was
      referenced as a writable account within an instruction. For any
      programs that are freshly added to the cache, this field is set to
      0. */
   ulong last_modified_slot;

   /* Stores the last slot verification checks were ran for a program.
      Programs are reverified if they are mentioned in the current
      transaction, and if one of the following are true:
      - It is the first time they are referenced in a transaction in the
        current epoch
      - The program was a writable account in a transaction

      We reverify referenced programs at least once every epoch
      regardless of whether they were modified or not because changes
      in the active feature set may cause existing deployed programs
      to be invalided (e.g. stricter ELF / VM / sBPF checks). */
   ulong last_slot_verification_ran;

   ulong entry_pc;
   ulong text_cnt;
   ulong text_off;
   ulong text_sz;

   ulong rodata_sz;

  /* We keep the pointer to the calldests raw memory around, so that we can easily copy the entire
     data structures (including the private header) later. */
   void *                calldests_shmem;
   fd_sbpf_calldests_t * calldests;
   uchar *               rodata;

   /* SBPF version, SIMD-0161 */
   ulong sbpf_version;
};
typedef struct fd_sbpf_validated_program fd_sbpf_validated_program_t;

/* arbitrary unique value, in this case
   echo -n "fd_sbpf_validated_program" | sha512sum | head -c 16 */
#define FD_SBPF_VALIDATED_PROGRAM_MAGIC 0xfd5540ddc5a33496

FD_PROTOTYPES_BEGIN

fd_sbpf_validated_program_t *
fd_sbpf_validated_program_new( void *                    mem,
                              fd_sbpf_elf_info_t const * elf_info,
                              ulong                      last_modified_slot,
                              ulong                      last_slot_verification_ran );

ulong
fd_sbpf_validated_program_align( void );

ulong
fd_sbpf_validated_program_footprint( fd_sbpf_elf_info_t const * elf_info );

void
fd_sbpf_get_sbpf_versions( uint *                sbpf_min_version,
                           uint *                sbpf_max_version,
                           ulong                 slot,
                           fd_features_t const * features );

/* Loads a single program cache entry for a given pubkey. Returns 0 on
   success and -1 on failure. On success, `*valid_prog` holds a pointer
   to the program cache entry. */
int
fd_bpf_load_cache_entry( fd_funk_t const *                    funk,
                         fd_funk_txn_t const *                funk_txn,
                         fd_pubkey_t const *                  program_pubkey,
                         fd_sbpf_validated_program_t const ** valid_prog );

/* Parses the programdata from a program account. Returns a pointer to
   the program data and sets `out_program_data_len` on success. Returns
   NULL on failure or if the program account is not owned by a BPF
   loader program ID, and leaves `out_program_data_len` in an undefined
   state. Reasons for failure vary on the loader version. See the
   respective functions in this file for more details. */
uchar const *
fd_bpf_get_programdata_from_account( fd_funk_t const *        funk,
                                     fd_funk_txn_t const *    funk_txn,
                                     fd_txn_account_t const * program_acc,
                                     ulong *                  out_program_data_len,
                                     fd_spad_t *              runtime_spad );

/* Returns 1 if the program failed verification, 0 otherwise. */
uchar
fd_program_cache_program_failed_verification( fd_sbpf_validated_program_t const * validated_prog );

/* Updates the program cache for a single program. This function is
   called for every program that is referenced in a transaction, plus
   every single account in a lookup table referenced in the transaction.
   This function...
   - Accepts a pubkey and reads the programdata from the account
   - Creates a program cache entry for the program if it doesn't exist
     in the cache already
   - Reverifies programs if either...
      - The program was recently modified
      - The program has not been verified yet for the current epoch
   - Invalidated programs that fail ELF / sBPF verification
   - Updates the program cache entry for the program after
     reverification (syscalls, calldests, etc)

   With this design, the program cache is designed to only grow as new
   programs are deployed / invoked. If a program fails verification, it
   stays in the cache so that repeated calls won't DOS the validator by
   forcing reverifications (since we won't be able to distinguish failed
   verifications from new deployments). */
void
fd_program_cache_update_program( fd_exec_slot_ctx_t * slot_ctx,
                                 fd_pubkey_t const *  program_pubkey,
                                 fd_spad_t *          runtime_spad );

/* Queues a single program account for reverification. This function
   queries the cache for an existing entry and queues it for
   reverification by setting the `last_modified_slot` field in the
   program cache entry to the current slot. If the cache entry
   for the program does not exist yet (e.g. newly deployed programs),
   this function does nothing and instead,
   `fd_program_cache_program_failed_verification()` will insert
   the program into the cache. */
void
fd_program_cache_queue_program_for_reverification( fd_funk_t *              funk,
                                                   fd_funk_txn_t *          funk_txn,
                                                   fd_txn_account_t const * program_acc,
                                                   ulong                    current_slot );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_runtime_program_fd_program_cache_h */
