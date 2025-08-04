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

   The program cache lives in Funk and is fork-aware. The size of the
   program cache is bounded by the size of the Funk instance.

   On bootup, the program cache starts out empty. As programs (defined
   as accounts owned by one of the BPF loaders that can be invoked
   by the user) are referenced as account keys within transactions
   (either statically or through address lookup tables),
   `fd_program_cache_update_program()` accepts a pubkey as input and
   will attempt to either insert the program into the cache (performing
   sBPF + ELF validations) if missing, or reverify the program if
   needed.

   During transaction execution, we accumulate any program pubkeys that
   are deployed, extended, or upgraded (basically, any calls to
   `fd_deploy_program()` in the BPF loaders) since those instructions
   may have changed the program's executable data (closed / retracted
   programs also do, but see comments below on how we handle that).
   After a transaction is executed successfully, we iterate through
   these accumulated program keys and queue them for reverification.
   To mark a program for reverification, we simply update the
   `last_slot_modified` field to the current slot. When the program is
   next referenced in a transaction, `fd_program_cache_update_program()`
   will check if the program was modified since the last time it was
   reverified, and reverify the program accordingly to update the cache
   entry's sBPF info, calldests, etc. Once the program has been
   reverified, the entry's `last_slot_verified` field will be updated
   to the current slot.

   When a program is reverified and updated in the cache, we clone the
   record down to the current funk transaction from an ancestor, and
   then modify the record within the current funk transaction.

   A program cache entry may also be reverified after crossing an
   epoch boundary, even if it was not modified recently. This is because
   the network's active feature set may have changed, and any previously
   {valid,invalid} programs may now be {valid,invalid}. Therefore,
   if a program is referenced in a transaction that has not been
   reverified since the last epoch (regardless of it having been
   modified or not), it will be reverified and updated.

   If a program fails verification due to invalid ELF headers / sBPF
   loading failures, then we update the `failed_verification` tag,
   set `last_slot_verified` to the current slot, and set
   `last_slot_modified` to 0. A future program upgrade / network feature
   set change could make this program valid again.

   A key invariant with the program cache design is that it does not
   evict any entries - it only grows through the lifetime of the
   client's execution. Because of this invariant, we do not touch cache
   entries for programs which are closed, and instead let
   transaction-level account loading and BPF loader program checks
   catch cases where a user tries to invoke a closed program.

   Another key invariant is that for any given program, we will insert /
   update its cache entry at most ONCE per slot, and this will happen
   the FIRST time the program is referenced in a transaction before it
   is dispatched to the exec tiles. This is important because it ensures
   that the replay tile does not race with the exec tiles by updating
   the cache entry for a program while an exec tile is already executing
   it. Even if a program is upgraded in the same slot after it has been
   reverified, the network forbids invoking programs in the same slot as
   they are deployed / upgraded, so we can wait for a future slot to
   update the program cache entry when it is invoked next.

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
           update the `last_slot_modified` to queue the program
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
           and thus fail account loading checks.

   TL;DR: Deploys and upgrades are treated the same way - if the cache
   entry exists, it's queued for reverification. If it doesn't, the
   program cache will verify and add it to the cache the next time it's
   invoked. Cases where the program is closed / retracted are not
   explicitly handled.

   Q: Is the program cache concurrency-safe?
   A: Yes. In any given slot, the replay tile first iterates through
      each transaction in a single-threaded manner. For each
      transaction, it will read the accounts and will call
      `fd_program_cache_update_program()` for each program, and then
      dispatch the transaction to the exec tiles. This means
      that the first time any program is referenced in any transaction
      in the slot, the replay tile will update the associated program
      cache entry before dispatching the transaction to any of the exec
      tiles. Furthermore, we are not allowed to insert / reverify a
      program cache entry more than once within a single slot. This
      guarantees that any read / write accesses for a particular program
      in the program cache by the exec / writer tiles will occur after
      the cache entries have been processed by the replay tile in any
      given slot. Furthermore, if the program was upgraded, the writer
      tile simply updates a single header in the existing program cache
      entry `last_slot_modified`, which is behind a blocking write lock.
      Note that if there is read-write or write-write-contention
      between two transactions for any accounts, the scheduler will
      ensure that those two transactions are scheduled and finalized
      in a serial manner. */

/* `fd_program_cache_entry` defines the structure for a single
   program cache entry. */
struct fd_program_cache_entry {
  ulong magic;

   /* For any programs that fail verification, we retain this flag for
      to prevent any reverification attempts for the remainder of the
      epoch / until the program is modified again (instead of removing
      them from the cache). When `failed_verification` is set,
      the values of all other fields except for
      `last_slot_verified` are undefined. Any invocations of a
      program that fails verification will continue to fail until the
      program is queued for reverification by an eligible BPF loader
      instruction (e.g. the program is upgraded). */
   uchar failed_verification;

   /* Stores the last slot the program was modified. This field is
      updated at the end of a transaction for a program account that was
      referenced as a writable account within an instruction. For any
      programs that are freshly added to the cache, this field is set to
      0. */
   ulong last_slot_modified;

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
   ulong last_slot_verified;

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
typedef struct fd_program_cache_entry fd_program_cache_entry_t;

/* arbitrary unique value, in this case
   echo -n "fd_program_cache_entry" | sha512sum | head -c 16 */
#define FD_PROGRAM_CACHE_ENTRY_MAGIC 0xb45640baf006ddf6

FD_PROTOTYPES_BEGIN

fd_program_cache_entry_t *
fd_program_cache_entry_new( void *                     mem,
                            fd_sbpf_elf_info_t const * elf_info,
                            ulong                      last_slot_modified,
                            ulong                      last_slot_verified );

ulong
fd_program_cache_entry_footprint( fd_sbpf_elf_info_t const * elf_info );

/* Loads a single program cache entry for a given pubkey. Returns 0 on
   success and -1 on failure. On success, `*cache_entry` holds a pointer
   to the program cache entry. */
int
fd_program_cache_load_entry( fd_funk_t const *                 funk,
                             fd_funk_txn_t const *             funk_txn,
                             fd_pubkey_t const *               program_pubkey,
                             fd_program_cache_entry_t const ** cache_entry );

/* Parses the programdata from a program account. Returns a pointer to
   the program data and sets `out_program_data_len` on success. Returns
   NULL on failure or if the program account is not owned by a BPF
   loader program ID, and leaves `out_program_data_len` in an undefined
   state. Reasons for failure vary on the loader version. See the
   respective functions in this file for more details. */
uchar const *
fd_program_cache_get_account_programdata( fd_funk_t const *        funk,
                                          fd_funk_txn_t const *    funk_txn,
                                          fd_txn_account_t const * program_acc,
                                          ulong *                  out_program_data_len,
                                          fd_spad_t *              runtime_spad );

/* Updates the program cache for a single program. This function is
   called for every program that is referenced in a transaction, plus
   every single account in a lookup table referenced in the transaction.
   This function...
   - Accepts a pubkey and reads the programdata from the account
   - Creates a program cache entry for the program if it doesn't exist
     in the cache already
   - Reverifies programs if either...
      - The program was recently modified in a STRICTLY PRIOR SLOT
      - The program has not been verified yet for the current epoch
   - Invalidated programs that fail ELF / sBPF verification
   - Updates the program cache entry for the program after
     reverification (syscalls, calldests, etc)

   With this design, the program cache is designed to only grow as new
   programs are deployed / invoked. If a program fails verification, it
   stays in the cache so that repeated calls won't DOS the validator by
   forcing reverifications (since we won't be able to distinguish failed
   verifications from new deployments).

   When a program is reverified (and the cache entry already exists in
   some ancestor funk transaction), we clone the record down to the
   current funk transaction and acquire a blocking write lock on the
   cloned funk record. */
void
fd_program_cache_update_program( fd_exec_slot_ctx_t * slot_ctx,
                                 fd_pubkey_t const *  program_key,
                                 fd_spad_t *          runtime_spad );

/* Queues a single program account for reverification. This function
   queries the cache for an existing entry and queues it for
   reverification by setting the `last_slot_modified` field in the
   program cache entry to the current slot. If the cache entry
   for the program does not exist yet (e.g. newly deployed programs),
   this function does nothing and instead,
   `fd_program_cache_publish_failed_verification_rec()` will insert
   the program into the cache.

   If the record exists in the program cache, this function will
   acquire a write-lock on the program cache entry. */
void
fd_program_cache_queue_program_for_reverification( fd_funk_t *         funk,
                                                   fd_funk_txn_t *     funk_txn,
                                                   fd_pubkey_t const * program_key,
                                                   ulong               current_slot );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_runtime_program_fd_program_cache_h */
