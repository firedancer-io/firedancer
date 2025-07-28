#ifndef HEADER_fd_src_flamenco_runtime_program_fd_program_cache_h
#define HEADER_fd_src_flamenco_runtime_program_fd_program_cache_h

#include "../../fd_flamenco_base.h"
#include "../fd_acc_mgr.h"
#include "../context/fd_exec_slot_ctx.h"
#include "../../vm/syscall/fd_vm_syscall.h"
#include "../fd_system_ids.h"

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
      updated at the end of a transaction for a program account which
      is either deployed, retracted, closed, upgraded, migrated, or
      extended by a v3 / v4 loader instruction. For any programs that
      are freshly added to the cache, this field is set to 0. */
   ulong last_slot_modified;

   /* Stores the last slot verification checks were ran for a program.
      Programs are reverified if they are mentioned in the current
      transaction, and if one of the following are true:
      - It is the first time they are referenced in a transaction in the
        current epoch
      - The program was recently deployed, retracted, closed, upgraded,
        migrated, or extended by a v3 / v4 loader instruction

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
fd_sbpf_validated_program_new( void * mem, fd_sbpf_elf_info_t const * elf_info );

ulong
fd_sbpf_validated_program_align( void );

ulong
fd_sbpf_validated_program_footprint( fd_sbpf_elf_info_t const * elf_info );

int
fd_bpf_load_cache_entry( fd_funk_t const *                    funk,
                         fd_funk_txn_t const *                funk_txn,
                         fd_pubkey_t const *                  program_pubkey,
                         fd_sbpf_validated_program_t const ** valid_prog );

void
fd_sbpf_get_sbpf_versions( uint *                sbpf_min_version,
                           uint *                sbpf_max_version,
                           ulong                 slot,
                           fd_features_t const * features );

/* Parses the programdata from a program account. Returns a pointer to the program data
   and sets `out_program_data_len` on success. Returns NULL on failure or if the program
   account is not owned by a BPF loader program ID, and leaves `out_program_data_len`
   in an undefined state. Reasons for failure vary on the loader version. See the respective
   functions in this file for more details. */
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
   - Reads the programdata from an account, given the pubkey
   - Creates a program cache entry for the program if it doesn't exist in the cache already
   - Reverifies programs if...
      - The program was recently modified
      - Lazily reverifies programs as they are invoked in a transaction (only once per program per epoch)
      - Invalidates programs that fail verification until the next epoch
      - Updates the program cache entry for the program after reverification (syscalls, calldests, etc)

   With this design, the program cache is designed to only grow as new programs are deployed / invoked. If a program fails
   verification, it stays in the cache so that repeated calls won't DOS the validator by forcing reverifications (since we
   won't be able to distinguish failed verifications from new deployments). */
void
fd_program_cache_update_program( fd_exec_slot_ctx_t * slot_ctx,
                                 fd_pubkey_t const *  program_pubkey,
                                 fd_spad_t *          runtime_spad );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_runtime_program_fd_program_cache_h */
