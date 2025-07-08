#ifndef HEADER_fd_src_flamenco_runtime_program_fd_bpf_program_util_h
#define HEADER_fd_src_flamenco_runtime_program_fd_bpf_program_util_h

#include "../../fd_flamenco_base.h"
#include "../fd_acc_mgr.h"
#include "../context/fd_exec_slot_ctx.h"
#include "../../vm/syscall/fd_vm_syscall.h"
#include "../fd_system_ids.h"

struct fd_sbpf_validated_program {
  ulong magic;

   /* For any programs that fail verification, we retain this flag for the current epoch to
      prevent any reverification attempts for the remainder of the epoch (instead of
      removing them from the cache). When `failed_verification` is set, the value of all other
      fields in this struct are undefined. */
   uchar failed_verification;

   /* Stores the last epoch verification checks were ran for a program. Programs are reverified
      the first time they are mentioned in a transaction in an epoch, and then never again
      until the next epoch. This is because feature set changes across the epoch boundary can
      make existing deployed programs invalid. If `last_epoch_verification_ran` != current epoch,
      then we run the verification and update `failed_verification` if it fails. */
   ulong last_epoch_verification_ran;

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

/* FIXME: Implement this (or remove?) */
ulong
fd_sbpf_validated_program_from_sbpf_program( fd_sbpf_program_t const *     prog,
                                             fd_sbpf_validated_program_t * valid_prog );

int
fd_bpf_scan_and_create_bpf_program_cache_entry( fd_exec_slot_ctx_t * slot_ctx,
                                                fd_spad_t *          runtime_spad );

int
fd_bpf_scan_and_create_bpf_program_cache_entry_para( fd_exec_slot_ctx_t *    slot_ctx,
                                                     fd_spad_t *             runtime_spad,
                                                     fd_exec_para_cb_ctx_t * exec_para_ctx );

int
fd_bpf_load_cache_entry( fd_funk_t const *                    funk,
                         fd_funk_txn_t const *                funk_txn,
                         fd_pubkey_t const *                  program_pubkey,
                         fd_sbpf_validated_program_t const ** valid_prog );

void
fd_bpf_get_sbpf_versions( uint *                sbpf_min_version,
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

/* Updates the program cache for a single program. This function is called for every program
   that is referenced in a transaction, plus every single account in a lookup table referenced
   in the transaction. This function...
   - Reads the programdata from an account, given the pubkey
   - Creates a program cache entry for the program if it doesn't exist in the cache already
   - Reverifies programs every epoch
      - Lazily reverifies programs as they are invoked in a transaction (only once per program per epoch)
      - Invalidates programs that fail verification until the next epoch
      - Updates the program cache entry for the program after reverification (syscalls, calldests, etc)

   With this design, the program cache is designed to only grow as new programs are deployed / invoked. If a program fails
   verification, it stays in the cache so that repeated calls won't DOS the validator by forcing reverifications (since we
   won't be able to distinguish failed verifications from new deployments). */
void
fd_bpf_program_update_program_cache( fd_exec_slot_ctx_t * slot_ctx,
                                     fd_pubkey_t const *  program_pubkey,
                                     fd_spad_t *          runtime_spad );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_runtime_program_fd_bpf_program_util_h */
