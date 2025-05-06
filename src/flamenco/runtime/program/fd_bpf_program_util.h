#ifndef HEADER_fd_src_flamenco_runtime_program_fd_bpf_program_util_h
#define HEADER_fd_src_flamenco_runtime_program_fd_bpf_program_util_h

#include "../../fd_flamenco_base.h"
#include "../fd_runtime_public.h"
#include "../fd_acc_mgr.h"
#include "../context/fd_exec_slot_ctx.h"
#include "../../vm/syscall/fd_vm_syscall.h"

struct fd_sbpf_validated_program {
  ulong magic;

  ulong last_updated_slot;
  ulong entry_pc;
  ulong text_cnt;
  ulong text_off;
  ulong text_sz;

  ulong rodata_sz;

  /* We keep the pointer to the calldests raw memory around, so that we can easily copy the entire
     data structures (including the private header) later. */
  void * calldests_shmem;
  fd_sbpf_calldests_t * calldests;

  uchar * rodata;

  /* Backing memory for calldests and rodata */
  // uchar calldests_shmem[];
  // uchar rodata[];

  /* SBPF version, SIMD-0161 */
  ulong sbpf_version;
};
typedef struct fd_sbpf_validated_program fd_sbpf_validated_program_t;

/* arbitrary unique value, in this case
   echo -n "fd_sbpf_validated_program" | sha512sum | head -c 16 */
#define FD_SBPF_VALIDATED_PROGRAM_MAGIC 0xfd5540ddc5a33496

FD_PROTOTYPES_BEGIN

void
bpf_tpool_wrapper( void * para_arg_1,
                   void * para_arg_2,
                   void * fn_arg_1,
                   void * fn_arg_2,
                   void * fn_arg_3,
                   void * fn_arg_4 );

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

void
fd_bpf_is_bpf_program( fd_funk_rec_t const * rec,
                       fd_wksp_t *           funk_wksp,
                       uchar *               is_bpf_program );

int
fd_bpf_scan_and_create_bpf_program_cache_entry_para( fd_exec_slot_ctx_t *    slot_ctx,
                                                     fd_spad_t *             runtime_spad,
                                                     fd_exec_para_cb_ctx_t * exec_para_ctx );

int
fd_bpf_load_cache_entry( fd_funk_t *                    funk,
                         fd_funk_txn_t *                funk_txn,
                         fd_pubkey_t const *            program_pubkey,
                         fd_sbpf_validated_program_t ** valid_prog );

void
fd_bpf_get_sbpf_versions( uint *                sbpf_min_version,
                          uint *                sbpf_max_version,
                          ulong                 slot,
                          fd_features_t const * features );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_runtime_program_fd_bpf_program_util_h */
