#ifndef HEADER_fd_src_flamenco_runtime_program_fd_bpf_program_util_h
#define HEADER_fd_src_flamenco_runtime_program_fd_bpf_program_util_h

#include "../../fd_flamenco_base.h"
#include "../../../ballet/sbpf/fd_sbpf_loader.h"
#include "../../../funk/fd_funk_txn.h"

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
};
typedef struct fd_sbpf_validated_program fd_sbpf_validated_program_t;

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
                                                fd_funk_txn_t *      funk_txn,
                                                int                  update_program_blacklist );

int
fd_bpf_check_and_create_bpf_program_cache_entry( fd_exec_slot_ctx_t * slot_ctx,
                                                 fd_funk_txn_t *      funk_txn,
                                                 fd_pubkey_t const *  pubkey,
                                                 int                  update_program_blacklist );

int
fd_bpf_scan_and_create_bpf_program_cache_entry_tpool( fd_exec_slot_ctx_t * slot_ctx,
                                                      fd_funk_txn_t *      funk_txn,
                                                      fd_tpool_t *         tpool,
                                                      int                  update_program_blacklist );

int
fd_bpf_load_cache_entry( fd_exec_slot_ctx_t *           slot_ctx,
                         fd_pubkey_t const *            program_pubkey,
                         fd_sbpf_validated_program_t ** valid_prog );

/* There are a few programs that exist in certain Solana clusters, notably
   in devnet and testnet that were deployed before stricter bytecode/executable
   checks were added. If these programs are added to a transaction list, the
   transaction should throw a sanitization error. Agave manages this by
   verifying and reloading programs on demand if it gets evicted from its
   loaded program cache. To avoid loading and verifying every program
   for each transaction, the blacklist of programs is calculated on startup.
   This list does not need to be updated because new programs that violate
   verification/loading checks can't be deployed. As a note, this function
   should ONLY be invoked on programs that are:
   1. Owned by a loader program
   2. Are able to be loaded
   3. Are able to be verified
   For reference: see transaction_processor::replenish_program_cache(). */
void
fd_bpf_add_to_program_blacklist( fd_exec_slot_ctx_t * slot_ctx,
                                 fd_pubkey_t const  * program_pubkey );

int
fd_bpf_is_in_program_blacklist( fd_exec_slot_ctx_t * slot_ctx, 
                                fd_pubkey_t const  * program_pubkey );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_runtime_program_fd_bpf_program_util_h */
