#ifndef HEADER_fd_src_flamenco_runtime_program_fd_bpf_program_util_h
#define HEADER_fd_src_flamenco_runtime_program_fd_bpf_program_util_h

#include "../../../ballet/sbpf/fd_sbpf_maps.h"
#include "../../fd_flamenco_base.h"
#include "../fd_executor.h"
#include "../fd_runtime.h"

struct fd_sbpf_validated_program {
  ulong magic;

  ulong last_updated_slot;
  ulong entry_pc;
  ulong text_cnt;
  ulong text_off;
  ulong rodata_sz;

  fd_sbpf_calldests_t calldests[4096];

  uchar rodata[];
};
typedef struct fd_sbpf_validated_program fd_sbpf_validated_program_t;

FD_PROTOTYPES_BEGIN

fd_sbpf_validated_program_t *
fd_sbpf_validated_program_new( void * mem );


ulong
fd_sbpf_validated_program_align( void );

ulong
fd_sbpf_validated_program_footprint( ulong rodata_sz );

ulong
fd_sbpf_validated_program_from_sbpf_program( fd_sbpf_program_t const * prog, 
                                             fd_sbpf_validated_program_t * valid_prog );

int
fd_bpf_scan_and_create_bpf_program_cache_entry( fd_exec_slot_ctx_t * slot_ctx );

int
fd_bpf_load_cache_entry( fd_exec_slot_ctx_t * slot_ctx,
                         fd_pubkey_t const * program_pubkey,
                         fd_sbpf_validated_program_t ** valid_prog );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_runtime_program_fd_bpf_program_util_h */
