#ifndef HEADER_fd_src_flamenco_runtime_program_fd_bpf_loader_serialization_h
#define HEADER_fd_src_flamenco_runtime_program_fd_bpf_loader_serialization_h

#include "../../fd_flamenco_base.h"
#include "../../vm/fd_vm.h"

#define FD_NON_DUP_MARKER           (0xFF   )

/* The most input memory regions an instruction can have: a metadata
   region and a data region for each unique account, plus a final
   region. */
#define FD_BPF_LOADER_INPUT_REGIONS_MAX (2UL*MAX_TX_ACCOUNT_LOCKS+1UL)

FD_PROTOTYPES_BEGIN

int
fd_bpf_loader_input_serialize_parameters( fd_exec_instr_ctx_t *     instr_ctx,
                                          fd_vm_input_region_t *    input_mem_regions,
                                          uint *                    input_mem_regions_cnt,
                                          fd_vm_acc_region_meta_t * acc_region_metas,
                                          int                       direct_account_pointers_in_program_input,
                                          uchar                     is_deprecated,
                                          ulong *                   instr_data_offset,
                                          ulong *                   account_pointers_offset,
                                          ulong *                   serialized_bytes_written );

/* input and acc_region_metas must come from serialize_parameters for
   this instruction with the same ABI.  ABI v0 ignores serialized
   data-length fields. */
int
fd_bpf_loader_input_deserialize_parameters( fd_exec_instr_ctx_t *           ctx,
                                            fd_vm_acc_region_meta_t const * acc_region_metas,
                                            uchar *                         input,
                                            ulong                           input_sz,
                                            uchar                           is_deprecated );


FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_runtime_program_fd_bpf_loader_serialization_h */
