#ifndef HEADER_fd_src_flamenco_runtime_program_fd_bpf_loader_serialization_h
#define HEADER_fd_src_flamenco_runtime_program_fd_bpf_loader_serialization_h

#include "../../fd_flamenco_base.h"
#include "../../vm/fd_vm.h"

#define FD_NON_DUP_MARKER           (0xFF   )

FD_PROTOTYPES_BEGIN

int
fd_bpf_loader_input_serialize_parameters( fd_exec_instr_ctx_t *     instr_ctx,
                                          ulong *                   pre_lens,
                                          fd_vm_input_region_t *    input_mem_regions,
                                          uint *                    input_mem_regions_cnt,
                                          fd_vm_acc_region_meta_t * acc_region_metas,
                                          int                       stricter_abi_and_runtime_constraints,
                                          int                       direct_mapping,
                                          uchar                     is_deprecated,
                                          ulong *                   instr_data_offset,
                                          ulong *                   serialized_bytes_written );

int
fd_bpf_loader_input_deserialize_parameters( fd_exec_instr_ctx_t * ctx,
                                            ulong const *         pre_lens,
                                            uchar *               input,
                                            ulong                 input_sz,
                                            int                   stricter_abi_and_runtime_constraints,
                                            int                   direct_mapping,
                                            uchar                 is_deprecated );


FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_runtime_program_fd_bpf_loader_serialization_h */
