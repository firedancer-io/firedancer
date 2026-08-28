#ifndef HEADER_fd_src_flamenco_runtime_program_fd_bpf_loader_serialization_h
#define HEADER_fd_src_flamenco_runtime_program_fd_bpf_loader_serialization_h

#include "../../fd_flamenco_base.h"
#include "../../vm/fd_vm.h"

#define FD_NON_DUP_MARKER           (0xFF   )

/* Returned when out_cap is too small for the input region.  Positive,
   so never confused with an (negative) instruction error.  The caller
   retries into a bigger frame; nothing was executed yet so the partial
   write has no side effects. */
#define FD_BPF_LOADER_SERIALIZE_FULL (1)

FD_PROTOTYPES_BEGIN

/* Serializes into out (FD_RUNTIME_EBPF_HOST_ALIGN aligned, out_cap
   bytes); returns FD_BPF_LOADER_SERIALIZE_FULL if out_cap is too
   small. */

int
fd_bpf_loader_input_serialize_parameters( fd_exec_instr_ctx_t *     instr_ctx,
                                          uchar *                   out,
                                          ulong                     out_cap,
                                          ulong *                   pre_lens,
                                          fd_vm_input_region_t *    input_mem_regions,
                                          uint *                    input_mem_regions_cnt,
                                          fd_vm_acc_region_meta_t * acc_region_metas,
                                          int                       virtual_address_space_adjustments,
                                          int                       direct_mapping,
                                          int                       direct_account_pointers_in_program_input,
                                          uchar                     is_deprecated,
                                          ulong *                   instr_data_offset,
                                          ulong *                   serialized_bytes_written );

int
fd_bpf_loader_input_deserialize_parameters( fd_exec_instr_ctx_t * ctx,
                                            ulong const *         pre_lens,
                                            uchar *               input,
                                            ulong                 input_sz,
                                            int                   virtual_address_space_adjustments,
                                            int                   direct_mapping,
                                            uchar                 is_deprecated );


FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_runtime_program_fd_bpf_loader_serialization_h */
