#ifndef HEADER_fd_src_flamenco_runtime_program_fd_bpf_loader_serialization_h
#define HEADER_fd_src_flamenco_runtime_program_fd_bpf_loader_serialization_h

#include "../../fd_flamenco_base.h"
#include "../fd_executor.h"
#include "../fd_runtime.h"

#define MAX_PERMITTED_DATA_INCREASE (10 * 1024)

FD_PROTOTYPES_BEGIN

uchar *
fd_bpf_loader_input_serialize_aligned( fd_exec_instr_ctx_t ctx, ulong * sz, ulong * pre_lens );

int
fd_bpf_loader_input_deserialize_aligned( fd_exec_instr_ctx_t ctx, ulong const * pre_lens, uchar * input, ulong input_sz );

uchar *
fd_bpf_loader_input_serialize_unaligned( fd_exec_instr_ctx_t ctx, ulong * sz, ulong * pre_lens );

int
fd_bpf_loader_input_deserialize_unaligned( fd_exec_instr_ctx_t ctx, ulong const * pre_lens, uchar * input, ulong input_sz );


FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_runtime_program_fd_bpf_loader_serialization_h */
