#ifndef HEADER_fd_src_flamenco_runtime_program_fd_bpf_loader_serialization_h
#define HEADER_fd_src_flamenco_runtime_program_fd_bpf_loader_serialization_h

#include "../../fd_flamenco_base.h"
#include "../fd_executor.h"
#include "../fd_runtime.h"

#define MAX_PERMITTED_DATA_INCREASE (10 * 1024)

FD_PROTOTYPES_BEGIN

uchar *
fd_bpf_loader_input_serialize_aligned( instruction_ctx_t ctx, ulong * sz );

int
fd_bpf_loader_input_deserialize_aligned( instruction_ctx_t ctx, uchar * input, ulong input_sz );

uchar *
fd_bpf_loader_input_serialize_unaligned( instruction_ctx_t ctx, ulong * sz );

int
fd_bpf_loader_input_deserialize_unaligned( instruction_ctx_t ctx, uchar * input, ulong input_sz );


FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_runtime_program_fd_bpf_loader_serialization_h */