#ifndef HEADER_fd_src_flamenco_runtime_program_fd_bpf_loader_v4_program_h
#define HEADER_fd_src_flamenco_runtime_program_fd_bpf_loader_v4_program_h

#include "../context/fd_exec_instr_ctx.h"

/* BPF Loader v4 account state
   Directly mapped - does not use bincode */

struct __attribute__((packed)) fd_bpf_loader_v4_state {
  /* 0x00 */ ulong slot;
  /* 0x08 */ uchar authority_addr[ 32 ];
  /* 0x28 */ ulong status;
};

typedef struct fd_bpf_loader_v4_state fd_bpf_loader_v4_state_t;

#define FD_BPF_LOADER_V4_STATUS_RETRACTED (0x00UL)
#define FD_BPF_LOADER_V4_STATUS_DEPLOYED  (0x01UL)
#define FD_BPF_LOADER_V4_STATUS_FINALIZED (0x02UL)

FD_PROTOTYPES_BEGIN

/* fd_bpf_loader_v4_get_state{_laddr,_const,$} returns a pointer to the
   state header of an account owned by the BPF Loader v4 program.  Does
   no validation on the header other than bounds checks.  Return value
   is a 'raw' address in the local address space (laddr), a read-only
   pointer (const), or a read-write pointer.  Returns NULL on buffer
   underflow. */

FD_FN_PURE static inline ulong
fd_bpf_loader_v4_get_state_laddr( fd_account_meta_t const * meta,
                                  uchar const *             data ) {
  if( FD_UNLIKELY( meta->dlen < sizeof(fd_bpf_loader_v4_state_t) ) )
    return 0;
  return (ulong)data;
}

FD_FN_PURE static inline fd_bpf_loader_v4_state_t const *
fd_bpf_loader_v4_get_state_const( fd_account_meta_t const * meta,
                                  uchar const *             data ) {
  return (fd_bpf_loader_v4_state_t const *)fd_bpf_loader_v4_get_state_laddr( meta, data );
}

FD_FN_PURE static inline fd_bpf_loader_v4_state_t *
fd_bpf_loader_v4_get_state( fd_account_meta_t const * meta,
                            uchar *                   data ) {
  return (fd_bpf_loader_v4_state_t *)fd_bpf_loader_v4_get_state_laddr( meta, data );
}

/* fd_bpf_loader_v4_program_execute is the instruction processing
   entrypoint for the Solana BPF loader program */

int
fd_bpf_loader_v4_program_execute( fd_exec_instr_ctx_t ctx );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_runtime_program_fd_bpf_loader_v4_program_h */
