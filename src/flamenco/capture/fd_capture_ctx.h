#ifndef HEADER_fd_src_flamenco_capture_fd_capture_ctx_h
#define HEADER_fd_src_flamenco_capture_fd_capture_ctx_h

#include "../../util/fd_util_base.h"

/* Context needed to do solcap capture during execution of transactions */

struct fd_capture_ctx {

  ulong                    current_txn_idx;

  /*======== PROTOBUF ========*/
  char const *             dump_proto_output_dir;
  char const *             dump_proto_sig_filter;
  ulong                    dump_proto_start_slot;

  /* Instruction Capture */
  int                      dump_instr_to_pb;

  /* Transaction Capture */
  int                      dump_txn_to_pb;

  /* Block Capture */
  int                      dump_block_to_pb;

  /* Syscall Capture */
  int                      dump_syscall_to_pb;

  /* ELF Capture */
  int                      dump_elf_to_pb;

};
typedef struct fd_capture_ctx fd_capture_ctx_t;

#endif /* HEADER_fd_src_flamenco_capture_fd_capture_ctx_h */

