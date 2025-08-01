#ifndef HEADER_fd_src_flamenco_runtime_context_fd_capture_ctx_h
#define HEADER_fd_src_flamenco_runtime_context_fd_capture_ctx_h

#include "../../capture/fd_solcap_writer.h"

/* Context needed to do solcap capture during execution of transactions */
#define FD_CAPTURE_CTX_ALIGN (8UL)
struct __attribute__((aligned(FD_CAPTURE_CTX_ALIGN))) fd_capture_ctx {
  ulong magic; /* ==FD_CAPTURE_CTX_MAGIC */

  /* Solcap */
  ulong                    solcap_start_slot;
  int                      trace_dirfd;
  int                      trace_mode;
  fd_solcap_writer_t *     capture;
  int                      capture_txns; /* Capturing txns can add significant time */

  /* Checkpointing */
  ulong                    checkpt_freq;    /* Must be a rooted slot */
  char const *             checkpt_path;    /* Wksp checkpoint format */
  char const *             checkpt_archive; /* Funk archive format */

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
#define FD_CAPTURE_CTX_FOOTPRINT ( sizeof(fd_capture_ctx_t) + fd_solcap_writer_footprint() )
#define FD_CAPTURE_CTX_MAGIC (0x193ECD2A6C395195UL) /* random */

FD_PROTOTYPES_BEGIN

void *
fd_capture_ctx_new( void * mem );

fd_capture_ctx_t *
fd_capture_ctx_join( void * mem );

void *
fd_capture_ctx_leave( fd_capture_ctx_t * ctx );

void *
fd_capture_ctx_delete( void * mem );

/* Temporary locks to protect the blockstore txn_map. See comment in
   fd_runtime_write_transaction_status. */
void
fd_capture_ctx_txn_status_start_read( void );

void
fd_capture_ctx_txn_status_end_read( void );

void
fd_capture_ctx_txn_status_start_write( void );

void
fd_capture_ctx_txn_status_end_write( void );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_runtime_context_fd_capture_ctx_h */
