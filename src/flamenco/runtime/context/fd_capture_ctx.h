#ifndef HEADER_fd_src_flamenco_runtime_context_fd_capture_ctx_h
#define HEADER_fd_src_flamenco_runtime_context_fd_capture_ctx_h

#include "../../capture/fd_solcap_writer.h"
#include "../fd_runtime_const.h"

/* fd_capture_ctx_account_update_msg_t is the message sent from
   writer tile to replay tile that notifies the solcap writer that an
   account update has occurred. */

struct __attribute__((packed)) fd_capture_ctx_account_update_msg {
  fd_pubkey_t              pubkey;
  fd_solana_account_meta_t info;
  ulong                    data_sz;
  fd_hash_t                hash;
  /* Account data follows immediately after this struct */
};
typedef struct fd_capture_ctx_account_update_msg fd_capture_ctx_account_update_msg_t;
#define FD_CAPTURE_CTX_ACCOUNT_UPDATE_MSG_FOOTPRINT (FD_RUNTIME_ACC_SZ_MAX + sizeof(fd_capture_ctx_account_update_msg_t))

/* Maximum number of accounts that can be updated in a single transaction */
#define FD_CAPTURE_CTX_MAX_ACCOUNT_UPDATES         (128UL)
#define FD_CAPTURE_CTX_ACCOUNT_UPDATE_BUFFER_SZ    (FD_CAPTURE_CTX_MAX_ACCOUNT_UPDATES * FD_CAPTURE_CTX_ACCOUNT_UPDATE_MSG_FOOTPRINT)
#define FD_CAPTURE_CTX_ACCOUNT_UPDATE_BUFFER_ALIGN (8UL)

/* Context needed to do solcap capture during execution of transactions */
struct fd_capture_ctx {
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

  /* Account update buffer, account updates to be sent over the writer_replay link are buffered here
     to avoid passing stem down into the runtime.

     FIXME: write directly into the dcache to avoid the memory copy and allocation
     TODO: remove this when solcap v2 is here. */
  uchar *                    account_updates_buffer;
  uchar *                    account_updates_buffer_ptr;
  ulong                      account_updates_len;
};
typedef struct fd_capture_ctx fd_capture_ctx_t;

static inline ulong
fd_capture_ctx_align( void ) {
  return fd_ulong_max( alignof(fd_capture_ctx_t),
         fd_ulong_max( fd_solcap_writer_align(), FD_CAPTURE_CTX_ACCOUNT_UPDATE_BUFFER_ALIGN ));
}

static inline ulong
fd_capture_ctx_footprint( void ) {
  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, fd_capture_ctx_align(),   sizeof(fd_capture_ctx_t) );
  l = FD_LAYOUT_APPEND( l, fd_solcap_writer_align(), fd_solcap_writer_footprint() );
  l = FD_LAYOUT_APPEND( l, 8UL,                      FD_CAPTURE_CTX_ACCOUNT_UPDATE_BUFFER_SZ );
  return FD_LAYOUT_FINI( l, fd_capture_ctx_align() );
}

#define FD_CAPTURE_CTX_MAGIC     (0x193ECD2A6C395195UL) /* random */

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
