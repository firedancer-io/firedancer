#ifndef HEADER_fd_src_flamenco_capture_fd_capture_ctx_h
#define HEADER_fd_src_flamenco_capture_fd_capture_ctx_h

/* fd_capture_ctx provides a context for capturing Solana runtime data
   during transaction execution.  The capture system supports two output
   modes:

   1. Buffer mode: writes to a shared memory buffer that is consumed by
      a capture tile and subsequently written to a file.  This is the
      default for live firedancer execution and backtest.

   2. File mode: writes directly to a file.  This is used for single-
      threaded harnesses that don't need the capture tile.

   Captured data includes account updates, bank preimages, and other
   runtime events in the solcap format. */

#include "fd_solcap_writer.h"
#include "../../util/fd_util_base.h"
#include "../../util/log/fd_log.h"
#include <sys/types.h>
#include "../../tango/fd_tango_base.h"

typedef struct fd_capture_link_vt fd_capture_link_vt_t;

/* fd_capture_link_t is the base type for capture links.  It uses a
   v-table pattern to support polymorphic write operations to either
   buffer or file destinations. */

struct fd_capture_link {
  fd_capture_link_vt_t const * vt; /* Virtual function table for this link type */
};
typedef struct fd_capture_link fd_capture_link_t;

/* fd_capture_link_buf_t is a capture link that writes to a shared
   memory buffer (frag stream).  This buffer is consumed by a capture
   tile which writes the data to a file. */

struct fd_capture_link_buf {
  fd_capture_link_t base;
  ulong             idx;
  fd_wksp_t *       mem;
  ulong             chunk0;
  ulong             wmark;
  ulong             chunk;
  fd_frag_meta_t *  mcache;
  ulong             depth;
  ulong             seq;
  ulong *           fseq;
};
typedef struct fd_capture_link_buf fd_capture_link_buf_t;

/* fd_capture_link_file_t is a capture link that writes directly to a
   file.  Used in single-threaded harness mode. */

struct fd_capture_link_file {
  fd_capture_link_t base;
  int               fd;
};
typedef struct fd_capture_link_file fd_capture_link_file_t;

/* fd_capture_link_vt_t is the virtual function table for capture
   links.  This allows the capture context to write to different
   destinations (buffer or file) without needing to check the link type
   at each call site. */

struct fd_capture_link_vt {
  void (* write_account_update)( fd_capture_ctx_t *               ctx,
                                 ulong                            txn_idx,
                                 fd_pubkey_t const *              key,
                                 fd_solana_account_meta_t const * info,
                                 ulong                            slot,
                                 uchar const *                    data,
                                 ulong                            data_sz);

  void (* write_bank_preimage)( fd_capture_ctx_t * ctx,
                                ulong              slot,
                                fd_hash_t const *  bank_hash,
                                fd_hash_t const *  prev_bank_hash,
                                fd_hash_t const *  accounts_lt_hash_checksum,
                                fd_hash_t const *  poh_hash,
                                ulong              signature_cnt);
};


/* Context needed to do solcap capture during execution of transactions */

struct fd_capture_ctx {
  ulong magic; /* ==FD_CAPTURE_CTX_MAGIC */

  fd_capture_link_t *        capture_link;
  union {
    fd_capture_link_buf_t * buf;
    fd_capture_link_file_t * file;
  } capctx_type;

  /* Solcap */
  ulong                    solcap_start_slot;
  fd_solcap_writer_t *     capture;

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

static inline ulong
fd_capture_ctx_align( void ) {
  return fd_ulong_max( alignof(fd_capture_ctx_t), fd_solcap_writer_align() );
}

static inline ulong
fd_capture_ctx_footprint( void ) {
  ulong l = FD_LAYOUT_INIT;
  l    = FD_LAYOUT_APPEND ( l, fd_capture_ctx_align(),   sizeof(fd_capture_ctx_t) );
  l    = FD_LAYOUT_APPEND ( l, fd_solcap_writer_align(), fd_solcap_writer_footprint() );
  return FD_LAYOUT_FINI   ( l, fd_capture_ctx_align() );
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

FD_PROTOTYPES_END

/* Solcap capture link functions

   The following functions write solcap messages to either a buffer or
   file.  They are used as v-table implementations for the capture link
   abstraction.

   For each message type, there are two implementations:
   - _buf:  writes to a shared memory frag stream (buffer mode)
   - _file: writes directly to a file descriptor (file mode)

   The v-table dispatch mechanism automatically selects the correct
   implementation based on the link type, so callers use the inline
   wrapper functions below instead of calling these directly.

*/

void
fd_capture_link_translate_account_update_buf( fd_capture_ctx_t *               ctx,
                                              ulong                            txn_idx,
                                              fd_pubkey_t const *              key,
                                              fd_solana_account_meta_t const * info,
                                              ulong                            slot,
                                              uchar const *                    data,
                                              ulong                            data_sz );

void
fd_capture_link_translate_account_update_file( fd_capture_ctx_t *               ctx,
                                               ulong                            txn_idx,
                                               fd_pubkey_t const *              key,
                                               fd_solana_account_meta_t const * info,
                                               ulong                            slot,
                                               uchar const *                    data,
                                               ulong                            data_sz );

/* fd_capture_link_write_account_update writes an account update to the
   capture link. Uses v-table dispatch to automatically route to the
   correct implementation (buffer or file) based on the link type. */

static inline void
fd_capture_link_write_account_update( fd_capture_ctx_t *               ctx,
                                      ulong                            txn_idx,
                                      fd_pubkey_t const *              key,
                                      fd_solana_account_meta_t const * info,
                                      ulong                            slot,
                                      uchar const *                    data,
                                      ulong                            data_sz ) {
  FD_TEST( ctx && ctx->capture_link );
  ctx->capture_link->vt->write_account_update( ctx, txn_idx, key, info, slot, data, data_sz );
}

void
fd_capture_link_write_bank_preimage_buf( fd_capture_ctx_t * ctx,
                                         ulong              slot,
                                         fd_hash_t const *  bank_hash,
                                         fd_hash_t const *  prev_bank_hash,
                                         fd_hash_t const *  accounts_lt_hash_checksum,
                                         fd_hash_t const *  poh_hash,
                                         ulong              signature_cnt );

void
fd_capture_link_write_bank_preimage_file( fd_capture_ctx_t * ctx,
                                          ulong              slot,
                                          fd_hash_t const *  bank_hash,
                                          fd_hash_t const *  prev_bank_hash,
                                          fd_hash_t const *  accounts_lt_hash_checksum,
                                          fd_hash_t const *  poh_hash,
                                          ulong              signature_cnt );

/* fd_capture_link_write_bank_preimage writes a bank preimage to the
   capture link. Uses v-table dispatch to automatically route to the
   correct implementation (buffer or file) based on the link type. */

static inline void
fd_capture_link_write_bank_preimage( fd_capture_ctx_t * ctx,
                                     ulong              slot,
                                     fd_hash_t const *  bank_hash,
                                     fd_hash_t const *  prev_bank_hash,
                                     fd_hash_t const *  accounts_lt_hash_checksum,
                                     fd_hash_t const *  poh_hash,
                                     ulong              signature_cnt ) {
  FD_TEST( ctx && ctx->capture_link );
  ctx->capture_link->vt->write_bank_preimage( ctx, slot, bank_hash, prev_bank_hash, accounts_lt_hash_checksum, poh_hash, signature_cnt );
}

/* fd_capture_link_buf_vt is the v-table for buffer mode capture links.
   It routes all write operations to the buffer implementations. */

static const
fd_capture_link_vt_t fd_capture_link_buf_vt = {
  .write_account_update = fd_capture_link_translate_account_update_buf,
  .write_bank_preimage  = fd_capture_link_write_bank_preimage_buf,
};

/* fd_capture_link_file_vt is the v-table for file mode capture links.
   It routes all write operations to the file implementations. */

static const
fd_capture_link_vt_t fd_capture_link_file_vt = {
  .write_account_update = fd_capture_link_translate_account_update_file,
  .write_bank_preimage  = fd_capture_link_write_bank_preimage_file,
};

#endif /* HEADER_fd_src_flamenco_capture_fd_capture_ctx_h */

