#ifndef HEADER_fd_src_discof_capture_fd_capture_ctx_h
#define HEADER_fd_src_discof_capture_fd_capture_ctx_h

#include "../../flamenco/capture/fd_solcap_writer.h"
#include "../../flamenco/runtime/fd_runtime_const.h"
#include "../../flamenco/fd_rwlock.h"
#include "../../util/fd_util_base.h"
#include "../../util/log/fd_log.h"
#include <sys/types.h>
#include "../../flamenco/capture/fd_solcap_proto.h"
#include "../../tango/mcache/fd_mcache.h"
#include "../../tango/dcache/fd_dcache.h"
#include "../../tango/fd_tango_base.h"

/*

Nishk (TODO): Write docs for capture context

*/


/* fd_capture_ctx_account_update_msg_t is the message sent from
   exec tile to replay tile that notifies the solcap writer that an
   account update has occurred. */

struct __attribute__((packed)) fd_capture_ctx_account_update_msg {
  fd_pubkey_t              pubkey;
  fd_solana_account_meta_t info;
  ulong                    data_sz;
  fd_hash_t                hash;
  ulong                    bank_idx;
  /* Account data follows immediately after this struct */
};
typedef struct fd_capture_ctx_account_update_msg fd_capture_ctx_account_update_msg_t;

typedef struct fd_capture_link_vt fd_capture_link_vt_t;

struct fd_capture_link {
  const fd_capture_link_vt_t * vt;
};
typedef struct fd_capture_link fd_capture_link_t;

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

struct fd_capture_link_file {
  fd_capture_link_t base;
  FILE *           file;
};
typedef struct fd_capture_link_file fd_capture_link_file_t;

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
  } capctx_buf;

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

/*
  Solcap Buffer Writables

  All the following functions are helpers to be used by subscribers of
  the shared capture context buffer to write solcap messages out to the
  buffer.
*/

struct __attribute__((packed)) fd_solcap_buf_msg {
  ushort sig;
  ulong slot;
  ulong txn_idx;
  /* Data follows immediately after this struct in memory */
};
typedef struct fd_solcap_buf_msg fd_solcap_buf_msg_t;

/* The following capctx_buf_translate functions are wrappers used by
   the funtime to drop solcap buffer messages into the capctx buffer.

   Each is mapped directly to a specific solcap writer function.
*/

void
fd_cap_link_translate_account_update_buf(fd_capture_ctx_t *             ctx,
                                       ulong                            txn_idx,
                                       fd_pubkey_t const *              key,
                                       fd_solana_account_meta_t const * info,
                                       ulong                            slot,
                                       uchar const *                    data,
                                       ulong                            data_sz);

void
fd_cap_link_translate_account_update_file( fd_capture_ctx_t *               ctx,
                                           ulong                            txn_idx,
                                           fd_pubkey_t const *              key,
                                           fd_solana_account_meta_t const * info,
                                           ulong                            slot,
                                           uchar const *                    data,
                                           ulong                            data_sz);

static inline void
fd_capture_link_write_account_update( fd_capture_ctx_t *               ctx,
                                      ulong                            txn_idx,
                                      fd_pubkey_t const *              key,
                                      fd_solana_account_meta_t const * info,
                                      ulong                            slot,
                                      uchar const *                    data,
                                      ulong                            data_sz) {
  ctx->capture_link->vt->write_account_update(ctx, txn_idx, key, info, slot, data, data_sz);
}

void
fd_cap_link_write_bank_preimage_buf( fd_capture_ctx_t * ctx,
                                     ulong              slot,
                                     fd_hash_t const *  bank_hash,
                                     fd_hash_t const *  prev_bank_hash,
                                     fd_hash_t const *  accounts_lt_hash_checksum,
                                     fd_hash_t const *  poh_hash,
                                     ulong              signature_cnt);

void
fd_cap_link_write_bank_preimage_file( fd_capture_ctx_t * ctx,
                                      ulong              slot,
                                      fd_hash_t const *  bank_hash,
                                      fd_hash_t const *  prev_bank_hash,
                                      fd_hash_t const *  accounts_lt_hash_checksum,
                                      fd_hash_t const *  poh_hash,
                                      ulong              signature_cnt);

static inline void
fd_capture_link_write_bank_preimage( fd_capture_ctx_t * ctx,
                                     ulong              slot,
                                     fd_hash_t const *  bank_hash,
                                     fd_hash_t const *  prev_bank_hash,
                                     fd_hash_t const *  accounts_lt_hash_checksum,
                                     fd_hash_t const *  poh_hash,
                                     ulong              signature_cnt) {
  ctx->capture_link->vt->write_bank_preimage(ctx, slot, bank_hash, prev_bank_hash, accounts_lt_hash_checksum, poh_hash, signature_cnt);
}

static const
fd_capture_link_vt_t fd_capture_link_buf_vt = {
  .write_account_update = fd_cap_link_translate_account_update_buf,
  .write_bank_preimage  = fd_cap_link_write_bank_preimage_buf,
};

static const
fd_capture_link_vt_t fd_capture_link_file_vt = {
  .write_account_update = fd_cap_link_translate_account_update_file,
  .write_bank_preimage  = fd_cap_link_write_bank_preimage_file,
};

uint32_t
fd_capctx_buf_process_msg( fd_capture_ctx_t *   capture_ctx,
                          fd_solcap_buf_msg_t * msg_hdr,
                          char *                actual_data );

#endif /* HEADER_fd_src_discof_capture_fd_capture_ctx_h */
