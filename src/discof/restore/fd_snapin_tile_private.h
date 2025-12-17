#ifndef HEADER_fd_discof_restore_fd_snapin_tile_private_h
#define HEADER_fd_discof_restore_fd_snapin_tile_private_h

/* fd_snapin_tile_private.h contains private APIs for the "snapin" tile,
   which is the tile responsible for parsing a snapshot, and directing
   database writes. */

#include "utils/fd_ssparse.h"
#include "utils/fd_ssmanifest_parser.h"
#include "utils/fd_slot_delta_parser.h"
#include "utils/fd_ssctrl.h"
#include "../../flamenco/accdb/fd_accdb_admin.h"
#include "../../flamenco/accdb/fd_accdb_user.h"
#include "../../flamenco/runtime/fd_txncache.h"
#include "../../disco/stem/fd_stem.h"
#include "../../disco/topo/fd_topo.h"
#include "../../vinyl/io/fd_vinyl_io.h"
#include "../../vinyl/meta/fd_vinyl_meta.h"

struct blockhash_group {
  uchar blockhash[ 32UL ];
  ulong txnhash_offset;
};

typedef struct blockhash_group blockhash_group_t;

struct fd_snapin_out_link {
  ulong       idx;
  fd_wksp_t * mem;
  ulong       chunk0;
  ulong       wmark;
  ulong       chunk;
  ulong       mtu;
};
typedef struct fd_snapin_out_link fd_snapin_out_link_t;

struct buffered_account_batch {
  uchar const * batch[ FD_SSPARSE_ACC_BATCH_MAX ];
  ulong         batch_cnt;
  ulong         slot;
  /* index at which to start processing a buffered account batch */
  ulong         remaining_idx;
};

typedef struct buffered_account_batch buffered_account_batch_t;

struct fd_snapin_tile {
  int  state;
  uint full      : 1;       /* loading a full snapshot? */
  uint use_vinyl : 1;       /* using vinyl-backed accdb? */
  uint lthash_disabled : 1; /* disable lthash checking? */

  ulong seed;
  long boot_timestamp;

  fd_accdb_admin_t accdb_admin[1];
  fd_accdb_user_t  accdb[1];

  fd_txncache_t * txncache;
  uchar *         acc_data;

  fd_funk_txn_xid_t xid[1]; /* txn XID */

  fd_stem_context_t *      stem;

  fd_ssparse_t *           ssparse;
  fd_ssmanifest_parser_t * manifest_parser;
  fd_slot_delta_parser_t * slot_delta_parser;

  buffered_account_batch_t buffered_batch;

  struct {
    int manifest_done;
    int status_cache_done;
    int manifest_processed;
  } flags;

  ulong bank_slot;

  ulong blockhash_offsets_len;
  blockhash_group_t * blockhash_offsets;

  ulong   txncache_entries_len;
  ulong * txncache_entries_len_vinyl_ptr;
  fd_sstxncache_entry_t * txncache_entries;

  fd_txncache_fork_id_t txncache_root_fork_id;

  struct {
    ulong full_bytes_read;
    ulong incremental_bytes_read;
    ulong accounts_inserted;
  } metrics;

  struct {
    fd_wksp_t * wksp;
    ulong       chunk0;
    ulong       wmark;
    ulong       mtu;
    ulong       pos;
  } in;

  ulong                out_ct_idx;
  fd_snapin_out_link_t manifest_out;
  fd_snapin_out_link_t gui_out;
  fd_snapin_out_link_t hash_out;
  ulong *              hash_out_cons_fseq;

  struct {
    uchar * bstream_mem;
    ulong   bstream_sz;

    /* Vinyl in either io_wd or io_mm mode */
    fd_vinyl_io_t * io;
    fd_vinyl_io_t * io_wd;
    fd_vinyl_io_t * io_mm;
    ulong           io_seed;

    fd_vinyl_meta_t map[1];

    ulong txn_seq;  /* bstream seq of first txn record (in [seq_past,seq_present]) */
    uint  txn_active : 1;
  } vinyl;

  struct {
    uchar * pair;
    ulong   pair_sz;

    uchar * dst;
    ulong   dst_rem;
    ulong   data_rem;

    fd_vinyl_meta_ele_t * meta_ele;
  } vinyl_op;
};

typedef struct fd_snapin_tile fd_snapin_tile_t;

/* Funk APIs **********************************************************/

FD_PROTOTYPES_BEGIN

int fd_snapin_process_account_header_funk( fd_snapin_tile_t * ctx, fd_ssparse_advance_result_t * result );
int fd_snapin_process_account_data_funk  ( fd_snapin_tile_t * ctx, fd_ssparse_advance_result_t * result );
int fd_snapin_process_account_batch_funk ( fd_snapin_tile_t * ctx, fd_ssparse_advance_result_t * result, buffered_account_batch_t * buffered_batch );

void
fd_snapin_read_account_funk( fd_snapin_tile_t *  ctx,
                             void const *        acct_addr,
                             fd_account_meta_t * meta,
                             uchar *             data,
                             ulong               data_max );

FD_PROTOTYPES_END

/* Vinyl APIs *********************************************************/

FD_PROTOTYPES_BEGIN

#define FD_SNAPIN_IO_SPAD_MAX (64UL<<20) /* 64 MiB of I/O scratch space */

/* fd_snapin_vinyl_privileged_init performs administrative tasks, such
   as opening and mapping the bstream file descriptor. */

void
fd_snapin_vinyl_privileged_init( fd_snapin_tile_t * ctx,
                                 fd_topo_t *        topo,
                                 fd_topo_tile_t *   tile );

/* fd_snapin_vinyl_unprivileged_init performs setup tasks after being
   sandboxed.  (anything that might be exposed to untrusted data) */

void
fd_snapin_vinyl_unprivileged_init( fd_snapin_tile_t * ctx,
                                   fd_topo_t *        topo,
                                   fd_topo_tile_t *   tile,
                                   void *             io_mm_mem,
                                   void *             io_wd_mem );

/* fd_snapin_vinyl_seccomp returns a seccomp sandbox policy suitable
   for vinyl operation. */

ulong
fd_snapin_vinyl_seccomp( ulong                out_cnt,
                         struct sock_filter * out );

/* fd_snapin_vinyl_reset pauses the snapwr tile (waits for the snapwr
   tile to ack) and formats a bstream file to be empty.  THIS IS A
   DESTRUCTIVE ACTION. */

void
fd_snapin_vinyl_reset( fd_snapin_tile_t * ctx );

/* fd_snapin_vinyl_txn_begin starts a transactional burst write.
   Assumes vinyl uses the io_mm backend.  The write can then either be
   committed or cancelled.  There is no practical limit on the size of
   this burst. */

void
fd_snapin_vinyl_txn_begin( fd_snapin_tile_t * ctx );

/* fd_snapin_vinyl_txn_commit finishes a transactional burst write.
   Assumes vinyl uses the io_mm backend.  Reads through bstream records
   written since txn_begin was called and updates the vinyl_meta index. */

void
fd_snapin_vinyl_txn_commit( fd_snapin_tile_t * ctx );

/* fd_snapin_vinyl_txn_cancel abandons a transactional burst write.
   Assumes vinyl uses the io_mm backend.  Reverts the bstream state to
   when txn_begin was called. */

void
fd_snapin_vinyl_txn_cancel( fd_snapin_tile_t * ctx );

/* fd_snapin_vinyl_wd_init transitions the vinyl backend from generic
   vinyl accessor (io_mm) to fast dumb direct account insertion (io_wd).
   This must be called before calling fd_snapin_process_account_*.
   Starts the snapwr tile (waits for the snapwr tile to ack). */

void
fd_snapin_vinyl_wd_init( fd_snapin_tile_t * ctx );

/* fd_snapin_vinyl_wd_fini transitions the vinyl backend from fast dumb
   direct account insertion (io_wd) back to generic mode (io_mm).
   Pauses the snapwr tile (waits for the snapwr to ack). */

void
fd_snapin_vinyl_wd_fini( fd_snapin_tile_t * ctx );

/* fd_snapin_vinyl_shutdown instructs vinyl-related tiles of the loader
   to shut down.  Blocks until all affected tiles have acknowledged the
   shutdown signal. */

void
fd_snapin_vinyl_shutdown( fd_snapin_tile_t * ctx );

/* Internal APIs for inserting accounts */

int fd_snapin_process_account_header_vinyl( fd_snapin_tile_t * ctx, fd_ssparse_advance_result_t * result );
int fd_snapin_process_account_data_vinyl  ( fd_snapin_tile_t * ctx, fd_ssparse_advance_result_t * result );
int fd_snapin_process_account_batch_vinyl ( fd_snapin_tile_t * ctx, fd_ssparse_advance_result_t * result );

void
fd_snapin_read_account_vinyl( fd_snapin_tile_t *  ctx,
                              void const *        acct_addr,
                              fd_account_meta_t * meta,
                              uchar *             data,
                              ulong               data_max );

FD_PROTOTYPES_END

/* Generic APIs *******************************************************/

FD_PROTOTYPES_BEGIN

/* int return value for fd_snapin_process_account_header,
fd_snapin_process_account_data, and fd_snapin_process_account_batch
indicates whether to yield to stem for credit return */

static inline int
fd_snapin_process_account_header( fd_snapin_tile_t *            ctx,
                                  fd_ssparse_advance_result_t * result ) {
  if( ctx->use_vinyl ) {
    return fd_snapin_process_account_header_vinyl( ctx, result );
  } else {
    return fd_snapin_process_account_header_funk( ctx, result );
  }
  return 0;
}

static inline int
fd_snapin_process_account_data( fd_snapin_tile_t *            ctx,
                                fd_ssparse_advance_result_t * result ) {
  if( ctx->use_vinyl ) {
    return fd_snapin_process_account_data_vinyl( ctx, result );
  } else {
    return fd_snapin_process_account_data_funk( ctx, result );
  }
  return 0;
}

static inline int
fd_snapin_process_account_batch( fd_snapin_tile_t *            ctx,
                                 fd_ssparse_advance_result_t * result,
                                 buffered_account_batch_t *    buffered_batch ) {
  if( ctx->use_vinyl ) {
    return fd_snapin_process_account_batch_vinyl( ctx, result );
  } else {
    return fd_snapin_process_account_batch_funk( ctx, result, buffered_batch );
  }
  return 0;
}

static inline void
fd_snapin_read_account( fd_snapin_tile_t *  ctx,
                        void const *        acct_addr,
                        fd_account_meta_t * meta,
                        uchar *             data,
                        ulong               data_max ) {
  if( ctx->use_vinyl ) {
    fd_snapin_read_account_vinyl( ctx, acct_addr, meta, data, data_max );
  } else {
    fd_snapin_read_account_funk( ctx, acct_addr, meta, data, data_max );
  }
}

/* fd_snapin_send_duplicate_account sends a duplicate account message
   with the signature FD_SNAPSHOT_HASH_MSG_SUB or
   FD_SNAPSHOT_HASH_MSG_SUB_HDR, depending on if this duplicate account
   contains valid account data. The message is only
   sent if lthash verification is enabled in the snapshot loader.

   lamports is account's lamports value.  data is the account's data,
   which can be optionally null.  data_len is the length of the account
   data.  executable is the account's executable flag. owner points to
   the account's owner (32 bytes).  pubkey points to the account's
   pubkey (32 bytes).  early_exit is an optional pointer to an int flag
   that is set to 1 if the caller should yield to stem following this
   call. */
static inline void
fd_snapin_send_duplicate_account( fd_snapin_tile_t * ctx,
                                  ulong              lamports,
                                  uchar const *      data,
                                  ulong              data_len,
                                  uchar              executable,
                                  uchar const *      owner,
                                  uchar const *      pubkey,
                                  int                has_data,
                                  int *              early_exit ) {
  if( FD_UNLIKELY( ctx->lthash_disabled ) ) return;

  if( FD_LIKELY( has_data ) ) {
    fd_snapshot_full_account_t * existing_account = fd_chunk_to_laddr( ctx->hash_out.mem, ctx->hash_out.chunk );
    fd_snapshot_account_hdr_init( &existing_account->hdr, pubkey, owner, lamports, executable, data_len );
    fd_memcpy( existing_account->data, data, data_len );
    fd_stem_publish( ctx->stem, ctx->out_ct_idx, FD_SNAPSHOT_HASH_MSG_SUB, ctx->hash_out.chunk, sizeof(fd_snapshot_account_hdr_t)+data_len, 0UL, 0UL, 0UL );
    ctx->hash_out.chunk = fd_dcache_compact_next( ctx->hash_out.chunk, sizeof(fd_snapshot_account_hdr_t)+data_len, ctx->hash_out.chunk0, ctx->hash_out.wmark );
  } else {
    fd_snapshot_account_hdr_t * acc_hdr = fd_chunk_to_laddr( ctx->hash_out.mem, ctx->hash_out.chunk );
    fd_snapshot_account_hdr_init( acc_hdr, pubkey, owner, lamports, executable, data_len );
    fd_stem_publish( ctx->stem, ctx->out_ct_idx, FD_SNAPSHOT_HASH_MSG_SUB_HDR, ctx->hash_out.chunk, sizeof(fd_snapshot_account_hdr_t), 0UL, 0UL, 0UL );
    ctx->hash_out.chunk = fd_dcache_compact_next( ctx->hash_out.chunk, sizeof(fd_snapshot_account_hdr_t), ctx->hash_out.chunk0, ctx->hash_out.wmark );
  }
  if( FD_LIKELY( early_exit ) ) *early_exit = 1;
}

/* fd_snapin_send_duplicate_account_data sends a duplicate account
   message with the signature FD_SNAPSHOT_HASH_MSG_SUB_DATA.  The
   message is only sent if lthash verification is enabled in the
   snapshot loader.

   data is the account's data, which cannot be null.  data_len is the
   length of the account data.  early_exit is an optional pointer to an
   int flag that is set to 1 if the caller should yield to stem
   following this call. */
static inline void
fd_snapin_send_duplicate_account_data( fd_snapin_tile_t * ctx,
                                       uchar const *      data,
                                       ulong              data_sz,
                                       int *              early_exit ) {
  if( FD_UNLIKELY( ctx->lthash_disabled ) ) return;

  uchar * drop_account_data = fd_chunk_to_laddr( ctx->hash_out.mem, ctx->hash_out.chunk );
  fd_memcpy( drop_account_data, data, data_sz );
  fd_stem_publish( ctx->stem, ctx->out_ct_idx, FD_SNAPSHOT_HASH_MSG_SUB_DATA, ctx->hash_out.chunk, data_sz, 0UL, 0UL, 0UL );
  ctx->hash_out.chunk = fd_dcache_compact_next( ctx->hash_out.chunk, data_sz, ctx->hash_out.chunk0, ctx->hash_out.wmark );
  if( FD_LIKELY( early_exit ) ) *early_exit = 1;
}

FD_PROTOTYPES_END

#endif /* HEADER_fd_discof_restore_fd_snapin_tile_private_h */
