#ifndef HEADER_fd_discof_restore_fd_snapin_tile_private_h
#define HEADER_fd_discof_restore_fd_snapin_tile_private_h

/* fd_snapin_tile_private.h contains private APIs for the "snapin" tile,
   which is the tile responsible for parsing a snapshot, and directing
   database writes. */

#include "utils/fd_ssparse.h"
#include "utils/fd_ssmanifest_parser.h"
#include "utils/fd_slot_delta_parser.h"
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

struct fd_snapin_tile {
  int  state;
  uint full      : 1; /* loading a full snapshot? */
  uint use_vinyl : 1; /* using vinyl-backed accdb? */

  ulong seed;
  long boot_timestamp;

  fd_accdb_admin_t accdb_admin[1];
  fd_accdb_user_t  accdb[1];

  fd_txncache_t * txncache;
  uchar *         acc_data;

  fd_funk_txn_xid_t xid[1]; /* txn XID */

  fd_stem_context_t *      stem;
  ulong                    out_ct_idx;
  ulong                    out_mani_idx;

  fd_ssparse_t *           ssparse;
  fd_ssmanifest_parser_t * manifest_parser;
  fd_slot_delta_parser_t * slot_delta_parser;

  struct {
    int manifest_done;
    int status_cache_done;
    int manifest_processed;
  } flags;

  ulong bank_slot;

  ulong blockhash_offsets_len;
  blockhash_group_t * blockhash_offsets;

  ulong txncache_entries_len;
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

  struct {
    fd_wksp_t * wksp;
    ulong       chunk0;
    ulong       wmark;
    ulong       chunk;
    ulong       mtu;
  } manifest_out;

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

void fd_snapin_process_account_header_funk( fd_snapin_tile_t * ctx, fd_ssparse_advance_result_t * result );
void fd_snapin_process_account_data_funk  ( fd_snapin_tile_t * ctx, fd_ssparse_advance_result_t * result );
void fd_snapin_process_account_batch_funk ( fd_snapin_tile_t * ctx, fd_ssparse_advance_result_t * result );

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

void fd_snapin_process_account_header_vinyl( fd_snapin_tile_t * ctx, fd_ssparse_advance_result_t * result );
void fd_snapin_process_account_data_vinyl  ( fd_snapin_tile_t * ctx, fd_ssparse_advance_result_t * result );
void fd_snapin_process_account_batch_vinyl ( fd_snapin_tile_t * ctx, fd_ssparse_advance_result_t * result );

FD_PROTOTYPES_END

/* Generic APIs *******************************************************/

FD_PROTOTYPES_BEGIN

static inline void
fd_snapin_process_account_header( fd_snapin_tile_t *            ctx,
                                  fd_ssparse_advance_result_t * result ) {
  if( ctx->use_vinyl ) {
    fd_snapin_process_account_header_vinyl( ctx, result );
  } else {
    fd_snapin_process_account_header_funk( ctx, result );
  }
}

static inline void
fd_snapin_process_account_data( fd_snapin_tile_t *            ctx,
                                fd_ssparse_advance_result_t * result ) {
  if( ctx->use_vinyl ) {
    fd_snapin_process_account_data_vinyl( ctx, result );
  } else {
    fd_snapin_process_account_data_funk( ctx, result );
  }
}

static inline void
fd_snapin_process_account_batch( fd_snapin_tile_t *            ctx,
                                 fd_ssparse_advance_result_t * result ) {
  if( ctx->use_vinyl ) {
    fd_snapin_process_account_batch_vinyl( ctx, result );
  } else {
    fd_snapin_process_account_batch_funk( ctx, result );
  }
}

FD_PROTOTYPES_END

#endif /* HEADER_fd_discof_restore_fd_snapin_tile_private_h */
