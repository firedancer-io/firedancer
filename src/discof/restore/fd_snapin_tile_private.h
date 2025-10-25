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
    fd_vinyl_io_t * io;
    fd_vinyl_meta_t map[1];
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

FD_PROTOTYPES_BEGIN

void fd_snapin_process_account_header_funk( fd_snapin_tile_t * ctx, fd_ssparse_advance_result_t * result );
void fd_snapin_process_account_data_funk  ( fd_snapin_tile_t * ctx, fd_ssparse_advance_result_t * result );
void fd_snapin_process_account_batch_funk ( fd_snapin_tile_t * ctx, fd_ssparse_advance_result_t * result );

void fd_snapin_process_account_header_vinyl( fd_snapin_tile_t * ctx, fd_ssparse_advance_result_t * result );
void fd_snapin_process_account_data_vinyl  ( fd_snapin_tile_t * ctx, fd_ssparse_advance_result_t * result );
void fd_snapin_process_account_batch_vinyl ( fd_snapin_tile_t * ctx, fd_ssparse_advance_result_t * result );

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
