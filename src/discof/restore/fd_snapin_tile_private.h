#ifndef HEADER_fd_discof_restore_fd_snapin_tile_private_h
#define HEADER_fd_discof_restore_fd_snapin_tile_private_h

/* fd_snapin_tile_private.h contains private APIs for the "snapin" tile,
   which is the tile responsible for parsing a snapshot, and directing
   database writes. */

#include "utils/fd_ssparse.h"
#include "utils/fd_ssmanifest_parser.h"
#include "utils/fd_slot_delta_parser.h"
#include "../../flamenco/accdb/fd_accdb_admin.h"
#include "../../flamenco/runtime/fd_txncache.h"
#include "../../disco/stem/fd_stem.h"

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
};

typedef struct fd_snapin_tile fd_snapin_tile_t;

FD_PROTOTYPES_BEGIN

void fd_snapin_process_account_header_funk( fd_snapin_tile_t * ctx, fd_ssparse_advance_result_t * result );
void fd_snapin_process_account_data_funk  ( fd_snapin_tile_t * ctx, fd_ssparse_advance_result_t * result );
void fd_snapin_process_account_batch_funk ( fd_snapin_tile_t * ctx, fd_ssparse_advance_result_t * result );

void
fd_snapin_read_account_funk( fd_snapin_tile_t *  ctx,
                             void const *        acct_addr,
                             fd_account_meta_t * meta,
                             uchar *             data,
                             ulong               data_max );

static inline void
fd_snapin_process_account_header( fd_snapin_tile_t *            ctx,
                                  fd_ssparse_advance_result_t * result ) {
  fd_snapin_process_account_header_funk( ctx, result );
}

static inline void
fd_snapin_process_account_data( fd_snapin_tile_t *            ctx,
                                fd_ssparse_advance_result_t * result ) {
  fd_snapin_process_account_data_funk( ctx, result );
}

static inline void
fd_snapin_process_account_batch( fd_snapin_tile_t *            ctx,
                                 fd_ssparse_advance_result_t * result ) {
  fd_snapin_process_account_batch_funk( ctx, result );
}

static inline void
fd_snapin_read_account( fd_snapin_tile_t *  ctx,
                        void const *        acct_addr,
                        fd_account_meta_t * meta,
                        uchar *             data,
                        ulong               data_max ) {
  fd_snapin_read_account_funk( ctx, acct_addr, meta, data, data_max );
}

FD_PROTOTYPES_END

#endif /* HEADER_fd_discof_restore_fd_snapin_tile_private_h */
