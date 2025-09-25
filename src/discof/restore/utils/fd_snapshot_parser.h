#ifndef HEADER_fd_src_discof_restore_utils_fd_snapshot_parser_h
#define HEADER_fd_src_discof_restore_utils_fd_snapshot_parser_h

#include "../../../flamenco/types/fd_types.h"
#include "fd_ssmanifest_parser.h"
#include "fd_slot_delta_parser.h"
#include "fd_ssmsg.h"

#define SNAP_STATE_IGNORE       ((uchar)0)  /* ignore file content */
#define SNAP_STATE_TAR          ((uchar)1)  /* reading tar header (buffered) */
#define SNAP_STATE_MANIFEST     ((uchar)2)  /* reading manifest (zero copy) */
#define SNAP_STATE_STATUS_CACHE ((uchar)3)  /* reading status cache (zero copy) */
#define SNAP_STATE_ACCOUNT_HDR  ((uchar)4)  /* reading account hdr (buffered) */
#define SNAP_STATE_ACCOUNT_DATA ((uchar)5)  /* reading account data (zero copy) */
#define SNAP_STATE_DONE         ((uchar)6)  /* expect no more data */

#define SNAP_FLAG_FAILED  1
#define SNAP_FLAG_DONE    2

struct fd_snapshot_parser;
typedef struct fd_snapshot_parser fd_snapshot_parser_t;

typedef void
(* fd_snapshot_parser_process_manifest_fn_t)( void * _ctx );

typedef void
(* fd_snapshot_process_acc_hdr_fn_t)( void *                          _ctx,
                                      fd_solana_account_hdr_t const * hdr );

typedef void
(* fd_snapshot_process_acc_data_fn_t)( void *        _ctx,
                                       uchar const * buf,
                                       ulong         data_sz );

struct fd_snapshot_parser_metrics {
  ulong accounts_files_processed;
  ulong accounts_files_total;
  ulong accounts_processed;
};

typedef struct fd_snapshot_parser_metrics fd_snapshot_parser_metrics_t;

struct fd_snapshot_parser {
  uchar state;
  uchar flags;
  uchar manifest_done;
  uchar status_cache_done;
  uchar processing_accv;

  /* Frame buffer */

  uchar * buf;
  ulong   buf_ctr;  /* number of bytes allocated in buffer */
  ulong   buf_sz;   /* target buffer size (buf_ctr<buf_sz implies incomplete read) */
  ulong   buf_max;  /* byte capacity of buffer */

  /* Manifest dcache buffer */
  uchar * manifest_buf;
  ulong   manifest_bufsz;

  /* Tar parser */
  ulong goff;          /* current position in stream */
  ulong tar_file_rem; /* number of stream bytes in current TAR file */

  /* Snapshot file parser */
  ulong   accv_slot;     /* account vec slot */
  ulong   accv_id;       /* account vec index */
  ulong   accv_sz;       /* account vec size */
  ulong   accv_key_max;  /* max account vec count */

  /* Account defrag */
  ulong acc_sz;
  ulong acc_rem;  /* acc bytes pending write */
  ulong acc_pad;  /* padding size at end of account */

  /* Account processing callbacks */
  fd_snapshot_parser_process_manifest_fn_t manifest_cb;
  fd_slot_delta_parser_process_entry_fn_t  status_cache_cb;
  fd_snapshot_process_acc_hdr_fn_t         acc_hdr_cb;
  fd_snapshot_process_acc_data_fn_t        acc_data_cb;
  void * cb_arg;

  fd_ssmanifest_parser_t * manifest_parser;
  fd_slot_delta_parser_t * slot_delta_parser;

  /* Metrics */
  fd_snapshot_parser_metrics_t metrics;
};
typedef struct fd_snapshot_parser fd_snapshot_parser_t;

FD_FN_CONST static inline ulong
fd_snapshot_parser_align( void ) {
  return 128UL;
}

FD_FN_CONST ulong
fd_snapshot_parser_footprint( ulong max_acc_vecs );

static inline void
fd_snapshot_parser_reset_tar( fd_snapshot_parser_t * self ) {
  self->state           = SNAP_STATE_TAR;
  self->buf_ctr         = 0UL;
  self->buf_sz          = 0UL;
  self->processing_accv = 0;
  self->tar_file_rem    = 0UL;
}

/* Reset the snapshot parser on a new stream.  As part of stream
   decoding, the manifest is written to an output buffer so that the
   caller can send it to interested parties.  The location to place the
   manifest should be given in the manifest_buf and manifest_bufsz
   parameters. */

static inline void
fd_snapshot_parser_reset( fd_snapshot_parser_t * self,
                          uchar *                manifest_buf,
                          ulong                  manifest_bufsz ) {
  self->flags = 0UL;
  fd_snapshot_parser_reset_tar( self );
  fd_ssmanifest_parser_init( self->manifest_parser, (fd_snapshot_manifest_t*)manifest_buf );
  fd_slot_delta_parser_init( self->slot_delta_parser, self->status_cache_cb, self->cb_arg );

  self->status_cache_done    = 0;
  self->manifest_done        = 0;
  self->metrics.accounts_files_processed = 0UL;
  self->metrics.accounts_files_total     = 0UL;
  self->metrics.accounts_processed       = 0UL;
  self->processing_accv                  = 0;
  self->goff                             = 0UL;
  self->accv_slot                        = 0UL;
  self->accv_id                          = 0UL;

  self->manifest_buf   = manifest_buf;
  self->manifest_bufsz = manifest_bufsz;
}

fd_snapshot_parser_t *
fd_snapshot_parser_new( void * mem,
                        void * cb_arg,
                        ulong  seed,
                        ulong  max_acc_vecs,
                        fd_snapshot_parser_process_manifest_fn_t manifest_cb,
                        fd_slot_delta_parser_process_entry_fn_t  status_cache_cb,
                        fd_snapshot_process_acc_hdr_fn_t         acc_hdr_cb,
                        fd_snapshot_process_acc_data_fn_t        acc_data_cb );

static inline void
fd_snapshot_parser_close( fd_snapshot_parser_t * self ) {
  self->flags = SNAP_FLAG_DONE;
}

static inline fd_snapshot_parser_metrics_t
fd_snapshot_parser_get_metrics( fd_snapshot_parser_t * self ) {
  return self->metrics;
}

uchar const *
fd_snapshot_parser_process_chunk( fd_snapshot_parser_t * self,
                                  uchar const *          buf,
                                  ulong                  bufsz );

#endif /* HEADER_fd_src_discof_restore_utils_fd_snapshot_parser_h */
