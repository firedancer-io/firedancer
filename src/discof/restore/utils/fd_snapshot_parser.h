#ifndef HEADER_fd_src_discof_restore_utils_fd_snapshot_parser_h
#define HEADER_fd_src_discof_restore_utils_fd_snapshot_parser_h

#include "../../../flamenco/types/fd_types.h"

#define SNAP_STATE_IGNORE       ((uchar)0)  /* ignore file content */
#define SNAP_STATE_TAR          ((uchar)1)  /* reading tar header (buffered) */
#define SNAP_STATE_MANIFEST     ((uchar)2)  /* reading manifest (buffered) */
#define SNAP_STATE_ACCOUNT_HDR  ((uchar)3)  /* reading account hdr (buffered) */
#define SNAP_STATE_ACCOUNT_DATA ((uchar)4)  /* reading account data (zero copy) */
#define SNAP_STATE_DONE         ((uchar)5)  /* expect no more data */

struct fd_snapshot_accv_key {
  ulong slot;
  ulong id;
};

typedef struct fd_snapshot_accv_key fd_snapshot_accv_key_t;

static const fd_snapshot_accv_key_t
fd_snapshot_accv_key_null = { 0UL, 0UL };

FD_FN_PURE static inline ulong
fd_snapshot_accv_key_hash( fd_snapshot_accv_key_t key ) {
  return fd_hash( 0x39c49607bf16463aUL, &key, sizeof(fd_snapshot_accv_key_t) );
}

struct fd_snapshot_accv_map {
  fd_snapshot_accv_key_t key;
  ulong                  sz;
  ulong                  hash;  /* use uint or ulong hash? */
};

typedef struct fd_snapshot_accv_map fd_snapshot_accv_map_t;

#define MAP_NAME              fd_snapshot_accv_map
#define MAP_T                 fd_snapshot_accv_map_t
#define MAP_LG_SLOT_CNT       23  /* 8.39 million */
#define MAP_KEY_T             fd_snapshot_accv_key_t
#define MAP_KEY_NULL          fd_snapshot_accv_key_null
#define MAP_KEY_INVAL(k)      ( ((k).slot==0UL) & ((k).id==0UL) )
#define MAP_KEY_EQUAL(k0,k1)  ( ((k0).slot==(k1).slot) & ((k0).id==(k1).id) )
#define MAP_KEY_EQUAL_IS_SLOW 0
#define MAP_HASH_T            ulong
#define MAP_KEY_HASH(k0)      fd_snapshot_accv_key_hash(k0)
#include "../../../util/tmpl/fd_map.c"

#define SNAP_FLAG_FAILED  1
#define SNAP_FLAG_BLOCKED 2
#define SNAP_FLAG_DONE    4

/* TODO: bound out to real required maximum */
#define SCRATCH_SZ 4*1024*1024*1024UL

struct fd_snapshot_parser;
typedef struct fd_snapshot_parser fd_snapshot_parser_t;

typedef void
(* fd_snapshot_parser_process_manifest_fn_t)( fd_snapshot_parser_t *        parser,
                                              void *                        _ctx,
                                              fd_solana_manifest_global_t * manifest,
                                              ulong                         manifest_sz );

typedef void
(* fd_snapshot_process_acc_hdr_fn_t)( fd_snapshot_parser_t *          parser,
                                      fd_solana_account_hdr_t const * hdr,
                                      void *                          _ctx );

typedef void
(* fd_snapshot_process_acc_data_fn_t)( fd_snapshot_parser_t * parser,
                                       void *                 _ctx,
                                       uchar const *          buf,
                                       ulong                  data_sz );

typedef void
(* fd_snapshot_process_acc_done_fn_t)( fd_snapshot_parser_t * parser,
                                       void *                 _ctx );

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
  ulong   accv_slot;  /* account vec slot */
  ulong   accv_id;    /* account vec index */
  ulong   accv_sz;    /* account vec size */
  fd_snapshot_accv_map_t * accv_map;

  /* Account defrag */
  ulong acc_sz;
  ulong acc_rem;  /* acc bytes pending write */
  ulong acc_pad;  /* padding size at end of account */

  /* Account processing callbacks */
  fd_snapshot_parser_process_manifest_fn_t manifest_cb;
  fd_snapshot_process_acc_hdr_fn_t         acc_hdr_cb;
  fd_snapshot_process_acc_data_fn_t        acc_data_cb;
  fd_snapshot_process_acc_done_fn_t        acc_done_cb;
  void * cb_arg;

  /* Metrics */
  fd_snapshot_parser_metrics_t metrics;
};
typedef struct fd_snapshot_parser fd_snapshot_parser_t;

FD_FN_CONST static inline ulong
fd_snapshot_parser_align( void ) {
  return fd_ulong_max( alignof(fd_snapshot_parser_t), fd_snapshot_accv_map_align() );
}

FD_FN_CONST static inline ulong
fd_snapshot_parser_footprint( void ) {
  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, alignof(fd_snapshot_parser_t), sizeof(fd_snapshot_parser_t)     );
  l = FD_LAYOUT_APPEND( l, fd_snapshot_accv_map_align(),  fd_snapshot_accv_map_footprint() );
  l = FD_LAYOUT_APPEND( l, 16UL,                          SCRATCH_SZ                       );
  return l;
}

static inline void
fd_snapshot_parser_reset_tar( fd_snapshot_parser_t * self ) {
  self->state           = SNAP_STATE_TAR;
  self->buf_ctr         = 0UL;
  self->buf_sz          = 0UL;
  self->processing_accv = 0;
  self->tar_file_rem    = 0UL;
}

static inline void
fd_snapshot_parser_reset( fd_snapshot_parser_t * self ) {
  self->flags = 0UL;
  fd_snapshot_parser_reset_tar( self );
  self->manifest_done = 0;
  self->metrics.accounts_files_processed = 0UL;
  self->metrics.accounts_files_total     = 0UL;
  self->metrics.accounts_processed       = 0UL;
  self->processing_accv                  = 0;
  self->goff                             = 0UL;
  self->accv_slot                        = 0UL;
  self->accv_id                          = 0UL;
  fd_snapshot_accv_map_clear( self->accv_map );
}

static inline fd_snapshot_parser_t *
fd_snapshot_parser_new( void * mem,
                        fd_snapshot_parser_process_manifest_fn_t manifest_cb,
                        fd_snapshot_process_acc_hdr_fn_t         acc_hdr_cb,
                        fd_snapshot_process_acc_data_fn_t        acc_data_cb,
                        fd_snapshot_process_acc_done_fn_t        acc_done_cb,
                        void *                                   cb_arg ) {
  if( FD_UNLIKELY( !mem ) ) {
    FD_LOG_WARNING(( "NULL mem" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)mem, fd_snapshot_parser_align() ) ) ) {
    FD_LOG_WARNING(( "unaligned mem" ));
    return NULL;
  }

  FD_SCRATCH_ALLOC_INIT( l, mem );
  fd_snapshot_parser_t * self = (fd_snapshot_parser_t *)FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_snapshot_parser_t), sizeof(fd_snapshot_parser_t) );

  self->state         = SNAP_STATE_TAR;
  self->flags         = 0;
  self->manifest_done = 0;

  self->buf_sz  = 0UL;
  self->buf_ctr = 0UL;
  self->buf_max = SCRATCH_SZ;

  void * accv_map_mem = FD_SCRATCH_ALLOC_APPEND( l, fd_snapshot_accv_map_align(), fd_snapshot_accv_map_footprint() );
  void * buf_mem      = FD_SCRATCH_ALLOC_APPEND( l, 16UL, SCRATCH_SZ );

  self->accv_map = fd_snapshot_accv_map_join( fd_snapshot_accv_map_new( accv_map_mem ) );
  FD_TEST( self->accv_map );

  self->buf = buf_mem;

  self->manifest_cb = manifest_cb;
  self->acc_hdr_cb  = acc_hdr_cb;
  self->acc_data_cb = acc_data_cb;
  self->acc_done_cb = acc_done_cb;
  self->cb_arg      = cb_arg;

  self->metrics.accounts_files_processed = 0UL;
  self->metrics.accounts_files_total     = 0UL;
  self->metrics.accounts_processed       = 0UL;
  self->processing_accv                  = 0;
  self->goff                             = 0UL;

  return self;
}

static inline void
fd_snapshot_parser_close( fd_snapshot_parser_t * self ) {
  self->flags = SNAP_FLAG_DONE;
  fd_snapshot_accv_map_clear( self->accv_map );
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
