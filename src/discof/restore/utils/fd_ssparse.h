#ifndef HEADER_fd_src_discof_restore_utils_fd_ssparse_h
#define HEADER_fd_src_discof_restore_utils_fd_ssparse_h

#include "../../../util/fd_util_base.h"

#define FD_SSPARSE_ADVANCE_ERROR          (-1)
#define FD_SSPARSE_ADVANCE_AGAIN          ( 0)
#define FD_SSPARSE_ADVANCE_MANIFEST       ( 1)
#define FD_SSPARSE_ADVANCE_MANIFEST_DONE  ( 2)
#define FD_SSPARSE_ADVANCE_STATUS_CACHE   ( 3)
#define FD_SSPARSE_ADVANCE_ACCOUNT_HEADER ( 4)
#define FD_SSPARSE_ADVANCE_ACCOUNT_DATA   ( 5)
#define FD_SSPARSE_ADVANCE_ACCOUNT_BATCH  ( 6)
#define FD_SSPARSE_ADVANCE_DONE           ( 7)
#define FD_SSPARSE_ADVANCE_APPENDVEC      ( 8)
#define FD_SSPARSE_ADVANCE_REGION         ( 9)

/* fd_ssparse_t is a solana snapshot parser.  It is designed to parse a
   snapshot in streaming fashion, chunk by chunk. */
struct fd_ssparse {
  int state;
  uint batch_enabled : 1;
  uint appendvec_passthrough : 1;

  struct {
    int seen_zero_tar_frame;
    int seen_manifest;
    int seen_status_cache;
    int seen_version;
  } flags;

  uchar version[ 5UL ];

  struct {
    uchar header[ 512UL ];
    ulong file_bytes;
    ulong file_bytes_consumed;
    ulong header_bytes_consumed;
  } tar;

  struct {
    uchar header[ 136UL ];
    ulong header_bytes_consumed;
    ulong data_bytes_consumed;
    ulong data_len;
  } account;

  ulong acc_vec_bytes;
  ulong slot;
  ulong bytes_consumed;
};

typedef struct fd_ssparse fd_ssparse_t;

/* FD_SSPARSE_ACC_BATCH_MAX controls the max number of accounts in a
   batch. */
#define FD_SSPARSE_ACC_BATCH_MAX (8UL)

struct fd_ssparse_advance_result {
  ulong bytes_consumed;

  union {
    struct {
      uchar const *   data;
      ulong           data_sz;
    } manifest;

    struct {
      uchar const * data;
      ulong         data_sz;
      int           done;
    } status_cache;

    struct {
      ulong         slot;
      ulong         data_len;
      uchar const * pubkey;
      ulong         lamports;
      ulong         rent_epoch;
      uchar const * owner;
      int           executable;
      uchar const * hash;
    } account_header;

    struct {
      uchar const * data;
      ulong         data_sz;
    } account_data;

    struct {
      /* Points to first byte of each account entry
         Each account entry is guaranteed unfragmented
         Useful for fast path processing */
      uchar const * batch[ FD_SSPARSE_ACC_BATCH_MAX ];
      ulong         batch_cnt;
      ulong         slot;
    } account_batch;

    /* Returned once per appendvec tar entry when appendvec passthrough
       is enabled, immediately after the 512 byte tar header has been
       parsed.  The appendvec body is then skipped (consumed without
       parsing). */
    struct {
      ulong slot;
      ulong data_sz; /* tar entry size in bytes */
    } appendvec;

    /* Returned once per non-appendvec tar entry (version, manifest,
       status cache) when appendvec passthrough is enabled, immediately
       after the 512 byte tar header has been parsed.  The entry body
       is still parsed as usual on subsequent advances. */
    struct {
      ulong data_sz; /* tar entry size in bytes */
    } region;
  };
};

typedef struct fd_ssparse_advance_result fd_ssparse_advance_result_t;

FD_PROTOTYPES_BEGIN

fd_ssparse_t *
fd_ssparse_init( fd_ssparse_t * ssparse );

/* fd_ssparse_advance parses a snapshot stream chunk.

   ssparse points to the parser.  data points to the snapshot stream.
   data_sz is the size of the snapshot stream chunk.  result points to
   fd_ssparse_advance_result_t object.  On success, the contents of the
   result are populated according to the return result.  result is not
   populated if the return result is ADVANCE_AGAIN or ADVANCE_ERROR. */
int
fd_ssparse_advance( fd_ssparse_t *                ssparse,
                    uchar const *                 data,
                    ulong                         data_sz,
                    fd_ssparse_advance_result_t * result );

/* fd_ssparse_batch_enable toggles whether batch processing is enabled.
   If enabled, ssparse will deliver FD_SSPARSE_ADVANCE_ACCOUNT_BATCH
   messages.  (These may help the caller processing accounts in batches
   to amortize per-account overhead, such as slow DRAM/disk fetches.) */
void
fd_ssparse_batch_enable( fd_ssparse_t * ssparse,
                         int            enabled );

/* fd_ssparse_appendvec_passthrough_enable toggles appendvec
   passthrough mode.  When enabled, ssparse delivers a single
   FD_SSPARSE_ADVANCE_APPENDVEC result per appendvec tar entry (as soon
   as the tar header has been parsed) and then skips the appendvec body
   without parsing individual accounts.  Non-appendvec tar entries
   (version, manifest, status cache) deliver FD_SSPARSE_ADVANCE_REGION
   once at header parse time and are then parsed as usual. */
void
fd_ssparse_appendvec_passthrough_enable( fd_ssparse_t * ssparse,
                                         int            enabled );

/* fd_ssparse_appendvec_parse switches the parser from skipping to
   parsing the current appendvec body.  Only valid immediately after
   fd_ssparse_advance returned FD_SSPARSE_ADVANCE_APPENDVEC (with
   passthrough enabled): instead of skipping the appendvec body, the
   parser then delivers ACCOUNT_HEADER/ACCOUNT_DATA/ACCOUNT_BATCH
   results for it, exactly as if passthrough were disabled for this
   one entry.  Tar padding, next-header discovery and end-of-stream
   detection continue via the normal state machine. */
void
fd_ssparse_appendvec_parse( fd_ssparse_t * ssparse );

/* fd_ssparse_accv_init initializes ssparse to parse a single appendvec
   body mid-stream, without a surrounding tar stream.  slot is the slot
   of the appendvec (from the tar entry name), sz is the appendvec body
   size in bytes (the tar entry size).  The caller then feeds exactly
   sz bytes of the appendvec body via fd_ssparse_advance, receiving
   ACCOUNT_HEADER/ACCOUNT_DATA/ACCOUNT_BATCH results.  batch_enabled
   is preserved. */
void
fd_ssparse_accv_init( fd_ssparse_t * ssparse,
                      ulong          slot,
                      ulong          sz );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_discof_restore_utils_fd_ssparse_h */
