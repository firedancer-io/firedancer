#ifndef HEADER_fd_src_discof_restore_utils_fd_ssparse_h
#define HEADER_fd_src_discof_restore_utils_fd_ssparse_h

#include "../../../util/fd_util_base.h"

#define FD_SSPARSE_MAGIC (0xF17EDA2CE58AC5E0) /* FIREDANCE PARSE V0 */

#define FD_SSPARSE_ADVANCE_ERROR          (-1)
#define FD_SSPARSE_ADVANCE_AGAIN          ( 0)
#define FD_SSPARSE_ADVANCE_MANIFEST       ( 1)
#define FD_SSPARSE_ADVANCE_STATUS_CACHE   ( 2)
#define FD_SSPARSE_ADVANCE_ACCOUNT_HEADER ( 3)
#define FD_SSPARSE_ADVANCE_ACCOUNT_DATA   ( 4)
#define FD_SSPARSE_ADVANCE_ACCOUNT_BATCH  ( 5)
#define FD_SSPARSE_ADVANCE_DONE           ( 6)

/* fd_ssparse_t is a solana snapshot parser.  It is designed to parse a
   snapshot in streaming fasion, chunk by chunk. */
struct fd_ssparse_private;
typedef struct fd_ssparse_private fd_ssparse_t;

struct acc_vec_key {
  ulong slot;
  ulong id;
};

typedef struct acc_vec_key acc_vec_key_t;

struct acc_vec {
  acc_vec_key_t key;
  ulong         file_sz;

  ulong         map_next;
  ulong         map_prev;

  ulong         pool_next;
};

typedef struct acc_vec acc_vec_t;

#define POOL_NAME  acc_vec_pool
#define POOL_T     acc_vec_t
#define POOL_NEXT  pool_next
#define POOL_IDX_T ulong

#include "../../../util/tmpl/fd_pool.c"

#define MAP_NAME          acc_vec_map
#define MAP_ELE_T         acc_vec_t
#define MAP_KEY_T         acc_vec_key_t
#define MAP_KEY           key
#define MAP_IDX_T         ulong
#define MAP_NEXT          map_next
#define MAP_PREV          map_prev
#define MAP_KEY_HASH(k,s) fd_hash( s, k, sizeof(acc_vec_key_t) )
#define MAP_KEY_EQ(k0,k1) ( ((k0)->slot==(k1)->slot) && ((k0)->id==(k1)->id) )

#include "../../../util/tmpl/fd_map_chain.c"

/* FD_SSPARSE_ACC_BATCH_MAX controls the max number of accounts in a
   batch. */
#define FD_SSPARSE_ACC_BATCH_MAX (8UL)

struct fd_ssparse_advance_result {
  ulong bytes_consumed;

  union {
    struct {
      uchar const *   data;
      ulong           data_sz;
      acc_vec_map_t * acc_vec_map;
      acc_vec_t *     acc_vec_pool;
    } manifest;

    struct {
      uchar const * data;
      ulong         data_sz;
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
      uchar const * owner;
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
  };
};

typedef struct fd_ssparse_advance_result fd_ssparse_advance_result_t;

FD_PROTOTYPES_BEGIN

FD_FN_CONST ulong
fd_ssparse_align( void );

FD_FN_CONST ulong
fd_ssparse_footprint( ulong max_acc_vecs );

void *
fd_ssparse_new( void *  shmem,
                ulong   max_acc_vecs,
                ulong   seed );

fd_ssparse_t *
fd_ssparse_join( void * ssparse );

/* fd_ssparse_reset rewinds the parser to accept a new snapshot stream */
void
fd_ssparse_reset( fd_ssparse_t * ssparse );

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

/* fd_ssparse_config_prog_slow_path_enable toggles whether config
   programs are routed away from batch processing to individual slow
   path account processing.  If enabled, config program accounts are
   only processed in the slow path (FD_SSPARSE_ADVANCE_ACCOUNT_HEADER
   and FD_SSPARSE_ADVANCE_ACCOUNT_DATA) and not returned by
   FD_SSPARSE_ADVANCE_ACCOUNT_BATCH.  Note that batch processing must
   be enabled for this option to take effect.  Otherwise, this option
   does nothing. */
void
fd_ssparse_config_prog_slow_path_enable( fd_ssparse_t * ssparse,
                                         int            enabled );

/* Test/Fuzz APIs */

/* fd_ssparse_populate_acc_vec_map is for testing/fuzzing purposes
   only.  It takes an array of slots, ids, and file sizes and populates
   the ssparse object's internal append vec map. */
int
fd_ssparse_populate_acc_vec_map( fd_ssparse_t * ssparse,
                                 ulong *        slots,
                                 ulong *        ids,
                                 ulong *        file_szs,
                                 ulong          cnt );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_discof_restore_utils_fd_ssparse_h */
