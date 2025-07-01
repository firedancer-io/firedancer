#ifndef HEADER_fd_src_flamenco_runtime_fd_rocksdb_h
#define HEADER_fd_src_flamenco_runtime_fd_rocksdb_h

#include "../../ballet/block/fd_microblock.h"
#include "fd_blockstore.h"

/** allocations made for offline-replay in the blockstore */
struct fd_block {
  /* Used only in offline at the moment. Stored in the blockstore
     memory and used to iterate the block's contents.

   A block's data region is indexed to support iterating by shred,
   microblock/entry batch, microblock/entry, or transaction.
   This is done by iterating the headers for each, stored in allocated
   memory.
   To iterate shred payloads, for example, a caller should iterate the headers in tandem with the data region
   (offsetting by the bytes indicated in the shred header).

   Note random access of individual shred indices is not performant, due to the variable-length
   nature of shreds. */

  ulong data_gaddr;   /* ptr to the beginning of the block's allocated data region */
  ulong data_sz;      /* block size */
  ulong shreds_gaddr; /* ptr to the first fd_block_shred_t */
  ulong shreds_cnt;
  ulong batch_gaddr;  /* list of fd_block_entry_batch_t */
  ulong batch_cnt;
  ulong micros_gaddr; /* ptr to the list of fd_block_micro_t */
  ulong micros_cnt;
};
typedef struct fd_block fd_block_t;

FD_PROTOTYPES_BEGIN

/* fd_blockstore_block_data_laddr returns a local pointer to the block's
   data.  The returned pointer lifetime is until the block is removed. */

FD_FN_PURE static inline uchar *
fd_blockstore_block_data_laddr( fd_blockstore_t * blockstore, fd_block_t * block ) {
  return fd_wksp_laddr_fast( fd_blockstore_wksp( blockstore ), block->data_gaddr );
}

FD_FN_PURE static inline fd_block_entry_batch_t *
fd_blockstore_block_batch_laddr( fd_blockstore_t * blockstore, fd_block_t * block ) {
  return fd_wksp_laddr_fast( fd_blockstore_wksp( blockstore ), block->batch_gaddr );
}

FD_FN_PURE static inline fd_block_micro_t *
fd_blockstore_block_micro_laddr( fd_blockstore_t * blockstore, fd_block_t * block ) {
  return fd_wksp_laddr_fast( fd_blockstore_wksp( blockstore ), block->micros_gaddr );
}

FD_PROTOTYPES_END

#if FD_HAS_ROCKSDB

#include "../../ballet/shred/fd_shred.h"
#include <rocksdb/c.h>

#define FD_ROCKSDB_CF_CNT (21UL)

#define FD_ROCKSDB_CFIDX_DEFAULT                  (0UL)
#define FD_ROCKSDB_CFIDX_META                     (1UL)
#define FD_ROCKSDB_CFIDX_DEAD_SLOTS               (2UL)
#define FD_ROCKSDB_CFIDX_DUPLICATE_SLOTS          (3UL) /* Usually empty */
#define FD_ROCKSDB_CFIDX_ERASURE_META             (4UL)
#define FD_ROCKSDB_CFIDX_ORPHANS                  (5UL) /* Usually empty */
#define FD_ROCKSDB_CFIDX_BANK_HASHES              (6UL)
#define FD_ROCKSDB_CFIDX_ROOT                     (7UL)
#define FD_ROCKSDB_CFIDX_INDEX                    (8UL)
#define FD_ROCKSDB_CFIDX_DATA_SHRED               (9UL)
#define FD_ROCKSDB_CFIDX_CODE_SHRED               (10UL)
#define FD_ROCKSDB_CFIDX_TRANSACTION_STATUS       (11UL)
#define FD_ROCKSDB_CFIDX_ADDRESS_SIGNATURES       (12UL)
#define FD_ROCKSDB_CFIDX_TRANSACTION_MEMOS        (13UL)
#define FD_ROCKSDB_CFIDX_TRANSACTION_STATUS_INDEX (14UL)
#define FD_ROCKSDB_CFIDX_REWARDS                  (15UL)
#define FD_ROCKSDB_CFIDX_BLOCKTIME                (16UL)
#define FD_ROCKSDB_CFIDX_PERF_SAMPLES             (17UL)
#define FD_ROCKSDB_CFIDX_BLOCK_HEIGHT             (18UL)
#define FD_ROCKSDB_CFIDX_OPTIMISTIC_SLOTS         (19UL)
#define FD_ROCKSDB_CFIDX_MERKLE_ROOT_META         (20UL) /* Usually empty */

/* Solana rocksdb client */
struct fd_rocksdb {
  rocksdb_t *                     db;
  const char *                    db_name;
  const char *                    cfgs      [ FD_ROCKSDB_CF_CNT ];
  rocksdb_column_family_handle_t* cf_handles[ FD_ROCKSDB_CF_CNT ];
  rocksdb_options_t *             opts;
  rocksdb_readoptions_t *         ro;
  rocksdb_writeoptions_t *        wo;
};
typedef struct fd_rocksdb fd_rocksdb_t;
#define FD_ROCKSDB_FOOTPRINT sizeof(fd_rocksdb_t)
#define FD_ROCKSDB_ALIGN (8UL)

/* root column iterator */
struct fd_rocksdb_root_iter {
  fd_rocksdb_t *                  db;
  rocksdb_iterator_t*             iter;
};
typedef struct fd_rocksdb_root_iter fd_rocksdb_root_iter_t;
#define FD_ROCKSDB_ROOT_ITER_FOOTPRINT sizeof(fd_rocksdb_root_iter_t)
#define FD_ROCKSDB_ROOT_ITER_ALIGN (8UL)

FD_PROTOTYPES_BEGIN

void *
fd_rocksdb_root_iter_new( void * shiter );

fd_rocksdb_root_iter_t *
fd_rocksdb_root_iter_join( void * iter );

void *
fd_rocksdb_root_iter_leave( fd_rocksdb_root_iter_t * iter );

/* fd_rocksdb_root_iter_seek

    0 = success
   -1 = seek for supplied slot failed
   -2 = seek succeeded but slot did not match what we seeked for
   -3 = seek succeeded but points at an empty slot */

int
fd_rocksdb_root_iter_seek( fd_rocksdb_root_iter_t * iter,
                           fd_rocksdb_t *           db,
                           ulong                    slot,
                           fd_slot_meta_t *         m,
                           fd_valloc_t              valloc );

/*  fd_rocksdb_root_iter_next

    0 = success
   -1 = not properly initialized with a seek
   -2 = invalid starting iterator
   -3 = next returned an invalid iterator state
   -4 = seek succeeded but points at an empty slot */

int
fd_rocksdb_root_iter_next( fd_rocksdb_root_iter_t * iter,
                           fd_slot_meta_t *         m,
                           fd_valloc_t              valloc );

int
fd_rocksdb_root_iter_slot( fd_rocksdb_root_iter_t * self,
                           ulong *                  slot );

void
fd_rocksdb_root_iter_destroy( fd_rocksdb_root_iter_t * iter );

/* fd_rocksdb_init: Returns a pointer to a description of the error on failure

  The provided db_name needs to point at the actual rocksdb directory
  as apposed to the directory above (like the solana ledger-tool) */

char *
fd_rocksdb_init( fd_rocksdb_t * db,
                 char const *   db_name );

/* fd_rocksdb_new: Creates a new rocksdb

   The provided db_name has to the be the full path where the directory
   will be created. The fd_rocksdb_t object will be initialized */

void
fd_rocksdb_new( fd_rocksdb_t * db,
                char const *   db_name );

/* fd_rocksdb_destroy

   Frees up the internal data structures */

void
fd_rocksdb_destroy( fd_rocksdb_t * db );

/* fd_rocksdb_last_slot:  Returns the last slot in the db

   This uses the root column to discover the slot of the last root in
   the db.  If there is an error, this sets *err to a constant string
   describing the error.  There is no need to free that string. */

ulong
fd_rocksdb_last_slot( fd_rocksdb_t * db,
                      char **        err );

/* fd_rocksdb_first_slot:  Returns the first slot in the db

   This uses the root column to discover the slot of the first root in
   the db.  If there is an error, this sets *err to a constant string
   describing the error.  There is no need to free that string. */

ulong
fd_rocksdb_first_slot( fd_rocksdb_t * db,
                       char **        err );

ulong
fd_rocksdb_find_last_slot( fd_rocksdb_t * db,
                           char **        err );

/* fd_rocksdb_get_meta

   Retrieves the meta structure associated with the supplied slot.  If
   there is an error, *err is set to a string describing the error.
   It is expected that you should free() the error once done with it

   returns a 0 if there is no obvious error */
int
fd_rocksdb_get_meta( fd_rocksdb_t *   db,
                     ulong            slot,
                     fd_slot_meta_t * m,
                     fd_valloc_t      valloc );

/* fd_rocksdb_get_txn_status_raw queries transaction status metadata.
   slot is the slot number of the block that contains the txn.  sig
   points to the first signature of the txn.  Returns data==NULL if
   record not found.  On success, creates a malloc-backed buffer to hold
   return value, copies raw serialized status into buffer, sets *psz to
   the byte size of the status and returns pointer to buffer.  Caller
   must free() non-NULL returned region.  On failure, returns NULL and
   content of *psz is undefined.  Value is Protobuf-encoded
   TransactionStatusMeta.  Use fd_solblock nanopb API to deserialize
   value. */

void *
fd_rocksdb_get_txn_status_raw( fd_rocksdb_t * self,
                               ulong          slot,
                               void const *   sig,
                               ulong *        psz );

/* fd_rocksdb_copy_over_slot_indexed_range copies over all entries for a
   given column family index into another rocksdb assuming that the key
   is prefixed with the slot number. This includes column families where
   the key is just the slot number but also ones where the key starts with
   the slot number. */

int
fd_rocksdb_copy_over_slot_indexed_range( fd_rocksdb_t * src,
                                         fd_rocksdb_t * dst,
                                         ulong          cf_idx,
                                         ulong          start_slot,
                                         ulong          end_slot );

/* fd_rocksdb_copy_over_txn_status constructs a key to query a transaction
   status and copies over the entry into another rocksdb. The index is used
   to specify which transaction. */

void
fd_rocksdb_copy_over_txn_status( fd_rocksdb_t * src,
                                 fd_rocksdb_t * dst,
                                 ulong          slot,
                                 void const *   sig );

/* fd_rocksdb_insert_entry inserts a key, value pair into a given rocksdb */

int
fd_rocksdb_insert_entry( fd_rocksdb_t * db,
                         ulong          cf_idx,
                         const char *   key,
                         ulong          key_len,
                         const char *   value,
                         ulong          value_len );

/* Import from rocksdb into blockstore */

int
fd_rocksdb_import_block_blockstore( fd_rocksdb_t *    db,
                                    fd_slot_meta_t *  m,
                                    fd_blockstore_t * blockstore,
                                    const uchar *     hash_override,
                                    fd_valloc_t       valloc );

int
fd_rocksdb_import_block_shredcap( fd_rocksdb_t *             db,
                                  fd_slot_meta_t *           metadata,
                                  fd_io_buffered_ostream_t * ostream,
                                  fd_io_buffered_ostream_t * bank_hash_ostream,
                                  fd_valloc_t                valloc );

/* fd_blockstore_block_query queries blockstore for block at slot.
   Returns a pointer to the block or NULL if not in blockstore.  The
   returned pointer lifetime is until the block is removed.  Check
   return value for error info.

   In theory the caller does not need to wrap this function in a
   start/end read. What is being read lives in the block_info object,
   and this function does a valid concurrent read for the block_gaddr.
   The fd_block_t object itself has no such guarantees, and needs a
   read/write lock to modify. */
void
fd_blockstore_block_allocs_remove( fd_blockstore_t * blockstore, ulong slot );

static inline fd_block_t *
fd_blockstore_block_query(fd_blockstore_t *blockstore, ulong slot){
  int err = FD_MAP_ERR_AGAIN;
  ulong query_block_gaddr = 0;
  while( err == FD_MAP_ERR_AGAIN ){
    fd_block_map_query_t quer[1] = { 0 };
    err = fd_block_map_query_try( blockstore->block_map, &slot, NULL, quer, 0 );
    fd_block_info_t * query = fd_block_map_query_ele( quer );
    if ( err == FD_MAP_ERR_KEY ) return NULL;
    if ( FD_UNLIKELY( err == FD_MAP_ERR_AGAIN ) ) continue;
    /* later change this to all shreds received */
    if( FD_UNLIKELY( query->block_gaddr == 0 ) ) return NULL;
    query_block_gaddr = query->block_gaddr;
    err = fd_block_map_query_test( quer );
  }
  return fd_wksp_laddr_fast( fd_blockstore_wksp( blockstore ), query_block_gaddr );
}

FD_PROTOTYPES_END

#endif

#endif // HEADER_fd_src_flamenco_runtime_fd_rocksdb_h
