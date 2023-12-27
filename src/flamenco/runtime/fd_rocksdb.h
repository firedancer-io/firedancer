#ifndef HEADER_fd_src_flamenco_runtime_fd_rocksdb_h
#define HEADER_fd_src_flamenco_runtime_fd_rocksdb_h

#if FD_HAS_ROCKSDB

#include "fd_banks_solana.h"
#include "../../ballet/shred/fd_shred.h"
#include "../../ballet/block/fd_microblock.h"
#include <rocksdb/c.h>

#define FD_ROCKSDB_CF_CNT (6UL)

#define FD_ROCKSDB_CFIDX_DEFAULT     (0UL)
#define FD_ROCKSDB_CFIDX_META        (1UL)
#define FD_ROCKSDB_CFIDX_ROOT        (2UL)
#define FD_ROCKSDB_CFIDX_DATA_SHRED  (3UL)
#define FD_ROCKSDB_CFIDX_BANK_HASHES (4UL)
#define FD_ROCKSDB_CFIDX_TXN_STATUS  (5UL)

/* Solana rocksdb client */
struct fd_rocksdb {
  rocksdb_t *                     db;
  const char *                    db_name;
  const char *                    cfgs      [ FD_ROCKSDB_CF_CNT ];
  rocksdb_column_family_handle_t* cf_handles[ FD_ROCKSDB_CF_CNT ];
  rocksdb_options_t *             opts;
  rocksdb_readoptions_t *         ro;
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

void *
fd_rocksdb_get_block( fd_rocksdb_t *   db,
                      fd_slot_meta_t * m,
                      fd_valloc_t      valloc,
                      ulong *          result_sz );

/* fd_rocksdb_get_bank_hash looks up the bank hash for the given slot.
   Writes the hash to out on success and returns out.  On failure, the
   content of out is undefined and NULL is returned.  Reasons for
   failure are written to log. */

void *
fd_rocksdb_get_bank_hash( fd_rocksdb_t * self,
                          ulong          slot,
                          void *         out );

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

typedef struct fd_blockstore fd_blockstore_t;

/* Import from rocksdb into blockstore */

int
fd_rocksdb_import_block( fd_rocksdb_t *    db,
                         fd_slot_meta_t *  m,
                         fd_blockstore_t * blockstore,
                         int txnstatus );

FD_PROTOTYPES_END

#endif

#endif // HEADER_fd_src_flamenco_runtime_fd_rocksdb_h
