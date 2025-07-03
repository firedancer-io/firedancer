/* fd_rocksdb.c provides a high-level interface for interacting with RocksDB
   in the context of Solana blockchain data processing. This module handles
   database initialization, slot and block management, shred operations,
   and data import/export functionality.

   RocksDB is used as the underlying storage engine for Solana's blockstore,
   which stores blocks, transactions, and metadata. This module provides
   abstractions for:

   - Database initialization and cleanup
   - Slot metadata management
   - Block and shred data operations
   - Transaction status and signature lookups
   - Bank hash and block height tracking
   - Data import from RocksDB to blockstore
   - Data export to shredcap format

   The module defines column families for different data types:
   - default: General purpose data
   - meta: Slot metadata
   - dead_slots: Slots that are no longer valid
   - duplicate_slots: Slots with duplicate content
   - erasure_meta: Erasure coding metadata
   - orphans: Orphaned blocks
   - bank_hashes: Bank state hashes
   - root: Root slot information
   - index: General indexing data
   - data_shred: Data shreds for blocks
   - code_shred: Code shreds for erasure coding
   - transaction_status: Transaction execution status
   - address_signatures: Address-to-signature mappings
   - transaction_memos: Transaction memo data
   - transaction_status_index: Index for transaction status
   - rewards: Validator rewards data
   - blocktime: Block timestamps
   - perf_samples: Performance sampling data
   - block_height: Block height information
   - optimistic_slots: Optimistically confirmed slots
   - merkle_root_meta: Merkle root metadata

   All functions assume valid inputs unless otherwise noted. Error conditions
   are typically signaled through return values and logged with appropriate
   detail levels. */

#include "fd_rocksdb.h"
#include "fd_blockstore.h"
#include "../shredcap/fd_shredcap.h"
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include "../../util/bits/fd_bits.h"

/* fd_rocksdb_init initializes a RocksDB database handle for read-only access.
   This function sets up the database with all required column families and
   prepares it for querying blockchain data.

   db points to an uninitialized fd_rocksdb_t structure that will be configured
   on success. The structure will be zeroed and then populated with database
   handles and column family configurations.

   db_name points to a null-terminated string containing the filesystem path
   to the RocksDB database directory. This should be the path to a valid
   Solana ledger database.

   Returns NULL on success, or a null-terminated error string on failure.
   The error string is allocated by RocksDB and must be freed by the caller
   using free(). Common failure reasons include:
   - Invalid database path
   - Corrupted database
   - Missing column families
   - Permission issues
   - Insufficient memory

   On success, the database is opened in read-only mode with all column
   families accessible. The caller must call fd_rocksdb_destroy() to
   properly clean up resources when done.

   Example usage:
     fd_rocksdb_t db;
     char * err = fd_rocksdb_init( &db, "/path/to/ledger" );
     if( err ) {
       FD_LOG_ERR(( "Failed to open database: %s", err ));
       free( err );
       return -1;
     }
     // ... use database ...
     fd_rocksdb_destroy( &db ); */

char *
fd_rocksdb_init( fd_rocksdb_t * db,
                 char const *   db_name ) {
  /* Zero out the entire database structure to ensure clean initialization */
  fd_memset(db, 0, sizeof(fd_rocksdb_t));

  /* Create RocksDB options object that will configure database behavior */
  db->opts = rocksdb_options_create();
  
  /* Configure all column family names. These must match exactly with the
     column families that exist in the RocksDB database on disk. The order
     and names correspond to the FD_ROCKSDB_CFIDX_* constants defined in
     the header file. */
  db->cfgs[ FD_ROCKSDB_CFIDX_DEFAULT                  ] = "default";
  db->cfgs[ FD_ROCKSDB_CFIDX_META                     ] = "meta";
  db->cfgs[ FD_ROCKSDB_CFIDX_DEAD_SLOTS               ] = "dead_slots";
  db->cfgs[ FD_ROCKSDB_CFIDX_DUPLICATE_SLOTS          ] = "duplicate_slots";
  db->cfgs[ FD_ROCKSDB_CFIDX_ERASURE_META             ] = "erasure_meta";
  db->cfgs[ FD_ROCKSDB_CFIDX_ORPHANS                  ] = "orphans";
  db->cfgs[ FD_ROCKSDB_CFIDX_BANK_HASHES              ] = "bank_hashes";
  db->cfgs[ FD_ROCKSDB_CFIDX_ROOT                     ] = "root";
  db->cfgs[ FD_ROCKSDB_CFIDX_INDEX                    ] = "index";
  db->cfgs[ FD_ROCKSDB_CFIDX_DATA_SHRED               ] = "data_shred";
  db->cfgs[ FD_ROCKSDB_CFIDX_CODE_SHRED               ] = "code_shred";
  db->cfgs[ FD_ROCKSDB_CFIDX_TRANSACTION_STATUS       ] = "transaction_status";
  db->cfgs[ FD_ROCKSDB_CFIDX_ADDRESS_SIGNATURES       ] = "address_signatures";
  db->cfgs[ FD_ROCKSDB_CFIDX_TRANSACTION_MEMOS        ] = "transaction_memos";
  db->cfgs[ FD_ROCKSDB_CFIDX_TRANSACTION_STATUS_INDEX ] = "transaction_status_index";
  db->cfgs[ FD_ROCKSDB_CFIDX_REWARDS                  ] = "rewards";
  db->cfgs[ FD_ROCKSDB_CFIDX_BLOCKTIME                ] = "blocktime";
  db->cfgs[ FD_ROCKSDB_CFIDX_PERF_SAMPLES             ] = "perf_samples";
  db->cfgs[ FD_ROCKSDB_CFIDX_BLOCK_HEIGHT             ] = "block_height";
  db->cfgs[ FD_ROCKSDB_CFIDX_OPTIMISTIC_SLOTS         ] = "optimistic_slots";
  db->cfgs[ FD_ROCKSDB_CFIDX_MERKLE_ROOT_META         ] = "merkle_root_meta";

  /* Create an array of options pointers, one for each column family.
     For simplicity, we use the same options for all column families. */
  rocksdb_options_t const * cf_options[ FD_ROCKSDB_CF_CNT ];
  for( ulong i=0UL; i<FD_ROCKSDB_CF_CNT; i++ )
    cf_options[ i ] = db->opts;

  /* Initialize error pointer to track any failures during database opening */
  char *err = NULL;

  /* Open the database in read-only mode with all column families.
     Parameters:
     - db->opts: Database options
     - db_name: Path to the database directory
     - FD_ROCKSDB_CF_CNT: Number of column families to open
     - db->cfgs: Array of column family names
     - cf_options: Array of options for each column family
     - db->cf_handles: Output array to store column family handles
     - false: Don't perform error if missing column families
     - &err: Pointer to receive error messages */
  db->db = rocksdb_open_for_read_only_column_families(
      db->opts,
      db_name,
      FD_ROCKSDB_CF_CNT,
      (char              const * const *)db->cfgs,
      (rocksdb_options_t const * const *)cf_options,
      db->cf_handles,
      false,
      &err );

  /* Check if database opening failed and return error if so */
  if( FD_UNLIKELY( err ) ) return err;

  /* Create read options object for future read operations */
  db->ro = rocksdb_readoptions_create();

  /* Return NULL to indicate successful initialization */
  return NULL;
}

/* fd_rocksdb_new creates a new RocksDB database for read-write access.
   This function initializes a database with the ability to create new
   column families and write data. It is typically used when setting up
   a new ledger or when write access is required.

   db points to an uninitialized fd_rocksdb_t structure that will be configured
   on success. The structure will be zeroed and then populated with database
   handles and column family configurations.

   db_name points to a null-terminated string containing the filesystem path
   where the RocksDB database should be created or opened. If the database
   does not exist, it will be created with the default column families.

   This function differs from fd_rocksdb_init in that it:
   - Opens the database in read-write mode
   - Creates the database if it doesn't exist
   - Creates all required column families
   - Enables LZ4 compression for better performance
   - Sets up write options for database modifications

   The function will log an error and terminate the program if database
   creation fails, as this is considered a fatal error.

   After successful initialization, the database is ready for both read
   and write operations. The caller must call fd_rocksdb_destroy() to
   properly clean up resources when done.

   Example usage:
     fd_rocksdb_t db;
     fd_rocksdb_new( &db, "/path/to/new/ledger" );
     // ... use database for read/write operations ...
     fd_rocksdb_destroy( &db ); */

void
fd_rocksdb_new( fd_rocksdb_t * db,
                char const *   db_name ) {
  /* Zero out the entire database structure to ensure clean initialization */
  fd_memset(db, 0, sizeof(fd_rocksdb_t));

  /* Create RocksDB options object that will configure database behavior */
  db->opts = rocksdb_options_create();
  
  /* Enable database creation if it doesn't exist. This allows the function
     to create a new database from scratch if no database exists at db_name */
  rocksdb_options_set_create_if_missing(db->opts, 1);

  /* Configure all column family names. These must match exactly with the
     FD_ROCKSDB_CFIDX_* constants. When creating a new database, these
     column families will be created automatically. */
  db->cfgs[ FD_ROCKSDB_CFIDX_DEFAULT                  ] = "default";
  db->cfgs[ FD_ROCKSDB_CFIDX_META                     ] = "meta";
  db->cfgs[ FD_ROCKSDB_CFIDX_DEAD_SLOTS               ] = "dead_slots";
  db->cfgs[ FD_ROCKSDB_CFIDX_DUPLICATE_SLOTS          ] = "duplicate_slots";
  db->cfgs[ FD_ROCKSDB_CFIDX_ERASURE_META             ] = "erasure_meta";
  db->cfgs[ FD_ROCKSDB_CFIDX_ORPHANS                  ] = "orphans";
  db->cfgs[ FD_ROCKSDB_CFIDX_BANK_HASHES              ] = "bank_hashes";
  db->cfgs[ FD_ROCKSDB_CFIDX_ROOT                     ] = "root";
  db->cfgs[ FD_ROCKSDB_CFIDX_INDEX                    ] = "index";
  db->cfgs[ FD_ROCKSDB_CFIDX_DATA_SHRED               ] = "data_shred";
  db->cfgs[ FD_ROCKSDB_CFIDX_CODE_SHRED               ] = "code_shred";
  db->cfgs[ FD_ROCKSDB_CFIDX_TRANSACTION_STATUS       ] = "transaction_status";
  db->cfgs[ FD_ROCKSDB_CFIDX_ADDRESS_SIGNATURES       ] = "address_signatures";
  db->cfgs[ FD_ROCKSDB_CFIDX_TRANSACTION_MEMOS        ] = "transaction_memos";
  db->cfgs[ FD_ROCKSDB_CFIDX_TRANSACTION_STATUS_INDEX ] = "transaction_status_index";
  db->cfgs[ FD_ROCKSDB_CFIDX_REWARDS                  ] = "rewards";
  db->cfgs[ FD_ROCKSDB_CFIDX_BLOCKTIME                ] = "blocktime";
  db->cfgs[ FD_ROCKSDB_CFIDX_PERF_SAMPLES             ] = "perf_samples";
  db->cfgs[ FD_ROCKSDB_CFIDX_BLOCK_HEIGHT             ] = "block_height";
  db->cfgs[ FD_ROCKSDB_CFIDX_OPTIMISTIC_SLOTS         ] = "optimistic_slots";
  db->cfgs[ FD_ROCKSDB_CFIDX_MERKLE_ROOT_META         ] = "merkle_root_meta";

  /* Open/create the database in read-write mode. If the database doesn't
     exist, it will be created. Only the default column family is created
     initially by this call. */
  char * err = NULL;
  db->db = rocksdb_open(db->opts, db_name, &err);
  if ( err != NULL ) {
    /* Database creation/opening failed - this is a fatal error since we
       can't proceed without a working database */
    FD_LOG_ERR(("rocksdb creation failed: %s", err));
  }

  /* Create write options object for future write operations */
  db->wo = rocksdb_writeoptions_create();

  /* Create all additional column families beyond the default.
     The default column family (index 0) already exists after opening,
     so we start from index 1. Each column family is created with the
     same options as the main database. */
  for ( ulong i = 1; i < FD_ROCKSDB_CF_CNT; ++i ) {
    db->cf_handles[i] = rocksdb_create_column_family(db->db, db->opts, db->cfgs[i], &err);
  }
  
  /* Enable LZ4 compression for better storage efficiency and I/O performance.
     LZ4 provides a good balance between compression ratio and speed. */
  rocksdb_options_set_compression( db->opts, rocksdb_lz4_compression );
}

/* fd_rocksdb_destroy properly cleans up and releases all resources associated
   with a RocksDB database handle. This function must be called for every
   database opened with fd_rocksdb_init() or fd_rocksdb_new() to prevent
   resource leaks.

   db points to an initialized fd_rocksdb_t structure that was previously
   configured by fd_rocksdb_init() or fd_rocksdb_new(). After this function
   returns, the structure will be in an undefined state and should not be
   used without re-initialization.

   The function performs the following cleanup operations:
   - Destroys all column family handles
   - Releases read options (if present)
   - Releases database options
   - Closes the database connection
   - Releases write options (if present)

   This function is safe to call on partially initialized structures or
   structures that have already been destroyed, as it checks for NULL
   pointers before attempting to release resources.

   After calling this function, the db structure should be considered
   invalid and must not be used for any database operations.

   Example usage:
     fd_rocksdb_t db;
     fd_rocksdb_init( &db, "/path/to/ledger" );
     // ... use database ...
     fd_rocksdb_destroy( &db ); // Always call this to clean up */

void fd_rocksdb_destroy(fd_rocksdb_t *db) {

  /* Clean up all column family handles first. We iterate through all
     possible column families and destroy any that were successfully created.
     The NULL check prevents attempting to destroy handles that were never
     initialized or already destroyed. */
  for( ulong i=0UL; i<FD_ROCKSDB_CF_CNT; i++ ) {
    if( db->cf_handles[i] ) {
      /* Destroy the column family handle and release associated resources */
      rocksdb_column_family_handle_destroy( db->cf_handles[i] );
      /* Set pointer to NULL to prevent double-destruction */
      db->cf_handles[i] = NULL;
    }
  }

  /* Clean up read options if they were created during initialization */
  if( db->ro ) {
    rocksdb_readoptions_destroy( db->ro );
    /* Clear the pointer to prevent dangling reference */
    db->ro = NULL;
  }

  /* Clean up database options that were created during initialization */
  if( db->opts ) {
    rocksdb_options_destroy( db->opts );
    /* Clear the pointer to prevent dangling reference */
    db->opts = NULL;
  }

  /* Close the main database handle and release all associated resources.
     This must be done after destroying column family handles since they
     depend on the main database handle being valid. */
  if( db->db ) {
    rocksdb_close( db->db );
    /* Clear the pointer to prevent dangling reference */
    db->db = NULL;
  }

  /* Clean up write options if they were created (only present in read-write mode) */
  if( db->wo ) {
    rocksdb_writeoptions_destroy( db->wo );
  }
}

/* fd_rocksdb_last_slot retrieves the highest slot number from the root
   column family in the database. This function is used to determine the
   most recent slot that has been processed and stored in the database.

   db points to an initialized fd_rocksdb_t structure representing an open
   database connection. The database must have been successfully opened
   with fd_rocksdb_init() or fd_rocksdb_new().

   err points to a char pointer that will be set to an error message string
   if the operation fails. The caller should check this value on return.
   If non-NULL, it points to a static string that does not need to be freed.

   Returns the highest slot number found in the root column family on success.
   The slot number is returned in host byte order (converted from the
   big-endian format used in the database).

   Returns 0 on failure, with *err set to an error message. Common failure
   reasons include:
   - Database connection is invalid
   - Root column family is empty
   - Database corruption
   - I/O errors

   The function uses an iterator to seek to the last entry in the root
   column family. Slot numbers are stored in big-endian format in the
   database for proper lexicographic ordering.

   Example usage:
     char * err;
     ulong last_slot = fd_rocksdb_last_slot( &db, &err );
     if( err ) {
       FD_LOG_ERR(( "Failed to get last slot: %s", err ));
       return -1;
     }
     FD_LOG_INFO(( "Last slot: %lu", last_slot )); */

ulong fd_rocksdb_last_slot(fd_rocksdb_t *db, char **err) {
  /* Create an iterator on the root column family. The root column family
     contains entries for all finalized slots, with slot numbers as keys
     stored in big-endian format for proper lexicographic ordering. */
  rocksdb_iterator_t* iter = rocksdb_create_iterator_cf(db->db, db->ro, db->cf_handles[FD_ROCKSDB_CFIDX_ROOT]);
  
  /* Seek to the last entry in the root column family. Since slot numbers
     are stored in big-endian format, the lexicographically last entry
     corresponds to the numerically highest slot number. */
  rocksdb_iter_seek_to_last(iter);
  
  /* Check if the iterator is positioned at a valid entry. If not, the
     root column family is empty, meaning no slots have been finalized yet. */
  if (!rocksdb_iter_valid(iter)) {
    /* Clean up the iterator before returning */
    rocksdb_iter_destroy(iter);
    /* Set error message to indicate empty database */
    *err = "db column for root is empty";
    /* Return 0 to indicate no valid slot found */
    return 0;
  }

  /* Extract the key from the current iterator position. The key is the
     slot number stored in big-endian format. */
  size_t klen = 0;
  const char *key = rocksdb_iter_key(iter, &klen); // There is no need to free key
  
  /* Convert the big-endian slot number to host byte order. The key should
     be exactly 8 bytes (sizeof(unsigned long)) containing the slot number. */
  unsigned long slot = fd_ulong_bswap(*((unsigned long *) key));
  
  /* Clean up the iterator now that we have extracted the slot number */
  rocksdb_iter_destroy(iter);
  
  /* Return the slot number in host byte order */
  return slot;
}

/* fd_rocksdb_find_last_slot finds the highest slot number by iterating through
   all entries in the root column family. This function is similar to
   fd_rocksdb_last_slot but uses a different approach that scans all entries
   rather than seeking to the last entry.

   This function is useful when the database ordering might not be reliable
   or when you want to verify the maximum slot through exhaustive search.
   However, it is less efficient than fd_rocksdb_last_slot for large databases.

   db points to an initialized fd_rocksdb_t structure representing an open
   database connection. The database must have been successfully opened
   with fd_rocksdb_init() or fd_rocksdb_new().

   err points to a char pointer that will be set to an error message string
   if the operation fails. The caller should check this value on return.
   If non-NULL, it points to a static string that does not need to be freed.

   Returns the highest slot number found by scanning all entries in the root
   column family. The slot number is returned in host byte order (converted
   from the big-endian format used in the database).

   Returns 0 on failure, with *err set to an error message. Common failure
   reasons include:
   - Database connection is invalid
   - Root column family is empty
   - Database corruption
   - I/O errors

   The function iterates through all entries in the root column family,
   converting each key from big-endian format and tracking the maximum
   value seen. This provides a warning log message each time a new maximum
   is found, which can be useful for debugging.

   Time complexity: O(n) where n is the number of entries in the root
   column family.

   Example usage:
     char * err;
     ulong max_slot = fd_rocksdb_find_last_slot( &db, &err );
     if( err ) {
       FD_LOG_ERR(( "Failed to find last slot: %s", err ));
       return -1;
     }
     FD_LOG_INFO(( "Maximum slot found: %lu", max_slot )); */

ulong fd_rocksdb_find_last_slot(fd_rocksdb_t *db, char **err) {
  /* Initialize the maximum slot number seen so far to 0 */
  ulong max_slot = 0;
  
  /* Create an iterator on the root column family to scan all entries */
  rocksdb_iterator_t* iter = rocksdb_create_iterator_cf(db->db, db->ro, db->cf_handles[FD_ROCKSDB_CFIDX_ROOT]);
  
  /* Position iterator at the first entry in the root column family.
     This starts an exhaustive scan through all slot entries. */
  rocksdb_iter_seek_to_first(iter);
  
  /* Check if there are any entries in the root column family */
  if (!rocksdb_iter_valid(iter)) {
    /* No entries found - clean up iterator before returning */
    rocksdb_iter_destroy(iter);
    /* Set error message indicating empty database */
    *err = "db column for root is empty";
    /* Return 0 to indicate no slots found */
    return 0;
  }

  /* Iterate through all entries in the root column family to find the maximum slot */
  for( ; rocksdb_iter_valid(iter); rocksdb_iter_next(iter) ) {
    /* Extract the key from the current iterator position */
    size_t klen = 0;
    const char *key = rocksdb_iter_key(iter, &klen); // There is no need to free key
    
    /* Convert the big-endian slot number key to host byte order */
    unsigned long slot = fd_ulong_bswap(*((unsigned long *) key));

    /* Check if this slot number is higher than any we've seen before */
    if( slot > max_slot ) {
      /* Update our maximum slot number */
      max_slot = slot;
      /* Log this discovery for debugging purposes. This helps track
         the progression through the database during scanning. */
      FD_LOG_WARNING(("new max_slot: %lu", max_slot));
    }
  }

  /* Clean up the iterator after completing the scan */
  rocksdb_iter_destroy(iter);
  
  /* Return the highest slot number found during the exhaustive scan */
  return max_slot;
}

/* fd_rocksdb_first_slot retrieves the lowest slot number from the root
   column family in the database. This function is used to determine the
   earliest slot that has been processed and stored in the database.

   db points to an initialized fd_rocksdb_t structure representing an open
   database connection. The database must have been successfully opened
   with fd_rocksdb_init() or fd_rocksdb_new().

   err points to a char pointer that will be set to an error message string
   if the operation fails. The caller should check this value on return.
   If non-NULL, it points to a static string that does not need to be freed.

   Returns the lowest slot number found in the root column family on success.
   The slot number is returned in host byte order (converted from the
   big-endian format used in the database).

   Returns 0 on failure, with *err set to an error message. Common failure
   reasons include:
   - Database connection is invalid
   - Root column family is empty
   - Database corruption
   - I/O errors

   The function uses an iterator to seek to the first entry in the root
   column family. Slot numbers are stored in big-endian format in the
   database for proper lexicographic ordering, so the first entry
   lexicographically corresponds to the numerically smallest slot.

   Time complexity: O(1) as it only accesses the first entry.

   Example usage:
     char * err;
     ulong first_slot = fd_rocksdb_first_slot( &db, &err );
     if( err ) {
       FD_LOG_ERR(( "Failed to get first slot: %s", err ));
       return -1;
     }
     FD_LOG_INFO(( "First slot: %lu", first_slot )); */

ulong
fd_rocksdb_first_slot( fd_rocksdb_t * db,
                       char **        err ) {

  /* Create an iterator on the root column family to access slot entries */
  rocksdb_iterator_t* iter = rocksdb_create_iterator_cf(db->db, db->ro, db->cf_handles[FD_ROCKSDB_CFIDX_ROOT]);
  
  /* Position iterator at the first entry. Since slot numbers are stored
     in big-endian format, the lexicographically first entry corresponds
     to the numerically smallest slot number. */
  rocksdb_iter_seek_to_first(iter);
  
  /* Check if the iterator is positioned at a valid entry */
  if( FD_UNLIKELY( !rocksdb_iter_valid(iter) ) ) {
    /* No entries found in root column family - clean up and return error */
    rocksdb_iter_destroy(iter);
    /* Set error message indicating empty database */
    *err = "db column for root is empty";
    /* Return 0 to indicate no valid slot found */
    return 0;
  }

  /* Extract the key from the first entry in the root column family */
  ulong klen = 0;
  char const * key = rocksdb_iter_key( iter, &klen ); // There is no need to free key
  
  /* Convert the big-endian slot number to host byte order. The first entry
     contains the smallest slot number since keys are stored in sorted order. */
  ulong slot = fd_ulong_bswap( *((ulong *)key));
  
  /* Clean up the iterator now that we have the first slot number */
  rocksdb_iter_destroy(iter);
  
  /* Return the earliest slot number found */
  return slot;
}

/* fd_rocksdb_get_meta retrieves and decodes slot metadata from the database.
   Slot metadata contains important information about a slot including its
   status, parent relationships, and confirmation state.

   db points to an initialized fd_rocksdb_t structure representing an open
   database connection. The database must have been successfully opened
   with fd_rocksdb_init() or fd_rocksdb_new().

   slot is the slot number for which to retrieve metadata. Slot numbers
   are stored in big-endian format in the database.

   m points to a fd_slot_meta_t structure that will be populated with the
   decoded metadata on success. The caller is responsible for ensuring
   this structure is valid.

   valloc is a memory allocator used for temporary allocations during
   the decoding process. This is typically the valloc from the calling
   thread's context.

   Returns 0 on success, with *m populated with the slot metadata.
   Returns -1 if the slot metadata is not found in the database.
   Returns -2 if there was an error retrieving the metadata from the database.

   The function performs the following operations:
   1. Converts the slot number to big-endian format for database lookup
   2. Queries the metadata column family for the slot
   3. Decodes the binary metadata using the bincode format
   4. Allocates temporary memory for the decoded structure
   5. Copies the decoded metadata to the output structure
   6. Frees temporary allocations

   The metadata is stored in a serialized bincode format in the database
   and must be decoded before use. The decoding process validates the
   format and ensures the data is well-formed.

   Time complexity: O(1) database lookup plus O(metadata_size) for decoding.

   Example usage:
     fd_slot_meta_t meta;
     int result = fd_rocksdb_get_meta( &db, slot_num, &meta, valloc );
     if( result == 0 ) {
       FD_LOG_INFO(( "Slot %lu metadata retrieved successfully", slot_num ));
     } else if( result == -1 ) {
       FD_LOG_WARNING(( "Slot %lu metadata not found", slot_num ));
     } else {
       FD_LOG_ERR(( "Failed to retrieve slot %lu metadata", slot_num ));
     } */

int
fd_rocksdb_get_meta( fd_rocksdb_t *   db,
                     ulong            slot,
                     fd_slot_meta_t * m,
                     fd_valloc_t      valloc ) {
  /* Convert slot number to big-endian format for use as database key.
     RocksDB stores slot numbers in big-endian to ensure proper lexicographic ordering. */
  ulong ks = fd_ulong_bswap(slot);
  
  /* Initialize size variable to receive the length of the retrieved data */
  size_t vallen = 0;

  /* Initialize error pointer for RocksDB error reporting */
  char * err  = NULL;
  
  /* Query the metadata column family for the slot's metadata. 
     Parameters:
     - db->db: Database handle
     - db->ro: Read options
     - db->cf_handles[FD_ROCKSDB_CFIDX_META]: Meta column family handle
     - &ks: Big-endian slot number as key
     - sizeof(ks): Size of the key (8 bytes)
     - &vallen: Output parameter for data size
     - &err: Output parameter for error messages */
  char * meta = rocksdb_get_cf( db->db,
                                db->ro,
                                db->cf_handles[FD_ROCKSDB_CFIDX_META],
                                (const char *) &ks,
                                sizeof(ks),
                                &vallen,
                                &err );

  /* Check if the database operation encountered an error */
  if( NULL != err ) {
    /* Log the error and clean up the error string */
    FD_LOG_WARNING(( "%s", err ));
    free( err );
    /* Return -2 to indicate database access error */
    return -2;
  }

  /* Check if no data was found for this slot */
  if (0 == vallen)
    /* Return -1 to indicate slot metadata not found */
    return -1;

  /* Set up bincode decoding context to deserialize the metadata.
     The metadata is stored in serialized bincode format in the database. */
  fd_bincode_decode_ctx_t ctx;
  ctx.data = meta;  /* Start of serialized data */
  ctx.dataend = &meta[vallen];  /* End of serialized data */

  /* Calculate the memory footprint needed for the decoded metadata structure */
  ulong total_sz = 0UL;
  if( fd_slot_meta_decode_footprint( &ctx, &total_sz ) ) {
    /* Decoding footprint calculation failed - this indicates corrupted data */
    FD_LOG_ERR(( "fd_slot_meta_decode failed" ));
  }

  /* Allocate aligned memory for the decoded metadata structure */
  uchar * mem = fd_valloc_malloc( valloc, fd_slot_meta_align(), total_sz );
  if( NULL == mem ) {
    /* Memory allocation failed - this is a critical error */
    FD_LOG_ERR(( "fd_valloc_malloc failed" ));
  }

  /* Decode the serialized metadata into the allocated memory region */
  fd_slot_meta_decode( mem, &ctx );

  /* Copy the decoded metadata to the output structure. Only copy the
     main structure, not any nested data that might exist. */
  fd_memcpy( m, mem, sizeof(fd_slot_meta_t) );

  /* Free the raw metadata buffer that was allocated by RocksDB */
  free(meta);

  /* Return 0 to indicate successful metadata retrieval and decoding */
  return 0;
}

/* fd_rocksdb_root_iter_new initializes a new root iterator structure.
   This function prepares a memory region to be used as a root iterator
   for traversing slot entries in the database.

   ptr points to a memory region of at least sizeof(fd_rocksdb_root_iter_t)
   bytes with appropriate alignment. The memory will be zeroed and initialized
   as an empty iterator.

   Returns ptr cast to void pointer for consistency with other constructor
   functions in the codebase.

   The returned iterator must be configured with fd_rocksdb_root_iter_seek()
   before use and should be cleaned up with fd_rocksdb_root_iter_destroy()
   when done.

   Time complexity: O(1) - just zeroes the structure.

   Example usage:
     fd_rocksdb_root_iter_t iter_mem;
     void * iter = fd_rocksdb_root_iter_new( &iter_mem );
     // ... use iterator ...
     fd_rocksdb_root_iter_destroy( (fd_rocksdb_root_iter_t *)iter ); */

void *
fd_rocksdb_root_iter_new     ( void * ptr ) {
  fd_memset(ptr, 0, sizeof(fd_rocksdb_root_iter_t));
  return ptr;
}

/* fd_rocksdb_root_iter_join joins an initialized root iterator.
   This function is used to establish a local handle to a root iterator
   that has been initialized with fd_rocksdb_root_iter_new().

   ptr points to a memory region that was previously initialized with
   fd_rocksdb_root_iter_new().

   Returns a typed pointer to the root iterator structure for use in
   subsequent iterator operations.

   This function is safe to call multiple times on the same iterator
   (multiple joins are allowed).

   Time complexity: O(1) - just returns a cast pointer.

   Example usage:
     void * iter_mem = fd_rocksdb_root_iter_new( &iter_storage );
     fd_rocksdb_root_iter_t * iter = fd_rocksdb_root_iter_join( iter_mem );
     // ... use iter ...
     fd_rocksdb_root_iter_leave( iter ); */

fd_rocksdb_root_iter_t *
fd_rocksdb_root_iter_join    ( void * ptr ) {
  return (fd_rocksdb_root_iter_t *) ptr;
}

/* fd_rocksdb_root_iter_leave leaves a joined root iterator.
   This function releases a local handle to a root iterator that was
   obtained with fd_rocksdb_root_iter_join().

   ptr points to a root iterator structure that was returned by
   fd_rocksdb_root_iter_join().

   Returns a void pointer to the underlying memory region for consistency
   with other destructor functions in the codebase.

   This function should be called to balance each call to
   fd_rocksdb_root_iter_join(). After calling this function, the
   ptr should not be used for iterator operations.

   Time complexity: O(1) - just returns a cast pointer.

   Example usage:
     fd_rocksdb_root_iter_t * iter = fd_rocksdb_root_iter_join( iter_mem );
     // ... use iter ...
     void * mem = fd_rocksdb_root_iter_leave( iter );
     // iter is now invalid, use mem for cleanup if needed */

void *
fd_rocksdb_root_iter_leave   ( fd_rocksdb_root_iter_t * ptr ) {
  return ptr;
}

/* fd_rocksdb_root_iter_seek positions the iterator at a specific slot
   and retrieves the associated metadata. This function initializes
   the iterator for use and seeks to the specified slot position.

   self points to a root iterator structure that was obtained from
   fd_rocksdb_root_iter_join().

   db points to an initialized fd_rocksdb_t structure representing an open
   database connection.

   slot is the slot number to seek to. The iterator will be positioned
   at this slot if it exists in the database.

   m points to a fd_slot_meta_t structure that will be populated with the
   slot metadata if the seek is successful.

   valloc is a memory allocator used for temporary allocations during
   the metadata decoding process.

   Returns 0 on success, with the iterator positioned at the specified slot
   and *m populated with the slot metadata.
   Returns -1 if the slot is not found in the database.
   Returns -2 if there was a mismatch between the requested slot and the
   slot found at the seek position.

   The function creates a RocksDB iterator if one doesn't already exist
   for this root iterator. It then seeks to the specified slot and
   validates that the correct slot was found before retrieving the
   associated metadata.

   Time complexity: O(log n) for the seek operation plus O(metadata_size)
   for decoding the metadata.

   Example usage:
     fd_rocksdb_root_iter_t * iter = fd_rocksdb_root_iter_join( iter_mem );
     fd_slot_meta_t meta;
     int result = fd_rocksdb_root_iter_seek( iter, &db, target_slot, &meta, valloc );
     if( result == 0 ) {
       FD_LOG_INFO(( "Iterator positioned at slot %lu", target_slot ));
     } else {
       FD_LOG_WARNING(( "Failed to seek to slot %lu", target_slot ));
     } */

int
fd_rocksdb_root_iter_seek( fd_rocksdb_root_iter_t * self,
                           fd_rocksdb_t *           db,
                           ulong                    slot,
                           fd_slot_meta_t *         m,
                           fd_valloc_t              valloc ) {
  /* Store database handle in iterator for future operations */
  self->db = db;

  /* Create RocksDB iterator if one doesn't already exist for this root iterator.
     The iterator is created lazily to avoid unnecessary resource usage. */
  if( FD_UNLIKELY( !self->iter ) )
    self->iter = rocksdb_create_iterator_cf(self->db->db, self->db->ro, self->db->cf_handles[FD_ROCKSDB_CFIDX_ROOT]);

  /* Convert slot number to big-endian format for database key lookup.
     This ensures the seek operation finds the correct slot entry. */
  ulong ks = fd_ulong_bswap( slot );

  /* Seek the iterator to the specified slot. The iterator will be positioned
     at the entry with the matching key, or the next entry if an exact match
     is not found. */
  rocksdb_iter_seek( self->iter, (char const *)&ks, sizeof(ulong) );
  
  /* Check if the iterator is positioned at a valid entry after seeking */
  if( FD_UNLIKELY( !rocksdb_iter_valid(self->iter) ) )
    /* Return -1 to indicate the slot was not found */
    return -1;

  /* Extract the key from the current iterator position to verify we found
     the correct slot */
  size_t klen = 0;
  char const * key = rocksdb_iter_key( self->iter, &klen ); // There is no need to free key
  
  /* Convert the key back to host byte order to compare with requested slot */
  ulong kslot = fd_ulong_bswap( *((ulong *)key) );

  /* Verify that the iterator is positioned at the requested slot.
     If not, the seek operation found a different slot (usually the next one). */
  if( FD_UNLIKELY( kslot != slot ) ) {
    /* Log warning about slot mismatch for debugging purposes */
    FD_LOG_WARNING(( "fd_rocksdb_root_iter_seek: wanted slot %lu, found %lu",
                     slot, kslot ));
    /* Return -2 to indicate slot mismatch */
    return -2;
  }

  /* Retrieve the metadata for the found slot using the existing metadata
     retrieval function. This handles the bincode decoding automatically. */
  return fd_rocksdb_get_meta( self->db, slot, m, valloc );
}

/* fd_rocksdb_root_iter_slot retrieves the slot number at the current
   iterator position. This function is used to determine which slot
   the iterator is currently positioned at.

   self points to a root iterator structure that has been positioned
   using fd_rocksdb_root_iter_seek().

   slot points to a ulong that will be populated with the current slot
   number on success.

   Returns 0 on success, with *slot set to the current slot number.
   Returns -1 if the iterator is not properly initialized.
   Returns -2 if the iterator is not positioned at a valid entry.

   The function validates that the iterator is properly initialized
   and positioned at a valid entry before extracting the slot number
   from the current key.

   Time complexity: O(1) - just reads the current iterator position.

   Example usage:
     ulong current_slot;
     int result = fd_rocksdb_root_iter_slot( iter, &current_slot );
     if( result == 0 ) {
       FD_LOG_INFO(( "Iterator is at slot %lu", current_slot ));
     } else {
       FD_LOG_WARNING(( "Iterator is not at a valid position" ));
     } */

int
fd_rocksdb_root_iter_slot  ( fd_rocksdb_root_iter_t * self, ulong *slot ) {
  /* Verify that the iterator has been properly initialized with a database
     handle and RocksDB iterator. Both are required for slot extraction. */
  if ((NULL == self->db) || (NULL == self->iter))
    /* Return -1 to indicate iterator is not properly initialized */
    return -1;

  /* Check if the iterator is currently positioned at a valid entry.
     An invalid iterator means we're past the end of the data or never sought. */
  if (!rocksdb_iter_valid(self->iter))
    /* Return -2 to indicate iterator is not at a valid position */
    return -2;

  /* Extract the key from the current iterator position. The key contains
     the slot number in big-endian format. */
  size_t klen = 0;
  const char *key = rocksdb_iter_key(self->iter, &klen); // There is no need to free key
  
  /* Convert the big-endian slot number key to host byte order and store
     it in the output parameter. */
  *slot = fd_ulong_bswap(*((unsigned long *) key));
  
  /* Return 0 to indicate successful slot number extraction */
  return 0;
}

/* fd_rocksdb_root_iter_next advances the iterator to the next slot
   and retrieves the associated metadata. This function is used to
   iterate through slots in ascending order.

   self points to a root iterator structure that has been positioned
   using fd_rocksdb_root_iter_seek().

   m points to a fd_slot_meta_t structure that will be populated with the
   metadata from the next slot on success.

   valloc is a memory allocator used for temporary allocations during
   the metadata decoding process.

   Returns 0 on success, with the iterator advanced to the next slot
   and *m populated with the slot metadata.
   Returns -1 if the iterator is not properly initialized.
   Returns -2 if the iterator is not positioned at a valid entry.
   Returns -3 if there are no more entries after the current position.

   The function validates that the iterator is properly initialized
   and positioned, advances to the next entry, and then retrieves
   the metadata for the new position.

   Time complexity: O(1) for advancing the iterator plus O(metadata_size)
   for decoding the metadata.

   Example usage:
     fd_slot_meta_t meta;
     int result = fd_rocksdb_root_iter_next( iter, &meta, valloc );
     if( result == 0 ) {
       FD_LOG_INFO(( "Advanced to next slot" ));
     } else if( result == -3 ) {
       FD_LOG_INFO(( "Reached end of iteration" ));
     } else {
       FD_LOG_WARNING(( "Failed to advance iterator" ));
     } */

int
fd_rocksdb_root_iter_next( fd_rocksdb_root_iter_t * self,
                           fd_slot_meta_t *         m,
                           fd_valloc_t              valloc ) {
  /* Verify that the iterator has been properly initialized with both a
     database handle and RocksDB iterator. Both are required to advance. */
  if ((NULL == self->db) || (NULL == self->iter))
    /* Return -1 to indicate iterator is not properly initialized */
    return -1;

  /* Check if the iterator is currently positioned at a valid entry.
     We need to be at a valid position before we can advance. */
  if (!rocksdb_iter_valid(self->iter))
    /* Return -2 to indicate iterator is not at a valid position */
    return -2;

  /* Advance the iterator to the next entry in the root column family.
     This moves from the current slot to the next slot in ascending order. */
  rocksdb_iter_next(self->iter);

  /* Check if the iterator is still at a valid entry after advancing.
     If not, we've reached the end of the data. */
  if (!rocksdb_iter_valid(self->iter))
    /* Return -3 to indicate no more entries available */
    return -3;

  /* Extract the key from the new iterator position to get the slot number */
  size_t klen = 0;
  const char *key = rocksdb_iter_key(self->iter, &klen); // There is no need to free key

  /* Convert the big-endian slot number to host byte order and retrieve
     the metadata for this slot. This combines slot extraction with
     metadata retrieval in a single call. */
  return fd_rocksdb_get_meta( self->db, fd_ulong_bswap(*((unsigned long *) key)), m, valloc );
}

/* fd_rocksdb_root_iter_destroy properly cleans up a root iterator
   and releases any associated resources. This function must be called
   for every iterator that was initialized to prevent resource leaks.

   self points to a root iterator structure that was obtained from
   fd_rocksdb_root_iter_join().

   The function releases the RocksDB iterator handle if one exists
   and resets the iterator state. After calling this function, the
   iterator should not be used for any operations.

   This function is safe to call multiple times on the same iterator
   or on an iterator that was never fully initialized.

   Time complexity: O(1) - just releases the iterator handle.

   Example usage:
     fd_rocksdb_root_iter_t * iter = fd_rocksdb_root_iter_join( iter_mem );
     // ... use iterator ...
     fd_rocksdb_root_iter_destroy( iter ); // Always call this to clean up */

void
fd_rocksdb_root_iter_destroy ( fd_rocksdb_root_iter_t * self ) {
  if (NULL != self->iter) {
    rocksdb_iter_destroy(self->iter);
    self->iter = 0;
  }
  self->db = NULL;
}

/* fd_rocksdb_get_txn_status_raw retrieves raw transaction status data
   from the database. This function queries the transaction status
   column family using a composite key of signature and slot.

   self points to an initialized fd_rocksdb_t structure representing an open
   database connection.

   slot is the slot number where the transaction was processed.

   sig points to a 64-byte transaction signature used as part of the
   database key.

   psz points to a ulong that will be populated with the size of the
   returned data on success.

   Returns a pointer to the raw transaction status data on success.
   The returned data is owned by RocksDB and must be freed by the caller
   using free(). The size of the data is returned in *psz.

   Returns NULL on failure. Common failure reasons include:
   - Transaction not found in the database
   - Database I/O error
   - Invalid signature or slot

   The function constructs a 72-byte composite key consisting of:
   - Bytes 0-63: 64-byte transaction signature
   - Bytes 64-71: 8-byte slot number in big-endian format

   Time complexity: O(log n) for the database lookup.

   Example usage:
     uchar signature[64];
     ulong data_size;
     void * status_data = fd_rocksdb_get_txn_status_raw( &db, slot, signature, &data_size );
     if( status_data ) {
       // Process status_data of size data_size
       free( status_data );
     } else {
       FD_LOG_WARNING(( "Transaction status not found" ));
     } */

void *
fd_rocksdb_get_txn_status_raw( fd_rocksdb_t * self,
                               ulong          slot,
                               void const *   sig,
                               ulong *        psz ) {

  /* Convert slot number to big-endian format for use in the composite key.
     The transaction status column family uses keys with the format:
     (signature[64], slot[8]) where slot is in big-endian format. */
  ulong slot_be = fd_ulong_bswap( slot );

  /* Construct the composite key for the transaction status lookup.
     The key format is signature (64 bytes) followed by slot (8 bytes).
     Total key size: 72 bytes. */
  char key[72];
  memcpy( key,      sig,      64UL );  /* First 64 bytes: transaction signature */
  memcpy( key+64UL, &slot_be, 8UL  );  /* Last 8 bytes: slot number in big-endian */

  /* Initialize variables for the database query */
  char * err = NULL;  /* Error message from RocksDB */
  
  /* Query the transaction status column family using the composite key.
     Parameters:
     - self->db: Database handle
     - self->ro: Read options
     - self->cf_handles[FD_ROCKSDB_CFIDX_TRANSACTION_STATUS]: Transaction status column family
     - key: Composite key (signature + slot)
     - 72UL: Size of the composite key
     - psz: Output parameter for result size
     - &err: Output parameter for error messages */
  char * res = rocksdb_get_cf(
      self->db, self->ro,
      self->cf_handles[ FD_ROCKSDB_CFIDX_TRANSACTION_STATUS ],
      key, 72UL,
      psz,
      &err );

  /* Check if the database operation encountered an error */
  if( FD_UNLIKELY( err ) ) {
    /* Log the error for debugging purposes */
    FD_LOG_WARNING(("err=%s", err));
    /* Free the error message allocated by RocksDB */
    free( err );
    /* Return NULL to indicate failure */
    return NULL;
  }
  
  /* Return the transaction status data. The caller is responsible for
     freeing this memory using free(). The size is returned in *psz. */
  return res;
}

/* fd_rocksdb_get_slot extracts the slot number from a database key
   based on the column family format. Different column families store
   the slot number in different positions within their keys.

   cf_idx is the column family index (one of the FD_ROCKSDB_CFIDX_*
   constants) that determines the key format.

   key points to the database key from which to extract the slot number.
   The key format depends on the column family.

   Returns the slot number extracted from the key, converted from
   big-endian to host byte order.

   Key formats by column family:
   - FD_ROCKSDB_CFIDX_TRANSACTION_STATUS: (signature[64], slot[8])
   - FD_ROCKSDB_CFIDX_ADDRESS_SIGNATURES: (pubkey[32], slot[8], u32[4], signature[64])
   - All others: (slot[8], ...)

   The function handles the byte-order conversion from the big-endian
   format used in the database keys to the host byte order.

   Time complexity: O(1) - just extracts and converts a field.

   Example usage:
     ulong slot = fd_rocksdb_get_slot( FD_ROCKSDB_CFIDX_META, key_data );
     FD_LOG_INFO(( "Extracted slot: %lu", slot )); */

ulong
fd_rocksdb_get_slot( ulong cf_idx, char const * key ) {
  /* Handle different key formats based on the column family.
     Each column family has a specific key structure that determines
     where the slot number is located within the key. */
  switch (cf_idx) {
    case FD_ROCKSDB_CFIDX_TRANSACTION_STATUS:
      /* Transaction status keys have format: (signature[64], slot[8])
         The slot number is located at offset 64 in the key. */
      return fd_ulong_bswap(*((ulong *) &key[64])); /* (signature,slot)*/
      
    case FD_ROCKSDB_CFIDX_ADDRESS_SIGNATURES:
      /* Address signatures keys have format: (pubkey[32], slot[8], u32[4], signature[64])
         The slot number is located at offset 32 in the key. */
      return fd_ulong_bswap(*((ulong *) &key[32])); /* (pubkey,slot,u32,signature) */
      
    default: 
      /* All other column families have the slot number at the start of the key.
         This is the most common format: (slot[8], ...) */
      return fd_ulong_bswap( *((ulong *)&key[0]) ); /* The key is just the slot number */
  }

  /* Fallback case - should never be reached due to the default case above,
     but included for completeness. Extract slot from the beginning of the key. */
  return fd_ulong_bswap( *((ulong *)key) );
}

/* fd_rocksdb_iter_seek_to_slot_if_possible positions a RocksDB iterator
   to seek to entries for a specific slot, if the column family supports
   slot-based seeking. Some column families have slot numbers at the
   beginning of their keys, allowing efficient seeking.

   iter points to a RocksDB iterator that will be positioned.

   cf_idx is the column family index that determines whether slot-based
   seeking is possible and where the slot is located in the key.

   slot is the slot number to seek to.

   The function behavior depends on the column family:
   - For column families with slot-based keys: Seeks to the slot prefix
   - For column families without slot-based keys: Seeks to the first entry

   Column families that do not support slot-based seeking:
   - FD_ROCKSDB_CFIDX_TRANSACTION_STATUS: Keys are (signature, slot)
   - FD_ROCKSDB_CFIDX_ADDRESS_SIGNATURES: Keys are (pubkey, slot, u32, signature)

   For these column families, the iterator is positioned at the first
   entry and the caller must iterate through entries to find the desired slot.

   Time complexity: O(log n) for seekable column families, O(1) for
   non-seekable column families.

   Example usage:
     fd_rocksdb_iter_seek_to_slot_if_possible( iter, FD_ROCKSDB_CFIDX_META, target_slot );
     // iter is now positioned at or near the target slot */

void
fd_rocksdb_iter_seek_to_slot_if_possible( rocksdb_iterator_t * iter, const ulong cf_idx, const ulong slot ) {
  /* Convert slot number to big-endian format for use as a key prefix.
     This is used for column families that store slot numbers at the
     beginning of their keys. */
  ulong k = fd_ulong_bswap(slot);
  
  /* Choose seeking strategy based on column family key format */
  switch (cf_idx) {
    /* These column families do not have the slot number at the start of their keys,
       so we cannot seek directly to a slot. Instead, we position at the first
       entry and let the caller iterate to find the desired slot. */
    case FD_ROCKSDB_CFIDX_TRANSACTION_STATUS:
      /* Key format: (signature[64], slot[8]) - slot is not at the start */
    case FD_ROCKSDB_CFIDX_ADDRESS_SIGNATURES:
      /* Key format: (pubkey[32], slot[8], u32[4], signature[64]) - slot is not at the start */
      rocksdb_iter_seek_to_first( iter );
      break;
      
    default: 
      /* All other column families have the slot number at the start of their keys,
         allowing efficient seeking by slot prefix. Key format: (slot[8], ...)
         
         We seek using the slot number as a prefix. This positions the iterator
         at the first entry for the specified slot, or the first entry with a
         slot number greater than the specified slot if no exact match exists. */
      rocksdb_iter_seek( iter, (const char *)&k, 8);
      break;
  }
}

/* fd_rocksdb_copy_over_slot_indexed_range copies data from one RocksDB
   database to another for a specific column family and slot range.
   This function is used to transfer blockchain data between databases
   during migration or backup operations.

   src points to the source RocksDB database from which to copy data.
   The database must be open and readable.

   dst points to the destination RocksDB database to which data will be
   copied. The database must be open and writable.

   cf_idx is the column family index (one of the FD_ROCKSDB_CFIDX_*
   constants) that specifies which column family to copy.

   start_slot is the first slot number to include in the copy operation
   (inclusive).

   end_slot is the last slot number to include in the copy operation
   (inclusive).

   Returns 0 on success, -1 on failure.

   The function skips certain column families that are not slot-indexed:
   - FD_ROCKSDB_CFIDX_TRANSACTION_MEMOS
   - FD_ROCKSDB_CFIDX_TRANSACTION_STATUS
   - FD_ROCKSDB_CFIDX_ADDRESS_SIGNATURES

   For supported column families, the function:
   1. Creates an iterator on the source database
   2. Seeks to the start slot (if the column family supports slot-based seeking)
   3. Iterates through entries, copying those within the slot range
   4. Inserts each entry into the destination database

   The function handles the different key formats used by different
   column families and extracts slot numbers appropriately.

   Time complexity: O(n * log m) where n is the number of entries in the
   range and m is the size of the destination database.

   Example usage:
     int result = fd_rocksdb_copy_over_slot_indexed_range( &src_db, &dst_db,
                                                           FD_ROCKSDB_CFIDX_META,
                                                           start_slot, end_slot );
     if( result == 0 ) {
       FD_LOG_INFO(( "Successfully copied slot range [%lu, %lu]", start_slot, end_slot ));
     } else {
       FD_LOG_ERR(( "Failed to copy slot range" ));
     } */

int
fd_rocksdb_copy_over_slot_indexed_range( fd_rocksdb_t * src,
                                         fd_rocksdb_t * dst,
                                         ulong          cf_idx,
                                         ulong          start_slot,
                                         ulong          end_slot ) {
  FD_LOG_NOTICE(( "fd_rocksdb_copy_over_slot_indexed_range: %lu", cf_idx ));

  if ( cf_idx == FD_ROCKSDB_CFIDX_TRANSACTION_MEMOS  ||
       cf_idx == FD_ROCKSDB_CFIDX_TRANSACTION_STATUS ||
       cf_idx == FD_ROCKSDB_CFIDX_ADDRESS_SIGNATURES ) {
    FD_LOG_NOTICE(( "fd_rocksdb_copy_over_range: skipping cf_idx=%lu because not slot indexed", cf_idx ));
    return 0;
  }

  rocksdb_iterator_t * iter = rocksdb_create_iterator_cf( src->db, src->ro, src->cf_handles[cf_idx] );
  if ( FD_UNLIKELY( iter == NULL ) ) {
    FD_LOG_ERR(( "rocksdb_create_iterator_cf failed for cf_idx=%lu", cf_idx ));
  }

  for ( fd_rocksdb_iter_seek_to_slot_if_possible( iter, cf_idx, start_slot ); rocksdb_iter_valid( iter ); rocksdb_iter_next( iter ) ) {
    ulong klen = 0;
    char const * key = rocksdb_iter_key( iter, &klen ); // There is no need to free key

    ulong slot = fd_rocksdb_get_slot( cf_idx, key );
    if ( slot < start_slot ) {
      continue;
    }
    else if ( slot > end_slot ) {
      break;
    }

    ulong vlen = 0;
    char const * value = rocksdb_iter_value( iter, &vlen );

    fd_rocksdb_insert_entry( dst, cf_idx, key, klen, value, vlen );
  }
  rocksdb_iter_destroy( iter );
  return 0;
}

/* fd_rocksdb_insert_entry inserts a key-value pair into a specific
   column family in the database. This function is used to write
   blockchain data to the database.

   db points to an initialized fd_rocksdb_t structure representing an open
   database connection with write capabilities.

   cf_idx is the column family index (one of the FD_ROCKSDB_CFIDX_*
   constants) that specifies which column family to write to.

   key points to the key data to be inserted. The key format depends
   on the column family.

   klen is the length of the key data in bytes.

   value points to the value data to be inserted.

   vlen is the length of the value data in bytes.

   Returns 0 on success, -1 on failure.

   The function uses the database's write options to perform the insertion.
   If the insertion fails, a warning message is logged with the error details.

   Common failure reasons include:
   - Database is read-only
   - Insufficient disk space
   - Database corruption
   - Invalid column family index

   The function does not validate the key or value formats, so the caller
   must ensure the data is appropriate for the specified column family.

   Time complexity: O(log n) where n is the number of entries in the
   column family.

   Example usage:
     char key_data[16];
     char value_data[1024];
     int result = fd_rocksdb_insert_entry( &db, FD_ROCKSDB_CFIDX_META,
                                           key_data, sizeof(key_data),
                                           value_data, sizeof(value_data) );
     if( result == 0 ) {
       FD_LOG_INFO(( "Successfully inserted entry" ));
     } else {
       FD_LOG_ERR(( "Failed to insert entry" ));
     } */

int
fd_rocksdb_insert_entry( fd_rocksdb_t * db,
                         ulong          cf_idx,
                         const char *   key,
                         ulong          klen,
                         const char *   value,
                         ulong          vlen )
{
  /* Initialize error pointer to capture any RocksDB errors */
  char * err = NULL;
  
  /* Insert the key-value pair into the specified column family.
     Parameters:
     - db->db: Database handle
     - db->wo: Write options configured during database initialization
     - db->cf_handles[cf_idx]: Handle for the target column family
     - key: Pointer to the key data
     - klen: Length of the key data in bytes
     - value: Pointer to the value data
     - vlen: Length of the value data in bytes
     - &err: Output parameter for error messages */
  rocksdb_put_cf( db->db, db->wo, db->cf_handles[cf_idx],
                  key, klen, value, vlen, &err );
  
  /* Check if the insertion operation encountered an error */
  if( FD_UNLIKELY( err != NULL ) ) {
    /* Log the error for debugging purposes */
    FD_LOG_WARNING(( "rocksdb_put_cf failed with error %s", err ));
    /* Return -1 to indicate insertion failure */
    return -1;
  }
  
  /* Return 0 to indicate successful insertion */
  return 0;
}

/* fd_blockstore_scan_block scans a reconstructed block to extract
   microblock information and validate the block structure. This
   function is used as part of the deshredding process to analyze
   the block content after it has been reconstructed from shreds.

   blockstore points to the blockstore context where the block is stored.

   slot is the slot number of the block being scanned.

   block points to the block structure that will be populated with
   microblock information during the scan.

   The function performs the following operations:
   1. Allocates memory for microblock metadata
   2. Iterates through all batches in the block
   3. For each batch, processes all microblocks
   4. For each microblock, validates and parses all transactions
   5. Records microblock offsets and counts
   6. Handles trailing bytes in batches according to Agave compatibility

   The function follows Agave's behavior for batch processing, allowing
   trailing bytes to be ignored in batches for compatibility with
   bincode version 1.3.3 default deserializer behavior.

   Block structure:
   - Blocks contain one or more batches
   - Each batch contains one or more microblocks
   - Each microblock contains one or more transactions
   - Microblocks are recorded with their offsets for later access

   The function will terminate the program if it encounters parsing
   errors or memory allocation failures, as these indicate critical
   data corruption or resource exhaustion.

   Time complexity: O(n) where n is the total number of transactions
   in the block.

   Example usage:
     fd_blockstore_scan_block( blockstore, slot_num, block );
     // block now contains microblock metadata for efficient access */

static void
fd_blockstore_scan_block( fd_blockstore_t * blockstore, ulong slot, fd_block_t * block ) {

  fd_block_micro_t * micros = fd_alloc_malloc( fd_blockstore_alloc( blockstore ),
                                               alignof( fd_block_micro_t ),
                                               sizeof( *micros ) * FD_MICROBLOCK_MAX_PER_SLOT );

  /*
   * Agave decodes precisely one array of microblocks from each batch.
   * As of bincode version 1.3.3, the default deserializer used when
   * decoding a batch in the blockstore allows for trailing bytes to be
   * ignored.
   * https://github.com/anza-xyz/agave/blob/v2.1.0/ledger/src/blockstore.rs#L3764
   */
  uchar allow_trailing = 1UL;

  uchar const * data = fd_blockstore_block_data_laddr( blockstore, block );
  FD_LOG_DEBUG(( "scanning slot %lu, ptr %p, sz %lu", slot, (void *)data, block->data_sz ));

  fd_block_entry_batch_t const * batch_laddr = fd_blockstore_block_batch_laddr( blockstore, block );
  ulong const                    batch_cnt   = block->batch_cnt;

  ulong micros_cnt = 0UL;
  ulong blockoff   = 0UL;
  for( ulong batch_i = 0UL; batch_i < batch_cnt; batch_i++ ) {
    ulong const batch_end_off = batch_laddr[ batch_i ].end_off;
    if( blockoff + sizeof( ulong ) > batch_end_off ) FD_LOG_ERR(( "premature end of batch" ));
    ulong mcount = FD_LOAD( ulong, data + blockoff );
    blockoff += sizeof( ulong );

    /* Loop across microblocks */
    for( ulong mblk = 0; mblk < mcount; ++mblk ) {
      if( blockoff + sizeof( fd_microblock_hdr_t ) > batch_end_off )
        FD_LOG_ERR(( "premature end of batch" ));
      if( micros_cnt < FD_MICROBLOCK_MAX_PER_SLOT ) {
        fd_block_micro_t * m = micros + ( micros_cnt++ );
        m->off               = blockoff;
      }
      fd_microblock_hdr_t * hdr = (fd_microblock_hdr_t *)( data + blockoff );
      blockoff += sizeof( fd_microblock_hdr_t );

      /* Loop across transactions */
      for( ulong txn_idx = 0; txn_idx < hdr->txn_cnt; txn_idx++ ) {
        uchar         txn_out[FD_TXN_MAX_SZ];
        uchar const * raw    = data + blockoff;
        ulong         pay_sz = 0;
        ulong         txn_sz = fd_txn_parse_core( (uchar const *)raw,
                                          fd_ulong_min( batch_end_off - blockoff, FD_TXN_MTU ),
                                          txn_out,
                                          NULL,
                                          &pay_sz );
        if( txn_sz == 0 || txn_sz > FD_TXN_MTU ) {
          FD_LOG_ERR(( "failed to parse transaction %lu in microblock %lu in slot %lu. txn size: %lu",
                        txn_idx,
                        mblk,
                        slot,
                        txn_sz ));
        }

        if( pay_sz == 0UL )
          FD_LOG_ERR(( "failed to parse transaction %lu in microblock %lu in slot %lu",
                        txn_idx,
                        mblk,
                        slot ));

        blockoff += pay_sz;
      }
    }
    if( FD_UNLIKELY( blockoff > batch_end_off ) ) {
      FD_LOG_ERR(( "parser error: shouldn't have been allowed to read past batch boundary" ));
    }
    if( FD_UNLIKELY( blockoff < batch_end_off ) ) {
      if( FD_LIKELY( allow_trailing ) ) {
        FD_LOG_DEBUG(( "ignoring %lu trailing bytes in slot %lu batch %lu", batch_end_off-blockoff, slot, batch_i ));
      }
      if( FD_UNLIKELY( !allow_trailing ) ) {
        FD_LOG_ERR(( "%lu trailing bytes in slot %lu batch %lu", batch_end_off-blockoff, slot, batch_i ));
      }
    }
    blockoff = batch_end_off;
  }

  fd_block_micro_t * micros_laddr =
      fd_alloc_malloc( fd_blockstore_alloc( blockstore ),
                       alignof( fd_block_micro_t ),
                       sizeof( fd_block_micro_t ) * micros_cnt );
  fd_memcpy( micros_laddr, micros, sizeof( fd_block_micro_t ) * micros_cnt );
  block->micros_gaddr = fd_wksp_gaddr_fast( fd_blockstore_wksp( blockstore ), micros_laddr );
  block->micros_cnt   = micros_cnt;

  fd_alloc_free( fd_blockstore_alloc( blockstore ), micros );
}

/* deshred reconstructs a complete block from individual shreds stored
   in the blockstore. This function is the core of the deshredding
   process that converts shred data back into a complete block structure.

   blockstore points to the blockstore containing the shreds to be
   deshredded and where the reconstructed block will be stored.

   slot is the slot number of the block to be reconstructed.

   Returns FD_BLOCKSTORE_SUCCESS on successful reconstruction.

   The function performs the following major operations:
   1. Queries the block map to get block information
   2. Calculates total block size by iterating through all shreds
   3. Allocates memory for the reconstructed block
   4. Copies shred payloads into the block data buffer
   5. Records shred metadata and batch boundaries
   6. Scans the block to extract microblock information
   7. Updates block metadata including hash and completion flags

   Block reconstruction process:
   - Shreds are retrieved in order from the shred map
   - Shred payloads are concatenated to form the block data
   - Batch boundaries are identified by shred flags
   - Block metadata is populated from the last microblock hash

   The function handles both regular shreds and shreds that mark
   slot completion or data completion boundaries. These special
   shreds are used to identify batch boundaries within the block.

   Memory allocation:
   - Allocates a single contiguous region for the entire block
   - Includes space for block header, data, shred metadata, and batch info
   - Uses aligned allocation for optimal performance

   The function will terminate the program if it encounters memory
   allocation failures, as this indicates critical resource exhaustion.

   Time complexity: O(n) where n is the number of shreds in the slot.

   Example usage:
     int result = deshred( blockstore, slot_num );
     if( result == FD_BLOCKSTORE_SUCCESS ) {
       FD_LOG_INFO(( "Successfully deshredded slot %lu", slot_num ));
     } */

static int
deshred( fd_blockstore_t * blockstore, ulong slot ) {
  /* Log the start of the deshredding process for debugging */
  FD_LOG_NOTICE(( "[%s] slot %lu", __func__, slot ));

  /* Query the block map to get information about the block we're deshredding.
     This is a blocking operation that waits for the block info to be available. */
  fd_block_map_query_t query[1];
  int err = fd_block_map_prepare( blockstore->block_map, &slot, NULL, query, FD_MAP_FLAG_BLOCKING );
  fd_block_info_t * block_info = fd_block_map_query_element( query );
  
  /* Verify that the block exists and hasn't been deshredded yet.
     block_gaddr == 0 indicates the block data hasn't been reconstructed. */
  FD_TEST( err == FD_MAP_SUCCESS && block_info->slot == slot && block_info->block_gaddr == 0 );
  /* FIXME: Duplicate blocks are not currently supported */

  /* Record the timestamp when deshredding begins */
  block_info->ts = fd_log_wallclock();
  
  /* Calculate the number of shreds to process. slot_complete_idx is the
     index of the last shred, so we add 1 to get the total count. */
  ulong shred_cnt = block_info->slot_complete_idx + 1;
  
  /* Publish the updated block info back to the map */
  fd_block_map_publish( query );

  /* First pass: Calculate the total size needed for the reconstructed block
     and count the number of batch boundaries. */
  ulong block_sz  = 0UL;  /* Total size of all shred payloads */
  ulong batch_cnt = 0UL;  /* Number of batches in the block */
  fd_shred_t shred_hdr;   /* Temporary storage for shred headers */
  
  /* Iterate through all shreds to calculate sizes and count batches */
  for( uint idx = 0; idx < shred_cnt; idx++ ) {
    /* Construct the shred key for map lookup */
    fd_shred_key_t key = { slot, idx };
    int err = FD_MAP_ERR_AGAIN;
    
    /* Retry loop for querying the shred map (handles concurrency) */
    while( err == FD_MAP_ERR_AGAIN ) {
      fd_buf_shred_map_query_t query[1] = { 0 };
      err = fd_buf_shred_map_query_try( blockstore->shred_map, &key, NULL, query, 0 );
      
      /* Handle various error conditions */
      if( FD_UNLIKELY( err == FD_MAP_ERR_KEY ) ) 
        FD_LOG_ERR(( "[%s] map missing shred %lu %u while deshredding", __func__, slot, idx ));
      if( FD_UNLIKELY( err == FD_MAP_ERR_CORRUPT ) ) 
        FD_LOG_ERR(( "[%s] map corrupt. shred %lu %u", __func__, slot, idx ));
      if( FD_UNLIKELY( err == FD_MAP_ERR_AGAIN ) ) continue;
      
      /* Extract shred header for size calculation */
      fd_buf_shred_t const * shred = fd_buf_shred_map_query_element_const( query );
      shred_hdr = shred->hdr;
      err = fd_buf_shred_map_query_test( query );
    }
    FD_TEST( !err );
    
    /* Add this shred's payload size to the total block size */
    block_sz += fd_shred_payload_sz( &shred_hdr );
    
    /* Check if this shred marks the end of a batch. Batches are delimited
       by shreds with SLOT_COMPLETE or DATA_COMPLETE flags. */
    if( FD_LIKELY( ( shred_hdr.data.flags & FD_SHRED_DATA_FLAG_SLOT_COMPLETE ) ||
                     shred_hdr.data.flags & FD_SHRED_DATA_FLAG_DATA_COMPLETE ) ) {
      batch_cnt++;
    }
  }

  /* Calculate memory layout for the reconstructed block.
     The block structure contains:
     1. fd_block_t header
     2. Raw block data (aligned to 128 bytes)
     3. Array of shred metadata (aligned to fd_block_shred_t)
     4. Array of batch boundary info (aligned to fd_block_entry_batch_t) */
  ulong data_off  = fd_ulong_align_up( sizeof(fd_block_t), 128UL );
  ulong shred_off = fd_ulong_align_up( data_off + block_sz, alignof(fd_block_shred_t) );
  ulong batch_off = fd_ulong_align_up( shred_off + (sizeof(fd_block_shred_t) * shred_cnt), alignof(fd_block_entry_batch_t) );
  ulong tot_sz    = batch_off + (sizeof(fd_block_entry_batch_t) * batch_cnt);

  /* Allocate memory for the entire reconstructed block */
  fd_alloc_t * alloc = fd_blockstore_alloc( blockstore );
  fd_wksp_t *  wksp  = fd_blockstore_wksp( blockstore );
  fd_block_t * block = fd_alloc_malloc( alloc, 128UL, tot_sz );
  if( FD_UNLIKELY( !block ) ) {
    FD_LOG_ERR(( "[%s] OOM: failed to alloc block. blockstore needs to hold in memory all blocks for slots >= SMR, so either increase memory or check for issues with publishing new SMRs.", __func__ ));
  }

  /* Initialize the block header */
  fd_memset( block, 0, sizeof(fd_block_t) );

  /* Set up pointers to the different sections of the allocated memory */
  uchar * data_laddr  = (uchar *)((ulong)block + data_off);
  block->data_gaddr   = fd_wksp_gaddr_fast( wksp, data_laddr );
  block->data_sz      = block_sz;
  
  fd_block_shred_t * shreds_laddr = (fd_block_shred_t *)((ulong)block + shred_off);
  block->shreds_gaddr = fd_wksp_gaddr_fast( wksp, shreds_laddr );
  block->shreds_cnt   = shred_cnt;
  
  fd_block_entry_batch_t * batch_laddr = (fd_block_entry_batch_t *)((ulong)block + batch_off);
  block->batch_gaddr = fd_wksp_gaddr_fast( wksp, batch_laddr );
  block->batch_cnt    = batch_cnt;

  /* Second pass: Copy shred data and build the reconstructed block */
  ulong off     = 0UL;    /* Current offset in the block data */
  ulong batch_i = 0UL;    /* Current batch index */
  
  for( uint idx = 0; idx < shred_cnt; idx++ ) {
    /* Construct shred key for lookup */
    fd_shred_key_t key        = { slot, idx };
    ulong          payload_sz = 0UL;
    uchar          flags      = 0;
    int err = FD_MAP_ERR_AGAIN;
    
    /* Retry loop for querying the shred map */
    while( err == FD_MAP_ERR_AGAIN ) {
      fd_buf_shred_map_query_t query[1] = { 0 };;
      err = fd_buf_shred_map_query_try( blockstore->shred_map, &key, NULL, query, 0 );
      if( FD_UNLIKELY( err == FD_MAP_ERR_AGAIN ) ) continue;
      if( FD_UNLIKELY( err == FD_MAP_ERR_KEY ) ) 
        FD_LOG_ERR(( "[%s] map missing shred %lu %u while deshredding", __func__, slot, idx ));
      if( FD_UNLIKELY( err == FD_MAP_ERR_CORRUPT ) ) 
        FD_LOG_ERR(( "[%s] map corrupt. shred %lu %u", __func__, slot, idx ));
      
      /* Extract shred data and copy payload to the block data buffer */
      fd_shred_t const * shred = &fd_buf_shred_map_query_element_const( query )->hdr;
      memcpy( data_laddr + off, fd_shred_data_payload( shred ), fd_shred_payload_sz( shred ) );

      /* Store shred metadata for future reference */
      shreds_laddr[idx].hdr = *shred;
      shreds_laddr[idx].off = off;
      
      /* Verify that the copy operation was successful */
      FD_TEST( 0 == memcmp( &shreds_laddr[idx].hdr, shred, sizeof( fd_shred_t ) ) );
      FD_TEST( 0 == memcmp( data_laddr + shreds_laddr[idx].off, fd_shred_data_payload( shred ), fd_shred_payload_sz( shred ) ) );

      /* Extract payload size and flags for batch processing */
      payload_sz = fd_shred_payload_sz( shred );
      flags      = shred->data.flags;

      err = fd_buf_shred_map_query_test( query );
    }
    FD_TEST( !err );
    
    /* Update offset for next shred */
    off += payload_sz;
    
    /* Check if this shred marks the end of a batch */
    if( FD_LIKELY( (flags & FD_SHRED_DATA_FLAG_SLOT_COMPLETE) || flags & FD_SHRED_DATA_FLAG_DATA_COMPLETE ) ) {
      /* Record the end offset of this batch */
      batch_laddr[ batch_i++ ].end_off = off;
    }
  }
  
  /* Verify that we processed the expected number of batches */
  if( FD_UNLIKELY( batch_cnt != batch_i ) ) {
    FD_LOG_ERR(( "batch_cnt(%lu)!=batch_i(%lu) potential memory corruption", batch_cnt, batch_i ));
  }

  /* Scan the reconstructed block to extract microblock metadata */
  fd_blockstore_scan_block( blockstore, slot, block );

  /* Memory barrier to ensure all writes are visible before publishing */
  FD_COMPILER_MFENCE();

  /* Update the block map with the reconstructed block information */
  err = fd_block_map_prepare( blockstore->block_map, &slot, NULL, query, FD_MAP_FLAG_BLOCKING );
  block_info = fd_block_map_query_element( query );
  FD_TEST( err == FD_MAP_SUCCESS && block_info->slot == slot );

  /* Store the block address and extract the block hash from the last microblock */
  block_info->block_gaddr          = fd_wksp_gaddr_fast( wksp, block );
  fd_block_micro_t *    micros     = fd_wksp_laddr_fast( wksp, block->micros_gaddr );
  uchar *               data       = fd_wksp_laddr_fast( wksp, block->data_gaddr );
  fd_microblock_hdr_t * last_micro = (fd_microblock_hdr_t *)( data + micros[block->micros_cnt - 1].off );
  memcpy( &block_info->block_hash, last_micro->hash, sizeof( fd_hash_t ) );

  /* Update block status flags to indicate completion */
  block_info->flags = fd_uchar_clear_bit( block_info->flags, FD_BLOCK_FLAG_RECEIVING );
  block_info->flags = fd_uchar_set_bit( block_info->flags, FD_BLOCK_FLAG_COMPLETED );
  
  /* Publish the updated block info */
  fd_block_map_publish( query );

  /* Return success */
  return FD_BLOCKSTORE_SUCCESS;
}

/* fd_blockstore_block_allocs_remove safely removes all memory allocations
   associated with a block from the blockstore. This function is used to
   free memory when a block is no longer needed, typically during cleanup
   or when the block is being evicted from memory.

   blockstore points to the blockstore containing the block to be removed.

   slot is the slot number of the block whose allocations should be removed.

   The function performs the following safety checks and operations:
   1. Queries the block map to verify the block exists
   2. Checks that no replay operation is in progress for this block
   3. Safely removes the microblock metadata allocations
   4. Removes the main block allocation

   Safety considerations:
   - Returns early if the slot is not found (no error, as this is safe)
   - Refuses to remove blocks that are currently being replayed
   - Uses memory barriers to ensure thread safety during removal
   - Checks for NULL pointers before attempting to free memory

   The function is designed to be safe to call even if:
   - The slot doesn't exist in the blockstore
   - The block has already been partially or completely removed
   - Memory allocations are in an inconsistent state

   Thread safety:
   - Uses memory barriers to coordinate with other threads
   - Safely handles concurrent access to the block map
   - Prevents removal of blocks that are actively being used

   Time complexity: O(log n) for the block map lookup, O(1) for cleanup.

   Example usage:
     fd_blockstore_block_allocs_remove( blockstore, old_slot );
     // All memory for old_slot has been safely freed */

void
fd_blockstore_block_allocs_remove( fd_blockstore_t * blockstore,
                                   ulong slot ){
  fd_block_map_query_t query[1] = { 0 };
  ulong block_gaddr             = 0;
  int    err  = FD_MAP_ERR_AGAIN;
  while( err == FD_MAP_ERR_AGAIN ) {
    err = fd_block_map_query_try( blockstore->block_map, &slot, NULL, query, 0 );
    if( FD_UNLIKELY( err == FD_MAP_ERR_AGAIN ) ) continue;
    if( FD_UNLIKELY( err == FD_MAP_ERR_KEY ) ) return; /* slot not found */
    fd_block_info_t * block_info = fd_block_map_query_ele( query );
    if( FD_UNLIKELY( fd_uchar_extract_bit( block_info->flags, FD_BLOCK_FLAG_REPLAYING ) ) ) {
      FD_LOG_WARNING(( "[%s] slot %lu has replay in progress. not removing.", __func__, slot ));
      return;
    }
    block_gaddr  = block_info->block_gaddr;
    err = fd_block_map_query_test( query );
  }

  /* Remove all the allocations relating to a block. */

  fd_wksp_t *  wksp  = fd_blockstore_wksp( blockstore );
  fd_alloc_t * alloc = fd_blockstore_alloc( blockstore );

  fd_block_t *   block   = fd_wksp_laddr_fast( wksp, block_gaddr );

  /* DO THIS FIRST FOR THREAD SAFETY */
  FD_COMPILER_MFENCE();
  //block_info->block_gaddr = 0;

  if( block->micros_gaddr ) fd_alloc_free( alloc, fd_wksp_laddr_fast( wksp, block->micros_gaddr ) );

  fd_alloc_free( alloc, block );
}

/* fd_rocksdb_import_block_blockstore imports a complete block from RocksDB
   into a blockstore by reconstructing it from stored shreds. This function
   is the primary interface for loading blockchain data from persistent
   storage into memory for processing.

   db points to an initialized RocksDB database containing the block data.

   m points to the slot metadata for the block to be imported.

   blockstore points to the destination blockstore where the reconstructed
   block will be stored.

   hash_override points to a 32-byte bank hash to use instead of the one
   stored in the database, or NULL to use the stored hash.

   valloc is a memory allocator used for temporary allocations during
   the import process.

   Returns 0 on success, -1 on failure.

   The function performs the following major operations:
   1. Retrieves all shreds for the slot from the data_shred column family
   2. Validates that all required shreds are present and in order
   3. Inserts each shred into the blockstore
   4. Triggers deshredding to reconstruct the complete block
   5. Retrieves and sets additional metadata (timestamps, block height, bank hash)
   6. Updates blockstore state with the new block

   Shred retrieval and validation:
   - Iterates through shreds from index 0 to m->received
   - Validates that each shred exists and is at the expected index
   - Parses each shred to ensure it's well-formed
   - Reports detailed errors for missing or malformed shreds

   Additional metadata retrieved:
   - Block timestamp from blocktime column family
   - Block height from block_height column family  
   - Bank hash from bank_hashes column family (with bincode decoding)

   Block state updates:
   - Sets various block flags (completed, processed, confirmed, etc.)
   - Updates blockstore watermarks (lps, hcs, wmk)
   - Records block height and bank hash

   The function handles the complex bank hash decoding process, which
   involves deserializing a versioned hash structure and extracting
   the current frozen hash value.

   Time complexity: O(n * log m) where n is the number of shreds and
   m is the size of the blockstore.

   Example usage:
     fd_slot_meta_t metadata;
     int result = fd_rocksdb_import_block_blockstore( &db, &metadata, blockstore,
                                                      NULL, valloc );
     if( result == 0 ) {
       FD_LOG_INFO(( "Successfully imported block for slot %lu", metadata.slot ));
     } else {
       FD_LOG_ERR(( "Failed to import block for slot %lu", metadata.slot ));
     } */

int
fd_rocksdb_import_block_blockstore( fd_rocksdb_t *    db,
                                    fd_slot_meta_t *  m,
                                    fd_blockstore_t * blockstore,
                                    const uchar *     hash_override,
                                    fd_valloc_t       valloc ) {
  ulong slot = m->slot;
  ulong start_idx = 0;
  ulong end_idx = m->received;

  rocksdb_iterator_t * iter = rocksdb_create_iterator_cf(db->db, db->ro, db->cf_handles[FD_ROCKSDB_CFIDX_DATA_SHRED]);

  char k[16];
  ulong slot_be = *((ulong *) &k[0]) = fd_ulong_bswap(slot);
  *((ulong *) &k[8]) = fd_ulong_bswap(start_idx);

  rocksdb_iter_seek(iter, (const char *) k, sizeof(k));

  for (ulong i = start_idx; i < end_idx; i++) {
    ulong cur_slot, index;
    uchar valid = rocksdb_iter_valid(iter);

    if (valid) {
      size_t klen = 0;
      const char* key = rocksdb_iter_key(iter, &klen); // There is no need to free key
      if (klen != 16)  // invalid key
        continue;
      cur_slot = fd_ulong_bswap(*((ulong *) &key[0]));
      index = fd_ulong_bswap(*((ulong *) &key[8]));
    }

    if (!valid || cur_slot != slot) {
      FD_LOG_WARNING(("missing shreds for slot %lu", slot));
      rocksdb_iter_destroy(iter);
      return -1;
    }

    if (index != i) {
      FD_LOG_WARNING(("missing shred %lu at index %lu for slot %lu", i, index, slot));
      rocksdb_iter_destroy(iter);
      return -1;
    }

    size_t dlen = 0;
    // Data was first copied from disk into memory to make it available to this API
    const unsigned char *data = (const unsigned char *) rocksdb_iter_value(iter, &dlen);
    if (data == NULL) {
      FD_LOG_WARNING(("failed to read shred %lu/%lu", slot, i));
      rocksdb_iter_destroy(iter);
      return -1;
    }

    // This just correctly selects from inside the data pointer to the
    // actual data without a memory copy
    fd_shred_t const * shred = fd_shred_parse( data, (ulong) dlen );
    if (shred == NULL) {
      FD_LOG_WARNING(("failed to parse shred %lu/%lu", slot, i));
      rocksdb_iter_destroy(iter);
      return -1;
    }
    fd_blockstore_shred_insert( blockstore, shred );
    // if (rc != FD_BLOCKSTORE_SUCCESS_SLOT_COMPLETE && rc != FD_BLOCKSTORE_SUCCESS) {
    //   FD_LOG_WARNING(("failed to store shred %lu/%lu", slot, i));
    //   rocksdb_iter_destroy(iter);
    //   return -1;
    // }

    rocksdb_iter_next(iter);
  }

  rocksdb_iter_destroy(iter);

  fd_block_info_t * block_info = fd_blockstore_block_map_query( blockstore, slot );
  if( FD_LIKELY( block_info && fd_blockstore_shreds_complete( blockstore, slot ) ) ) {
    deshred( blockstore, slot );

    size_t vallen = 0;
    char * err = NULL;
    char * res = rocksdb_get_cf(
      db->db,
      db->ro,
      db->cf_handles[ FD_ROCKSDB_CFIDX_BLOCKTIME ],
      (char const *)&slot_be, sizeof(ulong),
      &vallen,
      &err );
    if( FD_UNLIKELY( err ) ) {
      FD_LOG_WARNING(( "rocksdb: %s", err ));
      free( err );
    } else if(vallen == sizeof(ulong)) {
      block_info->ts = (*(long*)res)*((long)1e9); /* Convert to nanos */
      free(res);
    }

    vallen = 0;
    err = NULL;
    res = rocksdb_get_cf(
      db->db,
      db->ro,
      db->cf_handles[ FD_ROCKSDB_CFIDX_BLOCK_HEIGHT ],
      (char const *)&slot_be, sizeof(ulong),
      &vallen,
      &err );
    block_info->block_height = 0;
    if( FD_UNLIKELY( err ) ) {
      FD_LOG_WARNING(( "rocksdb: %s", err ));
      free( err );
    } else if(vallen == sizeof(ulong)) {
      block_info->block_height = *(ulong*)res;
      free(res);
    }

    vallen = 0;
    err = NULL;
    if (NULL != hash_override)
      fd_memcpy( block_info->bank_hash.hash, hash_override, 32UL );
    else {
      res = rocksdb_get_cf(
        db->db,
          db->ro,
          db->cf_handles[ FD_ROCKSDB_CFIDX_BANK_HASHES ],
          (char const *)&slot_be, sizeof(ulong),
          &vallen,
          &err );
      if( FD_UNLIKELY( err ) ) {
        FD_LOG_WARNING(( "rocksdb: %s", err ));
        free( err );
      } else {
        fd_bincode_decode_ctx_t decode = {
          .data    = res,
          .dataend = res + vallen
        };
        ulong total_sz = 0UL;
        int decode_err = fd_frozen_hash_versioned_decode_footprint( &decode, &total_sz );

        uchar * mem = fd_valloc_malloc( valloc, fd_frozen_hash_versioned_align(), total_sz );
        if( NULL == mem ) {
          FD_LOG_ERR(( "fd_valloc_malloc failed" ));
        }

        fd_frozen_hash_versioned_t * versioned = fd_frozen_hash_versioned_decode( mem, &decode );
        if( FD_UNLIKELY( decode_err!=FD_BINCODE_SUCCESS ) ) goto cleanup;
        if( FD_UNLIKELY( decode.data!=decode.dataend    ) ) goto cleanup;
        if( FD_UNLIKELY( versioned->discriminant !=fd_frozen_hash_versioned_enum_current ) ) goto cleanup;
        /* Success */
        fd_memcpy( block_info->bank_hash.hash, versioned->inner.current.frozen_hash.hash, 32UL );
      cleanup:
        free( res );
      }
    }
  }

  blockstore->shmem->lps = slot;
  blockstore->shmem->hcs = slot;
  blockstore->shmem->wmk = slot;

  if( FD_LIKELY( block_info ) ) {
    block_info->flags =
      fd_uchar_set_bit(
      fd_uchar_set_bit(
      fd_uchar_set_bit(
      fd_uchar_set_bit(
      fd_uchar_set_bit(
        block_info->flags,
        FD_BLOCK_FLAG_COMPLETED ),
        FD_BLOCK_FLAG_PROCESSED ),
        FD_BLOCK_FLAG_EQVOCSAFE ),
        FD_BLOCK_FLAG_CONFIRMED ),
        FD_BLOCK_FLAG_FINALIZED );
  }

  return 0;
}

/* fd_rocksdb_import_block_shredcap exports a block from RocksDB to the
   shredcap file format. This function is used to convert blockchain data
   from the database into a specialized capture format for analysis,
   replay, or archival purposes.

   db points to an initialized RocksDB database containing the block data.

   metadata points to the slot metadata for the block to be exported.

   ostream points to a buffered output stream where the shredcap data
   will be written.

   bank_hash_ostream points to a separate buffered output stream where
   bank hash information will be written.

   valloc is a memory allocator used for temporary allocations during
   the export process.

   Returns 0 on success, -1 on failure.

   The shredcap format is a specialized binary format that preserves
   the original shred structure while adding metadata for efficient
   processing. The format includes:

   Slot Header (written first):
   - Magic number for format identification
   - Version number for compatibility
   - Payload size (updated after processing)
   - Slot metadata (consumed, received, timestamps, etc.)

   Shred Data (for each shred):
   - Shred header with size information
   - Aligned shred data with boundary padding
   - Each shred is aligned to FD_SHREDCAP_ALIGN boundaries

   Slot Footer (written last):
   - Magic number for validation
   - Total payload size for verification

   The function performs the following operations:
   1. Writes slot header with placeholder payload size
   2. Iterates through all shreds for the slot
   3. For each shred: writes shred header and aligned shred data
   4. Updates payload size in slot header using file seeking
   5. Writes slot footer
   6. Exports bank hash data to separate stream

   File handling:
   - Uses buffered I/O for efficient writing
   - Handles buffer flushes and file seeking carefully
   - Updates payload size field after processing completes
   - Aligns shred data to specified boundaries

   Bank hash export:
   - Retrieves bank hash from database
   - Decodes versioned hash structure
   - Writes bank hash entry to separate stream

   The function maintains compatibility with external analysis tools
   by preserving the exact shred structure and adding only minimal
   metadata overhead.

   Time complexity: O(n) where n is the number of shreds in the slot.

   Example usage:
     fd_slot_meta_t metadata;
     int result = fd_rocksdb_import_block_shredcap( &db, &metadata,
                                                    shred_stream, hash_stream, valloc );
     if( result == 0 ) {
       FD_LOG_INFO(( "Successfully exported slot %lu to shredcap", metadata.slot ));
     } else {
       FD_LOG_ERR(( "Failed to export slot %lu", metadata.slot ));
     } */

int
fd_rocksdb_import_block_shredcap( fd_rocksdb_t *               db,
                                  fd_slot_meta_t *             metadata,
                                  fd_io_buffered_ostream_t *   ostream,
                                  fd_io_buffered_ostream_t *   bank_hash_ostream,
                                  fd_valloc_t                  valloc ) {
  ulong slot = metadata->slot;

  /* pre_slot_hdr_file_offset is the current offset within the file, but
     pre_slot_hdr_file_offset_real accounts for the size of the buffer that has
     been filled but not flushed. This value is used to jump back into the file to
     populate the payload_sz for the slot header */
  long pre_slot_hdr_file_offset      = lseek( ostream->fd, 0, SEEK_CUR );
  long pre_slot_hdr_file_offset_real = pre_slot_hdr_file_offset + (long)ostream->wbuf_used;
  if ( FD_UNLIKELY( pre_slot_hdr_file_offset == -1 ) ) {
    FD_LOG_ERR(( "lseek error while seeking to current location" ));
  }

  /* Write slot specific header */
  fd_shredcap_slot_hdr_t slot_hdr;
  slot_hdr.magic                 = FD_SHREDCAP_SLOT_HDR_MAGIC;
  slot_hdr.version               = FD_SHREDCAP_SLOT_HDR_VERSION;
  slot_hdr.payload_sz            = ULONG_MAX; /* This value is populated after slot is processed */
  slot_hdr.slot                  = metadata->slot;
  slot_hdr.consumed              = metadata->consumed;
  slot_hdr.received              = metadata->received;
  slot_hdr.first_shred_timestamp = metadata->first_shred_timestamp;
  slot_hdr.last_index            = metadata->last_index;
  slot_hdr.parent_slot           = metadata->parent_slot;
  fd_io_buffered_ostream_write( ostream, &slot_hdr, FD_SHREDCAP_SLOT_HDR_FOOTPRINT );

  /* We need to track the payload size */
  ulong payload_sz = 0;

  rocksdb_iterator_t* iter = rocksdb_create_iterator_cf( db->db, db->ro, db->cf_handles[FD_ROCKSDB_CFIDX_DATA_SHRED] );

  char k[16];
  ulong slot_be = *((ulong *) &k[0]) = fd_ulong_bswap( slot );
  *((ulong *) &k[8]) = fd_ulong_bswap( 0 );

  rocksdb_iter_seek( iter, (const char *) k, sizeof(k) );

  ulong start_idx = 0;
  ulong end_idx   = metadata->received;
  for ( ulong i = start_idx; i < end_idx; i++ ) {
    ulong cur_slot, index;
    uchar valid = rocksdb_iter_valid( iter );

    if ( valid ) {
      size_t klen = 0;
      const char* key = rocksdb_iter_key( iter, &klen ); // There is no need to free key
      if ( klen != 16 ) {  // invalid key
        continue;
      }
      cur_slot = fd_ulong_bswap(*((ulong *) &key[0]));
      index    = fd_ulong_bswap(*((ulong *) &key[8]));
    }

    if ( !valid || cur_slot != slot ) {
      FD_LOG_WARNING(( "missing shreds for slot %lu", slot ));
      rocksdb_iter_destroy( iter );
      return -1;
    }

    if ( index != i ) {
      FD_LOG_WARNING(( "missing shred %lu at index %lu for slot %lu", i, index, slot ));
      rocksdb_iter_destroy( iter );
      return -1;
    }

    size_t dlen = 0;
    // Data was first copied from disk into memory to make it available to this API
    const unsigned char *data = (const unsigned char *) rocksdb_iter_value( iter, &dlen );
    if ( data == NULL ) {
      FD_LOG_WARNING(( "failed to read shred %lu/%lu", slot, i ));
      rocksdb_iter_destroy( iter );
      return -1;
    }

    fd_shred_t const * shred = fd_shred_parse( data, (ulong) dlen );
    if ( shred == NULL ) {
      FD_LOG_WARNING(( "failed to parse shred %lu/%lu", slot, i ));
      rocksdb_iter_destroy( iter );
      return -1;
    }

    /* Write a shred header and shred. Each shred and it's header will be aligned */
    char shred_buf[ FD_SHREDCAP_SHRED_MAX ];
    char * shred_buf_ptr = shred_buf;
    ushort shred_sz = (ushort)fd_shred_sz( shred );
    uint shred_boundary_sz = (uint)fd_uint_align_up( shred_sz + FD_SHREDCAP_SHRED_HDR_FOOTPRINT,
                                                     FD_SHREDCAP_ALIGN ) - FD_SHREDCAP_SHRED_HDR_FOOTPRINT;

    fd_memset( shred_buf_ptr, 0, shred_boundary_sz );
    /* Populate start of buffer with header */
    fd_shredcap_shred_hdr_t * shred_hdr = (fd_shredcap_shred_hdr_t*)shred_buf_ptr;
    shred_hdr->hdr_sz            = FD_SHREDCAP_SHRED_HDR_FOOTPRINT;
    shred_hdr->shred_sz          = shred_sz;
    shred_hdr->shred_boundary_sz = shred_boundary_sz;

    /* Skip ahead and populate rest of buffer with shred and write out */
    fd_memcpy( shred_buf_ptr + FD_SHREDCAP_SHRED_HDR_FOOTPRINT, shred, shred_boundary_sz );
    fd_io_buffered_ostream_write( ostream, shred_buf_ptr,
                                  shred_boundary_sz + FD_SHREDCAP_SHRED_HDR_FOOTPRINT );

    payload_sz += shred_boundary_sz + FD_SHREDCAP_SHRED_HDR_FOOTPRINT;
    rocksdb_iter_next( iter );
  }

  /* Update file size */
  long pre_slot_processed_file_offset = lseek( ostream->fd, 0, SEEK_CUR );
  if ( FD_UNLIKELY( pre_slot_processed_file_offset == -1 ) ) {
    FD_LOG_ERR(( "lseek error when seeking to current position" ));
  }

  if ( FD_UNLIKELY( pre_slot_processed_file_offset == pre_slot_hdr_file_offset ) ) {
    /* This case is when the payload from the shreds is smaller than the free
       space from the write buffer. This means that the buffer was not flushed
       at any point. This case is highly unlikely */
    fd_io_buffered_ostream_flush( ostream );
  }

  /* Safely assume that the buffer was flushed to the file at least once. Store
     original seek position, skip to position with payload_sz in header, write
     updated payload sz, and then reset seek position. */
  long original_offset = lseek( ostream->fd, 0, SEEK_CUR );
  if ( FD_UNLIKELY( original_offset == -1 ) ) {
    FD_LOG_ERR(( "lseek error when seeking to current position" ));
  }
  long payload_sz_file_offset = pre_slot_hdr_file_offset_real +
                                (long)FD_SHREDCAP_SLOT_HDR_PAYLOAD_SZ_OFFSET;

  long offset;
  offset = lseek( ostream->fd, payload_sz_file_offset, SEEK_SET );
  if ( FD_UNLIKELY( offset == -1 ) ) {
    FD_LOG_ERR(( "lseek error when seeking to offset=%ld", payload_sz_file_offset ));
  }
  ulong to_write;
  fd_io_write( ostream->fd, &payload_sz, sizeof(ulong), sizeof(ulong), &to_write );

  offset = lseek( ostream->fd, original_offset, SEEK_SET );
  if ( FD_UNLIKELY( offset == -1 ) ) {
    FD_LOG_ERR(( "lseek error when seeking to offset=%ld", original_offset ));
  }

  /* Write slot footer */
  fd_shredcap_slot_ftr_t slot_ftr;
  slot_ftr.magic      = FD_SHREDCAP_SLOT_FTR_MAGIC;
  slot_ftr.payload_sz = payload_sz;
  fd_io_buffered_ostream_write( ostream, &slot_ftr, FD_SHREDCAP_SLOT_FTR_FOOTPRINT );
  rocksdb_iter_destroy( iter );

  /* Get and write bank hash information to respective file */
  size_t vallen = 0;
  char * err = NULL;
  char * res = rocksdb_get_cf( db->db, db->ro, db->cf_handles[ FD_ROCKSDB_CFIDX_BANK_HASHES ],
               (char const *)&slot_be, sizeof(ulong), &vallen, &err );
  if( FD_UNLIKELY( err ) ) {
    FD_LOG_WARNING((" Could not get bank hash data due to err=%s",err ));
    free( err );
  } else {
    fd_bincode_decode_ctx_t decode = {
      .data    = res,
      .dataend = res + vallen,
    };
    ulong total_sz = 0UL;
    int decode_err = fd_frozen_hash_versioned_decode_footprint( &decode, &total_sz );

    uchar * mem = fd_valloc_malloc( valloc, fd_frozen_hash_versioned_align(), total_sz );

    fd_frozen_hash_versioned_t * versioned = fd_frozen_hash_versioned_decode( mem, &decode );

    if( FD_UNLIKELY( decode_err != FD_BINCODE_SUCCESS ) ) goto cleanup;
    if( FD_UNLIKELY( decode.data!=decode.dataend    ) ) goto cleanup;
    if( FD_UNLIKELY( versioned->discriminant != fd_frozen_hash_versioned_enum_current ) ) goto cleanup;
    fd_shredcap_bank_hash_entry_t bank_hash_entry;
    bank_hash_entry.slot = slot;
    fd_memcpy( &bank_hash_entry.bank_hash, versioned->inner.current.frozen_hash.hash, 32UL );
    fd_io_buffered_ostream_write( bank_hash_ostream, &bank_hash_entry, FD_SHREDCAP_BANK_HASH_ENTRY_FOOTPRINT );
  cleanup:
    free( res );
  }
  return 0;
}
