#ifndef HEADER_fd_src_flamenco_runtime_fd_rocksdb_h
#define HEADER_fd_src_flamenco_runtime_fd_rocksdb_h

/* fd_rocksdb.h provides type definitions, constants, and function declarations
   for interacting with RocksDB in the context of Solana blockchain data storage.
   This header defines the public API for the RocksDB integration module.

   The header defines data structures and APIs for:
   - RocksDB database initialization and management
   - Column family configuration and access
   - Block and shred data structures for offline replay
   - Slot metadata retrieval and iteration
   - Transaction status lookups
   - Data import/export between RocksDB and blockstore
   - Shredcap format export capabilities

   The module supports both read-only and read-write access modes, with
   comprehensive error handling and memory management. All functions
   are designed to handle concurrent access patterns common in blockchain
   processing environments.

   Column families are used to organize different types of blockchain data:
   - Slot metadata and block information
   - Transaction data and status
   - Shred data for block reconstruction
   - Validator rewards and performance metrics
   - Bank state and hash information

   The API follows consistent patterns for resource management, error handling,
   and memory allocation, integrating seamlessly with the broader Firedancer
   architecture. */

#include "../../ballet/block/fd_microblock.h"
#include "fd_blockstore.h"

/** fd_block represents a reconstructed Solana block stored in blockstore memory
    for offline replay and analysis. This structure provides efficient access
    to block data through multiple indexing mechanisms.

    A block consists of shred data that has been deshredded (reconstructed)
    into a contiguous data region. The structure maintains metadata arrays
    that enable efficient iteration over different data granularities:
    - Individual shreds and their payloads
    - Entry batches (groups of transactions)  
    - Individual microblocks within batches
    - Individual transactions within microblocks

    Memory Layout:
    The block uses a single large allocation containing multiple regions:
    1. fd_block_t header (this structure)
    2. Contiguous raw block data (aligned to 128 bytes)
    3. Array of shred metadata (fd_block_shred_t[])
    4. Array of batch boundary info (fd_block_entry_batch_t[])
    5. Array of microblock metadata (fd_block_micro_t[])

    All pointers are stored as global addresses (gaddr) rather than local
    addresses to support sharing across address spaces in the workspace.

    Iteration Patterns:
    - Shred iteration: Use shreds_gaddr array with data_gaddr + offset
    - Batch iteration: Use batch_gaddr array for entry batch boundaries
    - Microblock iteration: Use micros_gaddr array within batch ranges
    - Transaction iteration: Parse microblock headers within microblocks

    Performance Characteristics:
    - Sequential access is highly optimized due to contiguous data layout
    - Random access by index requires linear search due to variable sizes
    - Memory usage is minimized through packed layout and shared allocations

    Thread Safety:
    - Structure is read-only after initialization
    - Safe for concurrent reads from multiple threads
    - Removal requires coordination through blockstore locking */
struct fd_block {
  /* Global address of the beginning of the block's reconstructed data region.
     This contains the concatenated payloads from all shreds in the block,
     arranged in slot order. The data can be parsed using the metadata
     arrays to extract individual components. */
  ulong data_gaddr;   

  /* Total size in bytes of the reconstructed block data. This represents
     the sum of all shred payload sizes after deshredding. */
  ulong data_sz;      

  /* Global address of the first fd_block_shred_t in the shred metadata array.
     This array contains shreds_cnt entries, each providing the original
     shred header and offset within the data region. */
  ulong shreds_gaddr; 

  /* Number of shreds that were combined to reconstruct this block.
     Each shred contributes a contiguous payload region to the block data. */
  ulong shreds_cnt;

  /* Global address of the first fd_block_entry_batch_t in the batch array.
     This array contains batch_cnt entries, each marking the end offset
     of an entry batch within the block data. */
  ulong batch_gaddr;  

  /* Number of entry batches in this block. Entry batches are groups of
     transactions that are processed together, delimited by special shreds
     with SLOT_COMPLETE or DATA_COMPLETE flags. */
  ulong batch_cnt;

  /* Global address of the first fd_block_micro_t in the microblock array.
     This array contains micros_cnt entries, each providing metadata about
     a microblock's location within the block data. */
  ulong micros_gaddr; 

  /* Number of microblocks in this block. Microblocks are the smallest
     atomic units containing one or more transactions, and are the basic
     building blocks of entry batches. */
  ulong micros_cnt;
};
typedef struct fd_block fd_block_t;

FD_PROTOTYPES_BEGIN

/* fd_blockstore_block_data_laddr converts a block's data global address
   to a local address pointer for direct memory access. This function
   provides efficient access to the reconstructed block data.

   blockstore points to the blockstore containing the block workspace.
   
   block points to a reconstructed block structure with valid data_gaddr.
   
   Returns a local pointer to the beginning of the block's data region.
   The returned pointer is valid until the block is removed from the
   blockstore. The data region contains concatenated shred payloads
   that can be parsed using the block's metadata arrays.
   
   This function is marked FD_FN_PURE since it performs a pure address
   translation without side effects. The workspace address translation
   is guaranteed to be deterministic for a given gaddr.
   
   Usage pattern:
     uchar * data = fd_blockstore_block_data_laddr( blockstore, block );
     // Access data[offset] using shred/micro/batch metadata for offsets */

FD_FN_PURE static inline uchar *
fd_blockstore_block_data_laddr( fd_blockstore_t * blockstore, fd_block_t * block ) {
  return fd_wksp_laddr_fast( fd_blockstore_wksp( blockstore ), block->data_gaddr );
}

/* fd_blockstore_block_batch_laddr converts a block's batch metadata global
   address to a local address pointer for accessing batch boundary information.
   
   blockstore points to the blockstore containing the block workspace.
   
   block points to a reconstructed block structure with valid batch_gaddr.
   
   Returns a local pointer to the first fd_block_entry_batch_t in the
   batch metadata array. The array contains block->batch_cnt entries,
   each specifying the end offset of an entry batch within the block data.
   
   Entry batches represent groups of transactions that are processed
   together, with boundaries determined by shreds marked with SLOT_COMPLETE
   or DATA_COMPLETE flags during the deshredding process.
   
   Usage pattern:
     fd_block_entry_batch_t * batches = fd_blockstore_block_batch_laddr( blockstore, block );
     for( ulong i = 0; i < block->batch_cnt; i++ ) {
       ulong batch_end = batches[i].end_off;
       // Process batch from previous end to batch_end
     } */

FD_FN_PURE static inline fd_block_entry_batch_t *
fd_blockstore_block_batch_laddr( fd_blockstore_t * blockstore, fd_block_t * block ) {
  return fd_wksp_laddr_fast( fd_blockstore_wksp( blockstore ), block->batch_gaddr );
}

/* fd_blockstore_block_micro_laddr converts a block's microblock metadata
   global address to a local address pointer for accessing microblock information.
   
   blockstore points to the blockstore containing the block workspace.
   
   block points to a reconstructed block structure with valid micros_gaddr.
   
   Returns a local pointer to the first fd_block_micro_t in the microblock
   metadata array. The array contains block->micros_cnt entries, each
   providing the offset of a microblock within the block data.
   
   Microblocks are the fundamental units of transaction organization within
   blocks, containing one or more transactions along with metadata headers.
   Each microblock can be parsed independently once its offset is known.
   
   Usage pattern:
     fd_block_micro_t * micros = fd_blockstore_block_micro_laddr( blockstore, block );
     uchar * data = fd_blockstore_block_data_laddr( blockstore, block );
     for( ulong i = 0; i < block->micros_cnt; i++ ) {
       fd_microblock_hdr_t * hdr = (fd_microblock_hdr_t *)( data + micros[i].off );
       // Process microblock at this offset
     } */

FD_FN_PURE static inline fd_block_micro_t *
fd_blockstore_block_micro_laddr( fd_blockstore_t * blockstore, fd_block_t * block ) {
  return fd_wksp_laddr_fast( fd_blockstore_wksp( blockstore ), block->micros_gaddr );
}

FD_PROTOTYPES_END

#if FD_HAS_ROCKSDB

#include "../../ballet/shred/fd_shred.h"
#include <rocksdb/c.h>

/* Total number of column families used by the Solana RocksDB schema.
   This count includes all the specialized column families for different
   types of blockchain data. */
#define FD_ROCKSDB_CF_CNT (21UL)

/* Column family indices for accessing different data types in RocksDB.
   Each column family stores a specific type of blockchain data with
   its own key-value schema and access patterns.

   Column families provide logical separation of data types while maintaining
   efficient storage and query performance. The indices below correspond
   to the cfgs array positions in the fd_rocksdb_t structure. */

/* Default column family - typically used for miscellaneous data that
   doesn't fit into other specialized column families. */
#define FD_ROCKSDB_CFIDX_DEFAULT                  (0UL)

/* Slot metadata column family stores fd_slot_meta_t structures containing
   information about slot status, parent relationships, and confirmation state.
   Key format: (slot[8]) - big-endian slot number
   Value format: bincode-serialized fd_slot_meta_t structure */
#define FD_ROCKSDB_CFIDX_META                     (1UL)

/* Dead slots column family tracks slots that have been determined to be
   invalid or orphaned and should not be processed.
   Key format: (slot[8]) - big-endian slot number
   Value format: typically empty or minimal metadata */
#define FD_ROCKSDB_CFIDX_DEAD_SLOTS               (2UL)

/* Duplicate slots column family tracks slots that have been seen multiple
   times, which can occur during network reorganizations.
   Key format: (slot[8]) - big-endian slot number
   Value format: duplicate detection metadata
   Note: Usually empty in most deployments */
#define FD_ROCKSDB_CFIDX_DUPLICATE_SLOTS          (3UL) /* Usually empty */

/* Erasure metadata column family stores information needed for erasure
   coding and reconstruction of incomplete blocks from available shreds.
   Key format: (slot[8]) - big-endian slot number
   Value format: erasure coding parameters and reconstruction metadata */
#define FD_ROCKSDB_CFIDX_ERASURE_META             (4UL)

/* Orphans column family tracks blocks that don't have a clear parent
   relationship in the blockchain, often due to network partitions.
   Key format: (slot[8]) - big-endian slot number
   Value format: orphan tracking metadata
   Note: Usually empty in most deployments */
#define FD_ROCKSDB_CFIDX_ORPHANS                  (5UL) /* Usually empty */

/* Bank hashes column family stores the cryptographic hashes representing
   the state of the Solana bank at each slot.
   Key format: (slot[8]) - big-endian slot number
   Value format: bincode-serialized hash versioned structure */
#define FD_ROCKSDB_CFIDX_BANK_HASHES              (6UL)

/* Root column family tracks slots that have been finalized and are
   considered part of the canonical blockchain.
   Key format: (slot[8]) - big-endian slot number
   Value format: root confirmation metadata */
#define FD_ROCKSDB_CFIDX_ROOT                     (7UL)

/* Index column family provides secondary indexing for efficient lookups
   of various blockchain data by alternative keys.
   Key format: varies by index type
   Value format: references to primary data locations */
#define FD_ROCKSDB_CFIDX_INDEX                    (8UL)

/* Data shred column family stores the actual shred data that makes up
   the blockchain blocks. These are the primary building blocks for reconstruction.
   Key format: (slot[8], shred_index[8]) - slot and shred index in big-endian
   Value format: raw shred data including headers and payload */
#define FD_ROCKSDB_CFIDX_DATA_SHRED               (9UL)

/* Code shred column family stores erasure coding shreds used for
   block reconstruction when data shreds are missing.
   Key format: (slot[8], shred_index[8]) - slot and shred index in big-endian
   Value format: raw code shred data including erasure coding information */
#define FD_ROCKSDB_CFIDX_CODE_SHRED               (10UL)

/* Transaction status column family stores the execution results and
   metadata for individual transactions.
   Key format: (signature[64], slot[8]) - transaction signature and slot in big-endian
   Value format: protobuf-encoded TransactionStatusMeta */
#define FD_ROCKSDB_CFIDX_TRANSACTION_STATUS       (11UL)

/* Address signatures column family provides lookup from account addresses
   to transaction signatures that affected those accounts.
   Key format: (pubkey[32], slot[8], u32[4], signature[64]) - complex composite key
   Value format: signature and slot references */
#define FD_ROCKSDB_CFIDX_ADDRESS_SIGNATURES       (12UL)

/* Transaction memos column family stores optional memo data attached
   to transactions for additional context or documentation.
   Key format: varies by memo type and reference
   Value format: raw memo data */
#define FD_ROCKSDB_CFIDX_TRANSACTION_MEMOS        (13UL)

/* Transaction status index column family provides efficient indexing
   for transaction status lookups by various criteria.
   Key format: varies by index type
   Value format: references to transaction status entries */
#define FD_ROCKSDB_CFIDX_TRANSACTION_STATUS_INDEX (14UL)

/* Rewards column family stores validator reward information for each slot,
   including staking rewards and fee distributions.
   Key format: (slot[8]) - big-endian slot number
   Value format: reward distribution data structure */
#define FD_ROCKSDB_CFIDX_REWARDS                  (15UL)

/* Blocktime column family stores timestamp information for when each
   block was produced by the network.
   Key format: (slot[8]) - big-endian slot number
   Value format: Unix timestamp as ulong */
#define FD_ROCKSDB_CFIDX_BLOCKTIME                (16UL)

/* Performance samples column family stores performance metrics and
   benchmarking data for network analysis.
   Key format: varies by sample type and time period
   Value format: performance measurement data */
#define FD_ROCKSDB_CFIDX_PERF_SAMPLES             (17UL)

/* Block height column family provides a mapping from slot numbers to
   block heights in the canonical chain.
   Key format: (slot[8]) - big-endian slot number
   Value format: block height as ulong */
#define FD_ROCKSDB_CFIDX_BLOCK_HEIGHT             (18UL)

/* Optimistic slots column family tracks slots that have been optimistically
   confirmed but may not yet be finalized.
   Key format: (slot[8]) - big-endian slot number
   Value format: optimistic confirmation metadata */
#define FD_ROCKSDB_CFIDX_OPTIMISTIC_SLOTS         (19UL)

/* Merkle root metadata column family stores Merkle tree root information
   for efficient verification of large data structures.
   Key format: varies by tree type and reference
   Value format: Merkle root hashes and metadata
   Note: Usually empty in most deployments */
#define FD_ROCKSDB_CFIDX_MERKLE_ROOT_META         (20UL) /* Usually empty */

/* fd_rocksdb provides a high-level interface to RocksDB for Solana blockchain
   data storage and retrieval. This structure encapsulates all the necessary
   RocksDB handles and configuration for efficient database operations.

   The structure supports both read-only and read-write access modes:
   - Read-only mode: Used for querying existing blockchain data
   - Read-write mode: Used for creating new databases and importing data

   Memory Layout:
   The structure contains handles for the main database and all column families,
   along with various RocksDB configuration objects. All handles are owned by
   this structure and must be properly cleaned up on destruction.

   Thread Safety:
   - The structure itself is not thread-safe for modification
   - Read operations through RocksDB handles are thread-safe
   - Concurrent access should use separate structure instances per thread

   Resource Management:
   - All RocksDB handles are managed by this structure
   - fd_rocksdb_destroy() must be called to prevent resource leaks
   - Column family handles are automatically created/opened during initialization */
struct fd_rocksdb {
  /* Main RocksDB database handle providing access to the underlying database.
     This handle is used for all database operations and is created during
     initialization. NULL indicates the database is not open. */
  rocksdb_t *                     db;

  /* Database name/path string for reference and logging purposes.
     Points to the filesystem path where the database is located.
     This is not owned by the structure and should not be freed. */
  const char *                    db_name;

  /* Array of column family name strings used during database operations.
     Each entry corresponds to a FD_ROCKSDB_CFIDX_* index and contains
     the string name that RocksDB uses to identify the column family.
     These strings are constants and should not be modified or freed. */
  const char *                    cfgs      [ FD_ROCKSDB_CF_CNT ];

  /* Array of column family handles providing access to each specialized
     data store within the database. Each handle corresponds to a specific
     FD_ROCKSDB_CFIDX_* index and is used for targeted read/write operations.
     Handles are created during initialization and must be destroyed on cleanup. */
  rocksdb_column_family_handle_t* cf_handles[ FD_ROCKSDB_CF_CNT ];

  /* Database options handle containing configuration settings for the entire
     database instance. This includes compression settings, cache sizes,
     and other performance-related parameters. Created during initialization. */
  rocksdb_options_t *             opts;

  /* Read options handle containing configuration for read operations such as
     snapshot consistency, caching behavior, and iteration preferences.
     Only present when the database is opened for reading. */
  rocksdb_readoptions_t *         ro;

  /* Write options handle containing configuration for write operations such as
     synchronization behavior, write batching, and durability guarantees.
     Only present when the database is opened for writing (read-write mode). */
  rocksdb_writeoptions_t *        wo;
};
typedef struct fd_rocksdb fd_rocksdb_t;

/* Memory footprint in bytes for fd_rocksdb_t structure.
   This represents the size needed for the structure itself, not including
   any dynamically allocated RocksDB handles or configuration objects. */
#define FD_ROCKSDB_FOOTPRINT sizeof(fd_rocksdb_t)

/* Memory alignment requirement for fd_rocksdb_t structure.
   This ensures proper alignment for efficient memory access and meets
   the requirements of any contained pointer fields. */
#define FD_ROCKSDB_ALIGN (8UL)

/* fd_rocksdb_root_iter provides iteration capabilities over the root column
   family, which contains finalized slots in the blockchain. This iterator
   allows efficient traversal of slots in ascending order.

   The iterator maintains a position within the root column family and can
   advance sequentially while providing slot metadata for each position.
   It uses lazy initialization to create the underlying RocksDB iterator
   only when needed.

   Lifecycle:
   1. Create with fd_rocksdb_root_iter_new()
   2. Join to get typed pointer with fd_rocksdb_root_iter_join()
   3. Seek to starting position with fd_rocksdb_root_iter_seek()
   4. Iterate with fd_rocksdb_root_iter_next()
   5. Clean up with fd_rocksdb_root_iter_destroy()
   6. Leave to release typed pointer with fd_rocksdb_root_iter_leave()

   Performance:
   - Sequential iteration is highly optimized by RocksDB
   - Seeking to arbitrary positions is logarithmic in database size
   - Iterator state is minimal, making it lightweight to create

   Thread Safety:
   - Each iterator instance should be used by only one thread
   - Multiple iterators can safely access the same database concurrently
   - Database handle can be shared between multiple iterator instances */
struct fd_rocksdb_root_iter {
  /* Database handle providing access to the root column family.
     This is a borrowed reference that must remain valid for the
     lifetime of the iterator. The iterator does not own this handle. */
  fd_rocksdb_t *                  db;

  /* RocksDB iterator handle for traversing the root column family.
     This handle is created lazily when first needed and provides
     the underlying iteration capabilities. NULL indicates no iterator
     has been created yet. */
  rocksdb_iterator_t*             iter;
};

typedef struct fd_rocksdb_root_iter fd_rocksdb_root_iter_t;

/* Memory footprint in bytes for fd_rocksdb_root_iter_t structure.
   This represents the size needed for the iterator structure itself,
   not including the underlying RocksDB iterator which is allocated separately. */
#define FD_ROCKSDB_ROOT_ITER_FOOTPRINT sizeof(fd_rocksdb_root_iter_t)

/* Memory alignment requirement for fd_rocksdb_root_iter_t structure.
   This ensures proper alignment for efficient memory access and meets
   the requirements of the contained pointer fields. */
#define FD_ROCKSDB_ROOT_ITER_ALIGN (8UL)

FD_PROTOTYPES_BEGIN

/* fd_rocksdb_root_iter_new initializes a root iterator in the provided
   memory region. This function prepares the memory for use as an iterator
   but does not create the underlying RocksDB iterator yet.

   shiter points to a memory region of at least FD_ROCKSDB_ROOT_ITER_FOOTPRINT
   bytes with FD_ROCKSDB_ROOT_ITER_ALIGN alignment. The memory will be zeroed
   and initialized as an empty iterator.

   Returns the same pointer cast to void* for consistency with other
   constructor functions in the codebase.

   The returned iterator must be joined with fd_rocksdb_root_iter_join()
   before use and cleaned up with fd_rocksdb_root_iter_destroy() when done.

   Time complexity: O(1) - just initializes memory structure. */
void *
fd_rocksdb_root_iter_new( void * shiter );

/* fd_rocksdb_root_iter_join establishes a local handle to a root iterator
   that was previously initialized with fd_rocksdb_root_iter_new().

   iter points to a memory region that was initialized with fd_rocksdb_root_iter_new().

   Returns a typed pointer to the root iterator for use in subsequent operations.
   This function performs type checking and validation of the iterator state.

   Multiple joins are allowed on the same iterator, but each join should be
   balanced with a corresponding leave operation.

   Time complexity: O(1) - just performs pointer casting and validation. */
fd_rocksdb_root_iter_t *
fd_rocksdb_root_iter_join( void * iter );

/* fd_rocksdb_root_iter_leave releases a local handle to a root iterator
   that was obtained with fd_rocksdb_root_iter_join().

   iter points to a root iterator that was returned by fd_rocksdb_root_iter_join().

   Returns a void pointer to the underlying memory for consistency with other
   destructor functions. The typed pointer should not be used after this call.

   This function should be called to balance each fd_rocksdb_root_iter_join().
   It does not destroy the underlying iterator - use fd_rocksdb_root_iter_destroy()
   for that purpose.

   Time complexity: O(1) - just performs pointer operations. */
void *
fd_rocksdb_root_iter_leave( fd_rocksdb_root_iter_t * iter );

/* fd_rocksdb_root_iter_seek positions the iterator at a specific slot
   and retrieves the associated metadata. This function initializes the
   underlying RocksDB iterator if needed and seeks to the specified position.

   iter points to a joined root iterator from fd_rocksdb_root_iter_join().

   db points to an initialized RocksDB database connection that contains
   the root column family to iterate over.

   slot is the target slot number to seek to. The iterator will be positioned
   at this slot if it exists in the database.

   m points to a fd_slot_meta_t structure that will be populated with the
   slot metadata if the seek operation is successful.

   valloc is a memory allocator used for temporary allocations during the
   metadata decoding process.

   Returns:
    0 = success - iterator positioned at slot with metadata retrieved
   -1 = seek failed - slot not found in database
   -2 = seek succeeded but slot mismatch (found different slot)
   -3 = seek succeeded but slot metadata is empty/invalid

   The function creates the underlying RocksDB iterator lazily on first use.
   Subsequent operations can use fd_rocksdb_root_iter_next() to advance.

   Time complexity: O(log n) for the seek operation plus metadata decoding time. */

int
fd_rocksdb_root_iter_seek( fd_rocksdb_root_iter_t * iter,
                           fd_rocksdb_t *           db,
                           ulong                    slot,
                           fd_slot_meta_t *         m,
                           fd_valloc_t              valloc );

/* fd_rocksdb_root_iter_next advances the iterator to the next slot
   and retrieves the associated metadata. This function moves the iterator
   forward in the root column family and decodes the metadata for the new position.

   iter points to a joined root iterator that has been positioned with
   fd_rocksdb_root_iter_seek().

   m points to a fd_slot_meta_t structure that will be populated with the
   metadata from the next slot on success.

   valloc is a memory allocator used for temporary allocations during the
   metadata decoding process.

   Returns:
    0 = success - iterator advanced with metadata retrieved
   -1 = not properly initialized - seek must be called first
   -2 = invalid starting iterator position
   -3 = next operation reached end of data
   -4 = next succeeded but slot metadata is empty/invalid

   The iterator advances to the next slot in ascending numerical order.
   Slots are stored in big-endian format ensuring proper lexicographic ordering.

   Time complexity: O(1) for advancement plus metadata decoding time. */

int
fd_rocksdb_root_iter_next( fd_rocksdb_root_iter_t * iter,
                           fd_slot_meta_t *         m,
                           fd_valloc_t              valloc );

/* fd_rocksdb_root_iter_slot retrieves the slot number at the current
   iterator position without advancing the iterator or retrieving metadata.

   self points to a joined root iterator that has been positioned with
   fd_rocksdb_root_iter_seek().

   slot points to a ulong variable that will receive the current slot number.

   Returns:
    0 = success - slot number retrieved
   -1 = iterator not properly initialized
   -2 = iterator not positioned at valid entry

   This function is useful for determining the current position without the
   overhead of metadata retrieval and decoding.

   Time complexity: O(1) - just extracts key from current position. */

int
fd_rocksdb_root_iter_slot( fd_rocksdb_root_iter_t * self,
                           ulong *                  slot );

/* fd_rocksdb_root_iter_destroy properly cleans up all resources associated
   with a root iterator. This function releases the underlying RocksDB iterator
   and resets the iterator state.

   iter points to a joined root iterator that was created with the root
   iterator lifecycle functions.

   This function must be called for every iterator to prevent resource leaks.
   After calling this function, the iterator should not be used for any operations
   until it is reinitialized.

   The function is safe to call multiple times or on partially initialized
   iterators, as it checks for NULL pointers before cleanup.

   Time complexity: O(1) - just releases iterator handle and resets state. */

void
fd_rocksdb_root_iter_destroy( fd_rocksdb_root_iter_t * iter );

/* fd_rocksdb_init opens an existing RocksDB database for read-only access.
   This function is used to connect to an existing Solana ledger database
   without the ability to modify the data.

   db points to an uninitialized fd_rocksdb_t structure that will be configured
   on success. The structure will be zeroed and populated with database handles
   and configuration objects.

   db_name points to a null-terminated string containing the filesystem path
   to the RocksDB database directory. This must point directly to the RocksDB
   directory (not the parent ledger directory like solana ledger-tool uses).

   Returns NULL on success, or a pointer to a null-terminated error string
   on failure. The error string is allocated by RocksDB and must be freed
   by the caller using free().

   Common failure reasons:
   - Database directory does not exist or is not accessible
   - Database is corrupted or incompatible
   - Required column families are missing
   - Insufficient memory for database handles
   - Permission denied accessing database files

   The database is opened with all required column families in read-only mode.
   Write operations will fail if attempted. Call fd_rocksdb_destroy() to clean
   up when done.

   Time complexity: O(1) with respect to database size, but may involve
   significant I/O for metadata loading. */

char *
fd_rocksdb_init( fd_rocksdb_t * db,
                 char const *   db_name );

/* fd_rocksdb_new creates a new RocksDB database or opens an existing one
   for read-write access. This function provides full database capabilities
   including the ability to create, modify, and delete data.

   db points to an uninitialized fd_rocksdb_t structure that will be configured
   on success. The structure will be zeroed and populated with database handles
   and configuration objects.

   db_name points to a null-terminated string containing the full filesystem
   path where the database directory will be created. If the database already
   exists, it will be opened for read-write access.

   The function performs the following initialization:
   - Creates database directory if it doesn't exist
   - Opens database with create_if_missing enabled
   - Creates all required column families
   - Configures LZ4 compression for optimal performance
   - Sets up write options for database modifications

   This function will terminate the program with FD_LOG_ERR if database
   creation fails, as this is considered a fatal error that prevents
   normal operation.

   Time complexity: O(1) with respect to database size, but may involve
   significant I/O for directory creation and metadata setup. */

void
fd_rocksdb_new( fd_rocksdb_t * db,
                char const *   db_name );

/* fd_rocksdb_destroy properly releases all resources associated with a
   RocksDB database handle. This function must be called for every database
   opened with fd_rocksdb_init() or fd_rocksdb_new() to prevent resource leaks.

   db points to an initialized fd_rocksdb_t structure that was configured
   by fd_rocksdb_init() or fd_rocksdb_new(). After this function returns,
   the structure will be in an undefined state.

   The function performs cleanup in the correct order:
   1. Destroys all column family handles
   2. Releases read options (if present)  
   3. Releases database options
   4. Closes main database handle
   5. Releases write options (if present)

   This function is safe to call on partially initialized structures or
   structures that have already been destroyed, as it checks for NULL
   pointers before cleanup operations.

   After calling this function, the database structure must not be used
   for any operations without re-initialization.

   Time complexity: O(1) - just releases handles and frees memory. */

void
fd_rocksdb_destroy( fd_rocksdb_t * db );

/* fd_rocksdb_last_slot retrieves the highest (most recent) slot number from
   the root column family. This function is used to determine the latest
   finalized slot in the blockchain.

   db points to an initialized RocksDB database that was opened with
   fd_rocksdb_init() or fd_rocksdb_new().

   err points to a char pointer that will be set to a constant error string
   if the operation fails. The caller should check this value on return.
   If non-NULL, it points to a static string that does not need to be freed.

   Returns the highest slot number found in the root column family on success.
   The slot number is converted from the big-endian storage format to host
   byte order before returning.

   Returns 0 on failure, with *err set to an error message. Common failure
   reasons include:
   - Database connection is invalid or closed
   - Root column family is empty (no finalized slots)
   - Database corruption or I/O errors

   The function uses efficient seeking to the last entry in the root column
   family. Since slot numbers are stored in big-endian format, the
   lexicographically last entry corresponds to the numerically highest slot.

   Time complexity: O(log n) where n is the number of finalized slots. */

ulong
fd_rocksdb_last_slot( fd_rocksdb_t * db,
                      char **        err );

/* fd_rocksdb_first_slot retrieves the lowest (earliest) slot number from
   the root column family. This function is used to determine the oldest
   finalized slot still available in the database.

   db points to an initialized RocksDB database that was opened with
   fd_rocksdb_init() or fd_rocksdb_new().

   err points to a char pointer that will be set to a constant error string
   if the operation fails. The caller should check this value on return.
   If non-NULL, it points to a static string that does not need to be freed.

   Returns the lowest slot number found in the root column family on success.
   The slot number is converted from the big-endian storage format to host
   byte order before returning.

   Returns 0 on failure, with *err set to an error message. Common failure
   reasons include:
   - Database connection is invalid or closed
   - Root column family is empty (no finalized slots)
   - Database corruption or I/O errors

   The function uses efficient seeking to the first entry in the root column
   family. Since slot numbers are stored in big-endian format, the
   lexicographically first entry corresponds to the numerically smallest slot.

   Time complexity: O(log n) where n is the number of finalized slots. */

ulong
fd_rocksdb_first_slot( fd_rocksdb_t * db,
                       char **        err );

/* fd_rocksdb_find_last_slot finds the highest slot number by exhaustively
   scanning all entries in the root column family. This function provides
   an alternative to fd_rocksdb_last_slot() that verifies the result through
   complete enumeration.

   db points to an initialized RocksDB database that was opened with
   fd_rocksdb_init() or fd_rocksdb_new().

   err points to a char pointer that will be set to a constant error string
   if the operation fails. The caller should check this value on return.
   If non-NULL, it points to a static string that does not need to be freed.

   Returns the highest slot number found by scanning all entries in the root
   column family. The slot number is converted from big-endian storage format
   to host byte order before returning.

   Returns 0 on failure, with *err set to an error message. Common failure
   reasons include:
   - Database connection is invalid or closed
   - Root column family is empty (no finalized slots)
   - Database corruption or I/O errors

   This function is useful when database ordering might be unreliable or when
   verification of the maximum slot is needed. However, it is less efficient
   than fd_rocksdb_last_slot() for large databases as it must examine every entry.

   Time complexity: O(n) where n is the number of finalized slots. */

ulong
fd_rocksdb_find_last_slot( fd_rocksdb_t * db,
                           char **        err );

/* fd_rocksdb_get_meta retrieves and decodes slot metadata from the metadata
   column family. Slot metadata contains critical information about a slot's
   status, parent relationships, confirmation state, and block structure.

   db points to an initialized RocksDB database that was opened with
   fd_rocksdb_init() or fd_rocksdb_new().

   slot is the slot number for which to retrieve metadata. The slot number
   will be converted to big-endian format for database key lookup.

   m points to a fd_slot_meta_t structure that will be populated with the
   decoded metadata on success. The caller is responsible for ensuring
   this structure is valid and properly aligned.

   valloc is a memory allocator used for temporary allocations during the
   bincode decoding process. The allocator should support the alignment
   requirements of the metadata structure.

   Returns:
    0 = success - metadata retrieved and decoded successfully
   -1 = slot not found - no metadata exists for the specified slot
   -2 = database error - error retrieving data from database

   The function performs the following operations:
   1. Converts slot number to big-endian format for database key
   2. Queries the metadata column family
   3. Decodes the bincode-serialized metadata structure
   4. Copies the decoded metadata to the output structure
   5. Cleans up temporary allocations

   The metadata is stored in serialized bincode format and must be decoded
   before use. This process validates the format and ensures data integrity.

   Time complexity: O(log n) for database lookup plus O(metadata_size) for decoding. */

int
fd_rocksdb_get_meta( fd_rocksdb_t *   db,
                     ulong            slot,
                     fd_slot_meta_t * m,
                     fd_valloc_t      valloc );

/* fd_rocksdb_get_txn_status_raw queries raw transaction status metadata
   from the transaction status column family. This function retrieves the
   execution results and metadata for a specific transaction.

   self points to an initialized RocksDB database that was opened with
   fd_rocksdb_init() or fd_rocksdb_new().

   slot is the slot number of the block that contains the transaction.
   This is used as part of the composite key for lookup.

   sig points to the first 64-byte signature of the transaction. This serves
   as the primary identifier for the transaction within the slot.

   psz points to a ulong variable that will receive the size of the returned
   data on success.

   Returns a pointer to a malloc-allocated buffer containing the raw serialized
   transaction status on success. The caller must free() this buffer when done.
   The size of the data is returned in *psz.

   Returns NULL on failure. Common failure reasons include:
   - Transaction not found in the database
   - Database I/O error
   - Invalid signature or slot parameters

   The returned data is Protobuf-encoded TransactionStatusMeta. Use the
   fd_solblock nanopb API to deserialize the value into a structured format.

   The function constructs a composite key consisting of:
   - Bytes 0-63: 64-byte transaction signature
   - Bytes 64-71: 8-byte slot number in big-endian format

   Time complexity: O(log n) where n is the number of transaction status entries. */

void *
fd_rocksdb_get_txn_status_raw( fd_rocksdb_t * self,
                               ulong          slot,
                               void const *   sig,
                               ulong *        psz );

/* fd_rocksdb_copy_over_slot_indexed_range copies data from one RocksDB
   database to another for a specific column family and slot range. This
   function is used for data migration, backup operations, and selective
   data transfer between databases.

   src points to the source RocksDB database from which data will be copied.
   The database must be open and readable.

   dst points to the destination RocksDB database to which data will be copied.
   The database must be open and writable with the target column family available.

   cf_idx is the column family index (one of the FD_ROCKSDB_CFIDX_* constants)
   that specifies which column family to copy. Only column families with
   slot-indexed keys are supported.

   start_slot is the first slot number to include in the copy operation (inclusive).

   end_slot is the last slot number to include in the copy operation (inclusive).

   Returns 0 on success, -1 on failure.

   The function skips column families that are not slot-indexed:
   - FD_ROCKSDB_CFIDX_TRANSACTION_MEMOS (varies by memo type)
   - FD_ROCKSDB_CFIDX_TRANSACTION_STATUS (signature-indexed)
   - FD_ROCKSDB_CFIDX_ADDRESS_SIGNATURES (address-indexed)

   For supported column families, the function iterates through entries,
   extracts slot numbers from keys, and copies entries within the specified
   slot range to the destination database.

   Time complexity: O(n * log m) where n is the number of entries in the
   range and m is the size of the destination database. */

int
fd_rocksdb_copy_over_slot_indexed_range( fd_rocksdb_t * src,
                                         fd_rocksdb_t * dst,
                                         ulong          cf_idx,
                                         ulong          start_slot,
                                         ulong          end_slot );

/* fd_rocksdb_copy_over_txn_status copies a single transaction status entry
   from one RocksDB database to another. This function constructs the
   appropriate composite key and transfers the transaction status data.

   src points to the source RocksDB database containing the transaction status.

   dst points to the destination RocksDB database where the status will be copied.

   slot is the slot number of the block containing the transaction.

   sig points to the 64-byte transaction signature that identifies the transaction.

   The function constructs the composite key (signature[64], slot[8]) and
   retrieves the transaction status from the source database, then inserts
   it into the destination database using the same key.

   Time complexity: O(log n) for each database operation. */

void
fd_rocksdb_copy_over_txn_status( fd_rocksdb_t * src,
                                 fd_rocksdb_t * dst,
                                 ulong          slot,
                                 void const *   sig );

/* fd_rocksdb_insert_entry inserts a key-value pair into a specific column
   family in the database. This function provides a generic interface for
   writing blockchain data to any column family.

   db points to an initialized RocksDB database that was opened with
   fd_rocksdb_new() for write access.

   cf_idx is the column family index (one of the FD_ROCKSDB_CFIDX_* constants)
   that specifies the target column family for the insertion.

   key points to the key data to be inserted. The key format must match
   the expected format for the specified column family.

   key_len is the length of the key data in bytes.

   value points to the value data to be inserted. The value format depends
   on the column family specifications.

   value_len is the length of the value data in bytes.

   Returns 0 on success, -1 on failure.

   Common failure reasons include:
   - Database opened in read-only mode
   - Insufficient disk space
   - Database corruption
   - Invalid column family index
   - Write options configuration issues

   The function uses the database's write options to perform the insertion
   with appropriate durability and performance characteristics.

   Time complexity: O(log n) where n is the number of entries in the target
   column family. */

int
fd_rocksdb_insert_entry( fd_rocksdb_t * db,
                         ulong          cf_idx,
                         const char *   key,
                         ulong          key_len,
                         const char *   value,
                         ulong          value_len );

/* fd_rocksdb_import_block_blockstore imports a complete block from RocksDB
   into a blockstore by reconstructing it from stored shreds. This function
   is the primary interface for loading blockchain data from persistent
   storage into memory for processing.

   db points to an initialized RocksDB database containing the block shreds
   and associated metadata.

   m points to the slot metadata for the block to be imported. This metadata
   contains information about the expected number of shreds and block structure.

   blockstore points to the destination blockstore where the reconstructed
   block will be stored for access and processing.

   hash_override points to a 32-byte bank hash to use instead of the stored
   hash, or NULL to use the hash from the database. This is useful for
   testing or when overriding stored hash values.

   valloc is a memory allocator used for temporary allocations during the
   import and reconstruction process.

   Returns 0 on success, -1 on failure.

   The function performs the following major operations:
   1. Retrieves all shreds for the slot from the data_shred column family
   2. Validates shred completeness and order
   3. Inserts shreds into the blockstore
   4. Triggers deshredding to reconstruct the complete block
   5. Retrieves additional metadata (timestamps, block height, bank hash)
   6. Updates blockstore state with the reconstructed block

   Time complexity: O(n * log m) where n is the number of shreds and m is
   the size of the blockstore. */

int
fd_rocksdb_import_block_blockstore( fd_rocksdb_t *    db,
                                    fd_slot_meta_t *  m,
                                    fd_blockstore_t * blockstore,
                                    const uchar *     hash_override,
                                    fd_valloc_t       valloc );

/* fd_rocksdb_import_block_shredcap exports a block from RocksDB to the
   shredcap file format. This function converts blockchain data from the
   database into a specialized binary format for analysis and archival.

   db points to an initialized RocksDB database containing the block shreds
   and metadata to be exported.

   metadata points to the slot metadata for the block to be exported.

   ostream points to a buffered output stream where the shredcap-formatted
   block data will be written.

   bank_hash_ostream points to a separate buffered output stream where
   bank hash information will be written in a parallel format.

   valloc is a memory allocator used for temporary allocations during the
   export process.

   Returns 0 on success, -1 on failure.

   The shredcap format includes:
   - Slot header with metadata and payload size
   - Individual shred data with headers and alignment
   - Slot footer for validation
   - Bank hash entries in separate stream

   The function maintains exact shred structure while adding minimal metadata
   overhead, making it suitable for external analysis tools and archival storage.

   Time complexity: O(n) where n is the number of shreds in the slot. */

int
fd_rocksdb_import_block_shredcap( fd_rocksdb_t *             db,
                                  fd_slot_meta_t *           metadata,
                                  fd_io_buffered_ostream_t * ostream,
                                  fd_io_buffered_ostream_t * bank_hash_ostream,
                                  fd_valloc_t                valloc );

/* fd_blockstore_block_allocs_remove safely removes all memory allocations
   associated with a block from the blockstore. This function is used to
   free memory when a block is no longer needed, typically during cleanup
   or when blocks are being evicted from memory.

   blockstore points to the blockstore containing the block to be removed.

   slot is the slot number of the block whose allocations should be removed.

   The function performs safety checks before removal:
   - Verifies the block exists in the blockstore
   - Ensures no replay operation is in progress for the block
   - Uses proper memory barriers for thread safety

   The function removes all allocations associated with the block:
   - Microblock metadata arrays
   - Main block data and structure
   - Shred and batch metadata

   This function is safe to call even if the slot doesn't exist or has
   already been removed, as it handles these cases gracefully.

   Time complexity: O(log n) for block map lookup, O(1) for cleanup. */
void
fd_blockstore_block_allocs_remove( fd_blockstore_t * blockstore, ulong slot );

/* fd_blockstore_block_query retrieves a block from the blockstore for
   the specified slot. This function provides read access to reconstructed
   blocks that have been deshredded and are available in memory.

   blockstore points to the blockstore to query for the block.

   slot is the slot number of the block to retrieve.

   Returns a pointer to the fd_block_t structure for the specified slot
   on success, or NULL if the block is not available in the blockstore.

   The returned pointer is valid until the block is removed from the
   blockstore. The caller should not modify the block structure or its
   referenced data.

   Common reasons for NULL return:
   - Block has not been deshredded yet
   - Block was removed due to memory pressure
   - Slot does not exist or is invalid
   - Block map lookup failed

   Thread Safety:
   The function uses non-blocking concurrent access to the block map.
   It performs a valid concurrent read of the block_gaddr field and
   handles retry scenarios automatically. The returned block structure
   itself requires read/write coordination for modifications but is
   safe for concurrent reads.

   Performance:
   The function uses optimized workspace address translation and
   lock-free map operations for minimal overhead. Multiple threads
   can safely query blocks concurrently.

   Time complexity: O(log n) where n is the number of blocks in the blockstore. */
static inline fd_block_t *
fd_blockstore_block_query(fd_blockstore_t *blockstore, ulong slot){
  /* Initialize variables for the non-blocking query loop */
  int err = FD_MAP_ERR_AGAIN;
  ulong query_block_gaddr = 0;
  
  /* Retry loop to handle concurrent access to the block map */
  while( err == FD_MAP_ERR_AGAIN ){
    /* Prepare query structure for block map lookup */
    fd_block_map_query_t quer[1] = { 0 };
    
    /* Attempt non-blocking query of the block map */
    err = fd_block_map_query_try( blockstore->block_map, &slot, NULL, quer, 0 );
    
    /* Extract block info from the query result */
    fd_block_info_t * query = fd_block_map_query_element( quer );
    
    /* Handle key not found - block doesn't exist */
    if ( err == FD_MAP_ERR_KEY ) return NULL;
    
    /* Continue retry loop if another operation is in progress */
    if ( FD_UNLIKELY( err == FD_MAP_ERR_AGAIN ) ) continue;
    
    /* Check if block has been deshredded (block_gaddr != 0 indicates reconstructed block) */
    if( FD_UNLIKELY( query->block_gaddr == 0 ) ) return NULL;
    
    /* Store the block address for later conversion to local address */
    query_block_gaddr = query->block_gaddr;
    
    /* Test the query to ensure consistency and complete the operation */
    err = fd_block_map_query_test( quer );
  }
  
  /* Convert the global address to a local address and return the block pointer */
  return fd_wksp_laddr_fast( fd_blockstore_wksp( blockstore ), query_block_gaddr );
}

FD_PROTOTYPES_END

#endif

#endif // HEADER_fd_src_flamenco_runtime_fd_rocksdb_h
