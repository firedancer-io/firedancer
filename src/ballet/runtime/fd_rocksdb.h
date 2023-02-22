#ifndef HEADER_fd_src_ballet_runtime_fd_rocksdb_h
#define HEADER_fd_src_ballet_runtime_fd_rocksdb_h

#if FD_HAS_ROCKSDB

#include "fd_banks_solana.h"
#include "../shred/fd_shred.h"
#include "../block/fd_microblock.h"
#include <rocksdb/c.h>

/* Solana rocksdb client */

/* slot meta data object found in the rocksdb */
struct fd_slot_meta {
  ulong  slot;
  ulong  consumed;
  ulong  received;
  ulong  first_shred_timestamp;
  ulong  last_index;
  ulong  parent_slot;
  ulong  num_next_slots;
  ulong *next_slots;
  uchar  is_connected;
  ulong  num_entry_end_indexes;
  uint   entry_end_indexes[64];
};
typedef struct fd_slot_meta fd_slot_meta_t;
#define FD_SLOT_META_FOOTPRINT sizeof(fd_slot_meta_t)
#define FD_SLOT_META_ALIGN (8UL)

/* all the micro blocks found in a slot */
struct fd_slot_blocks {
  uint block_cnt;
  uchar *first_blob;
  uchar *last_blob;
  uchar buffer[];
};
typedef struct fd_slot_blocks fd_slot_blocks_t;
#define FD_SLOT_BLOCKS_FOOTPRINT(x) (sizeof(fd_slot_blocks_t) + (x))
#define FD_SLOT_BLOCKS_ALIGN (8UL)

#define FD_BLOB_DATA_START (fd_ulong_align_up( 12UL, FD_MICROBLOCK_ALIGN ))

/* rocksdb client */
struct fd_rocksdb {
  rocksdb_t *                     db;
  const char *                    db_name;
  const char *                    cfgs[4];
  const rocksdb_options_t *       cf_options[4];
  rocksdb_column_family_handle_t* column_family_handles[4];
  rocksdb_options_t *             opts;
  rocksdb_readoptions_t *         ro;
};
typedef struct fd_rocksdb fd_rocksdb_t;
#define FD_ROCKSDB_FOOTPRINT sizeof(fd_rocksdb_t)
#define FD_ROCKSDB_ALIGN (8UL)

FD_PROTOTYPES_BEGIN

/* fd_slot_blocks_new

   Initialize the block
*/
void fd_slot_blocks_new(fd_slot_blocks_t *);

/* fd_slot_blocks_destroy

   free the internal data structures
*/
void fd_slot_blocks_destroy(fd_slot_blocks_t *, fd_free_fun_t freef,  void* freef_arg);

/* fd_rocksdb_init: Returns a pointer to a description of the error on failure

  The provided db_name needs to point at the actual rocksdb directory
  as apposed to the directory above (like the solana ledger-tool)
*/
char * fd_rocksdb_init(
    fd_rocksdb_t *db, 
    const char *db_name
);

/* fd_rocksdb_destroy

   Frees up the internal data structures
*/
void fd_rocksdb_destroy(
    fd_rocksdb_t *db
);

/* fd_rocksdb_last_slot:  Returns the last slot in the db

   This uses the root column to discover the slot of the last root in
   the db.  If there is an error, this sets *err to a constant string
   describing the error.  There is no need to free that string.
*/
ulong fd_rocksdb_last_slot(
    fd_rocksdb_t *db, 
    char **err
);

/* fd_rocksdb_first_slot:  Returns the first slot in the db

   This uses the root column to discover the slot of the first root in
   the db.  If there is an error, this sets *err to a constant string
   describing the error.  There is no need to free that string.
*/
ulong fd_rocksdb_first_slot(
    fd_rocksdb_t *db, 
    char **err
);

/* fd_rocksdb_get_meta

   Retrieves the meta structure associated with the supplied slot.  If
   there is an error, *err is set to a string describing the error.
   It is expected that you should free() the error once done with it
*/
void fd_rocksdb_get_meta(
    fd_rocksdb_t *db, 
    ulong slot,
    fd_slot_meta_t *m,
    fd_alloc_fun_t allocf, 
    void* allocf_arg,
    char **err
);

/* fd_slot_meta_decode

   Internal function normally only used by fd_rocksdb_get_meta to
   decode raw data into a fd_slot_meta_t structure
*/
void fd_slot_meta_decode(
    fd_slot_meta_t* self,
    void const** data, 
    void const* dataend,
    fd_alloc_fun_t allocf, 
    void* allocf_arg
);

void fd_slot_meta_destroy(
    fd_slot_meta_t* self,
    fd_free_fun_t freef, 
    void* freef_arg
);

/* fd_rocksdb_get_microblocks
*/
fd_slot_blocks_t * fd_rocksdb_get_microblocks(fd_rocksdb_t *db, 
  fd_slot_meta_t *m,
  fd_alloc_fun_t allocf, 
  void* allocf_arg
);

FD_PROTOTYPES_END

#endif

#endif // HEADER_fd_src_ballet_runtime_fd_rocksdb_h
