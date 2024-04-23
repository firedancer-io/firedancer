#ifndef HEADER_fd_src_app_fdshredcap_fdshredcap_h
#define HEADER_fd_src_app_fdshredcap_fdshredcap_h

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include "../../flamenco/types/fd_types.h"
#include "../../flamenco/fd_flamenco.h"
#include "../../flamenco/runtime/fd_rocksdb.h"
#include "../../flamenco/runtime/fd_blockstore.h"
#include "../../util/fd_util.h"

/* fd_shredcap is a capture format for solana ledgers. It stores all shreds for
   a given block together. It outputs configurably sized files that can be used
   for testing and replay. fd_shredcap allows for replay for a given range of
   blocks.

   Each ingest command will generate a directory of file(s) that each contain a 
   block range as described above. In addition to this, an manifest file will be
   generated which will allow for fast lookup for file ranges. The format for
   the manifest and for each shredcap capture file is as follows:

   |--fd_shredcap manifest-----------|
   |**** Header *********************|
   | Magic                           |
   | Start/End Slot                  |
   | Number of Files                 |
   |---------------------------------|
   |**** Entry **********************|
   | File Start/End Slot             |
   | Relative Path                   |
   |*********************************|
   |////// Each File in Directory ///|
   |---------------------------------|
   |**** Footer *********************|
   | Copy of Header                  |
   |---------------------------------|


   |--fd_shredcap capture------------|
   |**** File Header ****************|
   | Magic + Version + Header Size   |
   | Padding                         |
   |---------------------------------|
   |**** Slot Header ****************|
   | Magic + Header/Payload Sizes    |
   | Slot Related Metadata           |
   | Padding                         |
   |---------------------------------|
   |////// Start of Slot Payload ////| 
   |---------------------------------|
   |**** Shred Header ***************|
   | Shred Size                      |
   | Padding                         |
   |**** Shred Data *****************|
   | Padding                         |
   |---------------------------------|
   |////// All Shreds In Slot ///////|
   |---------------------------------|
   |////// End of Slot Payload //////| 
   |---------------------------------|
   |**** Slot Footer ****************|
   | Magic + Payload Size            |
   |---------------------------------|
   |///// More Slots ////////////////|
   |---------------------------------|
   |**** File Footer ****************|
   | Copy of File Header             |
   |---------------------------------|

   Shredcap also supports other column families available in rocksdb. Notably,
   the bank hashes are used during replay. This can be easily extended to
   support other column families. The general format is as follows:

   |--fd_shredcap bank hash ---------|
   |**** Header *********************|
   | Magic                           |
   | Start/End Slot                  |
   |---------------------------------|
   |**** Entry **********************|
   | Slot                            |
   | Bank Hash                       |
   |*********************************|
   |////// Each File in Directory ///|
   |---------------------------------|
   |**** Footer *********************|
   | Copy of Header                  |
   |---------------------------------|
   */

#define FD_SHREDCAP_ALIGN (16UL)
#define FD_SHREDCAP_CAPTURE_FILE_NAME_LENGTH (48UL)
#define FD_SHREDCAP_CAPTURE_PATH_NAME_LENGTH (256UL)

/****************************** Manifest **************************************/
#define FD_SHREDCAP_MANIFEST_MAGIC   (0x4370437043704370)
#define FD_SHREDCAP_MANIFEST_VERSION (1UL)

#define FD_SHREDCAP_MANIFEST_CAP_FOOTPRINT_V1 (32UL)
#define FD_SHREDCAP_MANIFEST_HDR_FOOTPRINT    (FD_SHREDCAP_MANIFEST_CAP_FOOTPRINT_V1)
#define FD_SHREDCAP_MANIFEST_FTR_FOOTPRINT    (FD_SHREDCAP_MANIFEST_CAP_FOOTPRINT_V1)
struct __attribute__((packed,aligned(FD_SHREDCAP_ALIGN))) fd_shredcap_manifest_cap_V1 {
  ulong magic;
  uint  version;
  uint  num_files;
  ulong start_slot;
  ulong end_slot;
};
typedef struct fd_shredcap_manifest_cap_V1 fd_shredcap_manifest_hdr_t;
typedef struct fd_shredcap_manifest_cap_V1 fd_shredcap_manifest_ftr_t;

#define FD_SHREDCAP_MANIFEST_ENTRY_FOOTPRINT_V1 (64UL)
#define FD_SHREDCAP_MANIFEST_ENTRY_FOOTPRINT    (FD_SHREDCAP_MANIFEST_ENTRY_FOOTPRINT_V1)
struct __attribute__((packed,aligned(FD_SHREDCAP_ALIGN))) fd_shredcap_manifest_entry_V1 {
  ulong start_slot;
  ulong end_slot;
  char  path[FD_SHREDCAP_CAPTURE_FILE_NAME_LENGTH]; /* Relative Path */
};
typedef struct fd_shredcap_manifest_entry_V1 fd_shredcap_manifest_entry_t;

/****************************** File Header/Footer ****************************/
#define FD_SHREDCAP_FILE_MAGIC   (0x1738173817381738UL)
#define FD_SHREDCAP_FILE_VERSION (1UL)

#define FD_SHREDCAP_FILE_CAP_FOOTPRINT_V1 (48UL)
#define FD_SHREDCAP_FILE_HDR_FOOTPRINT    (FD_SHREDCAP_FILE_CAP_FOOTPRINT_V1)
#define FD_SHREDCAP_FILE_FTR_FOOTPRINT    (FD_SHREDCAP_FILE_CAP_FOOTPRINT_V1)
struct __attribute__((packed,aligned(FD_SHREDCAP_ALIGN))) fd_shredcap_file_cap_V1 {
  ulong magic;
  uint  version;
  ulong start_slot;
  ulong end_slot;
  ulong num_blocks;
};
typedef struct fd_shredcap_file_cap_V1 fd_shredcap_file_hdr_t;
typedef struct fd_shredcap_file_cap_V1 fd_shredcap_file_ftr_t;

/***************************** Slot Header/Footer *****************************/
#define FD_SHREDCAP_SLOT_HDR_MAGIC   (0x8108108108108108UL)
#define FD_SHREDCAP_SLOT_HDR_VERSION (1UL)

#define FD_SHREDCAP_SLOT_HDR_FOOTPRINT_V1 (80UL)
#define FD_SHREDCAP_SLOT_HDR_FOOTPRINT    (FD_SHREDCAP_SLOT_HDR_FOOTPRINT_V1)

#define FD_SHREDCAP_SLOT_HDR_PAYLOAD_SZ_OFFSET_V1 (12UL)
#define FD_SHREDCAP_SLOT_HDR_PAYLOAD_SZ_OFFSET    (FD_SHREDCAP_SLOT_HDR_PAYLOAD_SZ_OFFSET_V1)
struct __attribute__((packed,aligned(FD_SHREDCAP_ALIGN))) fd_shredcap_slot_hdr_V1 {
  ulong magic; 
  uint  version;
  ulong payload_sz;
  ulong slot;
  ulong consumed;
  ulong received;
  ulong first_shred_timestamp;
  ulong last_index;
  ulong parent_slot;
};
typedef struct fd_shredcap_slot_hdr_V1 fd_shredcap_slot_hdr_t;

#define FD_SHREDCAP_SLOT_FTR_MAGIC (7939793979397939UL)

#define FD_SHREDCAP_SLOT_FTR_FOOTPRINT_V1 (16UL)
#define FD_SHREDCAP_SLOT_FTR_FOOTPRINT    (FD_SHREDCAP_SLOT_FTR_FOOTPRINT_V1)
struct __attribute((packed,aligned(FD_SHREDCAP_ALIGN))) fd_shredcap_slot_ftr_V1 {
  ulong magic;
  ulong payload_sz;
};
typedef struct fd_shredcap_slot_ftr_V1 fd_shredcap_slot_ftr_t;

/***************************** Shreds *****************************************/
/* 1228 is the max shred sz and the footprint for the shred header is 8. For the 
   total shred to have an alignment of FD_SHREDCAP_ALIGN the max footprint must
   be align_up( 1228 + 8, 16 ) == 1248 */
#define FD_SHREDCAP_SHRED_MAX (1248U)

#define FD_SHREDCAP_SHRED_HDR_FOOTPRINT_V1 (8U)
#define FD_SHREDCAP_SHRED_HDR_FOOTPRINT    (FD_SHREDCAP_SHRED_HDR_FOOTPRINT_V1)
struct __attribute__((packed,aligned(FD_SHREDCAP_ALIGN))) fd_shredcap_shred_hdr_V1
{
  ushort hdr_sz; /* == FD_SHREDCAP_SHRED_HDR_FOOTPRINT */
  ushort shred_sz; /* Size of shred */
  uint   shred_boundary_sz; /* Size of padded shred without header */
  /* This struct will be followed by a dynamically sized shred */
};
typedef struct fd_shredcap_shred_hdr_V1 fd_shredcap_shred_hdr_t;

/***************************** Bank Hash **************************************/
#define FD_SHREDCAP_BANK_HASH_MAGIC   (2001200120012001UL)
#define FD_SHREDCAP_BANK_HASH_VERSION (1UL)

#define FD_SHREDCAP_BANK_HASH_CAP_FOOTPRINT_V1 (48UL)
#define FD_SHREDCAP_BANK_HASH_HDR_FOOTPRINT (FD_SHREDCAP_BANK_HASH_CAP_FOOTPRINT_V1)
#define FD_SHREDCAP_BANK_HASH_FTR_FOOTPRINT (FD_SHREDCAP_BANK_HASH_CAP_FOOTPRINT_V1)
struct __attribute__((packed,aligned(FD_SHREDCAP_ALIGN))) fd_shredcap_bank_hash_cap_V1
{
  ulong magic;
  uint  version;
  ulong start_slot;
  ulong end_slot;
  ulong num_blocks;
};
typedef struct fd_shredcap_bank_hash_cap_V1 fd_shredcap_bank_hash_hdr_t;
typedef struct fd_shredcap_bank_hash_cap_V1 fd_shredcap_bank_hash_ftr_t;

#define FD_SHREDCAP_BANK_HASH_ENTRY_FOOTPRINT_V1 (48UL)
#define FD_SHREDCAP_BANK_HASH_ENTRY_FOOTPRINT (FD_SHREDCAP_BANK_HASH_ENTRY_FOOTPRINT_V1)
struct __attribute__((packed,aligned(FD_SHREDCAP_ALIGN))) fd_shredcap_bank_hash_entry_V1
{
  ulong     slot;
  fd_hash_t bank_hash;
};
typedef struct fd_shredcap_bank_hash_entry_V1 fd_shredcap_bank_hash_entry_t; 

/******************************************************************************/

/* To account for the max possible size it could take to write a block, the case 
   where there there are the max number of shreds per block in addition to each 
   shred being as large as possible. The block header and footer also need to be
   added to this footprint. */
#define FD_SHREDCAP_MAX_BLOCK_STORAGE_FOOTPRINT (((1 << 15UL) * FD_SHREDCAP_SHRED_MAX) + \
                                                   FD_SHREDCAP_SLOT_HDR_FOOTPRINT + \
                                                   FD_SHREDCAP_SLOT_FTR_FOOTPRINT)

/* Take in rocksdb path and output shredcap capture to specified capture_dir.
   The resulting directory will include a manifest, bank_hash file, and the 
   set of capture files  */
void fd_shredcap_ingest_rocksdb_to_capture( const char * rocksdb_dir,
                                              const char * capture_dir,
                                              ulong        max_file_sz,
                                              ulong        start_slot,
                                              ulong        end_slot );

/* Iterate through manifest and seek out number of files in capture as well as
   the start/end file indicies based on the slot range [start_slot, end_slot]. */
void fd_shredcap_manifest_seek_range( const char * capture_dir,
                                      char * manifest_buf,
                                      ulong start_slot,
                                      ulong end_slot,
                                      ulong * start_file_idx,
                                      ulong * end_file_idx,
                                      int * manifest_fd );

/* Iterate through the bank hash file return the first/last slot as well as 
   their indicies based on the slot range [start_slot, end_slot]*/
void fd_shredcap_bank_hash_seek_first( const char * capture_dir,
                                       char * bank_hash_buf,
                                       ulong start_slot,
                                       ulong end_slot,
                                       ulong * first_slot_idx,
                                       int * bank_hash_fd );

/* Verify manifest, capture files, bank hash file. This is an in depth check
   that can be done standalone or on top of any other shredcap operation. It 
   checks that the file format specification is followed in addition to checking
   for validity of slots. */
void fd_shredcap_verify( const char * capture_dir, fd_blockstore_t * blockstore );

/* Populate a blockstore will blocks from a given range from a shredcap capture. */
void fd_shredcap_populate_blockstore( const char * capture_dir, 
                                        fd_blockstore_t * blockstore, 
                                        ulong start_slot, 
                                        ulong end_slot );

#endif // HEADER_fd_src_app_fdshredcap_fdshredcap_h
