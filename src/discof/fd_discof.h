#ifndef HEADER_fd_src_discof_fd_discof_h
#define HEADER_fd_src_discof_fd_discof_h

#ifndef HEADER_fd_src_app_fdshredcap_fdshredcap_h
#define HEADER_fd_src_app_fdshredcap_fdshredcap_h

#include "../flamenco/types/fd_types_custom.h"
#include "../flamenco/runtime/fd_blockstore.h"


/* TODO: Consider adding a file-wide header and trailer to both of the
   following file formats. */

/* TODO: Consider adding a version-agnostic header and trailer to both
   of the following file formats. */

/* TODO: Consider adding accessors/mutators for each of these fields. */

/* Shredcap slice capture format. This format enables us to capture
   slices of shreds from the repair tile as they are made ready for
   the replay tile. We expect the format to be as follows:

   +-------------------------------------------------------------------+
   | fd_shredcap_slice_header_msg_t                                    |
   +-------------------------------------------------------------------+
   | fd_shred_t (header and payload)                                   |
   | ... This is repeated for every data shred in the slice            |
   +-------------------------------------------------------------------+
   | fd_shredcap_slice_trailer_msg_t                                   |
   +-------------------------------------------------------------------+
   | ... This is repeated for every captured slice                     |
   +-------------------------------------------------------------------+

  */

struct __attribute__((packed)) fd_shredcap_slice_header_msg_v1  {
  ulong magic;
  ulong version;
  ulong payload_sz;
};
typedef struct fd_shredcap_slice_header_msg_v1 fd_shredcap_slice_header_msg_t;
#define FD_SHREDCAP_SLICE_HEADER_MAGIC     (0XF00F00F00UL)
#define FD_SHREDCAP_SLICE_HEADER_V1        (0x1UL)
#define FD_SHREDCAP_SLICE_HEADER_FOOTPRINT (sizeof(fd_shredcap_slice_header_msg_t))

struct __attribute__((packed)) fd_shredcap_slice_trailer_msg_v1 {
  ulong magic;
  ulong version;
};
typedef struct fd_shredcap_slice_trailer_msg_v1 fd_shredcap_slice_trailer_msg_t;
#define FD_SHREDCAP_SLICE_TRAILER_MAGIC     (0X79397939UL)
#define FD_SHREDCAP_SLICE_TRAILER_V1        (0x1UL)
#define FD_SHREDCAP_SLICE_TRAILER_FOOTPRINT (sizeof(fd_shredcap_slice_trailer_msg_t))

/* fd_shredcap_slice_header_validate will crash the program if the
   header is obviously corrupted. */
static inline void
fd_shredcap_slice_header_validate( fd_shredcap_slice_header_msg_t const * header ) {
  if( FD_UNLIKELY( header->magic!=FD_SHREDCAP_SLICE_HEADER_MAGIC ) ) {
    FD_LOG_CRIT(( "Invalid magic number in shredcap slice header: %lu", header->magic ));
  }
  if( FD_UNLIKELY( header->version != FD_SHREDCAP_SLICE_HEADER_V1 ) ) {
    FD_LOG_CRIT(( "Invalid version in shredcap slice header: %lu", header->version ));
  }
  if( FD_UNLIKELY( header->payload_sz>FD_SLICE_MAX_WITH_HEADERS ) ) {
    FD_LOG_CRIT(( "Invalid payload size in shredcap slice header: %lu", header->payload_sz ));
  }
}

/* fd_shredcap_slice_trailer_validate will crash the program if the
   trailer is obviously corrupted. */
static inline void
fd_shredcap_slice_trailer_validate( fd_shredcap_slice_trailer_msg_t const * trailer ) {
  if( FD_UNLIKELY( trailer->magic!=FD_SHREDCAP_SLICE_TRAILER_MAGIC ) ) {
    FD_LOG_CRIT(( "Invalid magic number in shredcap slice trailer: %lu", trailer->magic ));
  }
  if( FD_UNLIKELY( trailer->version != FD_SHREDCAP_SLICE_TRAILER_V1 ) ) {
    FD_LOG_CRIT(( "Invalid version in shredcap slice trailer: %lu", trailer->version ));
  }
}


/* Shredcap bank hash capture format. This format enables us to capture
   the bank hashes calculated by the network in the replay tile. We
   expect the format to be as follows:

   +-------------------------------------------------------------------+
   | fd_shredcap_bank_hash_msg_v1                                      |
   +-------------------------------------------------------------------+
   | fd_hash_t bank_hash                                               |
   +-------------------------------------------------------------------+
   | ... This is repeated for every bank hash in the replay tile       |
   +-------------------------------------------------------------------+

   As a note, the bank hashes are not necessarily needed to be in a
   strict order. They are recorded in the order that the slots are
   finished executing.
  */

struct __attribute__((packed)) fd_shredcap_bank_hash_msg_v1 {
  ulong     magic;
  ulong     version;
  ulong     slot;
  fd_hash_t bank_hash;
};
typedef struct fd_shredcap_bank_hash_msg_v1 fd_shredcap_bank_hash_msg_t;
#define FD_SHREDCAP_BANK_HASH_MAGIC     (0X810810810UL)
#define FD_SHREDCAP_BANK_HASH_V1        (0x1UL)
#define FD_SHREDCAP_BANK_HASH_FOOTPRINT (sizeof(fd_shredcap_bank_hash_msg_t))

/* fd_shredcap_bank_hash_msg_validate will crash the program if the
   bank hash message is obviously corrupted. */
static inline void
fd_shredcap_bank_hash_msg_validate( fd_shredcap_bank_hash_msg_t const * msg ) {
  if( FD_UNLIKELY( msg->magic!=FD_SHREDCAP_BANK_HASH_MAGIC ) ) {
    FD_LOG_CRIT(( "Invalid magic number in shredcap bank hash message: %lu", msg->magic ));
  }
  if( FD_UNLIKELY( msg->version!=FD_SHREDCAP_BANK_HASH_V1 ) ) {
    FD_LOG_CRIT(( "Invalid version in shredcap bank hash message: %lu", msg->version ));
  }
}


#endif // HEADER_fd_src_app_fdshredcap_fdshredcap_h

#endif /* HEADER_fd_src_discof_fd_discof_h */
