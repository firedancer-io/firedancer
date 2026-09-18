#ifndef HEADER_fd_src_discof_failover_fd_failover_role_h
#define HEADER_fd_src_discof_failover_fd_failover_role_h

#include "fd_failover_proto.h"

#define FD_FAILOVER_ROLE_VERSION (1U)

#define FD_FAILOVER_ROLE_FILE_STANDBY   (0U)
#define FD_FAILOVER_ROLE_FILE_ACTIVE    (1U)
#define FD_FAILOVER_ROLE_FILE_DEMOTING  (2U)
#define FD_FAILOVER_ROLE_FILE_PROMOTING (3U)
#define FD_FAILOVER_ROLE_FILE_RECLAIM   (4U)
#define FD_FAILOVER_ROLE_FILE_CNT       (5U)

struct fd_failover_role_file {
  uint  version;
  ulong term;
  uchar role;
  uchar staked_pubkey[ 32 ];
  uchar paused;
  ulong baton_slot;
  ulong engaged_floor;
};

typedef struct fd_failover_role_file fd_failover_role_file_t;

#define FD_FAILOVER_ROLE_BODY_SZ (4UL+8UL+1UL+32UL+1UL+8UL+8UL)
#define FD_FAILOVER_ROLE_FILE_SZ (FD_FAILOVER_ROLE_BODY_SZ+32UL)

#define FD_FAILOVER_ROLE_PATH     "failover-role"
#define FD_FAILOVER_ROLE_TMP_PATH "failover-role.new"

FD_PROTOTYPES_BEGIN

/* The fixed-width image is little-endian and ends with a SHA-256 digest.
   Deserialization ignores bytes after the current image. */

ulong
fd_failover_role_ser( fd_failover_role_file_t const * role,
                      uchar *                         buf );

int
fd_failover_role_de( uchar const *             buf,
                     ulong                     buf_sz,
                     fd_failover_role_file_t * out );

/* Load returns zero, ENOENT when no role file exists, EPROTO for an
   invalid image, or another errno value for an I/O failure. */

int
fd_failover_role_load( int                       dir_fd,
                       fd_failover_role_file_t * out );

/* Store writes the record to a temporary file, syncs it, renames it over
   the live file and syncs the directory.  file_fd is a descriptor
   reserved for the temporary file and stays open on success.  With
   sandboxed=1 it is closed first and openat must return the same number,
   anything else is an error.  Otherwise, as in the threaded dev launcher
   with its shared descriptor table, the new descriptor is moved onto
   file_fd.  Unless both are UINT_MAX, owner_uid and owner_gid are given
   to the new file with fchown before the rename.  The write at boot runs
   before the tile drops to the validator user, and the loader refuses a
   file whose owner differs from the directory's.  Later writes already
   run as that user, and the sandbox has no fchown, so they pass UINT_MAX.
   Returns zero or an errno value. */

int
fd_failover_role_store( int                             dir_fd,
                        int                             file_fd,
                        int                             sandboxed,
                        uint                            owner_uid,
                        uint                            owner_gid,
                        fd_failover_role_file_t const * role );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_discof_failover_fd_failover_role_h */
