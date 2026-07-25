#ifndef HEADER_fd_src_discof_restore_utils_fd_ssarchive_h
#define HEADER_fd_src_discof_restore_utils_fd_ssarchive_h

#include "../../../flamenco/fd_flamenco_base.h"

#include <stdlib.h>

/* FD_SNAP_NAME_MAX is the max length of a snapshot filename (cstr)
   including NUL terminator. */
#define FD_SNAP_NAME_MAX (128UL)

/* FD_SSARCHIVE_MAX_ENTRIES is the number of snapshots of each class
   (full, incremental) that fd_ssarchive_latest_pair considers.  If a
   directory holds more than this, only the newest
   FD_SSARCHIVE_MAX_ENTRIES of each class are considered. */
#define FD_SSARCHIVE_MAX_ENTRIES (512UL)

FD_PROTOTYPES_BEGIN

/* Parses a snapshot filename into components.

    incremental-snapshot-344185432-344209085-45eJ5C91fEenPRFc8NiqaDXMCHcPFwRUTMH3k1zY6a1B.tar.zst
    snapshot-344185432-BSP9ztdFEjwvkBo2LhHA47g9Q3PDwja9x5fj7taFRKH5.tar.zst
    snapshot-369927872-AaswH3EY2QJtTL1rTGxKCKsJ6SAjAeAvNfJhgM9D4ytU.tar

   Returns -1 on failure and 0 on success. */

static inline int
fd_ssarchive_parse_filename( char const * _name,
                             ulong *      full_slot,
                             ulong *      incremental_slot,
                             uchar        hash[ static FD_HASH_FOOTPRINT ],
                             int *        is_zstd ) {
  char name[ PATH_MAX ];
  fd_cstr_ncpy( name, _name, sizeof(name) );

  char * ptr = name;
  int is_incremental;
  if( !strncmp( ptr, "incremental-snapshot-", 21UL ) ) {
    is_incremental = 1;
    ptr += 21UL;
  } else if( !strncmp( ptr, "snapshot-", 9UL ) ) {
    is_incremental = 0;
    ptr += 9UL;
  } else {
    return -1;
  }

  char * next = strchr( ptr, '-' );
  if( FD_UNLIKELY( !next ) ) return -1;
  *next = '\0';
  char * endptr;
  *full_slot = strtoul( ptr, &endptr, 10 );
  if( FD_UNLIKELY( *endptr!='\0' || endptr==ptr || *full_slot==ULONG_MAX ) ) return -1;

  if( is_incremental ) {
    ptr = next + 1;
    next = strchr( ptr, '-' );
    if( FD_UNLIKELY( !next ) ) return -1;
    *next = '\0';
    *incremental_slot = strtoul( ptr, &endptr, 10 );
    if( FD_UNLIKELY( *endptr!='\0' || endptr==ptr || *incremental_slot==ULONG_MAX ) ) return -1;
  } else {
    *incremental_slot = ULONG_MAX;
  }

  ptr = next + 1;
  next = strchr( ptr, '.' );
  if( FD_UNLIKELY( !next ) ) return -1;
  *next = '\0';
  ulong sz = (ulong)(next - ptr);
  if( FD_UNLIKELY( sz>FD_BASE58_ENCODED_32_LEN ) ) return -1;
  uchar * result = fd_base58_decode_32( ptr, hash );
  if( FD_UNLIKELY( result!=hash ) ) return -1;

  ptr = next + 1;

  if(       FD_LIKELY( 0==strcmp( ptr, "tar.zst" ) ) ) *is_zstd = 1;
  else if ( FD_LIKELY( 0==strcmp( ptr, "tar"     ) ) ) *is_zstd = 0;
  else return -1;

  return 0;
}

/* Given a directory on the filesystem, determine the most recent (full,
   incremental) slot pair, whether each snapshot is zstd compressed, the
   associated full and incremental hashes, and the snapshot paths.  The
   incremental slot is set to ULONG_MAX if the highest pair is just a
   full snapshot alone, or if incremental_snapshot is 0 (only full
   snapshots are considered).  In this case, incremental_path is left
   empty, *incremental_is_zstd is set to 0, and incremental_hash is
   zeroed.

   Returns -1 on failure, and 0 on success. */

int
fd_ssarchive_latest_pair( char const * directory,
                          int          incremental_snapshot,
                          ulong *      full_slot,
                          ulong *      incremental_slot,
                          char         full_path[ static PATH_MAX ],
                          char         incremental_path[ static PATH_MAX ],
                          int *        full_is_zstd,
                          int *        incremental_is_zstd,
                          uchar        full_hash[ static FD_HASH_FOOTPRINT ],
                          uchar        incremental_hash[ static FD_HASH_FOOTPRINT ] );

/* Given a directory on the file system, remove old snapshots by slot
   age until the number of full snapshots matches the
   max_full_snapshots_to_keep and the number of incremental snapshots
   matches the max_incremental_snapshots_to_keep parameter. */
void
fd_ssarchive_remove_old_snapshots( char const * directory,
                                   uint         max_full_snapshots_to_keep,
                                   uint         max_incremental_snapshots_to_keep );
FD_PROTOTYPES_END

#endif /* HEADER_fd_src_discof_restore_utils_fd_ssarchive_h */
