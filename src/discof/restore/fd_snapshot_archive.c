#include "fd_snapshot_archive.h"
#include "../../ballet/base58/fd_base58.h"
#include <dirent.h>
#include <errno.h>
#include <stdio.h>

static void
fd_snapshot_archive_set_full_path( char const *    snapshot_archive_path,
                                   struct dirent * snapshot_entry,
                                   char            filename[ PATH_MAX ] ) {
  ulong archive_path_len = strlen( snapshot_archive_path );
  ulong entry_path_len   = strlen( snapshot_entry->d_name );

  /* need to account for extra slash character and null terminating character */
  if( archive_path_len + entry_path_len >= PATH_MAX - 2 ) {
    FD_LOG_ERR(( "snapshot file path length of %lu is too long", archive_path_len + entry_path_len ));
  }

  fd_memcpy( filename, snapshot_archive_path, archive_path_len );
  filename[ archive_path_len ] = '/';
  fd_memcpy( filename+archive_path_len + 1, snapshot_entry->d_name, entry_path_len );
  filename[ archive_path_len + 1 + entry_path_len ] = '\0';

}

static int
fd_snapshot_archive_parse_full_snapshot_file( char const *                  snapshot_archive_path,
                                              struct dirent *               snapshot_entry,
                                              fd_snapshot_archive_entry_t * archive_entry ) {
  ulong slot;
  char hash[ FD_BASE58_ENCODED_32_SZ ];
  int res = sscanf( snapshot_entry->d_name,
                    "%*[^-]-%lu-%[^.].*",
                    &slot,
                    hash );

  if( res == 2UL ) {
    fd_snapshot_archive_set_full_path( snapshot_archive_path, snapshot_entry, archive_entry->filename );
    archive_entry->slot = slot;
    fd_base58_decode_32( hash, archive_entry->hash.hash );
    return 0;
  }

  return -1;
}

static int
fd_snapshot_archive_parse_incremental_snapshot_file( char const *                              snapshot_archive_path,
                                                     struct dirent *                           snapshot_entry,
                                                     fd_incremental_snapshot_archive_entry_t * archive_entry ) {
  ulong full_slot;
  ulong inc_slot;
  char hash[ FD_BASE58_ENCODED_32_SZ ];
  int res = sscanf( snapshot_entry->d_name,
                    "incremental-snapshot-%lu-%lu-%[^.].*",
                    &full_slot,
                    &inc_slot,
                    hash );

  if( res == 3UL ) {
    fd_snapshot_archive_set_full_path( snapshot_archive_path, snapshot_entry, archive_entry->inner.filename );
    archive_entry->base_slot = full_slot;
    archive_entry->inner.slot = inc_slot;
    fd_base58_decode_32( hash, archive_entry->inner.hash.hash );
    return 0;
  }

  return -1;
}

int
fd_snapshot_archive_get_latest_full_snapshot( char const *                  snapshot_archive_path,
                                              fd_snapshot_archive_entry_t * full_snapshot_entry ) {
  DIR * dir = opendir(snapshot_archive_path );
  if( FD_UNLIKELY( !dir ) ) {
    return ENOENT;
  }

  struct dirent * entry;
  ulong highest_slot = 0UL;
  fd_snapshot_archive_entry_t temp_entry;

  while(( entry = readdir( dir ) )) {
    int res = fd_snapshot_archive_parse_full_snapshot_file( snapshot_archive_path, entry, &temp_entry );

    if( FD_UNLIKELY( res ) ) {
      continue;
    }

    if( temp_entry.slot > highest_slot ) {
      *full_snapshot_entry = temp_entry;
      highest_slot = temp_entry.slot;
    }
  }

  return highest_slot ? 0 : -1;
}

int
fd_snapshot_archive_get_latest_incremental_snapshot( char const *                              snapshot_archive_path,
                                                     fd_incremental_snapshot_archive_entry_t * incremental_snapshot_entry ) {
  DIR * dir = opendir(snapshot_archive_path );
  if( FD_UNLIKELY( !dir ) ) {
    return ENOENT;
  }

  struct dirent * entry;
  ulong highest_slot = 0UL;
  fd_incremental_snapshot_archive_entry_t temp_entry;

  while(( entry = readdir( dir ) )) {
    int res = fd_snapshot_archive_parse_incremental_snapshot_file( snapshot_archive_path, entry, &temp_entry );

    if( FD_UNLIKELY( res ) ) {
      continue;
    }

    if( temp_entry.inner.slot > highest_slot ) {
      *incremental_snapshot_entry = temp_entry;
      highest_slot = temp_entry.inner.slot;
    }
  }

  return highest_slot ? 0 : -1;
}
