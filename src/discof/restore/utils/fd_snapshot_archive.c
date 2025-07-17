#include "fd_snapshot_archive.h"
#include <dirent.h>
#include <errno.h>
#include <stdio.h>

static int
fd_snapshot_archive_parse_full_snapshot_name( char const * snapshot_name,
                                              ulong *      slot,
                                              uchar        decoded_hash[ static FD_HASH_FOOTPRINT ] ) {
  char hash[ FD_BASE58_ENCODED_32_SZ ];

  if( strstr( snapshot_name, "partial" ) ) {
    /* skip partial files */
    return -1;
  }

  int res = sscanf( snapshot_name,
                    "snapshot-%lu-%[^.].*",
                    slot,
                    hash );

  if( res == 2UL ) {
    fd_base58_decode_32( hash, decoded_hash );
    return 0;
  } else {
    *slot = ULONG_MAX;
    return -1;
  }
}

static int
fd_snapshot_archive_parse_incremental_snapshot_name( char const * snapshot_name,
                                                     ulong *      base_slot,
                                                     ulong *      slot,
                                                     uchar        decoded_hash[ static FD_HASH_FOOTPRINT ] ) {
  char hash[ FD_BASE58_ENCODED_32_SZ ];

  if( strstr( snapshot_name, "partial" ) ) {
    /* skip partial files */
    return -1;
  }

  int res = sscanf( snapshot_name,
                    "incremental-snapshot-%lu-%lu-%[^.].*",
                    base_slot,
                    slot,
                    hash );

  if( res == 3UL ) {
    fd_base58_decode_32( hash, decoded_hash );
    return 0;
  } else {
    *base_slot = ULONG_MAX;
    *slot      = ULONG_MAX;
    return -1;
  }
}

static int
fd_snapshot_archive_populate_full_entry( char const *                       snapshot_archive_path,
                                         char const *                       snapshot_name,
                                         fd_full_snapshot_archive_entry_t * full_snapshot_entry ) {
  ulong slot;
  uchar decoded_hash[ FD_HASH_FOOTPRINT ];

  int res = fd_snapshot_archive_parse_full_snapshot_name( snapshot_name, &slot, decoded_hash );
  if( FD_UNLIKELY( res ) ) {
    return -1;
  }

  if( !fd_cstr_printf_check( full_snapshot_entry->path, PATH_MAX, NULL, "%s/%s", snapshot_archive_path, snapshot_name ) ) {
    FD_LOG_ERR(( "snapshot path too long `%s/%s`", snapshot_archive_path, snapshot_name ));
  }

  full_snapshot_entry->slot = slot;
  fd_memcpy( full_snapshot_entry->hash, decoded_hash, FD_HASH_FOOTPRINT );
  return 0;
}

static int
fd_snapshot_archive_populate_incremental_entry( char const *                              snapshot_archive_path,
                                                char const *                              snapshot_name,
                                                fd_incremental_snapshot_archive_entry_t * incremental_snapshot_entry ) {
  ulong base_slot;
  ulong slot;
  uchar decoded_hash[ FD_HASH_FOOTPRINT ];

  int res = fd_snapshot_archive_parse_incremental_snapshot_name( snapshot_name, &base_slot, &slot, decoded_hash );
  if( FD_UNLIKELY( res ) ) {
    incremental_snapshot_entry->slot = ULONG_MAX;
    return -1;
  }

  if( !fd_cstr_printf_check( incremental_snapshot_entry->path, PATH_MAX, NULL, "%s/%s", snapshot_archive_path, snapshot_name ) ) {
    FD_LOG_ERR(( "snapshot path too long `%s/%s`", snapshot_archive_path, snapshot_name ));
  }

  incremental_snapshot_entry->base_slot = base_slot;
  incremental_snapshot_entry->slot      = slot;
  fd_memcpy( incremental_snapshot_entry->hash, decoded_hash, FD_HASH_FOOTPRINT );
  return 0;
}

int
fd_snapshot_archive_get_latest_full_snapshot( char const *                       snapshot_archive_path,
                                              fd_full_snapshot_archive_entry_t * full_snapshot_entry ) {
  DIR * dir = opendir(snapshot_archive_path );
  if( FD_UNLIKELY( !dir ) ) {
    return ENOENT;
  }

  struct dirent * entry;
  ulong highest_slot = 0UL;
  full_snapshot_entry->slot = ULONG_MAX;

  while(( entry = readdir( dir ) )) {
    int res = fd_snapshot_archive_populate_full_entry( snapshot_archive_path,
                                                       entry->d_name,
                                                       full_snapshot_entry );

    if( FD_UNLIKELY( res ) ) {
      continue;
    }

    if( full_snapshot_entry->slot>highest_slot ) {
      highest_slot = full_snapshot_entry->slot;
    }
  }

  if( FD_UNLIKELY( -1==closedir( dir ) ) ) FD_LOG_ERR(( "closedir() failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  if( FD_UNLIKELY( errno && errno!=ENOENT ) ) FD_LOG_ERR(( "readdir() failed (%i-%s)", errno, fd_io_strerror( errno ) ));

  return full_snapshot_entry->slot==ULONG_MAX ? -1 : 0;
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
  incremental_snapshot_entry->base_slot = ULONG_MAX;
  incremental_snapshot_entry->slot      = ULONG_MAX;

  while(( entry = readdir( dir ) )) {
    int res = fd_snapshot_archive_populate_incremental_entry( snapshot_archive_path,
                                                              entry->d_name,
                                                              incremental_snapshot_entry );

    if( FD_UNLIKELY( res ) ) {
      continue;
    }

    if( incremental_snapshot_entry->slot>highest_slot ) {
      highest_slot = incremental_snapshot_entry->slot;
    }
  }

  if( FD_UNLIKELY( -1==closedir( dir ) ) ) FD_LOG_ERR(( "closedir() failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  if( FD_UNLIKELY( errno && errno!=ENOENT ) ) FD_LOG_ERR(( "readdir() failed (%i-%s)", errno, fd_io_strerror( errno ) ));

  return incremental_snapshot_entry->slot==ULONG_MAX ? -1 : 0;
}
