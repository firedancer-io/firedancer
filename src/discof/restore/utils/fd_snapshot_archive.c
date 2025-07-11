#include "fd_snapshot_archive.h"
#include <dirent.h>
#include <errno.h>
#include <stdio.h>

static int
fd_snapshot_archive_parse_full_snapshot_name( char const * snapshot_name,
                                              ulong *      slot,
                                              uchar        decoded_hash[ 32UL ][ 1UL ] ) {
  char hash[ FD_BASE58_ENCODED_32_SZ ];

  if( snapshot_name[0] == '/' ) {
    /* skip the starting slash */
    snapshot_name++;
  }

  if( strstr( snapshot_name, "partial" ) ) {
    /* skip partial files */
    return -1;
  }

  int res = sscanf( snapshot_name,
                    "snapshot-%lu-%[^.].*",
                    slot,
                    hash );

  if( res == 2UL ) {
    fd_base58_decode_32( hash, decoded_hash[0] );
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
                                                     uchar        decoded_hash[ 32UL ][ 1UL ] ) {
  char hash[ FD_BASE58_ENCODED_32_SZ ];

  if( snapshot_name[0] == '/' ) {
    /* skip the starting slash */
    snapshot_name++;
  }

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
    fd_base58_decode_32( hash, decoded_hash[0] );
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
  uchar decoded_hash[ 32UL ][ 1UL];

  int res = fd_snapshot_archive_parse_full_snapshot_name( snapshot_name, &slot, decoded_hash );
  if( FD_UNLIKELY( res ) ) {
    full_snapshot_entry->slot = ULONG_MAX;
    return -1;
  }

  if( !fd_cstr_printf_check( full_snapshot_entry->full_path, PATH_MAX, NULL, "%s/%s", snapshot_archive_path, snapshot_name ) ) {
    FD_LOG_ERR(( "snapshot path too long `%s/%s`", snapshot_archive_path, snapshot_name ));
  }

  full_snapshot_entry->slot = slot;
  fd_memcpy( full_snapshot_entry->hash.hash, decoded_hash, sizeof(fd_hash_t) );
  return 0;
}

static int
fd_snapshot_archive_populate_incremental_entry( char const *                              snapshot_archive_path,
                                                char const *                              snapshot_name,
                                                fd_incremental_snapshot_archive_entry_t * incremental_snapshot_entry ) {
  ulong base_slot;
  ulong slot;
  uchar decoded_hash[ 32UL ][ 1UL];

  int res = fd_snapshot_archive_parse_incremental_snapshot_name( snapshot_name, &base_slot, &slot, decoded_hash );
  if( FD_UNLIKELY( res ) ) {
    incremental_snapshot_entry->slot = ULONG_MAX;
    return -1;
  }

  if( !fd_cstr_printf_check( incremental_snapshot_entry->full_path, PATH_MAX, NULL, "%s/%s", snapshot_archive_path, snapshot_name ) ) {
    FD_LOG_ERR(( "snapshot path too long `%s/%s`", snapshot_archive_path, snapshot_name ));
  }

  incremental_snapshot_entry->base_slot = base_slot;
  incremental_snapshot_entry->slot      = slot;
  fd_memcpy( incremental_snapshot_entry->hash.hash, decoded_hash, sizeof(fd_hash_t) );
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
  fd_full_snapshot_archive_entry_t temp_entry;

  while(( entry = readdir( dir ) )) {
    int res = fd_snapshot_archive_populate_full_entry( snapshot_archive_path,
                                                       entry->d_name,
                                                       &temp_entry );

    if( FD_UNLIKELY( res ) ) {
      continue;
    }

    if( temp_entry.slot > highest_slot ) {
      *full_snapshot_entry = temp_entry;
      highest_slot         = temp_entry.slot;
    }
  }

  return 0;
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
    int res = fd_snapshot_archive_populate_incremental_entry( snapshot_archive_path,
                                                              entry->d_name,
                                                              &temp_entry );

    if( FD_UNLIKELY( res ) ) {
      continue;
    }

    if( temp_entry.slot > highest_slot ) {
      *incremental_snapshot_entry = temp_entry;
      highest_slot                = temp_entry.slot;
    }
  }

  return 0;
}
