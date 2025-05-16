#ifndef src_flamenco_types_fd_pubkey_type_h
#define src_flamenco_types_fd_pubkey_type_h

#include "../fd_flamenco_base.h"

#define FD_HASH_FOOTPRINT (32UL)
#define FD_HASH_ALIGN (8UL)
#define FD_PUBKEY_FOOTPRINT FD_HASH_FOOTPRINT
#define FD_PUBKEY_ALIGN FD_HASH_ALIGN
/* TODO this should not have packed alignment, but it's misused everywhere */

union __attribute__((packed)) fd_hash {
  uchar hash[ FD_HASH_FOOTPRINT ];
  uchar key [ FD_HASH_FOOTPRINT ]; // Making fd_hash and fd_pubkey interchangeable

  // Generic type specific accessors
  ulong ul  [ FD_HASH_FOOTPRINT / sizeof(ulong) ];
  uint  ui  [ FD_HASH_FOOTPRINT / sizeof(uint)  ];
  uchar uc  [ FD_HASH_FOOTPRINT ];
};

typedef union fd_hash fd_hash_t;
typedef union fd_hash fd_pubkey_t;

FD_FN_PURE static inline int
fd_hash_eq( fd_hash_t const * a,
            fd_hash_t const * b ) {
  return 0==memcmp( a, b, sizeof(fd_hash_t) );
}

#endif
