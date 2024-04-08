#ifndef HEADER_fd_src_choreo_fd_choreo_base_h
#define HEADER_fd_src_choreo_fd_choreo_base_h

#include "../util/fd_util.h"

#define FD_SLOT_NULL (ULONG_MAX)

#define FD_HASH_FOOTPRINT   (32UL)
#define FD_HASH_ALIGN       (8UL)
#define FD_PUBKEY_FOOTPRINT FD_HASH_FOOTPRINT
#define FD_PUBKEY_ALIGN     FD_HASH_ALIGN

/* clang-format off */
union __attribute__((packed)) fd_hash {
  uchar hash[FD_HASH_FOOTPRINT];
  uchar key[FD_HASH_FOOTPRINT]; // Making fd_hash and fd_pubkey interchangeable

  // Generic type specific accessors
  ulong ul[FD_HASH_FOOTPRINT / sizeof(ulong)];
  uint  ui[FD_HASH_FOOTPRINT / sizeof(uint)];
  uchar uc[FD_HASH_FOOTPRINT];
};

typedef union fd_hash fd_hash_t;
typedef union fd_hash fd_pubkey_t;

static const fd_pubkey_t pubkey_null = { 0 };

struct __attribute__((aligned(8UL))) fd_slot_hash {
 ulong     slot;
 fd_hash_t hash;
};
typedef struct fd_slot_hash fd_slot_hash_t;
#define FD_SLOT_HASH_FOOTPRINT sizeof(fd_slot_hash_t)
#define FD_SLOT_HASH_ALIGN     (8UL)
#define FD_SLOT_HASH_CMP(a,b)  (fd_int_if(((a)->slot)<((b)->slot),-1,fd_int_if(((a)->slot)>((b)->slot),1),memcmp((a),(b),sizeof(fd_slot_hash_t))))
#define FD_SLOT_HASH_EQ(a,b)   ((((a)->slot)==((b)->slot)) & !(memcmp(((a)->hash.uc),((b)->hash.uc),sizeof(fd_hash_t))))
/* clang-format on */

static const fd_slot_hash_t slot_hash_null = { .slot = FD_SLOT_NULL, .hash = {{0}} };

#endif /* HEADER_fd_src_choreo_fd_choreo_base_h */
