#ifndef HEADER_fd_src_choreo_fd_choreo_base_h
#define HEADER_fd_src_choreo_fd_choreo_base_h

#include "../flamenco/fd_flamenco_base.h"
#include "../flamenco/types/fd_types.h"

/* clang-format off */
#define FD_SLOT_HASH_CMP(a,b)  (fd_int_if(((a)->slot)<((b)->slot),-1,fd_int_if(((a)->slot)>((b)->slot),1),memcmp((a),(b),sizeof(fd_slot_hash_t))))
#define FD_SLOT_HASH_EQ(a,b)   ((((a)->slot)==((b)->slot)) & !(memcmp(((a)->hash.uc),((b)->hash.uc),sizeof(fd_hash_t))))
/* clang-format on */

static const fd_slot_hash_t FD_SLOT_HASH_NULL = { .slot = FD_SLOT_NULL, .hash = { { 0 } } };

#endif /* HEADER_fd_src_choreo_fd_choreo_base_h */
